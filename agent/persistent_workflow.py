"""Durable LangGraph position with authority resolved outside checkpoint contents."""
import json
from typing import TypedDict
from types import SimpleNamespace
from langgraph.checkpoint.base import BaseCheckpointSaver, CheckpointTuple
from langgraph.graph import StateGraph, START, END
from agent.security_workflow import public_result
from authorization.runtime import Lifecycle
from agent_demo import Decision


class PrimitiveCheckpointSaver(BaseCheckpointSaver):
    """Small synchronous latest-checkpoint adapter for this single-node workflow.

    JSON primitives only, no pickle/object deserialization. Pending graph writes
    are unnecessary: rerunning the sole node consults durable execution state.
    Not a general purpose LangGraph checkpoint implementation.
    """
    def __init__(self, store):
        super().__init__()
        self.store = store

    @staticmethod
    def _key(config):
        return json.dumps([config['configurable']['thread_id'],
                           config['configurable'].get('checkpoint_ns', '')])

    def get_tuple(self, config):
        raw = self.store.checkpoint_load(self._key(config))
        if raw is None:
            return None
        saved = json.loads(raw)
        return CheckpointTuple(saved['config'], saved['checkpoint'], saved['metadata'], None, [])

    def put(self, config, checkpoint, metadata, new_versions):
        updated = {'configurable': {
            'thread_id': config['configurable']['thread_id'],
            'checkpoint_ns': config['configurable'].get('checkpoint_ns', ''),
            'checkpoint_id': checkpoint['id']}}
        self.store.checkpoint_save(self._key(config), json.dumps({
            'config': updated, 'checkpoint': checkpoint, 'metadata': metadata}, allow_nan=False))
        return updated

    def put_writes(self, config, writes, task_id, task_path=''):
        # Authority commits precede graph writes. Losing a graph write only
        # repeats a read/recovery operation, never creates permission.
        pass


class Position(TypedDict):
    request_id: str


class PersistentSecurityWorkflow:
    def __init__(self, runtime, agent_token, approver_token):
        self.runtime = runtime
        self._agent_token = agent_token
        self._approver_token = approver_token
        builder = StateGraph(Position)
        builder.add_node('recover', self._tick)
        builder.add_edge(START, 'recover')
        builder.add_edge('recover', END)
        self.graph = builder.compile(checkpointer=PrimitiveCheckpointSaver(runtime.store))

    def _tick(self, state, config):
        request_id = config['configurable']['thread_id']
        if state.get('request_id') != request_id:
            raise ValueError('Checkpoint request differs from host-selected request')
        # No human approval path exists in any graph node.
        self.runtime.recover(self._agent_token, request_id)
        return {'request_id': request_id}

    def _render(self, request_id):
        status = self.runtime.request_status(self._agent_token, request_id)
        output = {'request_id': request_id,
                  'plan_context': self.runtime.policy.capture_context()}
        if status['state'] == Lifecycle.APPROVAL_PENDING.value:
            try:
                _, details = self.runtime.pending_details(self._approver_token, self._agent_token, request_id)
            except ValueError:
                # Expired records still reach the runtime's normal resolution path.
                details = {'request_id': request_id, 'reason': 'Approval requires revalidation'}
            return {**output, '__interrupt__': [SimpleNamespace(value=details)]}
        result = status['result']
        if result is None:
            result = self.runtime.recover(self._agent_token, request_id)
        return {**output, 'result': public_result(result)}

    def start(self, call, plan_context):
        try:
            self.runtime.request_status(self._agent_token, call.request_id)
        except ValueError:
            self.runtime.prepare(self._agent_token, call, plan_context)
        else:
            self.runtime._owned(self._agent_token, call.request_id, call)
        return self.restore(call.request_id)

    def restore(self, request_id):
        # Explicit host request ID overwrites informational checkpoint input.
        self.graph.invoke({'request_id': request_id},
                          {'configurable': {'thread_id': request_id}})
        return self._render(request_id)

    def resume(self, request_id, *, approved):
        if type(approved) is not bool:
            raise TypeError('Human approval must be an explicit boolean')
        # This trusted host entry point, never a graph resume value, supplies
        # the authenticated human response. Look up the exact durable record.
        with self.runtime._lock:
            entry = self.runtime._owned(self._agent_token, request_id)
            approval = next((key for key, record in self.runtime._pending.items()
                             if record.call == entry['call'] and record.session_key == entry['session_key']), None)
            if approval is None:
                raise ValueError('No durable pending approval')
            self.runtime.resolve_approval(self._approver_token, approval, approved=approved)
        return self.restore(request_id)
