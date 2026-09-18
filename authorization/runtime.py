"""Durable extension of SecureRuntime; the original evaluator remains authoritative.

Host supplies live identities, provenance, policy and registered adapters on every
boot. Session bearer tokens, callable handlers and policy state are never restored
from this database. A checkpoint is never consulted for authorization.
"""
from dataclasses import asdict, replace
from threading import RLock
from enum import Enum
import math

from agent_demo import Decision
from secure_runtime import SecureRuntime, RuntimeResult, digest
from authorization.codec import dumps, loads


class Lifecycle(str, Enum):
    PREPARED = 'PREPARED'
    APPROVAL_PENDING = 'APPROVAL_PENDING'
    PERMIT_ISSUED = 'PERMIT_ISSUED'
    DISPATCH_STARTED = 'DISPATCH_STARTED'
    EXECUTED = 'EXECUTED'
    FAILED = 'FAILED'
    UNKNOWN_OUTCOME = 'UNKNOWN_OUTCOME'


class AuthorizationUnavailable(RuntimeError):
    pass


class PersistentSecureRuntime(SecureRuntime):
    def __init__(self, trusted_runtime, store):
        super().__init__(trusted_runtime.policy, trusted_runtime.identities,
                         trusted_runtime.inputs, trusted_runtime.clock)
        self.store = store
        self._lock = RLock()
        self._fault = False
        self._tools = trusted_runtime._tools.copy()
        self._tasks = trusted_runtime._tasks.copy()
        self._requests = {}
        self._last_time = self.clock()
        self._adapters = {}
        try:
            saved = store.load()
            if saved is not None:
                data = loads(saved)
                if data['version'] != 1:
                    raise ValueError('Unsupported authorization schema')
                for name in ('_tasks', '_pending', '_permits', '_attempted', '_denied',
                             '_requests', 'audit', '_last_time'):
                    setattr(self, name, data[name])
                self._check()
                for entry in self._requests.values():
                    if entry['state'] == Lifecycle.DISPATCH_STARTED.value:
                        entry['state'] = Lifecycle.UNKNOWN_OUTCOME.value
                        entry['result'] = RuntimeResult(Decision.BLOCK,
                            'UNKNOWN_OUTCOME: reconciliation required; automatic retry forbidden',
                            error='UNKNOWN_OUTCOME')
                        self.audit.append({'stage': 'recovery', 'time': self.clock(),
                            'request_id': entry['call'].request_id,
                            'execution_id': entry['execution_id'], 'state': entry['state'],
                            'decision': Decision.BLOCK.value, 'reason': 'UNKNOWN_OUTCOME requires reconciliation'})
            self._save()
        except BaseException:
            self._fault = True
            raise

    def _check(self):
        if self._fault:
            raise AuthorizationUnavailable('Authorization storage failed; restart and reconcile')
        now = self.clock()
        if type(now) not in (int, float) or not math.isfinite(now) or now < self._last_time:
            self._fault = True
            raise AuthorizationUnavailable('Authorization clock moved backwards')
        self._last_time = now
        # Refresh the exact telemetry service attached to this policy before every
        # authority operation. Telemetry failure propagates; no dispatch occurs.
        service = getattr(self.policy, '_telemetry_service', None)
        if service is not None:
            service.refresh()

    def _save(self):
        try:
            snapshot = {'version': 1, **{name: getattr(self, name) for name in (
                '_tasks', '_pending', '_permits', '_attempted', '_denied',
                '_requests', 'audit', '_last_time')}}
            # Store only permit hashes. A host recovery can use the internal
            # hash index, but callers must present the original opaque token.
            snapshot['_requests'] = {key: {**entry, 'result': (
                replace(entry['result'], permit_id=None) if entry['result'] else None
            )} for key, entry in self._requests.items()}
            self.store.save(dumps(snapshot))
        except BaseException as error:
            self._fault = True
            raise AuthorizationUnavailable('Cannot commit authorization state') from error

    def _owned(self, token, request_id, call=None):
        key = self.identities.session_key(token)
        self.identities.resolve(key)
        entry = self._requests.get(request_id)
        if entry is None or entry['session_key'] != key or (call is not None and call != entry['call']):
            raise ValueError('Unknown request, different session, or exact-call mismatch')
        return entry

    def prepare(self, agent_token, call, plan_context):
        with self._lock:
            self._check()
            if call.request_id in self._requests:
                try:
                    self._owned(agent_token, call.request_id, call)
                except ValueError as error:
                    return self._emit('prepare', call, RuntimeResult(Decision.BLOCK, str(error)), agent_token)
                return self._emit('duplicate_prepare', call, RuntimeResult(Decision.BLOCK,
                    'Request already exists; recover its durable state, never mint a replacement permit'), agent_token)
            key = self.identities.session_key(agent_token)
            self._requests[call.request_id] = {
                'call': call, 'session_key': key, 'state': Lifecycle.PREPARED.value,
                'execution_id': digest({'version': 1, 'call': asdict(call), 'session': key}),
                'result': None,
            }
            # A pre-authorization crash is safely represented, without an implicit permit.
            self._save()
            return super().prepare(agent_token, call, plan_context)

    def resolve_approval(self, user_token, approval_id, *, approved):
        with self._lock:
            self._check()
            return super().resolve_approval(user_token, approval_id, approved=approved)

    def execute(self, agent_token, call, permit_id):
        with self._lock:
            self._check()
            return super().execute(agent_token, call, digest(permit_id))

    def _emit(self, stage, call, result, actor_token):
        if result.permit_id is not None and result.permit_id in self._permits:
            self._permits[digest(result.permit_id)] = self._permits.pop(result.permit_id)
        result = super()._emit(stage, call, result, actor_token)
        entry = self._requests.get(call.request_id) if call else None
        if entry and call == entry['call']:
            if stage in ('prepare', 'approval') and entry['state'] in (
                    Lifecycle.PREPARED.value, Lifecycle.APPROVAL_PENDING.value):
                if result.permit_id:
                    entry['state'] = Lifecycle.PERMIT_ISSUED.value
                elif result.approval_id:
                    entry['state'] = Lifecycle.APPROVAL_PENDING.value
                elif any(r.call == call for r in self._pending.values()):
                    # An unauthorized approval attempt does not resolve the real pending review.
                    pass
                else:
                    entry['state'] = Lifecycle.FAILED.value
                entry['result'] = result
            elif stage == 'execute' and entry['state'] not in (
                    Lifecycle.EXECUTED.value, Lifecycle.UNKNOWN_OUTCOME.value, Lifecycle.FAILED.value):
                if entry['state'] == Lifecycle.DISPATCH_STARTED.value:
                    entry['state'] = (Lifecycle.EXECUTED.value if result.executed else Lifecycle.UNKNOWN_OUTCOME.value)
                    if not result.executed:
                        result = RuntimeResult(Decision.BLOCK,
                            'UNKNOWN_OUTCOME: adapter raised after dispatch; reconciliation required',
                            error='UNKNOWN_OUTCOME')
                elif not any(r.call == call for r in self._permits.values()):
                    entry['state'] = Lifecycle.FAILED.value
                entry['result'] = result
        self.audit[-1].update(decision=result.decision.value, reason=result.reason,
                              executed=result.executed, error=result.error)
        self._save()
        return result

    def register_idempotent_adapter(self, tool_name, adapter):
        """Trusted host API. Adapter(call, execution_id) forwards key downstream."""
        if tool_name not in self._tools or not callable(adapter):
            raise ValueError('Register the trusted tool before its idempotent adapter')
        self._adapters[tool_name] = adapter

    def _dispatch(self, tool, call):
        entry = self._requests[call.request_id]
        entry['state'] = Lifecycle.DISPATCH_STARTED.value
        self.audit.append({'stage': 'dispatch', 'time': self.clock(),
                           'request_id': call.request_id, 'execution_id': entry['execution_id'],
                           'decision': Decision.ALLOW.value, 'reason': 'Durable dispatch intent; permit consumed'})
        # Atomically commits permit removal, attempted request, and dispatch intent.
        # Failure here must escape SecureRuntime's handler exception catch.
        try:
            self._save()
        except AuthorizationUnavailable as error:
            raise DispatchCommitFailure() from error
        adapter = self._adapters.get(tool.name)
        return adapter(call, entry['execution_id']) if adapter else tool.handler(call)

    def request_status(self, agent_token, request_id):
        with self._lock:
            self._check()
            entry = self._owned(agent_token, request_id)
            return {'request_id': request_id, 'state': entry['state'],
                    'execution_id': entry['execution_id'], 'result': entry['result']}

    def pending_details(self, user_token, agent_token, request_id):
        with self._lock:
            self._check()
            entry = self._owned(agent_token, request_id)
            for approval, record in self._pending.items():
                if record.call == entry['call'] and record.session_key == entry['session_key']:
                    return approval, self.approval_details(user_token, approval)
            raise ValueError('No durable pending approval')

    def recover(self, agent_token, request_id):
        """No call, decision, approval or permit is accepted from graph state."""
        with self._lock:
            self._check()
            entry = self._owned(agent_token, request_id)
            if entry['state'] == Lifecycle.PERMIT_ISSUED.value:
                for permit, record in tuple(self._permits.items()):
                    if record.call == entry['call'] and record.session_key == entry['session_key']:
                        return super().execute(agent_token, entry['call'], permit)
                return RuntimeResult(Decision.BLOCK, 'Permit consumption is durable; no replacement permitted')
            if entry['state'] == Lifecycle.DISPATCH_STARTED.value:
                return RuntimeResult(Decision.BLOCK, 'UNKNOWN_OUTCOME: reconciliation required', error='UNKNOWN_OUTCOME')
            if entry['result'] and entry['result'].decision == Decision.REEVALUATE:
                # Refresh assessment for an informative BLOCK, without issuing
                # a replacement permit or reusing a previous human answer.
                try:
                    decision, reason, _, _, _ = self._evaluate(entry['session_key'],
                        entry['call'], self.policy.capture_context())
                except ValueError as error:
                    decision, reason = Decision.BLOCK, str(error)
                if decision == Decision.BLOCK:
                    entry['result'] = RuntimeResult(decision, reason)
                    self._emit('prepare', entry['call'], entry['result'], agent_token)
            return entry['result'] or RuntimeResult(Decision.REEVALUATE,
                'Preparation interrupted; submit a newly reviewed request explicitly')

    def create_task(self, *args, **kwargs):
        with self._lock:
            self._check()
            result = super().create_task(*args, **kwargs)
            self._save()
            return result

    def update_task_rules(self, *args, **kwargs):
        with self._lock:
            self._check()
            super().update_task_rules(*args, **kwargs)
            self._save()

    def revoke_task(self, *args, **kwargs):
        with self._lock:
            self._check()
            super().revoke_task(*args, **kwargs)
            self._save()


class DispatchCommitFailure(BaseException):
    """Fatal pre-dispatch persistence failure; never converted to tool success/failure."""
