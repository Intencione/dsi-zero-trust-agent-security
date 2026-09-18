"""Checkpointed authorization workflow, with no telemetry writers or tool handlers.

Only the trusted host may start/resume runs. A model receives business tool
results, never this graph, its checkpoint state, or the approver session.
"""

from typing import TypedDict

from langgraph.checkpoint.memory import InMemorySaver
from langgraph.checkpoint.serde.jsonplus import JsonPlusSerializer
from langgraph.graph import END, START, StateGraph
from langgraph.types import Command, interrupt

from agent_demo import Decision, PlanContext
from secure_runtime import RuntimeResult, SecureRuntime, ToolCall


class SecurityState(TypedDict):
    call: ToolCall
    plan_context: PlanContext
    decision: str
    reason: str
    permit_id: str | None
    approval_id: str | None
    approval_details: dict | None
    result: dict | None


def public_result(result: RuntimeResult) -> dict:
    """Return useful tool output without disclosing authorization capabilities."""
    return {
        "status": "executed" if result.executed else (
            "blocked" if result.decision == Decision.BLOCK else "not_executed"
        ),
        "decision": result.decision.value,
        "executed": result.executed,
        "output": result.output,
        "reason": result.reason,
        "error": result.error,
    }


class SecurityWorkflow:
    def __init__(self, runtime: SecureRuntime, agent_token: str, approver_token: str):
        self.runtime = runtime
        self._agent_token = agent_token
        self._approver_token = approver_token
        serializer = JsonPlusSerializer(allowed_msgpack_modules=[
            ("secure_runtime", "ToolCall"),
            ("agent_demo", "EnvironmentType"),
            ("agent_demo", "NetworkAccess"),
            ("agent_demo", "EnvironmentContext"),
            ("agent_demo", "PlanContext"),
        ])
        builder = StateGraph(SecurityState)
        builder.add_node("security_check", self._prepare)
        builder.add_node("approval", self._approve)
        builder.add_node("execute", self._execute)
        builder.add_node("refresh_context", self._refresh)
        builder.add_node("block", self._block)
        builder.add_edge(START, "security_check")
        builder.add_conditional_edges("security_check", self._route, {
            "execute": "execute", "approval": "approval",
            "refresh_context": "refresh_context", "block": "block",
        })
        builder.add_conditional_edges("approval", self._route, {
            "execute": "execute", "approval": "block",
            "refresh_context": "refresh_context", "block": "block",
        })
        builder.add_conditional_edges("execute", self._after_execute, {
            "refresh_context": "refresh_context", "end": END,
        })
        builder.add_edge("refresh_context", "security_check")
        builder.add_edge("block", END)
        self.graph = builder.compile(checkpointer=InMemorySaver(serde=serializer))

    @staticmethod
    def _fields(result):
        return {
            "decision": result.decision.value, "reason": result.reason,
            "permit_id": result.permit_id, "approval_id": result.approval_id,
        }

    def _prepare(self, state):
        result = self.runtime.prepare(
            self._agent_token, state["call"], state["plan_context"]
        )
        details = None
        if result.decision == Decision.APPROVAL:
            details = self.runtime.approval_details(self._approver_token, result.approval_id)
        return {**self._fields(result), "approval_details": details}

    def _approve(self, state):
        # This node restarts on resume. Reuse the original review snapshot so
        # expiry/revocation reaches resolve_approval instead of failing inspection.
        approved = interrupt({"type": "human_approval", **state["approval_details"]})
        if type(approved) is not bool:
            raise TypeError("Human approval must be an explicit boolean")
        return self._fields(self.runtime.resolve_approval(
            self._approver_token, state["approval_id"], approved=approved
        ))

    def _execute(self, state):
        result = self.runtime.execute(self._agent_token, state["call"], state["permit_id"])
        return {**self._fields(result), "result": public_result(result)}

    def _refresh(self, state):
        return {
            "plan_context": self.runtime.policy.capture_context(),
            "permit_id": None, "approval_id": None, "approval_details": None, "result": None,
        }

    @staticmethod
    def _block(state):
        return {"result": {
            "status": "blocked", "decision": state["decision"],
            "executed": False, "output": None, "reason": state["reason"], "error": None,
        }}

    @staticmethod
    def _route(state):
        return {
            Decision.ALLOW.value: "execute", Decision.APPROVAL.value: "approval",
            Decision.REEVALUATE.value: "refresh_context", Decision.BLOCK.value: "block",
        }[state["decision"]]

    @staticmethod
    def _after_execute(state):
        # A permit can become stale between prepare/approval and dispatch.
        # Handler failures are terminal; they must not cause an automatic retry.
        return "refresh_context" if state["decision"] == Decision.REEVALUATE.value else "end"

    @staticmethod
    def _config(request_id):
        return {"configurable": {"thread_id": request_id}}

    def start(self, call: ToolCall, plan_context: PlanContext):
        return self.graph.invoke({
            "call": call, "plan_context": plan_context, "decision": "", "reason": "",
            "permit_id": None, "approval_id": None, "approval_details": None, "result": None,
        }, config=self._config(call.request_id))

    def resume(self, request_id: str, *, approved: bool):
        if type(approved) is not bool:
            raise TypeError("Human approval must be an explicit boolean")
        return self.graph.invoke(Command(resume=approved), config=self._config(request_id))
