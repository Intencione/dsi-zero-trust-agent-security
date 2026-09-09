from typing import TypedDict, Literal

from langgraph.graph import StateGraph, START, END

from agent_demo import DEMO_ENVIRONMENT, Decision
from secure_agent_demo import make_demo
from secure_runtime import ToolCall


# ============================================================
# Existing Security Runtime
# ============================================================

demo = make_demo()
runtime = demo.runtime


# ============================================================
# Graph State
# ============================================================

class SecurityState(TypedDict):
    call: ToolCall
    plan_context: object

    decision: str
    reason: str

    permit_id: str | None
    approval_id: str | None

    result: object


# ============================================================
# Security Node
# ============================================================

def security_check(state: SecurityState):
    print("\n[NODE] security_check")

    prepared = runtime.prepare(
        demo.agent_token,
        state["call"],
        state["plan_context"],
    )

    print(f"Decision: {prepared.decision.value}")
    print(f"Reason: {prepared.reason}")

    return {
        "decision": prepared.decision.value,
        "reason": prepared.reason,
        "permit_id": prepared.permit_id,
        "approval_id": prepared.approval_id,
    }


# ============================================================
# Execution Node
# ============================================================

def execute_node(state: SecurityState):
    print("[NODE] execute_node")

    result = runtime.execute(
        demo.agent_token,
        state["call"],
        state["permit_id"],
    )

    print(f"Executed: {result.executed}")
    print(f"Reason: {result.reason}")

    return {
        "result": result,
    }


# ============================================================
# Reevaluation Node
# ============================================================

def refresh_context_node(state: SecurityState):
    print("[NODE] refresh_context_node")
    print("Capturing fresh security context...")

    fresh_context = runtime.policy.capture_context()

    return {
        "plan_context": fresh_context,
    }


# ============================================================
# Block Node
# ============================================================

def block_node(state: SecurityState):
    print("[NODE] block_node")
    print(f"Action blocked: {state['reason']}")

    return {
        "result": {
            "status": "blocked",
            "reason": state["reason"],
        }
    }


# ============================================================
# Approval Node
# ============================================================

def approval_node(state: SecurityState):
    print("[NODE] approval_node")
    print("Human approval is required.")
    print(f"Approval ID: {state['approval_id']}")

    return {
        "result": {
            "status": "approval_required",
            "approval_id": state["approval_id"],
            "reason": state["reason"],
        }
    }


# ============================================================
# Router
# ============================================================

def route_security_decision(
    state: SecurityState,
) -> Literal[
    "execute_node",
    "block_node",
    "refresh_context_node",
    "approval_node",
]:

    if state["decision"] == Decision.ALLOW.value:
        return "execute_node"

    if state["decision"] == Decision.BLOCK.value:
        return "block_node"

    if state["decision"] == Decision.REEVALUATE.value:
        return "refresh_context_node"

    return "approval_node"


# ============================================================
# Build Graph
# ============================================================

builder = StateGraph(SecurityState)

builder.add_node("security_check", security_check)
builder.add_node("execute_node", execute_node)
builder.add_node("refresh_context_node", refresh_context_node)
builder.add_node("block_node", block_node)
builder.add_node("approval_node", approval_node)


builder.add_edge(
    START,
    "security_check",
)


builder.add_conditional_edges(
    "security_check",
    route_security_decision,
)


builder.add_edge(
    "refresh_context_node",
    "security_check",
)


builder.add_edge(
    "execute_node",
    END,
)

builder.add_edge(
    "block_node",
    END,
)

builder.add_edge(
    "approval_node",
    END,
)


graph = builder.compile()


# ============================================================
# Helper
# ============================================================

def run_call(label, call, plan_context):

    print("\n\n==========================================")
    print(label)
    print("==========================================")

    output = graph.invoke(
        {
            "call": call,
            "plan_context": plan_context,

            "decision": "",
            "reason": "",

            "permit_id": None,
            "approval_id": None,

            "result": None,
        }
    )

    print("\nFINAL GRAPH RESULT:")
    print(output["result"])


# ============================================================
# Test 1 — ALLOW
# ============================================================

normal_context = runtime.policy.capture_context()

read_call = ToolCall(
    task_id=demo.task_id,
    tool_name="read_document",
    resource_id=DEMO_ENVIRONMENT.resource_id,
    target_machine_id=DEMO_ENVIRONMENT.target_machine_id,
    instruction_id=demo.instruction_id,
    arguments=(
        ("path", "/finance/monthly.csv"),
    ),
)

run_call(
    "TEST 1 — NORMAL AUTHORIZED READ",
    read_call,
    normal_context,
)


# ============================================================
# Test 2 — BLOCK
# ============================================================

email_call = ToolCall(
    task_id=demo.task_id,
    tool_name="send_email",
    resource_id=DEMO_ENVIRONMENT.resource_id,
    target_machine_id=DEMO_ENVIRONMENT.target_machine_id,
    instruction_id=demo.instruction_id,
    arguments=(
        ("recipient", "colleague@example.test"),
        ("body", "Monthly report"),
    ),
)

run_call(
    "TEST 2 — EMAIL OUTSIDE TASK SCOPE",
    email_call,
    runtime.policy.capture_context(),
)


# ============================================================
# Test 3 — REEVALUATE -> BLOCK
# ============================================================

old_context = runtime.policy.capture_context()

runtime.policy.dsi.calculate(
    network_anomaly=100,
    unknown_operations=100,
    destructive_activity=100,
    other_alerts=100,
)

print("\n*** ENTERPRISE SECURITY INCIDENT ***")
print(
    f"Current DSI: {runtime.policy.dsi.score:.1f} "
    f"({runtime.policy.dsi.get_level().value})"
)
print(
    f"Security Epoch: {runtime.policy.dsi.epoch}"
)


report_call = ToolCall(
    task_id=demo.task_id,
    tool_name="generate_report",
    resource_id=DEMO_ENVIRONMENT.resource_id,
    target_machine_id=DEMO_ENVIRONMENT.target_machine_id,
    instruction_id=demo.instruction_id,
    arguments=(
        ("format", "pdf"),
    ),
)

run_call(
    "TEST 3 — STALE PLAN AFTER SECURITY INCIDENT",
    report_call,
    old_context,
)