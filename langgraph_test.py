from typing import TypedDict, Literal

from langgraph.graph import StateGraph, START, END


# ============================================================
# State
# ============================================================

class SecurityState(TypedDict):
    decision: str
    result: str


# ============================================================
# Nodes
# ============================================================

def security_check(state: SecurityState):
    print("\n[NODE] security_check")
    print(f"Decision received: {state['decision']}")

    # For now this node does not change anything.
    return {}


def allow_node(state: SecurityState):
    print("[NODE] allow_node")

    return {
        "result": "Action is allowed and may execute."
    }


def block_node(state: SecurityState):
    print("[NODE] block_node")

    return {
        "result": "Action is blocked."
    }


def reevaluate_node(state: SecurityState):
    print("[NODE] reevaluate_node")

    return {
        "result": "Security context must be refreshed and evaluated again."
    }


# ============================================================
# Conditional Router
# ============================================================

def route_security_decision(
    state: SecurityState
) -> Literal["allow_node", "block_node", "reevaluate_node"]:

    if state["decision"] == "ALLOW":
        return "allow_node"

    if state["decision"] == "BLOCK":
        return "block_node"

    return "reevaluate_node"


# ============================================================
# Build Graph
# ============================================================

builder = StateGraph(SecurityState)

builder.add_node("security_check", security_check)
builder.add_node("allow_node", allow_node)
builder.add_node("block_node", block_node)
builder.add_node("reevaluate_node", reevaluate_node)


# START -> security_check
builder.add_edge(
    START,
    "security_check"
)


# security_check -> one of three branches
builder.add_conditional_edges(
    "security_check",
    route_security_decision,
)


# Every branch ends for now
builder.add_edge("allow_node", END)
builder.add_edge("block_node", END)
builder.add_edge("reevaluate_node", END)


# Compile into an executable graph
graph = builder.compile()


# ============================================================
# Test
# ============================================================

for decision in ["ALLOW", "BLOCK", "REEVALUATE"]:

    print("\n===================================")
    print(f"TESTING: {decision}")

    output = graph.invoke(
        {
            "decision": decision,
            "result": "",
        }
    )

    print(f"FINAL RESULT: {output['result']}")