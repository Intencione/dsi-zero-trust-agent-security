from typing import TypedDict, Literal

from langchain.agents import create_agent
from langchain.tools import tool
from langchain_openai import ChatOpenAI

from langgraph.graph import StateGraph, START, END

from agent_demo import DEMO_ENVIRONMENT, Decision
from secure_agent_demo import make_demo
from secure_runtime import ToolCall


# ============================================================
# Existing DSI / Zero Trust Runtime
# ============================================================

demo = make_demo()
runtime = demo.runtime


# Security context under which the current agent run began.
current_plan_context = runtime.policy.capture_context()

# Used only for this demo so the simulated incident happens once.
security_event_triggered = False


# ============================================================
# LangGraph State
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
# LangGraph Nodes
# ============================================================

def security_check_node(state: SecurityState):
    print("\n[NODE] security_check")

    prepared = runtime.prepare(
        demo.agent_token,
        state["call"],
        state["plan_context"],
    )

    print(f"[SECURITY DECISION] {prepared.decision.value}")
    print(f"[REASON] {prepared.reason}")

    return {
        "decision": prepared.decision.value,
        "reason": prepared.reason,
        "permit_id": prepared.permit_id,
        "approval_id": prepared.approval_id,
    }


def execute_node(state: SecurityState):
    global security_event_triggered

    print("[NODE] execute")

    result = runtime.execute(
        demo.agent_token,
        state["call"],
        state["permit_id"],
    )

    print(f"[EXECUTED] {result.executed}")

    call = state["call"]

    # --------------------------------------------------------
    # Demo-only security incident
    # --------------------------------------------------------
    #
    # After the first successful document read,
    # simulate the enterprise entering crisis mode.
    #
    # In a real system this would come from SIEM / EDR /
    # network telemetry, not from the Agent workflow.
    # --------------------------------------------------------

    if (
        call.tool_name == "read_document"
        and result.executed
        and not security_event_triggered
    ):
        security_event_triggered = True

        print("\n*** SIMULATED ENTERPRISE SECURITY INCIDENT ***")

        runtime.policy.dsi.calculate(
            network_anomaly=100,
            unknown_operations=100,
            destructive_activity=100,
            other_alerts=100,
        )

        print(
            f"DSI changed to {runtime.policy.dsi.score:.1f} "
            f"({runtime.policy.dsi.get_level().value})"
        )

        print(
            f"Security Epoch is now "
            f"{runtime.policy.dsi.epoch}"
        )

    return {
        "result": {
            "status": "executed",
            "executed": result.executed,
            "output": result.output,
            "reason": result.reason,
        }
    }


def refresh_context_node(state: SecurityState):
    print("[NODE] refresh_context")
    print("[CAPTURING FRESH SECURITY CONTEXT]")

    fresh_context = runtime.policy.capture_context()

    return {
        "plan_context": fresh_context,
    }


def block_node(state: SecurityState):
    print("[NODE] block")

    return {
        "result": {
            "status": "blocked",
            "reason": state["reason"],
        }
    }


def approval_node(state: SecurityState):
    print("[NODE] approval")
    print("Human approval is required.")

    return {
        "result": {
            "status": "approval_required",
            "approval_id": state["approval_id"],
            "reason": state["reason"],
        }
    }


# ============================================================
# LangGraph Router
# ============================================================

def route_security_decision(
    state: SecurityState,
) -> Literal[
    "execute",
    "block",
    "refresh_context",
    "approval",
]:

    if state["decision"] == Decision.ALLOW.value:
        return "execute"

    if state["decision"] == Decision.BLOCK.value:
        return "block"

    if state["decision"] == Decision.REEVALUATE.value:
        return "refresh_context"

    if state["decision"] == Decision.APPROVAL.value:
        return "approval"

    raise ValueError(
        f"Unknown security decision: {state['decision']}"
    )


# ============================================================
# Build LangGraph
# ============================================================

builder = StateGraph(SecurityState)

builder.add_node(
    "security_check",
    security_check_node,
)

builder.add_node(
    "execute",
    execute_node,
)

builder.add_node(
    "refresh_context",
    refresh_context_node,
)

builder.add_node(
    "block",
    block_node,
)

builder.add_node(
    "approval",
    approval_node,
)


builder.add_edge(
    START,
    "security_check",
)


builder.add_conditional_edges(
    "security_check",
    route_security_decision,
)


builder.add_edge(
    "refresh_context",
    "security_check",
)


builder.add_edge(
    "execute",
    END,
)

builder.add_edge(
    "block",
    END,
)

builder.add_edge(
    "approval",
    END,
)


security_graph = builder.compile()


# ============================================================
# Security Graph Gateway
# ============================================================

def run_security_graph(call: ToolCall):
    global current_plan_context

    print("\n===================================")
    print("[LLM PROPOSED TOOL CALL]")
    print(f"Tool: {call.tool_name}")
    print(f"Arguments: {dict(call.arguments)}")

    output = security_graph.invoke(
        {
            "call": call,
            "plan_context": current_plan_context,

            "decision": "",
            "reason": "",

            "permit_id": None,
            "approval_id": None,

            "result": None,
        }
    )

    # Important:
    # If the graph refreshed the security context during
    # REEVALUATE, preserve that fresh context for future calls.
    current_plan_context = output["plan_context"]

    return output["result"]


# ============================================================
# LangChain Tools
# ============================================================

@tool
def read_document(path: str):
    """Read an enterprise document at the specified path."""

    call = ToolCall(
        task_id=demo.task_id,
        tool_name="read_document",
        resource_id=DEMO_ENVIRONMENT.resource_id,
        target_machine_id=DEMO_ENVIRONMENT.target_machine_id,
        instruction_id=demo.instruction_id,
        arguments=(
            ("path", path),
        ),
    )

    return run_security_graph(call)


@tool
def generate_report(format: Literal["pdf"]):
    """Generate the financial report. The supported format is pdf."""

    call = ToolCall(
        task_id=demo.task_id,
        tool_name="generate_report",
        resource_id=DEMO_ENVIRONMENT.resource_id,
        target_machine_id=DEMO_ENVIRONMENT.target_machine_id,
        instruction_id=demo.instruction_id,
        arguments=(
            ("format", format),
        ),
    )

    return run_security_graph(call)


@tool
def send_email(recipient: str, body: str):
    """Send an email to the specified recipient."""

    call = ToolCall(
        task_id=demo.task_id,
        tool_name="send_email",
        resource_id=DEMO_ENVIRONMENT.resource_id,
        target_machine_id=DEMO_ENVIRONMENT.target_machine_id,
        instruction_id=demo.instruction_id,
        arguments=(
            ("recipient", recipient),
            ("body", body),
        ),
    )

    return run_security_graph(call)


# ============================================================
# Model
# ============================================================

model = ChatOpenAI(
    model="gpt-5.6-luna",
    use_responses_api=True,
)


# ============================================================
# LangChain Agent
# ============================================================

agent = create_agent(
    model=model,
    tools=[
        read_document,
        generate_report,
        send_email,
    ],
    system_prompt="""
You are an enterprise finance AI agent.

You may propose actions using the provided tools.

Tool execution is controlled by an independent enterprise
security runtime through a security graph.

You must never assume that access to a tool means that
the action is authorized.

If an action is blocked, do not attempt to bypass the
security decision.

If the security environment changes, the system may
re-evaluate previously valid actions.

Complete the user's task using authorized tools only.
""",
)


# ============================================================
# Run
# ============================================================

result = agent.invoke(
    {
        "messages": [
            {
                "role": "user",
                "content":
                    "Read /finance/monthly.csv and generate a PDF report."
            }
        ]
    }
)


# ============================================================
# Final Agent Response
# ============================================================

print("\n\n========== FINAL AGENT RESPONSE ==========")

final_message = result["messages"][-1]

try:
    print(final_message.text)
except Exception:
    print(final_message.content)