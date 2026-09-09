from typing import Literal

from langchain.agents import create_agent
from langchain.tools import tool
from langchain_openai import ChatOpenAI

from agent_demo import DEMO_ENVIRONMENT, Decision
from secure_agent_demo import make_demo
from secure_runtime import ToolCall


# ============================================================
# Existing DSI / Zero Trust Runtime
# ============================================================

demo = make_demo()
runtime = demo.runtime


# This represents the security state under which
# the current agent plan was formed.
plan_context = runtime.policy.capture_context()


# Used so the simulated incident only happens once.
security_event_triggered = False


# ============================================================
# Security Gateway
# ============================================================

def secure_tool_call(tool_name: str, arguments: dict):
    """
    Convert an LLM-proposed tool action into our trusted ToolCall,
    then send it through SecureRuntime.
    """

    global security_event_triggered

    call = ToolCall(
        task_id=demo.task_id,
        tool_name=tool_name,
        resource_id=DEMO_ENVIRONMENT.resource_id,
        target_machine_id=DEMO_ENVIRONMENT.target_machine_id,
        instruction_id=demo.instruction_id,
        arguments=tuple(arguments.items()),
    )

    print("\n===================================")
    print("[LLM PROPOSED TOOL CALL]")
    print(f"Tool: {tool_name}")
    print(f"Arguments: {arguments}")

    # --------------------------------------------------------
    # First authorization attempt using the original plan context
    # --------------------------------------------------------

    prepared = runtime.prepare(
        demo.agent_token,
        call,
        plan_context,
    )

    print(f"[SECURITY DECISION] {prepared.decision.value}")
    print(f"[REASON] {prepared.reason}")

    # --------------------------------------------------------
    # ALLOW
    # --------------------------------------------------------

    if prepared.decision == Decision.ALLOW:

        result = runtime.execute(
            demo.agent_token,
            call,
            prepared.permit_id,
        )

        print(f"[EXECUTED] {result.executed}")

        # Simulate an enterprise security incident only AFTER
        # the first successful document read.
        if (
            tool_name == "read_document"
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
            "status": "executed",
            "output": result.output,
        }

    # --------------------------------------------------------
    # HUMAN APPROVAL
    # --------------------------------------------------------

    if prepared.decision == Decision.APPROVAL:
        return {
            "status": "approval_required",
            "approval_id": prepared.approval_id,
            "reason": prepared.reason,
        }

    # --------------------------------------------------------
    # REEVALUATE
    # --------------------------------------------------------

    if prepared.decision == Decision.REEVALUATE:

        print("[REEVALUATION REQUIRED]")
        print("[CAPTURING FRESH SECURITY CONTEXT]")

        fresh_context = runtime.policy.capture_context()

        reevaluated = runtime.prepare(
            demo.agent_token,
            call,
            fresh_context,
        )

        print(
            f"[FRESH SECURITY DECISION] "
            f"{reevaluated.decision.value}"
        )

        print(
            f"[FRESH REASON] "
            f"{reevaluated.reason}"
        )

        # Fresh decision = ALLOW
        if reevaluated.decision == Decision.ALLOW:

            result = runtime.execute(
                demo.agent_token,
                call,
                reevaluated.permit_id,
            )

            print(f"[EXECUTED AFTER REEVALUATION] {result.executed}")

            return {
                "status": "executed_after_reevaluation",
                "output": result.output,
            }

        # Fresh decision = APPROVAL
        if reevaluated.decision == Decision.APPROVAL:
            return {
                "status": "approval_required_after_reevaluation",
                "approval_id": reevaluated.approval_id,
                "reason": reevaluated.reason,
            }

        # Fresh decision = BLOCK or another REEVALUATE
        return {
            "status": reevaluated.decision.value,
            "reason": reevaluated.reason,
        }

    # --------------------------------------------------------
    # BLOCK
    # --------------------------------------------------------

    return {
        "status": "blocked",
        "reason": prepared.reason,
    }


# ============================================================
# LangChain Tools
# ============================================================

@tool
def read_document(path: str):
    """Read an enterprise document at the specified path."""

    return secure_tool_call(
        "read_document",
        {
            "path": path,
        },
    )


@tool
def generate_report(format: Literal["pdf"]):
    """Generate the financial report. The supported format is pdf."""

    return secure_tool_call(
        "generate_report",
        {
            "format": format,
        },
    )


@tool
def send_email(recipient: str, body: str):
    """Send an email to the specified recipient."""

    return secure_tool_call(
        "send_email",
        {
            "recipient": recipient,
            "body": body,
        },
    )


# ============================================================
# Model
# ============================================================

model = ChatOpenAI(
    model="gpt-5.6-luna",
    use_responses_api=True,
)


# ============================================================
# Agent
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

You may propose actions through the provided tools.

Tool execution is controlled by an independent enterprise
security runtime. You must never assume that having access
to a tool means that an action is authorized.

If a tool action is blocked, do not attempt to bypass the
security decision.

Complete the user's task using authorized tools.
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
# Final Response
# ============================================================

print("\n\n========== FINAL AGENT RESPONSE ==========")

final_message = result["messages"][-1]

try:
    print(final_message.text)
except Exception:
    print(final_message.content)