"""Composition root: provision mock authority, tools, telemetry, and the agent."""

import argparse
from dataclasses import dataclass, replace
from enum import Enum
import json
import secrets
from threading import RLock
import time
import tempfile
from pathlib import Path

from agent.models import build_agent, openai_model
from agent.security_workflow import SecurityWorkflow
from agent.tools import TaskBinding, build_tools
from agent_demo import (
    DEMO_ENVIRONMENT, EnvironmentType, GENERATE_FINANCIAL_REPORT,
    READ_INTERNAL_DOCUMENT, SEND_EMAIL,
)
from secure_agent_demo import DemoSetup, make_demo
from telemetry.dsi_service import DSIService
from telemetry.simulator import SecurityEventSimulator
from telemetry.sources import HMACSourceVerifier, SourceRegistry, TrustedSource


def review_json_value(value):
    if isinstance(value, Enum):
        return value.value
    raise TypeError(f"Unsupported approval display value: {type(value).__name__}")


def console_review(details):
    print("\nHUMAN APPROVAL REQUIRED — exact request snapshot")
    print(json.dumps(details, indent=2, default=review_json_value))
    return input("Approve this exact action? [y/N]: ").strip().lower() in ("y", "yes")


class DemoDriver:
    """Trusted host resumes interrupts and schedules events outside graph nodes.

    Serialization is local to this demo driver. It is not a distributed runtime
    lock or an atomic authorization/remote-execution guarantee.
    """

    def __init__(self, workflow, simulator, review, scenario, log):
        if simulator.service.policy is not workflow.runtime.policy:
            raise ValueError("Simulator and runtime must share the same PolicyEngine")
        self.workflow = workflow
        self.simulator = simulator
        self.review = review
        self.scenario = scenario
        self.log = log
        self.plan_context = workflow.runtime.policy.capture_context()
        self._lock = RLock()

    def _incident(self):
        status = self.simulator.trigger_incident()
        self.log(f"[SIMULATED TELEMETRY] {status}")

    def __call__(self, call):
        with self._lock:
            self.simulator.service.refresh()
            audit_start = len(self.workflow.runtime.audit)
            output = self.workflow.start(call, self.plan_context)
            # Re-evaluation may require another, new approval. Never carry the
            # earlier human answer over to a new pending authorization.
            while output.get("__interrupt__"):
                details = output["__interrupt__"][0].value
                if self.scenario == "approval-incident":
                    self._incident()
                approved = self.review(details)
                self.simulator.service.refresh()
                output = self.workflow.resume(call.request_id, approved=approved)
            self.plan_context = output["plan_context"]
            result = output["result"]
            if self.scenario == "after-read" and call.tool_name == "read_document" and result["executed"]:
                self._incident()
            for entry in self.workflow.runtime.audit[audit_start:]:
                self.log(f"[{entry['stage']}] {entry['decision']} | {entry['reason']}")
            return result


@dataclass
class FinanceDemo:
    setup: DemoSetup
    dsi_service: DSIService
    simulator: SecurityEventSimulator
    workflow: SecurityWorkflow
    driver: DemoDriver
    tools: list


def build_finance_demo(*, scenario="approval-incident", review=console_review,
                       log=print, clock=time.time, reliable_telemetry=False,
                       authorization_path=None):
    if scenario not in ("approval-incident", "after-read", "none"):
        raise ValueError("Unknown demo scenario")
    setup = make_demo(clock)
    runtime = setup.runtime
    if scenario != "after-read":
        runtime.policy.update_environment(replace(
            DEMO_ENVIRONMENT, environment_type=EnvironmentType.PRODUCTION
        ))

    def read_document(call):
        setup.effects.append(call)
        path = dict(call.arguments)["path"]
        if path != "/finance/monthly.csv":
            return {"simulated": True, "error": "File not found"}
        return {
            "simulated": True, "path": path,
            "content": {"revenue": 120000, "expenses": 80000, "profit": 40000},
        }

    def generate_report(call):
        setup.effects.append(call)
        return {
            "simulated": True, "generated": True, "format": dict(call.arguments)["format"],
            "report": "Monthly financial report",
        }

    def send_email(call):
        setup.effects.append(call)
        return {"simulated": True, "sent": True, "recipient": dict(call.arguments)["recipient"]}

    runtime.register_tool("read_document", READ_INTERNAL_DOCUMENT, {"path": "string"}, read_document)
    runtime.register_tool("generate_report", GENERATE_FINANCIAL_REPORT, {"format": "string"}, generate_report)
    runtime.register_tool("send_email", SEND_EMAIL, {"recipient": "string", "body": "string"}, send_email)

    if authorization_path is not None:
        from authorization.store import SQLiteAuthorizationStore
        from authorization.runtime import PersistentSecureRuntime
        store = SQLiteAuthorizationStore(authorization_path)
        if store.load() is not None:
            store.close()
            raise ValueError("Existing authorization requires original host identity/provenance; use explicit recovery, not fresh demo provisioning")
        runtime = PersistentSecureRuntime(runtime, store)
        setup.runtime = runtime

    source_key = secrets.token_bytes(32)
    sources = SourceRegistry([TrustedSource("demo-security", source_key)])
    if reliable_telemetry:
        from telemetry.reliability import ReliableDSIService
        if authorization_path is None:
            service = ReliableDSIService(runtime.policy, clock=clock,
                                         sources=[TrustedSource("demo-security", source_key)])
        else:
            service = ReliableDSIService.open_sqlite(runtime.policy, authorization_path,
                clock=clock, sources=[TrustedSource("demo-security", source_key)])
    else:
        service = DSIService(runtime.policy, clock=clock, verifier=HMACSourceVerifier(sources))
    simulator = SecurityEventSimulator(service, source_id="demo-security", key=source_key)
    if reliable_telemetry:
        simulator.heartbeat()
    if authorization_path is None:
        workflow = SecurityWorkflow(runtime, setup.agent_token, setup.user_token)
    else:
        from agent.persistent_workflow import PersistentSecurityWorkflow
        workflow = PersistentSecurityWorkflow(runtime, setup.agent_token, setup.user_token)
    driver = DemoDriver(workflow, simulator, review, scenario, log)
    binding = TaskBinding(
        setup.task_id, setup.instruction_id,
        setup.read_rule.resource_id, setup.read_rule.target_machine_id,
    )
    return FinanceDemo(setup, service, simulator, workflow, driver, build_tools(binding, driver))


def main(argv=None, *, default_scenario="approval-incident"):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--offline", action="store_true", help="Use a scripted model fixture; no API calls")
    parser.add_argument("--auto-approve", action="store_true", help="Simulate a human approving (offline only)")
    parser.add_argument("--scenario", choices=("approval-incident", "after-read", "none"), default=default_scenario)
    parser.add_argument("--model", default="gpt-5.6-luna", help="Live OpenAI model name")
    parser.add_argument("--in-memory", action="store_true", help="Legacy deterministic test workflow")
    parser.add_argument("--state-db", help="New SQLite authorization/checkpoint file; host credentials are not stored here")
    parser.add_argument("--reliable-telemetry", action=argparse.BooleanOptionalAction, default=True,
                        help="Source-health continuity; --no-reliable-telemetry selects the Phase 2 fixture")
    args = parser.parse_args(argv)
    if args.auto_approve and not args.offline:
        parser.error("--auto-approve is only for the offline simulated-human demo")
    if args.offline:
        from demos.scripted_model import ScriptedFinanceModel
        model = ScriptedFinanceModel()
    else:
        model = openai_model(args.model)
    print("RESEARCH DEMO: simulated identity, telemetry, human sessions, and tool effects.")
    print("Model: " + ("scripted fixture (not an LLM)" if args.offline else args.model))
    if args.in_memory and args.state_db:
        parser.error("--in-memory and --state-db are mutually exclusive")
    state_db = None if args.in_memory else (args.state_db or str(
        Path(tempfile.mkdtemp(prefix="dsi-authorization-")) / "runtime.sqlite"))
    if state_db:
        print(f"Persistent authorization and checkpoints: {state_db}")
    demo = build_finance_demo(
        scenario=args.scenario, review=(lambda details: True) if args.auto_approve else console_review,
        reliable_telemetry=args.reliable_telemetry,
        authorization_path=state_db,
    )
    result = build_agent(model, demo.tools).invoke({"messages": [{
        "role": "user", "content": "Read /finance/monthly.csv and generate a PDF report. Do not send it."
    }]})
    print("\nFINAL AGENT RESPONSE")
    print(result["messages"][-1].text)


if __name__ == "__main__":
    main()
