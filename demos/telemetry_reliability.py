"""Deterministic continuity/restart demo; only local simulated effects."""

from dataclasses import replace
from pathlib import Path
import secrets
import tempfile

from agent_demo import EnvironmentType
from secure_agent_demo import make_demo
from telemetry.reliability import ReliableDSIService
from telemetry.simulator import SecurityEventSimulator
from telemetry.sources import TrustedSource


def main():
    now = [1000]
    clock = lambda: now[0]
    key = secrets.token_bytes(32)
    config = TrustedSource("sensor", key, reporting_interval=10, grace_period=5)
    with tempfile.TemporaryDirectory(prefix="dsi-continuity-") as directory:
        database = Path(directory) / "telemetry.sqlite"
        demo = make_demo(clock)
        service = ReliableDSIService.open_sqlite(demo.runtime.policy, database, sources=[config], clock=clock)
        try:
            simulator = SecurityEventSimulator(service, source_id="sensor", key=key)
            simulator.heartbeat()
            print("Healthy source:", service.source_status("sensor")["status"])
            demo.runtime.policy.update_environment(replace(
                demo.runtime.policy.environment, environment_type=EnvironmentType.PRODUCTION,
            ))
            call = demo.read_call()
            prepared = demo.runtime.prepare(demo.agent_token, call, demo.runtime.policy.capture_context())
            print("Pending action:", prepared.decision.value)
            simulator.stop_heartbeats()
            now[0] += 16
            service.refresh()
            print("Source outage:", service.source_status("sensor")["status"], service.status()["level"])
            approved = demo.runtime.resolve_approval(demo.user_token, prepared.approval_id, approved=True)
            fresh = demo.runtime.prepare(demo.agent_token, call, demo.runtime.policy.capture_context())
            print("Human approves:", approved.decision.value, "→", fresh.decision.value)
            simulator.recover()
            payload, proof = simulator.submission("network_anomaly", 100)
            service.ingest(payload, proof)
        finally:
            service.close()
        recovered_demo = make_demo(clock)
        recovered = ReliableDSIService.open_sqlite(recovered_demo.runtime.policy, database,
                                                  sources=[config], clock=clock)
        try:
            print("Restart restored DSI:", recovered.status()["score"])
            print("Replay after restart:", recovered.ingest(payload, proof).reason)
            print("Restored source:", recovered.source_status("sensor")["status"])
            print("Retained audit records:", len(recovered.audit))
        finally:
            recovered.close()


if __name__ == "__main__":
    main()
