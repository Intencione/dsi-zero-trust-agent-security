"""Operational health, rotation and restart coverage with fake time only."""

from dataclasses import asdict, replace
from contextlib import closing
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from agent_demo import Decision, EnvironmentType
from secure_agent_demo import make_demo
from telemetry.dsi_service import DSIService, TelemetryLimits
from telemetry.events import EventType, SIGNAL_TYPES
from telemetry.reliability import ReliableDSIService, TelemetryUnavailable
from telemetry.simulator import SecurityEventSimulator
from telemetry.sources import TrustedSource, sign_event
from telemetry.sqlite_store import SQLiteEventStore
from telemetry.store import InMemoryEventStore


KEY = b"continuity-test-source-secret-001!"
NEW_KEY = b"continuity-test-source-secret-002!"


class Clock:
    def __init__(self, now=1000):
        self.now = now

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


def source(name="sensor", **changes):
    return TrustedSource(name, KEY, reporting_interval=10, grace_period=5, **changes)


class ContinuityTests(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self.demo = make_demo(self.clock)
        self.store = InMemoryEventStore()
        self.service = ReliableDSIService(self.demo.runtime.policy, sources=[source()],
                                          clock=self.clock, store=self.store,
                                          limits=TelemetryLimits(event_lifetime=30))
        self.sim = SecurityEventSimulator(self.service, source_id="sensor", key=KEY)

    def status(self):
        return self.service.source_status("sensor")["status"]

    def test_no_contact_is_offline_and_conservative(self):
        self.assertEqual(self.status(), "OFFLINE")
        self.assertEqual(self.service.status()["level"], "CRISIS")

    def test_healthy_heartbeat_and_no_threat_is_distinct_from_silence(self):
        self.sim.heartbeat()
        self.assertEqual(self.status(), "HEALTHY")
        self.assertEqual(self.service.status()["score"], 0)
        self.clock.advance(10)
        self.assertEqual(self.status(), "HEALTHY")
        self.sim.heartbeat()
        self.clock.advance(10)
        self.assertEqual(self.status(), "HEALTHY")

    def test_deterministic_health_thresholds(self):
        self.sim.heartbeat()
        for now, expected in ((1010, "HEALTHY"), (1010.1, "DEGRADED"), (1015, "DEGRADED"),
                              (1015.1, "STALE"), (1020, "STALE"), (1020.1, "OFFLINE")):
            self.clock.now = now
            self.assertEqual(self.status(), expected)
        reasons = [item.reason for item in self.service.audit if item.outcome == "source_health"]
        self.assertIn("HEALTHY->DEGRADED", reasons)
        self.assertIn("DEGRADED->STALE", reasons)
        self.assertIn("STALE->OFFLINE", reasons)

    def test_standard_criticality_has_longer_offline_threshold(self):
        demo = make_demo(self.clock)
        service = ReliableDSIService(demo.runtime.policy, sources=[source(criticality="standard")], clock=self.clock)
        sim = SecurityEventSimulator(service, source_id="sensor", key=KEY)
        sim.heartbeat()
        self.clock.advance(21)
        self.assertEqual(service.source_status("sensor")["status"], "STALE")
        self.assertEqual(service.status()["level"], "CRISIS")
        self.clock.advance(10)
        self.assertEqual(service.source_status("sensor")["status"], "OFFLINE")

    def test_delayed_authenticated_source_is_degraded(self):
        self.sim.heartbeat(delay=6)
        status = self.service.source_status("sensor")
        self.assertEqual(status["status"], "DEGRADED")
        self.assertEqual(status["last_authenticated_contact"], 1000)
        self.assertEqual(status["last_observed_at"], 994)
        self.assertEqual(self.service.status()["level"], "CRISIS")
        self.sim.recover()
        self.assertEqual(self.status(), "HEALTHY")

    def test_silence_keeps_threat_after_nominal_expiration(self):
        self.sim.multi_signal_crisis()
        self.sim.stop_heartbeats()
        self.clock.advance(31)
        self.assertIsNone(self.sim.scheduled_heartbeat())
        self.assertEqual(self.service.refresh()["score"], 100)
        self.assertEqual(len([event for event in self.store.active() if event.severity]), 4)
        self.sim.recover()
        self.assertEqual(self.status(), "HEALTHY")
        self.assertEqual(self.service.status()["score"], 100)
        self.sim.normal_environment()
        self.assertEqual(self.service.status()["score"], 0)

    def test_heartbeat_recovery_cannot_hide_unobserved_outage_expiry(self):
        self.sim.multi_signal_crisis()
        self.clock.advance(301)
        # No intermediate maintenance: accepting recovery must first protect
        # alerts that reached their lifetime while this source was unavailable.
        self.sim.recover()
        self.assertEqual(self.service.status()["score"], 100)

    def test_silence_after_normal_report_does_not_mean_normal_environment(self):
        self.sim.normal_environment()
        self.clock.advance(31)
        self.assertEqual(self.service.refresh()["level"], "CRISIS")

    def test_healthy_expiration_is_allowed_without_resurrection(self):
        self.sim.network_anomaly()
        for _ in range(3):
            self.clock.advance(10)
            self.sim.heartbeat()
        self.assertEqual(self.service.status()["score"], 0)
        self.clock.advance(100)
        self.service.refresh()
        self.assertFalse(any(event.event_type == EventType.NETWORK_ANOMALY for event in self.store.active()))

    def test_recovery_does_not_clear_another_source(self):
        demo = make_demo(self.clock)
        service = ReliableDSIService(demo.runtime.policy, sources=[source("a"), source("b")], clock=self.clock)
        a = SecurityEventSimulator(service, source_id="a", key=KEY)
        b = SecurityEventSimulator(service, source_id="b", key=KEY)
        a.heartbeat()
        b.multi_signal_crisis()
        self.clock.advance(301)
        service.refresh()
        a.recover()
        a.normal_environment()
        b.recover()
        self.assertEqual(service.status()["score"], 100)

    def test_authentication_contact_does_not_make_replays_healthy(self):
        event, proof = self.sim.submission(EventType.HEARTBEAT, 0)
        self.service.ingest(event, proof)
        self.clock.advance(21)
        self.assertFalse(self.service.ingest(event, proof).accepted)
        status = self.service.source_status("sensor")
        self.assertEqual(status["last_authenticated_contact"], 1021)
        self.assertEqual(status["last_accepted_event"], 1000)
        self.assertEqual(status["last_observed_sequence"], 1)
        self.assertEqual(status["status"], "OFFLINE")

    def test_unknown_and_invalid_auth_do_not_update_contact(self):
        event, proof = self.sim.submission(EventType.HEARTBEAT, 0)
        self.assertEqual(self.service.ingest(event, "x").reason, "invalid_authentication")
        self.assertIsNone(self.service.source_status("sensor")["last_authenticated_contact"])
        unknown = {**event, "source_id": "unknown"}
        self.assertEqual(self.service.ingest(unknown, sign_event(unknown, KEY)).reason, "unknown_source")

    def test_rotated_key_accepted_and_old_key_retired(self):
        self.sim.heartbeat()
        self.sim.rotate_key(2, NEW_KEY)
        self.sim.heartbeat()
        old = {**self.sim.submission(EventType.HEARTBEAT, 0)[0], "key_version": 1}
        self.assertEqual(self.service.ingest(old, sign_event(old, KEY)).reason, "retired_or_unknown_key")
        self.assertEqual(self.service.source_status("sensor")["current_version"], 2)
        self.assertTrue(any(item.outcome == "key_rotation" for item in self.service.audit))

    def test_rotation_overlap_is_bounded_and_expires_at_exact_boundary(self):
        self.sim.heartbeat()
        self.sim.rotate_key(2, NEW_KEY, overlap=5)
        event = self.sim.submission(EventType.HEARTBEAT, 0)[0]
        event["key_version"] = 1
        self.assertTrue(self.service.ingest(event, sign_event(event, KEY)).accepted)
        self.clock.advance(5)
        event = {**event, "event_id": "new-id", "sequence": 3, "observed_at": self.clock()}
        self.assertEqual(self.service.ingest(event, sign_event(event, KEY)).reason, "retired_or_unknown_key")
        self.sim.heartbeat()

    def test_rotation_does_not_reset_replay_sequence(self):
        self.sim.heartbeat()
        self.sim.rotate_key(2, NEW_KEY)
        event, _ = self.sim.submission(EventType.HEARTBEAT, 0)
        event.update(sequence=1, event_id="renamed")
        self.assertEqual(self.service.ingest(event, sign_event(event, NEW_KEY)).reason, "replayed_sequence")

    def test_subsequent_rotation_cannot_extend_retirement(self):
        self.sim.rotate_key(2, NEW_KEY, overlap=5)
        self.clock.advance(1)
        self.sim.rotate_key(3, b"third-rotation-credential-key-003", overlap=100)
        self.assertEqual(self.store.control["sources"]["sensor"]["versions"]["1"]["retire_at"], 1005)

    def test_concurrent_rotations_cannot_replace_the_same_key_version(self):
        def rotate(key):
            try:
                self.service.rotate_key("sensor", 2, key)
                return True
            except ValueError:
                return False
        with ThreadPoolExecutor(max_workers=2) as pool:
            accepted = list(pool.map(rotate, (NEW_KEY, b"concurrent-other-key-version-0002")))
        self.assertEqual(sum(accepted), 1)
        self.assertEqual(sum(item.outcome == "key_rotation" for item in self.service.audit), 1)

    def test_invalid_rotation_does_not_modify_dsi_or_key_metadata(self):
        self.sim.heartbeat()
        before = vars(self.demo.runtime.policy.dsi).copy()
        config = json.dumps(self.store.control["sources"], sort_keys=True)
        for version, key, overlap in ((True, NEW_KEY, 0), (1, NEW_KEY, 0), (2, b"weak", 0),
                                      (2, NEW_KEY, -1), (2, NEW_KEY, 301), (2, KEY, 0)):
            with self.subTest(version=version, overlap=overlap), self.assertRaises(ValueError):
                self.service.rotate_key("sensor", version, key, overlap=overlap)
            self.assertEqual(vars(self.demo.runtime.policy.dsi), before)
            self.assertEqual(json.dumps(self.store.control["sources"], sort_keys=True), config)

    def test_disabling_denies_events_and_enabling_requires_fresh_contact(self):
        self.sim.heartbeat()
        self.service.set_source_enabled("sensor", False)
        self.assertEqual(self.status(), "DISABLED")
        self.assertEqual(self.service.ingest(*self.sim.submission(EventType.HEARTBEAT, 0)).reason, "source_disabled")
        self.service.set_source_enabled("sensor", True)
        self.assertEqual(self.status(), "OFFLINE")
        self.assertEqual(self.service.source_status("sensor")["last_accepted_event"], 1000)
        self.assertEqual(self.service.status()["level"], "CRISIS")
        self.sim.recover()
        self.assertEqual(self.status(), "HEALTHY")

    def test_malformed_source_operations_cannot_modify_dsi(self):
        self.sim.heartbeat()
        before = vars(self.demo.runtime.policy.dsi).copy()
        for source_id, enabled in (("sensor", "yes"), ("unknown", True), ([], True)):
            with self.assertRaises(ValueError):
                self.service.set_source_enabled(source_id, enabled)
            self.assertEqual(vars(self.demo.runtime.policy.dsi), before)

    def test_untrusted_metadata_cannot_mark_source_healthy_or_rotate_keys(self):
        self.sim.heartbeat(delay=6)
        event, proof = self.sim.submission(EventType.HEARTBEAT, 0, observed_at=994,
                                          metadata={"health": "HEALTHY", "enabled": True, "key_version": 999})
        self.assertTrue(self.service.ingest(event, proof).accepted)
        self.assertEqual(self.status(), "DEGRADED")
        self.assertEqual(self.service.source_status("sensor")["current_version"], 1)

    def test_outage_during_pending_authorization_revalidates(self):
        self.sim.heartbeat()
        runtime = self.demo.runtime
        runtime.policy.update_environment(replace(runtime.policy.environment, environment_type=EnvironmentType.PRODUCTION))
        call = self.demo.read_call()
        prepared = runtime.prepare(self.demo.agent_token, call, runtime.policy.capture_context())
        self.assertEqual(prepared.decision, Decision.APPROVAL)
        self.clock.advance(16)
        self.service.refresh()
        resolved = runtime.resolve_approval(self.demo.user_token, prepared.approval_id, approved=True)
        self.assertEqual(resolved.decision, Decision.REEVALUATE)
        fresh = runtime.prepare(self.demo.agent_token, call, runtime.policy.capture_context())
        self.assertEqual(fresh.decision, Decision.BLOCK)
        self.assertFalse(self.demo.effects)

    def test_health_clock_failure_latches_crisis_and_is_visible(self):
        self.sim.heartbeat()
        self.clock.advance(-1)
        with self.assertRaises(TelemetryUnavailable):
            self.service.refresh()
        self.assertEqual(self.demo.runtime.policy.dsi.get_level().value, "CRISIS")
        self.assertIsNotNone(self.service.service_fault)
        self.assertEqual(self.service.audit[-1].outcome, "service_failure")

    def test_no_secrets_in_audit_or_persistable_state(self):
        self.sim.heartbeat()
        self.sim.rotate_key(2, NEW_KEY)
        text = json.dumps(self.store.snapshot())
        for key in (KEY, NEW_KEY):
            self.assertNotIn(key.decode(), text)
        self.assertTrue(any(item.outcome == "key_rotation" for item in self.service.audit))


class PersistenceTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "telemetry.sqlite"
        self.clock = Clock()
        self.service = None
        self.start()
        self.addCleanup(lambda: self.service.close() if self.service else None)

    def start(self, *, keys=None):
        self.demo = make_demo(self.clock)
        self.service = ReliableDSIService.open_sqlite(
            self.demo.runtime.policy, self.path, sources=[source()] if keys is None else (),
            keys=keys, clock=self.clock, limits=TelemetryLimits(event_lifetime=30),
        )
        self.sim = SecurityEventSimulator(self.service, source_id="sensor", key=KEY)

    def restart(self, **kwargs):
        self.service.close()
        self.start(**kwargs)

    def test_active_events_audit_sequence_and_health_survive_restart(self):
        self.sim.network_anomaly()
        before = [asdict(item) for item in self.service.audit]
        self.clock.advance(5)
        self.restart()
        self.assertEqual(self.service.status()["score"], 30)
        state = self.service.source_status("sensor")
        self.assertEqual(state["status"], "HEALTHY")
        self.assertEqual(state["last_observed_sequence"], 1)
        self.assertEqual(state["last_authenticated_contact"], 1000)
        self.assertEqual([asdict(item) for item in self.service.audit[:len(before)]], before)
        self.assertTrue(any(item.outcome == "recovery" for item in self.service.audit))

    def test_id_and_sequence_replay_survive_restart(self):
        event, proof = self.sim.submission(EventType.NETWORK_ANOMALY, 100)
        self.service.ingest(event, proof)
        self.restart()
        self.assertEqual(self.service.ingest(event, proof).reason, "duplicate_event")
        renamed = {**event, "event_id": "new-id"}
        self.assertEqual(self.service.ingest(renamed, sign_event(renamed, KEY)).reason, "replayed_sequence")

    def test_offline_restart_preserves_expired_but_unresolved_threat(self):
        self.sim.multi_signal_crisis()
        self.clock.advance(31)
        self.restart()
        self.assertEqual(self.service.status()["score"], 100)
        self.assertEqual(self.service.source_status("sensor")["status"], "OFFLINE")
        self.assertEqual(len(self.service._store.active()), 4)

    def test_expired_events_do_not_regain_influence_after_restart(self):
        self.sim.network_anomaly()
        for _ in range(3):
            self.clock.advance(10)
            self.sim.heartbeat()
        self.assertEqual(self.service.status()["score"], 0)
        self.restart()
        self.assertEqual(self.service.status()["score"], 0)
        self.assertFalse(any(e.event_type == EventType.NETWORK_ANOMALY for e in self.service._store.active()))
        old = {"event_id": "sensor:1", "source_id": "sensor", "sequence": 1,
               "event_type": "network_anomaly", "severity": 100, "observed_at": self.clock()}
        self.assertEqual(self.service.ingest(old, sign_event(old, KEY)).reason, "duplicate_event")

    def test_rotation_metadata_survives_restart_and_old_key_stays_retired(self):
        self.sim.heartbeat()
        self.sim.rotate_key(2, NEW_KEY)
        self.restart(keys={("sensor", 2): NEW_KEY})
        event = {"event_id": "post-restart", "source_id": "sensor", "sequence": 2,
                 "event_type": "heartbeat", "severity": 0, "observed_at": self.clock(), "key_version": 1}
        self.assertEqual(self.service.ingest(event, sign_event(event, KEY)).reason, "retired_or_unknown_key")
        event["key_version"] = 2
        self.assertTrue(self.service.ingest(event, sign_event(event, NEW_KEY)).accepted)

    def test_overlap_deadline_is_not_extended_by_restart(self):
        self.sim.heartbeat()
        self.sim.rotate_key(2, NEW_KEY, overlap=5)
        self.clock.advance(5)
        self.restart(keys={("sensor", 2): NEW_KEY})
        event = {"event_id": "retired", "source_id": "sensor", "sequence": 2,
                 "event_type": "heartbeat", "severity": 0, "observed_at": self.clock(), "key_version": 1}
        self.assertEqual(self.service.ingest(event, sign_event(event, KEY)).reason, "retired_or_unknown_key")

    def test_disabled_source_restores_without_implicit_reenable(self):
        self.sim.heartbeat()
        self.service.set_source_enabled("sensor", False)
        self.restart()
        self.assertEqual(self.service.source_status("sensor")["status"], "DISABLED")
        self.assertEqual(self.service.ingest(*self.sim.submission(EventType.HEARTBEAT, 0)).reason, "source_disabled")

    def test_commit_failure_rolls_back_replay_and_latches_service(self):
        self.sim.heartbeat()
        event, proof = self.sim.submission(EventType.NETWORK_ANOMALY, 100)
        with patch.object(self.service._store, "_commit_snapshot", side_effect=sqlite3.OperationalError("failure")):
            with self.assertRaises(TelemetryUnavailable):
                self.service.ingest(event, proof)
        self.assertEqual(self.demo.runtime.policy.dsi.get_level().value, "CRISIS")
        self.assertEqual(self.service.audit[-1].outcome, "service_failure")
        with self.assertRaises(TelemetryUnavailable):
            self.service.refresh()
        self.restart()
        self.assertTrue(self.service.ingest(event, proof).accepted)

    def test_runtime_cannot_observe_risk_reduction_before_durable_commit(self):
        shared_dsi = self.demo.runtime.policy.dsi
        self.assertEqual(shared_dsi.score, 95)
        commit = self.service._store._commit_snapshot
        observed = []
        def inspect_then_commit():
            observed.append(shared_dsi.score)
            commit()
        with patch.object(self.service._store, "_commit_snapshot", side_effect=inspect_then_commit):
            self.sim.heartbeat()
        self.assertTrue(observed)
        self.assertEqual(observed[0], 95)
        self.assertEqual(shared_dsi.score, 0)
        self.assertIs(shared_dsi, self.service.policy.dsi)

    def test_failed_recovery_missing_key_is_not_normal(self):
        self.sim.multi_signal_crisis()
        self.service.close()
        demo = make_demo(self.clock)
        with self.assertRaises(TelemetryUnavailable):
            ReliableDSIService.open_sqlite(demo.runtime.policy, self.path, keys={}, clock=self.clock)
        self.assertGreaterEqual(demo.runtime.policy.dsi.score, 95)

    def test_missing_database_state_is_not_silently_reinitialized(self):
        self.sim.heartbeat()
        self.service.close()
        with closing(sqlite3.connect(self.path)) as connection:
            connection.execute("DELETE FROM telemetry_state")
            connection.commit()
        demo = make_demo(self.clock)
        with self.assertRaises(TelemetryUnavailable):
            ReliableDSIService.open_sqlite(demo.runtime.policy, self.path, sources=[source()], clock=self.clock)
        self.assertEqual(demo.runtime.policy.dsi.get_level().value, "CRISIS")

    def test_corrupt_database_fails_conservatively(self):
        self.service.close()
        self.path.write_bytes(b"invalid SQLite database")
        demo = make_demo(self.clock)
        with self.assertRaises(TelemetryUnavailable):
            ReliableDSIService.open_sqlite(demo.runtime.policy, self.path, sources=[source()], clock=self.clock)
        self.assertEqual(demo.runtime.policy.dsi.get_level().value, "CRISIS")

    def test_second_writer_is_rejected(self):
        with self.assertRaises(BlockingIOError):
            SQLiteEventStore(self.path)

    def test_legacy_service_cannot_silently_bypass_persistence(self):
        self.service.close()
        store = SQLiteEventStore(self.path)
        try:
            with self.assertRaisesRegex(ValueError, "ReliableDSIService"):
                DSIService(make_demo().runtime.policy, store=store)
        finally:
            store.close()

    def test_sqlite_has_no_plaintext_source_keys(self):
        self.sim.rotate_key(2, NEW_KEY)
        self.service.close()
        data = self.path.read_bytes()
        self.assertNotIn(KEY, data)
        self.assertNotIn(NEW_KEY, data)

    def test_two_real_processes_restore_security_state(self):
        self.service.close()
        script = '''
import json,sys
from agent_demo import DynamicSecurityIndicator, PolicyEngine, DEMO_ENVIRONMENT
from telemetry.reliability import ReliableDSIService
from telemetry.sources import TrustedSource, sign_event
key=b"subprocess-test-security-key-0001"
policy=PolicyEngine(DynamicSecurityIndicator(),DEMO_ENVIRONMENT)
s=ReliableDSIService.open_sqlite(policy,sys.argv[1],sources=[TrustedSource("process-source",key)],clock=lambda:1000)
p={"event_id":"persisted-event","source_id":"process-source","sequence":1,"event_type":"network_anomaly","severity":100,"observed_at":1000}
r=s.ingest(p,sign_event(p,key))
print(json.dumps({"accepted":r.accepted,"reason":r.reason,"score":s.status()["score"],"audit":len(s.audit)}))
# Process termination closes SQLite and releases the writer lease.
'''
        path = Path(self.directory.name) / "process.sqlite"
        results = []
        for _ in range(2):
            result = subprocess.run([sys.executable, "-B", "-c", script, str(path)],
                                    capture_output=True, text=True, timeout=20,
                                    cwd=Path(__file__).resolve().parents[1])
            self.assertEqual(result.returncode, 0, result.stderr)
            results.append(json.loads(result.stdout))
        self.assertTrue(results[0]["accepted"])
        self.assertEqual(results[1]["reason"], "duplicate_event")
        self.assertEqual(results[1]["score"], 30)
        self.assertGreater(results[1]["audit"], results[0]["audit"])


class AgentContinuityTests(unittest.TestCase):
    def test_agent_has_no_health_or_credential_control_surface(self):
        from demos.finance_agent import build_finance_demo
        from pydantic import ValidationError
        demo = build_finance_demo(scenario="none", reliable_telemetry=True,
                                  clock=lambda: 1000, review=lambda details: True, log=lambda message: None)
        self.assertEqual({tool.name for tool in demo.tools}, {"read_document", "generate_report", "send_email"})
        read = next(tool for tool in demo.tools if tool.name == "read_document")
        for field in ("source_health", "enabled", "key_version", "rotate_key", "source_secret"):
            with self.subTest(field=field), self.assertRaises(ValidationError):
                read.invoke({"path": "/finance/monthly.csv", field: "forged"})
        self.assertEqual(demo.dsi_service.source_status("demo-security")["status"], "HEALTHY")
        self.assertFalse(demo.setup.effects)

    def test_real_graph_revalidates_outage_during_approval(self):
        from demos.finance_agent import build_finance_demo
        clock = Clock()
        demo = build_finance_demo(scenario="none", reliable_telemetry=True, clock=clock,
                                  review=lambda details: True, log=lambda message: None)
        def review(details):
            clock.advance(16)
            self.assertGreater(details["expires_at"], clock())
            return True
        demo.driver.review = review
        clock.advance(45)
        result = demo.driver(demo.setup.read_call())
        self.assertEqual(result["status"], "blocked")
        decisions = [(entry["stage"], entry["decision"]) for entry in demo.setup.runtime.audit]
        self.assertIn(("approval", "REEVALUATE"), decisions)
        self.assertIn(("prepare", "BLOCK"), decisions)
        self.assertFalse(demo.setup.effects)

    def test_reliable_agent_still_receives_mock_financial_outputs(self):
        from demos.finance_agent import build_finance_demo
        from demos.scripted_model import ScriptedFinanceModel
        from agent.models import build_agent
        demo = build_finance_demo(scenario="none", reliable_telemetry=True,
                                  review=lambda details: True, log=lambda message: None)
        model = ScriptedFinanceModel()
        build_agent(model, demo.tools).invoke({"messages": [{"role": "user", "content": "Generate the report"}]})
        self.assertEqual(model.observed_results[0]["output"]["content"]["profit"], 40000)
        self.assertEqual(len(demo.setup.effects), 2)
