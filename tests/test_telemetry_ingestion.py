"""Authenticated ingestion and lifecycle tests. All timing uses a fake clock."""

from dataclasses import FrozenInstanceError, asdict, replace
from concurrent.futures import ThreadPoolExecutor
import json
import unittest

from agent_demo import Decision, EnvironmentType
from secure_agent_demo import make_demo
from telemetry.dsi_service import DSIService, TelemetryLimits
from telemetry.events import EventType, SIGNAL_TYPES
from telemetry.simulator import SecurityEventSimulator
from telemetry.sources import HMACSourceVerifier, SourceRegistry, TrustedSource, sign_event
from telemetry.store import InMemoryEventStore


class FakeClock:
    def __init__(self):
        self.now = 1000

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


class TrustedTelemetryTests(unittest.TestCase):
    def setUp(self):
        self.clock = FakeClock()
        self.demo = make_demo(self.clock)
        self.runtime = self.demo.runtime
        self.key = b"test-source-key-32-bytes-minimum!!!"
        self.other_key = b"other-source-key-32-bytes-minimum!"
        self.registry = SourceRegistry([
            TrustedSource("sensor-a", self.key), TrustedSource("sensor-b", self.other_key),
            TrustedSource("admin", self.key, frozenset({EventType.EMERGENCY})),
        ])
        self.store = InMemoryEventStore()
        self.service = DSIService(
            self.runtime.policy, verifier=HMACSourceVerifier(self.registry),
            store=self.store, clock=self.clock,
        )

    def payload(self, **changes):
        return {
            "event_id": "event-1", "source_id": "sensor-a", "sequence": 1,
            "event_type": "network_anomaly", "severity": 100,
            "observed_at": self.clock(), **changes,
        }

    def submit(self, payload=None, *, key=None):
        payload = self.payload() if payload is None else payload
        return self.service.ingest(payload, sign_event(payload, self.key if key is None else key))

    def assert_rejected_unchanged(self, payload, reason, proof=None):
        dsi_before = vars(self.runtime.policy.dsi).copy()
        events_before = self.store.active()
        result = self.service.ingest(payload, sign_event(payload, self.key) if proof is None else proof)
        self.assertFalse(result.accepted)
        self.assertEqual(result.reason, reason)
        self.assertEqual(vars(self.runtime.policy.dsi), dsi_before)
        self.assertEqual(self.store.active(), events_before)
        self.assertEqual(self.service.audit[-1].outcome, "rejected")

    def test_valid_event_sets_authoritative_received_at_and_shared_state(self):
        dsi = self.runtime.policy.dsi
        result = self.submit(self.payload(observed_at=990, target_id="machine-1", resource_id="finance"))
        self.assertTrue(result.accepted)
        event = self.store.active()[0]
        self.assertEqual((event.observed_at, event.received_at, event.expires_at), (990, 1000, 1290))
        self.assertEqual(event.target_id, "machine-1")
        self.assertIs(self.service.policy, self.runtime.policy)
        self.assertIs(self.service.policy.dsi, dsi)
        self.assertEqual(dsi.score, 30)
        self.assertEqual(dsi.get_level().value, "ELEVATED")

    def test_unknown_source_cannot_self_register(self):
        self.assert_rejected_unchanged(self.payload(source_id="unknown"), "unknown_source")

    def test_invalid_authentication_cannot_update_state(self):
        self.assert_rejected_unchanged(self.payload(), "invalid_authentication", "0" * 64)
        self.assertFalse(self.service.audit[-1].authenticated)

    def test_source_cannot_use_another_sources_key(self):
        payload = self.payload(source_id="sensor-b")
        self.assert_rejected_unchanged(payload, "invalid_authentication")

    def test_proof_types_and_unicode_are_rejected(self):
        for proof in (True, 123, b"x" * 64, "é" * 64, "short"):
            with self.subTest(proof=proof):
                self.assert_rejected_unchanged(self.payload(), "invalid_authentication", proof)

    def test_signed_event_cannot_be_modified(self):
        original = self.payload(severity=20)
        proof = sign_event(original, self.key)
        for field, value in (("severity", 100), ("source_id", "sensor-b"), ("sequence", 2),
                             ("event_id", "renamed"), ("observed_at", 999), ("metadata", {"x": 1})):
            with self.subTest(field=field):
                self.assert_rejected_unchanged({**original, field: value}, "invalid_authentication", proof)

    def test_duplicate_event_is_rejected(self):
        self.assertTrue(self.submit().accepted)
        self.assert_rejected_unchanged(self.payload(), "duplicate_event")

    def test_new_id_with_old_authenticated_sequence_is_replay(self):
        self.submit()
        self.assert_rejected_unchanged(self.payload(event_id="renamed"), "replayed_sequence")

    def test_deduplication_is_global_across_sources(self):
        self.submit()
        payload = self.payload(source_id="sensor-b")
        self.assert_rejected_unchanged(payload, "duplicate_event", sign_event(payload, self.other_key))

    def test_stale_event_is_rejected(self):
        self.assert_rejected_unchanged(self.payload(observed_at=879), "stale_event")

    def test_excessive_future_timestamp_is_rejected(self):
        self.assert_rejected_unchanged(self.payload(observed_at=1005.01), "future_event")

    def test_freshness_boundary_is_inclusive(self):
        self.assertTrue(self.submit(self.payload(observed_at=880)).accepted)

    def test_future_tolerance_does_not_extend_event_lifetime(self):
        self.assertTrue(self.submit(self.payload(observed_at=1005)).accepted)
        self.assertEqual(self.store.active()[0].expires_at, 1300)
        self.clock.advance(300)
        self.assertEqual(self.service.refresh()["score"], 0)

    def test_source_cannot_supply_received_at_or_lifetime(self):
        for field in ("received_at", "expires_at", "event_lifetime", "dsi_score", "trusted"):
            with self.subTest(field=field):
                self.assert_rejected_unchanged(self.payload(**{field: 0}), "invalid_schema")

    def test_severity_has_strict_integer_type_and_range(self):
        for severity in (-1, 101, True, 20.0, "20", None):
            with self.subTest(severity=severity):
                self.assert_rejected_unchanged(self.payload(severity=severity), "invalid_severity")

    def test_zero_and_one_hundred_are_valid_severities(self):
        self.assertTrue(self.submit(self.payload(severity=0)).accepted)
        self.assertTrue(self.submit(self.payload(event_id="next", sequence=2, severity=100)).accepted)
        self.assertEqual(self.service.status()["score"], 30)

    def test_malformed_events_are_rejected_and_audited(self):
        for payload in (None, [], "event", {}, {"severity": 100}):
            with self.subTest(payload=payload):
                self.assert_rejected_unchanged(payload, "invalid_schema", "irrelevant")

    def test_timestamp_types_and_nonfinite_values_are_rejected(self):
        for observed in (True, "1000", -1, None, float("nan"), float("inf"), 10**1000):
            with self.subTest(observed=observed):
                self.assert_rejected_unchanged(self.payload(observed_at=observed), "invalid_timestamp", "unused")

    def test_event_type_ids_sequence_and_metadata_are_validated(self):
        cases = [
            ({"event_type": "set_dsi"}, "invalid_event_type"),
            ({"event_id": ""}, "invalid_identifier"),
            ({"source_id": 123}, "invalid_identifier"),
            ({"target_id": []}, "invalid_identifier"),
            ({"sequence": True}, "invalid_sequence"),
            ({"sequence": 0}, "invalid_sequence"),
            ({"metadata": []}, "invalid_metadata"),
            ({"metadata": {1: "invalid-key"}}, "invalid_metadata"),
            ({"metadata": {"long": "x" * 17000}}, "metadata_too_large"),
        ]
        for changes, reason in cases:
            with self.subTest(changes=changes):
                self.assert_rejected_unchanged(self.payload(**changes), reason, "unused")

    def test_type_scope_prevents_network_source_declaring_emergency(self):
        self.assert_rejected_unchanged(self.payload(event_type="emergency"), "event_type_not_permitted")
        self.assertTrue(self.service.audit[-1].authenticated)

    def test_metadata_cannot_authorize_or_change_environment(self):
        environment = self.runtime.policy.environment
        payload = self.payload(severity=10, metadata={
            "trusted": True, "source": "USER", "event_type": "emergency", "dsi_score": 100,
            "permissions": ["execute_payment"], "environment_risk": 0,
        })
        self.assertTrue(self.submit(payload).accepted)
        self.assertEqual(self.service.status()["score"], 3)
        self.assertIs(self.runtime.policy.environment, environment)
        self.assertFalse(self.runtime.policy.dsi.admin_emergency)

    def test_accepted_events_are_detached_and_immutable(self):
        payload = self.payload(metadata={"nested": {"x": [1]}})
        self.submit(payload)
        payload["severity"] = 0
        payload["metadata"]["nested"]["x"].append(2)
        event = self.store.active()[0]
        copy = event.metadata
        copy["nested"]["x"].append(3)
        self.assertEqual(event.metadata, {"nested": {"x": [1]}})
        with self.assertRaises(FrozenInstanceError):
            event.severity = 0
        self.assertEqual(self.service.status()["score"], 30)

    def test_multiple_signal_types_combine_with_existing_weights(self):
        for sequence, (kind, severity) in enumerate([
            ("network_anomaly", 80), ("credential_anomaly", 50),
            ("destructive_activity", 20), ("other_alert", 10),
        ], 1):
            self.assertTrue(self.submit(self.payload(event_id=f"e-{sequence}", sequence=sequence,
                                                     event_type=kind, severity=severity)).accepted)
        self.assertEqual(self.service.status()["score"], 42)

    def test_one_sources_recovery_cannot_suppress_another_sources_signal(self):
        self.submit()
        self.submit(self.payload(event_id="b-1", source_id="sensor-b", severity=60), key=self.other_key)
        self.submit(self.payload(event_id="a-2", sequence=2, severity=0))
        self.assertEqual(self.service.status()["score"], 18)

    def test_same_stream_updates_replace_instead_of_accumulating_forever(self):
        self.submit()
        self.submit(self.payload(event_id="next", sequence=2, severity=10))
        self.assertEqual(len(self.store.active()), 1)
        self.assertEqual(self.service.status()["score"], 3)

    def test_target_streams_do_not_clear_each_other(self):
        self.submit(self.payload(target_id="machine-a"))
        self.submit(self.payload(event_id="next", sequence=2, severity=0, target_id="machine-b"))
        self.assertEqual(self.service.status()["score"], 30)

    def test_new_sequence_with_older_observation_cannot_suppress_recent_alarm(self):
        self.submit()
        self.assert_rejected_unchanged(self.payload(event_id="older", sequence=2, observed_at=999,
                                                     severity=0), "out_of_order_observation")

    def test_expired_events_leave_active_dsi_at_exact_lifetime_boundary(self):
        self.submit()
        self.clock.advance(299)
        self.assertEqual(self.service.refresh()["score"], 30)
        self.clock.advance(1)
        self.assertEqual(self.service.refresh()["score"], 0)
        self.assertEqual(self.store.active(), ())
        self.assertEqual(self.service.audit[-1].outcome, "expired")

    def test_expiring_one_source_preserves_other_active_sources(self):
        self.submit()
        self.clock.advance(100)
        self.submit(self.payload(source_id="sensor-b", event_id="b-1", severity=50), key=self.other_key)
        self.clock.advance(200)
        self.assertEqual(self.service.refresh()["score"], 15)

    def test_replay_memory_survives_expiration(self):
        self.submit()
        self.clock.advance(300)
        self.service.refresh()
        # Even a re-signed fresh timestamp cannot revive an old ID or sequence.
        self.assert_rejected_unchanged(self.payload(sequence=2), "duplicate_event")
        self.assert_rejected_unchanged(self.payload(event_id="new-id"), "replayed_sequence")

    def test_rejected_event_does_not_trigger_expiration_or_change_dsi(self):
        self.submit()
        self.clock.advance(300)
        self.assert_rejected_unchanged(self.payload(event_id="bad", sequence=2), "invalid_authentication", "x")
        self.assertEqual(self.runtime.policy.dsi.score, 30)
        self.assertEqual(self.service.refresh()["score"], 0)

    def test_atomic_batch_changes_epoch_once_and_invalidates_pending_approval(self):
        self.runtime.policy.update_environment(replace(
            self.runtime.policy.environment, environment_type=EnvironmentType.PRODUCTION,
        ))
        context = self.runtime.policy.capture_context()
        call = self.demo.read_call()
        prepared = self.runtime.prepare(self.demo.agent_token, call, context)
        self.assertEqual(prepared.decision, Decision.APPROVAL)
        submissions = []
        for seq, kind in enumerate(sorted(SIGNAL_TYPES), 1):
            payload = self.payload(event_id=f"crisis-{seq}", sequence=seq, event_type=kind.value)
            submissions.append((payload, sign_event(payload, self.key)))
        self.assertTrue(self.service.ingest_batch(submissions).accepted)
        self.assertEqual(self.service.status()["score"], 100)
        self.assertEqual(self.runtime.policy.dsi.epoch, context.security_epoch + 1)
        approved = self.runtime.resolve_approval(self.demo.user_token, prepared.approval_id, approved=True)
        self.assertEqual(approved.decision, Decision.REEVALUATE)
        fresh = self.runtime.prepare(self.demo.agent_token, call, self.runtime.policy.capture_context())
        self.assertEqual(fresh.decision, Decision.BLOCK)
        self.assertFalse(self.demo.effects)

    def test_expiration_increments_epoch_and_invalidates_old_plan(self):
        self.submit()
        context = self.runtime.policy.capture_context()
        self.clock.advance(300)
        self.service.refresh()
        self.assertEqual(self.runtime.policy.dsi.epoch, context.security_epoch + 1)
        result = self.runtime.prepare(self.demo.agent_token, self.demo.read_call(), context)
        self.assertEqual(result.decision, Decision.REEVALUATE)

    def test_bad_event_rolls_back_entire_batch_without_poisoning_deduplication(self):
        good = self.payload()
        bad = self.payload(event_id="bad", sequence=2)
        result = self.service.ingest_batch([(good, sign_event(good, self.key)), (bad, "wrong")])
        self.assertFalse(result.accepted)
        self.assertEqual(self.store.active(), ())
        self.assertEqual(self.runtime.policy.dsi.score, 0)
        self.assertTrue(self.submit(good).accepted)

    def test_duplicates_inside_batch_reject_every_event_atomically(self):
        first = self.payload()
        second = self.payload(sequence=2)
        result = self.service.ingest_batch([(p, sign_event(p, self.key)) for p in (first, second)])
        self.assertEqual(result.reason, "duplicate_event")
        self.assertEqual(self.store.active(), ())
        self.assertTrue(self.submit(first).accepted)

    def test_batch_audit_does_not_misattribute_failed_signature_with_same_id(self):
        payload = self.payload()
        self.service.ingest_batch([(payload, sign_event(payload, self.key)), (payload, "wrong")])
        self.assertTrue(self.service.audit[0].authenticated)
        self.assertFalse(self.service.audit[1].authenticated)
        self.assertTrue(all(record.outcome == "rejected" for record in self.service.audit))

    def test_audit_records_acceptance_and_rejection_without_credentials_or_metadata(self):
        payload = self.payload(metadata={"secret": "metadata-not-for-audit"})
        proof = sign_event(payload, self.key)
        self.service.ingest(payload, proof)
        self.service.ingest(self.payload(event_id="bad", sequence=2), "invalid-proof-not-for-audit")
        records = self.service.audit
        text = json.dumps([asdict(record) for record in records])
        for secret in (proof, self.key.decode(), "metadata-not-for-audit", "invalid-proof-not-for-audit"):
            self.assertNotIn(secret, text)
        self.assertEqual([record.outcome for record in records], ["accepted", "rejected"])
        self.assertEqual(records[0].received_at, 1000)

    def test_clock_rollback_cannot_reactivate_expired_events(self):
        self.submit()
        self.clock.advance(300)
        self.service.refresh()
        self.clock.advance(-100)
        self.assert_rejected_unchanged(self.payload(event_id="next", sequence=2), "clock_moved_backwards")
        with self.assertRaisesRegex(ValueError, "clock_moved_backwards"):
            self.service.refresh()

    def test_authorized_emergency_is_finite_and_cannot_hide_other_signals(self):
        self.submit()
        self.submit(self.payload(source_id="admin", event_id="admin-1", event_type="emergency"))
        self.assertEqual(self.service.status()["score"], 95)
        self.submit(self.payload(source_id="admin", event_id="admin-2", sequence=2,
                                 event_type="emergency", severity=0))
        self.assertEqual(self.service.status()["score"], 30)
        self.submit(self.payload(source_id="admin", event_id="admin-3", sequence=3, event_type="emergency"))
        self.clock.advance(300)
        self.assertEqual(self.service.refresh()["score"], 0)
        self.assertFalse(self.runtime.policy.dsi.admin_emergency)

    def test_configured_service_has_no_unsigned_compatibility_writers(self):
        with self.assertRaises(PermissionError):
            self.service.ingest_signals(network_anomaly=100)
        with self.assertRaises(PermissionError):
            self.service.set_emergency(True)
        with self.assertRaises(PermissionError):
            SecurityEventSimulator(self.service)
        self.assertEqual(self.runtime.policy.dsi.score, 0)

    def test_second_service_cannot_replace_shared_policy_owner(self):
        with self.assertRaisesRegex(ValueError, "already has a telemetry service"):
            DSIService(self.runtime.policy)

    def test_source_registration_rejects_weak_keys_and_duplicate_source(self):
        with self.assertRaises(ValueError):
            TrustedSource("weak", b"short")
        with self.assertRaises(ValueError):
            self.registry.register(TrustedSource("sensor-a", self.other_key))

    def test_simulator_uses_explicitly_registered_source_and_normal_ingestion(self):
        simulator = SecurityEventSimulator(self.service, source_id="sensor-a", key=self.key)
        self.assertEqual(simulator.normal_environment()["score"], 0)
        self.assertEqual(simulator.credential_anomaly()["score"], 20)
        self.assertEqual(simulator.network_anomaly()["score"], 50)
        self.assertEqual(simulator.destructive_activity()["score"], 80)
        self.assertEqual(simulator.multi_signal_crisis()["score"], 100)
        self.assertTrue(all(record.authenticated for record in self.service.audit))
        self.assertEqual(len(self.service.audit), 11)
        self.clock.advance(300)
        self.assertEqual(self.service.status()["score"], 0)

    def test_verifier_is_replaceable_and_failure_is_closed_and_audited(self):
        class UnavailableVerifier:
            def verify(self, source_id, payload, proof):
                raise RuntimeError("internal secret")

        demo = make_demo(self.clock)
        service = DSIService(demo.runtime.policy, verifier=UnavailableVerifier(), clock=self.clock)
        result = service.ingest(self.payload(), "proof")
        self.assertEqual(result.reason, "authentication_unavailable")
        self.assertEqual(demo.runtime.policy.dsi.score, 0)
        self.assertNotIn("internal secret", repr(service.audit))

    def test_concurrent_duplicate_delivery_accepts_exactly_once(self):
        payload = self.payload()
        proof = sign_event(payload, self.key)
        with ThreadPoolExecutor(max_workers=4) as pool:
            results = list(pool.map(lambda _: self.service.ingest(payload, proof), range(16)))
        self.assertEqual(sum(result.accepted for result in results), 1)
        self.assertEqual(len(self.store.active()), 1)
        self.assertEqual(self.runtime.policy.dsi.epoch, 2)

    def test_invalid_batches_do_not_modify_state(self):
        for batch in (None, [], [None], [(self.payload(),)], [(self.payload(), "x", "extra")]):
            with self.subTest(batch=batch):
                self.assertEqual(self.service.ingest_batch(batch).reason, "invalid_batch")
                self.assertEqual(self.store.active(), ())
                self.assertEqual(self.runtime.policy.dsi.score, 0)

    def test_expired_on_arrival_rejected_even_with_long_ingestion_age_limit(self):
        demo = make_demo(self.clock)
        service = DSIService(demo.runtime.policy, clock=self.clock,
                             verifier=HMACSourceVerifier(self.registry),
                             limits=TelemetryLimits(max_event_age=600, event_lifetime=30))
        payload = self.payload(observed_at=970)
        self.assertEqual(service.ingest(payload, sign_event(payload, self.key)).reason, "stale_event")
        self.assertEqual(demo.runtime.policy.dsi.score, 0)

    def test_same_level_change_invalidates_permit_without_changing_epoch(self):
        call = self.demo.read_call()
        context = self.runtime.policy.capture_context()
        permit = self.runtime.prepare(self.demo.agent_token, call, context).permit_id
        self.submit(self.payload(severity=10))
        self.assertEqual(self.runtime.policy.dsi.epoch, context.security_epoch)
        result = self.runtime.execute(self.demo.agent_token, call, permit)
        self.assertEqual(result.decision, Decision.REEVALUATE)
        self.assertFalse(self.demo.effects)

    def test_custom_limits_are_validated(self):
        for config in ({"event_lifetime": 0}, {"max_event_age": -1},
                       {"future_tolerance": True}, {"future_tolerance": float("inf")}):
            with self.subTest(config=config), self.assertRaises(ValueError):
                TelemetryLimits(**config)
