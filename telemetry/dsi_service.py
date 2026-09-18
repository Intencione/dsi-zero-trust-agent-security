"""Trusted ingestion and publication of finite-lived security signals.

Only a host-owned service has the PolicyEngine reference. Producers get an
untrusted submission interface, not a score setter or source-registration API.
"""

from dataclasses import dataclass
import json
import secrets
from threading import RLock
import time

from agent_demo import PolicyEngine
from telemetry.events import (
    DSI_INPUTS, EventType, TelemetryError, canonical_payload, parse_event, timestamp,
)
from telemetry.sources import HMACSourceVerifier, SourceRegistry, SourceVerifier, TrustedSource
from telemetry.store import EventStore, InMemoryEventStore


@dataclass(frozen=True)
class TelemetryLimits:
    max_event_age: float = 120
    future_tolerance: float = 5
    event_lifetime: float = 300

    def __post_init__(self):
        for value in (self.max_event_age, self.future_tolerance, self.event_lifetime):
            timestamp(value)
        if self.max_event_age <= 0 or self.event_lifetime <= 0:
            raise ValueError("Event age and lifetime must be positive")


@dataclass(frozen=True)
class IngestionResult:
    accepted: bool
    reason: str
    event_ids: tuple[str, ...] = ()


@dataclass(frozen=True)
class TelemetryAudit:
    received_at: float | None
    outcome: str
    reason: str
    claimed_event_id: str | None
    claimed_source_id: str | None
    authenticated: bool


class DSIService:
    def __init__(self, policy: PolicyEngine, *, verifier: SourceVerifier | None = None,
                 store: EventStore | None = None, clock=time.time, limits=None):
        if getattr(policy, "_telemetry_service", None) is not None:
            raise ValueError("This PolicyEngine already has a telemetry service")
        self.policy = policy
        self.clock = clock
        self.limits = limits if limits is not None else TelemetryLimits()
        if type(self.limits) is not TelemetryLimits:
            raise ValueError("limits must be TelemetryLimits")
        self._simulation_registry = SourceRegistry() if verifier is None else None
        self._verifier = verifier if verifier is not None else HMACSourceVerifier(self._simulation_registry)
        self._store = store if store is not None else InMemoryEventStore()
        if getattr(self._store, "requires_transaction", False) and not getattr(self, "supports_persistence", False):
            raise ValueError("Use ReliableDSIService for transactional persistent telemetry")
        self._audit = []
        self._lock = RLock()
        self._last_now = 0
        self._legacy_simulator = None
        # Prevent competing stores/services from publishing into the same policy.
        policy._telemetry_service = self

    @property
    def audit(self):
        return tuple(self._audit)

    def _now(self):
        now = timestamp(self.clock())
        if now < self._last_now:
            raise TelemetryError("clock_moved_backwards")
        self._last_now = now
        return now

    def ingest(self, payload, proof):
        return self.ingest_batch([(payload, proof)])

    def ingest_batch(self, submissions):
        """All-or-nothing batch: verify every event before any store/DSI mutation.

        received_at is assigned here, never read from source input. Rejection
        does not run expiry maintenance or change the active DSI picture.
        """
        with self._lock:
            now = None
            parsed = []
            authenticated_indices = set()
            try:
                now = self._now()
                if type(submissions) not in (list, tuple) or not 1 <= len(submissions) <= 100:
                    raise TelemetryError("invalid_batch")
                for index, submission in enumerate(submissions):
                    if type(submission) not in (list, tuple) or len(submission) != 2:
                        raise TelemetryError("invalid_batch")
                    payload, proof = submission
                    event = parse_event(payload, now, self.limits.event_lifetime)
                    # Snapshot before verification. Neither mutable metadata nor
                    # source-owned dictionaries are retained in the event store.
                    wire = canonical_payload(payload)
                    event = parse_event(json.loads(wire), now, self.limits.event_lifetime)
                    try:
                        allowed = self._verifier.verify(event.source_id, wire, proof)
                    except TelemetryError:
                        raise
                    except Exception:
                        raise TelemetryError("authentication_unavailable") from None
                    authenticated_indices.add(index)
                    if event.event_type not in allowed:
                        raise TelemetryError("event_type_not_permitted")
                    if event.observed_at > now + self.limits.future_tolerance:
                        raise TelemetryError("future_event")
                    if now - event.observed_at > self.limits.max_event_age or event.expires_at <= now:
                        raise TelemetryError("stale_event")
                    parsed.append(event)
                expired = self._store.accept_batch(tuple(parsed), now)
            except (TelemetryError, ValueError, TypeError, OverflowError) as error:
                reason = str(error) if isinstance(error, TelemetryError) else "invalid_schema"
                self._record_rejection(submissions, now, reason, authenticated_indices)
                return IngestionResult(False, reason)
            self._record_expired(expired, now)
            for event in parsed:
                self._audit.append(TelemetryAudit(
                    now, "accepted", "accepted", event.event_id, event.source_id, True,
                ))
            self._publish()
            return IngestionResult(True, "accepted", tuple(event.event_id for event in parsed))

    def _record_rejection(self, submissions, now, reason, authenticated_indices):
        # No proofs, keys, raw metadata, or arbitrary error strings in the audit.
        items = submissions[:100] if type(submissions) in (tuple, list) else [None]
        for index, item in enumerate(items or [None]):
            payload = item[0] if type(item) in (tuple, list) and len(item) == 2 else None
            def claimed(name):
                value = payload.get(name) if type(payload) is dict else None
                return value if type(value) is str and len(value) <= 128 else None
            event_id, source_id = claimed("event_id"), claimed("source_id")
            self._audit.append(TelemetryAudit(
                now, "rejected", reason, event_id, source_id,
                index in authenticated_indices,
            ))

    def _record_expired(self, expired, now):
        for event in expired:
            self._audit.append(TelemetryAudit(
                now, "expired", "event_lifetime_elapsed", event.event_id, event.source_id, True,
            ))

    def _publish(self):
        signals = dict.fromkeys(DSI_INPUTS.values(), 0)
        emergency = False
        for event in self._store.active():
            if event.event_type == EventType.HEARTBEAT:
                continue
            if event.event_type == EventType.EMERGENCY:
                emergency = emergency or event.severity == 100
            else:
                name = DSI_INPUTS[event.event_type]
                signals[name] = max(signals[name], event.severity)
        # A single calculate call preserves the existing level-change epoch rule,
        # including a multi-signal batch and expiration of emergency declarations.
        self.policy.dsi.admin_emergency = emergency
        self.policy.dsi.calculate(**signals)

    def refresh(self):
        """Trusted host maintenance; no background thread or agent-triggered timer."""
        with self._lock:
            now = self._now()
            self._record_expired(self._store.expire(now), now)
            self._publish()
            return self._status_snapshot()

    def status(self):
        return self.refresh()

    def _status_snapshot(self):
        return {
            "score": self.policy.dsi.score,
            "level": self.policy.dsi.get_level().value,
            "security_epoch": self.policy.dsi.epoch,
            "admin_emergency": self.policy.dsi.admin_emergency,
        }

    def _provision_simulator(self, simulator, source_id):
        if self._simulation_registry is None or self._legacy_simulator is not None:
            raise PermissionError("Simulator auto-provisioning requires an unconfigured demo service")
        key = secrets.token_bytes(32)
        self._simulation_registry.register(TrustedSource(source_id, key, frozenset(EventType)))
        self._legacy_simulator = simulator
        return key

    def ingest_signals(self, *, network_anomaly=0, unknown_operations=0,
                       destructive_activity=0, other_alerts=0):
        """Phase 1 fixture compatibility, enabled only by explicit demo provisioning.

        Configured ingestion services reject this credential-free API. The demo
        adapter emits signed events and cannot directly set a DSI score.
        """
        if self._legacy_simulator is None:
            raise PermissionError("Submit authenticated telemetry events instead")
        return self._legacy_simulator.snapshot(
            network_anomaly=network_anomaly, unknown_operations=unknown_operations,
            destructive_activity=destructive_activity, other_alerts=other_alerts,
        )

    def set_emergency(self, enabled: bool):
        """Phase 1 demo adapter; real sources need explicit emergency event scope."""
        if self._legacy_simulator is None:
            raise PermissionError("Submit an authenticated, authorized emergency event instead")
        if type(enabled) is not bool:
            raise ValueError("Emergency state must be a boolean")
        return self._legacy_simulator.emergency(enabled)
