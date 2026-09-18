"""Opt-in trust continuity over the Phase 2 ingestion contract.

Legacy DSIService remains the TTL-only research fixture. Operational hosts use
ReliableDSIService with explicit source configuration and a transactional store.
"""

from contextlib import contextmanager
import copy
from dataclasses import asdict
from enum import Enum
import hashlib
import hmac
import json

from telemetry.dsi_service import DSIService, TelemetryAudit
from telemetry.events import EventType, TelemetryError, identifier, timestamp
from telemetry.sources import TrustedSource
from telemetry.store import InMemoryEventStore


class SourceHealth(str, Enum):
    HEALTHY = "HEALTHY"
    DEGRADED = "DEGRADED"
    STALE = "STALE"
    OFFLINE = "OFFLINE"
    DISABLED = "DISABLED"


class TelemetryUnavailable(RuntimeError):
    pass


def source_configuration(source):
    return {
        "source_id": source.source_id, "event_types": sorted(kind.value for kind in source.event_types),
        "reporting_interval": source.reporting_interval, "grace_period": source.grace_period,
        "criticality": source.criticality, "enabled": source.enabled,
        "current_version": source.key_version,
        "versions": {str(source.key_version): {"fingerprint": hashlib.sha256(source.key).hexdigest(),
                                              "retire_at": None}},
    }


class _VersionedVerifier:
    def __init__(self, service):
        self.service = service

    def verify(self, source_id, payload, proof):
        service = self.service
        source = service._store.control["sources"].get(source_id)
        if source is None:
            raise TelemetryError("unknown_source")
        if not source["enabled"]:
            raise TelemetryError("source_disabled")
        version = json.loads(payload).get("key_version", 1)
        record = source["versions"].get(str(version))
        if record is None or (record["retire_at"] is not None and service._last_now >= record["retire_at"]):
            raise TelemetryError("retired_or_unknown_key")
        key = service._keys.get((source_id, version))
        if key is None:
            raise TelemetryError("key_unavailable")
        if type(proof) is not str or len(proof) != 64 or not proof.isascii():
            raise TelemetryError("invalid_authentication")
        if not hmac.compare_digest(hmac.digest(key, payload, "sha256").hex(), proof):
            raise TelemetryError("invalid_authentication")
        service._contacts.add(source_id)
        return frozenset(EventType(value) for value in source["event_types"]) | {EventType.HEARTBEAT}


class ReliableDSIService(DSIService):
    supports_persistence = True

    @property
    def audit(self):
        with self._lock:
            return tuple(self._audit)

    @classmethod
    def open_sqlite(cls, policy, path, **kwargs):
        """Fail closed even if storage cannot be opened; caller calls close()."""
        from telemetry.sqlite_store import SQLiteEventStore
        store = None
        try:
            store = SQLiteEventStore(path)
            return cls(policy, store=store, **kwargs)
        except Exception as error:
            policy.dsi.set_emergency_mode(True)
            if store is not None:
                store.close()
            raise TelemetryUnavailable("Persistent telemetry initialization failed") from error

    def close(self):
        close = getattr(self._store, "close", None)
        if close is not None:
            close()

    def __init__(self, policy, *, sources=(), keys=None, store=None, **kwargs):
        self._keys = dict(keys or {})  # Host-injected secrets: never serialized.
        self._contacts = set()
        self.service_fault = None
        self._staged_dsi = None
        sources = tuple(sources)
        for source in sources:
            if type(source) is not TrustedSource:
                raise ValueError("Expected TrustedSource configurations")
            self._keys[(source.source_id, source.key_version)] = source.key
        if len({source.source_id for source in sources}) != len(sources):
            raise ValueError("Duplicate source configuration")
        store = store if store is not None else InMemoryEventStore()
        super().__init__(policy, verifier=_VersionedVerifier(self), store=store, **kwargs)
        try:
            with self._operation():
                recovered = bool(store.control)
                if recovered:
                    self._audit = [TelemetryAudit(**item) for item in store.control["audit"]]
                    self._last_now = store.control["last_now"]
                    saved = store.control["dsi"]
                    for name in ("score", "epoch", "admin_emergency"):
                        setattr(self._staged_dsi, name, saved[name])
                    if sources and {s.source_id for s in sources} != set(store.control["sources"]):
                        raise ValueError("Persistent source set mismatch")
                    for source in sources:
                        proposed = source_configuration(source)
                        saved_source = store.control["sources"][source.source_id]
                        for name in ("event_types", "reporting_interval", "grace_period", "criticality"):
                            if proposed[name] != saved_source[name]:
                                raise ValueError("Persistent source configuration mismatch")
                else:
                    if not sources:
                        raise ValueError("At least one source must be configured")
                    store.control.update(sources={}, health={})
                    for source in sources:
                        store.control["sources"][source.source_id] = source_configuration(source)
                        store.control["health"][source.source_id] = {
                            "status": SourceHealth.OFFLINE.value, "last_authenticated_contact": None,
                            "last_accepted_event": None, "last_observed_sequence": 0,
                            "last_observed_at": None, "delayed": False,
                            "needs_contact": True,
                        }
                now = self._now()
                for source_id, config in store.control["sources"].items():
                    for version, record in config["versions"].items():
                        if record["retire_at"] is not None and now >= record["retire_at"]:
                            continue
                        key = self._keys.get((source_id, int(version)))
                        if type(key) is not bytes or hashlib.sha256(key).hexdigest() != record["fingerprint"]:
                            raise ValueError("Required source credential unavailable or mismatched")
                self._event("recovery" if recovered else "registration", "state_restored" if recovered else "sources_registered", now)
                self._maintenance(now)
                self._record_expired(store.expire(now), now)
                self._publish_now()
        except Exception:
            # Even a failed constructor must not leave its runtime falsely NORMAL.
            self._fail_closed("initialization_failure")
            raise

    @contextmanager
    def _operation(self):
        with self._lock:
            if self.service_fault is not None:
                raise TelemetryUnavailable("Telemetry service requires trusted recovery")
            before = vars(self.policy.dsi).copy()
            saved = self._store.control.get("dsi")
            if saved and saved["score"] > before["score"]:
                before.update(saved)
            audit_before = list(self._audit)
            # A calculation snapshot is not an authority. The permanent shared
            # DSI object is updated only after the database commit succeeds.
            self._staged_dsi = copy.copy(self.policy.dsi)
            try:
                with self._store.transaction():
                    yield
                    self._save()
                vars(self.policy.dsi).update(vars(self._staged_dsi))
                self._staged_dsi = None
            except BaseException as error:
                # A rejected event is a result, not an exception. Infrastructure,
                # clock and recovery failures latch until a new trusted instance.
                vars(self.policy.dsi).update(before)
                self._staged_dsi = None
                self._audit = audit_before
                self._fail_closed("telemetry_operation_failure")
                if not isinstance(error, Exception):
                    raise
                raise TelemetryUnavailable("Telemetry operation failed conservatively") from error

    def _fail_closed(self, reason):
        self.service_fault = reason
        self.policy.dsi.set_emergency_mode(True)
        self._audit.append(TelemetryAudit(None, "service_failure", reason, None, None, False))

    def _save(self):
        self._store.control.update(
            audit=[asdict(item) for item in self._audit], last_now=self._last_now,
            dsi={name: getattr(self._staged_dsi, name) for name in ("score", "epoch", "admin_emergency")},
        )

    def _event(self, outcome, reason, now, source_id=None):
        self._audit.append(TelemetryAudit(now, outcome, reason, None, source_id, False))

    def _maintenance(self, now):
        protected = set()
        for source_id, source in self._store.control["sources"].items():
            health = self._store.control["health"][source_id]
            interval, grace = source["reporting_interval"], source["grace_period"]
            last = health["last_accepted_event"]
            age = float("inf") if last is None or health.get("needs_contact", False) else now - last
            offline = interval + 2 * grace if source["criticality"] == "critical" else 2 * interval + 2 * grace
            if not source["enabled"]:
                status = SourceHealth.DISABLED
            elif age > offline:
                status = SourceHealth.OFFLINE
            elif age > interval + grace:
                status = SourceHealth.STALE
            elif age > interval or health["delayed"]:
                status = SourceHealth.DEGRADED
            else:
                status = SourceHealth.HEALTHY
            if status.value != health["status"]:
                self._event("source_health", f"{health['status']}->{status.value}", now, source_id)
                health["status"] = status.value
            if status != SourceHealth.HEALTHY:
                protected.add(source_id)
        self._store.protected_sources = protected

    def _publish(self):
        # The base ingestion pipeline validates and records; this host layer
        # publishes only after contact/health updates within the same transaction.
        pass

    def _publish_now(self):
        from telemetry.events import DSI_INPUTS
        signals = dict.fromkeys(DSI_INPUTS.values(), 0)
        emergency = bool(self._store.protected_sources)
        for event in self._store.active():
            if event.event_type == EventType.EMERGENCY:
                emergency |= event.severity == 100
            elif event.event_type in DSI_INPUTS:
                name = DSI_INPUTS[event.event_type]
                signals[name] = max(signals[name], event.severity)
        self._staged_dsi.admin_emergency = emergency
        self._staged_dsi.calculate(**signals)

    def _status_snapshot(self):
        dsi = self._staged_dsi if self._staged_dsi is not None else self.policy.dsi
        return {"score": dsi.score, "level": dsi.get_level().value,
                "security_epoch": dsi.epoch, "admin_emergency": dsi.admin_emergency}

    def ingest_batch(self, submissions):
        with self._operation():
            now = self._now()
            self._contacts = set()
            self._maintenance(now)
            result = super().ingest_batch(submissions)
            for source_id in self._contacts:
                self._store.control["health"][source_id]["last_authenticated_contact"] = now
            if result.accepted:
                ids = set(result.event_ids)
                for event in sorted(self._store.active(), key=lambda item: item.sequence):
                    if event.event_id not in ids:
                        continue
                    state = self._store.control["health"][event.source_id]
                    source = self._store.control["sources"][event.source_id]
                    state.update(last_accepted_event=now, last_observed_sequence=event.sequence,
                                 last_observed_at=event.observed_at,
                                 needs_contact=False,
                                 delayed=now - event.observed_at > source["grace_period"])
                self._maintenance(now)
                self._publish_now()
            return result

    def refresh(self):
        with self._operation():
            now = self._now()
            self._maintenance(now)
            self._record_expired(self._store.expire(now), now)
            self._publish_now()
            return self._status_snapshot()

    def source_status(self, source_id):
        with self._lock:
            identifier(source_id)
            self.refresh()
            if source_id not in self._store.control["sources"]:
                raise ValueError("Unknown source")
            source = self._store.control["sources"][source_id]
            return {**self._store.control["health"][source_id], "current_version": source["current_version"],
                    "enabled": source["enabled"], "criticality": source["criticality"]}

    def _reject_control(self, reason, source_id):
        with self._operation():
            safe_id = source_id if type(source_id) is str and len(source_id) <= 128 else None
            self._event("control_rejected", reason, self._now(), safe_id)
        raise ValueError(reason)

    def rotate_key(self, source_id, new_version, new_key, *, overlap=0):
        with self._lock:
            return self._rotate_key(source_id, new_version, new_key, overlap=overlap)

    def _rotate_key(self, source_id, new_version, new_key, *, overlap=0):
        try:
            identifier(source_id)
            source = self._store.control["sources"][source_id]
            if type(new_version) is not int or not source["current_version"] < new_version <= 2**31 - 1:
                raise ValueError()
            if type(new_key) is not bytes or len(new_key) < 32:
                raise ValueError()
            fingerprint = hashlib.sha256(new_key).hexdigest()
            if any(record["fingerprint"] == fingerprint for record in source["versions"].values()):
                raise ValueError()
            if timestamp(overlap) > 300:
                raise ValueError()
        except (ValueError, KeyError, TypeError):
            self._reject_control("invalid_key_rotation", source_id)
        with self._operation():
            now = self._now()
            old = source["current_version"]
            # A subsequent rotation cannot extend any already scheduled retirement.
            for record in source["versions"].values():
                record["retire_at"] = min(record["retire_at"], now + overlap) if record["retire_at"] is not None else now + overlap
            source["versions"][str(new_version)] = {"fingerprint": fingerprint, "retire_at": None}
            source["current_version"] = new_version
            self._keys[(source_id, new_version)] = new_key
            self._event("key_rotation", f"version:{old}->{new_version};overlap:{overlap}", now, source_id)

    def set_source_enabled(self, source_id, enabled):
        with self._lock:
            return self._set_source_enabled(source_id, enabled)

    def _set_source_enabled(self, source_id, enabled):
        try:
            identifier(source_id)
            if source_id not in self._store.control["sources"] or type(enabled) is not bool:
                raise ValueError()
        except (ValueError, TypeError):
            self._reject_control("invalid_source_operation", source_id)
        with self._operation():
            now = self._now()
            source = self._store.control["sources"][source_id]
            if source["enabled"] == enabled:
                return
            source["enabled"] = enabled
            if enabled:
                # Re-enabling is not evidence of contact. Require a fresh event.
                self._store.control["health"][source_id]["needs_contact"] = True
            self._event("source_enabled" if enabled else "source_disabled", "host_configuration", now, source_id)
            self._maintenance(now)
            self._record_expired(self._store.expire(now), now)
            self._publish_now()
