"""Simulated source using the same signatures, validation, and store as ingestion.

Only the trusted host creates this object. No simulator, signing key, source
registry, refresh method, or ingestion method is exposed as an agent tool.
"""

from telemetry.dsi_service import DSIService
from telemetry.events import DSI_INPUTS, EventType
from telemetry.sources import sign_event


class SecurityEventSimulator:
    def __init__(self, service: DSIService, *, source_id="demo-security", key=None, key_version=1, sequence=0):
        self.service = service
        self.source_id = source_id
        self._sequence = sequence
        self._key_version = key_version
        self._heartbeats_enabled = True
        self._incident_triggered = False
        self._key = service._provision_simulator(self, source_id) if key is None else key

    def submission(self, event_type, severity, *, observed_at=None, **optional):
        self._sequence += 1
        payload = {
            "event_id": f"{self.source_id}:{self._sequence}", "source_id": self.source_id,
            "sequence": self._sequence, "event_type": EventType(event_type).value,
            "key_version": self._key_version,
            "severity": severity,
            "observed_at": self.service.clock() if observed_at is None else observed_at,
            **optional,
        }
        return payload, sign_event(payload, self._key)

    def emit(self, event_type, severity, **optional):
        result = self.service.ingest(*self.submission(event_type, severity, **optional))
        if not result.accepted:
            raise ValueError(f"Simulated telemetry rejected: {result.reason}")
        return self.service.status()

    def snapshot(self, *, network_anomaly=0, unknown_operations=0,
                 destructive_activity=0, other_alerts=0):
        values = dict(network_anomaly=network_anomaly, unknown_operations=unknown_operations,
                      destructive_activity=destructive_activity, other_alerts=other_alerts)
        observed_at = self.service.clock()
        submissions = [self.submission(kind, values[name], observed_at=observed_at)
                       for kind, name in DSI_INPUTS.items()]
        result = self.service.ingest_batch(submissions)
        if not result.accepted:
            raise ValueError(f"Simulated telemetry rejected: {result.reason}")
        return self.service.status()

    def normal_environment(self):
        """Clear only this source's four unscoped signal streams, never other sources."""
        return self.snapshot()

    def credential_anomaly(self, severity=100):
        return self.emit(EventType.CREDENTIAL_ANOMALY, severity)

    def network_anomaly(self, severity=100):
        return self.emit(EventType.NETWORK_ANOMALY, severity)

    def destructive_activity(self, severity=100):
        return self.emit(EventType.DESTRUCTIVE_ACTIVITY, severity)

    def multi_signal_crisis(self):
        return self.snapshot(network_anomaly=100, unknown_operations=100,
                             destructive_activity=100, other_alerts=100)

    def emergency(self, enabled):
        if type(enabled) is not bool:
            raise ValueError("Emergency state must be a boolean")
        return self.emit(EventType.EMERGENCY, 100 if enabled else 0)

    def trigger_incident(self):
        """Phase 1 scenario: publish a single atomic CRISIS batch, once."""
        if not self._incident_triggered:
            self.multi_signal_crisis()
            self._incident_triggered = True
        return self.service.status()

    def heartbeat(self, *, delay=0):
        return self.emit(EventType.HEARTBEAT, 0, observed_at=self.service.clock() - delay)

    def stop_heartbeats(self):
        """Stop local scheduled sends, never edit server health or DSI."""
        self._heartbeats_enabled = False

    def scheduled_heartbeat(self):
        return self.heartbeat() if self._heartbeats_enabled else None

    def recover(self):
        self._heartbeats_enabled = True
        return self.heartbeat()

    def rotate_key(self, new_version, new_key, *, overlap=0):
        """Trusted scenario driver calls the host's normal rotation interface."""
        self.service.rotate_key(self.source_id, new_version, new_key, overlap=overlap)
        self._key_version, self._key = new_version, new_key
