"""Strict wire schema and immutable accepted events. Timestamps are UTC seconds."""

from dataclasses import dataclass, field
from enum import Enum
import json
import math
import re
from types import MappingProxyType


class TelemetryError(ValueError):
    """A stable rejection code, never interpolated raw payload or credentials."""


class EventType(str, Enum):
    NETWORK_ANOMALY = "network_anomaly"
    CREDENTIAL_ANOMALY = "credential_anomaly"
    DESTRUCTIVE_ACTIVITY = "destructive_activity"
    OTHER_ALERT = "other_alert"
    EMERGENCY = "emergency"
    HEARTBEAT = "heartbeat"


DSI_INPUTS = MappingProxyType({
    EventType.NETWORK_ANOMALY: "network_anomaly",
    EventType.CREDENTIAL_ANOMALY: "unknown_operations",
    EventType.DESTRUCTIVE_ACTIVITY: "destructive_activity",
    EventType.OTHER_ALERT: "other_alerts",
})
SIGNAL_TYPES = frozenset(DSI_INPUTS)


def identifier(value):
    if type(value) is not str or not re.fullmatch(r"[A-Za-z0-9_.:/-]{1,128}", value):
        raise TelemetryError("invalid_identifier")
    return value


def timestamp(value):
    try:
        valid = type(value) in (int, float) and math.isfinite(value) and value >= 0
    except OverflowError:
        valid = False
    if not valid:
        raise TelemetryError("invalid_timestamp")
    return value


def json_value(value, depth=0):
    if depth > 8:
        raise TelemetryError("metadata_too_deep")
    if value is None or type(value) in (str, bool, int):
        return
    if type(value) is float and math.isfinite(value):
        return
    if type(value) is list and len(value) <= 128:
        for item in value:
            json_value(item, depth + 1)
        return
    if type(value) is dict and len(value) <= 128 and all(type(key) is str for key in value):
        for item in value.values():
            json_value(item, depth + 1)
        return
    raise TelemetryError("invalid_metadata")


def canonical_payload(payload):
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


@dataclass(frozen=True)
class TelemetryEvent:
    event_id: str
    source_id: str
    event_type: EventType
    severity: int
    observed_at: float
    received_at: float
    sequence: int
    expires_at: float
    target_id: str | None = None
    resource_id: str | None = None
    metadata_json: str = field(default="{}", repr=False)
    key_version: int = 1

    @property
    def metadata(self):
        # Return a copy: caller mutation cannot change an accepted event.
        return json.loads(self.metadata_json)

    @property
    def stream(self):
        return (self.source_id, self.event_type, self.target_id, self.resource_id)


def parse_event(payload, received_at, lifetime):
    required = {"event_id", "source_id", "event_type", "severity", "observed_at", "sequence"}
    optional = {"target_id", "resource_id", "metadata", "key_version"}
    if type(payload) is not dict or not required <= payload.keys() or payload.keys() - required - optional:
        raise TelemetryError("invalid_schema")
    identifier(payload["event_id"])
    identifier(payload["source_id"])
    if type(payload["event_type"]) is not str:
        raise TelemetryError("invalid_event_type")
    try:
        event_type = EventType(payload["event_type"])
    except ValueError:
        raise TelemetryError("invalid_event_type") from None
    severity = payload["severity"]
    if type(severity) is not int or not 0 <= severity <= 100:
        raise TelemetryError("invalid_severity")
    if event_type == EventType.EMERGENCY and severity not in (0, 100):
        raise TelemetryError("invalid_emergency_severity")
    if event_type == EventType.HEARTBEAT and severity != 0:
        raise TelemetryError("invalid_heartbeat_severity")
    version = payload.get("key_version", 1)
    if type(version) is not int or not 1 <= version <= 2**31 - 1:
        raise TelemetryError("invalid_key_version")
    sequence = payload["sequence"]
    if type(sequence) is not int or not 1 <= sequence <= 2**63 - 1:
        raise TelemetryError("invalid_sequence")
    observed = timestamp(payload["observed_at"])
    for name in ("target_id", "resource_id"):
        if payload.get(name) is not None:
            identifier(payload[name])
    metadata = payload.get("metadata", {})
    if type(metadata) is not dict:
        raise TelemetryError("invalid_metadata")
    json_value(metadata)
    metadata_json = canonical_payload(metadata).decode("utf-8")
    if len(metadata_json.encode("utf-8")) > 16384:
        raise TelemetryError("metadata_too_large")
    return TelemetryEvent(
        payload["event_id"], payload["source_id"], event_type, severity,
        observed, received_at, sequence, min(observed, received_at) + lifetime,
        payload.get("target_id"), payload.get("resource_id"), metadata_json, version,
    )
