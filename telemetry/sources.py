"""Host-provisioned sources and a replaceable authentication boundary.

HMAC here authenticates possession of a configured source key, not the truth of
the reported observation. Registration and signing keys never become agent tools.
"""

from dataclasses import dataclass, field
import hmac
from typing import Protocol

from telemetry.events import EventType, SIGNAL_TYPES, TelemetryError, canonical_payload, identifier, timestamp


@dataclass(frozen=True)
class TrustedSource:
    source_id: str
    key: bytes = field(repr=False)
    event_types: frozenset[EventType] = SIGNAL_TYPES
    reporting_interval: float = 60
    grace_period: float = 30
    criticality: str = "critical"
    enabled: bool = True
    key_version: int = 1

    def __post_init__(self):
        identifier(self.source_id)
        if type(self.key) is not bytes or len(self.key) < 32:
            raise ValueError("Source keys must contain at least 32 bytes")
        if type(self.event_types) is not frozenset or not self.event_types or any(
            type(kind) is not EventType for kind in self.event_types
        ):
            raise ValueError("Configure an immutable set of allowed EventType values")
        if timestamp(self.reporting_interval) <= 0 or timestamp(self.grace_period) <= 0:
            raise ValueError("Reporting interval and grace period must be positive")
        if self.criticality not in ("critical", "standard") or type(self.enabled) is not bool:
            raise ValueError("Invalid source operational configuration")
        if type(self.key_version) is not int or not 1 <= self.key_version <= 2**31 - 1:
            raise ValueError("Invalid credential version")


class SourceRegistry:
    def __init__(self, sources=()):
        self._sources = {}
        for source in sources:
            self.register(source)

    def register(self, source: TrustedSource):
        if type(source) is not TrustedSource or source.source_id in self._sources:
            raise ValueError("Invalid or already registered source")
        self._sources[source.source_id] = source

    def get(self, source_id):
        source = self._sources.get(source_id)
        if source is None:
            raise TelemetryError("unknown_source")
        return source


class SourceVerifier(Protocol):
    def verify(self, source_id: str, payload: bytes, proof: str) -> frozenset[EventType]: ...


def sign_event(payload, key: bytes):
    """Source-side helper. Never expose a configured signer to the model."""
    return hmac.digest(key, canonical_payload(payload), "sha256").hex()


class HMACSourceVerifier:
    def __init__(self, registry: SourceRegistry):
        self.registry = registry

    def verify(self, source_id, payload, proof):
        source = self.registry.get(source_id)
        if type(proof) is not str or len(proof) != 64 or not proof.isascii():
            raise TelemetryError("invalid_authentication")
        expected = hmac.digest(source.key, payload, "sha256").hex()
        if not hmac.compare_digest(expected, proof):
            raise TelemetryError("invalid_authentication")
        return source.event_types
