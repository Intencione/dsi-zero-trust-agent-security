"""Storage contract: acceptance and replay checks must be atomic per batch.

Replay tombstones/high watermarks outlive active events. A future durable adapter
must preserve them across restarts, and coordinate publication with DSI state.
"""

from threading import RLock
from typing import Protocol
from contextlib import contextmanager
from dataclasses import asdict
import copy

from telemetry.events import EventType, TelemetryError, TelemetryEvent


class EventStore(Protocol):
    def accept_batch(self, events: tuple[TelemetryEvent, ...], now: float) -> tuple[TelemetryEvent, ...]: ...
    def expire(self, now: float) -> tuple[TelemetryEvent, ...]: ...
    def active(self) -> tuple[TelemetryEvent, ...]: ...
    def transaction(self): ...
    def snapshot(self) -> dict: ...
    def restore(self, state: dict): ...


class InMemoryEventStore:
    def __init__(self):
        self._seen = set()
        self._sequences = {}
        self._observed = {}
        self._active = {}
        self._lock = RLock()
        self.control = {}
        self.protected_sources = set()
        self._held_streams = set()

    def accept_batch(self, events, now):
        with self._lock:
            seen, sequences, observed = self._seen.copy(), self._sequences.copy(), self._observed.copy()
            for event in events:
                if event.event_id in seen:
                    raise TelemetryError("duplicate_event")
                if event.sequence <= sequences.get(event.source_id, 0):
                    raise TelemetryError("replayed_sequence")
                if event.observed_at < observed.get(event.stream, 0):
                    raise TelemetryError("out_of_order_observation")
                seen.add(event.event_id)
                sequences[event.source_id] = event.sequence
                observed[event.stream] = event.observed_at
            self._seen, self._sequences, self._observed = seen, sequences, observed
            expired = self.expire(now)
            for event in events:
                self._active[event.stream] = event
                self._held_streams.discard(event.stream)
            return expired

    def expire(self, now):
        with self._lock:
            for event in self._active.values():
                if (event.expires_at <= now and event.severity > 0
                        and event.source_id in self.protected_sources):
                    self._held_streams.add(event.stream)
            expired = tuple(event for event in self._active.values()
                            if event.expires_at <= now and event.stream not in self._held_streams)
            for event in expired:
                del self._active[event.stream]
            return expired

    def active(self):
        with self._lock:
            return tuple(self._active.values())

    def snapshot(self):
        return copy.deepcopy({
            "schema_version": 1, "seen": sorted(self._seen), "sequences": self._sequences,
            "observed": [[list(key), value] for key, value in self._observed.items()],
            "active": [asdict(event) for event in self._active.values()],
            "held": [list(key) for key in self._held_streams],
            "protected": sorted(self.protected_sources), "control": self.control,
        })

    def restore(self, state):
        if state.get("schema_version") != 1:
            raise ValueError("Unsupported telemetry store schema")
        self._seen = set(state["seen"])
        self._sequences = dict(state["sequences"])
        self._observed = {tuple(key): value for key, value in state["observed"]}
        events = [TelemetryEvent(**{**item, "event_type": EventType(item["event_type"])})
                  for item in state["active"]]
        self._active = {event.stream: event for event in events}
        self._held_streams = {tuple(key) for key in state["held"]}
        self.protected_sources = set(state["protected"])
        self.control = copy.deepcopy(state["control"])

    @contextmanager
    def transaction(self):
        with self._lock:
            before = self.snapshot()
            try:
                yield
            except BaseException:
                self.restore(before)
                raise
