"""Single-writer SQLite snapshot adapter; no secrets or executable serialization.

The unit of commit is the full telemetry state, including replay, health and
audit. This intentionally simple adapter favors correctness over throughput.
"""

from contextlib import contextmanager
import fcntl
import json
import os
import sqlite3

from telemetry.store import InMemoryEventStore


class SQLiteEventStore(InMemoryEventStore):
    requires_transaction = True

    def __init__(self, path):
        super().__init__()
        path = os.path.realpath(os.fspath(path))
        self._connection = None
        self._lease = os.open(str(path) + ".lock", os.O_CREAT | os.O_RDWR, 0o600)
        try:
            fcntl.flock(self._lease, fcntl.LOCK_EX | fcntl.LOCK_NB)
            descriptor = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
            os.close(descriptor)
            self._connection = sqlite3.connect(path, isolation_level=None, check_same_thread=False)
            self._connection.execute("PRAGMA synchronous=FULL")
            self._connection.execute("CREATE TABLE IF NOT EXISTS telemetry_state (id INTEGER PRIMARY KEY CHECK(id=1), data TEXT NOT NULL)")
            self._connection.execute("CREATE TABLE IF NOT EXISTS telemetry_meta (id INTEGER PRIMARY KEY CHECK(id=1), initialized INTEGER NOT NULL)")
            row = self._connection.execute("SELECT data FROM telemetry_state WHERE id=1").fetchone()
            meta = self._connection.execute("SELECT initialized FROM telemetry_meta WHERE id=1").fetchone()
            if row:
                self.restore(json.loads(row[0]))
            elif meta and meta[0]:
                raise ValueError("Persistent telemetry state is missing")
        except BaseException:
            self.close()
            raise

    def _commit_snapshot(self):
        self._connection.execute(
            "INSERT INTO telemetry_state VALUES (1, ?) ON CONFLICT(id) DO UPDATE SET data=excluded.data",
            (json.dumps(self.snapshot(), sort_keys=True, allow_nan=False),),
        )
        self._connection.execute("INSERT INTO telemetry_meta VALUES (1, 1) ON CONFLICT(id) DO UPDATE SET initialized=1")
        self._connection.execute("COMMIT")

    def accept_batch(self, events, now):
        if self._connection is None or not self._connection.in_transaction:
            raise RuntimeError("Telemetry mutations require a transaction")
        return super().accept_batch(events, now)

    def expire(self, now):
        if self._connection is None or not self._connection.in_transaction:
            raise RuntimeError("Telemetry mutations require a transaction")
        return super().expire(now)

    @contextmanager
    def transaction(self):
        with self._lock:
            before = self.snapshot()
            try:
                self._connection.execute("BEGIN IMMEDIATE")
                yield
                self._commit_snapshot()
            except BaseException:
                self.restore(before)
                if self._connection is not None and self._connection.in_transaction:
                    self._connection.execute("ROLLBACK")
                raise

    def close(self):
        if self._connection is not None:
            self._connection.close()
            self._connection = None
        if self._lease is not None:
            os.close(self._lease)
            self._lease = None
