"""Atomic snapshot storage, separate authority and untrusted checkpoint namespaces."""
from typing import Protocol
from threading import RLock
import fcntl
import os
import sqlite3


class AuthorizationStore(Protocol):
    def load(self) -> str | None: ...
    def save(self, snapshot: str) -> None: ...
    def checkpoint_load(self, key: str) -> str | None: ...
    def checkpoint_save(self, key: str, value: str) -> None: ...
    def close(self) -> None: ...


class MemoryAuthorizationStore:
    def __init__(self):
        self.data = None
        self.checkpoints = {}

    def load(self):
        return self.data

    def save(self, snapshot):
        self.data = snapshot

    def checkpoint_load(self, key):
        return self.checkpoints.get(key)

    def checkpoint_save(self, key, value):
        self.checkpoints[key] = value

    def close(self):
        pass


class SQLiteAuthorizationStore:
    """One live runtime per database, synchronous atomic commits, local POSIX host."""
    def __init__(self, path):
        path = os.path.realpath(os.fspath(path))
        self._lock = RLock()
        self._db = None
        self._lease = os.open(path + '.authorization.lock', os.O_CREAT | os.O_RDWR, 0o600)
        try:
            fcntl.flock(self._lease, fcntl.LOCK_EX | fcntl.LOCK_NB)
            fd = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
            os.close(fd)
            self._db = sqlite3.connect(path, isolation_level=None, check_same_thread=False)
            self._db.execute('PRAGMA synchronous=FULL')
            self._db.execute('CREATE TABLE IF NOT EXISTS authorization (id INTEGER PRIMARY KEY CHECK(id=1), data TEXT NOT NULL)')
            self._db.execute('CREATE TABLE IF NOT EXISTS authorization_meta (id INTEGER PRIMARY KEY CHECK(id=1))')
            self._db.execute('CREATE TABLE IF NOT EXISTS workflow_checkpoints (key TEXT PRIMARY KEY, data TEXT NOT NULL)')
        except BaseException:
            self.close()
            raise

    def load(self):
        with self._lock:
            row = self._db.execute('SELECT data FROM authorization WHERE id=1').fetchone()
            if row is None and self._db.execute('SELECT id FROM authorization_meta').fetchone():
                raise ValueError('Authorization snapshot missing; recovery refused')
            return row[0] if row else None

    def save(self, snapshot):
        with self._lock:
            self._db.execute('BEGIN IMMEDIATE')
            try:
                self._db.execute('INSERT OR REPLACE INTO authorization VALUES (1, ?)', (snapshot,))
                self._db.execute('INSERT OR IGNORE INTO authorization_meta VALUES (1)')
                self._db.execute('COMMIT')
            except BaseException:
                self._db.execute('ROLLBACK')
                raise

    def checkpoint_load(self, key):
        with self._lock:
            row = self._db.execute('SELECT data FROM workflow_checkpoints WHERE key=?', (key,)).fetchone()
            return row[0] if row else None

    def checkpoint_save(self, key, value):
        with self._lock:
            self._db.execute('INSERT OR REPLACE INTO workflow_checkpoints VALUES (?, ?)', (key, value))

    def close(self):
        if self._db is not None:
            self._db.close()
            self._db = None
        if self._lease is not None:
            os.close(self._lease)
            self._lease = None
