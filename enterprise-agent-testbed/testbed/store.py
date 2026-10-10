"""Fixture reset and the local JSON data store.

The store reads synthetic fixtures from STATE_DIR. `reset_state()` rebuilds
STATE_DIR from the seed so every task starts from the same, known state.
create_ticket is the only write; it is atomic (write temp file + os.replace),
so an error can never leave a half-written ticket store.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .config import SEED_DIR, STATE_DIR


def fixture_version(seed_dir: Path = SEED_DIR) -> str:
    """Content hash of the seed fixtures, recorded in every run manifest."""
    h = hashlib.sha256()
    for p in sorted(seed_dir.glob("*.json")):
        h.update(p.name.encode())
        h.update(p.read_bytes())
    return "sha256:" + h.hexdigest()[:16]


def reset_state(state_dir: Path = STATE_DIR, seed_dir: Path = SEED_DIR) -> str:
    """Delete the runtime state and copy the seed fixtures back. Returns fixture version."""
    if state_dir.exists():
        shutil.rmtree(state_dir)
    shutil.copytree(seed_dir, state_dir)
    return fixture_version(seed_dir)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


class Store:
    """Tiny JSON-file store over the runtime state directory."""

    def __init__(self, state_dir: Path = STATE_DIR):
        self.state_dir = Path(state_dir)
        if not self.state_dir.exists():
            raise FileNotFoundError(f"State dir {self.state_dir} missing - run `python run.py reset` first.")

    # ---------- reads ----------
    def _load(self, name: str) -> list[dict[str, Any]]:
        with open(self.state_dir / f"{name}.json", encoding="utf-8") as f:
            return json.load(f)

    def _find(self, name: str, key: str, value: str) -> dict[str, Any] | None:
        for row in self._load(name):
            if row.get(key) == value:
                return row
        return None

    def get_email(self, email_id: str) -> dict[str, Any] | None:
        return self._find("emails", "email_id", email_id)

    def get_file(self, file_id: str) -> dict[str, Any] | None:
        return self._find("files", "file_id", file_id)

    def get_customer(self, customer_id: str) -> dict[str, Any] | None:
        return self._find("customers", "customer_id", customer_id)

    def get_user(self, actor_id: str) -> dict[str, Any] | None:
        return self._find("users", "actor_id", actor_id)

    def list_tickets(self) -> list[dict[str, Any]]:
        return self._load("tickets")

    # ---------- the only write ----------
    def append_ticket(self, *, customer_id: str, source_email_id: str, title: str,
                      body: str, created_by: str) -> dict[str, Any]:
        tickets = self.list_tickets()
        next_num = 1 + max((int(t["ticket_id"].split("-")[1]) for t in tickets), default=0)
        ticket = {
            "ticket_id": f"T-{next_num:03d}",  # assigned by the tool, never by the model
            "customer_id": customer_id,
            "source_email_id": source_email_id,
            "title": title,
            "body": body,
            "label": "Internal",
            "status": "open",
            "created_by": created_by,
            "created_at": utc_now(),
        }
        self._atomic_write("tickets", tickets + [ticket])
        return ticket

    def _atomic_write(self, name: str, data: Any) -> None:
        target = self.state_dir / f"{name}.json"
        fd, tmp = tempfile.mkstemp(dir=self.state_dir, prefix=f".{name}.", suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, target)
        except BaseException:
            if os.path.exists(tmp):
                os.unlink(tmp)
            raise
