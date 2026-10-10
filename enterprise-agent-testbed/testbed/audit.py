"""Append-only JSONL audit log, validated against schemas/audit_event.schema.json.

Events are produced by application code (the tool runner), never by the model.
Each tool call gets a 'pre' event (proposed call + decision, written BEFORE
execution) and a 'post' event (what actually happened), linked by call_id.
"""
from __future__ import annotations

import hashlib
import json
import os
import uuid
from pathlib import Path
from typing import Any, Callable

from jsonschema import Draft202012Validator

from .config import AUDIT_SCHEMA_PATH, AUDIT_SCHEMA_VERSION
from .store import utc_now

MAX_ARG_CHARS = 200


class AuditSchemaError(RuntimeError):
    pass


def sanitize_arguments(args: Any) -> dict[str, Any]:
    """Keep IDs verbatim; truncate long free text and keep a hash so it stays verifiable."""
    if not isinstance(args, dict):
        text = str(args)
        return {"_unparsed": text[:MAX_ARG_CHARS], "_length": len(text)}
    out: dict[str, Any] = {}
    for k, v in args.items():
        if isinstance(v, str) and len(v) > MAX_ARG_CHARS:
            out[k] = {"preview": v[:MAX_ARG_CHARS], "length": len(v),
                      "sha256": hashlib.sha256(v.encode()).hexdigest()}
        else:
            out[k] = v
    return out


class AuditLogger:
    def __init__(self, path: Path, run_id: str, policy_version: str,
                 echo: Callable[[dict], None] | None = None):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.touch(exist_ok=True)  # the log exists even if no call is ever made
        self.run_id = run_id
        self.policy_version = policy_version
        self.echo = echo
        with open(AUDIT_SCHEMA_PATH, encoding="utf-8") as f:
            self.validator = Draft202012Validator(json.load(f))
        self.events: list[dict[str, Any]] = []

    def log(self, **fields: Any) -> dict[str, Any]:
        event = {
            "schema_version": AUDIT_SCHEMA_VERSION,
            "event_id": uuid.uuid4().hex,
            "timestamp": utc_now(),
            "run_id": self.run_id,
            "policy_version": self.policy_version,
            **fields,
        }
        errors = sorted(self.validator.iter_errors(event), key=lambda e: list(e.path))
        if errors:
            msgs = "; ".join(f"{list(e.path)}: {e.message}" for e in errors)
            raise AuditSchemaError(f"Audit event violates schema: {msgs}")
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(json.dumps(event, ensure_ascii=False) + "\n")
            f.flush()
            os.fsync(f.fileno())
        self.events.append(event)
        if self.echo:
            self.echo(event)
        return event

    def events_for(self, task_id: str, trial: int) -> list[dict[str, Any]]:
        return [e for e in self.events if e["task_id"] == task_id and e["trial"] == trial]


def read_audit_log(path: Path) -> list[dict[str, Any]]:
    with open(path, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]
