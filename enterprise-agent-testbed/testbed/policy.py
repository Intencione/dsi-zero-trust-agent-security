"""Basic access checks: the toy role x resource-label matrix from Session 4, slide 6.

Enforced in application code (the tool runner) BEFORE any tool executes -
never only in the prompt. Default deny. Every Internal/Restricted grant also
requires that the resource is assigned to the caller.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from .config import POLICY_PATH


@dataclass(frozen=True)
class Actor:
    """Trusted caller identity. Comes from the session, never from model output."""
    actor_id: str
    role: str


@dataclass(frozen=True)
class Decision:
    decision: str  # "allow" | "deny"
    reason: str

    @property
    def allowed(self) -> bool:
        return self.decision == "allow"


ALLOW = "allow"
DENY = "deny"


class AccessPolicy:
    def __init__(self, path: Path = POLICY_PATH):
        with open(path, encoding="utf-8") as f:
            self.doc = json.load(f)
        self.version: str = self.doc["policy_version"]
        self.roles: dict = self.doc["roles"]
        self.operations: dict = self.doc["operations"]
        self.assignment_required: set[str] = set(self.doc["assignment_required_for"])
        self.default_decision: str = self.doc["default_decision"]
        if self.default_decision != DENY:
            raise ValueError("policy-0.1 requires default_decision = deny")
        self.field_labels: dict[str, str] = self.doc.get("field_level", {})

    def operation_known(self, tool: str) -> Decision:
        if tool in self.operations:
            return Decision(ALLOW, f"{tool} is a listed operation")
        return Decision(self.default_decision, f"default deny: '{tool}' is not a listed operation")

    def field_label(self, field: str) -> str:
        """Label of a sensitive field (e.g. 'lookup_customer.restricted_fields' -> 'Restricted')."""
        return self.field_labels.get(field, "Restricted")  # unknown sensitive fields: most restrictive

    def can_read_label(self, actor: Actor, label: str) -> bool:
        role = self.roles.get(actor.role)
        return bool(role) and label in role["read"]

    @staticmethod
    def _assigned(actor: Actor, assigned_to: Iterable[str]) -> bool:
        assigned = list(assigned_to)
        return "*" in assigned or actor.actor_id in assigned

    def check_read(self, actor: Actor, resource_id: str, label: str, assigned_to: Iterable[str]) -> Decision:
        if actor.role not in self.roles:
            return Decision(DENY, f"unknown role '{actor.role}'")
        if not self.can_read_label(actor, label):
            return Decision(DENY, f"role {actor.role} may not read {label} resource {resource_id}")
        if label in self.assignment_required and not self._assigned(actor, assigned_to):
            return Decision(DENY, f"{resource_id} is not assigned to {actor.actor_id}")
        return Decision(ALLOW, f"{actor.role} may read {label} resource {resource_id}")

    def check_write(self, actor: Actor, target_label: str) -> Decision:
        role = self.roles.get(actor.role)
        if not role:
            return Decision(DENY, f"unknown role '{actor.role}'")
        if target_label not in role["write"]:
            return Decision(DENY, f"role {actor.role} may not create {target_label} records")
        return Decision(ALLOW, f"{actor.role} may create {target_label} records")

    @staticmethod
    def combine(*decisions: Decision) -> Decision:
        """All must allow; the first denial is reported."""
        for d in decisions:
            if not d.allowed:
                return d
        return Decision(ALLOW, "; ".join(d.reason for d in decisions))
