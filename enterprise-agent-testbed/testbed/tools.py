"""The four local tools (Session 4, slide 4) and the tool catalog.

Each tool has two parts:
  * resolve(store, args)  -> the resources the call touches (for access checks + logging)
  * execute(store, actor, policy, args, resources) -> the tool output
The ToolRunner calls them in order: validate -> resolve -> authorize -> log -> execute.
read_email / read_file / lookup_customer are read-only; create_ticket is the only write.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Callable

from .config import TOOLS_SCHEMA_PATH
from .policy import AccessPolicy, Actor
from .store import Store


@dataclass
class Resource:
    resource_id: str
    label: str
    assigned_to: list[str]
    record: dict[str, Any]


class ToolError(Exception):
    """A tool-level error with a stable code (not_found, reference_mismatch, ...)."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


# ---------------------------------------------------------------- catalog
def load_catalog() -> dict[str, dict[str, Any]]:
    with open(TOOLS_SCHEMA_PATH, encoding="utf-8") as f:
        doc = json.load(f)
    return {t["name"]: t for t in doc["tools"]}


def tool_schema_version() -> str:
    with open(TOOLS_SCHEMA_PATH, encoding="utf-8") as f:
        return json.load(f)["schema_version"]


# ---------------------------------------------------------------- read_email
def _resolve_email(store: Store, args: dict) -> list[Resource]:
    email = store.get_email(args["email_id"])
    if email is None:
        raise ToolError("not_found", f"No email with ID {args['email_id']}.")
    customer = store.get_customer(email["customer_id"])
    if customer is None:
        raise ToolError("not_found", f"Email {email['email_id']} references unknown customer.")
    # An email inherits its customer's assignment.
    return [Resource(email["email_id"], email["label"], customer["assigned_to"], email)]


def _exec_read_email(store: Store, actor: Actor, policy: AccessPolicy, args: dict, res: list[Resource]) -> dict:
    e = res[0].record
    return {
        "source_id": e["email_id"],
        "email_id": e["email_id"],
        "customer_id": e["customer_id"],
        "from": e["from"],
        "received_at": e["received_at"],
        "subject": e["subject"],
        "body": e["body"],
        "label": e["label"],
    }


# ---------------------------------------------------------------- read_file
def _resolve_file(store: Store, args: dict) -> list[Resource]:
    doc = store.get_file(args["file_id"])
    if doc is None:
        raise ToolError("not_found", f"No document with ID {args['file_id']}.")
    return [Resource(doc["file_id"], doc["label"], doc["assigned_to"], doc)]


def _exec_read_file(store: Store, actor: Actor, policy: AccessPolicy, args: dict, res: list[Resource]) -> dict:
    d = res[0].record
    return {"source_id": d["file_id"], "file_id": d["file_id"], "title": d["title"],
            "label": d["label"], "content": d["content"]}


# ---------------------------------------------------------------- lookup_customer
def _resolve_customer(store: Store, args: dict) -> list[Resource]:
    c = store.get_customer(args["customer_id"])
    if c is None:
        raise ToolError("not_found", f"No customer with ID {args['customer_id']}.")
    return [Resource(c["customer_id"], c["label"], c["assigned_to"], c)]


CUSTOMER_FIELDS = ["customer_id", "name", "plan", "region", "onboarding_stage", "primary_contact", "label"]


def _exec_lookup_customer(store: Store, actor: Actor, policy: AccessPolicy, args: dict, res: list[Resource]) -> dict:
    c = res[0].record
    out = {k: c[k] for k in CUSTOMER_FIELDS}
    out["source_id"] = c["customer_id"]
    # Field-level rule from the policy file: restricted_fields carry their own label.
    if policy.can_read_label(actor, policy.field_label("lookup_customer.restricted_fields")):
        out["restricted_fields"] = c["restricted_fields"]
        out["withheld_fields"] = []
    else:
        out["withheld_fields"] = ["restricted_fields"]
    return out


# ---------------------------------------------------------------- create_ticket
def _resolve_ticket(store: Store, args: dict) -> list[Resource]:
    customer = store.get_customer(args["customer_id"])
    if customer is None:
        raise ToolError("not_found", f"No customer with ID {args['customer_id']}.")
    email = store.get_email(args["source_email_id"])
    if email is None:
        raise ToolError("not_found", f"No email with ID {args['source_email_id']}.")
    email_customer = store.get_customer(email["customer_id"])
    email_assigned = email_customer["assigned_to"] if email_customer else []
    return [
        Resource(customer["customer_id"], customer["label"], customer["assigned_to"], customer),
        Resource(email["email_id"], email["label"], email_assigned, email),
    ]


def check_ticket_consistency(args: dict, res: list[Resource]) -> None:
    """Semantic check that JSON Schema cannot express: the email must belong to the customer.
    Contradictory references are rejected, never silently repaired."""
    email = res[1].record
    if email["customer_id"] != args["customer_id"]:
        raise ToolError(
            "reference_mismatch",
            f"Email {email['email_id']} belongs to {email['customer_id']}, not {args['customer_id']}. No ticket created.",
        )


def _exec_create_ticket(store: Store, actor: Actor, policy: AccessPolicy, args: dict, res: list[Resource]) -> dict:
    check_ticket_consistency(args, res)
    title, body = args["title"].strip(), args["body"].strip()
    if len(title) < 3 or len(body) < 3:
        raise ToolError("invalid_value", "title and body need at least 3 non-space characters. No ticket created.")
    return store.append_ticket(
        customer_id=args["customer_id"],
        source_email_id=args["source_email_id"],
        title=title,
        body=body,
        created_by=actor.actor_id,  # from trusted session context
    )


# ---------------------------------------------------------------- registry
@dataclass
class ToolImpl:
    resolve: Callable[[Store, dict], list[Resource]]
    execute: Callable[[Store, Actor, AccessPolicy, dict, list[Resource]], dict]
    result_ref: Callable[[dict], str]


TOOL_IMPLS: dict[str, ToolImpl] = {
    "read_email": ToolImpl(_resolve_email, _exec_read_email, lambda o: o["source_id"]),
    "read_file": ToolImpl(_resolve_file, _exec_read_file, lambda o: o["source_id"]),
    "lookup_customer": ToolImpl(_resolve_customer, _exec_lookup_customer, lambda o: o["source_id"]),
    "create_ticket": ToolImpl(_resolve_ticket, _exec_create_ticket, lambda o: o["ticket_id"]),
}
