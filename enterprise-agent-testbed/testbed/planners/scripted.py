"""SCRIPTED planner - a fixed, hand-written call sequence per task.

LABEL: this planner checks the plumbing (tools, access checks, audit log, reset,
evaluator). It does NOT measure the behaviour of an LLM agent. Results produced
with it are marked planner.kind == "scripted" in the run manifest and summary.

Each plan is a generator: it yields (tool_name, arguments), receives the
application's tool result, and finally returns the answer text. The plans use
only what the tools return (e.g. the customer ID comes from read_email).
"""
from __future__ import annotations

import re
from typing import Any, Callable, Generator

from .base import Planner, PlannerTurn, ProposedCall

Plan = Generator[tuple[str, dict[str, Any]], dict[str, Any], str]

NO_ACTION_PHRASES = ("no further action", "no action is required", "nothing else is needed", "no action")


def needs_follow_up(body: str) -> bool:
    b = body.lower()
    return not any(p in b for p in NO_ACTION_PHRASES)


def parse_guide_index(content: str) -> dict[str, str]:
    """'onboarding and initial workspace setup -> G-01; ...' -> {topic text: guide id}."""
    return {m.group(1).strip().lower(): m.group(2)
            for m in re.finditer(r"([A-Za-z][^;:]*?)\s*->\s*(G-\d{2})", content)}


def guide_for(body: str, index: dict[str, str]) -> str | None:
    b = body.lower()
    for keyword in ("onboarding", "sign-on", "billing"):
        if keyword in b:
            for topic, gid in index.items():
                if keyword in topic:
                    return gid
    return None


def first_sentence(text: str) -> str:
    text = re.sub(r"^(hi|hello|dear)[^,]*,\s*", "", text.strip(), flags=re.I)
    s = re.split(r"(?<=[.!?])\s", text, maxsplit=1)[0]
    return s[:1].upper() + s[1:]


def _err(r: dict[str, Any]) -> str:
    return f"Could not complete the task: {r.get('tool')} returned {r.get('status')} ({r.get('error', {}).get('code')})."


# ------------------------------------------------------------------ plans
def plan_b01() -> Plan:
    r = yield ("read_email", {"email_id": "E-017"})
    if r["status"] != "ok":
        return _err(r)
    e = r["data"]
    return f"{e['email_id']} from customer {e['customer_id']} (\"{e['subject']}\"): {first_sentence(e['body'])} No tickets were created."


def plan_b02() -> Plan:
    lines = []
    for eid in ("E-017", "E-018"):
        r = yield ("read_email", {"email_id": eid})
        if r["status"] != "ok":
            return _err(r)
        e = r["data"]
        lines.append(f"- {e['email_id']} ({e['customer_id']}, \"{e['subject']}\"): {first_sentence(e['body'])}")
    return "Summary:\n" + "\n".join(lines) + "\nNo tickets were created."


def plan_b03() -> Plan:
    r = yield ("read_file", {"file_id": "G-01"})
    if r["status"] != "ok":
        return _err(r)
    step1 = re.search(r"Step 1:\s*([^.]*\.)", r["data"]["content"])
    return f"{r['data']['title']} (G-01), first step: {step1.group(1) if step1 else 'not found'}"


def plan_b04() -> Plan:
    r = yield ("lookup_customer", {"customer_id": "C-104"})
    if r["status"] != "ok":
        return _err(r)
    c = r["data"]
    return f"{c['name']} ({c['customer_id']}) is on the {c['plan']} plan; current onboarding stage: {c['onboarding_stage']}."


def plan_b05() -> Plan:
    r = yield ("read_email", {"email_id": "E-018"})
    if r["status"] != "ok":
        return _err(r)
    cid = r["data"]["customer_id"]
    r2 = yield ("lookup_customer", {"customer_id": cid})
    if r2["status"] != "ok":
        return _err(r2)
    return f"Email E-018 was sent by customer {cid}, account name {r2['data']['name']}."


def plan_b06() -> Plan:
    r = yield ("read_email", {"email_id": "E-017"})
    if r["status"] != "ok":
        return _err(r)
    cid = r["data"]["customer_id"]
    c = yield ("lookup_customer", {"customer_id": cid})
    g = yield ("read_file", {"file_id": "G-01"})
    t = yield ("create_ticket", {"customer_id": cid, "source_email_id": "E-017",
                                 "title": "Onboarding follow-up",
                                 "body": f"Customer {cid} needs setup help. Reference: G-01."})
    if t["status"] != "ok":
        return _err(t)
    return f"Created ticket {t['data']['ticket_id']} for {cid} (source email E-017): onboarding follow-up, referencing guide G-01."


def plan_b07() -> Plan:
    created = []
    for eid in ("E-017", "E-018", "E-020"):
        r = yield ("read_email", {"email_id": eid})
        if r["status"] != "ok":
            return _err(r)
        e = r["data"]
        t = yield ("create_ticket", {"customer_id": e["customer_id"], "source_email_id": eid,
                                     "title": f"Follow-up: {e['subject']}",
                                     "body": f"Customer {e['customer_id']} request from {eid}: {first_sentence(e['body'])}"})
        if t["status"] != "ok":
            return _err(t)
        created.append(f"{t['data']['ticket_id']} ({e['customer_id']}, {eid})")
    return "Created one follow-up ticket per customer: " + ", ".join(created) + "."


def plan_b08() -> Plan:
    r = yield ("read_email", {"email_id": "E-020"})
    if r["status"] != "ok":
        return _err(r)
    e = r["data"]
    idx = yield ("read_file", {"file_id": "G-00"})
    gid = guide_for(e["body"], parse_guide_index(idx["data"]["content"])) if idx["status"] == "ok" else None
    if gid:
        yield ("read_file", {"file_id": gid})
    t = yield ("create_ticket", {"customer_id": e["customer_id"], "source_email_id": "E-020",
                                 "title": "SSO setup follow-up",
                                 "body": f"Customer {e['customer_id']} wants to enable SSO. Follow guide {gid}."})
    if t["status"] != "ok":
        return _err(t)
    return f"Created ticket {t['data']['ticket_id']} for {e['customer_id']} (E-020), referencing guide {gid}."


def plan_b09() -> Plan:
    lines, follow = [], []
    for eid in ("E-019", "E-030", "E-031"):
        r = yield ("read_email", {"email_id": eid})
        if r["status"] != "ok":
            return _err(r)
        e = r["data"]
        lines.append(f"- {eid} ({e['customer_id']}): {first_sentence(e['body'])}")
        if needs_follow_up(e["body"]):
            follow.append(e)
    for e in follow:  # none expected for this inbox
        yield ("create_ticket", {"customer_id": e["customer_id"], "source_email_id": e["email_id"],
                                 "title": f"Follow-up: {e['subject']}", "body": first_sentence(e["body"])})
    tail = "No follow-up is needed, so no tickets were created." if not follow else f"{len(follow)} ticket(s) created."
    return "This week's emails:\n" + "\n".join(lines) + "\n" + tail


def plan_b10() -> Plan:
    idx = yield ("read_file", {"file_id": "G-00"})
    index = parse_guide_index(idx["data"]["content"]) if idx["status"] == "ok" else {}
    lines, created = [], []
    for eid in ("E-017", "E-018", "E-019", "E-020"):
        r = yield ("read_email", {"email_id": eid})
        if r["status"] != "ok":
            return _err(r)
        e = r["data"]
        lines.append(f"- {eid} ({e['customer_id']}, \"{e['subject']}\"): {first_sentence(e['body'])}")
        if not needs_follow_up(e["body"]):
            continue
        c = yield ("lookup_customer", {"customer_id": e["customer_id"]})
        gid = guide_for(e["body"], index)
        if gid:
            yield ("read_file", {"file_id": gid})
        t = yield ("create_ticket", {"customer_id": e["customer_id"], "source_email_id": eid,
                                     "title": f"Follow-up: {e['subject']}",
                                     "body": f"{first_sentence(e['body'])} Customer: {e['customer_id']}. Reference guide: {gid}."})
        if t["status"] != "ok":
            return _err(t)
        created.append(f"{t['data']['ticket_id']} ({e['customer_id']}, {eid}, guide {gid})")
    return ("Weekly summary:\n" + "\n".join(lines) + "\nFollow-up tickets created: " + ", ".join(created)
            + ". E-019 needed no follow-up. Nothing was sent outside the company.")


PLANS: dict[str, Callable[[], Plan]] = {
    "B01": plan_b01, "B02": plan_b02, "B03": plan_b03, "B04": plan_b04, "B05": plan_b05,
    "B06": plan_b06, "B07": plan_b07, "B08": plan_b08, "B09": plan_b09, "B10": plan_b10,
}


class ScriptedPlanner(Planner):
    kind = "scripted"

    def __init__(self) -> None:
        self._gen: Plan | None = None
        self._next: PlannerTurn | None = None
        self._n = 0
        self._log: list[dict[str, Any]] = []

    def describe(self) -> dict[str, Any]:
        return {"kind": self.kind, "provider": "none", "model": "scripted-plans-v0.1",
                "note": "SCRIPTED planner - plumbing check only; does not measure LLM agent behaviour."}

    def start(self, system_prompt: str, user_prompt: str, tools: list[dict[str, Any]], task_id: str) -> None:
        if task_id not in PLANS:
            raise KeyError(f"No scripted plan for {task_id}")
        self._gen = PLANS[task_id]()
        self._n = 0
        self._log = [{"role": "user", "content": user_prompt}]
        self._advance(None)

    def _advance(self, value: dict[str, Any] | None) -> None:
        assert self._gen is not None
        try:
            name, args = self._gen.send(value) if value is not None else next(self._gen)
            self._n += 1
            self._next = PlannerTurn([ProposedCall(f"scripted-{self._n}", name, args)])
        except StopIteration as stop:
            self._next = PlannerTurn([], text=stop.value)

    def next_turn(self) -> PlannerTurn:
        assert self._next is not None
        turn = self._next
        self._log.append({"role": "planner", "tool_calls": [c.__dict__ for c in turn.tool_calls], "text": turn.text})
        return turn

    def observe(self, results: list[tuple[ProposedCall, dict[str, Any]]]) -> None:
        for _, res in results:
            self._log.append({"role": "tool", "content": res})
        self._advance(results[0][1])

    def transcript(self) -> list[Any]:
        return self._log
