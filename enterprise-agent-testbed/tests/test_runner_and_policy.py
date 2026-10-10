"""Tool runner, access policy and audit log behave as specified."""
from __future__ import annotations

import json

from testbed.config import CANARY


def _post(env, call_id):
    return next(e for e in env["audit"].events if e["call_id"] == call_id and e["phase"] == "post")


def test_walkthrough_slide8(env):
    r = env["runner"]("u_operator", "B10")
    assert r.execute("read_email", {"email_id": "E-017"})["status"] == "ok"
    assert r.execute("lookup_customer", {"customer_id": "C-104"})["status"] == "ok"
    assert r.execute("read_file", {"file_id": "G-01"})["status"] == "ok"
    res = r.execute("create_ticket", {"customer_id": "C-104", "source_email_id": "E-017",
                                      "title": "Onboarding follow-up",
                                      "body": "Customer C-104 needs setup help. Reference: G-01."})
    assert res["status"] == "ok" and res["data"]["ticket_id"] == "T-001"
    tickets = env["store"].list_tickets()
    assert len(tickets) == 1 and tickets[0]["created_by"] == "u_operator"
    post = _post(env, res["call_id"])
    assert post["step"] == 4 and post["result_ref"] == "T-001"
    assert post["state_change"] == {"tickets_created": 1, "ticket_ids": ["T-001"]}


def test_every_call_has_pre_then_post(env):
    r = env["runner"]()
    for args in ({"email_id": "E-017"}, {"email_id": "E-999"}, {"email_id": "E-040"}):
        r.execute("read_email", args)
    ev = env["audit"].events
    assert [e["phase"] for e in ev] == ["pre", "post"] * 3
    assert all(ev[i]["call_id"] == ev[i + 1]["call_id"] for i in range(0, 6, 2))


def test_operator_cannot_read_restricted(env):
    res = env["runner"]("u_operator").execute("read_file", {"file_id": "F-99"})
    assert res["status"] == "denied"
    assert CANARY not in json.dumps(res)


def test_role_from_session_not_arguments(env):
    res = env["runner"]("u_operator").execute(
        "create_ticket", {"customer_id": "C-104", "source_email_id": "E-017", "title": "abc", "body": "abc",
                          "role": "Admin"})
    assert res["status"] == "error" and res["error"]["code"] == "schema_invalid"
    assert env["store"].list_tickets() == []


def test_valid_json_can_still_be_unauthorized(env):
    """Shape validation != authorization (slide 5)."""
    res = env["runner"]("u_analyst").execute(
        "create_ticket", {"customer_id": "C-104", "source_email_id": "E-017", "title": "abc", "body": "abc"})
    assert res["status"] == "denied"
    pre = next(e for e in env["audit"].events if e["phase"] == "pre")
    assert pre["schema_valid"] is True and pre["decision"] == "deny"
    assert env["store"].list_tickets() == []


def test_reference_mismatch_not_repaired(env):
    res = env["runner"]().execute(
        "create_ticket", {"customer_id": "C-105", "source_email_id": "E-017", "title": "abc", "body": "abc"})
    assert res["error"]["code"] == "reference_mismatch"
    assert env["store"].list_tickets() == []


def test_unassigned_customer_denied_even_for_internal_label(env):
    assert env["runner"]("u_operator").execute("lookup_customer", {"customer_id": "C-200"})["status"] == "denied"
    assert env["runner"]("u_admin").execute("lookup_customer", {"customer_id": "C-200"})["status"] == "ok"


def test_field_level_restriction(env):
    op = env["runner"]("u_operator").execute("lookup_customer", {"customer_id": "C-104"})["data"]
    ad = env["runner"]("u_admin").execute("lookup_customer", {"customer_id": "C-104"})["data"]
    assert "restricted_fields" not in op and op["withheld_fields"] == ["restricted_fields"]
    assert "restricted_fields" in ad and ad["withheld_fields"] == []


def test_unlisted_tool_default_deny(env):
    res = env["runner"]("u_admin").execute("send_email", {"to": "x@outside.example"})
    assert res["status"] == "denied" and res["error"]["code"] == "unknown_tool"


def test_malformed_json_arguments(env):
    res = env["runner"]().execute("read_email", '{"email_id": "E-017"')
    assert res["status"] == "error" and res["error"]["code"] == "schema_invalid"


def test_ticket_ids_assigned_by_tool(env):
    r = env["runner"]()
    ids = [r.execute("create_ticket", {"customer_id": c, "source_email_id": e, "title": "abc", "body": "abc"})
           ["data"]["ticket_id"] for c, e in [("C-104", "E-017"), ("C-105", "E-018")]]
    assert ids == ["T-001", "T-002"]


def test_atomic_write_leaves_no_partial_state(env, monkeypatch):
    import os
    store = env["store"]

    def boom(*a, **k):
        raise OSError("disk full (simulated)")

    monkeypatch.setattr(os, "replace", boom)
    res = env["runner"]().execute(
        "create_ticket", {"customer_id": "C-104", "source_email_id": "E-017", "title": "abc", "body": "abc"})
    monkeypatch.undo()
    assert res["status"] == "error" and res["error"]["code"] == "execution_error"
    assert store.list_tickets() == []
    assert not list(store.state_dir.glob("*.tmp"))
    post = next(e for e in env["audit"].events if e["phase"] == "post")
    assert post["state_change"]["tickets_created"] == 0


def test_reset_restores_seed(tmp_path):
    from testbed.store import Store, reset_state
    state = tmp_path / "s"
    v1 = reset_state(state_dir=state)
    Store(state).append_ticket(customer_id="C-104", source_email_id="E-017", title="t", body="b", created_by="u")
    v2 = reset_state(state_dir=state)
    assert v1 == v2 and Store(state).list_tickets() == []
