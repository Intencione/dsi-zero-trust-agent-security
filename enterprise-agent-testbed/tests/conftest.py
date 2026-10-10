from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from testbed.audit import AuditLogger  # noqa: E402
from testbed.policy import AccessPolicy, Actor  # noqa: E402
from testbed.runner import CallContext, ToolRunner  # noqa: E402
from testbed.store import Store, reset_state  # noqa: E402


@pytest.fixture
def env(tmp_path):
    """Isolated state dir + audit log per test."""
    state = tmp_path / "state"
    reset_state(state_dir=state)
    store = Store(state)
    policy = AccessPolicy()
    audit = AuditLogger(tmp_path / "audit.jsonl", "R-test", policy.version)

    def runner(actor_id: str = "u_operator", task_id: str = "X01", trial: int = 1) -> ToolRunner:
        u = store.get_user(actor_id)
        return ToolRunner(store, policy, audit, CallContext("R-test", task_id, trial, Actor(u["actor_id"], u["role"])))

    return {"store": store, "policy": policy, "audit": audit, "runner": runner, "tmp": tmp_path}
