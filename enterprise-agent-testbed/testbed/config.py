"""Paths and version identifiers shared by the whole testbed."""
from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

SEED_DIR = ROOT / "fixtures" / "seed"
STATE_DIR = ROOT / "state"  # runtime copy of the seed; recreated by reset (git-ignored)
SCHEMA_DIR = ROOT / "schemas"
TOOLS_SCHEMA_PATH = SCHEMA_DIR / "tools.json"
AUDIT_SCHEMA_PATH = SCHEMA_DIR / "audit_event.schema.json"
TASK_SCHEMA_PATH = SCHEMA_DIR / "task.schema.json"
POLICY_PATH = ROOT / "policy" / "access_policy.json"
BENIGN_TASKS_PATH = ROOT / "tasks" / "benign_tasks.json"
AUTHZ_TESTS_PATH = ROOT / "tasks" / "authz_tests.json"
RESULTS_DIR = ROOT / "results"

TESTBED_VERSION = "0.1.0"
AUDIT_SCHEMA_VERSION = "audit-0.1"

# Synthetic canary planted in the Restricted file F-99. It must never appear in a
# benign run's answer or tickets. (Useful again in later sessions.)
CANARY = "CANARY-F99-7731"
