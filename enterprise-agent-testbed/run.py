#!/usr/bin/env python3
"""Enterprise Operations Assistant v0.1 - command-line entry point.

  python run.py reset                                   # rebuild state/ from fixtures/seed
  python run.py baseline --planner openai --model <model>      # REAL LLM baseline (10 tasks)
  python run.py baseline --planner anthropic --model <model>
  python run.py baseline --planner scripted             # plumbing check (labelled, not an LLM result)
  python run.py authz                                   # separate authorization checks
  python run.py validate                                # validate task file + schemas
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))


def load_dotenv(path: Path = ROOT / ".env") -> None:
    """Minimal .env loader (KEY=VALUE lines). Within the file the LAST value wins (like python-dotenv);
    variables already set in the shell win over the file. Empty values are ignored
    (an empty *_BASE_URL would break the SDKs)."""
    if not path.exists():
        return
    values: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip().removeprefix("export ").strip()
        value = value.split(" #")[0].strip().strip('"').strip("'")
        if value:
            values[key] = value
    for key, value in values.items():
        os.environ.setdefault(key, value)


def main() -> int:
    load_dotenv()
    ap = argparse.ArgumentParser(description="Enterprise Operations Assistant v0.1 testbed")
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("reset", help="rebuild state/ from fixtures/seed (0 tickets)")
    sub.add_parser("validate", help="validate the task file and JSON schemas")

    b = sub.add_parser("baseline", help="run the benign tasks and save results + audit logs")
    b.add_argument("--planner", choices=["openai", "anthropic", "scripted"],
                   default=os.environ.get("PLANNER", "openai"))
    b.add_argument("--model", default=os.environ.get("MODEL"), help="model name (required for LLM planners)")
    b.add_argument("--base-url", default=None, help="override endpoint (OpenAI-compatible: also OPENAI_BASE_URL)")
    b.add_argument("--temperature", type=float, default=None, help="omit to use the provider default")
    b.add_argument("--max-tokens", type=int, default=None)
    b.add_argument("--extra-body", default=os.environ.get("EXTRA_BODY"),
                   help='provider-specific JSON, e.g. \'{"thinking": {"type": "disabled"}}\'')
    b.add_argument("--no-preflight", action="store_true", help="skip the one-request endpoint check")
    b.add_argument("--tasks", default=None, help="comma-separated subset, e.g. B06,B09")
    b.add_argument("--trials", type=int, default=1, help="trials per task (clean reset before each)")
    b.add_argument("--max-turns", type=int, default=40, help="planner turns per trial (default 40)")
    b.add_argument("--run-id", default=None)
    b.add_argument("--label", default="", help="free-text note stored in the manifest")
    b.add_argument("-v", "--verbose", action="store_true", help="print every tool call as it happens")

    a = sub.add_parser("authz", help="run the separate authorization/validation checks (no model)")
    a.add_argument("--run-id", default=None)
    a.add_argument("-v", "--verbose", action="store_true")

    args = ap.parse_args()

    from testbed.experiment import load_tasks, run_authz, run_baseline
    from testbed.store import reset_state

    if args.cmd == "reset":
        print(f"State reset from fixtures/seed (fixture version {reset_state()}).")
        return 0

    if args.cmd == "validate":
        import json
        from jsonschema import Draft202012Validator
        doc = load_tasks()
        for name in ["audit_event.schema.json", "task.schema.json"]:
            Draft202012Validator.check_schema(json.loads((ROOT / "schemas" / name).read_text(encoding="utf-8")))
        for t in json.loads((ROOT / "schemas" / "tools.json").read_text(encoding="utf-8"))["tools"]:
            Draft202012Validator.check_schema(t["input_schema"])
            Draft202012Validator.check_schema(t["output_schema"])
        print(f"OK: {len(doc['tasks'])} benign tasks, 4 tool schemas, audit + task schemas are valid.")
        return 0

    if args.cmd == "authz":
        out = run_authz(run_id=args.run_id, verbose=args.verbose)
        print(f"\nSaved to {out.relative_to(ROOT)}/ (summary.md, results.json, audit.jsonl)")
        return 0

    # baseline
    from testbed.planners import make_planner
    if args.planner != "scripted" and not args.model:
        ap.error("--model is required for LLM planners (or set MODEL in .env)")
    extra_body = None
    if args.extra_body:
        import json
        try:
            extra_body = json.loads(args.extra_body)
        except json.JSONDecodeError as e:
            ap.error(f"--extra-body is not valid JSON: {e}")
    kwargs = {} if args.planner == "scripted" else {
        "model": args.model, "base_url": args.base_url, "temperature": args.temperature,
        "max_tokens": args.max_tokens, "extra_body": extra_body,
    }
    factory = lambda: make_planner(args.planner, **kwargs)  # noqa: E731
    if args.planner == "scripted":
        print("NOTE: scripted planner = plumbing check only; it does not measure an LLM agent.\n")
    task_ids = [t.strip() for t in args.tasks.split(",")] if args.tasks else None
    out = run_baseline(factory, task_ids=task_ids, trials=args.trials, max_turns=args.max_turns,
                       run_id=args.run_id, verbose=args.verbose, label=args.label,
                       preflight=not args.no_preflight)
    print(f"\nSaved to {out.relative_to(ROOT)}/ (summary.md, results.json, audit.jsonl, transcripts/, final_state/)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
