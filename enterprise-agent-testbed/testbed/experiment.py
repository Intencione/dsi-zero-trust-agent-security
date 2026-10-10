"""Run the benign baseline and the separate authorization checks; save evidence.

results/<run_id>/
  manifest.json          planner/model/config (+ resolved model), code + fixture + policy + schema versions,
                         system-prompt hash; `completed` becomes true only when the run finishes
  audit.jsonl            every pre/post tool-call event (application-written)
  results.json           per-task, per-trial outcome with every check (rewritten after EVERY trial)
  summary.md             human-readable table (rewritten after every trial; failures kept)
  transcripts/<task>_t<n>.json          planner conversation + agent result
  final_state/<task>_t<n>_tickets.json  persisted ticket store after the trial
"""
from __future__ import annotations

import hashlib
import json
import platform
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from jsonschema import Draft202012Validator

from .agent import DEFAULT_MAX_TURNS, SYSTEM_PROMPT_SHA256, run_agent
from .audit import AuditLogger
from .config import (AUTHZ_TESTS_PATH, BENIGN_TASKS_PATH, CANARY, POLICY_PATH, RESULTS_DIR, ROOT,
                     SEED_DIR, STATE_DIR, TASK_SCHEMA_PATH, TESTBED_VERSION)
from .evaluator import evaluate
from .planners.base import Planner, PlannerUnavailable
from .policy import AccessPolicy, Actor
from .runner import CallContext, ToolRunner
from .store import Store, fixture_version, reset_state, utc_now
from .tools import tool_schema_version

INFRA_STOPS = {"planner_error", "runner_error"}  # failures that are not the agent's behaviour


# ------------------------------------------------------------------ helpers
def load_tasks(path: Path = BENIGN_TASKS_PATH) -> dict[str, Any]:
    with open(path, encoding="utf-8") as f:
        doc = json.load(f)
    with open(TASK_SCHEMA_PATH, encoding="utf-8") as f:
        errors = list(Draft202012Validator(json.load(f)).iter_errors(doc))
    if errors:
        raise ValueError("Task file violates task.schema.json: " + "; ".join(e.message for e in errors[:5]))
    for t in doc["tasks"]:
        seed = ROOT / t["fixture"]["seed"]
        if not (seed / "tickets.json").exists():
            raise ValueError(f"{t['task_id']}: fixture seed {seed} not found")
        missing = [i for i in t["fixture"]["inbox"] if i not in t["prompt"]]
        if missing:
            raise ValueError(f"{t['task_id']}: inbox IDs {missing} are not given to the agent in the prompt")
    return doc


def code_version() -> dict[str, Any]:
    h = hashlib.sha256()
    files = sorted((ROOT / "testbed").rglob("*.py")) + [ROOT / "run.py"] + sorted((ROOT / "schemas").glob("*.json")) \
        + [POLICY_PATH, BENIGN_TASKS_PATH, AUTHZ_TESTS_PATH]
    for p in files:
        if p.exists():
            h.update(str(p.relative_to(ROOT)).encode())
            h.update(p.read_bytes())
    info: dict[str, Any] = {"source_sha256": h.hexdigest()[:16], "git_commit": None, "git_dirty": None}
    try:
        info["git_commit"] = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True,
                                            text=True, check=True).stdout.strip()
        # results/ and state/ are outputs, not code: ignore them when deciding "dirty"
        info["git_dirty"] = bool(subprocess.run(
            ["git", "status", "--porcelain", "--", ".", ":(exclude)results", ":(exclude)state"],
            cwd=ROOT, capture_output=True, text=True, check=True).stdout.strip())
    except Exception:
        pass
    return info


def new_run_dir(results_dir: Path, run_id: str | None, kind: str) -> tuple[str, Path]:
    base = run_id or f"R-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}-{kind}"
    rid, n = base, 1
    while (results_dir / rid).exists():
        if run_id:  # an explicit run id must not overwrite earlier evidence
            raise FileExistsError(f"results/{run_id} already exists - choose another --run-id")
        n += 1
        rid = f"{base}-{n}"
    out = results_dir / rid
    out.mkdir(parents=True)
    return rid, out


def actor_for(store: Store, actor_id: str) -> Actor:
    u = store.get_user(actor_id)
    if u is None:
        raise ValueError(f"Unknown actor {actor_id}")
    return Actor(u["actor_id"], u["role"])  # trusted session identity from fixtures


def _write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False, default=str), encoding="utf-8")


def echo_event(e: dict[str, Any]) -> None:
    if e["phase"] != "post":
        return
    ref = f" -> {e['result_ref']}" if e["result_ref"] else ""
    err = f" [{e['error']['code']}]" if e["error"] else ""
    sc = f" (+{e['state_change']['tickets_created']} ticket)" if e["state_change"]["tickets_created"] else ""
    print(f"    {e['task_id']} step {e['step']:02d}  {e['tool']:<16} {e['decision']:<13} {e['status']}{ref}{err}{sc}")


# ------------------------------------------------------------------ baseline
def run_baseline(planner_factory: Callable[[], Planner], task_ids: list[str] | None = None,
                 trials: int = 1, max_turns: int = DEFAULT_MAX_TURNS, run_id: str | None = None,
                 results_dir: Path = RESULTS_DIR, verbose: bool = False, label: str = "",
                 preflight: bool = True) -> Path:
    tasks_doc = load_tasks()
    tasks = [t for t in tasks_doc["tasks"] if not task_ids or t["task_id"] in task_ids]
    if task_ids and len(tasks) != len(task_ids):
        raise ValueError(f"Unknown task id in {task_ids}")
    probe = planner_factory()
    desc = probe.describe()
    pre_info: dict[str, Any] = {}
    if preflight and desc["kind"] == "llm":
        try:
            pre_info = probe.preflight()  # fail fast on auth / model-name / network problems
        except PlannerUnavailable as e:
            raise SystemExit(f"Preflight failed - the model endpoint is not usable, no run was recorded.\n  {e}")
        print(f"Preflight OK: endpoint {desc.get('base_url_host')} answered as model {pre_info.get('resolved_model')}")
    kind = "scripted" if desc["kind"] == "scripted" else desc.get("provider", "llm")
    run_id, out = new_run_dir(results_dir, run_id, kind)
    policy = AccessPolicy()

    manifest = {
        "run_id": run_id,
        "label": label,
        "created_at": utc_now(),
        "completed": False,
        "testbed_version": TESTBED_VERSION,
        "planner": desc,
        "planner_preflight": pre_info,
        "planner_observed": {},
        "measures_llm_behaviour": desc["kind"] == "llm",
        "system_prompt_sha256": SYSTEM_PROMPT_SHA256,
        "code_version": code_version(),
        "fixture_versions": sorted({f"{t['fixture']['seed']}={fixture_version(ROOT / t['fixture']['seed'])}" for t in tasks}),
        "fixture_version": fixture_version(SEED_DIR),
        "policy_version": policy.version,
        "tool_schema_version": tool_schema_version(),
        "task_set_version": tasks_doc["task_set_version"],
        "tasks": [t["task_id"] for t in tasks],
        "trials_per_task": trials,
        "max_turns": max_turns,
        "reset_between_trials": True,
        "python": sys.version.split()[0],
        "platform": platform.platform(),
    }
    _write_json(out / "manifest.json", manifest)
    audit = AuditLogger(out / "audit.jsonl", run_id, policy.version, echo=echo_event if verbose else None)

    rows: list[dict[str, Any]] = []
    for task in tasks:
        for trial in range(1, trials + 1):
            # clean, identical starting state for every independent trial (the task's own seed)
            reset_state(seed_dir=ROOT / task["fixture"]["seed"])
            store = Store(STATE_DIR)
            start_tickets = store.list_tickets()
            assert len(start_tickets) == task["fixture"]["tickets_at_start"], "fixture reset failed"
            actor = actor_for(store, task["actor_id"])
            runner = ToolRunner(store, policy, audit, CallContext(run_id, task["task_id"], trial, actor))
            planner = planner_factory()
            if verbose:
                print(f"\n[{task['task_id']} trial {trial}] {task['title']}  (actor {actor.actor_id}/{actor.role})")
            agent = run_agent(planner, runner, task["prompt"], task["task_id"], max_turns=max_turns)
            tickets = store.list_tickets()
            events = audit.events_for(task["task_id"], trial)
            ev = evaluate(task, agent, tickets, events, start_tickets=start_tickets)
            tag = f"{task['task_id']}_t{trial}"
            _write_json(out / "final_state" / f"{tag}_tickets.json", tickets)
            _write_json(out / "transcripts" / f"{tag}.json", {
                "task_id": task["task_id"], "trial": trial, "actor": actor.__dict__, "prompt": task["prompt"],
                "stop_reason": agent.stop_reason, "error": agent.error, "final_answer": agent.final_answer,
                "visible_text": agent.visible_text, "tool_calls": agent.tool_calls,
                "planner_transcript": planner.transcript(),
            })
            rows.append({
                "task_id": task["task_id"], "title": task["title"], "trial": trial,
                "actor_id": actor.actor_id, "role": actor.role,
                "success": ev["success"], "failed_checks": ev["failed_checks"],
                "stop_reason": agent.stop_reason, "infrastructure_error": agent.stop_reason in INFRA_STOPS,
                "error": agent.error, "final_answer": agent.final_answer, "metrics": ev["metrics"],
                "checks": ev["checks"],
                "evidence": {"audit_log": "audit.jsonl", "final_state": f"final_state/{tag}_tickets.json",
                             "transcript": f"transcripts/{tag}.json"},
            })
            manifest["planner_observed"] = planner.observed() or manifest["planner_observed"]
            _save(out, manifest, rows)  # after EVERY trial, so an interrupted run keeps its evidence
            mark = "PASS" if ev["success"] else "FAIL"
            stop = f"  stop={agent.stop_reason}" if agent.stop_reason != "final_answer" else ""
            print(f"  {task['task_id']} t{trial}  {mark}  tickets={ev['metrics']['tickets_final']}/"
                  f"{task['expected']['ticket_count']}  calls={ev['metrics']['tool_calls']}{stop}"
                  + (f"  failed={ev['failed_checks']}" if not ev["success"] else ""))
            if agent.stop_reason in INFRA_STOPS and verbose:
                print("    " + (agent.error or "").splitlines()[0])

    manifest["completed"] = True
    manifest["finished_at"] = utc_now()
    _save(out, manifest, rows)
    n_infra = sum(r["infrastructure_error"] for r in rows)
    if n_infra:
        print(f"\nWARNING: {n_infra} trial(s) stopped on an infrastructure error (API/testbed), not agent behaviour. "
              f"See summary.md; fix the cause and re-run rather than reporting these as agent failures.")
    return out


def _save(out: Path, manifest: dict[str, Any], rows: list[dict[str, Any]]) -> None:
    _write_json(out / "manifest.json", manifest)
    _write_json(out / "results.json", {"run_id": manifest["run_id"], "completed": manifest["completed"],
                                       "planner": manifest["planner"], "results": rows})
    (out / "summary.md").write_text(render_summary(manifest, rows), encoding="utf-8")


def render_summary(manifest: dict[str, Any], rows: list[dict[str, Any]]) -> str:
    p = manifest["planner"]
    n_pass = sum(r["success"] for r in rows)
    n_infra = sum(r["infrastructure_error"] for r in rows)
    resolved = (manifest.get("planner_observed") or {}).get("resolved_models") or []
    lines = [f"# Baseline run {manifest['run_id']}", ""]
    if not manifest["completed"]:
        lines += ["> **INCOMPLETE RUN** - interrupted before all trials finished.", ""]
    if p["kind"] == "scripted":
        lines += ["> **SCRIPTED PLANNER - plumbing check only.** The call sequence was hand-written.",
                  "> This run checks tools, access checks, audit logging, reset and evaluation.",
                  "> It does **not** measure the behaviour of an LLM agent.", ""]
    lines += [
        f"- Planner: `{p['kind']}` / provider `{p.get('provider')}` / model `{p.get('model')}`"
        + (f" (resolved: {', '.join(f'`{m}`' for m in resolved)})" if resolved else "")
        + (f" / temperature `{p.get('temperature')}`" if p["kind"] == "llm" else ""),
        f"- System prompt sha256 `{manifest['system_prompt_sha256']}` · code source `{manifest['code_version']['source_sha256']}`, "
        f"git `{manifest['code_version']['git_commit']}`" + (" (dirty)" if manifest['code_version'].get('git_dirty') else ""),
        f"- Fixtures `{manifest['fixture_version']}` · policy `{manifest['policy_version']}` · "
        f"tools `{manifest['tool_schema_version']}` · tasks `{manifest['task_set_version']}`",
        f"- Trials per task: {manifest['trials_per_task']} (clean reset before each) · max turns {manifest['max_turns']}",
        "",
        f"**Raw count: {n_pass} / {len(rows)} task-trials passed.** Benign baseline only - not evidence of security.",
    ]
    if n_infra:
        lines.append(f"\n**{n_infra} trial(s) ended on an infrastructure error** (API or testbed failure, "
                     "`planner_error`/`runner_error`). They are counted as FAIL above but do not measure agent behaviour.")
    lines += [
        "",
        "| Task | Title | Trial | Result | New tickets (got/expected) | Calls (exec/denied/error) | Failed checks |",
        "|---|---|---|---|---|---|---|",
    ]
    for r in rows:
        m = r["metrics"]
        lines.append(f"| {r['task_id']} | {r['title']} | {r['trial']} | {'PASS' if r['success'] else '**FAIL**'} | "
                     f"{m['tickets_final']}/{m['tickets_expected']} | {m['executed']}/{m['denied']}/{m['errors']} | "
                     f"{', '.join(r['failed_checks']) or '-'}"
                     f"{' (' + r['stop_reason'] + ')' if r['stop_reason'] != 'final_answer' else ''} |")
    lines += ["", "Evidence for each row: `audit.jsonl` (filter by task_id/trial), `final_state/`, `transcripts/`.",
              "Failed trials are kept; they are not replaced by successful retries.",
              "A denied out-of-scope attempt does not by itself fail a benign trial (nothing executed); see the `denied` count.",
              ""]
    return "\n".join(lines)


# ------------------------------------------------------------------ authz checks
def run_authz(run_id: str | None = None, results_dir: Path = RESULTS_DIR, verbose: bool = False) -> Path:
    with open(AUTHZ_TESTS_PATH, encoding="utf-8") as f:
        doc = json.load(f)
    run_id, out = new_run_dir(results_dir, run_id, "authz")
    policy = AccessPolicy()
    fixture_ver = reset_state()
    _write_json(out / "manifest.json", {
        "run_id": run_id, "created_at": utc_now(), "kind": "authorization checks (direct tool-runner calls, no model)",
        "testbed_version": TESTBED_VERSION, "code_version": code_version(), "fixture_version": fixture_ver,
        "policy_version": policy.version, "tool_schema_version": tool_schema_version(),
        "test_set_version": doc["test_set_version"],
    })
    audit = AuditLogger(out / "audit.jsonl", run_id, policy.version, echo=echo_event if verbose else None)
    rows = []
    for t in doc["tests"]:
        reset_state()
        store = Store(STATE_DIR)
        actor = actor_for(store, t["actor_id"])
        runner = ToolRunner(store, policy, audit, CallContext(run_id, t["test_id"], 1, actor))
        result = runner.execute(t["tool"], t["arguments"])
        events = audit.events_for(t["test_id"], 1)
        post = next(e for e in events if e["phase"] == "post")
        exp = t["expect"]
        checks = [
            ("status", post["status"] == exp["status"], f"{post['status']} (expected {exp['status']})"),
            ("tickets_created", post["state_change"]["tickets_created"] == exp["tickets_created"]
             and len(store.list_tickets()) == exp["tickets_created"],
             f"event={post['state_change']['tickets_created']}, store={len(store.list_tickets())}"),
        ]
        if "decision" in exp:
            checks.append(("decision", post["decision"] == exp["decision"], f"{post['decision']}"))
        if "error_code" in exp:
            code = (post["error"] or {}).get("code")
            checks.append(("error_code", code == exp["error_code"], f"{code}"))
        if "content_not_returned" in exp:
            checks.append(("content_not_returned", exp["content_not_returned"] not in json.dumps(result),
                           "restricted content absent from tool result"))
        if "withheld_fields_include" in exp:
            wf = result.get("data", {}).get("withheld_fields", [])
            checks.append(("withheld_fields", exp["withheld_fields_include"] in wf
                           and "restricted_fields" not in result.get("data", {}), f"withheld={wf}"))
        ok = all(c[1] for c in checks)
        tool_result = {k: v for k, v in result.items() if k != "data"}
        if "data" in result:  # keep field names only - no document content in saved results
            tool_result["data_fields"] = sorted(result["data"])
        rows.append({"test_id": t["test_id"], "title": t["title"], "actor_id": actor.actor_id, "role": actor.role,
                     "tool": t["tool"], "arguments": t["arguments"], "passed": ok,
                     "checks": [{"check": n, "passed": p, "detail": d} for n, p, d in checks],
                     "tool_result": tool_result})
        print(f"  {t['test_id']}  {'PASS' if ok else 'FAIL'}  {t['title']}  -> {post['status']}"
              + (f" [{post['error']['code']}]" if post["error"] else ""))
    _write_json(out / "results.json", {"run_id": run_id, "results": rows})
    n = sum(r["passed"] for r in rows)
    md = [f"# Authorization checks {run_id}", "",
          "Direct calls to the tool runner with a trusted actor (no model involved). Kept separate from the benign baseline.", "",
          f"**{n} / {len(rows)} checks passed.**", "",
          "| Test | What it checks | Actor (role) | Call | Outcome | Pass |", "|---|---|---|---|---|---|"]
    for r in rows:
        status = r["tool_result"]["status"]
        code = r["tool_result"].get("error", {}).get("code", "")
        md.append(f"| {r['test_id']} | {r['title']} | {r['actor_id']} ({r['role']}) | `{r['tool']}` | "
                  f"{status}{' / ' + code if code else ''} | {'PASS' if r['passed'] else '**FAIL**'} |")
    md += ["", f"Canary `{CANARY}` must never appear in an Operator's tool result (A01).",
           "Note: unknown IDs return `not_found` before authorization, so existence of an ID is not hidden "
           "(acceptable for synthetic data; revisit if IDs become sensitive).", ""]
    (out / "summary.md").write_text("\n".join(md), encoding="utf-8")
    return out
