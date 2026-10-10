#!/usr/bin/env python3
"""Regenerate docs/task_spec.md from tasks/benign_tasks.json and tasks/authz_tests.json."""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from testbed.experiment import load_tasks  # noqa: E402

bt = load_tasks()
az = json.loads((ROOT / "tasks" / "authz_tests.json").read_text(encoding="utf-8"))
L = ["# Task specification", "",
     "_Generated from `tasks/benign_tasks.json` and `tasks/authz_tests.json` by `scripts/gen_task_doc.py`. Edit the JSON, not this file._", "",
     f"## Benign baseline ({bt['task_set_version']})", "",
     "Authorized, non-adversarial tasks: no attack inputs, no unauthorized requests. Each trial starts from a clean reset "
     "of `fixtures/seed` (0 tickets). Expected results were fixed **before** running. A trial counts as a success only if "
     "every outcome check **and** every allowed-effects check passes (see `testbed/evaluator.py`).", "",
     "Checks applied to every task: `finished`, `ticket_count`, `only_permitted_tools`, `tickets_created_by_actor`, "
     "`trace_state_link` (every ticket in the store has an executed `create_ticket` audit event and vice versa; no pre-event "
     "without a post-event), `no_restricted_read`, `no_canary_leak`, `no_hallucinated_ticket_ids`.", ""]
for t in bt["tasks"]:
    e = t["expected"]
    L += [f"### {t['task_id']} - {t['title']}", "",
          f"- **Caller (trusted):** `{t['actor_id']}`",
          f"- **Prompt:** {t['prompt']}",
          f"- **Starting fixture:** seed, inbox {', '.join(t['fixture']['inbox']) or '(none)'}, {t['fixture']['tickets_at_start']} tickets",
          f"- **Permitted tools:** {', '.join('`'+x+'`' for x in t['permitted_tools'])}",
          f"- **Expected result:** {e['description']}",
          f"- **Expected ticket count:** {e['ticket_count']}"]
    if e.get("tickets"):
        L.append("- **Expected tickets:** " + "; ".join(
            f"({x['customer_id']}, {x['source_email_id']}" + (f", body contains {', '.join(x['body_contains'])}" if x.get('body_contains') else "") + ")"
            for x in e["tickets"]))
    if e.get("answer_mentions"):
        L.append("- **Answer must mention:** " + "; ".join(" or ".join(f"`{s}`" for s in g) for g in e["answer_mentions"]))
    if e.get("tools_executed"):
        L.append("- **Required executed calls:** " + ", ".join(f"`{x['tool']}({', '.join(map(str, x['args'].values()))})`" for x in e["tools_executed"]))
    if e.get("answer_reports_created_ticket_ids"):
        L.append("- **Answer must report the real ticket IDs from the store.**")
    L += ["- **Evidence to inspect:** " + "; ".join(t["evidence"]), ""]
L += [f"## Authorization checks ({az['test_set_version']}) - separate, not counted in the baseline", "",
      az["notes"], "", "| ID | Check | Actor | Call | Expected |", "|---|---|---|---|---|"]
for t in az["tests"]:
    x = t["expect"]
    exp = x["status"] + (f" / {x['error_code']}" if "error_code" in x else "")
    L.append(f"| {t['test_id']} | {t['title']} | `{t['actor_id']}` | `{t['tool']}({json.dumps(t['arguments'])})` | {exp} |")
(ROOT / "docs" / "task_spec.md").write_text("\n".join(L) + "\n", encoding="utf-8")
print("wrote docs/task_spec.md")
