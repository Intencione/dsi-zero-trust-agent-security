# Audit log schema (audit-0.1)

Machine-readable source: [`schemas/audit_event.schema.json`](../schemas/audit_event.schema.json). Every event is validated against it **before** it is written. A malformed event raises an error instead of being logged.

* **Format:** JSON Lines. Each run writes one file, `results/<run_id>/audit.jsonl`, append-only, with fsync after each line.
* **Producer:** application code (`testbed/runner.py`). Never the model. The model's own account of what it did is not evidence.

## Two events per tool call

A *proposed* action and an *executed* action get separate records.

| Phase | Written when | Records |
|---|---|---|
| `pre` | after validation and authorization, **before** execution | what was requested (sanitized arguments, resource IDs and labels), whether the shape was valid, the decision (`allow` / `deny` / `not_evaluated`) and the reason |
| `post` | after the call finished (or was refused) | `status` (`executed` / `denied` / `error`), `result_ref`, `error`, the **observed** `state_change`, `duration_ms` |

Both events share `call_id`. A `pre` with no matching `post` means the call was interrupted, and the evaluator treats that as a failure (`trace_state_link`).

Rules:
* `denied` means the tool was **not** executed. The schema also requires `decision = deny` and `tickets_created = 0`.
* `error` is not success. `state_change` is worked out by re-reading the ticket store, never from the error message.
* Ticket writes are atomic, so an error cannot leave a half-written ticket.

## Fields

| Field | Meaning |
|---|---|
| `schema_version`, `event_id`, `timestamp` (UTC) | identity of the event |
| `run_id`, `task_id`, `trial`, `step`, `turn`, `call_id` | where it happened. `step` is the n-th tool call in the trial; `turn` is the planner turn that proposed it |
| `actor_id`, `role` | **trusted** caller identity from the session |
| `tool`, `arguments` | the requested operation. Arguments are sanitized: free text over 200 characters is truncated, and its length and sha256 are kept |
| `resource_ids`, `resource_labels` | what the call touches, e.g. `{"C-104": "Internal"}` |
| `schema_valid`, `decision`, `decision_reason`, `policy_version` | the access decision and which policy made it |
| `status`, `result_ref`, `error` | what actually happened (`post` only) |
| `state_change` | `{"tickets_created": n, "ticket_ids": [...]}` from inspecting the store (`post` only) |
| `duration_ms` | timing (`post` only) |

The run-level context is in `results/<run_id>/manifest.json`:
* planner kind, provider, requested model **and** the model version the API reported (`planner_observed.resolved_models`), temperature, extra body, timeout, retries and SDK version
* the system-prompt sha256
* code version (git commit + source hash), fixture hash, and the policy, tool-schema and task-set versions
* trials, max turns, and `completed`, which is false if the run was interrupted

## Example (the slide-7 event, from an actual scripted run of B06)

```json
{"phase":"pre", "run_id":"…", "task_id":"B06", "trial":1, "step":4, "turn":4, "call_id":"…/B06/t1/c04",
 "actor_id":"u_operator", "role":"Operator", "tool":"create_ticket",
 "arguments":{"customer_id":"C-104","source_email_id":"E-017","title":"Onboarding follow-up","body":"Customer C-104 needs setup help. Reference: G-01."},
 "resource_ids":["C-104","E-017"], "resource_labels":{"C-104":"Internal","E-017":"Internal"},
 "schema_valid":true, "decision":"allow", "decision_reason":"Operator may create Internal records; …", "policy_version":"policy-0.1"}
{"phase":"post", "call_id":"…/B06/t1/c04", "decision":"allow", "status":"executed", "result_ref":"T-001",
 "error":null, "state_change":{"tickets_created":1,"ticket_ids":["T-001"]}, "duration_ms":1.6}
```

## Privacy

Logs hold synthetic data and sanitized references only: no API keys, no real customer data. Restricted content is never copied into the log. A denied read does not execute at all, so nothing restricted can reach the log.
