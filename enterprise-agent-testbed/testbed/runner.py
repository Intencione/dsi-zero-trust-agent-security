"""The tool runner: application-controlled execution of model-proposed calls.

    The model PROPOSES a call. The application CONTROLS execution.

For every proposed call:
  1. Is the operation listed?           (default deny)
  2. Parse + validate input shape       (JSON Schema; shape != permission)
  3. Resolve referenced resources       (unknown IDs -> explicit not_found error)
  4. Authorize with the TRUSTED actor   (role x label matrix + assignment)
  5. Write the 'pre' audit event        (before anything executes)
  6. Execute (or not) and inspect state
  7. Write the 'post' audit event       (executed | denied | error, state change)
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass
from typing import Any

from jsonschema import Draft202012Validator

from .audit import AuditLogger, sanitize_arguments
from .policy import AccessPolicy, Actor, Decision
from .store import Store
from .tools import TOOL_IMPLS, Resource, ToolError, load_catalog


@dataclass
class CallContext:
    run_id: str
    task_id: str
    trial: int
    actor: Actor  # trusted session identity


class ToolRunner:
    def __init__(self, store: Store, policy: AccessPolicy, audit: AuditLogger, ctx: CallContext):
        self.store = store
        self.policy = policy
        self.audit = audit
        self.ctx = ctx
        self.catalog = load_catalog()
        self.in_validators = {n: Draft202012Validator(t["input_schema"]) for n, t in self.catalog.items()}
        self.out_validators = {n: Draft202012Validator(t["output_schema"]) for n, t in self.catalog.items()}
        self.step = 0

    # ------------------------------------------------------------ public
    def execute(self, tool: str, raw_args: Any, turn: int = 1) -> dict[str, Any]:
        self.step += 1
        step = self.step
        call_id = f"{self.ctx.run_id}/{self.ctx.task_id}/t{self.ctx.trial}/c{step:02d}"
        started = time.perf_counter()
        tickets_before = {t["ticket_id"] for t in self.store.list_tickets()}
        base = {
            "task_id": self.ctx.task_id, "trial": self.ctx.trial, "step": step, "turn": turn,
            "call_id": call_id, "actor_id": self.ctx.actor.actor_id, "role": self.ctx.actor.role, "tool": tool,
        }
        state = {"decision": "not_evaluated"}

        def pre(arguments: Any, resources: list[Resource], schema_valid: bool, decision: str, reason: str) -> None:
            state["decision"] = decision
            self.audit.log(
                **base, phase="pre", arguments=sanitize_arguments(arguments),
                resource_ids=[r.resource_id for r in resources],
                resource_labels={r.resource_id: r.label for r in resources},
                schema_valid=schema_valid, decision=decision, decision_reason=reason,
            )

        def post(status: str, result_ref: str | None, error: dict | None) -> None:
            # Inspect saved state; never infer "no write happened" from an error message.
            after = {t["ticket_id"] for t in self.store.list_tickets()}
            new_ids = sorted(after - tickets_before)
            self.audit.log(
                **base, phase="post", decision=state["decision"], status=status, result_ref=result_ref,
                error=error, state_change={"tickets_created": len(new_ids), "ticket_ids": new_ids},
                duration_ms=round((time.perf_counter() - started) * 1000, 3),
            )

        def reply(status: str, data: Any = None, error: dict | None = None) -> dict[str, Any]:
            out: dict[str, Any] = {"status": status, "tool": tool, "call_id": call_id}
            if data is not None:
                out["data"] = data
            if error is not None:
                out["error"] = error
            return out

        # 1. listed operation? (default deny)
        known = self.policy.operation_known(tool)
        if tool not in TOOL_IMPLS or not known.allowed:
            err = {"code": "unknown_tool", "message": known.reason if not known.allowed else f"No tool '{tool}'."}
            pre(raw_args, [], False, "deny", err["message"])
            post("denied", None, err)
            return reply("denied", error=err)

        # 2. parse + validate shape
        args, parse_error = self._parse(raw_args)
        if parse_error is None:
            problems = sorted(self.in_validators[tool].iter_errors(args), key=lambda e: list(e.path))
            if problems:
                parse_error = "; ".join(p.message for p in problems)
        if parse_error is not None:
            err = {"code": "schema_invalid", "message": f"Invalid arguments for {tool}: {parse_error}"}
            pre(raw_args, [], False, "not_evaluated", "input failed schema validation; authorization not evaluated")
            post("error", None, err)
            return reply("error", error=err)

        impl = TOOL_IMPLS[tool]

        # 3. resolve resources
        try:
            resources = impl.resolve(self.store, args)
        except ToolError as e:
            err = {"code": e.code, "message": e.message}
            pre(args, [], True, "not_evaluated", f"resource resolution failed: {e.code}")
            post("error", None, err)
            return reply("error", error=err)

        # 4 + 5. authorize with trusted identity, log BEFORE executing
        decision = self._authorize(tool, resources)
        pre(args, resources, True, decision.decision, decision.reason)
        if not decision.allowed:
            err = {"code": "forbidden", "message": f"Denied by {self.policy.version}: {decision.reason}"}
            post("denied", None, err)
            return reply("denied", error=err)

        # 6. execute
        try:
            output = impl.execute(self.store, self.ctx.actor, self.policy, args, resources)
            out_problems = list(self.out_validators[tool].iter_errors(output))
            if out_problems:
                raise ToolError("output_invalid", out_problems[0].message)
        except ToolError as e:
            err = {"code": e.code, "message": e.message}
            post("error", None, err)
            return reply("error", error=err)
        except Exception as e:  # unexpected failure: record it, state is inspected in post()
            err = {"code": "execution_error", "message": f"{type(e).__name__}: {e}"}
            post("error", None, err)
            return reply("error", error=err)

        # 7. completion event
        post("executed", impl.result_ref(output), None)
        return reply("ok", data=output)

    # ------------------------------------------------------------ helpers
    @staticmethod
    def _parse(raw_args: Any) -> tuple[dict[str, Any], str | None]:
        if isinstance(raw_args, dict):
            return raw_args, None
        if raw_args is None or raw_args == "":
            return {}, None
        if isinstance(raw_args, str):
            try:
                parsed = json.loads(raw_args)
            except json.JSONDecodeError as e:
                return {}, f"arguments are not valid JSON ({e.msg})"
            if not isinstance(parsed, dict):
                return {}, "arguments must be a JSON object"
            return parsed, None
        return {}, f"unsupported argument type {type(raw_args).__name__}"

    def _authorize(self, tool: str, resources: list[Resource]) -> Decision:
        actor = self.ctx.actor
        op = self.policy.operations[tool]
        if op["kind"] == "read":
            r = resources[0]
            return self.policy.check_read(actor, r.resource_id, r.label, r.assigned_to)
        if tool == "create_ticket":
            customer, email = resources
            return AccessPolicy.combine(
                self.policy.check_write(actor, op["target_label"]),
                self.policy.check_read(actor, customer.resource_id, customer.label, customer.assigned_to),
                self.policy.check_read(actor, email.resource_id, email.label, email.assigned_to),
            )
        return Decision("deny", f"default deny: no rule for {tool}")
