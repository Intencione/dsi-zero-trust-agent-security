"""In-memory authorization runtime around the DSI/environment policy demo.

Control-plane methods (identity provisioning, input ingestion, task grants,
and tool registration) are trusted fixture APIs, not agent tools. This is a
single-process simulation, not an IAM service or a hostile-code sandbox.
"""

from dataclasses import asdict, dataclass, field, replace
from enum import Enum
import hashlib
import json
import secrets
import time
from typing import Callable, Optional, Union

from agent_demo import Action, AgentIdentity, Decision, PlanContext, PolicyEngine


Scalar = Union[str, int]


def digest(value):
    def encode(item):
        if isinstance(item, Enum):
            return item.value
        raise TypeError(f"Unsupported binding value: {type(item).__name__}")
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), default=encode)
    return hashlib.sha256(payload.encode()).hexdigest()


def identifier(value):
    if not isinstance(value, str) or not value.strip():
        raise ValueError("Identifiers must be non-empty strings")


def duration(value):
    if type(value) is not int or value <= 0:
        raise ValueError("TTL must be a positive integer number of seconds")


@dataclass(frozen=True)
class Principal:
    subject_id: str
    kind: str
    owner: str = ""
    department: str = ""
    permissions: tuple[str, ...] = ()
    can_approve: bool = False
    active: bool = True
    version: int = 1


@dataclass(frozen=True)
class Session:
    subject_id: str
    principal_version: int
    expires_at: float
    source_machine_id: str = ""
    parent_session_key: str = ""


class MockIdentityProvider:
    """Simulates an IdP's provisioning and already-authenticated login events.

    Opaque bearer sessions are validated against issuer-owned records.
    issue_user_session is a fixture, NOT password/MFA authentication.
    """

    def __init__(self, clock=time.time):
        self.clock = clock
        self._principals = {}
        self._sessions = {}

    def _register(self, principal):
        identifier(principal.subject_id)
        previous = self._principals.get(principal.subject_id)
        if previous and previous.kind != principal.kind:
            raise ValueError("Cannot change a principal's identity kind")
        version = previous.version + 1 if previous else 1
        self._principals[principal.subject_id] = replace(principal, version=version)

    def register_user(self, user_id, *, can_approve=True):
        if type(can_approve) is not bool:
            raise ValueError("can_approve must be boolean")
        self._register(Principal(user_id, "human", can_approve=can_approve))

    def register_agent(self, agent_id, owner, department, permissions):
        if self.principal(owner).kind != "human":
            raise ValueError("Agents must be delegated by a human user")
        identifier(department)
        permissions = tuple(permissions)
        for permission in permissions:
            identifier(permission)
        self._register(Principal(agent_id, "agent", owner, department, permissions))

    def principal(self, subject_id):
        principal = self._principals.get(subject_id)
        if principal is None or not principal.active:
            raise ValueError("Unknown or inactive identity")
        return principal

    def set_active(self, subject_id, active):
        if type(active) is not bool:
            raise ValueError("active must be boolean")
        previous = self._principals[subject_id]
        self._principals[subject_id] = replace(
            previous, active=active, version=previous.version + 1
        )

    @staticmethod
    def session_key(token):
        identifier(token)
        return hashlib.sha256(token.encode()).hexdigest()

    def _issue(self, session):
        token = secrets.token_urlsafe(32)
        self._sessions[self.session_key(token)] = session
        return token

    def issue_user_session(self, user_id, ttl=3600):
        duration(ttl)
        principal = self.principal(user_id)
        if principal.kind != "human":
            raise ValueError("A human identity is required")
        return self._issue(Session(user_id, principal.version, self.clock() + ttl))

    def issue_agent_session(self, agent_id, user_token, source_machine_id, ttl=600):
        duration(ttl)
        identifier(source_machine_id)
        parent_key = self.session_key(user_token)
        parent, user = self.resolve(parent_key)
        agent = self.principal(agent_id)
        if user.kind != "human" or agent.kind != "agent" or agent.owner != user.subject_id:
            raise ValueError("Agent session is outside this user's delegation")
        return self._issue(Session(
            agent_id, agent.version, min(parent.expires_at, self.clock() + ttl),
            source_machine_id, parent_key,
        ))

    def resolve(self, session_key):
        session = self._sessions.get(session_key)
        if session is None or self.clock() >= session.expires_at:
            raise ValueError("Unknown, revoked, or expired session")
        principal = self.principal(session.subject_id)
        if principal.version != session.principal_version:
            raise ValueError("Identity or delegated permissions changed; authenticate again")
        if session.parent_session_key:
            _, parent = self.resolve(session.parent_session_key)
            if parent.kind != "human" or parent.subject_id != principal.owner:
                raise ValueError("Delegation is no longer valid")
        return session, principal

    def revoke(self, token):
        self._sessions.pop(self.session_key(token), None)


class InputSource(Enum):
    USER = "user"
    WEB = "web"
    EMAIL = "email"
    TOOL = "tool"
    AGENT = "agent"


@dataclass(frozen=True)
class InputRecord:
    input_id: str
    source: InputSource
    author: str
    content: str
    content_hash: str


class InputRegistry:
    """Source labels are assigned by trusted ingestion, never by a ToolCall."""

    def __init__(self, identities):
        self.identities = identities
        self._records = {}

    def _record(self, source, author, content):
        if not isinstance(content, str) or not content.strip():
            raise ValueError("Input content must be non-empty text")
        record = InputRecord(secrets.token_hex(16), source, author, content, digest(content))
        self._records[record.input_id] = record
        return record.input_id

    def user_instruction(self, user_token, content):
        _, user = self.identities.resolve(self.identities.session_key(user_token))
        if user.kind != "human":
            raise ValueError("Only an authenticated user can supply authorizing instructions")
        return self._record(InputSource.USER, user.subject_id, content)

    def external_data(self, source, content):
        if not isinstance(source, InputSource) or source == InputSource.USER:
            raise ValueError("External content cannot claim user authority")
        return self._record(source, "", content)

    def get(self, input_id):
        if input_id not in self._records:
            raise ValueError("Unknown input provenance")
        return self._records[input_id]


@dataclass(frozen=True)
class ArgumentConstraint:
    name: str
    allowed_values: tuple[Scalar, ...] = ()
    minimum: Optional[int] = None
    maximum: Optional[int] = None

    def __post_init__(self):
        identifier(self.name)
        object.__setattr__(self, "allowed_values", tuple(self.allowed_values))
        if any(type(value) not in (str, int) for value in self.allowed_values):
            raise ValueError("Only string and integer constraint values are supported")
        bounds = (self.minimum, self.maximum)
        if any(value is not None and type(value) is not int for value in bounds):
            raise ValueError("Numeric constraints require integer bounds")
        if (self.minimum is None) != (self.maximum is None):
            raise ValueError("Numeric constraints require both bounds")
        if self.minimum is not None and self.minimum > self.maximum:
            raise ValueError("Invalid numeric range")
        if not self.allowed_values and self.minimum is None:
            raise ValueError("Every argument needs an explicit allowlist or bounded range")

    def permits(self, value):
        if self.allowed_values and value not in self.allowed_values:
            return False
        if self.minimum is not None:
            return type(value) is int and self.minimum <= value <= self.maximum
        return True


@dataclass(frozen=True)
class CallRule:
    tool_name: str
    resource_id: str
    target_machine_id: str
    arguments: tuple[ArgumentConstraint, ...]

    def __post_init__(self):
        for value in (self.tool_name, self.resource_id, self.target_machine_id):
            identifier(value)
        object.__setattr__(self, "arguments", tuple(self.arguments))
        if any(not isinstance(item, ArgumentConstraint) for item in self.arguments):
            raise ValueError("Invalid argument constraints")
        if len({item.name for item in self.arguments}) != len(self.arguments):
            raise ValueError("Duplicate argument constraints")


@dataclass(frozen=True)
class ToolCall:
    task_id: str
    tool_name: str
    resource_id: str
    target_machine_id: str
    instruction_id: str
    arguments: tuple[tuple[str, Scalar], ...]
    evidence_ids: tuple[str, ...] = ()
    request_id: str = field(default_factory=lambda: secrets.token_hex(16))

    def __post_init__(self):
        for value in (
            self.task_id, self.tool_name, self.resource_id, self.target_machine_id,
            self.instruction_id, self.request_id,
        ):
            identifier(value)
        arguments = tuple(tuple(pair) for pair in self.arguments)
        if any(len(pair) != 2 for pair in arguments):
            raise ValueError("Arguments must be name/value pairs")
        for name, value in arguments:
            identifier(name)
            if type(value) not in (str, int):
                raise ValueError("Only flat string/integer tool parameters are supported")
        if len(dict(arguments)) != len(arguments):
            raise ValueError("Duplicate tool parameters")
        object.__setattr__(self, "arguments", tuple(sorted(arguments)))
        object.__setattr__(self, "evidence_ids", tuple(self.evidence_ids))
        for input_id in self.evidence_ids:
            identifier(input_id)


@dataclass(frozen=True)
class TaskGrant:
    task_id: str
    owner: str
    agent_id: str
    instruction_id: str
    rules: tuple[CallRule, ...]
    approvers: tuple[str, ...]
    expires_at: float
    version: int = 1
    revoked: bool = False


@dataclass(frozen=True)
class RegisteredTool:
    name: str
    action: Action
    schema: tuple[tuple[str, str], ...]
    handler: Callable = field(repr=False, compare=False)
    version: int = 1


@dataclass(frozen=True)
class RuntimeResult:
    decision: Decision
    reason: str
    approval_id: Optional[str] = None
    permit_id: Optional[str] = None
    executed: bool = False
    output: object = None
    error: Optional[str] = None


@dataclass(frozen=True)
class AuthorizationRecord:
    session_key: str
    call: ToolCall
    plan_context: PlanContext
    binding: str
    expires_at: float
    approver_session_key: str = ""
    reason: str = ""
    dsi_at_request: float = 0


class SecureRuntime:
    """Agent surface: prepare and execute. Human surface: resolve_approval.

    Approved parameters are rechecked and passed to the registered handler.
    Only local stub handlers are installed by the demo. All state is in memory;
    external execution would require durable, atomic enforcement at the tool.
    """

    def __init__(self, policy: PolicyEngine, identities, inputs, clock=time.time):
        self.policy = policy
        self.identities = identities
        self.inputs = inputs
        self.clock = clock
        self._tools = {}
        self._tasks = {}
        self._pending = {}
        self._permits = {}
        self._attempted = set()
        self._denied = set()
        self.audit = []

    def register_tool(self, name, action, schema, handler):
        identifier(name)
        if not isinstance(action, Action) or not callable(handler):
            raise ValueError("A trusted action and handler are required")
        schema = tuple(sorted(schema.items()))
        for argument, kind in schema:
            identifier(argument)
            if kind not in ("string", "integer"):
                raise ValueError("Only flat string/integer schemas are supported")
        previous = self._tools.get(name)
        self._tools[name] = RegisteredTool(
            name, replace(action), schema, handler, previous.version + 1 if previous else 1
        )

    def _human(self, token):
        key = self.identities.session_key(token)
        session, user = self.identities.resolve(key)
        if user.kind != "human":
            raise ValueError("A human session is required")
        return key, session, user

    def _validate_rules(self, rules, agent):
        rules = tuple(rules)
        if not rules or any(not isinstance(rule, CallRule) for rule in rules):
            raise ValueError("A task needs explicit call rules")
        for rule in rules:
            tool = self._tools.get(rule.tool_name)
            if tool is None or tool.action.name not in agent.permissions:
                raise ValueError("Task cannot exceed the agent's delegated permissions")
            constraints = {item.name: item for item in rule.arguments}
            if set(constraints) != dict(tool.schema).keys():
                raise ValueError("Every tool parameter must be explicitly constrained")
            for name, kind in tool.schema:
                constraint = constraints[name]
                expected = str if kind == "string" else int
                if any(type(value) is not expected for value in constraint.allowed_values):
                    raise ValueError("Constraint values do not match tool schema")
                if kind == "string" and constraint.minimum is not None:
                    raise ValueError("String parameters cannot use numeric ranges")
        return rules

    def create_task(self, user_token, agent_id, instruction_id, rules, *, approvers=(), ttl=600):
        duration(ttl)
        _, session, user = self._human(user_token)
        agent = self.identities.principal(agent_id)
        instruction = self.inputs.get(instruction_id)
        if agent.kind != "agent" or agent.owner != user.subject_id:
            raise ValueError("Task is outside the user's delegation")
        if instruction.source != InputSource.USER or instruction.author != user.subject_id:
            raise ValueError("Task authority must originate from this authenticated user")
        rules = self._validate_rules(rules, agent)
        approvers = tuple(approvers) or (user.subject_id,)
        for approver in approvers:
            if self.identities.principal(approver).kind != "human":
                raise ValueError("Task approvers must be human identities")
        task_id = secrets.token_hex(16)
        self._tasks[task_id] = TaskGrant(
            task_id, user.subject_id, agent_id, instruction_id, rules, approvers,
            min(session.expires_at, self.clock() + ttl),
        )
        return task_id

    def update_task_rules(self, user_token, task_id, rules):
        _, _, user = self._human(user_token)
        task = self._task(task_id)
        if task.owner != user.subject_id:
            raise ValueError("Only the task owner can change its scope")
        rules = self._validate_rules(rules, self.identities.principal(task.agent_id))
        self._tasks[task_id] = replace(task, rules=rules, version=task.version + 1)

    def revoke_task(self, user_token, task_id):
        _, _, user = self._human(user_token)
        task = self._tasks[task_id]
        if task.owner != user.subject_id:
            raise ValueError("Only the task owner can revoke it")
        self._tasks[task_id] = replace(task, revoked=True, version=task.version + 1)

    def _task(self, task_id):
        task = self._tasks.get(task_id)
        if task is None or task.revoked or self.clock() >= task.expires_at:
            raise ValueError("Unknown, revoked, or expired task grant")
        return task

    def _evaluate(self, session_key, call, plan_context):
        session, agent = self.identities.resolve(session_key)
        task = self._task(call.task_id)
        if agent.kind != "agent" or agent.subject_id != task.agent_id or agent.owner != task.owner:
            raise ValueError("Authenticated identity does not match the task delegation")
        if session.source_machine_id != self.policy.environment.source_machine_id:
            raise ValueError("Agent session is bound to another source machine")
        if (call.task_id, call.request_id) in self._denied:
            raise ValueError("This request was rejected by a human")
        if (call.task_id, call.request_id) in self._attempted:
            raise ValueError("This request already had an execution attempt")
        instruction = self.inputs.get(call.instruction_id)
        if (
            call.instruction_id != task.instruction_id
            or instruction.source != InputSource.USER
            or instruction.author != task.owner
        ):
            raise ValueError("External or unrelated instructions cannot authorize this task")
        evidence = tuple(self.inputs.get(item) for item in call.evidence_ids)
        tool = self._tools.get(call.tool_name)
        if tool is None:
            raise ValueError("Unknown tool")
        values = dict(call.arguments)
        if values.keys() != dict(tool.schema).keys():
            raise ValueError("Missing or unexpected tool parameters")
        for name, kind in tool.schema:
            if type(values[name]) is not (str if kind == "string" else int):
                raise ValueError("Tool parameter type mismatch")
        matched = any(
            rule.tool_name == call.tool_name
            and rule.resource_id == call.resource_id
            and rule.target_machine_id == call.target_machine_id
            and {item.name for item in rule.arguments} == values.keys()
            and all(item.permits(values[item.name]) for item in rule.arguments)
            for rule in task.rules
        )
        if not matched:
            raise ValueError("Tool, resource, target, or arguments exceed this task's scope")
        environment = self.policy.environment
        if (call.resource_id, call.target_machine_id) != (
            environment.resource_id, environment.target_machine_id
        ):
            raise ValueError("Tool call does not match the evaluated resource environment")
        identity = AgentIdentity(agent.subject_id, agent.owner, agent.department, agent.permissions)
        decision, reason = self.policy.evaluate(identity, tool.action, plan_context)
        binding = digest({
            "call": asdict(call), "session_key": session_key, "session": asdict(session),
            "agent": asdict(agent), "owner": asdict(self.identities.principal(task.owner)),
            "task": asdict(task), "tool_version": tool.version,
            "action": asdict(tool.action), "schema": tool.schema,
            "instruction": asdict(instruction), "evidence": [asdict(item) for item in evidence],
            "plan": asdict(plan_context) if isinstance(plan_context, PlanContext) else None,
            "environment": asdict(environment), "environment_epoch": self.policy.environment_epoch,
            "dsi": self.policy.dsi.score, "security_epoch": self.policy.dsi.epoch,
            "emergency": self.policy.dsi.admin_emergency,
        })
        return decision, reason, binding, min(session.expires_at, task.expires_at), tool

    def _emit(self, stage, call, result, actor_token):
        try:
            _, actor = self.identities.resolve(self.identities.session_key(actor_token))
            actor_id = actor.subject_id
        except ValueError:
            actor_id = None
        task = self._tasks.get(call.task_id) if call else None
        self.audit.append({
            "time": self.clock(), "stage": stage, "actor_id": actor_id,
            "assigned_agent": task.agent_id if task else None,
            "task_owner": task.owner if task else None,
            "request_id": call.request_id if call else None,
            "task_id": call.task_id if call else None, "tool": call.tool_name if call else None,
            "resource_id": call.resource_id if call else None,
            "target_machine_id": call.target_machine_id if call else None,
            "arguments_hash": digest(call.arguments) if call else None,
            "instruction_id": call.instruction_id if call else None,
            "evidence_ids": call.evidence_ids if call else (),
            "environment": asdict(self.policy.environment),
            "security_epoch": self.policy.dsi.epoch,
            "environment_epoch": self.policy.environment_epoch, "dsi": self.policy.dsi.score,
            "decision": result.decision.value, "reason": result.reason,
            "executed": result.executed, "error": result.error,
        })
        return result

    def prepare(self, agent_token, call, plan_context):
        try:
            key = self.identities.session_key(agent_token)
            decision, reason, binding, expiry, _ = self._evaluate(key, call, plan_context)
            record = AuthorizationRecord(
                key, call, plan_context, binding, min(expiry, self.clock() + 60),
                reason=reason, dsi_at_request=self.policy.dsi.score,
            )
            if decision == Decision.ALLOW:
                permit = secrets.token_urlsafe(32)
                self._permits[permit] = record
                result = RuntimeResult(decision, reason, permit_id=permit)
            elif decision == Decision.APPROVAL:
                approval = secrets.token_urlsafe(32)
                self._pending[approval] = record
                result = RuntimeResult(decision, reason, approval_id=approval)
            else:
                result = RuntimeResult(decision, reason)
        except ValueError as error:
            result = RuntimeResult(Decision.BLOCK, str(error))
        return self._emit("prepare", call, result, agent_token)

    def _approver(self, session_key, task_id):
        session, user = self.identities.resolve(session_key)
        task = self._task(task_id)
        if user.kind != "human" or not user.can_approve or user.subject_id not in task.approvers:
            raise ValueError("This identity is not authorized to approve the task")
        return session, user

    def approval_details(self, user_token, approval_id):
        record = self._pending[approval_id]
        self._approver(self.identities.session_key(user_token), record.call.task_id)
        if self.clock() >= record.expires_at:
            raise ValueError("Approval request expired")
        return {
            "call": asdict(record.call), "environment": asdict(record.plan_context.environment),
            "purpose": self.inputs.get(record.call.instruction_id).content,
            "agent_id": self._task(record.call.task_id).agent_id,
            "reason": record.reason, "dsi_at_request": record.dsi_at_request,
            "security_epoch": record.plan_context.security_epoch,
            "environment_epoch": record.plan_context.environment_epoch,
            "expires_at": record.expires_at,
        }

    def resolve_approval(self, user_token, approval_id, *, approved):
        record = self._pending.get(approval_id)
        if record is None:
            return self._emit("approval", None, RuntimeResult(
                Decision.BLOCK, "Unknown or already resolved approval"
            ), user_token)
        call = record.call
        try:
            if type(approved) is not bool:
                raise ValueError("An explicit approval or rejection is required")
            key = self.identities.session_key(user_token)
            session, _ = self._approver(key, call.task_id)
            if self.clock() >= record.expires_at:
                self._pending.pop(approval_id)
                result = RuntimeResult(Decision.REEVALUATE, "Approval request expired")
            elif not approved:
                self._pending.pop(approval_id)
                self._denied.add((call.task_id, call.request_id))
                result = RuntimeResult(Decision.BLOCK, "Human rejected this request")
            else:
                decision, reason, binding, expiry, _ = self._evaluate(
                    record.session_key, call, record.plan_context
                )
                self._pending.pop(approval_id)
                if decision in (Decision.BLOCK, Decision.REEVALUATE):
                    result = RuntimeResult(decision, reason)
                elif binding != record.binding:
                    result = RuntimeResult(Decision.REEVALUATE, "Authorization context changed during approval")
                else:
                    permit = secrets.token_urlsafe(32)
                    self._permits[permit] = replace(
                        record, approver_session_key=key,
                        expires_at=min(record.expires_at, expiry, session.expires_at),
                    )
                    result = RuntimeResult(Decision.ALLOW, "Human approved this exact call", permit_id=permit)
        except ValueError as error:
            result = RuntimeResult(Decision.BLOCK, str(error))
        return self._emit("approval", call, result, user_token)

    def execute(self, agent_token, call, permit_id):
        record = self._permits.get(permit_id)
        try:
            key = self.identities.session_key(agent_token)
            if record is None or key != record.session_key:
                raise ValueError("Unknown, consumed, or mismatched execution permit")
            # Consume before dispatch, including failures: at most one attempt per permit.
            self._permits.pop(permit_id)
            if call != record.call:
                raise ValueError("Execution differs from the authorized call")
            if self.clock() >= record.expires_at:
                result = RuntimeResult(Decision.REEVALUATE, "Execution permit expired")
            else:
                decision, reason, binding, _, tool = self._evaluate(key, call, record.plan_context)
                if decision in (Decision.BLOCK, Decision.REEVALUATE):
                    result = RuntimeResult(decision, reason)
                elif binding != record.binding:
                    result = RuntimeResult(Decision.REEVALUATE, "Authorization context changed before execution")
                elif decision == Decision.APPROVAL and not record.approver_session_key:
                    result = RuntimeResult(Decision.APPROVAL, "A valid human approval is required")
                else:
                    if record.approver_session_key:
                        self._approver(record.approver_session_key, call.task_id)
                    self._attempted.add((call.task_id, call.request_id))
                    try:
                        output = tool.handler(call)
                        result = RuntimeResult(Decision.ALLOW, "Authorized tool completed", executed=True, output=output)
                    except Exception as error:
                        result = RuntimeResult(
                            Decision.ALLOW, "Tool failed after authorization; permit consumed",
                            error=type(error).__name__,
                        )
        except ValueError as error:
            result = RuntimeResult(Decision.BLOCK, str(error))
        return self._emit("execute", call, result, agent_token)
