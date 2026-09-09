# DSI-Driven Zero Trust Security for AI Agents

This repository contains an early-stage prototype exploring how **Dynamic Security Indicators (DSI)** can be combined with **Zero Trust principles** to improve the security of autonomous AI agents operating inside an enterprise environment.

Run `python3 -B secure_agent_demo.py` for the complete local authorization workflow: task scope, identity and input provenance, exact tool constraints, DSI/environment policy, human approval, and one-use execution permits. Identities, approvals, telemetry, and tool effects are simulated; the demo sends no messages or payments.

The core idea is that an AI agent should not be trusted based only on its identity or previously granted permissions. Its ability to act should also depend on the organization's **current security condition**.

If the enterprise environment becomes more dangerous — for example, because of abnormal IP connections, suspicious operations, destructive behavior, unusual credential activity, or an administrator-declared emergency — the agent should automatically re-evaluate what it is allowed to do.

---

## Research Motivation

Traditional access control is often relatively static.

A user or software service receives a set of permissions, and those permissions remain available until they are manually changed or revoked.

Autonomous AI agents create a different security problem.

An agent may have legitimate credentials and valid permissions, but its actions may become unsafe if:

* The organization is actively under cyberattack
* Credentials have potentially been compromised
* The agent has been affected by prompt injection or goal hijacking
* External tools or APIs behave unexpectedly
* The organization temporarily needs to reduce its attack surface

In these situations, permissions that were appropriate under normal conditions may no longer be safe.

This prototype explores a **risk-adaptive authorization model** in which enterprise security conditions directly influence agent permissions and runtime behavior.

---

## Dynamic Security Indicator (DSI)

The prototype introduces a **Dynamic Security Indicator (DSI)** representing the current security condition of the organization.

The DSI uses a score from **0 to 100**.

Example security levels:

* **0–24 — NORMAL**
* **25–49 — ELEVATED**
* **50–74 — HIGH**
* **75–89 — SEVERE**
* **90–100 — CRISIS**

The score can be influenced by signals such as:

* Abnormal IP connections
* Unknown or suspicious operations
* Unusual API activity
* Destructive system behavior
* Credential anomalies
* Malware or intrusion alerts
* Administrator emergency activation

An administrator can also manually activate a crisis mode when the organization is responding to a major security incident.

---

## Risk-Adaptive Agent Behavior

The system does not treat all AI agents in the same way.

Instead, security restrictions depend on:

* Agent identity
* Department
* Delegated permissions
* Action sensitivity
* Current DSI value
* Whether the action requires internal resources
* Whether the action involves file transfer or other sensitive behavior
* Source and target machine risk and quarantine state
* Development, test, or production environment
* Target machine criticality and resource sensitivity
* Sandbox isolation, administrator privileges, and network access
* Authenticated mock session, delegation, expiry, revocation, and source-machine binding
* This task's permitted tools, exact resources, targets, and parameter constraints
* Authorizing user instruction versus external data provenance
* Approval authority, exact-call binding, expiry, and replay state

For example, during a major cyberattack:

### Finance Agent

A finance agent may stop all proactive operations because financial workflows are not essential to incident response.

Examples:

* Generate financial report → BLOCK
* Send financial email → BLOCK
* Transfer files → BLOCK
* Execute payment → BLOCK

### Marketing Agent

A marketing agent may continue low-risk public-facing work but lose access to sensitive internal resources.

Examples:

* Draft public announcement → subject to risk and environment checks
* Create social media content → REQUIRE HUMAN APPROVAL at DSI 95 in the demo
* Access internal network resources → BLOCK
* Transfer internal files → BLOCK

### Cybersecurity Agent

A cybersecurity agent may retain operational access because it is directly involved in incident response. The demo preserves existing delegated access to reading security logs and isolating hosts; it does not grant new permissions. Temporary additional access remains a future feature. Source-machine denials and environment approval requirements still apply to these agents.

This allows the organization to reduce unnecessary risk without completely shutting down all AI-assisted operations.

---

## Continuous Re-Evaluation

A major design principle of this prototype is that **previous authorization should not remain valid when the security environment changes**.

For example:

1. An agent creates a multi-step plan under normal conditions.
2. The organization later detects suspicious activity.
3. The DSI rises from NORMAL to SEVERE.
4. Previously approved actions become stale.
5. Remaining actions must be re-evaluated before execution.

This follows the Zero Trust principle of continuous verification.

---

## Security Epoch

The prototype uses a simple **Security Epoch** mechanism.

Whenever the security state changes significantly, the epoch number increases.

Example:

```text
DSI = 12
Security Epoch = 4
```

An agent receives authorization under Epoch 4.

Later:

```text
DSI = 82
Security Epoch = 5
```

The previous authorization is now considered stale.

The agent must re-evaluate its remaining actions under the new security state.

This prevents an agent from continuing to use permissions that were granted before a major security change.

---

## Current Security Decision Model

The complete runtime evaluates identity/session/delegation, task scope, input provenance, exact tool arguments and resource scope, department, action properties, DSI, and machine/resource/execution context. Plan validity uses a global Security Epoch and a local Environment Epoch. Approval and execution also check the current task and tool versions, exact call, full security state, session validity, and replay state. The original `agent_demo.py` remains the lower-level policy example; identity validation and actual stub dispatch are implemented in `secure_runtime.py` and exercised by `secure_agent_demo.py`.

See [the complete factor inventory and candidate extensions](model_factors.md) for each field, its current effect, and what is still unimplemented.

The system can return four possible outcomes:

* **ALLOW**
* **REQUIRE HUMAN APPROVAL**
* **BLOCK**
* **REEVALUATE**

The DSI has a high influence on the final decision because organization-wide security conditions should strongly affect what autonomous agents are allowed to do.

---

## Machine and Execution Environment

Every policy engine requires an explicit, immutable `EnvironmentContext` for one source-machine / target-machine / resource scope. In a deployed system, infrastructure telemetry and resource inventory must supply this context; an LLM must not classify its own requested action as safe.

The context distinguishes **sensitivity/criticality** (potential impact) from **current risk** (present danger). The demo uses independent restrictions rather than averaging local danger into the enterprise DSI:

* A quarantined source or source risk of 75+ blocks all actions, including incident response.
* A quarantined target or target risk of 75+ blocks business actions. Delegated cybersecurity log-reading and host-isolation actions can still be evaluated from a healthy source.
* Isolated execution blocks actions requiring intranet access. Sensitive file transfers (resource sensitivity 75+) are blocked in internet-enabled execution. This conservative rule checks network capability, not the actual transfer destination.
* Source risk 50–74 or non-response target risk 50–74 requires approval. Administrator execution and resource sensitivity 75+ also require approval.
* High-impact actions require approval in production, on critical targets (criticality 75+), or outside a sandbox. Here high-impact means action sensitivity 50+, file transfer, or a destructive action.

Existing permission and departmental denials still apply. Destructive actions require approval under NORMAL and are blocked at higher levels. The original risk formula remains `0.60 * DSI + 0.40 * action sensitivity`: 80+ blocks, 60–79.99 requires approval. The existing crisis incident-response exception bypasses this formula, but cannot override environment denials or approval requirements. Approval is returned only if no applicable denial applies.

All thresholds are illustrative research parameters, not empirically validated safety boundaries.

Plans capture both epochs and the environment snapshot. `update_environment()` increments the local Environment Epoch whenever any context field changes, even if enterprise DSI stays unchanged. Returning to an earlier environment does not revive old plans. This local counter belongs to one policy-engine instance. The complete runtime adds issuer-owned opaque execution permits; distributed per-machine versioning and signed remote authorizations are not implemented.

---

## Task, Identity, Provenance, and Execution Binding

The trusted setup provisions human and agent identities, records authenticated user instructions, registers tools and their action metadata, and creates structured task grants. The agent submits a `ToolCall` containing task/tool/resource/target IDs, exact arguments, an instruction reference, data references, and a request ID. It cannot set its own permissions, source trust label, or action sensitivity through this request.

* **Task scope:** each grant binds a user, agent, originating instruction, permitted call rules, authorized approvers, expiry, revocation state, and version. Grant creation cannot exceed the agent's delegated action permissions. Purpose text is shown to reviewers; its operational scope is explicitly configured, not inferred or semantically verified by an LLM.
* **Exact calls:** only registered tools are available. Each rule binds a tool, exact resource and target IDs, and a constraint for every argument. The demo supports flat string/integer schemas, exact allowlists (paths, recipients, payees, body text, output format), and bounded integers such as payment amounts in cents. Missing/extra parameters and type mismatches are rejected. Resource/target IDs must also match the policy engine's current environment.
* **Identity:** `MockIdentityProvider` validates opaque bearer sessions against issuer-owned records, including human/agent type, active status, identity version, expiration, revocation, parent-user delegation, and source-machine binding. Parent-session revocation invalidates dependent agent sessions. The login-issuance API simulates an already-authenticated login; it does not authenticate a real person or device.
* **Input provenance:** trusted ingestion labels user instructions, web content, emails, tool output, and agent messages. External content can be referenced as data but cannot authorize a task or replace its user instruction. Unknown input references are rejected. This does not detect every prompt injection or prevent malicious data from influencing an otherwise permitted action.
* **Approval and dispatch:** `prepare()` returns a permit for ALLOW, a pending request for APPROVAL, or a denial/re-evaluation. An authorized human can inspect the exact call, purpose, approval reason, environment, DSI, and expiry, then approve or reject. Approval rechecks the originating session, task, policy, and bound state. `execute()` requires the same session and exact call, rechecks current authorization, and consumes its permit before invoking the registered local handler. Replays of a permit or an already-attempted request ID within that task are blocked.

Pending approvals and permits expire at most 60 seconds after preparation in this demo, and never outlive their relevant session/task. A changed call requires a new authorization, even when the replacement parameters are also allowed by the task. Changes to task scope, registered tool version, DSI score (including within a security level), emergency state, or environment invalidate a mismatching approval/permit. An approving session must remain valid at execution.

These services and their registries are in-memory, trusted, single-process fixtures. Their provisioning/update methods must not be exposed as agent tools. Runtime audit records identify the actor and task, record argument hashes and environment/decision details, and omit bearer tokens and raw parameter text. There is no persistent audit store, distributed transaction, real sandbox, or atomic authorization with a remote API. Tool failures consume the attempt; side-effect reconciliation for real tools is future work.

---

## Zero Trust Principles Used

The prototype applies several Zero Trust concepts to AI agents:

* No implicit trust
* Least privilege
* Continuous authorization
* Runtime policy enforcement
* Human approval for high-risk actions
* Agent-specific identity
* Department-aware access control
* Dynamic permissions
* Auditability

The goal is not to assume that an agent is safe simply because it has valid credentials.

Instead, every important action is evaluated in context.

---

## Current Prototype

The current version includes:

* Simulated AI agents
* Department-specific policies
* Dynamic Security Indicator
* Security levels
* Security Epoch
* Runtime authorization checks
* Action sensitivity scoring
* Human approval logic
* Crisis mode
* Audit logging
* Dynamic permission restrictions
* Machine/resource/execution environment restrictions
* Environment snapshot and epoch re-evaluation
* Structured task grants and parameter/resource constraints
* Mock identity/session/delegation verification
* Trusted instruction and external-data provenance separation
* Approval inspection, approval/rejection, and revalidation
* One-use exact-call execution permits and local stub dispatch

The current prototype uses rule-based agent behavior rather than a real LLM.

This allows the initial security architecture to be tested independently before introducing additional uncertainty from model behavior.

The legacy `execute_action()` prints policy decisions. The complete runtime implements approval and resumption through local stub tools, with no real emails, payments, files, or enterprise API calls. Machine telemetry, resource labels, login events, and human approval events are simulated. Turning emergency mode off still resets DSI to zero in the lower-level policy demo.

Run the scenarios and policy checks with Python 3.9+ (standard library only):

```bash
python3 agent_demo.py
python3 -B secure_agent_demo.py
python3 -B -m unittest -v test_agent_demo.py test_secure_runtime.py
```

Scenario 4 holds enterprise DSI at NORMAL while demonstrating test versus production, stale environment context, risky source/target machines, incident response, and sensitive transfer restrictions.

The complete demo additionally covers task-scoped email denial, external instructions, production approval, changing parameters after approval, successful approved execution, replay prevention, and a security change while waiting for approval. Tests cover exact recipients, bounded payment amounts, session/task revocation and expiry, independent approver revocation, and changed tool/task versions.

---

## Planned Future Development

Future versions may include:

* Real LLM-based agents
* Tool calling
* Prompt injection attacks
* Goal hijacking scenarios
* Dynamic permission escalation and reduction
* MCP tool environments
* Enterprise API integration
* Network security telemetry
* SIEM integration
* More realistic departmental policies
* Automated incident-response behavior
* Multi-agent interaction

The system could later be tested against agent security benchmarks and simulated cyberattack scenarios.

---

## Research Question

The broader research question is:

**How can dynamic enterprise security conditions be integrated into Zero Trust authorization for autonomous AI agents so that agent permissions adapt in real time as organizational threat levels change?**

A more experimental formulation is:

**Can DSI-driven adaptive authorization reduce harmful AI-agent actions during cyber incidents while preserving legitimate low-risk business operations?**

---

## Potential Evaluation Metrics

Future experiments could compare:

1. Static permissions
2. Traditional Zero Trust authorization
3. DSI-driven adaptive Zero Trust

Possible metrics include:

* Attack success rate
* Unauthorized action rate
* Data leakage rate
* Legitimate task completion rate
* False blocking rate
* Human approval frequency
* Response latency
* Operational disruption during security incidents

The goal is to evaluate the tradeoff between **security and operational usefulness**.

---

## Current Status

This project is currently an early-stage research prototype.

The initial goal is to develop and understand the security architecture before integrating real LLM agents, external tools, and more complex attack scenarios.
