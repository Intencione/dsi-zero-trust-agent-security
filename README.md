# DSI-Driven Zero Trust Security for AI Agents

This repository contains an early-stage prototype exploring how **Dynamic Security Indicators (DSI)** can be combined with **Zero Trust principles** to improve the security of autonomous AI agents operating inside an enterprise environment.

Run `python3 -B secure_agent_demo.py` for the complete local authorization workflow: task scope, identity and input provenance, exact tool constraints, DSI/environment policy, human approval, and one-use execution permits. Identities, approvals, telemetry, and tool effects are simulated; the demo sends no messages or payments.

The finance agent also supports LangChain tool calling and a checkpointed LangGraph approval workflow. After installing the optional dependencies below, run `python3 -B llm_graph_demo.py --offline --auto-approve` to reproduce an incident during pending approval without an API key. This uses a scripted model fixture, not an LLM.

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

The original Phase 1 services and registries are in-memory, trusted, single-process fixtures; the Phase 4 extension below adds durable runtime authority. Their provisioning/update methods must not be exposed as agent tools. Runtime audit records identify the actor and task, record argument hashes and environment/decision details, and omit bearer tokens and raw parameter text. There is no persistent audit store, distributed transaction, real sandbox, or atomic authorization with a remote API. Tool failures consume the attempt; side-effect reconciliation for real tools is future work.

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

The policy/runtime demos use deterministic calls. The finance agent can use a live OpenAI chat model through LangChain, or a deterministic model fixture exercising the same LangChain tool loop without network access. The runtime remains independent of the model provider; other tool-calling LangChain chat models can be injected into `build_agent(model, tools)`. Only an OpenAI live-provider factory is currently supplied.

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

## Agent and Telemetry Architecture

```text
User → LangChain agent → proposed business arguments → LangGraph
     → SecureRuntime → ALLOW / BLOCK / REQUIRE HUMAN APPROVAL / REEVALUATE
     → one-use authorized execution → mock output → model

Security source / simulator → signed event → schema + source authentication
     → freshness + deduplication + replay checks → DSIService
     → the same PolicyEngine.dsi read by SecureRuntime
```

The trusted composition root creates one runtime, then injects its existing `PolicyEngine` into `DSIService`. It registers a simulated security source with a randomly generated signing key and explicitly permitted event types. The simulator submits signed events through the normal ingestion path; neither component creates another policy or DSI. LangGraph nodes do not emit telemetry events. The demo host schedules the incident only after the graph has paused, then obtains a human decision and resumes the same checkpointed request. The demo driver rejects a simulator wired to a different policy, and the service rejects a second service competing to publish into the same policy.

The model sees only business tool schemas and results. Task/instruction/resource/target bindings come from the host, and permissions, sensitivity, provenance, DSI, environment, approval and permit state remain runtime-controlled. String arguments are passed unchanged: `PDF` is blocked by the task's exact `pdf` constraint, and paths are not trimmed or normalized. Extra fields and incorrect types are rejected by the adapter. The email tool is available to the model but outside this finance task's grant.

Approval review displays the exact call, task purpose, environment, DSI and epoch snapshot, reason and expiry. Resume revalidates authorization; an expired approval that leads to another approval requires a new human decision. A permit becoming stale before dispatch also routes through context refresh. Tool errors remain terminal execution attempts. Actual mock outputs, such as revenue/expenses/profit and the simulated report description, return as LangChain `ToolMessage` data; pending IDs, permits and session tokens are not included in those results.

Code is organized incrementally:

| Location | Responsibility |
| --- | --- |
| `agent/models.py` | Injected LangChain model and optional OpenAI factory; no model construction on import |
| `agent/tools.py` | Strict business schemas and trusted task bindings |
| `agent/security_workflow.py` | Runtime authorization, interrupt/checkpoint/resume and refresh routing |
| `telemetry/events.py` | Strict event schema, immutable accepted records and explicit DSI input mapping |
| `telemetry/sources.py` | Host-provisioned source registry and replaceable HMAC verification |
| `telemetry/store.py` | Event-store protocol and atomic in-memory acceptance/replay tracking |
| `telemetry/dsi_service.py` | Authenticated ingestion, event lifecycle, audit and DSI publication |
| `telemetry/reliability.py` | Source health, versioned credentials, conservative continuity and transactional publication |
| `telemetry/sqlite_store.py` | Single-writer local SQLite persistence for events, replay, source and audit state |
| `telemetry/simulator.py` | Signed normal/anomaly/crisis scenarios through the same ingestion path |
| `demos/finance_agent.py` | Mock infrastructure, shared-state wiring, review and event scheduling, CLI |
| `demos/scripted_model.py` | Deterministic offline fixture using the real LangChain tool loop |
| `tests/` | Agent output, graph workflow and telemetry integration tests |
| `secure_runtime.py`, `agent_demo.py` | Existing security authority and policy; unchanged in this milestone |

The core and its original tests remain at the repository root. Moving them into `security/` is deferred to avoid changing imports and checkpoint serialization during these milestones. `llm_graph_demo.py` and `llm_secure_demo.py` remain executable compatibility entry points. The latter preserves the incident-after-read scenario using the shared graph path. The beginner examples `langchain_test.py` and `langgraph_test.py` remain learning examples, not the secured finance agent; the former's standalone stubs are outside this runtime.

## Phase 2: Trusted Telemetry Ingestion

Phase 2 introduced verification of structured events before deriving DSI. Events still come from local simulated sources; there are no SIEM connectors, HTTP endpoints, real IAM or infrastructure integrations. Phase 3 adds a local SQLite adapter, described below.

An accepted `TelemetryEvent` contains `event_id`, `source_id`, `event_type`, integer `severity` (0–100), `observed_at`, server-assigned `received_at`, a positive source `sequence`, server-derived `expires_at`, optional `target_id` / `resource_id`, and optional JSON metadata. All timestamps are finite, nonnegative UTC Unix seconds. Accepted events are immutable; reading metadata returns a detached copy.

Sources submit only the source-controlled fields. Supplying `received_at`, `expires_at`, a custom lifetime, `dsi_score`, or any other unknown field is rejected. Integers are checked strictly: booleans, strings and floats are not accepted as severity or sequence. Metadata permits bounded JSON values (16 KiB, maximum depth 8 and collection length 128); it cannot declare authority, permissions, emergency state or environment risk. Target/resource identifiers describe signal streams and do not change the runtime's evaluated environment.

The host configures `TrustedSource` entries before ingestion. Each has a source ID, a key of at least 32 bytes and an explicit event-type allowlist. `SourceVerifier` is replaceable; the supplied implementation uses HMAC-SHA256 over the canonical complete source payload, with constant-time digest comparison via [Python's HMAC API](https://docs.python.org/3/library/hmac.html). Naming a registered source is insufficient: the signature must verify with that source's key. The default source scope excludes emergency declarations. Signatures authenticate key possession and payload integrity, not the factual truth of an observation.

The ingestion rules are:

* `received_at` comes exclusively from an injected host clock. Default maximum observation age is 120 seconds and future tolerance is 5 seconds; both are configurable through `TelemetryLimits`.
* An event's lifetime defaults to 300 seconds. Expiry is `min(observed_at, received_at) + event_lifetime`, so tolerated future timestamps cannot extend its lifetime. An event already expired on arrival is rejected even if the ingestion age limit would otherwise allow it.
* Event IDs are globally unique within the store. Each source also has a strictly increasing sequence, so changing an ID cannot replay an old sequence. Older observations cannot replace newer observations in the same stream, even with a higher sequence.
* A stream is `(source_id, event_type, target_id, resource_id)`. The latest accepted event replaces that stream's prior state. Severity zero clears only that stream's contribution. Across sources and targets, each DSI input uses the maximum active severity, preventing one source's recovery from clearing another source's alert.
* `ingest_batch()` validates all events before committing any of them. A rejected batch does not consume IDs/sequences or partially update DSI. A valid multi-signal crisis is published once, preserving the original one-epoch transition from NORMAL to CRISIS.
* Rejected submissions do not change DSI or run expiry maintenance. Accepted/rejected events and expiry transitions have immutable audit records containing time, claimed IDs, authentication status and a stable outcome/reason. Keys, signatures and raw metadata are excluded.

The explicit signal mapping preserves the existing policy weights:

| Event type | DSI input | Weight / behavior |
| --- | --- | --- |
| `network_anomaly` | `network_anomaly` | 30% |
| `credential_anomaly` | `unknown_operations` | 20% |
| `destructive_activity` | `destructive_activity` | 30% |
| `other_alert` | `other_alerts` | 20% |
| `emergency` | Administrator emergency flag | Explicit source scope required; severity 100 enables the existing 95-point floor, 0 clears only that source's declaration |

For example, active severities of 80 / 50 / 20 / 10 yield DSI **42**, and four 100-severity signals yield **100**. A single 100-severity credential anomaly yields **20**, not CRISIS. Emergency events expire too; clearing an emergency preserves other active signals. No submission can assign an arbitrary DSI score.

`EventStore` separates persistence from ingestion. `InMemoryEventStore` atomically checks duplicate IDs, source sequence watermarks and observation ordering while replacing active streams. Expired events leave the active picture; their ID tombstones and replay watermarks remain for the store's lifetime. Store and service locks serialize local ingestion, but do not implement distributed transactions.

Expiration is cooperative: the trusted host calls `refresh()` on its maintenance schedule; `status()` also refreshes. The finance demo refreshes immediately before a tool workflow starts and before an approval resumes. There is no background scheduler in this phase. Direct runtime callers must arrange maintenance themselves. A backwards host clock is rejected, preserving the last published state. Policy level changes, including recovery after expiry, still increment Security Epoch; score changes within a level still invalidate bound approvals/permits through the unchanged runtime checks.

A host can provision a source against an existing runtime as follows (create only one telemetry service per policy):

```python
import secrets
import time
from telemetry.dsi_service import DSIService
from telemetry.sources import HMACSourceVerifier, SourceRegistry, TrustedSource, sign_event

# Host-side provisioning. These objects and the key never become agent tools.
source_key = secrets.token_bytes(32)
sources = SourceRegistry([TrustedSource("network-sensor", source_key)])
service = DSIService(runtime.policy, verifier=HMACSourceVerifier(sources))

# Source-side submission; observed_at is covered by the signature.
payload = {
    "event_id": "network-sensor:1", "source_id": "network-sensor",
    "sequence": 1, "event_type": "network_anomaly", "severity": 80,
    "observed_at": time.time(), "target_id": "machine-01",
}
receipt = service.ingest(payload, sign_event(payload, source_key))
assert receipt.accepted
assert service.policy is runtime.policy
```

`SecurityEventSimulator` provides `normal_environment()`, `credential_anomaly()`, `network_anomaly()`, `destructive_activity()` and `multi_signal_crisis()`. With an injected fake clock, source IDs, sequences and scenario outcomes are deterministic. `trigger_incident()` retains Phase 1's one-shot behavior. A normal scenario clears only that simulator's four unscoped signal streams, not other sources or an active emergency.

To preserve all original tests, an otherwise unconfigured `DSIService(policy)` can be explicitly provisioned by the legacy `SecurityEventSimulator(service)` constructor. Only that isolated fixture enables the old `ingest_signals()` / `set_emergency()` convenience methods; those methods now emit signed events through ingestion. Services configured with a verifier—including the canonical finance demo—reject both unsigned methods and simulator auto-registration. Neither variant exposes telemetry writers, source provisioning or signers through the model's tools.

Phase 2 validation: the unchanged baseline passed **74 tests** before editing, increasing to **124 passing tests**, including **50 new tests** for authentication, tampering, schema validation, clock boundaries, batch atomicity, concurrent duplicate delivery, replay after expiry, aggregation, metadata isolation, audit redaction, shared DSI/epoch effects, pending-approval revalidation and the agent boundary. All timing tests used fake clocks and no sleeps.

## Phase 3: Telemetry Reliability and Trust Continuity

`ReliableDSIService` extends the existing ingestion pipeline with source health, versioned keys and transactional persistence. It uses the same permanent `PolicyEngine` / DSI instance as `SecureRuntime`; neither the runtime nor its policy rules changed. Signed heartbeats use the same ingestion, freshness, source authentication, duplicate and sequence checks as security events, with `event_type="heartbeat"` and `severity=0`. The signed payload may specify a positive integer `key_version`; omission denotes version 1 for compatibility. Heartbeats affect contact/health, not threat signals. Metadata cannot declare health or rotate credentials.

There are two explicit service profiles:

* `DSIService` remains the Phase 2 TTL-only fixture, preserving all 124 original tests and their expiration expectations. It does **not** establish operational source health. It rejects accidental use with the transactional SQLite adapter.
* `ReliableDSIService` establishes health and trust continuity. The finance **CLI defaults to this profile**. Phase 4 now uses SQLite by default; `--in-memory` retains the earlier fixture. `--no-reliable-telemetry` selects the old fixture. Programmatic callers of the existing `build_finance_demo()` retain the old default for compatibility; pass `reliable_telemetry=True` to enable continuity. Use `ReliableDSIService.open_sqlite()` for durable telemetry.

`TrustedSource` now includes `reporting_interval` (default 60 seconds), `grace_period` (30 seconds), `criticality` (`critical` or `standard`), `enabled`, and `key_version`. Registrations and subsequent enable/disable and rotation operations belong to the trusted host, never to agent tools. The service tracks last authenticated contact, last accepted event time, last observed sequence and observation time, and an explicit health state. Authenticated but stale/replayed submissions can record contact; they cannot extend the deadline based on the last **accepted** event.

Let `I` be the reporting interval, `G` the grace period, and `age` the time since the last accepted event. The health rules are deterministic:

| State | Condition |
| --- | --- |
| HEALTHY | Enabled, a valid event has established contact, `age <= I`, and its observation was not delayed by more than `G` |
| DEGRADED | `I < age <= I + G`, or an otherwise timely accepted event reported an observation delayed by more than `G` |
| STALE | `I + G < age <= offline deadline` |
| OFFLINE | No established contact, contact required after re-enabling, or `age > offline deadline` |
| DISABLED | Explicitly disabled by the trusted host; all event submissions are rejected |

The offline deadline is `I + 2G` for critical sources and `2I + 2G` for standard sources. Stale/offline thresholds take precedence over the delayed-observation flag. Boundary times are inclusive on the healthier side. Fresh startup begins OFFLINE, never optimistically HEALTHY. Re-enabling requires a new accepted event while retaining historical contact and sequence records.

**Every non-HEALTHY registered source makes coverage uncertain.** This profile uses the existing emergency floor of 95 while coverage is uncertain, preserving any higher active threat score. `admin_emergency=True` may therefore indicate a coverage failure, not just an administrator's explicit declaration; consult source health and audit records to distinguish the causes. Disabling a source does not remove it from required coverage or make the environment safe.

Normal TTL expiration continues while a source is healthy. If a positive threat event reaches its TTL while its source is unavailable/degraded/disabled, it is retained as unresolved. A subsequent heartbeat restores source health but does **not** clear these retained threats. A new authenticated observation for that same source/type/target/resource stream replaces them; zero severity explicitly clears only that stream. Other sources' signals remain intact. Events already expired while coverage was healthy are never resurrected on recovery or restart. Recovery processing checks the prior health/expiry state before accepting new contact, including when no maintenance tick occurred during the outage.

Maintenance remains cooperative: the trusted host must call `refresh()` before authorization and on its operational schedule. The finance driver does so before starting a tool workflow and before resuming approval. The simulator emits an initial heartbeat; it is not a background producer that silently keeps itself healthy. Long runs without new source reports intentionally become unhealthy. Missing, delayed, or rejected events must not be used as substitutes for a heartbeat scheduler.

### Key rotation

`rotate_key(source_id, new_version, new_key, overlap=0)` is a trusted-host capability. Versions must increase, new keys must differ from previous keys and contain at least 32 bytes, and overlap must be between 0 and 300 seconds. Immediate retirement is the default. With overlap, the old key is accepted only while receipt time is strictly before its retirement deadline; a second rotation cannot extend an earlier retirement. Event IDs, sequence watermarks, health and threat state are never reset by rotation. Retired keys cannot authenticate even a newly named, freshly timestamped event.

The database stores version numbers, SHA-256 key fingerprints and retirement deadlines, **not plaintext source keys**. The host injects actual keys on startup. Every active or still-overlapping version must be supplied and match its fingerprint; missing or mismatched required credentials fail startup conservatively. Retired key metadata remains to enforce historical retirement. Keys and signatures are excluded from audit records. This is an in-process credential mechanism, not a production secret manager or IAM integration.

### Persistence and recovery

The storage contract adds transaction and snapshot/restore operations, keeping service behavior independent of the backend. `SQLiteEventStore` uses a versioned JSON snapshot inside a SQLite transaction to commit registrations, health/contact state, accepted IDs, sequence/observation watermarks, active events, expiry/retention information, DSI score/epoch, credential version metadata and audit history together. It uses explicit `BEGIN IMMEDIATE` / `COMMIT` and `synchronous=FULL`; see [SQLite atomic commit documentation](https://www.sqlite.org/atomiccommit.html) for the underlying transaction mechanism and filesystem assumptions.

The DSI calculation runs on a temporary calculation snapshot using the unchanged policy implementation. Only after commit succeeds are the results published into the permanent shared DSI object. A failed commit cannot expose a proposed risk reduction to the runtime. A process-local lock and an exclusive advisory writer lease prevent cooperating services from writing the same database concurrently. The adapter currently supports macOS/Linux (`fcntl`) and is deliberately a single-writer, full-snapshot prototype.

Restart restores telemetry state and replay protection, then evaluates elapsed time and source health before returning the service to the host. A healthy unexpired threat still contributes; an unresolved outage threat remains held; a previously expired event remains absent. Stored enabled state and retirement deadlines are authoritative and cannot be reset by passing a fresh registration. The source set and static monitoring configuration cannot silently change during recovery.

Use the startup helper so storage-open failures also fail conservatively:

```python
from telemetry.reliability import ReliableDSIService
from telemetry.sources import TrustedSource

# First startup: source_key is supplied securely by the trusted host.
service = ReliableDSIService.open_sqlite(
    runtime.policy, "/trusted/local/path/telemetry.sqlite",
    sources=[TrustedSource("sensor", source_key, reporting_interval=60, grace_period=30)],
)
# The source must establish authenticated contact before the system is healthy.
# ... ingest signed events / heartbeats and perform host maintenance ...
service.close()

# A new process creates its own runtime and re-injects the required versioned keys.
recovered = ReliableDSIService.open_sqlite(
    new_runtime.policy, "/trusted/local/path/telemetry.sqlite",
    keys={("sensor", 1): source_key},
)
recovered.close()
```

Detected database corruption/missing state, clock rollback and persistence failures raise `TelemetryUnavailable` and activate the existing conservative emergency behavior. A running service latches its failure in `service_fault` and records a `service_failure` in its in-memory audit; it requires trusted reinitialization rather than silently retrying into NORMAL. When persistence itself is unavailable, that failure record cannot be guaranteed durable. The host must stop dispatch on these errors. Ordinary rejected events and malformed control operations retain their no-DSI-mutation behavior; host maintenance remains necessary before any subsequent authorization.

Audit distinguishes accepted events, unknown sources, failed authentication, replay, stale/future observations, health transitions, key rotation, enable/disable, rejected control operations and restart/recovery. Rotation does not log keys. SQLite persists telemetry audit only: runtime permits, sessions, pending approvals and LangGraph checkpoints are still in memory.

Run the deterministic reliability/restart demo (temporary SQLite database, fake clock, no model/API calls):

```bash
python3 -B -m demos.telemetry_reliability
python3 -B llm_graph_demo.py --offline --auto-approve --scenario none
python3 -B -m unittest discover -v
```

The simulator now supports signed heartbeats, delayed contact, stopped scheduled heartbeats, recovery and host-mediated key rotation. Stopping its local heartbeat sender does not directly manipulate server health; only elapsed fake time and trusted maintenance produce health transitions.

Phase 3 validation: **124 baseline tests passed before changes; 167 tests pass afterward**, including **43 new tests**. Coverage includes exact health boundaries, source loss and recovery, pending-approval outage revalidation through the actual graph, credential retirement/overlap and concurrent rotation, SQLite rollback and initialization failures, commit-before-publication, and two separately launched Python processes preserving replay and active state. Tests use fake clocks and temporary databases, without sleeps. All pre-existing test files, `secure_runtime.py` and `agent_demo.py` remain byte-for-byte unchanged.

## Running the Finance Agent

The optional agent stack requires Python 3.10+. From the repository root:

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -r requirements-agent.txt

# Pending approval → simulated CRISIS → approve → REEVALUATE → BLOCK
python3 -B llm_graph_demo.py --offline --auto-approve

# Unchanged production context → approve read → execute read and PDF report stubs
python3 -B llm_graph_demo.py --offline --auto-approve --scenario none

# Authorized read → simulated CRISIS → stale report plan → refresh → BLOCK
python3 -B llm_secure_demo.py --offline

# Original tests plus all integration tests; no API calls
python3 -B -m unittest discover -v
```

Omit `--auto-approve` to answer each approval prompt yourself. The flag is restricted to the offline simulated-human demo. All business effects are mocks: no real file is read, PDF created, email sent, or payment executed. `simulated: true` marks handler outputs.

For a live model, configure `OPENAI_API_KEY` in your local environment, then run:

```bash
python3 -B llm_graph_demo.py
# Or select a model available to your API account:
python3 -B llm_graph_demo.py --model YOUR_MODEL_NAME --scenario none
```

The default model name remains `gpt-5.6-luna`, as in the original demo, with the Responses API setting preserved. Availability depends on the account. Live runs make model API requests; business tools still execute only local mocks. The canonical entry point is also available as `python3 -B -m demos.finance_agent` with the same options.

Phase 1 validation used Python 3.14.7 and the installed versions recorded in `requirements-agent.txt`: 51 baseline tests increased to 74 passing tests, including 23 integration tests. Original local demos and all three offline finance scenarios were run, including the terminal approval prompt with scripted input. No `OPENAI_API_KEY` was available, so live model demos could not complete; tool-output propagation was verified through the real LangChain loop with the scripted model. A fresh dependency installation was not part of that validation. Phase 2 adds only standard-library telemetry code and requires no additional dependencies.

This remains a local research prototype with simulated identities, source observations and business effects. SQLite durability now covers telemetry, authorization and graph position in the default finance CLI; the legacy TTL-only profile and in-memory adapter do not retain state across process restart. The persistent snapshot/audit grows without compaction and is not optimized for high-volume ingestion. It trusts the local filesystem: hostile database modification, deletion or rollback is not prevented by cryptographic sealing. There is no secret manager, network transport, process isolation, source attestation or production IAM. A compromised authenticated source can still lie about its observations. Maintenance must run independently of the agent, and the host must serialize telemetry publication with authorization/dispatch. The persistent runtime retains permits, approvals, executions and graph position. Live identity sessions and provenance must be re-provided by the trusted host; there is no atomic transaction with remote tool effects. Model output and provenance labels alone do not solve prompt injection.

---

## Planned Future Development

Future versions may include:

* Real telemetry transport, independent maintenance scheduling and external secret management
* Authenticated reconciliation and recovery administration for unknown tool outcomes
* Additional model-provider adapters and live-model evaluations
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

The current milestones separate telemetry from the agent workflow, validate authenticated security events, preserve telemetry trust continuity across outages/restarts, and test runtime enforcement around model tool calling. Real enterprise integrations, durable authorization state, and more complex attack evaluations remain future work.


## Phase 4: Persistent Authorization and Crash Recovery

The finance CLI now defaults to SQLite authorization, checkpoints and reliable telemetry.
`--state-db /path/to/new.sqlite` selects the file; otherwise it prints a newly allocated
SQLite path. `--in-memory` retains the original deterministic workflow. The programmatic
`build_finance_demo()` default remains the in-memory fixture for compatibility; pass
`authorization_path=...` to select persistence. This CLI provisions a **new** simulated
identity/task on each run and deliberately refuses an existing authorization DB rather
than pretending fresh sessions own old approvals. Use the recovery API with original
trusted host identity/provenance and tool bindings to reopen an existing DB.

```bash
python3 -m demos.authorization_recovery
python3 llm_graph_demo.py --offline --auto-approve --scenario none
python3 llm_graph_demo.py --offline --auto-approve --in-memory
python3 -m unittest discover -v
```

`demos.authorization_recovery` constructs separate runtime and graph instances on the
same database, restores a pending review, accepts the simulated human response, and
restores the completed output while invoking the mock tool only once.

### Architecture and authority boundary

`PersistentSecureRuntime` subclasses the existing runtime and retains its evaluator,
approver authentication, exact-call binding, source provenance, task scopes, epochs and
single-use checks. The only change in `secure_runtime.py` is a `_dispatch(tool, call)`
extension point at the existing handler call, after authorization and permit consumption.
The original in-memory runtime semantics remain intact.

`AuthorizationStore` exposes atomic snapshot load/save and a separate checkpoint namespace.
`SQLiteAuthorizationStore` uses synchronous transactions and a POSIX single-writer lease;
`MemoryAuthorizationStore` provides the deterministic alternative. A later database adapter
can implement this interface without moving policy decisions into storage. SQLite stores:

* Task grants, exact pending approval records and their session hashes, call, binding,
  plan/environment snapshot, relevant epochs, deadline and approving human session hash.
* Unused permit hashes, consumed/attempted request tombstones and human rejections.
* Canonical request records, execution identities, lifecycle states and completed results.
* Authorization and dispatch/recovery audit history.

Session bearer tokens, telemetry signing keys and Python handlers are not persisted.
Permit tokens are hashed at rest and the hash itself is not accepted as a caller's permit.
Approval IDs are record locators requiring human authentication, not approval authority.
Exact arguments, original approval context and tool results are sensitive data in the
trusted authority database; protect it accordingly. There is no encryption-at-rest feature.

`PersistentSecurityWorkflow` uses a synchronous, JSON-only LangGraph checkpointer specialized
for its single recovery node. Its state contains only `request_id`; it never stores a
permit, plan context, human answer or authorizing decision. It persists the latest position,
not general graph history/pending writes. Repeating the node consults durable runtime state.
The trusted host supplies the request ID and validates the session; a conflicting checkpoint
request ID is rejected. Returned UI approval details/results come from runtime records,
not checkpoint fields. This workflow's review pause is controlled by the host; it does not
trust LangGraph resume values as human approval. Only the authenticated host `resume` path
calls `resolve_approval`. No graph node can mint permits, approve, update authority records,
mark an execution complete or ingest telemetry. Existing agent tools remain business-only.

### Recovery contract

The host must supply live, authoritative identities/sessions, original input provenance,
registered tool descriptors/versions and verified current environment on every boot.
It must recover reliable telemetry **before** accepting requests. When a telemetry service
is attached, every persistent runtime authority operation refreshes that same service and
PolicyEngine/DSI; telemetry failure prevents dispatch. Host environment history/epochs must
also be trustworthy, not reconstructed from graph state. Never roll back identity revocation,
relabel external input as user instruction, or reuse tool versions for changed semantics.
The demo's mock IdP is not a durable login service. Missing original host context blocks
recovery; neither a checkpoint nor a fresh demo session can replace it.

```python
# All arguments below come from trusted host provisioning/recovery, not the agent.
store = SQLiteAuthorizationStore(database_path)
runtime = PersistentSecureRuntime(trusted_runtime, store)
workflow = PersistentSecurityWorkflow(runtime, original_agent_token, human_token)
review_or_result = workflow.restore(request_id)
# Only after an authenticated human answers the exact displayed request:
review_or_result = workflow.resume(request_id, approved=True)
```

| Last durable state / crash point | Recovery behavior |
| --- | --- |
| No request exists | A checkpoint cannot create authorization. |
| PREPARED, interrupted before decision | REEVALUATE; explicitly submit a newly reviewed request. No automatic permit. |
| APPROVAL_PENDING | Restore the real pending record; authenticate the human and run normal revalidation. |
| Approved / PERMIT_ISSUED, before dispatch | Use only the proven unused durable permit; recheck exact call, sessions, scope, binding and expiry. |
| Expired, mismatched, revoked or stale permit | Consume/reject or REEVALUATE; never automatically mint a replacement. |
| DISPATCH_STARTED, including the tiny window before the actual handler | UNKNOWN_OUTCOME after restart; no automatic retry, even if no effect actually occurred. |
| Tool raised after dispatch | Conservatively UNKNOWN_OUTCOME; the exception does not prove no side effect occurred. |
| Side effect happened but result commit was lost | UNKNOWN_OUTCOME; reconcile with external evidence. |
| EXECUTED | Return the durable result to the original authenticated session; do not invoke the tool again. |
| FAILED / human rejection | Return the terminal decision; preserve rejection and replay protection. |

Changed security or environment causes the original approval/permit to return REEVALUATE
or BLOCK. A read-only fresh assessment may strengthen REEVALUATE to BLOCK; it never creates
a replacement permit or carries a human answer to a new request. Duplicate `prepare` for
an existing request is rejected. Recovery is the only continuation path for that request.

Permit removal, the request attempt tombstone, DISPATCH_STARTED and dispatch audit are
committed together **before** invoking the adapter. A commit failure prevents invocation
and latches the runtime unavailable. If the commit fails after the side effect, recovery
sees the prior dispatch marker. Corrupt/missing initialized snapshots and clock rollback
refuse recovery. Failure audit cannot be guaranteed durable when storage itself is broken.

### Idempotency and reconciliation

The execution ID is SHA-256 over a versioned canonical exact ToolCall (including task,
request, tool, resource, target, instruction, arguments and evidence) and session hash.
It is stable across restart, but is not an authorization token. Trusted adapters may use
`register_idempotent_adapter(tool_name, adapter)` where `adapter(call, execution_id)`
forwards this ID to a downstream service supporting idempotency. Register the adapter as
part of the same trusted tool contract; version changed tool semantics normally.

A new logical request has a different identity; this is not cross-request business deduplication.
No remote payment/email services are included. The runtime does not claim exactly-once effects
and does not automatically retry even when an adapter accepts an idempotency key.
UNKNOWN_OUTCOME requires host/operator reconciliation against downstream records. Phase 4
intentionally offers no unverified “mark complete” or retry switch; reconciliation remains
blocked until a future authenticated, audited evidence-based resolution API is implemented.

Telemetry and authority can use separate tables in the same SQLite database, with their
own transactions and writer leases. They are not one distributed transaction. Recover and
refresh telemetry before authorization; the host must serialize concurrent security updates
with dispatch. Local snapshot corruption checks do not defend against malicious filesystem
rollback/deletion. Stores grow without compaction, results must be JSON-serializable, and
there is no process sandbox, HA, distributed execution or durable real IAM.

### Files and validation

New files: `authorization/{__init__,codec,store,runtime}.py`,
`agent/persistent_workflow.py`, `demos/authorization_recovery.py`, and
`tests/test_authorization_recovery.py`. Updated: `secure_runtime.py` (dispatch hook only),
`demos/finance_agent.py`, and this README. No existing tests were changed.

Phase 4 validation: **167 baseline tests passed before changes; 206 tests pass afterward**,
including **39 new tests**. Fake-clock tests construct separate runtime/graph instances on
the same SQLite file and cover approval recovery/revalidation, offline security/environment
changes, rejection and permit continuity, expiry and exact-call mismatch, checkpoints without
authority, cached results, crashes before/after dispatch and after side effects, commit failure,
idempotency stability, durable audit, joint telemetry recovery, revoked identities/tasks,
corruption, clock rollback and malicious graph fields. No sleeps or live remote effects.

Recommended Phase 5: authenticated recovery administration and evidence-based reconciliation,
with downstream idempotency lookup, durable host identity/provenance/environment provisioning,
operator audit, and process-level fault-injection tests before adding real side-effecting tools.
