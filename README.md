# DSI-Driven Zero Trust Security for AI Agents

This repository contains an early-stage prototype exploring how **Dynamic Security Indicators (DSI)** can be combined with **Zero Trust principles** to improve the security of autonomous AI agents operating inside an enterprise environment.

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

* Draft public announcement → ALLOW
* Create social media content → ALLOW
* Access internal network resources → BLOCK
* Transfer internal files → BLOCK

### Cybersecurity Agent

A cybersecurity agent may retain or even receive additional operational access because it is directly involved in incident response.

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

The prototype evaluates actions using multiple factors, including:

* Agent identity
* Department
* Delegated permissions
* DSI score
* Action sensitivity
* Security level
* Security epoch
* Crisis-specific departmental rules

The system can return four possible outcomes:

* **ALLOW**
* **REQUIRE HUMAN APPROVAL**
* **BLOCK**
* **REEVALUATE**

The DSI has a high influence on the final decision because organization-wide security conditions should strongly affect what autonomous agents are allowed to do.

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

The current prototype uses rule-based agent behavior rather than a real LLM.

This allows the initial security architecture to be tested independently before introducing additional uncertainty from model behavior.

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
