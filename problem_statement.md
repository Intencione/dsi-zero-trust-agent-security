# Problem Statement

## Dynamic Security Indicator-Driven Zero Trust for Autonomous AI Agents

Large language models are increasingly being integrated into autonomous AI agents that can interact with external tools, enterprise systems, internal data, APIs, cloud services, and other software. Unlike traditional language models that mainly generate information, AI agents may be able to take real actions, such as sending emails, accessing internal files, modifying data, transferring documents, or executing system operations.

This creates a new security challenge. An AI agent may have legitimate credentials and valid permissions while still performing an unsafe action. This may occur because of prompt injection, goal hijacking, compromised credentials, malicious external content, incorrect reasoning, excessive privileges, or changes in the organization's broader cybersecurity environment.

Traditional access-control systems usually make authorization decisions based primarily on identity and predefined permissions. However, permissions that are appropriate during normal business operations may become dangerous during an active cybersecurity incident.

For example, a finance agent may normally be authorized to read internal financial documents, transfer files, generate reports, and communicate with other systems. If the organization suddenly begins experiencing abnormal IP connections, suspicious credential activity, destructive operations, or a large-scale cyberattack, continuing to allow the finance agent to operate normally could increase the organization's attack surface.

At the same time, completely shutting down all AI agents may unnecessarily disrupt legitimate business operations. Different departments have different levels of operational importance and data sensitivity during a cybersecurity incident. A cybersecurity agent may need additional visibility and incident-response capabilities, while a marketing agent may still be able to perform low-risk public-facing work but should lose access to internal resources. A finance agent may need to stop most proactive operations entirely.

This project proposes a **Dynamic Security Indicator (DSI)** that represents the current security condition of an organization. The DSI is calculated using enterprise security signals such as abnormal network connections, unknown operations, destructive activity, security alerts, and administrator-declared emergencies.

The DSI is then integrated into a Zero Trust authorization system for AI agents.

Instead of making access decisions only based on static identity and permissions, the proposed system considers:

* Agent identity
* Department
* Delegated permissions
* Action sensitivity
* Current enterprise security level
* Internal-resource requirements
* File-transfer behavior
* Administrator emergency status
* Source-machine risk and quarantine state
* Target-machine risk, quarantine state, and business criticality
* Development, test, or production environment
* Resource sensitivity
* Sandbox isolation, execution privileges, and network access
* Authenticated mock identity, session validity, revocation, and user-to-agent delegation
* Explicit task scope, allowed tools, exact resources/targets, and parameter constraints
* Provenance of the authorizing instruction and external data
* Human approver authority, approval expiry, and consistency with the executed call

Machine and resource sensitivity are distinct from current threat conditions: a healthy production database may still be highly sensitive, while a single compromised agent runner should trigger restrictions even when enterprise-wide DSI is low. The prototype now represents these local factors separately and applies explicit blocks or approval requirements. It uses simulated context rather than live device telemetry or authenticated asset inventory.

The prototype also introduces a **Security Epoch** mechanism. When the enterprise security level changes, the Security Epoch changes and previously issued authorizations become stale. A separate **Environment Epoch** changes whenever the source, target, resource, or execution context changes within a policy-engine instance. Plans record both versions and the environment snapshot. AI agents must then re-evaluate remaining actions before execution, including when local machine risk changes without changing the enterprise DSI.

This creates a form of continuous authorization in which previously valid permissions are not automatically trusted after the security environment changes.

The main research question is:

**How can dynamic enterprise security conditions be integrated into Zero Trust authorization for autonomous AI agents so that permissions adapt in real time as organizational threat levels change?**

A related experimental question is:

**Can DSI-driven adaptive authorization reduce harmful AI-agent actions during cybersecurity incidents while preserving legitimate low-risk business operations?**

The complete local prototype validates issuer-owned mock sessions and user-to-agent delegation, task-specific grants, registered tool arguments and resources, input provenance, department, delegated permissions, action sensitivity, enterprise security conditions, and machine/resource/execution context. It returns one of four possible authorization decisions:

* ALLOW
* REQUIRE HUMAN APPROVAL
* BLOCK
* REEVALUATE

Pending approval requires an authorized human identity and binds to the exact call and its security context. Approved or directly allowed calls receive short-lived, one-use opaque permits. Before invoking a local stub tool, the runtime checks identity, task, arguments, resources, policy state, and approval validity again. A replay or substituted call cannot reuse the permit. Real identity authentication, telemetry attestation, tool isolation, remote execution, and semantic understanding of whether an action fulfills the user's purpose remain outside the demo; purpose is enforced through explicitly configured task constraints.

Future experiments could compare static access control, traditional Zero Trust authorization, and DSI-driven adaptive authorization under simulated agent attacks and enterprise security incidents.

Potential evaluation metrics include attack success rate, unauthorized action rate, data leakage rate, legitimate task completion rate, false blocking rate, human approval frequency, and system response latency.

The broader goal of this research is to explore how enterprises can safely use increasingly autonomous AI agents while maintaining security, accountability, and operational usefulness.

The [factor inventory and brainstorm](model_factors.md) distinguish implemented decision inputs, audit-only metadata, and candidate extensions. The immediate evaluation can also compare DSI-only authorization against DSI plus environment controls to measure whether local context improves outcomes without excessive blocking.
