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

The prototype also introduces a **Security Epoch** mechanism. When the enterprise security environment changes significantly, the Security Epoch changes and previously issued authorizations become stale. AI agents must then re-evaluate remaining actions before execution.

This creates a form of continuous authorization in which previously valid permissions are not automatically trusted after the security environment changes.

The main research question is:

**How can dynamic enterprise security conditions be integrated into Zero Trust authorization for autonomous AI agents so that permissions adapt in real time as organizational threat levels change?**

A related experimental question is:

**Can DSI-driven adaptive authorization reduce harmful AI-agent actions during cybersecurity incidents while preserving legitimate low-risk business operations?**

The initial prototype compares agent identity, department, action sensitivity, and dynamic enterprise security conditions before returning one of four possible authorization decisions:

* ALLOW
* REQUIRE HUMAN APPROVAL
* BLOCK
* REEVALUATE

Future experiments could compare static access control, traditional Zero Trust authorization, and DSI-driven adaptive authorization under simulated agent attacks and enterprise security incidents.

Potential evaluation metrics include attack success rate, unauthorized action rate, data leakage rate, legitimate task completion rate, false blocking rate, human approval frequency, and system response latency.

The broader goal of this research is to explore how enterprises can safely use increasingly autonomous AI agents while maintaining security, accountability, and operational usefulness.
