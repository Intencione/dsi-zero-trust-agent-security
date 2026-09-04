# AI Agent Security & Zero Trust Demo

This repository contains an early-stage demonstration of applying Zero Trust security principles to AI agents.

The main idea is that an AI agent should not automatically be trusted simply because it is authorized to perform a task. Every sensitive tool call should be evaluated based on the agent's identity, delegated permissions, requested action, risk level, as well as dynamic security environment.

## Current Demo

The current prototype includes:

* A simple AI-agent-style task planner
* Multiple simulated tools
* Agent identity
* Permission checking
* Least-privilege access control
* Runtime policy enforcement
* Human approval for high-risk actions
* Basic audit logging
* Dynamic security indicator

The current agent does not yet use a real LLM. A simple rule-based planner is used so that the initial security architecture can be tested independently from model behavior.

## Research Direction

The broader research question is:

**How can Zero Trust principles be adapted to secure autonomous AI agents that interact with external tools, enterprise data, and real-world systems?**

Future versions may integrate an LLM, more complex tool environments, prompt-injection attacks, dynamic permissions, and security benchmarks.
