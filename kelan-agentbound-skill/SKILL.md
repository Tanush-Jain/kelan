---
name: agentbound-monitoring
description: Monitor agent execution behavior, flag unauthorized file access or process spawns outside declared scope, and generate audit reports using Kelan AgentBound eBPF probes.
tags:
  - security
  - agent-monitoring
  - ebpf
---

# AgentBound Security & Behavior Monitoring Skill

Use this skill whenever a user requests to monitor, inspect, or audit an AI agent's execution behavior (e.g., *"is my agent behaving?"*, *"check what my agent has been doing"*, *"audit agent PID 1234"*).

## Workflow Instructions

1. **Start Monitoring Session**:
   Call `start_monitoring(agent_pid_or_name="<PID or name>")` to attach sentinel eBPF probes to the target agent process.
   Note the returned `session_id` and declared scope paths.

2. **Retrieve Behavioral Divergence Events**:
   Call `get_divergence_events(session_id="<session_id>")` to pull recent kernel file access, network connection, and process execution events correlated against the agent's declared scope.

3. **Retrieve Aggregate Session Summary (Optional)**:
   Call `get_session_summary(session_id="<session_id>")` to view daily rollup statistics for the monitored agent.

4. **Plain Language Report & Citation Rules**:
   - Explain all findings in clear, natural language.
   - **MUST** cite specific file paths (e.g., `/etc/shadow`, `~/.ssh/id_rsa`), network endpoints, and exact confidence scores (e.g., `0.95`) returned by the tools.
   - **CRITICAL**: Never fabricate, hallucinate, or assume a security finding if the tool returns zero divergence events. If no divergence is detected, state clearly that the agent is operating within declared scope.

5. **Stop Monitoring**:
   Call `stop_monitoring(session_id="<session_id>")` when auditing is complete.
