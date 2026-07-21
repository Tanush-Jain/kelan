# Kelan : AI Agent Security Platform

<div align="center">

[![CI](https://github.com/Tanush-Jain/kelan/actions/workflows/ci.yml/badge.svg)](https://github.com/Tanush-Jain/kelan/actions/workflows/ci.yml)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![eBPF](https://img.shields.io/badge/eBPF-XDP-orange.svg)](https://ebpf.io/)
[![ML-KEM-768](https://img.shields.io/badge/PQ_Crypto-ML--KEM--768-purple.svg)](https://csrc.nist.gov/Pubs/FIPS/203/final)
[![MCP](https://img.shields.io/badge/MCP-stdio-green.svg)](https://modelcontextprotocol.io)

**Agent behavior monitoring & security : powered by eBPF, local AI, and post-quantum crypto.**

[**Quick Start**](#quick-start) · [**AgentBound**](#kelan-agentbound) · [**Architecture**](#architecture) · [**MCP Plugin**](#mcp--claude-code-plugin) · [**Docs**](docs/) · [**Contributing**](docs/CONTRIBUTING.md)

</div>

---

## What is Kelan?

Kelan is an open-source **AI agent security platform** that runs entirely on your own infrastructure. It monitors what AI agents actually do at the kernel level : file access, network connections, process spawns : and flags anything that falls outside the agent's declared scope.

Two integrated layers:

| Layer | What it does |
|---|---|
| **Kelan AgentBound** | eBPF probes watch any running agent (Claude Code, Cursor, Aider, Codex…) and correlate kernel events against the agent's declared intent using a local LLM |
| **Kelan Core** | Zero-trust network enforcement : ML-KEM-768 post-quantum handshakes, XDP packet-level control, local AI trust scoring for every connection |

**Nothing leaves your machine. No SaaS. No telemetry by default. Your keys, your data.**

---

## Kelan AgentBound

AgentBound is Kelan's **monitor-only** AI agent security layer. It answers one question in real time:

> *Is my AI agent doing what it said it would do?*

### How it works

```
Agent process (Claude, Cursor, Aider…)
        │
        ▼ eBPF probes (openat, connect, execve)
┌───────────────────────────────────────────────┐
│              SentinelDetector                  │
│  kernel event → kind + details + timestamp     │
└───────────────────┬───────────────────────────┘
                    │
        ┌───────────▼────────────┐
        │     IntentExtractor     │
        │  /proc/<pid>/environ    │
        │  .claude/ CLAUDE.md     │
        │  → declared_paths       │
        │  → agent_type           │
        └───────────┬────────────┘
                    │
        ┌───────────▼────────────┐
        │   HybridCorrelation     │
        │   Engine (Ollama +      │
        │   local skill library)  │
        │  → in_scope? reason     │
        │    confidence           │
        └───────────┬────────────┘
                    │
        ┌───────────▼────────────┐
        │  Hash-chained JSONL     │
        │  audit log              │
        │  + live terminal table  │
        └────────────────────────┘
```

### Run it

```bash
# Monitor all detected agent processes
kelan bound

# Target a specific PID
kelan bound --pid 4392

# One-shot snapshot + exit
kelan bound --once

# Generate EU AI Act compliance export
kelan bound --export-compliance

# Opt in to sharing anonymized daily statistics
kelan bound --share-stats
```

Live output:

```
PID      | AGENT TYPE      | LAST ACTION                    | IN-SCOPE?  | REASON
---------|-----------------|--------------------------------|------------|-------
4392     | claude-code     | file_access:/etc/ssh/config    | NO (FLAGGED)| restricted_sensitive_path
4392     | claude-code     | network_connect:api.openai.com | YES        | within declared network scope
```

Every event is appended to `agentbound_audit.jsonl` with SHA-256 hash-chaining for tamper detection.

### What it monitors

| Probe | Kernel hook | What it catches |
|---|---|---|
| `openat` / `open` | file access | reads to `~/.ssh/`, `~/.aws/`, `/etc/shadow`, paths outside declared scope |
| `connect` | network | connections to hosts outside the agent's declared network scope |
| `execve` | process spawn | subprocesses the agent wasn't declared to run |

### Compliance export

```bash
kelan bound --export-compliance
# → agentbound_compliance_export.json
# → agentbound_compliance_export.md
```

Produces an **EU AI Act Article 12**-aligned document: total sessions monitored, divergence event breakdown, hash-chain integrity status, and per-category statistics.

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                         KELAN PLATFORM                            │
│                                                                    │
│  ┌──────────────────────────────────┐   ┌──────────────────────┐  │
│  │        AgentBound Layer           │   │    Core Network      │  │
│  │                                   │   │    Security Layer    │  │
│  │  eBPF Probes → SentinelDetector   │   │                      │  │
│  │  IntentExtractor (/proc)          │   │  eBPF/XDP Enforcer   │  │
│  │  HybridCorrelationEngine          │   │  (Rust, line-rate)   │  │
│  │  BehaviorIndex (opt-in stats)     │   │                      │  │
│  │  ComplianceExport (EU AI Act)     │   │  AI Trust Evaluator  │  │
│  │  MCP Server (stdio transport)     │   │  (Ollama, local)     │  │
│  └──────────────────────────────────┘   │                      │  │
│                                          │  PQ Crypto           │  │
│  Exposed as MCP tools to any agent:      │  ML-KEM-768          │  │
│  start_monitoring · get_divergence_events│  Ed25519 · X25519    │  │
│  get_session_summary · stop_monitoring   └──────────────────────┘  │
└──────────────────────────────────────────────────────────────────┘
```

**Key properties:**
- **Kernel-level visibility** : eBPF probes can't be bypassed by the agent being monitored
- **Local AI only** : Ollama (gemma3 or compatible) runs on your machine; no external API calls
- **Post-quantum ready** : ML-KEM-768 + Ed25519 + X25519 handshakes, safe against harvest-now-decrypt-later
- **Monitor-only by default** : AgentBound never blocks, kills, or throttles. Observe first.

---

## MCP & Claude Code Plugin

Kelan AgentBound ships as a **standalone MCP server** (stdio transport). Any MCP-capable host can invoke it without modification.

### Install in Claude Code

```bash
/plugin marketplace add https://github.com/Tanush-Jain/kelan.git
/plugin install kelan-agentbound@kelan-agentbound
```

### Available MCP tools

| Tool | What it does |
|---|---|
| `start_monitoring(agent_pid_or_name)` | Attach eBPF probes; returns `session_id` |
| `get_divergence_events(session_id)` | Return classified events since last call |
| `get_session_summary(session_id)` | Aggregate stats for the session |
| `stop_monitoring(session_id)` | Detach probes, close session |

### Supported hosts

| Host | Manifest location |
|---|---|
| Claude Code | [`kelan-agentbound-plugin/`](kelan-agentbound-plugin/) |
| Gemini CLI | [`gemini-extension.json`](gemini-extension.json) |
| Antigravity | [`plugins/kelan-agentbound/`](plugins/kelan-agentbound/) |
| Grok Build | [`grok-plugin/`](grok-plugin/) |
| ChatGPT / Codex | See [`docs/chatgpt-submission.md`](docs/chatgpt-submission.md) |

All five manifests point at the same `kelan-agentbound-mcp/server.py` and `kelan-agentbound-skill/SKILL.md` : no duplication.

---

## Quick Start

### Prerequisites

| Requirement | Version | Notes |
|---|---|---|
| Python | 3.10:3.12 | `brew install python@3.12` |
| Rust | 1.77+ | `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \| sh` |
| Ollama | Latest | `brew install ollama` |
| Linux kernel | 5.10+ | Required for eBPF probes |

### Install

```bash
git clone https://github.com/Tanush-Jain/kelan.git
cd Kelan
bash install.sh
```

Sets up Python venv, installs all dependencies, builds Rust components, and verifies Ollama.

### Configure

```bash
cp .env.example .env
# Edit .env : set OLLAMA_HOST if Ollama runs on a different machine
```

### Launch

```bash
bash launch.sh          # development mode
bash launch.sh --prod   # production (Docker Compose)
bash launch.sh --stop   # stop everything
```

Core API starts on `http://localhost:3000`. Verify with `GET /health`.

---

## Core Network Security API

### Health

```http
GET /health
→ { "status": "ok", "version": "2.0.0", "ollama": "connected" }
```

### Trust Evaluation

```http
POST /api/v1/evaluate
Content-Type: application/json

{
  "session_id": "abc123",
  "client_ip": "10.0.0.5",
  "protocol": "tcp",
  "payload_hash": "sha256:..."
}

→ {
  "trust_score": 0.87,
  "decision": "allow",
  "reasoning": "Normal behavioral pattern, known session"
}
```

Full API docs: run `bash launch.sh` and open `http://localhost:3000/docs`

---

## Repository Structure

```
Kelan/
├── install.sh                        ← Run once on fresh clone
├── launch.sh                         ← Start / stop everything
│
├── kelan/                            ← Core Python package
│   ├── agentbound/                   ← AgentBound monitoring layer
│   │   ├── cli.py                    ← `kelan bound` entry point
│   │   ├── intent_extractor.py       ← /proc environ + scope extraction
│   │   ├── behavior_engine.py        ← LLM correlation engine
│   │   ├── behavior_index.py         ← Opt-in anonymized statistics
│   │   ├── compliance_export.py      ← EU AI Act export
│   │   └── skill_loader.py           ← 754-skill security library loader
│   ├── sentinel/
│   │   └── detector.py               ← eBPF event receiver & classifier
│   ├── protocol/                     ← Post-quantum handshake (ML-KEM-768)
│   └── ai/                           ← Ollama client + hybrid engine
│
├── kelan-agentbound-mcp/
│   └── server.py                     ← Standalone MCP server (stdio)
│
├── kelan-agentbound-skill/
│   └── SKILL.md                      ← Canonical agent skill definition
│
├── kelan-agentbound-plugin/          ← Claude Code plugin
│   ├── .claude-plugin/
│   │   ├── plugin.json
│   │   └── marketplace.json
│   └── plugin/
│       ├── skills/                   ← symlink → kelan-agentbound-skill/
│       ├── agents/
│       ├── hooks/
│       └── mcp/                      ← symlink → kelan-agentbound-mcp/
│
├── plugins/kelan-agentbound/         ← Antigravity plugin
├── gemini-extension.json             ← Gemini CLI extension
├── grok-plugin/                      ← Grok Build plugin
│
├── kelan-ebpf/                       ← Rust: XDP/eBPF kernel programs
├── kelan-ebpf-loader/                ← Rust: userspace eBPF loader
│
├── docs/
│   ├── chatgpt-submission.md         ← ChatGPT / Codex submission guide
│   ├── PRODUCTION_DEPLOYMENT.md
│   └── CONTRIBUTING.md
│
├── docker-compose.yml                ← Dev compose
├── docker-compose.prod.yml           ← Production compose
└── .env.example                      ← Copy to .env and configure
```

---

## Attack Simulation

```bash
# Full suite: port scans, SYN floods, protocol confusion, behavioral anomalies
bash scripts/simulate_attacks.sh

# Throttled : easier to observe in logs
bash scripts/simulate_attacks_throttled.sh
```

---

## Security

Found a vulnerability? **Do not open a public issue.**  
Email `kernalsecurity@gmail.com` with:
- Description of the vulnerability
- Steps to reproduce
- Potential impact

We respond within 48 hours and credit reporters in release notes.

All secrets must be in `.env` (gitignored). Pre-commit hooks block accidental secret commits. GitHub Actions run TruffleHog and `pip-audit` on every push.

---

## Contributing

See [`docs/CONTRIBUTING.md`](docs/CONTRIBUTING.md) for the full guide.

```bash
# Quick version
git checkout -b feat/your-feature
# make changes, add tests
cargo test && pytest   # both must pass
# open PR
```

Areas we need help with:
- [ ] Windows / WSL2 support for AgentBound
- [ ] Additional LLM backends (llama.cpp, vLLM)
- [ ] Grafana dashboard templates for agent behavior metrics
- [ ] Kubernetes deployment manifests
- [ ] Integration tests for the MCP server

---

## Roadmap

| Version | Target | Focus |
|---|---|---|
| v0.1 | Q3 2026 | AgentBound MVP : monitor-only, MCP server, 5-platform distribution |
| v0.2 | Q4 2026 | Agent Behavior Index public dashboard, Kubernetes operator |
| v0.3 | Q1 2027 | GUI dashboard, alert integrations (PagerDuty, Slack) |
| v1.0 | Q2 2027 | Distributed enforcement mesh, LSM enforcement mode |

---

## License

Licensed under the **Apache License 2.0**.  
Copyright 2026 Tanush Jain : see [LICENSE](LICENSE) for details.

---

<div align="center">

Built by [Tanush Jain](https://github.com/Tanush-Jain) · [kernalsecurity@gmail.com](mailto:kernalsecurity@gmail.com)

⭐ Star the repo if Kelan helps you : it directly supports the project

</div>
