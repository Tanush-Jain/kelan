# Kelan Security — AITP

<div align="center">

<img src="docs/assets/kelan-banner.png" alt="Kelan Security" width="600" />

**Adaptive Intent Transport Protocol**  
*Zero-Trust Network Security with Local AI + eBPF Enforcement*

[![CI](https://github.com/Kelan-Security/kelan-core/actions/workflows/ci.yml/badge.svg)](https://github.com/Kelan-Security/kelan-core/actions/workflows/ci.yml)
[![Security Audit](https://github.com/Kelan-Security/kelan-core/actions/workflows/ci.yml/badge.svg?event=push)](https://github.com/Kelan-Security/kelan-core/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/Rust-1.77+-orange.svg)](https://www.rust-lang.org)
[![Python](https://img.shields.io/badge/Python-3.10--3.12-blue.svg)](https://python.org)
[![Ollama](https://img.shields.io/badge/AI-Ollama%20%2B%20Gemma-green.svg)](https://ollama.com)

[**Quick Start**](#quick-start) · [**Architecture**](#architecture) · [**Docs**](docs/) · [**Contributing**](docs/CONTRIBUTING.md)

</div>

---

## What is Kelan?

Kelan is an open-source **zero-trust security layer** that runs entirely on your infrastructure. It combines:

- **eBPF/XDP kernel enforcement** (Rust) — packet-level traffic control at line rate, no kernel modules
- **Local AI trust evaluation** (Python + Ollama) — every connection scored by a local LLM, no cloud calls
- **Post-quantum cryptography** — ML-KEM-768 + Ed25519 + X25519 handshakes
- **AITP protocol** — Adaptive Intent Transport Protocol, session-aware trust scoring

**Nothing leaves your network. No SaaS. No telemetry. Your keys, your data.**

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    KELAN SECURITY STACK                  │
│                                                          │
│  ┌─────────────┐    ┌──────────────┐    ┌────────────┐  │
│  │  eBPF/XDP   │    │  AI Trust    │    │  AITP      │  │
│  │  Enforcer   │◄──►│  Evaluator   │◄──►│  Protocol  │  │
│  │  (Rust)     │    │  (Ollama)    │    │  Server    │  │
│  └─────────────┘    └──────────────┘    └────────────┘  │
│         │                  │                  │          │
│  Kernel XDP           Local LLM          FastAPI +       │
│  packet filter        (gemma3)           SQLite          │
│  (no kernel mod)      no cloud           port 3000       │
└─────────────────────────────────────────────────────────┘
```

**Key properties:**
- Kernel-level enforcement — can't be bypassed by userspace processes
- Local-only AI — zero external API calls, works air-gapped
- Post-quantum ready — safe against Harvest Now, Decrypt Later attacks
- Session-aware — trust scores evolve over connection lifetime

---

## Quick Start

### Prerequisites

| Requirement | Version | Install |
|-------------|---------|---------|
| Python | 3.10–3.12 | `brew install python@3.12` |
| Rust | 1.77+ | `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \| sh` |
| Ollama | Latest | `brew install ollama` |
| Linux kernel | 5.10+ (for eBPF) | Required for enforcement node |

### Install (one command)

```bash
git clone https://github.com/Kelan-Security/kelan-core.git
cd kelan-core
bash install.sh
```

This sets up your Python venv, installs all dependencies, builds Rust components, and verifies Ollama.

### Configure

```bash
cp .env.example .env
# Edit .env — set OLLAMA_HOST if Ollama runs on a different machine
```

### Launch

```bash
bash launch.sh          # development mode
bash launch.sh --prod   # production (Docker Compose)
bash launch.sh --stop   # stop everything
```

Kelan starts on `http://localhost:3000`. Check `GET /health` to verify.

---

## Core Concepts

### AITP — Adaptive Intent Transport Protocol

Every network session goes through intent classification before data flows:

```
Client → AITP Handshake → AI Trust Score → [ALLOW / DENY / THROTTLE] → Session
```

Trust scores are computed locally using gemma3 running in Ollama. The model evaluates:
- Packet timing patterns
- Protocol anomalies
- Session history
- Behavioral fingerprinting

### eBPF/XDP Enforcement

The Rust layer attaches to your network interface at the XDP hook point — the earliest possible packet processing stage. Packets from untrusted sessions are dropped before they reach the kernel TCP stack.

```bash
# Attach enforcer to interface (requires root/CAP_NET_ADMIN)
sudo ./target/release/kelan-ebpf-loader --iface eth0
```

### Post-Quantum Crypto

Every AITP handshake uses:
- **ML-KEM-768** (CRYSTALS-Kyber) for key encapsulation
- **Ed25519** for authentication signatures
- **X25519** for ephemeral Diffie-Hellman

Safe against both current and future quantum adversaries.

---

## API Reference

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

### Session Status

```http
GET /api/v1/sessions/{session_id}
→ { "session_id": "...", "trust_score": 0.87, "packets": 142, "created_at": "..." }
```

Full API docs: [`docs/`](docs/) or run `bash launch.sh` and open `http://localhost:3000/docs`

---

## Attack Simulation

Test Kelan's detection with the included simulation scripts:

```bash
# Full attack simulation suite
bash scripts/simulate_attacks.sh

# Throttled (slower, easier to observe in logs)
bash scripts/simulate_attacks_throttled.sh
```

Simulates: port scans, SYN floods, protocol confusion attacks, behavioral anomalies.

---

## Deployment

### Development (local)

```bash
bash launch.sh
```

### Production (Docker)

```bash
docker-compose -f docker-compose.prod.yml up -d
```

### Production (systemd)

```bash
sudo cp kelan.service /etc/systemd/system/
sudo systemctl enable --now kelan
sudo systemctl status kelan
```

Full deployment guide: [`docs/PRODUCTION_DEPLOYMENT.md`](docs/PRODUCTION_DEPLOYMENT.md)

### Kali Linux (attack testing node)

See [`docs/KALI_MAC_CONNECTION_GUIDE.md`](docs/KALI_MAC_CONNECTION_GUIDE.md)

---

## Repository Structure

```
kelan-core/
├── install.sh                  ← Run once on fresh clone
├── launch.sh                   ← Daily driver: start/stop everything
│
├── kelan-ebpf/                 ← Rust: XDP/eBPF kernel programs
├── kelan-ebpf-loader/          ← Rust: userspace eBPF loader
│
├── src/ or kelan_server/       ← Python: FastAPI + AI trust evaluator
│   ├── main.py
│   ├── aitp/                   ← Protocol implementation
│   ├── ai/                     ← Ollama integration
│   └── crypto/                 ← PQ crypto layer
│
├── scripts/                    ← Internal shell scripts
│   ├── start.sh
│   ├── stop.sh
│   ├── start_all.sh
│   ├── simulate_attacks.sh
│   └── simulate_attacks_throttled.sh
│
├── docs/                       ← All documentation
│   ├── KALI_MAC_CONNECTION_GUIDE.md
│   ├── PRODUCTION_DEPLOYMENT.md
│   ├── CONTRIBUTING.md
│   └── ...
│
├── docker-compose.yml          ← Dev compose
├── docker-compose.prod.yml     ← Production compose
├── docker-compose.monitoring.yml ← Grafana/Prometheus
│
├── .env.example                ← Copy to .env and configure
└── README.md
```

---

## Security

Kelan is a security tool — we take its own security seriously.

- All secrets must be in `.env` (gitignored) — never hardcoded
- Pre-commit hooks block accidental secret commits
- GitHub Actions run TruffleHog on every push
- `cargo audit` + `pip-audit` run weekly via Dependabot

**Found a vulnerability?** Please do NOT open a public issue. Email `security@kelan.io` with:
- Description of the vulnerability
- Steps to reproduce
- Potential impact

We respond within 48 hours and will credit you in the release notes.

---

## Contributing

See [`docs/CONTRIBUTING.md`](docs/CONTRIBUTING.md) for the full guide.

**Quick version:**
1. Fork → branch (`git checkout -b feat/your-feature`)
2. Make changes → add tests
3. `cargo test && pytest` must pass
4. PR → we review within 72 hours

Areas we need help with:
- [ ] Windows Subsystem for Linux (WSL2) support
- [ ] Additional LLM backends (llama.cpp, vLLM)
- [ ] Grafana dashboard templates
- [ ] Kubernetes deployment manifests
- [ ] Integration tests

---

## Roadmap

| Version | Target | Focus |
|---------|--------|-------|
| v2.0 | Q3 2026 | Python rewrite, stable API, OSS launch |
| v2.1 | Q4 2026 | Kubernetes operator, multi-node |
| v2.2 | Q1 2027 | GUI dashboard, alert integrations |
| v3.0 | Q2 2027 | Distributed enforcement mesh |

---

## License

Kelan Core is licensed under the MIT License.
See the LICENSE file for details.

---

## IEEE Publication

Kelan's AITP protocol is the subject of a paper submitted to **IEEE CNS 2026**:

> *"AITP: Adaptive Intent Transport Protocol for Zero-Trust Network Security with Local AI Enforcement"*

Pre-print available after acceptance.

---

<div align="center">

Built with ❤️ by [Kelan Security](https://github.com/Kelan-Security)

⭐ Star us on GitHub if Kelan helps you — it directly helps the project grow

</div>