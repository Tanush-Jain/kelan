# 🛡️ Kelan: The Privacy-First, AI-Native Security Platform

> **100% Local-First Application Security Testing (SAST, DAST, SCA) & Offline Threat Intelligence.**  
> *Zero code leakage. Zero cloud telemetry. Zero unverified claims.*

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-3776AB.svg?logo=python&logoColor=white)](https://www.python.org/)
[![Cross-Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows-555555.svg)](docs/WINDOWS.md)
[![Air-Gapped LLM](https://img.shields.io/badge/LLM-Local%20Ollama%20(Gemma%2FQwen)-00B4D8.svg)](https://ollama.ai/)
[![Docker GHCR](https://img.shields.io/badge/Docker-GHCR%20Validated-2496ED.svg?logo=docker&logoColor=white)](Dockerfile)
[![Test Suite](https://img.shields.io/badge/tests-111%20passing%20%7C%2071%25%20coverage-success.svg)](kelan/tests)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## 💡 Why Kelan?

Traditional application security tools force an unacceptable tradeoff: **upload your proprietary source code and API traffic to third-party cloud servers**, or settle for brittle regex-based linters that flood developers with false positives.

**Kelan changes this paradigm.** Built for security engineers, solo developers, and high-compliance teams, Kelan runs **100% on your machine**:
* 🔒 **Zero Code or Network Leakage**: All AST parsing, web crawling, and LLM reasoning run locally via Ollama. No source code or scan telemetry ever leaves your environment.
* 🧠 **Semantic AST Awareness**: Analyzes full syntactic functions and classes using Tree-sitter across Python, JavaScript, TypeScript, and Solidity—eliminating arbitrary token window slicing.
* 🎯 **Deterministic Precision + AI Reasoning**: Deterministic baseline rules catch critical vulnerabilities (SQLi, cmd injection, path traversal) instantly, while local LLMs explain root causes and generate precise patches.
* ⚡ **Offline Threat Intelligence**: Includes an embedded SQLite FTS5 database that synchronizes CISA KEV exploits, EPSS daily scores, OSV.dev, and NVD CVEs for instant, air-gapped vulnerability lookups.
* 📊 **Zero-BS Local Dashboard**: A real-time React UI on `localhost:7681` showing live evidence and code snippets without fake animations or `Math.random()` metrics.

---

## 🏛️ Kelan Community Architecture & Capabilities

Kelan Community serves as the open-source wedge—giving you professional-grade security analysis without altering your operating system kernel:

| Feature | Description & Implementation Details | Automated Verification |
| :--- | :--- | :--- |
| **Audit-Only Mode** | Strictly open-source audit mode. Identifies vulnerabilities and explains them with zero capability to modify the kernel or block traffic. All kernel hooks, eBPF loaders, and permit/revoke endpoints are cleanly isolated from Community. | [`test_community_has_zero_pro_imports`](file:///kelan/tests/unit/test_no_pro_imports.py)<br>[`test_community_rejects_permit_revoke_endpoints`](file:///kelan/tests/unit/test_community_api.py) |
| **Semantic SAST Engine** | Tree-sitter AST parsing across Python, JavaScript, TypeScript, and Solidity with deterministic baseline rules (SQLi, command injection, path traversal, hardcoded secrets, XSS) and graceful degradation when Ollama is offline. | [`test_sast_deterministic.py`](file:///kelan/tests/unit/test_sast_deterministic.py) |
| **Active DAST Crawler** | Asynchronous payload engine with 34 encoding-bypass probe variants (raw, HTML entity, double-encoding, comment break, null-byte) and deterministic evidence graders. | [`test_dast_pipeline.py`](file:///kelan/tests/unit/test_dast_pipeline.py) |
| **Local Intelligence Library** | Offline SQLite store with FTS5 search (`kelan/intel/db.py`) syncing CISA KEV, EPSS daily scores, OSV.dev bulk data, GHSA, and NVD CVE API 2.0. Air-gapped Ed25519-signed bundle import/export (`kelan export-bundle`, `kelan update --offline-bundle`). | [`test_intel.py`](file:///kelan/tests/unit/test_intel.py) |
| **Air-Gapped LLM Triage** | Local orchestration via Ollama/Gemma (`kelan/ai/ollama_client.py`) for exploit reasoning and patch generation on reachable findings. Strictly local-first: zero network calls during scans unless explicitly enabled via `--online`. | [`test_ollama_client.py`](file:///kelan/tests/unit/test_ollama_client.py)<br>[`test_sca_local_first_network_disabled`](file:///kelan/tests/unit/test_plugin_framework.py) |
| **Local React Dashboard** | Standalone web UI served on `localhost:7681` (`kelan --dashboard`), featuring live scan timeline, findings severity filters, and Reasoning View showing code evidence alongside LLM explanation. Canned logs and `Math.random()` simulators removed. Process tracked with clean shutdown. | [`test_dashboard_not_launched_by_default`](file:///kelan/tests/unit/test_cli_menu.py)<br>[`test_dashboard_launched_and_stopped_with_flag`](file:///kelan/tests/unit/test_cli_menu.py) |
| **Windows & macOS Support** | Native cross-platform execution. Hardware-specific dependencies (`scapy`, `netifaces`) isolated into optional extra `[recon]`. Includes `kelan setup` wizard (system checks, disk space, Ollama detection, model pulling, optional daily task scheduler) and PyInstaller/Inno Setup packaging specs. | [`test_windows_packaging.py`](file:///kelan/tests/unit/test_windows_packaging.py) |

---

## ⚡ Quickstart: Clone to First Scan in 5 Minutes

### 🍎 macOS & 🐧 Linux

```bash
# 1. Clone the repository
git clone https://github.com/Tanush-Jain/kelan.git
cd kelan

# 2. Set up virtual environment & install Kelan
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -e .

# 3. Verify environment readiness
kelan doctor

# 4. Run an instant code security audit
kelan scan --target .
```

### 🪟 Windows 10/11 x64

Install via the standalone Inno Setup package (`KelanSetup.exe`) or via PowerShell:

```powershell
# Run the automated installer script
.\scripts\install.ps1

# Run the interactive configuration wizard
kelan setup

# Audit your project
kelan scan --target .
```
> See [docs/WINDOWS.md](docs/WINDOWS.md) for full Windows installation, code signing, and packaging guidelines.

### 🐳 Docker Container

Run Kelan directly in an isolated container without local Python dependencies:

```bash
# List available plugins
docker run --rm ghcr.io/tanush-jain/kelan:latest --plugins

# Scan current workspace mounted into container
docker run --rm -v $(pwd):/workspace ghcr.io/tanush-jain/kelan:latest scan --target /workspace

# Launch the full dashboard environment
docker compose -f deploy/docker-compose.yml up -d
```

---

## 🏗 System Architecture

```text
                               +-----------------------------------+
                               |        KELAN COMMUNITY CLI        |
                               |    (kelan scan / dast / intel)    |
                               +-----------------+-----------------+
                                                 |
         +---------------------------------------+---------------------------------------+
         |                                       |                                       |
         v                                       v                                       v
+------------------+                    +------------------+                    +------------------+
|   SAST Engine    |                    |   DAST Crawler   |                    | Offline Intel    |
| (Tree-sitter AST |                    |  (Async Crawler  |                    |  (SQLite + FTS5  |
|  + Baseline)     |                    |  + 34 Bypasses)  |                    |  CVE/EPSS/KEV)   |
+--------+---------+                    +--------+---------+                    +--------+---------+
         |                                       |                                       |
         +-------------------+-------------------+---------------------------------------+
                             |
                             v
               +---------------------------+
               |  Air-Gapped LLM Triage    |
               | (Local Ollama Orchestrator|
               |   qwen2.5-coder / gemma)  |
               +-------------+-------------+
                             |
                             v
               +---------------------------+
               |  Local React Dashboard    |
               |     (localhost:7681)      |
               | Timeline + Reasoning View |
               +---------------------------+
```

---

## 🔍 Core Engines in Depth

### 1. Semantic SAST (`kelan scan`)
* **Scope-Aware AST Parsing**: Uses Tree-sitter grammars to map whole code structures instead of crude line chunks.
* **Deterministic Baseline Rules**: Zero-dependency syntax analysis detects SQL injection, command execution, path traversal, and hardcoded credentials instantly.
* **Ollama Explanation & Remediation**: Reachable vulnerabilities are passed to local models (`qwen2.5-coder`, `gemma`) to construct verified remediation code snippets.

### 2. Active DAST Crawler (`kelan dast`)
* **Asynchronous Spider**: Automatically discovers endpoints, forms, hidden query parameters, and headers.
* **34 Encoding Bypass Variants**: Generates realistic attack payloads using double-URL encoding, HTML entities, nested comments, and null-byte terminators.
* **Heuristic Evidence Verification**: Evaluates responses deterministically by matching database exception signatures, unencoded marker reflections, and echo tokens.

### 3. Threat Intelligence Library (`kelan intel`)
* **Local SQLite FTS5 Engine**: Millisecond searches across millions of vulnerability records without internet access.
* **Daily Feed Synchronization (`kelan update`)**: Incremental updates with rate limiting, ETag caching, and exponential backoff from CISA KEV, FIRST EPSS, OSV.dev, and NVD.
* **Air-Gapped Bundles**: Export and import cryptographically signed archives (`kelan export-bundle` / `kelan update --offline-bundle`) verified using embedded Ed25519 public keys.

### 4. Local React Dashboard (`kelan --dashboard`)
* Served natively on `http://localhost:7681`.
* **Reasoning View**: Side-by-side inspection of vulnerable source code evidence and AI explanation.
* **Live Timeline**: Real-time scan progression and findings categorization.
* **Clean Shutdown**: Automatic background process management with zero orphan servers.

---

## 🛠 Command Reference

### Interactive Menu
```bash
kelan
```

### Static Application Security Testing (SAST)
```bash
# Scan specific directory with concurrency limit
kelan scan --target src/ --limit 20 --model qwen2.5-coder:latest

# Full repository audit with JSON report
kelan scan --target . --no-limit --json sast-report.json
```

| Flag | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `--target` | `path` | `.` | Target directory to audit |
| `--limit` | `int` | `10` | Maximum AST chunks to analyze (`0` for all) |
| `--model` | `string` | `qwen2.5-coder:latest` | Local Ollama model name |
| `--concurrency` | `int` | `2` | Parallel chunk evaluation workers |
| `--timeout` | `float` | `180.0` | Per-chunk evaluation timeout in seconds |
| `--json` | `path` | `None` | Path to save JSON report |
| `--no-limit` | `flag` | `False` | Scan every AST chunk without truncation |

### Dynamic Application Security Testing (DAST)
```bash
# Crawl local web service and test for bypass variants
kelan dast --target http://localhost:8080 --crawl --bypass --json dast-report.json

# Run deterministic checks with strict CI exit gate
kelan dast --target http://localhost:8080 --no-llm --ci-gate high
```

| Flag | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `--target` | `url` | *Required* | Seed URL to test |
| `--crawl` | `flag` | `False` | Spider origin-scoped links before probing |
| `--bypass` | `flag` | `False` | Enable 34 encoding-bypass probe variants |
| `--vectors` | `string` | `xss,sqli,cmdi,traversal,ssti` | Comma-separated vulnerability families |
| `--ci-gate` | `string` | `None` | Fail build with non-zero exit on threshold (`critical`, `high`) |
| `--no-llm` | `flag` | `False` | Run deterministic heuristic evaluation only |

### Intelligence Commands
```bash
# Update local vulnerability database from CISA, EPSS, OSV, and NVD
kelan update

# Search local database for an advisory or package
kelan intel search CVE-2024-21626

# Display newly added CISA KEV exploits and 7-day EPSS risers
kelan intel trending

# Export signed air-gapped bundle
kelan export-bundle --output kelan-intel.zip
```

---

## 🧪 Verification & System Health

The `kelan-core` codebase is continuously tested against strict quality and architectural constraints:

```bash
# 1. Run environment healthcheck
kelan doctor

# 2. Run automated test suite with coverage
pytest --cov=kelan --cov-config=pyproject.toml kelan/tests
```

* **Test Suite**: **111 unit & integration tests passing** in `2.76s`.
* **Code Coverage**: **71.14%** (exceeds the 50.0% CI gate threshold).
* **Static Import Isolation**: `test_no_pro_imports.py` guarantees zero proprietary Pro dependencies or kernel-altering modules are imported by the Community edition.
* **Code Quality**: Zero `ruff` lint errors and zero `mypy` typecheck errors across all 82 source files.

---

## 🏢 Community vs. Pro Edition

Kelan Community is built to prove AI reasoning and give developers a world-class audit wedge. For enterprises needing automated blocking and team coordination, **Kelan Pro** delivers active enforcement:

| Capability | Kelan Community (Open Source) | Kelan Pro (Commercial) |
| :--- | :---: | :---: |
| **Licensing** | MIT License | Commercial (Offline Ed25519 Signed) |
| **Execution Mode** | Audit-Only (Simulate & Explain) | Active Ring-0 Enforcement + Simulation |
| **SAST & DAST Scanning** | ✅ Full Tree-sitter & 34 Bypasses | ✅ Full Tree-sitter & 34 Bypasses |
| **Local Threat Intel** | ✅ Local SQLite (CISA KEV, EPSS, NVD) | ✅ Local SQLite + Pro Feed Ingestion |
| **Dashboard** | ✅ Standalone UI (`localhost:7681`) | ✅ Centralized Fleet Console + RBAC |
| **Kernel eBPF / XDP Filtering** | ❌ None (Isolated) | ✅ Line-rate XDP Packet Drop Engine |
| **Network Handshake** | ❌ None | ✅ Post-Quantum (ML-KEM-768 / Kyber) |
| **Approval Workflow** | ❌ None | ✅ Human-in-the-loop Rule Approval |
| **Append-Only Audit Log** | ❌ None | ✅ Cryptographic Audit Log |

> For enterprise licensing and proof-of-concept deployments, see [EDITIONS.md](EDITIONS.md).

---

## 🤝 Contributing

We welcome community contributions! Please read [CONTRIBUTING.md](docs/CONTRIBUTING.md) and [SECURITY.md](SECURITY.md) before submitting pull requests.

1. Fork the repo and create your branch from `main`.
2. Ensure all 111 tests pass (`pytest kelan/tests`).
3. Ensure linters pass cleanly (`ruff check .` and `mypy kelan/`).
4. Submit a descriptive Pull Request.

---

## 📜 License

Kelan Community is distributed under the **MIT License**. See [LICENSE](LICENSE) for details.
