# Kelan: AI-Native SAST/DAST & Zero-Trust Security Platform

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/)
[![Rust 2021](https://img.shields.io/badge/rust-2021-orange.svg)](https://www.rust-lang.org/)
[![eBPF Kernel Security](https://img.shields.io/badge/eBPF-Linux--Kernel-red.svg)](https://ebpf.io/)
[![Post-Quantum Cryptography](https://img.shields.io/badge/PQC-ML--KEM--768%20%7C%20Kyber-purple.svg)](https://csrc.nist.gov/projects/post-quantum-cryptography)
[![Ollama Powered](https://img.shields.io/badge/LLM-Ollama%20Local-green.svg)](https://ollama.ai/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**Kelan** is a privacy-first, local-first security platform combining AST-aware Static Application Security Testing (**SAST**), dynamic agentic vulnerability scanning (**DAST**), and a Post-Quantum Zero-Trust Network Shield powered by eBPF and ML-KEM-768.

By running entirely on local LLMs via Ollama, **Kelan ensures zero code or network telemetry ever leaves your environment**.

---

## 📑 Table of Contents

- [Key Features](#-key-features)
- [Architecture Overview](#-architecture-overview)
  - [1. SAST Engine (`kelan scan`)](#1-sast-engine-kelan-scan)
  - [2. DAST Engine (`kelan dast`)](#2-dast-engine-kelan-dast)
  - [3. Zero-Trust & Post-Quantum Shield](#3-zero-trust--post-quantum-shield)
- [Installation & Setup](#-installation--setup)
  - [System Requirements](#system-requirements)
  - [Environment Setup](#environment-setup)
  - [Local LLM Models](#local-llm-models)
- [CLI Reference & Usage](#-cli-reference--usage)
  - [Interactive Mode](#interactive-mode)
  - [SAST Command (`kelan scan`)](#sast-command-kelan-scan)
  - [DAST Command (`kelan dast`)](#dast-command-kelan-dast)
  - [CI/CD Integration](#cicd-integration)
- [Repository Structure](#-repository-structure)
- [Reporting Formats](#-reporting-formats)
  - [Terminal Report](#terminal-report)
  - [JSON Report Schema](#json-report-schema)
- [License](#-license)

---

## 🚀 Key Features

* **Zero Code Leakage**: Uses local Ollama models (`qwen2.5-coder`, `gemma4`) for vulnerability analysis. Proprietary code and dynamic payloads are never sent to external cloud APIs.
* **AST-Aware Semantic Chunker**: Parses multi-language source code (Python, JavaScript, TypeScript) using Tree-sitter into scope-aware code units (functions, classes) to bypass arbitrary token window limits.
* **Hybrid Deterministic + AI DAST**: Combines async web crawling, deterministic heuristic pattern matchers (SQL errors, reflected XSS, marker echo, header audits), and multi-family payload bypass suites with optional LLM summary generation.
* **WAF & Filter Bypass Suite**: Probes targets using 68+ payload variants across XSS, SQLi, Command Injection, Path Traversal, and SSTI (percent-encoding, double-encoding, HTML entities, Unicode, null-bytes, comment breaks).
* **Post-Quantum Network Enforcement**: Implements ML-KEM-768 (Kyber768) handshakes paired with eBPF kernel maps to enforce zero-trust network packet filtering at ring 0.
* **CI/CD Native**: Supports configurable severity thresholds (`--ci-gate high`) and structured JSON output for automated build pipeline failure and SIEM/dashboard ingestion.

---

## 🏗 Architecture Overview

```
                                +-----------------------------------+
                                |            KELAN CLI              |
                                |     (kelan scan / kelan dast)     |
                                +-----------------+-----------------+
                                                  |
                    +-----------------------------+-----------------------------+
                    |                                                           |
                    v                                                           v
       +-------------------------+                                 +-------------------------+
       |   SAST Pipeline         |                                 |   DAST Pipeline         |
       |   (kelan/scanner/)      |                                 |   (kelan/dast/)         |
       +------------+------------+                                 +------------+------------+
                    |                                                           |
      +-------------+-------------+                               +-------------+-------------+
      |                           |                               |                           |
      v                           v                               v                           v
+-----------+               +-----------+                   +-----------+               +-----------+
| Tree-     |               | Local     |                   | Async BFS |               | Heuristic |
| sitter    |               | Ollama    |                   | Crawler   |               | Evidence  |
| Chunker   |               | LLM       |                   | & Prober  |               | Grader    |
+-----------+               +-----------+                   +-----------+               +-----------+
                                                                                              |
                                                                                              v
                                                                                    +-------------------+
                                                                                    | Payload Bypass    |
                                                                                    | Engine (68+ sets) |
                                                                                    +-------------------+
```

### 1. SAST Engine (`kelan scan`)
* **Tree-Sitter Chunking**: Traverses codebases and extracts syntactically complete functions and classes instead of slicing raw lines.
* **Prompt Schema Enforcement**: Formats requests into structured JSON schemas (`SCANNER_JSON_SCHEMA`) enforcing root cause analysis and CWE mapping.
* **Strict Noise Reduction**: Instructs the model to dismiss code style or linting rules and focus exclusively on injection, state manipulation, logic bypass, and cryptographic flaws.

### 2. DAST Engine (`kelan dast`)
* **Async BFS Crawler**: Spiders origin-scoped HTML pages, identifying forms, input elements, hidden parameters, and URL query keys.
* **Bypass Probe Generator**: Generates encoding variants (raw, HTML entities, percent-encoding, double-encoding, comment breaking, null-byte injection).
* **Deterministic Graders**: Evaluates evidence without LLM hallucination:
  * **XSS**: Verifies unencoded reflection of payload markers in HTTP 200 responses.
  * **SQLi**: Matches SQL engine syntax and database exception strings.
  * **Command Injection**: Detects unique echo marker reflection in response bodies.
  * **Path Traversal**: Matches `/etc/passwd` or system file signatures.
  * **IDOR**: Measures structural response deltas across distinct resource IDs.
* **LLM Narrative Enrichment**: Optionally invokes Ollama to refine titles and remediation steps without altering underlying evidence or findings.

### 3. Zero-Trust & Post-Quantum Shield
* **PQC Handshake**: Uses Kyber768 (ML-KEM-768) post-quantum key encapsulation for initial session negotiation.
* **eBPF Enforcement**: Syncs authenticated identity states to eBPF kernel maps to perform line-rate packet drops for unauthenticated network traffic.

---

## 📦 Installation & Setup

### System Requirements
* **OS**: Linux / macOS
* **Python**: 3.10+
* **Rust Toolchain**: 1.75+ (for eBPF & PQC modules)
* **Ollama**: Installed and running locally (`http://localhost:11434`)

### Environment Setup

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/kelan-security/kelan-core.git
   cd kelan-core
   ```

2. **Create and Activate Virtual Environment**:
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   ```

3. **Install Dependencies and Package**:
   ```bash
   pip install --upgrade pip
   pip install -r requirements.txt
   pip install -e .
   ```

### Local LLM Models

Pull your preferred model via Ollama:

```bash
# Recommended for code analysis & speed (4.7 GB)
ollama pull qwen2.5-coder:latest

# Alternative general-purpose model (9.6 GB)
ollama pull gemma4:latest
```

### Running `kelan` CLI Commands

If running `kelan scan` returns `zsh: command not found: kelan`, use one of the following methods:

#### Option 1: Activate the Virtual Environment (Recommended)
Run this command in your terminal:
```bash
source .venv/bin/activate
```
Once activated, your terminal prompt will show `(.venv)` and you can run `kelan` directly from anywhere:
```bash
kelan scan
```

#### Option 2: Run via Virtual Environment Path Directly
Without activating `.venv`, call the executable using its relative path:
```bash
.venv/bin/kelan scan
```

#### Optional: Make `kelan` Globally Available in Shell
If you want `kelan` to work anywhere without having to activate `.venv` every time, add an alias to your Zsh configuration (`~/.zshrc`):
```bash
echo 'alias kelan="$(pwd)/.venv/bin/kelan"' >> ~/.zshrc
source ~/.zshrc
```
After doing this, typing `kelan scan` or `kelan dast` will work in any shell window!

---

## ⚙️ CLI Reference & Usage

### Interactive Mode

Running `kelan scan` without arguments launches an interactive prompt guiding target, limit, and model selection:

```bash
kelan scan
```

```text
🎯 Enter target directory to scan [default: .]: kelan/api
⚡ Enter chunk limit (0 for all) [default: 10]: 5

🧠 Available local models:
  1. qwen2.5-coder:latest  ← recommended
  2. gemma4:latest

Select a model (1-2) or type name [default: qwen2.5-coder:latest]: 1
```

### SAST Command (`kelan scan`)

| Flag | Type | Default | Description |
|---|---|---|---|
| `--target` | `path` | `.` | Target directory to scan |
| `--limit` | `int` | `10` | Maximum AST chunks to analyze (`0` for all) |
| `--model` | `string` | `qwen2.5-coder:latest` | Local Ollama model name |
| `--concurrency` | `int` | `2` | Number of parallel chunk evaluations |
| `--timeout` | `float` | `180.0` | Per-chunk timeout in seconds |
| `--json` | `path` | `None` | Write full analysis results to a JSON file |
| `--no-limit` | `flag` | `False` | Analyze every chunk in the target directory |

#### Examples
```bash
# Scan production API directory with 20-chunk limit
kelan scan --target kelan/api --limit 20 --model qwen2.5-coder:latest

# Full repository scan with JSON report output
kelan scan --target . --no-limit --json sast_report.json
```

### DAST Command (`kelan dast`)

| Flag | Type | Default | Description |
|---|---|---|---|
| `--target` | `url` | *Required* | Target seed URL |
| `--model` | `string` | `qwen2.5-coder:latest` | Local Ollama model for narrative enrichment |
| `--crawl` | `flag` | `False` | Spider origin-scoped pages before probing |
| `--max-pages` | `int` | `15` | Maximum pages to spider when `--crawl` is enabled |
| `--max-depth` | `int` | `3` | Maximum crawl depth |
| `--bypass` | `flag` | `False` | Enable multi-family encoding bypass payloads (68+ probes) |
| `--vectors` | `string` | `xss,sqli,cmdi,traversal,ssti` | Comma-separated list of vulnerability vectors |
| `--delay` | `float` | `0.5` | Politeness delay between requests (seconds) |
| `--json` | `path` | `None` | Path to save JSON report |
| `--ci-gate` | `string` | `None` | Threshold to fail build (`critical`, `high`, `medium`, `low`) |
| `--no-llm` | `flag` | `False` | Run deterministic heuristic evaluation only (no LLM call) |

#### Examples
```bash
# Basic single-page endpoint audit
kelan dast --target http://localhost:8080

# Comprehensive web crawl with bypass probes & JSON report
kelan dast --target http://localhost:8080 --crawl --max-pages 20 --bypass --json dast_report.json

# CI Pipeline run: fail build if HIGH or CRITICAL flaws exist
kelan dast --target http://staging.internal/ --crawl --bypass --ci-gate high
```

### CI/CD Integration

Example GitHub Actions workflow snippet (`.github/workflows/security-scan.yml`):

```yaml
name: Kelan Security Audit

on:
  push:
    branches: [ main, master ]
  pull_request:
    branches: [ main ]

jobs:
  security-audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Start Ollama Service
        run: |
          curl -fsSL https://ollama.com/install.sh | sh
          ollama serve &
          sleep 5
          ollama pull qwen2.5-coder:latest

      - name: Install Kelan
        run: |
          python -m venv .venv
          source .venv/bin/activate
          pip install -r requirements.txt
          pip install -e .

      - name: Run SAST Audit
        run: |
          source .venv/bin/activate
          kelan scan --target kelan/api --no-limit --json sast_report.json

      - name: Run DAST Audit with CI Gate
        run: |
          source .venv/bin/activate
          kelan dast --target http://localhost:8080 --crawl --bypass --json dast_report.json --ci-gate high

      - name: Upload Scan Artifacts
        uses: actions/upload-artifact@v4
        with:
          name: security-reports
          path: |
            sast_report.json
            dast_report.json
```

---

## 📁 Repository Structure

```text
kelan-core/
├── pyproject.toml              # PEP 621 build config & console_scripts entry
├── requirements.txt            # Python dependencies
├── kelan-scan                  # Convenience shell wrapper
├── kelan/                      # Main Python package
│   ├── ai/                     # Local LLM integration
│   │   ├── ollama_client.py    # Async HTTP client for Ollama API
│   │   └── prompts.py          # Trust-engine prompt definitions
│   ├── api/                    # Security management API
│   │   ├── server.py           # FastAPI management endpoints
│   │   ├── middleware/         # Auth & rate-limiting middleware
│   │   └── routes/             # API route handlers
│   ├── dast/                   # Dynamic Application Security Testing
│   │   ├── agent.py            # Legacy single-target DAST agent
│   │   ├── bypass.py           # Multi-family payload bypass engine
│   │   ├── cli.py              # DAST CLI command handler
│   │   ├── crawler.py          # Async BFS spider & HTML form parser
│   │   ├── heuristics.py       # Deterministic evidence graders
│   │   ├── llm.py              # LLM finding summarizer & narrative writer
│   │   ├── pipeline.py         # End-to-end DAST scan orchestrator
│   │   └── report.py           # Finding/Report dataclasses & CI gate logic
│   ├── enforcement/            # Kernel & eBPF enforcement
│   │   └── ebpf_bridge.py      # Kernel packet filtering bridge
│   ├── protocol/               # Post-Quantum cryptography & handshake
│   │   ├── crypto.py           # Kyber768 ML-KEM wrapper
│   │   └── handshake.py        # AITP handshake state machine
│   └── scanner/                # Static Application Security Testing
│       ├── analyzer.py         # VulnerabilityAnalyzer using Ollama
│       ├── chunker.py          # Tree-sitter AST semantic chunker
│       ├── cli.py              # SAST CLI command handler
│       ├── entrypoint.py       # Top-level 'kelan' CLI dispatcher
│       └── prompts.py          # SAST system prompt & JSON schema
└── tests/                      # Suite of unit & integration tests
    ├── dummy_server.py         # Intentionally vulnerable DAST target server
    ├── sample.py               # SAST test fixture
    └── unit/                   # Automated pytest suite
```

---

## 📊 Reporting Formats

### Terminal Report

```text
========================================================================
🛡️  KELAN DAST AGENT REPORT
========================================================================
Target:          http://localhost:8080
Model:           qwen2.5-coder:latest
Findings:        3
========================================================================

[HIGH] CWE-79 — Reflected Cross-Site Scripting (XSS)
  URL:         http://localhost:8080/
  Param:       search (GET)
  Evidence:    payload reflected unencoded in response (HTTP 200): <script>alert(1)</script>
  Remediation: Context-aware output encoding + CSP; input allowlist validation.
------------------------------------------------------------------------

[HIGH] CWE-639 — Broken Object Level Authorization (BOLA/IDOR)
  URL:         http://localhost:8080/api/user
  Param:       id (GET)
  Evidence:    Two different object IDs returned distinct (142 vs 138 byte) responses without authentication.
  Remediation: Enforce server-side authorization per object.
------------------------------------------------------------------------

[MEDIUM] CWE-693 — Missing Content-Security-Policy header
  URL:         http://localhost:8080/
  Param:       - (GET)
  Evidence:    response omits content-security-policy
  Remediation: Set CSP, HSTS, X-Frame-Options, X-Content-Type-Options.
------------------------------------------------------------------------
========================================================================
```

### JSON Report Schema

Saved when passing `--json report.json`:

```json
{
  "tool": "kelan-dast",
  "target": "http://localhost:8080",
  "model": "qwen2.5-coder:latest",
  "started_at": "2026-08-05T11:05:23.123456+00:00",
  "finished_at": "2026-08-05T11:05:45.654321+00:00",
  "meta": {},
  "risk_summary": "The application exhibits critical reflected XSS and unauthenticated BOLA endpoints.",
  "stats": {
    "severities": { "CRITICAL": 0, "HIGH": 2, "MEDIUM": 1, "LOW": 0, "INFO": 0 },
    "categories": { "xss": 1, "idor": 1, "header": 1 },
    "cwes": { "CWE-79": 1, "CWE-639": 1, "CWE-693": 1 }
  },
  "findings": [
    {
      "url": "http://localhost:8080/",
      "method": "GET",
      "param": "search",
      "category": "xss",
      "title": "Reflected Cross-Site Scripting (XSS)",
      "evidence": "payload reflected unencoded in response (HTTP 200): <script>alert(1)</script>",
      "remediation": "Context-aware output encoding + CSP; input allowlist validation.",
      "cwe": "CWE-79",
      "severity": "HIGH",
      "payload": "<script>alert(1)</script>",
      "variant": "raw",
      "confidence": "strong",
      "detected_at": "2026-08-05T11:05:30.000000+00:00"
    }
  ]
}
```

---

## 📜 License

Distributed under the **MIT License**. See `LICENSE` for details.
