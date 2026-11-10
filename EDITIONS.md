# Kelan Editions: Community vs. Pro

This document details the architectural boundaries, feature matrix, and distribution model between **Kelan Community** and **Kelan Pro**.

---

## 1. Architectural Overview

```
┌────────────────────────────────────────────────────────────────────────┐
│                        Kelan CLI (`kelan`)                             │
│                  Dispatches Community & Pro commands                   │
└──────────────────┬─────────────────────────────────┬───────────────────┘
                   │                                 │
                   ▼ (Static Codebase)               ▼ (Dynamic Entry Point)
┌──────────────────────────────────────┐  ┌──────────────────────────────┐
│       Kelan Community (`kelan`)      │  │     Kelan Pro (`kelan-pro`)  │
│                                      │  │                              │
│ • SAST (AST + Offline Regex + LLM)  │  │ • eBPF / XDP Kernel Filter   │
│ • DAST (Crawler, Headers, IDOR)      │  │ • Enforcement Agent & Bridge │
│ • SCA (Dependency Manifest Parser)   │  │ • Offline Ed25519 Licensing  │
│ • Cloud Audit (S3, IAM, Creds)       │  │ • Two-Person Approval Flow   │
│ • Port & Service Reconnaissance      │  │ • Multi-Role RBAC            │
│ • Exploit Chaining & Corroboration   │  │ • Simulation-First Engine    │
│ • SARIF / JSON / HTML Reports        │  │ • Append-Only Audit Log      │
│ • Environment Doctor (`kelan doctor`)│  │ • Post-Quantum Session KEM   │
│ • Audit-Mode API Server & Dashboard  │  │ • Quarantine & Drop Endpoints│
└──────────────────────────────────────┘  └──────────────────────────────┘
```

---

## 2. Feature Matrix

| Feature / Capability | Kelan Community (`kelan`) | Kelan Pro (`kelan-pro`) | Description / Rules |
| :--- | :---: | :---: | :--- |
| **Execution Mode** | Audit Only | Simulation & Active Enforce | Community reports findings; Pro can drop packets or quarantine sessions. |
| **SAST Scanning** | ✅ Included | ✅ Included | AST rules, regex checks, and local Ollama analysis. |
| **DAST Scanning** | ✅ Included | ✅ Included | Path crawling, header inspection, IDOR probes, and security heuristics. |
| **SCA Dependency Audit** | ✅ Included | ✅ Included | Local manifest inspection; local-first by default (network opt-in). |
| **Cloud Misconfig Audit** | ✅ Included | ✅ Included | AWS/GCP/Azure storage, IAM credential leak and privilege checks. |
| **Port Discovery (Recon)** | ✅ Included | ✅ Included | Scans target ports and detects open services. |
| **Exploit Chaining** | ✅ Included | ✅ Included | Correlates static vulnerabilities with live runtime exposures. |
| **Environment Doctor** | ✅ Included | ✅ Included | `kelan doctor` checks Python version, Ollama models, and tree-sitter grammars. |
| **Reports** | SARIF, JSON, HTML | SARIF, JSON, HTML, Audit Log | Standardised formats for CI/CD and security pipelines. |
| **Local Web Dashboard** | ✅ Included | ✅ Included | Visualise findings and metrics on `http://localhost:7681`. |
| **eBPF / XDP Kernel Drops** | ❌ Pro Only | ✅ Included | Hardware offload or Linux TC/XDP kernel packet drops. |
| **Runtime Enforcement Agent**| ❌ Pro Only | ✅ Included | Daemon orchestrating eBPF rules and Sentinel anomaly detectors. |
| **Simulation-First Engine** | ❌ Pro Only | ✅ Included | Dry-run policy enforcement without dropping live traffic. |
| **Emergency Kill Switch** | ❌ Pro Only | ✅ Included | Instantly flushes all kernel rules and restores fail-open routing. |
| **Offline Licence Verification**| ❌ Not Required | ✅ Included | Ed25519-signed licence verified offline. Zero phone-home network calls. |
| **Role-Based Access Control** | ❌ Pro Only | ✅ Included | Native `admin`, `operator`, `analyst`, and `auditor` permission boundaries. |
| **Approval Workflow** | ❌ Pro Only | ✅ Included | Two-person rule state machine for quarantine and block operations. |
| **Append-Only Audit Log** | ❌ Pro Only | ✅ Included | Cryptographically chained SHA-256 audit log for compliance. |
| **PQ Session Attestation** | ❌ Pro Only | ✅ Included | ML-KEM-768 / Kyber post-quantum cryptographic session handshake. |

---

## 3. Package & Dependency Boundaries

1. **Strict Community Isolation:**
   - The Community package has **zero import paths** to `kelan_pro`, `enforcement`, `sentinel`, `protocol`, `crypto`, `db`, or `trust`.
   - Verified in CI via static Abstract Syntax Tree (AST) inspection in `kelan/tests/unit/test_no_pro_imports.py`.
2. **Dynamic Entry Points:**
   - Kelan Pro integrates seamlessly into the `kelan` CLI via standard Python entry points:
     ```toml
     [project.entry-points."kelan.commands"]
     pro = "kelan_pro.cli:register_commands"
     ```
   - When Pro is installed, commands (`enforce`, `agent`, `simulate`, `rbac`, `license`) become active automatically.
   - When Pro is absent, invoking Pro commands displays an informative installation guide without crashing.
3. **Rust Build Separation:**
   - `kelan-ebpf` (Aya-based Rust eBPF loader and kernel program) is housed strictly in `kelan-pro/kelan-ebpf` and built only with Pro.
   - The Community edition has no Rust build dependencies.
   - Legacy C BPF kernels (`aitp-ebpf`) are preserved under `kelan-pro/bpf-legacy/` for reference.
   - Legacy prototype `aitp-sdk` with broken upstream references has been archived under `archive/aitp-sdk/`.
4. **Offline Licence Integrity:**
   - Pro requires an Ed25519-signed licence file.
   - Missing, expired, or tampered licences cause Pro commands to terminate with exit code 1 and a human-readable diagnostic message.
   - Project Project Rules: No telemetry, no phone-home, simulation-first, fail-open, capped, expiring.

