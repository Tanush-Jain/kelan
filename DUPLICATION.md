# Analysis of Duplicate Packages: `kelan/` vs `kelan-python/`

## 1. Executive Summary & Verdict

* **Authoritative / Newer Package:** `kelan/` (at project root).
* **Legacy / Drifted Package:** `kelan-python/kelan/`.
* **Recommendation:** Establish `kelan/` as the single source of truth. Do not maintain two divergent Python trees.

Root `kelan/` is actively developed and referenced by `pyproject.toml`, `requirements.txt`, and the primary CI test suites. `kelan-python/` is an earlier snapshot from an initial prototype, which has not received recent feature updates (such as the 8-plugin scanner architecture, tree-sitter chunking, DAST crawlers, or modern eBPF bridge enhancements).

---

## 2. High-Level Architectural Differences

| Attribute | Root `kelan/` (Authoritative) | `kelan-python/` (Legacy) |
| :--- | :--- | :--- |
| **Active Test Suite** | 139 passing unit and integration tests | 83 passing legacy tests in `test_kelan.py` |
| **Scanner & AST Architecture** | Full semantic chunker (tree-sitter), DAST crawler, SAST adapter | Absent (no scanner, DAST, or SAST plugins) |
| **Plugin Framework** | 8 registered plugins (`sast`, `dast`, `sca`, `recon`, `cloud`, `chains`, `runtime`, `ratelimit`) | Absent |
| **Dependency Config** | Root `pyproject.toml` (`[project.scripts] kelan = "kelan.scanner.entrypoint:main"`) | Standalone nested `pyproject.toml` |
| **Pydantic Version** | Pydantic V2 (`SettingsConfigDict`, `field_validator`, `model_validator`) | Older Pydantic constructs |
| **Enforcement Engine** | Simulation-first, fail-open, capped, expiring rules, kill-switch, audit log | Minimal raw subprocess wrapper |

---

## 3. Module-by-Module Comparison

### Common Modules Across Both Trees

#### 1. `config.py`
* **`kelan/config.py` (Newer):** Modern Pydantic V2 settings using `SettingsConfigDict` and `field_validator`. Configures database URLs, Ollama endpoints, and authentication tokens cleanly without dead code.
* **`kelan-python/kelan/config.py` (Older):** Older Pydantic pattern with verbose docstrings and redundant default validators.

#### 2. `database.py`
* **`kelan/database.py` (Newer):** Streamlined lightweight database connection provider adapted for the current service layout.
* **`kelan-python/kelan/database.py` (Older):** Contains 158 lines of custom async context managers, explicit session leak mitigations, and raw SQLAlchemy engine lifecycle handlers.

#### 3. `ai/engine.py`
* **`kelan/ai/engine.py` (Newer):** `HybridTrustEngine` integrated with `FallbackRulesEngine`, WebSocket broadcast listeners, and active circuit-breaker states.
* **`kelan-python/kelan/ai/engine.py` (Older):** Early implementation of the circuit-breaker trust engine with inline hardcoded fallback responses.

#### 4. `ai/ollama_client.py`
* **`kelan/ai/ollama_client.py` (Newer):** Shared `httpx.AsyncClient` session with prompt templates, timeout controls, and structured JSON generation for both runtime trust and scanner analysis.
* **`kelan-python/kelan/ai/ollama_client.py` (Older):** Similar client design, but missing scanner prompt integration and dynamic model parameter coercion.

#### 5. `ai/prompts.py`
* **`kelan/ai/prompts.py` (Newer):** Clean, focused prompt definitions for intent evaluation.
* **`kelan-python/kelan/ai/prompts.py` (Older):** 121 lines containing raw `<|im_start|>` chat-template tokens for specific local models.

#### 6. `enforcement/ebpf_bridge.py`
* **`kelan/enforcement/ebpf_bridge.py` (Newer):** Production-grade bridge with simulation-first default, fail-open guarantees, rule capping (max rules), automatic TTL expiration pruning, emergency `kill_switch()`, and append-only audit logging (`log/enforcement_audit.jsonl`).
* **`kelan-python/kelan/enforcement/ebpf_bridge.py` (Older):** Primitive 91-line script that merely writes JSON commands to `kelan-ebpf-loader` over stdin without expiration, capping, or audit logs.

#### 7. `protocol/`
* **`kelan/protocol/` (Newer):** Contains `handshake.py` and `crypto.py` implementing Post-Quantum Kyber768 (ML-KEM-768) key exchange and Ed25519 identity verification.
* **`kelan-python/kelan/protocol/` (Older):** Contains `session.py`, an earlier session state container without the full post-quantum cryptographic primitives.

#### 8. `sentinel/`
* **`kelan/sentinel/` (Newer):** Contains `detector.py`, featuring multi-anomaly sliding window detection (Sybil bursts, packet floods, port scans, and brute-force detection).
* **`kelan-python/kelan/sentinel/` (Older):** Contains `anomaly.py`, an older anomaly evaluator with hardcoded rate limits.

---

### Modules Unique to Root `kelan/` (77 files)

* **`scanner/`**: `SemanticChunker` (tree-sitter multi-language parser), `VulnerabilityAnalyzer` (deterministic rules + Ollama AI), interactive `cli.py`, `agent.py`, `prompts.py`.
* **`plugins/`**: Modular scanner plugins (`sast`, `dast`, `sca`, `ports`, `cloud`, `chains`, `runtime`, `analyze_ratelimit`).
* **`dast/`**: Asynchronous web crawler, attack probe generator, heuristic vulnerability graders (XSS, SQLi, command injection, path traversal), and report exporter.
* **`chains/`**: Multi-stage attack chain correlation engine linking static vulnerabilities with dynamic crawler findings.
* **`analyze/`**: Runtime RedoS regex validation and burst rate-limit grading.
* **`cloud/`**: Cloud asset auditing and security baseline verification.
* **`core/`**: `Finding`, `FindingSet`, SARIF / JSON serializers, `ScanContext`, `ScanTarget`, and `Scheduler`.
* **`doctor.py`**: Environment readiness diagnostic tool.

---

### Modules Unique to `kelan-python/` (6 files)

* **`simulation/engine.py`**: In-memory traffic and datagram simulation generator used for running mock load tests.
* **`server/`**: Standalone prototype server layout (`server/main.py`, `server/models.py`). This functionality was consolidated into `kelan/api/server.py` in the root package.

---

## 4. Single Source of Truth Resolution

1. **Canonical Package:** `kelan/` (Community) and `kelan-pro/kelan_pro/` (Pro) are established as the single source of truth.
2. **Simulation Capabilities Preserved:** Simulation engine logic was integrated into `kelan-pro/kelan_pro/simulation/engine.py`.
3. **Deprecation & Removal Complete:** The entire legacy `kelan-python/` directory has been removed to eliminate package ambiguity and maintenance overhead.

