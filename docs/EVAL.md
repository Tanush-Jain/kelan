# Kelan SAST Evaluation & Benchmark Scoreboard

**Generated Programmatically:** `2026-11-22T18:53:29.417984+00:00`  
**Harness Script:** `eval/run_eval.py` (Do not edit this document by hand)

---

## 1. Regression Test: SQL Injection & Command Injection

> **Motivating Sample:** `eval/corpus/regression/sql_injection_sample.py`  
> A single file containing both string-formatted query execution (`cursor.execute`) and `subprocess.call(cmd, shell=True)`.

**Status:** :white_check_mark: **PASSED (100% Deterministic Detection without Ollama)**

| Rule ID | CWE | Title | Line | Evidence | Confidence |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `KELAN-PY-SQLI-01` | `CWE-89` | SQL Injection: Unparameterized Dynamic Query | 6 | `Variable 'query' assigned dynamic SQL at line 5: f"SELECT * FROM users WHERE name = '{user_input}'" -> passed directly to sink.` | **HIGH** |
| `KELAN-PY-CMDI-01` | `CWE-78` | Command Injection: Unsanitized External Command Execution | 7 | `subprocess.call invoked with shell=True` | **HIGH** |

---

## 2. Multi-Layer Detection Performance Scoreboard

Precision, Recall, and False-Positive Rate (FPR) evaluated across the intentionally vulnerable corpus, held-out validation suites, and safe negative controls:

| Layer | Precision | Recall | False Positive Rate (FPR) | TP | FP | FN | TN |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Layer 1: Deterministic AST Rules** | 100.0% | 100.0% | 0.0% | 32 | 0 | 0 | 20 |
| **Layer 2: AST + Reachability Call Graph** | 100.0% | 100.0% | 0.0% | 32 | 0 | 0 | 20 |
| **Layer 3: AST + Reachability + LLM Triage** | 100.0% | 100.0% | 0.0% | 32 | 0 | 0 | 20 |

---

## 3. Held-Out Evaluation Set & Generalization

- **Held-Out Corpus**: Tested on un-tuned multi-function applications (`heldout_py_app.py`, `heldout_js_app.js`) with mixed reachable endpoints, uncalled dead code, and safe parameterized routes.
- **Call Graph Verification**: Verified that dead internal routines with zero incoming call edges evaluate to `reachability_verdict: unreachable` and do not trigger false alerts.

### Top Missed Cases

Zero false negatives across the corpus benchmark.

---

## 4. Architectural Guarantees

1. **Zero LLM Dependency for Layer 1 Detection**: With Ollama offline, all baseline vulnerabilities are detected deterministically with high confidence.
2. **Strict Reachability Invariant**: Unknown call paths stay `unknown` and are never coerced to `reachable` or `unreachable`.
3. **Bounded LLM Triage**: Layer 3 only receives reachable or unknown findings; the model cannot change reachability verdicts or invent findings.
