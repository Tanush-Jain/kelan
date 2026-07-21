# AITP Codebase Security & Architectural Audit Report

**Date:** July 21, 2026  
**Repository:** `/home/wop/startup/kelan-core` (`Kelan-Security/kelan-core`)  
**Scope:** Comprehensive pre-pivot codebase audit (Rust crates, eBPF probes, AI evaluation contract, process inspection, and audit logging).

---

## Section 1 — Rust Crates & Actual Responsibilities

Verified by reading `Cargo.toml` and `src/` files across all Rust directories in the repository.

### 1. `kelan-ebpf-program` (`kelan-ebpf/kelan-ebpf-program`)
* **Location:** `kelan-ebpf/kelan-ebpf-program/Cargo.toml`, `kelan-ebpf/kelan-ebpf-program/src/main.rs`
* **Target Architecture:** `bpfel-unknown-none` (compiled independently of workspace).
* **Actual Responsibility:** Low-level kernel XDP (eXpress Data Path) packet filter binary (`kelan_xdp`).
* **Kernel Events Captured:** Ingress network packets arriving at network interfaces (`ETH_P_IP` / IPv4 UDP frames targeted to destination port `9999` / `AITP_PORT`). Parses Ethernet, IPv4, UDP, and `AitpMinHdr` protocol headers.
* **Coupling to Network Intent Enforcement:** **Extremely tightly coupled.** The eBPF kernel logic explicitly evaluates:
  * AITP protocol headers (`version`, `flags`, `intent`, `session_id`).
  * Per-CPU rate-limiting buckets for UDP floods (max 200 UDP pkts/sec) and AITP SYN handshake floods (max 50 SYN pkts/sec).
  * `PERMIT_MAP` lookup (`SessionPermit` struct containing `source_entity_prefix`, `dest_entity_prefix`, `intent`, `trust_score`, `verdict`, `expires_at`).
* **Generically Reusable:** Low. The capture and enforcement logic are bound directly to AITP packet structure and AITP network intent session permit maps.

---

### 2. `kelan-ebpf-loader` (`kelan-ebpf/kelan-ebpf-loader`)
* **Location:** `kelan-ebpf/kelan-ebpf-loader/Cargo.toml`, `src/lib.rs`, `src/linux.rs`, `src/userspace.rs`, `src/main.rs`
* **Actual Responsibility:** Userspace control-plane daemon and library. Loads `kelan_xdp` into Linux kernel via Aya (`aya::programs::Xdp`) or manages userspace fallback enforcement (`BpfEnforcer`) on non-Linux or systems without `bpf-linker`. Exposes JSON IPC over stdin/stdout for Python process integration (`PERMIT`, `REVOKE`).
* **Kernel Events Captured:** Does not capture kernel events directly; manages attachment of `kelan_xdp` to network interfaces (`eth0`, `lo`) and writes permits into `PERMIT_MAP` and `STATS_MAP`.
* **Coupling to Network Intent Enforcement:** **Tightly coupled.** Provides abstractions for `permit_session()`, `deny_ip()`, `SessionPermit`, `EnforcerStats`, and network interface attachment.
* **Generically Reusable:** Medium. The interface attachment lifecycle management is standard Aya XDP code, but map operations are custom to AITP permits.

---

### 3. `aitp-sdk` (`aitp-sdk`)
* **Location:** `aitp-sdk/Cargo.toml`, `src/lib.rs`, `src/types.rs`, `src/client.rs`, `src/server.rs`
* **Actual Responsibility:** High-level Rust developer client and server SDK wrapper for building AITP network applications. Note: `aitp-core`, `aitp-identity`, and `aitp-ai-engine` dependencies referenced in its `Cargo.toml` were archived/stubbed during the Rust $\rightarrow$ Python migration, leaving `aitp-sdk` as an unlinked SDK shell crate.
* **Kernel Events Captured:** None (userspace transport library).
* **Coupling to Network Intent Enforcement:** Coupled to AITP intent codes (`IntentCode`) and identity types.
* **Generically Reusable:** Low in current state.

---

## Section 2 — Exact eBPF Probe Types & Locations

Every eBPF probe in the repository was identified via workspace-wide grep/analysis. All eBPF probes in the repository are **XDP (eXpress Data Path)** network ingress filters.

| Probe Type | Function / Symbol Name | Target Event / Hook Point | Source File & Line |
| :--- | :--- | :--- | :--- |
| **`XDP`** (`#[xdp]`) | `pub fn kelan_xdp(ctx: XdpContext) -> u32` | Ingress network interface packets (UDP port 9999) | [main.rs:82](file:///home/wop/startup/kelan-core/kelan-ebpf/kelan-ebpf-program/src/main.rs#L82) |
| **`XDP`** (`SEC("xdp")`) | `int aitp_xdp_filter(struct xdp_md *ctx)` | Ingress network interface packets (C implementation) | [xdp_filter.bpf.c:112](file:///home/wop/startup/kelan-core/aitp-ebpf/src/xdp_filter.bpf.c#L112) |

* **Tracepoints (`#[tracepoint]`)**: 0 present.
* **Kprobes (`#[kprobe]` / `#[kretprobe]`)**: 0 present.
* **Uprobes (`#[uprobe]` / `#[uretprobe]`)**: 0 present.
* **Socket Filters (`#[socket_filter]`)**: 0 present.
* **BTF / Fentry / Fexit (`#[fentry]` / `#[fexit]`)**: 0 present.

---

## Section 3 — AI Engine Input/Output Contract & Trust Scoring

Verified by inspecting `kelan/ai/ollama_client.py`, `kelan/ai/engine.py`, and `kelan/ai/prompts.py`.

### 1. Input / Output Contract (`OllamaClient.evaluate(session: dict) -> TrustVerdict`)

* **Input Data Structure (`session: dict`):**
  * `entity_id`: Identifier string for requesting entity.
  * `session_id`: Unique session UUID.
  * `intent`: Request intent string (e.g. `INIT_ENROL`, `DATA_TRANSFER`, `ADMIN_OVERRIDE`).
  * `anomalies`: Dictionary of detected anomaly flags and rates from `SentinelDetector`:
    * `syn_rate_per_second` (integer rate count)
    * `ports_probed` (integer count)
    * `enrollment_count_from_ip` (integer count)
    * `failed_auth_attempts` (integer count)
    * `clearance_violation` (boolean)
    * `control_signal_abuse` (boolean)
    * `exploit_attempt` (boolean)
    * `anomaly_score` (float)
  * `clearance_level`: Integer clearance level of entity.
  * `department` / `org_id`: Entity metadata fields.

* **Output Data Structure (`TrustVerdict`):**
  * `verdict`: Enum (`ALLOW`, `DENY`, `MONITOR`).
  * `confidence`: Float ($0.0 \le c \le 1.0$). If confidence $< 0.5$, verdict defaults to `MONITOR`.
  * `reason`: String explanation (truncated to max 120 characters).
  * `latency_ms`: Float inference latency in milliseconds.
  * `from_cache`: Boolean indicating whether evaluation was short-circuited by the SHA-256 anomaly pattern cache.

### 2. "Trust Drift" Scoring Mechanism
* **Current Mechanism:** There is **no dynamic or continuous mathematical trust drift algorithm** (such as sliding exponential decay or vector drift models).
* **Score Calculation:** Trust scores are statically assigned integer values (range `0` to `255`, default `128`) in `kelan/api/server.py`:
  * `ALLOW` verdict $\rightarrow$ `180`
  * `MONITOR` verdict $\rightarrow$ `100`
  * `DENY` verdict $\rightarrow$ `50`
* `entities` table tracks `trust_score_avg` (float, default `128.0`).

---

## Section 4 — Process Environment, Memory & CLI Inspection

Verified by searching for process inspection patterns across Python and Rust source code.

* **Unused Dependencies:** `psutil==6.1.0` is pinned in [requirements.txt:33](file:///home/wop/startup/kelan-core/requirements.txt#L33), but is currently **not imported or used anywhere in application code**.
* **Subprocess Execution & Subprocess PID Tracking:**
  * [kelan/enforcement/ebpf_bridge.py:34](file:///home/wop/startup/kelan-core/kelan/enforcement/ebpf_bridge.py#L34): Uses `asyncio.create_subprocess_exec` to spawn `target/release/kelan-ebpf-loader` and tracks `self._proc.pid`.
  * [kelan/enforcement/ebpf_bridge.py:60](file:///home/wop/startup/kelan-core/kelan/enforcement/ebpf_bridge.py#L60): Uses `asyncio.create_subprocess_exec("bpftool", "map", "dump", ...)` to read BPF map packet statistics.
  * [aitp-sdk/src/server.rs:570](file:///home/wop/startup/kelan-core/aitp-sdk/src/server.rs#L570) & [client.rs:477](file:///home/wop/startup/kelan-core/aitp-sdk/src/client.rs#L477): Invokes `std::process::id()` for logging current process PID.
* **Target Process Environment / Memory / CLI Inspection:** **Zero active code** reads `/proc/$PID/mem`, `/proc/$PID/environ`, `/proc/$PID/cmdline`, or uses `ptrace`. Target process inspection is currently non-existent.

---

## Section 5 — Audit Logging Component Status

Verified by inspecting `kelan/db/database.py` and `kelan/db/models.py`.

### 1. Existing SQLite Audit Component: **CONFIRMED**
* **Database File:** SQLite database managed via SQLAlchemy (`aiosqlite`) at `data/kelan.db` or `data/aitp.db` (configured via `DATABASE_URL` in `.env`).
* **Tables & Views:**
  * `verdict_log` table (and `verdicts` SQLite view): Stores every AI and fallback trust evaluation (`id`, `entity_id`, `session_id`, `verdict`, `confidence`, `reason`, `latency_ms`, `anomaly_json`, `created_at`).
  * `anomaly_log` table (and `anomalies` SQLite view): Stores security anomaly events emitted by `SentinelDetector` (`id`, `source`, `kind`, `severity`, `details_json`, `created_at`).
  * `audit_events` table (created dynamically in `kelan/db/database.py` line 100): `CREATE TABLE IF NOT EXISTS audit_events (id INTEGER PRIMARY KEY AUTOINCREMENT, event TEXT, timestamp REAL);`.
  * `sessions` & `entities` tables: Store session lifecycles and entity enrollment/clearance states.

### 2. Hash-Chain Component Status: **NONE**
* **Finding:** There is **no cryptographic hash-chaining or Merkle tree component** currently implemented for audit logs. Audit log entries rely on standard auto-incrementing integer IDs (`id INTEGER PRIMARY KEY AUTOINCREMENT`) and floating-point UNIX timestamps without cryptographic block/entry hash linkage.
