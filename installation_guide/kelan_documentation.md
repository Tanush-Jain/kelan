---

# Kelan Security — Installation & Usage Guide
## v0.3.0 | Kernel-Level Agentic Network Security

---

## PART 1: SERVER INSTALLATION (LINUX)

### 1.1 System Requirements

- **OS**: Ubuntu 22.04 LTS or later (kernel 5.15+ required for eBPF)
- **RAM**: 2GB minimum / 4GB+ recommended
- **CPU**: 2 cores minimum / 4+ cores recommended
- **Disk**: 10GB minimum (for metrics, baselines, and logs)
- **Network**: Open inbound ports:
  - UDP 9999 (AITP transport protocol)
  - TCP 3000 (HTTP REST API and WebSocket Hub)
  - TCP 3001 (HTTPS REST API / optional)
- **Access**: `root` or `sudo` access is required for mounting eBPF maps to the kernel.

### 1.2 Install System Dependencies

Run the following commands to install build prerequisites on Debian/Ubuntu systems:

```bash
# Update package repositories
sudo apt-get update -y

# Install build essentials, SSL, and network tools
sudo apt-get install -y build-essential pkg-config libssl-dev iproute2 curl

# Install eBPF dependencies
sudo apt-get install -y llvm clang libbpf-dev bpftool linux-headers-$(uname -r)

# Install Docker + Docker Compose (Optional, for monitoring stack)
sudo apt-get install -y docker.io docker-compose-v2
sudo systemctl enable --now docker
sudo usermod -aG docker $USER

# Install Rust toolchain
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"
```

### 1.3 Clone and Build

Clone the repository and build the workspace.

```bash
git clone https://github.com/kelan-security/kelan-core.git
cd kelan-core

# Build the workspace
cargo build --release
```

**Workspace Structure:**
- `aitp-server`: The core Intelligence Server daemon that listens on UDP/TCP.
- `kelan-sdk`: The Rust client library for integrating Kelan into your applications.
- `kelan-ebpf`: Kernel-level hooks for high-performance session dropping.
- `kelan-agent`: A lightweight client-side daemon for proxying connections (experimental).

### 1.4 Enable eBPF Kernel Enforcement

For production environments, eBPF is critical. It allows Kelan to block malicious connections in the kernel *before* they reach the application layer.

**A. How the `ebpf-native` feature works**
By default, Kelan falls back to software enforcement in userspace. The `ebpf-native` feature compiles and loads the XDP (eXpress Data Path) kernel hooks.

**B. Building with eBPF enabled**
You must install the `bpf-linker` before building:
```bash
cargo install bpf-linker
cargo build --release --features ebpf-native -p aitp-server
```

**C. Verify eBPF compatibility**
Ensure your kernel supports XDP:
```bash
uname -r
# Must output 5.15.x or higher

sudo bpftool feature probe | grep xdp
# Should show "eBPF program_type xdp is available"
```

**D. Identify your Network Interface**
Find your primary public-facing interface (often `eth0` or `ens3`):
```bash
ip link show
```

**E. Software Fallback**
If `ebpf-native` is omitted, Kelan safely falls back to software layer tracking. It works the same, but drops packets in the application space instead of the kernel, using more CPU under heavy attacks.

### 1.5 Configuration

Create a `.env` file in the project root:

```env
# ── Server Identity ──
AITP_NODE_NAME=kelan-core-01
ENVIRONMENT=production

# ── Network Settings ──
UDP_PORT=9999
HTTP_PORT=3000
HTTPS_PORT=3001
NETWORK_INTERFACE=eth0

# ── Trust Scoring ──
AITP_AI_ENGINE_MODE=hybrid
AITP_AI_ENGINE_GEMINI_API_KEY=[REDACTED_GEMINI_KEY]

# ── Authentication ──
JWT_SECRET=super_secret_jwt_signing_key_replace_me

# ── Database ──
DATABASE_URL=sqlite:data/kelan.db

# ── Logging ──
RUST_LOG=info,aitp_server=debug
```

- `NETWORK_INTERFACE`: Crucial for eBPF map attachment.
- `AITP_AI_ENGINE_MODE`: Use `hybrid` to blend static rules with Gemini evaluations. `rules` relies on pure heuristics.
- `DATABASE_URL`: Path to the SQLite instance.
- `JWT_SECRET`: Random string required to sign authorization tokens.

### 1.6 Database Setup

**A. SQLite (Default / Recommended for v0.3.0)**
Requires zero external configuration. Just set `DATABASE_URL=sqlite:data/kelan.db` in your `.env`. The `aitp-server` will automatically run SQLite schema migrations during initialization.

**B. PostgreSQL (Coming in v0.4.0)**
PostgreSQL integration is actively being stabilized for multi-node deployments. If experimenting:
```env
DATABASE_URL=postgres://kelan_admin:password@localhost:5432/kelan_db
```

### 1.7 Start the Server

**OPTION A — Direct binary (Testing)**
```bash
sudo ./target/release/aitp-server
```

**OPTION B — Systemd (Production Recommended)**
Create a service file at `/etc/systemd/system/kelan.service`:

```ini
[Unit]
Description=Kelan Intelligence Core
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/kelan-core
ExecStart=/opt/kelan-core/target/release/aitp-server
EnvironmentFile=/opt/kelan-core/.env
Restart=on-failure
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
```
Start and enable the service:
```bash
sudo systemctl daemon-reload
sudo systemctl enable kelan
sudo systemctl start kelan
```

**OPTION C — Docker Compose**
Deploy the server alongside the monitoring stack.
```bash
docker compose up -d
docker compose logs -f kelan-server
```

### 1.8 Verify Server is Running

```bash
# HTTP health check
curl http://localhost:3000/health
# Expected Output: {"status":"ok","version":"0.3.0"}

# Verify UDP listener is active on port 9999
ss -ulnp | grep 9999
# Expected Output: UNCONN 0 0 0.0.0.0:9999 0.0.0.0:* ...

# Verify eBPF maps (if ebpf-native is enabled)
sudo bpftool prog list | grep xdp
# Expected Output: ... xdp  name kelan_xdp ...

# View live systemd logs
sudo journalctl -u kelan -f
```

### 1.9 Firewall Configuration

Using `ufw`:
```bash
sudo ufw allow 9999/udp  # Allow AITP Secure Protocol
sudo ufw allow 3000/tcp  # Allow HTTP APIs
sudo ufw allow 3001/tcp  # Allow HTTPS APIs
sudo ufw allow from 127.0.0.1 to any port 9090 proto tcp # Local Prometheus
sudo ufw allow from 127.0.0.1 to any port 3003 proto tcp # Local Grafana
sudo ufw reload
```

### 1.10 Monitoring

If using Docker Compose, the monitoring stack spins up automatically:
- **Prometheus**: `http://<server-ip>:9090`
- **Grafana**: `http://<server-ip>:3001` (Credentials: `admin` / `aitp_admin`)
  - The *Kelan Overview* dashboard is pre-provisioned via `monitoring/grafana/dashboards/`.

---

## PART 2: CLIENT CONNECTION GUIDE

### 2.1 What Happens When You Connect

The Adaptive Intent Transport Protocol (AITP) utilizes a 5-phase handshake to establish connections:

- **Phase 1 (SYN)**: Your client submits an Identity (Ed25519 PK) and an `IntentCode` (reason for connection) to the server.
- **Phase 2 (SYN-ACK)**: The server verifies the identity structure and responds with a cryptographic challenge.
- **Phase 3 (Encapsulation)**: The client encapsulates a shared secret (ML-KEM-768/X25519) and signs the handshake.
- **Phase 4 (Evaluation)**: The Kelan Core passes the context to the AI Trust Engine to obtain a trust score (0-255).
- **Phase 5 (Resolution)**: If the Trust Engine issues an `Allow` or `Monitor` verdict, the session is registered in the kernel and data flows. `Deny` verdicts actively blackhole traffic at the eBPF layer.

### 2.2 Option A — Using kelan-sdk (Rust)

Add the SDK to your `Cargo.toml`:
```toml
[dependencies]
kelan-sdk = { git = "https://github.com/kelan-security/kelan-core", version = "0.3.0" }
```

Minimal connection setup:
```rust
use kelan_sdk::AitpClient;
use kelan_crypto::HybridSigningKey;
use aitp_core::header::IntentCode;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Generate your identity (in production: load from disk/secrets!)
    let identity = HybridSigningKey::generate();
    
    // 2. Connect to the Intelligence Server
    let session = AitpClient::builder()
        .server("127.0.0.1:9999")
        .intent(IntentCode::ModelInference)
        .identity(identity)
        .connect()
        .await?;
    
    println!("Connection Established!");
    println!("Session ID: {}", session.session_id);
    println!("Trust Score: {:.2}", session.trust_score);
    println!("Verdict: {}", session.verdict);
    
    match session.verdict.as_str() {
        "Allow" => { println!("Proceeding with operation.") }
        "Monitor" => { println!("Warning: Operation permitted but heavily logged.") }
        "Deny" => { println!("Fatal: Server strictly refused connection.") }
        _ => {}
    }

    Ok(())
}
```

**Common Intent Codes**:
- `IntentCode::ModelInference` — Used for requesting LLM completions.
- `IntentCode::DataSync` — Moving data tables.
- `IntentCode::ControlSignal` — High-risk; system state modification.
- `IntentCode::Telemetry` — Low risk; emitting logs or metrics.
- `IntentCode::Heartbeat` — Keeping connections alive.

### 2.3 Option B — Using the REST API

Integrate with Kelan to manage your security tenant remotely. 

**Retrieve a Token:**
```bash
curl -X POST http://127.0.0.1:3000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"entity_id": "system-admin-uuid", "secret": "your_secure_password"}'
```
*Response*: `{"token": "eyJhbGciOi...", "expires_in": 3600}`

**View Active Sessions:**
```bash
curl http://127.0.0.1:3000/api/sessions \
  -H "Authorization: Bearer eyJhbGciOi..."
```

**View Detected Anomalies:**
```bash
curl http://127.0.0.1:3000/api/anomalies \
  -H "Authorization: Bearer eyJhbGciOi..."
```

### 2.4 Option C — WebSocket Live Feed

Receive live updates about DDoS attempts, dropped connections, and session telemetry.

**JavaScript Client Example:**
```javascript
const ws = new WebSocket(
    'ws://127.0.0.1:3000/ws',
    ['bearer', 'eyJhbGciOi...'] 
);

ws.onopen = () => console.log('Connected to Kelan Sentinel stream');

ws.onmessage = (event) => {
    const data = JSON.parse(event.data);
    
    switch(data.type) {
        case 'SessionEstablished':
            console.log(`New session: ${data.session_id} [Trust: ${data.trust_score}]`);
            break;
        case 'AnomalyDetected':
            console.error(`🚨 ALERT: ${data.anomaly_type}. Action: ${data.recommended_action}`);
            break;
        case 'SessionDenied':
            console.warn(`Connection Refused. Reason: ${data.reason}`);
            break;
    }
};
```

### 2.5 Persistent Identity (Production)

> [!CAUTION]  
> If an application regenerates its `HybridSigningKey` on every startup, the Trust Engine will view it as a completely new identity, resetting its baseline trust score and penalizing it for being "Young".

**Generate and Save Identity (Once):**
```rust
let identity = HybridSigningKey::generate();
let secret_bytes = identity.to_secret_bytes();
std::fs::write("/etc/myapp/kelan_identity.key", secret_bytes).unwrap();
```

**Load on Subsequent Runs:**
```rust
let secret_bytes = std::fs::read("/etc/myapp/kelan_identity.key").unwrap();
let identity = HybridSigningKey::from_secret_bytes(&secret_bytes).unwrap();
```
*Always store this file securely with strict read permissions.*

### 2.6 Multi-Tenant Usage

The `aitp-server` separates data by `org_id` seamlessly. Your JWT dictates your organization scope.
- Subscribing to the WebSocket hub using an `Org A` JWT will strictly limit the event stream to `Org A` metrics.
- Threat baselines are tracked independently per organization so that one tenant's compromise does not block healthy agents on another.

---

## PART 3: KNOWN LIMITATIONS (v0.3.0)

> [!WARNING]  
> **Server Handshake Activates on SYN (SYN Flood Vulnerability)**  
> While the SDK completes all 5 phases, the server currently registers the session immediately upon receiving the initial `SYN` packet to maximize throughput. Verification of Post-Quantum Signatures (Phases 3-5) is fully implemented in logic, but bypassed in the current hot path socket loop. Ensure you rate-limit UDP 9999 externally via IP tables if deploying directly to the public web.

> [!NOTE]  
> **eBPF Requires Explicit Compile Flags**  
> If you compile without `--features ebpf-native`, Kelan transparently substitutes kernel enforcement with userspace enforcement. It still works, but will consume significantly more CPU while blocking attacks.

> [!NOTE]  
> **PostgreSQL Support**  
> Support code is present but unstable. Multi-node `aitp-server` clustering will officially ship in `v0.4.0`. Use the default SQLite `DATABASE_URL` for this release.

> [!WARNING]  
> **Header Sizing Differences**  
> `aitp-server` utilizes flexible length `AitpHeaderV4` structures to hold large Quantum signatures. Raw protocol clients attempting to connect directly via `aitp-core` structures may encounter serialization errors. **Always use `kelan-sdk`.**

---

## PART 4: QUICK REFERENCE

### Server Management
```bash
# Controls
sudo systemctl start kelan
sudo systemctl stop kelan
sudo systemctl restart kelan

# View raw logs
sudo journalctl -u kelan -f

# Verify kernel blocking
sudo bpftool map dump name PERMIT_MAP
sudo bpftool map dump name DENY_MAP
```

### Attack Simulation
```bash
cd kelan-core
cargo run --example attack_sim -- --server localhost:9999 --mode ddos
```

### Required Ports

| Port | Protocol | Purpose | Access |
|------|----------|---------|--------|
| **9999** | UDP | AITP Transport Socket | Public |
| **3000** | TCP | HTTP REST & WebSockets| Public |
| **3001** | TCP | HTTPS Server (Optional)| Public |
| **9090** | TCP | Prometheus Metrics | Internal |
| **3001** | TCP | Grafana Dashboard / UI | Internal |

---
