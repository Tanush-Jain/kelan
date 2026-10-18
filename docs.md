# 🛡️ Kelan Security — Command Reference & Operations Guide (docs.md)

This document contains a comprehensive, step-by-step cheat sheet of all commands required to install, configure, run, attack, and defend the Kelan Security Zero-Trust Network Shield.

---

## 📋 Table of Contents
1. [System Prerequisites & Installation](#1-system-prerequisites--installation)
2. [Ollama AI Trust Engine Setup](#2-ollama-ai-trust-engine-setup)
3. [Environment Configuration](#3-environment-configuration)
4. [Running the Control & Data Plane](#4-running-the-control--data-plane)
5. [Setting Up the TMUX Warroom Dashboard](#5-setting-up-the-tmux-warroom-dashboard)
6. [Simulating Attacks (Red Team Operations)](#6-simulating-attacks-red-team-operations)
7. [Kernel & Defense Auditing (Blue Team Operations)](#7-kernel--defense-auditing-blue-team-operations)

---

## 1. System Prerequisites & Installation

### A. Install Build & Kernel Dependencies
```bash
# Update repositories
sudo apt-get update -y

# Install compilation headers, SSL libraries, and network tools
sudo apt-get install -y build-essential pkg-config libssl-dev iproute2 curl jq python3

# Install LLVM, Clang, bpftool, and kernel headers required for eBPF native hooks
sudo apt-get install -y llvm clang libbpf-dev bpftool linux-headers-$(uname -r)

# Install Docker and Docker Compose (v2) for Grafana/Prometheus monitoring stack
sudo apt-get install -y docker.io docker-compose-v2
sudo systemctl enable --now docker
sudo usermod -aG docker $USER
```

### B. Install Rust & eBPF Compilation Toolchain
```bash
# Install Rust toolchain
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"

# Install bpf-linker for eBPF programs compilation
cargo install bpf-linker
```

### C. Clone and Build the Workspace
```bash
# Clone the repository
git clone https://github.com/kelan-security/kelan-core.git
cd kelan-core

# Build in standard debug mode
cargo build

# Build all binaries in optimized Release mode
cargo build --release

# Build specifically with native eBPF compilation enabled
cargo build --release --features ebpf-native -p aitp-server
```

---

## 2. Ollama AI Trust Engine Setup

Kelan uses local AI running on Ollama for real-time connection intent evaluations.

```bash
# On your Ollama Host (e.g. MacBook M4 or Local server):
# 1. Pull the model (Gemma 3 or Gemma 4)
ollama pull gemma3:9b
ollama pull gemma4:latest

# 2. Run the model to verify it's responsive
ollama run gemma3:9b "hello"

# 3. Expose Ollama on all interfaces if running on a remote machine:
# Set OLLAMA_HOST=0.0.0.0 environment variable before launching the Ollama service.
Normal forensice tools to be installed  

# Switch to pane 1 in tmux (Ctrl+B then arrow keys)
apt install -y hping3 nmap python3 python3-pip tcpdump netcat-openbsd
pip3 install requests scapy --break-system-packages
echo "✅ Attack tools ready"
```

---

## 3. Environment Configuration

Create or modify your `.env` file in the project root:

```ini
# AI Engine — points to MacBook or local Ollama host
OLLAMA_ENDPOINT=http:<Your device or server IP>>:pORT NUMBER
OLLAMA_MODEL=gemma3:9b
OLLAMA_TIMEOUT_SECS=8

# Database URL (SQLite is the default and auto-migrates)
KELAN_DB_URL=sqlite:data/kelan.db

# Server JWT signing secret and Bind Addresses
KELAN_JWT_SECRET=4f8f106f2e82f5b4a9235e1ab8e5f22e432c695a4570059e9f9c7a002a28114f
KELAN_LISTEN_ADDR=0.0.0.0:3000
KELAN_UDP_ADDR=0.0.0.0:9999

# Engine Mode: rules, ollama, or hybrid (runs rules + Ollama in parallel)
KELAN_MODE=hybrid
KELAN_EBPF_ENABLED=true
KELAN_LOG_LEVEL=info

# Target Network interface for kernel-level eBPF XDP attachments
KELAN_XDP_IFACE=wlan0

# Test Credentials for APIs
TEST_EMAIL=test@kelan.dev
TEST_PASSWORD=KelanTest#2024!

# Agentic verdict synchronization setup (macOS server ↔ Kali Linux enforcement client)
AGENTIC_ENABLED=true
AGENT_SYNC_ENDPOINT=/ws/agent
AGENT_AUTH_TOKEN=kelan-agent-secret-2024
```

---

## 4. Running the Control & Data Plane

### Option A: Direct Local Execution (Development)
```bash
# Source env and run target binary directly
export $(cat .env | grep -v '^#' | xargs)
./target/release/aitp-server
```

### Option B: Systemd Daemon (Production Daemon)
Create `/etc/systemd/system/kelan.service`:
```ini
[Unit]
Description=Kelan Intelligence Core Service
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/home/wop/startup/kelan-core
ExecStart=/home/wop/startup/kelan-core/target/release/aitp-server
EnvironmentFile=/home/wop/startup/kelan-core/.env
Restart=on-failure
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
```
Manage the systemd service:
```bash
sudo systemctl daemon-reload
sudo systemctl enable kelan
sudo systemctl start kelan
sudo systemctl status kelan
sudo journalctl -u kelan -f --no-tail
```

### Option C: Docker Compose Deploy (With Prometheus & Grafana)
```bash
# Start all containers in detached mode (builds server from Dockerfile if specified)
sudo docker compose up -d

# Check container status
sudo docker compose ps

# View real-time container logs
sudo docker compose logs -f kelan-server
```

---

## 5. Setting Up the TMUX Warroom Dashboard

To watch servers, live stats, eBPF maps, and execute attacks at once, use this automated 4-pane layout.

```bash
# 1. Start tmux background session named 'warroom' with window 'monitor'
tmux new-session -d -s warroom -n monitor

# 2. Split window into 4 panes
tmux split-window -h -t warroom
tmux split-window -v -t warroom:0.0
tmux split-window -v -t warroom:0.2

# 3. Setup Pane 0 (top-left): Live server logs filtered for key verdicts/operations
tmux send-keys -t warroom:0.0 "
cd ~/kelan-core && \
export \$(cat .env | grep -v '^#' | xargs) && \
RUST_LOG=info,aitp_server=debug ./target/release/aitp-server 2>&1 | \
grep -E --line-buffered 'verdict|ALLOW|DENY|MONITOR|Ollama|DROP|flood|anomaly|sentinel|attack|blocked|WARN|ERROR'
" Enter

# 4. Setup Pane 1 (bottom-left): Live attack injection shell
tmux send-keys -t warroom:0.1 "cd ~/kelan-core && export \$(cat .env | grep -v '^#' | xargs)" Enter
tmux send-keys -t warroom:0.1 "IFACE=\$(ip -o -4 route show to default | awk '{print \$5}' | head -1) && echo Attack terminal ready on \$IFACE" Enter

# 5. Setup Pane 2 (top-right): Live local HTTP statistics (curled every 2 seconds)
tmux send-keys -t warroom:0.2 "watch -n 2 'curl -s http://localhost:3000/api/stats | python3 -m json.tool 2>/dev/null || echo waiting...'" Enter

# 6. Setup Pane 3 (bottom-right): Live eBPF kernel maps and hooks monitor
tmux send-keys -t warroom:0.3 "watch -n 3 'echo \"=== PERMIT MAP ===\"; bpftool map list 2>/dev/null; echo \"\"; echo \"=== XDP PROGRAMS ===\"; bpftool prog list 2>/dev/null | grep -E xdp || echo none loaded'" Enter

# 7. Attach to the Warroom Dashboard
tmux attach -t warroom
```

---

## 6. Simulating Attacks (Red Team Operations)

### A. Simulating a Standard Connection Handshake
Run the minimal client example to initiate a legitimate connection:
```bash
cargo run --example minimal_client
```

### B. Simulating DDoS Floods (SYN/UDP Flood)
Use the included `attack_sim` program to fire high-throughput connection attempts:
```bash
# Standard high-volume attack towards the AITP secure UDP socket
cargo run --example attack_sim -- --server localhost:9999 --mode ddos

# Run throttled attack suite simulating anomalous patterns
./scripts/simulate_attacks_throttled.sh
```

### C. Injecting Malicious Intent / Intent Deviation
Execute the attack suite simulator script to test behavioral detection of anomalous intent sequences:
```bash
chmod +x scripts/simulate_attacks.sh
./scripts/simulate_attacks.sh
```

---

## 7. Kernel & Defense Auditing (Blue Team Operations)

### A. System & API Health Checks
```bash
# Query the local health checkpoint
curl -s http://localhost:3000/health | jq .

# Read live metrics & packet statistics
curl -s http://localhost:3000/api/stats | jq .
```

### B. Checking Kernel Hook States
```bash
# List all active eBPF programs on the system
sudo bpftool prog show

# Verify if the XDP filter is attached
sudo bpftool prog list | grep xdp

# Dump eBPF enforcement maps containing permitted/blocked IPs
sudo bpftool map dump name PERMIT_MAP
sudo bpftool map dump name DENY_MAP
sudo bpftool map dump name SYN_RATE_MAP
```

### C. Live Log Trailing
```bash
# View and follow local server logs
tail -f log/kelan.log 2>/dev/null || sudo journalctl -u kelan -f
```

---
