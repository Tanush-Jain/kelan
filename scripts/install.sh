#!/bin/bash
# Kelan Security — Installation Script
# Usage: sudo bash scripts/install.sh
# Supports: Ubuntu 22.04+, Debian 12+, ARM64 Linux

set -euo pipefail

RED='\033[0;31m'
GRN='\033[0;32m'
YLW='\033[1;33m'
NC='\033[0m'  # No Color

info()  { echo -e "${GRN}[kelan]${NC}  $*"; }
warn()  { echo -e "${YLW}[warn] ${NC}  $*"; }
error() { echo -e "${RED}[error]${NC}  $*"; }

echo ""
echo "╔══════════════════════════════════════════╗"
echo "║    Kelan Security — Installation v0.3    ║"
echo "╚══════════════════════════════════════════╝"
echo ""

# ── 1. Root check ─────────────────────────────────────────────────────────────
if [ "$EUID" -ne 0 ]; then
  error "Run as root: sudo bash scripts/install.sh"
  exit 1
fi

# ── 2. Detect OS ──────────────────────────────────────────────────────────────
if [ -f /etc/os-release ]; then
  . /etc/os-release
  OS_ID="$ID"
  OS_VERSION="$VERSION_ID"
  info "Detected OS: $PRETTY_NAME"
else
  warn "Cannot detect OS — assuming Debian-compatible"
  OS_ID="debian"
fi

# ── 3. Run kelan doctor ───────────────────────────────────────────────────────
info "Running pre-flight checks..."

DOCTOR_EXIT=0
if [ -f ./target/release/kelan-doctor ]; then
  ./target/release/kelan-doctor || DOCTOR_EXIT=$?
elif [ -f ./target/release/aitp_server ]; then
  ./target/release/aitp_server --doctor || DOCTOR_EXIT=$?
else
  warn "Kelan binaries not yet built — skipping doctor check (will run after build)"
fi

if [ "$DOCTOR_EXIT" -eq 1 ]; then
  error "Doctor reported critical failures. Please fix them before retrying."
  error "Run './target/release/kelan-doctor' for details."
  exit 1
elif [ "$DOCTOR_EXIT" -eq 2 ]; then
  warn "Doctor warnings detected — will continue in software enforcement mode"
fi

# ── 4. Install system dependencies ───────────────────────────────────────────
info "Installing system dependencies..."

if command -v apt-get &>/dev/null; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq 2>&1 | tail -1
  apt-get install -y --no-install-recommends \
    clang llvm libelf-dev \
    iproute2 iptables \
    curl wget git \
    ca-certificates \
    build-essential pkg-config libssl-dev \
    linux-tools-common linux-tools-generic \
    hping3 \
    2>&1 | grep -E "^(Get|Unpacking|Setting up|Processing)" || true
elif command -v dnf &>/dev/null; then
  dnf install -y clang llvm elfutils-libelf-devel iproute iptables curl hping3 2>/dev/null || true
else
  warn "Unknown package manager — you may need to install clang, llvm, libelf-dev manually"
fi

# ── 5. Install Rust (if not present) ─────────────────────────────────────────
if ! command -v cargo &>/dev/null; then
  info "Installing Rust toolchain..."
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | \
    sh -s -- -y --no-modify-path --default-toolchain stable
  source "$HOME/.cargo/env"
fi

info "Rust: $(rustc --version)"

# ── 6. Configure kernel for eBPF ──────────────────────────────────────────────
info "Enabling eBPF JIT..."
sysctl -w net.core.bpf_jit_enable=1 2>/dev/null || warn "Could not enable bpf_jit (may already be enabled)"
sysctl -w net.core.bpf_jit_harden=0 2>/dev/null || true

# Make persistent
echo "net.core.bpf_jit_enable = 1" >> /etc/sysctl.d/99-kelan.conf 2>/dev/null || true

# Mount BPF FS if not mounted
if ! mount | grep -q "bpf on /sys/fs/bpf"; then
  info "Mounting BPF filesystem..."
  mount -t bpf none /sys/fs/bpf 2>/dev/null || warn "Could not mount BPF FS"
fi

# ── 7. Build ──────────────────────────────────────────────────────────────────
info "Building Kelan (release, may take 2-5 min on first build)..."

cargo build --release -p aitp-server -p kelan-ebpf-loader 2>&1 | \
  grep -E "(Compiling|Finished|error)" || true

if [ ! -f ./target/release/aitp_server ]; then
  error "Build failed. Check output above."
  exit 1
fi

info "Build complete."

# ── 8. Run doctor again with proper binaries ──────────────────────────────────
info "Running post-build diagnostics..."
./target/release/kelan-doctor || true  # doctor exit codes are informational

# ── 9. Try to load eBPF XDP ──────────────────────────────────────────────────
EBPF_IFACE="${NETWORK_INTERFACE:-eth0}"

if [ -f ./target/bpfel-unknown-none/release/kelan_xdp ]; then
  info "Loading eBPF XDP onto $EBPF_IFACE..."
  # Attempt eBPF load — requires bpf-linker feature and root
  if ./target/release/kelan-ebpf-loader --load --iface "$EBPF_IFACE" 2>/dev/null; then
    info "✅ eBPF mode ACTIVE on $EBPF_IFACE"
  else
    warn "eBPF load failed — software enforcement active (XDP rate limiting will run in userspace)"
  fi
else
  warn "eBPF object not built (requires bpf-linker + nightly). Software enforcement active."
  warn "To enable native eBPF: cargo install bpf-linker && cargo xtask build-ebpf"
fi

# ── 10. Create systemd service ────────────────────────────────────────────────
info "Installing systemd service..."

INSTALL_DIR="$(pwd)"
cat > /etc/systemd/system/kelan.service << EOF
[Unit]
Description=Kelan Security Intelligence Core
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=${INSTALL_DIR}
ExecStartPre=${INSTALL_DIR}/target/release/kelan-doctor
ExecStart=${INSTALL_DIR}/target/release/aitp_server
Restart=on-failure
RestartSec=10
StandardOutput=journal
StandardError=journal
AmbientCapabilities=CAP_SYS_ADMIN CAP_NET_ADMIN CAP_BPF CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_SYS_ADMIN CAP_NET_ADMIN CAP_BPF CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable kelan

echo ""
echo "────────────────────────────────────────────"
info "✅ Installation complete!"
echo ""
echo "  Start server:  systemctl start kelan"
echo "  View logs:     journalctl -fu kelan"
echo "  Diagnostics:   ./target/release/kelan-doctor"
echo "  API:           http://localhost:3000/health"
echo "────────────────────────────────────────────"
