#!/usr/bin/env bash
# =============================================================================
# KELAN SECURITY — INSTALL.SH
# Run once after cloning. Sets up everything: Python venv, Rust, Ollama check.
# Usage: bash install.sh
# =============================================================================

set -euo pipefail

BOLD='\033[1m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

log()  { echo -e "${BOLD}${BLUE}[KELAN]${NC} $1"; }
ok()   { echo -e "${GREEN}[✓]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
fail() { echo -e "${RED}[✗]${NC} $1"; exit 1; }

echo ""
echo -e "${BOLD}╔══════════════════════════════════════╗${NC}"
echo -e "${BOLD}║    KELAN SECURITY — INSTALLER        ║${NC}"
echo -e "${BOLD}║    Adaptive Intent Transport Protocol ║${NC}"
echo -e "${BOLD}╚══════════════════════════════════════╝${NC}"
echo ""

# ── 1. Python check ──────────────────────────────────────────────────────────
log "Checking Python version..."
PYTHON_CMD=""
for cmd in python3.12 python3.11 python3.10 python3; do
  if command -v "$cmd" &>/dev/null; then
    PY_VER=$("$cmd" --version 2>&1 | awk '{print $2}')
    MAJOR=$(echo "$PY_VER" | cut -d. -f1)
    MINOR=$(echo "$PY_VER" | cut -d. -f2)
    if [[ "$MAJOR" -eq 3 && "$MINOR" -ge 10 && "$MINOR" -le 12 ]]; then
      PYTHON_CMD="$cmd"
      ok "Using $cmd ($PY_VER)"
      break
    fi
  fi
done

if [[ -z "$PYTHON_CMD" ]]; then
  fail "No compatible Python found (need 3.10–3.12). Install via: brew install python@3.12"
fi

# ── 2. Create venv ───────────────────────────────────────────────────────────
log "Creating Python virtual environment (.venv)..."
if [[ -d ".venv" ]]; then
  warn ".venv already exists — skipping creation"
else
  "$PYTHON_CMD" -m venv .venv
  ok "Created .venv"
fi

# ── 3. Activate venv ─────────────────────────────────────────────────────────
log "Activating .venv..."
# shellcheck disable=SC1091
source .venv/bin/activate
ok "venv active: $(python --version)"

# ── 4. Upgrade pip ───────────────────────────────────────────────────────────
log "Upgrading pip..."
pip install --upgrade pip --quiet
ok "pip upgraded"

# ── 5. Install Python requirements ───────────────────────────────────────────
log "Installing Python requirements..."
if [[ -f "requirements.txt" ]]; then
  pip install -r requirements.txt
  ok "Python requirements installed"
else
  warn "requirements.txt not found — skipping"
fi

# ── 6. Rust / Cargo check ────────────────────────────────────────────────────
log "Checking Rust toolchain..."
if command -v cargo &>/dev/null; then
  RUST_VER=$(rustc --version)
  ok "Rust found: $RUST_VER"
else
  warn "Rust not found. Installing via rustup..."
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
  # shellcheck disable=SC1091
  source "$HOME/.cargo/env"
  ok "Rust installed: $(rustc --version)"
fi

# ── 7. Build Rust/eBPF components ────────────────────────────────────────────
log "Building Rust components..."
if [[ -f "Cargo.toml" ]]; then
  cargo build --release 2>&1 | tail -5
  ok "Rust build complete"
else
  warn "Cargo.toml not found — skipping Rust build"
fi

# ── 8. Ollama check ──────────────────────────────────────────────────────────
log "Checking Ollama..."
if command -v ollama &>/dev/null; then
  ok "Ollama installed: $(ollama --version 2>/dev/null || echo 'version unknown')"
  
  # Check if ollama is running
  if curl -s http://localhost:11434/api/tags &>/dev/null; then
    ok "Ollama is running"
    
    # Check for required model
    if ollama list 2>/dev/null | grep -q "gemma"; then
      ok "gemma model found"
    else
      warn "gemma model not found. Pull it with:"
      echo "    ollama pull gemma3:latest"
    fi
  else
    warn "Ollama is installed but not running."
    echo ""
    echo "    Start Ollama:      ollama serve"
    echo "    Pull model:        ollama pull gemma3:latest"
    echo ""
  fi
else
  warn "Ollama not installed."
  echo ""
  echo "    Install:    brew install ollama   (macOS)"
  echo "                curl -fsSL https://ollama.com/install.sh | sh  (Linux)"
  echo "    Then run:   ollama pull gemma3:latest"
  echo ""
fi

# ── 9. .env check ────────────────────────────────────────────────────────────
log "Checking environment config..."
if [[ ! -f ".env" ]]; then
  if [[ -f ".env.example" ]]; then
    cp .env.example .env
    warn ".env created from .env.example — edit it before running launch.sh"
  else
    warn ".env not found and no .env.example to copy from"
  fi
else
  ok ".env exists"
fi

# ── 10. Summary ──────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}${GREEN}══════════════════════════════════════${NC}"
echo -e "${BOLD}${GREEN}  KELAN INSTALL COMPLETE              ${NC}"
echo -e "${BOLD}${GREEN}══════════════════════════════════════${NC}"
echo ""
echo "  Next steps:"
echo "    1. Edit .env with your config"
echo "    2. Ensure Ollama is running:  ollama serve"
echo "    3. Pull model if needed:      ollama pull gemma3:latest"
echo "    4. Launch Kelan:              bash launch.sh"
echo ""
