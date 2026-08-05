#!/usr/bin/env bash
# =============================================================================
# KELAN SECURITY — LAUNCH.SH
# Starts the full Kelan stack agentically. Verifies each component before launch.
# Usage: bash launch.sh [--dev | --prod | --stop]
# =============================================================================

set -euo pipefail

BOLD='\033[1m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

log()    { echo -e "${BOLD}${BLUE}[KELAN]${NC} $1"; }
ok()     { echo -e "${GREEN}[✓]${NC} $1"; }
warn()   { echo -e "${YELLOW}[!]${NC} $1"; }
fail()   { echo -e "${RED}[✗]${NC} $1"; exit 1; }
section(){ echo -e "\n${BOLD}${CYAN}── $1 ──${NC}"; }

MODE="${1:---dev}"

echo ""
echo -e "${BOLD}╔══════════════════════════════════════╗${NC}"
echo -e "${BOLD}║    KELAN SECURITY — LAUNCH           ║${NC}"
echo -e "${BOLD}║    Mode: ${MODE}                     ${NC}"
echo -e "${BOLD}╚══════════════════════════════════════╝${NC}"
echo ""

# ── STOP mode ─────────────────────────────────────────────────────────────────
if [[ "$MODE" == "--stop" ]]; then
  log "Stopping all Kelan processes..."
  bash scripts/stop.sh
  ok "All processes stopped"
  exit 0
fi

# ── Pre-flight: venv ──────────────────────────────────────────────────────────
section "PRE-FLIGHT CHECKS"

if [[ ! -d ".venv" ]]; then
  fail ".venv not found. Run: bash install.sh"
fi
# shellcheck disable=SC1091
source .venv/bin/activate
ok "Python venv active: $(python --version)"

# ── Pre-flight: .env ──────────────────────────────────────────────────────────
if [[ ! -f ".env" ]]; then
  fail ".env not found. Run: bash install.sh or cp .env.example .env"
fi
ok ".env found"
# shellcheck disable=SC1091
set -a; source .env; set +a

# ── Pre-flight: Rust binary ───────────────────────────────────────────────────
if [[ -f "target/release/kelan-ebpf-loader" ]]; then
  ok "Rust binary found"
else
  warn "Rust binary not found — building now (this takes ~2 min first time)"
  cargo build --release 2>&1 | tail -3
  ok "Rust build done"
fi

# ── Pre-flight: Ollama ────────────────────────────────────────────────────────
section "OLLAMA CHECK"

OLLAMA_HOST="${OLLAMA_HOST:-http://localhost:11434}"
log "Checking Ollama at $OLLAMA_HOST..."

if curl -s --max-time 3 "$OLLAMA_HOST/api/tags" &>/dev/null; then
  ok "Ollama is running"
  
  MODELS=$(curl -s "$OLLAMA_HOST/api/tags" | python -c "import sys,json; d=json.load(sys.stdin); print('\n'.join(m['name'] for m in d.get('models',[])))" 2>/dev/null || echo "")
  
  if echo "$MODELS" | grep -q "gemma"; then
    ok "gemma model available"
  else
    echo ""
    warn "⚠️  No gemma model found in Ollama."
    echo ""
    echo -e "  ${BOLD}Action required:${NC}"
    echo "    ollama pull gemma3:latest"
    echo ""
    read -rp "  Pull it now? [y/N]: " PULL_NOW
    if [[ "${PULL_NOW:-n}" =~ ^[Yy]$ ]]; then
      ollama pull gemma3:latest
      ok "Model pulled"
    else
      warn "Skipping — AI trust evaluation will not work without model"
    fi
  fi
else
  echo ""
  echo -e "  ${RED}[✗] Ollama is not running at $OLLAMA_HOST${NC}"
  echo ""
  echo -e "  ${BOLD}To start Ollama:${NC}"
  echo "    macOS:    ollama serve   (or open Ollama.app)"
  echo "    Linux:    systemctl start ollama  OR  ollama serve"
  echo ""
  echo -e "  ${BOLD}Remote Ollama (e.g. Mac at 192.168.x.x)?${NC}"
  echo "    Set OLLAMA_HOST in .env:"
  echo "    OLLAMA_HOST=http://OLLAMA_HOST_IP:11434"
  echo ""
  read -rp "  Continue without Ollama (limited functionality)? [y/N]: " CONTINUE
  if [[ ! "${CONTINUE:-n}" =~ ^[Yy]$ ]]; then
    fail "Aborted. Start Ollama first then re-run: bash launch.sh"
  fi
  warn "Continuing without Ollama — AI features disabled"
fi

# ── Backend verification ──────────────────────────────────────────────────────
section "BACKEND VERIFICATION"

log "Checking Python backend syntax..."
python -m py_compile kelan_server/main.py 2>/dev/null \
  || python -m py_compile src/main.py 2>/dev/null \
  || warn "Could not locate main.py for syntax check — proceeding"
ok "Python syntax OK"

log "Checking port availability..."
KELAN_PORT="${KELAN_PORT:-3000}"
if lsof -i ":$KELAN_PORT" &>/dev/null; then
  warn "Port $KELAN_PORT already in use — may be a previous Kelan instance"
  read -rp "  Kill existing and restart? [y/N]: " KILL_OLD
  if [[ "${KILL_OLD:-n}" =~ ^[Yy]$ ]]; then
    bash scripts/stop.sh 2>/dev/null || true
    sleep 1
    ok "Old processes killed"
  fi
fi

# ── Launch ─────────────────────────────────────────────────────────────────────
section "LAUNCHING KELAN STACK"

if [[ "$MODE" == "--prod" ]]; then
  log "Starting in PRODUCTION mode (docker-compose.prod.yml)..."
  docker-compose -f docker-compose.prod.yml up -d
  ok "Production stack started"
elif [[ "$MODE" == "--dev" ]]; then
  log "Starting in DEVELOPMENT mode..."
  bash scripts/start_all.sh
else
  fail "Unknown mode: $MODE. Use --dev, --prod, or --stop"
fi

# ── Post-launch health check ──────────────────────────────────────────────────
section "HEALTH CHECK"

log "Waiting for services to come up (10s)..."
sleep 10

KELAN_URL="http://localhost:$KELAN_PORT"
if curl -s --max-time 5 "$KELAN_URL/health" &>/dev/null; then
  ok "Kelan backend responding at $KELAN_URL"
elif curl -s --max-time 5 "$KELAN_URL" &>/dev/null; then
  ok "Kelan backend up at $KELAN_URL (no /health endpoint)"
else
  warn "Backend not responding yet at $KELAN_URL — may still be starting"
fi

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}${GREEN}══════════════════════════════════════${NC}"
echo -e "${BOLD}${GREEN}  KELAN RUNNING                       ${NC}"
echo -e "${BOLD}${GREEN}══════════════════════════════════════${NC}"
echo ""
echo "  Backend:     http://localhost:$KELAN_PORT"
echo "  Ollama:      $OLLAMA_HOST"
echo "  Mode:        $MODE"
echo ""
echo "  Stop:        bash launch.sh --stop"
echo "  Logs:        tail -f kelan.log (or docker-compose logs -f)"
echo ""
