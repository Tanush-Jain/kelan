#!/bin/bash
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Force working directory to repository root
cd "$SCRIPT_DIR/.."

# Pre-flight: check Ollama is reachable
OLLAMA_EP=${OLLAMA_ENDPOINT:-http://localhost:11434}
echo "Checking Ollama AI engine at $OLLAMA_EP..."
if ! curl -s --max-time 5 "$OLLAMA_EP/api/tags" > /dev/null 2>&1; then
  echo ""
  echo -e "${YELLOW}⚠️  WARNING: Ollama not reachable at $OLLAMA_EP${NC}"
  echo "   The server will start but AI trust will use fallback rules."
  echo ""
  echo "   To enable full AI trust evaluation:"
  echo "   1. On your Mac: OLLAMA_HOST=0.0.0.0 ollama serve"
  echo "   2. Pull model: ollama pull gemma3:9b"
  echo "   3. Set in .env: OLLAMA_ENDPOINT=http://<MAC-IP>:11434"
  echo ""
else
  echo "✅ Ollama reachable"
  # Show which model will be used
  MODEL=${OLLAMA_MODEL:-gemma3:9b}
  echo "   Model: $MODEL"
fi

echo -e "${BLUE}"
echo "╔═══════════════════════════════════════╗"
echo "║     KELAN SECURITY v0.3.0             ║"
echo "║     Kernel-Level Agentic Network      ║"
echo "║     Security System                   ║"
echo "╚═══════════════════════════════════════╝"
echo -e "${NC}"

# ── Prerequisites Check ──────────────────────
echo -e "${YELLOW}[1/6] Checking prerequisites...${NC}"

check_cmd() {
    if ! command -v $1 &> /dev/null; then
        echo -e "${RED}✗ $1 not found. Install it first.${NC}"
        exit 1
    else
        echo -e "${GREEN}✓ $1 found${NC}"
    fi
}

check_cmd cargo
check_cmd docker
check_cmd curl
check_cmd node   # for web terminal

# Check .env exists
if [ ! -f .env ]; then
    echo -e "${YELLOW}No .env found. Creating from template...${NC}"
    cp .env.example .env
    echo -e "${GREEN}Created .env file. Running with local Ollama defaults.${NC}"
fi

source .env

# ── Build ────────────────────────────────────
echo -e "${YELLOW}[2/6] Building workspace...${NC}"

cargo build --release --workspace 2>&1 | \
    grep -E "Compiling|Finished|error" || true

if [ ${PIPESTATUS[0]} -ne 0 ]; then
    echo -e "${RED}✗ Build failed${NC}"
    exit 1
fi
echo -e "${GREEN}✓ Build complete${NC}"

# ── Start Infrastructure ─────────────────────
echo -e "${YELLOW}[3/6] Starting infrastructure...${NC}"

# Clean up any orphans first
docker compose -f yml/docker-compose.yml -f yml/docker-compose.dev.yml down --remove-orphans 2>/dev/null \
    || true

# Start all infrastructure including postgres
docker compose -f yml/docker-compose.yml -f yml/docker-compose.dev.yml up -d postgres prometheus grafana

# Wait for postgres specifically
echo "Waiting for PostgreSQL to be ready..."
POSTGRES_READY=false
for i in {1..30}; do
    if docker compose -f yml/docker-compose.yml -f yml/docker-compose.dev.yml exec -T postgres \
        pg_isready -U kelan 2>/dev/null; then
        POSTGRES_READY=true
        break
    fi
    echo "  Postgres starting... ($i/30)"
    sleep 2
done

if [ "$POSTGRES_READY" = false ]; then
    echo -e "${RED}✗ PostgreSQL failed to start${NC}"
    docker compose -f yml/docker-compose.yml -f yml/docker-compose.dev.yml logs postgres | tail -20
    exit 1
fi

echo -e "${GREEN}✓ PostgreSQL ready${NC}"
sleep 2
echo -e "${GREEN}✓ Infrastructure ready${NC}"

# ── Start Kelan Server ───────────────────────
echo -e "${YELLOW}[4/6] Starting Kelan AITP server...${NC}"

mkdir -p log

# Find correct python interpreter
if [ -f "../venv/bin/python" ]; then
    PYTHON_BIN="../venv/bin/python"
elif [ -f "./venv/bin/python" ]; then
    PYTHON_BIN="./venv/bin/python"
elif [ -f ".venv/bin/python" ]; then
    PYTHON_BIN=".venv/bin/python"
else
    PYTHON_BIN="python3"
fi

echo "Using Python: $PYTHON_BIN"

# Start server
RUST_LOG=info,aitp_server=debug,kelan=debug \
    "$PYTHON_BIN" scripts/start_server.py \
    > log/kelan-server.log 2>&1 &

SERVER_PID=$!
echo $SERVER_PID > .kelan.pid

# Show initial logs immediately
sleep 2
echo "Server startup log:"
cat log/kelan-server.log

# Show bound ports
echo "Bound ports:"
lsof -i :3000 2>/dev/null | head -3
lsof -i :9999 2>/dev/null | head -3
lsof -p $SERVER_PID 2>/dev/null | \
    grep -E "TCP|UDP" | head -5

# Wait for HTTP health check
echo "Waiting for server to be ready..."
HTTP_PORT=${HTTP_PORT:-3000}

for i in {1..60}; do
    if curl -s \
        http://localhost:$HTTP_PORT/health \
        > /dev/null 2>&1; then
        echo -e "${GREEN}✓ Server ready (PID: $SERVER_PID)${NC}"
        break
    fi
    
    if [ $((i % 10)) -eq 0 ]; then
        echo "  Still waiting... ($i/60)"
        echo "  Last log: $(tail -1 log/kelan-server.log)"
    fi
    
    # Check if process died
    if ! kill -0 $SERVER_PID 2>/dev/null; then
        echo -e "${RED}✗ Server process died${NC}"
        echo "Full log:"
        cat log/kelan-server.log
        exit 1
    fi
    
    sleep 1
done

# ── Setup Command Center Dashboard ───────────
echo -e "${GREEN}✓ Command Center Dashboard configured at log/terminal.html${NC}"

# ── Start Dashboard ──────────────────────────
if [ -d "../kelan-web" ] || [ -d "dashboard" ] || [ -d "frontend" ] || [ -d "aitp-dashboard" ]; then
    echo -e "${YELLOW}Starting dashboard...${NC}"
    
    if [ -d "../kelan-web" ]; then
        DASH_DIR="../kelan-web"
    else
        DASH_DIR=$([ -d "aitp-dashboard" ] && echo "aitp-dashboard" || ([ -d "dashboard" ] && echo "dashboard" || echo "frontend"))
    fi
    
    if [ -f "$DASH_DIR/package.json" ]; then
        LOGS_DIR="$(pwd)/log"
        cd "$DASH_DIR"
        npm install --silent
        npm run dev > "$LOGS_DIR/dashboard.log" 2>&1 &
        DASH_PID=$!
        echo $DASH_PID >> "$LOGS_DIR/../.kelan.pid"
        cd - >/dev/null
        
        sleep 3
        echo -e "${GREEN}✓ Dashboard starting...${NC}"
    else
        echo -e "${YELLOW}⚠ Dashboard directory found, but package.json is missing in $DASH_DIR. Skipping...${NC}"
    fi
fi

# ── Run Verification Tests ───────────────────
echo -e "${YELLOW}[6/6] Running live verification...${NC}"
echo ""

# Small delay to ensure everything is up
sleep 2

./scripts/verify_python.sh

echo ""
echo -e "${GREEN}═══════════════════════════════════${NC}"
echo -e "${GREEN}  KELAN SECURITY IS RUNNING        ${NC}"
echo -e "${GREEN}═══════════════════════════════════${NC}"
echo ""
echo "  🌐 Dashboard:      http://localhost:3000"
echo "  📺 Command Center: log/terminal.html"
echo "  📊 Grafana:        http://localhost:3003"
echo "  📈 Prometheus:     http://localhost:9090"
echo ""
echo "  To stop everything: ./scripts/stop.sh"
echo ""

# Open browser automatically
sleep 2

if [[ "$OSTYPE" == "darwin"* ]]; then
    open http://localhost:3000 &
elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
    xdg-open http://localhost:3000 &
fi

# Also open the terminal HTML page
if [ -f "log/terminal.html" ]; then
    if [[ "$OSTYPE" == "darwin"* ]]; then
        open log/terminal.html
    else
        xdg-open log/terminal.html
    fi
fi
