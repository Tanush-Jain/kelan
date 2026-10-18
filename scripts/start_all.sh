#!/usr/bin/env bash
# AITP Master Orchestrator — Starts backend, frontend, and infrastructure.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Force working directory to repository root
cd "$SCRIPT_DIR/.."

BOLD='\033[1m'
GREEN='\033[0;32m'
AMBER='\033[0;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BOLD}╔══════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║        AITP Full Stack Orchestrator         ║${NC}"
echo -e "${BOLD}╚══════════════════════════════════════════════╝${NC}"

# 1. Cleanup existing processes
echo -e "${AMBER}Cleaning up stale local processes...${NC}"
# Kill frontend (Vite/npm)
FE_PID=$(lsof -t -i:5173 2>/dev/null || true)
if [ -n "$FE_PID" ]; then
    echo -e "  Killing frontend on port 5173 (PID $FE_PID)..."
    kill -9 $FE_PID 2>/dev/null || true
fi

# Kill backend via its own script
./scripts/stop.sh > /dev/null 2>&1 || true

# 2. Infrastructure (Docker)
if [ "$1" == "--docker" ] || [ "$AITP_USE_DOCKER" == "true" ]; then
    echo -e "${AMBER}Checking Docker infrastructure...${NC}"
    
    # Try to resolve Mac socket issues by setting common paths
    if [ "$(uname)" == "Darwin" ]; then
        export DOCKER_HOST="unix://$HOME/.docker/run/docker.sock"
    fi

    if docker compose version >/dev/null 2>&1; then
        echo -e "  Starting containers..."
        docker compose -f yml/docker-compose.yml -f yml/docker-compose.dev.yml up -d --build || {
            echo -e "${RED}⚠️ Docker connection failed.${NC}"
            echo -e "It looks like your Docker CLI can't talk to Docker Desktop."
            echo -e "Please ${BOLD}Manually Stop${NC} the 'aitp' containers in Docker Desktop UI to free up port 3000."
        }
    else
        echo -e "${RED}⚠️ Docker CLI not found or unreachable.${NC}"
        echo -e "Please ensure Docker Desktop is running. Proceeding with local stack only..."
    fi
fi

# 3. Backend (Intelligence Core)
echo -e "${AMBER}Starting Intelligence Core (Backend)...${NC}"
# We don't exit on error here because we want to see the "Address already in use" if it happens
./scripts/start.sh start || {
    echo -e "${RED}❌ Backend failed to start.${NC}"
    if lsof -i :3000 >/dev/null 2>&1; then
        echo -e "${RED}Reason: Port 3000 is still occupied.${NC}"
        echo -e "Check your Docker Desktop and stop the 'grafana' container."
    fi
    exit 1
}

# 4. Frontend (Admin Dashboard)
echo -e "${AMBER}Starting Admin Dashboard (Frontend)...${NC}"
cd ../kelan-web
# Run in background, redirect logs
npm run dev -- --port 5173 > ../kelan-core/log/aitp_frontend.log 2>&1 &
echo -e "${GREEN}✓ Frontend starting at http://localhost:5173${NC}"
cd ../kelan-core

# 5. Final Status
echo ""
echo -e "${GREEN}${BOLD}🚀 AITP STACK IS READY${NC}"
echo ""
echo "  Intelligence Core: http://localhost:3000"
echo "  Admin Dashboard:   http://localhost:5173"
if [ "$1" == "--docker" ]; then
    echo "  Grafana Metrics:   http://localhost:3001"
    echo "  Control Plane:     http://localhost:8080"
fi
echo ""
echo -e "${BLUE}Logs:${NC}"
echo "  Backend:  tail -f log/kelan-server.log"
echo "  Frontend: tail -f log/aitp_frontend.log"
echo ""
echo -e "${AMBER}Run simulations:${NC} ./scripts/simulate_attacks.sh"
echo ""
