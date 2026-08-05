#!/bin/bash
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR/.."
echo "Stopping Kelan Security..."

# Kill server processes by name
pkill -f aitp_server 2>/dev/null || true
pkill -f aitp-server 2>/dev/null || true
pkill -f start_server.py 2>/dev/null || true
pkill -f uvicorn 2>/dev/null || true
pkill -f ttyd 2>/dev/null || true
pkill -f dashboard_server.py 2>/dev/null || true

# Kill by PID file
if [ -f .kelan.pid ]; then
    while read pid; do
        kill $pid 2>/dev/null || true
    done < .kelan.pid
    rm -f .kelan.pid
fi

# Stop docker
docker compose -f yml/docker-compose.yml -f yml/docker-compose.dev.yml down --remove-orphans

echo -e "✓ All services stopped"
