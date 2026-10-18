#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────
#  AITP Stack Validation Script
#  Run after: docker compose up --build -d
#  Validates the entire stack is working end-to-end.
# ──────────────────────────────────────────────────────────────

set -uo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
NC='\033[0m'

PASS=0
FAIL=0
WARN=0

# Use a simpler check function that takes the exit status directly
report() {
    local status=$1
    local desc=$2
    local critical=${3:-true}

    if [ $status -eq 0 ]; then
        echo -e "  ${GREEN}✓${NC} ${desc}"
        ((PASS++))
    else
        if [ "$critical" = "true" ]; then
            echo -e "  ${RED}✗${NC} ${desc}"
            ((FAIL++))
        else
            echo -e "  ${YELLOW}⚠${NC} ${desc} (non-critical)"
            ((WARN++))
        fi
    fi
}

echo ""
echo -e "${CYAN}════════════════════════════════════════════════${NC}"
echo -e "${CYAN}        AITP Stack Validation${NC}"
echo -e "${CYAN}════════════════════════════════════════════════${NC}"
echo ""

# ── 1. Docker containers ──────────────────────────────────────
echo -e "${CYAN}▶ Docker Containers${NC}"

docker inspect --format='{{.State.Running}}' aitp-control-plane 2>/dev/null | grep -q true
report $? "aitp-control-plane is running"

docker inspect --format='{{.State.Running}}' aitp-node-alpha 2>/dev/null | grep -q true
report $? "aitp-node-alpha is running"

docker inspect --format='{{.State.Running}}' aitp-node-beta 2>/dev/null | grep -q true
report $? "aitp-node-beta is running"

docker inspect --format='{{.State.Running}}' aitp-prometheus 2>/dev/null | grep -q true
report $? "aitp-prometheus is running"

docker inspect --format='{{.State.Running}}' aitp-grafana 2>/dev/null | grep -q true
report $? "aitp-grafana is running"

echo ""

# ── 2. Service health ─────────────────────────────────────────
echo -e "${CYAN}▶ Service Health${NC}"

curl -sf http://localhost:8080/health >/dev/null
report $? "Control plane health endpoint" false

curl -sf http://localhost:9090/-/healthy >/dev/null
report $? "Prometheus is reachable" false

curl -sf http://localhost:3000/api/health >/dev/null
report $? "Grafana is reachable"

echo ""

# ── 3. Prometheus scraping ────────────────────────────────────
echo -e "${CYAN}▶ Prometheus Metrics${NC}"

curl -sf "http://localhost:9090/api/v1/targets" | grep -q '"activeTargets"'
report $? "Prometheus has scrape targets" false

curl -sf "http://localhost:9090/api/v1/query?query=up" | grep -q '"success"'
report $? "AITP metrics available" false

echo ""

# ── 4. Grafana dashboards ────────────────────────────────────
echo -e "${CYAN}▶ Grafana Dashboards${NC}"

curl -sf "http://localhost:3000/api/dashboards/uid/aitp-overview" | grep -q '"title"'
report $? "AITP Overview dashboard provisioned" false

echo ""

# ── 5. Network connectivity ──────────────────────────────────
echo -e "${CYAN}▶ Network${NC}"

docker exec aitp-node-alpha curl -sf http://172.20.0.10:8080/health >/dev/null
report $? "Node alpha can reach control plane" false

docker exec aitp-node-beta curl -sf http://172.20.0.10:8080/health >/dev/null
report $? "Node beta can reach control plane" false

echo ""

# ── Summary ──────────────────────────────────────────────────
echo -e "${CYAN}════════════════════════════════════════════════${NC}"
echo -e "  ${GREEN}Passed:${NC}  ${PASS}"
echo -e "  ${YELLOW}Warned:${NC}  ${WARN}"
echo -e "  ${RED}Failed:${NC}  ${FAIL}"
echo -e "${CYAN}════════════════════════════════════════════════${NC}"
echo ""

if [ "$FAIL" -eq 0 ]; then
    echo -e "${GREEN}All critical checks passed!${NC}"
else
    echo -e "${RED}${FAIL} check(s) failed.${NC}"
fi

echo ""
echo -e "  Grafana:       ${CYAN}http://localhost:3000${NC}  (admin / aitp_admin)"
echo -e "  Prometheus:    ${CYAN}http://localhost:9090${NC}"
echo -e "  Control Plane: ${CYAN}http://localhost:8080${NC}"
echo ""

[ "$FAIL" -eq 0 ]
