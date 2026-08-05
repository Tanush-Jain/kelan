#!/usr/bin/env bash
# AITP Attack Simulation Suite
# ─────────────────────────────────────────────────────────────────────────────

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR/.."

# Source .env to get OLLAMA_ENDPOINT
if [ -f .env ]; then
  # Use a simpler way to source that handles potential spaces/comments
  export $(grep -v '^#' .env | xargs)
fi

BASE="http://localhost:3000/api"
GREEN='\033[0;32m'
RED='\033[0;31m'
AMBER='\033[0;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

echo ""
echo -e "${BOLD}╔══════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║        AITP Attack Simulation Suite v0.3            ║${NC}"
echo -e "${BOLD}╚══════════════════════════════════════════════════════╝${NC}"
echo ""

# ── Auth (Create account and get token) ──────────────────────────────────────
UNIQUE_ID=$(date +%s)
EMAIL="sim_${UNIQUE_ID}@kelan.io"
PASS="SimPass123!"

echo -e "${BLUE}[AUTH]${NC} Registering as $EMAIL..."
RESPONSE=$(curl -s -X POST $BASE/auth/signup \
  -H 'Content-Type: application/json' \
  -d "{\"org_name\":\"Simulation Org\",\"email\":\"$EMAIL\",\"password\":\"$PASS\"}")

TOKEN=$(echo $RESPONSE | jq -r '.token')

if [ -z "$TOKEN" ] || [ "$TOKEN" = "null" ]; then
  echo -e "${RED}ERROR: Could not register user. check server logs.${NC}"
  echo "DEBUG Response: $RESPONSE"
  exit 1
fi

echo -e "${BLUE}[AUTH]${NC} Authenticated successfully."

auth() { curl -s -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' "$@"; }

# ── Setup test entities ───────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}=== SETUP: Creating test entities ===${NC}"

# Legitimate workstation
ENTITY_A=$(auth -X POST $BASE/entities \
  -d '{"name":"workstation-engineering-01","entity_type":"workstation",
       "department":"Engineering","clearance_level":1}' | jq -r '.entity_id')

# Legitimate internal service
ENTITY_B=$(auth -X POST $BASE/entities \
  -d '{"name":"ml-inference-service-03","entity_type":"service",
       "department":"AI","clearance_level":1}' | jq -r '.entity_id')

# Sensitive database
ENTITY_C=$(auth -X POST $BASE/entities \
  -d '{"name":"finance-database-prod","entity_type":"server",
       "department":"Finance","clearance_level":3}' | jq -r '.entity_id')

if [ "$ENTITY_A" = "null" ] || [ -z "$ENTITY_A" ]; then
  echo -e "${RED}ERROR: Entity creation failed. Check server logs.${NC}"
  exit 1
fi

echo -e "  Created workstation: ${ENTITY_A:0:16}..."
echo -e "  Created service:     ${ENTITY_B:0:16}..."
echo -e "  Created database:    ${ENTITY_C:0:16}..."

sleep 1

# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}═══════════════════════════════════════════════════════${NC}"
echo -e "${BOLD} ATTACK 1 — Legitimate Session (baseline)             ${NC}"
echo -e "${BOLD}═══════════════════════════════════════════════════════${NC}"
echo "Scenario: Engineering workstation → ModelInference → ml-inference-service"
echo ""

RESULT=$(auth -X POST $BASE/entities/$ENTITY_A/test-session \
  -d "{\"dest_entity_id\":\"$ENTITY_B\",\"intent\":\"ModelInference\"}")

echo "$RESULT" | jq '.'
echo ""

# ─────────────────────────────────────────────────────────────────────────────
echo -e "${BOLD}═══════════════════════════════════════════════════════${NC}"
echo -e "${BOLD} ATTACK 2 — Unknown/Unregistered Entity               ${NC}"
echo -e "${BOLD}═══════════════════════════════════════════════════════${NC}"
echo "Scenario: Unregistered device tries to connect"
echo ""

FAKE_ID="deadbeef$(openssl rand -hex 28)"
RESULT=$(auth -X POST $BASE/entities/$FAKE_ID/test-session \
  -d "{\"dest_entity_id\":\"$ENTITY_C\",\"intent\":\"DataSync\"}")

echo "$RESULT" | jq '.'
echo ""

# ─────────────────────────────────────────────────────────────────────────────
echo -e "${BOLD}═══════════════════════════════════════════════════════${NC}"
echo -e "${BOLD} ATTACK 3 — Clearance Violation                       ${NC}"
echo -e "${BOLD}═══════════════════════════════════════════════════════${NC}"
echo "Scenario: Clearance-1 workstation → clearance-3 finance database"
echo ""

RESULT=$(auth -X POST $BASE/entities/$ENTITY_A/test-session \
  -d "{\"dest_entity_id\":\"$ENTITY_C\",\"intent\":\"DataSync\"}")

echo "$RESULT" | jq '.'
echo ""

# ─────────────────────────────────────────────────────────────────────────────
echo -e "${BOLD}═══════════════════════════════════════════════════════${NC}"
echo -e "${BOLD} ATTACK 4 — ControlSignal Abuse                       ${NC}"
echo -e "${BOLD}═══════════════════════════════════════════════════════${NC}"
echo "Scenario: AI inference service declares ControlSignal intent"
echo ""

RESULT=$(auth -X POST $BASE/entities/$ENTITY_B/test-session \
  -d "{\"dest_entity_id\":\"$ENTITY_C\",\"intent\":\"ControlSignal\"}")

echo "$RESULT" | jq '.'
echo ""

# ─────────────────────────────────────────────────────────────────────────────
echo -e "${BOLD}═══════════════════════════════════════════════════════${NC}"
echo -e "${BOLD} ATTACK 5 — Lateral Movement (Compromised Service)    ${NC}"
echo -e "${BOLD}═══════════════════════════════════════════════════════${NC}"
echo "Scenario: ml-inference-service (compromised) → finance-database"
echo ""

RESULT=$(auth -X POST $BASE/entities/$ENTITY_B/test-session \
  -d "{\"dest_entity_id\":\"$ENTITY_C\",\"intent\":\"DataSync\", \"simulate_lateral_movement\":true}")

echo "$RESULT" | jq '.'
echo ""

# ─────────────────────────────────────────────────────────────────────────────
echo -e "${BOLD}═══════════════════════════════════════════════════════${NC}"
echo -e "${BOLD} ATTACK 6 — Data Exfiltration Pattern                 ${NC}"
echo -e "${BOLD}═══════════════════════════════════════════════════════${NC}"
echo "Scenario: Massive data transfer"
echo ""

RESULT=$(auth -X POST $BASE/entities/$ENTITY_A/test-session \
  -d "{\"dest_entity_id\":\"$ENTITY_B\",\"intent\":\"FileTransfer\", \"bytes_tx\":100000000}")

echo "$RESULT" | jq '.'

echo "Checking sentinel anomalies..."
auth GET "$BASE/sentinel/anomalies" | jq '.' | head -10
echo ""

# ─────────────────────────────────────────────────────────────────────────────
echo -e "${BOLD}═══════════════════════════════════════════════════════${NC}"
echo -e "${BOLD} ATTACK 7 — DDoS Flood Simulation                     ${NC}"
echo -e "${BOLD}═══════════════════════════════════════════════════════${NC}"
echo ""

echo "Sending 10 rapid sessions..."
for i in $(seq 1 10); do
  auth -X POST $BASE/entities/$ENTITY_A/test-session \
    -d "{\"dest_entity_id\":\"$ENTITY_B\",\"intent\":\"Heartbeat\"}" > /dev/null &
done
wait
echo "Flood complete."
echo ""

# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}═══════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}                   FINAL REPORT                       ${NC}"
echo -e "${BOLD}═══════════════════════════════════════════════════════${NC}"
echo ""

FINAL=$(auth $BASE/stats)
echo "Total Evaluated:  $(echo $FINAL | jq '.ai_calls // 0')"
echo "Total Blocked:    $(echo $FINAL | jq '.blocked_today // 0')"
echo ""

echo -e "${BLUE}[AI CHECK]${NC} Verifying Ollama reasoning..."
# Use OLLAMA_ENDPOINT from .env
VERIFY=$(auth -X POST $BASE/config/verify-key \
  -d "{\"provider\":\"ollama\",\"model\":\"${OLLAMA_MODEL:-gemma3:9b}\",\"api_key\":\"${OLLAMA_ENDPOINT:-}\"}" \
  2>/dev/null || echo '{"test_evaluation":{"reasoning":"API call failed"}}')

REASONING=$(echo $VERIFY | jq -r '.test_evaluation.reasoning // "not available"')
echo "  Ollama says:  $REASONING"

echo ""
echo -e "${BOLD}Simulation complete.${NC}"
echo ""
