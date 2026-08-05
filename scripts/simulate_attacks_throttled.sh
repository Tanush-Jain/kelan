#!/usr/bin/env bash
# AITP Attack Simulation Suite
# ─────────────────────────────────────────────────────────────────────────────

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR/.."

# Source .env to get OLLAMA_ENDPOINT
if [ -f .env ]; then
  export $(grep -v '^#' .env | xargs)
fi

BASE="http://localhost:3000/api"
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'
BOLD='\033[1m'
BLUE='\033[0;34m'

# Throttle for Free Tier (5 RPM = 1 request every 12s)
THROTTLE=13

echo -e "${BOLD}AITP Attack Simulation Suite (Throttled for Free Tier)${NC}"

# ── Auth (Create account and get token) ──────────────────────────────────────
UNIQUE_ID=$(date +%s)
EMAIL="sim_throttled_${UNIQUE_ID}@kelan.io"
PASS="SimPass123!"

echo -e "${BLUE}[AUTH]${NC} Registering as $EMAIL..."
RESPONSE=$(curl -s -X POST $BASE/auth/signup \
  -H 'Content-Type: application/json' \
  -d "{\"org_name\":\"Throttled Org\",\"email\":\"$EMAIL\",\"password\":\"$PASS\"}")

TOKEN=$(echo $RESPONSE | jq -r '.token')

if [ -z "$TOKEN" ] || [ "$TOKEN" = "null" ]; then
  echo -e "${RED}ERROR: Could not register user. check server logs.${NC}"
  echo "DEBUG Response: $RESPONSE"
  exit 1
fi

echo -e "${BLUE}[AUTH]${NC} Authenticated successfully."

auth() { curl -s -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' "$@"; }

# 1. Setup
echo "--- Setup ---"
ENTITY_A=$(auth -X POST $BASE/entities -d '{"name":"workstation-01","entity_type":"workstation","department":"Engineering","clearance_level":1}' | jq -r '.entity_id')
ENTITY_B=$(auth -X POST $BASE/entities -d '{"name":"service-01","entity_type":"service","department":"AI","clearance_level":1}' | jq -r '.entity_id')
ENTITY_C=$(auth -X POST $BASE/entities -d '{"name":"database-top-secret","entity_type":"server","department":"Finance","clearance_level":3}' | jq -r '.entity_id')

# 2. Attacks
echo "1. Baseline..."
auth -X POST $BASE/entities/$ENTITY_A/test-session -d "{\"dest_entity_id\":\"$ENTITY_B\",\"intent\":\"ModelInference\"}" | jq '.'
sleep $THROTTLE

echo "2. Clearance Violation..."
auth -X POST $BASE/entities/$ENTITY_A/test-session -d "{\"dest_entity_id\":\"$ENTITY_C\",\"intent\":\"DataSync\"}" | jq '.'
sleep $THROTTLE

echo "3. ControlSignal Abuse..."
auth -X POST $BASE/entities/$ENTITY_B/test-session -d "{\"dest_entity_id\":\"$ENTITY_C\",\"intent\":\"ControlSignal\"}" | jq '.'
sleep $THROTTLE

echo "4. Lateral Movement..."
auth -X POST $BASE/entities/$ENTITY_B/test-session -d "{\"dest_entity_id\":\"$ENTITY_C\",\"intent\":\"DataSync\", \"simulate_lateral_movement\":true}" | jq '.'
sleep $THROTTLE

echo "5. Exfiltration..."
auth -X POST $BASE/entities/$ENTITY_A/test-session -d "{\"dest_entity_id\":\"$ENTITY_B\",\"intent\":\"FileTransfer\", \"bytes_tx\":100000000}" | jq '.'
sleep $THROTTLE

# Final Report
echo ""
echo "--- Final Stats ---"
auth $BASE/stats | jq '.'

echo ""
echo "Verifying AI Reasoning..."
auth -X POST $BASE/config/verify-key -d "{\"provider\":\"ollama\",\"model\":\"${OLLAMA_MODEL:-gemma3:9b}\",\"api_key\":\"${OLLAMA_ENDPOINT:-}\"}" | jq '.'
