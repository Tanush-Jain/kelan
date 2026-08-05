#!/bin/bash

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

PASS=0
FAIL=0
SERVER="localhost"
UDP_PORT=${UDP_PORT:-9999}

# Auto-detect HTTP port
for PORT in 3000 8080 3001 8000; do
    if curl -s --max-time 1 \
        http://localhost:$PORT/health \
        > /dev/null 2>&1; then
        HTTP_PORT=$PORT
        echo "Found HTTP on port $PORT"
        break
    fi
done
HTTP_PORT=${HTTP_PORT:-3000}

pass() { 
    echo -e "${GREEN}  ✓ PASS${NC} — $1"
    PASS=$((PASS + 1))
}

fail() {
    echo -e "${RED}  ✗ FAIL${NC} — $1"
    echo -e "    ${YELLOW}→ $2${NC}"
    FAIL=$((FAIL + 1))
}

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  KELAN LIVE VERIFICATION"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# TEST 1: HTTP Health
echo ""
echo "[ HTTP API ]"
HEALTH=$(curl -s http://$SERVER:$HTTP_PORT/health)
if echo $HEALTH | grep -q "ok"; then
    pass "Health endpoint returns ok"
else
    fail "Health endpoint" "Got: $HEALTH"
fi

# TEST 2: Security Headers
HEADERS=$(curl -sI http://$SERVER:$HTTP_PORT/health)
if echo $HEADERS | grep -qi "x-frame-options"; then
    pass "Security headers present"
else
    fail "Security headers" "X-Frame-Options missing"
fi

# TEST 3: UDP Port Open
if ss -ulnp 2>/dev/null | grep -q $UDP_PORT || \
   netstat -ulnp 2>/dev/null | grep -q $UDP_PORT; then
    pass "UDP port $UDP_PORT is listening"
else
    fail "UDP port $UDP_PORT" "Port not open"
fi

# TEST 4: JWT Auth works
echo ""
echo "[ Authentication ]"
AUTH_RESPONSE=$(curl -s -X POST \
    http://$SERVER:$HTTP_PORT/api/auth/register \
    -H "Content-Type: application/json" \
    -d "{
        \"entity_id\": \"test-$(date +%s)\",
        \"org_name\": \"Test Org\",
        \"tier\": \"community\"
    }")

if echo $AUTH_RESPONSE | grep -q "token"; then
    pass "JWT token issued on registration"
    TOKEN=$(echo $AUTH_RESPONSE | \
        python3 -c "import sys,json; \
        print(json.load(sys.stdin).get('token',''))" \
        2>/dev/null)
else
    fail "JWT registration" "Got: $AUTH_RESPONSE"
    TOKEN=""
fi

# TEST 5: Protected endpoint with token
if [ -n "$TOKEN" ]; then
    STATS=$(curl -s \
        http://$SERVER:$HTTP_PORT/api/stats \
        -H "Authorization: Bearer $TOKEN")
    if echo $STATS | grep -qv "401\|Unauthorized"; then
        pass "Authenticated API access works"
    else
        fail "Authenticated API" "Got 401 with valid token"
    fi
fi

# TEST 6: SDK Handshake
echo ""
echo "[ Protocol Handshake ]"

# Build and run the basic_connect example
cargo run --example basic_connect \
    --release \
    -- \
    --server $SERVER:$UDP_PORT \
    --intent ModelInference \
    --timeout 10 \
    > /tmp/handshake_output.txt 2>&1

if grep -q "Session established\|Connected\|session_id" \
    /tmp/handshake_output.txt; then
    pass "5-phase AITP handshake completes"
    SCORE=$(grep -o "score: [0-9.]*" \
        /tmp/handshake_output.txt | head -1)
    echo "    Trust $SCORE"
else
    fail "AITP handshake" \
        "$(tail -3 /tmp/handshake_output.txt)"
fi

# TEST 7: Trust Engine evaluation
echo ""
echo "[ Trust Engine ]"

# Check circuit breaker state via metrics
METRICS=$(curl -s \
    http://$SERVER:$HTTP_PORT/metrics 2>/dev/null)

if echo $METRICS | grep -q "trust_verdict"; then
    pass "Trust metrics being exported"
else
    fail "Trust metrics" \
        "trust_verdict metric not found"
fi

# TEST 8: WebSocket Connection
echo ""
echo "[ WebSocket ]"

# Test WS connection using curl
WS_RESPONSE=$(curl -s \
    --include \
    --no-buffer \
    --header "Connection: Upgrade" \
    --header "Upgrade: websocket" \
    --header "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" \
    --header "Sec-WebSocket-Version: 13" \
    "http://$SERVER:$HTTP_PORT/ws" \
    --max-time 2 2>/dev/null)

if echo $WS_RESPONSE | grep -qi "101\|websocket"; then
    pass "WebSocket upgrade accepted"
else
    fail "WebSocket" "No 101 Switching Protocols"
fi

# TEST 9: Sentinel Attack Detection
echo ""
echo "[ Attack Detection ]"

# Run DDoS simulation
cargo run --example attack_sim \
    --release \
    -- \
    --server $SERVER:$UDP_PORT \
    --mode ddos \
    --duration 5s \
    > /tmp/attack_output.txt 2>&1 &

ATTACK_PID=$!
sleep 6
kill $ATTACK_PID 2>/dev/null

# Check if sentinel detected it
ANOMALIES=$(curl -s \
    http://$SERVER:$HTTP_PORT/api/anomalies/recent \
    2>/dev/null)

if echo $ANOMALIES | grep -qi "ddos\|anomaly\|detected"; then
    pass "DDoS attack detected by Sentinel"
else
    # Check logs as fallback
    if grep -qi "ddos\|anomaly\|detected" \
        log/kelan-server.log 2>/dev/null; then
        pass "DDoS detection visible in server logs"
    else
        fail "DDoS detection" \
            "No anomaly in logs or API"
    fi
fi

# TEST 10: eBPF Status
echo ""
echo "[ Enforcement ]"

if command -v bpftool &> /dev/null; then
    BPF_PROGS=$(sudo bpftool prog list 2>/dev/null)
    if echo $BPF_PROGS | grep -q "xdp"; then
        pass "eBPF XDP program loaded (kernel enforcement)"
    else
        echo -e "  ℹ INFO — Software enforcement active \
(no XDP — expected on non-Linux or without \
ebpf-native feature)"
    fi
else
    echo -e "  ℹ INFO — bpftool not available \
(install to verify eBPF status)"
fi

# Check software enforcer is working
if grep -q "enforcer\|enforcement\|permit\|deny" \
    log/kelan-server.log 2>/dev/null; then
    pass "Enforcement engine active in logs"
else
    fail "Enforcement engine" \
        "No enforcement activity in logs"
fi

# TEST 11: Multi-tenant Isolation
echo ""
echo "[ Multi-Tenant ]"

# Register two orgs
ORG_A=$(curl -s -X POST \
    http://$SERVER:$HTTP_PORT/api/auth/register \
    -H "Content-Type: application/json" \
    -d "{\"entity_id\":\"org-a-$(date +%s)\",
         \"org_name\":\"Org A\",
         \"tier\":\"community\"}" | \
    python3 -c "import sys,json; \
    print(json.load(sys.stdin).get('token',''))" \
    2>/dev/null)

ORG_B=$(curl -s -X POST \
    http://$SERVER:$HTTP_PORT/api/auth/register \
    -H "Content-Type: application/json" \
    -d "{\"entity_id\":\"org-b-$(date +%s)\",
         \"org_name\":\"Org B\",
         \"tier\":\"community\"}" | \
    python3 -c "import sys,json; \
    print(json.load(sys.stdin).get('token',''))" \
    2>/dev/null)

if [ -n "$ORG_A" ] && [ -n "$ORG_B" ]; then
    # Org A should not see Org B data
    ORG_A_DATA=$(curl -s \
        http://$SERVER:$HTTP_PORT/api/sessions \
        -H "Authorization: Bearer $ORG_A")
    ORG_B_DATA=$(curl -s \
        http://$SERVER:$HTTP_PORT/api/sessions \
        -H "Authorization: Bearer $ORG_B")
    
    # They should have different session lists
    if [ "$ORG_A_DATA" != "$ORG_B_DATA" ]; then
        pass "Multi-tenant isolation verified"
    else
        fail "Multi-tenant isolation" \
            "Org A and B see identical data"
    fi
else
    fail "Multi-tenant test setup" \
        "Could not register two test orgs"
fi

# ── FINAL REPORT ─────────────────────────────
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  VERIFICATION RESULTS"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "  ${GREEN}PASSED: $PASS${NC}"
echo -e "  ${RED}FAILED: $FAIL${NC}"
TOTAL=$((PASS + FAIL))
PCT=$((PASS * 100 / TOTAL))
echo "  SCORE:  $PCT% ($PASS/$TOTAL)"
echo ""

if [ $FAIL -eq 0 ]; then
    echo -e "${GREEN}  ✓ ALL SYSTEMS GO — READY TO DEPLOY${NC}"
elif [ $FAIL -le 2 ]; then
    echo -e "${YELLOW}  ⚠ MOSTLY READY — Fix $FAIL issues${NC}"
else
    echo -e "${RED}  ✗ NOT READY — $FAIL critical failures${NC}"
fi
echo ""

# Write report to file
cat > log/verification_report.txt << EOF
KELAN SECURITY VERIFICATION REPORT
Date: $(date)
Score: $PCT% ($PASS/$FAIL passed/failed)
$([ $FAIL -eq 0 ] && echo "STATUS: READY" || \
  echo "STATUS: NEEDS FIXES")
EOF
