#!/usr/bin/env bash
# security_tests.sh — Comprehensive security testing for KELAN (macOS-native)
# Usage: ./scripts/security_tests.sh [BASE_URL]
set -euo pipefail

KELAN_URL="${1:-${KELAN_URL:-http://localhost:3000}}"
TEST_EMAIL="security-test-$(date +%s)@test.kelan"
TEST_PASSWORD="TestPassword123!@#"

echo "🔒 KELAN SECURITY — COMPREHENSIVE SECURITY TESTING"
echo "=================================================="
echo ""
echo "Target: $KELAN_URL"
echo "Time:   $(date)"
echo ""

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m'

PASSED=0
FAILED=0
WARNINGS=0

pass()  { echo -e "  ${GREEN}✓ PASS${NC}:  $1"; ((PASSED++));   }
fail()  { echo -e "  ${RED}✗ FAIL${NC}:  $1"; ((FAILED++));   }
warn()  { echo -e "  ${YELLOW}⚠ WARN${NC}:  $1"; ((WARNINGS++)); }
section() { echo -e "\n${BOLD}━━━ $1 ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"; }

# ── Pre-flight: server must be reachable ─────────────────────────────────────
if ! curl -s --max-time 5 "$KELAN_URL/api/stats" > /dev/null 2>&1; then
    echo -e "${RED}❌ Server not reachable at $KELAN_URL — start with: ./scripts/start.sh${NC}"
    exit 1
fi

# ── TEST 1: TLS / SSL Configuration ──────────────────────────────────────────
section "TEST 1: TLS/SSL Configuration"

if echo "$KELAN_URL" | grep -q "https"; then
    HOST=$(echo "$KELAN_URL" | sed 's|https://||' | cut -d/ -f1)
    PORT=$(echo "$HOST" | grep -oE ':[0-9]+' | tr -d ':' || echo "443")
    HOST=$(echo "$HOST" | cut -d: -f1)

    TLS_INFO=$(echo | openssl s_client -connect "$HOST:$PORT" 2>/dev/null || true)
    TLS_VERSION=$(echo "$TLS_INFO" | grep "Protocol" | awk '{print $NF}' | head -1)

    if [[ "$TLS_VERSION" == "TLSv1.3" || "$TLS_VERSION" == "TLSv1.2" ]]; then
        pass "TLS version is secure: $TLS_VERSION"
    elif [[ -n "$TLS_VERSION" ]]; then
        fail "TLS version is insecure: $TLS_VERSION (need TLSv1.2+)"
    else
        warn "Could not determine TLS version"
    fi

    # Weak cipher test
    if echo | openssl s_client -connect "$HOST:$PORT" \
        -cipher 'DES:3DES:RC4:MD5:NULL' 2>/dev/null | grep -q "Cipher is"; then
        fail "Weak ciphers are accepted"
    else
        pass "Weak ciphers (DES/3DES/RC4/MD5) are disabled"
    fi
else
    warn "TLS tests skipped — server running on HTTP (expected for dev mode)"
fi

# ── TEST 2: Security Headers ──────────────────────────────────────────────────
section "TEST 2: Security Headers"

HEADERS=$(curl -sI "$KELAN_URL/api/stats" 2>/dev/null)

check_header() {
    local header="$1" label="$2"
    if echo "$HEADERS" | grep -qi "$header"; then
        VALUE=$(echo "$HEADERS" | grep -i "$header" | cut -d' ' -f2- | tr -d '\r')
        pass "$label: $VALUE"
    else
        fail "$label header MISSING"
    fi
}

if echo "$KELAN_URL" | grep -q "https"; then
    check_header "strict-transport-security" "HSTS"
else
    warn "HSTS check skipped (HTTP only — HSTS requires HTTPS)"
fi

check_header "x-frame-options"         "X-Frame-Options"
check_header "x-content-type-options"  "X-Content-Type-Options"
check_header "referrer-policy"          "Referrer-Policy"

if echo "$HEADERS" | grep -qi "content-security-policy"; then
    pass "Content-Security-Policy header present"
else
    warn "Content-Security-Policy header missing (add security_headers middleware)"
fi

# Check for version disclosure
if echo "$HEADERS" | grep -qi "^server:"; then
    SRV=$(echo "$HEADERS" | grep -i "^server:" | cut -d' ' -f2-)
    warn "Server header discloses: $SRV"
else
    pass "Server header not present (good — no version disclosure)"
fi

# ── TEST 3: Authentication Security ──────────────────────────────────────────
section "TEST 3: Authentication"

UNAUTH=$(curl -s -o /dev/null -w "%{http_code}" "$KELAN_URL/api/entities")
if [[ "$UNAUTH" == "401" || "$UNAUTH" == "403" ]]; then
    pass "Unauthenticated /api/entities → $UNAUTH (blocked)"
else
    fail "Unauthenticated /api/entities → $UNAUTH (should be 401)"
fi

UNAUTH2=$(curl -s -o /dev/null -w "%{http_code}" "$KELAN_URL/api/sessions")
if [[ "$UNAUTH2" == "401" || "$UNAUTH2" == "403" ]]; then
    pass "Unauthenticated /api/sessions → $UNAUTH2 (blocked)"
else
    fail "Unauthenticated /api/sessions → $UNAUTH2 (should be 401)"
fi

# Invalid JWT
INVALID_JWT=$(curl -s -o /dev/null -w "%{http_code}" \
    -H "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJoYWNrZXIifQ.BAD" \
    "$KELAN_URL/api/entities")
if [[ "$INVALID_JWT" == "401" || "$INVALID_JWT" == "403" ]]; then
    pass "Invalid JWT rejected → $INVALID_JWT"
else
    fail "Invalid JWT accepted → $INVALID_JWT"
fi

# Weak password rejection
WEAK_PASS=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST "$KELAN_URL/api/auth/signup" \
    -H "Content-Type: application/json" \
    -d "{\"org_name\":\"Test\",\"email\":\"weak@test.kelan\",\"password\":\"abc\"}")
if [[ "$WEAK_PASS" == "400" || "$WEAK_PASS" == "422" ]]; then
    pass "Weak password rejected → $WEAK_PASS"
else
    warn "Weak password response → $WEAK_PASS (check min-length validation)"
fi

# ── TEST 4: SQL Injection ─────────────────────────────────────────────────────
section "TEST 4: SQL Injection"

SQL1=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST "$KELAN_URL/api/auth/signin" \
    -H "Content-Type: application/json" \
    -d '{"email":"admin'"'"' OR '"'"'1'"'"'='"'"'1","password":"anything"}')
if [[ "$SQL1" != "200" ]]; then
    pass "SQL injection in email field → $SQL1 (blocked)"
else
    fail "SQL injection in email → 200 (CRITICAL: NOT BLOCKED)"
fi

SQL2=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST "$KELAN_URL/api/auth/signin" \
    -H "Content-Type: application/json" \
    -d '{"email":"a@b.c","password":"'"'"'; DROP TABLE organisations; --"}')
if [[ "$SQL2" != "200" ]]; then
    pass "SQL injection in password field → $SQL2 (blocked)"
else
    fail "SQL injection in password → 200 (CRITICAL: NOT BLOCKED)"
fi

SQL3=$(curl -s -o /dev/null -w "%{http_code}" \
    "$KELAN_URL/api/entities?id=1%27%20OR%20%271%27%3D%271")
if [[ "$SQL3" == "401" || "$SQL3" == "400" || "$SQL3" == "403" ]]; then
    pass "SQL injection in query string blocked → $SQL3"
else
    warn "SQL injection in query string → $SQL3 (verify parameterized queries)"
fi

# ── TEST 5: Rate Limiting ─────────────────────────────────────────────────────
section "TEST 5: Rate Limiting"

echo "  Sending 80 rapid auth requests..."
RATE_LIMITED=false
for i in $(seq 1 80); do
    CODE=$(curl -s -o /dev/null -w "%{http_code}" \
        -X POST "$KELAN_URL/api/auth/signin" \
        -H "Content-Type: application/json" \
        -d '{"email":"ratetest@kelan.io","password":"wrong"}' 2>/dev/null)
    if [[ "$CODE" == "429" ]]; then
        RATE_LIMITED=true
        pass "Rate limiting fires (429 at request #$i)"
        break
    fi
done

if [[ "$RATE_LIMITED" == "false" ]]; then
    fail "No 429 received after 80 rapid auth requests — rate limiting inactive"
fi

# ── TEST 6: Input Validation / XSS ───────────────────────────────────────────
section "TEST 6: XSS and Input Validation"

# Get a token for auth
TOKEN=$(curl -s -X POST "$KELAN_URL/api/auth/signup" \
    -H "Content-Type: application/json" \
    -d "{\"org_name\":\"SecTest\",\"email\":\"$TEST_EMAIL\",\"password\":\"$TEST_PASSWORD\"}" \
    | python3 -c "import sys,json; print(json.load(sys.stdin).get('token',''))" 2>/dev/null || echo "")

if [[ -n "$TOKEN" ]]; then
    XSS=$(curl -s -o /dev/null -w "%{http_code}" \
        -X POST "$KELAN_URL/api/entities" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer $TOKEN" \
        -d '{"name":"<script>alert(\"XSS\")</script>","entity_type":"workstation","public_key":"aaaa"}')
    if [[ "$XSS" == "400" || "$XSS" == "422" ]]; then
        pass "XSS payload in entity name rejected → $XSS"
    else
        warn "XSS payload response → $XSS (verify output is escaped or sanitized)"
    fi
else
    warn "Could not obtain token for XSS test (org may already exist)"
fi

# Path traversal
TRAV=$(curl -s -o /dev/null -w "%{http_code}" \
    "$KELAN_URL/api/../../../etc/passwd")
if [[ "$TRAV" != "200" ]]; then
    pass "Path traversal blocked → $TRAV"
else
    fail "Path traversal may be possible → $TRAV"
fi

# Oversized payload (1MB via /dev/urandom equivalent)
BIG=$(python3 -c "print('A' * 1048576)" 2>/dev/null || jot -r -c 1048576 A Z | tr -d '\n')
OVERSIZE=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST "$KELAN_URL/api/entities" \
    -H "Content-Type: application/json" \
    -d "{\"name\":\"$BIG\"}" 2>/dev/null || echo "000")
if [[ "$OVERSIZE" == "413" || "$OVERSIZE" == "400" || "$OVERSIZE" == "401" ]]; then
    pass "Oversized payload rejected → $OVERSIZE"
else
    warn "Oversized payload response → $OVERSIZE (verify body size limits)"
fi

# ── TEST 7: CORS Policy ───────────────────────────────────────────────────────
section "TEST 7: CORS Policy"

CORS=$(curl -sI \
    -H "Origin: https://evil.com" \
    -H "Access-Control-Request-Method: POST" \
    -X OPTIONS "$KELAN_URL/api/entities" 2>/dev/null)

if echo "$CORS" | grep -qi "access-control-allow-origin: \*"; then
    fail "CORS allows all origins (*) — SECURITY RISK in production"
elif echo "$CORS" | grep -qi "access-control-allow-origin: https://evil.com"; then
    fail "CORS allows attacker's origin https://evil.com"
elif echo "$CORS" | grep -qi "access-control-allow-origin"; then
    ALLOWED=$(echo "$CORS" | grep -i "access-control-allow-origin" | cut -d' ' -f2- | tr -d '\r')
    pass "CORS restricted to specific origin: $ALLOWED"
else
    pass "CORS: malicious origin not reflected (restrictive)"
fi

# ── TEST 8: Error Information Disclosure ──────────────────────────────────────
section "TEST 8: Error Information Disclosure"

ERR=$(curl -s "$KELAN_URL/api/nonexistent/endpoint/that/does/not/exist")

if echo "$ERR" | grep -qiE "backtrace|stack.?trace|at.*\\.rs:[0-9]|panicked"; then
    fail "Error response contains Rust stack trace — leaked internals"
else
    pass "No stack trace in error responses"
fi

if echo "$ERR" | grep -qiE "/Users/|/home/|/root/|/var/lib/"; then
    fail "Error response exposes file system path"
else
    pass "No file system paths in error responses"
fi

if echo "$ERR" | grep -qiE "postgresql://|sqlite://|sqlx::"; then
    fail "Error response discloses database details"
else
    pass "No database internals in error responses"
fi

# ── TEST 9: Cryptographic Security ───────────────────────────────────────────
section "TEST 9: Cryptographic Security"

if echo "$KELAN_URL" | grep -q "https"; then
    HOST=$(echo "$KELAN_URL" | sed 's|https://||' | cut -d/ -f1 | cut -d: -f1)
    PORT=$(echo "$KELAN_URL" | sed 's|https://||' | grep -oE ':[0-9]+' | tr -d ':' || echo "443")

    CERT_INFO=$(echo | openssl s_client -connect "$HOST:$PORT" 2>/dev/null \
        | openssl x509 -noout -text 2>/dev/null || true)

    KEY_SIZE=$(echo "$CERT_INFO" | grep "Public-Key" | grep -oE '[0-9]+' | head -1)
    if [[ -n "$KEY_SIZE" ]] && [[ "$KEY_SIZE" -ge 2048 ]]; then
        pass "Certificate key size: ${KEY_SIZE} bits (≥2048)"
    elif [[ -n "$KEY_SIZE" ]]; then
        fail "Certificate key size weak: ${KEY_SIZE} bits (need ≥2048)"
    else
        warn "Could not determine certificate key size"
    fi

    # macOS-compatible date comparison (no date -d)
    EXPIRY_STR=$(echo | openssl s_client -connect "$HOST:$PORT" 2>/dev/null \
        | openssl x509 -noout -enddate 2>/dev/null \
        | cut -d= -f2 || true)
    if [[ -n "$EXPIRY_STR" ]]; then
        EXPIRY_EPOCH=$(date -jf "%b %d %H:%M:%S %Y %Z" "$EXPIRY_STR" +%s 2>/dev/null || echo "0")
        NOW_EPOCH=$(date +%s)
        DAYS_LEFT=$(( (EXPIRY_EPOCH - NOW_EPOCH) / 86400 ))
        if [[ $DAYS_LEFT -gt 30 ]]; then
            pass "Certificate valid for $DAYS_LEFT more days (expires: $EXPIRY_STR)"
        elif [[ $DAYS_LEFT -gt 0 ]]; then
            warn "Certificate expires soon: $DAYS_LEFT days (renew now!)"
        else
            fail "Certificate has EXPIRED"
        fi
    fi
else
    warn "Cryptographic certificate tests skipped — server is HTTP"
fi

# Check local cert file as fallback
if [[ -f "certs/server.crt" ]]; then
    if openssl x509 -in certs/server.crt -noout -checkend 86400 2>/dev/null; then
        EXPIRY=$(openssl x509 -in certs/server.crt -noout -enddate 2>/dev/null | cut -d= -f2)
        pass "Local certs/server.crt valid — expires: $EXPIRY"
    else
        fail "certs/server.crt expires within 24 hours — renew immediately"
    fi
fi

# ── TEST 10: Secrets & Monitoring ─────────────────────────────────────────────
section "TEST 10: Secret Leakage & Monitoring"

BODY=$(curl -s "$KELAN_URL/api/stats" 2>/dev/null)
FORBIDDEN_TERMS=("JWT_SECRET" "AITP_JWT_SECRET" "DATABASE_URL" "password_hash" "private_key")
LEAKED=false
for term in "${FORBIDDEN_TERMS[@]}"; do
    if echo "$BODY" | grep -qi "$term"; then
        fail "Secret '$term' found in /api/stats response"
        LEAKED=true
    fi
done
if [[ "$LEAKED" == "false" ]]; then
    pass "No secrets detected in /api/stats response body"
fi

METRICS=$(curl -s -o /dev/null -w "%{http_code}" "$KELAN_URL/metrics" 2>/dev/null)
if [[ "$METRICS" == "200" ]]; then
    warn "/metrics endpoint publicly accessible (should be internal or protected)"
elif [[ "$METRICS" == "401" || "$METRICS" == "403" || "$METRICS" == "404" ]]; then
    pass "/metrics endpoint protected → $METRICS"
else
    pass "/metrics not on main port (likely separate port 9090 — good)"
fi

# macOS: check ~/kelan/log instead of /var/log/kelan
if [[ -d "$HOME/kelan/log" ]]; then
    LOG_COUNT=$(find "$HOME/kelan/log" -name "*.log" -mmin -60 2>/dev/null | wc -l | tr -d ' ')
    if [[ $LOG_COUNT -gt 0 ]]; then
        pass "Recent log files found in ~/kelan/log"
    else
        warn "No recent log files in ~/kelan/log (server logs go to stdout in dev mode)"
    fi
else
    warn "~/kelan/log not found (run ./scripts/generate_secrets.sh to create)"
fi

# ── Cargo audit ───────────────────────────────────────────────────────────────
section "TEST 11: Dependency Security (cargo audit)"

if command -v cargo &>/dev/null; then
    if cargo audit --quiet 2>/dev/null; then
        pass "cargo audit — no known CVEs in dependencies"
    else
        ADVISORIES=$(cargo audit 2>&1 | grep -c "error\[" || true)
        fail "cargo audit — $ADVISORIES advisory/advisories found (run 'cargo audit' for details)"
    fi
else
    warn "cargo not in PATH — skipping dependency audit"
fi

# ── Summary ───────────────────────────────────────────────────────────────────
TOTAL=$((PASSED + FAILED + WARNINGS))
PASS_RATE=0
[[ $TOTAL -gt 0 ]] && PASS_RATE=$((PASSED * 100 / TOTAL))

echo ""
echo -e "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "${BOLD}SECURITY TEST SUMMARY${NC}"
echo -e "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo -e "  ${GREEN}Passed:   $PASSED${NC}"
echo -e "  ${RED}Failed:   $FAILED${NC}"
echo -e "  ${YELLOW}Warnings: $WARNINGS${NC}"
echo -e "  Total:    $TOTAL  ($PASS_RATE% pass rate)"
echo ""

if [[ $FAILED -eq 0 && $WARNINGS -eq 0 ]]; then
    echo -e "${GREEN}${BOLD}✓ EXCELLENT — All security tests passed. Production-ready.${NC}"
elif [[ $FAILED -eq 0 ]]; then
    echo -e "${YELLOW}${BOLD}⚠ GOOD — All critical tests passed. Review warnings before production.${NC}"
elif [[ $PASS_RATE -ge 80 ]]; then
    echo -e "${YELLOW}${BOLD}⚠ ACCEPTABLE — Most tests passed. Fix failures before going live.${NC}"
else
    echo -e "${RED}${BOLD}✗ CRITICAL — Multiple security failures. DO NOT deploy to production.${NC}"
fi

echo ""
echo "Next steps:"
echo "  1. Fix all FAIL items above"
echo "  2. Run: cargo audit && cargo deny check advisories"
echo "  3. Load test: brew install k6 && k6 run scripts/load_test.js"
echo "  4. Run this script again after fixes"
echo ""

exit $FAILED
