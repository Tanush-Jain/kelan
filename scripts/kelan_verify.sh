#!/bin/bash
cd /home/wop/startup/kelan-core
source .env 2>/dev/null
export $(cat .env | grep -v '^#' | grep -v '^$' | xargs) 2>/dev/null

MAC_IP=$(echo "${OLLAMA_ENDPOINT:-http://localhost:11434}" | \
  sed 's|http://||' | cut -d: -f1)
OLLAMA_EP="${OLLAMA_ENDPOINT:-http://localhost:11434}"
API="http://localhost:${SERVER_PORT:-3000}"
MODEL="${OLLAMA_MODEL:-gemma3:9b}"

pass=0; fail=0
check() {
  if [ $3 -eq 0 ]; then
    echo "  ✅ $1"; pass=$((pass+1))
  else
    echo "  ❌ $1 — $2"; fail=$((fail+1))
  fi
}

echo ""
echo "╔══════════════════════════════════════════╗"
echo "║   Kelan Security — System Verification   ║"
echo "╚══════════════════════════════════════════╝"

echo ""
echo "── 1. KERNEL & EBPF ────────────────────────"
check "Kernel version" "$(uname -r)" 0
KVER=$(uname -r | cut -d. -f1-2 | tr -d '.')
[ "$KVER" -ge 515 ] 2>/dev/null
check "Kernel >= 5.15 (needed for XDP)" "kernel is $(uname -r)" $?
ls /sys/kernel/btf/vmlinux > /dev/null 2>&1
check "BTF available" "/sys/kernel/btf/vmlinux missing" $?
mount | grep -q bpf
check "BPF filesystem mounted" "run: mount -t bpf bpf /sys/fs/bpf" $?
PROGS=$(bpftool prog list 2>/dev/null | grep -c xdp || echo 0)
[ "$PROGS" -gt 0 ]
check "XDP program loaded ($PROGS programs)" \
  "no XDP programs — server may be in software mode" $?

echo ""
echo "── 2. OLLAMA ON MAC ($MAC_IP) ──────────────"
curl -s --max-time 5 "$OLLAMA_EP/api/tags" > /tmp/ollama_tags.json 2>/dev/null
check "Ollama reachable at $OLLAMA_EP" \
  "check: OLLAMA_HOST=0.0.0.0 ollama serve" $?
python3 -c "
import json
d=json.load(open('/tmp/ollama_tags.json'))
models=[m['name'] for m in d.get('models',[])]
assert len(models)>0, 'no models'
print(f'  Models available: {models}')
assert any('gemma' in m or 'mistral' in m for m in models)
" 2>/dev/null
check "gemma/mistral model pulled" \
  "run on Mac: ollama pull gemma3:9b" $?

echo ""
echo "── 3. OLLAMA INFERENCE TEST ────────────────"
VERDICT=$(curl -s --max-time 20 \
  -X POST "$OLLAMA_EP/api/generate" \
  -H "Content-Type: application/json" \
  -d "{
    \"model\": \"$MODEL\",
    \"prompt\": \"You are a network security AI. A client enrolled with intent: health_check, no anomalies detected. Respond ONLY with valid JSON: {\\\"verdict\\\":\\\"ALLOW\\\",\\\"confidence\\\":0.95,\\\"reason\\\":\\\"normal connection\\\"}\",
    \"stream\": false
  }" 2>/dev/null | python3 -c "
import sys,json
d=json.load(sys.stdin)
r=d.get('response','')
start=r.find('{'); end=r.rfind('}')+1
v=json.loads(r[start:end]) if start>=0 else {}
print(v.get('verdict','PARSE_FAIL'))
" 2>/dev/null)

echo "  Ollama raw verdict: $VERDICT"
echo "$VERDICT" | grep -qE "ALLOW|DENY|MONITOR"
check "Ollama returns structured verdict" \
  "verdict was: $VERDICT — check model + prompt" $?

echo ""
echo "── 4. AITP SERVER ──────────────────────────"
HEALTH=$(curl -s --max-time 5 "$API/api/health" 2>/dev/null)
echo "$HEALTH" | python3 -m json.tool > /dev/null 2>&1
check "Server responding at $API" \
  "start server: ./target/release/aitp-server" $?
echo "  Health response: $(echo $HEALTH | head -c 120)"

STATS=$(curl -s --max-time 5 "$API/api/stats" 2>/dev/null)
echo "$STATS" | python3 -c "
import sys,json
d=json.load(sys.stdin)
print(f'  Mode: {d.get(\"mode\",\"unknown\")}')
print(f'  Sessions: {d.get(\"active_sessions\",d.get(\"sessions\",0))}')
print(f'  Verdicts: {d.get(\"verdicts_total\",0)}')
print(f'  Dropped:  {d.get(\"packets_dropped\",0)}')
" 2>/dev/null || echo "  (stats not parseable — check endpoint)"
check "Stats endpoint returns JSON" "check /api/stats route" $?

echo ""
echo "── 5. ENROLLMENT (FULL HANDSHAKE) ──────────"
ENROLL=$(curl -s --max-time 15 \
  -X POST "$API/api/enroll" \
  -H "Content-Type: application/json" \
  -d "{
    \"entity_id\": \"verify-$(date +%s)\",
    \"name\": \"kelan-verify-node\",
    \"intent\": \"INIT_ENROL\",
    \"version\": 1
  }" 2>/dev/null)
echo "  Enroll response: $(echo $ENROLL | head -c 150)"
echo "$ENROLL" | python3 -c "
import sys,json
d=json.load(sys.stdin)
assert 'session_id' in d or 'entity_id' in d or 'verdict' in d or 'token' in d
" 2>/dev/null
check "Enrollment endpoint accepts request" \
  "check /api/enroll route + server logs" $?

echo ""
echo "── 6. OLLAMA TRUST VERDICT VIA SERVER ──────"
TRUST=$(curl -s --max-time 20 \
  -X POST "$API/api/trust/evaluate" \
  -H "Content-Type: application/json" \
  -d "{
    \"entity_id\": \"verify-trust-test\",
    \"intent\": \"model_inference\",
    \"session_id\": \"sess-verify-001\",
    \"anomalies\": []
  }" 2>/dev/null)
echo "  Trust response: $(echo $TRUST | head -c 200)"
echo "$TRUST" | python3 -c "
import sys,json
d=json.load(sys.stdin)
v=d.get('verdict','')
assert v in ['ALLOW','DENY','MONITOR'], f'bad verdict: {v}'
print(f'  Verdict: {v}, confidence: {d.get(\"confidence\",0):.2f}')
print(f'  Reason: {d.get(\"reason\",\"n/a\")}')
" 2>/dev/null
check "Server routes trust to Ollama and returns verdict" \
  "check trust/mod.rs wiring + ollama.rs" $?

echo ""
echo "── 7. WEBSOCKET AGENTIC SYNC ───────────────"
python3 -c "
import socket, time
s = socket.socket()
s.settimeout(3)
try:
    s.connect(('localhost', int('${SERVER_PORT:-3000}')))
    key = 'dGhlIHNhbXBsZSBub25jZQ=='
    s.send(f'GET /ws/agent HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n'.encode())
    resp = s.recv(512).decode()
    assert '101' in resp, f'got: {resp[:80]}'
    print('  WebSocket upgrade: 101 Switching Protocols')
    s.close()
except Exception as e:
    print(f'  WebSocket result: {e}')
    exit(1)
" 2>/dev/null
check "WebSocket /ws/agent endpoint reachable" \
  "check ws/handler.rs route mounting" $?

echo ""
echo "── 8. DATABASE ─────────────────────────────"
psql -h localhost -U kelan -d kelan -c \
  "SELECT count(*) as sessions FROM sessions;" \
  2>/dev/null | grep -q "[0-9]"
check "PostgreSQL sessions table accessible" \
  "check DB connection + migrations" $?
SESSIONS_DB=$(psql -h localhost -U kelan -d kelan -t \
  -c "SELECT count(*) FROM sessions;" 2>/dev/null | tr -d ' ')
echo "  Sessions in DB: ${SESSIONS_DB:-0}"

echo ""
echo "── 9. DASHBOARD ENDPOINT ───────────────────"
DASH=$(curl -s --max-time 5 \
  "http://localhost:${SERVER_PORT:-3000}/" 2>/dev/null | head -c 200)
echo "$DASH" | grep -qi "kelan\|html\|dashboard"
check "Dashboard root endpoint serving HTML" \
  "check static file serving in router" $?

GRAFANA=$(curl -s --max-time 3 \
  "http://localhost:3001/api/health" 2>/dev/null)
echo "$GRAFANA" | grep -q "ok\|Ok\|healthy"
check "Grafana accessible at :3001" \
  "start: docker compose up grafana" $?

echo ""
echo "╔══════════════════════════════════════════╗"
printf "║  Results: ✅ %2d passed   ❌ %2d failed    ║\n" $pass $fail
echo "╚══════════════════════════════════════════╝"
echo ""
if [ $fail -eq 0 ]; then
  echo "  System is fully operational."
  echo "  Ollama is detecting and responding to sessions."
  echo "  Dashboard is live."
else
  echo "  Fix the ❌ items above, then re-run:"
  echo "  bash /home/wop/startup/kelan-core/scripts/kelan_verify.sh"
fi
echo ""
