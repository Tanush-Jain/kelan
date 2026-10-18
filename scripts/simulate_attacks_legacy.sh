#!/bin/bash
set -e

SERVER_IP="${1:-127.0.0.1}"
SERVER_PORT="${2:-9999}"
API_URL="http://${SERVER_IP}:3000"
IFACE=$(ip -o -4 route show to default | awk '{print $5}' | head -1)

echo "╔══════════════════════════════════════════╗"
echo "║  Kelan Security — Attack Simulation      ║"
echo "║  Target: $SERVER_IP:$SERVER_PORT         ║"
echo "╚══════════════════════════════════════════╝"
echo ""

# Baseline stats before attack
echo "📊 Baseline stats:"
curl -s $API_URL/api/stats | python3 -m json.tool 2>/dev/null || \
  echo "(server not running — start aitp-server first)"
echo ""

# --- ATTACK 1: UDP SYN Flood ---
echo "🔥 ATTACK 1: UDP SYN Flood (10,000 packets)"
echo "   Sending via hping3..."
hping3 --udp -p $SERVER_PORT -c 10000 --faster \
  --rand-source $SERVER_IP 2>/dev/null &
FLOOD_PID=$!
sleep 4
kill $FLOOD_PID 2>/dev/null || true

echo "   Checking dropped packet count..."
DROPS=$(curl -s $API_URL/api/stats | \
  python3 -c "import sys,json; \
  d=json.load(sys.stdin); \
  print(d.get('packets_dropped',0))" 2>/dev/null || echo "N/A")
echo "   Packets dropped by eBPF/software: $DROPS"
echo ""

# --- ATTACK 2: TCP SYN Flood ---
echo "🔥 ATTACK 2: TCP SYN Flood (5,000 packets)"
hping3 -S -p 3000 -c 5000 --faster \
  --rand-source $SERVER_IP 2>/dev/null &
SYN_PID=$!
sleep 3
kill $SYN_PID 2>/dev/null || true
echo "   Watching sentinel anomalies..."
curl -s $API_URL/api/sentinel/events 2>/dev/null | \
  python3 -c "
import sys, json
try:
    events = json.load(sys.stdin)
    print(f'   Anomalies detected: {len(events.get(\"events\",[]))}')
except:
    print('   (auth required or no events yet)')
"
echo ""

# --- ATTACK 3: Identity spoofing ---
echo "🔥 ATTACK 3: Identity Spoofing attempt"
python3 - << 'PYEOF'
import socket, struct, os, random

# Build a fake AITP SYN packet with random bytes as signature
# (will fail Ed25519 verification)
fake_entity_id = b"SPOOF-" + os.urandom(8)
fake_payload = struct.pack(
    ">BBHIQ32s",
    4,           # version
    0x01,        # SYN flag
    len(fake_entity_id) + 32,
    random.randint(1, 999999),   # session_id
    random.randint(0, 2**63),    # timestamp
    fake_entity_id[:32].ljust(32, b'\x00')
) + os.urandom(64)  # fake Ed25519 signature

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.settimeout(2.0)
try:
    sock.sendto(fake_payload, ("127.0.0.1", 9999))
    print("   Spoofed SYN sent — server should reject it")
    resp = sock.recv(1024)
    print(f"   Got response ({len(resp)} bytes) — checking verdict...")
except socket.timeout:
    print("   No response (packet silently dropped — ✅ PROTECTED)")
except Exception as e:
    print(f"   Error: {e}")
finally:
    sock.close()
PYEOF
echo ""

# --- ATTACK 4: Port scan ---
echo "🔥 ATTACK 4: Port scan (nmap)"
nmap -sS -T4 --top-ports 100 $SERVER_IP -oG - 2>/dev/null | \
  grep "open" | head -5 || echo "   (run as root for SYN scan)"
echo ""

# --- RESULTS ---
echo "═══════════════════════════════════════════"
echo "📊 POST-ATTACK SUMMARY"
echo "═══════════════════════════════════════════"
curl -s $API_URL/api/stats | python3 -m json.tool 2>/dev/null || \
  echo "(unable to reach API)"
echo ""
echo "Check trust verdicts in Ollama logs:"
echo "  curl -s http://localhost:3000/api/sessions"
echo ""
echo "Check eBPF maps:"
echo "  bpftool map list"
echo "  bpftool prog list"
echo ""
echo "✅ Simulation complete. Check tmux monitor window for live stats."
