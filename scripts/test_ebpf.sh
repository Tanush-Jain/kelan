#!/usr/bin/env bash
# Tests eBPF XDP enforcement is actually working
# Run on Linux after server is started: ./scripts/test_ebpf.sh
set -euo pipefail

GREEN='\033[0;32m'
AMBER='\033[0;33m'
RED='\033[0;31m'
NC='\033[0m'

TOKEN=$(curl -s -X POST http://localhost:3000/api/auth/signin \
  -H 'Content-Type: application/json' \
  -d '{"email":"admin@test.com","password":"Test123!"}' | jq -r '.token')

echo "Testing eBPF enforcement mode..."
STATS=$(curl -s http://localhost:3000/api/stats \
  -H "Authorization: Bearer $TOKEN" | jq '.')

MODE=$(echo $STATS | jq -r '.ebpf_enforcement_mode // "unknown"')
echo -e "Enforcement mode: ${GREEN}$MODE${NC}"

if echo "$MODE" | grep -q "EbpfXdp"; then
  echo -e "${GREEN}✓ Real eBPF XDP enforcement active${NC}"
  echo "  Packets seen:    $(echo $STATS | jq '.ebpf_packets_total')"
  echo "  Packets dropped: $(echo $STATS | jq '.ebpf_packets_dropped')"
  echo "  Active permits:  $(echo $STATS | jq '.ebpf_active_permits // 0')"
else
  echo -e "${AMBER}⚠ Software enforcement mode${NC}"
  echo "  To enable eBPF: run on Linux 5.15+ as root"
  echo "  Check: uname -r (need 5.15+)"
  echo "  Check: ls /sys/kernel/btf/vmlinux (must exist)"
fi

if command -v bpftool &>/dev/null; then
  echo ""
  echo "BPF maps loaded:"
  sudo bpftool map list 2>/dev/null | grep -E "PERMIT_MAP|STATS_MAP" || \
    echo "  (bpftool not showing maps — run as root)"
fi
