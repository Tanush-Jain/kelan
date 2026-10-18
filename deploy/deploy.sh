#!/bin/bash
set -euo pipefail

DEPLOY_DIR="/opt/kelan"
REPO="https://github.com/YOUR_ORG/kelan-security"

echo "=== Kelan Security Deployment ==="
echo "Time: $(date)"

# Pull latest
if [ -d "$DEPLOY_DIR/.git" ]; then
  cd $DEPLOY_DIR
  git fetch origin
  git reset --hard origin/main
else
  git clone $REPO $DEPLOY_DIR
  cd $DEPLOY_DIR
fi

# Validate .env exists
[ -f .env ] || {
  echo "ERROR: .env missing"
  echo "Copy .env.example to .env and configure it"
  exit 1
}

# Pull latest images
docker compose pull

# Rolling restart (zero downtime)
docker compose up -d --remove-orphans

# Wait and verify
echo "Waiting for services..."
sleep 15

# Health check all services
HEALTH=$(curl -sf \
  http://localhost:3000/api/health 2>/dev/null)
echo "Health: $HEALTH"

STATUS=$(echo "$HEALTH" | python3 -c \
  "import sys,json; \
   d=json.load(sys.stdin); \
   print(d.get('status','unknown'))" 2>/dev/null)

if [ "$STATUS" = "healthy" ] || \
   [ "$STATUS" = "degraded" ]; then
  echo "=== Deployment complete ==="
  echo "Dashboard: http://$(hostname -I | \
    awk '{print $1}'):3000/dashboard"
else
  echo "ERROR: Health check failed"
  docker compose logs --tail=50
  exit 1
fi
