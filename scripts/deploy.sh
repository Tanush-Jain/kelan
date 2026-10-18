#!/usr/bin/env bash
# deploy.sh — Master Deployment Orchestrator for KELAN Security (macOS-native)
# Usage: ./scripts/deploy.sh [production|staging|dev]
set -euo pipefail

DEPLOYMENT_MODE="${1:-dev}"
DOMAIN="${DOMAIN:-localhost}"
APP_VERSION="${APP_VERSION:-0.3.0}"

# ── Banner ────────────────────────────────────────────────────────────────────
BLUE='\033[0;34m'
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m'

echo -e "${BLUE}"
cat << 'EOF'
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║   ██╗  ██╗███████╗██╗      █████╗ ███╗   ██╗                ║
║   ██║ ██╔╝██╔════╝██║     ██╔══██╗████╗  ██║                ║
║   █████╔╝ █████╗  ██║     ███████║██╔██╗ ██║                ║
║   ██╔═██╗ ██╔══╝  ██║     ██╔══██║██║╚██╗██║                ║
║   ██║  ██╗███████╗███████╗██║  ██║██║ ╚████║                ║
║   ╚═╝  ╚═╝╚══════╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═══╝                ║
║                                                               ║
║            AI-Trusted Intelligence Protocol                   ║
║         Production Deployment Orchestrator (macOS)            ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
EOF
echo -e "${NC}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"

echo -e "${BLUE}═══════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}DEPLOYMENT CONFIGURATION${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════${NC}"
echo "Mode:    $DEPLOYMENT_MODE"
echo "Domain:  $DOMAIN"
echo "Version: $APP_VERSION"
echo "Host OS: $(uname -s) $(uname -m)"
echo ""

cd "$ROOT_DIR"

# ── Pre-flight checks ─────────────────────────────────────────────────────────
echo -e "${YELLOW}[1/9] Pre-flight checks...${NC}"

# Docker Desktop (macOS — no sudo/docker group needed)
if ! command -v docker &>/dev/null; then
    echo -e "${RED}✗ Docker not installed.${NC}"
    echo "  Install Docker Desktop: brew install --cask docker"
    exit 1
fi
echo -e "${GREEN}✓ Docker found: $(docker --version | cut -d',' -f1)${NC}"

if ! docker info &>/dev/null 2>&1; then
    echo -e "${RED}✗ Docker Desktop is not running.${NC}"
    echo "  Start it: open /Applications/Docker.app"
    exit 1
fi
echo -e "${GREEN}✓ Docker Desktop running${NC}"

# docker compose v2 (plugin, not docker-compose v1)
if ! docker compose version &>/dev/null 2>&1; then
    echo -e "${RED}✗ 'docker compose' plugin not available.${NC}"
    echo "  Update Docker Desktop to 3.x+ which includes compose v2."
    exit 1
fi
echo -e "${GREEN}✓ Docker Compose v2: $(docker compose version --short)${NC}"

# .env
ENV_FILE="config/.env"
if [[ ! -f "$ENV_FILE" ]]; then
    echo -e "${RED}✗ $ENV_FILE not found.${NC}"
    echo "  Run: ./scripts/generate_secrets.sh"
    exit 1
fi
echo -e "${GREEN}✓ $ENV_FILE found${NC}"

# Validate no placeholder secrets remain
if grep -qE "YOUR_|CHANGE_ME|GENERATE_WITH" "$ENV_FILE" 2>/dev/null; then
    echo ""
    echo -e "${YELLOW}⚠ Warning: $ENV_FILE still contains placeholder values:${NC}"
    grep -E "YOUR_|CHANGE_ME|GENERATE_WITH" "$ENV_FILE" | head -5 | sed 's/^/    /'
    echo ""
    if [[ "$DEPLOYMENT_MODE" == "production" ]]; then
        echo -e "${RED}✗ Cannot deploy to production with placeholder secrets.${NC}"
        exit 1
    else
        read -r -p "  Continue in $DEPLOYMENT_MODE mode anyway? [y/N] " ok
        [[ "$ok" =~ ^[Yy]$ ]] || exit 1
    fi
else
    echo -e "${GREEN}✓ No placeholder values in $ENV_FILE${NC}"
fi

# JWT secret strength
JWT=$(grep "AITP_JWT_SECRET" "$ENV_FILE" | cut -d= -f2 2>/dev/null | tr -d '"' || true)
if [[ ${#JWT} -ge 32 ]]; then
    echo -e "${GREEN}✓ JWT secret is ≥32 characters (${#JWT} chars)${NC}"
else
    echo -e "${RED}✗ AITP_JWT_SECRET too short: ${#JWT} chars (need ≥32)${NC}"
    [[ "$DEPLOYMENT_MODE" == "production" ]] && exit 1
fi

# ── Security audit ────────────────────────────────────────────────────────────
echo ""
echo -e "${YELLOW}[2/9] Security audit (cargo audit)...${NC}"
if command -v cargo &>/dev/null; then
    if cargo audit --quiet 2>/dev/null; then
        echo -e "${GREEN}✓ No known CVEs in dependencies${NC}"
    else
        echo -e "${YELLOW}⚠ cargo audit found advisories — review before production${NC}"
        [[ "$DEPLOYMENT_MODE" == "production" ]] && cargo audit 2>&1 | head -20
    fi
else
    echo -e "${YELLOW}⚠ cargo not in PATH — skipping audit${NC}"
fi

# ── TLS certificates ──────────────────────────────────────────────────────────
echo ""
echo -e "${YELLOW}[3/9] TLS certificates...${NC}"
mkdir -p certs

if [[ "$DEPLOYMENT_MODE" == "production" && "$DOMAIN" != "localhost" ]]; then
    if [[ ! -f "certs/server.crt" ]]; then
        echo "  Obtaining Let's Encrypt certificate for $DOMAIN..."
        if command -v certbot &>/dev/null; then
            sudo certbot certonly --standalone -d "$DOMAIN" --non-interactive --agree-tos -m "admin@$DOMAIN"
            sudo cp "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" certs/server.crt
            sudo cp "/etc/letsencrypt/live/$DOMAIN/privkey.pem"   certs/server.key
            sudo chown "$(whoami)" certs/server.crt certs/server.key
        else
            echo -e "${YELLOW}  certbot not found — install: brew install certbot${NC}"
            echo "  Or run: ./scripts/generate_certs.sh prod"
            exit 1
        fi
    fi
    echo -e "${GREEN}✓ Production TLS certificate configured${NC}"
else
    if [[ ! -f "certs/server.crt" ]]; then
        echo "  Generating dev certificate..."
        if command -v mkcert &>/dev/null; then
            mkcert -install 2>/dev/null || true
            mkcert -cert-file certs/server.crt -key-file certs/server.key \
                localhost 127.0.0.1 ::1 kelan.local
            echo -e "${GREEN}  ✓ mkcert certificate (macOS Keychain trusted)${NC}"
        else
            ./scripts/generate_certs.sh self-signed
            echo -e "${GREEN}  ✓ Self-signed certificate (add -k to curl or install mkcert)${NC}"
        fi
    else
        echo -e "${GREEN}✓ Certificates already present${NC}"
    fi
fi

[[ -f "certs/server.crt" ]] && openssl x509 -in certs/server.crt -noout -subject -dates 2>/dev/null | sed 's/^/  /'

# ── Build Docker image ────────────────────────────────────────────────────────
echo ""
echo -e "${YELLOW}[4/9] Building Docker image...${NC}"

COMPOSE_FILE="yml/docker-compose.prod.yml"
[[ "$DEPLOYMENT_MODE" == "dev" ]] && COMPOSE_FILE="yml/docker-compose.yml"

if [[ -f "$COMPOSE_FILE" ]]; then
    docker compose -f "$COMPOSE_FILE" build --quiet kelan-server 2>&1 | tail -3
    echo -e "${GREEN}✓ Image built${NC}"
else
    echo -e "${YELLOW}⚠ $COMPOSE_FILE not found — building standalone image${NC}"
    docker build -t kelan-server:latest . --quiet
    echo -e "${GREEN}✓ kelan-server:latest built${NC}"
fi

# ── Start database ────────────────────────────────────────────────────────────
echo ""
echo -e "${YELLOW}[5/9] Starting PostgreSQL...${NC}"

if [[ -f "$COMPOSE_FILE" ]]; then
    export $(grep -v '^#' "$ENV_FILE" | xargs) 2>/dev/null || true
    docker compose -f "$COMPOSE_FILE" up -d postgres 2>/dev/null || true

    echo -n "  Waiting for PostgreSQL"
    for i in $(seq 1 30); do
        if docker compose -f "$COMPOSE_FILE" exec -T postgres \
            pg_isready -U kelan &>/dev/null 2>&1; then
            echo ""
            echo -e "${GREEN}✓ PostgreSQL ready${NC}"
            break
        fi
        echo -n "."
        sleep 2
        if [[ $i -eq 30 ]]; then
            echo ""
            echo -e "${RED}✗ PostgreSQL did not start in time${NC}"
            docker compose -f "$COMPOSE_FILE" logs postgres 2>/dev/null | tail -20
            exit 1
        fi
    done
else
    echo -e "${YELLOW}⚠ No compose file — assuming SQLite for dev mode${NC}"
fi

# ── Start all services ────────────────────────────────────────────────────────
echo ""
echo -e "${YELLOW}[6/9] Starting all services...${NC}"

if [[ -f "$COMPOSE_FILE" ]]; then
    docker compose -f "$COMPOSE_FILE" up -d --remove-orphans
    echo -e "${GREEN}✓ Services started${NC}"
    
    # Also start monitoring stack if available
    if [[ -f "yml/docker-compose.monitoring.yml" ]]; then
        docker compose -f "yml/docker-compose.monitoring.yml" up -d 2>/dev/null || true
        echo -e "${GREEN}✓ Monitoring stack started${NC}"
    fi
fi

# ── Health checks ─────────────────────────────────────────────────────────────
echo ""
echo -e "${YELLOW}[7/9] Waiting for services to become healthy...${NC}"
sleep 5

SERVICES=()
[[ -f "$COMPOSE_FILE" ]] && SERVICES=(
    "postgres"
    "kelan-server"
)

ALL_HEALTHY=true
for svc in "${SERVICES[@]}"; do
    STATUS=$(docker compose -f "$COMPOSE_FILE" ps "$svc" 2>/dev/null \
        | grep -iE "Up|running|healthy" | wc -l | tr -d ' ')
    if [[ "$STATUS" -gt 0 ]]; then
        echo -e "  ${GREEN}✓ $svc${NC}"
    else
        echo -e "  ${RED}✗ $svc not healthy${NC}"
        ALL_HEALTHY=false
    fi
done

if [[ "$ALL_HEALTHY" == "false" ]]; then
    echo ""
    echo -e "${RED}Some services failed. Showing logs:${NC}"
    [[ -f "$COMPOSE_FILE" ]] && docker compose -f "$COMPOSE_FILE" logs --tail=30
    exit 1
fi

# ── API health check ──────────────────────────────────────────────────────────
echo ""
echo -e "${YELLOW}[8/9] API health check...${NC}"
sleep 3

API_STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
    "http://localhost:3000/api/stats" 2>/dev/null || echo "000")

if [[ "$API_STATUS" == "200" ]]; then
    echo -e "${GREEN}✓ API responding at http://localhost:3000${NC}"
else
    echo -e "${YELLOW}⚠ API returned $API_STATUS (may still be initializing)${NC}"
    echo "  Check: docker compose -f $COMPOSE_FILE logs kelan-server"
fi

# ── Run security tests ────────────────────────────────────────────────────────
echo ""
echo -e "${YELLOW}[9/9] Running post-deploy security validation...${NC}"
if [[ -x "scripts/security_tests.sh" ]]; then
    if ./scripts/security_tests.sh "http://localhost:3000"; then
        echo -e "${GREEN}✓ All security tests passed${NC}"
    else
        echo -e "${YELLOW}⚠ Some security checks did not pass — review above${NC}"
    fi
else
    echo -e "${YELLOW}⚠ security_tests.sh not executable${NC}"
fi

# ── Auto-start via launchd (macOS — NOT systemd) ─────────────────────────────
if [[ "$DEPLOYMENT_MODE" == "production" ]]; then
    echo ""
    read -r -p "Enable auto-start on login via launchd? [y/N] " enable_launchd
    if [[ "$enable_launchd" =~ ^[Yy]$ ]]; then
        PLIST="$HOME/Library/LaunchAgents/io.kelan.server.plist"
        COMPOSE_ABS="$(pwd)/$COMPOSE_FILE"
        cat > "$PLIST" << PLIST_EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>io.kelan.server</string>
  <key>ProgramArguments</key>
  <array>
    <string>/usr/local/bin/docker</string>
    <string>compose</string>
    <string>-f</string>
    <string>$COMPOSE_ABS</string>
    <string>up</string>
    <string>-d</string>
  </array>
  <key>WorkingDirectory</key>
  <string>$(pwd)</string>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <false/>
  <key>StandardOutPath</key>
  <string>$HOME/kelan/log/launchd.log</string>
  <key>StandardErrorPath</key>
  <string>$HOME/kelan/log/launchd-error.log</string>
</dict>
</plist>
PLIST_EOF
        launchctl load "$PLIST" 2>/dev/null || true
        echo -e "${GREEN}✓ launchd agent installed: $PLIST${NC}"
        echo "  To remove: launchctl unload $PLIST && rm $PLIST"
    fi
fi

# ── Summary ───────────────────────────────────────────────────────────────────
[[ -f "$COMPOSE_FILE" ]] && docker compose -f "$COMPOSE_FILE" ps 2>/dev/null || true

GRAFANA_PASS=$(grep "GRAFANA_PASSWORD" "$ENV_FILE" 2>/dev/null | cut -d= -f2 || echo "(see config/.env)")

echo ""
echo -e "${GREEN}${BOLD}╔═══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}${BOLD}║              KELAN DEPLOYMENT SUCCESSFUL 🚀                    ║${NC}"
echo -e "${GREEN}${BOLD}╚═══════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${BLUE}Service Endpoints:${NC}"
echo "  🔒 API:        http://localhost:3000"
echo "  📊 Grafana:    http://localhost:3001  (admin / $GRAFANA_PASS)"
echo "  📈 Prometheus: http://localhost:9090"
if [[ "$DEPLOYMENT_MODE" == "production" && "$DOMAIN" != "localhost" ]]; then
    echo "  🌐 Production: https://$DOMAIN"
fi
echo ""
echo -e "${BLUE}Useful Commands:${NC}"
echo "  View logs:      docker compose -f $COMPOSE_FILE logs -f"
echo "  Stop:           docker compose -f $COMPOSE_FILE down"
echo "  Restart:        docker compose -f $COMPOSE_FILE restart"
echo "  Security test:  ./scripts/security_tests.sh"
echo "  Backup:         ./scripts/backup.sh"
echo "  Status:         docker compose -f $COMPOSE_FILE ps"
echo ""
echo -e "${RED}⚠️  SECURITY REMINDERS:${NC}"
echo "  • Set ALLOWED_ORIGINS to your real domain in config/.env"
echo "  • Change the default Grafana password"
echo "  • Configure SMTP_* and SLACK_WEBHOOK_URL for alerts"
echo "  • Run load test: brew install k6 && k6 run scripts/load_test.js"
echo "  • Monitor: docker compose -f $COMPOSE_FILE logs -f kelan-server"
echo ""
