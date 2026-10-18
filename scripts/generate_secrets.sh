#!/usr/bin/env bash
# generate_secrets.sh — Generate secure secrets for KELAN deployment (macOS-native)
# Usage: ./scripts/generate_secrets.sh
set -euo pipefail

echo "🔐 KELAN Security — Secrets Generator"
echo "======================================"
echo ""

# Generate a secure random string (macOS BSD openssl compatible)
generate_secret() {
    openssl rand -base64 64 | tr -d '=+/\n' | cut -c1-64
}

generate_password() {
    openssl rand -base64 32 | tr -d '=+/\n' | cut -c1-28
}

# Create config directory
mkdir -p config

# ── Generate main .env ────────────────────────────────────────────────────────
cat > config/.env << EOF
# KELAN SECURITY — PRODUCTION ENVIRONMENT CONFIGURATION
# Generated: $(date)
#
# ⚠️  CRITICAL: Never commit this file to version control
# Add config/.env to .gitignore immediately

# ============================================================================
# DATABASE CONFIGURATION
# ============================================================================
DATABASE_URL=postgresql://kelan:$(generate_password)@localhost:5432/kelan_db
DATABASE_MAX_CONNECTIONS=20
DATABASE_MIN_CONNECTIONS=5

# ============================================================================
# JWT AUTHENTICATION
# ============================================================================
JWT_SECRET=$(generate_secret)
JWT_EXPIRY_HOURS=24
JWT_REFRESH_SECRET=$(generate_secret)
JWT_REFRESH_EXPIRY_DAYS=30

# Kelan server uses this env var name:
AITP_JWT_SECRET=$(generate_secret)

# ============================================================================
# OLLAMA AI TRUST ENGINE
# ============================================================================
# Ollama endpoint (use local default or specify remote Mac IP)
OLLAMA_ENDPOINT=http://localhost:11434
OLLAMA_MODEL=gemma3:9b
OLLAMA_TIMEOUT_SECS=8

# ============================================================================
# SERVER CONFIGURATION
# ============================================================================
SERVER_HOST=0.0.0.0
SERVER_PORT=3000
AITP_HTTP_PORT=3000
AITP_HTTPS_PORT=8443
AITP_UDP_PORT=9999

# TLS Certificates (generate with: ./scripts/generate_certs.sh)
# Uncomment for HTTPS mode:
# TLS_CERT_PATH=certs/server.crt
# TLS_KEY_PATH=certs/server.key

# ============================================================================
# POST-QUANTUM CRYPTOGRAPHY
# ============================================================================
PQ_ALGORITHM=ml-kem-768
HYBRID_MODE=true
MIN_CRYPTO_ALGORITHM=HybridPQ
ADVERTISE_PQ=true

# ============================================================================
# TRUST ENGINE
# ============================================================================
AITP_TRUST_MODE=hybrid
AITP_TRUST_ALPHA=0.4

# ============================================================================
# SENTINEL (anomaly detection)
# ============================================================================
AITP_SENTINEL_ENABLED=true
AITP_SENTINEL_SCAN_INTERVAL_SECS=30
AITP_AUTO_QUARANTINE=false

# ============================================================================
# RATE LIMITING
# ============================================================================
RATE_LIMIT_REQUESTS_PER_MINUTE=60
RATE_LIMIT_BURST=10

# ============================================================================
# MONITORING
# ============================================================================
PROMETHEUS_PORT=9090
METRICS_ENABLED=true
GRAFANA_PASSWORD=$(generate_password)

# ============================================================================
# EBPF ENFORCEMENT
# ============================================================================
# Note: eBPF is Linux-only. macOS uses software enforcement automatically.
EBPF_MODE=auto
EBPF_INTERFACE=eth0
XDP_INTERFACE=eth0
AITP_EBPF_ENABLED=false

# ============================================================================
# CORS CONFIGURATION
# ============================================================================
# PRODUCTION: Set to your actual domain
# DEVELOPMENT: http://localhost:5173
ALLOWED_ORIGINS=http://localhost:5173
CORS_MAX_AGE=3600

# ============================================================================
# SECURITY HEADERS
# ============================================================================
HSTS_ENABLED=true
CSP_ENABLED=true

# ============================================================================
# LOGGING
# ============================================================================
LOG_LEVEL=info
AITP_LOG_LEVEL=info
LOG_FORMAT=json
# macOS log path (not /var/log which requires sudo):
AUDIT_LOG_PATH=$HOME/kelan/log/audit.log
RUST_LOG=aitp_server=info

# ============================================================================
# REDIS (for token revocation — optional)
# ============================================================================
REDIS_URL=redis://:$(generate_password)@localhost:6379
REDIS_MAX_CONNECTIONS=20

# ============================================================================
# POSTGRES (Docker Compose)
# ============================================================================
POSTGRES_PASSWORD=$(generate_password)

# ============================================================================
# SMTP (for alert emails — AlertManager)
# ============================================================================
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=alerts@yourdomain.com
SMTP_PASSWORD=YOUR_SMTP_APP_PASSWORD
SMTP_FROM=alerts@yourdomain.com
ALERT_EMAIL=you@yourdomain.com
ALERT_EMAIL_PASSWORD=YOUR_SMTP_APP_PASSWORD

# ============================================================================
# SLACK (for security alerts)
# ============================================================================
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/YOUR/WEBHOOK/URL

# ============================================================================
# ENVIRONMENT
# ============================================================================
ENVIRONMENT=development
APP_VERSION=0.3.0
EOF

echo "✅ Generated config/.env"
echo ""

# ── Generate .env.example (safe to commit) ───────────────────────────────────
cat > config/.env.example << 'EXAMPLE_EOF'
# KELAN SECURITY — ENVIRONMENT CONFIGURATION EXAMPLE
# Copy to .env and fill in real values. NEVER commit .env.

DATABASE_URL=postgresql://kelan:YOUR_PASSWORD@localhost:5432/kelan_db
DATABASE_MAX_CONNECTIONS=20

AITP_JWT_SECRET=GENERATE_WITH_openssl_rand_base64_64
JWT_EXPIRY_HOURS=24
JWT_REFRESH_SECRET=GENERATE_WITH_openssl_rand_base64_64
JWT_REFRESH_EXPIRY_DAYS=30

OLLAMA_ENDPOINT=http://localhost:11434
OLLAMA_MODEL=gemma3:9b
OLLAMA_TIMEOUT_SECS=8

SERVER_PORT=3000
AITP_HTTP_PORT=3000

MIN_CRYPTO_ALGORITHM=HybridPQ
ADVERTISE_PQ=true
AITP_TRUST_MODE=hybrid
AITP_SENTINEL_ENABLED=true
AITP_AUTO_QUARANTINE=false

ALLOWED_ORIGINS=http://localhost:5173
HSTS_ENABLED=true
CSP_ENABLED=true

LOG_LEVEL=info
AUDIT_LOG_PATH=~/kelan/log/audit.log

GRAFANA_PASSWORD=GENERATE_SECURE_PASSWORD
POSTGRES_PASSWORD=GENERATE_SECURE_PASSWORD
REDIS_URL=redis://:YOUR_PASSWORD@localhost:6379

SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=alerts@yourdomain.com
SMTP_PASSWORD=YOUR_GMAIL_APP_PASSWORD
ALERT_EMAIL=you@yourdomain.com
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/YOUR/WEBHOOK/URL

ENVIRONMENT=development
APP_VERSION=0.3.0
EXAMPLE_EOF

echo "✅ Generated config/.env.example"
echo ""

# ── Update root .gitignore ────────────────────────────────────────────────────
ROOT_DIR="$(dirname "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)")"
GITIGNORE="$ROOT_DIR/.gitignore"

add_if_missing() {
    local line="$1"
    if [[ -f "$GITIGNORE" ]] && grep -qF "$line" "$GITIGNORE" 2>/dev/null; then
        return
    fi
    echo "$line" >> "$GITIGNORE"
}

add_if_missing "# KELAN Secrets"
add_if_missing "config/.env"
add_if_missing "config/.env.local"
add_if_missing "config/.env.production"
add_if_missing "!config/.env.example"
add_if_missing "*.key"
add_if_missing "*.pem"
add_if_missing "certs/server.crt"
add_if_missing "secrets/"
add_if_missing "agent-identity.key"

echo "✅ Updated .gitignore"

# ── Create log directory (macOS uses ~/kelan not /var/log/kelan) ──────────────
mkdir -p "$HOME/kelan/log" "$HOME/kelan/backups"
echo "✅ Created ~/kelan/log and ~/kelan/backups"

echo ""
echo "======================================"
echo "✅ SECRETS GENERATED SUCCESSFULLY"
echo "======================================"
echo ""
echo "📝 Next steps:"
echo ""
echo "  1. Verify/Set your Ollama Endpoint:"
echo "     nano config/.env"
echo "     → OLLAMA_ENDPOINT=http://localhost:11434"
echo ""
echo "  2. Set ALLOWED_ORIGINS for your domain or localhost"
echo ""
echo "  3. Generate TLS certificates:"
echo "     ./scripts/generate_certs.sh"
echo ""
echo "  4. Verify no placeholder values remain:"
echo "     grep -E 'YOUR_|CHANGE_ME' config/.env"
echo "     → Should return NOTHING"
echo ""
echo "⚠️  SECURITY REMINDERS:"
echo "   • NEVER commit config/.env to git"
echo "   • Rotate secrets every 90 days"
echo "   • Use different secrets for dev / staging / production"
echo "   • In production: use AWS Secrets Manager or HashiCorp Vault"
echo ""
