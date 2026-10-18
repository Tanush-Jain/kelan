#!/usr/bin/env bash
# generate_certs.sh — TLS Certificate Generator for KELAN (macOS-native)
# Usage: ./scripts/generate_certs.sh  (interactive)
#        ./scripts/generate_certs.sh dev          (mkcert, Keychain-trusted)
#        ./scripts/generate_certs.sh self-signed  (openssl, not trusted)
#        ./scripts/generate_certs.sh prod         (CSR for commercial CA)
set -euo pipefail

GREEN='\033[0;32m'
AMBER='\033[0;33m'
RED='\033[0;31m'
BOLD='\033[1m'
NC='\033[0m'

echo -e "\n${BOLD}🔐 KELAN Security — TLS Certificate Generator${NC}"
echo "=============================================="
echo ""

# Check openssl
if ! command -v openssl &>/dev/null; then
    echo -e "${RED}❌ openssl not found. Install with: brew install openssl${NC}"
    exit 1
fi

mkdir -p certs

MODE="${1:-menu}"

# ── Option 1: mkcert — macOS Keychain trusted (best for dev) ─────────────────
generate_mkcert() {
    echo -e "${AMBER}📝 Using mkcert (trusted by macOS Keychain, Chrome, Firefox)...${NC}"

    if ! command -v mkcert &>/dev/null; then
        echo -e "${AMBER}mkcert not found — installing via Homebrew...${NC}"
        if ! command -v brew &>/dev/null; then
            echo -e "${RED}❌ Homebrew not installed. Install from https://brew.sh${NC}"
            exit 1
        fi
        brew install mkcert
        brew install nss 2>/dev/null || true  # Firefox support
    fi

    echo "Installing local CA into macOS Keychain (may prompt for password)..."
    mkcert -install

    mkcert \
        -cert-file certs/server.crt \
        -key-file  certs/server.key \
        localhost 127.0.0.1 ::1 kelan.local

    chmod 644 certs/server.crt
    chmod 600 certs/server.key

    echo ""
    echo -e "${GREEN}✅ Development certificate generated and trusted by macOS!${NC}"
    echo ""
    echo "ℹ️  This certificate is automatically trusted by:"
    echo "   • macOS Keychain"
    echo "   • Google Chrome"
    echo "   • Safari"
    echo "   • Firefox (if nss is installed)"
    echo ""
    echo "To remove the local CA later: mkcert -uninstall"
}

# ── Option 2: openssl self-signed (curl -k, not browser-trusted) ──────────────
generate_openssl_self_signed() {
    echo -e "${AMBER}📝 Generating self-signed certificate via openssl...${NC}"
    echo -e "${AMBER}⚠️  WARNING: Browsers will show security warnings with this cert.${NC}"
    echo -e "${AMBER}   Use only if mkcert is not available.${NC}"

    openssl genrsa -out certs/server.key 4096
    chmod 600 certs/server.key

    openssl req -new -x509 \
        -key  certs/server.key \
        -out  certs/server.crt \
        -days 365 \
        -subj "/C=US/ST=State/L=City/O=KELAN Security/OU=Development/CN=localhost" \
        -addext "subjectAltName=DNS:localhost,DNS:*.localhost,IP:127.0.0.1,IP:::1"

    chmod 644 certs/server.crt

    echo ""
    echo -e "${GREEN}✅ Self-signed certificate generated.${NC}"
    echo ""
    echo "To trust this cert on macOS (optional):"
    echo "  sudo security add-trusted-cert -d -r trustRoot \\"
    echo "    -k /Library/Keychains/System.keychain certs/server.crt"
    echo ""
    echo "When using curl, add -k flag to skip TLS verify:"
    echo "  curl -k https://localhost:8443/api/stats"
}

# ── Option 3: Generate CSR for production CA ──────────────────────────────────
generate_csr() {
    echo -e "${AMBER}📝 Generating production private key + CSR...${NC}"
    read -r -p "Enter your domain name (e.g. kelan.yourdomain.com): " DOMAIN

    if [[ -z "$DOMAIN" ]]; then
        echo -e "${RED}❌ Domain name is required.${NC}"
        exit 1
    fi

    openssl genrsa -out certs/server.key 4096
    chmod 600 certs/server.key

    openssl req -new \
        -key certs/server.key \
        -out certs/server.csr \
        -subj "/C=US/ST=State/L=City/O=KELAN Security/OU=Production/CN=$DOMAIN" \
        -addext "subjectAltName=DNS:$DOMAIN,DNS:www.$DOMAIN"

    echo ""
    echo -e "${GREEN}✅ Private key and CSR generated.${NC}"
    echo ""
    echo "📋 Next steps for production:"
    echo ""
    echo "  Option A — Let's Encrypt (free, automated):"
    echo "    brew install certbot"
    echo "    sudo certbot certonly --standalone -d $DOMAIN"
    echo "    sudo cp /etc/letsencrypt/live/$DOMAIN/fullchain.pem certs/server.crt"
    echo "    sudo cp /etc/letsencrypt/live/$DOMAIN/privkey.pem certs/server.key"
    echo "    sudo chown \$(whoami) certs/server.crt certs/server.key"
    echo ""
    echo "  Option B — Submit CSR to commercial CA:"
    echo "    Send certs/server.csr to DigiCert, Sectigo, or GlobalSign"
    echo "    Place returned cert at: certs/server.crt"
    echo ""
    echo -e "${RED}⚠️  Security reminders:${NC}"
    echo "   • NEVER commit certs/server.key to git"
    echo "   • Store private key with chmod 600 (already done)"
    echo "   • Let's Encrypt auto-renews every 90 days"
}

# ── Route based on argument or menu ───────────────────────────────────────────
case "$MODE" in
    dev)           generate_mkcert ;;
    self-signed)   generate_openssl_self_signed ;;
    prod)          generate_csr ;;
    menu)
        echo "Select certificate type:"
        echo ""
        echo "  1) Development  — mkcert (macOS Keychain trusted — recommended)"
        echo "  2) Development  — openssl self-signed (fallback, not browser-trusted)"
        echo "  3) Production   — generate CSR for Let's Encrypt or commercial CA"
        echo ""
        read -r -p "Enter choice [1/2/3]: " choice
        case "$choice" in
            1) generate_mkcert ;;
            2) generate_openssl_self_signed ;;
            3) generate_csr ;;
            *) echo -e "${RED}Invalid choice.${NC}"; exit 1 ;;
        esac
        ;;
    *)
        echo -e "${RED}Unknown mode: $MODE${NC}"
        echo "Usage: $0 [dev|self-signed|prod]"
        exit 1
        ;;
esac

# ── Set permissions ────────────────────────────────────────────────────────────
[[ -f certs/server.key ]] && chmod 600 certs/server.key
[[ -f certs/server.crt ]] && chmod 644 certs/server.crt

# ── Verify output ─────────────────────────────────────────────────────────────
echo "📋 Certificate Information:"
echo "=========================================="
if [[ -f certs/server.crt ]]; then
    openssl x509 -in certs/server.crt -noout -subject -dates -issuer 2>/dev/null || true
fi
echo "=========================================="
echo ""
echo "Files created:"
[[ -f certs/server.key ]] && echo "  certs/server.key  (PRIVATE — chmod 600, never commit)"
[[ -f certs/server.crt ]] && echo "  certs/server.crt  (certificate)"
[[ -f certs/server.csr ]] && echo "  certs/server.csr  (CSR — submit to CA)"
echo ""
echo -e "${GREEN}✅ Certificate generation complete!${NC}"
echo ""
