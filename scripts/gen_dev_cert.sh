#!/usr/bin/env bash
# Generates a self-signed TLS certificate for local development.
# Usage: bash scripts/gen_dev_cert.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
CERT_DIR="$REPO_ROOT/certs"
# Prefer repo-root .env; fall back to aitp-server/.env
if [ -f "$REPO_ROOT/.env" ]; then
    ENV_FILE="$REPO_ROOT/.env"
else
    ENV_FILE="$REPO_ROOT/aitp-server/.env"
fi

echo "==> Generating self-signed TLS certificate …"
mkdir -p "$CERT_DIR"

openssl req -x509 -newkey rsa:4096 \
  -keyout "$CERT_DIR/key.pem" \
  -out    "$CERT_DIR/cert.pem" \
  -days 365 \
  -nodes \
  -subj "/C=IN/ST=Dev/L=Local/O=Kelan Security/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"

echo ""
echo "  Cert → $CERT_DIR/cert.pem"
echo "  Key  → $CERT_DIR/key.pem"

# Append TLS paths to .env if not already present
if [ -f "$ENV_FILE" ]; then
    grep -q "TLS_CERT_PATH" "$ENV_FILE" 2>/dev/null || \
        echo "TLS_CERT_PATH=./certs/cert.pem" >> "$ENV_FILE"
    grep -q "TLS_KEY_PATH" "$ENV_FILE" 2>/dev/null || \
        echo "TLS_KEY_PATH=./certs/key.pem" >> "$ENV_FILE"
    echo ""
    echo "==> Updated $ENV_FILE with TLS paths"
else
    echo ""
    echo "==> .env not found at $ENV_FILE — skipping .env update"
    echo "    Add these manually:"
    echo "      TLS_CERT_PATH=./certs/cert.pem"
    echo "      TLS_KEY_PATH=./certs/key.pem"
fi

echo ""
echo "==> Done! To start the server with TLS:"
echo "    cargo run -p aitp-server"
echo ""
echo "    Or override inline (without modifying .env):"
echo "    TLS_CERT_PATH=./certs/cert.pem TLS_KEY_PATH=./certs/key.pem cargo run -p aitp-server"
