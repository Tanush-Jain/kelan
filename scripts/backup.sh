#!/usr/bin/env bash
# Kelan Security — macOS Backup Script
# Backs up PostgreSQL, configuration, and certs to ~/kelan/backups
# Usage: ./scripts/backup.sh [docker-compose-file]
set -euo pipefail

GREEN='\033[0;32m'
AMBER='\033[0;33m'
RED='\033[0;31m'
BOLD='\033[1m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
COMPOSE_FILE="${1:-$ROOT_DIR/yml/docker-compose.prod.yml}"
BACKUP_ROOT="$HOME/kelan/backups"
DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="$BACKUP_ROOT/$DATE"

echo -e "\n${BOLD}Kelan Security — Backup${NC}"
echo -e "Date: $DATE"
echo -e "Target: $BACKUP_DIR\n"

mkdir -p "$BACKUP_DIR"

# ── 1. PostgreSQL ─────────────────────────────────────────────────────────
echo -e "${AMBER}→ Dumping PostgreSQL...${NC}"
if docker compose -f "$COMPOSE_FILE" ps postgres 2>/dev/null | grep -q "running\|Up"; then
    docker compose -f "$COMPOSE_FILE" exec -T postgres \
        pg_dump -U kelan kelan \
        | gzip > "$BACKUP_DIR/postgres_$DATE.sql.gz"
    echo -e "${GREEN}  ✓ Database backup: $BACKUP_DIR/postgres_$DATE.sql.gz${NC}"
else
    echo -e "${AMBER}  ⚠ Postgres not running — skipping DB backup${NC}"
fi

# ── 2. Configuration files ───────────────────────────────────────────────
echo -e "${AMBER}→ Archiving configuration...${NC}"
tar -czf "$BACKUP_DIR/config_$DATE.tar.gz" \
    -C "$ROOT_DIR" \
    --exclude=".git" \
    --exclude="target" \
    --exclude="node_modules" \
    .env.example \
    yml/ \
    nginx/ \
    yml/docker-compose.prod.yml \
    yml/docker-compose.monitoring.yml \
    2>/dev/null || true
echo -e "${GREEN}  ✓ Config archive: $BACKUP_DIR/config_$DATE.tar.gz${NC}"

# ── 3. Certificates ───────────────────────────────────────────────────────
echo -e "${AMBER}→ Backing up certificates (no private keys in config backup)...${NC}"
if [[ -d "$ROOT_DIR/certs" ]]; then
    # NOTE: We backup the cert (public) separately. The private key should be
    # stored in a secrets manager, not in a general backup.
    cp "$ROOT_DIR/certs/server.crt" "$BACKUP_DIR/server_$DATE.crt" 2>/dev/null || true
    echo -e "${GREEN}  ✓ Certificate backed up${NC}"
    echo -e "${AMBER}  ⚠  Private key (server.key) NOT included — store in secrets manager${NC}"
fi

# ── 4. Docker volumes metadata ───────────────────────────────────────────
echo -e "${AMBER}→ Saving Docker volume list...${NC}"
docker volume ls --format "{{.Name}}" | grep -i kelan > "$BACKUP_DIR/volumes_$DATE.txt" 2>/dev/null || true
echo -e "${GREEN}  ✓ Volume list: $BACKUP_DIR/volumes_$DATE.txt${NC}"

# ── 5. Prune old backups (keep 30 days) ──────────────────────────────────
echo -e "${AMBER}→ Pruning backups older than 30 days...${NC}"
find "$BACKUP_ROOT" -maxdepth 1 -type d -mtime +30 -exec rm -rf {} + 2>/dev/null || true
echo -e "${GREEN}  ✓ Pruning done${NC}"

# ── Summary ───────────────────────────────────────────────────────────────
TOTAL_SIZE=$(du -sh "$BACKUP_DIR" 2>/dev/null | cut -f1)
echo ""
echo -e "${GREEN}${BOLD}✅ Backup complete${NC}"
echo -e "  Directory: $BACKUP_DIR"
echo -e "  Size:      $TOTAL_SIZE"
echo ""
echo -e "${BOLD}Recent backups in $BACKUP_ROOT:${NC}"
ls -1t "$BACKUP_ROOT" | head -5 | while read -r d; do
    SIZE=$(du -sh "$BACKUP_ROOT/$d" 2>/dev/null | cut -f1)
    echo "  $d  ($SIZE)"
done
echo ""
