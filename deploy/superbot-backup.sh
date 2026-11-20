#!/usr/bin/env bash
# Daily sqlite-safe backup of SuperBot DATA_DIR. Installed as /usr/local/bin/superbot-backup
set -euo pipefail

HOME_DIR=${1:?usage: superbot-backup <service-user-home>}
ENV_FILE="$HOME_DIR/superbot/.env"
# shellcheck disable=SC1090
set -a
# shellcheck source=/dev/null
source "$ENV_FILE"
set +a

DATA_DIR=${DATA_DIR:-"$HOME_DIR/superbot/data"}
BACKUP_ROOT="$HOME_DIR/superbot/backups"
RETENTION_DAYS=${SUPERBOT_BACKUP_RETENTION_DAYS:-14}
STAMP=$(date -u +%Y%m%d-%H%M%S)
DEST="$BACKUP_ROOT/$STAMP"
DB="$DATA_DIR/app.sqlite"

mkdir -p "$DEST"
if [[ -f "$DB" ]]; then
  sqlite3 "$DB" ".backup '$DEST/app.sqlite'"
  cp -a "$DATA_DIR/bots" "$DEST/" 2>/dev/null || true
  # Each user's facts (users/<id>/USER.md, ADR 0029); USER.md is from before per-user folders.
  cp -a "$DATA_DIR/users" "$DEST/" 2>/dev/null || true
  cp -a "$DATA_DIR/USER.md" "$DEST/" 2>/dev/null || true
fi
find "$BACKUP_ROOT" -mindepth 1 -maxdepth 1 -type d -mtime "+$RETENTION_DAYS" -exec rm -rf {} +