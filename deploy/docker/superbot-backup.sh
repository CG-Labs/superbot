#!/usr/bin/env bash
# SQLite-safe backup of DATA_DIR inside the SuperBot image. Installed as /usr/local/bin/superbot-backup.
#   superbot-backup          write $BACKUP_DIR/superbot-<UTC stamp>.tar.gz and prune old archives
#   superbot-backup -        stream the archive to stdout
#   superbot-backup --loop   back up now, then every SUPERBOT_BACKUP_INTERVAL seconds (compose `backup` service)
set -euo pipefail
umask 077

DATA_DIR=${DATA_DIR:-/data}
BACKUP_DIR=${BACKUP_DIR:-/backups}
RETENTION_DAYS=${SUPERBOT_BACKUP_RETENTION_DAYS:-14}
INTERVAL=${SUPERBOT_BACKUP_INTERVAL:-86400}

log() { printf '%s superbot-backup: %s\n' "$(date -u +%FT%TZ)" "$*" >&2; }

# Archive layout: app.sqlite (an online .backup copy) plus everything else in DATA_DIR
# except the live database files and per-run screen state.
archive() {
  local out=$1 tmp status=0
  local members=(-C "$DATA_DIR" .)
  tmp=$(mktemp -d)
  if [[ -f "$DATA_DIR/app.sqlite" ]]; then
    sqlite3 "$DATA_DIR/app.sqlite" ".backup '$tmp/app.sqlite'" || status=$?
    members+=(-C "$tmp" app.sqlite)
  fi
  if [[ $status -eq 0 ]]; then
    tar -czf "$out" \
      --anchored --exclude=./app.sqlite --exclude='./app.sqlite-*' --exclude=./screens \
      --exclude='./.restore-*' --exclude='./.pre-restore-*' \
      "${members[@]}" || status=$?
  fi
  rm -rf "$tmp"
  return "$status"
}

# The backup sidecar and `docker compose exec botd superbot-backup` share BACKUP_DIR, so runs
# take a lock on it and never reuse a file name. Explicit exits: callers use `||`, which turns off set -e.
backup_to_dir() {
  mkdir -p "$BACKUP_DIR" || return
  (
    flock -w 600 9 || { log "timed out waiting for $BACKUP_DIR/.lock"; exit 1; }
    stamp=$(date -u +%Y%m%d-%H%M%S)
    dest="$BACKUP_DIR/superbot-$stamp.tar.gz"
    n=1
    while [[ -e "$dest" ]]; do
      dest="$BACKUP_DIR/superbot-$stamp-$n.tar.gz"
      n=$((n + 1))
    done
    partial=$(mktemp "$BACKUP_DIR/.partial-XXXXXXXX") || exit 1
    archive "$partial" || { rm -f "$partial"; exit 1; }
    mv "$partial" "$dest" || exit 1
    find "$BACKUP_DIR" -mindepth 1 -maxdepth 1 \
      \( \( -name 'superbot-*.tar.gz' -mtime "+$RETENTION_DAYS" \) -o \( -name '.partial-*' -mmin +1440 \) \) \
      -delete || exit 1
    log "wrote $dest"
  ) 9>"$BACKUP_DIR/.lock"
}

case "${1:-}" in
  -) archive - ;;
  --loop)
    [[ "$INTERVAL" =~ ^[1-9][0-9]*$ ]] || { log "SUPERBOT_BACKUP_INTERVAL must be a positive number of seconds"; exit 1; }
    while true; do
      backup_to_dir || log "backup failed; retrying in ${INTERVAL}s"
      # Background sleep + wait so SIGTERM stops the loop at once.
      sleep "$INTERVAL" &
      wait $!
    done
    ;;
  "") backup_to_dir ;;
  -h|--help) sed -n '2,5s/^# \{0,1\}//p' "$0" ;;
  *) log "unknown argument: $1"; exit 2 ;;
esac
