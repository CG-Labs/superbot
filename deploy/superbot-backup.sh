#!/usr/bin/env bash
# SQLite-safe backup of SuperBot's DATA_DIR, for the installer (systemd timer) and the Docker image.
# Installed as /usr/local/bin/superbot-backup. Design: docs/adr/0030-backup-restore-drill.md.
#   superbot-backup                write $BACKUP_DIR/superbot-<UTC stamp>.tar.gz[.age] and prune old archives
#   superbot-backup -              stream the archive to stdout
#   superbot-backup --loop         back up now, then every SUPERBOT_BACKUP_INTERVAL seconds (compose `backup` service)
#   superbot-backup --home DIR     read DATA_DIR from DIR/superbot/.env; archives go to DIR/superbot/backups
# With SUPERBOT_BACKUP_AGE_RECIPIENTS (age public keys) or SUPERBOT_BACKUP_AGE_RECIPIENTS_FILE set,
# archives are encrypted with age and end in .age. The master key is never in an archive.
set -euo pipefail
umask 077

log() { printf '%s superbot-backup: %s\n' "$(date -u +%FT%TZ)" "$*" >&2; }
die() { log "$*"; exit 2; }

# KEY=value from an installer .env, without running it as shell. Quotes around the value are dropped.
env_file_value() {
  local file=$1 key=$2 value
  value=$(sed -n "s/^${key}=//p" "$file" | tail -n 1)
  case $value in
    \"*\" | \'*\') value=${value:1:-1} ;;
  esac
  printf '%s' "$value"
}

# Installer layout: ~/superbot/.env holds DATA_DIR and the backup settings.
use_home() {
  local home=$1 env_file key value
  env_file="$home/superbot/.env"
  [[ -r "$env_file" ]] || die "cannot read $env_file"
  for key in DATA_DIR BACKUP_DIR SUPERBOT_BACKUP_RETENTION_DAYS SUPERBOT_BACKUP_AGE_RECIPIENTS SUPERBOT_BACKUP_AGE_RECIPIENTS_FILE; do
    if [[ -z "${!key:-}" ]]; then
      value=$(env_file_value "$env_file" "$key")
      [[ -z "$value" ]] || export "$key=$value"
    fi
  done
  export DATA_DIR=${DATA_DIR:-"$home/superbot/data"}
  export BACKUP_DIR=${BACKUP_DIR:-"$home/superbot/backups"}
}

mode=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --home) [[ -n "${2:-}" ]] || die "--home needs a directory"; use_home "$2"; shift 2 ;;
    -h|--help) sed -n '2,9s/^# \{0,1\}//p' "$0"; exit 0 ;;
    - | --loop) mode=$1; shift ;;
    # Units from before ADR 0030 ran `superbot-backup <service-user-home>`.
    /*) [[ -d "$1" ]] || die "no such directory: $1"; use_home "$1"; shift ;;
    *) die "unknown argument: $1 (see --help)" ;;
  esac
done

DATA_DIR=${DATA_DIR:-/data}
BACKUP_DIR=${BACKUP_DIR:-/backups}
RETENTION_DAYS=${SUPERBOT_BACKUP_RETENTION_DAYS:-14}
INTERVAL=${SUPERBOT_BACKUP_INTERVAL:-86400}
FORMAT=1

[[ "$RETENTION_DAYS" =~ ^[0-9]+$ ]] || die "SUPERBOT_BACKUP_RETENTION_DAYS must be a whole number of days"

recipients=()
if [[ -n "${SUPERBOT_BACKUP_AGE_RECIPIENTS:-}" ]]; then
  for r in ${SUPERBOT_BACKUP_AGE_RECIPIENTS//,/ }; do
    recipients+=(-r "$r")
  done
fi
if [[ -n "${SUPERBOT_BACKUP_AGE_RECIPIENTS_FILE:-}" ]]; then
  [[ -r "$SUPERBOT_BACKUP_AGE_RECIPIENTS_FILE" ]] || die "cannot read SUPERBOT_BACKUP_AGE_RECIPIENTS_FILE=$SUPERBOT_BACKUP_AGE_RECIPIENTS_FILE"
  recipients+=(-R "$SUPERBOT_BACKUP_AGE_RECIPIENTS_FILE")
fi
# Asked for encryption but can't: fail rather than write plaintext.
if [[ ${#recipients[@]} -gt 0 ]] && ! command -v age >/dev/null 2>&1; then
  die "age recipients are set but age is not installed"
fi
suffix=.tar.gz
[[ ${#recipients[@]} -eq 0 ]] || suffix=.tar.gz.age

# Archive layout: app.sqlite (an online .backup copy), .superbot-backup (format and time), and
# everything else in DATA_DIR except the live database files and per-run screen state.
archive() {
  local tmp status=0
  local members=(-C "$DATA_DIR" .)
  [[ -d "$DATA_DIR" ]] || { log "no DATA_DIR at $DATA_DIR"; return 1; }
  tmp=$(mktemp -d)
  printf 'format=%s\ncreated=%s\n' "$FORMAT" "$(date -u +%FT%TZ)" >"$tmp/.superbot-backup"
  members+=(-C "$tmp" .superbot-backup)
  if [[ -f "$DATA_DIR/app.sqlite" ]]; then
    sqlite3 "$DATA_DIR/app.sqlite" ".backup '$tmp/app.sqlite'" || status=$?
    members+=(-C "$tmp" app.sqlite)
  fi
  if [[ $status -eq 0 ]]; then
    if [[ ${#recipients[@]} -gt 0 ]]; then
      { tar -czf - "${excludes[@]}" "${members[@]}" | age "${recipients[@]}"; } || status=$?
    else
      tar -czf - "${excludes[@]}" "${members[@]}" || status=$?
    fi
  fi
  rm -rf "$tmp"
  return "$status"
}
excludes=(--anchored --exclude=./app.sqlite --exclude='./app.sqlite-*' --exclude=./screens
  --exclude=./.superbot-backup --exclude='./.restore-*' --exclude='./.pre-restore-*')

# The backup sidecar and `docker compose exec botd superbot-backup` share BACKUP_DIR, so runs
# take a lock on it and never reuse a file name. Explicit exits: callers use `||`, which turns off set -e.
backup_to_dir() {
  mkdir -p "$BACKUP_DIR" || return
  (
    flock -w 600 9 || { log "timed out waiting for $BACKUP_DIR/.lock"; exit 1; }
    stamp=$(date -u +%Y%m%d-%H%M%S)
    dest="$BACKUP_DIR/superbot-$stamp$suffix"
    n=1
    while [[ -e "$dest" ]]; do
      dest="$BACKUP_DIR/superbot-$stamp-$n$suffix"
      n=$((n + 1))
    done
    partial=$(mktemp "$BACKUP_DIR/.partial-XXXXXXXX") || exit 1
    archive >"$partial" || { rm -f "$partial"; exit 1; }
    mv "$partial" "$dest" || exit 1
    # Folders named <stamp> are snapshots from the installer's script before ADR 0030.
    find "$BACKUP_DIR" -mindepth 1 -maxdepth 1 \
      \( \( -type f \( -name 'superbot-*.tar.gz' -o -name 'superbot-*.tar.gz.age' \) -mtime "+$RETENTION_DAYS" \) \
      -o \( -type f -name '.partial-*' -mmin +1440 \) \
      -o \( -type d -name '[0-9]*-[0-9]*' -mtime "+$RETENTION_DAYS" \) \) \
      -exec rm -rf -- {} + || exit 1
    log "wrote $dest"
  ) 9>"$BACKUP_DIR/.lock"
}

case "$mode" in
  -) archive ;;
  --loop)
    [[ "$INTERVAL" =~ ^[1-9][0-9]*$ ]] || die "SUPERBOT_BACKUP_INTERVAL must be a positive number of seconds"
    while true; do
      backup_to_dir || log "backup failed; retrying in ${INTERVAL}s"
      # Background sleep + wait so SIGTERM stops the loop at once.
      sleep "$INTERVAL" &
      wait $!
    done
    ;;
  "") backup_to_dir ;;
esac
