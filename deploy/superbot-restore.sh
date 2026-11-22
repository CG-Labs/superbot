#!/usr/bin/env bash
# Restore or check a superbot-backup archive. Installed as /usr/local/bin/superbot-restore.
# Design and the full drill: docs/adr/0030-backup-restore-drill.md, docs/ops/backup-restore.md.
#   superbot-restore [--home DIR] [--identity FILE] <archive | ->           restore into DATA_DIR (botd stopped)
#   superbot-restore [--home DIR] [--identity FILE] --check <archive | ->   only unpack, verify, and summarise
# --home DIR reads DATA_DIR and PORT from DIR/superbot/.env (installer layout). Encrypted (.age)
# archives need the age identity: --identity or SUPERBOT_BACKUP_AGE_IDENTITY_FILE. An encrypted
# app.sqlite (docs/adr/0116-database-encrypted-at-rest.md) is read with `botd database query` (botd on
# PATH, or SUPERBOT_BOTD) and the master key; without them it is restored unread.
# Run as the user that owns DATA_DIR. The previous contents stay in DATA_DIR/.pre-restore-<stamp>/.
set -euo pipefail
umask 077

die() { printf 'superbot-restore: %s\n' "$*" >&2; exit 1; }
say() { printf 'superbot-restore: %s\n' "$*" >&2; }

env_file_value() {
  local file=$1 key=$2 value
  value=$(sed -n "s/^${key}=//p" "$file" | tail -n 1)
  case $value in
    \"*\" | \'*\') value=${value:1:-1} ;;
  esac
  printf '%s' "$value"
}

use_home() {
  local home=$1 env_file key value
  env_file="$home/superbot/.env"
  [[ -r "$env_file" ]] || die "cannot read $env_file"
  for key in DATA_DIR PORT SUPERBOT_BACKUP_AGE_IDENTITY_FILE SUPERBOT_MASTER_KEY SUPERBOT_MASTER_KEY_FILE \
    SUPERBOT_MASTER_KEY_PREVIOUS SUPERBOT_MASTER_KEY_PREVIOUS_FILE; do
    if [[ -z "${!key:-}" ]]; then
      value=$(env_file_value "$env_file" "$key")
      [[ -z "$value" ]] || export "$key=$value"
    fi
  done
  export DATA_DIR=${DATA_DIR:-"$home/superbot/data"}
  [[ -n "${SUPERBOT_MASTER_KEY:-}${SUPERBOT_MASTER_KEY_FILE:-}" ]] || export SUPERBOT_MASTER_KEY_FILE="$home/.config/superbot/master.key"
}

check_only=false
identity=""
src=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --home) [[ -n "${2:-}" ]] || die "--home needs a directory"; use_home "$2"; shift 2 ;;
    --identity) [[ -n "${2:-}" ]] || die "--identity needs a file"; identity=$2; shift 2 ;;
    --check) check_only=true; shift ;;
    -h|--help) sed -n '2,9s/^# \{0,1\}//p' "$0"; exit 0 ;;
    -) src=-; shift ;;
    -*) die "unknown option: $1 (see --help)" ;;
    *) [[ -z "$src" ]] || die "give one archive"; src=$1; shift ;;
  esac
done

DATA_DIR=${DATA_DIR:-/data}
PORT=${PORT:-3000}
identity=${identity:-${SUPERBOT_BACKUP_AGE_IDENTITY_FILE:-}}
[[ -n "$src" ]] || die "usage: superbot-restore [--check] [--home DIR] [--identity FILE] <archive.tar.gz[.age] | ->"
[[ "$src" == - || -f "$src" ]] || die "no such archive: $src"

botd_running() {
  # `compose run` containers don't answer to the service name, so the first only reaches a running botd.
  curl -fsS --max-time 2 "http://botd:${PORT}/healthz" >/dev/null 2>&1 && return 0
  curl -fsS --max-time 2 "http://127.0.0.1:${PORT}/healthz" >/dev/null 2>&1 && return 0
  command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet superbot.service 2>/dev/null
}

plain_sqlite() { [[ "$(head -c 15 "$1" | tr -d '\0')" == "SQLite format 3" ]]; }

# Runs read-only SQL on a database copy: sqlite3 for a plain one, botd (with the master key)
# for an encrypted one.
query() {
  if plain_sqlite "$1"; then
    sqlite3 -readonly "$1" "$2"
  else
    "${SUPERBOT_BOTD:-botd}" database query "$1" "$2"
  fi
}

count() { query "$1" "SELECT count(*) FROM $2" 2>/dev/null || echo '?'; }

summary() {
  local dir=$1 db=$1/app.sqlite created newest sealed
  created=$(sed -n 's/^created=//p' "$dir/.superbot-backup" 2>/dev/null || true)
  newest=$(query "$db" "SELECT strftime('%Y-%m-%dT%H:%M:%SZ', max(at) / 1000, 'unixepoch') FROM audit_events" 2>/dev/null || true)
  sealed=no
  [[ -z $(query "$db" "SELECT 1 FROM settings WHERE key = 'secrets_key_check'" 2>/dev/null) ]] || sealed=yes
  plain_sqlite "$db" || sealed="yes (the database is encrypted under it)"
  printf 'created:          %s\n' "${created:-unknown (archive from before ADR 0030)}"
  printf 'newest audit:     %s\n' "${newest:-none}"
  printf 'users:            %s\n' "$(count "$db" users)"
  printf 'bots:             %s\n' "$(count "$db" bots)"
  printf 'messages:         %s\n' "$(count "$db" messages)"
  printf 'routines:         %s\n' "$(count "$db" routines)"
  printf 'saved secrets:    %s\n' "$(count "$db" secrets)"
  printf 'audit events:     %s\n' "$(count "$db" audit_events)"
  printf 'needs master key: %s\n' "$sealed"
  plain_sqlite "$db" || printf 'database:         encrypted (SQLCipher, ADR 0116)\n'
}

if [[ "$check_only" == true ]]; then
  work=$(mktemp -d)
else
  # A root-owned restore would leave botd unable to write its own data.
  if [[ "${EUID:-$(id -u)}" -eq 0 && -d "$DATA_DIR" && $(stat -c %u "$DATA_DIR") != 0 ]]; then
    die "run as the owner of $DATA_DIR ($(stat -c %U "$DATA_DIR")), e.g. sudo -u $(stat -c %U "$DATA_DIR") superbot-restore ..."
  fi
  botd_running && die "botd is running; stop it first (systemctl stop superbot, or docker compose stop botd backup)"
  mkdir -p "$DATA_DIR"
  work="$DATA_DIR/.restore-$(date -u +%Y%m%d-%H%M%S)"
  mkdir "$work"
fi
trap 'rm -rf "$work"' EXIT

input=$src
if [[ "$src" == - ]]; then
  input="$work/archive"
  cat >"$input"
fi
magic=$(head -c 34 "$input" | tr -d '\0')
if [[ "$magic" == age-encryption.org/v1* || "$magic" == "-----BEGIN AGE ENCRYPTED FILE-----" ]]; then
  command -v age >/dev/null 2>&1 || die "the archive is encrypted with age, which is not installed"
  [[ -n "$identity" ]] || die "the archive is encrypted: give the age identity with --identity FILE or SUPERBOT_BACKUP_AGE_IDENTITY_FILE"
  [[ -r "$identity" ]] || die "cannot read age identity $identity"
  age -d -i "$identity" -o "$work/archive.tar.gz" "$input" || die "could not decrypt the archive with $identity"
  input="$work/archive.tar.gz"
fi

mkdir "$work/data"
tar -xzf "$input" -C "$work/data" --no-same-owner --no-same-permissions || die "could not unpack the archive"
rm -f "$work/archive" "$work/archive.tar.gz"
[[ -f "$work/data/app.sqlite" ]] || die "archive has no app.sqlite; not a superbot-backup archive"
format=$(sed -n 's/^format=//p' "$work/data/.superbot-backup" 2>/dev/null || true)
[[ -z "$format" || "$format" == 1 ]] || die "archive format $format is newer than this superbot-restore; upgrade first"
size=$(stat -c %s "$work/data/app.sqlite")
if plain_sqlite "$work/data/app.sqlite"; then
  check=$(sqlite3 "$work/data/app.sqlite" 'PRAGMA integrity_check;' 2>&1) || true
  [[ "$check" == ok ]] || die "app.sqlite failed integrity_check: $check"
elif (( size == 0 || size % 512 != 0 )); then
  # SQLCipher writes whole pages, so anything else is damaged, encrypted or not.
  die "app.sqlite failed integrity_check: neither SQLite nor whole encrypted pages ($size bytes)"
elif check=$(query "$work/data/app.sqlite" 'PRAGMA integrity_check;' 2>&1); then
  [[ "$check" == ok ]] || die "app.sqlite failed integrity_check: $check"
elif [[ "$check" == *"wrong key"* ]]; then
  die "app.sqlite is encrypted under another master key: $check. Give its key (SUPERBOT_MASTER_KEY_FILE, or SUPERBOT_MASTER_KEY_PREVIOUS_FILE)"
else
  say "app.sqlite is encrypted and wasn't checked here ($check); botd checks it with the master key when it starts"
fi

summary "$work/data"
if [[ "$check_only" == true ]]; then
  say "archive is good"
  exit 0
fi

rm -f "$work/data/.superbot-backup"
previous="$DATA_DIR/.pre-restore-${work##*/.restore-}"
mkdir "$previous"
find "$DATA_DIR" -mindepth 1 -maxdepth 1 ! -name '.restore-*' ! -name '.pre-restore-*' -exec mv -t "$previous" {} +
find "$work/data" -mindepth 1 -maxdepth 1 -exec mv -t "$DATA_DIR" {} +
say "restored into $DATA_DIR. Previous data kept in $previous (delete it once SuperBot looks right)."
