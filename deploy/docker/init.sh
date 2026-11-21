#!/usr/bin/env bash
# Create or update deploy/docker/.env for the Compose setup. Safe to re-run: never replaces
# AUTH_PASSWORD or SUPERBOT_MASTER_KEY.
#   ./init.sh                                   # http://localhost, random password
#   ./init.sh --domain bots.example.com --tz Europe/Jersey --user-name Alex
set -euo pipefail

DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ENV_FILE=${ENV_FILE:-"$DIR/.env"}
DOMAIN="" TZ_VALUE="" USER_NAME_VALUE="" HARNESSES="" ISOLATION_VALUE=""
DOMAIN_SET=false HARNESSES_SET=false

die() { printf 'init.sh: %s\n' "$*" >&2; exit 1; }

usage() {
  cat <<'EOF'
Usage: init.sh [options]

  --domain NAME      Public hostname: automatic HTTPS, listen on all interfaces
  --localhost        Plain HTTP on 127.0.0.1 only (clears a previous --domain)
  --tz ZONE          TZ for routines (e.g. Europe/Jersey)
  --user-name NAME   USER_NAME shown in the app
  --harnesses LIST   Harness CLIs baked into the image, e.g. "claude codex pi" (add hermes for Hermes Agent)
  --isolation        Run each user's Bots as their own Unix account (ISOLATION=users; new .env files have it)
  --no-isolation     Run every Bot as botd's account (ISOLATION=off)
  -h, --help         Show this help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --domain) DOMAIN=${2:?--domain needs a value}; DOMAIN_SET=true; shift 2 ;;
    --localhost) DOMAIN=""; DOMAIN_SET=true; shift ;;
    --tz) TZ_VALUE=${2:?--tz needs a value}; shift 2 ;;
    --user-name) USER_NAME_VALUE=${2:?--user-name needs a value}; shift 2 ;;
    --harnesses) HARNESSES=${2?--harnesses needs a value}; HARNESSES_SET=true; shift 2 ;;
    --isolation) ISOLATION_VALUE=users; shift ;;
    --no-isolation) ISOLATION_VALUE=off; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown option: $1 (see --help)" ;;
  esac
done

if [[ -n "$DOMAIN" && ! "$DOMAIN" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$ ]]; then
  die "--domain must be a bare hostname like bots.example.com"
fi
for value in "$TZ_VALUE" "$USER_NAME_VALUE" "$HARNESSES"; do
  [[ "$value" != *"'"* && "$value" != *$'\n'* ]] || die "values must not contain a single quote or newline: $value"
done

# Values are single-quoted so Compose reads them literally.
set_env() {
  local key=$1 value=$2 tmp line found=false
  tmp=$(mktemp "$ENV_FILE.XXXXXX")
  while IFS= read -r line || [[ -n "$line" ]]; do
    if [[ "$line" == "$key="* ]]; then
      printf "%s='%s'\n" "$key" "$value"
      found=true
    else
      printf '%s\n' "$line"
    fi
  done <"$ENV_FILE" >"$tmp"
  [[ "$found" == true ]] || printf "%s='%s'\n" "$key" "$value" >>"$tmp"
  chmod 0600 "$tmp"
  mv "$tmp" "$ENV_FILE"
}

if [[ ! -f "$ENV_FILE" ]]; then
  install -m 0600 "$DIR/.env.example" "$ENV_FILE"
  printf 'Created %s\n' "$ENV_FILE"
fi
chmod 0600 "$ENV_FILE"

new_password=""
if ! grep -Eq "^AUTH_PASSWORD=('[^']+'|[^'[:space:]]+)" "$ENV_FILE"; then
  new_password=$(od -An -tx1 -N24 /dev/urandom | tr -d ' \n')
  set_env AUTH_PASSWORD "$new_password"
fi

new_key=false
if ! grep -Eq "^SUPERBOT_MASTER_KEY=('[^']+'|[^'[:space:]]+)" "$ENV_FILE"; then
  set_env SUPERBOT_MASTER_KEY "$(od -An -tx1 -N32 /dev/urandom | tr -d ' \n')"
  new_key=true
fi

if [[ "$DOMAIN_SET" == true ]]; then
  set_env SUPERBOT_DOMAIN "$DOMAIN"
  if [[ -n "$DOMAIN" ]]; then
    set_env SUPERBOT_BIND 0.0.0.0
    set_env CORS_ORIGINS "https://$DOMAIN"
  else
    set_env SUPERBOT_BIND 127.0.0.1
    set_env CORS_ORIGINS ""
  fi
fi
[[ -z "$TZ_VALUE" ]] || set_env TZ "$TZ_VALUE"
[[ -z "$USER_NAME_VALUE" ]] || set_env USER_NAME "$USER_NAME_VALUE"
[[ "$HARNESSES_SET" != true ]] || set_env SUPERBOT_HARNESSES "$HARNESSES"
[[ -z "$ISOLATION_VALUE" ]] || set_env ISOLATION "$ISOLATION_VALUE"

if [[ -n "$new_password" ]]; then
  printf 'New login password (also AUTH_PASSWORD in %s): %s\n' "$ENV_FILE" "$new_password"
fi
if [[ "$new_key" == true ]]; then
  printf 'New master key: SUPERBOT_MASTER_KEY in %s. Back it up apart from the data volume.\n' "$ENV_FILE"
fi
printf 'Next: cd %s && docker compose up -d --build\n' "$DIR"
