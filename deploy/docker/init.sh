#!/usr/bin/env bash
# Create or update deploy/docker/.env for the Compose setup. Safe to re-run: never replaces
# AUTH_PASSWORD or SUPERBOT_MASTER_KEY, except --rotate-master-key (docs/ops/master-key-rotation.md).
#   ./init.sh                                   # http://localhost, random password
#   ./init.sh --domain bots.example.com --tz Europe/Jersey --user-name Alex
#   ./init.sh --from-source                     # build the images here instead of pulling them
# A new .env gets an age key for backups (docs/adr/0114-backups-encrypted-by-default.md), made with
# the host's age-keygen; the private half goes to backup-identity.txt (BACKUP_IDENTITY_FILE).
set -euo pipefail

DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ENV_FILE=${ENV_FILE:-"$DIR/.env"}
DOMAIN="" TZ_VALUE="" USER_NAME_VALUE="" HARNESSES="" ISOLATION_VALUE="" SOURCE=""
DOMAIN_SET=false HARNESSES_SET=false ROTATE_KEY=false
BACKUP_GENERATE=false BACKUP_ENCRYPTION=""
BACKUP_IDENTITY_FILE=${BACKUP_IDENTITY_FILE:-"$DIR/backup-identity.txt"}
BUILD_FILES=docker-compose.yml:docker-compose.build.yml

die() { printf 'init.sh: %s\n' "$*" >&2; exit 1; }

usage() {
  cat <<'EOF'
Usage: init.sh [options]

  --domain NAME      Public hostname: automatic HTTPS, listen on all interfaces
  --localhost        Plain HTTP on 127.0.0.1 only (clears a previous --domain)
  --tz ZONE          TZ for routines (e.g. Europe/Jersey)
  --user-name NAME   USER_NAME shown in the app
  --harnesses LIST   Harness CLIs baked into the image, e.g. "claude codex pi" (add hermes for Hermes Agent);
                     needs --from-source
  --isolation        Run each user's Bots as their own Unix account (ISOLATION=users; new .env files have it)
  --no-isolation     Run every Bot as botd's account (ISOLATION=off); Bots' screens need this
  --from-source      Build the images from this checkout (docker-compose.build.yml) instead of pulling them
  --published        Pull the published images from ghcr.io (the default; clears --from-source)
  --rotate-master-key
                     Keep the current SUPERBOT_MASTER_KEY as SUPERBOT_MASTER_KEY_PREVIOUS and write a new
                     one; the next `docker compose up -d` seals everything again under the new key
                     (docs/ops/master-key-rotation.md). Refused while a rotation is still pending.
  --backup-age-generate
                     Make the backup age key now, if .env has no SUPERBOT_BACKUP_AGE_RECIPIENTS (a new
                     .env gets one anyway). Needs age-keygen on this host (apt-get install age)
  --backup-encryption auto|required|off
                     SUPERBOT_BACKUP_ENCRYPTION: warn about plain backups (auto), refuse them
                     (required), or keep them plain by choice (off)
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
    --from-source) SOURCE=build; shift ;;
    --published) SOURCE=published; shift ;;
    --rotate-master-key) ROTATE_KEY=true; shift ;;
    --backup-age-generate) BACKUP_GENERATE=true; shift ;;
    --backup-encryption) BACKUP_ENCRYPTION=${2:?--backup-encryption needs a value}; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown option: $1 (see --help)" ;;
  esac
done

if [[ -n "$DOMAIN" && ! "$DOMAIN" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$ ]]; then
  die "--domain must be a bare hostname like bots.example.com"
fi
case $BACKUP_ENCRYPTION in
  "" | auto | required | off) ;;
  *) die "--backup-encryption must be auto, required or off" ;;
esac
[[ "$BACKUP_GENERATE" != true || "$BACKUP_ENCRYPTION" != off ]] || die "--backup-age-generate makes a key that --backup-encryption off would not use"
[[ "$BACKUP_IDENTITY_FILE" == /* ]] || die "BACKUP_IDENTITY_FILE must be an absolute path"
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

fresh=false
if [[ ! -f "$ENV_FILE" ]]; then
  fresh=true
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
if [[ "$ROTATE_KEY" == true ]]; then
  if grep -Eq "^SUPERBOT_MASTER_KEY_PREVIOUS=('[^']+'|[^'[:space:]]+)" "$ENV_FILE"; then
    die "SUPERBOT_MASTER_KEY_PREVIOUS is already set: a rotation is pending. Run docker compose up -d, check the log says \"Master key rotated\" (or \"nothing to rotate\"), remove SUPERBOT_MASTER_KEY_PREVIOUS from $ENV_FILE, then rotate again."
  fi
  current=$(sed -n -E "s/^SUPERBOT_MASTER_KEY=[[:space:]]*(.*[^[:space:]])[[:space:]]*$/\1/p" "$ENV_FILE" | tail -n 1)
  if [[ "$current" =~ ^\'(.*)\'$ || "$current" =~ ^\"(.*)\"$ ]]; then current=${BASH_REMATCH[1]}; fi
  [[ -n "$current" ]] || die "no SUPERBOT_MASTER_KEY in $ENV_FILE to rotate from"
  # The forms botd accepts: 64 hex characters, or base64 of 32 bytes.
  if [[ ! "$current" =~ ^[0-9A-Fa-f]{64}$ && ! "$current" =~ ^[A-Za-z0-9+/]{43}=$ ]]; then
    die "SUPERBOT_MASTER_KEY in $ENV_FILE is not 64 hex characters or base64 of 32 bytes; nothing was changed"
  fi
  # The previous key goes in first: a crash between the two writes leaves the old key in both.
  set_env SUPERBOT_MASTER_KEY_PREVIOUS "$current"
  set_env SUPERBOT_MASTER_KEY "$(od -An -tx1 -N32 /dev/urandom | tr -d ' \n')"
  unset current
  printf 'Rotating the master key: the old one is SUPERBOT_MASTER_KEY_PREVIOUS in %s, the new one SUPERBOT_MASTER_KEY.\n' "$ENV_FILE"
  printf 'Run docker compose up -d, check the botd log says "Master key rotated", then remove SUPERBOT_MASTER_KEY_PREVIOUS and back up the new key.\n'
elif ! grep -Eq "^SUPERBOT_MASTER_KEY=('[^']+'|[^'[:space:]]+)" "$ENV_FILE"; then
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
case "$SOURCE" in
  build) set_env COMPOSE_FILE "$BUILD_FILES" ;;
  published) set_env COMPOSE_FILE docker-compose.yml ;;
esac

# Backup encryption: a new .env (or --backup-age-generate) with no recipients gets an age key,
# unless backups are plain by choice. An .env that has recipients, or an opt-out, is kept.
[[ -z "$BACKUP_ENCRYPTION" ]] || set_env SUPERBOT_BACKUP_ENCRYPTION "$BACKUP_ENCRYPTION"
policy=$(sed -n "s/^SUPERBOT_BACKUP_ENCRYPTION=//p" "$ENV_FILE" | tail -n 1 | tr -d "'\"" | tr '[:upper:]' '[:lower:]')
new_backup_key=false no_age=false
# A nonempty SUPERBOT_BACKUP_AGE_RECIPIENTS, quoted or not.
HAS_RECIPIENTS='^SUPERBOT_BACKUP_AGE_RECIPIENTS=('"'"'[^'"'"'[:space:]][^'"'"']*'"'"'|"[^"[:space:]][^"]*"|[^'"'"'"[:space:]]+)'
if ! grep -Eq "$HAS_RECIPIENTS" "$ENV_FILE" && [[ "$policy" != off ]] &&
  [[ "$fresh" == true || "$BACKUP_GENERATE" == true ]]; then
  if command -v age-keygen >/dev/null 2>&1; then
    [[ ! -L "$BACKUP_IDENTITY_FILE" ]] || die "refusing symlinked $BACKUP_IDENTITY_FILE"
    if [[ ! -e "$BACKUP_IDENTITY_FILE" ]]; then
      (umask 077 && age-keygen -o "$BACKUP_IDENTITY_FILE" 2>/dev/null) || die "age-keygen could not write $BACKUP_IDENTITY_FILE"
      new_backup_key=true
    fi
    chmod 0600 "$BACKUP_IDENTITY_FILE"
    public=$(age-keygen -y "$BACKUP_IDENTITY_FILE") || die "$BACKUP_IDENTITY_FILE is not an age identity"
    set_env SUPERBOT_BACKUP_AGE_RECIPIENTS "$public"
  elif [[ "$BACKUP_GENERATE" == true ]]; then
    die "--backup-age-generate needs age-keygen on this host (apt-get install age)"
  else
    no_age=true
  fi
fi
if [[ "$policy" == required ]] && ! grep -Eq "$HAS_RECIPIENTS" "$ENV_FILE"; then
  die "SUPERBOT_BACKUP_ENCRYPTION=required, but $ENV_FILE has no SUPERBOT_BACKUP_AGE_RECIPIENTS: install age and run ./init.sh --backup-age-generate"
fi

if [[ -n "$new_password" ]]; then
  printf 'New login password (also AUTH_PASSWORD in %s): %s\n' "$ENV_FILE" "$new_password"
fi
if [[ "$new_key" == true ]]; then
  printf 'New master key: SUPERBOT_MASTER_KEY in %s. Back it up apart from the data volume.\n' "$ENV_FILE"
fi
if [[ "$new_backup_key" == true ]]; then
  printf 'New backup key: %s, the only key that opens your encrypted backups. Copy it off this host now\n' "$BACKUP_IDENTITY_FILE"
  printf '(a password manager or vault), then delete it here (shred -u %s).\n' "$BACKUP_IDENTITY_FILE"
elif [[ -f "$BACKUP_IDENTITY_FILE" ]]; then
  printf 'The backup key is still on this host at %s. Once you have a copy off the host, delete it here.\n' "$BACKUP_IDENTITY_FILE"
fi
if [[ "$no_age" == true ]]; then
  printf 'Backups will be plain: age-keygen is not installed here. Install age and run ./init.sh --backup-age-generate,\n'
  printf 'or set SUPERBOT_BACKUP_ENCRYPTION=off to keep them plain by choice (docs/ops/backup-restore.md#encryption).\n'
fi
if grep -qx "COMPOSE_FILE='$BUILD_FILES'" "$ENV_FILE"; then
  printf 'Next: cd %s && docker compose up -d --build\n' "$DIR"
else
  [[ "$HARNESSES_SET" != true ]] || printf 'Note: --harnesses applies only to images built here (--from-source).\n'
  printf 'Next: cd %s && docker compose up -d\n' "$DIR"
fi
