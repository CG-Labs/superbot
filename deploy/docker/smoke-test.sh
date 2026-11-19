#!/usr/bin/env bash
# End-to-end check of the Compose setup in an isolated project (own volumes, env file, and ports).
# Never touches a real install's volumes. Usage, from anywhere:
#   deploy/docker/smoke-test.sh              # builds the image
#   SUPERBOT_IMAGE=superbot:ci SMOKE_NO_BUILD=1 deploy/docker/smoke-test.sh
set -euo pipefail

DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
PROJECT=${SMOKE_PROJECT:-superbot-smoke}
HTTP_PORT=${SMOKE_HTTP_PORT:-18080}
HTTPS_PORT=${SMOKE_HTTPS_PORT:-18443}
BASE="http://127.0.0.1:$HTTP_PORT"
WORK=$(mktemp -d)
export SUPERBOT_ENV_FILE="$WORK/.env"

log() { printf '==> %s\n' "$*"; }
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
dc() { docker compose -f "$DIR/docker-compose.yml" -p "$PROJECT" --env-file "$SUPERBOT_ENV_FILE" "$@"; }

cleanup() {
  local status=$?
  if [[ $status -ne 0 ]]; then
    dc ps -a || true
    dc logs --no-color --tail 100 || true
  fi
  if [[ "${SMOKE_KEEP:-}" == 1 ]]; then
    printf 'Kept project %s; env file %s\n' "$PROJECT" "$SUPERBOT_ENV_FILE" >&2
  else
    dc down -v --remove-orphans >/dev/null 2>&1 || true
    rm -rf "$WORK"
  fi
  exit "$status"
}
trap cleanup EXIT

expect_code() { # expected-code curl-args...
  local want=$1 got
  shift
  got=$(curl -s -o /dev/null -w '%{http_code}' "$@" || true)
  [[ "$got" == "$want" ]] || fail "expected HTTP $want, got $got: curl $*"
}

log "Writing an isolated env file"
ENV_FILE="$SUPERBOT_ENV_FILE" "$DIR/init.sh" --localhost --tz UTC --user-name Smoke >/dev/null
grep -Ev '^(SUPERBOT_HTTP_PORT|SUPERBOT_HTTPS_PORT|ALLOWED_HOSTS)=' "$SUPERBOT_ENV_FILE" >"$WORK/env.tmp"
mv "$WORK/env.tmp" "$SUPERBOT_ENV_FILE"
{
  echo "SUPERBOT_HTTP_PORT=$HTTP_PORT"
  echo "SUPERBOT_HTTPS_PORT=$HTTPS_PORT"
  echo "ALLOWED_HOSTS=127.0.0.1:$HTTP_PORT,localhost:$HTTP_PORT"
} >>"$SUPERBOT_ENV_FILE"
PASSWORD=$(sed -n "s/^AUTH_PASSWORD='\(.*\)'$/\1/p" "$SUPERBOT_ENV_FILE")
[[ -n "$PASSWORD" ]] || fail "init.sh did not set AUTH_PASSWORD"
[[ -z "${GITHUB_ACTIONS:-}" ]] || echo "::add-mask::$PASSWORD"
AUTH=(-u "smoke:$PASSWORD")

MASTER_KEY=$(sed -n "s/^SUPERBOT_MASTER_KEY='\(.*\)'$/\1/p" "$SUPERBOT_ENV_FILE")
[[ ${#MASTER_KEY} == 64 ]] || fail "init.sh did not set a 64-hex SUPERBOT_MASTER_KEY"
[[ -z "${GITHUB_ACTIONS:-}" ]] || echo "::add-mask::$MASTER_KEY"
ENV_FILE="$SUPERBOT_ENV_FILE" "$DIR/init.sh" --localhost >/dev/null
grep -qx "SUPERBOT_MASTER_KEY='$MASTER_KEY'" "$SUPERBOT_ENV_FILE" || fail "re-running init.sh replaced the master key"

log "Compose refuses to start without AUTH_PASSWORD or SUPERBOT_MASTER_KEY"
if SUPERBOT_ENV_FILE=/dev/null docker compose -f "$DIR/docker-compose.yml" -p "$PROJECT" --env-file /dev/null config -q 2>/dev/null; then
  fail "compose config succeeded without AUTH_PASSWORD"
fi
grep -v '^SUPERBOT_MASTER_KEY=' "$SUPERBOT_ENV_FILE" >"$WORK/nokey.env"
if SUPERBOT_ENV_FILE="$WORK/nokey.env" docker compose -f "$DIR/docker-compose.yml" -p "$PROJECT" --env-file "$WORK/nokey.env" config -q 2>/dev/null; then
  fail "compose config succeeded without SUPERBOT_MASTER_KEY"
fi

log "Starting the stack"
build=(--build)
[[ "${SMOKE_NO_BUILD:-}" != 1 ]] || build=(--no-build)
dc up -d "${build[@]}" --wait --wait-timeout 180

log "Health, auth, and Host checks through Caddy"
[[ $(curl -fsS "$BASE/healthz") == '{"ok":true}' ]] || fail "/healthz did not return {\"ok\":true}"
expect_code 401 "$BASE/api/state"
expect_code 401 -u "smoke:wrong-password" "$BASE/api/state"
expect_code 403 "${AUTH[@]}" -H "Host: evil.example" "$BASE/api/state"
expect_code 200 "${AUTH[@]}" "$BASE/"
state=$(curl -fsS "${AUTH[@]}" "$BASE/api/state")
grep -q '"name":"Smoke"' <<<"$state" || fail "USER_NAME from .env not applied: $state"

log "Sessions: the password signs in as the owner; the token works until logout"
expect_code 303 "$BASE/"
login=$(curl -fsS -H 'Content-Type: application/json' -d "{\"password\":\"$PASSWORD\"}" "$BASE/api/auth/login")
TOKEN=$(sed -n 's/.*"token":"\(sbs_[0-9a-f]*\)".*/\1/p' <<<"$login")
[[ -n "$TOKEN" ]] || fail "no session token from /api/auth/login"
grep -q '"role":"admin"' <<<"$(curl -fsS -H "Authorization: Bearer $TOKEN" "$BASE/api/auth/me")" || fail "the owner is not an admin"
expect_code 200 -X POST -H "Authorization: Bearer $TOKEN" "$BASE/api/auth/logout"
expect_code 401 -H "Authorization: Bearer $TOKEN" "$BASE/api/state"

log "botd is not published on the host and runs as non-root"
if curl -fsS --max-time 2 http://127.0.0.1:3000/healthz >/dev/null 2>&1; then
  fail "botd port 3000 is reachable from the host"
fi
[[ $(dc exec -T botd id -u) != 0 ]] || fail "botd runs as root"

for h in ${SMOKE_HARNESSES-claude codex pi}; do
  dc exec -T botd "$h" --version >/dev/null || fail "harness CLI $h is not runnable in the image"
  grep -q "\"$h\"" <<<"$state" || fail "botd does not list harness $h"
done
log "Harness CLIs runnable: ${SMOKE_HARNESSES-claude codex pi}"

log "botd's folder (prepended to Bots' PATH) holds no harness CLI, so runtime npm upgrades win"
# shellcheck disable=SC2016
dc exec -T botd sh -c 'd=$(dirname "$(command -v botd)"); for h in claude codex pi hermes; do [ ! -e "$d/$h" ] || exit 1; done' \
  || fail "a harness CLI sits next to botd and would shadow ~/.local/bin for Bots"

log "Backup service wrote an archive"
for _ in $(seq 1 30); do
  dc exec -T backup sh -c 'ls /backups/superbot-*.tar.gz' >/dev/null 2>&1 && break
  sleep 1
done
dc exec -T backup sh -c 'ls /backups/superbot-*.tar.gz' >/dev/null || fail "no archive in /backups"

log "Manual backups from botd share the volume and do not collide with the backup service"
before=$(dc exec -T backup sh -c 'ls /backups/superbot-*.tar.gz | wc -l')
dc exec -T botd superbot-backup &
manual_pid=$!
dc exec -T backup superbot-backup
wait "$manual_pid" || fail "manual backup in botd failed"
after=$(dc exec -T backup sh -c 'ls /backups/superbot-*.tar.gz | wc -l')
[[ "$after" -eq $((before + 2)) ]] || fail "expected 2 new archives in the backups volume, got $((after - before))"
# shellcheck disable=SC2016
dc exec -T backup sh -c 'for f in /backups/superbot-*.tar.gz; do tar -tzf "$f" | grep -qx app.sqlite || exit 1; done' \
  || fail "a backup archive is damaged"

log "SSE events stream through Caddy without buffering"
curl -sN --max-time 5 "${AUTH[@]}" "$BASE/api/events" >"$WORK/events.txt" &
events_pid=$!
sleep 1
curl -fsS "${AUTH[@]}" -H 'Content-Type: application/json' -d '{"name":"KeepMe"}' "$BASE/api/bots" >/dev/null
wait "$events_pid" || true
grep -q '"name":"KeepMe"' "$WORK/events.txt" || fail "no bot event on /api/events within 5s"

log "Secrets: saved encrypted, listed by name only, never in the database or a backup in plaintext"
SECRET_VALUE="smoke-$(od -An -tx1 -N16 /dev/urandom | tr -d ' \n')"
[[ -z "${GITHUB_ACTIONS:-}" ]] || echo "::add-mask::$SECRET_VALUE"
printf '%s\n' "$SECRET_VALUE" | SUPERBOT_PASSWORD="$PASSWORD" dc exec -T -e SUPERBOT_PASSWORD botd botctl secret set SMOKE_API_KEY >/dev/null \
  || fail "botctl secret set failed"
secrets=$(curl -fsS "${AUTH[@]}" "$BASE/api/secrets")
grep -q '"name":"SMOKE_API_KEY"' <<<"$secrets" || fail "saved secret not listed: $secrets"
if grep -qF "$SECRET_VALUE" <<<"$secrets"; then fail "the API returned a secret value"; fi
if dc logs --no-color botd | grep -qF -e "$SECRET_VALUE" -e "$MASTER_KEY"; then fail "a secret reached botd's logs"; fi

log "Backup and restore round trip"
dc exec -T botd superbot-backup - >"$WORK/backup.tar.gz"
tar -tzf "$WORK/backup.tar.gz" | grep -qx 'app.sqlite' || fail "archive has no app.sqlite"
mkdir "$WORK/unpacked"
tar -xzf "$WORK/backup.tar.gz" -C "$WORK/unpacked"
if grep -rqF -e "$SECRET_VALUE" -e "$MASTER_KEY" "$WORK/unpacked"; then fail "a backup holds a secret or the master key"; fi
curl -fsS "${AUTH[@]}" -H 'Content-Type: application/json' -d '{"name":"DropMe"}' "$BASE/api/bots" >/dev/null
if dc run --rm --no-deps -T botd superbot-restore - <"$WORK/backup.tar.gz" 2>/dev/null; then
  fail "restore ran while botd was up"
fi
dc stop botd backup
dc run --rm --no-deps -T botd superbot-restore - <"$WORK/backup.tar.gz"
dc up -d --no-build --wait --wait-timeout 120
bots=$(curl -fsS "${AUTH[@]}" "$BASE/api/bots")
grep -q '"name":"KeepMe"' <<<"$bots" || fail "restored data is missing KeepMe"
if grep -q '"name":"DropMe"' <<<"$bots"; then fail "restore did not roll back DropMe"; fi
grep -q '"name":"SMOKE_API_KEY"' <<<"$(curl -fsS "${AUTH[@]}" "$BASE/api/secrets")" || fail "restored data lost the saved secret"

log "Audit log is restored with the data and exports CSV"
expect_code 401 "$BASE/api/audit/export.csv"
audit=$(curl -fsS "${AUTH[@]}" "$BASE/api/audit?action=bot.created")
grep -q '"name":"KeepMe"' <<<"$audit" || fail "audit log is missing bot.created for KeepMe: $audit"
if grep -q '"name":"DropMe"' <<<"$audit"; then fail "restore did not roll back the audit log"; fi
curl -fsS "${AUTH[@]}" "$BASE/api/audit/export.csv" >"$WORK/audit.csv"
IFS= read -r header <"$WORK/audit.csv" || true
[[ "${header%$'\r'}" == id,time,actor_kind,* ]] || fail "audit CSV has no header: $header"
grep -q ',bot.created,' "$WORK/audit.csv" || fail "audit CSV has no bot.created row"

log "Smoke test passed"
