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

log "Compose refuses to start without AUTH_PASSWORD"
if SUPERBOT_ENV_FILE=/dev/null docker compose -f "$DIR/docker-compose.yml" -p "$PROJECT" --env-file /dev/null config -q 2>/dev/null; then
  fail "compose config succeeded without AUTH_PASSWORD"
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
dc exec -T botd sh -c 'd=$(dirname "$(command -v botd)"); for h in claude codex pi; do [ ! -e "$d/$h" ] || exit 1; done' \
  || fail "a harness CLI sits next to botd and would shadow ~/.local/bin for Bots"

log "Backup service wrote an archive"
for _ in $(seq 1 30); do
  dc exec -T backup sh -c 'ls /backups/superbot-*.tar.gz' >/dev/null 2>&1 && break
  sleep 1
done
dc exec -T backup sh -c 'ls /backups/superbot-*.tar.gz' >/dev/null || fail "no archive in /backups"
before=$(dc exec -T backup sh -c 'ls /backups/superbot-*.tar.gz | wc -l')
sleep 1
dc exec -T botd superbot-backup
after=$(dc exec -T backup sh -c 'ls /backups/superbot-*.tar.gz | wc -l')
[[ "$after" -gt "$before" ]] || fail "manual 'exec botd superbot-backup' did not land in the backups volume"

log "SSE events stream through Caddy without buffering"
curl -sN --max-time 5 "${AUTH[@]}" "$BASE/api/events" >"$WORK/events.txt" &
events_pid=$!
sleep 1
curl -fsS "${AUTH[@]}" -H 'Content-Type: application/json' -d '{"name":"KeepMe"}' "$BASE/api/bots" >/dev/null
wait "$events_pid" || true
grep -q '"name":"KeepMe"' "$WORK/events.txt" || fail "no bot event on /api/events within 5s"

log "Backup and restore round trip"
dc exec -T botd superbot-backup - >"$WORK/backup.tar.gz"
tar -tzf "$WORK/backup.tar.gz" | grep -qx 'app.sqlite' || fail "archive has no app.sqlite"
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

log "Smoke test passed"
