#!/usr/bin/env bash
# End-to-end check of the Compose setup in an isolated project (own volumes, env file, and ports).
# Never touches a real install's volumes. Usage, from anywhere:
#   deploy/docker/smoke-test.sh              # builds the images from this checkout
#   SUPERBOT_IMAGE=superbot:ci SUPERBOT_CADDY_IMAGE=superbot-caddy:ci SMOKE_NO_BUILD=1 deploy/docker/smoke-test.sh
#   SMOKE_NO_BUILD=1 deploy/docker/smoke-test.sh   # the published images (SUPERBOT_VERSION, default main)
set -euo pipefail

DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
COMPOSE_FILES=(-f "$DIR/docker-compose.yml")
[[ "${SMOKE_NO_BUILD:-}" == 1 ]] || COMPOSE_FILES+=(-f "$DIR/docker-compose.build.yml")
PROJECT=${SMOKE_PROJECT:-superbot-smoke}
HTTP_PORT=${SMOKE_HTTP_PORT:-18080}
HTTPS_PORT=${SMOKE_HTTPS_PORT:-18443}
BASE="http://127.0.0.1:$HTTP_PORT"
WORK=$(mktemp -d)
export SUPERBOT_ENV_FILE="$WORK/.env"

log() { printf '==> %s\n' "$*"; }
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
dc() { docker compose "${COMPOSE_FILES[@]}" -p "$PROJECT" --env-file "$SUPERBOT_ENV_FILE" "$@"; }

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
ENV_FILE="$SUPERBOT_ENV_FILE" BACKUP_IDENTITY_FILE="$WORK/init-identity.txt" "$DIR/init.sh" --localhost --tz UTC --user-name Smoke >/dev/null
# init.sh encrypts backups to a key it makes when the host has age-keygen (ADR 0114); the restore
# drill below sets its own, made in the image, so it runs the same either way.
if command -v age-keygen >/dev/null 2>&1; then
  grep -q "^SUPERBOT_BACKUP_AGE_RECIPIENTS='age1" "$SUPERBOT_ENV_FILE" || fail "init.sh made no backup key"
fi
grep -Ev '^(SUPERBOT_HTTP_PORT|SUPERBOT_HTTPS_PORT|ALLOWED_HOSTS|SUPERBOT_BACKUP_AGE_RECIPIENTS)=' "$SUPERBOT_ENV_FILE" >"$WORK/env.tmp"
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
expect_code 200 "${AUTH[@]}" "$BASE/console/"
log "The landing page and get-started form are public"
expect_code 200 "$BASE/"
expect_code 200 "$BASE/get-started"
expect_code 200 "$BASE/site/get-started.js"
grep -qi "^content-security-policy: default-src 'self'" <<<"$(curl -fsSI "$BASE/")" || fail "the landing page has no CSP"
grep -q '"enabled":true' <<<"$(curl -fsS "$BASE/api/signups/config")" || fail "sign-ups are not open"
log "Caddy serves the web client at /app/ and leaves everything else to botd"
expect_code 200 "$BASE/app/"
expect_code 302 "$BASE/app"
expect_code 200 "$BASE/app/some/deep/link"
curl -fsS "$BASE/app/" >"$WORK/app.html"
entry=$(grep -o '/app/_expo/static/js/web/entry-[0-9a-f]*\.js' "$WORK/app.html" | sed -n 1p)
[[ -n "$entry" ]] || fail "/app/ is not the client's index.html (built without SUPERBOT_WEB_BASE_URL=/app?)"
expect_code 200 "$BASE$entry"
grep -qi '^cache-control: public, max-age=31536000, immutable' <<<"$(curl -fsSI "$BASE$entry")" || fail "client bundle is not cached as immutable"
grep -qi '^cache-control: no-cache' <<<"$(curl -fsSI "$BASE/app/")" || fail "client index.html is cacheable, so upgrades would not show"
expect_code 303 "$BASE/app.js"
state=$(curl -fsS "${AUTH[@]}" "$BASE/api/state")
grep -q '"name":"Smoke"' <<<"$state" || fail "USER_NAME from .env not applied: $state"

log "Sessions: the password signs in as the owner; the token works until logout"
expect_code 303 "$BASE/console/"
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

log "Database encryption (ADR 0115): required for a new .env, and botd made the database encrypted"
grep -qx "SUPERBOT_DATABASE_ENCRYPTION='required'" "$SUPERBOT_ENV_FILE" || fail "a new .env doesn't require database encryption"
grep -q 'Database encryption: encrypted with SQLCipher.*; created encrypted' <<<"$(dc logs --no-color botd)" || fail "botd didn't create an encrypted database"
[[ $(dc exec -T botd botd database status /data/app.sqlite) == encrypted ]] || fail "botd database status doesn't say encrypted"

log "Per-user accounts (ADR 0058): on for a new .env, and an account can't read botd's data or env"
grep -qx 'ISOLATION=users' "$SUPERBOT_ENV_FILE" || fail "a new .env doesn't turn per-user accounts on"
grep -q 'Isolation: each user' <<<"$(dc logs --no-color botd)" || fail "botd didn't start with per-user accounts"
grep -q 'Screens: off (per-user' <<<"$(dc logs --no-color botd)" || fail "screens aren't off under per-user accounts"
probe=smokeprobe
dc exec -T botd sudo -n /usr/local/sbin/superbot-userctl ensure "$probe" >/dev/null || fail "superbot-userctl couldn't make an account"
as_account() { dc exec -T -w "/srv/superbot/users/$probe/home" botd sudo -n -u "sb-u-$probe" /opt/superbot/bin/superbot-run /bin/sh -c "$1"; }
[[ $(as_account 'id -un') == "sb-u-$probe" ]] || fail "superbot-run didn't run as the account"
for p in /data /data/app.sqlite /home/superbot /proc/1/environ; do
  if as_account "if [ -d '$p' ]; then ls -A '$p'; else head -c 1 '$p'; fi" >/dev/null 2>&1; then fail "the account can read $p"; fi
done
environs=$(as_account 'cat /proc/[0-9]*/environ 2>/dev/null | tr "\0" "\n"' || true)
if grep -qF -e "$MASTER_KEY" -e "$PASSWORD" <<<"$environs"; then
  fail "the account can read botd's env"
fi
if as_account 'sudo -n true' >/dev/null 2>&1; then fail "the account can use sudo"; fi
[[ $(dc exec -T -u 0 botd find / -xdev -type f -perm /6000) == /usr/bin/sudo ]] || fail "the image has setuid programs besides sudo"
uid=$(dc exec -T botd stat -c %u "/srv/superbot/users/$probe/home")
dc up -d --no-build --force-recreate --wait --wait-timeout 120 botd
dc exec -T botd sudo -n /usr/local/sbin/superbot-userctl ensure "$probe" >/dev/null || fail "superbot-userctl couldn't remake the account"
[[ $(dc exec -T botd id -u "sb-u-$probe") == "$uid" ]] || fail "a recreated container gave the account another uid"

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
dc exec -T backup sh -c 'for f in /backups/superbot-*.tar.gz; do l=$(tar -tzf "$f") || exit 1; [ "$(printf "%s\n" "$l" | grep -cx app.sqlite)" -ge 1 ] || exit 1; done' \
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
logs=$(dc logs --no-color botd) || fail "could not read botd's logs"
if grep -qF -e "$SECRET_VALUE" -e "$MASTER_KEY" <<<"$logs"; then fail "a secret reached botd's logs"; fi

log "Backup and restore round trip"
dc exec -T botd superbot-backup - >"$WORK/backup.tar.gz"
listing=$(tar -tzf "$WORK/backup.tar.gz") || fail "the archive is unreadable"
grep -qx 'app.sqlite' <<<"$listing" || fail "archive has no app.sqlite"
mkdir "$WORK/unpacked"
tar -xzf "$WORK/backup.tar.gz" -C "$WORK/unpacked"
if grep -rqF -e "$SECRET_VALUE" -e "$MASTER_KEY" "$WORK/unpacked"; then fail "a backup holds a secret or the master key"; fi
[[ "$(head -c 15 "$WORK/unpacked/app.sqlite" | tr -d '\0')" != "SQLite format 3" ]] || fail "the archive holds the database decrypted"
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

log "Restore drill: the backup service writes an age-encrypted archive"
dc exec -T botd age-keygen >"$WORK/identity.txt" 2>/dev/null
RECIPIENT=$(sed -n 's/^# public key: //p' "$WORK/identity.txt")
[[ "$RECIPIENT" == age1* ]] || fail "age-keygen in the image gave no public key"
# Read by the container's uid; WORK itself stays private to this user.
chmod 0644 "$WORK/identity.txt"
echo "SUPERBOT_BACKUP_AGE_RECIPIENTS=$RECIPIENT" >>"$SUPERBOT_ENV_FILE"
dc up -d --no-build --wait --wait-timeout 120 backup
encrypted=""
for _ in $(seq 1 30); do
  encrypted=$(dc exec -T backup sh -c 'ls /backups/superbot-*.tar.gz.age 2>/dev/null | tail -n 1' || true)
  [[ -z "$encrypted" ]] || break
  sleep 1
done
[[ -n "$encrypted" ]] || fail "the backup service wrote no .age archive"
dc cp "backup:$encrypted" "$WORK/drill.tar.gz.age"
[[ $(head -c 21 "$WORK/drill.tar.gz.age") == age-encryption.org/v1 ]] || fail "the archive is not age-encrypted"
if tar -tzf "$WORK/drill.tar.gz.age" >/dev/null 2>&1; then fail "the encrypted archive opens without the identity"; fi
restore_run() { dc run --rm --no-deps -T -v "$WORK/identity.txt:/run/age-identity:ro" botd superbot-restore --identity /run/age-identity "$@"; }
if dc run --rm --no-deps -T botd superbot-restore --check - <"$WORK/drill.tar.gz.age" 2>/dev/null; then
  fail "an encrypted archive was accepted without the identity"
fi
restore_run --check - <"$WORK/drill.tar.gz.age" >"$WORK/check.txt" || fail "superbot-restore --check rejected the archive"
grep -q '^needs master key: yes' "$WORK/check.txt" || fail "--check did not report the sealed secret"

log "Restore drill: lose every volume, start fresh, restore (timed against the RTO budget)"
dc down -v
dc up -d --no-build --wait --wait-timeout 180
if grep -q '"name":"KeepMe"' <<<"$(curl -fsS "${AUTH[@]}" "$BASE/api/bots")"; then fail "fresh volumes still hold KeepMe"; fi
t0=$(date +%s)
dc stop botd backup
restore_run - <"$WORK/drill.tar.gz.age" >/dev/null
dc up -d --no-build --wait --wait-timeout 120
rto=$(($(date +%s) - t0))
[[ $(curl -fsS "$BASE/healthz") == '{"ok":true}' ]] || fail "/healthz is not ok after the restore"
grep -q '"name":"KeepMe"' <<<"$(curl -fsS "${AUTH[@]}" "$BASE/api/bots")" || fail "KeepMe is missing after restoring onto fresh volumes"
grep -q '"name":"SMOKE_API_KEY"' <<<"$(curl -fsS "${AUTH[@]}" "$BASE/api/secrets")" || fail "the saved secret is missing after the restore"
grep -q '"name":"KeepMe"' <<<"$(curl -fsS "${AUTH[@]}" "$BASE/api/audit?action=bot.created")" || fail "the audit log is missing after the restore"
((rto <= ${SMOKE_RTO_SECONDS:-300})) || fail "restore took ${rto}s (budget ${SMOKE_RTO_SECONDS:-300}s)"
log "Restore drill passed: back up in ${rto}s"

log "Master key rotation (ADR 0096): init.sh keeps the old key as the previous one, botd seals everything again at start"
ENV_FILE="$SUPERBOT_ENV_FILE" "$DIR/init.sh" --rotate-master-key >/dev/null
NEW_KEY=$(sed -n "s/^SUPERBOT_MASTER_KEY='\(.*\)'$/\1/p" "$SUPERBOT_ENV_FILE")
[[ -z "${GITHUB_ACTIONS:-}" ]] || echo "::add-mask::$NEW_KEY"
[[ ${#NEW_KEY} == 64 && "$NEW_KEY" != "$MASTER_KEY" ]] || fail "init.sh --rotate-master-key did not write a new key"
grep -qx "SUPERBOT_MASTER_KEY_PREVIOUS='$MASTER_KEY'" "$SUPERBOT_ENV_FILE" || fail "init.sh --rotate-master-key did not keep the old key"
if ENV_FILE="$SUPERBOT_ENV_FILE" "$DIR/init.sh" --rotate-master-key >/dev/null 2>&1; then fail "init.sh rotated again while a rotation was pending"; fi
dc up -d --no-build --wait --wait-timeout 120
grep -q "Master key rotated" <<<"$(dc logs --no-color botd)" || fail "botd did not rotate the master key"
grep -q '"action":"secret.master_key_rotated"' <<<"$(curl -fsS "${AUTH[@]}" "$BASE/api/audit?action=secret.master_key_rotated")" || fail "no audit event for the rotation"
grep -q '"name":"SMOKE_API_KEY"' <<<"$(curl -fsS "${AUTH[@]}" "$BASE/api/secrets")" || fail "the saved secret is missing after the rotation"
grep -v '^SUPERBOT_MASTER_KEY_PREVIOUS=' "$SUPERBOT_ENV_FILE" >"$WORK/env.tmp"
install -m 0600 "$WORK/env.tmp" "$SUPERBOT_ENV_FILE"
dc up -d --no-build --wait --wait-timeout 120
[[ $(curl -fsS "$BASE/healthz") == '{"ok":true}' ]] || fail "botd did not start with the new key alone"
MASTER_KEY=$NEW_KEY

log "Screens (docs/computer.md): on with ISOLATION=off, a Bot's screen starts and is viewed through Caddy"
ENV_FILE="$SUPERBOT_ENV_FILE" "$DIR/init.sh" --no-isolation >/dev/null
dc up -d --no-build --force-recreate --wait --wait-timeout 120 botd
grep -q 'Screens: on (viewers listen on 0.0.0.0' <<<"$(dc logs --no-color botd)" || fail "botd didn't turn screens on"
bot_id=$(curl -fsS "${AUTH[@]}" -H 'Content-Type: application/json' -d '{"name":"Screenie"}' "$BASE/api/bots" \
  | grep -o '"id":"[0-9a-zA-Z_-]*"' | sed -n '1s/"id":"\(.*\)"/\1/p')
[[ -n "$bot_id" ]] || fail "no id for the new Bot"
screen=$(curl -fsS "${AUTH[@]}" "$BASE/api/bots/$bot_id/screen") || fail "the Bot's screen didn't start"
url=$(sed -n 's/.*"url":"\([^"]*\)".*/\1/p' <<<"$screen")
[[ "$url" =~ ^/screen/(69[0-9][0-9])/\?token=([0-9a-f]{32})$ ]] || fail "unexpected screen link: $screen"
port=${BASH_REMATCH[1]} token=${BASH_REMATCH[2]}
[[ -z "${GITHUB_ACTIONS:-}" ]] || echo "::add-mask::$token"
display=":$((port - 6800))"
expect_code 200 "$BASE$url"
grep -qi '<html' <<<"$(curl -fsS "$BASE$url")" || fail "Caddy didn't serve the screen's viewer at $BASE/screen/$port/"
ws_code() { # The viewer's live stream, opened through Caddy with the given token.
  curl -s -o /dev/null -m 3 -w '%{http_code}' -H 'Connection: Upgrade' -H 'Upgrade: websocket' \
    -H 'Sec-WebSocket-Version: 13' -H 'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==' "$BASE/screen/$port/ws?token=$1" || true
}
[[ $(ws_code "$token") == 101 ]] || fail "the screen's live stream didn't open through Caddy"
[[ $(ws_code "$(od -An -tx1 -N16 /dev/urandom | tr -d ' \n')") == 401 ]] || fail "the screen's live stream opened with a wrong token"
dc exec -T botd xdpyinfo -display "$display" >/dev/null || fail "no X display $display in botd"

log "Computer use: Chromium opens on the Bot's screen"
ab() { dc exec -T -e DISPLAY="$display" -e AGENT_BROWSER_SESSION=smoke -e AGENT_BROWSER_HEADED=1 -e AGENT_BROWSER_NO_XVFB=1 botd agent-browser "$@"; }
ab open 'data:text/html,<title>superbot-smoke</title><h1>hello</h1>' >/dev/null || fail "agent-browser couldn't open a page"
[[ $(ab get title) == superbot-smoke ]] || fail "agent-browser read the wrong title"
windows=$(dc exec -T botd xwininfo -display "$display" -root -tree) || fail "couldn't list the windows on $display"
grep -q '"superbot-smoke - Chromium"' <<<"$windows" || fail "Chromium isn't on the Bot's screen: $windows"

log "Chromium runs with its sandbox on (ADR 0107)"
for _ in $(seq 1 60); do
  grep -q 'Chromium sandbox: on (checked' <<<"$(dc logs --no-color botd)" && break
  sleep 1
done
grep -q 'Chromium sandbox: on (checked' <<<"$(dc logs --no-color botd)" \
  || fail "botd didn't find Chromium's sandbox working: $(dc logs --no-color botd | grep 'Chromium sandbox' || true)"
ab open chrome://sandbox >/dev/null || fail "agent-browser couldn't open chrome://sandbox"
sandbox=$(ab get text body) || fail "couldn't read chrome://sandbox"
grep -q 'You are adequately sandboxed' <<<"$sandbox" || fail "chrome://sandbox says Chromium isn't sandboxed: $sandbox"
grep -Eq 'Layer 1 Sandbox[[:space:]]+Namespace' <<<"$sandbox" || fail "Chromium's namespace sandbox isn't on: $sandbox"
browsers=$(dc exec -T botd pgrep -a -f '^/usr/lib/chromium/chromium') || fail "no Chromium processes in botd"
if grep -q -- '--no-sandbox' <<<"$browsers"; then fail "a Chromium process runs with --no-sandbox: $browsers"; fi
# shellcheck disable=SC2016
dc exec -T botd sh -c 'n=0; for p in $(pgrep -f "^/usr/lib/chromium/chromium --type=renderer"); do grep -q "^Seccomp:[[:space:]]*2" "/proc/$p/status" || exit 1; n=$((n + 1)); done; [ "$n" -gt 0 ]' \
  || fail "a Chromium renderer runs without its seccomp filter"
ab close >/dev/null || true
log "Without the profile's namespaces Chromium refuses to start, rather than run unsandboxed"
image=$(docker inspect --format '{{.Config.Image}}' "$(dc ps -q botd)")
if refused=$(docker run --rm --cap-drop ALL --entrypoint chromium "$image" --headless --disable-gpu --dump-dom about:blank 2>&1); then
  fail "Chromium started under Docker's default seccomp profile"
fi
grep -q 'No usable sandbox' <<<"$refused" || fail "Chromium failed for another reason under Docker's default profile: $refused"
dc exec -T botd agent-desktop --version >/dev/null || fail "agent-desktop is not runnable in the image"

log "Smoke test passed"
