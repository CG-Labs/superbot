#!/usr/bin/env bash
# Backup and restore drill for the installer (systemd) path, on a THROWAWAY host such as a CI runner.
# Installs SuperBot's units from this checkout with the installer's own functions, seeds data, backs up
# through the real timer unit (age-encrypted), then loses the whole service user (data, .env, master key,
# local archives), reinstalls, restores from the "off-host" copies, and checks the data came back. It
# times the restore against the RTO budget and checks the timer against the RPO. It deletes the service
# user and its home: never run it on a server you care about. docs/ops/backup-restore.md.
#   sudo SUPERBOT_DRILL_THROWAWAY=1 deploy/backup-drill.sh <folder with botd and botctl>
set -euo pipefail

[[ "${SUPERBOT_DRILL_THROWAWAY:-}" == 1 ]] || {
  echo "backup-drill.sh deletes the service user and its data. Set SUPERBOT_DRILL_THROWAWAY=1 on a throwaway host." >&2
  exit 2
}
BIN_SRC=${1:?usage: sudo SUPERBOT_DRILL_THROWAWAY=1 deploy/backup-drill.sh <folder with botd and botctl>}
BIN_SRC=$(cd "$BIN_SRC" && pwd)
REPO=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
RTO_BUDGET=${SUPERBOT_DRILL_RTO_SECONDS:-300}
# The timer runs daily at 03:15 with up to 15 minutes of random delay.
RPO_BUDGET=${SUPERBOT_DRILL_RPO_SECONDS:-$((24 * 3600 + 15 * 60))}
BASE=http://127.0.0.1:3000

export SUPERBOT_INSTALL_NO_MAIN=1
# shellcheck source=install.sh
source "$REPO/deploy/install.sh"
# shellcheck disable=SC2034 # read by stage_trusted_deploy
INSTALL_DIR=$REPO
# shellcheck disable=SC2034 # read by configure_env
# A throwaway server, unlicensed: testing mode, as the installer's --testing-mode sets (ADR 0068).
TESTING_MODE_ON=true

OFFSITE=$(mktemp -d) # stands in for storage off the host: the archive, .env, master key, age identity
WORK=$(mktemp -d)
# The service user reads its copy of the identity from WORK by name; nothing else there is readable.
chmod 0700 "$OFFSITE"
chmod 0711 "$WORK"
install -d -m 0700 "$WORK/plain"

step() { printf '\n==> drill: %s\n' "$*"; }
# The record line superbot-evidence drills --record reads (ADR 0177); the last one printed counts.
record() { printf '{"superbotDrill":1,"drill":"server-restore","finishedAt":"%s",%s}\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$1"; }
fail() {
  printf 'DRILL FAILED: %s\n' "$*" >&2
  journalctl -u superbot -u superbot-backup --no-pager -n 40 >&2 || true
  record '"passed":false'
  exit 1
}

home() { user_home; }
setting() { sed -n "s/^$1=//p" "$(home)/superbot/.env" | tail -n 1 | tr -d "\"'"; }
password() { setting AUTH_PASSWORD; }
api() { curl -fsS -u "drill:$(password)" "$@"; }
as_user() { sudo -u "$SUPERBOT_USER" -H "$@"; }
botctl_as_owner() { as_user env SUPERBOT_PASSWORD="$(password)" "$BIN_DIR/botctl" "$@"; }

wait_healthz() {
  for _ in $(seq 1 120); do
    [[ $(curl -fsS --max-time 2 "$BASE/healthz" 2>/dev/null) == '{"ok":true}' ]] && return 0
    sleep 0.5
  done
  return 1
}

# The installer's steps that matter for backups, minus the builds: the drill brings its own binaries.
# With "custom", DATA_DIR and the master key live away from the defaults, as an operator may set them.
install_superbot() {
  local h custom=${1:-}
  ensure_user
  h=$(home)
  install -d -m 0755 -o "$SUPERBOT_USER" -g "$SUPERBOT_USER" "$h/superbot"
  install -m 0644 -o "$SUPERBOT_USER" -g "$SUPERBOT_USER" "$REPO/.env.example" "$h/superbot/.env.example"
  stage_trusted_deploy
  install -m 0755 "$BIN_SRC/botd" "$BIN_DIR/botd"
  install -m 0755 "$BIN_SRC/botctl" "$BIN_DIR/botctl"
  configure_env
  set_env_var "$h/superbot/.env" SCREENS off
  set_env_var "$h/superbot/.env" SUPERBOT_BACKUP_AGE_RECIPIENTS "$RECIPIENT"
  if [[ "$custom" == custom ]]; then
    set_env_var "$h/superbot/.env" DATA_DIR "$h/srv-data"
    set_env_var "$h/superbot/.env" SUPERBOT_MASTER_KEY_FILE "$h/.keys/superbot.key"
  fi
  ensure_master_key
  install_systemd
  install_backup
  wait_healthz || fail "botd did not answer /healthz after install"
}

need_root
command -v systemctl >/dev/null && [[ -d /run/systemd/system ]] || fail "needs systemd"
for c in age age-keygen sqlite3 curl; do command -v "$c" >/dev/null || fail "needs $c"; done
age-keygen -o "$OFFSITE/identity.txt" 2>/dev/null
RECIPIENT=$(age-keygen -y "$OFFSITE/identity.txt")

step "fresh install from this checkout, with a custom DATA_DIR and master key path"
install_superbot custom
H=$(home)
OLD_DATA=$(setting DATA_DIR)
OLD_KEY=$(setting SUPERBOT_MASTER_KEY_FILE)
[[ "$OLD_DATA" == "$H/srv-data" && "$OLD_KEY" == "$H/.keys/superbot.key" && -f "$OLD_DATA/app.sqlite" && -s "$OLD_KEY" ]] ||
  fail "the custom DATA_DIR or master key path was not used"
[[ $(systemctl show -p ExecStart --value superbot-backup.service) == *"$BIN_DIR/superbot-backup --home $H"* ]] ||
  fail "the backup unit does not run superbot-backup --home $H"

step "seed data: a Bot, a sealed secret, a user"
SECRET_VALUE="drill-$(od -An -tx1 -N16 /dev/urandom | tr -d ' \n')"
[[ -z "${GITHUB_ACTIONS:-}" ]] || echo "::add-mask::$SECRET_VALUE"
api -H 'Content-Type: application/json' -d '{"name":"DrillKeep"}' "$BASE/api/bots" >/dev/null
printf '%s\n' "$SECRET_VALUE" | botctl_as_owner secret set DRILL_API_KEY >/dev/null
botctl_as_owner user add drill@example.com "Drill User" --role member >/dev/null

step "back up through the timer's unit"
systemctl start superbot-backup.service
[[ $(systemctl show -p Result --value superbot-backup.service) == success ]] || fail "superbot-backup.service failed"
mapfile -t archives < <(find "$H/superbot/backups" -maxdepth 1 -name 'superbot-*.tar.gz.age')
[[ ${#archives[@]} == 1 ]] || fail "expected one encrypted archive, found ${#archives[@]}"
ARCHIVE=${archives[0]}
[[ $(stat -c '%U %a' "$ARCHIVE") == "$SUPERBOT_USER 600" ]] || fail "archive is not 0600 and owned by $SUPERBOT_USER"
[[ $(head -c 21 "$ARCHIVE") == age-encryption.org/v1 ]] || fail "archive is not age-encrypted"
age -d -i "$OFFSITE/identity.txt" "$ARCHIVE" | tar -xzf - -C "$WORK/plain"
if grep -rqF -e "$SECRET_VALUE" -e "$(cat "$OLD_KEY")" "$WORK/plain"; then
  fail "the archive holds a secret value or the master key"
fi
install -m 0600 -o "$SUPERBOT_USER" "$OFFSITE/identity.txt" "$WORK/identity.txt"
check=$(as_user superbot-restore --check --identity "$WORK/identity.txt" "$ARCHIVE")
printf '%s\n' "$check"
grep -q '^needs master key: yes' <<<"$check" || fail "--check did not see the sealed secret"

step "RPO: the timer is persistent and next fires within ${RPO_BUDGET}s"
[[ $(systemctl show -p Persistent --value superbot-backup.timer) == yes ]] || fail "timer is not Persistent=true"
next=$(systemctl show -p NextElapseUSecRealtime --value superbot-backup.timer)
next_in=$(($(date -d "$next" +%s) - $(date +%s)))
((next_in > 0 && next_in <= RPO_BUDGET)) || fail "next backup in ${next_in}s (budget ${RPO_BUDGET}s)"

step "a change after the backup (inside the RPO window, so it is lost)"
api -H 'Content-Type: application/json' -d '{"name":"DrillDrop"}' "$BASE/api/bots" >/dev/null
cp "$ARCHIVE" "$OFFSITE/archive.tar.gz.age"
cp "$H/superbot/.env" "$OFFSITE/env"
cp "$OLD_KEY" "$OFFSITE/master.key"
OLD_PASSWORD=$(password)
[[ -z "${GITHUB_ACTIONS:-}" ]] || echo "::add-mask::$OLD_PASSWORD"

step "disaster: lose the service user, its data, .env, master key, and local archives"
systemctl stop superbot.service superbot-backup.timer
userdel -r "$SUPERBOT_USER" 2>/dev/null || true
[[ ! -e "$H" ]] || fail "$H still exists"

step "reinstall on the 'new' host (default paths: it knows nothing of the old ones)"
install_superbot
NEW_KEY=$(setting SUPERBOT_MASTER_KEY_FILE)
[[ $(password) != "$OLD_PASSWORD" ]] || fail "reinstall reused the old password"
bots=$(api "$BASE/api/bots") || fail "could not list Bots on the fresh install"
if grep -q DrillKeep <<<"$bots"; then fail "fresh install already has DrillKeep"; fi

step "restore in the documented order: old .env first, then its key path and DATA_DIR (timed)"
t0=$(date +%s)
systemctl stop superbot.service superbot-backup.timer
install -m 0600 -o "$SUPERBOT_USER" -g "$SUPERBOT_USER" "$OFFSITE/env" "$H/superbot/.env"
[[ $(setting DATA_DIR) == "$OLD_DATA" && $(setting SUPERBOT_MASTER_KEY_FILE) == "$OLD_KEY" ]] || fail "the old .env paths are not in place"
install -d -m 0700 -o "$SUPERBOT_USER" -g "$SUPERBOT_USER" "$(dirname "$OLD_KEY")" "$OLD_DATA"
install -m 0600 -o "$SUPERBOT_USER" "$OFFSITE/identity.txt" "$WORK/identity.txt"
as_user superbot-restore --home "$H" --identity "$WORK/identity.txt" - <"$OFFSITE/archive.tar.gz.age" >/dev/null
rm -f "$WORK/identity.txt"
[[ -f "$OLD_DATA/app.sqlite" ]] || fail "the archive was not restored into the old DATA_DIR"
t1=$(date +%s)

# Untimed check: botd refuses the restored data with the new host's master key in the old key's place.
install -m 0600 -o "$SUPERBOT_USER" -g "$SUPERBOT_USER" "$NEW_KEY" "$OLD_KEY"
systemctl start superbot.service
sleep 5
if curl -fsS --max-time 2 "$BASE/healthz" >/dev/null 2>&1; then fail "botd started with the wrong master key"; fi
grep -q "wrong key" <<<"$(journalctl -u superbot --no-pager --since "-1min")" || fail "botd did not log the wrong master key"
systemctl stop superbot.service

t2=$(date +%s)
install -m 0600 -o "$SUPERBOT_USER" -g "$SUPERBOT_USER" "$OFFSITE/master.key" "$OLD_KEY"
systemctl start superbot.service superbot-backup.timer
wait_healthz || fail "botd did not answer /healthz after restore"
t3=$(date +%s)
RTO=$(((t1 - t0) + (t3 - t2)))

step "check the restored data"
[[ $(password) == "$OLD_PASSWORD" ]] || fail "the old .env was not restored"
bots=$(api "$BASE/api/bots")
grep -q '"name":"DrillKeep"' <<<"$bots" || fail "DrillKeep is missing after restore"
if grep -q '"name":"DrillDrop"' <<<"$bots"; then fail "DrillDrop (after the backup) should be gone"; fi
grep -q '"name":"DRILL_API_KEY","shadowedBy":null,"store":"sealed"' <<<"$(api "$BASE/api/secrets")" || fail "the sealed secret is missing"
grep -q drill@example.com <<<"$(botctl_as_owner users)" || fail "the drill user is missing"
grep -q '"name":"DrillKeep"' <<<"$(api "$BASE/api/audit?action=bot.created")" || fail "the audit log lost bot.created for DrillKeep"
systemctl start superbot-backup.service
[[ $(systemctl show -p Result --value superbot-backup.service) == success ]] || fail "backup after restore failed"
((RTO <= RTO_BUDGET)) || fail "restore took ${RTO}s (budget ${RTO_BUDGET}s)"

step "passed: restore took ${RTO}s (budget ${RTO_BUDGET}s); next backup in ${next_in}s (RPO budget ${RPO_BUDGET}s)"
record "\"passed\":true,\"durationMs\":$((RTO * 1000)),\"rtoMs\":$((RTO_BUDGET * 1000)),\"nextBackupInSeconds\":$next_in,\"rpoBudgetSeconds\":$RPO_BUDGET"
