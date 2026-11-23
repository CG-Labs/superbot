#!/usr/bin/env bash
# Restore drill for a managed machine (ADR 0074): restores a drill user's machine from an off-host
# backup through botd's admin API, waits for it to enroll again, and checks how long it took against
# the tier's RTO, as botd recorded it. Everything on that machine since the backup is lost, so run it
# only against a machine kept for drills, never a customer's. docs/ops/machine-recovery.md.
#   deploy/machine-restore-drill.sh <drill user> [--fresh] [--identity <age key file>] --yes
# --fresh backs the machine up first; without it the drill restores the newest scheduled backup.
# Needs botctl and jq on the server, and SUPERBOT_TOKEN (botctl login) for an admin.
set -euo pipefail

usage() {
  echo "usage: deploy/machine-restore-drill.sh <drill user> [--fresh] [--identity <age key file>] --yes" >&2
  exit 2
}
USER_KEY=${1:-}
[[ -n "$USER_KEY" && "$USER_KEY" != --* ]] || usage
shift
FRESH=false
IDENTITY=()
YES=false
while [[ $# -gt 0 ]]; do
  case "$1" in
    --fresh) FRESH=true ;;
    --identity)
      [[ -n "${2:-}" ]] || usage
      IDENTITY=(--identity "$2")
      shift
      ;;
    --yes) YES=true ;;
    *) usage ;;
  esac
  shift
done
$YES || {
  echo "The drill replaces $USER_KEY's machine with a backup and loses everything since. Add --yes for a drill machine." >&2
  exit 2
}
BOTCTL=${BOTCTL:-botctl}
POLL=${SUPERBOT_DRILL_POLL_SECONDS:-10}
# How long past the RTO to wait for botd to record a restore it finished (MACHINE_RECONCILE_SECONDS is 60).
GRACE=${SUPERBOT_DRILL_GRACE_SECONDS:-180}

step() { printf '==> drill: %s\n' "$*"; }
fail() {
  printf 'DRILL FAILED: %s\n' "$*" >&2
  exit 1
}
# The record line superbot-evidence drills --record reads (ADR 0177); the last one printed counts.
# Any other exit, by fail or by set -e inside a command substitution, prints a failed one.
RECORDED=false
on_exit() {
  local status=$?
  if ((status != 0)) && ! $RECORDED; then
    printf '{"superbotDrill":1,"drill":"machine-restore","finishedAt":"%s","passed":false}\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  fi
}
trap on_exit EXIT
api() { "$BOTCTL" "$@" || fail "botctl $*"; }

step "objectives"
api machine recovery | jq -c '.objectives[]'

if $FRESH; then
  step "backing up $USER_KEY's machine"
  BACKUP=$(api machine backup "$USER_KEY" | jq -r '.id')
  while :; do
    STATE=$(api machine backups "$USER_KEY" | jq -r --arg id "$BACKUP" '.backups[] | select(.id == $id) | .state')
    [[ "$STATE" != running ]] && break
    sleep "$POLL"
  done
  [[ "$STATE" == "done" ]] || fail "backup $BACKUP is $STATE"
else
  BACKUP=$(api machine backups "$USER_KEY" | jq -r '[.backups[] | select(.state == "done")][0].id // empty')
  [[ -n "$BACKUP" ]] || fail "$USER_KEY's machine has no finished backup; run with --fresh"
fi

step "restoring $USER_KEY's machine from $BACKUP"
RESTORE=$(api machine restore "$USER_KEY" "$BACKUP" "${IDENTITY[@]}" --yes | jq -r '.restore.id')
[[ -n "$RESTORE" && "$RESTORE" != null ]] || fail "botd didn't start a restore"
DEADLINE=
while :; do
  R=$(api machine restore "$USER_KEY" status)
  [[ $(jq -r '.restore.id' <<<"$R") == "$RESTORE" ]] || fail "another restore replaced $RESTORE"
  STATE=$(jq -r '.restore.state' <<<"$R")
  case "$STATE" in
    done | failed) break ;;
  esac
  if [[ -z "$DEADLINE" ]]; then
    DEADLINE=$(jq -r 'if (.restore.createdAt | type) == "number" and (.restore.rtoMs | type) == "number" then .restore.createdAt + .restore.rtoMs else empty end' <<<"$R")
    [[ "$DEADLINE" =~ ^[0-9]+$ ]] || fail "botd recorded no RTO for $RESTORE"
  fi
  # botd marks a restore done on its next reconcile after the agent enrolls, so give it time
  # to; the pass or fail below is from the time botd recorded, not from this clock.
  (($(date +%s%3N) <= DEADLINE + GRACE * 1000)) || fail "restore $RESTORE is still $STATE past its RTO (botd carries on with it)"
  printf '    %s\n' "$STATE"
  sleep "$POLL"
done
[[ "$STATE" == "done" ]] || fail "restore $RESTORE failed: $(jq -r '.restore.error' <<<"$R")"

TOOK=$(jq -r '.restore.durationMs' <<<"$R")
RTO=$(jq -r '.restore.rtoMs' <<<"$R")
[[ "$TOOK" =~ ^[0-9]+$ && "$RTO" =~ ^[0-9]+$ ]] || fail "botd recorded no timing for $RESTORE"
step "restore $RESTORE took $((TOOK / 1000)) s of an RTO of $((RTO / 60000)) minutes"
jq -c '{superbotDrill: 1, drill: "machine-restore", finishedAt: (now | todate), passed: (.restore.durationMs <= .restore.rtoMs), restoreId: .restore.id, backupId: .restore.backupId, tier: .restore.tier, durationMs: .restore.durationMs, rtoMs: .restore.rtoMs}' <<<"$R"
RECORDED=true
((TOOK <= RTO)) || fail "past the RTO"
step "passed"
