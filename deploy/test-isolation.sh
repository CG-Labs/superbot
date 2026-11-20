#!/usr/bin/env bash
# Per-user accounts on a real host (docs/adr/0037-per-user-unix-accounts.md). It sets them up
# with the installer's own functions, checks the privileged surface, then runs botd's OS
# tests: user B's Bot, through the real run path, against user A's folder and logins.
#
# It adds accounts, a sudoers rule, and /srv/superbot-test, so run it only on a throwaway
# host (CI does), as root:
#   cargo build --bin superbot-run && cargo test --no-run   # as yourself, in the repo
#   sudo deploy/test-isolation.sh --yes target/debug/superbot-run <botd test binary>
# The test binary is the `botd-<hash>` cargo test --no-run prints for src/main.rs.
set -euo pipefail

die() { printf 'test-isolation: %s\n' "$*" >&2; exit 1; }
log() { printf '==> %s\n' "$*"; }

[[ "${1:-}" == --yes && $# == 3 ]] || die "usage: sudo $0 --yes <superbot-run> <botd test binary> (throwaway hosts only)"
[[ "$(id -u)" == 0 ]] || die "run as root"
run_bin=$(realpath "$2")
test_bin=$(realpath "$3")
repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

SVC=sbtest
LIB=/usr/local/lib/superbot-test
TEST_DIR=/srv/superbot-test

cleanup() {
  local u
  for u in $(getent passwd | awk -F: -v d="$TEST_DIR/users/" 'index($6, d) == 1 { print $1 }'); do
    userdel "$u" 2>/dev/null || true
    groupdel "$u" 2>/dev/null || true
  done
  rm -rf "$TEST_DIR" "$LIB" /etc/sudoers.d/superbot-isolation
}
cleanup
trap cleanup EXIT

log "Setting up a service account and per-user accounts with deploy/install.sh's functions"
apt-get install -y -qq acl sudo >/dev/null
id "$SVC" >/dev/null 2>&1 || useradd -m -s /bin/bash "$SVC"
home=$(getent passwd "$SVC" | cut -d: -f6)
install -d -m 0755 "$LIB/bin" "$LIB/fake" "$LIB/share/deploy"
install -m 0755 "$run_bin" "$LIB/bin/superbot-run"
install -m 0755 "$test_bin" "$LIB/botd-tests"
install -m 0755 "$repo/deploy/test-isolation-harness.sh" "$LIB/fake/claude"
install -m 0644 "$repo/deploy/superbot-userctl.sh" "$LIB/share/deploy/superbot-userctl.sh"
install -d -o "$SVC" -g "$SVC" -m 0700 "$home/superbot"
install -o "$SVC" -g "$SVC" -m 0600 /dev/null "$home/superbot/.env"

# shellcheck source=deploy/install.sh
SUPERBOT_INSTALL_NO_MAIN=1 source "$repo/deploy/install.sh"
SUPERBOT_USER=$SVC BIN_DIR=$LIB/bin SHARE_DIR=$LIB/share SYSTEMD_DIR=$LIB/systemd \
  ISOLATION_MODE=users ISOLATION_DIR=$TEST_DIR/users configure_isolation
grep -qx 'ISOLATION=users' "$home/superbot/.env" || die ".env lacks ISOLATION=users"
grep -qx 'ProtectProc=invisible' "$LIB/systemd/superbot.service.d/isolation.conf" || die "no drop-in"
[[ "$(stat -c '%a %U' "$TEST_DIR/users")" == "711 root" ]] || die "$TEST_DIR/users isn't root's 0711"
[[ "$(stat -c '%a' "$home")" == 750 ]] || die "$home isn't 0750"

as_svc() { sudo -u "$SVC" -H -- "$@"; }
refused() { if "$@" >/dev/null 2>&1; then die "allowed: $*"; fi; }

log "The service account may do exactly two things as others, and nothing else"
refused as_svc sudo -n true
refused as_svc sudo -n -u root "$LIB/bin/superbot-run" true
refused as_svc sudo -n -u "$SVC" "$LIB/bin/superbot-run" true
refused as_svc sudo -n /usr/local/sbin/superbot-userctl remove u1
refused as_svc sudo -n /usr/bin/id
for bad in ../etc 'u1 u2' U1 "$(printf 'a%.0s' {1..28})" ''; do
  refused as_svc sudo -n /usr/local/sbin/superbot-userctl ensure "$bad"
done
getent passwd | grep -q '^sb-u-' && die "a refused call made an account"
as_svc sudo -n /usr/local/sbin/superbot-userctl ensure t1 >/dev/null
id -nG sb-u-t1 | tr ' ' '\n' | grep -qx "$SVC" && die "sb-u-t1 is in $SVC's group"
[[ "$(getent passwd sb-u-t1 | cut -d: -f7)" == /usr/sbin/nologin ]] || die "sb-u-t1 can log in"
(cd "$TEST_DIR/users/t1/workspace" && as_svc sudo -n -E -u sb-u-t1 -- "$LIB/bin/superbot-run" /usr/bin/true)
# superbot-run refuses to start outside the account's folders, and as any other account.
(cd "$TEST_DIR/users" && refused as_svc sudo -n -E -u sb-u-t1 -- "$LIB/bin/superbot-run" /usr/bin/true)
(cd "$TEST_DIR/users/t1/workspace" && refused as_svc "$LIB/bin/superbot-run" /usr/bin/true)
# A per-user account can't start anything elsewhere, nor sudo.
refused sudo -u sb-u-t1 sudo -n true

log "botd's OS tests, as $SVC"
envs=(SUPERBOT_ISOLATION_OS_TEST=1 ISOLATION_DIR="$TEST_DIR/users" SUPERBOT_RUN_DIR="$LIB/bin"
  PATH="$LIB/fake:/usr/local/bin:/usr/bin:/bin" HOME="$home" AUTH_PASSWORD=must-not-leak)
args=(--ignored --test-threads=1 --nocapture accounts_os_tests)
if [[ -d /run/systemd/system ]]; then
  # The same sandboxing as superbot.service with its isolation drop-in.
  props=()
  for p in NoNewPrivileges=false ProtectProc=invisible PrivateTmp=true ProtectKernelTunables=true ProtectControlGroups=true; do
    props+=(-p "$p")
  done
  for e in "${envs[@]}"; do
    props+=(-E "$e")
  done
  systemd-run --quiet --wait --pipe --collect --uid="$SVC" --gid="$SVC" -p WorkingDirectory="$home" "${props[@]}" \
    "$LIB/botd-tests" "${args[@]}"
else
  log "No systemd: running without ProtectProc, so other accounts' processes are visible"
  (cd "$home" && sudo -u "$SVC" -- env -i "${envs[@]}" SUPERBOT_PROCS_VISIBLE=1 "$LIB/botd-tests" "${args[@]}")
fi
log "Per-user accounts hold"
