#!/usr/bin/env bash
# Per-user accounts on a real host (docs/adr/0037-per-user-unix-accounts.md). It sets them up
# with the installer's own functions, checks the privileged surface, then runs botd's OS
# tests: user B's Bot, through the real run path, against user A's folder and logins, and
# a teammate's run of an owner's shared Bot, as its own account with its own login
# (docs/adr/0064-teammate-accounts-on-one-server.md).
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
    pkill -KILL -u "$u" 2>/dev/null || true
    userdel "$u" 2>/dev/null || true
    groupdel "$u" 2>/dev/null || true
  done
  rm -rf "$TEST_DIR" "$LIB" /etc/sudoers.d/superbot-isolation /etc/superbot/isolation.conf \
    /usr/local/sbin/superbot-userctl /run/superbot-userctl.lock
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
for h in claude pi hermes; do
  install -m 0755 "$repo/deploy/test-isolation-harness.sh" "$LIB/fake/$h"
done
install -m 0644 "$repo/deploy/superbot-userctl.sh" "$LIB/share/deploy/superbot-userctl.sh"
install -d -o "$SVC" -g "$SVC" -m 0700 "$home/superbot"
install -o "$SVC" -g "$SVC" -m 0600 /dev/null "$home/superbot/.env"
printf 'AUTH_PASSWORD=must-not-leak\n' >"$home/superbot/.env"
install -d -o "$SVC" -g "$SVC" -m 0700 "$home/.config" "$home/.config/superbot"
install -o "$SVC" -g "$SVC" -m 0600 /dev/null "$home/.config/superbot/master.key"

# shellcheck source=deploy/install.sh
SUPERBOT_INSTALL_NO_MAIN=1 source "$repo/deploy/install.sh"
SUPERBOT_USER=$SVC BIN_DIR=$LIB/bin SHARE_DIR=$LIB/share SYSTEMD_DIR=$LIB/systemd \
  ISOLATION_MODE=users ISOLATION_DIR=$TEST_DIR/users configure_isolation
grep -qx 'ISOLATION=users' "$home/superbot/.env" || die ".env lacks ISOLATION=users"
# An upgrade with no flags keeps it on, in the same folder, whatever botd's account
# wrote into .env meanwhile.
printf '%s\n' "ISOLATION_DIR=$TEST_DIR/tampered" >>"$home/superbot/.env"
SUPERBOT_USER=$SVC BIN_DIR=$LIB/bin SHARE_DIR=$LIB/share SYSTEMD_DIR=$LIB/systemd \
  ISOLATION_MODE="" ISOLATION_DIR="" configure_isolation
[[ ! -e "$TEST_DIR/tampered" ]] || die "the upgrade used ISOLATION_DIR from .env"
[[ "$(SUPERBOT_USER=$SVC SUDOERS_FILE=/nonexistent isolation_mode)" == off ]] || die "ISOLATION=users in .env alone turned isolation on"
grep -qx "ISOLATION_DIR=$TEST_DIR/users" "$home/superbot/.env" || die "the upgrade lost ISOLATION_DIR in .env"
grep -qx "ISOLATION_DIR=$TEST_DIR/users" /etc/superbot/isolation.conf || die "the upgrade lost ISOLATION_DIR in isolation.conf"
grep -qx 'ProtectProc=invisible' "$LIB/systemd/superbot.service.d/isolation.conf" || die "no drop-in"
[[ "$(stat -c '%a %U' "$TEST_DIR/users")" == "711 root" ]] || die "$TEST_DIR/users isn't root's 0711"
[[ "$(stat -c '%a' "$home")" == 750 ]] || die "$home isn't 0750"
# ADR 0058: a new install (no .env yet) gets accounts; an existing one keeps its setting.
# shellcheck disable=SC2034 # read by default_isolation
picked() { (ISOLATION_MODE="" UPGRADE=$1 SUPERBOT_USER=$SVC; default_isolation >/dev/null; printf '%s' "$ISOLATION_MODE"); }
[[ -z "$(picked false)" ]] || die "an existing install was switched to per-user accounts"
mv "$home/superbot/.env" "$home/superbot/.env.kept"
[[ "$(picked false)" == users ]] || die "a new install didn't get per-user accounts"
[[ -z "$(picked true)" ]] || die "an upgrade was switched to per-user accounts"
mv "$home/superbot/.env.kept" "$home/superbot/.env"

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
grep -q '^sb-u-' <<<"$(getent passwd)" && die "a refused call made an account"
as_svc sudo -n /usr/local/sbin/superbot-userctl ensure t1 >/dev/null
grep -qx "$SVC" <<<"$(id -nG sb-u-t1 | tr ' ' '\n')" && die "sb-u-t1 is in $SVC's group"
[[ "$(getent passwd sb-u-t1 | cut -d: -f7)" == /usr/sbin/nologin ]] || die "sb-u-t1 can log in"
for d in bots settings; do
  [[ "$(stat -c '%a %U' "$TEST_DIR/users/t1/$d")" == "2770 root" ]] || die "t1/$d isn't root's 2770"
done
# A container's /etc/passwd starts over when it's recreated: the account comes back with
# the uid that owns its files.
uid=$(id -u sb-u-t1)
userdel sb-u-t1
groupdel sb-u-t1 2>/dev/null || true
as_svc sudo -n /usr/local/sbin/superbot-userctl ensure t1 >/dev/null
[[ "$(id -u sb-u-t1)" == "$uid" ]] || die "the re-made sb-u-t1 got another uid"
(cd "$TEST_DIR/users/t1/workspace" && as_svc sudo -n -E -u sb-u-t1 -- "$LIB/bin/superbot-run" /usr/bin/true)
# superbot-run refuses to start outside the account's folders, and as any other account.
(cd "$TEST_DIR/users" && refused as_svc sudo -n -E -u sb-u-t1 -- "$LIB/bin/superbot-run" /usr/bin/true)
(cd "$TEST_DIR/users/t1/workspace" && refused as_svc "$LIB/bin/superbot-run" /usr/bin/true)
# A per-user account can't start anything elsewhere, nor sudo.
refused sudo -u sb-u-t1 sudo -n true

log "A teammate's account for an owner's shared Bots is its own (ADR 0064)"
for bad in 't1 t1' 't1 ../x' 't1 U2' 't1 t2 t3' "t1 $(printf 'a%.0s' {1..28})"; do
  # shellcheck disable=SC2086 # each is the arguments, on purpose
  refused as_svc sudo -n /usr/local/sbin/superbot-userctl ensure $bad
done
grep -q '^sb-t-' <<<"$(getent passwd)" && die "a refused call made a teammate account"
as_svc sudo -n /usr/local/sbin/superbot-userctl ensure t2 >/dev/null
pair=sb-t-$(printf '%s' 't1:t2' | sha256sum | cut -c1-24)
[[ "$(as_svc sudo -n /usr/local/sbin/superbot-userctl ensure t1 t2)" == "$pair $TEST_DIR/users/t1-t2/home" ]] || die "no $pair for t1's Bots and t2"
grep -qx "$SVC" <<<"$(id -nG "$pair" | tr ' ' '\n')" && die "$pair is in $SVC's group"
[[ "$(getent passwd "$pair" | cut -d: -f7)" == /usr/sbin/nologin ]] || die "$pair can log in"
[[ "$(stat -c '%a %U' "$TEST_DIR/users/t1-t2/home")" == "2770 $pair" ]] || die "t1-t2/home isn't $pair's 2770"
# Neither the owner's account nor the teammate's own may enter it, nor it theirs.
for u in sb-u-t1 sb-u-t2; do
  refused sudo -u "$u" ls "$TEST_DIR/users/t1-t2"
  refused sudo -u "$pair" ls "$TEST_DIR/users/${u#sb-u-}"
done
(cd "$TEST_DIR/users/t1-t2/workspace" && as_svc sudo -n -E -u "$pair" -- "$LIB/bin/superbot-run" /usr/bin/true)
(cd "$TEST_DIR/users/t1/workspace" && refused as_svc sudo -n -E -u "$pair" -- "$LIB/bin/superbot-run" /usr/bin/true)
(cd "$TEST_DIR/users/t1-t2/workspace" && refused as_svc sudo -n -E -u sb-u-t1 -- "$LIB/bin/superbot-run" /usr/bin/true)
refused sudo -u "$pair" sudo -n true

log "botd's OS tests, as $SVC"
envs=(SUPERBOT_ISOLATION_OS_TEST=1 ISOLATION_DIR="$TEST_DIR/users" SUPERBOT_RUN_DIR="$LIB/bin"
  PATH="$LIB/fake:/usr/local/bin:/usr/bin:/bin" HOME="$home" AUTH_PASSWORD=must-not-leak
  SUPERBOT_OS_TEST_KEY_FILE="$home/.config/superbot/master.key")
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
