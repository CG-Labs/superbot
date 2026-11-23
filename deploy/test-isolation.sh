#!/usr/bin/env bash
# Per-user accounts on a real host (docs/adr/0037-per-user-unix-accounts.md). It sets them up
# with the installer's own functions, checks the privileged surface, then runs botd's OS
# tests: user B's Bot, through the real run path, against user A's folder and logins, and
# a teammate's run of an owner's shared Bot, as its own account with its own login
# (docs/adr/0064-teammate-accounts-on-one-server.md), and that account's removal when the
# teammate leaves (docs/adr/0066-removing-teammate-accounts-on-one-server.md).
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

log "The service account may run superbot-run as per-user accounts and superbot-userctl, and nothing else"
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
# A run can't gain privileges again, through sudo or any setuid program (ADR 0145).
nnp=$(cd "$TEST_DIR/users/t1/workspace" && as_svc sudo -n -E -u sb-u-t1 -- "$LIB/bin/superbot-run" /usr/bin/grep NoNewPrivs /proc/self/status)
[[ "$(awk '{print $2}' <<<"$nnp")" == 1 ]] || die "a run can gain privileges: $nnp"
# And it runs under the seccomp filter (ADR 0156).
sc=$(cd "$TEST_DIR/users/t1/workspace" && as_svc sudo -n -E -u sb-u-t1 -- "$LIB/bin/superbot-run" /usr/bin/grep '^Seccomp:' /proc/self/status)
[[ "$(awk '{print $2}' <<<"$sc")" == 2 ]] || die "a run isn't under the seccomp filter: $sc"
# superbot-run refuses to start outside the account's folders, and as any other account.
(cd "$TEST_DIR/users" && refused as_svc sudo -n -E -u sb-u-t1 -- "$LIB/bin/superbot-run" /usr/bin/true)
(cd "$TEST_DIR/users/t1/workspace" && refused as_svc "$LIB/bin/superbot-run" /usr/bin/true)
# A per-user account can't start anything elsewhere, nor sudo.
refused sudo -u sb-u-t1 sudo -n true

log "Harness session retention sweeps as the account, inside its own folders only (ADR 0112)"
sid=0b9d2f6e-3c1a-4e8b-9f00-1a2b3c4d5e6f
sudo -u sb-u-t1 mkdir -p "$TEST_DIR/users/t1/home/.claude/projects/-w"
sudo -u sb-u-t1 touch -d '400 days ago' "$TEST_DIR/users/t1/home/.claude/projects/-w/$sid.jsonl" "$TEST_DIR/users/t1/home/.claude/projects/-w/keep.md"
sweep() { printf '{"before":%s,"roots":[{"base":"%s","path":".claude/projects","depth":2}]}' "$(($(date +%s) * 1000))" "$1"; }
out=$(cd "$TEST_DIR/users/t1/home" && sweep "$TEST_DIR/users/t1/home" | as_svc sudo -n -E -u sb-u-t1 -- "$LIB/bin/superbot-run" --sweep)
grep -q '"sessions":1' <<<"$out" || die "the sweep didn't delete the old session: $out"
[[ ! -e "$TEST_DIR/users/t1/home/.claude/projects/-w/$sid.jsonl" && -e "$TEST_DIR/users/t1/home/.claude/projects/-w/keep.md" ]] || die "the sweep deleted the wrong files"
(cd "$TEST_DIR/users/t1/home" && sweep "$TEST_DIR/users" | refused as_svc sudo -n -E -u sb-u-t1 -- "$LIB/bin/superbot-run" --sweep)

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

log "A leaving teammate's account goes, and nothing else does (ADR 0066)"
userctl() { as_svc sudo -n /usr/local/sbin/superbot-userctl "$@"; }
id1=0123456789abcdef
for bad in "t1 t1 $id1 delete" "t2 t2 $id1 hold" "t1 ../x $id1 delete" "t1 U2 $id1 delete" "t1 t2 XYZ delete" "t1 t2 ../$id1 delete" \
  "t1 t2 $id1" "t1 t2 $id1 keep" "t1 t2 $id1 archive" "t1 t2 $id1 archive ../x" "t1 t2 $id1 archive .x" "t1 t2 $id1 hold x" "t1 t2 $id1 delete x"; do
  # shellcheck disable=SC2086 # each is the arguments, on purpose
  refused userctl remove $bad
done
for bad in "" ../x "$id1 x" XYZ; do
  # shellcheck disable=SC2086 # each is the arguments, on purpose
  refused userctl purge $bad
done
getent passwd "$pair" >/dev/null || die "a refused remove took $pair"
for u in sb-u-t1 sb-u-t2; do getent passwd "$u" >/dev/null || die "a refused remove took $u"; done
# An account with the name a pair would get, but not the home: never removed.
forged=sb-t-$(printf '%s' 't1:t3' | sha256sum | cut -c1-24)
useradd --system --home-dir /nonexistent --no-create-home --shell /usr/sbin/nologin "$forged"
refused userctl remove t1 t3 "$id1" delete
getent passwd "$forged" >/dev/null || die "remove took $forged, which isn't its account"
userdel "$forged"
groupdel "$forged" 2>/dev/null || true

# The pair account has work, a set-id file, a temp file and a tool that ignores TERM.
pair_uid=$(id -u "$pair")
ws=$TEST_DIR/users/t1-t2/workspace
sudo -u "$pair" sh -c "cd '$ws' && echo notes >notes.txt && : >tool && chmod 4755 tool && : >/tmp/sb-left-\$(id -u)"
# And a run's memory copy it never got to save, beside the teammate's USER.md.
sudo -u "$pair" sh -c "echo remembered >'$TEST_DIR/users/t1-t2/memory/b1.md' && echo me >'$TEST_DIR/users/t1-t2/memory/USER.md'"
# A file of the same name already set aside is kept beside it, not in its place.
sudo -u "$pair" sh -c "mkdir -p '$ws/unsaved-memory' && echo earlier >'$ws/unsaved-memory/b1.md'"
[[ -e "/tmp/sb-left-$pair_uid" ]] || die "no temp file of $pair"
sudo -u "$pair" setsid sh -c 'trap "" TERM; while :; do sleep 0.2; done' </dev/null >/dev/null 2>&1 &
sleep 0.5
pgrep -u "$pair_uid" >/dev/null || die "no process of $pair"
pgrep -u "$(id -u sb-u-t1)" >/dev/null && die "sb-u-t1 has processes already"
sudo -u sb-u-t1 setsid sh -c 'trap "" TERM; while :; do sleep 0.2; done' </dev/null >/dev/null 2>&1 &
owner_pid=$!
out=$(userctl remove t1 t2 "$id1" archive t2-notes)
grep -qx account=removed <<<"$out" || die "remove said: $out"
grep -qx work=archived <<<"$out" || die "remove said: $out"
to=$TEST_DIR/users/t1/workspace/from-teammates/t2-notes
grep -qx "path=$to" <<<"$out" || die "remove said: $out"
getent passwd "$pair" >/dev/null && die "$pair is still there"
getent group "$pair" >/dev/null && die "$pair's group is still there"
pgrep -u "$pair_uid" >/dev/null && die "a process of $pair is still going"
kill -0 "$owner_pid" 2>/dev/null || die "remove stopped someone else's process"
[[ ! -e "$TEST_DIR/users/t1-t2" ]] || die "t1-t2 is still there"
[[ ! -e "/tmp/sb-left-$pair_uid" ]] || die "$pair's temp file is still there"
[[ "$(stat -c '%U' "$to/notes.txt")" == sb-u-t1 && "$(cat "$to/notes.txt")" == notes ]] || die "the work isn't sb-u-t1's"
[[ "$(stat -c '%a' "$to/tool")" == 755 ]] || die "a set-id bit was handed over"
[[ "$(cat "$to/unsaved-memory/b1-2.md")" == remembered ]] || die "the unsaved memory copy was lost"
[[ "$(cat "$to/unsaved-memory/b1.md")" == earlier ]] || die "a memory copy already set aside was replaced"
[[ ! -e "$to/unsaved-memory/USER.md" ]] || die "the teammate's USER.md was handed to the owner"
for u in sb-u-t1 sb-u-t2; do getent passwd "$u" >/dev/null || die "remove took $u"; done
[[ -d "$TEST_DIR/users/t1/home" && -d "$TEST_DIR/users/t2/home" ]] || die "remove took a user's own folder"
pkill -KILL -u sb-u-t1 || true
# Again: nothing left to do, the archived work stays, and it still says where it went.
out=$(userctl remove t1 t2 "$id1" archive t2-notes)
grep -qx account=absent <<<"$out" && grep -qx work=archived <<<"$out" && grep -qx "path=$to" <<<"$out" || die "remove again said: $out"
[[ -f "$to/notes.txt" ]] || die "remove again touched the archive"

# Held aside, root's alone, until purged.
userctl ensure t1 t2 >/dev/null
sudo -u "$pair" sh -c "echo held >'$ws/held.txt'"
id2=fedcba9876543210
out=$(userctl remove t1 t2 "$id2" hold)
grep -qx work=held <<<"$out" || die "remove hold said: $out"
[[ "$(stat -c '%a %U' "$TEST_DIR/users/.left")" == "700 root" ]] || die ".left isn't root's 0700"
[[ "$(cat "$TEST_DIR/users/.left/$id2/held.txt")" == held ]] || die "the held work isn't there"
[[ "$(userctl purge "$id2")" == purged=yes ]] || die "purge didn't"
[[ ! -e "$TEST_DIR/users/.left/$id2" ]] || die "the held work is still there"
[[ "$(userctl purge "$id2")" == purged=no ]] || die "purge again did something"

# A try that stopped once the work was staged in the owner's workspace: the next one tidies
# it away and says where it went.
id3=00112233aabbccdd
staged=$TEST_DIR/users/t1/workspace/.superbot-from-teammate-$id3
sudo -u sb-u-t1 sh -c "mkdir '$staged' && echo staged >'$staged/s.txt'"
out=$(userctl remove t1 t2 "$id3" archive t2-later)
grep -qx work=archived <<<"$out" && grep -qx "path=$TEST_DIR/users/t1/workspace/from-teammates/t2-later" <<<"$out" || die "remove after a staged try said: $out"
[[ ! -e "$staged" && -f "$TEST_DIR/users/t1/workspace/from-teammates/t2-later/s.txt" ]] || die "the staged work wasn't tidied away"

# As a recreated container leaves it: a pair's folder, but not its account. botd's OS test
# finds and removes it.
userctl ensure t1 t3 >/dev/null
lost=sb-t-$(printf '%s' 't1:t3' | sha256sum | cut -c1-24)
userdel "$lost"
groupdel "$lost" 2>/dev/null || true

log "One read-only Hermes environment serves every account's Bots, each with its own record (ADR 0072)"
hs=$LIB/hermes
launcher=$hs/.hermes/hermes-agent/.hermes/bin/hermes
mkdir -p "$(dirname "$launcher")"
# shellcheck disable=SC2016 # expanded by the fake launcher
printf '#!/bin/sh\necho "lazy=${HERMES_DISABLE_LAZY_INSTALLS:-} home=$HERMES_HOME"\n' >"$launcher"
chmod 0755 "$launcher"
key=$(printf '%s' "$(cd "$hs/.hermes/hermes-agent" && pwd -P)" | sha256sum | cut -c1-16)
st=$hs/.hermes/installs/$key
mkdir -p "$st/environments/g1/venv" "$st/inputs"
: >"$st/inputs/uv.lock"
printf '{"environment": "%s/environments/g1/venv"}\n' "$st" >"$st/facts.json"
wrapper=$(HOME="$hs" sh "$repo/deploy/hermes-share.sh")
chmod -R go-w "$hs"
for u in t1 t2; do
  bh=$TEST_DIR/users/$u/home/hermes
  out=$(sudo -u "sb-u-$u" env HERMES_HOME="$bh" "$wrapper")
  [[ "$out" == "lazy=1 home=$bh" ]] || die "sb-u-$u's Bot didn't run the shared Hermes: $out"
  [[ "$(stat -c '%U' "$bh/installs/$key")" == "sb-u-$u" ]] || die "sb-u-$u's record of the install isn't its own"
  (( (8#$(stat -c '%a' "$bh/installs/$key") & 8#007) == 0 )) || die "other accounts may read sb-u-$u's record of the install"
  [[ "$(readlink "$bh/installs/$key/environments")" == "$st/environments" ]] || die "sb-u-$u's Bot doesn't use the shared environment"
  refused sudo -u "sb-u-$u" touch "$st/environments/g1/venv/x"
  refused sudo -u "sb-u-$u" touch "$st/facts.json"
done
refused sudo -u sb-u-t2 ls "$TEST_DIR/users/t1/home/hermes"
refused sudo -u sb-u-t2 env HERMES_HOME="$TEST_DIR/users/t1/home/hermes" "$wrapper"

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
