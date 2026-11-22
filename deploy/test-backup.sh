#!/usr/bin/env bash
# Fast checks of superbot-backup and superbot-restore against a made-up DATA_DIR: no botd, systemd,
# or Docker. Needs sqlite3 and age. The full drills: deploy/backup-drill.sh and deploy/docker/smoke-test.sh.
#   deploy/test-backup.sh
set -euo pipefail

DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
BACKUP="$DIR/superbot-backup.sh"
RESTORE="$DIR/superbot-restore.sh"
T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT
# Nothing may answer as botd here, or restores are refused.
export PORT=1

fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
ok() { printf 'ok - %s\n' "$*"; }
refuses() { # message command...
  local msg=$1
  shift
  if "$@" >"$T/out" 2>&1; then fail "expected a refusal: $*"; fi
  grep -qF -- "$msg" "$T/out" || { cat "$T/out" >&2; fail "expected '$msg' from: $*"; }
}

seed() { # data-dir
  mkdir -p "$1/bots/b1" "$1/screens/1"
  sqlite3 "$1/app.sqlite" "CREATE TABLE bots (id TEXT, name TEXT); INSERT INTO bots VALUES ('b1', 'KeepMe');
    CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT); INSERT INTO settings VALUES ('secrets_key_check', 'sb1:x');
    CREATE TABLE audit_events (id INTEGER PRIMARY KEY, at INTEGER); INSERT INTO audit_events (at) VALUES (1763600000000);"
  echo memory >"$1/bots/b1/MEMORY.md"
  echo facts >"$1/USER.md"
  echo transient >"$1/screens/1/state"
}
names() { sqlite3 "$1/app.sqlite" "SELECT group_concat(name) FROM bots"; }

# Installer layout: <home>/superbot/{.env,data,backups}, with a quoted DATA_DIR as the installer may write.
H="$T/home"
D="$H/superbot/data"
mkdir -p "$H/superbot"
seed "$D"
printf "DATA_DIR='%s'\nPORT=1\n" "$D" >"$H/superbot/.env"

"$BACKUP" --home "$H" 2>/dev/null
mapfile -t plain < <(find "$H/superbot/backups" -name 'superbot-*.tar.gz')
[[ ${#plain[@]} == 1 ]] || fail "--home did not write one archive to ~/superbot/backups"
[[ $(stat -c %a "${plain[0]}") == 600 ]] || fail "archive is not 0600"
tar -tzf "${plain[0]}" >"$T/list"
grep -qx app.sqlite "$T/list" && grep -qx .superbot-backup "$T/list" && grep -qx ./bots/b1/MEMORY.md "$T/list" ||
  fail "archive lacks app.sqlite, .superbot-backup, or Bot memory"
if grep -q screens "$T/list"; then fail "archive holds per-run screen state"; fi
ok "--home reads a quoted DATA_DIR and writes a private archive without screens"

"$BACKUP" "$H" 2>/dev/null
[[ $(find "$H/superbot/backups" -name 'superbot-*.tar.gz' | wc -l) == 2 ]] || fail "same-second runs collided"
ok "the old unit's 'superbot-backup <home>' still works, and same-second runs get distinct names"

mkdir "$H/superbot/backups/20200101-000000"
touch -d 2020-01-01 "$H/superbot/backups/20200101-000000"
cp "${plain[0]}" "$H/superbot/backups/superbot-20200101-000000.tar.gz"
touch -d 2020-01-01 "$H/superbot/backups/superbot-20200101-000000.tar.gz"
"$BACKUP" --home "$H" 2>/dev/null
[[ ! -e "$H/superbot/backups/20200101-000000" && ! -e "$H/superbot/backups/superbot-20200101-000000.tar.gz" ]] ||
  fail "retention kept an old archive or old-style snapshot folder"
ok "retention prunes old archives and pre-ADR 0030 snapshot folders"

N="$T/nested"
seed "$N"
DATA_DIR=$N BACKUP_DIR=$N/./backups "$BACKUP" 2>/dev/null
DATA_DIR=$N BACKUP_DIR=$N/backups "$BACKUP" 2>/dev/null
mapfile -t nested < <(find "$N/backups" -name 'superbot-*.tar.gz' | sort)
[[ ${#nested[@]} == 2 ]] || fail "BACKUP_DIR inside DATA_DIR did not write two archives"
tar -tzf "${nested[1]}" >"$T/list"
grep -qx ./bots/b1/MEMORY.md "$T/list" || fail "nested-BACKUP_DIR archive lacks Bot memory"
if grep -q backups "$T/list"; then fail "an archive holds the backups inside DATA_DIR"; fi
refuses "BACKUP_DIR must not be DATA_DIR" env DATA_DIR="$N" BACKUP_DIR="$N/" "$BACKUP"
ok "a BACKUP_DIR inside DATA_DIR is left out of archives, and BACKUP_DIR = DATA_DIR is refused"

age-keygen -o "$T/id.txt" 2>/dev/null
RECIPIENT=$(age-keygen -y "$T/id.txt")
age-keygen -o "$T/other.txt" 2>/dev/null
DATA_DIR=$D SUPERBOT_BACKUP_AGE_RECIPIENTS=$RECIPIENT "$BACKUP" - >"$T/enc.age"
[[ $(head -c 21 "$T/enc.age") == age-encryption.org/v1 ]] || fail "stream is not age-encrypted"
if tar -tzf "$T/enc.age" >/dev/null 2>&1; then fail "the encrypted stream opens as plain tar"; fi
ok "recipients encrypt the archive"

mkdir "$T/noage"
for c in bash date; do ln -s "$(command -v "$c")" "$T/noage/$c"; done
refuses "age recipients are set but age is not installed" \
  env PATH="$T/noage" DATA_DIR="$D" SUPERBOT_BACKUP_AGE_RECIPIENTS="$RECIPIENT" "$BACKUP" -
ok "encryption asked for but unavailable fails instead of writing plaintext"

# A tar that reports exit code $FAKE_TAR_EXIT after doing its work, as GNU tar does (1) when a Bot
# writes a file mid-read, or (2) on a fatal error.
mkdir "$T/faketar"
printf '#!/bin/sh\n%s "$@" || exit $?\nexit "$FAKE_TAR_EXIT"\n' "$(command -v tar)" >"$T/faketar/tar"
chmod +x "$T/faketar/tar"
B="$T/busy-backups"
PATH="$T/faketar:$PATH" FAKE_TAR_EXIT=1 DATA_DIR=$D BACKUP_DIR=$B "$BACKUP" 2>"$T/out"
PATH="$T/faketar:$PATH" FAKE_TAR_EXIT=1 DATA_DIR=$D BACKUP_DIR=$B SUPERBOT_BACKUP_AGE_RECIPIENTS=$RECIPIENT "$BACKUP" 2>>"$T/out"
grep -q "changed while they were read" "$T/out" || fail "no warning for files changed mid-read"
[[ $(find "$B" -name 'superbot-*.tar.gz' | wc -l) == 1 && $(find "$B" -name 'superbot-*.tar.gz.age' | wc -l) == 1 ]] ||
  fail "a file changing mid-read discarded the archive"
listing=$(tar -tzf "$(find "$B" -name 'superbot-*.tar.gz')") || fail "the kept archive is unreadable"
grep -qx app.sqlite <<<"$listing" || fail "the kept archive has no app.sqlite"
rm -rf "$B"
refuses "backup failed" env PATH="$T/faketar:$PATH" FAKE_TAR_EXIT=2 DATA_DIR="$D" BACKUP_DIR="$B" "$BACKUP"
[[ -z $(find "$B" -type f ! -name .lock) ]] || fail "a fatal tar error left an archive or partial file"
ok "files changing mid-read keep the archive; fatal tar errors leave nothing"

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  echo private >"$D/bots/b1/unreadable"
  chmod 000 "$D/bots/b1/unreadable"
  refuses "backup failed" env DATA_DIR="$D" BACKUP_DIR="$B" "$BACKUP"
  [[ -z $(find "$B" -type f ! -name .lock) ]] || fail "a backup that could not read a file was kept"
  rm -f "$D/bots/b1/unreadable"
  ok "a file the backup can't read fails the run instead of being left out"
fi

refuses "give the age identity" "$RESTORE" --check "$T/enc.age"
refuses "could not decrypt" "$RESTORE" --check --identity "$T/other.txt" "$T/enc.age"
"$RESTORE" --check --identity "$T/id.txt" - <"$T/enc.age" >"$T/check" 2>&1
grep -q '^bots:  *1$' "$T/check" && grep -q '^needs master key: yes' "$T/check" && grep -q '^newest audit: *2025-' "$T/check" ||
  { cat "$T/check" >&2; fail "--check summary is wrong"; }
ok "--check needs the right identity and summarises the archive"

sqlite3 "$D/app.sqlite" "INSERT INTO bots VALUES ('b2', 'DropMe')"
echo stray >"$D/stray.txt"
SUPERBOT_BACKUP_AGE_IDENTITY_FILE=$T/id.txt "$RESTORE" --home "$H" - <"$T/enc.age" 2>/dev/null
[[ $(names "$D") == KeepMe ]] || fail "restore did not roll back the database"
[[ $(cat "$D/bots/b1/MEMORY.md") == memory && ! -e "$D/stray.txt" && ! -e "$D/.superbot-backup" ]] ||
  fail "restore left DATA_DIR in the wrong shape"
prev=$(find "$D" -maxdepth 1 -name '.pre-restore-*')
[[ -f "$prev/stray.txt" ]] && [[ $(names "$prev") == KeepMe,DropMe ]] || fail "previous data was not kept aside"
ok "restore swaps DATA_DIR and keeps the previous contents"

DATA_DIR=$D "$BACKUP" - >"$T/again.tar.gz"
listing=$(tar -tzf "$T/again.tar.gz") || fail "the backup after a restore is unreadable"
if grep -q -e '\.pre-restore-' -e '\.restore-' <<<"$listing"; then fail "a backup carried restore leftovers"; fi
ok "backups skip restore leftovers"

mkdir "$T/bad"
printf 'not a database' >"$T/bad/app.sqlite"
tar -czf "$T/bad.tar.gz" -C "$T/bad" app.sqlite
refuses "integrity_check" "$RESTORE" --check "$T/bad.tar.gz"
rm "$T/bad/app.sqlite"
seed "$T/bad"
printf 'format=2\n' >"$T/bad/.superbot-backup"
tar -czf "$T/future.tar.gz" -C "$T/bad" .
refuses "newer than this superbot-restore" "$RESTORE" --check "$T/future.tar.gz"
tar -czf "$T/empty.tar.gz" -C "$T/bad" USER.md
refuses "not a superbot-backup archive" "$RESTORE" --check "$T/empty.tar.gz"
before=$(names "$D")
refuses "integrity_check" env DATA_DIR="$D" "$RESTORE" "$T/bad.tar.gz"
[[ $(names "$D") == "$before" ]] || fail "a refused restore changed DATA_DIR"
ok "damaged, foreign, and newer-format archives are refused before anything is swapped"

python3 -m http.server 18731 --bind 127.0.0.1 --directory "$T" >/dev/null 2>&1 &
srv=$!
mkdir -p "$T/healthz"
for _ in $(seq 1 50); do curl -fsS -o /dev/null http://127.0.0.1:18731/healthz/ 2>/dev/null && break; sleep 0.1; done
refuses "botd is running" env DATA_DIR="$D" PORT=18731 "$RESTORE" "${plain[0]}"
kill "$srv"
ok "restore refuses while something answers /healthz on PORT"

# SUPERBOT_BACKUP_ENCRYPTION (ADR 0114): required refuses plaintext, from the environment or .env.
R="$T/required"
refuses "refusing to write a plain archive" env DATA_DIR="$D" BACKUP_DIR="$R" SUPERBOT_BACKUP_ENCRYPTION=required "$BACKUP"
[[ -z $(find "$R" -type f ! -name .lock 2>/dev/null) ]] || fail "required left a plain archive"
refuses "must be auto, required or off" env DATA_DIR="$D" BACKUP_DIR="$R" SUPERBOT_BACKUP_ENCRYPTION=maybe "$BACKUP"
cp "$H/superbot/.env" "$T/env.saved"
echo SUPERBOT_BACKUP_ENCRYPTION=required >>"$H/superbot/.env"
refuses "refusing to write a plain archive" "$BACKUP" --home "$H"
echo "SUPERBOT_BACKUP_AGE_RECIPIENTS=$RECIPIENT" >>"$H/superbot/.env"
"$BACKUP" --home "$H" 2>/dev/null
[[ -n $(find "$H/superbot/backups" -name 'superbot-*.tar.gz.age') ]] || fail "required with recipients wrote no encrypted archive"
cp "$T/env.saved" "$H/superbot/.env"
DATA_DIR=$D BACKUP_DIR=$R SUPERBOT_BACKUP_ENCRYPTION=off "$BACKUP" 2>/dev/null
[[ -n $(find "$R" -name 'superbot-*.tar.gz') ]] || fail "off didn't write a plain archive"
ok "SUPERBOT_BACKUP_ENCRYPTION=required refuses plain archives; off and recipients still write"

# Compose's init.sh (ADR 0114): a new .env gets a private age key; the key restores what the
# sidecar would write with that .env; a re-run keeps it; plain by choice makes none.
INIT="$DIR/docker/init.sh"
C="$T/compose"
mkdir "$C"
ENV_FILE="$C/.env" BACKUP_IDENTITY_FILE="$C/identity.txt" "$INIT" --localhost >"$T/init.out"
[[ -f "$C/identity.txt" && $(stat -c %a "$C/identity.txt") == 600 ]] || fail "init.sh made no private backup key"
public=$(age-keygen -y "$C/identity.txt")
grep -qx "SUPERBOT_BACKUP_AGE_RECIPIENTS='$public'" "$C/.env" || fail "init.sh doesn't encrypt to its key"
grep -q "Copy it off this host now" "$T/init.out" || fail "init.sh doesn't say to copy the key off"
key=$(sha256sum "$C/identity.txt") env_before=$(cat "$C/.env")
ENV_FILE="$C/.env" BACKUP_IDENTITY_FILE="$C/identity.txt" "$INIT" --localhost >"$T/init.out"
[[ "$(sha256sum "$C/identity.txt")" == "$key" && "$(cat "$C/.env")" == "$env_before" ]] || fail "re-running init.sh changed the key or .env"
grep -q "still on this host" "$T/init.out" || fail "init.sh doesn't say the key is still on the host"
DATA_DIR=$D SUPERBOT_BACKUP_AGE_RECIPIENTS=$public "$BACKUP" - >"$T/compose.age"
"$RESTORE" --check --identity "$C/identity.txt" "$T/compose.age" >"$T/check" 2>&1 || { cat "$T/check" >&2; fail "init.sh's key doesn't open the archive"; }
refuses "could not decrypt" "$RESTORE" --check --identity "$T/id.txt" "$T/compose.age"
O="$T/compose-off"
mkdir "$O"
ENV_FILE="$O/.env" BACKUP_IDENTITY_FILE="$O/identity.txt" "$INIT" --localhost --backup-encryption off >/dev/null
[[ ! -e "$O/identity.txt" ]] || fail "init.sh made a key with --backup-encryption off"
grep -qx "SUPERBOT_BACKUP_ENCRYPTION='off'" "$O/.env" || fail "init.sh didn't write --backup-encryption off"
refuses "makes a key that --backup-encryption off" env ENV_FILE="$O/.env" "$INIT" --backup-age-generate --backup-encryption off
ENV_FILE="$O/.env" BACKUP_IDENTITY_FILE="$O/identity.txt" "$INIT" --backup-encryption auto --backup-age-generate >/dev/null
grep -qx "SUPERBOT_BACKUP_AGE_RECIPIENTS='$(age-keygen -y "$O/identity.txt")'" "$O/.env" || fail "--backup-age-generate didn't set recipients"
E="$T/compose-empty"
mkdir "$E"
printf 'SUPERBOT_BACKUP_AGE_RECIPIENTS=""\n' >"$E/.env"
refuses "required, but" env ENV_FILE="$E/.env" "$INIT" --backup-encryption required
ENV_FILE="$E/.env" BACKUP_IDENTITY_FILE="$E/identity.txt" "$INIT" --backup-age-generate >/dev/null
grep -qx "SUPERBOT_BACKUP_AGE_RECIPIENTS='$(age-keygen -y "$E/identity.txt")'" "$E/.env" || fail "init.sh took quoted-empty recipients as set"
printf "SUPERBOT_BACKUP_AGE_RECIPIENTS=' %s '\n" "$public" >"$E/.env"
cp "$E/.env" "$T/padded.env"
ENV_FILE="$E/.env" BACKUP_IDENTITY_FILE="$E/identity2.txt" "$INIT" --backup-encryption required --backup-age-generate >/dev/null
[[ ! -e "$E/identity2.txt" ]] && grep -qxF "$(cat "$T/padded.env")" "$E/.env" || fail "init.sh took padded recipients as unset"
ok "init.sh makes a private key for a new .env, keeps it on re-runs, and it restores the archives"

# An encrypted database (ADR 0116): a real botd makes one; superbot-backup copies it with botd
# and the master key, still encrypted; superbot-restore reads it with the key, restores it
# unread without one, and refuses another key. CI passes the release build as SUPERBOT_BOTD.
BOTD=${SUPERBOT_BOTD:-}
for b in "$DIR/../target/release/botd" "$DIR/../target/debug/botd"; do
  [[ -n "$BOTD" || ! -x "$b" ]] || BOTD=$b
done
if [[ -z "$BOTD" ]]; then
  [[ -z "${CI:-}" ]] || fail "set SUPERBOT_BOTD to a botd build for the encrypted database checks"
  echo "skip - encrypted database checks (no botd: build it, or set SUPERBOT_BOTD)"
  echo "All backup script checks passed"
  exit 0
fi
BOTD=$(realpath "$BOTD")
plain_db() { [[ "$(head -c 15 "$1" | tr -d '\0')" == "SQLite format 3" ]]; }
new_key() { (umask 077 && head -c 32 /dev/urandom | base64 >"$1"); }
EH="$T/enc-home"
ED="$EH/superbot/data"
mkdir -p "$ED" "$EH/keys" "$EH/workspace"
new_key "$EH/keys/master.key"
new_key "$T/wrong.key"
printf "DATA_DIR='%s'\nPORT=1\nSUPERBOT_MASTER_KEY_FILE=%s\n" "$ED" "$EH/keys/master.key" >"$EH/superbot/.env"
env -i PATH="$PATH" HOME="$EH" HOST=127.0.0.1 PORT=18732 AUTH_PASSWORD=ci-password DATA_DIR="$ED" WORKSPACE_DIR="$EH/workspace" \
  SCREENS=off TESTING_MODE=on SUPERBOT_DATABASE_ENCRYPTION=required SUPERBOT_MASTER_KEY_FILE="$EH/keys/master.key" \
  "$BOTD" >"$T/botd.log" 2>&1 &
botd_pid=$!
for _ in $(seq 1 100); do curl -fsS -o /dev/null http://127.0.0.1:18732/healthz 2>/dev/null && break; sleep 0.1; done
curl -fsS -u ci:ci-password -H 'Content-Type: application/json' -d '{"name":"KeepEnc"}' http://127.0.0.1:18732/api/bots >/dev/null ||
  { cat "$T/botd.log" >&2; fail "botd didn't start on an encrypted database"; }
kill "$botd_pid"
wait "$botd_pid" 2>/dev/null || true
if plain_db "$ED/app.sqlite"; then fail "botd made a plain database with SUPERBOT_DATABASE_ENCRYPTION=required"; fi

SUPERBOT_BOTD=$BOTD "$BACKUP" --home "$EH" 2>/dev/null
mapfile -t enc < <(find "$EH/superbot/backups" -name 'superbot-*.tar.gz')
[[ ${#enc[@]} == 1 ]] || fail "no archive of the encrypted database"
mkdir "$T/enc-unpacked"
tar -xzf "${enc[0]}" -C "$T/enc-unpacked" ./app.sqlite 2>/dev/null || tar -xzf "${enc[0]}" -C "$T/enc-unpacked" app.sqlite
if plain_db "$T/enc-unpacked/app.sqlite"; then fail "the archive holds the database decrypted"; fi
refuses "backup failed" env SUPERBOT_BOTD="$BOTD" DATA_DIR="$ED" BACKUP_DIR="$T/enc-nokey" SUPERBOT_MASTER_KEY_FILE="$T/wrong.key" "$BACKUP"
refuses "botd isn't on PATH" env SUPERBOT_BOTD="$T/no-botd" DATA_DIR="$ED" BACKUP_DIR="$T/enc-nokey" "$BACKUP"
ok "superbot-backup copies an encrypted database with botd and the master key, still encrypted"

SUPERBOT_BOTD=$BOTD "$RESTORE" --home "$EH" --check "${enc[0]}" >"$T/check" 2>&1 || { cat "$T/check" >&2; fail "--check refused the encrypted archive"; }
grep -Eq '^bots: +[1-9]' "$T/check" && grep -q '^database: *encrypted' "$T/check" && grep -q '^needs master key: yes' "$T/check" ||
  { cat "$T/check" >&2; fail "--check summary of an encrypted database is wrong"; }
SUPERBOT_BOTD=$BOTD SUPERBOT_MASTER_KEY_FILE="$T/missing.key" "$RESTORE" --check "${enc[0]}" >"$T/check" 2>&1 ||
  { cat "$T/check" >&2; fail "--check without the master key refused the archive"; }
grep -q "wasn't checked here" "$T/check" && grep -q '^bots:  *?$' "$T/check" || { cat "$T/check" >&2; fail "--check without the key doesn't say it couldn't read it"; }
refuses "encrypted under another master key" env SUPERBOT_BOTD="$BOTD" SUPERBOT_MASTER_KEY_FILE="$T/wrong.key" "$RESTORE" --check "${enc[0]}"
refuses "could not check the encrypted app.sqlite" env SUPERBOT_BOTD="$BOTD" SUPERBOT_MASTER_KEY=not-a-key "$RESTORE" --check "${enc[0]}"
rm "$ED/app.sqlite"
SUPERBOT_BOTD=$BOTD "$RESTORE" --home "$EH" "${enc[0]}" 2>/dev/null
[[ $(SUPERBOT_MASTER_KEY_FILE="$EH/keys/master.key" "$BOTD" database query "$ED/app.sqlite" "SELECT name FROM bots WHERE name = 'KeepEnc'") == KeepEnc ]] ||
  fail "the restored database doesn't open with the master key"
ok "superbot-restore reads an encrypted database with the key, restores it unread without one, and refuses another key"

echo "All backup script checks passed"
