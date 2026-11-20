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
  grep -qF "$msg" "$T/out" || { cat "$T/out" >&2; fail "expected '$msg' from: $*"; }
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
tar -tzf "$(find "$B" -name 'superbot-*.tar.gz')" | grep -qx app.sqlite || fail "the kept archive is unreadable"
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
if tar -tzf "$T/again.tar.gz" | grep -q -e '\.pre-restore-' -e '\.restore-'; then fail "a backup carried restore leftovers"; fi
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

echo "All backup script checks passed"
