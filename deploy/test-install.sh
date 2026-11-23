#!/usr/bin/env bash
# Fast checks of install.sh without root, systemd, Node, or a network: no early-exit readers in
# pipes, the web client archive check, unit template refusals, and the exit status when this
# run's web client is not installed. The full install path runs in .github/workflows/server.yml.
#   deploy/test-install.sh
set -euo pipefail

DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT

fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
ok() { printf 'ok - %s\n' "$*"; }

# Under pipefail, `cmd | grep -q` (or -m, or `| head`) fails whenever the reader exits before cmd
# has written everything, which depends on timing and size (#93). Use grep ... <<<"$(cmd)".
mapfile -t scripts < <(grep -l pipefail "$DIR"/*.sh "$DIR"/docker/*.sh "$DIR"/../.github/workflows/*.yml | grep -v '/test-install\.sh$')
early=$(grep -nE '\|[[:space:]]*(grep[[:space:]]([^|]*[[:space:]])?-([a-zA-Z]*[qm]|-quiet|-max-count)|head([[:space:]]|$))' "${scripts[@]}" || true)
[[ -z "$early" ]] || fail "a pipe can fail under pipefail when its reader exits early:"$'\n'"$early"
ok "no pipe ends in an early-exiting reader (${#scripts[@]} scripts)"

export SUPERBOT_INSTALL_NO_MAIN=1
# shellcheck source=install.sh
source "$DIR/install.sh"

# A web client build big enough that tar is still listing when index.html has been seen.
mkdir -p "$T/d/assets"
echo '<!doctype html>' >"$T/d/index.html"
seq -f "$T/d/assets/chunk-%05g.js" 1 20000 | xargs touch
echo x >"$T/evil"
ln -s /etc/passwd "$T/d/leak"
tar -C "$T/d" -cf "$T/big.tar" ./index.html ./assets
for _ in 1 2 3 4 5; do
  client_archive_ok "$T/big.tar" || fail "a big, valid web client build was refused"
done
ok "a big web client build passes the archive check every time"

tar -C "$T/d" -cf "$T/leak.tar" ./index.html ./leak ./assets
tar -C "$T/d" -cf "$T/noindex.tar" ./assets
# Bad names first and index.html last: an early-exiting grep used to skip the name check.
for name in ../evil /etc/evil; do
  tar -cf "$T/name.tar" --transform "s,^\./evil\$,$name," -C "$T" ./evil -C "$T/d" ./assets ./index.html 2>/dev/null
  [[ $(tar -tf "$T/name.tar" 2>/dev/null | sed -n 1p) == "$name" ]] || fail "could not make an archive holding $name"
  if client_archive_ok "$T/name.tar" 2>/dev/null; then fail "a build holding $name was accepted"; fi
done
for bad in leak noindex; do
  if client_archive_ok "$T/$bad.tar"; then fail "the $bad build was accepted"; fi
done
ok "builds with links, '..', absolute names, or no index.html are refused"

{
  printf '[Service]\nExecStartPre=/bin/sh -c id\n'
  seq -f '# filler %g' 1 20000
} >"$T/evil.service"
if (render_unit "$T/evil.service" "$T/out.service" "$(service_unit_fixed /home/superbot)") 2>"$T/err"; then
  fail "a long unit template with ExecStartPre was rendered"
fi
grep -q 'unexpected privileged directive' "$T/err" || { cat "$T/err" >&2; fail "render_unit did not refuse ExecStartPre"; }
[[ ! -e "$T/out.service" ]] || fail "render_unit wrote a refused unit"
ok "a long unit template with a privileged directive is refused"

# main with every system step stubbed out: only the web client steps, the summary, and the exit run.
cat >"$T/run.sh" <<'EOF'
set -euo pipefail
export SUPERBOT_INSTALL_NO_MAIN=1
source "$1"
shift
for f in need_root detect_source_dir ensure_user install_packages install_node install_rustup_user sync_repo \
  stage_trusted_deploy build_botd install_site configure_env ensure_master_key install_hermes install_systemd \
  install_backup install_caddy configure_ufw; do
  eval "$f() { :; }"
done
user_home() { printf '%s\n' "$TEST_HOME"; }
client_node_ok() { [[ $TEST_NODE == yes ]]; }
sudo() { [[ $TEST_BUILD == ok ]]; }
install_client() { [[ $TEST_INSTALL == ok ]]; }
main "$@"
EOF
mkdir -p "$T/home" "$T/app"
echo previous >"$T/app/index.html"
upgrade() { # node build install [flags...]
  local node=$1 build=$2 install=$3
  shift 3
  rc=0
  TEST_HOME="$T/home" TEST_NODE=$node TEST_BUILD=$build TEST_INSTALL=$install CLIENT_DIR="$T/app" \
    bash "$T/run.sh" "$DIR/install.sh" --upgrade --non-interactive --domain ci.example.com --tz UTC "$@" \
    >"$T/out" 2>"$T/err" || rc=$?
  grep -q 'SuperBot is installed.' "$T/out" || { cat "$T/out" "$T/err" >&2; fail "no summary (exit $rc)"; }
}
loud() { # message [app line]
  local app=${2:-"https://ci.example.com/app/ (still the previous web client: this run's was not installed)"}
  [[ $rc == 3 ]] || { cat "$T/out" "$T/err" >&2; fail "expected exit status 3 for '$1', got $rc"; }
  [[ $(tail -n 2 "$T/err" | sed -n 1p) == "!! $1. Everything else is installed, but /app/ still serves the previous web client, if any." ]] ||
    { cat "$T/err" >&2; fail "no final warning for '$1'"; }
  grep -qxF "  App:      $app" "$T/out" || { cat "$T/out" >&2; fail "the summary hides '$1'"; }
}
quiet() {
  [[ $rc == 0 ]] || { cat "$T/out" "$T/err" >&2; fail "expected exit status 0, got $rc"; }
  if grep -q 'Exiting with status' "$T/err"; then fail "a warning about the web client on a good run"; fi
}

upgrade yes ok ok
quiet
grep -qx '  App:      https://ci.example.com/app/' "$T/out" || fail "the summary has no app URL"
upgrade yes ok refused
loud "Web client not installed"
upgrade yes failed ok
loud "Web client build failed"
rm "$T/app/index.html"
upgrade yes ok refused
loud "Web client not installed" "not served (this run's web client was not installed)"
echo previous >"$T/app/index.html"
ok "a refused or failed web client ends the run with a final warning and exit status 3"

upgrade no ok ok
quiet
grep -q 'skipping the web client' "$T/err" || fail "no warning without Node"
upgrade yes failed refused --no-client
quiet
grep -q 'Skipping the web client (--no-client)' "$T/out" || fail "--no-client did not skip the web client"
ok "no Node or --no-client still exits 0"

# No free tier (ADR 0068): only --testing-mode writes TESTING_MODE=on, and the summary says so.
user_home() { echo "$T/home"; }
BACKUP_IDENTITY_FILE="$T/home-identity.txt"
mkdir -p "$T/home/superbot"
cp "$DIR/../.env.example" "$T/home/superbot/.env.example"
SUPERBOT_USER=$(id -un) DRY_RUN=false TESTING_MODE_ON=false configure_env >/dev/null
if grep -q '^TESTING_MODE=' "$T/home/superbot/.env"; then fail "testing mode was turned on without --testing-mode"; fi
parse_args --testing-mode
[[ "$TESTING_MODE_ON" == true ]] || fail "--testing-mode was not read"
SUPERBOT_USER=$(id -un) DRY_RUN=false configure_env >/dev/null
grep -qx 'TESTING_MODE=on' "$T/home/superbot/.env" || fail "--testing-mode did not set TESTING_MODE=on"
grep -q 'no free tier' <<<"$(usage)" || fail "the help doesn't say there's no free tier"
ok "--testing-mode, and only it, turns testing mode on"

# Off-host server backups (ADR 0109): an upgrade with no flags writes nothing and warns that
# backups stay on this host; the flags write the store, with keys from the environment only.
env_file="$T/home/superbot/.env"
before=$(cat "$env_file")
SUPERBOT_USER=$(id -un) DRY_RUN=false configure_env >/dev/null
[[ "$(grep -v '^TESTING_MODE=' "$env_file")" == "$(grep -v '^TESTING_MODE=' <<<"$before")" ]] || fail "an upgrade with no backup flags changed .env"
if grep -q '^SERVER_BACKUP_' "$env_file"; then fail "server backup settings were written without flags"; fi
[[ "$(backup_destination "$env_file")" == "on this host only (no store is set)" ]] || fail "no store, but: $(backup_destination "$env_file")"
grep -q 'Server backups stay on this host' <<<"$(DOMAIN=ci.example.com summary 2>&1)" || fail "the summary doesn't warn that backups stay on this host"
grep -qx '  Backups:  on this host only (no store is set) (botctl backups)' <<<"$(DOMAIN=ci.example.com summary 2>/dev/null)" || fail "the summary has no Backups line"
for bad in "--backup-s3-bucket b-1" "--backup-s3-endpoint https://s3.example.com" \
  "--backup-s3-bucket b-1 --backup-s3-endpoint http://s3.example.com" "--backup-s3-bucket B_1 --backup-s3-endpoint https://s3.example.com" \
  "--backup-age-recipients ssh-ed25519" "--backup-off-host maybe"; do
  # shellcheck disable=SC2086
  if (parse_args $bad && check_backup_target) 2>/dev/null; then fail "accepted $bad"; fi
done
age_key=age1qyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqs3290gq
parse_args --backup-s3-endpoint https://s3.example.com --backup-s3-bucket superbot-backups --backup-s3-region auto --backup-age-recipients "$age_key"
check_backup_target
if (SUPERBOT_USER=$(id -un) DRY_RUN=false configure_env) >/dev/null 2>"$T/err"; then fail "a store without keys was written"; fi
grep -q 'needs SERVER_BACKUP_S3_ACCESS_KEY_ID' "$T/err" || { cat "$T/err" >&2; fail "no word about the missing keys"; }
SERVER_BACKUP_S3_ACCESS_KEY_ID=AKIDCI SERVER_BACKUP_S3_SECRET_ACCESS_KEY=ci-secret-0123 SUPERBOT_USER=$(id -un) DRY_RUN=false configure_env >/dev/null
for line in SERVER_BACKUP_S3_ENDPOINT=https://s3.example.com SERVER_BACKUP_S3_BUCKET=superbot-backups SERVER_BACKUP_S3_REGION=auto \
  SERVER_BACKUP_S3_ACCESS_KEY_ID=AKIDCI SERVER_BACKUP_S3_SECRET_ACCESS_KEY=ci-secret-0123 "SUPERBOT_BACKUP_AGE_RECIPIENTS=$age_key"; do
  grep -qxF "$line" "$env_file" || fail ".env lacks $line"
done
if grep -q '^SERVER_BACKUP_S3_PREFIX=' "$env_file"; then fail "an unset prefix was written"; fi
[[ "$(backup_destination "$env_file")" == off-host ]] || fail "a store, but: $(backup_destination "$env_file")"
if grep -q 'Server backups stay on this host' <<<"$(DOMAIN=ci.example.com summary 2>&1)"; then fail "the summary warns with a store set"; fi
# A later upgrade with no flags keeps the store and its keys.
# shellcheck disable=SC2034 # read by install.sh's functions
BACKUP_S3_ENDPOINT="" BACKUP_S3_BUCKET="" BACKUP_S3_REGION="" BACKUP_AGE_RECIPIENTS=""
SUPERBOT_USER=$(id -un) DRY_RUN=false configure_env >/dev/null
grep -qxF SERVER_BACKUP_S3_SECRET_ACCESS_KEY=ci-secret-0123 "$env_file" || fail "an upgrade dropped the store's keys"
# A key kept in a file, then replaced from the environment: only the new key stays, as
# botd refuses a key set both ways.
unset_env_var "$env_file" SERVER_BACKUP_S3_SECRET_ACCESS_KEY
printf 'SERVER_BACKUP_S3_SECRET_ACCESS_KEY_FILE=/run/secrets/s3\n' >>"$env_file"
SERVER_BACKUP_S3_SECRET_ACCESS_KEY=ci-secret-4567 SUPERBOT_USER=$(id -un) DRY_RUN=false configure_env >/dev/null
grep -qxF SERVER_BACKUP_S3_SECRET_ACCESS_KEY=ci-secret-4567 "$env_file" || fail "the replacement key wasn't written"
if grep -q '^SERVER_BACKUP_S3_SECRET_ACCESS_KEY_FILE=' "$env_file"; then fail "the replaced key's _FILE was kept"; fi
grep -qxF SERVER_BACKUP_S3_ACCESS_KEY_ID=AKIDCI "$env_file" || fail "the other key was dropped"
parse_args --backup-off-host off
SUPERBOT_USER=$(id -un) DRY_RUN=false configure_env >/dev/null
[[ "$(backup_destination "$env_file")" == "on this host only (SERVER_BACKUP_OFF_HOST=off)" ]] || fail "off, but: $(backup_destination "$env_file")"
ok "off-host backups: nothing written without flags, the flags and keys written with them, and the gap warned about"

# Backup encryption (ADR 0114): a new install makes an age key and encrypts to it; an upgrade
# changes nothing unless asked; plain is a choice that's written down; required refuses plain.
command -v age-keygen >/dev/null || fail "these checks need age (apt-get install age)"
command -v sqlite3 >/dev/null || fail "these checks need sqlite3"
fresh_home() { # name: a home with no .env yet
  H="$T/$1"
  mkdir -p "$H/superbot"
  cp "$DIR/../.env.example" "$H/superbot/.env.example"
  user_home() { echo "$H"; }
  env_file="$H/superbot/.env"
}
# shellcheck disable=SC2034 # read by install.sh's functions
reset_flags() {
  BACKUP_S3_ENDPOINT="" BACKUP_S3_BUCKET="" BACKUP_S3_REGION="" BACKUP_S3_PREFIX="" BACKUP_AGE_RECIPIENTS="" BACKUP_OFF_HOST=""
  BACKUP_ENCRYPTION="" BACKUP_AGE_GENERATE=false NEW_BACKUP_IDENTITY_FILE="" DATABASE_ENCRYPTION=""
}
configure() { SUPERBOT_USER=$(id -un) DRY_RUN=false configure_env >/dev/null; }

reset_flags
fresh_home enc-new
BACKUP_IDENTITY_FILE="$T/enc-new-identity.txt"
configure
[[ -f "$BACKUP_IDENTITY_FILE" && $(stat -c %a "$BACKUP_IDENTITY_FILE") == 600 ]] || fail "a new install made no private backup key"
public=$(age-keygen -y "$BACKUP_IDENTITY_FILE")
grep -qxF "SUPERBOT_BACKUP_AGE_RECIPIENTS=$public" "$env_file" || fail "a new install doesn't encrypt to its key"
out=$(DOMAIN=ci.example.com summary 2>&1)
grep -qxF '  Encrypted: age (SUPERBOT_BACKUP_AGE_RECIPIENTS)' <<<"$out" || { echo "$out" >&2; fail "the summary doesn't say backups are encrypted"; }
grep -q "New backup key at $BACKUP_IDENTITY_FILE.*Copy it off this host now" <<<"$out" || fail "the summary doesn't say to copy the new key off the host"
if grep -q "aren't encrypted" <<<"$out"; then fail "the summary warns about plain backups with a key set"; fi
ok "a new install makes a private age key and encrypts backups to it"

# The key opens what superbot-backup writes with that .env; nothing else does.
before=$(cat "$env_file") key=$(sha256sum "$BACKUP_IDENTITY_FILE")
reset_flags
configure
[[ "$(cat "$env_file")" == "$before" && "$(sha256sum "$BACKUP_IDENTITY_FILE")" == "$key" ]] || fail "an upgrade changed the key or .env"
grep -q "backup key is still on this host" <<<"$(DOMAIN=ci.example.com summary 2>&1)" || fail "the summary doesn't say the key is still on the host"
mkdir -p "$H/superbot/data/bots/b1"
sqlite3 "$H/superbot/data/app.sqlite" "CREATE TABLE bots (id TEXT, name TEXT); INSERT INTO bots VALUES ('b1', 'KeepMe');"
PORT=1 "$DIR/superbot-backup.sh" --home "$H" 2>/dev/null
mapfile -t sealed < <(find "$H/superbot/backups" -name 'superbot-*.tar.gz.age')
[[ ${#sealed[@]} == 1 ]] || fail "superbot-backup didn't write an encrypted archive with the installer's .env"
if PORT=1 "$DIR/superbot-restore.sh" --check "${sealed[0]}" >/dev/null 2>&1; then fail "the archive opened without the key"; fi
grep -q '^bots:  *1$' <<<"$(PORT=1 "$DIR/superbot-restore.sh" --check --identity "$BACKUP_IDENTITY_FILE" "${sealed[0]}" 2>&1)" ||
  fail "the installer's key doesn't restore its archive"
ok "an upgrade keeps the key, and the key restores the archives superbot-backup encrypts to it"

# An install from before ADR 0114: upgrades make no key unless asked, and say backups are plain.
reset_flags
fresh_home enc-old
BACKUP_IDENTITY_FILE="$T/enc-old-identity.txt"
# Quoted-empty recipients are plain, as superbot-backup reads them.
printf 'AUTH_PASSWORD=x\nDATA_DIR=%s\nSUPERBOT_BACKUP_AGE_RECIPIENTS=%s\nSUPERBOT_BACKUP_AGE_RECIPIENTS_FILE=""\n' "$H/superbot/data" "''" >"$env_file"
cp "$env_file" "$T/enc-old.env"
configure
[[ ! -e "$BACKUP_IDENTITY_FILE" ]] || fail "an upgrade made a key without --backup-age-generate"
[[ "$(grep '^SUPERBOT_BACKUP_' "$env_file")" == "$(grep '^SUPERBOT_BACKUP_' "$T/enc-old.env")" ]] || fail "an upgrade changed backup encryption settings without flags"
out=$(DOMAIN=ci.example.com summary 2>&1)
grep -qxF '  Encrypted: plain (no SUPERBOT_BACKUP_AGE_RECIPIENTS)' <<<"$out" || fail "the summary doesn't say backups are plain"
grep -q "Server backups aren't encrypted.*--backup-age-generate" <<<"$out" || fail "the summary doesn't warn about plain backups"
parse_args --backup-encryption required
check_backup_target
if (configure) 2>"$T/err"; then fail "required was accepted with no recipients"; fi
grep -q 'SUPERBOT_BACKUP_ENCRYPTION=required, but' "$T/err" || { cat "$T/err" >&2; fail "no word about required"; }
reset_flags
parse_args --backup-age-generate --backup-encryption required
check_backup_target
configure
grep -qxF "SUPERBOT_BACKUP_AGE_RECIPIENTS=$(age-keygen -y "$BACKUP_IDENTITY_FILE")" "$env_file" || fail "--backup-age-generate didn't encrypt to a new key"
grep -qxF 'SUPERBOT_BACKUP_ENCRYPTION=required' "$env_file" || fail "--backup-encryption wasn't written"
[[ $(grep -c '^SUPERBOT_BACKUP_AGE_RECIPIENTS=' "$env_file") == 1 ]] || fail "--backup-age-generate left the empty recipients line"
ok "upgrades make a key only with --backup-age-generate, and required refuses plain"

reset_flags
fresh_home enc-off
BACKUP_IDENTITY_FILE="$T/enc-off-identity.txt"
parse_args --backup-encryption off
check_backup_target
configure
[[ ! -e "$BACKUP_IDENTITY_FILE" ]] || fail "--backup-encryption off made a key"
grep -qxF 'SUPERBOT_BACKUP_ENCRYPTION=off' "$env_file" || fail "--backup-encryption off wasn't written"
out=$(DOMAIN=ci.example.com summary 2>&1)
grep -qxF '  Encrypted: plain by choice (SUPERBOT_BACKUP_ENCRYPTION=off)' <<<"$out" || fail "the summary doesn't say plain is a choice"
if grep -q "aren't encrypted" <<<"$out"; then fail "plain by choice still warns"; fi
# Without age-keygen, a new install still finishes, plain, and says so.
reset_flags
fresh_home enc-noage
BACKUP_IDENTITY_FILE="$T/enc-noage-identity.txt"
(age-keygen() { return 127; } && configure) 2>"$T/err" || { cat "$T/err" >&2; fail "a new install without age failed"; }
grep -q 'Could not make a backup age key' "$T/err" || fail "no word that the key couldn't be made"
if grep -q '^SUPERBOT_BACKUP_AGE_RECIPIENTS=' "$env_file"; then fail "recipients were written without a key"; fi
for bad in "--backup-encryption maybe" "--backup-age-generate --backup-encryption off" \
  "--backup-age-generate --backup-age-recipients age1qyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqs3290gq"; do
  reset_flags
  # shellcheck disable=SC2086
  if (parse_args $bad && check_backup_target) 2>/dev/null; then fail "accepted $bad"; fi
done
ok "plain by choice is written and said, a host without age still installs, and contradictory flags are refused"

# Database encryption (ADR 0116): a new install requires it; an upgrade changes nothing unless
# asked, and says when the database is plain; the flag is written as given.
reset_flags
fresh_home db-new
BACKUP_IDENTITY_FILE="$T/db-new-identity.txt"
configure
grep -qxF 'SUPERBOT_DATABASE_ENCRYPTION=required' "$env_file" || fail "a new install doesn't require database encryption"
out=$(DOMAIN=ci.example.com summary 2>&1)
grep -qxF '  Database: encrypted when botd starts (SUPERBOT_DATABASE_ENCRYPTION=required) (botctl database)' <<<"$out" ||
  { echo "$out" >&2; fail "the summary doesn't say the database will be encrypted"; }
grep -q 'encrypts the database and saved secrets' <<<"$out" || fail "the summary doesn't say the master key encrypts the database"
mkdir -p "$H/superbot/data"
head -c 8192 /dev/urandom >"$H/superbot/data/app.sqlite"
grep -qxF '  Database: encrypted (SQLCipher, key derived from the master key) (botctl database)' <<<"$(DOMAIN=ci.example.com summary 2>&1)" ||
  fail "the summary doesn't see an encrypted database"
db_has_sealed_values "$H/superbot/data/app.sqlite" || fail "an encrypted database wasn't taken to need the master key"
ok "a new install requires database encryption, and an encrypted database needs the master key"

reset_flags
fresh_home db-old
BACKUP_IDENTITY_FILE="$T/db-old-identity.txt"
mkdir -p "$H/superbot/data"
printf 'AUTH_PASSWORD=x\nDATA_DIR=%s\nSUPERBOT_BACKUP_ENCRYPTION=off\n' "$H/superbot/data" >"$env_file"
sqlite3 "$H/superbot/data/app.sqlite" "CREATE TABLE bots (id TEXT); INSERT INTO bots VALUES ('b1');"
configure
if grep -q '^SUPERBOT_DATABASE_ENCRYPTION=' "$env_file"; then fail "an upgrade set database encryption without the flag"; fi
out=$(DOMAIN=ci.example.com summary 2>&1)
grep -qxF '  Database: plain (SUPERBOT_DATABASE_ENCRYPTION=auto) (botctl database)' <<<"$out" || { echo "$out" >&2; fail "the summary doesn't say the database is plain"; }
grep -q "The database isn't encrypted.*--database-encryption required" <<<"$out" || fail "the summary doesn't warn about a plain database"
parse_args --database-encryption required
check_backup_target
out=$(SUPERBOT_USER=$(id -un) DRY_RUN=false configure_env 2>&1)
grep -qxF 'SUPERBOT_DATABASE_ENCRYPTION=required' "$env_file" || fail "--database-encryption required wasn't written"
grep -q 'botd encrypts it when it starts, keeping a plain copy' <<<"$out" || fail "no word that botd encrypts the plain database"
touch "$H/superbot/data/app.sqlite-plain-20260101-000000"
grep -q "A plain copy of the database is still beside it: $H/superbot/data/app.sqlite-plain-20260101-000000" <<<"$(DOMAIN=ci.example.com summary 2>&1)" ||
  fail "the summary doesn't warn about the plain copy"
reset_flags
parse_args --database-encryption off
configure
grep -qxF 'SUPERBOT_DATABASE_ENCRYPTION=off' "$env_file" || fail "--database-encryption off wasn't written"
out=$(DOMAIN=ci.example.com summary 2>&1)
grep -qxF '  Database: plain by choice (SUPERBOT_DATABASE_ENCRYPTION=off) (botctl database)' <<<"$out" || fail "the summary doesn't say plain is a choice"
if grep -q "The database isn't encrypted" <<<"$out"; then fail "a plain database by choice still warns"; fi
reset_flags
if (parse_args --database-encryption maybe && check_backup_target) 2>/dev/null; then fail "accepted --database-encryption maybe"; fi
grep -q -- '--database-encryption auto|required|off' <<<"$(usage)" || fail "the help has no --database-encryption"
ok "upgrades keep the database setting unless asked, warn when it's plain, and write the flag as given"

# --source-dir (and any separate checkout, picked up on its own) syncs over the live install
# with rsync --delete: runtime state must survive it, neither deleted nor overwritten.
command -v rsync >/dev/null || fail "these checks need rsync"
src="$T/src" H="$T/live"
live="$H/superbot"
user_home() { echo "$H"; }
mkdir -p "$src/server/src" "$src/data" "$live/.git" "$live/server/src"
echo '[workspace]' >"$src/Cargo.toml"
echo 'fn main() {}' >"$src/server/src/main.rs"
echo 'NEW=1' >"$src/.env.example"
echo 'AUTH_PASSWORD=checkout' >"$src/.env"
echo checkout >"$src/data/app.sqlite"
echo 'fn old() {}' >"$live/server/src/old.rs"
echo 'OLD_SETTING=1' >"$live/.env.example"
state=(.env.local data/app.sqlite data/license.key data/evidence/b.tar workspace/users/u1/notes.md
  backups/superbot-20260101T000000Z.tar.gz.age license/license.key config/tiers.json metrics-token)
put_state() { local f; for f in "${state[@]}"; do mkdir -p "$(dirname "$live/$f")" && echo "live $f" >"$live/$f"; done; }
put_state
printf 'AUTH_PASSWORD=live\nDATA_DIR=%s\nWORKSPACE_DIR=./workspace\nLICENSE_KEY_FILE="%s"\nTIERS_FILE=config/tiers.json\n' \
  "$live/data" "$live/license/license.key" >"$live/.env"
sync_live() { (INSTALL_DIR=$src OFFLINE_BUNDLE="" DRY_RUN=false sync_repo) >/dev/null 2>"$T/err" || { cat "$T/err" >&2; fail "sync_repo failed"; }; }
survives() {
  local f
  for f in "${state[@]}"; do
    [[ "$(cat "$live/$f" 2>/dev/null)" == "live $f" ]] || fail "--source-dir deleted or overwrote $f"
  done
  grep -qx 'AUTH_PASSWORD=live' "$live/.env" || fail "--source-dir overwrote .env"
}
sync_live
survives
[[ "$(cat "$live/.env.example")" == NEW=1 && -f "$live/server/src/main.rs" ]] || fail "--source-dir didn't copy the checkout"
[[ ! -e "$live/server/src/old.rs" ]] || fail "--source-dir no longer removes files the checkout dropped"
# DATA_DIR moved inside the install folder, with botd's default BACKUP_DIR beside it.
printf 'DATA_DIR=./state/data\n' >>"$live/.env"
state+=(state/data/app.sqlite state/backups/superbot-20260102T000000Z.tar.gz)
put_state
sync_live
survives
# A quoted value keeps the quotes inside it, and a file reached through a linked folder keeps
# the link, even when the link leads outside the install folder.
mkdir -p "$T/outside" && echo outside >"$T/outside/plans.json" && ln -s "$T/outside" "$live/linked"
printf "TIERS_FILE=\"./config/customer's.json\"\nMACHINE_MIRROR_CA_FILE=./linked/plans.json\n" >>"$live/.env"
state+=("config/customer's.json")
put_state
sync_live
survives
[[ -L "$live/linked" && "$(cat "$live/linked/plans.json")" == outside ]] || fail "--source-dir removed the link to a configured file"
# A first sync, onto a folder with no .git yet, doesn't overwrite either.
rm -rf "$live/.git"
sync_live
survives
printf 'EVIDENCE_DIR=%s/\n' "$live" >>"$live/.env"
if (INSTALL_DIR=$src OFFLINE_BUNDLE="" DRY_RUN=false sync_repo) >/dev/null 2>"$T/err"; then fail "a setting pointing at the install folder itself was synced over"; fi
grep -q 'which --source-dir syncs over' "$T/err" || { cat "$T/err" >&2; fail "no word about the setting at the install folder"; }
ok "--source-dir keeps .env, data, the workspace, backups and every state path .env names inside the install"

echo "all install checks passed"
