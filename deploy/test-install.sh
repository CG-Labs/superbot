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

echo "all install checks passed"
