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
loud() { # message
  [[ $rc == 3 ]] || { cat "$T/out" "$T/err" >&2; fail "expected exit status 3 for '$1', got $rc"; }
  [[ $(tail -n 2 "$T/err" | sed -n 1p) == "!! $1. Everything else is installed, but /app/ still serves the previous web client, if any." ]] ||
    { cat "$T/err" >&2; fail "no final warning for '$1'"; }
  grep -qF 'App:      https://ci.example.com/app/ (still the previous web client' "$T/out" || { cat "$T/out" >&2; fail "the summary hides '$1'"; }
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
ok "a refused or failed web client ends the upgrade with a final warning and exit status 3"

upgrade no ok ok
quiet
grep -q 'skipping the web client' "$T/err" || fail "no warning without Node"
upgrade yes failed refused --no-client
quiet
grep -q 'Skipping the web client (--no-client)' "$T/out" || fail "--no-client did not skip the web client"
ok "no Node or --no-client still exits 0"

echo "all install checks passed"
