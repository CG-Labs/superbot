#!/usr/bin/env bash
# Tests deploy/hermes-shared.sh and deploy/hermes-seal.sh with a fake Hermes installer
# (ADR 0072): an install is sealed, upgrades switch in one rename, a run that started on
# the old version finishes on it, the previous version stays and older ones go, a cut-short
# install starts again, and a bad checksum installs nothing. No network, no root.
#
#   deploy/test-hermes-shared.sh
set -euo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
pass() { printf 'ok: %s\n' "$*"; }
python=$(command -v python3) || fail "needs python3"

# What Hermes's installer leaves, in miniature: a checkout whose launcher execs a Python,
# a committed environment with its record, the install stamp, and ~/.local/bin/hermes.
installer=$work/install.sh
cat >"$installer" <<EOF
#!/usr/bin/env bash
set -euo pipefail
commit=\${*: -1}
data=\$HOME/.hermes
checkout=\$data/hermes-agent
key=\$(printf '%s' "\$(cd "\$HOME" && pwd -P)/.hermes/hermes-agent" | sha256sum | cut -c1-16)
gen=\$data/installs/\$key/environments/g1
mkdir -p "\$checkout/.hermes/bin" "\$gen/venv" "\$gen/.leases" "\$HOME/.local/bin"
: >"\$gen/.lease-managed"
: >"\$gen/venv/pyvenv.cfg"
printf '%s\n' "\$commit" >"\$checkout/VERSION"
printf '{"packages": {"venv": {"environment": "%s"}}}\n' "\$gen/venv" >"\$data/installs/\$key/facts.json"
printf '{"commit": "%s", "updateMechanism": "self"}\n' "\$commit" >"\$checkout/install-stamp.json"
cat >"\$checkout/.hermes/bin/hermes" <<'LAUNCHER'
#!/bin/sh
exec $python -I -c '
import json, os, pathlib, sys, time
launcher, args = sys.argv[1], sys.argv[2:]
checkout = pathlib.Path(launcher).resolve().parents[2]
stamp = json.loads((checkout / "install-stamp.json").read_text())
home = pathlib.Path(os.environ["HERMES_HOME"])
if stamp["updateMechanism"] != "external" or not (checkout.parent / "manifest.json").is_file():
    (home / "installs" / "own" / "environments").mkdir(parents=True, exist_ok=True)
if args == ["config", "path"]:
    print(home / "config.yaml")
elif args[0] == "slow":
    time.sleep(float(args[1]))
    print((checkout / "VERSION").read_text().strip())
' "\$0" "\$@"
LAUNCHER
chmod +x "\$checkout/.hermes/bin/hermes"
printf '#!/bin/sh\nexec %s "\$@"\n' "\$checkout/.hermes/bin/hermes" >"\$HOME/.local/bin/hermes"
chmod +x "\$HOME/.local/bin/hermes"
EOF
export HERMES_INSTALLER=$installer
sum=$(sha256sum "$installer" | cut -d' ' -f1)
a=$(printf 'a%.0s' {1..40}) b=$(printf 'b%.0s' {1..40}) c=$(printf 'c%.0s' {1..40})
dir=$work/opt/hermes
run() { env -i PATH=/usr/bin:/bin HOME="$work" HERMES_HOME="$work/bot" "$dir/current/.local/bin/hermes" "$@"; }

launcher=$("$here/hermes-shared.sh" "$dir" "$a" "$sum" 2>/dev/null)
[[ "$launcher" == "$dir/current/.local/bin/hermes" ]] || fail "prints the launcher, not $launcher"
[[ "$(readlink "$dir/current")" == "$a" ]] || fail "current is $a"
grep -q '"updateMechanism": "external"' "$dir/$a/.hermes/hermes-agent/install-stamp.json" || fail "the stamp is external"
grep -q '"venv": "installs/.*/environments/g1/venv"' "$dir/$a/.hermes/manifest.json" || fail "the manifest names the environment"
if compgen -G "$dir/$a/.hermes/installs/*/environments/g1/.lease*" >/dev/null; then fail "the environment isn't lease-managed"; fi
mkdir -p "$work/bot"
[[ "$(run slow 0)" == "$a" ]] && [[ ! -e "$work/bot/installs" ]] || fail "a Bot runs the shared install, building nothing"
pass "installs, seals and switches to $a"

# A run on $a is mid-way when $b is installed.
run slow 2 >"$work/mid-run" &
mid=$!
sleep 0.3
"$here/hermes-shared.sh" "$dir" "$b" "$sum" >/dev/null 2>&1
[[ "$(readlink "$dir/current")" == "$b" && "$(run slow 0)" == "$b" ]] || fail "new runs start on $b"
wait "$mid"
[[ "$(cat "$work/mid-run")" == "$a" ]] || fail "the run that started on $a finished on it, not $(cat "$work/mid-run")"
[[ -d "$dir/$a" ]] || fail "the previous version stays"
pass "switches to $b; a run on $a finishes on $a"

"$here/hermes-shared.sh" "$dir" "$c" "$sum" >/dev/null 2>&1
[[ ! -e "$dir/$a" && -d "$dir/$b" && "$(readlink "$dir/current")" == "$c" ]] || fail "keeps $b, removes $a"
before=$(stat -c %Y "$dir/$c/.hermes/hermes-agent/VERSION")
sleep 1
"$here/hermes-shared.sh" "$dir" "$c" "$sum" >/dev/null 2>&1
[[ "$(stat -c %Y "$dir/$c/.hermes/hermes-agent/VERSION")" == "$before" ]] || fail "an installed version isn't installed again"
pass "keeps one previous version; an installed one is kept"

rm "$dir/$b/.superbot-sealed"
"$here/hermes-shared.sh" "$dir" "$b" "$sum" >/dev/null 2>&1
[[ -f "$dir/$b/.superbot-sealed" && "$(readlink "$dir/current")" == "$b" ]] || fail "a cut-short install starts again"
pass "a cut-short install starts again"

if "$here/hermes-shared.sh" "$dir" "$a" "$(printf '0%.0s' {1..64})" >/dev/null 2>&1; then fail "a bad checksum installs"; fi
[[ "$(readlink "$dir/current")" == "$b" ]] || fail "a bad checksum leaves current alone"
pass "a bad checksum installs nothing"

# The layout before versions: the install straight in the folder, kept until a switch.
legacy=$work/legacy
mkdir -p "$legacy/.hermes/hermes-agent" "$legacy/.local/bin"
"$here/hermes-shared.sh" "$legacy" "$a" "$sum" >/dev/null 2>&1
[[ -d "$legacy/.hermes" ]] || fail "the unversioned install stays while runs may use it"
"$here/hermes-shared.sh" "$legacy" "$b" "$sum" >/dev/null 2>&1
[[ ! -e "$legacy/.hermes" && ! -e "$legacy/.local" ]] || fail "the unversioned install goes after a switch"
pass "the unversioned install is removed after a switch"
