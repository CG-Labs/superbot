#!/usr/bin/env bash
# Seals a Hermes Agent install so every Bot on the host shares its one dependency
# environment (docs/adr/0072-one-hermes-environment-per-host.md):
#
#   deploy/hermes-seal.sh <home>
#
# <home> is the HOME Hermes's own installer ran with (it left <home>/.hermes/hermes-agent).
# Hermes keeps dependency state per data root (HERMES_HOME), and each Bot has its own, so
# each Bot's first run built its own environment: about 470 MiB and 20 CPU-seconds, and
# none at all for a Bot whose OS user doesn't own the install. Sealed, Hermes treats the
# install as it treats its own Docker image:
# - manifest.json beside the checkout names the environment the installer built, which
#   every data root then loads read-only (Hermes's sealed-payload layout);
# - the install stamp's updateMechanism is "external": the install is SuperBot's
#   installer's to update, so Hermes builds no environment per data root and doesn't
#   check GitHub for updates (once a day per Bot, through `gh` where it is installed).
# Then a run under a fresh data root must start without building anything.
# Safe to run again. Uses only what Hermes's installer left (its own Python).
set -euo pipefail

die() { printf 'hermes-seal: %s\n' "$*" >&2; exit 1; }

(( $# == 1 )) || die "usage: $0 <home>"
[[ -d "$1/.hermes/hermes-agent" ]] || die "$1 has no .hermes/hermes-agent: run Hermes's installer with HOME=$1 first"
home=$(cd "$1" && pwd -P)
data=$home/.hermes
launcher=$data/hermes-agent/.hermes/bin/hermes
[[ -x "$launcher" ]] || die "$launcher is missing"
# The launcher execs Hermes's own Python: `exec <python> -I -c '...'`.
python=$(sed -n 's/^exec \(\/[^ ]*python3[^ ]*\) .*/\1/p' "$launcher" | head -1)
[[ -n "$python" && -x "$python" ]] || die "can't find the Python $launcher runs"

"$python" -I - "$data" <<'PY'
import hashlib, json, os, sys
from pathlib import Path

data = Path(sys.argv[1])
checkout = data / "hermes-agent"

def fail(why):
    sys.exit(f"hermes-seal: {why}")

def write(path, value):
    tmp = path.with_name(f".{path.name}.seal-tmp")
    tmp.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
    os.chmod(tmp, 0o644)
    os.replace(tmp, path)

# Where Hermes's installer committed the environment (pm/environments.py: the state of
# an install is <root>/installs/<first 16 hex of sha256(checkout path)>/facts.json).
key = hashlib.sha256(str(checkout.resolve()).encode("utf-8")).hexdigest()[:16]
facts = data / "installs" / key / "facts.json"
try:
    venv = Path(json.loads(facts.read_text(encoding="utf-8"))["packages"]["venv"]["environment"]).resolve()
except (OSError, ValueError, KeyError, TypeError) as e:
    fail(f"no committed environment in {facts}: {e}")
if not venv.is_relative_to(data.resolve()) or not (venv / "pyvenv.cfg").is_file():
    fail(f"the committed environment {venv} isn't a venv under {data}")
write(data / "manifest.json", {"repo": "hermes-agent", "venv": str(venv.relative_to(data.resolve())), "store": "tools"})
# Each run leases a lease-managed environment by creating a file inside it, which a
# Bot's OS user can't (and shouldn't) do. A sealed install is never updated in place,
# so nothing collects its environment and the lease is moot: unmarked, it is skipped.
for name in (".lease-managed", ".leases"):
    path = venv.parent / name
    if path.is_dir():
        import shutil
        shutil.rmtree(path)
    elif path.exists():
        path.unlink()

stamp_path = checkout / "install-stamp.json"
try:
    stamp = json.loads(stamp_path.read_text(encoding="utf-8"))
except (OSError, ValueError) as e:
    fail(f"can't read {stamp_path}: {e}")
if stamp.get("updateMechanism") != "external":
    stamp["updateMechanism"] = "external"
    write(stamp_path, stamp)
PY

# A fresh data root, as a new Bot's, twice (the second start finds Hermes's own record
# of the first): it must start, build no environment of its own, write nothing into the
# shared one, and not check for updates.
probe=$(mktemp -d)
trap 'rm -rf "$probe"' EXIT
mkdir "$probe/home" "$probe/hermes"
venv=$(sed -n 's/.*"venv": "\(.*\)".*/\1/p' "$data/manifest.json")
for _ in 1 2; do
  out=$(env -i PATH=/usr/bin:/bin LANG=C.UTF-8 HOME="$probe/home" HERMES_HOME="$probe/hermes" \
    "$home/.local/bin/hermes" config path 2>&1) || die "a fresh data root can't start Hermes: $out"
done
if find "$probe/hermes" -path '*/installs/*' \( -name environments -o -name facts.json \) | grep -q .; then
  die "a fresh data root still builds its own environment"
fi
[[ ! -e "$data/$venv/../.leases" ]] || die "a run wrote into the shared environment"
[[ ! -e "$probe/hermes/source-checks" ]] || die "a fresh data root still checks for updates"
printf 'Sealed Hermes Agent in %s: Bots share %s\n' "$data" "$venv"
