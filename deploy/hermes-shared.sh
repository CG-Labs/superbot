#!/usr/bin/env bash
# Installs Hermes Agent once per host, for every Bot on it to share
# (docs/adr/0072-one-hermes-environment-per-host.md):
#
#   deploy/hermes-shared.sh <dir> <commit> [<installer sha256>]
#
# Runs Hermes's own installer at <commit> with HOME=<dir>/<commit>, seals that install
# (deploy/hermes-seal.sh: one dependency environment for every data root, no update
# checks), then points <dir>/current at it in one rename. Hermes's launcher and
# environment name their own folder, so a run that started on the old version finishes
# on it; the next run starts on the new one. The previous version stays for runs still
# on it; older ones are removed. A version already installed and sealed is kept.
#
# Every Bot runs <dir>/current/.local/bin/hermes, printed last. The caller decides who
# owns <dir> (root, on a server) and links the launcher onto PATH.
# HERMES_INSTALLER=<file> uses that installer instead of downloading it (tests).
set -euo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
die() { printf 'hermes-shared: %s\n' "$*" >&2; exit 1; }
log() { printf 'hermes-shared: %s\n' "$*" >&2; }

(( $# == 2 || $# == 3 )) || die "usage: $0 <dir> <commit> [<installer sha256>]"
commit=$2
want=${3:-}
[[ "$commit" =~ ^[0-9a-f]{40}$ ]] || die "Hermes takes a full commit, not $commit"
[[ -z "$want" || "$want" =~ ^[0-9a-f]{64}$ ]] || die "the installer's SHA-256 must be 64 hex digits"
mkdir -p "$1"
dir=$(cd "$1" && pwd -P)
home=$dir/$commit
sealed=$home/.superbot-sealed

# One install at a time per folder.
exec 9>"$dir/.lock"
command -v flock >/dev/null && { flock -w 3600 9 || die "another install in $dir didn't finish within an hour"; }

previous=$(readlink "$dir/current" 2>/dev/null || true)

if [[ ! -f "$sealed" ]]; then
  # A folder without the mark is an install that was cut short: start it again.
  rm -rf "$home"
  mkdir -p "$home"
  script=$dir/.installer-$commit.sh
  trap 'rm -f "$script"' EXIT
  if [[ -n "${HERMES_INSTALLER:-}" ]]; then
    cp "$HERMES_INSTALLER" "$script"
  else
    url="https://raw.githubusercontent.com/NousResearch/hermes-agent/$commit/scripts/install.sh"
    curl -fsSL --retry 3 "$url" -o "$script" || die "couldn't download $url"
  fi
  if [[ -n "$want" ]]; then
    printf '%s  %s\n' "$want" "$script" | sha256sum -c --quiet - || die "Hermes's installer doesn't match the pinned SHA-256"
  fi
  log "installing Hermes Agent ${commit:0:12} in $home"
  env -i HOME="$home" SHELL=/bin/bash LANG=C.UTF-8 PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    bash "$script" --non-interactive --skip-browser --skip-computer-use --commit "$commit" >"$home/.install.log" 2>&1 \
    || { tail -40 "$home/.install.log" >&2; die "Hermes Agent ${commit:0:12} didn't install"; }
fi
# Sealing again is cheap and picks up a newer seal.
bash "$here/hermes-seal.sh" "$home" >&2
: >"$sealed"

relink() {
  ln -sfn "$1" "$dir/.$2-tmp"
  mv -T "$dir/.$2-tmp" "$dir/$2"
}
if [[ "$previous" != "$commit" ]]; then
  [[ -z "$previous" ]] || relink "$previous" previous
  relink "$commit" current
  log "Bots now start Hermes Agent ${commit:0:12}${previous:+ (was ${previous:0:12})}"
fi

# Keep this version and the one before it, which runs may still be on; remove the rest.
# The layout before versions (the install straight in <dir>) is the one before until a
# second switch.
keep=$(readlink "$dir/previous" 2>/dev/null || true)
for d in "$dir"/*/; do
  name=$(basename "$d")
  [[ "$name" =~ ^[0-9a-f]{40}$ && "$name" != "$commit" && "$name" != "$keep" ]] || continue
  log "removing Hermes Agent ${name:0:12}"
  rm -rf "$d"
done
if [[ -n "$keep" && -d "$dir/.hermes" ]]; then
  log "removing the unversioned install in $dir"
  rm -rf "$dir/.hermes" "$dir/.local" "$dir/.cache" "$dir/.bashrc" "$dir/.profile"
fi

printf '%s\n' "$dir/current/.local/bin/hermes"
