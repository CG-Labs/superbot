#!/usr/bin/env bash
# Installs harness CLIs at the versions SuperBot pins for machines
# (server/src/adapters/install.rs), for the harness end-to-end tests (ADR 0057).
#
#   deploy/install-harness-clis.sh <prefix> [claude] [codex] [pi] [hermes]
#
# Each npm CLI goes to <prefix>/<bin>/node_modules/.bin, checked against the pinned
# integrity (one prefix each: npm prunes what a prefix's package.json doesn't list).
# Hermes Agent goes under <prefix>/hermes as its HOME, from its installer at the pinned
# commit, checked against the pinned SHA-256; deploy/hermes-share.sh then makes its one
# environment every Bot's and leaves the hermes they run in <prefix>/hermes/.hermes/superbot.
# HARNESS_VERSION_<BIN> (e.g. HARNESS_VERSION_CODEX=0.141.0) installs another version;
# npm still checks the registry's hashes, but there is no pin to compare with.
# Prints the PATH entries to add, one per line, last.
set -euo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
pins="$here/../server/src/adapters/install.rs"

die() { printf 'install-harness-clis: %s\n' "$*" >&2; exit 1; }

# Downloads fail now and then; try three times.
retry() {
  local n
  for n in 1 2 3; do
    "$@" && return 0
    (( n < 3 )) && { printf 'install-harness-clis: attempt %s failed, retrying\n' "$n" >&2; sleep $(( n * 5 )); }
  done
  return 1
}

# The value of `field` in the pin whose `bin` is $1.
pin() {
  local v
  v=$(awk -v bin="$1" -v field="$2" '
    index($0, "bin: \"" bin "\"") { found = 1 }
    found && index($0, field ": \"") { sub(".*" field ": \"", ""); sub("\".*", ""); print; exit }
  ' "$pins")
  [[ -n "$v" ]] || die "no $2 for $1 in $pins"
  printf '%s\n' "$v"
}

(( $# >= 2 )) || die "usage: $0 <prefix> claude|codex|pi|hermes ..."
prefix=$1
shift
mkdir -p "$prefix"
prefix=$(cd "$prefix" && pwd)
paths=()

for bin in "$@"; do
  override_var="HARNESS_VERSION_${bin^^}"
  version=$(pin "$bin" version)
  pinned=1
  if [[ -n "${!override_var:-}" && "${!override_var}" != "$version" ]]; then
    version=${!override_var}
    pinned=0
  fi
  case "$bin" in
    claude|codex|pi)
      package=$(pin "$bin" package)
      if (( pinned )); then
        want=$(pin "$bin" integrity)
        got=$(npm view "$package@$version" dist.integrity)
        [[ "$got" == "$want" ]] || die "$package@$version: the registry has $got, the pin says $want"
      fi
      printf 'Installing %s@%s\n' "$package" "$version"
      mkdir -p "$prefix/$bin"
      retry npm install --prefix "$prefix/$bin" --no-audit --no-fund --no-save --loglevel=error "$package@$version" >/dev/null
      exe="$prefix/$bin/node_modules/.bin/$bin"
      grep -Fq "$version" <<<"$("$exe" --version)" || die "$exe --version isn't $version"
      paths+=("$prefix/$bin/node_modules/.bin")
      ;;
    hermes)
      [[ "$version" =~ ^[0-9a-f]{40}$ ]] || die "Hermes takes a full commit, not $version"
      home="$prefix/hermes"
      mkdir -p "$home"
      script="$prefix/hermes-install.sh"
      retry curl -fsSL "https://raw.githubusercontent.com/NousResearch/hermes-agent/$version/scripts/install.sh" -o "$script"
      if (( pinned )); then
        printf '%s  %s\n' "$(pin hermes sha256)" "$script" | sha256sum -c --quiet - || die "Hermes's installer doesn't match the pinned SHA-256"
      fi
      printf 'Installing Hermes Agent %s\n' "${version:0:12}"
      retry env HOME="$home" bash "$script" --non-interactive --skip-browser --skip-computer-use --commit "$version" >"$prefix/hermes-install.log" 2>&1 \
        || { tail -40 "$prefix/hermes-install.log" >&2; die "Hermes Agent didn't install"; }
      wrapper=$(HOME="$home" sh "$here/hermes-share.sh") || die "couldn't share Hermes Agent's environment"
      HOME="$home" "$wrapper" --version >/dev/null || die "hermes --version failed"
      paths+=("$(dirname "$wrapper")")
      ;;
    *) die "unknown harness $bin: use claude, codex, pi or hermes" ;;
  esac
done

printf '%s\n' "${paths[@]}"
