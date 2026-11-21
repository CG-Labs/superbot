#!/usr/bin/env bash
# Hermes Agent's pin, under ADR 0011's supported-version policy (ADR 0075): stable
# release tags only, never a canary, and every bump goes through the test suite.
#
#   deploy/hermes-pin.sh show           the pin: tag, commit, installer SHA-256
#   deploy/hermes-pin.sh latest         the newest stable release upstream
#   deploy/hermes-pin.sh verify         checks upstream that the pinned commit is the
#                                       pinned tag's, that tag a stable release, and the
#                                       installer at it the pinned SHA-256; warns when a
#                                       newer stable release is out
#   deploy/hermes-pin.sh bump [TAG]     moves the pin to TAG (default: latest) in
#                                       server/src/adapters/install.rs, the Dockerfile,
#                                       deploy/install.sh and the docs that name it
#   deploy/hermes-pin.sh test DIR [--footprint]
#                                       installs the pin under DIR and runs the Hermes
#                                       hook tests against it (and the footprint), as
#                                       the harness-e2e workflow does
#
# Needs curl, git, jq and sha256sum. GITHUB_TOKEN, if set, goes to GitHub's API.
set -euo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repo=$(cd "$here/.." && pwd)
pins="$repo/server/src/adapters/install.rs"
upstream=NousResearch/hermes-agent

die() { printf 'hermes-pin: %s\n' "$*" >&2; exit 1; }
say() { printf 'hermes-pin: %s\n' "$*"; }
warn() {
  if [[ -n "${GITHUB_ACTIONS:-}" ]]; then printf '::warning::%s\n' "$*"; else printf 'hermes-pin: warning: %s\n' "$*" >&2; fi
}

# The value of `field` in the hermes pin.
pin() {
  local v
  v=$(awk -v field="$1" '
    index($0, "bin: \"hermes\"") { found = 1 }
    found && index($0, field ": \"") { sub(".*" field ": \"", ""); sub("\".*", ""); print; exit }
  ' "$pins")
  [[ -n "$v" ]] || die "no hermes $1 in $pins"
  printf '%s\n' "$v"
}

api() {
  local auth=()
  [[ -n "${GITHUB_TOKEN:-}" ]] && auth=(-H "Authorization: Bearer $GITHUB_TOKEN")
  curl -fsSL --retry 3 -H 'Accept: application/vnd.github+json' "${auth[@]}" "https://api.github.com/repos/$upstream/$1"
}

# Stable tags are vMAJOR.MINOR.PATCH; canaries carry +canary.<time>.
stable_name() { [[ "$1" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; }

# Fails unless $1 is a published, non-prerelease GitHub release with a stable name.
check_stable() {
  stable_name "$1" || die "$1 isn't a stable tag (vMAJOR.MINOR.PATCH); canaries are never pinned"
  api "releases/tags/$1" | jq -e '.draft == false and .prerelease == false' >/dev/null \
    || die "$1 isn't a published stable release of $upstream"
}

latest() {
  local tag
  tag=$(api releases/latest | jq -r .tag_name)
  stable_name "$tag" || die "upstream's latest release, $tag, isn't a stable tag"
  printf '%s\n' "$tag"
}

# The commit tag $1 points at (an annotated tag's target, not the tag object).
commit_of() {
  local refs commit
  refs=$(git ls-remote "https://github.com/$upstream" "refs/tags/$1" "refs/tags/$1^{}") || die "couldn't list $upstream's tags"
  commit=$(awk -v t="refs/tags/$1^{}" '$2 == t { print $1 }' <<<"$refs")
  [[ -n "$commit" ]] || commit=$(awk -v t="refs/tags/$1" '$2 == t { print $1 }' <<<"$refs")
  [[ "$commit" =~ ^[0-9a-f]{40}$ ]] || die "no tag $1 in $upstream"
  printf '%s\n' "$commit"
}

installer_sha() {
  curl -fsSL --retry 3 "https://raw.githubusercontent.com/$upstream/$1/scripts/install.sh" | sha256sum | cut -d' ' -f1
}

# Replaces the literal $2 with $3 in file $1; fails if $2 isn't there.
swap() {
  local file=$1 from=$2 to=$3
  grep -qF -- "$from" "$file" || die "\"$from\" isn't in ${file#"$repo"/}"
  FROM=$from TO=$to perl -0pi -e 's/\Q$ENV{FROM}\E/$ENV{TO}/g' "$file"
}

show() {
  printf 'tag     %s\ncommit  %s\nsha256  %s\n' "$(pin tag)" "$(pin version)" "$(pin sha256)"
}

verify() {
  local tag commit sha want newest
  tag=$(pin tag)
  commit=$(pin version)
  sha=$(pin sha256)
  check_stable "$tag"
  want=$(commit_of "$tag")
  [[ "$want" == "$commit" ]] || die "the pin says $tag is $commit, but upstream's $tag is $want"
  [[ "$(installer_sha "$commit")" == "$sha" ]] || die "scripts/install.sh at $tag doesn't match the pinned SHA-256"
  say "pinned to $tag ($commit), a stable release; its installer matches"
  newest=$(latest)
  if [[ "$newest" != "$tag" && "$(printf '%s\n%s\n' "$tag" "$newest" | sort -V | tail -1)" == "$newest" ]]; then
    warn "Hermes Agent $newest is out (pinned: $tag). Bump it with deploy/hermes-pin.sh bump (docs/adr/0075-hermes-upgrades.md)."
  fi
}

bump() {
  local to=${1:-} from old_commit old_sha commit sha f
  [[ -n "$to" ]] || to=$(latest)
  check_stable "$to"
  from=$(pin tag)
  old_commit=$(pin version)
  old_sha=$(pin sha256)
  [[ "$to" != "$from" ]] || { say "already pinned to $from"; return 0; }
  if [[ "$(printf '%s\n%s\n' "$from" "$to" | sort -V | head -1)" == "$to" ]]; then
    warn "$to is older than the pin, $from: rolling back"
  fi
  commit=$(commit_of "$to")
  sha=$(installer_sha "$commit")
  say "$from ($old_commit) -> $to ($commit)"
  [[ "$sha" == "$old_sha" ]] || say "its scripts/install.sh changed: read the diff before trusting the new SHA-256 ($sha)"

  swap "$pins" "$old_commit" "$commit"
  swap "$pins" "tag: \"$from\"" "tag: \"$to\""
  [[ "$sha" == "$old_sha" ]] || swap "$pins" "$old_sha" "$sha"
  for f in Dockerfile deploy/install.sh; do
    swap "$repo/$f" "$old_commit" "$commit"
    swap "$repo/$f" "commit of tag $from" "commit of tag $to"
  done
  swap "$repo/deploy/README.md" "release $from" "release $to"
  swap "$repo/docs/backend.md" "tested on $from" "tested on $to"
  swap "$repo/docs/ROADMAP.md" "pinned to $from" "pinned to $to"
  cat <<EOF

Now take it through the suite (docs/adr/0075-hermes-upgrades.md):
  1. cargo test                                  (the pins agree everywhere)
  2. deploy/hermes-pin.sh test /tmp/hermes-clis  (hook, canary and timeout tests on the real $to)
  3. Open a pull request: the harness-e2e workflow runs those again, the footprint,
     and deploy/hermes-pin.sh verify. Put the footprint report and what changed in
     the adapter (ideally nothing) in it, and add the bump to ADR 0075's log.
EOF
}

run_tests() {
  local dir=${1:-} footprint=false
  [[ -n "$dir" ]] || die "usage: $0 test DIR [--footprint]"
  [[ "${2:-}" == --footprint ]] && footprint=true
  local path
  path=$("$here/install-harness-clis.sh" "$dir" hermes | grep '^/' | tail -1)
  cd "$repo"
  PATH="$path:$PATH" SUPERBOT_E2E_REQUIRE=1 SUPERBOT_E2E_HARNESSES=hermes \
    cargo test --test harness_e2e -- --ignored --nocapture --test-threads=1
  if $footprint; then
    PATH="$path:$PATH" "$here/harness-footprint.sh" --harness hermes --out "$dir/footprint"
  fi
}

case "${1:-}" in
  show) show ;;
  latest) latest ;;
  verify) verify ;;
  bump) bump "${2:-}" ;;
  test) shift; run_tests "$@" ;;
  *) die "usage: $0 show|latest|verify|bump [TAG]|test DIR [--footprint]" ;;
esac
