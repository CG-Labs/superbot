#!/usr/bin/env bash
# CHANGELOG.md and GitHub releases (ADR 0111). The release workflow runs this; so can you.
#
#   deploy/release-notes.sh check       fails unless CHANGELOG.md is well formed, its newest
#                                       version is server/Cargo.toml's, and every v<semver>
#                                       tag has a dated section
#   deploy/release-notes.sh notes TAG   checks as above, and that TAG is v<Cargo version>
#                                       with a dated section, then prints that section as
#                                       the release notes
#   deploy/release-notes.sh self-test   runs the checks against fixtures
#
# CHANGELOG.md follows Keep a Changelog 1.1.0: an optional `## [Unreleased]` first, then
# `## [X.Y.Z] - YYYY-MM-DD` sections, newest first. The newest may say `- Unreleased`
# instead of a date until it is tagged. CHANGELOG, CARGO_TOML and RELEASE_TAGS (one tag per
# line; default: the `v*` tags HEAD contains) override the inputs. With GITHUB_REPOSITORY set,
# the notes end with the release's image names.
set -euo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repo=$(cd "$here/.." && pwd)
changelog=${CHANGELOG:-$repo/CHANGELOG.md}
cargo_toml=${CARGO_TOML:-$repo/server/Cargo.toml}

die() { printf 'release-notes: %s\n' "$*" >&2; exit 1; }

semver_re='^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$'
is_semver() { [[ "$1" =~ $semver_re ]]; }

# Succeeds if semver $1 is newer than $2. A release is newer than its own prereleases;
# prereleases of one version compare by `sort -V`, close enough for rc.1 < rc.2.
newer() {
  local a=${1%%-*} b=${2%%-*} i x y
  local -a av bv
  IFS=. read -ra av <<<"$a"
  IFS=. read -ra bv <<<"$b"
  for i in 0 1 2; do
    x=${av[i]} y=${bv[i]}
    ((10#$x > 10#$y)) && return 0
    ((10#$x < 10#$y)) && return 1
  done
  [[ $1 == "$2" ]] && return 1
  [[ $1 != *-* ]] && return 0
  [[ $2 != *-* ]] && return 1
  [[ $(printf '%s\n%s\n' "${1#*-}" "${2#*-}" | sort -V | tail -n1) == "${1#*-}" ]]
}

valid_date() {
  [[ "$1" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]] && [[ $(date -u -d "$1" +%F 2>/dev/null) == "$1" ]]
}

cargo_version() {
  local v
  v=$(awk '/^\[/ { pkg = ($0 == "[package]") } pkg && /^version *= *"/ { sub(/^version *= *"/, ""); sub(/".*/, ""); print; exit }' "$cargo_toml")
  [[ -n "$v" ]] || die "no [package] version in $cargo_toml"
  is_semver "$v" || die "$cargo_toml: version $v isn't semver"
  printf '%s\n' "$v"
}

tags() {
  if [[ -n "${RELEASE_TAGS+x}" ]]; then
    printf '%s\n' "$RELEASE_TAGS"
  else
    # Only tags this commit contains: an older tag's changelog can't know newer ones.
    git -C "$repo" tag --merged HEAD --list 'v*'
  fi
}

# `version<TAB>date` for each version section, top to bottom; date is `Unreleased` for a
# pending one. Fails on any `## ` heading that isn't a section Keep a Changelog allows.
sections() {
  local line n=0 first=1 v d
  while IFS= read -r line || [[ -n "$line" ]]; do
    n=$((n + 1))
    [[ $line == '## '* ]] || continue
    if [[ $line == '## [Unreleased]' ]]; then
      ((first)) || die "CHANGELOG.md:$n: [Unreleased] must be the first section"
    elif [[ $line =~ ^'## ['([^]]+)'] - '(.+)$ ]]; then
      v=${BASH_REMATCH[1]} d=${BASH_REMATCH[2]}
      is_semver "$v" || die "CHANGELOG.md:$n: $v isn't semver (X.Y.Z, no leading v)"
      [[ $d == Unreleased ]] || valid_date "$d" || die "CHANGELOG.md:$n: $d isn't a date (YYYY-MM-DD) or Unreleased"
      printf '%s\t%s\t%s\n' "$v" "$d" "$n"
    else
      die "CHANGELOG.md:$n: \`$line\` isn't \`## [Unreleased]\` or \`## [X.Y.Z] - YYYY-MM-DD\`"
    fi
    first=0
  done <"$changelog"
}

# The body of version $1's section, without the blank lines around it, followed by the
# link reference definitions (`[label]: target`) from anywhere in the file that it uses.
body() {
  awk -v want="## [$1] - " '
    /^\[[^]]+\]: / { label = tolower(substr($0, 2, index($0, "]:") - 2)); defs[label] = $0; order[++d] = label; next }
    index($0, "## ") == 1 { on = (index($0, want) == 1); next }
    on { lines[++n] = $0; text = text "\n" tolower($0) }
    END {
      s = 1; while (s <= n && lines[s] ~ /^[ \t]*$/) s++
      e = n; while (e >= s && lines[e] ~ /^[ \t]*$/) e--
      for (i = s; i <= e; i++) print lines[i]
      sep = "\n"
      for (i = 1; i <= d; i++) {
        l = order[i]
        if (!(l in used) && index(text, "[" l "]")) { printf "%s%s\n", sep, defs[l]; sep = ""; used[l] = 1 }
      }
    }
  ' "$changelog"
}

check() {
  [[ -f "$changelog" ]] || die "no $changelog"
  [[ $(head -n1 "$changelog") == '# Changelog' ]] || die "CHANGELOG.md must start with \`# Changelog\`"
  local list v d n prev='' prev_date='' top='' i=0 tag cargo
  list=$(sections)
  [[ -n "$list" ]] || die "CHANGELOG.md has no version sections"
  declare -A dated=() seen=()
  while IFS=$'\t' read -r v d n; do
    i=$((i + 1))
    [[ -z "${seen[$v]:-}" ]] || die "CHANGELOG.md:$n: $v has two sections"
    seen[$v]=1
    ((i == 1)) && top=$v
    if [[ $d == Unreleased ]]; then
      ((i == 1)) || die "CHANGELOG.md:$n: only the newest version may be Unreleased"
    else
      dated[$v]=1
      [[ -z "$prev_date" || ! "$d" > "$prev_date" ]] || die "CHANGELOG.md:$n: $v is dated $d, after the newer $prev ($prev_date)"
      prev_date=$d
    fi
    [[ -z "$prev" ]] || newer "$prev" "$v" || die "CHANGELOG.md:$n: $v must come after $prev (newest first)"
    body "$v" | grep -v -e '^#' -e '^[[:space:]]*$' -e '^\[[^]]*\]: ' >/dev/null || die "CHANGELOG.md:$n: $v's section has no entries"
    prev=$v
  done <<<"$list"
  cargo=$(cargo_version)
  [[ $cargo == "$top" ]] || die "server/Cargo.toml is $cargo but CHANGELOG.md's newest version is $top; add a section for $cargo or bump Cargo.toml"
  while IFS= read -r tag; do
    [[ -n "$tag" ]] || continue
    is_semver "${tag#v}" || continue
    [[ -n "${dated[${tag#v}]:-}" ]] || die "tag $tag has no dated section in CHANGELOG.md (## [${tag#v}] - YYYY-MM-DD)"
  done < <(tags)
}

notes() {
  local tag=${1:-} v
  if [[ $tag != v* ]] || ! is_semver "${tag#v}"; then
    die "$tag isn't a release tag (v<semver>, like v1.2.3 or v1.2.3-rc.1)"
  fi
  v=${tag#v}
  RELEASE_TAGS="$(tags)"$'\n'"$tag" check
  [[ $(cargo_version) == "$v" ]] || die "$tag doesn't match server/Cargo.toml's version $(cargo_version)"
  if [[ -z "${GITHUB_REPOSITORY:-}" ]]; then
    body "$v"
    return
  fi
  # A release page resolves relative links against itself, so they point at the tag's files.
  local files="${GITHUB_SERVER_URL:-https://github.com}/$GITHUB_REPOSITORY/blob/$tag/"
  body "$v" | sed -E -e "s|\]\(([^):/#][^):]*)\)|](${files}\1)|g" -e "s~^(\[[^]]+\]: )([^ :/#][^ :]*)( |$)~\1${files}\2\3~"
  local image="ghcr.io/${GITHUB_REPOSITORY,,}"
  # shellcheck disable=SC2016 # the backticks are Markdown
  printf '\n---\n\nImages: `%s:%s` and `%s-caddy:%s`, signed and with build provenance, once the docker workflow has published them for this tag. [Verify them](%sdeploy/README.md#verifying-the-images) before you run them.\n' \
    "$image" "$v" "$image" "$v" "$files"
}

self_test() {
  local fails=0 out
  dir=$(mktemp -d)
  trap 'rm -rf "$dir"' EXIT
  printf '[package]\nname = "x"\nversion = "1.1.0"\n\n[dependencies]\nfoo = { version = "9.9.9" }\n' >"$dir/Cargo.toml"

  # expect pass|fail NAME WHY CMD [TAGS [TAG]], with the changelog on stdin: the command must
  # pass or fail as said, and its output contain WHY.
  expect() {
    local want=$1 name=$2 why=$3 cmd=$4 tags_=${5:-} got
    cat >"$dir/CHANGELOG.md"
    if out=$(CHANGELOG="$dir/CHANGELOG.md" CARGO_TOML="$dir/Cargo.toml" RELEASE_TAGS="$tags_" GITHUB_REPOSITORY='' \
      bash "${BASH_SOURCE[0]}" "$cmd" "${@:6}" 2>&1); then got=pass; else got=fail; fi
    if [[ $got == "$want" && $out == *"$why"* ]]; then
      printf 'ok   %s\n' "$name"
    else
      printf 'FAIL %s: wanted %s with "%s", got %s:\n%s\n' "$name" "$want" "$why" "$got" "$out"
      fails=$((fails + 1))
    fi
  }

  local good='# Changelog

## [Unreleased]

- Next.

## [1.1.0] - 2026-11-20

### Added

- Two.

## [1.1.0-rc.1] - 2026-11-19

- Candidate.

## [1.0.0] - 2026-11-01

- One.

[1.0.0]: https://example.invalid/v1.0.0
'
  expect pass 'a good changelog passes' '' check <<<"$good"
  expect pass 'tags with dated sections pass' '' check $'v1.0.0\nv1.1.0-rc.1\nv1.1.0\nnot-semver\nvbranch' <<<"$good"
  expect fail 'a tag without a section fails' 'tag v0.9.0 has no dated section' check $'v1.0.0\nv0.9.0' <<<"$good"
  expect pass 'notes for the Cargo version pass' '- Two.' notes '' v1.1.0 <<<"$good"
  if [[ $out != $'### Added\n\n- Two.' ]]; then
    printf 'FAIL notes print just the section, got:\n%s\n' "$out"; fails=$((fails + 1))
  else
    printf 'ok   notes print just the section\n'
  fi
  printf '# Changelog\n\n## [1.0.0] - 2026-11-01\n\n- One.\n\n[1.0.0]: https://example.invalid/v1.0.0\n' >"$dir/CHANGELOG.md"
  printf '[package]\nversion = "1.0.0"\n' >"$dir/Cargo-1.0.0.toml"
  out=$(CHANGELOG="$dir/CHANGELOG.md" CARGO_TOML="$dir/Cargo-1.0.0.toml" RELEASE_TAGS='' GITHUB_REPOSITORY='' \
    bash "${BASH_SOURCE[0]}" notes v1.0.0 2>&1) || true
  if [[ $out == '- One.' ]]; then printf 'ok   link references are not notes\n'; else
    printf 'FAIL link references are not notes, got:\n%s\n' "$out"; fails=$((fails + 1)); fi
  expect fail 'notes for a tag that isn'\''t the Cargo version fail' 'doesn'\''t match server/Cargo.toml'\''s version 1.1.0' notes '' v1.0.0 <<<"$good"
  expect fail 'notes for a tag with no section fail' 'tag v1.2.0 has no dated section' notes '' v1.2.0 <<<"$good"
  expect fail 'a tag that isn'\''t v<semver> fails' 'isn'\''t a release tag' notes '' 1.1.0 <<<"$good"
  expect fail 'a tag with a leading zero fails' 'isn'\''t a release tag' notes '' v1.01.0 <<<"$good"
  expect fail 'notes for an Unreleased section fail' 'tag v1.1.0 has no dated section' notes '' v1.1.0 <<<'# Changelog

## [1.1.0] - Unreleased

- Two.
'
  expect pass 'an Unreleased newest version passes check' '' check <<<'# Changelog

## [1.1.0] - Unreleased

- Two.

## [1.0.0] - 2026-11-01

- One.
'
  expect fail 'a tagged version left Unreleased fails' 'tag v1.1.0 has no dated section' check v1.1.0 <<<'# Changelog

## [1.1.0] - Unreleased

- Two.
'
  expect fail 'a Cargo version with no section fails' 'server/Cargo.toml is 1.1.0 but CHANGELOG.md'\''s newest version is 1.0.0' check <<<'# Changelog

## [1.0.0] - 2026-11-01

- One.
'
  expect fail 'a section newer than Cargo fails' 'newest version is 1.2.0' check <<<'# Changelog

## [1.2.0] - 2026-11-21

- Three.

## [1.1.0] - 2026-11-20

- Two.
'
  expect fail 'an older Unreleased section fails' 'only the newest version may be Unreleased' check <<<'# Changelog

## [1.1.0] - 2026-11-20

- Two.

## [1.0.0] - Unreleased

- One.
'
  expect fail 'a duplicate version fails' '1.1.0 has two sections' check <<<'# Changelog

## [1.1.0] - 2026-11-20

- Two.

## [1.1.0] - 2026-11-19

- Two again.
'
  expect fail 'versions out of order fail' '1.0.1 must come after 1.0.0' check <<<'# Changelog

## [1.1.0] - 2026-11-20

- Two.

## [1.0.0] - 2026-11-01

- One.

## [1.0.1] - 2026-10-01

- One and a bit.
'
  expect fail 'a release below its own prerelease fails' '1.1.0 must come after 1.1.0-rc.1' check <<<'# Changelog

## [1.1.0-rc.1] - 2026-11-20

- Candidate.

## [1.1.0] - 2026-11-19

- Two.
'
  expect fail 'dates going forward down the file fail' 'after the newer 1.1.0' check <<<'# Changelog

## [1.1.0] - 2026-11-01

- Two.

## [1.0.0] - 2026-11-20

- One.
'
  expect fail 'an impossible date fails' '2026-02-30 isn'\''t a date' check <<<'# Changelog

## [1.1.0] - 2026-02-30

- Two.
'
  expect fail 'a version with a leading v fails' 'v1.1.0 isn'\''t semver' check <<<'# Changelog

## [v1.1.0] - 2026-11-20

- Two.
'
  expect fail 'a heading Keep a Changelog has no place for fails' "\`## 1.1.0\` isn't" check <<<'# Changelog

## 1.1.0

- Two.
'
  expect fail 'Unreleased below a version fails' '[Unreleased] must be the first section' check <<<'# Changelog

## [1.1.0] - 2026-11-20

- Two.

## [Unreleased]

- Next.
'
  expect fail 'an empty section fails' '1.1.0'\''s section has no entries' check <<<'# Changelog

## [1.1.0] - 2026-11-20

### Added

## [1.0.0] - 2026-11-01

- One.
'
  expect fail 'a file without the title fails' "must start with \`# Changelog\`" check <<<'## [1.1.0] - 2026-11-20

- Two.
'
  expect fail 'a file without versions fails' 'has no version sections' check <<<'# Changelog

## [Unreleased]

- Next.
'
  printf '# Changelog\n\n## [1.1.0] - 2026-11-20\n\n- Two ([ADR](docs/adr/x.md#why), [site](https://x.example/a), [here](#two)).\n' >"$dir/CHANGELOG.md"
  out=$(CHANGELOG="$dir/CHANGELOG.md" CARGO_TOML="$dir/Cargo.toml" RELEASE_TAGS='' GITHUB_REPOSITORY=Owner/Repo \
    bash "${BASH_SOURCE[0]}" notes v1.1.0 2>&1) || true
  # shellcheck disable=SC2016 # the backticks are Markdown
  if [[ $out == *'`ghcr.io/owner/repo:1.1.0` and `ghcr.io/owner/repo-caddy:1.1.0`'* ]]; then
    printf 'ok   notes name the images, in lower case\n'
  else
    printf 'FAIL notes name the images, got:\n%s\n' "$out"; fails=$((fails + 1))
  fi
  if [[ $out == *'- Two ([ADR](https://github.com/Owner/Repo/blob/v1.1.0/docs/adr/x.md#why), [site](https://x.example/a), [here](#two)).'* ]]; then
    printf 'ok   notes link the tag'\''s files, and leave other links alone\n'
  else
    printf 'FAIL notes link the tag'\''s files, got:\n%s\n' "$out"; fails=$((fails + 1))
  fi

  printf '# Changelog\n\n## [1.1.0] - 2026-11-20\n\n- See [the guide][guide] and [Site].\n\n## [1.0.0] - 2026-11-01\n\n- One.\n\n[guide]: deploy/README.md\n[site]: https://x.example\n[unused]: docs/x.md\n[1.0.0]: https://x.example/v1.0.0\n' >"$dir/CHANGELOG.md"
  out=$(CHANGELOG="$dir/CHANGELOG.md" CARGO_TOML="$dir/Cargo.toml" RELEASE_TAGS='' GITHUB_REPOSITORY=Owner/Repo \
    bash "${BASH_SOURCE[0]}" notes v1.1.0 2>&1) || true
  if [[ $out == *$'[the guide][guide] and [Site].\n\n[guide]: https://github.com/Owner/Repo/blob/v1.1.0/deploy/README.md\n[site]: https://x.example\n'* && $out != *unused* && $out != *'[1.0.0]:'* ]]; then
    printf 'ok   notes keep the link definitions they use, pointed at the tag\n'
  else
    printf 'FAIL notes keep the link definitions they use, got:\n%s\n' "$out"; fails=$((fails + 1))
  fi

  { printf '# Changelog\n\n## [1.1.0] - 2026-11-20\n\n'; for _ in $(seq 20000); do printf -- '- A long entry about one change of many.\n'; done; } >"$dir/CHANGELOG.md"
  if CHANGELOG="$dir/CHANGELOG.md" CARGO_TOML="$dir/Cargo.toml" RELEASE_TAGS='' bash "${BASH_SOURCE[0]}" check >/dev/null 2>&1; then
    printf 'ok   a long section passes\n'
  else
    printf 'FAIL a long section passes\n'; fails=$((fails + 1))
  fi

  # Re-running an older tag's release, once a newer tag exists, checks only the tags it holds.
  local git_=(git -C "$dir/repo" -c user.name=test -c user.email=test@example.invalid -c init.defaultBranch=main)
  mkdir -p "$dir/repo/deploy" "$dir/repo/server"
  cp "${BASH_SOURCE[0]}" "$dir/repo/deploy/release-notes.sh"
  "${git_[@]}" init -q
  printf '[package]\nversion = "1.0.0"\n' >"$dir/repo/server/Cargo.toml"
  printf '# Changelog\n\n## [1.0.0] - 2026-11-01\n\n- One.\n' >"$dir/repo/CHANGELOG.md"
  "${git_[@]}" add -A && "${git_[@]}" commit -qm one && "${git_[@]}" tag v1.0.0
  printf '[package]\nversion = "1.1.0"\n' >"$dir/repo/server/Cargo.toml"
  printf '# Changelog\n\n## [1.1.0] - 2026-11-20\n\n- Two.\n\n## [1.0.0] - 2026-11-01\n\n- One.\n' >"$dir/repo/CHANGELOG.md"
  "${git_[@]}" commit -qam two && "${git_[@]}" tag v1.1.0 && "${git_[@]}" checkout -q v1.0.0
  if out=$(env -u CHANGELOG -u CARGO_TOML -u RELEASE_TAGS GITHUB_REPOSITORY='' bash "$dir/repo/deploy/release-notes.sh" notes v1.0.0 2>&1) && [[ $out == '- One.' ]]; then
    printf 'ok   an older tag still releases once a newer one exists\n'
  else
    printf 'FAIL an older tag still releases once a newer one exists, got:\n%s\n' "$out"; fails=$((fails + 1))
  fi
  "${git_[@]}" checkout -q v1.1.0 && "${git_[@]}" tag -d v1.0.0 >/dev/null && "${git_[@]}" tag v0.9.0 v1.1.0
  if ! out=$(env -u CHANGELOG -u CARGO_TOML -u RELEASE_TAGS bash "$dir/repo/deploy/release-notes.sh" check 2>&1) && [[ $out == *'tag v0.9.0 has no dated section'* ]]; then
    printf 'ok   tags the commit holds are still checked\n'
  else
    printf 'FAIL tags the commit holds are still checked, got:\n%s\n' "$out"; fails=$((fails + 1))
  fi

  ((fails == 0)) || die "$fails self-test case(s) failed"
  printf 'release-notes: self-test passed\n'
}

case ${1:-} in
  check) check ;;
  notes) notes "${2:-}" ;;
  self-test) self_test ;;
  *) die "usage: $0 check | notes TAG | self-test" ;;
esac
