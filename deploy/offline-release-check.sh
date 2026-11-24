#!/usr/bin/env bash
# Checks a published release's offline bundles end to end, as an air-gapped customer would use
# them (docs/adr/0172-release-bundles-checked-end-to-end.md, docs/ops/air-gapped.md), with its
# Hermes and harness bundles (docs/adr/0247-hermes-and-harness-bundles-in-the-release-check.md).
#   deploy/offline-release-check.sh online DIR --version V --image NAME=REF... [--commit SHA]
#                                   [--image-identity ID] [--max-glibc 2.N] [--key FILE] [--any-binary-arch]
#                                   [--without-harness-bundles]
#       # connected: DIR holds both arches' bundles with their .sha256 and .sigstore.json, as
#       # attached to the release; each is signed, the tag's commit, built for its arch, and its
#       # images are what each REF names in its registry now, signed. So are both arches' Hermes
#       # and harness bundles, at the pins of the release's botd, which takes them for machines.
#       # Writes DIR/release-check.expected.
#   deploy/offline-release-check.sh offline DIR --mirror HOST[:PORT]/PATH [--trusted-root FILE]
#                                   [--image-identity ID] [--key FILE] [--no-network-probe]
#       # no network: every bundle verifies against Sigstore's trusted root, both offline bundles
#       # go to the mirror as the signed multi-arch index, and cosign verifies every image and the
#       # provenance there.
# --key checks signatures against a cosign public key with no transparency log instead of the
# release identities, --any-binary-arch skips the binaries' arch, and --without-harness-bundles
# skips the Hermes and harness bundles: all for CI, whose test release signs with a throwaway key,
# bundles one runner's binaries for both arches and has no Hermes or harness bundles.
set -euo pipefail

DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
export SUPERBOT_INSTALL_NO_MAIN=1
# shellcheck source=install.sh source-path=SCRIPTDIR
source "$DIR/install.sh"

ARCHES=(x86_64 aarch64)
ISSUER=https://token.actions.githubusercontent.com
EXPECTED='release-check.expected'

usage() { sed -n '2,22p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; }

need() {
  local c
  for c in "$@"; do command -v "$c" >/dev/null 2>&1 || die "This check needs $c"; done
}

bundle_path() { printf '%s/superbot-offline-%s-%s.tar.gz\n' "$1" "$2" "$3"; }
image_repo() { printf '%s\n' "${1%:*}"; }
image_tag() { printf '%s\n' "${1##*:}"; }

# The ELF machine of FILE: x86_64, aarch64 or what the header says.
elf_arch() {
  local magic machine
  magic=$(od -An -tx1 -N4 "$1" | tr -d ' \n')
  [[ "$magic" == 7f454c46 ]] || { echo not-elf; return; }
  machine=$(od -An -tx1 -j18 -N2 "$1" | tr -d ' \n')
  case $machine in
    3e00) echo x86_64 ;;
    b700) echo aarch64 ;;
    *) echo "machine-$machine" ;;
  esac
}

# The newest GLIBC_2.N symbol version FILE asks for, or nothing.
glibc_needed() { { grep -aoE 'GLIBC_2\.[0-9]+' "$1" || true; } | sort -uV | tail -n 1 | sed 's/^GLIBC_//'; }

version_le() { local v; mapfile -t v < <(printf '%s\n' "$1" "$2" | sort -V); [[ "${v[0]}" == "$1" ]]; }

# cosign arguments for a bundle's signature (verify-blob) and an image's (verify).
blob_check_args() {
  if [[ -n "$KEY" ]]; then
    BLOB_CHECK=(--key "$KEY" --insecure-ignore-tlog=true)
  else
    BLOB_CHECK=(--certificate-identity-regexp "$OFFLINE_SIGNER_IDENTITY_REGEXP" --certificate-oidc-issuer "$OFFLINE_SIGNER_ISSUER")
  fi
  [[ -z "$TRUSTED_ROOT" ]] || BLOB_CHECK+=(--trusted-root "$TRUSTED_ROOT")
}
image_check_args() {
  if [[ -n "$KEY" ]]; then
    IMAGE_CHECK=(--key "$KEY" --insecure-ignore-tlog=true)
  else
    IMAGE_CHECK=(--certificate-identity "$IMAGE_IDENTITY" --certificate-oidc-issuer "$ISSUER")
  fi
  [[ -z "$TRUSTED_ROOT" ]] || IMAGE_CHECK+=(--trusted-root "$TRUSTED_ROOT")
}

# With --key, offline-bundle.sh sees each bundle through a folder without its .sigstore.json:
# the installer checks a signature beside a bundle only against the release identity.
stage_bundles() {
  local dir=$1 a
  if [[ -z "$KEY" ]]; then
    STAGE=$dir
    return
  fi
  STAGE="$WORK/stage"
  mkdir -p "$STAGE"
  for a in "${ARCHES[@]}"; do
    stage_file "$dir" "$(basename "$(bundle_path "$dir" "$VERSION" "$a")")"
  done
}
stage_file() { [[ -z "$KEY" ]] || ln -sf "$(cd "$1" && pwd)/$2" "$STAGE/$2"; }

# Connected: a bundle attached to the release, as the installer takes it. Its .sha256 and
# .sigstore.json are beside it, its SHA-256 matches, its signature verifies against the
# release identity, and offline-bundle.sh verify accepts it, signature checked. Sets SUM.
check_published() {
  local b=$1 what=${2:-bundle} f want
  for f in "$b" "$b.sha256" "$b.sigstore.json"; do
    [[ -f "$f" ]] || die "The release has no $(basename "$f")"
  done
  SUM=$(sha256sum "$b" | cut -c1-64)
  want=$(awk 'NR == 1 { print $1 }' "$b.sha256")
  [[ "$SUM" == "$want" ]] || die "$(basename "$b") is $SUM, but its .sha256 says $want"
  cosign verify-blob --bundle "$b.sigstore.json" "${BLOB_CHECK[@]}" "$b" >/dev/null 2>"$WORK/cosign.err" \
    || { cat "$WORK/cosign.err" >&2; die "$(basename "$b")'s signature doesn't verify"; }
  log "$(basename "$b"): SHA-256 $SUM, signature verified"
  "$DIR/offline-bundle.sh" verify "$STAGE/$(basename "$b")" --sha256 "$SUM" >"$WORK/verify.log" 2>&1 \
    || { cat "$WORK/verify.log" >&2; die "$(basename "$b") isn't a good $what"; }
  if [[ -z "$KEY" ]] && ! grep -Fq 'Bundle signature verified' "$WORK/verify.log"; then
    cat "$WORK/verify.log" >&2; die "The installer didn't check $(basename "$b")'s signature"
  fi
}

# Offline: NAME in DIR verifies as the installer checks it, against SUM and, keyless, against
# Sigstore's trusted root.
verify_offline() {
  local dir=$1 name=$2 sum=$3
  [[ -f "$dir/$name" ]] || die "No $dir/$name"
  stage_file "$dir" "$name"
  if [[ -n "$KEY" ]]; then
    cosign verify-blob --bundle "$dir/$name.sigstore.json" "${BLOB_CHECK[@]}" "$STAGE/$name" >/dev/null 2>"$WORK/cosign.err" \
      || { cat "$WORK/cosign.err" >&2; die "$name's signature doesn't verify offline"; }
  fi
  SIGSTORE_TRUSTED_ROOT=$TRUSTED_ROOT "$DIR/offline-bundle.sh" verify "$STAGE/$name" --sha256 "$sum" >"$WORK/verify.log" 2>&1 \
    || { cat "$WORK/verify.log" >&2; die "$name doesn't verify offline"; }
  if [[ -z "$KEY" ]] && ! grep -Fq 'Bundle signature verified' "$WORK/verify.log"; then
    cat "$WORK/verify.log" >&2; die "The installer didn't check $name's signature offline"
  fi
  log "$name: signature and every file verified with no network"
}

# The programs matching PATTERNS (tar wildcards, * stopping at /) in a tree bundle's TAR, a
# member of BUNDLE, read without unpacking the tree: at least one ELF file, each for ARCH and,
# with MAX_GLIBC, asking for no newer glibc. Scripts among them are skipped.
tree_programs_ok() {
  local bundle=$1 member=$2 arch=$3 max_glibc=$4 out p name got n=0
  shift 4
  out="$WORK/programs"
  rm -rf "$out" && mkdir -p "$out"
  # Only regular files go to the command, so the tree's links are never made here.
  # shellcheck disable=SC2016 # expanded by tar's shell, once per file
  tar -xzOf "$bundle" "$member" | PROGRAMS=$out tar -x --wildcards --no-wildcards-match-slash \
    --to-command='cat >"$PROGRAMS/$(printf %s "$TAR_FILENAME" | tr / :)"' "$@" 2>/dev/null || true
  for p in "$out"/*; do
    [[ -f "$p" ]] || continue
    name=$(basename "$p" | tr : /)
    got=$(elf_arch "$p")
    [[ "$got" != not-elf ]] || continue
    n=$((n + 1))
    [[ "$got" == "$arch" ]] || die "$(basename "$bundle")'s $name is built for $got, not $arch"
    if [[ -n "$max_glibc" ]]; then
      got=$(glibc_needed "$p")
      [[ -z "$got" ]] || version_le "$got" "$max_glibc" \
        || die "$(basename "$bundle")'s $name needs glibc $got, newer than $max_glibc: it won't run on every supported Ubuntu"
    fi
  done
  rm -rf "$out"
  ((n > 0)) || die "$(basename "$bundle") has no program to check the arch of ($*)"
}

# The release's Hermes and harness bundles for each arch, as install.sh --offline takes them
# (--hermes-bundle, --harness-bundle) and botd serves them to machines (MACHINE_HERMES_BUNDLE,
# MACHINE_HARNESS_BUNDLE): published and signed as the offline bundles are, built from the tag's
# commit for their arch, and at exactly the pins of the release's own botd, which says machines
# would take them. Each goes into the record.
check_tool_bundles() {
  local dir=$1 commit=$2 max_glibc=$3 any_arch=$4 host botd pins hermes_commit="" hermes_tag="" a kind f b m inner
  local what problem names programs=() files=()
  host=$(uname -m)
  [[ "$host" == x86_64 || "$host" == aarch64 ]] \
    || die "The Hermes and harness bundles are checked against the release's own botd, which runs on x86_64 or aarch64, not $host"
  botd="$WORK/x-$host/superbot-offline-$VERSION-$host/bin/botd"
  chmod 0755 "$botd"
  pins=$(harness_pins "$botd") \
    || die "The release's botd doesn't say which harness CLIs it pins (botd harness pins), so its Hermes and harness bundles can't be checked against it"
  read -r hermes_commit hermes_tag < <(awk '$1 == "hermes" { print $3, $4; exit }' <<<"$pins") || true
  [[ "$hermes_commit" =~ ^[0-9a-f]{40}$ && "$hermes_tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] \
    || die "The release's botd pins no Hermes Agent release (botd harness pins)"
  m="$WORK/MANIFEST"
  for a in "${ARCHES[@]}"; do
    for kind in hermes harnesses; do
      case $kind in
        hermes) f="superbot-hermes-$hermes_tag-$a.tar.gz" what="Hermes bundle" inner=hermes.tar \
          programs=('hermes/.local/bin/*' 'hermes/.local/share/uv/python/*/bin/*') ;;
        harnesses) f="superbot-harnesses-$VERSION-$a.tar.gz" what="harness bundle" inner=harnesses.tar \
          programs=(superbot-harnesses/bin/node) ;;
      esac
      b="$dir/$f"
      stage_file "$dir" "$f"
      check_published "$b" "$what"
      # verify checked MANIFEST against SHA256SUMS; the whole file is hashed again below.
      tar -xzOf "$b" "${f%.tar.gz}/MANIFEST" >"$m" 2>/dev/null || die "Couldn't read $f's MANIFEST"
      [[ "$(manifest_value "$m" arch)" == "$a" ]] || die "$f says it is for $(manifest_value "$m" arch)"
      [[ -z "$commit" || "$(manifest_value "$m" commit)" == "$commit" ]] \
        || die "$f was built from $(manifest_value "$m" commit), not the tag's commit $commit"
      if [[ $kind == hermes ]]; then
        [[ "$(manifest_value "$m" hermes_commit)" == "$hermes_commit" && "$(manifest_value "$m" hermes_tag)" == "$hermes_tag" ]] \
          || die "$f holds Hermes Agent $(manifest_value "$m" hermes_tag) ($(manifest_value "$m" hermes_commit)), but the release's botd pins $hermes_tag ($hermes_commit)"
      else
        [[ "$(manifest_value "$m" version)" == "$VERSION" ]] || die "$f says it is version $(manifest_value "$m" version)"
        problem=$(harness_mismatch "$m" "$(harness_manifest_lines "$pins" "$a")")
        [[ -z "$problem" ]] || die "$f doesn't hold what the release's botd pins ($problem)"
      fi
      [[ "$any_arch" == true ]] || tree_programs_ok "$b" "${f%.tar.gz}/$inner" "$a" "$max_glibc" "${programs[@]}"
      [[ "$(sha256sum "$b" | cut -c1-64)" == "$SUM" ]] || die "$f changed while it was read"
      log "$f: $a${commit:+, commit $commit}, at the release's pins${max_glibc:+ (glibc $max_glibc or older)}"
      echo "$kind $a $f $SUM" >>"$WORK/expected"
      files+=("$b")
    done
  done

  "$botd" harness check-bundles "${files[@]}" >"$WORK/botd.log" 2>&1 \
    || { cat "$WORK/botd.log" >&2; die "The release's botd wouldn't serve these bundles to machines (MACHINE_HERMES_BUNDLE, MACHINE_HARNESS_BUNDLE)"; }
  while read -r kind a f SUM; do
    what=$([[ $kind == hermes ]] && echo "Hermes bundle" || echo "harness bundle")
    grep -Eq "^$a $what /.*/$f: .*, SHA-256 $SUM\$" "$WORK/botd.log" \
      || { cat "$WORK/botd.log" >&2; die "The release's botd didn't check $f for machines"; }
  done < <(awk '$1 == "hermes" || $1 == "harnesses"' "$WORK/expected")
  names=$(awk '$1 == "npm" || $1 == "hermes" { printf "%s%s", sep, $2; sep = ", " }' <<<"$pins")
  grep -Fqx "Machines would install $names from these bundles" "$WORK/botd.log" \
    || { cat "$WORK/botd.log" >&2; die "The release's botd wouldn't install every harness it pins from these bundles"; }
  log "The release's botd would serve both arches' Hermes and harness bundles to machines: $names"
}

# Offline: each Hermes and harness bundle the online check recorded verifies with no network.
# The record names both kinds for both arches, or says the online check skipped them.
verify_tool_bundles() {
  local dir=$1 expected=$2 kind a f sum
  if grep -qx 'harness-bundles skipped' "$expected"; then
    warn "The online check skipped the Hermes and harness bundles (--without-harness-bundles)"
    return 0
  fi
  for kind in hermes harnesses; do
    for a in "${ARCHES[@]}"; do
      f="" sum=""
      read -r f sum < <(awk -v k="$kind" -v a="$a" '$1 == k && $2 == a { print $3, $4; exit }' "$expected") || true
      [[ -n "$f" ]] || die "$expected has no $kind bundle for $a: run the online check again"
      [[ "$f" =~ ^superbot-$kind-[0-9A-Za-z._+-]+-$a\.tar\.gz$ && "$sum" =~ ^[0-9a-f]{64}$ ]] \
        || die "$expected names \"$f\" with \"$sum\" for the $a $kind bundle"
      verify_offline "$dir" "$f" "$sum"
    done
  done
}

# The digest a registry's tag names, read as a customer would: anonymously, unless the
# operator's own auth file has a login.
# Hashed from a file, byte for byte: a command substitution would drop a trailing newline.
registry_digest() {
  skopeo inspect --raw "docker://$1" >"$WORK/raw.json" || return 1
  printf 'sha256:%s\n' "$(sha256sum <"$WORK/raw.json" | cut -c1-64)"
}

cmd_online() {
  local dir="" images=() commit="" max_glibc="" any_arch=false tools=true a b got extracted name ref spec m f
  [[ $# -ge 1 && "$1" != -* ]] || die "online needs the folder with the release's bundles"
  dir=$1
  shift
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --version) VERSION=$2; shift 2 ;;
      --image) images+=("$2"); shift 2 ;;
      --commit) commit=$2; shift 2 ;;
      --image-identity) IMAGE_IDENTITY=$2; shift 2 ;;
      --max-glibc) max_glibc=$2; shift 2 ;;
      --key) KEY=$2; shift 2 ;;
      --any-binary-arch) any_arch=true; shift ;;
      --without-harness-bundles) tools=false; shift ;;
      *) die "Unknown option: $1" ;;
    esac
  done
  [[ -d "$dir" ]] || die "No folder $dir"
  [[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.+-]+)?$ ]] || die "--version \"$VERSION\" isn't a version"
  [[ ${#images[@]} -gt 0 ]] || die "Give each image the release should carry: --image NAME=REF"
  [[ -z "$commit" || "$commit" =~ ^[0-9a-f]{40}$ ]] || die "--commit must be a full commit SHA"
  [[ -z "$max_glibc" || "$max_glibc" =~ ^2\.[0-9]+$ ]] || die "--max-glibc must look like 2.35"
  [[ -z "$KEY" || -f "$KEY" ]] || die "--key: no file at $KEY"
  IMAGE_IDENTITY=${IMAGE_IDENTITY:-https://github.com/CG-Labs/superbot/.github/workflows/docker.yml@refs/tags/v$VERSION}
  need cosign skopeo jq tar sha256sum od
  WORK=$(mktemp -d)
  trap 'rm -rf "$WORK"' EXIT
  blob_check_args
  image_check_args
  stage_bundles "$dir"

  declare -A refs=()
  for spec in "${images[@]}"; do
    name=${spec%%=*} ref=${spec#*=}
    [[ "$spec" == *=* && "$name" =~ ^[a-z0-9][a-z0-9-]*$ && -n "$ref" ]] || die "--image wants NAME=REF"
    [[ -z "${refs[$name]:-}" ]] || die "--image $name is given twice"
    refs[$name]=$ref
  done
  local names
  names=$(printf '%s\n' "${!refs[@]}" | sort | tr '\n' ' ')

  : >"$WORK/expected"
  echo "version $VERSION" >>"$WORK/expected"
  for a in "${ARCHES[@]}"; do
    b=$(bundle_path "$dir" "$VERSION" "$a")
    check_published "$b"

    # verify checked every file against SHA256SUMS; these are the same bytes, read once more.
    extracted="$WORK/x-$a"
    mkdir -p "$extracted"
    m="superbot-offline-$VERSION-$a"
    tar -xzf "$b" -C "$extracted" --no-same-owner --wildcards "$m/MANIFEST" "$m/SHA256SUMS" "$m/bin/*" "$m/images/*.ref" \
      "$m/images/*.digest" "$m/images/*.index" "$m/signatures/*" 2>/dev/null \
      || die "$(basename "$b") doesn't hold signed images (images/*.index, signatures/): it can't put up the signed index"
    (cd "$extracted/$m" && grep -E '  (MANIFEST|bin/.*|images/.*\.(ref|digest|index)|signatures/.*)$' SHA256SUMS | sha256sum --check --strict --quiet) \
      || die "$(basename "$b") changed while it was read"
    m="$extracted/$m"
    [[ "$(manifest_value "$m/MANIFEST" version)" == "$VERSION" ]] || die "$(basename "$b") says it is version $(manifest_value "$m/MANIFEST" version)"
    [[ "$(manifest_value "$m/MANIFEST" arch)" == "$a" ]] || die "$(basename "$b") says it is for $(manifest_value "$m/MANIFEST" arch)"
    [[ -z "$commit" || "$(manifest_value "$m/MANIFEST" commit)" == "$commit" ]] \
      || die "$(basename "$b") was built from $(manifest_value "$m/MANIFEST" commit), not the tag's commit $commit"
    [[ "$(manifest_value "$m/MANIFEST" image_format)" == oci ]] || die "$(basename "$b")'s images aren't OCI archives"
    [[ -z "$(manifest_value "$m/MANIFEST" unsigned_images)" ]] || die "$(basename "$b") carries images bundled without a signature check"
    [[ "$(manifest_value "$m/MANIFEST" images | tr ' ' '\n' | sed '/^$/d' | sort | tr '\n' ' ')" == "$names" ]] \
      || die "$(basename "$b") holds images \"$(manifest_value "$m/MANIFEST" images)\", not \"${names% }\""
    for f in "${OFFLINE_BINARIES[@]}" superbot-oci; do
      [[ -f "$m/bin/$f" ]] || die "$(basename "$b") has no bin/$f"
      got=$(elf_arch "$m/bin/$f")
      [[ "$got" == "$a" || "$any_arch" == true ]] || die "$(basename "$b")'s bin/$f is built for $got, not $a"
      if [[ -n "$max_glibc" ]]; then
        got=$(glibc_needed "$m/bin/$f")
        [[ -z "$got" ]] || version_le "$got" "$max_glibc" \
          || die "$(basename "$b")'s bin/$f needs glibc $got, newer than $max_glibc: it won't run on every supported Ubuntu"
      fi
    done
    log "$(basename "$b"): version $VERSION, $a binaries${max_glibc:+ (glibc $max_glibc or older)}${commit:+, commit $commit}"
    echo "bundle $a $(cut -c1-64 "$b.sha256")" >>"$WORK/expected"
  done
  if [[ "$tools" == true ]]; then
    check_tool_bundles "$dir" "$commit" "$max_glibc" "$any_arch"
  else
    warn "Not checking the Hermes and harness bundles (--without-harness-bundles)"
    echo "harness-bundles skipped" >>"$WORK/expected"
  fi

  for name in $names; do
    ref=${refs[$name]}
    local index="" darch digest raw
    for a in "${ARCHES[@]}"; do
      m="$WORK/x-$a/superbot-offline-$VERSION-$a"
      [[ "$(cat "$m/images/$name.ref")" == "$ref" ]] || die "The $a bundle's $name image is $(cat "$m/images/$name.ref"), not $ref"
      [[ -f "$m/images/$name.index" && -f "$m/signatures/$name.tar" ]] || die "The $a bundle's $name image has no signed index or signatures"
      got=$(cat "$m/images/$name.index")
      [[ -z "$index" || "$got" == "$index" ]] || die "The bundles' $name images come from different indexes ($index, $got)"
      index=$got
    done
    got=$(registry_digest "$ref") || die "Couldn't read $ref from its registry, as a customer's connected machine would (anonymously)"
    raw=$(cat "$WORK/raw.json")
    [[ "$got" == "$index" ]] || die "$ref names $got now, but the bundles carry $index: the tag has moved since the bundles were made"
    for a in "${ARCHES[@]}"; do
      m="$WORK/x-$a/superbot-offline-$VERSION-$a"
      darch=$(case $a in x86_64) echo amd64 ;; aarch64) echo arm64 ;; esac)
      digest=$(jq -r --arg a "$darch" '[.manifests[]? | select(.platform.os == "linux" and .platform.architecture == $a) | .digest][0] // empty' <<<"$raw")
      [[ "$digest" == "$(cat "$m/images/$name.digest")" ]] || die "$ref's linux/$darch image is ${digest:-missing}, but the $a bundle carries $(cat "$m/images/$name.digest")"
    done
    cosign verify "$(image_repo "$ref")@$index" "${IMAGE_CHECK[@]}" >/dev/null 2>"$WORK/cosign.err" \
      || { cat "$WORK/cosign.err" >&2; die "$ref ($index) isn't signed by ${KEY:-$IMAGE_IDENTITY}"; }
    log "$name: $ref is $index in its registry, signed, with each arch's image as bundled"
    echo "image $name $ref $index" >>"$WORK/expected"
  done
  mv "$WORK/expected" "$dir/$EXPECTED"
  log "Connected checks passed. Carry $dir (with $EXPECTED) to a host with no network and run: $0 offline $dir --mirror ..."
}

cmd_offline() {
  local dir="" mirror="" probe=true a b sum name ref index dest d expected
  [[ $# -ge 1 && "$1" != -* ]] || die "offline needs the folder the online check passed"
  dir=$1
  shift
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --mirror) mirror=$2; shift 2 ;;
      --trusted-root) TRUSTED_ROOT=$2; shift 2 ;;
      --image-identity) IMAGE_IDENTITY=$2; shift 2 ;;
      --key) KEY=$2; shift 2 ;;
      --no-network-probe) probe=false; shift ;;
      *) die "Unknown option: $1" ;;
    esac
  done
  expected="$dir/$EXPECTED"
  [[ -f "$expected" ]] || die "No $expected: run the online check first"
  [[ -n "$mirror" ]] || die "offline needs --mirror HOST[:PORT]/PATH, a registry inside the network"
  [[ -z "$KEY" || -f "$KEY" ]] || die "--key: no file at $KEY"
  [[ -n "$KEY" || -n "$TRUSTED_ROOT" ]] || die "Offline, cosign needs Sigstore's trusted root: give --trusted-root (cosign initialize on a connected machine)"
  [[ -z "$TRUSTED_ROOT" || -f "$TRUSTED_ROOT" ]] || die "--trusted-root: no file at $TRUSTED_ROOT"
  need cosign skopeo jq curl
  if [[ "$probe" == true ]] && curl -sS --max-time 5 https://github.com >/dev/null 2>&1; then
    die "This host reaches github.com: run the offline check where there is no network"
  fi
  VERSION=$(awk '$1 == "version" { print $2 }' "$expected")
  [[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.+-]+)?$ ]] || die "$expected has no version"
  IMAGE_IDENTITY=${IMAGE_IDENTITY:-https://github.com/CG-Labs/superbot/.github/workflows/docker.yml@refs/tags/v$VERSION}
  WORK=$(mktemp -d)
  trap 'rm -rf "$WORK"' EXIT
  blob_check_args
  image_check_args
  stage_bundles "$dir"

  local push=() sums=()
  for a in "${ARCHES[@]}"; do
    sum=$(awk -v a="$a" '$1 == "bundle" && $2 == a { print $3 }' "$expected")
    [[ "$sum" =~ ^[0-9a-f]{64}$ ]] || die "$expected has no SHA-256 for the $a bundle"
    b=$(bundle_path "$STAGE" "$VERSION" "$a")
    verify_offline "$dir" "$(basename "$b")" "$sum"
    push+=("$b") sums+=(--sha256 "$sum")
  done
  verify_tool_bundles "$dir" "$expected"

  # A record cut short must not pass with nothing checked in the mirror: every image the
  # verified bundles hold needs its record, and every record an image.
  local listed recorded
  listed=$(tar -xzOf "$(bundle_path "$dir" "$VERSION" x86_64)" "superbot-offline-$VERSION-x86_64/MANIFEST" | sed -n 's/^images=//p' | tail -n 1 \
    | tr ' ' '\n' | sed '/^$/d' | sort | tr '\n' ' ')
  recorded=$(awk '$1 == "image" { print $2 }' "$expected" | sort | tr '\n' ' ')
  [[ -n "$listed" ]] || die "The bundles hold no images: nothing to check in a mirror"
  [[ "$recorded" == "$listed" ]] || die "$expected records images \"${recorded% }\", but the bundles hold \"${listed% }\": run the online check again"

  SIGSTORE_TRUSTED_ROOT=$TRUSTED_ROOT "$DIR/offline-bundle.sh" push "${push[@]}" "${sums[@]}" --registry "$mirror" >"$WORK/push.log" 2>&1 \
    || { cat "$WORK/push.log" >&2; die "Pushing both bundles to $mirror failed"; }
  sed 's/^/    /' "$WORK/push.log"

  while read -r _ name ref index; do
    dest="$mirror/$(basename "$(image_repo "$ref")"):$(image_tag "$ref")"
    d=$(registry_digest "$dest") || die "Couldn't read $dest from the mirror"
    [[ "$d" == "$index" ]] || die "$dest names $d, not the signed index $index"
    cosign verify "$dest" "${IMAGE_CHECK[@]}" >/dev/null 2>"$WORK/cosign.err" \
      || { cat "$WORK/cosign.err" >&2; die "cosign verify failed for $dest in the mirror"; }
    skopeo inspect --raw "docker://$dest" | jq -r '.manifests[].digest' >"$WORK/children"
    [[ -s "$WORK/children" ]] || die "$dest isn't a multi-arch index"
    while read -r d; do
      cosign verify "$(image_repo "$dest")@$d" "${IMAGE_CHECK[@]}" >/dev/null 2>"$WORK/cosign.err" \
        || { cat "$WORK/cosign.err" >&2; die "cosign verify failed for $(image_repo "$dest")@$d in the mirror"; }
    done <"$WORK/children"
    cosign verify-attestation --type slsaprovenance1 "$dest" "${IMAGE_CHECK[@]}" >/dev/null 2>"$WORK/cosign.err" \
      || { cat "$WORK/cosign.err" >&2; die "cosign verify-attestation found no verified build provenance for $dest in the mirror"; }
    log "$name: $dest is the signed index $index; it, its $(wc -l <"$WORK/children") manifests and its provenance verify with no network"
  done < <(awk '$1 == "image"' "$expected")
  log "Offline checks passed for $VERSION"
}

KEY="" TRUSTED_ROOT="" IMAGE_IDENTITY="" VERSION="" WORK="" STAGE=""
case "${1:-}" in
  online) shift; cmd_online "$@" ;;
  offline) shift; cmd_offline "$@" ;;
  -h|--help|"") usage ;;
  *) die "Unknown command: $1 (online or offline)" ;;
esac
