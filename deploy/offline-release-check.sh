#!/usr/bin/env bash
# Checks a published release's offline bundles end to end, as an air-gapped customer would use
# them (docs/adr/0172-release-bundles-checked-end-to-end.md, docs/ops/air-gapped.md).
#   deploy/offline-release-check.sh online DIR --version V --image NAME=REF... [--commit SHA]
#                                   [--image-identity ID] [--max-glibc 2.N] [--key FILE] [--any-binary-arch]
#       # connected: DIR holds both arches' bundles with their .sha256 and .sigstore.json, as
#       # attached to the release; each is signed, the tag's commit, built for its arch, and its
#       # images are what each REF names in its registry now, signed. Writes DIR/release-check.expected.
#   deploy/offline-release-check.sh offline DIR --mirror HOST[:PORT]/PATH [--trusted-root FILE]
#                                   [--image-identity ID] [--key FILE] [--no-network-probe]
#       # no network: the bundles verify against Sigstore's trusted root, both go to the mirror as
#       # the signed multi-arch index, and cosign verifies every image and the provenance there.
# --key checks signatures against a cosign public key with no transparency log instead of the
# release identities, and --any-binary-arch skips the binaries' arch: both for CI, whose test
# release signs with a throwaway key and bundles one runner's binaries for both arches.
set -euo pipefail

DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
export SUPERBOT_INSTALL_NO_MAIN=1
# shellcheck source=install.sh source-path=SCRIPTDIR
source "$DIR/install.sh"

ARCHES=(x86_64 aarch64)
ISSUER=https://token.actions.githubusercontent.com
EXPECTED='release-check.expected'

usage() { sed -n '2,15p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; }

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
  local dir=$1 a b
  if [[ -z "$KEY" ]]; then
    STAGE=$dir
    return
  fi
  dir=$(cd "$dir" && pwd)
  STAGE="$WORK/stage"
  mkdir -p "$STAGE"
  for a in "${ARCHES[@]}"; do
    b=$(bundle_path "$dir" "$VERSION" "$a")
    ln -sf "$b" "$STAGE/$(basename "$b")"
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
  local dir="" images=() commit="" max_glibc="" any_arch=false a b want got extracted name ref spec m f
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
    for f in "$b" "$b.sha256" "$b.sigstore.json"; do
      [[ -f "$f" ]] || die "The release has no $(basename "$f")"
    done
    got=$(sha256sum "$b" | cut -c1-64)
    want=$(awk 'NR == 1 { print $1 }' "$b.sha256")
    [[ "$got" == "$want" ]] || die "$(basename "$b") is $got, but its .sha256 says $want"
    cosign verify-blob --bundle "$b.sigstore.json" "${BLOB_CHECK[@]}" "$b" >/dev/null 2>"$WORK/cosign.err" \
      || { cat "$WORK/cosign.err" >&2; die "$(basename "$b")'s signature doesn't verify"; }
    log "$(basename "$b"): SHA-256 $got, signature verified"
    "$DIR/offline-bundle.sh" verify "$(bundle_path "$STAGE" "$VERSION" "$a")" --sha256 "$got" >"$WORK/verify.log" 2>&1 \
      || { cat "$WORK/verify.log" >&2; die "$(basename "$b") isn't a good bundle"; }
    if [[ -z "$KEY" ]] && ! grep -Fq 'Bundle signature verified' "$WORK/verify.log"; then
      cat "$WORK/verify.log" >&2; die "The installer didn't check $(basename "$b")'s signature"
    fi

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
    if [[ -n "$KEY" ]]; then
      cosign verify-blob --bundle "$(bundle_path "$dir" "$VERSION" "$a").sigstore.json" "${BLOB_CHECK[@]}" "$b" >/dev/null 2>"$WORK/cosign.err" \
        || { cat "$WORK/cosign.err" >&2; die "$(basename "$b")'s signature doesn't verify offline"; }
    fi
    SIGSTORE_TRUSTED_ROOT=$TRUSTED_ROOT "$DIR/offline-bundle.sh" verify "$b" --sha256 "$sum" >"$WORK/verify.log" 2>&1 \
      || { cat "$WORK/verify.log" >&2; die "$(basename "$b") doesn't verify offline"; }
    if [[ -z "$KEY" ]] && ! grep -Fq 'Bundle signature verified' "$WORK/verify.log"; then
      cat "$WORK/verify.log" >&2; die "The installer didn't check $(basename "$b")'s signature offline"
    fi
    log "$(basename "$b"): signature and every file verified with no network"
    push+=("$b") sums+=(--sha256 "$sum")
  done

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
