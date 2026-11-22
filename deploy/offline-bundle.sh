#!/usr/bin/env bash
# Offline bundles for air-gapped installs (docs/adr/0128-air-gapped-self-host.md,
# docs/ops/air-gapped.md). Made on a connected machine, carried in, installed with
# `install.sh --offline`, which checks it the same way `verify` does.
#   deploy/offline-bundle.sh build --out DIR [--version V] [--bin-dir DIR] [--client-dir DIR]
#                                  [--image NAME=REF]... [--image-identity ID] [--allow-unsigned]
#   deploy/offline-bundle.sh verify BUNDLE [--sha256 HEX]
#   deploy/offline-bundle.sh load BUNDLE [--sha256 HEX]      # docker load its images, no network
#   deploy/offline-bundle.sh push BUNDLE --registry HOST[:PORT][/PATH] [--sha256 HEX]
#                                  # copy its images to a registry mirror, digests unchanged
set -euo pipefail

DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
export SUPERBOT_INSTALL_NO_MAIN=1
# shellcheck source=install.sh source-path=SCRIPTDIR
source "$DIR/install.sh"

# Files deploy/docker needs for Compose with loaded images (no build).
DOCKER_FILES=(docker-compose.yml Caddyfile .env.example init.sh seccomp-chromium.json)
IMAGE_ISSUER=https://token.actions.githubusercontent.com

usage() {
  sed -n '2,10p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
}

# The repository root: the checkout this script is in (deploy/..).
repo_root() { cd "$DIR/.." && pwd; }

cargo_version() {
  awk -F'"' '/^\[package\]/ { p = 1; next } /^\[/ { p = 0 } p && /^version *=/ { print $2; exit }' "$1/server/Cargo.toml"
}

script_mode() { [[ "$1" == *.sh ]] && echo 0755 || echo 0644; }

# Copies a folder of plain files, refusing links and anything else.
copy_plain_tree() {
  local src=$1 dest=$2 odd
  [[ -d "$src" ]] || die "No folder $src"
  odd=$(find "$src" ! -type f ! -type d)
  [[ -z "$odd" ]] || die "Refusing $src: it holds links or special files:"$'\n'"$odd"
  mkdir -p "$dest"
  cp -R "$src/." "$dest/"
}

docker_arch() {
  case $1 in
    x86_64) echo amd64 ;;
    aarch64) echo arm64 ;;
    *) die "No Docker platform for $1" ;;
  esac
}

# Image references: [HOST[:PORT]/]PATH:TAG. A tag is required, so docker load can name what it
# loads and a mirror gets the same tag; a digest is not taken (the bundle records it).
image_ref_ok() { [[ "$1" =~ ^[a-z0-9][a-z0-9._/:-]*:[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$ && "$1" != *//* ]]; }
image_repo() { printf '%s\n' "${1%:*}"; }
image_tag() { printf '%s\n' "${1##*:}"; }
# REF as Docker and containerd name it: docker.io/library/ for one-word names, docker.io/ for
# paths without a registry host.
image_full_name() {
  local ref=$1 first=${1%%/*}
  if [[ "$ref" != */* ]]; then
    printf 'docker.io/library/%s\n' "$ref"
  elif [[ "$first" == *.* || "$first" == *:* || "$first" == localhost ]]; then
    printf '%s\n' "$ref"
  else
    printf 'docker.io/%s\n' "$ref"
  fi
}

skopeo_copy_args() {
  local help
  help=$(skopeo copy --help 2>&1 || true)
  SKOPEO_COPY=(skopeo copy -q)
  [[ "$help" != *--preserve-digests* ]] || SKOPEO_COPY+=(--preserve-digests)
}

# What REF names in its registry for linux/DOCKER_ARCH: IMAGE_TOP is REPO@ the digest REF points
# at (an index, or one image), which cosign checks; IMAGE_PLATFORM is REPO@ the image for this
# arch, which is bundled. Attestation entries in an index have no platform and are skipped.
resolve_registry_image() {
  local ref=$1 darch=$2 raw repo top digest got
  raw="$OFFLINE_TMP/raw.json"
  skopeo inspect --raw "docker://$ref" >"$raw" || die "Couldn't read $ref from its registry"
  top="sha256:$(sha256sum <"$raw" | awk '{ print $1 }')"
  repo=$(image_repo "$ref")
  if jq -e 'has("manifests")' "$raw" >/dev/null 2>&1; then
    digest=$(jq -r --arg a "$darch" \
      '[.manifests[] | select(.platform.os == "linux" and .platform.architecture == $a) | .digest][0] // empty' "$raw")
    [[ "$digest" =~ ^sha256:[0-9a-f]{64}$ ]] || die "$ref has no linux/$darch image"
  else
    digest=$top
    got=$(skopeo inspect "docker://$repo@$digest" | jq -r .Architecture) || die "Couldn't read $ref's config"
    [[ "$got" == "$darch" ]] || die "$ref is a $got image, not $darch"
  fi
  IMAGE_TOP="$repo@$top" IMAGE_PLATFORM="$repo@$digest"
}

# Copies SRC (a skopeo source, e.g. docker://REPO@DIGEST) into an OCI image layout, digests kept,
# and packs it as TAR with a Docker manifest.json beside its index.json: an OCI archive that
# skopeo, crane or regctl push to a registry unchanged, and that docker load reads. Prints the
# image's manifest digest.
oci_image_archive() {
  local src=$1 ref=$2 tar=$3 layout digest
  layout=$(mktemp -d "$OFFLINE_TMP/layout.XXXXXX")
  skopeo_copy_args
  "${SKOPEO_COPY[@]}" "$src" "oci:$layout:$(image_tag "$ref")" >/dev/null || die "Couldn't copy $ref into the bundle"
  digest=$(jq -r 'if (.manifests | length) == 1 then .manifests[0].digest else empty end' "$layout/index.json")
  [[ "$digest" =~ ^sha256:[0-9a-f]{64}$ && -f "$layout/blobs/sha256/${digest#sha256:}" ]] || die "Copying $ref didn't give one image"
  jq -c --arg ref "$ref" '[{
      Config: ("blobs/sha256/" + (.config.digest | ltrimstr("sha256:"))),
      RepoTags: [$ref],
      Layers: [.layers[].digest | "blobs/sha256/" + ltrimstr("sha256:")]
    }]' "$layout/blobs/sha256/${digest#sha256:}" >"$layout/manifest.json" || die "$ref's manifest isn't an image manifest"
  jq -c --arg name "$(image_full_name "$ref")" '.manifests[0].annotations["io.containerd.image.name"] = $name' \
    "$layout/index.json" >"$layout/index.json.new" && mv "$layout/index.json.new" "$layout/index.json"
  tar -C "$layout" --owner=0 --group=0 --numeric-owner --sort=name -cf "$tar" oci-layout index.json manifest.json blobs
  chmod 0644 "$tar"
  rm -rf -- "$layout"
  printf '%s\n' "$digest"
}

# NAME=REF: this arch's image, its cosign signature checked (unless --allow-unsigned), saved as
# an OCI archive with the registry's digests, with what the check printed (certificate, Rekor
# entry) and its SBOM beside it. An unsigned image of your own comes from the local Docker if
# it is there, else from its registry.
bundle_image() {
  local spec=$1 out=$2 arch=$3 identity=$4 unsigned=$5 name ref darch digest got
  name=${spec%%=*} ref=${spec#*=}
  [[ "$spec" == *=* && "$name" =~ ^[a-z0-9][a-z0-9-]*$ ]] || die "--image wants NAME=REF, e.g. superbot=ghcr.io/cg-labs/superbot:0.1.0"
  image_ref_ok "$ref" || die "--image $name: \"$ref\" isn't a tagged image reference (HOST/PATH:TAG, lowercase, no digest)"
  [[ ! -e "$out/images/$name.tar" ]] || die "--image $name is given twice"
  command -v skopeo >/dev/null 2>&1 || die "--image needs skopeo"
  command -v jq >/dev/null 2>&1 || die "--image needs jq"
  darch=$(docker_arch "$arch")
  mkdir -p "$out/images"
  if [[ "$unsigned" != true ]]; then
    command -v cosign >/dev/null 2>&1 || die "cosign is needed to check $ref's signature (or --allow-unsigned for an image of your own)"
    command -v docker >/dev/null 2>&1 || die "--image needs docker (buildx) to read $ref's SBOM"
    resolve_registry_image "$ref" "$darch"
    cosign verify "$IMAGE_TOP" --certificate-identity "$identity" --certificate-oidc-issuer "$IMAGE_ISSUER" \
      --output json >"$out/images/$name.cosign.json" || die "$ref isn't signed by $identity: not bundling it"
    log "Signature checked: $IMAGE_TOP, signed by $identity"
    docker buildx imagetools inspect "$IMAGE_TOP" --format "{{ json (index .SBOM \"linux/$darch\").SPDX }}" >"$out/images/$name.sbom.spdx.json" \
      || die "Couldn't read $ref's SBOM"
    digest=$(oci_image_archive "docker://$IMAGE_PLATFORM" "$ref" "$out/images/$name.tar")
    [[ "$digest" == "${IMAGE_PLATFORM#*@}" ]] || die "Copying $ref changed its digest ($digest, not ${IMAGE_PLATFORM#*@}): not bundling it"
  else
    warn "Bundling $ref without checking a signature (--allow-unsigned)"
    if command -v docker >/dev/null 2>&1 && docker image inspect "$ref" >/dev/null 2>&1; then
      got=$(docker image inspect --format '{{.Architecture}}' "$ref")
      [[ "$got" == "$darch" ]] || die "$ref is a $got image, not $darch"
      # Through docker save rather than skopeo's docker-daemon: source, whose Docker API
      # version newer Docker engines refuse.
      docker save -o "$OFFLINE_TMP/saved.tar" "$ref" || die "docker save failed for $ref"
      digest=$(oci_image_archive "docker-archive:$OFFLINE_TMP/saved.tar" "$ref" "$out/images/$name.tar")
      rm -f -- "$OFFLINE_TMP/saved.tar"
    else
      resolve_registry_image "$ref" "$darch"
      digest=$(oci_image_archive "docker://$IMAGE_PLATFORM" "$ref" "$out/images/$name.tar")
    fi
  fi
  printf '%s\n' "$ref" >"$out/images/$name.ref"
  printf '%s\n' "$digest" >"$out/images/$name.digest"
  log "Bundled $ref as $digest (linux/$darch)"
}

cmd_build() {
  local out="" version="" root bin_dir client_dir arch identity="" unsigned=false images=() stage top f commit name
  root=$(repo_root)
  bin_dir="$root/target/release"
  client_dir="$root/apps/client/dist-app"
  arch=$(uname -m)
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --out) out=$2; shift 2 ;;
      --version) version=$2; shift 2 ;;
      --bin-dir) bin_dir=$2; shift 2 ;;
      --client-dir) client_dir=$2; shift 2 ;;
      --arch) arch=$2; shift 2 ;;
      --image) images+=("$2"); shift 2 ;;
      --image-identity) identity=$2; shift 2 ;;
      --allow-unsigned) unsigned=true; shift ;;
      -h|--help) usage; exit 0 ;;
      *) die "Unknown option: $1" ;;
    esac
  done
  [[ -n "$out" ]] || die "build needs --out DIR"
  version=${version:-$(cargo_version "$root")}
  [[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.+-]+)?$ ]] || die "--version \"$version\" isn't a version"
  [[ "$arch" =~ ^(x86_64|aarch64)$ ]] || die "--arch must be x86_64 or aarch64"
  identity=${identity:-https://github.com/CG-Labs/superbot/.github/workflows/docker.yml@refs/tags/v$version}
  commit=$(git -C "$root" rev-parse HEAD 2>/dev/null || echo unknown)

  top="superbot-offline-$version-$arch"
  OFFLINE_TMP=$(mktemp -d)
  trap cleanup_offline EXIT
  stage="$OFFLINE_TMP/$top"
  mkdir -p "$stage/bin" "$stage/deploy" "$stage/docker"

  for f in "${OFFLINE_BINARIES[@]}"; do
    [[ -f "$bin_dir/$f" && -x "$bin_dir/$f" ]] || die "No $bin_dir/$f: run cargo build --release first (or give --bin-dir)"
    install -m 0755 "$bin_dir/$f" "$stage/bin/$f"
  done
  for f in "${DEPLOY_FILES[@]}" install.sh offline-bundle.sh; do
    install -m "$(script_mode "$f")" "$root/deploy/$f" "$stage/deploy/$f"
  done
  for f in "${DOCKER_FILES[@]}"; do
    install -m "$(script_mode "$f")" "$root/deploy/docker/$f" "$stage/docker/$f"
  done
  install -m 0644 "$root/.env.example" "$stage/env.example"
  copy_plain_tree "$root/site" "$stage/site"
  [[ -f "$client_dir/index.html" ]] || die "No web client in $client_dir: build it with SUPERBOT_WEB_BASE_URL=/app npx expo export --platform web --output-dir dist-app (in apps/client)"
  grep -q '/app/_expo/static/' "$client_dir/index.html" || die "$client_dir wasn't built for /app/: set SUPERBOT_WEB_BASE_URL=/app when exporting it"
  copy_plain_tree "$client_dir" "$stage/client"

  local names=()
  for f in "${images[@]}"; do
    bundle_image "$f" "$stage" "$arch" "$identity" "$unsigned"
    names+=("${f%%=*}")
  done

  {
    echo format=1
    echo "version=$version"
    echo "arch=$arch"
    echo "commit=$commit"
    echo "created=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "images=${names[*]}"
    [[ ${#names[@]} -eq 0 ]] || echo "image_format=oci"
    [[ "$unsigned" != true || ${#names[@]} -eq 0 ]] || echo "unsigned_images=true"
  } >"$stage/MANIFEST"
  (cd "$stage" && find . -type f -printf '%P\n' | LC_ALL=C sort | xargs -d '\n' sha256sum) >"$OFFLINE_TMP/SHA256SUMS"
  mv "$OFFLINE_TMP/SHA256SUMS" "$stage/SHA256SUMS"

  mkdir -p "$out"
  name="$top.tar.gz"
  tar -C "$OFFLINE_TMP" --owner=0 --group=0 --numeric-owner --sort=name -czf "$out/$name" "$top"
  (cd "$out" && sha256sum "$name" >"$name.sha256")
  log "Bundle: $out/$name"
  log "SHA-256: $(awk '{ print $1 }' "$out/$name.sha256") (publish this where the operator can check it)"
}

# BUNDLE [--sha256 HEX]: checks it as install.sh --offline does, into a temporary folder.
verify_args() {
  [[ $# -ge 1 ]] || die "Give the bundle"
  BUNDLE=$1
  shift
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --sha256) OFFLINE_BUNDLE_SHA256=$2; shift 2 ;;
      --registry) [[ "${ALLOW_REGISTRY:-}" == 1 ]] || die "--registry is for push"; PUSH_REGISTRY=$2; shift 2 ;;
      *) die "Unknown option: $1" ;;
    esac
  done
  [[ -f "$BUNDLE" ]] || die "No bundle at $BUNDLE"
  [[ -z "$OFFLINE_BUNDLE_SHA256" || "$OFFLINE_BUNDLE_SHA256" =~ ^[0-9a-f]{64}$ ]] || die "--sha256 must be 64 lowercase hex digits"
  OFFLINE_TMP=$(mktemp -d)
  trap cleanup_offline EXIT
}

cmd_verify() {
  verify_args "$@"
  OFFLINE_ANY_ARCH=1 offline_unpack_bundle "$BUNDLE" "$OFFLINE_TMP"
  sed 's/^/    /' "$OFFLINE_DIR/MANIFEST"
  log "$BUNDLE is a good bundle"
}

cmd_load() {
  verify_args "$@"
  command -v docker >/dev/null 2>&1 || die "load needs docker"
  offline_unpack_bundle "$BUNDLE" "$OFFLINE_TMP"
  local tar name ref found=false
  for tar in "$OFFLINE_DIR"/images/*.tar; do
    [[ -f "$tar" ]] || continue
    found=true
    name=$(basename "$tar" .tar)
    ref=$(cat "$OFFLINE_DIR/images/$name.ref")
    docker load -q -i "$tar" >/dev/null || die "docker load failed for $name"
    docker image inspect "$ref" >/dev/null 2>&1 || die "$name loaded, but $ref isn't there"
    if [[ -f "$OFFLINE_DIR/images/$name.cosign.json" ]]; then
      log "Loaded $ref ($(cat "$OFFLINE_DIR/images/$name.digest"), signature checked when bundled)"
    else
      warn "Loaded $ref: unsigned (bundled with --allow-unsigned)"
    fi
  done
  [[ "$found" == true ]] || die "This bundle has no images: it is for install.sh --offline only"
  log "Run Compose from the bundle's docker/ folder with SUPERBOT_VERSION=$OFFLINE_VERSION in .env (docs/ops/air-gapped.md#docker-compose)"
}

# A registry and optional path to push under: a host (with a dot or a port, or localhost), then
# lowercase path components.
registry_ok() {
  local first=${1%%/*}
  [[ "$1" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?(:[0-9]+)?(/[a-z0-9]+([._-][a-z0-9]+)*)*$ ]] || return 1
  [[ "$first" == *.* || "$first" == *:* || "$first" == localhost ]]
}

# The Compose .env setting for a bundled image, by its NAME.
compose_image_var() {
  case $1 in
    superbot) echo SUPERBOT_IMAGE ;;
    caddy) echo SUPERBOT_CADDY_IMAGE ;;
  esac
}

# Copies each image to REGISTRY/<its repository's last part>:<its tag> from the OCI archive, as it
# is: the registry ends up with the digest the bundle recorded (the one whose signature was
# checked when it was bundled), and that is checked after the push.
cmd_push() {
  local PUSH_REGISTRY=""
  ALLOW_REGISTRY=1 verify_args "$@"
  [[ -n "$PUSH_REGISTRY" ]] || die "push needs --registry HOST[:PORT][/PATH], e.g. --registry registry.corp.example/superbot"
  registry_ok "$PUSH_REGISTRY" || die "--registry \"$PUSH_REGISTRY\" isn't HOST[:PORT][/path] (a host with a dot or a port, or localhost; a lowercase path)"
  command -v skopeo >/dev/null 2>&1 || die "push needs skopeo (docs/ops/air-gapped.md#registry-mirrors)"
  OFFLINE_ANY_ARCH=1 offline_unpack_bundle "$BUNDLE" "$OFFLINE_TMP"
  [[ -n "$(manifest_value "$OFFLINE_DIR/MANIFEST" images)" ]] || die "This bundle has no images: it is for install.sh --offline only"
  [[ "$(manifest_value "$OFFLINE_DIR/MANIFEST" image_format)" == oci ]] \
    || die "This bundle's images are docker save archives, which a registry can't take with their digests: use a bundle made by a newer offline-bundle.sh, or docker load and docker push"
  local tar name ref want dest got var arch envs=()
  arch=$(manifest_value "$OFFLINE_DIR/MANIFEST" arch)
  skopeo_copy_args
  for tar in "$OFFLINE_DIR"/images/*.tar; do
    [[ -f "$tar" ]] || continue
    name=$(basename "$tar" .tar)
    ref=$(cat "$OFFLINE_DIR/images/$name.ref")
    want=$(cat "$OFFLINE_DIR/images/$name.digest")
    if ! image_ref_ok "$ref" || [[ ! "$want" =~ ^sha256:[0-9a-f]{64}$ ]]; then
      die "Refusing $BUNDLE: images/$name.ref or .digest isn't one"
    fi
    dest="$PUSH_REGISTRY/$(basename "$(image_repo "$ref")"):$(image_tag "$ref")"
    "${SKOPEO_COPY[@]}" "oci-archive:$tar" "docker://$dest" >/dev/null || die "Couldn't push $name to $dest"
    skopeo inspect --raw "docker://$dest" >"$OFFLINE_TMP/pushed.json" || die "Couldn't read $dest back from the registry"
    got="sha256:$(sha256sum <"$OFFLINE_TMP/pushed.json" | awk '{ print $1 }')"
    [[ "$got" == "$want" ]] || die "$dest is $got after the push, not the bundle's $want: don't use it"
    log "Pushed $ref to $dest ($want, linux/$(docker_arch "$arch"))"
    var=$(compose_image_var "$name")
    [[ -z "$var" ]] || envs+=("$var=$(image_repo "$dest")@$want")
  done
  if [[ ${#envs[@]} -gt 0 ]]; then
    log "For Compose, pin these in .env (docs/ops/air-gapped.md#registry-mirrors):"
    printf '    %s\n' "${envs[@]}"
  fi
}

case "${1:-}" in
  build) shift; cmd_build "$@" ;;
  verify) shift; cmd_verify "$@" ;;
  load) shift; cmd_load "$@" ;;
  push) shift; cmd_push "$@" ;;
  -h|--help|"") usage ;;
  *) die "Unknown command: $1 (build, verify, load or push)" ;;
esac
