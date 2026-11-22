#!/usr/bin/env bash
# Offline bundles for air-gapped installs (docs/adr/0128-air-gapped-self-host.md,
# docs/ops/air-gapped.md). Made on a connected machine, carried in, installed with
# `install.sh --offline`, which checks it the same way `verify` does.
#   deploy/offline-bundle.sh build --out DIR [--version V] [--bin-dir DIR] [--client-dir DIR]
#                                  [--image NAME=REF]... [--image-identity ID] [--allow-unsigned]
#   deploy/offline-bundle.sh verify BUNDLE [--sha256 HEX]
#   deploy/offline-bundle.sh load BUNDLE [--sha256 HEX]      # docker load its images, no network
set -euo pipefail

DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
export SUPERBOT_INSTALL_NO_MAIN=1
# shellcheck source=install.sh source-path=SCRIPTDIR
source "$DIR/install.sh"

# Files deploy/docker needs for Compose with loaded images (no build).
DOCKER_FILES=(docker-compose.yml Caddyfile .env.example init.sh seccomp-chromium.json)
IMAGE_ISSUER=https://token.actions.githubusercontent.com

usage() {
  sed -n '2,8p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
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

# NAME=REF: pulled for this arch, its cosign signature checked (unless --allow-unsigned), saved
# for `docker load`, with what the check printed (certificate, Rekor entry) and its SBOM beside it.
bundle_image() {
  local spec=$1 out=$2 arch=$3 identity=$4 unsigned=$5 name ref platform pinned
  name=${spec%%=*} ref=${spec#*=}
  [[ "$spec" == *=* && "$name" =~ ^[a-z0-9][a-z0-9-]*$ && -n "$ref" ]] || die "--image wants NAME=REF, e.g. superbot=ghcr.io/cg-labs/superbot:0.1.0"
  command -v docker >/dev/null 2>&1 || die "--image needs docker"
  platform="linux/$(docker_arch "$arch")"
  mkdir -p "$out/images"
  if [[ "$unsigned" != true ]]; then
    command -v cosign >/dev/null 2>&1 || die "cosign is needed to check $ref's signature (or --allow-unsigned for an image of your own)"
    log "Pulling $ref ($platform)"
    docker pull -q --platform "$platform" "$ref" >/dev/null
    pinned=$(docker image inspect --format '{{index .RepoDigests 0}}' "$ref")
    [[ "$pinned" == *@sha256:* ]] || die "No registry digest for $ref"
    cosign verify "$pinned" --certificate-identity "$identity" --certificate-oidc-issuer "$IMAGE_ISSUER" \
      --output json >"$out/images/$name.cosign.json" || die "$ref isn't signed by $identity: not bundling it"
    log "Signature checked: $pinned, signed by $identity"
    docker buildx imagetools inspect "$pinned" --format "{{ json (index .SBOM \"$platform\").SPDX }}" >"$out/images/$name.sbom.spdx.json" \
      || die "Couldn't read $ref's SBOM"
    printf '%s\n' "$pinned" >"$out/images/$name.digest"
  else
    docker image inspect "$ref" >/dev/null 2>&1 || docker pull -q --platform "$platform" "$ref" >/dev/null
    warn "Bundling $ref without checking a signature (--allow-unsigned)"
    docker image inspect --format '{{.Id}}' "$ref" >"$out/images/$name.digest"
  fi
  printf '%s\n' "$ref" >"$out/images/$name.ref"
  docker save -o "$out/images/$name.tar" "$ref"
  chmod 0644 "$out/images/$name.tar"
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

case "${1:-}" in
  build) shift; cmd_build "$@" ;;
  verify) shift; cmd_verify "$@" ;;
  load) shift; cmd_load "$@" ;;
  -h|--help|"") usage ;;
  *) die "Unknown command: $1 (build, verify or load)" ;;
esac
