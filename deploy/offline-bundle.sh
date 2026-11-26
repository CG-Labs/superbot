#!/usr/bin/env bash
# Offline bundles for air-gapped installs (docs/adr/0128-air-gapped-self-host.md,
# docs/ops/air-gapped.md). Made on a connected machine, carried in, installed with
# `install.sh --offline`, which checks it the same way `verify` does.
#   deploy/offline-bundle.sh build --out DIR [--version V] [--bin-dir DIR] [--client-dir DIR] [--arch A]
#                                  [--image NAME=REF]... [--image-identity ID | --image-key FILE] [--allow-unsigned]
#   deploy/offline-bundle.sh hermes --out DIR [--tree /opt/hermes]
#                                  # a Hermes bundle: Hermes Agent at the pinned commit, installed here for
#                                  # /opt/hermes (as root, connected), for install.sh --offline --with-hermes
#   deploy/offline-bundle.sh harnesses --out DIR [--version V] [--bin-dir DIR] [--tree /opt/superbot-harnesses]
#                                  # a harness bundle: Node.js, Claude Code, Codex and Pi at the pins of
#                                  # --bin-dir's botd, installed here for /opt/superbot-harnesses (connected),
#                                  # for install.sh --offline --harness-bundle
#   deploy/offline-bundle.sh verify BUNDLE [--sha256 HEX]   # an offline, Hermes or harness bundle
#   deploy/offline-bundle.sh load BUNDLE [--sha256 HEX] [-- COMPOSE_OPTION...]
#                                  # docker load its images, no network; in a Compose stack's folder,
#                                  # then check-compose with the loaded image
#   deploy/offline-bundle.sh check-compose [--image REF] [--key-file FILE] [-- COMPOSE_OPTION...]
#                                  # whether botd from REF (else the image Compose would run) would start
#                                  # with the stack's settings and run Bots with its license, before you switch
#   deploy/offline-bundle.sh backup-compose [--dir DIR] [-- COMPOSE_OPTION...]
#                                  # a rollback point before you switch: the running botd's backup, kept in DIR
#                                  # (default ./superbot-rollback) with the image it was taken on
#   deploy/offline-bundle.sh rollback-compose [--dir DIR] [--identity FILE] [-- COMPOSE_OPTION...]
#                                  # once .env names that image again: restore the rollback point and start on it
#   deploy/offline-bundle.sh load-hermes HERMES_BUNDLE [--sha256 HEX] [--image REF] [--env-file FILE] [--volume NAME]
#                                  # Hermes Agent for Compose: the checked tree in a Docker volume,
#                                  # for the pin of the image Compose runs, mounted by docker-compose.hermes.yml
#   deploy/offline-bundle.sh push BUNDLE... --registry HOST[:PORT][/PATH] [--sha256 HEX]...
#                                  # copy its images, signatures and attestations to a registry mirror,
#                                  # digests unchanged; one bundle per arch puts up the signed multi-arch index
set -euo pipefail

DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
export SUPERBOT_INSTALL_NO_MAIN=1
# shellcheck source=install.sh source-path=SCRIPTDIR
source "$DIR/install.sh"

# Files deploy/docker needs for Compose with loaded images (no build).
DOCKER_FILES=(docker-compose.yml docker-compose.hermes.yml Caddyfile .env.example init.sh seccomp-chromium.json)
IMAGE_ISSUER=https://token.actions.githubusercontent.com
# load-hermes's volume, once the tree in it has run: Compose mounts only a volume that has it.
HERMES_VOLUME_MARK=.superbot-hermes
# Set while load-hermes fills a volume it made, so a failure removes it.
HERMES_VOLUME_NEW=""

usage() {
  sed -n '2,31p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
}

# The first of SUPERBOT_OCI and CANDIDATES (then superbot-oci on PATH) that runs here: one
# built for another arch doesn't. superbot-oci copies the signatures and attestations, which
# skopeo can't (docs/adr/0147-signatures-and-multi-arch-indexes-in-mirrors.md).
find_oci() {
  local c
  for c in "${SUPERBOT_OCI:-}" "$@" "$(command -v superbot-oci 2>/dev/null || true)"; do
    [[ -n "$c" && -f "$c" && -x "$c" ]] || continue
    if "$c" --version >/dev/null 2>&1; then
      printf '%s\n' "$c"
      return 0
    fi
  done
  return 1
}

# Unpacks an OCI layout TAR from a checked bundle into DEST, if it is plain files and folders.
untar_layout() {
  local tar=$1 dest=$2 entries names
  entries=$(tar -tvf "$tar" 2>/dev/null) || die "Couldn't read $tar"
  names=$(tar -tf "$tar" 2>/dev/null) || die "Couldn't read $tar"
  local bad=false
  awk '{ t = substr($0, 1, 1) } t != "-" && t != "d" { bad = 1 } END { exit bad }' <<<"$entries" || bad=true
  if grep -Eq '^/|(^|/)\.\.(/|$)' <<<"$names"; then bad=true; fi
  [[ "$bad" == false ]] || die "Refusing $tar: it holds links, special files or paths outside it"
  mkdir -p "$dest"
  tar -xf "$tar" -C "$dest" --no-same-owner --no-same-permissions || die "Couldn't unpack $tar"
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
# entry) and its SBOM beside it, and its signatures and attestations (an OCI layout, for push)
# in signatures/NAME.tar.
# With KEY, the signature is checked against that public key instead of IDENTITY. An unsigned
# image of your own comes from the local Docker if it is there, else from its registry.
bundle_image() {
  local spec=$1 out=$2 arch=$3 identity=$4 unsigned=$5 key=$6 name ref darch digest got signer sigs
  local check=(--certificate-identity "$identity" --certificate-oidc-issuer "$IMAGE_ISSUER")
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
    signer=$identity
    if [[ -n "$key" ]]; then
      # A key's signatures have no transparency log entry to check: the key is the trust.
      check=(--key "$key" --insecure-ignore-tlog=true)
      signer="the key in $key"
    fi
    resolve_registry_image "$ref" "$darch"
    cosign verify "$IMAGE_TOP" "${check[@]}" --output json >"$out/images/$name.cosign.json" || die "$ref isn't signed by $signer: not bundling it"
    log "Signature checked: $IMAGE_TOP, signed by $signer"
    docker buildx imagetools inspect "$IMAGE_TOP" --format "{{ json (index .SBOM \"linux/$darch\").SPDX }}" >"$out/images/$name.sbom.spdx.json" \
      || die "Couldn't read $ref's SBOM"
    digest=$(oci_image_archive "docker://$IMAGE_PLATFORM" "$ref" "$out/images/$name.tar")
    [[ "$digest" == "${IMAGE_PLATFORM#*@}" ]] || die "Copying $ref changed its digest ($digest, not ${IMAGE_PLATFORM#*@}): not bundling it"
    sigs=$(mktemp -d "$OFFLINE_TMP/signatures.XXXXXX")
    rmdir "$sigs"
    "$OCI_TOOL" fetch --from "$(image_full_name "$IMAGE_TOP")" --image "$digest" --out "$sigs" \
      || die "Couldn't copy $ref's signatures and attestations into the bundle"
    # Beside images/, not in it: an older offline-bundle.sh would docker load any images/*.tar.
    mkdir -p "$out/signatures"
    tar -C "$sigs" --owner=0 --group=0 --numeric-owner --sort=name -cf "$out/signatures/$name.tar" oci-layout index.json blobs
    chmod 0644 "$out/signatures/$name.tar"
    rm -rf -- "$sigs"
    # The signed index the image came from, which push puts up when it has every arch's bundle.
    [[ "$IMAGE_TOP" == "$IMAGE_PLATFORM" ]] || printf '%s\n' "${IMAGE_TOP#*@}" >"$out/images/$name.index"
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
  local out="" version="" root bin_dir client_dir arch identity="" key="" unsigned=false images=() stage top f commit name
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
      --image-key) key=$2; shift 2 ;;
      --allow-unsigned) unsigned=true; shift ;;
      -h|--help) usage; exit 0 ;;
      *) die "Unknown option: $1" ;;
    esac
  done
  [[ -n "$out" ]] || die "build needs --out DIR"
  version=${version:-$(cargo_version "$root")}
  [[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.+-]+)?$ ]] || die "--version \"$version\" isn't a version"
  [[ "$arch" =~ ^(x86_64|aarch64)$ ]] || die "--arch must be x86_64 or aarch64"
  [[ -z "$key" || -z "$identity" ]] || die "Give --image-identity or --image-key, not both"
  [[ -z "$key" || -f "$key" ]] || die "--image-key: no file at $key"
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
  # superbot-oci goes with the images, for push on the mirror's side; the installer doesn't use it.
  if [[ ${#images[@]} -gt 0 ]]; then
    [[ -f "$bin_dir/superbot-oci" && -x "$bin_dir/superbot-oci" ]] || die "No $bin_dir/superbot-oci, which a bundle with images carries: cargo build --release --bin superbot-oci"
  fi
  [[ ! -f "$bin_dir/superbot-oci" ]] || install -m 0755 "$bin_dir/superbot-oci" "$stage/bin/superbot-oci"
  if [[ ${#images[@]} -gt 0 && "$unsigned" != true ]]; then
    OCI_TOOL=$(find_oci "$bin_dir/superbot-oci") \
      || die "No superbot-oci runs on this machine to copy the images' signatures ($bin_dir/superbot-oci is for $arch): set SUPERBOT_OCI to one built for $(uname -m)"
  fi
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
    bundle_image "$f" "$stage" "$arch" "$identity" "$unsigned" "$key"
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
      --registry) die "--registry is for push" ;;
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
  if offline_archive_ok "$BUNDLE" superbot-hermes >/dev/null; then
    OFFLINE_ANY_ARCH=1 hermes_unpack_bundle "$BUNDLE" "$OFFLINE_TMP" "$OFFLINE_BUNDLE_SHA256"
    sed 's/^/    /' "$HERMES_BUNDLE_DIR/MANIFEST"
    log "$BUNDLE is a good Hermes bundle"
    return
  fi
  if offline_archive_ok "$BUNDLE" superbot-harnesses >/dev/null; then
    OFFLINE_ANY_ARCH=1 harness_unpack_bundle "$BUNDLE" "$OFFLINE_TMP" "$OFFLINE_BUNDLE_SHA256"
    sed 's/^/    /' "$HARNESS_BUNDLE_DIR/MANIFEST"
    log "$BUNDLE is a good harness bundle"
    return
  fi
  OFFLINE_ANY_ARCH=1 offline_unpack_bundle "$BUNDLE" "$OFFLINE_TMP"
  sed 's/^/    /' "$OFFLINE_DIR/MANIFEST"
  log "$BUNDLE is a good bundle"
}

# The value of FIELD in server/src/adapters/install.rs's pin for BIN, as
# deploy/install-harness-clis.sh reads it.
harness_pin() {
  local pins v
  pins="$(repo_root)/server/src/adapters/install.rs"
  [[ -f "$pins" ]] || die "No $pins: run hermes from a checkout of the release tag"
  v=$(awk -v bin="$1" -v field="$2" '
    index($0, "bin: \"" bin "\"") { found = 1 }
    found && index($0, field ": \"") { sub(".*" field ": \"", ""); sub("\".*", ""); print; exit }
  ' "$pins")
  [[ -n "$v" ]] || die "No $2 for $1 in $pins"
  printf '%s\n' "$v"
}

# Hermes Agent's pinned installer, run as root with HOME=$HERMES_SHARED_DIR as install.sh
# --with-hermes runs it, but in a mount namespace of its own whose $HERMES_SHARED_DIR is TREE,
# so this machine's own /opt is never touched. Then hermes-share.sh, and hermes --version with
# no network, as a Bot would run it.
hermes_install_tree() {
  local tree=$1 commit=$2 sha=$3 installer
  [[ "${EUID:-$(id -u)}" -eq 0 ]] || die "hermes installs Hermes Agent for $HERMES_SHARED_DIR, so it runs as root: sudo $0 hermes ... (or give --tree)"
  local c
  for c in curl git unshare mount sha256sum; do command -v "$c" >/dev/null 2>&1 || die "hermes needs $c"; done
  installer="$OFFLINE_TMP/hermes-install.sh"
  curl -fsSL --retry 3 "https://raw.githubusercontent.com/NousResearch/hermes-agent/$commit/scripts/install.sh" -o "$installer" \
    || die "Couldn't download Hermes Agent's installer for $commit"
  printf '%s  %s\n' "$sha" "$installer" | sha256sum -c --quiet - || die "Hermes Agent's installer doesn't match the pinned SHA-256 ($sha)"
  # Copied out first: the namespace's $HERMES_SHARED_DIR parent is empty, and this checkout may be under it.
  install -m 0644 "$DIR/hermes-share.sh" "$OFFLINE_TMP/hermes-share.sh"
  log "Installing Hermes Agent ${commit:0:12} for $HERMES_SHARED_DIR (in a mount namespace of its own; about 2.5 GB)"
  # shellcheck disable=SC2016 # expanded by the inner bash
  unshare --mount --propagation private -- bash -euo pipefail -c '
    tree=$1 dest=$2 installer=$3 share=$4 commit=$5
    path=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
    mount -t tmpfs -o mode=0755 superbot-hermes "$(dirname "$dest")"
    mkdir "$dest"
    mount --bind "$tree" "$dest"
    env -i HOME="$dest" SHELL=/bin/bash PATH="$path" LANG=C.UTF-8 TERM=dumb \
      bash "$installer" --non-interactive --skip-browser --skip-computer-use --commit "$commit"
    env -i HOME="$dest" PATH="$path" sh "$share" >/dev/null
    probe=$(mktemp -d)
    unshare --net -- env -i HOME="$probe" HERMES_HOME="$probe/hermes" PATH="$path" "$dest/.hermes/superbot/hermes" --version
    rm -rf "$probe"
  ' _ "$tree" "$HERMES_SHARED_DIR" "$installer" "$OFFLINE_TMP/hermes-share.sh" "$commit" \
    || die "Hermes Agent didn't install, or didn't run with no network"
}

# A Hermes bundle: Hermes Agent at the pinned commit, as its own installer leaves it with
# HOME=$HERMES_SHARED_DIR, for install.sh --offline --with-hermes --hermes-bundle. Its Python,
# packages and Node.js tools are inside that folder and its links point inside it, so it runs
# there, and only there, with no network. Caches are left out.
cmd_hermes() {
  local out="" tree="" arch commit tag sha top stage name parent skip excludes=()
  local unbundled=(.cache .hermes/cache/uv .hermes/cache/pnpm)
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --out) out=$2; shift 2 ;;
      --tree) tree=$2; shift 2 ;;
      -h|--help) usage; exit 0 ;;
      *) die "Unknown option: $1" ;;
    esac
  done
  [[ -n "$out" ]] || die "hermes needs --out DIR"
  arch=$(uname -m)
  [[ "$arch" =~ ^(x86_64|aarch64)$ ]] || die "Hermes bundles are for x86_64 or aarch64, not $arch"
  commit=$(harness_pin hermes version) tag=$(harness_pin hermes tag) sha=$(harness_pin hermes sha256)
  [[ "$commit" == "$HERMES_COMMIT" ]] || die "install.sh pins Hermes Agent $HERMES_COMMIT, but server/src/adapters/install.rs pins $commit: bundle the pinned one (unset HERMES_COMMIT)"
  [[ "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "Hermes Agent's pinned tag \"$tag\" isn't a stable release"
  OFFLINE_TMP=$(mktemp -d)
  trap cleanup_offline EXIT
  chmod 0755 "$OFFLINE_TMP"
  if [[ -z "$tree" ]]; then
    parent="$OFFLINE_TMP/root"
    install -d -m 0755 "$parent/hermes"
    hermes_install_tree "$parent/hermes" "$commit" "$sha"
  else
    [[ "$(basename "$tree")" == hermes && -d "$tree" ]] || die "--tree must be a folder named hermes, as $HERMES_SHARED_DIR is"
    parent=$(cd "$(dirname "$tree")" && pwd)
  fi
  [[ "$(hermes_installed "$parent/hermes")" == "$commit" ]] || die "$parent/hermes isn't Hermes Agent $commit"
  if ! compgen -G "$parent/hermes/.hermes/installs/*/facts.json" >/dev/null \
    || ! grep -qF "\"$HERMES_SHARED_DIR/.hermes/installs/" "$parent"/hermes/.hermes/installs/*/facts.json; then
    die "$parent/hermes wasn't installed for $HERMES_SHARED_DIR (its installs/*/facts.json name another place), so it wouldn't run there"
  fi
  [[ -x "$parent/hermes/.hermes/superbot/hermes" ]] || die "$parent/hermes has no .hermes/superbot/hermes: run deploy/hermes-share.sh with HOME=$HERMES_SHARED_DIR"

  bundle_tree_ok "$parent/hermes" "$HERMES_SHARED_DIR" "${unbundled[@]}" || die "Not bundling $parent/hermes: $BUNDLE_TREE_PROBLEM"

  top="superbot-hermes-$tag-$arch"
  stage="$OFFLINE_TMP/$top"
  mkdir -p "$stage"
  log "Packing Hermes Agent $tag"
  for skip in "${unbundled[@]}"; do excludes+=("--exclude=hermes/$skip"); done
  tar -C "$parent" --owner=0 --group=0 --numeric-owner --sort=name --anchored "${excludes[@]}" \
    -cf "$stage/hermes.tar" hermes || die "Couldn't pack $parent/hermes"
  if [[ -z "$tree" ]]; then rm -rf -- "$parent"; fi
  bundle_tar_ok "$stage/hermes.tar" || die "Not bundling $parent/hermes: $BUNDLE_TREE_PROBLEM"
  {
    echo format=1
    echo kind=hermes
    echo "hermes_tag=$tag"
    echo "hermes_commit=$commit"
    echo "prefix=$HERMES_SHARED_DIR"
    echo "arch=$arch"
    echo "commit=$(git -C "$(repo_root)" rev-parse HEAD 2>/dev/null || echo unknown)"
    echo "created=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  } >"$stage/MANIFEST"
  (cd "$stage" && sha256sum hermes.tar MANIFEST) >"$OFFLINE_TMP/SHA256SUMS"
  mv "$OFFLINE_TMP/SHA256SUMS" "$stage/SHA256SUMS"
  mkdir -p "$out"
  name="$top.tar.gz"
  tar -C "$OFFLINE_TMP" --owner=0 --group=0 --numeric-owner --sort=name -czf "$out/$name" "$top"
  (cd "$out" && sha256sum "$name" >"$name.sha256")
  log "Hermes bundle: $out/$name"
  log "SHA-256: $(awk '{ print $1 }' "$out/$name.sha256") (publish this where the operator can check it)"
}

# Runs a command from a harness tree being bundled, with no network when this is root, and a
# HOME of its own, so a CLI's --version writes nothing of the builder's.
harness_probe() {
  local home="$OFFLINE_TMP/probe-home"
  mkdir -p "$home"
  if [[ "${EUID:-$(id -u)}" -eq 0 ]] && command -v unshare >/dev/null 2>&1; then
    unshare --net -- env HOME="$home" "$@"
  else
    env HOME="$home" "$@"
  fi
}

# Node.js for ARCH at PINS, checked against its pinned SHA-256, with each npm harness PINS
# names installed into it at its pinned version, as machines install them (ADR 0039): npm packs
# the package, its tarball is checked against the pinned integrity, and npm installs that file
# with the registry's hashes for its dependencies. npm's registry and login are the builder's
# own npm settings; its cache is left out of the tree.
harness_install_tree() {
  local tree=$1 pins=$2 arch=$3 c node sha dist url bin version package integrity file got cache dl
  for c in curl tar xz sha256sum openssl base64 jq; do command -v "$c" >/dev/null 2>&1 || die "harnesses needs $c"; done
  read -r node sha < <(awk -v a="$arch" '$1 == "node" && $3 == a { print $2, $4 }' <<<"$pins")
  [[ -n "$node" && -n "$sha" ]] || die "botd pins no Node.js for $arch"
  case $arch in x86_64) dist=x64 ;; aarch64) dist=arm64 ;; esac
  url="https://nodejs.org/dist/v$node/node-v$node-linux-$dist.tar.xz"
  log "Downloading Node.js $node for $arch"
  curl -fsSL --retry 3 "$url" -o "$OFFLINE_TMP/node.tar.xz" || die "Couldn't download $url"
  printf '%s  %s\n' "$sha" "$OFFLINE_TMP/node.tar.xz" | sha256sum -c --quiet - || die "Node.js $node for $arch doesn't match the pinned SHA-256 ($sha)"
  tar -xJf "$OFFLINE_TMP/node.tar.xz" -C "$tree" --strip-components=1 --no-same-owner || die "Couldn't unpack Node.js $node"
  rm -f -- "$OFFLINE_TMP/node.tar.xz"
  cache="$OFFLINE_TMP/npm-cache" dl="$OFFLINE_TMP/npm-packs"
  mkdir -p "$cache" "$dl"
  export npm_config_update_notifier=false
  while read -r bin version package integrity; do
    log "Installing $package@$version ($bin)"
    file=$(cd "$dl" && PATH="$tree/bin:$PATH" npm pack "$package@$version" --json --cache "$cache" --loglevel=error | jq -r 'if length == 1 then .[0].filename else empty end') \
      || die "npm pack failed for $package@$version"
    file=$(basename "$file")
    [[ -n "$file" && -f "$dl/$file" ]] || die "npm pack made no single tarball for $package@$version"
    got="sha512-$(openssl dgst -sha512 -binary "$dl/$file" | base64 -w0)"
    [[ "$got" == "$integrity" ]] || die "$package@$version from your npm registry is $got, but botd pins $integrity: not bundling it"
    PATH="$tree/bin:$PATH" npm install -g --prefix "$tree" --omit=dev --no-fund --no-audit --cache "$cache" --loglevel=error "$dl/$file" >/dev/null \
      || die "npm install failed for $package@$version"
  done < <(awk '$1 == "npm" { print $2, $3, $4, $5 }' <<<"$pins")
}

# Whether TREE holds Node.js and each npm harness at PINS, and runs them: what is bundled is what
# was asked for, whoever made the tree. Sets BUNDLE_TREE_PROBLEM when it doesn't.
harness_tree_pinned() {
  local tree=$1 pins=$2 arch=$3 node out bin version package
  BUNDLE_TREE_PROBLEM=""
  node=$(awk -v a="$arch" '$1 == "node" && $3 == a { print $2 }' <<<"$pins")
  if [[ -e "$tree/etc/npmrc" ]]; then
    BUNDLE_TREE_PROBLEM="it has npm's global settings, etc/npmrc, which may hold a registry login"
    return 1
  fi
  [[ -x "$tree/bin/node" ]] || { BUNDLE_TREE_PROBLEM="it has no bin/node"; return 1; }
  out=$(harness_probe "$tree/bin/node" --version 2>&1) || true
  [[ "$out" == "v$node" ]] || { BUNDLE_TREE_PROBLEM="its Node.js is \"$out\", not v$node"; return 1; }
  while read -r bin version package; do
    out=$(jq -r .version "$tree/lib/node_modules/$package/package.json" 2>/dev/null) || true
    [[ "$out" == "$version" ]] || { BUNDLE_TREE_PROBLEM="its $package is \"$out\", not $version"; return 1; }
    [[ -x "$tree/bin/$bin" ]] || { BUNDLE_TREE_PROBLEM="it has no bin/$bin"; return 1; }
    out=$(harness_probe env PATH="$tree/bin:$PATH" "$tree/bin/$bin" --version 2>&1) || true
    [[ "$out" == *"$version"* ]] || { BUNDLE_TREE_PROBLEM="$bin --version says \"$(head -c 300 <<<"$out")\", not $version"; return 1; }
  done < <(awk '$1 == "npm" { print $2, $3, $4 }' <<<"$pins")
}

# A harness bundle: Node.js with Claude Code, Codex and Pi installed into it at the pins of the
# release's botd, for install.sh --offline --harness-bundle. The tree is relocatable (npm's and
# Node.js's links are relative), so it is built anywhere, as any user; it runs from
# $HARNESSES_DIR once installed, through the wrappers the installer writes.
cmd_harnesses() {
  local out="" version="" root bin_dir tree="" arch pins botd name parent top stage f
  root=$(repo_root)
  bin_dir="$root/target/release"
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --out) out=$2; shift 2 ;;
      --version) version=$2; shift 2 ;;
      --bin-dir) bin_dir=$2; shift 2 ;;
      --tree) tree=$2; shift 2 ;;
      -h|--help) usage; exit 0 ;;
      *) die "Unknown option: $1" ;;
    esac
  done
  [[ -n "$out" ]] || die "harnesses needs --out DIR"
  version=${version:-$(cargo_version "$root")}
  [[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.+-]+)?$ ]] || die "--version \"$version\" isn't a version"
  arch=$(uname -m)
  [[ "$arch" =~ ^(x86_64|aarch64)$ ]] || die "Harness bundles are for x86_64 or aarch64, not $arch"
  botd="$bin_dir/botd"
  [[ -f "$botd" && -x "$botd" ]] || die "No $botd: run cargo build --release --bin botd first (or give --bin-dir); its pins are what is bundled"
  pins=$(harness_pins "$botd") || die "$botd doesn't say which harness CLIs it pins (botd harness pins): build botd from this checkout"
  command -v jq >/dev/null 2>&1 || die "harnesses needs jq"
  OFFLINE_TMP=$(mktemp -d)
  trap cleanup_offline EXIT
  chmod 0755 "$OFFLINE_TMP"
  name=$(basename "$HARNESSES_DIR")
  if [[ -z "$tree" ]]; then
    parent="$OFFLINE_TMP/root"
    mkdir -p "$parent/$name"
    harness_install_tree "$parent/$name" "$pins" "$arch"
  else
    [[ "$(basename "$tree")" == "$name" && -d "$tree" ]] || die "--tree must be a folder named $name, as $HARNESSES_DIR is"
    parent=$(cd "$(dirname "$tree")" && pwd)
  fi
  harness_tree_pinned "$parent/$name" "$pins" "$arch" || die "Not bundling $parent/$name: $BUNDLE_TREE_PROBLEM"
  bundle_tree_ok "$parent/$name" "$HARNESSES_DIR" || die "Not bundling $parent/$name: $BUNDLE_TREE_PROBLEM"

  top="superbot-harnesses-$version-$arch"
  stage="$OFFLINE_TMP/$top"
  mkdir -p "$stage"
  log "Packing $(harness_names "$pins")"
  tar -C "$parent" --owner=0 --group=0 --numeric-owner --sort=name -cf "$stage/harnesses.tar" "$name" || die "Couldn't pack $parent/$name"
  if [[ -z "$tree" ]]; then rm -rf -- "$parent"; fi
  bundle_tar_ok "$stage/harnesses.tar" "$name" || die "Not bundling $parent/$name: $BUNDLE_TREE_PROBLEM"
  {
    echo format=1
    echo kind=harnesses
    echo "version=$version"
    echo "prefix=$HARNESSES_DIR"
    echo "arch=$arch"
    harness_manifest_lines "$pins" "$arch"
    echo "commit=$(git -C "$root" rev-parse HEAD 2>/dev/null || echo unknown)"
    echo "created=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  } >"$stage/MANIFEST"
  (cd "$stage" && sha256sum harnesses.tar MANIFEST) >"$OFFLINE_TMP/SHA256SUMS"
  mv "$OFFLINE_TMP/SHA256SUMS" "$stage/SHA256SUMS"
  mkdir -p "$out"
  f="$top.tar.gz"
  tar -C "$OFFLINE_TMP" --owner=0 --group=0 --numeric-owner --sort=name -czf "$out/$f" "$top"
  (cd "$out" && sha256sum "$f" >"$f.sha256")
  log "Harness bundle: $out/$f"
  log "SHA-256: $(awk '{ print $1 }' "$out/$f.sha256") (publish this where the operator can check it)"
}

cmd_load() {
  local args=()
  while [[ $# -gt 0 && "$1" != -- ]]; do args+=("$1"); shift; done
  [[ $# -eq 0 ]] || { shift; COMPOSE_OPTS=("$@"); }
  verify_args "${args[@]}"
  command -v docker >/dev/null 2>&1 || die "load needs docker"
  local recorded_sha=$OFFLINE_BUNDLE_SHA256
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
  local ref
  ref=$(cat "$OFFLINE_DIR/images/superbot.ref" 2>/dev/null) || return 0
  load_hermes_notice "$ref"
  # The check runs the image with the stack's secrets and data, so only when the bundle was
  # checked against something the operator chose, as push: its verified signature, or a
  # --sha256 from where it was published. A .sha256 file beside it could have been replaced.
  if [[ "$OFFLINE_SIGNED" != true && -z "$recorded_sha" ]] && compose_stack_here; then
    warn "Not checking the Compose stack against $ref: this bundle was checked only against the .sha256 beside it, which could have been replaced with it. Give --sha256 <recorded sha-256> (or its signature with cosign), or check the image yourself once you trust it: $0 check-compose --image $ref (docs/ops/air-gapped.md#upgrading-with-compose)"
  elif compose_stack_here; then
    compose_upgrade_check "$ref"
    log "To switch the stack to it: SUPERBOT_VERSION=$OFFLINE_VERSION in .env (or SUPERBOT_IMAGE=$ref), then docker compose up -d"
    compose_rollback_notice
  else
    log "Before you switch a Compose stack to $ref, check it from the stack's folder: $0 check-compose --image $ref (docs/ops/air-gapped.md#upgrading-with-compose)"
  fi
}

# Which Hermes bundle Compose needs for the image REF just loaded. Asked of the image, in a
# container with no network, not of the bundle's bin/botd on this host: the .sha256 beside a
# bundle could have been replaced with it.
load_hermes_notice() {
  local pins commit tag volume
  pins=$(docker run --rm --network none --entrypoint botd "$1" harness pins 2>/dev/null) || return 0
  read -r commit tag < <(awk '$1 == "hermes" { print $3, $4; exit }' <<<"$pins") || true
  [[ "${commit:-}" =~ ^[0-9a-f]{40}$ ]] || return 0
  volume=$(hermes_volume_name "$commit")
  if docker volume inspect "$volume" >/dev/null 2>&1; then
    log "This release's Hermes Agent ($tag) is already in the Docker volume $volume, for Compose with Hermes (SUPERBOT_HERMES_VOLUME=$volume)"
  else
    log "With Hermes Agent in Compose, load this release's Hermes bundle ($tag): $0 load-hermes superbot-hermes-$tag-$(uname -m).tar.gz (docs/ops/air-gapped.md#hermes-agent-with-docker-compose)"
  fi
}

# --- Compose upgrades checked first (docs/adr/0317-compose-upgrades-checked-first.md) ----------

# docker compose's own options for the stack (-f, -p, --env-file, --project-directory), given
# after --. Without them, Compose finds the stack from this folder, as `docker compose up` does.
COMPOSE_OPTS=()
COMPOSE_ERR=/dev/null
# The image compose_upgrade_check judged.
COMPOSE_IMAGE=""

stack() { docker compose "${COMPOSE_OPTS[@]}" "$@"; }

# Whether there is a stack here that has run botd: an upgrade, not a first start.
compose_stack_here() {
  docker compose version >/dev/null 2>&1 || return 1
  [[ -n "$(stack ps -a -q botd 2>/dev/null)" ]]
}

# Whether IMAGE's botd has the subcommand whose usage is USAGE. An older botd would take the
# subcommand for a start and run as the server, so nothing is asked of one without it.
image_botd_has() {
  # shellcheck disable=SC2016 # expanded in the container
  docker run --rm --network none --entrypoint sh "$1" -c 'b=$(command -v botd) && grep -qaF "$1" "$b"' _ "$2" >/dev/null 2>&1
}

# The same, of the botd the stack runs now.
stack_botd_has() {
  # shellcheck disable=SC2016 # expanded in the container
  stack exec -T botd sh -c 'b=$(command -v botd) && grep -qaF "$1" "$b"' _ "$1" </dev/null >/dev/null 2>&1
}

# botd ARGS... from IMAGE as Compose would start the stack's botd: the service's env_file,
# environment, volumes, user and network, with SUPERBOT_IMAGE over .env's, and nothing else
# started. botd's stdout is printed; Compose's and botd's stderr go to COMPOSE_ERR.
stack_botd_run() {
  local image=$1
  shift
  SUPERBOT_IMAGE=$image stack run --rm --no-deps -T --entrypoint botd botd "$@" 2>"$COMPOSE_ERR"
}

# The last line in COMPOSE_ERR that isn't Compose's progress.
compose_err() { grep -vE '^ *(Network|Volume|Container) ' "$COMPOSE_ERR" | tail -n 1 || true; }

# Whether botd from IMAGE would start with the stack's settings: its own `botd settings check`
# (ADR 0310), else `botd machines check`, run as Compose would start botd. A refusal dies naming
# each refused setting, saying nothing has changed and AGAIN (what to run once .env is fixed).
compose_settings_check() {
  local image=$1 again=$2 doc=$3 what="" out rc refused
  if image_botd_has "$image" "Usage: botd settings check"; then
    what=settings
  elif image_botd_has "$image" "Usage: botd machines check"; then
    what=machines
  else
    warn "botd in $image can't check its settings (botd settings check), so they weren't checked"
    return 0
  fi
  rc=0
  out=$(stack_botd_run "$image" "$what" check </dev/null) || rc=$?
  case $rc in
    0) log "Settings: botd from $image would start with this stack's settings (botd $what check)" ;;
    1)
      refused=$(sed -n "s/^botd wouldn't start with these settings: //p" <<<"$out")
      [[ -n "$refused" ]] || refused=$(tail -n 1 <<<"$out")
      warn "botd from $image wouldn't start with this stack's settings: $(head -n 1 <<<"$refused")"
      tail -n +2 <<<"$refused" | sed 's/^/    and: /' >&2
      die "Nothing in the stack has changed: keep it on the image it runs. Change what botd names in .env (the running botd reads it again only when Compose recreates it), $again ($doc)"
      ;;
    *) die "botd $what check didn't finish in $image (status $rc), so the stack's settings weren't checked: $(compose_err). Nothing in the stack has changed: keep it on the image it runs, and check again ($doc)" ;;
  esac
}

# Whether a newer release than IMAGE's botd has run on the stack's database. botd starts on a
# database a newer botd migrated without refusing it, so this is asked of the image's own
# `botd support check` (ADR 0187), read-only, as Compose would start botd
# (docs/adr/0327-compose-upgrades-keep-a-way-back.md). Dies when one has.
compose_downgrade_check() {
  local image=$1 out rc line why doc="docs/ops/air-gapped.md#going-back-with-compose"
  if ! image_botd_has "$image" "Usage: botd support check"; then
    warn "botd in $image can't check the stack's database (botd support check), so whether a newer release ran on it wasn't checked"
    return 0
  fi
  rc=0
  out=$(stack_botd_run "$image" support check </dev/null) || rc=$?
  ((rc <= 1)) \
    || die "botd support check didn't finish in $image (status $rc), so the stack's database wasn't checked: $(compose_err). Nothing in the stack has changed: keep it on the image it runs, and check again ($doc)"
  line=$(grep -E '^(ok|info|warn|fail) +database ' <<<"$out" | head -n 1) || true
  if [[ -z "$line" ]]; then
    warn "botd support check in $image said nothing of the stack's database, so whether a newer release ran on it wasn't checked: $(compose_err)"
    return 0
  fi
  why=$(grep -oE 'made by a newer botd \([^)]*\)|botd [^ ;]+ ran on it last; this is [^ ;]+' <<<"$line" | head -n 1) || true
  if [[ -z "$why" ]]; then
    log "Database: no release newer than botd in $image has run on this stack's database (botd support check)"
    return 0
  fi
  warn "botd from $image is older than the release that last ran on this stack's database: $why"
  die "Nothing in the stack has changed: keep it on the image it runs. An older botd starts on a database a newer one changed, and may not work on it. To go back, restore the rollback point taken before the upgrade on that image: $0 rollback-compose, or a backup made on that release ($doc)"
}

# Whether botd from IMAGE (empty: the image Compose would run botd from now) would start with
# the Compose stack's settings and run Bots with its license, before the stack is switched to it
# (docs/adr/0317-compose-upgrades-checked-first.md). The image's own `botd settings check` and
# `botd license check` (ADR 0310, ADR 0305) run as Compose would start botd; the running botd
# says whether Bots run now. KEY, a file, is judged as the license in its place. Nothing in the
# stack changes: it dies listing what to change, or returns.
compose_upgrade_check() {
  local image=${1:-} key=${2:-} configured out rc now_rc=2 why lic doc="docs/ops/air-gapped.md#upgrading-with-compose"
  COMPOSE_ERR="$OFFLINE_TMP/compose.err"
  if [[ -n "$image" ]]; then
    [[ "$image" != -* && "$image" != *'$'* && "$image" != *[[:space:]]* ]] || die "--image \"$image\" isn't an image reference"
    configured=$(SUPERBOT_IMAGE=$image stack config --images botd 2>"$COMPOSE_ERR") \
      || die "docker compose can't read this stack: $(compose_err) (run this from the folder you run Compose from, or give Compose's options after --)"
    [[ "$(head -n 1 <<<"$configured")" == "$image" ]] \
      || die "Compose runs botd from $(head -n 1 <<<"$configured") here whatever SUPERBOT_IMAGE says (another Compose file names botd's image), so $image can't be checked as it would run: check that image, or change the file"
  else
    configured=$(stack config --images botd 2>"$COMPOSE_ERR") \
      || die "docker compose can't read this stack: $(compose_err) (run this from the folder you run Compose from, or give Compose's options after --)"
    image=$(head -n 1 <<<"$configured")
  fi
  COMPOSE_IMAGE=$image
  [[ -n "$(stack ps -a -q botd 2>/dev/null)" ]] \
    || die "This Compose stack has never run botd, so there is nothing to upgrade: run this from your stack's folder, or give Compose's options after -- ($doc)"
  docker image inspect "$image" >/dev/null 2>&1 \
    || die "No image $image here: load the release's images first ($0 load <bundle>), or docker pull it from your registry"

  compose_downgrade_check "$image"
  compose_settings_check "$image" "then check again: $0 check-compose --image $image" "$doc"

  if ! image_botd_has "$image" "Usage: botd license check"; then
    warn "botd in $image can't check licenses (botd license check), so the license wasn't checked"
    return 0
  fi
  lic="this stack's license"
  local -a key_args=()
  if [[ -n "$key" ]]; then
    key_args=(--key-file -)
    lic="the key in $key"
    [[ "$key" != - ]] || key=/dev/stdin
  fi
  rc=0
  out=$(tr -d '[:space:]' <"${key:-/dev/null}" | stack_botd_run "$image" license check "${key_args[@]}") || rc=$?
  if [[ $rc -eq 1 && -n "$(stack ps -q botd 2>/dev/null)" ]] && stack_botd_has "Usage: botd license check"; then
    now_rc=0
    stack exec -T botd botd license check </dev/null >/dev/null 2>&1 || now_rc=$?
    ((now_rc <= 1)) || now_rc=2
  fi
  case $rc in
    0)
      log "License: botd from $image would run Bots with $lic: $(license_detail "$out")"
      sed -n 's/^Warning: //p' <<<"$out" | while IFS= read -r w; do warn "License with $image: $w"; done
      ;;
    1)
      why="botd from $image wouldn't run Bots with $lic: $(license_detail "$out")"
      case $now_rc in
        0) ;;
        1) warn "$why Bots don't run on this stack now either ($doc)"; return 0 ;;
        *) warn "$why The running botd can't say whether Bots run now (botd license check) ($doc)"; return 0 ;;
      esac
      warn "Bots run now, but $why"
      grep -E '^  ' <<<"$out" | sed -n '2,$p' >&2 || true
      die "Nothing in the stack has changed: keep it on the image it runs. Ask CG-Labs for a license key that release takes, check it with $0 check-compose --image $image --key-file <file>, then install it with botctl license install, now if the running botd takes it too, else right after you switch ($doc)"
      ;;
    *)
      die "botd license check didn't finish in $image (status $rc), so the license wasn't checked: $(compose_err). Nothing in the stack has changed: keep it on the image it runs, and check again ($doc)"
      ;;
  esac
}

cmd_check_compose() {
  local image="" key=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --image) image=$2; shift 2 ;;
      --key-file) key=$2; shift 2 ;;
      --) shift; COMPOSE_OPTS=("$@"); break ;;
      -h|--help) usage; exit 0 ;;
      *) die "Unknown option: $1 (Compose's own options go after --)" ;;
    esac
  done
  [[ -z "$key" || "$key" == - || (-f "$key" && -r "$key") ]] || die "Can't read the key in --key-file $key"
  { command -v docker && docker compose version; } >/dev/null 2>&1 || die "check-compose needs docker and its Compose plugin"
  OFFLINE_TMP=$(mktemp -d)
  trap cleanup_offline EXIT
  compose_upgrade_check "$image" "$key"
  if [[ -n "$image" ]]; then
    log "To switch the stack to $COMPOSE_IMAGE: SUPERBOT_VERSION (or SUPERBOT_IMAGE) in .env, then docker compose up -d"
  else
    log "Compose would run botd from $COMPOSE_IMAGE, as .env says: docker compose up -d switches the stack to it"
  fi
  compose_rollback_notice
}

# Before a switch: the way back, the rollback point backup-compose took on the image botd runs
# now, else how to take one.
compose_rollback_notice() {
  local dir=$COMPOSE_ROLLBACK_DIR doc="docs/ops/air-gapped.md#going-back-with-compose" cid id
  cid=$(stack ps -q botd 2>/dev/null | head -n 1) || true
  id=$([[ -z "$cid" ]] || docker inspect -f '{{.Image}}' "$cid" 2>/dev/null) || true
  if [[ -n "$id" && -f "$dir/record" && "$(record_value "$dir/record" image_id)" == "$id" ]]; then
    log "Way back: the rollback point in $dir, taken $(record_value "$dir/record" taken) on the image botd runs now ($0 rollback-compose, $doc)"
  else
    log "For a way back, take a rollback point first, with botd on the release it runs now: $0 backup-compose ($doc)"
  fi
}

# --- Compose upgrades keep a way back (docs/adr/0327-compose-upgrades-keep-a-way-back.md) -----

# Where backup-compose keeps its one rollback point, from the folder Compose runs in.
COMPOSE_ROLLBACK_DIR=superbot-rollback
ROLLBACK_ARCHIVE_RE='^superbot-compose-[a-z0-9_-]+-[0-9]{8}-[0-9]{6}\.tar\.gz(\.age)?$'

# NAME's value in a rollback record, read as text, never run.
record_value() { sed -n "s/^$2=//p" "$1" | tail -n 1; }

compose_needs_docker() {
  { command -v docker && docker compose version; } >/dev/null 2>&1 || die "$1 needs docker and its Compose plugin"
  OFFLINE_TMP=$(mktemp -d)
  trap cleanup_offline EXIT
  COMPOSE_ERR="$OFFLINE_TMP/compose.err"
}

# DIR, made if missing: a folder of this user's that only they can open, not a link.
rollback_dir() {
  [[ -n "$1" && "$1" != -* ]] || die "--dir needs a folder"
  (umask 077 && mkdir -p -- "$1") || die "Couldn't make $1"
  [[ -d "$1" && ! -L "$1" && -O "$1" ]] || die "$1 isn't a folder of yours (or is a link): give --dir a folder only you own"
  chmod 0700 -- "$1"
}

# One backup-compose or rollback-compose at a time per rollback folder.
rollback_lock() {
  command -v flock >/dev/null 2>&1 || return 0
  [[ ! -L "$1/.lock" ]] || die "Refusing the symlinked lock file $1/.lock"
  exec 8>>"$1/.lock"
  flock -n 8 || die "Another backup-compose or rollback-compose is using $1: wait for it to finish, then run this again"
}

# Prints previous=yes|no (whether botd is given SUPERBOT_MASTER_KEY_PREVIOUS), then the database's
# key check: a value sealed under the master key, written again by each rotation (ADR 0096).
# shellcheck disable=SC2016 # expanded in the container
KEY_CHECK_SH='p=no; [ -z "${SUPERBOT_MASTER_KEY_PREVIOUS:-}${SUPERBOT_MASTER_KEY_PREVIOUS_FILE:-}" ] || p=yes; echo "previous=$p"
exec botd database query "${DATA_DIR:-/data}/app.sqlite" "SELECT value FROM settings WHERE key = '\''secrets_key_check'\''"'
KEY_CHECK_HAS="usage: botd database backup"

# KEY_CHECK_SH's output as a record keeps it: the key check's SHA-256, or none before botd sealed anything.
key_check_digest() {
  local v
  v=$(sed 1d <<<"$1")
  if [[ -z "$v" ]]; then echo none; else printf '%s' "$v" | sha256sum | awk '{ print $1 }'; fi
}

cmd_backup_compose() {
  local dir=$COMPOSE_ROLLBACK_DIR cid image image_id project ext name old sha stamp part new kc out doc="docs/ops/air-gapped.md#going-back-with-compose"
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --dir) dir=${2:-}; shift 2 ;;
      --) shift; COMPOSE_OPTS=("$@"); break ;;
      -h|--help) usage; exit 0 ;;
      *) die "Unknown option: $1 (Compose's own options go after --)" ;;
    esac
  done
  compose_needs_docker backup-compose
  cid=$(stack ps -q botd 2>"$COMPOSE_ERR") \
    || die "docker compose can't read this stack: $(compose_err) (run this from the folder you run Compose from, or give Compose's options after --)"
  cid=$(head -n 1 <<<"$cid")
  [[ -n "$cid" ]] || die "botd isn't running in this Compose stack: start it on the release you are leaving (docker compose up -d), then take the rollback point ($doc)"
  read -r image image_id project < <(docker inspect -f '{{.Config.Image}} {{.Image}} {{index .Config.Labels "com.docker.compose.project"}}' "$cid" 2>/dev/null) || true
  [[ "${image_id:-}" =~ ^sha256:[0-9a-f]{64}$ && "${project:-}" =~ ^[a-z0-9][a-z0-9_-]*$ && -n "${image:-}" && "$image" != *'$'* ]] \
    || die "Couldn't tell which image and Compose project botd's container $cid runs"
  rollback_dir "$dir"
  rollback_lock "$dir"
  # Which master key sealed the database's values, so rollback-compose can tell a rotation since.
  kc=unknown
  if stack_botd_has "$KEY_CHECK_HAS" && out=$(stack exec -T botd sh -c "$KEY_CHECK_SH" </dev/null 2>/dev/null); then
    kc=$(key_check_digest "$out")
  fi
  part=$(umask 077 && mktemp "$dir/.partial.XXXXXX") || die "Couldn't write in $dir"
  # The running release's own superbot-backup, as the backup service runs it: a consistent copy
  # of the database, encrypted to the stack's backup recipients when it has them.
  if ! (umask 077 && stack exec -T botd superbot-backup - </dev/null >"$part" 2>"$COMPOSE_ERR"); then
    rm -f -- "$part"
    die "superbot-backup failed in botd: $(compose_err). No rollback point was taken, and the last one is kept ($doc)"
  fi
  if [[ "$(head -c 21 "$part")" == age-encryption.org/v1 ]]; then
    ext=.tar.gz.age
  elif [[ "$(head -c 2 "$part" | od -An -tx1 | tr -d ' \n')" == 1f8b ]]; then
    ext=.tar.gz
  else
    rm -f -- "$part"
    die "superbot-backup in botd wrote no archive. No rollback point was taken, and the last one is kept ($doc)"
  fi
  stamp=$(date -u +%Y%m%d-%H%M%S)
  name="superbot-compose-$project-$stamp$ext"
  mv -- "$part" "$dir/$name"
  sha=$(sha256sum <"$dir/$name" | awk '{ print $1 }')
  old=""
  [[ ! -f "$dir/record" ]] || old=$(record_value "$dir/record" archive)
  new=$(umask 077 && mktemp "$dir/.record.XXXXXX") || die "Couldn't write in $dir"
  printf 'format=1\nproject=%s\nimage=%s\nimage_id=%s\ntaken=%s\narchive=%s\nsha256=%s\nkey_check=%s\n' \
    "$project" "$image" "$image_id" "$(date -u +%FT%TZ)" "$name" "$sha" "$kc" >"$new" || { rm -f -- "$new"; die "Couldn't write $new"; }
  mv -- "$new" "$dir/record"
  [[ "$old" == "$name" || ! "$old" =~ $ROLLBACK_ARCHIVE_RE ]] || rm -f -- "${dir:?}/$old"
  log "Rollback point: $dir/$name ($(du -h "$dir/$name" | cut -f1)), of botd on $image. One is kept: the next backup-compose replaces it."
  [[ "$ext" == .tar.gz.age ]] || warn "It isn't encrypted (the stack has no SUPERBOT_BACKUP_AGE_RECIPIENTS): keep $dir private"
  log "To go back to $image after you switch, losing everything since: set SUPERBOT_VERSION (or SUPERBOT_IMAGE=$image) in .env back, then $0 rollback-compose$([[ "$dir" == "$COMPOSE_ROLLBACK_DIR" ]] || printf ' --dir %s' "$dir")$([[ "$ext" != .tar.gz.age ]] || printf ' --identity <your backup key>') ($doc)"
}

# The number of .pre-restore-* folders superbot-restore has left in botd's DATA_DIR, from IMAGE:
# one more after a failed restore means it had started swapping the data.
pre_restores() {
  # shellcheck disable=SC2016 # expanded in the container
  SUPERBOT_IMAGE=$1 stack run --rm --no-deps -T --entrypoint sh botd -c 'ls -d "${DATA_DIR:-/data}"/.pre-restore-* 2>/dev/null | wc -l' </dev/null 2>"$COMPOSE_ERR"
}

# Refuses a rollback point whose saved secrets need a master key botd won't be given: the key
# check KC that backup-compose recorded, against the stack's database now, read by RUNNING's botd.
compose_key_check() {
  local running=$1 kc=$2 taken=$3 out
  [[ "$kc" != none ]] || return 0
  if [[ ! "$kc" =~ ^[0-9a-f]{64}$ ]]; then
    warn "The rollback point doesn't say which master key sealed its saved secrets: if the key was rotated since $taken, set SUPERBOT_MASTER_KEY_PREVIOUS in .env to the key from before"
    return 0
  fi
  if ! image_botd_has "$running" "$KEY_CHECK_HAS" \
    || ! out=$(SUPERBOT_IMAGE=$running stack run --rm --no-deps -T --entrypoint sh botd -c "$KEY_CHECK_SH" </dev/null 2>"$COMPOSE_ERR"); then
    warn "Couldn't read which master key seals the stack's database now: if it was rotated since $taken, set SUPERBOT_MASTER_KEY_PREVIOUS in .env to the key from before"
    return 0
  fi
  if [[ "$(key_check_digest "$out")" == "$kc" ]]; then
    log "Master key: the one that sealed the rollback point's saved secrets seals the stack's database now"
    return 0
  fi
  [[ "$(head -n 1 <<<"$out")" == previous=yes ]] \
    || die "The master key was rotated since the rollback point was taken ($taken): its saved secrets open only with the key from before, and botd isn't given it. Set SUPERBOT_MASTER_KEY_PREVIOUS in .env to that key, then run this again (docs/ops/master-key-rotation.md). Nothing has changed"
  log "Master key: rotated since $taken; botd opens the rollback point's saved secrets with SUPERBOT_MASTER_KEY_PREVIOUS, which must be the key from before"
}

cmd_rollback_compose() {
  local dir=$COMPOSE_ROLLBACK_DIR identity="" rec format project image image_id taken archive sha cid now_project running configured have
  local before after out rc newest kc doc="docs/ops/air-gapped.md#going-back-with-compose"
  local -a mount=() rargs=()
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --dir) dir=${2:-}; shift 2 ;;
      --identity) identity=${2:-}; shift 2 ;;
      --) shift; COMPOSE_OPTS=("$@"); break ;;
      -h|--help) usage; exit 0 ;;
      *) die "Unknown option: $1 (Compose's own options go after --)" ;;
    esac
  done
  rec="$dir/record"
  [[ -f "$rec" ]] \
    || die "No rollback point in $dir: backup-compose takes one before you switch. Without one, restore a backup made on the release you go back to (docs/ops/backup-restore.md)"
  rollback_lock "$dir"
  format=$(record_value "$rec" format) project=$(record_value "$rec" project) image=$(record_value "$rec" image)
  image_id=$(record_value "$rec" image_id) taken=$(record_value "$rec" taken) archive=$(record_value "$rec" archive) sha=$(record_value "$rec" sha256)
  kc=$(record_value "$rec" key_check)
  [[ "$format" == 1 ]] || die "$rec isn't a rollback record this offline-bundle.sh reads (format ${format:-missing})"
  [[ "$project" =~ ^[a-z0-9][a-z0-9_-]*$ && "$image_id" =~ ^sha256:[0-9a-f]{64}$ && "$sha" =~ ^[0-9a-f]{64}$ && -n "$taken" \
    && -n "$image" && "$image" != -* && "$image" != *'$'* && "$image" != *[[:space:]]* && "$archive" =~ $ROLLBACK_ARCHIVE_RE ]] \
    || die "$rec is damaged: it isn't a record backup-compose wrote"
  [[ -f "$dir/$archive" ]] || die "The rollback point's archive $dir/$archive is gone"
  [[ "$(sha256sum <"$dir/$archive" | awk '{ print $1 }')" == "$sha" ]] \
    || die "$dir/$archive has changed since backup-compose took it (its SHA-256 isn't the record's), so it can't be trusted to go back with. Nothing has changed"
  if [[ "$archive" == *.age ]]; then
    [[ -n "$identity" ]] || die "The rollback point is encrypted: give your backup key with --identity <file> (the age identity, readable by the container's user, uid 10001). Nothing has changed"
    [[ -f "$identity" && -r "$identity" ]] || die "Can't read the backup key in --identity $identity"
    identity="$(cd "$(dirname -- "$identity")" && pwd)/$(basename -- "$identity")"
    [[ "$identity" != *:* ]] || die "--identity $identity: docker can't mount a path with ':' in it; copy the key elsewhere. Nothing has changed"
    mount=(-v "$identity:/run/superbot-age-identity:ro")
    rargs=(--identity /run/superbot-age-identity)
  fi
  compose_needs_docker rollback-compose

  cid=$(stack ps -a -q botd 2>"$COMPOSE_ERR") \
    || die "docker compose can't read this stack: $(compose_err) (run this from the folder you run Compose from, or give Compose's options after --)"
  cid=$(head -n 1 <<<"$cid")
  [[ -n "$cid" ]] || die "This Compose stack has never run botd, so there is nothing to roll back"
  read -r running now_project < <(docker inspect -f '{{.Config.Image}} {{index .Config.Labels "com.docker.compose.project"}}' "$cid" 2>/dev/null) || true
  [[ "${now_project:-}" == "$project" ]] \
    || die "The rollback point is of the Compose project $project, not this one (${now_project:-unknown}): run this from that stack's folder, or give its Compose options after --"
  configured=$(stack config --images botd 2>"$COMPOSE_ERR") || die "docker compose can't read this stack: $(compose_err)"
  configured=$(head -n 1 <<<"$configured")
  [[ "$configured" == "$image" ]] \
    || die "Compose would start botd from $configured, but the rollback point was taken on $image: set SUPERBOT_VERSION (or SUPERBOT_IMAGE=$image) in .env back to it first, so the data goes back to the release that made it. Nothing has changed ($doc)"
  have=$(docker image inspect -f '{{.Id}}' "$image" 2>/dev/null) \
    || die "No image $image here: load that release's images again ($0 load <its bundle>), or docker pull it from your registry. Nothing has changed"
  [[ "$have" == "$image_id" ]] \
    || die "$image here is another build ($have) than the rollback point was taken on ($image_id): load that release's bundle again. Nothing has changed"

  compose_settings_check "$image" "then run this again" "$doc"
  compose_key_check "$running" "$kc" "$taken"
  rc=0
  out=$(SUPERBOT_IMAGE=$image stack run --rm --no-deps -T "${mount[@]}" botd superbot-restore "${rargs[@]}" --check - <"$dir/$archive" 2>"$COMPOSE_ERR") || rc=$?
  [[ $rc -eq 0 ]] || die "superbot-restore in $image refused the rollback point: $(compose_err). Nothing has changed"
  newest=$(sed -n 's/^newest audit: *//p' <<<"$out" | head -n 1)
  log "Rollback point: $archive, taken $taken on $image (its newest audit event: ${newest:-unknown}); superbot-restore --check passed"
  before=$(pre_restores "$image") || die "Couldn't look in botd's data volume: $(compose_err). Nothing has changed"

  warn "Going back to $image: everything saved in this stack since $taken is lost"
  stack stop >/dev/null 2>"$COMPOSE_ERR" || { stack start >/dev/null 2>&1 || true; die "docker compose stop failed: $(compose_err). Nothing has changed"; }
  rc=0
  SUPERBOT_IMAGE=$image stack run --rm --no-deps -T "${mount[@]}" botd superbot-restore "${rargs[@]}" - <"$dir/$archive" >/dev/null 2>"$COMPOSE_ERR" || rc=$?
  if [[ $rc -ne 0 ]]; then
    local why
    why=$(compose_err)
    after=$(pre_restores "$image") || after=""
    if [[ "$after" == "$before" ]]; then
      stack start >/dev/null 2>"$COMPOSE_ERR" || die "The restore failed before it changed botd's data ($why), and the stack didn't start again: $(compose_err). Start it with docker compose start"
      die "The restore failed before it changed botd's data: $why. The stack runs again as it was, on $running. The rollback point is kept"
    fi
    die "The restore failed while it swapped botd's data in: $why. The stack stays stopped: the data from before is in the newest .pre-restore-* folder in botd's data volume. Run this again, or move that folder's contents back (docker compose run --rm --no-deps --entrypoint sh botd) and docker compose start ($doc)"
  fi
  log "Restored botd's data from $taken. Starting the stack on $image"
  stack up -d --wait >/dev/null 2>"$COMPOSE_ERR" \
    || die "The data is back as it was on $taken, but the stack didn't come up healthy on $image: $(compose_err). See docker compose ps and docker compose logs botd. The rollback point is kept in $dir: fix what botd says, then docker compose up -d, or run this again ($doc)"
  rm -f -- "$rec" "${dir:?}/$archive"
  log "The stack runs on $image again, with its data from $taken. What the restore replaced is in .pre-restore-* in botd's data volume: remove it once SuperBot looks right"
}

# --- Hermes Agent for Compose (docs/adr/0275-hermes-agent-bundle-for-docker-compose.md) -------

hermes_volume_name() { printf 'superbot-hermes-%s\n' "${1:0:12}"; }

# The last NAME=value in a Compose env FILE, as Compose reads it: without the quotes around it,
# and unquoted, without a " # comment" after it or the spaces around it.
compose_env_value() {
  local line v="" re="^[[:space:]]*(export[[:space:]]+)?$2[[:space:]]*=[[:space:]]*(.*)$"
  while IFS= read -r line || [[ -n "$line" ]]; do
    line=${line%$'\r'}
    [[ "$line" =~ $re ]] || continue
    v=${BASH_REMATCH[2]}
    if [[ "$v" =~ ^\'([^\']*)\' || "$v" =~ ^\"([^\"]*)\" ]]; then
      v=${BASH_REMATCH[1]}
    else
      [[ "$v" != \#* ]] || v=""
      v=${v%%[[:space:]]#*}
      v=${v%"${v##*[![:space:]]}"}
    fi
  done <"$1"
  printf '%s\n' "$v"
}

# The image docker-compose.yml runs botd from: SUPERBOT_IMAGE, else the published image at
# SUPERBOT_VERSION (main when unset), from this environment first, then ENV_FILE, as Compose
# reads them.
compose_botd_image() {
  local env=$1 image=${SUPERBOT_IMAGE:-} version=${SUPERBOT_VERSION:-}
  if [[ -f "$env" ]]; then
    [[ -n "$image" ]] || image=$(compose_env_value "$env" SUPERBOT_IMAGE)
    [[ -n "$version" ]] || version=$(compose_env_value "$env" SUPERBOT_VERSION)
  fi
  image=${image:-ghcr.io/cg-labs/superbot:${version:-main}}
  [[ "$image" != *'$'* ]] \
    || die "The image Compose runs botd from is $image here, with a variable Compose fills in: give it with --image"
  printf '%s\n' "$image"
}

# One load-hermes at a time per volume: while one fills it, the volume has no marker yet, and
# another would take it for a failed load and remove it.
hermes_volume_lock() {
  local lock="/tmp/superbot-load-hermes-$1.lock"
  command -v flock >/dev/null 2>&1 || return 0
  [[ -e "$lock" ]] || (umask 0; set -C; : >"$lock") 2>/dev/null || true
  [[ -f "$lock" && ! -L "$lock" ]] || die "Couldn't use the lock file $lock"
  exec 9<"$lock"
  flock -n 9 || die "Another load-hermes is filling the Docker volume $1: wait for it to finish, then run this again"
}

# Runs IMAGE with VOLUME at $HERMES_SHARED_DIR and no network: docker run's own options, then
# --, then the entrypoint and its arguments.
hermes_volume_run() {
  local image=$1 volume=$2 opts=()
  shift 2
  while [[ $# -gt 0 && "$1" != -- ]]; do opts+=("$1"); shift; done
  shift
  docker run --rm --network none "${opts[@]}" -v "$volume:$HERMES_SHARED_DIR${HERMES_VOLUME_MODE:-}" --entrypoint "$1" "$image" "${@:2}"
}

# Hermes Agent from VOLUME, run in IMAGE as Compose runs it: read-only, with no network, from
# PATH, with a HERMES_HOME of its own, as the image's user and as another account (per-user
# accounts run it as theirs). Prints the version it says.
hermes_volume_probe() {
  local image=$1 volume=$2 user out rc
  for user in "" 65534:65534; do
    rc=0
    # shellcheck disable=SC2016 # expanded in the container
    out=$(HERMES_VOLUME_MODE=:ro hermes_volume_run "$image" "$volume" ${user:+--user "$user"} -- sh -c \
      'command -v hermes >/dev/null || exit 3; p=$(mktemp -d) && HOME=$p HERMES_HOME=$p/hermes hermes --version' 2>&1) || rc=$?
    [[ $rc -ne 3 ]] \
      || die "$image has no hermes on PATH for the volume: it is older than load-hermes (ADR 0275). Use the image of the release the Hermes bundle is for"
    [[ $rc -eq 0 ]] || die "Hermes Agent in the Docker volume $volume didn't run in $image (as ${user:-its user}): $(tail -n 5 <<<"$out")"
  done
  head -n 1 <<<"$out"
}

load_hermes_cleanup() {
  [[ -z "$HERMES_VOLUME_NEW" ]] || docker volume rm "$HERMES_VOLUME_NEW" >/dev/null 2>&1 || true
  cleanup_offline
}

# Hermes Agent for Compose with no internet: the Hermes bundle checked as install.sh checks it,
# for the Hermes Agent the image Compose runs pins, its tree checked again as files, then copied
# into a Docker volume of its own, root's, shared as install.sh shares it, and run from there as
# Compose will. The volume is marked last, so one left by a failed load is made again.
cmd_load_hermes() {
  local bundle="" sha="" image="" env_file=.env volume="" arch commit tag pinned img_arch tree version
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --sha256) sha=$2; shift 2 ;;
      --image) image=$2; shift 2 ;;
      --env-file) env_file=$2; shift 2 ;;
      --volume) volume=$2; shift 2 ;;
      -h|--help) usage; exit 0 ;;
      -*) die "Unknown option: $1" ;;
      *) [[ -z "$bundle" ]] || die "Give one Hermes bundle"; bundle=$1; shift ;;
    esac
  done
  [[ -n "$bundle" ]] || die "Give the Hermes bundle (superbot-hermes-<tag>-<arch>.tar.gz)"
  [[ -f "$bundle" ]] || die "No Hermes bundle at $bundle"
  [[ -z "$sha" || "$sha" =~ ^[0-9a-f]{64}$ ]] || die "--sha256 must be 64 lowercase hex digits"
  [[ -z "$volume" || "$volume" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$ ]] || die "--volume \"$volume\" isn't a Docker volume name"
  OFFLINE_TMP=$(mktemp -d)
  trap load_hermes_cleanup EXIT
  hermes_unpack_bundle "$bundle" "$OFFLINE_TMP" "$sha"
  arch=$(manifest_value "$HERMES_BUNDLE_DIR/MANIFEST" arch)
  commit=$(manifest_value "$HERMES_BUNDLE_DIR/MANIFEST" hermes_commit)
  tag=$(manifest_value "$HERMES_BUNDLE_DIR/MANIFEST" hermes_tag)

  command -v docker >/dev/null 2>&1 || die "load-hermes needs docker"
  [[ -n "$image" ]] || image=$(compose_botd_image "$env_file") || exit 1
  docker image inspect "$image" >/dev/null 2>&1 \
    || die "No image $image here: load the release's images first ($0 load), or give --image"
  img_arch=$(docker image inspect --format '{{.Architecture}}' "$image" 2>/dev/null) || true
  [[ "$img_arch" == "$(docker_arch "$arch")" ]] || die "$image is for linux/$img_arch, but the Hermes bundle is for $arch"
  pinned=$(docker run --rm --network none --entrypoint botd "$image" harness pins 2>/dev/null \
    | awk '$1 == "hermes" { print $3; exit }') || true
  [[ "$pinned" =~ ^[0-9a-f]{40}$ ]] || die "$image's botd doesn't say which Hermes Agent it pins (botd harness pins): use a SuperBot image of the Hermes bundle's release"
  [[ "$pinned" == "$commit" ]] \
    || die "The Hermes bundle holds Hermes Agent ${commit:0:12}, but $image pins ${pinned:0:12}: use the Hermes bundle made for the image's release (docs/ops/air-gapped.md#hermes-agent-with-docker-compose)"
  volume=${volume:-$(hermes_volume_name "$commit")}
  hermes_volume_lock "$volume"

  local label
  if label=$(docker volume inspect --format '{{ index .Labels "org.superbot.hermes-commit" }}' "$volume" 2>/dev/null); then
    [[ "$label" == "$commit" ]] \
      || die "The Docker volume $volume wasn't made by load-hermes for Hermes Agent ${commit:0:12}${label:+ (it is for ${label:0:12})}: give another --volume, or remove it yourself"
    if [[ "$(HERMES_VOLUME_MODE=:ro hermes_volume_run "$image" "$volume" -- cat "$HERMES_SHARED_DIR/$HERMES_VOLUME_MARK" 2>/dev/null)" == "$commit" ]]; then
      version=$(hermes_volume_probe "$image" "$volume")
      log "Hermes Agent ${commit:0:12} is already in the Docker volume $volume, and runs in $image: $version"
      load_hermes_settings "$volume"
      return
    fi
    warn "The Docker volume $volume holds no finished load of Hermes Agent ${commit:0:12}: making it again"
    docker volume rm "$volume" >/dev/null || die "Couldn't remove the Docker volume $volume: stop what uses it (docker compose down), then run this again"
  fi

  tree="$OFFLINE_TMP/tree"
  mkdir -m 0700 "$tree"
  log "Unpacking Hermes Agent ${commit:0:12} from $bundle"
  tar -xf "$HERMES_BUNDLE_DIR/hermes.tar" -C "$tree" --no-same-owner || die "Couldn't unpack Hermes Agent from $bundle"
  rm -f -- "$HERMES_BUNDLE_DIR/hermes.tar"
  bundle_tree_ok "$tree/hermes" "$HERMES_SHARED_DIR" || die "Refusing $bundle: $BUNDLE_TREE_PROBLEM"
  [[ "$(hermes_installed "$tree/hermes")" == "$commit" ]] || die "Refusing $bundle: its checkout isn't Hermes Agent $commit"

  log "Copying Hermes Agent ${commit:0:12} into the Docker volume $volume"
  docker volume create --label "org.superbot.hermes-commit=$commit" "$volume" >/dev/null || die "Couldn't make the Docker volume $volume"
  HERMES_VOLUME_NEW=$volume
  tar -C "$tree" --owner=0 --group=0 --numeric-owner -cf - hermes \
    | hermes_volume_run "$image" "$volume" -i --user 0:0 -- tar -xf - -C "$(dirname "$HERMES_SHARED_DIR")" --no-same-owner \
    || die "Couldn't copy Hermes Agent into the Docker volume $volume"
  rm -rf -- "$tree"
  # As install.sh: hermes-share.sh with the install's HOME, then root's alone to change and
  # every account's to run. The script is copied in, as it writes itself out as the wrapper.
  local readable
  readable=$(printf ' %q' "${HERMES_SHARED_READABLE[@]}")
  # shellcheck disable=SC2016 # expanded in the container
  hermes_volume_run "$image" "$volume" -i --user 0:0 -e HOME="$HERMES_SHARED_DIR" -- sh -euc '
    cat >/tmp/hermes-share.sh
    sh /tmp/hermes-share.sh >/dev/null
    cd "$HOME"
    chown root:root .
    chmod 0755 .
    chmod -R go-w .
    for d in '"$readable"'; do
      [ ! -d "$d" ] || chmod -R a+rX "$d"
    done
    chmod go+rx .hermes .hermes/superbot
  ' <"$DIR/hermes-share.sh" || die "Couldn't share Hermes Agent's environment in the Docker volume $volume"
  version=$(hermes_volume_probe "$image" "$volume")
  # shellcheck disable=SC2016 # expanded in the container
  hermes_volume_run "$image" "$volume" --user 0:0 -- sh -c 'printf "%s\n" "$1" >"$2"' _ "$commit" "$HERMES_SHARED_DIR/$HERMES_VOLUME_MARK" \
    || die "Couldn't mark the Docker volume $volume as loaded"
  HERMES_VOLUME_NEW=""
  log "Hermes Agent $tag (${commit:0:12}) is in the Docker volume $volume, and runs in $image with no network: $version"
  load_hermes_settings "$volume"
}

load_hermes_settings() {
  log "For Compose, set these in .env, then docker compose up -d (docs/ops/air-gapped.md#hermes-agent-with-docker-compose):"
  printf '    %s\n' "COMPOSE_FILE=docker-compose.yml:docker-compose.hermes.yml" "SUPERBOT_HERMES_VOLUME=$1"
  log "With a docker-compose.override.yml, name it in COMPOSE_FILE too: Compose reads it only when COMPOSE_FILE isn't set"
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

# BUNDLE... [--sha256 HEX]...: each image goes to REGISTRY/<its repository's last part>:<its tag>
# as it is, with the signatures and attestations bundled with it, through superbot-oci. One
# bundle per arch of one release puts up the signed multi-arch index the images came from, so
# the tag names the digest cosign checked; one bundle puts up its image alone. The digest the tag
# names after the push is checked.
cmd_push() {
  local registry="" bundles=() sums=() i j s
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --registry) registry=$2; shift 2 ;;
      --sha256) sums+=("$2"); shift 2 ;;
      -*) die "Unknown option: $1" ;;
      *) bundles+=("$1"); shift ;;
    esac
  done
  [[ -n "$registry" ]] || die "push needs --registry HOST[:PORT][/PATH], e.g. --registry registry.corp.example/superbot"
  registry_ok "$registry" || die "--registry \"$registry\" isn't HOST[:PORT][/path] (a host with a dot or a port, or localhost; a lowercase path)"
  [[ ${#bundles[@]} -gt 0 ]] || die "Give the bundle, or one bundle per arch"
  [[ ${#sums[@]} -eq 0 || ${#sums[@]} -eq ${#bundles[@]} ]] || die "Give one --sha256 per bundle, in the bundles' order, or none"
  for s in "${sums[@]}"; do [[ "$s" =~ ^[0-9a-f]{64}$ ]] || die "--sha256 must be 64 lowercase hex digits"; done
  OFFLINE_TMP=$(mktemp -d)
  trap cleanup_offline EXIT

  local dirs=() arches=() trusted=() version="" listed="" dir arch b
  for i in "${!bundles[@]}"; do
    b=${bundles[i]}
    [[ -f "$b" ]] || die "No bundle at $b"
    mkdir "$OFFLINE_TMP/b$i"
    OFFLINE_BUNDLE_SHA256=${sums[i]:-}
    OFFLINE_ANY_ARCH=1 offline_unpack_bundle "$b" "$OFFLINE_TMP/b$i"
    dir=$OFFLINE_DIR arch=$(manifest_value "$OFFLINE_DIR/MANIFEST" arch)
    [[ -n "$(manifest_value "$dir/MANIFEST" images)" ]] || die "$b has no images: it is for install.sh --offline only"
    [[ "$(manifest_value "$dir/MANIFEST" image_format)" == oci ]] \
      || die "$b's images are docker save archives, which a registry can't take with their digests: use a bundle made by a newer offline-bundle.sh, or docker load and docker push"
    if [[ $i -gt 0 ]]; then
      [[ "$OFFLINE_VERSION" == "$version" ]] || die "$b is $OFFLINE_VERSION, but ${bundles[0]} is $version: give bundles of one release, one per arch"
      [[ "$(manifest_value "$dir/MANIFEST" images)" == "$listed" ]] || die "$b and ${bundles[0]} hold different images: give bundles of one release, one per arch"
      for s in "${arches[@]}"; do [[ "$s" != "$arch" ]] || die "Two of these bundles are for $arch: give one per arch"; done
    fi
    version=$OFFLINE_VERSION listed=$(manifest_value "$dir/MANIFEST" images)
    dirs+=("$dir") arches+=("$arch")
    # A bundle's superbot-oci is run only if the bundle was checked against something the
    # operator chose: its verified signature, or a --sha256 from where it was published. A
    # .sha256 file beside it could have been replaced with it.
    if [[ "$OFFLINE_SIGNED" == true || -n "${sums[i]:-}" ]]; then trusted+=("$dir"); fi
  done
  local multi=false
  [[ ${#dirs[@]} -eq 1 ]] || multi=true

  # Everything is checked before anything is pushed: two images whose repositories end alike
  # (team-a/app:1, team-b/app:1) would take the same tag, and the second push would silently
  # replace the first; bundles that can't make up an image's signed index would leave it half done.
  local tar name ref dest index names=() dests=() indexes=()
  declare -A seen=()
  for tar in "${dirs[0]}"/images/*.tar; do
    [[ -f "$tar" ]] || continue
    name=$(basename "$tar" .tar)
    ref=$(cat "${dirs[0]}/images/$name.ref")
    image_ref_ok "$ref" || die "Refusing ${bundles[0]}: images/$name.ref isn't an image reference"
    index=""
    for j in "${!dirs[@]}"; do
      dir=${dirs[j]} b=${bundles[j]}
      [[ -f "$dir/images/$name.tar" && "$(cat "$dir/images/$name.ref")" == "$ref" ]] || die "$b doesn't hold the same $name image ($ref) as ${bundles[0]}: give bundles of one release"
      [[ "$(cat "$dir/images/$name.digest")" =~ ^sha256:[0-9a-f]{64}$ ]] || die "Refusing $b: images/$name.digest isn't a digest"
      [[ "$multi" == true ]] || { index=$(cat "$dir/images/$name.index" 2>/dev/null || true); continue; }
      [[ -f "$dir/images/$name.index" && -f "$dir/signatures/$name.tar" ]] \
        || die "$b's $name image has no signed multi-arch index with it (unsigned, or bundled before ADR 0147), so these bundles can't put one up: push each to its own --registry path"
      s=$(cat "$dir/images/$name.index")
      [[ -z "$index" || "$s" == "$index" ]] || die "The bundles' $name images come from different signed indexes ($index, $s): give bundles of one release"
      index=$s
    done
    [[ -z "$index" || "$index" =~ ^sha256:[0-9a-f]{64}$ ]] || die "Refusing ${bundles[0]}: images/$name.index isn't a digest"
    dest="$registry/$(basename "$(image_repo "$ref")"):$(image_tag "$ref")"
    [[ -z "${seen[$dest]:-}" ]] || die "Images ${seen[$dest]} and $name would both be pushed to $dest: nothing pushed"
    seen[$dest]=$name
    names+=("$name") dests+=("$dest") indexes+=("$index")
  done

  local oci tools=() untrusted=false
  for dir in "${trusted[@]}"; do
    [[ ! -f "$dir/bin/superbot-oci" ]] || { chmod 0755 "$dir/bin/superbot-oci"; tools+=("$dir/bin/superbot-oci"); }
  done
  for dir in "${dirs[@]}"; do
    if [[ -f "$dir/bin/superbot-oci" && ${#tools[@]} -eq 0 ]]; then untrusted=true; fi
  done
  if ! oci=$(find_oci "${tools[@]}"); then
    [[ "$untrusted" == false ]] \
      || die "push runs the bundle's superbot-oci only when the bundle is checked against its signature (with cosign here) or a --sha256 you give from where it was published, not just the .sha256 file beside it: give --sha256, or set SUPERBOT_OCI to a superbot-oci you trust (docs/ops/air-gapped.md#registry-mirrors)"
    die "push needs superbot-oci, which bundles with images carry in bin/ (one for this machine's arch, $(uname -m)); or set SUPERBOT_OCI to one (docs/ops/air-gapped.md#registry-mirrors)"
  fi

  # Every image's layouts are unpacked and checked by superbot-oci (with no network) before the
  # first push, so one that can't go up leaves the mirror as it was.
  local u units top want what var envs=() platforms="" wants=() whats=()
  for arch in "${arches[@]}"; do platforms+="${platforms:+, }linux/$(docker_arch "$arch")"; done
  for i in "${!names[@]}"; do
    name=${names[i]} dest=${dests[i]} index=${indexes[i]} units=()
    for j in "${!dirs[@]}"; do
      u="$OFFLINE_TMP/units/$name/$j"
      untar_layout "${dirs[j]}/images/$name.tar" "$u/image"
      [[ ! -f "${dirs[j]}/signatures/$name.tar" ]] || untar_layout "${dirs[j]}/signatures/$name.tar" "$u/signatures"
      units+=("$u")
    done
    top=$("$oci" push --check --to "$dest" "${units[@]}") || die "Can't push $name to $dest: nothing pushed"
    if [[ "$multi" == true ]]; then
      want=$index what="the signed index for $platforms"
    else
      want=$(cat "${dirs[0]}/images/$name.digest") what="linux/$(docker_arch "${arches[0]}")"
      # An index that lists this arch alone (and its attestations) is put up whole.
      [[ -z "$index" || "$top" != "$index" ]] || want=$index what="the signed index for linux/$(docker_arch "${arches[0]}")"
    fi
    [[ "$top" == "$want" ]] || die "$dest would name $top, not the bundle's $want: nothing pushed"
    wants+=("$want") whats+=("$what")
  done

  for i in "${!names[@]}"; do
    name=${names[i]} dest=${dests[i]} want=${wants[i]} what=${whats[i]} units=()
    ref=$(cat "${dirs[0]}/images/$name.ref")
    for j in "${!dirs[@]}"; do
      u="$OFFLINE_TMP/units/$name/$j"
      [[ -d "$u/signatures" ]] \
        || warn "$name (${arches[j]}) has no signatures in its bundle (unsigned, or bundled before ADR 0147): cosign verify won't find any in the mirror"
      units+=("$u")
    done
    top=$("$oci" push --to "$dest" "${units[@]}") || die "Couldn't push $name to $dest"
    [[ "$top" == "$want" ]] || die "$dest is $top after the push, not the bundle's $want: don't use it"
    log "Pushed $ref to $dest ($top, $what)"
    var=$(compose_image_var "$name")
    [[ -z "$var" ]] || envs+=("$var=$(image_repo "$dest")@$top")
  done
  if [[ ${#envs[@]} -gt 0 ]]; then
    log "For Compose, pin these in .env (docs/ops/air-gapped.md#registry-mirrors):"
    printf '    %s\n' "${envs[@]}"
  fi
}

case "${1:-}" in
  build) shift; cmd_build "$@" ;;
  hermes) shift; cmd_hermes "$@" ;;
  harnesses) shift; cmd_harnesses "$@" ;;
  verify) shift; cmd_verify "$@" ;;
  load) shift; cmd_load "$@" ;;
  check-compose) shift; cmd_check_compose "$@" ;;
  backup-compose) shift; cmd_backup_compose "$@" ;;
  rollback-compose) shift; cmd_rollback_compose "$@" ;;
  load-hermes) shift; cmd_load_hermes "$@" ;;
  push) shift; cmd_push "$@" ;;
  -h|--help|"") usage ;;
  *) die "Unknown command: $1 (build, hermes, harnesses, verify, load, check-compose, backup-compose, rollback-compose, load-hermes or push)" ;;
esac
