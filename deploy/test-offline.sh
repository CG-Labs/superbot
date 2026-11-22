#!/usr/bin/env bash
# Offline bundles and install.sh --offline without root or a network
# (docs/adr/0128-air-gapped-self-host.md): a bundle builds and verifies; tampered, unsafe, or
# unanchored bundles are refused; downgrades are refused; operator certificates are checked;
# the Caddyfile is unchanged without one; and a dry run of the whole offline install touches
# no package manager, git or download. The real install, as root with networking off, runs in
# .github/workflows/offline.yml.
#   deploy/test-offline.sh
set -euo pipefail

DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT

fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
ok() { printf 'ok - %s\n' "$*"; }

export SUPERBOT_INSTALL_NO_MAIN=1
# shellcheck source=install.sh source-path=SCRIPTDIR
source "$DIR/install.sh"

ARCH=$(uname -m)
VERSION=0.1.0-test

# Stand-ins for the release binaries and an exported web client built for /app/.
mkdir -p "$T/bin" "$T/client/_expo/static/js/web" "$T/client/assets/node_modules/@expo"
for b in "${OFFLINE_BINARIES[@]}"; do
  printf '#!/bin/sh\necho %s\n' "$b" >"$T/bin/$b"
  chmod 0755 "$T/bin/$b"
done
echo '<!doctype html><script src="/app/_expo/static/js/web/entry-abc.js"></script>' >"$T/client/index.html"
echo 'console.log(1)' >"$T/client/_expo/static/js/web/entry-abc.js"
echo font >"$T/client/assets/node_modules/@expo/icons.ttf"

"$DIR/offline-bundle.sh" build --out "$T/out" --version "$VERSION" --bin-dir "$T/bin" --client-dir "$T/client" >"$T/build.log" 2>&1 \
  || { cat "$T/build.log" >&2; fail "the bundle didn't build"; }
B="$T/out/superbot-offline-$VERSION-$ARCH.tar.gz"
[[ -f "$B" && -f "$B.sha256" ]] || fail "no bundle and .sha256 in $T/out"
names=$(tar -tf "$B")
for f in MANIFEST SHA256SUMS bin/botd bin/botctl deploy/install.sh deploy/offline-bundle.sh deploy/superbot.service env.example site/index.html client/index.html docker/docker-compose.yml docker/.env.example; do
  grep -qx "superbot-offline-$VERSION-$ARCH/$f" <<<"$names" || fail "the bundle has no $f"
done
owners=$(tar -tvf "$B" | awk '{ print $2 }' | sort -u)
[[ "$owners" == "0/0" ]] || fail "bundle entries should be owned by 0/0, not $owners"
for f in deploy/install.sh deploy/offline-bundle.sh docker/init.sh; do
  [[ "$(tar -tvf "$B" "superbot-offline-$VERSION-$ARCH/$f" | cut -c1-10)" == -rwxr-xr-x ]] || fail "$f isn't executable in the bundle"
done
"$DIR/offline-bundle.sh" verify "$B" >"$T/verify.log" 2>&1 || { cat "$T/verify.log" >&2; fail "a good bundle didn't verify"; }
grep -q "version=$VERSION" "$T/verify.log" || fail "verify didn't show the manifest"
ok "a bundle builds, with binaries, templates, the client, the site and Compose files, and verifies"

if "$DIR/offline-bundle.sh" build --out "$T/bad" --bin-dir "$T/nope" --client-dir "$T/client" >/dev/null 2>&1; then
  fail "a build without binaries succeeded"
fi
mkdir -p "$T/root-client"
echo '<!doctype html><script src="/_expo/static/js/web/entry-abc.js"></script>' >"$T/root-client/index.html"
if "$DIR/offline-bundle.sh" build --out "$T/bad" --bin-dir "$T/bin" --client-dir "$T/root-client" >/dev/null 2>&1; then
  fail "a client not built for /app/ was bundled"
fi
ok "a build without binaries, or with a client not built for /app/, is refused"

# Unpacks the good bundle into $T/x, runs a change there, and packs it as $T/$1.tar.gz with a
# matching .sha256, re-hashing SHA256SUMS unless the change says not to (KEEP_SUMS=1).
TOP="superbot-offline-$VERSION-$ARCH"
remake() {
  local name=$1
  shift
  rm -rf "$T/x" && mkdir -p "$T/x"
  tar -xf "$B" -C "$T/x"
  (cd "$T/x/$TOP" && "$@")
  if [[ "${KEEP_SUMS:-}" != 1 ]]; then
    (cd "$T/x/$TOP" && find . -type f ! -path ./SHA256SUMS -printf '%P\n' | LC_ALL=C sort | xargs -d '\n' sha256sum >SHA256SUMS)
  fi
  tar -C "$T/x" -czf "$T/$name.tar.gz" "$TOP"
  (cd "$T" && sha256sum "$name.tar.gz" >"$name.tar.gz.sha256")
  printf '%s\n' "$T/$name.tar.gz"
}
refused() {
  local bundle=$1 want=$2 why=$3 out
  if out=$("$DIR/offline-bundle.sh" verify "$bundle" 2>&1); then fail "$why: accepted"; fi
  grep -Fq "$want" <<<"$out" || { printf '%s\n' "$out" >&2; fail "$why: refused for another reason"; }
}

refused "$(KEEP_SUMS=1 remake changed sh -c 'echo evil >>bin/botd')" "files don't match SHA256SUMS" "a changed binary"
refused "$(KEEP_SUMS=1 remake extra sh -c 'echo x >bin/extra')" "files SHA256SUMS doesn't list" "a file SHA256SUMS doesn't list"
refused "$(KEEP_SUMS=1 remake missing rm client/assets/node_modules/@expo/icons.ttf)" "files don't match SHA256SUMS" "a listed file that is gone"
refused "$(remake link ln -s /etc/shadow site/leak)" "not an offline bundle" "a symlink"
# shellcheck disable=SC2016
refused "$(KEEP_SUMS=1 remake escape sh -c 'echo "$(sha256sum MANIFEST | cut -c1-64)  ../MANIFEST" >>SHA256SUMS')" "outside the bundle" "SHA256SUMS naming ../"
refused "$(remake format sed -i 's/^format=1$/format=2/' MANIFEST)" "bundle format 2" "an unknown bundle format"
# shellcheck disable=SC2016
refused "$(remake version sed -i 's/^version=.*/version=$(id)/' MANIFEST)" "isn't a version" "a version that isn't one"
refused "$(remake nobin rm bin/superbot-run)" "no bin/superbot-run" "a bundle without a binary"
refused "$(remake noclient rm -r client)" "needs env.example, site/ and client/" "a bundle without the client"

mkdir -p "$T/two/$TOP" "$T/two/superbot-offline-other"
tar -xf "$B" -C "$T/two"
echo x >"$T/two/superbot-offline-other/x"
tar -C "$T/two" -czf "$T/two.tar.gz" "$TOP" superbot-offline-other
(cd "$T" && sha256sum two.tar.gz >two.tar.gz.sha256)
refused "$T/two.tar.gz" "not an offline bundle" "two top folders"
mkdir -p "$T/dots"
tar -xf "$B" -C "$T/dots"
echo x >"$T/evil"
tar -C "$T/dots" -czf "$T/dots.tar.gz" "$TOP" --transform 's,^evil$,'"$TOP"'/../evil,' -C "$T" evil 2>/dev/null
(cd "$T" && sha256sum dots.tar.gz >dots.tar.gz.sha256)
[[ $(tar -tf "$T/dots.tar.gz" | tail -n 1) == "$TOP/../evil" ]] || fail "couldn't make a bundle holding ../"
refused "$T/dots.tar.gz" "not an offline bundle" "a '..' entry"
ok "changed, extra or missing files, links, '..', other folders, formats, versions and missing parts are refused"

cp "$B" "$T/anchor.tar.gz"
refused "$T/anchor.tar.gz" "Nothing to check the bundle against" "a bundle with no SHA-256 or signature beside it"
if "$DIR/offline-bundle.sh" verify "$T/anchor.tar.gz" --sha256 "$(printf '0%.0s' {1..64})" >/dev/null 2>&1; then
  fail "a wrong --sha256 was accepted"
fi
"$DIR/offline-bundle.sh" verify "$T/anchor.tar.gz" --sha256 "$(awk '{ print $1 }' "$B.sha256")" >/dev/null || fail "the right --sha256 was refused"
cp "$B.sha256" "$T/anchor.tar.gz.sha256"
echo junk >>"$T/anchor.tar.gz"
refused "$T/anchor.tar.gz" "not the one published" "a damaged bundle"
ok "a bundle is checked against its published SHA-256 before it is opened, and needs one"

other=x86_64
[[ "$ARCH" != x86_64 ]] || other=aarch64
wrong=$(remake arch sed -i "s/^arch=.*/arch=$other/" MANIFEST)
"$DIR/offline-bundle.sh" verify "$wrong" >/dev/null || fail "verify (on any machine) refused another arch's bundle"
rm -rf "$T/u" && mkdir "$T/u"
if (offline_unpack_bundle "$wrong" "$T/u") 2>"$T/arch.err"; then fail "the installer accepted a bundle for $other"; fi
grep -q "This bundle is for $other" "$T/arch.err" || fail "the arch refusal didn't say why"
ok "verify reads any arch's bundle; the installer takes only this host's"

# Images, with stand-ins for skopeo, docker, cosign and superbot-oci over a registry in $REG: an
# index with this arch's image, another arch's and an attestation; a local image; a mirror to
# push to. superbot-oci is only in the bin folder, so push finds it in the bundle, as on a mirror
# host; its own tests (cargo test --bin superbot-oci) run it against registries.
command -v jq >/dev/null 2>&1 || fail "the image checks need jq"
case $ARCH in x86_64) DARCH=amd64 OTHER_DARCH=arm64 ;; *) DARCH=arm64 OTHER_DARCH=amd64 ;; esac
REG="$T/reg"
mkdir -p "$REG/blobs" "$REG/refs" "$REG/local" "$T/img" "$T/stub"
regkey() { printf '%s' "$1" | sha256sum | cut -c1-16; }
blob() {
  local d
  d=sha256:$(sha256sum <"$1" | cut -c1-64)
  cp "$1" "$REG/blobs/${d#sha256:}"
  printf '%s\n' "$d"
}
make_image() {
  local darch=$1 marker=$2 ld cd diff
  mkdir -p "$T/img/$marker" && echo "$marker" >"$T/img/$marker/marker"
  tar -C "$T/img/$marker" --owner=0 --group=0 --mtime=@0 -cf - marker | gzip -n >"$T/img/$marker.layer"
  ld=$(blob "$T/img/$marker.layer")
  diff=sha256:$(gzip -dc "$T/img/$marker.layer" | sha256sum | cut -c1-64)
  printf '{"architecture":"%s","os":"linux","config":{},"rootfs":{"type":"layers","diff_ids":["%s"]}}' "$darch" "$diff" >"$T/img/$marker.config"
  cd=$(blob "$T/img/$marker.config")
  printf '{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"%s","size":%d},"layers":[{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":"%s","size":%d}]}' \
    "$cd" "$(stat -c %s "$T/img/$marker.config")" "$ld" "$(stat -c %s "$T/img/$marker.layer")" >"$T/img/$marker.manifest"
  blob "$T/img/$marker.manifest"
}
MINE=$(make_image "$DARCH" mine)
THEIRS=$(make_image "$OTHER_DARCH" theirs)
entry() { printf '{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"%s","size":%d,"platform":{"architecture":"%s","os":"linux"}}' "$1" "$(stat -c %s "$REG/blobs/${1#sha256:}")" "$2"; }
printf '{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[%s,%s,{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"%s","size":1,"platform":{"architecture":"unknown","os":"unknown"}}]}' \
  "$(entry "$THEIRS" "$OTHER_DARCH")" "$(entry "$MINE" "$DARCH")" "$THEIRS" >"$T/img/index.json"
INDEX=$(blob "$T/img/index.json")
cp "$T/img/index.json" "$REG/refs/$(regkey reg.test/cg/superbot:1.0.0)"
cp "$T/img/index.json" "$REG/refs/$(regkey reg.test/cg/unsigned:1.0.0)"
printf '{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[%s]}' "$(entry "$THEIRS" "$OTHER_DARCH")" >"$REG/refs/$(regkey reg.test/cg/elsewhere:1.0.0)"
cp "$T/img/theirs.manifest" "$REG/refs/$(regkey reg.test/cg/single:1.0.0)"
echo "reg.test/cg/superbot@$INDEX" >"$REG/signed"
OWN=$(make_image "$DARCH" own)
echo "$OWN" >"$REG/local.digest"
echo "$DARCH" >"$REG/local/$(regkey own-image:2)"
echo "$OTHER_DARCH" >"$REG/local/$(regkey foreign-image:2)"

cat >"$T/stub/skopeo" <<'EOF'
#!/usr/bin/env bash
# skopeo over $STUB_REG. STUB_REWRITE=copy or push changes the manifest it writes.
set -euo pipefail
reg=$STUB_REG
key() { printf '%s' "$1" | sha256sum | cut -c1-16; }
manifest_of() { if [[ $1 == *@sha256:* ]]; then cat "$reg/blobs/${1##*@sha256:}"; else cat "$reg/refs/$(key "$1")"; fi; }
rewrite() { if [[ ${STUB_REWRITE:-} == "$1" ]]; then jq -c '.annotations = {"changed": "yes"}'; else cat; fi; }
case $1 in
  inspect)
    if [[ $2 == --raw ]]; then manifest_of "${3#docker://}"; exit; fi
    cfg=$(manifest_of "${2#docker://}" | jq -r .config.digest)
    jq '{Architecture: .architecture}' "$reg/blobs/${cfg#sha256:}" ;;
  copy)
    [[ $2 != --help ]] || { echo '      --preserve-digests'; exit; }
    args=()
    for a in "${@:2}"; do [[ $a == -* ]] || args+=("$a"); done
    src=${args[0]} dest=${args[1]}
    case $src in
      docker://*) m=$(manifest_of "${src#docker://}") ;;
      docker-archive:*) m=$(cat "$reg/blobs/$(sed 's/^sha256://' "$reg/local.digest")") ;;
      oci-archive:*)
        x=$(mktemp -d)
        tar -xf "${src#oci-archive:}" -C "$x"
        [[ -f $x/oci-layout && -f $x/manifest.json ]] || { echo "not an OCI archive with manifest.json" >&2; exit 1; }
        d=$(jq -r '.manifests[0].digest' "$x/index.json")
        cp "$x"/blobs/sha256/* "$reg/blobs/"
        rewrite push <"$x/blobs/sha256/${d#sha256:}" >"$reg/refs/$(key "${dest#docker://}")"
        rm -rf "$x"
        exit ;;
    esac
    dir=${dest#oci:}
    dir=${dir%:*}
    tag=${dest##*:}
    mkdir -p "$dir/blobs/sha256"
    echo '{"imageLayoutVersion":"1.0.0"}' >"$dir/oci-layout"
    for d in $(jq -r '.config.digest, .layers[].digest' <<<"$m"); do cp "$reg/blobs/${d#sha256:}" "$dir/blobs/sha256/"; done
    printf '%s' "$m" | rewrite copy >"$dir/m"
    d=$(sha256sum <"$dir/m" | cut -c1-64)
    mv "$dir/m" "$dir/blobs/sha256/$d"
    printf '{"schemaVersion":2,"manifests":[{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:%s","size":%d,"annotations":{"org.opencontainers.image.ref.name":"%s"}}]}' \
      "$d" "$(stat -c %s "$dir/blobs/sha256/$d")" "$tag" >"$dir/index.json" ;;
  *) echo "stub skopeo: $*" >&2; exit 2 ;;
esac
EOF
cat >"$T/stub/docker" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
key() { printf '%s' "$1" | sha256sum | cut -c1-16; }
case "$1 $2" in
  "image inspect")
    ref=${*: -1}
    [[ -f $STUB_REG/local/$(key "$ref") ]] || exit 1
    if [[ $3 == --format ]]; then cat "$STUB_REG/local/$(key "$ref")"; else echo '[{}]'; fi ;;
  "save -o") : >"$3" ;;
  "load -q")
    # As docker load reads it: an OCI archive with a Docker manifest.json naming the image.
    ref=$(tar -xOf "$4" manifest.json 2>/dev/null | jq -r '.[0].RepoTags[0]') || { echo "stub docker: $4 isn't an image archive" >&2; exit 1; }
    echo loaded >"$STUB_REG/local/$(key "$ref")" ;;
  "buildx imagetools") echo '{"spdxVersion":"SPDX-2.3"}' ;;
  *) echo "stub docker: $*" >&2; exit 2 ;;
esac
EOF
cat >"$T/stub/cosign" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
[[ $1 == verify ]] || { echo "stub cosign: $*" >&2; exit 2; }
echo "$*" >>"$STUB_REG/cosign.log"
grep -qx "$2" "$STUB_REG/signed" || { echo "no matching signatures" >&2; exit 1; }
echo '[{"critical":{"identity":{"docker-reference":"reg.test/cg/superbot"}}}]'
EOF
cat >"$T/bin/superbot-oci" <<'EOF'
#!/usr/bin/env bash
# superbot-oci over $STUB_REG. fetch writes a layout naming the index and one signature; push
# tags the signed index (from more than one unit) or the one unit's image, and prints its
# digest, or another one with STUB_REWRITE=push.
set -euo pipefail
reg=$STUB_REG
key() { printf '%s' "$1" | sha256sum | cut -c1-16; }
case $1 in
  --version) echo "superbot-oci stub" ;;
  fetch)
    echo "$*" >>"$reg/oci.log"
    [[ $2 == --from && $4 == --image && $6 == --out ]] || { echo "stub superbot-oci: $*" >&2; exit 2; }
    out=$7
    mkdir -p "$out/blobs/sha256"
    echo '{"imageLayoutVersion":"1.0.0"}' >"$out/oci-layout"
    sig=$(printf '{"signature-for":"%s"}' "$5")
    d=$(printf '%s' "$sig" | sha256sum | cut -c1-64)
    printf '%s' "$sig" >"$out/blobs/sha256/$d"
    printf '{"schemaVersion":2,"manifests":[{"digest":"%s","annotations":{"dev.superbot.oci.role":"index"}},{"digest":"sha256:%s","annotations":{"dev.superbot.oci.role":"referrer"}}]}' \
      "${3##*@}" "$d" >"$out/index.json" ;;
  push)
    [[ $2 == --to ]] || { echo "stub superbot-oci: $*" >&2; exit 2; }
    dest=$3
    for u in "${@:4}"; do
      [[ -f $u/image/oci-layout && -f $u/image/manifest.json ]] || { echo "stub superbot-oci: $u/image isn't an image layout" >&2; exit 1; }
      echo "push $dest $(jq -r '.manifests[0].digest' "$u/image/index.json") signatures=$([[ -f $u/signatures/index.json ]] && echo yes || echo no)" >>"$reg/oci.log"
    done
    if [[ $# -gt 4 ]]; then
      top=$(jq -r '.manifests[] | select(.annotations["dev.superbot.oci.role"] == "index") | .digest' "$4/signatures/index.json")
      cp "$reg/blobs/${top#sha256:}" "$reg/refs/$(key "$dest")"
    else
      top=$(jq -r '.manifests[0].digest' "$4/image/index.json")
      cp "$4/image/blobs/sha256/${top#sha256:}" "$reg/refs/$(key "$dest")"
    fi
    [[ ${STUB_REWRITE:-} != push ]] || top=sha256:$(printf '%064d' 0)
    echo "$top" ;;
  *) echo "stub superbot-oci: $*" >&2; exit 2 ;;
esac
EOF
chmod 0755 "$T/stub/"* "$T/bin/superbot-oci"
stubbed() { STUB_REG=$REG PATH="$T/stub:$PATH" "$@"; }
ibuild() { stubbed "$DIR/offline-bundle.sh" build --out "$1" --version "$VERSION" --bin-dir "$T/bin" --client-dir "$T/client" "${@:2}"; }

ibuild "$T/iout" --image superbot=reg.test/cg/superbot:1.0.0 --image-identity https://ci.test/docker.yml@refs/tags/v1.0.0 >"$T/ibuild.log" 2>&1 \
  || { cat "$T/ibuild.log" >&2; fail "a bundle with a signed image didn't build"; }
IB="$T/iout/$TOP.tar.gz"
rm -rf "$T/ix" && mkdir "$T/ix" && tar -xf "$IB" -C "$T/ix"
I="$T/ix/$TOP"
grep -qx "image_format=oci" "$I/MANIFEST" || fail "MANIFEST doesn't say the images are OCI archives"
grep -qx "images=superbot" "$I/MANIFEST" || fail "MANIFEST doesn't list the image"
! grep -q "^unsigned_images=" "$I/MANIFEST" || fail "a signed image was called unsigned"
[[ "$(cat "$I/images/superbot.digest")" == "$MINE" ]] || fail "the bundled image isn't this arch's, with the registry's digest"
grep -Fq "verify reg.test/cg/superbot@$INDEX --certificate-identity https://ci.test/docker.yml@refs/tags/v1.0.0" "$REG/cosign.log" \
  || fail "cosign didn't check the index the tag named, with the identity given"
for f in images/superbot.cosign.json images/superbot.sbom.spdx.json images/superbot.ref signatures/superbot.tar bin/superbot-oci; do [[ -s "$I/$f" ]] || fail "no $f"; done
[[ "$(cat "$I/images/superbot.index")" == "$INDEX" ]] || fail "the bundle doesn't record the signed index the image came from"
grep -Fq "fetch --from reg.test/cg/superbot@$INDEX --image $MINE --out " "$REG/oci.log" \
  || fail "the signatures weren't copied from the signed index, for this arch's image"
mkdir "$T/ix/sig" && tar -xf "$I/signatures/superbot.tar" -C "$T/ix/sig"
[[ -f "$T/ix/sig/oci-layout" && "$(jq -r '.manifests[0].digest' "$T/ix/sig/index.json")" == "$INDEX" ]] || fail "signatures/superbot.tar isn't the layout superbot-oci wrote"
[[ "$(tar -tvf "$I/signatures/superbot.tar" | awk '{ print $2 }' | sort -u)" == 0/0 ]] || fail "the signatures layout's entries aren't owned by 0/0"
mkdir "$T/ix/oci" && tar -xf "$I/images/superbot.tar" -C "$T/ix/oci"
O="$T/ix/oci"
[[ -f "$O/oci-layout" && -f "$O/blobs/sha256/${MINE#sha256:}" ]] || fail "the image isn't an OCI layout holding its manifest"
[[ "$(jq -r '.manifests | length' "$O/index.json")" == 1 && "$(jq -r '.manifests[0].digest' "$O/index.json")" == "$MINE" ]] || fail "index.json doesn't name the one image"
[[ "$(jq -r '.manifests[0].annotations["io.containerd.image.name"]' "$O/index.json")" == reg.test/cg/superbot:1.0.0 ]] || fail "index.json doesn't name the image for containerd"
[[ "$(jq -r '.[0].RepoTags[0]' "$O/manifest.json")" == reg.test/cg/superbot:1.0.0 ]] || fail "manifest.json doesn't tag the image for docker load"
for p in $(jq -r '.[0].Config, .[0].Layers[]' "$O/manifest.json"); do [[ -f "$O/$p" ]] || fail "manifest.json names $p, which isn't in the archive"; done
[[ "$(sha256sum <"$O/$(jq -r '.[0].Config' "$O/manifest.json")" | cut -c1-64)" == "$(jq -r '.config.digest' "$T/img/mine.manifest" | cut -c8-)" ]] \
  || fail "manifest.json's config isn't the image's"
"$DIR/offline-bundle.sh" verify "$IB" >/dev/null || fail "a bundle with an image didn't verify"
ok "an image is checked by the digest its tag names, and bundled for this arch as an OCI archive with the registry's digest that docker load also reads, with its signatures and attestations"

printf 'key\n' >"$T/cosign.pub"
ibuild "$T/ikey" --image superbot=reg.test/cg/superbot:1.0.0 --image-key "$T/cosign.pub" >"$T/ikey.log" 2>&1 || { cat "$T/ikey.log" >&2; fail "a key-signed image didn't bundle"; }
grep -Fqx "verify reg.test/cg/superbot@$INDEX --key $T/cosign.pub --insecure-ignore-tlog=true --output json" "$REG/cosign.log" || fail "cosign didn't check the image against --image-key"
grep -Fq "signed by the key in $T/cosign.pub" "$T/ikey.log" || fail "the build didn't say which key signed the image"
ok "--image-key checks an image's signature against a key instead of the release identity"

stubbed "$DIR/offline-bundle.sh" load "$IB" >"$T/load.log" 2>&1 || { cat "$T/load.log" >&2; fail "load of a bundle with signatures failed"; }
grep -Fq "Loaded reg.test/cg/superbot:1.0.0 ($MINE, signature checked when bundled)" "$T/load.log" || fail "load didn't load the image alone"
rm -f "$REG/local/$(regkey reg.test/cg/superbot:1.0.0)"
ok "load loads a bundle's images, with its signatures beside them"

ibuild "$T/iown" --image own=own-image:2 --allow-unsigned >"$T/iown.log" 2>&1 || { cat "$T/iown.log" >&2; fail "a local image didn't bundle"; }
[[ "$(tar -xOf "$T/iown/$TOP.tar.gz" "$TOP/images/own.digest")" == "$OWN" ]] || fail "the local image wasn't bundled from docker save"
grep -qx "unsigned_images=true" <<<"$(tar -xOf "$T/iown/$TOP.tar.gz" "$TOP/MANIFEST")" || fail "MANIFEST doesn't say an image is unsigned"
ibuild "$T/iunsigned" --image u=reg.test/cg/unsigned:1.0.0 --allow-unsigned >/dev/null 2>&1 || fail "an unsigned registry image didn't bundle"
[[ "$(tar -xOf "$T/iunsigned/$TOP.tar.gz" "$TOP/images/u.digest")" == "$MINE" ]] || fail "an unsigned registry image wasn't this arch's"
ok "--allow-unsigned bundles a local image through docker save, or a registry's for this arch"

irefused() {
  local want=$1 why=$2 out
  shift 2
  rm -rf "$T/inope"
  if out=$(ibuild "$T/inope" "$@" 2>&1); then fail "$why: bundled"; fi
  grep -Fq -- "$want" <<<"$out" || { printf '%s\n' "$out" >&2; fail "$why: refused for another reason"; }
  [[ ! -e "$T/inope" ]] || [[ -z "$(ls -A "$T/inope")" ]] || fail "$why: left a bundle behind"
}
irefused "isn't a tagged image reference" "an untagged reference" --image x=reg.test/cg/superbot
irefused "isn't a tagged image reference" "a reference by digest" --image "x=reg.test/cg/superbot@$INDEX"
irefused "isn't a tagged image reference" "an uppercase reference" --image x=Reg.test/cg/superbot:1.0.0
irefused "isn't signed by" "an image with no signature from the identity" --image x=reg.test/cg/unsigned:1.0.0
irefused "has no linux/$DARCH image" "an index without this arch" --image x=reg.test/cg/elsewhere:1.0.0 --allow-unsigned
irefused "is a $OTHER_DARCH image, not $DARCH" "a single image of another arch" --image x=reg.test/cg/single:1.0.0 --allow-unsigned
irefused "is a $OTHER_DARCH image, not $DARCH" "a local image of another arch" --image x=foreign-image:2 --allow-unsigned
STUB_REWRITE=copy irefused "changed its digest" "a copy that changed the signed digest" --image superbot=reg.test/cg/superbot:1.0.0
irefused "given twice" "the same name twice" --image x=own-image:2 --image x=own-image:2 --allow-unsigned
irefused "not both" "a key and an identity" --image superbot=reg.test/cg/superbot:1.0.0 --image-key "$T/cosign.pub" --image-identity x
irefused "no file at" "a key that isn't there" --image superbot=reg.test/cg/superbot:1.0.0 --image-key "$T/nokey.pub"
mkdir -p "$T/nooci" && cp "$T/bin/"* "$T/nooci/" && rm "$T/nooci/superbot-oci"
rm -rf "$T/inope"
out=$(stubbed "$DIR/offline-bundle.sh" build --out "$T/inope" --version "$VERSION" --bin-dir "$T/nooci" --client-dir "$T/client" --image x=own-image:2 --allow-unsigned 2>&1) \
  && fail "a bundle with images was built without superbot-oci"
grep -Fq "cargo build --release --bin superbot-oci" <<<"$out" || { printf '%s\n' "$out" >&2; fail "a build without superbot-oci was refused for another reason"; }
ok "untagged, digest-only or odd references, unsigned images, other arches, changed digests, and images without superbot-oci are not bundled"

push() { stubbed "$DIR/offline-bundle.sh" push "$@" 2>&1; }
out=$(push "$IB" --registry mirror.test:5000/superbot) || { printf '%s\n' "$out" >&2; fail "push failed"; }
[[ "$(cat "$REG/refs/$(regkey mirror.test:5000/superbot/superbot:1.0.0)")" == "$(cat "$REG/blobs/${MINE#sha256:}")" ]] || fail "the mirror didn't get the bundled manifest"
grep -Fq "SUPERBOT_IMAGE=mirror.test:5000/superbot/superbot@$MINE" <<<"$out" || { printf '%s\n' "$out" >&2; fail "push didn't print the pinned Compose setting"; }
grep -Fqx "push mirror.test:5000/superbot/superbot:1.0.0 $MINE signatures=yes" "$REG/oci.log" || fail "push didn't hand superbot-oci the image with its signatures"
out=$(STUB_REWRITE=push push "$IB" --registry mirror.test/changed) && fail "a push that changed the digest passed"
grep -Fq "after the push, not the bundle's $MINE" <<<"$out" || { printf '%s\n' "$out" >&2; fail "the changed push failed for another reason"; }
for bad in mirror "mirror.test/Upper" "https://mirror.test" "mirror.test//x" "-mirror.test"; do
  out=$(push "$IB" --registry "$bad") && fail "--registry $bad was accepted"
  grep -Fq "isn't HOST[:PORT][/path]" <<<"$out" || { printf '%s\n' "$out" >&2; fail "--registry $bad refused for another reason"; }
done
out=$(push "$IB") && fail "push without --registry passed"
grep -q "needs --registry" <<<"$out" || fail "push without --registry didn't say why"
out=$(push "$B" --registry mirror.test) && fail "push of a bundle without images passed"
grep -q "has no images" <<<"$out" || fail "push of a bundle without images didn't say why"
old=$(B=$IB remake oldimages sed -i '/^image_format=/d' MANIFEST)
out=$(push "$old" --registry mirror.test) && fail "push of docker save images passed"
grep -q "docker save archives" <<<"$out" || fail "push of docker save images didn't say why"
cp "$T/img/index.json" "$REG/refs/$(regkey reg.test/other/unsigned:1.0.0)"
ibuild "$T/iclash" --image a=reg.test/cg/unsigned:1.0.0 --image b=reg.test/other/unsigned:1.0.0 --allow-unsigned >/dev/null 2>&1 \
  || fail "two images with the same last path part didn't bundle"
out=$(push "$T/iclash/$TOP.tar.gz" --registry mirror.test/clash) && fail "two images pushed to one tag"
grep -Fq "Images a and b would both be pushed to mirror.test/clash/unsigned:1.0.0: nothing pushed" <<<"$out" || { printf '%s\n' "$out" >&2; fail "the clash was refused for another reason"; }
[[ ! -e "$REG/refs/$(regkey mirror.test/clash/unsigned:1.0.0)" ]] || fail "an image was pushed before the clash was found"
grep -q "is for push" <<<"$("$DIR/offline-bundle.sh" verify "$IB" --registry mirror.test 2>&1 || true)" || fail "verify took --registry"
grep -Fq "has no signatures in its bundle" <<<"$(push "$T/iunsigned/$TOP.tar.gz" --registry mirror.test/u)" || fail "push of an unsigned image didn't warn that it has no signatures"
nooci=$(B=$IB remake nooci rm bin/superbot-oci)
out=$(push "$nooci" --registry mirror.test) && fail "push without superbot-oci passed"
grep -q "push needs superbot-oci" <<<"$out" || { printf '%s\n' "$out" >&2; fail "push without superbot-oci didn't say why"; }
ok "push copies images with their signatures to a mirror with the bundle's digest, checks it there, prints Compose's pinned settings, and refuses bad registries, two images on one tag, old bundles, and no superbot-oci"

# Both arches' bundles of one release: the signed index goes up, and the tag names it.
case $ARCH in x86_64) OTHER_ARCH=aarch64 ;; *) OTHER_ARCH=x86_64 ;; esac
OTOP="superbot-offline-$VERSION-$OTHER_ARCH"
ibuild "$T/iother" --arch "$OTHER_ARCH" --image superbot=reg.test/cg/superbot:1.0.0 --image-identity https://ci.test/docker.yml@refs/tags/v1.0.0 >"$T/iother.log" 2>&1 \
  || { cat "$T/iother.log" >&2; fail "the other arch's bundle didn't build"; }
OB="$T/iother/$OTOP.tar.gz"
[[ "$(tar -xOf "$OB" "$OTOP/images/superbot.digest")" == "$THEIRS" ]] || fail "the other arch's bundle doesn't hold its image"
out=$(push "$IB" "$OB" --registry mirror.test/multi --sha256 "$(cut -c1-64 "$IB.sha256")" --sha256 "$(cut -c1-64 "$OB.sha256")") \
  || { printf '%s\n' "$out" >&2; fail "push of both arches' bundles failed"; }
[[ "$(cat "$REG/refs/$(regkey mirror.test/multi/superbot:1.0.0)")" == "$(cat "$T/img/index.json")" ]] || fail "the mirror's tag isn't the signed index"
grep -Fq "to mirror.test/multi/superbot:1.0.0 ($INDEX, the signed index for linux/$DARCH, linux/$OTHER_DARCH)" <<<"$out" || { printf '%s\n' "$out" >&2; fail "push didn't say it put up the index"; }
grep -Fq "SUPERBOT_IMAGE=mirror.test/multi/superbot@$INDEX" <<<"$out" || fail "Compose's pin isn't the signed index"
for d in "$MINE" "$THEIRS"; do
  grep -Fqx "push mirror.test/multi/superbot:1.0.0 $d signatures=yes" "$REG/oci.log" || fail "superbot-oci didn't get $d with its signatures"
done
pushrefused() {
  local want=$1 why=$2 out
  shift 2
  if out=$(push "$@"); then fail "$why: pushed"; fi
  grep -Fq -- "$want" <<<"$out" || { printf '%s\n' "$out" >&2; fail "$why: refused for another reason"; }
}
pushrefused "Two of these bundles are for $ARCH" "the same arch twice" "$IB" "$IB" --registry mirror.test/twice
pushrefused "one --sha256 per bundle" "one --sha256 for two bundles" "$IB" "$OB" --registry mirror.test/x --sha256 "$(cut -c1-64 "$IB.sha256")"
pushrefused "not the one published" "a --sha256 for the other bundle" "$IB" "$OB" --registry mirror.test/x --sha256 "$(cut -c1-64 "$OB.sha256")" --sha256 "$(cut -c1-64 "$IB.sha256")"
ibuild "$T/iotherv" --arch "$OTHER_ARCH" --version 0.1.0-other --image superbot=reg.test/cg/superbot:1.0.0 --image-identity https://ci.test/docker.yml@refs/tags/v1.0.0 >/dev/null 2>&1 \
  || fail "the other version's bundle didn't build"
pushrefused "give bundles of one release" "bundles of two versions" "$IB" "$T/iotherv/superbot-offline-0.1.0-other-$OTHER_ARCH.tar.gz" --registry mirror.test/x
ibuild "$T/iotheru" --arch "$OTHER_ARCH" --image superbot=reg.test/cg/unsigned:1.0.0 --allow-unsigned >/dev/null 2>&1 || fail "the other arch's unsigned bundle didn't build"
pushrefused "doesn't hold the same superbot image" "bundles of different images" "$IB" "$T/iotheru/$OTOP.tar.gz" --registry mirror.test/x
ibuild "$T/iotheru2" --arch "$OTHER_ARCH" --image superbot=reg.test/cg/superbot:1.0.0 --allow-unsigned >/dev/null 2>&1 || fail "the other arch's unsigned bundle didn't build"
pushrefused "has no signed multi-arch index with it" "an unsigned arch" "$IB" "$T/iotheru2/$OTOP.tar.gz" --registry mirror.test/x
pushrefused "hold different images" "a bundle with other images" "$IB" "$(B=$OB TOP=$OTOP remake noimage sh -c 'sed -i "s/^images=.*/images=other/" MANIFEST')" --registry mirror.test/x
[[ ! -e "$REG/refs/$(regkey mirror.test/x/superbot:1.0.0)" && ! -e "$REG/refs/$(regkey mirror.test/twice/superbot:1.0.0)" ]] || fail "a refused push pushed something"
ok "both arches' bundles put up the signed multi-arch index; bundles of one arch twice, of two releases, or that can't make the index are refused before anything is pushed"

# Versions: same or newer installs; older is refused.
release="$T/offline-release"
for installed in "$VERSION" 0.0.9 0.1.0-rc.1 0.1.0 9.9.9; do
  printf 'format=1\nversion=%s\n' "$installed" >"$release"
  newer=false
  [[ "$installed" != 0.1.0 && "$installed" != 9.9.9 ]] || newer=true
  if (DRY_RUN=true OFFLINE_BUNDLE=$B OFFLINE_RELEASE_FILE=$release prepare_offline) >"$T/prep.log" 2>&1; then
    [[ "$newer" == false ]] || fail "a downgrade from $installed to $VERSION was allowed"
  else
    [[ "$newer" == true ]] || { cat "$T/prep.log" >&2; fail "installing $VERSION over $installed was refused"; }
    grep -q "newer than the bundle's $VERSION" "$T/prep.log" || fail "the downgrade refusal didn't say why"
  fi
done
ok "a bundle installs over the same or an older version, never a newer one"

# SemVer precedence, both ways round.
order=(0.0.9 0.1.0-alpha 0.1.0-alpha.1 0.1.0-alpha.beta 0.1.0-ci.2 0.1.0-ci.10 0.1.0-rc.1 0.1.0 0.1.1 0.2.0 0.10.0 1.0.0)
for ((i = 0; i < ${#order[@]}; i++)); do
  for ((j = 0; j < ${#order[@]}; j++)); do
    if ((i > j)); then
      semver_gt "${order[i]}" "${order[j]}" || fail "${order[i]} should be newer than ${order[j]}"
    else
      ! semver_gt "${order[i]}" "${order[j]}" || fail "${order[i]} shouldn't be newer than ${order[j]}"
    fi
  done
done
! semver_gt 0.1.0+b.2 0.1.0+b.1 || fail "build metadata changed the order"
ok "versions order as SemVer: a release candidate upgrades to its release, never back"

# Flags that can't work offline.
flags() {
  (
    # shellcheck disable=SC2034
    OFFLINE_BUNDLE=$B INSTALL_DIR="" WITH_HERMES=false DOMAIN="" TLS_CERT="" OFFLINE_BUNDLE_SHA256=""
    for a in "$@"; do declare "$a"; done
    check_offline_flags
  ) 2>&1
}
grep -q "can't run --offline" <<<"$(flags WITH_HERMES=true || true)" || fail "--offline --with-hermes was allowed"
grep -q "needs --tls-cert" <<<"$(flags DOMAIN=bots.example.com || true)" || fail "--offline --domain without a certificate was allowed"
grep -q "not --source-dir" <<<"$(flags INSTALL_DIR=/srv/src || true)" || fail "--offline --source-dir was allowed"
# shellcheck disable=SC2034
grep -q "needs --offline" <<<"$( (OFFLINE_BUNDLE="" OFFLINE_BUNDLE_SHA256=abc; check_offline_flags) 2>&1 || true)" || fail "--bundle-sha256 without --offline was allowed"
ok "--offline refuses --with-hermes, --source-dir, and --domain without a certificate"

# Operator certificates.
cert() {
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days "${3:-30}" -subj "/CN=$1" \
    -addext "subjectAltName=DNS:$1" -keyout "$T/$2.key" -out "$T/$2.pem" 2>/dev/null
}
cert offline.test good 90
cert other.test other 90
tls() { (TLS_CERT=$1 TLS_KEY=$2 DOMAIN=${3:-offline.test}; check_tls_files) 2>&1; }
tls "$T/good.pem" "$T/good.key" >/dev/null || fail "a good certificate was refused"
grep -q "isn't for offline.test" <<<"$(tls "$T/other.pem" "$T/other.key" || true)" || fail "a certificate for another name was accepted"
grep -q "doesn't match" <<<"$(tls "$T/good.pem" "$T/other.key" || true)" || fail "a key for another certificate was accepted"
grep -q "isn't a PEM certificate" <<<"$(tls "$T/good.key" "$T/good.key" || true)" || fail "a key given as the certificate was accepted"
# shellcheck disable=SC2034
grep -q "both --tls-cert and --tls-key" <<<"$( (TLS_CERT=$T/good.pem TLS_KEY="" DOMAIN=offline.test; check_tls_files) 2>&1 || true)" || fail "a certificate without a key was accepted"
cert offline.test soon 10
grep -q "ends within 30 days" <<<"$(tls "$T/soon.pem" "$T/soon.key")" || fail "no warning for a certificate about to end"
mkdir -p "$T/ca/new"
: >"$T/ca/index.txt"
printf '%s\n' '[ca]' 'default_ca = d' '[d]' "database = $T/ca/index.txt" "new_certs_dir = $T/ca/new" \
  "serial = $T/ca/serial" 'default_md = sha256' 'policy = p' 'copy_extensions = copy' '[p]' 'commonName = supplied' >"$T/ca/ca.cnf"
echo 01 >"$T/ca/serial"
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj /CN=offline.test \
  -addext subjectAltName=DNS:offline.test -keyout "$T/future.key" -out "$T/future.csr" 2>/dev/null
openssl ca -batch -selfsign -config "$T/ca/ca.cnf" -keyfile "$T/future.key" -in "$T/future.csr" \
  -startdate 20990101000000Z -enddate 20991231000000Z -out "$T/future.pem" >/dev/null 2>&1 || fail "couldn't make a future certificate"
grep -q "isn't valid until" <<<"$(tls "$T/future.pem" "$T/future.key" || true)" || fail "a certificate that starts in 2099 was accepted"
ok "an operator certificate must be PEM, a pair, for --domain, and valid now; one about to end is a warning"

# The Caddyfile: unchanged without a certificate, no CA and no OCSP with one.
plain=$(render_caddyfile bots.example.com 127.0.0.1:3000 /var/www/superbot-app /var/www/superbot-site)
[[ "$(sed -n 1p <<<"$plain")" == "bots.example.com {" ]] || fail "the online Caddyfile gained a global block"
! grep -Eq '^[[:space:]]*(tls|auto_https|ocsp_stapling)' <<<"$plain" || fail "the online Caddyfile gained TLS settings"
with=$(render_caddyfile bots.example.com 127.0.0.1:3000 /var/www/superbot-app /var/www/superbot-site /etc/caddy/superbot-tls)
grep -qx $'\tauto_https disable_certs' <<<"$with" || fail "no auto_https disable_certs"
grep -qx $'\tocsp_stapling off' <<<"$with" || fail "no ocsp_stapling off"
grep -qx $'\ttls /etc/caddy/superbot-tls/cert.pem /etc/caddy/superbot-tls/key.pem' <<<"$with" || fail "no tls line"
[[ "$(sed '1,/^$/d' <<<"$with" | grep -v $'^\ttls ')" == "$plain" ]] || fail "the certificate changed more than the TLS lines"
if command -v caddy >/dev/null 2>&1; then
  mkdir -p "$T/tls"
  cp "$T/good.pem" "$T/tls/cert.pem"
  cp "$T/good.key" "$T/tls/key.pem"
  render_caddyfile offline.test 127.0.0.1:3000 "$T" "$T" "$T/tls" >"$T/Caddyfile"
  caddy validate --adapter caddyfile --config "$T/Caddyfile" >/dev/null 2>&1 || { caddy validate --adapter caddyfile --config "$T/Caddyfile" >&2 || true; fail "caddy refused the offline Caddyfile"; }
  ok "the Caddyfile is the same without a certificate; with one, no CA and no OCSP, and caddy validates it"
else
  ok "the Caddyfile is the same without a certificate; with one, no CA and no OCSP (caddy not here to validate)"
fi

# A dry run of the whole offline install, as main runs it, without root. With unprivileged
# namespaces, it runs with no network at all.
cat >"$T/run.sh" <<'EOF'
set -euo pipefail
export SUPERBOT_INSTALL_NO_MAIN=1
source "$1"
shift
need_root() { :; }
getent() { [[ $1 != passwd ]] && command getent "$@"; }
id() { [[ $# -eq 0 || $1 == -* ]] && command id "$@"; }
main "$@"
EOF
net=()
if unshare -rn true 2>/dev/null; then net=(unshare -rn); fi
"${net[@]}" bash "$T/run.sh" "$DIR/install.sh" --dry-run --non-interactive --offline "$B" \
  --domain offline.test --tls-cert "$T/good.pem" --tls-key "$T/good.key" --tz UTC >"$T/dry.log" 2>&1 \
  || { cat "$T/dry.log" >&2; fail "the offline dry run failed"; }
for want in "Offline bundle $VERSION ($ARCH" "Bundle SHA-256 matches" "would copy deploy templates from the bundle" \
  "/bin/botd /usr/local/bin/botd" "would install the bundle's web client into root-owned /var/www/superbot-app" \
  "would install the landing page from /tmp/" "would serve offline.test with the certificate in $T/good.pem" \
  "would record bundle $VERSION" "Offline: no packages" "--offline <newer bundle> --upgrade --domain offline.test" "SuperBot is installed."; do
  grep -Fq -- "$want" "$T/dry.log" || { cat "$T/dry.log" >&2; fail "the offline dry run didn't say: $want"; }
done
if grep -Ei 'apt-get|rustup|nodesource|cloudsmith|would fetch|git clone|npm ci|build the web client in|cargo build' "$T/dry.log"; then
  fail "the offline dry run reached for the network"
fi
first_line() { awk -v s="$1" 'index($0, s) { print NR; exit }' "$2"; }
rec=$(first_line "would record bundle $VERSION" "$T/dry.log")
bin=$(first_line "/bin/botd /usr/local/bin/botd" "$T/dry.log")
if [[ -z "$rec" || -z "$bin" ]] || ((rec > bin)); then
  fail "the bundle's version is recorded after its binaries are installed"
fi
ok "a dry run of the offline install uses only the bundle${net:+ (with no network)}"
