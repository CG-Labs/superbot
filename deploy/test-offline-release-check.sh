#!/usr/bin/env bash
# deploy/offline-release-check.sh without root or a network
# (docs/adr/0172-release-bundles-checked-end-to-end.md): a release of two bundles passes both
# phases, and each thing the check is for is caught: a missing or wrong signature or SHA-256, the
# wrong commit or version, binaries for another arch or a newer glibc, unsigned images, a tag that
# moved in the registry, an arch's image that differs, an image signature that fails, and, offline,
# a mirror that names another digest or has no verified provenance. cosign, skopeo and
# superbot-oci are stand-ins; the real check runs in .github/workflows/offline.yml (CI's own
# signed release) and offline-release-check.yml (each published release, against ghcr.io).
#   deploy/test-offline-release-check.sh
set -euo pipefail

DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT

fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
ok() { printf 'ok - %s\n' "$*"; }

command -v jq >/dev/null 2>&1 || fail "this test needs jq"
VERSION=0.1.0-check
COMMIT=$(printf 'c%.0s' {1..40})
REF=reg.test/cg/superbot:$VERSION
CHECK="$DIR/offline-release-check.sh"

mkdir -p "$T/bin" "$T/client/_expo/static/js/web" "$T/stub" "$T/reg"
for b in botd botctl superbot-machine superbot-run; do printf '#!/bin/sh\necho %s\n' "$b" >"$T/bin/$b"; done
# superbot-oci as push runs it: --version, then push [--check] --to DEST UNIT..., printing the
# digest the tag names (the index in the units' signatures/, as the real one would).
cat >"$T/bin/superbot-oci" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
[[ ${1:-} == --version ]] && { echo superbot-oci stub; exit 0; }
[[ ${1:-} == push ]] || exit 2
shift
[[ ${1:-} == --check ]] && shift
[[ $1 == --to ]] || exit 2
dest=$2
shift 2
cat "$1/signatures/index-digest"
echo "$dest" >>"${STUB_REG:?}/pushed"
EOF
chmod 0755 "$T/bin/"*
echo '<!doctype html><script src="/app/_expo/static/js/web/entry-abc.js"></script>' >"$T/client/index.html"
echo 'console.log(1)' >"$T/client/_expo/static/js/web/entry-abc.js"

# The registry: an index naming an amd64 and an arm64 image, by digest.
AMD=sha256:$(printf 'amd' | sha256sum | cut -c1-64)
ARM=sha256:$(printf 'arm' | sha256sum | cut -c1-64)
index_json() {
  printf '{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[{"digest":"%s","platform":{"os":"linux","architecture":"amd64"}},{"digest":"%s","platform":{"os":"linux","architecture":"arm64"}}]}' "$1" "$2"
}
index_json "$AMD" "$ARM" >"$T/reg/index.json"
INDEX=sha256:$(sha256sum <"$T/reg/index.json" | cut -c1-64)

# skopeo inspect --raw docker://REF: the registry's index for any tag, unless STUB_RAW names
# another file. cosign: logs its arguments, and fails a command matching STUB_COSIGN_FAIL.
cat >"$T/stub/skopeo" <<'EOF'
#!/usr/bin/env bash
[[ $1 == inspect && $2 == --raw ]] || exit 2
echo "$3" >>"$STUB_REG/skopeo.log"
cat "${STUB_RAW:-$STUB_REG/index.json}"
EOF
cat >"$T/stub/cosign" <<'EOF'
#!/usr/bin/env bash
echo "$*" >>"$STUB_REG/cosign.log"
if [[ -n ${STUB_COSIGN_FAIL:-} && "$*" == *"$STUB_COSIGN_FAIL"* ]]; then echo "stub: no matching signatures" >&2; exit 1; fi
exit 0
EOF
chmod 0755 "$T/stub/"*
stubbed() { STUB_REG="$T/reg" STUB_RAW="${RAW:-}" STUB_COSIGN_FAIL="${FAIL:-}" PATH="$T/stub:$PATH" "$@"; }

# A release: each arch's bundle built by offline-bundle.sh, then given a signed image as build
# would (images/, signatures/, MANIFEST), with its .sha256 and a .sigstore.json.
release() {
  local out=$1 a top x darch digest
  shift
  rm -rf "$out" && mkdir -p "$out"
  for a in x86_64 aarch64; do
    "$DIR/offline-bundle.sh" build --out "$T/plain" --version "$VERSION" --arch "$a" --bin-dir "${BIN_DIR:-$T/bin}" \
      --client-dir "$T/client" >/dev/null 2>&1 || fail "the $a bundle didn't build"
    top="superbot-offline-$VERSION-$a"
    x="$T/x/$a"
    rm -rf "$x" && mkdir -p "$x"
    tar -xzf "$T/plain/$top.tar.gz" -C "$x"
    darch=$(case $a in x86_64) echo amd64 ;; *) echo arm64 ;; esac)
    digest=$([[ $darch == amd64 ]] && echo "$AMD" || echo "$ARM")
    (
      cd "$x/$top"
      mkdir -p images signatures
      echo "$REF" >images/superbot.ref
      echo "$digest" >images/superbot.digest
      echo "$INDEX" >images/superbot.index
      mkdir -p img sig && echo "image-$a" >img/oci-layout && echo "$INDEX" >sig/index-digest
      tar -cf images/superbot.tar -C img oci-layout && tar -cf signatures/superbot.tar -C sig index-digest && rm -r img sig
      sed -i "s/^commit=.*/commit=$COMMIT/; s/^images=.*/images=superbot\nimage_format=oci/" MANIFEST
      "$@"
      find . -type f ! -path ./SHA256SUMS -printf '%P\n' | LC_ALL=C sort | xargs -d '\n' sha256sum >SHA256SUMS
    )
    tar -C "$x" --owner=0 --group=0 -czf "$out/$top.tar.gz" "$top"
    (cd "$out" && sha256sum "$top.tar.gz" >"$top.tar.gz.sha256")
    echo '{"stub":"sigstore bundle"}' >"$out/$top.tar.gz.sigstore.json"
  done
}
online() { stubbed "$CHECK" online "$1" --version "$VERSION" --image "superbot=$REF" --commit "$COMMIT" --key "$T/cosign.pub" "${@:2}" 2>&1; }
offline() { stubbed "$CHECK" offline "$1" --mirror localhost:5002/mirror --key "$T/cosign.pub" --no-network-probe "${@:2}" 2>&1; }
refused() {
  local why=$1 want=$2 out
  shift 2
  if out=$("$@" 2>&1); then printf '%s\n' "$out" >&2; fail "$why: accepted"; fi
  grep -Fq "$want" <<<"$out" || { printf '%s\n' "$out" >&2; fail "$why: refused for another reason"; }
}
echo 'stub public key' >"$T/cosign.pub"

release "$T/good" true
out=$(online "$T/good" --any-binary-arch) || { printf '%s\n' "$out" >&2; fail "a good release failed the online check"; }
grep -Fq "superbot: $REF is $INDEX in its registry" <<<"$out" || fail "the online check didn't report the image"
exp="$T/good/release-check.expected"
grep -qx "version $VERSION" "$exp" || fail "release-check.expected has no version"
grep -qx "bundle x86_64 $(cut -c1-64 "$T/good/superbot-offline-$VERSION-x86_64.tar.gz.sha256")" "$exp" || fail "release-check.expected has no x86_64 SHA-256"
grep -qx "image superbot $REF $INDEX" "$exp" || fail "release-check.expected has no image"
for a in x86_64 aarch64; do
  grep -Fq "verify-blob --bundle $T/good/superbot-offline-$VERSION-$a.tar.gz.sigstore.json --key $T/cosign.pub --insecure-ignore-tlog=true" "$T/reg/cosign.log" \
    || fail "the $a bundle's signature wasn't checked against the key"
done
grep -Fqx "verify reg.test/cg/superbot@$INDEX --key $T/cosign.pub --insecure-ignore-tlog=true" "$T/reg/cosign.log" || fail "the signed index wasn't checked in its registry"
ok "a release of two signed bundles passes the online check, which records their SHA-256s and the signed index"

: >"$T/reg/cosign.log"
out=$(offline "$T/good") || { printf '%s\n' "$out" >&2; fail "a good release failed the offline check"; }
grep -Fqx "localhost:5002/mirror/superbot:$VERSION" "$T/reg/pushed" || fail "the offline check didn't push to the mirror"
for want in "verify localhost:5002/mirror/superbot:$VERSION --key" "verify localhost:5002/mirror/superbot@$AMD --key" \
  "verify localhost:5002/mirror/superbot@$ARM --key" "verify-attestation --type slsaprovenance1 localhost:5002/mirror/superbot:$VERSION --key"; do
  grep -Fq "$want" "$T/reg/cosign.log" || fail "the offline check didn't run cosign $want"
done
grep -Fq "is the signed index $INDEX; it, its 2 manifests and its provenance verify with no network" <<<"$out" || fail "the offline check didn't report the mirror"
ok "offline, both bundles verify and go to the mirror, where the index, each image and the provenance are verified"

g="$T/good/superbot-offline-$VERSION-aarch64.tar.gz"
mv "$g.sigstore.json" "$T/sig.bak"
refused "a bundle without its signature" "no superbot-offline-$VERSION-aarch64.tar.gz.sigstore.json" online "$T/good" --any-binary-arch
mv "$T/sig.bak" "$g.sigstore.json"
cp "$g.sha256" "$T/sum.bak"
printf '%064d  x\n' 0 >"$g.sha256"
refused "a .sha256 that doesn't match" "but its .sha256 says" online "$T/good" --any-binary-arch
mv "$T/sum.bak" "$g.sha256"
FAIL="verify-blob --bundle $g" refused "a bundle signature that fails" "signature doesn't verify" online "$T/good" --any-binary-arch
mkdir -p "$T/onearch"
cp "$g" "$g.sha256" "$g.sigstore.json" "$T/onearch/"
refused "a missing arch" "no superbot-offline-$VERSION-x86_64.tar.gz" online "$T/onearch" --any-binary-arch
ok "a release missing a bundle or signature, or with a wrong SHA-256 or signature, is refused"

refused "the wrong commit" "was built from $COMMIT, not the tag's commit" online "$T/good" --any-binary-arch --commit "$(printf 'd%.0s' {1..40})"
refused "the wrong version" "isn't a version" online "$T/good" --any-binary-arch --version 'v1'
release "$T/unsigned" sed -i '$ a unsigned_images=true' MANIFEST
refused "an unsigned image" "bundled without a signature check" online "$T/unsigned" --any-binary-arch
release "$T/noindex" rm images/superbot.index
refused "an image without its signed index" "doesn't hold signed images" online "$T/noindex" --any-binary-arch
refused "a missing image" 'not "other superbot"' online "$T/good" --any-binary-arch --image other=reg.test/cg/other:1
ok "the wrong commit, version or images, unsigned images and images without a signed index are refused"

refused "binaries that aren't for their arch" "is built for not-elf, not x86_64" online "$T/good"
mkdir -p "$T/elf"
elf() { printf '\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00'"$2"'\x00GLIBC_2.17 GLIBC_%s\n' "$3" >"$1"; chmod 0755 "$1"; }
for b in botd botctl superbot-machine superbot-run superbot-oci; do elf "$T/elf/$b" '\x3e' 2.39; done
BIN_DIR="$T/elf" release "$T/elfrel" true
refused "an aarch64 bundle with x86_64 binaries" "aarch64.tar.gz's bin/botd is built for x86_64, not aarch64" online "$T/elfrel"
[[ $(source /dev/stdin <<<"$(sed -n '/^elf_arch()/,/^}/p; /^glibc_needed()/p' "$CHECK")"; glibc_needed "$T/elf/botd") == 2.39 ]] \
  || fail "glibc_needed didn't find 2.39"
[[ $(source /dev/stdin <<<"$(sed -n '/^elf_arch()/,/^}/p' "$CHECK")"; elf_arch "$T/elf/botd") == x86_64 ]] || fail "elf_arch didn't read x86_64"
elf "$T/elf/arm" '\xb7' 2.35
[[ $(source /dev/stdin <<<"$(sed -n '/^elf_arch()/,/^}/p' "$CHECK")"; elf_arch "$T/elf/arm") == aarch64 ]] || fail "elf_arch didn't read aarch64"
ok "binaries built for another arch are refused, and the ELF machine and glibc versions are read"

mkdir -p "$T/glibc"
for b in botd botctl superbot-machine superbot-run; do elf "$T/glibc/$b" '\x3e' 2.39; done
cp "$T/bin/superbot-oci" "$T/glibc/superbot-oci"
BIN_DIR="$T/glibc" release "$T/glibcrel" true
refused "binaries needing a newer glibc" "needs glibc 2.39, newer than 2.35" online "$T/glibcrel" --any-binary-arch --max-glibc 2.35
out=$(online "$T/glibcrel" --any-binary-arch --max-glibc 2.39) || { printf '%s\n' "$out" >&2; fail "binaries within --max-glibc were refused"; }
ok "binaries that need a newer glibc than the oldest supported Ubuntu's are refused"

index_json "$ARM" "$AMD" >"$T/reg/moved.json"
RAW="$T/reg/moved.json" refused "a tag that moved" "the tag has moved since the bundles were made" online "$T/good" --any-binary-arch
FAIL="verify reg.test" refused "an image signature that fails" "isn't signed by $T/cosign.pub" online "$T/good" --any-binary-arch
other=sha256:$(printf 'other' | sha256sum | cut -c1-64)
index_json "$AMD" "$other" >"$T/reg/index.json"
INDEX=sha256:$(sha256sum <"$T/reg/index.json" | cut -c1-64)
release "$T/armdiff" true
refused "an arch's image that differs" "linux/arm64 image is $other, but the aarch64 bundle carries $ARM" online "$T/armdiff" --any-binary-arch
index_json "$AMD" "$ARM" >"$T/reg/index.json"
INDEX=sha256:$(sha256sum <"$T/reg/index.json" | cut -c1-64)
ok "a tag that moved, an image signature that fails, and an arch's image that differs from the bundle's are refused"

refused "no online check first" "run the online check first" offline "$T/nothing"
refused "keyless with no trusted root" "give --trusted-root" stubbed "$CHECK" offline "$T/good" --mirror localhost:5002/mirror --no-network-probe
RAW="$T/reg/moved.json" refused "a mirror naming another digest" "not the signed index $INDEX" offline "$T/good"
FAIL="verify-attestation" refused "no verified provenance in the mirror" "no verified build provenance" offline "$T/good"
FAIL="verify localhost:5002/mirror/superbot@$ARM" refused "an image in the mirror whose signature fails" "cosign verify failed for localhost:5002/mirror/superbot@$ARM" offline "$T/good"
printf '%064d  x\n' 0 >"$T/sum"
sed -i "s/^bundle aarch64 .*/bundle aarch64 $(cut -c1-64 "$T/sum")/" "$T/good/release-check.expected"
refused "a bundle that changed after the online check" "doesn't verify offline" offline "$T/good"
ok "offline, a missing online record or trusted root, a mirror naming another digest, an unverified image or provenance, and a changed bundle are refused"
