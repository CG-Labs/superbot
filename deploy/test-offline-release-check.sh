#!/usr/bin/env bash
# deploy/offline-release-check.sh without root or a network
# (docs/adr/0172-release-bundles-checked-end-to-end.md): a release of two bundles passes both
# phases, and each thing the check is for is caught: a missing or wrong signature or SHA-256, the
# wrong commit or version, binaries for another arch or a newer glibc, unsigned images, a tag that
# moved in the registry, an arch's image that differs, an image signature that fails, and, offline,
# a mirror that names another digest or has no verified provenance. So is each Hermes and harness
# bundle (ADR 0247) that is missing, unsigned, at other pins than the release's botd's, from
# another commit, of programs for another arch, or that botd wouldn't serve to machines. cosign,
# skopeo, botd and superbot-oci are stand-ins; the real check runs in .github/workflows/offline.yml (CI's own
# signed release) and offline-release-check.yml (each published release, against ghcr.io).
#   deploy/test-offline-release-check.sh
set -euo pipefail

DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
T=$(mktemp -d)
trap 'chmod -R u+rwX "$T" 2>/dev/null; rm -rf "$T"' EXIT

fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
ok() { printf 'ok - %s\n' "$*"; }

command -v jq >/dev/null 2>&1 || fail "this test needs jq"
VERSION=0.1.0-check
COMMIT=$(printf 'c%.0s' {1..40})
REF=reg.test/cg/superbot:$VERSION
CHECK="$DIR/offline-release-check.sh"

mkdir -p "$T/bin" "$T/client/_expo/static/js/web" "$T/stub" "$T/reg"
for b in botctl superbot-machine superbot-run; do printf '#!/bin/sh\necho %s\n' "$b" >"$T/bin/$b"; done
# botd as the check runs the release's own: harness pins prints STUB_PINS, and harness
# check-bundles says what machines would take, as the real one does (ADR 0247), unless
# STUB_BOTD_FAIL makes it refuse or STUB_BOTD_SUMMARY says something else last.
cat >"$T/bin/botd" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
[[ ${1:-} == harness ]] || { echo botd; exit 0; }
case ${2:-} in
  pins) cat "${STUB_PINS:?}" ;;
  check-bundles)
    shift 2
    [[ -z ${STUB_BOTD_FAIL:-} ]] || { echo "$STUB_BOTD_FAIL" >&2; exit 1; }
    for f in "$@"; do
      a=${f%.tar.gz} sum=$(sha256sum "$f" | cut -c1-64)
      [[ "$sum" == "$(cut -c1-64 "$f.sha256")" ]] || { echo "$f has SHA-256 $sum" >&2; exit 1; }
      case $(basename "$f") in
        superbot-hermes-*) echo "${a##*-} Hermes bundle $(realpath "$f"): Hermes Agent, SHA-256 $sum" ;;
        superbot-harnesses-*) echo "${a##*-} harness bundle $(realpath "$f"): claude, codex, pi, SHA-256 $sum" ;;
      esac
    done
    echo "${STUB_BOTD_SUMMARY:-Machines would install claude, codex, pi, hermes from these bundles}"
    ;;
  *) exit 2 ;;
esac
EOF
HTAG=v0.1.0
HCOMMIT=$(printf 'e%.0s' {1..40})
{
  printf 'node 22.0.1 x86_64 %s\nnode 22.0.1 aarch64 %s\n' "$(printf 'a%.0s' {1..64})" "$(printf 'b%.0s' {1..64})"
  printf 'npm claude 2.1.0 @anthropic-ai/claude-code sha512-Y2xhdWRl\nnpm codex 0.1.0 @openai/codex sha512-Y29kZXg=\n'
  printf 'npm pi 1.0.0 @earendil-works/pi-coding-agent sha512-cGk=\nhermes hermes %s %s %s\n' "$HCOMMIT" "$HTAG" "$(printf 'f%.0s' {1..64})"
} >"$T/pins"
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
# With a trailing newline, as some registries serve it: the digest is of every byte.
{ index_json "$AMD" "$ARM"; echo; } >"$T/reg/index.json"
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
stubbed() {
  STUB_REG="$T/reg" STUB_RAW="${RAW:-}" STUB_COSIGN_FAIL="${FAIL:-}" STUB_PINS="${PINS:-$T/pins}" STUB_BOTD_FAIL="${BOTD_FAIL:-}" \
    STUB_BOTD_SUMMARY="${SUMMARY:-}" PATH="$T/stub:$PATH" "$@"
}

# ELF FILE for MACHINE (\x3e, \xb7) asking for GLIBC, as the check reads one.
elf() { printf '\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00'"$2"'\x00GLIBC_2.17 GLIBC_%s\n' "$3" >"$1"; chmod 0755 "$1"; }
machine() { case $1 in x86_64) printf '%s\n' '\x3e' ;; *) printf '%s\n' '\xb7' ;; esac; }

# A Hermes or harness bundle in OUT for ARCH as offline-bundle.sh hermes and harnesses make them,
# at the stand-in botd's pins, with ELF stand-ins for its programs (for TREE_ARCH, needing
# TREE_GLIBC) and a script beside them. Its packages' native files are its arch's, needing
# NATIVE_GLIBC, and the other arch's, needing a glibc no Ubuntu has, in a read-only folder.
# CMD runs in its folder before it is summed.
tool_bundle() {
  local out=$1 kind=$2 a=$3 x="$T/tool" top t name inner pkg other
  shift 3
  if [[ -d "$x" ]]; then chmod -R u+w "$x"; fi
  rm -rf "$x" && mkdir -p "$x"
  other=$([[ $a == x86_64 ]] && echo aarch64 || echo x86_64)
  if [[ $kind == hermes ]]; then
    top="superbot-hermes-$HTAG-$a" name=hermes inner=hermes.tar
    t="$x/tree/hermes" && mkdir -p "$t/.local/bin" "$t/.local/share/uv/python/cpython-3.14.9/bin"
    elf "$t/.local/bin/uv" "$(machine "${TREE_ARCH:-$a}")" "${TREE_GLIBC:-2.17}"
    elf "$t/.local/share/uv/python/cpython-3.14.9/bin/python3.14" "$(machine "${TREE_ARCH:-$a}")" 2.17
    ln -s python3.14 "$t/.local/share/uv/python/cpython-3.14.9/bin/python3"
    printf '#!/bin/sh\n' >"$t/.local/bin/hermes"
    pkg="$t/.hermes/installs/k/environments/g/venv/lib/python3.14/site-packages/native"
    mkdir -p "$pkg"
    elf "$pkg/_core.$a.so" "$(machine "$a")" "${NATIVE_GLIBC:-2.17}"
    elf "$pkg/_core.$other.so" "$(machine "$other")" 2.99
  else
    top="superbot-harnesses-$VERSION-$a" name=superbot-harnesses inner=harnesses.tar
    t="$x/tree/superbot-harnesses" && mkdir -p "$t/bin"
    elf "$t/bin/node" "$(machine "${TREE_ARCH:-$a}")" "${TREE_GLIBC:-2.28}"
    printf '#!/bin/sh\n' >"$t/bin/claude"
    pkg="$t/lib/node_modules/@anthropic-ai/claude-code/vendor/ripgrep"
    mkdir -p "$pkg/$a-linux" "$pkg/$other-linux"
    elf "$pkg/$a-linux/rg" "$(machine "$a")" "${NATIVE_GLIBC:-2.17}"
    elf "$pkg/$other-linux/rg" "$(machine "$other")" 2.99
  fi
  chmod a-w "$pkg"
  mkdir -p "$x/$top"
  tar -C "$x/tree" --owner=0 --group=0 --numeric-owner --sort=name -cf "$x/$top/$inner" "$name"
  (
    cd "$x/$top"
    if [[ $kind == hermes ]]; then
      printf 'format=1\nkind=hermes\nhermes_tag=%s\nhermes_commit=%s\nprefix=/opt/hermes\narch=%s\ncommit=%s\n' "$HTAG" "$HCOMMIT" "$a" "$COMMIT" >MANIFEST
    else
      printf 'format=1\nkind=harnesses\nversion=%s\nprefix=/opt/superbot-harnesses\narch=%s\nharnesses=claude codex pi\n' "$VERSION" "$a" >MANIFEST
      awk -v a="$a" '$1 == "node" && $3 == a { print "node=" $2 " " $4 } $1 == "npm" { print "harness_" $2 "=" $3 " " $4 " " $5 }' "$T/pins" >>MANIFEST
      echo "commit=$COMMIT" >>MANIFEST
    fi
    "$@"
    sha256sum "$inner" MANIFEST >SHA256SUMS
  )
  tar -C "$x" --owner=0 --group=0 --numeric-owner -czf "$out/$top.tar.gz" "$top"
  (cd "$out" && sha256sum "$top.tar.gz" >"$top.tar.gz.sha256")
  echo '{"stub":"sigstore bundle"}' >"$out/$top.tar.gz.sigstore.json"
}

# A release: each arch's bundle built by offline-bundle.sh, then given a signed image as build
# would (images/, signatures/, MANIFEST), with its .sha256 and a .sigstore.json, and each arch's
# Hermes and harness bundles.
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
    tool_bundle "$out" hermes "$a" true
    tool_bundle "$out" harnesses "$a" true
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

for a in x86_64 aarch64; do
  for kind in hermes harnesses; do
    f=$([[ $kind == hermes ]] && echo "superbot-hermes-$HTAG-$a.tar.gz" || echo "superbot-harnesses-$VERSION-$a.tar.gz")
    grep -qx "$kind $a $f $(cut -c1-64 "$T/good/$f.sha256")" "$exp" || fail "release-check.expected doesn't record $f"
    grep -Fq "verify-blob --bundle $T/good/$f.sigstore.json --key $T/cosign.pub" "$T/reg/cosign.log" || fail "$f's signature wasn't checked"
  done
done
grep -Fq "The release's botd would serve both arches' Hermes and harness bundles to machines: claude, codex, pi, hermes" <<<"$out" \
  || { printf '%s\n' "$out" >&2; fail "the online check didn't ask the release's botd about its Hermes and harness bundles"; }
ok "both arches' Hermes and harness bundles are checked and recorded, and the release's botd would serve them to machines"

: >"$T/reg/cosign.log"
out=$(offline "$T/good") || { printf '%s\n' "$out" >&2; fail "a good release failed the offline check"; }
grep -Fqx "localhost:5002/mirror/superbot:$VERSION" "$T/reg/pushed" || fail "the offline check didn't push to the mirror"
for want in "verify localhost:5002/mirror/superbot:$VERSION --key" "verify localhost:5002/mirror/superbot@$AMD --key" \
  "verify localhost:5002/mirror/superbot@$ARM --key" "verify-attestation --type slsaprovenance1 localhost:5002/mirror/superbot:$VERSION --key"; do
  grep -Fq "$want" "$T/reg/cosign.log" || fail "the offline check didn't run cosign $want"
done
grep -Fq "is the signed index $INDEX; it, its 2 manifests and its provenance verify with no network" <<<"$out" || fail "the offline check didn't report the mirror"
for f in "superbot-hermes-$HTAG-aarch64.tar.gz" "superbot-harnesses-$VERSION-x86_64.tar.gz"; do
  grep -Fq "$f: signature and every file verified with no network" <<<"$out" || fail "the offline check didn't verify $f"
done
ok "offline, both bundles verify and go to the mirror, where the index, each image and the provenance are verified, and the Hermes and harness bundles verify"

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
# This release's botd is an ELF stand-in, which can't say its pins.
refused "binaries needing a newer glibc" "needs glibc 2.39, newer than 2.35" online "$T/glibcrel" --any-binary-arch --max-glibc 2.35 --without-harness-bundles
out=$(online "$T/glibcrel" --any-binary-arch --max-glibc 2.39 --without-harness-bundles) || { printf '%s\n' "$out" >&2; fail "binaries within --max-glibc were refused"; }
ok "binaries that need a newer glibc than the oldest supported Ubuntu's are refused"

index_json "$ARM" "$AMD" >"$T/reg/moved.json"
RAW="$T/reg/moved.json" refused "a tag that moved" "the tag has moved since the bundles were made" online "$T/good" --any-binary-arch
FAIL="verify reg.test" refused "an image signature that fails" "isn't signed by $T/cosign.pub" online "$T/good" --any-binary-arch
other=sha256:$(printf 'other' | sha256sum | cut -c1-64)
index_json "$AMD" "$other" >"$T/reg/index.json"
INDEX=sha256:$(sha256sum <"$T/reg/index.json" | cut -c1-64)
release "$T/armdiff" true
refused "an arch's image that differs" "linux/arm64 image is $other, but the aarch64 bundle carries $ARM" online "$T/armdiff" --any-binary-arch
{ index_json "$AMD" "$ARM"; echo; } >"$T/reg/index.json"
INDEX=sha256:$(sha256sum <"$T/reg/index.json" | cut -c1-64)
ok "a tag that moved, an image signature that fails, and an arch's image that differs from the bundle's are refused"

refused "no online check first" "run the online check first" offline "$T/nothing"
refused "keyless with no trusted root" "give --trusted-root" stubbed "$CHECK" offline "$T/good" --mirror localhost:5002/mirror --no-network-probe
RAW="$T/reg/moved.json" refused "a mirror naming another digest" "not the signed index $INDEX" offline "$T/good"
FAIL="verify-attestation" refused "no verified provenance in the mirror" "no verified build provenance" offline "$T/good"
FAIL="verify localhost:5002/mirror/superbot@$ARM" refused "an image in the mirror whose signature fails" "cosign verify failed for localhost:5002/mirror/superbot@$ARM" offline "$T/good"
cp "$T/good/release-check.expected" "$T/exp.bak"
sed -i '/^image /d' "$T/good/release-check.expected"
refused "a record without its image lines" 'records images "", but the bundles hold "superbot"' offline "$T/good"
cp "$T/exp.bak" "$T/good/release-check.expected"
echo "image other reg.test/cg/other:1 $INDEX" >>"$T/good/release-check.expected"
refused "a record naming an image the bundles don't hold" 'records images "other superbot"' offline "$T/good"
cp "$T/exp.bak" "$T/good/release-check.expected"
printf '%064d  x\n' 0 >"$T/sum"
sed -i "s/^bundle aarch64 .*/bundle aarch64 $(cut -c1-64 "$T/sum")/" "$T/good/release-check.expected"
refused "a bundle that changed after the online check" "doesn't verify offline" offline "$T/good"
ok "offline, a missing or cut-short online record or trusted root, a mirror naming another digest, an unverified image or provenance, and a changed bundle are refused"

# The Hermes and harness bundles (docs/adr/0247-hermes-and-harness-bundles-in-the-release-check.md).
release "$T/tools" true
fresh() { rm -rf "$T/t2" && cp -r "$T/tools" "$T/t2"; }
HB="superbot-hermes-$HTAG-aarch64.tar.gz" NB="superbot-harnesses-$VERSION-x86_64.tar.gz"
fresh && rm "$T/t2/$HB"
refused "a release without a Hermes bundle" "The release has no $HB" online "$T/t2" --any-binary-arch
fresh && rm "$T/t2/$NB.sigstore.json"
refused "a harness bundle without its signature" "The release has no $NB.sigstore.json" online "$T/t2" --any-binary-arch
fresh && printf '%064d  x\n' 0 >"$T/t2/$NB.sha256"
refused "a harness bundle whose .sha256 doesn't match" "$NB is" online "$T/t2" --any-binary-arch
FAIL="verify-blob --bundle $T/tools/$HB" refused "a Hermes bundle signature that fails" "$HB's signature doesn't verify" online "$T/tools" --any-binary-arch
fresh && tool_bundle "$T/t2" hermes aarch64 sed -i 's/^kind=.*/kind=other/' MANIFEST
refused "a Hermes bundle the installer refuses" "$HB isn't a good Hermes bundle" online "$T/t2" --any-binary-arch
ok "a release missing a Hermes or harness bundle or its signature, or with a wrong SHA-256, signature or bundle, is refused"

fresh && tool_bundle "$T/t2" hermes aarch64 sed -i "s/^hermes_commit=.*/hermes_commit=$(printf 'd%.0s' {1..40})/" MANIFEST
refused "a Hermes bundle of another Hermes Agent" "holds Hermes Agent $HTAG ($(printf 'd%.0s' {1..40})), but the release's botd pins $HTAG ($HCOMMIT)" online "$T/t2" --any-binary-arch
fresh && tool_bundle "$T/t2" harnesses x86_64 sed -i '/^harness_pi=/d' MANIFEST
refused "a harness bundle without Pi" "$NB doesn't hold what the release's botd pins (pi is missing" online "$T/t2" --any-binary-arch
fresh && tool_bundle "$T/t2" harnesses x86_64 sed -i 's/^harness_claude=2.1.0/harness_claude=2.0.9/' MANIFEST
refused "a harness bundle of another Claude Code" "(claude is 2.0.9 @anthropic-ai/claude-code sha512-Y2xhdWRl, not 2.1.0" online "$T/t2" --any-binary-arch
fresh && tool_bundle "$T/t2" harnesses x86_64 sed -i "s/^commit=.*/commit=$(printf 'd%.0s' {1..40})/" MANIFEST
refused "a harness bundle from another commit" "$NB was built from $(printf 'd%.0s' {1..40}), not the tag's commit" online "$T/t2" --any-binary-arch
fresh && tool_bundle "$T/t2" hermes aarch64 sed -i 's/^arch=.*/arch=x86_64/' MANIFEST
refused "a Hermes bundle for another arch" "$HB says it is for x86_64" online "$T/t2" --any-binary-arch
printf 'hermes hermes %s %s x\n' "$HCOMMIT" "$HTAG" >"$T/badpins"
PINS="$T/badpins" refused "a botd that doesn't say its pins" "doesn't say which harness CLIs it pins" online "$T/tools" --any-binary-arch
grep -v '^hermes ' "$T/pins" >"$T/nohermes"
PINS="$T/nohermes" refused "a botd that pins no Hermes Agent" "pins no Hermes Agent release" online "$T/tools" --any-binary-arch
BOTD_FAIL="no Hermes bundle for aarch64" refused "a botd that wouldn't serve the bundles" "wouldn't serve these bundles to machines" online "$T/tools" --any-binary-arch
SUMMARY="Machines would install claude, codex, pi from these bundles, and hermes from the internet or the operator's mirrors" \
  refused "a botd that would fetch Hermes Agent for machines" "wouldn't install every harness it pins from these bundles" online "$T/tools" --any-binary-arch
ok "Hermes and harness bundles at other pins, commits or arches than the release's botd's, and a botd that won't say its pins or serve them, are refused"

# The programs in a tree are read without unpacking it (tree_programs_ok, sourced as the ELF
# readers are above, as the release's binaries are ELF stand-ins that can't run).
tree_ok() (
  source /dev/stdin <<<"$(sed -n '/^elf_arch()/,/^}/p; /^glibc_needed()/p; /^version_le()/p; /^tree_programs_ok()/,/^}/p' "$CHECK")"
  # shellcheck disable=SC2317 # called by tree_programs_ok
  die() { printf '%s\n' "$*"; exit 1; }
  # shellcheck disable=SC2034 # read by tree_programs_ok
  WORK=$(mktemp -d -p "$T")
  tree_programs_ok "$@"
)
mkdir -p "$T/trees"
tool_bundle "$T/trees" hermes aarch64 true
tool_bundle "$T/trees" harnesses x86_64 true
hermes_programs=("superbot-hermes-$HTAG-aarch64/hermes.tar" aarch64 2.35 'hermes/.local/bin/*' 'hermes/.local/share/uv/python/*/bin/*')
out=$(tree_ok "$T/trees/$HB" "${hermes_programs[@]}") || { printf '%s\n' "$out" >&2; fail "a Hermes tree of aarch64 programs was refused"; }
out=$(tree_ok "$T/trees/$NB" "superbot-harnesses-$VERSION-x86_64/harnesses.tar" x86_64 2.35 superbot-harnesses/bin/node) \
  || { printf '%s\n' "$out" >&2; fail "a harness tree with an x86_64 Node.js was refused"; }
TREE_ARCH=x86_64 tool_bundle "$T/trees" hermes aarch64 true
refused "an aarch64 Hermes bundle of x86_64 programs" "$HB's hermes/.local/bin/uv is built for x86_64, not aarch64" tree_ok "$T/trees/$HB" "${hermes_programs[@]}"
TREE_GLIBC=2.39 tool_bundle "$T/trees" hermes aarch64 true
refused "a Hermes bundle needing a newer glibc" "needs glibc 2.39, newer than 2.35" tree_ok "$T/trees/$HB" "${hermes_programs[@]}"
NATIVE_GLIBC=2.39 tool_bundle "$T/trees" harnesses x86_64 true
refused "a harness bundle whose npm package needs a newer glibc" \
  "$NB's superbot-harnesses/lib/node_modules/@anthropic-ai/claude-code/vendor/ripgrep/x86_64-linux/rg needs glibc 2.39, newer than 2.35" \
  tree_ok "$T/trees/$NB" "superbot-harnesses-$VERSION-x86_64/harnesses.tar" x86_64 2.35 superbot-harnesses/bin/node
NATIVE_GLIBC=2.39 tool_bundle "$T/trees" hermes aarch64 true
refused "a Hermes bundle whose Python package needs a newer glibc" "site-packages/native/_core.aarch64.so needs glibc 2.39, newer than 2.35" \
  tree_ok "$T/trees/$HB" "${hermes_programs[@]}"
refused "a tree without the programs" "has no program to check the arch of (nothing/*)" tree_ok "$T/trees/$NB" "superbot-harnesses-$VERSION-x86_64/harnesses.tar" x86_64 "" 'nothing/*'
ok "a Hermes or harness bundle's programs for another arch, or native files for its arch needing a newer glibc, are refused (other platforms' builds are skipped), as is a tree without them"

out=$(online "$T/tools" --any-binary-arch) || { printf '%s\n' "$out" >&2; fail "the release failed the online check"; }
cp "$T/tools/release-check.expected" "$T/exp.bak"
sed -i '/^hermes aarch64 /d' "$T/tools/release-check.expected"
refused "a record without an arch's Hermes bundle" "has no hermes bundle for aarch64" offline "$T/tools"
cp "$T/exp.bak" "$T/tools/release-check.expected"
sed -i 's|^harnesses x86_64 [^ ]*|harnesses x86_64 ../superbot-harnesses-x-x86_64.tar.gz|' "$T/tools/release-check.expected"
refused "a record naming a file outside the folder" "names \"../superbot-harnesses-x-x86_64.tar.gz\"" offline "$T/tools"
cp "$T/exp.bak" "$T/tools/release-check.expected"
sed -i "s/^\(hermes x86_64 [^ ]*\) .*/\1 $(printf 'a%.0s' {1..64})/" "$T/tools/release-check.expected"
refused "a Hermes bundle that changed after the online check" "superbot-hermes-$HTAG-x86_64.tar.gz doesn't verify offline" offline "$T/tools"
cp "$T/exp.bak" "$T/tools/release-check.expected"
mkdir -p "$T/main"
cp "$T/tools"/superbot-offline-* "$T/main/"
refused "a release without its Hermes and harness bundles" "The release has no superbot-hermes-$HTAG-x86_64.tar.gz" online "$T/main" --any-binary-arch
out=$(online "$T/main" --any-binary-arch --without-harness-bundles) || { printf '%s\n' "$out" >&2; fail "--without-harness-bundles still checked them"; }
grep -qx 'harness-bundles skipped' "$T/main/release-check.expected" || fail "the record doesn't say the Hermes and harness bundles were skipped"
out=$(offline "$T/main") || { printf '%s\n' "$out" >&2; fail "a record that skipped the Hermes and harness bundles failed offline"; }
grep -Fq "The online check skipped the Hermes and harness bundles" <<<"$out" || fail "the offline check didn't say they were skipped"
ok "offline, a record missing a Hermes or harness bundle, naming another file or another SHA-256 is refused; --without-harness-bundles is recorded and said"
