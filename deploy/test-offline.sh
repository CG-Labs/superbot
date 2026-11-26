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
# The stand-in botd pins harness CLIs as the real one does (botd harness pins, ADR 0232).
NODE_PIN=22.0.1
pins_botd() {
  {
    printf '#!/bin/sh\n[ "$*" = "harness pins" ] || { echo botd; exit 0; }\ncat <<EOF\n'
    printf 'node %s x86_64 %s\nnode %s aarch64 %s\n' "$NODE_PIN" "$(printf 'a%.0s' {1..64})" "$NODE_PIN" "$(printf 'b%.0s' {1..64})"
    printf 'npm claude %s @anthropic-ai/claude-code sha512-Y2xhdWRl\n' "${2:-2.1.0}"
    printf 'npm codex 0.1.0 @openai/codex sha512-Y29kZXg=\nnpm pi 1.0.0 @earendil-works/pi-coding-agent sha512-cGk=\n'
    printf 'hermes hermes %s v0.0.1 %s\nEOF\n' "$(printf 'e%.0s' {1..40})" "$(printf 'f%.0s' {1..64})"
  } >"$1"
  chmod 0755 "$1"
}
pins_botd "$T/bin/botd"
echo '<!doctype html><script src="/app/_expo/static/js/web/entry-abc.js"></script>' >"$T/client/index.html"
echo 'console.log(1)' >"$T/client/_expo/static/js/web/entry-abc.js"
echo font >"$T/client/assets/node_modules/@expo/icons.ttf"

"$DIR/offline-bundle.sh" build --out "$T/out" --version "$VERSION" --bin-dir "$T/bin" --client-dir "$T/client" >"$T/build.log" 2>&1 \
  || { cat "$T/build.log" >&2; fail "the bundle didn't build"; }
B="$T/out/superbot-offline-$VERSION-$ARCH.tar.gz"
[[ -f "$B" && -f "$B.sha256" ]] || fail "no bundle and .sha256 in $T/out"
names=$(tar -tf "$B")
for f in MANIFEST SHA256SUMS bin/botd bin/botctl deploy/install.sh deploy/offline-bundle.sh deploy/superbot.service env.example site/index.html client/index.html docker/docker-compose.yml docker/docker-compose.hermes.yml docker/.env.example; do
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
refused "$T/anchor.tar.gz" "Nothing to check $T/anchor.tar.gz against" "a bundle with no SHA-256 or signature beside it"
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

# Hermes bundles (docs/adr/0200-hermes-agent-bundle-for-air-gapped-installs.md), from a tree laid
# out as Hermes's installer leaves one with HOME=/opt/hermes: its checkout at the pinned commit,
# its install's record, the hermes Bots run, links inside it (relative and absolute), a hard link,
# and a cache, which isn't bundled. The real install, as root with no network, is in offline.yml.
pin_of() {
  awk -v field="$1" 'index($0, "bin: \"hermes\"") { f = 1 } f && index($0, field ": \"") { sub(".*" field ": \"", ""); sub("\".*", ""); print; exit }' \
    "$DIR/../server/src/adapters/install.rs"
}
HTAG=$(pin_of tag)
[[ "$(pin_of version)" == "$HERMES_COMMIT" ]] || fail "install.sh and install.rs pin different Hermes commits"
fake_hermes() {
  local h=$1/hermes
  mkdir -p "$h/.hermes/hermes-agent/.git" "$h/.hermes/installs/k/environments/g/venv/bin" "$h/.hermes/superbot" \
    "$h/.local/bin" "$h/.local/share/uv/python/cpython-3.14.9/bin" "$h/.cache/uv" "$h/.hermes/cache/uv"
  echo "${2:-$HERMES_COMMIT}" >"$h/.hermes/hermes-agent/.git/HEAD"
  printf '{"environment": "%s/.hermes/installs/k/environments/g/venv"}\n' "${3:-/opt/hermes}" >"$h/.hermes/installs/k/facts.json"
  printf '#!/bin/sh\necho hermes\n' >"$h/.hermes/superbot/hermes"
  chmod 0755 "$h/.hermes/superbot/hermes"
  echo python >"$h/.local/share/uv/python/cpython-3.14.9/bin/python3.14"
  ln -s ../../.hermes/superbot/hermes "$h/.local/bin/hermes"
  ln -s /opt/hermes/.local/share/uv/python/cpython-3.14.9/bin/python3.14 "$h/.hermes/installs/k/environments/g/venv/bin/python"
  ln -s /opt/hermes "$h/.hermes/home"
  ln "$h/.hermes/superbot/hermes" "$h/.hermes/superbot/hermes.copy"
  echo cached >"$h/.cache/uv/blob"
  echo cached >"$h/.hermes/cache/uv/blob"
}
fake_hermes "$T/htree"
"$DIR/offline-bundle.sh" hermes --out "$T/hout" --tree "$T/htree/hermes" >"$T/hbuild.log" 2>&1 \
  || { cat "$T/hbuild.log" >&2; fail "a Hermes bundle didn't build from a tree"; }
HTOP="superbot-hermes-$HTAG-$ARCH"
HB="$T/hout/$HTOP.tar.gz"
[[ -f "$HB" && -f "$HB.sha256" ]] || fail "no Hermes bundle and .sha256 in $T/hout"
[[ "$(tar -tf "$HB" | LC_ALL=C sort | tr '\n' ' ')" == "$HTOP/ $HTOP/MANIFEST $HTOP/SHA256SUMS $HTOP/hermes.tar " ]] || fail "the Hermes bundle holds more than MANIFEST, SHA256SUMS and hermes.tar"
hm=$(tar -xOf "$HB" "$HTOP/MANIFEST")
for want in format=1 kind=hermes "hermes_tag=$HTAG" "hermes_commit=$HERMES_COMMIT" prefix=/opt/hermes "arch=$ARCH"; do
  grep -qx "$want" <<<"$hm" || fail "the Hermes bundle's MANIFEST has no $want"
done
inner=$(tar -xOf "$HB" "$HTOP/hermes.tar" | tar -tv)
grep -q ' hermes/.local/bin/hermes -> ../../.hermes/superbot/hermes$' <<<"$inner" || fail "the Hermes bundle lost a relative link"
grep -q ' hermes/.hermes/superbot/hermes.copy link to hermes/.hermes/superbot/hermes$' <<<"$inner" || fail "the Hermes bundle lost a hard link"
! grep -Eq ' hermes/(\.cache|\.hermes/cache/uv)/' <<<"$inner" || fail "the Hermes bundle carries caches"
[[ "$(awk '{ print $2 }' <<<"$inner" | sort -u)" == 0/0 ]] || fail "the Hermes tree's entries aren't owned by 0/0"
"$DIR/offline-bundle.sh" verify "$HB" >"$T/hverify.log" 2>&1 || { cat "$T/hverify.log" >&2; fail "a good Hermes bundle didn't verify"; }
grep -q "good Hermes bundle" "$T/hverify.log" || fail "verify didn't say it is a Hermes bundle"
ok "a Hermes bundle builds from a Hermes tree for /opt/hermes, with its links and without caches, and verifies"

hbrefused() {
  local why=$1 want=$2 out
  shift 2
  rm -rf "$T/hnope"
  if out=$("$DIR/offline-bundle.sh" hermes --out "$T/hnope" "$@" 2>&1); then fail "$why: bundled"; fi
  grep -Fq -- "$want" <<<"$out" || { printf '%s\n' "$out" >&2; fail "$why: refused for another reason"; }
}
fake_hermes "$T/hother" "$(printf 'b%.0s' {1..40})"
hbrefused "another Hermes commit" "isn't Hermes Agent $HERMES_COMMIT" --tree "$T/hother/hermes"
fake_hermes "$T/hhome" "$HERMES_COMMIT" /home/builder/hermes
hbrefused "a tree installed for another place" "wasn't installed for /opt/hermes" --tree "$T/hhome/hermes"
mkdir -p "$T/hname" && cp -a "$T/htree/hermes" "$T/hname/elsewhere"
hbrefused "a folder not named hermes" "a folder named hermes" --tree "$T/hname/elsewhere"
cp -a "$T/htree" "$T/hout2" && ln -s /etc/shadow "$T/hout2/hermes/.hermes/leak"
hbrefused "a tree with a link out of it" "points outside /opt/hermes, to /etc/shadow" --tree "$T/hout2/hermes"
if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  hbrefused "an install without root" "runs as root"
  ok "a Hermes bundle is only made of the pinned commit's tree, installed for /opt/hermes, with no link out of it; installing one needs root"
else
  ok "a Hermes bundle is only made of the pinned commit's tree, installed for /opt/hermes, with no link out of it"
fi

# Repacks the Hermes bundle with hermes.tar made from $T/hx/hermes after a change there (or from
# the change's own tar with HTAR=1), re-hashing SHA256SUMS unless KEEP_SUMS=1.
hremake() {
  local name=$1
  shift
  rm -rf "$T/hx" "$T/hy" && mkdir -p "$T/hx" "$T/hy"
  tar -xf "$HB" -C "$T/hy"
  tar -xf "$T/hy/$HTOP/hermes.tar" -C "$T/hx"
  if [[ "${HTAR:-}" == 1 ]]; then
    (cd "$T/hx" && "$@" >"$T/hy/$HTOP/hermes.tar")
  elif [[ "${HMANIFEST:-}" == 1 ]]; then
    (cd "$T/hy/$HTOP" && "$@")
  else
    (cd "$T/hx" && "$@")
    tar -C "$T/hx" --sort=name -cf "$T/hy/$HTOP/hermes.tar" hermes
  fi
  if [[ "${KEEP_SUMS:-}" != 1 ]]; then
    (cd "$T/hy/$HTOP" && find . -type f ! -path ./SHA256SUMS -printf '%P\n' | LC_ALL=C sort | xargs -d '\n' sha256sum >SHA256SUMS)
  fi
  tar -C "$T/hy" -czf "$T/$name.tar.gz" "$HTOP"
  (cd "$T" && sha256sum "$name.tar.gz" >"$name.tar.gz.sha256")
  printf '%s\n' "$T/$name.tar.gz"
}
refused "$(KEEP_SUMS=1 hremake hchanged sh -c 'echo evil >>hermes/.hermes/superbot/hermes')" "files don't match SHA256SUMS" "a changed hermes.tar"
refused "$(hremake hsuid chmod u+s hermes/.hermes/superbot/hermes)" "setuid or setgid" "a setuid file in hermes.tar"
refused "$(hremake hfifo mkfifo hermes/pipe)" "special files" "a pipe in hermes.tar"
refused "$(HTAR=1 hremake houtside sh -c 'echo x >other && tar --sort=name -cf - hermes other')" "outside one hermes/ folder" "a file outside hermes/ in hermes.tar"
refused "$(HTAR=1 hremake hdots tar --sort=name --transform 's,^hermes/.local/bin/hermes$,hermes/../x,' -cf - hermes)" "path with .." "a '..' entry in hermes.tar"
refused "$(HTAR=1 hremake hhard tar --sort=name --transform 's,^hermes/.hermes/superbot/hermes$,elsewhere/hermes,RSh' -cf - hermes)" "hard link to a file outside" "a hard link out of hermes.tar"
refused "$(HMANIFEST=1 hremake hkind sed -i 's/^kind=.*/kind=other/' MANIFEST)" "isn't a Hermes bundle's" "a Hermes bundle of another kind"
refused "$(HMANIFEST=1 hremake hprefix sed -i 's,^prefix=.*,prefix=/home/x/hermes,' MANIFEST)" "installed for /home/x/hermes, not /opt/hermes" "a Hermes bundle for another place"
refused "$(HMANIFEST=1 hremake hcommit sed -i 's/^hermes_commit=.*/hermes_commit=main/' MANIFEST)" "isn't a full commit" "a Hermes bundle without a commit"
refused "$(HMANIFEST=1 hremake hnotar rm hermes.tar)" "no hermes.tar" "a Hermes bundle without hermes.tar"
cp "$HB" "$T/hanchor.tar.gz"
refused "$T/hanchor.tar.gz" "Nothing to check" "a Hermes bundle with no SHA-256 or signature beside it"
ok "changed trees, setuid files, special files, paths outside hermes/, '..', hard links out, other kinds, places and commits are refused"

# The tree as files, once unpacked: links must stay inside, followed through other links.
rm -rf "$T/hv" && mkdir -p "$T/hv" && tar -xOf "$HB" "$HTOP/hermes.tar" | tar -x -C "$T/hv"
bundle_tree_ok "$T/hv/hermes" /opt/hermes || fail "a good Hermes tree was refused: $BUNDLE_TREE_PROBLEM"
for bad in /etc ../../.. ../.hermes/../../x /opt/hermes-other/x /opt/hermes/../etc; do
  ln -sfn "$bad" "$T/hv/hermes/.hermes/bad"
  if bundle_tree_ok "$T/hv/hermes" /opt/hermes; then fail "a link to $bad was taken"; fi
  [[ "$BUNDLE_TREE_PROBLEM" == *"points outside /opt/hermes"* ]] || fail "a link to $bad was refused for another reason: $BUNDLE_TREE_PROBLEM"
done
ln -sfn ../hermes-agent "$T/hv/hermes/.hermes/bad"
bundle_tree_ok "$T/hv/hermes" /opt/hermes || fail "a relative link inside was refused: $BUNDLE_TREE_PROBLEM"
ln -sfn . "$T/hv/hermes/.hermes/dot"
ln -sfn dot/../hermes-agent "$T/hv/hermes/.hermes/bad"
bundle_tree_ok "$T/hv/hermes" /opt/hermes || fail "a link through a link inside was refused: $BUNDLE_TREE_PROBLEM"
for chain in "dot/../../.. dot" "dot/../../x dot" "up/../x /opt/hermes" "up/../../x .." "loop loop2"; do
  read -r bad via <<<"$chain"
  rm -f "$T/hv/hermes/.hermes/bad" "$T/hv/hermes/.hermes/up" "$T/hv/hermes/.hermes/loop" "$T/hv/hermes/.hermes/loop2"
  [[ $via == dot ]] || ln -sfn "$via" "$T/hv/hermes/.hermes/${bad%%/*}"
  [[ $bad != loop ]] || ln -sfn loop "$T/hv/hermes/.hermes/loop2"
  ln -sfn "$bad" "$T/hv/hermes/.hermes/bad"
  if bundle_tree_ok "$T/hv/hermes" /opt/hermes; then fail "a link out through another link was taken: bad -> $bad, via $via"; fi
done
rm -f "$T/hv/hermes/.hermes/bad" "$T/hv/hermes/.hermes/up" "$T/hv/hermes/.hermes/loop" "$T/hv/hermes/.hermes/loop2" "$T/hv/hermes/.hermes/dot"
mkfifo "$T/hv/hermes/pipe"
if bundle_tree_ok "$T/hv/hermes" /opt/hermes; then fail "a pipe in the tree was taken"; fi
ok "an unpacked Hermes tree's links stay inside it, absolute ones inside /opt/hermes, even followed through other links"

wrong=$(HMANIFEST=1 hremake harch sed -i "s/^arch=.*/arch=$other/" MANIFEST)
"$DIR/offline-bundle.sh" verify "$wrong" >/dev/null || fail "verify (on any machine) refused another arch's Hermes bundle"
rm -rf "$T/hu" && mkdir "$T/hu"
if (hermes_unpack_bundle "$wrong" "$T/hu" "") 2>"$T/harch.err"; then fail "the installer accepted a Hermes bundle for $other"; fi
grep -q "This Hermes bundle is for $other" "$T/harch.err" || fail "the Hermes arch refusal didn't say why"
if (DRY_RUN=true HERMES_BUNDLE=$HB HERMES_COMMIT=$(printf 'c%.0s' {1..40}) prepare_hermes_bundle) >"$T/hpin.log" 2>&1; then
  fail "a Hermes bundle of another commit than the installer pins was taken"
fi
grep -Fq "but this installer pins cccccccccccc" "$T/hpin.log" || { cat "$T/hpin.log" >&2; fail "the commit refusal didn't say why"; }
if (DRY_RUN=true HERMES_BUNDLE=$HB HERMES_BUNDLE_SHA256=$(cut -c1-64 "$B.sha256") prepare_hermes_bundle) >/dev/null 2>&1; then
  fail "a Hermes bundle was checked against the main bundle's --hermes-bundle-sha256"
fi
(DRY_RUN=true HERMES_BUNDLE=$HB HERMES_BUNDLE_SHA256=$(cut -c1-64 "$HB.sha256") OFFLINE_BUNDLE_SHA256=$(cut -c1-64 "$B.sha256") prepare_hermes_bundle) >/dev/null 2>&1 \
  || fail "a Hermes bundle wasn't checked against its own --hermes-bundle-sha256"
ok "the installer takes only this host's arch and the commit it pins, checked against the Hermes bundle's own SHA-256"

# An exit with the old Hermes Agent moved aside (a failure hermes_failed didn't see) puts it back
# and starts botd again; when it can't be put back, it is kept where it is, for the operator, and
# botd still starts (its other harnesses don't need Hermes).
swap() {
  rm -rf "$T/hswap" && mkdir -p "$T/hswap/stage/previous" "$T/hswap/stage/bundle" "$T/hswap/opt/hermes"
  echo old >"$T/hswap/stage/previous/marker"
  echo new >"$T/hswap/opt/hermes/marker"
}
swap
out=$( (HERMES_SHARED_DIR=$T/hswap/opt/hermes HERMES_STAGE=$T/hswap/stage HERMES_PREVIOUS=$T/hswap/stage/previous BOTD_STOPPED=true OFFLINE_TMP=""
  systemctl() { echo "systemctl $*"; }
  cleanup_offline) 2>&1)
grep -q "systemctl start superbot.service" <<<"$out" || fail "botd wasn't started again after the old Hermes Agent was put back"
[[ "$(cat "$T/hswap/opt/hermes/marker")" == old && ! -e "$T/hswap/stage" ]] || fail "the old Hermes Agent wasn't put back, or the staging was left"
if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  swap
  chmod 0555 "$T/hswap/opt"
  out=$( (HERMES_SHARED_DIR=$T/hswap/opt/hermes HERMES_STAGE=$T/hswap/stage HERMES_PREVIOUS=$T/hswap/stage/previous BOTD_STOPPED=true OFFLINE_TMP=""
    systemctl() { echo "systemctl $*"; }
    cleanup_offline) 2>&1)
  chmod 0755 "$T/hswap/opt"
  grep -Fq "it is in $T/hswap/stage/previous" <<<"$out" || fail "a Hermes Agent that couldn't be put back wasn't named"
  [[ "$(cat "$T/hswap/stage/previous/marker")" == old && ! -e "$T/hswap/stage/bundle" ]] || fail "a Hermes Agent that couldn't be put back was deleted"
  grep -q "systemctl start superbot.service" <<<"$out" || fail "botd wasn't started again when the old Hermes Agent couldn't be put back"
fi
ok "an exit mid-swap puts the old Hermes Agent back and starts botd again, or keeps it when it can't"

# An upgrade without --with-hermes says when the Hermes Agent it keeps isn't the one pinned.
fake_hermes "$T/hpinned" "$(printf 'd%.0s' {1..40})"
note=$( (HERMES_SHARED_DIR=$T/hpinned/hermes OFFLINE_BUNDLE=$B SUPERBOT_USER=nobody-here DRY_RUN=true; hermes_pin_notice) 2>&1)
grep -Fq "Hermes Agent dddddddddddd is installed in $T/hpinned/hermes, but this release pins ${HERMES_COMMIT:0:12}: re-run with --with-hermes --hermes-bundle" <<<"$note" \
  || { printf '%s\n' "$note" >&2; fail "no notice for an installed Hermes Agent that isn't pinned"; }
[[ -z "$( (HERMES_SHARED_DIR=$T/htree/hermes SUPERBOT_USER=nobody-here DRY_RUN=true; hermes_pin_notice) 2>&1)" ]] || fail "a notice for the pinned Hermes Agent"
ok "an upgrade that keeps another Hermes Agent than the one pinned says how to replace it"

# Hermes Agent for Compose (docs/adr/0275-hermes-agent-bundle-for-docker-compose.md): before it
# makes a volume, load-hermes refuses a Hermes bundle the installer would, and an image that isn't
# here, is for another arch, or pins another Hermes Agent. A stand-in docker answers for the image;
# the real runs are in docker.yml's smoke test (the real image) and offline.yml (the real bundle).
mkdir -p "$T/fakedocker"
cat >"$T/fakedocker/docker" <<'EOF'
#!/bin/sh
echo "$*" >>"$FAKE_DOCKER_LOG"
for a; do last=$a; done
case "$1 $2" in
  "image inspect")
    [ "$last" = "$FAKE_DOCKER_IMAGE" ] || exit 1
    case "$*" in *--format*) echo "$FAKE_DOCKER_ARCH" ;; esac
    exit 0 ;;
  "volume inspect")
    [ -n "${FAKE_DOCKER_VOLUME+x}" ] && [ "$last" = "$FAKE_DOCKER_VOLUME" ] || exit 1
    echo "${FAKE_DOCKER_VOLUME_LABEL:-}"
    exit 0 ;;
  "run --rm")
    case "$*" in *"--entrypoint botd $FAKE_DOCKER_IMAGE harness pins") printf '%s\n' "$FAKE_DOCKER_PINS"; exit 0 ;; esac ;;
esac
exit 1
EOF
chmod 0755 "$T/fakedocker/docker"
docker_arch() { case $1 in x86_64) echo amd64 ;; aarch64) echo arm64 ;; esac; }
DOCKER_ARCH=$(docker_arch "$ARCH")
GOOD_PINS="node $NODE_PIN $ARCH $(printf 'a%.0s' {1..64})
hermes hermes $HERMES_COMMIT $HTAG $(printf 'f%.0s' {1..64})"
lhrefused() {
  local why=$1 want=$2 out
  shift 2
  : >"$T/fakedocker.log"
  if out=$(PATH="$T/fakedocker:$PATH" FAKE_DOCKER_LOG="$T/fakedocker.log" FAKE_DOCKER_IMAGE=${LH_IMAGE-superbot:here} \
    FAKE_DOCKER_ARCH=${LH_ARCH-$DOCKER_ARCH} FAKE_DOCKER_PINS=${LH_PINS-$GOOD_PINS} \
    "$DIR/offline-bundle.sh" load-hermes "$@" 2>&1); then
    fail "$why: loaded"
  fi
  grep -Fq -- "$want" <<<"$out" || { printf '%s\n' "$out" >&2; fail "$why: refused for another reason"; }
  ! grep -Eq '^(volume (create|rm)|run .* -v )' "$T/fakedocker.log" || fail "$why: a Docker volume was changed or used before the refusal"
}
lhrefused "no bundle" "Give the Hermes bundle"
lhrefused "an offline bundle" "not a Hermes bundle" "$B" --image superbot:here
lhrefused "a wrong SHA-256" "not the one published" "$HB" --image superbot:here --sha256 "$(printf '0%.0s' {1..64})"
lhrefused "a changed hermes.tar" "files don't match SHA256SUMS" "$T/hchanged.tar.gz" --image superbot:here
lhrefused "another arch's Hermes bundle" "This Hermes bundle is for $other" "$(HMANIFEST=1 hremake harch sed -i "s/^arch=.*/arch=$other/" MANIFEST)" --image superbot:here
lhrefused "a bad volume name" "isn't a Docker volume name" "$HB" --image superbot:here --volume '../x'
lhrefused "an image that isn't here" "No image superbot:gone here" "$HB" --image superbot:gone
printf "AUTH_PASSWORD=x\nSUPERBOT_VERSION='1.2.3'\n" >"$T/compose.env"
lhrefused "Compose's image at .env's version" "No image ghcr.io/cg-labs/superbot:1.2.3 here" "$HB" --env-file "$T/compose.env"
printf 'SUPERBOT_VERSION=1.2.3\nSUPERBOT_IMAGE="registry.corp.example/superbot/superbot@sha256:%s"\n' "$(printf 'c%.0s' {1..64})" >>"$T/compose.env"
lhrefused "Compose's image named in .env" "No image registry.corp.example/superbot/superbot@sha256:cccc" "$HB" --env-file "$T/compose.env"
SUPERBOT_IMAGE=superbot:from-env lhrefused "Compose's image from the environment, over .env" "No image superbot:from-env here" "$HB" --env-file "$T/compose.env"
(cd "$T" && cp compose.env .env && lhrefused "Compose's image from ./.env" "No image registry.corp.example/superbot/superbot@sha256:cccc" "$HB")
LH_ARCH=$(docker_arch "$other") lhrefused "an image for another arch" "superbot:here is for linux/$(docker_arch "$other"), but the Hermes bundle is for $ARCH" "$HB" --image superbot:here
LH_PINS="node $NODE_PIN $ARCH x" lhrefused "an image whose botd pins no Hermes Agent" "doesn't say which Hermes Agent it pins" "$HB" --image superbot:here
LH_PINS="hermes hermes $(printf 'b%.0s' {1..40}) v9.9.9 x" lhrefused "an image that pins another Hermes Agent" \
  "The Hermes bundle holds Hermes Agent ${HERMES_COMMIT:0:12}, but superbot:here pins bbbbbbbbbbbb" "$HB" --image superbot:here
printf 'export SUPERBOT_VERSION = 4.5.6   # the release\nSUPERBOT_IMAGE=\n' >"$T/compose.env"
lhrefused "Compose's version with a comment after it" "No image ghcr.io/cg-labs/superbot:4.5.6 here" "$HB" --env-file "$T/compose.env"
# shellcheck disable=SC2016 # for Compose to fill in
printf 'SUPERBOT_IMAGE="${MIRROR}/superbot:1.2.3" # mirror\n' >"$T/compose.env"
lhrefused "an image Compose fills in from a variable" "with a variable Compose fills in: give it with --image" "$HB" --env-file "$T/compose.env"
FAKE_DOCKER_VOLUME=superbot_data lhrefused "a volume load-hermes didn't make" \
  "The Docker volume superbot_data wasn't made by load-hermes for Hermes Agent ${HERMES_COMMIT:0:12}: give another --volume" "$HB" --image superbot:here --volume superbot_data
FAKE_DOCKER_VOLUME=$(printf 'superbot-hermes-%.12s' "$HERMES_COMMIT") FAKE_DOCKER_VOLUME_LABEL=$(printf 'b%.0s' {1..40}) \
  lhrefused "a volume load-hermes made for another Hermes Agent" "(it is for bbbbbbbbbbbb)" "$HB" --image superbot:here
if command -v flock >/dev/null; then
  lock="/tmp/superbot-load-hermes-lh-locked-$$.lock"
  : >"$lock"
  (flock -n 8 && lhrefused "a volume another load-hermes is filling" "Another load-hermes is filling the Docker volume lh-locked-$$" \
    "$HB" --image superbot:here --volume "lh-locked-$$") 8<"$lock"
  rm -f "$lock"
fi
ok "load-hermes checks the Hermes bundle as the installer does, and takes it only for the pin of Compose's image, on this arch, into a volume of its own that no other load is filling"

# Harness bundles (docs/adr/0232-harness-cli-bundle-for-air-gapped-servers.md), from a tree laid
# out as Node.js's tarball and npm install -g --prefix leave one: bin/node, each CLI linked from
# bin/ into lib/node_modules, and its package.json. The real one, built with the network and
# installed as root with none, is in offline.yml.
fake_harnesses() {
  local h=$1/superbot-harnesses b v p
  mkdir -p "$h/bin" "$h/include/node"
  printf '#!/bin/sh\necho v%s\n' "${2:-$NODE_PIN}" >"$h/bin/node"
  chmod 0755 "$h/bin/node"
  echo header >"$h/include/node/node.h"
  ln "$h/bin/node" "$h/include/node/node.copy"
  for b in "claude ${3:-2.1.0} @anthropic-ai/claude-code" "codex 0.1.0 @openai/codex" "pi 1.0.0 @earendil-works/pi-coding-agent"; do
    read -r b v p <<<"$b"
    mkdir -p "$h/lib/node_modules/$p/node_modules/dep"
    printf '{"name": "%s", "version": "%s"}\n' "$p" "$v" >"$h/lib/node_modules/$p/package.json"
    printf '#!/usr/bin/env node\n' >"$h/lib/node_modules/$p/node_modules/dep/index.js"
    # A CLI that runs only with the tree's Node.js first on PATH, as its wrapper puts it.
    # shellcheck disable=SC2016 # expanded by the CLI
    printf '#!/bin/sh\n[ "$(command -v node)" = "%s" ] || { echo "no node"; exit 1; }\necho "%s (%s)"\n' "${4:-/opt/superbot-harnesses}/bin/node" "$v" "$b" \
      >"$h/lib/node_modules/$p/cli.js"
    chmod 0755 "$h/lib/node_modules/$p/cli.js"
    ln -s "../lib/node_modules/$p/cli.js" "$h/bin/$b"
  done
}
# The builder runs the tree's CLIs from where it is, so these check for their own node.
fake_harnesses "$T/ntree" "$NODE_PIN" 2.1.0 "$T/ntree/superbot-harnesses"
"$DIR/offline-bundle.sh" harnesses --out "$T/nout" --version "$VERSION" --bin-dir "$T/bin" --tree "$T/ntree/superbot-harnesses" >"$T/nbuild.log" 2>&1 \
  || { cat "$T/nbuild.log" >&2; fail "a harness bundle didn't build from a tree"; }
NTOP="superbot-harnesses-$VERSION-$ARCH"
NB="$T/nout/$NTOP.tar.gz"
[[ -f "$NB" && -f "$NB.sha256" ]] || fail "no harness bundle and .sha256 in $T/nout"
[[ "$(tar -tf "$NB" | LC_ALL=C sort | tr '\n' ' ')" == "$NTOP/ $NTOP/MANIFEST $NTOP/SHA256SUMS $NTOP/harnesses.tar " ]] || fail "the harness bundle holds more than MANIFEST, SHA256SUMS and harnesses.tar"
nm=$(tar -xOf "$NB" "$NTOP/MANIFEST")
nsha=$(printf 'a%.0s' {1..64})
[[ "$ARCH" == x86_64 ]] || nsha=$(printf 'b%.0s' {1..64})
for want in format=1 kind=harnesses "version=$VERSION" prefix=/opt/superbot-harnesses "arch=$ARCH" "harnesses=claude codex pi" "node=$NODE_PIN $nsha" \
  "harness_claude=2.1.0 @anthropic-ai/claude-code sha512-Y2xhdWRl" "harness_codex=0.1.0 @openai/codex sha512-Y29kZXg=" "harness_pi=1.0.0 @earendil-works/pi-coding-agent sha512-cGk="; do
  grep -qxF -- "$want" <<<"$nm" || fail "the harness bundle's MANIFEST has no $want"
done
! grep -q hermes <<<"$nm" || fail "the harness bundle's MANIFEST names Hermes, which has its own bundle"
inner=$(tar -xOf "$NB" "$NTOP/harnesses.tar" | tar -tv)
grep -q ' superbot-harnesses/bin/codex -> ../lib/node_modules/@openai/codex/cli.js$' <<<"$inner" || fail "the harness bundle lost a CLI's link"
grep -q ' superbot-harnesses/include/node/node.copy link to superbot-harnesses/bin/node$' <<<"$inner" || fail "the harness bundle lost a hard link"
[[ "$(awk '{ print $2 }' <<<"$inner" | sort -u)" == 0/0 ]] || fail "the harness tree's entries aren't owned by 0/0"
"$DIR/offline-bundle.sh" verify "$NB" >"$T/nverify.log" 2>&1 || { cat "$T/nverify.log" >&2; fail "a good harness bundle didn't verify"; }
grep -q "good harness bundle" "$T/nverify.log" || fail "verify didn't say it is a harness bundle"
grep -q "Harness bundle: claude codex pi on Node.js $NODE_PIN ($ARCH, SuperBot $VERSION) checked" "$T/nverify.log" || fail "verify didn't say what the harness bundle holds"
ok "a harness bundle builds from a tree at botd's pins, for /opt/superbot-harnesses, with its links, and verifies"

nbrefused() {
  local why=$1 want=$2 out
  shift 2
  rm -rf "$T/nnope"
  if out=$("$DIR/offline-bundle.sh" harnesses --out "$T/nnope" --version "$VERSION" "$@" 2>&1); then fail "$why: bundled"; fi
  grep -Fq -- "$want" <<<"$out" || { printf '%s\n' "$out" >&2; fail "$why: refused for another reason"; }
}
ntree() { rm -rf "${T:?}/${1:?}" && fake_harnesses "$T/$1" "${2:-$NODE_PIN}" "${3:-2.1.0}" "$T/$1/superbot-harnesses"; }
ntree nnode 20.0.0
nbrefused "another Node.js" "its Node.js is \"v20.0.0\", not v$NODE_PIN" --bin-dir "$T/bin" --tree "$T/nnode/superbot-harnesses"
ntree nclaude "$NODE_PIN" 2.0.9
nbrefused "another Claude Code" "its @anthropic-ai/claude-code is \"2.0.9\", not 2.1.0" --bin-dir "$T/bin" --tree "$T/nclaude/superbot-harnesses"
ntree nrun && sed -i 's/^echo "0.1.0 (codex)"$/echo 0.0.9/' "$T/nrun/superbot-harnesses/lib/node_modules/@openai/codex/cli.js"
nbrefused "a CLI that says another version" "codex --version says \"0.0.9\", not 0.1.0" --bin-dir "$T/bin" --tree "$T/nrun/superbot-harnesses"
ntree nnpmrc && mkdir -p "$T/nnpmrc/superbot-harnesses/etc" && echo "//registry.example/:_authToken=secret" >"$T/nnpmrc/superbot-harnesses/etc/npmrc"
nbrefused "a tree with npm's global settings" "etc/npmrc, which may hold a registry login" --bin-dir "$T/bin" --tree "$T/nnpmrc/superbot-harnesses"
ntree nleak && ln -s /etc/shadow "$T/nleak/superbot-harnesses/lib/leak"
nbrefused "a tree with a link out of it" "points outside /opt/superbot-harnesses, to /etc/shadow" --bin-dir "$T/bin" --tree "$T/nleak/superbot-harnesses"
mkdir -p "$T/nname" && cp -a "$T/ntree/superbot-harnesses" "$T/nname/elsewhere"
nbrefused "a folder not named superbot-harnesses" "a folder named superbot-harnesses" --bin-dir "$T/bin" --tree "$T/nname/elsewhere"
mkdir -p "$T/nopins" && cp "$T/bin"/* "$T/nopins/" && printf '#!/bin/sh\necho botd\n' >"$T/nopins/botd"
nbrefused "a botd that pins nothing" "doesn't say which harness CLIs it pins" --bin-dir "$T/nopins" --tree "$T/ntree/superbot-harnesses"
nbrefused "no botd" "No $T/nnope-bin/botd" --bin-dir "$T/nnope-bin" --tree "$T/ntree/superbot-harnesses"
ok "a harness bundle is only made of a tree at botd's pins that runs them, with no npm login and no link out of it"

# Repacks the harness bundle as hremake does the Hermes one.
nremake() {
  local name=$1
  shift
  rm -rf "$T/nx" "$T/ny" && mkdir -p "$T/nx" "$T/ny"
  tar -xf "$NB" -C "$T/ny"
  tar -xf "$T/ny/$NTOP/harnesses.tar" -C "$T/nx"
  if [[ "${HTAR:-}" == 1 ]]; then
    (cd "$T/nx" && "$@" >"$T/ny/$NTOP/harnesses.tar")
  elif [[ "${HMANIFEST:-}" == 1 ]]; then
    (cd "$T/ny/$NTOP" && "$@")
  else
    (cd "$T/nx" && "$@")
    tar -C "$T/nx" --sort=name -cf "$T/ny/$NTOP/harnesses.tar" superbot-harnesses
  fi
  if [[ "${KEEP_SUMS:-}" != 1 ]]; then
    (cd "$T/ny/$NTOP" && find . -type f ! -path ./SHA256SUMS -printf '%P\n' | LC_ALL=C sort | xargs -d '\n' sha256sum >SHA256SUMS)
  fi
  tar -C "$T/ny" -czf "$T/$name.tar.gz" "$NTOP"
  (cd "$T" && sha256sum "$name.tar.gz" >"$name.tar.gz.sha256")
  printf '%s\n' "$T/$name.tar.gz"
}
refused "$(KEEP_SUMS=1 nremake nchanged sh -c 'echo evil >>superbot-harnesses/bin/node')" "files don't match SHA256SUMS" "a changed harnesses.tar"
refused "$(nremake nsuid chmod u+s superbot-harnesses/bin/node)" "setuid or setgid" "a setuid file in harnesses.tar"
refused "$(nremake nfifo mkfifo superbot-harnesses/pipe)" "special files" "a pipe in harnesses.tar"
refused "$(HTAR=1 nremake noutside sh -c 'echo x >other && tar --sort=name -cf - superbot-harnesses other')" "outside one superbot-harnesses/ folder" "a file outside superbot-harnesses/ in harnesses.tar"
refused "$(HTAR=1 nremake nhard tar --sort=name --transform 's,^superbot-harnesses/bin/node$,elsewhere/node,RSh' -cf - superbot-harnesses)" "hard link to a file outside" "a hard link out of harnesses.tar"
refused "$(HMANIFEST=1 nremake nkind sed -i 's/^kind=.*/kind=hermes/' MANIFEST)" "isn't a harness bundle's" "a harness bundle of another kind"
refused "$(HMANIFEST=1 nremake nprefix sed -i 's,^prefix=.*,prefix=/usr/local,' MANIFEST)" "installed for /usr/local, not /opt/superbot-harnesses" "a harness bundle for another place"
refused "$(HMANIFEST=1 nremake nnotar rm harnesses.tar)" "no harnesses.tar" "a harness bundle without harnesses.tar"
cp "$NB" "$T/nanchor.tar.gz"
refused "$T/nanchor.tar.gz" "Nothing to check" "a harness bundle with no SHA-256 or signature beside it"
nwrong=$(HMANIFEST=1 nremake narch sed -i "s/^arch=.*/arch=$other/" MANIFEST)
"$DIR/offline-bundle.sh" verify "$nwrong" >/dev/null || fail "verify (on any machine) refused another arch's harness bundle"
rm -rf "$T/nu" && mkdir "$T/nu"
if (harness_unpack_bundle "$nwrong" "$T/nu" "") 2>"$T/narch.err"; then fail "the installer accepted a harness bundle for $other"; fi
grep -q "This harness bundle is for $other" "$T/narch.err" || fail "the harness arch refusal didn't say why"
ok "changed trees, setuid files, special files, paths outside superbot-harnesses/, hard links out, other kinds, places and arches are refused"

# The installer checks the harness bundle against the pins of the main bundle's own botd.
mkdir -p "$T/noff/bin"
nprep() { (DRY_RUN=true OFFLINE_DIR=$T/noff HARNESS_BUNDLE=$1 HARNESS_BUNDLE_SHA256=${2:-}; prepare_harness_bundle; echo "wanted: $HARNESS_WANTED") 2>&1; }
pins_botd "$T/noff/bin/botd"
out=$(nprep "$NB") || { printf '%s\n' "$out" >&2; fail "a harness bundle at the release's pins was refused"; }
grep -qxF "wanted: harnesses=claude codex pi" <<<"$out" || fail "the installer didn't take the release's pins"
pins_botd "$T/noff/bin/botd" 2.1.1
out=$(nprep "$NB") && fail "a harness bundle of another Claude Code than the release pins was taken"
grep -Fq "doesn't hold what this release pins (claude is 2.1.0 @anthropic-ai/claude-code sha512-Y2xhdWRl, not 2.1.1 @anthropic-ai/claude-code sha512-Y2xhdWRl)" <<<"$out" \
  || { printf '%s\n' "$out" >&2; fail "the pin refusal didn't say why"; }
printf '#!/bin/sh\necho botd\n' >"$T/noff/bin/botd"
out=$(nprep "$NB") && fail "a harness bundle was taken with a botd that pins nothing"
grep -Fq "doesn't say which harness CLIs it pins" <<<"$out" || { printf '%s\n' "$out" >&2; fail "the no-pins refusal didn't say why"; }
pins_botd "$T/noff/bin/botd"
out=$(nprep "$(HMANIFEST=1 nremake nless sed -i '/^harness_pi=/d' MANIFEST)") && fail "a harness bundle without Pi was taken"
grep -Fq "(pi is missing, not 1.0.0" <<<"$out" || { printf '%s\n' "$out" >&2; fail "the missing-harness refusal didn't say why"; }
nprep "$NB" "$(cut -c1-64 "$B.sha256")" >/dev/null && fail "a harness bundle was checked against another bundle's SHA-256"
nprep "$NB" "$(cut -c1-64 "$NB.sha256")" >/dev/null || fail "a harness bundle wasn't checked against its own --harness-bundle-sha256"
for bad in "node 22.0 x86_64 $nsha" "node 22.0.1 x86_64 ${nsha:1}" "node 22.0.1 x86_64 ${nsha}0" "node 22.0.1 x86_64 ${nsha^^}" "npm Claude 2.1.0 @a/b sha512-x" "npm claude latest @a/b sha512-x" "npm claude 2.1.0 @a/b md5-x" "npm claude 2.1.0 '@a/b;id' sha512-x" "npm claude 2.1.0 @a/b"; do
  printf '#!/bin/sh\nprintf "%%s\\n" "node 22.0.1 x86_64 %s" "npm codex 0.1.0 @openai/codex sha512-Y29kZXg=" "%s"\n' "$nsha" "$bad" >"$T/noff/bin/botd"
  if harness_pins "$T/noff/bin/botd" >/dev/null; then fail "harness pins with \"$bad\" were taken"; fi
done
pins_botd "$T/noff/bin/botd"
# Ubuntu 22.04's awk is mawk, which reads fewer regular expressions than gawk.
if command -v mawk >/dev/null 2>&1; then
  mkdir -p "$T/mawk" && ln -sf "$(command -v mawk)" "$T/mawk/awk"
  # shellcheck disable=SC2016 # expanded by the inner bash
  mpins=$(env PATH="$T/mawk:$PATH" bash -c 'SUPERBOT_INSTALL_NO_MAIN=1 source "$1" && harness_pins "$2"' _ "$DIR/install.sh" "$T/noff/bin/botd") \
    || fail "mawk refused good harness pins"
  grep -q '^node ' <<<"$mpins" || fail "mawk lost the Node.js pins"
fi
ok "the installer takes a harness bundle only at the pins of the release's botd, checked against its own SHA-256"

# The wrapper puts the tree's Node.js first, and runs the CLI from the tree.
w=$(HARNESSES_DIR=/opt/superbot-harnesses; harness_wrapper codex)
# shellcheck disable=SC2016 # the wrapper's own text
for want in 'PATH=/opt/superbot-harnesses/bin:$PATH' 'exec /opt/superbot-harnesses/bin/codex "$@"' 'DISABLE_AUTOUPDATER=1'; do
  grep -qxF -- "$want" <<<"$w" || { printf '%s\n' "$w" >&2; fail "the harness wrapper doesn't say: $want"; }
done
sh -n <<<"$w" || fail "the harness wrapper isn't sh"
ok "each harness CLI runs through the installer's wrapper, on the tree's Node.js, with its updater off"

# An exit mid-swap puts the old harness tree back, removes the new links, puts back what they
# replaced, and starts botd again.
rm -rf "$T/nswap" && mkdir -p "$T/nswap/stage/previous" "$T/nswap/stage/replaced" "$T/nswap/stage/bundle" "$T/nswap/opt/superbot-harnesses" "$T/nswap/bin"
echo old >"$T/nswap/stage/previous/marker"
echo new >"$T/nswap/opt/superbot-harnesses/marker"
echo "operator's own claude" >"$T/nswap/stage/replaced/claude"
ln -s "$T/nswap/opt/superbot-harnesses/superbot/claude" "$T/nswap/bin/claude"
ln -s "$T/nswap/opt/superbot-harnesses/superbot/codex" "$T/nswap/bin/codex"
out=$( (HARNESSES_DIR=$T/nswap/opt/superbot-harnesses BIN_DIR=$T/nswap/bin HARNESS_STAGE=$T/nswap/stage HARNESS_PREVIOUS=$T/nswap/stage/previous
  HARNESS_MOVED_IN=true HARNESS_LINKED=("$T/nswap/bin/claude" "$T/nswap/bin/codex") BOTD_STOPPED=true OFFLINE_TMP=""
  systemctl() { echo "systemctl $*"; }
  cleanup_offline) 2>&1)
grep -q "systemctl start superbot.service" <<<"$out" || fail "botd wasn't started again after the old harness CLIs were put back"
[[ "$(cat "$T/nswap/opt/superbot-harnesses/marker")" == old && ! -e "$T/nswap/stage" ]] || fail "the old harness CLIs weren't put back, or the staging was left"
[[ "$(cat "$T/nswap/bin/claude")" == "operator's own claude" && ! -L "$T/nswap/bin/claude" && ! -e "$T/nswap/bin/codex" ]] || fail "the new links weren't undone, or what they replaced wasn't put back"
ok "an exit mid-swap puts the old harness CLIs and the operator's own links back, and starts botd again"

# A file the operator had in BIN_DIR that can't be moved back stays in the staging folder, also
# after harness_failed has already tried once.
rm -rf "$T/nswap" && mkdir -p "$T/nswap/stage/previous" "$T/nswap/stage/replaced" "$T/nswap/stage/bundle" "$T/nswap/opt/superbot-harnesses" "$T/nswap/bin"
echo old >"$T/nswap/stage/previous/marker"
echo "operator's own claude" >"$T/nswap/stage/replaced/claude"
ln -s "$T/nswap/opt/superbot-harnesses/superbot/claude" "$T/nswap/bin/claude"
out=$( (HARNESSES_DIR=$T/nswap/opt/superbot-harnesses BIN_DIR=$T/nswap/bin HARNESS_STAGE=$T/nswap/stage HARNESS_PREVIOUS=$T/nswap/stage/previous
  HARNESS_MOVED_IN=true HARNESS_LINKED=("$T/nswap/bin/claude") BOTD_STOPPED=false OFFLINE_TMP=""
  mv() { [[ "${*: -1}" != "$BIN_DIR/claude" ]] || return 1; command mv "$@"; }
  ! harness_put_back || exit 9
  cleanup_offline) 2>&1) || fail "harness_put_back said it put back a file it couldn't: $out"
grep -Fq "Couldn't put $T/nswap/bin/claude back: it is in $T/nswap/stage/replaced/claude" <<<"$out" || fail "no warning for a file that couldn't be put back: $out"
[[ "$(cat "$T/nswap/stage/replaced/claude")" == "operator's own claude" && ! -e "$T/nswap/stage/bundle" ]] || fail "the staging folder was removed with the operator's own file in it"
[[ "$(cat "$T/nswap/opt/superbot-harnesses/marker")" == old && ! -e "$T/nswap/bin/claude" ]] || fail "the old harness CLIs weren't put back, or the new link was left"
ok "a file the operator had that can't be put back is kept in the staging folder"

# An offline upgrade without --harness-bundle keeps the harness CLIs it has, and says when
# they aren't the release's.
mkdir -p "$T/nkept/superbot"
(cd "$T/noff" && harness_manifest_lines "$(harness_pins bin/botd)" "$ARCH" | sed 's/^harness_codex=0.1.0/harness_codex=0.0.5/') >"$T/nkept/superbot/MANIFEST"
note=$( (HARNESSES_DIR=$T/nkept OFFLINE_DIR=$T/noff; harness_pin_notice) 2>&1)
grep -Fq "The harness CLIs in $T/nkept aren't the ones this release pins (codex is 0.0.5 @openai/codex sha512-Y29kZXg=, not 0.1.0 @openai/codex sha512-Y29kZXg=): re-run with --harness-bundle" <<<"$note" \
  || { printf '%s\n' "$note" >&2; fail "no notice for kept harness CLIs that aren't pinned"; }
(cd "$T/noff" && harness_manifest_lines "$(harness_pins bin/botd)" "$ARCH") >"$T/nkept/superbot/MANIFEST"
[[ -z "$( (HARNESSES_DIR=$T/nkept OFFLINE_DIR=$T/noff; harness_pin_notice) 2>&1)" ]] || fail "a notice for the pinned harness CLIs"
[[ -z "$( (HARNESSES_DIR=$T/nothing-here OFFLINE_DIR=$T/noff; harness_pin_notice) 2>&1)" ]] || fail "a notice on a server without harness CLIs from a bundle"
ok "an upgrade that keeps other harness CLIs than the ones pinned says how to replace them"

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
  "run --rm")
    echo "$*" >>"$STUB_REG/run.log"
    [[ -n "${STUB_PINS:-}" && "$*" == *"--network none --entrypoint botd "*" harness pins" ]] || exit 1
    printf '%s\n' "$STUB_PINS" ;;
  "volume inspect") exit 1 ;;
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
# digest, or another one with STUB_REWRITE=push. push --check prints it without pushing, and
# refuses the destination in $STUB_REFUSE.
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
    shift
    check=false
    [[ $1 != --check ]] || { check=true; shift; }
    [[ $1 == --to ]] || { echo "stub superbot-oci: $*" >&2; exit 2; }
    dest=$2
    set -- push "$@"
    for u in "${@:4}"; do
      [[ -f $u/image/oci-layout && -f $u/image/manifest.json ]] || { echo "stub superbot-oci: $u/image isn't an image layout" >&2; exit 1; }
    done
    if [[ $check == true ]]; then
      [[ $dest != "${STUB_REFUSE:-}" ]] || { echo "superbot-oci: stub refuses $dest" >&2; exit 1; }
      if [[ $# -gt 4 ]]; then jq -r '.manifests[] | select(.annotations["dev.superbot.oci.role"] == "index") | .digest' "$4/signatures/index.json"
      else jq -r '.manifests[0].digest' "$4/image/index.json"; fi
      exit 0
    fi
    for u in "${@:4}"; do
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

STUB_PINS="hermes hermes $(printf 'd%.0s' {1..40}) v7.7.7 x" stubbed "$DIR/offline-bundle.sh" load "$IB" >"$T/load.log" 2>&1 \
  || { cat "$T/load.log" >&2; fail "load with the Hermes notice failed"; }
grep -Fq "load this release's Hermes bundle (v7.7.7): " "$T/load.log" || { cat "$T/load.log" >&2; fail "load didn't name the Hermes bundle its image pins"; }
grep -Fqx "run --rm --network none --entrypoint botd reg.test/cg/superbot:1.0.0 harness pins" "$REG/run.log" || fail "load didn't ask the loaded image for its pins"
rm -f "$REG/local/$(regkey reg.test/cg/superbot:1.0.0)" "$REG/run.log"
ok "load names the Hermes bundle for Compose from the loaded image's pins, asked in a container with no network, not the bundle's botd on the host"

# Compose upgrades checked first (docs/adr/0317-compose-upgrades-checked-first.md), with a
# stand-in docker: each image in $CS/images lists the checks its botd has, $CS/out and $CS/rc
# hold what each image's `botd <check> check` prints and exits with, and $CS/running names the
# image of the botd container that runs now.
CS="$T/compose"
mkdir -p "$T/cstub" "$CS/images" "$CS/out" "$CS/rc"
cat >"$T/cstub/docker" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
key() { printf '%s' "$1" | sha256sum | cut -c1-16; }
cs=$STUB_COMPOSE
caps() { [[ -f "$cs/images/$(key "$1")" ]] && grep -qw "$2" "$cs/images/$(key "$1")"; }
# The check a usage line names: "Usage: botd license check" is license.
check_of() { awk '{ print $3 }' <<<"$1"; }
botd_out() { cat "$cs/out/$(key "$1").$2" 2>/dev/null || true; exit "$(cat "$cs/rc/$(key "$1").$2" 2>/dev/null || echo 0)"; }
if [[ $1 != compose ]]; then
  case "$1 $2" in
    "image inspect") [[ -f "$cs/images/$(key "${*: -1}")" ]] ;;
    "load -q") : ;;
    "run --rm")
      echo "docker $*" >>"$cs/log"
      [[ "$*" == *"--network none --entrypoint sh "* ]] || exit 1
      image=${*: -5:1}
      caps "$image" "$(check_of "${*: -1}")" ;;
    *) echo "stub docker: $*" >&2; exit 2 ;;
  esac
  exit
fi
shift
opts=()
while [[ $# -gt 0 && ! $1 =~ ^(version|ps|config|run|exec)$ ]]; do opts+=("$1"); shift; done
[[ $# -gt 0 ]] || exit 2
if [[ -f "$cs/noconfig" && $1 != version ]]; then echo "no configuration file provided: not found" >&2; exit 1; fi
case $1 in
  version) echo "Docker Compose version stub" ;;
  ps)
    if [[ $2 == -a ]]; then [[ ! -f "$cs/exists" ]] || echo c0ffee; else [[ ! -f "$cs/running" ]] || echo c0ffee; fi ;;
  config)
    if [[ -f "$cs/override" ]]; then cat "$cs/override"; elif [[ -n "${SUPERBOT_IMAGE:-}" ]]; then echo "$SUPERBOT_IMAGE"; else cat "$cs/configured"; fi ;;
  run)
    [[ "${*:2:6}" == "--rm --no-deps -T --entrypoint botd botd" ]] || { echo "stub compose run: $*" >&2; exit 2; }
    echo "run image=${SUPERBOT_IMAGE:-} opts=${opts[*]} args=${*:8} stdin=$(cat)" >>"$cs/log"
    echo " Container superbot-botd-run-1 Creating" >&2
    botd_out "$SUPERBOT_IMAGE" "$8" ;;
  exec)
    running=$(cat "$cs/running")
    echo "exec image=$running args=${*:4}" >>"$cs/log"
    if [[ $4 == sh ]]; then caps "$running" "$(check_of "${*: -1}")"; else botd_out "$running" "$5"; fi ;;
esac
EOF
chmod 0755 "$T/cstub/docker"
ckey() { printf '%s' "$1" | sha256sum | cut -c1-16; }
# IMAGE CHECKS...: an image here whose botd has those checks.
cimage() { local i=$1; shift; echo "$*" >"$CS/images/$(ckey "$i")"; }
# IMAGE CHECK RC OUTPUT: what that image's botd says to `botd CHECK check`.
csays() { printf '%s\n' "$4" >"$CS/out/$(ckey "$1").$2"; echo "$3" >"$CS/rc/$(ckey "$1").$2"; }
cstack() { rm -f "$CS/log"; (cd "$T" && env -u SUPERBOT_IMAGE STUB_COMPOSE="$CS" PATH="$T/cstub:$PATH" "$DIR/offline-bundle.sh" "$@"); }
OK_SETTINGS=$'Observability: ok\nbotd would start with these settings.'
OK_LICENSE=$'License: active, from /data/license.key\n  Licensed to Acme Ltd (business, 25 seats) until 2027-03-31.\nSeats: 3 of 25 in use\nWarning: 3 people more than last month\nBots would run with this license (botd 0.2.0).'
NO_LICENSE=$'License: invalid, from /data/license.key\n  The license key isn\'t valid (unknown_key).\n  Signed with a key this release no longer trusts.\nSeats: 3 in use, and none allowed\nBots wouldn\'t run with this license (botd 0.2.0): The license key isn\'t valid (unknown_key).'
touch "$CS/exists" "$CS/running"
echo old:1 >"$CS/running"
echo old:1 >"$CS/configured"
cimage old:1 settings license
cimage new:2 settings license
csays old:1 license 0 "$OK_LICENSE"
csays new:2 settings 0 "$OK_SETTINGS"
csays new:2 license 0 "$OK_LICENSE"

cstack check-compose --image new:2 -- -p stack -f x.yml >"$T/cc.log" 2>&1 || { cat "$T/cc.log" >&2; fail "check-compose refused a stack the new botd would start"; }
for want in "Settings: botd from new:2 would start with this stack's settings (botd settings check)" \
  "License: botd from new:2 would run Bots with this stack's license: Licensed to Acme Ltd (business, 25 seats) until 2027-03-31." \
  "License with new:2: 3 people more than last month" \
  "To switch the stack to new:2: SUPERBOT_VERSION (or SUPERBOT_IMAGE) in .env, then docker compose up -d"; do
  grep -Fq -- "$want" "$T/cc.log" || { cat "$T/cc.log" >&2; fail "check-compose didn't say: $want"; }
done
grep -Fqx "run image=new:2 opts=-p stack -f x.yml args=settings check stdin=" "$CS/log" || { cat "$CS/log" >&2; fail "botd settings check didn't run from the new image as Compose starts the stack's botd"; }
grep -Fqx "run image=new:2 opts=-p stack -f x.yml args=license check stdin=" "$CS/log" || fail "botd license check didn't run from the new image as Compose starts botd"
grep -Fq "docker run --rm --network none --entrypoint sh new:2 -c " "$CS/log" || fail "the new image's botd wasn't asked for its checks in a container with no network"
if grep -q "^exec " "$CS/log"; then fail "the running botd was asked about the license when the new one would run Bots"; fi
if grep -q "Container superbot-botd-run" "$T/cc.log"; then fail "Compose's progress reached the output"; fi
ok "check-compose runs the new image's botd settings check and license check as Compose would start the stack's botd, with Compose's own options, and says how to switch"

csays new:2 settings 1 $'SSO: refused\nbotd wouldn\'t start with these settings: SSO: SSO_PUBLIC_URL is required with SSO_PROVIDERS\nbotd wouldn\'t start with these settings: Server backups: SERVER_BACKUP_OFF_HOST must be auto, on or off, not "sometimes"'
if cstack check-compose --image new:2 >"$T/cc.log" 2>&1; then fail "check-compose passed a stack the new botd wouldn't start"; fi
for want in "botd from new:2 wouldn't start with this stack's settings: SSO: SSO_PUBLIC_URL is required with SSO_PROVIDERS" \
  '    and: Server backups: SERVER_BACKUP_OFF_HOST must be auto, on or off, not "sometimes"' \
  "Nothing in the stack has changed: keep it on the image it runs." "check-compose --image new:2"; do
  grep -Fq -- "$want" "$T/cc.log" || { cat "$T/cc.log" >&2; fail "a refused setting didn't say: $want"; }
done
if grep -q "args=license" "$CS/log"; then fail "the license was checked after a refused setting"; fi
csays new:2 settings 137 ""
if cstack check-compose --image new:2 >"$T/cc.log" 2>&1; then fail "check-compose passed when botd settings check didn't finish"; fi
grep -Fq "botd settings check didn't finish in new:2 (status 137), so the stack's settings weren't checked" "$T/cc.log" || { cat "$T/cc.log" >&2; fail "a settings check that didn't finish wasn't said"; }
if grep -q "args=license" "$CS/log"; then fail "the license was checked after a settings check that didn't finish"; fi
csays new:2 settings 0 "$OK_SETTINGS"
csays new:2 license 3 ""
if cstack check-compose --image new:2 >"$T/cc.log" 2>&1; then fail "check-compose passed when botd license check couldn't read the license"; fi
grep -Fq "botd license check didn't finish in new:2 (status 3), so the license wasn't checked" "$T/cc.log" || { cat "$T/cc.log" >&2; fail "a license check that didn't finish wasn't said"; }
if grep -q "To switch the stack" "$T/cc.log"; then fail "check-compose said how to switch after a check that didn't finish"; fi
csays new:2 license 0 "$OK_LICENSE"
ok "check-compose stops on settings the new botd would refuse, naming each, before anything else, and on a check that doesn't finish"

cimage mid:2 machines license
csays mid:2 machines 0 "botd would start with these machine settings."
csays mid:2 license 0 "$OK_LICENSE"
cstack check-compose --image mid:2 >"$T/cc.log" 2>&1 || { cat "$T/cc.log" >&2; fail "check-compose refused an image with only botd machines check"; }
grep -Fq "Settings: botd from mid:2 would start with this stack's settings (botd machines check)" "$T/cc.log" || fail "an image with only botd machines check wasn't checked with it"
cimage bare:2
cstack check-compose --image bare:2 >"$T/cc.log" 2>&1 || { cat "$T/cc.log" >&2; fail "check-compose refused an image whose botd has no checks"; }
grep -Fq "botd in bare:2 can't check its settings (botd settings check), so they weren't checked" "$T/cc.log" || fail "an image without the checks wasn't said"
grep -Fq "botd in bare:2 can't check licenses (botd license check), so the license wasn't checked" "$T/cc.log" || fail "an image without botd license check wasn't said"
if grep -q "^run " "$CS/log" 2>/dev/null; then fail "a botd without the checks was run, which would start it as the server"; fi
ok "an image with only botd machines check is checked with it; one with neither, or no license check, is said and never run"

csays new:2 license 1 "$NO_LICENSE"
if cstack check-compose --image new:2 >"$T/cc.log" 2>&1; then fail "check-compose passed a license the new botd wouldn't run Bots with, while Bots run now"; fi
for want in "Bots run now, but botd from new:2 wouldn't run Bots with this stack's license: The license key isn't valid (unknown_key)." \
  "Signed with a key this release no longer trusts." "Nothing in the stack has changed" "check-compose --image new:2 --key-file <file>" "botctl license install"; do
  grep -Fq -- "$want" "$T/cc.log" || { cat "$T/cc.log" >&2; fail "a license the new botd won't take didn't say: $want"; }
done
grep -Fqx "exec image=old:1 args=botd license check" "$CS/log" || fail "the running botd wasn't asked whether Bots run now"
csays old:1 license 1 "$NO_LICENSE"
cstack check-compose --image new:2 >"$T/cc.log" 2>&1 || { cat "$T/cc.log" >&2; fail "check-compose stopped on a license Bots don't run with now either"; }
grep -Fq "Bots don't run on this stack now either" "$T/cc.log" || fail "a license Bots don't run with now wasn't said"
cimage old:1 settings
cstack check-compose --image new:2 >"$T/cc.log" 2>&1 || { cat "$T/cc.log" >&2; fail "check-compose stopped when the running botd can't check licenses"; }
grep -Fq "The running botd can't say whether Bots run now" "$T/cc.log" || fail "a running botd without botd license check wasn't said"
if grep -q "^exec image=old:1 args=botd license" "$CS/log"; then fail "a running botd without botd license check was asked"; fi
rm -f "$CS/running"
cstack check-compose --image new:2 >"$T/cc.log" 2>&1 || { cat "$T/cc.log" >&2; fail "check-compose stopped on a stack whose botd is stopped"; }
grep -Fq "The running botd can't say whether Bots run now" "$T/cc.log" || fail "a stopped botd wasn't said"
echo old:1 >"$CS/running"
cimage old:1 settings license
csays old:1 license 0 "$OK_LICENSE"
printf '  key.\n  more\n' >"$T/renewal.key"
csays new:2 license 0 "$OK_LICENSE"
cstack check-compose --image new:2 --key-file "$T/renewal.key" >"$T/cc.log" 2>&1 || { cat "$T/cc.log" >&2; fail "check-compose refused a key the new botd takes"; }
grep -Fqx "run image=new:2 opts= args=license check --key-file - stdin=key.more" "$CS/log" || { cat "$CS/log" >&2; fail "--key-file wasn't judged by the new botd from stdin, whitespace dropped"; }
grep -Fq "would run Bots with the key in $T/renewal.key: " "$T/cc.log" || fail "--key-file's key wasn't named"
csays new:2 license 0 "$OK_LICENSE"
ok "check-compose stops when Bots run now but the new botd wouldn't run them, asked of the running botd; it warns when they don't run now or the running botd can't say; --key-file judges a renewal"

cstack check-compose >"$T/cc.log" 2>&1 || { cat "$T/cc.log" >&2; fail "check-compose without --image failed"; }
grep -Fqx "run image=old:1 opts= args=settings check stdin=" "$CS/log" || fail "without --image, the image Compose would run wasn't checked"
echo other:9 >"$CS/override"
if cstack check-compose --image new:2 >"$T/cc.log" 2>&1; then fail "check-compose checked an image Compose wouldn't run botd from"; fi
grep -Fq "Compose runs botd from other:9 here whatever SUPERBOT_IMAGE says" "$T/cc.log" || { cat "$T/cc.log" >&2; fail "an override naming botd's image wasn't said"; }
rm -f "$CS/override"
crefused() { # why, then what it says, then check-compose's arguments
  local why=$1 want=$2
  shift 2
  if cstack check-compose "$@" >"$T/cc.log" 2>&1; then fail "$why: checked"; fi
  grep -Fq -- "$want" "$T/cc.log" || { cat "$T/cc.log" >&2; fail "$why: didn't say $want"; }
  if grep -q "^run " "$CS/log" 2>/dev/null; then fail "$why: botd ran"; fi
}
crefused "an image not here" "No image gone:3 here: load the release's images first" --image gone:3
crefused "an option for Compose before --" "Unknown option: -p (Compose's own options go after --)" -p stack
crefused "an image that isn't a reference" "isn't an image reference" --image '-x'
crefused "a key that can't be read" "Can't read the key in --key-file $T/none.key" --key-file "$T/none.key"
rm -f "$CS/exists"
crefused "a stack that has never run botd" "This Compose stack has never run botd, so there is nothing to upgrade" --image new:2
touch "$CS/noconfig"
crefused "no stack here" "docker compose can't read this stack: no configuration file provided: not found" --image new:2
rm -f "$CS/noconfig"
touch "$CS/exists"
ok "check-compose checks the image Compose would run without --image, and refuses images Compose wouldn't run botd from, images not here, a stack it can't read or that never ran botd, and bad options"

REF=reg.test/cg/superbot:1.0.0
IB_SHA=$(awk '{ print $1 }' "$IB.sha256")
cimage "$REF" settings license
csays "$REF" settings 0 "$OK_SETTINGS"
csays "$REF" license 0 "$OK_LICENSE"
cstack load "$IB" >"$T/cl.log" 2>&1 || { cat "$T/cl.log" >&2; fail "load checked only against the .sha256 beside it failed"; }
grep -Fq "Not checking the Compose stack against $REF: this bundle was checked only against the .sha256 beside it" "$T/cl.log" || { cat "$T/cl.log" >&2; fail "load didn't say why it left the stack unchecked"; }
grep -Fq "check-compose --image $REF" "$T/cl.log" || fail "load didn't say how to check the stack itself"
if grep -q "^run " "$CS/log" 2>/dev/null; then fail "load ran an image from a bundle checked only against the .sha256 beside it with the stack's data"; fi
cstack load "$IB" --sha256 "$IB_SHA" -- -p stack >"$T/cl.log" 2>&1 || { cat "$T/cl.log" >&2; fail "load into a stack the new botd would start failed"; }
grep -Fqx "run image=$REF opts=-p stack args=settings check stdin=" "$CS/log" || { cat "$CS/log" >&2; fail "load didn't check the loaded image against the stack"; }
grep -Fq "To switch the stack to it: SUPERBOT_VERSION=$VERSION in .env (or SUPERBOT_IMAGE=$REF), then docker compose up -d" "$T/cl.log" || { cat "$T/cl.log" >&2; fail "load didn't say how to switch the stack"; }
csays "$REF" settings 1 "botd wouldn't start with these settings: Status page: STATUS_PAGE must be on or off"
if cstack load "$IB" --sha256 "$IB_SHA" >"$T/cl.log" 2>&1; then fail "load passed a stack the loaded botd wouldn't start"; fi
grep -Fq "botd from $REF wouldn't start with this stack's settings: Status page: STATUS_PAGE must be on or off" "$T/cl.log" || { cat "$T/cl.log" >&2; fail "load didn't say what the loaded botd refuses"; }
rm -f "$CS/exists"
cstack load "$IB" --sha256 "$IB_SHA" >"$T/cl.log" 2>&1 || { cat "$T/cl.log" >&2; fail "load with no stack here failed"; }
grep -Fq "Before you switch a Compose stack to $REF, check it from the stack's folder: " "$T/cl.log" || { cat "$T/cl.log" >&2; fail "load with no stack didn't say how to check one"; }
if grep -q "^run " "$CS/log" 2>/dev/null; then fail "load ran botd with no stack to check"; fi
ok "load checks the loaded image against the Compose stack it runs in, only for a bundle checked against a recorded --sha256 or its signature, and stops when botd wouldn't start; with no stack, it says how to check one"

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
# One bundle, with the --sha256 an operator copies from where it was published.
tpush() { push "$1" --sha256 "$(cut -c1-64 "$1.sha256")" "${@:2}"; }
out=$(push "$IB" --registry mirror.test/untrusted) && fail "push ran a bundle's superbot-oci checked only against the .sha256 beside it"
grep -Fq "only when the bundle is checked against its signature" <<<"$out" || { printf '%s\n' "$out" >&2; fail "the untrusted superbot-oci was refused for another reason"; }
! grep -q "mirror.test/untrusted" "$REG/oci.log" 2>/dev/null || fail "the untrusted superbot-oci ran"
out=$(SUPERBOT_OCI=$T/bin/superbot-oci push "$IB" --registry mirror.test/own) || { printf '%s\n' "$out" >&2; fail "push with SUPERBOT_OCI failed"; }
out=$(tpush "$IB" --registry mirror.test:5000/superbot) || { printf '%s\n' "$out" >&2; fail "push failed"; }
[[ "$(cat "$REG/refs/$(regkey mirror.test:5000/superbot/superbot:1.0.0)")" == "$(cat "$REG/blobs/${MINE#sha256:}")" ]] || fail "the mirror didn't get the bundled manifest"
grep -Fq "SUPERBOT_IMAGE=mirror.test:5000/superbot/superbot@$MINE" <<<"$out" || { printf '%s\n' "$out" >&2; fail "push didn't print the pinned Compose setting"; }
grep -Fqx "push mirror.test:5000/superbot/superbot:1.0.0 $MINE signatures=yes" "$REG/oci.log" || fail "push didn't hand superbot-oci the image with its signatures"
out=$(STUB_REWRITE=push tpush "$IB" --registry mirror.test/changed) && fail "a push that changed the digest passed"
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
grep -Fq "has no signatures in its bundle" <<<"$(tpush "$T/iunsigned/$TOP.tar.gz" --registry mirror.test/u)" || fail "push of an unsigned image didn't warn that it has no signatures"
cp "$T/img/index.json" "$REG/refs/$(regkey reg.test/cg/later:1.0.0)"
ibuild "$T/itwo" --image a=reg.test/cg/unsigned:1.0.0 --image b=reg.test/cg/later:1.0.0 --allow-unsigned >/dev/null 2>&1 || fail "two images didn't bundle"
out=$(STUB_REFUSE=mirror.test/two/later:1.0.0 tpush "$T/itwo/$TOP.tar.gz" --registry mirror.test/two) && fail "a push with an image superbot-oci refuses passed"
grep -Fq "Can't push b to mirror.test/two/later:1.0.0: nothing pushed" <<<"$out" || { printf '%s
' "$out" >&2; fail "the refused image was refused for another reason"; }
[[ ! -e "$REG/refs/$(regkey mirror.test/two/unsigned:1.0.0)" ]] || fail "the first image was pushed before the second was refused"
out=$(tpush "$T/itwo/$TOP.tar.gz" --registry mirror.test/two) || { printf '%s
' "$out" >&2; fail "push of two images failed"; }
[[ -e "$REG/refs/$(regkey mirror.test/two/unsigned:1.0.0)" && -e "$REG/refs/$(regkey mirror.test/two/later:1.0.0)" ]] || fail "push of two images didn't push both"
nooci=$(B=$IB remake nooci rm bin/superbot-oci)
out=$(tpush "$nooci" --registry mirror.test) && fail "push without superbot-oci passed"
grep -q "push needs superbot-oci" <<<"$out" || { printf '%s\n' "$out" >&2; fail "push without superbot-oci didn't say why"; }
ok "push copies images with their signatures to a mirror with the bundle's digest, checks it there, prints Compose's pinned settings, and refuses bad registries, two images on one tag, an image that can't go up (before pushing any), old bundles, and no superbot-oci; a bundle's superbot-oci runs only once the bundle is checked against a signature or a --sha256 given"

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
    OFFLINE_BUNDLE=$B INSTALL_DIR="" WITH_HERMES=false DOMAIN="" TLS_CERT="" OFFLINE_BUNDLE_SHA256="" HERMES_BUNDLE="" HERMES_BUNDLE_SHA256="" \
      HARNESS_BUNDLE="" HARNESS_BUNDLE_SHA256=""
    for a in "$@"; do declare "$a"; done
    check_offline_flags
  ) 2>&1
}
grep -q "needs --hermes-bundle" <<<"$(flags WITH_HERMES=true HERMES_BUNDLE="" || true)" || fail "--offline --with-hermes was allowed without a Hermes bundle"
grep -q "needs --with-hermes" <<<"$(flags HERMES_BUNDLE="$HB" || true)" || fail "--hermes-bundle was taken without --with-hermes"
grep -q "can't read" <<<"$(flags WITH_HERMES=true HERMES_BUNDLE="$T/nope.tar.gz" || true)" || fail "a Hermes bundle that isn't there was taken"
grep -q "64 lowercase hex" <<<"$(flags WITH_HERMES=true HERMES_BUNDLE="$HB" HERMES_BUNDLE_SHA256=abc || true)" || fail "a bad --hermes-bundle-sha256 was taken"
grep -q "needs --hermes-bundle" <<<"$(flags HERMES_BUNDLE_SHA256="$(printf '0%.0s' {1..64})" || true)" || fail "--hermes-bundle-sha256 was taken without a Hermes bundle"
flags WITH_HERMES=true HERMES_BUNDLE="$HB" >/dev/null || fail "--offline --with-hermes --hermes-bundle was refused"
# shellcheck disable=SC2034
grep -q "for --offline installs" <<<"$( (OFFLINE_BUNDLE="" OFFLINE_BUNDLE_SHA256="" HERMES_BUNDLE=$HB; check_offline_flags) 2>&1 || true)" || fail "--hermes-bundle was taken without --offline"
grep -q "needs --tls-cert" <<<"$(flags DOMAIN=bots.example.com || true)" || fail "--offline --domain without a certificate was allowed"
grep -q "not --source-dir" <<<"$(flags INSTALL_DIR=/srv/src || true)" || fail "--offline --source-dir was allowed"
# shellcheck disable=SC2034
grep -q "needs --offline" <<<"$( (OFFLINE_BUNDLE="" OFFLINE_BUNDLE_SHA256=abc; check_offline_flags) 2>&1 || true)" || fail "--bundle-sha256 without --offline was allowed"
ok "--offline refuses --with-hermes without a Hermes bundle, --source-dir, and --domain without a certificate; --hermes-bundle needs --offline and --with-hermes"
flags HARNESS_BUNDLE="$NB" >/dev/null || fail "--offline --harness-bundle was refused"
flags HARNESS_BUNDLE="$NB" HARNESS_BUNDLE_SHA256="$(cut -c1-64 "$NB.sha256")" >/dev/null || fail "--harness-bundle with its SHA-256 was refused"
grep -q "can't read" <<<"$(flags HARNESS_BUNDLE="$T/nope.tar.gz" || true)" || fail "a harness bundle that isn't there was taken"
grep -q "64 lowercase hex" <<<"$(flags HARNESS_BUNDLE="$NB" HARNESS_BUNDLE_SHA256=ABC || true)" || fail "a bad --harness-bundle-sha256 was taken"
grep -q "needs --harness-bundle" <<<"$(flags HARNESS_BUNDLE_SHA256="$(printf '0%.0s' {1..64})" || true)" || fail "--harness-bundle-sha256 was taken without a harness bundle"
# shellcheck disable=SC2034
grep -q "for --offline installs" <<<"$( (OFFLINE_BUNDLE="" OFFLINE_BUNDLE_SHA256="" HERMES_BUNDLE="" HARNESS_BUNDLE=$NB; check_offline_flags) 2>&1 || true)" \
  || fail "--harness-bundle was taken without --offline"
ok "--harness-bundle needs --offline and a readable bundle, and --harness-bundle-sha256 needs it and 64 hex digits"

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

# The summary's botd offline check (ADR 0257), with a stand-in botd that answers as the
# real one does for each outcome. botd runs with only its .env, never the installer's environment.
mkdir -p "$T/obin"
cat >"$T/obin/botd" <<EOF
#!/bin/sh
[ "\$1 \$2 \$3 \$4" = "offline check --home /home/sb" ] || { echo "botd \$*"; exit 2; }
[ -z "\${LEAK:-}" ] || { echo "the installer's environment reached botd"; exit 3; }
case \$(cat "$T/obin/mode") in
  internet) printf '  internet  Billing                BILLING: Billing at api.stripe.com: Stripe, on the internet.\n  check     Backups                SERVER_BACKUP_S3_ENDPOINT: at s3.example.net\n  ok        License                fine\n'; exit 1 ;;
  check) printf '  check     Backups                SERVER_BACKUP_S3_ENDPOINT: at s3.example.net\n  ok        License                fine\n'; exit 0 ;;
  clean) printf '  ok        License                fine\n'; exit 0 ;;
  *) echo "no such subcommand"; exit 2 ;;
esac
EOF
chmod 0755 "$T/obin/botd"
ocheck() { echo "$1" >"$T/obin/mode"; (BIN_DIR=$T/obin OFFLINE_BUNDLE=$B DRY_RUN=false SUPERBOT_USER=sb LEAK=1; export LEAK; offline_settings_check /home/sb) 2>&1; }
out=$(ocheck clean)
grep -Fq "botd offline check: nothing botd's settings name is on the internet" <<<"$out" || fail "a clean offline check wasn't said: $out"
if grep -Eq '^!!|Check these' <<<"$out"; then fail "a clean offline check warned: $out"; fi
out=$(ocheck check)
for want in "nothing botd's settings name is on the internet" "Check these" "SERVER_BACKUP_S3_ENDPOINT"; do
  grep -Fq -- "$want" <<<"$out" || fail "an offline check with names to check didn't say $want: $out"
done
out=$(ocheck internet)
for want in "!! botd offline check: some of botd's settings reach the internet" "BILLING: Billing at api.stripe.com" "SERVER_BACKUP_S3_ENDPOINT" \
  "sudo -u sb botd offline check --home /home/sb"; do
  grep -Fq -- "$want" <<<"$out" || fail "an offline check with settings on the internet didn't say $want: $out"
done
if grep -Fq "License" <<<"$out"; then fail "the offline check's warning listed settings that are fine: $out"; fi
out=$(ocheck old)
grep -Fq "botd offline check didn't run (status 2)" <<<"$out" || fail "an offline check that didn't run wasn't said: $out"
[[ -z $( (OFFLINE_BUNDLE='' BIN_DIR=$T/obin; offline_settings_check /home/sb) 2>&1) ]] || fail "an online install ran the offline check"
ok "an offline install's summary says what botd's settings reach on the internet (botd offline check)"

# The bundle's botd checks machines' settings in .env before an offline upgrade changes anything
# (ADR 0294), as botd's user, with only the .env and --machine-*-bundle over it.
MH=$T/mhome
mkdir -p "$MH/superbot" "$T/mbundle/bin"
cat >"$T/mbundle/bin/botd" <<EOF
#!/bin/sh
# Usage: botd machines check
[ "\$1 \$2 \$3 \$4" = "machines check --home $MH" ] || { echo "botd \$*"; exit 2; }
[ -z "\${LEAK:-}" ] || { echo "the installer's environment reached botd"; exit 3; }
[ "\$(pwd)" = / ] || { echo "botd ran in \$(pwd)"; exit 3; }
shift 4
echo "\$*" >"$T/mbundle/args"
case \$(cat "$T/mbundle/mode") in
  ok) printf 'Settings: %s/superbot/.env, over botd'"'"'s environment\nMachines: incus, enrolling at https://10.0.0.5:8443\nx86_64 Hermes bundle /srv/b/superbot-hermes-v0.24.0-x86_64.tar.gz: Hermes Agent v0.24.0 (bbbbbbbbbbbb), SHA-256 cc\nbotd would start with these machine settings.\n' "$MH"; exit 0 ;;
  stale) printf 'Settings: x\nbotd wouldn'"'"'t start with these settings: Machine enrollment: MACHINE_HERMES_BUNDLE: /srv/b/superbot-hermes-v0.23.3-x86_64.tar.gz holds Hermes Agent caafe5389ae5, but machines'"'"' plan pins bbbbbbbbbbbb: use the Hermes bundle made for this release\n'; exit 1 ;;
  *) echo "no such subcommand"; exit 2 ;;
esac
EOF
chmod 0755 "$T/mbundle/bin/botd"
mcheck() {
  echo "$1" >"$T/mbundle/mode"
  shift
  (
    OFFLINE_BUNDLE=$B OFFLINE_DIR=$T/mbundle OFFLINE_VERSION=0.2.0 DRY_RUN=false SUPERBOT_USER=sb LEAK=1
    export LEAK
    id() { [[ $1 == sb ]]; }
    user_home() { echo "$MH"; }
    sudo() { [[ $1 == -u ]] || { echo "sudo $*"; return 9; }; echo "$2" >"$T/mbundle/as"; shift 2; "$@"; }
    local a
    for a in "$@"; do declare "$a"; done
    offline_settings_start_check
  ) 2>&1
}
: >"$T/mbundle/args"
[[ -z $(mcheck ok) ]] || fail "machines' settings were checked with no .env"
echo 'MACHINE_CONTROL_URL=https://10.0.0.5:8443' >"$MH/superbot/.env"
out=$(mcheck ok) || fail "a good machine settings check stopped the install: $out"
for want in "Machines' settings: the bundle's botd would start with them (botd machines check)" "    Machines: incus, enrolling at" "    x86_64 Hermes bundle /srv/b/superbot-hermes-v0.24.0"; do
  grep -Fq -- "$want" <<<"$out" || fail "a good machine settings check didn't say $want: $out"
done
[[ $(cat "$T/mbundle/as") == sb && -z $(cat "$T/mbundle/args") ]] || fail "the check didn't run as botd's user with only the .env: $(cat "$T/mbundle/as" "$T/mbundle/args")"
NEW_BUNDLES="--set MACHINE_HERMES_BUNDLE=/srv/b/superbot-hermes-v0.24.0-x86_64.tar.gz --set MACHINE_HARNESS_BUNDLE=/srv/b/h-x86_64.tar.gz=abc"
out=$(mcheck ok MACHINE_HERMES_BUNDLE_VALUE=/srv/b/superbot-hermes-v0.24.0-x86_64.tar.gz MACHINE_HARNESS_BUNDLE_VALUE=/srv/b/h-x86_64.tar.gz=abc) \
  || fail "a good check with new bundles stopped the install: $out"
[[ $(cat "$T/mbundle/args") == "$NEW_BUNDLES" ]] || fail "the check wasn't given the new bundles: $(cat "$T/mbundle/args")"
if out=$(mcheck stale); then fail "an upgrade went on though its botd wouldn't start: $out"; fi
for want in "!! The bundle's botd (0.2.0) wouldn't start with $MH/superbot/.env: Machine enrollment: MACHINE_HERMES_BUNDLE: /srv/b/superbot-hermes-v0.23.3" \
  "Nothing has changed" "re-run with --machine-hermes-bundle or --machine-harness-bundle" "docs/ops/air-gapped.md#upgrading"; do
  grep -Fq -- "$want" <<<"$out" || fail "a refused check didn't say $want: $out"
done
out=$(mcheck stale DRY_RUN=true) || fail "a dry run stopped on the check: $out"
grep -Fq "[dry-run] would stop here: The bundle's botd (0.2.0) wouldn't start with" <<<"$out" || fail "a dry run didn't say the upgrade would stop: $out"
out=$(mcheck old) || fail "a botd that can't run the check stopped the install: $out"
grep -Fq "botd machines check didn't run (status 2)" <<<"$out" || fail "a check that didn't run wasn't said: $out"
{ echo '#!/bin/sh'; echo "echo ran >$T/mbundle/args"; } >"$T/mbundle/bin/botd"
echo "not run" >"$T/mbundle/args"
out=$(mcheck ok) || fail "a bundle's botd from before the check stopped the install: $out"
grep -Fq "The bundle's botd (0.2.0) can't check machines' settings" <<<"$out" || fail "an older botd wasn't said: $out"
[[ $(cat "$T/mbundle/args") == "not run" ]] || fail "an older botd was run, which would start as the server"
[[ -z $( (OFFLINE_BUNDLE=''; offline_settings_start_check) 2>&1) ]] || fail "an online install checked machines' settings"
ok "an offline upgrade stops before changing anything when the bundle's botd wouldn't start with machines' settings (botd machines check)"

# A bundle's botd with botd settings check judges every setting botd refuses at start, over what
# this run writes into .env (ADR 0310), as botd's user, with only the .env, from /.
cat >"$T/mbundle/bin/botd" <<EOF
#!/bin/sh
# Usage: botd settings check
[ "\$1 \$2 \$3 \$4" = "settings check --home $MH" ] || { echo "botd \$*"; exit 2; }
[ -z "\${LEAK:-}" ] || { echo "the installer's environment reached botd"; exit 3; }
[ "\$(pwd)" = / ] || { echo "botd ran in \$(pwd)"; exit 3; }
shift 4
printf '%s\n' "\$@" >"$T/mbundle/args"
case \$(cat "$T/mbundle/mode") in
  ok) printf '  ok       SSO\nMachines: incus, enrolling at https://10.0.0.5:8443\nbotd would start with these settings.\n'; exit 0 ;;
  sso) printf '  refused  SSO   SSO: SSO_PUBLIC_URL is required with SSO_PROVIDERS\nbotd wouldn'"'"'t start with these settings: SSO: SSO_PUBLIC_URL is required with SSO_PROVIDERS\nbotd wouldn'"'"'t start with these settings: STATUS_PAGE must be on or off, not "maybe"\n'; exit 1 ;;
  isolation) printf 'botd wouldn'"'"'t start with these settings: Isolation: ISOLATION_DIR /var/lib/superbot-users: No such file or directory. Run deploy/install.sh --isolation.\n'; exit 1 ;;
  isolation-and) printf 'botd wouldn'"'"'t start with these settings: Isolation: ISOLATION_DIR /var/lib/superbot-users: No such file. Run deploy/install.sh --isolation.\nbotd wouldn'"'"'t start with these settings: Sessions: SESSION_MAX_AGE must be a number of minutes\n'; exit 1 ;;
  isolation-files) printf 'botd wouldn'"'"'t start with these settings: Isolation: superbot-userctl isn'"'"'t at /usr/local/sbin/superbot-userctl. Run deploy/install.sh --isolation.\nbotd wouldn'"'"'t start with these settings: Isolation: ISOLATION_TEAMMATE_FILES must be archive or delete, not "sometimes"\n'; exit 1 ;;
  *) echo "no such subcommand"; exit 2 ;;
esac
EOF
chmod 0755 "$T/mbundle/bin/botd"
printf 'AUTH_PASSWORD=pw\nMACHINE_CONTROL_URL=https://10.0.0.5:8443\n' >"$MH/superbot/.env"
out=$(mcheck ok) || fail "a good settings check stopped the install: $out"
for want in "Settings: the bundle's botd would start with them (botd settings check)" "    Machines: incus, enrolling at"; do
  grep -Fq -- "$want" <<<"$out" || fail "a good settings check didn't say $want: $out"
done
[[ $(cat "$T/mbundle/as") == sb ]] || fail "the settings check didn't run as botd's user"
want="--set HOST=127.0.0.1 --set PORT=3000 --set DATA_DIR=$MH/superbot/data --set WORKSPACE_DIR=$MH/superbot/workspace"
[[ $(tr '\n' ' ' <"$T/mbundle/args") == "$want " ]] || fail "the settings check wasn't given what every install writes: $(cat "$T/mbundle/args")"
out=$(SERVER_BACKUP_S3_SECRET_ACCESS_KEY=s3-secret-9f1c mcheck ok DOMAIN=bot.corp.example TESTING_MODE_ON=true BACKUP_S3_BUCKET=sb-backups \
  BACKUP_S3_ENDPOINT=https://s3.corp.example BACKUP_S3_REGION=eu-west-2 BACKUP_OFF_HOST=on BACKUP_ENCRYPTION=required BACKUP_AGE_GENERATE=true \
  DATABASE_ENCRYPTION=required ISOLATION_MODE=off MACHINE_HERMES_BUNDLE_VALUE=/srv/b/hermes.tar.gz) || fail "a good settings check with flags stopped the install: $out"
given=$(cat "$T/mbundle/args")
for want in ALLOWED_HOSTS=bot.corp.example CORS_ORIGINS=https://bot.corp.example TESTING_MODE=on SERVER_BACKUP_S3_ENDPOINT=https://s3.corp.example \
  SERVER_BACKUP_S3_BUCKET=sb-backups SERVER_BACKUP_S3_REGION=eu-west-2 SERVER_BACKUP_S3_SECRET_ACCESS_KEY=given-to-the-installer \
  SERVER_BACKUP_S3_SECRET_ACCESS_KEY_FILE= SERVER_BACKUP_OFF_HOST=on SUPERBOT_BACKUP_ENCRYPTION=required \
  SUPERBOT_BACKUP_AGE_RECIPIENTS=made-by-the-installer SUPERBOT_DATABASE_ENCRYPTION=required ISOLATION=off MACHINE_HERMES_BUNDLE=/srv/b/hermes.tar.gz; do
  grep -qxF -- "$want" <<<"$given" || fail "the settings check wasn't given $want: $given"
done
if grep -Fq s3-secret-9f1c <<<"$given"; then fail "an S3 key from the installer's environment reached botd's command line: $given"; fi
if grep -q '^AUTH_PASSWORD=' <<<"$given"; then fail "a .env with a password was given a stand-in: $given"; fi
if grep -q 'ACCESS_KEY_ID' <<<"$given"; then fail "a key not given to the installer was set: $given"; fi
mcheck ok BACKUP_AGE_GENERATE=true BACKUP_AGE_RECIPIENTS=age1given >/dev/null || fail "the settings check with recipients stopped the install"
grep -qxF SUPERBOT_BACKUP_AGE_RECIPIENTS=age1given "$T/mbundle/args" || fail "given recipients weren't judged as given: $(cat "$T/mbundle/args")"
if grep -q made-by-the-installer "$T/mbundle/args"; then fail "a stand-in was set beside given recipients: $(cat "$T/mbundle/args")"; fi
mcheck ok BACKUP_AGE_GENERATE=true BACKUP_ENCRYPTION=off >/dev/null || fail "the settings check for plain backups stopped the install"
if grep -q RECIPIENTS=made "$T/mbundle/args"; then fail "a key was assumed for plain backups"; fi
echo 'MACHINE_CONTROL_URL=https://10.0.0.5:8443' >"$MH/superbot/.env"
mcheck ok >/dev/null || fail "the settings check with no password stopped the install"
grep -qxF AUTH_PASSWORD=made-by-the-installer "$T/mbundle/args" || fail "a .env with no password wasn't judged with the one the installer makes"
if out=$(mcheck sso); then fail "an upgrade went on though its botd would refuse SSO: $out"; fi
for want in "!! The bundle's botd (0.2.0) wouldn't start with $MH/superbot/.env: SSO: SSO_PUBLIC_URL is required" \
  '    and: STATUS_PAGE must be on or off, not "maybe"' "Nothing has changed" "else change $MH/superbot/.env as it says" \
  "sudo -u sb <bundle>/bin/botd settings check --home $MH" "docs/ops/air-gapped.md#upgrading"; do
  grep -Fq -- "$want" <<<"$out" || fail "a refused settings check didn't say $want: $out"
done
out=$(mcheck sso DRY_RUN=true) || fail "a dry run stopped on the settings check: $out"
grep -Fq "[dry-run] would stop here: The bundle's botd (0.2.0) wouldn't start with $MH/superbot/.env: SSO:" <<<"$out" || fail "a dry run didn't say it would stop: $out"
grep -Fq "and: STATUS_PAGE" <<<"$out" || fail "a dry run didn't list every refusal: $out"
if out=$(mcheck isolation); then fail "an Isolation refusal with isolation already on went on: $out"; fi
out=$(mcheck isolation ISOLATION_MODE=users) || fail "per-user accounts this run sets up stopped the install: $out"
grep -Fq "once this run has set up per-user accounts" <<<"$out" || fail "a check passed once accounts are set up wasn't said: $out"
if out=$(mcheck isolation-and ISOLATION_MODE=users); then fail "a refusal beside isolation's went on: $out"; fi
grep -Fq "wouldn't start with $MH/superbot/.env: Sessions: SESSION_MAX_AGE" <<<"$out" || fail "the refusal beside isolation's wasn't said: $out"
if grep -Fq "and: Isolation" <<<"$out"; then fail "isolation this run sets up was listed as refused: $out"; fi
if out=$(mcheck isolation-files ISOLATION_MODE=users); then fail "a bad isolation setting went on because this run sets up per-user accounts: $out"; fi
grep -Fq "wouldn't start with $MH/superbot/.env: Isolation: ISOLATION_TEAMMATE_FILES must be archive or delete" <<<"$out" || fail "a bad isolation setting wasn't said: $out"
if grep -Fq "superbot-userctl" <<<"$out"; then fail "a helper this run installs was listed as refused: $out"; fi
mcheck ok ISOLATION_MODE=users ISOLATION_DIR=/srv/u >/dev/null || fail "a good settings check turning on isolation stopped the install"
for want in ISOLATION=users ISOLATION_DIR=/srv/u; do
  grep -qxF "$want" "$T/mbundle/args" || fail "the settings check wasn't given $want, which this run writes: $(cat "$T/mbundle/args")"
done
mcheck ok ISOLATION_MODE=users >/dev/null || fail "a good settings check turning on isolation in the default folder stopped the install"
grep -qxF ISOLATION_DIR=/srv/superbot/users "$T/mbundle/args" || fail "the settings check wasn't given the default users' folder: $(cat "$T/mbundle/args")"
ok "an offline upgrade stops before changing anything when the bundle's botd would refuse any setting at start, judged over what the install writes (botd settings check)"

flags() { (parse_args "$@"; check_offline_flags) 2>&1; }
if out=$(flags --machine-hermes-bundle /srv/b/h.tar.gz); then fail "--machine-hermes-bundle was taken online: $out"; fi
grep -Fq "are for --offline --upgrade" <<<"$out" || fail "--machine-hermes-bundle online didn't say why: $out"
if out=$(flags --offline "$B" --machine-harness-bundle /srv/b/n.tar.gz); then fail "--machine-harness-bundle was taken on a new install: $out"; fi
grep -Fq "use them with --upgrade" <<<"$out" || fail "--machine-harness-bundle without --upgrade didn't say why: $out"
flags --offline "$B" --upgrade --machine-harness-bundle /srv/b/n.tar.gz >/dev/null || fail "--machine-harness-bundle with --offline --upgrade was refused"
flags --offline "$B" --upgrade --machine-hermes-bundle "/srv/tmp/h.tar.gz,/srv/b/a.tar.gz=$(printf 'a%.0s' {1..64})" >/dev/null \
  || fail "a bundle under /srv/tmp with a pinned SHA-256 was refused"
for p in /tmp/h.tar.gz /var/tmp/h.tar.gz "/tmp/h.tar.gz=$(printf 'b%.0s' {1..64})"; do
  if out=$(flags --offline "$B" --upgrade --machine-hermes-bundle "/srv/b/x.tar.gz, $p"); then fail "--machine-hermes-bundle took $p, which botd's PrivateTmp hides: $out"; fi
  grep -Fq "is under /tmp or /var/tmp, which botd's service can't see (PrivateTmp)" <<<"$out" || fail "$p under /tmp wasn't said: $out"
done
if out=$(flags --offline "$B" --upgrade --machine-harness-bundle /var/tmp/n.tar.gz); then fail "--machine-harness-bundle took /var/tmp: $out"; fi
printf 'A=1\nMACHINE_HERMES_BUNDLE=/srv/b/old.tar.gz\n' >"$T/menv"
(MACHINE_HERMES_BUNDLE_VALUE=/srv/b/new.tar.gz=abc MACHINE_HARNESS_BUNDLE_VALUE=/srv/b/n.tar.gz; configure_machine_bundles "$T/menv") >/dev/null
[[ $(cat "$T/menv") == $'A=1\nMACHINE_HERMES_BUNDLE=/srv/b/new.tar.gz=abc\nMACHINE_HARNESS_BUNDLE=/srv/b/n.tar.gz' ]] || fail "the new bundles weren't written to .env: $(cat "$T/menv")"
(configure_machine_bundles "$T/menv") >/dev/null
[[ $(cat "$T/menv") == $'A=1\nMACHINE_HERMES_BUNDLE=/srv/b/new.tar.gz=abc\nMACHINE_HARNESS_BUNDLE=/srv/b/n.tar.gz' ]] || fail ".env changed without the flags"
ok "--machine-hermes-bundle and --machine-harness-bundle are for --offline --upgrade, and set .env"

# Offline upgrades back up DATA_DIR and .env first, and --rollback goes back with them (ADR 0300).
# The real superbot-backup and superbot-restore, on a real SQLite database; root's commands are
# stand-ins, and botd's user is this one.
if out=$(flags --rollback); then fail "--rollback was taken online: $out"; fi
grep -Fq "are for --offline upgrades" <<<"$out" || fail "--rollback online didn't say why: $out"
if out=$(flags --upgrade --no-upgrade-backup); then fail "--no-upgrade-backup was taken online: $out"; fi
if out=$(flags --offline "$B" --rollback); then fail "--rollback was taken without --upgrade: $out"; fi
grep -Fq "use it with --upgrade" <<<"$out" || fail "--rollback without --upgrade didn't say why: $out"
if out=$(flags --offline "$B" --upgrade --rollback --no-upgrade-backup); then fail "--rollback was taken with --no-upgrade-backup: $out"; fi
if out=$(flags --offline "$B" --upgrade --rollback --machine-harness-bundle /srv/b/n.tar.gz); then fail "--rollback was taken with --machine-harness-bundle: $out"; fi
grep -Fq "puts back the .env from before the upgrade" <<<"$out" || fail "--rollback with a machine bundle didn't say why: $out"
flags --offline "$B" --upgrade --rollback >/dev/null || fail "--offline --upgrade --rollback was refused"
flags --offline "$B" --upgrade --no-upgrade-backup >/dev/null || fail "--offline --upgrade --no-upgrade-backup was refused"
flags --upgrade >/dev/null || fail "an online upgrade was refused"
ok "--rollback and --no-upgrade-backup are for --offline upgrades only, and --rollback keeps the old .env's machine bundles"

RB=$T/rollback
RH=$RB/home
COMMIT=$(tar -xOf "$B" "$TOP/MANIFEST" | sed -n 's/^commit=//p')
mkdir -p "$RB/bin" "$RB/bundle/bin" "$RB/bundle/deploy"
install -m 0755 "$DIR/superbot-backup.sh" "$RB/bin/superbot-backup"
cp "$DIR/superbot-backup.sh" "$DIR/superbot-restore.sh" "$RB/bundle/deploy/"
cp "$T/bin/botd" "$RB/bundle/bin/botd"
tar -xOf "$B" "$TOP/MANIFEST" >"$RB/bundle/MANIFEST"
# A host that runs the bundle's release, with chats in its database, and a .env as the installer
# writes it.
rb_host() {
  rm -rf "$RH" "$RB/dir" "$RB/as" "$RB/systemctl" "$RB/active"
  mkdir -p "$RH/superbot/data/bots"
  printf 'DATA_DIR=%s\nPORT=9\nMACHINE_HARNESS_BUNDLE=/srv/b/old.tar.gz\n%s' "$RH/superbot/data" "${1:-}" >"$RH/superbot/.env"
  chmod 0600 "$RH/superbot/.env"
  sqlite3 "$RH/superbot/data/app.sqlite" "CREATE TABLE t (v TEXT); INSERT INTO t VALUES ('before')"
  echo before >"$RH/superbot/data/bots/notes"
  tar -xOf "$B" "$TOP/MANIFEST" >"$RB/offline-release"
}
# Runs CODE with install.sh's functions as root would, with DRY_RUN off unless CODE sets it.
# shellcheck disable=SC2317 # the stand-ins are called from CODE, through eval
rb() {
  (
    SUPERBOT_USER=$(id -un) BIN_DIR=$RB/bin ROLLBACK_DIR=$RB/dir OFFLINE_RELEASE_FILE=$RB/offline-release
    BACKUP_IDENTITY_FILE=$RB/identity OFFLINE_BUNDLE=$B OFFLINE_DIR=$RB/bundle DRY_RUN=false
    user_home() { echo "$RH"; }
    sudo() { [[ $1 == -u ]] || { echo "sudo $*"; return 9; }; echo "$2" >>"$RB/as"; shift 2; "$@"; }
    install() {
      local a=()
      while (($#)); do case $1 in -o | -g) shift 2 ;; *) a+=("$1"); shift ;; esac; done
      command install "${a[@]}"
    }
    systemctl() { echo "systemctl $*" >>"$RB/systemctl"; [[ $1 != is-active ]] || [[ -e "$RB/active" ]]; }
    eval "$1"
  ) 2>&1
}
rows() { sqlite3 "$RH/superbot/data/app.sqlite" 'SELECT group_concat(v) FROM t'; }
# What an upgrade to 0.2.0 leaves: the release recorded, a new chat, a changed .env.
rb_upgraded() {
  sed -i 's/^version=.*/version=0.2.0/' "$RB/offline-release"
  sqlite3 "$RH/superbot/data/app.sqlite" "INSERT INTO t VALUES ('after')"
  echo after >>"$RH/superbot/data/bots/notes"
  sed -i 's,^MACHINE_HARNESS_BUNDLE=.*,MACHINE_HARNESS_BUNDLE=/srv/b/new.tar.gz,' "$RH/superbot/.env"
}
UPGRADE_TO="OFFLINE_INSTALLED=$VERSION OFFLINE_VERSION=0.2.0"

rb_host
out=$(rb "$UPGRADE_TO; offline_rollback_point") || fail "the backup before an upgrade failed: $out"
record=$RB/dir/record
for want in format=1 "from_version=$VERSION" "from_commit=$COMMIT" to_version=0.2.0 "env=env-"; do
  grep -q "^$want" "$record" || fail "the rollback record has no $want: $(cat "$record")"
done
archive=$RB/dir/$(sed -n 's/^archive=//p' "$record")
[[ "$archive" == "$RB/dir/superbot-pre-upgrade-$VERSION-"*.tar.gz && -f "$archive" ]] || fail "no plain backup archive: $archive"
[[ $(sha256sum "$archive" | cut -c1-64) == $(sed -n 's/^archive_sha256=//p' "$record") ]] || fail "the record's SHA-256 isn't the archive's"
cmp -s "$RH/superbot/.env" "$RB/dir/$(sed -n 's/^env=//p' "$record")" || fail "the .env wasn't kept as it was"
[[ $(stat -c %a "$RB/dir") == 700 && $(stat -c %a "$record") == 600 && $(stat -c %a "$archive") == 600 ]] || fail "the rollback folder isn't root's only"
[[ $(sort -u "$RB/as") == "$(id -un)" ]] || fail "the backup didn't run as botd's user"
grep -Fq "Rollback point: $archive" <<<"$out" || fail "the upgrade didn't say how to go back: $out"
grep -Fq "install.sh --offline <its bundle> --upgrade --rollback" <<<"$out" || fail "the upgrade didn't give the rollback command: $out"
sleep 1
out=$(rb "$UPGRADE_TO; offline_rollback_point") || fail "a second backup failed: $out"
[[ $(find "$RB/dir" -mindepth 1 | wc -l) == 3 ]] || fail "a second backup didn't replace the first: $(ls -A "$RB/dir")"
ok "an offline upgrade to a newer release first backs up DATA_DIR and .env, as botd's user, root-only, keeping one"

rm -rf "$RB/dir"
for code in "OFFLINE_INSTALLED=$VERSION OFFLINE_VERSION=$VERSION" "OFFLINE_INSTALLED= OFFLINE_VERSION=0.2.0" "$UPGRADE_TO OFFLINE_BUNDLE=" "$UPGRADE_TO DRY_RUN=true"; do
  out=$(rb "$code; offline_rollback_point") || fail "$code stopped: $out"
  [[ ! -e "$RB/dir" ]] || fail "$code backed up"
done
grep -Fq "[dry-run] would back up DATA_DIR and $RH/superbot/.env with $VERSION's superbot-backup into $RB/dir" <<<"$out" || fail "a dry run didn't say it would back up: $out"
out=$(rb "$UPGRADE_TO NO_UPGRADE_BACKUP=true; offline_rollback_point") || fail "--no-upgrade-backup stopped: $out"
[[ ! -e "$RB/dir" ]] || fail "--no-upgrade-backup backed up"
grep -Fq -- "--rollback can't take this host back to $VERSION" <<<"$out" || fail "--no-upgrade-backup didn't warn: $out"
printf '#!/bin/sh\necho "superbot-backup: No space left on device" >&2\nexit 2\n' >"$RB/bin/superbot-backup"
if out=$(rb "$UPGRADE_TO; offline_rollback_point"); then fail "an upgrade went on though its backup failed: $out"; fi
for want in "Couldn't back up before the upgrade: superbot-backup: No space left on device" "Nothing has changed" "--no-upgrade-backup"; do
  grep -Fq -- "$want" <<<"$out" || fail "a failed backup didn't say $want: $out"
done
[[ -z $(ls -A "$RB/dir") ]] || fail "a failed backup left files: $(ls -A "$RB/dir")"
install -m 0755 "$DIR/superbot-backup.sh" "$RB/bin/superbot-backup"
ok "no backup for the same release, a new install, an online install or a dry run; --no-upgrade-backup warns; a failed backup stops the upgrade"

# prepare_offline unpacks the real bundle; the rest uses $RB/bundle, the same scripts and MANIFEST.
rollback() { rb "ROLLBACK=true DRY_RUN=true; prepare_offline; OFFLINE_DIR=$RB/bundle DRY_RUN=false; prepare_rollback; offline_rollback_point"; }
rb_host
rb "$UPGRADE_TO; offline_rollback_point" >/dev/null || fail "the backup before an upgrade failed"
kept_env=$(cat "$RH/superbot/.env")
rb_upgraded
if out=$(rb "DRY_RUN=true; prepare_offline"); then fail "an older bundle was taken without --rollback: $out"; fi
grep -Fq "To go back to the backup taken before the upgrade to 0.2.0, losing everything since, add --rollback" <<<"$out" || fail "the downgrade refusal didn't offer --rollback: $out"
touch "$RB/active"
out=$(rollback) || fail "the rollback failed: $out"
for want in "Offline rollback: 0.2.0 -> $VERSION, with the backup taken before the upgrade to 0.2.0" \
  "the backup taken before the upgrade to 0.2.0 unpacks and checks out" "Put back DATA_DIR and .env from before the upgrade to 0.2.0" \
  "Previous data kept in $RH/superbot/data/.pre-restore-" "The .env 0.2.0 ran with is kept as $RH/superbot/.env.before-rollback-"; do
  grep -Fq -- "$want" <<<"$out" || fail "the rollback didn't say $want: $out"
done
[[ $(rows) == before && $(cat "$RH/superbot/data/bots/notes") == before ]] || fail "the rollback didn't put back the data: $(rows)"
[[ $(cat "$RH/superbot/.env") == "$kept_env" ]] || fail "the rollback didn't put back the .env"
[[ $(stat -c %a "$RH/superbot/.env") == 600 ]] || fail "the .env put back isn't 0600"
grep -qx MACHINE_HARNESS_BUNDLE=/srv/b/new.tar.gz "$RH"/superbot/.env.before-rollback-* || fail "the .env it replaced wasn't kept"
[[ $(sqlite3 "$RH"/superbot/data/.pre-restore-*/app.sqlite 'SELECT group_concat(v) FROM t') == before,after ]] || fail "the data it replaced wasn't kept"
grep -qx "version=$VERSION" "$RB/offline-release" || fail "the rollback didn't record the bundle's release"
[[ -z $(ls -A "$RB/dir") ]] || fail "the backup was left after the rollback: $(ls -A "$RB/dir")"
grep -qx "systemctl stop superbot.service" "$RB/systemctl" || fail "superbot wasn't stopped for the rollback"
out=$(rollback) || fail "running the rollback again failed: $out"
grep -Fq "This host already runs $VERSION: nothing to roll back" <<<"$out" || fail "a second rollback didn't say there's nothing to do: $out"
ok "--rollback stops botd, puts back DATA_DIR and .env from before the upgrade, keeping what they replace, and records the older release"

rb_host
rb "$UPGRADE_TO; offline_rollback_point" >/dev/null || fail "the backup before an upgrade failed"
rb_upgraded
cp -a "$RB/dir" "$RB/dir.good"
cp "$RB/offline-release" "$RB/release.good"
refused_rollback() {
  local want=$1 why=$2 out
  if out=$(rollback); then fail "$why: rolled back"; fi
  grep -Fq -- "$want" <<<"$out" || fail "$why: refused for another reason: $out"
  grep -Fq "Nothing has changed" <<<"$out" || fail "$why: didn't say nothing has changed: $out"
  [[ $(rows) == before,after ]] || fail "$why: the data changed"
  grep -qx MACHINE_HARNESS_BUNDLE=/srv/b/new.tar.gz "$RH/superbot/.env" || fail "$why: the .env changed"
  rm -rf "$RB/dir" && cp -a "$RB/dir.good" "$RB/dir" && cp "$RB/release.good" "$RB/offline-release"
}
sed -i 's/^from_version=.*/from_version=0.0.9/' "$RB/dir/record"
refused_rollback "the backup in $RB/dir is of 0.0.9, not $VERSION: roll back with the 0.0.9 bundle" "a backup of another release"
sed -i 's/^from_commit=.*/from_commit=0123456789abcdef/' "$RB/dir/record"
refused_rollback "built from 0123456789abcdef, but this bundle is built from $COMMIT" "a backup of another build"
sed -i 's/^version=.*/version=0.3.0/' "$RB/offline-release"
refused_rollback "taken before the upgrade to 0.2.0, but this host runs 0.3.0" "a host upgraded again since"
echo x >>"$RB/dir/$(sed -n 's/^archive=//p' "$RB/dir/record")"
refused_rollback "has changed since it was backed up" "a changed backup"
rm "$RB/dir/$(sed -n 's/^env=//p' "$RB/dir/record")"
refused_rollback "the backup's files aren't all in $RB/dir" "a backup without its .env"
broken=$RB/dir/$(sed -n 's/^archive=//p' "$RB/dir/record")
head -c 100 "$RB/dir.good/${broken##*/}" >"$broken"
sed -i "s/^archive_sha256=.*/archive_sha256=$(sha256sum "$broken" | cut -c1-64)/" "$RB/dir/record"
refused_rollback "doesn't restore: superbot-restore: could not unpack the archive" "a backup that doesn't unpack"
sed -i "s,^DATA_DIR=.*,DATA_DIR=$RH/elsewhere," "$RB/dir/$(sed -n 's/^env=//p' "$RB/dir/record")"
refused_rollback "sets DATA_DIR=$RH/elsewhere, but the installer runs botd with $RH/superbot/data" "an old .env with another DATA_DIR"
rm -rf "$RB/dir"
refused_rollback "no backup was taken before an offline upgrade on this host" "no backup"
printf '#!/bin/sh\ncase " $* " in *" --check "*) cat >/dev/null; exit 0 ;; esac\ncat >/dev/null\necho "superbot-restore: disk full" >&2\nexit 1\n' >"$RB/bundle/deploy/superbot-restore.sh"
rm -f "$RB/systemctl" && touch "$RB/active"
if out=$(rollback); then fail "a rollback whose restore failed went on: $out"; fi
cp "$DIR/superbot-restore.sh" "$RB/bundle/deploy/"
grep -Fq "Couldn't put back the backup taken before the upgrade: superbot-restore: disk full. DATA_DIR wasn't touched, and superbot is back as it was on 0.2.0" <<<"$out" || fail "a failed restore didn't say so: $out"
grep -qx MACHINE_HARNESS_BUNDLE=/srv/b/new.tar.gz "$RH/superbot/.env" || fail "a failed restore didn't put the .env back"
[[ -z $(compgen -G "$RH/superbot/.env.before-rollback-*") ]] || fail "a failed restore left the .env it kept"
grep -qx "systemctl start superbot.service" "$RB/systemctl" || fail "a failed restore didn't start superbot again"
grep -qx "version=0.2.0" "$RB/offline-release" || fail "a failed restore recorded the older release"
[[ -f "$RB/dir/record" ]] || fail "a failed restore removed the backup"
cat >"$RB/bundle/deploy/superbot-restore.sh" <<'EOF'
#!/bin/sh
case " $* " in *" --check "*) cat >/dev/null; exit 0 ;; esac
cat >/dev/null
mkdir "$2/superbot/data/.pre-restore-test"
echo "superbot-restore: No space left on device" >&2
exit 1
EOF
rm -f "$RB/systemctl" && touch "$RB/active"
if out=$(rollback); then fail "a rollback whose restore failed while swapping went on: $out"; fi
cp "$DIR/superbot-restore.sh" "$RB/bundle/deploy/"
grep -Fq "stopped while swapping $RH/superbot/data: superbot-restore: No space left on device. superbot is left stopped" <<<"$out" || fail "a restore failed while swapping didn't say so: $out"
! grep -q "systemctl start" "$RB/systemctl" || fail "superbot was started on data a failed swap left"
[[ -n $(compgen -G "$RH/superbot/.env.before-rollback-*") ]] || fail "a failed swap didn't keep the .env it replaced"
grep -qx "version=0.2.0" "$RB/offline-release" || fail "a failed swap recorded the older release"
[[ -f "$RB/dir/record" ]] || fail "a failed swap removed the backup"
rm -rf "$RH/superbot/data/.pre-restore-test" "$RH"/superbot/.env.before-rollback-*
sed -i 's,^MACHINE_HARNESS_BUNDLE=.*,MACHINE_HARNESS_BUNDLE=/srv/b/new.tar.gz,' "$RH/superbot/.env"
sed -i 's/^version=.*/version=0.0.9/' "$RB/offline-release"
if out=$(rollback); then fail "--rollback took a newer bundle: $out"; fi
grep -Fq -- "--rollback goes back to an older release, but this host runs 0.0.9 and the bundle is $VERSION" <<<"$out" || fail "--rollback to a newer bundle didn't say why: $out"
rm "$RB/offline-release"
if out=$(rollback); then fail "--rollback went on with no release recorded: $out"; fi
grep -Fq "this host has no offline release recorded" <<<"$out" || fail "--rollback with no release recorded didn't say why: $out"
ok "--rollback is refused, changing nothing, for another release's or build's backup, a host upgraded since, a changed or broken backup, an old .env with another DATA_DIR, or none; a restore that fails before the swap puts the .env back and starts botd, and one that fails while swapping leaves botd stopped"

if command -v age-keygen >/dev/null 2>&1; then
  age-keygen -o "$RB/identity" 2>/dev/null
  rb_host "SUPERBOT_BACKUP_AGE_RECIPIENTS=$(age-keygen -y "$RB/identity")"$'\n'
  rb "$UPGRADE_TO; offline_rollback_point" >/dev/null || fail "an encrypted backup before an upgrade failed"
  archive=$RB/dir/$(sed -n 's/^archive=//p' "$RB/dir/record")
  [[ "$archive" == *.tar.gz.age && $(head -c 21 "$archive") == age-encryption.org/v1 ]] || fail "the backup wasn't encrypted as the server's backups are: $archive"
  rb_upgraded
  mv "$RB/identity" "$RB/identity.away"
  if out=$(rollback); then fail "an encrypted backup was restored without its key: $out"; fi
  grep -Fq "is encrypted: put the age identity that opens it at $RB/identity" <<<"$out" || fail "a missing backup key wasn't said: $out"
  mv "$RB/identity.away" "$RB/identity"
  out=$(rollback) || fail "the encrypted rollback failed: $out"
  [[ $(rows) == before ]] || fail "the encrypted rollback didn't put back the data: $(rows)"
  ok "the backup is encrypted to the server's backup recipients, and --rollback opens it with the backup key, as root"
fi

# A rollback checks machines' settings against the .env it puts back, which botd's user reads
# from a copy of its own, in the folder the unit runs botd in.
rb_host
rb "$UPGRADE_TO; offline_rollback_point" >/dev/null || fail "the backup before an upgrade failed"
rb_upgraded
cat >"$RB/bundle/bin/botd" <<EOF
#!/bin/sh
# Usage: botd machines check
[ \$# = 4 ] && [ "\$1 \$2 \$3" = "machines check --env-file" ] || { echo "botd \$*"; exit 2; }
case "\$4" in "$RB/dir/"*) echo "botd read root's copy"; exit 2 ;; esac
echo "\$4" >"$RB/copy"
[ "\$(pwd)" = "$RH/superbot" ] || { echo "botd ran in \$(pwd)"; exit 2; }
cat -- "\$4" >"$RB/checked"
grep -q old.tar.gz "$RB/checked" && { echo "Machines: incus, enrolling at https://10.0.0.5:8443"; exit 0; }
echo "botd wouldn't start with these settings: Machine enrollment: MACHINE_HARNESS_BUNDLE: can't read it"; exit 1
EOF
chmod 0755 "$RB/bundle/bin/botd"
out=$(rb "ROLLBACK_RESTORE=true OFFLINE_VERSION=$VERSION; offline_settings_start_check") || fail "a rollback's machine check failed: $out"
grep -Fq "Machines' settings: the bundle's botd would start with them" <<<"$out" || fail "a rollback's machine check wasn't said: $out"
cmp -s "$RB/checked" "$RB/dir/$(sed -n 's/^env=//p' "$RB/dir/record")" || fail "the rollback's machine check didn't read the .env from before the upgrade"
[[ ! -e $(cat "$RB/copy") ]] || fail "the rollback's machine check left botd's user's copy of the .env behind"
sed -i 's/old.tar.gz/gone.tar.gz/' "$RB/dir/$(sed -n 's/^env=//p' "$RB/dir/record")"
if out=$(rb "ROLLBACK_RESTORE=true OFFLINE_VERSION=$VERSION; offline_settings_start_check"); then fail "a rollback went on with machine settings its botd refuses: $out"; fi
grep -Fq "Nothing has changed. The .env from before the upgrade names something $VERSION's botd can't use now" <<<"$out" \
  || fail "a rollback's refused machine check didn't say why: $out"
cp "$T/bin/botd" "$RB/bundle/bin/botd"
ok "a rollback checks machines' settings in the .env it puts back, read by botd's user from a copy it removes"

# With botd settings check, a rollback judges every setting in the .env it puts back, over what
# the install then writes, from a copy botd's user owns (ADR 0310).
rb_host
rb "$UPGRADE_TO; offline_rollback_point" >/dev/null || fail "the backup before an upgrade failed"
rb_upgraded
cat >"$RB/bundle/bin/botd" <<EOF
#!/bin/sh
# Usage: botd settings check
[ "\$1 \$2 \$3" = "settings check --env-file" ] || { echo "botd \$*"; exit 2; }
case "\$4" in "$RB/dir/"*) echo "botd read root's copy"; exit 2 ;; esac
[ "\$(pwd)" = "$RH/superbot" ] || { echo "botd ran in \$(pwd)"; exit 2; }
cat -- "\$4" >"$RB/checked"
shift 4
printf '%s\n' "\$@" >"$RB/args"
grep -q old.tar.gz "$RB/checked" && { echo "botd would start with these settings."; exit 0; }
echo "botd wouldn't start with these settings: Server backups: SERVER_BACKUP_OFF_HOST must be auto, on or off, not \"sometimes\""; exit 1
EOF
chmod 0755 "$RB/bundle/bin/botd"
out=$(rb "ROLLBACK_RESTORE=true OFFLINE_VERSION=$VERSION; offline_settings_start_check") || fail "a rollback's settings check failed: $out"
grep -Fq "Settings: the bundle's botd would start with them (botd settings check)" <<<"$out" || fail "a rollback's settings check wasn't said: $out"
cmp -s "$RB/checked" "$RB/dir/$(sed -n 's/^env=//p' "$RB/dir/record")" || fail "the rollback's settings check didn't read the .env from before the upgrade"
for want in "DATA_DIR=$RH/superbot/data" PORT=3000; do
  grep -qxF "$want" "$RB/args" || fail "the rollback's settings check wasn't given $want, which the install writes: $(cat "$RB/args")"
done
sed -i 's/old.tar.gz/gone.tar.gz/' "$RB/dir/$(sed -n 's/^env=//p' "$RB/dir/record")"
if out=$(rb "ROLLBACK_RESTORE=true OFFLINE_VERSION=$VERSION; offline_settings_start_check"); then fail "a rollback went on with settings its botd refuses: $out"; fi
for want in "wouldn't start with $RB/dir/" "Server backups: SERVER_BACKUP_OFF_HOST must be auto, on or off" "Nothing has changed. The .env from before the upgrade names something $VERSION's botd can't use now"; do
  grep -Fq -- "$want" <<<"$out" || fail "a rollback's refused settings check didn't say $want: $out"
done
cp "$T/bin/botd" "$RB/bundle/bin/botd"
ok "with botd settings check, a rollback judges every setting in the .env it puts back, over what the install writes"

# Before an offline upgrade or rollback changes anything, the running release's botd and the
# bundle's judge the license as their start would (ADR 0305). Stand-in botds take the keys in
# their folder's accepts, judging the one on stdin with --key-file -, else DATA_DIR/license.key.
# lbotd DIR DATA_DIR
lbotd() {
  mkdir -p "$1"
  cat >"$1/botd" <<EOF
#!/bin/sh
# Usage: botd license check
[ "\$1 \$2" = "license check" ] || { echo "botd \$*"; exit 2; }
[ -z "\${LEAK:-}" ] || { echo "the installer's environment reached botd"; exit 3; }
shift 2
echo "\$*" >"$1/args"
pwd >"$1/pwd"
case " \$* " in *" --env-file "*) f=\$(echo "\$*" | sed 's/.*--env-file \([^ ]*\).*/\1/'); cp "\$f" "$1/env"; echo "\$f" >"$1/copy" ;; esac
case " \$* " in *" --key-file - "*) key=\$(cat) ;; *) key=\$(cat "$2/license.key" 2>/dev/null) ;; esac
echo "\$key" >"$1/judged"
if [ -z "\$key" ]; then printf 'Settings: x\nLicense: unlicensed, from nothing: no license is set\n  No license is installed.\nSeats: 2 in use, and none allowed\nBots wouldn'"'"'t run with this license (botd 9): No license is installed.\n'; exit 1; fi
if grep -qx "\$key" "$1/accepts" 2>/dev/null; then printf 'Settings: x\nLicense: active, from y\n  Licensed to Acme Ltd (business, 5 seats) until 2027-01-01.\nSeats: 2 of 5 in use\nWarning: The license ends in 20 days.\nBots would run with this license (botd 9).\n'; exit 0; fi
printf 'Settings: x\nLicense: invalid, from y\n  The license key isn'"'"'t valid (unknown_key).\n  This license was signed by a key this version of SuperBot doesn'"'"'t know.\nBots wouldn'"'"'t run with this license (botd 9): The license key isn'"'"'t valid (unknown_key).\n'; exit 1
EOF
  chmod 0755 "$1/botd"
}
LH=$T/lhome
mkdir -p "$LH/superbot/data"
echo 'DATA_DIR=x' >"$LH/superbot/.env"
lbotd "$T/lnow" "$LH/superbot/data"
lbotd "$T/lbundle/bin" "$LH/superbot/data"
echo old >"$LH/superbot/data/license.key"
lcheck() {
  printf '%s\n' "$1" >"$T/lnow/accepts"
  printf '%s\n' "$2" >"$T/lbundle/bin/accepts"
  shift 2
  (
    OFFLINE_BUNDLE=$B OFFLINE_DIR=$T/lbundle OFFLINE_VERSION=0.2.0 BIN_DIR=$T/lnow DRY_RUN=false SUPERBOT_USER=sb LEAK=1 LICENSE_FILE=""
    export LEAK
    id() { [[ $1 == sb ]]; }
    user_home() { echo "$LH"; }
    sudo() { [[ $1 == -u ]] || { echo "sudo $*"; return 9; }; echo "$2" >>"$T/lbundle/as"; shift 2; "$@"; }
    local a
    for a in "$@"; do declare "$a"; done
    offline_license_check
  ) 2>&1
}
: >"$T/lbundle/as"
out=$(lcheck old old) || fail "a license both releases take stopped the upgrade: $out"
for want in "License: 0.2.0 would run Bots with this server's license: Licensed to Acme Ltd (business, 5 seats) until 2027-01-01." \
  "License with 0.2.0: The license ends in 20 days."; do
  grep -Fq -- "$want" <<<"$out" || fail "a good license check didn't say $want: $out"
done
[[ $(cat "$T/lbundle/bin/args") == "--home $LH" && $(cat "$T/lbundle/bin/pwd") == / ]] || fail "the bundle's botd didn't judge the server's settings: $(cat "$T/lbundle/bin/args")"
[[ $(sort -u "$T/lbundle/as") == sb ]] || fail "the license check didn't run as botd's user: $(cat "$T/lbundle/as")"
if out=$(lcheck old ""); then fail "an upgrade went on though its botd wouldn't run Bots with the license: $out"; fi
for want in "!! Bots run now, but 0.2.0 wouldn't run Bots with this server's license: The license key isn't valid (unknown_key)." \
  "This license was signed by a key this version of SuperBot doesn't know." "Nothing has changed" "re-run with --license-file" \
  "sudo -u sb <bundle>/bin/botd license check --home $LH --key-file <file>" "docs/ops/air-gapped.md#the-license-through-upgrades"; do
  grep -Fq -- "$want" <<<"$out" || fail "a refused license check didn't say $want: $out"
done
out=$(lcheck old "" DRY_RUN=true) || fail "a dry run stopped on the license check: $out"
grep -Fq "[dry-run] would stop here, as Bots run now: 0.2.0 wouldn't run Bots" <<<"$out" || fail "a dry run didn't say the upgrade would stop: $out"
out=$(lcheck "" "") || fail "an upgrade where Bots don't run now either stopped: $out"
grep -Fq "Bots don't run on this server now either" <<<"$out" || fail "a license neither release takes wasn't said: $out"
printf 'renewed\n\n' >"$T/lkey"
out=$(lcheck old renewed LICENSE_FILE="$T/lkey") || fail "a renewal the bundle takes stopped the upgrade: $out"
grep -Fq "License: 0.2.0 would run Bots with the key in --license-file" <<<"$out" || fail "the renewal given wasn't judged: $out"
[[ $(cat "$T/lbundle/bin/judged") == renewed && $(cat "$T/lbundle/bin/args") == "--key-file - --home $LH" ]] \
  || fail "the bundle's botd didn't judge the key in --license-file: $(cat "$T/lbundle/bin/args" "$T/lbundle/bin/judged")"
printf 'rene\n  wed\n' >"$T/lwrapped"
out=$(lcheck old renewed LICENSE_FILE="$T/lwrapped") || fail "a key wrapped across lines stopped the upgrade: $out"
[[ $(cat "$T/lbundle/bin/judged") == renewed ]] || fail "a wrapped key wasn't judged as it is installed: $(cat "$T/lbundle/bin/judged")"
if out=$(lcheck old old LICENSE_FILE="$T/lkey"); then fail "an upgrade went on with a --license-file its botd doesn't take: $out"; fi
grep -Fq "0.2.0 wouldn't run Bots with the key in --license-file" <<<"$out" || fail "a --license-file the bundle refuses wasn't said: $out"
out=$(lcheck old "" TESTING_MODE_ON=true) || fail "--testing-mode stopped on the license: $out"
grep -Fq "License: --testing-mode sets TESTING_MODE=on, so 0.2.0 runs Bots with or without a license" <<<"$out" || fail "--testing-mode wasn't said: $out"
mv "$T/lnow/botd" "$T/lnow/botd.away"
out=$(lcheck old "") || fail "an upgrade from a release that can't check licenses stopped: $out"
grep -Fq "The running release can't say whether Bots run now" <<<"$out" || fail "an older running release wasn't said: $out"
mv "$T/lnow/botd.away" "$T/lnow/botd"
mv "$T/lbundle/bin/botd" "$T/lbundle/bin/botd.away"
{ echo '#!/bin/sh'; echo "echo ran >$T/lbundle/bin/args"; } >"$T/lbundle/bin/botd"
chmod 0755 "$T/lbundle/bin/botd"
echo "not run" >"$T/lbundle/bin/args"
out=$(lcheck old "") || fail "a bundle's botd from before the license check stopped the upgrade: $out"
grep -Fq "The bundle's botd (0.2.0) can't check licenses" <<<"$out" || fail "an older bundle botd wasn't said: $out"
[[ $(cat "$T/lbundle/bin/args") == "not run" ]] || fail "an older bundle botd was run, which would start as the server"
mv "$T/lbundle/bin/botd.away" "$T/lbundle/bin/botd"
[[ -z $( (OFFLINE_BUNDLE=''; offline_license_check) 2>&1) ]] || fail "an online install checked the license"
ok "an offline upgrade stops before changing anything when Bots run now but the bundle's botd wouldn't run them with the license (botd license check)"

mv "$LH/superbot/.env" "$LH/superbot/env.away"
[[ -z $(lcheck old old) ]] || fail "a new install without --license-file checked a license"
out=$(lcheck "" "" LICENSE_FILE="$T/lkey") || fail "a new install stopped on its --license-file: $out"
grep -Fq "!! The key in --license-file isn't a license 0.2.0 takes: The license key isn't valid (unknown_key). Install one it takes" <<<"$out" \
  || fail "a new install's --license-file the bundle refuses wasn't said: $out"
out=$(lcheck "" renewed LICENSE_FILE="$T/lkey") || fail "a new install's good --license-file stopped it: $out"
grep -Fq "License: 0.2.0 takes the key in --license-file: Licensed to Acme Ltd" <<<"$out" || fail "a new install's good --license-file wasn't said: $out"
out=$( (
  OFFLINE_BUNDLE=$B OFFLINE_DIR=$T/lbundle OFFLINE_VERSION=0.2.0 SUPERBOT_USER=nobody-here LICENSE_FILE="$T/lkey" DRY_RUN=false
  echo renewed >"$T/lbundle/bin/accepts"
  offline_license_check
) 2>&1) || fail "a new install with no botd user yet stopped on the license check: $out"
grep -Fq "License: 0.2.0 takes the key in --license-file" <<<"$out" || fail "a new install with no botd user yet didn't judge --license-file: $out"
mv "$LH/superbot/env.away" "$LH/superbot/.env"
ok "a new offline install says whether the bundle's botd takes the key in --license-file, and goes on either way"

# A rollback keeps the license installed since the upgrade when the older release takes it, and
# otherwise judges the backup's. The rollback's own botds are stand-ins; the backup is real.
lrollback() { rb "${1:-}ROLLBACK=true DRY_RUN=true; prepare_offline; OFFLINE_DIR=$RB/bundle DRY_RUN=false; prepare_rollback; offline_license_check; offline_rollback_point${2:-}"; }
lrb_host() {
  rb_host "${1:-}"
  echo old >"$RH/superbot/data/license.key"
  rb "$UPGRADE_TO; offline_rollback_point" >/dev/null || fail "the backup before an upgrade failed"
  rb_upgraded
  echo renewed >"$RH/superbot/data/license.key"
  lbotd "$RB/bin" "$RH/superbot/data"
  lbotd "$RB/bundle/bin" "$RH/superbot/data"
  printf 'old\nrenewed\n' >"$RB/bin/accepts"
  printf '%s\n' "$2" >"$RB/bundle/bin/accepts"
  touch "$RB/active"
}
lrb_host "" renewed
out=$(lrollback) || fail "a rollback with a renewal the older release takes failed: $out"
for want in "Rollback: keeping the license installed since the upgrade to 0.2.0, which $VERSION takes" \
  "License: $VERSION would run Bots with the license installed now, which the rollback keeps" \
  "Kept the license installed since the upgrade as $RH/superbot/data/license.key"; do
  grep -Fq -- "$want" <<<"$out" || fail "the rollback didn't say $want: $out"
done
[[ $(rows) == before && $(cat "$RH/superbot/data/license.key") == renewed ]] || fail "the rollback didn't keep the renewal: $(rows) $(cat "$RH/superbot/data/license.key")"
[[ $(stat -c %a "$RH/superbot/data/license.key") == 600 ]] || fail "the license kept isn't 0600"
[[ $(cat "$RB/bundle/bin/pwd") == "$RH/superbot" && $(cat "$RB/bundle/bin/args") == "--key-file - --env-file "* ]] || fail "the older botd didn't judge with the .env it goes back to: $(cat "$RB/bundle/bin/args")"
cmp -s "$RB/bundle/bin/env" "$RH/superbot/.env" || fail "the older botd didn't read the .env from before the upgrade"
[[ ! -e $(cat "$RB/bundle/bin/copy") ]] || fail "the license check left botd's user's copy of the .env behind"

lrb_host "" renewed
rm -f "$RB/systemctl"
if out=$(lrollback "write_license_key() { return 1; }; "); then fail "a rollback went on though it couldn't keep the renewal: $out"; fi
for want in "Couldn't write the license installed since the upgrade as $RH/superbot/data/license.key. superbot is left stopped" \
  "The key is kept in $RB/dir/license.key"; do
  grep -Fq -- "$want" <<<"$out" || fail "a renewal that couldn't be kept didn't say $want: $out"
done
[[ $(cat "$RB/dir/license.key") == renewed && $(stat -c %a "$RB/dir/license.key") == 600 ]] || fail "the renewal wasn't kept root-only"
[[ $(cat "$RH"/superbot/data/.pre-restore-*/license.key) == renewed ]] || fail "the renewal isn't in the restore's copy of the data"
! grep -q "systemctl start" "$RB/systemctl" || fail "superbot was started without the renewal"
rm -rf "$RB/dir"

lrb_host "" renewed
out=$(lrollback "TESTING_MODE_ON=true ") || fail "a rollback with --testing-mode failed: $out"
for want in "License: --testing-mode sets TESTING_MODE=on, so $VERSION runs Bots" "Kept the license installed since the upgrade as $RH/superbot/data/license.key"; do
  grep -Fq -- "$want" <<<"$out" || fail "a rollback with --testing-mode didn't say $want: $out"
done
[[ $(cat "$RH/superbot/data/license.key") == renewed ]] || fail "a rollback with --testing-mode didn't keep the renewal"

# An old .env whose LICENSE_KEY_FILE is in DATA_DIR: the restore puts that file back, and it wins.
KF=$RH/superbot/data/keys/lic
rb_host "LICENSE_KEY_FILE=$KF"$'\n'
mkdir -p "${KF%/*}" && echo oldkf >"$KF"
rb "$UPGRADE_TO; offline_rollback_point" >/dev/null || fail "the backup before an upgrade failed"
rb_upgraded
echo renewed >"$KF" && echo renewed >"$RH/superbot/data/license.key"
lbotd "$RB/bin" "$RH/superbot/data" && printf 'oldkf\nrenewed\n' >"$RB/bin/accepts"
lbotd "$RB/bundle/bin" "$RH/superbot/data" && echo renewed >"$RB/bundle/bin/accepts"
touch "$RB/active"
if out=$(lrollback); then fail "a rollback went on though the older release wouldn't run Bots with the LICENSE_KEY_FILE it puts back: $out"; fi
grep -Fq "wouldn't run Bots with the license in LICENSE_KEY_FILE ($KF) from before the upgrade" <<<"$out" || fail "the backup's LICENSE_KEY_FILE wasn't judged: $out"
[[ $(cat "$RB/bundle/bin/judged") == oldkf ]] || fail "the live LICENSE_KEY_FILE was judged, not the backup's: $(cat "$RB/bundle/bin/judged")"
! grep -q '^LICENSE_KEY_FILE=' "$RB/bundle/bin/env" || fail "LICENSE_KEY_FILE was left over the key judged in its place"
[[ $(rows) == before,after && $(cat "$KF") == renewed ]] || fail "a refused rollback changed something"
out=$(lrollback "LICENSE_FILE=$T/lkey " "; install_license") || fail "a rollback with --license-file over LICENSE_KEY_FILE failed: $out"
grep -Fq "Kept the key in --license-file, which LICENSE_KEY_FILE names, as $KF" <<<"$out" || fail "--license-file wasn't written where LICENSE_KEY_FILE points: $out"
[[ $(rows) == before && $(cat "$KF") == renewed && ! -e "$RH/superbot/data/license.key" ]] || fail "--license-file didn't replace the backup's LICENSE_KEY_FILE alone"
rb_host "LICENSE_KEY=inline"$'\n'"LICENSE_KEY_FILE=$KF"$'\n'
mkdir -p "${KF%/*}" && echo oldkf >"$KF"
rb "$UPGRADE_TO; offline_rollback_point" >/dev/null || fail "the backup before an upgrade failed"
rb_upgraded
lbotd "$RB/bundle/bin" "$RH/superbot/data" && echo inline >"$RB/bundle/bin/accepts"
touch "$RB/active"
out=$(lrollback "LICENSE_FILE=$T/lkey ") || true
grep -qx "LICENSE_KEY_FILE=$KF" "$RB/bundle/bin/env" || fail "LICENSE_KEY_FILE was dropped though LICENSE_KEY is set too, which botd refuses: $out"

lrb_host "" old
out=$(lrollback) || fail "a rollback whose older release takes only the license from before failed: $out"
for want in "The license installed since the upgrade to 0.2.0 isn't one $VERSION takes" \
  "License: $VERSION would run Bots with the license from before the upgrade, which the rollback puts back"; do
  grep -Fq -- "$want" <<<"$out" || fail "the rollback didn't say $want: $out"
done
[[ $(cat "$RB/bundle/bin/judged") == old && $(cat "$RH/superbot/data/license.key") == old ]] || fail "the rollback didn't judge and put back the backup's license"

lrb_host "" ""
if out=$(lrollback); then fail "a rollback went on though the older release wouldn't run Bots with either license: $out"; fi
for want in "Bots run now, but $VERSION wouldn't run Bots with the license from before the upgrade" "Nothing has changed. Roll back with --license-file"; do
  grep -Fq -- "$want" <<<"$out" || fail "a refused rollback didn't say $want: $out"
done
[[ $(rows) == before,after && $(cat "$RH/superbot/data/license.key") == renewed ]] || fail "a refused rollback changed something"
grep -q "systemctl stop" "$RB/systemctl" 2>/dev/null && fail "a refused rollback stopped superbot"
echo third >"$T/lkey3"
echo third >"$RB/bundle/bin/accepts"
out=$(lrollback "LICENSE_FILE=$T/lkey3 " "; install_license") || fail "a rollback with --license-file failed: $out"
grep -Fq "License: $VERSION would run Bots with the key in --license-file" <<<"$out" || fail "the rollback's --license-file wasn't judged: $out"
[[ $(cat "$RH/superbot/data/license.key") == third ]] || fail "the rollback didn't install --license-file over the backup's"
if command -v age-keygen >/dev/null 2>&1; then
  rm -f "$RB/identity"
  age-keygen -o "$RB/identity" 2>/dev/null
  lrb_host "SUPERBOT_BACKUP_AGE_RECIPIENTS=$(age-keygen -y "$RB/identity")"$'\n' old
  out=$(lrollback) || fail "a rollback with an encrypted backup failed: $out"
  [[ $(cat "$RB/bundle/bin/judged") == old ]] || fail "the license in an encrypted backup wasn't judged: $(cat "$RB/bundle/bin/judged")"
fi
rm -f "$RB/bin/botd" "$RB/bin/accepts" "$RB/bin/args" "$RB/bin/pwd" "$RB/bin/judged" "$RB/bin/env" "$RB/bin/copy"
cp "$T/bin/botd" "$RB/bundle/bin/botd"
ok "a rollback keeps a renewal the older release takes (leaving botd stopped if it can't write it), else judges the backup's license (or LICENSE_KEY_FILE in DATA_DIR), and stops when Bots run now but wouldn't after"

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
  "would record bundle $VERSION" "Offline: no packages" "--offline <newer bundle> --upgrade --domain offline.test" "SuperBot is installed." \
  "would check botd's settings for anything on the internet: botd offline check --home"; do
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

"${net[@]}" bash "$T/run.sh" "$DIR/install.sh" --dry-run --non-interactive --offline "$B" --with-hermes --hermes-bundle "$HB" \
  --tz UTC >"$T/hdry.log" 2>&1 || { cat "$T/hdry.log" >&2; fail "the offline dry run with Hermes Agent failed"; }
for want in "Hermes bundle: Hermes Agent $HTAG (${HERMES_COMMIT:0:12}, $ARCH) checked" \
  "would install Hermes Agent $HERMES_COMMIT system-wide in /opt/hermes from the Hermes bundle $HB, linked from /usr/local/bin/hermes" "SuperBot is installed."; do
  grep -Fq -- "$want" "$T/hdry.log" || { cat "$T/hdry.log" >&2; fail "the offline dry run with Hermes Agent didn't say: $want"; }
done
if grep -Ei 'apt-get|raw\.githubusercontent|would fetch|git clone' "$T/hdry.log"; then
  fail "the offline dry run with Hermes Agent reached for the network"
fi
ok "a dry run of the offline install with Hermes Agent installs it from the Hermes bundle${net:+ (with no network)}"

"${net[@]}" bash "$T/run.sh" "$DIR/install.sh" --dry-run --non-interactive --offline "$B" --harness-bundle "$NB" \
  --tz UTC >"$T/ndry.log" 2>&1 || { cat "$T/ndry.log" >&2; fail "the offline dry run with the harness bundle failed"; }
for want in "Harness bundle: claude codex pi on Node.js $NODE_PIN ($ARCH, SuperBot $VERSION) checked" \
  "would install claude codex pi system-wide in /opt/superbot-harnesses from the harness bundle $NB, linked from /usr/local/bin" \
  "Claude Code, Codex and Pi are in /opt/superbot-harnesses, from the harness bundle" "SuperBot is installed."; do
  grep -Fq -- "$want" "$T/ndry.log" || { cat "$T/ndry.log" >&2; fail "the offline dry run with the harness bundle didn't say: $want"; }
done
if grep -Ei 'apt-get|registry\.npmjs|npm install|nodejs\.org|would fetch|git clone' "$T/ndry.log"; then
  fail "the offline dry run with the harness bundle reached for the network"
fi
grep -Fq "re-run with --harness-bundle" "$T/dry.log" || fail "an offline install without the harness bundle didn't say how to add the harness CLIs"
ok "a dry run of the offline install with the harness bundle installs the harness CLIs from it${net:+ (with no network)}"
