#!/usr/bin/env bash
# Writes seccomp-chromium.json: Docker's default seccomp profile plus the one thing Chromium's
# sandbox needs from it (docs/adr/0106-chromium-sandbox-in-the-container.md). Docker's default
# allows namespaces in clone and unshare only with CAP_SYS_ADMIN, and chroot only with
# CAP_SYS_CHROOT, which botd's container doesn't have. This adds:
#   clone, unshare  with no namespace flags besides CLONE_NEWUSER, CLONE_NEWPID, CLONE_NEWNET
#   chroot          (it needs CAP_SYS_CHROOT, which a process has only in a user namespace it made)
# Everything else is Docker's profile, byte for byte. Mount, UTS, IPC and cgroup namespaces stay
# refused, in the container and in every user namespace made in it (seccomp filters are inherited).
# Usage: deploy/docker/seccomp-chromium.sh          # rewrite the profile
#        deploy/docker/seccomp-chromium.sh --check  # fail if the committed profile differs (CI)
set -euo pipefail

# Docker's own default profile (github.com/moby/profiles, the version Docker 28 and 29 build in).
PROFILES_TAG=seccomp/v0.1.0
PROFILES_SHA256=01536f1d1df938ae611eba20d6349e0de7a99b6ecdee1549427a0b01b8301e28

DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
OUT="$DIR/seccomp-chromium.json"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

curl -fsSL -o "$TMP/default.json" "https://raw.githubusercontent.com/moby/profiles/$PROFILES_TAG/seccomp/default.json"
echo "$PROFILES_SHA256  $TMP/default.json" | sha256sum -c --quiet -

# CLONE_NEWNS | CLONE_NEWCGROUP | CLONE_NEWUTS | CLONE_NEWIPC: these must stay clear.
REFUSED_NS=$((0x00020000 | 0x02000000 | 0x04000000 | 0x08000000))
jq --indent 2 --argjson refused "$REFUSED_NS" '.syscalls += [
  {
    names: ["clone", "unshare"],
    action: "SCMP_ACT_ALLOW",
    args: [{index: 0, value: $refused, op: "SCMP_CMP_MASKED_EQ"}],
    comment: "SuperBot: user, PID and network namespaces for Chromium'"'"'s sandbox",
    excludes: {arches: ["s390", "s390x"]}
  },
  {
    names: ["chroot"],
    action: "SCMP_ACT_ALLOW",
    comment: "SuperBot: Chromium'"'"'s sandbox chroots inside its own user namespace"
  }
]' "$TMP/default.json" >"$TMP/out.json"

if [[ "${1:-}" == --check ]]; then
  diff -u "$OUT" "$TMP/out.json" || { echo "seccomp-chromium.json is stale: run $0" >&2; exit 1; }
  echo "seccomp-chromium.json matches Docker's profile ($PROFILES_TAG) plus Chromium's rules"
else
  mv "$TMP/out.json" "$OUT"
  echo "Wrote $OUT"
fi
