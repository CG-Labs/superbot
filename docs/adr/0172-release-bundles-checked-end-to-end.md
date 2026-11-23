# 0172: Every release's offline bundles checked end to end, against ghcr.io and with no network

## Status

Accepted (23 Nov 2026). Fourth slice of [#59](https://github.com/CG-Labs/superbot/issues/59) (M5, "Air-gapped self-host"). Builds on offline bundles ([ADR 0128](0128-air-gapped-self-host.md)), release bundles and registry mirrors ([ADR 0140](0140-release-bundles-and-registry-mirrors.md)), signatures and multi-arch indexes in mirrors ([ADR 0147](0147-signatures-and-multi-arch-indexes-in-mirrors.md)) and image signing ([ADR 0101](0101-image-scanning-and-signing.md)). It closes what ADR 0147 left for #59: checking a tagged release's bundles end to end against ghcr.io.

0172 was reserved for this work.

## Context

Everything a customer does with a bundle is tested in CI, but always on bundles CI made a minute earlier, from local registries, signed with a throwaway key and no transparency log. What a customer downloads differs in every way that matters:

- **The signatures are keyless.** The bundle is signed by the `offline` workflow and the images by the `docker` workflow, with Fulcio certificates and Rekor entries. Offline, cosign checks those only against Sigstore's trusted root, copied in beforehand. Nothing had ever verified a keyless signature with no network, nor the guide's instructions for getting the trusted root.
- **The images come from ghcr.io.** They are the `docker` workflow's index, with BuildKit's attestation manifests, `cosign sign --recursive` signatures and `actions/attest` provenance. A customer's connected machine reads ghcr.io with no login, and CI never had.
- **Each arch is built on its own runner.** The aarch64 bundle is built on an arm runner and the x86_64 one on Ubuntu 22.04, so the binaries run on 22.04 and 24.04. Nothing checked that a bundle's binaries are for its arch, or that they don't need a newer glibc than 22.04 has.
- **Time passes.** A tag on ghcr.io can be moved after the bundles were made, and Sigstore's trust root rotates. A release that verified on its day can stop verifying later.

There is no release yet: `v0.1.0` is untagged. So the check has to run by itself when the first release is tagged, and on every release after it, not as a one-off by hand.

While writing this we found that ghcr.io refuses anonymous reads of `cg-labs/superbot` today: the packages are private. A customer's connected machine can't pull them. Neither can `release-bundle`, which reads ghcr.io with no login, so the first tag would fail there too. Making the packages public is a repository setting, outside this change.

## Decision

### `deploy/offline-release-check.sh`, in two phases

It checks a release's attached files as a customer uses them, in the order they would.

**`online DIR --version V --image NAME=REF... [--commit SHA] [--max-glibc 2.N]`**, on a connected machine, with both arches' bundles and their `.sha256` and `.sigstore.json` in `DIR`:

1. Both arches' bundles, `.sha256` and `.sigstore.json` are there, and each `.sha256` matches.
2. Each bundle's signature verifies with `cosign verify-blob` against the identity the installer accepts (`OFFLINE_SIGNER_IDENTITY_REGEXP`, the `offline` workflow on `main` or a version tag). It can't be pinned to the tag, because `release-bundle` runs from a `workflow_run`, whose certificate names `main`. The commit check binds the bundle to the tag instead.
3. `offline-bundle.sh verify` accepts each bundle, and says it checked the signature.
4. From each bundle's own files, checked against its `SHA256SUMS`, the check confirms that:
   - `MANIFEST` names the version, the bundle's arch and the tag's commit;
   - its images are OCI archives, none bundled with `--allow-unsigned`, and exactly the `--image` names;
   - every binary, `superbot-oci` included, is an ELF file for the bundle's arch;
   - with `--max-glibc`, no binary asks for a newer `GLIBC_2.N` symbol version.
5. For each image, both bundles carry the same reference and signed index, with signatures. ghcr.io's tag must name that same index now, read anonymously. Each arch's entry in it must be the image that arch's bundle carries, and `cosign verify` checks the index against the `docker` workflow at that tag.
6. It writes `DIR/release-check.expected`: the version, each bundle's SHA-256 and each image's reference and signed index. This is the record an operator would write down before carrying bundles in.

**`offline DIR --mirror HOST/PATH --trusted-root FILE`**, with no network. It refuses to run if `github.com` answers. Then:

1. Each bundle passes `offline-bundle.sh verify`, as the installer checks it: against the recorded SHA-256 and, with `SIGSTORE_TRUSTED_ROOT`, its keyless signature.
2. `offline-bundle.sh push` sends both bundles to the mirror. Each tag there must name the recorded signed index, read back.
3. `cosign verify` passes on the tag and on every manifest the index lists (both images and both attestation manifests), keyless against the trusted root. `cosign verify-attestation --type slsaprovenance1` passes on the tag.

It adds no new trust path: it runs the installer's and `offline-bundle.sh`'s own checks and cosign's own commands, exactly as the guide tells operators to. Operators can run it too, before carrying a release in. `--key` swaps the release identities for a cosign public key with no transparency log, and `--any-binary-arch` skips the arch check. Both exist only for CI's test release, which signs with a throwaway key and bundles one runner's binaries for both arches. With `--key`, `offline-bundle.sh` sees the bundles through links without their `.sigstore.json`, because the installer checks a signature beside a bundle only against the release identity.

### `offline-release-check.yml`

A workflow with read-only permissions (`contents: read`; no `id-token`, no `packages`, no registry login). It runs:

- **after every release:** `offline.yml`'s new `release-check` job calls it once `release-bundle` has attached both arches' bundles to the tag's release;
- **weekly** on the latest release, so a tag that moved on ghcr.io, a trust root that rotated or a package made private shows up within a week;
- **by hand** for any release tag.

It downloads the release's `superbot-offline-*` files and gets Sigstore's trusted root with `cosign initialize`, copied from where the guide says. Then it runs `online` with `--commit` (the tag's commit), `--max-glibc 2.35` (Ubuntu 22.04's) and the two published images. Inside a network namespace with only loopback, it runs a `registry:2` binary as the mirror and runs `offline` there. Still in the namespace, it installs botd from the x86_64 bundle with `install.sh --offline`, using the installer from that bundle, `--bundle-sha256` and `SIGSTORE_TRUSTED_ROOT`. botd joins the namespace through a systemd drop-in, and the job checks the signature was verified and `/healthz` answers. Last, it `docker load`s the bundle's images with no network. A scheduled run with no release yet passes with a notice.

### CI

- `deploy/test-offline-release-check.sh` covers both phases without root or a network. It uses stand-ins for cosign, skopeo and `superbot-oci`, and two bundles built by the real `offline-bundle.sh`. A good release passes. Each of these is refused:
  - a missing bundle or signature, or a wrong SHA-256 or signature;
  - the wrong commit, version or images, unsigned images, or images without a signed index;
  - binaries for another arch, or needing a newer glibc;
  - a tag that moved, an image signature that fails, or an arch's image that differs;
  - offline: no online record, no trusted root, a mirror naming another digest, an image or provenance that doesn't verify, or a bundle changed since the online check.
- `offline.yml`'s `install-offline` job signs its two-arch test release's bundles with the throwaway key and runs `online` against the local registry. The step that pushed both bundles into the network namespace and ran cosign there now runs `offline`. So the script runs on every change to the offline path, against real registries, cosign, `superbot-oci` and bundles.
- `server/tests/offline_release.rs` checks the wiring:
  - `release-check` follows `release-bundle` with the same tag;
  - the workflow runs after releases, weekly and by hand, and is read-only with no login;
  - steps run in order: download, trust root, connected, namespace, offline, install. The offline and install steps run in the namespace;
  - a real release is checked keyless, binaries and all;
  - values reach scripts through `env`.

## Consequences

- When `v0.1.0` is tagged, its bundles are checked end to end without anyone remembering to. They're checked against ghcr.io and, with no network, against Sigstore's real trust root: keyless signatures, the signed index in a mirror, provenance, an install and a load. Every release after it gets the same check, and the latest release is re-checked weekly.
- A failure is a red run on the release, not a customer's ticket. The check doesn't delete or re-make anything, and the operator guide says what to do with a release that fails.
- **#59's remaining code is done.** What's left is operational: making the ghcr.io packages public (today they refuse anonymous reads, so `release-bundle` and this check would both fail), tagging the first release, and fixing anything its run finds.
- Only the x86_64 bundle is installed in the release check. The aarch64 bundle is verified, pushed and checked in the mirror, its binaries checked for arch and glibc, but not run. Installing it on an arm runner is a possible follow-up.
- The check runs from `main`'s copy of the script against older releases, so a later script may refuse an older release for a reason that release didn't know about. That is intended: the weekly run says whether a release still meets today's bar.
