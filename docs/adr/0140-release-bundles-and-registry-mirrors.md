# 0140: Offline bundles for every release, and images in OCI layout for registry mirrors

## Status

Accepted (22 Nov 2026). Second slice of [#59](https://github.com/CG-Labs/superbot/issues/59) (M5, "Air-gapped self-host"). Builds on the offline bundle and `install.sh --offline` ([ADR 0128](0128-air-gapped-self-host.md)), image signing ([ADR 0101](0101-image-scanning-and-signing.md)) and GitHub releases from tags ([ADR 0111](0111-changelog-and-github-releases.md)). It closes the two follow-ups ADR 0128 left: release bundles made with every tag, and images in a registry mirror format.

0140 was reserved for this work.

## Context

ADR 0128 shipped offline bundles, but:

- **Release bundles only existed if a maintainer remembered to run the workflow** for each published release. An air-gapped customer can't fetch from `main`; a release without bundles is one they can't install.
- **Images were `docker save` tarballs.** `docker save` writes uncompressed layers and a new manifest, so the image no longer has the digest the `docker` workflow signed. That's fine for `docker load` on one host. It doesn't work for the usual air-gapped Compose or Kubernetes setup: one internal registry (Harbor, Artifactory, Nexus, a plain `registry:2`) that every host pulls from, pinned by digest. Pushing a loaded image (`docker tag` + `docker push`) gives a third digest that matches nothing anyone signed or recorded.

## Decision

### Bundles follow the docker workflow for every tag

`offline.yml`'s `release-bundle` job now also starts on `workflow_run` when the `docker` workflow finishes. It runs only when that run was a `push` of a tag starting with `v` in this repository (not a fork) and it succeeded, so the tag's images are published and signed. Manual `workflow_dispatch` stays, for a release made before this change or a run that failed.

We considered and rejected:

- **`push: tags` on `offline.yml`.** It would race the docker workflow: the bundle step needs the tag's images, which take most of an hour to build, sign and tag. It would have to wait on a runner or fail.
- **Having the docker workflow dispatch `offline.yml`.** That needs `actions: write` on the job that signs the images, which ADR 0101 keeps minimal.

`workflow_run` runs the default branch's copy of `offline.yml`, so the job checks out `refs/tags/<tag>` itself. For a tag push, `workflow_run.head_branch` is the tag name. To be safe, the job checks the tag is `v<semver>`, that its commit is on `main` (as `release.yml` does), and that it is the commit the docker run built (`workflow_run.head_sha`). Otherwise a tag moved after the build would bundle images of another commit. The bundle is signed keylessly under `offline.yml@refs/heads/main`, which the installer's signer pattern already accepts. The job then waits for `release.yml`'s release for the tag, then attaches the bundle, its `.sha256` and `.sigstore.json`. Values from the event reach scripts only through `env`. The `offline_release` test (in the docs workflow) holds the workflow to all of this.

Each docker run on `main` also triggers `offline.yml` through `workflow_run`. Those runs are skipped at the job level, which costs nothing but shows as skipped runs.

### Images as OCI archives, digests kept

`offline-bundle.sh build --image NAME=REF` now copies each image with skopeo instead of `docker pull` + `docker save`:

1. It reads what `REF` names in its registry. That is either an index, with this arch's entry picked and attestation entries (no platform) skipped, or a single image, whose config must be this arch.
2. cosign checks the signature on the digest `REF` named (the index; the docker workflow signs `--recursive`), as before. The SBOM is read as before.
3. skopeo copies this arch's image by digest (`--preserve-digests` where skopeo has it) into an OCI image layout. The build then refuses the image unless the copied manifest has exactly the digest the signed index lists for this arch. The chain is: signed index → this arch's digest → manifest → blobs, each checked by digest.
4. The layout is packed as `images/<name>.tar`, an **OCI archive**. Beside its `index.json` (annotated with the image name for containerd) is a Docker `manifest.json` (`Config`, `RepoTags`, `Layers` naming the same blobs), the same dual format `docker save` has written since Docker 25. So **one file** is both what `skopeo copy oci-archive:...`, `regctl image import` or `crane` push to a registry unchanged, and what `docker load` reads. We checked this on Docker 29 with both the containerd image store and the classic one (overlay2, gzip layers decompressed on load). Layers stay compressed, so bundles also get smaller.

`images/<name>.digest` is now that image's manifest digest (`sha256:...`). `MANIFEST` gains `image_format=oci`. The bundle `format` stays 1: an older `offline-bundle.sh load` still loads these images, and the installer never reads `images/`.

`REF` must be a tagged reference (`HOST/PATH:TAG`, lowercase, no digest), so `docker load` and the mirror get a name and a tag. An `--allow-unsigned` image that is in the local Docker (an operator's own, e.g. with Hermes Agent) goes through `docker save` and skopeo's `docker-archive:` source. We don't use skopeo's `docker-daemon:` source, because Docker 29 refuses the API version skopeo 1.13 uses. Otherwise it comes from its registry like a signed one.

skopeo and jq are needed only on the connected side, and only with `--image`. They are in Ubuntu's archive and on GitHub's runners.

### `offline-bundle.sh push BUNDLE --registry HOST[:PORT][/PATH]`

This is for an operator's mirror inside the air gap. It checks the bundle as `verify` does (any arch: the machine pushing needn't be the server). Then it copies each image from its OCI archive to `REGISTRY/<last part of its repository>:<its tag>`, reads the manifest back, and fails unless the registry now has the bundle's digest. Last, it prints Compose's `.env` settings pinned by digest (`SUPERBOT_IMAGE=.../superbot@sha256:...`, `SUPERBOT_CADDY_IMAGE=...`). It refuses a bundle with no images, or with `docker save` images from before this change. Credentials, CAs and plain-HTTP lab registries use skopeo's own configuration (`skopeo login`, `/etc/containers/certs.d`, `registries.conf`), so no TLS-disabling flag is added here.

The mirror gets the image, not its cosign signature. The digest is the check: it is the one whose signature was verified when the bundle was made, and the signed bundle carries that verification record (`images/<name>.cosign.json`) and the SBOM. Copying the signatures and attestations too would let `cosign verify` run against the mirror, but offline that needs Sigstore's trust root and the transparency log entries. That stays a follow-up.

One bundle is one arch. Pushing an x86_64 and an aarch64 bundle to the same `--registry` overwrites the tag, so a mixed-arch site uses a path per arch (`--registry registry.corp.example/superbot/arm64`). Digest pins are per arch anyway.

### Tests

- `deploy/test-offline.sh` (no network, no Docker) runs the image paths against stand-ins for skopeo, docker and cosign over a fake registry. They hold an index with this arch's image, another arch's and an attestation, plus a local image and a mirror. The tests check:
  - the signed image is checked by the index digest its tag names, with the given identity, and bundled as this arch's image with the registry's digest;
  - the archive is an OCI layout, and its `manifest.json` names the blobs it holds;
  - local and registry `--allow-unsigned` images both work;
  - these are refused: untagged, digest-only and uppercase references; unsigned images; indexes without this arch; single images and local images of another arch; a copy that changes the digest; a name given twice;
  - `push` lands the bundle's manifest in the mirror and prints the pinned settings, and refuses a registry that changes the digest, bad `--registry` values, bundles without images, and `docker save` bundles.

  Mutating the digest checks or the arch filter makes the tests fail.
- `offline.yml`'s `install-offline` job, on Ubuntu 22.04 and 24.04 (each with its own archive's skopeo), runs two local registries. It pushes a two-arch image to the first, bundles it with a local image, and checks the bundled digest equals the registry's for the runner's arch. It `docker load`s both images with no network, pushes the bundle to the second registry, and checks the digest there and that `docker pull` by that digest works.
- `server/tests/offline_release.rs` checks the workflow wiring above.

## Consequences

- Every `v*` tag gets x86_64 and aarch64 bundles with its signed images, attached to its release, with nobody remembering to run anything. The manual run remains for backfills.
- An air-gapped site can fill its own registry from a bundle and pin Compose (or anything else) to digests that match what CG-Labs signed.
- Making a bundle with images needs skopeo and jq, as well as docker (for the SBOM) and cosign.
- Bundles made before this change still install and load, but `push` refuses them.
- Still to do for #59: cosign signatures and attestations in the mirror. A multi-arch index in the mirror is also left: today one bundle is one arch.
