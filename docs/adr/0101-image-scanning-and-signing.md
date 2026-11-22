# 0101: Container image scanning and signing

## Status

Accepted (22 Nov 2026). Part of the SOC 2 readiness checklist of M4, [#50](https://github.com/CG-Labs/superbot/issues/50); closes rows CC7.1-3 (container image scanning) and CC5.2-2 (signed images with provenance) of the [readiness checklist](../security/soc2-readiness-checklist.md).

0100 is the highest number on `main`, and no open pull request adds an ADR, so this is 0101. Renumber it if another ADR lands first.

## Context

[`docker.yml`](../../.github/workflows/docker.yml) builds `ghcr.io/cg-labs/superbot` and `ghcr.io/cg-labs/superbot-caddy` for amd64 and arm64, smoke-tests them, and publishes them from `main`, version tags and a weekly rebuild without the cache ([ADR 0084](0084-published-image-with-computer-use.md)). Nothing checked the images for known vulnerabilities, and nothing let an operator prove that an image came from this repository's workflow rather than from anyone else with a token for the package. SOC 2 CC7.1 expects vulnerabilities in what we ship to be detected; CC5.2 expects technology controls over what runs, which for a published image means a signature and a record of how it was built. Actions are already pinned by commit ([ADR 0100](0100-github-actions-pinned-by-commit.md)), so the same workflow can be trusted to do both.

The images are Debian (Node's slim image, with Chromium for the Bots' computer) and Alpine (Caddy). Debian always has CVEs with no fixed package yet, many marked "won't fix", so a gate on every finding would be red for good and then ignored.

## Decision

### Scanning

- **[Grype](https://github.com/anchore/grype)**, installed by `anchore/scan-action/download-grype` (the Grype release is the one that action version pins, from Grype's own install script, which checks the release checksums). The build job scans both images for its architecture right after the smoke test, on every event, pull requests from forks included, since scanning needs no write token. The pushes that follow are the same builds from the same cache, so the scan describes what is published. Each scan writes JSON, SARIF and a table; they are kept as the workflow artifact `image-scan-<arch>` for 90 days, the most a public repository allows.
- **Code scanning**: the `image-scan` job (one per image and architecture) uploads the SARIF to GitHub code scanning, category `image-<image>-<arch>`, only for pushes to `main`, version tags, the weekly rebuild and manual runs on `main`. Pull requests skip the upload, so a fork's run needs no `security-events` token, and a pull request can't put alerts on `main`.
- **Severity policy**: CI fails on a **Critical vulnerability with a fixed version** that isn't accepted in [`.grype.yaml`](../../.grype.yaml). Everything else (High and below, and anything with no fix) is reported, in the job summary as counts by severity, in code scanning and in the artifact, but doesn't fail. A finding we can't fix ourselves (the fix has to come from upstream, say Caddy's own binary built with an older Go) is accepted in `.grype.yaml`, one entry per finding with its reason and owner, reviewed like any change and removed when the fix lands, as `.cargo/audit.toml` does for Rust ([ADR 0092](0092-dependency-vulnerability-scanning.md)).
- **Fixes actually land**: the Dockerfile now runs `apt-get upgrade` in the runtime stage and `apk upgrade` in the Caddy stage, so a fresh build has every fixed OS package, not only what the base image had when it was last rebuilt. When the scan was first tried, `caddy:2` itself carried a fixable Critical (zlib) that the upgrade removes. Builds on `main` reuse the cache, so a new fix can be missing from them until the weekly rebuild; a manual run (`workflow_dispatch`, which rebuilds without the cache) brings it in early and refreshes the cache for later builds.
- **What a red scan holds back**: a release. `publish` waits for `image-scan`; for a version tag, a failed scan stops publishing, and the release is cut again once it's fixed. For `main` and the weekly rebuild the images are still published and the workflow is red: holding back a rebuild would also hold back every other fix it carries.

### Signing and provenance

- **Sign before tagging**: `publish` makes each multi-arch index under a staging tag for its ref (`staging-main`, `staging-v1.2.3`), signs and attests that digest, and only then points the public tags at it, checking each one resolves to the signed digest. If signing or an attestation fails, the public tags stay on the last verified image.
- **cosign, keyless**: `publish` signs each multi-arch image by digest with `cosign sign --recursive`, so the index, each platform's image and their attestations are signed. The certificate comes from Sigstore's Fulcio for the job's GitHub OIDC token, and the signature is logged in Rekor; there is no key to store, rotate or leak. The identity is the workflow file and ref: `https://github.com/CG-Labs/superbot/.github/workflows/docker.yml@refs/heads/main` (pushes, the weekly run and manual runs) or `...@refs/tags/v<version>`. Operators check exactly that identity and issuer ([`deploy/README.md`](../../deploy/README.md#verifying-the-images)).
- **Build provenance**: `actions/attest` writes a signed SLSA v1 provenance attestation for each image's index digest, stored by GitHub and pushed to GHCR beside the image; `gh attestation verify` checks it and the signing workflow. Its artifact storage record is off (`create-storage-record: false`), so the job needs no `artifact-metadata` permission.
- **SBOM and BuildKit provenance**: the push steps set `sbom` and `provenance: mode=max`, so each platform image carries an SPDX SBOM and BuildKit's own provenance as attestation manifests, inside the index that cosign signs. The SBOM generator image (`docker/buildkit-syft-scanner`) is pinned by digest, in the spirit of ADR 0100; Dependabot doesn't update it, so it is bumped by hand.
- **Least privilege per job**: the workflow default stays `contents: read`. `build` keeps `packages: write` (push by digest); `image-scan` has `security-events: write`; `publish` has `packages: write`, `id-token: write` and `attestations: write`. Nothing that runs for a pull request needs a write token, and `publish` never runs for one.
- **CI checks all of this** ([`server/tests/image_supply_chain.rs`](../../server/tests/image_supply_chain.rs)): that both images are scanned with `.grype.yaml`, that results are kept and uploaded only outside pull requests, that the gate fails on fixable Critical, that each push carries provenance and an SBOM, that both images are signed and attested, that each job has exactly the permissions above, and that the operator docs show the verify commands with the exact identity. It runs with the `docs` workflow on changes under `.github/` and in the server workflow's `cargo test`.

## Alternatives

- **Trivy.** As capable, and the more common choice. In March 2026 its GitHub Actions had 76 of 77 tags hijacked and a malicious release was published ([GHSA-69fq-xp46-6x23](https://github.com/aquasecurity/trivy/security/advisories/GHSA-69fq-xp46-6x23)). A SHA pin would have protected us, but we chose the scanner whose release channel hasn't been taken over. Switching later means changing one step and the gate's JSON query.
- **Docker Scout or GitHub's own image scanning.** Scout needs a Docker account and its results live in Docker's service; neither gives a SARIF and artifact we keep. Rejected.
- **Fail on every Critical and High.** Red on most days for Debian CVEs with no fix, so it would be ignored. Rejected for the policy above; High findings are still visible in code scanning.
- **Never fail, only report.** Nothing would make a fixable Critical get fixed. Rejected.
- **Scan the published image in a later job.** Scans exactly what's in the registry, but can't run for pull requests, which have no image to pull. The build job's scan covers both, from the same build.
- **Signing with a stored key.** A key is a secret to protect and rotate, and verification would depend on distributing it. Keyless signing ties the signature to the workflow, which is what operators want to know. Rejected.
- **Only BuildKit's attestations, or only GitHub's.** BuildKit's SBOM and provenance aren't signed by themselves; GitHub's attestation alone is verifiable only with the GitHub CLI or API. cosign plus GitHub's attestation covers both the Sigstore tooling and `gh`.

## Consequences

- Each push, weekly run and release leaves scan results in code scanning and as an artifact (90 days; download them for a Type II observation period that's longer), and each published image has a signature and provenance an operator can check.
- The first scan of the server image found three fixable Critical Go standard library flaws, all in Debian's `age` binary (built with Go 1.24.4): TLS session resumption, the HTTP/2 server, and Windows junctions. `age` only encrypts backups locally and reaches none of them, so they are accepted in `.grype.yaml` until Debian rebuilds it.
- A fixable Critical turns the workflow red until it's fixed (a manual run picks up a Debian or Alpine fix) or accepted with a reason in `.grype.yaml`. A release can't be published past it.
- Images published before this change are unsigned. Verifying a tag checks what it points to now; operators who pin by digest run exactly what they verified.
- The weekly rebuild and every merge add a scan of each image (about a minute each, the vulnerability database cached between runs) and, when publishing, the SBOM generation and signing.
