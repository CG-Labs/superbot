# 0147: Signatures, attestations and multi-arch indexes in registry mirrors

## Status

Accepted (22 Nov 2026). Third slice of [#59](https://github.com/CG-Labs/superbot/issues/59) (M5, "Air-gapped self-host"). Builds on offline bundles ([ADR 0128](0128-air-gapped-self-host.md)), release bundles and registry mirrors ([ADR 0140](0140-release-bundles-and-registry-mirrors.md)) and image signing ([ADR 0101](0101-image-scanning-and-signing.md)). It closes the two follow-ups ADR 0140 left: the images' signatures and attestations in the mirror, and multi-arch indexes in the mirror.

0147 was reserved for this work.

## Context

After ADR 0140, `offline-bundle.sh push` put each image into an operator's registry with its signed digest, but:

- **No signatures went with it.** `cosign verify` against the mirror found nothing, so a site couldn't use its registry's or cluster's signature policy (Harbor's cosign enforcement, Kyverno, Sigstore's policy-controller) for our images. The digest pin was the only check.
- **One bundle is one arch.** A bundle holds the image for its arch, so the mirror's tag named that image, not the multi-arch index the `docker` workflow signed. A mixed-arch site needed a path per arch, and even with signatures copied, `cosign verify` on the tag would check a digest nobody signed.

What the `docker` workflow publishes for each image (ADR 0101):

- A multi-arch **index** listing the amd64 and arm64 images and, for each, a BuildKit **attestation manifest** (SBOM and provenance, `vnd.docker.reference.type: attestation-manifest`, pointing at its image by `vnd.docker.reference.digest`).
- `cosign sign --recursive` signatures on the index, both images and both attestation manifests. cosign 3 stores each as an OCI 1.1 artifact (a Sigstore bundle) whose `subject` is what it signs. A registry with the [referrers API](https://github.com/opencontainers/distribution-spec/blob/main/spec.md#listing-referrers) lists them there; on one without it (`registry:2`), cosign keeps an index of them under the subject's fallback tag, `sha256-<hex>`. Older cosign used `sha256-<hex>.sig` and `.att` tags instead.
- `actions/attest` SLSA provenance on the index, pushed to the registry the same way.

The tools we could use don't fit:

- **skopeo** copies images and indexes but not their referrers, so the signatures would stay behind.
- **`cosign save` / `cosign load`** keep an image's signatures, but `save` takes every arch, so each bundle would carry the other arch's image too.
- **oras, regctl and crane** do this, but none is in Ubuntu's archive. Shipping one more downloaded binary goes against the bundle's "nothing extra to fetch inside" promise, and AGENTS.md says Rust first.

## Decision

### `superbot-oci`, a small Rust OCI client

A new binary, `server/src/bin/superbot-oci`, built from the workspace with the HTTP and TLS stack botd already uses (reqwest, rustls). It is separate from `botd` (which starts the server) and `botctl` (which has no HTTP library on purpose). It has two commands, and `offline-bundle.sh` runs both.

**`fetch --from HOST/PATH@INDEX --image DIGEST --out DIR`** copies one arch's signature graph into an OCI image layout:

1. The index cosign just checked must list `DIGEST`. It goes in, with the attestation manifests that index has for `DIGEST`, and not the other arch's.
2. Then, breadth first from the index, the image and its attestation manifests: each subject's referrers, from the referrers API and the fallback tag (both, merged, since a registry can gain the API after some referrers went into the tag). Each is checked against its digest and must name that subject. Its own referrers are followed too (a signature on an attestation). Cosign's older `.sig`, `.att` and `.sbom` tags are copied as tags.
3. Every manifest and blob is checked against its digest as it is downloaded. More than 1,000 manifests, a manifest over 4 MiB or a blob over 1 GiB is refused. Bodies are read in chunks and refused when they pass the limit, so an oversized reply is never read whole. Every page of a referrers list is read (its `Link: <...>; rel="next"`), up to 1,000 entries and 100 pages, and a link back to a page already read is refused. A page on any host but the registry's own is refused.

Each `index.json` entry says what it is in an annotation, `dev.superbot.oci.role`: `index`, `attestation`, `referrer` or `tag` (named by `org.opencontainers.image.ref.name`).

**`push --to HOST/PATH:TAG UNIT...`** puts them in a mirror. A unit is a folder with `image/` (an image's OCI layout, as bundled) and, if signed, `signatures/` (what `fetch` wrote):

- When the units hold every image and attestation manifest their index lists, the **index goes up unchanged**, with the images and attestation manifests first (registries check an index's children exist). The tag then names the digest the `docker` workflow signed. That needs every unit to carry the same index and no image twice; anything else is refused before anything is written. With one unit whose index lists more, the tag names that unit's image alone, as before. Its own attestation manifests still go up (and their signatures), though nothing in the mirror lists them.
- Then each signature and attestation, once its subject is in the mirror, so referrers of referrers follow. A registry that lists a manifest by its `subject` says so (`OCI-Subject` on the response). For one that doesn't, `push` writes the subject's fallback tag itself, keeping what it already lists, as cosign and oras do. Our role annotations aren't copied into it. Then the cosign tags. A `.sig` or `.att` tag holds one signature or attestation per layer, and cosign adds a layer each time it signs again, so the bundles' copies and the mirror's may differ. The tag gets every layer any of them holds, with its config's per-layer lists kept in step, so no bundle's copy, older or newer, takes a signature away.
- The tag goes last and is read back, and the push fails unless it names the expected digest. So a tag never names an image whose signatures aren't there yet.
- `push --check` runs every check that needs no network and prints the digest the tag would name. `offline-bundle.sh` runs it for every image before it pushes the first.
- Logins, CAs and plain-HTTP lab registries come from where skopeo and Docker keep them: the auth files (`auths`, `credHelpers` and `credsStore`, running `docker-credential-*` as Docker does), `certs.d/HOST/*.crt` (CAs) and `*.cert` with its `*.key` (a client certificate, sent only to the registry's own host: upload addresses and redirects elsewhere are reached without it), and `insecure = true` in `registries.conf` (and its `.d` folders). As in containers/image, the registry with the longest matching prefix decides, and a later file's registry with the same prefix replaces an earlier one, so an `insecure = false` for one host wins over `*.corp.example`. As there, `insecure` means the certificate isn't checked, with plain HTTP only if HTTPS doesn't answer. Bearer token and basic logins are supported. An operator's setup from ADR 0140 keeps working unchanged.
- The login, or the token it gets, goes only to the registry's own scheme, host and port. An upload location on another host (storage behind the registry) gets the upload without it. The client also refuses an HTTPS registry that hands it an HTTP upload location, next page or token service, and redirects elsewhere drop the login.

### Bundles and `offline-bundle.sh`

- **`build`**, for a signed image, after cosign's check and the copy: runs `superbot-oci fetch` from the index cosign checked, for this arch's image. It saves the layout as `signatures/<name>.tar`, sorted and owned by 0, and the index's digest as `images/<name>.index`. It goes in its own `signatures/` folder rather than `images/`, because an older `offline-bundle.sh load` would `docker load` any `images/*.tar`. A bundle with images carries `bin/superbot-oci` for `push`. The installer doesn't use it: it isn't in `OFFLINE_BINARIES`, so installs are unchanged, and `SHA256SUMS` covers it like every file. The `superbot-oci` that `build` runs is `SUPERBOT_OCI`, else the bundled one if it runs here, else one on `PATH`, so a bundle for another arch can be made.
- **`build --image-key FILE`** checks an image's signature against a cosign public key instead of the release identity, with no transparency log entry (a private key's signatures usually have none). It is for an operator's own signed images and for CI.
- **`push BUNDLE... --registry R [--sha256 HEX]...`** takes one bundle, as before, or one per arch. Several bundles must be one release (same version and images, each image with the same reference, signed index and signatures) with one bundle per arch. Every check (each bundle's SHA-256 and files, destinations that would clash, bundles that can't make the index) runs before anything is pushed. It runs `SUPERBOT_OCI`, or the bundle's `superbot-oci` (one that runs on this machine), but only if the bundle was checked against its verified signature or a `--sha256` the operator gave. A `.sha256` file beside the bundle doesn't count, since whoever could swap the bundle could swap it too, and running the bundled tool would then run their code. Then it checks the digest it reports (the signed index with several bundles, the bundle's image with one), and prints Compose's digest pins as before. **skopeo is no longer needed to push.** A bundle without signatures (unsigned, or from before this change) still pushes, with a warning that `cosign verify` won't find any.
- The bundle `format` stays 1. Older scripts ignore `signatures/` and `images/<name>.index`.

Verifying in the mirror is cosign's own command, against our identity, with `--trusted-root` offline, as the installer already does for the bundle itself. The guide shows it.

### Tests

- `cargo test --bin superbot-oci` runs both commands against an in-process registry. It has a published image shaped like the `docker` workflow's: a two-arch index with attestation manifests, signatures on all five, provenance with its own signature, and a `.sig` tag. The registry runs with and without the referrers API, behind a token login, and in a mode where it changes what a tag returns. The tests check:
  - fetch takes one arch's graph and not the other's, and refuses tampered blobs and manifests, an image the index doesn't list, and a single image given as an index;
  - two units put up the unchanged index with every signature listed, through the API or fallback tags (keeping what a fallback tag held), and fetching again from the mirror gets the same graph;
  - one unit tags its image with its signatures;
  - the same arch twice, different indexes, an unsigned unit and a missing arch are refused with nothing written;
  - a changed tag is caught, and logins come from the auth file;
  - referrers listed one to a page are all fetched, and a page on another host is refused; an oversized manifest is refused;
  - uploads on another host get no login, and an HTTPS registry can't send the client to HTTP;
  - `--check` names the tag's digest without writing, and refuses what `push` refuses;
  - cosign tags keep every signature from every bundle and the mirror, whatever order the bundles come in;
  - `registries.conf` (most specific registry first, later files win) and auth file parsing.
- `deploy/test-offline.sh` adds a stand-in for `superbot-oci` (only in the bin folder, so `push` finds it in the bundle). It checks the signatures layout and recorded index in a bundle, `--image-key`, that `load` still loads only images, and multi-bundle push: the index pin, refusals of two releases, one arch twice, mismatched `--sha256`, different images and an unsigned arch, each before anything is pushed. With two images, if `superbot-oci` refuses the second, the first isn't pushed. A bundle with images and no `superbot-oci` isn't built.
- `offline.yml`'s `install-offline` job builds a two-arch image with SBOM and provenance in a local registry. It signs it `--recursive` and attests it with a throwaway key and no transparency log, so nothing about it leaves the runner. It then bundles the image for x86_64 and aarch64 with `--image-key`, and `docker load`s one with no network. Inside the network namespace with no network, it runs a registry (the binary from `registry:2`), pushes both bundles, and checks that the tag names the signed index and that both attestation manifests are there. `cosign verify` must pass on the tag and each manifest, and `cosign verify-attestation` on the provenance. We ran the same script against Zot, which has the referrers API, while developing this.
- `server/tests/offline_release.rs` checks that wiring, and that both jobs build `superbot-oci`.

## Consequences

- An air-gapped site's registry holds our images as we signed them: the multi-arch index, both arches, the SBOM and provenance attestations and every signature. `cosign verify`, `cosign verify-attestation` and registry or cluster signature policies work against it with no internet, given Sigstore's trusted root.
- A mixed-arch site uses one path: `docker pull` picks each host's arch from the index.
- Making a bundle with images needs `superbot-oci` (`cargo build --release --bin superbot-oci`; release bundles carry it). Pushing needs only `superbot-oci`, from the bundle.
- `superbot-oci` is a second, small OCI client to maintain. It does only what bundles need, and its tests pin the registry behaviours it relies on.
- What a release bundle carries is only as good as what the `docker` workflow published. The CI test uses local registries, so the first tagged release's bundles are still to be checked end to end against ghcr.io; that is what remains for #59.
