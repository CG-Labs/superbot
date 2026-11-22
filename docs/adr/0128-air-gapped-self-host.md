# 0128: Air-gapped self-host: offline bundles, `install.sh --offline`, and an offline license

## Status

Accepted (22 Nov 2026). First slice of [#59](https://github.com/CG-Labs/superbot/issues/59) (M5, "Air-gapped self-host"; the roadmap's *Air-gapped: Possible manual → M5 docs + license*). Builds on the installer ([ADR 0006](0006-docker-compose.md) and `deploy/install.sh`), the self-host license key ([ADR 0038](0038-self-host-license-key.md)), image signing ([ADR 0101](0101-image-scanning-and-signing.md)) and model providers over HTTPS ([ADR 0097](0097-model-providers-over-https.md)).

0121 to 0127 are taken by `main`, open PRs or running agents, so this is 0128.

## Context

Some buyers (defence, government, regulated finance) run software only on networks with no internet. Before this, an air-gapped install was "possible, manually": the installer clones GitHub, installs packages from apt and NodeSource, installs Rust with rustup, builds botd and the web client (cargo and npm fetch dependencies), and gets Caddy's certificate from Let's Encrypt. Compose pulls images from GHCR. An operator had to recreate all of that by hand, with nothing to check what they carried in.

The license was the other question: does it phone home, and how are seats enforced without a network?

## Decision

### The license already works offline

Read from the code: `server/src/license/` verifies an Ed25519-signed token against public keys compiled into botd (`TRUSTED`), reads it from the environment or `DATA_DIR/license.key`, and counts seats in the local database inside the same transaction that activates a person. It has no network client, and nothing else in botd reports the license. So **no offline mode is needed**; the test `licensing_never_reaches_the_network` keeps it that way (the license code may not name a network client or URL, and a license verifies with its seats from the key alone). Seat enforcement, grace, and renewal offline are documented in `docs/ops/air-gapped.md`. The license's clock is the server's: an internal NTP server is the operator's job.

### An offline bundle

`deploy/offline-bundle.sh build`, on a connected machine with the server's arch, packs one `superbot-offline-<version>-<arch>.tar.gz`: the four release binaries, the web client built for `/app/`, the landing page, the installer and its templates, the Compose files, botd's `.env.example`, a `MANIFEST` (format 1, version, arch, commit, date, images) and a `SHA256SUMS` of every other file, all owned by 0:0. Beside it, `<bundle>.sha256`.

Images are optional (`--image NAME=REF`). Each is pulled for the bundle's arch, its cosign signature checked against the `docker` workflow's identity at that version's tag, and only then `docker save`d, with what `cosign verify` printed (certificate and Rekor entry) and its SPDX SBOM beside it. An image that doesn't verify isn't bundled; `--allow-unsigned` exists for an operator's own images and is recorded in `MANIFEST`. Signatures are checked when bundling, on the connected side, because checking an image's keyless signature offline would need its registry's signature artifacts and Sigstore's trust root on the server; the bundle's own signature (below) covers the images it carries.

The `offline` workflow's manual run makes the release bundles: per arch, from the release tag, with that release's images, then `cosign sign-blob` keyless under the workflow's GitHub identity (`<bundle>.sigstore.json`), attached to the GitHub release.

### Checking a bundle

The installer (and `offline-bundle.sh verify` and `load`, which source it) checks, in order:

1. **Who made it**, before reading anything inside: its SHA-256 against `--bundle-sha256` (the value the operator recorded from where it was published) or else `<bundle>.sha256`, and its cosign signature if `.sigstore.json` is beside it and cosign is installed. Offline, cosign needs Sigstore's trusted root; the installer uses only the operator's own copy (`SIGSTORE_TRUSTED_ROOT`), never one beside the bundle, which whoever altered the bundle could also replace. With neither a checksum nor a verified signature, it stops.
2. **Its shape**, from the listing alone: one `superbot-offline-*` folder of plain files and folders, with no links, devices, absolute names or `..`.
3. **Its contents**, once unpacked into a fresh root-owned folder with permissions reset: `MANIFEST` format 1, a version, an arch that is this host's; every `SHA256SUMS` line a hash and a plain relative path; every file listed, with the right hash, and nothing unlisted; every binary, template, the client and the site present.

A bundle older than the one recorded in `/usr/local/share/superbot/offline-release` is refused: a database a newer botd migrated may not open with an older one. Going back is a restore from backup.

### `install.sh --offline <bundle>`

A mode of the same installer, so offline and online installs share every step that doesn't touch the network: users, `.env`, the master key, encryption, the license, per-user accounts, units, backups, the summary. With `--offline` it:

- runs no `apt-get`, NodeSource, rustup, git, cargo, npm or curl; it checks the packages it would have installed are there and lists the missing ones before changing anything;
- installs the bundle's binaries root-owned, stages templates from the bundle into the root-owned trusted folder, installs the client and landing page from the bundle through the same root-owned release swap, and gives the service user only `.env.example`, so `~/superbot` holds `.env`, data and workspace and no source;
- refuses `--with-hermes` (it downloads Hermes Agent) and `--source-dir`;
- with `--domain`, requires `--tls-cert` and `--tls-key`: checked as PEM, a matching pair, valid now and for the domain (a warning within 30 days of the end), copied to `/etc/caddy/superbot-tls` (key `0640 root:caddy`), and served with `tls`, `auto_https disable_certs` and `ocsp_stapling off`, so Caddy never contacts a CA;
- records the bundle's `MANIFEST` for the next upgrade's version check.

`--upgrade` with a newer bundle replaces what the bundle carries and restarts botd. `--tls-cert`/`--tls-key` also work online. Without `--offline` and without them, nothing changes: the default online install and `install.sh --upgrade --domain ...` behave exactly as before, and the Caddyfile they write is byte for byte the same.

### Compose

`offline-bundle.sh load <bundle>` checks the bundle the same way and `docker load`s its images; the bundle's `docker/` folder runs them with `SUPERBOT_VERSION` set, so Compose never pulls. An operator certificate for Compose's Caddy is a documented override, not a new file.

### Tests

- `deploy/test-offline.sh` (no root, no network): a bundle builds and verifies; a changed, extra or missing file, a link, a `..` entry, two top folders, a `..` path in `SHA256SUMS`, an unknown format, a bad version and a missing binary or client are refused; a bundle needs a SHA-256 or a signature and a wrong or damaged one is refused; `verify` reads any arch but the installer only its own; downgrades are refused; flags that can't work offline are refused; certificates are checked; the online Caddyfile is unchanged; a dry run of the whole offline install, under an unprivileged network namespace when the host allows one, uses only the bundle.
- `.github/workflows/offline.yml`: on Ubuntu 22.04 and 24.04, builds real bundles from the commit, then, as root inside a network namespace with only loopback (where `curl https://github.com` is checked to fail) that botd and Caddy also join through a systemd drop-in, installs from one with an operator certificate, checks botd, the client and the landing page over HTTPS with that certificate and that Caddy's log shows no CA or OCSP call, upgrades to a newer bundle, refuses the older one again, and `docker load`s a bundled image, all with no network.
- `licensing_never_reaches_the_network` in `server/src/license/mod.rs`.

## Consequences

- An air-gapped install is a documented, tested path: `docs/ops/air-gapped.md` covers getting, verifying, carrying in, installing and upgrading a bundle, certificates, Compose, model providers inside the customer's network, what needs the internet, licensing and seats, and how updates and CVE fixes reach a server that can't fetch them.
- The bundle carries SuperBot, not the OS: Caddy, sqlite3, acl, age, bubblewrap and the harness CLIs come from the operator's own mirrors for the bash install. The published image has the harness CLIs, which makes Compose the easier air-gapped path for them.
- Features that are network services by nature stay unavailable offline unless the customer runs an equivalent inside: Stripe, Expo push, Turnstile, cloud SSO providers, Linode machines, and the console's harness-install buttons.
- Release bundles exist only once a maintainer runs the workflow for a published release; making that part of tagging, and a bundle per release for each arch with images in a registry mirror format (OCI layout) rather than `docker save`, are follow-ups for #59.
- Bundle size is dominated by the images (several GB with them, tens of MB without).
