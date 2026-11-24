# Air-gapped installs

SuperBot runs on a server with no internet access. You make (or download) an **offline bundle** on a connected machine, check it, carry it in, and install or upgrade from it with `install.sh --offline`. Nothing on the server then calls GitHub, a package registry, Let's Encrypt or CG-Labs. The license is checked offline too. The design is in [ADR 0128](../adr/0128-air-gapped-self-host.md), release bundles and registry mirrors in [ADR 0140](../adr/0140-release-bundles-and-registry-mirrors.md), signatures and multi-arch indexes in mirrors in [ADR 0147](../adr/0147-signatures-and-multi-arch-indexes-in-mirrors.md), how every release's bundles are checked end to end in [ADR 0172](../adr/0172-release-bundles-checked-end-to-end.md), harness installs on users' machines from your own mirrors in [ADR 0186](../adr/0186-harness-installs-from-internal-mirrors.md), Hermes Agent from a Hermes bundle in [ADR 0200](../adr/0200-hermes-agent-bundle-for-air-gapped-installs.md), and Hermes Agent on users' machines from that bundle in [ADR 0210](../adr/0210-hermes-agent-on-air-gapped-machines.md).

## What a bundle holds

`superbot-offline-<version>-<arch>.tar.gz` (`x86_64` or `aarch64`), with `<bundle>.sha256` beside it, and `<bundle>.sigstore.json` when it is a signed release bundle:

| Path | What |
|------|------|
| `bin/` | `botd`, `botctl`, `superbot-machine`, `superbot-run`, built for release; with images, `superbot-oci` too, which `push` uses (the installer doesn't) |
| `client/` | The Expo web client, built for `/app/` |
| `site/` | The landing page |
| `deploy/` | `install.sh`, `offline-bundle.sh`, the systemd units and the backup, restore and per-user account scripts |
| `docker/` | The Compose file, its Caddyfile, `.env.example` and `init.sh` |
| `env.example` | botd's `.env` template |
| `images/` | Optional: each image for the bundle's arch as an OCI archive (`<name>.tar`, which `docker load` also reads), with the digest it has in its registry, its reference and that digest, what `cosign verify` printed when it was bundled (`<name>.cosign.json`: certificate and transparency log entry), its SBOM (`<name>.sbom.spdx.json`), and for a signed image the digest of the multi-arch index that was signed (`<name>.index`) |
| `signatures/` | With signed images: each one's signatures and attestations as an OCI layout (`<name>.tar`): the cosign signatures on the multi-arch index, this arch's image and its attestation manifest (BuildKit's SBOM and provenance), and the build provenance on the index |
| `MANIFEST` | Format, version, arch, commit, date, images and their format (`image_format=oci`) |
| `SHA256SUMS` | The SHA-256 of every other file |

The installer refuses a bundle unless every file in it is listed in `SHA256SUMS` with the right hash and nothing else is there, and it holds only plain files and folders under one `superbot-offline-*` folder (no links, devices, absolute paths or `..`).

## Before you start

The bundle carries SuperBot, not the operating system. Install these on the server first, from your own package mirror (Ubuntu 22.04 or 24.04; release bundles are built on 22.04, so their binaries run on both):

- Always: `sudo`, `openssl`, `sqlite3`, `tar`, `coreutils`, `systemd`.
- Per-user accounts (on by default): `acl` (for `setfacl`).
- With `--domain`: `caddy` (Caddy's own apt repository, or your mirror of it).
- Recommended: `age` (encrypted backups), `bubblewrap` and `socat` (harness sandboxes).
- With `--ufw`: `ufw`.

The installer lists anything missing and stops before it changes anything.

**Harness CLIs** (Claude Code, Codex, Pi) are not in the bundle for the bash install: install them from your npm mirror, system-wide, as in [deploy/README.md](../../deploy/README.md#one-unix-account-per-user). **Hermes Agent** comes from its own [Hermes bundle](#hermes-agent): `--with-hermes` with `--offline` needs `--hermes-bundle`. Users' own machines install their harness CLIs from your mirrors instead ([below](#harness-clis-on-users-machines)). The published image already has Claude Code, Codex and Pi and the screens, so [Docker Compose](#docker-compose) is the simpler path when you need them. It doesn't have Hermes Agent: for Hermes with Compose, build your own image on the connected side (`docker build --build-arg HARNESSES="claude codex pi hermes" -t superbot-hermes:<version> .`) and bundle it with `--image superbot=superbot-hermes:<version> --allow-unsigned` (it is your image, so there is no release signature to check). After loading it, set `SUPERBOT_IMAGE=superbot-hermes:<version>` in `.env` as well as `SUPERBOT_VERSION`, so Compose runs your image instead of the published one.

## Getting a bundle

**A release bundle.** Every release on GitHub has one per arch, attached to it: once the `docker` workflow has published and signed a `v<version>` tag's images, the `offline` workflow builds the bundles from that tag's commit, with those images, signs each with cosign under the workflow's GitHub identity, and attaches the bundle, its `.sha256` and its `.sigstore.json` to the release. (A maintainer can also run it by hand for a release.)

**Your own**, from a checkout of a release tag, on a machine with the same arch as the server:

```sh
cargo build --release --bin botd --bin botctl --bin superbot-machine --bin superbot-run --bin superbot-oci
(cd apps/client && npm ci && SUPERBOT_WEB_BASE_URL=/app npx expo export --platform web --output-dir dist-app)
deploy/offline-bundle.sh build --out dist \
  --image superbot=ghcr.io/cg-labs/superbot:0.1.0 \
  --image caddy=ghcr.io/cg-labs/superbot-caddy:0.1.0
```

`--image` is optional (leave it out for the bash install alone); with it you also need `skopeo`, `jq`, `docker` (with buildx, for the SBOM) and `cosign`. A reference must have a tag (`HOST/PATH:TAG`). The cosign signature on what the tag names is checked against the `docker` workflow at that version's tag (`--image-identity` to change it), then the image for the bundle's arch is copied from the registry as it is, so it keeps the digest that was signed; an image that doesn't verify, or whose digest would change, is not bundled. Its signatures and attestations are copied into the bundle with it, by `superbot-oci`, for [`push`](#registry-mirrors). For an image you signed with your own cosign key, give `--image-key cosign.pub` instead: the signature is checked against that key, with no transparency log. `--allow-unsigned` bundles an image of your own without a check (from your local Docker if it is there, else from its registry), and `MANIFEST` says so. The command prints the bundle's SHA-256: record it somewhere the server's operator can read it without the bundle.

## Verifying a bundle

On the connected machine, check a release bundle's signature, then the bundle:

```sh
cosign verify-blob --bundle superbot-offline-0.1.0-x86_64.tar.gz.sigstore.json \
  --certificate-identity-regexp '^https://github\.com/CG-Labs/superbot/\.github/workflows/offline\.yml@refs/(heads/main|tags/v[0-9A-Za-z.+-]+)$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  superbot-offline-0.1.0-x86_64.tar.gz
deploy/offline-bundle.sh verify superbot-offline-0.1.0-x86_64.tar.gz
```

Accept no other identity: a signature from a fork or another workflow is not ours. Carry in the bundle and its `.sha256` (and `.sigstore.json`) on your approved media. On the server, the installer checks it again before it reads anything inside:

- **Its SHA-256**, against `--bundle-sha256 <hex>` (the value you recorded, which is the real check) or else the `.sha256` beside it (which travelled with the bundle, so it only catches damage).
- **Its signature**, if `.sigstore.json` is beside it and `cosign` is installed. Offline, cosign needs Sigstore's trusted root: run `cosign initialize` on a connected machine, copy `~/.sigstore/root/tuf-repo-cdn.sigstore.dev/targets/trusted_root.json` in separately from the bundle, and point `SIGSTORE_TRUSTED_ROOT` at it. A trusted root that came with the bundle is never used.

With neither a SHA-256 nor a verified signature, the installer stops.

## Checking a release end to end

Every release's bundles are checked the way you'll use them, by the [`offline-release-check`](../../.github/workflows/offline-release-check.yml) workflow ([ADR 0172](../adr/0172-release-bundles-checked-end-to-end.md)). It runs once the bundles are attached, again every week on the latest release, and by hand for any release. It checks the files attached to the release, not a rebuild:

- **Connected:**
  - each bundle's signature and SHA-256;
  - that each bundle was built from the tag's commit, with binaries for its arch that run on Ubuntu 22.04;
  - that its images are exactly what ghcr.io's tags name now, signed by the `docker` workflow. ghcr.io is read with no login, as your machine would.
- **With no network**, against Sigstore's trusted root fetched as [above](#verifying-a-bundle):
  - the bundles verify;
  - both go to a registry mirror as the signed multi-arch index, and `cosign verify` and `verify-attestation` pass there;
  - botd installs from the x86_64 bundle, and its images load.

A green run on the release's tag means all of that held on that day. The run's summary lists each check. If a release's latest run is red, don't install it: use the previous release and tell your CG-Labs contact.

You can run the same check yourself, with the same script (from a checkout of `main`), on the connected machine and then inside your network:

```sh
deploy/offline-release-check.sh online ./release --version 0.1.0 --commit <the tag's commit> \
  --image superbot=ghcr.io/cg-labs/superbot:0.1.0 --image caddy=ghcr.io/cg-labs/superbot-caddy:0.1.0
# carry ./release (now with release-check.expected) and trusted_root.json in, then:
deploy/offline-release-check.sh offline ./release --mirror registry.corp.example/superbot-check --trusted-root trusted_root.json
```

`./release` holds both arches' bundles with their `.sha256` and `.sigstore.json`, as attached to the release. `online` writes `release-check.expected`: each bundle's SHA-256 and each image's signed digest, the record to check against inside. `offline` refuses to run where `github.com` answers. It pushes to the mirror path you give, so use a scratch path, not the one Compose pulls from. It needs `cosign`, `skopeo`, `jq` and `curl`.

## Installing

Extract the installer from the bundle (or use the one from the same release tag), then:

```sh
sudo bash install.sh --offline superbot-offline-0.1.0-x86_64.tar.gz \
  --bundle-sha256 <recorded sha-256> \
  --domain bots.corp.example --tls-cert /root/bots.pem --tls-key /root/bots.key \
  --license-file /root/superbot.license --tz Europe/London
```

Everything else works as in [deploy/README.md](../../deploy/README.md) (`--isolation`, backups, `--database-encryption`, ...), except that nothing is built or downloaded: the binaries, web client, landing page and templates come from the bundle, root-owned, and the service user's `~/superbot` holds only `.env`, `data/` and `workspace/`. Without `--domain`, botd listens on `127.0.0.1:3000` only, as online.

### TLS certificates

There is no Let's Encrypt without a network, so `--domain` needs `--tls-cert` (PEM, the full chain) and `--tls-key` (PEM, no passphrase), usually from your internal CA. The installer checks that they are a pair, valid now and for `--domain` (it warns within 30 days of the end), copies them to `/etc/caddy/superbot-tls/` (the key readable by root and Caddy only), and writes a Caddyfile with `auto_https disable_certs` and `ocsp_stapling off`, so Caddy never contacts a CA. To renew, re-run the installer with the new files (an `--upgrade` with the same bundle is fine).

Browsers and the mobile apps must trust your CA. `--tls-cert` and `--tls-key` also work without `--offline`, for a connected server with its own certificate; without them, the online installer gets one from Let's Encrypt as before.

## Upgrading

```sh
sudo bash install.sh --offline superbot-offline-0.2.0-x86_64.tar.gz --upgrade \
  --bundle-sha256 <recorded sha-256> --domain bots.corp.example --tls-cert /root/bots.pem --tls-key /root/bots.key
```

The same checks run, then the binaries, client, site and templates are replaced and botd restarts; `.env`, the database, the master key, the license and per-user accounts stay. Back up first (`botctl backups`, [backup-restore.md](backup-restore.md)) and read the release's notes in the [changelog](../../CHANGELOG.md). The installed version is recorded in `/usr/local/share/superbot/offline-release`; a bundle **older** than it is refused, because a database a newer botd changed may not open with an older one. To go back, restore a backup made on the older version.

## Hermes Agent

Hermes Agent has no npm package, and its own installer downloads from GitHub, PyPI and more. So it comes in a bundle of its own, `superbot-hermes-<tag>-<arch>.tar.gz`, with `.sha256` and, on a release, `.sigstore.json` beside it. Every release has one per arch, attached to it and signed like the main bundle. It holds Hermes Agent at the commit that release pins, as its installer leaves it in `/opt/hermes`: the checkout, its Python, packages and Node.js tools. It is about 1 GB, and 2.7 GB unpacked. It is the same from release to release until the pin moves, so you only carry a new one in when the installer asks for it.

**Your own**, from a checkout of the same release tag, on a connected Ubuntu machine with the server's arch (as root: it installs into a private mount namespace, so the machine's own `/opt` is untouched; it needs `curl`, `git` and `unshare`):

```sh
sudo deploy/offline-bundle.sh hermes --out dist
```

It runs Hermes's installer for the pinned commit, after checking its SHA-256. It then checks that Hermes runs with no network and packs it. Verify a Hermes bundle as any other, with `cosign verify-blob` (same identity) and `deploy/offline-bundle.sh verify`, and record its SHA-256.

**Install or upgrade** with the main bundle (install `libatomic1` from your mirror first; it needs about 4 GB free under `/opt` while it runs, plus 2.7 GB when it replaces an earlier Hermes):

```sh
sudo bash install.sh --offline superbot-offline-0.2.0-x86_64.tar.gz --bundle-sha256 <recorded sha-256> \
  --with-hermes --hermes-bundle superbot-hermes-v0.23.3-x86_64.tar.gz --hermes-bundle-sha256 <its recorded sha-256> \
  --domain bots.corp.example --tls-cert /root/bots.pem --tls-key /root/bots.key
```

(add `--upgrade` on a server that is already installed). Before anything changes, the installer checks:

- the Hermes bundle's SHA-256 or signature, as for the main bundle;
- its files against `SHA256SUMS`;
- that its `MANIFEST` is for this arch, for `/opt/hermes`, and for the exact commit this release pins;
- that its tree holds only files, folders and links that stay inside `/opt/hermes`, none setuid.

Then it stops botd, swaps the tree into `/opt/hermes` (root-owned, linked from `/usr/local/bin/hermes`) and checks that another account can run it. If anything fails, it puts the previous `/opt/hermes` back. Hermes always goes in `/opt/hermes` this way, with or without per-user accounts. Bots' own Hermes data is in their folders, not there, so replacing it loses nothing. If `/opt/hermes` already holds the pinned commit, it says so and leaves it.

An `--upgrade` without `--with-hermes` keeps the Hermes Agent you have. When the new release pins another commit, the installer says so: re-run with `--with-hermes --hermes-bundle` and that release's Hermes bundle.

Users' own machines get Hermes Agent from the same bundle, through botd ([below](#hermes-agent-on-users-machines)).

## Docker Compose

A bundle made with `--image` carries the images. On the server (Docker, its Compose plugin and optionally cosign installed from your mirror):

```sh
deploy/offline-bundle.sh load superbot-offline-0.1.0-x86_64.tar.gz --sha256 <recorded sha-256>
```

It checks the bundle as the installer does and runs `docker load` for each image, with no registry. Then use the bundle's `docker/` folder as [deploy/docker](../../deploy/README.md#docker-compose-supported): `./init.sh`, and `SUPERBOT_VERSION=0.1.0` in `.env` so Compose uses the loaded tags (it never pulls an image it has). Each image's `images/<name>.cosign.json` and `images/<name>.sbom.spdx.json` are the signature check and SBOM from when it was bundled, for your records and scanners. With several hosts, or to keep images in one place, push them to your own registry instead ([below](#registry-mirrors)). For your own certificate, add `tls /etc/caddy/tls/cert.pem /etc/caddy/tls/key.pem` under the site line of a copy of the Caddyfile, and mount it and the certificate folder with a `docker-compose.override.yml`:

```yaml
services:
  caddy:
    volumes:
      - ./Caddyfile.offline:/etc/caddy/Caddyfile:ro
      - ./tls:/etc/caddy/tls:ro
```

## Registry mirrors

If your network has its own container registry (Harbor, Artifactory, Nexus, Zot, `registry:2`, ...), push a bundle's images into it, from any machine that can reach it. Give both arches' bundles of a release to put up the multi-arch images:

```sh
deploy/offline-bundle.sh push superbot-offline-0.1.0-x86_64.tar.gz superbot-offline-0.1.0-aarch64.tar.gz \
  --sha256 <x86_64 sha-256> --sha256 <aarch64 sha-256> --registry registry.corp.example/superbot
```

It checks each bundle as the installer does (one `--sha256` per bundle, in the same order), and that they are one release with one bundle per arch. Then, with the bundle's `superbot-oci`, it copies each image to `<registry>/<name>:<tag>` (here `registry.corp.example/superbot/superbot:0.1.0` and `.../superbot-caddy:0.1.0`) exactly as it is in the bundles: both arches' images, the **signed multi-arch index** they came from, unchanged, and every signature and attestation the bundles carry. The tag goes up last and is read back, and it stops unless the registry now has the **same digest** that was signed: the index's, so `docker pull` on either arch gets its own image. With one bundle, the tag names that arch's image alone, with its signatures and its SBOM and provenance manifests. Everything is checked before anything is pushed: bundles of two releases, the same arch twice, an unsigned image or a bundle made before ADR 0147 in a multi-arch push, and two images that would take the same tag are refused. It prints the settings for Compose's `.env`, pinned by digest:

```sh
SUPERBOT_IMAGE=registry.corp.example/superbot/superbot@sha256:...
SUPERBOT_CADDY_IMAGE=registry.corp.example/superbot/superbot-caddy@sha256:...
```

Put them in `.env` (with `SUPERBOT_VERSION` too) and Compose pulls from your registry; a digest pin means a changed image in the registry can't be run in its place.

### Checking signatures in the mirror

The mirror has the release's cosign signatures and provenance, so you (or your registry's admission policy) can check an image there, with no internet. cosign needs Sigstore's trusted root offline, as for [the bundle](#verifying-a-bundle): `trusted_root.json`, copied in separately.

```sh
cosign verify registry.corp.example/superbot/superbot:0.1.0 --trusted-root trusted_root.json \
  --certificate-identity https://github.com/CG-Labs/superbot/.github/workflows/docker.yml@refs/tags/v0.1.0 \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
cosign verify-attestation --type slsaprovenance1 registry.corp.example/superbot/superbot:0.1.0 --trusted-root trusted_root.json \
  --certificate-identity https://github.com/CG-Labs/superbot/.github/workflows/docker.yml@refs/tags/v0.1.0 \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

The first checks the index's signature; each arch's image (`...@sha256:<its digest>`) is signed too. The second checks the build provenance the `docker` workflow attached. `docker buildx imagetools inspect registry.corp.example/superbot/superbot:0.1.0 --format '{{ json (index .SBOM "linux/amd64").SPDX }}'` reads each arch's SBOM from the mirror. Accept no other identity, as for the published images ([deploy/README.md](../../deploy/README.md#verifying-the-images)).

### Notes

- **Registries:** with the [OCI 1.1 referrers API](https://github.com/opencontainers/distribution-spec/blob/main/spec.md#listing-referrers) (Zot, Harbor 2.8 and later) the signatures are listed there; otherwise (`registry:2`) under the `sha256-<digest>` tags cosign also reads, keeping what those tags already list. The registry must take OCI image indexes and artifact manifests, as current ones do.
- **The push tool** is `superbot-oci`, in the bundle's `bin/` for its arch: push from a machine of a bundle's arch, or set `SUPERBOT_OCI` to one built for yours (`cargo build --release --bin superbot-oci`). skopeo and docker aren't needed. `push` runs the bundle's copy only when the bundle was checked against its signature (with cosign on that machine) or a `--sha256` you gave from where it was published. A `.sha256` file beside the bundle isn't enough, since whoever could change the bundle could change it too. Without either, give `--sha256` or set `SUPERBOT_OCI`.
- **Logins and certificates** are skopeo's and Docker's: `skopeo login registry.corp.example` or `docker login` (their auth files and credential helpers), your internal CA in `/etc/containers/certs.d/registry.corp.example/ca.crt` (or `/etc/docker/certs.d/...`, or the system's trust store), and a client certificate the registry asks for as `client.cert` with its `client.key` in the same folder. A registry without TLS, or with a certificate that can't be checked, for a lab only, is marked `insecure = true` in `/etc/containers/registries.conf.d/`: as with skopeo, its certificate isn't checked, and plain HTTP is used only if it doesn't answer HTTPS. That is for the registry's own address: a token service or storage on another host it sends you to must have a certificate your system or the registry's `certs.d` CA trusts. As with skopeo, the most specific registry entry decides, and a later file's entry for the same registry replaces an earlier one. Your login and client certificate go only to the registry itself, never to an upload address or a redirect on another host, and never over plain HTTP from a registry on HTTPS.
- **Doing it yourself:** the images are OCI archives and the signatures OCI layouts, so after extracting a bundle any tool that copies OCI layouts with their referrers can push them; then check the digests yourself.
- Bundles made before ADR 0147 have no signatures or `superbot-oci` (set `SUPERBOT_OCI`): their images go up alone, one arch per path (`--registry registry.corp.example/superbot/arm64`), and `cosign verify` against the mirror finds nothing; `images/<name>.cosign.json` is the record of the check. Bundles made before ADR 0140 (with `docker save` images) can't be pushed with their digests: `push` refuses them. Use `load` for those, or a newer bundle.

## Harness CLIs on users' machines

With a control plane (`MACHINE_CONTROL_URL`), each user's machine installs the harness CLIs in `MACHINE_HARNESSES` by itself ([ADR 0039](../adr/0039-machine-harnesses-and-agent-upgrades.md)): Node.js from nodejs.org, then Claude Code, Codex and Pi from npm's registry. Neither is reachable here, so point machines at your own copies:

```sh
MACHINE_NODE_MIRROR=https://mirror.corp.example/nodejs/dist
MACHINE_NPM_REGISTRY=https://mirror.corp.example/api/npm/npm-remote/
MACHINE_MIRROR_CA_FILE=/etc/superbot/mirror-ca.pem
```

- **`MACHINE_NODE_MIRROR`** is laid out as `https://nodejs.org/dist`: machines fetch `<mirror>/v<version>/node-v<version>-linux-x64.tar.xz` (or `-arm64`). An Artifactory or Nexus generic remote of `https://nodejs.org/dist`, or a folder of those files on any web server inside the network, does.
- **`MACHINE_NPM_REGISTRY`** is an npm registry: an Artifactory, Nexus or Verdaccio remote of `https://registry.npmjs.org`, or one you filled on the connected side. Machines fetch the harnesses and everything they depend on from it, and nothing from npm's registry.
- **`MACHINE_MIRROR_CA_FILE`** (optional) is the CA, PEM, one or more certificates, that the mirrors' certificates are signed by, if machines don't already trust it. Machines trust it besides their own roots, for these downloads only; botd checks it at start.
- Both must be `https://`, with no login in the URL. The Node.js mirror must serve its files without one; for a registry that wants one, see [below](#registries-that-need-a-login). All three need `MACHINE_CONTROL_URL`, and botd won't start with a value it can't use.
- **Incus containers** never reach private addresses ([guide](incus-containers.md)), so open each mirror's address and port, exactly, with `INCUS_EGRESS_ALLOW=10.0.0.20:443` (comma-separated, IPv6 as `[fd00::20]:443`). Only TCP to those ports opens. `botctl machine mirror` fails, naming the address to add, while one is still closed.
- **Linode machines'** outbound rules ([ADR 0179](../adr/0179-outbound-rules-at-the-provider.md)) drop private addresses too, with no per-address exception; `botctl machine mirror` says so. Put the mirrors on addresses those rules don't hold, or set `MACHINE_FIREWALL_EGRESS=off`.

**The pins don't change.** Node.js is still checked against the SHA-256 botd pins for its version, and each npm harness's package against its pinned SHA-512, wherever it came from, so a mirror can serve them but can't change them: a file that differs fails that harness's install, with the reason in `botctl machine agent <user>`. The packages a harness depends on are checked against the SHA-512 your registry lists for them, as they would be against npm's. To change what a machine installs, change `MACHINE_HARNESSES` (`name@version=<checksum>`), never the mirror.

**Check the mirrors before machines need them:**

```sh
botctl machine mirror
```

botd fetches every file the harness plan names, from where machines would and trusting what they would: each arch's Node.js tarball, and each npm harness's package document and tarball. It checks each against its pin and answers with an entry per file (`ok`, and an `error` saying what is missing or different), and `"ok": true` only when every one passed. `blocked` lists any mirror address the machines' firewall would drop, which botd, outside it, still reaches, including where the mirror redirects (`redirects`) and any Incus host's address. Nothing is installed or changed. botd must reach the mirrors as machines do. With a remote that fetches from upstream on first use, this fills it too. Run it after every upgrade, since a release can move a pin, then `botctl machine harnesses <user>` sends a machine the plan now.

**Agents:** a machine's agent needs this release or later to use the npm registry or the CA, since older ones would refuse the plan or fetch from npm's registry: botd doesn't send them a plan with mirrors in it, and `botctl machine harnesses <user>` says to upgrade first. Agents upgrade from botd itself, over the control plane, so `botctl machine upgrade <user>` (or `MACHINE_AGENT_UPGRADES=auto`) works with no internet. A mirror for Node.js alone needs no upgrade.

### Registries that need a login

If your registry asks for a login even to read (Artifactory, Nexus, GitLab, Verdaccio with `htpasswd`), give botd one, read-only, for machines to use ([ADR 0219](../adr/0219-npm-registry-logins-for-air-gapped-machines.md)). Either a token:

```sh
MACHINE_NPM_TOKEN_FILE=/run/secrets/npm-token
```

or a username and password:

```sh
MACHINE_NPM_USERNAME=svc-superbot
MACHINE_NPM_PASSWORD_FILE=/run/secrets/npm-password
```

- `MACHINE_NPM_TOKEN` is sent as `Bearer` (npm's `_authToken`); the username and password as `Basic` (npm's `_auth`). Use whichever your registry takes from npm: an Artifactory identity token or API key, a Nexus user token, a GitLab deploy token, a Verdaccio user.
- The token and password are secrets: set them as above, as `MACHINE_NPM_TOKEN` and `MACHINE_NPM_PASSWORD`, or in an [external store](vault.md) (`<prefix>/server/MACHINE_NPM_TOKEN`). botd keeps them from every Bot run and redacts them from its logs.
- They need `MACHINE_NPM_REGISTRY` and `MACHINE_CONTROL_URL`. botd won't start with both kinds set, half of the username and password, or a token with characters registry tokens don't have (only letters, digits and `- . _ ~ + / = :`).
- The plan only says a login is needed, never what it is. For each npm install, a machine's agent fetches it from botd over the machine port's mutual TLS, writes it in a root-only folder in its state folder (`/var/lib/superbot-machine/npm-login`; never in the tools, since Bot users read those), points npm at that file, and removes it when the install ends or the agent restarts. npm sends it to your registry and to tarballs under it, and nowhere else. Its errors never show it.
- Each fetch is in the audit log as `machine.npm_login_sent`, with the user, the registry and the login's kind, never its value.
- `botctl machine mirror` signs in as machines will (`"npmLogin": "token"` or `"basic"`), only to URLs under the registry. A 401 or 403 says to check the login; a 401 with none set says your registry wants one.
- To rotate it, change the secret and restart botd. Plans don't change, so nothing reinstalls.
- Agents need this release or later. botd doesn't send older ones the plan, and `botctl machine harnesses <user>` says to upgrade first (`botctl machine upgrade <user>`).

The Node.js mirror can't take a login: serve its tarballs to machines without one.

### Hermes Agent on users' machines

Hermes Agent has no npm package, and its installer reaches GitHub and PyPI, which no mirror setting covers. Machines get it from botd instead, from the [Hermes bundle](#hermes-agent) you carry in for the server ([ADR 0210](../adr/0210-hermes-agent-on-air-gapped-machines.md)). Put the bundle for each of your machines' arches on botd's server, with its `.sha256` beside it, and name them in `.env`:

```sh
MACHINE_HERMES_BUNDLE=/var/lib/superbot/superbot-hermes-v0.23.3-x86_64.tar.gz,/var/lib/superbot/superbot-hermes-v0.23.3-aarch64.tar.gz
```

- Each is an absolute path, readable by botd's user, at most one per arch. Instead of the `.sha256` file, give the SHA-256 you recorded: `<path>=<sha-256>`. It needs `MACHINE_CONTROL_URL`.
- At start, botd checks each bundle in full as `install.sh` does: its SHA-256, its files against `SHA256SUMS`, its `MANIFEST` (for `/opt/hermes`), and every entry of its tree. Each must hold the Hermes commit machines' plan pins, the same one the server's bundle holds. botd won't start otherwise, and names the file.
- botd serves them to enrolled machines only, over the machine port's mutual TLS. Machines reach that port anyway, so no firewall changes.
- Each machine's agent downloads its arch's bundle and checks its SHA-256. It unpacks and checks the tree in a root-only folder beside `/opt/hermes`, moves it in, and runs `hermes-share.sh` there. If anything fails, it puts the previous `/opt/hermes` back. A machine needs about 1 GB free for the download and 2.7 GB under `/opt`, twice that while it replaces an earlier one.
- `botctl machine mirror` reads each bundle again and checks it against its SHA-256. After you replace a bundle file (for a release that moves the Hermes pin), restart botd.
- Agents need this release or later. botd doesn't send older ones the plan, and `botctl machine harnesses <user>` says to upgrade first (`botctl machine upgrade <user>`).

Without `MACHINE_HERMES_BUNDLE`, machines run Hermes's installer, which needs the internet. Then leave `hermes` out of `MACHINE_HARNESSES` and set it explicitly: unset, it defaults to the managed tiers' harness, Hermes on the shipped plans. botd's startup log and `botctl machine mirror` name any harness still fetched from the internet.

## Model providers

Bots need a model provider, and in an air-gapped network it must be one inside it: a self-hosted model server with an OpenAI-compatible API (vLLM, Ollama, TGI, ...), or a provider's private endpoint reachable from your network. Model provider URLs must be `https://`, or `http://` on the server itself ([ADR 0097](../adr/0097-model-providers-over-https.md)):

- **Hermes Agent:** `SUPERBOT_HERMES_PROVIDER` and `SUPERBOT_HERMES_BASE_URL` in `.env`, or per-tier `providers` with a `baseUrl` in the tiers file ([ADR 0077](../adr/0077-two-providers-through-tier-routing.md)). Save the key with `botctl secret set`.
- **Claude Code, Codex, Pi:** their own settings, e.g. `ANTHROPIC_BASE_URL` in `.env` for an Anthropic-compatible gateway, a Bot's `~/.codex/config.toml`, or Pi's `models.json`.

Logins that go through a vendor's website (`claude login`, `codex login`) don't work offline: use API keys for your internal endpoint.

## What needs the internet, and what to do instead

| Feature | Offline |
|---------|---------|
| License | Works: checked against keys built into botd, no phone-home ([below](#license-and-seats)) |
| Sign-in | Password, TOTP, and SSO against an identity provider inside your network (ADFS, Keycloak or another OIDC/SAML IdP); cloud IdPs (Entra, Google, GitHub, Apple) only if the server can reach them |
| Harness CLIs on this server | Claude Code, Codex and Pi download from the internet: install from your npm mirror instead, or use the published image |
| `--with-hermes` | Downloads Hermes Agent: with `--offline`, give `--hermes-bundle` ([Hermes Agent](#hermes-agent)) |
| Harness CLIs on users' machines | Claude Code, Codex and Pi from your Node.js and npm mirrors ([above](#harness-clis-on-users-machines)); Hermes Agent from botd's Hermes bundle (`MACHINE_HERMES_BUNDLE`, [above](#hermes-agent-on-users-machines)) |
| Billing (Stripe), push notifications (`PUSH_PROVIDER=expo`), Turnstile on the sign-up form | Need the internet: leave them off (the default) |
| Managed machines on Linode | Need the internet: use Incus hosts inside your network, or none |
| Off-host backups | An S3-compatible store inside your network (MinIO, Ceph) |
| Error reporting and traces | Off by default; point them at a Sentry-compatible tracker or OTLP collector inside your network |
| Email | Your own SMTP relay |

## License and seats

The license key ([ADR 0038](../adr/0038-self-host-license-key.md)) is a signed token checked against public keys compiled into botd, so it verifies with no network, and botd never reports it, or anything else, to CG-Labs. A test guards that the license code opens no connection. Seats are counted in the server's own database: the license names how many active people it covers, and botd refuses to add or re-enable people beyond that, from the console, SSO, SCIM and sign-up approvals alike. Nobody is signed out when a license ends; it keeps its seats for 14 days, then the server is unlicensed and Bots stop running until a new key is installed (console, `botctl license install`, or `--license-file`). Renewal is a new key file from CG-Labs, carried in like the bundle. Admins are warned 30 days before the end, so plan the transfer ahead.

botd's clock decides when a license starts and ends: keep it right with an internal NTP server.

## Updates and CVEs

- Security fixes ship as new releases ([SECURITY.md](../../SECURITY.md)); each release's notes in the [changelog](../../CHANGELOG.md) say what changed. Watch the releases from a connected machine (or ask your CG-Labs contact for notice), then make or download the bundle, verify it, and upgrade as above.
- Images are rebuilt weekly with Debian's security fixes and scanned on every build ([ADR 0101](../adr/0101-image-scanning-and-signing.md)); a release bundle carries that release's images, and every release has its bundles. Each image's SBOM is in the bundle, so your own scanner can match new CVEs against it offline.
- Rust and npm dependencies are scanned in CI ([ADR 0092](../adr/0092-dependency-vulnerability-scanning.md)). The host's own packages (Caddy, OpenSSL, the kernel) are yours to update from your mirror.
- For an urgent fix, upgrade to the release that carries it; there are no in-place patches. Keep the previous bundle until the new one has run well, and a backup to restore if it doesn't.
