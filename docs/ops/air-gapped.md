# Air-gapped installs

SuperBot runs on a server with no internet access. You make (or download) an **offline bundle** on a connected machine, check it, carry it in, and install or upgrade from it with `install.sh --offline`. Nothing on the server then calls GitHub, a package registry, Let's Encrypt or CG-Labs. The license is checked offline too. The design is in [ADR 0128](../adr/0128-air-gapped-self-host.md).

## What a bundle holds

`superbot-offline-<version>-<arch>.tar.gz` (`x86_64` or `aarch64`), with `<bundle>.sha256` beside it, and `<bundle>.sigstore.json` when it is a signed release bundle:

| Path | What |
|------|------|
| `bin/` | `botd`, `botctl`, `superbot-machine`, `superbot-run`, built for release |
| `client/` | The Expo web client, built for `/app/` |
| `site/` | The landing page |
| `deploy/` | `install.sh`, `offline-bundle.sh`, the systemd units and the backup, restore and per-user account scripts |
| `docker/` | The Compose file, its Caddyfile, `.env.example` and `init.sh` |
| `env.example` | botd's `.env` template |
| `images/` | Optional: each image as a `docker save` tarball (`<name>.tar`), its reference and digest, what `cosign verify` printed when it was bundled (`<name>.cosign.json`: certificate and transparency log entry) and its SBOM (`<name>.sbom.spdx.json`) |
| `MANIFEST` | Format, version, arch, commit, date, images |
| `SHA256SUMS` | The SHA-256 of every other file |

The installer refuses a bundle unless every file in it is listed in `SHA256SUMS` with the right hash and nothing else is there, and it holds only plain files and folders under one `superbot-offline-*` folder (no links, devices, absolute paths or `..`).

## Before you start

The bundle carries SuperBot, not the operating system. Install these on the server first, from your own package mirror (Ubuntu 22.04 or 24.04):

- Always: `sudo`, `openssl`, `sqlite3`, `tar`, `coreutils`, `systemd`.
- Per-user accounts (on by default): `acl` (for `setfacl`).
- With `--domain`: `caddy` (Caddy's own apt repository, or your mirror of it).
- Recommended: `age` (encrypted backups), `bubblewrap` and `socat` (harness sandboxes).
- With `--ufw`: `ufw`.

The installer lists anything missing and stops before it changes anything.

**Harness CLIs** (Claude Code, Codex, Pi, Hermes Agent) are not in the bundle for the bash install: install them from your npm or Python mirror, system-wide, as in [deploy/README.md](../../deploy/README.md#one-unix-account-per-user). `--with-hermes` downloads Hermes Agent, so it is refused with `--offline`, and the console's *Install* buttons for harness CLIs download too: don't use them. The published image already has the harness CLIs and the screens, so [Docker Compose](#docker-compose) is the simpler path when you need them.

## Getting a bundle

**A release bundle.** The `offline` workflow's manual run makes one per arch for a published version, bundles that version's signed images, signs the bundle with cosign under the workflow's GitHub identity, and attaches the bundle, its `.sha256` and its `.sigstore.json` to the GitHub release.

**Your own**, from a checkout of a release tag, on a machine with the same arch as the server:

```sh
cargo build --release --bin botd --bin botctl --bin superbot-machine --bin superbot-run
(cd apps/client && npm ci && SUPERBOT_WEB_BASE_URL=/app npx expo export --platform web --output-dir dist-app)
deploy/offline-bundle.sh build --out dist \
  --image superbot=ghcr.io/cg-labs/superbot:0.1.0 \
  --image caddy=ghcr.io/cg-labs/superbot-caddy:0.1.0
```

`--image` is optional (leave it out for the bash install alone). Each image is pulled for the bundle's arch and its cosign signature checked against the `docker` workflow at that version's tag (`--image-identity` to change it) before it is saved; an image that doesn't verify is not bundled. `--allow-unsigned` bundles an image of your own without a check, and `MANIFEST` says so. The command prints the bundle's SHA-256: record it somewhere the server's operator can read it without the bundle.

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

## Docker Compose

A bundle made with `--image` carries the images. On the server (Docker, its Compose plugin and optionally cosign installed from your mirror):

```sh
deploy/offline-bundle.sh load superbot-offline-0.1.0-x86_64.tar.gz --sha256 <recorded sha-256>
```

It checks the bundle as the installer does and runs `docker load` for each image, with no registry. Then use the bundle's `docker/` folder as [deploy/docker](../../deploy/README.md#docker-compose-supported): `./init.sh`, and `SUPERBOT_VERSION=0.1.0` in `.env` so Compose uses the loaded tags (it never pulls an image it has). Each image's `images/<name>.cosign.json` and `images/<name>.sbom.spdx.json` are the signature check and SBOM from when it was bundled, for your records and scanners. For your own certificate, add `tls /etc/caddy/tls/cert.pem /etc/caddy/tls/key.pem` under the site line of a copy of the Caddyfile, and mount it and the certificate folder with a `docker-compose.override.yml`:

```yaml
services:
  caddy:
    volumes:
      - ./Caddyfile.offline:/etc/caddy/Caddyfile:ro
      - ./tls:/etc/caddy/tls:ro
```

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
| Harness CLI installs (console buttons), `--with-hermes` | Download from the internet: install from your mirror instead |
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
- Images are rebuilt weekly with Debian's security fixes and scanned on every build ([ADR 0101](../adr/0101-image-scanning-and-signing.md)); a release bundle carries that release's images. Each image's SBOM is in the bundle, so your own scanner can match new CVEs against it offline.
- Rust and npm dependencies are scanned in CI ([ADR 0092](../adr/0092-dependency-vulnerability-scanning.md)). The host's own packages (Caddy, OpenSSL, the kernel) are yours to update from your mirror.
- For an urgent fix, upgrade to the release that carries it; there are no in-place patches. Keep the previous bundle until the new one has run well, and a backup to restore if it doesn't.
