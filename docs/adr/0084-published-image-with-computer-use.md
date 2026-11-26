# 0084: A published image, with the Bots' computer in it

## Status

Accepted (21 Nov 2026). [#39](https://github.com/CG-Labs/superbot/issues/39) (M3). Builds on [ADR 0003](0003-computer.md) (the Bots' computer), [ADR 0006](0006-docker-compose.md) (Docker Compose), [ADR 0045](0045-screens-on-machines.md) (screens on machines) and [ADR 0058](0058-harness-os-user-by-default.md) (per-user accounts by default).

0081 and 0083 are on `main`, and open PR #142 holds 0082, so this is 0084.

## Context

ADR 0006 made Compose a supported install but left two things for later: a published image, and screens in it. Every Compose host built the images itself (a Rust build, the Expo export, about 1.8 GB of npm), so an install or upgrade took many minutes and a few GB of build cache, and nothing in CI shipped what it tested. And `botd` in the container said `Screens: off`: the image had no Xvfb, browser or voxl, and Caddy, in its own container, couldn't reach voxl on botd's loopback anyway.

Constraints: no paid services, and no secret someone has to create; amd64 and arm64 hosts (Graviton, Ampere, Apple silicon); nothing in the image that isn't on a bash install with `install-computer.sh`; and per-user accounts (`ISOLATION=users`) stay the default for new `.env` files.

## Decision

### Registry: GHCR, with the workflow's own token

`.github/workflows/docker.yml` publishes `ghcr.io/cg-labs/superbot` (botd) and `ghcr.io/cg-labs/superbot-caddy` (Caddy with the web client and landing page, which Compose also needs). It logs in with `GITHUB_TOKEN` (`packages: write`), so there is nothing to set up: GHCR is free for public images, the package is linked to this repository by the `org.opencontainers.image.source` label, and a package a workflow creates takes the repository's visibility. If an organization policy makes it private, an org admin flips it to public once in the package's settings.

### Tags

| Event | Tags |
|---|---|
| Push to `main` | `main`, `sha-<7-char commit>` |
| Tag `v1.2.3` | `1.2.3`, `1.2`, `1` (not for `v0.x`), `latest` |
| Tag `v1.2.3-rc.1` | `1.2.3-rc.1` only |
| Weekly (Monday) | `main`, rebuilt without the cache |
| Pull request | none: build and smoke test only |

Compose uses `SUPERBOT_VERSION`, default `main`, since there is no release tag yet; the default moves to `latest` with the first release. `sha-<commit>` pins an exact build.

### Multi-arch on native runners

Each architecture builds on its own runner (`ubuntu-24.04` and `ubuntu-24.04-arm`, free for public repositories), loads the image, and runs the whole Compose smoke test against it. Only then does it push by digest. A last job joins the two digests under the tags with `docker buildx imagetools create`, for both images. QEMU would have made the arm64 Rust, voxl and Expo builds many times slower, and would have tested nothing on arm64.

The GitHub Actions cache keeps layers between runs, so a Debian package layer could otherwise stay the same for months. The weekly run and every version tag build with `no-cache` and `pull`, so Debian's security fixes, above all Chromium's, reach the published images.

### Computer use: the bash install's stack, in the one image

The runtime stage adds what `deploy/install-computer.sh` installs: Xvfb, Openbox, D-Bus (`dbus-x11`), `at-spi2-core`, `x11-utils`, Noto fonts, voxl, agent-browser (and its skills, for `AGENT_BROWSER_SKILLS_DIR`) and agent-desktop. There are two differences:

- **Debian's `chromium`** instead of Chrome for Testing, which has no Linux arm64 build. `AGENT_BROWSER_EXECUTABLE_PATH=/usr/bin/chromium` points agent-browser at it, and Debian's security updates keep it current. agent-browser turns Chrome's sandbox off in a container, as it must: Docker's seccomp profile blocks the user namespaces the sandbox needs. That gives a run nothing more than it has: it already runs commands as that account. (Changed by [ADR 0107](0107-chromium-sandbox-in-the-container.md): the sandbox is on in the container now.)
- **voxl is built in its own stage** (`cargo install voxl-server --no-default-features`, pinned to `install-computer.sh`'s 0.3.5) and copied in, so the runtime gets only its four libraries (x264, libyuv, opus, libjpeg), not a compiler.

Release binaries (agent-browser, agent-desktop) are pinned by version and checked by SHA-256 for each architecture. sudo stays the image's only setuid program, and the smoke test checks that.

### One image, not a slim variant

Computer use adds about 357 MB compressed (518 MB to 875 MB) and 1.27 GB on disk (1.94 GB to 3.21 GB). Most of it is Chromium (about 390 MB with its data) and Mesa's LLVM, which Chromium needs. Openbox brings Python and Ghostscript, but leaving Openbox out would change what botd requires. We publish one image anyway:

- A Bot's own computer is the product. A slim variant would make "can my Bot use a browser?" depend on the tag someone picked.
- Two variants would double the build matrix, the tags and the docs, and the smoke test would cover only one of them.
- When per-user screens land, a default install gets screens by changing a setting, not by switching images.
- It's a one-time download per upgrade, next to about 1 GB of harness CLIs already in the image.

Building from source can still drop it: `SUPERBOT_COMPUTER=off` (the `COMPUTER` build arg) skips the packages and the voxl build.

### Caddy reaches the screens in botd's container: `SCREEN_ADDR`

voxl listened on `127.0.0.1` inside botd's container, out of Caddy's reach. botd gets one setting, `SCREEN_ADDR` (an IP address, default `127.0.0.1`; anything else stops botd at start). voxl listens there, and so do botd's ports for screens on machines (ADR 0045). botd dials them on loopback when it is `0.0.0.0` or `::`. Compose sets `SCREEN_ADDR=0.0.0.0`, which `.env` can't override, and Caddy routes `/screen/69xx/` to `botd:69xx`, as the bash install's Caddy does to `127.0.0.1`. Only Caddy shares that network (the backup service has none), botd publishes no port, and each viewer still checks its own token. The smoke test checks that the live stream opens with the right token and is refused (401) with a wrong one.

Compose also gives botd `shm_size: 1gb`: Docker's 64 MB `/dev/shm` is too small for Chromium.

### Screens follow isolation, as on the bash install

botd turns its screens off under `ISOLATION=users`: an X display belongs to botd's account, and per-user screens don't exist yet (ADR 0037). That doesn't change here. New `.env` files keep per-user accounts on, and their log says `Screens: off (per-user screens ...)`. `./init.sh --no-isolation` turns screens on, with what ADR 0058 says that costs. The image is ready for per-user screens when they exist. ([ADR 0342](0342-per-user-screens-on-one-server.md) later runs each screen as its run's per-user account, so Compose has screens with accounts on.)

### Compose pulls by default; building from source is one flag

`docker-compose.yml` names the published images and has no `build:`. `docker-compose.build.yml` adds the builds and local names back. `./init.sh --from-source` writes `COMPOSE_FILE=docker-compose.yml:docker-compose.build.yml` to `.env`, so plain `docker compose` builds from the checkout, and `--published` goes back. `SUPERBOT_HARNESSES` (Hermes Agent, a subset of the CLIs) and `SUPERBOT_COMPUTER` apply only to images built from source; the published image has Claude Code, Codex and Pi.

### The smoke test

`deploy/docker/smoke-test.sh` runs on both architectures, against the images about to be pushed. After its earlier checks (health, auth, the client, per-user accounts, backups, the restore drill), it now also checks:

- screens are off under per-user accounts;
- with `ISOLATION=off`, botd says `Screens: on (viewers listen on 0.0.0.0 ...)`, a new Bot's screen starts, and its link serves voxl's viewer through Caddy;
- the live stream opens with the right token and is refused with a wrong one;
- agent-browser opens a page in Chromium on that Bot's display (checked with `xwininfo`), and agent-desktop runs.

The `backup` service gets a trivial healthcheck of its own (`test -d /backups`) instead of a disabled one: Compose 2.40 fails `up --wait` on a service whose healthcheck is disabled.

## Consequences

- Installing or upgrading with Compose is `docker compose pull && docker compose up -d`: no toolchain, and a host doesn't need RAM for a Rust build.
- Existing Compose installs switch from local builds to the published images on their next `docker compose up` after pulling this change. Their volumes don't change. One that baked Hermes Agent in (`SUPERBOT_HARNESSES` with `hermes`) must run `./init.sh --from-source` first, or its Hermes Bots stop with `harness_missing`.
- Every push to `main` builds both architectures and runs the smoke test twice. Pull requests run both, in parallel.
- `main` moves with every merge. Hosts that want stability pin `sha-<commit>` or, once there are releases, a version.
- The published Chromium is as current as the last uncached build (a week at most) plus Debian's own lag behind upstream, which agent-browser warns about when it starts a browser.

## Alternatives considered

- **Docker Hub.** Needs an account, a token stored as a secret, and has pull limits. GHCR needs nothing new.
- **QEMU for arm64.** One runner, but much slower, and it would test nothing on arm64. Native runners cost nothing for a public repository.
- **amd64 only.** arm64 servers are a common, cheaper choice for self-hosting, and every part of the stack has an arm64 build once Chromium comes from Debian.
- **A `-computer` (or `-slim`) variant.** Rejected above: it doubles the matrix for a feature that is the product's core.
- **Caddy in botd's network namespace** (`network_mode: service:botd`), so loopback would work. botd would then see every browser request as coming from 127.0.0.1, and Caddy's ports would have to be published on the botd service. A one-line bind setting keeps the network model as it is.
- **botd proxying `/screen/` itself.** botd would reimplement voxl's WebSocket proxying, which ADR 0045 already turned down.
- **Chrome for Testing on amd64, Chromium on arm64.** Two browsers to test and support for no gain.

## Not yet

- Per-user screens, so screens work with `ISOLATION=users`.
- Signed images and build provenance attestations.
- A read-only root filesystem.
