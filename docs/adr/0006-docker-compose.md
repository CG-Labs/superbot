# 0006: Docker Compose as a supported install

Date: 2026-11-19. Status: accepted.

## Context

The only supported install was the Ubuntu bash installer (`deploy/install.sh`: systemd, Caddy, backup timer). Operators asked for Compose (upstream issue #7), and the roadmap lists it under M1.

## Decision

- **One image, one `botd` container for all Bots.** Same model as the bash install: one OS user, one shared `WORKSPACE_DIR`. Per-Bot containers are an isolation feature (roadmap M5), not packaging.
- **Image** (root `Dockerfile`): build on `rust:1-trixie` with `--locked`; run on `node:22-trixie-slim`, because Claude Code, Codex, and Pi ship as npm packages. Adds only `ca-certificates curl git procps sqlite3 tini tzdata`. `tini` is PID 1 (reaps harness children, forwards SIGTERM). Non-root `superbot` (uid 10001). `HEALTHCHECK` on `/healthz`.
- **Harness CLIs baked in at build time** (`HARNESSES` build arg, default all three, versions pinnable). Upgrading means rebuilding; the Claude auto-updater is off. A runtime `npm i -g` lands in the home volume and takes precedence on `PATH`.
- **Compose** (`deploy/docker/`): `botd`, `caddy:2`, and a `backup` sidecar from the same image. Only Caddy publishes ports. `SUPERBOT_DOMAIN` set gives automatic HTTPS; empty gives plain HTTP on `127.0.0.1` only.
- **Secure by default, no new auth code.** The image sets `HOST=0.0.0.0`, so `botd`'s existing rule (no public bind without `AUTH_PASSWORD`) applies; Compose also fails fast without it and forces `ALLOW_NO_AUTH` off. `ALLOWED_HOSTS` always includes the domain (or `localhost`), since Caddy forwards the browser's Host. Containers drop all capabilities (Caddy keeps `NET_BIND_SERVICE`) and set `no-new-privileges`.
- **Volumes:** `data` (`DATA_DIR`), `workspace` (`WORKSPACE_DIR`), `home` (`/home/superbot`: harness logins and sessions), `backups`, and Caddy's `caddy-data`/`caddy-config`. Named volumes, not bind mounts, so ownership works without host uid setup.
- **Backups:** `superbot-backup` makes a tarball of an online SQLite `.backup` plus the rest of `DATA_DIR`, using the same layout as the bash backup, so bash backups restore into Compose. The sidecar runs it daily with retention and has no network. `superbot-restore` checks integrity, refuses while `botd` is up, and keeps the old data. Archives leave out `home` (secrets) and `workspace`.
- **Coexistence:** both installs stay supported and independent. Compose lives in `deploy/docker/` with its own `.env.example`, so the bash `.env` (`HOST=127.0.0.1`, host paths) never leaks into containers. No shared state, and the installer's staged file list does not include `deploy/docker/`.

## Why

- A Node runtime base costs about 200 MB, but the harness CLIs need Node anyway. They dominate the image (about 1.3 GB of 1.8 GB), so `HARNESSES` lets operators bake only what they use.
- Reusing `botd`'s auth and Host checks instead of adding proxy auth keeps one security model across both installs.

## Not yet

Screens and computer use (Xvfb, browser, voxl) in the image; published registry images; read-only root filesystem.
