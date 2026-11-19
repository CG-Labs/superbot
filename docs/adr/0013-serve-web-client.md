# 0013: Installs build and serve the web client at /app/

Date: 2026-11-19. Status: accepted.

## Context

Both installs built only `botd`, which serves the small built-in page in `web/`. The real interface, the Expo client in `apps/client`, was never deployed, so servers never got its features (routine editor, screen viewer, handoff). A hand-made export at `/app/` behind Caddy was the stopgap.

## Decision

- **Path: `/app/`, served by Caddy, not botd.** `redir /app /app/`, then `handle_path /app/*` with `try_files {path} /index.html` and `file_server`. Everything else (`/`, `/login`, `/api`, `/api/events` SSE with `flush_interval -1`, `/healthz`) still goes to botd. botd stays a pure API and admin server, with no static-file code to harden.
- **`/` stays the built-in page.** Making the client the single primary interface is still a proposal pending owner confirmation (roadmap, decision 5). The built-in page and its sign-in flow use `/` and `/login`, so redirecting `/` would need botd changes and would hide the admin page. Once confirmed, the switch is a Caddy `redir / /app/` plus moving the built-in page to `/admin`.
- **Base URL at build time, not in `app.json`.** `apps/client/app.config.js` sets `experiments.baseUrl` from `SUPERBOT_WEB_BASE_URL` only when it is set, so native, Electron (`file://`), and dev builds are unchanged. `npm run build:web:server` exports to `dist-app/`.
- **Same origin by default.** A web build served over http(s) outside dev fills the login's Server URL with `window.location.origin`. Same origin also means no CORS setup.
- **Caching.** Hashed bundles under `/_expo/static/` are `immutable`; `index.html` and everything else is `no-cache`, so an upgrade shows on the next load.
- **Bash installer, trusted-template model ([ADR 0005](0005-installer-trusted-units.md)).** The service user runs `npm ci` and `expo export` in its checkout. Its own `tar` streams the result to root, so root never walks a tree the service user controls. Root accepts the archive only if every entry is a plain file or folder, none uses `..`, and `index.html` is present. It unpacks into a new root-owned release in `/var/www/superbot-app.releases/` (`0755`/`0644`) and swaps the `/var/www/superbot-app` symlink with a single `rename`. One previous release is kept. A real folder at that path, such as the stopgap, becomes the previous release. A tampered checkout can change what browsers load, which it already can through botd, but not what root runs or reads.
- **Failure is not fatal.** No Node 20+ for the service user, a failed build, or a refused archive gives a warning and keeps the previous client. `--no-client` skips the build. Caddy gets the `/app/` block only when a client is installed.
- **Compose: client baked into Caddy.** A `client` stage in the root `Dockerfile` runs the same export. A `caddy` target copies it onto `caddy:2` at `/srv/superbot-app`, and Compose builds that target for its `caddy` service. Every `docker compose build` ships the checkout's client. A shared volume was rejected: it fills only once, so upgrades would keep serving the old client.

## Why

- Each upgrade ships the client from the same commit as botd, with no manual step.
- Caddy already fronts both installs and serves static files well. botd stays unchanged.

## Not yet

Published images; serving the client without Caddy (installs without `--domain`).

## Update (19 Nov 2026)

The owner confirmed the client as the single primary interface ([ADR 0027](0027-expo-primary-hermes-default.md)). `/` became the public landing page and the built-in page moved to `/console/` ([ADR 0022](0022-landing-and-signups.md)), so no `/` redirect is needed. Members and read-only users who open `/console/` are sent to `/app/`, sign-in lands them there, and botd no longer sends them from `/app/` to the console when no client is installed.
