# SuperBot VPS install

Idempotent installer for Ubuntu 22.04 or 24.04: `botd`, `botctl`, the web client, systemd, optional Caddy HTTPS, and daily SQLite backups.

Prefer containers? See [Docker Compose (supported)](#docker-compose-supported): same auth, HTTPS, and backups, on any Linux host with Docker.

## One command (from GitHub)

```sh
curl -fsSL https://raw.githubusercontent.com/CG-Labs/superbot/main/deploy/install.sh | sudo bash -s -- \
  --domain bots.example.com \
  --tz Europe/Jersey \
  --user-name "Alex"
```

Re-run with `--upgrade` to pull latest `main`, rebuild, and restart. Root never installs units from the service user's checkout: it fetches the repo into a root-owned `/usr/local/share/superbot/src.git`, stages `deploy/` in `/usr/local/share/superbot/deploy`, and renders units with a fixed `User=`, paths, and `ExecStart=`:

```sh
curl -fsSL https://raw.githubusercontent.com/CG-Labs/superbot/main/deploy/install.sh | sudo bash -s -- --upgrade
```

## From a local checkout

```sh
sudo deploy/install.sh --domain bots.example.com --tz UTC
```

If flags are omitted, the script prompts on a TTY. The checkout must not be owned by (or live under the home of) the service user; the installer refuses it otherwise.

## What it does

1. Creates user `superbot` (override with `--user`)
2. Installs build deps, Node.js 22 LTS, rustup for the service user
3. Clones or updates [CG-Labs/superbot](https://github.com/CG-Labs/superbot) under `~/superbot`
4. Builds release `botd` / `botctl` → `/usr/local/bin`
5. Builds the [web client](#web-client) (`apps/client`) → `/var/www/superbot-app` (skip with `--no-client`)
6. Writes `~/superbot/.env` from `.env.example` with:
   - `HOST=127.0.0.1`, `PORT=3000`, `TZ`, `USER_NAME`, data paths
   - Random `AUTH_PASSWORD` on first install (never overwritten on re-run)
   - `ALLOWED_HOSTS` and `CORS_ORIGINS` when `--domain` is set
   - `SUPERBOT_MASTER_KEY_FILE`, after creating the [master key](#master-key) if it is missing (never replaced)
7. **systemd** `superbot.service` (hardened, runs as the service user)
8. **Caddy** automatic HTTPS when `--domain` is set: the [landing page](#landing-page-and-sign-ups) at `/`, the web client at `/app/`, everything else to `botd` (`flush_interval -1` for SSE)
9. Optional **UFW** (`--ufw`): allow 22, 80, 443
10. Daily **backup** timer (on by default; `--no-backup` to skip)
11. With `--with-hermes`: [Hermes Agent](#hermes-agent) for the service user

Admin password file: `~superbot/.superbot-admin-password` (mode `0600`).

## After install

```sh
journalctl -u superbot -f
sudo -iu superbot claude login   # or codex login, etc.
```

Open `https://your-domain/app/` for the app (it fills in the server URL), or `https://your-domain/console/` for the built-in admin page. Sign in with the saved password. `https://your-domain/` is the public landing page. The app is the interface for everyone; the console is for admins only, and other people who open it or sign in at `/login` land on `/app/` ([ADR 0027](../docs/adr/0027-expo-primary-hermes-default.md)).

To add people, open **Users** in the app's sidebar (admins only), add them with a role, and send the invite it shows: the app URL, the server URL, and a one-time code (1 hour, 24 hours, or 7 days). The invite link (`/app/#code=…`) fills in the sign-in form; the code stays in the URL fragment, so it never reaches Caddy's or botd's logs. Design: [ADR 0021](../docs/adr/0021-admin-portal.md).

## Web client

The installer builds the Expo client (`apps/client`) from the same commit as `botd` on every install and `--upgrade`, and Caddy serves it at `/app/`. `/` is the [landing page](#landing-page-and-sign-ups); `/console/` (the built-in admin page), `/login`, `/api`, `/api/events`, and `/healthz` go to `botd`. Design: [ADR 0013](../docs/adr/0013-serve-web-client.md). With `--no-client`, members and read-only users have no browser interface (they use the desktop or mobile app); admins keep `/console/`.

- The service user builds it (`npm ci`, `expo export` with `SUPERBOT_WEB_BASE_URL=/app`) in `~/superbot/apps/client/dist-app`. Root copies only plain files and folders into a new root-owned release in `/var/www/superbot-app.releases/`, then switches the `/var/www/superbot-app` symlink in one step. The previous release is kept. Set `CLIENT_DIR` to use another path.
- Needs Node.js 20+ (the installer sets up 22). Without it, or if the build fails, the installer warns and keeps the previous client. `--no-client` skips it.
- Served only through Caddy, so it needs `--domain`.
- A hand-made `/var/www/superbot-app` folder is kept as the previous release on the first run.
- Build it yourself: `cd apps/client && npm ci && npm run build:web:server`. Plain `npm run build:web` (Electron, local) is unchanged.

## Options

| Flag | Meaning |
|------|---------|
| `--domain` | Public hostname for Caddy |
| `--tz` | `TZ` for routines |
| `--user-name` | `USER_NAME` in the app |
| `--upgrade` | Pull, rebuild, restart |
| `--ufw` | Enable firewall rules |
| `--no-backup` | Skip backup timer |
| `--with-hermes` | Also install Hermes Agent ([below](#hermes-agent)) |
| `--no-client` | Skip building the web client |
| `--dry-run` | Print steps only |
| `--source-dir` | Copy a local tree instead of cloning |

## Hermes Agent

Opt-in, because it is large (about 2.5 GB for the install, plus about 0.5 GB per Bot that uses it). `--with-hermes` runs Hermes's own installer as the service user, pinned to the commit of release v0.23.2 (override with `HERMES_COMMIT=<sha>`), and puts `~/.local/bin` on botd's `PATH` in `.env`. Hermes has no login: save a provider key, encrypted ([master key](#master-key)):

```sh
sudo -u superbot env SUPERBOT_PASSWORD="$(sudo grep -oP '^AUTH_PASSWORD=\K.*' ~superbot/superbot/.env)" botctl secret set OPENROUTER_API_KEY < /path/to/key.txt
```

To pick a provider or endpoint, set `SUPERBOT_HERMES_PROVIDER` (Hermes's `--provider`, e.g. `openrouter`) and `SUPERBOT_HERMES_BASE_URL` in `~superbot/superbot/.env`, then `sudo systemctl restart superbot`. Pick Hermes Agent for a Bot in its settings, or set `DEFAULT_HARNESS=hermes`. How it runs and its limits: [backend docs](../docs/backend.md#hermes-agent).

## Binaries

Release binaries are installed system-wide in `/usr/local/bin` so `botctl` stays next to `botd` on the Bots' PATH. To use user-local installs instead, set `BIN_DIR` before running the script (advanced).

## Approvals after an upgrade

Fresh installs ask before risky actions. An install from before approvals keeps running without them (`bypass`) after `--upgrade`, and botd logs a warning at start. To opt in, on the server:

```sh
sudo -u superbot env SUPERBOT_PASSWORD="$(sudo grep -oP '^AUTH_PASSWORD=\K.*' ~superbot/superbot/.env)" botctl policy set global mode=ask
```

Or use the switch at the bottom of the web app's Approvals window. Don't put `SUPERBOT_PASSWORD` in `.env`: it's for your shell. See [docs/backend.md](../docs/backend.md#approvals).

## Master key

botd encrypts saved secrets (`botctl secret set`) and approvals' tool input with a master key: `~superbot/.config/superbot/master.key` (mode `0600`, folder `0700`). The installer creates it on first install and on the first `--upgrade` that needs it, before botd restarts, and never replaces it. It is outside `DATA_DIR`, so the daily backups don't include it: **copy it somewhere safe, apart from the backups.** Design and threat model: [ADR 0010](../docs/adr/0010-secrets.md).

```sh
# Save a key for the Bots (value on stdin, stays out of shell history); list names; delete
sudo -u superbot env SUPERBOT_PASSWORD="$(sudo grep -oP '^AUTH_PASSWORD=\K.*' ~superbot/superbot/.env)" sh -c 'botctl secret set OPENAI_API_KEY < /path/to/key.txt; botctl secrets'
```

- **Upgrading** from a release before secrets: the first start seals old approval inputs and scrubs known secrets (the login password, keys in `.env`) from saved chats. Nothing else changes. To downgrade, restore a backup from before the upgrade.
- **Restoring on a new server**: restore the backup, then put the key back at the same path (owner `superbot`, mode `0600`) before starting botd. With a missing or wrong key, botd logs why and refuses to start; the installer refuses too rather than make a new key over sealed data.
- **Key lost for good**: add `SUPERBOT_FORGET_SEALED=1` to `.env` and restart. Saved secrets and old approval inputs are dropped, everything else is kept, and a new key is made. It only drops what the current key can't open, but remove the line afterwards.
- **Your own key**: set `SUPERBOT_MASTER_KEY` (64 hex chars, `openssl rand -hex 32`) in `.env` instead of the file, or point `SUPERBOT_MASTER_KEY_FILE` elsewhere. Not both.

## Computer / screens

For Xvfb, browser automation, and live screens, run [`install-computer.sh`](install-computer.sh) after the base install.

## Audit log retention

Admin actions (logins, Bot and routine changes, approvals, policy, handoffs) are kept in an append-only table in `app.sqlite` ([ADR 0009](../docs/adr/0009-audit-events.md)). Read or export it from the web app's Audit log, or `botctl audit export > audit.csv` on the server with `SUPERBOT_PASSWORD` set.

- `AUDIT_RETENTION_DAYS` in `.env`: unset or `0` keeps events forever (default: they are small, and deleting them can't be undone). `1` to `36500` deletes older events every 6 hours. Restart `botd` after changing it.
- Both installs back it up: the bash timer and the Compose `backup` service take a SQLite `.backup` of `app.sqlite`, audit table included, and keep archives for `SUPERBOT_BACKUP_RETENTION_DAYS` (default 14). So a pruned event still exists in backups for that long; shorten it too if you must erase events.
- Source IPs: the installer's Caddy is on loopback, so `botd` trusts its `X-Forwarded-For`. Compose sets `TRUST_FORWARDED_FOR=1`, since `botd` is reachable only through Caddy.

## Landing page and sign-ups

`/` is a public landing page and `/get-started` a form to ask for access ([ADR 0022](../docs/adr/0022-landing-and-signups.md)). The built-in admin page moved from `/` to `/console/`; `/app/` is unchanged.

- The installer copies `site/` (plain files, no build) into a root-owned release in `/var/www/superbot-site.releases/` and switches the `/var/www/superbot-site` symlink, like the client, on every install and `--upgrade`. Caddy serves `/`, `/get-started`, and `/site/*` from it. Set `SITE_DIR` to use another path. botd has the same pages built in, so they work without Caddy too.
- Requests wait for an admin: `botctl signup list`, then `botctl signup approve <id>` (prints a one-time sign-in code, once) or `botctl signup reject <id>`. **No email is sent**: give the person their code yourself. Details: [docs/backend.md](../docs/backend.md#sign-ups).
- Optional bot check: `TURNSTILE_SITE_KEY` and `TURNSTILE_SECRET` in `.env` turn on Cloudflare Turnstile. `SIGNUPS=off` closes the form.
- Upgrading needs no config change. The first start adds the `signups` table. Bookmarks of `/` for the admin page should move to `/console/`.

## Users and sign-in after an upgrade

botd now has users, roles, and sessions ([ADR 0012](../docs/adr/0012-users-sessions-rbac.md)). Upgrading (`--upgrade`, or a new Compose image) needs no config change:

- The first start adds the user tables and an admin owner account (`USER_NAME`; set `OWNER_EMAIL` in `.env` to give it an email). The audit log keeps calling it `operator`.
- `AUTH_PASSWORD` still works everywhere as the owner's break-glass login: browsers, the client, scripts, and `botctl` with `SUPERBOT_PASSWORD`. Browsers now get a sign-in page instead of the password box; the client swaps a saved password for a session token on its next start.
- Add people with roles and give each a one-time sign-in code (on the server, with `SUPERBOT_PASSWORD` set as above): `botctl user add alex@example.com "Alex" --role member`, then `botctl user code alex@example.com`. In Compose: `docker compose exec -T -e SUPERBOT_PASSWORD botd botctl ...`.
- Sessions last `SESSION_IDLE_TIMEOUT` without use (default `7d`) and at most `SESSION_MAX_AGE` (default `30d`). Revoke with `botctl session revoke-all <user>`.
- People can sign in with Microsoft Entra ID: register an app, set `SSO_PROVIDERS=entra` and the `SSO_*` settings in `.env`, and link people with `botctl user link`. Step by step: [docs/sso/entra.md](../docs/sso/entra.md). The first start after this upgrade adds the `user_identities` table. Google and any OIDC IdP (Okta, Keycloak, Auth0, …) work the same way, alone or next to Entra (`SSO_PROVIDERS=entra,google,okta`): [docs/sso/google.md](../docs/sso/google.md), [docs/sso/oidc.md](../docs/sso/oidc.md). SSO stays off until `SSO_PROVIDERS` is set; upgrading needs no new settings.
- Once every admin can sign in without the password, set `AUTH_BREAK_GLASS=0` and restart: the password is then ignored. To get back in, set it to `1` and restart.
- Downgrading: older botd ignores the new tables and keeps working with `AUTH_PASSWORD`.

## Docker Compose (supported)

`botd` + Caddy (automatic HTTPS) + a daily backup job, from [`deploy/docker/`](docker/). Needs Docker Engine with the Compose v2 plugin. Design: [ADR 0006](../docs/adr/0006-docker-compose.md).

### Quick start

```sh
git clone https://github.com/CG-Labs/superbot.git
cd superbot/deploy/docker
./init.sh --domain bots.example.com --tz Europe/Jersey --user-name "Alex"
docker compose up -d --build
docker compose logs -f botd
```

`init.sh` writes `.env` (mode `0600`) from [`.env.example`](docker/.env.example) with a random `AUTH_PASSWORD`, prints it once, and never replaces it on re-run. Open `https://bots.example.com/app/` for the app, or `https://bots.example.com/console/` for the built-in admin page, and sign in with that password. DNS for the domain must point at the host, with ports 80 and 443 open.

Without a domain, `./init.sh` gives plain HTTP at `http://localhost`, published on `127.0.0.1` only. For another machine, use a domain (HTTPS); over plain HTTP the password crosses the network in clear text.

| Service | Role |
|---------|------|
| `botd` | Server, web app, harness CLIs. Runs as uid `10001`, no capabilities, port 3000 not published. |
| `caddy` | `caddy:2` plus the [web client](#web-client) and [landing page](#landing-page-and-sign-ups), built from this checkout (`Dockerfile` target `caddy`). Publishes 80/443 on `SUPERBOT_BIND`, serves the landing page at `/` and the client at `/app/`, proxies everything else to `botd` (SSE unbuffered). |
| `backup` | Archives `DATA_DIR` at start and every `SUPERBOT_BACKUP_INTERVAL` seconds. No network. |

| Volume | Mounted at | Holds |
|--------|------------|-------|
| `data` | `/data` (`DATA_DIR`) | SQLite database, Bot memory, user file. Back this up. |
| `workspace` | `/workspace` (`WORKSPACE_DIR`) | The Bots' shared files. |
| `home` | `/home/superbot` | Harness logins and sessions (`~/.claude`, `~/.claude.json`, `~/.codex`, `~/.pi`), runtime `npm i -g` installs. Hermes Agent keeps its per-Bot data in `data` instead. |
| `backups` | `/backups` | Backup archives. |
| `caddy-data`, `caddy-config` | Caddy | Certificates and ACME account. |

`init.sh` also writes a random `SUPERBOT_MASTER_KEY` once, which encrypts saved secrets ([master key](#master-key)); Compose refuses to start without it. Save API keys for the Bots encrypted instead of in `.env` with `SUPERBOT_PASSWORD=<AUTH_PASSWORD> docker compose exec -T -e SUPERBOT_PASSWORD botd botctl secret set OPENAI_API_KEY < key.txt`.

Secure by default: Compose refuses to start without `AUTH_PASSWORD`; the image sets `HOST=0.0.0.0`, so `botd` itself also refuses to run without it, and `ALLOW_NO_AUTH` is forced off. `ALLOWED_HOSTS` always includes `SUPERBOT_DOMAIN` (or `localhost`); add other names, such as `localhost:8080` when you change `SUPERBOT_HTTP_PORT`, in `.env`.

Every other `botd` setting (`TZ`, `USER_NAME`, `DEFAULT_HARNESS`, `CORS_ORIGINS`, `RUN_TIMEOUT_MINUTES`, …) goes in `.env`; apply changes with `docker compose up -d`. `HOST`, `PORT`, `DATA_DIR`, and `WORKSPACE_DIR` are fixed by the image.

### Harness CLIs and logins

The image bakes in Claude Code, Codex, and Pi (`npm i -g` at build time). Pick a subset with `SUPERBOT_HARNESSES` in `.env` (e.g. `claude`, or empty for none), then `docker compose build botd && docker compose up -d`. Pin versions with build args, e.g. `docker compose build --build-arg CLAUDE_CODE_VERSION=2.1.328 botd` (`CODEX_VERSION` and `PI_VERSION` too).

Hermes Agent is opt-in: add it with `SUPERBOT_HARNESSES=claude codex pi hermes` (about 2.5 GB more in the image, plus about 0.5 GB per Bot in the `data` volume). The image installs it in `/opt/hermes`, pinned with `HERMES_COMMIT`. It has no login: save a provider key with `botctl secret set` (above) and, if needed, set `SUPERBOT_HERMES_PROVIDER` and `SUPERBOT_HERMES_BASE_URL` in `.env`. See [backend docs](../docs/backend.md#hermes-agent).

Log in once inside the container, as the `superbot` user that runs the Bots. Logins are stored in the `home` volume and survive upgrades and container recreation:

| Harness | Interactive login | Or put in `.env` |
|---------|-------------------|------------------|
| Claude Code | `docker compose exec -it botd claude auth login` (open the URL, paste the code back) | `CLAUDE_CODE_OAUTH_TOKEN` (from `claude setup-token`) or `ANTHROPIC_API_KEY` |
| Codex | `docker compose exec -it botd codex login --device-auth` | `OPENAI_API_KEY`, or store it: `docker compose exec -T botd codex login --with-api-key < key.txt` |
| Pi | `docker compose exec -it botd pi auth login <provider> --no-browser` | A provider key, e.g. `OPENROUTER_API_KEY` |
| Hermes Agent | None | A provider key, e.g. `OPENROUTER_API_KEY`, best saved with `botctl secret set` |

Check with `claude auth status`, `codex login status`, or `pi auth check` (same `docker compose exec` prefix).

Keys in `.env` pass through to the Bots, like the bash install. Claude Code's self-updater is off (`DISABLE_AUTOUPDATER=1`); CLIs update when you rebuild. For a newer CLI without a rebuild, `docker compose exec botd npm i -g @openai/codex@latest` installs it into the `home` volume, where it wins on `PATH` until you `npm rm -g` it.

### Upgrade

```sh
cd superbot && git pull
cd deploy/docker
docker compose exec botd superbot-backup        # optional: archive first
docker compose build --pull && docker compose up -d
```

Volumes are kept. The schema migrates on start, as with the bash install. The build also rebuilds the `caddy` image with the checkout's web client. To pin a release, `git checkout <tag>` before building.

Upgrading from a release before secrets: run `./init.sh` once first. It adds a random `SUPERBOT_MASTER_KEY` to `.env` (Compose refuses to start without one) and leaves everything else alone. The key encrypts saved secrets and approvals' tool input ([master key](#master-key)); it stays in `.env` on the host, never in a volume.

### Backup and restore

The `backup` service writes `superbot-<UTC stamp>.tar.gz` to the `backups` volume (default every 24 h, keeps 14 days: `SUPERBOT_BACKUP_INTERVAL`, `SUPERBOT_BACKUP_RETENTION_DAYS`). Each archive has an online SQLite `.backup` copy of `app.sqlite` plus the rest of `DATA_DIR` (Bot memory, `USER.md`), so it is safe while Bots are running.

```sh
# On demand, into the backups volume, or streamed to the host (copy it off-site)
docker compose exec botd superbot-backup
docker compose exec -T botd superbot-backup - > superbot-$(date -u +%Y%m%d).tar.gz

# List and copy archives out of the volume
docker compose exec backup ls -l /backups
docker compose cp backup:/backups/superbot-20261119-031500.tar.gz .

# Restore (botd must be stopped; the old data is kept in /data/.pre-restore-<stamp>/)
docker compose stop botd backup
docker compose run --rm --no-deps -T botd superbot-restore - < superbot-20261119.tar.gz
docker compose up -d
```

Archives include the audit log (`audit_events` lives in `app.sqlite`). See [Audit log retention](#audit-log-retention).

`superbot-restore` checks the archive with `PRAGMA integrity_check` before it swaps anything, and refuses to run while `botd` is up.

Archives don't include `SUPERBOT_MASTER_KEY`, by design. Keep a copy of `.env` (or at least that line) somewhere safe, apart from the archives: restoring onto a new host needs the same key, or saved secrets can't be read (see [master key](#master-key) for the way out if it is lost).

Archives do not include the `workspace` volume (Bots' files) or the `home` volume (harness logins: secrets; log in again after a fresh restore). Back those up with a raw volume copy if you need them:

```sh
docker run --rm -v superbot_workspace:/v:ro -v "$PWD":/out debian:trixie-slim \
  tar -czf /out/workspace.tar.gz -C /v .
```

`docker compose down` keeps volumes; `docker compose down -v` deletes them, logins and data included.

### Moving from the bash installer

The two installs are independent; do not run both on one host (both want ports 80/443). The bash backup layout (`app.sqlite`, `bots/`, `USER.md`) matches the archive format, so:

```sh
sudo systemctl disable --now superbot superbot-backup.timer caddy
sudo -u superbot superbot-backup /home/superbot
sudo tar -czf superbot-migrate.tar.gz -C /home/superbot/superbot/backups/<stamp> .
cd superbot/deploy/docker && ./init.sh --domain bots.example.com   # reuse AUTH_PASSWORD from ~superbot/superbot/.env if you like
# Carry the master key over (replacing the one init.sh made), or saved secrets won't open:
key=$(sudo cat ~superbot/.config/superbot/master.key) && sed -i "s|^SUPERBOT_MASTER_KEY=.*|SUPERBOT_MASTER_KEY='$key'|" .env
docker compose up -d --build && docker compose stop botd backup
docker compose run --rm --no-deps -T botd superbot-restore - < superbot-migrate.tar.gz
docker compose up -d
```

Then log the harness CLIs in again inside the container.

### Not in the image yet

Screens and computer use (Xvfb, browser, voxl): `botd` reports `Screens: off`. Use the bash installer plus [`install-computer.sh`](install-computer.sh) if you need them.

### Check the setup

[`deploy/docker/smoke-test.sh`](docker/smoke-test.sh) builds the image and runs the stack in an isolated project (own volumes and ports 18080/18443): health, auth, Host allowlist, the landing page, the web client at `/app/`, harness CLIs, SSE through Caddy, saved secrets (encrypted, names only, absent from logs and backups), and a backup/restore round trip, then removes everything. CI runs it on every change to the image.