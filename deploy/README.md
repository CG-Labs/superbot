# SuperBot VPS install

Idempotent installer for Ubuntu 22.04 or 24.04: `botd`, `botctl`, systemd, optional Caddy HTTPS, and daily SQLite backups.

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
5. Writes `~/superbot/.env` from `.env.example` with:
   - `HOST=127.0.0.1`, `PORT=3000`, `TZ`, `USER_NAME`, data paths
   - Random `AUTH_PASSWORD` on first install (never overwritten on re-run)
   - `ALLOWED_HOSTS` and `CORS_ORIGINS` when `--domain` is set
   - `SUPERBOT_MASTER_KEY_FILE`, after creating the [master key](#master-key) if it is missing (never replaced)
6. **systemd** `superbot.service` (hardened, runs as the service user)
7. **Caddy** automatic HTTPS when `--domain` is set (`flush_interval -1` for SSE)
8. Optional **UFW** (`--ufw`): allow 22, 80, 443
9. Daily **backup** timer (on by default; `--no-backup` to skip)

Admin password file: `~superbot/.superbot-admin-password` (mode `0600`).

## After install

```sh
journalctl -u superbot -f
sudo -iu superbot claude login   # or codex login, etc.
```

Open `https://your-domain` and log in with any username and the saved password.

## Options

| Flag | Meaning |
|------|---------|
| `--domain` | Public hostname for Caddy |
| `--tz` | `TZ` for routines |
| `--user-name` | `USER_NAME` in the app |
| `--upgrade` | Pull, rebuild, restart |
| `--ufw` | Enable firewall rules |
| `--no-backup` | Skip backup timer |
| `--dry-run` | Print steps only |
| `--source-dir` | Copy a local tree instead of cloning |

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

`init.sh` writes `.env` (mode `0600`) from [`.env.example`](docker/.env.example) with a random `AUTH_PASSWORD`, prints it once, and never replaces it on re-run. Open `https://bots.example.com` and log in with any username and that password. DNS for the domain must point at the host, with ports 80 and 443 open.

Without a domain, `./init.sh` gives plain HTTP at `http://localhost`, published on `127.0.0.1` only. For another machine, use a domain (HTTPS); over plain HTTP the password crosses the network in clear text.

| Service | Role |
|---------|------|
| `botd` | Server, web app, harness CLIs. Runs as uid `10001`, no capabilities, port 3000 not published. |
| `caddy` | Publishes 80/443 on `SUPERBOT_BIND`, proxies to `botd` (SSE unbuffered). |
| `backup` | Archives `DATA_DIR` at start and every `SUPERBOT_BACKUP_INTERVAL` seconds. No network. |

| Volume | Mounted at | Holds |
|--------|------------|-------|
| `data` | `/data` (`DATA_DIR`) | SQLite database, Bot memory, user file. Back this up. |
| `workspace` | `/workspace` (`WORKSPACE_DIR`) | The Bots' shared files. |
| `home` | `/home/superbot` | Harness logins and sessions (`~/.claude`, `~/.claude.json`, `~/.codex`, `~/.pi`), runtime `npm i -g` installs. |
| `backups` | `/backups` | Backup archives. |
| `caddy-data`, `caddy-config` | Caddy | Certificates and ACME account. |

`init.sh` also writes a random `SUPERBOT_MASTER_KEY` once, which encrypts saved secrets ([master key](#master-key)); Compose refuses to start without it. Save API keys for the Bots encrypted instead of in `.env` with `SUPERBOT_PASSWORD=<AUTH_PASSWORD> docker compose exec -T -e SUPERBOT_PASSWORD botd botctl secret set OPENAI_API_KEY < key.txt`.

Secure by default: Compose refuses to start without `AUTH_PASSWORD`; the image sets `HOST=0.0.0.0`, so `botd` itself also refuses to run without it, and `ALLOW_NO_AUTH` is forced off. `ALLOWED_HOSTS` always includes `SUPERBOT_DOMAIN` (or `localhost`); add other names, such as `localhost:8080` when you change `SUPERBOT_HTTP_PORT`, in `.env`.

Every other `botd` setting (`TZ`, `USER_NAME`, `DEFAULT_HARNESS`, `CORS_ORIGINS`, `RUN_TIMEOUT_MINUTES`, …) goes in `.env`; apply changes with `docker compose up -d`. `HOST`, `PORT`, `DATA_DIR`, and `WORKSPACE_DIR` are fixed by the image.

### Harness CLIs and logins

The image bakes in Claude Code, Codex, and Pi (`npm i -g` at build time). Pick a subset with `SUPERBOT_HARNESSES` in `.env` (e.g. `claude`, or empty for none), then `docker compose build botd && docker compose up -d`. Pin versions with build args, e.g. `docker compose build --build-arg CLAUDE_CODE_VERSION=2.1.328 botd` (`CODEX_VERSION` and `PI_VERSION` too).

Log in once inside the container, as the `superbot` user that runs the Bots. Logins are stored in the `home` volume and survive upgrades and container recreation:

| Harness | Interactive login | Or put in `.env` |
|---------|-------------------|------------------|
| Claude Code | `docker compose exec -it botd claude auth login` (open the URL, paste the code back) | `CLAUDE_CODE_OAUTH_TOKEN` (from `claude setup-token`) or `ANTHROPIC_API_KEY` |
| Codex | `docker compose exec -it botd codex login --device-auth` | `OPENAI_API_KEY`, or store it: `docker compose exec -T botd codex login --with-api-key < key.txt` |
| Pi | `docker compose exec -it botd pi auth login <provider> --no-browser` | A provider key, e.g. `OPENROUTER_API_KEY` |

Check with `claude auth status`, `codex login status`, or `pi auth check` (same `docker compose exec` prefix).

Keys in `.env` pass through to the Bots, like the bash install. Claude Code's self-updater is off (`DISABLE_AUTOUPDATER=1`); CLIs update when you rebuild. For a newer CLI without a rebuild, `docker compose exec botd npm i -g @openai/codex@latest` installs it into the `home` volume, where it wins on `PATH` until you `npm rm -g` it.

### Upgrade

```sh
cd superbot && git pull
cd deploy/docker
docker compose exec botd superbot-backup        # optional: archive first
docker compose build --pull && docker compose up -d
```

Volumes are kept. The schema migrates on start, as with the bash install. To pin a release, `git checkout <tag>` before building.

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

[`deploy/docker/smoke-test.sh`](docker/smoke-test.sh) builds the image and runs the stack in an isolated project (own volumes and ports 18080/18443): health, auth, Host allowlist, harness CLIs, SSE through Caddy, saved secrets (encrypted, names only, absent from logs and backups), and a backup/restore round trip, then removes everything. CI runs it on every change to the image.