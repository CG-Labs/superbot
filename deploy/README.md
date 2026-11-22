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

Re-run with `--upgrade` to pull latest `main`, rebuild, and restart. Exit status 3 means everything but the [web client](#web-client) was upgraded. Root never installs units from the service user's checkout: it fetches the repo into a root-owned `/usr/local/share/superbot/src.git`, stages `deploy/` in `/usr/local/share/superbot/deploy`, and renders units with a fixed `User=`, paths, and `ExecStart=`:

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
4. Builds release `botd` / `botctl` / `superbot-run` → `/usr/local/bin`
5. Builds the [web client](#web-client) (`apps/client`) → `/var/www/superbot-app` (skip with `--no-client`)
6. Writes `~/superbot/.env` from `.env.example` with:
   - `HOST=127.0.0.1`, `PORT=3000`, `TZ`, `USER_NAME`, data paths
   - Random `AUTH_PASSWORD` on first install (never overwritten on re-run)
   - `ALLOWED_HOSTS` and `CORS_ORIGINS` when `--domain` is set
   - `SUPERBOT_MASTER_KEY_FILE`, after creating the [master key](#master-key) if it is missing (never replaced)
7. **systemd** `superbot.service` (hardened, runs as the service user)
8. **Caddy** automatic HTTPS when `--domain` is set: the [landing page](#landing-page-and-sign-ups) at `/`, the web client at `/app/`, everything else to `botd` (`flush_interval -1` for SSE)
9. Optional **UFW** (`--ufw`): allow 22, 80, 443
10. Daily **backup** timer (on by default; `--no-backup` to skip), plus `superbot-restore`: see [Backups and restore](#backups-and-restore)
11. With `--with-hermes`: [Hermes Agent](#hermes-agent) for the service user
12. On new installs (or with `--isolation`): [one Unix account per user](#one-unix-account-per-user)

Admin password file: `~superbot/.superbot-admin-password` (mode `0600`).

## After install

```sh
journalctl -u superbot -f
sudo -iu superbot claude login   # or codex login, etc.
```

With per-user accounts (new installs, or `--isolation`), log harnesses in per user instead: [one Unix account per user](#one-unix-account-per-user).

Open `https://your-domain/app/` for the app (it fills in the server URL), or `https://your-domain/console/` for the built-in admin page. Sign in with the saved password. `https://your-domain/` is the public landing page. The app is the interface for everyone, admins included (chat, Bots, approvals, screens). The console is a minimal admin and break-glass page: users and roles, sign-up requests, per-user machines, the audit log, and settings (approval mode, server secrets, SCIM tokens). Only admins get it; other people who open it or sign in at `/login` land on `/app/` ([ADR 0027](../docs/adr/0027-expo-primary-hermes-default.md), [ADR 0032](../docs/adr/0032-console-admin-only.md)).

### Setup wizard

On a new server the console opens on **Setup** until an admin finishes or hides it ([ADR 0034](../docs/adr/0034-onboarding-wizard.md)). It walks through:

1. **Domain:** the public address, whether you reached it over HTTPS through Caddy, and the commands to set it (the one-command installer with `--upgrade --domain`, or `init.sh --domain` for Compose).
2. **Sign-in:** each SSO provider, whether it's ready, the redirect URI to register at the IdP, and a box to save its client secret (it takes effect at once). `.env` lines to add a provider of any type.
3. **Plans:** the tiers file, or the open `self-host` tier, and how to add a [tiers file](#tiers-plans).
4. **Finish:** a checklist, including a second admin besides the break-glass owner and approvals on.

The wizard writes only what botd can change while running: SSO secrets, the approval mode, and its own progress. Settings read at startup come as commands and `.env` lines to copy, with the restart command. From a shell on the server: `botctl setup` prints the checklist and `botctl setup done` finishes it. Admins in the app see **Finish server setup ↗** in the sidebar until then.

To add people, open **Users** in the app's sidebar or in the console (admins only), add them with a role, and send the invite it shows: the app URL, the server URL, and a one-time code (1 hour, 24 hours, or 7 days). The invite link (`/app/#code=…`) fills in the sign-in form; the code stays in the URL fragment, so it never reaches Caddy's or botd's logs. Design: [ADR 0021](../docs/adr/0021-admin-portal.md).

## Web client

The installer builds the Expo client (`apps/client`) from the same commit as `botd` on every install and `--upgrade`, and Caddy serves it at `/app/`. `/` is the [landing page](#landing-page-and-sign-ups); `/console/` (the built-in admin page), `/login`, `/api`, `/api/events`, and `/healthz` go to `botd`. Design: [ADR 0013](../docs/adr/0013-serve-web-client.md). With `--no-client`, nobody has browser chat (use the desktop or mobile app); admins keep `/console/` for admin tasks.

- The service user builds it (`npm ci`, `expo export` with `SUPERBOT_WEB_BASE_URL=/app`) in `~/superbot/apps/client/dist-app`. Root copies only plain files and folders into a new root-owned release in `/var/www/superbot-app.releases/`, then switches the `/var/www/superbot-app` symlink in one step. The previous release is kept. Set `CLIENT_DIR` to use another path.
- Needs Node.js 20+ (the installer sets up 22). Without Node, the installer warns, keeps the previous client, and exits 0. `--no-client` skips it.
- If the build fails or root refuses it, the installer still finishes everything else and keeps serving the previous client release. It then ends with a final `!!` warning and **exit status 3**, on a fresh install and on `--upgrade`, so scripts and operators can't miss it. Fix the cause it names and re-run.
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
| `--backup-s3-endpoint`, `--backup-s3-bucket` | Copy server backups off the host to S3-compatible storage; keys in `SERVER_BACKUP_S3_ACCESS_KEY_ID` and `SERVER_BACKUP_S3_SECRET_ACCESS_KEY` in the installer's environment, never flags ([below](#backups-and-restore)) |
| `--backup-s3-region`, `--backup-s3-prefix` | The store's region (us-east-1; `auto` for R2) and key prefix (`superbot/`) |
| `--backup-age-recipients` | Encrypt backup archives to these age public keys (`SUPERBOT_BACKUP_AGE_RECIPIENTS`) |
| `--backup-off-host auto\|on\|off` | `SERVER_BACKUP_OFF_HOST`: copy when a store is set, refuse to start without one, or never copy |
| `--with-hermes` | Also install Hermes Agent ([below](#hermes-agent)) |
| `--license-file` | Install the license key CG-Labs sent ([below](#license)) |
| `--isolation` / `--no-isolation` | Each user's Bots run as their own Unix account, or not ([below](#one-unix-account-per-user)). On for new installs; upgrades keep what they had |
| `--no-client` | Skip building the web client |
| `--dry-run` | Print steps only |
| `--source-dir` | Copy a local tree instead of cloning |

## Hermes Agent

Opt-in, because it is large (about 2.5 GB for the install). `--with-hermes` runs Hermes's own installer as the service user, pinned to the commit of release v0.23.3 (override with `HERMES_COMMIT=<sha>`; bumps go through `deploy/hermes-pin.sh`, [ADR 0075](../docs/adr/0075-hermes-upgrades.md)), then `deploy/hermes-share.sh`, which gives every Bot the install's one Python environment, read-only, while each Bot keeps its own Hermes folder ([ADR 0072](../docs/adr/0072-one-hermes-environment-per-computer.md)). It puts `~/.hermes/superbot` on botd's `PATH` in `.env`. With [per-user accounts](#one-unix-account-per-user), which can't open the service user's home, it installs Hermes system-wide instead, as root in `/opt/hermes`, linked from `/usr/local/bin/hermes`. Re-running the installer at a new `HERMES_COMMIT` stops botd while Hermes changes, so no running Bot loses its environment. Hermes has no login: save a provider key, encrypted ([master key](#master-key)):

```sh
sudo -u superbot env SUPERBOT_PASSWORD="$(sudo grep -oP '^AUTH_PASSWORD=\K.*' ~superbot/superbot/.env)" botctl secret set OPENROUTER_API_KEY < /path/to/key.txt
```

To pick a provider or endpoint, set `SUPERBOT_HERMES_PROVIDER` (Hermes's `--provider`, e.g. `openrouter`) and `SUPERBOT_HERMES_BASE_URL` in `~superbot/superbot/.env`, then `sudo systemctl restart superbot`. Pick Hermes Agent for a Bot in its settings, or set `DEFAULT_HARNESS=hermes`. How it runs and its limits: [backend docs](../docs/backend.md#hermes-agent).

## One Unix account per user

Each user's Bots, on every harness, run as their own account, `sb-u-<user id>`, so one user's Bots can't read or write another's folder or harness logins, nor botd's data, database, `.env`, or master key. **On for new installs.** An install from before keeps what it had (botd's log says `Isolation: off` and how to opt in); `--no-isolation` opts out. Design: [ADR 0037](../docs/adr/0037-per-user-unix-accounts.md), [ADR 0058](../docs/adr/0058-harness-os-user-by-default.md).

```sh
sudo bash deploy/install.sh --upgrade --isolation     # opt an existing install in; or with curl, as above
```

What root sets up (and `--no-isolation` takes away again, keeping accounts and their folders):

- `/usr/local/sbin/superbot-userctl` (makes one account and its folders, and removes a leaving teammate's account, nothing else) and `/etc/superbot/isolation.conf` (where the folders go and botd's group).
- `/etc/sudoers.d/superbot-isolation`: the service user may start `/usr/local/bin/superbot-run` as a member of `superbot-users`, keeping the run's env, and run `superbot-userctl ensure <id>` (or `ensure <owner> <teammate>`, a teammate's account for an owner's shared Bots), `remove <owner> <teammate> ...` and `purge <id>` (a leaving teammate's account and held work) as root. Nothing else. Installs from before the teammate removals: re-run `sudo bash deploy/install.sh --upgrade --isolation` to get `remove` and `purge`. Checked with `visudo -c` first.
- `/etc/systemd/system/superbot.service.d/isolation.conf`: `NoNewPrivileges=false` (sudo is setuid) and `ProtectProc=invisible` (a run sees only its own account's processes).
- `/srv/superbot/users` (root, `0711`; set `ISOLATION_DIR` to move it), the `superbot-users` group, the service home at `0750`, and `ISOLATION=users` in `.env`.

Then, as the service user, at a terminal:

```sh
sudo -iu superbot
export SUPERBOT_PASSWORD=...                     # AUTH_PASSWORD from ~/superbot/.env, or SUPERBOT_TOKEN from botctl login
botctl user isolation alex@example.com           # the account and its folders
botctl user harness-login alex@example.com claude   # claude auth login, as alex's account
botctl user harness-login alex@example.com codex
botctl user harness-login bea@example.com claude --owner alex@example.com   # bea's own login, for alex's shared Bots
```

Accounts are made at a user's first run, or with `botctl user isolate <user>`. Install harness CLIs system-wide (`sudo npm install -g @anthropic-ai/claude-code @openai/codex`): per-user accounts can't open the service user's `~/.local`. Pi and Hermes Agent use provider keys (`botctl secret set`); their approval guard and settings are files botd writes, which the account can read but not change. Screens are off until they can run this way. To check it on a throwaway host: `deploy/test-isolation.sh` (CI runs it).

With `SHARED_BOTS=isolated` too, a teammate's run of someone else's shared Bot runs as an account of its own for that owner's Bots (`sb-t-<hash>`, folders in `ISOLATION_DIR/<owner>-<teammate>/`), never as the owner's. Neither the owner's account nor the teammate's own can enter it. Claude Code and Codex Bots then need the teammate's own login there, or a server-wide key: teammates log in from the Bot's details in the app, and an admin can use `botctl user harness-login <teammate> <harness> --owner <owner>`. Without either, the Bot says so and doesn't run; it never uses the owner's login. `ISOLATION_TEAMMATES=off` in `.env` keeps the old behaviour (the owner's account). Design: [ADR 0064](../docs/adr/0064-teammate-accounts-on-one-server.md).

When a teammate is disabled, deprovisioned or deleted, or loses the owner's Bots, their account for those Bots goes, within seconds: its processes are stopped, their work is handed to the owner's account (in `workspace/from-teammates/<name>-<date>`), and their folder, login, temp files and the account are deleted. A user's own account, the owner's and system accounts are never touched. `ISOLATION_TEAMMATE_FILES=delete` holds the work aside instead (`ISOLATION_DIR/.left/`, root's) and deletes it after `ISOLATION_TEAMMATE_FILES_DAYS` (default 7, `0` at once). A removal that fails is audited and retried every few minutes. Admins see and force them in the console's user detail, or:

```sh
botctl user teammates alex@example.com                       # teammates' accounts for alex's Bots, and alex's for others'
botctl user teammates alex@example.com remove bea@example.com   # remove bea's account for alex's Bots now
botctl user teammate-removals                                # open removals (pending, or work held)
```

Design: [ADR 0066](../docs/adr/0066-removing-teammate-accounts-on-one-server.md).

Turning it on doesn't move files. Each user's work starts in a new, empty `ISOLATION_DIR/<id>/workspace`; their old folder, `WORKSPACE_DIR/users/<id>`, stays where it was. Bot memory and `USER.md` carry over by themselves (botd keeps the real copies). Harness sessions don't: each Bot's next run starts a fresh one, with its memory. To bring a user's files along, as root, after `botctl user isolate <user>`:

```sh
systemctl stop superbot
rsync -a --chown=sb-u-<id>:superbot ~superbot/superbot/workspace/users/<id>/ /srv/superbot/users/<id>/workspace/
chmod -R g+rwX,o-rwx /srv/superbot/users/<id>/workspace
systemctl start superbot
```

Turning it off is the same in reverse: work done meanwhile stays in `ISOLATION_DIR/<id>/workspace`, so copy it back with `--chown=superbot:superbot`.

## Binaries

Release binaries are installed system-wide in `/usr/local/bin` so `botctl` stays next to `botd` on the Bots' PATH. To use user-local installs instead, set `BIN_DIR` before running the script (advanced). `superbot-machine` is the agent for managed machines (below); self-hosted servers never run it.

## Managed machines: enrollment

Managed hosting only (one Linode per user, [ADR 0025](../docs/adr/0025-control-plane-linode.md), or one Incus container per user on a shared host, [ADR 0065](../docs/adr/0065-incus-container-machines.md) and [its guide](../docs/ops/incus-containers.md)). Self-hosted servers skip this. With `LINODE_TOKEN` or `MACHINE_PROVIDER=incus` set, add to `.env`:

```sh
MACHINE_CONTROL_URL=https://<server-ip>:8443   # how machines reach this server; turns enrollment on
# MACHINE_LISTEN=0.0.0.0:8443                   # default: all addresses, the URL's port
# MACHINE_AGENT_PORT=7443                       # where each machine's agent answers
```

botd then listens on that port for machines (TLS from its own CA, not Caddy's), so open it in the firewall (`sudo ufw allow 8443/tcp`; with Docker, publish it too). Each new machine gets a one-time token in its cloud-init data, downloads `superbot-machine` from botd, enrolls for a 30-day certificate, and answers botd over mutual TLS. Suspend holds its certificate; destroy revokes it. The CA key is derived from the [master key](#master-key), so there is nothing new to back up; a new master key means every machine re-enrolls. A new token for a machine (shown once): `POST /api/users/<user>/machine/enrollment`; revoke its certificates: `DELETE /api/users/<user>/machine/certificates`. Design: [ADR 0031](../docs/adr/0031-machine-enrollment-mtls.md).

### Firewall and first boot

To put every machine behind a Linode Cloud Firewall, add (the Linode token also needs **Firewalls: read/write**):

```sh
MACHINE_FIREWALL=on
# MACHINE_FIREWALL_SOURCES=<server-ip>/32   # who may reach the agent; default: the control URL's address
# MACHINE_SSH_SOURCES=<your-ip>/32          # SSH stays closed unless set
# MACHINE_ENROLL_TIMEOUT_MINUTES=15         # then a machine that hasn't enrolled is flagged
```

botd makes one firewall, `<MACHINE_LABEL_PREFIX>-fw`. It drops all inbound traffic except the agent port from those sources, and lets all outbound traffic out. Each new machine is behind it from its first boot. The reconciler puts back changed rules and detached machines, and botd deletes the firewall with the last machine. If the URL names a host rather than an IP, set `MACHINE_FIREWALL_SOURCES`.

On first boot, cloud-init downloads `superbot-machine` from botd. The download trusts only botd's CA, and the binary must match the SHA-256 in the user data. cloud-init then enrolls with the one-time token, deletes the token and its own copy of the user data, and starts `superbot-machine.service`. Nothing needs doing by hand.

A machine that hasn't enrolled within the timeout shows "Didn't enroll in time" in the console, and botd records `machine.enroll_timeout` once. Open the machine's Lish console in Linode Cloud Manager and read `/var/log/cloud-init-output.log`. Then issue a new token and run `superbot-machine enroll` there, or destroy the machine and request a new one. Firewall changes are audited as `machine.firewall_*`. Design: [ADR 0035](../docs/adr/0035-machine-firewall-auto-enroll.md).

### Running Bots on machines

Once machines enroll, choose where Bots run with `MACHINE_ROUTING` in `.env`:

```sh
MACHINE_ROUTING=assigned   # off (default): all here; assigned: assigned users on their machine; on: everyone, or refused
```

Then move users over one at a time, on the server:

```sh
botctl machine assign <user>       # their machine must be running and enrolled
botctl machine placement [<user>]  # where each user's Bots run, and why
botctl machine unassign <user>     # back to this server (with MACHINE_ROUTING=assigned)
```

An assigned user's Bots run only on their machine. If it is down, suspended, outdated, or missing the Bot's harness, the Bot says so and nothing runs here instead. New machines download `botctl` from botd as well as the agent, so keep `botctl` next to `botd` (the installer and image do). On the machine, Bots reach botd through the agent on `127.0.0.1:7444` (loopback only; no new firewall rule). Design: [ADR 0036](../docs/adr/0036-bots-on-the-users-machine.md).

A shared Bot runs on its owner's machine for everyone who uses it. With routing on or assigned, shared Bots are isolated (`SHARED_BOTS=isolated`, the only choice then): a teammate's run gets their own access to other Bots and the server-wide keys only, never the owner's own keys or `USER.md`. So for teammates to use a shared Bot, log its harness in on the owner's machine or save a server-wide key. Design: [ADR 0046](../docs/adr/0046-shared-bots-under-isolation.md).

### Harness CLIs and agent upgrades on machines

To have each machine's agent install harness CLIs by itself once it enrolls, add:

```sh
MACHINE_HARNESSES=claude,codex,pi   # pinned versions, checked by hash; name@version for another
MACHINE_AGENT_UPGRADES=manual       # manual (default): only when you ask; auto: every idle agent, once per build
```

Left unset with a tiers file, machines install the managed tiers' default harnesses (Hermes on the shipped plans); `MACHINE_HARNESSES=none` installs nothing ([ADR 0079](../docs/adr/0079-hermes-default-for-managed-tiers.md)). Until a Bot's harness is installed, its runs are refused with "still being installed". With approvals on, a Codex Bot needs Codex 0.141.0 or newer, here or on its machine: an older one, or one whose version can't be read, is refused before it runs (keep `codex` at its pin, or `codex@<version>` 0.141.0 or newer; on this server, `npm install -g @openai/codex@<version>`) ([ADR 0059](../docs/adr/0059-refusing-guarded-runs-on-old-codex.md)). Agents upgrade themselves to the `superbot-machine` next to `botd`: they download it from botd over the pinned channel, check its SHA-256, swap it in, and restart. If botd can't reach the new agent, the old one is put back. On the server:

```sh
botctl machine agent <user>               # its build, harnesses and upgrade, against botd's
botctl machine upgrade <user>             # upgrade its agent now
botctl machine upgrade <user> hold        # keep it at its build (release: let it go)
botctl machine harnesses <user>           # install MACHINE_HARNESSES now, retrying failures
```

Each step is audited as `machine.harness_*` and `machine.agent_upgrade*`. Machines enrolled before this change can't replace their own agent: rebuild them (below). Harnesses there need a login (below) or an API key in the user's secrets. Design: [ADR 0039](../docs/adr/0039-machine-harnesses-and-agent-upgrades.md).

### Rebuilding machines from before agent upgrades

A machine enrolled before agent upgrades can't update itself. botd can rebuild it in place with today's agent: Linode wipes its disks and reinstalls it from `MACHINE_IMAGE` with today's first-boot setup and a new enrollment token. It keeps its Linode, IP address and firewall. It enrolls again by itself, then gets the harness CLIs, the Bots' own user, screens and the user's folder like a new machine. On the server:

```sh
botctl machine legacy                          # machines whose agent is too old to upgrade, and their rebuilds
botctl machine rebuild <user>                  # rebuild it now (it waits until its agent is idle)
botctl machine rebuild <user> --discard-work   # also when it may hold the user's files
botctl machine rebuild <user> status           # queued, rebuilding, retrying, done, failed or cancelled
botctl machine rebuild <user> cancel           # only before it is sent to Linode
```

A rebuild erases everything on the machine. Bots' memory and the user's facts are kept here, but files Bots made there are lost. So a machine that is or was assigned, or where a Bot ran, is only rebuilt with `--discard-work`: copy off what's needed first, or restore it later from Linode's backups (`MACHINE_BACKUPS`). While a rebuild is underway, that user's Bots say so and don't run. A held agent (`botctl machine upgrade <user> hold`) isn't rebuilt. If the machine doesn't enroll again in time, botd sends the rebuild again after a backoff (1, 2, 4, 8 minutes), up to 5 times, then marks it failed. To rebuild idle machines that never ran Bots by themselves, add:

```sh
MACHINE_LEGACY_REBUILDS=auto   # manual (default): only when you ask; off: never
```

Each step is audited as `machine.rebuild_*` and `machine.rebuilt`. Design: [ADR 0056](../docs/adr/0056-rebuilding-machines-enrolled-before-0039.md).

### Harness logins and the user's folder on machines

Both are off by default. To turn them on, add:

```sh
MACHINE_HARNESS_LOGINS=on       # Claude Code and Codex log in on the user's machine; the login stays there
MACHINE_FOLDER_SYNC=on          # copy the user's folder to their machine when they're assigned
MACHINE_FOLDER_SYNC_MAX_MB=2048 # a bigger folder isn't copied
```

Then, on the server:

```sh
botctl machine harness-login <user> claude  # runs `claude auth login` on their machine; type what it asks for here
botctl machine harness-logins <user>        # which harnesses are logged in there
botctl machine harness-logout <user> claude # remove that login from the machine
botctl machine teammates <user> logins <teammate>         # a teammate's own logins there (ADR 0062)
botctl machine teammates <user> logout <teammate> claude  # remove that teammate's own login
botctl machine folder <user>                # how the last copy went
botctl machine sync <user>                  # copy their folder again now
```

The login runs on the machine. Its sign-in link or code shows in your terminal, and the credentials stay on the machine. With logins on, a Bot whose harness isn't logged in there, and whose owner has no API key for it, says so and doesn't run. Pi and Hermes keep using API keys.

The folder copy sends only what the machine doesn't have. Each file is checked by SHA-256, and a copy cut short picks up where it stopped. Links are never followed. Files changed on the machine, even during the copy, are kept, and nothing there is deleted. Bots wait for the first copy, and agent upgrades wait for a running login. Each step is audited as `machine.harness_login*` and `machine.folder_sync_*`. Design: [ADR 0041](../docs/adr/0041-machine-harness-logins-and-folder-copy.md).

### Bots' own user on machines

The agent on a machine runs as root, and by default so do its Bots. To run them as their own unprivileged user instead, add:

```sh
MACHINE_BOT_USER=on   # Bots, their harness CLIs, logins and the folder copy run as superbot-bots
```

After the next heartbeat, botd asks each idle agent to switch. The agent makes the `superbot-bots` user if it must, hands it the Bots' home (workspace, logins, folder copy) without following links, and from then on runs every harness, login and cleanup as it. The agent's key and the harness CLIs stay root's. Until the switch is done, a Bot says it's being set up and doesn't run; nothing runs on the server instead. New machines get the user at first boot.

Machines already enrolled switch once their agent is botd's build (`MACHINE_AGENT_UPGRADES=auto`, or `botctl machine upgrade <user>`). Agents from before ADR 0039 can't upgrade: rebuild them (`botctl machine rebuild <user>`). Turning the setting off later doesn't switch a machine back. On the server:

```sh
botctl machine bot-user <user>   # ask its agent now, retrying a failure
botctl machine agent <user>      # agent.botUser shows ready, setting_up or failed
```

Each step is audited as `machine.bot_user_*`. Design: [ADR 0043](../docs/adr/0043-bots-own-os-user-on-machines.md).

### Screens on machines

A Bot running on its owner's machine has its browser and files there, so its screen should be there too. With the Bots' own user on, add:

```sh
MACHINE_SCREENS=on            # Bots routed to a machine get their screen there
MACHINE_SCREEN_PORTS=6960-6999  # botd's loopback ports for them (the default); inside the /screen/ route
```

The machine's agent runs the screen (Xvfb, Openbox, D-Bus, voxl) as `superbot-bots`, and botd shows it at the usual `/screen/<port>/` link through the agent's mutual-TLS port. Nothing new opens on the machine. The same Bot access checks apply, and narrowing who may see a Bot gives its screen a new link. New machines install the programs at first boot. If a `voxl` binary sits next to `botd` (or on its `PATH`), they download it from botd; otherwise install it there yourself (`install-computer.sh` builds it). Already enrolled machines need the programs installed and botd's agent build. On the server:

```sh
botctl machine screens <user>             # screens open on their machine, and what's missing there
botctl machine screens <user> close <bot> # close one now
```

Each step is audited as `machine.screen_*`. Design: [ADR 0045](../docs/adr/0045-screens-on-machines.md).

### Teammates' own user on machines

A shared Bot runs on its owner's machine even when a teammate uses it. By default that run is the owner's Bots' user, so its tools could read the owner's folder and harness logins. With the Bots' own user on, add:

```sh
MACHINE_TEAMMATE_USERS=on   # a teammate's run of a shared Bot is their own OS user, in their own home
```

Before a teammate's run, botd asks the owner's agent to make that teammate a user there (`superbot-t-...`, no login shell) with a home of its own under the agent's state folder, readable by no one else. The run works there, can't read the owner's home, and carries a token that stops working once someone else runs the Bot. The machine's harness logins live in the owner's home, never used for teammates. So Claude Code and Codex Bots need a server-wide key for teammates' runs, or, with `MACHINE_HARNESS_LOGINS=on`, the teammate's own login there: they log in from the Bot's details in the app, as their own user, in their own home ([ADR 0062](../docs/adr/0062-teammate-harness-logins.md)). Otherwise the Bot says so and doesn't run. Each person gets their own screen of the Bot (admins can open a teammate's with `?for=<user>`), and every display there takes an X cookie. Agents must be botd's build: an older one refuses teammates' runs as outdated rather than running them as the Bots' user. Off, teammates' runs stay as before.

Audited as `machine.teammate_user_created`, with `teammateUser` on `bot.run_routed` and `harness.invoked`. Design: [ADR 0048](../docs/adr/0048-teammates-own-os-user-on-machines.md).

When a teammate leaves (disabled, deprovisioned by SCIM, or no longer able to run any of the owner's Bots), botd asks the owner's agent to stop their jobs, screens and processes and remove their user and home. A machine that's offline is asked again after each round of heartbeats until it's done. Their work folder goes to the owner's `work/from-teammates/` by default; to delete it instead after a grace period:

```sh
MACHINE_TEAMMATE_FILES=delete     # archive (default) or delete
MACHINE_TEAMMATE_FILES_DAYS=7     # with delete: days it's held first, 0 to 365
```

```sh
botctl machine removals [open|pending|held|done|cancelled|all]  # removals, open ones by default
botctl machine teammates <user>                                 # teammates with a user on their machine
botctl machine teammates <user> remove <teammate>               # remove one now
```

Audited as `machine.teammate_removal_*`, `machine.teammate_removed` and `machine.teammate_files_*`. Design: [ADR 0052](../docs/adr/0052-teammate-offboarding-on-machines.md).

## Approvals after an upgrade

Fresh installs ask before risky actions. An install from before approvals keeps running without them (`bypass`) after `--upgrade`, and botd logs a warning at start. To opt in, on the server:

```sh
sudo -u superbot env SUPERBOT_PASSWORD="$(sudo grep -oP '^AUTH_PASSWORD=\K.*' ~superbot/superbot/.env)" botctl policy set global mode=ask
```

Or use the switch at the bottom of the web app's Approvals window. Don't put `SUPERBOT_PASSWORD` in `.env`: it's for your shell. See [docs/backend.md](../docs/backend.md#approvals).

## Checking approvals through the harnesses

`deploy/harness-e2e.sh` checks, for each logged-in harness CLI on the server, that its hook really goes through SuperBot's approvals with its real model: an allowed command runs, one a deny rule matches is blocked, and a `git push` to a local test repo waits, then runs once approved or fails once denied. It uses a throwaway botd (temp data, a free loopback port), never the running service, and makes a few short model calls per harness. Run it as the user with the logins, from a checkout:

```sh
sudo -u superbot -H bash -lc 'cd ~/superbot && deploy/harness-e2e.sh'
sudo -u superbot -H bash -lc 'cd ~/superbot && deploy/harness-e2e.sh --harness hermes --env-file ~/superbot/.env --model <model>'
```

It ends with `PASS` or `FAIL` per harness and exits non-zero on any failure. Only harness and provider variables from `--env-file` reach the test's botd. `--fake` runs the CI version with a fake model instead (no login). CI runs that version on every change to the hook path, at the pinned CLI versions; bumping a pin is in [ADR 0057](../docs/adr/0057-harness-hook-e2e-tests.md#pinned-to-what-machines-install).

## Measuring a harness's footprint

`deploy/harness-footprint.sh` measures what each harness costs per Bot on this machine: disk for the install and per Bot, what one more Bot adds, cold and warm start, memory (RSS and PSS) and CPU per run, what's left running when idle, several Bots at once, and how many runs fit each tier's machine. It uses a throwaway botd and the fake model by default (no login, no cost), and writes `footprint.md` and `footprint.json`:

```sh
deploy/harness-footprint.sh --install-clis /tmp/clis --out /tmp/footprint            # the pinned CLIs
deploy/harness-footprint.sh --harness hermes --cpus 1 --concurrency 3                 # a Starter's single vCPU
deploy/harness-footprint.sh --harness hermes --real --env-file .env --model <model>   # real model (opt-in, costs)
```

The `harness-e2e` workflow's Footprint job runs it on the pinned CLIs and uploads the report. Results and what they mean: [ADR 0070](../docs/adr/0070-hermes-per-bot-footprint.md), and for Hermes's shared environment, [ADR 0072](../docs/adr/0072-one-hermes-environment-per-computer.md).

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
- **Rotating the key**: keep the old key as `SUPERBOT_MASTER_KEY_PREVIOUS_FILE` (or `SUPERBOT_MASTER_KEY_PREVIOUS`), put a new one in its place, and restart: botd seals everything again under the new key in one transaction and records `secret.master_key_rotated`. Then remove the previous key. Compose: `./init.sh --rotate-master-key`. Steps, checks and recovery: [master key rotation](../docs/ops/master-key-rotation.md) ([ADR 0096](../docs/adr/0096-master-key-rotation.md)).

## Backups and restore

`superbot-backup.timer` archives `DATA_DIR` daily at 03:15 into `~superbot/superbot/backups/superbot-<UTC stamp>.tar.gz` (an online SQLite copy, so safe while Bots run) and keeps `SUPERBOT_BACKUP_RETENTION_DAYS` (default 14). Set `SUPERBOT_BACKUP_AGE_RECIPIENTS` in `.env` to encrypt them with age. Same tool and format as Compose.

```sh
sudo systemctl start superbot-backup.service                     # back up now
sudo -u superbot superbot-restore --check <archive>              # verify an archive without touching live data
sudo systemctl stop superbot superbot-backup.timer               # restore
sudo -u superbot superbot-restore --home /home/superbot - < <archive>
sudo systemctl start superbot superbot-backup.timer
```

botd copies each archive off the host when it has a store ([ADR 0109](../docs/adr/0109-server-backups-off-the-host.md)): `SERVER_BACKUP_S3_*` in `.env`, or the machine backups' store when that is set. The installer writes one from flags, with the keys from its environment; an upgrade without them keeps what `.env` has:

```sh
sudo SERVER_BACKUP_S3_ACCESS_KEY_ID=<access-key-id> SERVER_BACKUP_S3_SECRET_ACCESS_KEY=<secret-access-key> \
  bash -s -- --upgrade --backup-s3-endpoint https://<s3-endpoint> --backup-s3-bucket <bucket> \
  < <(curl -fsSL https://raw.githubusercontent.com/CG-Labs/superbot/main/deploy/install.sh)
botctl backups                                                   # the store, the newest copies, the RPO
```

Without a store, archives stay on the host: the installer's summary, botd's log, the setup checklist and `/metrics` say so. Copy the master key and `.env` off the server yourself: they are never in archives. The default RPO is 24 hours, and only for copies that survive the host. Full procedure (new host, hourly schedule, encryption, the drills CI runs, RPO/RTO targets): [docs/ops/backup-restore.md](../docs/ops/backup-restore.md).

## Computer / screens

For Xvfb, browser automation, and live screens, run [`install-computer.sh`](install-computer.sh) after the base install.

## Audit log retention

Admin actions (logins, Bot and routine changes, approvals, policy, handoffs) are kept in an append-only table in `app.sqlite` ([ADR 0009](../docs/adr/0009-audit-events.md)). Read or export it from the web app's Audit log, or `botctl audit export > audit.csv` on the server with `SUPERBOT_PASSWORD` set.

- `AUDIT_RETENTION_DAYS` in `.env`: unset or `0` keeps events forever (default: they are small, and deleting them can't be undone). `1` to `36500` deletes older events every 6 hours. Restart `botd` after changing it.
- Both installs back it up: the bash timer and the Compose `backup` service take a SQLite `.backup` of `app.sqlite`, audit table included, and keep archives for `SUPERBOT_BACKUP_RETENTION_DAYS` (default 14). So a pruned event still exists in backups for that long; shorten it too if you must erase events.
- Source IPs: the installer's Caddy is on loopback, so `botd` trusts its `X-Forwarded-For`. Compose sets `TRUST_FORWARDED_FOR=1`, since `botd` is reachable only through Caddy.

## Chat history retention

Chat history (every Bot's messages, routine prompts and Bot-to-Bot messages) is kept forever by default. To delete it after a while ([ADR 0098](../docs/adr/0098-chat-retention.md)):

- `CHAT_RETENTION_DAYS` in `.env`: unset or `0` keeps it forever (default). `1` to `36500` deletes older messages when `botd` starts and every 6 hours after, 500 at a time, and records `chat.pruned` in the audit log with how many went (never their text). Restart `botd` after changing it; the change is audited as `chat.retention_changed`.
- Never deleted: a message whose run is still queued or running, and anything in or from the chat of a Bot an admin holds. Hold a Bot for a legal hold or any other reason; a held Bot, or one a held Bot wrote to, can't be deleted until the hold is released. Holds are for admins only, through `botctl` (below) or `GET /api/retention` and `PUT`/`DELETE /api/retention/holds/<bot-id>` (`{"reason": "..."}`), and are audited (`chat.hold_placed`, `chat.hold_changed`, `chat.hold_released`).
- Backups keep deleted messages for `SUPERBOT_BACKUP_RETENTION_DAYS` (default 14), as with the audit log.
- Not covered: each harness's own session files in the Bot's folder (`DATA_DIR/bots/<id>/`, or the Bot's folder on the user's machine), Bots' memory files, and teammates' work archived to an owner's `from-teammates/` folder. For teammates' work, `MACHINE_TEAMMATE_FILES=delete` and `ISOLATION_TEAMMATE_FILES=delete` delete it after a grace period instead of archiving it.

```sh
botctl retention                                   # settings, the last pass, held Bots
botctl retention hold <bot-id> "Legal hold: matter 42"
botctl retention release <bot-id>
```

## Metrics and logs

Both are off by default, and the installer and Compose don't turn them on. Design and the full list of metrics: [ADR 0089](../docs/adr/0089-metrics-and-structured-logs.md).

**Metrics.** `botd` serves Prometheus' text format at `/metrics` on a listener of its own, never on its main port, so Caddy never exposes it:

| Setting in `.env` | Meaning |
|---|---|
| `METRICS_LISTEN` | `off` (default), `on` (`127.0.0.1:9464`), or an address and port such as `0.0.0.0:9464` |
| `METRICS_TOKEN` or `METRICS_TOKEN_FILE` | A bearer token for scrapers, at least 24 characters. Required off loopback: `botd` won't start without it |

The metrics cover requests (by route class, method and status class, with latency), Bot runs (by harness and result, with duration, plus runs underway, waiting and refused), approvals waiting and the oldest one's age, audit events worth alerting on (failed sign-ins, failed notifications, machine backups, RPO breaches, restores), every failed sign-in guess by method and suspicious sign-in patterns ([sign-in alerts](#status-page-and-slo-alerts)), and with managed machines, machines by state, the reconciler, and each tier's RPO status. Labels never hold ids, emails, names, paths or message text.

**Host capacity.** `/metrics` also shows `botd`'s own host (`host="botd"`): its CPU threads, load, memory, and the disks `DATA_DIR` and `WORKSPACE_DIR` are on. With Incus machines it adds each host by its `INCUS_HOSTS` name: what machines' plans take of its `INCUS_CAPACITY` and `INCUS_MAX_MACHINES`, whether it's open for new machines, machines waiting for room, and, read every `MACHINE_RECONCILE_SECONDS`, the host's own CPU threads, load, memory and storage pool space. Design: [ADR 0106](../docs/adr/0106-host-capacity-metrics.md). Alert rules for hosts nearing capacity are in [`prometheus/superbot-capacity.rules.yml`](prometheus/superbot-capacity.rules.yml), tested with `promtool test rules prometheus/superbot-capacity.rules.test.yml`; load them next to the other rules. A Grafana dashboard is in [`grafana/superbot-capacity.json`](grafana/superbot-capacity.json): in Grafana, **Dashboards → New → Import**, upload it, and pick your Prometheus data source; it shows one botd at a time.

**Server backups.** `superbot_server_backup_off_host` is 1 when botd copies its backups off the host and 0 when they stay on it; with a store, `/metrics` adds the RPO, the newest copy's age and time, and whether it is past the RPO. Design: [ADR 0109](../docs/adr/0109-server-backups-off-the-host.md). Alert rules (backups on the host, past the RPO, copies failing) are in [`prometheus/superbot-server-backups.rules.yml`](prometheus/superbot-server-backups.rules.yml), tested with `promtool test rules prometheus/superbot-server-backups.rules.test.yml`.

**Backup encryption.** `superbot_backup_encrypted{target}` is 1 when a backup target is age-encrypted and 0 when it is plain, for `server_archives` (superbot-backup's archives), `server_copies` (botd's off-host copies) and `machines` (Incus machines' off-host backups); `superbot_backup_plaintext_allowed` is 1 with `SUPERBOT_BACKUP_ENCRYPTION=off`. Design: [ADR 0114](../docs/adr/0114-backups-encrypted-by-default.md). The alert rule (a target plain for an hour, unless plain by choice) is in [`prometheus/superbot-backup-encryption.rules.yml`](prometheus/superbot-backup-encryption.rules.yml), tested with `promtool test rules prometheus/superbot-backup-encryption.rules.test.yml`.

**Machine backups.** With Linode machines, `/metrics` shows running machines by tier with Linode Backups on or off and, with `MACHINE_BACKUPS=on` (the default), the oldest newest backup's age, those past the RPO (`MACHINE_BACKUPS_RPO_HOURS`, 26 by default) and the RPO itself, read from what Linode last said of each machine, never per machine. botd also audits and emails each machine that goes past it (`machine.rpo_breached`). Design: [ADR 0110](../docs/adr/0110-linode-machine-recovery-objectives.md); objectives and the restore procedure: [machine recovery](../docs/ops/machine-recovery.md#linode-machines). Alert rules for stale backups and backups left off are in [`prometheus/superbot-backups.rules.yml`](prometheus/superbot-backups.rules.yml), tested with `promtool test rules prometheus/superbot-backups.rules.test.yml`; load them next to the other rules.

On the installer's server, with a Prometheus (or Grafana Alloy, or an OpenTelemetry Collector) on the same host:

```sh
echo 'METRICS_LISTEN=on' | sudo tee -a ~superbot/superbot/.env
sudo systemctl restart superbot
curl -fsS http://127.0.0.1:9464/metrics | head
```

```yaml
# prometheus.yml
scrape_configs:
  - job_name: superbot
    static_configs:
      - targets: ["127.0.0.1:9464"]
```

To scrape from another host, bind an address the scraper reaches, set a token, and let only the scraper through the firewall (`sudo ufw allow from <prometheus-ip> to any port 9464`):

```sh
openssl rand -hex 32 | sudo tee ~superbot/superbot/metrics-token >/dev/null
sudo chown superbot: ~superbot/superbot/metrics-token && sudo chmod 600 ~superbot/superbot/metrics-token
printf 'METRICS_LISTEN=0.0.0.0:9464\nMETRICS_TOKEN_FILE=%s\n' ~superbot/superbot/metrics-token | sudo tee -a ~superbot/superbot/.env
sudo systemctl restart superbot
```

```yaml
scrape_configs:
  - job_name: superbot
    authorization:
      credentials_file: /etc/prometheus/superbot-token   # the same token
    static_configs:
      - targets: ["<server-ip>:9464"]
```

With Docker Compose, `botd` must listen beyond the container's loopback for a scraper to reach it, so a token is needed. In `deploy/docker/.env`, set `METRICS_LISTEN=0.0.0.0:9464` and `METRICS_TOKEN=<openssl rand -hex 32>`. The port isn't published: put the scraper on the `superbot_default` network and scrape `botd:9464`, or add `ports: ["127.0.0.1:9464:9464"]` to `botd` in a `docker-compose.override.yml` to scrape from the host.

**Structured logs.** `LOG_FORMAT=json` (default `text`) makes `botd` print one JSON object per line, on stdout and stderr as before, for journald, Docker's logging drivers, or a shipper such as Vector or Promtail. Each has `ts` (UTC), `level` and `msg`. On top of `botd`'s own lines, it logs every request (`http.request`: request id, method, route template, route class, status, duration) and every run (`message.queued`, `run.started`, `run.finished`: run, message and Bot ids, harness, result, duration). No emails, names, IP addresses, message text, paths as sent or tokens; those stay in the [audit log](#audit-log-retention). Every response has an `X-Request-Id` header, the same id as its log line. An id sent in by a proxy is kept if it's plain (letters, digits, `-`, `_`, `.`, up to 64). `journalctl -u superbot -o cat | jq 'select(.msg == "run.finished")'` lists finished runs.

## Status page and SLO alerts

`botd` serves a public status page at `/status` (and `/status.json` for tools), through Caddy like every other path: no Caddyfile change. It shows the API, database, machines and control plane (with managed machines), harness runners and notifications (once a channel is on), each from `botd`'s own checks and its last few minutes of requests and runs, plus incident notes admins post in the console's **Status** tab. It shows no customer data, counts, hostnames or errors. `/status.json` answers 503 during a major outage, so an uptime probe counts it as down. Design: [ADR 0090](../docs/adr/0090-status-page-and-uptime-slo.md); the objectives it serves: [docs/slo.md](../docs/slo.md).

| Setting in `.env` | Meaning |
|---|---|
| `STATUS_PAGE` | `on` (default) or `off` (both pages answer 404; admins can still prepare incidents) |

Anyone can read what you post, so write for customers: what's affected, what to expect, when you'll update. Known secret values are redacted, but nothing else is.

**Uptime probe.** `botd` can't report its own downtime, so the SLO's uptime is measured from outside: probe `https://<your-domain>/status.json` every 30 seconds from somewhere that isn't the server's host. With Prometheus' blackbox exporter:

```yaml
scrape_configs:
  - job_name: superbot-status
    metrics_path: /probe
    params: { module: [http_2xx] }
    scrape_interval: 30s
    static_configs:
      - targets: ["https://<your-domain>/status.json"]
    relabel_configs:
      - { source_labels: [__address__], target_label: __param_target }
      - { target_label: __address__, replacement: "<blackbox-exporter>:9115" }
```

Uptime Kuma or a hosted uptime checker works too: alert when two checks in a row fail.

**Alert rules.** [`deploy/prometheus/superbot-slo.rules.yml`](prometheus/superbot-slo.rules.yml) has error-budget burn-rate alerts on the [metrics](#metrics-and-logs), and alerts for `botd` not being scraped, the probe failing, and Bot runs failing. They assume the scrape jobs are named `superbot` and `superbot-status`, and a 99.9% target (change `superbot:slo_availability:target` for another):

```sh
sudo cp deploy/prometheus/superbot-slo.rules.yml /etc/prometheus/
promtool check rules /etc/prometheus/superbot-slo.rules.yml
```

```yaml
# prometheus.yml
rule_files: ["/etc/prometheus/superbot-slo.rules.yml"]
```

**Sign-in alerts.** `botd` reports suspicious sign-in patterns on its own, on by default: bursts of failed password, sign-in code and second-factor guesses from one IP or at one account, a sign-in right after one, and admins signing in from a network none of their sessions came from. Each is an `auth.suspicious_sign_in` audit event with the IP and account, and a count in `superbot_signin_suspicious_total`; bursts at one account and sign-ins right after a burst also go to the email and webhook alerts admins turn on under [Approval notifications](#approval-notifications). Thresholds are in `.env` ([ADR 0104](../docs/adr/0104-suspicious-sign-in-alerts.md)):

| Setting in `.env` | Meaning |
|---|---|
| `SIGNIN_ALERTS` | `on` (default) or `off` |
| `SIGNIN_ALERT_IP_FAILURES` | Failed guesses from one IP within the window (default 10, the sign-in limiter's own limit) |
| `SIGNIN_ALERT_ACCOUNT_FAILURES` | Failed guesses at one account, from any IP (default 5) |
| `SIGNIN_ALERT_WINDOW` | `5m` to `24h` (default `15m`) |
| `SIGNIN_ALERT_NEW_IP` | Whose new-network sign-ins are reported: `admins` (default, the owner included), `all` or `off` |

[`deploy/prometheus/superbot-signin.rules.yml`](prometheus/superbot-signin.rules.yml) turns them into alerts: a page when a sign-in works right after a burst, and tickets for attacks on one account, repeated bursts, more than 100 failed guesses in 15 minutes, and admins on new networks. Load it beside the SLO rules:

```sh
sudo cp deploy/prometheus/superbot-signin.rules.yml /etc/prometheus/
promtool check rules /etc/prometheus/superbot-signin.rules.yml
```

```yaml
# prometheus.yml
rule_files: ["/etc/prometheus/superbot-slo.rules.yml", "/etc/prometheus/superbot-signin.rules.yml"]
```

Route `severity: page` to on-call and `severity: ticket` to a queue in Alertmanager.

## Approval notifications

A pending approval can reach people by email and a webhook when no app is open ([ADR 0061](../docs/adr/0061-approval-notifications.md)). Both are off until an admin turns them on; neither needs a paid service.

1. **Links.** Notices link to the approval at `<PUBLIC_URL>/app/home?approval=<id>` and to its audit trail in the console. `PUBLIC_URL` defaults to `SSO_PUBLIC_URL`, else `https://` and the first `ALLOWED_HOSTS` entry, which the installer and Compose set to your domain. Without any, notices go without links.
2. **Email (optional).** Set `SMTP_HOST` and `SMTP_FROM` (like `SuperBot <bots@example.com>`) in `.env`, and if your server signs in, `SMTP_USERNAME` and the password: `SMTP_PASSWORD`, `SMTP_PASSWORD_FILE`, or `botctl secret set SMTP_PASSWORD` (or the console's Server secrets). `SMTP_TLS` is `starttls` (default, port 587), `tls` (port 465) or `none` (only to `127.0.0.1`, port 25); `SMTP_PORT` changes the port. botd refuses to send if STARTTLS isn't offered, and never signs in without TLS. Restart `botd`: its startup line says `Notifications: email ready…`.
3. **Turn it on.** In the app, open the approval policy (Approvals → Edit risky actions…) and use the Notifications card, or the console's Settings. Choose email addresses (and whether each Bot's owner and operators get email too), a webhook URL (a Slack incoming webhook, or any https endpoint; `json` posts are signed with `NOTIFY_WEBHOOK_SECRET` if set), how long to wait first (30 s by default: approvals answered by then send nothing), how often one Bot may notify (120 s: the rest go as one digest), and whether notices show the command or only the Bot and the risk. **Send a test** sends one now.
4. **Per Bot.** A Bot's own approval policy in the app turns email or the webhook on or off for it, and can give it its own webhook URL, for example its team's channel.

Webhook URLs are secrets: botd keeps them in the sealed store (`NOTIFY_WEBHOOK_URL`, and `NOTIFY_WEBHOOK_URL_BOT_<ID>` per Bot) and shows only their host. Set in `.env` instead, they win and change only there. No Bot gets these, the SMTP password or the signing secret. Every send and failure is in the audit log (`notification.sent`, `notification.failed`), and settings changes are `notifications.updated`.

### Push notifications (optional)

The phone app can get a push for a waiting approval or a finished routine ([ADR 0080](../docs/adr/0080-client-push-notifications.md)). Off until you turn it on; no paid service and no app store.

1. **Server.** Set `PUSH_PROVIDER=expo` in `.env` and restart `botd`: its startup line says `push through expo`. If your Expo project turns on enhanced push security, add `EXPO_ACCESS_TOKEN` (`.env` or `botctl secret set EXPO_ACCESS_TOKEN`).
2. **App build.** Whoever builds the app with EAS (a free Expo account) puts the real project id in `apps/client/app.json` (`expo.extra.eas.projectId`) and gives EAS the push credentials it asks for: an FCM V1 key for Android, an APNs key for iOS. These stay with EAS, not botd.
3. **People.** Each person turns it on in the app's Settings, per phone, and chooses approvals, routines, or both. Signing out, or an admin revoking the session, removes the phone.

Pushes name only the Bot, never what it asked; tapping one opens the approval or the Bot's chat. Audited as `push.registered`, `push.updated`, `push.unregistered`, and `notification.sent` / `notification.failed` with `channel: push`.

## Tiers (plans)

Off unless you set `TIERS_FILE`: without it every user is on one open `self-host` tier and Bots run on whatever model they're set to, as before. To sell plans that pick the model ([ADR 0033](../docs/adr/0033-tiers-model-routing.md)):

- Copy [`tiers.example.json`](tiers.example.json) next to `.env`, edit the routes and limits, and set `TIERS_FILE` to its path (and `DEFAULT_TIER` if you like). Restart `botd`; it refuses to start on a bad file.
- Assign users: `botctl user tier alex@example.com pro`, or `default`. `botctl tiers` lists them with their routes.
- Hermes routes can use model endpoints the file names under `providers`, with a `fallback` chain per route ([ADR 0077](../docs/adr/0077-two-providers-through-tier-routing.md)). Save each endpoint's key as the secret its `keySecret` names, e.g. `botctl secret set TIER_ANTHROPIC_KEY < key.txt`. Until then, runs routed to it are refused, fallbacks to it are skipped, and botd warns at startup. Each `baseUrl` must be `https://`; plain `http://` is allowed only to this host (`127.0.0.1`, `::1`, `localhost`), for a local model server or a TLS tunnel, and botd refuses to start on anything else ([ADR 0097](../docs/adr/0097-model-providers-over-https.md)).
- New Bots on a managed tier get its `defaultHarness` (else its first route's harness): Hermes on every shipped plan. `DEFAULT_HARNESS` applies only on open tiers like `self-host`. botd's startup line says which, and warns if a default isn't installed where the runs happen; a run on a harness that isn't installed here is refused, with how to install it (`deploy/install.sh --with-hermes`, or `hermes` in `SUPERBOT_HARNESSES` for Docker) ([ADR 0079](../docs/adr/0079-hermes-default-for-managed-tiers.md)).
- Bots made before keep their harness. To move a managed tier's Bots onto its default, list them first, then move them (Bots mid-run are skipped; run it again later). Each move is audited (`bot.updated` with `via: tier_default`, and `tier.bots_moved`), and starts a fresh session:

  ```sh
  botctl tiers move-bots pro --dry-run
  botctl tiers move-bots pro                       # or one user: --user alex@example.com
  ```
- Upgrading needs no config change. The first start adds the `users.tier` column and the `usage_monthly` table.

Each tier's `limits` ([ADR 0040](../docs/adr/0040-billing-v0-tier-limits.md)) are checked on the server, and a limit left out is unlimited:

| Limit | What it caps | When it's reached |
|-------|--------------|-------------------|
| `maxBots` | Bots a user owns | Creating or taking over another Bot is refused. |
| `monthlyRuns` | Bot runs per calendar month (UTC) | Runs are refused, and the Bot says why. |
| `dailyRoutineRuns` | Routine runs per day (UTC) | Routine firings are skipped until midnight. The Bot says so once a day. |
| `machineType` | The Linode plan (`g6-standard-2`, …) for the user's machine | Admins can't request or resize their machine to another size. Without one, `MACHINE_TIERS` decides as before. |
| `concurrentRuns` | Bot runs at once on the user's machine ([ADR 0073](../docs/adr/0073-concurrent-runs-per-machine.md)) | More runs wait their turn, oldest first; the Bot shows it's queued and can be stopped. Without one, `MAX_CONCURRENT_RUNS` (default 8). Runs on this server share `MAX_CONCURRENT_RUNS` instead. |
| `maxStorageMb` | Storage for a user's files, in MB (1 MB = 1,000,000 bytes): their folder and what botd keeps for them and their Bots ([ADR 0082](../docs/adr/0082-storage-limits-per-tier.md)) | From 90% the Bot warns once a day. At 100% new messages and runs are refused until files are deleted or the plan grows. While a user's Bots work on their own machine, what its agent says the Bots' and teammates' homes hold counts instead of their folder on the server; the OS doesn't count, and the machine's disk size is still `machineType`'s. A machine that hasn't reported yet counts as nothing (the total shows "at least"); `superbot_machine_storage_reports{report="missing"}` finds them ([ADR 0105](../docs/adr/0105-machine-disk-use-in-storage-limits.md)). |

Every refusal is in the audit log (`bot.create_refused`, `routine.run_refused`, `machine.refused`, `bot.run_refused`, `bot.message_refused`). `botctl usage` (or `GET /api/usage`, admins) lists each person's use against their limits and flags anyone over, for example after moving to a smaller plan; the client shows the same on each user.

### Stripe (optional)

**Billing is off while SuperBot is in testing** ([ADR 0068](../docs/adr/0068-no-free-tier.md)): botd reads no `STRIPE_*` setting and makes no Stripe call unless `BILLING=on`, which testing mode refuses. The Plan screen and the console say billing is off. Use no real Stripe keys until billing is turned on.

With `BILLING=on`, off unless `STRIPE_WEBHOOK_SECRET` is set; `/billing/stripe/webhook` answers 404 until then. With only the webhook, botd never calls Stripe: it only receives signed events. Add `STRIPE_SECRET_KEY` to sell plans in the app ([ADR 0042](../docs/adr/0042-billing-checkout-portal-customers.md)). Use test-mode keys until you're ready to charge.

1. In each tier, list its Stripe price ids in `stripePrices` (see [`tiers.example.json`](tiers.example.json)). A price may belong to one tier only. Checkout sells a tier's first price; tiers without one can't be bought.
2. In Stripe, add a webhook endpoint at `https://<your-host>/billing/stripe/webhook` for `customer.subscription.created`, `.updated`, `.deleted`, `checkout.session.completed`, and `customer.deleted`, and put its signing secret (`whsec_…`) in `STRIPE_WEBHOOK_SECRET` (or `STRIPE_WEBHOOK_SECRET_FILE`).
3. For checkout and the customer portal, put a secret key in `STRIPE_SECRET_KEY` (or `STRIPE_SECRET_KEY_FILE`). A restricted key (`rk_…`) with write access to Checkout Sessions and Customer portal is enough. Stripe sends people back to `PUBLIC_URL` (default: `SSO_PUBLIC_URL`, else `https://` and the first `ALLOWED_HOSTS` entry) at `/app/plan`.
4. In Stripe's dashboard, turn on the customer portal (Settings → Billing → Customer portal) and choose what people may do there: update their card, see invoices, switch between your plans' prices, cancel.
5. Set `BILLING=on` and restart `botd`. Its startup line says whether the webhook and checkout are on.

Everyone then sees **Plan** in the client's sidebar: their plan and use against its limits, **Upgrade** buttons for each plan with a price, and **Manage billing** once they have a Stripe customer. Read-only people see their plan but can't buy one. Someone who already pays is sent to the portal instead of a second checkout. Without `STRIPE_SECRET_KEY`, subscriptions you create in Stripe still set tiers if they carry `metadata.superbot_user_id` (the user's id from `botctl users`) or belong to a customer botd has linked.

Each Stripe customer is linked to one user, from a completed checkout or the first subscription event botd can place; the first link stands, and deleting the customer in Stripe removes it. Users are never matched by email. `botctl usage` shows each user's customer.

Usage and token metering ([ADR 0050](../docs/adr/0050-billing-period-token-usage.md)): botd records each run's model tokens and counts runs and tokens per billing period, the paid subscription's period or else the calendar month. People see theirs on the Plan screen and with `botctl usage me`. To report tokens to Stripe for usage-based prices, create a meter in Stripe (aggregation: sum; customer mapping from `stripe_customer_id`), set `STRIPE_METER_EVENT` to its event name, and restart. Off unless set; it needs `STRIPE_SECRET_KEY`, and a restricted key also needs write access to Meter Events.

An active, trialing, or past-due subscription puts the user on its price's tier; a canceled, unpaid, or paused one moves them back to the default tier. Events are checked against their signature and a 5-minute clock window, applied once, and in order. Every change is audited (`user.tier_changed` with `source: stripe`, `billing.subscription_synced`); events botd can't place are audited as `billing.event_ignored`. A subscription event replaces a tier an admin set by hand.

## License

SuperBot has **no free tier** ([ADR 0068](../docs/adr/0068-no-free-tier.md)). A license from CG-Labs names your organisation and sets your plan and seats ([ADR 0038](../docs/adr/0038-self-host-license-key.md)). botd checks it offline, so nothing phones home. Without a license, botd starts and admins can sign in to install one, but Bots don't run and nobody new can be added.

**Testing mode.** A test server (like the dogfood server) runs without a license only when the operator sets `TESTING_MODE=on` in `.env` (or installs with `--testing-mode`) and restarts botd. It lifts the seat limit and keeps billing off. botd's start-up log, the console's License card, and the setup wizard all say "Testing mode". It is never on by default, and a valid license always wins over it.

```sh
sudo deploy/install.sh --upgrade --testing-mode   # test servers only
```

```sh
sudo deploy/install.sh --upgrade --license-file /path/to/license.key   # or, on a running server:
sudo -u superbot env SUPERBOT_PASSWORD="$(sudo grep -oP '^AUTH_PASSWORD=\K.*' ~superbot/superbot/.env)" sh -c 'botctl license install < /path/to/license.key; botctl license'
```

Or paste it into the console under Settings (or the setup wizard's Plans step). These all save `DATA_DIR/license.key` (mode `0600`; backups include it) and take effect at once. `LICENSE_KEY` or `LICENSE_KEY_FILE` in `.env` wins over that file and needs a restart.

- **Seats**: active people other than the owner account. Over the limit, nobody is signed out or disabled, but nobody new can be added or re-enabled (by an admin, SSO sign-up, an approved request, or SCIM) until one is free. The error says so, and `license.seat_refused` is audited.
- **Renewals**: admins are warned 30 days before the license ends. After it ends, it keeps its seats for 14 more days, then Bots stop running and nobody new can be added (unless testing mode is on). Nobody is signed out; install the renewed key any time.
- **A bad key** (changed, signed by someone else, or for something else) never stops botd from starting: it logs why, and the server is unlicensed until a valid key is installed. `botctl license` and the console show the reason. Installs, removals, refusals, and status changes are audited (`license.*`).

## Landing page and sign-ups

`/` is a public landing page and `/get-started` a form to ask for access ([ADR 0022](../docs/adr/0022-landing-and-signups.md)). The built-in admin page moved from `/` to `/console/`; `/app/` is unchanged.

- The installer copies `site/` (plain files, no build) into a root-owned release in `/var/www/superbot-site.releases/` and switches the `/var/www/superbot-site` symlink, like the client, on every install and `--upgrade`. Caddy serves `/`, `/get-started`, and `/site/*` from it. Set `SITE_DIR` to use another path. botd has the same pages built in, so they work without Caddy too.
- Requests wait for an admin: **Requests** in the console or **Users** in the app, or `botctl signup list`, then `botctl signup approve <id>` (prints a one-time sign-in code, once) or `botctl signup reject <id>`. **No email is sent**: give the person their code yourself. Details: [docs/backend.md](../docs/backend.md#sign-ups).
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
- To require two-factor authentication for admins and the owner's password, set `AUTH_MFA=admins` (or `all`) and restart, or choose it in the console's Settings. Each admin sets up an authenticator app at their next code or password sign-in. The password then works only at `/login` or with `botctl login` (which asks for the code), not over HTTP Basic, so scripts that send `SUPERBOT_PASSWORD` need a `SUPERBOT_TOKEN` instead ([ADR 0094](../docs/adr/0094-totp-second-factor.md)).
- After upgrading to a release with the [setup wizard](#setup-wizard), admins see it once in the console. Finish or hide it there, or run `botctl setup done`.
- Downgrading: older botd ignores the new tables and keeps working with `AUTH_PASSWORD`.

## Docker Compose (supported)

`botd` + Caddy (automatic HTTPS) + a daily backup job, from [`deploy/docker/`](docker/). Needs Docker Engine with the Compose v2 plugin, on amd64 or arm64. Compose pulls the published images, `ghcr.io/cg-labs/superbot` and `ghcr.io/cg-labs/superbot-caddy`, or [builds them from the checkout](#build-from-source). Design: [ADR 0006](../docs/adr/0006-docker-compose.md), [ADR 0084](../docs/adr/0084-published-image-with-computer-use.md).

### Quick start

```sh
git clone https://github.com/CG-Labs/superbot.git
cd superbot/deploy/docker
./init.sh --domain bots.example.com --tz Europe/Jersey --user-name "Alex"
docker compose up -d
docker compose logs -f botd
```

`init.sh` writes `.env` (mode `0600`) from [`.env.example`](docker/.env.example) with a random `AUTH_PASSWORD`, prints it once, and never replaces it on re-run. Open `https://bots.example.com/app/` for the app, or `https://bots.example.com/console/` for the built-in admin page, and sign in with that password; the console opens on the [setup wizard](#setup-wizard). DNS for the domain must point at the host, with ports 80 and 443 open.

Without a domain, `./init.sh` gives plain HTTP at `http://localhost`, published on `127.0.0.1` only. For another machine, use a domain (HTTPS); over plain HTTP the password crosses the network in clear text.

| Service | Role |
|---------|------|
| `botd` | Server, web app, harness CLIs, and the Bots' [screens and browser](#screens-and-computer-use-in-docker). Runs as uid `10001`, port 3000 not published. Only the capabilities `sudo` needs to start [each user's runs as their own account](#per-user-accounts-in-docker). |
| `caddy` | `caddy:2` plus the [web client](#web-client) and [landing page](#landing-page-and-sign-ups) (`Dockerfile` target `caddy`, published as `superbot-caddy`). Publishes 80/443 on `SUPERBOT_BIND`, serves the landing page at `/` and the client at `/app/`, Bots' screens at `/screen/<port>/`, and proxies everything else to `botd` (SSE unbuffered). |
| `backup` | Archives `DATA_DIR` at start and every `SUPERBOT_BACKUP_INTERVAL` seconds. No network. |

| Volume | Mounted at | Holds |
|--------|------------|-------|
| `data` | `/data` (`DATA_DIR`) | SQLite database, Bot memory, each user's `users/<id>/USER.md`. Back this up. |
| `workspace` | `/workspace` (`WORKSPACE_DIR`) | Each user's working folder, `users/<id>/`, shared by that user's Bots. |
| `home` | `/home/superbot` | Harness logins and sessions (`~/.claude`, `~/.claude.json`, `~/.codex`, `~/.pi`), runtime `npm i -g` installs. Hermes Agent keeps its per-Bot data in `data` instead. |
| `backups` | `/backups` | Backup archives. |
| `users` | `/srv/superbot/users` | With [per-user accounts](#per-user-accounts-in-docker): each user's home (harness logins), workspace, memory copies, and Bots' harness state. |
| `caddy-data`, `caddy-config` | Caddy | Certificates and ACME account. |

`init.sh` also writes a random `SUPERBOT_MASTER_KEY` once, which encrypts saved secrets ([master key](#master-key)); Compose refuses to start without it. To replace it, run `./init.sh --rotate-master-key` and follow [master key rotation](../docs/ops/master-key-rotation.md). Save API keys for the Bots encrypted instead of in `.env` with `SUPERBOT_PASSWORD=<AUTH_PASSWORD> docker compose exec -T -e SUPERBOT_PASSWORD botd botctl secret set OPENAI_API_KEY < key.txt`.

Secure by default: Compose refuses to start without `AUTH_PASSWORD`; the image sets `HOST=0.0.0.0`, so `botd` itself also refuses to run without it, and `ALLOW_NO_AUTH` is forced off. `ALLOWED_HOSTS` always includes `SUPERBOT_DOMAIN` (or `localhost`); add other names, such as `localhost:8080` when you change `SUPERBOT_HTTP_PORT`, in `.env`.

Every other `botd` setting (`TZ`, `USER_NAME`, `DEFAULT_HARNESS`, `CORS_ORIGINS`, `RUN_TIMEOUT_MINUTES`, …) goes in `.env`; apply changes with `docker compose up -d`. For tiers ([ADR 0033](../docs/adr/0033-tiers-model-routing.md)), copy the file into the data volume (`docker compose cp tiers.json botd:/data/tiers.json`) and set `TIERS_FILE=/data/tiers.json`; without it every user is on the open `self-host` tier, as before. For a [license](#license), paste the key into the console (it lands in the `data` volume) or set `LICENSE_KEY` in `.env`. `HOST`, `PORT`, `DATA_DIR`, and `WORKSPACE_DIR` are fixed by the image.

### Images and versions

Each merge to `main` and each release publishes both images for amd64 and arm64 to GHCR. Choose one with `SUPERBOT_VERSION` in `.env`:

| `SUPERBOT_VERSION` | What |
|--------------------|------|
| `main` (default) | The latest merge to `main`, and a weekly rebuild with Debian's security fixes |
| `1.2.3`, `1.2`, `1`, `latest` | A release, once there are any; what changed in each is in [CHANGELOG.md](../CHANGELOG.md) and on its GitHub release |
| `sha-<7-char commit>` | Exactly the build of that commit on `main` |

Set `SUPERBOT_IMAGE` and `SUPERBOT_CADDY_IMAGE` to use images from somewhere else (a mirror, or your own registry).

### Verifying the images

Every published image is signed keylessly with [cosign](https://docs.sigstore.dev/cosign/) by the `docker` workflow, under its GitHub identity, and carries SLSA build provenance and an SBOM ([ADR 0101](../docs/adr/0101-image-scanning-and-signing.md)). Images published before that are unsigned. The `staging-*` tags are the workflow's own, used to sign an image before its public tags move; don't run them. Check an image before you run it, with cosign 3 or later:

```sh
cosign verify ghcr.io/cg-labs/superbot:main \
  --certificate-identity https://github.com/CG-Labs/superbot/.github/workflows/docker.yml@refs/heads/main \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

For a release, the identity ends in the tag instead: `--certificate-identity https://github.com/CG-Labs/superbot/.github/workflows/docker.yml@refs/tags/v1.2.3` with `ghcr.io/cg-labs/superbot:1.2.3`. Check `ghcr.io/cg-labs/superbot-caddy` the same way. Accept no other identity: a signature from a fork, another workflow or another branch is not ours.

Check the build provenance (which commit and workflow run built it) with the GitHub CLI:

```sh
gh attestation verify oci://ghcr.io/cg-labs/superbot:main \
  --repo CG-Labs/superbot \
  --signer-workflow CG-Labs/superbot/.github/workflows/docker.yml \
  --source-ref refs/heads/main
```

Use `--source-ref refs/tags/v1.2.3` for a release. Read each platform's SBOM (SPDX) and BuildKit's own provenance with `docker buildx imagetools inspect ghcr.io/cg-labs/superbot:main --format '{{ json (index .SBOM "linux/amd64").SPDX }}'` (or `.Provenance` and `.SLSA`).

A tag moves to newer builds, so to run exactly what you verified, verify by digest and pin it: take the digest `cosign verify` prints (`docker-manifest-digest`) and set `SUPERBOT_IMAGE=ghcr.io/cg-labs/superbot@sha256:<digest>` in `.env` (and `SUPERBOT_CADDY_IMAGE` likewise). Each image's vulnerability scan is in the workflow run's `image-scan-<arch>` artifact (JSON, SARIF and a table), and in the repository's code scanning alerts for its maintainers.

### Build from source

To build both images from the checkout instead, for another set of harness CLIs, Hermes Agent, pinned CLI versions, or a change of your own:

```sh
./init.sh --from-source          # writes COMPOSE_FILE=docker-compose.yml:docker-compose.build.yml to .env
docker compose up -d --build
```

Or pass both files each time: `docker compose -f docker-compose.yml -f docker-compose.build.yml up -d --build`. `./init.sh --published` goes back to the published images. A build takes several minutes and a few GB of build cache.

### Harness CLIs and logins

The image bakes in Claude Code, Codex, and Pi (`npm i -g` at build time). When [building from source](#build-from-source), pick a subset with `SUPERBOT_HARNESSES` in `.env` (e.g. `claude`, or empty for none), then `docker compose build botd && docker compose up -d`. Pin versions with build args, e.g. `docker compose build --build-arg CLAUDE_CODE_VERSION=2.1.328 botd` (`CODEX_VERSION` and `PI_VERSION` too).

Hermes Agent is opt-in and needs [building from source](#build-from-source): add it with `SUPERBOT_HARNESSES=claude codex pi hermes` (about 2.5 GB more in the image). The image installs it in `/opt/hermes`, pinned with `HERMES_COMMIT`, and its Bots share its one environment ([ADR 0072](../docs/adr/0072-one-hermes-environment-per-computer.md)). It has no login: save a provider key with `botctl secret set` (above) and, if needed, set `SUPERBOT_HERMES_PROVIDER` and `SUPERBOT_HERMES_BASE_URL` in `.env`. See [backend docs](../docs/backend.md#hermes-agent).

Log in once inside the container, as the `superbot` user that runs the Bots. Logins are stored in the `home` volume and survive upgrades and container recreation:

| Harness | Interactive login | Or put in `.env` |
|---------|-------------------|------------------|
| Claude Code | `docker compose exec -it botd claude auth login` (open the URL, paste the code back) | `CLAUDE_CODE_OAUTH_TOKEN` (from `claude setup-token`) or `ANTHROPIC_API_KEY` |
| Codex | `docker compose exec -it botd codex login --device-auth` | `OPENAI_API_KEY`, or store it: `docker compose exec -T botd codex login --with-api-key < key.txt` |
| Pi | `docker compose exec -it botd pi auth login <provider> --no-browser` | A provider key, e.g. `OPENROUTER_API_KEY` |
| Hermes Agent | None | A provider key, e.g. `OPENROUTER_API_KEY`, best saved with `botctl secret set` |

Check with `claude auth status`, `codex login status`, or `pi auth check` (same `docker compose exec` prefix).

With [per-user accounts](#per-user-accounts-in-docker), log Claude Code and Codex in per user instead: `docker compose exec -it -e SUPERBOT_PASSWORD botd botctl user harness-login <user> claude` (or `codex`), with `SUPERBOT_PASSWORD` set to `AUTH_PASSWORD`. Those logins live in the `users` volume.

Keys in `.env` pass through to the Bots, like the bash install. Claude Code's self-updater is off (`DISABLE_AUTOUPDATER=1`); CLIs update when you rebuild. For a newer CLI without a rebuild, `docker compose exec botd npm i -g @openai/codex@latest` installs it into the `home` volume, where it wins on `PATH` until you `npm rm -g` it.

### Per-user accounts in Docker

New `.env` files have `ISOLATION=users`: each user's Bots run as their own Unix account inside the container, which can't read the `data` volume, the database, the `home` volume or botd's env (where `.env`'s secrets are). An `.env` from before has no `ISOLATION` line and stays off; botd's log says so. Turn it on or off with `./init.sh --isolation` or `--no-isolation`, then `docker compose up -d`. Design: [ADR 0058](../docs/adr/0058-harness-os-user-by-default.md).

How it works: the image has `sudo` (its only setuid program), `superbot-run`, and the root helper `superbot-userctl`, with the same sudo rules as the [bash install](#one-unix-account-per-user). The `botd` service adds back `CHOWN`, `DAC_OVERRIDE`, `FOWNER`, `FSETID`, `SETUID`, `SETGID` and `AUDIT_WRITE`, and turns `no-new-privileges` off, so `sudo` works; runs drop all of them. Accounts and their folders live in the `users` volume. A recreated container makes each account again, with the uid that owns its files.

Harness CLIs must be in the image (`SUPERBOT_HARNESSES`): ones installed later with `npm i -g` land in the `home` volume, which accounts can't open. Runs see the container's other processes (but not their env); the bash install's systemd unit hides them. Turning it on doesn't move a user's files from the `workspace` volume: copy them into `/srv/superbot/users/<id>/workspace/` as with the [bash install](#one-unix-account-per-user).

### Upgrade

```sh
cd superbot && git pull                          # for changes to the compose files and Caddyfile
cd deploy/docker
docker compose exec botd superbot-backup        # optional: archive first
docker compose pull && docker compose up -d
```

Volumes are kept. The schema migrates on start, as with the bash install. The `caddy` image carries the matching web client. To pin a version, set `SUPERBOT_VERSION` (see [Images and versions](#images-and-versions)). When [building from source](#build-from-source), run `docker compose build --pull && docker compose up -d` instead, after `git checkout <tag>` to pin a release.

Upgrading from before the published images: Compose built the images locally then, and now pulls them, so the next `docker compose up -d` switches to the published ones. Volumes don't change. If you baked in Hermes Agent or another set of harness CLIs, run `./init.sh --from-source` first to keep building your own.

Upgrading from a release before secrets: run `./init.sh` once first. It adds a random `SUPERBOT_MASTER_KEY` to `.env` (Compose refuses to start without one) and leaves everything else alone. The key encrypts saved secrets and approvals' tool input ([master key](#master-key)); it stays in `.env` on the host, never in a volume.

### Backup and restore

The `backup` service writes `superbot-<UTC stamp>.tar.gz` to the `backups` volume (default every 24 h, keeps 14 days: `SUPERBOT_BACKUP_INTERVAL`, `SUPERBOT_BACKUP_RETENTION_DAYS`). Each archive has an online SQLite `.backup` copy of `app.sqlite` plus the rest of `DATA_DIR` (Bot memory, each user's `USER.md`), so it is safe while Bots are running.

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

To encrypt archives, set `SUPERBOT_BACKUP_AGE_RECIPIENTS` in `.env` and `docker compose up -d`; restoring then needs the identity (`--identity`). To copy them off the host, set `SERVER_BACKUP_S3_BUCKET`, `_ENDPOINT`, `_ACCESS_KEY_ID` and `_SECRET_ACCESS_KEY` in `.env` and `docker compose up -d`: botd reads the `backups` volume and copies each new archive within a minute, with an RPO of `SUPERBOT_BACKUP_INTERVAL` plus 2 hours ([ADR 0109](../docs/adr/0109-server-backups-off-the-host.md)); without them, botd warns that archives stay on the host. Check an archive without touching live data with `superbot-restore --check`. New host, schedule, and the restore drill: [docs/ops/backup-restore.md](../docs/ops/backup-restore.md).

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

The two installs are independent; do not run both on one host (both want ports 80/443). Both use the same `superbot-backup` archive format, so:

```sh
sudo systemctl disable --now superbot superbot-backup.timer caddy
sudo -u superbot superbot-backup --home /home/superbot - > superbot-migrate.tar.gz
cd superbot/deploy/docker && ./init.sh --domain bots.example.com   # reuse AUTH_PASSWORD from ~superbot/superbot/.env if you like
# Carry the master key over (replacing the one init.sh made), or saved secrets won't open:
key=$(sudo cat ~superbot/.config/superbot/master.key) && sed -i "s|^SUPERBOT_MASTER_KEY=.*|SUPERBOT_MASTER_KEY='$key'|" .env
docker compose up -d && docker compose stop botd backup
docker compose run --rm --no-deps -T botd superbot-restore - < superbot-migrate.tar.gz
docker compose up -d
```

Then log the harness CLIs in again inside the container.

### Screens and computer use in Docker

The image has the Bots' computer ([docs/computer.md](../docs/computer.md)): each Bot's virtual screen (Xvfb, Openbox, D-Bus), a browser (agent-browser driving Debian's Chromium), agent-desktop, and voxl for the live view you watch and take over in the app. It's the stack [`install-computer.sh`](install-computer.sh) installs on a bash install, with Chromium in place of Chrome for Testing so it works on arm64 too.

As on a bash install, botd turns screens off while [per-user accounts](#per-user-accounts-in-docker) are on: an X display belongs to botd's account, and per-user screens don't exist yet. The log says `Screens: off (per-user screens ...)`. To use screens, run every Bot as botd's account:

```sh
./init.sh --no-isolation && docker compose up -d
docker compose logs botd | grep Screens        # Screens: on (viewers listen on 0.0.0.0, SCREEN_ADDR).
```

Each screen's viewer listens in the `botd` container on ports 6901 and up (`SCREEN_BASE`, `MAX_SCREENS`). Compose sets `SCREEN_ADDR=0.0.0.0` so Caddy, on the compose network, can serve them at `/screen/<port>/`; no port is published, and each viewer checks its own token. `botd` gets 1 GB of shared memory for Chromium. Size the host for about 0.5 to 1 GB of RAM per open screen (`MAX_SCREENS`, default 3), and set `SCREEN_SIZE` and `SCREEN_IDLE_MINUTES` in `.env` as on a bash install. The bash install's earlyoom safety net isn't in the container: cap memory with Docker if the host is tight.

Chromium runs with its sandbox on ([ADR 0107](../docs/adr/0107-chromium-sandbox-in-the-container.md)). Compose gives `botd` [`seccomp-chromium.json`](docker/seccomp-chromium.json): Docker's default seccomp profile plus the user, PID and network namespaces the sandbox needs, so keep it next to `docker-compose.yml`. The image's `chromium` drops the `--no-sandbox` agent-browser adds in containers. botd checks at start and logs `Chromium sandbox: on (checked ...)`. If the host can't allow it (some rootless or Kubernetes runtimes), the log says `Chromium sandbox: on, but Chromium can't start sandboxed here` and browsers won't open; set `SUPERBOT_CHROMIUM_SANDBOX=off` in `.env` to run Chromium without its sandbox, which the log then warns about on every start. Running the image without Compose needs `--security-opt seccomp=deploy/docker/seccomp-chromium.json` too.

Building from source, `SUPERBOT_COMPUTER=off` leaves all of this out (about 1.2 GB smaller).

### Check the setup

[`deploy/docker/smoke-test.sh`](docker/smoke-test.sh) builds the images and runs the stack in an isolated project (own volumes and ports 18080/18443): health, auth, Host allowlist, the landing page, the web client at `/app/`, harness CLIs, SSE through Caddy, saved secrets (encrypted, names only, absent from logs and backups), per-user accounts (on for a new `.env`, unable to read `/data` or botd's env, the same uid after a recreate), a backup/restore round trip, and screens (off under per-user accounts; with `ISOLATION=off`, a Bot's screen starts, its live view opens through Caddy only with its token, and Chromium opens on it, sandboxed, and refuses to start without the seccomp profile), then removes everything. `SMOKE_NO_BUILD=1` tests the published images instead (`SUPERBOT_VERSION`). CI runs it on amd64 and arm64 on every change to the image, before publishing.