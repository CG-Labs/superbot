# Backup and restore

How to back up a SuperBot server, restore it in place or onto a new host, and prove it works. Applies to both supported installs: the [VPS installer](../../deploy/README.md) (systemd) and [Docker Compose](../../deploy/README.md#docker-compose-supported). Design: [ADR 0030](../adr/0030-backup-restore-drill.md).

## Targets

| | Default (self-host) | Recommended for teams and managed |
|--|--|--|
| **RPO** (data you can lose) | 24 hours: one archive a day (03:15 ± 15 min, or every `SUPERBOT_BACKUP_INTERVAL` seconds in Compose) | 1 hour: hourly archives, copied off the host |
| **RTO** (time to serve again) | 1 hour on a new host: install (about 20 to 30 minutes, mostly the build) plus restore | Same |
| Restore step alone | 5 minutes (the drills' budget; a small install takes seconds) | Same |

The RPO only holds for archives that are **off the host**. Archives on the server's own disk die with it.

## What a backup holds

`superbot-backup` writes `superbot-<UTC stamp>.tar.gz` (or `.tar.gz.age` when [encrypted](#encryption)). Both installs use the same tool and the same format, so archives move between them.

| In the archive | Not in the archive | Keep it off-host yourself |
|--|--|--|
| `app.sqlite` as an online SQLite `.backup` copy (users, sessions, Bots, chats, routines, approvals, sealed secrets, the audit log), Bot memory (`bots/`), user files (`USER.md`, `users/`), Hermes per-Bot data, `.superbot-backup` (format and time) | The master key (by design, [ADR 0010](../adr/0010-secrets.md)); `.env`; the workspace; harness logins (`~/.claude`, `~/.codex`, …); per-run screen state; Caddy certificates | **Master key** (installer: `~superbot/.config/superbot/master.key`; Compose: `SUPERBOT_MASTER_KEY` in `deploy/docker/.env`). **`.env`** (login password, SSO settings). **The age identity**, if you encrypt. |

Without the master key, saved secrets and approvals' tool input can't be read; botd refuses to start on the restored data until you give it the right key or tell it to drop them ([master key](../../deploy/README.md#master-key)).

The copy is safe while Bots are running: SQLite's `.backup` takes a consistent snapshot.

## Schedule

**Installer.** `superbot-backup.timer` runs daily (`Persistent=true`, so a missed run happens at boot). Archives go to `~superbot/superbot/backups` (or `BACKUP_DIR` in `.env`; a folder inside `DATA_DIR` is left out of archives) and are kept `SUPERBOT_BACKUP_RETENTION_DAYS` (default 14). For a 1-hour RPO, add a drop-in, which upgrades keep:

```sh
sudo systemctl edit superbot-backup.timer
# [Timer]
# OnCalendar=
# OnCalendar=hourly
```

Back up now: `sudo systemctl start superbot-backup.service`. Check runs: `systemctl list-timers superbot-backup.timer`, `journalctl -u superbot-backup`.

**Compose.** The `backup` service archives at start and every `SUPERBOT_BACKUP_INTERVAL` seconds (default `86400`; `3600` for hourly) into the `backups` volume. Back up now: `docker compose exec botd superbot-backup`.

## Off-site copies

Copy archives off the host on the same schedule, with whatever you trust: `rclone copy`, `aws s3 cp`, `restic`, `rsync` to another machine. For example, on an installer host, a root cron job or timer after each backup:

```sh
rclone copy --max-age 2h ~superbot/superbot/backups remote:superbot-backups
```

For Compose, stream the archive straight to the host: `docker compose exec -T botd superbot-backup - > superbot-$(date -u +%Y%m%d-%H%M).tar.gz`.

Copy the master key and `.env` off-host once, and again whenever they change. Keep them apart from the archives.

## Encryption

Optional, with [age](https://age-encryption.org). The server holds only the public key, so neither it nor your off-site storage can read old archives; restoring needs the identity (private key) you keep elsewhere.

```sh
age-keygen -o superbot-backup-identity.txt     # on your laptop; store it like a password
# prints: Public key: age1...
```

Put the public key in the server's `.env` (installer) or `deploy/docker/.env` (Compose), comma-separating several:

```sh
SUPERBOT_BACKUP_AGE_RECIPIENTS=age1...
```

Then `sudo systemctl start superbot-backup.service` or `docker compose up -d`. If the setting is there but `age` is missing, backups fail rather than write plaintext. The installer installs `age` and the image includes it.

## Check an archive

`superbot-restore --check` unpacks to a temporary folder, runs SQLite's `integrity_check`, and prints what's inside, without touching the live data. Run it on every off-site copy you depend on, at least monthly.

```sh
sudo -u superbot superbot-restore --check /home/superbot/superbot/backups/superbot-20261119-031500.tar.gz
docker compose run --rm --no-deps -T botd superbot-restore --check - < superbot-20261119.tar.gz
# encrypted: add --identity FILE (Compose: -v "$PWD/identity.txt:/run/age-identity:ro" ... --identity /run/age-identity)
```

```text
created:          2026-11-19T03:15:02Z
newest audit:     2026-11-19T03:14:40Z
users:            12
bots:             9
...
needs master key: yes
```

`newest audit` is the last change the archive holds: the start of the data you'd lose.

## Restore

`superbot-restore` refuses to run while botd is up, checks the archive before it changes anything, swaps `DATA_DIR` in one step, and keeps the old contents in `DATA_DIR/.pre-restore-<stamp>/` until you delete them. Run it as the user that owns `DATA_DIR`.

### Installer, same host

```sh
sudo systemctl stop superbot superbot-backup.timer
sudo -u superbot superbot-restore --home /home/superbot - < superbot-<stamp>.tar.gz[.age]   # add --identity FILE if encrypted
sudo systemctl start superbot superbot-backup.timer
curl -fsS http://127.0.0.1:3000/healthz                                                    # {"ok":true}
```

### Installer, new host

1. Run the installer as usual ([deploy/README.md](../../deploy/README.md)). It makes a new password and master key; both are replaced below.
2. Stop botd and put back the old `.env` **first**, so the restore and the key use its paths (a custom `DATA_DIR` or `SUPERBOT_MASTER_KEY_FILE`). If the domain changed, edit `ALLOWED_HOSTS` and `CORS_ORIGINS` in it now.
3. Put the old master key where that `.env` expects it, make sure `DATA_DIR` exists for `superbot`, then restore and start (owner `superbot`, mode `0600` throughout):

```sh
sudo systemctl stop superbot superbot-backup.timer
env=/home/superbot/superbot/.env
sudo install -m 0600 -o superbot -g superbot old.env "$env"
setting() { sudo sed -n "s/^$1=//p" "$env" | tail -n 1 | tr -d "\"'"; }
key=$(setting SUPERBOT_MASTER_KEY_FILE)        # empty if the key is inline as SUPERBOT_MASTER_KEY
if [ -n "$key" ]; then
  sudo install -d -m 0700 -o superbot -g superbot "$(dirname "$key")"
  sudo install -m 0600 -o superbot -g superbot old-master.key "$key"
fi
sudo install -d -m 0700 -o superbot -g superbot "$(setting DATA_DIR)"
sudo -u superbot superbot-restore --home /home/superbot - < superbot-<stamp>.tar.gz[.age]   # add --identity FILE if encrypted
sudo systemctl start superbot superbot-backup.timer
curl -fsS http://127.0.0.1:3000/healthz
```

4. If the domain changed, update the SSO redirect URLs at your IdP (and re-run the installer with `--domain` so Caddy serves the new name).
5. Log the harness CLIs in again (`sudo -iu superbot claude login`, …). Restore the workspace from your own copy if you keep one.

With the wrong master key, botd logs `the master key doesn't open this database's encrypted values (wrong key)` and exits; fix the key and start again.

### Compose, same host

```sh
docker compose stop botd backup
docker compose run --rm --no-deps -T botd superbot-restore - < superbot-<stamp>.tar.gz
docker compose up -d
```

Encrypted: mount the identity and pass it, e.g. `docker compose run --rm --no-deps -T -v "$PWD/identity.txt:/run/age-identity:ro" botd superbot-restore --identity /run/age-identity - < superbot-<stamp>.tar.gz.age`. The file must be readable by uid `10001`.

### Compose, new host

```sh
git clone https://github.com/CG-Labs/superbot.git && cd superbot/deploy/docker
cp /path/to/old/.env .env          # same AUTH_PASSWORD and SUPERBOT_MASTER_KEY; or run ./init.sh and copy the key line in
docker compose up -d --wait          # add --build if .env has COMPOSE_FILE (built from source)
docker compose stop botd backup
docker compose run --rm --no-deps -T botd superbot-restore - < superbot-<stamp>.tar.gz
docker compose up -d
```

Then log the harness CLIs in again inside the container.

## Drills

A restore you haven't tried is a hope. Two drills run in CI on every change to the server, the installer, or the image, and fail the build if the data doesn't come back or the restore runs over budget:

| Drill | Where | What it proves |
|--|--|--|
| Installer | [`deploy/backup-drill.sh`](../../deploy/backup-drill.sh), job `backup-drill` in `server.yml` | Installs the real systemd units with the installer's functions, seeds a Bot, a sealed secret, and a user, backs up through `superbot-backup.service` with age encryption, checks the archive holds no secret or key, checks the timer is persistent and fires within the RPO, then deletes the service user (data, `.env`, master key, local archives), reinstalls, shows botd refusing the new key, restores the off-host copies, and checks the data, the secret, the user, and the audit log. A change made after the backup is gone, as the RPO says. Restore budget: `SUPERBOT_DRILL_RTO_SECONDS` (300). |
| Compose | [`deploy/docker/smoke-test.sh`](../../deploy/docker/smoke-test.sh), job `compose-smoke` in `docker.yml` | The `backup` service writes an age-encrypted archive; `--check` refuses it without the identity; then every volume is deleted, a fresh stack starts empty, and the archive is restored and checked. Restore budget: `SMOKE_RTO_SECONDS` (300). |
| Scripts | [`deploy/test-backup.sh`](../../deploy/test-backup.sh), job `backup-scripts` | Retention, name collisions, the installer's `.env` layout, encryption failures, damaged, foreign, and newer-format archives refused before anything changes. |

**Your own drill, quarterly** (and after any big upgrade): restore the latest **off-site** archive onto a scratch server following [Installer, new host](#installer-new-host) or [Compose, new host](#compose-new-host), sign in, and check a few Bots and chats. Time it from "server gone" to `/healthz`: that is your real RTO. Write down the date, the archive's `newest audit`, and the time taken. On a throwaway VM you can also run the installer drill itself (it deletes the `superbot` user, so never on a real server):

```sh
cargo build --release
sudo SUPERBOT_DRILL_THROWAWAY=1 deploy/backup-drill.sh target/release
```

Don't run a restored copy next to the live server to "test" it: botd would run the same routines and could act twice.

## Per-user machines (managed hosting)

This guide covers botd's own data. Users' machines ([ADR 0025](../adr/0025-control-plane-linode.md)) are backed up separately:

- **Incus containers**: off-host backups to S3-compatible storage, age-encrypted, kept per tier, with an admin restore that makes the machine enroll anew ([ADR 0071](../adr/0071-off-host-machine-backups.md), [setup](incus-containers.md#7-off-host-backups-optional)). Off unless `MACHINE_BACKUP_S3_BUCKET` is set. Each tier has a backup schedule, an RPO and an RTO that botd checks and alerts on ([ADR 0074](../adr/0074-machine-rpo-and-rto.md), [machine recovery](machine-recovery.md)): by default every 24 hours with an RPO of 26 (pro every 12, RPO 14; max every 6, RPO 8), and an RTO of 60 minutes.
- **Linode VMs**: Linode's own backups (`MACHINE_BACKUPS=on`, the default), restored from Linode's console.

Keep the age identity for machine backups off botd's host too, like the one for server archives. Without it, encrypted machine backups can't be restored.

A restored botd database still knows every backup's object key, so after a server restore, `botctl machine backups` lists them and machine restores work as before. Each object has a JSON manifest beside it, so the bucket can still be read without the database.

## Not covered yet

- **Managed hosting**: a contractual RPO and RTO for machines, and exporting Linode machines to customer storage, are follow-ups on [#40](https://github.com/CG-Labs/superbot/issues/40).
- The workspace and harness logins: copy the volumes or folders yourself if you need them ([Compose example](../../deploy/README.md#backup-and-restore)).
- Point-in-time recovery between archives (SQLite WAL shipping, e.g. Litestream) would take the RPO under an hour; not planned for M3.
