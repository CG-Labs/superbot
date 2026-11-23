# Runbook: upgrades

Planning an upgrade, or one that went wrong: botd won't start on the new version, starts but something broke, or has to be undone. Severity: [2](severity.md#severities) if an upgrade left the server down for everyone (Severity 1 once it's past the plan's response target with no way back), 3 if it's up but something broke, 4 for planning one. For offline installs, the [air-gapped runbook](runbook-air-gapped.md) covers carrying the bundle in; this page covers the rest.

The rule: **back up just before, check before and after, and go back by restoring the backup, never by starting an older botd on a newer database.** botd changes its database's schema on its first start on a new version; an older botd doesn't know those changes.

## First five minutes

When an upgrade has gone wrong:

1. **Is botd up?** `systemctl status superbot` (installer) or `docker compose ps` (Compose). If it answers `/healthz` but something broke, skip to [up but broken](#up-but-broken).
2. **Why it stopped:** `sudo botd support check --home /home/superbot` (Compose: `docker compose run --rm --no-deps botd botd support check`) says, without botd, whether the database opens, its schema against this botd's, the master key, disk, backups and the license ([support check](support-check.md)). Its last log lines say the rest: `journalctl -u superbot -n 200` or `docker compose logs --tail 200 botd`.
3. **Get a bundle for the ticket:** `sudo botd support bundle --home /home/superbot` (Compose: [support check](support-check.md#run-it)). It has the check's findings, redacted settings and the newest log lines.
4. **Decide:** fix forward if the cause is clear and quick (below), otherwise [go back](#going-back) now. Don't keep a Severity 2 open while debugging.

## Before an upgrade

For Enterprise, inside the agreed change window ([onboarding](onboarding.md)); for everyone, after reading the [changelog](../../CHANGELOG.md) for anything that needs action.

1. **Check:** `sudo botd support check --home /home/superbot --before-upgrade`. It exits 1 on any failure; fix those first. A warning about backups means take one now.
2. **Back up now** and keep the archive: `sudo systemctl start superbot-backup.service` (Compose: `docker compose exec botd superbot-backup`). Check it with `superbot-restore --check` ([backup and restore](../ops/backup-restore.md)). With an off-host store, `botctl backups` shows it copied.
3. **Keep the way back:** note the version running (the check's `last started by botd`, or `version.json` in a support bundle), and keep the master key, `.env` and the age identity where you can reach them. Compose: note `SUPERBOT_VERSION` (or the image's `sha-<commit>` tag). Air-gapped: keep the previous bundle.
4. **Upgrade:** `sudo bash deploy/install.sh --upgrade` (or the one-command form, [deploy/README.md](../../deploy/README.md)), or set `SUPERBOT_VERSION` and `docker compose pull && docker compose up -d`.

## After an upgrade

1. `botd support check` again: everything ok, `botd` running, and the database's schema matching this botd's.
2. `curl -fsS http://127.0.0.1:3000/healthz` answers `{"ok":true}`, the check's `last started by botd` is the new version, and `/status.json` shows no open incident.
3. A [support bundle](support-bundle.md) (`botctl support-bundle`) for the record, with health and the start-up lines; check the log for warnings botd printed at start.
4. Sign in with SSO, run a Bot, and check approvals still appear ([approvals after an upgrade](../../deploy/README.md#approvals-after-an-upgrade), [sign-in after an upgrade](../../deploy/README.md#users-and-sign-in-after-an-upgrade)).

## Fix forward

| What the check or log says | Cause | Fix |
|---|---|---|
| A setting botd rejects, by name | A setting changed meaning or became required | Fix it in `.env` per the changelog, restart |
| `disk` fails | The build, images or a backup filled the disk | Free space (old archives, `docker system prune`, journald's logs), restart |
| `database`: encrypted, no key opens it | The upgrade's `.env` lost the master key's setting, or the key file moved | Put `SUPERBOT_MASTER_KEY_FILE` or `SUPERBOT_MASTER_KEY` back as before, restart |
| `database`: schema changes run at the next start, and botd stays starting | A long schema change on a large database | Wait for it: botd logs each one. Don't kill it mid-change |
| `license` fails after the upgrade | No license key moved with a new `DATA_DIR`, or it ended | Install the key ([license](../../deploy/README.md#license)) |
| The web client is old (installer exit status 3) | The client build failed; botd is upgraded | Fix what the installer named and re-run it ([web client](../../deploy/README.md#web-client)) |

## Up but broken

Something works differently, or a feature fails, with botd up: a support bundle (`botctl support-bundle`) shows the start-up settings, health and recent failures. If it's a regression with no workaround and it blocks the customer's work, go back below; otherwise ticket it at its severity and keep the new version.

## Going back

Restore the backup taken just before the upgrade, **with the version it was made on**. Everything since the backup is lost, which is why it's taken just before.

1. Install the previous version: the installer from the previous release's tag or commit, or `SUPERBOT_VERSION` set back (Compose), or the previous offline bundle. Don't start it yet if you can avoid it: stop it (`sudo systemctl stop superbot superbot-backup.timer`, or `docker compose stop botd backup`).
2. Restore the archive ([server restore](runbook-server-restore.md), steps for the same host).
3. `botd support check`: the database's schema must match this botd's. If it says **made by a newer botd**, the data is still the upgraded one: the restore didn't take, so do it again.
4. Start botd and run the after-upgrade checks above.

Never start an older botd on a database a newer one has changed, and never set `PRAGMA user_version` by hand: the older botd doesn't know the new tables and columns, and what it writes may not be readable by either version.

## Escalate when

- botd won't start on the new version and the cause isn't in the table above.
- Going back fails, or the backup from before the upgrade is missing or won't restore.
- The database fails its integrity check after an upgrade.
- An upgrade lost data the customer had before it.

Escalate to engineering with the offline bundle and the version from before and after ([escalation](escalation.md)).

## Afterwards

Record the upgrade (versions, time down, whether it went back) for the customer's next [health check](health-check.md). A rollback or a Severity 2 gets a written review ([escalation](escalation.md#after-a-severity-1)), and any step this runbook missed is added here.
