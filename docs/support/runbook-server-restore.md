# Runbook: server restore

The SuperBot server's own data has to come back from a backup: the host is lost, the database is damaged, data was deleted, or an [upgrade is being undone](runbook-upgrade.md#going-back). For one user's machine or an Incus host, see [machine down or restore](runbook-machine-down.md); the commands for each install are in [backup and restore](../ops/backup-restore.md#restore). Severity: [1](severity.md#severities) while the server is down for everyone, 2 for damaged or lost data with the server up.

The server's RTO is 1 hour and its RPO the newest off-host archive (24 hours by default, 1 hour recommended; [SLO](../slo.md)). The restore step alone takes minutes; most of the hour goes on getting the host and the three things below together.

## First five minutes

1. **Confirm a restore is the fix.** `sudo botd support check --home /home/superbot` (Compose: `docker compose exec botd botd support check` while botd runs, `docker compose run --rm --no-deps botd botd support check` while it's stopped) works without botd ([support check](support-check.md)). A restore is right when `database` fails its integrity check or can't be read, `data_dir` is gone, or data the customer needs was lost. It's **not** the fix when the master key is missing or wrong (put the key back), the disk is full (free space), or a setting is rejected (fix `.env`): restoring then loses data for nothing.
2. **Save what's there** before changing anything: `sudo botd support bundle --home /home/superbot` for the ticket. `superbot-restore` keeps the old `DATA_DIR` in `DATA_DIR/.pre-restore-<stamp>/`, but take your own copy of a damaged database if there's room.
3. **Gather the three things**, all kept off the host ([what a backup holds](../ops/backup-restore.md#what-a-backup-holds)):
   - the **archive**: the newest good one, from the host's `BACKUP_DIR` or the off-host store (check its SHA-256 against its manifest);
   - the **age identity**, if it ends in `.age`;
   - the **master key** and the old **`.env`**. Without the key, an encrypted database can't be opened at all.
4. **Pick the archive.** The newest before the problem started: for damage or deleted data, the last one from before it; for an upgrade being undone, the one taken just before it, restored with the version it was made on.

## Restore

1. Stop botd and the backup timer: `sudo systemctl stop superbot superbot-backup.timer` (Compose: `docker compose stop botd backup`). `superbot-restore` refuses while botd runs.
2. Check the archive without touching live data: `sudo -u superbot superbot-restore --check <archive>` (add `--identity <file>` if encrypted).
3. On a new host, install first and put the old `.env` and master key back **before** restoring ([new host](../ops/backup-restore.md#installer-new-host), [Compose, new host](../ops/backup-restore.md#compose-new-host)).
4. Restore ([same host](../ops/backup-restore.md#installer-same-host), [Compose](../ops/backup-restore.md#compose-same-host)).
5. **Check before starting:** `sudo botd support check --home /home/superbot`. Before you start botd, `database` must be ok (integrity ok, schema no newer than this botd's) and `master_key` found. If `database` says the key doesn't open it, it's the wrong key: find the right one, don't start botd. If it says made by a newer botd, install that version first.
6. Start botd and the timer, then check again: `botd` running and `/healthz` answering.

## After the restore

- **Take a backup now** (`sudo systemctl start superbot-backup.service`), so the next RPO starts from the restored data.
- **Tell the customer** what was lost: everything after the archive's time (chats, approvals, audit events, sign-ups). People signed in after it sign in again; sign-in codes made after it don't work.
- **Machines** keep running. Ones made, rebuilt or given new certificates after the archive's time may not be recognised by the restored botd: check `botctl machine list` and follow [machine recovery](../ops/machine-recovery.md) for any that don't come back, and remove at the provider any it no longer knows.
- **On a new host:** harness CLIs log in again, SSO redirect URLs change if the domain did, and the workspace comes from the customer's own copy if they keep one.
- A [support bundle](support-bundle.md) (`botctl support-bundle`) once botd is up, for health and the start-up lines.

## Escalate when

- No archive restores (`superbot-restore --check` fails on all of them), or none is off the host and the host is lost.
- The master key or the age identity is lost: the data can't be read, and the customer has to be told.
- The restore runs past the 1-hour RTO.
- `database` still fails its integrity check after a restore.

Escalate to engineering with the offline bundle ([escalation](escalation.md)).

## Afterwards

Record the restore time against the RTO and the data lost against the RPO, with the [restore drills](../ops/backup-restore.md#drills). A Severity 1 gets a written review ([escalation](escalation.md#after-a-severity-1)); if the archive was older than the RPO, find out why backups weren't copied off.
