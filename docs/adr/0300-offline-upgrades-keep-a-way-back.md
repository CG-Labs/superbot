# 0300: Offline upgrades keep a way back

## Status

Accepted (25 Nov 2026). Seventeenth slice of [#59](https://github.com/CG-Labs/superbot/issues/59) (M5, "Air-gapped self-host"). Builds on `install.sh --offline` and its downgrade refusal ([ADR 0128](0128-air-gapped-self-host.md)), backups and restores ([ADR 0030](0030-backup-restore-drill.md), encrypted by default in [ADR 0114](0114-backups-encrypted-by-default.md)), and upgrades checked against machines' settings ([ADR 0294](0294-offline-upgrades-checked-against-machines-settings.md)).

0300 was reserved for this work.

## Context

ADR 0294 stops an offline upgrade before it changes anything when the new botd wouldn't start. A release can still go wrong after it starts: a bug, a changed default, a client that misbehaves. Then the operator wants the release they had back.

The installer refuses a bundle older than the one recorded, because a database the newer botd migrated may not open with the older one. So going back meant restoring a backup by hand: stop botd, find a backup taken on the older release, decrypt it, restore it as botd's user, then install the older bundle past the refusal. The guide said "back up first", but nothing checked that anyone had. Daily backups may be a day old, may be off the host, and may hold a `.env` that no longer matches. On an air-gapped network there is no vendor to call while this goes wrong.

## Decision

### An offline upgrade backs up first

When `install.sh --offline` installs a newer release over a recorded one, it takes a backup after every check has passed and before anything changes:

- **DATA_DIR**, with the running release's own `superbot-backup` (`/usr/local/bin/superbot-backup`, else the bundle's), as botd's user, with `--home` and only `PATH` and `HOME`. So it is the server's usual backup: a consistent SQLite copy, `botd database backup` for an encrypted database, and age-encrypted to the server's backup recipients when it has them. The older release made it, so the older release's restore reads it.
- **`.env`**, copied as it is.

Both go in `/usr/local/share/superbot/rollback/`, root's only (0700, files 0600), with a `record`: the release backed up and its commit, the release being installed, when, the archive's name and SHA-256, and the `.env` copy's name. The archive is written to a partial file and the record is replaced last, so a run that stops halfway leaves the last good backup. Once the new record is in place, the older backup is removed: one is kept.

If the backup fails (a full disk, `SUPERBOT_BACKUP_ENCRYPTION=required` with no recipients), the upgrade stops with "Nothing has changed". `--no-upgrade-backup` skips it with a warning. Same-release reinstalls (a certificate renewal), fresh installs and online upgrades take none.

### `--rollback` goes back with it

`install.sh --offline <older bundle> --upgrade --rollback` takes that release back. The downgrade refusal gives way only when the backup is exactly the way back:

- it is of the bundle's release, and of the bundle's commit when both are known;
- it was taken before the upgrade to the release that runs now, so no later release has opened the database since;
- its files are there, and the archive has the SHA-256 the record holds.

Otherwise it stops, says which, and says that nothing has changed. Without `--rollback`, the downgrade refusal says to add it when a backup that fits is there.

Before anything changes, the bundle's `superbot-restore --check` reads the backup, decrypted by root with `BACKUP_IDENTITY_FILE` when it is encrypted, as botd's user from a pipe. botd's user can't read the rollback folder or the backup key. Machines' settings are checked as in ADR 0294, against the `.env` that will be put back, fed to `botd machines check --env-file /dev/stdin` through a pipe in botd's working directory.

Then the installer stops botd, puts the `.env` back (keeping the current one as `.env.before-rollback-<stamp>`) and restores DATA_DIR with the bundle's `superbot-restore`. That script keeps what it replaces in `DATA_DIR/.pre-restore-<stamp>/`. If the restore fails, the current `.env` goes back and botd starts again as it was. Once the restore succeeds, the bundle's release is recorded and the backup is removed. The install then goes on as for any bundle: binaries, client, units, and a restart.

A rollback that stops after the restore is run again with the same command. The host then runs the bundle's release, so it reinstalls that release with nothing to restore. `--rollback` refuses a newer bundle, `--no-upgrade-backup`, and `--machine-hermes-bundle` or `--machine-harness-bundle`, since the old `.env` decides those.

## Considered

- **Starting the new release and rolling back automatically if it fails.** By then the database may be migrated, and many failures show only later, when people use it. The operator decides; the installer makes that one command.
- **Keeping the old binaries instead of asking for the old bundle.** It saves carrying the bundle again, but the guide already says to keep the previous bundle. Reinstalling from the bundle runs every check again, for the client, templates and units too.
- **Writing the backup to `BACKUP_DIR` with the daily ones.** Retention would prune it, off-host copies would ship it, and botd's user could change it. A root-only folder keeps the record and archive as they were made.
- **A plain archive, since it stays on the host.** Backups follow the server's encryption setting everywhere. With the identity off the host, as the installer advises, the operator brings it back for the rollback.
- **Rolling back per-user accounts, Hermes Agent and the harness CLIs too.** Bot runs keep no database state there, and the bundle's own checks already say when Hermes or harness pins differ. They are left as they are.

## Consequences

- An offline upgrade that goes wrong is undone with one command and the previous bundle, with no network, as long as no later upgrade has run. Everything saved since the upgrade is lost, and the installer says so before and after.
- An offline upgrade needs room for one more backup under `/usr/local/share/superbot`, and takes as long as a backup.
- Online upgrades (`install.sh --upgrade`) are unchanged: neither the backup nor `--rollback` applies to them.
- Tested:
  - `deploy/test-offline.sh`, with the real `superbot-backup` and `superbot-restore` on a real SQLite database:
    - an upgrade backs up as botd's user into a root-only folder, keeps one backup, and stops on a failed backup with nothing left behind;
    - no backup for the same release, a fresh install, an online install, a dry run or `--no-upgrade-backup`;
    - `--rollback` puts back the data and `.env`, keeps what they replace, records the older release and removes the backup, and running it again reinstalls;
    - it is refused, with nothing changed, for another release's or build's backup, a host upgraded since, a changed, incomplete, broken or missing backup, a newer bundle and no recorded release;
    - a failed restore puts the `.env` back and starts botd;
    - an encrypted backup needs the backup key, and restores with it;
    - machines' settings are checked against the old `.env` through a pipe;
    - the flags need `--offline` and `--upgrade`, and refuse each other where they conflict.
  - `offline.yml`, with no network, an encrypted database and encrypted backups: the upgrade records a backup of the older release. The downgrade refusal offers `--rollback`. `--rollback` then removes a secret saved after the upgrade and keeps one saved before, puts back the `.env` from before the upgrade, and serves HTTPS again. Upgrading again takes a new backup.
- Not covered:
  - Docker Compose (`offline-bundle.sh load`): Compose's volumes are the operator's, and `superbot-restore` is how to go back there ([backup-restore.md](../ops/backup-restore.md)).
  - Going back more than one upgrade: the backup is replaced by the next upgrade's.
  - Host state outside DATA_DIR and `.env`: per-user accounts and their folders, `/opt/hermes`, `/opt/superbot-harnesses`, and changes users' machines made from the newer release.
