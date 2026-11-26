# Runbook: encryption at rest

botd's database or a backup target is plain when it should be encrypted, encrypting the database left a plain copy behind, or botd won't start because the database key is missing or wrong. Severity: [1](severity.md#severities) when botd won't start for the key, since the service is down; 2 when the customer was promised encryption at rest (their onboarding record, their agreement, a security questionnaire) and something is plain, or a plain copy or plain backups have left the host; 3 otherwise. Plain data that may have been copied by someone who shouldn't have it is a security incident, [Severity 1](escalation.md#security-incidents), whatever the alerts say.

The settings and procedures are in [database encryption](../ops/database-encryption.md), [backup encryption](../ops/backup-restore.md#encryption) and [master key rotation](../ops/master-key-rotation.md); this page is the order to work in.

## First five minutes

1. **What's plain.** As an admin on the server:

   ```sh
   botctl database                    # the setting, whether the database is encrypted, any plain copies
   botctl backups                     # each backup target, encrypted or plain, and why
   botctl audit 20 --action server.database_encryption_changed
   botctl audit 20 --action server.backup_encryption_changed
   ```

   With botd down, `botd support check` reads the database's format and tries the master key without it ([support check](support-check.md#the-checks)), and `botd database status <file>` says `encrypted` or `plain` from a file's first bytes. The setup checklist's "Database encrypted" and "Backups encrypted" items say the same in the console.
2. **By choice or not.** `SUPERBOT_DATABASE_ENCRYPTION=off` or `SUPERBOT_BACKUP_ENCRYPTION=off` keeps data plain on purpose, and the alerts stay quiet; `auto` (the default when unset) keeps an old plain database plain and warns. Check what the customer's onboarding record says they chose ([onboarding](onboarding.md)). A choice to stay plain is the customer's, recorded; not a fault to fix behind their back.
3. **Did anything change?** An upgrade from before encryption was the default, `.env` rewritten or restored from an old copy, the master key moved or rotated, a server restored onto a new host, age recipients removed, or a new target added (an off-host store, Incus machines' backups, a regional chat store).

## The database isn't encrypted

`SuperBotDatabaseUnencrypted`: `app.sqlite` has been plain for an hour and plaintext wasn't chosen. Anyone who gets the file, a disk image, a provider snapshot or a copy of `DATA_DIR` can read every chat in it.

1. Take a backup, and make sure the master key is copied off the host: from now on the database opens only with it.
2. Set `SUPERBOT_DATABASE_ENCRYPTION=required` and restart (installer: `--upgrade --database-encryption required`; Compose: `./init.sh --database-encryption required`). botd encrypts it on start, checks the copy and keeps the plain one beside it ([encrypting an existing server](../ops/database-encryption.md#encrypting-an-existing-server)). Allow a few seconds per hundred megabytes and free disk about the database's size.
3. If botd won't start after that, it left the plain database as it was and logs why: [below](#botd-wont-start-for-the-key).

Then delete the plain copy, as in the next section.

## A plain copy is left

`SuperBotDatabasePlainCopyLeft`: encrypting kept the plain database as `app.sqlite-plain-<UTC time>` for a day or more. It holds every chat unencrypted. It's the way back if anything looked wrong after encrypting; once SuperBot runs well, delete it: `botctl database` names it, and [the plain copy](../ops/database-encryption.md#the-plain-copy) has the commands. Deleting it is audited (`server.database_encryption_changed`). Backups never include it, but a disk image or a provider snapshot of the host taken meanwhile does: ask whether any were taken, and treat them as plain.

## Backups aren't encrypted

`SuperBotBackupsUnencrypted`: a backup target has been plain for an hour and plaintext wasn't chosen. `botctl backups` names each target and what to set:

| Target | What's plain | Set |
|---|---|---|
| `server_archives` | `superbot-backup`'s archives on the host | `SUPERBOT_BACKUP_AGE_RECIPIENTS` |
| `server_copies` | botd's copies of them off the host | `SUPERBOT_BACKUP_AGE_RECIPIENTS`, or `SERVER_BACKUP_AGE_RECIPIENTS` to encrypt on the way |
| `machines` | Incus machines' off-host backups | `MACHINE_BACKUP_AGE_RECIPIENTS` |
| `chat_stores` | Regional chat stores' off-host copies | `REGION_DATA_AGE_RECIPIENTS` |

Make a key on a machine the customer controls (`age-keygen`), or on the server with `--backup-age-generate` and copy it off at once; the server keeps only the public key ([encryption](../ops/backup-restore.md#encryption)). Without the identity, encrypted archives can't be restored, so check the customer holds it before you call this done. Archives already written stay plain: once a new encrypted one exists and is copied off, delete the plain ones from the store too, or record that the customer keeps them. `SUPERBOT_BACKUP_ENCRYPTION=required` then refuses plain backups from now on.

## botd won't start for the key

An encrypted database opens only with the master key it's encrypted under. botd's last log lines, and `botd support check`'s `master_key` and database findings, say which case it is; the [database encryption guide](../ops/database-encryption.md#if-something-goes-wrong) has the table of messages and fixes. In short:

- **No master key found**: put it back where `.env` says (`SUPERBOT_MASTER_KEY_FILE`, or `SUPERBOT_MASTER_KEY`). After a move to a new host, it's the key from the old one.
- **The wrong key**: mid-rotation, set the old key as `SUPERBOT_MASTER_KEY_PREVIOUS(_FILE)` with the new one in place ([master key rotation](../ops/master-key-rotation.md#if-something-goes-wrong)).
- **The key is lost**: the database can't be opened, and nothing in botd can help. Restore a backup together with the key it was made under ([server restore](runbook-server-restore.md)).

Never set `SUPERBOT_DATABASE_ENCRYPTION=off` to get past it: `off` never decrypts, and botd still needs the key.

## Before telling the customer it's fixed

1. `botctl database` says encrypted with no plain copies, and `botctl backups` shows every target encrypted (or plain by a recorded choice).
2. The setup checklist's "Database encrypted" and "Backups encrypted" items are done.
3. After new backup recipients, a new archive restores with `superbot-restore --check --identity <file>` using the identity the customer holds ([check an archive](../ops/backup-restore.md#check-an-archive)).

## Escalate when

- botd won't start and neither the current nor the previous master key opens the database.
- Encrypting fails again after its cause (disk, another process) is fixed.
- A plain copy, plain archives or a disk image may have been copied off the host by someone who shouldn't have them: a security incident, [Severity 1](escalation.md#security-incidents).

## Afterwards

Note in the customer's onboarding record what's encrypted, under which key, and who holds the master key and the backup identity, off the host. If the customer chose to stay plain, record that choice and who made it, since auditors ask.
