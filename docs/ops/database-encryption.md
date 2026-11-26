# Database encryption at rest

botd's database, `DATA_DIR/app.sqlite`, holds every chat, Bot setting, user and the audit log. It is encrypted with [SQLCipher](https://www.zetetic.net/sqlcipher/) under a key derived from the [master key](../../deploy/README.md#master-key), so the file, a disk image, a provider snapshot or the database in a backup reads as noise without that key. Design: [ADR 0116](../adr/0116-database-encrypted-at-rest.md).

It doesn't protect against anyone who can run code as botd's service user or as root on the host: botd holds the key while it runs. Files beside the database in `DATA_DIR` (Bots' memory, each user's `USER.md`) and the workspace aren't encrypted by SuperBot; keep the host's disk encrypted for those.

## The setting

`SUPERBOT_DATABASE_ENCRYPTION` in `.env` (installer) or `deploy/docker/.env` (Compose):

| Value | A new database | An existing plain database | An encrypted database |
|-------|----------------|-----------------------------|------------------------|
| `auto` (the default when unset) | Encrypted | Kept plain, with a warning at startup, an open setup checklist item and `/metrics` | Opened with its key |
| `required` (what new installs write) | Encrypted | Encrypted when botd starts, keeping a [plain copy](#the-plain-copy); botd refuses to start if it can't | Opened with its key |
| `off` | Plain, by choice | Kept plain, still shown in `/metrics`, `botctl database` and the audit log | Opened with its key: `off` never decrypts |

## New installs

`deploy/install.sh` and `deploy/docker/init.sh` write `SUPERBOT_DATABASE_ENCRYPTION=required` into a new `.env`, so botd creates the database encrypted on its first start. Nothing else to do; back up the master key as you would anyway.

## Encrypting an existing server

Before you start, take a backup and make sure the master key is copied off the host: from now on the database opens only with it.

**Installer:**

```sh
sudo systemctl start superbot-backup.service
sudo bash -s -- --upgrade --database-encryption required < <(curl -fsSL https://raw.githubusercontent.com/CG-Labs/superbot/main/deploy/install.sh)
```

**Compose** (from `deploy/docker`):

```sh
docker compose exec botd superbot-backup
./init.sh --database-encryption required
docker compose up -d
```

Or set the line in `.env` by hand and restart botd. On start, botd:

1. Checks the master key opens what is already sealed in the database (it refuses to encrypt under a key that isn't the database's own).
2. Takes the database out of WAL mode and locks it, so nothing writes to it while it is copied (this fails if another process has it open), then writes an encrypted copy next to it (`app.sqlite-reencrypt`), checks it with SQLite's `integrity_check`, and checks every table has the same number of rows.
3. Keeps the plain database as `app.sqlite-plain-<UTC time>` (mode `0600`) and moves the encrypted copy into its place.

If any step fails, the encrypted copy is deleted, the plain database is left as it was, and botd logs why and exits. The log says `Database encryption: encrypted with SQLCipher ...; encrypted the plain database on this start, keeping a plain copy in app.sqlite-plain-...`, and the audit log records `server.database_encryption_changed` with `migrated` set to that file's name.

Encrypting reads and writes the whole database once: allow a few seconds per hundred megabytes, and free disk space about the database's size.

## The plain copy

The plain copy is your way back if anything looks wrong after encrypting. It holds every chat unencrypted, so delete it once SuperBot runs well:

```sh
botctl database                                             # names the copy
sudo -u superbot shred -u ~superbot/superbot/data/app.sqlite-plain-<time>     # installer
docker compose exec botd sh -c 'shred -u /data/app.sqlite-plain-*'           # Compose
```

Until you do, botd warns at every start, the setup checklist's "Database encrypted" item stays open, `superbot_database_plain_copies` counts it, and deleting it is audited. Backups never include it. `shred` can't promise the blocks are gone on SSDs or copy-on-write filesystems: another reason to keep the host's disk encrypted.

To go back to the plain database instead: stop botd, move `app.sqlite` aside, rename the plain copy to `app.sqlite`, set `SUPERBOT_DATABASE_ENCRYPTION=off` (or `auto`), and start botd. Anything changed since encrypting is lost.

## Checking it

- `botctl database`, or `GET /api/database` (admins): the setting, whether the database is encrypted, and any plain copies.
- The startup log line `Database encryption: ...`, and `server.started` in the audit log, which records the setting and whether the database is encrypted.
- The setup checklist's "Database encrypted" item: done when encrypted with no plain copy left.
- `/metrics`: `superbot_database_encrypted`, `superbot_database_plaintext_allowed` and `superbot_database_plain_copies`. Alert rules: [`superbot-database-encryption.rules.yml`](../../deploy/prometheus/superbot-database-encryption.rules.yml).
- The audit log: `server.database_encryption_changed` whenever the setting, the encryption or the plain copies change (checked at start and every minute), and on each start that encrypts or re-encrypts the database.
- On the host, without the key: `botd database status <file>` prints `encrypted` or `plain` from the file's first bytes.

## Backups and restores

Archives hold the database as it is, encrypted under the master key of the day; age encrypts the whole archive on top when it has recipients ([backup guide](backup-restore.md#encryption)). `superbot-backup` copies an encrypted database with `botd database backup` and `superbot-restore` reads it with `botd database query`, both with the master key. Restoring needs the archive, its age identity if encrypted, and the master key it was made under. [Backup guide](backup-restore.md#what-a-backup-holds).

## Master key rotation

Rotating the master key ([guide](master-key-rotation.md)) re-encrypts the database under the new key on the next start, before the sealed values are sealed again. To restore an archive from before a rotation, set the old key as `SUPERBOT_MASTER_KEY_PREVIOUS(_FILE)` with the current key in place: botd re-encrypts the restored database on start.

## If something goes wrong

| What you see | What it means | What to do |
|--------------|---------------|------------|
| `the database is encrypted (ADR 0116) but no master key was found` | botd can't find the master key | Put the key back where `.env` says (`SUPERBOT_MASTER_KEY_FILE`, or `SUPERBOT_MASTER_KEY`) |
| `the master key doesn't open the encrypted database (wrong key)` | The key isn't the one the database is encrypted under | Use the right key; mid-rotation, set the old one as the previous key |
| `the master key doesn't open this database's encrypted values (wrong key)` while encrypting | `required` met a plain database whose sealed values are under another key | Fix the key first; nothing was changed |
| `another botd is using this DATA_DIR`, or `encrypting the database: another process has it open` | Another botd, or a tool like `sqlite3`, has the database open | Stop it and start botd again; nothing was changed |
| `encrypting the database: ...` | A step above failed (disk full, a damaged database, a process still writing) | botd left the plain database as it was; fix the cause and start again |
| The master key is lost | An encrypted database can't be opened, and `SUPERBOT_FORGET_SEALED` doesn't help | Restore a backup together with the key it was made under |

Support works through the [encryption at rest runbook](../support/runbook-encryption.md): the database or a backup plain, a plain copy left, and botd not starting for the key.
