# 0116: The database encrypted at rest

## Status

Accepted (22 Nov 2026). Part of the SOC 2 readiness checklist of M4, [#50](https://github.com/CG-Labs/superbot/issues/50); closes checklist row C1.1-1 in the [readiness checklist](../security/soc2-readiness-checklist.md). Revisits the option [ADR 0010](0010-secrets.md) rejected (whole-database encryption) for the rest of the database; field-level sealing of secrets stays as it is. Builds on master key rotation ([ADR 0096](0096-master-key-rotation.md)) and encrypted backups ([ADR 0114](0114-backups-encrypted-by-default.md)).

0115 is the highest number on `main` (from [#177](https://github.com/CG-Labs/superbot/pull/177)).

## Context

botd keeps the organisation's data in one SQLite file, `DATA_DIR/app.sqlite`: chats, routines, users, Bot settings and the audit log. Only secrets, approvals' tool input, push tokens and TOTP secrets were sealed under the master key ([ADR 0010](0010-secrets.md)); everything else was plain, so anyone with the file, a disk image, a provider snapshot, a copy of `DATA_DIR` or an unencrypted backup could read every chat. The docs told operators to encrypt the host's disk, and nothing checked that they had.

## Options

1. **Require and verify the operator's disk encryption, recorded per host.** botd can't tell from inside a container or a VM whether the block device under it is encrypted (`dm-crypt` is visible on bare metal, not under Docker volumes, cloud block storage or a provider's own encryption), so "verified" would mean an operator's checkbox. It also doesn't protect what leaves the disk: `DATA_DIR` copies, provider snapshots taken from a running VM, archives without age.
2. **Seal more columns** (chat text, memory) field by field, as secrets are. Every query, search and retention job over those columns would change; foreign keys, indexes and the audit log's text stay readable; and each new column is one more place to forget.
3. **SQLCipher**, through rusqlite's `bundled-sqlcipher-vendored-openssl` feature: the whole file, its WAL and every page encrypted (AES-256 with an HMAC per page), with the same SQL. The costs ADR 0010 named were a C dependency, a custom SQLite build, and harder backups and installs.
4. **SQLite's own encryption extension (SEE)**: commercial licence, not open source.

botd already builds SQLite from C (`bundled`), so SQLCipher swaps one C library for another plus OpenSSL, built from source by `openssl-src` and tracked by `cargo audit` like any crate. `sqlx` isn't used. The backup scripts can call botd itself instead of `sqlite3`. That leaves SQLCipher as the only option that covers the whole database without the operator's help, so it is the choice; disk encryption stays recommended for the files beside it.

## Decision

botd opens `app.sqlite` with SQLCipher 4 under a key derived from the master key. New installs are encrypted from the first start; existing ones opt in, and a plain database is encrypted in place with a plain copy kept.

### The key

`HMAC-SHA256(master key, "superbot/database/v1")`, given to SQLCipher as a raw 256-bit key (`x'…'`), so SQLCipher skips its password KDF: the input is already a random 256-bit key. It comes from the master key itself, not the derived-key root of ADR 0096, which is stored inside the database it would have to open. Nothing new is stored: the master key opens the database, the database holds the derived-key root, and the sealed values are opened as before.

### `SUPERBOT_DATABASE_ENCRYPTION`

| Value | A new database | An existing plain one |
|-------|----------------|-----------------------|
| `auto` (default) | Encrypted | Kept plain, with a warning in the log, the setup checklist and `/metrics` |
| `required` | Encrypted | Encrypted at start, with a plain copy kept; botd refuses to start if it can't |
| `off` | Plain, by choice | Kept plain, still shown and audited |

An encrypted database is always opened with its key, whatever the setting: botd never decrypts. `deploy/install.sh` and `deploy/docker/init.sh` write `required` into a new `.env` and take `--database-encryption`; an upgrade with no flag changes nothing. `auto` is the default for an unset value so an upgrade never rewrites an operator's database unasked.

### Encrypting a plain database

At start, before anything else opens the database, botd:

1. brings the plain schema up to date, and refuses unless the master key (or, mid-rotation, the previous key) opens what is already sealed, so the file is never encrypted under a key that isn't its own; with no key and nothing sealed, it makes the key first;
2. checkpoints the WAL, counts every table's rows, and exports the database into `app.sqlite-reencrypt` with `sqlcipher_export`, keeping `user_version`;
3. checks the copy with `integrity_check` and the same row counts, and refuses if the original's WAL still holds changes (another process writing);
4. keeps the original as `app.sqlite-plain-<UTC time>` (a hard link, else a copy; `0600`), removes its `-wal` and `-shm`, renames the copy over `app.sqlite` and syncs the folder.

Any failure deletes the work files and leaves the original untouched. `superbot-backup` already leaves `app.sqlite-*` out of archives, so the plain copy is never backed up. It stays until the operator deletes it, with a startup warning, an open checklist item, a gauge and an alert, because an encryption that loses data is worse than a plaintext file the operator was told about.

### Rotation

When the master key doesn't open the database and the previous key does ([ADR 0096](0096-master-key-rotation.md)), botd re-encrypts it the same way under the new key (no old-key copy kept), then the sealed values are sealed again as before. The two steps are independent and each repeats safely: a crash between them leaves a database the new key opens with values the previous key opens, and the next start finishes. `SUPERBOT_FORGET_SEALED` can't help with an encrypted database whose key is lost; the error says to restore a backup and its key.

### Backups and restores

`superbot-backup` can't copy an encrypted database with `sqlite3`, so botd gains a small offline command for the scripts:

- `botd database backup <src> <dest>`: SQLite's online backup, with the destination keyed like the source, so the archive holds the database still encrypted.
- `botd database query <file> <sql>`: read-only rows, for `superbot-restore`'s summary and `integrity_check`.
- `botd database status <file>`: `encrypted` or `plain`, from the first 16 bytes, without a key.

They find the master key as botd does (`SUPERBOT_MASTER_KEY(_FILE)`, then the previous key). The systemd unit already reads `.env`; `--home` falls back to `~/.config/superbot/master.key`; the Compose `backup` service now gets `SUPERBOT_MASTER_KEY`, which it never writes into an archive. `superbot-restore` restores an encrypted database it can't read (no key on hand) and lets botd check it on start, but refuses one another key can't open, and refuses a file that is neither SQLite nor whole pages. Archives are encrypted twice: the database by SQLCipher under the master key, the archive by age when it has recipients; an archive made without age still keeps the database unreadable.

### What botd shows

- **Startup**: `Database encryption: ...` with the setting and what happened (created, encrypted on this start with the copy's name, re-encrypted after a rotation), and a `WARNING` for a plain database (unless `off`) or a plain copy left. `server.started` records the setting and whether the database is encrypted.
- **Setup checklist**: "Database encrypted", done when encrypted with no plain copy left.
- **`GET /api/database` and `botctl database`** (admins): the setting, `encrypted`, the cipher, and plain copies with their sizes.
- **Metrics**: `superbot_database_encrypted`, `superbot_database_plaintext_allowed`, `superbot_database_plain_copies`. [`superbot-database-encryption.rules.yml`](../../deploy/prometheus/superbot-database-encryption.rules.yml) raises a ticket for a plain database after an hour (unless plain by choice) and a plain copy after a day.
- **Audit**: `server.database_encryption_changed` (actor `system`, `database-encryption`) the first time botd sees a state and whenever the setting, the encryption or the plain copies change, checked at start and every minute; and on every start that encrypted or re-encrypted the file, even when the summary is unchanged. It records the setting, `encrypted`, the plain copies, what was migrated or re-keyed, and the state before. Counted in `superbot_events_total`.

## Consequences

- Threat model: protects the file, disk images, snapshots, copies of `DATA_DIR` and archives; not anyone who can run code as botd's user or root on a running host, who can read the key. The files beside the database (Bots' memory, `USER.md`) and the workspace are still plain: host disk encryption remains recommended for them.
- The master key now opens the whole database, not just its secrets: losing it loses the server's data unless a backup and its key survive. The installer, `init.sh` and the docs say so where they already said to back the key up.
- SQLCipher costs some CPU per page (typically 5-15% on SQLite workloads); botd's database is small and its load light.
- Builds need a C compiler, `make` and `perl` for OpenSSL: present in the `rust` image and the installer's `build-essential`. OpenSSL is built in, so hosts need no `libssl` at runtime. Advisories for `openssl-src` reach `cargo audit`.
- `sqlite3` alone can't read an encrypted database; operators use `botd database query` or SQLCipher's shell with the derived key.
- Supersedes ADR 0010's rejection of whole-database encryption; its field-level sealing stays, so a stolen key-less database copy still can't open secrets even with SQLCipher stripped.

## Tests

- [`server/src/database_encryption.rs`](../../server/src/database_encryption.rs): the setting; key derivation and redaction; new databases encrypted unless `off`; a plain database encrypted with its copy (plain, `0600`, the same rows and `user_version`); a database whose sealed values another key opens left plain; rotation re-encrypting, through `sealed::bootstrap`; a failed encryption (a missing folder for the copy, a reader holding the WAL) leaving the original as it was; `botd database backup` and `query`; startup lines.
- [`server/src/database_encryption_http_tests.rs`](../../server/src/database_encryption_http_tests.rs): a plain database shown in `/metrics`, the checklist and `/api/database` (admins only) and audited once; an encryption and its plain copy audited at start, deleting the copy audited and the item done; a re-key audited with an unchanged summary; `off`, and a failed audit write tried again.
- [`server/tests/database_encryption.rs`](../../server/tests/database_encryption.rs): the real `botd` from `off` to `auto` to `required`, every row kept and the copy plain; `botd database` copying and reading it; another key refused, and botd refusing to start with it.
- [`server/tests/master_key_rotation.rs`](../../server/tests/master_key_rotation.rs): a rotation re-encrypts the file, so the old key no longer opens it.
- [`deploy/test-backup.sh`](../../deploy/test-backup.sh) (with the release `botd` in CI): an encrypted database archived still encrypted, checked and restored with its key, restored unread without one, refused under another. [`deploy/test-install.sh`](../../deploy/test-install.sh): new installs write `required`; upgrades change nothing without the flag and warn about a plain database and a plain copy; the flag is written as given and bad values refused. [`deploy/docker/smoke-test.sh`](../../deploy/docker/smoke-test.sh): a new Compose `.env` requires it, botd creates the database encrypted, and archives keep it so. [`deploy/backup-drill.sh`](../../deploy/backup-drill.sh) runs unchanged on an encrypted database: backup through the unit, `--check` without the key, a restore, and botd refusing the wrong key.
