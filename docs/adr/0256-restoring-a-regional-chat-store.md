# 0256: Restoring a regional chat store from its backups

## Status

Accepted (24 Nov 2026). The thirteenth slice of [#58](https://github.com/CG-Labs/superbot/issues/58) (M5, "Contractual data residency"). Builds on [ADR 0215](0215-pinned-chats-in-a-store-in-their-region.md) (pinned people's chats in a store in their region), [ADR 0238](0238-clearing-moved-rows-from-store-backups.md) (clearing moved rows out of a store's backups) and [ADR 0246](0246-copying-store-backups-off-the-host-in-their-region.md) (copying those backups to a bucket in the region). Runs offline like `botd database` and `botd support check` ([ADR 0187](0187-offline-support-check-and-bundle.md)). 0256 was reserved for this work.

## Context

Each regional chat store has daily backups in its folder and, with ADR 0246, copies in a bucket in its region. Restoring one was left as prose: stop botd, download the copy, decrypt it, check its SHA-256, and put it back as `chats.sqlite`. Done by hand, that is easy to get wrong in ways that break the pin or the law:

- A backup from before a Bot moved to another region still holds that Bot's chats. Put back as is, a customer pinned to Frankfurt has chats in London again, and nothing records a move to clear them (ADR 0238).
- A backup from before someone was erased (ADR 0102) still holds what they wrote, and botd won't erase them again.
- A backup of another region's store, or of an earlier store in the same folder, opens fine and silently puts the wrong chats in the region.
- Copying a backup over the store loses the store as it was, with no way back, and leaves nothing in the audit log.

## Options

1. **Keep the prose** (ADR 0215, 0246). Every step above is the operator's to get right, and nothing is audited.
2. **An admin API in botd, as it runs.** Restoring under a running botd means detaching and reattaching a store with requests in flight, and the main reason to restore is a lost volume, when botd stops at startup (ADR 0215) and serves no API.
3. **A `botctl` command.** botctl talks to a running botd over the API, so it has the same problem; it also has no access to the store's folder or botd's keys.
4. **An offline `botd chat-store` command, run on the server with botd stopped** (chosen). It reads the same settings and keys as botd, takes botd's locks so it can't run beside it, and does the checks and the clean-up before anything changes. ADR 0246 named this a `botctl` command; it is a `botd` subcommand instead, for the reasons in 2 and 3.

## Decision

### The command

- `botd chat-store list <region>` shows the store's file, its backups in `backups/` (newest first, and which have a copy in the bucket) and the copies in its bucket. No keys or secrets are printed.
- `botd chat-store restore <region> <backup | newest>` restores one: a backup by its name in the folder (`chats-<time>.sqlite`), a copy by its name in the bucket (`chats-<time>-<sha256>.sqlite[.age]`), or `newest`: the folder's newest backup, else the bucket's newest copy. Without `--yes` it does every check, prepares the backup, says what a restore would do, deletes its work and changes nothing.
- `--identity <file>` gives the age identity that opens encrypted copies (ADR 0246). `--replace-unreadable` lets a store that doesn't open be deleted rather than kept. `--home` and `--env-file` read settings as `botd support check` does.
- Settings and keys are botd's: `DATA_DIR`, `REGION_DATA_DIRS`, the master key and the previous one mid-rotation (ADR 0116, 0188), and the region's `REGION_DATA_S3_<REGION>_*` settings, with the bucket's secret key from the settings or else from botd's saved server secrets. A broken bucket setting only fails a restore that needs the bucket.
- It exits 0 when done, 1 when refused or failed and 2 for a usage error.

### Checks before anything changes

- botd's data lock and the store's lock are taken (ADR 0215), so it refuses while botd runs, and botd can't start during a restore.
- The region must be in `REGION_DATA_DIRS`, its folder must exist (the volume mounted), and botd's database must exist and record a store for the region. Restoring botd's own database is the server restore's job (`docs/support/runbook-server-restore.md`), and must come first.
- A copy from the bucket is downloaded into the store's own folder, never the host's temp folder, decrypted there if encrypted, and checked against the SHA-256 in its name.
- The backup must open with the master key or the previous one (encrypted only when botd's database is), pass `PRAGMA integrity_check`, and be this store: the id and region written into it (ADR 0215) must match botd's record.
- A store that is there but doesn't open is refused without `--replace-unreadable`.
- A store that still holds rows of Bots kept elsewhere now, waiting for botd to move them (ADR 0215), is refused: restoring would leave those rows only in a backup. The operator starts botd, lets it move them, and stops it.

### Preparing the backup

The backup is copied into a work file `.restore-<name>` in the store's folder, with temp files and the journal in memory, so nothing of it is written outside the region. Then:

- **Erasures since are run on it again.** For each erased person, with the pseudonym they were given, the same statements botd ran on their stores run on it: their routines deleted, what they and their Bots wrote replaced with `[erased]`, their approval decisions pseudonymised. The statements are shared with botd's erasure, so the two can't drift. Their Bots come from the audit log (`bot.deleted` with reason `user_erased`). When someone was erased after the backup was made and the audit log no longer reaches back that far (`AUDIT_RETENTION_DAYS` pruned it), their Bots can't all be found, so the restore is refused: restore a newer backup.
- **Only the region's Bots are kept.** Every row of a Bot whose owner's pin (their team's, else their own) isn't in the region now is deleted: Bots that moved out since, and Bots deleted since. So a restore never brings a moved Bot's chats back into a region it left, and needs no move to clear.
- Both use `secure_delete`, and the file is rebuilt with `VACUUM` and checked again, so no page of what was taken out is left in it.
- It is compared with the store now, by row id: what comes back (rows the store lost) and what goes (rows made since the backup).

### Restoring

- The store now, if it opens, is checkpointed into one file and moved into `backups/` as a backup made now (`chats-<now>.sqlite`). So it is cleared of moved rows (ADR 0238) and copied off the host (ADR 0246) like any other backup, and the restore can be undone by restoring it. A store that doesn't open is deleted, and only with `--replace-unreadable`.
- The work file replaces `chats.sqlite`, and the folder is synced.
- A note (`restored.json`, mode 0600) is left in the folder. At its next start botd audits the restore as `residency.chat_store_restored` by the system actor `residency`, with `region`, `storeId`, `backup`, `from` (folder or bucket), `backupAt`, `restoredAt`, the backup `kept`, `replacedUnreadable`, the counts `held`, `dropped`, `erased`, `back` and `gone`, and the user it ran as, then deletes the note.
- At every start, before it opens the stores, botd deletes `.restore-*` work files left by a restore that was cut off: they may hold rows that have since left the store.
- Routines that come back run on their schedule once botd starts, so the command says so when any do.
- botd then starts as usual: its message ids continue past the restored store's (ADR 0215), it moves rows that belong elsewhere, and its next check backs the store up and copies it off the host.

## Consequences

- A lost or damaged store comes back from a backup in its folder or its bucket with one command, checked and audited, without breaking a pin or an erasure.
- Restoring loses what was written since the backup, at most a day (the backup interval); the dry run says how much first.
- The store as it was counts against `REGION_DATA_BACKUPS` like any backup, so one older backup is pruned at the next check.
- A Bot whose move into the region is still waiting (its rows still in another place) may get rows back from the backup that it later moves in with `INSERT OR IGNORE`, keeping the backup's version of those rows. Erasures are run on them all the same.
- A restore under a host whose clock is behind the backup's time is fine; the checks use the backup's name and botd's records, not the clock.

## Not done (still on #58)

- The rest of botd's data per region: accounts, sessions and the audit log are still where botd runs. A pin's report says so.
- Moving a store to another folder or region while botd is running.

## Tests

- Unit (`machines/chat_store_restore.rs`):
  - a backup in the folder comes back without the chats of a Bot that moved to Frankfurt (no page of them left), refused while those chats are still waiting to move; the dry run counts what comes back and goes and changes nothing; the store it replaces is kept as a backup; a cut-off restore's work file is deleted; botd's next start audits it once and opens the store;
  - erasures made since are run on it again: an erased person's routine, their Bot's message in another Bot's chat and their approval decision, gone from every page;
  - a backup older than the audit log is refused once someone was erased since;
  - after the volume is lost, an age-encrypted copy comes back from the bucket, with its secret key from botd's saved secrets; without an identity or with a wrong one it is refused and nothing is left;
  - refused while botd holds the lock, for another region's backup, a file that isn't a database, a name that isn't a backup's, an unreadable store without `--replace-unreadable` (and replaced with it), a region not in `REGION_DATA_DIRS`, a missing folder and a missing botd database;
  - the command line and copy names are parsed strictly.
