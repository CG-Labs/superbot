# 0246: Copying regional chat stores' backups off the host, inside their region

## Status

Accepted (24 Nov 2026). The twelfth slice of [#58](https://github.com/CG-Labs/superbot/issues/58) (M5, "Contractual data residency"). Extends [ADR 0215](0215-pinned-chats-in-a-store-in-their-region.md) (pinned people's chats in a store in their region), [ADR 0228](0228-routines-and-approvals-in-the-regional-store.md) (their routines and approvals with them) and [ADR 0238](0238-clearing-moved-rows-from-store-backups.md) (clearing moved rows out of a store's backups). Reuses the S3 client and age encryption of [ADR 0071](0071-off-host-machine-backups.md). 0246 was reserved for this work.

## Context

Each regional chat store (`REGION_DATA_DIRS`) is backed up daily into its own folder's `backups/`. ADR 0215 left getting that folder's storage off the host to the operator ("a provider's volume snapshots in the same region, for example"). In practice the store and every backup of it sit on one volume: lose the volume and a pinned customer's chats, routines and approvals are gone, along with every restore point. botd's own database has off-host server backups (ADR 0109), and machines have theirs (ADR 0071), but the stores had none.

The copy has to stay in the region, or it breaks the pin it serves. It also has to follow ADR 0238: once a Bot's rows have left a store, they must leave the off-host copies too, or a customer pinned to Frankfurt still has chats in London's bucket.

## Options

1. **Leave it to the operator** (ADR 0215). Volume snapshots are per provider, and botd can't tell a report what they hold or clear moved rows out of them.
2. **Reuse the machine backup store of the region** (`MACHINE_BACKUP_S3_<REGION>_*`, ADR 0117). One bucket less to set up, but machine backups are only for Incus containers (Linode has its own backups), so Linode deployments, which pin too, would have nothing.
3. **A bucket per region of its own, mirroring the folder** (chosen). Works with any provider, named per region in the same way as machine backup stores, and the bucket can be the same one as the machines' with a different prefix.
4. **Copy only new backups and never delete.** Simpler, but every rewrite of ADR 0238 and every pruned backup would be left behind in the bucket.

## Decision

### Settings

- `REGION_DATA_S3_<REGION>_BUCKET`, `_ENDPOINT`, `_REGION` (default `us-east-1`), `_ACCESS_KEY_ID` and `_SECRET_ACCESS_KEY` (or `_FILE`) give a region in `REGION_DATA_DIRS` a bucket for its store's backups. `<REGION>` is the id in upper case with `-` as `_`, as for machine backup stores (`REGION_DATA_S3_DE_FRA_2_BUCKET`). The operator states, by naming it for the region, that the bucket is in it, as for machine backups (ADR 0117).
- `REGION_DATA_S3_PREFIX` (default `superbot/`) starts every key. `REGION_DATA_AGE_RECIPIENTS` (or `_FILE`) age-encrypts each copy to those public keys, on top of botd's database key when database encryption is on (ADR 0116). The copies are a backup target of ADR 0114 (`chat_stores`): plain ones are warned about, shown in `superbot_backup_encrypted` and the setup checklist, and `SUPERBOT_BACKUP_ENCRYPTION=required` makes botd refuse to start without the recipients.
- botd stops at startup when a bucket is set (not empty) for a region with no store in `REGION_DATA_DIRS`, when a bucket's endpoint or keys are missing or malformed, or when the prefix or recipients are set with no bucket.
- The secret access key is botd's own (`server_secret`): saved and listed with server secrets, never given to a Bot, and redacted from logs. No process botd starts inherits any `REGION_DATA_S3_*` setting.
- A region without a bucket works as before. Nothing is copied anywhere else, ever: not to another region's bucket, not to the machines' default store.
- Each store's destination (endpoint, bucket and key prefix) is recorded at startup. botd only deletes copies where it copies now, so when a store's bucket or prefix changes, or is unset, the earlier copies may hold rows that left the store with nothing to clear them: botd stops at startup and says so. Once the operator has deleted them (or chosen to keep them), `REGION_DATA_S3_FORGET=<region>,...` lets botd start, records the new destination and audits it as `residency.chat_store_copies_forgotten` with `previous` and `now`. Naming a region whose destination didn't change is a warning to remove it.

### The bucket mirrors the folder

- Each store's copies are under `<prefix>region-data/<region>/<store id>/`. The store id is the one written into the store when it was made (ADR 0215), so a store made again in the region never mixes with an earlier one's.
- Each backup `chats-<UTC time>.sqlite` is copied to `chats-<UTC time>-<SHA-256 of the file>.sqlite` (`.age` added when encrypted). A backup ADR 0238 rewrote is a new file with a new hash, so it is a new object.
- On every hourly check (the same task as the store backups and their clearing, and on the first one after startup), for each store whose region has a bucket:
  - unfinished multipart uploads under the store's prefix are aborted, since one cut off by a restart may hold rows that have since left the store;
  - the folder's backups are listed strictly (a folder or entry botd can't read is a failure, so the bucket isn't emptied to match a folder it couldn't list) and hashed, with each hash kept in memory while the file's size, time and inode are the same;
  - each backup without a copy is streamed up as a multipart upload, checked against the file's hash when not encrypted;
  - while the store's own file is missing (its volume lost, or mounted empty) or its folder holds no backups, nothing is deleted from the bucket and the pass fails, so its copies, then the only ones, stay;
  - every object under the prefix that no backup matches (a pruned backup, or a backup's copy from before it was rewritten) is deleted, and in a bucket that keeps old versions, every version and delete marker of it is deleted for good.
- A pass that changed the bucket is audited as `residency.chat_store_backups_copied` by the system actor `residency`, with `region`, `bucket`, `uploaded`, `deleted` and `copies`. A failure is audited under the same name as a failure, with `error`, and tried again on the next check.
- Restoring from a copy means downloading it, decrypting it with the operator's age identity if encrypted, checking its SHA-256 against its name, and putting it back as ADR 0215 says (botd stopped, the file as `chats.sqlite`).

### Clearing waits for the copies

- ADR 0238 records a move out of a store as cleared once the store's backups no longer hold the Bot's rows. With a bucket, the hourly check now rewrites the backups first, then copies, and records the moves as cleared only if that store's copy pass succeeded. Otherwise the clearing is audited as `residency.chat_store_backups_cleared` with outcome failure and `error` naming the copies, and the moves stay uncleared.
- So a report's `earlierCopies` (and "not all in the region") stands for the bucket's copies too: it lists a move until neither the store's backups nor their copies hold the rows. An entry has `offHost` true while the bucket may still hold a copy of a backup from before the move (no pass since has matched a folder whose oldest backup is later, or none has run since botd started), so a move stays listed when bucket deletes keep failing after its local backups are pruned.

### Evidence and visibility

- `GET /api/regions` gives each region's `chatStore.offHost` (null without a bucket): the endpoint and bucket, whether copies are encrypted, `copies`, `newestCopyAt`, `lastCopiedAt`, and the last pass's `error` and `failingSince`. No keys. Admins get a residency warning while a store's last copy pass failed.
- Residency reports' `chats.offHost` gives `copies`, `newestCopyAt`, `lastCopiedAt` and `failing`, with no endpoint or bucket, and null when the pin's region's store has no bucket; it is covered by the digest. The Markdown says how many backups are copied off the host to a bucket in the region and the newest, or that they are on the store's own volume. A report warns while the last copy pass failed.
- What a pass found is kept in memory: after a restart, views show no copies until the first check, which runs at startup.

## Consequences

- A pinned customer's chats, routines and approvals survive the loss of the store's volume, from a copy in their region, at most a day old (the store's backup interval).
- One more bucket per region to set up, with credentials that can list, write and delete under the prefix (and delete versions, if the bucket keeps them). A bucket with Object Lock or a retention rule that refuses deletes keeps moves uncleared and says so; that is the operator's choice to make.
- Each new or rewritten backup is uploaded whole. Backups are the size of one store; a check that changes nothing lists the bucket and reads nothing else.
- Hashing reads each backup once per botd start.

## Not done (still on #58)

- The rest of botd's data per region: accounts, sessions and the audit log are still where botd runs. A pin's report says so.
- A `botctl` command to restore a store backup, from the folder or from its bucket.
- Moving a store to another folder or region while botd is running.

## Tests

- Unit (`machines/chat_store_copies.rs`):
  - settings: a bucket per region with a store and no other, the endpoint and keys each region needs, the shared prefix and age recipients, nothing set without a bucket, and the secret key kept as botd's own;
  - each backup is copied once, named by its SHA-256, byte for byte; a pass that changes nothing only lists; a backup pruned from the folder is deleted from the bucket; only changes are audited;
  - with age recipients, copies are encrypted, decrypt with the identity to the backup, and are named by the plain file's hash;
  - in a versioned bucket, a backup rewritten without a moved Bot's rows replaces its copy, every version of the old copy is deleted, and the move is recorded as cleared only then: a bucket that refuses keeps it uncleared, warns, marks the report failing, audits the failure and leaves no parts;
  - unfinished uploads under the store's prefix are aborted, on every page of the listing, and others' are left; a folder botd can't list fails the pass and deletes nothing;
  - a store whose file is gone, or whose folder is empty, deletes nothing from its bucket, and the bucket is known to hold its backups from the oldest on;
  - an empty bucket setting is none; a store whose bucket or prefix changed, or was unset, stops botd until `REGION_DATA_S3_FORGET` names it, which is audited and records the new destination.
- Unit (`backup_encryption_http_tests.rs`): the copies are a target, plain without `REGION_DATA_AGE_RECIPIENTS`, and `required` refuses that.
- Unit (`chat_stores.rs`): reports warn of earlier copies off the host once the backups themselves are pruned.
- Unit (`residency_report.rs`): the Markdown line about copies off the host, and none for reports from before it.
- End to end on the real router (`machines_residency_tests.rs`): a person pinned to London has her store's backup copied to London's bucket on the hourly check, audited; `GET /api/regions` and the report (and its Markdown and digest) show the copies, Frankfurt's store has none, and no keys or bucket reach the report; pinned to Frankfurt with the bucket refusing, the move stays an earlier copy, the clearing is audited as failed and admins are warned; on the next check the copy is replaced without her chat and the report says all of it is in the region.
