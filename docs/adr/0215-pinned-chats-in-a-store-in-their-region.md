# 0215: Pinned people's chats in a store in their region

## Status

Accepted (23 Nov 2026). The ninth slice of [#58](https://github.com/CG-Labs/superbot/issues/58) (M5, "Contractual data residency"), and the first part of its last item, splitting botd's database by region. Builds on [ADR 0129](0129-contractual-data-residency.md) (residency pins), [ADR 0184](0184-botds-own-data-region.md) (botd's own data region), [ADR 0155](0155-residency-reports.md) (residency reports), [ADR 0168](0168-residency-in-the-app.md) (residency in the app), [ADR 0116](0116-database-encrypted-at-rest.md) (the database encrypted at rest), [ADR 0096](0096-master-key-rotation.md) (master key rotation) and [ADR 0205](0205-ending-a-kept-pin-once-the-data-is-gone.md). 0215 was reserved for this work.

## Context

A pin holds a person's or team's machines, machine backups and model calls in a region. botd's own database is wherever botd runs (ADR 0184), so a botd in London serving a customer pinned to Frankfurt keeps their chats in London. The report says so, and `RESIDENCY_SERVER_DATA=require` makes the operator run one botd per region. Chats are what residency customers ask about most: they hold what people typed and what their Bots answered. The remaining #58 item is letting one botd hold two regions' data. Chats are the biggest and most sensitive part of it, and the most self-contained: one table, written in a handful of places.

## Options

1. **One botd per region** (ADR 0184's `require`). Works today, but doubles the servers, accounts and admin for an operator with one customer in a second region.
2. **A database per region for everything.** The goal, but accounts, teams, sessions, SCIM, billing and the audit chain are read across regions on every request; splitting them means a router in front of every query and cross-database consistency for the audit chain. Too big for one change and in subsystems others are changing.
3. **Chats in a store in their region, the rest where botd runs** (chosen). One table moves. Reads stay single queries through SQLite's `ATTACH`, so nothing that lists, searches, exports or erases chats changes shape.
4. **Chats in an external database per region (such as Postgres).** A second database engine to run, back up and key, for one table.

## Decision

### `REGION_DATA_DIRS=<region>=<folder>,...`

- Each entry gives a region in `MACHINE_REGIONS` a folder on storage in that region (a volume mounted from it, typically). botd keeps that region's chats in `<folder>/chats.sqlite`, made on first start.
- botd stops at startup when: the control plane is off (pins need it); `RESIDENCY_SERVER_DATA=require` is set (every pin is then held to botd's own region, so a store elsewhere contradicts it); a region isn't offered, is botd's own `SERVER_DATA_REGION`, or is named twice; a folder isn't absolute, is inside `DATA_DIR` or contains it (server backups archive `DATA_DIR`, and would carry the chats out of the region), or overlaps another region's.
- Folders are made if missing and set to `0700`. botd holds a lock on each store, as on its own database, so two botds can't share one.
- Unset (the default), nothing changes: every chat stays in botd's own database.

### Where a chat is kept

- A Bot's messages are kept in the store of its owner's pin region: their team's pin, else their own (the same rule as `residency::of_user`). If that region has no store, or the owner isn't pinned, they stay in botd's own database.
- Each store is attached to botd's single SQLite connection. A TEMP view named `messages` puts botd's own table and each store's together, and SQLite resolves unqualified names to TEMP objects first, so every read (chat history, search, exports, erasure checks, retention) sees all places with no change.
- Writes name the table they change. New messages go to where their Bot's chat belongs. Status, edits, retention deletes, erasure and deleting a Bot run on every place by id.
- Ids stay unique across places: a store row takes the next id after botd's own sequence and every store's highest, then bumps botd's sequence. At startup, botd's sequence is raised past every store's highest id.
- The store's table copies botd's columns (adding any botd's table has gained since), with `id` as its primary key and the same chat indexes.

### Moving chats

- Each Bot's chat is moved to where it belongs now: copied, then deleted from where it was. This runs right after a pin or unpin (user or team), on every reconcile pass (which catches joins, leaves, kept pins ending and Bots given away), and at startup.
- In WAL mode, a transaction across attached files is atomic per file only. A crash mid-move can leave a copy in both places; the next pass deletes the copy in the wrong place (`INSERT OR IGNORE`, then delete). A message is never in neither.
- Messages of a deleted Bot left in a store are deleted on the same pass.
- Each move is audited as `residency.chats_moved` by the system actor `residency`, with `from`, `to` (`null` for botd's own database), and the number of Bots and messages. The reconcile pass's result counts them as `chatsMoved`.

### A store that goes missing

- Each store has a `chat_store` row with an id and its region, written when it was made. botd records each region's store id in its own database.
- botd stops at startup if a recorded store's file is missing (an unmounted volume would otherwise get a new, empty store and the old chats would look gone), or if a store's id or region isn't the one recorded (the wrong volume).
- A region dropped from `REGION_DATA_DIRS` whose store still holds messages stops botd. One that holds none, or whose file is gone with nothing recorded as left, is forgotten, logged.
- A file that isn't a chat store, or doesn't open with botd's key, stops botd. botd changes nothing in it first.

### Encryption

- A store is keyed with botd's database key (ADR 0116), so it is as encrypted as botd's own database.
- At startup, a plain store is encrypted when botd's database is. A store still under the previous key during a master key rotation (ADR 0096, `SUPERBOT_MASTER_KEY_PREVIOUS`) is re-encrypted under the new one, using the same verified copy as botd's own database. No plain or old-key copy is kept.
- A store that is encrypted when botd's database isn't, or that neither key opens, stops botd.
- Saved secrets are redacted from stores at startup, as from botd's own messages.

### Backups, kept in the region

- Server backups (`deploy/superbot-backup.sh`, ADR 0184) archive `DATA_DIR`, so they never carry a store. Each store is backed up in its own folder instead: `<folder>/backups/chats-<UTC time>.sqlite`, daily, under the same key, with botd's online backup (one read transaction), checked with `PRAGMA integrity_check`, fsynced, and renamed into place. The newest `REGION_DATA_BACKUPS` (default 7, 1 to 365) are kept.
- A backup is the store itself. Restoring one means stopping botd and putting the copy back as `chats.sqlite`.
- A failure is logged, audited as `residency.chat_store_backup_failed` and tried again on the next hourly check. A store holding messages with no backup from the last 26 hours is a residency warning (startup log, `GET /api/regions`, `botctl regions`).
- Getting the folder's storage itself off the host, within the region (a provider's volume snapshots in the same region, for example), is the operator's. Botd doesn't copy a store anywhere else.

### Evidence and visibility

- The residency report gets a `chats` section: whether the pin's region has a store; the pinned Bots' messages in it, in botd's own database and in another region's store; whether they are all in the region (in its store, or in botd's own database when that is stated to be in the region); and the store's newest backup. It is in the Markdown as "Chats" and covered by the digest.
- When botd's own data isn't in the pin's region but all the pin's chats are in the region's store, "not covered" says botd's own database apart from chats.
- Warnings: messages still to move, messages in another region's store, and no backup from the last day.
- `GET /api/regions` shows each region's `chatStore` (messages, backups, newest backup) and `residency.chatStores` (all stores and `keep`).
- `GET /api/me/residency` gives `chats: {store, inRegion}`, and the app tells people their chats are kept in the region, in a database of their own there, or that they are being moved.

## Consequences

- One botd can hold two regions' chats: a London botd with `REGION_DATA_DIRS=de-fra-2=/mnt/fra` keeps a Frankfurt-pinned team's chats in Frankfurt, and its report says so.
- A store is one more file to keep mounted. botd stops rather than run without it, which is an outage instead of a silent gap.
- Chat writes for pinned people run in a savepoint across two files. Reads go through one view, and SQLite pushes `WHERE` clauses into each part of it, so lookups by Bot or id still use indexes.
- An index a later migration adds to botd's own `messages` table isn't copied to stores. Startup copies the columns and the two chat indexes only.
- Chats in stores aren't in server backups. The store backups in each folder are the copy, and a server restore on a new host needs the store folders too.

## Not done (still on #58)

- The rest of botd's data per region: accounts, routines, approvals (which hold tool calls), sessions and the audit log are still where botd runs. A pin's report says so.
- Copying a store's backups off the host, inside its region.
- A `botctl` command to restore a store backup.
- Moving a store to another folder or region while botd is running.

## Tests

- Unit (`db/chats.rs`):
  - with no stores, everything stays in botd's own table;
  - a pinned owner's messages go to their region's store, reads see every place, and ids stay unique;
  - a team pin holds its members' chats, and a member leaving takes theirs out;
  - writes by id, retention and deleting a Bot reach the store;
  - a copy left in both places by a crash is cleared by the next pass;
  - a store that goes missing, or isn't the one recorded, stops botd;
  - an empty store dropped from the settings is forgotten, and one holding messages isn't;
  - a store gets the columns botd's table gained since it was made;
  - a store is encrypted with botd's key and refuses another.
- Unit (`machines/chat_stores.rs`):
  - `REGION_DATA_DIRS` validation (each refusal above, `0700` folders, `REGION_DATA_BACKUPS`);
  - backups are named by time, made once a day, the newest kept, each a self-contained copy of the store.
- Unit (`residency_report.rs`): "not covered" leaves chats out only when they are all in the region's store; the Markdown "Chats" section.
- End to end on the real router (`machines_residency_tests.rs`), with the in-memory Linode provider: a person's messages stay in botd's own database until she is pinned; the pin moves them into London's store, audited as `residency.chats_moved` by the system; new messages go straight there; the report, its Markdown and digest, `GET /api/me/residency` and `GET /api/regions` show the store; a backup is made in the region's folder and clears the report's warning; unpinning brings the messages back.
- Client (`residency.test.ts`): the lines about chats kept in the region, being moved, or nothing without a store, and the server-copy line without "and chats" when they are held.
