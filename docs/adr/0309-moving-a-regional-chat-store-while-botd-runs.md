# 0309: Moving a regional chat store while botd runs

## Status

Accepted (26 Nov 2026). A slice of [#58](https://github.com/CG-Labs/superbot/issues/58) (M5, "Contractual data residency"). Follows [ADR 0304](0304-usage-records-in-the-regional-store.md) and builds on [ADR 0215](0215-pinned-chats-in-a-store-in-their-region.md) (regional chat stores), [ADR 0238](0238-clearing-moved-rows-from-store-backups.md), [ADR 0246](0246-copying-store-backups-off-the-host-in-their-region.md), [ADR 0256](0256-restoring-a-regional-chat-store.md) and [ADR 0293](0293-own-secrets-in-the-regional-store.md). 0309 was reserved for this work.

## Context

A region's chat store now holds most of a pinned person's data: chats, routines, approvals, memory, facts, sign-ins, own secrets, second factors and usage records. Its folder (`REGION_DATA_DIRS`) is storage the operator mounts in the region, usually a volume. Volumes fill up, get replaced with bigger or faster ones, or move to another storage class. Every earlier ADR listed "moving a store while botd runs" as not done. Until now the only way was to stop botd, copy the file and its backups by hand, change `REGION_DATA_DIRS` and start again, which is an outage for everyone and easy to get wrong: a copy taken while botd still wrote to the store loses rows, and forgetting the backups leaves them behind uncleared (ADR 0238) and out of `botd chat-store restore`'s reach.

The store is attached to two connections: botd's own and the users' secrets' (ADR 0293). Both were fixed at startup.

## Options

1. **Document the stopped-botd procedure.** Simple, but an outage, and the steps that matter (no writes during the copy, moving the backups) are left to the operator.
2. **Copy online, then catch up the rows written meanwhile.** Shortest pause, but a row-level catch-up across twelve tables, with deletes, is a second sync engine to get right.
3. **Copy with both connections held, then switch** (chosen). Nothing can write to the store during the copy, so the copy is exact; requests wait for it at disk speed. Then the store is attached from its new file on both connections under the same schema name, so every view and query keeps working.

## Decision

### Asking for it

- `POST /api/regions/{region}/chat-store/move` `{"folder": "/mnt/lon-2"}`, for admins only (it falls through to `Admin` in RBAC), and `botctl regions move-store <region> <folder>`.
- The folder must be absolute, outside `DATA_DIR` (server backups would carry the store out of the region), not in or around any store's folder (this store's included), empty, and owned by the user botd runs as. botd makes it if it is missing (and removes it again when it refuses), and sets it to `0700`, as for `REGION_DATA_DIRS`.
- A store keeps its region. Moving pinned data to another region is a pin; botd can't check that a folder is in a region any more than it can for `REGION_DATA_DIRS`, so the operator states it by asking.
- A move takes the control plane's operations lock (no pin, unpin or reconcile meanwhile) and a lock the hourly store check also takes, so no backup, clearing or copy off the host reads or writes the folder during it.

### The move

1. botd takes the store lock on the new file (`chats.sqlite-lock`), so another botd can't use it.
2. With botd's connection and the users' secrets' connection held, it copies the store with SQLite's backup API, under botd's database key, so an encrypted store stays encrypted and nothing plain is written. The copy is checked (`integrity_check`, and its `chat_store` row is this store's id and region), made a single file, synced and renamed into place.
3. The old file is marked with where the copy is (a `chat_store_moved_to` table), so if botd stops before the old file is deleted, it is known to be stale (below).
4. On both connections, the store's schema is detached and the new file attached under the same name, checked to be the store, and set to WAL. The views across places name the schema, so they read the new file from then on. botd's record (`chat_stores.path`) is updated.
5. Only then are the connections let go. If any step fails, the old file is attached again on both connections, its mark and the copy deleted, and nothing has changed; the move is audited as failed.
6. The store's backups are moved after it: each copied into the new folder's `backups/`, synced, renamed, the folder synced, then deleted from the old one. Half-made ones are deleted. The old file and its WAL are deleted and its lock let go. A `MOVED.txt` note in the old folder says where the store went and what `REGION_DATA_DIRS` must say. Anything that couldn't be moved or deleted is listed in the answer, the audit and the note.

It is audited as `residency.chat_store_moved` (target `chat_store`, the region), with the old and new folders, the store id, its size, the backups moved, anything left, and `regionDataDirs`: the setting as it must be now.

### Until the settings say so

- `REGION_DATA_DIRS` still names the old folder until the operator changes it. Admins are warned (`GET /api/regions`, `botctl regions`): the store was moved to the new folder and `REGION_DATA_DIRS` must name it before botd next starts.
- At startup, a recorded store missing from the folder `REGION_DATA_DIRS` names, but present where botd recorded it, stops botd with the exact setting to use, rather than make an empty store in the old folder. So does an old file still there with the move's mark once botd's record names the copy: botd may have written to the copy since. A mark whose move never switched (the record still names the old file) is dropped. botd doesn't follow the record by itself: the setting is the operator's statement of where the region's storage is.
- `botd chat-store list|restore` says the same when the settings still name the old folder: the store's backups moved with it.
- Bucket copies (ADR 0246) are named by the store's id and each file's SHA-256, so they are unchanged and nothing is uploaded again.

## Consequences

- A store can be moved onto new storage in its region without an outage, only a pause while it is copied. A store of a few GB pauses requests for seconds; the runbook says to move at a quiet time.
- The copy is exact: nothing writes to the store between its copy and the switch, so no row is lost or duplicated, and ids, meter state and sealed values come over as they are.
- The old storage holds nothing botd needs once the move is done, except files the answer lists.
- A store's lock is now kept in a list botd can let go of, not leaked at startup.

## Not done (still on #58)

- The rest of botd's database per region: accounts and the audit log are still where botd runs.
- `usage_daily` (per-person counts of routine runs a day) stays in botd's own database (ADR 0304).
- Following a move by itself at startup: the operator changes `REGION_DATA_DIRS`.

## Tests

- `db::chats`: a move while botd runs keeps every row, and reads, new rows, own secrets on the secrets' connection and pin moves all reach the new file, not the old one; it records the new path; a move that fails (a missing folder, a file already there, the same path, an unknown region) leaves the store attached where it was; an encrypted store stays under botd's key; after a move, startup with the old folder named is refused with the setting to use, and starts with the new one; the same holds when botd stopped before the old file was deleted, and a mark from a move that never switched is dropped at startup.
- `machines::chat_store_restore`: `locate` refuses with the new folder while the settings name the old one, and finds the store once they name the new one.
- HTTP (`machines_residency_tests.rs`): only admins move a store; a relative folder, one in `DATA_DIR`, one inside the store's folder, another store's folder and a non-empty one are refused and audited as failed, and folders botd made for them are removed; a move puts the store and its backup in the new folder and leaves only `MOVED.txt` in the old one, audited with `regionDataDirs`; new messages go there, the pin's report stays `kept`, the hourly check backs it up there, and `GET /api/regions` warns that `REGION_DATA_DIRS` still names the old folder.
- `botctl`: `regions move-store <region> <folder>` sends the move.
