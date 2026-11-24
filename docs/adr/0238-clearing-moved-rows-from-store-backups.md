# 0238: Clearing moved rows out of a store's earlier backups

## Status

Accepted (24 Nov 2026). The eleventh slice of [#58](https://github.com/CG-Labs/superbot/issues/58) (M5, "Contractual data residency"). Extends [ADR 0215](0215-pinned-chats-in-a-store-in-their-region.md) (pinned people's chats in a store in their region) and [ADR 0228](0228-routines-and-approvals-in-the-regional-store.md) (their routines and approvals with them). 0238 was reserved for this work.

## Context

Each regional chat store is backed up daily into its own folder's `backups/`, keeping the newest `REGION_DATA_BACKUPS` (default 7, up to 365). When a Bot's chat, routines and approvals leave a store (a pin moved to another region, an unpin, a member leaving a pinned team, a Bot given away), the move deletes them from the store and zeroes them, but the store's backups from before the move still hold them. ADR 0215 disclosed these as `earlierCopies` in the report and let them age out.

For a customer pinned to Frankfurt whose data used to be in London, that is a week (or up to a year) of their chats, tool calls and scheduled instructions in another region's backups, which the report must call "not all in the region". It is the one way botd itself keeps a pin's data outside its region after a move has finished.

## Options

1. **Let them age out** (ADR 0215). Honest, but the window is set by `REGION_DATA_BACKUPS`, not the agreement.
2. **Delete every backup made before the move.** Simple, but each move out of a store takes every restore point from everyone else in it, leaving only the next one.
3. **Rewrite each earlier backup without the moved Bots' rows** (chosen). The backups stay restore points for everyone still kept in the store, and the moved rows leave them within the hour.
4. **Re-encrypt per Bot** (crypto-shredding: a key per Bot, dropped on a move). Clears every copy at once, but needs per-Bot keys across botd's database, the stores and their backups; far beyond this slice.

## Decision

### What is cleared

- After a Bot's rows leave a store, botd records the move (`chat_moves_out`, ADR 0215). That record now has `cleared_at`, set once the store's backups no longer hold the Bot's rows. A new move out of the same store sets it back to empty.
- A Bot's rows are taken out of a store's backups when its move out isn't cleared yet, it is kept somewhere else now (another store, botd's own database, or it was deleted), and nothing of it is left in the store itself. The last condition means a move that is still pending (pinned elsewhere, not yet moved) never loses the only other copy of what the store still holds. A Bot that moved back into the store is left in its backups: they are in its region.
- Every backup of the store is checked, not only those named before the move: a backup that began reading just before a move committed holds its rows under a later name.

### How a backup is rewritten

- Backups that hold none of the Bots' rows are left as they are.
- Otherwise the backup is copied to `.partial-<name>` beside it, opened with botd's database key, and the Bots' rows are deleted from its `messages`, `routines` and `approvals` with `secure_delete` on, then `VACUUM`ed so no page of theirs is left in the file. Its rollback journal and VACUUM's working copy are kept in memory, so no copy is written to the host's temp folder outside the region. It must pass `PRAGMA integrity_check`, is fsynced, and is renamed over the original, keeping its name (its time), so a crash leaves the old file or the new one. The folder is fsynced after.
- A backup is still the store itself and still restores by putting it back as `chats.sqlite` (ADR 0215). A restored backup no longer holds the moved Bots, which live elsewhere.
- What a rewritten file's earlier blocks held on the disk is up to the filesystem, as for any deleted file; with database encryption on (ADR 0116), they were encrypted.

### When

- On the same hourly check as the store backups, right after them (in the same task, so no backup of botd's is made while one is rewritten), and on the first check after startup.
- Once every backup of a store is done, its moves are recorded as cleared, only if each is still the move that was read (a Bot that moved out again meanwhile keeps its newer one).
- A backup that can't be rewritten (it doesn't open with botd's key, for example one made before a master key rotation, or fails its check) leaves the store's moves uncleared; the others are still rewritten. It is tried again each hour, and goes by itself once it is older than the newest `REGION_DATA_BACKUPS`, after which the moves are cleared.

### Evidence and visibility

- Each store whose backups were rewritten is audited as `residency.chat_store_backups_cleared` by the system actor `residency`, with `region`, `bots`, `backups` and the `messages`, `routines` and `approvals` taken out. A failure is audited under the same name as a failure, with `error`.
- The report's `earlierCopies` lists only moves not yet cleared, so once cleared, a pin whose chats, routines and approvals are all in its store is `inRegion` for them again, and the report's warning about other stores' backups goes. Its wording now says botd clears them out on its next hourly check.
- `GET /api/regions` and `botctl regions` warn when a store's backups have held a moved Bot's rows for over three hours (two checks, plus slack): clearing is failing.
- The app's line about older backups says they hold earlier copies until SuperBot clears them out.

## Consequences

- After a move, a pin's data is out of another region's store backups within the hour, not within `REGION_DATA_BACKUPS` days, and the report can say all of it is in the region.
- Each rewrite copies a whole backup once per move batch per hour; backups are the size of one store, and only those holding a moved Bot are copied.
- A store's backups now change after they are made. Nothing outside botd may rely on their bytes staying the same (an operator's checksums of them, for example).
- Backups from before a master key rotation can't be cleared once the previous key is gone; they are disclosed until they age out, as before.

## Not done (still on #58)

- The rest of botd's data per region: accounts, sessions and the audit log are still where botd runs. A pin's report says so.
- Copying a store's backups off the host, inside its region.
- A `botctl` command to restore a store backup.
- Moving a store to another folder or region while botd is running.
- Clearing an erased person's rows out of store backups (erasure deletes them from the live store; backups age out, as for botd's own server backups).

## Tests

- Unit (`machines/chat_stores.rs`):
  - a Bot's rows that left London are taken out of both its backups, the other person's rows stay, each file keeps its name, passes its integrity check and stays one self-contained file, no partial copy is left, and the move stops being an earlier copy; a second pass does nothing; moving out again clears again;
  - a move back into the store, or one still pending, isn't cleared; a moved Bot deleted since is;
  - a backup that can't be opened keeps the moves uncleared while the others are rewritten, and once it is gone the next pass clears them.
- Unit (`db/chats.rs`): move records from before this change gain `cleared_at` and still count as earlier copies until cleared.
- End to end on the real router (`machines_residency_tests.rs`): pinned from London to Frankfurt, London's backup is an earlier copy; left for hours, `GET /api/regions` warns; the hourly pass takes her messages out of it, the backup still says it is London's store, the clearing is audited with counts, and the report (`earlierCopies` empty, `inRegion` true, digest), `GET /api/me/residency` (`earlierBackups: 0`) and `GET /api/regions` show it.
- Client (`residency.test.ts`): the line about older backups.
