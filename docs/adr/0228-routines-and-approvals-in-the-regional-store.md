# 0228: Pinned people's routines and approvals in their region's store

## Status

Accepted (24 Nov 2026). The tenth slice of [#58](https://github.com/CG-Labs/superbot/issues/58) (M5, "Contractual data residency"), and the second part of its last item, splitting botd's database by region. Extends [ADR 0215](0215-pinned-chats-in-a-store-in-their-region.md) (pinned people's chats in a store in their region). Builds on [ADR 0129](0129-contractual-data-residency.md), [ADR 0155](0155-residency-reports.md), [ADR 0096](0096-master-key-rotation.md) (master key rotation) and the approvals' sealed tool input. 0228 was reserved for this work.

## Context

ADR 0215 keeps a pinned person's chats in a SQLite store in their pin's region, attached to botd's database. Two more tables hold what people and their Bots wrote:

- **Routines**: a Bot's scheduled instructions (`instruction` is free text, often naming customers, documents or plans).
- **Approvals**: the tool calls a Bot asked a person to allow, with the call's subject (a command line, a file path, a URL), its full input sealed under the master key, and the person's note.

Both are per Bot, like chats, and the report listed both as "not covered" in botd's own database. Accounts, sessions and the audit log are read across all people on every request, and are in subsystems other work is changing (SCIM, SAML, the audit export), so they stay for later.

## Options

1. **One botd per region** (ADR 0184's `require`). Still works, but the operator runs a second server for two tables.
2. **A second store per table.** More files to mount, back up and check for one region, for no gain.
3. **The same store as the chats, by the same rule** (chosen). One file per region, one move, one backup, one report section. Reads keep going through TEMP views.
4. **Leave them in botd's database and say so.** What the report did. Customers asking where their Bots' tool calls are kept get "in another region".

## Decision

### What is kept where

- A Bot's routines and approvals are kept where its chat is: in the store of its owner's pin region (their team's pin, else their own), else in botd's own database. Every rule of ADR 0215 applies: moves on pins, unpins, every reconcile pass and at startup; copy committed before delete; a crash leaving a row in both places is cleared on the next pass; rows of deleted Bots left in a store are deleted on the same pass.
- The store gets `routines` and `approvals` tables with botd's columns (adding any botd's tables gain later), `id` as the primary key, and their indexes (`routines(bot_id)`, `approvals(status, created_at)`, `approvals(bot_id)`). Policy rules, run grants and every other table stay in botd's own database.
- A TEMP view per table puts botd's own rows and each store's together, so every read (the approvals inbox, a Bot's routines, the scheduler, exports, erasure checks) is unchanged.
- Each view reads an id from the first place that has it (botd's own database, then the stores in order). A move stopped between its copy and its delete (a crash, a full disk) leaves a row in two places until the next pass; without this, the scheduler would see a routine twice and run it twice, and the inbox would list an approval twice. Updates by id reach both copies, so the one read is current. This applies to chats too, which ADR 0215 showed twice in that window.
- The approvals view also has a `rowid` column (each part's own rowid). A view's rowid is NULL, and the inbox breaks ties in `created_at` by rowid, so two approvals asked in the same millisecond in the same place keep the order they were asked in. Rowids are per file: same-millisecond approvals in different places, or moved since, are in a fixed but arbitrary order. A shared sequence would fix that at the cost of a column in botd's own `approvals` and its migrations; one millisecond doesn't warrant it.

### Ids

- Routine and approval ids are random text. A new one is drawn until no place has it, under the connection lock, so an id is unique across botd's database and every store, and a move never meets a different row with the same id.
- An approval's sealed input is bound to its id (`approvals.input/<id>`), not to where it is kept, so a moved approval still opens.

### Writes

- New routines and approvals go to where their Bot's chat belongs.
- Updates and deletes by id (a routine edited, paused or run; an approval decided, expired or closed) run on every place. "Did it change a row" checks count changes in all places: a crash between a move's copy and delete can leave the same row in two places, and both are changed.
- Deciding an approval with "remember" changes the approval in its store and adds the policy rule in botd's own database in one transaction. In WAL mode that isn't atomic across files: a crash can keep one and lose the other. Losing the rule means the next call asks again; losing the decision means an approval that stays pending until it expires. Neither lets a call through that wasn't approved.
- Deleting a Bot deletes its messages, routines and approvals in every place first: foreign keys don't cascade across files.
- Erasing a person deletes the routines they wrote and clears their name and notes from approvals they decided, in every place.

### Nothing left behind

- When a move deletes rows from a file, `secure_delete` is on for that transaction, so the deleted rows are zeroed rather than left in free pages, and the WAL is checkpointed and truncated after a pass that moved anything. The same goes for chats. A move out of a store then leaves nothing readable in that file; its backups from before still hold the rows, as ADR 0215 discloses.
- The zeroed pages only replace the old ones in the file at the checkpoint. A reader on another connection (a store backup, for example) can block it; botd then remembers that, logs a warning, and checkpoints again on every pass, moves or not, until it completes.

### Sealed input under the master key

- botd's own approvals' input is brought under the current master key at startup (plaintext sealed, previous key's values sealed again, with `SUPERBOT_FORGET_SEALED=1` unreadable ones dropped). That runs before stores are attached, so each store's approvals get the same pass right after they are: in one transaction per store, with `secure_delete` on, then a WAL checkpoint.
- During a rotation, input neither key opens is left as it is and logged. Outside one, it stops botd (nothing changed), as a wrong key does for botd's own database, unless `SUPERBOT_FORGET_SEALED=1`.
- botd says to remove the previous key only once every store's approvals are under the new one. The rotation log line adds how many were sealed again.
- Saved secrets are redacted from store approvals at startup, as from botd's own.

### A store that holds them

- A region dropped from `REGION_DATA_DIRS` whose store holds routines or approvals stops botd, as one holding messages does; the log says what it holds.

### Evidence and visibility

- The report's `chats` section gets `routines` and `approvals`, each `{inStore, inServerDatabase, elsewhere}` like `messages`. `inRegion` needs all three in the region. The Markdown section is "Chats, routines and approvals", with a line for each table that has rows. "Not covered" leaves out chats, routines and approvals when they are all in the region's store. The digest covers it all.
- Routines or approvals outside their pin's store make the pin `data_outside` like chats, and the report names how many ("their Bots have 1 routine and 1 approval in botd's own database, not gb-lon's chat store").
- `GET /api/regions` shows `routines` and `approvals` in each `chatStore`; `GET /api/me/residency` counts them in `chats.moving`; the app says "Your chats, routines and approvals are kept in ...".
- `residency.chats_moved` keeps its name and gains `routines` and `approvals` in its details; the reconcile result adds `routinesMoved` and `approvalsMoved`.

## Consequences

- A pinned team's tool calls, the notes on them and their Bots' scheduled instructions stay in their region with their chats.
- Approval and routine writes for pinned people go through the store; updates by id touch every place, which is one more statement per store.
- An index a later migration adds to botd's own `routines` or `approvals` isn't copied to stores, as for chats.
- A "remember" decision isn't crash-atomic across the two files (above); the failure modes ask again rather than allow.

## Not done (still on #58)

- The rest of botd's data per region: accounts, sessions and the audit log are still where botd runs. A pin's report says so.
- Copying a store's backups off the host, inside its region.
- Deleting a store's earlier backups that still hold a moved row, rather than waiting for them to age out.
- A `botctl` command to restore a store backup.
- Moving a store to another folder or region while botd is running.

## Tests

- Unit (`db/chats.rs`):
  - a pinned owner's routines and approvals go to the store with the chat, reads and updates by id reach them, ids stay unique, and unpinning brings them back;
  - approvals in the inbox are newest first, with same-time ties in the order they were asked, across places;
  - deleting a Bot takes its routines and approvals out of the store at once;
  - erasure deletes a person's routines and clears their decisions in a store;
  - a move stopped between its copy and its delete loses nothing, and the next pass clears the duplicate;
  - moved rows leave no copy in the file they left (raw file bytes, WAL included);
  - a checkpoint a reader blocked is tried again on the next pass, even with nothing to move;
  - a row left in two places by a stopped move is read once meanwhile;
  - a dropped store holding routines or approvals stops botd;
  - a store gets the columns botd's tables gained since it was made;
  - startup seals a store's approvals under the current key: plaintext sealed, previous key's values sealed again, unreadable ones left during a rotation, refused outside one, dropped with forget.
- Unit (`residency_report.rs`, `main.rs`): the Markdown section and "not covered"; the rotation log only says to remove the previous key once store approvals are sealed again.
- End to end on the real router (`machines_residency_tests.rs`): a routine made through the API and approvals stay in botd's database until the owner is pinned; the pin moves them, audited with counts; new approvals go straight to the store; listing and pausing routines, the inbox order and approving with "remember" work; the report, Markdown and `GET /api/regions` count them; a routine and an approval left outside make the pin `data_outside` until reconcile moves them (`routinesMoved`, `approvalsMoved`); unpinning brings them back with their sealed input still opening.
- Client (`residency.test.ts`): the lines about chats, routines and approvals.
