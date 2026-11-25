# 0276: A pinned person's Bots' memory is kept in their region's chat store

## Status

Accepted (25 Nov 2026). The fifteenth slice of [#58](https://github.com/CG-Labs/superbot/issues/58) (M5, "Contractual data residency"). Builds on [ADR 0215](0215-pinned-chats-in-a-store-in-their-region.md) and [ADR 0228](0228-routines-and-approvals-in-the-regional-store.md) (regional chat stores), [ADR 0238](0238-clearing-moved-rows-from-store-backups.md) (clearing store backups), [ADR 0256](0256-restoring-a-regional-chat-store.md) (restoring a store), [ADR 0267](0267-runs-on-a-computer-in-the-pins-region.md) (runs only on a computer in the region) and [ADR 0036](0036-bots-on-the-users-machine.md) (memory carried with each job). 0276 was reserved for this work.

## Context

With a regional store, a pinned person's chats, routines and approvals are kept in their region, and since ADR 0267 their Bots run only on a computer there. One piece of their Bots' content still stayed where botd runs: each Bot's memory. botd keeps its own copy in `DATA_DIR/bots/<id>/MEMORY.md`, sends it with every job to the machine and writes back what the run learned (ADR 0036). It is what the Bot has learned about its job and its owner's work, so it is customer content as much as the chat it came from, and it sat in botd's files and server backups outside the region. The report listed it only as part of "botd's own files".

Owners' facts (`DATA_DIR/users/<id>/USER.md`) have the same problem, but are kept per owner, not per Bot.

## Options

1. **Say so in the report and the DPA.** Already true in general terms; a pin would still hold a Bot's chat in the region but not what it learned from it.
2. **Keep it only on the machine.** botd would stop keeping a copy, but jobs, handovers, isolation and the machine folder copy all rely on botd's copy, and a machine that is rebuilt would lose it.
3. **Keep it in the store, as a row like the rest** (chosen). A Bot's memory becomes one more kept table (`memories`, one row per Bot), so every path that holds the region's data already covers it: moves with zeroing and the WAL emptied, the store's encryption at rest, its backups and their off-host copies, backup clearing, restore, and a dropped store that still holds rows stops botd.

## Decision

### Where it is kept

A Bot's memory is kept where its chat is: in the store of its owner's pin (their team's, else their own) when that region has one, else in its file in DATA_DIR as before. botd reads it from a row if there is one, else from its file (`kept_memory`), and saves it where it belongs, removing the copy in the other place (`keep_memory_text`). Every place botd read or wrote the file now goes through these: a Bot's first memory, seeding and saving runs under per-user accounts, handovers, what a run on a machine sends back, teammates' copies (ADR 0046) and the system prompt.

### Moving between the file and the store

botd's own database gains a `memories` table that only holds a memory on its way between a file and a store, so the move itself is the existing `place_chats`:

- **Into a store** (a pin, startup, every reconcile pass): before the move, the file of each Bot whose memory belongs in a store is taken into botd's table and deleted (a link or anything but a plain file is left alone). If a row is kept already, it is the newer copy and the file is only deleted. The move then takes the row to the store, zeroed in botd's database with its WAL emptied.
- **Out of a store** (an unpin, or a store dropped from a pin's region): the move brings the row back to botd's table, recording the move for that store's backups to be cleared; botd writes it to the file (written whole and synced, then renamed in place), then deletes the row, zeroed.

Moves are audited as `residency.chats_moved` with `memories`, and reconcile returns `memoriesMoved`.

### Saying so

- Reports, `GET /api/regions` and the app count a Bot's memory with chats, routines and approvals (`chats.memories`, the "Bots' memory" row in the Markdown report, `chatStore.memories`). A memory file left in DATA_DIR for a Bot whose memory belongs in a store counts as outside the region, so the pin is `data_outside` until the next pass moves it.
- What a pin doesn't cover now names Bots' memory as in the store, and owners' facts as still in botd's files.
- The app says "Your chats, routines, approvals and Bots' memory are kept in ...". The DPA template (annex IV) says the same.

## Consequences

- A pinned person's Bots' memory is in their region at rest: in the store, its backups and its off-host copies. botd still relays it with each job, from wherever botd runs, as it does chats.
- **On upgrade**, the first start moves the memory files of pinned people's Bots into their stores and deletes them from DATA_DIR. Server backups taken before still hold them; the report already says server backups hold data from before it moved.
- Stores and store backups from before gain the table when attached or restored; a restore run against a botd database from before it leaves the table out until botd starts.
- The machine folder copy (ADR 0041) seeds a Bot's memory from its file only, so a memory kept in a store reaches the machine with the Bot's first job instead.

## Not done (still on #58)

- Owners' facts (`USER.md`) in the region's store. They are kept per owner, so they need rows keyed by user through backup clearing and restore.
- The rest of botd's database per region: accounts, sessions and the audit log are still where botd runs. A pin's report says so.
- Moving a regional store while botd is running.

## Tests

- `db::chats`: a pinned owner's Bot's memory is taken from its file, moved to the store and back with the pin, recorded for backup clearing, saved where it is kept, deleted with its Bot, and leaves no bytes in the files it left; a dropped store holding one stops botd; a store from before gains the table.
- `machines::chat_stores`: a memory file moves into the store and is deleted (a link is left alone), audited with `memories`; unpinned, it is written back to its file, and the store's backups are cleared of it.
- `machines::chat_store_restore`: a restore keeps only the memory of Bots still kept in the store, and a backup from before gains the table.
- HTTP (`machines_residency_tests.rs`): a pin moves a Bot's memory into London's store and deletes its file; what a run sends back is saved there; the report (JSON and Markdown), the regions page and the app count it; a file left in DATA_DIR or a row left in botd's database makes the pin unkept until reconcile; unpinned, it is written back to its file.
- Client (`residency.test.ts`): Settings names Bots' memory with chats, routines and approvals.
