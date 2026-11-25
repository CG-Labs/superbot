# 0277: A pinned person's facts are kept in their region's chat store

## Status

Accepted (25 Nov 2026). The sixteenth slice of [#58](https://github.com/CG-Labs/superbot/issues/58) (M5, "Contractual data residency"). Follows [ADR 0276](0276-bots-memory-in-the-regional-store.md) (Bots' memory in the store) and builds on [ADR 0215](0215-pinned-chats-in-a-store-in-their-region.md), [ADR 0228](0228-routines-and-approvals-in-the-regional-store.md), [ADR 0238](0238-clearing-moved-rows-from-store-backups.md), [ADR 0256](0256-restoring-a-regional-chat-store.md) and [ADR 0029](0029-per-user-isolation.md) (each user's facts file). 0277 was reserved for this work.

## Context

After ADR 0276, one piece of a pinned person's content still stayed where botd runs: their facts, the `USER.md` their Bots keep about them (`DATA_DIR/users/<id>/USER.md`). botd sends it with jobs, writes back what a run learned, and puts it in the system prompt. It is about the person, so it is customer content, and it sat in botd's files and server backups outside the region.

Unlike a Bot's memory, the facts belong to a person, not a Bot. Everything a store keeps so far is keyed by Bot: where a row belongs, the moves recorded for backup clearing, what a restore keeps, and what a dropped store still holds.

## Options

1. **Keep them with each Bot's memory.** One copy per Bot would split one person's facts, and a run would see only its own Bot's copy.
2. **Key them by the owner's first Bot.** It breaks when that Bot is deleted or handed over.
3. **Rows keyed by person, through the same paths** (chosen). A `facts` table, one row per person, in botd's database and in each store. Each kept table names its key (`bot_id` or `user_id`), and every path that worked on a list of Bots now works on Bots and people.

## Decision

### Where they are kept

A person's facts are kept in the store of their pin (their team's, else their own, the rule their Bots' chats follow) when that region has one, else in their file in DATA_DIR as before. botd reads them from a row if there is one, else from the file (`kept_facts`), and saves them where they belong, removing the copy in the other place (`keep_facts_text`). Every place that read or wrote the file now goes through these, under the same lock as memory: a first Bot's default facts, seeding and saving under per-user accounts, what a run on a machine sends back, and the system prompt.

### Moving between the file and the store

The move is the same as for memory (ADR 0276), run on the same passes (a pin, startup, every reconcile):

- Into a store, the file is taken into botd's `facts` table and deleted (a link is left alone), and `place_chats` moves the row to the store, zeroed in botd's database with its WAL emptied.
- Out of a store, the row comes back, botd writes the file (whole and synced, then renamed) and deletes the row, zeroed. A save while the file can't be written goes to the row, never past it, and a later pass writes it.

`place_chats` places each table by its key: rows of Bots by their owner's region, facts by the person's. Moves of facts are recorded per person (`facts_moves_out`) next to the Bots' (`chat_moves_out`), so a store's backups are cleared of them once they leave, and the clearing is audited with `users` and `facts`. Moves are audited with `facts` in `residency.chats_moved`, and reconcile returns `factsMoved`.

### Restore, erasure, a dropped store

- A restore keeps only the rows of Bots and people still kept in the region (`kept_in_region`), so a person who moved since keeps no facts in the restored store, and erasures run again on it.
- Erasing a person deletes their facts row, zeroed, before their pin ends, so no later pass writes them back to a file. Erasing in a copy of a store deletes them there too.
- A store dropped from `REGION_DATA_DIRS` that still holds facts stops botd, as with any other rows.

### Saying so

- Reports, `GET /api/regions` and the app count facts with the rest (`chats.facts`, the "Owners' facts" row in the Markdown report, `chatStore.facts`). A facts file left in DATA_DIR for a person whose facts belong in a store counts as outside the region, so the pin is `data_outside` until the next pass.
- What a pin doesn't cover no longer names botd's files for facts.
- The app says "Your chats, routines, approvals, Bots' memory and the facts your Bots keep about you are kept in ...". The DPA template (annex IV) says the same.

## Consequences

- A pinned person's facts are in their region at rest: in the store, its backups and off-host copies. botd still relays them with each job, as it does chats.
- **On upgrade**, the first start moves pinned people's facts files into their stores. Server backups taken before still hold them, which the report already says.
- Stores and backups from before gain the table when attached or restored.
- The machine folder copy (ADR 0041) seeds facts from the file only, as with memory, so facts kept in a store reach the machine with the first job.

## Not done (still on #58)

- The rest of botd's database per region: accounts, sessions and the audit log are still where botd runs. A pin's report says so.
- Moving a regional store while botd is running.

## Tests

- `db::chats`: a pinned person's facts move to the store and back with the pin; a team pin keeps its members' facts and a member leaving takes theirs out; a dropped store holding facts stops botd; a store from before gains the table; copies of a store are kept and cleared by person as well as by Bot; an erasure deletes facts in a store and in a copy.
- `machines::chat_stores`: a facts file moves into the store and is deleted (a link is left alone), audited with `facts`; unpinned, it is written back, and the store's backups are cleared of it.
- `machines::chat_store_restore`: a restore keeps only the facts of people still kept in the store, none of an erased person's.
- HTTP (`machines_residency_tests.rs`): a pin moves facts into London's store and deletes the file; saves and a new Bot's first facts go there; the report, the regions page and the app count them; a file or row left outside makes the pin unkept until reconcile; unpinned, they are written back; erased, they are gone.
- Client (`residency.test.ts`): Settings names the facts with chats, routines, approvals and Bots' memory.
