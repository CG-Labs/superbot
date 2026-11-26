# 0304: A pinned person's model usage records are kept in their region's chat store

## Status

Accepted (26 Nov 2026). A slice of [#58](https://github.com/CG-Labs/superbot/issues/58) (M5, "Contractual data residency"). Follows [ADR 0299](0299-second-factors-in-the-regional-store.md) (second factors in the store) and builds on [ADR 0215](0215-pinned-chats-in-a-store-in-their-region.md), [ADR 0238](0238-clearing-moved-rows-from-store-backups.md), [ADR 0256](0256-restoring-a-regional-chat-store.md), [ADR 0050](0050-billing-period-token-usage.md) (usage records) and the Stripe meter they feed. 0304 was reserved for this work.

## Context

After ADR 0299, a pinned person's content, sign-ins, own secrets and second factor are in their region's store. botd's own database still holds a row for every model run of their Bots (`token_usage`, ADR 0050): which Bot, run and message, which harness and model, the tokens in and out, when, and whether it was sent to Stripe's usage meter. Together they show when and how much each person used their Bots, a usage log tied to the person, and a pin's report named it only as part of "botd's own database".

It is per person (`user_id` is the Bot's owner), has no foreign keys, and is read through a handful of queries (quotas, the usage page, the meter and run stats), so it fits the kept-table machinery the earlier slices built. Accounts and the audit log, still left outside, are read by almost every request.

## Options

1. **Leave it where botd runs and say so.** It keeps a log of a pinned person's use outside their region.
2. **Keep only totals in botd's own database.** Quotas would still work, but the meter sends one event per record with that record's id, so it needs the rows.
3. **Move the rows with the pin** (chosen). `token_usage` becomes a kept table keyed by person.

## Decision

### Where they are kept

A person's usage records are kept in the store of their pin (their team's, else their own, as sign-ins, own secrets and second factors are) when that region has one, else in botd's own database as before. Reads (`tokens_used`, the usage summary, the pending meter queue, run stats by harness) go through the view across every place. A new record is written to the store of its owner's pin; marking one sent or failed reaches every place that holds it, so a move cut off between its copy and its delete leaves both copies marked and the record is never sent twice.

### Ids stay unique

A record's id is part of the meter's idempotency key (`superbot-{run}-{id}`) and how the meter marks it, so no two places may hand out the same id. Usage records take ids as chat messages do: botd's own sequence for the table is the one counter. A record written to a store takes the next id past that sequence and every place's highest, and bumps the sequence. On start, the sequence is raised past each store's highest id, so a store attached later never collides. This is the messages code, now shared by both tables.

### Moving them

`place_chats` moves them with the person's pin, on the same passes as everything else: a pin, startup and every reconcile. Moves are audited with `usageRecords` in `residency.chats_moved`, and reconcile returns `usageRecordsMoved`. The audit log hides values under any key containing "token", so neither name says tokens. Moves are recorded per person, so a store's backups are cleared of them once they leave (ADR 0238). Ids move with the rows.

### Restore

A backup holds usage records as they were. Restored as they were, one sent to Stripe since would be pending again and sent twice, and one recorded since would be lost (and its tokens no longer count against the quota). So a restore puts the store's records now, for the people kept in it, in place of the backup's, as it does sign-ins and second factors.

With the store missing or unreadable, the backup's are kept: they are the only copy, and dropping them would undercount quotas and the bill. But nothing then says whether a record still pending in the backup was sent since, so those are marked `failed` (held back from the meter) rather than sent again. The restore says how many (`meterHeldBack` in its note and audit) and asks the operator to check them against Stripe; a double charge is worse than one the operator adds by hand. Records made after the backup are lost with the store, as its chats are; a backup from before this ADR has none of a pinned person's.

### Saying so

- Reports, `GET /api/regions` and the app count them with the rest (`chats.usageRecords`; a "Model usage records" row in the Markdown report). A pinned person's records left in botd's own database, or in another region's store, count as outside the region until the next pass.
- What a pin doesn't cover still names accounts and the audit log, no longer the person's usage records.
- The app says "... your second factor and the usage records of your Bots' runs are kept in ..." only when the server says its store keeps them (`chats.usageRecords` in `GET /api/me/residency`). The DPA template (annex IV) says the same.

## Consequences

- A pinned person's per-run usage is in their region at rest: in the store, its backups and off-host copies.
- **On upgrade**, the first start moves pinned people's usage records into their stores, ids and meter state intact. Server backups taken before still hold them, which the report already says.
- Stripe still gets the meter events (as it did before this): the customer id and token counts leave the region when they are sent, under the operator's Stripe agreement. This ADR is about where botd keeps them.
- Every write to a store-kept record and every quota check reads across the attached stores, as chats already do.

## Not done (still on #58)

- `usage_daily` (per-person counts of routine runs a day, for the daily limit) stays in botd's own database: its writes upsert on a key, which a view across places can't take, and it holds two counts a day, not what was run.
- The rest of botd's database per region: accounts and the audit log are still where botd runs. A pin's report says so.
- Moving a regional store while botd is running.

## Tests

- `db::chats`: a pinned person's usage records move to the store and back with the pin, ids intact; quotas, the usage summary and the meter queue still read them; marking one sent reaches the store; new ones go where their owner's are kept, with ids no place repeats, also after a restart; someone unpinned stays in botd's own; the move is recorded for clearing the store's backups; a move cut off after its copy counts usage once, queues it once and marks both copies; a restored copy takes the store's records now, or keeps its own and marks pending ones failed when the store is gone; a place's summary names them.
- `machines::chat_store_restore`: a restore takes usage records from the store it replaces, so one sent since isn't sent again and one recorded since is kept; with the store gone, the backup's are kept and pending ones held back from the meter, and the result says so.
- HTTP (`machines_residency_tests.rs`): a pin moves usage records into London's store, audited; `GET /api/me/usage` still counts them and new ones are written there; the report and `GET /api/me/residency` say so; one left outside makes the pin unkept until reconcile; unpinned, they come back.
- Client (`residency.test.ts`): Settings names the usage records with the rest when the server says so.
