# 0316: The details of a pinned person's audit events are kept in their region's chat store

## Status

Accepted (26 Nov 2026). A slice of [#58](https://github.com/CG-Labs/superbot/issues/58) (M5, "Contractual data residency"). Follows [ADR 0309](0309-moving-a-regional-chat-store-while-botd-runs.md) (moving a store while botd runs) and builds on [ADR 0215](0215-pinned-chats-in-a-store-in-their-region.md), [ADR 0238](0238-clearing-moved-rows-from-store-backups.md), [ADR 0256](0256-restoring-a-regional-chat-store.md), [ADR 0304](0304-usage-records-in-the-regional-store.md) and the audit hash chain ([ADR 0122](0122-siem-export-and-tamper-evident-audit.md)). 0316 was reserved for this work.

## Context

After ADR 0304, a pinned person's content, sign-ins, own secrets, second factor and usage records are in their region's store. botd's audit log still holds, for every event they cause, their IP address and browser, their name, email and IdP subject, their session and what changed (`details`). That is the most personal part of the log, and a pin's report named it only as part of "botd's own database".

The log is unlike the earlier tables in three ways:

- It is one hash chain across everyone (ADR 0122). Every row's seal covers its fixed columns, and a salted digest of its erasable columns, so an erasure can clear those without breaking the chain. A row can't leave botd's log without breaking it.
- An append-only trigger refuses any change but an erasure, and SQLite triggers can't write to a table in another attached database.
- Admins read, filter, verify and export it all as one log, across every person.

## Options

1. **Leave the log where botd runs and say so.** It keeps a pinned person's IP addresses and activity outside their region.
2. **Move whole rows into the store.** That breaks the one chain, and with it verification, the evidence pack and the SIEM export's chain fields.
3. **A log per store, each with its own chain.** Verification, filters and exports would have to merge several logs, and an event about two people in two regions has no single home.
4. **Keep each row and its seal in botd's log; move its erasable columns and salt to the store** (chosen). It is the split ADR 0122 already makes for erasure.

## Decision

### Whose event it is

An event belongs to the user who acted (`actor_kind = 'user'`), else the user it was done on behalf of, else the user it is about (`target_type = 'user'`). If that person's pin is held in a region with a store, the event's details are kept there; otherwise in botd's log, as before.

### What stays and what moves

botd's row keeps the event's id, time, action, outcome, kinds, roles, Bot and the chain columns (`chain_prev`, `chain_hash`, `chain_digest`). Its erasable columns (actor id, name, email and subject, target id, IP address, browser, session, on-behalf-of, details) and its salt move to the store's `audit_details`, keyed by the event's id with the person's id. botd's row has those set empty, no salt, and `details` = `{"inChatStore":"<region>"}`, so anyone reading botd's database alone sees where the rest is.

The salt moves with the details: botd's row alone can't be checked against guesses of what it held. With both, verification recomputes the digest exactly as before.

### Writing and reading

New events are written by botd in Rust, not by a trigger: the row to botd's log and the details to the store, in one transaction. Reads (the audit page, filters, `GET /api/audit/verify`, the SIEM export, the archive, evidence packs) go through a view that joins each row to its details wherever they are, so every reader sees the same log as before.

### Moving them

`place_chats` moves them with the person's pin, on the same passes as everything else. botd's append-only trigger now also allows a move: while a setting is held inside the move's transaction, a row may change only if its fixed columns and seal stay the same. botd reinstalls the trigger each start, so no migration is needed. Moves are audited with `auditEvents` in `residency.chats_moved`, reconcile returns `auditEventsMoved`, and moves are recorded per person, so a store's backups are cleared of them once they leave (ADR 0238). A move cut off part way is finished on the next pass: details a store already holds only lose their copy in botd's row. Unpinned, the details go back into botd's rows.

### Erasure and retention

An erasure rewrites the details where they are kept. Retention deletes them with their rows.

### A store lost

If a forgotten store (`REGION_DATA_FORGET`) or a lost one held an event's only details, botd's row has no salt, and verification would fail on it. So botd names those events with an `audit.erased` event (actor `residency`, target the store's region), the same way an erasure names the rows it clears. The log still verifies, and says why those details are gone. Forgetting the store's record and naming its events share one transaction, so a start cut off between them does both again.

### A crash between two files

botd's database and each store are separate SQLite files, and a transaction across them commits each file on its own. So a crash can keep one file's half of a write or move and not the other's. Each start checks every store's events against where their details are:

- An event that points at one store but whose details another holds (a move between stores cut off) is pointed at that store.
- An event whose details no place holds (the store's commit was lost) is named with `audit.erased`, once. Its details are gone, as a whole event cut off before its commit would be.
- Details whose row botd's log lost are ignored by reads (they are only joined to rows with no salt), dropped on the next pass, and their id is never handed out again: botd's id counter is raised past every store's highest at start.

A restore takes the details from the store it replaces, as it does sign-ins. With that store gone, the backup's details are kept, with erasures since the backup applied again. Events whose details only the lost store held are named as erased, and the restore says how many (`auditDetailsLost`).

### Saying so

- Reports, `GET /api/regions` and the app count them with the rest (`chats.auditEvents`; an "Audit events' details" row in the Markdown report).
- What a pin doesn't cover names the audit log's sealed rows, not the details of the person's events. It now also names audit events sent whole to a SIEM or the write-once audit archive.
- The app says "... and the details of the audit log's entries about what you did are kept in ..." only when the server says its store keeps them (`chats.auditEvents` in `GET /api/me/residency`). The DPA template (annex IV) says the same.

## Consequences

- A pinned person's IP addresses, browsers, names and activity details are in their region at rest: in the store, its backups and off-host copies.
- botd's log stays one chain that verifies. Its rows still show when something happened, what kind of thing, and its outcome, but not who did it or to whom.
- **On upgrade**, the first start moves pinned people's audit details into their stores. Server backups taken before still hold them, which the report already says.
- While any store is attached, filters on erasable columns (actor, target, IP) read across the view and can't use botd's indexes, so they scan the log.

## Not done (still on #58)

- Accounts and `usage_daily` stay in botd's own database. A pin's report says so.
- An event an unpinned admin makes about a pinned person is the admin's, so its details stay in botd's log, under the admin's own residency.
- The SIEM export and the write-once audit archive send full events to wherever the operator points them.
- Offline readers of botd's database alone (not through botd) see the placeholders.
- Backups of another region's store keep the pre-erasure details of events that only name an erased person as their target, until a restore applies erasures again.

## Tests

- `db::chats`: a pinned person's audit details move to the store and back with the pin, and new ones are written there; they survive a restart and a pass cut off after its copy; botd's log still refuses any change but an erasure or a move; an erasure rewrites them where they are kept; retention deletes them there; a forgotten store's events are named as erased and the log verifies; a crash between the files' commits is put right on the next start (details lost named once, a cut-off move pointed at the right store, details whose row was lost ignored, dropped and their id not reused); a place's summary names them.
- `machines::chat_store_restore`: a restore takes audit details from the store it replaces; with it gone, the events only it held are named as erased and the log still verifies; it waits for details of someone unpinned to go home first.
- HTTP (`machines_residency_tests.rs`): a pin moves audit details into London's store, audited; the audit page reads them whole, new ones are written there, and verification passes; the report and `GET /api/me/residency` say so; unpinned, they come back and the log still verifies.
- Client (`residency.test.ts`): Settings names the audit details with the rest when the server says so.
