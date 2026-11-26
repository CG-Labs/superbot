# 0321: Events about a pinned person are kept in their region's store, whoever made them

## Status

Accepted (26 Nov 2026). A slice of [#58](https://github.com/CG-Labs/superbot/issues/58) (M5, "Contractual data residency"). Follows [ADR 0316](0316-audit-details-in-the-regional-store.md) (audit details in the regional store), which left this on #58's list, and builds on [ADR 0238](0238-clearing-moved-rows-from-store-backups.md) and [ADR 0256](0256-restoring-a-regional-chat-store.md). 0321 was reserved for this work.

## Context

ADR 0316 keeps the details of a pinned person's audit events in their region's chat store. An event belongs to the person who acted, else the one a Bot acted for, else the one it is about, decided from its columns alone. So an event an admin makes about a pinned person (pinning them, changing their role, resetting their second factor, erasing a Bot, getting their residency report) is the admin's. When the admin isn't pinned, its details stay in botd's log: the pinned person's name, email and what changed, next to the admin's IP address, outside the person's region.

#58's list named two things left: these events, and accounts. These events are the smaller piece, and the one a customer is most likely to ask about: an admin's changes to a pinned person's account, and the reports on their pin, are about that person. Accounts by region is a much larger change (botd's `users` table is joined almost everywhere) and stays for later.

## Options

1. **The person it is about, always.** Simple and fixed, but an event a pinned admin makes about an unpinned person would leave the admin's region, which ADR 0316 keeps.
2. **Two copies, one per person.** Erasure, verification and moves would have to keep both in step, and the chain covers only one salt.
3. **The first of the event's people who is held in a store** (chosen): the person who acted, the one a Bot acted for, the person it is about, in that order, but skipping anyone whose pin isn't in a region with a store.

## Decision

### Whose event it is

An event's details are kept for the first of its people (the user who acted, the user a Bot acted for, the user it is about) whose pin, their team's first, is in a region with a store. With none, they stay in botd's log, as before. So:

- An unpinned admin's event about a pinned person is kept in that person's store.
- A pinned person's own events stay theirs, even about someone pinned elsewhere (ADR 0316 unchanged).
- A system, SCIM or service account event about a pinned person is theirs, as before.

### Who it belongs to can change

Whether someone is held in a store changes with pins, so who an event belongs to is decided again on every pass (`place_chats`), not only when it is written. Before the pass moves anything, each place's details (each store's, and botd's own `audit_details` mid-move) are given to whoever they belong to now (`audit_reown`), and then move with that person as everything else does. For example: Cy, an unpinned admin, edits Ada (pinned to London), so the details go to London, kept for Ada. If Cy is then pinned to Frankfurt, they are Cy's and move to Frankfurt. If Cy is unpinned again, they are Ada's again and go back to London. If neither is held, they go back into botd's log.

This needs the event's fixed columns (`actor_kind`, `target_type`) from botd's row, so the re-owning joins each place's details to it.

### Backups and restores

A store's backups keep each event's details under the person they were kept for when the backup was made. That may not be the person they belong to now. So:

- **Clearing a store's backups** (ADR 0238) takes out the audit details the store no longer holds, by event id, rather than those of the people who left. Details kept for one person in a backup but for another now are cleared once they leave the store, and never while they are still there.
- **A restore with the store gone** (ADR 0256) keeps the backup's details only for events botd's log says this store holds, whoever the backup kept them for, and drops the rest as kept elsewhere now. The next pass gives them to whoever they belong to. A restore with the store readable still takes them from that store, as before: it waits, as for any row, while the store holds details kept for someone who left until a pass gives them to whoever they belong to now.
- Placement doesn't wait for clearing. Details that come back to the store while its backups are cleared may still be taken out of them, as if the clearing had come first. The store holds them, and the backups taken from then on do too.

### Saying so

`GET /api/me/residency` adds `chats.auditAbout`. The app then says "... and the details of the audit log's entries about what you did and what others not held in another region did about you are kept in ...". The DPA template's annex IV, the data flows page and the ops guide say the same. Reports count these events with the person's own.

## Consequences

- An admin's changes to a pinned person's account, the reports on their pin and their pin's own events are kept in the pinned person's region. The admin's IP address and name for those events are there too: the event is about the pinned person, and an admin who isn't pinned has no region to keep them in.
- **On upgrade**, the first pass moves the details of existing events about pinned people made by unpinned users into the person's store. Server backups taken before still hold them, which the report already says.
- Every pass now reads each store's audit details once to see who they belong to. That's a scan of their primary keys and one lookup per row, cheap next to the moves it decides.
- Restoring a backup with the store gone no longer drops details whose person left the region but which still belong there through another of the event's people.

## Not done (still on #58)

- Accounts and `usage_daily` stay in botd's own database. A pin's report says so.
- An event a pinned person makes about someone pinned in another region stays in the first person's store.
- The SIEM export and the write-once audit archive send full events wherever the operator points them (ADR 0316).

## Tests

- `db::chats`: an event's people are listed in order without repeats; an unpinned admin's events about a pinned person wait in botd's log, counted as that person's, until the next pass moves them to their store, and new ones are written there; one by someone pinned elsewhere stays with them; when the admin is pinned to another region, the events become the admin's and move there; when the admin is unpinned, they go back to the person's store; with neither pinned, they go back into botd's log, which still verifies; a backup restored with its store gone keeps only the details botd's log says the store holds.
- `machines::chat_store_restore`: a restore waits while the store holds details kept for someone who left, then keeps them for the other person they belong to.
- `machines::chat_stores`: a store's backups are cleared of details that left the store with another of their people, though the backup kept them for someone else, and keep those still in the store when the person the backup kept them for leaves.
- HTTP (`machines_residency_tests.rs`): the admin's pin of a pinned person, and the first residency report on it, are kept in the person's store; `GET /api/me/residency` says `auditAbout`.
- Client (`residency.test.ts`): Settings names what others did about you when the server says so.
