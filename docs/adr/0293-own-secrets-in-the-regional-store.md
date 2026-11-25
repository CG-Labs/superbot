# 0293: A pinned person's own secrets are kept in their region's chat store

## Status

Accepted (25 Nov 2026). A slice of [#58](https://github.com/CG-Labs/superbot/issues/58) (M5, "Contractual data residency"). Follows [ADR 0283](0283-sign-ins-in-the-regional-store.md) (sign-ins in the store) and builds on [ADR 0215](0215-pinned-chats-in-a-store-in-their-region.md), [ADR 0228](0228-routines-and-approvals-in-the-regional-store.md) (sealing in a store), [ADR 0238](0238-clearing-moved-rows-from-store-backups.md), [ADR 0256](0256-restoring-a-regional-chat-store.md), [ADR 0029](0029-per-user-isolation.md) (a user's own secrets) and [ADR 0010](0010-secrets.md) (secrets). 0293 was reserved for this work.

## Context

After ADR 0283, a pinned person's content and sign-ins are in their region's store. botd's own database still holds, for each person, the secrets they saved for their own Bots (ADR 0029): API keys and tokens, each sealed under the master key, by name. These are among the most sensitive rows a person has. A pin's report said they were outside the region only by naming "botd's own database".

Secrets differ from what moved before in one way: they live on a connection of their own (`secrets::sealed::UserSecrets`, opened at startup before any store is attached), not on botd's main one, so the views and writes botd's database uses for stores don't reach them.

## Options

1. **Leave them where botd runs and say so.** It keeps a pinned person's credentials outside their region.
2. **Route secrets through botd's main connection.** Larger: every secret read and write, and the redactor's startup load, would change hands, and secrets would start depending on the database's lifecycle.
3. **Attach the stores to the secrets' own connection too** (chosen). Same file, same key, same views, so reads are unchanged and writes name the place.
4. **A separate per-region secrets file.** A second kind of regional file to back up, copy off the host, clear and restore. The chat store already does all of that.

## Decision

### Where they are kept

A person's own secrets are kept in the store of their pin (their team's, else their own, as facts and sign-ins are) when that region has one, else in botd's own database as before. `user_secrets` is a kept table keyed by `user_id`, with its primary key `(user_id, name)`. Kept tables could only have a single-column key before; a composite key now works through SQLite row values in the copy, compare and view queries.

Once botd's database has attached the stores at startup, the users' secrets attach the same stores to their connection, with the same database key, and the same `user_secrets` view across every place. Then:

- Reads (`get`, `names`, the redactor's load) go through the view, unchanged.
- A new secret is written to the store of its owner's pin.
- Changing or deleting one reaches every place that holds it, in one write transaction, so a move's copy can't put it back in a place already cleared.

The redactor learned secret values at startup before the stores were attached, and both startup scrubs of saved chats and approvals ran without the stores' values. So once the stores are attached it learns their values, and when they hold any, saved rows in botd's database and every store are scrubbed again.

### Moving them

`place_chats` moves them with the person's pin, on the same passes as facts and sign-ins: a pin, startup and every reconcile. A move cut off between its copy and its delete leaves a secret in two places until the next pass, which keeps either copy. Changes and deletes reach both, so neither is lost. Moves are audited with `personalKeys` in `residency.chats_moved`, and reconcile returns `personalKeysMoved`. The JSON name avoids "secret" because the audit log hides the value of any key that names one. Moves are recorded per person (`facts_moves_out`), so a store's backups are cleared of them once they leave.

### Sealing

At startup, before botd serves anything, each store's secrets are sealed again, as approvals' tool inputs and push tokens are (ADR 0228, ADR 0283): plaintext ones are sealed, ones under the previous key are sealed under the new one, and a store holding ones neither key opens stops botd. Mid-rotation they are left as they are; with `SUPERBOT_FORGET_SEALED=1` the secret is deleted and its owner saves it again. The rotation lines count them.

### Restore

A backup holds secrets as they were when it was made. Restored as they were, a secret deleted since would come back, and one changed since would turn back to its old value. So a restore puts the store's secrets now, for the people kept in it, in place of the backup's. Unlike sessions, a secret can't be made again by signing in. So with the store missing or unreadable, the backup's are kept: they are the only copy left. Kept secrets that neither master key opens (a backup from before a rotation) would stop botd at start, so the restore refuses them, as it does approvals' inputs, unless `SUPERBOT_FORGET_SEALED=1` says botd drops them and their owners save them again. The restore says which it did.

Erasure deletes them in the store and, when a backup is restored, in the backup too.

### Saying so

- Reports, `GET /api/regions` and the app count them with the rest (`chats.personalKeys`; "Personal secrets" rows in the Markdown report). A pinned person's secret left in botd's own database counts as outside the region until the next pass.
- What a pin doesn't cover names accounts and the audit log, no longer the person's own secrets.
- The app says "... your sign-ins and your own secrets are kept in ..." only when the server says its store keeps them (`chats.secrets` in `GET /api/me/residency`). A server from before this keeps them in its own database, and the app says so. The DPA template (annex IV) says the same.

## Consequences

- A pinned person's own API keys and tokens are in their region at rest: in the store, its backups and off-host copies. They were sealed before and still are.
- **On upgrade**, the first start moves pinned people's secrets into their stores. No Bot loses a key. Server backups taken before still hold them, which the report already says.
- The secrets' connection holds the stores open too. Both connections write the same files, under SQLite's locking, as two connections to botd's database already do.
- Server-wide secrets (ADR 0010) stay in botd's own database; they are not a person's own data.

## Not done (still on #58)

- The rest of botd's database per region: accounts and the audit log are still where botd runs. A pin's report says so.
- Moving a regional store while botd is running.

## Tests

- `db::chats`: a pinned person's secrets move to the store and back with the pin; new ones, changes and deletes reach the store and someone unpinned stays in botd's own; the redactor's load sees them; a move cut off after its copy keeps changes and deletes made meanwhile; secrets in a store are sealed at startup; an erasure deletes them in a copy of a store.
- `db::chats`: saved rows are scrubbed again of values only a store holds.
- `machines::chat_store_restore`: a restore takes secrets from the store it replaces, so one deleted or changed since stays so; with the store gone, the backup's are kept; kept ones under a lost key are refused unless botd drops them.
- `main`: the rotation lines count secrets in stores.
- HTTP (`machines_residency_tests.rs`): a pin moves a secret into London's store, audited; the report counts it; one left outside makes the pin unkept until reconcile; unpinned, it comes back.
- Client (`residency.test.ts`): Settings names own secrets with the rest, and not on a server from before this.
