# 0299: A pinned person's second factor is kept in their region's chat store

## Status

Accepted (25 Nov 2026). A slice of [#58](https://github.com/CG-Labs/superbot/issues/58) (M5, "Contractual data residency"). Follows [ADR 0293](0293-own-secrets-in-the-regional-store.md) (own secrets in the store) and builds on [ADR 0215](0215-pinned-chats-in-a-store-in-their-region.md), [ADR 0228](0228-routines-and-approvals-in-the-regional-store.md) (sealing in a store), [ADR 0238](0238-clearing-moved-rows-from-store-backups.md), [ADR 0256](0256-restoring-a-regional-chat-store.md), [ADR 0283](0283-sign-ins-in-the-regional-store.md) (sign-ins), [ADR 0094](0094-totp-second-factor.md) (the second factor) and [ADR 0096](0096-master-key-rotation.md) (key rotation). 0299 was reserved for this work.

## Context

After ADR 0293, a pinned person's content, sign-ins and own secrets are in their region's store. botd's own database still holds each person's second factor (ADR 0094): the TOTP secret their authenticator app shares, sealed under the master key, and their recovery codes, kept as keyed hashes. With the secret, anyone can make that person's codes. It is personal data about how they sign in, as their sessions are, and a pin's report named it only as part of "botd's own database".

What else is left outside (accounts and the audit log) is far larger and is read by almost every request; the second factor is per person, has no foreign keys, and fits the kept-table machinery the earlier slices built.

## Options

1. **Leave it where botd runs and say so.** It keeps a secret that signs a pinned person in outside their region.
2. **Move the TOTP secret only, keep recovery codes in botd's database.** Recovery codes are hashes, but they are still per person and sign them in; splitting them from their factor means two places to check on every sign-in and erasure.
3. **Move both tables with the pin** (chosen). `user_mfa` and `mfa_recovery_codes` become kept tables keyed by person, with the codes as children of the factor.

## Decision

### Where they are kept

A person's second factor and its recovery codes are kept in the store of their pin (their team's, else their own, as sign-ins and own secrets are) when that region has one, else in botd's own database as before. `user_mfa` is a kept table keyed by `user_id`; `mfa_recovery_codes` is keyed by `(user_id, code_hash)` with `user_mfa` as its parent, so a pass sweeps codes whose factor is gone (stores have no foreign keys).

Reads (`mfa`, `mfa_enabled`, `mfa_recovery_left`, sign-in's check) go through the view across every place, unchanged. Writes name the place:

- Starting enrolment writes a new pending factor to the store of its owner's pin; restarting it replaces every copy of the pending one. Both refuse while a confirmed one exists, as before.
- Confirming it, spending a step or a recovery code, new recovery codes and turning it off reach every place that holds it, in one write transaction. New recovery codes are written wherever the factor is, so a move cut off between its copy and its delete keeps codes with both copies.

A code spent during such a cut-off move is spent in both copies, so it never works twice, and the next pass keeps either.

### Moving them

`place_chats` moves them with the person's pin, on the same passes as sign-ins and own secrets: a pin, startup and every reconcile. Moves are audited with `secondFactors` and `recoveryCodes` in `residency.chats_moved`, and reconcile returns `secondFactorsMoved` and `recoveryCodesMoved`. Neither name contains a word the audit log hides. Moves are recorded per person, so a store's backups are cleared of them once they leave (ADR 0238).

### Sealing

At startup, before botd serves anything, each store's second factors are sealed again, as own secrets are (ADR 0293): plaintext ones are sealed, ones under the previous key are sealed under the new one, and a store holding ones neither key opens stops botd. Mid-rotation they are left as they are and counted; with `SUPERBOT_FORGET_SEALED=1` the factor and its codes are deleted and its owner sets it up again. The rotation lines count them.

Recovery codes are keyed hashes under a key derived from the master key. When a rotation renews derived keys (`SUPERBOT_ROTATE_DERIVED_KEYS=1`), botd already drops its own database's codes, since no code would match. It now does the same in each store, for each factor it seals again, and their owners make new codes in Settings.

### Restore

A backup holds second factors as they were when it was made. Restored as they were, one turned off or reset since would come back, and a recovery code spent since would work again. So a restore puts the store's second factors and codes now, for the people kept in it, in place of the backup's.

With the store missing or unreadable, the backup's are kept, as own secrets are: dropping them would let anyone with a person's password sign in as them without the second step, and would turn off a factor their admin may require. Kept ones neither master key opens would stop botd at start, so the restore refuses them unless `SUPERBOT_FORGET_SEALED=1` says botd drops them and their owners set them up again. The restore says which it did.

Erasure deletes them in every place and, when a backup is restored, in the backup too.

### Saying so

- Reports, `GET /api/regions` and the app count them with the rest (`chats.secondFactors`, `chats.recoveryCodes`; "Second factors" and "Recovery codes" rows in the Markdown report). A pinned person's second factor or codes left in botd's own database, or in another region's store, count as outside the region until the next pass.
- What a pin doesn't cover still names accounts and the audit log, no longer the person's second factor.
- The app says "... your own secrets and your second factor are kept in ..." only when the server says its store keeps it (`chats.secondFactors` in `GET /api/me/residency`). A server from before this keeps it in its own database, and the app says so. The DPA template (annex IV) says the same.

## Consequences

- A pinned person's TOTP secret and recovery codes are in their region at rest: in the store, its backups and off-host copies. The secret was sealed before and still is.
- **On upgrade**, the first start moves pinned people's second factors into their stores. Nobody has to set theirs up again. Server backups taken before still hold them, which the report already says.
- Sign-in reads a pinned person's second factor from their region's store. If that store can't be opened, botd doesn't start (ADR 0215), so nobody signs in without it.
- Login challenges (the short-lived wait between password and code) and the second-factor policy stay in botd's own database: one is a few minutes' state, the other is server-wide.

## Not done (still on #58)

- The rest of botd's database per region: accounts and the audit log are still where botd runs. A pin's report says so.
- Moving a regional store while botd is running.

## Tests

- `db::chats`: a pinned person's second factor and recovery codes move to the store and back with the pin; enrolment, confirmation, spent codes, new codes and turning it off reach the store, and someone unpinned stays in botd's own; a move cut off after its copy keeps changes made meanwhile and a spent code stays spent; second factors in a store are sealed at startup, resealed in a rotation (dropping codes when derived keys are renewed) and dropped with `SUPERBOT_FORGET_SEALED=1`; an erasure deletes them in the store and in a copy of it; a place's summary names them.
- `machines::chat_store_restore`: a restore takes second factors from the store it replaces, so one turned off since stays off and a code spent since stays spent; with the store gone, the backup's are kept; kept ones under a lost key are refused unless botd drops them.
- `main`: the rotation lines count second factors in stores.
- HTTP (`machines_residency_tests.rs`): a pin moves an enrolled second factor and its codes into London's store, audited; sign-in still asks for it and takes a code; new recovery codes are written there; the report and `GET /api/me/residency` say so; one left outside makes the pin unkept until reconcile; unpinned, it comes back.
- Client (`residency.test.ts`): Settings names the second factor with the rest, and not on a server from before this.
