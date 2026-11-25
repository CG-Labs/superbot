# 0283: A pinned person's sign-ins are kept in their region's chat store

## Status

Accepted (25 Nov 2026). A slice of [#58](https://github.com/CG-Labs/superbot/issues/58) (M5, "Contractual data residency"). Follows [ADR 0277](0277-owners-facts-in-the-regional-store.md) (owners' facts in the store) and builds on [ADR 0215](0215-pinned-chats-in-a-store-in-their-region.md), [ADR 0238](0238-clearing-moved-rows-from-store-backups.md), [ADR 0256](0256-restoring-a-regional-chat-store.md), [ADR 0080](0080-client-push-notifications.md) (push devices) and [ADR 0137](0137-saml-signed-requests-and-single-logout.md) (SAML sessions). 0283 was reserved for this work.

## Context

After ADR 0277, all of a pinned person's content is in their region's store. What stays where botd runs is botd's own database: accounts, sign-in sessions and the audit log. Of these, sessions are the most personal and the busiest. Each one holds the IP address and browser (user agent) of every device the person signs in from, and when they last used it. With a session come two more tables: the native SAML sign-in that made it (the IdP's NameID and session index), and the phone it registered for push, with the phone's sealed push token.

Accounts are referenced by nearly every table, so moving them means splitting botd's schema. The audit log is one hash chain across everyone. Sessions are per person and fit the machinery ADR 0277 built for facts: rows keyed by person, placed by their pin, moved, cleared from backups and restored the same way.

## Options

1. **Leave sessions where botd runs and say so.** That is what the report does today. It leaves the IP addresses and devices of pinned people outside their region.
2. **Move only `sessions`.** `saml_sessions` and `push_devices` reference a session with a foreign key that deletes them with it. Left in botd's database, they would point at sessions that aren't there, and a SAML sign-in names the person at their IdP.
3. **Move a session with its SAML sign-in and push device** (chosen). Three kept tables keyed by person, placed together.
4. **Split accounts first.** Larger and riskier, and nothing else needs it to start with sessions.

## Decision

### Where they are kept

A person's sessions, their SAML sign-ins and push devices are kept in the store of their pin (their team's, else their own, as facts are) when that region has one, else in botd's own database as before. `sessions`, `saml_sessions` and `push_devices` are kept tables keyed by `user_id`. `saml_sessions` gains a `user_id` column (a migration fills it from its session). Each store gets the unique indexes botd's tables have on a token's hash and a device's session, so the same checks hold there.

Reads go through the views every place shares, so signing in, checking a session, listing them and finding the phones to notify are unchanged. Writes name the place:

- A new session is written to the store of the person's pin.
- A SAML sign-in and a push device are written where their session is, so the three always move together.
- Touching, revoking, pruning and erasing run on every place.

### Moving them

`place_chats` moves the three with the person's pin, on the same passes as facts: a pin, startup and every reconcile. A store has no foreign keys, so a move deletes a session's SAML sign-in and push device before the session (botd's own tables would delete them with it, uncounted). Pruning, and each move, sweeps a store of SAML sign-ins and push devices whose session is gone.

A move cut off between its copy and its delete leaves a session in two places for one pass. Revoking it reaches both, and revoking all of someone's sessions tells their IdP once.

Moves are audited with `sessions`, `samlSessions` and `pushDevices` in `residency.chats_moved`, and reconcile returns `sessionsMoved`, `samlSessionsMoved` and `pushDevicesMoved`. They are recorded per person (`facts_moves_out`), so a store's backups are cleared of them once they leave.

### Push tokens

A push token is sealed under the master key. At startup, before botd serves anything, push tokens in each store are sealed again, as approvals' tool inputs are (ADR 0228): plaintext ones are sealed, ones under the previous key are sealed under the new one, and a store holding ones neither key opens stops botd. Mid-rotation they are left as they are; with `SUPERBOT_FORGET_SEALED=1` the device is deleted and the phone registers again. The rotation lines count them.

### Restore

A backup of a store holds sessions as they were when it was made. Restored as they were, a session revoked since would work again. So a restore puts the store's sessions now, for the people kept in it, in place of the backup's. With the store missing or unreadable, the backup's are dropped and their people sign in again. A restore never brings a session back, and signs out nobody who is signed in. The restore says which it did.

### Saying so

- Reports, `GET /api/regions` and the app count sign-ins with the rest (`chats.sessions`, `chats.samlSessions`, `chats.pushDevices`; "Sign-in sessions", "SAML sign-ins" and "Push devices" rows in the Markdown report). A pinned person's session left in botd's own database counts as outside the region until the next pass.
- What a pin doesn't cover names accounts and the audit log, no longer sessions.
- The app says "Your chats, routines, approvals, Bots' memory, the facts your Bots keep about you and your sign-ins are kept in ...". The DPA template (annex IV) says the same.

## Consequences

- A pinned person's IP addresses, devices and push tokens are in their region at rest: in the store, its backups and off-host copies.
- **On upgrade**, the first start moves pinned people's sessions into their stores. Nobody is signed out. Server backups taken before still hold them, which the report already says.
- Each sign-in check reads across every attached store, as chat reads already do.
- Store tables don't repeat botd's `CHECK` constraints; only botd writes them.

## Not done (still on #58)

- The rest of botd's database per region: accounts and the audit log are still where botd runs. A pin's report says so.
- Moving a regional store while botd is running.

## Tests

- `db::chats`: a pinned person's sessions, SAML sign-ins and push devices move to the store and back with the pin; new ones, touches and revokes reach the store, and a token moved between sessions stays one device; pruning and erasure clear them in a store; a move cut off after its copy still revokes once; push tokens in a store are sealed at startup; stores gain the unique indexes; copies of a store are cleared of sessions by person.
- `machines::chat_store_restore`: a restore takes sign-ins from the store it replaces, so a session revoked since stays revoked; with the store gone, the backup's are dropped.
- `main`: the rotation lines count push tokens in stores.
- HTTP (`machines_residency_tests.rs`): a pin moves a session into London's store and it still signs in; a new sign-in lands there; the report counts them; a session left outside makes the pin unkept until reconcile; signing out ends it there; unpinned, they come back.
- Client (`residency.test.ts`): Settings names sign-ins with the rest.
