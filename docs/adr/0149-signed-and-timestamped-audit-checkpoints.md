# 0149: Signed and timestamped audit checkpoints

## Status

Accepted (22 Nov 2026). Second slice of [#56](https://github.com/CG-Labs/superbot/issues/56) in M5. Builds on the hash chain and SIEM export ([ADR 0122](0122-siem-export-and-tamper-evident-audit.md)), whose "Later" list had external timestamping of checkpoints, signed checkpoints, and a UI for the chain's state. 0143 to 0148 are held by other open work.

## Context

ADR 0122's chain has no key, on purpose: a key on the same host doesn't stop root. What catches a rebuilt chain is a copy of its hashes kept elsewhere, today the SIEM. That leaves three gaps:

- **No SIEM, or a SIEM the attacker also reaches.** Many self-hosters have no SIEM. Then nothing outside the host remembers the head.
- **Backdating.** Even with a SIEM, nothing says *when* a head existed, except the SIEM's own clock and retention.
- **Copies without the key.** A stolen backup of `app.sqlite`, a database-level user, or a script with SQL access can rebuild the chain without touching `master.key`. A signature by a key derived from `master.key` catches all of them.

Operators also asked to see the chain's state without reading JSON: the head, the last checkpoint, whether timestamps work, how far the export is behind, and the last check.

Constraints: no paid service required, off by default for anything that leaves the host, audit writes must never wait on a third party, no new heavy dependencies, and no changes to the secrets backends or RBAC code (both have other work in flight).

## Options

**Signing**

1. **Ed25519 with a key derived from the master key.** Nothing new to store, back up or rotate; `aws-lc-rs` (already a dependency) signs and verifies.
2. **A separate key file.** One more secret to back up and protect, for no gain against root, who reads both.
3. **A key in the external secrets backend.** Would touch the backends, and checkpoints would stop when the backend is down.

**External time**

1. **RFC 3161 time-stamping (TSA).** A standard every CA and many free services run (FreeTSA, DigiCert, Sectigo, Apple, a company's own). Tokens are CMS SignedData that anyone can check with `openssl ts -verify`, offline, for as long as the TSA's certificate chain is kept.
2. **A transparency log (Sigstore Rekor).** Needs network access to Rekor to check, its own client format, and puts entries on a public log.
3. **Blockchain anchoring (OpenTimestamps).** Slow (hours to confirm), and verification needs the chain's data.

**Where checkpoints live**

1. **As audit events, sealed onto the chain**, with a side table for what changes after (the token).
2. **Only in a side table.** Then deleting a checkpoint wouldn't break the chain.

## Decision

Signing option 1, external time option 1, storage option 1.

### Checkpoints

- **When**: every `AUDIT_CHECKPOINT_MINUTES` (default 60; `0` turns the schedule off), if something other than checkpoint events happened since the last one, and on `POST /api/audit/checkpoints` (`botctl audit checkpoint`). Ticks once a minute.
- **What is signed**: the head the checkpoint is sealed onto, as a fixed statement:

  ```
  superbot-audit-checkpoint-v1
  seq=<id of the head>
  hash=<its chain_hash>
  at=<unix ms>
  key=<key id>
  ```

  An empty log signs `seq=0` and the genesis hash.
- **Written as an event.** The checkpoint is an `audit.checkpoint` event recorded inside the chain's write lock (`audit_chain::insert_with`), so the head it signs is exactly its own `chainPrev`, with nothing sealed in between. Its details are the statement's fields, the public key and the signature, all hex and numbers. Its record in `audit_checkpoints` (keyed by the event id) is written in the same transaction. A trigger refuses any change to what was signed, and to a token once stored. Retention deletes a record with its event, or, when its timestamp event came later (after a TSA outage), with that one, so the export and the check still have the token. A record with no `audit.checkpoint` event behind it is never shown, scheduled from or stamped.
- **The key**: Ed25519, the seed derived from the master key's root for `audit/checkpoint-signing/v1` ([ADR 0096](0096-master-key-rotation.md)). It survives rotation unless the rotation makes new derived keys; then the next checkpoint uses the new key. The key id is the first 8 bytes of SHA-256 of the public key, in hex. Every key used is kept in `settings` (`audit_checkpoint_keys`) and recorded once as `audit.checkpoint_key`, so the SIEM gets each public key the moment it is first used.
- **The public key** is at `GET /api/audit/checkpoints/key` and `botctl audit key`.

### Timestamps

- **Off by default.** `AUDIT_TIMESTAMP_URL` names an RFC 3161 TSA (`http` or `https`: the token is signed, and only a hash is sent). No credentials, query or fragment in the URL; only scheme, host and port are shown and logged.
- **What is stamped**: SHA-256 of the statement, `\nsig=`, and the signature hex. A request carries a random 64-bit nonce and asks for the TSA's certificate. `Content-Type: application/timestamp-query`, 30-second timeout, no redirects, replies capped at 256 KiB.
- **Checked before it's kept**: the reply must grant a token whose TSTInfo names SHA-256 and our imprint and nonce, whose signed attributes' digest matches, whose signature verifies (RSA PKCS#1 v1.5, ECDSA P-256/P-384 or Ed25519) under a certificate the ESS signing-certificate attribute names, with `timeStamping` as its only extended key usage, marked critical (RFC 3161 2.3, as `openssl ts -verify` checks), and valid at the token's time. With `AUDIT_TIMESTAMP_CA_FILE` (PEM), the certificate must chain to one of those CAs, a path `webpki` checks as RFC 5280 asks (path lengths, name constraints, unknown critical extensions), with no certificate on it limited to uses other than time-stamping; without it, tokens are kept and shown as `trusted: null`, since botd has no TSA roots of its own to check against.
- **Kept** as base64 DER in the record, and recorded as an `audit.checkpoint_timestamped` event with the TSA's time, serial, policy, certificate hash and subject, and the token's SHA-256. The event is sealed onto the chain like any other.
- **Never in the way.** One task stamps the oldest pending checkpoint at a time, woken when one is made. A failure is retried with backoff from 1 second to 5 minutes, with jitter. Audit writes never wait. After 3 failures in a row, `audit.timestamp_failing` is recorded once (with a `reason`: `unreachable`, `refused`, `malformed`, `imprint`, `nonce`, `signature`, `certificate`, `untrusted` or `unsaved`), then `audit.timestamp_recovered`. A checkpoint waiting for its token is not a failure of the chain.
- No ASN.1 crate: a small DER reader and writer, with `x509-parser` for certificates and `rustls-webpki` for certificate paths (both already in the build, through rcgen and rustls). Tested against real tokens from FreeTSA and DigiCert and a fake TSA built with `rcgen`.

### Verification

`GET /api/audit/verify` and `botctl audit verify` now also check, for every intact event they walk:

- **`audit.checkpoint`**: it names the head it is sealed onto (`hash` is its `chainPrev`, `seq` the event before it), the key id matches the key, the key is trusted, the signature verifies, and its record exists and matches. Failing any is a break with reason `checkpoint`.
- **`audit.checkpoint_timestamped`**: the record it names points back to it, the stored token is the one recorded (SHA-256), and the token verifies against the statement and signature, with the nonce and, when set, the CA file. Failing any is a break with reason `timestamp`. A timestamp whose checkpoint is before the walk and gone (pruned) is skipped.
- **Records without events**: a checkpoint record, or a stored token, that no event in the log accounts for is a break too, wherever its id points (past the head included), so a forged record can't pose as the last checkpoint. A record whose checkpoint was pruned must be kept by its timestamp event.

The report's `checkpoints` has how many were checked and stamped, how many stamps chain to the CA file, the last checkpoint and timestamp, the keys trusted, and `firstBroken` with a specific reason (`head`, `key`, `signature`, `record`, `malformed`, or the token's own: `imprint`, `nonce`, `certificate`, `untrusted`, ...) and message.

New options:

- `from=<id>` and `to=<id>` (`--from`, `--to`) limit the walk. A range starting after the first event takes that event's link as stored. Pins outside it report `outside`. When erased events in it wait for an `audit.erased` after its end, the walk carries on to the head, every check included, so a rewritten erasure can't excuse them; the report's `range` says how far it went. The app marks a partial check's result as such.
- `key=<hex>` (`--key`, repeatable) trusts only those public keys instead of botd's own, now and before. Use it with a key taken from the SIEM or an earlier `botctl audit key`: the key history lives in the database, which is what the check doubts.

### The chain's state

`GET /api/audit/chain` and `botctl audit chain` (admins): the head, the anchor, the checkpoint schedule, count, key and last checkpoint (with its timestamp), how many events since, the TSA, how many tokens are stamped and pending, whether stamping is failing and its last error, the SIEM export's progress (as `GET /api/audit/siem`), and the last `audit.verified` result. `GET /api/audit/checkpoints` lists checkpoints, newest first, with their tokens.

In the app, the audit log has a **Chain** panel: read-only lines for the last check, the head, the last checkpoint, timestamps and the export, each marked good, warning or bad, the checkpoint key, and a **Check now** button that runs the same check as `botctl audit verify`.

### The SIEM export

Both checkpoint events go out with the rest, and each carries a `checkpoint` object with its record: the statement, signature, public key and key id, and, on `audit.checkpoint_timestamped`, the token (base64), its imprint and the TSA. A SIEM can check both with `openssl` and nothing from botd.

`/metrics` adds `superbot_audit_checkpoint_last_timestamp_seconds`, and with a TSA, `superbot_audit_timestamp_pending_checkpoints`, `superbot_audit_timestamp_failing` and `superbot_audit_timestamp_last_timestamp_seconds`.

## What it does and doesn't prove

- **Against someone with the database but not `master.key`** (a stolen backup, SQL access): they can rebuild the chain, but not sign the checkpoints on it. Every checkpoint after the change breaks (`head`), and forging one breaks as `key`.
- **Against root** (who has both): the signatures prove nothing, as ADR 0122 says of any key on the host. The timestamps still do: a rebuilt chain can't get tokens for the past, so a checkpoint whose head changed shows as broken, and new tokens carry today's time. The SIEM's copy, and pinning `--key` with a key taken from it, remain the stronger checks.
- **Against a TSA that lies**: trust in the time is trust in the TSA. Pick one whose policy you accept, set `AUDIT_TIMESTAMP_CA_FILE`, and keep its certificates: a token is checkable for as long as its chain is.
- **Between checkpoints**: a change to events after the last checkpoint is caught by the chain and the SIEM, not by a signature. Shorter intervals narrow that window.

## Consequences

- Hourly checkpoints add up to 24 events a day (48 with a TSA), only while there is other activity.
- An erasure leaves checkpoint and timestamp events alone: they hold hashes and numbers, never personal data, and rewriting them would break the check.
- Master key rotation with new derived keys starts a new checkpoint key; old checkpoints still verify against the kept key history, or with `--key` for each key.
- A raw edit of `audit_checkpoints` now shows in `botctl audit verify`, like a raw edit of `audit_events`.
- Later for #56: stamping each checkpoint with more than one TSA. S3 batches with write-once storage came in [ADR 0154](0154-write-once-s3-audit-archive.md).
