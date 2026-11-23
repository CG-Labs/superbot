# 0122: SIEM export and a tamper-evident audit log

## Status

Accepted (22 Nov 2026). First slice of [#56](https://github.com/CG-Labs/superbot/issues/56) in M5. Builds on the audit log ([ADR 0009](0009-audit-events.md)), its actors ([ADR 0019](0019-audit-actors.md)), retention and erasure ([ADR 0102](0102-erasing-a-users-data.md)). ADR 0009 left "SIEM export and tamper evidence" for M5.

0120 is the highest number on `main`; open PRs hold 0121, 0123 and 0125.

## Context

The audit log is a SQLite table that triggers keep append-only. That stops mistakes and API misuse, but anyone who can write `app.sqlite` (the service user, root, someone with a backup) can drop the triggers and change, delete or add rows, and nothing shows it. Enterprise buyers also want the events in their own SIEM (Splunk, Elastic, Sentinel, Datadog, a syslog server), where they correlate them and keep them for years, out of reach of the host's admins.

Constraints:

- **Existing databases** upgrade in place, with their history.
- **Retention** (`AUDIT_RETENTION_DAYS`) deletes old rows, and **erasure** (ADR 0102) rewrites the personal fields of a person's rows to a pseudonym. Both must keep working, and neither may break the evidence.
- **Nothing leaves the host unless asked.** No secret may reach the sink.
- No new heavy dependencies; botd already has `sha2`, `reqwest` and `rustls`.

## Options

**Tamper evidence**

1. **Per-row hash chain** in the table. Each row stores the hash of the one before it and of its own content; verification walks it and names the first break. Cheap, local, works with any backup.
2. **HMAC chain under a key** (the master key). Someone with the database but not the key can't rebuild the chain. But the master key sits on the same host (`DATA_DIR`), so the attacker this is for (root) has it too, and rotating it would mean re-hashing history.
3. **Write-once storage** (S3 Object Lock, WORM). The strongest, but needs a provider and is a deployment choice, not something botd can do alone.
4. **A transparency log or external timestamping** (RFC 3161, Sigstore Rekor). A third party that must be reachable, for every row or every checkpoint.

**Export**

1. **HTTPS webhook with JSON lines**: every SIEM and log pipeline takes it (Splunk HEC raw, Elastic, Vector, Fluent Bit, Logstash `http`, Datadog, Sentinel via a collector).
2. **Syslog** (RFC 5424) over TLS (RFC 5425): what older SIEMs and rsyslog/syslog-ng take.
3. **S3 objects**: batches to a bucket, often with Object Lock. Useful, but SIEMs read it on their own schedule and it overlaps the backups' store.
4. **Kafka, OTLP logs, vendor APIs**: more dependencies, one vendor each.

## Decision

Option 1 for tamper evidence, without a key, with the hashes copied off the host by the export, which is where the guarantee comes from. Options 1 and 2 for export. Write-once storage, S3 batches and timestamping are later work that build on the same chain.

### The hash chain

Four columns on `audit_events`: `chain_prev`, `chain_hash`, `chain_salt`, `chain_digest`.

```
chain_digest = SHA-256("superbot-audit-chain-v1" \n "erasable" \n chain_salt \n JSON[erasable columns])
chain_hash   = SHA-256("superbot-audit-chain-v1" \n chain_prev \n JSON[fixed columns] \n chain_digest)
```

- **Fixed columns** are the ones nothing may change: `id, at, actor_kind, action, target_type, bot_id, outcome, actor_role, auth_method, idp, idp_provider`. **Erasable columns** are the ones erasure may rewrite: `actor_id, actor_name, actor_subject, target_id, ip, user_agent, details, actor_email, session_id, on_behalf_of`. Each list is a JSON array of the stored values, so NULL, numbers and text can't be confused and no field runs into the next. A BLOB, which botd never writes, is `{"blob": "<hex>"}`, so storing a value as another type breaks the link too.
- **`chain_salt`** is 16 random bytes per row. Erasure clears it along with the person's data and keeps the digest. The chain still verifies: an erased row's digest is taken as written. And the digest no longer reveals anything: without the salt, nobody can test a guess of the old values against it. A row whose fields changed while its salt is kept is a change, not an erasure.
- **Erasures are on the chain too.** In its own transaction, an erasure writes `audit.erased` naming the rows whose salt it cleared, as id ranges. An erased row that no intact `audit.erased` after it names fails as `erased`. Intact means with its salt, so the rows it names are checked: no erasure clears an `audit.erased` event's salt (it holds nobody's data), so one without a salt names nothing and fails as `erased` itself. Otherwise someone could clear its salt, widen its rows, and change any row they cover with every hash, and so every pin, unchanged. Without this, clearing a salt by hand would let someone with the database change a row's erasable fields unseen. They could still append a forged `audit.erased`, but that is a new event the SIEM receives, not a silent change.
- **The first row** links to 64 zeros. A row written after pruning links to the **anchor**: the id and hash of the last pruned row, kept in `settings`.
- **Writing** happens in one place (`audit_chain::insert`). It takes SQLite's write lock (`BEGIN IMMEDIATE`) when not already in a transaction, reads the last hash, and picks the id itself, so two writers can't fork the chain. A `BEFORE INSERT` trigger refuses a row without a seal. The update trigger now also refuses any change to the seal, except clearing the salt during an erasure.
- **Pruning** deletes only a run from the start of the log, by id: an old row written after a younger one waits for it. The last deleted row becomes the anchor, in the same transaction. `audit.pruned` records the anchor. Pruning never goes past what the SIEM export has delivered.
- **The migration** seals existing rows in id order and records `audit.schema_upgraded` (target `audit/chain`, with how many it sealed). History from before the upgrade is only as trustworthy as it was then; the chain covers it from now on.
- **Verification**: `GET /api/audit/verify` (admins) and `botctl audit verify`, which exits 1 on a break. It walks the chain in batches and returns `ok`, how many rows it checked and found erased, the first and the head (id and hash), the anchor, and `firstBroken` (the lowest id that breaks) with a reason: `unsealed` (no seal, or one that isn't text), `link` (a row before it was removed, added, reordered, or the start was cut without an anchor), `contents` (the row changed), `erased` (its salt is gone but no erasure names it), or `pin`. Each row is judged against the row before it as stored, so one changed row counts once. A row that can't be read fails the check (`error`); it is never skipped. Pruning while a check runs moves the anchor, so a check that fails then is run again, up to three times.
- **Pins**: `?pin=<id>:<hash>` (repeatable, up to 100). Hashes kept elsewhere, from the SIEM or an earlier check, that the row must still have. Results: `match`, `mismatch`, `gone` (older than the anchor, so pruned) or `missing` (newer than anything pruned, yet not there: deleted, or an older backup restored), which fails. The pruned anchor row still matches.
- **Checkpoints**: botd verifies itself a minute after start and then daily, and records `audit.verified` with the result and the head's hash (`success` or `failure`). Every check through the API is recorded too. A break also logs a warning.

### What it does and doesn't prove

Without a key, anyone with write access to the database can rebuild the whole chain after changing a row, and verification on that host alone will pass. The chain makes that detectable from outside: every exported event carries its `chainPrev` and `chainHash`, and each `audit.verified` checkpoint carries the head. A rebuilt chain no longer matches the hashes the SIEM already has. Checking them is `botctl audit verify --pin <id>:<hash>`, with a hash taken from the SIEM. A key on the same host wouldn't change this against root, so we don't pretend it does. What the chain proves alone: rows weren't changed, removed, inserted or reordered through anything but a deliberate rebuild, which is what backups restored from, bugs and casual edits produce.

### The SIEM export

Off unless `AUDIT_EXPORT` is set.

| Variable | Default | Meaning |
|---|---|---|
| `AUDIT_EXPORT` | `off` | The sink. `https://...`: POST JSON lines. `syslog+tls://host[:6514]`: RFC 5424 over TLS. `http://` and `syslog+tcp://` only to loopback |
| `AUDIT_EXPORT_INSECURE` | `off` | `on` allows `http://` and `syslog+tcp://` to any host (a collector on a private network) |
| `AUDIT_EXPORT_HEADERS` or `_FILE` | none | `name=value` headers for an HTTPS sink, split by commas (a token). A server secret: redacted everywhere, no harness inherits it |
| `AUDIT_EXPORT_START` | `all` | Where a new sink starts: `all` sends the history still in the database, `new` only what comes after |

- **Delivery** is at least once (for the webhook; see syslog below), in id order, in batches of up to 200, by one task. The last delivered id is saved per sink in `settings`, so a restart, or a sink that comes back, resumes there. A sink should de-duplicate on `id` (plus `host`).
- **Retries** back off from 1 second to 5 minutes, with jitter, forever. Events wait in the database. Retention never deletes past the cursor, so a long outage grows the table instead of losing events. After 3 failures in a row, `audit.export_failing` is recorded once and a warning logged. `audit.export_recovered` follows when delivery resumes. Both go out with the next batch.
- **Webhook**: `POST` with `Content-Type: application/x-ndjson`, one event per line; any 2xx is success. 30-second timeout. No redirects, which could carry the headers elsewhere. URLs with user info, a query or a fragment are refused, so a token can't hide in them; only the scheme, host and port are logged or shown.
- **Syslog**: RFC 5424, facility 13 (log audit), severity 6 for success, 5 for failure, 4 for denied. APP-NAME `superbot`, MSGID the action, no structured data, the JSON line as the message. Framed by octet counting (RFC 5425 / RFC 6587). TLS checks the server's certificate against the system's roots. Syslog has no acknowledgement: a batch counts as delivered once written to the connection, so a connection that drops can lose what was in flight. Gaps show as missing ids and broken `chainPrev` links in the SIEM. Use the webhook where every event must arrive.
- **The cursor** is saved before a batch counts as delivered. If it can't be saved (a full disk), that is a failed try and the batch goes again.
- **The payload** is the API's event (`GET /api/audit`), plus `schema: "superbot.audit.v1"`, `host`, `chainPrev` and `chainHash`. Events are scrubbed when written (secrets redacted, tokens and passwords never recorded), so nothing new can leak. The headers are never in a payload. Errors are redacted before they are logged or recorded.
- **Status**: `GET /api/audit/siem` and `botctl audit siem` show the sink, delivered, pending, failing, and the last error. `/metrics` has `superbot_audit_export_pending_events`, `superbot_audit_export_failing` and `superbot_audit_export_last_delivery_timestamp_seconds`.

Erased data already in a SIEM isn't erased by botd. The operator's DPA and the SIEM's own retention cover it, as they do for backups.

## Consequences

- Every audit write now takes the write lock and one extra read. Writes are already serialised behind one connection, so this costs a few microseconds.
- Old rows written after a younger one now wait for it before retention deletes them. With botd stamping rows as it writes them, that only happens around clock changes.
- Restoring a backup older than the last export shows as `mismatch` for pins taken after it. That's correct: the history on the host differs from the one the SIEM saw.
- A raw `INSERT INTO audit_events` (a script, a future migration) now fails. Code must use `audit_chain::insert`.
- Later: S3 batches with Object Lock. Signed checkpoints, their RFC 3161 timestamps, and a view of the chain's state came in [ADR 0149](0149-signed-and-timestamped-audit-checkpoints.md).
