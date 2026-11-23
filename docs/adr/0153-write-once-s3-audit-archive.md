# 0153: A write-once S3 archive of the audit log

## Status

Accepted (23 Nov 2026). Third slice of [#56](https://github.com/CG-Labs/superbot/issues/56) in M5. Builds on the hash chain and SIEM export ([ADR 0122](0122-siem-export-and-tamper-evident-audit.md)) and the signed, timestamped checkpoints ([ADR 0149](0149-signed-and-timestamped-audit-checkpoints.md)), whose "Later" lists both had S3 batches with write-once storage. 0150 to 0152 are held by other work.

## Context

What catches a rebuilt chain is a copy of its hashes kept off the host. Today that copy is the SIEM, if there is one, and the SIEM is only as safe as its own admins and retention. Auditors (SOC 2 CC7.2, SEC 17a-4, HIPAA, ISO 27001 A.8.15) often ask for logs on storage nobody can change or delete for a set time, including the people who run the system. S3 Object Lock is that storage. AWS S3, MinIO, Backblaze B2, Wasabi, Ceph RGW and others implement it. Many self-hosters already have such a store for backups ([ADR 0071](0071-off-host-machine-backups.md), [ADR 0109](0109-server-backups-off-the-host.md)), and botd already has a small SigV4 client for it.

Constraints: off by default; no new dependencies; audit writes never wait on the store; no changes to the secrets backends or RBAC (other work in flight); the same at-least-once, in-order delivery and retention hold as the other sinks.

## Options

**Where it fits**

1. **A third sink of `AUDIT_EXPORT`** (`s3://bucket/prefix`). It reuses the cursor, retries, failure events, retention hold and status of the export. One sink at a time, so an operator with a SIEM and an archive picks one, or has the SIEM write to the archive.
2. **A second, independent exporter** with its own cursor. Both at once, but twice the state, and retention would wait for the slower of two cursors. That can come later on top of option 1.
3. **Part of server backups**. Backups are whole-database snapshots on a schedule, overwritten by rotation; they aren't per-event and can't be locked for years without keeping every snapshot.

**How objects are locked**

1. **The bucket's default retention** (`bucket`, the default). The operator sets the mode and period on the bucket once, where their compliance team can see it. botd checks there is one.
2. **Per object, as botd asks** (`compliance` or `governance` with `AUDIT_EXPORT_S3_RETAIN_DAYS`). Works on a bucket with Object Lock but no default, and puts the period in botd's config.
3. **Off** for a plain bucket, for those who only want the batches.

**Proving it's locked**

1. **Trust the PUT.** Some stores accept the lock headers and keep nothing, or a bucket was made without Object Lock. Then the archive would look fine and protect nothing.
2. **Check the bucket's configuration once, and read every object's lock back.** One more request per batch, and a store that doesn't lock becomes a failing export.

**Batches**

1. **One object per batch of up to 10,000 events, sent when the oldest waiting event is `AUDIT_EXPORT_S3_BATCH_SECONDS` old** (300 by default). Few, readable objects; at most a few minutes behind.
2. **One object per event.** Millions of tiny objects, priced per request.
3. **Gzip.** Smaller, but needs a CRC-32 and gzip framing botd doesn't have, and most stores compress or tier cold data anyway. Later, if asked.

## Decision

Sink option 1, all three lock options with `bucket` the default, proof option 2, batch option 1.

### Settings

| Variable | Default | Meaning |
|---|---|---|
| `AUDIT_EXPORT` | `off` | `s3://<bucket>[/<prefix>]` turns the archive on. The prefix defaults to `superbot-audit`. No credentials, port, query or fragment |
| `AUDIT_EXPORT_S3_ENDPOINT` | none (required) | `https://host[:port]`, or `http://` to loopback (a local MinIO). Path-style requests, as backups use |
| `AUDIT_EXPORT_S3_REGION` | `us-east-1` | The signing region (`auto` for R2) |
| `AUDIT_EXPORT_S3_ACCESS_KEY_ID`, `AUDIT_EXPORT_S3_SECRET_ACCESS_KEY` (or `_FILE`) | none (required) | From the secret store. The secret key is a server secret: redacted everywhere, never given to a Bot |
| `AUDIT_EXPORT_S3_LOCK` | `bucket` | `bucket`, `compliance`, `governance` or `off` |
| `AUDIT_EXPORT_S3_RETAIN_DAYS` | none | 1 to 36500; required with `compliance` or `governance`, refused otherwise |
| `AUDIT_EXPORT_S3_BATCH_SECONDS` | `300` | 0 to 86400. How long the oldest waiting event waits for more |

### Objects

- **Key**: `<prefix>/<yyyy>/<mm>/<dd>/<first id>-<last id>.jsonl`, dated by the first event (UTC), ids zero-padded to 20 digits so a listing is in order.
- **Body**: the same JSON lines the webhook gets (`superbot.audit.v1`, with `chainPrev`, `chainHash` and checkpoint records), so the chain runs on from object to object and the checkpoints' signatures and tokens can be checked from the archive alone, as ADR 0149 describes.
- **Headers**: `Content-Type: application/x-ndjson`; `x-amz-checksum-sha256` with `x-amz-sdk-checksum-algorithm: SHA256` (Object Lock writes must carry a checksum, and the store checks the body against it); metadata `superbot-schema`, `-first-id`, `-last-id`, `-events`, `-chain-prev` (the first event's link) and `-chain-head` (the last event's hash), so a listing tool can check continuity without reading bodies. With `compliance` or `governance`, `x-amz-object-lock-mode` and `x-amz-object-lock-retain-until-date` (now plus the days). All headers are signed.

### Proof of the lock

Unless the lock is `off`:

- Before the first batch, and again after any failure, botd reads the bucket's Object Lock configuration (`GET ?object-lock`). No Object Lock, or `bucket` mode with no default retention, is a failure with reason `not_write_once`, and nothing is written.
- After each `PUT`, botd reads that version back (`HEAD ?versionId=`). The write must have made a version, the size must match, and the object must carry a lock mode and a retain-until date: the mode asked for and at least the date asked for, or with `bucket`, any date in the future. Otherwise the batch fails with `not_write_once`, the cursor stays, and retention keeps the events.

### Delivery

As the other sinks (ADR 0122): one task, in id order, at least once, cursor per sink (`audit_export:s3://<endpoint host>/<bucket>/<prefix>`), backoff from 1 second to 5 minutes, `audit.export_failing` after 3 failures with a `reason` (`delivery_failed`, `not_write_once`, `unreadable`, `cursor_unsaved`) and `audit.export_recovered` after. One difference: a batch is retried with exactly the same events, so a retry writes the same key. Its last id is saved in `settings` (`audit_export:<sink>#batch`) before the first try, so this holds across a restart too. If an earlier try landed and only the cursor failed, the bucket holds two versions of the same object, both locked, not two overlapping objects.

### Status

`GET /api/audit/siem` and `botctl audit siem` show `kind: "s3"` and an `archive` object: the endpoint, bucket, prefix, lock, days, batch seconds, and the last object written (key, version, events, lock mode and retain-until). The app's Chain panel says when the last object's lock ends, and warns when objects aren't locked.

## What it does and doesn't prove

- **Against root on the host, or anyone with the database and `master.key`**: they can rebuild the chain and sign new checkpoints, but can't change or delete what is already in the archive. Pin hashes from it (`botctl audit verify --pin`), or trust only the checkpoint keys in it (`--key`).
- **Against someone with the archive's keys**: in compliance mode, they can't shorten the lock or delete a locked version, nor can the store account's root. In governance mode, a principal with `s3:BypassGovernanceRetention` can. They can add objects, but forged events don't link to the real chain and their checkpoints don't verify. Give botd a key that can only do `s3:GetBucketObjectLockConfiguration` on the bucket, and `s3:PutObject`, `s3:GetObject`, `s3:GetObjectVersion` (the `HEAD` of the version it wrote), `s3:GetObjectRetention` (to see that version's lock) and, with `compliance` or `governance`, `s3:PutObjectRetention` on the prefix's objects. Never `s3:BypassGovernanceRetention` or deletes.
- **Before a batch goes**: events are in the archive only once their batch is written, up to `AUDIT_EXPORT_S3_BATCH_SECONDS` plus any outage later. Shorter batches narrow that window, at more requests.
- **Erasure**: the archive keeps erased people's data until the lock ends, like a SIEM or a backup. The operator's DPA and the lock period cover that. Pick the period with that in mind.

## Consequences

- One `PUT` and one `HEAD` per batch, plus one `GET` of the bucket's configuration after start and after failures: at the default of 5 minutes, about 600 requests a day.
- A bucket in compliance mode can't be emptied before its locks end, not even by the account's root: `botd` never deletes from the archive.
- `SERVER_SECRETS` gains `AUDIT_EXPORT_S3_SECRET_ACCESS_KEY`.
- The S3 client names the store in its errors ("the audit archive" here, "the backup store" for backups), and can send signed extra headers, read an object's headers and read a bucket's Object Lock configuration.
- Later: an archive alongside a SIEM (a second cursor), gzip, and a `botctl audit verify` that reads the archive itself to check continuity and pin every batch's head.
