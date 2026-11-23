# Audit log: SIEM export and tamper evidence

Every audit event is sealed onto a hash chain as it is written, so a changed, removed, added or reordered event shows. Every hour botd signs a checkpoint of the chain's head, and can have each one timestamped by an RFC 3161 time-stamping authority (TSA). botd can also send every event to your SIEM as it happens: JSON lines over HTTPS, or RFC 5424 syslog over TLS. Or it can archive them in batches to an S3 bucket with Object Lock, where nobody can change or delete them until their retention ends ([below](#archive-events-to-write-once-s3)). The chain and checkpoints are always on and need nothing. Timestamps and the export are off until you set them. Design: [ADR 0122](../adr/0122-siem-export-and-tamper-evident-audit.md), [ADR 0149](../adr/0149-signed-and-timestamped-audit-checkpoints.md), [ADR 0154](../adr/0154-write-once-s3-audit-archive.md) and [ADR 0163](../adr/0163-checking-the-audit-archive.md).

## Check the chain

```sh
export SUPERBOT_PASSWORD=<your AUTH_PASSWORD>
botctl audit verify
```

It prints the result and exits 1 if the chain is broken. The same is `GET /api/audit/verify` for admins. The answer has:

- `ok`, `checked` (events walked) and `erased` (events whose personal fields an erasure replaced; they still verify).
- `head`: the newest event's id and hash. `first` and `anchor`: where the chain starts after retention deleted older events.
- `firstBroken`: the lowest event id that breaks the chain, and why:
  - `contents`: the event was changed.
  - `link`: an event before it was removed, added or reordered, or the start was cut without an anchor.
  - `unsealed`: it has no seal at all.
  - `erased`: its salt was cleared, but no erasure (`audit.erased`) with its own salt names it, so its fields can't be checked. Erasures never clear an `audit.erased` event's salt, so one without a salt is itself reported here.
  - `pin`: it differs from a hash you gave (below).
  - `checkpoint`: a signed checkpoint doesn't hold (below).
  - `timestamp`: a checkpoint's RFC 3161 token doesn't hold (below).
  - `archive`: it differs from the write-once archive, with `--archive` ([below](#check-the-archive)).
- `error`: the log couldn't be read to the end. The check fails.
- `checkpoints`: what the check found about checkpoints and timestamps (below).

`--from <id>` and `--to <id>` check only those events, which is quicker on a large log. A range starting after the first event takes that event's link as stored. If erased events in the range are named by an erasure after `--to`, the check carries on to the head, and `range` in the answer shows that.

botd also checks itself a minute after starting and then once a day. Each check, and each one through the API, is recorded as `audit.verified` with the result and the head's hash; a failed check's `reason` is the first break's code (`contents`, `link`, `pin`, `unsealed`, `erased`, `checkpoint`, `timestamp`, `archive`) or `unreadable`, which `botctl support-bundle` shows. A broken chain logs a warning that links here.

`botctl audit chain` (or `GET /api/audit/chain`) shows it all at once: the head, the last checkpoint and timestamp, how many events since, whether timestamping is failing, how far the export is behind, and the last check's result. In the app, the audit log's **Chain** button shows the same, with **Check now**.

### Hold it to a copy kept elsewhere

The chain has no secret key. Someone who can write `app.sqlite` (root, the service user) could change an event and re-hash everything after it, and the chain would verify again on that host. What catches this is a hash kept somewhere they can't reach: your SIEM. Every exported event carries its `chainHash`, and every `audit.verified` carries the head. Pick any event your SIEM holds and pin it:

```sh
botctl audit verify --pin 4182:3f1c...e9a0 --pin 9921:77ab...0c12
```

Each pin is `match`, `mismatch`, `gone` (older than what retention deleted), `missing` (newer than that, yet not there) or `outside` (not in `--from`/`--to`). A mismatch or a missing event fails the check: the history on the host is not the one your SIEM saw.

Without a SIEM, signed and timestamped checkpoints (next) do part of this job, and a write-once archive does it for every event ([below](#check-the-archive)).

## Checkpoints and timestamps

A checkpoint is an `audit.checkpoint` event that signs the chain's head: the id and hash of the event just before it, and the time. It is signed with an Ed25519 key derived from the master key, so nothing new needs a backup. Someone with a copy of `app.sqlite` but not `DATA_DIR/master.key` (a stolen backup, SQL access) can rebuild the chain, but not sign it.

With a TSA, each checkpoint is also sent, as a hash, to a time-stamping authority, which signs it with its time. That proves the head existed by then, which even root can't fake later: a rebuilt chain can't get tokens for the past. Any RFC 3161 TSA works, and several are free:

| TSA | `AUDIT_TIMESTAMP_URL` | CA file |
|---|---|---|
| FreeTSA | `https://freetsa.org/tsr` | `https://freetsa.org/files/cacert.pem` |
| DigiCert | `http://timestamp.digicert.com` | DigiCert Trusted Root G4 |
| Your own (OpenSSL, EJBCA, a CA's service) | its URL | its CA |

Plain `http` is fine: only a hash goes out, and the token is signed.

| Setting | Default | Meaning |
|---|---|---|
| `AUDIT_CHECKPOINT_MINUTES` | `60` | How often to sign a checkpoint, if anything happened since the last one. `0` or `off` stops the schedule (`botctl audit checkpoint` still works). Up to `10080` (a week) |
| `AUDIT_TIMESTAMP_URL` | off | An RFC 3161 TSA to timestamp each checkpoint. `http://` or `https://`, no username, password, query or fragment |
| `AUDIT_TIMESTAMP_CA_FILE` | none | PEM certificates the TSA's must chain to. Without it, tokens are kept and checked, but shown as `trusted: null`: botd has no TSA roots of its own |

A bad value stops botd at startup with a message naming the setting.

```sh
botctl audit key                 # the public key, its id, and every key used before
botctl audit checkpoint          # sign one now
botctl audit checkpoints 10      # the last 10, with their tokens
```

### What the check proves

`botctl audit verify` checks every checkpoint and timestamp it walks. `checkpoints` in its answer has how many it `checked`, how many are `timestamped` (and `trustedTimestamps`, with a CA file), the `last` checkpoint and `lastTimestamp`, the `keys` it trusted, and `firstBroken` with one of:

- `head`: the checkpoint doesn't sign the head it is sealed onto. Events before it were changed and the chain rebuilt.
- `key`: signed by a key botd doesn't trust, or the key id doesn't match.
- `signature`: the signature doesn't verify.
- `record`: its record in `audit_checkpoints` is gone, differs from the event, or exists without one (a pruned checkpoint's record stays only while its timestamp event is in the log); or the stored token isn't the one recorded.
- `malformed`: the event's details are incomplete.
- For a token: `imprint` (it stamps something else), `nonce`, `signature`, `certificate` (not a time-stamping certificate, or not valid at its time), `untrusted` (doesn't chain to `AUDIT_TIMESTAMP_CA_FILE`, or a CA on the way is limited to other uses, path lengths or names) or `malformed`.

botd trusts the keys it has used, which it keeps in the database. To doubt the database too, take the key from your SIEM (each new key is recorded as `audit.checkpoint_key`) or an earlier `botctl audit key`, and pin it:

```sh
botctl audit verify --key 3b6a27bc...aa51 --pin 4182:3f1c...e9a0
```

Then only that key counts, for every checkpoint. After a master key rotation that made new derived keys, give `--key` once per key.

Signatures can't stop root, who holds the master key too; the TSA's tokens and your SIEM can. Changes after the last checkpoint are caught by the chain and the SIEM only, so a shorter `AUDIT_CHECKPOINT_MINUTES` narrows that window.

### Check a checkpoint without botd

Each exported `audit.checkpoint` and `audit.checkpoint_timestamped` carries a `checkpoint` object with the `statement` that was signed, the `signature`, the `publicKey`, and on the timestamped one the `timestamp.token` (base64 DER). With `jq` and OpenSSL 3, from one exported `audit.checkpoint_timestamped` line in `line.json`:

```sh
# The signature
jq -j .checkpoint.statement line.json > statement
jq -r .checkpoint.signature line.json | xxd -r -p > sig
(printf '302a300506032b6570032100'; jq -r .checkpoint.publicKey line.json) | xxd -r -p > key.der
openssl pkeyutl -verify -pubin -keyform DER -inkey key.der -rawin -in statement -sigfile sig

# The timestamp: it stamps the statement, "\nsig=" and the signature
jq -j '.checkpoint.statement + "\nsig=" + .checkpoint.signature' line.json > stamped
jq -r .checkpoint.timestamp.token line.json | base64 -d > token.der
openssl ts -verify -token_in -in token.der -data stamped -CAfile <tsa-ca.pem>
```

Then compare the statement's `seq` and `hash` with that event in your SIEM: they must be its `id` and `chainHash`. Keep the TSA's certificates: a token can be checked for as long as its chain can.

### Failures

Timestamping never holds up the audit log. Checkpoints wait as `pending` and are stamped one at a time, oldest first, with backoff from 1 second up to 5 minutes. After 3 failures in a row botd logs a warning and records `audit.timestamp_failing` with a `reason` (`unreachable`, `refused`, `malformed`, `imprint`, `nonce`, `signature`, `certificate`, `untrusted` or `unsaved`); `audit.timestamp_recovered` follows. `botctl audit chain` shows the last error.

With metrics on, `/metrics` has `superbot_audit_checkpoint_last_timestamp_seconds` and, with a TSA, `superbot_audit_timestamp_pending_checkpoints`, `superbot_audit_timestamp_failing` and `superbot_audit_timestamp_last_timestamp_seconds`. Alert on `superbot_audit_timestamp_failing == 1`, or on the last checkpoint growing older than twice `AUDIT_CHECKPOINT_MINUTES` while there is activity.

### If it's broken

1. Don't restart or restore yet. Copy `app.sqlite` (and `DATA_DIR/master.key` if the database is encrypted) somewhere safe.
2. Note `firstBroken`. Compare that event and the ones around it with your SIEM's copy (`id`, `chainPrev`, `chainHash`) and your backups.
3. Restoring a backup older than events the SIEM already has also shows as a broken pin: expected after a restore, and worth recording.
4. Treat an unexplained break as a security incident.

## Send events to a SIEM

In `.env` (installer) or `deploy/docker/.env` (Compose), then restart botd:

| Setting | Default | Meaning |
|---|---|---|
| `AUDIT_EXPORT` | `off` | Where to send events. `https://<collector>/<path>`: JSON lines. `syslog+tls://<host>[:6514]`: syslog over TLS. `http://` and `syslog+tcp://` work only to loopback |
| `AUDIT_EXPORT_INSECURE` | `off` | `on` allows `http://` and `syslog+tcp://` to any host, for a collector on a private network such as the Compose network |
| `AUDIT_EXPORT_HEADERS` or `AUDIT_EXPORT_HEADERS_FILE` | none | HTTPS only: headers, `name=value` pairs split by commas, such as `Authorization=Bearer <token>`. A secret: redacted everywhere, and no Bot's harness gets it. With `SECRETS_BACKEND=vault` it can live in Vault ([vault.md](vault.md)) |
| `AUDIT_EXPORT_START` | `all` | For a new sink: `all` sends the history still in the database first, `new` only events from now on |

A bad value stops botd at startup with a message naming the setting. URLs with a username, password, query or fragment are refused, so put tokens in `AUDIT_EXPORT_HEADERS`.

### What arrives

One JSON object per event, the same shape as `GET /api/audit`, plus:

| Field | Meaning |
|---|---|
| `schema` | `superbot.audit.v1` |
| `host` | The server's host name |
| `chainPrev`, `chainHash` | The event's link in the chain. Each event's `chainPrev` is the previous event's `chainHash` |
| `checkpoint` | Only on `audit.checkpoint` and `audit.checkpoint_timestamped`: the signed statement, signature and key, and on the second the RFC 3161 token ([above](#check-a-checkpoint-without-botd)) |

```json
{"id":4182,"at":1795000000000,"time":"2026-11-19T13:46:40.000Z","actorKind":"user","actorId":"u1a2b3c","actorEmail":"ada@example.com","actorRole":"admin","authMethod":"sso","action":"bot.created","targetType":"bot","targetId":"b9f8e7","outcome":"success","details":{"name":"Scout"},"schema":"superbot.audit.v1","host":"<server-host>","chainPrev":"9a0c...","chainHash":"3f1c..."}
```

Events are scrubbed when they are recorded: passwords, tokens, message text and routine instructions are never in them, and known secrets are redacted. The export headers are never in an event.

- **Webhook**: `POST` with `Content-Type: application/x-ndjson`, up to 200 events per request, one per line. Answer any 2xx to accept the batch. Redirects aren't followed.
- **Syslog**: RFC 5424, facility 13 (log audit), severity 6 (success), 5 (failure) or 4 (denied), APP-NAME `superbot`, MSGID the action, and the JSON object as the message. Octet-counted framing (RFC 5425). The certificate is checked against the system's trusted roots. Syslog has no acknowledgement, so a dropped connection can lose the batch in flight: use the webhook if every event must arrive.

### Delivery and failures

- Events go in id order. The last delivered id is saved, so after a restart or an outage botd carries on from there. Delivery is at least once: de-duplicate on `host` and `id`.
- A failure is retried with backoff from 1 second up to 5 minutes, for as long as it takes. Events wait in the database meanwhile, and retention (`AUDIT_RETENTION_DAYS`) never deletes an event the sink hasn't taken, so a long outage grows the table instead of losing events.
- An event botd can't read from the database (a damaged row) is a failure too: export stops before it and retries, rather than skip it. `botctl audit verify` names the row.
- After 3 failures in a row botd logs a warning and records `audit.export_failing` with a `reason` of `delivery_failed`, `unreadable`, `cursor_unsaved` or, for the S3 archive, `not_write_once`; `audit.export_recovered` follows when delivery resumes.
- `botctl audit siem` (or `GET /api/audit/siem`) shows the sink, the last delivered id, how many are pending, whether it's failing, and the last error. With metrics on, `/metrics` has `superbot_audit_export_pending_events`, `superbot_audit_export_failing` and `superbot_audit_export_last_delivery_timestamp_seconds`. Alert on `superbot_audit_export_failing == 1` or a growing pending count.

### Examples

Vector, Fluent Bit, Logstash's `http` input and most SIEM collectors take JSON lines over HTTPS. For a collector on the same host:

```sh
AUDIT_EXPORT=http://127.0.0.1:8687/superbot
```

Splunk HTTP Event Collector, raw endpoint, with the channel as a header:

```sh
AUDIT_EXPORT=https://<splunk-host>:8088/services/collector/raw
AUDIT_EXPORT_HEADERS=Authorization=Splunk <hec-token>,X-Splunk-Request-Channel=<channel-guid>
```

rsyslog or syslog-ng with a TLS listener:

```sh
AUDIT_EXPORT=syslog+tls://<syslog-host>:6514
```

With Compose, run the collector on the `superbot_default` network and set `AUDIT_EXPORT=http://<collector>:<port>/<path>` with `AUDIT_EXPORT_INSECURE=on`.

### Changing the sink

The cursor is kept per sink URL. A new URL starts as `AUDIT_EXPORT_START` says; switching back to an old URL resumes where it stopped. To send everything again to the same sink, use a different path or remove its row from `settings` while botd is stopped. The row's key is `audit_export:` and the sink with its port always written, defaults included, and for a webhook its path: `https://<collector>/ingest` is saved as `audit_export:https://<collector>:443/ingest`, and `syslog+tls://<host>` as `audit_export:syslog+tls://<host>:6514`.

## Archive events to write-once S3

Instead of a SIEM, `AUDIT_EXPORT` can name an S3 bucket. botd writes events there in batches, one JSON-lines object per batch, and each object is locked with S3 Object Lock: until its retention ends nobody can change or delete it, not botd, not root on the server, and in compliance mode not even the store account's root. It works with any S3-compatible store with Object Lock: AWS S3, MinIO, Backblaze B2, Wasabi, Ceph.

Make the bucket with Object Lock on (it can only be turned on when the bucket is made, on most stores), and give it a default retention, for example compliance mode for 7 years (2555 days). Then:

```sh
AUDIT_EXPORT=s3://<bucket>/<prefix>
AUDIT_EXPORT_S3_ENDPOINT=https://s3.<region>.amazonaws.com
AUDIT_EXPORT_S3_REGION=<region>
AUDIT_EXPORT_S3_ACCESS_KEY_ID=<key id>
AUDIT_EXPORT_S3_SECRET_ACCESS_KEY=<secret>
```

| Setting | Default | Meaning |
|---|---|---|
| `AUDIT_EXPORT` | `off` | `s3://<bucket>[/<prefix>]`. The prefix defaults to `superbot-audit`; give each server its own |
| `AUDIT_EXPORT_S3_ENDPOINT` | none | The store's address, `https://host[:port]` (`http://` only to loopback, for a local MinIO) |
| `AUDIT_EXPORT_S3_REGION` | `us-east-1` | The region requests are signed for (`auto` for R2) |
| `AUDIT_EXPORT_S3_ACCESS_KEY_ID`, `AUDIT_EXPORT_S3_SECRET_ACCESS_KEY` (or `_FILE`) | none | The store's keys. The secret is redacted everywhere and no Bot gets it; with `SECRETS_BACKEND=vault` both can live in Vault |
| `AUDIT_EXPORT_S3_LOCK` | `bucket` | `bucket`: the bucket's default retention locks each object (botd checks there is one). `compliance` or `governance`: botd locks each object itself for `AUDIT_EXPORT_S3_RETAIN_DAYS`. `off`: a plain bucket, nothing locked |
| `AUDIT_EXPORT_S3_RETAIN_DAYS` | none | 1 to 36500, with `compliance` or `governance` only |
| `AUDIT_EXPORT_S3_BATCH_SECONDS` | `300` | A batch goes when its oldest event is this old, or at 10,000 events. 0 sends each batch at once |

The key botd uses needs, on the bucket (`arn:aws:s3:::<bucket>`), `s3:GetBucketObjectLockConfiguration`; and on its objects (`arn:aws:s3:::<bucket>/<prefix>/*`), `s3:PutObject`, `s3:GetObject` and `s3:GetObjectVersion` (botd reads back the version it wrote), `s3:GetObjectRetention` (to see its lock), and with `compliance` or `governance`, `s3:PutObjectRetention`. Don't give it `s3:BypassGovernanceRetention` or any delete rights. Other stores name these differently; MinIO uses the same names.

- **Objects** are `<prefix>/<yyyy>/<mm>/<dd>/<first id>-<last id>.jsonl`, dated by their first event, ids padded to 20 digits so they list in order. Each holds the same lines the webhook gets ([above](#what-arrives)), so each event's `chainPrev` is the previous event's `chainHash` across objects too, and checkpoints can be checked from the archive with OpenSSL. Metadata: `x-amz-meta-superbot-first-id`, `-last-id`, `-events`, `-chain-prev` (the first event's link), `-chain-head` (the last event's hash) and `-schema`.
- **Proof of the lock.** Before the first batch, botd checks that the bucket has Object Lock on (and a default retention with `bucket`). After writing each object it reads it back, and the object must have a version and a lock: the mode asked for and at least the date asked for, or with `bucket`, a date in the future. If not, nothing counts as delivered, retention keeps the events, and after 3 tries `audit.export_failing` is recorded with `reason` `not_write_once`. A store that takes the lock headers and keeps nothing can't pass.
- **Retries** write the same events to the same key, even after a restart (botd saves each batch's last id before writing it), so an object written whose cursor wasn't saved gets a second version of the same events, not an overlapping object.
- **Status**: `botctl audit siem` shows `kind: "s3"` and `archive`, with the bucket, lock and the last object written (key, version, events, lock mode and `retainUntil`). The app's audit log says when the last object's lock ends.

Read it back with any S3 tool, for example `aws s3 cp --recursive s3://<bucket>/<prefix>/ ./audit/`, then `cat audit/*/*/*/*.jsonl | jq -c '{id, chainPrev, chainHash}'` to see the chain run through. Or let botd check all of it (next).

### Check the archive

```sh
botctl audit verify --archive
```

This checks the chain as usual and also reads the whole archive (`GET /api/audit/verify?archive=on`). botd lists every version of every object under the prefix. For each object it reads the version written first (by its id, `null` too for one written before versioning was on), which Object Lock keeps whatever was written to that key later. Then it checks:

- each object is what its key and metadata say, and is locked (unless the lock is `off`);
- the chain runs from event to event and object to object with no gap, from where botd began archiving to the last event it delivered;
- every signed checkpoint in the archive holds under the trusted keys (botd's own, or `--key`);
- the archive reaches the last event botd says it delivered;
- every archived event has the same hash in this server's log. This catches a log rebuilt after an event was changed: its own chain verifies, but it no longer matches what was archived. It's the same as pinning every event (`--pin`).

The check fails, and exits 1, if any of that doesn't hold. `firstBroken` then names the first event here that differs from the archive (reason `archive`). The answer's `archive` block counts `objects`, `events`, `matched`, `gone` (deleted here by retention, with the anchor's hash still checked), `mismatched`, `missing`, `locked`, `lockExpired` and `checkpoints`. It also counts `repeated` (events written twice, as when the export is sent again; their checkpoints are still checked), `retried` (extra identical versions of an object) and `hidden` (objects behind a delete marker, which are still read). `firstProblems` lists the first 20 problems, each with a `key`, `id` and one of these reasons:

| Reason | Meaning |
|---|---|
| `mismatch`, `missing` | An archived event has another hash in this server's log, or isn't in it, and retention didn't delete it |
| `link` | An event doesn't link to the one before it: an object is missing, or isn't botd's |
| `start` | The archive doesn't start where botd began archiving: objects are missing at the start. botd records where it began when it first archives to a prefix; an archive begun before botd recorded it fails here too, so start a new prefix |
| `behind` | The archive ends before the last event botd delivered to it: objects are missing at the end |
| `overwritten` | A later version of an object differs from the one botd wrote. The first one is what's checked |
| `metadata`, `order` | An object's key or metadata doesn't match its events, or they're out of order |
| `unlocked` | An object has no lock. An ended lock is only counted, as `lockExpired` |
| `checkpoint` | A signed checkpoint in the archive doesn't hold |
| `stray` | A key under the prefix that botd didn't write |
| `unreadable` | An object couldn't be read or parsed |

`--from` and `--to` read only the objects that hold those events, and `--pin` and `--key` work as usual. The check costs one listing plus one `GET` per object (more for objects with several versions), four at a time. A year of 5-minute batches is about 100,000 objects, so use a range for frequent checks and run the whole archive less often, for example weekly from cron. `audit.verified` records the result.

For this, the key botd uses also needs `s3:ListBucketVersions` on the bucket; export works without it. Without it the check fails, and the error names the missing right. It still needs no delete rights.

Erased users' data stays in locked objects until their lock ends, like a SIEM or a backup: choose the period with your DPA in mind.

## Retention and erasure

- Retention deletes events from the start of the log only, and keeps the last deleted event's hash as the anchor the chain carries on from. An old event written after a newer one waits until the newer one is old enough too. `audit.pruned` records the anchor.
- Erasing a user ([ADR 0102](../adr/0102-erasing-a-users-data.md)) replaces their personal fields with a pseudonym and drops each event's salt, so its digest says nothing about them. The erasure records `audit.erased` with the ids it changed, and the chain still verifies. A salt cleared any other way fails as `erased`. Copies already in your SIEM aren't erased by botd: cover them with your SIEM's retention and your DPA, as with backups.
