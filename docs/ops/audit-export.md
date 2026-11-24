# Audit log: SIEM export and tamper evidence

Every audit event is sealed onto a hash chain as it is written, so a changed, removed, added or reordered event shows. Every hour botd signs a checkpoint of the chain's head, and can have each one timestamped by an RFC 3161 time-stamping authority (TSA). botd can also send every event to your SIEM as it happens: JSON lines over HTTPS, or RFC 5424 syslog over TLS. Or it can archive them in batches to an S3 bucket with Object Lock, where nobody can change or delete them until their retention ends ([below](#archive-events-to-write-once-s3)), or do both at once ([below](#a-siem-and-an-archive-together)), and send to up to four SIEMs, each with its own token ([below](#several-siems)), Microsoft Sentinel among them, signed in with Entra ID ([below](#microsoft-sentinel-azure-monitor)). Batches and archive objects can be gzipped ([below](#compression)). The chain and checkpoints are always on and need nothing. Timestamps and the export are off until you set them. Design: [ADR 0122](../adr/0122-siem-export-and-tamper-evident-audit.md), [ADR 0149](../adr/0149-signed-and-timestamped-audit-checkpoints.md), [ADR 0154](../adr/0154-write-once-s3-audit-archive.md), [ADR 0163](../adr/0163-checking-the-audit-archive.md), [ADR 0173](../adr/0173-an-archive-alongside-a-siem.md), [ADR 0183](../adr/0183-daily-check-of-new-archive-objects.md), [ADR 0191](../adr/0191-several-siems-with-their-own-headers.md), [ADR 0199](../adr/0199-self-checking-audit-lines.md), [ADR 0207](../adr/0207-checking-timestamps-from-exported-lines.md), [ADR 0217](../adr/0217-audit-export-to-azure-monitor.md) and [ADR 0227](../adr/0227-gzip-for-the-audit-export.md).

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

botd also checks itself a minute after starting and then once a day, along with what is new in the archive if there is one ([below](#the-daily-check)). Each check, and each one through the API, is recorded as `audit.verified` with the result and the head's hash; a failed check's `reason` is the first break's code (`contents`, `link`, `pin`, `unsealed`, `erased`, `checkpoint`, `timestamp`, `archive`) or `unreadable`, which `botctl support-bundle` shows. A broken chain logs a warning that links here.

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

Then compare the statement's `seq` and `hash` with that event in your SIEM: they must be its `id` and `chainHash`. Keep the TSA's certificates: a token can be checked for as long as its chain can. `botctl audit verify-lines --timestamp-ca <tsa-ca.pem>` does all of this for every line at once ([below](#check-exported-events-without-botd)), and the archive check does it from the archive.

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
| `AUDIT_EXPORT` | `off` | Where to send events. `https://<collector>/<path>`: JSON lines. `syslog+tls://<host>[:6514]`: syslog over TLS. `azure-monitor://<host>/<dcr>/<stream>`: Microsoft Sentinel ([below](#microsoft-sentinel-azure-monitor)). `http://` and `syslog+tcp://` work only to loopback. Add `,s3://<bucket>/<prefix>` to archive them too ([below](#a-siem-and-an-archive-together)). Any entry can be named, `<name>=<url>`, and several SIEMs must be ([below](#several-siems)) |
| `AUDIT_EXPORT_INSECURE` | `off` | `on` allows `http://` and `syslog+tcp://` to any host, for a collector on a private network such as the Compose network |
| `AUDIT_EXPORT_HEADERS` or `AUDIT_EXPORT_HEADERS_FILE` | none | HTTPS only: headers, `name=value` pairs split by commas, such as `Authorization=Bearer <token>`. A secret: redacted everywhere, and no Bot's harness gets it. With `SECRETS_BACKEND=vault` it can live in Vault ([vault.md](vault.md)). For one SIEM only; with several, each has its own `AUDIT_EXPORT_HEADERS_<NAME>` |
| `AUDIT_EXPORT_START` | `all` | For a new sink: `all` sends the history still in the database first, `new` only events from now on. A named sink can have its own, `AUDIT_EXPORT_START_<NAME>` |
| `AUDIT_EXPORT_COMPRESS` | `off` | `gzip`: webhook and Azure Monitor request bodies go gzipped, with `Content-Encoding: gzip`. A named sink can have its own, `AUDIT_EXPORT_COMPRESS_<NAME>` ([below](#compression)) |

A bad value stops botd at startup with a message naming the setting. URLs with a username, password, query or fragment are refused, so put tokens in `AUDIT_EXPORT_HEADERS`.

### What arrives

One JSON object per event, the same shape as `GET /api/audit`, plus:

| Field | Meaning |
|---|---|
| `schema` | `superbot.audit.v1` |
| `host` | The server's host name |
| `chainPrev`, `chainHash` | The event's link in the chain. Each event's `chainPrev` is the previous event's `chainHash` |
| `chainDigest` | The salted digest of the fields an erasure may rewrite, which `chainHash` covers. With it, anyone can work `chainHash` out from the line ([below](#check-exported-events-without-botd)). On every event after `digestsAfter` in `botctl audit siem`: the first export with this version saves where they start |
| `chainSalt` | The digest's salt, so the personal fields and `details` are checked too. Left out when that would let someone test guesses at something hidden: for erased events, and for events whose details were redacted on the way out |
| `checkpoint` | Only on `audit.checkpoint` and `audit.checkpoint_timestamped`: the signed statement, signature and key, and on the second the RFC 3161 token ([above](#check-a-checkpoint-without-botd)) |

```json
{"id":4182,"at":1795000000000,"time":"2026-11-19T13:46:40.000Z","actorKind":"user","actorId":"u1a2b3c","actorEmail":"ada@example.com","actorRole":"admin","authMethod":"sso","action":"bot.created","targetType":"bot","targetId":"b9f8e7","outcome":"success","details":{"name":"Scout"},"schema":"superbot.audit.v1","host":"<server-host>","chainPrev":"9a0c...","chainHash":"3f1c...","chainDigest":"5e2d...","chainSalt":"b71f..."}
```

Events are scrubbed when they are recorded: passwords, tokens, message text and routine instructions are never in them, and known secrets are redacted. The export headers are never in an event.

- **Webhook**: `POST` with `Content-Type: application/x-ndjson`, up to 200 events per request, one per line, gzipped with `Content-Encoding: gzip` if you ask ([below](#compression)). Answer any 2xx to accept the batch. Redirects aren't followed.
- **Azure Monitor**: records of a data collection rule's stream, each with the line whole ([below](#microsoft-sentinel-azure-monitor)).
- **Syslog**: RFC 5424, facility 13 (log audit), severity 6 (success), 5 (failure) or 4 (denied), APP-NAME `superbot`, MSGID the action, and the JSON object as the message. Octet-counted framing (RFC 5425). The certificate is checked against the system's trusted roots. Syslog has no acknowledgement, so a dropped connection can lose the batch in flight: use the webhook if every event must arrive.

### Delivery and failures

- Events go in id order. The last delivered id is saved, so after a restart or an outage botd carries on from there. Delivery is at least once: de-duplicate on `host` and `id`.
- A failure is retried with backoff from 1 second up to 5 minutes, for as long as it takes. Events wait in the database meanwhile, and retention (`AUDIT_RETENTION_DAYS`) never deletes an event the sink hasn't taken, so a long outage grows the table instead of losing events.
- An event botd can't read from the database (a damaged row) is a failure too: export stops before it and retries, rather than skip it. `botctl audit verify` names the row.
- After 3 failures in a row botd logs a warning and records `audit.export_failing` with a `reason` of `delivery_failed`, `unreadable`, `cursor_unsaved`, for Azure Monitor `sign_in_failed`, or, for the S3 archive, `not_write_once`; `audit.export_recovered` follows when delivery resumes.
- `botctl audit siem` (or `GET /api/audit/siem`) shows the sink, the last delivered id, how many are pending, whether it's failing, and the last error. With metrics on, `/metrics` has `superbot_audit_export_pending_events`, `superbot_audit_export_failing` and `superbot_audit_export_last_delivery_timestamp_seconds`, each labelled with the sink's `kind` (`webhook`, `syslog`, `azure-monitor` or `s3`) and, for a named sink, its `name`. Alert on `superbot_audit_export_failing == 1` or a growing pending count.

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

The cursor is kept per sink URL. A new URL starts as `AUDIT_EXPORT_START` (or its `AUDIT_EXPORT_START_<NAME>`) says; switching back to an old URL resumes where it stopped. A name isn't part of the cursor, so naming a running sink, or renaming it, resumes it. To send everything again to the same sink, use a different path or remove its row from `settings` while botd is stopped. The row's key is `audit_export:` and the sink with its port always written, defaults included, and for a webhook its path: `https://<collector>/ingest` is saved as `audit_export:https://<collector>:443/ingest`, and `syslog+tls://<host>` as `audit_export:syslog+tls://<host>:6514`.

## Archive events to write-once S3

Instead of a SIEM, or beside one ([below](#a-siem-and-an-archive-together)), `AUDIT_EXPORT` can name an S3 bucket. botd writes events there in batches, one JSON-lines object per batch, and each object is locked with S3 Object Lock: until its retention ends nobody can change or delete it, not botd, not root on the server, and in compliance mode not even the store account's root. It works with any S3-compatible store with Object Lock: AWS S3, MinIO, Backblaze B2, Wasabi, Ceph.

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
| `AUDIT_EXPORT` | `off` | `s3://<bucket>[/<prefix>]`, alone or after a SIEM and a comma. The prefix defaults to `superbot-audit`; give each server its own |
| `AUDIT_EXPORT_S3_ENDPOINT` | none | The store's address, `https://host[:port]` (`http://` only to loopback, for a local MinIO) |
| `AUDIT_EXPORT_S3_REGION` | `us-east-1` | The region requests are signed for (`auto` for R2) |
| `AUDIT_EXPORT_S3_ACCESS_KEY_ID`, `AUDIT_EXPORT_S3_SECRET_ACCESS_KEY` (or `_FILE`) | none | The store's keys. The secret is redacted everywhere and no Bot gets it; with `SECRETS_BACKEND=vault` both can live in Vault |
| `AUDIT_EXPORT_S3_LOCK` | `bucket` | `bucket`: the bucket's default retention locks each object (botd checks there is one). `compliance` or `governance`: botd locks each object itself for `AUDIT_EXPORT_S3_RETAIN_DAYS`. `off`: a plain bucket, nothing locked |
| `AUDIT_EXPORT_S3_RETAIN_DAYS` | none | 1 to 36500, with `compliance` or `governance` only |
| `AUDIT_EXPORT_S3_BATCH_SECONDS` | `300` | A batch goes when its oldest event is this old, or at 10,000 events. 0 sends each batch at once |
| `AUDIT_EXPORT_S3_COMPRESS` | `off` | `gzip`: each object is gzipped, `.jsonl.gz` ([below](#compression)) |
| `AUDIT_EXPORT_S3_CHECK` | `daily` | `daily`: botd's daily self-check also checks the objects written since its last pass ([below](#the-daily-check)). `off`: only when you ask |

The key botd uses needs, on the bucket (`arn:aws:s3:::<bucket>`), `s3:GetBucketObjectLockConfiguration` and, for the daily check ([below](#the-daily-check)), `s3:ListBucketVersions`; and on its objects (`arn:aws:s3:::<bucket>/<prefix>/*`), `s3:PutObject`, `s3:GetObject` and `s3:GetObjectVersion` (botd reads back the version it wrote), `s3:GetObjectRetention` (to see its lock), and with `compliance` or `governance`, `s3:PutObjectRetention`. Don't give it `s3:BypassGovernanceRetention` or any delete rights. Other stores name these differently; MinIO uses the same names.

- **Objects** are `<prefix>/<yyyy>/<mm>/<dd>/<first id>-<last id>.jsonl` (`.jsonl.gz` with `AUDIT_EXPORT_S3_COMPRESS=gzip`), dated by their first event, ids padded to 20 digits so they list in order. Each holds the same lines the webhook gets ([above](#what-arrives)), so each event's `chainPrev` is the previous event's `chainHash` across objects too, and checkpoints can be checked from the archive with OpenSSL. Metadata: `x-amz-meta-superbot-first-id`, `-last-id`, `-events`, `-chain-prev` (the first event's link), `-chain-head` (the last event's hash) and `-schema`.
- **Proof of the lock.** Before the first batch, botd checks that the bucket has Object Lock on (and a default retention with `bucket`). After writing each object it reads it back, and the object must have a version and a lock: the mode asked for and at least the date asked for, or with `bucket`, a date in the future. If not, nothing counts as delivered, retention keeps the events, and after 3 tries `audit.export_failing` is recorded with `reason` `not_write_once`. A store that takes the lock headers and keeps nothing can't pass.
- **Retries** write the same events to the same key, even after a restart (botd saves each batch's last id before writing it), so an object written whose cursor wasn't saved gets a second version of the same events, not an overlapping object.
- **Status**: `botctl audit siem` shows `kind: "s3"` and `archive`, with the bucket, lock and the last object written (key, version, events, `bytes`, and when gzipped `uncompressedBytes`, lock mode and `retainUntil`), and `compress`. The app's audit log says when the last object's lock ends.

Read it back with any S3 tool, for example `aws s3 cp --recursive s3://<bucket>/<prefix>/ ./audit/`, then `cat audit/*/*/*/*.jsonl | jq -c '{id, chainPrev, chainHash}'` (`zcat audit/*/*/*/*.jsonl.gz` for a gzipped archive) to see the chain run through. Or let botd check all of it (next).

### Check the archive

```sh
botctl audit verify --archive
```

This checks the chain as usual and also reads the whole archive (`GET /api/audit/verify?archive=on`). botd lists every version of every object under the prefix. For each object it reads the version written first, which Object Lock keeps whatever was written to that key later. Then it checks:

- each object is what its key and metadata say, and is locked (unless the lock is `off`);
- the chain runs from event to event and object to object with no gap;
- every signed checkpoint in the archive holds under the trusted keys (botd's own, or `--key`);
- every checkpoint's RFC 3161 timestamp in the archive holds: the token the line carries is the one its event recorded (by SHA-256, which the chain covers), it stamps that checkpoint's statement and signature at the time recorded, and its TSA's certificate signed it, chaining to `AUDIT_TIMESTAMP_CA_FILE` when that is set. The token isn't covered by any hash, so a changed one would otherwise go unseen;
- the archive begins with the first event botd sent it, and reaches the last event botd says it delivered;
- every archived event has the same hash in this server's log. This catches a log rebuilt after an event was changed: its own chain verifies, but it no longer matches what was archived. It's the same as pinning every event (`--pin`). While the event is still here, what the archive says it was must also match this server's row: its fields, and, unless an erasure has since rewritten them, the personal ones.

The check fails, and exits 1, if any of that doesn't hold. `firstBroken` then names the first event here that differs from the archive (reason `archive`). The answer's `archive` block counts `objects`, `events`, `matched`, `gone` (deleted here by retention, with the anchor's hash still checked), `mismatched`, `altered`, `missing`, `locked`, `lockExpired`, `checkpoints`, `timestamps` and `trustedTimestamps` (null without `AUDIT_TIMESTAMP_CA_FILE`), with the newest timestamp as `lastTimestamp`. It also counts `repeated` (events a restarted export wrote twice), `retried` (extra identical versions of an object) and `hidden` (objects behind a delete marker, which are still read). `bound`, `boundFixed` and `unbound` count the copies whose hash vouches for every field (they have `chainSalt`), only the fields no erasure changes (erased or redacted on the way out), or nothing (sent before `digestsAfter`). `firstProblems` lists the first 20 problems, each with a `key`, `id` and one of these reasons:

| Reason | Meaning |
|---|---|
| `mismatch`, `missing` | An archived event has another hash in this server's log, or isn't in it, and retention didn't delete it |
| `contents` | An archived event has this server's hash but says something else: the archive's copy was changed. Events retention deleted here can't be compared this way, but `digest` still catches them |
| `digest` | An archived event's hash doesn't follow from what it says (its fields, `chainDigest` and, with it, `chainSalt`): the copy was changed. This holds after retention deleted the row here |
| `unbound` | An event after `digestsAfter` has no `chainDigest`: it was stripped, to hide a change, or the object isn't botd's |
| `link` | An event doesn't link to the one before it: an object is missing, or isn't botd's |
| `behind` | The archive ends before the last event botd delivered to it: objects are missing at the end |
| `start` | The archive begins after the first event botd sent it: objects are missing at the start. Archives started before this check was added aren't asked |
| `overwritten` | A later version of an object differs from the one botd wrote. The first one is what's checked |
| `metadata`, `order` | An object's key or metadata doesn't match its events, or they're out of order |
| `unlocked` | An object has no lock. An ended lock is only counted, as `lockExpired` |
| `checkpoint` | A signed checkpoint in the archive doesn't hold, even in a repeated batch |
| `timestamp` | A checkpoint's timestamp in the archive doesn't hold, even in a repeated batch: its token isn't the one recorded, is missing, doesn't stamp that checkpoint, or its TSA isn't trusted. The error says which |
| `stray` | A key under the prefix that botd didn't write |
| `unreadable` | An object couldn't be read or parsed |

`--from` and `--to` read only the objects that hold those events, and every event in that range that botd has delivered must be there (`start` or `behind` otherwise; for an archive started before botd recorded where it began, only when the range reads something or reaches the last event delivered), and `--pin` and `--key` work as usual. The check costs one listing plus one `GET` per object (more for objects with several versions), four at a time. A year of 5-minute batches is about 100,000 objects, so use a range for frequent checks; botd checks what is new every day by itself (next). `audit.verified` records the result. A whole check that passes is also where the daily check carries on from.

For this, the key botd uses also needs `s3:ListBucketVersions` on the bucket; export works without it. Without it the check fails, and the error names the missing right. It still needs no delete rights.

### The daily check

With an archive, botd's daily self-check also checks it, unless `AUDIT_EXPORT_S3_CHECK=off`. It runs the same checks as `--archive`, but only on what is new since its last pass:

- every object past the head the last passing check reached. The chain must carry on from that head with no gap;
- every object the store says was written to since the last pass began (from the listing's `LastModified`, which no writer can set), whatever events it names. So a forged copy of an old batch, or a new version over an old object, is read the next day;
- and before reading, the head the last pass reached must still have the same hash here. A log rebuilt from any event, even one already checked, changes that hash, so it fails as `mismatch` (reason `archive`).

The first daily check, with no pass yet, reads the whole archive once. After that it costs one listing plus about one `GET` per batch written that day: about 288 at 5-minute batches. Each check is one `audit.verified`, and its `archive` block has `after` (the head it carried on from) and `skipped` (objects not read again). The app's audit log shows it as `Archive check`. A check that fails doesn't move the last pass, so the next day reads from the same place and fails again until it's resolved. A passing whole check by hand moves it too.

What the daily check doesn't see is an old object deleted for good. In compliance mode nobody can do that. In governance mode, or with the lock off, keep running the whole check from cron too, for example weekly: `botctl audit verify --archive`.

If it fails:

- `error` naming `s3:ListBucketVersions`: grant that right on the bucket (archives set up before the daily check may lack it), or set `AUDIT_EXPORT_S3_CHECK=off`.
- `mismatch` or `missing` at the head it carried on from, or at an archived event: this server's log no longer says what was archived. Treat it as tampering until shown otherwise: compare the archive's copy of that event with the log, and with your SIEM's copy if there is one.
- `timestamp` with `untrusted`: if you changed TSA, `AUDIT_TIMESTAMP_CA_FILE` must still hold the old TSA's CA as well as the new one's. Otherwise, as below.
- `contents`, `digest`, `unbound`, `overwritten`, `stray`, `timestamp`: someone wrote to the archive with its key. The first version of each object is still what's checked. Find who used the key, then rotate it.
- `link` or `behind`: new objects are missing. Check the export's status (`botctl audit siem`) first.

Erased users' data stays in locked objects until their lock ends, like a SIEM or a backup: choose the period with your DPA in mind.

## A SIEM and an archive together

List both in `AUDIT_EXPORT`, split by a comma: live events for your SIEM's detections, and a copy nobody can change for auditors. The SIEM's settings (`AUDIT_EXPORT_HEADERS`, `AUDIT_EXPORT_INSECURE`) and the archive's (`AUDIT_EXPORT_S3_*`) are the same as for each alone:

```sh
AUDIT_EXPORT=https://<splunk-host>:8088/services/collector/raw,s3://<bucket>/<prefix>
AUDIT_EXPORT_HEADERS=Authorization=Splunk <hec-token>,X-Splunk-Request-Channel=<channel-guid>
AUDIT_EXPORT_S3_ENDPOINT=https://s3.<region>.amazonaws.com
AUDIT_EXPORT_S3_REGION=<region>
AUDIT_EXPORT_S3_ACCESS_KEY_ID=<key id>
AUDIT_EXPORT_S3_SECRET_ACCESS_KEY=<secret>
```

- **One archive.** One `s3://` archive at most, in any place in the list, beside up to four SIEMs (`https://`, `syslog+tls://`, `azure-monitor://`, or the plain forms; [below](#several-siems)). Two archives or an empty entry stop botd at startup. A comma in a webhook's path is written `%2C`.
- **Each on its own.** Each sink has its own cursor, retries, `audit.export_failing` and `audit.export_recovered` (with `kind` in their details), so a SIEM outage doesn't stop the archive, and the archive's batching doesn't slow the SIEM. Both get the same lines, so `host` and `id` match across them.
- **Retention waits for both.** `AUDIT_RETENTION_DAYS` never deletes an event either sink hasn't taken.
- **Adding one keeps the other.** Cursors are kept per sink, so adding an archive beside a running SIEM (or the other way round) resumes the one that was there. The new one starts as `AUDIT_EXPORT_START` says: with `all`, the default, the archive starts with the history still in the database.
- **Status.** `botctl audit siem` (`GET /api/audit/siem`) leads with the sink in the worst state, failing first and then furthest behind, so its `failing` and `pending` cover both, and lists each under `sinks`. The app's audit log shows a `SIEM export` and an `Archive` line. In `/metrics`, each sink is its own series by `kind`.
- **Checks.** `botctl audit verify --archive` checks the archive as above, and the daily check reads what is new in it. Pins from the SIEM (`--pin`) and the archive check can be used together.

## Several SIEMs

Your own SIEM and an MDR provider's collector, a SIEM and a data lake, or the SIEM you use and the one you're moving to: list up to four in `AUDIT_EXPORT`, each with a name, and give each webhook its own headers. An archive can sit beside them as above.

```sh
AUDIT_EXPORT=splunk=https://<splunk-host>:8088/services/collector/raw,mdr=https://<mdr-collector>/ingest,soc=syslog+tls://<syslog-host>:6514,s3://<bucket>/<prefix>
AUDIT_EXPORT_HEADERS_SPLUNK=Authorization=Splunk <hec-token>,X-Splunk-Request-Channel=<channel-guid>
AUDIT_EXPORT_HEADERS_MDR=Authorization=Bearer <mdr-token>
AUDIT_EXPORT_START_MDR=new
```

- **Names.** `<name>=<url>`: 1 to 24 letters and digits, starting with a letter, case-insensitive (shown in lowercase). Not `file`. With more than one SIEM, every SIEM needs one; the archive may have one too. Two sinks with the same name, or the same URL listed twice, stop botd at startup.
- **Headers.** `AUDIT_EXPORT_HEADERS_<NAME>` (or `_FILE`), the name in capitals, goes to that webhook and no other. It's a secret like `AUDIT_EXPORT_HEADERS`: redacted, never given to a Bot, and with Vault it lives in the server folder as `AUDIT_EXPORT_HEADERS_<NAME>`. With several SIEMs, `AUDIT_EXPORT_HEADERS` stops botd, since it would go to all of them. A webhook with no headers of its own sends none. Syslog, Azure Monitor and the archive take no headers.
- **Where each starts.** `AUDIT_EXPORT_START_<NAME>` (`all` or `new`) is for that sink when it is new; otherwise `AUDIT_EXPORT_START` applies. Above, the MDR gets only what happens from now on, while a new archive still gets the history.
- **Each on its own.** As with an archive: each SIEM has its own cursor (by URL, so naming a running sink resumes it), retries and failure events, so one outage doesn't hold up the others. `audit.export_failing` and `audit.export_recovered` carry the `name`. Every SIEM gets the same lines, so `host`, `id` and `chainHash` match across them and pins can come from any.
- **Retention waits for all of them.** A SIEM that stays down grows the table for every sink: alert on each one's `pending`.
- **Status.** `botctl audit siem` leads with the sink in the worst state and lists each under `sinks`, with its `name`. The app's audit log shows a line per sink, such as `SIEM export (splunk)`. In `/metrics`, each named sink's series has a `name` label as well as `kind`.
- **A misspelt name** in `AUDIT_EXPORT_HEADERS_<NAME>` isn't caught at startup: that webhook sends no headers, its SIEM refuses them, and the export shows as failing for that sink.

A single SIEM needs no name, so settings from before keep working. To move to several, name the one you have (it resumes where it was) and move its `AUDIT_EXPORT_HEADERS` to `AUDIT_EXPORT_HEADERS_<NAME>`.

## Microsoft Sentinel (Azure Monitor)

Sentinel reads a Log Analytics workspace, and botd writes there itself through Azure Monitor's Logs Ingestion API, with no collector beside it. It signs in to Entra ID as its own Azure identity, the one Key Vault uses ([cloud-secrets.md](cloud-secrets.md)): a managed identity on Azure or workload identity on AKS need no secret at all. Design: [ADR 0217](../adr/0217-audit-export-to-azure-monitor.md).

```sh
AUDIT_EXPORT=sentinel=azure-monitor://<dcr-name>-<suffix>.<region>-1.ingest.monitor.azure.com/<dcr immutable id>/Custom-SuperBotAudit
AUDIT_EXPORT_AZURE_AUTH=managed-identity
AZURE_CLIENT_ID=<user-assigned identity's client id, if not the system-assigned one>
```

| Setting | Default | Meaning |
|---|---|---|
| `AUDIT_EXPORT` | `off` | `azure-monitor://<host>/<dcr>/<stream>`, alone or beside other sinks (name it then). `<host>` is the rule's logs ingestion endpoint, or its data collection endpoint's (private link too), without `https://`; it must end in `.monitor.azure.com`, `.monitor.azure.us` or `.monitor.azure.cn`, which also picks the cloud tokens are for. `<dcr>` is the rule's immutable id (`dcr-` and 32 hex digits), `<stream>` its input stream (`Custom-<name>`) |
| `AUDIT_EXPORT_AZURE_AUTH` | `AZURE_KEYVAULT_AUTH`, else `managed-identity` | `managed-identity`, `workload-identity` or `client-secret`, read with the same `AZURE_CLIENT_ID`, `AZURE_TENANT_ID`, `AZURE_CLIENT_SECRET` (or `_FILE`), `AZURE_FEDERATED_TOKEN_FILE`, `AZURE_AUTHORITY_HOST`, `IDENTITY_ENDPOINT` and `IDENTITY_HEADER` as Key Vault |

It takes no headers, and no credentials in the URL. Tokens are asked for `https://monitor.azure.com` (or `.us`, `.cn`), kept until two thirds of their life, sent only to that host, and redacted everywhere.

### Set it up

1. Create the table, in the workspace Sentinel uses:

```sh
az monitor log-analytics workspace table create -g <rg> --workspace-name <workspace> -n SuperBotAudit_CL --columns \
  TimeGenerated=datetime EventId=long Host=string Action=string Outcome=string ActorKind=string ActorId=string \
  ActorName=string ActorEmail=string ActorRole=string AuthMethod=string TargetType=string TargetId=string BotId=string \
  SourceIp=string SessionId=string Details=dynamic ChainHash=string LinePart=int Line=string
```

2. Create a data collection rule for it, in the workspace's region, with the same columns as its stream. Save this as `dcr.json`, with the workspace's resource id:

```json
{
  "location": "<region>",
  "kind": "Direct",
  "properties": {
    "streamDeclarations": {
      "Custom-SuperBotAudit": {
        "columns": [
          { "name": "TimeGenerated", "type": "datetime" }, { "name": "EventId", "type": "long" },
          { "name": "Host", "type": "string" }, { "name": "Action", "type": "string" }, { "name": "Outcome", "type": "string" },
          { "name": "ActorKind", "type": "string" }, { "name": "ActorId", "type": "string" }, { "name": "ActorName", "type": "string" },
          { "name": "ActorEmail", "type": "string" }, { "name": "ActorRole", "type": "string" }, { "name": "AuthMethod", "type": "string" },
          { "name": "TargetType", "type": "string" }, { "name": "TargetId", "type": "string" }, { "name": "BotId", "type": "string" },
          { "name": "SourceIp", "type": "string" }, { "name": "SessionId", "type": "string" }, { "name": "Details", "type": "dynamic" },
          { "name": "ChainHash", "type": "string" }, { "name": "LinePart", "type": "int" }, { "name": "Line", "type": "string" }
        ]
      }
    },
    "destinations": { "logAnalytics": [{ "workspaceResourceId": "<workspace resource id>", "name": "workspace" }] },
    "dataFlows": [{ "streams": ["Custom-SuperBotAudit"], "destinations": ["workspace"], "transformKql": "source", "outputStream": "Custom-SuperBotAudit_CL" }]
  }
}
```

```sh
rule=/subscriptions/<subscription>/resourceGroups/<rg>/providers/Microsoft.Insights/dataCollectionRules/superbot-audit
az rest --method put --url "https://management.azure.com$rule?api-version=2024-03-11" --body @dcr.json
az rest --method get --url "https://management.azure.com$rule?api-version=2024-03-11" --query "properties.{dcr: immutableId, host: endpoints.logsIngestion}"
```

3. Give botd's identity the **Monitoring Metrics Publisher** role on the rule, and nothing more. It can take 30 minutes to apply; until then the export fails with 403 and retries.

```sh
az role assignment create --assignee <botd identity's principal id> --role "Monitoring Metrics Publisher" --scope "$rule"
```

4. Set `AUDIT_EXPORT` from the `dcr` and `host` above (the host without `https://`) and restart botd. New events show in `SuperBotAudit_CL` within a few minutes of the first delivery.

### What arrives

Each event is one row: `TimeGenerated` (the event's time), `EventId` (its `id`, which is a reserved column name in Log Analytics), the typed columns above, `LinePart` (0), and `Line`, the event's JSON line exactly as every other sink gets it ([above](#what-arrives)). The columns are read from `Line`, so they never say more than it does: what was redacted or erased there is so in them too. Queries use the columns:

```kusto
SuperBotAudit_CL
| where Action startswith "auth." and Outcome != "success"
| summarize failures = count() by ActorEmail, SourceIp, bin(TimeGenerated, 1h)
```

A transformation in the rule (`transformKql`) can drop columns you don't want, but keep `EventId`, `Host`, `ChainHash`, `LinePart` and `Line`.

- **Requests.** A batch of up to 200 events goes as JSON arrays of at most 1 MB each, in order. If one fails, the batch goes again whole, and Azure keeps arrays it already took, so de-duplicate on `Host`, `EventId` and `LinePart` (`summarize arg_max(TimeGenerated, *) by Host, EventId, LinePart`).
- **Tokens.** When Azure refuses one (401), botd gets a new one and tries once more; only a second refusal is a failure.
- **Throttling.** A 429 waits as long as `Retry-After` says, up to 5 minutes, then the usual backoff.
- **Failures** are recorded as for any sink, with Azure's error code and what to do: `403` needs the role (step 3), `404` a wrong rule, stream or host, `400` a stream that doesn't declare the columns (step 2). A failed sign-in is `sign_in_failed`: check the identity settings, and for a managed identity that botd runs where one is assigned.
- **Size.** Azure cuts any field over 64 KB. A line over 32,000 bytes, such as the `audit.erased` of a long-lived user, goes as several rows with `LinePart` 1, 2, and so on, the same typed columns (`Details` empty), and in `Line` a piece of the line (`"schema":"superbot.audit.part.v1"`). `botctl audit verify-lines` puts the pieces back together, so nothing is cut. An erasure names at most 1,000 id ranges in each `audit.erased` event, so those lines stay under 43 KB for every sink.

### Check the copy in Sentinel

`Line` goes into `botctl audit verify-lines` unchanged, pieces of long lines too, in any order ([below](#check-exported-events-without-botd)):

```sh
az monitor log-analytics query -w <workspace id> -o tsv \
  --analytics-query "SuperBotAudit_CL | where TimeGenerated > ago(30d) | project Line" \
  | botctl audit verify-lines - --key <checkpoint public key hex> --digests-after <id>
```

A query returns at most 500,000 rows, so check a long history a month at a time. `ChainHash` gives pins for `botctl audit verify --pin <EventId>:<ChainHash>`. The typed columns aren't checked: compare them with `Line` if a detection depends on one.

## Compression

Audit lines compress about tenfold. Gzip is off by default, so keys and bodies stay as downstream tools expect; turn it on where they take it. Design: [ADR 0227](../adr/0227-gzip-for-the-audit-export.md).

```sh
AUDIT_EXPORT=splunk=https://<splunk-host>:8088/services/collector/raw,legacy=https://<collector>/ingest,s3://<bucket>/<prefix>
AUDIT_EXPORT_COMPRESS=gzip
AUDIT_EXPORT_COMPRESS_LEGACY=off
AUDIT_EXPORT_S3_COMPRESS=gzip
```

- **SIEMs.** `AUDIT_EXPORT_COMPRESS=gzip` gzips every webhook and Azure Monitor request body and adds `Content-Encoding: gzip`; the lines inside are the same. `AUDIT_EXPORT_COMPRESS_<NAME>` (`gzip` or `off`) is that named sink's own and wins, so above every SIEM but `legacy` gets gzip. Splunk HEC, Elastic, Vector, Fluent Bit, Logstash's `http` input and Azure's Logs Ingestion API take it. A collector that doesn't answers an error, often 400 or 415, and the sink shows as failing: turn it off for that sink. Azure's 1 MB limit holds before compression too, so its arrays are cut at 1 MB and then gzipped.
- **Syslog** has no compression. `AUDIT_EXPORT_COMPRESS_<NAME>=gzip` on a syslog sink stops botd at startup, and so does `AUDIT_EXPORT_COMPRESS=gzip` when no sink is a webhook or Azure Monitor.
- **Archive.** `AUDIT_EXPORT_S3_COMPRESS=gzip` writes each object as `<first id>-<last id>.jsonl.gz`, one gzip member with `Content-Type: application/gzip` and no `Content-Encoding`, so every S3 client downloads the same bytes. Metadata, the lock and the read-back are as before. Keys change from then on: tools that list `*.jsonl` (an Athena table, Splunk's S3 input) need `*.jsonl.gz` too. `AUDIT_EXPORT_COMPRESS` doesn't touch the archive, and `AUDIT_EXPORT_COMPRESS_<NAME>` naming it stops botd.
- **Checks.** The [archive check](#check-the-archive) reads `.jsonl` and `.jsonl.gz` keys, so an archive switched part way checks whole, the chain running across both. A `.gz` object must be gzip to its last byte and hold at most 256 MB uncompressed, or it is `unreadable`. Versions of a key are compared by their lines, so a retry that compressed differently is `retried`, not `overwritten`. A batch cut before the switch and retried after it lands on the `.gz` key, and its events show as `repeated`. `botctl audit verify-lines` gunzips by itself ([below](#check-exported-events-without-botd)).
- **Status.** `botctl audit siem` shows each sink's `compress` (`gzip` or `off`), and the startup log says which are gzipped.

## Check exported events without botd

`botctl audit verify-lines` checks exported events where they landed: a copy of the archive, a SIEM export, years later, with the server gone. It needs no botd, no database and no network, only the `botctl` binary:

```sh
aws s3 cp --recursive s3://<bucket>/<prefix>/ ./audit/
botctl audit verify-lines ./audit/ --key <checkpoint public key hex> --digests-after <id> --timestamp-ca <tsa-ca.pem>

# A SIEM export, as JSON lines or syslog, from a file or stdin
botctl audit verify-lines siem-export-2026-11.jsonl.gz --key <checkpoint public key hex> --digests-after <id>
```

`aws s3 cp` takes each key's latest version, while botd's archive check reads the first, which Object Lock keeps. If someone wrote a version over a locked object, this checks theirs; `botctl audit verify --archive` names it as `overwritten`.

It reads files, directories (their `.jsonl`, `.ndjson`, `.json` and `.log` files, and each of those with `.gz`) and `-` for stdin, in any order, copies and all. It gunzips whatever starts as gzip, so a gzipped archive, `cat audit/*/*/*/*.jsonl.gz | botctl audit verify-lines -` and a `.gz` SIEM export need no `zcat`. Each gzipped input may unpack to at most `--max-gunzip-mb` (default 4096), so a small file can't fill memory; past it, the check stops and names the file. A syslog line is read from its first `{`. Lines from other sources are counted as `ignored`. For each `host` it checks:

- each line against its own hash: `chainHash` from `chainPrev`, the fields no erasure changes and `chainDigest`, and with `chainSalt`, `chainDigest` from the other fields (`digest` otherwise);
- copies of one event against each other (`conflict`);
- the chain from event to event, with no gap (`link`);
- that every event after `--digests-after` carries `chainDigest` (`unbound`). Take it from `digestsAfter` in `botctl audit siem` once, and keep it with the checkpoint key. It never changes. Without it, the first line with a digest stands in for it, so lines stripped of every digest bind nothing, and still pass;
- each signed checkpoint (`checkpoint`), under the keys given with `--key` (from `botctl audit key`, or the `audit.checkpoint_key` events in your SIEM). Without `--key` a checkpoint is checked under the key in it, which only shows it agrees with whoever signed it;
- each checkpoint's RFC 3161 timestamp (`timestamp`), as the [archive check](#check-the-archive) does: the token is the one its event recorded, stamps that checkpoint at the time recorded, and chains to the CA certificates given with `--timestamp-ca` (a PEM file, as `AUDIT_TIMESTAMP_CA_FILE`; repeat it for several TSAs). Without `--timestamp-ca` a token is checked under the certificate it carries, which only shows it agrees with whoever signed it. When the checkpoint's own event isn't among the lines, the record the timestamp line carries stands in for it, and its signature must hold under `--key`.

It prints a JSON report: per host, `events`, `copies`, `first` and `firstPrev` (the genesis hash for a log never pruned), `head`, `bound`, `boundFixed` and `unbound` (as for the [archive check](#check-the-archive)), `checkpoints` and their `checkpointKeys`, `timestamps`, `trustedTimestamps` (null without `--timestamp-ca`), `lastTimestamp`, `unstamped` (checkpoints made with a TSA whose timestamp isn't among the lines, which isn't a failure: it may not be exported yet), and the first 20 `firstProblems`, each with `id`, `at` (`<file>:<line>`) and `reason`. It exits 1 if anything doesn't hold, or if no events were found.

What it can't tell you:

- that nothing is missing at the start or the end. Compare `first` and `head` with what botd says it delivered (`botctl audit siem`), or pin a head kept elsewhere: the last `audit.checkpoint` you trust signs it;
- what a line without `chainSalt` said in its personal fields and `details`. Those are erased or redacted events, and `boundFixed` counts them;
- anything about events sent before `digestsAfter`, beyond their links. Check them with `botctl audit verify --archive` while their rows are still here;
- whether a TSA certificate was revoked. It checks the TSA's chain at the token's time, so a certificate that has since expired still holds, and it reads no revocation list.

## Retention and erasure

- Retention deletes events from the start of the log only, and keeps the last deleted event's hash as the anchor the chain carries on from. An old event written after a newer one waits until the newer one is old enough too. `audit.pruned` records the anchor.
- Erasing a user ([ADR 0102](../adr/0102-erasing-a-users-data.md)) replaces their personal fields with a pseudonym and drops each event's salt, so its digest says nothing about them. The erasure records the ids it changed in `audit.erased` events (several, of at most 1,000 id ranges each, when the rows are scattered), and the chain still verifies. A salt cleared any other way fails as `erased`. Copies already in your SIEM aren't erased by botd: cover them with your SIEM's retention and your DPA, as with backups.
