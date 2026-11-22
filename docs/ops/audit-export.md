# Audit log: SIEM export and tamper evidence

Every audit event is sealed onto a hash chain as it is written, so a changed, removed, added or reordered event shows. botd can also send every event to your SIEM as it happens: JSON lines over HTTPS, or RFC 5424 syslog over TLS. The chain is always on and needs nothing. The export is off until you set a sink. Design: [ADR 0122](../adr/0122-siem-export-and-tamper-evident-audit.md).

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
  - `erased`: its salt was cleared, but no erasure (`audit.erased`) names it, so its fields can't be checked.
- `error`: the log couldn't be read to the end. The check fails.
  - `pin`: it differs from a hash you gave (below).

botd also checks itself a minute after starting and then once a day. Each check, and each one through the API, is recorded as `audit.verified` with the result and the head's hash. A broken chain logs a warning that links here.

### Hold it to a copy kept elsewhere

The chain has no secret key. Someone who can write `app.sqlite` (root, the service user) could change an event and re-hash everything after it, and the chain would verify again on that host. What catches this is a hash kept somewhere they can't reach: your SIEM. Every exported event carries its `chainHash`, and every `audit.verified` carries the head. Pick any event your SIEM holds and pin it:

```sh
botctl audit verify --pin 4182:3f1c...e9a0 --pin 9921:77ab...0c12
```

Each pin is `match`, `mismatch`, `gone` (older than what retention deleted) or `missing` (newer than that, yet not there). A mismatch or a missing event fails the check: the history on the host is not the one your SIEM saw.

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
| `AUDIT_EXPORT_HEADERS` or `AUDIT_EXPORT_HEADERS_FILE` | none | HTTPS only: headers, `name=value` pairs split by commas, such as `Authorization=Bearer <token>`. A secret: redacted everywhere, and no Bot's harness gets it |
| `AUDIT_EXPORT_START` | `all` | For a new sink: `all` sends the history still in the database first, `new` only events from now on |

A bad value stops botd at startup with a message naming the setting. URLs with a username, password, query or fragment are refused, so put tokens in `AUDIT_EXPORT_HEADERS`.

### What arrives

One JSON object per event, the same shape as `GET /api/audit`, plus:

| Field | Meaning |
|---|---|
| `schema` | `superbot.audit.v1` |
| `host` | The server's host name |
| `chainPrev`, `chainHash` | The event's link in the chain. Each event's `chainPrev` is the previous event's `chainHash` |

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
- After 3 failures in a row botd logs a warning and records `audit.export_failing`; `audit.export_recovered` follows when delivery resumes.
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

## Retention and erasure

- Retention deletes events from the start of the log only, and keeps the last deleted event's hash as the anchor the chain carries on from. An old event written after a newer one waits until the newer one is old enough too. `audit.pruned` records the anchor.
- Erasing a user ([ADR 0102](../adr/0102-erasing-a-users-data.md)) replaces their personal fields with a pseudonym and drops each event's salt, so its digest says nothing about them. The erasure records `audit.erased` with the ids it changed, and the chain still verifies. A salt cleared any other way fails as `erased`. Copies already in your SIEM aren't erased by botd: cover them with your SIEM's retention and your DPA, as with backups.
