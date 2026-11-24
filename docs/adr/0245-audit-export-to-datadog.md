# 0245: Audit export to Datadog

## Status

Accepted (24 Nov 2026). Thirteenth slice of [#56](https://github.com/CG-Labs/superbot/issues/56) in M5. Builds on the SIEM export ([ADR 0122](0122-siem-export-and-tamper-evident-audit.md)), several SIEMs with their own headers ([ADR 0191](0191-several-siems-with-their-own-headers.md)), self-checking lines ([ADR 0199](0199-self-checking-audit-lines.md)), the Azure Monitor sink ([ADR 0217](0217-audit-export-to-azure-monitor.md)), gzip ([ADR 0227](0227-gzip-for-the-audit-export.md)) and the Google SecOps sink ([ADR 0237](0237-audit-export-to-google-secops.md)), which left Datadog's own API for later.

## Context

#56 asks for audit events streamed to SIEMs with tamper evidence. Datadog Cloud SIEM reads Datadog Log Management, and botd can't reach it well today:

1. **The webhook doesn't fit.** Datadog's Logs API (`POST https://http-intake.logs.<site>/api/v2/logs`) takes a JSON array of logs, not the webhook's JSON lines (`application/x-ndjson`). Customers run the Datadog Agent or Vector beside botd to convert them.
2. **Datadog parses JSON in `message`.** A log whose `message` is a JSON line becomes that line's attributes, and the text itself is gone, so a copy in Datadog couldn't check itself.
3. **It drops old logs.** A log dated more than 18 hours ago is dropped at intake, with a 202 all the same. A new sink starts with the history (`AUDIT_EXPORT_START=all`), and a sink back from a long outage is behind too.
4. **Its limits.** At most 5 MB uncompressed and 1,000 logs a request, 1 MB a log (longer ones are cut). Gzip is documented and recommended. Authentication is an API key in `DD-API-KEY`, with no token exchange.

Constraints: harness-agnostic and Rust only; no new dependencies; no secret in the URL or in events; the same delivery guarantees as the other sinks (in order, at least once, its own cursor, retention held); the key must go only to Datadog's intake. A parallel change touches the shared stores (#58), so no new server-secret names.

## Options

**How to reach Datadog**

1. **Document the Agent or Vector.** No code, but another agent to secure and keep up.
2. **A native sink** for the Logs API.

**Where the API key lives**

1. **A new secret**, `AUDIT_EXPORT_DATADOG_API_KEY` (and `_<NAME>`). Clear, but a new family of server-secret names in the shared secrets code.
2. **The sink's headers**, `AUDIT_EXPORT_HEADERS` or `AUDIT_EXPORT_HEADERS_<NAME>` (ADR 0191), as `DD-API-KEY=<key>`: already a server secret no Bot gets, in the env or Vault, redacted, and one per named sink.

**What a log holds**

1. **The line as `message`.** Simple, but Datadog parses it away (point 2).
2. **The line exactly in its own attribute, its fields as attributes beside it.** Checks itself and is searchable at once, at about twice the bytes.

**How old events are dated**

1. **Always the event's time.** Anything older than 18 hours is silently lost.
2. **The event's time while Datadog takes it, else when Datadog takes it**, the true time still in the attributes.

**How the sink is named**

1. **An `https://` URL** of the intake. Easy to point at the wrong host with the key.
2. **Its own scheme**, `datadog://<site>`, from which botd builds the intake.

## Decision

Option 2, then 2, 2, 2 and 2.

- **The sink.** `AUDIT_EXPORT=datadog://<site>`, named or not, in any place in the list. It is one of the up to four SIEMs (ADR 0191), with its own cursor (by site), retries, start, status (`datadog` in `botctl audit siem`), failure events and metrics (`kind="datadog"`). The site is `datadoghq.com`, `datadoghq.eu` or `ddog-gov.com`, or a region of one (two letters and a number: `us3`, `us5`, `ap1`, `ap2`, `uk1`, `us2`), so new regions need no release; `app.datadoghq.com` and other hosts are refused. No credentials, port, path, query or fragment. Requests go only to `https://http-intake.logs.<site>`.
- **The key.** The sink's headers setting holds exactly one header, `DD-API-KEY`, 32 letters and digits, so an application key (40) or any other header is refused at startup. A Datadog sink without one stops botd, naming the setting. With several SIEMs each has its own, as for webhooks.
- **Logs.** Each event is one log: `ddsource` and `service` `superbot`, `hostname` the line's `host`, `message` the action, `status` from the outcome as syslog's severity (`info`, `notice` for failure, `warn` for denied), Datadog's standard `evt.name`, `evt.outcome`, `usr.id`, `usr.name`, `usr.email` and `network.client.ip` when the line has them, every field of the line under `superbot`, and `line`, the JSON line exactly as every other sink gets it, with `linePart` 0. All come from the line as exported, so they never say more than it does. `timestamp` is the event's `at` while it is under 17 hours old; older events go without, so Datadog dates them when it takes them and `superbot.time` keeps when they happened.
- **Long lines.** A line over 256 KB (twice that in a log) goes as several logs, `linePart` 1 to n, each `line` a piece (`superbot.audit.part.v1`, as for Azure) and `superbot` without `details`. `botctl audit verify-lines` puts them back together.
- **Requests.** `POST <intake>/api/v2/logs`, `Content-Type: application/json`, gzipped with `AUDIT_EXPORT_COMPRESS` or the sink's own `_<NAME>` (ADR 0227). A batch (up to 200 events) is split into arrays of at most 4 MB before compression and 1,000 logs, sent in order. Any failure fails the batch, which is sent again whole; Datadog doesn't de-duplicate, so de-duplicate on `@superbot.host` and `@superbot.id`. A 429 waits as `Retry-After` says (seconds or an HTTP date), up to 5 minutes, before the usual backoff. Errors carry the status and a hint for 400, 401, 403, 413 and 429, never Datadog's answer.
- **`Retry-After`.** Its parsing, seconds or an HTTP date, now lives in the export (`audit_export::retry_after`) and serves Azure Monitor, Google SecOps and Datadog. Azure Monitor read only seconds, so an HTTP date meant no wait at all; it now waits for it too.
- **Checking the copy.** `line` goes into `botctl audit verify-lines` one per line, pieces in any order: from Datadog's log archives (JSON lines, `.attributes.line`) or an export of the Log Explorer.

## Consequences

- Datadog customers send audit events straight from botd, with no Agent, and Cloud SIEM rules can match on standard attributes at once.
- The copy in Datadog checks itself, line by line and as a chain, like the archive and other SIEMs.
- Each event is ingested about twice over (the line and its attributes), which Datadog bills by. Gzip cuts the transfer, not the ingested bytes.
- History older than 18 hours is dated when Datadog took it; searches by event time use `@superbot.at`.
- The key is a header setting like any webhook's; no new secret names.
- Azure Monitor now waits for a `Retry-After` given as an HTTP date.
- Later, if asked: tags (`ddtags`) per sink, SecOps labels, namespaces and UDM, and gzip for SecOps if Google documents it.
