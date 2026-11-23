# 0191: Several SIEMs, each with its own headers

## Status

Accepted (23 Nov 2026). Seventh slice of [#56](https://github.com/CG-Labs/superbot/issues/56) in M5. Builds on the SIEM export ([ADR 0122](0122-siem-export-and-tamper-evident-audit.md)) and an archive alongside a SIEM ([ADR 0173](0173-an-archive-alongside-a-siem.md)). The "Later" lists of ADRs 0173 and 0183, and the roadmap, have "more than one SIEM (per-sink headers)".

## Context

`AUDIT_EXPORT` takes one SIEM and one archive. Enterprises often need two or more SIEMs at once: a SOC's Splunk and a cloud team's Sentinel, a managed detection provider beside the in-house SIEM, or the old and new SIEM during a migration that can take months. Each collector has its own credentials. ADR 0173 kept one SIEM because `AUDIT_EXPORT_HEADERS` has one owner: with two webhooks, a single headers setting could send one collector's token to the other.

Constraints: no new dependencies; existing settings, cursors, metrics series and alerts keep working unchanged; one collector's credentials must never reach another; one sink's outage mustn't hold up the rest.

## Options

**How to tell sinks apart**

1. **By position**: `AUDIT_EXPORT_HEADERS_1`, `_2`, in `AUDIT_EXPORT`'s order. No new syntax, but reordering the list, or adding a sink in front, silently sends each token to another collector.
2. **By name**: `AUDIT_EXPORT=splunk=https://...,sentinel=https://...`, with `AUDIT_EXPORT_HEADERS_SPLUNK`. A token is tied to the sink it was written for, whatever the order. A `=` in a URL comes after its `://`, so `<name>=` before the scheme can't be mistaken for part of a URL.
3. **By host**: headers keyed on the collector's host. Two webhooks on one host (two Splunk HEC indexes) would clash, and host names make awkward variable names.

**What the cursor is keyed on**

1. **The URL, as now.** Naming a sink that is already running keeps its place; changing its URL starts over, as before.
2. **The name.** A URL could change without resending history, but naming an existing sink would resend everything, and renaming one would too.

**How many**

1. **A small cap**: four SIEMs plus the one archive. Each sink is a task, a connection and a copy of the retention hold; four covers every case raised (two SIEMs plus a migration) and keeps the status and metrics readable.
2. **Any number.** Nothing needs it, and a long list is more likely a mistake than a plan.

## Decision

Naming option 2, cursor option 1, count option 1.

- `AUDIT_EXPORT` entries may be `<name>=<url>`. A name is a letter, then letters, digits or `_`, at most 32, case-insensitive (kept in lower case), unique, not `webhook`, `syslog` or `s3` (so it can't be confused with a kind in metrics), and not `file` or ending in `_file` (so `AUDIT_EXPORT_HEADERS_<NAME>_FILE` always means one sink's headers file, never the shared `AUDIT_EXPORT_HEADERS_FILE` or another sink's value). Every SIEM needs a name once there are two or more; a lone SIEM and the archive may have one. The same sink listed twice (same cursor) stops botd.
- Up to `MAX_SIEMS` (4) SIEMs and one archive, in any order.
- **Headers per sink.** A named webhook's headers are the secret `AUDIT_EXPORT_HEADERS_<NAME>` (or `_FILE`, or Vault), parsed and redacted like `AUDIT_EXPORT_HEADERS`. The whole `AUDIT_EXPORT_HEADERS_` prefix is botd's own (`server_secret`): no Bot is given it, it is read from the external store's server folder, and it and its `_FILE` are stripped from everything botd starts, whatever the name. `AUDIT_EXPORT_HEADERS` still works with exactly one webhook, named or not, and is refused with two or more, since it can't say which one it's for; setting both it and the webhook's own stops botd. A named syslog sink or archive with headers stops botd. A webhook with no headers of its own gets none: headers never fall back to another sink's. botd reads only the names `AUDIT_EXPORT` lists, so a leftover `AUDIT_EXPORT_HEADERS_<NAME>` is ignored (the secret store reads by name and can't list what's set).
- Each sink runs as ADR 0173 set out: its own task, cursor, retries and failure events, with retention held for the slowest.
- `audit.export_failing` and `audit.export_recovered` gain `name`; `GET /api/audit/siem` gives each sink's `name` (null when unnamed), with the worst sink leading as before; the startup summary's `auditExport` entries gain `name`; logs say `<name> (<sink>)`.
- `/metrics` adds a `name` label to a named sink's series. An unnamed sink is always the only one of its kind, so its series keep only `kind`, and existing alerts and dashboards are unchanged.
- The app's audit log labels each line `SIEM export (<name>)` or `Archive (<name>)` for a named sink.

## Consequences

- A team can feed every SIEM it runs, and move between SIEMs without a gap, each collector seeing only its own credentials.
- Each extra SIEM is another reader of the audit table and another hold on retention: a SIEM left failing holds events for all. Alert on each sink's `pending`.
- A single-SIEM setup is unchanged, and can be named later without resending history.
- Later: checking checkpoint timestamp tokens from the archive, exporting each event's chain digest so contents can be checked after retention, gzip, per-sink start positions, and per-sink `AUDIT_EXPORT_INSECURE`.
