# 0191: Several SIEMs, each with its own headers

## Status

Accepted (23 Nov 2026). Seventh slice of [#56](https://github.com/CG-Labs/superbot/issues/56) in M5. Builds on the SIEM export ([ADR 0122](0122-siem-export-and-tamper-evident-audit.md)) and an archive alongside a SIEM ([ADR 0173](0173-an-archive-alongside-a-siem.md)), whose "How many sinks" option 2 this takes up. The "Later" lists of ADRs 0173 and 0183, and the roadmap, have "more than one SIEM (per-sink headers)"; ADR 0173's also has "per-sink start positions".

## Context

`AUDIT_EXPORT` takes one SIEM and one archive. Enterprises often need more than one SIEM: their own Splunk or Sentinel and an MDR provider's collector; a SIEM and a data lake; or two SIEMs while moving from one to the other. Each has its own token, and today there is one `AUDIT_EXPORT_HEADERS`, so the second can't be sent anything.

Constraints: no new dependencies; existing settings, cursors and archives keep working unchanged; one SIEM's token must never reach another; one SIEM's outage mustn't hold up the others; the headers stay server secrets that no Bot gets, in the env or in Vault.

## Options

**How headers find their sink**

1. **By position**: `AUDIT_EXPORT_HEADERS_2` for the second SIEM listed. No new syntax, but reordering `AUDIT_EXPORT`, or adding a SIEM before another, would send one vendor's token to the other vendor, silently.
2. **By host**: headers keyed by the sink's host. Hosts have dots and ports, which aren't in environment variable names, and two sinks on one host (two Splunk HEC tokens, two paths on one collector) can't be told apart.
3. **By a name in `AUDIT_EXPORT`**: `AUDIT_EXPORT=splunk=https://...,mdr=https://...`, with `AUDIT_EXPORT_HEADERS_SPLUNK` and `AUDIT_EXPORT_HEADERS_MDR`. The binding is written next to the URL, so moving entries around moves nothing else. A name also labels the sink in events, status and metrics, where `kind` no longer tells sinks apart. The cost is a little syntax; it's unambiguous, since a URL always has `:` before any `=`.
4. **A file describing the sinks** (TOML or JSON). Room for anything, but a second way to configure export, and secrets in it or beside it.

**What a name is part of**

1. **Only the label and settings.** The cursor stays keyed by the URL, so naming a running sink, or renaming it, resumes it rather than sending the history again.
2. **The cursor too.** That would let two entries share a URL with different tokens, but naming an existing sink would start it over.

**How many**

1. **Up to four SIEMs and one archive.** Every sink holds retention back while it's behind, so each one added is another way for the table to grow. Four covers an own SIEM, an MDR, a data lake and one being moved to.
2. **Any number.** Nothing needs it, and each is a task, a connection and a cursor.

**Where a new sink starts**

`AUDIT_EXPORT_START` applies to every sink with no cursor yet. Adding an MDR's collector beside a SIEM that has run for a year means choosing between sending it the whole history and sending the archive (if it's new too) nothing old.

1. **`AUDIT_EXPORT_START_<NAME>`** for a named sink, falling back to `AUDIT_EXPORT_START`.
2. **Keep one setting**, and have operators add sinks one at a time.

## Decision

Option 3 for headers, option 1 for the cursor, option 1 for the count, option 1 for starts.

- **Names.** Any entry in `AUDIT_EXPORT` may be `<name>=<url>`. A name is 1 to 24 letters and digits, starting with a letter, case-insensitive and shown in lowercase; `file` is refused, since `AUDIT_EXPORT_HEADERS_FILE` already means the headers' file. An entry is named when what comes before its first `=` has no `:` or `/`, so `https://host/a=b` is not. Two sinks with one name, or one URL listed twice (they would share a cursor and race), stop botd at startup.
- **Count.** Up to four SIEMs (webhook or syslog) and one archive, in any order. With more than one SIEM, every SIEM must be named; the archive may be. A single SIEM needs no name, so every existing setting works unchanged.
- **Headers.** `AUDIT_EXPORT_HEADERS_<NAME>` (or `_FILE`), the name in capitals, goes to that webhook only. `AUDIT_EXPORT_HEADERS` still goes to the one SIEM when there is one, named or not; with more than one it stops botd, since it would go to all of them. Setting both for one sink, or headers for a syslog sink or the archive, stops botd too. A named webhook without headers of its own sends none.
- **Secrets.** `AUDIT_EXPORT_HEADERS_<NAME>` is a server secret like `AUDIT_EXPORT_HEADERS`: read from Vault's server folder, refused as a user's own secret, redacted everywhere, and, with its `_FILE`, kept from everything botd starts.
- **Starts.** `AUDIT_EXPORT_START_<NAME>` (`all` or `new`) applies to that sink when it has no cursor yet; otherwise `AUDIT_EXPORT_START` does.
- **Seeing them.** `name` is added to each sink in `GET /api/audit/siem` (null when unnamed), to `audit.export_failing` and `audit.export_recovered` when the sink is named, and to the startup summary's `auditExport`. Logs and the startup line show `splunk (https://host:443)`. The app's audit log labels the line `SIEM export (splunk)`. `/metrics` adds a `name` label to a named sink's series, beside `kind`, so two webhooks are two series; an unnamed sink's series are unchanged.
- Everything else is as ADR 0173 has it: each sink its own task, cursor, retries and failure events; retention held for the slowest; status led by the sink in the worst state.

## Consequences

- An MDR, a data lake, or the SIEM being moved to, can be added beside the SIEM in use without a proxy fanning events out, and each sees only its own token.
- All SIEMs get the same lines, so `host`, `id` and `chainHash` match across them, and pins (`--pin`) can come from any of them.
- Each SIEM down holds retention back. Alert on each sink's `pending`, now by `name`.
- Prometheus selectors such as `{kind="webhook"}` still match named sinks, but with several SIEMs they can return several series, so review aggregations and joins that expect one. Naming a running sink starts a new series (the old one, without `name`, ends). Alerts such as `superbot_audit_export_failing == 1` match each sink unchanged.
- A typo in `AUDIT_EXPORT_HEADERS_<NAME>` isn't caught at startup (botd can't list every name a secret store holds): that webhook sends no headers, its SIEM refuses the batches, and the export fails loudly, naming the sink.
- One URL can't be listed twice with two tokens. A collector that needs that can take one token, or two paths.
- Later: checking checkpoint timestamp tokens from the archive, exporting each event's chain digest so contents can be checked after retention, and gzip.
