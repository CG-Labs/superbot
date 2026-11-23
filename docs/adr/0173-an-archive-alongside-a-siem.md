# 0173: An archive alongside a SIEM

## Status

Accepted (23 Nov 2026). Fifth slice of [#56](https://github.com/CG-Labs/superbot/issues/56) in M5. Builds on the SIEM export ([ADR 0122](0122-siem-export-and-tamper-evident-audit.md)), the write-once S3 archive ([ADR 0154](0154-write-once-s3-audit-archive.md)) and checking it ([ADR 0163](0163-checking-the-audit-archive.md)). The "Later" lists of ADR 0154 and ADR 0163, and the roadmap, have "an archive alongside a SIEM (a second cursor)".

## Context

`AUDIT_EXPORT` names one sink. An enterprise security team usually wants two things from the audit log: live events in its SIEM (Splunk, Sentinel, Elastic) for detection, and a copy nobody can change for auditors and incident response. Today it has to pick one. A SIEM alone leaves only pins against tampering (`--pin`); an archive alone sends nothing to the SIEM until a batch closes, and nothing to alert on.

Constraints: no new dependencies or secrets; existing single-sink settings, cursors and archives keep working unchanged; one sink's outage mustn't lose or hold up the other's events.

## Options

**How to name the second sink**

1. **A list in `AUDIT_EXPORT`**, split by a comma: `AUDIT_EXPORT=https://<siem>/<path>,s3://<bucket>/<prefix>`. The settings already split by sink (`AUDIT_EXPORT_HEADERS` is the webhook's, `AUDIT_EXPORT_S3_*` the archive's), so nothing else is renamed. A comma in a webhook's path must be written `%2C`.
2. **A new `AUDIT_ARCHIVE=s3://...`.** Clearer at a glance, but `AUDIT_EXPORT=s3://` already means the archive, so there would be two ways to set it, and the `AUDIT_EXPORT_S3_*` names would no longer match.

**How many sinks**

1. **One SIEM (webhook or syslog) and one archive at most.** That covers the need. Each setting has one owner, so headers can't go to the wrong webhook, and each kind of sink is unique, so it can label metrics.
2. **Any number.** That needs per-sink headers and S3 settings (`AUDIT_EXPORT_2_HEADERS`...), a bigger change, for a need nobody has raised.

**How they run**

1. **Independently**: an exporter per sink, each with its own cursor (already keyed by sink), retries, failure events and status. Retention keeps every event that any sink hasn't taken.
2. **In lockstep**: one cursor, a batch counts when both took it. Simpler, but a SIEM outage would stop the archive too, and the archive's batches would cut the SIEM's latency to its batch length.

## Decision

Naming option 1, count option 1, running option 1.

- `AUDIT_EXPORT` takes one or two sinks split by a comma, at most one SIEM and one `s3://` archive, in either order. Anything else, or an empty entry, stops botd at startup. `AUDIT_EXPORT_HEADERS` needs a webhook among them. `AUDIT_EXPORT_INSECURE` applies to the SIEM, and `AUDIT_EXPORT_START` to each sink that has no cursor yet, so an archive added beside a running SIEM starts with the history still in the database, by default.
- Each sink runs as before, in its own task, from its own cursor. Adding an archive to an existing SIEM, or the other way round, resumes the one that was there.
- Retention (`AUDIT_RETENTION_DAYS`) holds every event after the lowest cursor.
- `audit.export_failing` and `audit.export_recovered` gain `kind`, so a SIEM rule can tell which sink it is about.
- `GET /api/audit/siem` (and the `export` block of `GET /api/audit/chain`) keeps its fields, now taken from the sink in the worst state, failing first and then furthest behind, so a script that reads `failing` or `pending` sees trouble at either sink. With one sink this is the same answer as before. `sinks` lists every sink's own view, in the order `AUDIT_EXPORT` gives them. The app's audit log shows one line per sink, `SIEM export` and `Archive`.
- `/metrics` gains a `kind` label (`webhook`, `syslog` or `s3`) on `superbot_audit_export_pending_events`, `superbot_audit_export_failing` and `superbot_audit_export_last_delivery_timestamp_seconds`. Alerts such as `superbot_audit_export_failing == 1` match each sink unchanged; a query that matched the series with no labels at all needs `kind`.
- `botctl audit verify --archive` finds the archive among the sinks.

## Consequences

- A SIEM outage no longer means a gap in the tamper-proof copy, and the archive's batching no longer delays the SIEM.
- Both sinks get the same lines, so an event's `host` and `id` match across them, and the archive can be held to what the SIEM saw.
- A long outage at either sink grows the table for both, as with one sink: alert on each sink's `pending`.
- The startup summary's `auditExport` is now a list of `{kind, sink}`, or null when off.
- Later: more than one SIEM (per-sink headers), per-sink start positions, and a daily automatic check of new archive objects.
