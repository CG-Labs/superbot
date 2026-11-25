# 0273: Stopped audit sinks in the app and metrics, and #56 delivered

## Status

Accepted (25 Nov 2026). Sixteenth and last slice of [#56](https://github.com/CG-Labs/superbot/issues/56) (M5, SIEM export and tamper-evident audit). It finishes the deferral ADR 0264 left first, stopped sinks in the app's audit log panel. Then it closes #56's scope, as [ADR 0259](0259-per-user-computer-hardening-delivered.md) did for #54. The follow-ups below are proposed, not started.

## Context

[ADR 0264](0264-audit-export-starts-and-stops-on-the-chain.md) made taking a sink out of `AUDIT_EXPORT` an event, `audit.export_stopped`, so the export can't be stopped quietly. Only `GET /api/audit/siem` and `botctl audit siem` list stopped sinks, though:

1. **The app's audit log panel stays quiet.** It reads `GET /api/audit/chain`, whose `export` block has only the sinks running. With one SIEM taken out and an archive left, the panel shows a healthy `Archive` line and nothing else. With export off, it shows the dim `Off (AUDIT_EXPORT)`, the same as a server that never exported. An admin who checks the chain in the app, as [the guide](../ops/audit-export.md) suggests, doesn't see the stop unless they read the event list.
2. **`botctl audit chain` doesn't show it either**, for the same reason.
3. **Prometheus has nothing to alert on.** Running sinks have series. A sink taken out just has no series, which looks the same as a sink that was never set.

Constraints: no new settings, dependencies, tables or events. Nothing more on the line or the chain. Never a webhook's path.

## Options

**What `/api/audit/chain` carries**

1. **Only a count of stopped sinks.** The panel could warn, but couldn't say which.
2. **The same `export` block as `GET /api/audit/siem`**, `stopped` included, built by one function so the two can't drift.

**When and why**

1. **Only the stop's event id**, as today.
2. **Also its time and `reason`** (`removed` or `export_off`), read from that event. Both are null once retention has deleted it.

**Metrics**

1. **A series per stopped sink**, labelled by kind and name. Names of sinks retired long ago would stay series forever.
2. **One gauge counting them**, `superbot_audit_export_stopped_sinks`, always present (0 with none), export on or off.

## Decision

Option 2 each time.

- **One status.** `audit_export::status` builds the `export` block for both `GET /api/audit/siem` and `GET /api/audit/chain`: running sinks as before, and stopped sinks under `stopped`, export off too. `botctl audit chain` shows it as is.
- **When and why.** Each stopped sink gains `stoppedAt` (Unix ms) and `reason`, from its `audit.export_stopped`. Both are null once retention has deleted that event. The sink stays listed by its record until it is set again.
- **The panel.** After the running sinks' lines, a `Stopped SIEM` or `Stopped archive` line for each stopped sink (with its name, if it has one), in the warning colour. It says what the sink showed (never a path), whether it was taken out or export was turned off, when, the stop's event id, the last event it took, and how many it hasn't taken. With export off and a stopped sink, the `SIEM export: Off` line is a warning, not dim. Lines are keyed by position, as two unnamed stopped sinks share a label.
- **Metrics.** `superbot_audit_export_stopped_sinks`, one unlabelled gauge, in `/metrics` whether export is on or off. Alert when it rises: `delta(superbot_audit_export_stopped_sinks[1h]) > 0`. Because a sink stays stopped until set again, `> 0` stays true after a SIEM is retired on purpose.

## #56 is delivered

#56 asks for one thing: "Stream audit events to SIEMs with tamper evidence." With this slice each part is merged and tested, and off by default where it sends anything off the server:

| #56 asks for | Delivered by | Checked by |
|---|---|---|
| Stream audit events | Every event, in order, at least once, from a saved cursor with retries and retention held until delivered, as JSON lines over HTTPS or RFC 5424 syslog over TLS ([ADR 0122](0122-siem-export-and-tamper-evident-audit.md)). Several SIEMs, each with its own headers, cursor and start ([ADR 0173](0173-an-archive-alongside-a-siem.md), [ADR 0191](0191-several-siems-with-their-own-headers.md)), and gzip ([ADR 0227](0227-gzip-for-the-audit-export.md)) | `audit_chain_http_tests`, `audit_export` |
| To SIEMs | Any collector that takes JSON lines over HTTPS or syslog over TLS (the guide shows Splunk's HTTP Event Collector), plus Microsoft Sentinel ([ADR 0217](0217-audit-export-to-azure-monitor.md)), Google SecOps ([ADR 0237](0237-audit-export-to-google-secops.md)) and Datadog ([ADR 0245](0245-audit-export-to-datadog.md)) natively, with labels for scoping ([ADR 0255](0255-labels-on-datadog-and-secops-logs.md)) | `audit_azure`, `audit_secops`, `audit_datadog` against stand-ins |
| Tamper evidence in the log | A SHA-256 hash chain that keeps erasure and retention whole, checked daily and on request ([ADR 0122](0122-siem-export-and-tamper-evident-audit.md)). Ed25519-signed checkpoints and RFC 3161 timestamps ([ADR 0149](0149-signed-and-timestamped-audit-checkpoints.md)) | `audit_chain_http_tests`, `audit_checkpoint_http_tests` |
| Tamper evidence outside it | A write-once S3 archive ([ADR 0154](0154-write-once-s3-audit-archive.md)), read back by hand and daily ([ADR 0163](0163-checking-the-audit-archive.md), [ADR 0183](0183-daily-check-of-new-archive-objects.md)). Exported lines that check themselves and their timestamps with no botd ([ADR 0199](0199-self-checking-audit-lines.md), [ADR 0207](0207-checking-timestamps-from-exported-lines.md)) | `audit_archive_http_tests`, `botctl audit verify-lines` tests |
| Not stopped quietly | Starts, stops and returns of every sink on the chain ([ADR 0264](0264-audit-export-starts-and-stops-on-the-chain.md)), and in the app, `botctl audit chain` and `/metrics` (this ADR). Monthly evidence in `audit-integrity.json` ([ADR 0261](0261-audit-integrity-evidence.md)) | `audit_export`, `evidence_integrity`, `evidence_http_tests`, the client's `auditChain` tests |

As with #54, the later slices were mostly deferrals and extra vendors, not things the issue names. Each ADR still defers more, so #56 would never end if every deferral stayed under it.

## Follow-ups

These are proposed, in order of value. None is started. Each would need an issue (under M5, or later) and an ADR of its own.

1. **Checkpoints and timestamps changed on the chain.** Setting `AUDIT_CHECKPOINT_MINUTES=0` or unsetting `AUDIT_TIMESTAMP_URL` takes signing or timestamping away with no event. This is the same quiet stop ADR 0264 closed for the export. Recording the change at startup, as the export does, would also let `audit-integrity.json` judge a period by the interval in force at the time (deferred by [ADR 0261](0261-audit-integrity-evidence.md)).
2. **Retiring a sink on purpose.** A SIEM taken out for good stays listed as stopped, and in the gauge, until set again. Clearing it means editing `settings` while botd is stopped. A `botctl audit siem retire <sink>`, recorded on the chain, would clear it and keep the warning for stops nobody explained.
3. **Pairing a skipped start with a later stop** of the same sink in the evidence bundle, so a sink set with `new` and taken out within one period isn't counted as skipping ([ADR 0264](0264-audit-export-starts-and-stops-on-the-chain.md)).
4. **Matching each month's pinned head against the next month's checks** automatically in the coverage report ([ADR 0261](0261-audit-integrity-evidence.md)).
5. **Google SecOps UDM**, through a parser or `events:import`, so detections need no custom parser ([ADR 0237](0237-audit-export-to-google-secops.md), [ADR 0255](0255-labels-on-datadog-and-secops-logs.md)).
6. **Labels that differ by event**, by action or team ([ADR 0255](0255-labels-on-datadog-and-secops-logs.md)).
7. **Gzip for SecOps**, if Google documents it ([ADR 0227](0227-gzip-for-the-audit-export.md), [ADR 0237](0237-audit-export-to-google-secops.md)).

## Consequences

- A stopped sink shows wherever the chain's state does: the app, `botctl audit chain`, `botctl audit siem` and `/metrics`. An admin who opens the panel sees the stop without reading the events.
- `GET /api/audit/chain`'s `export` gains `stopped`. `GET /api/audit/siem`'s stopped sinks gain `stoppedAt` and `reason`. Clients that ignore unknown fields are unaffected.
- `/metrics` gains one series, present even with export off.
- A SIEM retired for good keeps a warning line in the panel and a count in the gauge until follow-up 2, or until its row is removed from `settings`.
- #56 can be closed once this is merged. Nothing needs upgrading.

## Tests

- `audit_chain_http_tests.rs`: on the real router, `GET /api/audit/chain` shows no `stopped` with nothing stopped. A named SIEM taken out with export off is listed there as `export_off`, with its name and address (never its path), its delivered and pending counts, and its stop's id and time. That block is the same as `GET /api/audit/siem`'s. The gauge goes from 0 to 1. With export back on with another SIEM, the stop isn't recorded again, both are shown, and the gauge stays 1. Once retention has deleted the stop's event, the sink is still listed, with `stoppedAt` and `reason` null.
- `apps/client/src/__tests__/auditChain.test.ts`: a stopped sink's line for taken out, export off and pruned; stopped lines after running ones, in the warning colour; and `Off` as a warning only when a sink was stopped.
