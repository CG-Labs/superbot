# 0264: Audit export starts and stops on the chain

## Status

Accepted (25 Nov 2026). Fifteenth slice of [#56](https://github.com/CG-Labs/superbot/issues/56) in M5. Builds on the SIEM export ([ADR 0122](0122-siem-export-and-tamper-evident-audit.md)), several sinks with their own cursors and starts ([ADR 0173](0173-an-archive-alongside-a-siem.md), [ADR 0191](0191-several-siems-with-their-own-headers.md)) and the audit integrity evidence ([ADR 0261](0261-audit-integrity-evidence.md)), which deferred an event for a sink first set mid-period with `AUDIT_EXPORT_START=new`.

## Context

#56 asks for audit events streamed to SIEMs with tamper evidence. The chain shows that no recorded event was changed, and the export retries until every event reaches each sink. But the export's own configuration could change with no trace:

1. **A sink taken out leaves nothing behind.** Removing a SIEM from `AUDIT_EXPORT`, or unsetting it, and restarting botd stops the export without an event. Someone with access to botd's settings could stop it before doing something and turn it back on after; the chain would still be whole, and the SIEM's gap would look like a quiet week. PCI DSS 10.2.1.6 expects audit logs being started, stopped or paused to be logged themselves.
2. **A new sink can start past events.** `AUDIT_EXPORT_START=new` (or a named sink's) starts it at the head, by design. Nothing recorded that it did, or which events it never got. The evidence bundle ([ADR 0261](0261-audit-integrity-evidence.md)) only sees where each sink's cursor is now, so a SIEM set with `new` halfway through a month looks as if it took every event of that month.
3. **A sink can come back short.** A sink's cursor is kept when it's taken out, and putting it back resumes there. Retention holds events only for sinks that are running, so by then it may have deleted events the sink never took. The export carries on from the first event left, silently.

Constraints: no new settings, dependencies or tables; no change to delivery, cursors, the line or the chain; nothing secret in events (a webhook's path can hold a token, so it never goes in one).

## Options

**Where to see a stop**

1. **Only a log line.** Gone with the log, and nothing a SIEM or auditor can hold.
2. **An audit event at startup**, when botd compares the sinks with a cursor to the sinks set. It goes on the chain like any event, and to every sink still running, so the remaining SIEMs see it.
3. **An event when the setting changes.** botd reads `AUDIT_EXPORT` only at start, so startup is when it changes.

**What a sink that ran before is called**

1. **Its cursor's key.** For a webhook that's the URL with its path, which may hold a token.
2. **A record saved when it runs**, its kind, name and the address it shows (no path), beside its cursor in `settings`; for one that ran before botd kept records, what its key gives away safely: kind and host.

**What the evidence bundle does with it**

1. **List the changes only.**
2. **Also stop naming CC2.1-2 for a period a running sink skipped or missed events of.** ADR 0261 says the row holds while every export took every event of the period; a sink started past some of them didn't. A sink taken out is listed but doesn't on its own unmap the row: the sinks still running are judged as before, and with none left export is off.

## Decision

Option 2 each time.

- **`audit.export_started`** when a sink with no cursor starts: `sink`, `kind`, `name`, `start` (`all` or `new`), `after` (it gets every event after this id) and `skipped` (events kept in the log up to `after`, 0 with `all`). A sink starting with `new` starts at the head from before this start's events, so it gets its own `audit.export_started` and any `audit.export_stopped` beside it. The cursor and the event to record are saved in one transaction (the event as `unrecorded` in the sink's record) before the event is written, and cleared once it is, so a crash or failed write in between records it at the next start rather than losing it; at worst it is recorded twice.
- **`audit.export_stopped`** once for each sink with a cursor that `AUDIT_EXPORT` no longer lists: `sink`, `kind`, `name` from its record, `reason` (`removed` while other sinks run, `export_off` when none does), `delivered` (its cursor) and `pending` (events it hadn't taken). botd logs a warning too. The event's id is saved in the sink's record, so it isn't recorded again; a sink that ran before this version and is no longer set is recorded the first time botd starts with it.
- **`audit.export_resumed`** when a sink recorded as stopped is set again, or when retention has deleted events after its cursor: `after`, `stoppedEvent` (the stop's id, if any), and `missed: {after, through}`, the ids deleted before it took them, with a warning. When the event can't be written it is held in the sink's `unrecorded` list, which takes the stop's place, and recorded at the next start: a gap retention made isn't found again once the cursor has passed it.
- **The record.** `settings` keeps `audit_export:<sink id>#sink`, `{kind, name, sink, stopped, unrecorded}`, written each start; `unrecorded` is the list of events still to write, in order. Logs name a sink by the address it shows, never its id, which for a webhook holds its path. Like the sink's other `#` keys, it isn't a cursor.
- **Seen.** `GET /api/audit/siem` and `botctl audit siem` list sinks recorded as stopped under `stopped` (kind, name, sink, delivered, pending, the stop's id), when export is off too. `audit.export_stopped` and `audit.export_resumed` count in `superbot_events_total`.
- **Evidence.** `audit-integrity.json` lists the period's changes under `export.changes` (kind, name, codes, ids and counts; never an address) and adds three exceptions: `exportStopped`, `exportSkipped` (a sink started past an event of the period) and `exportMissed` (a sink back with events deleted). Its manifest names CC2.1-2, and so CC7.2-2, only with no `exportSkipped` or `exportMissed`. Starts and returns recorded after the period count too when they reach into its event ids (a start with `after` at or past its first event, a return whose `missed` overlaps it; all of them, read a page at a time), and a return within the period counts only when its `missed` reaches the period's events (any return does once retention has deleted events from the period's start, as its first id is then unknown), so a bundle for last month made after a sink was set with `new` this month doesn't overstate what that sink has; `export.changes` lists only the period's own. Exceptions are counted by the coverage report as before.

## Consequences

- Stopping the export, or one sink, is on the chain, delivered to the other sinks, and in the month's evidence. An operator can still stop export, but not quietly.
- A SIEM set with `new` mid-month is a gap for CC2.1-2 that month, as it should be: it lacks the month's earlier events. Starting a replacement SIEM with `all`, the default, keeps the row.
- Every new sink adds one event when it first starts. Tests and collectors that expected a new sink's first line to be another event see `audit.export_started` first.
- After upgrading, botd records `audit.export_stopped` once for any sink that has a cursor but is no longer set, however long ago it was taken out.
- A sink set with `new` that is taken out within the same period still counts as skipping: the bundle doesn't pair events of the same sink.

## Alternatives considered

- **Deleting a stopped sink's cursor**: would make putting it back start afresh, changing what [the guide](../ops/audit-export.md#changing-the-sink) promises. Kept, with the stop in its record.
- **Holding retention for stopped sinks**: a sink taken out for good would hold the log forever. `missed` records what a returning sink lost instead.
- **Failure outcome for stops**: the export did what it was told. SIEM rules match the action.

## Tests

- `audit_export.rs`: a start saved but never recorded (botd stopped in between) is recorded at the next start, before the stop of a sink since taken out, and only once; a new sink records its start (`all` from 0; `new` from the head, with what it skips, and still gets its own start); a restart records nothing; a sink taken out is recorded once as `removed`, with its name, address without path, delivered and pending; export off records `export_off` for each; a sink from before records has its webhook path left out; the stopped list shows them; a sink back after retention records `resumed` with its stop and the ids it missed, and is no longer listed as stopped; a return that can't be written is held in the record and recorded, once, at the next start, even after the cursor has passed the gap.
- `evidence_integrity.rs`: changes are listed with kinds and names, never addresses; a stop is an exception only; a start past an event of the period is `exportSkipped`, one at the period's start isn't; a return is `exportMissed` only when its deleted ids reach into the period, or retention has cut into it; every start and return after a period, however many, is held to its ids.
- `evidence_http_tests.rs`: on the real app, a webhook set with `new` after the period's first event lists its start, is `exportSkipped` and doesn't name CC2.1-2, for that period and for the day before, built afterwards; one set with `all` names it for both.

## Deferred

- Showing stopped sinks in the app's audit log panel.
- Pairing a skipped start with a later stop of the same sink in the bundle.
