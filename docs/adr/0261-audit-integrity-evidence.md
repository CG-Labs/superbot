# 0261: Audit integrity evidence in the evidence bundle

## Status

Accepted (24 Nov 2026). Fourteenth slice of the SOC 2 Type II programme ([#57](https://github.com/CG-Labs/superbot/issues/57), M5). Adds a file to botd's evidence bundle ([ADR 0142](0142-type-ii-evidence-bundles.md)), bumping its format to 3, and teaches the coverage report ([ADR 0169](0169-evidence-coverage-report.md)) about it. Collects evidence for the tamper-evident audit log and its export ([ADR 0122](0122-siem-export-and-tamper-evident-audit.md), [ADR 0149](0149-signed-and-timestamped-audit-checkpoints.md), [ADR 0173](0173-an-archive-alongside-a-siem.md)). Serves readiness checklist rows CC2.1-2 and CC7.2-2 in the [evidence plan](../security/soc2-evidence-plan.md#the-evidence-bundle).

## Context

The checklist marks CC2.1-2 ("audit events exported to a SIEM") and CC7.2-2 ("a tamper-evident audit log shipped off the server") Done: botd seals every event onto a hash chain, checks the chain daily (`audit.verified`), signs a checkpoint of the head every hour while there are new events (`audit.checkpoint`), and ships every event to one or more sinks with retries (`audit.export_failing`, `audit.export_recovered`). A Type II report asks whether those controls operated through the observation period, not whether they're built. The evidence bundle held none of it: `audit-summary.json` counts the events and the coverage report listed both rows as covered by no bundle. The evidence plan still said "SIEM export and a tamper-evident log once built (#56)" under what is manual.

Two things only a record from the period can show: that the daily check and the hourly checkpoints kept running (a botd whose check loop stalled still has a whole chain), and that every event of the month reached the sink (the export retries, so a sink that was failing for a week may have caught up, or may not).

## Decision

### `audit-integrity.json`

botd's evidence bundle gains `audit-integrity.json`, built in the same pass over the period's events as the rest, plus three reads from before it (the last whole check, the last start, and the oldest event the last checkpoint didn't sign), so a stretch that starts before the period is judged from its real start.

- **Checks.** Every `audit.verified` in the period: when, by whom (system or a person, by kind), whole or a range, its result and reason code, events checked and broken, and the head's id. Only a check of the whole chain counts as the daily check.
- **Check gaps.** A gap opens when botd writes an event more than 25 hours after the last whole check (the check runs a day after the last ended, so an hour covers a long one), and closes at the next whole check; a whole check that itself comes more than 25 hours late opens and closes one. botd starting resets the clock, since the check runs a minute after start: a server that was down wrote nothing, which uptime evidence covers, not this file. Judging by events written rather than by calendar day avoids flagging a day the daily check slipped past midnight.
- **Checkpoint gaps.** A gap opens when botd writes an event more than `AUDIT_CHECKPOINT_MINUTES` and 15 minutes after the oldest event no checkpoint has signed, and closes at the next checkpoint; a checkpoint that itself comes that late is a gap ending at it, since the events waited unsigned until then. Checkpoints' own events (signing, timestamps, key changes) need none, as botd's scheduler already treats them. The interval is the one in force when the bundle is made; botd records no event when it changes.
- **Export.** Each sink by kind and, when named, by its name (lowercase letters and digits), never its address, headers or last error: how far it has delivered, what's pending, whether it has taken the period's last event, and whether it's failing now; every `audit.export_failing` in the period with its kind, reason code and the backlog then.
- **The chain now and the period's pin.** The head, the latest whole check when the bundle is made and the last one by the period's end, the checkpoint key's id and public key, timestamping's state, and the last checkpoint at or before the period's last event: its event, sequence, hash, signature and public key. Kept with the month's evidence, it lets anyone later run `botctl audit verify --pin <seq>:<hash>`, checking that the month's events are the ones the auditor saw, against a signature botd's key made at the time.
- **Exceptions**, counted by the coverage report: features off (`checkpoints`, `export`), failed checks, the last whole check by the period's end or the latest one failed, the scan stopped before the period's end (past 5 million events), check gaps, checkpoint gaps, sinks behind, export failures and timestamp failures.

### The manifest names a row only while it held

As with the uptime bundle ([ADR 0249](0249-uptime-evidence-from-the-outside-probe.md)), the file's manifest entry is conditional: CC2.1 and CC2.1-2 while there is an export and every sink has delivered the period's last event; CC7.2 and CC7.2-2 while, as well, checkpoints are on, there was no check or checkpoint gap, and both the last whole check by the period's end and the latest one when the bundle is made passed: a later failure means the period's rows may have changed since, so rebuilding an old month after a break no longer names it. Neither is named when the scan stopped before the period's end, since the unread events could hold a gap or an event no sink took. CC7.2-2 asks for a log shipped off the server, so it needs the export too. A month that doesn't hold is a gap in the coverage report for that row, with the reason in the file's exceptions.

### Format 3 and coverage

botd's evidence bundle format goes from 2 to 3. The coverage report expects `audit-integrity.json` in every evidence bundle of format 3 or newer, checks it like the other files, counts its exceptions, and maps CC2.1-2 and CC7.2-2 from each manifest. Bundles of format 2 or older still check without it.

Nothing else in it is new: values are counts, codes, ids, times, hashes and signatures, all through the bundle's existing scrubbing, and the file holds no address, header, error message or name.

## Alternatives considered

- **Running the check when the bundle is made**: shows the chain is whole now, which the next daily check also shows; it can't show the check ran through the month, which is what Type II tests. The bundle reads the checks botd recorded instead.
- **One check per calendar day**: simpler to explain, but the check runs every 24 hours after the last ended, so it drifts across midnight and some days legitimately have none.
- **Mapping the rows whatever happened, as the other botd files do**: the coverage report would show a month with a broken chain or a stalled export as covered. The uptime bundle set the precedent for a manifest that maps only what held.
- **Recording an event when a sink starts**: would show a sink set mid-period with `AUDIT_EXPORT_START=new`, whose cursor starts past events it never sent. Left for later; the bundle can only see where each sink's cursor is.

## Tests

- Unit tests in `evidence_integrity.rs`: a daily check and hourly checkpoints leave no gaps; events written a day past the last check are a gap until the next, and so is a check or checkpoint that itself came late; a server that was down isn't a gap, but one that started and ran a day without checking is; a failed check is kept, and a check of a range never counts as the daily one; events left unsigned past the interval are a gap, checkpoints' own events aren't, and checkpoints off is reported as off; export failures keep only codes.
- `evidence_http_tests.rs`: on the real app, a checked and signed log with no export names neither row; with a webhook that fails three times and then takes everything, both rows, the failure listed by kind and reason, no address or header in the file, and the period's pin matching a later `GET /api/audit/verify?pin=`; a scan cut short names neither; a changed row makes the next check fail and leaves only CC2.1-2, for that period and for an earlier one that held until then. The file list and the evidence plan's table are checked as before.
- `coverage.rs`: a format 2 bundle without the file checks, a format 3 one must have it, its exceptions are counted, and a manifest naming no row covers none; the coverage kind's file and controls match botd's constants and the plan.

## Consequences

- An operator who hasn't set `AUDIT_EXPORT` gets an evidence bundle whose `audit-integrity.json` names neither row, and a coverage report showing them as gaps: the rows are Done in the product, but not yet evidenced on that server.
- A failed chain check keeps CC7.2-2 out of every month until a whole check passes again. After an unexplained break the operator follows the [audit export guide](../ops/audit-export.md#if-its-broken) and treats it as a security incident, which is what an auditor would expect to find recorded.
- CC2.1-2 and CC7.2-2 stay Done; the checklist notes now point at the bundle.

## Deferred

- An `audit.export_started` event, so a sink first set mid-period with `AUDIT_EXPORT_START=new` shows the events it skipped.
- Matching each month's pin against the next month's checks automatically in the coverage report.
- Recording changes of `AUDIT_CHECKPOINT_MINUTES` so a period is judged by the interval in force at the time.
