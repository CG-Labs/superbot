# 0155: Residency reports for customers

## Status

Accepted (23 Nov 2026). The third slice of [#58](https://github.com/CG-Labs/superbot/issues/58) (M5, "Contractual data residency"). Builds on [ADR 0129](0129-contractual-data-residency.md) (residency pins) and [ADR 0139](0139-in-region-model-routes.md) (in-region model routes). 0155 was reserved for this work.

## Context

A pin holds a tenant's machines, backups and model calls to a region, and audits every refusal. The [DPA's residency annex](../security/dpa-template.md#iv5-evidence) promises the customer evidence on request. Until now that meant an operator filtering the audit log by a dozen actions, reading `GET /api/regions`, and listing each person's machine, host and backups by hand. That is slow, easy to get wrong, and gives the customer nothing they can check was not edited after it was made.

## Options

1. **Document the audit filters.** Cheap, but the operator still assembles the evidence by hand, and the customer gets loose CSVs.
2. **Put residency in the SOC 2 evidence bundle** ([ADR 0142](0142-type-ii-evidence-bundles.md)). That bundle is for the provider's auditor and covers the whole server; a customer should see only their own pin.
3. **A report per pin** (chosen). One request makes a document about one pin: where its data is now, what happened in a period, and what it doesn't cover, sealed with a digest.

## Decision

### The report

`GET /api/users/{key}/residency/report` (the user's own pin) and `GET /api/teams/{id}/residency/report`, admins only by RBAC's default arm. 404 when there is no pin; for a member of a pinned team without their own, the error names the team's report.

- **Period**: `?from=&to=`, as the audit API takes them (unix ms, RFC 3339 or a date; a date as `to` is the end of that day). By default the last 90 days, never past now, at most 400 days.
- **Subject and pin**: user or team, name, region, reference, when and by whom pinned.
- **Where the data is now**, per person the pin holds (the user, or the team's current members): their machine's id, state, recorded region, and for Incus the host it is on and that host's region; whether it is in the region by both; their kept backups, how many are in a store in the region and how many outside; their plan and whether it has a model route in the region (ADR 0139).
- **Status**: `kept` when none of that is outside the region, else `data_outside`, with `outside` saying what and whose. This uses the same check as pinning (ADR 0129), so the report and a new pin agree.
- **Warnings**: why the region can't keep pinned data now (not offered, untagged hosts, no backup store), and plans with no in-region route, whose runs are refused.
- **Region**: whether it is offered, the Incus hosts in it, and whether off-host backups have a store there.
- **Activity in the period**, from the audit log:
  - pin changes on the subject: pinned, renewed, unpinned (with the reason), refused;
  - refusals the pin caused, counted by event and kind: `machine.residency_refused` (by `action`), `bot.run_refused` with reason `residency_pinned` (run, or pinned while queued), and region changes, joins and team deletes refused as `residency_pinned`. A refusal counts when it is on the subject, names the pin among a run's pins, or is about one of its people in its region. A run refusal also counts when its `pinnedRegions` include the region and it carried one of the pin's people, whichever pin it named: a member's own pin and their team's agree on the region, and the run names only the team's;
  - runs held to in-region routes: `harness.invoked` with `residency.regions` including the region and `residency.people` (the people the run carried, now recorded on held runs and on residency run refusals) including one of the pin's people. Counting by who was recorded at the time keeps past counts fixed when a Bot is deleted or handed over. Runs recorded before this fall back to the asker and the Bot's owner now;
  - `truncated` when the period has more matching events than one report reads (100,000).
- **Not covered**: botd's own database and server backups, what Bots' tools send, other subprocessors, and people who have left a pinned team.

Counts, never chats, prompts or IP addresses. Names and emails of the covered people are in it, since it is about them and goes to their organisation.

### The digest

`digest` is the SHA-256, in hex, of the report without `digest`, written as JSON with every object's keys sorted and no whitespace. Those are the bytes `jq -cjS 'del(.digest)' report.json` writes, so a customer checks a report with `jq` and `sha256sum` and needs nothing from us. A test checks the same digest from both, Unicode and control characters included.

The digest seals the document, not the state: `generatedAt` is inside it, so two reports differ. Each report is audited as `residency.report_generated` on the subject with its period, status and digest, so the provider's tamper-evident audit log ([ADR 0122](0122-siem-export-and-tamper-evident-audit.md), [ADR 0149](0149-signed-and-timestamped-audit-checkpoints.md)) shows which reports were issued, and a customer can ask the provider to confirm that a digest they hold is in it.

### Formats

JSON by default. `?format=markdown` gives a readable document (an attachment with a dated name) with tables per person and per refusal, then the digest and the exact JSON it seals, in a fence no value inside can close, so the customer can check a Markdown report too. `botctl user|team residency <key> report [--from <when>] [--to <when>] [--json] [-o <file>]` prints or saves either; Markdown unless `--json`.

### What it doesn't do

- **No signature by botd.** The digest proves the document is whole; that it came from the provider rests on the audit log entry and the channel it was sent over. Signing it with the audit checkpoint key is possible later.
- **No history of where a machine was.** Machines and backups are reported as they are now; the past is in the refusals and the audit log. A pin is refused while any data is outside (ADR 0129), so "kept now" plus "pinned since" is the claim.
- **No self-service.** Customers don't fetch it themselves yet; showing the pin and its report in the app is still to do.

## Consequences

- An operator answers a customer's residency evidence request with one command, and the DPA annex names it.
- A customer can check a report wasn't changed, and can compare it with the provider's audit log.
- Every report is itself audited, so who asked for evidence, and when, is on record.

## Tests

- Unit (`residency_report.rs`): the digest is over sorted, compact JSON without itself; periods (default, end of day, never past now, at most 400 days, bad input); Markdown table cells; the JSON in the Markdown reads back with the same digest, even with backticks in a name.
- The route tests (`residency_routes_http_tests.rs`) check that held runs and residency run refusals record `people`.
- End to end (`residency_report_http_tests.rs`), on the real router with the Incus and S3 stand-ins and the fake Linode:
  - a pinned user's report: 404 before the pin, 403 for a member; machine, host and backups in the region; the open plan's route warning; the pin's change, a refused move, a refused region change, a refused run naming her pin and one naming an agreeing team pin that carried her counted, another pin's refusal and runs held elsewhere or for others not; held runs counted by the people recorded, a deleted Bot's included; the digest checks and is audited; Markdown carries the reference, a refusal row, the digest and the JSON it seals; a period before the pin is empty; bad format and periods refused; a backup in another region's store turns the status to `data_outside`;
  - a team's report covers both members, counts the refused team delete and region change, and a member's own report points to the team's.
- botctl (`residency_report_commands`).
