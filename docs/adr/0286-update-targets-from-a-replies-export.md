# 0286: Update targets, from the ticket system's export of replies

## Status

Accepted (25 Nov 2026). Fifteenth slice of enterprise support playbooks in M5, [#60](https://github.com/CG-Labs/superbot/issues/60), after the TAM handover draft ([ADR 0278](0278-tam-handover-draft.md)). Takes up the alternative [ADR 0167](0167-support-report-from-ticket-exports.md) set aside, "update targets too".

Numbering: this number was reserved for this work.

## Context

[Severity](../support/severity.md#updates-until-its-fixed) promises customers two things per ticket: a first answer within the response target, and updates until it's fixed (hourly around the clock for Severity 1, every 4 hours of the plan's support hours for Severity 2, at least every 3 business days for Severity 3). The support report (ADR 0167) judges the first; nothing judged the second. The status page's hourly updates are checked in each incident review (ADR 0201), but a Severity 1 or 2 ticket that isn't an incident, and every Severity 3, was checked by hand or not at all. For an Enterprise customer whose order form sets update targets, that's a promise nobody could show was kept at the quarterly review.

ADR 0167 left it out because a tickets export has only a ticket's first answer, and "per-comment exports differ too much between systems to read generically". They differ in their headers and in how they mark a reply public or from the customer, which is what the tickets export's reader already copes with: header aliases, `--column`, and values read in the forms systems write them.

Constraints as before: Rust first, no new dependencies, nothing personal in the output, nothing that contacts a ticket system or anyone else, and no change to botd, RBAC, the audit format or the support bundle.

## Decision

### `--updates` on `botctl support-report`

`botctl support-report <tickets.csv> --updates <replies.csv | ->` reads a second CSV, one row per reply or comment, and adds an update targets section to the report, in each format (an `updates` object in the JSON, a `### Update targets` section in Markdown). Without `--updates`, the report is unchanged.

- **Its own module.** `server/src/support_updates.rs`, included into `botctl` beside the report, reuses the report's CSV reader, time parser, business calendar and targets. The report now keeps the tickets it counted (`Report::tickets`), so the two judge exactly the same tickets: opened in the period, the customer's with `--customer`, readable. Its options are taken out of the arguments before the report's own, so `support_report::parse_args` is unchanged.
- **Five fields, nothing else.** The ticket id, the time, and optionally whether the row is public (`public`, or `private` read the other way) and whether its author is support (`author`). Bodies, authors' names and emails, and every other column are never read. A bare `ID` isn't a ticket alias, since in a comments export it's the comment's own id; ticket ids match ignoring case and a leading `#`. The author column is read only by role (Author role, Sender type, Direction): a column of names would make every row "an author it doesn't know", so a column called just "Author" isn't read at all.
- **What counts as an update.** A public row from support. The customer's own messages and automations (`system`, `trigger`, `bot`) aren't updates; an auto-reply doesn't tell the customer what's being done. Rows that can't be read are skipped and named by line; rows for tickets outside the report are counted, not read.
- **The targets are severity.md's.** `support_updates::default_target`: Severity 1 one hour on the clock, Severity 2 four business hours, Severity 3 three business days, Severity 4 none. A test reads severity.md's updates table and checks each row's wording against them. `--update-target <sev>=<time>` takes an agreement's, in `--target`'s forms (so `2=4h` is every 4 hours around the clock, and an agreed Severity 4 target is judged too).
- **Gaps from the first answer to the end.** The clock starts at the ticket's first answer, from the tickets export: the response target covers the time before it, so a late first answer isn't counted twice. Each stretch between the first answer, each update after it, and the end (resolution, or `--as-of` while open) is measured as the target counts time and judged against it. A ticket is late when any stretch is over; the report gives the number over and the longest. An open ticket whose last stretch is already over is marked "next update overdue", the one finding that asks for something to be done today.
- **Saying when the export looks short.** Tickets with no first answer aren't judged (the response target covers them). Judged tickets with no rows at all are counted and named in a note, since that usually means the replies export was filtered differently from the tickets export, and would otherwise read as silence.

## Alternatives

- **Call the ticket systems' APIs.** As in ADR 0167: one adapter and one set of credentials per system, and a network client in a tool that otherwise reaches only botd.
- **Read updates from the tickets export.** Some systems export a "last updated" or "number of replies" field. Neither says how long the customer waited between updates, which is what the promise is about.
- **Judge only Severity 1 and 2.** They're the ones with targets in hours, but Severity 3's "at least every 3 business days" is the one most often broken quietly, on tickets nobody is watching.
- **Count the customer's replies as resetting the clock.** A customer asking "any news?" is a sign the target was missed, not kept.
- **Read the severity's history.** A ticket that drops a level after a workaround should be judged at each severity for its time there, but exports rarely carry the history and never in the same way. The page says to note it beside the ticket.
- **Put the updates in a separate command.** It needs the report's tickets, period, calendar, customer and plans; a separate command would repeat every option and could judge different tickets.

## Tests

`support_updates.rs`: the defaults against severity.md's updates table; a report's tickets judged from an export with bodies, authors' names and comment ids that never reach the output: a Severity 1 with an internal note and a customer's message that don't count, a Severity 2 over its business hours with `#t-2` matching `T-2`, an open Severity 3 with its next update overdue, a Severity 4 not judged, a ticket with no first answer, a judged ticket with no rows, a row for another ticket, and rows skipped by line; an agreed 24×7 target and an agreed Severity 4 target, with named columns; a `private` column and a `direction` column, and an author it doesn't know; a ticket resolved with its first answer; the columns it needs and an empty period; the options split from the report's and their errors. `botctl.rs`: `--updates` from stdin beside a tickets file in each format, no `updates` object without it, and the errors for two stdins and a missing file. `tests/support_docs.rs`: the support report page explains every option in the usage and every field of both exports, and severity, the review template and escalation point at the update targets.
