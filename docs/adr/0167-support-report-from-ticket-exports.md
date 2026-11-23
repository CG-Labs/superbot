# 0167: The support report, from the ticket system's export

## Status

Accepted (23 Nov 2026). Fourth slice of enterprise support playbooks in M5, [#60](https://github.com/CG-Labs/superbot/issues/60), after the support bundle ([ADR 0131](0131-support-bundle.md)), the TAM programme and health score ([ADR 0144](0144-tam-programme-and-health-score.md)) and the score's history ([ADR 0157](0157-health-score-history-and-console.md)).

Numbering: this number was reserved for this work.

## Context

The playbooks promise response targets per plan and severity ([severity](../support/severity.md#response-targets)) and say misses "are counted per month in the Provider's support report". The quarterly review asks for "response targets met and missed (from the support system)". Nothing made that report: a support manager would work it out by hand from a ticket system's dashboard, in its own idea of business hours and priorities, differently each time and per customer.

The tickets aren't in botd. They're in whatever system the Provider runs: Zendesk, Freshdesk, Jira Service Management, a shared inbox with a helpdesk on top. Constraints: Rust first with no new dependencies, harness agnostic, nothing personal in the output, and nothing that contacts anyone or anything.

## Decision

### `botctl support-report`, offline, from a CSV export

`botctl support-report <tickets.csv | ->` reads a ticket system's CSV export and prints the report as text, Markdown (to paste into a review) or JSON. Unlike `botctl`'s other admin commands it needs no botd and no sign-in: the export is on the support manager's machine, not the customer's server.

- **CSV, because every ticket system exports it.** Columns are found by header names the common systems use (`Ticket ID`, `Priority`, `Created at`, `First reply at`, `Solved at`, `Organization`, ...), ignoring case and punctuation; `--column <field>=<header>` names any other. Quoted fields, line breaks in fields, a byte-order mark, and semicolon or tab separators (spreadsheet exports in many locales) are handled by a small RFC 4180 reader in the module.
- **Seven fields, nothing else.** Id, severity, plan, opened, first response, resolved, and customer (only to pick one with `--customer`). Subjects, requesters and every other column are never read into the report. A row that can't be read is named by its line number, not its contents. Ticket ids remain, since a miss has to be looked up.
- **The targets are severity.md's.** The plan defaults are a table in the module, and a test parses severity.md's response targets table and checks every cell against it, so the code and the promise can't drift. An agreement's targets are `--target <sev>=<time>` (`30m`, `2h`, `4bh`, `1bd`), applied to every ticket in the report: Enterprise targets are per customer, and the report is run per customer for them.
- **Business time as the playbook defines it.** Clock targets (`1 h, 24×7`) count the clock. Business-hour and business-day targets count only business hours: one span a day (`--hours`, 09:00 to 17:30 by default), on some weekdays (`--weekdays`), at a fixed UTC offset (`--utc-offset`), except `--holidays`. A business day is one day's business hours, so a ticket at 16:00 on Friday with a one business day target is due at 16:00 on Monday.
- **Met, missed, waiting.** A ticket is met if its first answer came within target, missed if it came late or the target passed with none, and waiting if it has none yet but is within target (`--as-of`, now by default). Waiting tickets aren't in the percentage. Tickets count in the month they were opened (UTC); closed counts use the month they were resolved; what's open at the end counts every ticket opened before the period's end and not resolved by then.
- **The last three full months by default**, a quarter for a review; `--from` and `--to` pick up to 36 months.

The logic lives in `server/src/support_report.rs`, included into `botctl` by path like `superbot-machine`'s shared modules, so botd doesn't carry it. It uses chrono, already a dependency.

## Alternatives

- **Call ticket systems' APIs.** Always current, no export step, but one adapter per system, credentials for each on a support machine, and a network client in a tool that otherwise reaches only botd. An export works with all of them today, and a Provider who wants it automated can script the export.
- **Keep tickets in botd.** A support ticket table would let the console show the report, but botd is the customer's server and tickets are the Provider's records: they don't belong in a customer's database, and a self-hosted customer's botd never sees their tickets.
- **Use the ticket system's own SLA reports.** Each system computes them its own way (Zendesk's SLA policies, Jira's calendars), set up per Provider, and some plans don't have them. The playbook's targets would then be checked against whatever the system was configured with, not against severity.md.
- **Time zones with daylight saving.** Exact, but needs a time zone database (chrono-tz, or the system's zoneinfo, which air-gapped and Windows machines may not have). A fixed offset is exact for UTC and for most of a month elsewhere; the page says to run summer and winter months separately where the offset changes.
- **Update targets too.** An export has a ticket's first answer, not every update, and per-comment exports differ too much between systems to read generically. Update targets on Severity 1 and 2 are checked in each incident's review instead.
- **Pause the clock while waiting on the customer.** Ticket systems record that differently or not at all. Response targets end at the first answer, which rarely comes after a question back to the customer, so the page says to note it beside the miss.

## Tests

- `support_report.rs`: the plan defaults against every cell of severity.md's response targets table; target, hours, weekday, offset, severity and plan parsing; times as ticket systems export them; business time over evenings, weekends, holidays and an offset; CSV quoting, line breaks, byte-order marks and semicolons; a report's met, missed, waiting, closed and open counts and its median, from an export with subjects and emails that never reach the output; an unanswered ticket past its target; one customer with agreed targets, in Markdown; columns found by alias or named, and the errors when one is missing; the options and their errors; and an empty period.
- `botctl.rs`: the command reads a file or stdin with no botd, in each format.
- `support_docs.rs`: the playbook's links, every option in the command's usage and every field explained on its page, and severity, the review template and the health check pointing at it.
