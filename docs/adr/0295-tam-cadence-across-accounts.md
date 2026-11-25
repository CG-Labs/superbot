# 0295: The TAM cadence across accounts, from the CRM's export

## Status

Accepted (25 Nov 2026). Seventeenth slice of enterprise support playbooks in M5, [#60](https://github.com/CG-Labs/superbot/issues/60), after the escalations due now ([ADR 0289](0289-escalations-due-now-from-the-ticket-exports.md)).

Numbering: this number was reserved for this work.

## Context

#60 is "support and success playbooks, named TAM". The support side now has a check for each promise: response and update targets afterwards (ADRs 0167, 0286) and during the shift (ADR 0289), the rota and contacts (ADR 0211). The success side has drafts for one customer at a time, from that customer's server: the onboarding check (ADR 0233), the monthly health check (ADR 0252), the business review (ADR 0262) and the TAM handover (ADR 0278).

What nothing checks is the TAM's own promise across the book of accounts. [The TAM programme](../support/tam.md#cadence) promises each Enterprise customer a kickoff within 5 business days of signing, a check-in each week until go-live and in the week after it, a monthly health check, a quarterly business review, a restore drill twice a year, and a Severity 1's review walked through within 5 business days. Support readiness (ADR 0211) checks each customer has a TAM and a backup, and that no TAM has too many; it doesn't check the TAMs keep up. A customer whose TAM fell behind is found at the renewal, or not at all. botd can't see it: a self-hosted customer's server isn't the Provider's, the Provider has many customers, and kickoffs, drills, walk-throughs and renewals are in the CRM, not in botd.

Constraints as before: Rust first, no new dependencies, nothing personal beyond what the check is about, nothing that contacts a CRM, calendar, chat or anyone else, and no change to botd, RBAC, the audit format or the support bundle.

## Decision

### `botctl tam-cadence`

A new offline command, `server/src/tam_cadence.rs`, included into `botctl` beside the support report and readiness. It reads the CRM's CSV export of the accounts with a TAM (customer, TAM, and the date of each cadence step) and lists, by account, each promise overdue or due within `--warn-days` (7 by default), with when it was due, why and what to do, then each TAM's counts. It exits 1 when anything is overdue, so the Provider's daily job can post it; due soon alone doesn't.

- **One row per account, the CRM's own dates.** The fields are `customer`, `tam`, `signed`, `kickoff`, `go-live`, `check-in`, `health-check`, `business-review`, `restore-drill`, `severity-1`, `incident-review` and `renewal`, each found by common CRM headers or named with `--column`. Only `customer` is required. A promise is judged only when the export has its columns, and a note names those it couldn't judge, rather than calling every account overdue on a column nobody exports. A date after today is a step booked, not held.
- **Three stages, from the dates.** Signed (no kickoff yet), onboarding (kicked off, not live) and live. Each stage has its promises: the kickoff, then weekly check-ins, then the week-1 check-in (judged for 31 days after go-live, after which the monthly health check is the cadence), health checks, reviews and drills. The Severity 1 walk-through and the renewal apply at any stage. Without a go-live column every account is live, the commonest export for a book that's been running a while, and a note says so.
- **The handover's sums, and tam.md's words.** A month is 31 days after the last health check, and a review is due by the end of the calendar quarter after the last one's: as the TAM handover (ADR 0278) counts its next dates, so the two never disagree. The restore drill is due 183 days after the last. With no step and no go-live recorded, it's due now: a record to fix. The 5 business days count `--weekdays` and `--holidays`, in the support timezone (`--utc-offset`), which is also which day "today" is. A test reads tam.md's cadence table and checks every "when" the command judges, and the health check's 90 days for a renewal.
- **The renewal is a warning until it passes.** A renewal within `--renewal-days` (90, as the health check's license item) is due soon, for the account owner and the next review's agenda; a renewal date in the past is overdue until it's renewed or corrected, since a lapsed record hides the next one.
- **By TAM, busiest first.** Each TAM's accounts, overdue and due soon, so the support manager sees who needs help; `--tam` gives one TAM their own book. Accounts with no TAM are grouped last, and point at `botctl support-readiness --tams`, which judges that.
- **It reads names and dates only.** Contacts, emails, revenue and every other column are never read. Customer and TAM names are the output's point, like readiness's TAM list: the Provider's own records, kept where the CRM is. Names are put on one line, and shown in Markdown as code spans with `|` escaped (the escalation check's `md_cell`, now shared), so a name can't add a link, emphasis or a cell.

## Alternatives

- **An option on `botctl support-readiness --tams`.** Readiness reads the same CRM, but answers "can we keep our promises" with names and roles only, and exits 1 on a staffing failure. This needs a dozen dated columns, a stage per account and a daily verdict; one command with both would mix a monthly gate with a daily list.
- **Judge it from botd's records.** The health check and handover already do for one customer. botd sees one deployment, not the Provider's book, and doesn't hold signing, kickoff, drill, walk-through or renewal dates. Collecting each customer's handover JSON would send the Provider data it doesn't need, and wouldn't reach self-hosted customers who don't send it.
- **Use the CRM's API.** One adapter per CRM, and credentials in a tool that otherwise needs none; every CRM exports CSV.
- **Flag late steps already done.** A kickoff held on day 8 broke the promise, but there's nothing to do about it now; listing it daily would bury what's due. The support report counts the support side's misses afterwards; a quarterly business review is where a TAM's late steps belong.
- **Per-customer cadences.** Some agreements change the cadence. That needs a column per promise per account; until a Provider asks, an agreed exception is recorded as a date, or the customer is reviewed with `--customer`.

## Tests

`tam_cadence.rs`: the cadence against tam.md's table and health-check.md's renewal; business days over a weekend and holidays and with six weekdays, and quarters across a year; the options and bad ones, a date as noon in the support timezone and today as that timezone's; a book of accounts with TAM emails, revenue and owners' emails that never reach the output, judged on a fixed day: a Severity 1 walk-through late behind an older review, a restore drill and a health check overdue, a renewal due soon, a kickoff overdue and one due soon, check-ins overdue from the last one and from the kickoff, an account with everything in hand, a week-1 check-in missed and a renewal past, a kickoff booked ahead that doesn't count, an account with no dates, a duplicate customer, a row with no customer and an unreadable date skipped by line, the most urgent first, and each TAM's counts with no TAM last; the week-1 check-in after a month and one before go-live, a review the day of its Severity 1 and an older one; no go-live column, a named column, and no customer column; `--warn-days 0`, `--renewal-days`, `--tam` in another case and `--customer`; names that would break a line, a table, add a link or close a code span; dates as CRMs export them. `botctl.rs`: a file and stdin in each format, exit status when nothing is overdue, a missing file and the usage. `tests/support_docs.rs`: the page explains every option, field and item, and the TAM page, the index and readiness point at it.
