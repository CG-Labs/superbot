# TAM cadence check

Which promises of the [TAM programme's cadence](tam.md#cadence) are overdue or due soon, across every account with a TAM ([ADR 0295](../adr/0295-tam-cadence-across-accounts.md)): a kickoff not held within 5 business days of signing, a weekly onboarding check-in or the check-in in the week after go-live missed, a monthly health check, a quarterly business review or a twice-yearly restore drill not done in time, a Severity 1 whose review hasn't been walked through within 5 business days, and a renewal coming up or past. `botctl health-check`, `botctl business-review` and `botctl tam-handover` look at one customer's server; this looks at the Provider's whole book of accounts, from its own records, so a customer whose TAM fell behind is seen before the customer notices.

`botctl tam-cadence` reads the CRM's export of the accounts. It runs anywhere `botctl` does, needs no botd and no sign-in, and reaches no CRM, calendar or chat: it says what's due, and tells nobody. It prints the list on stdout either way and exits 1 when anything is overdue, so a daily job can raise it with the TAMs and the support manager.

## Running it

```sh
# Every account, as of today
botctl tam-cadence accounts.csv

# One TAM's book, as Markdown for their weekly one-to-one
botctl tam-cadence accounts.csv --tam "<tam-name>" --markdown

# One customer, before their business review
botctl tam-cadence accounts.csv --customer "<customer>"

# From stdin, in the support timezone with its holidays, as JSON for a chat hook
some-export-command | botctl tam-cadence - --utc-offset +01:00 --holidays 2026-12-25,2026-12-28 --json
```

| Option | What it does |
|---|---|
| `--tam <name>` | Only the accounts whose TAM is this person, ignoring case and punctuation |
| `--customer <name>` | Only this customer, ignoring case and punctuation |
| `--weekdays <days>` | Business days, for the 5 business days of a kickoff and of a review's walk-through: `mon-fri` by default; also lists like `mon,wed,fri` or `all` |
| `--utc-offset <+HH:MM>` | The support timezone's offset from UTC, `+00:00` by default: which day "today" is, and the day of a time in the export |
| `--holidays <dates>` | The Provider's public holidays, `YYYY-MM-DD` separated by commas; repeatable. They aren't business days |
| `--warn-days <days>` | How many days ahead a promise is due soon, 7 by default, 0 to 60. With 0, only what's due today is |
| `--renewal-days <days>` | How many days ahead a renewal is due soon, 90 by default (as the [health check](health-check.md#6-the-account)'s license item), 1 to 366 |
| `--column <field>=<header>` | Which column of the export holds a field, when its header isn't one it knows (below). Repeatable |
| `--as-of <time>` | When "now" is, today by default: a date or a time, to see what was due on a day in the past |
| `--markdown`, `--json` | A Markdown table to paste, or JSON. Plain text by default |

## The export

One row per account with a TAM: every Enterprise customer, and any other given a TAM by agreement. Most CRMs can export a view of accounts with these fields as CSV (commas, semicolons or tabs; quoted fields; a byte-order mark is fine). Only `customer` is required; each promise is judged only when the export has the columns it needs, and a note names those it couldn't judge. Dates are `YYYY-MM-DD`, `YYYY/MM/DD` or a time, taken on its day in the support timezone. A date after today hasn't happened yet: a kickoff or review booked ahead is not one held.

| Field | Headers it knows | What it's for |
|---|---|---|
| `customer` | Customer, Account, Account name, Organisation, Organization, Company | The account. A customer listed twice is read once, and the later row is skipped |
| `tam` | TAM, TAM name, Technical account manager, Named TAM | Grouping by TAM, and `--tam` |
| `signed` | Signed, Signed on, Contract signed, Signature date, Close date | When the kickoff's 5 business days start |
| `kickoff` | Kickoff, Kick off date, Kicked off | When the kickoff was held: onboarding has started |
| `go-live` | Go-live, Go-live date, Went live, Live since | When the customer went live. Without this column every account is taken as live |
| `check-in` | Check-in, Last check-in | The last check-in with the customer's owner |
| `health-check` | Health check, Last health check | The last monthly [health check](health-check.md) |
| `business-review` | Business review, Last business review, QBR, Last QBR | The last [quarterly business review](qbr-template.md) |
| `restore-drill` | Restore drill, Last restore drill, Last drill | The last restore drill on their deployment |
| `severity-1` | Severity 1, Last Severity 1, Sev 1, Last major incident | The day of the customer's last Severity 1 |
| `incident-review` | Incident review, Last incident review, Review shared | The day its [review](incident-review.md) was last walked through with them |
| `renewal` | Renewal, Renewal date, Renews, Contract end | The next renewal |

Every other column (contacts, emails, phone numbers, revenue, notes) is never read. A row with no customer, or a date it can't read, is skipped and named by its line.

## What it flags

Each account is at one stage: **signed** (no kickoff or check-in yet), **onboarding** (kicked off, or with a check-in, and not live) or **live**. Each promise for its stage that is overdue, or due within `--warn-days`, is listed with when it was due, why, and what to do, the account with the oldest overdue promise first:

| Item | Stage | Due |
|---|---|---|
| `incident_review` | Any | 5 business days after a Severity 1, unless its review was walked through on or after that day |
| `kickoff` | Signed | 5 business days after signing; with no signing date either, now |
| `check_in` | Onboarding | 7 days after the last check-in, or the kickoff if there's none since |
| `check_in` | Live | 7 days after go-live, while no check-in since go-live is recorded; judged in the first 31 days after go-live, when the monthly health check takes over |
| `health_check` | Live | 31 days after the last health check, or go-live if there's none since; with neither, now |
| `business_review` | Live | By the end of the calendar quarter after the last review's (or go-live's); with neither, now |
| `restore_drill` | Live | 183 days after the last drill, or go-live; with neither, now |
| `renewal` | Any | Due soon from `--renewal-days` before; overdue once the date in the record has passed, until it's renewed or corrected |

A month is 31 days, as the [TAM handover](tam.md#draft-it-first) counts the next health check, and the quarterly review is due by the end of the quarter after the last one, as it counts the next review. The output ends with each TAM's accounts, overdue and due-soon promises, the busiest first, and accounts with no TAM always last (`botctl support-readiness --tams` checks that every account has one, [support readiness](readiness.md#the-tam-list)).

## What it doesn't know

- **What happened that the CRM doesn't hold.** It judges the record. A health check held but not recorded is overdue until it is; the fix is the record.
- **What a customer agreed.** A customer who asked for business reviews twice a year, or no restore drill, still shows them as due; leave them out with `--customer` when reviewing that customer, or record the agreed date.
- **The weekly check-ins' content, and the week-1 check-in's.** It knows a check-in was held, not what was covered; the [onboarding check](onboarding-check.md) on the customer's server says what's still open.
- **Ticket and incident detail.** A Severity 1 date comes from the record, not the ticket system; [escalation check](escalation-check.md) covers the tickets themselves.

It reads customer names, TAM names and dates. The output names customers and TAMs, which is the Provider's own list, so keep it where the Provider's CRM is kept ([records](tam.md#records)). Names from the export are put on one line, and shown as code in Markdown, so they can't add a link (a bare URL included), emphasis or a cell.

## Where it fits

1. **Each morning, from the Provider's own job**: export the accounts from the CRM, run `botctl tam-cadence`, and on exit 1 post the output to the TAMs' channel. The export and the posting are the Provider's job, never `botctl`'s.
2. **In each TAM's one-to-one** with the support manager, with `--tam` and `--markdown`.
3. **Each month, with [support readiness](readiness.md#when-to-run-it)**: readiness checks every account has a TAM and a backup; this checks they're getting the cadence.
4. **Before a handover**, with `--customer`, so the new TAM starts from what's already due ([handover](tam.md#handover)).
