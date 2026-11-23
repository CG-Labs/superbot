# Support report

The Provider's monthly count of tickets and response targets ([ADR 0167](../adr/0167-support-report-from-ticket-exports.md)): for each month, tickets opened and closed by severity, how many got a first human answer within their plan's [response target](severity.md#response-targets), which missed it and by how much, and what was still open at the end. It is the "support report" [severity](severity.md#targets-not-resolution-times) counts misses in, and the numbers for section 4 of the [quarterly business review](qbr-template.md#4-support-and-incidents).

`botctl support-report` makes it from the ticket system's CSV export. It runs anywhere `botctl` does, needs no botd and no sign-in, and reaches no ticket system: the support manager exports, runs it, and keeps the output in the support system.

## Running it

```sh
# Last three full months, every customer, plans from the export's plan column
botctl support-report tickets.csv

# One Enterprise customer's quarter for their review, with their agreed targets, as Markdown
botctl support-report tickets.csv --customer "<customer>" --plan enterprise \
  --from 2026-07 --to 2026-09 --target 1=15m --target 2=1h --markdown > support-q3.md

# From stdin, as JSON
some-export-command | botctl support-report - --plan pro --json
```

| Option | What it does |
|---|---|
| `--plan <plan>` | The plan for tickets with no plan column or an empty one: `self-host`, `starter`, `pro`, `max` or `enterprise`. Needed unless the export has a plan column |
| `--customer <name>` | Only the tickets whose customer (organisation) column is this name, ignoring case and punctuation |
| `--from <YYYY-MM>`, `--to <YYYY-MM>` | The months to report, both included, at most 36. The last three full months by default |
| `--hours <HH:MM-HH:MM>` | Business hours, `09:00-17:30` by default; `00:00-24:00` for round the clock |
| `--weekdays <days>` | Business days, `mon-fri` by default; also lists like `mon,wed,fri` or `all` |
| `--utc-offset <+HH:MM>` | The support timezone's offset from UTC, `+00:00` by default. Fixed: run summer and winter months separately if it changes |
| `--holidays <dates>` | The Provider's public holidays, `YYYY-MM-DD` separated by commas; repeatable |
| `--target <sev>=<time>` | An agreement's response target for a severity, for every ticket in the report: `30m` or `2h` on the clock, `4bh` business hours, `1bd` business days. Repeatable |
| `--column <field>=<header>` | Which column holds a field, when the export's header isn't one it knows. Repeatable |
| `--as-of <time>` | When "still waiting" is judged, now by default; also moves the default months |
| `--markdown`, `--json` | Markdown tables to paste into a review, or JSON. Plain text by default |

Run it per customer for an Enterprise review (`--customer`, with `--target` for each target their order form changed), and across everyone for the Provider's own monthly look at whether its targets hold.

## The export

A CSV with a header row, comma, semicolon or tab separated, as Zendesk, Freshdesk, Jira Service Management, Help Scout and most other systems export. `botctl support-report` finds these columns by their header, ignoring case and punctuation:

| Field | Headers it knows | Needed |
|---|---|---|
| `id` | ID, Ticket ID, Ticket, Ticket number, Number, Key, Issue key, Case number, Case ID | Yes |
| `severity` | Severity, Sev, Priority | Yes |
| `opened` | Opened, Created, Created at, Date created, Requested, Submitted | Yes |
| `first-response` | First response, First response at, First reply at, First replied at, Responded at | Yes |
| `resolved` | Resolved, Resolved at, Solved at, Closed, Closed at, Resolution date | For closed counts and what's open |
| `plan` | Plan, Tier, Support plan | Unless `--plan` |
| `customer` | Customer, Organization, Organisation, Org, Account, Company | For `--customer` |

Severities read as `1` to `4` in any form (`Sev 2`, `S3`, `P1`, `Severity 1: Critical`), or by the priority names ticket systems use: urgent or critical is 1, high is 2, normal or medium is 3, low is 4. If your system's priorities don't line up with [severity](severity.md#severities) that way, export a severity field instead.

Times are RFC 3339 (`2026-09-01T10:00:00Z`) or a date and time (`2026-09-01 10:00`, with or without seconds or a `+0100` offset); one without an offset is read at `--utc-offset`. The first response must be the first answer from a person, not an auto-reply: most systems have a field for it ("first reply time" in Zendesk, "first responded at" in Freshdesk). Export that, not the first public comment.

A row it can't read (no id, a severity that isn't 1 to 4, a time it can't read, one before the ticket was opened, a plan that isn't SuperBot's) is skipped and named by its line number. Fix the export and run it again rather than leave rows out.

## What it reports

- **Per month and severity**: tickets opened that month, how many were answered within target (met), answered late or not answered with the target gone (missed), and closed that month (whenever they were opened), with the median time to the first answer on the clock.
- **The period**: answered within target out of all judged, as a percentage. Tickets still waiting for an answer but within target aren't judged yet; they're counted separately.
- **Missed**: each late ticket by id, with its severity and plan, when it was opened, how long the first answer took (in business time when its target is), and the target.
- **Open at the end**: tickets opened before the end of the period and not resolved by then, by severity, whenever they were opened.

A target counts the clock for targets like `1 h, 24×7`, and only business hours for business-hour and business-day targets; a business day is one day's business hours (8.5 hours by default), so a ticket at 16:00 on Friday with a one business day target is due at 16:00 on Monday. Months are UTC calendar months by when a ticket was opened.

## What it doesn't do

- **Read anything else.** Subjects, descriptions, requesters, emails and every other column are left alone; the report has ticket ids, severities, plans and times, nothing personal. Ticket ids still identify tickets, so keep the output where the tickets are.
- **Judge update targets.** An export has a ticket's first answer, not every update. Check [update targets](severity.md#updates-until-its-fixed) on Severity 1 and 2 tickets by hand in the review of each incident ([escalation](escalation.md#after-a-severity-1)).
- **Know about pauses.** Time waiting on the customer counts. Response targets end at the first answer, so this only matters when the first question went back to the customer before any answer, which is rare; note it beside the miss.
- **Talk to the ticket system or botd.** Nothing is fetched or sent. Credits under a written SLA are worked out from this report by the account owner, never by the tool.

## Each month

1. On the first business day, export last month's tickets and run `botctl support-report <export> --from <last month> --to <last month>`.
2. For each missed ticket: was it real (not a severity changed later, or an auto-reply counted as the answer)? If real, why, and is it a staffing, rota or routing problem? Note the cause in the ticket.
3. If the period's percentage for Severity 1 or 2 is below the Provider's goal, or misses cluster on nights, weekends or one queue, raise it with the support manager ([escalation](escalation.md)). Response targets are a promise only once the [on-call rota](README.md#for-the-provider) exists.
4. For each Enterprise customer with a review coming, run it for their quarter with `--customer`, their `--target`s and `--markdown`, and give it to their [TAM](tam.md).
