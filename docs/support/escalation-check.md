# Escalation check

Which open tickets must go to someone now, by [escalation](escalation.md#timed-escalation)'s timed rules ([ADR 0289](../adr/0289-escalations-due-now-from-the-ticket-exports.md)): a response target missed or about to be, every Severity 1 for the on-call engineer and the incident commander, a Severity 1 still open after 2 hours for management, a Severity 2 still in the runbook 2 hours after its first answer for the on-call engineer, and, from the replies, a customer update overdue or about to be. The [support report](support-report.md) counts these afterwards, month by month; this check is for the shift, so a target about to be missed is raised before it is, as escalation asks.

`botctl support-escalations` reads the same exports as the support report. It runs anywhere `botctl` does, needs no botd and no sign-in, and reaches no ticket system, pager or chat: it says who to tell, and tells nobody. It prints the list on stdout either way and exits 1 when anything needs escalating, so a job every few minutes can raise it in the support channel or page.

## Running it

```sh
# Now, from an export of every open ticket, plans from the export's plan column
botctl support-escalations open-tickets.csv

# With the replies on those tickets, so late updates are flagged too
botctl support-escalations open-tickets.csv --updates replies.csv

# One Enterprise customer, with their agreed targets, as Markdown for the incident channel
botctl support-escalations open-tickets.csv --customer "<customer>" --plan enterprise \
  --target 1=15m --target 2=1h --update-target 2=2h --updates replies.csv --markdown

# From stdin, warning at half a target, as JSON for a chat hook
some-export-command | botctl support-escalations - --plan pro --warn 50 --json
```

| Option | What it does |
|---|---|
| `--plan <plan>` | The plan for tickets with no plan column or an empty one: `self-host`, `starter`, `pro`, `max` or `enterprise`. Needed unless the export has a plan column |
| `--customer <name>` | Only the tickets whose customer (organisation) column is this name, ignoring case and punctuation |
| `--hours <HH:MM-HH:MM>` | Business hours, `09:00-17:30` by default; `00:00-24:00` for round the clock |
| `--weekdays <days>` | Business days, `mon-fri` by default; also lists like `mon,wed,fri` or `all` |
| `--utc-offset <+HH:MM>` | The support timezone's offset from UTC, `+00:00` by default |
| `--holidays <dates>` | The Provider's public holidays, `YYYY-MM-DD` separated by commas; repeatable |
| `--target <sev>=<time>` | An agreement's response target for a severity: `30m` or `2h` on the clock, `4bh` business hours, `1bd` business days. Repeatable |
| `--column <field>=<header>` | Which column of the tickets export holds a field, when its header isn't one the [support report knows](support-report.md#the-export). Repeatable |
| `--warn <percent>` | How much of a target may go before it's about to be missed, 75 by default, 1 to 99 |
| `--as-of <time>` | When "now" is, now by default: to see what was due at a time in the past |
| `--markdown`, `--json` | A Markdown table to paste, or JSON. Plain text by default |
| `--updates <file>` | The export of replies on the tickets, `-` for stdin (only one of the two exports can be): adds late and nearly late [updates](#updates) |
| `--update-target <sev>=<time>` | An agreement's update target for a severity, as `--target` writes times. Repeatable. Needs `--updates` |
| `--update-column <field>=<header>` | Which column of the updates export holds a field, when its header isn't one the [update targets know](support-report.md#update-targets). Repeatable. Needs `--updates` |

The tickets export is the support report's, with the same columns, severities and times ([the export](support-report.md#the-export)), but of the tickets open now rather than a month's. A ticket is open when it was opened by `--as-of` and has no resolved time, or one after it; without a resolved column, every ticket in the export is taken as open, which suits a ticket system's "unresolved tickets" view. A first answer after `--as-of` counts as none yet. A row it can't read is skipped and named by its line.

## What it flags

Each open ticket that needs something is listed, the most urgent first, with each thing it needs, who to tell (a role from [escalation](escalation.md#inside-the-provider)), what to do, and why:

| Code | When | Tell |
|---|---|---|
| `response.missed` | No first answer, and the [response target](severity.md#response-targets) has passed | The support manager; answer it now |
| `sev1.management` | A Severity 1 open 2 hours or more | Management, unless there's a workaround |
| `sev1.on_call` | Every open Severity 1, until it's resolved or drops a level | The on-call engineer and the incident commander; for Enterprise, the customer's [TAM](tam.md) too |
| `update.overdue` | With `--updates`: the last update is longer ago than the [update target](severity.md#updates-until-its-fixed) | The support engineer; update the customer now |
| `sev2.on_call` | A Severity 2 answered 2 hours or more ago and still open | The on-call engineer, unless the runbook is getting somewhere |
| `response.at_risk` | No first answer, and `--warn` of the response target has gone | The support manager, before it's missed |
| `update.due_soon` | With `--updates`: `--warn` of the update target has gone since the last update | The support engineer, before it's due |

Time counts as each target counts it. Response and update targets in hours on the clock (`1 h, 24×7`) count every minute; those in business hours or business days count only `--hours` on `--weekdays`, except `--holidays`. The 2 hours for management and for the on-call engineer count as the ticket's response target does: on the clock for a plan with round-the-clock response at that severity, in business hours otherwise. So a Starter Severity 1 raised on Saturday isn't for management until Monday, and an Enterprise one is after 2 hours whatever the day.

### Updates

With `--updates`, each open, answered ticket with an update target (Severity 1 to 3, and Severity 4 only with an agreed one) is judged from its last update: support's last public reply up to `--as-of`, or its first answer if there's none since. The replies export and what counts as an update are the support report's ([update targets](support-report.md#update-targets)): the customer's messages, internal notes and automations aren't updates. An open ticket with no rows at all is judged from its first answer and named in a note, since that usually means the replies export didn't cover it.

## What it doesn't know

- **Whether it's already been done.** A ticket stays listed while its rule holds: a Severity 1 is for the on-call engineer until it's resolved. Say in the ticket who was told and when; the list is for the shift to read, not a log.
- **Workarounds and progress.** Management needs telling about a Severity 1 after 2 hours *without a workaround*, and the on-call engineer about a Severity 2 *without progress*. Neither is in an export, so both are listed with "unless"; the support engineer decides.
- **A Severity 2 getting worse outside business hours**, which [escalation](escalation.md#timed-escalation) sends to the on-call engineer at once on plans with 24×7 Severity 1. Raise it to Severity 1 if it is.
- **Security incidents.** A suspected breach goes to `<security-email>` and the incident commander at once, whatever this says ([security incidents](escalation.md#security-incidents)).
- **Pauses.** Time waiting on the customer counts, as in the support report.

It reads ticket ids, severities, plans and times, the customer column only to pick one with `--customer`, and from the replies only ticket ids, times, visibility and author roles. Subjects, bodies, requesters, authors and emails are never read, and the output names no customer except the one asked for. Ticket ids from the export are put on one line, and shown as code in Markdown, so they can't add a link (a bare URL included), emphasis or a cell.

## Where it fits

1. **Every few minutes, from the Provider's own job**: export the open tickets (and their replies) from the ticket system, run `botctl support-escalations`, and on exit 1 post the output to the support channel, or page for a `sev1` code. The export and the posting are the Provider's job, never `botctl`'s.
2. **At each shift handover**, with `--markdown`, so the next shift starts from what's due.
3. **On a Severity 1**, the incident commander runs it with `--customer` for each affected Enterprise customer, so their TAM and their updates aren't missed ([running a Severity 1](runbook-major-incident.md)).
4. **Afterwards**, each month's [support report](support-report.md#each-month) counts what was missed anyway.
