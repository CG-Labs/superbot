# Support readiness

Whether the Provider can keep what these playbooks promise ([ADR 0211](../adr/0211-support-readiness-check.md)): its own contacts filled in, an on-call rota that covers the hours its plans sell Severity 1 response in, and a TAM and a different backup TAM for every Enterprise customer, none of them over the accounts a TAM covers. [Response targets](severity.md#targets-not-resolution-times) are a promise only once these exist.

`botctl support-readiness` checks them. It runs anywhere `botctl` does, needs no botd and no sign-in, and reaches no paging tool or CRM: the support manager exports the rota and the TAM list, runs it, and fixes what it reports. It exits 1 when any check fails, so it can gate a launch or run from cron.

## Running it

```sh
# Everything, for the next four weeks
botctl support-readiness --docs ./support --rota rota.csv --tams tams.csv --max-accounts 8

# The rota for December, in the support timezone, with the plans actually sold
botctl support-readiness --rota rota.csv --from 2026-12-01 --to 2026-12-31 \
  --utc-offset +01:00 --holidays 2026-12-25,2026-12-26 --plan starter --plan pro

# From a paging tool's export on stdin, as Markdown for the support manager
some-export-command | botctl support-readiness --rota - --markdown > rota-check.md
```

Give at least one of `--docs`, `--rota` and `--tams`; only the checks given run.

| Option | What it does |
|---|---|
| `--docs <dir>` | The Provider's copy of these playbooks: every Markdown file under it, in any folders, is checked for [contact placeholders](#the-contacts) still left |
| `--rota <file>` | The [on-call rota](#the-on-call-rota) as CSV, `-` for stdin |
| `--tams <file>` | The [TAM list](#the-tam-list) as CSV, `-` for stdin (only one of the two can be) |
| `--plan <plan>` | A plan the Provider sells: `self-host`, `starter`, `pro`, `max` or `enterprise`. Repeatable. Every plan by default. Decides the hours the rota must cover |
| `--from <YYYY-MM-DD>`, `--to <YYYY-MM-DD>` | The days to check the rota over, both included, at most 366, from midnight at `--utc-offset`. The four weeks from now by default |
| `--hours <HH:MM-HH:MM>` | Business hours, `09:00-17:30` by default, as in [tiers](tiers.md#per-plan) |
| `--weekdays <days>` | Business days, `mon-fri` by default; also lists like `mon,wed,fri` or `all` |
| `--utc-offset <+HH:MM>` | The support timezone's offset from UTC, `+00:00` by default; times in the rota without an offset are read at it |
| `--holidays <dates>` | The Provider's public holidays, `YYYY-MM-DD` separated by commas; repeatable |
| `--max-stretch <hours>` | Warn when one person is primary for longer than this without a break, 168 (a week) by default |
| `--max-accounts <n>` | The accounts a TAM covers at most, the number [tam.md](tam.md#who-gets-one) promises. Without it, accounts per TAM are listed but not judged |
| `--column <field>=<header>` | Which column holds a field, when the export's header isn't one it knows. Repeatable |
| `--as-of <time>` | When "now" is, for the default four weeks and the report's date |
| `--markdown`, `--json` | Markdown to share, or JSON. Plain text by default |

Each finding is a failure or a warning. Failures are promises that can't be kept as things stand; warnings are risks to look at. The report starts with the verdict: ready, ready with warnings, or not ready.

## The contacts

These playbooks ship with placeholders where the Provider's own details go. Every one of these, still in angle brackets anywhere in `--docs`, is a failure, with the files and lines it's on: support-email, support-portal-url, security-email, status-page-url, support-hours, support-timezone, support-languages, self-host-contacts, supported-releases, on-call-pager, on-call-line, incident-channel, engineering-escalation, support-manager, engineering-manager, escalation-email and tam-accounts-per-person.

The TAM's name and email and the backup TAM's name differ per customer, so they stay placeholders in the playbooks and aren't failures; the [TAM list](#the-tam-list) is checked instead. Fill in the rest in the Provider's copy of this folder (its wiki, its own repository, its help centre), not in SuperBot's public repository, and point `--docs` at that copy.

## The on-call rota

The rota is the on-call engineer's ([escalation](escalation.md#inside-the-provider) level 2): who the pager reaches, when. Export it from the paging tool (PagerDuty, Opsgenie, Grafana OnCall and most others export shifts as CSV) or keep it in a spreadsheet, one row per shift. `botctl support-readiness` finds these columns by their header, ignoring case and punctuation:

| Field | Headers it knows | Needed |
|---|---|---|
| `person` | Person, Name, User, User name, Engineer, Responder, On call, Member | Yes |
| `start` | Start, Starts, Start time, Start at, Start date, From, Shift start, On call start | Yes |
| `end` | End, Ends, End time, End at, End date, Until, To, Shift end, On call end | Yes |
| `role` | Role, Level, Escalation level, Layer, Position, Rota role | No: without it every shift is primary |

A role is primary (`primary`, `1`, `Level 1`, `L1`) or secondary (`secondary`, `backup`, `2`). Later escalation levels (`3`, `manager`) are read and counted, but aren't cover: they're the [escalation](escalation.md) after the on-call engineer. People are matched by name, ignoring case and punctuation. Times are RFC 3339 or a date and time, as in the [support report](support-report.md#the-export). A row it can't read (no person, a time it can't read, an end not after its start, a role it doesn't know) is skipped and named by its line, as a warning.

What it checks, from `--from` to `--to`:

- **A primary at all times the plans need one** (a failure for each gap). If any plan given with `--plan` sells Severity 1 response outside business hours (Pro, Max and Enterprise, from the [tiers](tiers.md#per-plan) table), that's around the clock; otherwise only business hours, `--hours` on `--weekdays` except `--holidays`. Every plan by default, so around the clock.
- **A backup whenever there's a primary** (a warning for each stretch without one): a secondary who isn't also the primary at the time. A pager that reaches one person has nobody to escalate to when they don't answer.
- **No one primary for too long** (a warning): one person's primary shifts joined end to end for longer than `--max-stretch`. Time as secondary doesn't count towards it.
- **Load**: each person's hours as primary and as secondary in the period, and how many of them were outside business hours, for fairness. It isn't judged.

## The TAM list

One row per Enterprise customer, exported from the CRM or support system where the [TAM programme](tam.md#records) keeps who covers whom:

| Field | Headers it knows | Needed |
|---|---|---|
| `customer` | Customer, Organization, Organisation, Org, Account, Company | Yes |
| `tam` | TAM, TAM name, Technical account manager, Account manager, Named TAM | Yes |
| `backup` | Backup, Backup TAM, Backup TAM name, Deputy, Cover, Secondary TAM | Yes |

What it checks:

- **Every customer has a TAM** (a failure for each that doesn't).
- **Every customer has a backup TAM who isn't the TAM** (a failure for each that doesn't).
- **No TAM over `--max-accounts`** (a failure for each who is).
- **Each customer once** (a warning for a customer listed twice, ignoring case and punctuation: which TAM is it?). A row with no customer is skipped and named by its line, as a warning.

Each person's accounts as TAM and as backup are listed beside the findings.

## What it doesn't do

- **Read anything else.** Only the columns above: emails, phone numbers and every other column are left alone. People's and customers' names are in the output, since that's what needs fixing, so keep it where the rota and the CRM are, not in a ticket or a Bot's chat.
- **Check that contacts work.** A filled-in address can still bounce, and a pager can still be misrouted. Page the rota and write to each address when they change.
- **Know about leave.** It checks the rota as exported. Put holidays and swaps in the paging tool before exporting, and check again after changes.
- **Judge the support engineers' hours.** Level 1 works tickets in business hours; whether they answer in time is the [support report](support-report.md)'s job.
- **Talk to the paging tool, the CRM or botd.** Nothing is fetched or sent.

## When to run it

1. **Before selling a plan**, and before the first Enterprise kickoff: `--docs` on the Provider's copy, `--rota` for the next four weeks with the plans it will sell, and `--tams` with `--max-accounts`. Don't sell Severity 1 response outside business hours until the rota passes.
2. **Each month**, beside the [support report](support-report.md#each-month): the rota for the next month. A missed response target on a night or weekend often starts as a gap here.
3. **When the rota or a TAM changes**: someone leaves or joins, a swap, a customer signs or moves to another TAM ([handover](tam.md#handover)).
4. **From cron**, if the paging tool can export on a schedule: it exits 1 on a failure, so the job's own alert says the next four weeks have a gap.
