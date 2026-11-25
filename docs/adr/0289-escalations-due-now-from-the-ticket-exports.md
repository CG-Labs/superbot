# 0289: Escalations due now, from the ticket exports

## Status

Accepted (25 Nov 2026). Sixteenth slice of enterprise support playbooks in M5, [#60](https://github.com/CG-Labs/superbot/issues/60), after update targets from a replies export ([ADR 0286](0286-update-targets-from-a-replies-export.md)).

Numbering: this number was reserved for this work.

## Context

[Escalation](../support/escalation.md#timed-escalation) sets timed rules: every Severity 1 to the on-call engineer at once and to management at 2 hours without a workaround; a Severity 2 to the on-call engineer after 2 hours in the runbook without progress; and a response target about to be missed raised with the support manager "before it is, not after". The support report (ADR 0167) and its update targets (ADR 0286) judge those promises a month later. Nothing helped keep them during the shift: the support engineer watched the queue and did the sums, in business hours for some plans and on the clock for others, by hand.

The support report already reads the ticket system's export of tickets and of replies, with each plan's targets, business hours, holidays and an agreement's targets. What it lacks for this is "now": it counts tickets opened in whole months, and judges what was, not what is due.

Constraints as before: Rust first, no new dependencies, nothing personal in the output, nothing that contacts a ticket system, pager, chat or anyone else, and no change to botd, RBAC, the audit format or the support bundle.

## Decision

### `botctl support-escalations`

A new offline command, `server/src/support_escalations.rs`, included into `botctl` beside the report. It takes the report's exports, columns and options (`--plan`, `--customer`, business hours, `--target`, `--column`, `--as-of`, the formats, and `--updates` with its own), plus `--warn <percent>`, and lists each open ticket that needs escalating now, the most urgent first, with who to tell, what to do and why. It exits 1 when anything does, so the Provider's own job can post or page on it every few minutes.

- **Reused readers, not copies.** The report's row reader is split out as `support_report::read_tickets` (every readable ticket, whenever opened) and the update targets' as `support_updates::read_replies`; `report` and `judge` now call them, unchanged in behaviour. So the two commands read the same exports the same way, and severity.md's targets are judged by one `Target`. The report's `--from` and `--to` are refused: there is no period.
- **Open as of `--as-of`.** Opened by then and not resolved by then. Without a resolved column every ticket is open, since a ticket system's "unresolved tickets" view usually has none, and a note says so. A first answer after `--as-of` is none yet, so a past time shows what was due then.
- **Seven codes, from escalation.md's rules.** `response.missed` and `response.at_risk` (no first answer, the target passed or `--warn` of it gone) for the support manager; `sev1.on_call` for every open Severity 1 (the on-call engineer and incident commander, and the TAM for Enterprise, as the [TAM page](../support/tam.md#what-a-tam-does) says) and `sev1.management` once it's been open 2 hours; `sev2.on_call` for a Severity 2 2 hours after its first answer; and with `--updates`, `update.overdue` and `update.due_soon` for the support engineer, judged from support's last public reply (or the first answer) against the update target. A test reads escalation.md's timed escalation and checks the 2 hours and every role named.
- **The 2 hours count as the ticket's response target does.** On the clock where the plan answers that severity round the clock, in business hours otherwise. A Starter Severity 1 raised on Saturday isn't for management until Monday's hours have run; an Enterprise one is, after 2 hours, any day. This is what "worked continuously during the plan's hours" in severity.md means for the escalation clock.
- **75% is "about to be missed".** The default warning leaves a quarter of each target: 7.5 minutes of an Enterprise Severity 1's 30, a business hour of a Pro Severity 2's 4. `--warn` changes it.
- **It lists, it doesn't remember.** A ticket stays listed while its rule holds; the export has no field for "already escalated". Workarounds and progress aren't in exports either, so those two rules say "unless", and the support engineer decides.
- **Nothing personal, nothing sent.** It reads what the report and its update targets read, never subjects, bodies, requesters or authors, and names no customer except the one asked for with `--customer`. Ticket ids are put on one line, and shown in Markdown as a code span with `|` escaped, so an id can't add a link (GitHub autolinks bare URLs even when brackets are escaped), emphasis or a cell. botctl reaches no ticket system, pager or chat: the Provider's own job exports and posts.

## Alternatives

- **An option on `botctl support-report`.** ADR 0286 kept update targets in the report because they need its tickets and period. This needs the open tickets with no period, and a different verdict (exit 1 when something is due, for a job every few minutes); one command with two meanings for its options and its exit code would be harder to run from cron.
- **Page or post from botctl.** That needs a pager's and a chat's API and credentials in a tool that otherwise reaches only botd, and one adapter per tool. A Provider's job already has those; the exit code and JSON are enough to drive it.
- **Track escalations already made.** A state file would let the list say "told at 10:15", but would be one more record of tickets outside the ticket system, out of step with it. The ticket is where who was told belongs.
- **Count the 2 hours on the clock for every plan.** escalation.md's "2 hours" read literally, but it would page management at weekends for plans whose Severity 1 is worked in business hours only.
- **Judge it in botd.** botd doesn't hold the Provider's tickets; customers' servers never see them.

## Tests

`support_escalations.rs`: the 2 hours and roles against escalation.md; an export with subjects, requesters and organisations that never reach the output, judged at a fixed time: a Starter Severity 3 past its business-day target, an Enterprise Severity 1 past 2 hours for management and its TAM, a Severity 1 with 5 minutes left, a Pro Severity 2 7 business hours in the runbook, one at exactly 75%, a resolved ticket, one opened after `--as-of` and a row skipped by line; with replies, an overdue update past an internal note and a customer's message, one nearly due in business time, a reply after `--as-of` not counted, rows for closed tickets not read, and an agreed 24×7 update target with tickets without rows named; a past `--as-of` with a later first answer; a Saturday on business-hour and agreed round-the-clock targets; ids that would break a line or a table, add a link (bracketed or a bare URL) or close their code span; the options, refused months, and errors naming this command's usage, not the report's. `botctl.rs`: both exports from a file and stdin in each format, exit status when nothing is due, and the errors for two stdins and a missing file. `tests/support_docs.rs`: the page explains every option and code, and escalation, the index and the Severity 1 runbook point at it. The support report's and update targets' own tests pass unchanged on the split-out readers.
