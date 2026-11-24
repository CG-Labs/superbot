# 0262: The quarterly business review, drafted from botd's records

## Status

Accepted (24 Nov 2026). Twelfth slice of enterprise support playbooks in M5, [#60](https://github.com/CG-Labs/superbot/issues/60), after the monthly health check ([ADR 0252](0252-monthly-health-check.md)).

Numbering: this number was reserved for this work.

## Context

Each quarter the technical account manager holds a business review with an Enterprise customer's sponsor and owner ([TAM programme](../support/tam.md#cadence), [ADR 0144](0144-tam-programme-and-health-score.md)). The [template](../support/qbr-template.md) asks for three months of health, adoption and usage, incidents, and security and data, before the goals and what's next. Until now the TAM filled it in by hand: the score for each month from three health checks' records, `botctl health-score history --days 90`, runs and failures from the score's facts, `botctl incidents` and each review, the audit log for access reviews and configuration changes, `botctl machine recovery` for restores. On a self-hosted server that is the customer's admin running a dozen commands and sending every output.

botd holds most of it already: the score it records each day (ADR 0157), each health check (`support.health_checked`, ADR 0252), runs, refusals and failures in the audit log, status page incidents with whether a review was drafted (ADR 0201), access reviews, configuration changes and machine restores. The incident commander's review had the same shape of problem, and the incident review draft (ADR 0201) solved it: botd writes the parts it saw into the document's own layout and marks the rest for people.

Constraints as before: Rust first, no new dependencies, codes and counts only, and no change to RBAC, the audit format, the support bundle, vaults or air-gapped installs, which other M5 tracks are changing.

## Decision

### A draft of the template, by calendar month

`business_review.rs` builds the template's seven sections for **three calendar months in UTC**, ending with `to=YYYY-MM`: the last whole month by default, this month at the latest, in which case its figures run to now and the draft says the quarter isn't over. A calendar quarter is named by its number (`Q3 2026 (July to September)`), any other three months by their names, so a customer whose year starts in another month gets their own quarters.

- **Each month:** the last score botd recorded in it with the signals at watch or at risk then; the month's health checks, with the last one's score and open items; runs finished and failed or timed out, runs refused at a plan's limit, monthly token limits reached and runs held to run limits; single sign-on attempts and failures, SCIM failures and approvals left to expire, read as the health score reads them (its `Inputs::add`, so the two never disagree); machine backup failures; and refusals to keep data in its region.
- **The quarter:** the score's trend from its first recorded day to its last (`health_history::trend`); runs and failures by harness, from each run's Bot, with deleted Bots together; status page incidents posted in the quarter or still open from before it, with impact, times, duration and whether a review was drafted; access reviews signed off; successful changes to native SAML, SCIM tokens, custom roles, role grants and residency pins, counted; machine restores and those past their RTO.
- **Now:** people active in the last 30 days and licensed seats, the backups signal's summary, residency warnings and when the license ends, since the template asks for those as they stand at the review.
- **Actions:** a row for each signal at watch or at risk at the quarter's end, each incident still open and each major or critical one with no review drafted.

Goals, attendees, the deployment's type, tickets, each Severity 1's cause, the last restore drill, releases that matter and the customer's plans stay **"To fill in"**, with the command that fills them where there is one: the support report (ADR 0167) for the quarter's months, `botctl usage`, `botctl incident review <id>`, `botctl audit --from --to` for the changes.

The month of each figure is the month its event was recorded in; botd has no per-month copy of anything else. When the audit log keeps less than the quarter reaches back (`AUDIT_RETENTION_DAYS`), the draft says its earliest months show fewer events than happened, as the health score does.

`Db::audit_counts_between` bounds the health score's grouped audit count by an end time, and `Db::run_results_by_bot` groups finished runs by Bot and result; both are reads.

### Where it's served

`GET /api/support/business-review[?to=YYYY-MM&format=markdown]` (admins: the route isn't in RBAC's table, so no custom role reaches it, as with the health check), as JSON or a Markdown download; `botctl business-review [--to <YYYY-MM>] [--json] [-o <file>]`, Markdown by default; and a **Draft business review** link in the console's Support tab with the month to end on, a download made only when clicked. Unknown parameters are refused without echoing anything that isn't an id.

Each draft is recorded as `support.business_review_drafted`, with its months, format, whether the quarter was over, and the counts of incidents and health checks, so the quarterly cadence shows in the audit log beside the monthly checks. The draft holds codes, counts, dates, harness names, region ids and incident ids: never a person's name or email, an incident's title, an address or a bucket, so it can go to the customer as it is.

## Alternatives

- **The last 90 days instead of calendar months.** The template's health table has a column per month, and a quarter's review is held a few days after it ends; 90 days back from the day it's drafted would split months and change with the day it's run.
- **Judge each line, as the health check does.** A review isn't a checklist: it reports what happened and agrees what's next with the customer. The draft states what botd saw and leaves the judgement to the TAM; what would be open already is in the actions table and in that month's health check.
- **Render it in `botctl`, as the health check's Markdown is.** The draft is a document the console offers as a download too, as the incident review is (ADR 0201), so botd renders it once for both.
- **Fill it from the support bundle.** A bundle covers 7 days of audit summary and the score's history; the quarter's counts by month aren't in it, and adding them would change the bundle's format while other work reads it.

## Tests

`business_review`'s unit tests: months parse, add and are named, calendar quarters by number; the query takes a month up to this one and a format, and refuses anything else without echoing it; a month's counts are read as the health score reads them (single sign-on only, unknown SCIM tokens not the customer's, residency refusals from both actions); a recorded day keeps its signals in the playbook's order; signals flagged at a month's end are listed with those months; the draft has the template's sections in order, its tables and lines, actions for an unreviewed incident and a signal at risk and none for a reviewed one; a quarter so far, an empty server and no machines or license say so; text from records can't break the Markdown or leak a link; the JSON and audit details hold months, ids and counts. `business_review_http_tests`: admins only (members, read-only, a custom role with every delegable permission and Bots refused), JSON and the Markdown download with its headers, each draft audited with its months and counts; bad parameters refused and not recorded; on a real server, runs by harness and refusals at a limit, a health check, an access review and a major incident without a review followed until it's reviewed and resolved, with no name, email or incident title in either form. `botctl`'s tests: the options. `interface_http_tests`: the console's link is a download made only when clicked, not when the Support tab loads, and the month only changes the link. `tests/support_docs.rs`: the template explains the command, each option, the route, the audit action and the console's link, says what botd fills in for each of its seven sections, and the index and the TAM page point at the command.
