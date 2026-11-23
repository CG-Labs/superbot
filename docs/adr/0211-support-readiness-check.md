# 0211: Support readiness: contacts, the on-call rota and the TAM list, checked offline

## Status

Accepted (23 Nov 2026). Seventh slice of enterprise support playbooks in M5, [#60](https://github.com/CG-Labs/superbot/issues/60), after the support bundle ([ADR 0131](0131-support-bundle.md)), the TAM programme and health score ([ADR 0144](0144-tam-programme-and-health-score.md)), the score's history ([ADR 0157](0157-health-score-history-and-console.md)), the support report ([ADR 0167](0167-support-report-from-ticket-exports.md)), the offline support check ([ADR 0187](0187-offline-support-check-and-bundle.md)) and incident review drafts ([ADR 0201](0201-incident-review-drafts.md)).

Numbering: this number was reserved for this work.

## Context

What #60 had left was "the Provider's real contacts, TAMs and on-call rota". Those are the Provider's people, not SuperBot's, and this repository is public: they can't be filled in here. But the playbooks lean on them everywhere. [Tiers](../support/tiers.md) sell Severity 1 response around the clock on Pro, Max and Enterprise; the index says to staff an on-call rota before selling that, and that response targets are a promise only once the rota exists; [the TAM programme](../support/tam.md) promises every Enterprise customer a TAM and a backup, each TAM with few enough accounts to keep the cadence; and seventeen placeholders (`<support-email>`, `<on-call-pager>` and the rest) wait for the Provider's own details. Nothing told a Provider whether it had done any of this. A forgotten placeholder, a weekend with nobody on the pager or a customer whose TAM left shows up only when a customer is let down, and the support report ([ADR 0167](0167-support-report-from-ticket-exports.md)) sees it a month later as a missed target.

The facts are all in the Provider's own tools: its copy of the playbooks, its paging tool's rota and its CRM's account list. Each can be exported, as the ticket system's can.

Constraints: Rust first, no new dependencies; nothing of the Provider's people in this repository; no paging tool or CRM API (each has its own, and credentials for them don't belong in `botctl`); and no change to botd, RBAC, SAML, the audit log or air-gapped installs, which other M5 tracks are changing at the same time.

## Decision

### One offline command, three optional checks

`botctl support-readiness` (`server/src/support_readiness.rs`, compiled into `botctl` beside `support_report.rs`, whose calendar, CSV reader, time parsing and plans it reuses) runs without botd and checks whatever it's given: `--docs <dir>`, `--rota <csv>` and `--tams <csv>`, at least one. Each finding is a failure (a promise that can't be kept as things stand) or a warning (a risk). It prints a verdict first (ready, ready with warnings, not ready), then each check's findings and a table, as text, Markdown or JSON, and exits 1 on any failure, so it can gate a launch or run from cron like `botd support check`.

### Contacts: the placeholders left

With `--docs`, every Markdown file under the folder is searched for the Provider's placeholders, a fixed list in the code of the seventeen the playbooks use for the Provider's own contacts, hours and limits; each one still there is a failure with its files and lines. The TAM's name and email and the backup TAM's name are per customer, so they stay placeholders in the playbooks and are checked through the TAM list instead. A test keeps the list and the playbooks in step both ways: every one is used in `docs/support`, and every placeholder in the contact pages (index, tiers, severity, escalation, TAM programme, the Severity 1 runbook) is on one list or the other. The readiness page names them without angle brackets, so it doesn't count against itself.

### The rota: gaps against what's sold

With `--rota`, a CSV of shifts (person, start, end and an optional role, found by header like the support report's columns, or named with `--column`) is checked from `--from` to `--to`, the four weeks from now by default. The hours that need a primary come from the plans given with `--plan` (every plan by default): around the clock if any of them sells Severity 1 response outside business hours, as tiers.md's table says for Pro, Max and Enterprise (a unit test reads that column), otherwise business hours, with the support report's `--hours`, `--weekdays`, `--utc-offset` and `--holidays`. Then:

- each stretch of those hours with no primary is a failure;
- each with a primary but no secondary who isn't also that primary is a warning;
- one person's primary shifts joined end to end for longer than `--max-stretch` (168 hours by default) is a warning;
- and each person's hours as primary, as secondary and outside business hours are listed, not judged.

Roles read as paging tools export them: primary, secondary or backup, or an escalation level (1, 2, L1, Level 2). Later levels are counted but aren't cover, since they're the escalation after the on-call engineer. A role it doesn't know skips the row, named by its line, rather than guessing whether it's cover.

### The TAM list

With `--tams`, a CSV of customers with their TAM and backup TAM: a customer without a TAM, or without a backup who isn't the TAM, is a failure; so is a TAM over `--max-accounts`. That number is the Provider's (tam.md's `<tam-accounts-per-person>`), so without the option accounts are listed but not judged. A customer listed twice is a warning.

### Only the columns it needs

Like the support report, it reads only the fields above: emails, phone numbers and every other column of the exports are left alone, and a skipped row is named by its line, not its contents. People's and customers' names are in the output, since they're what needs fixing; the page says to keep it where the rota and CRM are.

## Alternatives

- **Fill the contacts in here, or in a config file botd serves.** This repository is public and every Provider's contacts differ. A settings file for botd would be one more place for the same details, and the playbooks are where support reads them; checking the Provider's copy of the playbooks is enough.
- **A paging tool or CRM integration.** Each has its own API and credentials, and a Provider may run none of them (a spreadsheet is a rota). An export works with all of them and keeps `botctl` free of their credentials.
- **Put it in botd, under `/api/support`.** botd knows nothing about the Provider's staff, and the checks need none of botd's data; an offline command also runs before botd is installed, which is when a Provider is getting ready to sell.
- **A separate command per check.** Readiness is one question asked before selling and each month, with the same period and calendar options; one command with optional inputs keeps one verdict and one exit code.
- **Judge load and fairness.** What's fair depends on pay, time off in lieu and team size; the hours are listed so the support manager can judge.
- **A warning for a weekly primary shift.** Many rotas are a week as primary, then a week as secondary; counting secondary time towards a stretch flagged every such rota, so only primary time counts, and the default allows a week.

## Tests

`support_readiness`'s unit tests: which plans sell Severity 1 outside business hours, against tiers.md's column; options and the period (local midnights, the last day included, `--as-of`, at most 366 days, and only one input on stdin), and bad ones refused; roles as paging tools write them; a rota with a gap, a secondary who is also the primary and a stretch with no secondary, the same person by name in different case, later levels read but not cover, skipped rows by line with their reasons, each person's hours and those outside business hours, and no email, phone number or level 3 person in any output; business-hours-only coverage for Starter and self-host, holidays and all weekdays, and round the clock once Max is sold; business hours at a negative UTC offset; a long primary stretch across the period's start flagged once, not after `--max-stretch` is raised, and not for a week as primary then a week as secondary; an empty rota as one gap; columns found or named; a TAM list with no TAM, no backup, the TAM as their own backup, a duplicate, a skipped row and a TAM over `--max-accounts`, and not judged without it; placeholders found with their lines and per-customer ones not; and every Provider placeholder used in the shipped playbooks. `botctl`'s test reads a docs folder with subfolders, a TAM list file and a rota on stdin, and returns the report as an error (exit 1) when there's a gap or a placeholder. `tests/support_docs.rs` checks the readiness page explains every option and field, the placeholder lists match the playbooks' contact pages, and the index, TAM programme, escalation and support report point at it.
