# 0271: The monthly health check in the support bundle

## Status

Accepted (25 Nov 2026). Thirteenth slice of enterprise support playbooks in M5, [#60](https://github.com/CG-Labs/superbot/issues/60), after the quarterly business review draft ([ADR 0262](0262-business-review-draft.md)). Adds to the support bundle ([ADR 0131](0131-support-bundle.md)) and its triage ([ADR 0220](0220-support-bundle-triage.md)) what the monthly health check ([ADR 0252](0252-monthly-health-check.md)) left out of them.

Numbering: this number was reserved for this work.

## Context

The monthly health check judges the TAM's 22 checklist items from botd's records, as `botctl health-check` and `GET /api/support/health-check`. ADR 0252 kept it out of the support bundle while other work was reading the bundle's format. The roadmap left it as a follow-up.

The bundle is the one thing support always has from a customer, and triage is how support reads it. Before this change, triage read the score's signals, the setup checklist and the onboarding check ([ADR 0243](0243-onboarding-check-in-the-console-and-the-bundle.md)). It couldn't see what only the health check reads: a native SAML certificate ending with nothing to replace it, a SCIM tenant whose tokens have all expired, a major incident with no review, approvals turned off, server backups that never leave the host, residency warnings, runs refused at a plan's limit, a license due for renewal. Several of these are the cause of a ticket before anyone knows it, and the certificate one becomes a sign-in outage on a known date. To see any of them, support had to ask the customer's admin to run `botctl health-check` as well and send its output.

Constraints as before: Rust first, no new dependencies, codes and counts only. No change to RBAC, the audit format, SAML, vaults, SOC 2 evidence or the audit export, which other M5 tracks are changing.

## Decision

### The bundle carries `health-check.json`

`botctl support-bundle` (`GET /api/support/bundle`) adds `health-check.json`, after `onboarding.json`. It holds the same view `GET /api/support/health-check` returns, judged in the same blocking task as the rest of the bundle by the same `health_check::gather` and `check`. `support::Checks::judge` makes both check views for a bundle, so the route and the tests build them the same way. The file goes through the bundle's redaction like every other one, though the view already holds only codes, counts, provider ids and incident ids.

A bundle's health check isn't recorded as `support.health_checked`. That action is the TAM's monthly cadence: the health check's own `incidents` item and the business review's health checks per month (ADR 0262) count it. A customer's admin making a bundle for a ticket isn't a TAM's check, and counting it would make a month look covered when it wasn't. The bundle's `support.bundle_created` already lists the files it holds, as with onboarding.

The bundle format goes from 3 to 4. An older `botctl support-triage` then says a newer botd made the bundle and some files are left out. A newer one expects `health-check.json` only from format 4, so a format-3 bundle isn't reported as having had a file taken out.

### Triage: open items for the TAM, and a warning for an ending certificate

`botctl support-triage` reads `health-check.json` and adds:

- **`health_check.open`**, at info with no severity, when any item is open. It lists each open item by label and id, except the four that only restate what triage already reads elsewhere: `score`, `sign_in` and `runs` come from the score's signals, and `setup` from health.json's setup checklist. The finding points at the health check page and at each listed item's guide. An open health check item is something for the TAM to raise, not an incident. Where one causes an incident, the status, score, audit and log rules already set the severity from what is actually failing, as ADR 0243 decided for onboarding.
- **`health_check.saml`**, a warning with no severity, when the `saml` item is open, meaning a native SAML certificate in use ends within 60 days and no newer one of the same kind is in use. It carries the item's detail (which provider, which certificate, how many days) and points at the SAML runbook's first steps. This is the one item that turns into an outage on a date botd already knows: when the certificate ends, sign-in through that provider stops. It still has no severity, because it hasn't ended yet. If sign-in is already failing, the identity signal and the audit rules set the severity.

The bundle is untrusted input. Ids are taken only if they look like ids, and labels and details go through triage's usual cleaning. The guides come from a table in `support_triage.rs`, never from the bundle, so a crafted bundle can't name a page. `botctl` compiles `support_triage.rs` without botd's `health_check.rs`, so it can't read `health_check::ITEMS` directly. Instead, a botd-side test holds the table equal to every item's guide that is a playbook page. An id from a newer botd is listed with no guide.

### The business review stays out of the bundle

The quarterly business review draft (ADR 0262) isn't added. It covers three calendar months, a ticket's bundle covers the last 7 days of audit summary and the score's history, and nothing in the review changes how a ticket is triaged. Its route also refuses to draft at all when botd can't read the incidents or the score's history. In a bundle, that would leave either a missing file or one that says less than the route. The TAM gets the draft from `botctl business-review` or the console's link, once a quarter, as before.

## Alternatives

- **Keep the health check out of the bundle** (ADR 0252). Support keeps asking for `botctl health-check` separately, and the items behind early warnings (an ending certificate, lapsed SCIM tokens, approvals off) stay out of the one file support always has.
- **Record a bundle's check as `support.health_checked`.** It's one event fewer to explain, but every ticket's bundle would count as a monthly check in the health check's own cadence and in the business review's count. That count is meant to show the TAM's checks.
- **Give open items a severity.** Severity sizes a ticket's response. Nearly every server has some open item (server backups on the host, a renewal coming), so every bundle would suggest a severity and hide the absence of a real problem, as ADR 0243 found for onboarding.
- **Severity 2 for an ending SAML certificate.** Severity 2 is for something failing now (severity.md). A certificate ending in 50 days fails nothing yet. If it has ended, sign-in failures show in the score and the audit log, and those rules set the severity from what really happens.
- **List every open item, including the score's.** It's simpler, but the score's signals and the setup checklist would show twice in one triage, once with their evidence and once as a checklist line.
- **Take guides from the bundle.** It's shorter, but a crafted bundle could then put any path or link in the triage, and in the Markdown note pasted into a ticket.

## Tests

`support_triage`'s unit tests: open items listed by label and id; `score`, `setup`, `sign_in` and `runs` left out; bad ids left out and an unknown id kept with no guide; guides from the table, not the bundle; the SAML item as its own warning with its cleaned detail and no severity; no finding when only items shown elsewhere are open; `health-check.json` expected only from format 4, with format 3 still asking only for onboarding; and the newer-format note at format 5. `support_triage_tests`: the online bundle botd really makes, with both checks judged on a real app, triaged: `health_check.open` at info with no severity, naming the unreviewed critical incident and server backups with their guides, and no SAML warning without a native SAML provider; and triage's guide table equal to `health_check::ITEMS`. `support_http_tests`: the bundle's files in order with `health-check.json`, its format, window and every item in order, not clear on a test server with server backups open, judged from the same score as `health-score.json`; and one `support.bundle_created` with no `support.health_checked` beside it. `tests/support_docs.rs`: the support bundle page and the bundle's README list every file, the triage page explains both new findings, and the health check page has a section on the bundle.
