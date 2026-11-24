# 0252: The monthly health check, judged from botd's records

## Status

Accepted (24 Nov 2026). Eleventh slice of enterprise support playbooks in M5, [#60](https://github.com/CG-Labs/superbot/issues/60), after the onboarding check in the console and the bundle ([ADR 0243](0243-onboarding-check-in-the-console-and-the-bundle.md)).

Numbering: this number was reserved for this work.

## Context

Every Enterprise customer gets a monthly [health check](../support/health-check.md) from their technical account manager ([ADR 0144](0144-tam-programme-and-health-score.md)): 22 checklist items, meant to take an hour. Before this, the TAM got there by hand: the health score and its history, then `botctl setup`, `botctl incidents`, `botctl sso saml <provider>` for each provider, `botctl scim tokens`, `botctl roles`, `botctl backups`, `botctl machine recovery`, `botctl regions`, `botctl machine egress`, `botctl usage` and `botctl license`, each read and judged against the checklist. That's about fifteen commands a customer a month, on a self-hosted server often run by the customer's admin, who then has to share every output.

botd already holds the answer to most of them. The go-live checklist had the same problem, and the onboarding check ([ADR 0233](0233-onboarding-check.md)) solved it by judging each item from botd's records, with a test holding the items to the checklist. The monthly checklist was the remaining one done by hand.

Constraints as in ADR 0233: Rust first, no new dependencies, codes and counts only, and no change to RBAC, the audit format, the support bundle, vaults or air-gapped installs, which other M5 tracks are changing.

## Decision

### One item per checklist line, judged from what botd holds

`health_check.rs` judges each of the 22 lines of `docs/support/health-check.md`, in order, as `done`, `open`, `confirm` or `n/a`. A test reads the page and holds each item to its line, its section and a guide that exists, as the onboarding check does.

- **From the health score** (ADR 0144), for the last 30 days: the score and band, signals at watch or at risk, and the `identity`, `runs` and `approvals` signals, each open at watch or at risk. The license item reads the score's license facts with the checklist's own threshold: a renewal within 90 days is open, not the score's 30.
- **From its history** (ADR 0157), for the last 31 days: open when a signal got worse.
- **From botd's records:** setup items not done; status page incidents still open, and ones of `major` or `critical` impact with no review drafted (`status.incident_reviewed`, ADR 0201); native SAML certificates ending within 60 days with no newer one of the same kind in use (the checklist's 60, not the expiry warnings' 30, ADR 0198); SCIM tokens and failed requests, or, with the Google Workspace sync (ADR 0162), whose tenant takes no token, its audited passes (`scim.google_sync`): open when the latest failed or none succeeded in 30 days; custom roles and who holds them; the newest `access_review.completed`; server backups against their RPO; machines past their RPO, restores past their RTO and failed machine backups; residency warnings; refusals for a pending egress policy and runs held to run limits; and runs refused at a plan's limit.

**Open means the TAM acts on it this month**, which is why the score at watch is open: the checklist puts every signal at watch on the next check-in's agenda. What botd can't see stays `confirm`, with what botd does see beside it: the version (botd can't see newer releases, connected or air-gapped), the IdP's provisioning log, whether custom roles are still needed, the next drill's booking, the agreed egress policy, the tickets and changes at the customer. An access review is `confirm`, not open, when none is recent, since only some customers' policies ask for one each quarter.

There are no skips. The onboarding check has them because a customer may not need an item at all; here, what doesn't apply to a server (no SAML, no machines, no regions, SCIM off, testing mode) is already `n/a` from botd's own settings.

### Where it's served

`GET /api/support/health-check` (admins: the route isn't in RBAC's table, so no custom role reaches it, as with the onboarding check), `botctl health-check` as text, a Markdown checklist for the customer's record, or JSON, exiting 1 while anything is open so a monthly job can raise a task, and a **Run health check** button in the console's Support tab, which runs only when pressed. It takes no parameters: the checklist's windows are fixed, and an unknown one is refused without echoing anything that isn't an id.

Each check is recorded as `support.health_checked`, with the score, band, counts and open ids, so a TAM's monthly checks show in the audit log, as onboarding checks do. Details are codes, counts, provider ids and incident ids: never a name, an email, an incident's title, an address or a bucket.

## Alternatives

- **A Markdown-only checklist, as before.** It stays the source of the items, but a TAM spends the hour collecting outputs instead of acting on them, and a customer's admin has to send fifteen of them.
- **Put it in the support bundle.** The bundle already carries the health score, its history and the onboarding check; the rest of this check is the TAM's monthly question, not an incident's, and adding it would change the bundle's format while other work reads it. It can be added later as its own file if support asks.
- **Use the health score's thresholds throughout** (the license and SAML certificates at 30 days). The checklist asks for more notice because a renewal or a certificate rotation at a customer takes weeks; the check follows the checklist, and the score is unchanged.
- **Audit nothing, as the health score does.** The score loads with the console's Support tab, so auditing it would fill the log. The health check runs on request, once a month, and the record of it is the evidence the cadence is kept.

## Tests

`health_check`'s unit tests: a healthy customer has nothing open and eight items to confirm; a new server shows the score and backups open and the rest not applicable; the score, its band and trend; open and unreviewed incidents; SAML certificates ending with and without a replacement; SCIM by tokens and failures, and the Google Workspace sync standing in for a token; signals at watch or at risk; backups and machines; people at a limit and the license; the score's report and history read into inputs; the view and audit details; each item a line of the checklist with a guide that exists; and no `@`, `s3://` or URL in any detail. `health_check_http_tests`: admins only (members, read-only, a custom role with every delegable permission and Bots refused), every item in order, each check audited with the view's counts and open ids, parameters refused and not recorded, and on a real server an open major incident without a review, refusals at a plan's limit and an access review followed through to a drafted review and a resolved incident, with no name, email or incident title in the reply. `sso_saml_sp_http_tests`: an IdP certificate ending in 45 days, before botd's own warnings start, is open, and done once the IdP's metadata lists a newer one. `scim_google_http_tests`: a Google-only deployment is open before its first pass, `confirm` once a pass succeeds with no SCIM token, and open again when the latest pass fails. `botctl`'s tests: the options, the text report and the Markdown checklist with botd's text escaped. `interface_http_tests`: the console calls the route only from its button, not when the Support tab loads. `tests/support_docs.rs`: the health check page explains every item in order, each status and option, the route, the audit action and the console, and the index and the TAM page point at the command.
