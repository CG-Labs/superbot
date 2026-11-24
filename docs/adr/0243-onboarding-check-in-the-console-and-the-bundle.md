# 0243: The onboarding check in the console and the support bundle

## Status

Accepted (24 Nov 2026). Tenth slice of enterprise support playbooks in M5, [#60](https://github.com/CG-Labs/superbot/issues/60), after the onboarding check ([ADR 0233](0233-onboarding-check.md)). Amends ADR 0233's choice to keep the check out of the support bundle.

Numbering: this number was reserved for this work.

## Context

The onboarding check ([ADR 0233](0233-onboarding-check.md)) judges the onboarding checklist's 32 items from botd's records, as `botctl onboarding` and `GET /api/support/onboarding`. Two gaps were left as follow-ups:

- **The console.** A customer's admin works in the console, and its Support tab already shows the health score and makes the support bundle ([ADR 0157](0157-health-score-history-and-console.md)). To see where onboarding stands they had to use `botctl` on the server.
- **The support bundle.** ADR 0233 kept the check out of the bundle because triage ([ADR 0220](0220-support-bundle-triage.md)) reads the bundle's file list, and onboarding is a TAM's question, not an incident's. But the bundle is what support gets from a customer, and many tickets in the first months are onboarding gaps showing up as faults: break-glass still on, Bots running as botd's own account, backups never copied off the host. Support had no way to see that without asking for a second command.

Constraints as in ADR 0233: Rust first, no new dependencies, codes and counts only, and no change to RBAC, the audit format, vaults or air-gapped installs, which other M5 tracks are changing.

## Decision

### The bundle carries `onboarding.json`, with no skips

`botctl support-bundle` (`GET /api/support/bundle`) adds `onboarding.json`: the same view `GET /api/support/onboarding` returns, judged in the same blocking task as the rest of the bundle, with no skips. Skips are agreed at kickoff and never stored (ADR 0233), so the bundle can't know them; triage says so. The file goes through the bundle's redaction like every other one, though the view already holds only codes, counts and provider ids.

The check isn't recorded as its own `support.onboarding_checked`: the bundle's `support.bundle_created` already lists the files it holds, and one action recording two events would double-count a TAM's checks. The check runs before the bundle is recorded, so on the first bundle `first_bundle` is open, which is true at the moment it was judged.

The bundle format goes from 2 to 3, so an older `botctl support-triage` says a newer botd made the bundle and some files are left out.

### Triage lists open items for the TAM, with no severity

`botctl support-triage` reads `onboarding.json` and, when any item is open, adds one `onboarding.open` finding, at info level with no severity, listing each open item's label and id, pointing at the onboarding check's page. An open onboarding item is a gap to raise, not an incident; where it causes one, the health, score, audit and log rules already set the severity from what's actually failing. `first_bundle` is left out, since the bundle in hand is one. Ids are taken only if they look like ids and labels go through triage's usual cleaning, since the bundle is untrusted.

Triage expects `onboarding.json` only in bundles of format 3 or newer, so a format-2 bundle from an older botd isn't reported as having a file taken out.

### The console checks on request

The Support tab gets an **Onboarding** section: a field for skips and a **Check onboarding** button. The result shows the counts, whether anything is open, and each item by section with its status, what botd saw and its guide (shown as a repository path, not a link, so an air-gapped console doesn't point outside). It calls the same route, so it's admins only and audited as before.

It checks only when the button is pressed, not when the tab opens. Each check is audited so a TAM's checks show in the log (ADR 0233); checking on every visit would fill the audit log with checks nobody asked for. The health score, which isn't audited, still loads with the tab.

The Markdown checklist stays `botctl onboarding markdown`'s. Moving its rendering into botd for a console download would change `botctl`'s and the API's shape for a copy-and-paste the CLI already does.

## Alternatives

- **Keep the check out of the bundle** (ADR 0233). Support would keep asking for `botctl onboarding` separately, and the onboarding gaps behind early tickets would stay invisible in the one file support always has.
- **Put the skips in the bundle by passing them to `botctl support-bundle`.** Customers make bundles for tickets, not the TAM, and wouldn't know the skips; a skip typed there would also need explaining in the ticket. The onboarding record is where skips live.
- **Give open onboarding items a severity (4).** Severity sizes a ticket's response. Every new customer has open items, so every bundle from one would suggest a Severity 4 and hide the absence of a real problem.
- **Run the check when the Support tab opens.** Simpler, but every visit would be an audited check, which makes the audit trail of onboarding checks meaningless.

## Tests

`support_http_tests`: the bundle's file list, in order, with `onboarding.json`; its format, every checklist item in order, no skips, not ready on a test server, and `first_bundle` open since this bundle wasn't recorded yet; and no `support.onboarding_checked` beside the bundle's event. `support_triage_tests`: the online bundle botd really makes, with the onboarding view gathered from a real app, triaged: `onboarding.open` at info with no severity, naming the identity provider and server backups items and not `first_bundle`. `support_triage`'s unit tests: open items listed by label and id, others and bad ids left out, control characters cleaned, no finding when only `first_bundle` is open, `onboarding.json` missing only from a format-3 bundle, and the newer-format note at format 4. `interface_http_tests`: the console calls the route only from the Onboarding form, not when the Support tab loads, with the typed skips. `tests/support_docs.rs`: the support bundle page lists every file `support::build` writes, and the onboarding check page covers the console and the bundle.
