# 0233: Onboarding check: the checklist judged from botd's own records

## Status

Accepted (24 Nov 2026). Ninth slice of enterprise support playbooks in M5, [#60](https://github.com/CG-Labs/superbot/issues/60), after the support bundle ([ADR 0131](0131-support-bundle.md)), the TAM programme and health score ([ADR 0144](0144-tam-programme-and-health-score.md)), the score's history ([ADR 0157](0157-health-score-history-and-console.md)), the support report ([ADR 0167](0167-support-report-from-ticket-exports.md)), the offline support check ([ADR 0187](0187-offline-support-check-and-bundle.md)), incident review drafts ([ADR 0201](0201-incident-review-drafts.md)), the support readiness check ([ADR 0211](0211-support-readiness-check.md)) and bundle triage ([ADR 0220](0220-support-bundle-triage.md)).

Numbering: this number was reserved for this work.

## Context

[Onboarding](../support/onboarding.md) is a 32-item checklist across six sections: kickoff, identity, isolation, backups, residency, and monitoring and go-live. The technical account manager ticks it in the customer's onboarding record, item by item, by asking the customer or reading settings off the server. Most items are things botd already knows: whether an SSO provider is ready, whether an admin has signed in with SSO, whether SCIM has deprovisioned anyone, whether break-glass is off, where Bots run, whether backups are copied off the host within their RPO and encrypted, whether residency has warnings, whether metrics are on, whether a support bundle has been made. Asking the customer for them is slow, and a box ticked from memory is how a customer goes live with break-glass on or backups that never left the host.

The setup wizard (`botctl setup`, [ADR 0034](0034-onboarding-wizard.md)) covers first-run configuration, and the health score ([ADR 0144](0144-tam-programme-and-health-score.md)) covers a live customer's adoption and reliability. Nothing covers signed to live: the checklist with its items, its guides, and the items a person must confirm.

Constraints: Rust first, no new dependencies; no change to RBAC, SSO, the audit log's format, vaults, evidence or air-gapped installs, which other M5 tracks are changing at the same time; and a report that can go in a CRM or ticket as it is, so no personal data.

## Decision

### One report per checklist item, from what botd holds

`server/src/onboarding.rs` lists the checklist's 32 items, each with an id, its section, a label and its guide, and judges each from botd's settings and records into one of five statuses: `done`, `open`, `confirm` (botd can't see it: contacts, the identity provider's MFA, a drill's times, the go-live letter), `n/a` (no data regions, no machines, no SSO provider), or `skipped`. Judging is a pure function of an `Inputs` struct gathered once from botd (auth settings, the license, the policy, notifications, backup and encryption checklists, machines and residency, the setup wizard's own checklist, and audit counts), so every rule is unit-tested without a server.

Where botd can tell an item was tested and not just configured, the rule asks for the test: SCIM is done only once it has deprovisioned someone (the checklist's "unassign a test user"), with a working token used in the last 30 days; an admin besides the owner must have signed in with SSO; server backups need a copy off the host within the RPO and every backup encrypted. Items botd can't see are `confirm` with what botd does know (the plans and seats, the machine restores it recorded, how many people used it this week), never `done`.

`GET /api/support/onboarding` serves it and `botctl onboarding` prints it as text, a Markdown checklist for the onboarding record, or JSON. `ready` is true when nothing is open, and `botctl` exits 1 while something is, so a script can wait for it.

### Skips agreed at kickoff, not stored

Some items don't apply to a customer by agreement: the database encrypted at rest "if required", SCIM "if they want". `?skip=a,b` (`--skip`) turns those from open or to-confirm into `skipped`. Skips are passed each time rather than stored, because the agreement belongs in the onboarding record with the rest of the customer's decisions, and a stored skip on a shared server would need its own permission, audit and UI. A skip on an item that's done or doesn't apply anyway is listed as unneeded so it can be dropped; an unknown id is a 400 listing the ids there are, so a typo can't silently skip nothing.

### Admin only, audited, no personal data

The route isn't in RBAC's table, so it falls to admin, the default for routes nobody classified, and no custom role reaches it ([ADR 0123](0123-custom-roles.md)); RBAC's code is untouched. Each check is recorded as `support.onboarding_checked` with the open and skipped ids and the counts, so a TAM's checks show in the audit log. Details are codes, counts and provider ids: never a person's name or email, an address, a bucket or the licensee. A test feeds the rules inputs full of names and addresses and checks none comes out.

### Kept in step with the checklist

A test reads `docs/support/onboarding.md`, matches each `- [ ] ` line to its item by section and how the line starts, and checks the counts agree both ways, so a checklist line added or reworded without the code fails the build. The same test checks each item's guide and anchor exists. `tests/support_docs.rs` checks the page documents every item id and option, and that the onboarding page, the index and the TAM programme point at it.

## Alternatives

- **Extend the setup wizard.** The wizard is first-run configuration for whoever installs botd, shown in the console; the checklist is the Provider's process, with items botd can't judge and skips agreed with a customer. Mixing them would put kickoff paperwork in front of every self-hoster. The check reads the wizard's checklist as one item instead.
- **Store the checklist's state in botd, with ticks for the `confirm` items.** It would make botd the onboarding record, with a person's ticks next to botd's judgements and no way to tell them apart later. The record is the customer's file in the Provider's CRM; the check is evidence for it.
- **Put the check in the support bundle.** The bundle's format and file list are read by triage ([ADR 0220](0220-support-bundle-triage.md)); adding a file means changing both. Onboarding is a TAM's question on a working server, not an incident's, so it has its own command for now.
- **Judge `confirm` items from heuristics,** such as MFA done whenever SSO is ready. botd can't see the identity provider's policy, and calling a guess done is how a box gets ticked that shouldn't be.

## Tests

`onboarding`'s unit tests: ids unique and in known sections, every item with a rule; a customer ready to go live with nothing open and exact details; a fresh install's open and not-applicable items; identity (providers ready and waiting, admins with SSO, JIT, MFA, break-glass, sign-in alerts); SCIM's tokens, expiry, recent use and deprovisions; isolation, hardening, approvals and notices; server backups' copy, RPO and encryption, the database, machine backups and breaches; residency's regions, warnings and backup stores; go-live's status page, metrics, setup, bundles and pilot; skips, unneeded skips and unknown ids; the view and audit details; no name or address in any detail; and the items matching `docs/support/onboarding.md` with every guide and anchor existing. HTTP tests on the real router: admins only (member, read-only, a custom role with every delegable permission, a Bot and no sign-in refused), each check audited and refused ones not; skips and unknown parameters; SCIM, a support bundle, metrics, a machine restore and a team recorded through botd turning items done with no name in the report; approvals in bypass; and an admin's SSO sign-in. `botctl`'s tests: options, the text summary and the Markdown with its escaping.
