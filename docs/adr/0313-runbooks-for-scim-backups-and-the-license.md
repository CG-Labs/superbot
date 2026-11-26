# 0313: Runbooks for SCIM provisioning, backups and the license

## Status

Accepted (26 Nov 2026). Nineteenth slice of enterprise support playbooks in M5, [#60](https://github.com/CG-Labs/superbot/issues/60), after health score alerts ([ADR 0307](0307-health-score-alerts.md)).

Numbering: this number was reserved for this work.

## Context

The customer health score has six signals (ADR 0144). Since ADR 0307, botd tells the admins' alert channels when one goes at risk, linking its section of the health score page, and the Provider's Prometheus rules raise a ticket for it. Bundle triage (ADR 0220), the offline support check (ADR 0187) and the monthly health check (ADR 0252) point at a runbook for each problem they find.

Three of the six had none. `identity`'s SCIM half pointed at the SCIM setup guide, `backups` at the machine-down runbook and the backup procedures, and `license` back at its own paragraph on the health score page. Triage's audit groups did the same, and server backup failures (`server.backup_copy_failed`, `server.backup_rpo_breached`) fell into `audit.other`, with no runbook at all. A support engineer handed "Backups at risk" or "SCIM uniqueness ×7" had to work out the order from guides written for setting things up, under a response target. The other runbooks each have the same shape (first five minutes, a table of reasons and fixes, when to escalate, afterwards), and a test holds it.

Two smaller faults showed up on the way. The health score page said runs refused for the license have reason `license`; botd records `unlicensed`. And triage suggested Severity 2 for a server with no usable license, where Bots don't run for anyone, which [severity](../support/severity.md#severities) calls 1.

Constraints: Rust first, no new dependencies, nothing that changes what botd records or sends, and no edits to RBAC, vaults, offline upgrades or SOC 2 evidence code, which other M5 tracks are changing.

## Decision

### Three runbooks in the shape of the others

- [`runbook-scim.md`](../support/runbook-scim.md): every reason botd records on `scim.request_failed`, with the two the score names for tokens it no longer takes (`revoked_token`, `expired_token`), in one table of what it usually means and the fix; provisioning stopped (a revoked, expired or ending token); Google Workspace's sync; and leavers who keep access, which is a security incident once they use it.
- [`runbook-backups.md`](../support/runbook-backups.md): server backups (not set up, on the host, never copied, a failed copy, past the RPO, no new archive) and machine backups (a failed backup, past the RPO, Linode backups not turned on, deleting a destroyed machine's backups), each by the audit action or the words botd uses, then what to check before telling the customer it's fixed.
- [`runbook-license.md`](../support/runbook-license.md): each mode, each reason a key isn't a license (the token's, the setting's, an install's refusal), seats, and Bots stopped.

Each sizes the incident against severity's definitions and says when to escalate. They link the setup guides and procedures for detail rather than repeat them.

### Everything that names these problems points at them

- Triage: the `identity` signal opens `runbook-scim.md#provisioning-stopped` for a revoked or expired token or a tenant whose tokens all end soon, and `#reasons-and-fixes` for other SCIM reasons; `backups` opens `#server-backups` or `#machine-backups` from the signal's facts (no server facts means not set up); `license` opens the runbook; runs refused `unlicensed` add `#bots-stopped`; `check.backups` and `check.license` open them too, failed or warned.
- A new audit group, `audit.backups`: `server.backup_*`, `machine.backup*` and `machine.rpo_breached` failures, ahead of the machine group, after residency (a pin's refusals stay the residency runbook's, and a failed restore the machine runbook's). `audit.scim` and `audit.license` point at their runbooks.
- The monthly health check's `scim`, `backups` and `license` items take the runbooks as their guides, and triage's copy of those guides with them.
- The health score page's three sections, the health check's checklist lines, the support check page and the index link them. The health score alert keeps linking the score page's section, which now leads to the runbook, so the notice's text doesn't change.

### Two corrections

- No usable license suggests Severity 1 in triage (the signal with `usable: false`, and the offline check's failure). A license in its grace period, or over its seats, stays 2.
- The health score page names the refusal `unlicensed`.

## Alternatives

- **Link the setup guides' troubleshooting.** They explain one error at a time for whoever is setting up. A runbook says what to look at first, how bad it is and when to escalate, which is what support needs under a target.
- **One runbook for "identity".** Sign-in already has two (SSO and SAML). SCIM fails differently (a token, not a person signing in) and its worst case is a leaver keeping access, not someone locked out.
- **Fold backups into the machine-down runbook.** That one is for something down now. Late backups are a risk with nothing down yet, and server backups aren't machines.
- **Link runbooks from the health score alert.** The notice's line points at the signal's section, which says what the signal means before the steps. Changing it would change a notice admins already see, for one click.
- **Keep Severity 2 for no usable license.** Bots don't run for anyone; that's the definition of 1, and triage exiting 1 already paged on 2, so only the label was wrong.

## Tests

`support_docs`: the SCIM runbook's table has every `scimType` (snake case) and every `status_` the SCIM code can return without one (a status it doesn't know fails the test), with `insufficient_scope` and the two token reasons; the license runbook has every mode of `license::Mode`, every reason from the token's `code()`, the loader's problems and an install's refusals, and every `license.*` audit action; the backups runbook names every `_failed`, `_breached` and `_refused` action server and machine backups record, and triage's `audit.backups` points at it; the health score page, the health check's items and the index point at all three; every runbook keeps the shared shape, and every link and anchor resolves. `support_triage`'s unit tests: the SCIM, backups and license signals open the section their facts call for; no usable license suggests 1 and grace 2; runs refused `unlicensed` open the license runbook; backup failures are their own group, residency refusals and failed restores aren't; the offline check's backups and license findings open their runbooks; every runbook triage names exists with its anchor.
