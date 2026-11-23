# 0130: The security policy set and the Type II evidence plan in the repository

## Status

Accepted (22 Nov 2026). First slice of the SOC 2 Type II programme ([#57](https://github.com/CG-Labs/superbot/issues/57), M5). Builds on the [SOC 2 control mapping](../security/soc2-control-mapping.md) and the [readiness checklist](../security/soc2-readiness-checklist.md) ([#50](https://github.com/CG-Labs/superbot/issues/50)), whose next items were a named security owner, the policy set (CC5.3-1) and the incident response plan (CC7.4-1).

Numbered 0130 because 0122 to 0129 are reserved for other open PRs.

## Context

A Type II report says controls operated over a period, with evidence for all of it. The readiness checklist showed that most open rows are process: written policies, an incident response plan, and records people keep. Three things shape where those documents live and how they are checked:

- **The repository is public, and holds no private details** ([`AGENTS.md`](../../AGENTS.md)): no names, emails or hosts. But a policy needs an owner, and an auditor needs to see who approved what.
- **Policies state product facts.** A plan that says "disable the user" or "restore the newest archive" is only right if the command and setting exist and behave as described. Those facts drift as the code changes, as the security pack would without its link checks.
- **Product evidence is already produced**, but in places that forget: GitHub keeps workflow logs and artifacts for a limited time, `AUDIT_RETENTION_DAYS` can delete events, and `botctl` shows only current state.

## Options

1. **Policies kept privately by the managed provider.** The usual way. Nothing here to check against the code, and nothing for a self-hoster to start from; the product facts in them would drift unseen.
2. **Policies in the repository, with names.** Breaks the no-private-details rule, and ties the public text to one provider.
3. **Policies in the repository by role, approvals and names in a private register.** The text is public, versioned and checked like the pack. Each approval records the commit it approved, so the exact text is fixed without copying it.

## Decision

Option 3.

- **Eight policies** under [`docs/security/policies/`](../security/policies/README.md): information security, access control, change management, the incident response plan, vendor management, business continuity and disaster recovery, data classification and retention, and acceptable use. Each starts with a header table: owner, approver, review cadence, status and the checklist items it covers.
- **Owners are roles**, the six in the checklist's owner table (management, security owner, engineering lead, operator, people lead, privacy lead). No person is named here. The provider's private **policy register** names who holds each role and a deputy, and records each approval as the policy, the commit it was approved at, the approver and the date, plus acknowledgements, exceptions and review minutes.
- **Provider choices are placeholders** in square brackets (`[N] hours`), with a suggested value where one is common, as the legal templates do.
- **Policies cite the product, not restate it**: commands, settings and audit events by name, linked to the ADR or operator guide behind them. The business continuity plan takes its objectives from the existing recovery objectives and backup ADRs; the data classification policy takes its retention settings from the retention ADRs.
- **A Type II evidence plan** ([`soc2-evidence-plan.md`](../security/soc2-evidence-plan.md)) has one row per Trust Services criterion the mapping covers, not per checklist row: what SuperBot already produces (audit events, CI runs, the access-review report, drill artifacts), how and how often to collect it, what is still manual, and the checklist rows it serves. Criteria are fixed; checklist rows are added as gaps are found, and the plan names them per criterion without having to change shape. A calendar says what to export monthly (audit log, CI runs and drill artifacts, merged pull requests) so nothing ages out.
- **CI checks them** in `server/tests/security_docs_links.rs`, which already checks the pack: every link, ADR and file reference in the policies resolves; the pack's index links the policy index, which links every policy; all eight exist; each header has an owner from the checklist's roles, an approver, a review cadence, a draft or approved status, and only checklist items that exist; the incident response plan keeps its severity levels, runbook, communication and post-incident review sections; the business continuity plan links the backup guide and the recovery objectives; the data classification policy cites the retention ADRs; no policy contains an email address or claims a certification; and the evidence plan has a complete row for every criterion, in order.
- **Checklist statuses move only as far as the documents go.** A row whose evidence is a written document now drafted (the policy set, the incident response plan and its severity definitions, the change management policy, the business continuity plan, the classification scheme, the security objectives, written responsibilities) becomes **Partial**, with approval and the records named as what is left. Rows whose evidence is a record of something done (training, reviews, assessments, tabletops) stay **Gap**: a policy saying they will happen is not evidence that they did.

## Consequences

- A provider adopts the set by naming people and approving commits privately; a self-hoster can adopt it the same way for their own audit.
- A code change that makes a policy's product fact wrong must fix the policy in the same PR, as for the pack; CI catches broken references, not wrong descriptions, so review still matters.
- A policy change here is a new version: the provider approves the new commit before relying on it.
- The checklist now has more **Partial** rows, none **Done**: nothing is adopted, and SuperBot is not SOC 2 certified.

## Deferred

- Automating the monthly collection (a `botctl` command or a scheduled job that exports the audit log and CI runs to the evidence store, with digests). The server's part is built: monthly evidence bundles ([ADR 0142](0142-type-ii-evidence-bundles.md)). So is exporting CI runs and pull requests from GitHub: the change-management bundle ([ADR 0148](0148-change-management-evidence-from-github.md)).
- A code of conduct (CC1.1-1), the risk register's template (CC3.2-1) and the configuration baseline document (CC5.1-1). The baseline is drafted ([ADR 0148](0148-change-management-evidence-from-github.md), [configuration baseline](../security/configuration-baseline.md)).
- Engaging an auditor and starting the observation period, once the policies are adopted.
