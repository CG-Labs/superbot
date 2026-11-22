# SOC 2 Type II evidence plan

What evidence shows each control operating over a Type II observation period, which of it SuperBot already produces, how and how often to collect it, and what is still manual. Part of the [security pack](README.md) and the SOC 2 Type II programme ([#57](https://github.com/CG-Labs/superbot/issues/57)). It builds on the [control mapping](soc2-control-mapping.md), the [readiness checklist](soc2-readiness-checklist.md) and the [policy set](policies/README.md). Design: [ADR 0130](../adr/0130-policy-set-and-type-ii-evidence.md).

**SuperBot is not SOC 2 certified, no SOC 2 audit has started, and no observation period has begun.** This is a plan for collecting evidence once one does. The auditor decides what evidence is enough.

## Why collect continuously

A Type II report covers an observation period, commonly 3 to 12 months, and the auditor tests samples drawn from the whole of it: a few access reviews, a sample of changes, a sample of days' backups. Evidence that wasn't kept at the time can't be made later. Three things in the product make this urgent:

- **GitHub keeps workflow logs and artifacts for a limited time** (90 days by default, and some of this repository's artifacts for 14), so CI evidence must be exported at least monthly.
- **Audit retention can delete events.** If `AUDIT_RETENTION_DAYS` is set, it must cover the period plus a year ([retention](policies/data-classification-and-retention.md#retention)); monthly exports keep a copy either way.
- **Point-in-time state isn't history.** `botctl backups` or the setup checklist show today's settings only, so they are captured on a schedule.

## Where evidence is kept

Outside this public repository, in an access-controlled store the security owner runs, readable by the people who collect and the auditor. One folder per criterion and month (`CC6.3/2027-03/`), each file named for what it is and when it was taken. Exports are kept as produced, with a SHA-256 digest recorded beside each, and nothing is edited after collection. Evidence is kept for the observation period plus at least a year, or longer if the auditor asks. Evidence holding customer data (audit exports carry emails and IP addresses) is Confidential under the [data classification policy](policies/data-classification-and-retention.md#classes).

## Collection calendar

| When | What | How |
|------|------|-----|
| Continuously | Audit events, CI runs, alerts, status page incidents | The product records them; nothing to do but keep them |
| Monthly | Each managed server's audit log for the month | `botctl audit export --from <first day> --to <first day of next month> > audit-<server>-<YYYY-MM>.csv` |
| Monthly | CI runs for every workflow, and the drills' artifacts | `gh run list --workflow <file> --created <YYYY-MM-01>..<YYYY-MM-last> --limit 1000 --json databaseId,headSha,event,conclusion,createdAt,url`; then for each run kept as evidence, its log (`gh run view <id> --log > run-<id>.log`) and its artifacts (`gh run download <id>`): the Grype reports (`image-scan-*`) from `docker.yml`, and `restore-drill-*` and `host-drill-*` from `incus-e2e.yml` |
| Monthly | The population of changes: every pull request merged in the month, with its reviews and checks | `gh pr list --state merged --search "merged:<YYYY-MM-01>..<YYYY-MM-last>" --limit 1000 --json number,title,author,mergedAt,mergedBy,reviews,statusCheckRollup,url` |
| Monthly | Alert history from the operator's Alertmanager, and the machine restore drill | Alertmanager's export; [`deploy/machine-restore-drill.sh`](../../deploy/machine-restore-drill.sh)'s last line |
| Quarterly | Access reviews: SuperBot's report and sign-off, and access outside SuperBot | The dated CSV from `GET /api/access-review/export.csv` and the `access_review.completed` event; each system's user list and the reviewer's sign-off ([access control policy](policies/access-control.md#reviewing-access)) |
| Quarterly | Each server's configuration against the baseline | `botctl backups`, `botctl database`, `botctl retention`, `botctl machine recovery`, the setup checklist, and the server's settings with secrets removed, compared with the [configuration baseline](policies/information-security.md#configuration-baseline) |
| Quarterly | Branch protection on `main` | `gh api repos/<owner>/<repo>/branches/main/protection` |
| Quarterly | Server restore drill; management review minutes; SLO report; legal holds and exceptions reviewed | The records the policies describe |
| Yearly | Policy reviews and approvals; acknowledgements and training; risk assessment; vendor reviews; tabletop; host-loss drill on production hardware; penetration test; master key rotation | The records the policies describe |
| On each event | Incidents and their notices and reviews; emergency changes; new vendors; erasure and deletion requests; joiners, movers and leavers | The incident record, the change record, the register |

## By criterion

"Already produced" is evidence SuperBot's code or CI makes without anyone remembering to; "Still manual" is what people must do or record. Checklist rows in **Gap** have little or no evidence yet: they must close before the observation period starts, or be carved out with the auditor.

| Criterion | Already produced | How it's collected | Still manual | Checklist rows |
|-----------|------------------|--------------------|--------------|----------------|
| CC1.1 Integrity and ethical values | Public contributor rules ([`AGENTS.md`](../../AGENTS.md)) and design records | None needed | A code of conduct, and acknowledgements at hire and yearly | CC1.1-1 |
| CC1.2 Board oversight | None | None | Quarterly management review minutes; the yearly independent review | CC1.2-1 |
| CC1.3 Structure and authority | Roles inside the product, with every change audited (`user.role_changed`, `team.role_changed`) | Monthly audit export | The register naming each role's holder and deputy; org chart; role descriptions | CC1.3-1 |
| CC1.4 Competence | None | None | Background-check and training completion records | CC1.4-1 |
| CC1.5 Accountability | Every audited action names its actor ([ADR 0019](../adr/0019-audit-actors.md)) | Monthly audit export | Performance reviews that include security duties; disciplinary records | CC1.5-1 |
| CC2.1 Quality information | The audit log; `/metrics`; alert rules tested with `promtool` in CI ([`deploy/prometheus/`](../../deploy/prometheus/)); dashboards ([`deploy/grafana/`](../../deploy/grafana/)) | Monthly audit export and alert history; `server.yml` runs | Quarterly screenshots of live dashboards; SIEM export once built ([#56](https://github.com/CG-Labs/superbot/issues/56)) | CC2.1-1, CC2.1-2 |
| CC2.2 Internal communication | ADRs, the pack and the policies, with their git history | None needed | Policy acknowledgements and awareness training records | CC2.2-1 |
| CC2.3 External communication | Status page incidents (`status.incident_created`, `status.incident_updated`, `/status.json`); [`SECURITY.md`](../../SECURITY.md); security advisories; releases | Monthly audit export; the advisory list | The log of vulnerability reports and responses; published privacy policy and terms; signed DPAs | CC2.3-1, CC2.3-2, CC2.3-3 |
| CC3.1 Objectives | None | None | Approval of the [information security policy](policies/information-security.md#security-objectives)'s objectives | CC3.1-1 |
| CC3.2 Risk identification | Internal reviews ([auth review](auth-review-2026-11.md)) | None | The risk register and its yearly review; the penetration test report, fixes and retest | CC3.2-1, CC3.2-2 |
| CC3.3 Fraud risk | Signed Stripe webhooks; signups that wait for an admin (`signup.approved`, `signup.rejected`); plan changes audited (`user.tier_changed`) | Monthly audit export | The fraud risk assessment in the register | CC3.3-1 |
| CC3.4 Changes affecting controls | Pull requests that change a control carry its ADR and pack update; CI checks the pack ([`server/tests/security_docs_links.rs`](../../server/tests/security_docs_links.rs)) | Monthly population of merged PRs; `docs.yml` runs | None beyond reviewing them | CC3.4-1 |
| CC4.1 Evaluations | CI on every change and weekly: route-by-role walk, isolation as root, harness hooks, Incus restores ([`server.yml`](../../.github/workflows/server.yml), [`harness-e2e.yml`](../../.github/workflows/harness-e2e.yml), [`incus-e2e.yml`](../../.github/workflows/incus-e2e.yml)) | Monthly CI export | An independent evaluation (internal audit or readiness assessment) | CC4.1-1 |
| CC4.2 Deficiencies | Issues and fix PRs; RPO and host alerts | Monthly PR population; audit export | The findings tracker with severity, owner and due date; management review minutes | CC4.2-1 |
| CC5.1 Control activities | The setup checklist, `botctl backups`, `botctl database`, `botctl retention`; `machine.hardened` and `machine.hardening_failed` per machine ([ADR 0126](../adr/0126-per-user-machine-hardening.md)) | Quarterly configuration snapshot; monthly audit export | The baseline document and each quarterly check against it | CC5.1-1 |
| CC5.2 Technology controls | Actions pinned by commit, checked in CI ([`server/tests/actions_pinned.rs`](../../server/tests/actions_pinned.rs)); signed images with provenance and SBOM ([ADR 0101](../adr/0101-image-scanning-and-signing.md)) | Monthly CI export; `cosign verify` and `gh attestation verify` output for each image deployed | Saving the verification output at each upgrade | CC5.2-1, CC5.2-2 |
| CC5.3 Policies | The [policy set](policies/README.md), checked by CI | None needed | Approvals, reviews and acknowledgements in the register | CC5.3-1 |
| CC6.1 Logical access | `auth.login` with method and second factor, `user.mfa_enabled`, `auth.mfa_policy_updated`, `secret.master_key_rotated` | Monthly audit export; `AUTH_MFA` in the quarterly snapshot | MFA settings of staff accounts on production systems, and of the IdPs staff sign in with; the yearly key rotation record | CC6.1-1, CC6.1-2, CC6.1-3, CC6.1-4 |
| CC6.2 Registration | `user.created`, `signup.approved`, `team.invited`, `scim.user_*`; botd refusing just-in-time accounts without an allow-list, tested in CI | Monthly audit export | Requests and approvals for production access outside SuperBot | CC6.2-1 |
| CC6.3 Least privilege and removal | The access-review report as dated CSV with its digest, `access_review.exported`, `access_review.completed` ([ADR 0099](../adr/0099-access-review-report.md)); `user.disabled`, `user.deprovisioned`, `session.revoked_all` | Quarterly review package; monthly audit export | Reviews of access outside SuperBot; leavers matched against the people lead's list | CC6.3-1, CC6.3-2, CC6.3-3 |
| CC6.4 Physical access | None (inherited from the hosting providers) | None | The hosting providers' assurance reports, reviewed yearly | CC6.4-1 |
| CC6.5 Disposal | `user.erased`, `user.erase_refused`, `machine.backups_deleted`, `machine.destroyed` | Audit export per request | The request log and answer; removal of the isolation folder | CC6.5-1, CC6.5-2 |
| CC6.6 Boundary protection | Sign-in limits; `auth.suspicious_sign_in`; `machine.firewall_*` and `machine.hardened` | Monthly audit export | Intrusion detection or WAF configuration and alerts, once chosen | CC6.6-1 |
| CC6.7 Data in transit and backups | botd refusing plain-HTTP providers, tested in CI; `server.backup_encryption_changed` and the backup encryption metric | Quarterly snapshot (`botctl backups`); monthly audit export | Restoring with the key in the drills | CC6.7-1, CC6.7-2 |
| CC6.8 Malicious software | `approval.requested`, `approval.approved`, `approval.denied`, `policy.denied`; the Chromium sandbox smoke test in [`docker.yml`](../../.github/workflows/docker.yml) | Monthly audit and CI export | Endpoint detection on servers and hosts, once chosen | CC6.8-1, CC6.8-2, CC6.8-3 |
| CC7.1 Vulnerabilities and configuration | [`dependency-audit.yml`](../../.github/workflows/dependency-audit.yml) runs; Grype results as artifacts and in code scanning; accepted findings in [`.cargo/audit.toml`](../../.cargo/audit.toml) and [`.grype.yaml`](../../.grype.yaml); `machine.reboot_required` | Monthly CI export with the `image-scan-*` artifacts downloaded; code scanning alert list | The vulnerability tracker with due dates | CC7.1-1, CC7.1-2, CC7.1-3 |
| CC7.2 Anomaly monitoring | `auth.suspicious_sign_in`; alert rules tested in CI; email and webhook alerts | Monthly audit export and alert history | A ticket showing each alert was looked at; SIEM export and a tamper-evident log once built ([#56](https://github.com/CG-Labs/superbot/issues/56)) | CC7.2-1, CC7.2-2 |
| CC7.3 Evaluating events | The events above as sources | None | A ticket per security event with its severity ([incident response plan](policies/incident-response.md#severity-levels)) | CC7.3-1 |
| CC7.4 Responding | Containment is audited: `user.disabled`, `session.revoked_all`, `machine.cert_revoked`, `machine.suspended`, `secret.deleted`, `chat.hold_placed` | Audit export per incident | Incident records; notices sent; the yearly tabletop record | CC7.4-1, CC7.4-2 |
| CC7.5 Recovering | `machine.restored`, `machine.restore_failed`, `machine.restore_rto_exceeded`; drill outputs | Monthly audit export and drill artifacts | Post-incident reviews and their actions | CC7.5-1 |
| CC8.1 Change management | Merged PRs with checks; [`CHANGELOG.md`](../../CHANGELOG.md) and GitHub releases from [`release.yml`](../../.github/workflows/release.yml); signed images; `machine.agent_upgraded` | Monthly PR population; release list | Branch protection export; production change records; emergency change reviews | CC8.1-1, CC8.1-2, CC8.1-3 |
| CC9.1 Business disruption | Backups, RPO checks and restores (A1.2, A1.3) | As A1.2 and A1.3 | Business continuity test records; the accepted risk for no failover | CC9.1-1, CC9.1-2 |
| CC9.2 Vendors | The [subprocessor list](subprocessors.md) | None | Vendor assessments and yearly reviews; the published list; change notices sent | CC9.2-1, CC9.2-2 |
| A1.1 Capacity | Host capacity metrics, rules and dashboard ([ADR 0106](../adr/0106-host-capacity-metrics.md)); SLO burn-rate rules; `/status` | Monthly alert history | The outside probe's results and a monthly SLO report; capacity reviews | A1.1-1, A1.1-2, A1.1-3 |
| A1.2 Backups | `server.backup_copied`, `server.backup_copy_failed`, `server.backup_rpo_breached` and `_recovered`; `machine.backup_created`, `machine.backup_failed`, `machine.rpo_breached` and `_recovered`; `botctl backups`, `botctl machine recovery` | Monthly audit export; quarterly snapshot | The backup stores' configuration and a listing of their contents | A1.2-1, A1.2-2 |
| A1.3 Recovery testing | Restore drills in CI within their budgets (`backup-drill` in `server.yml`, `compose-smoke` in `docker.yml`, `incus-e2e.yml`); `machine.restored` with its duration against the RTO | Monthly CI export and drill artifacts | Quarterly server restore records; the yearly host-loss drill on production hardware | A1.3-1 |
| C1.1 Protecting confidential information | `server.database_encryption_changed`, `botctl database` ([ADR 0116](../adr/0116-database-encrypted-at-rest.md)); sealed secrets | Quarterly snapshot; monthly audit export | Each host's disk encryption; the approved data inventory ([classification policy](policies/data-classification-and-retention.md#inventory)) | C1.1-1, C1.1-2 |
| C1.2 Disposing of confidential information | `chat.pruned`, `harness_sessions.pruned`, `teammate_files.pruned`, `audit.pruned`; `chat.hold_placed`, `chat.hold_released`; `*.retention_changed`; `botctl retention` | Monthly audit export; quarterly snapshot | The legal hold log; confirmations of deletion when customers leave | C1.2-1 |

## What is still manual

Most of the remaining work is records people keep, not code: the register (role holders, approvals, acknowledgements, exceptions), training and background checks, the risk register, management review minutes, vendor reviews, incident and change records, and reviews of access outside SuperBot. Product evidence needs only collecting on the calendar above, which is itself a monthly and quarterly task for the operator and security owner until it is automated.

## Before the observation period starts

1. Adopt the [policy set](policies/README.md#adopting-them) and name the role holders.
2. Close or carve out the checklist's **Gap** rows that have no evidence ([readiness checklist](soc2-readiness-checklist.md#before-engaging-an-auditor)).
3. Set up the evidence store and run one full month of the calendar as a dry run, then fix what was hard to collect.
4. Agree the period, the criteria and the sample sizes with the auditor.
