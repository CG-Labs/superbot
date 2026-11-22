# SOC 2 readiness checklist

What has to be true before a SOC 2 audit of the managed SuperBot service can start, built from every gap in the [SOC 2 control mapping](soc2-control-mapping.md#gaps-for-the-soc-2-readiness-checklist-m4). Part of the [security pack](README.md), [#50](https://github.com/CG-Labs/superbot/issues/50) and the M4 exit criteria on the [roadmap](../ROADMAP.md#m4--public-launch).

**SuperBot is not SOC 2 certified, and no SOC 2 audit has started.** This is a readiness path, not a claim of compliance. A status of **Done** means the repository shows the control exists; only an auditor can say whether it is designed and operating well enough.

## How to read it

Each row is one thing to close. Its ID is the criterion it serves (AICPA 2017 Trust Services Criteria, revised points of focus 2022) and a number.

| Column | Meaning |
|--------|---------|
| Kind | **Product**: SuperBot's code must do it, and the evidence is code, an ADR or a CI job. **Process**: people must do it, and the evidence is a written policy, a record or a setting outside this repository. |
| Owner | The role that closes it, from the table below. |
| Evidence to collect | What an auditor will ask to see. For a Type II audit, collect it for the whole observation period. |
| Status | **Done**: the repository shows it, with a link. **Partial**: some of it exists, linked; the rest is named. **Gap**: nothing in the product or this repository does it yet. |

Statuses are checked against the code on `main`, not plans. When a change closes or opens a row, the same PR updates it ([pack rules](README.md#keeping-it-accurate)). CI checks that every link and every ADR and file reference here resolves, that every row has a known kind, owner and status, that every **Done** or **Partial** row links its evidence, that every criterion in the mapping's gap list has a row, and that the summary counts match the rows (`server/tests/security_docs_links.rs`).

| Owner | Who |
|-------|-----|
| Management | Whoever runs the managed provider: sets direction, approves policies and accepts risk. |
| Security owner | The named person accountable for the security programme and this checklist. |
| Engineering lead | Owns the code, CI and release process. |
| Operator | Runs the managed servers, hosts and backups. For a self-hoster's own audit, the customer. |
| People lead | Hiring, onboarding, training and leaving. |
| Privacy lead | Privacy policy, DPA, subprocessors and data-subject requests. |

Scope: the managed service. A self-hosting customer is its own service organisation: the product rows below are what SuperBot gives them, and the process rows are theirs to do. Physical security and data-centre controls are inherited from the hosting provider (Linode/Akamai, or wherever the Incus hosts run), whose own report the managed provider must review (CC6.4-1).

## Summary

| Area | Done | Partial | Gap |
|------|------|---------|-----|
| CC1 Control environment | 0 | 0 | 5 |
| CC2 Communication and information | 1 | 1 | 4 |
| CC3 Risk assessment | 0 | 1 | 4 |
| CC4 Monitoring activities | 0 | 1 | 1 |
| CC5 Control activities | 0 | 0 | 4 |
| CC6 Logical and physical access | 2 | 4 | 11 |
| CC7 System operations | 1 | 2 | 6 |
| CC8 Change management | 0 | 0 | 3 |
| CC9 Risk mitigation | 0 | 1 | 3 |
| A1 Availability | 0 | 1 | 5 |
| C1 Confidentiality | 0 | 1 | 2 |

## CC1: Control environment

| ID | Item | Kind | Owner | Evidence to collect | Status | Where it stands |
|----|------|------|-------|---------------------|--------|-----------------|
| CC1.1-1 | Code of conduct and ethics policy, acknowledged by everyone with access | Process | Management | Signed policy; an acknowledgement per person at hire and yearly | Gap | Contributor rules in `AGENTS.md` forbid committing secrets or private details, but there is no code of conduct or acknowledgement. |
| CC1.2-1 | A body (board, or management with a named independent reviewer) that oversees security | Process | Management | Charter; minutes of at least quarterly security reviews | Gap | None. |
| CC1.3-1 | A named security owner, an org chart and written security responsibilities | Process | Management | Org chart; role descriptions; appointment of the security owner | Gap | Roles exist for customers inside the product (ADR 0012, ADR 0087), not for the service organisation. |
| CC1.4-1 | Hiring checks and security training | Process | People lead | Background-check records; onboarding and yearly training completion | Gap | None. |
| CC1.5-1 | Security responsibilities tied to performance and discipline | Process | People lead | Policy; review records that include security duties | Gap | The product names the actor of every audited action (ADR 0019), but nothing holds people accountable for the service. |

## CC2: Communication and information

| ID | Item | Kind | Owner | Evidence to collect | Status | Where it stands |
|----|------|------|-------|---------------------|--------|-----------------|
| CC2.1-1 | Metrics, alert rules and dashboards for the service | Product | Engineering lead | Dashboard definitions in the repository; screenshots of live dashboards; alert history | Partial | A Prometheus endpoint and structured logs ([ADR 0089](../adr/0089-metrics-and-structured-logs.md), [PR #150](https://github.com/CG-Labs/superbot/pull/150)) and SLO burn-rate alert rules tested with `promtool` ([`deploy/prometheus/superbot-slo.rules.yml`](../../deploy/prometheus/superbot-slo.rules.yml), [ADR 0090](../adr/0090-status-page-and-uptime-slo.md)). No dashboards and no error reporting. |
| CC2.1-2 | Audit events exported to a SIEM | Product | Engineering lead | Export configuration; events arriving in the SIEM | Gap | The audit log is only in SQLite, with CSV export (ADR 0009). Planned for M5. |
| CC2.2-1 | Security policies communicated to personnel, with awareness training | Process | People lead | Policy portal or handbook; training completion records | Gap | ADRs and this pack are public, but they describe the product, not staff duties. |
| CC2.3-1 | A vulnerability-disclosure policy and security contact | Process | Security owner | `SECURITY.md`; GitHub private vulnerability reporting turned on; a log of reports and responses | Gap | There is no `SECURITY.md`, and GitHub's private vulnerability reporting is off for the repository. Turn it on before publishing a policy that points at it. |
| CC2.3-2 | A public status page for availability incidents | Product | Operator | Status page history; incident notes posted within the SLO's 15 minutes | Done | `/status` and `/status.json`, with incident notes admins post in the console, and an SLO that commits to posting within 15 minutes of confirming an outage ([ADR 0090](../adr/0090-status-page-and-uptime-slo.md), [`server/src/status.rs`](../../server/src/status.rs), [SLO](../slo.md), [PR #151](https://github.com/CG-Labs/superbot/pull/151)). |
| CC2.3-3 | Privacy policy, terms of service and a DPA | Process | Privacy lead | Published documents; signed DPAs | Gap | None. GDPR docs are on the M4 roadmap. |

## CC3: Risk assessment

| ID | Item | Kind | Owner | Evidence to collect | Status | Where it stands |
|----|------|------|-------|---------------------|--------|-----------------|
| CC3.1-1 | Written security objectives that risks are measured against | Process | Security owner | Approved objectives document | Gap | The roadmap's goals and this pack's stated properties are inputs, not objectives. |
| CC3.2-1 | A risk register with owners, reviewed at least yearly | Process | Security owner | The register; review records; treatment decisions | Gap | Inputs exist: the roadmap's risks table, the [auth review](auth-review-2026-11.md) and its [SCIM follow-up](auth-review-2026-11-scim.md), and each ADR's trade-offs. None has owners or a review cycle. |
| CC3.2-2 | An external penetration test, with findings fixed | Process | Security owner | Tester's report; fix PRs; retest letter | Gap | Only the internal reviews above. Planned before M3 general availability. |
| CC3.3-1 | A fraud risk assessment | Process | Security owner | The assessment, in the risk register | Gap | Product controls exist (signed Stripe webhooks, ADR 0042; Bots can't approve their own actions, ADR 0007), but no assessment. |
| CC3.4-1 | Changes that affect controls are reviewed | Process | Engineering lead | PRs that changed a control, each with its ADR and pack update | Partial | Significant changes get an ADR, and the pack changes in the same PR ([pack rules](README.md#keeping-it-accurate)); CI checks the pack's links. No scheduled review of business or technology changes. |

## CC4: Monitoring activities

| ID | Item | Kind | Owner | Evidence to collect | Status | Where it stands |
|----|------|------|-------|---------------------|--------|-----------------|
| CC4.1-1 | An independent evaluation of controls | Process | Management | Internal audit or readiness assessment report | Gap | CI tests controls continuously (route-by-role walk, isolation as root, restore drills; see the mapping's CC4.1), but nobody independent has evaluated them. |
| CC4.2-1 | Deficiencies reported to management and fixed by a deadline | Process | Security owner | Tracker of findings with severity, owner and due date; closure records | Partial | Findings are GitHub issues fixed in PRs (for example the AUTH findings, [ADR 0024](../adr/0024-auth-review-hardening.md)); RPO breaches and host failures alert the operator ([`server/src/notify/mod.rs`](../../server/src/notify/mod.rs)). No severity deadlines or reporting to management. |

## CC5: Control activities

| ID | Item | Kind | Owner | Evidence to collect | Status | Where it stands |
|----|------|------|-------|---------------------|--------|-----------------|
| CC5.1-1 | A hardened configuration baseline for the managed service | Process | Operator | Baseline document; each server's settings checked against it | Gap | Several protections are off until the operator turns them on (`MACHINE_FIREWALL`, `MACHINE_BOT_USER`, `MACHINE_TEAMMATE_USERS`, `TEAMS`, `AUTH_MFA`, backup encryption), and nothing records which the managed service uses. |
| CC5.2-1 | GitHub Actions pinned by commit | Product | Engineering lead | Workflows referencing actions by full commit SHA; an update process | Gap | Every workflow in [`.github/workflows/`](../../.github/workflows/) pins actions by tag (for example `actions/checkout@v4`). |
| CC5.2-2 | Signed container images with provenance | Product | Engineering lead | Signatures and attestations on each published image; verification steps for operators | Gap | Images are built and published by CI ([`docker.yml`](../../.github/workflows/docker.yml), ADR 0084) without signatures or provenance. |
| CC5.3-1 | A written policy set: information security, access control, change management, incident response, vendor management, data classification and retention, acceptable use, business continuity | Process | Security owner | Approved policies with owners and review dates | Gap | Operator guides exist ([install](../../deploy/README.md), [backup and restore](../ops/backup-restore.md), [machine recovery](../ops/machine-recovery.md)), but no policies. |

## CC6: Logical and physical access

| ID | Item | Kind | Owner | Evidence to collect | Status | Where it stands |
|----|------|------|-------|---------------------|--------|-----------------|
| CC6.1-1 | Multi-factor authentication in SuperBot | Product | Engineering lead | MFA enforced for admins and break-glass sign-in; tests | Done | TOTP with one-time recovery codes for sign-in codes and the owner's password, required for admins (the owner included) or everyone by an admin's policy or `AUTH_MFA`; secrets sealed under the master key; wrong codes limited per IP and per user and audited; HTTP Basic refused once the owner needs a second factor ([ADR 0094](../adr/0094-totp-second-factor.md), [`server/src/mfa.rs`](../../server/src/mfa.rs), tests in [`server/src/mfa_http_tests.rs`](../../server/src/mfa_http_tests.rs)). Off by default: the managed service must set it (CC5.1-1). SSO sign-ins rely on the IdP's MFA (CC6.1-2). |
| CC6.1-2 | A written requirement to enforce MFA at the IdP | Process | Security owner | The requirement in the access control policy; each IdP's MFA setting | Partial | The [questionnaire FAQ](questionnaire-faq.md) and every [IdP guide](../sso/) tell customers to require MFA at their IdP, with where to set it ([ADR 0094](../adr/0094-totp-second-factor.md) leaves SSO sign-ins to it). There is no access control policy to hold the requirement yet (CC5.3-1), and the managed provider's own staff sign-in has no stated rule. |
| CC6.1-3 | Rotating the secrets master key | Product | Engineering lead | A rotation command, tested, and its audit event | Done | With the old key set as the previous key, botd re-seals every sealed value under the new key at start, in one transaction with a `secret.master_key_rotated` audit event; a crash part-way changes nothing, and the machine CA is kept unless asked otherwise ([ADR 0096](../adr/0096-master-key-rotation.md), [`server/src/secrets/sealed.rs`](../../server/src/secrets/sealed.rs)). Tested for rotation, a crash part-way, wrong keys and running twice, end to end in [`server/tests/master_key_rotation.rs`](../../server/tests/master_key_rotation.rs) and the Compose smoke test. Operator steps for Compose (`init.sh --rotate-master-key`) and the installer: [master key rotation](../ops/master-key-rotation.md). |
| CC6.1-4 | An external secret vault | Product | Engineering lead | Vault configuration; botd reading from it | Gap | A trait seam only (ADR 0010). Planned for M5. |
| CC6.2-1 | Just-in-time accounts limited to allowed domains for every provider | Product | Engineering lead | Startup refusing JIT without a domain list; tests | Partial | Google, Apple and GitHub refuse just-in-time accounts without allowed domains or organizations ([`server/src/sso/mod.rs`](../../server/src/sso/mod.rs)); generic OIDC and SAML accept them without one. |
| CC6.3-1 | An access-review report for admins | Product | Engineering lead | A report of each person's role, last sign-in and Bot access, exportable and dated | Partial | The admin portal shows each person's role, last sign-in and Bot access ([ADR 0021](../adr/0021-admin-portal.md)), and the audit log exports to CSV ([ADR 0009](../adr/0009-audit-events.md)). No single report to sign off. |
| CC6.3-2 | Periodic access reviews, signed off | Process | Security owner | Quarterly review records for admins, operators and production access | Gap | None. |
| CC6.3-3 | Custom roles and service accounts | Product | Engineering lead | Role definitions; tests | Gap | Fixed roles only (ADR 0012, ADR 0087). Planned for M5. |
| CC6.4-1 | Review of the hosting providers' own assurance reports | Process | Security owner | Each provider's SOC 2 or ISO 27001 report, reviewed yearly with notes on their complementary controls | Gap | The [subprocessor list](subprocessors.md) names them; no reviews. |
| CC6.5-1 | Erasing a user's data | Product | Engineering lead | An erasure command or API, tested, with its audit event | Gap | Users are disabled, never deleted; a SCIM delete is a soft delete (ADR 0023). GDPR erasure is on the M4 roadmap. |
| CC6.5-2 | Deleting a destroyed machine's backups on request | Product | Engineering lead | A deletion path, tested and audited | Gap | Backups are deleted only when their retention ends ([ADR 0071](../adr/0071-off-host-machine-backups.md)). |
| CC6.6-1 | Intrusion detection or a WAF in front of the service | Process | Operator | Tool configuration; alert history | Gap | Only Caddy is public, with sign-in rate limits ([auth review](auth-review-2026-11.md)); nothing detects intrusions. |
| CC6.7-1 | Model providers reached only over HTTPS | Product | Engineering lead | The tiers file refusing `http://` outside loopback; tests | Gap | A provider's `baseUrl` may be `http` or `https` (`server/src/tiers.rs`, ADR 0077), which would send prompts and keys unencrypted. |
| CC6.7-2 | Backups encrypted | Product | Operator | Each backup target's age recipients; a restore with the key | Partial | age encryption exists for server and machine backups ([ADR 0030](../adr/0030-backup-restore-drill.md), [ADR 0071](../adr/0071-off-host-machine-backups.md)) but is off until the operator sets recipients. |
| CC6.8-1 | Malware scanning or endpoint detection on servers and hosts | Process | Operator | Agent deployment records; alert history | Gap | None in the product or this repository. |
| CC6.8-2 | Egress allowlists for runs | Product | Engineering lead | Per-machine egress policy; tests | Gap | Incus containers can't reach private ranges or the host (ADR 0065), but public egress is open. Planned for M5. |
| CC6.8-3 | Chromium's sandbox inside the container | Product | Engineering lead | The image running Chromium sandboxed; a smoke test | Gap | Off inside the published image (ADR 0084). |

## CC7: System operations

| ID | Item | Kind | Owner | Evidence to collect | Status | Where it stands |
|----|------|------|-------|---------------------|--------|-----------------|
| CC7.1-1 | Dependency vulnerability scanning in CI | Product | Engineering lead | Workflow runs on each lockfile change and weekly | Done | `cargo audit` and `npm audit` on every lockfile change and weekly ([`dependency-audit.yml`](../../.github/workflows/dependency-audit.yml), [ADR 0092](../adr/0092-dependency-vulnerability-scanning.md)). |
| CC7.1-2 | Findings from the scan fixed, or accepted with a reason | Product | Engineering lead | The list of accepted findings with reasons and owners; fix PRs | Partial | One RustSec advisory accepted, with why it can't reach botd ([`.cargo/audit.toml`](../../.cargo/audit.toml)). The client's Markdown renderer pulls in `markdown-it` 10 with High advisories and no fixed release, so the npm gate fails only on Critical until it's replaced ([ADR 0092](../adr/0092-dependency-vulnerability-scanning.md)). |
| CC7.1-3 | Container image scanning | Product | Engineering lead | Scan results on each published image | Gap | Images are rebuilt weekly for Debian's security fixes ([`docker.yml`](../../.github/workflows/docker.yml)) but not scanned. |
| CC7.2-1 | Alerts on suspicious sign-in patterns | Product | Engineering lead | Alert rules; tests; alert history | Partial | Failed sign-ins are counted in the opt-in metrics ([ADR 0089](../adr/0089-metrics-and-structured-logs.md)), and SLO alert rules ship ([`deploy/prometheus/superbot-slo.rules.yml`](../../deploy/prometheus/superbot-slo.rules.yml)), but no rule watches sign-ins. |
| CC7.2-2 | A tamper-evident audit log shipped off the server | Product | Engineering lead | Hash chain or write-once store; export configuration | Gap | Append-only in SQLite (ADR 0009). Planned for M5. |
| CC7.3-1 | A triage process and incident classification | Process | Security owner | Severity definitions; a ticket per security event | Gap | None. |
| CC7.4-1 | An incident response plan, roles and runbooks | Process | Security owner | The plan; runbooks; a yearly tabletop exercise | Gap | Containment tools exist (disable a user, end sessions, revoke a machine's certificates; [`server/src/rbac.rs`](../../server/src/rbac.rs) lists the admin routes), but no plan. |
| CC7.4-2 | Telling customers and regulators about security incidents and breaches | Process | Privacy lead | Notification commitment in the DPA; notification records | Gap | The SLO covers outages only ([SLO](../slo.md)). GDPR work is on the M4 roadmap. |
| CC7.5-1 | Post-incident reviews | Process | Security owner | A written review per significant incident, with actions tracked | Gap | The SLO's error budget policy asks for a review of outages that spend a quarter of the budget ([SLO](../slo.md)); nothing covers security incidents. |

## CC8: Change management

| ID | Item | Kind | Owner | Evidence to collect | Status | Where it stands |
|----|------|------|-------|---------------------|--------|-----------------|
| CC8.1-1 | Branch protection and required reviews on `main` | Process | Engineering lead | Exported branch protection settings; a sample of PRs with approvals and green checks | Gap | Changes reach `main` through PRs that run CI, but branch protection is a GitHub setting this repository can't show. |
| CC8.1-2 | A change-management policy with segregation of duties and an emergency-change process | Process | Engineering lead | The policy; emergency changes with after-the-fact approval | Gap | None. |
| CC8.1-3 | Release notes for each release | Process | Engineering lead | A changelog or GitHub release per tag | Gap | Images are tagged by commit and semver (ADR 0084), but there is no changelog and no GitHub releases. |

## CC9: Risk mitigation

| ID | Item | Kind | Owner | Evidence to collect | Status | Where it stands |
|----|------|------|-------|---------------------|--------|-----------------|
| CC9.1-1 | A high-availability control plane | Product | Engineering lead | Failover design; a failover test | Gap | botd is one process with one SQLite database; the RTO is 1 hour ([ADR 0030](../adr/0030-backup-restore-drill.md)). |
| CC9.1-2 | A business continuity plan | Process | Management | The plan; a yearly test | Gap | Recovery tools exist (A1.2), but no plan. |
| CC9.2-1 | Vendor risk assessments | Process | Security owner | An assessment per vendor before use and yearly | Gap | None. |
| CC9.2-2 | A published subprocessor list and DPA for the managed service | Process | Privacy lead | The published list; change notices to customers | Partial | Every outside service the code can call is listed, with what it gets and the setting that turns it on ([subprocessors](subprocessors.md)); the managed service's actual vendors aren't published. |

## A1: Availability

| ID | Item | Kind | Owner | Evidence to collect | Status | Where it stands |
|----|------|------|-------|---------------------|--------|-----------------|
| A1.1-1 | Host capacity metrics and capacity dashboards | Product | Engineering lead | Metrics for each host's CPU, memory and disk against its capacity; dashboards | Gap | Metrics cover machines by state, runs and run slots ([ADR 0089](../adr/0089-metrics-and-structured-logs.md)), not host capacity. |
| A1.1-2 | Machines' disk use counted in tier storage limits | Product | Engineering lead | Storage limits including reported disk use; tests | Gap | Machines report disk use, but storage limits don't count it ([ADR 0085](../adr/0085-resizing-machines-on-a-tier-change.md), [ADR 0082](../adr/0082-storage-limits-per-tier.md)). |
| A1.1-3 | Uptime measured against the SLO for a quarter | Process | Operator | The outside probe's results; monthly SLO reports | Partial | The SLO, the probe target and burn-rate rules exist ([SLO](../slo.md), [ADR 0090](../adr/0090-status-page-and-uptime-slo.md)); no quarter has been measured. |
| A1.2-1 | Server backups copied off the host by default | Product | Engineering lead | Off-host backup configuration; backups arriving there | Gap | Server backups stay on the host unless the operator copies them off ([ADR 0030](../adr/0030-backup-restore-drill.md)); only Incus machines back up off-host ([ADR 0071](../adr/0071-off-host-machine-backups.md)). |
| A1.2-2 | Recovery objectives for Linode machines | Product | Engineering lead | Objectives, checks and alerts like Incus machines' | Gap | Linode machines rely on Linode Backups, which the [machine recovery objectives](machine-recovery-objectives.md) don't cover. |
| A1.3-1 | The host-loss drill on production hardware, with full-size restore times | Process | Operator | Drill record with timings against the RTO | Gap | Drilled in CI on small machines ([`incus-e2e.yml`](../../.github/workflows/incus-e2e.yml)); the manual drill ([`deploy/machine-restore-drill.sh`](../../deploy/machine-restore-drill.sh)) hasn't been run on production hardware ([#29](https://github.com/CG-Labs/superbot/issues/29)). |

## C1: Confidentiality

| ID | Item | Kind | Owner | Evidence to collect | Status | Where it stands |
|----|------|------|-------|---------------------|--------|-----------------|
| C1.1-1 | Database encryption at rest | Product | Engineering lead | Encrypted database, or the operator's disk encryption recorded per host | Gap | Only secrets are sealed; chat history and the rest of the database aren't encrypted by SuperBot ([encryption at rest](data-flows.md#at-rest)). |
| C1.1-2 | A data-classification scheme | Process | Security owner | The scheme in the policy set; data inventory | Gap | [Data flows](data-flows.md) describes what is stored where, without classes. |
| C1.2-1 | Retention for chat history and teammates' archived work | Product | Engineering lead | Retention settings; deletion jobs; tests | Partial | Chat history: `CHAT_RETENTION_DAYS` (off by default) deletes older messages in batches every 6 hours, never a running message or a Bot an admin holds (a legal hold, which also stops the Bot being deleted), with each pass audited as `chat.pruned` with its counts, and settings, the last pass and holds shown to admins (`botctl retention`, `GET /api/retention`) ([ADR 0097](../adr/0097-chat-retention.md), [`server/src/retention.rs`](../../server/src/retention.rs), tests in [`server/src/retention_http_tests.rs`](../../server/src/retention_http_tests.rs)). The audit log and backups have their own settings ([retention](data-flows.md#retention)). Left: teammates' work archived to an owner's `from-teammates/` folder is kept until someone deletes it (`*_TEAMMATE_FILES=delete` deletes it instead of archiving), and harness session files in each Bot's folder aren't covered. Erasure of a user's data is CC6.5-1. |

## Before engaging an auditor

1. **Name the security owner and the scope.** The system is the managed service; the criteria are Security, plus Availability and Confidentiality if customers' contracts rely on them. Write the system description from the [architecture](architecture.md) and [data flows](data-flows.md) pages, and name the hosting and storage providers as carved-out subservice organisations.
2. **Adopt the policy set** (CC5.3-1) and the incident response plan (CC7.4-1), approved by management. Most CC1 to CC5 rows close with them.
3. **Close or accept every product gap.** Each row above is either closed with code and tests, or accepted in the risk register (CC3.2-1) with a compensating control. Auditors expect at least MFA for staff (CC6.1-1 or CC6.1-2), access reviews (CC6.3-1, CC6.3-2), vulnerability management (CC7.1) and branch protection evidence (CC8.1-1).
4. **List the complementary user entity controls**: what customers must do for the controls to work, such as enforcing MFA at their IdP and reviewing who has access. The **Customer** rows of the [control mapping](soc2-control-mapping.md) are the start.
5. **Run a readiness assessment** with the chosen CPA firm or a consultant, and the external penetration test (CC3.2-2), and fix what they find.
6. **Start collecting evidence** from the day policies are adopted, in the "Evidence to collect" column: a Type II report can only cover the time evidence exists for.

## Type I and Type II

A **Type I** report says whether controls are suitably designed at one date. A **Type II** report says whether they also operated effectively over an observation period, commonly 3 to 12 months, and is what most enterprise buyers ask for. The [roadmap](../ROADMAP.md#compliance-path-not-promises) puts this readiness checklist in M4 and the Type II programme in M5. A Type I can come first once the process rows are done; a Type II needs those controls running, with evidence, for the whole period, so evidence collection should start as soon as each control is in place, not when the auditor arrives.
