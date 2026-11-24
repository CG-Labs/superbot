# Information security policy

The umbrella policy for a managed SuperBot service: who is responsible for security, what the service is trying to achieve, and how risks, exceptions, training and breaches of policy are handled. Part of the [policy set](README.md). **Draft, not adopted. SuperBot is not SOC 2 certified.**

| Field | Value |
|-------|-------|
| Owner | Security owner |
| Approver | Management |
| Review | Yearly, and after a significant incident or a change to the service's scope |
| Status | Draft, not yet approved |
| Controls | CC1.2-1, CC1.3-1, CC1.4-1, CC1.5-1, CC2.2-1, CC3.1-1, CC3.2-1, CC3.2-2, CC3.3-1, CC4.1-1, CC4.2-1, CC5.1-1, CC5.3-1 |

## Scope

The managed SuperBot service: the botd server and its database, the per-user machines and the hosts they run on, backups and the stores they go to, the repository and CI that build the service, and the accounts that administer any of them. It applies to everyone the provider gives access to any of these: employees, contractors and anyone else ("personnel"). A self-hoster adopting it replaces "the service" with their install.

## Roles and responsibilities

The roles are the owners in the [readiness checklist](../soc2-readiness-checklist.md#how-to-read-it). The private policy register names who holds each, and a deputy; one person may hold several roles, except where a policy needs two people (the [change management policy](change-management.md#reviews-and-segregation-of-duties) and the [access control policy](access-control.md#granting-access)).

| Role | Responsible for |
|------|-----------------|
| Management | Setting direction and the risk appetite; approving policies; accepting risks and exceptions; appointing the security owner; the quarterly security review. |
| Security owner | Running the security programme and the readiness checklist; owning the risk register; leading incident response; approving access to production; vendor assessments; reporting to management. |
| Engineering lead | The code, CI and releases; reviewing changes; fixing vulnerabilities within the deadlines below. |
| Operator | Running the managed servers, hosts, backups and their settings; the configuration baseline; drills; first response to alerts. |
| People lead | Hiring checks, onboarding and leaving, acknowledgements, training records, discipline. |
| Privacy lead | The privacy policy, DPAs, the subprocessor list, data-subject requests and breach notices to customers. |

## Security objectives

What the service holds itself to. Risks are assessed against these, and the evidence plan measures them.

1. **Customers' data stays theirs.** One user's chats, files, secrets and machine are not reachable by another user or by another customer, except through sharing they chose ([access control and isolation](../access-control.md)). Saved secrets are never returned by the API or written to logs ([ADR 0010](../../adr/0010-secrets.md)).
2. **Bots act only as allowed.** Risky tool calls wait for a person, and are refused when the check can't be made ([ADR 0007](../../adr/0007-approvals.md)).
3. **Every privileged action is accountable.** It is in the audit log with its actor ([ADR 0009](../../adr/0009-audit-events.md), [ADR 0019](../../adr/0019-audit-actors.md)).
4. **The service is available as promised.** Uptime meets the [SLO](../../slo.md) for each plan, and data can be recovered within the [recovery objectives](../machine-recovery-objectives.md) and the server's 1-hour RTO ([ADR 0030](../../adr/0030-backup-restore-drill.md)).
5. **Known vulnerabilities are fixed in time.** Within the deadlines below.

## Risk assessment

- The security owner keeps a risk register: each risk, its owner, likelihood and impact, the controls that treat it, and the decision (reduce, accept, transfer, avoid). Inputs: the [roadmap's risks](../../ROADMAP.md#risks--open-questions), internal reviews such as the [auth review](../auth-review-2026-11.md), penetration tests, incidents, vendor assessments and each ADR's trade-offs.
- The register is reviewed in full at least yearly, and a risk is added or rescored after any SEV-1 or SEV-2 incident, a new vendor that receives customer data, or a change to the service's architecture.
- The yearly assessment includes fraud: how billing, signups, approvals and access could be abused for gain, and the controls against it.
- Accepting a risk above the appetite management sets needs management's approval, recorded in the register with a review date.

## Management review

Management and the security owner meet at least quarterly to review: the checklist's open items, the risk register, incidents and their reviews, vulnerability and access-review status, drills, vendor reviews, and exceptions. Minutes are kept in the register. Until there is an independent body, management names someone not responsible for running the service to review the programme yearly (an internal audit or an outside readiness assessment).

## Configuration baseline

The operator keeps a written baseline of the settings every managed server runs with, and checks each server against it at least quarterly and after every upgrade. It starts from the protections that are off by default: `AUTH_MFA` (at least `admins`), `SUPERBOT_BACKUP_ENCRYPTION=required`, `SUPERBOT_DATABASE_ENCRYPTION=required`, `SERVER_BACKUP_OFF_HOST=on`, `MACHINE_FIREWALL=on` on Linode, `MACHINE_ON_DISABLE=suspend` (the default), `MACHINE_BOT_USER`, `MACHINE_TEAMMATE_USERS`, and the retention periods the [data classification and retention policy](data-classification-and-retention.md#retention) sets. `botctl backups`, `botctl database`, `botctl retention` and the setup checklist show most of them. The baseline, with the value and the check for each setting, is the [configuration baseline](../configuration-baseline.md).

## Vulnerability management

Vulnerabilities from any source (CI scans, reports under [`SECURITY.md`](../../../SECURITY.md), penetration tests, vendors) are tracked with a severity, an owner and a due date, and fixed or accepted with a reason within:

| Severity | Fixed or accepted within |
|----------|--------------------------|
| Critical, High | 30 days |
| Medium, Low | 90 days |

These match `SECURITY.md`, and are counted in calendar days from when the vulnerability is received. One not yet assessed is held to the shortest. CI already fails on fixable Critical image findings and on High npm advisories, and accepted findings are listed with their reasons ([ADR 0092](../../adr/0092-dependency-vulnerability-scanning.md), [ADR 0101](../../adr/0101-image-scanning-and-signing.md), [ADR 0115](../../adr/0115-client-markdown-renderer-and-npm-audit-at-high.md)). One that is being exploited is an incident ([incident response plan](incident-response.md)). Only the security owner or management accepts a vulnerability rather than fixing it. Overdue items go to the quarterly management review; each month's [vulnerability bundle](../soc2-evidence-plan.md#the-vulnerability-bundle) lists the scan findings closed late or overdue against these windows.

The service has an external penetration test at least yearly, the first within a year of this policy's approval. Its Critical and High findings are retested within 30 days of the last of them being fixed, and the retest report kept. Vulnerabilities from outside the CI scans (reports, penetration tests, vendors and internal reviews) and the penetration tests are recorded in the [policy register](../policy-register.md#vulnerabilities-and-penetration-tests), which checks them against these deadlines.

## People

- **Before access:** background checks where the law allows, proportionate to the role, and acknowledgement of this policy, the [acceptable use policy](acceptable-use.md) and the [code of conduct](code-of-conduct.md).
- **Training:** security awareness at onboarding and yearly; incident response roles take part in the yearly tabletop; engineers get secure-development training yearly. The people lead keeps completion records.
- **Leaving:** access removed as the [access control policy](access-control.md#removing-access) says.
- **Accountability:** security duties are part of each role's description and of performance reviews. Breaking a policy, on purpose or through repeated negligence, leads to disciplinary action up to ending the engagement, under the provider's disciplinary process.

## Exceptions

Anyone who can't meet a policy asks the security owner for an exception, in writing, saying why, the risk, any compensating control and an end date of at most a year. Management approves exceptions that accept a risk above the appetite. Exceptions are kept in the register and reviewed quarterly.

## The policy set

This policy and the others in the [set](README.md) are approved by management, reviewed at least yearly, and communicated to everyone in scope. Changes follow the [adoption steps](README.md#adopting-them).
