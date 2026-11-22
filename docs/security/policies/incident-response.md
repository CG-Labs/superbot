# Incident response plan

How a managed SuperBot provider finds, rates, contains, fixes, tells people about and learns from security incidents and outages. Part of the [policy set](README.md). **Draft, not adopted. SuperBot is not SOC 2 certified.**

| Field | Value |
|-------|-------|
| Owner | Security owner |
| Approver | Management |
| Review | Yearly, after every SEV-1 or SEV-2 incident, and after the yearly tabletop exercise |
| Status | Draft, not yet approved |
| Controls | CC2.3-1, CC2.3-2, CC4.2-1, CC7.2-1, CC7.3-1, CC7.4-1, CC7.4-2, CC7.5-1 |

## What counts as an incident

A **security event** is anything that might affect the confidentiality, integrity or availability of the service or customers' data: an alert, a report, an odd audit entry. An **incident** is an event that has, or very likely has, done so. A **personal data breach** is an incident that leads to the accidental or unlawful destruction, loss, change, disclosure of or access to personal data; it has its own notice duties ([communication](#communication)).

Everyone in scope reports a suspected incident at once to the security owner or the on-call operator, and doesn't investigate on their own beyond keeping evidence.

## Severity levels

The incident commander sets the severity at triage and changes it as facts emerge. When in doubt, choose the higher one.

| Severity | Meaning | Examples | Respond within | Updates |
|----------|---------|----------|----------------|---------|
| SEV-1 Critical | Confirmed or very likely compromise of customer data or of the service's keys, or the service down for everyone | Isolation between users broken in production; the master key, a backup age identity or a hosting provider token leaked; an exploited vulnerability; data lost beyond the recovery objectives; the API down for all customers | 15 minutes, any hour | Hourly to management and on the status page; customers as below |
| SEV-2 High | A likely compromise limited in reach, or a major loss of function | An admin or SSO tenant compromised; a Critical or High vulnerability exploitable from the internet, not yet exploited; a lost Incus host; many machines past their RPO; one component down for all customers | 1 hour, any hour | Every 4 hours to management; status page if customers notice |
| SEV-3 Medium | A contained event affecting one customer or user, or a weakness with limited exposure | One user's account taken over and stopped; a leaked secret of one customer, rotated; a Medium vulnerability; one machine's restore past its RTO | 1 business day | Daily until closed |
| SEV-4 Low | No impact found, or a minor weakness | A burst of failed sign-ins that stopped; a false positive; a Low vulnerability; a policy breach with no exposure | 5 business days | At closing |

"Respond within" is from the first alert or report to a named incident commander working on it. Vulnerabilities are also held to the fix deadlines in the [information security policy](information-security.md#vulnerability-management) and [`SECURITY.md`](../../../SECURITY.md).

## Roles

| Role | Who | Does |
|------|-----|------|
| Incident commander | The security owner, or the on-call operator until they take over | Sets the severity, leads, decides, approves emergency changes ([change management](change-management.md#emergency-changes)), closes the incident. |
| Operations | The operator | Contains and recovers: SuperBot admin actions, hosts, backups. |
| Engineering | The engineering lead | Finds the cause in the code, writes and ships the fix. |
| Communications | The privacy lead for data breaches; otherwise the operator | Status page, customer notices, regulators' questions, the reporter. |
| Scribe | Anyone the commander names | Keeps the timeline: what was seen, decided and done, and when (UTC). |

For SEV-3 and SEV-4 one person may hold every role. The private policy register names the people and an out-of-hours contact for each role.

## Runbook

### 1. Detect

Sources the product already gives the operator:

- **Audit events** ([ADR 0009](../../adr/0009-audit-events.md)): `auth.suspicious_sign_in` for bursts of failed sign-in, code and second-factor guesses and admins on a new network ([ADR 0104](../../adr/0104-suspicious-sign-in-alerts.md)); `scim.auth_failed`; `policy.denied` and `bot.run_refused`; `machine.hardening_failed` and `machine.reboot_required` ([ADR 0126](../../adr/0126-per-user-machine-hardening.md)); `machine.rpo_breached`, `server.backup_rpo_breached`, `machine.restore_failed`, `machine.host_down` and `machine.host_lost`. Search them with `botctl audit --action <action>`.
- **Alerts** by email or webhook for RPO breaches, failed or slow restores, hosts not answering and suspicious sign-ins at one account ([`server/src/notify/mod.rs`](../../../server/src/notify/mod.rs)), and the Prometheus rules in [`deploy/prometheus/`](../../../deploy/prometheus/) for the SLO, errors, sign-ins, capacity and backups.
- **Error reports** to a Sentry-compatible tracker, when `ERROR_REPORT_DSN` is set ([ADR 0113](../../adr/0113-service-dashboards-and-error-reporting.md)).
- **Reports** from outside under [`SECURITY.md`](../../../SECURITY.md), from customers, from vendors, and from CI's dependency and image scans.

### 2. Triage

1. Open an incident record in the provider's private tracker (for a vulnerability report, the GitHub security advisory too) with what was seen, when, and by whom.
2. Name the incident commander, set the severity, and decide whether it may be a personal data breach. If it may be, start the breach clock: the time the provider became aware.
3. Bring in the roles the severity needs.

An event that turns out not to be an incident is closed in the record with the reason, so every security event has a ticket.

### 3. Keep evidence

Before changing anything that would destroy it:

- Export the audit log for the period: `botctl audit export --from <time> --to <time> > incident-<id>-audit.csv`. Check `botctl retention`: if `AUDIT_RETENTION_DAYS` would delete events still needed, raise it until the incident is closed.
- Hold the chats and files of Bots involved out of retention: `botctl retention hold <bot> "<incident id>"` ([ADR 0098](../../adr/0098-chat-retention.md)).
- Copy the newest server backup off the host: `botctl backups copy`; for a machine, back it up before rebuilding it (`botctl machine backup <user>`).
- Keep host logs and the hosting provider's records the provider can export.

Evidence goes in the incident record's restricted folder, never in this repository or a public issue.

### 4. Contain

Pick the playbooks that fit; every command is audited.

| Situation | Contain with |
|-----------|--------------|
| A user's account is compromised | `botctl user disable <user>`: ends their sessions, stops their runs and queued messages, and suspends their machine when `MACHINE_ON_DISABLE=suspend`, the default and the [baseline](information-security.md#configuration-baseline) ([ADR 0124](../../adr/0124-deprovisioning-stops-bots-and-machines.md)). Confirm it with `botctl machine show <user>`; if it is still running (`keep`), run `botctl machine suspend <user>`. For SSO, also block them at the IdP. Check what they did: `botctl audit --actor user:<email>`. |
| An admin or an IdP connection is compromised | As above for the admin; `botctl session revoke-all <user>` for anyone they may have handed a session; `botctl scim token revoke <id>` and rotate the SSO client secret at the IdP; review admins with the access-review report. |
| A saved secret has leaked | Revoke it at its issuer first, then replace it (`botctl secret set <NAME> < file`) or delete it (`botctl secret rm <NAME>`). |
| The master key may have leaked | Rotate it and everything it protected, following [after a leak](../../ops/master-key-rotation.md#after-a-leak) ([ADR 0096](../../adr/0096-master-key-rotation.md)). |
| A machine may be compromised | `botctl machine revoke <user> --yes` cuts its certificates; `botctl machine suspend <user>` powers it off. Recover it by `botctl machine rebuild <user>` or by restoring a backup from before the compromise. |
| A Bot is doing harm | Stop its run (Stop in the app, `POST /api/bots/{id}/stop`), then disable its owner or make sure its policy isn't `bypass` and set the risky classes it used to `deny` (`botctl policy set <bot> mode=ask <class>=deny`). Bots can't approve their own actions ([ADR 0007](../../adr/0007-approvals.md)). |
| A host or the server is lost | Follow the [business continuity plan](business-continuity.md#scenarios). |
| A vulnerability is being exploited | Turn off the affected feature by its setting if it has one, block at Caddy or the provider firewall, and ship the fix as an emergency change. |

### 5. Eradicate and recover

Remove the cause (fix the code, patch the host, rotate every credential the attacker could have read), restore from a clean backup if needed, and check the service is healthy and the server matches the [configuration baseline](information-security.md#configuration-baseline). Watch the same signals more closely for at least two weeks.

### 6. Close

The commander closes the incident when it's contained and recovered, notices are sent, and the review is scheduled. The record keeps the severity, the timeline, the evidence, the notices and the actions.

## Communication

| Who | When | How |
|-----|------|-----|
| Management | SEV-1 and SEV-2 at once, then at each update interval | Directly, by the commander |
| Customers, for an outage | Within 15 minutes of confirming it, then at least hourly until resolved, as the [SLO](../../slo.md#status-page-and-incidents) commits | An incident on the status page ([ADR 0090](../../adr/0090-status-page-and-uptime-slo.md)); it shows no customer data, hostnames or errors |
| Customers, for a personal data breach | Without undue delay and within `[N] hours` (48 suggested) of becoming aware, as the [DPA](../dpa-template.md#8-personal-data-breaches) commits, with what is known and more as it is learned | To each affected customer's notice contact, by the privacy lead |
| Regulators and data subjects | The customer, as controller, decides and notifies (72 hours under GDPR Article 33); the provider helps with the facts | Through the customer; the provider notifies a regulator itself only for its own data as controller |
| Customers, for other security incidents that affect them | SEV-1 and SEV-2 within `[N]` business days, with what happened and what they should do | Email, and the status page if many are affected |
| The reporter of a vulnerability | Acknowledge within 3 days, update at least every 14, as [`SECURITY.md`](../../../SECURITY.md) says | The GitHub security advisory |
| The public | Only through the communications role, after management agrees | Status page, security advisory, release notes under **Security** |

Notices say what happened, when, what data and customers it affects, what the provider has done, what the customer should do, and who to contact. They name no individual on the provider's side, and no other customer.

## Post-incident review

- Every SEV-1 and SEV-2, every personal data breach, and every outage that spent more than a quarter of the error budget (the [SLO's error budget policy](../../slo.md#error-budget-policy)) gets a written review within 10 business days of closing. SEV-3 incidents get a short one in the record.
- Reviews are blameless: they look for what let the incident happen and what would stop it next time, not for someone to blame.
- Each review has: summary and impact; the timeline; how it was detected and how long that took; the cause; what went well and what didn't; and actions, each with an owner and a due date, tracked as issues to closure.
- Reviews feed the risk register and are listed in the quarterly management review. An availability incident's review is linked from its status page note.

## Testing the plan

A tabletop exercise at least yearly, with every role, on a scenario such as a leaked master key, a compromised admin, a lost Incus host or a breach in a model provider. The exercise is recorded like a review, and its actions tracked. Containment commands are tried on a non-production server at the same time.
