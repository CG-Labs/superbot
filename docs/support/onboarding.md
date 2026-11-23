# Onboarding and success

How a new customer goes from signed to live, and how they're looked after once they are. Each checklist links the guide that does the work; this page doesn't repeat them. For managed plans the Provider does the server-side items and the customer does the identity provider's; for self-host and Enterprise deployments, agree who does what at kickoff. Tick each box in the customer's onboarding record, not here.

## 1. Kickoff

Within 5 business days of signing (Enterprise: led by the technical account manager).

- [ ] Plan, seats and support tier confirmed ([tiers](tiers.md)); Enterprise targets written into the order form ([severity](severity.md#enterprise-defaults)).
- [ ] Customer contacts: an admin who owns SuperBot, an identity provider admin, a security contact, and who may raise Severity 1. Recorded in the support system, not in this repository.
- [ ] Deployment chosen: managed shared server, a dedicated one, or self-host ([operator guide](../../deploy/README.md)). Self-host has its license key installed (`botctl license`, [ADR 0038](../adr/0038-self-host-license-key.md)).
- [ ] Data region chosen, if residency matters (section 5).
- [ ] The customer has the [security pack](../security/README.md) and, if they need one, the [DPA template](../security/dpa-template.md) and [subprocessors](../security/subprocessors.md).
- [ ] Go-live date and the people who'll use it first (a pilot team is best).

## 2. Identity: SSO and SCIM

- [ ] The identity provider set up from its guide: [Microsoft Entra ID](../sso/entra.md), [Google](../sso/google.md), [GitHub](../sso/github.md), [Apple](../sso/apple.md), [Okta or any OIDC provider](../sso/oidc.md), or [SAML through a bridge](../sso/saml.md).
- [ ] One admin signs in with SSO and the console's setup wizard shows identity done (`botctl setup`).
- [ ] Just-in-time sign-up has an allow-list (allowed domains, tenants or orgs), or is off and people are linked by hand ([ADR 0103](../adr/0103-sso-jit-needs-an-allow-list.md)).
- [ ] MFA required at the identity provider ([OIDC](../sso/oidc.md#require-mfa-at-the-idp), [SAML](../sso/saml.md#require-mfa-at-the-idp)), or SuperBot's own for password sign-in (`AUTH_MFA`).
- [ ] SCIM, if they want people added and removed from their directory: [SCIM guide](../sso/scim.md) ([ADR 0023](../adr/0023-scim.md)), and [groups as teams](../sso/scim.md#groups-as-teams) if they manage teams there ([ADR 0095](../adr/0095-scim-groups-as-teams.md)). Test it by unassigning a test user and checking they're disabled.
- [ ] Break-glass: once every admin signs in with SSO, `AUTH_BREAK_GLASS=0`, and the customer knows how to turn it back on ([after an upgrade](../../deploy/README.md#users-and-sign-in-after-an-upgrade)). Keep the [sign-in runbook](runbook-sign-in.md) handy.
- [ ] Sign-in alerts on ([deploy guide](../../deploy/README.md#metrics-and-logs) and [access control](../security/access-control.md#authentication)).

## 3. Isolation

- [ ] Where Bots run is decided: each user's own machine (managed plans; [Incus containers](../ops/incus-containers.md) or Linode VMs) or one server with a Unix account per user ([`ISOLATION=users`](../../deploy/README.md#one-unix-account-per-user), [ADR 0029](../adr/0029-per-user-isolation.md), [ADR 0037](../adr/0037-per-user-unix-accounts.md)).
- [ ] Machines hardened at first boot (`MACHINE_HARDENING`, on by default, [ADR 0126](../adr/0126-per-user-machine-hardening.md)); plans that promise their own kernel listed in `MACHINE_OWN_KERNEL_TIERS`.
- [ ] Approval policy reviewed with the customer: `ask` for risky classes, the timeout, and who gets notified ([approval notifications](../../deploy/README.md#approval-notifications), [ADR 0061](../adr/0061-approval-notifications.md)).
- [ ] Shared Bots and teams set up as they work ([access control](../security/access-control.md#isolation-between-users)).

## 4. Backups and recovery

- [ ] Server backups run and are copied off the host ([backup and restore](../ops/backup-restore.md), [ADR 0109](../adr/0109-server-backups-off-the-host.md)), encrypted ([ADR 0114](../adr/0114-backups-encrypted-by-default.md)); `botctl backups` shows the newest copy within its RPO.
- [ ] The age identity that decrypts them, and the master key ([master key rotation](../ops/master-key-rotation.md)), are stored somewhere other than the server, and two people know where.
- [ ] The database encrypted at rest, if required ([database encryption](../ops/database-encryption.md)).
- [ ] Machine backups on with the plan's RPO: off-host for Incus ([setup](../ops/incus-containers.md#7-off-host-backups-optional)), Linode Backups for Linode ([recovery](../ops/machine-recovery.md#linode-machines)); `botctl machine recovery` shows nothing breaching.
- [ ] A restore drilled before go-live, server and machine ([backup drills](../ops/backup-restore.md#drills), [machine drill](../ops/machine-recovery.md#restore-drill)), with the times recorded against the RTO.
- [ ] The customer has the [recovery objectives](../security/machine-recovery-objectives.md) for their plan.

## 5. Data residency

- [ ] The customer's region set before their first machine: `botctl user region` or `botctl team region`, and `botctl regions` shows no residency warnings ([data regions](../ops/incus-containers.md#data-regions), [ADR 0117](../adr/0117-uk-eu-data-regions.md)).
- [ ] Machine backups stay in the same region (`MACHINE_BACKUP_RESIDENCY`); server backups' bucket is in a region the customer accepts.
- [ ] Model providers and their regions reviewed against the customer's needs ([data flows](../security/data-flows.md), [subprocessors](../security/subprocessors.md)). Self-host customers check [GDPR self-hosting](../security/gdpr-self-hosting.md).

## 6. Monitoring and go-live

- [ ] The status page reachable and an outside probe on `/status.json` ([status page and SLO alerts](../../deploy/README.md#status-page-and-slo-alerts)); the customer knows `<status-page-url>`.
- [ ] Metrics, alert rules and structured logs wired up ([metrics and logs](../../deploy/README.md#metrics-and-logs)); error reports on if wanted ([tracing](../ops/tracing.md)).
- [ ] The setup wizard's checklist complete (`botctl setup`).
- [ ] A first support bundle made and read with the customer, so both sides know what one looks like ([support bundle](support-bundle.md)).
- [ ] The pilot team uses it for a week; their questions go into the first review.
- [ ] Go-live confirmed in writing, with the support channels and escalation contacts.

## Success cadence

| When | What | Who |
|---|---|---|
| Week 1 after go-live | Check-in: sign-in, approvals, first runs, open tickets | Support (Enterprise: TAM) |
| Monthly | [Health check](health-check.md): the [health score](health-score.md), usage against the plan (`botctl usage`), failed runs by harness, approvals waiting, open tickets, SLO and backup report | Enterprise: TAM with the customer's owner |
| Quarterly | [Business review](qbr-template.md): adoption, incidents and their reviews, roadmap items they care about, renewals and seats | Enterprise: TAM and the customer's sponsor |
| Twice a year | Restore drill on their deployment, with times recorded; security pack and DPA refreshed | Provider, shared with the customer |
| Before each upgrade | Release notes and any action needed; change window agreed (Enterprise); the [upgrade runbook](runbook-upgrade.md#before-an-upgrade) | Provider |

Signs a customer needs help before they ask: sign-ins dropping, many approvals expiring unanswered, runs failing on one harness, seats near the license limit (`botctl license`), or repeated Severity 3 tickets on the same thing. Most of these show in the [health score](health-score.md) (`botctl health-score`). Raise them at the next check-in, or sooner. Enterprise customers' TAMs run the fuller cadence in the [TAM programme](tam.md#cadence).
