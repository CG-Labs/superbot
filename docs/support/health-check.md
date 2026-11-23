# Monthly health check

What the technical account manager (TAM) checks each month for an Enterprise customer, in about an hour ([TAM programme](tam.md#cadence)). On a managed or dedicated deployment the Provider runs the commands; on a self-hosted one, the customer's admin runs them and shares the output, or a [support bundle](support-bundle.md) (which has the health score in it). Record the score, and anything not ticked, in the customer's record, not here.

## 1. The score

- [ ] `botctl health-score` for the last 30 days. Note the score, the band and each signal's status ([what they mean](health-score.md)).
- [ ] Compared with last month's (`botctl health-score history --days 31`): which signal moved, and why.
- [ ] Each signal at risk has a ticket or an action with an owner and a date; each at watch is on the next check-in's agenda.

## 2. The deployment

- [ ] Version: `botctl whoami` answers, and the [changelog](../../CHANGELOG.md) has no release since theirs with a security fix they lack. If it does, agree an upgrade window ([air-gapped](runbook-air-gapped.md) servers need the bundle carried in).
- [ ] Setup: `botctl setup` has nothing open that was done at go-live.
- [ ] Status: `/status.json` shows no open incident, and last month's incidents have their reviews ([escalation](escalation.md#after-a-severity-1)).

## 3. Identity

- [ ] Sign-in: the score's `identity` reasons. Anything new goes to the [sign-in](runbook-sign-in.md) or [SAML](runbook-saml.md) runbook.
- [ ] SAML (if used): `botctl sso saml <provider>` shows each IdP certificate's expiry; one within 60 days is in the customer's record, with who rotates it.
- [ ] SCIM (if used): `botctl scim tokens` lists the tokens in use, and the IdP's provisioning log shows no errors. People who left are disabled.
- [ ] Roles: `botctl roles` matches what the customer expects; anyone with a custom role across the server still needs it ([roles runbook](runbook-custom-roles.md)).
- [ ] Access review: the customer signed one off this quarter (`/api/access-review`, [ADR 0099](../adr/0099-access-review-report.md)), if their policy asks.

## 4. Data and backups

- [ ] `botctl backups`: the newest copy off the host is within its RPO.
- [ ] `botctl machine recovery` (managed machines): nothing past its RPO; last restores within the RTO.
- [ ] Residency (if pinned): `botctl regions` shows no residency warnings ([residency runbook](runbook-residency.md)).
- [ ] The next restore drill is booked ([TAM cadence](tam.md#cadence)).

## 5. Bots and machines

- [ ] Runs: the score's `runs` signal; failures by harness against the [harness runbook](runbook-harness-outage.md).
- [ ] Run limits and allow-lists (if used): `botctl machine egress` is what the customer agreed; no `egress_policy_pending` refusals or many `machine.run_limited` events ([runbook](runbook-run-limits-egress.md)).
- [ ] Approvals: the score's `approvals` signal; the policy (`botctl policy`) still fits how they work ([approvals runbook](runbook-approvals-stuck.md)).
- [ ] Usage: `botctl usage` against the plan's limits; anyone at a limit every month may need another tier.

## 6. The account

- [ ] License (self-host): `botctl license` end date and seats; a renewal within 90 days is with the account owner.
- [ ] Open tickets: none past their response target, none open for more than a month without a plan.
- [ ] Anything from the customer since last time: changes to their IdP, network, team or plans that SuperBot should know about.

## Afterwards

Send the customer's owner a short note: the score and band, what changed, and what's being done, with owners and dates. Keep the full checklist for the [quarterly review](qbr-template.md).
