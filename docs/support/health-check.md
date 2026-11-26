# Monthly health check

What the technical account manager (TAM) checks each month for an Enterprise customer, in about an hour ([TAM programme](tam.md#cadence)). On a managed or dedicated deployment the Provider runs the commands; on a self-hosted one, the customer's admin runs them and shares the output, or a [support bundle](support-bundle.md), which has the health score and this check in it ([below](#in-the-support-bundle)). Record the score, and anything not ticked, in the customer's record, not here.

Start with `botctl health-check` ([below](#run-it-first)): it judges every item of this checklist from botd's own records, so the hour goes on what's open and what only a person can confirm.

## Run it first

```sh
# Section by section, then what's open
botctl health-check

# For the customer's record, as a Markdown checklist
botctl health-check markdown > health-check-2027-02.md

# For a CRM or ticket system's hook
botctl health-check json
```

| Option | What it does |
|---|---|
| `markdown` | A checklist per section for the customer's record: ticked when done, struck through when it doesn't apply, and each open item with its guide. `--markdown` works too |
| `json` | The report as botd sends it, from `GET /api/support/health-check` (admins only). `--json` works too |

It runs on the customer's server, signed in as an admin (`BOTD_TOKEN`, or the password), prints the report on stdout and exits 1 while any item is open, so a monthly job can raise a task. The console's Support tab does the same with **Run health check**; it runs only when pressed, not when the tab opens. Each check is recorded in the audit log as `support.health_checked`, with the score, the band, the counts and the open ids, so the monthly cadence shows in the log. Design: [ADR 0252](../adr/0252-monthly-health-check.md).

Each item is one of:

| Status | Means | What to do |
|---|---|---|
| `done` | botd sees nothing to act on | Tick it |
| `open` | botd sees something to act on this month | Follow the detail and the guide; give it an owner and a date in the customer's record |
| `confirm` | botd can't see it: it's at the identity provider, in the ticket system, or a person's to judge | Check it with the customer, then tick it |
| `n/a` | It doesn't apply to this server, like SAML certificates with no native SAML provider | Nothing |

Details are codes, counts, provider ids and incident ids: never a person's name or email, an incident's title, an address or a bucket. So the report can go in the customer's record as it is. What botd reads for each item is [at the end](#what-botd-reads).

## 1. The score

- [ ] `botctl health-score` for the last 30 days. Note the score, the band and each signal's status ([what they mean](health-score.md)).
- [ ] Compared with last month's (`botctl health-score history --days 31`): which signal moved, and why.
- [ ] Each signal at risk has a ticket or an action with an owner and a date; each at watch is on the next check-in's agenda.

## 2. The deployment

- [ ] Version: `botctl whoami` answers, and the [changelog](../../CHANGELOG.md) has no release since theirs with a security fix they lack. If it does, agree an upgrade window ([air-gapped](runbook-air-gapped.md) servers need the bundle carried in).
- [ ] Setup: `botctl setup` has nothing open that was done at go-live.
- [ ] Status: `/status.json` shows no open incident, and last month's incidents (`botctl incidents`) have their reviews ([escalation](escalation.md#after-a-severity-1), [drafts](incident-review.md#the-review-draft)), with any missed status page target looked into.

## 3. Identity

- [ ] Sign-in: the score's `identity` reasons. Anything new goes to the [sign-in](runbook-sign-in.md) or [SAML](runbook-saml.md) runbook.
- [ ] SAML (if used): `botctl sso saml <provider>` shows each IdP certificate's expiry; one within 60 days is in the customer's record, with who rotates it.
- [ ] SCIM (if used): `botctl scim tokens` lists the tokens in use, and the IdP's provisioning log shows no errors. People who left are disabled. If not, the [SCIM runbook](runbook-scim.md).
- [ ] Roles: `botctl roles` matches what the customer expects; anyone with a custom role across the server still needs it ([roles runbook](runbook-custom-roles.md)).
- [ ] Access review: the customer signed one off this quarter (`/api/access-review`, [ADR 0099](../adr/0099-access-review-report.md)), if their policy asks.

## 4. Data and backups

- [ ] `botctl backups`: the newest copy off the host is within its RPO. If not, the [backups runbook](runbook-backups.md).
- [ ] `botctl machine recovery` (managed machines): nothing past its RPO; last restores within the RTO.
- [ ] Residency (if pinned): `botctl regions` shows no residency warnings ([residency runbook](runbook-residency.md)).
- [ ] The next restore drill is booked ([TAM cadence](tam.md#cadence)).

## 5. Bots and machines

- [ ] Runs: the score's `runs` signal; failures by harness against the [harness runbook](runbook-harness-outage.md).
- [ ] Run limits and allow-lists (if used): `botctl machine egress` is what the customer agreed; no `egress_policy_pending` refusals or many `machine.run_limited` events ([runbook](runbook-run-limits-egress.md)).
- [ ] Approvals: the score's `approvals` signal; the policy (`botctl policy`) still fits how they work ([approvals runbook](runbook-approvals-stuck.md)).
- [ ] Usage: `botctl usage` against the plan's limits; anyone at a limit every month may need another tier.

## 6. The account

- [ ] License (self-host): `botctl license` end date and seats; a renewal within 90 days is with the account owner ([license runbook](runbook-license.md)).
- [ ] Tickets: last month's [support report](support-report.md) for the customer (`botctl support-report <export> --customer "<customer>"`) has no miss without a cause; none open past its response target, none open for more than a month without a plan.
- [ ] Anything from the customer since last time: changes to their IdP, network, team or plans that SuperBot should know about.

## Afterwards

Send the customer's owner a short note: the score and band, what changed, and what's being done, with owners and dates. Keep the full checklist for the [quarterly review](qbr-template.md).

## In the support bundle

Every [support bundle](support-bundle.md) has this check in it as `health-check.json`: the same report as `botctl health-check json`, judged when the bundle is made. A bundle's check isn't recorded as `support.health_checked`, because a bundle made for a ticket isn't the TAM's monthly check, and the cadence above and the [business review](qbr-template.md#draft-it-first) count only those. So a customer's admin can send a bundle instead of running the check and sending its output.

When support triages the bundle ([bundle triage](triage.md)), open items show as `health_check.open` for the TAM, with no severity and each item's guide. The score's items (`score`, `sign_in`, `runs`) and `setup` are left out there, since triage already reports the score's signals and the setup checklist. A native SAML certificate ending with nothing to replace it shows as its own warning, `health_check.saml`, since sign-in through that provider stops the day it ends. Design: [ADR 0271](../adr/0271-health-check-in-the-support-bundle.md).

## What botd reads

Each item of `botctl health-check`, in the checklist's order. The score's window is the last 30 days; "last month" is the last 31.

| Item | botd reads |
|---|---|
| `score` | The [health score](health-score.md): `done` when healthy, `open` at watch or at risk, naming the signals; it says when the audit log keeps less than 30 days |
| `trend` | The score's [history](health-score.md#history) for the last month: `open` when a signal got worse, naming it; `confirm` when botd records too few days or none (`HEALTH_SCORE_HISTORY_DAYS=0`) |
| `actions` | `done` when no signal is at watch or at risk; else `confirm` that each has an action or is on the agenda |
| `version` | Always `confirm`: botd's version, since botd can't see newer releases, connected or air-gapped |
| `setup` | `botctl setup`'s checklist: `open` with the items not done |
| `incidents` | The status page: `open` for an incident still open, or one of `major` or `critical` impact open or resolved last month with no review drafted (`botctl incident review`, audited as `status.incident_reviewed`); by id, never title |
| `sign_in` | The score's `identity` signal: `open` at watch or at risk, `done` when ok, `n/a` with no single sign-on or SCIM |
| `saml` | Each native SAML provider's certificates in use, botd's and the IdP's (ADR 0198): `open` when one ends within 60 days and no newer one of the same kind is in use; `done` otherwise; `n/a` with no native SAML provider |
| `scim` | SCIM tokens, the Google Workspace sync's passes and the score's failed SCIM requests: `open` with no working token and no Google Workspace sync, a sync whose latest pass failed or that had no successful pass in 30 days, a tenant whose tokens have all expired (revoked ones don't count), a tenant whose tokens all end within 14 days, tokens with no request in 30 days, or failed requests; else `confirm` the IdP's provisioning log; `n/a` when SCIM is off |
| `roles` | Always `confirm`: the custom roles, and how many people hold one across the server and how many of those end |
| `access_review` | `access_review.completed` in the audit log: `done` within the last 92 days, else `confirm`, since only some policies ask for one |
| `backups` | Server backups: `open` when they stay on the host, the newest copy off it is past its RPO, or none has been copied yet |
| `machine_recovery` | Users' machines: `open` for a machine past its RPO, a restore last month that took longer than its RTO, or a failed machine backup in the last 30 days; `n/a` with no machines |
| `residency` | `botctl regions`' warnings: `open` with any; `n/a` when the server offers no data regions |
| `restore_drill` | Always `confirm`, with how long ago botd recorded the newest machine restore |
| `runs` | The score's `runs` signal: `open` at watch or at risk, `n/a` with too few runs to judge |
| `egress` | Run refusals while a machine's egress policy was being applied (`egress_policy_pending`): `open` with any; else `confirm` the policy, with how many runs were held to run limits; `n/a` with no machines |
| `approvals` | The score's `approvals` signal: `open` at watch or at risk, or when approvals are off (bypass); else `confirm` the policy |
| `usage` | Runs refused at a plan's limit (`tier_limit`, `tier_token_limit`, `storage_limit`) and monthly token limits reached in the last 30 days: `open` with any, counts only |
| `license` | The score's license facts: `open` with no usable license, in its grace period, ending within 90 days, or with 90% of its seats in use; `n/a` in testing mode with none |
| `tickets` | Always `confirm`: tickets are in the ticket system ([support report](support-report.md)) |
| `changes` | Always `confirm`: ask the customer |
