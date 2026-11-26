# Support

How customers get help with SuperBot, how fast, and how the Provider runs support. "Provider" is whoever runs the SuperBot server, as in the [uptime SLO](../slo.md). These are SuperBot's default playbooks. A Provider fills in the placeholders (`<support-email>` and the like) with its own details, changes the numbers to the ones it can keep, and keeps this folder in step with its contracts. Part of [#60](https://github.com/CG-Labs/superbot/issues/60).

## The playbooks

| Document | What it covers |
|---|---|
| [Support tiers](tiers.md) | What support each plan gets: channels, hours, and who it covers |
| [Severity and response targets](severity.md) | Severity 1 to 4, with examples, and response and update targets per plan |
| [Escalation](escalation.md) | Who a ticket goes to next, when, and how a customer escalates |
| [Escalation check](escalation-check.md) | `botctl support-escalations`: the open tickets the timed escalation rules apply to now, from the ticket system's export, with who to tell: response targets missed or about to be, Severity 1 and 2 past their 2 hours, and late updates |
| [Onboarding and success](onboarding.md) | Getting a new customer live: SSO and SCIM, isolation, backups and residency checklists, then the success cadence |
| [Onboarding check](onboarding-check.md) | `botctl onboarding`: each onboarding checklist item judged from botd's records: done, open with its guide, or for a person to confirm; and whether the customer is ready to go live |
| [Support bundle](support-bundle.md) | `botctl support-bundle`: what it collects, what it never collects, and how to send it |
| [Bundle triage](triage.md) | `botctl support-triage`: the first read of a customer's bundle, offline: what it shows, the severity that suggests, the runbook for each problem, and what to ask next |
| [Support check and the offline bundle](support-check.md) | `botd support check` and `botd support bundle`: diagnostics and a bundle without botd, for a server that won't start, before an upgrade and after a restore |
| [Technical account managers](tam.md) | The named TAM for Enterprise customers: what they do, the cadence from kickoff to renewal, and handover, drafted from botd's records by `botctl tam-handover` |
| [TAM cadence check](tam-cadence.md) | `botctl tam-cadence`: across every account with a TAM, from the CRM's export, the kickoffs, check-ins, health checks, business reviews, restore drills, Severity 1 review walk-throughs and renewals overdue or due soon, by account and by TAM |
| [Customer health score](health-score.md) | `botctl health-score`: six signals from botd's own records, how they're scored, and what to do about each; its daily [history](health-score.md#history), [alerts](health-score.md#alerts) when it falls, and the console's Support tab |
| [Health check](health-check.md) | The TAM's monthly (Enterprise) or quarterly checklist, judged from botd's records by `botctl health-check` |
| [Quarterly business review](qbr-template.md) | The template for the review with the customer's owner and sponsor, drafted from botd's records by `botctl business-review` |
| [Incidents and their reviews](incident-review.md) | `botctl incident`: posting and updating the status page from the server, and `botctl incident review`, a draft of the post-incident review from botd's records |
| [Support report](support-report.md) | `botctl support-report`: tickets by month and severity from the ticket system's export, response targets met and missed, what's still open, and with `--updates` whether tickets were updated as often as promised |
| [Support readiness](readiness.md) | `botctl support-readiness`: contact placeholders left, gaps in the on-call rota for the hours the plans sell, and every Enterprise customer with a TAM and a different backup |

Runbooks for the incidents support sees most:

| Runbook | When |
|---|---|
| [Running a Severity 1](runbook-major-incident.md) | The incident commander's steps: detection, the status page within 15 minutes, hourly updates, resolving, and the review |
| [Sign-in and SSO failures](runbook-sign-in.md) | People can't sign in, with SSO, a password or a code |
| [Machine down or restore](runbook-machine-down.md) | A user's machine, an Incus host, or the server itself is down |
| [Upgrades](runbook-upgrade.md) | Before and after an upgrade, one that left botd down or broken, and going back |
| [Server restore](runbook-server-restore.md) | The server's own data comes back from a backup: a lost host, a damaged database, deleted data |
| [Harness or model provider outage](runbook-harness-outage.md) | Bot runs fail or time out on one harness or provider |
| [Approval queue stuck](runbook-approvals-stuck.md) | Bots wait on approvals nobody sees, or that never resolve |
| [SAML sign-in](runbook-saml.md) | SAML sign-in fails: signatures, certificates, clocks, metadata |
| [Custom roles](runbook-custom-roles.md) | Someone can't do what their role should allow, or can do too much |
| [Residency pins](runbook-residency.md) | A pinned customer's machine, backup or Bot run is refused or lands in the wrong region |
| [Air-gapped installs](runbook-air-gapped.md) | An offline install or upgrade fails, or something tries to reach the internet |
| [Run limits and allow-lists](runbook-run-limits-egress.md) | Runs are held to limits or refused, or a tool can't reach a host |

## Opening a ticket

Customers write to `<support-email>` or open a ticket at `<support-portal-url>`. Enterprise customers can also use their agreed channel (see [tiers](tiers.md#enterprise)). Security issues go to `<security-email>`, never to a public issue tracker.

A good ticket has:

1. **What's wrong**, in a sentence, and the [severity](severity.md) you think it is.
2. **Who and how many** are affected: everyone, a team, one person, one Bot.
3. **Since when**, in UTC, and anything that changed just before (an upgrade, a setting, the identity provider).
4. **What you see**: the error text, and the `X-Request-Id` of a failing request if you have it (every botd response carries one, and it matches botd's log line).
5. **A support bundle** for anything on a self-hosted or dedicated server: `botctl support-bundle` on the server, then attach the file ([how](support-bundle.md)). It has no secrets, chats, names or emails, and it answers most of support's first questions. If botd is down, `botd support bundle` makes one without it ([how](support-check.md)).

Never put a password, token, API key, sign-in code or recovery code in a ticket. If one was sent by mistake, say so and rotate it: support deletes it from the ticket, but treats it as exposed.

Check `<status-page-url>` (the server's `/status`) first: a known incident there is already being worked on and is updated at least hourly.

## For the Provider

- Keep [tiers](tiers.md) in step with the published plans (`/pricing`, from the tiers file, [ADR 0121](../adr/0121-published-plans.md)) and the [SLO](../slo.md). A plan's support line can also go in its `features` in the tiers file, so buyers see it on `/pricing`.
- Name a TAM and a backup for each Enterprise customer before its kickoff ([TAM programme](tam.md)), and keep each TAM's accounts few enough to hold the [cadence](tam.md#cadence). When a customer changes TAM, or its TAM is away for more than two weeks, draft the [handover](tam.md#draft-it-first) with `botctl tam-handover` on the day.
- Run `botctl tam-cadence` on the CRM's export of the accounts each morning ([TAM cadence check](tam-cadence.md#where-it-fits)), and take every overdue kickoff, check-in, health check, business review, restore drill and Severity 1 walk-through to its TAM that day.
- Staff an on-call rota before selling Severity 1 response outside business hours. Response targets are a promise only once the rota exists.
- Check all three with `botctl support-readiness` before selling a plan and each month ([support readiness](readiness.md#when-to-run-it)): the contacts filled in, the rota without gaps, and the TAM list.
- Check each new customer's server with `botctl onboarding` ([onboarding check](onboarding-check.md#where-it-fits)) at kickoff, weekly until go-live, and before confirming go-live: nothing open, and every item to confirm confirmed.
- Run `botctl support-escalations` on the open tickets every few minutes and at each shift handover ([escalation check](escalation-check.md#where-it-fits)), and tell whoever it names: a response target about to be missed goes to the support manager before it is.
- Triage each bundle a ticket brings with `botctl support-triage` ([bundle triage](triage.md#where-it-fits)) before the first response, and paste it into the ticket's internal note.
- Run the [support report](support-report.md#each-month) each month, with the replies export for its [update targets](support-report.md#update-targets), and look into every missed response target and late update.
- Draft each Severity 1's review with `botctl incident review` ([incident reviews](incident-review.md#finishing-the-review)), and look into every missed status page target it flags.
- Review this folder with the rest of the [security pack](../security/README.md) at least once a year, and after any incident whose review changes a runbook.
