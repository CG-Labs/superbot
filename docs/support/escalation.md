# Escalation

Who works a ticket, who it goes to next, and when. Roles, not people: the Provider fills in the placeholders with its own rota and keeps them current, and checks the rota covers the hours its plans sell with `botctl support-readiness` ([support readiness](readiness.md#the-on-call-rota)). Severity and targets: [severity](severity.md).

## Inside the Provider

| Level | Role | Takes the ticket when | Reached through |
|---|---|---|---|
| 1 | Support engineer | Every new ticket: triage, severity, first response, the [runbooks](README.md#the-playbooks) | `<support-email>`, `<support-portal-url>` |
| 2 | On-call engineer | Severity 1 at once; Severity 2 that a runbook doesn't fix within 2 hours; any page alert ([SLO alerts](../slo.md#alerts)) | `<on-call-pager>` |
| 3 | Engineering owner of the component (server, machines, harness adapters, sign-in, billing) | Level 2 needs a code change, a data repair, or a decision outside the runbooks | `<engineering-escalation>` |
| Incident commander | One named person for each Severity 1, usually the on-call engineer until handed over | Every Severity 1, from the first minute | `<incident-channel>` |
| Management | `<support-manager>`, then `<engineering-manager>` | A Severity 1 past 2 hours without a workaround; any data loss or security incident; a customer escalation (below) | `<escalation-email>` |

The incident commander owns the status page note, the hourly updates and the customer's Severity 1 ticket, and hands work to others rather than doing it. They decide when the incident is over. Their steps: [running a Severity 1](runbook-major-incident.md); the status page from the server's shell: `botctl incident` ([incidents](incident-review.md#posting-and-updating)).

### Timed escalation

- **Severity 1**: on-call engineer at once; management at 2 hours without a workaround; a written review afterwards (below).
- **Severity 2**: on-call engineer after 2 hours in the runbook without progress, or at once outside business hours on plans with 24×7 Severity 1 if it is getting worse.
- **Severity 3 and 4**: level 3 only for a confirmed bug, through the issue tracker. The ticket links the issue.
- **A response target about to be missed**: the support engineer tells the support manager before it is, not after.

### Security incidents

A suspected breach, leaked secret or cross-tenant exposure is Severity 1 and goes to `<security-email>` and the incident commander at once, whoever raised it. Follow the Provider's incident response plan and the breach notice terms in its DPA ([template](../security/dpa-template.md)). Support doesn't discuss details on an open ticket until the security lead says what may be shared.

## Outside the Provider

Some causes belong to someone else. Support still owns the ticket and keeps the customer updated.

| Cause | Who | How |
|---|---|---|
| Hermes Agent defect at the pinned release | Its maintainers, upstream | An upstream issue, linked from the ticket; pin bumps follow [ADR 0075](../adr/0075-hermes-upgrades.md) |
| Other harness CLIs (Claude Code, Codex, Pi) | Their vendors | The vendor's support or issue tracker; best effort ([tiers](tiers.md#harnesses)) |
| Model provider outage | The provider | Its status page; see the [outage runbook](runbook-harness-outage.md) |
| Machine hosting (Linode, the Incus hosts' provider) | The hosting provider | Its support, with the machine's id from `botctl machine show <user>` |
| The customer's identity provider | The customer's IdP admin | Through the customer; see the [sign-in runbook](runbook-sign-in.md) |

## For customers

If a ticket isn't moving as it should:

1. Reply on the ticket asking for it to be escalated, and say why (impact grew, a target was missed, the fix didn't work). Support raises it a level and answers within the ticket's response target.
2. Enterprise: contact your [technical account manager](tam.md) (`<tam-email>`), who can pull in any level.
3. If that doesn't resolve it, write to `<escalation-email>`, quoting the ticket number. A manager answers within one business day.

## After a Severity 1

Within 5 business days, the incident commander writes a review: timeline in UTC, impact, cause, what went well and badly, and actions with owners. `botctl incident review <id> --detected <time>` drafts it from botd's records: the status page timeline, botd's starts and configuration changes around it, what failed while it lasted, and whether the status page's targets were kept ([incident reviews](incident-review.md)). It's linked from the status page note, as the [error budget policy](../slo.md#error-budget-policy) asks, and shared with affected Enterprise customers. Runbooks the review changes are updated in this folder.
