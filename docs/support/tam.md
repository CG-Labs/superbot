# Technical account manager programme

Enterprise customers get a named technical account manager (TAM): one person at the Provider who knows their deployment, joins their onboarding, runs their success cadence and is their way in when something goes wrong ([tiers](tiers.md#what-each-plan-covers)). This page is what a TAM does, and when. The Provider fills in the placeholders and keeps who covers which customer in its support system, never in this repository.

## Who gets one

Every Enterprise agreement names a TAM (`<tam-name>`, `<tam-email>`) and a backup TAM (`<backup-tam-name>`) who covers holidays and absences. Other plans don't have one; their customers get the same playbooks from support. A Provider may offer a TAM to a large self-host customer by agreement; this page then applies to them too.

A TAM covers at most `<tam-accounts-per-person>` Enterprise customers, so each one gets the cadence below. `botctl support-readiness --tams` checks the Provider's TAM list for a customer without a TAM or a different backup, and a TAM over that number ([support readiness](readiness.md#the-tam-list)). When a customer moves to another TAM, the old one writes a handover (below) and joins the next check-in to introduce the new one.

## What a TAM does

- **Knows the deployment.** Where it runs (dedicated, VPC or on-premises, connected or [air-gapped](../ops/air-gapped.md)), its version, identity provider and SCIM, isolation, data regions and residency pins, backups and their RPO, harnesses and model providers, custom roles, and outbound allow-lists. Kept in the customer's record, from the [onboarding checklists](onboarding.md) and the [health check](health-check.md).
- **Leads onboarding** from kickoff to go-live ([onboarding](onboarding.md)), with the customer's owner.
- **Runs the cadence**: check-ins, monthly health checks and quarterly business reviews (below).
- **Is the escalation point.** The customer can ask their TAM to pull in any level ([escalation](escalation.md#for-customers)). On a Severity 1, the TAM joins the incident channel, keeps the customer's sponsor informed beside the incident commander's updates, and joins the review.
- **Speaks for the customer inside the Provider**: brings their feature requests to the roadmap with the business reason, and their open tickets to the support manager when they stall.
- **Plans changes with them**: upgrade windows for their deployment, release notes that need action, and settings that change behaviour (a new egress rule, a residency pin, a role change).

A TAM doesn't replace support: tickets still go to `<support-email>` or `<support-portal-url>` and are worked to their [severity](severity.md) targets, whoever is on holiday. A TAM never needs the customer's passwords, tokens or keys, and never asks for them.

## Cadence

| When | What | With | Output |
|---|---|---|---|
| Within 5 business days of signing | Kickoff ([agenda](#kickoff-agenda)) | The customer's owner, IdP admin and security contact | Onboarding plan and dates, in the customer's record |
| Weekly until go-live | Onboarding check-in: the checklists' open items (`botctl onboarding`, [onboarding check](onboarding-check.md)), blockers | The customer's owner | Updated checklists |
| Week 1 after go-live | Check-in: sign-in, approvals, first runs, open tickets | The customer's owner and pilot team | Issues raised as tickets |
| Monthly | [Health check](health-check.md) (`botctl health-check` judges it from botd's records), with the [health score](health-score.md) | The TAM alone, then a short call with the customer's owner if anything is watch or at risk | Score and notes in the customer's record |
| Quarterly | [Business review](qbr-template.md) (`botctl business-review` drafts it from botd's records) | The customer's sponsor and owner | The review document, actions with owners |
| Twice a year | Restore drill on their deployment, times recorded against the RTO | The Provider's on-call engineer and the customer's owner | Drill record |
| Before each upgrade | Release notes and any action needed; the change window | The customer's owner | Agreed window |
| Within 5 business days of a Severity 1 | The incident review ([drafted from botd's records](incident-review.md#the-review-draft)), shared and walked through | The customer's owner and sponsor | Actions with owners |

`botctl tam-cadence` checks this cadence across every account from the CRM's export: each kickoff, check-in, health check, business review, restore drill and Severity 1 walk-through overdue or due soon, and each renewal coming up, by account and by TAM ([TAM cadence check](tam-cadence.md)). Record each step's date in the customer's record as it happens, so the check reads what was done.

The health score is a prompt, not a verdict: a TAM who sees a signal at risk calls the customer before the next scheduled check-in (botd [alerts](health-score.md#alerts) when the band falls, a signal goes at risk or the score falls 10 points below the last check, and the Provider's Prometheus can route the same to the TAM), and a TAM who knows something the score can't (a reorganisation, a merger, a champion leaving) acts on that too.

## Kickoff agenda

1. Introductions: the TAM, the backup TAM, the customer's owner, IdP admin, security contact, and who may raise Severity 1.
2. What they bought: plan, seats, support tier and the Enterprise targets in the order form ([severity](severity.md#enterprise-defaults)).
3. The deployment: where it runs, who operates it, network limits (air-gapped, proxies, an outbound allow-list), and the data region.
4. The [onboarding checklists](onboarding.md), who does each part, and the dates. Run `botctl onboarding` on their server to see what's already done, and agree which items they don't need ([skips](onboarding-check.md#running-it)).
5. The pilot team and what success looks like for them in the first month: who uses it, for what, and how they'll tell.
6. How to get help: channels, severity, escalation, the status page, and a first [support bundle](support-bundle.md) made together.
7. The cadence above, and the first dates in calendars.

## Handover

When a customer changes TAM, or the TAM is away for more than two weeks, write in the customer's record:

- the deployment summary (from the health check's first section);
- the last health score, its signals at watch or at risk, and what's being done;
- open tickets, open incident actions, and promises made (a feature, a date, a call);
- the people and how they like to work (channel, meeting times, who decides);
- upcoming dates: renewal, license end, upgrade windows, the next review.

### Draft it first

`botctl tam-handover` drafts this note from botd's records, so the outgoing TAM's time goes on what only they know: tickets, promises and the people.

```sh
# The handover note in Markdown, for the customer's record
botctl tam-handover -o handover.md

# For a CRM or the support system's hook
botctl tam-handover --json
```

| Option | What it does |
|---|---|
| `--json` | The draft as botd sends it, from `GET /api/support/tam-handover` (admins only), instead of Markdown |
| `-o <file>` | Save it, readable by you only, instead of printing it |

It runs on the customer's server, signed in as an admin (`SUPERBOT_TOKEN`, or the password); on a self-hosted one, the customer's admin runs it and sends the file. The console's Support tab has the same as **Draft TAM handover**. It covers the deployment as it is when drafted, so draft it on the day of the handover. Each draft is recorded in the audit log as `support.tam_handover_drafted`, with the score, the open item ids, the number of incidents and the dates overdue; it isn't recorded as a monthly health check. Design: [ADR 0278](../adr/0278-tam-handover-draft.md).

| Section | From botd's records | Left to fill in |
|---|---|---|
| 1. The deployment | botd's version, single sign-on providers by id and kind, SCIM and its working tokens, custom roles and who holds one, machines and data regions, backups, the approvals policy, Bots by harness, people active and licensed seats, the license | Where it runs and who operates it, the IdP's admin and MFA, model provider accounts, the network |
| 2. Health | The [health score](health-score.md) and band now, each signal at watch or at risk with its summary, the last month's trend, the last [health check](health-check.md) (`support.health_checked`) with its open items, and the last [business review](qbr-template.md) draft | What's being done about each signal |
| 3. Open work | Every item the health check finds open now, with what botd sees and its guide; status page incidents still open, or major or critical in the last 92 days with no [review](incident-review.md#the-review-draft) drafted | Open tickets (`botctl support-report`), open incident actions, promises made |
| 4. The people | Nothing: botd names nobody | All of it, by role |
| 5. Upcoming dates | The license's end, native SAML certificates ending within 60 days, SCIM tokens ending within 14 days, the next monthly health check (31 days after the last), the next quarterly review (the month after the quarter that follows the last draft's) and the next access review (92 days after the last), each marked when overdue | The renewal, upgrade windows, the next restore drill and check-in |

The draft holds codes, counts, dates, provider ids, harness names, region ids and incident ids: never a person's name or email, a Bot's name, an incident's title, an address or a bucket.

## Records

Everything about a customer (contacts, the onboarding record, health checks, reviews, handovers) is kept in the Provider's support system or CRM, with access limited to the people who work with them. Not in this repository, not in a ticket other customers' staff can see, and not in a Bot's chat. The health score, onboarding check, health check and support bundle carry no personal data, so they can be attached; anything copied from the console or the audit log can, so trim it first.
