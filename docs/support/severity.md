# Severity and response targets

How support sizes a ticket, and how fast each plan hears back. The customer suggests a severity; support sets it from the definitions below and says why if it differs. It can change as more is known, both ways. Plans and channels: [support tiers](tiers.md).

## Severities

| Severity | Meaning | Examples |
|---|---|---|
| **1: Critical** | The service is down or unusable for most of the customer's people, data is lost or exposed, or a security incident is suspected. No workaround. | The server or `/status.json` doesn't answer; nobody can sign in; a restore lost data beyond the RPO; a token or key leaked; Bots act without approval when policy says ask |
| **2: High** | A major function fails for many people, or for one critical workflow, and there's no reasonable workaround. The service is degraded but up. | SSO fails for one identity provider while break-glass works; a whole Incus host is down; Hermes runs fail for everyone; approvals reach nobody, so Bots wait; backups past their RPO |
| **3: Normal** | Part of a function fails, or one person or Bot is affected, and there's a workaround. | One user's machine won't start; one person can't sign in; a routine misfires; a non-Hermes harness fails (best effort, [tiers](tiers.md#harnesses)) |
| **4: Low** | A question, how-to, cosmetic issue, documentation gap or feature request. | How to set up SCIM; a typo in the console; asking for a new IdP |

Severity 1 and 2 are for production. A test or staging server's outage is Severity 3 at most, unless the agreement says otherwise.

Severity 1 needs someone on the customer's side reachable while it's worked on. If nobody is, support carries on and the ticket can drop to Severity 2.

## Response targets

The time from a ticket arriving to a person (not an auto-reply) answering with a first assessment. "h" counts clock hours; "business h" and "business days" count only [business hours](tiers.md#per-plan).

| Severity | Self-host (licensed) | Starter | Pro | Max | Enterprise |
|---|---|---|---|---|---|
| 1 | 1 business day | 4 business h | 1 h, 24×7 | 1 h, 24×7 | By agreement (default 30 min, 24×7) |
| 2 | 2 business days | 1 business day | 4 business h | 2 business h | By agreement (default 2 h, 24×7) |
| 3 | 3 business days | 2 business days | 1 business day | 1 business day | By agreement (default 4 business h) |
| 4 | 5 business days | 5 business days | 3 business days | 2 business days | By agreement (default 1 business day) |

## Updates until it's fixed

| Severity | Updates | Where |
|---|---|---|
| 1 | At least hourly, around the clock while it's worked on | The ticket, and `<status-page-url>` when the service or many customers are affected ([SLO](../slo.md#status-page-and-incidents)) |
| 2 | Every 4 hours during the plan's support hours | The ticket |
| 3 | Every business day while there's news, at least every 3 business days | The ticket |
| 4 | When there's news | The ticket |

Each update says what's known, what's being done, and when the next update comes. Late updates on tickets are counted in the [support report](support-report.md#update-targets) from the ticket system's export of replies (`botctl support-report --updates`); the status page's are in each [incident review](incident-review.md#the-review-draft). A ticket closes when the customer confirms the fix, or 5 business days after a proposed fix with no reply.

## Targets, not resolution times

These are response targets. Resolution depends on the cause; for an outage the [SLO](../slo.md) and the plan's [RPO and RTO](../security/machine-recovery-objectives.md) are the commitments. Severity 1 and 2 are worked continuously during the plan's hours (Severity 1 around the clock where the plan has it) until there's a fix or a workaround, after which the ticket can drop a level.

A response target is missed when the first human answer is late; misses are counted per month in the Provider's [support report](support-report.md) (`botctl support-report`). Only a written agreement turns these targets into an SLA with credits; until then, they are what the Provider runs to, like the SLO's objectives.

## Enterprise defaults

The Enterprise column above is the starting point for the order form. Agree, and write down:

1. Response and update targets for each severity, and which are 24×7.
2. The channels, including whether there's a shared chat channel and an on-call line (`<on-call-line>`), and who on the customer's side may raise Severity 1.
3. Which harnesses the SLA covers (Hermes Agent by default; others best effort, [tiers](tiers.md#harnesses)).
4. Maintenance windows, and how far ahead upgrades on their deployment are announced (at least the SLO's 48 hours).
5. Service credits, if any, set below the objective as the [SLO](../slo.md#objectives) advises.
