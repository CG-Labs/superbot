# Customer health score

One number from 0 to 100 for how a customer's deployment is doing, and the six signals behind it. The technical account manager (TAM) reads it at each [health check](health-check.md) and brings it to the [quarterly business review](qbr-template.md); support reads it when a ticket looks like more than one problem. botd works it out from what it already records, so nothing is sent anywhere and nothing new is collected. Design: [ADR 0144](../adr/0144-tam-programme-and-health-score.md).

## Get it

On the server, as an admin (as for any operator command; `botctl admin` lists them):

```sh
botctl health-score                 # the last 30 days, one line per signal
botctl health-score --days 90 json  # the full report as JSON
```

Or `GET /api/support/health-score?days=30` as an admin. The window is 7 to 90 days, 30 if not given. Members, read-only users, custom roles and Bots get 403. A [support bundle](support-bundle.md) carries the same report for the last 30 days as `health-score.json`.

The report has counts and reason codes only: no names, emails, IP addresses, Bot names, chats or free-text reasons. It can go into a review deck as it is.

## Reading the score

Each signal is **ok** (100 points), **watch** (50) or **at risk** (0), or **n/a** when there's nothing to judge yet. The score is the weighted mean of the signals that aren't n/a, so a new server isn't marked down for runs it hasn't had.

| Band | Score | Means |
|---|---|---|
| Healthy | 80 or more, and no signal at risk | Nothing to chase. Keep the cadence |
| Watch | 50 to 79, or 80 or more with a signal at risk | Raise it at the next check-in, sooner for a signal at risk. Open a ticket for anything a runbook fixes |
| At risk | below 50 | Contact the customer's owner this week with a plan, and tell the support manager ([escalation](escalation.md)) |

A ratio over fewer than 10 events (runs, sign-ins, approvals) says little, so it's n/a, though its counts are still shown. If the audit log keeps fewer days than the window (`AUDIT_RETENTION_DAYS`), the report says `partial` and the counts cover only what's kept.

| Signal | Weight | Counts | Watch | At risk |
|---|---|---|---|---|
| [`adoption`](#adoption) | 25 | People with a seat who signed in or used a session in the window | below 60% | below 30% |
| [`runs`](#runs) | 20 | Bot runs that ended in an error or a timeout | 5% or more | 15% or more |
| [`identity`](#identity) | 20 | Single sign-on attempts that failed; failed SCIM requests | 10% or more; 1 failed SCIM request | 25% or more; 10 failed SCIM requests |
| [`backups`](#backups) | 20 | The newest server backup off the host, against its RPO; machines past their RPO; failed machine backups | Server backups not set up or kept on the host; a machine backup failed | Server backups past their RPO; a machine past its RPO |
| [`approvals`](#approvals) | 10 | Approvals that expired unanswered | 10% or more | 30% or more |
| [`license`](#license) | 5 | The license's end and its seats | Ends within 30 days; 90% of seats in use | Ended or not usable; more people active than seats |

## The signals

### `adoption`

People with a seat (active users, the owner account aside, as the license counts them) who signed in, or whose session or API token was used, in the window. Low adoption is the earliest sign a customer won't renew: people were given access and didn't come back.

When it's low: ask who the pilot team was and whether they're still using it ([onboarding](onboarding.md#6-monitoring-and-go-live)); check sign-in works for them ([sign-in runbook](runbook-sign-in.md)); offer a short session for their teams. People who left should be disabled (by SCIM, or `botctl user disable`), which also frees their seats.

### `runs`

Of the Bot runs that finished in the window (`bot.run_finished`), how many ended in `error` or `timeout`. Runs a person stopped, or that a restart interrupted, aren't failures. The report also lists runs refused before they started (`bot.run_refused`), most frequent reason first, and how many were held to their run limits (`machine.run_limited`).

When it's high: see which harness and when ([harness or model provider outage](runbook-harness-outage.md)). A refusal reason of `egress_policy_pending` or many runs held to limits point at the [run limits and allow-lists runbook](runbook-run-limits-egress.md); `license` at the license below.

### `identity`

Single sign-on attempts that failed (`auth.login_failed` with method `sso`), as a share of all single sign-on attempts, with the most frequent reasons; and failed SCIM requests made with a token, or with a revoked one still in use. Requests with no token or an unknown one are only counted (`scimUnauthenticated`): anyone on the internet can send those. The signal is the worse of the two.

When it's watch or at risk: the reasons say which runbook. `bad_signature`, `wrong_audience`, `wrong_recipient`, `expired` and other SAML codes go to the [SAML runbook](runbook-saml.md); `not_linked`, `wrong_tenant` and `code_exchange_failed` to the [sign-in runbook](runbook-sign-in.md). A revoked SCIM token in use means the IdP's provisioning stopped: make a new token (`botctl scim token create`) and put it in the IdP ([SCIM guide](../sso/scim.md)).

### `backups`

The worst of: server backups (at risk past their RPO, watch if not set up or kept only on the host), users' machines past their RPO (at risk), and machine backups that failed in the window (watch). Machines count only where botd manages them.

When it's watch or at risk: `botctl backups` and `botctl machine recovery` say what's late; [machine down or restore](runbook-machine-down.md) and [backup and restore](../ops/backup-restore.md) say what to do. A pinned customer's backups refused for residency show here too ([residency runbook](runbook-residency.md)).

### `approvals`

Approvals that expired unanswered (`approval.expired`) as a share of those asked for (`approval.requested`), with how many are waiting now. Many expiring means Bots ask people who aren't there, or who never hear.

When it's high: the [approval queue runbook](runbook-approvals-stuck.md). Often the policy asks for more than the customer needs: review it with them.

### `license`

Self-hosted servers: watch when the license ends within 30 days or 90% of its seats are in use; at risk once it has ended (its grace period too), when there's no usable license, or when more people are active than it covers. n/a in testing mode with no license.

When it's watch or at risk: renewals and seats go to the account owner; `botctl license` shows the detail. Air-gapped servers need the new key carried in ([air-gapped runbook](runbook-air-gapped.md)).

## What it isn't

- **Not a measure of support.** Tickets, response times and satisfaction live in the support system, which botd can't see. Put them beside the score in the [review](qbr-template.md).
- **Not history.** botd doesn't keep past scores. Record each health check's score in the customer's record (outside this repository) to see the trend.
- **Not the status page.** An outage shows on `/status`; the score shows what the last weeks were like for the customer's people.
