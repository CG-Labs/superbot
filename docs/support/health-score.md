# Customer health score

One number from 0 to 100 for how a customer's deployment is doing, and the six signals behind it. The technical account manager (TAM) reads it at each [health check](health-check.md) and brings it to the [quarterly business review](qbr-template.md); support reads it when a ticket looks like more than one problem. botd works it out from what it already records, so nothing is sent anywhere and nothing new is collected. Design: [ADR 0144](../adr/0144-tam-programme-and-health-score.md).

## Get it

On the server, as an admin (as for any operator command; `botctl admin` lists them):

```sh
botctl health-score                 # the last 30 days, one line per signal
botctl health-score --days 90 json  # the full report as JSON
```

Or `GET /api/support/health-score?days=30` as an admin, or the console's **Support** tab, which shows the score, each signal and the history below, with a button for the [support bundle](support-bundle.md). The window is 7 to 90 days, 30 if not given. Members, read-only users, custom roles and Bots get 403. A [support bundle](support-bundle.md) carries the same report for the last 30 days as `health-score.json`.

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
| [`identity`](#identity) | 20 | Single sign-on attempts that failed; SCIM requests with a valid token that were refused, revoked or expired tokens still in use, and tenants whose SCIM tokens all end within 14 days | 10% or more; 1 failed SCIM request; a tenant's SCIM tokens ending within 14 days | 25% or more; 10 failed SCIM requests |
| [`backups`](#backups) | 20 | The newest server backup off the host, against its RPO; machines past their RPO; failed machine backups | Server backups not set up, kept on the host, or none copied off it yet; a machine backup failed | Server backups past their RPO; a machine past its RPO |
| [`approvals`](#approvals) | 10 | Approvals that expired unanswered | 10% or more | 30% or more |
| [`license`](#license) | 5 | The license's end and its seats | Ends within 30 days; 90% of seats in use | Ended or not usable; more people active than seats |

## The signals

### `adoption`

People with a seat (active users, the owner account aside, as the license counts them) who signed in, or whose session or API token was used, in the window. botd keeps when each person last used one on the person, so it counts after the session itself is gone. Low adoption is the earliest sign a customer won't renew: people were given access and didn't come back.

When it's low: ask who the pilot team was and whether they're still using it ([onboarding](onboarding.md#6-monitoring-and-go-live)); check sign-in works for them ([sign-in runbook](runbook-sign-in.md)); offer a short session for their teams. People who left should be disabled (by SCIM, or `botctl user disable`), which also frees their seats.

### `runs`

Of the Bot runs that finished in the window (`bot.run_finished`), how many ended in `error` or `timeout`. Runs a person stopped, or that a restart interrupted, aren't failures. The report also lists runs refused before they started (`bot.run_refused`), most frequent reason first, and how many were held to their run limits (`machine.run_limited`).

When it's high: see which harness and when ([harness or model provider outage](runbook-harness-outage.md)). A refusal reason of `egress_policy_pending` or many runs held to limits point at the [run limits and allow-lists runbook](runbook-run-limits-egress.md); `license` at the license below.

### `identity`

Single sign-on attempts that failed (`auth.login_failed` with method `sso`, including those the audit log throttled, listed as `throttled` since their reasons weren't logged), as a share of all single sign-on attempts, with the most frequent reasons; and SCIM requests made with a valid token that botd refused or failed (`scim.request_failed`: a duplicate user, a bad request, no seat left, a server error; not a 404, which IdPs get in their normal course), or with a revoked or expired token still in use (`revoked_token`, `expired_token`); and the number of SCIM tenants whose every working token ends within 14 days (`scimTenantsExpiring`, a count, never their names), which make it at least watch ([ADR 0196](../adr/0196-scim-token-expiry-and-rotation.md)). Requests with no token or an unknown one are only counted (`scimUnauthenticated`): anyone on the internet can send those. So are bad-token requests the audit log throttled, whose reasons it didn't log. The signal is the worse of the two.

When it's watch or at risk: the reasons say which runbook. `bad_signature`, `wrong_audience`, `wrong_recipient`, `expired` and other SAML codes go to the [SAML runbook](runbook-saml.md); `not_linked`, `wrong_tenant` and `code_exchange_failed` to the [sign-in runbook](runbook-sign-in.md). `uniqueness` means the IdP sent someone botd already has (another tenant, a reused `externalId` or email): `botctl audit --action scim.request_failed` shows when, and the IdP's provisioning log shows who. `status_403` is usually no seat left (see `license`). `insufficient_scope` means a token sent a request its [scopes](../sso/scim.md#token-scopes) don't allow, usually group pushes from a users-only token: turn group provisioning off in the IdP, or rotate the token with the scope the event names. A revoked or expired SCIM token in use means the IdP's provisioning stopped: make a new token (`botctl scim token create`) and put it in the IdP ([SCIM guide](../sso/scim.md)). A tenant counted in `scimTenantsExpiring` stops provisioning soon: `botctl scim tokens` (or `GET /api/scim/tokens`, `expiringTenants`) names it; rotate one of its tokens (`botctl scim token rotate <id>`) and put the new one in the IdP ([token expiry and rotation](../sso/scim.md#token-expiry-and-rotation)).

### `backups`

The worst of: server backups (at risk past their RPO, watch if not set up, kept only on the host, or copied off it but none copied yet), users' machines past their RPO (at risk), and machine backups that failed in the window (watch). Machines count only where botd manages them.

When it's watch or at risk: `botctl backups` and `botctl machine recovery` say what's late; [machine down or restore](runbook-machine-down.md) and [backup and restore](../ops/backup-restore.md) say what to do. A pinned customer's backups refused for residency show here too ([residency runbook](runbook-residency.md)).

### `approvals`

Approvals that expired unanswered (`approval.expired`) as a share of those asked for (`approval.requested`), with how many are waiting now. Many expiring means Bots ask people who aren't there, or who never hear.

When it's high: the [approval queue runbook](runbook-approvals-stuck.md). Often the policy asks for more than the customer needs: review it with them.

### `license`

Self-hosted servers: watch when the license ends within 30 days or 90% of its seats are in use; at risk once it has ended (its grace period too), when there's no usable license, or when more people are active than it covers. n/a in testing mode with no license.

When it's watch or at risk: renewals and seats go to the account owner; `botctl license` shows the detail. Air-gapped servers need the new key carried in ([air-gapped runbook](runbook-air-gapped.md)).

## History

botd records the 30-day score once a UTC day, within its first hours, and keeps 400 days of them (`HEALTH_SCORE_HISTORY_DAYS`, 1 to 3650; 0 records none). Each day keeps only the score, its band and each signal's status. Design: [ADR 0157](../adr/0157-health-score-history-and-console.md).

```sh
botctl health-score history             # the last 90 days, a line per day, then the trend
botctl health-score history --days 365  # a year, for the business review
```

Or `GET /api/support/health-score/history?days=90` as an admin (1 to 3650 days), or the console's Support tab. The trend compares the newest day with the oldest in the window: the score's change, and the signals that got worse or better (one that was n/a on either day is neither). History starts when botd first runs with this version: past days aren't worked out afterwards, since who was active then can't be read back. A [support bundle](support-bundle.md) carries the last 90 days as `health-score-history.json`.

At a [health check](health-check.md), a fall of 10 points or more since the last check, or a signal that went from ok to at risk, is worth a line in the customer's record even if the band didn't change.

## Alerts

botd doesn't wait for the next check to say the score fell ([ADR 0307](../adr/0307-health-score-alerts.md)). When it records the day's score, it compares it with the day recorded before, and tells its alert channels once, on the day it shows, when:

- **the band fell**: healthy to watch or at risk, or watch to at risk;
- **a signal went at risk** that wasn't the day before, with what botd saw and the signal's section of this page;
- **the score fell 10 points or more below the last [health check](health-check.md)'s**, on the day it crossed.

The notice goes to the global email list and webhook of [approval notifications](../../deploy/README.md#approval-notifications), where botd's other alerts go, with a link to the console's Support tab. Each is recorded as `support.health_score_fell` (both days' scores and bands, the signals newly at risk, the check's score), so `botctl audit --action support.health_score_fell` lists them. Recovery isn't told. Alerts need the [history](#history): with `HEALTH_SCORE_HISTORY_DAYS=0` there's nothing to compare with. A customer's admin who gets one forwards it to their TAM, and the TAM calls before the next check-in ([TAM programme](tam.md#cadence)).

For Prometheus, `/metrics` shows the newest recorded day: `superbot_health_score`, `superbot_health_score_band{band}` (1 for its band), `superbot_health_signal_at_risk{signal}` and `superbot_health_score_recorded_timestamp_seconds`. [`superbot-health-score.rules.yml`](../../deploy/prometheus/superbot-health-score.rules.yml) turns them into tickets, never pages: the band at risk, a signal at risk, a fall of 10 points or more below the week's highest score, and no new record for 36 hours. A Provider that scrapes its customers' servers routes these to each customer's TAM.

## What it isn't

- **Not a measure of support.** Tickets, response times and satisfaction live in the support system, which botd can't see. The [support report](support-report.md) counts tickets and response targets from its export; put it beside the score in the [review](qbr-template.md).
- **Not a full archive.** History keeps each day's score, band and signal statuses, not the counts behind them; the support bundle and the report for a window carry those. Copy the score into the customer's record at each check too, since history goes after `HEALTH_SCORE_HISTORY_DAYS`.
- **Not the status page.** An outage shows on `/status`; the score shows what the last weeks were like for the customer's people.
