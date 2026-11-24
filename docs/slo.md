# Uptime SLO for managed SuperBot

The availability targets a SuperBot operator holds managed SuperBot to, how they are measured, the error budget each gives, and what happens when it's spent. It's the uptime counterpart of the [machine recovery objectives](security/machine-recovery-objectives.md) (RPO and RTO per plan, [ADR 0074](adr/0074-machine-rpo-and-rto.md)). Design: [ADR 0090](adr/0090-status-page-and-uptime-slo.md), [#47](https://github.com/CG-Labs/superbot/issues/47).

"Provider" is whoever runs the SuperBot server. "Service" is that server's API, sign-in, the web app and console it serves, and Bot runs it starts. These are SuperBot's default numbers; a Provider that changes them changes them here too, and doesn't promise tighter numbers than its own measurements show.

## Objectives

Each plan has an availability objective over a rolling 30-day window:

| Plan | Availability | Error budget per 30 days | Machine RPO / RTO |
|---|---|---|---|
| Starter | 99.5% | 3 h 36 min | 26 h / 60 min |
| Pro | 99.9% | 43 min | 14 h / 60 min |
| Max | 99.9% | 43 min | 8 h / 60 min |
| Enterprise | 99.95%, by agreement | 21 min | by agreement |

Pro and Max share the same server and the same objective: the plans sell more resources and fresher backups, not a different service. Enterprise's 99.95% needs a deployment of its own with a standby server (M5), and isn't offered on a shared server. A server shared by several plans is run to the strictest objective on it, which is what the [burn-rate alerts](#alerts) use (99.9%).

**Why these numbers.** The whole-server RTO is 1 hour ([ADR 0030](adr/0030-backup-restore-drill.md)). One restore of a lost server fits Starter's monthly budget three times over, but spends more than all of Pro's and Max's. So 99.9% is an objective the Provider runs to and alerts on, not a promise that a month with a disaster stays inside it. An SLA with service credits should be set below the objective (for example 99.0% for Starter and 99.5% for Pro and Max), so one disaster recovered within its RTO doesn't breach the contract. Until the Provider has measured a quarter at 99.9%, don't sign 99.9% into a contract.

## How it's measured

Two indicators, each held to the plan's objective:

1. **Uptime (the contractual one).** A probe outside the server's host fetches `https://<domain>/status.json` every 30 seconds with a 10-second timeout, from at least one location the Provider doesn't host the server in. A minute is **down** if both checks in it fail (no answer, a timeout, or anything but a 2xx: `/status.json` answers 503 when it reports a major outage). Availability is the share of minutes in the window that aren't down. A blackbox exporter, Uptime Kuma, or any hosted uptime checker can be the probe. `/status.json` is answered by botd itself (through Caddy), so a failing proxy, botd or database shows, and it reads the database, so a botd that answers but can't reach its data shows too.
2. **Request success (the early warning).** The share of requests botd answers without a 5xx, from `superbot_http_requests_total` ([ADR 0089](adr/0089-metrics-and-structured-logs.md)), excluding `/healthz` and the status page (probes, not users). It catches partial failures the probe misses, such as one feature failing, and drives the [burn-rate alerts](#alerts). It can't see time botd is down (nothing is counted then), which is why uptime is the contractual measure.

The window for alerting and the budget is a rolling 30 days. Reports and any credits use calendar months, in UTC. `superbot-evidence uptime` makes each month's report from the probe's own checks (Prometheus' blackbox exporter, or any probe's export): availability against each plan's objective, the error budget spent, every outage and those that need a written review, with announced maintenance left out ([ADR 0251](adr/0251-uptime-evidence-from-the-outside-probe.md), [evidence plan](security/soc2-evidence-plan.md#the-uptime-bundle)).

Bot runs have an internal objective, not a contractual one: at least 90% of finished runs in any hour end done rather than in an error or a timeout. Runs depend on model providers and on what people ask of them, so this one isn't in an SLA; it's alerted on as a ticket.

## What doesn't count against it

1. **Announced maintenance.** Posted on the status page as a `maintenance` incident at least 48 hours ahead, at most 4 hours a month, and outside 08:00 to 18:00 in the server's region on weekdays. Maintenance past its announced end counts.
2. **One customer's machine.** A machine down because its host failed, or being restored, is covered by its plan's [RPO and RTO](security/machine-recovery-objectives.md), not by this objective. A host that doesn't answer shows on the status page as a partial outage of machines. If all of a server's hosts are down, those minutes count as down.
3. **Things outside the Provider's control**: model providers and other third-party services the customer's Bots use, the customer's own network, identity provider or devices, and force majeure. A Provider outage that started with one of these still counts.
4. **Suspended accounts and machines**, and requests refused for a plan's limits, a policy, or bad credentials (4xx answers aren't failures).
5. **Self-hosted servers.** A licensed self-host operator runs to its own objectives. The same tools (status page, alert rules) are there for it to use.

## Error budget policy

The error budget is what the objective allows to fail: 0.1% of a 30-day window is 43 minutes.

- **Budget left.** Ship as normal.
- **Half spent in the window.** The on-call engineer reviews what spent it and whether a fix is needed before the next risky change (a schema migration, a substrate change, a harness pin bump).
- **All spent.** Only fixes, security patches and reliability work ship until the rolling window has budget again. Each incident that spent more than a quarter of the budget gets a written review (what happened, why, what changes), linked from its status page note.

## Alerts

[`deploy/prometheus/superbot-slo.rules.yml`](../deploy/prometheus/superbot-slo.rules.yml) has the alert rules, tested with `promtool` in CI:

| Alert | When | Severity |
|---|---|---|
| `SuperBotErrorBudgetBurnFast` | 5xx share above 14.4× the budget rate over 1 h and 5 min, or 6× over 6 h and 30 min (2% or 5% of the 30-day budget gone) | page |
| `SuperBotErrorBudgetBurnSlow` | above 3× over 1 day and 2 h, or 1× over 3 days and 6 h | ticket |
| `SuperBotDown` | Prometheus can't scrape botd for 2 minutes | page |
| `SuperBotStatusProbeFailing` | the outside-in probe of `/status.json` fails for 2 minutes | page |
| `SuperBotRunFailuresHigh` | more than 10% of an hour's runs (at least 10) end in an error or a timeout | ticket |

How to load them: [deploy/README.md](../deploy/README.md#status-page-and-slo-alerts).

## Status page and incidents

`/status` (and `/status.json`) is public. It shows the service's components (API, database, machines and control plane, harness runners, notifications), each judged from botd's own checks and the last minutes of its metrics, and incident notes the Provider's admins post from the console. It shows no customer data, counts, hostnames or errors ([ADR 0090](adr/0090-status-page-and-uptime-slo.md)).

When the probe or a page alert fires, the on-call engineer posts an incident within 15 minutes of confirming it, naming the affected components, and updates it at least hourly until it's resolved (from the console, or `botctl incident` on the server). `botctl incident review` checks both targets afterwards ([incident reviews](support/incident-review.md), [ADR 0201](adr/0201-incident-review-drafts.md)). Resolved incidents stay on the page for 14 days.
