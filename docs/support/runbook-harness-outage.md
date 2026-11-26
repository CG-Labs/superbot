# Runbook: harness or model provider outage

Bot runs fail or time out on one harness (Hermes Agent, Claude Code, Codex, Pi) or one model provider, while the rest of SuperBot works. Severity: [2](severity.md#severities) when Hermes runs fail for many people (the SLA covers Hermes), 3 for another harness or one Bot ([tiers](tiers.md#harnesses)). A model provider's own outage is outside the [SLO](../slo.md#what-doesnt-count-against-it) on every plan, but support still works it.

## First five minutes

1. **Which harness, which model, how many.** One Bot, everyone on one plan (its tier's route), or every run on one harness? Ask for a failing run's time and the Bot.
2. **The signals.** The status page's harness runners component; the `SuperBotHarnessRunsFailing` alert (more than 25% of a harness's runs failing over 30 minutes) or `SuperBotRunFailuresHigh` (more than 10% of an hour's runs on every harness: [SLO alerts](../slo.md#alerts), [error alerts](../../deploy/README.md#metrics-and-logs)).
3. **What the runs say.** botd logs every finished run with its harness and result:

   ```sh
   journalctl -u superbot -o cat | jq -Rc 'fromjson? | select(.msg == "run.finished" and .result != "done")' | tail -20
   ```

   Or make a support bundle: `logs.jsonl` has the recent `run.finished` lines and `health.json` the last 15 minutes' runs by result. The Bot's chat shows the harness's own error text to its owner.
4. **The provider's status page**, for the model in the tier's route (`botctl tiers` lists routes and their fallbacks).

## Causes and fixes

| What you see | Usually | Do |
|---|---|---|
| Every run on one harness fails at once, right after an upgrade or image change | The harness CLI changed, or its pin moved | Check the harness version on the server or machines; roll back to the last good image or pin. Hermes pin bumps take stable releases through the test suite ([ADR 0075](../adr/0075-hermes-upgrades.md)) |
| Errors naming authentication, a 401 or "log in" | The harness's login or API key expired or was revoked | Claude Code and Codex logins: `botctl machine harness-logins <user>` and log in again ([harness logins](../../deploy/README.md#harness-logins-and-the-users-folder-on-machines)). Keys for a tier's providers: `botctl secret set <keySecret> < file`, then restart |
| 429s, overloaded, or 5xx from the provider; runs time out | The model provider is degraded or rate limiting | Below: fallback, then moving Bots, then telling people |
| One Bot only | Its settings, its model, or what it was asked | Compare with another Bot on the same plan; often a model name the provider retired |
| Runs wait and never start | Not a harness problem: run slots are full (`SuperBotRunQueueBacklog`) or approvals are waiting | [Approval queue stuck](runbook-approvals-stuck.md), or raise `MAX_CONCURRENT_RUNS` or a tier's `concurrentRuns` |

## While a provider is down

1. **Fallback.** A tier route on Hermes can list up to three fallback providers and models, tried in order when the first fails ([ADR 0077](../adr/0077-two-providers-through-tier-routing.md)). Check `botctl tiers`: if the route has a fallback whose key is saved, runs should already be moving to it (`harness.invoked` in the audit log lists the chain, and any fallback skipped for a missing key). If not, add a fallback to the route in the tiers file, save its key, and restart botd. Plan this before an outage: every managed route should have one.
2. **Move Bots to another harness.** If a whole harness is down, a tier's default harness can change in the tiers file, and `botctl tiers move-bots <tier> --dry-run`, then without `--dry-run`, moves the tier's Bots that run elsewhere onto it ([ADR 0079](../adr/0079-hermes-default-for-managed-tiers.md)). Tell their owners; moving back is the same command after changing the default again.
3. **Tell people.** If many customers are affected, post a partial outage of harness runners on the status page, naming the provider if it has said so publicly. Routines that fail meanwhile are not re-run on their own; owners can run them again.
4. **Usage.** Runs that start and then fail count towards a plan's monthly runs; only runs refused before they start are given back ([ADR 0040](../adr/0040-billing-v0-tier-limits.md)). If an outage spent many, say so in the ticket; credits are by agreement.

## Escalate when

- Hermes runs fail for many people for more than 30 minutes with no provider outage to explain it: level 2, possibly an upstream issue ([escalation](escalation.md#outside-the-provider)).
- A fallback is configured but runs don't use it.
- Runs succeed but act wrongly (a harness ignoring approvals, writing outside its workspace): that's a security issue, [Severity 1](escalation.md#security-incidents).

## Afterwards

If a route had no fallback, add one. Note the provider, start and end times, and runs failed in the ticket, for the monthly report.
