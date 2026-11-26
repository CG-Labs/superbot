# Runbook: errors and panics in botd

botd answers requests with 5xx errors, spends its availability error budget, panics, or stops getting its error reports through to the error tracker, while it's still up. Severity: [1](severity.md#severities) when sign-in or Bots fail for most of the customer's people (the `auth` or `bots` route class, or the fast burn on every route); 2 when one major function fails for many people (another route class, or the fast burn); 3 for the slow burn, one panic, or a route class few people use; 4 for error reports not arriving while nothing else is wrong. botd down altogether is [the server itself](runbook-machine-down.md#the-server-itself).

The metrics and settings are in the deploy guide's [metrics and logs](../../deploy/README.md#metrics-and-logs), and the objectives in the [SLO](../slo.md); this page is the order to work in.

## First five minutes

1. **Which requests, since when.** The alert names the route class, or the share of all requests failing. With metrics on, the service dashboard ([`superbot-service.json`](../../deploy/grafana/superbot-service.json)) shows the 5xx share by route class, panics and error reports. The status page (`/status`) says which components botd itself judges degraded.
2. **What botd logged.** Every response has an `X-Request-Id`, the same as its log line. With `LOG_FORMAT=json`:

   ```sh
   journalctl -u superbot -o cat | jq -Rc 'fromjson? | select(.msg == "http.request" and .status >= 500)' | tail -20
   journalctl -u superbot -o cat | jq -Rc 'fromjson? | select(.msg == "server.panic")' | tail -5
   ```

   `fromjson?` skips the plain-text lines Rust's panic hook writes next to the JSON. (Compose: `docker compose logs --tail 2000 botd`.) With an error tracker (`ERROR_REPORT_DSN`), each 5xx and panic is there too, with the route template and request id but never the panic's message, which stays in botd's log. A support bundle has the recent log lines in `logs.jsonl` and the last 15 minutes' metrics in `health.json`.
3. **Did anything change?** An upgrade (most often), a setting, the database's disk, the host's memory, the proxy in front of botd, a provider botd calls for that route (Stripe for `billing_webhook`, the identity provider for `auth`, Incus or Linode for `machines`).

## Requests failing

`SuperBotErrorBudgetBurnFast` (a page) and `SuperBotErrorBudgetBurnSlow` watch every request's 5xx share against the 99.9% objective ([SLO alerts](../slo.md#alerts)): the fast one spends 2% of the 30-day budget in an hour, or 5% in six; the slow one would spend it all before the window ends. `SuperBotRouteClassErrors` watches one route class: more than 5% of its requests (at least 20) failing over 10 minutes. 4xx answers never count: they're refusals, not failures. `healthz` and `status` are left out of all three, since they're probes and `/status.json` answers 503 on purpose in a major outage.

| Route class | Requests | Usually, when it fails |
|---|---|---|
| `auth` | Sign-in, sessions, `/login` | The identity provider, the database; [sign-in runbook](runbook-sign-in.md) |
| `bots` | Bots, routines, harnesses, the app's state | The database, a harness setting, a Bot's machine |
| `bot_calls` | `botctl ask` and handoffs between Bots | The Bot asked, its machine or harness ([harness outage](runbook-harness-outage.md)) |
| `events` | The app's live event stream | The proxy closing long-lived connections, or memory |
| `approvals` | Approvals and the permission policy | The database; [approval queue stuck](runbook-approvals-stuck.md) |
| `approval_hook` | Harnesses asking whether a tool may run | Runs wait or fail with it: the database, or botd overloaded |
| `machines` | Machines and Incus hosts (admins) | Incus or Linode not answering; [machine down](runbook-machine-down.md), [host capacity](runbook-capacity.md) |
| `users` | Users, `/api/me`, the console's SCIM settings | The database; with SCIM, [SCIM provisioning](runbook-scim.md) |
| `scim` | The identity provider's SCIM requests | [SCIM provisioning](runbook-scim.md) |
| `teams` | Teams and their settings | The database |
| `audit` | The audit log's reads and exports (admins) | A large export, the database's disk; [audit trail](runbook-audit-trail.md) |
| `billing` | Billing, usage, tiers, the license | The tiers file, Stripe; [license and seats](runbook-license.md) |
| `billing_webhook` | Stripe's webhook | Stripe retries for days; check the webhook secret |
| `signups` | Sign-up requests | The database, mail sending |
| `api_other` | Any other API | The route in the log lines |
| `web` | The app and console's pages | The files botd serves, after an upgrade |
| `healthz`, `status` | Health checks and the status page | Left out of these alerts; botd down is [the server itself](runbook-machine-down.md#the-server-itself) |

The log lines' `route` is the route template (`/api/bots/{id}/messages`), which narrows it further. If every class fails at once, it's botd or what it stands on: `botd support check`'s database and disk findings ([support check](support-check.md#the-checks)), the host's memory, then an upgrade to [go back](runbook-upgrade.md#going-back) from. Post on the status page for anything a customer would notice, within 15 minutes for a page ([running a Severity 1](runbook-major-incident.md)).

## Panics

`SuperBotPanics`: botd panicked in the last 15 minutes. A request handler that panics answers 500 and botd carries on; a background task that panics stops until botd restarts, so what it did (a reconcile, an export, a sweep) quietly stops too. A panic that ends botd is `SuperBotDown` instead.

1. Find it: the `server.panic` log line has its source location and request id; the message is on botd's stderr just before it. The error tracker groups repeats by location.
2. If it's a request, the request id's `http.request` line names the route. If it's a task, check what the location belongs to is still running (`botctl machine hosts`, `botctl audit siem`, `botctl backups`, as fits), and restart botd if not.
3. Every panic is a bug in botd: send its location, kind, botd's version (`server.started` in the audit log records it) and what led to it, never the request's contents, as an issue for the next release.

## Error reports aren't arriving

`SuperBotErrorReportsFailing`: the error tracker refused or didn't answer botd's reports in the last 30 minutes, so panics and 5xx answers may be missing there; botd's log still has them all. Check `ERROR_REPORT_DSN` (a project deleted or its key rotated), the tracker's rate limits and status, and egress from the server to it. botd's log names the failure (`error tracker ...`). Reports over 20 a minute are dropped on purpose and counted as `dropped`, not `failed`.

## Before telling the customer it's fixed

1. The 5xx share is back under the alert for its route class, on the dashboard, for at least 30 minutes, and no new `server.panic` lines.
2. What the customer saw works: sign in, open a Bot, run something, as fits the route class.
3. For a fast burn, note the error budget spent in the ticket: `superbot-evidence uptime` counts the month's.

## Escalate when

- 5xx answers continue after going back to the previous version.
- botd panics again in the same place after a restart.
- 5xx answers with no `http.request` line at warn level: the proxy answered, not botd.
- Errors expose another customer's data, or a request succeeds that should be refused: a security incident, [Severity 1](escalation.md#security-incidents).

## Afterwards

Note the cause, the route class and the budget spent in the ticket, for the monthly report. Anything that spent more than a quarter of the error budget gets a written review ([error budget policy](../slo.md#error-budget-policy)). If an upgrade caused it, note the versions, so the next customer's upgrade can wait for the fix.
