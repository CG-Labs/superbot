# 0113: Dashboards for requests and runs, error alerts, and error reporting

## Status

Accepted (22 Nov 2026). Part of the SOC 2 readiness checklist of M4, [#50](https://github.com/CG-Labs/superbot/issues/50); closes checklist row CC2.1-1 in the [readiness checklist](../security/soc2-readiness-checklist.md). Builds on metrics and structured logs ([ADR 0089](0089-metrics-and-structured-logs.md)), the status page and SLO alerts ([ADR 0090](0090-status-page-and-uptime-slo.md)), and the host capacity dashboard ([ADR 0106](0106-host-capacity-metrics.md)).

0111 is the highest number on `main`; another open PR holds 0112.

## Context

CC2.1-1 asks for metrics, alert rules and dashboards for the service. botd already had a Prometheus endpoint with requests by route class and runs by harness and result (ADR 0089), SLO burn-rate alerts (ADR 0090), and a host capacity dashboard (ADR 0106). Three things were missing:

- **No dashboards for requests and runs.** The numbers were in `/metrics`, but an operator had to write their own queries to see them.
- **Alerts only for the whole.** The SLO rules watch every route's 5xx against the error budget and every harness's runs against the 10% run objective. One broken route class, or one harness failing while the others are fine, could hide inside a healthy total.
- **No error reporting.** A 5xx left a `warn` log line with a request id, and a panic left Rust's message on stderr. Nobody was told, nothing grouped repeats, and a panic in a request handler dropped the connection, so it wasn't even counted as a 5xx.

Whatever reports errors must not leak what botd keeps private. A panic message is any text the code formatted into it, which can be a prompt, a file's contents or a token. A 5xx's body can quote what was asked.

## Decision

### Metrics added

| Metric | Labels | Meaning |
|---|---|---|
| `superbot_runs_started_total` | `harness` | Runs that took a slot and called their harness, so a dashboard can show started beside finished |
| `superbot_panics_total` | none | Panics in botd since it started, caught or not, whether or not reports are on |
| `superbot_error_reporting_enabled` | none | 1 when `ERROR_REPORT_DSN` is set |
| `superbot_error_reports_total` | `kind` (`panic`, `http_5xx`), `outcome` (`sent`, `failed`, `dropped`) | Reports to the tracker, written from zero |

Labels come from fixed lists, as ADR 0089 requires: harness names from the adapters, two kinds, three outcomes. No user, Bot, team, path or message text. Queue depth is the existing `superbot_runs_waiting` (runs waiting for a slot, ADR 0073) and `superbot_approvals_pending`.

### A dashboard: `deploy/grafana/superbot-service.json`

Three rows, for one botd or all of them summed (`instance` is a multi-select):

- **Requests by route class**: rate, 5xx share and p95 latency at a glance; requests by route class and by status class; 5xx share and 4xx rate by route class; p50 and p95 latency by route class. Health checks and the status page are left out of shares and latency, as in the SLO.
- **Bot runs by harness**: runs underway, waiting for a slot, the hour's failure share and approvals waiting; runs started, finished (by result) and failed per minute by harness; failure share by harness; queue depth and slots; p50 and p95 run duration by harness; runs refused by reason.
- **Errors**: whether reporting is on, reports failed or dropped, 5xx answers and panics; panics over time and reports by kind and outcome.

A test renders `/metrics` and fails if the dashboard or the new rules name a metric botd doesn't write, and checks every query is scoped to `$job` and `$instance`.

### Alert rules: `deploy/prometheus/superbot-errors.rules.yml`

Next to the SLO rules, not instead of them:

| Alert | Fires when | Severity |
|---|---|---|
| `SuperBotHarnessRunsFailing` | Over 25% of one harness's finished runs failed (error or timeout) in 30 minutes, with at least 5 runs, for 10 minutes | ticket |
| `SuperBotRouteClassErrors` | Over 5% of one route class's requests were 5xx in 10 minutes, with at least 20 requests, for 10 minutes | ticket |
| `SuperBotPanics` | botd panicked in the last 15 minutes | ticket |
| `SuperBotRunQueueBacklog` | Runs have waited for a slot for 30 minutes without the queue emptying | ticket |
| `SuperBotErrorReportsFailing` | The tracker refused or didn't answer a report in the last 30 minutes | ticket |

The run objective and the error budget stay with the SLO rules (`SuperBotRunFailuresHigh`, `SuperBotErrorBudgetBurnFast`, `SuperBotErrorBudgetBurnSlow`), which page. These are tickets: a part failing is worth a look, and the SLO pages when it costs users. A panic that ends botd is never scraped; `SuperBotDown` covers it. Each rule has `promtool` tests (`superbot-errors.rules.test.yml`) that it fires and stays quiet when it should, run in CI's `prometheus-rules` job.

### Error reporting: a Sentry-compatible DSN, off by default, built from an allow-list

`ERROR_REPORT_DSN` (or `ERROR_REPORT_DSN_FILE`) names a project in any tracker that takes Sentry's envelope protocol: Sentry, self-hosted Sentry, GlitchTip or Bugsink. Unset, botd sends nothing. `ERROR_REPORT_ENVIRONMENT` (default `production`) tags each report. The DSN must be `https://`; plain `http://` only to loopback. Its key is one of botd's secrets: redacted from output and never printed.

botd reports two things:

- **A panic**: the source location (`src/runner.rs:1234`, a dependency's as `crate-version/src/...`, never a build directory), a kind from a fixed list (`called Option::unwrap() on a None value`, `index out of bounds`, `string sliced inside a character`, and a few more), the request id if it happened in a request, and level `fatal`. Never the panic's message: a formatted panic can hold any text. Rust's own hook still prints the message to stderr, so it's in botd's log on the host, and a `server.panic` JSON line gives the location and request id to find it.
- **A 5xx answer**: method, route template (`/api/bots/{id}/messages`, or `unmatched`), route class, status and request id, level `error`. Never the path as sent, a query, a header, or either body. The status page's own 503s are left out, as in the SLO.

Each report also carries botd's release and the environment; it never carries a user, server name, IP, request or breadcrumbs. Before sending, every string is passed through botd's secret redaction and anything shaped like an email is replaced, then cut to 200 characters. Repeats group by fingerprint (a panic's location; a 5xx's method, route and status). At most 20 reports a minute are sent, from a queue of 64; the rest are dropped and counted.

A request handler that panics now answers 500 (tower-http's `CatchPanicLayer`, inside the request tracker), so it is counted, logged and reported as a 5xx instead of dropping the connection.

#### Why this way

- **A Sentry-compatible DSN** because it's the format every common error tracker takes, including ones a self-hoster can run themselves (GlitchTip, Bugsink, self-hosted Sentry). It groups repeats and notifies, which logs and metrics don't.
- **A small client of our own, not the `sentry` crate.** The crate's defaults gather what we must not send (breadcrumbs from logs, request data, environment and OS contexts, the panic message and backtrace), and keeping it safe would mean auditing its integrations on every upgrade. Ours is a few hundred lines that send only fields we name, over the `reqwest` botd already has.
- **Not the panic message, not a backtrace.** Release builds are stripped, so a backtrace has no names; the message is the one field that may hold user data. The location and the kind are enough to find the line; the host's log has the rest.
- **Metrics and structured logs too, not only the tracker.** A self-hoster with no tracker still gets `superbot_panics_total`, the 5xx counts, alerts on both, and `server.panic` lines with request ids. Operators who'd rather not send anything off the host need not.

## Consequences

- Operators get a requests-and-runs dashboard to import, five more alert rules to load, and an error tracker they can turn on with one setting.
- A panicking request handler answers 500 instead of dropping the connection. Clients see an error body (`{"error": "Internal error"}`) where they used to see a reset.
- The tracker sees route templates, status codes, source locations, request ids, botd's version and the server's own IP as the sender. Turn on the tracker's "don't store IP addresses" setting if that matters; nothing in a report names a customer.
- A panic's message stays on the host. Finding it means reading botd's log at the request id the tracker shows.
- The SOC 2 row's operator evidence (screenshots of the live dashboards, alert history, the tracker's issues) can only come from a running deployment; the repository holds the definitions and their tests.
- Not covered: traces (still deferred, ADR 0089), the Expo client's own errors, and panics in the machine agent (`superbot-machine`), which shows only as a machine gone quiet (`machine.lost`).
