# 0089: Metrics and structured logs for botd

## Status

Accepted (21 Nov 2026). The first slice of M4 observability, [#46](https://github.com/CG-Labs/superbot/issues/46). It builds on the audit log ([ADR 0009](0009-audit-events.md), [ADR 0019](0019-audit-actors.md)), concurrent runs ([ADR 0073](0073-concurrent-runs-per-machine.md)), machine RPO and RTO ([ADR 0074](0074-machine-rpo-and-rto.md)), which said "no Prometheus endpoint" until botd had one, and secrets ([ADR 0010](0010-secrets.md)). The status page is [#47](https://github.com/CG-Labs/superbot/issues/47).

Numbering: `main` has up to 0088, with 0086 left unused for other open work (ADRs 0087 and 0088). No open PR adds an ADR, so this is 0089. Renumber it if a collision appears at merge.

## Context

botd had `/healthz`, the audit log, and free-text lines in `journalctl` or `docker logs`. An operator couldn't graph request rates, errors or latency, see how many runs fail or how long they take, notice approvals piling up, or alert on a machine past its RPO from a monitoring system. The audit log answers "who did what", one event at a time. It isn't for rates, and polling it is heavy.

Two things a managed launch needs: numbers a monitoring system can scrape and alert on, and logs a log pipeline can parse and join up. Neither may leak what botd keeps private: people's emails, names, messages, Bots' work, or tokens.

## Decision

### `/metrics`, in Prometheus' text format, on a listener of its own

botd serves Prometheus' text exposition format (version 0.0.4) at `/metrics`. It's off unless `METRICS_LISTEN` is set:

| Setting | Meaning | Default |
|---|---|---|
| `METRICS_LISTEN` | `off`, `on` (`127.0.0.1:9464`), or an address and port | off |
| `METRICS_TOKEN` or `METRICS_TOKEN_FILE` | A bearer token scrapers must send; at least 24 characters | none |

- **Its own listener, never the main port.** Caddy proxies botd's main port to the internet, and machines' Bots reach it through the machine port as if from loopback (ADR 0036). A check for loopback callers on the main port would let every Bot on a machine in. On its own listener, `/metrics` is reachable only where the operator binds it, and that listener serves nothing else.
- **A token off loopback.** botd refuses to start with a `METRICS_LISTEN` off loopback and no `METRICS_TOKEN`. With a token set, every scrape must send `Authorization: Bearer <token>`, compared in constant time, on loopback too. The token is one of botd's own secrets (`SERVER_SECRETS`): from the environment or a `_FILE`, redacted from what botd writes, and never given to a Bot's run. It's read only when metrics are on, so a leftover `METRICS_TOKEN_FILE` doesn't stop a server with metrics off from starting.
- **Why Prometheus' format.** Every common monitoring system reads it: Prometheus, Grafana Agent and Alloy, VictoriaMetrics, Datadog, New Relic, the OpenTelemetry Collector's Prometheus receiver. It's plain text that needs no client library. botd writes it itself, a few hundred lines of Rust with no new dependency, so the label rules below are enforced by types, not by a library's conventions.

### What it shows

Counters and histograms kept in botd's memory (they start at zero on restart, as Prometheus expects):

| Metric | Labels |
|---|---|
| `superbot_http_requests_total`, `superbot_http_request_duration_seconds` (histogram) | `route_class`, `method`, `status_class` (the histogram: `route_class`) |
| `superbot_runs_total`, `superbot_run_duration_seconds` (histogram), `superbot_runs_active` | `harness`, `result` (the histogram and gauge: `harness`) |
| `superbot_runs_refused_total` | `reason` |
| `superbot_events_total` | `event`, `outcome`: audit actions an operator alerts on (failed sign-ins, approvals, machine backups, RPO breaches and recoveries, restores, lost hosts, notifications) |
| `superbot_machine_reconcile_passes_total`, `..._last_pass_timestamp_seconds`, `..._last_pass_duration_seconds` | none |

Gauges read at each scrape:

| Metric | Labels |
|---|---|
| `superbot_approvals_pending`, `superbot_approvals_oldest_pending_age_seconds` | none |
| `superbot_run_slots_held`, `superbot_runs_waiting` (ADR 0073) | none |
| `superbot_machines` (with the control plane on) | `state` |
| `superbot_machine_storage_reports` (with routing on; [ADR 0105](0105-machine-disk-use-in-storage-limits.md)) | `report` |
| `superbot_incus_host_*`, `superbot_incus_machines_waiting_for_room` (with Incus hosts; [ADR 0106](0106-host-capacity-metrics.md)) | `host` (the last: none) |
| `superbot_host_*`: botd's own host and Incus hosts' CPUs, load, memory and disk ([ADR 0106](0106-host-capacity-metrics.md)) | `host`, `kind`, and `disk` for disks |
| `superbot_machine_rpo_breaches_open`, `superbot_machines_rpo_tracked`, `superbot_machines_past_rpo`, `superbot_machine_backup_age_max_seconds`, `superbot_machine_rpo_seconds` (with off-host backups on) | `tier` (the first: none) |
| `superbot_build_info` | `version` |

Request duration is to the first byte of the answer, so a long SSE stream (`/api/events`) counts its setup, not its life.

### Labels stay bounded and say nothing about people

Every label value is one of a fixed list in the code: route classes (`bots`, `approvals`, `machines`, `users`, `auth`, `events`, `approval_hook`, `scim`, `web` and a few more, from the path's first segments only), HTTP methods, status classes (`2xx`), harness names, run results, audit actions, machine states. A value not on its list is `other`. Refusal reasons are botd's own snake_case words, capped at 32 distinct values. Tier names are the operator's `MACHINE_TIERS`. There are no user, Bot, machine, approval or run ids, no paths, emails, names, messages or tokens. So a server's series count doesn't grow with its users, and tests check that emails, names, message text, query strings and ids in requests never reach the output.

The roadmap's "RED metrics per user" isn't built: a label per user is unbounded and names people. Per-user usage stays in the admin usage views ([ADR 0050](0050-billing-period-token-usage.md)). Per tier for requests and runs is left for later: a run's tier is known, but a request's isn't until after auth, and the useful split hasn't shown itself yet.

### Structured JSON logs, with request and run ids

`LOG_FORMAT=json` (default `text`) prints one JSON object per line, on the same streams as before (information on stdout, warnings on stderr), for journald, Docker, or any shipper to parse:

- **botd's own lines** become `{"ts", "level", "msg"}`. `ts` is UTC, RFC 3339, in milliseconds. A leading `WARNING: ` becomes `"level": "warn"`.
- **Every request**: `http.request`, with `requestId`, `method`, `route` (the matched template, such as `/api/bots/{id}/messages`, never the path as sent; absent when a request was refused before routing, by sign-in or SCIM's guard, or matched nothing), `routeClass`, `status` and `durationMs`. Successful `/healthz` checks aren't logged.
- **Every run**: `message.queued` (with the `requestId` that queued it, if any), then `run.started` and `run.finished`, with `runId` (the same `r…` id the audit log and run tokens use), `messageId`, `botId`, `harness`, `trigger`, `host`, and on finishing `result`, `durationMs` and `attempts`. The message id joins a request to the run it started.
- **Request ids.** botd gives every request an id and returns it as `X-Request-Id`. One sent in (by Caddy, a load balancer or a client) is kept if it's 1 to 64 letters, digits, `-`, `_` or `.`. Otherwise botd makes a new one, so nothing else a caller sends is logged.

The structured lines carry only botd's own ids, names of harnesses and routes, statuses and timings: no user ids, emails, names, IP addresses, user agents, message text, tool input, paths as sent, or tokens. Those stay in the audit log, behind admin access and its redaction (ADR 0010, ADR 0019). In text format, nothing changes: no request or run lines are added, and botd's lines print as before.

### Defaults don't change

Nothing is on until set. The installer and Docker Compose write neither setting, and Compose publishes no new port. [deploy/README.md](../../deploy/README.md#metrics-and-logs) says how to turn each on, for the installer and for Compose.

## Consequences

- Operators can scrape botd, graph it and alert on errors, latency, failing runs, approvals waiting, and machines past their RPO, instead of polling the recovery API and reading the audit log.
- Counters live in memory and reset on restart. Prometheus handles that (`rate()`, `increase()`). The gauges read from the database are right after a restart.
- A scrape reads a few counts from SQLite and, with off-host backups on, each live machine's newest backup and restore: two small queries per machine. At hundreds of machines and a 15 to 60 second scrape interval that's negligible. At many thousands it'd want caching.
- On a server without per-user accounts, every Bot runs as botd's account and could read a loopback `/metrics` anyway, as it could read `.env`. The metrics hold nothing secret, but `METRICS_TOKEN` keeps scrapes to those with it.
- Deferred: traces (OpenTelemetry, OTLP export, harness run spans); shipping logs (left to the operator's pipeline: journald, Docker's logging drivers, Vector, Promtail); dashboards and alert rules (examples to come with the docs portal); the status page and SLO ([#47](https://github.com/CG-Labs/superbot/issues/47)); error reporting; the self-host server's own `DATA_DIR` backup age (the backup runs outside botd, as a timer or the Compose sidecar, so node_exporter's textfile collector is the place for it); per-tier request and run labels; metrics from machines' agents.
