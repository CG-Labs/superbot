# 0118: Harness run traces and per-tier metrics

## Status

Accepted (22 Nov 2026). Part of Observability in M4, [#46](https://github.com/CG-Labs/superbot/issues/46). Builds on metrics and structured logs ([ADR 0089](0089-metrics-and-structured-logs.md)) and the request/run dashboards and error reporting ([ADR 0113](0113-service-dashboards-and-error-reporting.md)), which both left tracing and per-tier labels for later.

0116 is the highest number on `main`; open PR [#180](https://github.com/CG-Labs/superbot/pull/180) holds 0117.

## Context

#46 asks for structured logs, RED metrics per user or tier, harness run traces and error reporting. Logs, request and run metrics, dashboards and error reports exist. Two gaps were left:

- **No traces.** A slow or failed run shows up as one `run.finished` line and a histogram bucket. Nothing showed where the time went: waiting for a slot, the harness itself, a tool, an approval the owner sat on, or a call to a Bot's machine. The request that queued the run, the run, and the Bot's own calls back to botd during it (its approval hook, `botctl`) had no shared id.
- **RED metrics only by route class and harness.** An operator selling tiers couldn't see whether one plan's users were getting errors or slow runs.

Whatever is added must keep ADR 0089's rules: off unless asked for, nothing that could carry a user's words, a secret or a path, and bounded label sets.

## Options

1. **The `opentelemetry` crates** (`opentelemetry`, `opentelemetry_sdk`, `opentelemetry-otlp`, `tracing-opentelemetry`). The standard SDK, but about 40 crates more, protobuf code generation or a gRPC stack, and botd doesn't use `tracing` today, so every call site would change twice. Its context propagation is thread- and `tracing`-span based, which doesn't follow botd's spawned run tasks without the same plumbing we'd write anyway.
2. **Write spans to the structured log** and let the log shipper build traces. Most log pipelines can't, and it would make `LOG_FORMAT=json` lines much noisier.
3. **A small OTLP/HTTP JSON exporter in botd**, like the error reporter of ADR 0113 (a Sentry client in about 300 lines). OTLP/HTTP with JSON bodies is part of the OTLP spec, every OpenTelemetry Collector, Grafana Tempo, Jaeger, Honeycomb and most vendors accept it, and botd already has `reqwest` and `serde_json`.

Option 3: no new dependencies, and the exporter knows botd's privacy rules instead of trusting call sites to apply them.

## Decision

### Settings, off by default

| Variable | Default | Meaning |
|---|---|---|
| `TRACES_OTLP_ENDPOINT` | off | OTLP/HTTP traces URL. An empty path becomes `/v1/traces`. HTTPS, or HTTP to loopback only |
| `TRACES_OTLP_INSECURE` | off | `on` allows plain HTTP to a non-loopback collector (a sidecar on a private network) |
| `TRACES_OTLP_HEADERS` | none | `name=value` pairs split by commas (an API key). A server secret: `_FILE` works, values are redacted, and no harness inherits it |
| `TRACES_SAMPLE_RATIO` | `1` | Share of new traces kept, 0 to 1, decided on the trace id so a whole trace is kept or dropped |
| `TRACES_PARENT` | `ignore` | `accept` continues a caller's W3C `traceparent` (behind a proxy that traces). Ignored by default, so a stranger can't choose botd's trace ids or force sampling |

They are SuperBot's own names, not `OTEL_EXPORTER_OTLP_*`: harnesses inherit botd's environment, and Claude Code, Codex and Pi read the `OTEL_*` names for their own telemetry, which would start sending it unasked. Endpoints with user info, a query or a fragment are refused so a key can't hide in the URL; the endpoint's host is all that's logged.

With no endpoint, no span is made: every span is an inert `Option` and costs one branch.

### Spans

| Span | Kind | Parent | Attributes |
|---|---|---|---|
| `{method} {route}` | server | a trusted `traceparent`, else none; a Bot's request joins its run | `http.request.method`, `http.route` (the template), `superbot.route_class`, `superbot.request_id`, `superbot.tier`, `http.response.status_code` |
| `run {harness}` | internal | the request that queued the message (a routine or a timer: none) | `superbot.message_id`, `superbot.bot_id`, `superbot.harness`, `superbot.trigger`, `superbot.tier`, `superbot.run_id`, `superbot.host`, `superbot.run.waited_for_slot`, `superbot.run.result`, `superbot.run.attempts`, `superbot.run.refused` |
| `harness {harness}` | internal | the run; one per attempt (a lost session retries) | `superbot.attempt`, `superbot.resumed`, `superbot.guarded`, `superbot.host`, `gen_ai.request.model`, `superbot.attempt.result`, `superbot.replies`, `gen_ai.usage.input_tokens`, `gen_ai.usage.output_tokens` |
| `tool {name}` | internal | the attempt, from the harness's tool call to its result | `superbot.tool.name`, `superbot.tool.ran` |
| `approval.check` | internal | the Bot's hook request | `superbot.harness`, `superbot.tool.name`, `superbot.policy.action`, `superbot.policy.class`, `superbot.approval.status`, `superbot.approval.id` |
| `machine.job` | client | the attempt, for a run on a Bot's machine | `superbot.machine_id`, `superbot.job_id` |
| `{method} /v1/{call}` | client | whatever called the machine's agent | `http.request.method`, `superbot.agent.call`, `superbot.machine_id`, `http.response.status_code` |

Each audit event recorded inside a span is added to it as a span event named by its action, with its outcome and reason code. Spans are marked as errors for 5xx answers, failed runs and attempts, and failed agent calls. Health checks and the status page make no spans. Calls to a machine's agent carry a `traceparent`, so the agent can join later; the agent and the harness CLIs don't emit spans yet.

A Bot's requests during a run are tied to it through the run id inside its `BOT_TOKEN` ([ADR 0083](0083-per-run-tokens.md)): botd keeps the live attempts' spans by run id and makes the request's span a child of the attempt's. Nothing from the Bot's side is trusted to pick the trace. Queued messages remember the request that queued them the same way. Both registries are bounded (4096 entries).

### What never goes in a span

Attribute names are fixed strings in botd's code. Values are ids botd made (request, run, message, Bot, machine, approval), names from fixed lists (route templates, route classes, harnesses, tiers, policy classes, audit actions, results), numbers and booleans. Tool names are kept only if they look like identifiers (`Bash`, `mcp__github__search`); anything else is `other`. Every string still goes through the error reporter's scrubber (known secrets redacted, emails replaced, 200 characters at most). No message text, prompt, reply, tool input or output, file path, user id, email or name is ever set, and the HTTP tests check a run with all of those in it.

### Logs and the audit log

When a span is kept, structured log lines written inside it gain `traceId` and `spanId`, and audit events recorded inside it gain them in `details`, so an operator can go from an audit row or a log line to the trace. Unsampled and untraced work adds nothing.

### Export

Finished spans are queued (2048 at most; past that they are dropped and counted) and sent in batches of up to 256 every 5 seconds, or sooner when a batch fills, as `ExportTraceServiceRequest` JSON with `service.name=superbot-botd` and `service.version`. Requests time out after 10 seconds and don't follow redirects. A failure logs one warning until a send works again. On shutdown botd waits up to 3 seconds to send what's left.

| Metric | Labels | Meaning |
|---|---|---|
| `superbot_tracing_enabled` | none | 1 when `TRACES_OTLP_ENDPOINT` is set |
| `superbot_trace_spans_total` | `outcome` (`sent`, `failed`, `dropped`) | Spans the collector accepted, spans it refused or that could not be sent, and spans dropped from a full queue |

### Per-tier RED metrics

When `/metrics` is on (or traces are), each request and run is labelled with the tier of whoever it's for: a signed-in person's plan ([ADR 0093](0093-team-billing.md) for team plans), a Bot's owner's plan for a Bot's request and runs, and `none` for a request with no signed-in caller. Health checks aren't counted.

| Metric | Labels |
|---|---|
| `superbot_http_requests_by_tier_total` | `tier`, `status_class` |
| `superbot_http_request_duration_by_tier_seconds` | `tier` (histogram) |
| `superbot_runs_by_tier_total` | `tier`, `result` |
| `superbot_run_duration_by_tier_seconds` | `tier` (histogram) |

They are separate families, so the existing series, dashboards and alert rules don't change. Tiers are names an operator configures; the first 16 seen get their own label and any more are `other`. There is no per-user label: user ids would grow without bound and put an identifier in every scrape. An operator who needs one user's numbers can filter traces by `superbot.bot_id` or use the usage API.

## Consequences

- An operator with a collector can see where a run's time went and follow a request into its run and the Bot's approval hook. Without one nothing changes: no span is made, the headers setting is never read, and `/metrics` gains only `superbot_tracing_enabled 0` and, when it's on, the per-tier families.
- Our own exporter means we keep up with OTLP ourselves. The JSON encoding is stable and the exporter is one module of about 1000 lines, tested against a fake collector; if botd moves to `tracing`, the span model and attribute names carry over.
- Sampling is head-based. A rare failed run is kept only at the ratio; tail sampling belongs in a collector.
- Still open on #46: spans from inside the machine agent and the harness CLIs (their own OpenTelemetry output, opt-in per Bot), per-tier alert rules and dashboard panels, browser errors, and log shipping guidance.
