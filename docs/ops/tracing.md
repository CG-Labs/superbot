# Traces

botd can send OpenTelemetry traces over OTLP/HTTP: a span for each request and each Bot run, with the harness attempts, tool calls, approval checks and calls to a Bot's machine inside it. Use them to see where a slow or failed run spent its time, and to follow a request into the run it queued and the Bot's own calls back to botd. Off by default; nothing changes until you set an endpoint. Design: [ADR 0118](../adr/0118-harness-run-traces-and-per-tier-metrics.md).

## Settings

In `.env` (installer) or `deploy/docker/.env` (Compose):

| Setting | Default | Meaning |
|---|---|---|
| `TRACES_OTLP_ENDPOINT` | `off` | The collector's OTLP/HTTP URL. With no path, `/v1/traces` is added. `https://`, or `http://` to loopback |
| `TRACES_OTLP_INSECURE` | `off` | `on` allows `http://` to any host, for a collector on a private network such as the Compose network |
| `TRACES_OTLP_HEADERS` or `TRACES_OTLP_HEADERS_FILE` | none | Headers for the collector, `name=value` pairs split by commas, such as `Authorization=Bearer <token>`. A secret: values are redacted everywhere and no Bot's harness gets them |
| `TRACES_SAMPLE_RATIO` | `1` | Share of new traces kept, `0` to `1`. A trace is kept or dropped whole |
| `TRACES_PARENT` | `ignore` | `accept` continues a W3C `traceparent` header sent in, when a proxy in front of botd traces too. Leave it at `ignore` when botd faces the internet directly |

botd reads its own `TRACES_*` names, not `OTEL_EXPORTER_OTLP_*`, because harnesses inherit botd's environment and would start sending their own telemetry. Restart botd after a change. A bad value stops botd at startup with a message naming the setting.

## Quick try: Jaeger on the same host

```sh
docker run -d --name jaeger -p 127.0.0.1:16686:16686 -p 127.0.0.1:4318:4318 jaegertracing/jaeger:<version>
echo 'TRACES_OTLP_ENDPOINT=http://127.0.0.1:4318' | sudo tee -a ~superbot/superbot/.env
sudo systemctl restart superbot
```

Send a Bot a message, then open `http://127.0.0.1:16686` (through an SSH tunnel) and pick the `superbot-botd` service.

## An OpenTelemetry Collector

A collector lets you sample, batch and send to any backend (Grafana Tempo, Honeycomb, Datadog). A minimal one that receives botd's spans and sends them to Tempo:

```yaml
# otel-collector.yaml
receivers:
  otlp:
    protocols:
      http:
        endpoint: 0.0.0.0:4318
processors:
  batch: {}
exporters:
  otlphttp:
    endpoint: http://tempo:4318
service:
  pipelines:
    traces:
      receivers: [otlp]
      processors: [batch]
      exporters: [otlphttp]
```

With Compose, add it beside botd in a `docker-compose.override.yml`, on the same network:

```yaml
services:
  otel-collector:
    image: otel/opentelemetry-collector-contrib:<version>
    command: ["--config=/etc/otel-collector.yaml"]
    volumes: ["./otel-collector.yaml:/etc/otel-collector.yaml:ro"]
    restart: unless-stopped
```

and in `deploy/docker/.env`:

```sh
TRACES_OTLP_ENDPOINT=http://otel-collector:4318
TRACES_OTLP_INSECURE=on
```

A hosted backend usually takes an API key in a header: `TRACES_OTLP_ENDPOINT=https://<collector-host>` and `TRACES_OTLP_HEADERS=<header-name>=<api-key>`. Keep the key in a file with `TRACES_OTLP_HEADERS_FILE` (mode `0600`, owned by the service user) instead of `.env` if you prefer.

## What a trace shows

```
POST /api/bots/{id}/messages            the request that sent the message
└─ run claude                           the run: waited for a slot? result, attempts
   └─ harness claude                    one attempt: model, replies, tokens, result
      ├─ tool Bash                      from the tool call to its result
      ├─ POST /api/approvals/check      the Bot's approval hook, joined by its run token
      │  └─ approval.check              policy action and class, the approval's outcome
      └─ machine.job                    a run on the Bot's machine, over its agent's link
```

Other calls to a machine's agent made during a traced request (a teammate's login, a screen, an upgrade) are client spans named by method and the first two path segments, such as `POST /v1/logins`; they carry a `traceparent` header so the agent can join later.

| Span | What it carries |
|---|---|
| `{method} {route}` | `http.route` (the template, never the path as sent), `superbot.route_class`, `superbot.request_id` (the `X-Request-Id`), `superbot.tier`, `http.response.status_code` |
| `run {harness}` | `superbot.bot_id`, `superbot.message_id`, `superbot.run_id`, `superbot.trigger`, `superbot.tier`, `superbot.host`, `superbot.run.waited_for_slot`, `superbot.run.result`, `superbot.run.attempts`, and `superbot.run.refused` with the reason code when a limit refused it |
| `harness {harness}` | `superbot.attempt`, `superbot.resumed`, `superbot.guarded`, `gen_ai.request.model`, `superbot.attempt.result`, `superbot.replies`, `gen_ai.usage.input_tokens`, `gen_ai.usage.output_tokens` |
| `tool {name}` | `superbot.tool.name`, `superbot.tool.ran` |
| `approval.check` | `superbot.tool.name`, `superbot.policy.action` (`allow`, `ask`, `deny`), `superbot.policy.class`, `superbot.approval.status`, `superbot.approval.id` |
| `machine.job`, `{method} /v1/{call}` | `superbot.machine_id`, `superbot.job_id`, `superbot.agent.call`, `http.response.status_code` |

Audit events recorded during a span appear on it as span events (`bot.token_issued`, `approval.requested`, `bot.run_finished`, ...), with their outcome and reason code. Failed runs and attempts, tool calls that end in an error (refused, blocked or failing), 5xx answers and failed machine calls are marked as errors. Health checks and the status page make no spans.

A routine's or a timer's run starts its own trace.

## From a log line or an audit row to its trace

With `LOG_FORMAT=json`, every line written during a kept trace has `traceId` and `spanId`; so does every audit event's details. To find a run's trace from the log:

```sh
journalctl -u superbot -o cat | jq -r 'select(.msg == "run.finished" and .result == "failed") | .traceId'
```

Paste the id into your backend's trace search. In Grafana Tempo, TraceQL finds failed runs of one harness: `{ name = "run claude" && span.superbot.run.result = "failed" }`.

## What is never sent

Attribute names are fixed in botd's code, and values are ids botd made, names from fixed lists, numbers and booleans. Tool names are kept only when they look like identifiers; anything else is `other`. Every string, span names included, is scrubbed before it's sent: known secrets redacted, anything like an email replaced, at most 200 characters. No message, prompt, reply, tool input or output, file path, user id, email, name or IP address is ever in a span. The collector sees botd's IP address as the sender.

## Sampling

`TRACES_SAMPLE_RATIO` decides from the trace id, so every span of a trace is kept or dropped together, and a Bot's calls during a run follow the run's decision. Sampling happens when the trace starts, so a ratio below 1 can miss a rare failure; keep `1` and sample in the collector (its `tail_sampling` processor can keep every error) if that matters. Logs and audit events name a trace only when it was kept.

## Checking it works

`/metrics` (when on) shows:

- `superbot_tracing_enabled`: 1 when an endpoint is set.
- `superbot_trace_spans_total{outcome}`: spans the collector accepted (`sent`), refused, rejected in a partly accepted export, or couldn't be sent (`failed`), and dropped because 2048 were already waiting (`dropped`).

botd logs one warning when sending starts failing (`sending spans to the trace collector: it ...`) and doesn't repeat it until a send works again. Spans are sent every 5 seconds, and on shutdown botd waits up to 3 seconds to send the rest.

## Per-tier metrics

With `/metrics` on, requests and runs are also counted by tier: see [Metrics and logs](../../deploy/README.md#metrics-and-logs). They need no tracing.
