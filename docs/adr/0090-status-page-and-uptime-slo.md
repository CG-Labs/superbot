# 0090: Status page and uptime SLO

## Status

Accepted (21 Nov 2026). The status page and SLO of M4, [#47](https://github.com/CG-Labs/superbot/issues/47). Builds on metrics and structured logs ([ADR 0089](0089-metrics-and-structured-logs.md)), machine RPO and RTO ([ADR 0074](0074-machine-rpo-and-rto.md)), the self-host server's backup targets ([ADR 0030](0030-backup-restore-drill.md)), RBAC ([ADR 0012](0012-users-sessions-rbac.md)) and the audit log ([ADR 0009](0009-audit-events.md)).

Numbering: `main` has up to 0089. Open PR #149 adds another 0089 (billing emails), which has to move when it merges, so this is 0090. Renumber it if a collision appears at merge.

## Context

M4's exit criteria include "SLO defined for managed uptime", and managed customers need somewhere to see whether SuperBot is up and what's being done when it isn't. ADR 0089 gave botd numbers to alert on, but no objective to alert against and no page for customers. Machines already have an RPO and RTO per plan; the service itself had no availability target.

The page has to be public, so it must be safe to expose: no tenant data, no counts that say how big a customer base is, no hostnames, errors or tokens. And it has to stay honest when it matters most: a page that says "operational" while botd is down is worse than none.

## Decision

### The SLO

[docs/slo.md](../slo.md) is the objective, in the same contract-ready style as the [machine recovery objectives](../security/machine-recovery-objectives.md):

- **Per plan, over a rolling 30 days**: Starter 99.5% (3 h 36 min of budget), Pro and Max 99.9% (43 min), Enterprise 99.95% by agreement, on a deployment of its own. Pro and Max get the same objective because they share a server and sell resources, not a different service (the same reasoning as ADR 0074's single RTO).
- **Consistent with the RTO.** One whole-server restore at its 1-hour RTO spends more than Pro's monthly budget. So the doc says so and recommends an SLA with credits below the objective (99.0% Starter, 99.5% Pro and Max), and not signing 99.9% before a quarter's measurement shows it.
- **Two indicators.** *Uptime*, the contractual one: an outside-in probe of `/status.json` every 30 seconds; a minute is down when both checks fail. *Request success*: the non-5xx share of `superbot_http_requests_total`, excluding probes, as the early warning that drives burn-rate alerts. botd can't count its own downtime, so the probe is the measure of record. A machine down on a failed host is covered by its RPO and RTO, not this objective, unless every host is down.
- **An error budget policy**: review at half spent; only fixes and reliability work once it's all spent; a written review for any incident that spent a quarter.

### The status page: botd serves it

`GET /status` (HTML) and `GET /status.json` are served by botd on its main port, beside `/healthz`, outside sign-in. `/status.json` answers 503 (with the same body) when the overall status is a major outage and 200 otherwise, so an uptime probe that wants a 2xx counts a server that answers but is down as down; `/status`, for people, is always 200. Caddy already sends every path it doesn't serve itself to botd, so neither the installer's Caddyfile nor Compose's changes.

**Why in botd, not a hosted status service.** The components' health comes from botd's own checks and counters, which no outside service can see without a scrape endpoint being opened to it. A hosted page (Statuspage, Instatus, Better Stack) can still be put in front by an operator who wants one off-site: `/status.json` uses the component status names those tools use (`operational`, `degraded_performance`, `partial_outage`, `major_outage`, `under_maintenance`). The cost: if the server is down, so is its page. That's acceptable because the outside probe is what measures uptime and pages on-call, and an operator can publish the probe's results elsewhere.

### What each component looks at

| Component | Shown | Looks at |
|---|---|---|
| API | always | the 5xx share of the last 5 minutes of requests (from 20 requests): 5% degraded, 25% partial outage, 50% major outage |
| Database | always | `SELECT 1` through the same connection lock as every query: an error is a major outage, slower than 500 ms degraded |
| Machines and control plane | control plane on | hosts not answering (some: partial outage; all: major outage), the reconciler more than 3 intervals and a minute behind, 10% or more of live machines in error, or open RPO breaches (degraded) |
| Harness runners | always | the failed share (error or timeout) of the last 15 minutes of finished runs (from 4): 25% degraded, 50% partial outage |
| Notifications | a channel on: push, or email (with SMTP set up) or a webhook for the server or any Bot | the last 15 minutes of `notification.failed` against `notification.sent`: 5 failures and no successes is a partial outage; at least 2 failures and half or more failing, degraded |

"The last minutes" come from a small per-minute window (15 minutes) kept beside ADR 0089's counters and fed by the same calls (except requests to `/healthz` and the status pages, so probes can't dilute the API's error share), so the page reacts to now rather than to totals since the last restart. Stopped, interrupted and policy-ended runs aren't failures. The thresholds are constants in `server/src/status.rs`, tested one by one.

### Incident notes

Admins post incidents in the console's Status tab or at `/api/status/incidents` (`GET`, `POST`; `PATCH` and `DELETE /{id}`; `POST /{id}/updates`). Each has a title, an impact (`none`, `minor`, `major`, `critical`, `maintenance`), the components it affects, and a timeline of updates, each with a state (`investigating`, `identified`, `monitoring`, `resolved`) and a body. They live in SQLite (`status_incidents`, `status_incident_updates`), so they're in the server's backups. Each incident and its first update, and each update and the state it sets, are written in one transaction. A write that fails answers 500 and isn't audited. Every change is audited (`status.incident_created`, `status.incident_updated`, `status.incident_deleted`).

An open incident raises each component it names to at least its impact (minor: degraded, major: partial outage, critical: major outage, maintenance: under maintenance), and an open incident naming none still sets the overall status. Every open incident counts, not just those listed. Checks can make things worse than the incident says, never better. Resolved incidents stay on the page for 14 days, up to 20 incidents and 10 updates each.

The routes fall to `Admin` in `rbac::classify` like every unclassified route; Bots and members get 403.

### Safe to expose

- Components and their notes are fixed strings in the code. No counts, ids, hostnames, error text, tiers or customer names are ever in the output.
- Incident text is the one thing people write. The public view drops authors and update ids. Titles (up to 120 characters) and bodies (up to 2,000) lose control characters, known secret values are redacted before they're saved (the same redaction as the audit log, ADR 0010), and the console says that anyone can read them. The HTML escapes everything.
- The HTML page runs no script: `Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'`, no frames, no forms, `nosniff`, and it reloads itself every minute with a meta refresh.
- **Cost of being open.** One snapshot (a few small queries) answers every caller for 10 seconds, and an incident change clears it. So fetching the page in a loop costs botd a few queries every 10 seconds, whatever the rate.
- `STATUS_PAGE=off` turns both pages into a 404, for a self-hoster who doesn't want one. It's on by default, like `/healthz`.

### Burn-rate alerts

[`deploy/prometheus/superbot-slo.rules.yml`](../../deploy/prometheus/superbot-slo.rules.yml) has recording rules for the 5xx share over 5 minutes to 3 days and the multiwindow, multi-burn-rate alerts from the Google SRE workbook (14.4× and 6× page; 3× and 1× ticket), plus botd down (`up`), the probe failing (`probe_success`), and runs failing. The target is one recording rule (`superbot:slo_availability:target`, 0.999), so a Starter-only server changes one line. CI runs `promtool check rules` and `promtool test rules` against a test file with a failing hour, a healthy day, a dead scrape and failing runs; a Rust test checks that every metric the rules name is one botd exports, so renaming a metric can't leave an alert that never fires.

## Consequences

- Managed customers get a status page and the Provider gets an objective, an error budget and alerts with no new service to run. Operators who want an off-site page can feed one from `/status.json` or from their probe.
- botd's own page can't show botd down. The outside probe and `SuperBotDown` cover that, and docs/slo.md makes the probe the measure of record.
- The component checks are heuristics over short windows: a burst of 5xx in a quiet minute (20 requests) can flash "degraded" for a few minutes. That's the trade for a page that reacts quickly; the SLO itself is measured over 30 days.
- A server with no traffic shows "operational" for API and runners: there's nothing to judge. The database check still runs on every snapshot.
- Deferred: uptime history bars (needs storing samples, or reading them from Prometheus); scheduled maintenance in the future (post it as a `none`-impact note until it starts); email or webhook subscriptions to incidents; per-tier or per-region components; showing the probe's own results on the page.
