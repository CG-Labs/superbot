# 0288: Alert history evidence from Prometheus

## Status

Accepted (25 Nov 2026). Eighteenth slice of the SOC 2 Type II programme ([#57](https://github.com/CG-Labs/superbot/issues/57), M5). Adds a seventh command to `superbot-evidence` ([ADR 0148](0148-change-management-evidence-from-github.md)) and a seventh kind of bundle to the coverage report ([ADR 0169](0169-evidence-coverage-report.md)). Reads the alert rules of [ADR 0090](0090-status-page-and-uptime-slo.md), [ADR 0104](0104-suspicious-sign-in-alerts.md), [ADR 0106](0106-host-capacity-metrics.md) and [ADR 0113](0113-service-dashboards-and-error-reporting.md) as the operator's Prometheus ran them. Serves readiness checklist rows CC2.1-1, CC7.2-1 and A1.1-1 in the [evidence plan](../security/soc2-evidence-plan.md#the-alerts-bundle).

## Context

Three **Done** rows ask for "alert history": CC2.1-1 (metrics, alert rules and dashboards), CC7.2-1 (alerts on suspicious sign-ins) and A1.1-1 (host capacity metrics). The rules ship in `deploy/prometheus/` and are tested with `promtool`, but what they fired on a running server lived only in the operator's Prometheus and Alertmanager, kept for as long as they keep it (Prometheus' default is 15 days). The evidence plan's calendar listed "alert history from the operator's Alertmanager" as a monthly manual task with no format, the coverage report listed none of the three rows as collected by any bundle, and nothing showed that the rules were loaded at all: a server whose operator never loaded them, or whose Prometheus was down for a week, looked the same as a quiet month.

Alertmanager's own API holds only the alerts active now, so it can't give a month's history. Prometheus can: every alerting rule writes an `ALERTS` series with a sample at each evaluation while the alert is pending or firing, kept as long as Prometheus keeps anything.

## Decision

### `superbot-evidence alerts`

`superbot-evidence alerts --prometheus <url> [--watch <selector>] [--rules <rule file>]... [--from <YYYY-MM-DD> --to <YYYY-MM-DD>] [-o <file>]`, with the binary's period rules (last month by default), private never-overwritten output, `PROMETHEUS_TOKEN` handled as the uptime bundle handles it ([ADR 0249](0249-uptime-evidence-from-the-outside-probe.md): never on the command line, never over plain `http` off this computer) and the same Prometheus client, which gains a read of `/api/v1/rules`. It refuses a period that hasn't ended. It writes a bundle in the change-management bundle's shape, folder `superbot-alerts-<from>_<to>-<UTC time>/`, manifest kind `alerting`, with one file, `alerts.json`.

It reads four things:

- **Episodes.** The raw samples of `ALERTS{alertstate="firing"}`, a day at a time as the uptime bundle reads the probe (an instant query of a range vector a minute longer than the day, keeping only the day's samples). Samples of one series no more than 5 minutes apart are one episode, from its first sample to its last; 5 minutes is Prometheus' lookback and well over the 30 to 60 second evaluation intervals the deploy guide uses. Only alerts named `SuperBot…` or in the expected rules are kept; others' samples are counted, not named, since an operator's Prometheus may alert on things that aren't ours to record. Each episode has its alert, severity, a series id (a digest of all its labels), its labels shown, minutes, and whether it was firing at the period's start or end.
- **Whether Prometheus was watching.** The raw samples of `--watch`, by default `up{job="superbot"}`, botd's scrape, which `SuperBotDown` and every other shipped rule read. Prometheus writes an `up` sample at each scrape, 0 or 1, so a stretch without one means Prometheus wasn't scraping botd and no SuperBot alert could fire. Stretches of more than 5 minutes are gaps, the period's edges included, and their minutes are summed by month and day. A period with no watch samples at all is refused: a wrong `--watch` or the wrong Prometheus, not a month of evidence.
- **The rules loaded**, from `/api/v1/rules?type=alert`, as the bundle is made. Each expected rule is judged loaded, healthy (not `health: err`), evaluated in the last 10 minutes, and given its expected severity. The expected rules are those in the rule files `deploy/prometheus/` ships, built into the binary (a unit test checks the list against the folder), or with `--rules`, those in the files the operator loads, recorded by name, size and SHA-256, so a server without Incus can leave out the capacity rules and say so. Rule files are read for `alert:` names and the `severity:` label under each, enough for the shipped files' shape, without a YAML parser. Loaded `SuperBot…` rules that weren't expected are listed by name.
- **Notifications**, where Prometheus scrapes Alertmanager: `sum by (integration) (increase(alertmanager_notifications_total[1d]))` and the same of `alertmanager_notifications_failed_total` at each day's end, rounded. A day with no such series is recorded as not recorded, not as zero.

### What maps

The manifest names CC2.1, CC7.2, A1.1 and rows CC2.1-1, CC7.2-1 and A1.1-1 only while the period's unwatched minutes fit in the 99.9% error budget (44.6 minutes in a 31-day month, the uptime bundle's measure, so monitoring is held to what the service is) and every expected rule is loaded, healthy and evaluated. A month Prometheus wasn't watching, or whose rules weren't loaded or are failing, is a gap in the coverage report, not evidence that nothing happened.

**Exceptions** (counted by the coverage report): every page, which needs its response on record (a ticket, or an incident in the [policy register](../security/policy-register.md#incidents)); episodes that fired more than a day; alerts still firing at the period's end; watch gaps, and months whose gaps exceed the budget; rules that couldn't be read, aren't loaded, are failing, aren't being evaluated, or are loaded with another severity (a page downgraded to a ticket reaches no one on call); notifications that failed, by day and integration; and the days with no notifications recorded.

**What stays out.** The token, the Prometheus address, rule files' paths, rules' expressions and errors (`lastError` can quote a target), and every label but `alertname`, `severity`, `job` and the ones the shipped rules group by that never name a host (`harness`, `route_class`, `provider`, `tier`); `instance`, `host` and `target` go only into the series' digest. Group and integration names are kept when plain.

### Coverage

The coverage report knows the seventh prefix, kind and format, expects `alerts.json` in every alerts bundle, counts its exceptions, and maps its three rows. A store without alerts bundles now reports that kind as missing, so a store complete before isn't complete until they are added, as with uptime bundles. The `change-evidence` workflow doesn't make one: it runs on GitHub, which can't reach the operator's Prometheus.

## Alternatives considered

- **Alertmanager's API** (`/api/v2/alerts`): only the alerts active now, and silences; no history.
- **An Alertmanager webhook receiver in botd** recording every notification: a history from the moment it's set up, but it shows what was routed, not what fired, misses whatever Prometheus never sent, and puts a receiver for an operator's whole Alertmanager in the product. Prometheus already keeps the record.
- **Range queries of `ALERTS`** on a grid: simpler, but values are carried forward 5 minutes after the last sample, smearing every episode's end; raw samples carry the evaluation times.
- **Prometheus' own `up` for the watch** (`up{job="prometheus"}`): shows Prometheus ran, not that it could reach botd; botd's scrape is what the rules read.
- **Rule evaluation failures over the period** from `prometheus_rule_evaluation_failures_total`: needs Prometheus to scrape itself, which isn't set up by the deploy guide. The rules are checked as of the bundle's making instead, and a bundle made more than 7 days after its period is already flagged by the coverage report.
- **Matching pages to register incidents automatically**: the register names incidents by id and detection time, not alert episodes; the pages are listed for the person sampling to match.

## Tests

- Unit tests in `alerts.rs`: the shipped rule files parse with a severity on every alert and are all expected; rule files parse (quoted names, comments, `alert:` after `expr:`, recording rules' labels ignored) and refuse files without alerts or with bad names; a month with two episodes of one alert split by a gap, a ticket still firing at the end, someone else's alert skipped, a watch gap, notifications sent and failed and days not recorded, a rule not loaded, failing, not evaluated and with another severity, none of which maps, nothing of hosts, expressions, paths or errors written; a clean month maps and unreadable rules don't; a month Prometheus mostly missed maps no controls, a full one maps the three rows; a period with no watch samples is refused; watch gaps at the edges, date ranges and months; options, the token never on the command line, and a period that hasn't ended; the default watch is the scrape job the deploy guide names and `SuperBotDown` reads; names don't collide; the file maps to real controls and the evidence plan's table says so.
- `server/tests/alert_evidence.rs`: the real binary against a stand-in Prometheus (both series a day at a time, the notification counters, the rules, the bearer token on every request): the summary, `tar -xf` and `sha256sum -c`, the manifest, the episodes and notifications, nothing of the token, address, hosts, expressions or paths in the bundle, `coverage` checking the bundle and covering the three rows; an operator's rule file naming a rule that isn't loaded maps nothing; nothing is written over a file, a token isn't sent in clear, and a watch with no samples writes nothing.
- `coverage.rs` and `evidence_coverage.rs`: the seventh kind is expected and reported missing when absent.

## Consequences

- The three rows' alert history is collected like the rest of the calendar; the screenshots of live dashboards stay manual.
- Operators run it themselves each month, where Prometheus is reachable, and keep Prometheus' retention over a month (the default 15 days isn't); a month not made is a gap in the coverage report.
- A page's response is still a record people keep; the bundle is the population an auditor samples it from.
- The shipped rule files are now read by the binary as well as `promtool`; adding one to `deploy/prometheus/` fails a unit test until it is listed.

## Deferred

- Matching pages to register incidents or tickets.
- Rule evaluation failures through the period, once the deploy guide has Prometheus scrape itself.
- Silences in force through the period, which Alertmanager doesn't keep a history of either.
