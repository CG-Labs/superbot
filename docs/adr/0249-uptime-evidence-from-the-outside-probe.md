# 0249: Uptime evidence from the outside probe

## Status

Accepted (24 Nov 2026). Thirteenth slice of the SOC 2 Type II programme ([#57](https://github.com/CG-Labs/superbot/issues/57), M5). Adds a sixth command to `superbot-evidence` ([ADR 0148](0148-change-management-evidence-from-github.md)) and a sixth kind of bundle to the coverage report ([ADR 0169](0169-evidence-coverage-report.md)). Measures the availability SLO of [ADR 0090](0090-status-page-and-uptime-slo.md) ([docs/slo.md](../slo.md)). Serves readiness checklist row A1.1-3 in the [evidence plan](../security/soc2-evidence-plan.md#the-uptime-bundle).

## Context

A1.1-3 ("uptime measured against the SLO for a quarter") asks for the outside probe's results and monthly SLO reports. It was the one row of A1.1 with nothing collecting its evidence: the coverage report listed it among the rows no bundle covers. The SLO already defines the measurement: a probe outside the server's host fetches `/status.json` every 30 seconds, a minute is down if both checks in it fail, availability is the share of minutes that aren't down, reports use calendar months in UTC, announced maintenance (up to 4 hours a month) doesn't count, and an incident that spent more than a quarter of the error budget gets a written review. botd can't count its own downtime, so the probe is the measure of record, and its results live in Prometheus (the blackbox exporter `deploy/README.md` sets up, which `SuperBotStatusProbeFailing` alerts on) or a hosted checker, for as long as they keep them. Nobody turned them into a monthly report, and nothing checked that a month had one.

## Decision

### `superbot-evidence uptime`

`superbot-evidence uptime (--prometheus <url> [--query <selector>] | --checks <file>...) [--objective <percent>] [--maintenance <from>/<to>]... [--from <YYYY-MM-DD> --to <YYYY-MM-DD>] [-o <file>]`, with the binary's period rules (last month by default) and private, never-overwritten output. It refuses a period that hasn't ended, and a period with no checks at all (a wrong query, not a month of evidence). It writes a bundle in the change-management bundle's shape, folder `superbot-uptime-<from>_<to>-<UTC time>/`, manifest kind `availability`, with one file, `uptime.json`.

**Where the checks come from.** Either source gives a list of checks: when, whether `/status.json` answered 2xx, and which series (a probe location, or a file) it came from.

- `--prometheus <url>` reads the raw samples of `--query` (default `probe_success{job="superbot-status"}`), a day at a time, as instant queries of a range vector (`<selector>[86460s]` at each day's end). Raw samples carry the probe's own timestamps; a range query would return values Prometheus evaluated on a grid, which repeat a stopped probe's last answer for its 5-minute lookback and so hide a gap. Each request reads a minute more than its day and keeps only the day's samples, so none is lost at a boundary or counted twice, and a day of checks every 30 seconds is 2,880 samples a series, well under Prometheus' limits. So `--query` must be a series selector, parsed before any request (quoted values as PromQL quotes them, so a regex matcher's brackets are allowed). It must return one server's probe: series with more than one `target` (or, failing that, `instance`) label are refused, since combining two servers' checks as if they were locations would let one's answers hide the other's outages; an operator with several servers adds the target to `--query` and makes a bundle each. A token, if Prometheus needs one, comes from `PROMETHEUS_TOKEN`, never the command line, and is refused over plain `http` except to this computer; plain `http` without a token is allowed, since Prometheus often listens only on an internal network. GET only, no redirects followed, server errors retried.
- `--checks <file>...` reads any other probe's export (Uptime Kuma, a hosted checker): one check a line, `<time>,<result>[,<location>]`, the time as RFC 3339 or Unix seconds, the result `1`/`0`, `true`/`false` or `up`/`down`, `#` comments skipped, and a first line of column names (letters only) skipped as a header, so a mistyped first check is refused rather than taken for one; each location a series. A line that isn't a check refuses the file, naming the lines. No token or network.

### What counts

- **A minute is down when it had checks and every one failed**, from any location; up when any check in it succeeded; unmeasured when it had none. This is the SLO's "both checks fail" generalised: one answer means users could reach the service, and a single failed check in a minute with the other missing is still down. Several probe locations aren't voted on: a regional failure that one location still sees through isn't counted, which the ADR accepts because the SLO doesn't promise per-region availability.
- **Availability is the share of minutes that weren't down**, as the SLO says, so unmeasured minutes aren't down. That would let a probe that stopped report 100%, so the manifest maps `uptime.json` to A1.1 and A1.1-3 only while the period's unmeasured minutes fit in the objective's error budget (44.6 minutes in a 31-day month at 99.9%): gaps that could hide the objective being missed make the month a gap in the coverage report rather than evidence. Runs of 5 minutes or more unmeasured are listed either way.
- **Objectives.** Each calendar month and the whole period are judged against `--objective` (default 99.9%, the strictest plan on a shared server, matching the burn-rate rules' target) and against each plan's in `docs/slo.md` (Starter 99.5%, Pro and Max 99.9%, Enterprise 99.95%), with the budget in minutes and the share spent. Whether an objective is met is decided in integers (down × 10,000 ≤ minutes × (10,000 − objective in hundredths of a percent)), so rounding never flips it. A unit test reads the objectives, the maintenance limit, the review rule and the default probe job from `docs/slo.md`, `deploy/README.md` and the alert rules.
- **Outages** are runs of down minutes. One that spent more than a quarter of the 30-day error budget at the objective (10.8 minutes at 99.9%) is marked as needing a written review, which the [incident response plan](../security/policies/incident-response.md#post-incident-review) requires and the register's incidents ([ADR 0223](0223-incidents-in-the-register.md)) check once it is recorded there as an error-budget outage. Matching outages to register incidents automatically is left for later: the register names incidents by id, not by time window.
- **Announced maintenance.** Each `--maintenance <from>/<to>` excuses the minutes that start inside it, up to 4 hours each calendar month; minutes past that count as usual and the month is an exception. The tool can't see that a window was announced 48 hours ahead and outside business hours in the server's region (status incidents of impact `maintenance` don't carry a planned start), so the windows are recorded in the bundle for the operator to match to their status page notes.

**Exceptions** (the first things an auditor samples, counted by the coverage report): months the objective was missed, months half the error budget or more was spent (the error budget policy's review point), outages needing a written review, an outage still going at the period's end, probe gaps, months whose gaps are longer than the error budget, and maintenance past 4 hours.

**What stays out.** The token, the Prometheus address and the probe's target: the query is recorded with only the job and location labels' values (any other matcher's value, such as a target's address, is replaced by `<not recorded>`); each Prometheus series is named by a digest of its labels and shows only its `job` and location labels (`location`, `region`, `probe`, `site`, `zone`, `source`) when their values are plain. A checks file is named by its base name, size and SHA-256. The probe's own export is the underlying evidence and is kept beside the bundle.

### Coverage

The coverage report knows the sixth prefix, kind and format, expects `uptime.json` in every uptime bundle, counts its exceptions, and maps A1.1 and A1.1-3. A store without uptime bundles now reports that kind as missing, so a store complete before isn't complete until they are added; that is the intent, as with drill bundles. The monthly `change-evidence` workflow doesn't make one: it runs on GitHub, which can't reach the operator's Prometheus.

## Alternatives considered

- **botd measuring its own uptime** from its start and stop events: it can't see the proxy, the network or itself hung, and the SLO already makes the outside probe the measure of record.
- **Prometheus range queries** (`query_range` at a 30-second step): simpler parsing, but the 11,000-point limit means many requests, and evaluated values smear a stopped probe's last answer over 5 minutes.
- **Counting unmeasured minutes as down**: stricter than the SLO, and a monitoring outage would read as a service outage. Mapping no controls while the gaps exceed the budget keeps both the SLO's arithmetic and an honest coverage report.
- **A majority vote across probe locations**: closer to some hosted checkers, but the SLO is written for one location and doesn't define a quorum; recording every series lets an auditor see disagreement.
- **Reading maintenance windows from botd's status incidents**: they say when maintenance was posted and resolved, not when it was planned to start and end, so they can't show the 48-hour notice. Left for when scheduled maintenance is added to the status page (ADR 0090's deferred list).

## Tests

- Unit tests in `uptime.rs`: a minute is down only when every check in it failed, from any location, and the period's end belongs to the next; a month with a short and a long outage, its availability, budget, plans, outages needing review, gaps and exceptions, and the review threshold at another objective; maintenance excused up to 4 hours with the rest counted, an outage ongoing at the end, and malformed windows; a month the probe mostly missed maps no controls, a full one maps A1.1-3; months judged on their own; checks files with locations, a header and comments, and each refusal; Prometheus read a day at a time with nothing counted twice, NaN skipped, the target's address never shown, a non-selector refused, a query returning two servers refused, and a target in the query never recorded; regex matchers with brackets accepted, and only a first line of column names taken for a header; selectors, objectives and options, the token never on the command line, and a period that hasn't ended; the objectives match `docs/slo.md`, the default query matches the deploy guide and the alert; names don't collide; the file maps to real controls and the evidence plan's table says so. `prometheus.rs`: a token never over plain `http` off this computer, answers and refusals.
- `server/tests/uptime_evidence.rs`: the real binary against a stand-in Prometheus (the query, the day-by-day times, the bearer token on every request), and against a checks file: the summary, `tar -xf` and `sha256sum -c`, the manifest, the outage needing a review, nothing of the token or the probe's target in the bundle, `coverage` checking the bundle and covering A1.1-3; a period with no checks writes nothing, and nothing is written over a file.
- `coverage.rs` and `evidence_coverage.rs`: the sixth kind is expected and reported missing when absent.

## Consequences

- A1.1-3 stays Partial until a quarter has been measured: the bundle is how it will be.
- Operators run it themselves each month, where Prometheus is reachable; a month not made is a gap in the coverage report.
- The SLO's numbers are now in code as well as in `docs/slo.md`; the unit test keeps them together.

## Deferred

- Matching outages needing review to incidents in the register.
- The rolling 30-day window, which needs the 29 days before the period; calendar months are what reports and credits use.
- Checking maintenance windows against scheduled status page notes, once the status page can schedule them.
