# 0331: Every alert links its runbook

## Status

Accepted (26 Nov 2026). Twenty-first slice of enterprise support playbooks in M5, [#60](https://github.com/CG-Labs/superbot/issues/60), after runbooks for the secrets store and the audit trail ([ADR 0322](0322-runbooks-for-the-secrets-store-and-the-audit-trail.md)).

Numbering: this number was reserved for this work.

## Context

SuperBot ships eleven Prometheus rule files with 43 alerts. Since ADR 0322 the audit trail's four linked their runbook section; the other 39 didn't. Some named an ops guide (backups, encryption, the secrets store's change events), some only a setting or a command, and the health score's named its page. Whoever is paged at night got a description and had to guess which of the support folder's dozens of pages to open.

Three areas with alerts had no runbook at all:

- **Host capacity** ([ADR 0106](0106-host-capacity-metrics.md)): ten alerts, two of them pages (machines waiting for room, no open Incus host). Bundle triage counted `machine.placement_failed` with machine failures and pointed at the machine down runbook, which isn't where "no room" is fixed.
- **Encryption at rest** ([ADR 0114](0114-backups-encrypted-by-default.md), [ADR 0116](0116-database-encrypted-at-rest.md)): three alerts, and botd refusing to start for the database key, which is a Severity 1.
- **botd's own errors** ([ADR 0113](0113-service-dashboards-and-error-reporting.md), [ADR 0090](0090-status-page-and-uptime-slo.md)): the error budget burn (a page), one route class's 5xx, panics and error reports. Triage sent a panic to the escalation page.

Suspicious sign-ins ([ADR 0104](0104-suspicious-sign-in-alerts.md)) and the secrets store's change events had runbooks, but no section that named their alerts.

Constraints: no new dependencies, nothing that changes what botd records, sends or exposes, no SLAs or prices, and no edits to the SAML, RBAC, residency or air-gapped code other M5 tracks are changing.

## Decision

### Every alert ends with its runbook section

Each alert's description ends with `See docs/support/<runbook>.md#<section>.`, and that section names the alert in code (`` `SuperBotHostDiskFull` ``), so searching the page for the alert's name lands there too. One link per alert, to the section that says what to do; the section links the setup guide, so descriptions don't carry both. An alert whose fix is per label (the health score's signal) keeps its templated link as well, before the fixed one. The promtool tests' expected annotations change with them.

Repo paths, not URLs: the repo is public and a Provider runs its own fork and docs site, so it can rewrite one prefix. Not a `runbook_url` annotation either: Alertmanager's default templates don't show it, and the description is what every receiver shows.

### Three runbooks in the shape of the others

- [`runbook-capacity.md`](../support/runbook-capacity.md): no room for new machines (every reason placement gives for a host, with its fix), machines on another team's host, a host short of memory, disk or CPU (allocation against `INCUS_CAPACITY` versus what the host uses), and stale readings. Severity 1 for botd's own disk nearly full.
- [`runbook-encryption.md`](../support/runbook-encryption.md): the database plain, a plain copy left, each backup target plain, and botd not starting for the key, which links the database encryption guide's table rather than repeating it. A plain choice made by the customer is recorded, not undone.
- [`runbook-server-errors.md`](../support/runbook-server-errors.md): requests failing (the burn alerts and every route class, with where each usually fails), panics (a task that panics stops quietly), and error reports. botd down stays in [the server itself](../support/runbook-machine-down.md#the-server-itself), which now names `SuperBotDown` and `SuperBotStatusProbeFailing`.

Existing runbooks gain the sections their alerts need: [suspicious sign-ins](../support/runbook-sign-in.md#suspicious-sign-ins) (each pattern, with what to do), [change events lost](../support/runbook-secrets.md#change-events-lost), and lines naming the alerts in the backups, audit trail, harness and health score sections.

### Triage points at them

- `machine.placement_failed` is its own group, `audit.capacity`, pointing at no room for new machines, apart from `audit.machines`.
- `logs.panic` points at the panics section before escalation.

## Alternatives

- **A table of alerts in one page.** It would be one more thing to keep in step, and still a step away from what to do. The test below makes the description the index.
- **New alerts for what has none** (the database's size, the error tracker's drops). Worth doing when an incident asks for it; this slice changes no rule's expression, severity or timing.
- **Generating descriptions from the runbooks.** A build step for YAML that promtool and every Provider read as is; a test is enough.

## Tests

`support_docs`: every alert in every shipped rule file links a `docs/support/` section that exists and names it; every rule file has a test file, and CI checks and tests both; the capacity runbook explains every reason placement gives for a host, the encryption runbook every backup target and the plain copy's name, the errors runbook every route class and the error reports' outcomes, and the sign-in runbook every suspicious pattern; triage, the index and the ADR's links resolve. `support_triage`: placement failures form `audit.capacity` with its section, apart from machine failures, and a panic points at the panics section. promtool: every rule file's tests, with the new descriptions.
