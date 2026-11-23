# 0201: Incident commands and review drafts from botd's records

## Status

Accepted (23 Nov 2026). Sixth slice of enterprise support playbooks in M5, [#60](https://github.com/CG-Labs/superbot/issues/60), after the support bundle ([ADR 0131](0131-support-bundle.md)), the TAM programme and health score ([ADR 0144](0144-tam-programme-and-health-score.md)), the score's history ([ADR 0157](0157-health-score-history-and-console.md)), the support report ([ADR 0167](0167-support-report-from-ticket-exports.md)) and the offline support check ([ADR 0187](0187-offline-support-check-and-bundle.md)).

Numbering: this number was reserved for this work.

## Context

The playbooks promise a lot around a Severity 1 and gave the incident commander little to keep it with. The [SLO](../slo.md#status-page-and-incidents) says an incident is posted within 15 minutes of confirming it and updated at least hourly; [escalation](../support/escalation.md#after-a-severity-1) says every Severity 1 gets a written review within 5 business days, with a UTC timeline, impact, cause, lessons and actions, shared with Enterprise customers. The status page's incidents ([ADR 0090](0090-status-page-and-uptime-slo.md)) could be posted only from the console or by hand-written API calls, which is awkward from a shell on the server during an outage, and the console may be what's broken. And every review started from a blank page: the commander rebuilt the timeline from the status page, read the audit log for restarts and configuration changes around the start, and judged the update targets by eye. The support report ([ADR 0167](0167-support-report-from-ticket-exports.md)) checks tickets' first responses but said update targets had to be checked by hand, since a ticket export has only the first answer.

botd already has every fact a review starts from: each status page post with its time and state, and the audit log with botd's starts (and versions), every configuration change, every run and sign-in. Nobody had joined them.

Constraints: Rust first, no new dependencies; nothing personal in something meant to be shared with customers; and no change to RBAC, SAML, the audit log and its exports, or air-gapped installs, which other M5 tracks are changing at the same time.

## Decision

### `botctl incident` for the status page

`botctl incidents`, and `botctl incident open | update | resolve | edit | delete`, are thin wrappers over the existing `/api/status/incidents` routes, with the same validation, audit events and admin-only access. `open` takes the title and text, `--impact`, a repeated `--component` and `--state`; `update` a state and text; `resolve` is an update to `resolved`; `delete` needs `--yes` and says to resolve real incidents instead. Each prints what comes next: open says to update hourly, resolve prints the review command.

### A review draft, made by botd

`GET /api/status/incidents/{id}/review` (and `botctl incident review <id>`) builds the draft from the incident and the audit log. It's under `/api/status`, so it takes that prefix's default in `rbac::classify`: admins only, with no RBAC change. Each draft is audited as `status.incident_reviewed` (format, lead-in, whether a detection time was given). It answers JSON, or Markdown with `?format=markdown` as a download (`incident-review-<id>.md`, `no-store`), which the console's Status tab links as **Draft review**, a plain download with the session cookie, like the support bundle's link.

The draft has the review's sections in [escalation](../support/escalation.md#after-a-severity-1)'s order. What records can say is filled in; impact, cause, what went well and actions are left marked "To fill in", since they're judgements:

- **Summary**: the incident's impact, components, posted, identified and resolved times and duration. Severity is left to fill in: the status page's impact describes the public page, not the ticket.
- **Timeline (UTC)**: every status page post, botd's `server.started` events with the version, and successful configuration changes (a fixed list of actions: policy and rules, roles, SSO and MFA, license, notifications, egress, setup, tiers, users' roles and tiers, SCIM and service tokens, secrets set or deleted, billing mail settings, Bots' settings; the policy and SSO families by exact name, since `policy.allowed` is every auto-approved tool call and `sso.saml_role_skipped` a sign-in) from a lead-in (24 hours by default, 1 to 168) before the start to its end. Over 50 changes, those nearest the start are kept and the rest counted.
- **Status page targets**: the first post against `--detected` (15 minutes), and every stretch between posts over an hour while the incident was open, including from the last post to now while it's still open. Time spent resolved before a reopening isn't a late update. Maintenance has no update target.
- **What botd saw**: runs finished and failed, sign-in failures (with throttled ones' `unloggedSinceLast`), denials, all failures and audit events while it lasted, beside the same length of time just before (capped at the lead-in), and the most frequent failing actions, each throttled failure counted for the ones it stands for.
- **What went badly** starts with the targets it missed.

The incident starts at its detection time when one is given and is earlier than the first post, else at the first post, and ends at its resolution or now. A detection time after the first post is refused: it would hide a late post.

### It names nobody

The draft is meant to be shared with customers, so it follows the support bundle's rules. Actors are kinds (user, bot, system); targets are types; no ids, names, emails, IP addresses, sign-in subjects or free-text details are read into it. The only free text is the status page's, which admins wrote for the public (and botd redacted on the way in). Update authors aren't shown.

### Two pages on top

[Incidents and their reviews](../support/incident-review.md) documents the commands, every option, what the draft holds and never holds, and how to finish and share a review. [Running a Severity 1](../support/runbook-major-incident.md) is the commander's runbook: write down detection, post within 15 minutes, update hourly, resolve, draft the review. Escalation, the TAM cadence, the health check, the quarterly review, the SLO and the playbooks' index point at them.

## Alternatives

- **Render the Markdown in `botctl`.** `botctl` includes `support_report.rs` because that report needs no botd; this draft needs botd's database, and the console needs the same Markdown, so botd renders it once.
- **Detection from botd's own signals** (the first failed run, the first 5xx). Guessing would be wrong whenever the cause was outside botd (the network, an IdP) or failures were normal noise; the commander knows when the alert fired or the ticket came in, and the draft says when it wasn't given.
- **Count with SQL (`audit_counts`).** It has no end time and counts by code, not by action; reading the events (at most 20,000 for each part, the support bundle's limit) lets one pass build the timeline, the counts and the failures, and the draft says when it hit the limit.
- **Store reviews in botd.** Reviews are written and shared in the Provider's own documents and ticket system; a stored, edited copy would be one more place for personal data. The draft is made on request and not kept.
- **Severity on incidents.** A status page incident isn't a ticket, and several tickets can share one; adding severity would change the status page's API, which the console and other tools use. The draft leaves it to fill in.

## Tests

`incident_review`'s unit tests: hourly gaps between posts, to now while open, and not while resolved before a reopening; first-post timing only with a detection time, 15 minutes being on time, durations from detection, and no update target for maintenance; the merged timeline in order with botd's start and its version, failed changes and those before the lead-in left out, the counts while it lasted and for the same time before (throttled failures included), and no id, name, email, address, subject or user agent in the JSON or the Markdown; the 50 changes nearest the start kept; the Markdown's sections, flagged misses, one table cell per post whatever its text, and an open incident's warning; the query's options; and which actions are changes. `incident_review_http_tests`: admins only (members, read-only users and Bots get 403, nobody 401, an unknown incident 404); a backdated incident with audit events around it gives the right durations, targets, timeline and counts, the Markdown download's headers, and two `status.incident_reviewed` events; and bad options and a detection after the first post get 400. `botctl`'s tests: each incident command's request, the review's query and file, and the list and messages. `tests/support_docs.rs` checks the incidents page explains every option of both commands and every section of the draft, and that the Severity 1 runbook and escalation use them.
