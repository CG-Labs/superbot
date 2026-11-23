# 0157: Health score history and the console's Support tab

## Status

Accepted (23 Nov 2026). Third slice of enterprise support playbooks in M5, [#60](https://github.com/CG-Labs/superbot/issues/60), after the support bundle ([ADR 0131](0131-support-bundle.md)) and the TAM programme and customer health score ([ADR 0144](0144-tam-programme-and-health-score.md)). Reverses ADR 0144's "no history is stored".

Numbering: this number was reserved for this work.

## Context

ADR 0144 computes the health score on demand and keeps nothing, leaving the trend to each TAM's notes. Two things the roadmap left for #60 follow from that:

- **Score history.** A monthly note gives one point a month, taken on whatever day the check happened. A score that fell to "at risk" for a week mid-month and recovered never shows. The quarterly review's "how did the quarter go" is twelve weeks of the customer's admin's memory. And on a self-hosted server, the TAM sees the score only when the admin runs the command.
- **A console button for the bundle and the score.** Both are `botctl` commands and admin-only API routes. A customer's admin who doesn't use a shell on the server (Docker Compose, a managed host) has to `curl` with a token to send support a bundle.

Constraints are ADR 0144's: nothing personal leaves, explainable, Rust first with no new dependencies, harness agnostic, and botd contacts no one.

## Decision

### One row a day: the score, its band and each signal's status

botd records the 30-day score once a UTC day in a new `health_scores` table: the date, when it was taken, the window, the score (null when there's nothing to judge), the band, and each signal's status (`ok`, `watch`, `risk` or `n/a`) as a small JSON object. Not the counts, summaries or reason codes: those are in the live report and the support bundle, and a status is enough to see which signal moved. A row has nothing personal in it, so erasure ([ADR 0102](0102-erasing-a-users-data.md)) and residency don't touch it.

- **Daily, at the first chance.** An hourly loop (first pass two minutes after start) records today's score if today has none. The first of the day stays; a restart doesn't add a second. A server that's down all day has no row for that day, which is itself worth knowing.
- **The 30-day window, always.** Each day's score is the one a TAM would get from `botctl health-score` that day, so days compare like for like.
- **Kept 400 days by default** (`HEALTH_SCORE_HISTORY_DAYS`, 1 to 3650; 0 records none): a year of reviews plus a quarter to compare with. Older days are deleted on the same pass. A row is about 200 bytes, so a year is under 100 KB.
- **No backfill.** Adoption reads who was active from users' last sign-in and use, which only says "now", so a past day can't be worked out again. History starts with the first day botd runs this version.
- **Not audited.** Recording is botd's own bookkeeping of aggregate counts, like usage; an event a day would only add noise to the log the score reads.

### Reading it

`GET /api/support/health-score/history?days=<n>` (1 to 3650, 90 by default) returns the days in the window, oldest first, whether botd is recording and for how long, and a trend: the newest day against the oldest in the window, with the score's change and the signals that got worse or better. A signal that was n/a on either day is neither, since "nothing to judge" isn't better or worse than a verdict. Like the score, it isn't in the RBAC table, so it's admins only, and it isn't audited.

`botctl health-score history [--days <n>] [json]` prints a line per day (date, score, band, a bar, the signals at risk) and the trend. The support bundle carries the last 90 days as `health-score-history.json`, scrubbed like its other files. Adding a file leaves the other files' shapes alone, so the bundle's `FORMAT` stays 2.

### The console's Support tab

A **Support** tab in the admin console ([ADR 0032](0032-console-admin-only.md)) shows the live score and band, each signal with its weight, status and summary, the history (30, 90 or 365 days, newest first, each with a `<meter>` and the signals at risk and at watch) with its trend, and a **Download support bundle** link to `GET /api/support/bundle`. The link is a plain download with the session cookie, so the bundle is made and audited (`support.bundle_created`) exactly as from `botctl`. No inline styles or scripts: the console's CSP is unchanged.

The Expo client doesn't get the tab. The score is for the customer's admins and the TAM (ADR 0144), and the console is where admin-only server tools live.

## Alternatives

- **Store the full report each day.** Lets a TAM read any past day's counts, but keeps 6 KB a day of reason codes and would make retention and the bundle's scrubbing a question for the table too. Statuses are what the trend needs; the counts are a support bundle away.
- **Work history out on demand from the audit log.** No table, but adoption can't be read back for a past day, and `AUDIT_RETENTION_DAYS` would cap the history at the log's retention.
- **A row per signal.** Easier to query by signal, but six times the rows for no reader that needs it; the JSON object is read whole.
- **Record from the TAM's `botctl health-score` runs.** Gives points only when someone looks, which is the gap this closes.
- **Send the history to the Provider.** New collection from self-hosted servers, against the bundle's rule that the customer chooses what leaves (ADR 0131). The admin sends a bundle or the command's output.
- **A chart library in the console.** The console has no build step and a strict CSP; a `<meter>` per day reads well enough and adds nothing to load.

## Tests

- `health_history.rs`: settings (default 400, 0 off, bounds), a day keeps only the score, band and statuses (no summaries or facts), the trend's change and worse/better signals in the playbook's order with n/a skipped, one row a day with the first kept, pruning past `keep_days` and nothing done when off, and the `days` bounds.
- `health_history_http_tests.rs`: admins only (members, a custom role with every delegable permission, and a Bot get 403; no session 401), bad `days` are 400, an empty history, days outside the window left out, today's row from the live score, the trend against the oldest day, and no email in the table.
- `support_http_tests.rs`: the bundle carries `health-score-history.json`.
- `interface_http_tests.rs`: the console links the Support tab, and its new API call is routed.
- `botctl.rs`: the history's request path and its printout, recording off included.
- `support_docs.rs`: the playbooks' links and `botctl` commands, the new ones included.
