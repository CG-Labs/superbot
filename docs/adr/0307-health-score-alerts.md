# 0307: Alerts when the customer health score falls

## Status

Accepted (26 Nov 2026). Eighteenth slice of enterprise support playbooks in M5, [#60](https://github.com/CG-Labs/superbot/issues/60), after the TAM cadence across accounts ([ADR 0295](0295-tam-cadence-across-accounts.md)).

Numbering: this number was reserved for this work.

## Context

botd works out the customer health score from its own records (ADR 0144) and records it once a day (ADR 0157). People only see it when they go and look: at the TAM's monthly health check (ADR 0252), in a business review or a handover draft (ADRs 0262, 0278), or when support triages a bundle (ADR 0220). The [TAM programme](../support/tam.md#cadence) asks more: "a TAM who sees a signal at risk calls the customer before the next scheduled check-in". With nothing telling anyone, a signal that goes at risk the day after a health check can sit for a month. The [health score page](../support/health-score.md#history) says a fall of 10 points or more since the last check, or a signal that went at risk, is worth a line in the customer's record. Nothing points either out when it happens.

botd already tells people of other things that go wrong between looks. Backups past their RPO, a machine host down and suspicious sign-ins go to the admins' alert channels (the global email list and webhook of approval notifications, ADR 0061), and `/metrics` with rule files in `deploy/prometheus/` serves operators who alert from Prometheus (ADR 0089). A Provider that runs many customers' servers scrapes them all, so Prometheus is where a whole book of accounts can be watched.

Constraints as before: Rust first, no new dependencies, codes and counts only, and no change to RBAC, the support bundle, vaults, SAML, residency or air-gapped installs, which other M5 tracks are changing.

## Decision

### botd tells its alert channels, once, on the day it shows

When `health_history::record` has recorded today's score, `health_alert::watch` compares the report with the day recorded before it (the newest earlier row, however long ago). Three changes count, each from the playbook:

- **The band fell**: healthy to watch or at risk, or watch to at risk. `unknown` is no band, so a server's first judged day isn't a fall.
- **A signal went at risk**: at risk today and not the day before. This includes a signal that was n/a, since an at-risk signal is the same news whatever it was.
- **The score fell 10 points or more below the last health check's** (the newest `support.health_checked`), today and not the day before. Without a health check there's nothing to measure from, and the first two still apply.

If any holds, botd records `support.health_score_fell` (a system event, target `support`/`health_score`, with both days' dates, scores and bands, whether the band fell, the signals newly at risk and the check's score), and sends one alert through `notify::alert` linking to the console's Support tab. The notice says what fell from what, each signal newly at risk with its summary from the report and its playbook's anchor, and the 10-point line. Summaries are the report's own (counts and reason codes), and the notifier redacts secrets as it does for every alert.

Each change is told once. A signal at risk for a week is told on its first day, and a score that stays 10 below the check is told the day it crosses. The day is recorded once (`INSERT OR IGNORE`, checked first), so a restart doesn't repeat it. Recovery isn't told: the next look shows it, and a notice for each improvement would teach people to ignore them. There's no setting to turn it off: the notices go only where an admin has set the global email list or webhook, as other alerts do, and `HEALTH_SCORE_HISTORY_DAYS=0` (no history) stops them with the comparison.

### `/metrics` and the Prometheus rules

From the newest recorded day, while botd records them: `superbot_health_score` (when the score is known), `superbot_health_score_band{band}` (1 for its band), `superbot_health_signal_at_risk{signal}` and `superbot_health_score_recorded_timestamp_seconds`. These are a database read of one row, never the score worked out again, so a scrape costs nothing and agrees with the history. [`superbot-health-score.rules.yml`](../../deploy/prometheus/superbot-health-score.rules.yml) has four ticket alerts, none paging, since the score changes once a day: the band at risk, a signal at risk (by signal), a fall of 10 points or more below the week's highest score, and no new record for 36 hours. The fall is measured against the week's highest, since Prometheus doesn't know when the TAM last checked. CI runs `promtool` on it, and the alert evidence tool (ADR 0288) lists it with the other shipped rule files.

## Alternatives

- **Only Prometheus rules.** Self-hosted customers who don't run Prometheus would hear nothing, and their admins are the people who can act on a signal at risk. The notifier is already set up on most servers for approvals.
- **Only botd's notices.** A Provider with many customers needs one place across them, and alert routing (by customer, to each TAM) belongs in its Alertmanager, not in each customer's botd.
- **Notify the TAM directly.** botd doesn't know who the TAM is (ADR 0278 names nobody), and a self-hosted customer's server shouldn't send its data to the Provider unasked. The customer's admin can forward the channel; the Provider scrapes `/metrics` where it runs the server.
- **Work the score out again at each scrape.** It reads 30 days of the audit log, and the recorded day is what the history, the health check and the business review read.
- **Count it in `superbot_events_total`.** That list is what an operator alerts on across all of botd and is shared; the gauges carry more (which signal, the score) and need no change to it.
- **Tell each day while something is at risk.** That turns a daily digest into noise. The audit log, the Support tab and the rules (which fire while it lasts) show it's still at risk.

## Tests

`health_alert`'s unit tests: nothing worse is no fall (the same day, a small fall that stays healthy, a signal already at risk, better, from unknown); a band that falls is told with both days; signals newly at risk, from watch or n/a, in the playbook's order with their summaries and playbook links; a fall below the last check told only on the day it crosses (not 9 below, not without a check, from an unknown score, never to unknown); the audit details hold codes, scores and dates only; with no earlier day nothing is told; the metrics show the newest day, nothing before the first. `health_alert_http_tests`: on a real server with an SMTP server, today's live score after a healthy day is audited once with its scores and band, mailed to the alert list with the console's Support link and no one's email, audited as sent, not told again the same day, shown in `/metrics`, and the shipped rules use only metrics botd writes. `superbot-health-score.rules.test.yml`: nothing for a healthy server recorded each day; the band and a signal at risk at once; a 12-point fall on one server and not an 8-point one on another; no record for 36 hours, an hour later. `tests/support_docs.rs`: the health score page documents the audit action, each gauge and the rule file, and the TAM page and the index point at the alerts.
