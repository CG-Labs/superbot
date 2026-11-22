# 0104: Alerts on suspicious sign-in patterns

## Status

Accepted (22 Nov 2026). Part of the SOC 2 readiness checklist of M4, [#50](https://github.com/CG-Labs/superbot/issues/50); closes checklist row CC7.2-1 in the [readiness checklist](../security/soc2-readiness-checklist.md). Builds on the audit log ([ADR 0009](0009-audit-events.md)), users and sessions ([ADR 0012](0012-users-sessions-rbac.md)), the sign-in limiter of the auth review ([ADR 0024](0024-auth-review-hardening.md)), alerts by email and webhook ([ADR 0074](0074-machine-rpo-and-rto.md)), metrics ([ADR 0089](0089-metrics-and-structured-logs.md)), the SLO alert rules ([ADR 0090](0090-status-page-and-uptime-slo.md)) and TOTP ([ADR 0094](0094-totp-second-factor.md)).

0103 is the highest number on `main`. Open PR [#164](https://github.com/CG-Labs/superbot/pull/164) holds 0100, which `main` already uses, so it will likely move to 0102; this ADR takes 0104 to stay clear of it.

## Context

botd already slowed guessing down: ten failed sign-ins per IP in ten minutes, five wrong second factors per account in fifteen, and each failure audited as `auth.login_failed`. Nothing looked at those failures together. An operator learned of a password-guessing run, or of someone with a person's sign-in code hammering their second factor, only by reading the audit log. SOC 2's CC7.2 expects the system to be monitored for anomalies that could be attacks, with alerts someone acts on.

Two things in the code shaped the design:

- `auth.login_failed` is throttled to one event per IP and method per minute, so the log can't be flooded. `superbot_events_total{event="auth.login_failed"}` counts those events, not failures, so it can't measure a burst.
- A wrong sign-in code names no account: codes are random 256-bit secrets looked up by hash. Only the break-glass password (always the owner) and second factors (after a good first factor) say whose account was tried.

## Decision

### What botd detects

botd watches every failed sign-in that guesses a credential (the break-glass password, a sign-in code, a TOTP code, a recovery code) before the audit log's throttle, and every sign-in that works. It reports four patterns:

| Pattern | When | Counted by |
|---|---|---|
| `ip_failures` | `SIGNIN_ALERT_IP_FAILURES` (10) failed guesses from one IP within `SIGNIN_ALERT_WINDOW` (15 minutes) | Source IP |
| `account_failures` | `SIGNIN_ALERT_ACCOUNT_FAILURES` (5) failed guesses at one account within the window, from any IP: break-glass password guesses at the owner, or wrong second factors after a good password or code | User id |
| `success_after_failures` | A sign-in works from an IP, or to an account, that reached its limit within the window | Either |
| `new_ip` | Someone `SIGNIN_ALERT_NEW_IP` covers (admins, the owner included, by default) signs in from a network none of their kept sessions came from: another /24 for IPv4, /64 for IPv6. Not their first sign-in, which has nothing to compare | User id |

Repeated lockouts aren't a pattern of their own: a key that stays over its limit is reported again each window, and an alert rule counts those reports.

The defaults sit at the limiter's own limits, so a burst is reported as the limiter starts refusing it. Expired sessions, Bot and SCIM tokens, and IdP errors aren't guesses and aren't counted; SSO sign-ins rely on the IdP's own protection, as for MFA ([ADR 0094](0094-totp-second-factor.md)), but a sign-in through SSO still counts as a success for the other patterns. Two password failures aren't guesses either: the right password over HTTP Basic, refused because the owner needs a second factor, and any password once break-glass is off, which can't sign in and which browsers resend on every request from before it was turned off.

### What a detection does

1. **An audit event**, `auth.suspicious_sign_in`, by the system actor `signin_watch`, with the source IP and user agent of the request that completed the pattern, the account as its target (for every pattern but `ip_failures`, which isn't about one account), and details: `pattern`, `scope` (`ip` or `account`), `method`, and for failure patterns `failures`, `threshold` and `windowSeconds`; for sign-ins, the new `session` id. Never what was sent. The failure patterns have outcome `failure`, the sign-in ones `success`. At most 60 are written a minute, over all IPs and accounts; the next one written says how many weren't (`unrecordedSinceLast`), as `auth.login_failed` does.
2. **Counters** in the opt-in metrics: `superbot_signin_failures_total{method}`, every failed guess before the audit throttle, and `superbot_signin_suspicious_total{pattern}`, every detection, written or not. Every label value is written from the start, at zero, so `increase()` sees the first one. Labels come from fixed lists: no IP, user id or email.
3. **An email and webhook alert**, through the admins' global channels ([ADR 0074](0074-machine-rpo-and-rto.md)), for `account_failures` and `success_after_failures` only: both point at one person, and the second may mean someone got in. The alert names the account and method and links to the console's audit log; the IP stays there, behind admin access, not in a third party's inbox or Slack. Bursts from one IP are the internet's background noise, and new networks are frequent for people who travel, so those two go to the audit log and metrics but not to email.

### Alert rules

[`deploy/prometheus/superbot-signin.rules.yml`](../../deploy/prometheus/superbot-signin.rules.yml) ships beside the SLO rules, tested with `promtool` in CI (`prometheus-rules`) like them:

| Alert | Fires when | Severity |
|---|---|---|
| `SuperBotSignInAfterFailures` | any `success_after_failures` in 15 minutes | page |
| `SuperBotAccountSignInFailures` | any `account_failures` in 15 minutes | ticket |
| `SuperBotSignInBurstsRepeated` | three or more `ip_failures` in an hour: someone keeps coming back after the limiter's pauses | ticket |
| `SuperBotSignInFailuresHigh` | more than 100 failed guesses in 15 minutes, for 5 minutes: guessing spread across IPs, each under its limit | ticket |
| `SuperBotSignInFromNewNetwork` | any `new_ip` in 15 minutes | ticket |

botd decides what's suspicious, so the thresholds live in `.env` and the rules only turn each kind into an alert. An end-to-end test checks every series the rules use is one the real botd exports.

### Settings

| Setting | Meaning | Default |
|---|---|---|
| `SIGNIN_ALERTS` | `on` or `off` | on |
| `SIGNIN_ALERT_IP_FAILURES` | Failed guesses from one IP, 2 to 1000 | 10 |
| `SIGNIN_ALERT_ACCOUNT_FAILURES` | Failed guesses at one account, 2 to 1000 | 5 |
| `SIGNIN_ALERT_WINDOW` | `5m` to `24h` | `15m` |
| `SIGNIN_ALERT_NEW_IP` | `admins`, `all` or `off` | admins |

Unlike metrics, this is on by default. It's safe: it writes audit events botd already has the data for, counters nobody sees until metrics are on, and emails only where an admin turned on alert channels. A detector that has to be turned on before an attack is no control. A bad value stops botd at start, naming the setting; the startup log says what's on.

### Personal data

Nothing new is stored. The counts are timestamps in memory keyed by IP and user id, at most each limit's worth per key and 10,000 keys per kind, dropped once they fall out of the window and on restart. The new-network check reads the IPs of the user's sessions, which botd already keeps and prunes 30 days after they end; the audit events carry the source IP every audit event already does and go with `AUDIT_RETENTION_DAYS` like the rest. The metrics hold no IP, id or email.

## Rejected

- **Prometheus rules on `auth.login_failed` alone.** The event is throttled, has no account for code guesses, and can't see a success following failures. Detection needs botd's view of each attempt.
- **Geolocation or "impossible travel".** It needs a GeoIP database (a licence and updates) and sends nothing botd can check; a new network is the signal operators can confirm with the person.
- **New-network reports for everyone by default.** Members on phones would bury the admin alerts. `SIGNIN_ALERT_NEW_IP=all` is there for servers that want it.
- **Blocking on detection.** The limiter already refuses bursts; blocking an account on others' guesses locks the person out. Detections inform; disabling a user or ending their sessions stays an admin's call ([ADR 0012](0012-users-sessions-rbac.md)).
- **Persisting counts.** Surviving a restart would mean storing failed attempts per IP and account; an attacker gains nothing from a restart they can't cause, and the audit log keeps every reported pattern.

## Tests

- **Unit tests** (`server/src/signin_watch.rs`): bursts per IP reported once a window and again if they go on; failures wider than the window don't add up; one account counted across IPs; a success after a burst reported once, and not after the window; off reports nothing; tracking and the audit budget stay bounded; networks compared by /24 and /64; settings parsed and refused by name. `server/src/obs/metrics.rs`: labels come only from the fixed lists.
- **HTTP tests** on the real router (`server/src/signin_watch_http_tests.rs`): ten wrong codes from one IP are reported before the limiter's 429, with the IP and no account; wrong TOTP and recovery codes at one account from three IPs are reported with the account, then the account's next sign-in is flagged with its session; break-glass guesses over HTTP Basic and the sign-in page count against the owner, and the owner's next Basic request is flagged; an admin from a new network is reported, the same /24 isn't, a member isn't unless `all`; off reports nothing; expired sessions, bad Bot tokens and a password cached from before break-glass was turned off aren't guesses; nothing sent is ever in an event or metric.
- **End to end** (`server/tests/signin_alerts.rs`): the real `botd` reports a burst and the sign-in after it in the audit log and `/metrics`, exports every series the shipped rules use, says what's on at start, and refuses bad settings by name.
- **Alert rules** (`deploy/prometheus/superbot-signin.rules.test.yml`): each alert fires when it should, with its labels and text, and stops once the window passes; two bursts an hour and a few failures a minute stay quiet.

## Consequences

- Operators with metrics get paged when a sign-in works after a burst, and tickets for attacks on one account, repeated bursts, spread-out guessing and admins on new networks. Without metrics, admins with alert channels get email or a webhook for the two that point at one person, and every detection is in the audit log.
- A sustained burst writes one audit event per IP or account per window, not one per attempt.
- Behind a proxy that isn't on loopback and without `TRUST_FORWARDED_FOR`, every request comes from the proxy's IP, so per-IP counts merge; the deploy guide already says to set it.
- Counts reset on restart, as the limiter's do.
- CC7.2-1 is done for the product. The checklist's process rows (CC7.3-1 triage, CC7.4-1 incident response) say who acts on these alerts and how.
