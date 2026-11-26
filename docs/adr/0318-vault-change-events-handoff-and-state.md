# 0318: Vault's change events: an old stream that ends uncertainly, and the stream's state

## Status

Accepted (26 Nov 2026). Part of secrets vault integration in M5, [#55](https://github.com/CG-Labs/superbot/issues/55). Builds on following Vault's change events ([ADR 0306](0306-following-vaults-change-events.md)): it closes a gap a review of that work found in its make-before-break resubscribe, and does the first of the ideas it left for later, "the stream's state in `botctl secrets backend` and `/metrics`".

Numbered 0318 because it is the number reserved for this slice.

## Context

### The handoff

Before the token a subscription was made with is due, botd opens a new subscription, then closes the old stream and reads it to its end (ADR 0306), so no event falls between them. Each stream is read by a task of its own, which handed frames to botd over a channel of 64. While botd opened the new subscription, it took nothing from the old one, so the reader could fill the channel and wait. A review of ADR 0306's change pointed out what follows, and the code confirms it:

- A reader waiting on a full channel doesn't read, so it only meets the old connection's end (a drop, a reset, Vault's close) once botd has taken the frames ahead of it. The check that the old stream had ended before the new one opened looked at a flag the reader sets when it reads the end, so it said no.
- Then `finish()` read the old stream until a close, an error or 2 s, and treated each the same: an error after the queued frames was dropped without a word, and so was a timeout.

Either way, events Vault sent on the old connection before the new subscription opened, and that never arrived, were lost, and nothing read the names again until the cache ran out. Four tests against the stand-in Vault showed it: a connection dropped behind queued events, a close Vault answers by dropping the connection, a close it never answers, and more events waiting than the channel holds. All four missed a change with no event.

### The stream's state

ADR 0306 audits the stream's losses and recoveries (`secret.vault_events`), but an operator can't see at a glance whether botd follows the events now, and Prometheus can't alert on a stream that stays down. `botctl secrets backend` says only that botd is set to follow them.

## Options

For the handoff:

1. **Read everything again after every handoff.** Simple, and always right, but each hourly resubscribe (and each token renewal, more often with short logins) then reads every cached secret, which is what following events is meant to avoid.
2. **A bigger channel.** Moves the threshold; a burst of events during a slow subscription still fills it, and an error after the queue is still dropped.
3. **A reader that never waits, and a clean end defined narrowly.** Chosen. The reader always reads, so it meets the end as it comes; and the old stream counts as ended cleanly only when Vault's close comes after botd's own. Anything else reads everything again.

For the state: the audit log alone (hard to alert on); failing `/healthz` or `botctl secrets backend` when the stream is down (wrong: reads still work, runs carry on, and the cache bounds staleness, ADR 0306); or **counts and a gauge in `botctl secrets backend`, the setup report and `/metrics`, with alert rules** (chosen).

## Decision

### The handoff

- **The reader never waits for botd.** Each stream's reader task hands frames on over an unbounded channel, so it reads the connection as data comes, and sets the stream's `ended` flag when it meets a close, an error or the end, at the time it happens. What it holds is capped: past 16 MiB of frames botd hasn't taken (Vault's events are a few hundred bytes), the reader stops with an error, which counts as an end. Outside a handoff botd takes each frame at once, so the cap only matters while it opens a subscription.
- **A clean end.** `finish()` returns whether the old stream ended cleanly: it hadn't ended before botd sent its own close, the close went out, and a close came back within 2 s. TCP keeps a connection's bytes in order, so Vault's close arriving after botd's means every event Vault sent on it arrived first, and any event after the new subscription opened is on the new stream. Every event still on its way is read and applied either way.
- **Anything else reads everything again.** A stream that ended before botd closed it (Vault closed it, or the connection dropped, perhaps while botd was opening the new one), a close botd couldn't send, an error or the end before Vault's answer, and no answer within 2 s: once the new stream is open, botd reads every cached answer again (`ExternalStore::refresh`), as after a gap, and logs a warning with the reason. The token reasons ADR 0306 already had (a new token, a late renewal, a new subscription that opened after the old token ran out) still read everything again too.
- What stays: a Vault close that crosses botd's close on the wire after the new stream opened can't be told from an answer. Vault would have had to close the old stream on its own between registering the new subscription and receiving botd's close, which is the same moment from Vault's side, and anything it sent before that close still arrives first.

### The stream's state

- **Kept by the stream.** botd counts, since it started: whether a stream is open now, and since when it has been (or not); changes it read again as they were announced, and when the last was; times the stream was lost; reads of everything because events may have been missed (after a loss, an uncertain handoff, or more than 1,024 names waiting); and its own reason for the last loss (`Vault closed the stream`, `Vault stopped answering pings`, ...), never a path, a value or Vault's text. The `Provider` trait gains `watch_status`, None for backends without a stream.
- **`botctl secrets backend` and the setup report.** The setup report's `secretsBackend` (`GET /api/setup`, which `botctl secrets backend` reads) gains `events` (`following`, `forSeconds`, `changes`, `lastChangeSecondsAgo`, `lost`, `catchUps`, `lastLoss`), with ages worked out by botd so they don't depend on the caller's clock; null without a stream. `botctl secrets backend` adds a line, for example `Change events: followed for 2h; 3 read again as they changed, the last 30s ago; lost 1 time, last: Vault closed the stream; every cached secret read again 2 times, as events may have been missed.`, or `not followed for 40s, subscribing again; meanwhile a change reaches botd within the cache time`. A lost stream doesn't make the command fail: it fails when the backend can't be read, as before.
- **`/metrics`.** Only while botd follows a store's change events, labelled with the backend's kind and nothing else: `superbot_secrets_change_events_following` (gauge, 1 or 0), `superbot_secrets_change_events_changes_total`, `superbot_secrets_change_events_lost_total`, `superbot_secrets_change_events_catch_ups_total` (counters) and `superbot_secrets_change_events_last_change_timestamp_seconds` (gauge, once there is a change). The names don't say Vault, so change events from the other backends can use them.
- **Alert rules.** [`deploy/prometheus/superbot-secrets-events.rules.yml`](../../deploy/prometheus/superbot-secrets-events.rules.yml): `SuperBotSecretsChangeEventsDown` when the stream has been down for 10 minutes (botd tries at least once a minute), and `SuperBotSecretsChangeEventsFlapping` when it was lost 6 times or more in an hour for 15 minutes (each loss reads every cached secret again; a proxy closing long-lived connections is the usual cause). Both are tickets: runs carry on, and the cache bounds staleness. Tested with `promtool test rules`, and listed among the rule files the alerts evidence bundle expects (ADR 0288).

## Consequences

- No change unless `VAULT_EVENTS=1` is set.
- A handoff whose old stream ends any way but with Vault's answer reads every cached secret again: at most once per resubscribe, and only when something went wrong or Vault didn't answer the close within 2 s. A clean handoff still reads nothing again.
- Up to 16 MiB more memory per stream in the worst case, only while botd opens a subscription with events piling up.
- Operators see in `botctl secrets backend` and in Prometheus whether botd follows the events, how often it lost them, and how often it read everything again, and can alert on a stream that stays down or keeps dropping.
- Tested against the stand-in Vault in `server/src/secrets/vault/events.rs`, which can now drop a connection at once, drop it instead of answering botd's close, or leave the close unanswered:
  - Each of the four ways above reads everything again, with the new subscription and no later one, and the change with no event lands; the events queued ahead of a drop still count.
  - A clean handoff (each new AppRole login, the old stream closed after the new one opened) reads nothing again.
  - The stream's state end to end: following with no changes at startup, the changes counted as they are read, a loss with its reason and `following` false, then following again with a catch-up counted; none with `VAULT_EVENTS` off.
  - `diagnose` and `render_watch` with a stand-in backend: nothing without a stream, the view's ages, never negative, the metrics with only the backend label, no reasons or values in them, no timestamp before the first change, and every metric the alert rules use is one botd writes. `botctl`'s line for following, lost and catching up, and a lost stream not failing the command.
  - No Vault Enterprise or network, as for ADR 0306.
- Ideas for later, each for an issue of its own: change events from Azure Event Grid, Google Pub/Sub and AWS EventBridge for the other backends (they would report through the same `watch_status` and metrics), and a refresh button in the console.
- Ops guide: [docs/ops/vault.md](../ops/vault.md#following-vaults-change-events).
