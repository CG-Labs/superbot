# 0048: Billing-period usage and token metering

## Status

Accepted (20 Nov 2026). Third slice of billing v0 ([#31](https://github.com/CG-Labs/superbot/issues/31)), after [ADR 0040](0040-billing-v0-tier-limits.md) (tier limits, the Stripe webhook) and [ADR 0042](0042-billing-checkout-portal-customers.md) (checkout, the portal, customers). Builds on [ADR 0033](0033-tiers-model-routing.md) (tiers, `monthlyTokens`).

## Context

Tiers had a `monthlyTokens` limit, but nothing enforced it: botd didn't know how many tokens a run used. Runs counted per UTC calendar month, while a paying user's Stripe subscription renews on its own day. What the harnesses say about tokens:

- **Hermes Agent**: its `result` line has `tokens: {input, output, total, cache_read, cache_write}`, with input apart from the cache. It writes 0 for counts the provider didn't give. The model is in its `system/init` line.
- **Claude Code**: its `result` event has `usage` (Anthropic's counts: input apart from the cache) and `modelUsage`, one entry per model the run used. It reports them on failed runs too.
- **Codex**: `turn.completed` has `usage` with OpenAI's counts, where `input_tokens` includes cached tokens. It doesn't name the model.
- **Pi**: each assistant `message_end` has `usage: {input, output, cacheRead, cacheWrite}` and the model.

## Decision

### Record every run's tokens, or that they're unknown

Each adapter turns its harness's counts into one shape, `Usage {model, input, output, cache_read, cache_write}`, where `input` excludes the cache, so the four add up to the total. Codex's input is reduced by its cached tokens. Harness-specific parsing stays in each adapter.

The runner gives each run an id (`runId`, also on `harness.invoked` and `bot.run_finished`), adds up what every attempt reported, and writes one `token_usage` row per model. The model falls back to the route's model when the harness doesn't name it. A run that reported nothing gets one row with `reported = 0` and zero counts. It counts as a run "without token reports", never as a free run. Hermes's all-zero counts mean unknown too.

Rows are charged to the **Bot's owner**, the same person the run counts for (ADR 0033, 0040), and keep the Bot's id. Neither column has a foreign key, so a deleted Bot's tokens stay billed.

### The billing period

A user's period is:

1. their paid subscription's own period (Stripe's `current_period_start` and `current_period_end`, now kept), while now is in it and it's a month or shorter;
2. otherwise months counted from that period's end once now is past it (the days before Stripe's late renewal event arrives; Stripe starts the next period at that end, so the key doesn't change when it does), else from its start (a yearly plan's months, or from its end for rows from before starts were kept);
3. with no paid subscription, the calendar month, UTC.

Runs (`monthlyRuns`) and tokens (`monthlyTokens`) both count in it. A subscription period's key is its start, like `2026-11-14T08:00:00Z`, and a calendar month keeps `YYYY-MM`, so runs counted before this change stay counted. Someone who subscribes starts a fresh period, which is what they paid for. Routine runs stay per UTC day.

### The token limit

Before a run starts, it's refused if the owner's tokens in the period have reached their tier's `monthlyTokens`. The refusal is audited as `bot.run_refused` (reason `tier_token_limit`, with `used`, `limit`, `period`, `periodEnd`) and explained in chat: "The Pro plan allows 5,000,000 model tokens a month, and this month's are used up. More start on the 1st (UTC)." For a subscription period, the message names the period's end date. A routine that keeps firing doesn't repeat the bubble. A refused run takes no run from `monthlyRuns`. The run that crosses the limit is audited as `usage.token_limit_reached`, by `billing` on behalf of the owner, judged in the period the run ends in, where its tokens count.

Tokens are known only when a run ends, so runs already going when the limit is reached finish. Use can therefore pass the limit by what those runs used. Stopping a run midway would lose work the user is paying for. Admins see users past the limit in `GET /api/usage` (`over` includes `monthlyTokens`).

### Who sees what

- `GET /api/me/usage`: the caller's own period, tokens (in all, by Bot, and by model), and runs. People only, never Bots. There's no parameter naming a user, so nobody can ask for someone else's. On a managed tier, the per-model breakdown is left out for non-admins, as model names are (ADR 0033). A Bot the caller no longer owns (given to someone else, or deleted) keeps its usage but shows no name, so its new owner's name for it stays private.
- `GET /api/users/{key}/usage`: anyone's, admins only (every `users/...` route is Admin in RBAC).
- `GET /api/usage` (admins) and `GET /api/me/tier` add the period and its tokens.
- `botctl usage me`, `botctl usage user <user>`, and the client's Plan screen ("Usage this period") read these.

Audit details don't use "token" in key names: the audit log redacts any key containing it, so the run's total is `usage`.

### Reporting to Stripe: optional, off by default

With `STRIPE_METER_EVENT` set to a Stripe meter's event name (it needs `STRIPE_SECRET_KEY`), a run's rows with tokens are queued for Stripe, for owners with a linked customer. Every minute botd sends up to 100 as meter events (`POST /v1/billing/meter_events`: `event_name`, `payload[stripe_customer_id]`, `payload[value]`, the row's own `identifier`, and its `timestamp`). The identifier and idempotency key are the row's, so Stripe counts a resent row once.

A row Stripe refuses (a 4xx other than 429) is marked failed and audited as `billing.meter_failed`. So is one with no customer, or one that couldn't reach Stripe in five passes. When Stripe is down, the pass stops and tries again next minute. Without the variable, botd queues nothing and never calls the meter API. Tests use a fake Stripe on loopback.

Stripe's meters carry one number per event, so botd sends the total tokens. Prices per input or output token would need a meter each; that's later, if a plan needs it.

## Consequences

- `monthlyTokens` is a real limit. A harness that reports nothing (or a provider that doesn't give Hermes counts) isn't limited by it. Those runs are shown as unknown, and `monthlyRuns` still applies.
- Migration 20 adds `token_usage` and `subscriptions.period_start`. Existing subscriptions get their start from their next Stripe event; until then, months count back from their end.
- Usage is per owner, as runs are. Someone using a teammate's shared Bot spends the teammate's tokens. Under `SHARED_BOTS=isolated`, it's still the owner's plan that applies (ADR 0046).
- Not built: storage limits, resizing machines on a tier change, billing emails, and per-token-type Stripe prices.
