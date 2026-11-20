# 0040: Billing v0, per-user tier limits and a Stripe seam

## Status

Accepted (20 Nov 2026). First slice of [#31](https://github.com/CG-Labs/superbot/issues/31) (M3, billing v0). Builds on tiers ([ADR 0033](0033-tiers-model-routing.md)), the control plane ([ADR 0025](0025-control-plane-linode.md), [ADR 0035](0035-machine-firewall-auto-enroll.md)), the audit log ([ADR 0009](0009-audit-events.md)), and the self-host license ([ADR 0038](0038-self-host-license-key.md)).

0039 is machine harnesses and agent upgrades ([PR #97](https://github.com/CG-Labs/superbot/pull/97)), so this is 0040.

## Context

Tiers ([ADR 0033](0033-tiers-model-routing.md)) pick each Bot's model and cap Bots and runs a month, but a plan also has to bound the two other things that cost money: routines, which run with nobody watching, and the size of the user's machine. And nothing yet moved a user between tiers except an admin. Billing v0 needs both, without breaking self-hosted servers and without botd ever spending money on its own.

## Decision

### Limits

A tier's `limits` in `TIERS_FILE` now has four enforced limits. Each is optional; left out means unlimited.

| Limit | Counted | Enforced at |
|-------|---------|-------------|
| `maxBots` | Bots the user owns | Creating a Bot, and transferring one to them |
| `monthlyRuns` | Runs per calendar month, UTC (`usage_monthly`) | Each run ([ADR 0033](0033-tiers-model-routing.md)) |
| `dailyRoutineRuns` | Routine firings per UTC day (`usage_daily`) | The cron loop, before a routine's message is queued |
| `machineType` | The provider plan (Linode type) of the user's machine | Requesting and resizing a machine |

Without `TIERS_FILE` every user is on the built-in `self-host` tier, which has no limits, so existing installs behave exactly as before. The license ([ADR 0038](0038-self-host-license-key.md)) limits seats, not usage, and doesn't interact with these.

**Why a day for routines.** Routines are where cost runs away unattended: a `*/5` schedule is 288 runs a day. A monthly routine cap would let one bad schedule spend the month in days and then silence every routine the user has for weeks. A daily cap stops a runaway within hours and recovers by itself at midnight, and `monthlyRuns` still caps the total. UTC, so the boundary is the same for every user and every server, and it is the same clock as the monthly period.

Counting is one SQL statement (insert or increment while under the cap), so concurrent firings can't overshoot. A firing takes a routine run before its message is queued; if the run is later refused (the tier's route, placement or isolation), the routine run and the monthly run are both given back, and a routine message dropped by Stop gives its routine run back, so refusals the user didn't cause don't use up their quota. A refused firing queues nothing. Every refusal is audited (`routine.run_refused`, outcome `denied`, with the tier, limit and day); the Bot says why in its chat on the first refusal of a day only, so a busy schedule doesn't flood it.

**Machine size.** `machineType` is a plan name, not a `MACHINE_TIERS` key, so a tier can name any Linode type. A machine request without a tier gets the owner's plan size; a request or resize to anything else is refused with 403 and a `machine.refused` event naming the asked and allowed sizes. The machine's stored tier name is the `MACHINE_TIERS` entry with that plan, or the user's tier name if none has it. Without `machineType`, `MACHINE_TIERS` decides as before. Machines are not resized when a user's tier changes: resizing reboots the user's computer, so an admin does it. The usage view flags machines that no longer fit.

**Bots.** Creating a Bot over `maxBots`, or transferring one to a user at their limit, is refused (as in ADR 0033) and is now audited (`bot.create_refused`, `bot.transfer_refused`). Users already over a limit after moving to a smaller plan keep what they have; only new Bots and runs are refused.

### Seeing usage

`GET /api/usage` (admins) lists every user with their tier, their use against each limit this month and today, their machine and whether it fits, their subscription, and which limits they're over. `botctl usage` prints it, one line per user (`botctl usage json` for the raw view). The client's admin area shows the same on each user. Users see their own through `/api/me/tier`, which now includes routine runs today.

### Stripe seam

Disabled unless `STRIPE_WEBHOOK_SECRET` (or `_FILE`) is set; until then `/billing/stripe/webhook` answers 404 and no billing code runs. botd never calls Stripe, holds no API key, and creates no products or prices: it only receives signed events.

- **Mapping.** Each tier lists its Stripe price ids in `stripePrices`. A price belongs to one tier; the file is refused at startup otherwise. Only admins see the price ids.
- **Signature.** The `Stripe-Signature` header is checked as Stripe documents: HMAC-SHA256 of `{t}.{body}` with the endpoint secret, compared in constant time, any `v1` may match, and `t` within 5 minutes of now. Bodies are capped at 512 KiB. Bad requests get 400 and a `billing.webhook_refused` event (rate-limited, so a flood doesn't fill the log). The secret must look like `whsec_…`, is redacted from logs, and is a reserved name: it is never saved as a secret and never reaches a Bot's environment, from the environment or a `_FILE`.
- **Events.** Only `customer.subscription.*`; anything else is acknowledged and ignored. The user is `metadata.superbot_user_id` on the subscription, or the user a known subscription id already belongs to. Paying statuses (`active`, `trialing`, `past_due`) set the tier of the subscription's price; ending ones (`canceled`, `unpaid`, `incomplete_expired`, `paused`, and `deleted` events) move the user back to the default tier; `incomplete` records the subscription and leaves the tier alone. `past_due` keeps the plan because Stripe is still retrying the payment; when it gives up it sends one of the ending statuses.
- **Safety.** Each event applies once (`billing_events` holds the ids), in order (an event older than the last one applied for that subscription is ignored), and only to its own user (a subscription id that belongs to someone else is ignored). botd keeps every subscription a user has had, ended ones too, each at its latest event. The user's tier is that of their paying subscription that Stripe created last, or the default tier when none pays; an event for any other subscription is recorded but changes no tier (`superseded`). So the tier doesn't depend on the order Stripe delivers events in: a late event for a replaced plan can't bring it back, even after the new plan ends, and a new plan applies whether or not the old one's cancellation arrived first. One transaction does all of this and the tier change. Events botd can't place (unknown user, unmapped price) are audited as `billing.event_ignored`; every change is audited as `user.tier_changed` (actor `system:billing`, on behalf of the user, `source: stripe`) and `billing.subscription_synced`.
- **Tests** use fixture payloads (`server/tests/fixtures/stripe/`) with made-up ids, signed in the test with a test secret.

## Deliberately out of scope (later #31 slices)

- Checkout, the customer portal, and any Stripe API call (creating customers or subscriptions, putting `superbot_user_id` in their metadata).
- An upgrade screen in the client for users.
- Usage periods aligned with each subscription's billing period instead of calendar months and UTC days.
- Token metering and enforcing `monthlyTokens`; storage limits.
- Resizing machines automatically when a user's tier changes.
- Billing emails (receipts, failed payments, limit warnings).

## Consequences

- Self-hosted servers without a tiers file are unchanged, and servers with one only gain limits they add.
- A Stripe event replaces a tier an admin set by hand; admins who comp a plan shouldn't also give that user a subscription.
- Around midnight UTC a given-back routine run may be credited to the day its message was queued rather than the day it fired. The difference is at most one run.
- Losing the webhook secret only stops tier sync: users keep their tier, and admins can still set it with `botctl user tier`.
