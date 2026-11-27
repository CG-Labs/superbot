# 0346: Yearly and team-only prices at checkout

## Status

Accepted (27 Nov 2026). Slice 1 of the [Finish line](../ROADMAP.md#finish-line) for [#31](https://github.com/CG-Labs/superbot/issues/31) (billing v0). It does two items left open by earlier billing ADRs: "more than one price per tier at checkout (yearly and monthly)" from [ADR 0042](0042-billing-checkout-portal-customers.md), and "team-only prices" and "yearly prices at checkout" from [ADR 0093](0093-team-billing.md). Like all billing, it is off unless Stripe is set up, and never on in testing mode ([ADR 0068](0068-no-free-tier.md)).

## Context

Each tier lists the Stripe prices that pay for it in `stripePrices` ([ADR 0040](0040-billing-v0-tier-limits.md)). Checkout, for a person or for a team, sold only the first one. So:

- A tier could have a yearly price, and the webhook would place its subscriptions, but nobody could buy it in the app.
- A team paid the same per-seat price as a person, and every tier was on sale to people, so a plan meant only for companies could be bought by anyone.

Operators set prices in the tiers file today, so the new ones belong there too, with no new environment variable and no Stripe call at startup.

## Decision

### `checkoutPrices` in the tiers file

A tier may add `checkoutPrices`, which says which of its `stripePrices` each checkout sells:

```json
{ "name": "pro", "label": "Pro",
  "stripePrices": ["price_pro_monthly", "price_pro_yearly", "price_pro_team_monthly"],
  "checkoutPrices": { "month": "price_pro_monthly", "year": "price_pro_yearly", "teamMonth": "price_pro_team_monthly" } }
```

- **People** buy `month` or `year`.
- **Teams** buy `teamMonth` or `teamYear` when either is set. Otherwise they buy what people buy, as before.
- **Team-only.** A tier with only team prices is sold only to teams. The Plan screen doesn't list it. A personal checkout for it is a 400: "The Business plan is for teams only…". A team that pays for it gives every member its plan, as in ADR 0093.
- **Without `checkoutPrices` nothing changes.** People and teams buy the first `stripePrices` entry, and the apps show one button as before.

Startup checks, each of which stops botd with the tier named: every price named must be one of the tier's own `stripePrices`, so the webhook always places what checkout sells, and a price still belongs to one tier only. At least one key is set. No price is used as both a monthly and a yearly one, for any buyer. Unknown keys are refused. A team may buy the same price as people at the same interval. Every `stripePrices` entry still sets the tier from the webhook, sold or not, so old prices keep working for subscribers who already have them.

botd doesn't ask Stripe what interval a price bills at, since that would mean a Stripe call at startup, and ADR 0068 allows none while billing is off. Stripe's price decides what is charged and how often. The operator names each price for its real interval, as with `publishedPrices` ([ADR 0121](0121-published-plans.md)). Checking prices against Stripe's is #42's second slice.

### Checkout

- `POST /api/billing/checkout` and `POST /api/team/billing/checkout` take `{tier, interval?}`, with `interval` `month` or `year`.
- Leaving `interval` out (or sending null) buys the tier's first interval for that buyer, monthly before yearly, so older apps that send only `{tier}` buy what they did.
- An interval the tier isn't sold at ("The Starter plan isn't sold yearly here."), or anything other than `month` or `year`, is a 400, refused before Stripe is asked or a checkout page is closed.
- Everything else is as in ADR 0042 and 0093: one open page per payer, nobody pays twice, a seat per member for teams, the same metadata, so the webhook places yearly and team subscriptions exactly as it does monthly ones.
- `billing.checkout_created` records the `interval` beside the price.

### What people see

- Plans in `GET /api/billing` and in the team's `billing.plans` carry `intervals` (`["month", "year"]`) when the tier has `checkoutPrices`, for that buyer. They never show price ids. The pricing page's view (`/api/plans`) is unchanged.
- The Plan and Team screens show a button for each interval ("Upgrade to Pro, paid monthly", "Upgrade to Pro, paid yearly"; "Buy Business for the team, paid yearly"). A plan without `intervals` keeps its single button, which sends no interval.
- `GET /api/tiers` (admins) shows `checkoutPrices`. The startup line says how each tier with them is sold, e.g. `pro (3; people monthly and yearly, teams monthly)`.

### Off by default

Nothing here runs without `BILLING=on`, the webhook secret and `STRIPE_SECRET_KEY`. Both checkout routes still answer 404 while billing is off, whatever the tiers file says. The tests run against the fake Stripe on loopback with made-up keys and price ids.

## Consequences

- Operators can sell yearly plans, price seats for teams differently from people, and keep company plans off people's Plan screens, without new settings or code.
- A tiers file without `checkoutPrices` behaves exactly as before, and so do apps that never send an interval.
- Team-only is enforced at checkout. A subscription made by hand in Stripe's dashboard, or a plan switch in Stripe's customer portal, still sets the tier its price pays for, as ADR 0040 says. Operators who sell team-only plans should leave their prices out of the personal portal's plan switching, which is set up in the Stripe dashboard.
- A price named for the wrong interval bills as Stripe says while the app shows the interval it was named for. Startup can't catch that until prices are checked against Stripe.
