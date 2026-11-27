# 0350: Published prices checked against Stripe's

## Status

Accepted (27 Nov 2026). Slice 2 of [#42](https://github.com/CG-Labs/superbot/issues/42)'s [finish line](../ROADMAP.md#finish-line), the last engineering slice of published plans. Builds on published plans ([ADR 0121](0121-published-plans.md)), the licensed self-host plan ([ADR 0348](0348-licensed-self-host-plan-on-pricing.md)), billing v0's limits, checkout and team seats ([ADR 0040](0040-billing-v0-tier-limits.md), [ADR 0042](0042-billing-checkout-portal-customers.md), [ADR 0093](0093-team-billing.md)), yearly and team-only checkout prices ([ADR 0346](0346-yearly-and-team-only-prices-at-checkout.md)) and no free tier ([ADR 0068](0068-no-free-tier.md)).

## Context

`/pricing`, `/api/plans` and the app's Plan screen show each tier's `publishedPrices`, which the operator writes in the tiers file next to its `stripePrices` (ADR 0121). Checkout charges the Stripe price. ADR 0121 kept the two apart on purpose: the public page must not call Stripe for every visitor, break when Stripe is slow, or need a key a self-hoster may not have. It left reconciling them as a follow-up, and its only guard was a startup warning for a sold tier with no published price. A wrong one went unnoticed: change a price in Stripe, or mistype an amount in the file, and the page promises one price while checkout charges another.

The constraints are ADR 0121's: no price is shipped or invented, a server with billing off stays quiet and calls nothing, and the public page still never calls Stripe.

## Decision

### One check, run where Stripe's key already is

`server/src/price_check.rs` reads each tier's `stripePrices` with botd's own Stripe client (`GET /v1/prices/{id}?expand[]=currency_options`, all at once, with the client's timeout and one retry) and compares them with the tier's `publishedPrices`. It only reads prices: nothing is created or charged, and a restricted key needs only read access to Prices. It runs:

- **At startup**, in the background, when checkout is on (`BILLING=on`, the webhook secret and `STRIPE_SECRET_KEY`) and a tier lists `stripePrices`. botd logs one line when everything matches, else a warning per finding and one naming the command to re-run. botd starts either way: Stripe being slow or down at boot shouldn't stop a server that otherwise works, and the page's prices are the operator's to fix.
- **On demand** at `GET /api/tiers/stripe-check`, for anyone with `billing.manage` (who can already see price ids in `GET /api/tiers`). It answers 200 with a `status` of `ok`, `drift`, `unchecked` or `off`, so a caller tells drift from a failed request. Ten checks a minute, server-wide, on the checkout limiter, so the route can't be used to flood Stripe.
- **From a shell** with `botctl plans check-stripe [json]`, which reads that route, prints each tier's Stripe prices and findings, and exits 0 when everything matches or billing is off, 1 on drift and 2 when Stripe couldn't be read, so a deploy step or cron job can gate on it.

botctl doesn't call Stripe itself. It is a small HTTP/1.0 client with no TLS stack, and the key stays in botd: the operator needs a `SUPERBOT_TOKEN`, not the Stripe key, in their shell.

### What counts as drift

Checkout sells the prices a tier's `checkoutPrices` names, per buyer (people, teams per seat) and interval (month, year); a tier without it sells its first `stripePrices` entry monthly to both (ADR 0346). The page shows people's prices, or teams' on a team-only tier. The check holds every price checkout sells, and every published price, to Stripe:

- **A published price** must be charged by an active Stripe price of the same tier at the same amount, currency and interval. Interval means a licensed price renewing every month or every year; "every 3 months", metered, one-time and tiered prices never match. A Stripe price's other currencies (`currency_options`) count, since Checkout can charge them.
- **A price checkout sells** must be active (or checkout fails), have a fixed amount, and renew at the interval `checkoutPrices` sells it at (every month or year without `checkoutPrices`). A price sold to the buyer the page shows must charge, in its own currency, exactly what the page shows for that currency and interval; if the page doesn't show its currency and interval at all, that is drift too: the buyer pays something the page never mentioned. Another of its currency options that the page leaves out is a note: only some buyers see it.
- **An interval the page shows** must be one checkout sells that buyer, when the tier has `checkoutPrices`: a yearly price on the page with no `year` entry promises something checkout can't sell.
- **A price Stripe doesn't have** (404) is drift: it is usually a live price id read with a test key, or the other way round, and checkout would fail on it.

What is **not** drift, reported as notes: a separate team price (`teamMonth`, `teamYear`) that charges a different seat price than the page (the page shows people's prices; ADR 0346 lets teams pay differently), a published interval a tier without `checkoutPrices` can't sell yet (checkout sells only its first price), another price in `stripePrices` that is archived or charges a different amount (checkout doesn't sell it; subscribers already on it keep their plan, as ADR 0040 places them by any listed price), a sold tier with no `publishedPrices` (the page says "Contact us"; ADR 0121's startup warning already names it), and a tier with published prices but no `stripePrices`, such as the `self-host` tier a license pays for (ADR 0348): nothing at Stripe to compare.

A price that couldn't be read for another reason (no answer, a bad key, a rate limit) makes the result `unchecked`, not `drift`, and the tier's published prices aren't judged, since the missing price might be the one that matches. Drift found elsewhere still wins.

### Safe to log

Findings name tiers, price ids, amounts in the page's own format (`£29 / month`) and Stripe's error status, type and code (`stripe::Error`'s display). The key is never in a request URL, a log line, a response or botctl's output; it stays in the client's Authorization header, as for every other Stripe call. Nothing new is public: `/pricing` and `/api/plans` are unchanged and still never call Stripe.

### Billing off: nothing happens

Without `STRIPE_SECRET_KEY` (billing off, testing mode, or billing on without checkout) botd has no Stripe client. Startup logs nothing new, and the route and botctl say why there's nothing to check (`status: off`) and succeed.

## Tests

- `price_check::tests`: Stripe price objects are read as checkout charges them (monthly and yearly, other intervals, metered, one-time, tiered, currency options); matching prices pass; a different amount, currency or interval, a published price only an archived price charges, and a sold price checkout can't sell are drift, each said once; with `checkoutPrices`, each price is held to its interval, a page interval checkout doesn't sell is drift, and a separate team price that differs is a note; currency options count where the page shows them; a missing price is drift and an unreadable one leaves the tier unchecked; tiers with no published or no Stripe prices are notes; the report puts drift before unchecked, and its log lines carry only tiers and findings.
- `price_check_http_tests.rs`, on the real router against a fake Stripe on loopback with a placeholder key: matching prices pass and each is read once with the key and `expand[]=currency_options`; a moved and an archived price are drift; a price Stripe doesn't have is drift and an unreachable Stripe is `unchecked`; nothing is called with billing or checkout off; members are refused before Stripe is called, a `billing.manage` delegate gets the same report as an admin, and the eleventh check in a minute is refused; no response contains the key or webhook secret.
- `rbac::tests`: the route needs `billing.manage`. `auth_review_http_tests.rs` finds it in the router and checks it refuses callers without credentials.
- `botctl`: the summary lists prices, drift and notes, and the exit code follows the status.

## Consequences

- An operator learns about drift at startup and whenever they run the check, not the moment Stripe changes. A price edited in Stripe while botd runs is caught by the next check; a scheduled `botctl plans check-stripe` covers that.
- Startup makes a few Stripe reads when checkout is on: one per listed price, in the background.
- The page states one price per person, so a team seat price that differs is only a note. If the page later shows team prices, `price_check::compare` should hold them to it as it does people's.
- Prices on the public site's landing page ([#44](https://github.com/CG-Labs/superbot/issues/44)) are a separate copy; if it reads `/api/plans` at build time, this check covers it too.
- Real prices remain the owner's decision; this only makes sure that once written, the page and checkout agree.
