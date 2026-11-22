# 0121: Published plans from the tiers file

## Status

Accepted (22 Nov 2026). First slice of published per-user plans in M4, [#42](https://github.com/CG-Labs/superbot/issues/42). Builds on tiers ([ADR 0033](0033-tiers-model-routing.md)), billing v0's limits and Stripe prices ([ADR 0040](0040-billing-v0-tier-limits.md), [ADR 0042](0042-billing-checkout-portal-customers.md), [ADR 0050](0050-billing-period-token-usage.md), [ADR 0082](0082-storage-limits-per-tier.md)), team billing ([ADR 0093](0093-team-billing.md)), no free tier ([ADR 0068](0068-no-free-tier.md)) and the status page ([ADR 0090](0090-status-page-and-uptime-slo.md)), whose style and safety rules it follows.

Numbering: `main` has up to 0118. Open PRs hold the next two: the public site and docs portal ([PR #182](https://github.com/CG-Labs/superbot/pull/182), 0119 once it moves off `main`'s 0118) and the managed substrate ([PR #183](https://github.com/CG-Labs/superbot/pull/183), 0120), so this is 0121. Renumber it if a collision appears at merge.

## Context

M4's exit criteria include "published plans": buyers must be able to see each managed tier's price and limits, and how to reach sales for Enterprise. Today the plans live in the operator's tiers file: labels, limits botd enforces, and the Stripe price ids that set a user's tier. Signed-in people see their own plan and the ones they can buy on the app's Plan screen; nobody else sees anything.

Copying plans by hand into a marketing page would drift from what botd enforces, so the published plans should come from the same file. Three constraints shape it:

- **No invented prices.** The repository is public and self-hosted; it must not ship or guess real prices. Amounts are the operator's.
- **Self-host stays quiet.** A self-hosted server with billing off has no plans to sell and must publish nothing unless its operator asks.
- **Public means safe.** The page is open to anyone, so it may show only what a buyer may see. ADR 0033 keeps models and routes for admins, and Stripe price ids are configuration, not something to hand out.

## Decision

### Two open pages, from the tiers file

`GET /api/plans` (JSON) and `GET /pricing` (HTML) are served by botd, open to anyone, like `/status`. They are built on each request from the loaded tiers file (in memory, no database or network), so they always say what botd enforces. `/pricing` sits beside `/status` outside sign-in; `/api/plans` is in the API and let through by the auth middleware like `/api/signups/config`, so it keeps the `ALLOWED_HOSTS` check.

A tier is **listed when it is sold**: it has `stripePrices` (as the Plan screen lists it) or `publishedPrices`. The built-in self-host tier and open internal tiers aren't. Each listed tier shows:

| Field | From |
|---|---|
| `name`, `label` | the tier |
| `prices` | `publishedPrices`, each with `amount`, `currency`, `interval` and a `display` string (`£29 / month`) |
| `limits` | `maxBots`, `monthlyRuns`, `monthlyTokens`, `dailyRoutineRuns`, `maxStorageMb`, and `concurrentRuns` (the tier's, else the server's `MAX_CONCURRENT_RUNS`, since that is what applies). `null` is no limit |
| `machine` | `{cpus, memoryGiB, diskGiB}` for the tier's `machineType` when the provider knows it without a call (Incus plans); otherwise `null` |
| `features` | the tier's `features`: short lines in the operator's words, such as model access or support |

Plus `enterprise` (`{label, contactUrl}` when `PLANS_CONTACT_URL` is set, else `null`), `contactUrl`, `perPerson: true`, `checkout` and `buyUrl` (the app's Plan screen, when people can buy there), and `signupUrl` (`/get-started`, when sign-ups are on).

### Prices are the operator's words, not Stripe's

Each tier may list `publishedPrices`: `[{amount, currency, interval}]`, the amount in the currency's smallest unit as Stripe's `unit_amount` counts it, a three-letter ISO 4217 currency, and `month` or `year`; at most four, one per currency and interval, and never zero (ADR 0068: no free tier). The tiers file is checked at start, as for every other field, and botd refuses to start on a bad one.

**Why not read amounts from Stripe.** botd would have to call Stripe for a public, unauthenticated page: an amplifier anyone could hit, a page that breaks when Stripe is slow, and a `STRIPE_SECRET_KEY` dependency for something self-hosters without billing might still want. Caching at startup would still need the key and still drift until a restart. Writing the amount next to the Stripe price id keeps one file as the source and costs the operator one line per price. The deploy guide says to keep them equal, since Stripe charges its own price. Reconciling them (a startup check against Stripe when the key is set) is a follow-up.

A sold tier without `publishedPrices` shows "Contact us", linked to `PLANS_CONTACT_URL` when set; botd's startup log names each one, so an operator sees what the page is missing. No price is ever shipped: `deploy/tiers.example.json` has none.

### Enterprise is a contact link

Enterprise is custom (ADR 0068, the roadmap), so it's not a tier with limits. `PLANS_CONTACT_URL`, an `https://` page or a `mailto:` address of up to 300 characters, adds an Enterprise entry with a "Contact sales" link. Anything else (`http:`, `javascript:`, credentials in the URL) is refused at start, because it goes into a public page's links. Unset: no Enterprise entry.

### Off unless billing is on, or the operator says so

`PLANS_PAGE`:

- `auto` (default): published only while billing is on (`BILLING=on` with a webhook secret). A self-hosted server, or any server in testing mode (where billing is always off), publishes nothing.
- `on`: always, for an operator who wants the page before billing (a test server previewing it, or prices sold another way).
- `off`: never.

While not published, both pages answer 404 with a fixed message naming `PLANS_PAGE`, for everyone, admins included, so the response says nothing about the plans.

### Safe to be public

Neither page shows Stripe price ids, routes, models, providers, endpoint names, machine plan ids (a Linode type names the provider), users, subscriptions or counts. `features` are the only free text and are the operator's own, for the public. Labels and features are escaped. The HTML page has no script and the same restrictive CSP, `nosniff` and `no-referrer` headers as `/status`, with `Cache-Control: public, max-age=60`.

Signed-in people's tier view (`GET /api/me/tier`, the Plan screen's list) now also carries `publishedPrices` and `features` when set: the same public data, so the app can show prices later. Admins' tier view shows them too. Stripe price ids stay admin-only.

### The page

`/pricing` reuses the status page's stylesheet and layout: one card per plan with its prices (or "Contact us"), its limits in plain words ("3 Bots", "300 Bot runs a month", "5 GB of storage", "No monthly token limit"), its machine and its features, then an Enterprise card, a line that prices are per person and a team pays one seat per member (ADR 0093), and links to the Plan screen, `/get-started`, `/status` and the JSON when each applies.

### The public site

The public site and docs portal ([PR #182](https://github.com/CG-Labs/superbot/pull/182)) is static and built separately. It can link to `/pricing` on the managed server, or fetch `/api/plans` at build time to render the same numbers in its own style, so there is still one source. This change doesn't edit the site.

## Tests

- `tiers::tests`: `publishedPrices` and `features` are read and checked (currency, interval, amount range, no zero, no duplicates, at most four; features' length, count and one line), and appear in a tier's view only when set; a tier is sold with a Stripe or a published price.
- `plans::tests`: `PLANS_PAGE` follows billing under `auto`, and `on` and `off` override it; `PLANS_CONTACT_URL` takes only https and mailto; prices display with symbols, decimals and thousands, and zero-decimal currencies as whole units; the snapshot lists only sold tiers with their limits, machine size and the server's run cap, and contains no Stripe price id, model, provider, harness or machine plan id; the page shows prices or "Contact us", escapes the operator's text and has no script; the startup line names listed tiers and warns about unpriced ones.
- `plans_http_tests.rs`, on the real router: both pages 404 when plans were never set up, with `auto` and billing off, and with `off` and billing on, for admins too; published, `/api/plans` answers anyone with the plans, prices, limits and Enterprise entry, the right headers and no secrets; `/pricing` renders the same plans with no script; a signed-in person's tier view has published prices and no Stripe ids.
- `auth_review_http_tests.rs`: both routes are in the public list; every other route still refuses callers without credentials.

## Consequences

- Operators write each price twice, as a Stripe price and as `publishedPrices`, and must keep them equal. The startup warning catches a missing one, not a wrong one.
- Linode machine sizes aren't shown yet: the provider only knows a type's size by asking Linode's API. Operators can describe it in `features` until botd caches Linode types.
- Prices are shown as written, with no tax wording; operators who must show tax-inclusive prices write them that way and can say so in `features`. A page-wide note setting is a follow-up.
- The licensed self-host plan and per-region prices aren't published in this slice; nor are the SLOs per plan ([docs/slo.md](../slo.md)), which could be added from the same file later.
- A legacy tier still listed in `stripePrices` for existing subscribers is published too, as it already is on the Plan screen; hiding a tier from sale is a follow-up for both.
