# 0121: Published plans from the tiers file

## Status

Accepted (22 Nov 2026). First slice of published per-user plans in M4, [#42](https://github.com/CG-Labs/superbot/issues/42). Builds on tiers ([ADR 0033](0033-tiers-model-routing.md)), billing v0's limits and Stripe prices ([ADR 0040](0040-billing-v0-tier-limits.md), [ADR 0042](0042-billing-checkout-portal-customers.md), [ADR 0050](0050-billing-period-token-usage.md), [ADR 0082](0082-storage-limits-per-tier.md)), team billing ([ADR 0093](0093-team-billing.md)), no free tier ([ADR 0068](0068-no-free-tier.md)) and the status page ([ADR 0090](0090-status-page-and-uptime-slo.md)), whose style and safety rules it follows.

Numbering: the managed substrate ([PR #183](https://github.com/CG-Labs/superbot/pull/183), [ADR 0120](0120-managed-substrate.md)) is merged, and the public site and docs portal ([PR #182](https://github.com/CG-Labs/superbot/pull/182)) holds 0119, so this is 0121. Renumber it if a collision appears at merge.

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
| `limits` | `maxBots`, `monthlyRuns`, `monthlyTokens`, `dailyRoutineRuns`, `maxStorageMb`; `null` is no limit. `concurrentRuns` only while Bots run on their owners' machines (`MACHINE_ROUTING` on or assigned): the tier's, else `MAX_CONCURRENT_RUNS`, which is what a machine applies. Bots on the server itself share one cap with everyone, which is no plan's limit, so it's left out |
| `machine` | `{cpus, memoryGiB, diskGiB}` for the tier's `machineType` when the provider knows it without a call (Incus plans); otherwise `null` |
| `ownKernel` | `true` only when botd holds every machine the tier's people can get to a kernel of their own (`MACHINE_OWN_KERNEL_TIERS`, [ADR 0120](0120-managed-substrate.md)); see below |
| `features` | the tier's `features`: short lines in the operator's words, such as model access or support |

Plus `enterprise` (`{label, contactUrl}` when `PLANS_CONTACT_URL` is set, else `null`), `contactUrl`, `perPerson: true`, `checkout` and `buyUrl` (the app's Plan screen, when people can buy there), and `signupUrl` (`/get-started`, when sign-ups are on).

### Own kernel only where botd holds to it

ADR 0120 lets an operator promise some tiers their own kernel and makes botd hold to it: it won't start with a provider whose machines share their host's kernel for those tiers, and refuses runs on their machines that aren't its VMs. The page states that promise exactly where it is enforced, so it can't claim more than botd does. A tier's machine tier is found as when its people ask for a machine (ADR 0040): its `machineType`, named by the `MACHINE_TIERS` entry with that plan, else by the tier's own name. `ownKernel` is `true` when `MACHINE_OWN_KERNEL_TIERS` lists that name. A tier with no `machineType` can get any `MACHINE_TIERS` entry, so it is `true` only when every entry is listed (`all`). Without a control plane, or with the setting unset, it is `false` for every tier and the page says nothing about kernels, even on Linode, whose machines are VMs anyway: an unset setting is no promise. The page adds "with its own kernel" to the machine line, or "Own machine with its own kernel" when the size isn't known. It says nothing about the provider or the plan id.

Routing holds a subscriber to the promise of the plan they're on now, not only to their machine's recorded tier: a machine left by a previous provider isn't resized when its owner changes plan (ADR 0085), so its recorded tier can lag behind. When `own_kernel_for` is true for the owner's current tier, runs go only to this server's VMs, and a container from before is refused with "your plan needs a computer with a kernel of its own".

### Prices are the operator's words, not Stripe's

Each tier may list `publishedPrices`: `[{amount, currency, interval}]`, the amount in the currency's smallest unit as Stripe's `unit_amount` counts it, a currency from a fixed list of ISO 4217 codes with their decimal places (`tiers::CURRENCIES`: two-decimal ones such as `gbp`, `eur` and `usd`, Stripe's zero-decimal ones such as `jpy`, and the three-decimal `bhd`, `jod`, `kwd`, `omr`, `tnd`), and `month` or `year`; at most four, one per currency and interval, and never zero (ADR 0068: no free tier). The tiers file is checked at start, as for every other field, and botd refuses to start on a bad one. The fixed list means a typo such as `gpb` is refused rather than published, and every amount is shown at its currency's real scale (`KWD 1.500`, `JPY 3,000`, `£29`).

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

`/pricing` reuses the status page's stylesheet and layout: one card per plan with its prices (or "Contact us"), its limits in plain words ("3 Bots", "300 Bot runs a month", "5 GB of storage", "No monthly token limit"), its machine (and its own kernel, where held to it) and its features, then an Enterprise card, a line that prices are per person and a team pays one seat per member (ADR 0093), and links to the Plan screen, `/get-started`, `/status` and the JSON when each applies.

### The public site

The public site and docs portal ([PR #182](https://github.com/CG-Labs/superbot/pull/182)) is static and built separately. It can link to `/pricing` on the managed server, or fetch `/api/plans` at build time to render the same numbers in its own style, so there is still one source. This change doesn't edit the site.

## Tests

- `tiers::tests`: `publishedPrices` and `features` are read and checked (currency from the list, so a three-letter typo is refused, interval, amount range, no zero, no duplicates, at most four; features' length, count and one line), and appear in a tier's view only when set; a tier is sold with a Stripe or a published price.
- `plans::tests`: `PLANS_PAGE` follows billing under `auto`, and `on` and `off` override it; `PLANS_CONTACT_URL` takes only https and mailto; prices display with symbols, decimals and thousands, zero-decimal currencies as whole units and three-decimal ones at their scale; the snapshot lists only sold tiers with their limits and machine size, `ownKernel` only for tiers held to it, on the page too, runs at once only where Bots run on their own machines, and contains no Stripe price id, model, provider, harness or machine plan id; the page shows prices or "Contact us", escapes the operator's text and has no script; the startup line names listed tiers and warns about unpriced ones.
- `plans_http_tests.rs`, on the real router: both pages 404 when plans were never set up, with `auto` and billing off, and with `off` and billing on, for admins too; published, `/api/plans` answers anyone with the plans, prices, limits and Enterprise entry, the right headers and no secrets; `/pricing` renders the same plans with no script; runs at once appear, with the server's cap as the default, only with Bots routed to machines; a signed-in person's tier view has published prices and no Stripe ids; `ownKernel` follows `MACHINE_OWN_KERNEL_TIERS` through each tier's `machineType`, and a tier with none only under every machine tier.
- `machines::tests`: a tier's machine tier is its `machineType`'s `MACHINE_TIERS` name, else its own; `own_kernel_for` is true for a sized tier whose machine tier is listed, for an unsized one only when all are, and never without a control plane.
- `machines::route::tests`: an owner whose current plan is promised its own kernel is refused on a container whose recorded tier isn't held to it, and still runs on this server's VM.
- `auth_review_http_tests.rs`: both routes are in the public list; every other route still refuses callers without credentials.

## Consequences

- Operators write each price twice, as a Stripe price and as `publishedPrices`, and must keep them equal. The startup warning catches a missing one, not a wrong one.
- Linode machine sizes aren't shown yet: the provider only knows a type's size by asking Linode's API. Operators can describe it in `features` until botd caches Linode types.
- A currency outside the list needs a code change to add, with its decimal places.
- Prices are shown as written, with no tax wording; operators who must show tax-inclusive prices write them that way and can say so in `features`. A page-wide note setting is a follow-up.
- The licensed self-host plan and per-region prices aren't published in this slice; nor are the SLOs per plan ([docs/slo.md](../slo.md)), which could be added from the same file later.
- A legacy tier still listed in `stripePrices` for existing subscribers is published too, as it already is on the Plan screen; hiding a tier from sale is a follow-up for both.
