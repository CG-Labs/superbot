# 0348: The licensed self-host plan on /pricing, linked from the public site

## Status

Accepted (27 Nov 2026). Slice 1 of [#42](https://github.com/CG-Labs/superbot/issues/42)'s [finish line](../ROADMAP.md#finish-line). Builds on published plans ([ADR 0121](0121-published-plans.md)), the self-host license ([ADR 0038](0038-self-host-license-key.md)), no free tier ([ADR 0068](0068-no-free-tier.md)), the public site ([ADR 0119](0119-public-site-and-docs-portal.md)) and the landing page on the design tokens ([ADR 0338](0338-landing-page-on-the-design-tokens.md)).

## Context

SuperBot sells two things: managed plans per person, and a license for self-hosted servers. ADR 0121 published the managed plans at `/pricing` and `/api/plans` and left out the licensed self-host plan, so a buyer reading the page learns nothing about running SuperBot themselves. The public site's landing page names a Self-host plan, but in its own words, and nothing on the public site links to `/pricing`.

`/pricing` also still used the status page's stylesheet, with its own greys and blues, after every other surface moved onto the design tokens (ADR 0338).

The same rules hold: no invented prices, logos, quotes or metrics; a self-hosted server with billing off publishes nothing unless its operator asks; and the public page shows only what a buyer may see.

## Decision

### The plan, said once

`server/src/license/offer.rs` holds what the licensed plan is, in buyers' words, and nothing that needs a dependency, so botd, `superbot-site` and `superbot-license` all include it:

- **Edition:** `business`, the edition `superbot-license sign` writes when none is given (it now reads the constant).
- **Seats:** "Per seat: one for each active person, none for the owner account", as ADR 0038 counts them.
- **Includes:** your servers and your data, even air-gapped; every feature in the open source code (ADR 0038 gates nothing); single sign-on, SCIM, approvals and audit; a license key checked offline.

Every line is something a license gives today.

### On /pricing and /api/plans

`/api/plans` gains `selfHost`, `null` when not listed:

| Field | From |
|---|---|
| `label`, `edition`, `perSeat`, `seats`, `includes` | `offer.rs` |
| `prices` | the `self-host` tier's `publishedPrices`, each with `display` per seat (`£40 per seat / year`) |
| `features` | the `self-host` tier's `features`, in the operator's words |
| `licenseUrl` | where to ask for a license |

**Listed when there's somewhere to ask.** `PLANS_LICENSE_URL` (an `https://` page or `mailto:` address, checked like `PLANS_CONTACT_URL`) says where; unset, `PLANS_CONTACT_URL` does. With neither, the plan isn't listed, as Enterprise isn't without a contact. botd's startup line says which, and whether the plan has prices.

**Prices only from configuration.** They come from the same file and field as every other plan's, so one `publishedPrices` check covers them (currency list, no zero, at most four) and botd still ships none. Without them the card says "Contact us". The `self-host` tier is never listed as a managed plan, even with prices or a Stripe price id: a license pays for it, not checkout. Its limits and machine aren't shown, since a license's limit is its seats.

The card comes first, as on the public site, with "Licensed, business edition", the seats and includes lines, the operator's features, the prices or "Contact us", and a "Request a license" button. Nothing else on the page changes: managed plans, Enterprise, the per-person note and the links are as ADR 0121 has them.

### /pricing on the design tokens

The page now links `/site/site.css`, the landing page's stylesheet, whose token block comes from `tokens.json` (ADR 0338). It uses the landing page's header, skip link, cards and buttons, and follows the browser's light or dark setting. botd and Caddy both serve `/site/site.css` to anyone. The CSP drops `style-src 'unsafe-inline'` for `style-src 'self'` and `img-src 'self'` (the logo); there is still no script. `/status` keeps its own style; moving it is a separate change.

### Linked from the public site

`superbot-site --pricing-url URL` (or `SUPERBOT_SITE_PRICING_URL`) is a managed server's `/pricing`. The nav and footer's "Plans" link becomes "Pricing", to that URL when given, else to the landing page's plans section, the public site's own equivalent. With a URL, the plans note says current prices are there. The landing page's Self-host card now uses `offer.rs`'s lines and a "Request a license" button to the contact URL. It still shows no prices ("Pricing to be published"): prices on the landing page are [#44](https://github.com/CG-Labs/superbot/issues/44)'s slice 2.

The server's own landing page (`site/index.html`) doesn't link to `/pricing`. Every server shows it, mostly from disk through Caddy, and most servers publish no plans, so the link would be a 404 there.

## Alternatives considered

- **Self-host settings of their own** (`PLANS_LICENSE_PRICES` and similar): a second place for prices, with its own checks. The `self-host` tier already exists in every tiers file and already has `publishedPrices` and `features`.
- **Listing it on every published page**, with "Contact us" and no link: a plan nobody can ask for.
- **Generating a pricing page in the public site**: a second renderer of the same plans. The landing page's plans section is already the public site's version.
- **Editions and seat minimums in configuration**: there is one edition today and no minimum; adding settings for them would describe things that don't exist.

## Tests

- `plans::tests`: `PLANS_LICENSE_URL` is checked like `PLANS_CONTACT_URL` and falls back to it, and alone adds no Enterprise entry; prices read per seat; the self-host entry has its edition, seats, includes, per-seat prices and features, no limits, machine or Stripe id, and comes first on the page with "Request a license"; with no price, or no `self-host` tier, it says "Contact us" and no currency appears; with nowhere to ask it isn't listed; the `self-host` tier is never a managed plan; the page links `site.css`, has no inline style or script, and every class it uses is in `site.css`; the startup line names the self-host entry.
- `plans_http_tests.rs`, on the real router: `selfHost` from `PLANS_LICENSE_URL` in `/api/plans` and on `/pricing`, with the new CSP and `/site/site.css` served to anyone; no entry without a URL.
- `superbot-site`: `--pricing-url` takes only http(s); "Pricing" links to it in the nav and footer, else to `index.html#plans`; the Self-host card has `offer.rs`'s lines and "Request a license"; still no prices; the real build has no broken links.

## Consequences

- An operator who already set `PLANS_CONTACT_URL` gets the self-host plan on `/pricing` at their next upgrade, at that contact. `PLANS_LICENSE_URL` sends it elsewhere.
- Self-host prices are written per seat. A minimum seat count, volume pricing or other editions would need `offer.rs` and the page to change.
- Changing what a license includes means editing `offer.rs`, which changes `/pricing` and the public site together.
- Selling licenses still needs CG-Labs's public key in `TRUSTED` (ADR 0038); the page says how to ask, not that a key can be bought today without one.
