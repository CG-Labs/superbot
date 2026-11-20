# 0042: Billing v0, checkout, the customer portal, and Stripe customers

## Status

Accepted (20 Nov 2026). Second slice of [#31](https://github.com/CG-Labs/superbot/issues/31) (M3, billing v0), on top of [ADR 0040](0040-billing-v0-tier-limits.md) (tier limits and the signed Stripe webhook). Uses the audit log ([ADR 0009](0009-audit-events.md)), roles ([ADR 0012](0012-users-sessions-rbac.md)), and secrets ([ADR 0029](0029-per-user-isolation.md)).

0040 is the first billing slice; 0041 was taken by machine harness logins, so this is 0042.

## Context

ADR 0040 made Stripe subscriptions set a user's tier, but someone still had to create each subscription by hand with the user's id in its metadata, and botd knew nothing about who a Stripe customer was. People need to buy a plan and manage it (card, invoices, cancel) from the app, and botd needs to tie each Stripe customer to one user so a later subscription lands on the right person, without ever trusting an email address. Self-hosted servers must stay exactly as they are.

## Decision

### botd calls Stripe, for two things only

With `STRIPE_SECRET_KEY` (or `_FILE`) set, botd calls Stripe for two things: Checkout Sessions (create, expire, and read one's status: `POST /v1/checkout/sessions`, `POST …/{id}/expire`, `GET …/{id}`) and Billing Portal sessions (`POST /v1/billing_portal/sessions`). It creates no products, prices, customers or subscriptions itself; Checkout makes the customer and subscription when someone pays.

- **Off by default.** Without the key, `GET /api/billing` and both `POST`s answer 404 "Billing isn't set up on this server.", and the client hides its Plan screen. The webhook (ADR 0040) works with or without the key.
- **Startup checks.** The key needs `STRIPE_WEBHOOK_SECRET` too (without the webhook a checkout would never change anyone's plan), must look like a secret or restricted key (`sk_…`, `rk_…`; the publishable `pk_…` is refused), and the server needs its public address. Any of these wrong stops startup with a message that never repeats the key.
- **Public address.** Stripe sends people back to `{public}/app/plan?checkout=success|cancelled` and the portal to `{public}/app/plan`. `{public}` is `PUBLIC_URL`, else `SSO_PUBLIC_URL`, else `https://` and the first `ALLOWED_HOSTS` entry. It must be https with no path, query or user info (http only on loopback, for development). The address never comes from the request, so a forged `Host` header can't send someone to another site after paying.
- **HTTP.** Form-encoded `POST`s with the key as a bearer token, a pinned `Stripe-Version` (`2025-09-30.clover`) so Stripe's changes don't reach us unannounced, a 5-second connect and 20-second total timeout, and one retry after half a second on no answer, 429 or 5xx.
- **Idempotency.** Every `POST` sends an `Idempotency-Key`, so the retry gets the same answer instead of a second session. A checkout's key is new for each request: the page before it was just closed, and a reused key would bring it back. Portal and expire keys are the action, the user, the minute, and a hash of the form, so a double-click gets the same portal page.
- **Secrets.** The key is redacted from logs, is a reserved name (never saved as a secret, never in a Bot's environment, from the environment or a `_FILE`), and is never sent anywhere but Stripe. When Stripe refuses, the server log gets the HTTP status and Stripe's error type and code only, the person gets a plain "Stripe couldn't open the checkout just now" (502), and the audit event gets the same short reason. Session URLs are returned to the person who asked and never logged or audited.

### Checkout and the portal

- `POST /api/billing/checkout {tier}` opens a subscription Checkout for the tier's first price in `stripePrices`. Only tiers with a price can be bought; others are 400. It sets `client_reference_id` and `metadata.superbot_user_id` on the session and `subscription_data.metadata.superbot_user_id` on the subscription it creates, so the webhook can always place the result. A linked customer is reused (`customer`); otherwise the user's email is a prefill (`customer_email`), never used to match.
- **Nobody pays twice.** Someone whose subscription already pays for their plan gets 409 and is pointed at the portal; plan changes and cancelling happen in Stripe's portal, configured in the Stripe dashboard. Each person has at most one open checkout page: botd remembers it (`billing_checkouts`), pages expire after 31 minutes, and before opening another it expires the last one. If Stripe says the last one was paid (the webhook may not be here yet), the new checkout is refused with 409; if Stripe can't be reached, it's a 502 and no second page opens. One checkout per person runs at a time, so two clicks can't race. `checkout.session.completed` forgets the page.
- `POST /api/billing/portal` opens the portal for the user's linked customer, or 409 when they have none yet.
- `GET /api/billing` is the user's plan and use against its limits, the plans for sale (labels and limits, no price ids), their paying subscription (status, tier, period end), whether they have a billing account to manage, and whether their role may change it.
- **Who.** Reading needs Read; buying and the portal need Write, so read-only people see their plan but change nothing. Bots are refused: billing is a person's. Break-glass and loopback development act as the owner account.
- **Limits.** Ten sessions a minute per user, then 429, so a script can't flood Stripe from one account.

### Linking users to Stripe customers

A new `billing_customers` table holds at most one Stripe customer per user and one user per customer. The first link stands: a later event naming another customer for the user, or this customer for another user, changes nothing and is audited as ignored.

- **`checkout.session.completed`** links the session's customer to the user in `metadata.superbot_user_id` or `client_reference_id`; if both are set and differ, nothing is linked (`user_mismatch`).
- **`customer.subscription.*`** links the subscription's customer to its user, once the event has placed it (ADR 0040), so subscriptions made outside Checkout link too. Its user is found from its metadata, then the subscription id botd already knows, then the linked customer, so a subscription made in the dashboard or portal without metadata still lands on its customer's user. A subscription whose customer is linked to someone else is ignored (`customer_of_another_user`) and changes no tier.
- **`customer.deleted`** removes the link, so the user's next checkout makes a new customer, and remembers the customer (`billing_deleted_customers`) so no later event, such as its subscription's cancellation arriving afterwards, links it again (`customer_deleted`). Stripe ends the customer's subscriptions with their own events, which still set the tier.
- **Upgrading.** Subscribers from before this change are linked at migration when their subscriptions name one customer that no other user's do, so they can open the portal at once; anyone else is linked by their next event.
- No email address is ever used to find a user.
- Each event applies once, as before (`billing_events`). Add `checkout.session.completed` and `customer.deleted` to the webhook endpoint in Stripe.

### Audit

`billing.checkout_created` (tier, price, session id, customer; or failure with the reason), `billing.portal_created` (customer), `billing.customer_linked` (customer, how: `checkout` or `subscription`, event id) and `billing.customer_unlinked`. A checkout refused because a subscription already pays is audited as denied; rate-limited ones are not, so a flood doesn't fill the log. Linking is done by `system:billing` on behalf of the user. Admins see each user's customer in `GET /api/usage` and `botctl usage`.

### Client

A Plan screen at `/app/plan`, opened from the sidebar for everyone when the server sells plans: the current plan with its use against each limit and any limit already passed, the subscription's status and period end, "Manage billing" for people with a billing account, and an "Upgrade to …" button on each other plan for people without a paying subscription. Buttons open Stripe's page (https only) in the same tab on the web, the browser on phones; coming back shows "Thanks…" or "Checkout cancelled. Nothing was charged." and reloads, and the screen reloads when the app comes back to the front. After a successful checkout it checks again every 3 seconds for a minute until Stripe's webhook has set the plan.

### Tests

The server tests run a fake Stripe on loopback that checks the bearer key, the idempotency key, the pinned version and the form, and replays an answer for a repeated key as Stripe does; nothing reaches the network. Webhook tests use fixture events (`server/tests/fixtures/stripe/`) with made-up ids, signed with a test secret. No test or document uses a real key.

## Deliberately out of scope (later #31 slices)

- Usage periods aligned with each subscription's billing period instead of calendar months and UTC days.
- Token metering and enforcing `monthlyTokens`; storage limits.
- Resizing machines when a user's tier changes.
- Billing emails (receipts, failed payments, limit warnings); Stripe's own emails can cover receipts meanwhile.
- More than one price per tier at checkout (yearly and monthly), and linking a customer by hand.

## Consequences

- Self-hosted servers without the key are unchanged; a server with only the webhook secret behaves as in ADR 0040.
- Managed servers hold a Stripe secret key. A restricted key with write access to Checkout Sessions and Billing Portal sessions (and nothing else) is enough and limits the damage if it leaks.
- A plan can't be bought twice from the app, but an admin can still create a second subscription in Stripe's dashboard; ADR 0040's rule (the newest paying subscription sets the tier) still applies.
- Moving a person to another Stripe customer needs `customer.deleted` (deleting the old customer) first, since the first link stands.
