# 0093: Team billing

## Status

Accepted (21 Nov 2026). Seventh slice of billing v0 ([#31](https://github.com/CG-Labs/superbot/issues/31)) and the team-level billing item on per-user isolation ([#30](https://github.com/CG-Labs/superbot/issues/30), [roadmap](../ROADMAP.md)). Builds on tier limits and the Stripe webhook ([ADR 0040](0040-billing-v0-tier-limits.md)), checkout, the portal and customers ([ADR 0042](0042-billing-checkout-portal-customers.md)), resizing machines on a tier change ([ADR 0085](0085-resizing-machines-on-a-tier-change.md)), team accounts and machines ([ADR 0087](0087-team-accounts-and-machines.md)), team screens ([ADR 0088](0088-team-screens-in-the-apps.md)) and billing emails ([ADR 0091](0091-billing-emails.md)). Like all billing, off unless Stripe is configured, never in testing mode ([ADR 0068](0068-no-free-tier.md)).

Numbering: `main` has up to 0092 (dependency scanning), so this is 0093.

## Context

Billing was per person: each user bought their own plan. Teams (ADR 0087) now share Bots and get machines, but a company wants one bill for everyone, paid by whoever runs the team, that grows and shrinks as people join and leave. Stripe models this as one subscription whose item has a quantity (seats).

Everything ADR 0042 made safe for one person has to stay safe: Stripe redelivers events and sends them out of order, customers are never matched by email, and nobody's plan may move because of a subscription that isn't theirs.

## Decisions

### Who pays, and for whom

- **The team owns the subscription.** A team has at most one Stripe customer (`team_customers`), separate from people's: a customer is a person's or a team's, never both, and one linked to either is refused for the other (`customer_of_another_user`).
- **Owners and admins pay.** `POST /api/team/billing/checkout {tier}` (write access, team owners and admins) opens Stripe Checkout for the team with a quantity of one seat per member; `POST /api/team/billing/portal` opens the team customer's portal. Returns go to `/app/team`. One open checkout per team, like a person's; a second while one pays is a 409. A paid checkout stays the team's open one until its subscription is recorded (or Stripe's 3 days of webhook retries pass), so a delayed subscription event can't let a second checkout open; the check runs again under the team's lock.
- **The team's plan is everyone's plan.** While a team pays (status `active`, `trialing` or `past_due`, as for a person), each member's tier, limits, machine size and billing period are the team plan's, read in one place (`tier_of`). It wins over a member's own tier, even a higher one, so a team gets what it pays for and nothing it doesn't.
- **No double plans.** A member of a paying team can't start a personal checkout (409, `teamPays`; `billing.checkout_created` denied, reason `team_pays`). A personal subscription they already had is still recorded and still theirs to cancel in their portal; the Plan screen says their team pays.

### Telling team subscriptions apart

A subscription event is the team's when its metadata names a team (`superbot_team_id`), when its id is a known team subscription, or when it names no user and its customer is a team's. Anything naming both a user and a team is ignored (`ambiguous_payer`): the payer must be unambiguous. A team subscription id is never applied to a person, nor a person's to a team (`other_user`). Unknown teams and prices are ignored and audited. Ordering, staleness and supersession follow ADR 0042 exactly; it's the same code shape with a team id for the user id.

### Seats follow the team

- **One seat per member**, at least one. Joining or leaving a team (invite accepted, removed, left, or an admin's change) wakes a seat sync; one also runs every minute.
- **Absolute and prorated.** botd sets the subscription item's quantity (`POST /v1/subscription_items/{id}`, `proration_behavior=create_prorations`) to the member count, so a retry or a late sync can't double count, and Stripe charges or credits the part of the period. A quantity changed in Stripe's portal is set back on the next pass.
- **Retries never give up.** Each try has its own idempotency key; failures back off 1, 4, 16, 64 minutes, then hourly, and show as "Stripe didn't take the new seat count yet" to the team's managers. Audited as `team.seats_synced` and `team.seats_sync_failed` (no Stripe error text in the app).
- **A paying team can't vanish.** The last member can't leave, be removed or the team deleted (an admin included) while a subscription pays (409, `team.delete_refused`, reason `team_pays`), so nobody is billed for a team that no longer exists. Cancel first. An open checkout is expired first, under the same lock a checkout opens under; if it was already paid, or Stripe can't say, the team stays (`checkout_completed`, `checkout_unknown`).

### Members' machines

A team plan change moves each member's tier the same way an admin's change does: `user.tier_changed` (source `team`) and a resize request per member (ADR 0085). Joining a paying team moves the newcomer onto its plan; leaving moves them back to their own. The resize cause is `team`, so members don't get ADR 0091's resize emails for a plan they didn't buy.

### Metered tokens

With `STRIPE_METER_EVENT` (ADR 0050), a run's tokens are reported to whoever pays for its owner's plan when the run ends: the team's customer while the team pays, else the owner's own. The customer is stored with the row, so a member who leaves afterwards doesn't move usage already recorded.

### Emails and screens

- **Team billing emails** (ADR 0091's kinds: started, changed, payment failed, ending, ended) go to the team's owners and admins, once each per event, with team wording and a link to `/app/team`. Members aren't emailed; their app shows the plan.
- **Client.** The Team screen has a Plan section: everyone sees whether the team pays; managers see the status, seats against members, buy buttons and Manage billing. The Plan screen says the team pays and hides upgrades. Read-only people get no buttons.
- **Console.** The Teams tab shows each team's plan, status and seats for server admins, who change nothing there: the team's managers do, in Stripe.

### Off by default

No table is written and no route answers without billing; self-host is unchanged. The team routes and the seat sync need `STRIPE_SECRET_KEY` (a restricted key now also needs write access to Subscriptions, for the seat count); with only the webhook, team subscriptions made in Stripe are still applied.

## Consequences

- Companies get one bill that tracks their headcount, and each person still gets their own machine.
- A team plan is the floor and the ceiling: someone on a paying team can't buy more for themselves. A future per-person add-on would need its own design.
- A member who had a personal plan keeps paying for it until they cancel it. The app says the team pays, but botd doesn't cancel anything in Stripe on someone's behalf.
- Restricted Stripe keys need one more permission.

## Remaining

- Team-only prices (a tier sold only to teams, or per-seat prices that differ from a person's). (Done in [ADR 0346](0346-yearly-and-team-only-prices-at-checkout.md).)
- Telling members with a personal plan, by email, that they can cancel it once their team pays.
- Yearly prices at checkout (as for people). (Done in [ADR 0346](0346-yearly-and-team-only-prices-at-checkout.md).)
- SCIM groups as teams, so seats follow the IdP. (Done in [ADR 0095](0095-scim-groups-as-teams.md).)
- Server admins changing a team's plan from the console.
