# 0347: Server admins change a team's plan

## Status

Accepted (27 Nov 2026). Second Finish line slice of billing v0 ([#31](https://github.com/CG-Labs/superbot/issues/31), [roadmap](../ROADMAP.md#finish-line)). Builds on team billing ([ADR 0093](0093-team-billing.md)), billing emails ([ADR 0091](0091-billing-emails.md)), resizing on a tier change ([ADR 0085](0085-resizing-machines-on-a-tier-change.md)) and the console kit ([ADR 0337](0337-a-shared-kit-for-settings-and-admin-screens.md)). Billing stays off by default and never runs in testing mode ([ADR 0068](0068-no-free-tier.md)).

Numbering: 0347 was reserved for this slice.

## Context

ADR 0093 left two items on team billing: server admins couldn't change a team's plan (only the team's own managers could, in Stripe), and a member still paying for a personal plan wasn't told they could cancel it once their team's plan covered them. On a server without billing, an admin had no way to give a whole team a plan at all: only person by person.

## Decisions

### One endpoint, two cases

`PUT /api/teams/{id}/plan {tier: name | null}` (server admins; `rbac::classify` leaves `/api/teams` to admins), from a Plan picker on each team in the console's Teams tab. It returns the team as admins see it, with a new `plan`: `{current: {name, label, source}, given, paid}`. `GET /api/teams` adds `plans`, each tier's `{name, label, priced}`.

- **No subscription pays for the team** (billing off, or on and the team hasn't bought a plan): the plan is the admin's to give. It's recorded on the team (`teams.tier`), and every member's tier is the team's, read in the same place as a paid team plan (`tier_of`). There's no Stripe call, so nobody is charged, with billing on or off. `null` takes it away. The plan and the emails it asks for are saved in one transaction, and only if the plan is still the one the request read, so two admins giving the same plan at once email members once; the same plan set again changes nothing but asks again for any resize a change left unasked (botd stopped between, say). Audited as `team.tier_changed` (source `admin`), and each member it moves as `user.tier_changed` (source `team`, via `admin`) with a resize request, as for a paid team plan.
- **A Stripe subscription pays**: botd moves that subscription onto the tier's first Stripe price (`POST /v1/subscriptions/{id}`, the seat item's id, price and current seat count, `proration_behavior=create_prorations`, an idempotency key of its own per request, kept across the client's retries of it, so asking for a plan again after a round trip to another reaches Stripe again) and answers 202. It's sent even for the plan Stripe last reported, so choosing it again undoes a change still on its way. Nothing changes until Stripe's `customer.subscription.updated` arrives; the webhook applies it as any other team plan change (ADR 0093), so ordering, staleness and redelivery stay its job. Audited as `team.plan_change_requested` (success or failure; Stripe's error text is logged, not shown).
- **Refused, and audited as denied** (409): taking away a plan Stripe pays for (`team_pays`: its managers cancel it under Manage billing), a tier with no Stripe price (`no_price`), a subscription whose item botd hasn't seen yet (`no_item`), and any change to a paid plan while this server can't call Stripe (`billing_off`). A Stripe failure is a 502.

A paid plan always wins over a given one: if the team's managers buy a plan, the subscription's tier is everyone's while it pays, and the given plan applies again after it ends.

### Telling members they may cancel

When a team moves to a plan, each member who still pays for a plan of their own (an active, trialing or past-due personal subscription) gets one email, `personal_plan_covered`: their team's plan now covers them, they may cancel their own plan, SuperBot won't cancel it for them, and **Manage billing** on `/app/plan` is where to do it.

- **Once per change.** The email's key is the change: the Stripe event's id for a paid plan (queued in the event's transaction, so redeliveries send nothing), or a fresh id per admin change. The same plan set twice is no change and sends nothing.
- **Any team plan, any source.** A team starting to pay in Stripe, a paid plan moving, or an admin giving one: all are "the team moves to a plan", and SuperBot has no free tier, so each counts.
- **Only if still true.** It isn't sent if they've cancelled, or aren't on the team it names (its id is kept with the email, never shown), by the time it goes (`billing.email_skipped`, reason `not_needed`). It goes to the member, not the team's managers, and says nothing about prices or Stripe ids. With billing off nothing is queued, as for every billing email.

### Console

The Teams tab gets a Plan picker in each team's header (the kit's `.bar` select). Changing it asks first, saying whether Stripe will charge (prorations) or nothing is charged, and that people still paying for their own plan are emailed. For a team that pays in Stripe, "No team plan" and unpriced plans can't be picked, and a 202 shows "Stripe is moving ...'s subscription". Until Stripe reports the new plan, the picker shows the plan asked for (kept in the page, not on the server), so picking the current plan again undoes the change. The billing line says a given plan is "given here".

In the app, `billing.plan` and `teamPlan` carry the same `source`. With billing off, `GET /api/team` still shows a given plan as `billing: {plan, canChange: false}`, with no Stripe controls. A plan an admin gave says so on the Team and Plan screens, and doesn't stop the team's last person leaving: only a plan Stripe pays for does, as on the server.

## Consequences

- A server without billing can put a whole team on a plan in one step, and a paying team's plan can be changed without its managers, with Stripe's prorations and the webhook as the one place plans change.
- Members on an admin-given plan meter tokens to nobody: there's no subscription to bill.
- A personal checkout is refused while a team's plan covers someone, given or paid (`team_pays`).
- botd still cancels nothing on anyone's behalf.

## Remaining

- A member joining a team that's already on a plan, while paying for their own, isn't emailed.
- A paid team moves to its tier's first Stripe price. Choosing between a tier's prices (yearly, team-only) belongs to #31's checkout slice.
