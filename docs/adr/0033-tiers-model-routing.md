# 0033: Tiers and model routing hidden behind them

## Status

Accepted. Implements [#32](https://github.com/CG-Labs/superbot/issues/32) (M3) and lays the foundation for billing v0, [#31](https://github.com/CG-Labs/superbot/issues/31), without any payment provider. It follows the owner's decision of 19 Nov 2026 ([roadmap](../ROADMAP.md#decisions-19-nov-2026), decision 3): pricing is **per user**, with several tiers that differ by language model access and limits; **users pick a tier, not a model**. It builds on [ADR 0012](0012-users-sessions-rbac.md) (users, roles), [ADR 0017](0017-bot-acls.md) (Bot owners), [ADR 0019](0019-audit-actors.md) (audit actors), [ADR 0027](0027-expo-primary-hermes-default.md) (Hermes for managed tiers) and [ADR 0029](0029-per-user-isolation.md) (a Bot runs for its owner).

## Context

Every Bot had a harness, a model and an effort, all set by whoever managed it. The client showed a model picker. That suits self-hosting, where the operator pays the model bills. It doesn't suit managed plans:

- the plan, not the user, decides which models someone gets, since the models are most of the cost;
- model names change and mean little to most buyers; a plan name ("Pro") is what they bought;
- limits (Bots, runs) need to follow the same plan.

Billing v0 will sell those plans. Before it can, botd needs to know what a plan *is* and enforce it. This ADR does that, with no payment code.

## Decision

### A tier

A tier has a name, a label, **routes**, and **limits**:

- **Routes** say what its users' Bots may run on: a harness, and optionally a provider, model and effort. `"any"` means any harness and model, as before tiers.
- **Limits** are simple and per user: `maxBots` (Bots they own), `monthlyRuns` (Bot runs a calendar month, UTC), and `monthlyTokens`. Unset means unlimited. `monthlyTokens` is read and shown but **not enforced**: harnesses don't report token counts to botd yet.

A tier with routes is **managed**: the plan picks the model.

### Config

`TIERS_FILE` names a JSON file; `DEFAULT_TIER` names the tier users without one get, over the file's `default`, else the first tier.

```json
{
  "default": "starter",
  "tiers": [
    { "name": "starter", "label": "Starter",
      "routes": [{ "harness": "hermes", "provider": "openrouter", "model": "anthropic/claude-haiku-4.5" }],
      "limits": { "maxBots": 3, "monthlyRuns": 300 } },
    { "name": "pro", "label": "Pro",
      "routes": [
        { "harness": "hermes", "provider": "openrouter", "model": "anthropic/claude-sonnet-4.5" },
        { "harness": "claude", "model": "claude-sonnet-4-5", "effort": "high" }
      ],
      "limits": { "maxBots": 10, "monthlyRuns": 3000 } },
    { "name": "self-host", "routes": "any" }
  ]
}
```

A full example is [`deploy/tiers.example.json`](../../deploy/tiers.example.json). botd checks it at startup and refuses to start on a mistake, like other settings: unknown fields, names that aren't lowercase slugs, repeated tiers or routes, unknown harnesses, a provider for a harness that doesn't take one (only Hermes does), and provider, model or effort names with spaces or a leading `-` (they become command-line arguments). Changing the file needs a restart.

**Without `TIERS_FILE`** there is one built-in tier, `self-host`: `"any"`, no limits. Every Bot runs exactly as it's set, so existing installs change nothing. `DEFAULT_TIER` set to anything else without a file is a startup error.

The file is not a secret: it holds model names, not keys. Provider keys stay in the secrets store ([ADR 0010](0010-secrets.md)).

### Per-user assignment

`users.tier` (a new migration) holds the tier an admin gave the user; NULL means the default tier. So changing `DEFAULT_TIER` moves everyone who has no tier of their own, and a new user gets the default until someone picks another.

- **Admins** set it: `PATCH /api/users/:id {tier: "<name>" | null}`, or `botctl user tier <user> <tier|default>`. Any other role gets 403 (the `users` routes are admin-only). Only listed tiers are accepted (400 otherwise).
- **Audit**: `user.tier_changed` with `{from, to, effectiveFrom, effectiveTo}`, the stored values and the tiers they meant, with the admin as actor.
- A stored tier that the file no longer lists acts as the default; botd warns about it at startup.

### Routing: the owner's tier picks the route

A Bot runs for its owner (ADR 0029), so it runs on its **owner's** tier, whoever asked. Before every run, the runner asks the tier for the route:

- `"any"`: the Bot's own harness, model and effort, as before.
- **Managed**: the Bot's model if it is one of the tier's routes for the Bot's harness, else that harness's first route. The provider and effort always come from the route, never from the Bot.
- **Managed, harness not in the tier**: the run is refused, not moved to another harness (a harness's sessions don't carry across). The Bot says which harnesses the plan has, and `bot.run_refused` is audited with reason `tier_harness`.

The route goes to the adapter: model and effort as before, and the provider in `RunInput::provider` (Hermes's `--provider`, over `SUPERBOT_HERMES_PROVIDER`). Adapters say whether they take a provider (`Adapter::supports_provider`), so this stays harness-agnostic. `harness.invoked` records the tier and the route actually used.

So the stored model on a Bot is only a preference among the tier's routes. A Bot set up before its owner moved tier, or set straight in the database, still runs only on routes the tier allows.

### Enforcement on the API

- `POST /api/bots` and `PATCH /api/bots/:id`: a harness, model or effort outside the owner's tier is a **403** with a plain reason. Leaving model and effort out is always fine; the tier picks. Only fields being changed are checked, so a Bot from before a downgrade can still be renamed; an effort alone is checked against the route of the model the Bot keeps. Admins are held to this too: the tier is the routing table, and an admin who wants a model for someone gives them a tier that has it.
- New Bots without a harness get `DEFAULT_HARNESS`, or the tier's first harness if it doesn't have that one. `/api/state` lists only the caller's tier's harnesses.
- `maxBots`: creating a Bot, a Bot making one for its owner, and an admin handing a Bot to someone are all refused (403) at the limit. The count and the insert (or owner change) are one SQL statement, so racing requests can't pass it together. Lowering a limit doesn't delete Bots.
- `monthlyRuns`: each run takes one from the owner's count for the month (`usage_monthly`, keyed by user and `YYYY-MM`) in one SQL statement, so racing runs can't both take the last one. At the limit the run is refused (`bot.run_refused`, reason `tier_limit`) and the Bot says when more start. A run refused afterwards by machine routing gives its count back. Runs by anyone on a shared Bot count for its owner, who pays for it.

Every new query names the user (`users.id`, `bots.owner_id`, `usage_monthly.user_id`).

### What people see

On a managed tier, models are the back end's business:

- Bot views carry `tier: {name, label, managed}`. On a managed tier they leave out `model` and `effort`, for everyone, in every response and in the live stream.
- **Admins** (people, not their Bots) also get `model`, `effort`, `route` (or `routeError`), and `harnesses` (the owner's tier's, for editing someone else's Bot) on every Bot, in responses and the stream.
- `GET /api/harnesses/:name/models` is 403 for non-admins on a managed tier. Admins can add `?tier=<name>` to list just that tier's models for the harness.
- `GET /api/me/tier` (people only): your tier's name, label, managed flag, limits and this month's use (`runs`, `bots`). No routes. `/api/state` has the same tier under `me.tier`.
- `GET /api/tiers` (admins): every tier with its routes, the default, and where they came from. `botctl tiers`.
- The admin portal's user views carry `tier` (stored) and `plan` (the tier they're on and their use).

The client shows a Bot's plan ("Pro plan · the plan picks the model") instead of the model picker to non-admins on a managed tier, and gives admins the picker with only that tier's models. Self-host keeps the picker.

### How billing v0 attaches (#31)

Billing v0 adds a payment provider without changing any of the above:

1. A `subscriptions` table keyed by user: provider, customer and subscription ids, status, the tier it pays for, the current period.
2. The provider's webhook (signed, idempotent by event id) sets `users.tier` from the subscription and records `user.tier_changed` with a system actor (`system:billing`) on behalf of the user. A lapsed subscription sets the tier back to the default. Admin changes stay possible, for support and comps.
3. The tiers file gains price ids per tier. Its tier names are what the provider's products map to.
4. Usage periods follow the subscription's billing period instead of the calendar month; `usage_monthly` gets a token column once harnesses report tokens, and `monthlyTokens` is enforced the same way runs are.
5. Machine size follows the user's tier: `MACHINE_TIERS` ([ADR 0025](0025-control-plane-linode.md)) uses the same names, and a machine request without a tier will take the user's.

Nothing in this slice calls a payment provider or anything that costs money.

## Deliberately out of scope

- Any payment provider, prices, checkout, invoices or webhooks.
- Token metering and enforcing `monthlyTokens`.
- Routine-run limits separate from runs, storage limits, and per-tier machine sizes tied to `users.tier` (the machine API is unchanged here).
- Changing tiers in the client's admin portal (the API and `botctl` do it).
- Reloading the tiers file without a restart.
- Fallback routes when a provider is down.

## Consequences

- Self-hosted servers are unaffected: no file, one open tier, and the model picker as before.
- On a managed tier a Bot's stored model is a preference, not a promise; admins see the real route on every Bot.
- A user moved to a tier without their Bots' harness gets refusals until someone switches those Bots. That is deliberate: a run never moves to a harness nobody chose.
- Monthly run counts are per server and survive restarts; they are in the database and its backups.
