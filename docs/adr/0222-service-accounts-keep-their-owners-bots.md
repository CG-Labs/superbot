# 0222: Service accounts keep their owner's Bots

## Status

Accepted (24 Nov 2026). Twelfth slice of [#53](https://github.com/CG-Labs/superbot/issues/53) (M5, "Advanced RBAC"), on top of [ADR 0143](0143-service-accounts.md) (service accounts), [ADR 0170](0170-service-accounts-granted-bots.md) (granted Bots), [ADR 0182](0182-delegates-own-service-accounts.md) (delegates' own) and [ADR 0046](0046-shared-bots-under-isolation.md) (shared Bots, open or isolated).

0222 was set aside for this change; other open pull requests hold 0219 to 0221 and 0223.

## Context

Since ADR 0170 a service account can be granted a Bot, but it can't make one. Automation that needs a Bot of its own, such as CI that sets up a Bot per repository, or a provisioning script, has to ask a person to make it and grant it, every time. ADR 0209 left "service accounts owning Bots" as the last item for #53, with one open question: a Bot runs on someone's machine, under someone's plan, with someone's keys and memory. A service account has none of those.

## Decision

### Whose Bot it is

- A service account never owns a Bot. A Bot it makes is owned by **its owner** (`bots.owner_id`), so the Bot uses the owner's machine, plan limit, harness keys, folder and memory, exactly like one the owner made. Nothing in the machine, plan or key code changes.
- The Bot records the account that **keeps** it: `bots.service_account_id`. The account manages that Bot as its owner would, within everything that caps it on every request (ADR 0143): its role, its token's scopes and what its owner holds now.

### Making one

- `POST /api/bots` from a service account token with `write` (no longer refused as a person's route). The same body as for a person.
- Always private: `visibility: shared` is refused with 400. Only its owner can share it.
- At most `MAX_KEPT_BOTS` (20) Bots per account (409, `service_account_bot_limit`), on top of the owner's plan limit (403, `tier_bot_limit`), so a leaked token can't fill the owner's machine or plan. Both counts and the insert are one SQL statement, so parallel requests can't overshoot.
- Refused if the account was deleted or changed owner mid-request (409, `service_account_changed`).
- Audited as `bot.created` with `serviceAccount`, refusals as `bot.create_refused` with it.

### What it can do with one

- Rename it, change its harness, model and settings, run it, read its chat, and delete it: `manage`, capped by its role, scopes and owner. A read-only account or a `read`-scoped token still only views.
- It can't change who owns it or who can use it: `PATCH /api/bots/{id}/access` and `PUT|DELETE /api/bots/{id}/grants/{user}` are now person-only routes for service accounts ("Who owns a Bot and who can use it is for a person to decide"). It still can't open screens or decide approvals; its owner does.
- The owner and admins see and manage it as any of the owner's Bots.

### When the link goes

The Bot always stays its owner's. The account stops keeping it when:

- The Bot is given to someone else (its owner changes).
- The account is given another owner.
- The account is deleted.

SQLite triggers clear `service_account_id` in each case, and refuse a link to anything but a live service account of the Bot's own owner, so no code path can leave a stale or foreign link. Every read also checks the account is live and still the Bot owner's (`acl::kept_by`). The released Bots are read in the same transaction as the change, so one made meanwhile isn't missed. Each release is audited as `bot.service_account_released` with `reason` (`bot_owner_changed`, `owner_changed`, `service_account_deleted`), and `service_account.updated`/`.deleted` (and the delete reply) count them as `keptBotsReleased`. A run the account has going on a released Bot stops, even if it can still use the Bot some other way: that run began as the owner's, with their keys. The Bot's queue stays, so the owner's queued work still runs, and the account's is checked again when it starts, no longer as keeper.

Disabling the account keeps the link: its tokens stop working, and it keeps the Bot again once enabled.

### Runs with isolated shared Bots

With `SHARED_BOTS=isolated` a run for anyone but the owner uses that person's access and the server's keys, never the owner's (ADR 0046). A kept Bot's run for its account is treated as the owner's own run: the owner's keys, facts, session and folder, and no teammate OS user. That's the point: the Bot is the owner's, made for automation they set up. But the run's Bot token (and `botctl` inside it) acts for the **account**, so what the run can reach on the server is capped by the account, not the owner. A screen asked for by that token is the owner's.

### Where it shows

- `GET /api/bots` and `/api/bots/{id}/access` add `serviceAccount` {id, name} to a kept Bot.
- `GET /api/service-accounts` adds `keptBots` to each account and `maxKeptBots`; `GET /api/service-accounts/{id}` marks `kept` in `bots`.
- The access review marks a kept Bot `kept: true` (and " kept" in the CSV). The sign-off digest doesn't change: the account already counts the Bot as one it reaches, with its access.
- App: the Bot's Sharing section says which account keeps it; the service account list says how many Bots each keeps; the access review line says "kept". Console: the account card lists them.

## Alternatives considered

- **The service account owns the Bot.** It has no machine, plan, keys or memory, so each of those would need a rule, and the machine code would need a non-person owner throughout. Owning it through its owner reuses all of that unchanged.
- **Give the Bot to the account's owner with a grant to the account.** That works today but needs a person each time, and a grant can't be `manage` (ADR 0170).
- **Let it share Bots or grant others.** A leaked token could then expose the owner's machine and keys to the whole server. Sharing stays a person's decision.
- **Move kept Bots with the account to its new owner.** The Bots hold the old owner's memory and files on their machine. Leaving them with the person whose machine they're on is the safe default; the new owner's account can make new ones.
- **Run kept Bots as the account (isolated, the server's keys).** The account has no keys or facts of its own, so the Bot would run with nobody's setup. The owner chose to lend the account their Bots; capping only what the run can reach on the server keeps that lending bounded.

## Consequences

- Automation can make, change and remove Bots without a person, within its owner's plan and a per-account cap, and every step is audited.
- One column (`bots.service_account_id`), one index and four triggers. Old Bots aren't kept by anyone.
- Service account tokens can now create Bots, so a `write` token is worth more; scope tokens to `read` where they don't need it.
- Still to do for #53: assigning an existing Bot to one of its owner's accounts, and managing kept Bots from the app (today it shows them).
