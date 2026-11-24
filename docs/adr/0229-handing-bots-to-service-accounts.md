# 0229: Handing existing Bots to service accounts

## Status

Accepted (24 Nov 2026). Thirteenth slice of [#53](https://github.com/CG-Labs/superbot/issues/53) (M5, "Advanced RBAC"), on top of [ADR 0222](0222-service-accounts-keep-their-owners-bots.md) (service accounts keep their owner's Bots) and [ADR 0170](0170-service-accounts-granted-bots.md) (granted Bots).

0229 was set aside for this change; other open pull requests hold 0225 and 0230 to 0233.

## Context

Since ADR 0222 a service account keeps the Bots it makes: they stay its owner's (machine, plan, keys, memory) and the account manages them. ADR 0222 left two things for #53:

- A Bot that already exists can't be handed to an account. Automation that should take over a Bot a person set up (its chat, settings, memory) needs a new Bot instead.
- The app and console show kept Bots but can't change them. The owner can't take a Bot back from an account without deleting the account or giving the Bot away.

## Decision

### Who decides

Only a person: **the Bot's owner, or an admin**. Never a service account (its own or another's token), never a Bot token, and not teammates who can see or use the Bot, even with `bots.manage` or a manager grant. Lending the owner's keys and memory to automation is the owner's call. Refusals are audited as `bot.keep_refused` with `reason`.

### Handing one over

`PUT /api/bots/{id}/keeper` `{serviceAccount: <id>}`, with `manage` on the Bot:

- Only to a live service account of **the Bot's own owner** (the ADR 0222 triggers enforce this too). Someone else's account is 404 for non-admins, so they don't learn it exists, and 409 for admins. A person's id is 400.
- Not a **primary Bot** (409): it stays its owner's own.
- At most `MAX_KEPT_BOTS` (20) per account, as for Bots it makes (409, `service_account_bot_limit`). The count, the account check and the update are one SQL statement, so parallel requests can't overshoot.
- Refused while the owner is being erased (409), and if the Bot or the account changed owner or was deleted meanwhile (409, `bot_changed` / `service_account_changed`).
- The account's grant on the Bot, if any, is removed in the same transaction: keeping gives more (`manage`), and a grant left behind would come back as soon as the Bot is taken back.
- If another account kept it, that one stops: audited as `bot.service_account_released` with `reason: "reassigned"`, and its run there stops (the run began with the owner's keys).
- Audited as `bot.service_account_assigned` with `serviceAccount`, `name`, `owner`, `from` and `grantRemoved`. Handing it to the account that already keeps it changes nothing and audits nothing.
- The visibility, the owner and other people's grants don't change.

### Taking it back

`DELETE /api/bots/{id}/keeper`, owner or admin, with `view` on the Bot: letting go only narrows. The account stops keeping it and its run there stops, audited as `bot.service_account_released` with `reason: "released"`. 404 if no account keeps it.

### Where it shows

- `GET /api/bots/{id}/access` adds `keepers` (the owner's live accounts: id, name, role, status, `keptBots`, `full`) and `maxKeptBots`, only for those who may decide and only for non-primary Bots, so the apps offer the choice only when it would work.
- `GET /api/service-accounts/{id}` adds `keptBotList` (the Bots it keeps) and `keepable` (the owner's Bots the caller may hand it, each with `keptBy` if another account keeps it now).
- App: the Bot's Sharing section has a "Kept by a service account" picker (owner or admin, non-primary), with a plain confirmation that says what the account can do with it. The service account screen lists the Bots it keeps with "Take back", and offers the owner's other Bots with "Hand it over".
- Console: unchanged; its service account card still lists kept Bots. The console is admin-only and never calls Bot routes (ADR 0032), so handing over and taking back are the app's.
- `botctl bot keep <bot> <service-account>` and `botctl bot release <bot>`.
- The access review's sign-off digest now covers which Bots each service account keeps, alongside its access and grant on each. ADR 0222 left `kept` out, because a Bot the account made was new access anyway. A handover can leave access as it was (a read-only account that already viewed a shared Bot still only views it), yet the report changed, so without this an earlier sign-off would stay valid. It's added only for accounts that keep Bots, so other reports keep their digests; a server whose accounts already keep Bots gets a new digest once, on upgrade.

The account is now a person-only route for service accounts (`/api/bots/{id}/keeper` joins `grants`), and the route is classified `write`.

## Alternatives considered

- **Let anyone with `manage` on the Bot decide.** A manager grant or `bots.manage` would then lend the owner's keys and memory to an account the owner didn't pick for it. Manage covers the Bot's settings, not whose automation runs as its owner.
- **Let the service account claim a Bot it was granted.** A leaked token could then take over every Bot it can reach. Who keeps a Bot stays a person's decision, as who owns and uses one already is (ADR 0222).
- **Keep the grant alongside.** Taking the Bot back would silently leave the account with operator or viewer access the owner may have forgotten. Removing it makes "Take back" mean the account reaches it no more, unless someone grants it again.
- **Refuse reassignment; require taking it back first.** Two steps for the same outcome, with a window where nobody keeps it. One request, audited as a release and an assignment, is clearer.
- **Hand over primary Bots too.** A person's primary Bot is their own chat and memory; automation should have its own Bot.

## Consequences

- Owners can move a Bot they set up to automation, and take it back, without new Bots or giving it away. Every change is audited and stops the old account's run.
- The two items ADR 0222 left for #53 are done. What remains is follow-up polish, not missing scope: for example handing several Bots in one request, or letting members who own service accounts open their account's page (today it's an admin or delegate view; they use the Bot's picker instead).
