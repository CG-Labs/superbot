# 0324: Handing several Bots to a service account at once

## Status

Accepted (26 Nov 2026). Part of [#53](https://github.com/CG-Labs/superbot/issues/53) (M5, "Advanced RBAC"): the fifth follow-up [ADR 0272](0272-advanced-rbac-delivered.md) ranked, deferred by [ADR 0229](0229-handing-bots-to-service-accounts.md), [ADR 0239](0239-owners-see-and-stop-their-service-accounts.md) and [ADR 0263](0263-team-owners-decide-requests-for-team-roles.md). Builds on ADR 0229 (handing existing Bots to service accounts) and [ADR 0222](0222-service-accounts-keep-their-owners-bots.md) (service accounts keep their owner's Bots). The fourth follow-up was [ADR 0320](0320-two-approvers-for-chosen-roles.md).

0324 was set aside for this change.

## Context

Since ADR 0229 the Bot's owner or an admin hands an existing Bot to one of the owner's service accounts with `PUT /api/bots/{id}/keeper`, one Bot per request. Moving a set of Bots to automation (a team's nightly jobs, or every Bot of a project) takes one request per Bot, and a loop that stops halfway leaves some Bots handed and some not, with the account's 20-Bot limit (`MAX_KEPT_BOTS`) found only when it's reached. The app's service account screen offers one Bot at a time for the same reason.

ADR 0272 sketched the shape: a list in one request, checked against the 20-per-account limit in one transaction.

## Options

1. **`POST /api/service-accounts/{id}/kept-bots` `{bots: [...]}`, all or none.** The account is the one thing every Bot shares, so it goes in the path; the Bots are a list. Each Bot gets the same checks as `PUT .../keeper`, and one transaction hands them all or none.
2. **The same route, handing what it can.** Report each Bot's result and hand the rest. A script then has to read a mixed result and decide what to undo; a half-done handover is what this change exists to avoid.
3. **`PUT .../kept-bots` replacing the whole set** (handing the listed Bots and taking back the rest). One request then also narrows, so a stale list from a script silently takes Bots back. Taking back stays one Bot at a time, explicitly.
4. **A list on `PUT /api/bots/{id}/keeper`.** The path names one Bot; a list there doesn't fit.

We chose option 1.

## Decision

`POST /api/service-accounts/{id}/kept-bots` `{bots: ["<bot id>", ...]}`:

| Rule | Answer | Why |
|---|---|---|
| Who | The account's owner or an admin, a person: others' accounts are 404 for anyone who manages none, 403 for delegates (as `GET /api/service-accounts/{id}`); service accounts and Bots are refused (`person_only`, `need_user`). Classified `write`, so read-only people can't. | As ADR 0229: lending the owner's keys and memory to automation is the owner's call. |
| Which Bots | 1 to 20 ids, repeats counted once; anything else is 400. Each must be one the caller sees (404) and manages (403), decides (403, `not_owner`), not a primary Bot (409), and the account owner's (409 for admins). | The same checks as `PUT .../keeper`, in the same order, so the two routes never disagree. |
| All or none | The first Bot refused stops the request with nothing changed, and the error starts with `Bot <id>:`. All are then handed in one transaction, each with `PUT .../keeper`'s guarded statement (`Db::keep_bots`), so earlier ones count against the limit for later ones and any refusal rolls back the rest. | A script either did it or didn't; no half-done state to clean up. |
| The limit | 409 `service_account_bot_limit` when the Bots it keeps plus the new ones would pass 20, audited with `kept` and `adding`. | The limit is the same; it's checked once for the set. |
| Already kept | A Bot the account keeps already changes nothing and is listed in `unchanged`. | Retrying a request is harmless. |
| Moved from another account | That account stops keeping it and its run there stops, audited `bot.service_account_released` with `reason: "reassigned"`, as one handover does. | Unchanged from ADR 0229. |

Each handed Bot is audited as `bot.service_account_assigned` with the same details as one handover plus `batch` (how many Bots the request named), its grant is removed in the same transaction, and its access change goes out as before. Refusals are `bot.keep_refused` with `batch` too. The reply is the account as `GET /api/service-accounts/{id}` shows it (with `keptBotList` and `keepable`), plus `handed` and `unchanged`, Bot ids in the order asked.

**Clients.** The app's service account screen lists the Bots the caller may hand it with checkboxes, up to the room the account has left, and one confirmation names them all and any account each moves from ("All of them are handed over, or none."). One Bot still uses `PUT .../keeper`, so the screen keeps working against servers from before. `botctl bot keep <bot>... <service-account>` sends one request for several Bots, and `PUT .../keeper` for one. The console is unchanged (ADR 0229: it never calls Bot routes).

Nothing else changes: no migration, no new permission or event name, and the access review sees handed Bots as `kept` as before (its digest covers them, ADR 0229).

## Alternatives considered

- **Check the limit before the transaction only.** Two requests racing could both pass and overshoot. Each update keeps ADR 0229's guard instead, inside the one transaction.
- **Skip Bots the caller can't hand and hand the rest.** Option 2 above: a quiet partial result.
- **Allow more than 20 ids and refuse at the limit.** No request over 20 could ever succeed, so it's a plain 400.
- **Taking several back at once.** Letting go only narrows and is already one click per Bot; no one asked for it. It can follow the same shape if needed.

## Consequences

- Handing a set of Bots to automation is one request that does all of it or none, in the app, `botctl` and the API.
- `PUT` and `DELETE /api/bots/{id}/keeper` are unchanged.
- ADR 0272's last follow-up is unchanged and not started: a per-role switch for what teams may give, worth it only if roles gain team permissions a team's owners don't hold.

## Tests

- `kept_bots_http_tests.rs`, on the real router:
  - `an_owner_hands_several_bots_to_their_service_account_at_once`: three Bots in one request (one granted, one moved from another account), repeats counted once; the reply's `handed`, `unchanged`, `keptBotList` and `keepable`; grants removed; each audited with `batch`; the old account released and refused; a second request changes only the new Bot; the account's own token is refused.
  - `several_bots_go_together_or_not_at_all`: a primary Bot, an unseen Bot, an unmanaged Bot and another owner's Bot each stop the request, named, with nothing handed; others' accounts, delegates and a person's id are refused; bad bodies are 400; read-only owners can't; past the limit together none goes, audited with `kept` and `adding`, while one alone fits.
- `db` unit test `several_bots_are_handed_together_or_not_at_all`: the limit counted across the set, rollback on a refusal, grants and moves, Bots already kept, deleted accounts.
- `rbac` (`every_route_is_classified`) and `service_accounts` (`person_only`) cover the route; the router walk test checks it needs credentials and the right role.
- `botctl` unit test: `bot keep` with several Bots.
- Client: `access.test.ts` (`keepersQuestion`), `api.test.ts` (`keepBots`), `ServiceAccountsAdmin.test.tsx` (several Bots in one request, capped at the room left).
