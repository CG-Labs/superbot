# 0170: Service accounts granted Bots, and their refusal counts

## Status

Accepted (23 Nov 2026). Seventh slice of [#53](https://github.com/CG-Labs/superbot/issues/53) (M5, "Advanced RBAC"), on top of [ADR 0143](0143-service-accounts.md) (service accounts), [ADR 0152](0152-service-accounts-in-the-apps.md) (service accounts in the apps) and [ADR 0165](0165-service-accounts-in-access-reviews.md) (service accounts in access reviews). Extends [ADR 0017](0017-bot-acls.md) (Bot ACLs) and [ADR 0087](0087-team-accounts-and-machines.md) (teams).

0170 was set aside for this change; other open pull requests hold 0159, 0162, 0163, 0166, 0167, 0169 and 0171.

## Context

A service account reaches Bots the way a person in its team would: a shared Bot of its team, or of no team when it is in none. It can't be granted a private Bot. `PUT /api/bots/{id}/grants/{user}` finds people only, so a person's own CI script can't use their own private Bot without sharing it with everyone. That is the first thing people ask service accounts for.

There was also a gap. ADR 0143 caps a service account's permissions by its owner on every request, but not its Bot access. A team's service account handed to someone outside the team still reached the team's shared Bots, which its owner couldn't. Grants would widen that gap, so it closes first.

Admins investigating a script also had no quick answer to "is this account being refused, and why?". Refusals were in the audit log, but a refused token's `auth.login_failed` didn't say whose it was, and was throttled per address, so it couldn't be counted per account.

## Decision

### Never more than its owner, Bot by Bot

A service account's access to a Bot is the lesser of:

- what its role, team and grants give it, by ADR 0017's rules (as for a person in its team), and
- what its owner can do with that Bot now.

An admin owner caps nothing. A disabled, erased or missing owner, or a deleted account, reaches nothing. The cap is worked out on every request, in lists, in live streams (rechecked every few seconds), for runs it asks for (`SHARED_BOTS=isolated` already caps a run by the asker's access, and the asker's access is now capped), and in the access review. So an owner who loses a Bot, is moved to another team, or is demoted takes their service accounts' access with them at once. Changing a service account's owner or team stops the runs it asked for on Bots it can no longer operate.

This changes one case from before: a team's service account whose owner isn't on the team no longer reaches the team's shared Bots. Accounts made by admins, and by people on their own team, are unchanged.

### Grants

A Bot's owner or an admin grants a service account `viewer` or `operator` with the same routes as for people, naming it by id:

- `PUT /api/bots/{id}/grants/{sa}` `{level}` and `DELETE /api/bots/{id}/grants/{sa}`; `botctl bot grant <bot> <sa> <level>` and `botctl bot revoke <bot> <sa>`.
- As for a person, a grant reaches only the Bot's owner's team (`other_team`, 404 to non-admins).
- A grant is refused (409, `bot.access_refused` with `reason: "service_account_owner"`, the owner and their access) when the account's owner can't do as much with the Bot as the grant would allow. The runtime cap would make such a grant do nothing; refusing it says so when it's made. The message doesn't name the owner.
- A deleted account can't be granted (404).
- `bot.access_granted`, `bot.access_revoked` and `bot.access_refused` carry `kind: "service_account"` for them. A Bot's access view lists them with `kind: "service_account"` and no email.

Grants go when they can no longer reach, as a person's do:

- Deleting the account takes all of them away (`bot.access_revoked`, `reason: "service_account_deleted"`; `grantsRemoved` in the reply and in `service_account.deleted`).
- Moving it to another team, or out of one, takes away those on Bots whose owners it no longer shares a team with (`reason: "team_changed"`).
- When a person leaves a team, grants on their Bots to the team's service accounts go with those to their teammates (`reason: "left_team"`), and the offboarding preview counts them.
- Changing its owner keeps its grants. The cap follows the new owner.

An operator grant lets it operate the Bot within its role and token scopes: send messages, stop runs, mark it read. It never manages a Bot (grants stop at operator), never opens a screen, and never decides an approval: `notify::deciders` leaves service accounts out, so they're never asked to decide.

### Not owning Bots, yet

A Bot's owner decides where it runs (their machine), its plan and Bot limit, the keys and facts it uses, its memory and its OS user on the machine. A service account has none of these. Letting it own Bots needs a rule for whose machine, plan and keys a service account's Bot uses, and touches the machine code throughout. Giving a Bot to one (`PATCH /api/bots/{id}/access` `{owner}`) is refused with 409 and a pointer to grants.

### Refusal counts

Each service account's views (`GET /api/service-accounts` and `GET /api/service-accounts/{id}`, so `botctl service-account show` too) get `refusals`: how often it was refused in the last 30 days, by reason, and when last:

```json
{ "days": 30, "total": 9, "byReason": { "revoked": 5, "role": 2, "service_account": 1, "token_scope": 1 }, "lastAt": 1795406016182 }
```

They're counted from the audit log, so they agree with it and need no new table:

- **Requests refused after its token was taken**: `access.denied` events with the account as the actor (`token_scope`, `role`, `service_account`, `bot_acl`, `delegate_limit` and so on).
- **Its tokens refused**: `auth.login_failed` with `method: "service_token"` for a real token (`revoked`, `expired`, `account_disabled`, `account_deleted`, `owner_inactive`). These now name the account as the event's target, with `serviceAccount` and the token's id as `via` in the details ("token" keys are redacted in the log). They're throttled per address and account rather than per address, so the refusals a throttled event folds in (`unloggedSinceLast`) are that account's, and are counted under its reason. A token no one has (`unknown_token`) names no account and counts against none.

The list also has `refusalDays` (30). `GET /api/service-accounts/{id}` also gets `bots`: each Bot it reaches while enabled, with its access and any grant.

## Alternatives considered

- **Grants without the owner cap, as for people.** A Bot owner could then give someone's script more than that person has, and a team's account handed to an outsider would keep the team's Bots. The cap keeps ADR 0143's rule, "never more than its owner", true of Bots too.
- **Allow any grant and let the cap decide.** It would leave grants that do nothing, and the Bot's owner wouldn't learn why the script can't use the Bot. Refusing at grant time says so, and the cap still applies later.
- **Service accounts owning Bots in this slice.** See above: it needs a "runs as" owner for machines, plans, keys and memory. Grants cover the common case (a person's own script on their own Bot) without it.
- **A counter table for refusals.** Exact without the audit log, but a second record of the same events that can drift from the log. Counting from the log, with throttled sign-in failures folded per account, keeps one source.
- **Counting from the log as it was.** Throttling per address mixes accounts behind one address, and the old events didn't name the account, so per-account counts weren't possible.

## Consequences

- A person can grant their own private Bot to their script without sharing it.
- A service account's Bot access, like its permissions, follows its owner on every request. One case reaches less than before (a team's account owned by an outsider).
- `auth.login_failed` for a real service token has a target and two more detail fields; tools reading it keep working.
- Each list of service accounts reads 30 days of refusal events once. That is one query over a range of the indexed `at` column.
- Still to do for #53: service accounts owning Bots, and a delegate's view of the service accounts they own in the app.
