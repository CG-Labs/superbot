# 0239: Owners see and stop their own service accounts

## Status

Accepted (24 Nov 2026). Fourteenth slice of [#53](https://github.com/CG-Labs/superbot/issues/53) (M5, "Advanced RBAC"), on top of [ADR 0143](0143-service-accounts.md) (service accounts), [ADR 0152](0152-service-accounts-in-the-apps.md) (service accounts in the apps), [ADR 0182](0182-delegates-own-service-accounts.md) (a delegate's own service accounts) and [ADR 0229](0229-handing-bots-to-service-accounts.md) (handing Bots to service accounts).

0239 was set aside for this change; other open pull requests hold 0240 to 0243.

## Context

A service account acts with its owner's access: every request is capped by what the owner holds now (ADR 0143). But only people who hold `users.manage` could see one. Every service account route was classified `users.manage`. Two kinds of owner were left out:

- **Someone an admin made the owner.** An admin can make an account and give it to any active person (ADR 0143, ADR 0182). That person lends their access to it, yet couldn't see it, its tokens, when they were last used or from where, or the Bots it reaches.
- **A delegate who lost `users.manage`.** Their accounts keep working with whatever access they still hold. They could no longer see them or revoke a token they think has leaked.

In both cases the only way to stop an account was to ask an admin. ADR 0229 named this as a follow-up: members who own service accounts should be able to open their account's page.

## Decision

### What an owner may do

Anyone signed in, read-only people too, may do these things with the live service accounts they own:

- **See them.** `GET /api/service-accounts` lists the ones they own. `GET /api/service-accounts/{id}` returns its tokens (never their secrets), the Bots it reaches, the Bots it keeps and what it can use today. `GET /api/service-accounts/{id}/tokens` lists its tokens.
- **Revoke a token.** `DELETE /api/service-accounts/{id}/tokens/{token}`. It stops at once.
- **Disable it.** `PATCH /api/service-accounts/{id}` with exactly `{"status": "disabled"}`. Its tokens stop, its runs stop and its routines pause, as when an admin disables it.

Each of these only narrows what acts with the owner's access, so the owner can do it without asking. It's audited as before (`service_token.revoked`, `service_account.disabled`), naming the owner.

### What stays with admins and delegates

Making accounts, making and rotating tokens, enabling, renaming, changing the role, team or owner, and deleting still need `users.manage` (an admin, or a delegate for the ones they own). Each one makes a new secret, widens access, or undoes a decision an admin made:

- **Enabling.** An admin may have disabled it on purpose. Letting the owner switch it back on would undo that.
- **Making or rotating tokens.** A new secret is new access, even within the same scopes.
- **Deleting.** It's for good, and releases the Bots it keeps (ADR 0222). Disabling stops it just as well and can be undone by an admin.

An owner without `users.manage` who sends anything else in a `PATCH` (another field, `status: "active"`, or `disabled` with another field) gets 403. The refusal is logged as `access.denied` with `reason: "owner_limit"`, `limit: "service_account_change"` and the `fields` sent. The other routes stay classified `users.manage`, so the middleware refuses them as before.

### Someone else's

For a caller without `users.manage`, another person's service account is 404 on every route, so they can't learn which ids exist. The refusal is logged as `access.denied` with `reason: "owner_limit"` and `limit: "service_account_owner"`. Delegates still get 403 with `delegate_limit`, as in ADR 0182.

### How it's checked

The five routes above are now classified `account` instead of `users.manage`. Every handler checks the caller again:

- **Bots are refused (403).** A Bot's run acts for its owner but owns nothing here.
- **Service accounts are refused** by `person_only` before any handler runs, as before.
- **Managing** means holding `users.manage` (`Caller::can`), so admins and delegates are unchanged. `GET /api/service-accounts` adds `manage`: false for an owner who may only see and stop theirs. They get `choices: null`, since they give nothing.

### Where it shows

- `GET /api/state` (`me`) and `GET /api/auth/me` add `ownedServiceAccounts`: how many live service accounts the person owns. Service accounts and Bots get none. Changing an account's owner sends a `resync`, so an open app picks up the new count.
- **App.** The sidebar offers **Your service accounts** to anyone who manages service accounts or owns one. For an owner who doesn't manage them, the screen lists theirs. There's no **New service account** button. The page shows the account, what it can use today, its tokens with **Revoke**, and **Disable**, with a note that it acts with their access. There's no new token, rotate, settings, enable or delete. A disabled one says to ask an admin to enable it. They can still hand it their Bots and take them back there, as from the Bot's Sharing section (ADR 0229).
- A server from before this change sends no `manage`. The app then treats the caller as managing, since only managers got a list.
- `botctl service-accounts`, `service-account show`, `service-account disable` and `service-account token list|revoke` now work for any owner. The commands haven't changed.
- The console stays admin-only (ADR 0032).

## Alternatives considered

- **Let owners do everything delegates do.** An admin who gives an account to a read-only person, or takes `users.manage` from a delegate, means for them not to manage it. Seeing it and stopping it are safe either way. Widening it isn't.
- **Let owners enable and delete too.** Enabling can undo an admin's decision. Deleting is permanent and releases kept Bots. Disabling stops everything, and an admin can follow up.
- **A separate read-only "my service accounts" route.** It would duplicate the views, and could drift from them. The same routes with a narrower check keep one code path, and `botctl` works unchanged.
- **Return 403 for others' accounts, as for delegates.** Before this change, members got 403 whatever the id. Now that the route answers them, 403 for an existing id and 404 for a missing one would show which ids exist. Delegates already saw their limits, so their answer is unchanged.
- **Leave the sidebar entry to a probe of `GET /api/service-accounts`.** That would be one more request on every load for everyone. A count in `me` costs one indexed query.

## Consequences

- Everyone who lends their access to a service account can see what it does with it, and stop it, without an admin.
- `GET /api/service-accounts` and the other four routes answer every signed-in person, not just managers. People who own none get an empty list, and 404 for any id. Bots get 403.
- Each `GET /api/state` and `GET /api/auth/me` from a person counts their live service accounts: one query.
- Still to do for #53: nothing from its scope. A follow-up would be handing several Bots to an account in one request.
