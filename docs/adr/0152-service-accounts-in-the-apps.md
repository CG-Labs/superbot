# 0152: Service accounts in the apps

## Status

Accepted (22 Nov 2026). Fifth slice of [#53](https://github.com/CG-Labs/superbot/issues/53) (M5, "Advanced RBAC"), on top of [ADR 0143](0143-service-accounts.md) (service accounts). Follows [ADR 0132](0132-custom-roles-in-the-apps.md) (custom roles in the apps), [ADR 0021](0021-admin-portal.md) (the admin portal in the app) and [ADR 0032](0032-console-admin-only.md) (the admin-only console).

## Context

ADR 0143 put service accounts on the server: `/api/service-accounts` and `botctl service-account`. Admins could only manage them from a shell. They need to see each account, what it can use today, its tokens and when each was last used, and to make, rotate and revoke tokens without copying a secret through a terminal.

## Decision

### Where they're managed

- **The app** (`/app/`) gets a **Service accounts** screen next to Roles: the list (role, live tokens, last use, disabled, owner inactive), and for each account what it can use today, its tokens, a new-token form, its settings (name, description, role, team, owner), and Disable, Enable and Delete. Making one asks for a name, description, role (read-only, member or a custom role) and where (across the server or a team), and makes its first token with everything it holds unless unticked.
- **The console** (`/console/`) gets a **Service accounts** tab with the same: a form to make or edit one, and a card per account with its tokens and a new-token form.

Both call the ADR 0143 API and nothing else. The server still checks every role, team, owner, scope and day limit; the apps show its refusals as they come, such as an account that would hold more than its owner.

### Admins only

Both apps show service accounts to admins only, as they do roles. The console is admin-only already. The app shows the screen and its sidebar entry when `GET /api/auth/me` lists `admin`, and says "Only admins" otherwise. Delegates with `users.manage` can still manage the ones they own through the API and `botctl`; the app leaves them out so that the screen never shows a partial list as if it were all of them.

### Tokens are shown once

A new or rotated token's secret is in the reply to that request only. The app shows it in a panel with Copy (the share sheet on phones) and Done; the console shows it in the shown-once dialog it uses for sign-in codes and SCIM tokens. Done, picking another account, or closing the screen forgets it. Neither app writes it to storage, logs or a URL. Lists show a token's preview (`sbsa_…` and its last four characters), name, scopes, state, expiry, and last use with the address it came from.

### What the forms offer

- **Roles**: read-only, member, and the custom roles `GET /api/roles` lists. Never admin. With a team, a custom role applies only in that team; a read-only one is refused there, as the server does.
- **Scopes**: only the permissions the account holds (its `permissions` and `teamPermissions`), from the server's `scopes` list. None ticked means everything it holds. `account` isn't offered: every token has it.
- **Expiry**: 7, 30 and 90 days and a year, cut to the server's `maxDays`, with its `defaultDays` picked. There is no "never".
- **Rotate**: the old token stops now, or after an hour or a day; the new one gets a fresh expiry. Only a live token not yet replaced can be rotated. A replaced token shows until when it still works.

### Confirmations

The apps ask before disabling an account (its tokens and runs stop), deleting one (for good), revoking a token, and, in the console, rotating with no overlap (the old token stops at once). Enabling and making tokens don't ask.

## Alternatives considered

- **Show delegates their own service accounts in the app.** Possible from the same API, but the screen sits with the other admin screens, and a delegate's list would look like everyone's. `botctl` covers them until there is a page for delegates.
- **Keep a minted token until the screen closes, so it can be copied again.** It would linger in memory and on screen behind other work. Done forgets it; rotating is one tap if it was lost.
- **Work out what a token could use in the app.** The server already sends `effective`, capped by the owner; the apps show it rather than copy the rules.

## Consequences

- Admins can manage service accounts and their tokens in either app, without the API or a shell.
- The app and the console call only ADR 0143's routes; no server change was needed.
- Still to do: letting a service account own Bots or be granted one, listing them in access reviews, per-account refusal counts, and a delegate's view of their own service accounts in the app.
