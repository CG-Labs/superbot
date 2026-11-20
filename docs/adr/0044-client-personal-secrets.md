# 0044: Personal secrets in the client, and whose secret a run gets

## Status

Accepted (20 Nov 2026). A follow-up on [#30](https://github.com/CG-Labs/superbot/issues/30) (M3, per-user isolation): the "client UI for `/api/me/secrets`" that [ADR 0029](0029-per-user-isolation.md) deferred. It builds on [ADR 0010](0010-secrets.md) (secrets), [ADR 0012](0012-users-sessions-rbac.md) (roles), [ADR 0017](0017-bot-acls.md) (Bot owners and sharing), [ADR 0019](0019-audit-actors.md) (audit actors), [ADR 0027](0027-expo-primary-hermes-default.md) (the Expo client is the interface) and [ADR 0032](0032-console-admin-only.md) (the console is for admins).

0043 is taken by the separate OS user for Bots on machines (#29, in review), so this is 0044.

## Context

ADR 0029 gave each user their own secrets, sealed per user, that reach only Bots they own: `GET /api/me/secrets`, `PUT|DELETE /api/me/secrets/{name}`. Only `botctl` and raw API calls could use them. The client is the only interface for people who aren't admins (ADR 0027, 0032), so most people had no way to give their Bots an API key of their own.

#30 still lists three items: per-user screens, where shared team Bots run, and this screen. Per-user screens belong with screens on machines (#29, being built now) and team Bots wait on a product decision ([roadmap](../ROADMAP.md), open question 1). This one has no blocker, and it is what lets people use the per-user secrets the server already isolates.

## Decision

### The server: mostly there already

What ADR 0029 built stays as is: the routes need a signed-in person (Bot tokens get 403), listing needs `read` and changes need `write` (so read-only people can see their names but not change them), every query names the caller's user id from their session, and no route takes another user's id except the admin ones. Values go in and never come out; each is sealed with its user and name (`user-secrets/<user>/<NAME>`), so a row copied to another user doesn't open.

This slice adds only what the screen needs:

- **The list says more, still no values.** Each entry is `{ name, createdAt, updatedAt, overrides }`. `createdAt` stays put when a value is replaced. `overrides` is true when a server-wide secret of the same name also reaches Bots, so the screen can say that yours wins for your Bots. It tells the user nothing new: their own Bots see that name in their environment on every run.
- **Audit says whether a value was replaced.** `secret.set` carries `scope: "user"`, `userId`, and now `replaced: true|false`, with the person as actor (ADR 0019). `secret.deleted` is unchanged. Neither ever holds the value.

### The client: a "Your secrets" screen

Everyone signed in gets **Your secrets** in the sidebar (`/secrets`):

- A list of names with when each was saved and last replaced, and a note on names that override the server's.
- **Add a secret**: a name (typed names become environment-variable names: `openai api key` is `OPENAI_API_KEY`) and a masked value with autofill and autocorrect off. Names botd reserves and values over 64 KB are flagged before anything is sent; the server checks again and its message is shown if it refuses.
- **Replace** keeps the name and sends a new value. Typing a name you already have says that saving replaces it.
- **Delete** asks first and says what changes: the Bots stop getting it, or go back to the server's value.
- The value lives only in the text field until it is sent, then is cleared. It is never shown, logged, or kept by the app.
- Read-only people see their names with no add, replace or delete.

Org-wide (server) secrets stay admin-only: `GET|PUT|DELETE /api/secrets` need the admin role, and they are managed in the console's Settings (ADR 0032). Admins can list a user's names and delete them all (`/api/users/{id}/secrets`), for when someone leaves, but can't read or set another person's values.

### Whose secret a run gets: always the Bot's owner

A run gets the server-wide secrets with **its Bot's owner's** own secrets laid on top. It never gets the secrets of the person who asked, unless that person is the owner. This holds for a chat message, a routine, a Bot-to-Bot `ask` or `handoff` (the answering Bot's owner), and runs on the owner's machine (ADR 0036).

| Who asks | Bot | Secrets the run gets |
|---|---|---|
| Ada | Ada's Bot | Server-wide, then Ada's |
| Bea, through sharing or a grant | Ada's Bot | Server-wide, then Ada's |
| Bea's Bot, through `ask` | Ada's shared Bot | Server-wide, then Ada's |
| A routine | Ada's Bot | Server-wide, then Ada's |

Why the owner and not the asker:

- **It follows ADR 0029.** A shared Bot runs where its owner's computer is, in the owner's folder, as the owner's Unix account (ADR 0037). Sharing means others may use it, not move it (ADR 0017). The keys go with the folder.
- **The asker's key would be exposed.** The owner controls the Bot's instructions, tools, memory and folder. Giving Bea's key to Ada's Bot would let Ada, or anything her Bot writes to her folder, keep Bea's key. With owner-only resolution, using someone's shared Bot never hands them your keys.
- **Routines have no asker**, so an asker rule would need a fallback anyway.
- **One rule is easy to explain.** The screen says it: your secrets reach only Bots you own, including when others use them.

The trade-off: an owner's key pays for what people they share with ask for. To use your own key, use your own Bot. Per-user screens and team Bots (still open on #30) don't change this rule; a team-owned Bot would get the team owner's secrets.

Order, first wins: the owner's own secret, then a server-wide one (environment, then sealed; ADR 0010). Names botd itself uses can't be saved by people at all.

## Consequences

- Everyone can give their own Bots API keys from the app, with no admin and no `botctl`.
- `GET /api/me/secrets` adds `createdAt` and `overrides`; older clients ignore them, and the new client copes with older servers that send neither.
- `secret.set` with `scope: "user"` adds `replaced`.
- A cross-user test on the real router: two people save the same name, replace, delete, and add a server-wide secret of that name; each sees only their own, their Bots get only their own (or the server's after deleting), nobody can delete the other's, read-only people can list but not change, and no value reaches a response or the audit log.

## Deferred

- **Per-Bot secrets** (a key for one of your Bots, not all of them): not needed yet.
- **Telling the asker whose keys a shared Bot uses** in its details. Today only this screen and the docs say it's the owner's.
- **Expiry and rotation reminders** for personal secrets.
