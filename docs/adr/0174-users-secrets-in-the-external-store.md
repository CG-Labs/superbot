# 0174: Users' own secrets in the external store

## Status

Accepted (23 Nov 2026). Part of secrets vault integration in M5, [#55](https://github.com/CG-Labs/superbot/issues/55). Extends the external store ([ADR 0125](0125-external-secrets-backend-vault.md), [ADR 0136](0136-cloud-secret-managers.md), [ADR 0146](0146-aws-secrets-manager.md)) to per-user secrets ([ADR 0029](0029-per-user-isolation.md), [ADR 0044](0044-client-personal-secrets.md)), which ADR 0125 left in the sealed store.

Numbered 0174 because 0172, 0173, 0175 and 0176 are held by other work.

## Context

With an external store on, Bots' server-wide keys and botd's own secrets come from Vault, Key Vault, Secret Manager or Secrets Manager. Each user's own keys (their Anthropic or GitHub token, which only their Bots get) were still only in botd's sealed SQLite store, saved by the user from the client. Enterprises that run a secrets manager want those keys there too: issued, rotated and revoked by their own tooling, with the manager's access policies and audit, and never typed into another app. Without this, a company had to choose between giving every user's Bots the same team key, or letting people paste personal keys into botd.

The roadmap listed "per-user secrets in the external store, and short-lived credentials per run" as what remains on #55. Per-user folders came first: they need no new sign-in or backend API, work the same on all four backends, and short-lived credentials per run will need a place to put per-user grants anyway.

## Options

1. **Write users' secrets to the external store** when they save them in the client. botd would need write access to the backend, which ADR 0125 ruled out (a compromised botd could then overwrite every key), and a write path for four APIs.
2. **One folder per team** rather than per user. Teams don't map to a person's own keys, and a person can be in several.
3. **A read-only folder per user**, next to the shared ones, filled by the company's own tooling. Chosen.

## Decision

### Folders

With `SECRETS_USER_FOLDERS=1` (off by default; only `1` or `0`), botd also reads **`<prefix>/users/<user id>/<NAME>`**: on Vault and AWS a path, on Key Vault and Secret Manager a name prefix (`<prefix>-users-<user id>-<NAME>`, with Key Vault's `-` for `_`). The user id is botd's (`u` and 8 hex, `operator`, or a service account's `sa…`), shown by `botctl users` and the admin console. Only ids of `a-z` and `0-9`, at most 64 long, name a folder, so an id means the same in every backend, Key Vault's case-blind names included, and can't reach outside its folder. Every id botd makes fits; a user whose id doesn't gets no folder.

A user's folder holds only names a user may save (`check_user_name`): not reserved names, not botd's own (`LINODE_TOKEN`, `SSO_*_CLIENT_SECRET`, ...). Anything else there is ignored, as a name in the wrong shared folder is.

Users' folders aren't listed at startup or in `botctl secrets backend`, which only check the shared folders: there's one per user, and most may not exist. A missing folder is "no secrets", like an empty one.

### Order

For a Bot owned by a user, names come from, first wins:

1. that user's external folder,
2. what that user saved in botd (the sealed per-user store),
3. the server-wide secrets (environment, then the external store's `bots` folder, then the sealed store).

The external folder wins over the sealed copy for the same reason the external store wins over the sealed store for server-wide secrets: an operator who moves keys to the manager shouldn't have them shadowed by an old copy. Another user's folder is never read for a Bot.

### Cache, failing closed, audit, redaction

As for the shared folders: answers and name lists are cached for `SECRETS_CACHE_SECONDS`, per folder; once the cache runs out, a backend that can't answer is an error, and the run is refused with `secrets_unavailable` rather than started without the owner's keys or with the sealed copy under them. Reads that reach the backend are `secret.read` with `scope: users` and `userId`, the list's target is the folder (`users/<id>`), never a value. Values are redacted from that user's Bots (`redact::register_for`), as a value they saved in botd is, not from everyone's.

### In the client and API

`GET /api/me/secrets` (and the admin's `GET /api/users/{key}/secrets`) list the folder's names too, one entry per name, with `store` (`sealed` or the backend) and `saved` (whether the user also saved one in botd). Entries only in the folder have no dates. The client shows them as set by an admin in that store, without Replace; Delete is offered only for a saved copy, which it removes. Saving still goes into the sealed store, and doesn't need the backend. The list fails closed like a run would: `503` while the backend can't answer.

## Consequences

- No change unless `SECRETS_USER_FOLDERS=1` and an external backend is on. With `SECRETS_BACKEND=local` the setting is warned about and does nothing.
- Each Bot owner adds at most one list per `SECRETS_CACHE_SECONDS`, and one read per name. On Key Vault and Secret Manager a list pages through every secret in the vault or project, so keep users' secrets in their own vault or project if there are thousands.
- botd stays read-only. Removing a user (`botctl user delete`, SCIM, erasure) drops what they saved in botd, not their external folder: delete it with the backend's tooling, as with any other credential the company issued.
- The backend's own policies decide who can write each folder. botd's identity needs read and list on `<prefix>/users/*`, as on the shared folders.
- Threat model unchanged: botd's identity can read every user's folder, as it can read every user's sealed secrets with the master key. Run Bots on their own machines so a Bot can't use botd's identity (ADR 0125, ADR 0136).
- Tested in `server/src/secrets/external.rs` (order, isolation between users, ids that can't name a folder, cache, fail closed, audit, redaction, the setting), against the stand-ins for Vault, Secret Manager and Secrets Manager, Key Vault's names, and in the client's `SecretsView` tests.
- Remaining on #55: short-lived (dynamic) credentials handed to each run.
- Ops guides: [docs/ops/vault.md](../ops/vault.md#each-users-own-secrets), [docs/ops/cloud-secrets.md](../ops/cloud-secrets.md#each-users-own-secrets).
