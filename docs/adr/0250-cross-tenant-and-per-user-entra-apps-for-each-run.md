# 0250: Cross-tenant and per-user Entra apps for each run

## Status

Accepted (24 Nov 2026). Part of secrets vault integration in M5, [#55](https://github.com/CG-Labs/superbot/issues/55). Builds on Entra app tokens for each run ([ADR 0213](0213-entra-app-tokens-for-each-run.md)), which left "cross-tenant apps (a multitenant app provisioned in another tenant) and per-user apps" for later, and on the entry options of [ADR 0230](0230-session-policies-and-tags-for-each-run.md) and [ADR 0240](0240-downscoped-gcp-tokens-for-each-run.md).

## Context

With `AZURE_RUN_CREDENTIALS`, each run gets an access token of an Entra app that trusts botd's user-assigned managed identity (or its AKS workload identity) as a federated credential. Two gaps remain.

**Other tenants.** Every token comes from botd's own tenant (`AZURE_TENANT_ID`). Consultancies, MSPs and groups with several tenants keep the resources Bots work on in tenants other than the one botd runs in. Entra supports this without secrets: the app is registered in botd's tenant as **multitenant**, an admin of the other tenant consents to it (which makes its service principal there and gives it roles), and the workload asks the *other* tenant's token endpoint with the same assertion. The federated credential stays on the app's registration at home, with issuer `<authority>/<home tenant>/v2.0`. Another cloud is not supported.

**Each user's own app.** A run gets what the listed app may do, for every Bot owner. AWS and GCP can now scope one role or account per run (ADR 0230, ADR 0240). Entra has nothing like a session policy: an access token carries the app's roles. To keep each user's Bots to their own subscriptions or resource groups, an operator needs an app per user. ADR 0213 refused `{owner}` because Entra chooses app ids (GUIDs), so an app can't be named from a user id; it suggested a mapping file "if asked".

## Options

1. **A tenant per entry (`tenant=`).** One option, checked at startup; the token request goes to that tenant. Chosen.
2. **A tenant setting for all entries** (`AZURE_RUN_TENANT`). Simpler, but a Bot that works in two tenants needs two entries with two tenants. Rejected.
3. **Each user's app from a mapping file (`{owner}` as the app, `apps=<file>`).** botd looks up the owner's app as each run starts. Chosen: the operator keeps one file (generated from their own records, or by whatever makes the apps), no Graph permission is needed, and Entra still checks the trust on every exchange.
4. **Find each user's app in Graph** by a naming rule or tag (`superbot-u-<id>`). botd would need `Application.Read.All`, a request per run, and trust whatever app has the right name; anyone who can create apps could take a user's place. Rejected.
5. **Each user's app in their Key Vault folder** (`AZURE_APP_ID` in `users/<id>`). Users' folders are what an admin sets for a user, so it would work, but it ties run credentials to `SECRETS_USER_FOLDERS` and spreads the access map across secrets that aren't secret. Rejected.
6. **Per-user tenants only** (the user's tenant, one shared multitenant app). Covered by the file: an entry can name the same app for every user, each in their own tenant.

## Decision

### Setting

`AZURE_RUN_CREDENTIALS` entries take two options among their `NAME=accessToken` pairs, as `policy=` and `boundary=` are taken by AWS and GCP entries (the other settings refuse them by name, and an Azure entry refuses theirs):

```sh
AZURE_RUN_CREDENTIALS="<app id> tenant=<other tenant id>; {owner}@storage.azure.com apps=/etc/superbot/azure-apps.json USER_BLOB_TOKEN=accessToken"
```

- `tenant=<tenant>`: a tenant id (GUID) or one of its domains (`contoso.onmicrosoft.com`, lowercase). Never `common` or `organizations`: an app signs in as itself in one tenant. At most once. The token request goes to `<authority>/<tenant>/oauth2/v2.0/token` with the same assertion as always.
- `apps=<file>`: the entry's app is `{owner}` (alone, or `@` a resource); the file maps user ids to apps. The two go together: `{owner}` without `apps=`, or `apps=` with an app id, stops botd.

```json
{
  "u1a2b3c4": "11111111-2222-3333-4444-555555555555",
  "u5d6e7f8": { "app": "66666666-7777-8888-9999-aaaaaaaaaaaa", "tenant": "fabrikam.onmicrosoft.com" }
}
```

A JSON object of at most 1 MiB (about ten thousand users): each key a user id (lowercase letters and digits, as SuperBot makes them), each value an app's client id, or an object with `app` and optionally `tenant` and nothing else. Errors name a user id, never a value. It is read and checked at startup (a bad file stops botd), **and read again as each run that uses it starts**, so adding or taking out a user needs no restart. A user's `tenant` wins over the entry's `tenant=`, which wins over botd's own.

### Each run

As before, entries are taken in order, at the point leases are made. For an `apps=` entry:

- Only runs that get the owner's own secrets use it, as any `{owner}` entry (ADR 0174): a run for someone else doesn't read the file.
- The owner's app takes `{owner}`'s place in the entry, so the request, the lease id, and the audit's `path` all name the actual app (`<app id>@storage.azure.com`), with `userId`.
- **A user the file doesn't name gets no token from it**, and the entry's variables are taken out of the run (`cleared`), so neither botd's environment nor anything else gives them. This is not a failure: such a user has no Azure access through this entry, as a user without a folder secret has none. Other entries still apply.
- **A file that can't be read or checked now** (removed, half-written, wrong shape) refuses the run (`secrets_unavailable`, audited `secret.lease_issued` with `error: "apps"` and the entry's own path), and the leases already made for it are let go. botd never uses the map it read before: a user just taken out must not keep their app.

For any entry with a tenant other than botd's own, `secret.lease_issued` adds `tenant`. Entra's hints follow it: `invalid_client` names the federated credential on the app *at home* (issuer `<authority>/<home tenant>/v2.0`), and `unauthorized_client` from another tenant asks whether the app is multitenant and an admin there has consented. Lifetimes, expiry, release at run end and redaction are ADR 0213's.

### Code

`leases::Narrowing` gains `tenant` and `apps` (the file's path), and `Narrowed` gains `tenant`, which every backend but Azure refuses (the default `issue_narrowed` already refuses a non-empty one; AWS's and GCP's overrides check it too). `leases::AZURE` takes `AZURE_OPTIONS`; `entra_app_ok` accepts `{owner}` as the app. `RunCredentials::issue` reads the owner's app from the file (`user_app`) before the lease is asked for. `azure::KeyVault` overrides `issue_narrowed` and asks the run's tenant. The startup line notes each entry's tenant and file.

## Consequences

- No change unless an entry has `tenant=` or `apps=`.
- One botd can give Bots tokens in tenants other than its own, with no secret in any tenant: register the app as multitenant, have an admin of the other tenant consent to it and grant its service principal roles there. Revoking that consent (or disabling the service principal) stops new tokens in that tenant.
- Each user's Bots can act as their own app. Making the apps, their federated credentials and the file is the operator's: botd needs no Graph permission and makes nothing. Entra allows 20 federated credentials per app; each app needs only the one trusting botd.
- Whoever can edit the file decides which app each user's Bots act as, as whoever can edit `.env` decides the shared ones: keep it with botd's other configuration, writable only by its admins. It names no secret.
- A user taken out of the file gets no token from the next run; tokens already made run out at their expiry, as any Entra token.
- One file read per run that uses it (a small JSON file); Entra requests are unchanged.
- Tested in `server/src/secrets/leases.rs` (the options parsed and checked: tenants that aren't ids or domains, given twice, `{owner}` without `apps=` and the reverse, files of the wrong shape never quoted, refused by the other settings; the backends that can't ask a tenant refusing one; each user's app and tenant in place, a user not in the file getting none and their names cleared) and `server/src/secrets/azure.rs`, against the stand-in Entra, which provisions only some multitenant apps in other tenants: tokens from another tenant by id and by domain with botd's one assertion, the audit's `tenant`, the hints for an app not consented there and one without a federated credential (naming the home tenant), each user's app and tenant from the file, a user not in it and a run for someone else getting no token, an edit applying from the next run, and a file that breaks or goes refusing the runs that need it.
- Ops guide: [docs/ops/cloud-secrets.md](../ops/cloud-secrets.md#another-tenant-or-each-users-own-app).
