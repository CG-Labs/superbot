# 0291: An admin can refresh the external secrets cache, so a rotation lands at once

## Status

Accepted (25 Nov 2026). Part of secrets vault integration in M5, [#55](https://github.com/CG-Labs/superbot/issues/55). Adds to the cache that every external store shares: HashiCorp Vault ([ADR 0125](0125-external-secrets-backend-vault.md)), Azure Key Vault and GCP Secret Manager ([ADR 0136](0136-cloud-secret-managers.md)), AWS Secrets Manager ([ADR 0146](0146-aws-secrets-manager.md)) and users' folders ([ADR 0174](0174-users-secrets-in-the-external-store.md)).

Numbered 0291 because it is the number reserved for this slice; 0290 and 0292 to 0294 are held by parallel work.

## Context

botd caches each answer from the external store for `SECRETS_CACHE_SECONDS` (300 by default, up to a day). ADR 0125 chose this so a rotation needs no restart, and so botd rides out short outages. But the guide's advice for a rotation is to wait. That's fine for a routine rotation. It's wrong for the case rotations matter most: a key has leaked, the security team has rotated it in Vault, and botd keeps handing the old one to every Bot run until the cache runs out. With a cache of an hour, that's an hour of runs with a key the provider may already have revoked, failing in ways that look like the provider's fault. The only way to cut it short was to restart botd, which stops every running Bot.

There is a second gap. Some of botd's own secrets are read once at startup into settings (the Linode token, the Incus client key, metrics and backup store keys, Stripe's keys). For those, the cache doesn't matter: a rotation reaches them only on restart. The guide listed them by hand, and nothing told an admin which of the names they just rotated were among them.

ADR 0159 rejected per-secret version pinning because it turns a rotation into a config change. Event-driven invalidation (Vault's event notifications, Event Grid, Pub/Sub, EventBridge) would land rotations automatically, but it's four integrations, each needing an inbound path or a subscription, for something an admin does a few times a year.

## Options

1. **A shorter cache.** Every Bot run reads the backend, and a backend outage stops runs sooner. It changes the trade-off for every day to fix one.
2. **Restart botd.** Works today. Stops running Bots and sessions, and still doesn't say whether the new value arrived.
3. **Drop the cache on request.** Simple, but the admin learns nothing until the next run fails or works, and the next reads all land at once.
4. **Read the cache again on request, and report what changed.** Chosen. One admin action rotates the value everywhere botd caches it, and says whether it took.

## Decision

### Asking for it

- `POST /api/secrets/refresh` (admins only, like the rest of `/api/secrets`), body `{"names": ["OPENAI_API_KEY", ...]}` or nothing.
- `botctl secrets refresh [NAME ...]`. It exits non-zero when any read failed or a restart is needed, so a rotation script can check it.
- With `SECRETS_BACKEND=local`, it answers 409: the environment and the sealed store have no cache.

### What it reads

- **Everything** (no names): every answer in the cache, including "not there" answers and users' folders, every name botd's startup settings read from the external store, and every cached folder list plus the `bots` and `server` folders.
- **Some names**: those names in every folder that has them cached (so a user's own copy of `OPENAI_API_KEY` too), or, if none does, in the name's own shared folder. At most 100 names, each one the external store may answer. Reserved names are refused, as is any name that isn't an environment variable name. The folders are listed again too, so a newly added name reaches Bots at once.
- Reads go through the same path as any other: each is audited as `secret.read`, its value registered with the redactor, and the answer cached afresh. The old value stays registered, so it is still masked if it turns up in a Bot's output.
- Up to 8 reads run at once, on plain threads, each bounded by the client's timeouts. One refresh runs at a time; a second gets 409.
- A read already in flight when a refresh starts (a Bot run's, read before the rotation) still answers its caller, but doesn't cache its answer. Each refresh bumps an epoch before it reads; a value or folder list is cached only if no refresh started since its read began. Otherwise a slow read of the old key could land after the refresh and give it a fresh cache lifetime.

### Fail closed

A read the backend can't answer leaves nothing cached for that name, exactly as when the cache runs out: the next run that needs it is refused with `secrets_unavailable` until the backend answers. A refresh never keeps the old value because the new one couldn't be read. That's the point of the action: an admin refreshing during an outage is choosing not to use the old value. The report says so.

### What it says

For each name: `changed`, `unchanged`, `added` (was cached as not there), `removed` (was cached with a value, now not there), `found` or `not_found` (nothing cached to compare), or `unavailable`. With its scope and, for a user's folder, the user id. For each folder: whether it was listed, how many names it has, and which names came or went. Values are compared in memory only. The report and the audit log never carry a value, a length or a digest of one.

### Settings read at startup

botd's startup settings read the external store through a wrapper (`external::Startup`) that keeps each answer it gave, in memory, for the life of the process. A refresh reads those names again and marks one `restart: true` when the backend's answer is no longer the one startup read, including a name that was missing at startup and is set now. The report lists them, and botctl says to restart. So the guide's hand-kept list is no longer the only way to know. Startup names whose answer hasn't changed aren't flagged.

The copy is no new exposure: the settings that read it hold the same value in the same process. It is zeroed on drop like every other value.

### Audit

`secret.cache_refreshed`, by the admin, target the store kind (`secret_store`, `vault`, ...), outcome failure if any read or list failed. Details: the names asked for (or null for all), counts of each result, the names that changed, were added or removed, failed or need a restart (with scope and user id, at most 100, then a count of the rest), the names needing a restart, and how many folders were listed or failed. Unchanged names are counted, not listed.

## Consequences

- A leaked key rotated in the external store stops reaching new Bot runs within seconds of `botctl secrets refresh NAME`, with no restart. The admin is told which of botd's own settings still hold the old value and need one.
- Runs already going keep the environment they started with. Leases and tokens made for each run (ADR 0185, ADR 0194, ADR 0203, ADR 0213) are untouched: they're made per run, not cached. To cut off a leaked key in a running Bot, revoke it at the provider, which the rotation usually does.
- A full refresh asks the backend once for each cached answer: about the number of names times the users whose Bots ran within the cache time. The cache prunes old answers as new ones come in, so this stays near what a cache expiry would cost.
- The restart flag covers what botd's startup settings read through the external store. A component that copies a value later, through `secrets::global()`, isn't tracked; the ones listed in the guide read at startup.
- Not in this slice, each for an issue of its own: a button in the console, refreshing from a backend's own change events, and per-secret version pinning.
- Tested in `server/src/secrets/external.rs` against the in-memory backend: a read and a folder list paused across a rotation and a refresh never cache over it; changed, unchanged, added, removed and new names in shared and users' folders, read once each with nothing past the refresh read again; new and old values both redacted; named refreshes reading only those names; refused names, too many names and a second refresh at once asking nothing; a backend down failing closed with nothing cached and the failures audited; startup answers flagged only when they changed, including a name set after startup, with no value in the report or audit. In `server/src/main.rs`: 401 and 403 for others, 409 when local, 400 for bad bodies, and the change reaching the cache and the audit log with no value.
- Ops guides: [docs/ops/vault.md](../ops/vault.md#rotating-a-value-now) and [docs/ops/cloud-secrets.md](../ops/cloud-secrets.md).
