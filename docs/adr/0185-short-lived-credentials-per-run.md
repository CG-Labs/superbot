# 0185: Short-lived credentials for each run

## Status

Accepted (23 Nov 2026). Part of secrets vault integration in M5, [#55](https://github.com/CG-Labs/superbot/issues/55). Builds on Vault as the external store ([ADR 0125](0125-external-secrets-backend-vault.md), [ADR 0159](0159-vault-kubernetes-and-jwt-sign-in.md)) and users' folders ([ADR 0174](0174-users-secrets-in-the-external-store.md)), which listed short-lived credentials per run as what remains on #55.

## Context

Every secret a Bot gets so far is static: the same AWS key or database password for every run, until someone rotates it. A key a Bot leaks into a log, a commit or a prompt-injected request works until then, often for months. Enterprises that run Vault already issue short-lived credentials for this: Vault's AWS, database, GCP, Azure, Kubernetes and other secrets engines make a new credential on each read, under a lease that Vault revokes at its TTL or on request.

What a run needs is the same idea scaled to a run: a credential made as it starts, that ends when it ends.

## Options

1. **Store a TTL with static secrets** and rotate them often. Rotation is the backend's job and still gives every run in a window the same value.
2. **Teach each harness or adapter** to fetch credentials. Harness-specific, and the Bot would then hold a Vault token able to make more.
3. **botd asks Vault for a lease as each run starts**, gives the run the lease's fields as environment variables, and revokes the lease when the run ends. Chosen: harness-agnostic, the Bot never holds a Vault token, and the lease's own TTL bounds it if botd can't revoke.
4. **The cloud managers' equivalents** (AWS STS, GCP service account impersonation, Azure managed identities per run). Each is its own API and trust setup; Vault's engines already front all three. Left for later, behind the same `Issuer` trait.

## Decision

### Setting

`VAULT_RUN_CREDENTIALS` (off when empty; only with `SECRETS_BACKEND=vault`, warned about and ignored otherwise) lists paths and the variables their fields become. Entries are separated by `;` or new lines; each is a path, then `NAME=field` pairs separated by spaces:

```sh
VAULT_RUN_CREDENTIALS="aws/creds/bots AWS_ACCESS_KEY_ID=access_key AWS_SECRET_ACCESS_KEY=secret_key AWS_SESSION_TOKEN=security_token; database/creds/u-{owner} PGUSER=username PGPASSWORD=password"
```

- Paths are Vault paths (letters, digits, `. _ -` and `/`), read with `GET` in `VAULT_NAMESPACE` with botd's own token, so they work for every engine whose credentials endpoint answers a read.
- `{owner}` stands for the Bot owner's id, so a role per user (`database/creds/u-{owner}`) gives each user's Bots their own database user. Like users' folders, only ids of `a-z` and `0-9` up to 64 long are put into a path. Paths with `{owner}` are only read for runs that get the owner's own secrets: a teammate's run of a shared Bot under `SHARED_BOTS=isolated` (ADR 0046) gets only the shared roles.
- Names pass the same check as any secret a Bot gets (`check_name`), and appear once in the setting. At most 16 paths.
- Settings are checked at startup; a bad one stops botd with the reason. No lease is made at startup: that would make a credential nobody uses.

### A run's leases

As a run starts, after it has its place and slot and its other secrets are final, botd asks for one lease from each path. The run's environment gets each named field, over the static secrets of the same name (a fresh credential beats a stored one). A field that is null or empty (AWS's `security_token` for an IAM user) takes that name out of the run altogether, saved or server-wide value included: an old `AWS_SESSION_TOKEN` next to fresh IAM user keys would make every request fail. For the same reason the names the setting lists are kept from everything botd starts (`adapters::withhold`, ADR 0077), so a run never inherits one from botd's own environment; it gets them only from its lease. A field the answer doesn't have is an error: probably a typo, and a run without the variable would fail in a confusing way later.

The leases are held in a guard for the rest of the run and revoked (`PUT sys/leases/revoke/<lease id>`, the form a policy can limit to the leases of given paths) when it drops, so they end whether the run finishes, fails, times out, is stopped, or is refused late by a hook. Revoking runs on its own thread, so a slow Vault doesn't hold up the next run.

Leases are made last, after any wait for a slot, so a queued run never starts with a credential that was made long before.

### Failing closed

Like the rest of the external store: if a lease can't be made (Vault down, policy refuses, no engine at the path, an answer that isn't a lease, a missing field), the run is refused with `secrets_unavailable` and the Bot says the secret store can't be read. Leases already made for that run are revoked.

A plan's model provider key (a tier endpoint's `keySecret`, ADR 0077) may be one of these names. The plan's check that its provider has a key, made before any lease, counts a name the run's leases will give; once they are made, a provider key whose field came back empty refuses the run the same way, rather than starting it without a key or with a saved one under it.

If a lease can't be revoked (Vault down, botd stopped mid-run), it lasts until its TTL. So **the Vault role's TTL is the longest a credential can outlive its run**: set it a little over the longest run (`RUN_TIMEOUT_MINUTES`, 60 by default), not a day. Renewing leases for very long runs is left out; a role with a long `max_ttl` and a short `default_ttl` isn't needed while botd revokes at run end.

Vault also revokes a token's leases when the token itself ends, whatever their TTL, and botd's AppRole, Kubernetes or JWT token lives about an hour; logging in again later doesn't extend the token that made a lease. So before each lease botd checks the token it will use (`auth/token/lookup-self`, in Vault's default policy). If the token ends before the run could (`RUN_TIMEOUT_MINUTES` plus five minutes), botd renews it to that (`renew-self`), else logs in again for a new token, else refuses the run (`secrets_unavailable`, naming the token's max TTL). A token that never ends, such as a root token, needs neither. Renewing to the run's length, once per lease, needs no background renewer and leaves the token ending soon after its last run.

### Audit and redaction

- `secret.lease_issued` for each lease made or refused: target the path (`secret_lease`), the Bot, `store`, `path`, `names`, `leaseId`, `ttl`, `renewable`, and `userId` for a path with `{owner}`. Failures carry the error's kind and, for missing fields, which.
- `secret.lease_revoked` for each revocation, with the lease id, or the error.
- Never a value. The lease id is logged so an operator can revoke by hand (`vault lease revoke <id>`) when botd couldn't.
- Values are redacted from everyone's text while the lease lives: Vault made them, no user chose them, so redacting them everywhere can't be used to erase other people's words (the reason users' own values are redacted only from their Bots, ADR 0029). Each value is counted across live leases: once Vault confirms the revocation of the last lease that has it, it is forgotten, so the redactor doesn't grow with every run. A value botd already knew before a lease gave it (a static secret, say) is never forgotten this way, and one whose revocation failed stays redacted.

### Code

`secrets::leases` holds the setting, the `Issuer` trait (issue and revoke), `RunCredentials` and the `Leases` guard; `vault::Vault` implements `Issuer` sharing its client, token and runtime with the store. The runner asks `leases::for_run` once per run and holds the guard. Nothing is harness-specific.

## Consequences

- No change unless `VAULT_RUN_CREDENTIALS` is set with `SECRETS_BACKEND=vault`.
- botd's Vault policy needs `read` on each listed path (a glob such as `database/creds/u-*` for one with `{owner}`) and `update` on `sys/leases/revoke/<path>/*` for each, so it can revoke only those leases. botd's token can then make credentials for every listed role, as it can read every user's folder: run Bots on their own machines so a Bot can't use botd's token (ADR 0125).
- Each run makes one Vault request per path as it starts and one as it ends; Vault's own audit device has its side.
- The names given out are ordinary environment variables in the run. A Bot can still leak them while the run lasts; what changes is that they stop working when it ends.
- Leases from a run botd didn't see end (crash, kill -9) end at their TTL; botd doesn't keep lease ids across restarts.
- Tested in `server/src/secrets/leases.rs` (setting, a new lease per run, revoked when the guard drops, empty fields cleared, names withheld from inheritance, owner paths, fail closed with revocation, failed revocations, redaction counted across leases and kept for values botd already knew), against the stand-in Vault in `vault.rs` (the HTTP API, a KV path or missing engine refused, settings), and on the real router in `run_credentials_http_tests.rs` (a run gets the value, its reply is redacted, an empty field takes out a saved value of that name, the lease is revoked after, a lease that can't be made refuses the run).
- Ops guide: [docs/ops/vault.md](../ops/vault.md#short-lived-credentials-for-each-run).
