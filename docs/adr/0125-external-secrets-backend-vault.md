# 0125: An external secrets backend, HashiCorp Vault first

## Status

Accepted (22 Nov 2026). Part of secrets vault integration in M5, [#55](https://github.com/CG-Labs/superbot/issues/55). Fills the seam [ADR 0010](0010-secrets.md) left for M5 ("Vault, Azure Key Vault, or GCP Secret Manager is one more `SecretStore` in the list"). Builds on per-user secrets ([ADR 0029](0029-per-user-isolation.md)) and master key rotation ([ADR 0096](0096-master-key-rotation.md)).

0118 is the highest number on `main`; 0119 to 0124 are held by other open PRs, so this one takes 0125.

## Context

botd reads secrets from two places: the environment (`NAME` or `NAME_FILE`) and the sealed store in SQLite, encrypted under the master key ([ADR 0010](0010-secrets.md)). Enterprises already keep their keys in a secrets manager, with its own access policies, rotation and audit trail, and don't want copies in a `.env` or in botd's database. #55 asks for Azure Key Vault, GCP Secret Manager and HashiCorp Vault.

What botd needs from one, whatever it is:

- the server-wide secrets Bots get (`OPENAI_API_KEY`, `GITHUB_TOKEN`, ...), and botd's own (`server_secret` names such as `LINODE_TOKEN`, SSO client secrets, `SMTP_PASSWORD`, and Stripe's keys), kept apart so the manager's policies can tell them apart;
- rotation picked up without a restart;
- a failure that can't hand a Bot the wrong key, or a key the operator meant to replace;
- a record of what was read;
- no change for anyone who doesn't turn it on.

## Options

1. **Each component asks the manager itself** (billing for Stripe, the control plane for Linode, ...). Every component would grow a client and a cache; rejected.
2. **Sync the manager into the sealed store** on a timer. One more copy of every value, on disk, under a different key; a deleted secret lingers until the next sync. Rejected.
3. **A read-only `SecretStore` in front of the sealed store**, asked on demand with a short cache, generic over a small `Provider` trait so each manager is just a client. Chosen.

Vault comes first: it is self-hostable, the most common choice among self-hosters (OpenBao speaks the same API), and testable against a stand-in with no account. Its KV v2 engine and the token and AppRole methods cover most deployments; Kubernetes, JWT and cloud IAM sign-in can follow as more `Auth` cases.

## Decision

### Configuration

`SECRETS_BACKEND` is `local` (the default: the environment and the sealed store, as before) or `vault`. With `vault`:

| Setting | Default | Meaning |
|---------|---------|---------|
| `VAULT_ADDR` | (required) | `https://host:port`; plain `http://` only to loopback (a local Vault Agent) |
| `VAULT_NAMESPACE` | none | Sent as `X-Vault-Namespace` (Vault Enterprise, HCP) |
| `VAULT_CACERT` | system roots | PEM of a private CA for Vault's certificate |
| `VAULT_AUTH` | `token` | `token` or `approle` |
| `VAULT_TOKEN` / `VAULT_TOKEN_FILE` | | Token auth; the file is read again whenever Vault refuses the token, so Vault Agent can rotate it |
| `VAULT_ROLE_ID`, `VAULT_SECRET_ID` (each also `_FILE`) | | AppRole auth |
| `VAULT_APPROLE_MOUNT` | `approle` | |
| `VAULT_KV_MOUNT` | `secret` | The KV v2 mount |
| `VAULT_KV_PREFIX` | `superbot` | Folder under the mount |
| `VAULT_KV_FIELD` | `value` | Field holding the value |
| `SECRETS_CACHE_SECONDS` | `300` | 0 to 86400 |

Each secret is its own KV v2 secret: `<mount>/<prefix>/bots/<NAME>` for server-wide secrets that reach Bots, `<mount>/<prefix>/server/<NAME>` for botd's own. A name is only ever read from its own folder (`external::scope_of`), so a Bot secret put in `server/`, or `LINODE_TOKEN` put in `bots/`, is ignored, and a Vault policy can give botd's operators `bots/` without `server/`. Names botd reserves (`AUTH_PASSWORD`, `SUPERBOT_*`, `PATH`, the Vault credentials themselves, ...) are never read from Vault.

### Where it sits

Stores are asked in order, first answer wins: **environment, then Vault, then sealed**. The environment still wins, so an operator can override one value on one host; Vault shadows the sealed store, so a key moved to Vault replaces the copy saved with `botctl secret set` (the listing shows it as shadowed by `vault`). Writes still go to the sealed store; the external store is read-only, because botd shouldn't hold a token that can change the organisation's secrets.

Everything botd reads at startup (Stripe's keys, `LINODE_TOKEN`, `INCUS_CLIENT_KEY`, `TURNSTILE_SECRET`, `METRICS_TOKEN`, backup store keys, ...) is read through the environment and then Vault; later reads (SSO client secrets, the notifier's, Bots' keys at each run) go through `secrets::global()` with the same order.

Per-user secrets ([ADR 0029](0029-per-user-isolation.md)) stay in the sealed store in this slice.

### Cache and fail closed

`ExternalStore` caches each value (and each "not there") and each folder's name list for `SECRETS_CACHE_SECONDS`. A rotation in Vault reaches botd within that time, with no restart. Values read are registered with the redactor straight away, so they are scrubbed from chats, events and the audit log like every other known secret.

Failures fail closed:

- At startup, botd lists both folders and refuses to start if Vault can't be reached or refuses it.
- Once a cached answer is older than the cache time, a Vault that can't answer (down, sealed, a refused token, an unexpected reply) is `Error::Unavailable`. The cached value is dropped, not served stale, and the next store is **not** asked, so a sealed value Vault was meant to replace never comes back.
- A Bot run whose secrets can't be read doesn't start (checked again just before a run on a user's machine, which inherits nothing from botd, in case Vault went down while it waited for a slot): the Bot says so in the chat, and `bot.run_refused` is audited with reason `secrets_unavailable`. Everything else that hands out Bots' environment (harness logins on machines, runs elsewhere) gets none of the server-wide secrets rather than some of them.
- `GET /api/secrets` answers 503.

### Audit

Every read that reaches Vault, and every failure, is a `secret.read` event: actor `system` / `secrets`, target the secret's name (or the folder, for a list), and details `store`, `scope` (`bots` or `server`), `op` (`read` or `list`), `found`, and the error's kind. Never the value. Cache hits aren't audited, so the log grows with the cache time and the number of names, not with runs. AppRole logins are `secret.vault_login`. Reads can happen before the database is open, or while a caller holds it, so events wait in a bounded in-memory queue (10,000) that botd writes every two seconds; if it ever overflows, the oldest are dropped and `secret.read_events_dropped` says how many. Vault's own audit device records the same reads from its side.

### Talking to Vault

A `Vault` client (reqwest, rustls, 5 s to connect, 10 s per request, no redirects, so a token is never sent anywhere else) runs on a thread of its own with its own small runtime: `SecretStore::get` is synchronous and is called from inside botd's async code, where blocking on a runtime would panic. A caller on one of botd's runtime workers waits with `block_in_place`, so its other tasks move to another worker and a slow Vault never stalls requests, heartbeats or timers. A reply that isn't KV v2's shape is an error, not "not there", so it can't uncover the sealed copy. AppRole tokens are renewed by logging in again two thirds of the way through their lease, and once more whenever Vault refuses the token. A token file is read again whenever Vault refuses the token.

### The provider trait

```rust
pub trait Provider: Send + Sync {
    fn kind(&self) -> &'static str;
    fn describe(&self) -> String;
    fn read(&self, scope: Scope, name: &str) -> Result<Option<Zeroizing<String>>, Error>;
    fn list(&self, scope: Scope) -> Result<Vec<String>, Error>;
}
```

Folders, caching, fail-closed behaviour, redaction and audit live in `ExternalStore`, so Azure Key Vault (secrets named `superbot-bots-<name>`, managed identity or a service principal) or AWS Secrets Manager (`superbot/bots/<NAME>`, an instance role) are a client each and one more `SECRETS_BACKEND` value.

### Keeping Vault's credentials from Bots

`VAULT_TOKEN`, `VAULT_ROLE_ID` and `VAULT_SECRET_ID` are reserved names: they can't be saved as Bot secrets and aren't listed or handed to Bots. They and their `_FILE` variables are removed from the environment of every harness, screen and job botd starts.

## Consequences

- Self-host is unchanged unless `SECRETS_BACKEND=vault` is set.
- With Vault on, Vault is on botd's critical path for Bot runs: a Vault outage longer than the cache time stops runs (by design). The cache time trades how fast rotations land against how long botd rides out an outage.
- Tested against a stand-in Vault (KV v2, AppRole, namespaces, a refused token, Vault down) in `server/src/secrets/vault.rs` and a fake provider in `server/src/secrets/external.rs`; no real Vault, account or network.
- Threat model: a copy of botd's database or backups no longer holds secrets that live in Vault. Anyone who can run code as botd's user can still read botd's Vault token and, through it, whatever its policy allows; give botd a policy that reads only `<prefix>/*` and nothing else. Bots still receive their server-wide keys in their environment by design ([ADR 0010](0010-secrets.md)).
- Remaining on #55: per-user secrets in the external store, Azure Key Vault, GCP Secret Manager and AWS Secrets Manager providers, Vault's Kubernetes and JWT sign-in, and short-lived (dynamic) credentials handed to each run.
- Ops guide: [docs/ops/vault.md](../ops/vault.md).
