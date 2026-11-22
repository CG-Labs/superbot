# Reading secrets from HashiCorp Vault

botd can read its secrets from HashiCorp Vault (or OpenBao) instead of, or as well as, `.env` and the sealed store. Off by default. Design: [ADR 0125](../adr/0125-external-secrets-backend-vault.md).

## What goes where

One KV v2 secret per name, with the value in the field `value`:

| Path | Holds | Reaches Bots |
|------|-------|--------------|
| `secret/superbot/bots/<NAME>` | Server-wide keys for Bots: `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `GITHUB_TOKEN`, ... | Yes, at the start of each run |
| `secret/superbot/server/<NAME>` | botd's own: `LINODE_TOKEN`, `INCUS_CLIENT_KEY`, `SSO_<ID>_CLIENT_SECRET`, `SMTP_PASSWORD`, `STRIPE_SECRET_KEY`, `STRIPE_WEBHOOK_SECRET`, `TURNSTILE_SECRET`, `METRICS_TOKEN`, `AUDIT_EXPORT_HEADERS`, backup store keys, ... | Never |

A name in the wrong folder is ignored. `AUTH_PASSWORD`, `SUPERBOT_MASTER_KEY` and the Vault credentials stay in `.env`: botd needs them before it can reach Vault. Per-user secrets stay in botd's sealed store for now.

Order: a value in botd's environment wins, then Vault, then the sealed store (`botctl secret set`). `botctl secrets` shows where each name comes from and what it shadows.

## Set up Vault

```sh
vault secrets enable -path=secret kv-v2        # if it isn't there yet
vault kv put secret/superbot/bots/OPENAI_API_KEY value=@openai.key
vault kv put secret/superbot/server/LINODE_TOKEN value=@linode.token

vault policy write superbot - <<'EOF'
path "secret/data/superbot/*"     { capabilities = ["read"] }
path "secret/metadata/superbot/*" { capabilities = ["list"] }
EOF
```

Then AppRole (recommended):

```sh
vault auth enable approle
vault write auth/approle/role/superbot token_policies=superbot token_ttl=1h token_max_ttl=4h secret_id_ttl=0
vault read -field=role_id auth/approle/role/superbot/role-id > role_id
vault write -f -field=secret_id auth/approle/role/superbot/secret-id > secret_id
```

Or a token (`vault token create -policy=superbot -period=24h`), ideally kept fresh by Vault Agent in a file.

## Set up botd

In `.env` (installer) or `deploy/docker/.env` (Compose):

```sh
SECRETS_BACKEND=vault
VAULT_ADDR=https://vault.example.com:8200
VAULT_AUTH=approle
VAULT_ROLE_ID_FILE=/etc/superbot/vault/role_id
VAULT_SECRET_ID_FILE=/etc/superbot/vault/secret_id
# VAULT_NAMESPACE=admin            # Vault Enterprise / HCP
# VAULT_CACERT=/etc/superbot/vault/ca.pem
# VAULT_KV_MOUNT=secret  VAULT_KV_PREFIX=superbot  VAULT_KV_FIELD=value
# SECRETS_CACHE_SECONDS=300
```

Files must be readable by botd's service user only (`chmod 600`). Restart botd. The log says:

```
Secrets backend: HashiCorp Vault at https://vault.example.com:8200, KV v2 secret/superbot/{bots,server}/<NAME> field "value", AppRole at auth/approle, cached for 300 s (2 names; SECRETS_BACKEND, ADR 0125).
```

If Vault can't be reached or refuses botd, botd exits with the reason instead of starting without its secrets.

## Day to day

- **Rotate** a value in Vault (`vault kv put ...`). botd uses it within `SECRETS_CACHE_SECONDS`; no restart. Settings botd reads only at startup (Stripe, Linode, Incus, Turnstile, metrics and backup keys) need a restart.
- **Move a key from the sealed store to Vault**: put it in Vault, check `botctl secrets` shows the sealed copy as shadowed by `vault`, then `botctl secret rm NAME`.
- **Audit**: `botctl audit --action secret.read` (or the client's audit log) shows each read that reached Vault and each failure, by name, never the value. AppRole logins are `secret.vault_login`. Cache hits aren't logged; Vault's own audit device has its side.

## When Vault is down

botd fails closed. Within the cache time, cached answers stand. After that:

- Bot runs don't start; the Bot says the secret store can't be read, and `bot.run_refused` is audited with reason `secrets_unavailable`.
- botd never falls back to an older value or to the sealed store's copy.
- `GET /api/secrets` answers 503; the server log has Vault's reason (`Vault answered 503 ...`, `AppRole login answered 400 ...`).

Runs work again as soon as Vault answers. A longer `SECRETS_CACHE_SECONDS` rides out longer outages but delays rotations.

## Turning it off

Copy any keys you still need into `.env` or `botctl secret set`, remove `SECRETS_BACKEND` (or set `local`), and restart.
