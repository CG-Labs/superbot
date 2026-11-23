# Reading secrets from HashiCorp Vault

botd can read its secrets from HashiCorp Vault (or OpenBao) instead of, or as well as, `.env` and the sealed store. Off by default. Design: [ADR 0125](../adr/0125-external-secrets-backend-vault.md). For Azure Key Vault, GCP Secret Manager or AWS Secrets Manager, see [cloud-secrets.md](cloud-secrets.md).

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

Or a token (`vault token create -policy=superbot -period=24h`), ideally kept fresh by Vault Agent in a file. On Kubernetes, or anywhere the platform gives botd a JWT, use [Kubernetes or JWT sign-in](#kubernetes-and-jwt-sign-in) instead: then botd holds no Vault credential at all.

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

## Kubernetes and JWT sign-in

Design: [ADR 0159](../adr/0159-vault-kubernetes-and-jwt-sign-in.md). botd logs in with a JWT the platform writes to a file and rotates. It reads the file again at every login: at startup, two thirds of the way through each Vault token's lease, and whenever Vault refuses the token. Before sending the JWT, botd checks that the file holds a JWT that hasn't expired, so a wrong path fails with the setting's name and never reaches Vault.

**Kubernetes** (Vault checks the pod's service account token with the cluster's TokenReview API):

```sh
vault auth enable kubernetes
vault write auth/kubernetes/config kubernetes_host=https://<cluster-api>:6443
vault write auth/kubernetes/role/superbot \
  bound_service_account_names=botd bound_service_account_namespaces=superbot \
  audience=vault token_policies=superbot token_ttl=1h token_max_ttl=4h
```

```sh
SECRETS_BACKEND=vault
VAULT_ADDR=https://vault.example.com:8200
VAULT_AUTH=kubernetes
VAULT_KUBERNETES_ROLE=superbot
# VAULT_KUBERNETES_MOUNT=kubernetes
# VAULT_KUBERNETES_TOKEN_FILE=/var/run/secrets/vault/token   # default: the pod's service account token
```

Prefer a projected token with Vault's audience, mounted only into botd's container, over the default service account token:

```yaml
volumes:
  - name: vault-token
    projected:
      sources:
        - serviceAccountToken: { path: token, audience: vault, expirationSeconds: 3600 }
```

**JWT** (Vault checks the signature against an issuer it trusts: a cluster's OIDC issuer, GitHub Actions, SPIFFE, a cloud's workload identity):

```sh
vault auth enable jwt
vault write auth/jwt/config oidc_discovery_url=https://<issuer> bound_issuer=https://<issuer>
vault write auth/jwt/role/superbot role_type=jwt user_claim=sub \
  bound_subject=system:serviceaccount:superbot:botd bound_audiences=vault \
  token_policies=superbot token_ttl=1h
```

```sh
VAULT_AUTH=jwt
VAULT_JWT_FILE=/var/run/secrets/vault/token
VAULT_JWT_ROLE=superbot       # or leave it out to use the mount's default_role
# VAULT_JWT_MOUNT=jwt
```

**Namespaces** (Vault Enterprise, HCP Vault): when the auth method is mounted in another namespace than the secrets, set `VAULT_AUTH_NAMESPACE` to where the method is mounted (`root` for the root namespace). Reads still go to `VAULT_NAMESPACE`. This works for AppRole too.

```sh
VAULT_NAMESPACE=admin/team-a      # where secret/superbot/... is
VAULT_AUTH_NAMESPACE=admin        # where auth/kubernetes is
```

The startup line, `botctl secrets backend` and the setup report say how botd logs in, for example `Kubernetes login as role superbot at auth/kubernetes with the token in /var/run/secrets/vault/token in namespace admin`. Logins are audited as `secret.vault_login` with `method`, `role` and `namespace`, and never the JWT or Vault's token. Bots never get the token file: `VAULT_JWT_FILE` and `VAULT_KUBERNETES_TOKEN_FILE` are removed from everything botd starts. If Bots run locally as botd's own user, they could still read a token file mounted into the same container, so run them as locked-down run users ([ADR 0145](../adr/0145-locked-down-run-users-and-red-team.md)) or on their own machines.

When a login fails, botd logs the status (`Kubernetes login at auth/kubernetes answered 403 Forbidden`). Vault's own log, or its audit device, has the reason: a role bound to another service account or namespace, the wrong audience, or a cluster Vault can't reach for TokenReview.

## Day to day

- **Rotate** a value in Vault (`vault kv put ...`). botd uses it within `SECRETS_CACHE_SECONDS`; no restart. Settings botd reads only at startup (Stripe, Linode, Incus, Turnstile, metrics and backup keys) need a restart.
- **Move a key from the sealed store to Vault**: put it in Vault, check `botctl secrets` shows the sealed copy as shadowed by `vault`, then `botctl secret rm NAME`.
- **Audit**: `botctl audit --action secret.read` (or the client's audit log) shows each read that reached Vault and each failure, by name, never the value. AppRole, Kubernetes and JWT logins are `secret.vault_login`. Cache hits aren't logged; Vault's own audit device has its side.

## When Vault is down

botd fails closed. Within the cache time, cached answers stand. After that:

- Bot runs don't start; the Bot says the secret store can't be read, and `bot.run_refused` is audited with reason `secrets_unavailable`.
- botd never falls back to an older value or to the sealed store's copy.
- `GET /api/secrets` answers 503; the server log has Vault's reason (`Vault answered 503 ...`, `AppRole login at auth/approle answered 400 ...`, `the JWT in VAULT_JWT_FILE (...) expired 120 s ago`).

Runs work again as soon as Vault answers. A longer `SECRETS_CACHE_SECONDS` rides out longer outages but delays rotations.

## Turning it off

Copy any keys you still need into `.env` or `botctl secret set`, remove `SECRETS_BACKEND` (or set `local`), and restart.
