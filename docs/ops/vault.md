# Reading secrets from HashiCorp Vault

botd can read its secrets from HashiCorp Vault (or OpenBao) instead of, or as well as, `.env` and the sealed store. Off by default. Design: [ADR 0125](../adr/0125-external-secrets-backend-vault.md). For Azure Key Vault, GCP Secret Manager or AWS Secrets Manager, see [cloud-secrets.md](cloud-secrets.md).

## What goes where

One KV v2 secret per name, with the value in the field `value`:

| Path | Holds | Reaches Bots |
|------|-------|--------------|
| `secret/superbot/bots/<NAME>` | Server-wide keys for Bots: `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `GITHUB_TOKEN`, ... | Yes, at the start of each run |
| `secret/superbot/server/<NAME>` | botd's own: `LINODE_TOKEN`, `INCUS_CLIENT_KEY`, `SSO_<ID>_CLIENT_SECRET`, `SMTP_PASSWORD`, `STRIPE_SECRET_KEY`, `STRIPE_WEBHOOK_SECRET`, `TURNSTILE_SECRET`, `METRICS_TOKEN`, `AUDIT_EXPORT_HEADERS`, `AUDIT_EXPORT_HEADERS_<NAME>`, backup store keys, ... | Never |

A name in the wrong folder is ignored. `AUTH_PASSWORD`, `SUPERBOT_MASTER_KEY` and the Vault credentials stay in `.env`: botd needs them before it can reach Vault. Each user's own secrets can be in Vault too: see [each user's own secrets](#each-users-own-secrets). Runs can also get credentials Vault makes for them alone: see [short-lived credentials for each run](#short-lived-credentials-for-each-run).

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
VAULT_KUBERNETES_TOKEN_FILE=/var/run/secrets/vault/token
# VAULT_KUBERNETES_MOUNT=kubernetes
```

The role above asks for the audience `vault`, so give botd a projected token with that audience, mounted only into botd's container and readable only by botd's user:

```yaml
spec:
  serviceAccountName: botd
  automountServiceAccountToken: false   # no second, world-readable token in the pod
  securityContext:
    runAsUser: 10001                    # botd's uid, the same for every container in the pod
    runAsGroup: 10001
  containers:
    - name: botd
      volumeMounts:
        - { name: vault-token, mountPath: /var/run/secrets/vault, readOnly: true }
  volumes:
    - name: vault-token
      projected:
        defaultMode: 0400
        sources:
          - serviceAccountToken: { path: token, audience: vault, expirationSeconds: 3600 }
```

**Check the file's owner and mode.** Projected volumes are mounted `0644`, readable by every user in the container, unless you say otherwise. Separate run users ([ADR 0145](../adr/0145-locked-down-run-users-and-red-team.md)) then don't help: a Bot running as its own user can still read a world-readable token and log in to Vault as botd. With a pod-level `runAsUser`, the kubelet makes the token owned by that user. Don't add an `fsGroup` that Bots' users belong to: the kubelet gives that group read on the token too. Without a `runAsUser`, `defaultMode: 0400` leaves it owned by root, so botd can't read it and fails to start (closed, not open). In the running container, `ls -ln /var/run/secrets/vault/` must show botd's uid and `-r--------` or `-rw-------`.

Without `VAULT_KUBERNETES_TOKEN_FILE`, botd uses the pod's default service account token (`/var/run/secrets/kubernetes.io/serviceaccount/token`). Its audience is the Kubernetes API, so it works only if the Vault role sets no `audience`. It is also mounted world-readable, so use it only when no Bot runs in botd's container.

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

The startup line, `botctl secrets backend` and the setup report say how botd logs in, for example `Kubernetes login as role superbot at auth/kubernetes with the token in /var/run/secrets/vault/token in namespace admin`. Logins are audited as `secret.vault_login` with `method`, `role` and `namespace`, and never the JWT or Vault's token. Bots never get the token file: `VAULT_JWT_FILE` and `VAULT_KUBERNETES_TOKEN_FILE` are removed from everything botd starts. But a Bot that runs locally can still open the file itself. If it runs as botd's own user, it can always read it. If it runs as a locked-down run user ([ADR 0145](../adr/0145-locked-down-run-users-and-red-team.md)), it can read the file unless only botd's user may (above). The same holds for `VAULT_JWT_FILE`: make it `0400` and owned by botd, or run Bots on their own machines.

When a login fails, botd logs the status (`Kubernetes login at auth/kubernetes answered 403 Forbidden`). Vault's own log, or its audit device, has the reason: a role bound to another service account or namespace, the wrong audience, or a cluster Vault can't reach for TokenReview.

## Each user's own secrets

Off by default ([ADR 0174](../adr/0174-users-secrets-in-the-external-store.md)). With `SECRETS_USER_FOLDERS=1`, botd also reads `secret/superbot/users/<user id>/<NAME>`, and gives those values only to Bots that user owns:

```sh
botctl users                                          # each user's id, e.g. u1a2b3c4d
vault kv put secret/superbot/users/u1a2b3c4d/ANTHROPIC_API_KEY value=@ada-anthropic.key
```

```sh
# .env
SECRETS_USER_FOLDERS=1
```

The policy above already covers `superbot/users/*`. Who may write each folder is up to your own Vault policies and tooling: botd only reads.

- **Order** for a user's Bots: their Vault folder, then what they saved in the app (Your secrets), then the server-wide secrets. Another user's folder is never read.
- **Which names**: only names a user may save. Reserved names and botd's own (`LINODE_TOKEN`, `SSO_*`, ...) are ignored there. Ids are lowercase letters and digits; a user whose id has anything else gets no folder.
- **In the app** the user sees each name as set by an admin in HashiCorp Vault, with no way to replace it. A copy they saved before can still be deleted.
- **Cache, outages and audit** are as for the shared folders. A run whose owner's folder can't be read is refused (`secrets_unavailable`); reads are `secret.read` with `scope: users` and `userId`. Values are redacted from that user's Bots.
- **When someone leaves**: deleting the user in botd drops what they saved in the app, not their Vault folder. Delete it with `vault kv metadata delete` for each name.

`botctl secrets backend` and the startup line say whether user folders are on. They check only the shared folders.

## Short-lived credentials for each run

Off by default ([ADR 0185](../adr/0185-short-lived-credentials-per-run.md)). With `VAULT_RUN_CREDENTIALS`, botd asks one of Vault's dynamic secrets engines (AWS, database, GCP, Azure, ...) for a new credential as each run starts. The run gets it as environment variables, and botd revokes the lease when the run ends, however it ends. A key a Bot leaks stops working with the run.

```sh
vault secrets enable aws
vault write aws/config/root access_key=... secret_key=... region=eu-west-2
vault write aws/roles/bots credential_type=iam_user policy_arns=arn:aws:iam::aws:policy/ReadOnlyAccess \
  default_ttl=75m max_ttl=75m

vault secrets enable database
vault write database/roles/u-u1a2b3c4d db_name=app default_ttl=75m max_ttl=75m \
  creation_statements="CREATE ROLE \"{{name}}\" LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}'; GRANT app_read TO \"{{name}}\";"

vault policy write superbot-runs - <<'EOF'
path "aws/creds/bots"                       { capabilities = ["read"] }
path "database/creds/u-*"                   { capabilities = ["read"] }
path "sys/leases/revoke/aws/creds/bots/*"   { capabilities = ["update"] }
path "sys/leases/revoke/database/creds/u-*" { capabilities = ["update"] }
EOF
```

botd revokes with `sys/leases/revoke/<lease id>`, so the policy lets it revoke only leases from its own paths. Add `superbot-runs` to botd's role (`token_policies=superbot,superbot-runs`), then in `.env`:

```sh
VAULT_RUN_CREDENTIALS="aws/creds/bots AWS_ACCESS_KEY_ID=access_key AWS_SECRET_ACCESS_KEY=secret_key AWS_SESSION_TOKEN=security_token; database/creds/u-{owner} PGUSER=username PGPASSWORD=password"
```

- **Format**: entries separated by `;` or new lines. Each is a Vault path, then `NAME=field` pairs: the variable the run gets and the field of Vault's answer it comes from. At most 16 paths; each name once.
- **`{owner}`** is the Bot owner's id (`botctl users`), so each user's Bots can get their own role. Those paths are read only for runs that get the owner's own secrets, not a teammate's run of an isolated shared Bot.
- **Order**: these win over static secrets of the same name, and runs never inherit these names from botd's own environment. A field that is null or empty (`security_token` for an IAM user) leaves the name unset in the run, even if a static secret has it; a field that isn't in the answer refuses the run, as it is probably a typo.
- **TTL**: botd revokes each lease when its run ends. If it can't (Vault down, botd stopped mid-run), the lease ends at the role's TTL. Set `default_ttl` a little over your longest run (`RUN_TIMEOUT_MINUTES`, 60 by default), not a day, and no shorter, or a credential can lapse mid-run.
- **botd's own token**: Vault revokes a token's leases when the token ends. Before each lease botd makes sure its token lives past the longest run (`RUN_TIMEOUT_MINUTES` plus five minutes), renewing it or logging in again. If the token can't (its `token_max_ttl` or `-period` is shorter), the run is refused. Keep botd's `token_max_ttl` well over the longest run, and Vault's `default` policy on botd's token, which allows `lookup-self` and `renew-self`.
- **Fails closed**: if a lease can't be made, the run doesn't start (`bot.run_refused`, reason `secrets_unavailable`) and leases already made for it are revoked.
- **Model provider keys**: a plan's provider key (`keySecret` in the tiers file) can come from a lease alone. If the lease gives it empty, the run is refused as above.
- **Audit**: `botctl audit --action 'secret.lease_*'` shows each lease made (`secret.lease_issued`, with path, lease id, TTL and the variable names) and revoked (`secret.lease_revoked`), never a value. For a lease botd couldn't revoke, `vault lease revoke <lease id>` ends it now.
- **Redaction**: the values are redacted from everything botd saves and shows while a lease that has them lives, and forgotten once Vault has revoked the last one (unless botd knew the value already).

botd doesn't make a lease at startup, so a wrong path or missing policy shows on the first run. The startup line and `botctl secrets backend` list the paths (`runCredentials`). Only `SECRETS_BACKEND=vault` reads the setting.

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
