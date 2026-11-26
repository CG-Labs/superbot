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

## Cloud sign-in (AWS, Google Cloud, Azure)

Design: [ADR 0260](../adr/0260-vault-cloud-sign-in.md). On a cloud VM or container, botd logs in to Vault as its own cloud identity, so it holds no Vault credential. It logs in at startup, two thirds of the way through each Vault token's lease, and whenever Vault refuses the token, and each login proves who it is afresh.

**AWS** (`VAULT_AUTH=aws`, Vault's `aws` method, `iam` type). botd signs an STS `GetCallerIdentity` request with its own AWS keys and sends it to Vault, which sends it on to STS. The keys come from AWS's standard chain, as for Secrets Manager: the instance profile (IMDSv2), the container's credentials (ECS, EKS Pod Identity), web identity (EKS IRSA) or access keys in the environment.

```sh
vault auth enable aws
vault write auth/aws/config/client iam_server_id_header_value=vault.example.com
vault write auth/aws/role/superbot auth_type=iam \
  bound_iam_principal_arn=arn:aws:iam::<account-id>:role/botd \
  token_policies=superbot token_ttl=1h
```

```sh
SECRETS_BACKEND=vault
VAULT_ADDR=https://vault.example.com:8200
VAULT_AUTH=aws
VAULT_AWS_ROLE=superbot                   # or leave it out for the role named after botd's IAM role
VAULT_AWS_HEADER_VALUE=vault.example.com  # the mount's iam_server_id_header_value, if set
# VAULT_AWS_REGION=us-east-1              # the region of the mount's sts_endpoint
# VAULT_AWS_CREDENTIALS=chain             # or instance-profile, container, web-identity, env
# VAULT_AWS_MOUNT=aws
```

Set `iam_server_id_header_value`: without it, anyone holding a signed request botd made for this Vault could replay it to another. `VAULT_AWS_REGION` must match the mount's `sts_endpoint` and `sts_region`. With Vault's default (the global endpoint), leave it as `us-east-1`; with a regional endpoint such as `https://sts.eu-west-2.amazonaws.com`, set both to `eu-west-2`. Vault, not botd, must reach STS. botd needs no IAM permission: `GetCallerIdentity` is always allowed.

**Google Cloud** (`VAULT_AUTH=gcp`, Vault's `gcp` method, `iam` type). botd asks IAM Credentials to sign a JWT for `vault/<role>` as its service account, lasting 10 minutes, and logs in with it. The token for that comes from the metadata server, or a service account key.

```sh
vault auth enable gcp
vault write auth/gcp/role/superbot type=iam \
  bound_service_accounts=botd@<project>.iam.gserviceaccount.com \
  token_policies=superbot token_ttl=1h
```

```sh
VAULT_AUTH=gcp
VAULT_GCP_ROLE=superbot
# VAULT_GCP_SERVICE_ACCOUNT=vault-login@<project>.iam.gserviceaccount.com  # default: botd's own
# VAULT_GCP_CREDENTIALS=metadata          # or service-account-key, with GCP_SERVICE_ACCOUNT_KEY_FILE
# VAULT_GCP_MOUNT=gcp
```

botd's service account needs `iam.serviceAccounts.signJwt` on the account it signs as (the Service Account Token Creator role, on itself by default), and the IAM Credentials API must be on. A 403 says so. Vault checks the JWT against the account's public keys, so Vault's own Google credentials need `iam.serviceAccounts.get` and `iam.serviceAccountKeys.get`. Leave the role's `max_jwt_exp` at its default (15 minutes) or more.

**Azure** (`VAULT_AUTH=azure`, Vault's `azure` method). botd logs in with its managed identity's token for the mount's `resource`. It can also use a service principal or AKS workload identity, as Key Vault does.

```sh
vault auth enable azure
vault write auth/azure/config tenant_id=<tenant-id> resource=https://management.azure.com/
vault write auth/azure/role/superbot \
  bound_service_principal_ids=<managed-identity-object-id> \
  token_policies=superbot token_ttl=1h
```

```sh
VAULT_AUTH=azure
VAULT_AZURE_ROLE=superbot
# VAULT_AZURE_RESOURCE=https://management.azure.com/  # the mount's resource
# VAULT_AZURE_CREDENTIALS=managed-identity            # or client-secret, client-certificate, workload-identity
# VAULT_AZURE_INSTANCE=1                              # send the VM's details, for roles bound to them
# VAULT_AZURE_MOUNT=azure
```

Off Azure, `VAULT_AZURE_CREDENTIALS=client-certificate` signs in as a service principal with a certificate rather than a client secret, from the PEM file in `AZURE_CLIENT_CERTIFICATE_PATH` ([ADR 0269](../adr/0269-azure-certificate-credentials.md), [setup](cloud-secrets.md#with-a-certificate)). A role bound only to service principal ids needs nothing more. A role bound to a subscription, resource group or scale set needs `VAULT_AZURE_INSTANCE=1`: botd reads the VM's subscription, resource group and name (or scale set) from the instance metadata service and sends them with each login. That needs a managed identity on a VM or scale set, and Vault's own Azure credentials need read access to it.

**What botd shows.** The startup line, `botctl secrets backend` and the setup report say how botd logs in, for example `AWS login as role superbot at auth/aws, an STS request signed for us-east-1, with the server id header with the instance profile (IMDSv2)`. Logins are audited as `secret.vault_login` with `method` (`aws`, `gcp` or `azure`), `role` and `namespace`. Fetching AWS keys is also audited as `secret.backend_login` against the `vault` store. The audit log never has keys, signatures, JWTs or tokens. botd's AWS keys are masked in Bots' output while botd holds them. The credentials botd signs in with, and the settings that lead to them (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` and `AWS_SESSION_TOKEN` from the environment, `AWS_WEB_IDENTITY_TOKEN_FILE` and `AWS_ROLE_ARN`, the container's token, Google's key, Entra's client secret), are removed from everything botd starts and can't be saved as Bot secrets. `botd offline check` lists the endpoints botd reaches to log in (the metadata servers, IAM Credentials, Entra ID).

When a login fails, botd logs the status only (`Vault: AWS login at auth/aws answered 400 Bad Request`), since Vault's text can echo what was sent. Vault's log has the reason: usually a principal the role doesn't bind, a missing or wrong server id header, or a region that doesn't match the mount's.

### The instance's own identity (gce and ec2)

Design: [ADR 0298](../adr/0298-vault-sign-in-with-the-instances-own-identity.md). The `gcp` and `aws` methods also have a type that logs in with a document the cloud signs for the VM itself, rather than with botd's IAM identity. Use them when the Vault role should be bound to where botd runs (project, zone, labels, instance group; AMI, account, VPC, subnet), or when botd's service account may not be given the Service Account Token Creator role the `iam` type needs.

**GCE** (`VAULT_GCP_TYPE=gce`). botd asks the metadata server for the VM's identity token for `http://vault/<role>` with the instance's details (`format=full`), and logs in with it. Google signs it as the VM's service account, so botd needs no IAM permission at all.

```sh
vault write auth/gcp/role/superbot-vm type=gce \
  bound_projects=<project> bound_zones=europe-west2-a,europe-west2-b \
  bound_labels=app:superbot \
  token_policies=superbot token_ttl=1h
```

```sh
VAULT_AUTH=gcp
VAULT_GCP_TYPE=gce
VAULT_GCP_ROLE=superbot-vm
# VAULT_GCP_MOUNT=gcp
# GCE_METADATA_HOST=169.254.169.254
```

Vault's own Google credentials need `compute.instances.get`, and `compute.instanceGroups.list` for roles bound to instance groups (`roles/compute.viewer` has both), with the Compute Engine API on. The VM needs a service account; a 404 from the metadata server says so. `VAULT_GCP_CREDENTIALS` must be `metadata` (the default), and `VAULT_GCP_SERVICE_ACCOUNT` isn't used: the token is the VM's own account's. On GKE, use `VAULT_AUTH=kubernetes` or the `iam` type instead: Vault's `gce` roles check a Compute Engine instance.

**EC2** (`VAULT_AWS_TYPE=ec2`). botd reads the instance's PKCS#7-signed identity document from IMDSv2 and logs in with it and a nonce. At the instance's first login, Vault ties the nonce to the instance id. After that it takes a login from that instance only with the same nonce. So the nonce is what stops another process on the instance, which can read the same document, from logging in as botd.

```sh
vault write auth/aws/role/superbot auth_type=ec2 \
  bound_ami_id=<ami-id> bound_account_id=<account-id> bound_vpc_id=<vpc-id> \
  token_policies=superbot token_ttl=1h
```

```sh
openssl rand -hex 32 > /etc/superbot/vault-aws-nonce && chmod 600 /etc/superbot/vault-aws-nonce
```

```sh
VAULT_AUTH=aws
VAULT_AWS_TYPE=ec2
VAULT_AWS_NONCE_FILE=/etc/superbot/vault-aws-nonce   # or VAULT_AWS_NONCE
VAULT_AWS_ROLE=superbot                              # or leave it out for the role named after the AMI
# VAULT_AWS_MOUNT=aws
```

botd sends its own nonce rather than taking the one Vault would make, so a restart logs in again, and Vault neither returns it nor writes it to its audit log. Keep it like any other secret: it is reserved, masked in Bots' output, kept from everything botd starts, and redacted from the support bundle. Use a different nonce on each instance. Leave the role's `disallow_reauthentication` off, or botd can't log in again when its token ends. If the nonce is lost or changed, Vault refuses botd (`answered 400`, with a hint) until an operator deletes the instance's entry with `vault delete auth/aws/identity-accesslist/<instance-id>`. The `iam` type's `VAULT_AWS_REGION`, `VAULT_AWS_HEADER_VALUE` and `VAULT_AWS_CREDENTIALS` are refused with `ec2`, and botd needs no AWS keys. Vault itself needs AWS credentials to check the instance (`ec2:DescribeInstances`), and in some regions AWS's public certificate for the document (`auth/aws/config/certificate`). HashiCorp recommends the `iam` type where it fits. Choose `ec2` when the role must be bound to the AMI or network rather than the IAM role.

Both types: the startup line says which (`GCP login (gce) as role superbot-vm at auth/gcp, the VM's identity token of the metadata server's service account`), logins are audited as `secret.vault_login` with `type` (`gce` or `ec2`) beside `method` and `role`, never the token, the document or the nonce, and `botd offline check` lists only the metadata service.

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

Off by default ([ADR 0185](../adr/0185-short-lived-credentials-per-run.md)). With `VAULT_RUN_CREDENTIALS`, botd asks one of Vault's dynamic secrets engines (AWS, database, GCP, Azure, ...) for a new credential as each run starts. The run gets it as environment variables, and botd revokes the lease when the run ends, however it ends. A key a Bot leaks stops working with the run. Without Vault, [AWS STS sessions](cloud-secrets.md#short-lived-aws-credentials-for-each-run) and [GCP service account tokens](cloud-secrets.md#short-lived-gcp-credentials-for-each-run) work much the same way, but can't be revoked.

```sh
vault secrets enable aws
vault write aws/config/root access_key=... secret_key=... region=eu-west-2
vault write aws/roles/bots credential_type=iam_user policy_arns=arn:aws:iam::aws:policy/ReadOnlyAccess \
  default_ttl=15m max_ttl=75m

vault secrets enable database
vault write database/roles/u-u1a2b3c4d db_name=app default_ttl=15m max_ttl=75m \
  creation_statements="CREATE ROLE \"{{name}}\" LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}'; GRANT app_read TO \"{{name}}\";"

vault policy write superbot-runs - <<'EOF'
path "aws/creds/bots"                       { capabilities = ["read"] }
path "database/creds/u-*"                   { capabilities = ["read"] }
path "sys/leases/renew/aws/creds/bots/*"    { capabilities = ["update"] }
path "sys/leases/renew/database/creds/u-*"  { capabilities = ["update"] }
path "sys/leases/revoke/aws/creds/bots/*"   { capabilities = ["update"] }
path "sys/leases/revoke/database/creds/u-*" { capabilities = ["update"] }
EOF
```

botd renews with `sys/leases/renew/<lease id>` and revokes with `sys/leases/revoke/<lease id>`, so the policy lets it renew and revoke only leases from its own paths. Add `superbot-runs` to botd's role (`token_policies=superbot,superbot-runs`), then in `.env`:

```sh
VAULT_RUN_CREDENTIALS="aws/creds/bots AWS_ACCESS_KEY_ID=access_key AWS_SECRET_ACCESS_KEY=secret_key AWS_SESSION_TOKEN=security_token; database/creds/u-{owner} PGUSER=username PGPASSWORD=password"
```

- **Format**: entries separated by `;` or new lines. Each is a Vault path, then `NAME=field` pairs: the variable the run gets and the field of Vault's answer it comes from. At most 16 paths; each name once.
- **`{owner}`** is the Bot owner's id (`botctl users`), so each user's Bots can get their own role. Those paths are read only for runs that get the owner's own secrets, not a teammate's run of an isolated shared Bot.
- **Order**: these win over static secrets of the same name, and runs never inherit these names from botd's own environment. A field that is null or empty (`security_token` for an IAM user) leaves the name unset in the run, even if a static secret has it; a field that isn't in the answer refuses the run, as it is probably a typo.
- **TTL**: botd revokes each lease when its run ends. If it can't (Vault down, botd stopped mid-run), the lease ends at its TTL. Keep `default_ttl` short (minutes) and set `max_ttl` over your longest run (`RUN_TIMEOUT_MINUTES`, 60 by default) plus five minutes: botd renews the lease while the run lasts (see [below](#renewing-leases-for-long-runs)), so a lease it can't revoke ends within `default_ttl` of its last renewal.
- **botd's own token**: Vault revokes a token's leases when the token ends. Before each lease botd makes sure its token lives past the longest run (`RUN_TIMEOUT_MINUTES` plus five minutes), renewing it or logging in again. If the token can't (its `token_max_ttl` or `-period` is shorter), the run is refused. Keep botd's `token_max_ttl` well over the longest run, and Vault's `default` policy on botd's token, which allows `lookup-self` and `renew-self`.
- **Fails closed**: if a lease can't be made, the run doesn't start (`bot.run_refused`, reason `secrets_unavailable`) and leases already made for it are revoked.
- **Model provider keys**: a plan's provider key (`keySecret` in the tiers file) can come from a lease alone. If the lease gives it empty, the run is refused as above.
- **Audit**: `botctl audit --action 'secret.lease_*'` shows each lease made (`secret.lease_issued`, with path, lease id, TTL and the variable names), renewed (`secret.lease_renewed`) and revoked (`secret.lease_revoked`), never a value. For a lease botd couldn't revoke, `vault lease revoke <lease id>` ends it now.
- **Redaction**: the values are redacted from everything botd saves and shows while a lease that has them lives, and forgotten once Vault has revoked the last one (unless botd knew the value already).
- **Narrowing**: `policy=`, `policy-arn=` and `tags=` narrow each run's session only for [AWS STS without Vault](cloud-secrets.md#narrowing-each-runs-session), and botd won't start with them here. With Vault's AWS engine, narrow on the Vault role (`policy_document`, `policy_arns`, and `session_tags` for `assumed_role`), with a role per owner through `{owner}` if each user needs their own.

botd doesn't make a lease at startup, so a wrong path or missing policy shows on the first run. The startup line and `botctl secrets backend` list the paths (`runCredentials`). Only `SECRETS_BACKEND=vault` reads the setting.

### Renewing leases for long runs

([ADR 0221](../adr/0221-renewing-vault-leases-for-long-runs.md).) A renewable lease whose TTL is shorter than the longest run (`RUN_TIMEOUT_MINUTES` plus five minutes) is renewed while its run lasts. Nothing to turn on; leases that already last that long aren't renewed.

- **When**: two thirds of the way through each TTL, asking for the TTL the lease was made with (the role's `default_ttl`), and never past the run's latest end. When the run ends botd stops renewing, then revokes.
- **Max TTL**: Vault won't renew a lease past the role's `max_ttl`. When it gives less than asked, that renewal is the last, and if the lease then ends before the run could, **the run stops** when it does: the Bot says its short-lived credentials expired. So keep `max_ttl` over `RUN_TIMEOUT_MINUTES` plus five minutes. The same goes for a lease Vault made not renewable (AWS `assumed_role` and `federation_token` credentials): its TTL must cover a run, or the run stops when it ends.
- **Policy**: botd needs `update` on `sys/leases/renew/<path>/*` for each listed path, as above. Without it the first renewal is refused (`error: refused`, and the server log names the missing capability), and the run stops when its lease ends.
- **Vault down**: a failed renewal is tried again, every few seconds up to thirty, until the lease runs out; then the run stops. The lease never outlives its TTL because botd couldn't reach Vault, and a renewal that hangs doesn't hold the run past the lease's current end.
- **Audit**: each renewal is `secret.lease_renewed` with the lease id, the `increment` asked for, the `ttl` Vault gave and `expiresAt`; the one that hit the max TTL has `final: true`. Failures have `error`: `refused`, `unavailable`, or `expired` when the lease ran out while renewals failed. A one-hour run with a 15-minute `default_ttl` renews each lease about six times.

botd's own token must still outlive the run (see above): Vault ends a token's leases with it, renewed or not.

## Day to day

- **Rotate** a value in Vault (`vault kv put ...`). botd uses it within `SECRETS_CACHE_SECONDS`; no restart. To use it now, refresh botd's cache ([below](#rotating-a-value-now)). Settings botd reads only at startup (Stripe, Linode, Incus, Turnstile, metrics and backup keys) need a restart; the refresh names them.
- **Move a key from the sealed store to Vault**: put it in Vault, check `botctl secrets` shows the sealed copy as shadowed by `vault`, then `botctl secret rm NAME`.
- **Audit**: `botctl audit --action secret.read` (or the client's audit log) shows each read that reached Vault and each failure, by name, never the value. AppRole, Kubernetes and JWT logins are `secret.vault_login`. Cache hits aren't logged; Vault's own audit device has its side.

## Rotating a value now

After a leak, don't wait out the cache. Rotate the value in Vault, then:

```sh
botctl secrets refresh OPENAI_API_KEY     # or several names, or none for everything cached
```

botd reads each name again at once (in every folder that has it cached, users' folders included) and lists its folders again, so new runs get the new value and a new name reaches Bots straight away. It says, per name, `changed`, `unchanged`, `added`, `removed`, `found`, `not there` or `unavailable`, never a value, and exits non-zero if any read failed or botd needs a restart:

```text
vault read again: 1 name, 1 changed.
  1 changed, 0 added, 0 removed, 0 unchanged, 0 found, 0 not there, 0 unavailable.
  OPENAI_API_KEY in bots: changed
```

- **Restart needed**: botd's startup settings keep what they read until a restart. With no names, the refresh also reads every name they read from Vault and flags those whose value has changed since (`restart botd: it read the old value at startup`), including one that was missing at startup and is set now.
- **Vault down**: a name that can't be read is left with nothing cached, as when the cache runs out, so runs that need it are refused until Vault answers. A refresh never keeps the old value.
- **Running Bots** keep the environment they started with. Revoke the old key at its provider to cut them off too. Short-lived credentials for each run aren't cached, so a refresh doesn't touch them.
- **Audit**: `secret.cache_refreshed`, by the admin, with the counts and the names that changed, failed or need a restart. Each read is also a `secret.read`, as usual.
- The API is `POST /api/secrets/refresh` with `{"names": [...]}` or no body, for admins. It answers 409 with `SECRETS_BACKEND=local` or while another refresh runs.

See [ADR 0291](../adr/0291-refreshing-the-external-secrets-cache.md).

## When Vault is down

botd fails closed. Within the cache time, cached answers stand. After that:

- Bot runs don't start; the Bot says the secret store can't be read, and `bot.run_refused` is audited with reason `secrets_unavailable`.
- botd never falls back to an older value or to the sealed store's copy.
- `GET /api/secrets` answers 503; the server log has Vault's reason (`Vault answered 503 ...`, `AppRole login at auth/approle answered 400 ...`, `the JWT in VAULT_JWT_FILE (...) expired 120 s ago`).

Runs work again as soon as Vault answers. A longer `SECRETS_CACHE_SECONDS` rides out longer outages but delays rotations; `botctl secrets refresh` lands a rotation at once whatever the cache time.

## Turning it off

Copy any keys you still need into `.env` or `botctl secret set`, remove `SECRETS_BACKEND` (or set `local`), and restart.
