# Reading secrets from Azure Key Vault, GCP Secret Manager or AWS Secrets Manager

botd can read its secrets from Azure Key Vault, Google Cloud Secret Manager or AWS Secrets Manager instead of, or as well as, `.env` and the sealed store. It is off by default. It works like the [Vault backend](vault.md): read-only, cached, fails closed, and every read is audited. Design: [ADR 0136](../adr/0136-cloud-secret-managers.md) and, for AWS, [ADR 0146](../adr/0146-aws-secrets-manager.md), on top of [ADR 0125](../adr/0125-external-secrets-backend-vault.md).

## What goes where

Each name is one secret. Its name says which folder it is in:

| Folder | Holds | Reaches Bots | Azure Key Vault name | GCP Secret Manager id | AWS Secrets Manager name |
|--------|-------|--------------|----------------------|-----------------------|--------------------------|
| `bots` | Server-wide keys for Bots: `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `GITHUB_TOKEN`, ... | Yes, at the start of each run | `superbot-bots-OPENAI-API-KEY` | `superbot-bots-OPENAI_API_KEY` | `superbot/bots/OPENAI_API_KEY` |
| `server` | botd's own: `LINODE_TOKEN`, `SSO_<ID>_CLIENT_SECRET`, `SMTP_PASSWORD`, `STRIPE_SECRET_KEY`, ... | Never | `superbot-server-LINODE-TOKEN` | `superbot-server-LINODE_TOKEN` | `superbot/server/LINODE_TOKEN` |

Key Vault doesn't allow `_`, so write it as `-`. Case doesn't matter there. On AWS the folders are real paths, and store each value as plain text (`--secret-string`), not as key/value JSON. A name in the wrong folder is ignored. `AUTH_PASSWORD`, `SUPERBOT_MASTER_KEY` and the cloud credentials stay in `.env`, because botd needs them before it can sign in. Each user's own secrets can be here too: see [each user's own secrets](#each-users-own-secrets).

Order: a value in botd's environment wins, then the cloud store, then the sealed store (`botctl secret set`).

## Azure Key Vault

### Set up Azure

Use a vault of its own for SuperBot. Azure RBAC grants access per vault or per secret, not per name prefix.

```sh
az keyvault create -n <vault> -g <group> --enable-rbac-authorization true
az keyvault secret set --vault-name <vault> -n superbot-bots-OPENAI-API-KEY --file openai.key
az keyvault secret set --vault-name <vault> -n superbot-server-LINODE-TOKEN --file linode.token
```

Give botd's identity **Key Vault Secrets User** on the vault. That role reads and lists secrets and changes nothing:

```sh
az role assignment create --role "Key Vault Secrets User" --assignee <principal-id> \
  --scope "$(az keyvault show -n <vault> --query id -o tsv)"
```

### Set up botd

On an Azure VM, scale set or AKS node with a managed identity (recommended):

```sh
SECRETS_BACKEND=azure-keyvault
AZURE_KEYVAULT_URL=https://<vault>.vault.azure.net
# AZURE_CLIENT_ID=<client-id>          # a user-assigned identity
```

On App Service, Functions or Container Apps, the platform sets `IDENTITY_ENDPOINT` and `IDENTITY_HEADER`, and botd uses them.

With a service principal:

```sh
AZURE_KEYVAULT_AUTH=client-secret
AZURE_TENANT_ID=<tenant-id>
AZURE_CLIENT_ID=<app-client-id>
AZURE_CLIENT_SECRET_FILE=/etc/superbot/azure/client_secret
```

With AKS workload identity, use `AZURE_KEYVAULT_AUTH=workload-identity`. AKS sets `AZURE_TENANT_ID`, `AZURE_CLIENT_ID` and `AZURE_FEDERATED_TOKEN_FILE`. Sovereign clouds: use the vault's own URL (`.vault.azure.cn`, `.vault.usgovcloudapi.net`) and set `AZURE_AUTHORITY_HOST`.

## GCP Secret Manager

### Set up Google Cloud

```sh
gcloud secrets create superbot-bots-OPENAI_API_KEY --data-file=openai.key
gcloud secrets create superbot-server-LINODE_TOKEN --data-file=linode.token
```

botd's service account needs:

- `roles/secretmanager.secretAccessor` on SuperBot's secrets. Grant it per secret, or on the project with an IAM condition such as `resource.name.startsWith("projects/<project-number>/secrets/superbot-")`. Use two conditions to keep `superbot-bots-` and `superbot-server-` apart.
- `secretmanager.secrets.list` on the project, e.g. through `roles/secretmanager.viewer`. That shows names and metadata, never values.

For regional secrets (data residency), create them with `--location=<region>` and set `GCP_SECRET_MANAGER_LOCATION`. botd then uses that region's endpoint.

### Set up botd

On Compute Engine, GKE with workload identity, or Cloud Run (recommended):

```sh
SECRETS_BACKEND=gcp-secret-manager
GCP_SECRET_MANAGER_PROJECT=<project-id>
# GCP_SECRET_MANAGER_LOCATION=europe-west2
```

With a service account key, where no metadata server is available:

```sh
GCP_SECRET_MANAGER_AUTH=service-account-key
GCP_SERVICE_ACCOUNT_KEY_FILE=/etc/superbot/gcp/key.json   # project_id in the key is used if the project isn't set
```

## AWS Secrets Manager

### Set up AWS

```sh
aws secretsmanager create-secret --region <region> --name superbot/bots/OPENAI_API_KEY --secret-string file://openai.key
aws secretsmanager create-secret --region <region> --name superbot/server/LINODE_TOKEN --secret-string file://linode.token
```

Give botd's role or user a policy like this one. It reads SuperBot's two folders and changes nothing. `ListSecrets` can't be limited to a prefix; it shows names, never values:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret"],
      "Resource": [
        "arn:aws:secretsmanager:<region>:<account>:secret:superbot/bots/*",
        "arn:aws:secretsmanager:<region>:<account>:secret:superbot/server/*",
        "arn:aws:secretsmanager:<region>:<account>:secret:superbot/users/*"
      ]
    },
    { "Effect": "Allow", "Action": "secretsmanager:ListSecrets", "Resource": "*" }
  ]
}
```

If the secrets are encrypted with a customer-managed KMS key, botd also needs `kms:Decrypt` on that key. Two statements, one per folder, let you grant them separately.

### Set up botd

```sh
SECRETS_BACKEND=aws
AWS_SECRETS_MANAGER_REGION=<region>      # or AWS_REGION; required
# AWS_SECRETS_MANAGER_PREFIX=superbot
```

botd takes its credentials from the first of these that is set, as AWS's SDKs do, and says which in its startup line:

1. **Access keys**: `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` (or `AWS_SECRET_ACCESS_KEY_FILE=/etc/superbot/aws/secret_key`), and `AWS_SESSION_TOKEN` for temporary ones. Least preferred: they don't expire, so rotate them yourself.
2. **Web identity** (EKS IRSA): EKS sets `AWS_WEB_IDENTITY_TOKEN_FILE` and `AWS_ROLE_ARN`.
3. **Container credentials** (ECS task roles, EKS Pod Identity): the platform sets `AWS_CONTAINER_CREDENTIALS_RELATIVE_URI`, or `AWS_CONTAINER_CREDENTIALS_FULL_URI` and `AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE`.
4. **Instance profile** (EC2): from the instance metadata service, IMDSv2 only. Require IMDSv2 on the instance (`aws ec2 modify-instance-metadata-options --instance-id <id> --http-tokens required --http-put-response-hop-limit 1`).

To pin one, set `AWS_SECRETS_MANAGER_AUTH` to `env`, `web-identity`, `container` or `instance-profile`. botd never reads `~/.aws/config` or `~/.aws/credentials`, profiles, SSO or `credential_process`. For a VPC endpoint or FIPS, set `AWS_ENDPOINT_URL_SECRETS_MANAGER` (and `AWS_ENDPOINT_URL_STS` for web identity).

While `SECRETS_BACKEND=aws`, the credentials botd signs in with are its own: with access keys, `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` and `AWS_SESSION_TOKEN` can't be given to Bots by any store, and are removed from everything botd starts; with web identity or container credentials, their token and settings are. To give Bots AWS keys of their own, use [short-lived credentials for each run](#short-lived-aws-credentials-for-each-run), never botd's.

## Check it

Files must be readable by botd's service user only (`chmod 600`). Restart botd. The log says, for example:

```
Secrets backend: Azure Key Vault at https://<vault>.vault.azure.net, secrets superbot-{bots,server}-<NAME>, managed identity, cached for 300 s (2 names; SECRETS_BACKEND, ADR 0125).
Secrets backend: AWS Secrets Manager in <region> at https://secretsmanager.<region>.amazonaws.com, secrets superbot/{bots,server}/<NAME>, the instance profile (IMDSv2), cached for 300 s (2 names; SECRETS_BACKEND, ADR 0125).
```

If a setting is wrong, or the store can't be reached or refuses botd, botd exits with the reason instead of starting without its secrets. Settings for a backend you didn't choose are named in a warning.

While botd runs:

```sh
botctl secrets backend     # which backend, and whether it answers now (exits 1 if not)
botctl secrets             # each name, where it comes from, and what it shadows
botctl audit --action secret.read            # reads that reached the store, by name, never the value
botctl audit --action secret.backend_login   # sign-ins, by method
```

The console's setup report (`GET /api/setup`, `secretsBackend`) shows the same thing.

## Keep Bots away from botd's identity

A managed identity, the metadata server or an AWS instance profile gives a token to **any process on the machine** that asks `169.254.169.254` (ECS and EKS Pod Identity: `169.254.170.2` and `169.254.170.23`). That includes Bots running on botd's own host. Either run Bots on their own machines, whose egress rules already block metadata addresses ([ADR 0126](../adr/0126-per-user-machine-hardening.md)), or block the address on botd's host for everyone but botd:

```sh
sudo iptables -A OUTPUT -d 169.254.169.254 -m owner ! --uid-owner superbot -j REJECT
sudo iptables -A OUTPUT -d 169.254.170.0/24 -m owner ! --uid-owner superbot -j REJECT   # ECS, EKS Pod Identity
```

Make the rule persistent with your distribution's tool. On EC2, a hop limit of 1 also keeps containers on the host from reaching IMDS. With a service principal, key, access keys or a token file, botd removes the credentials from every harness's environment, but the file must still be readable only by botd.

## Each user's own secrets

Off by default ([ADR 0174](../adr/0174-users-secrets-in-the-external-store.md)). With `SECRETS_USER_FOLDERS=1`, botd also reads a folder per user, and gives its values only to Bots that user owns. `botctl users` shows each user's id (for example `u1a2b3c4d`):

| Backend | Name for `ANTHROPIC_API_KEY` of user `u1a2b3c4d` |
|---------|--------------------------------------------------|
| Azure Key Vault | `superbot-users-u1a2b3c4d-ANTHROPIC-API-KEY` |
| GCP Secret Manager | `superbot-users-u1a2b3c4d-ANTHROPIC_API_KEY` |
| AWS Secrets Manager | `superbot/users/u1a2b3c4d/ANTHROPIC_API_KEY` |

botd's access above already covers them on Azure and Google; on AWS, add `superbot/users/*` as in the policy above. botd only reads: your own tooling and policies decide who writes each folder.

- **Order** for a user's Bots: their folder, then what they saved in the app (Your secrets), then the server-wide secrets. Another user's folder is never read.
- **Which names**: only names a user may save. Reserved names and botd's own (`LINODE_TOKEN`, `SSO_*`, ...) are ignored there. Ids are lowercase letters and digits; a user whose id has anything else gets no folder.
- **In the app** the user sees each name as set by an admin in that store, with no way to replace it. A copy they saved before can still be deleted.
- **Cache, outages and audit** are as for the shared folders: a run whose owner's folder can't be read is refused (`secrets_unavailable`), and reads are `secret.read` with `scope: users` and `userId`. Values are redacted from that user's Bots.
- **Cost**: Key Vault and Secret Manager list every secret in the vault or project to find one user's, once per user per `SECRETS_CACHE_SECONDS`. With thousands of secrets, give SuperBot a vault or project of its own.
- **When someone leaves**: deleting the user in botd drops what they saved in the app, not their folder. Delete those secrets in the store.

## Short-lived AWS credentials for each run

Off by default ([ADR 0190](../adr/0190-sts-sessions-for-each-run.md)); only with `SECRETS_BACKEND=aws`. With `AWS_RUN_CREDENTIALS`, botd assumes an IAM role with STS (`AssumeRole`) as each run starts and gives the run that session's keys. A key a Bot leaks stops working soon after its run. No Vault is needed; for Vault's engines, see [Vault](vault.md#short-lived-credentials-for-each-run).

Make a role for the Bots, with only what they need, that botd's identity may assume:

```json
{
  "Version": "2012-10-17",
  "Statement": [{ "Effect": "Allow", "Principal": { "AWS": "arn:aws:iam::<account>:role/botd" }, "Action": "sts:AssumeRole" }]
}
```

and let botd's identity assume it (add a statement like this to botd's policy above):

```json
{ "Effect": "Allow", "Action": "sts:AssumeRole", "Resource": ["arn:aws:iam::<account>:role/superbot-bots", "arn:aws:iam::<account>:role/superbot-u-*"] }
```

Then in `.env`:

```sh
AWS_RUN_CREDENTIALS="arn:aws:iam::<account>:role/superbot-bots"
# or several, naming the variables each gives:
# AWS_RUN_CREDENTIALS="arn:aws:iam::<account>:role/superbot-bots; arn:aws:iam::<account>:role/superbot-u-{owner} OWN_AWS_ACCESS_KEY_ID=AccessKeyId OWN_AWS_SECRET_ACCESS_KEY=SecretAccessKey OWN_AWS_SESSION_TOKEN=SessionToken"
```

- **Format**: entries separated by `;` or new lines. Each is a role's ARN, then `NAME=field` pairs, where the field is `AccessKeyId`, `SecretAccessKey` or `SessionToken`. An entry with no pairs gives `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` and `AWS_SESSION_TOKEN`, which AWS's SDKs and CLI read. These names are allowed even when botd signs in with access keys of its own under them: the run gets the session's keys, never botd's. At most 16 roles; each name once.
- **`{owner}`** in the role's name is the Bot owner's id (`botctl users`), so each user's Bots can have their own role. Those roles are assumed only for runs that get the owner's own secrets, not a teammate's run of an isolated shared Bot.
- **Session length**: each session lasts as long as the longest run (`RUN_TIMEOUT_MINUTES`, 60 by default), at least STS's 15 minutes. The role's maximum session duration must be at least that. If botd's own identity is itself a role (web identity, container credentials, instance profile), AWS limits the sessions it makes to an hour, so keep `RUN_TIMEOUT_MINUTES` at 60 or less. A run longer than 12 hours can't be covered and is refused.
- **CloudTrail**: each session is named `superbot-<bot id>-<random>`, so CloudTrail shows which Bot's run made each call.
- **Can't be revoked**: STS has no way to end one session early. When the run ends, botd audits `secret.lease_released` with the session's expiry (`expiresAt`), and the keys work until then. A short `RUN_TIMEOUT_MINUTES` keeps that short. To cut off every session of a role at once, use the IAM console's "Revoke active sessions" on the role.
- **Fails closed**: if STS refuses (no permission, a role it can't assume, a session shorter than the run), the run doesn't start (`bot.run_refused`, reason `secrets_unavailable`). botd makes no session at startup, so a wrong ARN or policy shows on the first run.
- **Audit**: `botctl audit --action 'secret.lease_*'` shows each session made (`secret.lease_issued`, with the role, the assumed role's ARN as `leaseId`, TTL and the variable names) and let go (`secret.lease_released`), never a key.
- **Redaction**: the keys are redacted from everything botd saves and shows until the session expires.
- **Order**: these win over static secrets of the same name, and runs never inherit these names from botd's own environment.

## Day to day

- **Rotate**: add a new version (`az keyvault secret set ...`, `gcloud secrets versions add ...`, `aws secretsmanager put-secret-value ...`). botd uses it within `SECRETS_CACHE_SECONDS`, with no restart. Settings botd reads only at startup (Stripe, Linode, Incus, Turnstile, metrics and backup keys) need a restart.
- **Retire a key**: delete it. Disabling it (or its latest version on Google) is treated as an error, not as "not there", so Bot runs stop until it is deleted or enabled again. botd never falls back to an older copy. On AWS, a secret scheduled for deletion counts as deleted at once (botd checks with `DescribeSecret`); a new secret can take a few minutes to show in `botctl secrets`, because AWS's list is eventually consistent, but reads by name see it at once.
- **When the store is down**: the same as [for Vault](vault.md#when-vault-is-down). Cached answers stand for the cache time. After that, Bot runs are refused (`bot.run_refused`, reason `secrets_unavailable`) and `GET /api/secrets` answers 503.

## Turning it off

Copy any keys you still need into `.env` or `botctl secret set`, remove `SECRETS_BACKEND` (or set `local`), and restart.
