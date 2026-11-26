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

#### With a certificate

Off Azure, a certificate is safer than a client secret, and some tenants allow only certificates. The private key stays on botd's host; Entra gets a signed assertion that lasts 10 minutes ([ADR 0269](../adr/0269-azure-certificate-credentials.md)). Make a key and certificate, upload the certificate to the app, and give botd one PEM file with both:

```sh
umask 077   # the key is unencrypted: create every file readable only by you
openssl req -x509 -newkey rsa:3072 -nodes -days 365 -subj "/CN=superbot-botd" \
  -keyout key.pem -out cert.pem
az ad app credential reset --id <app-client-id> --cert @cert.pem --append
cat cert.pem key.pem > /etc/superbot/azure/botd.pem
chown superbot: /etc/superbot/azure/botd.pem && chmod 600 /etc/superbot/azure/botd.pem
rm key.pem
```

```sh
AZURE_KEYVAULT_AUTH=client-certificate
AZURE_TENANT_ID=<tenant-id>
AZURE_CLIENT_ID=<app-client-id>
AZURE_CLIENT_CERTIFICATE_PATH=/etc/superbot/azure/botd.pem
```

The key must be RSA (`PRIVATE KEY` or `RSA PRIVATE KEY`). botd checks the file when it starts and again at each sign-in, so it stops on a missing key, a certificate for another key, or one out of date.

To rotate, upload the new certificate with `--append`, replace the file, then delete the old certificate from the app. botd uses the new file from its next sign-in, with no restart. If Entra refuses the certificate, botd's error gives its SHA-1 thumbprint, which the app's **Certificates & secrets** page lists. The same setting works for Vault's `azure` sign-in (`VAULT_AZURE_CREDENTIALS=client-certificate`) and the Azure Monitor audit sink (`AUDIT_EXPORT_AZURE_AUTH=client-certificate`). `AZURE_RUN_CREDENTIALS` needs a managed identity or workload identity instead.

##### A PFX file or an encrypted key

`AZURE_CLIENT_CERTIFICATE_PATH` can also be a PFX (PKCS#12) file, as Windows, Key Vault and most certificate authorities hand them out, or a PEM file whose key is encrypted (`ENCRYPTED PRIVATE KEY`). Give botd the password the same way the Azure SDKs take it ([ADR 0280](../adr/0280-pfx-files-and-encrypted-keys-for-entra-sign-in.md)):

```sh
AZURE_CLIENT_CERTIFICATE_PATH=/etc/superbot/azure/botd.pfx
AZURE_CLIENT_CERTIFICATE_PASSWORD_FILE=/run/credentials/botd.service/pfx_password
```

`AZURE_CLIENT_CERTIFICATE_PASSWORD` works too. Keep the password apart from the file it opens, for example in a systemd credential or a Kubernetes secret mounted on its own, so a copy of the certificate file alone is no use. A PFX with an empty password needs no setting. To download a certificate Key Vault made: `az keyvault secret download --vault-name <vault> --name <cert> --encoding base64 --file botd.pfx`.

- PFX files: AES-256 with PBKDF2 (OpenSSL 3's and Windows' `AES256-SHA256` default) and the older 3DES and RC2 schemes. The file's MAC is checked. It must hold one private key and its certificate, with or without the chain.
- Encrypted PEM keys: PKCS#8 with PBES2, as `openssl pkcs8 -topk8 -v2 aes-256-cbc` writes them. Older `Proc-Type: 4,ENCRYPTED` keys are refused, with that command to convert them.
- A wrong password fails closed before Entra is asked. botd says the password doesn't open the file and never logs the password. A password set for a PEM file whose key isn't encrypted is refused, so a wrong file isn't taken for the right one.
- If botd says a PFX file you gave no password is "a PFX file with a password", it was written with a null password rather than an empty one. Write it again with the password from its protected file, so it stays out of shell history and process lists: `umask 077; openssl pkcs12 -in old.pfx -passin pass: -nodes | openssl pkcs12 -export -passout file:/run/credentials/botd.service/pfx_password -out botd.pfx`.
- botd reads the password once, at startup. A renewed file must use the same password, or botd must restart.

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

Off by default ([ADR 0194](../adr/0194-sts-sessions-for-each-run.md)); only with `SECRETS_BACKEND=aws`. With `AWS_RUN_CREDENTIALS`, botd assumes an IAM role with STS (`AssumeRole`) as each run starts and gives the run that session's keys. A key a Bot leaks stops working soon after its run. No Vault is needed; for Vault's engines, see [Vault](vault.md#short-lived-credentials-for-each-run).

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
- **Session length**: each session lasts as long as the longest run (`RUN_TIMEOUT_MINUTES`, 60 by default), at least STS's 15 minutes. The role's maximum session duration must be at least that. If botd's own identity is itself a role (web identity, container credentials, instance profile), AWS limits the sessions it makes to an hour, so keep `RUN_TIMEOUT_MINUTES` at 60 or less. A run timeout longer than 12 hours can't be covered, so those runs are refused. A run also stops when its session expires. The time limit counts from when the harness starts and restarts if botd retries the harness, so a run can reach the session's end first. When it does, the Bot says its credentials expired and to send the task again.
- **CloudTrail**: each session is named `superbot-<bot id>-<random>`, so CloudTrail shows which Bot's run made each call.
- **Can't be revoked**: STS has no way to end one session early. When the run ends, botd audits `secret.lease_released` with the session's expiry (`expiresAt`), and the keys work until then. A short `RUN_TIMEOUT_MINUTES` keeps that short. To cut off every session of a role at once, use the IAM console's "Revoke active sessions" on the role.
- **Fails closed**: if STS refuses (no permission, a role it can't assume, a session shorter than the run), the run doesn't start (`bot.run_refused`, reason `secrets_unavailable`). botd makes no session at startup, so a wrong ARN or policy shows on the first run.
- **Audit**: `botctl audit --action 'secret.lease_*'` shows each session made (`secret.lease_issued`, with the role, the assumed role's ARN as `leaseId`, TTL and the variable names) and let go (`secret.lease_released`), never a key.
- **Redaction**: the keys are redacted from everything botd saves and shows until the session expires.
- **Order**: these win over static secrets of the same name, and runs never inherit these names from botd's own environment.

### Narrowing each run's session

Off by default ([ADR 0230](../adr/0230-session-policies-and-tags-for-each-run.md)). An entry can narrow each run's session below what its role allows, so one role can serve every Bot and user without a role per owner. Add any of these after the role's ARN, among its `NAME=field` pairs:

- **`policy=<file>`**: an inline session policy, a JSON IAM policy in a file botd can read (no spaces in the path). The session gets only what both the role and this policy allow. `{owner}` and `{bot}` in its strings are the run's owner id and Bot id. botd reads it once at startup, and won't start if it isn't JSON with a `Statement`, is over STS's 2048 characters with spaces taken out, or has characters past U+00FF. Restart botd after editing it.
- **`policy-arn=<arn>`**: a managed policy, used the same way (up to 10, in the role's partition; `{owner}` allowed in its name). Use these when the inline policy gets too long.
- **`tags=bot`, `tags=owner` or `tags=bot,owner`**: session tags `superbot-bot=<bot id>` and `superbot-owner=<owner id>`, so the role's own policies can match on `aws:PrincipalTag/superbot-owner`. They are transitive: a session the run chains from this one keeps them and can't set its own under those keys. Tags need `sts:TagSession` as well as `sts:AssumeRole`, in botd's policy and in the role's trust policy.

```sh
AWS_RUN_CREDENTIALS="arn:aws:iam::<account>:role/superbot-users policy=/etc/superbot/run-policy.json tags=bot,owner"
```

```json
{
  "Version": "2012-10-17",
  "Statement": [{ "Effect": "Allow", "Action": ["s3:GetObject", "s3:PutObject"], "Resource": "arn:aws:s3:::<bucket>/users/{owner}/*" }]
}
```

The trust policy for tags:

```json
{
  "Version": "2012-10-17",
  "Statement": [{ "Effect": "Allow", "Principal": { "AWS": "arn:aws:iam::<account>:role/botd" }, "Action": ["sts:AssumeRole", "sts:TagSession"] }]
}
```

And a role policy that limits each user's runs to their own folder by tag, with no session policy at all:

```json
{ "Effect": "Allow", "Action": "s3:*", "Resource": "arn:aws:s3:::<bucket>/users/${aws:PrincipalTag/superbot-owner}/*" }
```

- **The owner's runs only**: an entry whose policy, managed policy or tags name the owner (`{owner}`, `tags=owner`) is used only for runs that get the owner's own secrets, like a role with `{owner}`. A teammate's run of an isolated shared Bot gets no session from it.
- **Fails closed**: if a run's policy is over 2048 characters once its ids are in, or a Bot's id isn't letters, digits, `-` and `_`, the run is refused (`secrets_unavailable`) before STS is asked. If STS refuses, the error names the likely cause: `sts:TagSession` for `AccessDenied` with tags, the policies for `MalformedPolicyDocument`, and their size for `PackedPolicyTooLarge` (STS packs the policies and tags together, so use `policy-arn=` or fewer tags).
- **Audit**: `secret.lease_issued` adds `policySha256` (the SHA-256 of the policy as sent: compact, keys sorted, the run's ids in, as `jq -jcS . <file>` prints it once you put them in), `policyArns` and `tags`. Never the policy file's path or a key.

## Short-lived GCP credentials for each run

Off by default ([ADR 0203](../adr/0203-gcp-service-account-tokens-for-each-run.md)); only with `SECRETS_BACKEND=gcp-secret-manager`. With `GCP_RUN_CREDENTIALS`, botd impersonates a service account as each run starts (IAM Credentials' `generateAccessToken`) and gives the run that account's access token. No service account key is made or stored, and a token a Bot leaks stops working soon after its run. No Vault is needed; for Vault's GCP engine, see [Vault](vault.md#short-lived-credentials-for-each-run).

Make a service account for the Bots, with only the roles they need, and let botd's own service account make tokens for it:

```sh
gcloud services enable iamcredentials.googleapis.com
gcloud iam service-accounts create superbot-bots
gcloud iam service-accounts add-iam-policy-binding superbot-bots@<project>.iam.gserviceaccount.com \
  --member=serviceAccount:<botd's account> --role=roles/iam.serviceAccountTokenCreator
```

Then in `.env`:

```sh
GCP_RUN_CREDENTIALS="superbot-bots@<project>.iam.gserviceaccount.com"
# or several, naming the variable each gives:
# GCP_RUN_CREDENTIALS="superbot-bots@<project>.iam.gserviceaccount.com; superbot-u-{owner}@<project>.iam.gserviceaccount.com OWN_GCP_TOKEN=accessToken"
```

- **Format**: entries separated by `;` or new lines. Each is a service account's email, then `NAME=accessToken` pairs. An entry with no pairs gives the token as `CLOUDSDK_AUTH_ACCESS_TOKEN`, which gcloud reads, and `GOOGLE_OAUTH_ACCESS_TOKEN`, which Terraform's Google provider reads. Google's client libraries read neither; code using them builds credentials from one of these variables. At most 16 accounts; each name once.
- **`{owner}`** before the `@` is the Bot owner's id (`botctl users`), so each user's Bots can have their own account (`superbot-u-{owner}`). Grant botd the Token Creator role on each one; Google has no wildcard for it. A service account id is at most 30 characters, so a longer one is refused before any request. Those accounts are used only for runs that get the owner's own secrets, not a teammate's run of an isolated shared Bot.
- **Token length**: each token lasts as long as the longest run (`RUN_TIMEOUT_MINUTES`, 60 by default), at least Google's 5 minutes. Google allows an hour unless the organization policy `constraints/iam.allowServiceAccountCredentialLifetimeExtension` lists the account, which allows up to 12 hours; keep `RUN_TIMEOUT_MINUTES` at 60 or less otherwise. A run timeout longer than 12 hours can't be covered, so those runs are refused. A run also stops when its token expires, and the Bot says its credentials expired and to send the task again.
- **Can't be revoked**: Google can't end one token early. When the run ends, botd audits `secret.lease_released` with the token's expiry (`expiresAt`), and the token works until then. In an emergency, disable the service account (`gcloud iam service-accounts disable ...`) or put an IAM deny policy on it: that stops every token it has.
- **Fails closed**: if Google refuses (botd lacks the role, the API is off, no such account, a lifetime the policy doesn't allow), the run doesn't start (`bot.run_refused`, reason `secrets_unavailable`), and the error names what to check. botd makes no token at startup, so a wrong email or role shows on the first run.
- **Audit**: `botctl audit --action 'secret.lease_*'` shows each token made (`secret.lease_issued`, with the account, a `leaseId` of `<email>/superbot-<bot id>-<random>`, TTL and the variable names) and let go (`secret.lease_released`), never a token. Google's own audit logs record the call as botd's account using the Bots' account.
- **Redaction**: the token is redacted from everything botd saves and shows until it expires.
- **Order**: these win over static secrets of the same name, and runs never inherit these names from botd's own environment.
- **Private Service Connect**: set `GCP_IAM_CREDENTIALS_ENDPOINT` to its endpoint (https only).

### Downscoping each run's GCP token

Off by default ([ADR 0240](../adr/0240-downscoped-gcp-tokens-for-each-run.md)). An entry can limit each run's token to some Cloud Storage buckets, roles and objects with a [Credential Access Boundary](https://cloud.google.com/iam/docs/downscoping-short-lived-credentials), so one service account can serve every Bot and user without an account per owner. botd makes the account's token as above, trades it at Google's Security Token Service for a downscoped one, and gives the run only that one.

Add `boundary=<file>` after the email: a boundary in Google's JSON, in a file botd can read (no spaces in the path). `{owner}` and `{bot}` in its strings are the run's owner id and Bot id. The token can do only what both the account's roles and the boundary allow.

```sh
gcloud services enable sts.googleapis.com
GCP_RUN_CREDENTIALS="superbot-users@<project>.iam.gserviceaccount.com boundary=/etc/superbot/run-boundary.json"
```

```json
{
  "accessBoundary": {
    "accessBoundaryRules": [{
      "availableResource": "//storage.googleapis.com/projects/_/buckets/<bucket>",
      "availablePermissions": ["inRole:roles/storage.objectAdmin"],
      "availabilityCondition": {
        "expression": "resource.name.startsWith('projects/_/buckets/<bucket>/objects/users/{owner}/') || api.getAttribute('storage.googleapis.com/objectListPrefix', '').startsWith('users/{owner}/')"
      }
    }]
  }
}
```

Grant the account the bucket roles once (here `roles/storage.objectAdmin` on `<bucket>`); the boundary keeps each run to its owner's folder. The second half of the condition lets a run list its own folder (`gcloud storage ls gs://<bucket>/users/<owner id>/`), since listing is checked against the bucket, not an object.

- **Checked at startup**: botd won't start unless the file is JSON of exactly this shape: 1 to 10 rules, each a bucket (`//storage.googleapis.com/projects/_/buckets/<bucket>`), a list of `inRole:<role>`, and optionally an `availabilityCondition` with an `expression` (and a `title` and `description`). A key botd doesn't know stops it, rather than letting Google drop it. Restart botd after editing the file.
- **Cloud Storage only**: Google honours boundaries for Cloud Storage alone, so other APIs refuse a downscoped token. For Bots that need both, add a second entry without a boundary, for an account with only the other roles, with its own variable names.
- **The owner's runs only**: an entry whose boundary names the owner (`{owner}`) is used only for runs that get the owner's own secrets, like an account with `{owner}`.
- **Fails closed**: a Bot id that isn't letters, digits, `-` and `_` refuses a run whose boundary names `{bot}`, before Google is asked. If STS refuses, the run doesn't start (`secrets_unavailable`): 400 points at the boundary (a role Google doesn't know, a condition that isn't CEL), 403 at the Security Token Service API. botd never gives the run the wider token instead.
- **Audit**: `secret.lease_issued` adds `boundarySha256` (the SHA-256 of the boundary as sent: compact, keys sorted, the run's ids in, as `jq -jcS . <file>` prints it once you put them in). Never the file's path or a token.
- **Token length**: the downscoped token ends when the impersonated one does (as long as the longest run), and can't be revoked either.
- **Private Service Connect**: set `GCP_STS_ENDPOINT` to its endpoint (https only).

## Short-lived Azure credentials for each run

Off by default ([ADR 0213](../adr/0213-entra-app-tokens-for-each-run.md)); only with `SECRETS_BACKEND=azure-keyvault`. With `AZURE_RUN_CREDENTIALS`, botd gets an access token of an Entra app as each run starts and gives it to the run. The app trusts botd's managed identity (or its AKS workload identity) as a federated credential, so no client secret is made or stored, and a token a Bot leaks stops working about an hour after its run started. No Vault is needed; for Vault's Azure engine, see [Vault](vault.md#short-lived-credentials-for-each-run).

botd must sign in with a **user-assigned** managed identity (`AZURE_CLIENT_ID`) and `AZURE_TENANT_ID`, or with workload identity. Entra doesn't accept a system-assigned identity or a client secret as another app's credential, so botd won't start with those and `AZURE_RUN_CREDENTIALS`.

Register an app for the Bots, give it only the roles they need, and let it trust botd's identity:

```sh
az ad app create --display-name superbot-bots            # note its appId and id
az ad sp create --id <app id>
az role assignment create --assignee <app id> --role Reader --scope /subscriptions/<subscription>
# Trust botd's user-assigned managed identity (its principal id, not its client id):
az ad app federated-credential create --id <app object id> --parameters '{
  "name": "superbot-botd",
  "issuer": "https://login.microsoftonline.com/<tenant>/v2.0",
  "subject": "<managed identity principal id>",
  "audiences": ["api://AzureADTokenExchange"]
}'
```

For AKS workload identity, use the cluster's OIDC issuer and `system:serviceaccount:<namespace>:<botd's service account>` as the subject instead. In US Government and China clouds the audience is `api://AzureADTokenExchangeUSGov` or `api://AzureADTokenExchangeChina`; botd picks it from `AZURE_AUTHORITY_HOST`.

Then in `.env`:

```sh
AZURE_RUN_CREDENTIALS="<app id>"
# or several, naming the resource and the variable each gives:
# AZURE_RUN_CREDENTIALS="<app id>; <storage app id>@storage.azure.com BLOB_TOKEN=accessToken"
```

- **Format**: entries separated by `;` or new lines. Each is an app's client id, optionally `@` the host of the resource its tokens are for (`storage.azure.com`, `vault.azure.net`, `graph.microsoft.com`, ...), then `NAME=accessToken` pairs. With no resource, tokens are for Azure Resource Manager in botd's cloud. An entry with no pairs gives the token as `AZURE_ACCESS_TOKEN`. No Azure tool reads a token from the environment by itself: use `Connect-AzAccount -AccessToken $env:AZURE_ACCESS_TOKEN -AccountId <app id>`, `curl -H "Authorization: Bearer $AZURE_ACCESS_TOKEN"`, or a static token credential in code. At most 16 apps; each name once. For another tenant, or an app per user, see [below](#another-tenant-or-each-users-own-app).
- **Token length**: Entra chooses it: 60 to 90 minutes by default. A token that ends before the longest run could (`RUN_TIMEOUT_MINUTES`, 60 by default) refuses the run, so keep `RUN_TIMEOUT_MINUTES` at 60 or less, or give the app a token lifetime policy that covers it. A run also stops when its token expires, and the Bot says its credentials expired and to send the task again.
- **Can't be revoked**: Entra can't end one token early. When the run ends, botd audits `secret.lease_released` with the token's expiry (`expiresAt`), and the token works until then. In an emergency, remove the app's federated credential or disable its service principal: no new tokens are made, and those out there run out.
- **Fails closed**: if Entra refuses (no federated credential trusting botd, an app not in the tenant, a resource that doesn't exist, a token shorter than a run), the run doesn't start (`bot.run_refused`, reason `secrets_unavailable`), and the error names what to check, never Entra's own description. botd makes no token at startup, so a wrong app id or trust shows on the first run.
- **Audit**: `botctl audit --action 'secret.lease_*'` shows each token made (`secret.lease_issued`, with the entry, a `leaseId` of `<entry>/superbot-<bot id>-<random>`, TTL and the variable names) and let go (`secret.lease_released`), never a token. The managed identity token botd trades is audited as `secret.backend_login` with its `audience`. Entra's sign-in logs show the app's service principal signing in with botd's managed identity as its credential.
- **Redaction**: the token is redacted from everything botd saves and shows until it expires.
- **Order**: these win over static secrets of the same name, and runs never inherit these names from botd's own environment.

### Another tenant, or each user's own app

Off by default ([ADR 0250](../adr/0250-cross-tenant-and-per-user-entra-apps-for-each-run.md)). Two entry options, after the app:

- **`tenant=<tenant id or domain>`**: tokens of a **multitenant** app from another tenant it is provisioned in. Register the app in botd's tenant as multitenant (`az ad app create --sign-in-audience AzureADMultipleOrgs ...`), keep its federated credential trusting botd there as above (issuer still `https://login.microsoftonline.com/<botd's tenant>/v2.0`), and have an admin of the other tenant consent to it (`https://login.microsoftonline.com/<other tenant>/adminconsent?client_id=<app id>`) and give its service principal the roles the Bots need there. Same cloud only.
- **`{owner}` as the app, with `apps=<file>`**: each user's Bots get a token of their own app. The file maps user ids (from `botctl users` or the admin console) to apps, and optionally each user's tenant:

```sh
AZURE_RUN_CREDENTIALS="{owner} apps=/etc/superbot/azure-apps.json; <shared app id> tenant=contoso.onmicrosoft.com SHARED_AZURE_TOKEN=accessToken"
```

```json
{
  "<user id>": "<their app id>",
  "<another user id>": { "app": "<their app id>", "tenant": "<their tenant id or domain>" }
}
```

Each app needs the federated credential trusting botd, like any other. A user's `tenant` wins over the entry's `tenant=`, which wins over botd's own.

- **Checked at startup, read at each run**: botd won't start unless the file is a JSON object of user ids and app client ids (or `{"app": ..., "tenant": ...}`, nothing else), at most 1 MiB. It reads it again as each run that uses it starts, so adding or taking out a user needs no restart. Write it in one go (to a new file, then rename it over the old one).
- **Users it doesn't name** get no token from that entry, and its variables are kept out of their runs. Runs for someone other than the owner never use it, as with any `{owner}` entry.
- **Fails closed**: if the file can't be read or checked when a run starts, that run doesn't start (`secrets_unavailable`), and botd never uses the map it read earlier. An app not consented in the other tenant gives `unauthorized_client`, and the error asks whether the app is multitenant and consented there.
- **Audit**: `secret.lease_issued` names the actual app in its `path`, the `userId` for an `apps=` entry, and `tenant` when it isn't botd's own.
- **Who decides**: whoever can edit the file decides which app each user's Bots act as. Keep it with botd's configuration, writable only by its admins. It holds no secret.

## Day to day

- **Rotate**: add a new version (`az keyvault secret set ...`, `gcloud secrets versions add ...`, `aws secretsmanager put-secret-value ...`). botd uses it within `SECRETS_CACHE_SECONDS`, with no restart. To use it now, after a leak, run `botctl secrets refresh NAME` (or no names for everything cached): botd reads it again at once, says whether it changed, and fails closed if the store can't answer ([details](vault.md#rotating-a-value-now), [ADR 0291](../adr/0291-refreshing-the-external-secrets-cache.md)). Settings botd reads only at startup (Stripe, Linode, Incus, Turnstile, metrics and backup keys) need a restart; the refresh names those whose value changed.
- **Retire a key**: delete it. Disabling it (or its latest version on Google) is treated as an error, not as "not there", so Bot runs stop until it is deleted or enabled again. botd never falls back to an older copy. On AWS, a secret scheduled for deletion counts as deleted at once (botd checks with `DescribeSecret`); a new secret can take a few minutes to show in `botctl secrets`, because AWS's list is eventually consistent, but reads by name see it at once.
- **When the store is down**: the same as [for Vault](vault.md#when-vault-is-down). Cached answers stand for the cache time. After that, Bot runs are refused (`bot.run_refused`, reason `secrets_unavailable`) and `GET /api/secrets` answers 503. The [secrets store runbook](../support/runbook-secrets.md) has every failure botd records and its fix.

## Turning it off

Copy any keys you still need into `.env` or `botctl secret set`, remove `SECRETS_BACKEND` (or set `local`), and restart.
