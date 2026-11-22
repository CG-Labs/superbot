# Reading secrets from Azure Key Vault or GCP Secret Manager

botd can read its secrets from Azure Key Vault or Google Cloud Secret Manager instead of, or as well as, `.env` and the sealed store. It is off by default. It works like the [Vault backend](vault.md): read-only, cached, fails closed, and every read is audited. Design: [ADR 0136](../adr/0136-cloud-secret-managers.md), on top of [ADR 0125](../adr/0125-external-secrets-backend-vault.md).

## What goes where

Each name is one secret. Its name says which folder it is in:

| Folder | Holds | Reaches Bots | Azure Key Vault name | GCP Secret Manager id |
|--------|-------|--------------|----------------------|-----------------------|
| `bots` | Server-wide keys for Bots: `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `GITHUB_TOKEN`, ... | Yes, at the start of each run | `superbot-bots-OPENAI-API-KEY` | `superbot-bots-OPENAI_API_KEY` |
| `server` | botd's own: `LINODE_TOKEN`, `SSO_<ID>_CLIENT_SECRET`, `SMTP_PASSWORD`, `STRIPE_SECRET_KEY`, ... | Never | `superbot-server-LINODE-TOKEN` | `superbot-server-LINODE_TOKEN` |

Key Vault doesn't allow `_`, so write it as `-`. Case doesn't matter there. A name in the wrong folder is ignored. `AUTH_PASSWORD`, `SUPERBOT_MASTER_KEY` and the cloud credentials stay in `.env`, because botd needs them before it can sign in. Per-user secrets stay in botd's sealed store for now.

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

## Check it

Files must be readable by botd's service user only (`chmod 600`). Restart botd. The log says, for example:

```
Secrets backend: Azure Key Vault at https://<vault>.vault.azure.net, secrets superbot-{bots,server}-<NAME>, managed identity, cached for 300 s (2 names; SECRETS_BACKEND, ADR 0125).
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

A managed identity or the metadata server gives a token to **any process on the machine** that asks `169.254.169.254`. That includes Bots running on botd's own host. Either run Bots on their own machines, whose egress rules already block metadata addresses ([ADR 0126](../adr/0126-per-user-machine-hardening.md)), or block the address on botd's host for everyone but botd:

```sh
sudo iptables -A OUTPUT -d 169.254.169.254 -m owner ! --uid-owner superbot -j REJECT
```

Make the rule persistent with your distribution's tool. With a service principal or key, botd removes the credentials from every harness's environment, but the file must still be readable only by botd.

## Day to day

- **Rotate**: add a new version (`az keyvault secret set ...`, `gcloud secrets versions add ...`). botd uses it within `SECRETS_CACHE_SECONDS`, with no restart. Settings botd reads only at startup (Stripe, Linode, Incus, Turnstile, metrics and backup keys) need a restart.
- **Retire a key**: delete it. Disabling it (or its latest version on Google) is treated as an error, not as "not there", so Bot runs stop until it is deleted or enabled again. botd never falls back to an older copy.
- **When the store is down**: the same as [for Vault](vault.md#when-vault-is-down). Cached answers stand for the cache time. After that, Bot runs are refused (`bot.run_refused`, reason `secrets_unavailable`) and `GET /api/secrets` answers 503.

## Turning it off

Copy any keys you still need into `.env` or `botctl secret set`, remove `SECRETS_BACKEND` (or set `local`), and restart.
