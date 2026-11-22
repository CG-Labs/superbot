# 0136: Azure Key Vault and GCP Secret Manager as secrets backends

## Status

Accepted (22 Nov 2026). Part of secrets vault integration in M5, [#55](https://github.com/CG-Labs/superbot/issues/55). Builds on the external secrets backend ([ADR 0125](0125-external-secrets-backend-vault.md)), which added HashiCorp Vault behind a `Provider` trait.

Numbered 0136 because 0131 to 0135 are held by other open PRs.

## Context

ADR 0125 put an `ExternalStore` between the environment and the sealed store. It handles the folders, cache, fail-closed reads, redaction and audit for any `Provider`, and Vault was the first provider. #55 also asks for Azure Key Vault and GCP Secret Manager. Enterprises on Azure or Google Cloud keep their keys there, and don't want to run a Vault just for botd.

What each needs that Vault doesn't:

- **Names.** Key Vault names allow only letters, digits and `-`, up to 127 characters, and are case-insensitive. Secret Manager ids allow letters, digits, `_` and `-`, up to 255. Neither has folders.
- **Sign-in.** Both use short-lived OAuth bearer tokens. On Azure they come from Microsoft Entra ID, through a managed identity, a service principal or a federated token. On Google Cloud they come from the metadata server or a service account key.
- **Replies.** Each has its own way of saying "disabled", "not there" and "no access".

## Options

1. **The vendors' SDKs** (`azure_security_keyvault_secrets` + `azure_identity`; `google-cloud-secretmanager` + `google-cloud-auth`). They bring large dependency trees (a second HTTP stack and gRPC/protobuf for Google), APIs that change often, and their own credential chains, which pick up whatever the environment offers. That last part is a risk for a server that starts harnesses. Rejected.
2. **Plain REST over botd's existing `reqwest` + rustls**, signing in by hand. Each call botd needs is one documented HTTP request (get a secret, list secrets, get a token). The only cryptography is an RS256 JWT for Google service account keys, which `aws-lc-rs` (already a dependency) signs. Chosen.

## Decision

### Configuration

`SECRETS_BACKEND` also takes `azure-keyvault` and `gcp-secret-manager`. Everything else is the same as for Vault: off by default, `SECRETS_CACHE_SECONDS`, the order (**environment, then the external store, then sealed**), read-only, and fail closed.

**Azure Key Vault**

| Setting | Default | Meaning |
|---------|---------|---------|
| `AZURE_KEYVAULT_URL` | (required) | `https://<vault>.vault.azure.net`. Sovereign clouds work too, and tokens are asked for that cloud's Key Vault resource |
| `AZURE_KEYVAULT_PREFIX` | `superbot` | Letters, digits, single `-` |
| `AZURE_KEYVAULT_AUTH` | `managed-identity` | `managed-identity`, `client-secret` or `workload-identity` |
| `AZURE_CLIENT_ID` | none | A user-assigned identity's client id; the app's for the other two |
| `AZURE_TENANT_ID` | | For `client-secret` and `workload-identity` |
| `AZURE_CLIENT_SECRET` (or `_FILE`) | | For `client-secret` |
| `AZURE_FEDERATED_TOKEN_FILE` | | For `workload-identity` (AKS sets it) |
| `AZURE_AUTHORITY_HOST` | `https://login.microsoftonline.com` | For sovereign clouds |

A managed identity's tokens come from the instance metadata service (`169.254.169.254`). On App Service, Functions and Container Apps, they come from `IDENTITY_ENDPOINT` with `IDENTITY_HEADER` when the platform sets them.

**GCP Secret Manager**

| Setting | Default | Meaning |
|---------|---------|---------|
| `GCP_SECRET_MANAGER_PROJECT` | the key's `project_id` | Project id |
| `GCP_SECRET_MANAGER_LOCATION` | none | Regional secrets, read from that region's endpoint (`secretmanager.<region>.rep.googleapis.com`), for data residency |
| `GCP_SECRET_MANAGER_ENDPOINT` | global or regional | Override, e.g. Private Service Connect |
| `GCP_SECRET_MANAGER_PREFIX` | `superbot` | Letters, digits, `_`, `-` |
| `GCP_SECRET_MANAGER_AUTH` | `metadata` | `metadata` or `service-account-key` |
| `GCP_SERVICE_ACCOUNT_KEY_FILE` (or the JSON itself in `GCP_SERVICE_ACCOUNT_KEY`) | | For `service-account-key` |
| `GCE_METADATA_HOST` | `169.254.169.254` | The metadata server, as Google's libraries read it |

### Names

The two folders become a name prefix, so a name is still only read from its own folder:

| botd name, folder | Azure Key Vault | GCP Secret Manager |
|---|---|---|
| `OPENAI_API_KEY`, bots | `superbot-bots-OPENAI-API-KEY` | `superbot-bots-OPENAI_API_KEY` |
| `LINODE_TOKEN`, server | `superbot-server-LINODE-TOKEN` | `superbot-server-LINODE_TOKEN` |

On Azure, `_` becomes `-`. botd's names never contain `-`, so the mapping is reversible. Key Vault ignores case, so listing upper-cases what follows the prefix. A name too long for the service can't exist there and counts as not there without asking. On Google, botd reads the `latest` version.

### Replies, and failing closed

As with Vault, only "there is no such secret" lets the next store answer. Everything else is `Error::Unavailable`, so it can't uncover a sealed copy:

- **Not there** (`None`): Key Vault's 404 (including a soft-deleted secret), Secret Manager's 404 (no such secret, or no versions), or an empty value.
- **Error**: a disabled Key Vault secret (403), a disabled or destroyed latest version on Google (400 `FAILED_PRECONDITION`), any other refusal or 5xx, a reply without a value, a payload whose CRC32C is missing, malformed or doesn't match, a payload that isn't UTF-8, a list reply of the wrong shape, a Key Vault list page that points to another host, and a list longer than 1000 pages.

To retire a key, delete it. Disabling it stops Bot runs until it is deleted or enabled again, which is louder, but never serves a value the operator meant to replace.

### Sign-in

Tokens are kept and renewed two thirds of the way through their life. When the service answers 401, botd gets a new token once and retries. Each sign-in is audited as `secret.backend_login` with the store and the method, never a credential. Error messages carry the HTTP status and the reply's short error code (`invalid_client`, `PERMISSION_DENIED`), never its description, which can quote what was sent.

Requests to the metadata and identity endpoints never go through a proxy. Requests to Key Vault, Entra ID, Secret Manager and Google's token endpoint follow no redirects, so a token is never sent anywhere else. A service account key's `token_uri` must be `https`.

### Shared plumbing

The runtime, request permits and abandoned-request skipping that Vault's client had move to `secrets/http.rs` (`Worker`), along with the HTTP client builder, base-URL checks, bearer tokens and sign-in audit. All three providers use it, and Vault behaves as before.

### Diagnostics

- **Startup**: settings are checked when botd starts, and both folders are listed, as for Vault. botd won't start on a bad setting or a backend it can't reach or sign in to. Settings for a backend other than the one chosen (`AZURE_KEYVAULT_URL` with `SECRETS_BACKEND=local`, say) are named in a warning.
- **Setup report**: `GET /api/setup` has `secretsBackend`: which backend, its description, its cache time, whether it answers now (asked straight from the backend, not the cache) and how many names it has, or why not.
- **botctl**: `botctl secrets backend` prints that and exits non-zero when the backend doesn't answer. `botctl setup` mentions a backend that doesn't answer.

### Keeping the credentials from Bots

`AZURE_CLIENT_SECRET`, `AZURE_FEDERATED_TOKEN`, `IDENTITY_HEADER` and `GCP_SERVICE_ACCOUNT_KEY` are reserved, so a `_FILE` setting such as `AZURE_FEDERATED_TOKEN_FILE` is never offered to Bots under its stem either. They can't be saved as Bot secrets and are never read from an external store. They, their `_FILE` variables, and `AZURE_FEDERATED_TOKEN_FILE` are removed from the environment of every harness, screen and job botd starts.

## Consequences

- Nothing changes unless `SECRETS_BACKEND` names one of these backends. No new crates.
- Tested against stand-ins for Key Vault, Entra ID, both managed identity endpoints, Secret Manager, Google's token endpoint (checking the JWT's RS256 signature) and the metadata server, in `server/src/secrets/azure.rs` and `gcp.rs`. No real cloud, account or network.
- Threat model: as in ADR 0125, anyone who can run code as botd's user can use botd's identity. With a managed identity or the metadata server, that includes **any process on the same VM that can reach `169.254.169.254`**, which means Bots running on botd's own host. Run Bots on their own machines, whose egress rules block metadata addresses ([ADR 0126](0126-per-user-machine-hardening.md)), or block the address on botd's host for everyone but botd's user. The guide shows how. With a service principal or key, keep the file readable by botd only.
- Access control is coarser than Vault's policies. On Azure, RBAC can be granted per vault or per secret, not per name prefix, so use a vault of its own for botd. On Google, IAM conditions on `resource.name` can grant the `bots` and `server` prefixes separately. Listing needs `secretmanager.secrets.list` on the project, which shows names, not values.
- Remaining on #55: per-user secrets in the external store, AWS Secrets Manager, Vault's Kubernetes and JWT sign-in, Azure certificate credentials, and short-lived credentials per run.
- Ops guide: [docs/ops/cloud-secrets.md](../ops/cloud-secrets.md).
