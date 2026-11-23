# 0213: Entra app tokens for each run

## Status

Accepted (23 Nov 2026). Part of secrets vault integration in M5, [#55](https://github.com/CG-Labs/superbot/issues/55). Builds on short-lived credentials for each run ([ADR 0185](0185-short-lived-credentials-per-run.md)), STS sessions for each run ([ADR 0194](0194-sts-sessions-for-each-run.md)) and GCP service account tokens for each run ([ADR 0203](0203-gcp-service-account-tokens-for-each-run.md)), which left Azure for later, and on Azure Key Vault as the external store ([ADR 0136](0136-cloud-secret-managers.md)).

## Context

AWS and Google Cloud shops without Vault can now give each run a credential that expires soon after it. Azure shops that use Key Vault as SuperBot's store (`SECRETS_BACKEND=azure-keyvault`) still have one way to give a Bot Azure access: a service principal's client secret in a store, which lasts until someone rotates it (up to two years).

ADR 0203 set Azure aside because a managed identity's token is botd's own identity, and a token of another app needs that app's secret. Entra has since made a third way generally available: an app registration can trust a **user-assigned managed identity as a federated identity credential** (May 2025). The workload asks its managed identity for a token for Entra's exchange audience (`api://AzureADTokenExchange`), then sends that token as a client assertion to Entra's token endpoint with the app's client id, and gets the app's access token. No secret exists. AKS workload identity works the same way: the federated token the platform writes for botd's pod can be the assertion for any app with a federated credential trusting that service account.

Entra access tokens can't be revoked (outside the few resources with continuous access evaluation) and their lifetime isn't chosen by the caller: about an hour, 60 to 90 minutes by default, or what a token lifetime policy on the app says.

## Options

1. **A client secret per run** (Microsoft Graph `addPassword`, `removePassword` at run end). Revocable, but botd would need `Application.ReadWrite.OwnedBy` or more in Graph, which lets it mint credentials for apps; a secret botd fails to remove lasts until its end date; secrets take time to replicate. Rejected.
2. **botd's own managed identity token for each run.** That is botd's identity, which reads every user's folder in Key Vault. Rejected.
3. **The Azure CLI's login per run** (`az login --federated-token` in the run). Hands the run a federated assertion that trades for any app trusting botd. Rejected.
4. **Trade botd's managed identity or workload identity token for an app's token** with the federated credential exchange, as each run starts, and let it go at its expiry. Chosen: what Microsoft recommends over secrets, botd needs no Graph permission and no secret, Entra checks the trust on every exchange, and it fits ADR 0194's path for leases that can't be revoked unchanged.

## Decision

### Setting

`AZURE_RUN_CREDENTIALS` (off when empty; only with `SECRETS_BACKEND=azure-keyvault`, warned about and ignored otherwise), written like `GCP_RUN_CREDENTIALS`: entries separated by `;` or new lines, each an app and then `NAME=field` pairs.

```sh
AZURE_RUN_CREDENTIALS="<app client id>; <app client id>@storage.azure.com BLOB_TOKEN=accessToken"
```

- An entry is the app registration's client id (a GUID), optionally `@` the host of the resource its tokens are for. With no resource, tokens are for Azure Resource Manager in botd's cloud (`management.azure.com`, `management.usgovcloudapi.net` or `management.chinacloudapi.cn`, from `AZURE_AUTHORITY_HOST`), which is what Azure PowerShell and plain REST calls to Azure need. Hosts are lowercase DNS names only, so the scope is always `https://<host>/.default`.
- No `{owner}`: Entra picks app ids, so a per-user app can't be named from a user id. Left for later (a mapping file, if asked).
- The one field is `accessToken`; an entry with no pairs gives it as `AZURE_ACCESS_TOKEN`. No Azure tool reads a bare token from the environment (the Azure Identity libraries, `az` and Terraform's `azurerm` all sign in themselves, with a secret, a certificate, an assertion or a managed identity), so the name is plain and documented: `Connect-AzAccount -AccessToken`, `curl -H "Authorization: Bearer $AZURE_ACCESS_TOKEN"`, or a few lines of static token credential in code. Giving the run an assertion instead would let it trade for every app that trusts botd.
- The 16-entry limit, unique names, checks at startup and nothing made at startup work as in ADR 0185, through the shared `leases::Syntax` (`leases::AZURE`).

botd must sign in to Key Vault in a way Entra accepts as another app's credential, checked at startup:

- `AZURE_KEYVAULT_AUTH=managed-identity` with `AZURE_CLIENT_ID` (a **user-assigned** identity; Entra refuses system-assigned ones as federated credentials) and `AZURE_TENANT_ID` (the tenant of the identity and the apps; it is the token endpoint's path). The managed identity's token for the exchange audience comes from the same instance metadata service or platform identity endpoint as Key Vault's, and is kept while it lasts (renewed two thirds through).
- `workload-identity`: the token in `AZURE_FEDERATED_TOKEN_FILE`, read afresh for each run, as for Key Vault.
- `client-secret` is refused: a secret can't be another app's federated credential.

The exchange audience follows the cloud: `api://AzureADTokenExchange`, `...USGov` for `login.microsoftonline.us`, `...China` for `login.chinacloudapi.cn`.

### A run's tokens

As a run starts, at the same point as the other backends' leases, botd posts to `<authority>/<tenant>/oauth2/v2.0/token` for each entry: `grant_type=client_credentials`, the app's `client_id`, `client_assertion_type=...jwt-bearer`, botd's assertion, and `scope=https://<resource>/.default`. When Entra answers `invalid_client` to a kept managed identity token, botd gets a new one and asks once more.

The answer must have a printable token of at most 16 KiB and a lifetime; a token that ends more than a minute before the run could (`RUN_TIMEOUT_MINUTES`) is refused, naming Entra's default lifetime and the token lifetime policy. Errors name only Entra's status and error code, never its description (which can quote the request), with a hint: `invalid_client` names the federated credential to add (issuer `<authority>/<tenant>/v2.0` and the identity's object id, or the cluster's issuer and service account, and the audience), `unauthorized_client` asks whether the app is registered in the tenant, and `invalid_scope` whether the resource exists in this cloud.

The lease id is botd's own handle, `<entry>/superbot-<bot id>-<random>`, unique per run and not secret; Entra's sign-in logs record the app's service principal sign-in with botd's managed identity as its credential.

As with STS sessions and Google's tokens, a run stops when its first token expires (`Leases::expires_first`), each token is audited as `secret.lease_released` with `revocable: false` and `expiresAt` at run end, and its value stays redacted until it expires. The managed identity's exchange token is audited as `secret.backend_login` with `audience`, and never leaves botd except to Entra.

### Code

`azure::KeyVault` implements `Issuer` (its worker is now shared, as GCP's, so the store and the issuer use one client, one runtime and one cached identity). `Config` gains `tenant` and `run_credentials_ok`; the managed identity request and the federated token read are shared with Key Vault's sign-in. `leases` gains `AZURE`. No change to the runner.

## Consequences

- No change unless `AZURE_RUN_CREDENTIALS` is set with `SECRETS_BACKEND=azure-keyvault`.
- The operator adds a federated credential to each app (Entra admin center: Certificates & secrets, Federated credentials, scenario "Managed Identity"; or the cluster's issuer for AKS) and gives the app the roles the Bots need. Anyone who can change an app's federated credentials decides what botd can act as; botd can then act as every listed app, as it can read every user's folder: run Bots on their own machines so a Bot can't use botd's identity (ADR 0136).
- A leaked token works until it expires, about an hour after its run started, not until the run ends. The guide says so, and that disabling the app's service principal or removing its federated credential stops new tokens; existing ones run out.
- `RUN_TIMEOUT_MINUTES` over 60 refuses runs unless the app has a token lifetime policy that covers them. Entra chooses lifetimes, so botd can only check.
- One managed identity token now and then and one Entra request per app as each run starts; none as it ends.
- Cross-tenant apps (a multitenant app provisioned in another tenant) and per-user apps are left for later.
- Tested in `server/src/secrets/leases.rs` (the entry syntax and default name) and `server/src/secrets/azure.rs`, against a stand-in Entra that accepts only an exchange-audience token it made or the federated token: a new token per run under the default and named variables, Resource Manager by default and a named resource, one managed identity token kept across runs and renewed when Entra refuses it, the federated token read afresh, the audit with the lease id and no token, let go and kept redacted at run end, refusals (`invalid_client`, `unauthorized_client`, `invalid_scope`, a short token, an odd answer, Entra down) without Entra's descriptions, the settings botd refuses, and each cloud's audience and Resource Manager. A run stopping at its token's expiry is covered on the real router by `run_credentials_http_tests.rs` (ADR 0194).
- Ops guide: [docs/ops/cloud-secrets.md](../ops/cloud-secrets.md#short-lived-azure-credentials-for-each-run).
