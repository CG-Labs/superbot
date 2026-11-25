# 0260: Vault sign-in as botd's AWS, Google Cloud or Azure identity

## Status

Accepted (24 Nov 2026). Part of secrets vault integration in M5, [#55](https://github.com/CG-Labs/superbot/issues/55). Adds `Auth` cases to the HashiCorp Vault provider ([ADR 0125](0125-external-secrets-backend-vault.md)). ADR 0125 left "Kubernetes, JWT and cloud IAM sign-in" for later. [ADR 0159](0159-vault-kubernetes-and-jwt-sign-in.md) built the first two; this ADR builds the third. It reuses the cloud sign-ins botd already has for AWS Secrets Manager ([ADR 0146](0146-aws-secrets-manager.md)), GCP Secret Manager and Azure Key Vault ([ADR 0136](0136-cloud-secret-managers.md)).

Numbered 0260 because it is the number reserved for this slice; 0258, 0259, 0261 and 0262 are held by parallel work.

## Context

The roadmap marked #55 delivered after ADR 0250. But on a cloud VM or container with no Kubernetes, botd still needs a Vault credential on its disk: a token kept fresh by Vault Agent, or an AppRole SecretID someone has to deliver and rotate. ADR 0159's `jwt` method helps only where the platform writes a JWT to a file, which plain EC2, GCE and Azure VMs don't do.

Vault's own answer is its cloud auth methods. Each lets the cloud prove who botd is:

- **`aws`** (the `iam` type). The client signs an STS `GetCallerIdentity` request with its AWS keys but doesn't send it. Vault sends it to STS and learns the caller's IAM principal from the answer. Vault needs no AWS credentials for this.
- **`gcp`** (the `iam` type). The client gets a JWT for `vault/<role>`, signed by Google's IAM Credentials API as a service account, and Vault checks it against the account's public keys.
- **`azure`**. The client sends a managed identity's (or any Entra) access token for the mount's `resource`. Vault checks it against Entra's keys, plus optionally the VM's subscription, resource group and name.

botd already holds these identities for the cloud secret managers. It has AWS's whole credential chain with renewal, Google's metadata server and service account keys, and Entra's managed identity, client secret and workload identity. What was missing was the Vault side.

The other candidates for #55 were left for later. Harness logins in the external store are outside #55 (they're about harness CLIs' own files, not Vault). A Vault Agent-style token sink for Bots would hand Vault access to Bots, which ADR 0125 rules out.

## Options

1. **Leave it to Vault Agent.** Agent's auto-auth supports all three methods and writes a token that `VAULT_TOKEN_FILE` reads. This works today and stays supported. But it is one more process to run, patch and watch on every server, and botd learns only from Vault's refusals that the token is bad.
2. **A Vault or cloud SDK** (`vaultrs`, the AWS SDK, `google-cloud-auth`, `azure_identity`). Each of these is a large tree of dependencies for one or two requests, and the repo already signs SigV4 (`crate::sigv4`) and talks to IMDS, the metadata server and Entra over `reqwest`.
3. **Three more `Auth` cases in botd's own client, on the cloud sign-ins botd already has.** Chosen. The login reply is the same token-with-a-lease as AppRole, so renewal, re-login on refusal, namespaces and audit are shared.

## Decision

### Configuration

| Setting | Default | Meaning |
|---------|---------|---------|
| `VAULT_AUTH` | `token` | Now also `aws`, `gcp` or `azure` |
| `VAULT_AWS_ROLE` | the role named after botd's IAM principal (Vault's default) | The Vault role |
| `VAULT_AWS_MOUNT` | `aws` | Where the method is mounted |
| `VAULT_AWS_REGION` | `us-east-1` | The region of the mount's `sts_endpoint`: `us-east-1` signs for the global `sts.amazonaws.com`, as Vault's default and its CLI do; other regions sign for `sts.<region>.amazonaws.com` (`.com.cn` in China) |
| `VAULT_AWS_HEADER_VALUE` | none | The mount's `iam_server_id_header_value`, signed as `X-Vault-AWS-IAM-Server-ID` |
| `VAULT_AWS_CREDENTIALS` | `chain` | Where botd's own AWS keys come from: `chain`, `env`, `web-identity`, `container` or `instance-profile`, from the standard `AWS_*` settings, as `AWS_SECRETS_MANAGER_AUTH` |
| `VAULT_GCP_ROLE` | (required) | The Vault role |
| `VAULT_GCP_MOUNT` | `gcp` | Where the method is mounted |
| `VAULT_GCP_SERVICE_ACCOUNT` | botd's own account | The account the JWT is signed as |
| `VAULT_GCP_CREDENTIALS` | `metadata` | botd's own Google sign-in: `metadata` or `service-account-key` (`GCP_SERVICE_ACCOUNT_KEY_FILE`); `GCP_IAM_CREDENTIALS_ENDPOINT` for Private Service Connect |
| `VAULT_AZURE_ROLE` | (required) | The Vault role |
| `VAULT_AZURE_MOUNT` | `azure` | Where the method is mounted |
| `VAULT_AZURE_RESOURCE` | `https://management.azure.com/` | The mount's `resource`, which the token is for |
| `VAULT_AZURE_CREDENTIALS` | `managed-identity` | botd's own Entra sign-in: `managed-identity`, `client-secret` or `workload-identity`, from the standard `AZURE_*` settings, as `AZURE_KEYVAULT_AUTH` |
| `VAULT_AZURE_INSTANCE` | `0` | `1` sends the VM's subscription, resource group, and name or scale set, read from the instance metadata service |

All of these are checked when botd starts, and the existing check lists both folders, so a bad role, region, account or resource stops botd. `VAULT_AZURE_INSTANCE=1` needs a managed identity on a VM (no `IDENTITY_ENDPOINT`), since only IMDS has the details. The credentials settings are separate from the secret managers' own (`AWS_SECRETS_MANAGER_AUTH`, ...) because only one backend is on at a time, and Vault is the one here.

### Logging in

Every login proves who botd is afresh, at startup, two thirds of the way through the Vault token's lease, and whenever Vault refuses the token. This is the same code path as AppRole and ADR 0159's JWTs.

- **AWS.** botd takes its keys from the chain (`aws::Credentials`), the same type Secrets Manager uses, split out of it for this, with the same renewal two thirds of the way through temporary keys' life. It signs `POST https://<sts host>/` with body `Action=GetCallerIdentity&Version=2011-06-15`. The signed headers are `content-type`, `host`, `x-amz-date`, `x-amz-security-token` if there is one, and the server id header if set. botd sends Vault the method, the URL, the body and the headers, base64-encoded as the method wants. When Vault refuses the token, the next login fetches new keys too, since an expired session is the likeliest cause.
- **Google.** botd asks IAM Credentials' `signJwt` to sign `{"aud": "vault/<role>", "sub": <account>, "exp": now + 10 minutes}` as the account, with its own token (metadata server or key). The lifetime is 10 minutes because Vault's roles allow at most `max_jwt_exp` (15 minutes by default) and JWTs are used once. With no account set, botd uses its own: the key's email, or the metadata server's `service-accounts/default/email`. A 401 from IAM Credentials gets one new Google token and one retry. A 403 names the permission (`iam.serviceAccounts.signJwt`) and the API to turn on. botd checks the answer is a JWT before sending it.
- **Azure.** botd gets an Entra token for the mount's resource through `azure::Entra`, the same client Key Vault uses (managed identity, client secret or workload identity), and sends it with the role. The VM's details are opt-in. Vault checks them only for roles bound to them, and sending them where Vault's own Azure credentials can't read the VM breaks a login that would otherwise pass. A scale set's instance sends `vmss_name`, any other VM `vm_name`.

Errors from Vault are its status only, as for every other login (Vault's text can echo what was sent). Errors from Google and Entra carry their status and error code, never their description.

### Audit and redaction

Logins are still `secret.vault_login`, with `method` (`aws`, `gcp` or `azure`), `role` (for AWS, only when set), `namespace` when the login carried one, and `error`'s kind on failure. Fetching AWS keys from the chain is audited as `secret.backend_login` against the `vault` store, as Secrets Manager audits its own against `aws`. No key, signature, JWT or token reaches the audit log.

botd's AWS keys are registered with the redactor while botd holds them, by reference count (`redact::hold` / `release`), because Secrets Manager's run credentials and Vault's sign-in can hold the same instance profile keys. One letting go must not unmask the other's. The chain's credential names and the settings that lead to them are kept from Bots once chosen (`keep_from_bots`), as ADR 0146 does. Google's key and Entra's client secret were reserved already. The signed JWT and Entra token are used once and never stored, so they aren't registered. Bots never get them.

### Offline check

`botd offline check` ([ADR 0257](0257-checking-settings-for-air-gapped-networks.md)) lists what botd reaches to log in to Vault: the metadata servers or identity endpoint, IAM Credentials, Entra ID for a client secret or workload identity, and STS for web identity. The `aws` method's own STS request is sent by Vault, so it is on Vault's side and isn't listed.

## Consequences

- No change unless `VAULT_AUTH` is `aws`, `gcp` or `azure`. Secrets Manager's AWS sign-in works as before. Its credential code moved into `aws::Credentials` unchanged, and its error texts now name `AWS_SECRETS_MANAGER_AUTH` or `VAULT_AWS_CREDENTIALS`, whichever was used.
- On EC2, ECS, EKS, GCE, Cloud Run, GKE and Azure VMs, botd needs no Vault credential at all. The Vault role binds to botd's IAM role, service account or managed identity, and rotation is the cloud's job.
- Threat model: anyone who can get botd's cloud identity can log in to Vault as botd. That includes a Bot running on botd's machine, which can reach the instance metadata service. This is the same exposure as the cloud secret managers (ADR 0136, ADR 0146). Bots on their own machines are kept off metadata addresses by the egress rules ([ADR 0126](0126-per-user-machine-hardening.md)). For AWS, `iam_server_id_header_value` stops a signed request botd made being replayed to another Vault. Give the Vault role a policy that reads only `<prefix>/*`, as ADR 0125 says.
- Vault needs: STS reachable from Vault (AWS); `iam.serviceAccounts.get` and `iam.serviceAccountKeys.get` for its own Google credentials (Google); and for `VAULT_AZURE_INSTANCE=1`, read access to the VM (Azure). botd needs `iam.serviceAccounts.signJwt` on the account it signs as (Google). AWS's `GetCallerIdentity` needs no permission.
- Tested against stand-ins in `server/src/secrets/vault.rs`:
  - AWS: a login signed with keys from the environment, with the server id header and a region, checked as STS would by recomputing the SigV4 signature. Then keys from a stand-in IMDSv2, kept while they last and replaced when Vault refuses the token, and the old ones unmasked. The default role and the global endpoint, a wrong server id refused, and a missing instance profile failing closed before Vault is asked.
  - Google: the metadata server's account and token, the JWT's audience, subject and lifetime, another account, a revoked Google token renewed once, and a 403 naming the permission.
  - Azure: the managed identity's token for the resource, the VM's details for a scale set's instance, and refusals.
  - Settings, the offline check's findings, and the credentials kept from Bots.
  - On the real router (`server/src/vault_auth_http_tests.rs`), admins see AWS and Google logins and failures in the audit log with no key, signature, JWT or value, and members can't.
  - No cloud, Vault or network.
- Remaining on #55: none of what it names. Ideas for later, outside this slice: Vault's `aws` `ec2` type (PKCS#7 identity documents, which Vault itself calls less secure than `iam`), GCP's `gce` type (instance identity tokens), and AliCloud or OCI sign-in, if asked for.
- Ops guide: [docs/ops/vault.md](../ops/vault.md#cloud-sign-in-aws-google-cloud-azure).
