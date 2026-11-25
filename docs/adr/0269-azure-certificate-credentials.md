# 0269: botd signs in to Entra ID with a certificate

## Status

Accepted (25 Nov 2026). Part of secrets vault integration in M5, [#55](https://github.com/CG-Labs/superbot/issues/55). Adds a sign-in method to the Entra ID client that Azure Key Vault ([ADR 0136](0136-cloud-secret-managers.md)), Vault's `azure` sign-in ([ADR 0260](0260-vault-cloud-sign-in.md)) and the Azure Monitor audit sink ([ADR 0217](0217-audit-export-to-azure-monitor.md)) share. ADR 0136 and [ADR 0146](0146-aws-secrets-manager.md) listed "Azure certificate credentials" as remaining on #55. Later ADRs dropped it from that list without building it.

Numbered 0269 because it is the number reserved for this slice; 0264, 0268, 0270 and 0271 are held by parallel work.

## Context

The roadmap marked #55 delivered after ADR 0260. The issue asks for Azure Key Vault, GCP Secret Manager and HashiCorp Vault stores, and all three work. But one gap ADR 0136 named was still open. Off Azure, botd could sign in to Entra ID only with a client secret:

- A managed identity needs botd to run on Azure (a VM, scale set, App Service or Container Apps).
- Workload identity needs a platform that writes a federated token to a file (AKS, or another Kubernetes cluster Entra trusts).
- That leaves a server on premises or on another cloud with `AZURE_KEYVAULT_AUTH=client-secret`.

A client secret is a shared password. Entra sends it on every sign-in, and anyone who copies it can use it from anywhere until it expires. Microsoft recommends certificates over secrets for apps' own credentials ([certificate credentials](https://learn.microsoft.com/en-us/entra/identity-platform/certificate-credentials)). Many tenants forbid new client secrets by app management policy. With a certificate, the private key never leaves botd's host. Only a signed, short-lived assertion goes to Entra.

## Options

1. **Leave it to client secrets.** Works today, but not in tenants that forbid them, and it keeps a shared password on disk.
2. **An Azure SDK** (`azure_identity`). A large tree of dependencies for one token request, and every other Azure call botd makes is plain REST over `reqwest`.
3. **A fourth sign-in method in botd's own Entra client.** Chosen. botd already signs RSA JWTs for Google's service account keys, with `aws-lc-rs`, and parses X.509 with `x509-parser` for SAML. The token request is the same `client_credentials` grant that workload identity sends, with a different assertion, so caching, renewal, re-sign-in on refusal and audit are shared.

## Decision

### Configuration

| Setting | Meaning |
|---------|---------|
| `AZURE_KEYVAULT_AUTH`, `VAULT_AZURE_CREDENTIALS`, `AUDIT_EXPORT_AZURE_AUTH` | Each now also takes `client-certificate` |
| `AZURE_CLIENT_CERTIFICATE_PATH` | A PEM file with the app's certificate and its unencrypted RSA private key (PKCS#8 `PRIVATE KEY` or PKCS#1 `RSA PRIVATE KEY`). The file may also hold the certificate's chain |
| `AZURE_TENANT_ID`, `AZURE_CLIENT_ID` | The app registration's tenant and client id, as for `client-secret` |

The names are the Azure SDKs' own, so a file and settings that work with `az login --service-principal` or `DefaultAzureCredential` work with botd.

Two of the SDKs' settings are refused at startup rather than ignored:

- `AZURE_CLIENT_CERTIFICATE_PASSWORD`. botd doesn't read PFX files or encrypted keys. The error shows how to convert a PFX with `openssl pkcs12 -nodes`. A password stored next to the file it unlocks protects nothing that the file's mode doesn't.
- `AZURE_CLIENT_SEND_CERTIFICATE_CHAIN`. Subject name and issuer sign-in mostly serves Microsoft's own first-party apps. Uploading the certificate to the app registration is the supported path for others.

### Checking the file

The file is read and checked at startup, so a bad file stops botd before it serves anything:

- exactly one private key, RSA, unencrypted (`ENCRYPTED PRIVATE KEY`, a legacy `Proc-Type: 4,ENCRYPTED` key or an EC key is refused, with the reason);
- a certificate whose public key is that key's, found among the file's certificates in any order;
- valid now: not before its `notBefore`, and not on or after its `notAfter` (the error gives the date).

Errors name the setting and what is wrong. They never quote the file.

### Signing in

At every sign-in (at startup, two thirds of the way through each token's life, and whenever the service refuses the token), botd reads the file again and checks it as above. A renewed certificate is used from the next sign-in with no restart. A file that can no longer be used fails closed before Entra is asked. botd never falls back to the key it read before.

botd sends the `client_credentials` grant with `client_assertion_type` `urn:ietf:params:oauth:client-assertion-type:jwt-bearer` and a client assertion in the format Entra documents today:

- header: `alg` `PS256` (RSA-PSS with SHA-256), `typ` `JWT`, `x5t#S256` (the base64url SHA-256 of the certificate's DER);
- claims: `aud` the exact token endpoint it posts to (`<AZURE_AUTHORITY_HOST>/<tenant>/oauth2/v2.0/token`, so sovereign clouds work), `iss` and `sub` the client id, a random `jti`, `nbf` and `iat` now, and `exp` 10 minutes later.

Each assertion is used once and never stored. When Entra answers `invalid_client`, the error adds the certificate's SHA-1 thumbprint (as the Entra admin center lists it) and the app's client id, and asks whether the certificate is uploaded and in date. As before, Entra's own description is never included.

### Where it applies

All three users of the shared client get the method with no code of their own:

- **Key Vault** (`SECRETS_BACKEND=azure-keyvault`).
- **Vault's `azure` sign-in** (`VAULT_AZURE_CREDENTIALS=client-certificate`): the token for the mount's resource is a service principal's. `VAULT_AZURE_INSTANCE=1` still needs a managed identity on a VM.
- **The Azure Monitor audit sink** (`AUDIT_EXPORT_AZURE_AUTH=client-certificate`).

`AZURE_RUN_CREDENTIALS` refuses it at startup, as it refuses a client secret. Entra trusts only a managed identity or a federated token as another app's credential. `botd offline check` lists Entra ID (`AZURE_AUTHORITY_HOST`) as the sign-in endpoint, as for a client secret.

### Audit and Bots

Logins are still `secret.backend_login` for Key Vault and `secret.vault_login` for Vault, with `method` `client-certificate`, and never the key, the assertion or the token. Like `AZURE_FEDERATED_TOKEN_FILE`, `AZURE_CLIENT_CERTIFICATE_PATH` and `AZURE_CLIENT_CERTIFICATE_PASSWORD` are removed from everything botd starts. The private key is never put in an environment variable, so there is no value to redact.

## Consequences

- No change unless a method setting is `client-certificate`. The other methods' error text now lists four methods.
- botd off Azure can use Key Vault, Vault's `azure` method or Azure Monitor in tenants that forbid client secrets, with no shared password on disk.
- Threat model: the PEM file is botd's credential. Anyone who can read it can sign in as the app until the certificate expires or is removed from the app. Keep it `0600`, owned by botd's user. A Bot running locally as botd's own user can read any file botd can, as with the federated token file ([ADR 0159](0159-vault-kubernetes-and-jwt-sign-in.md)). Run Bots on their own machines or as their own users ([ADR 0037](0037-per-user-unix-accounts.md)). Compared with a client secret, a captured assertion is good only for its 10 minutes at Entra's token endpoint, and the key itself never crosses the network.
- Rotation: upload the new certificate to the app, replace the file, then remove the old certificate from the app. botd picks the new file up at its next sign-in. An expired file stops sign-ins with a clear error rather than with Entra's refusal.
- Tested in `server/src/secrets/azure.rs` against the stand-in Entra, which now checks client assertions as Entra does. It finds the uploaded certificate by `x5t#S256` and verifies the PS256 signature with its key. It checks the audience against the endpoint actually called, the issuer and subject, a lifetime of at most 10 minutes, and a `jti` never seen before. The tests cover Key Vault reads with a certificate, a renewed certificate and a PKCS#1 key used at the next sign-in with no restart, and an unknown certificate refused with its thumbprint and no key in the error. A file that becomes unusable or expires fails closed before Entra is asked, and both outcomes are audited with no key. Vault's and Azure Monitor's sign-in go through the same client, and the offline check's endpoint is covered. The file checks above, the refused SDK settings and `AZURE_RUN_CREDENTIALS` refusing the method are tested too, along with the settings kept from local jobs. No Azure account or network is used.
- Remaining on #55: nothing the issue names, and nothing an earlier #55 ADR left on its list. #55 can be closed after this is merged. The ideas the ADRs left for later are outside the issue and would each need an issue of their own: PFX files and encrypted keys, and subject name and issuer sign-in, if asked for (this ADR); Vault's `aws` `ec2` and GCP's `gce` sign-in types, and AliCloud or OCI sign-in (ADR 0260); workload identity federation for each Bot (ADR 0203); per-secret version pinning (ADR 0159); and harness logins kept in the external store rather than on the service user's disk (the roadmap's next item, outside #55).
- Ops guide: [docs/ops/cloud-secrets.md](../ops/cloud-secrets.md#with-a-certificate).
