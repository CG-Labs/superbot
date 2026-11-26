# 0298: Vault sign-in with the instance's own identity (GCE and EC2)

## Status

Accepted (25 Nov 2026). Part of secrets vault integration in M5, [#55](https://github.com/CG-Labs/superbot/issues/55). Adds two `Auth` cases to the HashiCorp Vault provider ([ADR 0125](0125-external-secrets-backend-vault.md)), beside the cloud sign-in of [ADR 0260](0260-vault-cloud-sign-in.md), which left "Vault's `aws` `ec2` type" and "GCP's `gce` type" for later.

Numbered 0298 because it is the number reserved for this slice; 0296, 0297, 0299 and 0300 are held by parallel work.

## Context

ADR 0260 logs botd in to Vault as its cloud IAM identity: an STS request signed with its AWS keys (`aws`, `iam` type), or a JWT Google's IAM Credentials API signs as its service account (`gcp`, `iam` type). Two gaps remain on the two clouds where Vault has a second type.

- **Google.** The `iam` type needs botd's service account to hold `iam.serviceAccounts.signJwt` on itself: the Service Account Token Creator role. Security teams often refuse it, because it lets the holder mint tokens as the account. The `gce` type needs no permission on botd's side: the metadata server hands any VM an identity token Google signs, and Vault binds the role to the VM's project, zone or region, labels and instance groups. That is also the binding many teams want: "VMs in this project with this label", not "this service account, wherever it runs".
- **AWS.** The `iam` type binds a role to an IAM principal. Some teams bind Vault roles to the AMI, account, VPC or subnet an instance runs in, which only the `ec2` type checks: botd sends the instance's identity document, signed by AWS as PKCS#7, and Vault checks it and the instance.

Vault's docs say the `ec2` type is weaker than `iam`: any process on the instance can read the document. Vault's answer is a client nonce. At the instance's first login, Vault stores the instance id and the nonce in its access list, and takes later logins from that instance only with the same nonce. So the nonce, not the document, is the secret.

Other candidates for #55 that ADR 0291 and the roadmap list (a console button for refresh, refresh from the stores' change events, harness logins in the external store, workload identity federation per Bot) stay for later. Each is larger, and none removes a credential or a privileged role from botd's setup.

## Options

1. **Leave it to Vault Agent.** Agent's auto-auth supports `gce` and `ec2` and writes a token that `VAULT_TOKEN_FILE` reads. That still works. But it is another process on every server, and ADR 0260 already chose botd's own client for the cloud methods.
2. **Let Vault make the nonce** (send none at the first login, keep the one it returns). But botd would lose it at every restart, and Vault would refuse every later login until an operator deleted the access list entry. Vault also writes a nonce it makes to its audit log in plaintext.
3. **Persist a nonce botd makes** (in its data folder or the sealed store). It survives restarts, but botd then holds a credential nobody configured, which a restore onto another instance or a rebuilt data folder silently loses, and rotation has no handle.
4. **The operator sets the nonce** (`VAULT_AWS_NONCE`, or `_FILE`), as for any other secret. Chosen. It survives restarts and redeploys, it is delivered and rotated the way botd's other secrets are, and Vault never returns or logs it.

## Decision

### Configuration

| Setting | Default | Meaning |
|---------|---------|---------|
| `VAULT_GCP_TYPE` | `iam` | `gce`: log in with the VM's identity token from the metadata server |
| `VAULT_AWS_TYPE` | `iam` | `ec2`: log in with the instance's PKCS#7 identity document and a nonce |
| `VAULT_AWS_NONCE` | (required for `ec2`) | 16 to 128 printable characters, no spaces or quotes; or `VAULT_AWS_NONCE_FILE` |

The rest are ADR 0260's: `VAULT_GCP_ROLE` (required) and `VAULT_GCP_MOUNT`; `VAULT_AWS_ROLE` (default: Vault's, the role named after the AMI for `ec2`) and `VAULT_AWS_MOUNT`; `GCE_METADATA_HOST` and `AWS_EC2_METADATA_SERVICE_ENDPOINT` for the metadata services, and `AWS_EC2_METADATA_DISABLED`, as AWS's SDKs read them.

All are checked when botd starts. Settings of the `iam` type that the other type would ignore are refused rather than ignored, so a half-changed configuration doesn't look like it works: `VAULT_GCP_SERVICE_ACCOUNT` and a `VAULT_GCP_CREDENTIALS` other than `metadata` with `gce`; `VAULT_AWS_REGION`, `VAULT_AWS_HEADER_VALUE` and `VAULT_AWS_CREDENTIALS` with `ec2`. So is `ec2` with `AWS_EC2_METADATA_DISABLED=true`. Errors about the nonce never quote it.

### Logging in

Both run on the same path as every other login: at startup, two thirds of the way through the Vault token's lease, and once more when Vault refuses the token, in `VAULT_AUTH_NAMESPACE` if set. Each login fetches a fresh document.

- **GCE.** `GET http://<metadata host>/computeMetadata/v1/instance/service-accounts/default/identity?audience=http://vault/<role>&format=full` with `Metadata-Flavor: Google`, on the client that never uses a proxy. The audience is the one Vault Agent asks for (Vault checks that it ends in `vault/<role>`), and `format=full` adds the instance's details, which a `gce` role needs. botd checks the answer is a compact JWT and sends `{"role", "jwt"}` to `auth/<mount>/login`. A 404 adds "does this VM have a service account?". The metadata server's text is never quoted. No access token is fetched and IAM Credentials isn't called.
- **EC2.** An IMDSv2 session token (60 seconds), then `GET /latest/dynamic/instance-identity/pkcs7`. botd takes the line breaks out, as Vault wants, checks the rest is base64 of at most 16 KB, and sends `{"pkcs7", "nonce", "role"?}`. A 400 from Vault adds a hint naming the two usual causes: a nonce other than the first login's (changed, or another client logged in first), or a role not bound to the instance. Vault's own text is never logged, as for every login.

### Audit and redaction

Logins stay `secret.vault_login` with `method` (`gcp` or `aws`, Vault's method names) and `role` and `namespace` as before, plus `type` (`gce` or `ec2`). `type` is added only for these two, so ADR 0260's `iam` events are unchanged. Neither the identity token, the document nor the nonce reaches the audit log or an error.

The nonce is reserved (`check_name` refuses `VAULT_AWS_NONCE` as a Bot secret), registered with the redactor when botd reads it, removed with `VAULT_AWS_NONCE_FILE` from everything botd starts, and the support bundle redacts settings named with `NONCE`. The identity token and the document are used once and never stored, as ADR 0260 treats the signed JWT. Neither is a credential on its own: Vault binds the token to its audience and checks the document with the nonce.

### Offline check

`botd offline check` lists only the metadata service for these types: `GCE_METADATA_HOST` for `gce`, not IAM Credentials or a key's token URI; and `AWS_EC2_METADATA_SERVICE_ENDPOINT` for `ec2` when it is set (IMDS's own address is link-local), never STS.

## Consequences

- No change unless `VAULT_GCP_TYPE=gce` or `VAULT_AWS_TYPE=ec2` is set.
- On a GCE VM, botd logs in to Vault with no IAM role at all, and the Vault role can bind to project, zone, region, labels and instance groups. Vault's own Google credentials need `compute.instances.get`, and `compute.instanceGroups.list` for instance groups (`roles/compute.viewer`). On GKE, `kubernetes` or the `iam` type remain the way. `gce` roles check a Compute Engine instance.
- On EC2, Vault roles can bind to AMI, account, region, VPC, subnet and instance profile. Vault needs AWS credentials of its own to check the instance. The nonce must differ per instance, and the role must allow reauthentication (Vault's default). A lost or changed nonce locks botd out until an operator deletes the instance's access list entry, which the guide and the error say. HashiCorp recommends the `iam` type where it fits, and so does the guide.
- Threat model: as ADR 0260, anyone who can reach the metadata service on botd's VM, including a Bot running on it, can get the same GCE identity token and log in as botd's role. EC2 adds the nonce, which a Bot doesn't get. Bots on their own machines are kept off metadata addresses by the egress rules ([ADR 0126](0126-per-user-machine-hardening.md)).
- Tested against the stand-in Vault and metadata services in `server/src/secrets/vault.rs`:
  - GCE: the audience and `format=full`, no `signJwt` or access token, a new token at each login, a VM with no service account failing closed before Vault is asked, a role Vault doesn't bind refused, and audit details with `type`.
  - EC2: the document without line breaks, the default (AMI) role and a named one, the same nonce taken across a re-login and a second botd, another nonce refused with the hint and never quoted, an unreachable IMDS failing closed before Vault is asked, and the nonce masked.
  - Settings: each refusal above, the nonce from a file, and `VAULT_AWS_NONCE` reserved and removed from jobs botd starts.
  - On the real router (`server/src/vault_auth_http_tests.rs`), admins see both types' logins and failures with `type` and no token, document or nonce, and members can't. The offline check's findings in `server/src/offline_check.rs`, and the support bundle's redaction in `server/src/support.rs`.
  - No cloud, Vault or network.
- Ideas for later, each for an issue of its own: Vault's `ec2` role tags and `rsa2048` signatures, AliCloud or OCI sign-in, a refresh button in the console, and refresh from the stores' change events.
- Ops guide: [docs/ops/vault.md](../ops/vault.md#the-instances-own-identity-gce-and-ec2).
