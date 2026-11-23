# 0146: AWS Secrets Manager as a secrets backend

## Status

Accepted (22 Nov 2026). Part of secrets vault integration in M5, [#55](https://github.com/CG-Labs/superbot/issues/55). Builds on the external secrets backend ([ADR 0125](0125-external-secrets-backend-vault.md)) and the cloud secret managers ([ADR 0136](0136-cloud-secret-managers.md)).

Numbered 0146 because 0143 to 0145 are held by other open PRs.

## Context

ADR 0125 put an `ExternalStore` between the environment and the sealed store. It handles the folders, cache, fail-closed reads, redaction and audit for any `Provider`. ADR 0136 added Azure Key Vault and GCP Secret Manager. #55 also asks for AWS Secrets Manager, where enterprises on AWS keep their keys.

What AWS needs that the others don't:

- **Signing.** Every request is signed with Signature Version 4 (SigV4): an HMAC-SHA256 chain over the request, keyed by the secret access key. There is no bearer token to fetch and send.
- **Credentials.** They come from AWS's credential chain: access keys in the environment, a web identity token traded at STS (EKS IRSA), the container endpoint (ECS task roles, EKS Pod Identity), or the instance profile from the instance metadata service (IMDS). All but the first are temporary and expire.
- **Names.** Secret names allow letters, digits and `/_+=.@-`, up to 512 characters, so botd's folders can be real paths.
- **Replies.** Errors come as HTTP 400 with an error type (`ResourceNotFoundException`, `AccessDeniedException`, ...). A deleted secret stays, scheduled for deletion, for 7 to 30 days, and reads answer `InvalidRequestException` until it goes.

## Options

1. **The AWS SDK for Rust** (`aws-sdk-secretsmanager`, `aws-config`). It brings a large dependency tree (the smithy runtime, a second HTTP stack) and an automatic credential chain that also reads profiles, SSO caches and `credential_process`, which runs a program. ADR 0136 rejected the same trade for Azure and Google.
2. **The `aws-sigv4` crate on its own**, with the chain by hand. It still pulls in the smithy runtime types.
3. **Plain JSON over botd's existing `reqwest` + rustls, signed by hand.** botd already signs S3 backup requests with SigV4 ([ADR 0071](0071-off-host-machine-backups.md)) using `aws-lc-rs`, and three calls are enough (`GetSecretValue`, `ListSecrets`, `DescribeSecret`), plus one for STS. Chosen. The signer moves from the S3 client into `server/src/sigv4.rs`, which both use. It is tested against AWS's published examples (the SigV4 test suite's `get-vanilla`, the IAM guide example and the S3 example), and against Secrets Manager requests signed by botocore, with a session token and with a host that has a port.

## Decision

### Configuration

`SECRETS_BACKEND=aws`. Everything else is the same as for the other backends: off by default, `SECRETS_CACHE_SECONDS`, the order (**environment, then the external store, then sealed**), read-only, and fail closed.

| Setting | Default | Meaning |
|---------|---------|---------|
| `AWS_SECRETS_MANAGER_REGION` | `AWS_REGION`, then `AWS_DEFAULT_REGION` | The region the secrets are in. Required: botd doesn't guess it |
| `AWS_SECRETS_MANAGER_PREFIX` | `superbot` | Letters, digits and `/_+=.@-`, no empty parts (`acme/prod`) |
| `AWS_SECRETS_MANAGER_AUTH` | `chain` | `chain`, or one source: `env`, `web-identity`, `container`, `instance-profile` |
| `AWS_ENDPOINT_URL_SECRETS_MANAGER` | `https://secretsmanager.<region>.amazonaws.com` (`.amazonaws.com.cn` in China) | Override: a VPC endpoint, FIPS, or a test stand-in |
| `AWS_ENDPOINT_URL_STS` | `https://sts.<region>.amazonaws.com` | Override for web identity |

The credential settings are AWS's own: `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN` (or their `_FILE`); `AWS_WEB_IDENTITY_TOKEN_FILE`, `AWS_ROLE_ARN`, `AWS_ROLE_SESSION_NAME` (default `superbot-botd`); `AWS_CONTAINER_CREDENTIALS_RELATIVE_URI` or `_FULL_URI` with `AWS_CONTAINER_AUTHORIZATION_TOKEN(_FILE)`; `AWS_EC2_METADATA_SERVICE_ENDPOINT` and `AWS_EC2_METADATA_DISABLED`. The `AWS_ENDPOINT_URL_*` names are the SDKs' too.

### Credentials

With `chain`, botd takes the first source that is set, in the SDKs' order: environment keys, then web identity, then the container endpoint, then the instance profile. It checks the sources only as far as the first that is set, so a half-set later source it won't use can't stop it. It picks **once, at startup**, says which in the startup line and the setup report, and uses only that one. A source that later fails is an error, never a reason to try the next. Shared config and credentials files, SSO and `credential_process` are never read: they are for people, and `credential_process` runs a program. To pin a source, set `AWS_SECRETS_MANAGER_AUTH`.

- **Environment:** used as given, never renewed. `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` must both be set or neither. The secret key and session token are registered for redaction.
- **Web identity:** `AssumeRoleWithWebIdentity` at STS (unsigned, as AWS designed it), with the token file read again for every sign-in, because EKS rotates it.
- **Container:** a GET to `http://169.254.170.2<RELATIVE_URI>`, or to a `FULL_URI` that is https, or http to this computer, `169.254.170.2` or `169.254.170.23` (the SDKs' rule). The authorization token file is read again for every sign-in, because EKS Pod Identity rotates it.
- **Instance profile:** IMDSv2 only: a session token from `PUT /latest/api/token`, then the role's keys. botd never falls back to IMDSv1, so an instance that requires IMDSv2 works and a forwarded request can't get keys.

Temporary keys are kept and renewed two thirds of the way to their `Expiration`. Each new secret key and session token is registered for redaction, and the ones it replaces are forgotten, so the list doesn't grow. When Secrets Manager answers `ExpiredTokenException`, `UnrecognizedClientException` or `InvalidClientTokenId`, botd gets new keys once and retries. Each sign-in is audited as `secret.backend_login` with the store (`aws`) and the method, never a credential. Requests to IMDS and the container endpoint never go through a proxy. Requests to Secrets Manager and STS follow no redirects.

### Names

The folders are paths: `<prefix>/bots/<NAME>` and `<prefix>/server/<NAME>`, so `OPENAI_API_KEY` is `superbot/bots/OPENAI_API_KEY` and `LINODE_TOKEN` is `superbot/server/LINODE_TOKEN`. A name is only read from its own folder. Listing uses `ListSecrets` with a `name` filter on the folder (a case-sensitive prefix match), and botd checks the prefix again itself. botd reads the `AWSCURRENT` version. IAM can grant each folder on its own, by ARN: `arn:aws:secretsmanager:<region>:<account>:secret:superbot/bots/*`.

### Replies, and failing closed

As with the other backends, only "there is no such secret" lets the next store answer. Everything else is `Error::Unavailable`, so it can't uncover a sealed copy:

- **Not there** (`None`): `ResourceNotFoundException`, an empty `SecretString`, and a secret **scheduled for deletion**. A read of one answers `InvalidRequestException`. botd then asks `DescribeSecret`, and only if that shows a `DeletedDate` (or the secret is gone) does it count as not there. Deleting is how an operator retires a key in AWS, and it would be wrong to stop Bot runs for the whole recovery window.
- **Error**: any other `InvalidRequestException`, `AccessDeniedException`, `DecryptionFailure` (KMS), throttling, 5xx, a reply for a different secret name, a reply with no value, a `SecretBinary` that isn't UTF-8 text, a list reply of the wrong shape or an entry without a name, a `DescribeSecret` that is refused, and a list longer than 1000 pages.

Error messages carry the HTTP status and the error type with its namespace removed (taken from `x-amzn-ErrorType` or `__type`; STS's XML `Code`), never AWS's message, which can quote what was sent.

### Keeping the credentials from Bots

Unlike the names in ADR 0136, `AWS_ACCESS_KEY_ID` and the rest are names an operator may already use to give Bots their own AWS keys, so they can't be reserved for everyone. Instead, while `SECRETS_BACKEND=aws`, the source botd signs in with decides:

| Source | Reserved (can't be saved for Bots, never read from an external store, never offered to Bots) | Also removed from everything botd starts |
|---|---|---|
| `env` | `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN` | their `_FILE` |
| `web-identity` | `AWS_WEB_IDENTITY_TOKEN` | `AWS_WEB_IDENTITY_TOKEN_FILE`, `AWS_ROLE_ARN`, `AWS_ROLE_SESSION_NAME` |
| `container` | `AWS_CONTAINER_AUTHORIZATION_TOKEN` | its `_FILE`, `AWS_CONTAINER_CREDENTIALS_RELATIVE_URI` and `_FULL_URI` |
| `instance-profile` | none | none |

`secrets::keep_from_bots` records them when the backend is built at startup. `check_name` refuses them, and `adapters::secret_env` strips them, with the other secret settings, from every harness, screen and job. With another backend, or none, nothing changes.

### Diagnostics

As for the other backends: settings are checked when botd starts and both folders are listed, so botd won't start on a bad setting or a Secrets Manager it can't reach or sign in to. `AWS_SECRETS_MANAGER_REGION` or `AWS_SECRETS_MANAGER_AUTH` with another backend is named in a warning. `GET /api/setup`'s `secretsBackend` and `botctl secrets backend` say whether it answers now.

## Consequences

- Nothing changes unless `SECRETS_BACKEND=aws`. No new crates. The S3 backup client signs as before, now through `sigv4.rs`.
- Tested against stand-ins for Secrets Manager (which checks each request's SigV4 signature against the headers and body that arrived), IMDSv2, the container endpoint and STS, in `server/src/secrets/aws.rs`. No real AWS, account or network.
- IAM: botd needs `secretsmanager:GetSecretValue` and `secretsmanager:DescribeSecret` on its folders, `kms:Decrypt` on a customer-managed key if the secrets use one, and `secretsmanager:ListSecrets`, which can't be limited to a prefix and shows names, not values. The guide has a policy.
- Threat model: as in ADR 0125 and 0136, anyone who can run code as botd's user can use botd's identity. With the instance profile, the container endpoint or web identity, that includes **any process on the same host that can reach `169.254.169.254` or `169.254.170.2`**, or read the token file. Run Bots on their own machines, whose egress rules block metadata addresses ([ADR 0126](0126-per-user-machine-hardening.md)), or block those addresses on botd's host for everyone but botd's user, and require IMDSv2 with a hop limit of 1. The guide shows how.
- `ListSecrets` is eventually consistent, so a new secret can take a few minutes to appear in `botctl secrets`; reading it by name works at once.
- Remaining on #55: per-user secrets in the external store, Vault's Kubernetes and JWT sign-in, Azure certificate credentials, and short-lived credentials per run.
- Ops guide: [docs/ops/cloud-secrets.md](../ops/cloud-secrets.md#aws-secrets-manager).
