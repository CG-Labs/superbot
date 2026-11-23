# 0203: GCP service account tokens for each run

## Status

Accepted (23 Nov 2026). Part of secrets vault integration in M5, [#55](https://github.com/CG-Labs/superbot/issues/55). Builds on short-lived credentials for each run ([ADR 0185](0185-short-lived-credentials-per-run.md)) and STS sessions for each run ([ADR 0194](0194-sts-sessions-for-each-run.md)), which left "GCP (service account impersonation)" for later behind the same `Issuer` trait, and on GCP Secret Manager as the external store ([ADR 0136](0136-cloud-secret-managers.md)).

## Context

ADR 0194 gave AWS shops without Vault a fresh credential for each run. Google Cloud shops that use Secret Manager as SuperBot's store (`SECRETS_BACKEND=gcp-secret-manager`) still have only one way to give a Bot Google access: a service account key file in a store. Keys don't expire, Google's own guidance is not to make them, and many organizations forbid them by policy (`iam.disableServiceAccountKeyCreation`).

Google's answer is impersonation: a caller with `roles/iam.serviceAccountTokenCreator` on a service account asks IAM Credentials (`generateAccessToken`) for an OAuth access token of that account, for up to an hour, or up to 12 hours where the organization policy `constraints/iam.allowServiceAccountCredentialLifetimeExtension` lists the account. botd already holds a token of its own service account (metadata server or key) with the `cloud-platform` scope, which that API accepts.

Like an STS session, such a token can't be revoked: Google's documentation says service account access tokens stay valid until they expire (5 minutes to 12 hours), and `gcloud auth revoke` only forgets them locally. Disabling the account, or an IAM deny policy on it, is the emergency stop, and it hits every token of that account.

## Options

1. **A service account key per run** (`projects.serviceAccounts.keys.create`, deleted at run end). Revocable, but botd would need `iam.serviceAccountKeys.create` and `delete`, which many organizations forbid, keys take time to propagate, and a key botd fails to delete never expires. Rejected.
2. **Workload identity federation for each Bot**: Bots get an identity of their own that Google trusts. The right end state for Bots on their own machines, but it needs an identity provider botd runs and per-Bot trust setup. Left for later.
3. **Impersonation with `generateAccessToken`**, as long as the run may last, let go at its expiry. Chosen: what Google recommends over keys, botd needs one role on each account and no IAM write access, and it fits ADR 0194's path for leases that can't be revoked unchanged.
4. **Azure in the same change.** Azure has no counterpart that fits as well: a managed identity's token is botd's own, and a token for another app needs that app's secret or federation. Left for later.

## Decision

### Setting

`GCP_RUN_CREDENTIALS` (off when empty; only with `SECRETS_BACKEND=gcp-secret-manager`, warned about and ignored otherwise), written like `AWS_RUN_CREDENTIALS`: entries separated by `;` or new lines, each a service account's email and then `NAME=field` pairs.

```sh
GCP_RUN_CREDENTIALS="superbot-bots@my-project.iam.gserviceaccount.com; superbot-u-{owner}@my-project.iam.gserviceaccount.com OWN_GCP_TOKEN=accessToken"
```

- The email must be `<account>@<domain>.gserviceaccount.com` in lowercase letters, digits and `-` (so `iam.gserviceaccount.com`, and the default compute account on `developer.gserviceaccount.com`), with `{owner}` only before the `@`. Only emails, not unique ids: they say which account in the audit log. The one field is `accessToken`; `expireTime` is refused, since its value would be redacted everywhere.
- An entry with no pairs gives the token as `CLOUDSDK_AUTH_ACCESS_TOKEN` (gcloud, first in its order) and `GOOGLE_OAUTH_ACCESS_TOKEN` (Terraform's Google provider). Google's client libraries read no token from the environment; code using them reads one of these names itself. Neither name is one botd signs in with, so no exception to reserved names is needed (unlike ADR 0194's).
- `{owner}`, owners' ids, the 16-entry limit, unique names, checks at startup and nothing made at startup all work as in ADR 0185, through the shared `leases::Syntax` (`leases::GCP`). A service account id is at most 30 characters, so an `{owner}` account whose id would be longer is refused before any request, naming the limit; `superbot-u-{owner}` fits botd's ids.
- `GCP_IAM_CREDENTIALS_ENDPOINT` (default `https://iamcredentials.googleapis.com`) for Private Service Connect or a test stand-in; https only, as the other endpoints.

### A run's tokens

As a run starts, at the same point as Vault's leases and STS sessions, botd calls `POST <endpoint>/v1/projects/-/serviceAccounts/<email>:generateAccessToken` for each account with its own token (renewed as for Secret Manager reads; refused tokens get one more sign-in and retry) and:

- `scope` = `cloud-platform`: what the account's IAM roles allow is the limit, as with `gcloud --impersonate-service-account`.
- `lifetime` = the longest a run may last (`RUN_TIMEOUT_MINUTES`), at least Google's 5 minutes, so with the default of 60 minutes it fits Google's default hour. A run timeout over Google's 12 hours is refused before any request. A 400 for a lifetime over an hour names the organization policy.

The answer must have a printable token and an expiry; a token that ends more than a minute before the run could is refused. 403 names the role and the API to check, 404 asks whether the account exists. Google's messages are never repeated, only its status, as for Secret Manager.

Google gives the token no id, so the lease id is botd's own handle, `<email>/superbot-<bot id>-<random>`, unique per run and not secret. Google's audit logs record the call as botd's account using the target account, not this name.

A run stops when its first token expires (`Leases::expires_first`, ADR 0194), and the Bot says its short-lived credentials expired. At run end each token is audited as `secret.lease_released` with `revocable: false` and `expiresAt`, and its value stays redacted until then. A value given under two names is counted once per name, so it is forgotten only when the last lease that has it is let go.

### Code

`gcp::SecretManager` implements `Issuer` (its worker is now shared, so the store and the issuer use one client, one token and one runtime). `Config` gains `iam_endpoint`. `leases` gains `GCP`. `aws::session_name` is shared for the lease id. No change to the runner: ADR 0194 already made it stop at a lease's expiry.

## Consequences

- No change unless `GCP_RUN_CREDENTIALS` is set with `SECRETS_BACKEND=gcp-secret-manager`.
- botd's service account needs `roles/iam.serviceAccountTokenCreator` on each listed account (granted on the account; there is no wildcard, so an `{owner}` account needs it per user), and the IAM Service Account Credentials API must be enabled. botd can then act as every listed account, as it can read every user's folder: run Bots on their own machines so a Bot can't use botd's identity (ADR 0136).
- A leaked token works until it expires, up to `RUN_TIMEOUT_MINUTES` after its run started, not until the run ends. The guide says so, and that disabling the account (or a deny policy on it) cuts off its tokens in an emergency.
- One IAM Credentials request per account as each run starts; none as it ends.
- Tested in `server/src/secrets/leases.rs` (the email syntax and default names, one value under two names redacted until its last lease lets go) and `server/src/secrets/gcp.rs`, against the stand-in Google that checks botd's token on every call: a new token per run under the default and named variables, `{owner}` accounts only for the owner's own runs, the scope and lifetime sent (at least 5 minutes), the audit with the lease id and no token, let go and kept redacted at run end, refusals (403, 404, a lifetime over an hour, a short token, an odd answer, a run longer than 12 hours or an account id too long that is never sent, Google down) and a refused token signed in again, and the settings. A run stopping at its token's expiry is covered on the real router by `run_credentials_http_tests.rs` (ADR 0194).
- Ops guide: [docs/ops/cloud-secrets.md](../ops/cloud-secrets.md#short-lived-gcp-credentials-for-each-run).
