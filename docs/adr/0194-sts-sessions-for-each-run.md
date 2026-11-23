# 0194: STS sessions for each run

## Status

Accepted (23 Nov 2026). Part of secrets vault integration in M5, [#55](https://github.com/CG-Labs/superbot/issues/55). Builds on short-lived credentials for each run ([ADR 0185](0185-short-lived-credentials-per-run.md)), which left "the cloud managers' own APIs without Vault" for later behind its `Issuer` trait, and on AWS Secrets Manager as the external store ([ADR 0146](0146-aws-secrets-manager.md)).

## Context

ADR 0185 gives each run a fresh credential, but only through Vault's dynamic secrets engines. Many AWS shops don't run Vault: they use AWS Secrets Manager as SuperBot's store (`SECRETS_BACKEND=aws`) and IAM roles for everything else. For them, the only way to give a Bot AWS access today is a static IAM user key in a store, which works until someone rotates it.

AWS's own answer is STS: `AssumeRole` makes temporary keys for a role, for 15 minutes to 12 hours. botd already signs requests with SigV4 and already calls STS (web identity sign-in), with credentials from AWS's chain.

Unlike a Vault lease, an STS session can't be revoked on its own. IAM's "revoke active sessions" denies every session of a role issued before a time, which would also cut off other runs still going.

## Options

1. **Revoke through IAM** by putting a deny on the role for sessions issued before now. Cuts off every run of that role, needs botd to edit IAM policies, and IAM is eventually consistent. Rejected.
2. **Keep sessions short and let them expire**: ask for the run's longest length, audit when each ends, keep its keys redacted until then. Chosen: what STS is designed for, and botd needs no IAM write access.
3. **Session policies or tags per run** to narrow each session further. Useful, but they need more setup (`sts:TagSession` in trust policies) and a format for policies in a setting. Left for later; a role per owner (`{owner}`) covers the common case.
4. **GCP (service account impersonation) and Azure (managed identity tokens)** in the same change. Each is its own API and trust setup; their tokens are bearer tokens of an hour that can't be revoked either, so they would fit the same path. Left for later, behind the same trait.

## Decision

### Setting

`AWS_RUN_CREDENTIALS` (off when empty; only with `SECRETS_BACKEND=aws`, warned about and ignored otherwise), written like `VAULT_RUN_CREDENTIALS`: entries separated by `;` or new lines, each a role's ARN and then `NAME=field` pairs.

```sh
AWS_RUN_CREDENTIALS="arn:aws:iam::123456789012:role/superbot-bots; arn:aws:iam::123456789012:role/superbot-u-{owner} OWN_KEY_ID=AccessKeyId OWN_SECRET_KEY=SecretAccessKey OWN_SESSION_TOKEN=SessionToken"
```

- The ARN must be `arn:<aws|aws-cn|aws-us-gov>:iam::<12 digits>:role/<path/name>`, with `{owner}` only in the role's path or name. Fields are `AccessKeyId`, `SecretAccessKey` and `SessionToken`; anything else (`Expiration`) is refused, since its value would be redacted everywhere.
- An entry with no pairs gives `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` and `AWS_SESSION_TOKEN`, which AWS's SDKs and CLI read. These three are reserved while botd signs in with access keys under them (ADR 0146), so no store can give them to a Bot. This setting can, because the values are the run's own session, never botd's keys. The exception covers only these three names and only this setting.
- `{owner}`, owners' ids, the 16-entry limit, unique names, checks at startup and no session at startup all work as in ADR 0185. The parser is shared: a `leases::Syntax` per setting says what an entry starts with, which fields it may name, what an entry with no pairs gives, and which names botd signs in with that it may still give.

### A run's sessions

As a run starts, at the same point as Vault's leases, botd calls `AssumeRole` for each role, signed with its own keys (the same keys and renewal as for Secrets Manager reads; lapsed keys get one more sign-in and retry). It sends:

- `RoleSessionName` = `superbot-<bot id>-<8 random hex>`, cut to STS's 64 characters, so CloudTrail shows which Bot's run made each call, and two runs never share a name.
- `DurationSeconds` = the longest a run may last (`RUN_TIMEOUT_MINUTES`), at least 900. A run timeout over STS's 12 hours is refused before any request.

The answer must have all three keys, an expiry and the assumed role's ARN. A session that ends more than a minute before the run could is refused. If botd's own identity is a role, AWS caps chained sessions at an hour and answers `ValidationError` to more; the error names that cause. `AccessDenied` names the two policies to check. STS's messages are never repeated, only its error code, as for Secrets Manager.

A run's timer starts after setup, and a run may try its harness twice, each try with its own timer, so a session of exactly `RUN_TIMEOUT_MINUTES` could expire while the run goes on. Asking STS for more doesn't work: chained roles are capped at an hour, which is the default timeout. So a run also stops when its first session expires (`Leases::expires_first`): each try's timer is the shorter of the run timeout and the time left on that session. When the session is what stopped it, the Bot says its short-lived credentials expired and to send the task again, rather than naming the time limit. The result is still `timeout`, so the metrics' run results don't change. Vault's leases are revoked at run end, and their TTL is set on the Vault role (ADR 0185), so they don't cut runs short.

The lease id is the assumed role's ARN (`arn:aws:sts::<account>:assumed-role/<role>/<session name>`): what CloudTrail records as the caller, and not a secret.

### Leases that can't be revoked

`Issuer` gets `revocable()`, true by default. When a run's `Leases` drops and its issuer isn't revocable, botd makes no request. For each session it audits `secret.lease_released` with `leaseId`, `revocable: false` and `expiresAt`, and keeps its values in a list of expiring values. Those stay redacted until they expire. The list is checked as leases are made and let go, and values past their expiry are released from the same per-value count as Vault's leases. So a value botd knew already is never forgotten, and one a live lease still has stays redacted. A value may stay redacted past its expiry until the next run, which costs nothing. Nothing outlives a restart; a value from before a restart that is still valid is no longer redacted. That is the same gap ADR 0185 has for leases botd couldn't revoke.

### Code

`aws::SecretsManager` implements `Issuer` (its worker is now shared, so the store and the issuer use one client, one set of keys and one runtime). `Config` gains the STS endpoint (`AWS_ENDPOINT_URL_STS`, used by web identity too). `leases` gains `Syntax` with `VAULT` and `AWS`, `parse_as`, `Issuer::revocable` and the expiring list. `Issuer::issue` gains the Bot's id, which Vault ignores. `Leases::expires_first` gives the runner the deadline above. That and the Bot's message are the runner's only changes.

## Consequences

- No change unless `AWS_RUN_CREDENTIALS` is set with `SECRETS_BACKEND=aws`.
- botd's identity needs `sts:AssumeRole` on each listed role (a wildcard such as `role/superbot-u-*` for one with `{owner}`), and each role's trust policy must allow botd. botd can then assume every listed role, as it can read every user's folder: run Bots on their own machines so a Bot can't use botd's identity (ADR 0146).
- A leaked key works until its session expires, up to `RUN_TIMEOUT_MINUTES` after its run started (at least 15 minutes), not until the run ends as with Vault. The guide says so, and points at IAM's "revoke active sessions" for emergencies.
- One STS request per role as each run starts; none as it ends.
- Tested in `server/src/secrets/leases.rs` (the ARN syntax and default names, the reserved-name exception for this setting only, leases that can't be revoked audited with their expiry, never revoked, kept redacted until they expire and while a live lease shares the value) and `server/src/secrets/aws.rs`, against a stand-in STS that checks every SigV4 signature: a new session per run signed with botd's instance-profile keys, its keys under the default and named variables, `{owner}` roles only for the owner's own runs, the session name and length, the audit with the assumed role's ARN and no key, refusals (`AccessDenied`, `ValidationError`, a short session, an odd answer, a run longer than 12 hours that is never sent) and lapsed keys signed in again, and the settings. On the real router, `run_credentials_http_tests.rs` checks that a run stops when its session expires, well before its run timeout, and says why.
- Ops guide: [docs/ops/cloud-secrets.md](../ops/cloud-secrets.md#short-lived-aws-credentials-for-each-run).
