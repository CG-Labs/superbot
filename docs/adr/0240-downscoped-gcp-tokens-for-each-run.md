# 0240: Downscoped GCP tokens for each run

## Status

Accepted (24 Nov 2026). Part of secrets vault integration in M5, [#55](https://github.com/CG-Labs/superbot/issues/55). Builds on GCP service account tokens for each run ([ADR 0203](0203-gcp-service-account-tokens-for-each-run.md)) and on session policies and tags for each run ([ADR 0230](0230-session-policies-and-tags-for-each-run.md)), which narrowed AWS sessions and left "GCP's Credential Access Boundaries, a separate token exchange, for Cloud Storage only" for later.

## Context

With `GCP_RUN_CREDENTIALS`, each run gets an access token of a service account botd impersonates. A run gets everything that account's IAM roles allow. To keep each user's Bots to their own data, an operator today makes a service account per user (`superbot-u-{owner}`) and grants botd Token Creator on each one, since Google has no wildcard for it: an account, a binding and the roles for every user, made before that user's first run.

Google can narrow a token after it is made: **Credential Access Boundaries**. The holder of an access token with the `cloud-platform` scope posts it to the Security Token Service (`sts.googleapis.com/v1/token`, an OAuth 2.0 token exchange) with a boundary, and gets a token that can do only what both the account's roles and the boundary allow. A boundary is up to 10 rules, each a Cloud Storage bucket (`//storage.googleapis.com/projects/_/buckets/<bucket>`), the roles whose permissions are available on it (`inRole:roles/storage.objectViewer`), and optionally an IAM condition in CEL that limits it to objects (`resource.name.startsWith('projects/_/buckets/<bucket>/objects/<prefix>')`). The downscoped token ends when the token it came from does, and it can't be downscoped again. Only Cloud Storage honours boundaries: other Google APIs refuse the token.

A Bot runs code: whatever narrowing it gets must come from botd, never from the run.

## Options

1. **A service account per owner** (`{owner}`, ADR 0203). Works today. Every user needs an account and a binding made ahead of time.
2. **Hand the run the impersonated token and let it downscope itself** (Google's client libraries can). The run would hold the wider token. Rejected.
3. **A `boundary=<file>` option on each `GCP_RUN_CREDENTIALS` entry**, the boundary in Google's own JSON, `{owner}` and `{bot}` filled in for each run, the token exchanged by botd before the run starts. Chosen: the shape of ADR 0230's `policy=`, one account can serve every user's Cloud Storage access, the run only ever sees the narrower token, and an entry without it is exactly as before.
4. **Client-side downscoping** (Google's "client-side token generation", where a broker gets intermediary key material and mints downscoped tokens locally). Fewer requests, but only some languages have it, it needs more key material in botd, and one STS call per run is cheap. Rejected.
5. **Rules in the setting** (`bucket=`, `role=`, `prefix=`). Easier for the simplest case, but conditions are CEL, and a second, partial syntax for something Google already defines in JSON is one more thing to get wrong. A file in Google's format can be tried with `gcloud` and copied from Google's documentation.

## Decision

### Setting

A `GCP_RUN_CREDENTIALS` entry may have, after the service account's email and among its `NAME=accessToken` pairs, `boundary=<file>`: a Credential Access Boundary as Google documents it.

```json
{
  "accessBoundary": {
    "accessBoundaryRules": [{
      "availableResource": "//storage.googleapis.com/projects/_/buckets/acme-users",
      "availablePermissions": ["inRole:roles/storage.objectAdmin"],
      "availabilityCondition": {
        "expression": "resource.name.startsWith('projects/_/buckets/acme-users/objects/{owner}/') || api.getAttribute('storage.googleapis.com/objectListPrefix', '').startsWith('{owner}/')"
      }
    }]
  }
}
```

botd reads it once at startup and refuses to start unless it is JSON of exactly that shape, at most 64 KiB: 1 to 10 rules; each a bucket resource and a non-empty list of `inRole:<role>`; an optional condition with a non-empty `expression` and optional `title` and `description`, all strings; no other keys, so a misspelt one stops botd rather than being dropped by Google into a wider token. These are the checks Google's client libraries make before they send one. Its contents are never quoted in errors; its path has no spaces. At most one per entry. The other run credentials settings refuse it by name, as `GCP_RUN_CREDENTIALS` refuses `policy=`, `policy-arn=` and `tags=`.

`boundary=` is an option, not a variable, so an entry with only it still gives `CLOUDSDK_AUTH_ACCESS_TOKEN` and `GOOGLE_OAUTH_ACCESS_TOKEN`.

`GCP_STS_ENDPOINT` (default `https://sts.googleapis.com`) for Private Service Connect or a test stand-in; https only, as the other endpoints.

### Each run

`{owner}` and `{bot}` in the boundary's keys and strings become the run's owner id and Bot id, put into the parsed JSON as strings and written compactly (ADR 0230's `substitute`). Inside a CEL expression they land in a string literal: owner ids are lowercase letters and digits, and a boundary naming `{bot}` refuses a run whose Bot id isn't letters, digits, `-` and `_` (before any request), so neither can close the literal and change the condition. An entry whose boundary names the owner is only for runs that get the owner's own secrets, as an account with `{owner}` is (ADR 0174).

As the run starts, botd makes the account's token as before (ADR 0203), then posts it to `<GCP_STS_ENDPOINT>/v1/token` as a form: `grant_type=urn:ietf:params:oauth:grant-type:token-exchange`, `subject_token_type` and `requested_token_type` both `urn:ietf:params:oauth:token-type:access_token`, `subject_token`, and `options` the boundary as sent. No other credential: the token is its own proof. The answer must have a printable `access_token` of at most 16 KiB (Google's are at most 12 KB) that differs from the one sent. Its lifetime is the impersonated token's, or `expires_in` when Google gives a shorter one; a token that ends more than a minute before the run could is refused, as in ADR 0203.

The run gets only the downscoped token. The impersonated token stays in botd, is never audited or redacted (nothing shows it), and is dropped when the exchange is done.

Errors name only STS's status and OAuth error code, never its description, with a hint: 400 points at the boundary file (a role Google doesn't know, a condition that isn't CEL), 403 at the Security Token Service API in botd's project. The run is refused (`secrets_unavailable`) and the other leases already made for it are let go as before. botd never falls back to the wider token.

### Audit

`secret.lease_issued` adds `boundarySha256`, the SHA-256 of the boundary exactly as sent (compact JSON, keys sorted, ids in). The lease id, TTL, `secret.lease_released` at run end and redaction until expiry are ADR 0203's.

### Code

`leases::Narrowing` gains `boundary` (parsed at startup) and `Narrowed` gains `boundary` (per run, ids in) and `narrows_session()`. `Syntax.session: bool` becomes `options`, the entry options a setting takes: `SESSION_OPTIONS` for AWS, `BOUNDARY_OPTIONS` for GCP. `gcp::SecretManager` overrides `Issuer::issue_narrowed`: it refuses a session policy or tags, and exchanges the token when there is a boundary. `aws::SecretsManager` refuses a boundary, and the default `issue_narrowed` refuses any narrowing, so no backend makes a wider credential than asked. `gcp::Config` gains `sts_endpoint`.

## Consequences

- No change unless an entry has `boundary=`.
- One service account can serve every user's Cloud Storage access: grant it the bucket roles once, and scope each run with `{owner}` or `{bot}` in the boundary's buckets or conditions. No account or Token Creator binding per user.
- A downscoped token works with Cloud Storage only (`gcloud storage`, the JSON and XML APIs, client libraries given the token). An entry for other Google APIs needs its own account without a boundary; a Bot that needs both gets two entries with their own variable names.
- A boundary can only take away from the account's roles: a mistake in one gives a run less, never more. A boundary file botd can't read or check stops botd at startup, not a run. Editing it needs a restart.
- The Security Token Service API must be on in botd's project, as well as IAM Credentials. One more Google request per downscoped entry as each run starts; none as it ends.
- Like the token it came from, a downscoped token can't be revoked; it works until it expires, and disabling the account stops it.
- Tested in `server/src/secrets/leases.rs` (the option parsed and checked: missing, non-JSON, wrong shape, extra keys, 0 or 11 rules, a resource that isn't a bucket, permissions without `inRole:`, a bad condition, never quoting the file; refused by the other settings; the owner rule; ids filled in as JSON strings, a Bot id that can't stand in a boundary refused; the audit's hash; backends that can't downscope refusing) and `server/src/secrets/gcp.rs`, against a stand-in STS that trades only tokens the stand-in IAM Credentials made: the run gets the downscoped token and never the one it came from, an entry without a boundary isn't downscoped, the boundary sent with the run's ids, its lifetime, the audit, and refusals (400, 403, a token shorter than the run, the same token back, an odd answer, STS down) without Google's descriptions or a fallback to the wider token.
- Ops guide: [docs/ops/cloud-secrets.md](../ops/cloud-secrets.md#downscoping-each-runs-gcp-token).
