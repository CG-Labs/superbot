# 0230: Session policies and tags for each run

## Status

Accepted (24 Nov 2026). Part of secrets vault integration in M5, [#55](https://github.com/CG-Labs/superbot/issues/55). Builds on STS sessions for each run ([ADR 0194](0194-sts-sessions-for-each-run.md)), which left "session policies or tags per run" for later and named the setup they need (`sts:TagSession`) and the open question (a format for policies in a setting).

## Context

With `AWS_RUN_CREDENTIALS`, each run gets an STS session of an IAM role. A run gets everything its role allows. To give each user's Bots access to only their own data, an operator today makes a role per user (`role/superbot-u-{owner}`), which means an IAM role, trust policy and permissions for every user, made outside SuperBot before that user's first run.

STS can narrow a session as it makes it, with no change to the role:

- a **session policy**, inline (`Policy`, at most 2048 characters) or managed (`PolicyArns`, up to 10): the session gets only what both the role and these policies allow;
- **session tags** (`Tags`): the role's own policies can match on them (`aws:PrincipalTag/<key>`), so one role can scope each session by who it is for. Tags need `sts:TagSession` in botd's policy and the role's trust policy. Marked transitive (`TransitiveTagKeys`), they carry into sessions chained from this one and can't be set again under the same key there.

A Bot runs code: whatever narrowing it gets must come from botd, never from the run.

## Options

1. **A role per owner** (`{owner}`, ADR 0194). Works today. Every user needs an IAM role made ahead of time; that doesn't scale past a team.
2. **Separate settings** (`AWS_RUN_SESSION_POLICY`, `AWS_RUN_SESSION_TAGS`) for all roles. One policy for every role rarely fits, and tags fail for any role whose trust policy lacks `sts:TagSession`. Rejected.
3. **Options on each entry** of `AWS_RUN_CREDENTIALS`, next to its role: `policy=<file>`, `policy-arn=<arn>` and `tags=bot,owner`. Chosen: each role gets the narrowing that fits it, the setting stays one line per role, and an entry with no options is exactly as before.
4. **The policy inline in the setting.** A JSON policy has spaces and `;`, which the setting's format splits on, and doesn't fit in an environment variable well. A file it is.
5. **Templates with any variable** (`{user.email}`, request context). Only the two ids botd is sure of are offered: the Bot's and the owner's. Owner ids are lowercase letters and digits, Bot ids are checked to be letters, digits, `-` and `_`, so neither can be a wildcard or a path in an ARN.
6. **The same for Vault's AWS engine, GCP and Azure.** Vault's AWS roles already take `policy_document`, `policy_arns` and `session_tags`, set on the Vault role, not per request; Google's generateAccessToken and Entra's tokens have no session policy (GCP's Credential Access Boundaries are a separate token exchange, for Cloud Storage only). Left out; their settings refuse these options.

## Decision

### Setting

Each `AWS_RUN_CREDENTIALS` entry may have, after its role's ARN and among its `NAME=field` pairs:

- `policy=<file>`: an inline session policy. botd reads it once at startup and refuses to start unless it is JSON with a `Statement` (an object or array), at most 64 KiB on disk, at most 2048 characters once written compactly, and only characters up to U+00FF (what STS takes in a policy). Its path has no spaces (the setting splits on them). Its contents are never quoted in errors. At most one per entry.
- `policy-arn=<arn>`: a managed session policy, `arn:<partition>:iam::<account or aws>:policy/<path/name>`, in the role's partition. Up to 10 per entry, each once.
- `tags=bot`, `tags=owner` or `tags=bot,owner`: the session tags `superbot-bot=<bot id>` and `superbot-owner=<owner id>`, both transitive. At most once per entry.

Options aren't variables, so an entry with only options still gives `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` and `AWS_SESSION_TOKEN`. The names are lowercase, which no variable may be, so they can't be mistaken for one. The other run credentials settings (`VAULT_RUN_CREDENTIALS`, `GCP_RUN_CREDENTIALS`, `AZURE_RUN_CREDENTIALS`) refuse them by name. The parser is shared; a `Syntax` says whether its entries take them.

### Each run

`{owner}` and `{bot}` in the policy's keys and strings, and `{owner}` in a managed policy's name, become the run's owner id and Bot id. They are put into the parsed JSON as strings, then the policy is written compactly, so an id can't change the policy's shape. An entry whose policy, managed policies or tags name the owner is only for runs that get the owner's own secrets, as a role with `{owner}` is (ADR 0174): a teammate's run of an isolated shared Bot gets no session that the owner's tag or policy would scope.

The run is refused (`secrets_unavailable`) before STS is asked when the Bot's id can't stand in a policy or tag, or when the policy is over 2048 characters with the ids in. The other leases already made for the run are let go as before. STS's refusals name the likely cause: `sts:TagSession` for `AccessDenied` with tags, the policies for `MalformedPolicyDocument`, and their combined packed size for `PackedPolicyTooLarge` (STS packs policies and tags together into a limit it doesn't publish exactly, so botd can't check it beforehand).

### Audit

`secret.lease_issued` adds `policySha256`, the SHA-256 of the policy exactly as sent (compact JSON, keys sorted, ids in), `policyArns` and `tags`, when they are set. An auditor can tie a session to a policy file without the audit log holding the policy or the file's path. None of these is a secret; keys are never in it.

### Code

`leases` gains `Narrowing` (per entry, parsed at startup) and `Narrowed` (per run, ids filled in), `Wanted::narrowing`, and `Issuer::issue_narrowed`. Its default refuses a non-empty narrowing, so a backend that can't narrow fails closed instead of making a wider credential; `aws::SecretsManager` overrides it to add `Policy`, `PolicyArns.member.N.arn`, `Tags.member.N.Key/Value` and `TransitiveTagKeys.member.N` to `AssumeRole`. Vault, GCP and Azure are unchanged.

## Consequences

- No change unless an entry has one of these options.
- One role can serve every user: tag sessions with `tags=owner` and scope the role's policies with `${aws:PrincipalTag/superbot-owner}`, or give a session policy with `{owner}` in its resources. No role per user.
- Tags need `sts:TagSession` on the role for botd's identity and in the role's trust policy. Without it, runs are refused with that named.
- A narrowing can only take away from the role: a mistake in a policy gives a run less, never more. A policy file botd can't read stops botd at startup, not a run.
- Editing a policy file needs a restart, as the setting does.
- Tested in `server/src/secrets/leases.rs` (options parsed and checked: missing, unreadable, non-JSON, oversized and non-Latin-1 files never quoted; managed policy ARNs, partition, limits; tags; refused by the other settings; the owner rule; ids filled in as JSON, policies sent compact; the audit's hash, ARNs and tags; Bot ids that can't stand in a policy, and policies that grow past the limit, refused before any request; backends that can't narrow refusing) and `server/src/secrets/aws.rs`, against the stand-in STS that checks every SigV4 signature over the new fields: the policy, managed policies and transitive tags with the run's ids, an entry with no options sending none, a teammate's run getting no owner-scoped session, and `AccessDenied`, `MalformedPolicyDocument` and `PackedPolicyTooLarge` named.
- Ops guide: [docs/ops/cloud-secrets.md](../ops/cloud-secrets.md#narrowing-each-runs-session).
