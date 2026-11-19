# 0019: Per-user audit actors and IdP

## Status

Accepted. An M2 slice ([roadmap](../ROADMAP.md#m2--multi-user--sso)): audit log with per-user actors and IdP ([#23](https://github.com/CG-Labs/superbot/issues/23)). Extends [ADR 0009](0009-audit-events.md) (the audit table) on top of users and sessions ([ADR 0012](0012-users-sessions-rbac.md)), SSO ([ADR 0014](0014-oidc-sso-entra.md), [ADR 0016](0016-sso-multi-provider.md), [ADR 0018](0018-sso-github-apple.md)), and bot ACLs ([ADR 0017](0017-bot-acls.md)).

## Context

ADR 0009 left room for people: `actor_id` became the user id and `actor_subject` the IdP subject once users and SSO landed. That still can't answer the questions an admin asks of an audit log:

- **How did they get in?** Break-glass `AUTH_PASSWORD`, a sign-in code, or SSO, and through which provider. A break-glass session and an Entra session for the same owner look the same today.
- **Which sign-in?** Revoking a stolen session needs its id, and an investigation needs every action that session took.
- **Who was it then?** Emails and roles change. The log should keep what was true when the person acted.
- **Who is a Bot acting for?** Bots act with their owner's access (ADR 0017), and routines run with nobody signed in. Neither says whose authority was used.
- **What did the Bots run?** Bot runs and harness invocations aren't recorded at all, so "who made this Bot push to git" has no answer.

## Decision

### The actor

Every event's actor gains seven fields, set where the request is authenticated (one place, the auth middleware, plus sign-in and the runner):

| Field | Column | API | Value |
|-------|--------|-----|-------|
| Email | `actor_email` | `actorEmail` | The user's email when they acted. |
| Role | `actor_role` | `actorRole` | `admin`, `member`, or `readonly`, when they acted. |
| Method | `auth_method` | `authMethod` | `password` (break-glass `AUTH_PASSWORD`, Basic or login), `code` (one-time sign-in code), `sso`, `none` (`ALLOW_NO_AUTH` on loopback), or `bot_token` (`botctl` with the per-start `BOT_TOKEN`). |
| IdP | `idp` | `idp` | The SSO provider's type: `entra`, `google`, `oidc`, `github`, `apple`, `saml` (the SAML bridge, [ADR 0020](0020-saml-bridge.md)). |
| Provider | `idp_provider` | `idpProvider` | Its configured id from `SSO_PROVIDERS` (two Entra tenants are two providers). |
| Session | `session_id` | `sessionId` | The session's id. Never its token. |
| On behalf of | `on_behalf_of` | `onBehalfOf` | For a Bot or a scheduled run: the user whose authority it used (the Bot's owner). |

`actor_id`, `actor_name`, and `actor_subject` (`<issuer>|<sub>`) keep their meaning. `idp` and `idp_provider` mirror the `idp` and `provider` that SSO sign-in details already carry (ADR 0018), so the two read the same.

How each kind of actor looks:

- **Person**: `actor_kind=user`, their id, name, email, role, method, and (for SSO) IdP, provider, subject, and session. Basic auth with `AUTH_PASSWORD` has no session: it is `operator`, method `password`, session empty.
- **Bot** (`botctl`): `actor_kind=bot`, the Bot it names (still self-reported until per-Bot tokens), method `bot_token`, on behalf of its owner. An unnamed Bot call has no id and no owner.
- **System**: `actor_kind=system`, the part (`scheduler`, `approvals`, `migration`, ...). The scheduler also records on behalf of the routine's Bot owner.

The provider type is looked up from the live SSO config, and the session stores its provider id (`sessions.idp_provider`), so a session's events keep naming its provider for as long as it lives. GitHub and Apple (ADR 0018) needed nothing of their own: every SSO type goes through the same session code.

### Runs and harness invocations

A queued message stores who asked for it (`messages.requested_by`, the actor and source as JSON), so the run it starts is attributed even after a restart:

| Trigger | Run is attributed to |
|---------|----------------------|
| A person's chat message | That person, with their session. |
| `botctl ask` from a Bot | The asking Bot, on behalf of its owner. A person asking: the person. |
| A reply to `botctl ask` that arrived late | The Bot that replied, on behalf of its owner. |
| A routine | `system:scheduler`, on behalf of the Bot's owner. |
| A message queued before this change | `system:runner`, on behalf of the Bot's owner. |

Each run records `harness.invoked` per harness start (details: harness, model, effort, policy mode, guarded, resumed, attempt, trigger, message id) and one `bot.run_finished` (outcome, result `done`, `stopped`, `timeout`, `interrupted`, `unguarded`, `policy`, or `error`, duration, replies, attempts). Prompts and replies are never recorded, as before. Approval requests and handoffs are the Bot's, on behalf of its owner; decisions carry the deciding person's full actor, as every API action does.

### Schema migration

Migration 6 adds nullable columns only, plus `sessions.idp_provider` and `messages.requested_by`, and two partial indexes (`on_behalf_of`, `session_id`). Old rows keep `NULL`: the table is append-only (ADR 0009), and inventing who did something before it was recorded would be rewriting history. An upgrade writes one `audit.schema_upgraded` event (`system:migration`) so the boundary is on the record. Older clients that read `/api/audit` see extra fields and nothing removed.

### Filters and export

`/api/audit` and the CSV export take, beside the existing ones:

- `actor=user:<email>`: the user who has that email now; if none does, events recorded with it (case-insensitive). `actor=user:<id>` as before.
- `method=sso,password`, `idp=entra`, `idpProvider=<id>`, `subject=<issuer|sub>`, `session=<id>`, `onBehalfOf=<user id or email>`.

`botctl audit` and `botctl audit export` have matching flags (`--method`, `--idp`, `--idp-provider`, `--subject`, `--session`, `--on-behalf-of`). The CSV keeps its first fourteen columns in place and appends `actor_email,actor_role,auth_method,idp,idp_provider,session_id,on_behalf_of`, so scripts that read columns by position keep working. `audit.exported` records the filter, emails resolved to ids.

### Secrets

Unchanged rules, one more place: the actor's name and email and the user agent go through the same redaction as details (registered secret values and credential patterns), then are clipped. Session ids are not secrets; tokens never reach the actor.

### Web

The `web/` Audit log shows each actor's role and how they signed in under their name (`member · SSO · entra (work)`, `Bot token · for Ada`), with email, subject, session, and on-behalf-of in a tooltip, and filters by person (email or id) and sign-in method. The Expo client has no audit view yet; that stays a follow-up rather than growing this slice.

## Consequences

- An admin can answer who did what, how they signed in, from which session, and for whom a Bot acted, for API actions, sign-ins, approvals, config changes, Bot runs, and harness invocations.
- Revoking a session can be followed by `?session=<id>` to see everything it did.
- The audit table grows by a few short columns per row and two `harness`/`run` events per Bot task. Retention (`AUDIT_RETENTION_DAYS`) covers both.
- Bot ids are still self-reported (shared `BOT_TOKEN`); `on_behalf_of` is derived from the claimed Bot. Per-Bot tokens (later) make both verified without a schema change.
- Rows from before migration 6 have no actor details; filters by method, IdP, or session don't match them.

## Alternatives considered

- **Backfill old rows from sessions or users.** Rejected: the table is append-only by trigger, and today's email or role is not the one they had.
- **One JSON `actor` column.** Simpler to migrate, but filters and indexes need real columns, and CSV consumers need flat cells.
- **Attribute Bot runs to the Bot only.** Loses the person who started the chain, which is the question that matters after an incident.
- **Record prompts in `harness.invoked`.** Rejected for the same reason chats aren't in the log: they can carry secrets and personal data.
