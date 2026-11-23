# 0165: Service accounts in access reviews

## Status

Accepted (23 Nov 2026). Sixth slice of [#53](https://github.com/CG-Labs/superbot/issues/53) (M5, "Advanced RBAC"), on top of [ADR 0143](0143-service-accounts.md) (service accounts) and [ADR 0152](0152-service-accounts-in-the-apps.md) (service accounts in the apps). Extends [ADR 0099](0099-access-review-report.md) (the access-review report and its sign-off) and [ADR 0142](0142-type-ii-evidence-bundles.md) (Type II evidence bundles).

## Context

The access-review report (ADR 0099) lists everyone who can sign in. Service accounts can't sign in, so they were left out: `users()` skips them. But they hold access. Each has a role, maybe a custom role or a team, an owner whose permissions cap it, and API tokens that a script uses all day. A reviewer signing off a quarter's access saw none of this. The report's digest didn't cover it either, so a new token or a wider role between loading and signing off didn't stop the sign-off. SOC 2's CC6.2 and CC6.3 cover non-human access too, and auditors ask for it.

## Decision

### In the report, beside people

`GET /api/access-review` gets `serviceAccounts`: every service account that isn't deleted, by name. Disabled ones are listed too, because enabling one brings its tokens back. Each has:

- **Who**: id, name, description, role, status, when it was made and by whom.
- **Its roles**: its custom role across the server with that role's permissions, or its team (as a plain member) with its custom role's team permissions there.
- **Its owner**: id, name, email, status, and `ownerActive`. An owner who is disabled, erased or gone lends nothing, so the account's tokens are refused.
- **What it holds and can use today**: `permissions` and `teamPermissions` as its roles give them, and `effective`: what its tokens can use now, capped by its owner. Empty while it or its owner is inactive.
- **Bot access**: each Bot its role reaches, decided by the same ACLs as for a person ([ADR 0017](0017-bot-acls.md)). A team's account reaches its team's shared Bots.
- **Live tokens**: id, name, preview (`sbsa_…` and its last four characters), scopes (`null` means everything it holds), when it was made, when it expires, when it was last used, and whether it was rotated and is in its overlap. Revoked and expired tokens hold nothing, so they're left out.
- **Flags**: codes the server works out so that the app, the CSV and the bundle agree: `disabled`, `owner_inactive`, `unscoped_token` (a live token with everything the account holds), and `unused_token` (a live token not used for 90 days, counting from when it was made if never used).

Service accounts aren't people, so they stay out of `groups` and the people counts. The summary adds `serviceAccounts`, `serviceApiAccess` (their live tokens) and `serviceAccountsFlagged`. The name follows `apiAccess`, because the audit log redacts detail keys that contain "token" and the summary is saved with each sign-off.

As for people, the report is metadata only. It never has a token, its hash, or the address a token was last used from. That stays on the Service accounts screen (ADR 0152), where an admin investigating one account looks.

### In the digest

The digest covers each listed account's role and status, custom roles with their permissions, team, owner and `ownerActive`, `effective`, Bot access with grants, and each live token's id, scopes, expiry and whether it was replaced. So a new token, a wider scope, a role or team change, or an owner leaving makes the old digest stale. The export and the sign-off then answer 409, as for any other change in access.

When a token was last used is left out, as a session's is. A script calling during the review changes nothing. The flags are left out too: `unused_token` changes with time alone, not with access.

With no service accounts listed, the digest is worked out exactly as before. Reports from servers that never made one, or deleted them all, keep their digests.

### In the CSV and the evidence bundle

The CSV export gets one row per service account after the people, and four columns before `report_digest`: `kind` (`person` or `service_account`), `owner` (name, id, and `inactive` when it lends nothing), `effective_permissions`, and `service_tokens` (each live token's name, preview, scopes, expiry and last use). People's rows leave the new cells empty. Service accounts' rows leave the email, second-factor, sign-in and machine cells empty, because they have none. Every row still starts with when the report was made and ends with its digest.

The evidence bundle's `access-review.json` gets `serviceAccounts` with ids, roles, owner id, `effective`, token ids, scopes and dates, and flags. As for people, no names, descriptions or token names are included, since they're free text. The section's period events now count `service_account.*` and `service_token.*`.

### In the app

The access-review screen gets a **Service accounts** section after the people. Each account shows its role and team, its flags in words ("Owner inactive", "Token with everything", "Token unused 90 days"), its owner, what it can use today, its Bots, and each live token. The summary line counts service accounts and their live tokens. The section is left out when there are none, and against servers from before this change.

## Alternatives considered

- **Service accounts as people's rows in `groups`.** One list, but every client would have to handle rows with no email, second factor, sign-in or machine. Older clients would show them as people without a second factor. A separate list keeps both shapes honest. Older clients ignore it.
- **A separate service-account review and sign-off.** Auditors want one dated record saying the whole list was reviewed. Two sign-offs would mean two digests to match and two records per quarter.
- **Listing revoked and expired tokens.** They hold nothing, and the Service accounts screen and the audit log keep their history. The review is about access that exists now.
- **Last use in the digest.** Every call a script makes would make the reviewer reload. Sessions leave it out for the same reason.
- **Flags in the client only.** The CSV and the bundle need them too. Working them out once on the server keeps all three the same.

## Consequences

- A sign-off now covers non-human access: every service account, its owner, what it can use, and its live tokens. Changing any of it makes the sign-off stale.
- The CSV has four more columns. Tools that read it by column name keep working. Tools that read it by position need the new layout.
- Each report reads every service account's tokens and works out its Bot access. That is a few more queries per account, which is fine at the scale of one report.
- Still to do for #53: letting a service account own Bots or be granted one, per-account refusal counts, and a delegate's view of the service accounts they own in the app.
