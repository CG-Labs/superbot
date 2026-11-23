# 0196: SCIM tokens expire and rotate

## Status

Accepted (23 Nov 2026). Part of [#51](https://github.com/CG-Labs/superbot/issues/51) (SCIM provisioning). Builds on [ADR 0023](0023-scim.md) (per-tenant tokens), [ADR 0026](0026-scim-review-hardening.md) (review hardening) and [ADR 0144](0144-tam-programme-and-health-score.md) (the health score). Follows [ADR 0143](0143-service-accounts.md)'s service tokens, which already expire and rotate.

## Context

A SCIM token is a server-wide write credential: whoever holds one can create, change and deactivate everyone its tenant provisioned. Until now it never expired, and the only way to change it was to make a second token and revoke the first by hand. Enterprise security reviews (and SOC 2's CC6.1 and CC6.2) ask that integration secrets have a lifetime and a rotation procedure, and that their end is visible before it bites.

SCIM tokens differ from service tokens in one way that drives every choice below: **when a SCIM token stops, deprovisioning stops.** Entra and Okta can no longer deactivate people who leave, and nobody is told unless they watch the IdP's provisioning log. A token that expires silently is a worse security outcome than one that lives long.

Neither Entra ID nor Okta rotates a SCIM bearer secret itself: an admin pastes a new one into the app's provisioning settings. So rotation needs an overlap in which both tokens work.

## Decision

### Every new token expires

`POST /api/scim/tokens` takes `expiresInDays`, 1 to 730, default **365** (`botctl scim token create <tenant> --days N`). The default is a year, longer than ADR 0143's 90 days for service tokens, because each rotation is a manual step in the IdP and a missed one stops deprovisioning; a year is the cadence most enterprise credential policies ask of integration secrets. 730 days is the cap: no new token lives longer.

An expired token is refused with 401 like a revoked one, and audited as `scim.auth_failed` with `reason: "expired"`, its tenant and the token as target (and `rotatedTo` for a rotated one), throttled as other bad tokens are.

### Tokens made before this keep working

Tokens made before this change have no `expiresAt` and keep working (`state: "no_expiry"`). Giving them an end on upgrade would stop provisioning on a date no admin chose or was told about. They are flagged instead: the console shows "Never (rotate it)", the token list says `no_expiry`, and rotating one gives the old token an end (the overlap) and the new one a normal lifetime. ADR 0143 refuses never-expiring tokens outright; here that applies only to new ones.

### Rotation with an overlap

`POST /api/scim/tokens/{id}/rotate {expiresInDays?, keepOldHours?}` (`botctl scim token rotate <id> [--days N] [--keep-old-hours N]`, and a Rotate button in the console) makes a new token for the same tenant, label and SSO link, shown once with `Cache-Control: no-store`. The old one keeps working for `keepOldHours`, default **24**, at most 168 (a week), so the admin can paste the new token into the IdP and run **Test Connection** first; `0` revokes it at once. The overlap never lengthens the old token's life: it ends at the earlier of its own end and the overlap.

A token rotates once (`rotatedTo`); a revoked, expired or rotated one can't be rotated (409). The old token's update and the new token's insert are one transaction, conditional on the old one still being live and unrotated, so two concurrent rotations make one new token. Audited as `scim.token_rotated` with the new token's id, when the old one stops (`oldEndsAt`) and when the new one expires; never either value.

The new token is a new row, not a new secret on the old row: its id, `createdAt` and `lastUsedAt` say which one the IdP is actually sending, which is how an admin checks the switch-over happened before the overlap ends.

### Warning before the end

botd checks every 10 minutes (and at start) and audits, once per token:

- `scim.token_expiring`, 14 days before it ends (`daysLeft`);
- `scim.token_expired`, outcome `failure`, once it has ended.

Each says whether the token's tenant still has a working token (`tenantWorking`) and when the tenant's provisioning stops if nobody acts (`tenantEndsAt`: the latest end of its working tokens, null if one never expires). A tenant with a second token outlasting the first is fine; a tenant whose last token is ending is the case to act on. Rotated and revoked tokens end as planned and get neither event. Which notice was audited is kept on the token (`expiry_notice`). Each notice is claimed (a compare-and-set on it, only while the token is still unrevoked and unrotated) and its tenant's tokens read in the same transaction that writes the audit event: a notice that can't be recorded stays owed for the next pass, one already recorded is never repeated, and a token rotated or revoked after the pass read it gets none.

These are audit events rather than emails because the audit log is where SCIM's other alerts already go (`scim.auth_failed`, `scim.request_failed`), and it reaches the customer's SIEM ([ADR 0122](0122-siem-export-and-tamper-evident-audit.md)), which is where enterprise operators alert on credential expiry.

The same facts show where admins look:

- `GET /api/scim/tokens` gives each token a `state` (`active`, `expiring`, `rotated`, `expired`, `revoked`, `no_expiry`) and lists `expiringTenants`: tenants with a working token whose every working token ends within 14 days. The console's SCIM section says so above the table.
- The [health score](../support/health-score.md#identity)'s `identity` signal is at least **watch** while any tenant is in `expiringTenants` (`scimTenantsExpiring`, only a count, since health reports go into support bundles and a tenant's name can identify a customer), and counts requests with an expired token as `expired_token`, as it counts revoked ones.

## Consequences

- A tenant nobody rotates stops provisioning after a year, with two audit events and a health-score warning first. That is the intended trade: a bounded credential, made visible.
- Upgrading changes nothing for existing tokens until an admin rotates them.
- One migration adds `expires_at`, `rotated_to` and `expiry_notice` to `scim_tokens`; all nullable, nothing backfilled.
- The Google Workspace sync ([ADR 0162](0162-google-workspace-directory-sync.md)) uses no token and is unaffected.

## Alternatives considered

- **Expire existing tokens on upgrade (e.g. a year after creation).** Closest to "no token lives forever", but a server upgraded years after its token was made would stop deprovisioning that day. Rejected; flagged instead.
- **The 90-day default of service tokens.** Four manual IdP changes a year per tenant, each a chance to stop deprovisioning. Rejected for the default; `--days 90` is there for those whose policy asks.
- **Rotating the secret in place (same token id).** Simpler listing, but loses the evidence of which secret the IdP is sending during the overlap, and two secrets on one row complicate the hash lookup. Rejected.
- **Notifying by email.** botd's mail is set up for Bots' approvals and billing, not server admins' operational alerts, and would need a new recipient setting. The audit log and SIEM are the existing path; email can follow if asked for.
- **OAuth client credentials instead of bearer tokens.** RFC 7644 allows it and Okta supports it, but Entra's non-gallery SCIM app takes only a long-lived bearer secret. Out of scope.
