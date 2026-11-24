# 0224: SCIM token scopes

## Status

Accepted (24 Nov 2026). Part of [#51](https://github.com/CG-Labs/superbot/issues/51) (SCIM provisioning). Builds on [ADR 0023](0023-scim.md) (per-tenant tokens), which left per-token scopes for M5, [ADR 0026](0026-scim-review-hardening.md) (the SCIM review) and [ADR 0196](0196-scim-token-expiry-and-rotation.md) (expiry and rotation). Closes what the [SCIM review](../security/auth-review-2026-11-scim.md)'s SCIM-10 left open ("Scopes are still open"). Follows the scoped service tokens of [ADR 0143](0143-service-accounts.md). 0225 to 0228 are held by other open pull requests.

## Context

A SCIM token can do everything SCIM can do for its tenant: create, change, deactivate and delete people, and, with `SCIM_GROUPS=on`, make and delete teams and move people on and off them. With `SCIM_GROUP_ROLES=on`, group membership gives custom roles through mappings and role groups ([ADR 0138](0138-scim-group-role-mapping.md), [ADR 0180](0180-scim-role-groups.md)). So whoever holds a token holds all of that, whatever the connection needs.

Many connections need less:

- **Users only.** A tenant that provisions people while teams are run by hand, or by another tenant. If its token leaks, or the IdP's admin pushes a group by mistake, it should not be able to make a team or put people on one, and so not reach a role a mapping gives.
- **Read only.** Identity governance and reconciliation tools (access certification, joiner-mover-leaver audits) list users and groups to compare with the IdP. They must never deactivate anyone, which is the most damaging thing a SCIM write can do.
- **Groups only.** A sync script that manages teams for people another connection provisions.

Enterprise security reviews ask for least privilege on integration credentials (SOC 2 CC6.1 and CC6.3), and service tokens already have scopes ([ADR 0143](0143-service-accounts.md)). SCIM tokens were the remaining long-lived credential without them.

## Decision

### Four scopes

| Scope | Allows |
|-------|--------|
| `users:read` | `GET` on `/Users` and `/Users/{id}` (lists and filters) |
| `users:write` | `POST`, `PUT`, `PATCH` and `DELETE` on users, and reading them |
| `groups:read` | `GET` on `/Groups` and `/Groups/{id}` |
| `groups:write` | `POST`, `PUT`, `PATCH` and `DELETE` on groups, and reading them |

A write scope includes the read of the same resource: Entra and Okta look a resource up before they change it, so a write without its read is a token that fails in confusing ways. The scopes are stored and shown with the read filled in (`users:write` is listed as `["users:read", "users:write"]`), so what an admin sees is what the token can do.

Scopes are about which requests a token may send, nothing else. A `users:write` token's `DELETE` still takes the person off their team and away from their mapped roles, as deprovisioning always does ([ADR 0124](0124-deprovisioning-stops-bots-and-machines.md)); a `groups:write` token can only put on teams people its tenant provisioned, as before. Tenant scoping, the rate limit, SCIM's switches (`SCIM_GROUPS`, `SCIM_GROUP_ROLES`) and the rule that SCIM never names a role are unchanged: a scope narrows a token, never widens what SCIM can do.

**Discovery stays open.** `ServiceProviderConfig`, `ResourceTypes` and `Schemas` describe the server, not its people, and IdPs read them while testing a connection. They answer any valid token, whatever its scopes, and list both resource types.

### Enforced twice, from one table

- **The guard** ([ADR 0023](0023-scim.md)'s, which every `/scim/v2` request passes) works out the scope a request needs from its method and path: `GET` and `HEAD` read, anything else writes, on the resource named by the first path segment after `/scim/v2`. `Users` and `Groups` match in any case with empty segments skipped, more loosely than the router, so any path that reaches their handlers is checked. The open paths (`ServiceProviderConfig`, `ResourceTypes`, `Schemas`, `Bulk`) match exactly. **Anything else needs every scope**: no handler serves such a path today (a full token gets 404, a narrowed one 403), and a SCIM route added later without a scope of its own is closed to narrowed tokens until it gets one, rather than open to them. The check runs after the token and rate-limit checks, so a refused request counts against the tenant's rate as any other request does.
- **Bulk** ([ADR 0153](0153-scim-bulk.md)) checks each operation before handing it to its handler: every Bulk method writes, so an operation on `/Users` needs `users:write` and one on `/Groups` needs `groups:write`. The check comes before `bulkId` resolution, so the answer is about the scope. The rest of the request runs as before, so a users-only token's Bulk request with group operations provisions its people and refuses the groups.

A route test calls every SCIM route with a token of each single scope and checks it is refused exactly when it should be, and that unknown paths are refused to every narrowed token.

### The refusal

`403` with the SCIM error schema (RFC 7644 has no `scimType` for it), a detail naming the token's scopes and the one it lacks, and RFC 6750's challenge, `WWW-Authenticate: Bearer realm="SuperBot SCIM", error="insufficient_scope", scope="groups:write"`. A Bulk operation's result carries the same error in its `response`.

It is audited as `scim.request_failed` with `reason: "insufficient_scope"` and `scope`, like every other refusal of a valid token, so it reaches the SIEM and the [health score](../support/health-score.md#identity)'s SCIM failures with no change there. Each refused Bulk operation is its own event, as its own request's would be. An IdP pushing groups with a users-only token is a misconfiguration the customer should see, and a token used outside its scopes may have leaked.

### Making, rotating and listing

- `POST /api/scim/tokens` takes `scopes`, a list of one or more names; left out, the token gets all four, so existing scripts and docs make the same tokens as before. An empty list, an unknown name (including `admin`) or anything not a list of strings is a 400, and nothing is made. `botctl scim token create <tenant> --scopes users:write`, comma-separated. The console's SCIM form offers **Users and groups** (the default), **Users only** and **Read only**; other combinations are `botctl` or the API.
- `POST /api/scim/tokens/{id}/rotate` gives the new token the old one's scopes, or `scopes` if sent (`--scopes`), so rotation is also how a token is narrowed or widened without a gap. A token's scopes never change in place: a new secret goes with new powers, and the old row keeps a record of what the old secret could do.
- `GET /api/scim/tokens` shows each token's `scopes` and the list of all scopes; the console shows them as "Can: users (read and write), groups (read)". `botctl` prints a new token's scopes, with a reminder to turn group provisioning off in the IdP when it can't write groups.
- `scim.token_created` and `scim.token_rotated` record `scopes`; a rotation that changes them records `oldScopes` too.

### Tokens from before

The migration adds a nullable `scopes` column and fills nothing. A null is all four scopes, so an upgrade changes nothing any IdP can do, exactly as ADR 0196 kept tokens from before expiry working. They are listed with all four and can be narrowed by rotating them. New tokens always store their list.

Stored names this version doesn't know grant nothing, and a list that can't be read grants nothing: a downgrade or a damaged row fails closed, to a token that can only read discovery.

The Google Workspace sync ([ADR 0162](0162-google-workspace-directory-sync.md)) uses no token; its pass acts with all four scopes, as before.

## Consequences

- An admin can give each IdP connection only what it needs, and a read-only token for governance tools can't deprovision anyone, directly or through Bulk.
- A users-only token on a connection that also pushes groups makes the IdP report 403s for its group operations until group provisioning is turned off there or the token is rotated with `groups:write`. The detail, the challenge and the audit event say which.
- One migration (a nullable column); no new setting, no new audit action.
- SCIM-10 in the [SCIM review](../security/auth-review-2026-11-scim.md) is closed.

## Alternatives considered

- **A read-only flag instead of scopes.** Covers governance tools, not a users-only connection, which is the case that keeps a leaked token away from teams and the roles they carry. Rejected.
- **Separate read and write scopes with no implication.** Closer to OAuth convention, but a `users:write` token without `users:read` fails Entra's and Okta's lookups before every write, so every useful token would need both. Rejected; the implied read is shown, not hidden.
- **Finer scopes (deactivate, delete, members, the Enterprise extension).** Nothing asks for them yet; a scope per attribute multiplies the cases to test and to explain. Users and groups, read and write, cover the connections above. Finer ones can be added as new names without changing these.
- **Filtering discovery by scope** (listing only the resource types a token can reach). IdPs read discovery to test a connection; hiding Groups would make a misconfiguration look like a missing feature instead of a 403 that names the scope. Rejected.
- **Enforcing in each handler.** Twelve handlers each with a check is twelve places to forget one; the guard sees every request and Bulk calls the handlers directly, so those are the two places, both covered by the route test.
- **Changing scopes in place.** Simpler than rotating, but the same secret would gain powers it didn't have when it was handed to the IdP, and the record of what it could do would be lost. Rejected; rotate.
- **Defaulting new tokens to users only when `SCIM_GROUPS` is off.** Safer by default, but a token made before an admin turns groups on would then fail once they do. The console makes the choice visible instead.

## Not done

- Per-tenant scopes (every token of a tenant held to the same ceiling). Tokens are per connection already, and an admin makes every token.
- OAuth client credentials ([ADR 0196](0196-scim-token-expiry-and-rotation.md)'s alternative), which would carry scopes in the standard way; Entra's non-gallery SCIM app takes only a bearer secret.
