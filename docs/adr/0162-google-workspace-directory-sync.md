# 0162: Google Workspace provisioning through the Directory API

## Status

Accepted (23 Nov 2026). Part of SCIM provisioning in M5, [#51](https://github.com/CG-Labs/superbot/issues/51). Builds on the SCIM stub and its review ([ADR 0023](0023-scim.md), [ADR 0026](0026-scim-review-hardening.md)), groups as teams ([ADR 0095](0095-scim-groups-as-teams.md)), deprovisioning ([ADR 0124](0124-deprovisioning-stops-bots-and-machines.md)), group-to-role mapping ([ADR 0138](0138-scim-group-role-mapping.md)), and SCIM Bulk ([ADR 0153](0153-scim-bulk.md)), which first called the SCIM handlers directly.

## Context

Google Workspace was the last item on #51. Entra ID and Okta push SCIM to `/scim/v2`, but Google doesn't, for apps like ours:

- **Automatic provisioning** in the Admin console works only for apps in Google's catalog, each with a connector Google wrote for it.
- **Custom SCIM apps** (a bearer token and a SCIM base URL, like Okta's integration wizard) exist only as a limited beta. A customer in it can already point it at `/scim/v2` with a token; nothing more is needed for them.
- **Google Cloud Directory Sync** goes the other way (LDAP into Google).

So for most Workspace customers, the guide's advice was to put Entra ID or Okta in front of Google. That is a second IdP to buy and run just to provision.

What Google does offer every Workspace is the **Admin SDK Directory API**: list a customer's users (with `suspended` and `archived`), get a group, and list its members (nested groups expanded with `includeDerivedMembership`). A **service account** reaches it with an OAuth 2.0 JWT bearer grant (RFC 7523). It either has **domain-wide delegation** for chosen scopes and acts as an admin (the JWT's `sub`), or holds an admin role itself. Two read-only scopes are enough: `admin.directory.user.readonly` and `admin.directory.group.readonly`. And a Directory user's `id` is their Google ID, which Google's OpenID Connect documentation says is the `sub` of their ID tokens. So it links to Sign in with Google with no matching on email.

## Decision

### Pull from the Directory API, write through SCIM

With `GOOGLE_DIRECTORY_SYNC=on`, botd reads the directory every `GOOGLE_DIRECTORY_INTERVAL_MINUTES` (30 by default, 5 to 1440, first a minute after start), and on an admin's `botctl scim google sync` (`POST /api/scim/google/sync`). Each pass:

1. Signs a JWT with the service account's key (RS256, the two read-only scopes, `sub` = `GOOGLE_DIRECTORY_ADMIN` if set) and trades it for an access token.
2. Gets each group in `GOOGLE_DIRECTORY_GROUPS` and `GOOGLE_DIRECTORY_TEAM_GROUPS` (by email), then every page of its members with derived membership. `USER` members are people. A `CUSTOMER` member means the whole customer. `EXTERNAL` members, and users the customer's list doesn't have, are outside the domain and never provisioned. `GROUP` members are already expanded.
3. Lists every page of the customer's users (`GOOGLE_DIRECTORY_CUSTOMER`, `my_customer` by default), with only the fields it needs.
4. Works out the plan against the tenant's users, then sends each change to **the SCIM handler its request would reach**, with a synthetic `Caller` for the tenant, as Bulk does: `create_user`, `replace_user`, `delete_user`, and the group handlers. A person is a SCIM user with `userName` and `emails` their primary email (lowercase), `externalId` their Directory id, `name` from Google, and `active` = not suspended and not archived. A team group is a SCIM group with `externalId` its Directory id, its name, and its members.

There is no second implementation of provisioning. Roles (`SCIM_DEFAULT_ROLE`, never admin), the seat check, email conflicts (409, never matching on email), deprovisioning (sessions, routines, Bots, machine), restoring a deleted user by `externalId`, linking the SSO identity, team joins and leaves, group-to-role grants, and every audit event are SCIM's, for free and for good.

The sync's writes go into one SCIM tenant, `GOOGLE_DIRECTORY_TENANT` (`google` by default), with the audit actor `scim:google-directory` and method `google_directory`. With `GOOGLE_DIRECTORY_SSO` (which must be a `google` provider), the tenant links each user's identity at that provider with the Directory id as subject, as `--sso` does for a token. SCIM links only the users it creates, so each pass also links users already in the tenant who lack it (as when `GOOGLE_DIRECTORY_SSO` is set after the first pass), audited as `user.identity_linked`.

Unchanged people get no write: the plan compares SCIM's parse of the body it would send with the user as stored. A team is updated only if its name or members differ. Team groups are applied in two steps, removals then additions, so someone who moved between two team groups is moved in one pass. A person is on one team at most, so the first team group listed wins, and someone on a team the sync doesn't manage stays there (SCIM's own rule). A team group removed from the setting is deleted from the tenant as a SCIM group `DELETE` would be.

### The tenant is the sync's alone

Two writers to one tenant would undo each other. botd refuses to start if a live SCIM token uses `GOOGLE_DIRECTORY_TENANT`, and `POST /api/scim/tokens` refuses that tenant while the sync is on. The tenant's users without a matching person are removed, so it should be a new tenant name.

### Fail-closed

A pass that can't read **everything** changes nobody. That covers a key that is missing or invalid, a refused token, a network error, any non-2xx answer, a group that doesn't exist (404), an answer without the expected `kind`, a page whose list isn't a list, a person without an id or a valid email, a page token that repeats, more than 2,000 pages, or a page over 16 MiB. A partial read would look like people leaving. Google omits empty lists, so the `kind` check is what tells "no members" from "not a members answer".

Two guards stop a pass that read fine but would do damage. It may not remove or disable more than `GOOGLE_DIRECTORY_MAX_REMOVALS` people (10 by default; a deactivation of someone active, or a delete of someone active, counts). And it may not leave the tenant with nobody active when it has active people (an empty group, or the wrong one), counting who stays active here: held people don't. Either stops the pass before any write, audited as `denied`. Removals come last, and if earlier writes failed so that nobody would stay active, they wait too. An admin who has checked Google runs `botctl scim google sync --force`.

A failed pass, or one with failed writes, is tried again after 5 minutes (or the interval, if shorter). The last pass and the last good pass are in `GET /api/scim/google` and `botctl scim google`.

### An admin's disable holds

SCIM lets the IdP re-enable someone an admin disabled. A token-based IdP decides that, and its admins can see it. A pull every 30 minutes would silently undo an admin's emergency disable, so the sync is stricter. It enables a disabled user only if the newest event that disabled them was the sync's own (`user.disabled` or `scim.user_deleted` by `scim:google-directory`). Taking a user back or on (`scim.user_restored`, `scim.user_linked`) changes no status by itself, so the search goes on past it. An admin's disable, or one the audit log no longer shows, holds. This covers users the tenant takes back after a delete, and users SCIM takes on through an identity already linked (as after a just-in-time sign-in), too. The pass sends `active: false` for them and lists them as `held`. Enabling them by hand hands them back to the sync. This needs no new table: the audit log already records who disabled whom.

### The key is a server secret

The service account's JSON key is `GOOGLE_DIRECTORY_CREDENTIALS`: `botctl secret set`, the environment, `GOOGLE_DIRECTORY_CREDENTIALS_FILE`, or an external secrets store ([ADR 0125](0125-external-secrets-backend-vault.md), [ADR 0136](0136-cloud-secret-managers.md)), read again on every pass so a rotated key works without a restart. It is in `SERVER_SECRETS`. Without that, the name's `CREDENTIAL` would make the environment store offer its value to every Bot. As a server secret, it is never given to Bots, never saved as a user's secret, and its variables are stripped from harness environments. botd checks at startup that it parses as a service account key. `GET /api/scim/google` never shows it.

### Audit

Each change is SCIM's own events by `scim:google-directory`. Each pass is `scim.google_sync` (target `scim_tenant:<tenant>`). On **success** it carries what was created, updated, enabled, disabled, linked, deleted, held, skipped (suspended people who never had an account), outside the domain, and the team changes. On **failure** it carries `reason` and `detail` when nobody was changed, or the failed SCIM writes (`failed`, `failures`, at most 50, each also `scim.request_failed`). It is **denied** when a guard stopped it. An admin's request is `scim.google_sync_requested` (with `force`) by that admin, before the pass.

### Off by default, admins only

`GOOGLE_DIRECTORY_SYNC=off` unless set. `on` needs `SCIM=on`, at least one group, a valid key, and `SCIM_GROUPS=on` for team groups. At most 50 groups in all. `GOOGLE_DIRECTORY_API_URL` (tests) must be an https origin, or loopback. Both API routes are admin-only (unlisted routes are `Admin` in RBAC). The client follows no redirects, and uses HTTPS only unless the API is on loopback.

## Consequences

- A Workspace customer provisions SuperBot from their own directory with a service account, without a second IdP. With Sign in with Google, people sign in to the accounts the sync made.
- Changes reach SuperBot within the interval rather than at once. Suspending someone in Google takes up to 30 minutes by default to stop their Bots; disabling them in SuperBot, or `botctl scim google sync`, is immediate.
- Every SCIM behaviour, now and later, applies to Google users with no extra work.
- Each pass reads the customer's whole user list. For very large directories that is many requests (500 users a page) every interval; the interval and Google's quotas bound it.
- A key file is a long-lived credential. Giving the service account an admin role of its own, rather than delegation, avoids acting as a person; either way it is read-only by scope.

## Alternatives considered

- **Wait for Google's custom SCIM apps.** In beta for a few customers; those can already use `/scim/v2`. Everyone else would wait indefinitely.
- **A catalog app.** Needs a partnership with Google and a published app per deployment; doesn't fit a self-hosted server with its own domain.
- **Push notifications** (Directory API `watch` channels, or Workspace Events). They need a public HTTPS endpoint Google can reach and channel renewal, and are hints, not state: a full read is still needed. Polling a full read is simpler and correct; push can shorten the delay later.
- **Scope by organizational unit** instead of groups. OUs model where accounts are managed, not who uses an app; groups are what admins already use for app access, and they also give teams.
- **Writing users directly** rather than through the SCIM handlers. A second implementation of roles, conflicts, deprovisioning and audit, which would drift from SCIM's.
- **A new table for who disabled whom.** The audit log already says it, and a new migration would collide with parallel work. The cost: someone whose disable was pruned from the log stays disabled, which is the safe side.
- **Workload identity federation or the metadata server** instead of a key. Domain-wide delegation needs a JWT signed by the service account; without a key that is the IAM Credentials `signJwt` API, which needs Google Cloud credentials of its own. Possible later for botd running on Google Cloud.

## Not done

- Organizational units, aliases, custom schema attributes, and Google admin roles mapped to SuperBot roles (roles stay with admins and ADR 0138's group mappings).
- Push notifications (above), and syncing several Workspace customers (one tenant per server for now).
- A setting to let the sync re-enable people an admin disabled.
