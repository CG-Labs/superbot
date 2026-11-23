# 0160: SAML groups: required groups and groups mapped to custom roles

## Status

Accepted. The fifth M5 slice of full SAML ([#52](https://github.com/CG-Labs/superbot/issues/52), [roadmap](../ROADMAP.md#m5--enterprise)). Builds on [ADR 0127](0127-native-saml-service-provider.md) (the native SP), [ADR 0123](0123-custom-roles.md) (custom roles) and [ADR 0138](0138-scim-group-role-mapping.md) (SCIM groups mapped to custom roles), whose rules it follows. Setup guide: [native SAML](../sso/saml-native.md#groups).

## Context

Native SAML ([ADR 0127](0127-native-saml-service-provider.md), [0137](0137-saml-signed-requests-and-single-logout.md), [0150](0150-saml-encrypted-assertions.md), [0151](0151-saml-encrypted-nameids-ecdsa-and-signed-metadata.md)) signs people in, but reads only their NameID, email and name. Two things enterprises ask of SAML were still missing:

- **Who may sign in.** Anyone the IdP signs in to the app gets in. Many organisations assign the app broadly and want SuperBot itself to require a group, say "SuperBot Users", so a wrong assignment at the IdP doesn't let someone in, and just-in-time sign-up doesn't make accounts for them.
- **Roles from groups.** Organisations without SCIM (or whose IdP sends groups only in the assertion) want "everyone in Auditors can read the audit log" to follow group membership, as ADR 0138 does for SCIM.

Multiple IdPs already work (one provider each, ADR 0016), and metadata refresh, single logout, and signed and encrypted assertions are done. IdP-initiated sign-in stays off by design (ADR 0127). Group-based access was the largest gap left.

The risk is the same as in ADR 0138: if the IdP could name roles, whoever edits a group at the IdP would become an admin in SuperBot. The assertion also arrives through the browser, so only what the IdP signed may count.

## Decision

### Reading groups

- `SSO_<ID>_GROUPS_ATTRIBUTE` names the assertion attribute with the groups. There is no default: groups are read only when an admin names the attribute, so a stray attribute never becomes access. Entra ID's is `http://schemas.microsoft.com/ws/2008/06/identity/claims/groups`, with group object ids as values.
- Groups come only from the signed assertion's `AttributeStatement`s (after decryption, if encrypted), never from the response around it. Every value of every attribute with that name counts, trimmed and deduplicated. Values are compared exactly, case included: group names and ids are the IdP's, and folding case could merge two groups.
- Values that are empty, longer than 256 bytes, or have elements inside are skipped.
- **Unknown groups.** Entra ID sends a `groups.link` claim (`http://schemas.microsoft.com/claims/groups.link`) instead of the groups when someone is in too many. botd can't tell which groups that means, so the groups are *unknown* (`overage`). More than 500 values is unknown too (`too_many`), rather than a list cut short. Unknown groups count as no groups: they let no one past required groups and give no role.
- The setting is refused on the SAML bridge and Entra providers, like every native-only setting.

### Required groups

`SSO_<ID>_REQUIRED_GROUPS` (comma separated, exact names, needs `GROUPS_ATTRIBUTE` or botd refuses to start) lets in only people in at least one of them.

- Checked on every sign-in, after the assertion and the email are checked and before the account is looked up. So someone outside every required group is never made a user by just-in-time sign-up, and a linked user who left the group can't sign in.
- Refusals are `auth.login_failed` with reason `not_in_group`, or `groups_unknown` with `groups` = `overage`, `too_many` or `not_read`. The sign-in page says `sso_not_allowed`. These are vouched for by the IdP's signature, so they aren't throttled away, but they count towards the address's failed sign-ins.
- Leaving the group doesn't end sessions already made; that is still offboarding's job (SCIM, or an admin).

### Mapping a group to a custom role

An admin maps one provider's group to one custom role, across the server (org scope). The rules are ADR 0138's:

- **Never admin.** Refused (400, audited as `sso.saml_role_map_refused`, reason `admin`, `built_in` or `reaches_admins`): admin, any built-in role, and any custom role with a permission that reaches admins across the server (`rbac::REACHES_ADMINS`: `bots.manage`, `machines.manage`). A mapped role can't gain such a permission later (`PATCH /api/roles/{id}` is 409, naming the mapping) or be deleted (409) until the mapping goes. The database checks the role's permissions as it saves the mapping, the role, and each grant.
- A group has at most one mapping (`UNIQUE(provider, group_name)`). A provider must read groups before anything can be mapped to it (409).
- `botctl sso role-mappings | role map <provider> <group> <role> | role show <id> | role unmap <id>`, or `GET`/`POST /api/sso/role-mappings` and `GET`/`DELETE /api/sso/role-mappings/{id}`. Admins only. Making a mapping gives no one anything until they next sign in.

### Every sign-in reconciles

After the account is found and before the session starts, the provider's mappings are applied under one lock (`role_writes`, also taken by mapping writes and unlinking). Under the lock the person must still have an identity at the provider, so an unlink that finished while the sign-in waited isn't undone by it:

1. A grant from this provider stays while the assertion lists its group. Otherwise it's taken away (`left_group`, or `groups_unknown` when the groups are unknown or the provider no longer reads them).
2. Then, if the assertion lists a mapped group, the first such mapping (oldest first) gives its role, unless the person is an admin, the owner account, or already holds a custom role (by hand, from SCIM, or from another provider's group). Each skip is audited as `sso.saml_role_skipped` with its reason. The grant is one SQL update that repeats these checks, so it can't overwrite a change made meanwhile.

Grants from another provider's mappings are left alone; only the provider that gave a role takes it away.

### Only what it gave

Each grant is a row in `saml_role_grants` (mapping, user, and the built-in role it replaced). Taking it away clears the role only if it is still the mapping's, and puts back the earlier built-in role (never admin). Built-in role changes are audited as `user.role_changed` and run the same offboarding as an admin's change (`users::lost_access`).

Any change of that person's role by hand (giving a role, taking it away, setting the built-in role) *releases* the grant in the same transaction: nothing is taken back, and the release is remembered. While it's held, no mapping gives that person anything, whichever provider it belongs to, so an admin's decision isn't undone at the next sign-in. The grant SQL refuses while a release is held, so this doesn't rest on the order of the checks. Only the provider that gave the role can say the person left its group: once a sign-in with it no longer lists the group, the release ends and mappings apply again. Unlinking that provider's identity, removing the mapping, or erasing the person ends it too.

Grants also go when:

- the mapping is removed (`mapping_removed`, for everyone it gave the role to);
- an admin unlinks the person's last identity at that provider (`unlinked`): the IdP can't vouch for their groups any more. The identity is removed before the lock is taken, and sign-ins check for it under the lock, so a sign-in racing the unlink either runs first (and the unlink takes the role) or gives nothing;
- the person is erased.

### Audit

`sso.saml_role_mapped`, `sso.saml_role_unmapped` (with who lost the role), `sso.saml_role_map_refused`, `sso.saml_role_skipped`, and every grant and removal as the existing `role.assigned` and `role.unassigned` with `via: "saml"`, the mapping, provider, group and a reason. Sign-in grants have the system actor `sso`. A hand change that takes over a SAML grant records `takenFromSaml` or `samlMapping`. `GET /api/roles/{id}` shows each holder's `samlMapping` and each role's `samlMappings` count. `botctl sso saml <id>` shows the groups attribute, the required groups and how many mappings the provider has.

## Alternatives considered

- **Let the assertion name roles** (a `role` attribute, or groups like `superbot-admin`). Whoever edits the IdP's groups would become an admin. Refused, as in ADR 0138.
- **A default groups attribute** (`groups`, `memberOf`, Entra's claim URI). Convenient, but an IdP sending one for another app would start gating sign-ins or giving roles nobody chose. The admin names it.
- **Case-insensitive group names.** Friendlier for typos, but two groups differing only in case would merge. Exact matching, with the audit log showing what was sent, is safer.
- **Treat an Entra overage as "keep what they have".** Someone removed from every group but still past the overage limit would keep a role indefinitely. Unknown counts as none; the fix is to send fewer groups (Entra: "groups assigned to the application").
- **Give roles when the mapping is made.** Only a sign-in says who is in a group, and the last one may be months old. Roles follow the next sign-in instead.
- **Let a group override a hand-given role.** As in ADR 0138, an admin's choice wins; the release keeps a group from undoing it at the next sign-in.

## Consequences

- Organisations can require a group for SuperBot and delegate read-only admin duties through IdP groups without SCIM. Access from a group ends at the next sign-in after someone leaves it, or at once when the mapping or their link goes. Without SCIM, someone who never signs in again keeps their role until then; use SCIM ([ADR 0138](0138-scim-group-role-mapping.md)) or an admin to end it at once.
- Two tables (`saml_role_mappings`, `saml_role_grants`), two settings, four admin routes and four `botctl` commands. The console and the app don't list mappings yet; admins use `botctl` or the API.
- Someone holding a custom role by hand who is in a mapped group is audited as skipped on each sign-in.
- Mappings for a provider removed from the configuration stay and can be listed and removed; they give nothing.
