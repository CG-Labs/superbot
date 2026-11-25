# 0287: SAML groups per IdP of a federation

## Status

Accepted. The nineteenth M5 slice of full SAML ([#52](https://github.com/CG-Labs/superbot/issues/52), [roadmap](../ROADMAP.md#m5--enterprise)). Builds on [ADR 0160](0160-saml-groups-and-role-mapping.md) (groups: required groups and groups mapped to custom roles) and [ADR 0282](0282-saml-several-idps-of-a-federation.md) (several IdPs of a federation on one provider). Setup guide: [native SAML](../sso/saml-native.md#groups-with-several-idps).

## Context

ADR 0282 lets one native SAML provider take several IdPs of a federation, but refused `GROUPS_ATTRIBUTE` with them. A group name is each IdP's own: University A's `staff` isn't University B's, and a mapping of `staff` to a role would have given it to both. So a consortium on one provider could neither require a group nor give roles from groups.

Federations already have an answer for part of this. Their attributes for who someone is at an institution are scoped: eduPersonScopedAffiliation is `member@uni-a.example`, and the federation's metadata lists the domains each IdP may speak for (`shibmd:Scope`, which ADR 0282 already reads for emails). Shibboleth SPs drop a scoped value whose scope isn't the IdP's. Unscoped values (Grouper's `isMemberOf`, local group names) are the IdP's own names and say nothing about whose they are.

## Decision

### Groups with several IdPs

`GROUPS_ATTRIBUTE` is allowed with `IDP_ENTITY_IDS`. Groups are read as ADR 0160 says, then, with several IdPs only, every value scoped to a domain that isn't one of the signing IdP's scopes is dropped (`IdpMetadata::scope_groups`):

- A value is scoped when what follows its last `@` is a domain (`saml_sp::group_scope`, compared lowercase and exactly, as emails are: a scope doesn't cover its subdomains). `urn:…` entitlements and plain names aren't scoped and stay.
- An IdP whose metadata lists no scope keeps no scoped value, as it keeps no email.
- What was dropped is audited with a required-groups refusal (`groupsOutOfScope`, at most 20), so an admin can see why someone wasn't let in.

A single IdP isn't checked, as for emails (ADR 0282): its admin chose it, and many IdPs outside federations publish no scope.

### Required groups must be scoped

With several IdPs, each `REQUIRED_GROUPS` entry must be scoped (`member@uni-a.example,member@uni-b.example`), or botd won't start. With the scope check above, a scoped group can only come from the IdP the federation says speaks for its domain, so `member@uni-a.example` lets in University A's members and nobody else's. An unscoped required group would let in anyone at any listed IdP who has a group of that name.

### Mappings per IdP

A mapping on a provider with several IdPs names its IdP (`idp`, an entity ID the provider lists), and a provider with one IdP takes none (`POST /api/sso/role-mappings {provider, group, role, idp}`, `botctl sso role map <provider> <group> <role> --idp <entity ID>`). A group may be mapped once per IdP: `saml_role_mappings` gains `idp` (empty for the one IdP), and its `UNIQUE (provider, group_name)` becomes `UNIQUE (provider, idp, group_name)`. SQLite can't change a constraint in place, so the migration makes the table again, keeping its grants aside meanwhile (dropping the table would cascade to them). Existing mappings keep their ids and grants, with no IdP.

Every rule of ADR 0160 holds with "the provider" read as "the provider at that IdP":

- A sign-in at IdP X tries only X's mappings, and keeps or takes back only what X's mappings gave. A grant from another listed IdP's mapping is left alone, as another provider's is: only that IdP can say the person left its group. The same for a hand change's release.
- Unlinking takes back what a mapping gave once the person has no identity left at that mapping's IdP; an identity at another IdP of the same provider doesn't vouch for it.
- A mapping for an IdP the provider no longer has gives nothing (`active: false`): one taken off `IDP_ENTITY_IDS`, a mapping without an IdP once the provider lists several, or one naming an IdP once it lists one. What it gave goes at the person's next sign-in with the provider (`idp_not_listed`), and a release it holds ends, since that IdP can't vouch any more. It can still be listed and removed.

Grants, removals, skips and mapping changes carry `idp` in their audit details when the mapping names one. `GET /api/sso/role-mappings` lists each provider's IdPs (`idps`) and each mapping's `idp`.

## Alternatives considered

- **Keep refusing groups with several IdPs.** Safe, but a consortium would need one provider per institution for any group rule, which is what ADR 0282 set out to avoid.
- **Namespace group names by IdP in the value (`<entity ID>#staff`).** One field instead of two, but an admin would have to type the entity ID into every group, and a typo would make a mapping that never matches. A separate, checked `idp` is clearer and refused when wrong.
- **Mappings for every IdP at once.** "Everyone in `staff` at any listed IdP" is exactly the cross-institution grant ADR 0282 refused. A scoped value already does this safely: each IdP's own scoped value is its own group.
- **Required groups per IdP as settings (`SSO_<ID>_REQUIRED_GROUPS_<n>`).** Settings keyed by IdP don't fit environment variables, and federations' scoped attributes already say whose a group is. Scoped required groups need no new setting.
- **Unscoped required groups with a per-IdP check.** botd would have to know which IdP each unscoped name was meant for, which is a mapping in all but name. Scoped values carry it.
- **Check scoped groups for a single IdP too.** It would break IdPs with scoped-looking group names and no `shibmd:Scope`, for no gain: the admin chose that IdP.

## Consequences

- A consortium on one provider can require membership at its institutions (`member@uni-a.example,…`) and give roles from each institution's groups.
- A member IdP can't vouch for another member's scoped values, for groups as for emails.
- With several IdPs, a group value with an `@` and a domain after it counts only at the IdP whose scope that domain is; a local group name that happens to look like `team@host.example` is dropped unless the IdP lists that domain.
- Mappings for a provider that moves between one and several IdPs stop applying and take back what they gave at the next sign-in; admins map the groups again with or without `--idp`.
- Nothing changes for a provider with one IdP, the SAML bridge or OIDC. IdP-initiated restarts and SCIM linking stay refused with several IdPs (ADR 0282).
- Still open on #52, only if a customer needs it: whole federation aggregates over 1 MB, and every IdP of a federation without a list.
