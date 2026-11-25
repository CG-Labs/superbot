# 0282: Several SAML IdPs of a federation on one provider

## Status

Accepted. The eighteenth M5 slice of full SAML ([#52](https://github.com/CG-Labs/superbot/issues/52), [roadmap](../ROADMAP.md#m5--enterprise)). Builds on [ADR 0127](0127-native-saml-service-provider.md) (native SAML SP) and [ADR 0281](0281-saml-metadata-from-mdq.md) (metadata from MDQ). Setup guide: [native SAML](../sso/saml-native.md#several-idps-of-a-federation).

## Context

ADR 0281 lets one native SAML provider take one federation IdP's metadata from the federation's MDQ server. A platform used across institutions (a research consortium, a shared lab, a university group) has people at several IdPs of one federation. With one IdP per provider, an admin had to configure a provider per institution: a block of settings each, a button each on the sign-in page, and the same federation signer named again each time.

Three things are different once one provider speaks for several IdPs:

- **Which IdP?** An SP-initiated sign-in must go to one IdP, and only that IdP's answer can be taken. Federations solve this with a discovery service (SAML IdP Discovery, the SeamlessAccess service), which is a separate trust and a script on a page that isn't ours.
- **Whose identity?** Each IdP's NameIDs are its own: `alice` at two universities is two people.
- **Whose email?** Any IdP in a federation can sign any email address. The federation's metadata says which domains each IdP speaks for (`shibmd:Scope`, which Shibboleth SPs check for scoped attributes). Without that check, any member IdP could sign in as anyone at another member, by email (just in time, `ALLOWED_DOMAINS`, linking by email).

## Decision

### Settings

`SSO_<ID>_IDP_ENTITY_IDS` lists 2 to 100 entity IDs (`saml_sp::MAX_IDPS`), comma separated, instead of `IDP_ENTITY_ID`. Each is checked as an entity ID and listed once. It needs `IDP_MDQ_URL` (and so the federation's signer, ADR 0281): a metadata URL, file or import holds one entity, and an aggregate is what MDQ avoids. One entry is refused (set `IDP_ENTITY_ID`), as is setting both.

These are refused with several IdPs, at startup:

- `GROUPS_ATTRIBUTE` (and so `REQUIRED_GROUPS` and group role mappings, ADR 0160). Group names are each IdP's: one university's `admins` is not another's, and a role mapping would grant it to both.
- `IDP_INITIATED=restart` (ADR 0175). The restarted sign-in would need to know which IdP to go to, and the unsolicited response says so only before its signature is checked. Each sign-in starts at the chooser instead.

`Kind::SamlSp` holds `entity_ids`, one or more. `IdpSource::Mdq` holds the base URL, and the request URL is made per IdP (`url_for`). The provider caches each IdP's metadata by entity ID, with its own refresh time, failure gap, refusals to audit, and fetch lock, so a slow MDQ answer for one IdP doesn't hold up sign-ins at another. A single IdP works exactly as before.

### Choosing the IdP

`GET /api/auth/sso/{id}/start` without `idp` answers with a chooser page on SuperBot: the IdPs sorted by name, each a link to the same start URL with `idp=<entity ID>` added, so the app's `session`, `redirect`, `challenge`, `state` and `label` carry through. The name is the IdP's `mdui:DisplayName` (English first, else the first), else its `OrganizationDisplayName`, else the entity ID, whitespace collapsed and cut to 100 characters, and HTML-escaped. An IdP whose metadata isn't loaded yet is listed by its entity ID; the expiry check loads every IdP's at startup. The page runs no script: its CSP is `default-src 'none'` with its one style sheet allowed by hash, `form-action 'none'`, and `frame-ancestors 'none'`.

An `idp` that isn't listed fails the sign-in as `unknown_idp` (audited, throttled like other unvouched failures). Otherwise the AuthnRequest goes to that IdP, and the pending sign-in remembers it: the response is checked against that IdP's metadata only, so a response signed by another IdP is refused, whatever its Issuer says. A re-authentication (ADR 0225) goes back to the same IdP.

### Identities

The claims' issuer is the IdP that signed the response, as before, so identities are stored as `(entity ID, NameID)` and sessions as `entity ID|NameID`. A listed entity ID may not hold `|`: with IdPs `urn:example:idp` and `urn:example:idp|staff`, the first's NameID `staff|alice` and the second's `alice` would both be `urn:example:idp|staff|alice`, and a logout from one could end the other's sessions. Without it, a session's IdP is everything before the first `|`. Real entity IDs are URLs or URNs, which hardly ever hold one; such an IdP can still be its own provider with `IDP_ENTITY_ID`.

Linking by hand must say which IdP: `POST /api/users/{key}/identities` takes `idp`, and `botctl user link … --idp <entity ID>`. Without it, a provider with several IdPs is refused ("say which with --idp"), as is an entity ID it doesn't list. A SCIM token can't link such a provider, since SCIM's `externalId` doesn't say which IdP.

### Email scopes

With several IdPs, an email from the assertion counts only if its domain is one of the IdP's scopes in the signed federation metadata, exactly. Scopes come from `shibmd:Scope` on the `IDPSSODescriptor` or the entity (at most 64), as domains; `regexp="true"` scopes are skipped, since a pattern is easy to get wrong and SuperBot matches domains, not patterns. An email out of scope is dropped, so it can't link by email or show on the account. Where the email decides who gets in (`ALLOWED_DOMAINS`), the sign-in is refused as `email_out_of_scope` instead, and the person is told it was the wrong account.

A single IdP isn't checked: its admin chose it, and many IdPs outside federations publish no scope.

### Logout

- **To the IdP:** the session's IdP (from its identity key) gets the LogoutRequest, front or back channel (ADR 0137, 0208, 0258), and only that IdP's LogoutResponse to it is taken.
- **From an IdP:** botd reads the message's Issuer before anything is checked (`saml_slo::claimed_issuer`), only to pick which listed IdP's metadata to check it against. An Issuer that isn't listed is refused as `unknown_idp`. The message is then checked in full as from that IdP: its signature, `Destination`, times, and the Issuer again, so nothing read before the signature is trusted. It revokes only sessions under that IdP.

### Status and checks

`GET /api/sso/{id}/saml` adds `idpEntityIds` and `idps` (each IdP with its name, scopes and loaded metadata), and `botctl sso saml` lists them. Refresh, metadata refusals (with `entityId`), certificate expiry warnings (each IdP's certificate is replaced only by a newer one of the same IdP's, and each IdP's notice is claimed on its own, so IdPs sharing a certificate are each warned) and `botctl offline check` (every MDQ request URL) cover every IdP.

## Alternatives considered

- **A discovery service (SeamlessAccess, a federation's WAYF).** It puts people's choice on another party's page and script, and botd would have to take its answer back (the IdP Discovery protocol) and still check it against the list. A plain page on SuperBot, with no script, needs neither. A discovery service can still link to the start URL with `idp`.
- **Every IdP in the federation, without a list.** botd would take sign-ins from thousands of IdPs nobody chose, with a chooser to match. An explicit list keeps who can sign in a decision the admin made. Left for later, if a customer needs it: it would want a search box, and a federation-wide policy such as an entity category.
- **Let the response say which IdP.** The IdP would be known only from the unsigned Issuer of a response, which can't decide whose keys check it without trusting it first. The IdP is picked before the AuthnRequest goes out, and only its answer counts.
- **Groups across IdPs, namespaced by IdP.** Role mappings would need the IdP in each mapping, a change to ADR 0160's settings and table. Refused until someone needs it.
- **Scopes by pattern, or scope checks for a single IdP too.** Patterns (`regexp="true"`) are rare and easy to get wrong. A single IdP is the admin's own choice, and checking it would break IdPs that publish no scope. Neither for now.
- **One provider per IdP, as before.** Still works, and is right for two or three institutions with their own buttons. It doesn't scale to a consortium.

## Consequences

- A consortium in one federation needs one provider: `IDP_ENTITY_IDS`, `IDP_MDQ_URL` and `METADATA_SIGNING_CERT_FILE`. People pick their institution on SuperBot's page.
- A member IdP can't sign in as someone at another member by email: the federation's scopes decide.
- Providers with several IdPs can't use groups, IdP-initiated restarts or SCIM linking, and botd says so at startup.
- Nothing changes for a provider with one IdP, the SAML bridge or OIDC.
- Still open on #52, only if a customer needs it: whole federation aggregates over 1 MB, every IdP of a federation without a list, and group role mappings per IdP.
