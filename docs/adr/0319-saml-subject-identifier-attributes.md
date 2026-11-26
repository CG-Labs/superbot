# 0319: SAML subject-id and pairwise-id name people

## Status

Accepted. The twenty-fifth M5 slice of full SAML ([#52](https://github.com/CG-Labs/superbot/issues/52), [roadmap](../ROADMAP.md#m5--enterprise)). Builds on [ADR 0282](0282-saml-several-idps-of-a-federation.md) (several IdPs, scopes from the federation's metadata) and [ADR 0308](0308-saml-every-idp-of-a-federation.md) (every IdP of a federation). Setup guide: [native SAML](../sso/saml-native.md#subject-identifiers-subject-id-and-pairwise-id).

## Context

botd names a SAML person by their NameID and refuses a transient one (`transient_subject`), since a NameID that changes every sign-in can't be linked to anyone. That's right for Okta, Entra ID and ADFS, which send persistent NameIDs. But federations are moving the other way. The REFEDS and InCommon baselines, and the SAML2int profile, ask IdPs to send a transient NameID and say who the person is in an attribute of the OASIS SAML V2.0 Subject Identifier Attributes Profile (2019):

- `urn:oasis:names:tc:SAML:attribute:subject-id`: the same for every service the person uses.
- `urn:oasis:names:tc:SAML:attribute:pairwise-id`: different for each service.

Both are single-valued and scoped, `uniqueID@scope`. The unique ID is 1 to 127 characters, letters, digits, `=` and `-`, starting with a letter or digit. The scope is 1 to 127 characters, letters, digits, `-` and `.`, starting with a letter or digit. Values are compared without case. A relying party must check the scope against the IdP's `shibmd:Scope`s in its metadata. An SP says which it needs with the entity attribute `urn:oasis:names:tc:SAML:profiles:subject-id:req` (`subject-id`, `pairwise-id`, `none` or `any`).

So many of the IdPs that `IDP_ENTITY_IDS=all` reaches can't sign anyone in. This slice lets them.

## Decision

### `SSO_<ID>_SUBJECT`

The setting is `nameid` (the default, unchanged), `subject-id` or `pairwise-id`, for native SAML only. With an attribute, the persistent-NameID rule is lifted, and the attribute's value is the person: `Claims.subject`, stored under the IdP that signed it (`issuer|subject`), as a NameID is. So links, SCIM, role mappings, sessions and audit work as before, with one key per provider.

### What's taken

The attribute is read only from the signed assertion's `AttributeStatement`s. It must appear once, with exactly one `AttributeValue` of plain text and NameFormat `uri` if one is given. XML whitespace around the value is stripped. The value must match the profile's grammar, and is lowercased. A missing attribute is `no_subject_id`. Anything else is `bad_subject_id`. Nothing is picked from several values or attributes.

The scope must equal one of the IdP's `shibmd:Scope`s, from the metadata botd already checks (`regexp="true"` scopes are ignored, as for emails and groups). Otherwise the sign-in is `subject_id_scope`. Metadata with no scope vouches for none: an IdP outside a federation that sends the attribute must list its scopes. That's the profile's own rule, and without it any IdP of a federation could claim another's people. With one IdP it matters less, but the same rule keeps one code path and one meaning.

### The NameID stays, for logout

A NameID is still required, in any format, and kept as sent in the session's SAML login, as today. It's used only for single logout. An IdP's LogoutRequest names the transient NameID, not the attribute, so in attribute mode botd matches sessions by the stored NameID, exactly (it's opaque), with the IdP's issuer and any SessionIndexes. botd's own LogoutRequests, front or back channel, send the stored NameID back. `auth.slo` shows the person's `subject` and the `nameId`.

### SP metadata

With an attribute, our metadata has `<md:Extensions><mdattr:EntityAttributes><saml:Attribute Name="urn:oasis:names:tc:SAML:profiles:subject-id:req" NameFormat="…:uri"><saml:AttributeValue>pairwise-id</saml:AttributeValue>…`, first in the `EntityDescriptor`, and its NameIDFormat becomes transient. IdPs that release attributes by metadata (Shibboleth can, and some federations recommend it) then release the attribute without per-SP setup.

### Links and SCIM

An identity a person types (`botctl user link`, the API) or SCIM sends as `externalId` must be in the attribute's syntax, with a hint naming the setting otherwise, so a pasted NameID fails at once and not at sign-in. Its scope isn't checked there: the IdP's metadata may not be loaded yet, and sign-in enforces it anyway.

### What's shown

`auth.login` and refused sign-ins with claims carry `subjectFrom` (`subject-id` or `pairwise-id`; absent for NameIDs). `botctl sso saml <id>` says what people are known by and, with one IdP, lists its scopes or says no one can sign in. The API view has `subject`. Support triage knows the three new reasons as SAML ones.

## Alternatives considered

- **`any`: take whichever comes, as the profile's `req` allows.** One person could then be two identities at one IdP, depending on which attribute an IdP release happened to send. One key per provider keeps identities stable. A deployment that needs both can configure two providers.
- **Fall back to the NameID when the attribute is missing.** A persistent NameID and the attribute are different strings for the same person, so a fallback would sign people in as someone else's link, or as nobody. It also turns an IdP release mistake into silent duplicates. Refusing says what's wrong.
- **eduPersonPrincipalName or eduPersonTargetedID.** ePPN can be reassigned and isn't meant as an identifier; ePTID is deprecated in favour of pairwise-id. Admins who must use another attribute can still use the Keycloak bridge's mappers.
- **Accept scope-less metadata with one IdP.** It would help a few non-federation IdPs, at the cost of a second meaning for the setting. Listing scopes in metadata is a small change for the IdP's admin.
- **Check SCIM `externalId` scopes.** That would make provisioning wait on metadata (an MDQ fetch) and fail deprovisioning when it's down. Sign-in already refuses an out-of-scope value, so an unchecked link can't let anyone in.
- **Match logout by the attribute.** LogoutRequests carry the NameID the IdP issued for that session, not attributes, so this can't work. Matching the stored NameID is also what the SAML core spec describes.

## Consequences

- Federation IdPs that send only transient NameIDs (most new REFEDS and InCommon ones) can sign people in, making `IDP_ENTITY_IDS=all` useful.
- An IdP can only speak for the scopes its federation registered for it.
- `pairwise-id` gives SuperBot an identifier other services can't correlate with.
- Switching an existing provider to an attribute changes every identity: people must be re-linked, or SCIM must resend `externalId`s. The guide says so.
- The NameID check for transient formats is unchanged when the setting is `nameid`, so existing deployments see no difference.
