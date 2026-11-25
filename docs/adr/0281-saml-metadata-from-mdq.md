# 0281: SAML IdP metadata from a federation's MDQ server

## Status

Accepted. The seventeenth M5 slice of full SAML ([#52](https://github.com/CG-Labs/superbot/issues/52), [roadmap](../ROADMAP.md#m5--enterprise)). Builds on [ADR 0127](0127-native-saml-service-provider.md) (native SAML SP) and [ADR 0151](0151-saml-encrypted-nameids-ecdsa-and-signed-metadata.md) (signed IdP metadata). Setup guide: [native SAML](../sso/saml-native.md#metadata-from-a-federation-mdq).

## Context

Universities and research institutions sign in through federations (InCommon in the US, the national federations of eduGAIN elsewhere). A federation publishes its members' metadata in two ways:

- **A signed aggregate**: one `EntitiesDescriptor` with every member. InCommon's is about 60 MB, eduGAIN's about 80 MB. botd reads at most 1 MB of metadata (`MAX_METADATA`), so these don't fit. Raising the limit would mean parsing and checking the signature of a document of tens of MB every day for one IdP, on every botd.
- **MDQ** (the Metadata Query Protocol, draft-young-md-query): `GET <base>/entities/<entityID>` returns one entity's `EntityDescriptor`, signed by the federation. InCommon recommends it over its aggregate (Shibboleth's `DynamicHTTPMetadataProvider` with `requireSignedRoot` and `RequiredValidUntil`), and several national federations run one too.

botd could already read and check a signed aggregate up to 1 MB, or one entity's signed metadata, from a URL. Two things were missing for MDQ:

- **An MDQ answer is only as good as its signature.** Anyone can run an MDQ server, and a proxy can answer for one. A signed answer is also easy to keep: it could be served again later, after the IdP changed its keys because one leaked. ADR 0151 refuses signed metadata past its `validUntil`, but nothing made an answer carry one.
- **The last good copy outlived its `validUntil`.** When a refresh failed or was refused, botd kept using the copy it had, even once its `validUntil` had passed. A file or an import, read once, was used after it too. An attacker who could block the refresh would keep botd on old keys.

## Decision

### MDQ as a metadata source

`SSO_<ID>_IDP_MDQ_URL` is the MDQ server's base URL (https, no query or fragment), as the federation publishes it, such as `https://mdq.incommon.org`. It is a fourth source, beside `IDP_METADATA_URL`, `IDP_METADATA_FILE` and an import, and can't be set with the other two.

- **The request** is `<base>/entities/<entityID>`, with the IdP's entity ID (`IDP_ENTITY_ID`) percent-encoded except for RFC 3986's unreserved characters. So `/`, `:`, `?` and `#` in an entity ID stay in the one path segment, and the server can't be asked for anything else. `Accept: application/samlmetadata+xml`.
- **Fetching** is as for a metadata URL: when needed, refreshed daily, retried at most once per gap after a failure, at most 1 MB, over the SSO HTTP client (no redirects). A 404 is logged as the server not knowing the entity.
- **A signer is required.** The provider needs `METADATA_SIGNING_CERT_FILE`, the federation's MDQ signing certificate, and `SIGNED_METADATA=allow` is refused at startup. Without them botd won't start.
- **The answer** (`MetadataTrust::query`) must be:
  - the IdP's own `EntityDescriptor` at the root. An `EntitiesDescriptor` is refused, whether signed as a whole or only around the entity: that is not what the protocol returns for one entity, and a signature on part of a document leaves the rest unchecked (`not_one_entity`);
  - signed at the root (Shibboleth's `requireSignedRoot`) by a certificate in the file, with the algorithms ADR 0151 takes (`unsigned`, `bad_signature`, `weak_algorithm`);
  - with a `validUntil` (`no_valid_until`), not past (`expired`), and at most 30 days ahead (`valid_too_long`). 30 days covers federations' MDQ answers (InCommon's are valid for 14 days) and limits how long a stolen or cached answer can be served again.
- **Refusals** are audited as `sso.saml_metadata_refused` with `source: "mdq"`, and the last good copy stays, as for a metadata URL, but only until its own `validUntil`: an expired copy is never used, and that is checked again after a refresh that fails.
- **Everything else is the same.** The `EntityDescriptor` is read as before: SSO, SLO and artifact resolution endpoints, signing certificates, `WantAuthnRequestsSigned`. Certificate expiry warnings (ADR 0198) cover the federation's signer and the IdP's certificates, and refresh first when due. `botd offline check` and `botctl offline check` (ADR 0257, 0266) list the MDQ URL as an address botd reaches.

### No signed copy past its validUntil

Signed metadata now remembers the earliest `validUntil` between the entity and the root (`IdpMetadata::valid_until`), from every source. Past it, the copy is never used to check a sign-in or a logout message, even as the last good one:

- from a URL or MDQ, botd fetches it again. If that fails or is refused, the sign-in fails as `idp_metadata_expired`;
- from a file or an import, the sign-in fails as `idp_metadata_expired` until a fresh signed copy is given (a new file and a restart, or an import).

Unsigned metadata's `validUntil` still means nothing (anyone could have written it), so it doesn't end anything. `GET /api/sso/{id}/saml` shows `validUntil` and `expired`, and `botctl sso saml` the date. Outgoing logout requests still use the copy botd has, as before: they send nothing that needs the IdP's keys trusted.

## Alternatives considered

- **Raise the size limit and read whole aggregates.** It works for InCommon and eduGAIN without an MDQ server, but means a daily 60 to 80 MB download, parse and signature check, with memory to match, to read one entity. Left for a slice of its own, if a customer's federation has no MDQ server: it would need streaming, a separate limit and an on-disk cache.
- **Take an `EntitiesDescriptor` from MDQ.** Some servers can wrap one entity in an aggregate. Refused: the protocol answers a request for one entity with an `EntityDescriptor`, and InCommon's and the common servers (pyFF, Shibboleth's) do. One shape is one less thing to get wrong.
- **Honour `cacheDuration` for refreshes.** Federations set it from an hour to a day. A daily refresh is what metadata URLs get, and `validUntil` now bounds how long a copy can be used. Left as is.
- **Make the 30-day limit a setting.** No federation we know of signs MDQ answers for longer. A setting would let an admin turn a safety check off without knowing why it's there. Fixed; changing it is a code change with its reason.
- **Use the `{sha1}` form of the identifier.** MDQ servers may accept the SHA-1 of the entity ID instead. Every server must accept the percent-encoded entity ID, and it's what admins see in logs. Percent-encoding only.
- **Keep using an expired last good copy, as before.** Then blocking botd's refresh keeps it on keys the IdP or federation has withdrawn, which is what `validUntil` is there to prevent. A failed sign-in, audited with the reason, is better than an untrusted one.

## Consequences

- An IdP in InCommon, eduGAIN or another federation with an MDQ server works with three settings: `IDP_ENTITY_ID`, `IDP_MDQ_URL` and `METADATA_SIGNING_CERT_FILE`, and needs no metadata exchanged by hand. Its key rollovers reach botd within a day.
- Signed metadata from a file or an import that has a `validUntil` now stops signing people in once that passes. Admins see it in `botctl sso saml` and the audit log (`idp_metadata_expired`), and must give botd a fresh copy, or switch to a URL or MDQ, which refresh themselves.
- Nothing changes for unsigned metadata, the SAML bridge or OIDC.
- Still open on #52, only if a customer needs it: whole federation aggregates over 1 MB, and choosing an IdP among many (a discovery service, or one provider for every IdP in a federation).
