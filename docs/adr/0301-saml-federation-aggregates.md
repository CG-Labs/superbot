# 0301: SAML metadata from a federation's aggregate

## Status

Accepted. The twenty-second M5 slice of full SAML ([#52](https://github.com/CG-Labs/superbot/issues/52), [roadmap](../ROADMAP.md#m5--enterprise)). Builds on [ADR 0151](0151-saml-encrypted-nameids-ecdsa-and-signed-metadata.md) (signed IdP metadata), [ADR 0281](0281-saml-metadata-from-mdq.md) (one IdP's metadata from a federation's MDQ server) and [ADR 0282](0282-saml-several-idps-of-a-federation.md) (several IdPs of a federation on one provider). Setup guide: [native SAML](../sso/saml-native.md#a-federations-aggregate).

## Context

Research and education federations publish their members' metadata as one signed aggregate: an `EntitiesDescriptor` holding every member's `EntityDescriptor`, signed once at its root. InCommon's is about 60 MB, eduGAIN's about 100 MB. ADR 0281 left aggregates out: botd reads at most 1 MB of metadata, parsed whole with `roxmltree`, and InCommon and many national federations run an MDQ server that answers for one entity at a time. Federations without one (several national ones, eduGAIN's own feed, inter-federation hubs) publish only the aggregate, and a deployment there couldn't use native SAML with signed metadata at all. It is also the step before the last open gap, every IdP of a federation without a list, which needs the aggregate to know who the members are.

Reading a 100 MB aggregate the way botd reads 1 MB is out: a DOM costs many times the document in memory, per provider, daily. The signature has to be checked over the whole document, though, since it is the only thing saying what's in it. And a reader that checks a signature over one view of a document and then uses another view of it is how XML signature wrapping attacks work.

## Decision

### `SSO_<ID>_IDP_AGGREGATE_URL`

A new metadata source, alongside `IDP_METADATA_URL`, `IDP_METADATA_FILE` and `IDP_MDQ_URL`, and exclusive with them: the https URL of the federation's aggregate. It works for one IdP (`IDP_ENTITY_ID`) or several (`IDP_ENTITY_IDS`, which now takes MDQ or an aggregate). As for MDQ, it needs `METADATA_SIGNING_CERT_FILE`, and `SIGNED_METADATA=allow` is refused: aggregates are mirrored and cached by many hands, so only the federation's signature says what is in one. It isn't held to MDQ's one-entity rule. The source is `aggregate` in `botctl sso saml`, the audit log and certificate advice, and `botctl offline check` lists the URL as `metadata aggregate`. `botctl sso saml <id> import` is refused, as for any configured source.

### Verified as it streams

`saml_aggregate::read` reads the aggregate from any `io::Read` and never holds it:

- **A small tokenizer** of its own, no new crates: elements, attributes, text, CDATA and comments, with namespaces resolved as `roxmltree` resolves them. No DTDs (so no entities but the five predefined and character references), no processing instructions but the XML declaration, no stray text outside the root. Names, characters, `--` in comments and unbound prefixes are refused as a parser would. One token is at most 4 MB, nesting at most 128 deep, an element at most 256 attributes, the whole at most 256 MB after decompression.
- **Exclusive C14N into the digest.** The root must be an `md:EntitiesDescriptor` whose first child is its `ds:Signature`, as metadata's schema has it; anything else first is `unsigned`, and a second signature at the root is `wrapped`. The root's start tag waits until the signature is read (its prefix list and digest algorithm decide how to hash it), then everything but the signature is canonicalized as it streams by, exactly as `xmldsig::exc_c14n` renders a parsed document, and hashed. The `Reference` must name the root's `ID` or be `URI=""`, the whole document, which some federations use. `xmldsig::Signature` was split out of `verify_enveloped` so both share the checks of `SignedInfo`, algorithms and the signature value; only the digest is computed differently.
- **Only the listed IdPs are kept.** Each listed `EntityDescriptor` is copied out as written, inside an element declaring the namespaces in scope there, and canonicalized on its own as well (SHA-256). One over 1 MB, or listed twice, is dropped with why. The earliest `validUntil` of the `EntitiesDescriptor`s around it is kept with it.
- **Then validity**, once the signature verifies: the root's `validUntil` is required, not past, and at most 30 days ahead (as for MDQ answers, `no_valid_until`, `expired`, `valid_too_long`).

### Two readers must agree

`saml_sp::load_aggregate_entity` parses each copy again with `roxmltree`, as all metadata is parsed, canonicalizes the `EntityDescriptor` with `xmldsig::exc_c14n`, and uses it only if its SHA-256 equals the stream's. Anything the two readers see differently (an attribute, a namespace, a reference, text) changes one hash but not the other, and the copy is refused as `ambiguous`. So what botd uses is provably bytes the signature covered, whatever a quirk of either reader. The entity's own `validUntil` can only shorten its life, and it is then read exactly as metadata from a URL is.

### Fetched once for every IdP

A provider keeps one download state: when it was read, its last failure, and its `ETag` and `Last-Modified`. It's read when first needed and daily after (the hourly certificate check does this in the background), for every listed IdP at once:

- **A separate HTTP client**: ten minutes per download instead of SSO's ten seconds, no redirects. It asks for gzip (`flate2`, already a dependency) and sends its validators when every copy in hand is still good, so an unchanged aggregate is a `304`, which refreshes every copy's age. The body goes chunk by chunk over a channel to a blocking task that reads it; the download stops as soon as the reader refuses.
- **Sign-ins don't wait** while another task downloads, as long as their IdP's copy is good; only an IdP with no good copy waits for the download.
- **A read replaces each listed IdP's copy.** An IdP missing from the aggregate, listed twice or refused loses its copy: the federation dropped it, and its sign-ins fail as `idp_bad_response`; the log names it. An aggregate refused as a whole keeps every copy until its own `validUntil` (ADR 0281's rule), and is audited as `sso.saml_metadata_refused` with `entityId: null` and `kept` saying whether any IdP still has a copy.
- **Retried at most every ten refresh gaps** (ten minutes by default) after a failure, rather than every gap: each download costs the federation tens of MB.

## Alternatives considered

- **Raise the 1 MB limit and parse it whole.** Hundreds of MB of memory per provider, daily, and a parse time sign-ins would wait on. Rejected.
- **A streaming XML crate (`quick-xml`) and an XML security library.** A new parser in the trust path whose view of the document then differs from `roxmltree`'s, which is the wrapping risk this design closes; and no maintained Rust crate canonicalizes from a stream. The tokenizer here needs only what metadata uses, and the second reading checks it byte for byte.
- **Verify the stream, then trust the copy without parsing it twice.** One reader's quirk would then be the whole defence. The second hash costs little: only the listed IdPs are hashed twice.
- **Keep the aggregate on disk and parse entities from it.** Disk use and a cache to expire, for nothing a verified copy of each listed IdP doesn't already give.
- **Every member of the aggregate, without a list.** The other open gap: a provider would then accept any of thousands of IdPs, which needs its own decisions (the chooser, domains, who may sign up). This slice keeps the list.

## Consequences

- Native SAML works with signed metadata for federations that publish only an aggregate, for one IdP or many, in a few MB of memory whatever the aggregate's size.
- An unchanged aggregate costs one conditional request a day; a changed one, one download for all of a provider's IdPs.
- New code in the trust path: a tokenizer and a streaming canonicalizer, tested against the parsed canonical form (the libxml2 cases plus CRLF, CDATA, references, `xmlns=""` and inclusive prefixes), against tampering, wrapping and validity, and end to end over HTTP with gzip, `304`, a dropped IdP and a badly signed aggregate.
- Still open on #52, only if a customer needs it: every IdP of a federation without a list.
