# 0308: Every SAML IdP of a federation, without a list

## Status

Accepted. The twenty-third M5 slice of full SAML ([#52](https://github.com/CG-Labs/superbot/issues/52), [roadmap](../ROADMAP.md#m5--enterprise)). Builds on [ADR 0282](0282-saml-several-idps-of-a-federation.md) (several IdPs of a federation on one provider), [ADR 0287](0287-saml-groups-per-idp-of-a-federation.md) (groups per IdP), [ADR 0297](0297-scim-linking-at-one-idp-of-a-federation.md) (SCIM per IdP) and [ADR 0301](0301-saml-federation-aggregates.md) (metadata from a federation's signed aggregate). Setup guide: [native SAML](../sso/saml-native.md#every-idp-of-a-federation).

## Context

ADR 0282 lets one provider take several IdPs of a federation, at most 100, each named in `SSO_<ID>_IDP_ENTITY_IDS`. A research service open to a whole federation (a library resource, a shared instrument, a project across many universities) wants every member: InCommon has about a thousand IdPs, eduGAIN about five thousand, and members join and leave weekly. Listing them by hand never stays right. ADR 0301 left this as the last open gap on #52: the signed aggregate is the one place that says who the members are, and botd can now read it in a few MB.

Taking every IdP raises what a list settled by itself: which entities count as IdPs, whether a federation's tags can narrow them, how a person finds theirs among thousands, what an entity ID nobody listed may cost, and how warnings and logs stay readable at that scale.

## Decision

### `SSO_<ID>_IDP_ENTITY_IDS=all`

`all` (any case, alone) takes every SAML 2.0 IdP in the aggregate: each `EntityDescriptor` with an `IDPSSODescriptor` whose `protocolSupportEnumeration` has SAML 2.0. SPs, SAML 1 only IdPs and attribute authorities are skipped. It needs `IDP_AGGREGATE_URL`: MDQ answers for one entity at a time and can't say who the members are. It is refused with `IDP_ENTITY_ID` or beside other entity IDs. Everything else ADR 0282 says about several IdPs holds: each IdP speaks only for its `shibmd:Scope` domains, groups and role mappings are per IdP, links and SCIM tenants name an IdP, and `JIT_ROLE` needs `ALLOWED_DOMAINS`.

An entity ID with `|` is refused, as in a list (sessions keep `issuer|subject`). At most 10,000 IdPs: past that the aggregate is refused as a whole, so a federation can't grow a provider without bound.

### `SSO_<ID>_IDP_ENTITY_CATEGORIES`

Optional, only with `all`: up to 8 URIs, each of which an IdP must have to be taken. They're read from the entity's `mdattr:EntityAttributes`: `http://macedir.org/entity-category`, `http://macedir.org/entity-category-support` and `urn:oasis:names:tc:SAML:attribute:assurance-certification`. So `http://refeds.org/category/research-and-scholarship` takes the IdPs that support REFEDS R&S, and `https://refeds.org/sirtfi` those that assert Sirtfi. An IdP without them is left out as if not in the aggregate, and the log counts how many.

### Who the IdPs are

Membership is no longer configuration but the last good read of the aggregate. `Provider::lists(entity)` is whether the entity's copy is held, and `listed_idps()` the held IdPs, sorted. Every place that asked "is it one of ours" asks that: the start of a sign-in, unsolicited responses (ADR 0175), artifact sources, logout messages, sessions' IdPs, role mappings and admin links. A sign-in at an entity nobody holds reads the aggregate if it's due and is refused `unknown_idp` if it still isn't there. ADR 0301's rules already bound that: an aggregate read today isn't read again for an entity it didn't have, and a failed read is retried at most every ten refresh gaps, so made-up entity IDs can't make botd download it again. SCIM tenants (ADR 0297) keep their IdP even while the aggregate leaves it out, so its people can still be deprovisioned; only sign-ins need it held.

The aggregate is read as it streams (ADR 0301), and each IdP is parsed and checked by both readers as soon as its `EntityDescriptor` closes, inside the blocking reader. Only the parsed metadata is held until the root's signature verifies, not thousands of copies of XML. If the signature fails, all of it is dropped.

### The chooser is a search box

A list of thousands of links helps nobody. With `all`, the chooser is a GET form back to `/start`, carrying the sign-in's own parameters as hidden fields, with a `q` box. It shows the IdPs whose display name, entity ID or scopes contain every word typed, ignoring case, sorted by name, at most 50, and says how many more match. It lists nothing until something is typed. The page still runs no script. Its CSP allows `form-action 'self'` instead of `'none'`. IdPs tagged `http://refeds.org/category/hide-from-discovery` aren't shown, as federations ask, but `?idp=` still signs in there.

### Readable at scale

- **Logs**: one line per read, counting the IdPs taken and those left out by category, and one line counting the IdPs that can't be used, naming the first.
- **Certificate warnings**: the IdPs' own certificates aren't checked for expiry. The federation and each member look after those, and thousands would bury botd's own warnings. The federation's signing certificate and botd's keys are still warned about.
- **`botctl sso saml` and its API** show `everyIdp`: how many IdPs are held, how many are hidden, and the categories required. `idps` stays empty.
- **`botctl offline check`** lists only the aggregate URL, as for a list.

## Alternatives considered

- **Raise the list's limit.** It doesn't follow joins and leaves, and nobody keeps a 5,000-line setting right.
- **Every IdP through MDQ.** MDQ has no way to list entities, and fetching on demand would let any entity ID cost a request to the federation.
- **A discovery service (SeamlessAccess, a federation's WAYF).** A third party in every sign-in and a JavaScript page, against botd's no-script pages; a federation's own discovery can still send people to `/start?idp=`. Could come later as an option.
- **Show every IdP on one page.** Megabytes of HTML at eduGAIN's size, and still a search for the person, done by the browser.
- **Hold the XML until the signature verifies, then parse.** Tens of MB of copies for nothing: the parsed metadata is what's kept, and nothing is used before the signature verifies either way.
- **Keep warning about each IdP's certificates.** Thousands of audit events nobody here can act on.

## Consequences

- A provider can serve a whole federation, or every IdP with a given category, and follows its joins and leaves daily without any change to settings.
- The chooser needs the person to type part of their organization's name or domain.
- Who may sign in is now the federation's call, within the categories set. `ALLOWED_DOMAINS`, `REQUIRED_GROUPS` and linking decide who gets an account, as before.
- #52 has nothing left that a customer has asked for.
