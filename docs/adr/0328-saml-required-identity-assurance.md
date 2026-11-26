# 0328: Requiring identity assurance from the SAML IdP

## Status

Accepted. The twenty-seventh M5 slice of full SAML ([#52](https://github.com/CG-Labs/superbot/issues/52), [roadmap](../ROADMAP.md#m5--enterprise)). Builds on [ADR 0190](0190-saml-required-authn-context.md) (requiring how people signed in) and [ADR 0323](0323-saml-sp-metadata-for-federation-registration.md) (the attributes our SP metadata asks for). Setup guide: [native SAML](../sso/saml-native.md#require-identity-assurance-refeds-raf).

## Context

ADR 0190 lets botd require MFA: how someone signed in. Research services also need to know how well the person's organization knows who they are. A self-registered guest account with MFA is still a stranger. Services holding controlled data (NIH's, research infrastructures following the AARC guidelines) require both.

Research and education IdPs say this with the [REFEDS Assurance Framework](https://refeds.org/assurance) (RAF), in the multi-valued `eduPersonAssurance` attribute (`urn:oid:1.3.6.1.4.1.5923.1.1.1.11`):

- `https://refeds.org/assurance`: the IdP conforms to RAF. RAF says every RAF claim is made beside it.
- `ID/unique`, `ID/eppn-unique-no-reassign`, …: the identifier is unique and isn't reassigned.
- `IAP/low`, `IAP/medium`, `IAP/high`, `IAP/local-enterprise`: how the identity was checked. RAF says an IdP asserting `high` must also assert `medium` and `low`, and `medium` must come with `low`.
- `ATP/ePA-1m`, `ATP/ePA-1d`: affiliation freshness.
- `profile/cappuccino`, `profile/espresso`: bundles of the above. An IdP signalling Espresso must signal Cappuccino too.
- `version/2`: the IAP claims follow RAF 2.0's criteria rather than 1.0's.

ADR 0190's `AUTHN_METHODS_ATTRIBUTE` could already read `eduPersonAssurance`, but `AUTHN_CONTEXT` lets in anyone with *any* listed value, so it can't require MFA and a vetted identity at once, or several RAF components.

## Decision

A native SAML provider can require identity assurance (`SSO_<ID>_ASSURANCE`, a comma-separated list, no default). A sign-in must show **every** listed value among the values of the assurance attribute of the verified assertion. Otherwise it's refused.

- **The attribute.** `eduPersonAssurance` by its OID, or the one `SSO_<ID>_ASSURANCE_ATTRIBUTE` names, matched by `Name`. It's read only when `ASSURANCE` is set, and only from the assertion whose signature was checked. Values are read as ADR 0190 reads methods: trimmed, plain text, at most 256 bytes each, each once, and at most 32. Anything else is left out, which can only refuse a sign-in.
- **RAF's conformance value is added.** When any listed value is under `https://refeds.org/assurance/`, `https://refeds.org/assurance` is required first. Without it the IdP isn't making a RAF claim, so `IAP/medium` alone would mean nothing defined. The completed list is what `GET /api/sso/:id/saml` and `botctl sso saml <id>` show. Values of other frameworks are taken as they are. Up to 16 values, that one included.
- **Exact matches, no levels inferred.** RAF makes conforming IdPs send every lower level with a higher one, so requiring `IAP/medium` already lets in people at `IAP/high`. An IdP that sends `high` without `medium` doesn't conform, and is refused. Inferring levels would mean botd knowing each framework's order, and an IdP's mistake would become a sign-in.
- **When it's checked.** After the signature, the replay check, the email allow-list, required groups and the authentication context, and before the sign-in age check and the account lookup. So just in time never makes an account for someone without it, and it's checked on every sign-in. The refusal is `auth.login_failed` with reason `assurance`. The event lists what the IdP sent (`assurance`, at most 16 values of 128 characters) and what it lacked (`assuranceMissing`). The person sees `sso_assurance_required`: their organization hasn't vouched for their identity at the level this server requires. It counts against the client's address, as other refusals after the signature do.
- **Evidence.** With a requirement, every `auth.login` records `assurance`, the values the IdP sent.
- **Asking for it.** With `SP_DISPLAY_NAME`, our SP metadata lists the attribute as a `RequestedAttribute` with `isRequired="true"` (ADR 0323), with `FriendlyName="eduPersonAssurance"` when it's that one. Many IdPs release it only to SPs that ask.
- **Several IdPs.** Each person is held to the values the IdP that signed them in sent. No IdP's assurance counts for another's people, since only the signed assertion is read.
- **IdP-initiated sign-in** (ADR 0175) is unchanged: the sign-in it restarts is checked.
- **Settings that would look like a check.** `ASSURANCE_ATTRIBUTE` without `ASSURANCE` is refused at startup. Both are native SAML only.

## Alternatives considered

- **Reuse `AUTHN_CONTEXT`.** Its any-of rule is right for MFA, where IdPs name the same thing differently, and wrong for assurance, where each RAF component is a separate claim the service needs. Mixing both in one list would make MFA and assurance substitutes.
- **Any of the listed values.** Requiring a vetted *and* unique identity is the usual need. With any-of, an admin listing both would get either. A profile value (`profile/cappuccino`) covers the "one bundle" case under all-of.
- **Infer RAF's order** (`IAP/high` meets `IAP/medium`). RAF already requires IdPs to send lower levels. Inferring would accept non-conforming IdPs, and botd would need to know every framework's order.
- **Leave RAF's conformance value to the admin.** Most would forget it, and the check would then accept a value whose meaning isn't defined. Adding it costs nothing with a conforming IdP.
- **Check the IdP's metadata too** (for example its Sirtfi `assurance-certification`). That's about the IdP's incident response, not the person, and `IDP_ENTITY_CATEGORIES` (ADR 0308) already filters IdPs by it.
- **The same for OIDC** (`eduperson_assurance`). It fits there too, but #52 is SAML. Left for later.

## Consequences

- Research services can require a vetted, unique identity from federation IdPs, beside MFA, and every sign-in records the assurance it came with.
- A requirement an IdP can't meet locks its people out of that provider. Break-glass and one-time codes still work, and the audit log shows what the IdP sent and lacked.
- People already signed in keep their sessions when a requirement is turned on. It applies from their next sign-in.
- The bridge ([ADR 0020](0020-saml-bridge.md)) doesn't get this: the broker decides what it passes on.
