# 0323: SAML SP metadata a federation can register

## Status

Accepted. The twenty-sixth M5 slice of full SAML ([#52](https://github.com/CG-Labs/superbot/issues/52), [roadmap](../ROADMAP.md#m5--enterprise)). Builds on [ADR 0281](0281-saml-metadata-from-mdq.md) to [ADR 0319](0319-saml-subject-identifier-attributes.md), which let botd use a federation's IdPs. Setup guide: [native SAML](../sso/saml-native.md#registering-superbot-with-a-federation).

## Context

botd can now take every IdP of a research and education federation (InCommon, eduGAIN's national federations). But those IdPs only see SuperBot once the operator's home federation registers SuperBot's SP metadata, and they release attributes by what that metadata says. botd's metadata had none of what federations ask for:

- **`mdui:UIInfo`**: the name, description and links people see in discovery services and on consent pages.
- **`md:Organization`** and **`md:ContactPerson`**s, including the REFEDS security contact (`contactType="other"` with `remd:contactType="http://refeds.org/metadata/contactType/security"`, a `GivenName` and an `EmailAddress`).
- **Sirtfi**: the entity attribute `urn:oasis:names:tc:SAML:attribute:assurance-certification` with `https://refeds.org/sirtfi`, and `https://refeds.org/sirtfi2` with it for v2. It's self-asserted and needs a security contact. InCommon's Baseline Expectations and the UK federation's CoCo process ask for it.
- **`md:RequestedAttribute`**s in an `AttributeConsumingService`: what the SP reads, with `isRequired="true"` on what it needs. The REFEDS Code of Conduct v2 requires them, and Shibboleth IdPs can release by them.

Entity categories (REFEDS Research and Scholarship, Code of Conduct v2) are different: a registrar adds them after review. An SP's own claim is ignored or stripped. What an SP can do is have the metadata each one needs. R&S needs a `DisplayName`, an `InformationURL`, a technical contact and the HTTP-POST binding. CoCo v2 needs a `DisplayName`, a `Description` and a `PrivacyStatementURL`, and requested attributes.

## Decision

### Settings

New native SAML settings, all optional, refused on the bridge and on other types:

| Setting | Published as |
|--|--|
| `SP_DISPLAY_NAME` | `mdui:DisplayName`, and the `ServiceName` of the `AttributeConsumingService` |
| `SP_DESCRIPTION` | `mdui:Description` |
| `SP_INFORMATION_URL`, `SP_PRIVACY_URL` | `mdui:InformationURL`, `mdui:PrivacyStatementURL` |
| `SP_ORGANIZATION`, `SP_ORGANIZATION_URL` | `md:Organization` (its name as both name and display name) |
| `SP_CONTACT_TECHNICAL`, `_SUPPORT`, `_ADMINISTRATIVE`, `_SECURITY` | `md:ContactPerson`, the last as the REFEDS security contact |
| `SP_SIRTFI` | `off` (default), `v1`, or `v2` (both values) |

Text is one line, trimmed, at most 100 characters (500 for the description). Links must be https. A contact is `Name <email>` or an email, and the security contact must have a name. Startup refuses anything else, and refuses a description or link without a display name, an organization without its URL, and Sirtfi without a security contact. Every value is English (`xml:lang="en"`), which the categories require.

### Requested attributes

With a display name, the metadata lists the attributes botd reads: the email and display name (`EMAIL_ATTRIBUTE` and `NAME_ATTRIBUTE` if set, else eduPerson's `mail` and `displayName` by OID, with their friendly names), the groups attribute and the authentication methods attribute if named. The email is required when `ALLOWED_DOMAINS` is set, since sign-in then fails without it, and the groups with `REQUIRED_GROUPS`. Nothing else is required. A subject identifier stays in `subject-id:req` (ADR 0319), as CoCo v2 says. URIs carry the `uri` name format; short names (Okta's `email`) carry none.

Without a display name, no `AttributeConsumingService` is published: it needs a `ServiceName`, and inventing one would put a name in federations' listings that nobody chose.

### Unchanged unless set

With none of these settings, the metadata is byte for byte what it was. Okta, Entra ID and ADFS deployments, which import it once, see no change.

### What's shown

`GET /api/sso/<id>/saml` gains `about`: the values, the contacts, Sirtfi, the requested attributes, and for R&S and CoCo v2 the settings still missing (`RESPONSE_BINDING=post` too for R&S). `botctl sso saml <id>` prints a "Federation listing" line and one per category: "metadata ready, ask the federation to add it" or what to set. botd never claims a category itself.

## Alternatives considered

- **Publish entity categories from a setting.** Registrars add them, and many strip an SP's own. A setting would suggest a membership that isn't there. Showing what each still needs is what helps.
- **Several languages.** The categories need English, and most federations show English. Per-language settings would multiply ten settings by each language. A later slice can add them if someone asks.
- **`mdui:Logo`.** It needs its height and width, and federations recommend but don't require it. Left out for now.
- **Sign our own metadata.** Federations sign the aggregate they publish, and an SP's signature isn't checked by its IdPs there. Okta and Entra ID take unsigned metadata.
- **Requested attributes always, named after the provider's label.** That would change every existing deployment's metadata and put the label, often "Okta", in a federation's listing.

## Consequences

- An operator can register SuperBot with their federation from its metadata URL, without editing XML, and apply for R&S, CoCo v2 and Sirtfi.
- IdPs that release by requested attributes or by R&S send the email and name SuperBot needs.
- Contacts' emails are public in the metadata, as federations require. The guide says to use role addresses.
