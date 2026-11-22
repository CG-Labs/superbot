# Sign in with SAML 2.0 (Okta, Microsoft Entra ID, ADFS, OneLogin, …)

SuperBot is the SAML service provider (SP) itself: your IdP posts its signed answer straight to SuperBot, which checks the signature against the IdP's certificate and the audience, recipient, time and request it answers ([ADR 0127](../adr/0127-native-saml-service-provider.md)). There is nothing else to run. People land on the same users as with any other provider. If your IdP also speaks OpenID Connect, [OIDC](oidc.md) works just as well; the [Keycloak bridge](saml.md) remains for IdPs that need encrypted assertions or signed requests.

```
browser ──► SuperBot ──AuthnRequest──► Okta / Entra ID / ADFS
        ◄── signed SAML response (HTTP-POST to the ACS) ──
```

You need admin rights in the IdP and SuperBot on HTTPS at a fixed address, like `https://superbot.example.com`. Each provider has an id you choose (lowercase letters and digits), like `corp`; it names its settings (`SSO_CORP_*`) and its URLs.

## 1. Configure SuperBot

In `.env` (installer: `/home/superbot/superbot/.env`; Docker: `deploy/docker/.env`):

```bash
SSO_PROVIDERS=corp                       # several: entra,corp
SSO_PUBLIC_URL=https://superbot.example.com
SSO_CORP_TYPE=saml                       # and no SSO_CORP_ISSUER: that would be the bridge
SSO_CORP_IDP_ENTITY_ID=<the IdP's entity ID, from step 2>
SSO_CORP_IDP_METADATA_URL=<the IdP's metadata URL, from step 2>
SSO_CORP_LABEL=Acme                      # the button says "Sign in with Acme"
```

Restart botd, then show what to enter at the IdP:

```console
$ botctl sso saml corp
Acme (corp): ready
  SP entity ID (audience):  https://superbot.example.com/api/auth/sso/corp/metadata
  ACS URL (reply URL):      https://superbot.example.com/api/auth/sso/corp/acs
  SP metadata:              https://superbot.example.com/api/auth/sso/corp/metadata
  IdP entity ID:            http://www.okta.com/exk1abc
  IdP metadata from url (https://acme.okta.example/app/exk1abc/sso/saml/metadata):
    Sign-in URL: https://acme.okta.example/app/acme_superbot_1/exk1abc/sso/saml
    Certificate SHA-256 3f:a1:… (CN=acme), expires 2036-05-01
```

You can set up the IdP first and fill in the two IdP settings after: until botd has the IdP's metadata, the provider isn't offered and `botctl sso saml corp` says so.

**No metadata URL?** If the IdP has no URL botd can reach, either download the metadata and set `SSO_CORP_IDP_METADATA_FILE=/etc/superbot/corp-idp.xml` (read at startup), or leave both out and import it, which botd keeps in its database and audits:

```bash
botctl sso saml corp import < idp-metadata.xml
```

With a URL, botd refreshes the metadata daily (keeping the last good copy if the IdP is down), so certificate rollovers need nothing from you. With a file or an import, add the new certificate before the IdP switches to it: metadata may list several.

## 2. Register SuperBot at your IdP

Whatever the IdP:

- **ACS URL** (reply URL, single sign-on URL) and **Recipient/Destination**: the ACS URL above.
- **Audience** (SP entity ID, identifier): the SP entity ID above.
- **NameID**: **persistent**, from an id that never changes or moves to another person: not an email, UPN or username. SuperBot links people by it.
- **Sign the assertion** with RSA-SHA256 (signing the response as well is fine). Don't encrypt it.
- An **email** attribute, and a display name if you like.
- Only the people who should use SuperBot assigned to the app, and **MFA required** ([below](#require-mfa-at-the-idp)).

### Okta

1. **Applications → Create App Integration → SAML 2.0**, named SuperBot.
2. **Single sign-on URL**: the ACS URL, with **Use this for Recipient URL and Destination URL** on. **Audience URI (SP Entity ID)**: the SP entity ID.
3. **Name ID format**: **Persistent**. **Application username**: **Custom**, `user.getInternalProperty("id")`: the Okta user id (`00u…`), which never changes.
4. **Show Advanced Settings**: **Response** Signed, **Assertion Signature** Signed, **Signature Algorithm** RSA-SHA256, **Assertion Encryption** Unencrypted.
5. **Attribute Statements**: `email` → `user.email`, `displayName` → `user.displayName`.
6. **Assignments**: only the people or groups who should use SuperBot.

On the app's **Sign On** tab, the **Metadata URL** is `SSO_CORP_IDP_METADATA_URL` and the **Issuer** (`http://www.okta.com/exk…`) is `SSO_CORP_IDP_ENTITY_ID`.

### Microsoft Entra ID

1. **Entra admin center → Enterprise applications → New application → Create your own application**, named SuperBot, **Integrate any other application you don't find in the gallery (Non-gallery)**.
2. **Single sign-on → SAML → Basic SAML Configuration**: **Identifier (Entity ID)** the SP entity ID, **Reply URL (Assertion Consumer Service URL)** the ACS URL. Leave the sign-on, relay state and logout URLs empty.
3. **Attributes & Claims → Unique User Identifier (Name ID)**: **Name identifier format** Persistent, **Source attribute** `user.objectid`. The default (`user.userprincipalname`) can change and move to someone else.
4. Keep the default claims: Entra sends the email as `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress` (from `user.mail`) and the name as `http://schemas.microsoft.com/identity/claims/displayname`, which SuperBot reads without settings.
5. **SAML Certificates**: **Signing Option** Sign SAML assertion (or Sign SAML response and assertion), **Signing Algorithm** SHA-256. Leave **Token encryption** off.
6. **Properties → Assignment required?** Yes, then **Users and groups**: only those who should use SuperBot.

Under **SAML Certificates**, the **App Federation Metadata Url** is `SSO_CORP_IDP_METADATA_URL`. Under **Set up SuperBot**, the **Microsoft Entra Identifier** (`https://sts.windows.net/<tenant-id>/`) is `SSO_CORP_IDP_ENTITY_ID`.

### ADFS, OneLogin, PingFederate

The same in their terms: a relying party or SAML app from SuperBot's SP metadata URL, a persistent NameID from an immutable id (for ADFS, the custom rule in [the bridge guide](saml.md#adfs)), signed assertions with SHA-256, and email and name attributes. ADFS's entity ID is usually `http://<adfs-host>/adfs/services/trust` and its metadata is at `https://<adfs-host>/FederationMetadata/2007-06/FederationMetadata.xml`.

## 3. Let people in

**Link people (default).** SuperBot never matches an account to a user by email. Let the person try once, read their NameID from the audit log, then link it:

```bash
botctl audit 5 --action auth.login_failed          # details.subject on the not_linked event
botctl user link ada@example.com corp <subject>
```

Admins can also link it in the app: **Users**, pick the person, then **Single sign-on**. Subjects are compared without case.

**Or just in time** (your domains only). With `SSO_CORP_ALLOWED_DOMAINS=example.com` and `SSO_CORP_JIT_ROLE=member`, anyone your IdP signs in with an `@example.com` email becomes a member. `JIT_ROLE` without `ALLOWED_DOMAINS` is refused at startup ([ADR 0103](../adr/0103-sso-jit-needs-an-allow-list.md)). If the email already belongs to another user, sign-in is refused until an admin links them.

People disabled in SuperBot, by an admin or by SCIM deprovisioning ([SCIM](scim.md)), can't sign in, whatever the IdP says.

**Moving from the bridge.** Identities are stored the same way (the IdP's entity ID and the lowercased NameID), so links carry over: remove `ISSUER`, `CLIENT_ID`, `IDP_ALIAS` and the client secret, add the metadata, and register SuperBot at the IdP in place of Keycloak.

## All settings

`<ID>` is the provider id in capitals.

| Variable | Default | Meaning |
|----------|---------|---------|
| `SSO_<ID>_TYPE` | (required) | `saml`, without `SSO_<ID>_ISSUER`. |
| `SSO_<ID>_IDP_ENTITY_ID` | (required) | The IdP's entity ID. Responses from any other issuer are refused, and identities are stored under it. |
| `SSO_<ID>_IDP_METADATA_URL` | | The IdP's metadata, https, refreshed daily. |
| `SSO_<ID>_IDP_METADATA_FILE` | | Or a metadata file, read at startup. Without either, import it with `botctl sso saml <id> import`. |
| `SSO_<ID>_SP_ENTITY_ID` | `<SSO_PUBLIC_URL>/api/auth/sso/<id>/metadata` | Our entity ID (the audience), if the IdP needs another. |
| `SSO_<ID>_EMAIL_ATTRIBUTE` | `email`, `mail`, or the emailaddress claim URI | The attribute with the email. |
| `SSO_<ID>_NAME_ATTRIBUTE` | `displayName`, `name`, or the displayname claim URI | The attribute with the display name. |
| `SSO_<ID>_ALLOWED_DOMAINS` | | Only these email domains, comma separated (exact; list subdomains on their own). |
| `SSO_<ID>_JIT_ROLE` | `off` | `readonly`, `member` or `admin`: create a user at first sign-in. Needs `ALLOWED_DOMAINS`. |
| `SSO_<ID>_LABEL` | `Company SSO` | Button text: "Sign in with …". |

The bridge's settings (`CLIENT_ID`, `IDP_ALIAS`, `SCOPES`, `*_CLAIM`) are refused on a native provider, and the native ones on a bridge provider, so a provider is never half of each. There is no client secret.

## Require MFA at the IdP

SuperBot doesn't ask single sign-on sign-ins for its own second factor: the IdP's MFA is that factor, so require it there (Okta: an authentication policy with a possession factor on the app; Entra ID: a Conditional Access policy requiring MFA for the app). This is your control as the customer (CC6.1-2 in the [SOC 2 readiness checklist](../security/soc2-readiness-checklist.md)).

## Troubleshooting

Every refused sign-in is in the audit log with a reason (`botctl audit --action auth.login_failed`, `idp` = `saml`). Failures nobody vouched for, such as bad signatures, are logged at most once a minute per address, with a count of those skipped. People see a short message on the sign-in page.

| Reason | Fix |
|--------|-----|
| `not_linked` | Link the person, or turn on just in time. The event has the `subject` and the IdP's entity ID as `issuer`. |
| `unsigned` | The IdP signs only the response, or nothing: sign the assertion. |
| `bad_signature` | The IdP signed with a certificate botd doesn't have: refresh or import the metadata (`botctl sso saml <id>` shows the certificates in use). |
| `weak_algorithm`, `bad_algorithm` | Use RSA-SHA256 (SHA-1 is refused). |
| `encrypted_assertion` | Turn off assertion encryption, or use the bridge. |
| `wrong_audience` | The IdP's audience (entity ID) isn't the SP entity ID botctl shows. |
| `wrong_recipient`, `wrong_destination` | The IdP's ACS (reply) URL isn't the one botctl shows, often because `SSO_PUBLIC_URL` differs from the address people use. |
| `wrong_issuer` | `SSO_<ID>_IDP_ENTITY_ID` isn't the IdP's entity ID. |
| `in_response_to_mismatch`, `unknown_state` | Not an answer to a sign-in this browser started: IdP-initiated sign-in (from the IdP's app tile) isn't supported; start from SuperBot. Or the sign-in took over 10 minutes. |
| `expired`, `not_yet_valid` | Clocks differ by more than two minutes: fix NTP. |
| `replayed` | The same assertion was posted twice. |
| `transient_subject`, `missing_subject` | Use a persistent NameID. |
| `email_unverified`, `wrong_domain` | No email attribute was sent, or it isn't in `ALLOWED_DOMAINS`. Set `SSO_<ID>_EMAIL_ATTRIBUTE` if the IdP uses another name. |
| `idp_error` | The IdP said no (`idpStatus` has its status code), for example someone not assigned to the app. |
| `user_disabled` | The person is disabled in SuperBot. |
