# Sign in with a SAML identity provider (ADFS, Okta, OneLogin, PingFederate, …)

Lets people sign in with an identity provider that only speaks SAML 2.0, through [Keycloak](https://www.keycloak.org) as a bridge. Keycloak receives and checks the SAML response, then signs people in to SuperBot with OpenID Connect. SuperBot accepts only people that SAML IdP vouched for and links them by the IdP's own id for them, so they are the same users as with any other provider. Why a bridge and not SAML in botd: [ADR 0019](../adr/0020-saml-bridge.md). If your IdP also speaks OpenID Connect, use [the OIDC guide](oidc.md) instead: it's one service fewer.

```
browser ──► SuperBot ──OIDC──► Keycloak ──SAML──► ADFS / Okta / …
```

You need: admin rights in the IdP; a Keycloak (26 or later) on HTTPS that you keep updated, like `https://sso.example.com`; and SuperBot on HTTPS at a fixed address, like `https://superbot.example.com`. Run Keycloak in production mode with a database, as [its docs](https://www.keycloak.org/server/configuration-production) describe. Its SAML checks protect your sign-in, so apply its security releases.

Each provider has an id you choose (lowercase letters and digits), like `adfs`. It names its settings (`SSO_ADFS_*`) and its redirect URI. The examples use `adfs` for the SuperBot provider id and the Keycloak IdP alias, and `superbot` for the Keycloak realm.

## 1. A Keycloak realm for the bridge

In the Keycloak admin console, **Create realm** `superbot`. Keep it just for this bridge:

- **No local users.** Don't create any, and leave **Realm settings → Login → User registration** off. SuperBot refuses anyone who didn't come through your SAML IdP anyway.
- **Short sessions.** **Realm settings → Sessions**: **SSO Session Idle** 5 minutes, **SSO Session Max** 30 minutes. While a Keycloak session lasts, SuperBot sign-ins reuse it without asking the IdP again, so this bounds how long someone disabled at the IdP can still sign in. SuperBot's own sessions are separate.

## 2. Add your IdP to Keycloak

**Identity providers → SAML v2.0**:

| Field | Value |
|-------|-------|
| **Alias** | `adfs` (letters, digits, `.`, `_`, `-`). It is in the broker URLs and in `SSO_ADFS_IDP_ALIAS`. |
| **Display name** | Your company. |
| **Service provider entity ID** | Keep the default, `https://sso.example.com/realms/superbot`. Your IdP calls this the relying party identifier, or audience. |
| **Use entity descriptor** / **SAML entity descriptor** | On, with your IdP's metadata URL (see [the IdP examples](#3-register-the-bridge-at-your-idp)). Keycloak fills in the URLs and the signing certificate. Turn on **Use metadata descriptor URL** so certificate rollovers are picked up. |

Save, then check or set:

| Field | Value |
|-------|-------|
| **Identity provider entity ID** | Your IdP's entity ID, exactly as in its metadata. Keycloak refuses responses from any other issuer. The same value goes in `SSO_ADFS_IDP_ENTITY_ID`. |
| **Principal type** | **Subject NameID**. |
| **NameID policy format** | **Persistent**. A transient NameID changes every sign-in, and an email NameID can change hands. |
| **HTTP-POST binding response** and **for AuthnRequest** | On. |
| **Want AuthnRequests signed** | On. |
| **Want Assertions signed** | On. |
| **Validate Signatures** | On. Never turn this off. |
| **Allowed clock skew** | `0`, or a few seconds if clocks drift. Keep NTP running on both sides. |
| **Trust Email** | On only if the IdP's emails are verified company addresses (true for ADFS from Active Directory, and for Okta). Then SuperBot sees them as verified. Without it, `ALLOWED_DOMAINS` and just in time get no email. |
| **Sync mode** | **Force**, so name and email changes at the IdP are picked up at each sign-in. |

Then **Mappers → Add mapper** for each attribute your IdP sends, type **Attribute Importer**, sync mode Force: the IdP's email attribute to user attribute `email`, the given name to `firstName`, and the surname to `lastName`. The attribute names depend on the IdP; see below.

Keycloak publishes the bridge's SAML metadata, which your IdP needs, at:

```
https://sso.example.com/realms/superbot/broker/adfs/endpoint/descriptor
```

## 3. Register the bridge at your IdP

The bridge is the SAML service provider (relying party). Its **entity ID** is `https://sso.example.com/realms/superbot` and its **ACS URL** (reply URL, single sign-on URL) is `https://sso.example.com/realms/superbot/broker/adfs/endpoint`.

The NameID must be **persistent** and its value must **never change or move to another person**: not an email, UPN, or username. SuperBot links people by it.

### ADFS

1. **AD FS Management → Relying Party Trusts → Add Relying Party Trust**, **Claims aware**. Import the bridge's metadata URL above (or download it and import the file). Choose an access control policy that allows only the people who should use SuperBot.
2. **Edit Claim Issuance Policy → Add Rule → Send Claims Using a Custom Rule**, named `Persistent NameID`. It issues an opaque per-person id that ADFS keeps stable:

   ```
   c:[Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/windowsaccountname", Issuer == "AD AUTHORITY"]
    => add(store = "_OpaqueIdStore", types = ("http://superbot/internal/persistentid"), query = "{0};{1};{2}", param = "ppid", param = c.Value, param = c.OriginalIssuer);

   c:[Type == "http://superbot/internal/persistentid"]
    => issue(Type = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier", Issuer = c.Issuer, OriginalIssuer = c.OriginalIssuer, Value = c.Value, ValueType = c.ValueType, Properties["http://schemas.xmlsoap.org/ws/2005/05/identity/claimproperties/format"] = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent");
   ```

3. **Add Rule → Send LDAP Attributes as Claims**, store Active Directory: `E-Mail-Addresses` → **E-Mail Address**, `Given-Name` → **Given Name**, `Surname` → **Surname**.
4. Sign the whole response as well as the assertion (PowerShell on the ADFS server):

   ```powershell
   Set-AdfsRelyingPartyTrust -TargetName "SuperBot" -SamlResponseSignature MessageAndAssertion
   ```

In Keycloak, the ADFS metadata URL is `https://adfs.example.com/FederationMetadata/2007-06/FederationMetadata.xml`, and the entity ID is usually `http://adfs.example.com/adfs/services/trust` (check `entityID` in that file). The attribute importers use the claim URIs:

| Keycloak user attribute | ADFS attribute name |
|-------------------------|---------------------|
| `email` | `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress` |
| `firstName` | `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname` |
| `lastName` | `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname` |

### Okta

1. **Applications → Create App Integration → SAML 2.0**, named SuperBot.
2. **Single sign-on URL**: the ACS URL above, with **Use this for Recipient URL and Destination URL** on. **Audience URI (SP Entity ID)**: `https://sso.example.com/realms/superbot`.
3. **Name ID format**: **Persistent**. **Application username**: **Custom**, `user.getInternalProperty("id")`: the Okta user id (`00u…`), which never changes. Okta's username or email would.
4. **Show Advanced Settings**: **Response** Signed, **Assertion Signature** Signed, RSA-SHA256.
5. **Attribute Statements**: `email` → `user.email`, `firstName` → `user.firstName`, `lastName` → `user.lastName`.
6. **Assignments**: only the people or groups who should use SuperBot.

In Keycloak, the metadata URL is the **Metadata URL** on the app's **Sign On** tab, and the entity ID is the **Issuer** there, like `http://www.okta.com/exk…`. The attribute importers use `email`, `firstName`, and `lastName`.

OneLogin and PingFederate work the same way: a SAML app with the ACS URL and entity ID above, a persistent NameID from an immutable user id, signed responses and assertions, and email and name attributes.

## 4. Connect SuperBot to Keycloak

In the `superbot` realm, **Clients → Create client**:

- **OpenID Connect**, client id `superbot`. **Client authentication** on, **Standard flow** only (no direct access grants, no implicit).
- **Valid redirect URIs**: `https://superbot.example.com/api/auth/sso/adfs/callback`, exactly.
- **Advanced → Proof Key for Code Exchange Code Challenge Method**: S256.
- **Credentials**: note the client secret.

Then **Client scopes → superbot-dedicated → Configure a new mapper → User Session Note**, twice. These put the IdP's alias and its id for the person in the ID token, where SuperBot checks them:

| Name, User Session Note, and Token Claim Name | Add to ID token |
|-----------------------------------------------|-----------------|
| `identity_provider` | On |
| `identity_provider_identity` | On |

## 5. Configure SuperBot

In `.env` (installer: `/home/superbot/superbot/.env`; Docker: `deploy/docker/.env`):

```bash
SSO_PROVIDERS=adfs                       # several: entra,adfs
SSO_PUBLIC_URL=https://superbot.example.com
SSO_ADFS_TYPE=saml
SSO_ADFS_ISSUER=https://sso.example.com/realms/superbot
SSO_ADFS_CLIENT_ID=superbot
SSO_ADFS_IDP_ALIAS=adfs
SSO_ADFS_IDP_ENTITY_ID=http://adfs.example.com/adfs/services/trust
SSO_ADFS_LABEL=Acme                      # the button says "Sign in with Acme"
```

The client secret, in one of three ways (botd reads it when used, so rotating needs no restart):

```bash
botctl secret set SSO_ADFS_CLIENT_SECRET < kc-secret.txt && rm kc-secret.txt   # recommended
SSO_ADFS_CLIENT_SECRET_FILE=/etc/superbot/kc-secret
SSO_ADFS_CLIENT_SECRET=<value>
```

Restart botd. The log says `SSO: adfs (Acme, saml), ready; anyone SAML IdP http://adfs.example.com/adfs/services/trust signs in (broker alias adfs); …`. The button sends people straight to your IdP (`kc_idp_hint`), without a Keycloak page in between.

### All settings

`<ID>` is the provider id in capitals.

| Variable | Default | Meaning |
|----------|---------|---------|
| `SSO_<ID>_TYPE` | (required) | `saml`. |
| `SSO_<ID>_ISSUER` | (required) | The Keycloak realm's issuer, https: `https://<host>/realms/<realm>`. |
| `SSO_<ID>_CLIENT_ID` | (required) | The Keycloak client id. |
| `SSO_<ID>_CLIENT_SECRET` | (required) | As above; env, `_FILE`, or `botctl secret set`. |
| `SSO_<ID>_IDP_ALIAS` | (required) | The IdP's alias in Keycloak. Only ID tokens whose `identity_provider` claim is exactly this sign in. |
| `SSO_<ID>_IDP_ENTITY_ID` | (required) | The SAML IdP's entity ID. Identities are stored under it, so they stay valid if you rebuild or replace the bridge. |
| `SSO_<ID>_LABEL` | `Company SSO` | Button text: "Sign in with …". |
| `SSO_<ID>_SCOPES` | `openid profile email` | Must include `openid`. |
| `SSO_<ID>_ALLOWED_DOMAINS` | | Only people whose **verified** email is in one of these domains get in, comma separated (exact; list subdomains on their own). Needs **Trust Email** in Keycloak. |
| `SSO_<ID>_SUBJECT_CLAIM` | `identity_provider_identity` | The claim with the IdP's id for the person. Mutable claims (`email`, `preferred_username`, …) are refused. |
| `SSO_<ID>_EMAIL_CLAIM` | `email` | The claim with the email. It counts only when `email_verified` is true. |
| `SSO_<ID>_NAME_CLAIM` | `name` | The claim with the display name. |
| `SSO_<ID>_JIT_ROLE` | `off` | `readonly`, `member`, or `admin`: create a user the first time someone signs in. Needs `SSO_<ID>_ALLOWED_DOMAINS` (and so **Trust Email**): botd won't start without it ([ADR 0103](../adr/0103-sso-jit-needs-an-allow-list.md)). |

`SSO_PUBLIC_URL` and `SSO_APP_REDIRECTS` are shared by all providers; see [the Entra guide](entra.md#all-settings). Settings of other types (`TENANT`, `ALLOWED_ORGS`, …) on a `saml` provider are refused, and `IDP_ALIAS` or `IDP_ENTITY_ID` on other types are too.

Several SAML IdPs can share one Keycloak realm: add each as its own identity provider with its own alias, and give each its own SuperBot provider (same issuer and client, different id, alias, and entity ID).

## 6. Let people in

**Link people (default).** SuperBot never matches an account to a user by email. The subject is the NameID your IdP sends. ADFS's persistent id isn't shown anywhere in Active Directory, so let the person try once and read it from the audit log, then link it (Okta: the user's id, `00u…`, also works):

```bash
botctl audit 5 --action auth.login_failed          # details.subject on the not_linked event
botctl user link ada@example.com adfs <subject>
```

Admins can also link it in the app: **Users**, pick the person, then **Single sign-on** ([ADR 0021](../adr/0021-admin-portal.md)).

SAML subjects are compared without case: Keycloak lowercases the NameID before passing it on, and SuperBot lowercases what you link.

**Or just in time** (your domains only). With `SSO_ADFS_ALLOWED_DOMAINS=example.com` and `SSO_ADFS_JIT_ROLE=member`, anyone your IdP lets into the SuperBot app with a verified `@example.com` email becomes a member. `JIT_ROLE` without `ALLOWED_DOMAINS` is refused at startup ([ADR 0103](../adr/0103-sso-jit-needs-an-allow-list.md)). Also limit who can use the app at the IdP (ADFS: the relying party's access control policy; Okta: app assignments). If someone's email already belongs to another SuperBot user, sign-in is refused until an admin links them.

One person can sign in with several providers (SAML, Entra, Google, …) as one user: link each identity to the same user.

## Require MFA at the IdP

SuperBot doesn't ask single sign-on sign-ins for its own second factor: the IdP's MFA is that factor, so require it there. Sign-in codes and the owner's password get SuperBot's own two-factor authentication instead ([ADR 0094](../adr/0094-totp-second-factor.md)). Requiring MFA at your IdP is your control as the customer (CC6.1-2 in the [SOC 2 readiness checklist](../security/soc2-readiness-checklist.md)).

Require MFA at your SAML IdP, where people actually sign in: in ADFS, an access control policy such as **Permit everyone and require MFA** on the Keycloak relying party; in Okta, an authentication policy with a possession factor on the SAML app. The Keycloak bridge passes the sign-in through and adds no factor of its own.

## Troubleshooting

SAML problems show on Keycloak's error page and in its log (**Realm settings → Events** to keep them). SuperBot's are in its audit log with a reason (`botctl audit --action auth.login_failed`):

| Where | Message or reason | Fix |
|-------|-------------------|-----|
| Keycloak | "Invalid signature in response from identity provider" | The IdP's signing certificate in Keycloak is stale (use the metadata URL), or the IdP doesn't sign responses and assertions. |
| Keycloak | "Invalid requester", assertion expired | Clocks differ: fix NTP, or allow a few seconds of clock skew. |
| Keycloak | "Unexpected error when authenticating with identity provider" | Often the IdP's entity ID, audience, or ACS URL don't match. Keycloak's log has the detail. |
| SuperBot | `not_brokered` | The token wasn't from a sign-in through `SSO_<ID>_IDP_ALIAS`: the alias differs from Keycloak's, the two User Session Note mappers are missing, or someone signed in to Keycloak another way. People see "That account can't sign in here". |
| SuperBot | `not_linked` | Link the person, or turn on just in time. The event has the `subject` and the IdP's entity ID as `issuer`. |
| SuperBot | `missing_subject` | The `identity_provider_identity` mapper is missing or not added to the ID token. |
| SuperBot | `wrong_issuer` | `SSO_<ID>_ISSUER` isn't the realm's issuer, or Keycloak's hostname setting differs from the address botd uses. |
| SuperBot | `email_unverified`, `wrong_domain` | Turn on **Trust Email** and import the email attribute, or the email isn't in `ALLOWED_DOMAINS`. |
| SuperBot | `code_exchange_failed` | The client secret, a redirect URI mismatch, or PKCE not set to S256. |
