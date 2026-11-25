# Sign in with SAML 2.0 (Okta, Microsoft Entra ID, ADFS, OneLogin, …)

SuperBot is the SAML service provider (SP) itself: your IdP posts its signed answer straight to SuperBot, which checks the signature against the IdP's certificate and the audience, recipient, time and request it answers ([ADR 0127](../adr/0127-native-saml-service-provider.md)). There is nothing else to run. People land on the same users as with any other provider. If your IdP also speaks OpenID Connect, [OIDC](oidc.md) works just as well; the [Keycloak bridge](saml.md) remains for an IdP that encrypts assertions with AES-CBC but can't sign the whole response ([below](#aes-cbc-entra-id-and-adfs)).

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
  SLO URL (logout URL):     https://superbot.example.com/api/auth/sso/corp/slo
  SP metadata:              https://superbot.example.com/api/auth/sso/corp/metadata
  IdP entity ID:            http://www.okta.com/exk1abc
  SP signing certificate:   SHA-256 9c:02:… (generated), expires 2046-11-21
  Encrypted assertions:     off
  Signs AuthnRequests:      no
  Single logout:            yes
  Back-channel logout:      from the IdP only (its metadata has no SOAP SingleLogoutService)
    SOAP SLO URL:            https://superbot.example.com/api/auth/sso/corp/slo/soap
  IdP-initiated sign-in:    refused (start from SuperBot)
  Authentication context:   not checked (the IdP's MFA isn't required)
  IdP metadata from url (https://acme.okta.example/app/exk1abc/sso/saml/metadata):
    Sign-in URL: https://acme.okta.example/app/acme_superbot_1/exk1abc/sso/saml
    Logout URL:  https://acme.okta.example/app/exk1abc/slo/saml
    Certificate SHA-256 3f:a1:… (CN=acme), expires 2036-05-01
```

You can set up the IdP first and fill in the two IdP settings after: until botd has the IdP's metadata, the provider isn't offered and `botctl sso saml corp` says so.

**No metadata URL?** If the IdP has no URL botd can reach, either download the metadata and set `SSO_CORP_IDP_METADATA_FILE=/etc/superbot/corp-idp.xml` (read at startup), or leave both out and import it, which botd keeps in its database and audits:

```bash
botctl sso saml corp import < idp-metadata.xml
```

With a URL, botd refreshes the metadata daily (keeping the last good copy if the IdP is down), so certificate rollovers need nothing from you. With a file or an import, add the new certificate before the IdP switches to it: metadata may list several. botd warns 30 days before any certificate ends ([below](#certificates-that-are-ending)).

## 2. Register SuperBot at your IdP

Whatever the IdP:

- **ACS URL** (reply URL, single sign-on URL) and **Recipient/Destination**: the ACS URL above.
- **Audience** (SP entity ID, identifier): the SP entity ID above.
- **NameID**: **persistent**, from an id that never changes or moves to another person: not an email, UPN or username. SuperBot links people by it.
- **Sign the assertion** with RSA-SHA256 (signing the response as well is fine). Leave it unencrypted unless you [turn encryption on](#encrypted-assertions) at both ends.
- An **email** attribute, and a display name if you like.
- Only the people who should use SuperBot assigned to the app, and **MFA required** ([below](#require-mfa-at-the-idp)).

### Okta

1. **Applications → Create App Integration → SAML 2.0**, named SuperBot.
2. **Single sign-on URL**: the ACS URL, with **Use this for Recipient URL and Destination URL** on. **Audience URI (SP Entity ID)**: the SP entity ID.
3. **Name ID format**: **Persistent**. **Application username**: **Custom**, `user.getInternalProperty("id")`: the Okta user id (`00u…`), which never changes.
4. **Show Advanced Settings**: **Response** Signed, **Assertion Signature** Signed, **Signature Algorithm** RSA-SHA256, **Assertion Encryption** Unencrypted (or Encrypted, [below](#encrypted-assertions)).
5. **Attribute Statements**: `email` → `user.email`, `displayName` → `user.displayName`.
6. **Assignments**: only the people or groups who should use SuperBot.
7. The app's tile on the Okta dashboard posts an unsolicited response, which SuperBot refuses by default: see [app tiles](#idp-initiated-sign-in-app-tiles).

On the app's **Sign On** tab, the **Metadata URL** is `SSO_CORP_IDP_METADATA_URL` and the **Issuer** (`http://www.okta.com/exk…`) is `SSO_CORP_IDP_ENTITY_ID`.

### Microsoft Entra ID

1. **Entra admin center → Enterprise applications → New application → Create your own application**, named SuperBot, **Integrate any other application you don't find in the gallery (Non-gallery)**.
2. **Single sign-on → SAML → Basic SAML Configuration**: **Identifier (Entity ID)** the SP entity ID, **Reply URL (Assertion Consumer Service URL)** the ACS URL. Set **Sign on URL** to `https://superbot.example.com/api/auth/sso/corp/start`, so the My Apps tile starts the sign-in at SuperBot ([app tiles](#idp-initiated-sign-in-app-tiles)), and leave **Relay State** empty. The **Logout Url** is the SLO URL if you want [single logout](#single-logout).
3. **Attributes & Claims → Unique User Identifier (Name ID)**: **Name identifier format** Persistent, **Source attribute** `user.objectid`. The default (`user.userprincipalname`) can change and move to someone else.
4. Keep the default claims: Entra sends the email as `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress` (from `user.mail`) and the name as `http://schemas.microsoft.com/identity/claims/displayname`, which SuperBot reads without settings.
5. **SAML Certificates**: **Signing Option** Sign SAML assertion (or Sign SAML response and assertion), **Signing Algorithm** SHA-256. Leave **Token encryption** off, unless your policy wants assertions encrypted: Entra ID encrypts with AES-CBC, which needs **Sign SAML response and assertion** and `SSO_CORP_AES_CBC=signed-response` ([below](#aes-cbc-entra-id-and-adfs)).
6. **Properties → Assignment required?** Yes, then **Users and groups**: only those who should use SuperBot.

Under **SAML Certificates**, the **App Federation Metadata Url** is `SSO_CORP_IDP_METADATA_URL`. Under **Set up SuperBot**, the **Microsoft Entra Identifier** (`https://sts.windows.net/<tenant-id>/`) is `SSO_CORP_IDP_ENTITY_ID`.

### ADFS, OneLogin, PingFederate

The same in their terms: a relying party or SAML app from SuperBot's SP metadata URL, a persistent NameID from an immutable id (for ADFS, the custom rule in [the bridge guide](saml.md#adfs)), signed assertions with SHA-256, and email and name attributes. ADFS encrypts assertions with AES-CBC: turn encryption off at the relying party, or sign the response too ([below](#aes-cbc-entra-id-and-adfs)). ADFS's entity ID is usually `http://<adfs-host>/adfs/services/trust` and its metadata is at `https://<adfs-host>/FederationMetadata/2007-06/FederationMetadata.xml`.

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

## Groups

SuperBot can read the groups the IdP puts in the signed assertion, to require a group for sign-in and to give a custom role to everyone in a group ([ADR 0160](../adr/0160-saml-groups-and-role-mapping.md)). Name the attribute the IdP sends them in; nothing is read without it:

```bash
SSO_CORP_GROUPS_ATTRIBUTE=groups                  # Okta: a group attribute statement named groups
# Entra ID: Token configuration → Add groups claim → "Groups assigned to the application", group ID:
# SSO_CORP_GROUPS_ATTRIBUTE=http://schemas.microsoft.com/ws/2008/06/identity/claims/groups
SSO_CORP_REQUIRED_GROUPS=SuperBot Users           # optional: only people in one of these sign in
```

- Names are exact, case included. Entra ID sends group object ids, so use those.
- Only the signed assertion counts. Empty values, values over 256 bytes, and values with markup inside are skipped.
- If someone is in too many groups, Entra ID sends a link instead of the groups (an overage). Over 500 values is treated the same way. Their groups are then *unknown*, which counts as no groups. Send only the groups assigned to the application to stay under the limit.

**Required groups.** With `SSO_CORP_REQUIRED_GROUPS`, someone in none of the groups is refused before their account is looked up, so just in time never makes them an account, and someone who left the group can't sign in again. The audit log has `not_in_group` or `groups_unknown`, and the page says they aren't allowed. A role a group they left gave them goes even so. Sessions they already have aren't ended: deprovision them (SCIM, or `botctl user disable`).

**Groups mapped to custom roles.** An admin maps a group to a [custom role](../adr/0123-custom-roles.md), across the server:

```bash
botctl role add "Auditor" --perms audit.view
botctl sso role map corp "SuperBot Auditors" Auditor   # or a group's object id for Entra ID
                                                       # several IdPs: add --idp <entity ID> (below)
botctl sso role-mappings                               # every mapping, and the providers that read groups
botctl sso role show <id>                              # who it gave the role to
botctl sso role unmap <id>                             # takes the role from all of them
```

- Never admin, a built-in role, or a role with `bots.manage` or `machines.manage`, which reach admins. Such a mapping is refused and audited (`sso.saml_role_map_refused`), and a mapped role can't gain those permissions or be deleted.
- Each sign-in applies the mappings. Someone in the group with no custom role gets it (the role's base becomes their built-in role). Admins, the owner account, and people with a custom role already are skipped (`sso.saml_role_skipped`). When a sign-in no longer lists the group, or the groups are unknown, the role goes and their earlier built-in role comes back.
- Only what a mapping gave is taken away. If an admin changes that person's role by hand, the change stands: no group, of any provider, gives them a role until a sign-in with the provider that gave it no longer lists its group.
- The role also goes when the mapping is removed or the person's identity at the provider is unlinked. Making a mapping gives nothing until people sign in again. To end a role at once for someone who left the group, take it away by hand or use [SCIM group roles](scim.md).
- Grants and removals are audited as `role.assigned` and `role.unassigned` with `via` = `saml`. Mapping changes are `sso.saml_role_mapped` and `sso.saml_role_unmapped`.

## IdP-initiated sign-in (app tiles)

A tile on the IdP's portal (the Okta dashboard, Microsoft My Apps, the OneLogin portal) usually posts a signed response straight to SuperBot without SuperBot asking for one. Such an *unsolicited* response isn't tied to the browser it arrives in, so accepting it as a sign-in would let anyone with an account at your IdP sign someone else's browser in as themselves (login CSRF). SuperBot never does that ([ADR 0175](../adr/0175-saml-idp-initiated-sign-in-restarted.md)). By default the tile shows "That sign-in expired". Make tiles work in one of two ways.

**At the IdP: point the tile at SuperBot's start URL.** No setting needed; the tile then does what the sign-in button does.

- **Entra ID**: **Basic SAML Configuration → Sign on URL**: `https://superbot.example.com/api/auth/sso/corp/start`.
- **Okta**: on the SAML app, **General → App Settings**, untick **Display application icon to users**. Then add a **Bookmark App** from the catalog with that URL, assigned to the same people.
- **OneLogin** and others: if the app can start the sign-in at the SP (a login URL, or "SAML initiator: Service Provider"), use that URL.

**At SuperBot: restart the sign-in.**

```bash
SSO_CORP_IDP_INITIATED=restart
```

An unsolicited response is checked as fully as any other: the IdP's signature, issuer, audience, ACS URL, time, NameID and encryption. It must answer no request (no `InResponseTo`). Then its assertion is spent, botd audits `auth.saml_idp_initiated` with the subject the IdP named, and the browser goes to the start URL. The IdP already has a session, so it answers at once, and that answer signs the person in like any other sign-in. Nothing from the tile's response is used for the session, and its `RelayState` is ignored, so people land where any sign-in lands.

If the IdP answers SuperBot's request with another unsolicited response, it ignores AuthnRequests. Restarting again would loop, so the sign-in fails with `idp_initiated_loop` in the audit log. Fix the app at the IdP so it takes SP-initiated sign-ins. `botctl sso saml corp` shows the setting.

With [several IdPs of a federation](#several-idps-of-a-federation), the setting covers each of them: a tile is checked against the IdP its `Issuer` names (if listed), and the browser goes to `/api/auth/sso/<id>/start?idp=<that IdP>`, so the restarted sign-in goes to the same IdP without the chooser ([ADR 0290](../adr/0290-saml-idp-initiated-sign-in-at-several-idps.md)). A loop is that IdP answering its own restart unsolicited; another IdP's tile soon after restarts as usual.

## All settings

`<ID>` is the provider id in capitals.

| Variable | Default | Meaning |
|----------|---------|---------|
| `SSO_<ID>_TYPE` | (required) | `saml`, without `SSO_<ID>_ISSUER`. |
| `SSO_<ID>_IDP_ENTITY_ID` | (required, or `IDP_ENTITY_IDS`) | The IdP's entity ID. Responses from any other issuer are refused, and identities are stored under it. |
| `SSO_<ID>_IDP_ENTITY_IDS` | | Instead of `IDP_ENTITY_ID`: several IdPs of a federation, comma separated (2 to 100), each fetched from `IDP_MDQ_URL` and chosen at sign-in ([below](#several-idps-of-a-federation)). |
| `SSO_<ID>_IDP_METADATA_URL` | | The IdP's metadata, https, refreshed daily. |
| `SSO_<ID>_IDP_METADATA_FILE` | | Or a metadata file, read at startup. Without either, import it with `botctl sso saml <id> import`. |
| `SSO_<ID>_IDP_MDQ_URL` | | Or a federation's MDQ server, its https base URL (InCommon: `https://mdq.incommon.org`): botd asks it for each IdP alone, daily. Needs `METADATA_SIGNING_CERT_FILE` ([below](#metadata-from-a-federation-mdq)). |
| `SSO_<ID>_SP_ENTITY_ID` | `<SSO_PUBLIC_URL>/api/auth/sso/<id>/metadata` | Our entity ID (the audience), if the IdP needs another. |
| `SSO_<ID>_EMAIL_ATTRIBUTE` | `email`, `mail`, or the emailaddress claim URI | The attribute with the email. |
| `SSO_<ID>_NAME_ATTRIBUTE` | `displayName`, `name`, or the displayname claim URI | The attribute with the display name. |
| `SSO_<ID>_ALLOWED_DOMAINS` | | Only these email domains, comma separated (exact; list subdomains on their own). |
| `SSO_<ID>_JIT_ROLE` | `off` | `readonly`, `member` or `admin`: create a user at first sign-in. Needs `ALLOWED_DOMAINS`. |
| `SSO_<ID>_LABEL` | `Company SSO` | Button text: "Sign in with …". |
| `SSO_<ID>_SIGN_REQUESTS` | `false` | `true`: sign AuthnRequests with the SP key ([below](#signed-authnrequests)). |
| `SSO_<ID>_REQUEST_BINDING` | `auto` | How AuthnRequests reach the IdP: `auto` uses HTTP-Redirect when the IdP's metadata offers it, else HTTP-POST; `redirect` or `post` uses only that one ([below](#authnrequests-over-http-post)). `post` also puts logout over HTTP-POST when the IdP offers both ([logout](#logout-over-http-post)). |
| `SSO_<ID>_RESPONSE_BINDING` | `post` | How the IdP's answer comes back: `post`, posted by the browser; `artifact`, an artifact botd resolves at the IdP over SOAP ([below](#responses-over-http-artifact)). Only that one is taken. |
| `SSO_<ID>_SP_CERT_FILE` | | Your own SP certificate (PEM), with its key as `SSO_<ID>_PRIVATE_KEY`. Without it, botd makes and keeps one. |
| `SSO_<ID>_PRIVATE_KEY` | | With `SP_CERT_FILE`: the SP's private key (PKCS #8 PEM), as env, `_FILE`, or `botctl secret set`. |
| `SSO_<ID>_ENCRYPTED_ASSERTIONS` | `off` | `allow`: take encrypted assertions as well as plain ones; `require`: only encrypted ones ([below](#encrypted-assertions)). `off` refuses them. |
| `SSO_<ID>_SP_ENCRYPTION_CERT_FILE` | | With `allow` or `require`: your own encryption certificate (PEM), another key than the signing one, with its key as `SSO_<ID>_ENCRYPTION_PRIVATE_KEY`. Without it, botd makes and keeps one. |
| `SSO_<ID>_AES_CBC` | `off` | `signed-response`: also take AES-CBC encrypted assertions (Entra ID, ADFS), only inside a response the IdP signed ([below](#aes-cbc-entra-id-and-adfs)). Needs `ENCRYPTED_ASSERTIONS`. |
| `SSO_<ID>_ENCRYPTION_PRIVATE_KEY` | | With `SP_ENCRYPTION_CERT_FILE`: its private key (PKCS #8 PEM), as env, `_FILE`, or `botctl secret set`. |
| `SSO_<ID>_METADATA_SIGNING_CERT_FILE` | | The certificates (PEM, one or more) the IdP signs its metadata with. Metadata is then checked on every load ([below](#signed-idp-metadata)). |
| `SSO_<ID>_SIGNED_METADATA` | `require` with the file, else `off` | `require`: refuse unsigned metadata; `allow`: take it unchecked (not with `IDP_MDQ_URL`). Badly signed metadata is refused either way. |
| `SSO_<ID>_GROUPS_ATTRIBUTE` | | The assertion attribute with the person's groups ([above](#groups)). No default: without it, groups aren't read. |
| `SSO_<ID>_REQUIRED_GROUPS` | | Only people in one of these groups sign in, comma separated (exact). Needs `GROUPS_ATTRIBUTE`. With `IDP_ENTITY_IDS`, each must be scoped, like `member@uni.example` ([below](#groups-with-several-idps)). |
| `SSO_<ID>_IDP_INITIATED` | `off` | `restart`: an unsolicited response from an IdP's app tile starts an SP-initiated sign-in ([above](#idp-initiated-sign-in-app-tiles)). `off` refuses it. |
| `SSO_<ID>_AUTHN_CONTEXT` | | Only people the IdP says signed in one of these ways get in, comma separated (exact): authentication context classes, or values of `AUTHN_METHODS_ATTRIBUTE` ([below](#require-mfa-at-the-idp)). |
| `SSO_<ID>_AUTHN_METHODS_ATTRIBUTE` | | The assertion attribute listing how the person signed in, whose values count for `AUTHN_CONTEXT` too (Entra ID: `http://schemas.microsoft.com/claims/authnmethodsreferences`). Needs `AUTHN_CONTEXT`. |
| `SSO_<ID>_REQUEST_AUTHN_CONTEXT` | `false` | `true`: AuthnRequests ask the IdP for the `AUTHN_CONTEXT` classes (`RequestedAuthnContext`, exact). Needs `AUTHN_CONTEXT`. |
| `SSO_<ID>_FORCE_AUTHN` | `false` | `true`: every AuthnRequest asks the IdP to sign the person in again (`ForceAuthn`), and an answer from before the request is refused ([below](#sign-in-age-and-the-idps-session-limit)). |
| `SSO_<ID>_MAX_AUTHN_AGE` | | A duration (`30m`, `12h`, `7d`; 5m to 365d): a sign-in at the IdP older than this is sent back once with `ForceAuthn`. Not with `FORCE_AUTHN`. |
| `SSO_<ID>_IDP_SESSION_LIMIT` | `on` | Sessions end at the IdP's `SessionNotOnOrAfter`, if sooner than `SESSION_MAX_AGE`. `off` ignores it. |

The bridge's settings (`CLIENT_ID`, `IDP_ALIAS`, `SCOPES`, `*_CLAIM`) are refused on a native provider, and the native ones on a bridge provider, so a provider is never half of each. There is no client secret.

## The SP key

Each native provider has a signing key and certificate of its own ([ADR 0137](../adr/0137-saml-signed-requests-and-single-logout.md)). botd makes them the first time they're needed (RSA-3072, the certificate valid for 20 years), keeps the key sealed in its database, audits `sso.saml_sp_key_created`, and publishes the certificate and the SLO URL in the SP metadata. `botctl sso saml corp` shows its SHA-256. To replace it, [roll it over](#rolling-over-superbots-keys). botd warns before a certificate of its own ends, a configured one included ([below](#certificates-that-are-ending)). To use your own, set `SSO_CORP_SP_CERT_FILE=/etc/superbot/corp-sp.pem` and the key as `SSO_CORP_PRIVATE_KEY` (`botctl secret set SSO_CORP_PRIVATE_KEY < corp-sp.key`); the provider isn't offered until the key is set and matches the certificate. botd reads it once, so restart botd after changing it. Your own key may be RSA (2048 bits or more) or ECDSA P-256 or P-384 (PKCS #8): botd then signs with `ecdsa-sha256` or `ecdsa-sha384`. Generated keys are always RSA, which every IdP takes.

If your IdP imported SuperBot's metadata before this key existed, import it again (or add the certificate and the SLO URL by hand) before turning on signed requests or single logout.

## Signed AuthnRequests

Most IdPs don't need them. If yours says it wants signed requests (`WantAuthnRequestsSigned="true"` in its metadata, which botd refuses otherwise), set `SSO_CORP_SIGN_REQUESTS=true` and restart: every AuthnRequest is then signed with RSA-SHA256 (or ECDSA, with an ECDSA key of your own) over the redirect URL, and the metadata says so. At the IdP, import SuperBot's metadata again or upload the SP certificate (Entra ID: **SAML Certificates → Verification certificates**, with **Require verification certificates** on; Okta: **Signature Certificate** under **Show Advanced Settings**).

## AuthnRequests over HTTP-POST

botd sends AuthnRequests over HTTP-Redirect (in the URL) when the IdP's metadata lists an HTTP-Redirect `SingleSignOnService`, which nearly every IdP does. For an IdP that lists only HTTP-POST (some Shibboleth, PingFederate and government IdPs), botd uses that with no setting: the browser gets a page that posts the AuthnRequest to the IdP and moves on at once. To use HTTP-POST even when the IdP offers both (say, it wants signed requests in the message itself), set `SSO_CORP_REQUEST_BINDING=post`; `redirect` refuses metadata without an HTTP-Redirect URL, as before. `botctl sso saml corp` shows the binding in use.

Over HTTP-POST, a signed AuthnRequest ([above](#signed-authnrequests)) carries its signature inside the XML (an enveloped XML signature after the Issuer, RSA-SHA256 or your ECDSA key's), with the same SP certificate. The page loads nothing, runs only its own script and sends no Referer; without script, it shows a **Continue** button. The IdP's answer comes back to the ACS as before, held to the same checks.

## Responses over HTTP-Artifact

By default the browser posts the IdP's signed response to the ACS. Some IdPs, mostly government and higher-education Shibboleth ones, can send the browser back with only an artifact, a short reference, instead. botd then fetches the response from the IdP itself over SOAP, so the assertion never passes through the browser ([ADR 0268](../adr/0268-saml-artifact-binding.md)). Set `SSO_CORP_RESPONSE_BINDING=artifact` and restart, then import SuperBot's metadata at the IdP again: its one ACS is now HTTP-Artifact, and AuthnRequests ask for it.

- **The IdP's metadata** must list a SOAP `ArtifactResolutionService` on https (http only on loopback); metadata without one is refused, and the last good metadata stays.
- **Resolving.** The artifact must be the IdP's own (its SourceID is the SHA-1 of the IdP's entity ID) and name an endpoint index its metadata lists. botd sends an `ArtifactResolve`, signed with the SP signing key, to that URL, once per artifact, over the same HTTP client as metadata (10 seconds, no redirects). The `ArtifactResponse` must answer that request, come from the IdP, be under five minutes old, and carry exactly one `Response`. Its signature is checked when there is one; TLS carries it otherwise. The `Response` inside is then held to every check a posted one is: the assertion signature is still required.
- **One binding only.** A provider set to `artifact` refuses a posted response, and one set to `post` refuses an artifact, both as `wrong_binding`. The IdP may send the artifact by redirect (`GET` on the ACS) or by a posted form.
- **Audit.** `auth.login` carries `responseBinding: "artifact"`. Refusals are `auth.login_failed` with `bad_artifact`, `wrong_artifact_source`, `no_artifact_resolution`, `artifact_unknown` (the IdP had nothing for it), `artifact_mismatch`, `soap_fault`, `artifact_unreachable` or `artifact_http_error`. The last two, the IdP being down, don't count against the browser's address.

`botctl sso saml corp` shows `Responses over: HTTP-Artifact` and the IdP's artifact resolution URLs.

## Encrypted assertions

Assertions travel through the browser over HTTPS, so most setups don't need them encrypted as well. If your policy wants it, SuperBot decrypts them ([ADR 0150](../adr/0150-saml-encrypted-assertions.md)):

1. Set `SSO_CORP_ENCRYPTED_ASSERTIONS=allow` and restart. botd makes a second key for the provider, used only for decryption (RSA-3072, sealed in its database like the signing key, audited as `sso.saml_sp_key_created` with `use` = `encryption`), and publishes its certificate in the SP metadata as `<md:KeyDescriptor use="encryption">`, with the algorithms it takes. `botctl sso saml corp` shows its SHA-256.
2. At the IdP, import SuperBot's metadata again, or upload that certificate, and turn encryption on with **AES-GCM** and **RSA-OAEP**. Okta: **Assertion Encryption** Encrypted, **Encryption Algorithm** AES256-GCM, **Key Transport Algorithm** RSA-OAEP, **Encryption Certificate** the one from the SP metadata.
3. Once sign-ins work, set `SSO_CORP_ENCRYPTED_ASSERTIONS=require` so a plain assertion is refused.

What botd takes and refuses:

- **Content**: AES-128-GCM, AES-192-GCM, AES-256-GCM. AES-CBC is refused (`weak_algorithm`) unless `AES_CBC=signed-response` ([below](#aes-cbc-entra-id-and-adfs)). Triple DES is always refused.
- **Key transport**: RSA-OAEP (`rsa-oaep-mgf1p`, or XML Encryption 1.1 `rsa-oaep` with SHA-1 to SHA-512). RSA PKCS #1 v1.5 is refused (`weak_key_transport`).
- **Keys** come only from botd, never from the message. Several `EncryptedKey`s (as during an IdP certificate rollover) are fine; the one for botd's key is used.
- **The IdP's signature still counts.** Anyone can encrypt to SuperBot's public certificate, so the assertion inside must be signed by the IdP, exactly as a plain one. A signature on the response is checked before anything is decrypted. The decrypted assertion goes through every other check: one assertion only, no assertion inside it, signatures only where they belong, IDs unique across the response and the assertion.
- **Encrypted NameIDs** (`EncryptedID`), in assertions and in the IdP's LogoutRequests, are decrypted the same way, with the same key and algorithms ([ADR 0151](../adr/0151-saml-encrypted-nameids-ecdsa-and-signed-metadata.md)). They need `ENCRYPTED_ASSERTIONS=allow` or `require`, even if the IdP encrypts only the NameID. With it `off`, they're refused (`encrypted_id`). They're read only after the IdP's signature over them is checked. Inside there must be exactly one `NameID`, and a subject with two identifiers is refused (`wrapped`).

To use your own key, set `SSO_CORP_SP_ENCRYPTION_CERT_FILE=/etc/superbot/corp-enc.pem` and `botctl secret set SSO_CORP_ENCRYPTION_PRIVATE_KEY < corp-enc.key`. It must be another key than the signing one, and RSA (IdPs encrypt to it with RSA-OAEP). The provider isn't offered until the key is set and matches. To change the keys botd made, [roll them over](#rolling-over-superbots-keys).

The audit log's `auth.login` events show which cipher each sign-in used (`details.assertionEncryption`, such as `aes256-gcm`).

### AES-CBC (Entra ID and ADFS)

Entra ID and ADFS encrypt assertions only with AES-256-CBC. CBC alone isn't authenticated: changed ciphertext still decrypts, and the errors that gives can leak the plaintext (a padding oracle). SuperBot takes it only when the IdP signs the whole response, which covers the encrypted assertion, and checks that signature before decrypting ([ADR 0218](../adr/0218-saml-aes-cbc-in-signed-responses.md)). Changed ciphertext then fails as `bad_signature` and is never decrypted.

1. Set `SSO_CORP_ENCRYPTED_ASSERTIONS=allow` and `SSO_CORP_AES_CBC=signed-response`, and restart. The SP metadata then lists AES-256-CBC and AES-128-CBC after GCM.
2. Sign the response as well as the assertion. **Entra ID**: **SAML Certificates → Signing Option** Sign SAML response and assertion. **ADFS**: `Set-AdfsRelyingPartyTrust -TargetName SuperBot -SamlResponseSignature MessageAndAssertion`.
3. Turn encryption on with SuperBot's encryption certificate. **Entra ID**: **Token encryption → Import Certificate**, then **Activate token encryption certificate**. **ADFS**: the relying party's **Encryption** tab (importing SuperBot's metadata sets it).
4. Once sign-ins work, set `SSO_CORP_ENCRYPTED_ASSERTIONS=require`.

A CBC assertion in a response that isn't signed is refused as `cbc_unsigned_response`. The assertion inside must still be signed. Encrypted NameIDs never take CBC; Entra ID and ADFS don't encrypt them on their own.

## Rolling over SuperBot's keys

The keys botd makes can be replaced without a failed sign-in, on a schedule or after a suspected leak ([ADR 0181](../adr/0181-saml-sp-key-rollover.md)). Each provider's signing and encryption keys roll over separately; replace `encryption` with `signing` below for the signing key.

1. **Make the next key.** `botctl sso saml corp key next encryption`. botd makes a new key and publishes its certificate in the SP metadata after the one in use. A next encryption key decrypts from now on, too; a next signing key doesn't sign yet. Audited as `sso.saml_sp_key_created` with `stage` = `next`.
2. **Give it to the IdP.** An IdP that reads SuperBot's metadata URL picks it up by itself. Otherwise import the metadata again or upload the new certificate (`botctl sso saml corp` shows both SHA-256s). For encryption, switch the IdP's encryption certificate to the new one; for signing, add it beside the old one.
3. **Promote it.** `botctl sso saml corp key promote encryption`. The next key becomes the one in use, and the metadata publishes only it. A replaced encryption key is kept as *previous*: no longer published, but it still decrypts, so an IdP that hasn't switched yet keeps working. A replaced signing key is dropped. Audited as `sso.saml_sp_key_promoted`.
4. **Retire the old encryption key.** Once nothing is encrypted to it, `botctl sso saml corp key retire encryption`. Audited as `sso.saml_sp_key_retired`.

`botctl sso saml corp` shows each stage under the certificate it belongs to, and for encryption keys when each last decrypted a sign-in:

```console
  SP encryption certificate: SHA-256 4b:7e:… (generated), expires 2046-11-21
    In use; last decrypted a sign-in 3m ago
    Previous: SHA-256 a0:19:…: no longer published, still decrypts until retired; last decrypted a sign-in 2d ago
```

Promote once the next key has decrypted a sign-in (the IdP has it), and retire once the previous one hasn't for as long as your IdP takes to switch. These times are kept in memory, so they start over when botd restarts. `botctl sso saml corp key cancel encryption` drops a next key you haven't promoted. One rollover at a time: botd refuses a second next key, and a promotion while a previous key is still there.

The keys of each stage are sealed in botd's database like the first one, and rotating the master key covers them. Keys from `SSO_<ID>_SP_CERT_FILE` or `SSO_<ID>_SP_ENCRYPTION_CERT_FILE` are yours, so botd refuses to roll them over. To change one, add the new certificate at the IdP first (for encryption, IdPs take only one, so do it when you change the key), then change the file and the secret together and restart botd.

## Certificates that are ending

botd warns before any certificate a provider depends on ends ([ADR 0198](../adr/0198-saml-certificate-expiry-warnings.md)). That covers its own signing and encryption certificates, the IdP's signing certificates in the metadata in use, and the trusted signers in `METADATA_SIGNING_CERT_FILE`. botd never refuses a signature because a certificate has expired: the metadata says which key to trust. But an IdP replaces its certificate when it ends, and some IdPs refuse an expired SP certificate. Either way, sign-ins stop on that day unless someone acted first. The usual case is an IdP rollover (Entra ID every three years, ADFS yearly) while botd reads the metadata from a file or an import, which nothing refreshes.

From 30 days before its end, a certificate is *expiring*; after it, *expired*. `botctl sso saml corp` lists each one with what to do, and adds the time left after its date:

```console
Acme (corp): ready
  …
  IdP entity ID:            http://www.okta.com/exk1abc
  Certificate warnings:
    IdP signing certificate SHA-256 3f:a1:… expires 2026-12-20 (in 27 days)
      Renew it at the IdP, then import its new metadata (listing both certificates) before the IdP switches: botctl sso saml corp import < metadata.xml.
  SP signing certificate:   SHA-256 9c:02:… (generated), expires 2046-11-21
  …
    Certificate SHA-256 3f:a1:… (CN=acme), expires 2026-12-20 (in 27 days)
```

A certificate is *covered* when another of the same kind isn't ending. For example, the IdP's next certificate is already in its metadata, or botd's [next key](#rolling-over-superbots-keys) is published. The warning names it (`replacement`) and says what's left to do: nothing for the IdP's, or promote botd's next key once the IdP has it.

botd checks at startup and every hour. With a metadata URL, it reads the metadata again first when its daily refresh is due, so a certificate the IdP has already replaced isn't reported. Each certificate is audited once as each notice comes due, and logged as a warning:

- `sso.saml_certificate_expiring`, when it's 30 days from its end (`daysLeft`);
- `sso.saml_certificate_expired`, once it has ended. The outcome is `failure` if nothing replaces it, and `success` if something does.

Each has the provider, `role` (`sp_signing`, `sp_encryption`, `idp_signing` or `metadata_signing`), `stage` (`current` or `next` for a key botd made), `from` (where it comes from: `generated`, `secret`, `url`, `file` or `botctl`), the `certificate`'s SHA-256, its `subject`, `notAfter` and `replacement`. Alert on them in your SIEM (`botctl audit --action sso.saml_certificate_expiring`). The view (`GET /api/sso/<id>/saml`) gives every certificate `expiry` and `daysLeft`, and lists the warnings as `certificateWarnings`.

What to do, by certificate:

| Certificate | What to do |
|-------------|------------|
| botd's, generated | [Roll it over](#rolling-over-superbots-keys): `key next`, give the IdP the new metadata, `key promote`. Generated certificates last 20 years, so this is rare. |
| botd's, from `SP_CERT_FILE` or `SP_ENCRYPTION_CERT_FILE` | Make a new key and certificate, give the IdP the new certificate first, then change the file and the secret together and restart botd. |
| The IdP's, metadata from a URL | Renew it at the IdP. botd picks up the new certificate from the metadata by itself. |
| The IdP's, from a file or an import | Renew it at the IdP, and give botd metadata that lists both certificates (a new file and a restart, or `botctl sso saml corp import`) before the IdP switches. Better: use the metadata URL. |
| A trusted metadata signer | Add the IdP's or federation's next metadata signing certificate to `METADATA_SIGNING_CERT_FILE` and restart botd before it switches, or botd refuses the metadata it signs. |

## IdP keys: RSA and ECDSA

The IdP may sign with RSA (2048 bits or more, `rsa-sha256` or `rsa-sha512`) or ECDSA P-256 (`ecdsa-sha256`) or P-384 (`ecdsa-sha384`) keys ([ADR 0151](../adr/0151-saml-encrypted-nameids-ecdsa-and-signed-metadata.md)). Each algorithm verifies only with its own key type and curve. SHA-1 (`rsa-sha1`, `ecdsa-sha1`) is refused as `weak_algorithm`. Certificates with other curves or keys are refused when the metadata is read.

## Signed IdP metadata

By default botd trusts IdP metadata because it comes over https, from a file, or from an admin. If your IdP or federation signs its metadata, botd can check that signature, so a compromised web host or proxy can't swap in another signing certificate ([ADR 0151](../adr/0151-saml-encrypted-nameids-ecdsa-and-signed-metadata.md)):

```bash
SSO_CORP_METADATA_SIGNING_CERT_FILE=/etc/superbot/corp-idp-metadata.pem
# SSO_CORP_SIGNED_METADATA=require   # the default with the file; allow takes unsigned metadata too
```

- Get the metadata signing certificate from your IdP or federation, by a channel you trust. It's often not the certificate that signs assertions. Put several in the file during a rollover.
- Every load is checked: the URL, refreshed daily; the file, at startup; and `botctl sso saml <id> import`.
- The signature must be on the `EntityDescriptor`, or on the `EntitiesDescriptor` of an aggregate. It must verify against a certificate in the file, with strong algorithms only. With `require`, unsigned metadata is refused. With `allow`, it's taken unchecked. A bad signature is refused either way.
- Signed metadata past its `validUntil` is refused, so an old copy can't be served again.
- A refused copy never replaces the one in use. From a URL, botd keeps the last good copy and tries again later. An import is refused, and the stored copy stays. A bad file stops botd from starting.
- The copy in use is never used past its `validUntil` either, not even as the last good one ([ADR 0281](../adr/0281-saml-metadata-from-mdq.md)). From a URL or MDQ, botd fetches it again; from a file or an import, sign-ins fail as `idp_metadata_expired` until you give botd a fresh signed copy. `botctl sso saml corp` shows `Valid until` under the metadata. Unsigned metadata's `validUntil` vouches for nothing, so it ends nothing.
- Refusals are audited as `sso.saml_metadata_refused` (`botctl audit --action sso.saml_metadata_refused`), with the source, the reason (`unsigned`, `bad_signature`, `wrapped`, `weak_algorithm`, `bad_algorithm`, `expired`, and for MDQ `not_one_entity`, `no_valid_until` and `valid_too_long`), and whether a good copy is still in use (`kept`). `botctl sso saml corp` shows the setting and the trusted certificates.

### Metadata from a federation (MDQ)

Universities and research institutions often sign in through a federation, such as InCommon or a national federation in eduGAIN. Their aggregates of every member's metadata are far over botd's 1 MB limit, but many run an MDQ server (the Metadata Query Protocol) that answers for one entity at a time, signed by the federation ([ADR 0281](../adr/0281-saml-metadata-from-mdq.md)). Point botd at it instead of a metadata URL:

```bash
SSO_UNI_TYPE=saml
SSO_UNI_IDP_ENTITY_ID=https://idp.university.example/idp/shibboleth
SSO_UNI_IDP_MDQ_URL=https://mdq.incommon.org
SSO_UNI_METADATA_SIGNING_CERT_FILE=/etc/superbot/inc-md-cert-mdq.pem
```

- **The signer is required.** Get the federation's MDQ signing certificate by a channel you trust and check its fingerprint against the one the federation publishes (InCommon: `https://mdq.incommon.org/certs/inc-md-cert-mdq.pem`, not the certificate of its old aggregates). Without `METADATA_SIGNING_CERT_FILE`, or with `SIGNED_METADATA=allow`, botd won't start: anyone can answer for an MDQ server, so only the signature says the answer is the IdP's.
- **What botd asks.** `GET <base>/entities/<entity ID>`, the entity ID percent-encoded (`https%3A%2F%2Fidp.university.example%2Fidp%2Fshibboleth`), when the metadata is first needed and daily after, as for a metadata URL. A 404 in the log means the server doesn't know that entity ID: check `IDP_ENTITY_ID`.
- **What it takes.** Only the IdP's own `EntityDescriptor`, signed at its root by a certificate in the file, with a `validUntil` no more than 30 days ahead (InCommon's are 14). An aggregate, an unsigned or badly signed answer, one without a `validUntil` or valid for longer is refused and audited (`source` = `mdq`), and the last good copy stays until its own `validUntil`.
- **Everything else is as with a metadata URL**: the IdP's certificate rollovers reach botd within a day, [certificate warnings](#certificates-that-are-ending) cover the federation's signer, and `botctl offline check` lists the MDQ URL among the addresses botd reaches. `botctl sso saml uni` shows `IdP metadata from mdq (<the request URL>)`.

Register SuperBot with the IdP's operators as they ask: some take SuperBot's metadata URL directly, others only through the federation's registry.

#### Several IdPs of a federation

A research platform often serves people from many institutions in one federation. One provider can take several of its IdPs, each fetched from the MDQ server on its own ([ADR 0282](../adr/0282-saml-several-idps-of-a-federation.md)). List their entity IDs in `IDP_ENTITY_IDS` instead of `IDP_ENTITY_ID`:

```bash
SSO_UNI_TYPE=saml
SSO_UNI_IDP_ENTITY_IDS=https://idp.uni-a.example/idp/shibboleth,https://login.uni-b.example/idp/shibboleth
SSO_UNI_IDP_MDQ_URL=https://mdq.incommon.org
SSO_UNI_METADATA_SIGNING_CERT_FILE=/etc/superbot/inc-md-cert-mdq.pem
```

- **People choose their institution.** The sign-in button opens a page on SuperBot listing the IdPs by the name the federation publishes for each (`mdui:DisplayName`, else the organization's name, else the entity ID). It runs no script. Each choice sends an AuthnRequest to that IdP only, and only its signed answer to that request is taken. A start URL can skip the page with `&idp=<entity ID>`; an `idp` that isn't listed fails as `unknown_idp`.
- **Each identity is the IdP's.** People are stored under the IdP that signed them in (its entity ID is the `issuer`), so the same NameID at two institutions is two people. To link someone by hand, say which IdP: `botctl user link <user> uni <NameID> --idp https://idp.uni-a.example/idp/shibboleth`.
- **Emails only from the IdP's own domains.** Any IdP in the federation could send any email, so botd takes an email only at a domain the federation's metadata lists for that IdP (its `shibmd:Scope`s, exact domains; patterns are ignored). Another email is dropped. With `ALLOWED_DOMAINS` set, where the email decides who gets in, the sign-in is refused as `email_out_of_scope` instead.
- **Logout reaches the right IdP.** Signing out goes to the IdP that signed the session in; a logout message from an IdP is checked against that IdP's metadata, and one naming an IdP that isn't listed is refused as `unknown_idp`.
- **Each IdP's metadata is its own.** It's fetched when first needed and daily after, a refusal is audited with its `entityId`, and [certificate warnings](#certificates-that-are-ending) name the IdP. `botctl sso saml uni` lists every IdP with its name, email domains and certificates, and `botctl offline check` lists each MDQ URL.
- **Groups are each IdP's.** Groups work, but with rules of their own ([below](#groups-with-several-idps)).
- **Each IdP's tiles restart at that IdP.** With `IDP_INITIATED=restart`, an IdP's portal link (Shibboleth's `/idp/profile/SAML2/Unsolicited/SSO?providerId=…`, a library or LMS link) restarts the sign-in at the IdP that signed it, skipping the chooser ([ADR 0290](../adr/0290-saml-idp-initiated-sign-in-at-several-idps.md)). The response's `Issuer` (an artifact's `SourceID`) only says which listed IdP's keys to check it with; one naming an IdP that isn't listed is refused as `unknown_idp`, and one naming another IdP than signed it fails that IdP's signature check. [Below](#idp-initiated-sign-in-app-tiles) for the rest.
- **Not with SCIM.** SCIM can't link a provider with several IdPs: link people by hand or with just in time. botd lists at most 100 IdPs. Entity IDs with a comma or a `|` can't be listed: sessions keep `<entity ID>|<NameID>`, and a `|` in the entity ID could make one IdP's person look like another's at logout.

#### Groups with several IdPs

One institution's `staff` group isn't another's, so with several IdPs botd keeps groups apart by IdP ([ADR 0287](../adr/0287-saml-groups-per-idp-of-a-federation.md)). Federations send who someone is at an institution as *scoped* values, like eduPersonScopedAffiliation (`urn:oid:1.3.6.1.4.1.5923.1.1.1.9`, values like `member@uni-a.example`):

```bash
SSO_UNI_GROUPS_ATTRIBUTE=urn:oid:1.3.6.1.4.1.5923.1.1.1.9
SSO_UNI_REQUIRED_GROUPS=member@uni-a.example,member@uni-b.example   # only members, at either
```

- **A scoped value counts only from its own IdP.** A value is scoped when a domain follows its last `@`. It's kept only if that domain is one of the signing IdP's `shibmd:Scope`s, exactly, as for emails; otherwise it's dropped, so University B can't say someone is `member@uni-a.example`. Values without a scope (`staff`, `urn:mace:…` entitlements) are the IdP's own and stay.
- **Required groups must be scoped.** Each `REQUIRED_GROUPS` entry needs a domain (`member@uni-a.example`), or botd won't start: an unscoped `staff` would let in anyone at any listed IdP with a group of that name. A refusal lists the values it dropped as `groupsOutOfScope`.
- **Each mapping names its IdP.** Map a group at one IdP with `--idp`; the same name at another IdP is another group, mapped on its own:

```bash
botctl sso role map uni staff Auditor --idp https://idp.uni-a.example/idp/shibboleth
botctl sso role map uni faculty@uni-b.example Auditor --idp https://login.uni-b.example/idp/shibboleth
```

- A sign-in at an IdP applies only that IdP's mappings, and takes back only what they gave: someone with identities at two IdPs keeps a role from A's group when they sign in at B. Unlinking takes it back once they have no identity left at A.
- A mapping for an IdP the provider no longer has (taken off `IDP_ENTITY_IDS`, or made before the provider had several IdPs) shows `active: false`, gives nothing, and what it gave goes at the person's next sign-in (`idp_not_listed`). Map the group again with the right `--idp`, and remove the old one.

## Single logout

When the IdP's metadata has an HTTP-Redirect or HTTP-POST `SingleLogoutService` on https, botd does single logout over the browser ([HTTP-POST below](#logout-over-http-post)):

- **Signing out of SuperBot** ends the SuperBot session, then takes the browser to the IdP with a signed LogoutRequest, which ends the IdP session too and comes back to the sign-in page. The phone app and `botctl` have no browser to send, so they use the [back channel](#back-channel-soap-logout) when the IdP offers one, and otherwise end their own session only.
- **Signing out at the IdP** (or the IdP ending the session) sends SuperBot a signed LogoutRequest at the SLO URL. botd revokes the SuperBot sessions that IdP session made (or all of that person's sessions from this IdP if it names none), audits `auth.slo` with the sessions revoked, and answers with a signed LogoutResponse.

At the IdP, set the **logout URL** (single logout URL, SLO endpoint) to the SLO URL `botctl` shows, HTTP-Redirect or HTTP-POST, and give it the SP certificate to check our requests (Okta: **Enable Single Logout** and upload the **Signature Certificate**; Entra ID: **Logout Url (Optional)** under **Basic SAML Configuration**). Then refresh or import the IdP's metadata so botd sees its logout URL; `botctl sso saml corp` says `Single logout: yes`.

### Logout over HTTP-POST

Some IdPs list only an HTTP-POST `SingleLogoutService` (some Shibboleth, PingFederate and government IdPs). botd uses it with no setting ([ADR 0248](../adr/0248-saml-logout-over-http-post.md)); with both bindings listed it still uses HTTP-Redirect, unless `SSO_CORP_REQUEST_BINDING=post`, which then takes HTTP-POST for logout too.

- **Signing out of SuperBot** answers with a link to a one-time page on SuperBot (`…/api/auth/sso/corp/logout?h=…`) instead of the IdP's URL. The browser opens it as it would the IdP's, and the page posts the signed LogoutRequest to the IdP, like the [AuthnRequest page](#authnrequests-over-http-post). Each link works once, for five minutes. The SuperBot session has already ended by then, whatever happens next.
- **Signing out at the IdP**: botd's signed LogoutResponse goes back to the IdP on a page that posts it, with the IdP's RelayState, whichever binding the IdP's request came by.

Messages over HTTP-POST carry their signature inside the XML, made with the same SP key. `botctl sso saml corp` says `Single logout: yes, over HTTP-POST`, and `auth.logout` and `auth.slo_response` record `post` as the binding.

### Back-channel (SOAP) logout

Some IdPs (Shibboleth, PingFederate, some ADFS setups) end sessions server to server, with no browser: the SAML SOAP binding ([ADR 0208](../adr/0208-saml-back-channel-soap-logout.md)). botd does both directions, with nothing to turn on:

- **From the IdP.** SuperBot's metadata lists a SOAP `SingleLogoutService` at the SOAP SLO URL `botctl` shows (`…/slo/soap`), after the browser ones, so IdPs that pick by order keep using the browser. The IdP POSTs a signed LogoutRequest there; botd revokes the sessions as above, audits `auth.slo` with `binding` = `soap`, and answers with a signed LogoutResponse. The request must be signed (botd sits behind a proxy, so it can't use TLS client certificates instead), and its `Destination` must be the SOAP SLO URL.
- **To the IdP.** When the IdP's metadata has a SOAP `SingleLogoutService` on https, signing out of SuperBot from the phone app or `botctl` sends it a signed LogoutRequest from botd, so the IdP session ends too. A browser uses it only if the IdP has no browser logout URL. botd doesn't wait for the answer to end the session; it audits it as `auth.slo_response` with `binding` = `soap` (and a `reason` when the IdP didn't confirm). The IdP may sign its answer or not (botd reached it over https at the address in its metadata), but a signature must be the IdP's.

Re-import SuperBot's metadata at the IdP so it sees the SOAP endpoint. Shibboleth signs back-channel logout requests only to port 443, so serve SuperBot on 443, or set Shibboleth's `signRequests` for SuperBot's relying party. `botctl sso saml corp` shows `Back-channel logout: from the IdP, and to it` once the IdP's metadata has a SOAP logout URL.

#### When an admin or SCIM ends sessions

The same back channel ends IdP sessions when SuperBot sessions end without anyone signing out ([ADR 0258](../adr/0258-saml-back-channel-logout-on-revoke-and-deprovisioning.md)): an admin revokes a session or all of someone's sessions, disables or erases them, or SCIM deactivates or deletes them. For each session the IdP vouched for that was still live, botd sends the IdP's SOAP logout URL a signed LogoutRequest naming that IdP session, once per IdP session however many SuperBot sessions it made, so a stolen browser can't just sign back in through the IdP. There is nothing to turn on, and nothing waits for the IdP: the SuperBot sessions end at once either way. Each answer is audited as `auth.slo_response` with `revokeReason` (`revoked by admin`, `user disabled`, `deprovisioned by SCIM` or `deleted by SCIM`), and the admin's or SCIM's own event (`session.revoked`, `session.revoked_all`, `user.disabled`, `scim.user_deleted`) lists the request IDs in `idpLogouts`. An IdP with no SOAP logout URL can't be told without the person's browser, so there the sessions end in SuperBot only, as before. Nor is a session whose sign-in named no IdP session (no `SessionIndex`), since that request would sign the person out of the IdP on every device.

## Require MFA at the IdP

SuperBot doesn't ask single sign-on sign-ins for its own second factor: the IdP's MFA is that factor, so require it there (Okta: an authentication policy with a possession factor on the app; Entra ID: a Conditional Access policy requiring MFA for the app). This is your control as the customer (CC6.1-2 in the [SOC 2 readiness checklist](../security/soc2-readiness-checklist.md)).

**Make SuperBot check it too.** A policy that's switched off, scoped to the wrong group, or skipped on a trusted network lets a password alone through. SuperBot can refuse any sign-in the IdP doesn't vouch was made with MFA ([ADR 0190](../adr/0190-saml-required-authn-context.md)). The signed assertion says how the person signed in, as an authentication context class and often as an attribute listing the methods used. Name what to require:

```bash
# Entra ID: its authnmethodsreferences attribute lists multipleauthn once MFA was done.
SSO_CORP_AUTHN_CONTEXT=http://schemas.microsoft.com/claims/multipleauthn
SSO_CORP_AUTHN_METHODS_ATTRIBUTE=http://schemas.microsoft.com/claims/authnmethodsreferences
```

- **Exact values**, comma separated, case included. Someone gets in if the IdP sends any of them as the `AuthnContextClassRef` of the signed assertion, or as a value of the `AUTHN_METHODS_ATTRIBUTE` attribute (only that one, and only when it's set).
- **Checked on every sign-in**, after the signature and required groups, and before the account is looked up, so just in time never makes an account for someone without MFA. A refusal is `authn_context` in the audit log. The event lists what the IdP sent (`authnContexts`, and `authnMethods` with an attribute), and the person sees that the sign-in didn't use the method SuperBot requires.
- **Every sign-in records it.** `auth.login` has `authnContext`: the value that met the requirement or, without one, the class the IdP sent. Look at a few sign-ins before you require anything, to see what your IdP sends (`botctl audit 5 --action auth.login`).
- **Sessions people already have aren't ended.** The requirement applies from their next sign-in. `botctl sso saml corp` shows the setting.

What to require, by IdP:

| IdP | Settings | Notes |
|-----|----------|-------|
| Entra ID | `AUTHN_CONTEXT=http://schemas.microsoft.com/claims/multipleauthn`, `AUTHN_METHODS_ATTRIBUTE=http://schemas.microsoft.com/claims/authnmethodsreferences` | Entra ID sends the attribute in its responses. Don't set `REQUEST_AUTHN_CONTEXT`: Entra ID refuses the sign-in (AADSTS75011) when the person's session used another method. MFA itself comes from your Conditional Access policy. |
| ADFS | `AUTHN_CONTEXT=http://schemas.microsoft.com/claims/multipleauthn`, `REQUEST_AUTHN_CONTEXT=true` | Asking makes ADFS run its additional authentication, and it returns that class. Without asking, an additional authentication rule on the relying party must require MFA, and its claim rules must pass the `authnmethodsreferences` claim through (then set `AUTHN_METHODS_ATTRIBUTE` as for Entra ID). |
| Okta | `AUTHN_CONTEXT=mfa`, `AUTHN_METHODS_ATTRIBUTE=amr` | Okta's class is fixed by the app's settings, whatever the person did, so don't require a class. On the app, add an attribute statement named `amr` with the value `session.amr`. Okta then lists `pwd`, `mfa`, `swk` and so on. |
| Shibboleth, research federations | `AUTHN_CONTEXT=https://refeds.org/profile/mfa`, `REQUEST_AUTHN_CONTEXT=true` | The REFEDS MFA profile. |
| Keycloak, others | The class or method your IdP documents for MFA | Check what it sends in `auth.login` first. |

`REQUEST_AUTHN_CONTEXT=true` puts the listed values in every AuthnRequest, in order, as `RequestedAuthnContext` with `exact` comparison (with signed requests, inside what's signed). List only classes then, since an IdP may refuse a request for a value it doesn't know. An IdP that can't sign the person in that way answers `NoAuthnContext`: the audit log has `idp_error` with that `idpStatus`, and the person sees the same message. Asking doesn't replace the check: every response is held to the list either way.

App tiles ([above](#idp-initiated-sign-in-app-tiles)) aren't held to it, because their response never signs anyone in. The sign-in they restart is.

If the values are wrong, nobody gets in with this provider. Break-glass and one-time codes still work. Fix the setting from what the audit log says the IdP sent.

## Sign-in age and the IdP's session limit

The signed assertion says when the IdP signed the person in (`AuthnInstant`) and, from some IdPs, when its own session for them ends (`SessionNotOnOrAfter`). SuperBot uses both ([ADR 0225](../adr/0225-saml-session-lifetime-and-reauthentication.md)):

- **Sessions end with the IdP's.** A SuperBot session (web or app) from an assertion with `SessionNotOnOrAfter` ends then, or at `SESSION_MAX_AGE` if that's sooner. When it ends, the person signs in again through the IdP. This is on by default; `SSO_CORP_IDP_SESSION_LIMIT=off` ignores the IdP's limit.
- **An ended IdP session gets a new sign-in.** If the IdP's limit has already passed (or is under two minutes away), SuperBot sends the browser back to the IdP once, asking it to sign the person in again (`ForceAuthn`), instead of making a session that is already over.
- **Require a recent sign-in.** `SSO_CORP_MAX_AUTHN_AGE=12h` sends anyone whose IdP sign-in is older than 12 hours back to the IdP once, with `ForceAuthn`. `SSO_CORP_FORCE_AUTHN=true` asks for a new sign-in every time instead. Set one, not both.

```bash
# Sign in at the IdP at least once a working day to use SuperBot.
SSO_CORP_MAX_AUTHN_AGE=12h
```

- **One retry, then a clear refusal.** The IdP's answer to a `ForceAuthn` request must show a sign-in after that request (within two minutes of clock difference). If it answers from its old session again, the sign-in is refused: `stale_authn` (or `idp_session_ended`) in the audit log, and the person sees that their organization's sign-in was too long ago. An assertion without `AuthnInstant` can't show it's recent, so it's refused when a recent sign-in is required.
- **Checked last**, after the signature, required groups and MFA, and before the account is looked up, so just in time never makes an account from a stale sign-in. The sign-in asked again is audited as `auth.saml_reauthn` (`reason`, `authnInstant`, `authnSince`, `idpSessionEnds`). Every `auth.login` records `authnInstant`, `idpSessionEnds` when the IdP set one, and `forceAuthn` when SuperBot asked.
- **Several statements.** With more than one `AuthnStatement`, the latest `AuthnInstant` and the earliest `SessionNotOnOrAfter` count. Values outside the signed assertion are never read.
- **App tiles** ([above](#idp-initiated-sign-in-app-tiles)) aren't held to it, because their response never signs anyone in. The sign-in they restart is.
- **Sessions people already have aren't changed.** The settings apply from their next sign-in. `botctl sso saml corp` shows them.

Most IdPs honour `ForceAuthn` (Okta: the app's **Honor Force Authentication** setting must stay on). Some sign people in again silently, with Kerberos or a passkey, which is still a new sign-in. An IdP that ignores it fails with `stale_authn` every time: fix the app at the IdP, or set a longer `MAX_AUTHN_AGE`.

## Troubleshooting

Every refused sign-in is in the audit log with a reason (`botctl audit --action auth.login_failed`, `idp` = `saml`; `idpInitiated` is true for posts from an app tile). Failures nobody vouched for, such as bad signatures, are logged at most once a minute per address, with a count of those skipped. People see a short message on the sign-in page.

| Reason | Fix |
|--------|-----|
| `not_linked` | Link the person, or turn on just in time. The event has the `subject` and the IdP's entity ID as `issuer`. |
| `unsigned` | The IdP signs only the response, or nothing: sign the assertion. |
| `bad_signature` | The IdP signed with a certificate botd doesn't have: refresh or import the metadata (`botctl sso saml <id>` shows the certificates in use). Often its certificate rolled over: look for `sso.saml_certificate_expiring` ([above](#certificates-that-are-ending)). |
| `weak_algorithm`, `bad_algorithm` | Use RSA-SHA256 or ECDSA with SHA-256/384 (SHA-1 is refused), and AES-GCM if you encrypt. AES-CBC (Entra ID, ADFS) needs `AES_CBC=signed-response` ([above](#aes-cbc-entra-id-and-adfs)). |
| `encrypted_assertion` | The IdP encrypts but `SSO_<ID>_ENCRYPTED_ASSERTIONS` is `off`: turn it on ([above](#encrypted-assertions)), or turn off encryption at the IdP. |
| `unencrypted_assertion` | `ENCRYPTED_ASSERTIONS=require`, but the IdP sent a plain assertion: turn on encryption at the IdP. |
| `bad_encryption` | botd couldn't decrypt: the IdP encrypts to another certificate (import SuperBot's metadata again; after a [key rollover](#rolling-over-superbots-keys), it may still use a retired key), or the encrypted data is malformed. |
| `weak_key_transport` | The IdP wraps the key with RSA PKCS #1 v1.5: choose RSA-OAEP. (AES-CBC content shows as `weak_algorithm`.) |
| `cbc_unsigned_response` | An AES-CBC assertion in a response the IdP didn't sign: sign the response too (Entra ID: Sign SAML response and assertion; ADFS: `MessageAndAssertion`). |
| `encrypted_id` | The IdP encrypts the NameID but `SSO_<ID>_ENCRYPTED_ASSERTIONS` is `off`: set it to `allow`, and give the IdP SuperBot's encryption certificate. |
| `no_sp_key` | botd has no decryption key: with `SP_ENCRYPTION_CERT_FILE`, set `SSO_<ID>_ENCRYPTION_PRIVATE_KEY` (`botctl sso saml <id>` shows the problem). |
| `wrapped` | The response is shaped to fool signature checks, or the subject names the person twice (say, a `NameID` and an `EncryptedID`). |
| `wrong_audience` | The IdP's audience (entity ID) isn't the SP entity ID botctl shows. |
| `wrong_recipient`, `wrong_destination` | The IdP's ACS (reply) URL isn't the one botctl shows, often because `SSO_PUBLIC_URL` differs from the address people use. |
| `wrong_issuer` | `SSO_<ID>_IDP_ENTITY_ID` isn't the IdP's entity ID. |
| `in_response_to_mismatch`, `unknown_state` | Not an answer to a sign-in this browser started. Either it came from the IdP's app tile (see [app tiles](#idp-initiated-sign-in-app-tiles)), or the sign-in took over 10 minutes. |
| `idp_initiated_loop` | With `IDP_INITIATED=restart`, the IdP answered SuperBot's request with another unsolicited response: it ignores AuthnRequests. Fix the app at the IdP, or point the tile at the start URL. |
| `expired`, `not_yet_valid` | Clocks differ by more than two minutes: fix NTP. |
| `replayed` | The same assertion was posted twice. |
| `transient_subject`, `missing_subject` | Use a persistent NameID. |
| `email_unverified`, `wrong_domain` | No email attribute was sent, or it isn't in `ALLOWED_DOMAINS`. Set `SSO_<ID>_EMAIL_ATTRIBUTE` if the IdP uses another name. |
| `email_out_of_scope` | With [several IdPs](#several-idps-of-a-federation) and `ALLOWED_DOMAINS`: the IdP sent an email at a domain the federation doesn't list for it (`botctl sso saml <id>` shows each IdP's email domains). Its operators must add the scope in the federation's registry. |
| `unknown_idp` | With several IdPs: the start URL's `idp`, or an app tile's `Issuer` (`idpInitiated: true`; an artifact's `SourceID`), isn't one of `IDP_ENTITY_IDS` (`entityId` says what it was, when it could be read). |
| `idp_metadata_expired` | The IdP's signed metadata in use has passed its `validUntil`, and no fresh copy loaded. From a file or an import, give botd a fresh signed copy; from a URL or MDQ, look for `sso.saml_metadata_refused` or an unreachable server in the log ([above](#signed-idp-metadata)). |
| `idp_error` | The IdP said no (`idpStatus` has its status code), for example someone not assigned to the app. `Responder/NoAuthnContext`: it couldn't sign them in the way `REQUEST_AUTHN_CONTEXT` asked for ([above](#require-mfa-at-the-idp)). |
| `authn_context` | `SSO_<ID>_AUTHN_CONTEXT` is set and the IdP didn't vouch for any of its values. `authnContexts` and `authnMethods` say what it sent: password only (fix the IdP's MFA policy for the app), or another value for MFA (add it). Check `AUTHN_METHODS_ATTRIBUTE` names the attribute the IdP sends. |
| `stale_authn` | `FORCE_AUTHN` or `MAX_AUTHN_AGE` is set, and the IdP's answer to SuperBot's `ForceAuthn` request was from an older sign-in. `authnInstant` and `authnSince` say how old. The IdP ignores `ForceAuthn`: fix the app at the IdP ([above](#sign-in-age-and-the-idps-session-limit)). |
| `idp_session_ended` | The IdP's `SessionNotOnOrAfter` had passed, and its answer to SuperBot's `ForceAuthn` request was in the same ended session. `idpSessionEnds` says when. Fix the IdP's session lifetime, or set `IDP_SESSION_LIMIT=off`. |
| `user_disabled` | The person is disabled in SuperBot. |
| `not_in_group` | `SSO_<ID>_REQUIRED_GROUPS` is set and the assertion lists none of them. Check the name or id (exact, case included) and that the IdP sends the attribute `GROUPS_ATTRIBUTE` names. |
| `groups_unknown` | The IdP couldn't list the groups: `groups` = `overage` (Entra ID: send only groups assigned to the application) or `too_many` (over 500). |

Refused logout messages are audited as `auth.slo_failed` (`botctl audit --action auth.slo_failed`, `binding` = `soap` for the back channel), and the browser sees a short error; the back channel gets a SOAP fault with the reason. Those before the signature check (including `not_ready`, `no_slo` and `must_understand`) are throttled the same way.

| Reason | Fix |
|--------|-----|
| `unsigned`, `bad_signature` | The IdP must sign logout messages with a certificate in its metadata: refresh or import it. |
| `wrong_issuer` | The message came from another entity than `SSO_<ID>_IDP_ENTITY_ID`. |
| `unknown_idp` | With several IdPs: the message's `Issuer` isn't one of `IDP_ENTITY_IDS`. |
| `wrong_destination` | The IdP's logout URL for SuperBot isn't the SLO URL botctl shows (the SOAP SLO URL for the back channel), or it sends no `Destination`. |
| `must_understand` | The IdP's SOAP envelope has a header botd must understand to answer: send none. |
| `expired`, `not_yet_valid` | The message is older than five minutes, or clocks differ by more than two: fix NTP. |
| `replayed` | The same message arrived twice. |
| `unknown_request` | A LogoutResponse to a request botd didn't send, or sent over 10 minutes ago. |
| `encrypted_id` | The IdP encrypts the NameID: set `SSO_<ID>_ENCRYPTED_ASSERTIONS=allow` ([above](#encrypted-assertions)). |
| `bad_encryption` | The NameID is encrypted to another certificate: give the IdP SuperBot's encryption certificate. |
| `no_slo` | The IdP's metadata in use has no HTTP-Redirect `SingleLogoutService` on https. |
| `bad_message` | Not a SAML logout message botd can read (over SOAP: not a SOAP 1.1 envelope with one LogoutRequest in its body). |

When botd's own back-channel request fails, `auth.slo_response` is a failure with a `reason`: `unreachable` (botd couldn't reach the IdP's SOAP logout URL), `http_error` (`detail` has the HTTP status), `soap_fault` (the IdP refused it), or one of the reasons above for its answer. An IdP that answers but couldn't end every session is a failure with its SAML `status` instead (say, `Success/PartialLogout`: some of the person's other sessions at the IdP are still open). The SuperBot session is ended either way; end the IdP session there if you need to.
