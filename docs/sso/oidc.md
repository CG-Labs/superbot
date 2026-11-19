# Sign in with any OpenID Connect provider (Okta, Keycloak, Auth0, …)

Lets people sign in with your company's identity provider, set up purely in `.env`. Works with any IdP that does the OpenID Connect authorization code flow with PKCE and signs ID tokens with RS256: Okta, Keycloak, Auth0, Authentik, Zitadel, OneLogin, JumpCloud, and others. Design: [ADR 0014](../adr/0014-oidc-sso-entra.md) and [ADR 0015](../adr/0015-sso-multi-provider.md). For Microsoft and Google use their own guides ([Entra](entra.md), [Google](google.md)): they need checks a generic provider doesn't do.

You need: admin rights in the IdP, and SuperBot on HTTPS at a fixed address, like `https://superbot.example.com`. Each provider has an id you choose (lowercase letters and digits), like `okta`; it names its settings (`SSO_OKTA_*`) and its redirect URI.

## 1. Register SuperBot at the IdP

Make a **confidential web application** (one with a client secret) that uses the **authorization code** flow, with:

- **Redirect URI**: `https://superbot.example.com/api/auth/sso/<id>/callback`, exactly (no trailing slash).
- **Scopes**: `openid profile email`.
- **ID token signing**: RS256 (the usual default).
- **PKCE**: allowed or required, with S256. SuperBot always sends it.

Then note the **issuer URL**, the **client id**, and the **client secret**. The issuer is the address whose `/.well-known/openid-configuration` is the discovery document; it must be exactly the `issuer` in that document.

| IdP | Where | Issuer |
|-----|-------|--------|
| Okta | **Applications → Create App Integration → OIDC, Web Application**; grant type Authorization Code; sign-in redirect URI as above | `https://<org>.okta.com/oauth2/default` (custom authorization server) or `https://<org>.okta.com` (org server) |
| Keycloak | Realm → **Clients → Create client**, OpenID Connect; **Client authentication** on, **Standard flow** only; **Valid redirect URIs** as above; **Advanced → Proof Key for Code Exchange**: S256 | `https://<host>/realms/<realm>` |
| Auth0 | **Applications → Create Application → Regular Web Application**; **Allowed Callback URLs** as above | `https://<tenant>.auth0.com/` (with the trailing slash) |
| Authentik | **Applications → Providers → OAuth2/OpenID**, client type Confidential | `https://<host>/application/o/<slug>/` |

## 2. Configure SuperBot

In `.env` (installer: `/home/superbot/superbot/.env`; Docker: `deploy/docker/.env`):

```bash
SSO_PROVIDERS=okta                       # several: entra,google,okta
SSO_PUBLIC_URL=https://superbot.example.com
SSO_OKTA_TYPE=oidc
SSO_OKTA_ISSUER=https://acme.okta.com/oauth2/default
SSO_OKTA_CLIENT_ID=<client-id>
SSO_OKTA_LABEL=Okta                      # the button says "Sign in with Okta"
```

The client secret, in one of three ways (botd reads it when used, so rotating needs no restart):

```bash
botctl secret set SSO_OKTA_CLIENT_SECRET < okta-secret.txt && rm okta-secret.txt   # recommended
SSO_OKTA_CLIENT_SECRET_FILE=/etc/superbot/okta-secret
SSO_OKTA_CLIENT_SECRET=<value>
```

Restart botd. The log says `SSO: okta (Okta, oidc), ready; anyone the IdP signs in; …`. botd fetches the discovery document on the first sign-in, and uses HTTP Basic for the client secret when the IdP only supports that.

### All settings

`<ID>` is the provider id in capitals.

| Variable | Default | Meaning |
|----------|---------|---------|
| `SSO_<ID>_TYPE` | (required) | `oidc`. |
| `SSO_<ID>_ISSUER` | (required) | The issuer URL, https. A trailing slash in the setting is forgiven, but tokens must carry the issuer exactly as discovery names it. |
| `SSO_<ID>_CLIENT_ID` | (required) | The client id. |
| `SSO_<ID>_CLIENT_SECRET` | (required) | As above; env, `_FILE`, or `botctl secret set`. |
| `SSO_<ID>_LABEL` | the id | Button text: "Sign in with …". |
| `SSO_<ID>_SCOPES` | `openid profile email` | Must include `openid`. |
| `SSO_<ID>_ALLOWED_DOMAINS` | | Only people whose **verified** email is in one of these domains get in, comma separated (exact; list subdomains on their own). Everyone else is refused, linked or not. |
| `SSO_<ID>_SUBJECT_CLAIM` | `sub` | The claim that says who someone is. It must never change for a person: `email`, `preferred_username`, `upn`, `name`, and similar are refused. |
| `SSO_<ID>_EMAIL_CLAIM` | `email` | The claim with the email. It counts only when `email_verified` is `true` (a boolean, or the string `"true"`). |
| `SSO_<ID>_NAME_CLAIM` | `name` | The claim with the display name. |
| `SSO_<ID>_JIT_ROLE` | `off` | `readonly`, `member`, or `admin`: create a user the first time someone signs in. |

`SSO_PUBLIC_URL` and `SSO_APP_REDIRECTS` are shared by all providers; see [the Entra guide](entra.md#all-settings). Entra or Google settings (`TENANT`, `HOSTED_DOMAINS`, …) on an `oidc` provider are refused, so nothing looks like a restriction that isn't there.

Several generic providers can run at once, each with its own id, settings, and button: `SSO_PROVIDERS=okta,keycloak`.

## 3. Let people in

**Link people (default).** SuperBot never matches an IdP account to a user by email. Find the person's subject (Okta: the user's id, `00u…`; Keycloak: the user's **ID** on their page; Auth0: the `user_id`, like `auth0|…`), or let them try once and read it from the audit log, then link it:

```bash
botctl audit 5 --action auth.login_failed          # details.subject on the not_linked event
botctl user link ada@example.com okta <subject>
```

**Or just in time.** With `SSO_OKTA_JIT_ROLE=member`, anyone the IdP signs in to this app becomes a member. Limit who that is at the IdP (Okta: assign the app to groups; Keycloak: a realm just for your team, or a client role check; Auth0: only enable your company connection) and, to be sure, with `SSO_OKTA_ALLOWED_DOMAINS`. An IdP that lets anyone sign up (Auth0 with a database or social connection, for example) plus just in time means anyone can get in: don't combine them without `ALLOWED_DOMAINS`. If someone's email already belongs to another SuperBot user, sign-in is refused until an admin links them.

## Troubleshooting

Each failed sign-in is in the audit log with a reason (`botctl audit --action auth.login_failed`):

| Reason | Fix |
|--------|-----|
| `not_linked` | Link the person, or turn on just in time. The event has the `subject`. |
| `wrong_issuer` | `SSO_<ID>_ISSUER` isn't the discovery document's `issuer`, or tokens carry another one. |
| `missing_subject` | The token has no `SSO_<ID>_SUBJECT_CLAIM` claim. Check the mapping and the scopes. |
| `wrong_domain` | The verified email isn't in `SSO_<ID>_ALLOWED_DOMAINS`. People see "That account can't sign in here". |
| `email_unverified` | `ALLOWED_DOMAINS` is set but the token has no verified email (no `email` scope, a different `EMAIL_CLAIM`, or `email_verified` false). |
| `bad_algorithm` | The IdP signs ID tokens with something other than RS256. Switch the client (or realm) to RS256. |
| `code_exchange_failed` | Usually the client secret, a redirect URI mismatch, or PKCE disabled at the IdP. |
| `wrong_audience` | `SSO_<ID>_CLIENT_ID` isn't this client's id. |
| `idp_unreachable`, `idp_bad_response` | botd can't fetch discovery or keys. It must reach the issuer over https; responses over 1 MB or redirects are refused. |
