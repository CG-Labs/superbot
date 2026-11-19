# 0016: Several SSO providers: Google, generic OIDC, and account linking

## Status

Accepted. Third slice of M2 ([roadmap](../ROADMAP.md#m2--multi-user--sso)): Google sign-in ([#18](https://github.com/CG-Labs/superbot/issues/18)) and the generic OIDC connector ([#19](https://github.com/CG-Labs/superbot/issues/19); its SAML bridge is still to come). Extends [ADR 0014](0014-oidc-sso-entra.md), whose flow, token checks, secrets, and audit events are unchanged.

## Context

ADR 0014 built one OIDC layer and shipped Entra on it, with a bare `oidc` type for everyone else. Teams use Google Workspace, Okta, Keycloak, and Auth0 as much as Entra, and some use more than one (staff on Entra, contractors on Google). Each IdP has its own rule for who a token names and which of its claims can be trusted. We need those rules to be explicit and tested, without forking the flow per IdP.

## Decision

### Providers are a list, each with a type

`SSO_PROVIDERS=entra,google,okta` turns on several at once. Each id gets its own `SSO_<ID>_*` settings, client secret, redirect URI (`/api/auth/sso/<id>/callback`), button (in `SSO_PROVIDERS` order, on `web/login.html` and the client's login screen), and audit `provider`. Three types:

| Type | Default for id | Issuer | Subject | Who gets in |
|------|----------------|--------|---------|-------------|
| `entra` | `entra` | `{authority}/{tid}/v2.0`, tenant-checked (ADR 0014) | `oid` | Your tenant, or an allow-list |
| `google` | `google` | `https://accounts.google.com` | `sub` | With `HOSTED_DOMAINS`, only those Workspace domains |
| `oidc` | (none: set `TYPE`) | `SSO_<ID>_ISSUER`, via discovery | `SUBJECT_CLAIM` (`sub`) | With `ALLOWED_DOMAINS`, only verified emails there |

Configuration stays env only (ADR 0014's reasons). Startup refuses unsafe or unclear settings, now including a setting meant for another type (`SSO_GOOGLE_ALLOWED_DOMAINS`, `SSO_OKTA_TENANT`, …): ignoring it would look like a restriction that isn't there. The startup log says, per provider, who may sign in.

### Google

A preset of the generic flow, not a separate one. The differences are claim rules from [Google's ID token reference](https://developers.google.com/identity/openid-connect/reference):

- **Issuer**: tokens (and discovery) may say `https://accounts.google.com` or the legacy `accounts.google.com`. Both forms come from the configured issuer, never from what discovery returned, and identities are stored under the configured one, so a `botctl user link` and a sign-in name the same identity.
- **Subject is `sub`**, which Google never changes or reuses. Email is not: an account can change it.
- **A verified email is required** (`email_verified: true`), and the `email` scope must be configured. Google sends unverified ones only for unusual accounts, and refusing them costs nobody real.
- **Workspace domains are checked on `hd`, server-side.** `hd` is in Google's signed token only for Workspace and Cloud Identity accounts; the email's domain proves nothing, because anyone can make a personal Google account for any address. `SSO_GOOGLE_HOSTED_DOMAINS` lists the allowed domains, exactly (subdomains separately). The `hd` authorization parameter is sent too (`hd=domain`, or `hd=*` for several), but only to narrow Google's account picker; Google says not to rely on it and we don't. The check runs on every sign-in, so an account that left the Workspace, or is linked but now in another domain, is refused.
- **Just in time needs a domain list.** Without one, `JIT_ROLE` would make a user for every Google account on earth, so startup refuses it, like Entra's `common` without an allow-list. Personal accounts can still sign in once an admin links them.
- `prompt=select_account`, as for Entra, so a shared browser doesn't sign in as whoever was last.

### Generic OIDC

For Okta, Keycloak, Auth0, and the rest, only configuration:

- **Issuer**: `SSO_<ID>_ISSUER`; discovery's `issuer` must match it (a trailing-slash difference is forgiven, as it is a common typo and Auth0's issuer has one), and the token's `iss` must equal discovery's exactly. Identities are stored under the configured issuer.
- **Claim mapping**: `SUBJECT_CLAIM` (default `sub`), `EMAIL_CLAIM` (`email`), `NAME_CLAIM` (`name`). The subject must be a claim that never changes for a person, so `email`, `preferred_username`, `upn`, `name` and similar are refused at startup.
- **Email** counts only when `email_verified` is true. Some IdPs send it as the string `"true"`, which we accept; anything else, including no flag, means unverified.
- **`ALLOWED_DOMAINS`**: only people whose verified email is in one of these domains get in, linked or not. This is weaker than Google's `hd` (it trusts the IdP to verify emails), so it is not offered for Google; it is the right tool for IdPs that are your organization's own directory.
- Client authentication follows discovery: client secret in the form, or HTTP Basic when that is all the IdP supports (Okta's default). RS256 only, as before.

### Account linking

- **The key is `(issuer, subject)`; email never links.** No provider's email finds or merges a user, verified or not ("nOAuth"). This keeps the rule from ADR 0014 for every IdP, rather than trusting email for the IdPs where it is safer: the exceptions would be per IdP, per configuration, and easy to get wrong, and linking is a one-time admin step.
- **One user, many identities.** An admin links each identity (`botctl user link <user> <provider> <subject>`, or the API) to the same user; a person on Entra at work and Google at home is one SuperBot user with one role. Linking is admin only and audited. The subject for Google and generic IdPs is easiest to get from the `not_linked` audit event, which records it when someone tries.
- **Just in time makes a new user, never joins one.** If the email it would use belongs to someone else, sign-in is refused (`sso_email_taken`) and an admin links the identity instead. So turning on JIT for a second provider doesn't let it take over accounts made by the first.
- **Restrictions apply to linked identities too.** Tenant, Workspace domain, and email domain checks run on every sign-in, before the identity is looked up.

### Errors

A real account the server doesn't take (`wrong_domain`, `email_unverified`) comes back as the new page code `sso_wrong_account`, so people know to try another account rather than retry. Entra's errors are unchanged.

## Consequences

- Teams can offer Microsoft, Google, and their own IdP at once; adding one is a few lines of `.env`.
- Admins have to fetch a `sub` to link Google and generic identities. The audit log makes that one step; a linking UI is still to come.
- An IdP that signs ID tokens with something other than RS256 (some Keycloak realms set ES256) needs its setting changed. Adding ES256 is small if it comes up.
- With none of the new settings, nothing changes: `SSO_PROVIDERS` empty is still off, and the installer's and Compose's `.env.example` files are tested to stay that way.

## Not in this slice

- SAML bridge (rest of #19). (Apple and GitHub sign-in came next, in [ADR 0018](0018-sso-github-apple.md).)
- Group or role claims to SuperBot roles; mapping `hd` or email domain to a role.
- Desktop (Electron) SSO, IdP logout, and a linking UI (as in ADR 0014).
