# 0017: Sign in with GitHub and Sign in with Apple

## Status

Accepted. Fourth slice of M2 ([roadmap](../ROADMAP.md#m2--multi-user--sso)): Sign in with Apple ([#15](https://github.com/CG-Labs/superbot/issues/15)) and GitHub sign-in ([#16](https://github.com/CG-Labs/superbot/issues/16)). Extends [ADR 0014](0014-oidc-sso-entra.md) and [ADR 0016](0016-sso-multi-provider.md): the flow, binder cookie, handoff to the app, account linking, and audit events are unchanged. Setup guides: [GitHub](../sso/github.md), [Apple](../sso/apple.md).

## Context

The two remaining consumer IdPs on the roadmap each break an assumption of the OIDC layer:

- **GitHub isn't OIDC for people.** Its OAuth apps return an access token, no ID token, no discovery, no JWKS. Who signed in comes from its REST API. Its emails can be unverified or secondary, and its username can change hands.
- **Apple has no client secret to store.** The client secret is a JWT the client signs with an ES256 key from Apple, at most six months valid. Apple also returns with a cross-site form `POST` (`response_mode=form_post`, required when asking for name or email) and sends the person's name only once, in that post, outside the signed token.

We want both in the same per-provider model (`SSO_PROVIDERS`, `SSO_<ID>_*`, one button each), with their rules explicit and tested, without forking the flow or trusting anything the IdP's signature doesn't cover.

## Decision

### Two new types

| Type | Default for id | Identity stored as (issuer, subject) | Who gets in |
|------|----------------|--------------------------------------|-------------|
| `github` | `github` | (`SSO_<ID>_URL`, default `https://github.com`; the numeric user id) | With `ALLOWED_ORGS`, only active members of those orgs |
| `apple` | `apple` | (`https://appleid.apple.com`, `sub`) | With `ALLOWED_DOMAINS`, only verified emails there |

Both run through the same `start` and `callback` as the OIDC types: `state`, PKCE (S256), the binder cookie, the five-minute pending entry, one-time handoff codes for the apps, and the same `not_linked` / just-in-time / `email_taken` rules. Startup still refuses settings meant for another type (`SSO_GITHUB_ALLOWED_DOMAINS`, `SSO_APPLE_TENANT`, …) and just in time without a restriction.

### GitHub: OAuth, then the API, server-side

A separate sign-in path for the `github` type only; everything around it is shared.

- **Authorization**: `{URL}/login/oauth/authorize` with `state`, PKCE (GitHub supports S256), `prompt=select_account`, and `allow_signup=false`. No `nonce`: there is no token to bind it to; `state` plus PKCE plus the binder cookie cover the same replay and CSRF cases.
- **Code exchange** at `{URL}/login/oauth/access_token` with the client secret and the PKCE verifier. GitHub reports errors as `200` with an `error` field; those are failures.
- **Who**: `GET {API}/user`. The subject is the numeric `id`, checked to be digits. Never the `login`: logins are renamed and reused, which would hand an identity to a stranger. The login is kept only for display and the audit log (`username`).
- **Email**: `GET {API}/user/emails`; only the **primary** address and only if **verified**, or sign-in is refused (`email_unverified`). Like every provider, the email never links or merges users.
- **Orgs** (`ALLOWED_ORGS`): `GET {API}/user/memberships/orgs/{org}` with the person's token must say `state: active` for at least one listed org. Pending invites, non-members, and orgs that hide membership from the app (OAuth app restrictions) are refused (`wrong_org`, shown as `sso_wrong_account`); any other answer fails closed. Checked on every sign-in, before the identity is looked up, so it applies to linked identities too. Just in time requires it.
- **The token** is used for those calls only, then revoked in the background (`DELETE {API}/applications/{client_id}/token`). It is never stored or logged.
- **Scopes** default to `read:user user:email`, plus `read:org` with an org list; startup refuses scopes that can't do the checks.
- **GitHub Enterprise Server**: `SSO_<ID>_URL` (and `API_URL`, default `{URL}/api/v3`). The issuer is that URL, so github.com and an Enterprise server are separate namespaces of ids.

We chose an OAuth app over a GitHub App: it needs no installation per org, and its scopes say exactly what we read. A GitHub App would add install and permission steps for the same three calls.

### Apple: OIDC with a signed client secret

Apple is an OIDC preset like Google: discovery, Apple's JWKS, RS256 ID tokens, `iss` = `https://appleid.apple.com`, `aud` = the Services ID, `nonce`, expiry, and `sub` as the subject.

- **The client secret is minted per code exchange.** botd signs `{iss: team id, sub: Services ID, aud: issuer, iat, exp: iat + 5 min}` with ES256, header `kid` = the key id. Apple allows six months; five minutes means a leaked secret (in a proxy log, say) is useless almost at once, and there is no cached secret to expire or rotate. Signing uses the same `aws-lc-rs` crate as token verification.
- **The key is the only secret.** `SSO_<ID>_PRIVATE_KEY` (the `.p8`), set like other provider secrets: env, `_FILE`, or (recommended) the encrypted secrets store via `botctl secret set`. It is never written to SQLite in plain text, never passed to Bots, and redacted from logs. It is read for each sign-in, so a new key takes effect without restart (its key id is in env). The team id and key id are not secret and are checked at startup. A key that doesn't parse keeps the button hidden and says so in the startup log.
- **`form_post` without loosening cookies.** Apple's `POST` to the callback is cross-site, so the `SameSite=Lax` binder cookie isn't sent with it. Rather than relax the cookie to `None`, the `POST` handler only reads the form, stashes the posted name in the pending entry for that `state`, and answers `303` to the same callback as a `GET` with `code`, `state`, and `error`. That top-level `GET` carries the binder cookie, and all the usual checks run there. The `POST` handler refuses providers that aren't `form_post`, so it can't be used to bypass them. Nothing is trusted from the post except the name.
- **The name** comes only in that first post (`user.name`), unsigned. It is used only as the display name of a user made just in time, never for identity, and is clipped.
- **Hide My Email**: relay addresses are kept like any verified email. `ALLOWED_DOMAINS` can't list Apple's relay domain (anyone can have one), so with a domain list people must share their real address.
- **Scopes** are `name email` by default; Apple has no others. Cancelling at Apple (`user_cancelled_authorize`) shows as cancelled, like `access_denied` elsewhere.

### Buttons

Both appear only when configured and ready, like the others. Apple's guidelines require the exact text "Sign in with Apple" and a black or white button, so its button ignores `LABEL` and is white on the dark login screens.

### App Store guideline 4.8

An iOS app that signs people in with a third-party or social login must also offer an equivalent privacy-focused login; Sign in with Apple qualifies. Shipping Apple alongside GitHub and Google keeps that option open for an App Store build. Enterprise-only servers (only Entra, say) fall under the guideline's exception. The apps use Apple's web flow in the system browser; the native sign-in sheet is not used yet.

## Consequences

- Five provider types, any mix at once, one user per person across them (linked by admins or made just in time).
- GitHub sign-in costs three API calls and a revoke per sign-in; GitHub rate limits are per token, so this doesn't add up across people.
- GitHub org restrictions depend on the org approving the OAuth app if it restricts third-party access; until then members are refused with a clear reason.
- Apple needs a paid developer account and a public HTTPS domain; it can't be tried on `localhost`.
- Apple `sub`s are per developer team: moving the Services ID to another team changes them, and admins must re-link.

## Not in this slice

- Native Sign in with Apple on iOS (AuthenticationServices) and Apple's server-to-server notifications (account deleted, consent revoked, email relay changes).
- GitHub team restrictions, and enterprise-managed users' SAML/OIDC (use the org check or the generic OIDC type).
- SAML bridge (rest of [#19](https://github.com/CG-Labs/superbot/issues/19)), SCIM stub, bot ACLs, and a linking UI.
