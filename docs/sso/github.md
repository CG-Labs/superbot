# Sign in with GitHub

Lets people sign in to SuperBot with a GitHub account, on github.com or GitHub Enterprise Server. Optionally, only members of your GitHub organizations get in. Design: [ADR 0018](../adr/0018-sso-github-apple.md), on the layer from [ADR 0014](../adr/0014-oidc-sso-entra.md) and [ADR 0016](../adr/0016-sso-multi-provider.md).

You need: a GitHub account that can create an OAuth app (for an org, an org owner), and SuperBot on HTTPS at a fixed address, like `https://superbot.example.com`. Below, replace `superbot.example.com` with yours. GitHub can run next to Microsoft, Google, Apple, and other providers; each gets its own button.

GitHub isn't OpenID Connect: there is no ID token. botd exchanges the code itself (with PKCE), then asks GitHub's API who signed in. The access token is used for those calls only, then revoked; SuperBot never stores it.

## 1. Create the OAuth app on GitHub

For your organization: **Org settings → Developer settings → OAuth Apps → New OAuth App** (for a personal account: **Settings → Developer settings → OAuth Apps**).

1. **Application name** `SuperBot`, **Homepage URL** `https://superbot.example.com`.
2. **Authorization callback URL**: `https://superbot.example.com/api/auth/sso/github/callback`.
3. Leave **Enable Device Flow** off. **Register application**.
4. Copy the **Client ID**, then **Generate a new client secret** and copy it.

The callback URL is always `{SSO_PUBLIC_URL}/api/auth/sso/{provider id}/callback`.

Use an OAuth app, not a GitHub App: SuperBot asks for OAuth scopes (`read:user user:email`, plus `read:org` with an org restriction), which GitHub Apps ignore.

### What SuperBot reads

| From | Use |
|------|-----|
| `GET /user` → `id` | The account's numeric id: **the** identity SuperBot links to a user. It never changes; the login (username) can. |
| `GET /user` → `login`, `name` | Shown and saved (the login as `username` in the audit log); the name is the new user's name with just-in-time sign-up. |
| `GET /user/emails` | The **primary** email, and only if it is **verified**; otherwise sign-in is refused. Never used to decide who someone is. |
| `GET /user/memberships/orgs/{org}` | With `SSO_GITHUB_ALLOWED_ORGS`: the membership must be `active` (not a pending invite) in at least one of them. |

## 2. Configure SuperBot

In `.env` (installer: `/home/superbot/superbot/.env`; Docker: `deploy/docker/.env`):

```bash
SSO_PROVIDERS=github             # or entra,google,github to offer several
SSO_PUBLIC_URL=https://superbot.example.com
SSO_GITHUB_CLIENT_ID=<client-id>
# Only active members of these orgs (recommended).
SSO_GITHUB_ALLOWED_ORGS=<org>
```

The client secret, in one of three ways (botd reads it when used, so rotating needs no restart):

```bash
botctl secret set SSO_GITHUB_CLIENT_SECRET < github-secret.txt && rm github-secret.txt   # recommended
SSO_GITHUB_CLIENT_SECRET_FILE=/etc/superbot/github-secret
SSO_GITHUB_CLIENT_SECRET=<value>
```

Restart botd. The log says `SSO: github (GitHub, github), ready; members of <org> on https://github.com; …`, and the sign-in page and the app show **Sign in with GitHub**.

### Organizations

`SSO_GITHUB_ALLOWED_ORGS` is checked on GitHub's API on every sign-in, with the person's own token: an active member of any listed org gets in; anyone else is refused, even if an admin linked them. If GitHub can't answer, sign-in fails closed.

If the org restricts OAuth app access (**Org settings → Third-party access → OAuth app policy**), approve SuperBot there. Until then GitHub hides the membership and members are refused with `wrong_org`. An OAuth app owned by the org is always allowed.

Without `SSO_GITHUB_ALLOWED_ORGS`, any GitHub account can complete sign-in, but it only gets in if an admin linked it (below).

### GitHub Enterprise Server

Create the OAuth app on your server the same way, then:

```bash
SSO_GITHUB_URL=https://github.example.com
# SSO_GITHUB_API_URL defaults to {SSO_GITHUB_URL}/api/v3
```

The button then says **Sign in with GitHub Enterprise**. Identities are stored under the server's address, so a github.com account and an Enterprise account are never confused. To offer both, use two ids: `SSO_PROVIDERS=github,ghe` with `SSO_GHE_TYPE=github` and `SSO_GHE_URL=…`.

### All settings

| Variable | Default | Meaning |
|----------|---------|---------|
| `SSO_GITHUB_CLIENT_ID` | (required) | The OAuth app's client id. |
| `SSO_GITHUB_CLIENT_SECRET` | (required) | As above; env, `_FILE`, or `botctl secret set`. |
| `SSO_GITHUB_ALLOWED_ORGS` | | Org logins allowed in, comma separated. |
| `SSO_GITHUB_JIT_ROLE` | `off` | `readonly`, `member`, or `admin`: create a user on first sign-in. Needs `SSO_GITHUB_ALLOWED_ORGS` (otherwise anyone with a GitHub account would get in). |
| `SSO_GITHUB_URL` | `https://github.com` | GitHub Enterprise Server's web address. |
| `SSO_GITHUB_API_URL` | `https://api.github.com`, or `{URL}/api/v3` | Only if your API lives elsewhere. |
| `SSO_GITHUB_LABEL` | `GitHub` (`GitHub Enterprise` with `URL`) | Button text: "Sign in with …". |
| `SSO_GITHUB_SCOPES` | `read:user user:email` (+ `read:org` with orgs) | Must include `user:email`; with orgs, `read:org`. |
| `SSO_GITHUB_TYPE` | `github` for the id `github` | Set `github` to use another id. |

`SSO_PUBLIC_URL` and `SSO_APP_REDIRECTS` are shared by all providers; see [the Entra guide](entra.md#all-settings). botd refuses to start on a setting that is missing or unsafe (for example `SSO_GITHUB_ALLOWED_DOMAINS`, which GitHub doesn't have), and says which.

## 3. Let people in

**Link people (default).** SuperBot never matches a GitHub account to a user by email or username. The identity is the numeric user id:

```bash
gh api users/<login> --jq .id         # or ask them to try once: the audit log has it
botctl user add ada@example.com "Ada Lovelace" --role member   # if they aren't a user yet
botctl user link ada@example.com github <id>
```

A refused first try shows the id too: `botctl audit 5 --action auth.login_failed` (`details.subject` is the id, `details.username` the login).

Unlinking (`botctl user unlink`) stops new sign-ins; `botctl session revoke-all` ends current ones; `botctl user disable` does both.

**Or just in time** (orgs only). With `SSO_GITHUB_ALLOWED_ORGS=<org>` and `SSO_GITHUB_JIT_ROLE=member`, every active member of the org becomes a member on first sign-in. If someone's email already belongs to another SuperBot user, sign-in is refused until an admin links them.

A person can have GitHub and other identities linked to the same user: link each one.

## Apps

Same as the other providers: the iOS and Android apps open GitHub's page in the system browser and come back on `superbot://auth`; the web client returns to `{SSO_PUBLIC_URL}/app/auth`. Nothing extra to register at GitHub. Desktop (Electron) can't do SSO yet; use a sign-in code.

## Require MFA at the IdP

SuperBot doesn't ask single sign-on sign-ins for its own second factor: the IdP's MFA is that factor, so require it there. Sign-in codes and the owner's password get SuperBot's own two-factor authentication instead ([ADR 0094](../adr/0094-totp-second-factor.md)). Requiring MFA at your IdP is your control as the customer (CC6.1-2 in the [SOC 2 readiness checklist](../security/soc2-readiness-checklist.md)).

In each GitHub organization whose people use SuperBot, **Settings → Authentication security → Require two-factor authentication**. SuperBot sees only a GitHub account, not its organizations, so link only people from organizations that require it.

## Troubleshooting

Each failed sign-in is in the audit log with a reason (`botctl audit --action auth.login_failed`):

| Reason | Fix |
|--------|-----|
| `not_linked` | Link the person (`botctl user link … github <id>`), or turn on just in time. The event has the `subject` and `username`. |
| `wrong_org` | Not an active member of `SSO_GITHUB_ALLOWED_ORGS`, or the org hasn't approved the OAuth app (above). People see "That account can't sign in here". |
| `email_unverified` | The account's primary email isn't verified at GitHub, or `user:email` is missing from `SSO_GITHUB_SCOPES`. |
| `code_exchange_failed` | Usually the client secret, or a callback URL mismatch. |
| `idp_unreachable`, `idp_bad_response` | botd couldn't reach GitHub's API, or it answered oddly; check `SSO_GITHUB_URL` / `SSO_GITHUB_API_URL`. |
| `email_taken` | Just-in-time sign-up met an existing user with that email: link the identity to that user. |
| `idp_error` | GitHub refused; `idpError` says why (`access_denied` when the person clicked Cancel). |

GitHub's "The redirect_uri MUST match the registered callback URL for this application" means the callback URL in step 1 doesn't match `SSO_PUBLIC_URL` + `/api/auth/sso/github/callback`.
