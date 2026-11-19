# Sign in with Google

Lets people sign in to SuperBot with a Google account: Google Workspace (a company or school domain) or a personal account. Design: [ADR 0014](../adr/0014-oidc-sso-entra.md) and [ADR 0016](../adr/0016-sso-multi-provider.md).

You need: a Google Cloud project you can edit, and SuperBot on HTTPS at a fixed address, like `https://superbot.example.com`. Below, replace `superbot.example.com` with yours. Google can run next to Microsoft and other providers; each gets its own button.

## 1. Create the OAuth client in Google Cloud

In the [Google Cloud console](https://console.cloud.google.com), pick or create a project, then open **Google Auth Platform**.

1. **Branding**: app name `SuperBot`, a support email, and your domain under **Authorized domains**.
2. **Audience**: for Workspace, choose **Internal** (only your organization's accounts can even reach the consent screen). For personal accounts, choose **External**; while it is in **Testing**, only the test users you list can sign in.
3. **Data access**: the default `openid`, `.../auth/userinfo.email`, and `.../auth/userinfo.profile` scopes are all SuperBot asks for. None are sensitive, so no verification is needed.
4. **Clients → Create client**: type **Web application**, name `SuperBot`, and under **Authorized redirect URIs** add `https://superbot.example.com/api/auth/sso/google/callback`. Leave **Authorized JavaScript origins** empty.
5. Copy the **Client ID** (ends in `.apps.googleusercontent.com`) and the **Client secret**.

The redirect URI must match exactly: scheme, host, port, and path, with no trailing slash. It is always `{SSO_PUBLIC_URL}/api/auth/sso/{provider id}/callback`.

### Claims SuperBot reads

| Claim | Use |
|-------|-----|
| `iss` | Must be `https://accounts.google.com` (or the legacy `accounts.google.com`). |
| `sub` | The account's id: **the** identity SuperBot links to a user. Google never changes or reuses it. |
| `email`, `email_verified` | The email must be verified, or sign-in is refused. Shown and saved; never used to decide who someone is. |
| `hd` | The Workspace domain. With `SSO_GOOGLE_HOSTED_DOMAINS`, it must be one of them. Personal accounts have none. |
| `aud`, `azp` | Must be your client id. |
| `exp`, `iat`, `nbf`, `nonce` | Freshness and replay protection. |
| `name` | Display only (and the new user's name with just-in-time sign-up). |

## 2. Configure SuperBot

In `.env` (installer: `/home/superbot/superbot/.env`; Docker: `deploy/docker/.env`):

```bash
SSO_PROVIDERS=google             # or entra,google to offer both
SSO_PUBLIC_URL=https://superbot.example.com
SSO_GOOGLE_CLIENT_ID=<client-id>.apps.googleusercontent.com
# Workspace only: the domains whose accounts may sign in.
SSO_GOOGLE_HOSTED_DOMAINS=example.com
```

The client secret, in one of three ways (botd reads it when used, so rotating needs no restart):

```bash
botctl secret set SSO_GOOGLE_CLIENT_SECRET < google-secret.txt && rm google-secret.txt   # recommended
SSO_GOOGLE_CLIENT_SECRET_FILE=/etc/superbot/google-secret
SSO_GOOGLE_CLIENT_SECRET=<value>
```

Restart botd. The log says `SSO: google (Google, google), ready; Workspace domains example.com; …`, and the sign-in page and the app show **Sign in with Google**.

### Workspace domains

`SSO_GOOGLE_HOSTED_DOMAINS` is checked on the `hd` claim in Google's signed ID token, on every sign-in. A personal Google account made with a company address (`ada@example.com` without Workspace) has no `hd` and is refused; so is an account whose organization is another domain, even if an admin linked it. With one domain, SuperBot also sends `hd=example.com` so Google's account picker shows only that domain (with several, `hd=*`). That hint is only for convenience: Google says not to rely on it, and SuperBot doesn't.

Without `SSO_GOOGLE_HOSTED_DOMAINS`, any Google account can complete sign-in, but it only gets in if an admin linked it (below).

### All settings

| Variable | Default | Meaning |
|----------|---------|---------|
| `SSO_GOOGLE_CLIENT_ID` | (required) | The OAuth client id. |
| `SSO_GOOGLE_CLIENT_SECRET` | (required) | As above; env, `_FILE`, or `botctl secret set`. |
| `SSO_GOOGLE_HOSTED_DOMAINS` | | Workspace domains allowed in, comma separated. Subdomains are listed on their own. |
| `SSO_GOOGLE_JIT_ROLE` | `off` | `readonly`, `member`, or `admin`: create a user on first sign-in. Needs `SSO_GOOGLE_HOSTED_DOMAINS` (otherwise anyone with a Google account would get in). |
| `SSO_GOOGLE_LABEL` | `Google` | Button text: "Sign in with …". |
| `SSO_GOOGLE_SCOPES` | `openid profile email` | Must include `openid` and `email`. |
| `SSO_GOOGLE_TYPE` | `google` for the id `google` | Set `google` to use another id, e.g. `SSO_PROVIDERS=work,personal` with two Google clients. |

`SSO_PUBLIC_URL` and `SSO_APP_REDIRECTS` are shared by all providers; see [the Entra guide](entra.md#all-settings). botd refuses to start on a setting that is missing or unsafe (for example `SSO_GOOGLE_ALLOWED_DOMAINS`, which is the generic OIDC setting and would not check Workspace membership), and says which.

## 3. Let people in

**Link people (default).** SuperBot never matches a Google account to a user by email. The account's id is the `sub` claim, which Google doesn't show in its UI. The easy way to get it: ask the person to try signing in once. It is refused with "isn't set up yet", and the audit log has the id:

```bash
botctl audit 5 --action auth.login_failed      # details.subject is the sub; details.reason is not_linked
botctl user add ada@example.com "Ada Lovelace" --role member   # if they aren't a user yet
botctl user link ada@example.com google <sub>
```

Unlinking (`botctl user unlink`) stops new sign-ins; `botctl session revoke-all` ends current ones; `botctl user disable` does both.

**Or just in time** (Workspace only). With `SSO_GOOGLE_HOSTED_DOMAINS=example.com` and `SSO_GOOGLE_JIT_ROLE=member`, anyone in your Workspace becomes a member on first sign-in. If someone's email already belongs to another SuperBot user, sign-in is refused until an admin links them. To narrow it to some people, in the [Google Admin console](https://admin.google.com) restrict access to the app under **Security → API controls → App access control**.

A person can have Google and Microsoft (or any other provider) identities linked to the same user: link each one.

## Apps

Same as Entra: the iOS and Android apps open Google's page in the system browser and come back on `superbot://auth`; the web client returns to `{SSO_PUBLIC_URL}/app/auth`. Nothing extra to register at Google: Google only talks to botd. Desktop (Electron) can't do SSO yet; use a sign-in code.

## Troubleshooting

Each failed sign-in is in the audit log with a reason (`botctl audit --action auth.login_failed`):

| Reason | Fix |
|--------|-----|
| `not_linked` | Link the person (`botctl user link … google <sub>`), or turn on just in time. The event has the `subject`. |
| `wrong_domain` | The account isn't in `SSO_GOOGLE_HOSTED_DOMAINS` (or is a personal account). People see "That account can't sign in here". |
| `email_unverified` | The account's email isn't verified at Google, or `email` is missing from `SSO_GOOGLE_SCOPES`. |
| `code_exchange_failed` | Usually the client secret, or a redirect URI mismatch. |
| `wrong_audience` | `SSO_GOOGLE_CLIENT_ID` isn't this client's id. |
| `email_taken` | Just-in-time sign-up met an existing user with that email: link the identity to that user. |
| `idp_error` | Google refused; `idpError` says why (`access_denied` when consent was declined or the account isn't a test user). |

Google's `Error 400: redirect_uri_mismatch` means the URI in step 1 doesn't match `SSO_PUBLIC_URL` + `/api/auth/sso/google/callback`. `Error 403: org_internal` means an Internal app was used by an account outside your organization.
