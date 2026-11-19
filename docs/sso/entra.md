# Sign in with Microsoft Entra ID

Lets people sign in to SuperBot with their work Microsoft account. Design: [ADR 0014](../adr/0014-oidc-sso-entra.md).

Google and other OpenID Connect IdPs can be offered next to it: [Google](google.md), [Okta, Keycloak, Auth0, …](oidc.md).

You need: admin rights in your Entra tenant (to register an app), and SuperBot on HTTPS at a fixed address, like `https://superbot.example.com`. Below, replace `superbot.example.com` with yours.

## 1. Register the app in Entra

In the [Microsoft Entra admin center](https://entra.microsoft.com): **Identity → Applications → App registrations → New registration**.

| Field | Value |
|-------|-------|
| Name | `SuperBot` (people see it on the consent screen) |
| Supported account types | **Accounts in this organizational directory only (Single tenant)** |
| Redirect URI | Platform **Web**, `https://superbot.example.com/api/auth/sso/entra/callback` |

The redirect URI must match exactly: scheme, host, port, and path, with no trailing slash. It is always `{SSO_PUBLIC_URL}/api/auth/sso/{provider id}/callback`.

Then, in the new app:

1. **Overview**: copy the **Application (client) ID** and the **Directory (tenant) ID**.
2. **Certificates & secrets → Client secrets → New client secret**. Copy the **Value** (not the Secret ID) now; Entra shows it once. Note when it expires and put a reminder in your calendar.
3. **Authentication**: leave **Access tokens** and **ID tokens** (implicit grant) unchecked. SuperBot uses the authorization code flow with PKCE.
4. **API permissions**: the default **Microsoft Graph → User.Read** is enough; SuperBot asks for `openid profile email`, which need no extra permission. To skip the consent prompt for everyone, click **Grant admin consent**.
5. Optional, **Token configuration → Add optional claim → ID → email**: SuperBot then shows and saves people's email. It is never used to decide who someone is.

### Claims SuperBot reads

| Claim | Use |
|-------|-----|
| `tid` | Must be your tenant id. |
| `iss` | Must be `https://login.microsoftonline.com/{tid}/v2.0`. |
| `oid` | The person's object id: **the** identity SuperBot links to a user. Needs the `profile` scope, which SuperBot asks for. |
| `aud`, `azp` | Must be your client id. |
| `exp`, `iat`, `nbf`, `nonce` | Freshness and replay protection. |
| `name`, `email` | Display only (and the new user's name and email with just-in-time sign-up). |

## 2. Configure SuperBot

In `.env` (installer: `/home/superbot/superbot/.env`; Docker: `deploy/docker/.env`):

```bash
SSO_PROVIDERS=entra
SSO_PUBLIC_URL=https://superbot.example.com
SSO_ENTRA_CLIENT_ID=<application-client-id>
SSO_ENTRA_TENANT=<directory-tenant-id>
```

`SSO_PUBLIC_URL` must be an address botd answers to: with the installer's `--domain` it already is; otherwise add its host to `ALLOWED_HOSTS`.

The client secret, in one of three ways (botd reads it when used, so rotating needs no restart):

```bash
# Sealed in SuperBot's database (recommended), on the server:
botctl secret set SSO_ENTRA_CLIENT_SECRET < entra-secret.txt && rm entra-secret.txt
# Or a file only botd can read:
SSO_ENTRA_CLIENT_SECRET_FILE=/etc/superbot/entra-secret
# Or the value itself in .env:
SSO_ENTRA_CLIENT_SECRET=<value>
```

Bots never see it: botd keeps `SSO_*` out of their environment, and `botctl secrets` lists it as botd's own.

Restart botd. The log says `SSO: entra (Microsoft, entra), ready`. The web sign-in page and the app now show **Sign in with Microsoft**.

### All settings

| Variable | Default | Meaning |
|----------|---------|---------|
| `SSO_PROVIDERS` | (off) | Provider ids, comma separated. `entra` is an Entra provider unless `SSO_ENTRA_TYPE` says otherwise. |
| `SSO_PUBLIC_URL` | (required) | The https address people open SuperBot at, no path. Loopback may use http. |
| `SSO_ENTRA_CLIENT_ID` | (required) | Application (client) ID. |
| `SSO_ENTRA_CLIENT_SECRET` | (required) | As above; env, `_FILE`, or `botctl secret set`. |
| `SSO_ENTRA_TENANT` | (required) | Directory (tenant) ID, or `organizations` / `common` with `SSO_ENTRA_ALLOWED_TENANTS`. `consumers` (personal accounts) is not supported. |
| `SSO_ENTRA_ALLOWED_TENANTS` | | Tenant ids to accept with `organizations` or `common`, comma separated. |
| `SSO_ENTRA_JIT_ROLE` | `off` | `readonly`, `member`, or `admin`: create a user with this role the first time someone from your tenant signs in. Off: an admin links people first. |
| `SSO_ENTRA_LABEL` | `Microsoft` | Button text: "Sign in with …". |
| `SSO_ENTRA_SCOPES` | `openid profile email` | Must include `openid`; keep `profile` (Entra sends `oid` with it). |
| `SSO_ENTRA_AUTHORITY` | `https://login.microsoftonline.com` | Change for national clouds, e.g. `https://login.microsoftonline.us`. |
| `SSO_APP_REDIRECTS` | `superbot://auth` and `{SSO_PUBLIC_URL}/app/auth` | Where the SuperBot app may receive its one-time code. The default covers the native app and the web client the installer and Compose serve at `/app/`. Setting it replaces the default; add your web client's `https://…/auth` if you host it elsewhere. |

botd refuses to start on a setting that is missing or unsafe, and says which.

## 3. Let people in

**Link people (default).** SuperBot never matches a Microsoft account to a user by email. Find the person's **Object ID** (Entra admin center → **Users** → the person, or `az ad user show --id ada@example.com --query id -o tsv`) and link it:

```bash
botctl user add ada@example.com "Ada Lovelace" --role member   # if they aren't a user yet
botctl user link ada@example.com entra <object-id>
botctl user identities ada@example.com
botctl user unlink ada@example.com <identity-id>                 # identity id from the list
```

Unlinking stops new sign-ins; end current ones with `botctl session revoke-all ada@example.com`. Disabling a user (`botctl user disable`) does both.

**Or just in time.** With `SSO_ENTRA_JIT_ROLE=member`, anyone in your tenant who can sign in to the app becomes a member on first sign-in. To limit who that is, in Entra open **Enterprise applications → SuperBot → Properties**, set **Assignment required** to **Yes**, and assign users or groups under **Users and groups**. If someone's email already belongs to another SuperBot user, sign-in is refused until an admin links them.

Once every admin can sign in with Microsoft, consider `AUTH_BREAK_GLASS=0` ([backend docs](../backend.md#users-sessions-and-roles)).

## Several tenants

To accept people from more than one tenant, make the app multitenant (supported account types **Accounts in any organizational directory**; in the app's **Manifest** that is `"signInAudience": "AzureADMultipleOrgs"`), then:

```bash
SSO_ENTRA_TENANT=organizations
SSO_ENTRA_ALLOWED_TENANTS=<tenant-id-1>,<tenant-id-2>
```

Every other tenant is refused, even though Microsoft would sign its people in. Link people with `botctl user link <user> entra <object-id> --tenant <tenant-id>`.

## Apps

- **iOS and Android**: the app opens Microsoft's page in the system browser and comes back on `superbot://auth`. Nothing to register in Entra: Entra only talks to botd. Expo Go uses an `exp://…` address instead; add the one the app shows to `SSO_APP_REDIRECTS` while developing.
- **Web client** (Expo web): sign-in opens in a popup and returns to `{web client}/auth`. The one botd's installer or Compose serves returns to `{SSO_PUBLIC_URL}/app/auth`, which is allowed by default; add any other web client's address to `SSO_APP_REDIRECTS`.
- **Desktop (Electron)**: not yet; it loads from `file://`, which Microsoft can't return to. Use a sign-in code (`botctl user code <user>`).

## Troubleshooting

Each failed SSO sign-in is in the audit log with a reason (`botctl audit --action auth.login_failed`):

| Reason | Fix |
|--------|-----|
| `not_linked` | Link the person (`botctl user link`), or turn on `SSO_ENTRA_JIT_ROLE`. The event has the `subject` (object id) to link. |
| `wrong_tenant` | They signed in from another tenant. Check `SSO_ENTRA_TENANT` / `SSO_ENTRA_ALLOWED_TENANTS`. |
| `code_exchange_failed` | Usually the client secret (expired or wrong value) or a redirect URI mismatch. |
| `wrong_audience` | `SSO_ENTRA_CLIENT_ID` isn't this app's client id. |
| `email_taken` | Just-in-time sign-up met an existing user with that email: link the identity to that user instead. |
| `binder_mismatch`, `unknown_state` | The sign-in was finished in another browser, took longer than 10 minutes, or the page was reloaded. Try again. |
| `idp_error` | Microsoft refused; `idpError` says why (for example `access_denied` when consent was declined). |

Microsoft's error `AADSTS50011` (redirect URI mismatch) means the URI in step 1 doesn't match `SSO_PUBLIC_URL` + `/api/auth/sso/entra/callback`.
