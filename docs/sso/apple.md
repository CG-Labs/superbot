# Sign in with Apple

Lets people sign in to SuperBot with their Apple Account, including with Hide My Email. Design: [ADR 0017](../adr/0017-sso-github-apple.md), on the layer from [ADR 0014](../adr/0014-oidc-sso-entra.md) and [ADR 0016](../adr/0016-sso-multi-provider.md).

You need: a paid Apple Developer Program membership (Account Holder or Admin), and SuperBot on HTTPS at a public domain, like `https://superbot.example.com`. Apple refuses `localhost`, IP addresses, and plain HTTP. Below, replace `superbot.example.com` with yours. Apple can run next to Microsoft, Google, GitHub, and other providers; each gets its own button.

Apple is OpenID Connect with two twists, both handled by botd:

- **No fixed client secret.** botd signs a fresh one (an ES256 JWT, valid five minutes) for each sign-in with your Sign in with Apple key. The key is the only secret, and lives in the secrets store like the other providers' secrets.
- **Apple posts back.** Apple returns to SuperBot with a form `POST`, and sends the person's name only on their first sign-in, in that post.

## 1. Set up Sign in with Apple at Apple

In [Certificates, Identifiers & Profiles](https://developer.apple.com/account/resources/identifiers/list):

1. **App ID.** Under **Identifiers**, use your app's App ID or register one (type **App IDs → App**, e.g. `com.example.superbot`) with the **Sign in with Apple** capability on, **Enable as a primary App ID**.
2. **Services ID** (what the website signs in as). **Identifiers → + → Services IDs**: description `SuperBot`, identifier e.g. `com.example.superbot.web`. Turn on **Sign in with Apple → Configure**: the primary App ID from step 1, **Domains and Subdomains** `superbot.example.com`, **Return URLs** `https://superbot.example.com/api/auth/sso/apple/callback`. **Save**, **Continue**, **Register**.
3. **Key.** **Keys → +**: name `SuperBot`, turn on **Sign in with Apple → Configure** with the same primary App ID, **Register**, then **Download** the `AuthKey_<key-id>.p8` file. Apple lets you download it only once. Note the **Key ID** (ten characters).
4. **Team ID**: ten characters, shown under **Membership details** (and top right of the developer site).

The Return URL must match exactly. It is always `{SSO_PUBLIC_URL}/api/auth/sso/{provider id}/callback`.

### Claims SuperBot reads

| Claim | Use |
|-------|-----|
| `iss` | Must be `https://appleid.apple.com`. |
| `aud` | Must be your Services ID. |
| `sub` | The person's id for your team: **the** identity SuperBot links to a user. Stable across sign-ins and devices. |
| `email`, `email_verified` | Kept only if verified; with `SSO_APPLE_ALLOWED_DOMAINS`, required. Shown and saved; never used to decide who someone is. With Hide My Email it is a `@privaterelay.appleid.com` address. |
| `exp`, `iat`, `nonce` | Freshness and replay protection. |
| `user.name` (posted, not in the token) | Only on the first sign-in to your Services ID; the new user's name with just-in-time sign-up. |

## 2. Configure SuperBot

In `.env` (installer: `/home/superbot/superbot/.env`; Docker: `deploy/docker/.env`):

```bash
SSO_PROVIDERS=apple              # or entra,google,apple to offer several
SSO_PUBLIC_URL=https://superbot.example.com
SSO_APPLE_CLIENT_ID=com.example.superbot.web   # the Services ID, not the App ID
SSO_APPLE_TEAM_ID=<team-id>
SSO_APPLE_KEY_ID=<key-id>
```

The private key, in one of three ways (botd reads it for each sign-in, so it never sits in a file you forgot):

```bash
botctl secret set SSO_APPLE_PRIVATE_KEY < AuthKey_<key-id>.p8 && rm AuthKey_<key-id>.p8   # recommended
SSO_APPLE_PRIVATE_KEY_FILE=/etc/superbot/AuthKey.p8
SSO_APPLE_PRIVATE_KEY=<the .p8 contents: PEM, PEM with \n for line breaks, or the base64 body>
```

The secrets store keeps it encrypted; it is never written to SQLite in plain text, never given to Bots, and redacted from logs.

Restart botd. The log says `SSO: apple (Apple, apple), ready; any Apple Account; …`, and the sign-in page and the app show **Sign in with Apple** (white, per Apple's guidelines; the text doesn't change with `SSO_APPLE_LABEL`). If the key can't be read, the log says so and the button stays hidden.

**Rotating the key:** create a new key at Apple, `botctl secret set SSO_APPLE_PRIVATE_KEY < new.p8`, set `SSO_APPLE_KEY_ID` to its id, restart botd, then revoke the old key at Apple.

### Hide My Email

People may share a private relay address (`…@privaterelay.appleid.com`) instead of their real one. SuperBot accepts it (Apple verifies it) and shows it, but never uses email to decide who someone is, so nothing changes for linking. SuperBot doesn't send email, so you don't need to register email sources with Apple's relay.

`SSO_APPLE_ALLOWED_DOMAINS=example.com` lets in only verified emails in your domains. Relay addresses never match, so people must share their real address; botd refuses to start if you list `privaterelay.appleid.com`, since anyone can have one. Without it, any Apple Account can complete sign-in, but only gets in if an admin linked it (below).

### All settings

| Variable | Default | Meaning |
|----------|---------|---------|
| `SSO_APPLE_CLIENT_ID` | (required) | The Services ID. |
| `SSO_APPLE_TEAM_ID` | (required) | Your Apple Developer Team ID. |
| `SSO_APPLE_KEY_ID` | (required) | The Sign in with Apple key's Key ID. |
| `SSO_APPLE_PRIVATE_KEY` | (required) | The `.p8` key; env, `_FILE`, or `botctl secret set`. |
| `SSO_APPLE_ALLOWED_DOMAINS` | | Email domains allowed in, comma separated. |
| `SSO_APPLE_JIT_ROLE` | `off` | `readonly`, `member`, or `admin`: create a user on first sign-in. Needs `SSO_APPLE_ALLOWED_DOMAINS` (otherwise anyone with an Apple Account would get in). |
| `SSO_APPLE_SCOPES` | `name email` | Only `name` and `email`; `email` is needed with `ALLOWED_DOMAINS`. |
| `SSO_APPLE_LABEL` | `Apple` | Shown in the log; the button always says "Sign in with Apple". |
| `SSO_APPLE_TYPE` | `apple` for the id `apple` | Set `apple` to use another id. |

`SSO_PUBLIC_URL` and `SSO_APP_REDIRECTS` are shared by all providers; see [the Entra guide](entra.md#all-settings). botd refuses to start on a setting that is missing or unsafe, and says which.

## 3. Let people in

**Link people (default).** SuperBot never matches an Apple Account to a user by email. The identity is the `sub` claim, which Apple doesn't show anywhere. Ask the person to try signing in once. It is refused with "isn't set up yet", and the audit log has the id:

```bash
botctl audit 5 --action auth.login_failed      # details.subject is the sub; details.reason is not_linked
botctl user add ada@example.com "Ada Lovelace" --role member   # if they aren't a user yet
botctl user link ada@example.com apple <sub>
```

Unlinking (`botctl user unlink`) stops new sign-ins; `botctl session revoke-all` ends current ones; `botctl user disable` does both.

**Or just in time** (your domains only). With `SSO_APPLE_ALLOWED_DOMAINS=example.com` and `SSO_APPLE_JIT_ROLE=member`, anyone whose Apple Account shares a verified `@example.com` address becomes a member on first sign-in.

**The name comes once.** Apple sends it only the first time someone signs in to your Services ID. If that try was refused (not linked yet), later ones have no name, and the user's name stays whatever the admin set. To have Apple send it again, the person removes SuperBot under **Apple Account → Sign-In & Security → Sign in with Apple** and signs in again.

**Moving the Services ID to another team** changes every `sub`. SuperBot doesn't migrate them; re-link people after a transfer.

## Apps and App Store guideline 4.8

The iOS and Android apps open Apple's page in the system browser and come back on `superbot://auth`, like the other providers; the web client returns to `{SSO_PUBLIC_URL}/app/auth`. The native Sign in with Apple sheet isn't used yet. Desktop (Electron) can't do SSO yet; use a sign-in code.

[App Store Review Guideline 4.8](https://developer.apple.com/app-store/review/guidelines/#login-services): an iOS app that lets people set up or sign in to their primary account with a third-party or social login (Google, GitHub, …) must also offer an equivalent login that limits data to name and email, lets people keep their email private, and doesn't track them for ads without consent. Sign in with Apple meets it. So if a SuperBot build you publish on the App Store shows Google or GitHub buttons, turn on Apple too, unless an exception fits (for example, an enterprise or business app where people must sign in with an existing company account, such as a server with only Entra).

## Troubleshooting

Each failed sign-in is in the audit log with a reason (`botctl audit --action auth.login_failed`):

| Reason | Fix |
|--------|-----|
| `not_linked` | Link the person (`botctl user link … apple <sub>`), or turn on just in time. The event has the `subject`. |
| `wrong_domain` | The email isn't in `SSO_APPLE_ALLOWED_DOMAINS` (often a Hide My Email address). People see "That account can't sign in here". |
| `email_unverified` | With `SSO_APPLE_ALLOWED_DOMAINS`: no verified email in the token. |
| `code_exchange_failed` | Apple refused the client secret (`invalid_client`): check `SSO_APPLE_TEAM_ID`, `SSO_APPLE_KEY_ID`, that the key belongs to the same primary App ID as the Services ID, and the server's clock. |
| `bad_private_key` | `SSO_APPLE_PRIVATE_KEY` isn't a `.p8` key. |
| `wrong_audience` | `SSO_APPLE_CLIENT_ID` isn't the Services ID (an App ID won't work on the web). |
| `email_taken` | Just-in-time sign-up met an existing user with that email: link the identity to that user. |
| `idp_error` | Apple refused; `idpError` says why. People who close Apple's page see "Sign-in was cancelled" (`user_cancelled_authorize`). |

Apple's "Invalid web redirect url" or `invalid_request` page means the Return URL in step 1 doesn't match `SSO_PUBLIC_URL` + `/api/auth/sso/apple/callback`, or the domain isn't listed.
