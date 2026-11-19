# 0022: Public landing page and approved sign-ups

## Status

Accepted. Comes before self-serve tenancy and billing ([roadmap](../ROADMAP.md) M3/M4). It builds on [ADR 0012](0012-users-sessions-rbac.md) (users, roles, sign-in codes), [ADR 0014](0014-oidc-sso-entra.md) (SSO never links by email) and [ADR 0019](0019-audit-actors.md) (audit actors).

## Context

A server's front door used to be botd's built-in admin page at `/`. Strangers got a sign-in prompt and no idea what SuperBot is. We need:

- a public page explaining the product;
- a way to ask for access.

There is no tenancy, billing or mail service yet. So "sign up" has to mean "ask, and an admin approves", on one server with one set of users.

## Decision

### `/` is the landing page for everyone; the admin page moves to `/console/`

- `/` and `/get-started` are static pages from `site/`. They are the same for every visitor.
- The legacy admin UI (`web/`) moves to `/console/`. `/console` redirects there with a 308.
- `/app/` is still the client. When it isn't installed, botd sends `/app` to `/console/`.
- SSO and the sign-in page now land on `/console/`.
- *Update, 19 Nov 2026 ([ADR 0027](0027-expo-primary-hermes-default.md)):* only admins land on `/console/`. Everyone else lands on `/app/`, and botd sends only admins from a missing `/app/` to the console.
- The old `/app.js` and `/styles.css` paths are gone.

We considered showing the landing page only to signed-out visitors, keeping the admin page at `/` for signed-in ones. We rejected it:

- One URL with two pages, chosen by a cookie, can't be cached safely: a proxy or browser can show one to the other.
- It mixes up break-glass Basic auth and `ALLOW_NO_AUTH`, where "signed in" isn't a cookie.
- It hides the product page from the people who run the server.

A fixed path is simpler to reason about, document and test.

### Static, self-contained, served twice

- **No external dependencies.** The site is plain HTML and CSS plus one small script for the form. It uses no frameworks, fonts, trackers or CDNs.
- **Brand.** It reuses the client's brand tokens ([brand.md](../brand.md)) and mark, in dark and light themes.
- **botd** embeds the site, so it works with no proxy (dev, Compose without Caddy). Set `SITE_DIR` to serve it from disk while editing.
- **Caddy** serves the same files from disk in front of botd. `deploy/install.sh` installs them root-owned into `/var/www/superbot-site`, using the same release-and-symlink swap as the client, on every install and `--upgrade`. The Compose Caddy image bakes them in.
- **Headers.** Both servers send the same CSP, `nosniff` and Referrer-Policy. A test fails if the Caddyfiles' CSP drifts from botd's.
- **External origin.** The only one allowed is `challenges.cloudflare.com`, for the optional Turnstile check.

### Sign-ups are requests, approved by an admin

The get-started form asks for:

- name, work email and company;
- team size and use case;
- preferred sign-in (Microsoft, Google, GitHub, Apple, or other OIDC/SAML);
- consent.

The public endpoint is `POST /api/signups`, defended in layers:

- **Strict JSON.** Known fields only, with length limits and an email check. The body is capped at 16 KiB. Consent must be `true`.
- **Rate limit.** 5 requests per IP per hour (the proxy's `X-Forwarded-For` is trusted from loopback only), then 429 with `Retry-After`.
- **Honeypot.** A hidden `website` field. When it's filled, botd answers like a success, saves nothing, and records a throttled `signup.refused` event.
- **Turnstile (optional).** Cloudflare Turnstile is checked when `TURNSTILE_SECRET` and `TURNSTILE_SITE_KEY` are both set. The check fails closed: if Cloudflare can't be reached, the request is refused.
- **No duplicates.** One pending request per email (a unique index). A duplicate gets the same 202 response as a new one, so the form doesn't reveal who has asked.
- **A cap.** At most 1000 pending requests in total; beyond that, 503.
- **An off switch.** `SIGNUPS=off` closes the form: the endpoint returns 404 and the page says so.

Requests live in a new `signups` table (migration 7) and are audited (`signup.submitted`, `signup.approved`, `signup.rejected`).

**Approving** is admin-only (`POST /api/signups/:id/approve`, `botctl signup approve`). In one transaction it:

1. creates the user with the chosen role (member by default), through the same code as `POST /api/users`;
2. marks the request approved.

It then returns a one-time sign-in code (valid for 3 days by default). The code is shown once and only its hash is stored, like any other code. If a user with that email already exists, approval returns 409. Rejecting records an optional reason that only admins see.

### SSO is a hint, not a link

SSO never matches accounts by email ([ADR 0014](0014-oidc-sso-entra.md)), and a sign-up form must not change that. So:

- The confirmation screen names the configured providers that fit the person's email domain or chosen sign-in. It says they can use one *after* their account is connected.
- The approve response lists the same providers, so the admin knows to run `botctl user link`.

### No email, but a hook

There is no mail service, so nothing is sent. Every point where an email would go (request received, approved with the code, rejected) calls `signups::notify` with a typed `Notice`. Today it returns `false`, and approve reports `emailed: false`, so the admin hands the code over in person.

## Consequences

- Bookmarks of `/` that expected the admin page now get the landing page. Its footer links to the console, and the installer prints the console URL.
- Spam is bounded by the per-IP limit, the cap and (optionally) Turnstile. A request alone grants nothing: only an admin's approval creates a user.
- Requests store personal data: name, email, company, IP and user agent. Retention and purging are not built yet.

### Deferred

- Sending email (plug into `notify`).
- Letting people link their own SSO identity at first sign-in, instead of an admin linking it.
- Retention and purging of sign-up requests.
- A Signups screen in the client's admin area. Since built: **Requests** in the admin portal ([ADR 0021](0021-admin-portal.md)).
- Self-serve tenants and billing (M3/M4).
