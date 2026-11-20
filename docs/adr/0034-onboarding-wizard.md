# 0034: Onboarding wizard in the console

## Status

Accepted (20 Nov 2026). Closes [#35](https://github.com/CG-Labs/superbot/issues/35) (M3). Builds on the admin console ([ADR 0032](0032-console-admin-only.md)), SSO ([ADR 0014](0014-oidc-sso-entra.md), [0016](0016-sso-multi-provider.md), [0018](0018-sso-github-apple.md), [0020](0020-saml-bridge.md)), and tiers ([ADR 0033](0033-tiers-model-routing.md)).

0031 is taken by [PR #87](https://github.com/CG-Labs/superbot/pull/87), so this is 0034.

## Context

After `install.sh` or `docker compose up`, the first admin signs in with the break-glass password and has to work out from the docs what's left: a domain with HTTPS, sign-in for everyone else, plans, a second admin, and approvals. Most of these settings are read from `.env` at startup (`ALLOWED_HOSTS`, the Caddyfile, `SSO_*`, `TIERS_FILE`, `AUTH_BREAK_GLASS`). A few can change while botd runs: SSO client secrets (read from the secrets store each time they're used) and the approval mode.

## Decision

### Server

`GET /api/setup` (admins) reports what's set up and what's left, for the request it answers:

| Part | What it says |
|------|--------------|
| `domain` | The public URL (`SSO_PUBLIC_URL`, else the first public `ALLOWED_HOSTS` name), and whether this request came over HTTPS through the proxy (`X-Forwarded-Proto`, trusted the same way as `X-Forwarded-For`: from loopback, or with `TRUST_FORWARDED_FOR=1`). Requests from loopback without the proxy (botctl, SSH tunnels) count as "can't check", not as plain HTTP. Commands for DNS, `install.sh --domain`, and `init.sh --domain`. |
| `signIn` | Each SSO provider, whether it's ready (`Provider::not_ready`), its secret's name, and the redirect URI to register. Admins other than the break-glass owner, SCIM, sign-ups. Copy-ready `.env` lines for each provider type, merged into the current `SSO_PROVIDERS`. |
| `tiers` | The tiers file or the built-in open self-host tier, the default, each tier's limits (no models), and how to add a file. |
| `approvals` | The global approval mode. |
| `checklist` | Five items: public address with HTTPS, providers ready, a second admin, plans (always done: self-host is a valid choice), and approvals on. |
| `progress` | Step, dismissed, completed (when, by whom), and `show`. |

`PATCH /api/setup` (admins) takes `{step?, dismissed?, completed?}` and stores progress in the `settings` table, read and written under one database lock so a step save can't undo a concurrent finish. Finishing, reopening, hiding, and showing again are audited (`setup.completed` with the open items, `setup.reopened`, `setup.dismissed`, `setup.resumed`); moving between steps isn't.

Both routes fall into the RBAC default arm (admins only, never a Bot) and are listed in `rbac.rs`'s route test and the router walk.

### What the wizard writes

Only what botd can change while running, through routes that already exist and are audited:

- SSO client secrets (Apple: the private key) via `PUT /api/secrets/{name}`. The provider is offered at once, no restart. When botd's environment already sets the secret (`SSO_<ID>_CLIENT_SECRET` or `_FILE`), that value wins, so the report says so (`secretStore: "env"`, `secretSavable: false`) and the wizard explains how to change it in `.env` instead of offering a save box.
- The approval mode via `PUT /api/policy`.
- Its own progress via `PATCH /api/setup`.

Everything read at startup is shown as commands or `.env` lines to copy, with the restart command for each install type. botd doesn't edit `.env` or the Caddyfile: it runs as an unprivileged user that can't write them, and a typo there would stop the next start.

### Where it lives

A **Setup** tab in the console, with four steps (Domain, Sign-in, Plans, Finish) and copy buttons. The first admin lands on the console (break-glass sign-in goes there), so the console opens on Setup when it has no `#tab` and `progress.show` is true. The tab shows how many checklist items are still open.

- **Resumable:** Back, Next, and the step buttons save the step.
- **Dismissible:** "Hide setup" stops sending admins there; the tab stays and can be shown again.
- **Finish** works with items still open: the checklist is guidance, not a gate.

The client gets one admin-only sidebar link, **Finish server setup ↗**, that opens `/console/#setup` while `progress.show` is true. It checks again whenever the app comes back to the front, so it goes away once the wizard is finished in the console. Older servers (404) and non-admins (never asked) see nothing. The wizard isn't rebuilt in the client: it's a one-time admin task on the server, and the console is where admins already manage secrets and settings.

`botctl setup` prints the checklist; `botctl setup done | reopen | hide | show` change progress.

### Tests

- `setup_http_tests.rs`: a fresh install's report; member, read-only, and Bot get 403 and signed-out gets 401 for GET and PATCH, and a refused PATCH changes nothing; progress, validation, and audit events; HTTPS through a trusted proxy; a provider becoming ready once its secret is saved; a tiers file and bypass mode.
- `setup.rs` unit tests: public hosts, proxy trust, and that every provider template parses with `Sso::from_vars` once its placeholders are filled.
- The console tests cover the new tab and call; the client tests cover the link and when it shows.

## Consequences

- A fresh install tells its admin what's left and how to finish, in the browser or a terminal.
- Existing installs see the wizard once after upgrading; any admin can finish or hide it.
- The report never contains secret values or models, only names and readiness.
- New settings that can change at runtime can join the wizard as they appear; until then the wizard hands out commands.

## Alternatives considered

- **Write `.env` from the server.** Rejected: botd can't and shouldn't write its own startup config or Caddy's, and half the settings need a restart anyway.
- **A wizard in the client.** Rejected for now: it would duplicate the console's secrets and settings forms for a task done once per server. The client links to it instead.
- **Block the console until setup is done.** Rejected: a self-host install on loopback with codes only is complete as is.
