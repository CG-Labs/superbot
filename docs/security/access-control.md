# Access control and isolation

How people and Bots sign in, what each may do, how one user is kept from another, and what is recorded. Part of the [security pack](README.md).

## Authentication

| Method | How it works |
|--------|--------------|
| **Sessions** | An opaque 256-bit token, stored only as a SHA-256 hash. Sent as a cookie (`__Host-superbot_session`: HttpOnly, Secure, SameSite=Strict) or a bearer token from the apps. Ends after 7 days idle or 30 days at most, and on sign-out, "sign out everywhere", or the user being disabled ([ADR 0012](../adr/0012-users-sessions-rbac.md), [ADR 0024](../adr/0024-auth-review-hardening.md)). |
| **SSO (OpenID Connect)** | Microsoft Entra ID, Google, any OIDC provider (Okta, Auth0, Keycloak, ...), Sign in with Apple, and GitHub. Several at once; optional allowed email domains; just-in-time accounts, only with an allow-list for the provider (domains, GitHub organizations or Entra tenants, [ADR 0103](../adr/0103-sso-jit-needs-an-allow-list.md)) ([ADR 0014](../adr/0014-oidc-sso-entra.md), [ADR 0016](../adr/0016-sso-multi-provider.md), [ADR 0018](../adr/0018-sso-github-apple.md)). Entra emails count only when the tenant verified the domain ([auth review, AUTH-03](auth-review-2026-11.md)). |
| **SAML** | Through an OIDC broker (Keycloak) that checks the IdP's signed assertion. botd never parses SAML itself and accepts only logins brokered by the named IdP ([ADR 0020](../adr/0020-saml-bridge.md)). |
| **One-time sign-in codes** | An admin issues a code for a person; it expires (default 60 minutes). |
| **Break-glass password** | `AUTH_PASSWORD`, for the owner account, for setup and recovery. Constant-time compare and rate-limited. |
| **Two-factor authentication** | TOTP from any authenticator app, with ten one-time recovery codes, for sign-in codes and the password. An admin (or `AUTH_MFA`) requires it for admins, which includes the owner, or for everyone; anyone can turn on their own. Secrets are sealed under the master key; wrong codes are limited per IP and per user and audited. Once the owner needs it, the password works only at sign-in, not over HTTP Basic ([ADR 0094](../adr/0094-totp-second-factor.md)). |
| **SCIM 2.0 provisioning** | Off by default (`SCIM=on`). Its own hashed bearer token, valid only on `/scim/v2`. Deprovisioning disables the user and ends their sessions ([ADR 0023](../adr/0023-scim.md), [ADR 0026](../adr/0026-scim-review-hardening.md)). |
| **App lock** | Optional biometric unlock in the iOS and Android apps ([ADR 0078](../adr/0078-client-biometric-app-lock.md)). |

Sign-in failures (password, codes, second factors, SSO) are limited to 10 per 10 minutes per IP address, and wrong second factors to 5 per 15 minutes per person. Writes without a bearer token must come from botd's own origin, which blocks cross-site requests ([auth review](auth-review-2026-11.md)).

SSO sign-ins don't get SuperBot's second factor: they rely on the IdP's MFA, which the customer must require there (each [IdP guide](../sso/) says where).

**Not built:** WebAuthn or passkeys, and long-lived personal API tokens.

## Authorization

- **Roles.** `admin`, `member` and `readonly`. Every API route is classified; an unclassified route needs admin ([ADR 0012](../adr/0012-users-sessions-rbac.md)).
- **Custom roles.** An admin builds a role from `member` or `readonly` plus any of six fixed permissions (`users.manage`, `bots.manage`, `audit.view`, `billing.manage`, `signups.approve`, `machines.manage`) and gives it across the server or within a team. Each opens a named list of routes; unknown permission names are refused or grant nothing. Holders never reach admins, the owner, or other custom-role holders, and never make admins. Every change and refusal is audited ([ADR 0123](../adr/0123-custom-roles.md)).
- **Bot permissions.** A Bot is private to its owner or shared. Sharing grants `viewer` or `operator`; owners and admins manage. Read-only users can only view ([ADR 0017](../adr/0017-bot-acls.md)).
- **Shared Bots.** A shared Bot runs as its owner's Bot. With `SHARED_BOTS=isolated` it reaches for a teammate only what that teammate could, without the owner's keys or facts. That is the default, and the only choice, when Bots run on users' machines (`MACHINE_ROUTING` on or assigned). On one server (`MACHINE_ROUTING=off`) the default is `SHARED_BOTS=open`: a shared Bot acts with its owner's access, keys and facts for everyone who uses it ([ADR 0046](../adr/0046-shared-bots-under-isolation.md)).
- **Admin console.** `/console/` is for admins only ([ADR 0032](../adr/0032-console-admin-only.md)).
- **Approvals.** Risky actions wait for a person: destructive shell commands, file deletes, outbound messages, network installs and `git push`. Each harness checks with botd before each tool call through its own hook (Claude Code, Codex, Pi and Hermes Agent); if botd can't be reached, the call is refused. Bots can't approve. Scripts are read and classified like the command line that runs them ([ADR 0007](../adr/0007-approvals.md), [ADR 0051](../adr/0051-approve-once-per-run.md), [ADR 0053](../adr/0053-smarter-command-analysis.md), [ADR 0063](../adr/0063-canary-covers-every-hooked-tool.md)). Admins edit the policy in the apps ([ADR 0049](../adr/0049-policy-editor-in-the-apps.md)).
- **Harness sandboxes.** New installs turn on the harness's own sandbox for Claude Code and Codex ([ADR 0055](../adr/0055-harness-sandbox-defaults.md)).

## Bots: a token for each run

Each run of a Bot gets its own token (`sbb_<bot>.<id>.<HMAC-SHA256>`) ([ADR 0083](../adr/0083-per-run-tokens.md)):

- It is valid for that run only, for at most the run timeout plus 60 seconds, and is revoked as soon as the run ends, however it ends.
- botd holds what it may do in memory; nothing survives a restart.
- A Bot can do no more than its owner. A disabled owner's Bot can do nothing. A Bot can't act as another Bot.
- On machines, the agent's relay checks the token too, so nothing left on a machine reaches botd after the run.
- Issue and revoke are both audited (`bot.token_issued`, `bot.token_revoked`).

## Isolation between users

| Setup | What keeps users apart |
|-------|------------------------|
| **One server** | Each user's own working folder and facts ([ADR 0029](../adr/0029-per-user-isolation.md)). Each user's Bots run as that user's own Unix account (`sb-u-<id>`), which can't read botd's files, the database, the master key or other users' folders. On by default for new installs, for every harness ([ADR 0037](../adr/0037-per-user-unix-accounts.md), [ADR 0058](../adr/0058-harness-os-user-by-default.md)). A teammate's run of a shared Bot gets an account of its own for that owner's Bots only with `ISOLATION=users`, `SHARED_BOTS=isolated` and `ISOLATION_TEAMMATES` on (its default when both are set). `SHARED_BOTS` defaults to `open` here, so by default a teammate's run uses the owner's account, access and keys ([ADR 0064](../adr/0064-teammate-accounts-on-one-server.md), [ADR 0066](../adr/0066-removing-teammate-accounts-on-one-server.md)). |
| **Managed** | One machine per user (Linode VM or Incus container). A Linode VM has a kernel of its own. Incus containers on one host share its kernel, so a kernel escape would cross every user on that host; `MACHINE_OWN_KERNEL_TIERS` makes botd refuse to start with containers for the tiers it lists, and refuse runs on any machine of those tiers that isn't one of its VMs ([ADR 0065](../adr/0065-incus-container-machines.md), [ADR 0120](../adr/0120-managed-substrate.md)). A Bot runs only on its owner's machine, never on the server or another user's machine ([ADR 0036](../adr/0036-bots-on-the-users-machine.md)). On the machine, two settings separate runs further, both **off by default**. `MACHINE_BOT_USER=on` runs Bots as the unprivileged `superbot-bots` user; without it they run as root, like the machine agent, and can read the agent's key ([ADR 0043](../adr/0043-bots-own-os-user-on-machines.md)). `MACHINE_TEAMMATE_USERS=on` (needs `MACHINE_BOT_USER=on`) runs teammates as their own OS users with their own harness logins and screens; without it, a teammate's run of a shared Bot shares the owner's Bots' user and home, so its tools can read the owner's folder and logins, though botd still withholds the owner's keys and facts ([ADR 0046](../adr/0046-shared-bots-under-isolation.md), [ADR 0048](../adr/0048-teammates-own-os-user-on-machines.md), [ADR 0062](../adr/0062-teammate-harness-logins.md)). Either way, no run reaches another user's machine. |
| **Machine network** | Linode: only with `MACHINE_FIREWALL=on` (off by default), a Cloud Firewall drops inbound except botd to the agent port; SSH closed unless the operator lists sources. Without it, the Linode is open to the internet and only mutual TLS guards the agent port ([ADR 0035](../adr/0035-machine-firewall-auto-enroll.md)). Incus: botd requires `MACHINE_FIREWALL=on`; unprivileged containers with AppArmor and seccomp, and a firewall that keeps them off each other, the host and private ranges ([ADR 0065](../adr/0065-incus-container-machines.md)). |
| **Secrets** | Personal secrets reach only that person's own Bots. Each is sealed with its user and name. botd's own secrets never reach a run ([ADR 0029](../adr/0029-per-user-isolation.md), [ADR 0044](../adr/0044-client-personal-secrets.md)). |

Tested in CI on real hosts: no Bot reaches another user's folder or logins, or botd's files ([`deploy/test-isolation.sh`](../../deploy/test-isolation.sh), [`deploy/test-isolation-harness.sh`](../../deploy/test-isolation-harness.sh)), and Incus containers on a real host ([ADR 0069](../adr/0069-validating-incus-containers-on-a-real-host.md)).

**Planned:** per-user cgroup and egress limits for runs (M5, [roadmap](../ROADMAP.md)).

## Audit log

- Records sign-ins and failures, user and role changes, Bot and routine changes, policy and approval decisions, each harness run and its result, denied access, licence, SCIM and machine events ([ADR 0009](../adr/0009-audit-events.md)).
- Each event names its actor (user, Bot or system) with email, role, sign-in method, IdP, session, and who a Bot acted for ([ADR 0019](../adr/0019-audit-actors.md)).
- Append-only: database triggers refuse updates, and deletes except retention pruning. This guards against mistakes and API misuse, not someone with write access to the database file. Kept forever unless `AUDIT_RETENTION_DAYS` is set.
- Admins view and filter it in the apps and export CSV ([ADR 0028](../adr/0028-client-admin-console-link-and-audit.md), [ADR 0060](../adr/0060-client-audit-detail-and-filters.md)).
- **Access reviews**: admins see one report of everyone's role, status, team, SCIM tenant, second factor, last sign-in, Bot access, sessions and API tokens (never the tokens), and machine, export it as dated CSV, and sign it off; the sign-off is an `access_review.completed` event ([ADR 0099](../adr/0099-access-review-report.md)).
- **Planned:** tamper evidence (hash chain, write-once storage, shipping events off the server) (M5, [ADR 0009](../adr/0009-audit-events.md)).

## Licence key (self-host)

- A signed JWT (EdDSA, Ed25519) checked offline against public keys built into botd. It never calls home ([ADR 0038](../adr/0038-self-host-license-key.md)).
- It sets the number of seats and the edition, with a 14-day grace period after expiry.
- Without a valid licence, no Bot runs, unless `TESTING_MODE=on`. Admins can still sign in to install one ([ADR 0068](../adr/0068-no-free-tier.md)).
