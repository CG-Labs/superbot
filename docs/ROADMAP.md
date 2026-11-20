# SuperBot product roadmap

**Status:** Living plan for CG-Labs commercial productization of SuperBot. Owner decisions of 19 Nov 2026 are folded in ([below](#decisions-19-nov-2026)).  
**Baseline (Nov 2026):** Production-style self-host on a 4 GB Linode via [`deploy/install.sh`](../deploy/README.md) or [Docker Compose](../deploy/README.md#docker-compose-supported); [`apps/client`](../apps/client/) (Expo web + native + Electron) against `botd` with shared HTTP Basic auth.

Sizes are **S / M / L / XL** (effort and cross-cutting risk), not calendar commitments. Work is tracked as GitHub issues in milestones **M1–M5** ([tracking](#tracking)).

---

## Vision

SuperBot is a **team of AI coworkers**—each with memory, routines, and a Linux “computer”—that customers can **self-host** or run on **CG-Labs managed hosting**. Buyers get harness choice (Claude Code, Codex, Pi, Hermes Agent, …) without rebuilding orchestration, memory, or Bot-to-Bot workflows.

**North star:** An organization deploys SuperBot once, people sign in with the identity they already use (Apple, GitHub, Microsoft, Google, or their company IdP), and each person gets their own computer and Bots with clear **roles, audit, and isolation**—comparable to polished SaaS agents, but with data and compute under customer control.

### Target customers

| Segment | Need | Fit today | Gaps |
|--------|------|-----------|------|
| **Technical solopreneur / founder** | Personal VPS, one password, one harness | Strong (install + client + approvals + branding) | EAS project for store builds |
| **Small team (5–30)** | Shared instance, several humans, least privilege | Users, roles, sessions, SSO (Entra, Google, generic OIDC); shared and private Bots in review | Apple and GitHub sign-in, per-user computers |
| **Growth company (30–500)** | Managed hosting, billing, SSO, support | None | Control plane, per-user tiers |
| **Enterprise (500+)** | Entra/Google/Okta SSO, SCIM, SOC 2, UK/EU residency, procurement | None | Full enterprise pillar |

### Principles

1. **Rust first** for server, control plane, and isolation daemons; thin TS only where stores/browsers require it (`AGENTS.md`).
2. **Harness agnostic** — adapters stay small; product value is orchestration, memory, governance, and ops.
3. **Self-host parity** — every managed feature should be reproducible on customer infrastructure (with license where applicable).
4. **Secure by default** — no anonymous API on the public internet; move from shared password to identity, sessions, and policy.
5. **Honest scope** — ship vertical slices (e.g. one IdP end to end before the next) rather than checkbox features without enforcement.

---

## Decisions (19 Nov 2026)

Product decisions by the product owner, David Kennedy, on 19 Nov 2026. They replace the matching open questions.

| # | Topic | Decision | Status |
|---|-------|----------|--------|
| 1 | **Isolation** | One computer (VM or container) per **user**, not per Bot. A user's Bots share that user's computer. Managed hosting: one computer per user, or **one container per user** when running on a virtualised server ([#29](https://github.com/CG-Labs/superbot/issues/29); [ADR 0025](adr/0025-control-plane-linode.md), [PR #77](https://github.com/CG-Labs/superbot/pull/77)). | Decided |
| 2 | **Managed platform** | Provision per-user machines with the **Linode API** until a production-ready system exists. | Decided for now; revisit before M4 |
| 3 | **Pricing** | **Per user**, with several tiers. Tiers differ by language model access and other limits. Models can stay hidden in the back end: users pick a tier, not a model. | Decided |
| 4 | **SSO** | Support all the major identity providers: **Sign in with Apple, GitHub, Microsoft Entra ID, Google**, plus a generic **OIDC/SAML** path for others (e.g. Okta). A SCIM stub (users only) ships in M2 ([ADR 0023](adr/0023-scim.md)); full SCIM stays in M5. | Decided |
| 5 | **Interface** | [`apps/client`](../apps/client/) (Expo web at `/app/` + native + Electron) is the single primary interface for end users. The server-rendered pages stay only as an admin fallback: admin console, sign-up approvals, break-glass sign-in, health ([#28](https://github.com/CG-Labs/superbot/issues/28), [ADR 0027](adr/0027-expo-primary-hermes-default.md)); the console no longer has chat, Bots, or screens ([#82](https://github.com/CG-Labs/superbot/issues/82), [ADR 0032](adr/0032-console-admin-only.md)). | Decided by the owner, 19 Nov 2026 |
| 6 | **Back end / harness** | [Hermes Agent](https://github.com/NousResearch/hermes-agent) is the **default harness for managed tiers**. botd keeps orchestration, approvals, audit, routines, and memory ([ADR 0011](adr/0011-hermes-agent-backend.md), accepted; [ADR 0027](adr/0027-expo-primary-hermes-default.md)). The adapter is built ([#27](https://github.com/CG-Labs/superbot/issues/27), [ADR 0015](adr/0015-hermes-adapter.md)); ADR 0011's gate is the managed-tier release checklist. Self-host keeps Hermes opt-in. | Decided by the owner, 19 Nov 2026 |
| 7 | **Enterprise SLA** | **Hermes Agent** (pinned stable release) carries the Enterprise SLA. Claude Code, Codex, Pi, and other harnesses stay available as **best-effort** ([ADR 0027](adr/0027-expo-primary-hermes-default.md)). | Decided by the owner, 19 Nov 2026 |

---

## Current state (honest audit)

What exists in **CG-Labs/superbot** today:

| Area | Reality |
|------|---------|
| **Auth** | Users in SQLite with roles (admin, member, read-only) enforced per API route; server-side sessions (HttpOnly cookie for `web/`, bearer token for the client and `botctl`) with idle and absolute TTLs, logout, and admin revoke; one-time sign-in codes from an admin; `AUTH_PASSWORD` kept as break-glass owner login (`AUTH_BREAK_GLASS`, on by default) ([ADR 0012](adr/0012-users-sessions-rbac.md)). `ALLOW_NO_AUTH` on loopback only; `ALLOWED_HOSTS`; per-Bot `BOT_TOKEN` for `botctl`, capped by the Bot owner's role ([ADR 0029](adr/0029-per-user-isolation.md)). Sign in with Microsoft Entra ID, Google, and any generic OIDC IdP, several at once ([ADR 0014](adr/0014-oidc-sso-entra.md), [ADR 0016](adr/0016-sso-multi-provider.md)); GitHub and Apple sign-in merged ([PR #69](https://github.com/CG-Labs/superbot/pull/69), [ADR 0018](adr/0018-sso-github-apple.md)). Sign-ins, revokes, and user changes are audited; per-user audit actors (email, role, sign-in method, IdP, session, on behalf of) merged ([PR #70](https://github.com/CG-Labs/superbot/pull/70), [ADR 0019](adr/0019-audit-actors.md)). Bot ACLs (owner, shared or private, viewer/operator grants) merged ([PR #68](https://github.com/CG-Labs/superbot/pull/68), [ADR 0017](adr/0017-bot-acls.md)). Admin portal for onboarding in the client (users, roles, one-time codes with invite links, sessions, SSO links, Bot access) merged ([PR #72](https://github.com/CG-Labs/superbot/pull/72), [ADR 0021](adr/0021-admin-portal.md)). Access requests from the landing page, approved by an admin into a user and a one-time code (`botctl signup`, or **Requests** in the admin portal; no email yet), merged ([PR #74](https://github.com/CG-Labs/superbot/pull/74), [ADR 0022](adr/0022-landing-and-signups.md)). SCIM provisioning stub (users only, off by default, `botctl scim`) merged ([PR #75](https://github.com/CG-Labs/superbot/pull/75), [ADR 0023](adr/0023-scim.md)); its auth review and hardening merged ([PR #78](https://github.com/CG-Labs/superbot/pull/78), [ADR 0026](adr/0026-scim-review-hardening.md)). |
| **Client** | The single primary interface ([ADR 0027](adr/0027-expo-primary-hermes-default.md)): members who open `/console/` or sign in at `/login` (password, code, or web SSO) land on `/app/`, and the web build picks up that browser session. Login, SSE chat, bots CRUD (including changing a Bot's harness), Bot-to-Bot labels, copy, models/effort, routine create/edit/delete, live screen viewer (iframe / WebView) with take over, handoff cards and alerts; for admins, the Users portal, an audit log viewer with filters and CSV export, and a link to the admin console ([ADR 0028](adr/0028-client-admin-console-link-and-audit.md)); on managed tiers, the Bot's plan instead of the model picker for non-admins ([ADR 0033](adr/0033-tiers-model-routing.md)); no push or biometric lock; placeholder EAS `projectId`; SuperBot icons, splash and store art (merged, [PR #62](https://github.com/CG-Labs/superbot/pull/62)). |
| **Server** | SQLite single-tenant schema; harnesses run with their own prompts off, gated by the SuperBot **policy engine and approval queue** (default **ask** on fresh installs; [ADR 0007](adr/0007-approvals.md)); append-only **audit events** for admin actions with CSV export (`/api/audit`, `botctl audit export`, the Audit log in the client and the admin console; [ADR 0009](adr/0009-audit-events.md)); per-user actors with IdP, plus Bot runs and harness invocations, merged ([PR #70](https://github.com/CG-Labs/superbot/pull/70), [ADR 0019](adr/0019-audit-actors.md)). **Secrets** from env/`_FILE` or saved encrypted in SQLite (XChaCha20-Poly1305, master key outside `DATA_DIR`), redacted from chats, events, and audit ([ADR 0010](adr/0010-secrets.md)); external vaults not built (trait seam only). **Tiers** ([ADR 0033](adr/0033-tiers-model-routing.md)): per-user plans whose routing table picks each run's harness, provider and model, with Bot and monthly run limits; off (one open tier) unless `TIERS_FILE` is set. |
| **Harnesses** | Claude Code, Codex, Pi, and Hermes Agent adapters. Hermes is opt-in in the installer and image, pinned to v0.23.2 ([ADR 0011](adr/0011-hermes-agent-backend.md), [ADR 0015](adr/0015-hermes-adapter.md)). Hermes becomes the default for managed tiers and carries the Enterprise SLA; the others are best-effort ([ADR 0027](adr/0027-expo-primary-hermes-default.md)). |
| **Deploy** | Ubuntu bash installer (piped-install fix merged, [#3](https://github.com/CG-Labs/superbot/pull/3)), systemd, Caddy, daily SQLite backup timer; Docker Compose (`Dockerfile` + `deploy/docker/`: `botd`, Caddy, backup sidecar), smoke-tested in CI ([ADR 0006](adr/0006-docker-compose.md)). Both build the Expo web client from the deployed commit and serve it at `/app/` ([ADR 0013](adr/0013-serve-web-client.md)); the installer no longer refuses a good client build at random, and exits 3 with a final warning when this run's client was not installed, keeping the previous one ([#93](https://github.com/CG-Labs/superbot/issues/93)). `/` is a public landing page with a request-access form at `/get-started`; the built-in page moved to `/console/` (merged, [PR #74](https://github.com/CG-Labs/superbot/pull/74), [ADR 0022](adr/0022-landing-and-signups.md)). |
| **Multi-tenancy** | One deployment = one org in practice (`DATA_DIR`, `WORKSPACE_DIR`). Each user has their own folder, facts file, secrets, and per-Bot tokens on the server ([ADR 0029](adr/0029-per-user-isolation.md)); all Bots still run as one OS user. |
| **Observability** | `journalctl`, healthz; no metrics/tracing product. |
| **Compliance** | No certifications. Audit log with CSV export and configurable retention (`AUDIT_RETENTION_DAYS`, default keep forever). MIT license at repo root (see [Licensing & upstream](#licensing--upstream)). |

---

## Identity (SSO) — what we must build

Replacing or augmenting the shared Basic password is not a login screen swap. **SSO** implies:

| Capability | Why it follows from SSO |
|------------|-------------------------|
| **Multi-user accounts** | IdP subjects map to SuperBot users; no more one shared password per deployment. One user can link several IdPs. |
| **Roles / RBAC** | Admin, operator, viewer (and custom) on bots, routines, settings, and harness credentials. |
| **Per-user & shared Bots** | Ownership, delegation, and “team bots” with explicit ACLs. |
| **Session management** | OIDC refresh, idle timeout, revoke-all, device/session list for admins. |
| **Audit logs** | Who authenticated (and with which IdP), API actions, bot runs, harness invocations, config changes (immutable export). |
| **SCIM provisioning** | M2 stub: Entra and Okta create, update, disable, and soft-delete users with per-tenant tokens, linked to SSO identities, never roles ([ADR 0023](adr/0023-scim.md), [setup guide](sso/scim.md)). M5: groups and group→role mapping, Google Workspace, bulk. |
| **IdP targets** | **Sign in with Apple**, **GitHub**, **Microsoft Entra ID**, **Google** (consumer and Workspace), and a **generic OIDC / SAML** connector for the rest (e.g. Okta, OneLogin, Keycloak). Once the iOS app offers third-party social logins, App Store guideline 4.8 requires a privacy-focused login option too; Sign in with Apple meets it. |

Basic auth may remain for **break-glass** and **self-host hobby** tiers only, behind explicit policy.

---

## Milestones

### M0 — Baseline operator install (done)

| | |
|--|--|
| **Goal** | Credible single-owner production on a VPS. |
| **Scope** | `deploy/install.sh`, hardened `botd` auth, embedded + Expo client, harness adapters, memory/routines/Bot-to-Bot. |
| **Exit criteria** | HTTPS VPS; password rotation; backup timer; client talks to production origin (Columbia dogfood). |
| **Size** | — (achieved) |
| **Dependencies** | None |

---

### M1 — Foundation hardening

**Phase label:** *Foundation hardening*

| | |
|--|--|
| **Status** | **Merged:** installer fix ([#3](https://github.com/CG-Labs/superbot/pull/3)), Docker Compose ([#6](https://github.com/CG-Labs/superbot/pull/6), [ADR 0006](adr/0006-docker-compose.md)), approvals + harness policy ([#5](https://github.com/CG-Labs/superbot/pull/5), [ADR 0007](adr/0007-approvals.md)), client routine editor / screen viewer / handoff ([#7](https://github.com/CG-Labs/superbot/pull/7), [ADR 0008](adr/0008-client-screen-auth.md)), audit events + CSV ([#8](https://github.com/CG-Labs/superbot/pull/8), [ADR 0009](adr/0009-audit-events.md)), secrets store ([#9](https://github.com/CG-Labs/superbot/pull/9), [ADR 0010](adr/0010-secrets.md)), brand assets ([PR #62](https://github.com/CG-Labs/superbot/pull/62), 19 Nov 2026, [#12](https://github.com/CG-Labs/superbot/issues/12), [brand guide](brand.md)). **Remaining:** real EAS `projectId`. |
| **Goal** | Reduce blast radius and improve deploy surface before selling to strangers. |
| **Scope** | Approvals MVP (**done**); secrets via env/sealed store, not plaintext in SQLite (**done**); structured audit events (**done**); Docker Compose one-click (**done**); harness policy flags (**done**); client routine editor, screen viewer, handoff UI (**done**); brand assets (**done**); real EAS `projectId`. |
| **Exit criteria** | Compose documented as supported path (**done**); approvals cover send-email/shell/file-delete class tools (**done**); audit export CSV (**done**); client routine CRUD + screen iframe (**done**); secrets not in plaintext at rest (**done**); client builds under the real EAS project with SuperBot branding. |
| **Size** | **L** |
| **Dependencies** | M0 |

---

### M2 — Multi-user + SSO

**Phase label:** *Multi-user + SSO*

| | |
|--|--|
| **Goal** | First **sellable team** product: real users and familiar sign-in. |
| **Status** | **Complete** (19 Nov 2026): every M2 issue is closed. Slice 1 merged ([#61](https://github.com/CG-Labs/superbot/pull/61), [ADR 0012](adr/0012-users-sessions-rbac.md)): user store, server-side sessions with TTLs and revoke, RBAC v1 on the API, break-glass, `botctl` user/session commands, auth audit events, client token flow. Slice 2 merged: Microsoft Entra ID sign-in on a generic OIDC layer ([PR #65](https://github.com/CG-Labs/superbot/pull/65), [#17](https://github.com/CG-Labs/superbot/issues/17), [ADR 0014](adr/0014-oidc-sso-entra.md), [setup guide](sso/entra.md)). Slice 3 merged: Google sign-in with a server-checked Workspace domain restriction, and a generic OIDC connector (Okta, Keycloak, Auth0, …) configured in `.env`, with several providers on at once and one user per person across them ([PR #66](https://github.com/CG-Labs/superbot/pull/66), [#18](https://github.com/CG-Labs/superbot/issues/18), [#19](https://github.com/CG-Labs/superbot/issues/19), [ADR 0016](adr/0016-sso-multi-provider.md), guides for [Google](sso/google.md) and [OIDC](sso/oidc.md)). Slice 4 merged: bot ACLs: each Bot has an owner, is shared or private, and can grant users viewer or operator; enforced on every Bot, chat, routine, screen, and approval route and in the live stream; existing Bots stay shared; `botctl bot` commands, audit events, and a sharing switch in the client ([PR #68](https://github.com/CG-Labs/superbot/pull/68), [#20](https://github.com/CG-Labs/superbot/issues/20), [ADR 0017](adr/0017-bot-acls.md)). Slice 5 merged: Sign in with GitHub (numeric-id identity, verified primary email, optional org restriction checked on GitHub's API, GitHub Enterprise Server) and Sign in with Apple (per-sign-in ES256 client secret from a key in the secrets store, form-post callback, Hide My Email) ([PR #69](https://github.com/CG-Labs/superbot/pull/69), [#15](https://github.com/CG-Labs/superbot/issues/15), [#16](https://github.com/CG-Labs/superbot/issues/16), [ADR 0018](adr/0018-sso-github-apple.md), guides for [GitHub](sso/github.md) and [Apple](sso/apple.md)). Slice 6 merged: audit log with per-user actors and IdP: email, role, sign-in method (break-glass password, code, SSO, Bot token), IdP type and provider, session, and on-behalf-of on every event; Bot runs and harness invocations attributed to whoever asked; filters by person, method, IdP, session in `/api/audit`, CSV, `botctl`, and the web Audit log ([PR #70](https://github.com/CG-Labs/superbot/pull/70), [#23](https://github.com/CG-Labs/superbot/issues/23), [ADR 0019](adr/0019-audit-actors.md)). Slice 7 merged: SAML bridge: SAML-only IdPs (ADFS, Okta, OneLogin, PingFederate) sign in through a Keycloak broker that checks the SAML response; botd accepts only people the configured IdP vouched for and keys them by the IdP's entity ID and NameID ([PR #71](https://github.com/CG-Labs/superbot/pull/71), [ADR 0020](adr/0020-saml-bridge.md), [setup guide](sso/saml.md)); with it [#19](https://github.com/CG-Labs/superbot/issues/19) is complete. Slice 8 merged: admin portal for onboarding in the client: add people, one-time sign-in codes (1 hour, 24 hours, or 7 days) with a ready-to-send invite and link, roles, disable, sign out everywhere, SSO account links, last sign-in method, and each person's Bot access ([PR #72](https://github.com/CG-Labs/superbot/pull/72), [ADR 0021](adr/0021-admin-portal.md)). Slice 9 merged: auth pen-test review: no Critical or High findings; fixed CSRF on cached break-glass and no-auth callers, unlimited Basic password guesses, unverified Entra email at JIT sign-up, and cookie tossing (`__Host-` cookies); a router walk test checks every non-public route needs credentials and the right role ([PR #76](https://github.com/CG-Labs/superbot/pull/76), [#25](https://github.com/CG-Labs/superbot/issues/25), [report](security/auth-review-2026-11.md), [ADR 0024](adr/0024-auth-review-hardening.md)). Slice 10 merged: SCIM stub: Entra ID and Okta provision users at `/scim/v2` (discovery, Users list/filter/get/create/replace/patch, soft delete) with per-tenant `sbp_` tokens from `botctl scim`, `externalId` linked to SSO identities (never email), deactivation ending sessions, no role changes, audit events with the token as actor; off by default (`SCIM=on`); groups return an empty list ([PR #75](https://github.com/CG-Labs/superbot/pull/75), [#24](https://github.com/CG-Labs/superbot/issues/24), [ADR 0023](adr/0023-scim.md), [setup guide](sso/scim.md)). Close-out for [#24](https://github.com/CG-Labs/superbot/issues/24): design and stub done; groups, group→role mapping, Google Workspace, and bulk move to M5. Slice 11 merged: SCIM auth review (the addendum to slice 9's review): no Critical or High findings; fixed bad tokens from an IdP's shared addresses blocking its valid token (which could hold off deprovisioning), stale SCIM updates undoing an admin's disable, and unclear audit of revoked tokens and SCIM tokens sent to `/api`; the router walk test now covers `/scim/v2` (only a live SCIM token works there, it works nowhere else, and `SCIM=off` turns off every route) ([PR #78](https://github.com/CG-Labs/superbot/pull/78), [report](security/auth-review-2026-11-scim.md), [ADR 0026](adr/0026-scim-review-hardening.md)). Slice 12: interface decided ([#28](https://github.com/CG-Labs/superbot/issues/28), [ADR 0027](adr/0027-expo-primary-hermes-default.md)): the Expo client is the interface for everyone; `/console/` is for admins only and sends others to `/app/`; sign-in and web SSO land non-admins on `/app/`, which picks up the browser session; the client gained harness switching, delete confirmation, Bot-to-Bot labels, and copy. Slice 13: the client links admins to the console ([#80](https://github.com/CG-Labs/superbot/issues/80), [ADR 0028](adr/0028-client-admin-console-link-and-audit.md)): **Admin console ↗** in the sidebar, for admins only, opens `/console/` on the same origin from the web build and in the system browser on phones. Carried over, not an M2 blocker: pause or hand over a disabled user's Bot routines (SCIM-05, Low, accepted for M2 in the [SCIM review](security/auth-review-2026-11-scim.md)). |
| **Scope** | User store; JWT/session cookies for client; **Sign in with Apple**, **GitHub**, **Microsoft Entra ID**, **Google** (OIDC/OAuth); **generic OIDC** connector (Okta and others) and a SAML bridge where an IdP needs it; account linking (several IdPs per user); RBAC v1 (org admin, member, read-only); bot ACLs; migrate from `AUTH_PASSWORD` to SSO-primary with break-glass; session TTL and admin revoke; audit log with per-user actors and IdP; SCIM **design + stub** (full SCIM in M5). Parallel tracks: Hermes Agent harness adapter ([ADR 0011](adr/0011-hermes-agent-backend.md), option a, **done**); interface decision (Expo client primary, `web/` as admin fallback; **decided and built**, [ADR 0027](adr/0027-expo-primary-hermes-default.md)). |
| **Exit criteria** | Columbia org signs in with SSO only; each of Apple, GitHub, Entra, Google, and one generic OIDC IdP (e.g. Okta) works end to end; two roles enforced on API; shared vs private bots; pen-test style review of auth bypass; client uses token flow (no password in SecureStore for SSO tenants). |
| **Size** | **XL** |
| **Dependencies** | M1 (audit, approvals shape, secrets) |

---

### M3 — Private beta (managed + self-serve packaging)

**Phase label:** *Private beta*

| | |
|--|--|
| **Goal** | Paid early adopters on **managed hosting** and polished **self-host** SKU. |
| **Status** | **Started.** Control-plane foundation merged ([#29](https://github.com/CG-Labs/superbot/issues/29), [ADR 0025](adr/0025-control-plane-linode.md), [PR #77](https://github.com/CG-Labs/superbot/pull/77)): a `machines` table (one live machine per user), a Linode API v4 client behind a provider trait, tier → plan mapping in config, admin endpoints to request, suspend, resume, resize and destroy a user's machine, a reconciler, and audit events for each change. Off unless `LINODE_TOKEN` is set, so self-host is unchanged. Machine enrollment and mutual TLS done ([ADR 0031](adr/0031-machine-enrollment-mtls.md)): a one-time, 60-minute enrollment token per machine in its cloud-init data, exchanged for a 30-day client certificate from a control-plane CA derived from the master key; certificates rotate, are held on suspend and revoked on destroy, loss or by an admin; botd pins each machine's certificates when calling it; `machines.enrollment` and the last heartbeat show the state; every step is audited; a `superbot-machine` agent enrolls and answers heartbeats. Off unless `MACHINE_CONTROL_URL` is set. Machines come up locked down and enrolled with no manual steps ([ADR 0035](adr/0035-machine-firewall-auto-enroll.md)): one Linode Cloud Firewall per control plane drops inbound but for the agent port from the control plane (SSH only if configured), is attached at create, kept right by the reconciler and deleted with the last machine; cloud-init downloads botd's own `superbot-machine` (CA-pinned, SHA-256-checked), enrolls once, scrubs the token and starts the unit; machines that miss the enrollment deadline are flagged and audited. Off unless `MACHINE_FIREWALL=on`. Bots run on their owner's machine ([ADR 0036](adr/0036-bots-on-the-users-machine.md)): `MACHINE_ROUTING=off|assigned|on` (off by default) with admin assign/unassign (`botctl machine assign|unassign|placement`); a health check before each run; refusal with a reason when the machine is down, unassigned, outdated or missing the harness, never a fallback to the server or another user's machine; a versioned job protocol over mutual TLS that streams each harness run back (chat, stop, timeouts); approvals and `botctl` from the machine through the agent's loopback relay; memory and facts synced back to botd; placement and dispatch audited; tested end to end with a real agent over mTLS. Harness CLIs and agent upgrades on machines ([ADR 0039](adr/0039-machine-harnesses-and-agent-upgrades.md)): `MACHINE_HARNESSES` (Claude Code, Codex, Pi and Hermes at pinned versions, checked by hash, with Node.js) are installed by the agent itself once it enrolls and reported in its heartbeat, so `harness_missing` clears with no manual steps; the agent upgrades itself to botd's build over the pinned channel (SHA-256-checked, swapped atomically, kept once botd reaches the new agent, otherwise put back), `MACHINE_AGENT_UPGRADES=manual|auto`, with an admin trigger and hold (`botctl machine agent|upgrade|harnesses`), all audited; off unless set. Harness logins and the user's folder on machines ([ADR 0041](adr/0041-machine-harness-logins-and-folder-copy.md)): with `MACHINE_HARNESS_LOGINS=on`, Claude Code and Codex log in on the user's machine with the CLI's own login, run by the agent in a terminal over mutual TLS and relayed by botd (`botctl machine harness-login|harness-logins|harness-logout`); the credentials stay on the machine, heartbeats report each login's state, and runs with no login there and no key are refused with `harness_not_logged_in`; with `MACHINE_FOLDER_SYNC=on`, assigning a user copies their folder, facts and Bots' memory to it (SHA-256-checked, resumable, size-limited, never over changes made there; `botctl machine folder|sync`), with botd still the keeper of memory and facts; every step audited; off unless set. **Remaining on #29:** screens on machines, a separate OS user for Bots on the machine, upgrading machines enrolled before ADR 0039, and per-user containers on a virtualised server. Per-user isolation, first slice (part of [#30](https://github.com/CG-Labs/superbot/issues/30), [ADR 0029](adr/0029-per-user-isolation.md)): each user's Bots work in that user's folder (`WORKSPACE_DIR/users/<id>`) with that user's `USER.md` and their own secrets (`/api/me/secrets`); each Bot run gets its own token, can act only as itself and do no more than its owner (fixes AUTH-07); the runner picks the owner's machine as the routing target (`MACHINE_ROUTING`, off by default, refuses rather than falls back); a test walks every Bot route as another user and their Bot. OS isolation on one server done ([ADR 0037](adr/0037-per-user-unix-accounts.md), `ISOLATION=users`, off by default): each user's Bots run as their own Unix account (`sb-u-<id>`) through a minimal sudo rule, in folders other accounts can't open, with their own harness logins (`botctl user harness-login`); Claude Code and Codex only so far; a root test in CI walks one user's run against another's folder and logins. Bots routed to their owner's own machine skip it: that machine is theirs alone. **Remaining on #30:** per-user screens, where shared team Bots run, and a client screen for personal secrets. Client audit log viewer done ([#81](https://github.com/CG-Labs/superbot/issues/81), [ADR 0028](adr/0028-client-admin-console-link-and-audit.md)): admins filter by action, who, person, sign-in method, outcome, and date range, page back, and export CSV (a download on web, the share sheet on phones); the server already kept the log admin-only. Console end-user features retired ([#82](https://github.com/CG-Labs/superbot/issues/82), [ADR 0032](adr/0032-console-admin-only.md)): `/console/` is now a minimal admin and break-glass page with Users, sign-up Requests, Machines (the control plane's per-user machines), the Audit log, and Settings (approval mode, sign-in options, server secrets, SCIM tokens); chat, Bots, Bot approvals, and screens are only in the client; the page runs under a strict CSP; tests check every `/api` call in the console and in the client's `api.ts` is still routed. Backup restore drill ([#40](https://github.com/CG-Labs/superbot/issues/40), [ADR 0030](adr/0030-backup-restore-drill.md), [guide](ops/backup-restore.md)): one `superbot-backup` / `superbot-restore` tool and archive format for the installer and Compose (whole `DATA_DIR`, online SQLite copy), optional age encryption, `superbot-restore --check`; CI drills restore onto a fresh host (installer: real systemd units, service user deleted and reinstalled; Compose: all volumes deleted) within a 5-minute restore budget; targets RPO 24 h by default and 1 h recommended for teams and managed, RTO 1 h. Remaining on #40: managed per-user backups to customer S3 and a contractual RPO/RTO. Model routing hidden behind tiers ([#32](https://github.com/CG-Labs/superbot/issues/32), [ADR 0033](adr/0033-tiers-model-routing.md)): named tiers from `TIERS_FILE` with harness/provider/model routes and per-user limits (`maxBots`, `monthlyRuns`; `monthlyTokens` shown, not enforced); a tier per user set by admins (`botctl user tier`, audited); every run takes the route its owner's tier picks, and models outside it are refused; only admins see model names, and the client shows the plan instead of the model picker. Without `TIERS_FILE` one open `self-host` tier keeps today's behaviour. Billing v0, first slice built ([#31](https://github.com/CG-Labs/superbot/issues/31), [ADR 0040](adr/0040-billing-v0-tier-limits.md)): each tier also caps routine runs per UTC day and sets its users' machine size; Bots, runs, routine runs and machine sizes past a user's plan are refused and audited; admins see everyone's use against their limits (`GET /api/usage`, `botctl usage`, the client's user view); a signed Stripe webhook sets a user's tier from their subscription by the tiers' price ids, off unless `STRIPE_WEBHOOK_SECRET` is set, and botd never calls Stripe. **Remaining on #31:** checkout and the customer portal, linking users to Stripe customers, billing-period usage, token metering, storage limits, resizing machines on a tier change, an upgrade screen, and billing emails. Onboarding wizard ([#35](https://github.com/CG-Labs/superbot/issues/35), [ADR 0034](adr/0034-onboarding-wizard.md)): a Setup tab in the console that admins land on after a fresh install until someone finishes or hides it, with steps for the domain and HTTPS, sign-in (each SSO provider's readiness and redirect URI, saving its secret with no restart, `.env` templates for every provider type), plans (the tiers file or the open self-host tier), and a finish checklist (second admin, approvals on); `GET`/`PATCH /api/setup` (admins, audited), `botctl setup`, and a "Finish server setup" link for admins in the client. Settings read at startup are shown as commands to copy, not written. Self-host license key built ([#34](https://github.com/CG-Labs/superbot/issues/34), [ADR 0038](adr/0038-self-host-license-key.md)): Ed25519-signed keys checked offline, seat limits on every way a person becomes active (per-user Unix accounts take no extra seat), a 10-seat community edition without a key, and a grace period after a key ends; CG-Labs's signing key still to be made and its public half added. |
| **Scope** | Control plane that provisions **one machine per user via the Linode API**, or **one container per user** on a virtualised server (create, size by tier, suspend, destroy, backups; [#29](https://github.com/CG-Labs/superbot/issues/29), [ADR 0025](adr/0025-control-plane-linode.md), [PR #77](https://github.com/CG-Labs/superbot/pull/77)); **per-user isolation**: each user's Bots, workspace, harness logins, and screens live on that user's computer, with the org's shared data (users, roles, billing, audit) in the control plane; billing v0 (Stripe, **per-user subscription tiers**; limits and signed webhook **built**, [#31](https://github.com/CG-Labs/superbot/issues/31), [ADR 0040](adr/0040-billing-v0-tier-limits.md)); **model routing hidden behind tiers** (server picks provider and model per tier; users never pick a model on managed plans; **built**, [#32](https://github.com/CG-Labs/superbot/issues/32), [ADR 0033](adr/0033-tiers-model-routing.md)); **Hermes Agent as the default harness for managed tiers** (decided, [ADR 0027](adr/0027-expo-primary-hermes-default.md)), shipped once the [ADR 0011 checklist](adr/0011-hermes-agent-backend.md#recommendation) passes, and the harness behind the Enterprise SLA (others best-effort); client audit log viewer (**done**, [ADR 0028](adr/0028-client-admin-console-link-and-audit.md)), then retire the console's end-user features (**done**, [#82](https://github.com/CG-Labs/superbot/issues/82), [ADR 0032](adr/0032-console-admin-only.md)); license key for self-host (**built**: Ed25519-signed, checked offline, seat limits with a community edition and grace period; [#34](https://github.com/CG-Labs/superbot/issues/34), [ADR 0038](adr/0038-self-host-license-key.md); CG-Labs's signing key still to be made and its public half added); onboarding wizard (domain, IdP, tier; **done**, [#35](https://github.com/CG-Labs/superbot/issues/35), [ADR 0034](adr/0034-onboarding-wizard.md)), growing the approval-based sign-ups ([ADR 0022](adr/0022-landing-and-signups.md)) into self-serve with email, self-linked SSO, and sign-up data retention; client push notifications (routine completions, approvals), biometric optional unlock; **TestFlight / Play internal** tracks; published registry image with screens/computer use; DR: backup restore runbook + tested RPO target on managed tier. |
| **Exit criteria** | ≥3 paying design partners; user A's computer and Bots cannot reach user B's; tier limits enforced (models, Bots, machine size); restore drill documented; mobile beta installable from stores (internal). |
| **Size** | **L** |
| **Dependencies** | M2 |

---

### M4 — Public launch

**Phase label:** *Public launch*

| | |
|--|--|
| **Goal** | Open market SKU with clear plans and docs. |
| **Scope** | Pricing: **Free self-host OSS** plus published **per-user tiers** for managed (differ by model access, Bot count, machine size, routine runs, support) and **Enterprise** (custom); revisit the managed substrate (Linode API vs a production orchestrator); marketing site + docs portal; App Store / Play **production** listing; observability: metrics (Prometheus/OpenTelemetry), error reporting, uptime checks; status page for managed; GDPR privacy docs + DPA template; UK/EU region **option** for managed (London/Frankfurt). |
| **Exit criteria** | Public signup or contact-sales flow; published plans; SOC 2 **readiness** checklist (not full cert); SLO defined for managed uptime. |
| **Size** | **L** |
| **Dependencies** | M3 |

---

### M5 — Enterprise

**Phase label:** *Enterprise*

| | |
|--|--|
| **Goal** | Win regulated and large accounts. |
| **Scope** | **SCIM** provisioning (Entra, Google, Okta); full **SAML** where OIDC is insufficient; advanced RBAC (custom roles, service accounts); **per-user computer hardening** (harness runs as a separate OS user from `botd`, cgroup limits, egress policy, dedicated or VPC hosts for enterprise; see `docs/background/shared-vm-architecture.md`); secrets vault integration (Azure Key Vault, GCP SM, HashiCorp Vault); SIEM export (audit) with tamper evidence; **SOC 2 Type II** program; contractual **data residency** (UK/EU); optional air-gapped self-host; enterprise support & success playbooks. |
| **Exit criteria** | One enterprise logo on SCIM + Entra or Okta; per-user isolation passes a red-team scenario; SOC 2 auditor engaged; GDPR DPIA template for customers. |
| **Size** | **XL** |
| **Dependencies** | M4 |

---

## Security & isolation (cross-cutting)

| Topic | Today | Roadmap direction |
|-------|--------|-------------------|
| Harness permissions | Policy engine: default **ask** for risky tools; bypass only by opt-in (**done**: [ADR 0007](adr/0007-approvals.md)) | Hermes tool names in the policy (**done**, [ADR 0015](adr/0015-hermes-adapter.md)); per-Bot tokens (**done**, [ADR 0029](adr/0029-per-user-isolation.md)); approvals follow-ups ([list](approvals-followups.md)) |
| Compute isolation | Each user's Bots in that user's folder, with their own facts and secrets ([ADR 0029](adr/0029-per-user-isolation.md)); optionally one Unix account per user, with their own harness logins ([ADR 0037](adr/0037-per-user-unix-accounts.md)) | **One computer per user** (M3, [#30](https://github.com/CG-Labs/superbot/issues/30)): the user's machine; harness as separate OS user, cgroup and egress limits (M5) |
| Secrets | Env/`_FILE` or sealed in SQLite, master key outside backups, values redacted (**done**: [ADR 0010](adr/0010-secrets.md)); per-user secrets that reach only that user's Bots (**done**, [ADR 0029](adr/0029-per-user-isolation.md)); harness logins still on service user disk | Master-key rotation; external vaults + short-lived tokens (M5) |
| Audit | Append-only SQLite table, CSV export, retention setting (**done**: [ADR 0009](adr/0009-audit-events.md)) | Per-user actors and IdP subjects (**done**, M2: [PR #70](https://github.com/CG-Labs/superbot/pull/70), [ADR 0019](adr/0019-audit-actors.md)); viewer and CSV export in the client (**done**, [ADR 0028](adr/0028-client-admin-console-link-and-audit.md)); SIEM export and tamper evidence (M5) |
| Network | Caddy TLS, loopback `botd`; mTLS between the control plane and per-user machines, with one-time enrollment tokens and pinned certificates (**done**, off by default, [ADR 0031](adr/0031-machine-enrollment-mtls.md)); a Linode Cloud Firewall in front of every machine that drops inbound but for the agent port from the control plane, SSH only if configured (**done**, off by default, [ADR 0035](adr/0035-machine-firewall-auto-enroll.md)) | Per-user egress limits (M5) |
| Client | Session token in SecureStore (password only for servers from before ADR 0012) | OAuth tokens, certificate pinning (managed) |

---

## Client product gaps (tracked)

| Item | Priority | Milestone |
|------|----------|-----------|
| Screen viewer (voxl / `/api/bots/:id/screen`) | High | M1 ✓ |
| Handoff UI | High | M1 ✓ |
| Routine create/edit | High | M1 ✓ |
| `eas init` / real `projectId` | High | M1 |
| Custom icons / brand | Medium | M1 ✓ |
| Single primary interface (Expo client; `web/` as admin fallback), [ADR 0027](adr/0027-expo-primary-hermes-default.md) | High | M2 ✓ |
| Link to the admin console for admins on the web client ([#80](https://github.com/CG-Labs/superbot/issues/80), [ADR 0028](adr/0028-client-admin-console-link-and-audit.md)) | Low | M2 ✓ |
| Audit log viewer in the client (filters, CSV export) ([#81](https://github.com/CG-Labs/superbot/issues/81), [ADR 0028](adr/0028-client-admin-console-link-and-audit.md)) | Medium | M3 ✓ |
| Retire the console's end-user features (chat, Bots, screens), leaving a minimal admin page ([#82](https://github.com/CG-Labs/superbot/issues/82), [ADR 0032](adr/0032-console-admin-only.md)) | Medium | M3 ✓ |
| Suggested prompts in Bot details ([#83](https://github.com/CG-Labs/superbot/issues/83)) | Low | M3 |
| SSO sign-in (Apple, GitHub, Microsoft, Google, OIDC, SAML via bridge) | High | M2 |
| Plan instead of model picker on managed plans ([#32](https://github.com/CG-Labs/superbot/issues/32), [ADR 0033](adr/0033-tiers-model-routing.md)) | Medium | M3 ✓ |
| Push notifications | Medium | M3 |
| Biometric app lock | Medium | M3 |
| App Store / Play release | High | M4 |

---

## Deployment & hosting

| Mode | Today | Target |
|------|--------|--------|
| **Bash VPS installer** | Ubuntu 22.04 / 24.04 | Maintain; hardened CIS-aligned option |
| **Docker Compose** | **Supported** (M1 ✓): [`deploy/docker/`](../deploy/docker/), [docs](../deploy/README.md#docker-compose-supported) | Published registry image; screens/computer use in the image (M3) |
| **Managed cloud** | Control-plane foundation merged: Linode client, machine records, admin API, reconciler; off by default ([ADR 0025](adr/0025-control-plane-linode.md), [PR #77](https://github.com/CG-Labs/superbot/pull/77)); machine enrollment and mTLS ([ADR 0031](adr/0031-machine-enrollment-mtls.md)); machines come up behind a firewall and enroll on first boot with no manual steps, with an enrollment timeout ([ADR 0035](adr/0035-machine-firewall-auto-enroll.md)); Bots run on their owner's assigned machine ([ADR 0036](adr/0036-bots-on-the-users-machine.md)); harness CLIs and agent upgrades on machines ([ADR 0039](adr/0039-machine-harnesses-and-agent-upgrades.md)); harness logins and the user's folder on machines ([ADR 0041](adr/0041-machine-harness-logins-and-folder-copy.md)) | **Linode API**, one machine per user, or one container per user on a virtualised server (M3, [#29](https://github.com/CG-Labs/superbot/issues/29)); revisit the substrate before M4 |
| **Air-gapped** | Possible manual | M5 docs + license |

---

## Billing & licensing (commercial)

Pricing is **per user**. Managed tiers differ by language model access and other limits; models stay behind the tier, not in the user's hands.

| Tier (draft names) | Deployment | Models | Limits | Identity | Support |
|--------------|------------|--------|--------|----------|---------|
| **Community** | Self-host, MIT core | Bring your own harness and keys | Up to 10 active people without a license key ([ADR 0038](adr/0038-self-host-license-key.md)); every feature | Basic / break-glass | Community |
| **Managed tiers** (e.g. Starter / Pro / Max) | Managed, one computer (or container) per user, Bots on Hermes Agent by default | Hidden; higher tiers get stronger models and more usage | Bots, machine size, routine runs, storage | SSO (all major IdPs) + audit | Email → SLA |
| **Enterprise** | Dedicated / VPC / on-prem | Custom routing, customer keys allowed | Custom | SSO + SCIM + SAML + residency | Named TAM; SLA covers Hermes Agent, other harnesses best-effort |

Implementation: control-plane entitlement per user and tier (M3); a server-side **tier → provider/model routing table** (M3, built: [#32](https://github.com/CG-Labs/superbot/issues/32), [ADR 0033](adr/0033-tiers-model-routing.md), with per-user tiers, Bot and monthly run limits, and run counts per user; billing v0, [#31](https://github.com/CG-Labs/superbot/issues/31), first slice built: [ADR 0040](adr/0040-billing-v0-tier-limits.md), with daily routine-run and machine-size limits, admin usage views, and a signed Stripe webhook that sets tiers, off by default); license JWT for self-host (M3, built: [#34](https://github.com/CG-Labs/superbot/issues/34), [ADR 0038](adr/0038-self-host-license-key.md), with seats, edition, features, a 14-day grace period, and the `superbot-license` signing tool); usage metering per user for limits and margins (M3–M4).

---

## Observability, backups, and DR

| | Today | Target |
|--|--------|--------|
| Logs | journalctl | Structured JSON + ship (M4) |
| Metrics | None | RED metrics per user and tier (M4) |
| Traces | None | Harness run spans (M4) |
| Backup | Daily `DATA_DIR` archive (installer timer, Compose sidecar), optional age encryption, `superbot-restore --check` ([ADR 0030](adr/0030-backup-restore-drill.md)) | Managed automated per-user machine backups + customer S3 (M3) |
| DR | [Restore guide](ops/backup-restore.md) and restore drills in CI; RPO 24 h default (1 h recommended), RTO 1 h | RPO/RTO in contract (M3 managed) |

---

## Compliance (path, not promises)

| Framework | Intent |
|-----------|--------|
| **GDPR** | Privacy policy, subprocessors, DPA, erasure for managed users (M4) |
| **SOC 2** | Control mapping during M3; Type II pursuit in M5 |
| **Data residency** | UK/EU region choice for managed (M4); enterprise dedicated (M5) |

No certification claims until audits complete.

---

## Documentation & onboarding

| Deliverable | Milestone |
|-------------|-----------|
| Operator guide (install, upgrade, backup) | M0 ✓ expand |
| IdP setup (Apple, GitHub, Entra, Google, generic OIDC/SAML) | M2 |
| Sales/security pack (architecture, data flow) | M3 |
| End-user onboarding in client | M3 |

---

## Licensing & upstream

- **CG-Labs/superbot** is an **MIT-licensed** fork and continuation of the open-source line associated with **[davidondrej/superbot](https://github.com/davidondrej/superbot)** (original MIT copyright David Ondrej in [`LICENSE`](../LICENSE)).
- Commercial **trademarks, managed service, and enterprise modules** may be offered under separate terms; core server remains fork-friendly where MIT allows.
- Attribution and upstream goodwill preserved in release notes and docs; security fixes contributed back when practical.
- Hermes Agent is MIT (Nous Research); shipping it in our images only needs its notice kept ([ADR 0011](adr/0011-hermes-agent-backend.md)).

---

## Now / next / later

| Horizon | Focus |
|---------|--------|
| **Now** | Linode control plane next step on [#29](https://github.com/CG-Labs/superbot/issues/29): screens on machines and a separate OS user for Bots there (Bots, their harness CLIs, logins and the user's folder are already there, [ADR 0036](adr/0036-bots-on-the-users-machine.md), [ADR 0039](adr/0039-machine-harnesses-and-agent-upgrades.md), [ADR 0041](adr/0041-machine-harness-logins-and-folder-copy.md)); per-user isolation follow-ups ([#30](https://github.com/CG-Labs/superbot/issues/30): per-user screens, shared team Bots, the client's personal-secrets screen); finish M1: EAS `projectId`; approvals follow-ups ([list](approvals-followups.md)); Expo client as the single interface ([#28](https://github.com/CG-Labs/superbot/issues/28), [ADR 0027](adr/0027-expo-primary-hermes-default.md)) |
| **Next** | Pause or hand over a disabled user's Bot routines (SCIM-05 in the [SCIM review](security/auth-review-2026-11-scim.md)); measure Hermes per-Bot footprint (ADR 0011 checklist for the managed default) |
| **Later** | Linode control plane with one machine per user (foundation merged: [ADR 0025](adr/0025-control-plane-linode.md); enrollment/mTLS done: [ADR 0031](adr/0031-machine-enrollment-mtls.md); moving Bots next); billing v0 on the tiers ([#31](https://github.com/CG-Labs/superbot/issues/31): limits and the Stripe webhook built, [ADR 0040](adr/0040-billing-v0-tier-limits.md); checkout, billing-period usage, token metering next); public launch + stores; full SCIM (groups, role mapping); SOC 2 |

---

## Risks & open questions

| Risk | Mitigation |
|------|------------|
| Harness vendors change CLI/security model | Adapter versioning; feature detection; unguarded-run canary |
| Hermes upstream churn (daily canaries) | Pin stable releases; upgrade only through the test suite ([ADR 0011](adr/0011-hermes-agent-backend.md)) |
| SSO complexity (many IdPs, SAML tenants) | One IdP end to end first, then the rest on the same user model; SAML via bridge in M2, full SAML in M5 |
| Cross-user data leak | One machine per user; user ID in every control-plane query; integration tests; external pen test before M3 GA |
| Per-user machines cost more than shared ones | Size by tier; suspend idle machines; measure margins per tier |
| 4 GB VPS too small for computer use | Tiered hardware guide; managed sizes by tier |
| MIT fork vs commercial moat | Managed ops, compliance, enterprise features as paid layers |

### Decided (19 Nov 2026)

1. ~~Single shared computer vs per-bot container for v1 commercial default?~~ **One computer per user.**
2. ~~First managed substrate: Linode API vs Kubernetes vs fly/machines?~~ **Linode API for now**; revisit before M4.
3. ~~Seat-based vs bot-concurrency pricing?~~ **Per user, several tiers** by model access and limits; models hidden behind tiers.
4. ~~Which IdPs?~~ **Apple, GitHub, Entra ID, Google, plus generic OIDC/SAML** (e.g. Okta).
5. ~~Interface: Expo client primary, `web/` as admin fallback?~~ **Yes**: the Expo client is the single primary interface; server pages are an admin fallback ([ADR 0027](adr/0027-expo-primary-hermes-default.md)).
6. ~~Accept ADR 0011?~~ **Accepted**: Hermes Agent is the default harness for managed tiers ([ADR 0011](adr/0011-hermes-agent-backend.md), [ADR 0027](adr/0027-expo-primary-hermes-default.md)).
7. ~~Which harness carries enterprise SLAs?~~ **Hermes Agent**; Claude Code and other harnesses are best-effort.
8. ~~Managed hosting unit?~~ **One computer per user, or one container per user on a virtualised server** ([#29](https://github.com/CG-Labs/superbot/issues/29)).

### Still open

1. Where do shared “team bots” run when each user has their own computer (owner's machine, or a separate team machine)? For now, the owner's ([ADR 0029](adr/0029-per-user-isolation.md)).
2. Tier names, prices, and the exact limits per tier.

---

## Tracking

Each remaining roadmap item is one GitHub issue, labelled with its milestone and grouped in that milestone. Merged and in-review work links to its PR above.

| Milestone | Issues |
|-----------|--------|
| [M1 — Foundation hardening](https://github.com/CG-Labs/superbot/issues?q=is%3Aissue%20milestone%3AM1) | EAS `projectId`; approvals follow-ups (tracking). Brand assets done |
| [M2 — Multi-user + SSO](https://github.com/CG-Labs/superbot/issues?q=is%3Aissue%20milestone%3AM2) | User store and sessions; Sign in with Apple; GitHub sign-in; Microsoft Entra ID; Google sign-in; generic OIDC/SAML connector; RBAC v1 and bot ACLs; break-glass and session revoke; client token flow; per-user audit actors; SCIM design stub; auth pen-test review (and its SCIM addendum); IdP setup docs; Hermes Agent adapter; Expo client as the single interface (decided); admin console link in the web client ([#80](https://github.com/CG-Labs/superbot/issues/80), done) |
| [M3 — Private beta](https://github.com/CG-Labs/superbot/issues?q=is%3Aissue%20milestone%3AM3) | Linode control plane (one machine per user); per-user isolation; per-user tiers billing v0 ([#31](https://github.com/CG-Labs/superbot/issues/31), limits and Stripe webhook built); model routing hidden behind tiers; Hermes default harness for managed tiers (ADR 0011 checklist); client audit log viewer ([#81](https://github.com/CG-Labs/superbot/issues/81), done); retire console end-user features ([#82](https://github.com/CG-Labs/superbot/issues/82), done); suggested prompts ([#83](https://github.com/CG-Labs/superbot/issues/83)); self-host license key ([#34](https://github.com/CG-Labs/superbot/issues/34), built); onboarding wizard ([#35](https://github.com/CG-Labs/superbot/issues/35), done); push notifications; biometric unlock; TestFlight / Play internal; registry image with computer use; backup restore drill (self-host done, [ADR 0030](adr/0030-backup-restore-drill.md)); sales/security pack |
| [M4 — Public launch](https://github.com/CG-Labs/superbot/issues?q=is%3Aissue%20milestone%3AM4) | Published per-user plans; revisit managed substrate; marketing site and docs portal; store production release; observability; status page and SLO; GDPR docs and DPA; UK/EU region; SOC 2 readiness |
| [M5 — Enterprise](https://github.com/CG-Labs/superbot/issues?q=is%3Aissue%20milestone%3AM5) | SCIM; full SAML; advanced RBAC; per-user computer hardening; vault integrations; SIEM export; SOC 2 Type II; data residency; air-gapped self-host; enterprise support playbooks |

---

## Milestone map (phases)

```text
M0 Baseline ──► M1 Foundation hardening ──► M2 Multi-user + SSO
                                                    │
                    M5 Enterprise ◄── M4 Public launch ◄── M3 Private beta
```

*Maintainers: CG-Labs product/engineering. Update this doc when ADRs land in `docs/adr/`.*
