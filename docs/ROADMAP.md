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

Product decisions by the project owner. They replace the matching open questions.

| # | Topic | Decision | Status |
|---|-------|----------|--------|
| 1 | **Isolation** | One computer (VM or container) per **user**, not per Bot. A user's Bots share that user's computer. | Decided |
| 2 | **Managed platform** | Provision per-user machines with the **Linode API** until a production-ready system exists. | Decided for now; revisit before M4 |
| 3 | **Pricing** | **Per user**, with several tiers. Tiers differ by language model access and other limits. Models can stay hidden in the back end: users pick a tier, not a model. | Decided |
| 4 | **SSO** | Support all the major identity providers: **Sign in with Apple, GitHub, Microsoft Entra ID, Google**, plus a generic **OIDC/SAML** path for others (e.g. Okta). A SCIM stub (users only) ships in M2 ([ADR 0023](adr/0023-scim.md)); full SCIM stays in M5. | Decided |
| 5 | **Interface** | Make [`apps/client`](../apps/client/) (Expo web + native + Electron) the single primary interface; keep the built-in `web/` UI as a minimal admin and fallback. | **Proposal, pending owner confirmation** |
| 6 | **Back end / harness** | Owner wants the back end run by [Hermes Agent](https://github.com/NousResearch/hermes-agent). Assessment and recommendation: [ADR 0011](adr/0011-hermes-agent-backend.md) — add Hermes as an adapter now, make it the default engine behind a gate, don't replace botd's orchestration. | **Proposed** (ADR awaiting acceptance); option (a), the adapter, built ([#27](https://github.com/CG-Labs/superbot/issues/27), [ADR 0015](adr/0015-hermes-adapter.md)) |

---

## Current state (honest audit)

What exists in **CG-Labs/superbot** today:

| Area | Reality |
|------|---------|
| **Auth** | Users in SQLite with roles (admin, member, read-only) enforced per API route; server-side sessions (HttpOnly cookie for `web/`, bearer token for the client and `botctl`) with idle and absolute TTLs, logout, and admin revoke; one-time sign-in codes from an admin; `AUTH_PASSWORD` kept as break-glass owner login (`AUTH_BREAK_GLASS`, on by default) ([ADR 0012](adr/0012-users-sessions-rbac.md)). `ALLOW_NO_AUTH` on loopback only; `ALLOWED_HOSTS`; per-start `BOT_TOKEN` for `botctl`. Sign in with Microsoft Entra ID, Google, and any generic OIDC IdP, several at once ([ADR 0014](adr/0014-oidc-sso-entra.md), [ADR 0016](adr/0016-sso-multi-provider.md)); GitHub and Apple sign-in merged ([PR #69](https://github.com/CG-Labs/superbot/pull/69), [ADR 0018](adr/0018-sso-github-apple.md)). Sign-ins, revokes, and user changes are audited; per-user audit actors (email, role, sign-in method, IdP, session, on behalf of) merged ([PR #70](https://github.com/CG-Labs/superbot/pull/70), [ADR 0019](adr/0019-audit-actors.md)). Bot ACLs (owner, shared or private, viewer/operator grants) merged ([PR #68](https://github.com/CG-Labs/superbot/pull/68), [ADR 0017](adr/0017-bot-acls.md)). Admin portal for onboarding in the client (users, roles, one-time codes with invite links, sessions, SSO links, Bot access) merged ([PR #72](https://github.com/CG-Labs/superbot/pull/72), [ADR 0021](adr/0021-admin-portal.md)). Access requests from the landing page, approved by an admin into a user and a one-time code (`botctl signup`, or **Requests** in the admin portal; no email yet), merged ([PR #74](https://github.com/CG-Labs/superbot/pull/74), [ADR 0022](adr/0022-landing-and-signups.md)). SCIM provisioning stub (users only, off by default, `botctl scim`) in review ([PR #75](https://github.com/CG-Labs/superbot/pull/75), [ADR 0023](adr/0023-scim.md)). |
| **Client** | Login, SSE chat, bots CRUD, models/effort, routine create/edit/delete, live screen viewer (iframe / WebView) with take over, handoff cards and alerts; no audit log viewer, push, or biometric lock; placeholder EAS `projectId`; SuperBot icons, splash and store art (merged, [PR #62](https://github.com/CG-Labs/superbot/pull/62)). |
| **Server** | SQLite single-tenant schema; harnesses run with their own prompts off, gated by the SuperBot **policy engine and approval queue** (default **ask** on fresh installs; [ADR 0007](adr/0007-approvals.md)); append-only **audit events** for admin actions with CSV export (`/api/audit`, `botctl audit export`, web Audit log; [ADR 0009](adr/0009-audit-events.md)); per-user actors with IdP, plus Bot runs and harness invocations, merged ([PR #70](https://github.com/CG-Labs/superbot/pull/70), [ADR 0019](adr/0019-audit-actors.md)). **Secrets** from env/`_FILE` or saved encrypted in SQLite (XChaCha20-Poly1305, master key outside `DATA_DIR`), redacted from chats, events, and audit ([ADR 0010](adr/0010-secrets.md)); external vaults not built (trait seam only). |
| **Harnesses** | Claude Code, Codex, Pi, and Hermes Agent adapters. Hermes is opt-in in the installer and image, pinned to v0.23.2 ([ADR 0011](adr/0011-hermes-agent-backend.md), [ADR 0015](adr/0015-hermes-adapter.md)). |
| **Deploy** | Ubuntu bash installer (piped-install fix merged, [#3](https://github.com/CG-Labs/superbot/pull/3)), systemd, Caddy, daily SQLite backup timer; Docker Compose (`Dockerfile` + `deploy/docker/`: `botd`, Caddy, backup sidecar), smoke-tested in CI ([ADR 0006](adr/0006-docker-compose.md)). Both build the Expo web client from the deployed commit and serve it at `/app/` ([ADR 0013](adr/0013-serve-web-client.md)). `/` is a public landing page with a request-access form at `/get-started`; the built-in page moved to `/console/` (merged, [PR #74](https://github.com/CG-Labs/superbot/pull/74), [ADR 0022](adr/0022-landing-and-signups.md)). |
| **Multi-tenancy** | One deployment = one org in practice (`DATA_DIR`, shared `WORKSPACE_DIR`). All Bots share one computer. |
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
| **Status** | **In progress.** Slice 1 merged ([#61](https://github.com/CG-Labs/superbot/pull/61), [ADR 0012](adr/0012-users-sessions-rbac.md)): user store, server-side sessions with TTLs and revoke, RBAC v1 on the API, break-glass, `botctl` user/session commands, auth audit events, client token flow. Slice 2 merged: Microsoft Entra ID sign-in on a generic OIDC layer ([PR #65](https://github.com/CG-Labs/superbot/pull/65), [#17](https://github.com/CG-Labs/superbot/issues/17), [ADR 0014](adr/0014-oidc-sso-entra.md), [setup guide](sso/entra.md)). Slice 3 merged: Google sign-in with a server-checked Workspace domain restriction, and a generic OIDC connector (Okta, Keycloak, Auth0, …) configured in `.env`, with several providers on at once and one user per person across them ([PR #66](https://github.com/CG-Labs/superbot/pull/66), [#18](https://github.com/CG-Labs/superbot/issues/18), [#19](https://github.com/CG-Labs/superbot/issues/19), [ADR 0016](adr/0016-sso-multi-provider.md), guides for [Google](sso/google.md) and [OIDC](sso/oidc.md)). Slice 4 merged: bot ACLs: each Bot has an owner, is shared or private, and can grant users viewer or operator; enforced on every Bot, chat, routine, screen, and approval route and in the live stream; existing Bots stay shared; `botctl bot` commands, audit events, and a sharing switch in the client ([PR #68](https://github.com/CG-Labs/superbot/pull/68), [#20](https://github.com/CG-Labs/superbot/issues/20), [ADR 0017](adr/0017-bot-acls.md)). Slice 5 merged: Sign in with GitHub (numeric-id identity, verified primary email, optional org restriction checked on GitHub's API, GitHub Enterprise Server) and Sign in with Apple (per-sign-in ES256 client secret from a key in the secrets store, form-post callback, Hide My Email) ([PR #69](https://github.com/CG-Labs/superbot/pull/69), [#15](https://github.com/CG-Labs/superbot/issues/15), [#16](https://github.com/CG-Labs/superbot/issues/16), [ADR 0018](adr/0018-sso-github-apple.md), guides for [GitHub](sso/github.md) and [Apple](sso/apple.md)). Slice 6 merged: audit log with per-user actors and IdP: email, role, sign-in method (break-glass password, code, SSO, Bot token), IdP type and provider, session, and on-behalf-of on every event; Bot runs and harness invocations attributed to whoever asked; filters by person, method, IdP, session in `/api/audit`, CSV, `botctl`, and the web Audit log ([PR #70](https://github.com/CG-Labs/superbot/pull/70), [#23](https://github.com/CG-Labs/superbot/issues/23), [ADR 0019](adr/0019-audit-actors.md)). Slice 7 merged: SAML bridge: SAML-only IdPs (ADFS, Okta, OneLogin, PingFederate) sign in through a Keycloak broker that checks the SAML response; botd accepts only people the configured IdP vouched for and keys them by the IdP's entity ID and NameID ([PR #71](https://github.com/CG-Labs/superbot/pull/71), [ADR 0020](adr/0020-saml-bridge.md), [setup guide](sso/saml.md)); with it [#19](https://github.com/CG-Labs/superbot/issues/19) is complete. Slice 8 merged: admin portal for onboarding in the client: add people, one-time sign-in codes (1 hour, 24 hours, or 7 days) with a ready-to-send invite and link, roles, disable, sign out everywhere, SSO account links, last sign-in method, and each person's Bot access ([PR #72](https://github.com/CG-Labs/superbot/pull/72), [ADR 0021](adr/0021-admin-portal.md)). Slice 9 merged: auth pen-test review: no Critical or High findings; fixed CSRF on cached break-glass and no-auth callers, unlimited Basic password guesses, unverified Entra email at JIT sign-up, and cookie tossing (`__Host-` cookies); a router walk test checks every non-public route needs credentials and the right role ([PR #76](https://github.com/CG-Labs/superbot/pull/76), [#25](https://github.com/CG-Labs/superbot/issues/25), [report](security/auth-review-2026-11.md), [ADR 0024](adr/0024-auth-review-hardening.md)). **In review:** slice 10, SCIM stub: Entra ID and Okta provision users at `/scim/v2` (discovery, Users list/filter/get/create/replace/patch, soft delete) with per-tenant `sbp_` tokens from `botctl scim`, `externalId` linked to SSO identities (never email), deactivation ending sessions, no role changes, audit events with the token as actor; off by default (`SCIM=on`); groups return an empty list ([PR #75](https://github.com/CG-Labs/superbot/pull/75), [#24](https://github.com/CG-Labs/superbot/issues/24), [ADR 0023](adr/0023-scim.md), [setup guide](sso/scim.md)). Close-out for [#24](https://github.com/CG-Labs/superbot/issues/24): design and stub done; groups, group→role mapping, Google Workspace, and bulk move to M5. Remaining: an auth review of the SCIM endpoints (after #76), Hermes Agent adapter, interface proposal. |
| **Scope** | User store; JWT/session cookies for client; **Sign in with Apple**, **GitHub**, **Microsoft Entra ID**, **Google** (OIDC/OAuth); **generic OIDC** connector (Okta and others) and a SAML bridge where an IdP needs it; account linking (several IdPs per user); RBAC v1 (org admin, member, read-only); bot ACLs; migrate from `AUTH_PASSWORD` to SSO-primary with break-glass; session TTL and admin revoke; audit log with per-user actors and IdP; SCIM **design + stub** (full SCIM in M5). Parallel tracks: Hermes Agent harness adapter ([ADR 0011](adr/0011-hermes-agent-backend.md), option a); confirm the interface proposal (Expo client primary, `web/` as admin fallback). |
| **Exit criteria** | Columbia org signs in with SSO only; each of Apple, GitHub, Entra, Google, and one generic OIDC IdP (e.g. Okta) works end to end; two roles enforced on API; shared vs private bots; pen-test style review of auth bypass; client uses token flow (no password in SecureStore for SSO tenants). |
| **Size** | **XL** |
| **Dependencies** | M1 (audit, approvals shape, secrets) |

---

### M3 — Private beta (managed + self-serve packaging)

**Phase label:** *Private beta*

| | |
|--|--|
| **Goal** | Paid early adopters on **managed hosting** and polished **self-host** SKU. |
| **Status** | **Started.** Control-plane foundation in review ([#29](https://github.com/CG-Labs/superbot/issues/29), [ADR 0025](adr/0025-control-plane-linode.md)): a `machines` table (one live machine per user), a Linode API v4 client behind a provider trait, tier → plan mapping in config, admin endpoints to request, suspend, resume, resize and destroy a user's machine, a reconciler, and audit events for each change. Off unless `LINODE_TOKEN` is set, so self-host is unchanged. Next on #29: enrollment and mTLS between the control plane and each machine, then moving a user's Bots onto their machine. |
| **Scope** | Control plane that provisions **one machine per user via the Linode API** (create, size by tier, suspend, destroy, backups); **per-user isolation**: each user's Bots, workspace, harness logins, and screens live on that user's computer, with the org's shared data (users, roles, billing, audit) in the control plane; billing v0 (Stripe, **per-user subscription tiers**); **model routing hidden behind tiers** (server picks provider and model per tier; users never pick a model on managed plans); Hermes Agent as default engine for managed tiers once the [ADR 0011 gate](adr/0011-hermes-agent-backend.md#recommendation) passes; license key for self-host; onboarding wizard (domain, IdP, tier), growing the approval-based sign-ups ([ADR 0022](adr/0022-landing-and-signups.md)) into self-serve with email, self-linked SSO, and sign-up data retention; client push notifications (routine completions, approvals), biometric optional unlock; **TestFlight / Play internal** tracks; published registry image with screens/computer use; DR: backup restore runbook + tested RPO target on managed tier. |
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
| Harness permissions | Policy engine: default **ask** for risky tools; bypass only by opt-in (**done**: [ADR 0007](adr/0007-approvals.md)) | Hermes tool names in the policy (**done**, [ADR 0015](adr/0015-hermes-adapter.md)); per-Bot tokens and approvals follow-ups ([list](approvals-followups.md)) |
| Compute isolation | One OS user, one shared workspace for all Bots | **One computer per user** (M3); harness as separate OS user, cgroup and egress limits (M5) |
| Secrets | Env/`_FILE` or sealed in SQLite, master key outside backups, values redacted (**done**: [ADR 0010](adr/0010-secrets.md)); harness logins still on service user disk | Master-key rotation; external vaults + short-lived tokens (M5) |
| Audit | Append-only SQLite table, CSV export, retention setting (**done**: [ADR 0009](adr/0009-audit-events.md)) | Per-user actors and IdP subjects (M2, in review: [PR #70](https://github.com/CG-Labs/superbot/pull/70), [ADR 0019](adr/0019-audit-actors.md)); SIEM export and tamper evidence (M5) |
| Network | Caddy TLS, loopback `botd` | Same + mTLS between control plane and per-user machines (M3; enrollment design in [ADR 0025](adr/0025-control-plane-linode.md)) |
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
| Single primary interface (Expo client; `web/` as admin fallback) — proposal | High | M2 (confirm) |
| SSO sign-in (Apple, GitHub, Microsoft, Google, OIDC, SAML via bridge) | High | M2 |
| Tier picker instead of model picker on managed plans | Medium | M3 |
| Push notifications | Medium | M3 |
| Biometric app lock | Medium | M3 |
| App Store / Play release | High | M4 |

---

## Deployment & hosting

| Mode | Today | Target |
|------|--------|--------|
| **Bash VPS installer** | Ubuntu 22.04 / 24.04 | Maintain; hardened CIS-aligned option |
| **Docker Compose** | **Supported** (M1 ✓): [`deploy/docker/`](../deploy/docker/), [docs](../deploy/README.md#docker-compose-supported) | Published registry image; screens/computer use in the image (M3) |
| **Managed cloud** | Control-plane foundation in review: Linode client, machine records, admin API, reconciler; off by default ([ADR 0025](adr/0025-control-plane-linode.md)) | **Linode API**, one machine per user (M3); revisit the substrate before M4 |
| **Air-gapped** | Possible manual | M5 docs + license |

---

## Billing & licensing (commercial)

Pricing is **per user**. Managed tiers differ by language model access and other limits; models stay behind the tier, not in the user's hands.

| Tier (draft names) | Deployment | Models | Limits | Identity | Support |
|--------------|------------|--------|--------|----------|---------|
| **Community** | Self-host, MIT core | Bring your own harness and keys | None from us | Basic / break-glass | Community |
| **Managed tiers** (e.g. Starter / Pro / Max) | Managed, one machine per user | Hidden; higher tiers get stronger models and more usage | Bots, machine size, routine runs, storage | SSO (all major IdPs) + audit | Email → SLA |
| **Enterprise** | Dedicated / VPC / on-prem | Custom routing, customer keys allowed | Custom | SSO + SCIM + SAML + residency | Named TAM |

Implementation: control-plane entitlement per user and tier (M3); a server-side **tier → provider/model routing table** (M3); license JWT for self-host (M3); usage metering per user for limits and margins (M3–M4).

---

## Observability, backups, and DR

| | Today | Target |
|--|--------|--------|
| Logs | journalctl | Structured JSON + ship (M4) |
| Metrics | None | RED metrics per user and tier (M4) |
| Traces | None | Harness run spans (M4) |
| Backup | Daily SQLite timer (`deploy/superbot-backup.sh`) | Managed automated per-user machine backups + customer S3 (M3) |
| DR | Operator runbook | Tested restore, RPO/RTO in contract (M3 managed) |

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
| **Now** | Linode control plane review ([PR #77](https://github.com/CG-Labs/superbot/pull/77)); finish M1: EAS `projectId`; approvals follow-ups ([list](approvals-followups.md)); owner to accept ADR 0011 and confirm the interface proposal; Hermes Agent adapter ([#27](https://github.com/CG-Labs/superbot/issues/27)) |
| **Next** | Auth review of the SCIM endpoints (the M2 review, [ADR 0024](adr/0024-auth-review-hardening.md), came before them); measure Hermes per-Bot footprint (ADR 0011 gate) |
| **Later** | Linode control plane with one machine per user (foundation started: [ADR 0025](adr/0025-control-plane-linode.md); enrollment/mTLS and moving Bots next); per-user tiers and hidden model routing; public launch + stores; full SCIM (groups, role mapping); SOC 2 |

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

### Still open

1. **Interface:** make the Expo client the single primary interface and keep `web/` as admin fallback? Proposed; owner to confirm.
2. **Hermes Agent:** accept [ADR 0011](adr/0011-hermes-agent-backend.md) (adapter now, default engine behind a gate, no replacement of botd)?
3. Which harness is “supported” for enterprise SLAs (Hermes, Claude Code, Codex, Pi, or a subset)?
4. Where do shared “team bots” run when each user has their own computer (owner's machine, or a separate team machine)?
5. Tier names, prices, and the exact limits per tier.

---

## Tracking

Each remaining roadmap item is one GitHub issue, labelled with its milestone and grouped in that milestone. Merged and in-review work links to its PR above.

| Milestone | Issues |
|-----------|--------|
| [M1 — Foundation hardening](https://github.com/CG-Labs/superbot/issues?q=is%3Aissue%20milestone%3AM1) | EAS `projectId`; approvals follow-ups (tracking). Brand assets done |
| [M2 — Multi-user + SSO](https://github.com/CG-Labs/superbot/issues?q=is%3Aissue%20milestone%3AM2) | User store and sessions; Sign in with Apple; GitHub sign-in; Microsoft Entra ID; Google sign-in; generic OIDC/SAML connector; RBAC v1 and bot ACLs; break-glass and session revoke; client token flow; per-user audit actors; SCIM design stub; auth pen-test review; IdP setup docs; Hermes Agent adapter; confirm interface proposal |
| [M3 — Private beta](https://github.com/CG-Labs/superbot/issues?q=is%3Aissue%20milestone%3AM3) | Linode control plane (one machine per user); per-user isolation; per-user tiers billing v0; model routing hidden behind tiers; Hermes default-engine gate; self-host license key; onboarding wizard; push notifications; biometric unlock; TestFlight / Play internal; registry image with computer use; backup restore drill; sales/security pack |
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
