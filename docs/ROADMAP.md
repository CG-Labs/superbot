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
| **Technical solopreneur / founder** | Personal VPS, one password, one harness | Strong (install + client + approvals) | Client branding (in review) |
| **Small team (5–30)** | Shared instance, several humans, least privilege | Weak | SSO, multi-user, RBAC, per-user computers |
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
| 4 | **SSO** | Support all the major identity providers: **Sign in with Apple, GitHub, Microsoft Entra ID, Google**, plus a generic **OIDC/SAML** path for others (e.g. Okta). SCIM stays in M5. | Decided |
| 5 | **Interface** | Make [`apps/client`](../apps/client/) (Expo web + native + Electron) the single primary interface; keep the built-in `web/` UI as a minimal admin and fallback. | **Proposal, pending owner confirmation** |
| 6 | **Back end / harness** | Owner wants the back end run by [Hermes Agent](https://github.com/NousResearch/hermes-agent). Assessment and recommendation: [ADR 0011](adr/0011-hermes-agent-backend.md) — add Hermes as an adapter now, make it the default engine behind a gate, don't replace botd's orchestration. | **Proposed** (ADR awaiting acceptance) |

---

## Current state (honest audit)

What exists in **CG-Labs/superbot** today:

| Area | Reality |
|------|---------|
| **Auth** | Single `AUTH_PASSWORD` (Basic); optional `ALLOW_NO_AUTH` on loopback only; `ALLOWED_HOSTS`; per-start `BOT_TOKEN` for `botctl`. No user table, no SSO, no RBAC. Logins and failed logins are audited. |
| **Client** | Login, SSE chat, bots CRUD, models/effort, routine create/edit/delete, live screen viewer (iframe / WebView) with take over, handoff cards and alerts; no audit log viewer, push, or biometric lock; placeholder EAS `projectId`; SuperBot icons, splash and store art in review ([PR #62](https://github.com/CG-Labs/superbot/pull/62)). |
| **Server** | SQLite single-tenant schema; harnesses run with their own prompts off, gated by the SuperBot **policy engine and approval queue** (default **ask** on fresh installs; [ADR 0007](adr/0007-approvals.md)); append-only **audit events** for admin actions with CSV export (`/api/audit`, `botctl audit export`, web Audit log; [ADR 0009](adr/0009-audit-events.md)). **Secrets** from env/`_FILE` or saved encrypted in SQLite (XChaCha20-Poly1305, master key outside `DATA_DIR`), redacted from chats, events, and audit ([ADR 0010](adr/0010-secrets.md)); external vaults not built (trait seam only). |
| **Harnesses** | Claude Code, Codex, Pi adapters. Hermes Agent adapter proposed ([ADR 0011](adr/0011-hermes-agent-backend.md)). |
| **Deploy** | Ubuntu bash installer (piped-install fix merged, [#3](https://github.com/CG-Labs/superbot/pull/3)), systemd, Caddy, daily SQLite backup timer; Docker Compose (`Dockerfile` + `deploy/docker/`: `botd`, Caddy, backup sidecar), smoke-tested in CI ([ADR 0006](adr/0006-docker-compose.md)). |
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
| **SCIM provisioning** | Create/disable users and group→role mapping from Entra / Google Workspace / Okta (M5). |
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
| **Status** | **Merged:** installer fix ([#3](https://github.com/CG-Labs/superbot/pull/3)), Docker Compose ([#6](https://github.com/CG-Labs/superbot/pull/6), [ADR 0006](adr/0006-docker-compose.md)), approvals + harness policy ([#5](https://github.com/CG-Labs/superbot/pull/5), [ADR 0007](adr/0007-approvals.md)), client routine editor / screen viewer / handoff ([#7](https://github.com/CG-Labs/superbot/pull/7), [ADR 0008](adr/0008-client-screen-auth.md)), audit events + CSV ([#8](https://github.com/CG-Labs/superbot/pull/8), [ADR 0009](adr/0009-audit-events.md)), secrets store ([#9](https://github.com/CG-Labs/superbot/pull/9), [ADR 0010](adr/0010-secrets.md)). **In review:** brand assets ([PR #62](https://github.com/CG-Labs/superbot/pull/62), [#12](https://github.com/CG-Labs/superbot/issues/12), [brand guide](brand.md)). **Remaining:** real EAS `projectId`. |
| **Goal** | Reduce blast radius and improve deploy surface before selling to strangers. |
| **Scope** | Approvals MVP (**done**); secrets via env/sealed store, not plaintext in SQLite (**done**); structured audit events (**done**); Docker Compose one-click (**done**); harness policy flags (**done**); client routine editor, screen viewer, handoff UI (**done**); brand assets (**in review**); real EAS `projectId`. |
| **Exit criteria** | Compose documented as supported path (**done**); approvals cover send-email/shell/file-delete class tools (**done**); audit export CSV (**done**); client routine CRUD + screen iframe (**done**); secrets not in plaintext at rest (**done**); client builds under the real EAS project with SuperBot branding. |
| **Size** | **L** |
| **Dependencies** | M0 |

---

### M2 — Multi-user + SSO

**Phase label:** *Multi-user + SSO*

| | |
|--|--|
| **Goal** | First **sellable team** product: real users and familiar sign-in. |
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
| **Scope** | Control plane that provisions **one machine per user via the Linode API** (create, size by tier, suspend, destroy, backups); **per-user isolation**: each user's Bots, workspace, harness logins, and screens live on that user's computer, with the org's shared data (users, roles, billing, audit) in the control plane; billing v0 (Stripe, **per-user subscription tiers**); **model routing hidden behind tiers** (server picks provider and model per tier; users never pick a model on managed plans); Hermes Agent as default engine for managed tiers once the [ADR 0011 gate](adr/0011-hermes-agent-backend.md#recommendation) passes; license key for self-host; onboarding wizard (domain, IdP, tier); client push notifications (routine completions, approvals), biometric optional unlock; **TestFlight / Play internal** tracks; published registry image with screens/computer use; DR: backup restore runbook + tested RPO target on managed tier. |
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
| Harness permissions | Policy engine: default **ask** for risky tools; bypass only by opt-in (**done**: [ADR 0007](adr/0007-approvals.md)) | Hermes tool names in the policy (M2); per-Bot tokens and approvals follow-ups ([list](approvals-followups.md)) |
| Compute isolation | One OS user, one shared workspace for all Bots | **One computer per user** (M3); harness as separate OS user, cgroup and egress limits (M5) |
| Secrets | Env/`_FILE` or sealed in SQLite, master key outside backups, values redacted (**done**: [ADR 0010](adr/0010-secrets.md)); harness logins still on service user disk | Master-key rotation; external vaults + short-lived tokens (M5) |
| Audit | Append-only SQLite table, CSV export, retention setting (**done**: [ADR 0009](adr/0009-audit-events.md)) | Per-user actors and IdP subjects (M2); SIEM export and tamper evidence (M5) |
| Network | Caddy TLS, loopback `botd` | Same + mTLS between control plane and per-user machines (M3) |
| Client | Password in SecureStore | OAuth tokens, certificate pinning (managed) |

---

## Client product gaps (tracked)

| Item | Priority | Milestone |
|------|----------|-----------|
| Screen viewer (voxl / `/api/bots/:id/screen`) | High | M1 ✓ |
| Handoff UI | High | M1 ✓ |
| Routine create/edit | High | M1 ✓ |
| `eas init` / real `projectId` | High | M1 |
| Custom icons / brand | Medium | M1 (in review) |
| Single primary interface (Expo client; `web/` as admin fallback) — proposal | High | M2 (confirm) |
| SSO sign-in (Apple, GitHub, Microsoft, Google, OIDC) | High | M2 |
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
| **Managed cloud** | None | **Linode API**, one machine per user (M3); revisit the substrate before M4 |
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
| **Now** | Finish M1: EAS `projectId`, brand assets ([PR #62](https://github.com/CG-Labs/superbot/pull/62)); approvals follow-ups ([list](approvals-followups.md)); owner to accept ADR 0011 and confirm the interface proposal |
| **Next** | Multi-user data model; SSO with Apple, GitHub, Entra, Google, generic OIDC; RBAC v1; Hermes adapter |
| **Later** | Linode control plane with one machine per user; per-user tiers and hidden model routing; public launch + stores; SCIM; SOC 2 |

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
| [M1 — Foundation hardening](https://github.com/CG-Labs/superbot/issues?q=is%3Aissue%20milestone%3AM1) | EAS `projectId`; brand assets; approvals follow-ups (tracking) |
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
