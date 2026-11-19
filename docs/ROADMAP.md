# SuperBot product roadmap

**Status:** Living plan for CG-Labs commercial productization of SuperBot.  
**Baseline (Nov 2026):** Production-style self-host on a 4 GB Linode via [`deploy/install.sh`](../deploy/README.md); [`apps/client`](../apps/client/) (Expo web + native + Electron) against `botd` with shared HTTP Basic auth.

Sizes are **S / M / L / XL** (effort and cross-cutting risk), not calendar commitments.

---

## Vision

SuperBot is a **team of AI coworkers**—each with memory, routines, and a shared Linux “computer”—that customers can **self-host** or run on **CG-Labs managed hosting**. Buyers get harness choice (Claude Code, Codex, Pi, …) without rebuilding orchestration, memory, or Bot-to-Bot workflows.

**North star:** An organization deploys SuperBot once, signs in with **corporate identity**, and gives each person (or group) Bots with clear **roles, audit, and isolation**—comparable to polished SaaS agents, but with data and compute under customer control.

### Target customers

| Segment | Need | Fit today | Gaps |
|--------|------|-----------|------|
| **Technical solopreneur / founder** | Personal VPS, one password, one harness | Strong (install + client) | Client polish, approvals, computer use |
| **Small team (5–30)** | Shared instance, several humans, least privilege | Weak | SSO, multi-user, RBAC, audit |
| **Growth company (30–500)** | Managed hosting, billing, SSO, support | None | Multi-tenancy, cloud control plane |
| **Enterprise (500+)** | Entra/Google SSO, SCIM, SOC 2, UK/EU residency, procurement | None | Full enterprise pillar |

### Principles

1. **Rust first** for server, control plane, and isolation daemons; thin TS only where stores/browsers require it (`AGENTS.md`).
2. **Harness agnostic** — adapters stay small; product value is orchestration, memory, governance, and ops.
3. **Self-host parity** — every managed feature should be reproducible on customer infrastructure (with license where applicable).
4. **Secure by default** — no anonymous API on the public internet; move from shared password to identity, sessions, and policy.
5. **Honest scope** — ship vertical slices (e.g. Entra OIDC before SAML) rather than checkbox features without enforcement.

---

## Current state (honest audit)

What exists in **CG-Labs/superbot** today:

| Area | Reality |
|------|---------|
| **Auth** | Single `AUTH_PASSWORD` (Basic); optional `ALLOW_NO_AUTH` on loopback only; `ALLOWED_HOSTS`; per-start `BOT_TOKEN` for `botctl`. No user table, no SSO, no RBAC. |
| **Client** | Login, SSE chat, bots CRUD, models/effort, routine create/edit/delete, live screen viewer (iframe / WebView) with take over, handoff cards and alerts; no push or biometric lock; placeholder EAS `projectId`; template branding. |
| **Server** | SQLite single-tenant schema; harnesses run with their own prompts off, gated by the SuperBot **policy engine and approval queue** (default **ask** on fresh installs; [ADR 0007](adr/0007-approvals.md)); Vault **not built** (`docs/backend.md`). |
| **Deploy** | Ubuntu bash installer, systemd, Caddy, daily SQLite backup timer; Docker Compose (`Dockerfile` + `deploy/docker/`: `botd`, Caddy, backup sidecar), smoke-tested in CI ([ADR 0006](adr/0006-docker-compose.md)). |
| **Multi-tenancy** | One deployment = one org in practice (`DATA_DIR`, shared `WORKSPACE_DIR`). |
| **Observability** | `journalctl`, healthz; no metrics/tracing product. |
| **Compliance** | None; MIT license at repo root (see [Licensing & upstream](#licensing--upstream)). |

---

## Enterprise identity (SSO) — what we must build

Replacing or augmenting the shared Basic password is not a login screen swap. **Enterprise SSO** implies:

| Capability | Why it follows from SSO |
|------------|-------------------------|
| **Multi-user accounts** | IdP subjects map to SuperBot users; no more one shared password per deployment. |
| **Roles / RBAC** | Admin, operator, viewer (and custom) on bots, routines, settings, and harness credentials. |
| **Per-user & shared Bots** | Ownership, delegation, and “team bots” with explicit ACLs. |
| **Session management** | OIDC refresh, idle timeout, revoke-all, device/session list for admins. |
| **Audit logs** | Who authenticated, API actions, bot runs, harness invocations, config changes (immutable export). |
| **SCIM provisioning** | Create/disable users and group→role mapping from Entra / Google Workspace. |
| **IdP targets (v1 enterprise)** | **Microsoft Entra ID** (OIDC first, SAML where required) and **Google Workspace** (OIDC). |

Basic auth may remain for **break-glass** and **self-host hobby** tiers only, behind explicit policy.

---

## Milestones

### M0 — Baseline operator install (today)

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
| **Goal** | Reduce blast radius and improve deploy surface before selling to strangers. |
| **Scope** | Approvals MVP (pause before destructive harness tools); secrets via env/Vault interface (not plaintext in SQLite) ✓ ([ADR 0010](adr/0010-secrets.md)); structured audit **events** (append-only file or table) for admin actions; optional Docker **Compose** one-click (image + `botd` + Caddy + volume mounts) per [architecture](architecture.md) and community expectation (e.g. upstream issue **#7** — Compose packaging; not yet in CG-Labs tree); harness **policy** flags (when to allow bypass vs require approval); client: routine editor ✓, screen viewer parity with `web/` ✓, handoff UI ✓ ([ADR 0008](adr/0008-client-screen-auth.md)), real EAS `projectId` + brand assets. |
| **Exit criteria** | Compose documented as supported path; approvals cover send-email/shell/file-delete class tools; audit export CSV; client routine CRUD + screen iframe ✓. |
| **Size** | **L** |
| **Dependencies** | M0 |

---

### M2 — Multi-user + SSO

**Phase label:** *Multi-user + SSO*

| | |
|--|--|
| **Goal** | First **sellable team** product: real users and corporate login. |
| **Scope** | User store; JWT/session cookies for client; **Entra OIDC** + **Google Workspace OIDC**; SAML bridge for Entra where needed; RBAC v1 (org admin, member, read-only); bot ACLs; migrate from `AUTH_PASSWORD` to SSO-primary with break-glass; session TTL and admin revoke; audit log for auth and API; SCIM **design + stub** (full SCIM in M5). |
| **Exit criteria** | Columbia org on Entra/Google only; two roles enforced on API; shared vs private bots; pen-test style review of auth bypass; client uses token flow (no password in SecureStore for SSO tenants). |
| **Size** | **XL** |
| **Dependencies** | M1 (audit, approvals shape) |

---

### M3 — Private beta (managed + self-serve packaging)

**Phase label:** *Private beta*

| | |
|--|--|
| **Goal** | Paid early adopters on **managed hosting** and polished **self-host** SKU. |
| **Scope** | Control plane (provision Linode/K8s workers per tenant); per-tenant isolation (DB + workspace boundary); billing v0 (Stripe: seat or bot-hours); license key for self-host; onboarding wizard (domain, IdP, harness); client push notifications (routine completions), biometric optional unlock; **TestFlight / Play internal** tracks; DR: backup restore runbook + tested RPO target on managed tier. |
| **Exit criteria** | ≥3 paying design partners; tenant A cannot read tenant B; restore drill documented; mobile beta installable from stores (internal). |
| **Size** | **L** |
| **Dependencies** | M2 |

---

### M4 — Public launch

**Phase label:** *Public launch*

| | |
|--|--|
| **Goal** | Open market SKU with clear plans and docs. |
| **Scope** | Pricing: **Free self-host OSS**, **Team** (seats + SSO), **Business** (managed, SLA), **Enterprise** (custom); marketing site + docs portal; App Store / Play **production** listing; observability: metrics (Prometheus/OpenTelemetry), error reporting, uptime checks; status page for managed; GDPR privacy docs + DPA template; UK/EU region **option** for managed (London/Frankfurt). |
| **Exit criteria** | Public signup or contact-sales flow; published plans; SOC 2 **readiness** checklist (not full cert); SLO defined for managed uptime. |
| **Size** | **L** |
| **Dependencies** | M3 |

---

### M5 — Enterprise

**Phase label:** *Enterprise*

| | |
|--|--|
| **Goal** | Win regulated and large accounts. |
| **Scope** | **SCIM** provisioning (Entra + Google); full **SAML** where OIDC insufficient; advanced RBAC (custom roles, service accounts); **per-bot or per-tenant sandbox** (containers/namespaces, cgroup limits from `docs/background/shared-vm-architecture.md`); secrets vault integration (Azure Key Vault, GCP SM); SIEM export (audit); **SOC 2 Type II** program; contractual **data residency** (UK/EU); optional air-gapped self-host; enterprise support & success playbooks. |
| **Exit criteria** | One enterprise logo on SCIM + Entra; isolation POC passes red-team scenario; SOC 2 auditor engaged; GDPR DPIA template for customers. |
| **Size** | **XL** |
| **Dependencies** | M4 |

---

## Security & isolation (cross-cutting)

| Topic | Today | Roadmap direction |
|-------|--------|-------------------|
| Harness permissions | Bypass flags on all adapters | Policy engine: default **ask** for risky tools; bypass only in dev profiles (**done**: [ADR 0007](adr/0007-approvals.md)) |
| Compute isolation | One OS user, shared workspace | Tenant workspaces (M3); optional per-bot containers (M5) |
| Secrets | Env/`_FILE` or sealed in SQLite, master key outside backups, values redacted (**done**: [ADR 0010](adr/0010-secrets.md)); harness logins still on service user disk | Key rotation; Vault / Key Vault / Secret Manager stores and short-lived tokens (M5) |
| Network | Caddy TLS, loopback `botd` | Same + mTLS internal where multi-service |
| Client | Password in SecureStore | OAuth tokens, certificate pinning (managed) |

---

## Client product gaps (tracked)

| Item | Priority | Milestone |
|------|----------|-----------|
| Screen viewer (voxl / `/api/bots/:id/screen`) | High | M1 ✓ |
| Handoff UI | High | M1 ✓ |
| Routine create/edit | High | M1 ✓ |
| Push notifications | Medium | M3 |
| Biometric app lock | Medium | M3 |
| Custom icons / brand | Medium | M1 |
| `eas init` / real `projectId` | High | M1 |
| App Store / Play release | High | M4 |

---

## Deployment & hosting

| Mode | Today | Target |
|------|--------|--------|
| **Bash VPS installer** | Ubuntu 22/04 | Maintain, Hardened CIS-aligned option |
| **Docker Compose** | **Supported** (M1 ✓): [`deploy/docker/`](../deploy/docker/), [docs](../deploy/README.md#docker-compose-supported) | Published registry image; screens/computer use in the image |
| **Managed cloud** | None | M3 control plane, M4 SLA |
| **Air-gapped** | Possible manual | M5 docs + license |

---

## Billing & licensing (commercial)

| Tier (draft) | Deployment | Identity | Support |
|--------------|------------|----------|---------|
| **Community** | Self-host, MIT core | Basic / break-glass | Community |
| **Team** | Self-host | SSO seats | Email |
| **Business** | Managed multi-tenant | SSO + audit | SLA |
| **Enterprise** | Dedicated / VPC / on-prem | SCIM + SAML + residency | Named TAM |

Implementation: license JWT or control-plane entitlement (M3+); usage metering for bot-minutes optional (M4).

---

## Observability, backups, and DR

| | Today | Target |
|--|--------|--------|
| Logs | journalctl | Structured JSON + ship (M4) |
| Metrics | None | RED metrics per tenant (M4) |
| Traces | None | Harness run spans (M4) |
| Backup | Daily SQLite timer (`deploy/superbot-backup.sh`) | Managed automated + customer S3 (M3) |
| DR | Operator runbook | Tested restore, RPO/RTO in contract (M3 managed) |

---

## Compliance (path, not promises)

| Framework | Intent |
|-----------|--------|
| **GDPR** | Privacy policy, subprocessors, DPA, erasure for managed tenants (M4) |
| **SOC 2** | Control mapping during M3; Type II pursuit in M5 |
| **Data residency** | UK/EU region choice for managed (M4); enterprise dedicated (M5) |

No certification claims until audits complete.

---

## Documentation & onboarding

| Deliverable | Milestone |
|-------------|-----------|
| Operator guide (install, upgrade, backup) | M0 ✓ expand |
| IdP setup (Entra, Google) | M2 |
| Sales/security pack (architecture, data flow) | M3 |
| End-user onboarding in client | M3 |

---

## Licensing & upstream

- **CG-Labs/superbot** is an **MIT-licensed** fork and continuation of the open-source line associated with **[davidondrej/superbot](https://github.com/davidondrej/superbot)** (original MIT copyright David Ondrej in [`LICENSE`](../LICENSE)).
- Commercial **trademarks, managed service, and enterprise modules** may be offered under separate terms; core server remains fork-friendly where MIT allows.
- Attribution and upstream goodwill preserved in release notes and docs; security fixes contributed back when practical.

---

## Now / next / later

| Horizon | Focus |
|---------|--------|
| **Now** | Dogfood on Linode; client parity for routines + screen ✓; Compose image; approvals follow-ups ([list](approvals-followups.md)) |
| **Next** | Multi-user data model; Entra + Google OIDC; RBAC v1; private beta billing |
| **Later** | Public launch + stores; managed multi-tenant; SCIM; SOC 2; per-bot sandboxes |

---

## Risks & open questions

| Risk | Mitigation |
|------|------------|
| Harness vendors change CLI/security model | Adapter versioning; feature detection |
| SSO complexity (SAML tenants) | OIDC-first; SAML in M5 with paid SOW |
| Multi-tenant bug → data leak | Tenant ID in every query; integration tests; external pen test before M3 GA |
| 4 GB VPS too small for computer use | Tiered hardware guide; managed sizes |
| MIT fork vs commercial moat | Managed ops, compliance, enterprise features as paid layers |

**Open questions**

1. Single shared computer vs per-bot container for v1 commercial default?
2. First managed substrate: Linode API vs Kubernetes vs fly/machines?
3. Seat-based vs bot-concurrency pricing?
4. Keep embedded `web/` or client-only for product UX?
5. Which harness is “supported” for enterprise SLAs (Claude only vs all three)?

---

## Milestone map (phases)

```text
M0 Baseline ──► M1 Foundation hardening ──► M2 Multi-user + SSO
                                                    │
                    M5 Enterprise ◄── M4 Public launch ◄── M3 Private beta
```

*Maintainers: CG-Labs product/engineering. Update this doc when ADRs land in `docs/adr/`.*