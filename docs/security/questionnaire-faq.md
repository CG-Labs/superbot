# Security questionnaire FAQ

Short answers to common questions, as of the code on `main`. Each links to the detail. Part of the [security pack](README.md).

**Where is our data stored?**
Organisation data (users, chats, approvals, audit log, secrets, billing records) is in botd's SQLite database on the operator's server. On managed plans, each user's working files, Bot memory and harness logins are on that user's own machine, and in that machine's backups. See [data flows](data-flows.md#what-is-stored-where).

**Can we choose the region?**
The operator chooses Linode regions (`MACHINE_REGIONS`) or where Incus hosts run, and self-hosting runs wherever you put it. A UK/EU region choice for the managed service is planned for M4 ([roadmap](../ROADMAP.md)).

**Is data encrypted in transit?**
Yes, with one operator choice. HTTPS to the server, mutual TLS 1.3 between the server and machines, HTTPS to botd's outside services, and STARTTLS or TLS for email. Runs reach model providers at the `baseUrl` the operator sets in the plan routing file, which may be plain `http://`; use `https://` so prompts and keys are encrypted. See [encryption in transit](data-flows.md#in-transit).

**Is data encrypted at rest?**
Secrets, approval inputs and push tokens are encrypted field by field (XChaCha20-Poly1305) with a master key kept outside the data folder. The rest of the database, and machine disks, rely on the host's disk encryption. Backups are encrypted with age when the operator sets recipients, and are otherwise plain; machine backups include harness logins. See [encryption at rest](data-flows.md#at-rest).

**Do you support SSO and SCIM?**
Yes: Microsoft Entra ID, Google, Apple, GitHub, any OIDC provider, and SAML through a Keycloak broker. SCIM 2.0 user provisioning and deprovisioning. Native SAML is planned (M5). See [authentication](access-control.md#authentication).

**Do you support MFA?**
Yes. Sign-in codes and the owner's break-glass password can require a code from an authenticator app (TOTP), with one-time recovery codes. Admins require it for admins, which includes the owner, or for everyone ([ADR 0094](../adr/0094-totp-second-factor.md)). SSO sign-ins rely on your IdP's MFA: enforce it there ([IdP guides](../sso/)).

**How are users kept apart?**
Each user's Bots run as that user's own Unix account on one server, or on that user's own machine when managed. A Bot can do no more than its owner. On machines, running Bots as an unprivileged user (`MACHINE_BOT_USER`) and teammates as their own OS users (`MACHINE_TEAMMATE_USERS`) are off by default and must be turned on, as must the Linode firewall (`MACHINE_FIREWALL`). See [isolation](access-control.md#isolation-between-users).

**Can an AI agent take destructive actions on its own?**
Destructive commands, file deletes, outbound messages, network installs and `git push` wait for a person's approval by default. If the approval check can't be made, the action is refused. See [authorization](access-control.md#authorization).

**What credentials does a running Bot hold?**
A token for that run only, revoked when it ends, plus the secrets its owner and the server give it. Never botd's own secrets. See [per-run tokens](access-control.md#bots-a-token-for-each-run).

**Is there an audit log?**
Yes, append-only, with the actor of each event, viewable and exportable as CSV by admins. Kept forever unless retention is set. Tamper evidence (hash chain) is planned (M5). See [audit log](access-control.md#audit-log).

**Which third parties see our data?**
Only the services the operator turns on: hosting, backup storage, model providers, Stripe, push, email, webhooks, IdPs. See [subprocessors](subprocessors.md).

**Is our data used to train models?**
SuperBot trains nothing. What a model provider does with prompts is set by that provider's terms and the account the operator or person uses.

**Does SuperBot phone home?**
No. No telemetry, analytics or crash reporting; the licence key is checked offline.

**What are your backup RPO and RTO?**
Server: daily backups by default (RPO 24 hours), RTO target 1 hour, drilled in CI. Managed Incus machines: per plan, 8 to 26 hours RPO and 60 minutes RTO, checked and alerted. See [machine recovery objectives](machine-recovery-objectives.md).

**How long do you keep data?**
Sessions end after 7 days idle or 30 days. Backups are kept 14 days by default. The audit log is kept until a retention period is set. See [retention](data-flows.md#retention).

**Can a user's data be deleted?**
Users are disabled, not deleted, today; their sessions end at once. Teammates who leave have their OS users and homes removed from the owner's machine. Erasure for managed users is planned (M4).

**Has SuperBot been security tested?**
An internal authentication and authorization review found no critical or high issues ([auth review](auth-review-2026-11.md), [SCIM review](auth-review-2026-11-scim.md)). An external penetration test is planned before M3 general availability ([roadmap](../ROADMAP.md)).

**Are you SOC 2 certified?**
No. No SOC 2 audit has started. A [SOC 2 control mapping](soc2-control-mapping.md) shows, for each Security, Availability and Confidentiality criterion, what the product does, what the operator or customer must do, and the gaps. A [readiness checklist](soc2-readiness-checklist.md) tracks each gap with an owner, the evidence to collect and its status; a Type II audit is planned for M5 ([roadmap](../ROADMAP.md#compliance-path-not-promises)).

**Do you scan dependencies for known vulnerabilities?**
Yes, in CI: `cargo audit` and `npm audit` run on every lockfile change and weekly. Accepted findings are listed with reasons ([ADR 0092](../adr/0092-dependency-vulnerability-scanning.md)). Container images aren't scanned yet.

**Who is responsible for which controls?**
It depends on who runs the server. When you self-host, you are the operator: hosting, physical security, backups off the host, alert channels and your own policies are yours. On the managed service, those are the provider's. Either way, you decide who gets access and enforce MFA at your IdP. See [how to read the mapping](soc2-control-mapping.md#how-to-read-it).

**Is the code open?**
Yes. The code and every design decision ([ADRs](../adr/)) are public, so each answer here can be checked.
