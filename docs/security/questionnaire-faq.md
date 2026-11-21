# Security questionnaire FAQ

Short answers to common questions, as of the code on `main`. Each links to the detail. Part of the [security pack](README.md).

**Where is our data stored?**
Organisation data (users, chats, approvals, audit log, secrets, billing records) is in botd's SQLite database on the operator's server. On managed plans, each user's working files, Bot memory and harness logins are on that user's own machine, and in that machine's backups. See [data flows](data-flows.md#what-is-stored-where).

**Can we choose the region?**
The operator chooses Linode regions (`MACHINE_REGIONS`) or where Incus hosts run, and self-hosting runs wherever you put it. A UK/EU region choice for the managed service is planned for M4 ([roadmap](../ROADMAP.md)).

**Is data encrypted in transit?**
Yes. HTTPS to the server, mutual TLS 1.3 between the server and machines, HTTPS to every outside service, and STARTTLS or TLS for email. See [encryption in transit](data-flows.md#in-transit).

**Is data encrypted at rest?**
Secrets, approval inputs and push tokens are encrypted field by field (XChaCha20-Poly1305) with a master key kept outside the data folder. The rest of the database, and machine disks, rely on the host's disk encryption. Backups are encrypted with age when the operator sets recipients. See [encryption at rest](data-flows.md#at-rest).

**Do you support SSO and SCIM?**
Yes: Microsoft Entra ID, Google, Apple, GitHub, any OIDC provider, and SAML through a Keycloak broker. SCIM 2.0 user provisioning and deprovisioning. Native SAML is planned (M5). See [authentication](access-control.md#authentication).

**Do you support MFA?**
Not in SuperBot itself. Use SSO and enforce MFA at your IdP.

**How are users kept apart?**
Each user's Bots run as that user's own Unix account on one server, or on that user's own machine when managed. On machines, separate OS users for Bots and teammates, and the Linode firewall, are settings the operator turns on. A Bot can do no more than its owner. See [isolation](access-control.md#isolation-between-users).

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
An internal authentication and authorization review found no critical or high issues ([auth review](auth-review-2026-11.md), [SCIM review](auth-review-2026-11-scim.md)). An external penetration test is planned before M3 general availability, and SOC 2 work is M3 (control mapping) to M5 (Type II) ([roadmap](../ROADMAP.md)).

**Is the code open?**
Yes. The code and every design decision ([ADRs](../adr/)) are public, so each answer here can be checked.
