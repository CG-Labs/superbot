# Security questionnaire FAQ

Short answers to common questions, as of the code on `main`. Each links to the detail. Part of the [security pack](README.md).

**Where is our data stored?**
Organisation data (users, chats, approvals, audit log, secrets, billing records) is in botd's SQLite database on the operator's server. On managed plans, each user's working files, Bot memory and harness logins are on that user's own machine, and in that machine's backups. See [data flows](data-flows.md#what-is-stored-where).

**Can we choose the region?**
Yes, for machines and their backups. An admin sets a data region for your account or team, such as London (`gb-lon`) or Frankfurt (`de-fra-2`). Your machines are made only there, their backups go to a store there, and nothing is moved out unless you ask ([ADR 0117](../adr/0117-uk-eu-data-regions.md)). The server's own database stays where the operator runs botd. Self-hosting runs wherever you put it.

**Is data encrypted in transit?**
Yes. HTTPS to the server, mutual TLS 1.3 between the server and machines, HTTPS to botd's outside services, and STARTTLS or TLS for email. Model providers set in the plan routing file must be `https://`; botd refuses to start on a plain `http://` provider unless it is on the same host ([ADR 0097](../adr/0097-model-providers-over-https.md)). See [encryption in transit](data-flows.md#in-transit).

**Is data encrypted at rest?**
Secrets, approval inputs and push tokens are encrypted field by field (XChaCha20-Poly1305) with a master key kept outside the data folder, which the operator can rotate ([ADR 0096](../adr/0096-master-key-rotation.md)). The whole database is encrypted with SQLCipher under a key derived from the master key, on by default for new installs ([ADR 0116](../adr/0116-database-encrypted-at-rest.md)). Files beside it (Bots' memory, user notes), the workspace and machine disks rely on the host's disk encryption. Backups are encrypted with age when the operator sets recipients, and are otherwise plain; machine backups include harness logins. See [encryption at rest](data-flows.md#at-rest).

**Do you support SSO and SCIM?**
Yes: Microsoft Entra ID, Google, Apple, GitHub, any OIDC provider, and SAML through a Keycloak broker. SCIM 2.0 user provisioning and deprovisioning. Native SAML is planned (M5). See [authentication](access-control.md#authentication).

**Do you support MFA?**
Yes. Sign-in codes and the owner's break-glass password can require a code from an authenticator app (TOTP), with one-time recovery codes. Admins require it for admins, which includes the owner, or for everyone ([ADR 0094](../adr/0094-totp-second-factor.md)). SSO sign-ins rely on your IdP's MFA: enforce it there ([IdP guides](../sso/)).

**How are users kept apart?**
Each user's Bots run as that user's own Unix account on one server, or on that user's own machine when managed. A Bot can do no more than its owner. On machines, running Bots as an unprivileged user (`MACHINE_BOT_USER`) and teammates as their own OS users (`MACHINE_TEAMMATE_USERS`) are off by default and must be turned on, as must the Linode firewall (`MACHINE_FIREWALL`). See [isolation](access-control.md#isolation-between-users).

**Are users' machines hardened and patched?**
Yes, by default. Each new or rebuilt machine's first boot allows SSH only for root with a key and no forwarding, sets kernel hardening settings, turns on the distribution's unattended security updates (they never reboot by themselves; botd records when a reboot is waiting), and stops every user but root and the OS's network daemons from reaching private, link-local and cloud metadata addresses. Those egress rules bind Bots once `MACHINE_BOT_USER` is on. Each machine reports every step, and botd audits a failure. Machines made before this get it when rebuilt ([ADR 0126](../adr/0126-per-user-machine-hardening.md)).

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
Sessions end after 7 days idle or 30 days. Backups are kept 14 days by default. The audit log and chat history are kept until a retention period is set for each; chat retention skips Bots an admin puts on a legal hold. See [retention](data-flows.md#retention).

**Can a user's data be deleted?**
Yes. Disabling someone (or an IdP's SCIM delete) ends their sessions at once and keeps their data. On request, an admin erases them: their Bots, chats, sign-ins, second factor and secrets are deleted, the audit log keeps its events under a random pseudonym, and the erasure is itself audited. It is refused while their chat is under a legal hold. Copies in backups go when the backups' retention ends ([ADR 0102](../adr/0102-erasing-a-users-data.md)). Teammates who leave have their OS users and homes removed from the owner's machine. How to answer access and erasure requests with these tools: [GDPR guide for self-hosters](gdpr-self-hosting.md#answering-requests).

**Do you have a DPA and privacy policy?**
Drafts, not signed documents: a [DPA template](dpa-template.md) (GDPR Article 28 terms, a breach notification clause, a subprocessor annex and technical and organisational measures taken only from the code), a [privacy policy template](privacy-policy-template.md) and a [terms outline](terms-of-service-outline.md), all for legal review and not legal advice. Self-hosters are the controller of their own data; see the [GDPR guide for self-hosters](gdpr-self-hosting.md).

**Has SuperBot been security tested?**
An internal authentication and authorization review found no critical or high issues ([auth review](auth-review-2026-11.md), [SCIM review](auth-review-2026-11-scim.md)). An external penetration test is planned before M3 general availability ([roadmap](../ROADMAP.md)).

**Are you SOC 2 certified?**
No. No SOC 2 audit has started. A [SOC 2 control mapping](soc2-control-mapping.md) shows, for each Security, Availability and Confidentiality criterion, what the product does, what the operator or customer must do, and the gaps. A [readiness checklist](soc2-readiness-checklist.md) tracks each gap with an owner, the evidence to collect and its status; a Type II audit is planned for M5 ([roadmap](../ROADMAP.md#compliance-path-not-promises)).

**Do you scan dependencies for known vulnerabilities?**
Yes, in CI: `cargo audit` and `npm audit` run on every lockfile change and weekly. CI fails on any RustSec vulnerability and any High or Critical npm advisory; accepted findings are listed with reasons ([ADR 0092](../adr/0092-dependency-vulnerability-scanning.md), [ADR 0115](../adr/0115-client-markdown-renderer-and-npm-audit-at-high.md)). Every container image is scanned with Grype on each build and weekly; CI fails on a Critical vulnerability with a fix, and published images are signed with cosign and carry build provenance ([ADR 0101](../adr/0101-image-scanning-and-signing.md)).

**Who is responsible for which controls?**
It depends on who runs the server. When you self-host, you are the operator: hosting, physical security, backups off the host, alert channels and your own policies are yours. On the managed service, those are the provider's. Either way, you decide who gets access and enforce MFA at your IdP. See [how to read the mapping](soc2-control-mapping.md#how-to-read-it).

**Is the code open?**
Yes. The code and every design decision ([ADRs](../adr/)) are public, so each answer here can be checked.
