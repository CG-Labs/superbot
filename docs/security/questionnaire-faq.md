# Security questionnaire FAQ

Short answers to common questions, as of the code on `main`. Each links to the detail. Part of the [security pack](README.md).

**Where is our data stored?**
Organisation data (users, chats, approvals, audit log, secrets, billing records) is in botd's SQLite database on the operator's server. On managed plans, each user's working files, Bot memory and harness logins are on that user's own machine, and in that machine's backups. Three options change that: a pinned person's chats, sign-ins and audit details can sit in a chat store in their region ([residency pins](data-flows.md#in-a-regions-chat-store-residency-pins)); secrets can come from your own secrets manager instead ([external secret stores](data-flows.md#external-secret-stores)); and audit events can be copied to your SIEM and an S3 archive. See [data flows](data-flows.md#what-is-stored-where).

**Can we choose the region?**
Yes, for machines and their backups. An admin sets a data region for your account or team, such as London (`gb-lon`) or Frankfurt (`de-fra-2`). Your machines are made only there, their backups go to a store there, and nothing is moved out unless you ask ([ADR 0117](../adr/0117-uk-eu-data-regions.md)). Under a residency agreement the provider pins you to that region: backups, restores and moves elsewhere are refused and audited, and the region can't change until it is unpinned with a reason ([ADR 0129](../adr/0129-contractual-data-residency.md), [DPA Annex IV](dpa-template.md#annex-iv-data-residency)). Runs go only to a computer in the region ([ADR 0267](../adr/0267-runs-on-a-computer-in-the-pins-region.md)). When the operator gives botd a store for the region (`REGION_DATA_DIRS`), a pinned person's chats, routines, approvals, Bots' memory, sign-ins, own secrets, second factor and audit details are kept there too ([ADR 0215](../adr/0215-pinned-chats-in-a-store-in-their-region.md), [ADR 0316](../adr/0316-audit-details-in-the-regional-store.md)). Their account, their Bots' records and server backups still stay where the operator runs botd; the operator states that region, and can require every pin to match it ([ADR 0184](../adr/0184-botds-own-data-region.md)). Audit export holds back a pinned person's details from a sink stated to be in another region ([ADR 0330](../adr/0330-audit-export-held-to-a-pins-region.md)). A residency report, checkable with `jq` and `sha256sum`, shows where the data is and what the pin doesn't cover ([ADR 0155](../adr/0155-residency-reports.md)). Self-hosting runs wherever you put it. See [residency pins](data-flows.md#in-a-regions-chat-store-residency-pins).

**Do model calls stay in our region?**
Only if the plan routes them to a provider endpoint in that region. A data region alone covers machines and backups. A residency pin also holds model calls: the operator marks which regions each endpoint in the plan processes in, and a pinned user's or team's runs use only those endpoints, including fallbacks and Hermes Agent's side tasks, or are refused and audited ([ADR 0139](../adr/0139-in-region-model-routes.md)). Anthropic's own API has no UK or EU processing option; Claude through a cloud platform's regional endpoint, or OpenAI's data residency by arrangement, can give one. The provider must list each model provider and region in the [DPA](dpa-template.md#iv4-model-providers).

**Is data encrypted in transit?**
Yes. HTTPS to the server, mutual TLS 1.3 between the server and machines, HTTPS to botd's outside services, and STARTTLS or TLS for email. Model providers set in the plan routing file must be `https://`; botd refuses to start on a plain `http://` provider unless it is on the same host ([ADR 0097](../adr/0097-model-providers-over-https.md)). See [encryption in transit](data-flows.md#in-transit).

**Is data encrypted at rest?**
Secrets, approval inputs and push tokens are encrypted field by field (XChaCha20-Poly1305) with a master key kept outside the data folder, which the operator can rotate ([ADR 0096](../adr/0096-master-key-rotation.md)). The whole database is encrypted with SQLCipher under a key derived from the master key, on by default for new installs ([ADR 0116](../adr/0116-database-encrypted-at-rest.md)). Files beside it (Bots' memory, user notes), the workspace and machine disks rely on the host's disk encryption. Backups are encrypted with age when the operator sets recipients, and are otherwise plain; machine backups include harness logins. See [encryption at rest](data-flows.md#at-rest).

**Do you support SSO and SCIM?**
Yes: Microsoft Entra ID, Google, Apple, GitHub, any OIDC provider, and SAML 2.0, natively ([ADR 0127](../adr/0127-native-saml-service-provider.md)) or through a Keycloak broker. Native SAML checks signed assertions (optionally encrypted), maps IdP groups to roles, supports single logout and the artifact binding, reads metadata from a URL, MDQ or a federation such as InCommon or eduGAIN, and rolls its own keys over without downtime ([guide](../sso/saml-native.md)). SCIM 2.0 provisions and deprovisions users and groups for Entra ID, Okta and others, and Google Workspace is synced from its Directory API ([ADR 0274](../adr/0274-scim-provisioning-delivered.md)). See [authentication](access-control.md#authentication).

**Do you support MFA?**
Yes. Sign-in codes and the owner's break-glass password can require a code from an authenticator app (TOTP), with one-time recovery codes. Admins require it for admins, which includes the owner, or for everyone ([ADR 0094](../adr/0094-totp-second-factor.md)). SSO sign-ins rely on your IdP's MFA: enforce it there ([IdP guides](../sso/)). With native SAML, botd can also refuse a sign-in unless the IdP says the person signed in one of the ways you list, such as an MFA context class, and can ask the IdP for them (`SSO_<ID>_AUTHN_CONTEXT`, [ADR 0190](../adr/0190-saml-required-authn-context.md), [guide](../sso/saml-native.md#require-mfa-at-the-idp)).

**How are users kept apart?**
Each user's Bots run as that user's own Unix account on one server, or on that user's own machine when managed. A Bot can do no more than its owner. On machines, Bots run as an unprivileged, locked-down user by default (no sudo or setuid programs, no other user's files or processes), checked by a red-team suite in CI ([ADR 0145](../adr/0145-locked-down-run-users-and-red-team.md)). Teammates as their own OS users (`MACHINE_TEAMMATE_USERS`) and the Linode firewall (`MACHINE_FIREWALL`) are off by default and must be turned on. See [isolation](access-control.md#isolation-between-users).

**Are users' machines hardened and patched?**
Yes, by default. Each new or rebuilt machine's first boot allows SSH only for root with a key and no forwarding, sets kernel hardening settings, turns on the distribution's unattended security updates (they never reboot by themselves; botd records when a reboot is waiting), and stops every user but root and the OS's network daemons from reaching private, link-local and cloud metadata addresses. Those egress rules bind Bots, who run as an unprivileged user by default. Each machine reports every step, and botd audits a failure. Machines made before this get it when rebuilt ([ADR 0126](../adr/0126-per-user-machine-hardening.md)).

**Can an AI agent take destructive actions on its own?**
Destructive commands, file deletes, outbound messages, network installs and `git push` wait for a person's approval by default. If the approval check can't be made, the action is refused. See [authorization](access-control.md#authorization).

**What credentials does a running Bot hold?**
A token for that run only, revoked when it ends, plus the secrets its owner and the server give it. Never botd's own secrets. With an external secrets store, a run can instead get cloud or Vault credentials made for that run alone, which expire soon after (Vault, AWS STS, GCP service account tokens or Entra ID app tokens, [ADR 0185](../adr/0185-short-lived-credentials-per-run.md)). See [per-run tokens](access-control.md#bots-a-token-for-each-run) and [secrets in an external store](access-control.md#secrets-in-an-external-store).

**Can we keep secrets in our own secrets manager?**
Yes. botd can read Bots' keys, its own settings' secrets and, if you turn it on, each user's secrets from HashiCorp Vault, Azure Key Vault, GCP Secret Manager or AWS Secrets Manager, signing in with its platform identity where it can ([ADR 0125](../adr/0125-external-secrets-backend-vault.md), [ADR 0136](../adr/0136-cloud-secret-managers.md), [ADR 0146](../adr/0146-aws-secrets-manager.md), [ADR 0174](../adr/0174-users-secrets-in-the-external-store.md)). It only reads, caches values in memory for a few minutes, and fails closed: a secret it can't read stops that run, not a fallback to an old copy. See [external secret stores](data-flows.md#external-secret-stores).

**Is there an audit log?**
Yes, append-only, with the actor of each event, viewable and exportable as CSV by admins. Kept forever unless retention is set. Tamper-evident: each event is on a hash chain that `botctl audit verify` checks, with checkpoints signed by botd and optionally timestamped by an RFC 3161 authority ([ADR 0122](../adr/0122-siem-export-and-tamper-evident-audit.md), [ADR 0149](../adr/0149-signed-and-timestamped-audit-checkpoints.md)). Every event can be streamed to up to four SIEMs (HTTPS, syslog over TLS, Microsoft Sentinel, Google SecOps, Datadog) and an S3 archive that is write-once with Object Lock by default; botd checks new archive objects against its own log daily ([ADR 0183](../adr/0183-daily-check-of-new-archive-objects.md)), and a sink that stops is shown in the app ([ADR 0154](../adr/0154-write-once-s3-audit-archive.md), [ADR 0273](../adr/0273-stopped-audit-sinks-in-the-app-and-56-delivered.md)). See [audit log](access-control.md#audit-log) and [audit export](data-flows.md#audit-export).

**Which third parties see our data?**
Only the services the operator turns on: hosting, backup storage, model providers, Stripe, push, email, webhooks, IdPs, and, when set up, a secrets manager, SIEMs and an audit archive. See [subprocessors](subprocessors.md).

**Is our data used to train models?**
SuperBot trains nothing. What a model provider does with prompts is set by that provider's terms and the account the operator or person uses.

**Does SuperBot phone home?**
No. No telemetry, analytics or crash reporting; the licence key is checked offline.

**Can SuperBot run with no internet access?**
Yes, self-hosted. The operator builds or downloads an offline bundle on a connected machine, checks its signatures, carries it in and installs or upgrades from it; upgrades check every setting first and keep a backup for rollback. Harnesses and Hermes Agent come in bundles too, or from your own registry mirrors, and `botd offline check` lists any setting that would still reach the internet. The IdP, model providers, email, storage, SIEMs and secrets store must then be ones inside your network ([ADR 0128](../adr/0128-air-gapped-self-host.md), [guide](../ops/air-gapped.md)). Each tagged release is meant to attach signed bundles; none has been tagged yet, so for now the operator makes the bundle ([roadmap](../ROADMAP.md#finish-line)).

**What are your backup RPO and RTO?**
Server: daily backups by default (RPO 24 hours), RTO target 1 hour, drilled in CI. Managed Incus machines: per plan, 8 to 26 hours RPO and 60 minutes RTO, checked and alerted. See [machine recovery objectives](machine-recovery-objectives.md).

**How long do you keep data?**
Sessions end after 7 days idle or 30 days. Backups are kept 14 days by default. The audit log and chat history are kept until a retention period is set for each; chat retention skips Bots an admin puts on a legal hold. See [retention](data-flows.md#retention).

**Can a user's data be deleted?**
Yes. Disabling someone (or an IdP's SCIM delete) ends their sessions at once and keeps their data. On request, an admin erases them: their Bots, chats, sign-ins, second factor and secrets are deleted, the audit log keeps its events under a random pseudonym, and the erasure is itself audited. It is refused while their chat is under a legal hold. Copies in backups go when the backups' retention ends ([ADR 0102](../adr/0102-erasing-a-users-data.md)). Audit events already exported to a SIEM or archive are not erased by botd; their own retention applies ([ADR 0122](../adr/0122-siem-export-and-tamper-evident-audit.md)). Teammates who leave have their OS users and homes removed from the owner's machine. How to answer access and erasure requests with these tools: [GDPR guide for self-hosters](gdpr-self-hosting.md#answering-requests).

**Do you have a DPA and privacy policy?**
Drafts, not signed documents: a [DPA template](dpa-template.md) (GDPR Article 28 terms, a breach notification clause, a subprocessor annex and technical and organisational measures taken only from the code), a [privacy policy template](privacy-policy-template.md) and a [terms outline](terms-of-service-outline.md), all for legal review and not legal advice. Self-hosters are the controller of their own data; see the [GDPR guide for self-hosters](gdpr-self-hosting.md).

**Has SuperBot been security tested?**
An internal authentication and authorization review found no critical or high issues ([auth review](auth-review-2026-11.md), [SCIM review](auth-review-2026-11-scim.md)). No external penetration test has been done yet; it is on the owner's list for SOC 2 ([roadmap](../ROADMAP.md#finish-line)).

**Are you SOC 2 certified?**
No. No SOC 2 audit has started. A [SOC 2 control mapping](soc2-control-mapping.md) shows, for each Security, Availability and Confidentiality criterion, what the product does, what the operator or customer must do, and the gaps. A [readiness checklist](soc2-readiness-checklist.md) tracks each gap with an owner, the evidence to collect and its status. For a Type II audit there is readiness tooling only: draft policies not yet adopted, monthly evidence bundles, control-testing samples and a deficiency log. No auditor is engaged and no observation period has started ([roadmap](../ROADMAP.md#compliance-path-not-promises)).

**Do you scan dependencies for known vulnerabilities?**
Yes, in CI: `cargo audit` and `npm audit` run on every lockfile change and weekly. CI fails on any RustSec vulnerability and any High or Critical npm advisory; accepted findings are listed with reasons ([ADR 0092](../adr/0092-dependency-vulnerability-scanning.md), [ADR 0115](../adr/0115-client-markdown-renderer-and-npm-audit-at-high.md)). Every container image is scanned with Grype on each build and weekly; CI fails on a Critical vulnerability with a fix, and published images are signed with cosign and carry build provenance ([ADR 0101](../adr/0101-image-scanning-and-signing.md)).

**Who is responsible for which controls?**
It depends on who runs the server. When you self-host, you are the operator: hosting, physical security, backups off the host, alert channels and your own policies are yours. On the managed service, those are the provider's. Either way, you decide who gets access and enforce MFA at your IdP. See [how to read the mapping](soc2-control-mapping.md#how-to-read-it), and the controls the managed service relies on customers for, drafted in the [system description](soc2-system-description.md#dc6-complementary-user-entity-controls).

**Is the code open?**
Yes. The code and every design decision ([ADRs](../adr/)) are public, so each answer here can be checked.
