# Data Processing Agreement (template)

> **Template. Draft for legal review. Not legal advice.** This is a starting point for the provider of a managed SuperBot service, written from what the code on `main` does. It has not been reviewed by a lawyer, it is not a signed agreement, and it does not make anyone GDPR compliant or certified. Fill in every `[bracketed]` placeholder, delete what doesn't apply, and have counsel review it before use. SuperBot is not SOC 2 certified ([readiness checklist](soc2-readiness-checklist.md)). Part of the [security pack](README.md).

**How to use it.** Annex II states only measures SuperBot's code has, each linked to its design record (ADR) or code; several are settings the provider must turn on, and the annex says which. Where it says **[Provider: ...]**, the statement depends on how the provider runs the service and must be completed or deleted. Annex III must list only the outside services the managed service really uses, from the [subprocessor list](subprocessors.md). Numbers (backup schedules, retention) are SuperBot's defaults; if the provider changes them, change them here.

---

This Data Processing Agreement ("**DPA**") forms part of the agreement between:

- **[Customer legal name]**, [Customer registered address] (the "**Customer**", acting as controller); and
- **[Company legal name]**, [Registered address], [Company registration number] (the "**Provider**", acting as processor),

for the Provider's managed SuperBot service (the "**Service**") under [name and date of the main agreement] (the "**Agreement**").

## 1. Definitions

"**Data Protection Law**" means Regulation (EU) 2016/679 (the "**GDPR**"), the UK GDPR and Data Protection Act 2018, and [other applicable laws], as amended. "Controller", "processor", "personal data", "personal data breach", "data subject", "processing" and "supervisory authority" have the meanings in the GDPR. "**Customer Personal Data**" means personal data the Provider processes on the Customer's behalf in providing the Service, as described in [Annex I](#annex-i-description-of-the-processing). "**Subprocessor**" means a third party the Provider engages to process Customer Personal Data.

## 2. Roles and scope

2.1 The Customer is the controller, and the Provider the processor, of Customer Personal Data.

2.2 The Provider is a controller of the personal data it needs to run its own business: account administration, billing, security of the Service and compliance with law, as described in its privacy policy ([template](privacy-policy-template.md)). This DPA does not cover that data.

2.3 The subject matter, duration, nature and purpose of the processing, and the types of personal data and data subjects, are in [Annex I](#annex-i-description-of-the-processing).

## 3. Instructions

3.1 The Provider processes Customer Personal Data only on the Customer's documented instructions, including on transfers to third countries, unless required by law to which the Provider is subject; in that case it tells the Customer first, unless that law forbids it. The Agreement, this DPA and the Customer's use and configuration of the Service (for example which Bots run, what they are asked to do, and which model plan is chosen) are the Customer's instructions.

3.2 The Provider tells the Customer promptly if, in its opinion, an instruction infringes Data Protection Law.

3.3 The Customer is responsible for the lawfulness of the personal data it, its users and its Bots bring into the Service, and for having a legal basis for the processing it instructs.

## 4. Confidentiality

The Provider ensures that everyone it authorises to process Customer Personal Data is bound by confidentiality, by contract or by law. **[Provider: describe staff confidentiality agreements and who has production access.]**

## 5. Security

5.1 The Provider implements the technical and organisational measures in [Annex II](#annex-ii-technical-and-organisational-measures), taking into account the state of the art, the costs of implementation and the nature, scope, context and purposes of processing, and the risks to data subjects (GDPR Article 32).

5.2 The Provider may update those measures, provided the update does not lower the overall level of protection.

## 6. Subprocessors

6.1 The Customer gives general authorisation for the Provider to engage Subprocessors. The Subprocessors at the date of this DPA are in [Annex III](#annex-iii-subprocessors).

6.2 The Provider gives the Customer at least **[30] days'** notice before adding or replacing a Subprocessor, by [email to the Customer's notice contact / an update to the published list at [URL] with a subscription option]. The Customer may object on reasonable data protection grounds within that period; the parties will discuss in good faith, and if they can't resolve it the Customer may [terminate the affected part of the Service / other remedy].

6.3 The Provider imposes on each Subprocessor, by written contract, data protection obligations no less protective than this DPA, and remains liable to the Customer for its Subprocessors' performance.

6.4 SuperBot's own software sends nothing to its authors (CG-Labs): there is no telemetry, analytics or crash reporting in it, and its licence key is checked offline ([subprocessor list](subprocessors.md), [ADR 0038](../adr/0038-self-host-license-key.md)). CG-Labs is therefore not a Subprocessor through the software. **[Provider: delete this clause if you engage CG-Labs for support or hosting, and list it in Annex III.]**

## 7. Data subject requests

7.1 Taking into account the nature of the processing, the Provider assists the Customer by appropriate technical and organisational measures in responding to requests from data subjects to exercise their rights under Chapter III of the GDPR.

7.2 If the Provider receives such a request directly, it passes it to the Customer without undue delay and does not respond itself except to confirm it has passed it on, unless the Customer instructs otherwise.

7.3 The Service gives the Customer's admins these tools, described in the [self-hosting GDPR guide](gdpr-self-hosting.md#answering-requests), which applies equally to the managed Service:

- **Access**: a user's account record, sign-in identities, the Bots they can see, their routines, usage and sessions through the admin API and `botctl`, and audit events about them as CSV. There is no single export of everything about a person yet; the Provider will assist with the rest **[within [10] business days]**.
- **Rectification and restriction**: admins change a user's name or email, or disable them (which ends their sessions and pauses their routines), and both are audited.
- **Erasure**: admins erase a user (`POST /api/users/{key}/erase`, `botctl user erase`): their Bots, chats, routines, sign-ins, second factor, secrets and server folders are deleted, what they sent in others' chats becomes `[erased]`, and the audit log keeps its events under a random pseudonym. It is refused under a legal hold, while they are a team's last owner, while their plan is paying, or while they have a machine or machine backups the admin hasn't chosen to delete ([ADR 0102](../adr/0102-erasing-a-users-data.md), [ADR 0108](../adr/0108-deleting-a-destroyed-machines-backups.md)). What it leaves is in [section 10](#10-deletion-or-return-at-the-end).

## 8. Personal data breaches

8.1 The Provider notifies the Customer **without undue delay, and in any case within [48] hours**, after becoming aware of a personal data breach affecting Customer Personal Data.

8.2 The notice includes, as far as then known, and is updated as more becomes known: the nature of the breach, including the categories and approximate number of data subjects and records concerned; the name and contact details of the Provider's contact point ([Contact email]); the likely consequences; and the measures taken or proposed to address it and mitigate its effects (GDPR Article 33(3)).

8.3 The Provider takes reasonable steps to contain and investigate the breach, keeps a record of it, and gives the Customer the information it reasonably needs to meet its own obligations to notify supervisory authorities and data subjects (GDPR Articles 33 and 34). Notifying the Customer is not an admission of fault.

8.4 The Provider sends notices to [the Customer's security contact named in the order form].

8.5 Detection relies on the measures in Annex II (audit log, suspicious sign-in alerts, service alerts). **[Provider: this commitment needs an incident response plan with roles and runbooks behind it; SuperBot's [readiness checklist](soc2-readiness-checklist.md) tracks that as CC7.4-1, and records of notifications as CC7.4-2.]**

## 9. Assistance, records and audits

9.1 The Provider assists the Customer, taking into account the nature of processing and the information available to it, with the Customer's obligations under GDPR Articles 32 to 36 (security, breach notification, data protection impact assessments and prior consultation).

9.2 The Provider makes available to the Customer the information necessary to show compliance with GDPR Article 28, including this repository's [security pack](README.md) (architecture, data flows, access control, subprocessors, recovery objectives) and, for the Customer's machines, the backup and restore records described in the [machine recovery objectives](machine-recovery-objectives.md).

9.3 The Provider allows for and contributes to audits, including inspections, by the Customer or an auditor it mandates, **[no more than once a year, on [30] days' notice, during business hours, at the Customer's cost, subject to confidentiality]**, except after a personal data breach or where a supervisory authority requires it. **[Provider: if you later hold a third-party report (for example SOC 2 Type II or ISO 27001), you may offer it first. None exists for SuperBot today.]**

## 10. Deletion or return at the end

10.1 Within **[30] days** after the Service ends, the Provider, at the Customer's choice, returns Customer Personal Data in [format] and/or deletes it, unless law requires it to keep some.

10.2 Deletion uses the Service's erasure for each user (Section 7.3), with each user's machine destroyed and its backups deleted: Incus machines' off-host backups go with the erasure (`--delete-backups`; the erasure is refused while they are kept), and Linode deletes a Linode machine's own backups with the machine ([ADR 0108](../adr/0108-deleting-a-destroyed-machines-backups.md)). The following remain after that, and the Provider deletes them or lets them expire as stated:

- **Server backups**: kept for their retention period (by default 14 days on the server, `SUPERBOT_BACKUP_RETENTION_DAYS`, and 30 days off the host, `SERVER_BACKUP_RETENTION_DAYS`), then deleted ([data flows: retention](data-flows.md#retention), [ADR 0109](../adr/0109-server-backups-off-the-host.md)). The newest off-host copy is never deleted for age, so while backups keep running it is one taken after the erasure; if they stop, the last copy stays. Before confirming deletion, the Provider checks that a backup taken after the last erasure has been copied off the host, or deletes the remaining copies by hand. **[Provider: say which you do when the whole Service ends.]**
- **The pseudonymised audit log**: kept for **[period]** as evidence of security and of the erasure itself, naming each erased user only by a random pseudonym; free text in older events can still mention them, as [ADR 0102](../adr/0102-erasing-a-users-data.md) explains.
- **Billing records** at the payment processor, which the Provider keeps as controller to meet its legal obligations ([ADR 0102](../adr/0102-erasing-a-users-data.md)).
- **[Provider: per-user OS accounts on a shared server, if used, are removed by the Provider's operators after the erasure ([self-hosting GDPR guide](gdpr-self-hosting.md#erasure)).]**

10.3 The Provider confirms deletion in writing on request. Each erasure is recorded in the audit log as `user.erased`, with counts of what was deleted.

10.4 Returning data: SuperBot has no export of a whole organisation or user yet ([self-hosting GDPR guide](gdpr-self-hosting.md#what-exists-and-what-is-missing)). **[Provider: describe how you will return data, for example copies of users' working folders and an audit log export, or delete the return option.]**

## 11. International transfers

11.1 Customer Personal Data is stored in **[region(s)]**: the Service's control plane and its backups in [region], and users' machines and their backups in **[the Customer's data region, e.g. London (`gb-lon`) or Frankfurt (`de-fra-2`)]**. The Provider sets the Customer's data region for its account or team; the Service makes machines only there, keeps their backups in a store there, and refuses to move them elsewhere unless the Customer asks ([ADR 0117](../adr/0117-uk-eu-data-regions.md)). Model providers and other Subprocessors process it where Annex III says.

11.2 Where Customer Personal Data is transferred outside the UK or EEA to a country without an adequacy decision, the parties rely on **[the EU Standard Contractual Clauses (Module 2 or 3), the UK International Data Transfer Addendum, or another mechanism]**, incorporated by reference, with **[completion details]**.

11.3 **[Delete if not agreed.]** Where the parties agree data residency, [Annex IV](#annex-iv-data-residency) applies. It says what the Provider holds to the agreed region, what stays outside it, and how the Customer can check.

## 12. Liability, term and precedence

12.1 Each party's liability under this DPA is subject to the limits in the Agreement, **[except where Data Protection Law does not allow it]**.

12.2 This DPA lasts as long as the Provider processes Customer Personal Data.

12.3 If this DPA and the Agreement conflict on data protection, this DPA prevails; if the Standard Contractual Clauses apply and conflict with this DPA, they prevail.

12.4 Governing law and jurisdiction: **[as in the Agreement / [Jurisdiction]]**.

Signed for the Customer: [name, title, date] — Signed for the Provider: [name, title, date]

---

## Annex I: Description of the processing

| | |
|--|--|
| **Data subjects** | The Customer's users of the Service (employees, contractors, team members), and people whose data appears in content the Customer's users and Bots handle. |
| **Categories of personal data** | Account data: name, email, role, team, SSO identity (IdP subject), second-factor status, session and sign-in records. Content: messages to and from Bots, routines, Bot memory and each user's facts (`USER.md`), files in working folders and on users' machines, screens shown live (not recorded). Harness logins a user makes on their machine. Logs: audit events (actor, action, time, IP address, user agent). Usage: token counts and runs per Bot and model. Notification data: push device tokens, email addresses for approval and billing emails. See [data flows](data-flows.md#what-is-stored-where). |
| **Special categories** | None intended. The Customer controls what its users and Bots bring in, and must not instruct processing of special categories without telling the Provider **[and agreeing additional measures]**. |
| **Nature of processing** | Hosting, storage, backup and restore; running AI agents (Bots) on the Customer's instructions, which send prompts, conversation, tool output and file contents to the model providers of the chosen plan; sending notifications; producing usage records for billing. |
| **Purpose** | Providing the Service under the Agreement. |
| **Duration** | The term of the Agreement, then [Section 10](#10-deletion-or-return-at-the-end). |
| **Retention during the term** | As the Provider sets SuperBot's retention settings: chat history `CHAT_RETENTION_DAYS` **[value, or "kept until deleted"]**; audit log `AUDIT_RETENTION_DAYS` **[value]**; harness session files `HARNESS_SESSION_RETENTION_DAYS` **[value]**; teammates' archived work `TEAMMATE_FILES_RETENTION_DAYS` **[value]**; sessions end after 7 days idle or 30 days; server backups 14 days on the server and 30 days off it, the newest off-host copy always kept; Incus machine backups 14 days per plan (`MACHINE_BACKUP_RETENTION`), the newest of a live machine always kept; Linode machines' backups as Linode keeps them (the newest daily one and two weekly ones, [machine recovery objectives](machine-recovery-objectives.md#linode-machines)). Each setting's behaviour: [data flows: retention](data-flows.md#retention). |

## Annex II: Technical and organisational measures

Measures SuperBot's code provides. "Default" says whether it is on without the Provider doing anything; rows marked **setting** are only true once the Provider turns them on, and the Provider must confirm each.

| Area | Measure | Default | Evidence |
|------|---------|---------|----------|
| Encryption in transit | HTTPS to the server (Caddy, automatic certificates); mutual TLS 1.3 between the server and each machine with a pinned per-machine certificate; HTTPS with certificate checks to outside services; model providers in the plan routing file must be `https://` or botd refuses to start. | On | [Data flows: in transit](data-flows.md#in-transit), [ADR 0031](../adr/0031-machine-enrollment-mtls.md), [ADR 0097](../adr/0097-model-providers-over-https.md) |
| Encryption at rest | Secrets, approval inputs and push tokens sealed field by field with XChaCha20-Poly1305 under a master key kept outside the data folder and out of backups; the key can be rotated. The whole database is encrypted with SQLCipher under a key derived from the same master key. Files beside it (Bots' memory, user notes), the workspace and machine disks are not encrypted by SuperBot. **[Provider: state the host disk encryption you use.]** | On (sealed fields); database: on for new installs (`SUPERBOT_DATABASE_ENCRYPTION`) | [`server/src/secrets/sealed.rs`](../../server/src/secrets/sealed.rs), [`server/src/database_encryption.rs`](../../server/src/database_encryption.rs), [ADR 0010](../adr/0010-secrets.md), [ADR 0096](../adr/0096-master-key-rotation.md), [ADR 0116](../adr/0116-database-encrypted-at-rest.md) |
| Encrypted backups | Server backups and their off-host copies encrypted with age on new installs; plain backups are warned about, audited and can be refused (`SUPERBOT_BACKUP_ENCRYPTION=required`). Incus machine backups are encrypted only with `MACHINE_BACKUP_AGE_RECIPIENTS` (**setting**). | On for new installs | [ADR 0114](../adr/0114-backups-encrypted-by-default.md), [ADR 0071](../adr/0071-off-host-machine-backups.md) |
| Authentication | SSO with Microsoft Entra ID, Google, Apple, GitHub, OIDC, and SAML (natively or through a broker); just-in-time accounts only from an allow-list; sessions stored only as hashes and ended after 7 days idle or 30 days; sign-in failures rate-limited. | On | [Access control: authentication](access-control.md#authentication), [ADR 0012](../adr/0012-users-sessions-rbac.md), [ADR 0103](../adr/0103-sso-jit-needs-an-allow-list.md) |
| Multi-factor authentication | TOTP with recovery codes for sign-in codes and the break-glass password, required for admins or everyone by policy (**setting**: `AUTH_MFA` or the admin policy). SSO sign-ins rely on the IdP's MFA, which the Customer enforces at its IdP. | Off | [ADR 0094](../adr/0094-totp-second-factor.md) |
| Authorisation | Roles (admin, member, read-only); every API route classified, unclassified routes admin-only, checked by a test that walks the router; per-Bot sharing grants; each run gets its own short-lived token. Under the approval policy's `ask` mode, risky agent actions (destructive commands, deletes, outbound messages, installs, `git push`) wait for a person's approval and are refused if the check fails; admins can set classes to allow, save allow rules that skip asking, or switch a Bot or the server to `bypass`. New installs start in `ask`; servers installed before approvals existed start in `bypass`. **[Provider: confirm your global policy is `ask` and review allow rules and per-Bot overrides before keeping this promise.]** | Roles and tokens on; approvals on for new installs (**setting**) | [Access control: authorization](access-control.md#authorization), [ADR 0007](../adr/0007-approvals.md), [ADR 0017](../adr/0017-bot-acls.md), [ADR 0083](../adr/0083-per-run-tokens.md), [`server/src/auth_review_http_tests.rs`](../../server/src/auth_review_http_tests.rs) |
| Isolation between users | One machine per user (Linode VM or Incus container); a Bot runs only on its owner's machine. Incus containers are unprivileged and firewalled from each other, the host and private ranges. Bots run as an unprivileged, locked-down user on machines by default ([ADR 0145](../adr/0145-locked-down-run-users-and-red-team.md)); teammates as their own OS users, and the Linode Cloud Firewall, are **settings** (`MACHINE_TEAMMATE_USERS`, `MACHINE_FIREWALL`). Tested in CI on real hosts. | Partly on | [Access control: isolation](access-control.md#isolation-between-users), [ADR 0036](../adr/0036-bots-on-the-users-machine.md), [ADR 0065](../adr/0065-incus-container-machines.md), [ADR 0035](../adr/0035-machine-firewall-auto-enroll.md) |
| Logging | Append-only audit log of sign-ins, access changes, Bot, policy and approval decisions, runs, denied access and machine events, each naming its actor; admins filter and export it as CSV. | On | [Access control: audit log](access-control.md#audit-log), [ADR 0009](../adr/0009-audit-events.md), [ADR 0019](../adr/0019-audit-actors.md) |
| Detection and monitoring | Suspicious sign-in patterns (bursts of failed sign-ins and second-factor guesses from one IP or at one account, a sign-in right after them, admins signing in from a new network) recorded as audit events and counted in metrics; the ones aimed at one account also go to admins by email and webhook when those alert channels are set up. Prometheus metrics, alert rules and dashboards for the service; error reports scrubbed of prompts, chats and secrets, off unless set. | Sign-in audit events on; email and webhook channels, metrics and error reports **settings** | [ADR 0104](../adr/0104-suspicious-sign-in-alerts.md), [ADR 0089](../adr/0089-metrics-and-structured-logs.md), [ADR 0113](../adr/0113-service-dashboards-and-error-reporting.md) |
| Access reviews | An admin report of everyone's role, second factor, last sign-in, Bot access and sessions, exported as dated CSV and signed off as an audit event. **[Provider: state how often you review.]** | On | [ADR 0099](../adr/0099-access-review-report.md) |
| Availability and recovery | Daily server backups, copied off the host with an RPO that is alerted; restore drills in CI; a public status page and an uptime SLO. Incus machines: off-host backups on a per-plan schedule, with RPO and restore time (RTO) checked and alerted. Linode machines: Linode's own daily backups, with the RPO checked and alerted; SuperBot doesn't time their restores, so the restore time is the Provider's own target. **[Provider: keep only the rows for the machines you run.]** | On; off-host copies need a storage **setting** | [ADR 0030](../adr/0030-backup-restore-drill.md), [ADR 0109](../adr/0109-server-backups-off-the-host.md), [ADR 0074](../adr/0074-machine-rpo-and-rto.md), [ADR 0110](../adr/0110-linode-machine-recovery-objectives.md), [machine recovery objectives](machine-recovery-objectives.md), [SLO](../slo.md) |
| Retention and deletion | Retention settings for chat history, harness session files, teammates' archived work and the audit log, each pass audited; legal holds; erasure of a user's data with a pseudonymised audit log; deletion of a destroyed machine's backups on request. | Erasure on; retention periods **settings** | [ADR 0098](../adr/0098-chat-retention.md), [ADR 0112](../adr/0112-harness-session-and-teammate-files-retention.md), [ADR 0102](../adr/0102-erasing-a-users-data.md), [ADR 0108](../adr/0108-deleting-a-destroyed-machines-backups.md) |
| Minimising what leaves | Each outside service is off until configured; only the key for the routed model provider reaches a run, and botd's own secrets never do; push notifications carry no commands or output; the software sends nothing to its authors. | On | [Subprocessors](subprocessors.md), [data flows](data-flows.md#flows-to-outside-services) |
| Secure development | Dependency and container image vulnerability scanning in CI; signed images with build provenance; CI actions pinned by commit; design decisions recorded as ADRs; an internal authentication and authorization review. No external penetration test yet. | On | [ADR 0092](../adr/0092-dependency-vulnerability-scanning.md), [ADR 0101](../adr/0101-image-scanning-and-signing.md), [ADR 0100](../adr/0100-github-actions-pinned-by-commit.md), [auth review](auth-review-2026-11.md) |

**Organisational measures the Provider must add.** SuperBot's code can't provide these, and its [readiness checklist](soc2-readiness-checklist.md) tracks them as open: **[Provider: describe each, or remove it from this DPA until it exists]**

- A named security owner and management oversight (CC1).
- Written security policies, including access control, change management and data retention (CC5.3-1).
- Staff confidentiality, hiring checks and security training (CC1.4-1, CC2.2-1).
- An incident response plan with roles and runbooks, supporting Section 8 (CC7.4-1).
- Reviews of Subprocessors' security, including the hosting providers' own assurance reports (CC6.4-1, CC9.2-1).
- Physical security of data centres, inherited from the hosting providers in Annex III.

## Annex III: Subprocessors

**[Provider: list only the services the Service actually turns on.]** Every outside service SuperBot's code can talk to, what it receives and the setting that turns it on, is in the [subprocessor list](subprocessors.md); start from its "Services that receive customer data" table. Services in its "receive no customer data" table are not Subprocessors.

| Subprocessor | Service | Customer Personal Data it receives | Location | Transfer mechanism |
|--------------|---------|------------------------------------|----------|--------------------|
| [Hosting provider for the SuperBot server] | The control plane (botd, its database and files) | Everything the server stores: accounts, chat history, Bot memory, secrets (sealed), the audit log, server backups on the host | [Region] | [Mechanism] |
| [Hosting provider, e.g. Linode (Akamai), or the Incus hosts' provider] | Users' machines | Everything on a user's machine: working folder, Bot memory, harness logins | [The Customer's data region] | [Mechanism] |
| [Object storage provider] | Off-host server and machine backups | Full copies of the server's data and machines' disks, encrypted as Annex II says | [Server backups: the control plane's region. Machine backups: the Customer's data region] | [Mechanism] |
| [Model provider(s) in the plan routing file, each with the endpoint used] | Running Bots | Prompts, conversation, tool output and file contents the harness sends | [Region where the provider processes and stores it, from the provider's terms for that endpoint; "global" or "any" if it gives no region. See [Annex IV.4](#iv4-model-providers)] | [Mechanism] |
| [Payment processor, e.g. Stripe] | Billing | User and team ids, plan, email for a new customer, token counts, seat counts; card details entered at the processor | [Region] | [Mechanism] |
| [Push service, e.g. Expo, then Apple and Google] | Push notifications, if offered | Device token, a title and a line naming the Bot | [Region] | [Mechanism] |
| [Email provider (SMTP)] | Approval and billing emails | Recipient email and the notice's text | [Region] | [Mechanism] |
| [Webhook receivers, e.g. Slack, Mattermost, Discord] | Approval notices and server alerts, if configured | The Bot, tool, risk class, reason and a shortened command; a suspicious sign-in alert names the account's email | [Region] | [Mechanism] |
| [Sign-in providers the Provider configures] | Sign-in | Standard sign-in requests; the IdP returns identity and email | [Region] | [Mechanism] |
| [Bot check on the signup form, e.g. Cloudflare Turnstile] | Access requests, if enabled | The visitor's challenge answer and IP address | [Region] | [Mechanism] |

Harness logins a user makes with their own Claude or ChatGPT subscription go to that provider under the user's own account, not as the Provider's Subprocessor ([ADR 0041](../adr/0041-machine-harness-logins-and-folder-copy.md)). **[Legal review: confirm this treatment.]**

## Annex IV: Data residency

**[Delete this annex if no data residency is agreed.]** It applies under [Section 11.3](#11-international-transfers) and states only what SuperBot's code does ([ADR 0129](../adr/0129-contractual-data-residency.md), [ADR 0117](../adr/0117-uk-eu-data-regions.md)). Anything it doesn't cover is listed in IV.2 and IV.4; do not promise more in the Agreement.

### IV.1 The agreed region

- **Agreed Region**: **[e.g. the United Kingdom: London (`gb-lon`); or the EU: Frankfurt (`de-fra-2`)]**
- **Covered**: **[the Customer's team "[team name]" in the Service, or the named users: [list]]**
- **Reference**: **[the reference recorded with the pin, e.g. this DPA's number and date]**

The Provider pins the covered team or users to the Agreed Region in the Service, with the reference above. The Service refuses the pin unless their machines and machine backups are all in the Agreed Region already and the Service has hosts and a backup store there. While the pin holds:

(a) users' machines are made, restored and moved only on hosts in the Agreed Region;

(b) machine backups go only to a backup store in the Agreed Region. If none is available, the backup does not happen, and the Provider is alerted when a machine misses its recovery point; it is never sent elsewhere instead;

(c) a restore from a backup kept outside the Agreed Region, or onto a host outside it, is refused, including when a host is lost;

(d) the covered team's and users' data region can't be changed, and nobody whose machine or backups are outside the Agreed Region can join the covered team;

(e) Bots' runs for the covered team or users send model calls only to provider endpoints the Provider marks as in the Agreed Region, including fallbacks and the harness's side tasks; a run with no such endpoint is refused ([IV.4](#iv4-model-providers));

(f) every pin, unpin and refusal is recorded in the audit log, with the reference;

(g) **[Only if the Provider runs the server and its backup store in the Agreed Region; otherwise delete.]** the Service's own data (its database and files, and server backups) is in the Agreed Region: the Provider states so in the Service (`SERVER_DATA_REGION`, and the region of the server backups' off-host store), and the residency report shows it ([ADR 0184](../adr/0184-botds-own-data-region.md)). **[If the Provider runs with `RESIDENCY_SERVER_DATA=require`: the Service refuses any pin to another region and doesn't start unless server backups' off-host copies are in the Agreed Region.]**

(h) **[Only if the Provider keeps a chat store in the Agreed Region; otherwise delete.]** the chat history, routines, approvals (the tool calls a Bot asked to make, with their input and the decision's note) and memory (what each Bot keeps of what it has learned) of the covered team's or users' Bots, and the facts those Bots keep about each covered user, and each covered user's sign-in sessions (with the IP address and browser of each device, their SAML sign-ins and the push addresses of their phones), are kept in a database in the Agreed Region, separate from the Service's own database, with its backups in the same region; what moved there when the pin is made is recorded in the audit log, and the residency report's "Chats, routines, approvals and memory" section shows where it is ([ADR 0215](../adr/0215-pinned-chats-in-a-store-in-their-region.md), [ADR 0228](../adr/0228-routines-and-approvals-in-the-regional-store.md), [ADR 0276](../adr/0276-bots-memory-in-the-regional-store.md), [ADR 0277](../adr/0277-owners-facts-in-the-regional-store.md), [ADR 0283](../adr/0283-sign-ins-in-the-regional-store.md)). When they leave another region's such database (moved into the Agreed Region's), the Service removes them from that database's backups, normally within the hour, records it in the audit log, and the residency report lists those backups until it has ([ADR 0238](../adr/0238-clearing-moved-rows-from-store-backups.md)).

(i) Bots' runs for the covered team or users take place only on a computer in the Agreed Region: the user's machine there, or the Service's own server only where the Provider states it is in the Agreed Region (IV.1(g)); a run that would take place elsewhere, such as a covered user's run of a teammate's Bot whose machine is in another region, is refused ([ADR 0267](../adr/0267-runs-on-a-computer-in-the-pins-region.md)).

### IV.2 What the pin doesn't cover

| Data | Where it is | Note |
|------|-------------|------|
| The control plane: the Service's database (accounts, chat history, routines, sealed secrets, the audit log), the files beside it (including Bots' memory and the facts they keep about their users), and server backups | **[Where the Provider runs the server and keeps its backups, e.g. also London]** | The pin doesn't move these. They are in the Agreed Region only if the Provider runs the server and its backup store there; then IV.1(g) applies and this row can say "covered by IV.1(g)". The residency report's "botd's own data" section shows where the Provider states they are ([ADR 0184](../adr/0184-botds-own-data-region.md)). Chat history, routines, approvals, Bots' memory, the facts Bots keep about their users and their sign-in sessions aren't in this row where IV.1(h) applies. |
| Model calls outside the plan's routes | [IV.4](#iv4-model-providers) | The pin holds the plan's routes (IV.1(e)). It doesn't hold what a Bot's own tools send, such as a script calling an API with a key the user saved. |
| Push notifications, email, webhooks, billing and sign-in | As [Annex III](#annex-iii-subprocessors) says | |
| Harness logins with a person's own subscription | The model provider, under the person's own account | Not the Provider's Subprocessor (Annex III). |
| Support access | **[Where staff who can reach Customer Personal Data are, and how that access is controlled and logged]** | |

### IV.3 Changes

- The Provider unpins the covered team or users, or changes the Agreed Region, only on the Customer's documented instructions **[or: on [number] days' written notice]**. Unpinning records a reason in the audit log and moves nothing by itself.
- Moving to another region is a transfer the Customer agrees to first: machines are destroyed, their backups deleted on request ([ADR 0108](../adr/0108-deleting-a-destroyed-machines-backups.md)), the region changed, and new machines made.
- A user who leaves a covered team, including when they are removed by the Customer's identity provider, stays pinned to the Agreed Region with a pin of their own, kept from the team's with the same reference, so their remaining machine and machine backups stay held ([ADR 0171](../adr/0171-residency-startup-and-leavers.md)). The Service ends that pin by itself, recorded in the audit log, once that user has no machine and no machine backups left ([ADR 0205](../adr/0205-ending-a-kept-pin-once-the-data-is-gone.md)); the Provider may also end it sooner, recording a reason, on the Customer's documented instructions. **[If the Provider runs with `RESIDENCY_KEPT_PINS=keep`: instead, the Provider ends that pin, recording a reason, once their data is deleted or on the Customer's documented instructions.]** A user whose data is erased keeps no pin.
- If the Service can no longer keep the data in the Agreed Region (for example, the region's backup store is unavailable), it refuses backups and restores rather than using another region, and logs a warning. **[If the Provider runs with `RESIDENCY_STARTUP=refuse`: the Service also does not start while any pin can't be kept, and records that in the audit log.]** The Provider tells the Customer within **[time]** and restores in-region storage. Recovery points may be missed meanwhile.

### IV.4 Model providers

Each plan's routes, set by the Provider, decide the provider and endpoint ([data flows: model providers](data-flows.md#model-providers-through-tier-routing)). The Provider marks in the plan routing file which data regions each endpoint processes in. While the pin holds, a run for the covered team or users takes only a route whose endpoint is marked as in the Agreed Region, keeps only fallbacks that are, and is refused (and recorded in the audit log) if the plan has none ([ADR 0139](../adr/0139-in-region-model-routes.md)). The mark is the Provider's statement, not something the Service can check. **[Provider: list every endpoint marked as in the Agreed Region that the Customer's plan can route to, including fallbacks.]**

| Provider and endpoint | Where it processes | Where it stores | Source |
|-----------------------|--------------------|-----------------|--------|
| [e.g. a Claude model through a cloud platform's regional endpoint in [region]] | [Region] | [Region, or "not stored" with the retention the provider states] | [Link to the provider's terms] |

Facts to check against, as of November 2026. Confirm each provider's current terms before signing, and do not promise UK or EU processing of model calls unless every route in the plan gives it:

- **Anthropic's own API** offers US-only processing or global processing. It has no UK or EU option.
- **Claude through a cloud platform** (Amazon Bedrock, Google Vertex AI, Microsoft Foundry): the platform's region for the endpoint decides. Cross-region or global inference options can process outside it; use a regional endpoint and check the model is offered there.
- **OpenAI's API** offers data residency per project to eligible customers, by arrangement with OpenAI. Its Europe region stores and processes in the EEA or Switzerland. Its UK region stores in the UK but does not promise processing there. Some system data is excluded.
- **Routers** (for example OpenRouter) forward to upstream providers. Treat them as having no region unless their terms say otherwise.

Mark an endpoint as in the Agreed Region only if the provider's terms for that endpoint promise processing there, not only storage. With Hermes Agent, the harness's side tasks (summaries, titles, image analysis) use the run's own endpoint, and the keys of the harness's built-in providers are left out of the run. Claude Code and Codex run for a covered team or user only on a route to such an endpoint; their own logins aren't used, Claude Code's nonessential traffic to Anthropic (telemetry, error reports, update checks, WebFetch's domain check) is off, and so are Codex's analytics. A route with no endpoint from the routing file doesn't run for them.

### IV.5 Evidence

On request **[or: every [period]]**, under [Section 9](#9-assistance-records-and-audits), the Provider gives the Customer:

- the residency report for each pin (`botctl team residency <team> report`, or the admin API, [ADR 0155](../adr/0155-residency-reports.md)): where each covered person's machine, host and backups are, whether all of it is in the Agreed Region, the pin's changes, what it refused and how many runs it held to in-region routes in the period, where the Provider states the Service's own data is, and what it doesn't cover, sealed with a SHA-256 digest the Customer can check (`jq -cjS 'del(.digest)' report.json | sha256sum`). The Customer's people a pin covers see it in the app, and can download the report on their own pin, and the team's owners and admins the report on the team's pin, at any time ([ADR 0168](../adr/0168-residency-in-the-app.md));
- the audit log entries for the covered team and users, filtered by action and exported as CSV: `user.residency_pinned`, `team.residency_pinned`, `user.residency_pin_kept` (a leaver keeping the team's pin), `user.residency_pin_ended` (a leaver's kept pin ending once their machine data is gone), `user.residency_unpinned`, `team.residency_unpinned`, the `*_pin_refused` and `*_change_refused` entries, `team.join_refused`, `team.delete_refused` and `machine.residency_refused`, and `bot.run_refused` with reason `residency_pinned`, and `residency.startup_refused`; each run's `harness.invoked` entry shows the regions it was held to and any fallback left out;
- the regions view (`botctl regions`, or the admin API): each pin, its reference, and any warning that the Service can't keep it;
- for each machine, its region and host, and for each backup, the store and region it was kept in.
