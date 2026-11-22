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

- **Server backups**: kept for their retention period (by default 14 days on the server, `SUPERBOT_BACKUP_RETENTION_DAYS`, and 30 days off the host, `SERVER_BACKUP_RETENTION_DAYS`), then deleted ([data flows: retention](data-flows.md#retention), [ADR 0109](../adr/0109-server-backups-off-the-host.md)).
- **The pseudonymised audit log**: kept for **[period]** as evidence of security and of the erasure itself, naming each erased user only by a random pseudonym; free text in older events can still mention them, as [ADR 0102](../adr/0102-erasing-a-users-data.md) explains.
- **Billing records** at the payment processor, which the Provider keeps as controller to meet its legal obligations ([ADR 0102](../adr/0102-erasing-a-users-data.md)).
- **[Provider: per-user OS accounts on a shared server, if used, are removed by the Provider's operators after the erasure ([self-hosting GDPR guide](gdpr-self-hosting.md#erasure)).]**

10.3 The Provider confirms deletion in writing on request. Each erasure is recorded in the audit log as `user.erased`, with counts of what was deleted.

10.4 Returning data: SuperBot has no export of a whole organisation or user yet ([self-hosting GDPR guide](gdpr-self-hosting.md#what-exists-and-what-is-missing)). **[Provider: describe how you will return data, for example copies of users' working folders and an audit log export, or delete the return option.]**

## 11. International transfers

11.1 Customer Personal Data is stored in **[region(s)]**: the Service's control plane in [region] and users' machines in [regions], as set by the Provider (`MACHINE_REGIONS`, or where its Incus hosts are). Model providers and other Subprocessors process it where Annex III says.

11.2 Where Customer Personal Data is transferred outside the UK or EEA to a country without an adequacy decision, the parties rely on **[the EU Standard Contractual Clauses (Module 2 or 3), the UK International Data Transfer Addendum, or another mechanism]**, incorporated by reference, with **[completion details]**.

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
| **Retention during the term** | As the Provider sets SuperBot's retention settings: chat history `CHAT_RETENTION_DAYS` **[value, or "kept until deleted"]**; audit log `AUDIT_RETENTION_DAYS` **[value]**; harness session files `HARNESS_SESSION_RETENTION_DAYS` **[value]**; teammates' archived work `TEAMMATE_FILES_RETENTION_DAYS` **[value]**; sessions end after 7 days idle or 30 days; server backups 14 days on the server and 30 days off it; machine backups 14 days per plan. Each setting's behaviour: [data flows: retention](data-flows.md#retention). |

## Annex II: Technical and organisational measures

Measures SuperBot's code provides. "Default" says whether it is on without the Provider doing anything; rows marked **setting** are only true once the Provider turns them on, and the Provider must confirm each.

| Area | Measure | Default | Evidence |
|------|---------|---------|----------|
| Encryption in transit | HTTPS to the server (Caddy, automatic certificates); mutual TLS 1.3 between the server and each machine with a pinned per-machine certificate; HTTPS with certificate checks to outside services; model providers in the plan routing file must be `https://` or botd refuses to start. | On | [Data flows: in transit](data-flows.md#in-transit), [ADR 0031](../adr/0031-machine-enrollment-mtls.md), [ADR 0097](../adr/0097-model-providers-over-https.md) |
| Encryption at rest | Secrets, approval inputs and push tokens sealed field by field with XChaCha20-Poly1305 under a master key kept outside the data folder and out of backups; the key can be rotated. The rest of the database and machine disks are not encrypted by SuperBot. **[Provider: state the host disk encryption you use.]** | On (sealed fields) | [`server/src/secrets/sealed.rs`](../../server/src/secrets/sealed.rs), [ADR 0010](../adr/0010-secrets.md), [ADR 0096](../adr/0096-master-key-rotation.md) |
| Encrypted backups | Server backups and their off-host copies encrypted with age on new installs; plain backups are warned about, audited and can be refused (`SUPERBOT_BACKUP_ENCRYPTION=required`). Incus machine backups are encrypted only with `MACHINE_BACKUP_AGE_RECIPIENTS` (**setting**). | On for new installs | [ADR 0114](../adr/0114-backups-encrypted-by-default.md), [ADR 0071](../adr/0071-off-host-machine-backups.md) |
| Authentication | SSO with Microsoft Entra ID, Google, Apple, GitHub, OIDC, and SAML through a broker; just-in-time accounts only from an allow-list; sessions stored only as hashes and ended after 7 days idle or 30 days; sign-in failures rate-limited. | On | [Access control: authentication](access-control.md#authentication), [ADR 0012](../adr/0012-users-sessions-rbac.md), [ADR 0103](../adr/0103-sso-jit-needs-an-allow-list.md) |
| Multi-factor authentication | TOTP with recovery codes for sign-in codes and the break-glass password, required for admins or everyone by policy (**setting**: `AUTH_MFA` or the admin policy). SSO sign-ins rely on the IdP's MFA, which the Customer enforces at its IdP. | Off | [ADR 0094](../adr/0094-totp-second-factor.md) |
| Authorisation | Roles (admin, member, read-only); every API route classified, unclassified routes admin-only, checked by a test that walks the router; per-Bot sharing grants; risky agent actions (destructive commands, deletes, outbound messages, installs, `git push`) wait for a person's approval, and are refused if the check fails; each run gets its own short-lived token. | On | [Access control: authorization](access-control.md#authorization), [ADR 0007](../adr/0007-approvals.md), [ADR 0017](../adr/0017-bot-acls.md), [ADR 0083](../adr/0083-per-run-tokens.md), [`server/src/auth_review_http_tests.rs`](../../server/src/auth_review_http_tests.rs) |
| Isolation between users | One machine per user (Linode VM or Incus container); a Bot runs only on its owner's machine. Incus containers are unprivileged and firewalled from each other, the host and private ranges. Running Bots as an unprivileged user and teammates as their own OS users on machines, and the Linode Cloud Firewall, are **settings** (`MACHINE_BOT_USER`, `MACHINE_TEAMMATE_USERS`, `MACHINE_FIREWALL`). Tested in CI on real hosts. | Partly on | [Access control: isolation](access-control.md#isolation-between-users), [ADR 0036](../adr/0036-bots-on-the-users-machine.md), [ADR 0065](../adr/0065-incus-container-machines.md), [ADR 0035](../adr/0035-machine-firewall-auto-enroll.md) |
| Logging | Append-only audit log of sign-ins, access changes, Bot, policy and approval decisions, runs, denied access and machine events, each naming its actor; admins filter and export it as CSV. | On | [Access control: audit log](access-control.md#audit-log), [ADR 0009](../adr/0009-audit-events.md), [ADR 0019](../adr/0019-audit-actors.md) |
| Detection and monitoring | Alerts on bursts of failed sign-ins and second-factor guesses and admins signing in from a new network, by audit event, email and webhook; Prometheus metrics, alert rules and dashboards for the service; error reports scrubbed of prompts, chats and secrets, off unless set. | Sign-in alerts on; metrics and error reports **settings** | [ADR 0104](../adr/0104-suspicious-sign-in-alerts.md), [ADR 0089](../adr/0089-metrics-and-structured-logs.md), [ADR 0113](../adr/0113-service-dashboards-and-error-reporting.md) |
| Access reviews | An admin report of everyone's role, second factor, last sign-in, Bot access and sessions, exported as dated CSV and signed off as an audit event. **[Provider: state how often you review.]** | On | [ADR 0099](../adr/0099-access-review-report.md) |
| Availability and recovery | Daily server backups, copied off the host with an RPO that is alerted; machine backups on a per-plan schedule with RPO and RTO checked and alerted; restore drills in CI; a public status page and an uptime SLO. | On; off-host copies need a storage **setting** | [ADR 0030](../adr/0030-backup-restore-drill.md), [ADR 0109](../adr/0109-server-backups-off-the-host.md), [machine recovery objectives](machine-recovery-objectives.md), [SLO](../slo.md) |
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
| [Hosting provider, e.g. Linode (Akamai), or the Incus hosts' provider] | Users' machines | Everything on a user's machine: working folder, Bot memory, harness logins | [Region] | [Mechanism] |
| [Object storage provider] | Off-host server and machine backups | Full copies of the server's data and machines' disks, encrypted as Annex II says | [Region] | [Mechanism] |
| [Model provider(s) in the plan routing file] | Running Bots | Prompts, conversation, tool output and file contents the harness sends | [Region] | [Mechanism] |
| [Payment processor, e.g. Stripe] | Billing | User and team ids, plan, email for a new customer, token counts, seat counts; card details entered at the processor | [Region] | [Mechanism] |
| [Push service, e.g. Expo, then Apple and Google] | Push notifications, if offered | Device token, a title and a line naming the Bot | [Region] | [Mechanism] |
| [Email provider (SMTP)] | Approval and billing emails | Recipient email and the notice's text | [Region] | [Mechanism] |
| [Sign-in providers the Provider configures] | Sign-in | Standard sign-in requests; the IdP returns identity and email | [Region] | [Mechanism] |
| [Bot check on the signup form, e.g. Cloudflare Turnstile] | Access requests, if enabled | The visitor's challenge answer and IP address | [Region] | [Mechanism] |

Harness logins a user makes with their own Claude or ChatGPT subscription go to that provider under the user's own account, not as the Provider's Subprocessor ([ADR 0041](../adr/0041-machine-harness-logins-and-folder-copy.md)). **[Legal review: confirm this treatment.]**
