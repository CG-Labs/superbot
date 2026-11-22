# Data protection impact assessment (template)

> **Template. Draft for legal review. Not legal advice.** A starting point for a customer of a managed SuperBot service (the controller) assessing its use under GDPR Article 35 and UK GDPR. It is written from what the code on `main` does and has not been reviewed by a lawyer. Completing it does not make anyone GDPR compliant or certified, and SuperBot is not SOC 2 certified ([readiness checklist](soc2-readiness-checklist.md)). Fill in every `[bracketed]` placeholder, delete what doesn't apply, and have your data protection officer or counsel review it. Part of the [security pack](README.md).

**How to use it.** The customer completes it. Sections 2 and 6 are pre-filled with what SuperBot does, each linked to its design record (ADR); the customer must check each row against the service it actually buys, and the provider's [DPA](dpa-template.md) and subprocessor annex. Where it says **[Customer: ...]**, only the customer can answer. Where it says **[Provider: ...]**, ask the provider. Its structure follows Article 35(7): a description of the processing, necessity and proportionality, the risks, and the measures.

| | |
|--|--|
| **Controller** | **[Customer legal name]**, [Customer registered address] |
| **Service and provider (processor)** | SuperBot, run by **[Company legal name]**, [Registered address], [Contact email] |
| **DPIA owner** | **[Name, role]** |
| **Data protection officer** | **[Name, contact, or "not appointed" and why]** |
| **Version and date** | **[1.0, date]** |

## 1. Need for a DPIA

**[Customer: say why you are doing a DPIA.]** A DPIA is needed when processing is likely to result in a high risk to people. Points that often apply to AI teammates at work:

- [ ] **New technology**: AI agents that read, write and act on files, messages and outside services for people.
- [ ] **Employees' data**: the users are staff or contractors, in an unequal relationship with the controller.
- [ ] **Large scale or sensitive content**: **[number]** users; content may include customers', clients' or patients' data, or special categories.
- [ ] **Automated actions**: Bots can send messages, change files and call outside services; see risk R3.
- [ ] **Transfers**: model providers may process outside the UK or EEA; see R1.
- [ ] **[Other criteria from your supervisory authority's list]**

## 2. The processing

### 2.1 Nature

- **What SuperBot is.** AI teammates ("Bots") that people talk to in an app. Each Bot runs an agent harness that calls a model provider and works in a folder, on a server or on the user's own managed machine ([architecture](architecture.md)).
- **Where data comes from.** People's messages and files; what Bots read from tools and outside services they are given; sign-in from the customer's identity provider; usage counts. See [data flows: what is stored where](data-flows.md#what-is-stored-where).
- **How it is used.** To run the Bots people ask for, show results, keep history, enforce plan limits and bill.
- **Who can access it.** The user; people a Bot is shared with ([ADR 0017](../adr/0017-bot-acls.md)); the customer's admins in the service (roles, audit log, access reviews, [access control](access-control.md)); the provider's staff **[Provider: who, and how that access is logged]**.
- **Who receives it.** The subprocessors in the provider's [DPA Annex III](dpa-template.md#annex-iii-subprocessors). Model providers receive prompts, conversation, tool output and file contents the harness sends ([data flows: model providers](data-flows.md#model-providers-through-tier-routing)).
- **Retention.** As the provider sets SuperBot's retention settings ([data flows: retention](data-flows.md#retention)). **[Provider: the values.]**

### 2.2 Scope

- **Categories of data.** Account data (name, email, role, team, SSO identity, second-factor status, sign-in records); content (messages, routines, Bot memory, files in working folders and on machines, screens shown live, not recorded); harness logins a user makes on their machine; audit events with IP address and user agent; token usage. As in the [DPA Annex I](dpa-template.md#annex-i-description-of-the-processing).
- **Special categories and criminal data.** **[Customer: none intended, or which, why and the Article 9 condition.]**
- **People.** **[Number]** users; people named in the content they handle: **[e.g. customers, candidates, patients]**.
- **Location.** **[Region]** for users' machines and their backups; **[region]** for the service's own database and server backups; model providers as in IV.4 of the DPA. With an agreed residency, the provider pins the customer to a region and the service refuses to place, back up or restore machines elsewhere, or to run the customer's Bots on model endpoints not marked as in the region ([DPA Annex IV](dpa-template.md#annex-iv-data-residency), [ADR 0129](../adr/0129-contractual-data-residency.md)).

### 2.3 Context

**[Customer: describe the relationship with the people affected, whether they would expect this use, whether any are children or vulnerable, how they are told (privacy notice, staff policy), and any concerns raised before.]** Points to cover:

- Users choose what they send to a Bot, but may not know what the harness passes to the model provider, or which provider and region it is.
- Admins can see the audit log, including sign-in times and IP addresses ([access control: audit log](access-control.md#audit-log)). Say how that is limited to security and compliance and not used to monitor performance.
- Bots act with the access they are given. Say who decides which tools, secrets and outside services Bots get.

### 2.4 Purposes

**[Customer: the business purposes, e.g. drafting, research, coding, internal support, and the benefits to the organisation and to staff.]**

## 3. Consultation

**[Customer: who was consulted and what they said.]**

- Data protection officer: **[advice, date]**
- IT security: **[review, date]**
- Staff or their representatives (works council, union), where required: **[date, outcome]**
- The provider: its [DPA](dpa-template.md), [security pack](README.md) and answers to **[questions]**
- Model providers' terms on retention and use for training: **[links, date checked]**

## 4. Necessity and proportionality

| Question | Answer |
|----------|--------|
| Lawful basis (Article 6) | **[Customer: e.g. legitimate interests, with a balancing test attached; or contract]** |
| Special category condition (Article 9), if any | **[Customer]** |
| Is it necessary? Could less data do? | **[Customer]**. SuperBot sends model providers only what the harness sends for a run; keys and botd's own secrets don't go with it ([data flows](data-flows.md#flows-to-outside-services)). |
| Data minimisation | **[Customer: rules for what users may put in, e.g. no special categories or client data without approval]** |
| Retention | Chat history, harness sessions, archived work and the audit log have retention settings; set them ([GDPR guide: retention](gdpr-self-hosting.md#retention-settings)). **[Provider: the values.]** |
| Transparency | **[Customer: privacy notice or staff policy, and where it is]** |
| People's rights | Access, rectification, restriction and erasure are supported by admin tools; one export of everything about a person is not built yet ([GDPR guide: what is missing](gdpr-self-hosting.md#what-exists-and-what-is-missing)). **[Customer: how you will answer requests.]** |
| Processors | An Article 28 DPA with the provider ([template](dpa-template.md)), listing its subprocessors. |
| International transfers | **[Customer: which model providers and other subprocessors process outside the UK or EEA, and the transfer mechanism. Check the DPA's Annex III and IV.4.]** |

## 5. Risks

Likelihood: remote, possible or probable. Severity: minimal, significant or severe. **[Customer: score each for your use, and add your own.]**

| ID | Risk to people | Likelihood | Severity | Overall |
|----|----------------|------------|----------|---------|
| R1 | Content in prompts goes to a model provider outside the agreed region, is kept longer than expected, or is used to train models. | [ ] | [ ] | [ ] |
| R2 | Someone sees another user's Bots, chats, files or machine. | [ ] | [ ] | [ ] |
| R3 | A Bot takes a harmful action: sends a message, deletes files, or shares data with the wrong person or service. | [ ] | [ ] | [ ] |
| R4 | Content is kept longer than needed: chats, harness sessions, backups. | [ ] | [ ] | [ ] |
| R5 | Machines or their backups are placed, restored or moved outside the agreed region. | [ ] | [ ] | [ ] |
| R6 | Data is lost or unavailable after a failure. | [ ] | [ ] | [ ] |
| R7 | Inaccurate AI output is relied on in decisions about people. | [ ] | [ ] | [ ] |
| R8 | Secrets or credentials a Bot uses leak. | [ ] | [ ] | [ ] |
| R9 | The audit log is used to monitor staff beyond security and compliance. | [ ] | [ ] | [ ] |
| R10 | A person's rights request can't be answered fully or on time. | [ ] | [ ] | [ ] |
| R11 | An account is taken over. | [ ] | [ ] | [ ] |

## 6. Measures to reduce the risks

What SuperBot provides, and what the customer or provider must add. Rows marked **setting** are only true once the provider turns them on; check each with the provider ([DPA Annex II](dpa-template.md#annex-ii-technical-and-organisational-measures)).

| ID | Measures | Residual risk | Approved |
|----|----------|---------------|----------|
| R1 | The plan, not the user, picks the provider and model; only that route's key goes to a run ([ADR 0033](../adr/0033-tiers-model-routing.md)); providers must be HTTPS ([ADR 0097](../adr/0097-model-providers-over-https.md)). With a residency pin, runs use only endpoints the provider marks as in the region, fallbacks and Hermes Agent's side tasks included, or are refused and audited ([ADR 0139](../adr/0139-in-region-model-routes.md)); the mark is the provider's word, so the provider must name each endpoint and where it processes ([DPA IV.4](dpa-template.md#iv4-model-providers)). **[Customer: user guidance on what not to send; Provider: the endpoints marked as in the region, and their terms.]** | [ ] | [ ] |
| R2 | Roles; every API route classified, unclassified routes admin-only; per-Bot sharing grants; a short-lived token per run ([ADR 0083](../adr/0083-per-run-tokens.md)); one machine per user, Incus containers unprivileged and firewalled ([access control: isolation](access-control.md#isolation-between-users)). | [ ] | [ ] |
| R3 | Approvals: risky actions (destructive commands, deletes, outbound messages, installs, `git push`) wait for a person in `ask` mode ([ADR 0007](../adr/0007-approvals.md)); every decision audited. **setting**: confirm the global policy is `ask`. **[Customer: who may approve, and which tools Bots get.]** | [ ] | [ ] |
| R4 | Retention for chat history ([ADR 0098](../adr/0098-chat-retention.md)), harness sessions and archived work ([ADR 0112](../adr/0112-harness-session-and-teammate-files-retention.md)) and the audit log; machine backups 14 days by default; deleting a destroyed machine's backups ([ADR 0108](../adr/0108-deleting-a-destroyed-machines-backups.md)). **setting**: the periods. | [ ] | [ ] |
| R5 | Data regions for machines and their backups ([ADR 0117](../adr/0117-uk-eu-data-regions.md)); with a residency pin, placements, backups, restores, moves and recoveries outside the region are refused and audited, and the region can't change until unpinned with a reason ([ADR 0129](../adr/0129-contractual-data-residency.md)). The service's own database and server backups stay where the provider runs it ([DPA IV.2](dpa-template.md#iv2-what-the-pin-doesnt-cover)). | [ ] | [ ] |
| R6 | Daily server backups copied off the host, restore drills in CI; machine backups with recovery objectives checked and alerted ([ADR 0074](../adr/0074-machine-rpo-and-rto.md), [machine recovery objectives](machine-recovery-objectives.md)); backups encrypted by default for new installs ([ADR 0114](../adr/0114-backups-encrypted-by-default.md)). | [ ] | [ ] |
| R7 | **[Customer: a policy that AI output is checked by a person before it affects anyone, and no solely automated decisions with legal or similar effects (Article 22).]** SuperBot doesn't make decisions about people by itself. | [ ] | [ ] |
| R8 | Secrets sealed at rest and given only to runs that need them; the database encrypted ([ADR 0116](../adr/0116-database-encrypted-at-rest.md)); botd's own secrets never reach a run ([data flows](data-flows.md#flows-to-outside-services)). | [ ] | [ ] |
| R9 | **[Customer: a policy limiting who reads the audit log and why.]** Access reviews are recorded ([ADR 0099](../adr/0099-access-review-report.md)). | [ ] | [ ] |
| R10 | Admin tools for access, rectification and erasure ([ADR 0102](../adr/0102-erasing-a-users-data.md), [GDPR guide: answering requests](gdpr-self-hosting.md#answering-requests)). Gaps: one export per person, erasure from server backups before their retention ends. **[Customer: a process and timescale.]** | [ ] | [ ] |
| R11 | SSO with the customer's identity provider; sessions stored as hashes and time-limited; second factor for codes and the break-glass password ([ADR 0094](../adr/0094-totp-second-factor.md)); suspicious sign-in alerts ([ADR 0104](../adr/0104-suspicious-sign-in-alerts.md)). **[Customer: enforce MFA at your identity provider.]** | [ ] | [ ] |

## 7. Sign-off

| Item | Name, role, date | Notes |
|------|------------------|-------|
| Measures approved by | **[ ]** | Build the measures into the project plan, with owners and dates. |
| Residual risks approved by | **[ ]** | If a high risk remains, consult the supervisory authority before starting (Article 36). |
| DPO advice | **[ ]** | Summarise the advice, and if it wasn't followed, why. |
| Consultation responses reviewed by | **[ ]** | |
| Next review | **[date, or on a change of provider, model provider, region or use]** | Review when the service or its subprocessors change. |
