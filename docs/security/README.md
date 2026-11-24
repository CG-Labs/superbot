# Security and architecture pack

For buyers, security reviewers and procurement. It describes SuperBot as the code works today, and links each claim to the design record (ADR) behind it. Anything not built yet is marked **Planned**. Part of [#41](https://github.com/CG-Labs/superbot/issues/41).

"Operator" below is whoever runs the SuperBot server: the customer when they self-host, or the provider of a managed service. Most security features are settings the operator turns on. Where a default matters, it is stated.

## The pack

| Page | What it answers |
|------|-----------------|
| [Architecture](architecture.md) | The parts, where they run, how they connect, and the trust boundaries between them. |
| [Data flows](data-flows.md) | What data is stored where, how it is encrypted in transit and at rest, and what leaves for model providers, push, email, billing and backups. |
| [Access control and isolation](access-control.md) | Sign-in, roles, Bot permissions, per-run Bot tokens, approvals, the audit log, the licence key, and how one user is kept from another. |
| [Subprocessors](subprocessors.md) | Every outside service the code can talk to, what it receives, and the setting that turns it on. |
| [Security questionnaire FAQ](questionnaire-faq.md) | Short answers to common questionnaire questions. |
| [Machine recovery objectives](machine-recovery-objectives.md) | Backup schedule, RPO and RTO per plan for managed machines, as text for an SLA or DPA. |
| [SOC 2 control mapping](soc2-control-mapping.md) | Each SOC 2 Security, Availability and Confidentiality criterion: what the product does, what the operator or customer must do, and the gaps. A self-assessment, not a certification. |
| [Privacy policy (template)](privacy-policy-template.md) | A draft privacy policy for a managed provider: what it collects, why, on what basis, for how long, who receives it, and people's rights. For legal review; not legal advice. |
| [Terms of service (outline)](terms-of-service-outline.md) | The sections a managed provider's terms need, each with the product facts to check it against. For legal review; not legal advice. |
| [Data Processing Agreement (template)](dpa-template.md) | A draft GDPR Article 28 DPA: instructions, subprocessors and their annex, breach notification, help with requests, deletion at the end, and technical and organisational measures built only from controls in the code. For legal review; not legal advice. |
| [DPIA (template)](dpia-template.md) | A draft data protection impact assessment for a customer of a managed service: the processing, necessity, risks such as model providers' regions and Bots' actions, and the measures SuperBot has for each. For legal review; not legal advice. |
| [GDPR guide for self-hosters](gdpr-self-hosting.md) | Controller and processor roles, where personal data lives, retention settings, how to answer access and erasure requests with `botctl` and the admin API, breaches, and what is still missing. |
| [SOC 2 readiness checklist](soc2-readiness-checklist.md) | Every gap in the mapping as a checklist item: owner, evidence to collect, product or process, and whether it is done, partial or a gap; what to do before engaging an auditor; Type I and Type II. A readiness path, not a certification. |
| [Security policy set](policies/README.md) | Draft policies for a managed provider: information security, access control, change management, an incident response plan, vendor management, business continuity and disaster recovery, data classification and retention, acceptable use, and a code of conduct and ethics. Each has an owner role, a review cadence and the checklist items it covers; none names a person or is adopted yet. |
| [SOC 2 Type II evidence plan](soc2-evidence-plan.md) | For each criterion, the evidence SuperBot already produces (audit events, CI runs, the access-review report, drills), how and how often to collect it, and what is still manual. A plan, not a certification. |
| [Policy register](policy-register.md) | The format of the private register the security owner keeps of role holders, policy approvals, acknowledgements and training, risks, management reviews, vendors and exceptions, with a [template](policy-register-template.json), and the command that checks it against the policies' cadences each month. |
| [Configuration baseline](configuration-baseline.md) | The settings every managed server runs with, why, and the command that checks each; how to check a server quarterly and after changes. A draft, not adopted. |

Earlier reviews: [auth review, November 2026](auth-review-2026-11.md) and its [SCIM follow-up](auth-review-2026-11-scim.md).

## Keeping it accurate

- Every statement here must match the code on `main`. When a change makes one wrong, the same PR fixes the page.
- Links in this folder are checked by `cargo test` (`server/tests/security_docs_links.rs`), on every change to `docs/`, the workflows or the code: each relative link must point at a file that exists, each `#anchor` into a Markdown file at a heading that exists, each `ADR NNNN` at an ADR that exists, and each repository path in inline code at a file that exists. The pages in [`policies/`](policies/README.md) are checked the same way, and each policy must have an owner role, an approver, a review cadence and only checklist items that exist, with no email address; the incident response plan must keep its severity, runbook, communication and review sections. The evidence plan must keep a row for every criterion and list every checklist row. The readiness checklist's rows and summary are checked too, and so are the legal templates: each must say it is a draft for legal review and not legal advice, use placeholders for the provider's details, and the DPA must keep its breach, measures, subprocessor and data residency sections, the subprocessor annex linking the [subprocessor list](subprocessors.md), and the DPIA its sections from need to sign-off.
- The legal templates state only what the code does. A change that makes a statement in them wrong fixes it in the same PR, like any page here.
- Numbers (session lifetimes, backup schedules, limits) are SuperBot's defaults. An operator who changes them must restate them in their own copy.

## Not in this pack yet (Planned)

- SOC 2 Type II (M5, [#57](https://github.com/CG-Labs/superbot/issues/57)) ([roadmap](../ROADMAP.md)). The [readiness checklist](soc2-readiness-checklist.md) is the path to it; the [policy set](policies/README.md) is drafted but not adopted, no auditor is engaged and no observation period has started. SuperBot is not SOC 2 certified.
- An external penetration test before M3 general availability ([roadmap risks](../ROADMAP.md)).
- A reviewed, published privacy policy, terms, DPA and DPIA, and the managed service's own subprocessor list (M4, GDPR row of the [roadmap](../ROADMAP.md)). The [templates](dpa-template.md) above are drafts until counsel reviews them and a provider fills them in. Erasure is built ([ADR 0102](../adr/0102-erasing-a-users-data.md)); a single export of a person's data is not ([what is missing](gdpr-self-hosting.md#what-exists-and-what-is-missing)).
