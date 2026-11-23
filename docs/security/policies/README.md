# Security policy set

The written policies a managed SuperBot provider runs its service by: what people must do, who owns each duty, how often it is reviewed, and which items of the [SOC 2 readiness checklist](../soc2-readiness-checklist.md) it answers. Part of the [security pack](../README.md) and the SOC 2 Type II programme ([#57](https://github.com/CG-Labs/superbot/issues/57)). Design: [ADR 0130](../../adr/0130-policy-set-and-type-ii-evidence.md).

**These are drafts, not adopted policies. SuperBot is not SOC 2 certified, and no SOC 2 audit has started.** A policy counts as a control only once management approves it and people follow it, with evidence, for the whole observation period.

## The policies

| Policy | Owner | Review | What it covers |
|--------|-------|--------|----------------|
| [Information security](information-security.md) | Security owner | Yearly | Roles and responsibilities, security objectives, risk assessment, management review, training, exceptions, discipline. The umbrella for the rest. |
| [Access control](access-control.md) | Security owner | Yearly | Granting, reviewing and removing access to SuperBot and to the systems that run it; MFA; secrets and keys. |
| [Change management](change-management.md) | Engineering lead | Yearly | Code, dependency, release and production changes; reviews and segregation of duties; emergency changes. |
| [Incident response plan](incident-response.md) | Security owner | Yearly, after every SEV-1 or SEV-2, and after the yearly tabletop | Severity levels, roles, the runbook and containment playbooks, evidence, communication, post-incident reviews. |
| [Vendor management](vendor-management.md) | Security owner | Yearly | Assessing vendors and subprocessors before use and yearly, and telling customers about changes. |
| [Business continuity and disaster recovery](business-continuity.md) | Management | Yearly, after every test | Recovery objectives, the scenarios and how each is recovered, drills and tests. |
| [Data classification and retention](data-classification-and-retention.md) | Security owner | Yearly | Data classes, the inventory, handling rules, retention periods, legal holds and disposal. |
| [Acceptable use](acceptable-use.md) | People lead | Yearly | What personnel may and may not do with the provider's systems and customers' data. |

Owners are roles from the [checklist's owner table](../soc2-readiness-checklist.md#how-to-read-it), never people. The [Type II evidence plan](../soc2-evidence-plan.md) says what evidence shows each control operating and how it is collected.

## Adopting them

This repository is public, so it holds the policy text and nothing about the people who run a service ([`AGENTS.md`](../../../AGENTS.md)). To adopt the set, a provider:

1. **Names a person for each role** in the information security policy's [roles table](information-security.md#roles-and-responsibilities), starting with the security owner, in a private policy register kept outside this repository. Its format and a template are in [the policy register](../policy-register.md), and `superbot-evidence register` checks it against these policies' cadences each month ([ADR 0204](../../adr/0204-policy-register-checked-and-bundled.md)).
2. **Fills in its choices.** Text in square brackets, such as `[N] hours`, is the provider's to decide; each placeholder suggests a value where one is common.
3. **Approves each policy** by recording in the register the policy, the commit of this repository it was approved at and the file's SHA-256, the approver, and the date. The commit fixes the exact text approved; a later change here is a new version that needs approving again.
4. **Communicates them**: every person with access acknowledges the information security and acceptable use policies at hire and yearly, and the register keeps the acknowledgements.
5. **Starts collecting evidence** the same day, following the [evidence plan](../soc2-evidence-plan.md).

A provider that keeps its own copies edits them there and records the same approvals. A self-hosting customer running its own audit can adopt these as a starting point; the product facts in them are true of every install, the duties become theirs.

## Keeping them accurate

- Each policy has a header table with its owner (a role from the checklist), its approver, its review cadence, its status and the checklist items it covers. CI checks every header, that every item it names is a row of the checklist, that the set has all eight policies, that the incident response plan keeps its severity levels, runbook, communication and post-incident review sections, that the business continuity plan links the backup and recovery objectives it relies on, that the data classification policy cites the retention ADRs, that no policy names a person by email or claims a certification, and every link and file or ADR reference in them, like the rest of the pack (`server/tests/security_docs_links.rs`).
- Product facts in a policy (a setting, a command, a default) must match the code on `main`. A change that makes one wrong fixes the policy in the same PR, as for every page of the pack ([pack rules](../README.md#keeping-it-accurate)).
- A policy's review is recorded in the register, with any changes made here first.
