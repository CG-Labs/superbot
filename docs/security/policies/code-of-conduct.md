# Code of conduct and ethics policy

The standards of integrity and conduct everyone working for a managed SuperBot provider is held to, how to raise a concern about a breach of them, and how concerns are handled. Everyone with access acknowledges it at hire and yearly. Part of the [policy set](README.md). **Draft, not adopted. SuperBot is not SOC 2 certified.**

| Field | Value |
|-------|-------|
| Owner | People lead |
| Approver | Management |
| Review | Yearly |
| Status | Draft, not yet approved |
| Controls | CC1.1-1, CC1.5-1 |

## Scope

Everyone who works for the provider and has access to its systems or its customers' data: employees, contractors, and Management. A person is accountable for what the coding agents, assistants and Bots they direct do on their behalf, as the [acceptable use policy](acceptable-use.md#software-and-ai-tools) says.

## Standards of conduct

- **Honesty in records.** Records, evidence and reports are true and complete when made. Nobody backdates, edits or deletes a record, an audit event or an evidence bundle to change what it shows; a mistake is corrected with a new, dated record. This covers the [policy register](../policy-register.md), incident and change records, and everything collected under the [evidence plan](../soc2-evidence-plan.md).
- **Honesty with customers, auditors and regulators.** Say only what is true about the service and its security. Never claim a certification, audit or control the provider doesn't have: SuperBot is not SOC 2 certified until a report says otherwise. Answer auditors' and regulators' questions fully, and never hide or withhold evidence they ask for.
- **Customers' trust.** Use customers' data only for their requests and incidents, as the [acceptable use policy](acceptable-use.md#customers-data) says, and keep what you learn about customers confidential, during your work and after it.
- **Conflicts of interest.** Tell the people lead, at hire and whenever one arises, about any interest that could sway a decision you make for the provider: a stake in a vendor, competitor or customer, outside work, or a relative in such a business. Don't take part in a decision about a vendor, customer or colleague you have such an interest in. The people lead keeps the declarations.
- **Gifts and bribery.** Never offer, pay, ask for or accept a bribe, kickback or payment to speed up an official act, directly or through someone else. Gifts and hospitality from vendors, customers or candidates above [a value the provider sets, such as 100 EUR] are declared to the people lead, and never accepted while a decision about the giver is open.
- **Fair dealing and the law.** Follow the laws that apply to the provider's work, including data protection, competition, export control and sanctions laws. Don't use a competitor's confidential information or someone else's licensed work without the right to.
- **Respect.** Treat colleagues, customers and candidates with respect. Harassment, bullying and discrimination are breaches of this policy, whatever the setting, in person or online.
- **Security duties.** Follow the [policy set](README.md). Report suspected incidents, lost devices and phishing as the [acceptable use policy](acceptable-use.md#reporting) says.

## Raising a concern

Anyone, including people outside the provider, may raise a concern that this code or another policy has been broken, or is about to be:

- with the people lead, Management, or the security owner for a security matter;
- through [the provider's confidential channel, such as a dedicated mailbox or form], which may be used anonymously;
- about Management, with [an independent reviewer the provider names, such as an outside adviser or board member], who decides who handles it.

Concerns raised in good faith are never punished, even when they turn out to be unfounded. Retaliating against someone for raising a concern, or for helping look into one, is itself a breach of this code. Knowingly false reports are not raised in good faith.

## Handling concerns

1. **Record.** The people lead records each concern in the [policy register](../policy-register.md#conduct-concerns) when it is received, by an id only: the register's evidence never names the person who raised it or the person it is about, and the details stay in a confidential case file.
2. **Triage within 7 days.** Someone holding (or deputising) the People lead, Management or the Security owner role, and not involved in the matter, triages it: what it is, who looks into it, and whether anything must happen at once (removing access, preserving evidence, or treating it as an incident under the [incident response plan](incident-response.md)).
3. **Close within 90 days.** The concern is looked into and closed with an outcome: substantiated, not substantiated, withdrawn, or referred (to an incident, the authorities or another process). A concern still open after 90 days is reported to Management with the reason.
4. **Report.** The number of concerns received, open and closed, by outcome, is part of each quarterly [management review](information-security.md#management-review), with no names.

`superbot-evidence register` checks each month that every concern was triaged and closed in time, by someone holding one of those roles ([ADR 0214](../../adr/0214-code-of-conduct-and-concerns-in-the-register.md)).

## Breaking this code

Breaking this code leads to disciplinary action, proportionate to what happened, up to ending the engagement, as the [information security policy](information-security.md#people) says. Access may be removed at once while a concern is looked into.

## Acknowledgement

Everyone in scope acknowledges this code within 30 days of joining, or of its first approval, and again each year. The people lead records each acknowledgement in the [policy register](../policy-register.md), and `superbot-evidence register` flags anyone who hasn't acknowledged it in time.
