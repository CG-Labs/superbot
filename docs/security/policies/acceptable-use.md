# Acceptable use policy

What personnel of a managed SuperBot provider may and may not do with its systems, its accounts and its customers' data. Everyone with access acknowledges it at hire and yearly. Part of the [policy set](README.md). **Draft, not adopted. SuperBot is not SOC 2 certified.**

| Field | Value |
|-------|-------|
| Owner | People lead |
| Approver | Management |
| Review | Yearly |
| Status | Draft, not yet approved |
| Controls | CC1.5-1, CC2.2-1, CC5.3-1 |

## Accounts

- Use only your own named accounts, with MFA, as the [access control policy](access-control.md#authentication) requires. Never share a password, a sign-in code, a session or a token, or use someone else's.
- Use the provider's password manager for every work credential.
- Use production access only for the work it was granted for.

## Customers' data

- Look at a customer's chats, files, screens or machine only to answer that customer's request or an incident, and record why in the ticket or incident. Never browse out of curiosity.
- Never copy customers' data to a personal device or account, a personal AI tool, or any service the provider hasn't assessed ([vendor management](vendor-management.md)). Handle it as its class says ([data classification](data-classification-and-retention.md#handling)).
- Never put customers' data, secrets or private details of the service (server addresses, hostnames, tokens, keys, emails) in this public repository, its issues or pull requests, as [`AGENTS.md`](../../../AGENTS.md) already requires of contributors, or in any other public place.
- Never use a customer's Bots or machine for anything but their request.

## Devices

Any device used for the provider's work has: full-disk encryption; a screen lock after at most 5 minutes; the operating system and browser kept up to date; and, where the provider supplies one, its endpoint protection. Lost or stolen devices are reported to the security owner at once, as a security event. Devices are wiped before reuse or disposal.

## Software and AI tools

- Install only software from trusted sources on devices used for production work.
- Coding agents and AI assistants may work on this repository's public code. They may be given production access, secrets or customers' data only through the controls the service already applies to Bots: their own account, approvals for risky actions, and the access the work needs.
- Don't turn off a security control (an approval policy, the sandbox, a firewall, MFA, encryption, scanning) without an approved exception ([information security policy](information-security.md#exceptions)).

## Reporting

Report suspected incidents, lost devices, phishing and breaches of this policy to the security owner at once ([incident response plan](incident-response.md)). Reporting in good faith is never punished.

## Monitoring

The provider's systems record what is done in them, SuperBot's audit log included ([ADR 0009](../../adr/0009-audit-events.md)), and those records are reviewed for security. Personnel are told this when they acknowledge this policy.

## Breaking this policy

Breaking this policy leads to disciplinary action, as the [information security policy](information-security.md#people) says, and access may be removed at once while it's looked into.
