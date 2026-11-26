# Secure development

The yearly secure-development course for a managed SuperBot provider's engineers: anyone who writes, reviews, builds or deploys the code and configuration the service runs. Taken within 30 days of becoming an engineer (or of the [information security policy](../policies/information-security.md)'s first approval, for engineers already there), then at least yearly. It assumes the [security awareness](security-awareness.md) course. Part of the [training](README.md). **Draft, not adopted. SuperBot is not SOC 2 certified.**

| Field | Value |
|-------|-------|
| Course | secure-development |
| Owner | Engineering lead |
| Audience | Engineers, and the engineering lead and their deputy |
| Review | Yearly |
| Status | Draft, not yet approved |
| Controls | CC1.4-1, CC2.2-1 |

## 1. How SuperBot is put together

Read the [architecture](../architecture.md) and [data flows](../data-flows.md) first. The parts that matter most for security:

- **Isolation between customers.** Each user's Bots get their own computer. Nothing one customer's Bot or machine does may reach another's data, machine or credentials.
- **The Bot is untrusted.** A Bot runs an agent harness that reads web pages, files and messages, any of which may carry instructions. Treat everything a Bot or its machine sends to the server as untrusted input, however it is phrased.
- **Secrets.** Model keys, tokens and signing keys stay server-side or in the configured secret store, are never logged, and are never sent to a machine that doesn't need them.

## 2. Writing code

- **Validate at the boundary.** Parse and check every request, webhook, file and message from a client, a Bot or a machine before acting on it. Reject what you don't expect rather than trying to repair it.
- **Check authorisation on every request**, against the user and the resource, not only that someone is signed in. Most cross-customer leaks are a missing ownership check.
- **Use the safe APIs.** Parameterised SQL, never strings built from input; no shell commands built from input; paths checked to stay inside the folder they belong to.
- **Escape output.** The client renders Bot messages with its own Markdown renderer, which shows raw HTML as text, opens only http(s) and mailto links and never loads a message's images ([ADR 0115](../../adr/0115-client-markdown-renderer-and-npm-audit-at-high.md)). Keep it that way, and never render HTML from a Bot or user anywhere else.
- **Fail closed.** On an error, deny access and say so plainly; don't fall back to a wider permission.
- **Log events, not secrets.** Record who did what for the audit trail, but never passwords, tokens, keys, customer content or anything the [data classification](../policies/data-classification-and-retention.md) marks as restricted.
- **Prefer Rust and the standard, maintained crates** the repository already uses. Every new dependency is a supply-chain risk: justify it in the pull request.

## 3. Secrets and the public repository

This repository is public. Never commit server addresses, hostnames, domains, local paths, emails, usernames, tokens or keys, as [`AGENTS.md`](../../../AGENTS.md) requires; use placeholders and `.env`. If a secret is committed, even briefly or in a branch, treat it as leaked: tell the security owner, revoke and replace it, and only then clean the history.

## 4. Reviews, CI and releases

Follow the [change management policy](../policies/change-management.md):

- Every change goes through a pull request that someone other than the author reviews and approves ([reviews and segregation of duties](../policies/change-management.md#reviews-and-segregation-of-duties)). As a reviewer, read for the risks above, not just style.
- CI must pass before merging: tests, dependency and image scans ([dependencies and the supply chain](../policies/change-management.md#dependencies-and-the-supply-chain)). Don't silence a finding to get green; fix it or record why it is accepted.
- Production changes and emergency changes follow their own sections of that policy, and are recorded in the [policy register](../policy-register.md#production-changes).

## 5. Vulnerabilities

- Vulnerabilities are fixed within the windows in the [information security policy](../policies/information-security.md#vulnerability-management): Critical and High within 30 days, Medium and Low within 90.
- Reports from outside follow [`SECURITY.md`](../../../SECURITY.md). Never discuss an unfixed vulnerability in a public issue or pull request.
- A vulnerability being exploited is an incident: start the [incident response plan](../policies/incident-response.md).

## 6. Knowledge check

Answer in your own words; whoever runs the course keeps the answers in the people lead's file. All of them should be right before the course counts as finished.

1. A new endpoint returns a file by id. What must it check before returning it?
2. A Bot's message contains an HTML image tag with a script in it. Where could that hurt, and what stops it?
3. You find an API token in a commit from last week. What do you do, in what order?
4. A dependency scan flags a High advisory in a crate you need today. What are your options?
5. Why isn't "the request came from our own machine daemon" enough to trust it?
6. What may a log line about a failed sign-in contain, and what may it not?
