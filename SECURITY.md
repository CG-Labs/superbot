# Security policy

Thank you for helping keep SuperBot and the people who run it safe. This policy covers how to report a vulnerability, what happens next, and what is in scope.

## Supported versions

SuperBot is before 1.0, so only the newest code gets security fixes:

| Version | Supported |
|---------|-----------|
| `main`, and the `main` and `sha-<commit>` images built from it | Yes |
| The newest release (its `X.Y.Z`, `X.Y` and `latest` images), once there is one | Yes |
| Older releases | No: upgrade to the newest release or `main` |

Fixes land on `main` first and reach the `main` image when they merge. A release that needs a fix gets a new patch release, with the fix in [CHANGELOG.md](CHANGELOG.md) under **Security**. The weekly image rebuild picks up Debian's fixes without a release ([ADR 0084](docs/adr/0084-published-image-with-computer-use.md)).

## Reporting a vulnerability

**Please don't report security problems in public issues, pull requests or discussions.**

Report privately through GitHub's private vulnerability reporting: open the repository's [Security tab](https://github.com/CG-Labs/superbot/security) and choose **Report a vulnerability**, or go straight to [the report form](https://github.com/CG-Labs/superbot/security/advisories/new). Only the maintainers see the report, and we can discuss it, agree a fix and publish an advisory there with you.

> **Operator TODO:** a repository owner must turn on private vulnerability reporting (Settings, then Code security, then Private vulnerability reporting). Until it is on, the form above isn't offered. If you also want an email contact, for reporters without a GitHub account or for the managed service, add it here. Don't publish one nobody reads.

Please include:

- what is affected (component, version or commit, install method: installer, Docker Compose or managed);
- how to reproduce it, ideally step by step or with a proof of concept;
- what an attacker gains, and what they need first (an account, a role, network access);
- any fix or mitigation you suggest.

## What happens next

These are our targets, in calendar days from your report:

| Step | Target |
|------|--------|
| We acknowledge the report | 3 days |
| We confirm whether it's a vulnerability and its severity (CVSS) | 10 days |
| Fix released for Critical and High | 30 days |
| Fix released for Medium and Low | 90 days |

We keep you up to date in the advisory, at least every 14 days until it is fixed. When the fix is out, we publish a GitHub security advisory (with a CVE where one applies) and credit you unless you'd rather we didn't. We ask you to keep the details private until then, or for 90 days from your report, whichever comes first; if a fix needs longer, we'll explain why and agree a date with you. If the problem is already being exploited, we may publish sooner, with mitigations.

## Scope

In scope:

- the code in this repository: `botd` and `botctl`, the machine agent, the web, mobile and admin clients, the installers and the backup and restore tools;
- the container images this repository publishes (`ghcr.io/cg-labs/superbot` and `ghcr.io/cg-labs/superbot-caddy`) and how CI builds, signs and publishes them;
- SuperBot's documented security promises, such as isolation between users and between Bots, approvals, and saved secrets never returned by the API or written to logs ([security pack](docs/security/README.md)).

Out of scope:

- vulnerabilities in a harness (Claude Code, Codex, Pi, Hermes Agent), a model provider, an identity provider or another dependency: report them to that project. Do tell us if SuperBot uses it in a way that makes it worse;
- a self-hosted install that is misconfigured against the [deployment guide](deploy/README.md), such as one with authentication turned off;
- things a Bot does because its owner or an approver allowed it;
- denial of service by sheer volume, social engineering, physical attacks, and reports from automated scanners with no shown impact;
- testing against a managed SuperBot service or anyone else's install. Test against your own install.

## Safe harbour

If you act in good faith under this policy, we will consider your research authorised, won't take legal action against you or ask anyone else to, and will help if someone else does. Good faith means you:

- test only against an install you own or have permission to test;
- don't access, change or keep other people's data beyond the least needed to show the problem, and delete it after;
- don't degrade service for others;
- report to us privately and give us reasonable time to fix it before telling anyone else.

If you're unsure whether something is allowed, ask in a private report first.
