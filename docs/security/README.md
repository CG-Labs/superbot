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

Earlier reviews: [auth review, November 2026](auth-review-2026-11.md) and its [SCIM follow-up](auth-review-2026-11-scim.md).

## Keeping it accurate

- Every statement here must match the code on `main`. When a change makes one wrong, the same PR fixes the page.
- Links in this folder are checked by `cargo test` (`server/tests/security_docs_links.rs`): each relative link must point at a file that exists, and each `#anchor` into a Markdown file at a heading that exists.
- Numbers (session lifetimes, backup schedules, limits) are SuperBot's defaults. An operator who changes them must restate them in their own copy.

## Not in this pack yet (Planned)

- A SOC 2 control mapping (M3), and SOC 2 Type II (M5) ([roadmap](../ROADMAP.md)).
- An external penetration test before M3 general availability ([roadmap risks](../ROADMAP.md)).
- A privacy policy, a DPA, a published subprocessor list and erasure for managed users (M4, GDPR row of the [roadmap](../ROADMAP.md)).
