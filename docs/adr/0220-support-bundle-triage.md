# 0220: Support bundle triage: the first read of a customer's bundle, offline

## Status

Accepted (24 Nov 2026). Eighth slice of enterprise support playbooks in M5, [#60](https://github.com/CG-Labs/superbot/issues/60), after the support bundle ([ADR 0131](0131-support-bundle.md)), the TAM programme and health score ([ADR 0144](0144-tam-programme-and-health-score.md)), the score's history ([ADR 0157](0157-health-score-history-and-console.md)), the support report ([ADR 0167](0167-support-report-from-ticket-exports.md)), the offline support check ([ADR 0187](0187-offline-support-check-and-bundle.md)), incident review drafts ([ADR 0201](0201-incident-review-drafts.md)) and the support readiness check ([ADR 0211](0211-support-readiness-check.md)).

Numbering: this number was reserved for this work.

## Context

Every playbook asks the customer for a support bundle, and the bundle has what support asks first: the status page's checks, approvals and runs right now, the last 15 minutes' errors, machines and hosts, the health score's six signals with their reason codes, the score's history, a week of audit failures by action, botd's newest log lines, or, when botd is down, `botd support check`'s findings. But it arrives as nine JSON and text files, and the support engineer on level 1 has to read them all, know which field matters, size the ticket against [severity](../support/severity.md), and find the runbook. That is slow when the clock on a Severity 1 response is 30 minutes, and inconsistent between engineers: the same `bad_signature` count sends one to the SAML runbook and another to the sign-in one.

Every rule for reading a bundle is already written down, scattered across the playbooks: severity's examples (a whole Incus host down is Severity 2, backups past their RPO are Severity 2, the server not answering is Severity 1), the health score's "when it's watch or at risk" paragraphs, the runbooks' reason tables, and `botd support check`'s fixes. They can be applied mechanically.

Constraints: Rust first, no new dependencies; the bundle is the customer's file and untrusted; nothing that reaches a customer's server or a ticket system; and no change to botd's behaviour, RBAC, SAML, the audit log, vaults or air-gapped installs, which other M5 tracks are changing at the same time.

## Decision

### One offline command on the support engineer's machine

`botctl support-triage <bundle>` (`server/src/support_triage.rs`, compiled into `botctl` beside the support report, whose plans and response targets it reuses) reads a bundle and prints a triage: the suggested severity and the findings that set it, then each finding with its level, the severity it suggests, a sentence with the bundle's counts and reason codes, its evidence (file and field), the runbooks to read and the next step, then the runbooks to open and the questions for the customer. Text, Markdown for the ticket's internal note, or JSON for a ticket system's hook. It exits 1 when it suggests Severity 1 or 2, with the triage still on stdout, so a hook can raise the ticket.

It reads either bundle, told apart by their files (`check.json` and `logs.txt` are the offline one's), as a tar, a gzipped tar, the unpacked folder or the folder holding it, or a tar on stdin. With `--plan` it adds the plan's first response target for the suggested severity from the support report's table, so both tools agree with severity.md.

### Rules from the playbooks, each with its runbook

Each rule is the playbooks' own: status page components by level and component (a major outage of the API or database suggests Severity 1; of machines, runners or notifications, Severity 2); approvals waiting while every notification fails (2); request and run failure rates over the last 15 minutes, with minimum counts so a quiet server isn't judged on two requests; Incus hosts down, machines past their RPO (2) or in error (3); no harness and no managed machines (2); the health score's signals at risk or watch, mapped as the health score page says, with the reason codes choosing the SAML, sign-in or SCIM pages; a falling score; audit failures and denials grouped by the runbook they point at; log warnings counted by message with numbers taken out, and panics, which are bugs for level 3; and, offline, `botd support check`'s failures and warnings with its own fixes (botd not running suggests Severity 1, unless stopped on purpose). The SAML-only reason codes are a list in the code, kept equal by a test to the codes the SAML runbook's table has and the sign-in one's doesn't; another test checks every runbook and anchor the code names exists.

The suggestion is the most severe finding's. Support still sets the severity: a bundle sees the server, not how many people are stuck. Severity 1 and 2 are for production, so a server in testing mode is held to Severity 3 and the triage says so; `--production` lifts that for a customer whose production server runs in testing mode anyway.

### The bundle is untrusted input

Only the eleven file names bundles use are read, only as plain files at most one folder deep; two files with one name, or files from two folders, are refused rather than guessed between or mixed; the whole is at most 64 MiB unpacked, checked while reading, so a gzip bomb stops at the limit; nothing is written to disk. Every string taken from the bundle is cut to 240 characters with control characters removed, so a crafted incident title or log line can't rewrite the terminal, and the Markdown escapes `\`, `&`, `<`, `>`, `|`, `[` and `]`, so it can't add HTML, break the table, or make a link or an image a ticket system would fetch. The triage adds nothing the bundle doesn't have, and botd redacted the bundle before it was sent.

### Kept in step with the bundles

botd's test build includes the triage, and tests build a real online bundle (`support::build`, with an open incident and failed SAML sign-ins) and a real offline one (`support_check::bundle`), check every file in them is one the triage reads, triage them, and check the findings: the incident as a Severity 1 on the API, the sign-in failures to the SAML runbook, every warning and failure `botd support check` reported. A test fails when either bundle's format number changes without the triage's.

## Alternatives

- **Put the triage in botd, or in the bundle.** The customer's admin would see a severity before support did, and a botd that's down can't triage itself. The triage is the Provider's judgement against the Provider's playbooks, so it runs where the Provider reads the bundle; the bundle stays facts.
- **A ticket system integration.** Each has its own API and credentials, which don't belong in `botctl`; the JSON output and exit code let any system's hook call it.
- **Read the runbooks at run time to pick the rule.** The playbooks are prose for people; the rules are a handful of thresholds and codes, kept in step by tests instead.
- **Decide the severity.** Severity depends on how many people are affected and whether there's a workaround, which no bundle shows; the triage suggests and says why, and never lowers what the customer said.
- **Flag every audit failure or log warning.** A week of audit events always has some denied sign-ins, and botd logs warnings in its normal course; they're counted, grouped and listed as context, and only a group of 10 or more is a warning.

## Tests

`support_triage`'s unit tests: a healthy bundle with no findings and the usual questions; status components by level and component, the worst first, with open incidents and not resolved ones; approvals that reach nobody as one finding instead of three, error and failure rates with their minimums, runs waiting, machines, hosts and RPO breaches, the setup checklist; no harness and no machines; each health score signal's level, severity and runbooks, reason codes in the summary, the at-risk band; SAML and sign-in reason codes choosing the runbook; a falling score and a steady one; audit failures grouped, with reasons, SAML seen by method, and the warning threshold; log messages counted by shape and panics; the offline check's findings with their fixes, logs read as JSON after a collector's prefix or as text, and no logs; testing mode's cap and `--production`; versions behind by minor and patch, a recent restart, a newer format and a stale bundle; the response target per plan; control characters and HTML out of the output; an unreadable file and missing files; tars plain and gzipped, folders, two bundles, duplicate files and not a tar; a gzip bomb; options; and every runbook and anchor named existing, with the SAML codes matching the runbooks. `botctl`'s test reads a folder, a tar and stdin, and exits 1 only when it suggests Severity 1 or 2. botd's tests triage the real online and offline bundles. `tests/support_docs.rs` checks the triage page documents every option and finding, and that the index, the support bundle page and escalation point at it.
