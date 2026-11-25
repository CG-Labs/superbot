# 0292: SOC 2 system description, with its CUECs and CSOCs

## Status

Accepted (25 Nov 2026). Nineteenth slice of the SOC 2 Type II programme ([#57](https://github.com/CG-Labs/superbot/issues/57), M5). Adds a page to the security pack and the system description's approval to the register bundle of [ADR 0204](0204-policy-register-checked-and-bundled.md), which goes to format 8. No certification is claimed: SuperBot is not SOC 2 certified, and no audit has started.

## Context

A SOC 2 report opens with management's description of the system, written against the AICPA's description criteria (DC 200: DC1 to DC9). The auditor's opinion covers whether the description is fair, as well as whether the controls work. The readiness checklist's "Before engaging an auditor" asked for it in step 1 (scope, system description, carved-out subservice organisations) and step 4 (the complementary user entity controls), and nothing in the pack did either: the facts were spread across the architecture, data flows, SLO, DPA and subprocessor pages, and the **Customer** rows of the control mapping were "the start" of a CUEC list no one had written.

Without a written CUEC list, a customer can't know which controls are theirs. Without a list of what each subservice organisation is expected to do, the yearly vendor review has nothing to check their reports against.

## Decision

### A draft description in the pack

`docs/security/soc2-system-description.md` has a scope section, then a `## DCn` section for each criterion:

- **DC1, services.** What the managed service does and how customers reach it.
- **DC2, commitments and system requirements.** Commitments come from the pages that make them: the SLO's objectives and 15-minute incident note, the recovery objectives, the DPA's breach notice, subprocessor notice and deletion, residency, and `SECURITY.md`'s fix windows. The system requirements are the information security objectives, the configuration baseline and the policy set.
- **DC3, components.** Infrastructure, software, people, procedures and data, from the architecture and data classification pages. The boundary: the control plane, machines, backups, audit archive and the GitHub pipeline are inside. Customers' devices, IdPs, personal harness subscriptions and the services customers connect are outside.
- **DC4 and DC9, incidents and changes.** Placeholders filled at the end of a period from the register's incidents and production changes, the ADRs, the changelog and the change-management bundles.
- **DC5, criteria and controls.** Links the control mapping, checklist and evidence plan rather than repeating them.
- **DC6, CUECs.** Six controls, each tied to a criterion the mapping marks **Customer**: MFA at the IdP (CC6.1), deprovisioning at the IdP or through SCIM (CC6.2, CC6.3), keeping tokens and recovery codes secret (CC6.1), reading approval requests (CC6.8), reporting incidents (CC7.3), and deciding what data goes in and which providers are acceptable (C1.1). Deciding who gets access is listed as a customer responsibility, not a CUEC, as the 2022 guidance says.
- **DC7, CSOCs, by the carve-out method.** Linode (Akamai), Incus hosts, S3-compatible object storage, model providers and GitHub, each with the controls expected of it and the criteria that rely on them. GitHub is in because change evidence (CC8.1) is GitHub's records of branch protection, reviews and runs.
- **DC8, criteria left out.** None of Security, Availability and Confidentiality. Physical and environmental criteria are met through CSOCs.

The scope stays as the checklist set it: Security, Availability and Confidentiality. Processing Integrity and Privacy are excluded.

The CUECs and CSOCs feed back into the pack:

- The mapping marks CC6.8 and CC7.3 **Customer**, as their CUECs say.
- The vendor management policy moves GitHub from Low to High, since its records are evidence a control relies on. Its yearly review checks each carved-out vendor's report covers the controls the description expects.

### Approved like a policy, checked by the register

The description is management's assertion, so it needs an approval of a known text, kept up to date. That is what the register already does for policies. So `soc2-system-description` is accepted in `policyApprovals`, with the same fields and rules: approved by the role its header names (Management), at most a year old, of the text in force when the file is given.

`superbot-evidence register --description <file>` reads that file. It must have a `## DCn` section for each of DC1 to DC9, which stops a policy file passed by mistake. Without the flag, the approval is still checked for role and age.

`policies.json` keeps its `policies` list and summary to the policy set. The description goes under its own `systemDescription` key, with `summary.systemDescriptionCurrent`. Its exceptions share the file's four lists, named by its id. A current approval maps the new checklist row **CC2.3-4**, so `policies.json` now names CC2.3. The bundle's format goes to 8. No file is added, so older bundles still check in the coverage report.

### CI keeps it honest

`server/tests/security_docs_links.rs` checks the description against the pages it draws on:

- the draft and not-certified wording, and no emails;
- the header names roles;
- DC1 to DC9 appear in order;
- every **Customer** criterion in the mapping has a CUEC, and every CUEC criterion is **Customer**;
- every CSOC is on the subprocessor list, the hosting, storage and model providers and GitHub are all carved out, and CC6.4, A1.2 and CC8.1 are covered;
- GitHub is a High vendor, and vendor management links the description;
- DC2's percentages and 15 minutes match the SLO, and its breach notice matches the DPA;
- DC3 names every component in the architecture table, every role and every data class;
- the register template approves the description, and checklist row CC2.3-4 links it.

## Alternatives considered

- **A separate `system-description.json` bundle file.** That would add a file, a `SINCE_FORMAT` entry and a section, for one approval that is checked exactly like a policy's. Putting it in `policies.json` reuses the checks and adds no file.
- **Making the description a tenth policy.** It isn't one: it asserts facts, and binds no one to anything. As a policy it would join the set's acknowledgement and control-row rules, and the policy index's count. A separate key keeps the set's summary meaning what it did.
- **Generating DC3 from the architecture page.** The description is management's words, and what an auditor reads. A test that every component appears catches drift without making the page machine-written.
- **The inclusive method for subservice organisations.** That needs each vendor to agree to have its controls described and tested in SuperBot's report, which the large hosting and model providers don't do. Carve-out is the norm for them.
- **Writing the description against the AICPA's 2027 description criteria exposure draft (November 2026).** It is still out for comment. The 2018 criteria with the 2022 guidance are what reports use now; revisit when the new criteria are final.

## Tests

- **Register unit tests** cover:
  - a missing approval: an exception, and no CC2.3-4;
  - an approval more than a year old: review overdue, and no row;
  - a changed text or the wrong approver role: exceptions, with the row kept as for policies;
  - the policy summary counts only the nine policies;
  - `--description` refuses a file without DC1 to DC9 or with an unknown approver role, and reads the real page;
  - the template approves the policy set plus the description.
- **The coverage test** checks that a format-7 or format-8 bundle carrying CC2.3-4 still verifies.
- **The `register_evidence` integration test** runs with `--description` on the real page: no exceptions, CC2.3-4 counted complete in the coverage report. An edited copy is flagged as changed since approval, and a policy file given as the description is refused.
- **The docs test** is described above.

## Consequences

- The pack has a draft for both "Before engaging an auditor" steps that had nothing. CC2 has a new **Partial** row, CC2.3-4. What's left is the provider's details, approving the description, and giving the CUECs to customers.
- A provider's monthly register run now adds `--description docs/security/soc2-system-description.md`. A register without an approval of the description gets a `notApproved` exception, which is accurate until it is approved.
- When the mapping gains or loses a **Customer** status, or the subprocessor list, SLO or DPA changes, CI fails until the description agrees.

## Deferred

- DC4 and DC9 have no content until there is a period to report on. Filling them from the register and the change-management bundles is the provider's job at the end of the period.
- Giving the CUECs to customers, and recording that it was done, is a process step outside the product.
- Engaging an auditor, the readiness assessment and the observation period stay with management.
