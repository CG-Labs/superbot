# SOC 2 system description

The description of the managed SuperBot service that a SOC 2 report opens with, written against the AICPA's description criteria (DC 200, 2018, with the 2022 revised implementation guidance), one section for each of DC1 to DC9. Part of the [security pack](README.md) and the SOC 2 Type II programme ([#57](https://github.com/CG-Labs/superbot/issues/57), [ADR 0292](../adr/0292-soc2-system-description.md)).

**Draft, not adopted. SuperBot is not SOC 2 certified, and no SOC 2 audit has started.** This is management's description of the system for a managed provider to fill in and approve; the auditor tests it, it is not an auditor's opinion. Placeholders like [Company legal name] and [period start] are the provider's to fill in.

| Field | Value |
|-------|-------|
| Owner | Security owner |
| Approver | Management |
| Review | Yearly, and on any significant change to the system |
| Status | Draft, not yet approved |

## Scope

The system is the managed SuperBot service that [Company legal name] (the Provider) runs for its customers, over the period [period start] to [period end]. The criteria are the AICPA 2017 Trust Services Criteria (revised points of focus, 2022) for **Security**, **Availability** and **Confidentiality**; how SuperBot meets each is in the [control mapping](soc2-control-mapping.md). Processing Integrity and Privacy are not in scope ([DC8](#dc8-criteria-not-relevant-to-the-system)).

A customer that self-hosts SuperBot is its own service organisation: this description is not about its system, though the product parts of it ([DC3](#dc3-components-of-the-system)) are the same code.

The Provider approves this description like a policy, recorded in the [policy register](policy-register.md) as a `policyApprovals` entry for `soc2-system-description`, and `superbot-evidence register --description` checks that the approval is of the text in force, by the Approver role, within a year ([ADR 0292](../adr/0292-soc2-system-description.md)).

## DC1 Types of services provided

SuperBot gives each customer AI teammates (Bots) that work in chat, run routines, and act on a computer of their own. Each person on a plan gets a managed computer (a per-user machine) that their Bots run on, with a desktop the Bots can see and use. Bots run an agent harness (Claude Code, Codex, Pi or Hermes Agent) that calls the model providers the Provider routes them to. Risky actions wait for a person to approve them.

Customers reach the service through the client app (iOS, Android, web and desktop), the admin console and `botctl`, signing in with codes, a password with a second factor, or their identity provider (OIDC or SAML), with users and groups optionally provisioned by SCIM ([ADR 0023](../adr/0023-scim.md)). Plans are Starter, Pro, Max and Enterprise.

## DC2 Principal service commitments and system requirements

The Provider's commitments to customers, made in its terms, DPA and published pages, are:

| Commitment | Where it is made | What it is |
|------------|------------------|------------|
| Availability | [SLO](../slo.md) | Over a rolling 30 days: Starter 99.5%, Pro and Max 99.9%, Enterprise 99.95% by agreement. An incident note on the status page within 15 minutes of confirming an outage, updated at least hourly ([ADR 0090](../adr/0090-status-page-and-uptime-slo.md)). |
| Recovery | [Machine recovery objectives](machine-recovery-objectives.md) | An Incus machine's RPO is 26, 14 or 8 hours by plan and its RTO 60 minutes. A Linode machine's RPO is 26 hours on every plan, with a restore time target of 4 hours that is the Provider's own and not measured by SuperBot ([Linode machines](machine-recovery-objectives.md#linode-machines)). The server's RPO is 24 hours and its RTO 1 hour ([ADR 0030](../adr/0030-backup-restore-drill.md)). |
| Breach notice | [DPA template](dpa-template.md#8-personal-data-breaches), 8.1 | Without undue delay, and within [48] hours of becoming aware of a personal data breach. |
| Subprocessors | [DPA template](dpa-template.md#6-subprocessors), 6.2 | At least [30] days' notice before adding or replacing one, from the [subprocessor list](subprocessors.md). |
| Deletion at the end | [DPA template](dpa-template.md#10-deletion-or-return-at-the-end), 10.1 | Customer personal data returned or deleted within [30] days after the service ends. |
| Data residency | [DPA template](dpa-template.md#annex-iv-data-residency), Annex IV | Machines, their backups and the customer's data kept in the agreed region, with model calls in-region where the customer is pinned ([ADR 0117](../adr/0117-uk-eu-data-regions.md), [ADR 0129](../adr/0129-contractual-data-residency.md)). |
| Vulnerabilities | [`SECURITY.md`](../../SECURITY.md) | Reports acknowledged in 3 days and assessed in 10; Critical and High fixed in 30 days, the rest in 90. |
| Confidentiality | Terms and DPA | Customer content used only to provide the service, kept apart from other customers', and readable by the Provider's people only as the [access control policy](policies/access-control.md) allows. |

The system requirements that meet them are the [security objectives](policies/information-security.md#security-objectives) of the information security policy, the [configuration baseline](configuration-baseline.md) every managed server is held to, and the policy set's rules for access, change, incidents, vendors, continuity and data ([policies](policies/README.md)).

## DC3 Components of the system

What the system is made of, from the [architecture](architecture.md#components) and [data flows](data-flows.md) pages.

**Infrastructure.** The control-plane server (botd behind Caddy, its SQLite database encrypted with SQLCipher, [ADR 0116](../adr/0116-database-encrypted-at-rest.md)); the per-user machines, Linode VMs or Incus system containers on the Provider's hosts; S3-compatible object storage for off-host backups ([ADR 0071](../adr/0071-off-host-machine-backups.md)) and the write-once audit archive ([ADR 0154](../adr/0154-write-once-s3-audit-archive.md)); and the monitoring that probes and alerts on them ([SLO](../slo.md#alerts)).

**Software.** **botd**, **Caddy**, the **Client app**, the **Admin console**, **botctl**, **superbot-run**, the **Machine agent** and **Screens** are SuperBot's code, built from this repository; the published botd and Caddy images are scanned, signed and attested with their provenance ([ADR 0101](../adr/0101-image-scanning-and-signing.md)). The **Harnesses** are third-party CLIs, installed on machines at exact versions and checked against pinned hashes: Node.js and the npm packages by SHA-256 and SHA-512, Hermes Agent's installer by SHA-256 ([ADR 0039](../adr/0039-machine-harnesses-and-agent-upgrades.md)). The **Per-user machines** start from their provider's base images (Linode's, or the Incus image server's). **superbot-license** signs self-host licence keys offline and is not part of the managed system.

**People.** The roles the [policy set](policies/README.md) names: Management, Security owner, Engineering lead, Operator, People lead and Privacy lead, with the incident commander drawn from them ([incident response](policies/incident-response.md#roles)). Who holds each is in the Provider's private policy register, not here.

**Procedures.** The [policy set](policies/README.md), and the runbooks and guides they point to: [backup and restore](../ops/backup-restore.md), [machine recovery](../ops/machine-recovery.md), [master key rotation](../ops/master-key-rotation.md), [audit export](../ops/audit-export.md) and the [support runbooks](../support/README.md).

**Data.** Classed Restricted, Confidential, Internal or Public under the [data classification policy](policies/data-classification-and-retention.md#classes), whose [inventory](policies/data-classification-and-retention.md#inventory) says where each kind is stored, how it is encrypted and how long it is kept.

**Boundaries.** Inside the system: the control-plane servers, the per-user machines and their hosts, the backups and audit archive, and the GitHub repository, CI and release pipeline that change them ([change management](policies/change-management.md)). Outside it: customers' devices and networks, customers' identity providers, harness subscriptions a person signs in with under their own account, and the services a customer connects its Bots to. The [trust boundaries](architecture.md#trust-boundaries) say where data crosses each.

## DC4 Disclosures about identified system incidents

[To fill in at the end of the period.] Each security incident in the period that was a significant failure to meet the commitments in DC2, from the register's `incidents.json` ([ADR 0223](../adr/0223-incidents-in-the-register.md)), with what happened and what was done. None has been recorded: there is no production period yet.

## DC5 The applicable trust services criteria and related controls

The controls that meet each criterion are in the [control mapping](soc2-control-mapping.md), with the remaining work in the [readiness checklist](soc2-readiness-checklist.md) and the evidence for each in the [Type II evidence plan](soc2-evidence-plan.md). The controls customers and subservice organisations must run for them to work are in DC6 and DC7.

## DC6 Complementary user entity controls

The controls SuperBot's design assumes each customer runs. Without them, some criteria can't be met for that customer. The **Customer** rows of the [control mapping](soc2-control-mapping.md) are where each comes from; the Provider gives this list to customers with their contract.

| ID | The customer | Criteria | Why the service relies on it |
|----|--------------|----------|------------------------------|
| CUEC-1 | Requires multi-factor sign-in at its identity provider for everyone who signs in to SuperBot through it. | CC6.1 | SuperBot's own second factor covers codes and the password ([ADR 0094](../adr/0094-totp-second-factor.md)); an SSO sign-in is as strong as the IdP makes it ([IdP guides](../sso/)). |
| CUEC-2 | Deprovisions a leaver promptly: through SCIM, or, without SCIM, both at its identity provider and in SuperBot (`botctl user disable`). Keeps group memberships current. | CC6.2, CC6.3 | A SCIM deactivation or a disable in SuperBot ends existing sessions too ([ADR 0023](../adr/0023-scim.md), [IdP guides](../sso/)); a change at the IdP alone only stops new sign-ins, and a session lasts up to 7 days idle and 30 days at most ([sessions](access-control.md#authentication)). SuperBot can't know someone left until one of these happens. |
| CUEC-3 | Keeps the API tokens, service account tokens, SCIM tokens and recovery codes it is given secret, and revokes any it thinks exposed. | CC6.1 | Anyone holding one acts as its owner until it expires or is revoked ([ADR 0143](../adr/0143-service-accounts.md), [ADR 0196](../adr/0196-scim-token-expiry-and-rotation.md)). |
| CUEC-4 | Has the people who approve Bots' risky actions read each request before approving it. | CC6.8 | An approval lets the action run ([ADR 0007](../adr/0007-approvals.md)); the check is only as good as the person's reading of it. |
| CUEC-5 | Reports suspected incidents, misuse and compromised accounts to the Provider promptly. | CC7.3 | Events the customer sees first, such as a lost device or a phished account, reach the [incident response plan](policies/incident-response.md#communication) only when reported. |
| CUEC-6 | Decides what its people may put in chats, files and Bots' memory, and which plans, regions and model providers are acceptable for that data. | C1.1 | The harness sends prompts and file contents to the model provider the run is routed to ([data flows](data-flows.md)); classifying the customer's own content is the customer's. |

These are customer responsibilities but not complementary controls, because no criterion depends on them: deciding who may use SuperBot, which roles and grants each person has, and which Bots are shared. The admin tools for them and the quarterly access-review report are SuperBot's ([ADR 0099](../adr/0099-access-review-report.md)).

## DC7 Subservice organisations and complementary subservice organisation controls

The Provider uses the **carve-out method**: the subservice organisations' controls are not in this description, and the criteria below are met only if they run the controls listed. Each is a Critical or High vendor under the [vendor management policy](policies/vendor-management.md), whose yearly review of its assurance report checks that the report covers these controls ([ADR 0279](../adr/0279-vendor-assurance-reports-in-the-register.md)).

| ID | Subservice organisation | What it does for the system | Controls the Provider expects of it | Criteria |
|----|-------------------------|-----------------------------|-------------------------------------|----------|
| CSOC-1 | Linode (Akamai) | Hosts the control-plane server and Linode machines | Physical access to data centres limited to authorised people and reviewed; power, cooling, fire and flood protection; disks wiped or destroyed before reuse or disposal; one customer's instances isolated from another's, with access to its infrastructure controlled. | CC6.4, A1.2, CC6.5, CC6.1 |
| CSOC-2 | Incus hosts | The hosting company whose servers run Incus machines, where the Provider doesn't own them | As CSOC-1, for the servers and data centres it provides. | CC6.4, A1.2, CC6.5, CC6.1 |
| CSOC-3 | S3-compatible object storage | Holds off-host backups and the audit archive | As CSOC-1 for its storage; and, where the audit archive uses it, Object Lock retention that even the account holder can't shorten. | CC6.4, A1.2, CC6.5, CC6.1, CC7.2 |
| CSOC-4 | Model providers | Run the models Bots call, through the tiers file | Prompts and outputs used and kept only as its terms with the Provider say; traffic encrypted in transit; access to them limited inside the provider. | C1.1, C1.2, CC6.7 |
| CSOC-5 | GitHub | Holds the code and runs CI and releases | Enforces the branch protection and required reviews set on `main`, and keeps accurate records of reviews, checks and workflow runs, which the change evidence is exported from ([ADR 0148](../adr/0148-change-management-evidence-from-github.md)). | CC8.1 |

The Provider's own controls over each are in the [vendor management policy](policies/vendor-management.md): assessed before use, a contract and DPA, and a yearly review.

## DC8 Criteria not relevant to the system

None of the Security, Availability or Confidentiality criteria is left out. Physical access (CC6.4) and environmental protection (A1.2) are met through the subservice organisations in DC7, as the Provider runs no data centre of its own. Processing Integrity and Privacy are not in scope: customers haven't asked for them, and privacy commitments are made in the [privacy policy](privacy-policy-template.md) and [DPA](dpa-template.md) instead.

## DC9 Significant changes during the period

[To fill in at the end of the period.] Changes to the system, its commitments, its controls or its subservice organisations that a reader would want to know about, from the ADRs merged in the period, the [changelog](../../CHANGELOG.md), the monthly change-management bundles ([evidence plan](soc2-evidence-plan.md)) and the register's production changes ([ADR 0270](../adr/0270-production-changes-in-the-register.md)). A change to this description is approved again before the period's report.
