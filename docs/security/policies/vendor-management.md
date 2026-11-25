# Vendor management policy

How a managed SuperBot provider chooses, assesses, reviews and leaves the vendors the service depends on, and keeps customers told about subprocessors. Part of the [policy set](README.md). **Draft, not adopted. SuperBot is not SOC 2 certified.**

| Field | Value |
|-------|-------|
| Owner | Security owner |
| Approver | Management |
| Review | Yearly |
| Status | Draft, not yet approved |
| Controls | CC6.4-1, CC9.2-1, CC9.2-2 |

## The vendor inventory

The security owner keeps an inventory of every vendor the service uses, starting from the [subprocessor list](../subprocessors.md), which names every outside service SuperBot's code can call, what each receives and the setting that turns it on. For each vendor in use: what it does for the service, what data it gets, where that data is, the contract and DPA, its tier, its last assessment, and its owner inside the provider.

## Tiers

| Tier | Which vendors | Examples from the subprocessor list |
|------|---------------|-------------------------------------|
| Critical | Holds or can read customer content, or runs the service | The hosting provider for machines and the server (Linode/Akamai, or the Incus hosts' provider); object storage for backups; model providers in the tiers file |
| High | Receives personal data, could interrupt the service, or runs a control the service relies on | Stripe; the SMTP provider; Expo, APNs and FCM for push; the identity providers the provider itself signs in with; an error tracker; GitHub, which holds the code and runs the CI and releases change management relies on |
| Low | Receives no customer data | Certificate authorities through Caddy; image and package registries; app stores |

## Before using a vendor

For Critical and High vendors, before any customer data reaches them:

1. **Assessment.** The vendor's latest SOC 2 Type II or ISO 27001 report (with its scope and exceptions read), or answers to a security questionnaire where it has none; where it keeps data and which subprocessors it uses; its breach notice terms; how data is deleted when the service ends.
2. **Contract.** A DPA with GDPR Article 28 terms where it processes personal data, and data transfer terms where it is outside the customer's region.
3. **Configuration.** The [access control policy](access-control.md) applies to the account: MFA, named users, least privilege; and the setting that sends it data follows the [data classification policy](data-classification-and-retention.md#handling).
4. **Decision.** The security owner approves, or management for a vendor with findings the provider accepts; the risk goes in the register.

Low vendors are added to the inventory with no assessment.

## Yearly review

Every Critical and High vendor is reviewed yearly: the newest assurance report, read for exceptions and for the **complementary user entity controls** it expects of its customers, with a note of how the provider meets each; any incidents; whether the data it gets has changed. The hosting providers' reports also cover physical and environmental security, which the service inherits from them (checklist CC6.4-1), so a hosting provider's must be a SOC 2 Type II report or an ISO 27001 certificate, not a questionnaire. For a subservice organisation carved out in the [system description](../soc2-system-description.md#dc7-subservice-organisations-and-complementary-subservice-organisation-controls), the review also checks that the report covers the controls the description expects of it, and records any it doesn't as a risk. Findings go in the register: a SOC 2 report with deviations in its tests, or an opinion other than unqualified, is treated as a risk.

A report must still speak for the vendor: if a SOC 2 report's period ended more than 92 days ago, the security owner asks the vendor for a bridge letter covering the time since, or for its next report; an ISO 27001 certificate must not have expired. Each report review is recorded in the [policy register](../policy-register.md#vendors-assurance-reports), with the report, the note of complementary controls and any bridge letter kept in the evidence store.

## Telling customers

- The managed service publishes its subprocessors (the Critical and High vendors that process customer personal data) in the form of the [DPA's Annex III](../dpa-template.md#annex-iii-subprocessors).
- A new subprocessor, or a change in what one gets, is announced to customers `[N] days` ahead (30 suggested), with their right to object, as the DPA says. The notices sent are kept as evidence.

## Leaving a vendor

When a vendor is no longer used: its access and API tokens are revoked, the provider asks for deletion of the data it held and keeps the confirmation, the setting that used it is removed from every server, and the inventory and subprocessor list are updated.
