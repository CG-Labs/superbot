# Support tiers

What support each plan gets. The plans are the ones in the tiers file and on `/pricing` ([ADR 0121](../adr/0121-published-plans.md), [`deploy/tiers.example.json`](../../deploy/tiers.example.json)): the licensed self-host plan, the managed Starter, Pro and Max plans, and Enterprise, which is by agreement. Availability and recovery numbers are the [uptime SLO](../slo.md)'s and the [machine recovery objectives](../security/machine-recovery-objectives.md)'s; this page adds who answers, where, and when. Response times per severity are in [severity and response targets](severity.md).

## Per plan

| Plan | Channels | Hours | Severity 1 outside hours | Availability (SLO) | Machine RPO / RTO | Named contact |
|---|---|---|---|---|---|---|
| Self-host (licensed) | Email | Business hours | No | Your own ([SLO](../slo.md#what-doesnt-count-against-it)) | Your own | No |
| Starter | Email, portal | Business hours | No | 99.5% | 26 h / 60 min | No |
| Pro | Email, portal | Business hours | Yes, 24×7 | 99.9% | 14 h / 60 min | No |
| Max | Email, portal | Business hours | Yes, 24×7 | 99.9% | 8 h / 60 min | No |
| Enterprise | By agreement: email, portal, shared channel, on-call line | By agreement, up to 24×7 | Yes, 24×7 | 99.95%, by agreement | By agreement | Technical account manager |

- **Business hours** are `<support-hours>` (for example 09:00 to 17:30, Monday to Friday) in `<support-timezone>`, except the Provider's public holidays. A Provider serving several regions says which hours apply to which.
- **Channels.** Email is `<support-email>`; the portal is `<support-portal-url>`. Everyone can see `<status-page-url>`, and incidents there are posted within 15 minutes of being confirmed and updated at least hourly ([SLO](../slo.md#status-page-and-incidents)), whatever the plan.
- **Who can open tickets.** On managed plans, any admin of the customer's account; members ask their admin. Self-host: the license holder's named contacts (up to `<self-host-contacts>`).
- **Language.** `<support-languages>`.

## What each plan covers

All plans: SuperBot itself (botd, botctl, the web app and console, the installer and images), sign-in and SSO setup as documented, approvals, routines, and the harness adapters SuperBot ships.

- **Self-host (licensed).** Help with SuperBot on your own servers: install, upgrade, configuration, backups and restores as documented in the [operator guide](../../deploy/README.md), and bugs. Your servers, network, identity provider and model providers are yours; support explains what SuperBot needs from them. Fixes ship in releases; there's no hotfix to a single server.
- **Starter, Pro and Max (managed).** The Provider runs the server, the machines and their backups. Support covers anything in the service, including restoring a machine within its plan's RTO. Pro and Max add Severity 1 response at any hour. Max's faster targets for Severity 2 and 3 ([severity](severity.md)) are its support difference; Pro and Max share the same server and SLO.
- **Enterprise.** Everything above on a deployment of its own (dedicated, VPC or on-premises), plus:
  - a [technical account manager](tam.md) (`<tam-name>`, `<tam-email>`) who knows the deployment, joins onboarding, runs the [success cadence](onboarding.md#success-cadence) and is the customer's [escalation](escalation.md) point;
  - response targets, hours and channels agreed in the order form, starting from the defaults in [severity](severity.md#enterprise-defaults);
  - help with SCIM, SAML, data regions and security reviews (the [security pack](../security/README.md));
  - change windows agreed ahead for upgrades on their deployment.

### Harnesses

The SLA covers **Hermes Agent**, the managed default, at its pinned release ([ADR 0027](../adr/0027-expo-primary-hermes-default.md), [ADR 0075](../adr/0075-hermes-upgrades.md)). Claude Code, Codex, Pi and other harnesses are **best effort** on every plan: support helps, and a failure in SuperBot's adapter is a bug like any other, but an outage of the harness or its vendor doesn't count against response or availability targets. Model providers' outages are outside the SLO on every plan ([SLO](../slo.md#what-doesnt-count-against-it)); the [provider outage runbook](runbook-harness-outage.md) says what support does about them.

## Not covered

On any plan: the customer's own devices, network and identity provider; prompts, Bot instructions and what a Bot produces; custom code or harnesses SuperBot doesn't ship; and self-hosted servers on a release the Provider no longer supports (`<supported-releases>`), which are asked to upgrade first. Support may still help, best effort.

## Enterprise

Enterprise isn't a tier with limits; it's listed on `/pricing` as a "Contact sales" link (`PLANS_CONTACT_URL`, [ADR 0121](../adr/0121-published-plans.md#enterprise-is-a-contact-link)). Its support is written into the agreement: plan this table's row with the customer, record it in the order form, and give the on-call rota its contacts. Its 99.95% needs a deployment with a standby server, which is not offered on a shared server ([SLO](../slo.md#objectives)).
