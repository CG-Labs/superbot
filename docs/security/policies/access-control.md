# Access control policy

Who may get access to the managed SuperBot service and the systems that run it, how it is granted, checked and removed, and how secrets and keys are kept. Part of the [policy set](README.md). How SuperBot itself enforces access is in [access control and isolation](../access-control.md). **Draft, not adopted. SuperBot is not SOC 2 certified.**

| Field | Value |
|-------|-------|
| Owner | Security owner |
| Approver | Management |
| Review | Yearly |
| Status | Draft, not yet approved |
| Controls | CC5.3-1, CC6.1-1, CC6.1-2, CC6.1-3, CC6.2-1, CC6.2-2, CC6.3-1, CC6.3-2, CC6.5-1 |

## Scope

Two kinds of access:

- **Production access**: personnel's access to what runs the service: SuperBot admin accounts on managed servers, shells on servers and Incus hosts, the hosting provider's console and API (Linode, or the Incus hosts' provider), object storage for backups, DNS, the GitHub organisation and repository, Stripe, the SMTP and push accounts, the error tracker, and the keys in the [secrets section](#secrets-and-keys).
- **Customer access**: customers' users in SuperBot, which customers control. The provider's duty is to give them the tools and to require what the [customer duties](#customer-duties) say.

## Principles

- Least privilege: only the access a role needs, for as long as it needs it.
- Named accounts only. No shared logins except the break-glass account below.
- Access to customer content (chats, files, screens) only to answer that customer's request or an incident, recorded in the support ticket or incident record.

## Granting access

- Production access is requested in writing, saying the system, the level and why, and approved by the security owner; admin access to a managed server or the hosting provider also needs management's approval. Nobody approves their own request.
- Access is set up through the system's own accounts: a SuperBot account with the lowest role that works (`readonly`, `member`, `admin`; [ADR 0012](../../adr/0012-users-sessions-rbac.md)), a GitHub team, a hosting provider user with a limited role.
- The request, approval and grant are kept as evidence, and each grant of production access, its approvers and the day it ends are recorded in the [policy register](../policy-register.md#production-access). In SuperBot itself, `user.created` and `user.role_changed` audit events record the grant and who made it.

## Authentication

- **MFA everywhere in production.** Every production account uses MFA, with phishing-resistant methods (passkeys or security keys) where the system offers them.
- **SuperBot admins.** Each managed server sets `AUTH_MFA=admins` or `all`, so every admin session from a sign-in code or the password passed a TOTP second factor ([ADR 0094](../../adr/0094-totp-second-factor.md)). SSO sign-ins rely on the IdP's MFA, which must be required there.
- **Just-in-time SSO accounts** only with an allow-list of domains, organisations or tenants; botd refuses to start otherwise ([ADR 0103](../../adr/0103-sso-jit-needs-an-allow-list.md)).
- **Break-glass.** The server owner's password is the break-glass account. It has a second factor, is kept in the provider's password manager with access limited to the security owner and the operator, and every use is recorded in an incident or change record and reviewed at the next access review.

## Reviewing access

Every quarter, the security owner (or a delegate who isn't reviewing their own access) reviews:

- **SuperBot users on each managed server**, with the access-review report: roles, status, second factor, last sign-in, Bot access, sessions, API tokens and machines ([ADR 0099](../../adr/0099-access-review-report.md)). The reviewer fixes what's wrong, exports the dated CSV, and signs off in the app, which records `access_review.completed` with the report's digest.
- **Production access outside SuperBot**: the GitHub organisation, the hosting provider, object storage, DNS, Stripe and the other accounts in [scope](#scope), from each system's own user list. The reviewer records who has what, what changed, and signs off in the [register](../policy-register.md#production-access), with the user list's SHA-256 and whether every account needs a second factor. Reviews of managed servers are recorded there too, with the report's digest they signed off.

Findings (an account that should be gone, a role too high) are fixed within 5 business days, or 1 business day for admin access.

## Removing access

- When someone leaves, all their production access is removed by the end of their last day, or at once when they leave for cause. In SuperBot, deactivating them through SCIM or `botctl user disable` ends their sessions, stops their runs and, with `MACHINE_ON_DISABLE=suspend` (the default, and required by the [baseline](information-security.md#configuration-baseline)), suspends their machine ([ADR 0124](../../adr/0124-deprovisioning-stops-bots-and-machines.md)); with `keep`, suspend it with `botctl machine suspend`; `botctl session revoke-all` ends sessions alone.
- When someone changes role, access the new role doesn't need is removed within 5 business days.
- Shared secrets they could see (the break-glass password, keys) are rotated when someone who could see them leaves.
- A person's data is erased on request as the [data classification and retention policy](data-classification-and-retention.md#disposal) says.

## Secrets and keys

| Secret | Kept | Rotated |
|--------|------|---------|
| botd's master key | Outside the data folder, readable only by botd's user; a copy in the provider's password manager | Yearly, and at once if it may have leaked, by the [master key rotation](../../ops/master-key-rotation.md) procedure ([ADR 0096](../../adr/0096-master-key-rotation.md)) |
| Backup age identities | Off the host, in the password manager, never beside the backups ([ADR 0114](../../adr/0114-backups-encrypted-by-default.md)) | When someone who held one leaves, with backups re-encrypted to the new recipient |
| Provider API tokens (hosting, storage, Stripe, SMTP, model providers) | In the server's environment or SuperBot's sealed secrets; never in the repository | Yearly, and when someone who could read them leaves |
| SCIM tokens | In the IdP only; botd keeps a hash | When the IdP connection changes; revoke with `botctl scim token revoke` |

Secrets never go into the repository, issues, chats or tickets ([`AGENTS.md`](../../../AGENTS.md)).

## Customer duties

What customers must do for SuperBot's controls to work (complementary user entity controls), stated in the terms or DPA:

- require MFA at their IdP for everyone who signs in through SSO, following the [IdP guides](../../sso/);
- decide who gets access, assign the lowest role that works, and review their users with the access-review report;
- remove leavers, through SCIM or by disabling them.
