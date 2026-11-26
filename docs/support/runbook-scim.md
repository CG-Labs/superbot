# Runbook: SCIM provisioning

The customer's identity provider (IdP) stops adding, changing or removing people and groups in SuperBot: joiners can't get in, leavers keep their access, or teams and roles drift from the IdP's groups. Severity: [2](severity.md#severities) when a tenant's provisioning has stopped (its token revoked or expired, or every request failing), since leavers keep access until it's fixed; 3 when some people or groups fail and the rest go through; 1 if someone the IdP removed used SuperBot after they should have lost access, which is a [security incident](escalation.md#security-incidents).

The setup guide, with every error the IdP may show, is [SCIM](../sso/scim.md#troubleshooting); this page is the order to work in.

## First five minutes

1. **Which tenant, and what.** Ask which IdP connection (the tenant's name in `botctl scim tokens`), whether nothing goes through or only some people or groups, and the IdP's provisioning log line for one that failed: its time (UTC), the status and the message botd sent back.
2. **Is botd up?** `/status.json` answers 200. If not, this is an outage: [the server itself](runbook-machine-down.md#the-server-itself).
3. **The tokens.** On the server, as an admin:

   ```sh
   botctl scim tokens                                      # each tenant's tokens: expiry, scopes, last used; expiring tenants
   botctl audit 50 --action scim.request_failed            # refused or failed requests, with a reason and the tenant
   botctl audit 50 --action scim.auth_failed               # tokens botd didn't accept: revoked, expired, unknown, missing
   ```

   A support bundle has the week's counts by reason in `audit-summary.json` (`recentProblems`), and the [health score](health-score.md#identity)'s `identity` signal lists them as `scimReasons`, without names. [Bundle triage](triage.md) brings both here.
4. **Did anything change?** A token rotated, revoked or past its `--days`, the IdP's app moved to a new tenant or federation IdP, attribute mappings edited, group provisioning turned on, a license renewal with fewer seats, or `SCIM`, `SCIM_GROUPS` or `SCIM_GROUP_ROLES` changed in `.env`.

## Reasons and fixes

Every request a valid token sends that botd refuses or fails is audited as `scim.request_failed` with one of these reasons (a 404 isn't: IdPs get those in their normal course). A token botd doesn't accept is `scim.auth_failed`, and the health score counts the revoked and expired ones as `revoked_token` and `expired_token`.

| Reason | Usually | Fix |
|---|---|---|
| `revoked_token` | An admin revoked the token the IdP still sends. Provisioning has stopped for the tenant | Make a new token (`botctl scim token create <tenant> --sso <provider>`) and paste it into the IdP's provisioning settings; if nobody meant to revoke it, find who did (`botctl audit --action scim.token_revoked`) |
| `expired_token` | The token passed its expiry, and the IdP's provisioning stopped with it | Make or rotate a token ([token expiry and rotation](../sso/scim.md#token-expiry-and-rotation)) and paste it into the IdP. A rotation keeps the old token working for its overlap, so the IdP can be updated without a gap |
| `insufficient_scope` | The token's [scopes](../sso/scim.md#token-scopes) don't allow the request, usually group pushes from a users-only token. The event names the scope it lacked | Turn group provisioning off in the IdP, or rotate the token with the scope it needs (`botctl scim token rotate <id> --scopes users:write,groups:write`) |
| `uniqueness` | The IdP sent someone or a group botd already has: another user with that email, a `userName` or `externalId` in use in the tenant, an SSO identity linked to another user, a person another tenant manages, or a group name taken | The message says which. For an email, link the person's SSO identity to the existing user (`botctl user link`) so the tenant takes them on; for another tenant, decide which IdP owns them and unassign them in the other ([SCIM](../sso/scim.md#troubleshooting)) |
| `invalid_value` | A value botd can't accept: no `externalId` where the tenant links SSO, an email outside the federation IdP's domains, an unknown member | Fix the IdP's attribute mapping (Entra: **objectId** to **externalId**), or send the address the institution gives the person ([federations](../sso/scim.md#federations)) |
| `invalid_syntax`, `invalid_filter`, `invalid_path`, `no_target` | The request isn't SCIM botd reads: not a JSON object, a filter or `PATCH` path it doesn't support | Usually a custom or scripted client rather than Entra, Okta or Google; send the request the [SCIM guide](../sso/scim.md) shows. From a supported IdP, escalate with the IdP's log line |
| `mutability` | The IdP tried to change an `externalId` after it was set | Delete the user or group in the IdP's scope and provision them again, or put the old `externalId` back in the mapping |
| `status_403` | No seat left on the license, so a new or re-enabled person was refused (also `license.seat_refused`) | Free a seat (disable people who left) or add seats: the [license runbook](runbook-license.md#seats) |
| `status_405`, `status_413` | Bulk sent with a method other than `POST`, or over 100 operations or 1 MiB | Split the bulk request; check the IdP reads `ServiceProviderConfig` ([bulk](../sso/scim.md#bulk)) |
| `status_409` | A bulk operation names a `bulkId` no `POST` in the request defines, or whose `POST` failed; or a role group's declaration changed during a push | Read each bulk operation's `response`; a role group push is tried again on the next pass |
| `status_429` | Over 600 requests a minute for the tenant | Entra and Okta wait and retry by themselves; it only needs a look if it lasts ([limits](../sso/scim.md#limits)) |
| `status_500` | A database error, or the tenant's SAML provider now lists several IdPs and the tenant names none, or no longer lists the one it names | Name the IdP: `botctl scim token create <tenant> --sso <provider> --idp <entity ID>`. A database error with nothing in the log about the IdP: escalate |
| `status_501` | Group provisioning is off on the server (`SCIM_GROUPS`) | Set `SCIM_GROUPS=on` and restart botd, or turn group provisioning off in the IdP |
| `status_503` | botd couldn't load the federation's metadata to check an email against the IdP's domains | The IdP retries. Check the metadata source answers (`botctl sso saml <provider>`); the [SAML runbook](runbook-saml.md) if it doesn't |

Requests with no token or one botd doesn't know (`missing`, `unknown`) are only counted, never put down to a tenant: anyone on the internet can send them. Many of them at once from the IdP's addresses mean the IdP holds an old or mistyped token: paste the current one in again.

## Provisioning stopped

The IdP shows every request failing, or the health score counts `revoked_token` or `expired_token`, or a tenant in `scimTenantsExpiring` (every working token ending within 14 days).

1. `botctl scim tokens` names the tenant and when its tokens end. If one still works, rotate it (`botctl scim token rotate <id>`) so the old one keeps working while the customer pastes the new one in. If none does, make one (`botctl scim token create <tenant> --sso <provider>`, with the same `--idp` and `--scopes` as before).
2. The customer pastes it into the IdP and runs a provisioning cycle (Entra: **Restart provisioning**; Okta: **Push now** for the groups).
3. Check the next requests land: `botctl audit 20 --action 'scim.*'`.
4. Ask the customer who joined or left while it was stopped. People removed in the IdP meanwhile are disabled by the next cycle; if any of them must lose access now, `botctl user disable <user>` does it at once.

## Google Workspace

Google Workspace doesn't send SCIM: botd reads the directory itself on a schedule ([SCIM guide](../sso/scim.md#google-workspace)). `botctl scim google` shows its settings and last passes, with why the latest failed; `botctl scim google sync` runs a pass now. A pass that would remove more people than its limit stops and says so: check the directory change was meant, then `botctl scim google sync --force`.

## Leavers still have access

Someone removed or unassigned in the IdP can still sign in or still has Bots running.

1. Disable them now: `botctl user disable <user>` ends their sessions and pauses their routines. Then find out why SCIM didn't.
2. Was a request sent? The IdP's provisioning log shows whether it sent the `PATCH` or `DELETE`. If it didn't, the person is still in the app's scope there (a group assignment, a nested group, which SCIM doesn't follow).
3. If it was and botd refused it, the reason is in `botctl audit --action scim.request_failed`: fix it from the table.
4. If they signed in or a Bot of theirs ran after the IdP removed them, treat it as a [security incident](escalation.md#security-incidents): tell `<security-email>` with the times.

## Escalate when

- Requests fail with a reason not in this table, or a `status_500` with nothing in the IdP's log to explain it.
- The IdP shows success but botd didn't change the person or group, or changed the wrong one.
- People lost their roles or teams without a matching change in the IdP's groups (`scim.role_*` and `scim.group_*` events say what botd did).
- A leaver used SuperBot after their removal: Severity 1, a [security incident](escalation.md#security-incidents).

## Afterwards

Note the cause in the ticket. If a token ended, put the new token's end date in the customer's onboarding record and remind them a month before it ([onboarding](onboarding.md#2-identity-sso-and-scim)); the [monthly health check](health-check.md) opens its SCIM item for a tenant whose every token ends within 14 days. If a leaver kept access, the customer's access review should say so ([access reviews](../adr/0099-access-review-report.md)).
