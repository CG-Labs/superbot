# Runbook: sign-in and SSO failures

People can't sign in: with SSO, a password, or a one-time code. Severity: [1](severity.md#severities) if nobody can sign in, 2 if one identity provider fails for many people, 3 for one person.

## First five minutes

1. **How many.** Everyone, everyone on one identity provider, or one person? Ask for the time it happened (UTC) and the exact message.
2. **Is botd up?** `/status.json` answers 200, and `/healthz` answers. If not, this is an outage: [machine down or restore](runbook-machine-down.md#the-server-itself), and the status page.
3. **What the audit log says.** On the server, as an admin who can still get in (break-glass below if nobody can):

   ```sh
   botctl audit 50 --action auth.login_failed
   botctl audit 50 --action auth.login_failed --idp entra --from 2026-01-31
   ```

   Every failed sign-in has a `reason`. A support bundle has the last week's counted by reason (`audit-summary.json`, `recentProblems`), without names.
4. **Did anything change?** An upgrade, an SSO setting, a client secret expiring, a certificate or domain change, the IdP's app or conditional access policies.

## Reasons and fixes

| Reason | Usually | Fix |
|---|---|---|
| `not_linked` | The person's identity isn't linked to a user, and just-in-time sign-up is off or doesn't allow them | Link them (`botctl user link <user> <provider> <subject>`; the event has the subject), or add their domain, tenant or org to the allow-list ([ADR 0103](../adr/0103-sso-jit-needs-an-allow-list.md)) |
| `wrong_tenant`, `wrong_domain`, `wrong_org` | They signed in with an account outside what's allowed | Check the provider's allowed tenants, domains or orgs |
| `wrong_issuer`, `idp_unreachable`, `idp_bad_response` | botd can't reach the IdP, or it answers as a different issuer | Check the provider's issuer URL, DNS and egress from the server, and the IdP's status |
| `code_exchange_failed` | The client secret expired or changed, or the redirect URI doesn't match | New client secret at the IdP, then `botctl secret set <SSO_..._CLIENT_SECRET> < file` (or the console's Server secrets) and restart; check `SSO_PUBLIC_URL` against the IdP's redirect URI |
| `wrong_audience` | The client id isn't this app's | Fix the provider's `_CLIENT_ID` |
| `email_taken` | Just-in-time sign-up met an existing user with that email | Link the identity to that user instead |
| `binder_mismatch`, `unknown_state` | Finished in another browser, after 10 minutes, or the page reloaded | Try again in one browser tab; if it persists, check the proxy keeps cookies and `SSO_PUBLIC_URL` is the address people use |
| `idp_error` | The identity provider refused (consent declined, conditional access, a disabled account) | `idpError` says why; the customer's IdP admin fixes it there |
| `user_disabled` | The user is disabled, by an admin or SCIM | `botctl user enable <user>` if that's wrong; with SCIM, fix the assignment in the IdP or it's disabled again |

The guide for each provider has its own table and the provider's error codes: [Entra](../sso/entra.md#troubleshooting), [Google](../sso/google.md#troubleshooting), [GitHub](../sso/github.md#troubleshooting), [Apple](../sso/apple.md#troubleshooting), [OIDC](../sso/oidc.md#troubleshooting), [SAML](../sso/saml.md#troubleshooting), [SCIM](../sso/scim.md#troubleshooting).

## Nobody can sign in

1. If the identity provider is down (check its status page), say so on the status page and the ticket; it's outside the SLO ([what doesn't count](../slo.md#what-doesnt-count-against-it)), but people still need to work.
2. **Break-glass.** If `AUTH_BREAK_GLASS=0`, set it to `1` in `.env` and restart; the password (`AUTH_PASSWORD`) then works for the console and `botctl`. Turn it off again when SSO is back ([after an upgrade](../../deploy/README.md#users-and-sign-in-after-an-upgrade)).
3. **One-time codes.** For people who must work meanwhile: `botctl user code <user> --ttl 60` prints a sign-in code to give them over a channel you trust. Each use is audited.
4. Expired client secret or certificate: fix it as in the table, restart, and have one admin sign in before telling everyone.

## One person can't sign in

- `botctl users` and `botctl user identities <user>`: are they enabled, and is their identity the one they're using? A person with two accounts at the IdP often signs in with the other.
- Two-factor: a lost authenticator needs a recovery code, or an admin to reset their factors (`DELETE /api/users/<user>/mfa`, or the console's user page).
- Password sign-ins are rate limited after repeated failures: wait, and check `auth.suspicious_sign_in` and the sign-in alerts ([deploy guide](../../deploy/README.md#metrics-and-logs)) in case it isn't them.

## Suspicious sign-ins

botd watches failed sign-ins (passwords, sign-in codes, second factors) for guessing, audits each pattern it sees as `auth.suspicious_sign_in` with the `pattern`, and alerts ([ADR 0104](../adr/0104-suspicious-sign-in-alerts.md)). These aren't people locked out: they're someone else trying to get in. Severity 1 when a guess may have worked, 3 otherwise.

| Alert | Pattern | Do |
|---|---|---|
| `SuperBotSignInAfterFailures` (a page) | `success_after_failures`: a sign-in worked from an IP, or to an account, that had just reached its failure limit | Ask the person, over a channel you trust, whether it was them. If not, or they can't be reached: disable them (`botctl user disable <user>`, which ends their sessions and stops their runs), then [Severity 1](escalation.md#security-incidents) |
| `SuperBotAccountSignInFailures` | `account_failures`: one account reached `SIGNIN_ALERT_ACCOUNT_FAILURES` within `SIGNIN_ALERT_WINDOW`, from any IP | For a second factor, their password or code is known to someone else: have them change it. For the break-glass password, rotate `AUTH_PASSWORD` |
| `SuperBotSignInBurstsRepeated` | `ip_failures`: three or more bursts in an hour, each from one IP past `SIGNIN_ALERT_IP_FAILURES` | The events name the IPs: block them at the proxy or firewall if they persist |
| `SuperBotSignInFailuresHigh` | none: over 100 failed sign-ins in 15 minutes across the server | Guessing spread over many IPs. `superbot_signin_failures_total` by method, and `auth.login_failed` events, say where. A broken identity provider fails many people too: check the reasons above first |
| `SuperBotSignInFromNewNetwork` | `new_ip`: someone covered by `SIGNIN_ALERT_NEW_IP` (admins by default) signed in from a network none of their kept sessions came from | Confirm with them. Travel and new offices are the usual answer |

```sh
botctl audit 50 --action auth.suspicious_sign_in
```

## Escalate when

- Many people fail with a reason not in these tables, or with no `auth.login_failed` event at all (the request never reached botd: the proxy, DNS or certificate).
- A person signs in as someone else, or sign-ins succeed that should be refused: that's a security incident, [Severity 1](escalation.md#security-incidents).
- Break-glass and codes don't work either.

## Afterwards

Note the cause in the ticket. If a client secret expired, put its expiry date in the customer's onboarding record and remind them a month before the next one ([onboarding](onboarding.md#2-identity-sso-and-scim)).
