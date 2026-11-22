# Runbook: native SAML sign-in

People can't sign in with a SAML identity provider that botd talks to directly (`SSO_<ID>_TYPE=saml`, [guide](../sso/saml-native.md), [ADR 0127](../adr/0127-native-saml-service-provider.md)). For SAML through the Keycloak bridge, OIDC and the rest, use the [sign-in runbook](runbook-sign-in.md). Severity: [1](severity.md#severities) if SAML is the only way in and nobody can sign in, 2 if it fails for many while another way works, 3 for one person.

## First five minutes

1. **How many, since when.** Everyone on this IdP, or one person? The time (UTC) and the message on the sign-in page.
2. **What botd thinks of the IdP:**

   ```sh
   botctl sso saml <provider>
   ```

   It says whether the provider is ready (or what's wrong), where its metadata comes from (URL, file or import), and each signing certificate with its SHA-256 and expiry. "Not loaded yet" means botd has no metadata, so the provider isn't offered. A metadata URL botd couldn't fetch or read is in its log as `SSO <provider>: IdP metadata from <url>: ...` (and in a [support bundle](support-bundle.md)'s `logs.jsonl`).
3. **What the audit log says:**

   ```sh
   botctl audit 50 --action auth.login_failed --idp saml
   ```

   Each refusal has a `reason`. The [health score](health-score.md#identity)'s `identity` signal has the week's reasons counted, without names.
4. **What changed:** an IdP certificate rollover, a new app or attribute mapping at the IdP, a change of `SSO_PUBLIC_URL`, a proxy or domain, a clock.

## Reasons and fixes

The [guide's table](../sso/saml-native.md#troubleshooting) has every reason. The ones support sees most:

| Reason | Usually | Fix |
|---|---|---|
| `bad_signature` | The IdP rolled its signing certificate and botd has the old one (metadata from a file or an import, or the URL unreachable from the server) | With a URL: check the server can reach it, then restart botd, so the next sign-in fetches it again. With a file or import: get the new metadata from the IdP admin and `botctl sso saml <provider> import < idp-metadata.xml` |
| `wrong_audience`, `wrong_recipient`, `wrong_destination` | The IdP's entity ID or ACS URL isn't the one botctl shows, often after `SSO_PUBLIC_URL` or the domain changed | Set the IdP's values to what `botctl sso saml <provider>` shows |
| `expired`, `not_yet_valid` | Clocks differ by more than two minutes | Fix NTP on the server (and the IdP's, on premises) |
| `in_response_to_mismatch`, `unknown_state` | Sign-in started from the IdP's app tile, or took over 10 minutes | Start from SuperBot's sign-in page; IdP-initiated sign-in isn't supported |
| `encrypted_assertion`, `unsigned`, `weak_algorithm` | The IdP app's settings changed | Unencrypted assertions, signed with RSA-SHA256 ([guide](../sso/saml-native.md#2-register-superbot-at-your-idp)) |
| `not_linked`, `transient_subject` | A new person, or the NameID format changed | Link them ([guide](../sso/saml-native.md#3-let-people-in)); keep the NameID persistent. A changed NameID needs every person re-linked, so change it back if you can |
| `idp_error` | The IdP refused: the person isn't assigned to the app, or conditional access | `idpStatus` says which; the customer's IdP admin fixes it |

## Nobody can sign in

Break-glass and one-time codes work as for any provider ([sign-in runbook](runbook-sign-in.md#nobody-can-sign-in)). Fix the certificate or the settings, have one admin sign in, then tell everyone.

## Escalate when

- `bad_signature` persists after the metadata is current and `botctl sso saml <provider>` shows the certificate the IdP signs with.
- A sign-in succeeds that should be refused (another person's account, a person not assigned at the IdP): that's a security incident, [Severity 1](escalation.md#security-incidents).
- Refusals with `wrapped`, `bad_response` or a reason not in the guide, from an IdP that worked before.

## Afterwards

Note the cause in the ticket. If it was a certificate rollover with metadata from a file or import, put the new certificate's expiry in the customer's record, and suggest a metadata URL so the next rollover needs nothing ([health check](health-check.md#3-identity)).
