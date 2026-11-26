# Runbook: native SAML sign-in

People can't sign in with a SAML identity provider that botd talks to directly (`SSO_<ID>_TYPE=saml`, [guide](../sso/saml-native.md), [ADR 0127](../adr/0127-native-saml-service-provider.md), [ADR 0137](../adr/0137-saml-signed-requests-and-single-logout.md), [ADR 0175](../adr/0175-saml-idp-initiated-sign-in-restarted.md), [ADR 0181](../adr/0181-saml-sp-key-rollover.md), [ADR 0225](../adr/0225-saml-session-lifetime-and-reauthentication.md)). For SAML through the Keycloak bridge, OIDC and the rest, use the [sign-in runbook](runbook-sign-in.md). Severity: [1](severity.md#severities) if SAML is the only way in and nobody can sign in, 2 if it fails for many while another way works, 3 for one person.

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

   Each refusal has a `reason`. The [health score](health-score.md#identity)'s `identity` signal counts the last 30 days' reasons, without names.
4. **What changed:** an IdP certificate rollover, a rollover of SuperBot's own keys (`botctl audit --action sso.saml_sp_key_promoted`), a new app or attribute mapping at the IdP, a change of `SSO_PUBLIC_URL`, a proxy or domain, a clock.

## Reasons and fixes

The [guide's table](../sso/saml-native.md#troubleshooting) has every reason. The ones support sees most:

| Reason | Usually | Fix |
|---|---|---|
| `bad_signature` | The IdP rolled its signing certificate and botd has the old one (metadata from a file or an import, or the URL unreachable from the server) | With a URL: check the server can reach it, then restart botd, so the next sign-in fetches it again. With a file or import: get the new metadata from the IdP admin and `botctl sso saml <provider> import < idp-metadata.xml` |
| `wrong_audience`, `wrong_recipient`, `wrong_destination` | The IdP's entity ID or ACS URL isn't the one botctl shows, often after `SSO_PUBLIC_URL` or the domain changed | Set the IdP's values to what `botctl sso saml <provider>` shows |
| `expired`, `not_yet_valid` | Clocks differ by more than two minutes | Fix NTP on the server (and the IdP's, on premises) |
| `in_response_to_mismatch`, `unknown_state` | Sign-in started from the IdP's app tile, or took over 10 minutes | Point the tile at SuperBot's start URL, or set `SSO_<ID>_IDP_INITIATED=restart` ([guide](../sso/saml-native.md#idp-initiated-sign-in-app-tiles)); meanwhile, start from SuperBot's sign-in page |
| `idp_initiated_loop` | `IDP_INITIATED=restart`, but the IdP answers SuperBot's AuthnRequest unsolicited too | The IdP app must take SP-initiated sign-ins; point the tile at the start URL instead |
| `unknown_idp` with `idpInitiated: true` | A provider with several IdPs got a tile from an IdP that isn't in `IDP_ENTITY_IDS` (`entityId` names it) | Add the IdP to `IDP_ENTITY_IDS` if it should sign people in, else nothing: that IdP's people aren't let in ([ADR 0290](../adr/0290-saml-idp-initiated-sign-in-at-several-idps.md)) |
| `encrypted_assertion`, `unsigned`, `weak_algorithm` | The IdP app's settings changed | Unencrypted assertions, signed with RSA-SHA256 ([guide](../sso/saml-native.md#2-register-superbot-at-your-idp)) |
| `cbc_unsigned_response` | Entra ID or ADFS encrypts with AES-CBC (`AES_CBC=signed-response`), but signs only the assertion | Sign the response too: Entra ID **Sign SAML response and assertion**, ADFS `MessageAndAssertion` ([guide](../sso/saml-native.md#aes-cbc-entra-id-and-adfs)) |
| `not_linked`, `transient_subject` | A new person, or the NameID format changed | Link them ([guide](../sso/saml-native.md#3-let-people-in)); keep the NameID persistent, or, for a federation IdP that sends only transient NameIDs, set `SSO_<ID>_SUBJECT=subject-id` or `pairwise-id` ([guide](../sso/saml-native.md#subject-identifiers-subject-id-and-pairwise-id)). A changed NameID needs every person re-linked, so change it back if you can |
| `no_subject_id`, `bad_subject_id` | `SSO_<ID>_SUBJECT` is set, and the IdP released no such attribute, or not exactly one value like `8f2a91c4@uni.example` | The IdP admin releases the attribute to SuperBot (most federation IdPs read SuperBot's metadata, which asks for it). An IdP that can't: unset `SUBJECT` and use a persistent NameID ([guide](../sso/saml-native.md#subject-identifiers-subject-id-and-pairwise-id)) |
| `subject_id_scope` | The value's scope (after `@`) isn't a `shibmd:Scope` in the IdP's metadata, or the metadata lists none | `botctl sso saml <provider>` shows the scopes botd has. The IdP's federation registers its scopes; a scope it doesn't list is refused on purpose, since any IdP could claim it ([ADR 0319](../adr/0319-saml-subject-identifier-attributes.md)) |
| `idp_error` | The IdP refused: the person isn't assigned to the app, or conditional access | `idpStatus` says which; the customer's IdP admin fixes it. `Responder/NoAuthnContext`: it can't do the MFA that `REQUEST_AUTHN_CONTEXT` asks for |
| `authn_context` (people told MFA is required) | `SSO_<ID>_AUTHN_CONTEXT` is set and the IdP didn't vouch for any of its values: MFA was skipped at the IdP, or the IdP calls it something else | `authnContexts` and `authnMethods` in the event show what it sent. Password only: the IdP admin fixes its MFA policy for the app. Another name for MFA: add it to the setting ([guide](../sso/saml-native.md#require-mfa-at-the-idp)) |
| `stale_authn` (people told their sign-in was too long ago) | `SSO_<ID>_FORCE_AUTHN` or `MAX_AUTHN_AGE` is set, botd asked the IdP to sign the person in again (`ForceAuthn`), and the IdP answered from its old session anyway | `authnInstant` and `authnSince` in the event show how old it was. The IdP app must honour ForceAuthn (some ignore it for Kerberos or passwordless sign-ins); meanwhile, a longer `MAX_AUTHN_AGE`, or unset it ([guide](../sso/saml-native.md#sign-in-age-and-the-idps-session-limit)) |
| `idp_session_ended` | The IdP's `SessionNotOnOrAfter` had passed, botd asked it to sign the person in again, and it answered with the ended session again | `idpSessionEnds` in the event says when. The IdP admin fixes its session lifetime for the app; meanwhile, `SSO_<ID>_IDP_SESSION_LIMIT=off` ([guide](../sso/saml-native.md#sign-in-age-and-the-idps-session-limit)) |
| Not offered; `botctl sso saml <provider>` says the IdP wants signed requests | Its metadata has `WantAuthnRequestsSigned="true"` | `SSO_<ID>_SIGN_REQUESTS=true`, restart, and give the IdP SuperBot's metadata or SP certificate ([guide](../sso/saml-native.md#signed-authnrequests)) |
| `bad_encryption` right after `sso.saml_sp_key_promoted` or `sso.saml_sp_key_retired` | SuperBot's encryption key was rolled over and the IdP still encrypts to the old one, now retired | Give the IdP the current encryption certificate (`botctl sso saml <provider>`). Don't retire a previous key until `botctl sso saml <provider>` shows it unused ([guide](../sso/saml-native.md#rolling-over-superbots-keys)) |
| Not offered with your own SP key | `SSO_<ID>_PRIVATE_KEY` missing or not matching `SSO_<ID>_SP_CERT_FILE` | Set the matching key and restart ([guide](../sso/saml-native.md#the-sp-key)) |

## Signing out doesn't sign out

Single logout works only when the IdP's metadata has a logout URL and the IdP has SuperBot's SP certificate and SLO URL (`botctl sso saml <provider>` says `Single logout: yes`; [guide](../sso/saml-native.md#single-logout)). An IdP that imported SuperBot's metadata before the SP key existed needs it imported again. Refused logout messages are in `botctl audit 50 --action auth.slo_failed`: `unsigned` or `bad_signature` means the IdP's certificate isn't in the metadata botd has, `wrong_destination` a different SLO URL at the IdP, `expired` a clock. The phone app and `botctl` end only their own session, by design. A person still signed in after the IdP said they were signed out is Severity 2: end their sessions with `botctl session revoke-all <user>` (their Bots' work carries on) while it's fixed.

## Nobody can sign in

Break-glass and one-time codes work as for any provider ([sign-in runbook](runbook-sign-in.md#nobody-can-sign-in)). Fix the certificate or the settings, have one admin sign in, then tell everyone.

## Escalate when

- `bad_signature` persists after the metadata is current and `botctl sso saml <provider>` shows the certificate the IdP signs with.
- A sign-in succeeds that should be refused (another person's account, a person not assigned at the IdP): that's a security incident, [Severity 1](escalation.md#security-incidents).
- Refusals with `wrapped`, `bad_response` or a reason not in the guide, from an IdP that worked before.

## Afterwards

Note the cause in the ticket. If it was a certificate rollover with metadata from a file or import, put the new certificate's expiry in the customer's record, and suggest a metadata URL so the next rollover needs nothing ([health check](health-check.md#3-identity)).
