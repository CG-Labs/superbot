# 0190: Requiring how people signed in at the SAML IdP

## Status

Accepted. The eighth M5 slice of full SAML ([#52](https://github.com/CG-Labs/superbot/issues/52), [roadmap](../ROADMAP.md#m5--enterprise)). Builds on [ADR 0127](0127-native-saml-service-provider.md) (the native SP) and [ADR 0160](0160-saml-groups-and-role-mapping.md) (refusing people before just-in-time sign-up). Setup guide: [native SAML](../sso/saml-native.md#require-mfa-at-the-idp).

## Context

SuperBot doesn't ask single sign-on sign-ins for a second factor of its own. The IdP's MFA is that factor ([ADR 0094](0094-totp-second-factor.md)). Every IdP guide tells customers to require MFA there, and the SOC 2 checklist lists it as their duty (CC6.1-2). But botd took any signed assertion, whatever it said about how the person signed in. A Conditional Access policy that was switched off, scoped to the wrong group, or skipped for a "trusted" network left SuperBot open to a password alone, and nothing in SuperBot showed it.

A SAML assertion says how the person signed in, in two places:

- **The `AuthnContextClassRef`** of each `AuthnStatement`. This is the standard place. An SP can ask for classes with `RequestedAuthnContext` in its AuthnRequest. If the IdP can't sign the person in that way, it answers `NoAuthnContext`.
- **An attribute** that lists the methods used, as OIDC's `amr` claim does.

IdPs use these places differently:

- **Microsoft Entra ID** puts the strongest method in the class (`Password`, `MobileTwoFactorContract`, `SmartcardPKI`, …). It also sends an `authnmethodsreferences` attribute, which has `http://schemas.microsoft.com/claims/multipleauthn` once MFA was done. It honours `RequestedAuthnContext` only with `exact` comparison, and then returns `multipleauthn` as the class. But it fails the sign-in (AADSTS75011) when the person's existing session used another method than the one asked for.
- **ADFS** runs its additional authentication when asked for the `multipleauthn` class, and returns it.
- **Okta** sends a class fixed by the app's settings (`PasswordProtectedTransport` by default), whatever the person did. Its `session.amr` expression, mapped to an attribute, lists `pwd`, `mfa`, `swk` and so on.
- **Shibboleth and research federations** use the REFEDS MFA profile, `https://refeds.org/profile/mfa`, as the class.

So a check needs both places, and asking the IdP must be optional.

## Decision

A native SAML provider can require how people signed in (`SSO_<ID>_AUTHN_CONTEXT`, a comma-separated list, no default). A sign-in must show one of the listed values. It can show it as an `AuthnContextClassRef` of the verified assertion's `AuthnStatement`s, or as a value of the attribute `SSO_<ID>_AUTHN_METHODS_ATTRIBUTE` names, when one is set. Otherwise it's refused.

- **What's read.** Values are read only from the assertion whose signature was checked, like groups (ADR 0160). Each is trimmed, and must be plain text of at most 256 bytes. At most 16 are read from each place. Anything else is left out, which can only refuse a sign-in. A context with a declaration (`AuthnContextDecl`, `AuthnContextDeclRef`) or two classes names no class. Matches are exact, case included: these are URIs, and a near miss is another way of signing in. Values are URIs or tokens like `mfa`, with no spaces. Up to 16 can be listed.
- **When it's checked.** After the signature, the replay check, the email allow-list and required groups, and before the account is looked up. So just in time never makes an account for someone who didn't meet it, and it's checked on every sign-in. The refusal is `auth.login_failed` with reason `authn_context`. The event names the subject, the classes the IdP sent (`authnContexts`) and, with an attribute, its values (`authnMethods`), so an admin can see what to require or what the IdP did. The person sees "didn't use the method this server requires, such as multi-factor authentication" (`sso_mfa_required`). Like a required-groups refusal, it counts against the client's address.
- **Asking the IdP** (`SSO_<ID>_REQUEST_AUTHN_CONTEXT=true`, default `false`). AuthnRequests carry `RequestedAuthnContext` with `Comparison="exact"` and the listed values in order. `exact` is the one comparison every IdP takes. An IdP that answers `NoAuthnContext` is shown to the person as `sso_mfa_required`, audited as `idp_error` with that status. Asking isn't the check: a response is held to the list whether or not it was asked for.
- **Evidence.** Every native SAML `auth.login` now records `authnContext`. With a requirement, that's the value that met it, taken from the list in the admin's order. Without one, it's the first class the IdP sent. Admins can then see what their IdP sends before requiring it, and auditors see per sign-in that MFA was vouched for.
- **IdP-initiated sign-in** (ADR 0175) isn't changed. An unsolicited response never signs anyone in. It restarts as an SP-initiated sign-in, which is asked for and checked like any other.
- **Settings that would look like a check.** `AUTHN_METHODS_ATTRIBUTE` or `REQUEST_AUTHN_CONTEXT` without `AUTHN_CONTEXT` is refused at startup, as `REQUIRED_GROUPS` without `GROUPS_ATTRIBUTE` is. All three are native SAML only. `GET /api/sso/:id/saml` and `botctl sso saml <id>` show them.

The guide gives the setting for each IdP. For Entra ID, read the `authnmethodsreferences` attribute for `multipleauthn`, and don't ask. For ADFS, ask for `multipleauthn`. For Okta, map `session.amr` to an `amr` attribute and require `mfa`. For federations, use the REFEDS MFA class.

## Alternatives considered

- **Only the class, as the SAML spec intends.** Okta's class doesn't change with MFA, and Entra ID's is the "strongest method", which isn't the same as two factors (a FIDO2 key is `SmartcardPKI`, an Authenticator push without a password is `MobileTwoFactorContract`). The attribute lets an admin require what the IdP actually reports.
- **Shortcuts like `AUTHN_CONTEXT=mfa` that botd expands per IdP.** botd would have to keep up with each IdP's values. It would also have to guess which IdP it's talking to, and a guess that's too broad lets people in. Explicit values are what the IdP's documentation lists, and the audit log shows what it sends.
- **Asking by default.** Entra ID refuses sign-ins whose session used another method, so turning on a requirement would break sign-in for people already signed in to Microsoft 365. Off by default, the requirement works with any IdP. Asking is for IdPs that need it to do MFA (ADFS) or that do step-up on request.
- **`minimum` or `better` comparison.** These depend on the IdP ranking its classes, which isn't standard. Entra ID refuses them.
- **Applying it only to admins** (like `AUTH_MFA=admins`). The AuthnRequest is sent before botd knows who's signing in, and a refusal after the IdP's answer would need a step-up flow. One rule per provider is simpler and is what IdP policies do. Admins who need it alone can use a provider of their own.
- **Requiring a recent sign-in** (`AuthnInstant`, `ForceAuthn`). This is useful against long IdP sessions, but it's a separate control. It's left for later.
- **Doing the same for OIDC** (`acr`, `amr`). The same idea fits there, but #52 is SAML. It's left for later.

## Consequences

- Customers can make SuperBot enforce the IdP's MFA, not just trust it. A policy gap at the IdP becomes a refused, audited sign-in rather than a silent password-only session. This closes part of CC6.1-2 for native SAML.
- Every native SAML sign-in records how the IdP says the person signed in, with or without a requirement.
- People already signed in keep their sessions when a requirement is turned on. It applies from their next sign-in. End sessions by hand to apply it at once.
- The bridge ([ADR 0020](0020-saml-bridge.md)) doesn't get this: the broker decides how people sign in there.
- A wrong value locks everyone out of that provider. Break-glass and one-time codes still work, and the audit log shows what the IdP sent.
