# 0103: Just-in-time SSO accounts need an allow-list for every provider

## Status

Accepted (22 Nov 2026). Part of the SOC 2 readiness checklist of M4, [#50](https://github.com/CG-Labs/superbot/issues/50); closes checklist row CC6.2-1 in the [readiness checklist](../security/soc2-readiness-checklist.md). Amends [ADR 0016](0016-sso-multi-provider.md) (generic OIDC) and [ADR 0020](0020-saml-bridge.md) (SAML), where `ALLOWED_DOMAINS` was optional with just in time.

0101 is the highest number on `main`. Open PR [#164](https://github.com/CG-Labs/superbot/pull/164) holds 0100, which `main` already uses, so it will likely move to 0102; this ADR takes 0103 to stay clear of it.

## Context

With `SSO_<ID>_JIT_ROLE` set, the first sign-in of a person nobody has linked makes them a SuperBot user with that role. SOC 2's CC6.2 expects accounts to be registered and authorised before access, so who can become a user that way has to be bounded by something SuperBot checks, not only by how the IdP happens to be configured.

What each provider type did with just in time, read from `server/src/sso/mod.rs`:

| Type | Allow-list | With `JIT_ROLE` and no list |
|------|------------|-----------------------------|
| `google` | `HOSTED_DOMAINS` (the token's `hd`) | Refused at startup |
| `apple` | `ALLOWED_DOMAINS` (verified, non-relay email) | Refused at startup |
| `github` | `ALLOWED_ORGS` (active membership, from GitHub's API) | Refused at startup |
| `entra` | `TENANT` (a tenant id), or `organizations`/`common` with `ALLOWED_TENANTS` | Can't happen: a tenant id is required, and `organizations`/`common` are refused without `ALLOWED_TENANTS`, with or without just in time |
| `oidc` | `ALLOWED_DOMAINS` (verified email) | **Accepted**: anyone the IdP signs in got an account |
| `saml` | `ALLOWED_DOMAINS` (verified email) | **Accepted**: anyone the SAML IdP signs in got an account |

ADR 0016 and ADR 0020 left the list optional for `oidc` and `saml` because the IdP is usually the customer's own, and the guides told operators to limit the app to the right people there. But "usually" isn't a control. An IdP that lets anyone sign up (Auth0 with a database or social connection, a Keycloak realm with self-registration, a shared Okta org) plus just in time admits anyone, and nothing in SuperBot says so.

## Decision

### Refuse to start

botd refuses to start when a provider has `JIT_ROLE` set to a role and no allow-list for its type. `oidc` and `saml` now behave like `google`, `apple` and `github`: `SSO_<ID>_JIT_ROLE` needs `SSO_<ID>_ALLOWED_DOMAINS`. The error names the provider's settings, so the provider, and the setting to add:

```text
SSO: SSO_OKTA_JIT_ROLE without SSO_OKTA_ALLOWED_DOMAINS would let anyone the okta IdP signs in get an account: list your email domains, or link people instead
SSO: SSO_ADFS_JIT_ROLE without SSO_ADFS_ALLOWED_DOMAINS would let anyone SAML IdP http://adfs.example.com/adfs/services/trust signs in get an account: list your email domains, or link people instead
```

The list is the verified email's domain, checked at each sign-in as before: an unverified or missing email, or one at another domain, is refused (`email_unverified`, `wrong_domain`). Nothing about sign-in changes; only which settings start.

Without just in time (`JIT_ROLE` unset or `off`) no list is needed: an admin links each person, which is itself the authorisation.

### Why a pinned Entra tenant counts

Entra's allow-list is the tenant. `SSO_ENTRA_TENANT` is required. A tenant id (a GUID) makes botd use that tenant's own issuer and check each token's `tid` against it, so only accounts that tenant's admins created or invited can sign in. `organizations` and `common` accept every tenant, so they are refused unless `SSO_ENTRA_ALLOWED_TENANTS` lists the tenant ids to accept; each token's `tid` must be one of them. Personal Microsoft accounts (`consumers`) are refused outright. So there is no Entra setting that makes accounts for anyone outside a listed tenant, and Entra needs no change. The tenant is a stronger bound than an email domain: it is who owns the account, not a string in a claim.

Guest (B2B) users invited into the tenant can sign in with it; that is the tenant admin's decision, as it is for every other app in the tenant. The Entra guide already says how to require assignment to the app.

### On upgrade

A server with just in time on a generic OIDC or SAML provider and no `ALLOWED_DOMAINS` stops at upgrade. That is the point: that server was admitting anyone its IdP signed in. The fix is one line, `SSO_<ID>_ALLOWED_DOMAINS=<your domains>`, or `SSO_<ID>_JIT_ROLE=off` and linking people. Accounts already made are kept; the check only governs new ones.

We rejected warning and starting anyway. A warning is easy to miss in a log, and a control that depends on someone reading it fails open, which is what the checklist row is about. Refusing to start is what the other three types already did, and what botd does for every other unsafe SSO setting.

We also rejected an escape hatch (a setting to allow just in time without a list). An IdP whose users have no common email domain can keep `JIT_ROLE=off` and have an admin link people, or provision them with SCIM ([ADR 0023](0023-scim.md)), both of which are authorisation SuperBot can show.

## Tests

- **Unit tests** (`server/src/sso/mod.rs`, `every_type_refuses_just_in_time_without_an_allow_list`): for `oidc`, `saml`, `google`, `apple` and `github`, `JIT_ROLE` alone is refused with an error naming `JIT_ROLE` and the list setting; with the list it is accepted with the role. Entra with a tenant id and `JIT_ROLE` is accepted, and `organizations` with `JIT_ROLE` is refused naming `ALLOWED_TENANTS`, accepted with it. Without just in time, every type starts with no list.
- **End to end** (`server/tests/sso_jit_allow_list.rs`). The real `botd` exits at startup for each type with just in time and no list, saying which setting to add, and starts once the list is set, with a pinned Entra tenant, and without just in time.

## Consequences

- No provider type can make accounts just in time for people outside a list SuperBot checks: a domain, an organisation, or a tenant. CC6.2's just-in-time gap is closed.
- Generic OIDC and SAML servers with just in time and no domain list stop at upgrade until one is set. The error says how.
- An IdP with no common email domain can't use just in time; it links people or uses SCIM.
