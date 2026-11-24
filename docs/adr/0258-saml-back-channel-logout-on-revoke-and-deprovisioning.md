# 0258: SAML back-channel logout on revoke and deprovisioning

## Status

Accepted. The fifteenth M5 slice of full SAML ([#52](https://github.com/CG-Labs/superbot/issues/52), [roadmap](../ROADMAP.md#m5--enterprise)). Builds on [ADR 0208](0208-saml-back-channel-soap-logout.md) (back-channel SOAP logout), which left this out, and [ADR 0012](0012-users-sessions-rbac.md) (session revoke). Setup guide: [native SAML](../sso/saml-native.md#when-an-admin-or-scim-ends-sessions).

## Context

botd ends a native SAML IdP's session when the person signs out of SuperBot: over the browser (ADR 0137, ADR 0248) or, with no browser, over SOAP (ADR 0208). Sessions also end without a sign-out:

- an admin revokes one session (`DELETE /api/sessions/{id}`) or all of someone's (`DELETE /api/users/{key}/sessions`), usually because a device was lost or a session looks stolen;
- an admin disables or erases someone (`PATCH /api/users/{key}`, ADR 0102);
- SCIM deactivates or deletes them (`active: false`, `DELETE /scim/v2/Users/{id}`).

In each case botd revoked only its own sessions. The IdP session that made them lived on, so the same browser could sign straight back in through the IdP without a password, as long as the person was still allowed in. Disabled people are refused at sign-in, but the IdP session still kept them signed in to every other app sharing it, and Entra ID, for one, doesn't end sessions when an account is disabled. ADR 0208 named this gap and left it for later because the session and deprovisioning paths were changing then. It was the last back-channel item open on #52.

## Decision

When botd revokes sessions without a sign-out, it tells each native SAML IdP that vouched for one over SOAP, with no new setting.

- **Which sessions.** Those signed in through a native SAML provider whose cached IdP metadata has a SOAP `SingleLogoutService` (https, or http only on loopback, as ADR 0208), with the NameID and SessionIndex kept at sign-in (ADR 0137), and still live until this moment by their idle and absolute TTLs and the IdP's own session end (ADR 0225). A session that had already expired is left alone: its IdP session may be a newer one by now.
- **Once per IdP session.** Sessions with the same provider, NameID and SessionIndex (a web sign-in and a phone sign-in in the same IdP session, say) get one LogoutRequest. At most 20 go out per action, and a warning is logged past that; a person rarely has more than a few IdP sessions.
- **The request** is ADR 0208's: signed with an enveloped signature by the SP signing key, to the SOAP SLO URL, naming the NameID and that SessionIndex. Each IdP ends only that IdP session (and, as SLO does, the other apps in it), not every session the person has.
- **Never waiting on the IdP.** The SuperBot sessions are revoked first, and the requests are built from cached metadata only (no fetch) and sent one after another in the background. An IdP that is slow, down or refuses changes nothing in SuperBot.
- **Audited where the admin looks.** Each answer is `auth.slo_response` against the session, as for a sign-out, now with `revokeReason`: `revoked by admin`, `user disabled`, `deprovisioned by SCIM`, `deleted by SCIM` (and `logout` for sign-outs). The event of the action itself (`session.revoked`, `session.revoked_all`, `user.disabled`, `scim.user_deleted`) lists the request IDs in `idpLogouts`, only when it sent any, so the two can be matched. Erasure disables first, so it's covered by `user disabled`.

`revoke_user_sessions` now returns the sessions it revoked (`UPDATE … RETURNING`) rather than a count, so the choice is made from exactly the rows this action ended, with no read-then-revoke race.

## Alternatives considered

- **A setting (`SSO_<ID>_REVOKE_LOGOUT=off`).** The request goes only to the IdP the provider already trusts, at the address its metadata names, and names only an IdP session SuperBot itself has just ended. ADR 0208 turned on SOAP logout the same way. Rejected until someone needs revokes that leave the IdP alone.
- **Also send the browser bindings.** There is no browser of the person's to send: the admin's browser must not be used to end someone else's IdP session. Rejected; an IdP without a SOAP logout URL can't be told, and the guide says so.
- **One LogoutRequest naming only the NameID, to end every IdP session the person has.** Simpler, but it would also end IdP sessions SuperBot never saw, on devices nobody revoked. Rejected: one request per IdP session SuperBot ended.
- **Wait for the IdP's answer before answering the admin or SCIM.** SCIM clients have short timeouts and retry, and an IdP that is down would make revoking look broken when the SuperBot sessions are already gone. Rejected, as in ADR 0208.
- **Fetch the IdP's metadata when none is cached.** That would make an admin's action wait on the network. Metadata is loaded at startup and kept fresh (ADR 0127), so in practice it's always cached. Rejected.
- **Tell the IdP about sessions it ended itself.** Sessions the IdP's own LogoutRequest revoked (ADR 0137) are not sent back to it: that path doesn't go through these revokes.

## Consequences

- Revoking a session or a person in SuperBot, by hand or through SCIM, now also ends the IdP sessions behind it when the IdP supports SOAP logout, so a stolen browser can't sign back in through the IdP.
- Those people are also signed out of other apps in the same IdP session, as single logout always does. Admins who revoke a session for housekeeping should know this.
- Nothing changes for OIDC providers, the SAML bridge, password and code sessions, or IdPs without a SOAP logout URL.
- Still open on #52, only if a customer needs them: the Artifact binding and multi-IdP federation metadata (InCommon, eduGAIN).
