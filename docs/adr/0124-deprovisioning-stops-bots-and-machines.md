# 0124: Deprovisioning stops a person's Bots and machine

## Status

Accepted (22 Nov 2026). Part of SCIM provisioning in M5, [#51](https://github.com/CG-Labs/superbot/issues/51). Builds on the SCIM stub and its review ([ADR 0023](0023-scim.md), [ADR 0026](0026-scim-review-hardening.md)), groups as teams ([ADR 0095](0095-scim-groups-as-teams.md)), disabled users' routines ([ADR 0047](0047-disabled-users-routines.md)), teammate offboarding ([ADR 0052](0052-teammate-offboarding-on-machines.md), [ADR 0066](0066-removing-teammate-accounts-on-one-server.md)), per-run tokens ([ADR 0083](0083-per-run-tokens.md)) and the control plane ([ADR 0025](0025-control-plane-linode.md)).

Numbering: `main` has up to 0118; 0119 to 0123 are held by open pull requests, so this is 0124.

## Context

#51 asks for SCIM from Entra ID and Okta that creates and disables people, and for group-to-role mapping. Most of it exists: per-tenant bearer tokens, Users create, replace, patch, deactivate and soft delete, groups as teams, and audit events with the token as the actor.

What deprovisioning did not do was stop the person's work. Deactivating someone (`active: false`) or deleting them ended their sessions, paused their routines, closed screens and took them off teammates' machines. But:

- **A run already going on one of their Bots went on**, with whatever it had queued behind it, until the harness finished (up to the run timeout). So did a run on someone else's shared Bot that was for them.
- **A run for a teammate who was disabled kept its Bot token's reach.** A disabled owner's Bot token was already refused (`owner_role`, ADR 0029). But a run of an owner's shared Bot for a teammate (ADR 0046, 0064) lost only its Bot access when that teammate was disabled; every other route its token reaches still answered.
- **Their own machine kept running.** Its agent can no longer reach botd once its user is disabled (ADR 0031), but it kept its harness logins, files and processes up, and kept costing money, until an admin suspended it.

An enterprise expects a leaver's access to end with the IdP's update, everywhere, not after the next run finishes or an admin remembers the machine. The same holds when a server admin disables someone by hand.

## Decision

### One step after every disable

`deprovision::user_disabled` runs after the user is saved as disabled, wherever that happens: SCIM `active: false` (`via: scim`), SCIM `DELETE` (`scim_delete`), and an admin's `PATCH /api/users/{key}` with `status: disabled` (`admin`, so `botctl user disable` and the console too). Erasure already stops runs and destroys the machine itself (ADR 0102), so it doesn't call it. It:

1. **Stops every Bot they own that is busy**: the run going now is aborted, what's queued is dropped (routine runs given back to the period), and pending approvals are cancelled, as the Stop button does.
2. **Stops the runs on others' Bots that are for them**: queued or started, any message whose requester names them (who asked, on whose behalf, for whom), the same rule erasure uses.
3. **Suspends their machine** (below).
4. Records **`user.deprovisioned`** with `via`, `botsStopped`, `runsForThemStopped`, and `machine` (`{id, state}`), with the same actor as the disable: the SCIM token (`system`, `scim:<token id>`, method `scim_token`) or the admin.

It is safe to run twice. Entra and Okta often deactivate and then delete; the second pass finds nothing busy and the machine already off, and says so.

### Bot tokens act for no one who is disabled

Next to the existing check that a Bot can do no more than its owner (403, `access.denied` with `owner_role`), a run token whose run is for a teammate who is now disabled is refused on every route (403, `access.denied` with `for_user_disabled`). Stopping the run already revokes its token when the run ends; this covers the moments between, and any path that disables someone without stopping their runs.

### Their machine

`MACHINE_ON_DISABLE`, read with the control plane: `suspend` (the default) or `keep`.

- **Running**: suspended at once through the same path as an admin's suspend (`machine.suspended`, its certificates held), and marked with a **disable hold** (`machine_disable_holds`, migration 48).
- **Still being built** (`pending`, `provisioning`): held; the reconciler suspends it once it runs.
- **The provider refused**: `failed`, the hold stays, and the reconciler tries again on its next pass (`disabled.suspended` in its result).
- **Already suspended** without a hold (an admin did it, or a team released it): left alone, `already_suspended`, and no hold, so enabling them won't turn it on.
- **Gone**, no machine, or no control plane: `gone` or `none`.
- With `keep`: `kept`. It stays running and unreachable from botd, as before.

**Enabling them** (SCIM `active: true`, re-provisioning after a `DELETE`, or an admin) ends the hold and resumes the machine (`machine.resumed`, and `user.machine_resumed` with whether it worked), unless a team released it meanwhile, which ADR 0087 already takes back or destroys. Only a machine the disable suspended comes back on. If someone is enabled by a path that doesn't call this, the reconciler sees the hold of an active user and does the same.

The machine is suspended, never destroyed. Deprovisioning is reversible in SCIM (Entra and Okta reactivate people), and a destroyed machine takes the user's files with it. Destroying it is still an admin's step, or erasure's.

### What stays as it was

Sessions, sign-in codes, routines, screens, and teammates' accounts and users on others' machines are handled as ADR 0012, 0047, 0052 and 0066 decided. SCIM still never sets a role. Teams are left as ADR 0095 says: deactivation keeps someone on their team, disabled; `DELETE` takes them off a team their tenant's group put them on.

## Consequences

- A leaver's Bots stop within one request of the IdP's update, and their machine powers off with it, on SCIM and by hand alike.
- Disabling someone now stops runs other people started on that person's shared Bots too. That is ADR 0046's rule (a disabled owner's Bots don't run) applied to runs already going, not only new ones.
- An admin's disable to "pause" someone has the same effect as the IdP's: machine off. `MACHINE_ON_DISABLE=keep` is the way out for operators who want the machine left up.
- Suspending is one provider call per leaver, serialised with every other machine change.

## Alternatives considered

- **Let runs finish.** Simple, but a run can last up to the run timeout with its owner's access, and a queued message would still start for a run that was already going. Rejected.
- **Destroy the machine on `DELETE`.** Matches "delete", but Entra and Okta reactivate people, and destroying loses their files. Suspension with a hold is reversible; erasure is the destructive step.
- **Resume every suspended machine when a user is enabled.** Would turn on machines admins powered off on purpose. Hence the hold.

## Not done

- **Group-to-role mapping.** #51 asks for it, and ADR 0023 and ADR 0095 deferred it: it is where admin escalation hides. It needs its own design (at least: never `admin`, per tenant, opt-in, and what happens to a role when a group goes).
- Google Workspace, which has no generic SCIM client (the guide's workaround stands), and SCIM Bulk.
- Stopping a deprovisioned person's harness sessions on a teammate's machine beyond what ADR 0052 removes.
