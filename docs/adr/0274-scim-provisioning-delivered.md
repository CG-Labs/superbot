# 0274: SCIM provisioning is delivered, and what follows it

## Status

Accepted (25 Nov 2026). Closes the scope of [#51](https://github.com/CG-Labs/superbot/issues/51) (M5, SCIM provisioning) after seventeen ADRs, the last [ADR 0265](0265-changing-a-scim-mappings-role.md). The follow-ups below are proposed, not started.

Numbering: this number was reserved for this work.

## Context

#51 asks for three things: "SCIM for Entra, Google and Okta: create/disable users, group -> role mapping." Each is now merged and tested:

| #51 asks for | Delivered by | Checked by |
|---|---|---|
| SCIM for Entra ID and Okta | A SCIM 2.0 server with per-tenant tokens ([ADR 0023](0023-scim.md), [ADR 0026](0026-scim-review-hardening.md)), groups as teams ([ADR 0095](0095-scim-groups-as-teams.md)), Bulk ([ADR 0153](0153-scim-bulk.md)), the Enterprise User extension ([ADR 0176](0176-scim-enterprise-user-extension.md)), tokens that expire and rotate ([ADR 0196](0196-scim-token-expiry-and-rotation.md)) and scoped tokens ([ADR 0224](0224-scim-token-scopes.md)), with a [guide](../sso/scim.md) for each IdP | `scim_http_tests` (`entra_patches_deletes_softly_and_provisions_again`, `okta_provisions_finds_updates_and_deactivates`), `scim_groups_http_tests` (`entra_pushes_a_group_and_patches_its_members`, `okta_pushes_groups_with_put_and_patch`), `scim_bulk_http_tests`, `scim_tokens_http_tests`, `scim_scopes_http_tests` |
| SCIM for Google Workspace | Google pushes SCIM only to its catalog apps, so botd reads the directory through the same handlers ([ADR 0162](0162-google-workspace-directory-sync.md)), with push on user changes ([ADR 0216](0216-google-workspace-push.md)) and group membership ([ADR 0244](0244-google-workspace-group-membership-push.md)), and organizational units ([ADR 0234](0234-google-workspace-organizational-units.md)), with a [guide](../sso/google-workspace.md) | `scim_google_http_tests`, against a stand-in for Google's token, Directory and Reports APIs |
| Create users | `POST` and `PUT /scim/v2/Users`, linked to the IdP's SSO subject so each person is one user (ADR 0023) | `scim_http_tests` |
| Disable users | Deactivating or deleting someone ends their sessions, stops their runs and the runs for them, and suspends their machine ([ADR 0124](0124-deprovisioning-stops-bots-and-machines.md)) | `deprovision_http_tests`, `machines_offboard_tests` |
| Group to role mapping | A team's group mapped to a custom role, in the team or across the server ([ADR 0138](0138-scim-group-role-mapping.md)), role groups that aren't teams ([ADR 0180](0180-scim-role-groups.md)), team role groups ([ADR 0206](0206-scim-team-role-groups.md)), all of it in the console ([ADR 0253](0253-scim-group-roles-in-the-console.md)), and changing a mapping's role in place (ADR 0265); never admin nor a role reaching admins | `scim_group_roles_http_tests`, `scim_role_groups_http_tests`, `scim_team_role_groups_http_tests` |

The roadmap already said nothing in #51's scope was left. Each ADR still defers more, so #51 would never end if every deferral stayed under it, as [ADR 0259](0259-per-user-computer-hardening-delivered.md) found for #54.

## Options

1. **Keep #51 open** and keep taking deferred items under it.
2. **Call #51 delivered**, and list the deferred items as follow-ups, ranked, each for an issue of its own.

We chose option 2, as ADR 0259 did. Each follow-up is a separate choice with its own cost and priority.

## Decision

#51 is delivered. The roadmap says so, and no further slices are made under it.

These follow-ups are proposed, in order of value. None is started. Each would need an issue (under M5, or later) and an ADR of its own.

1. **Offering roles when one is taken outside SCIM** (deferred by ADR 0206). When an admin, rather than SCIM, takes someone off a mapped team, the role a mapping gave them goes, but the role groups they're in aren't offered until the IdP next pushes one of them; and when a role group's role is taken, the mappings they're under aren't offered either. Both fail closed (less access, not more), yet someone can be left without a role their groups say they should have. Likely shape: call the same offer ADR 0206 makes after SCIM's own changes from `teams::leave` and from a role group's revoke.
2. **Faster removals made in Google Groups itself** (deferred by ADR 0244). Changes a group's own managers make, and dynamic groups following their query, aren't in the Admin log, so a leaver taken out that way keeps access until the next scheduled pass (30 minutes by default). Likely shape: a cheaper membership-only check of the chosen groups between full passes, nudging a full pass when a member goes.
3. **A deprovisioned person's harness sessions on teammates' machines** (deferred by ADR 0124). Deprovisioning stops their runs everywhere and suspends their own machine, but anything left on a teammate's machine beyond what [ADR 0052](0052-teammate-offboarding-on-machines.md) removes stays until that machine is next cleaned up.
4. **Several Google Workspace customers on one server** (deferred by ADRs 0162, 0216, 0234 and 0244). The sync writes one tenant; a managed server with two Workspace customers can sync only one of them.
5. **OAuth client credentials for SCIM** (deferred by ADRs 0196 and 0224), for IdPs that support them (Okta), carrying scopes the standard way and removing the yearly manual rotation; Entra's non-gallery SCIM app keeps bearer tokens.
6. **SCIM protocol extras** (deferred by ADRs 0023, 0095, 0153 and 0176): ETags (`meta.version`), sorting, filtering on extension attributes, groups in groups, and more than one team per person. Entra and Okta don't need them today.
7. **Enterprise attributes where admins work** (deferred by ADR 0176): department, manager and the rest in the console's Users tab and the app, and an access review that sends each manager their reports' rows.
8. **Smaller extras**: email notices before a SCIM token ends, beside the audit events (ADR 0196); a console screen for linking groups to existing teams (ADR 0095); changing a mapping's group in place (ADR 0265); organizational units as role groups, excluding a sub-unit, aliases, custom schema attributes, and a setting to let the sync re-enable people an admin disabled (ADRs 0162 and 0234); and Google push without a public https address, through a relay (ADR 0216).

## Consequences

- #51 can be closed once this is merged. No behaviour changes, and nothing needs upgrading.
- The follow-ups stay visible in one place, ranked, rather than only in the Not done sections of seventeen ADRs.
- SCIM stays off by default (`SCIM=on`), as do groups as teams (`SCIM_GROUPS=on`), group roles (`SCIM_GROUP_ROLES=on`) and the Google sync (`GOOGLE_DIRECTORY_SYNC=on`); an operator turns on what their IdP uses, as the guides say.
- M5's exit criterion "one enterprise logo on SCIM + Entra or Okta" needs a customer using it; that is outside the code and outside this issue.
- Until the first follow-up exists, an admin who takes someone off a mapped team by hand and wants their role groups to apply at once takes them out of the role group in the IdP and adds them back, which offers its role; pushing the group unchanged offers nothing.

## Tests

None: this changes only docs. The links are checked by the docs workflow's site build.
