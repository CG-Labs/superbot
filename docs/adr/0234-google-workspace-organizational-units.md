# 0234: Google Workspace organizational units

## Status

Accepted (24 Nov 2026). Part of [#51](https://github.com/CG-Labs/superbot/issues/51) (SCIM provisioning). Builds on [ADR 0162](0162-google-workspace-directory-sync.md) (the Google Workspace sync), which left organizational units out, and [ADR 0216](0216-google-workspace-push.md) (push), which left removal from a group unpushed. 0235 to 0238 are held by other open pull requests.

## Context

The Google Workspace sync gives accounts to the people in chosen groups and makes chosen groups teams. Many Workspace customers don't keep a group for "who uses this app". They keep **organizational units** (OUs): every user is in exactly one, they form a tree (`/Engineering/Platform`), and admins already use them to decide which Google services and policies apply to whom. For those customers, the sync's first step was making and maintaining a group that mirrors an OU, which drifts.

Push (ADR 0216) has a gap: the Directory API has no watch on group members, so someone taken out of a chosen group, but not suspended, keeps access until the next scheduled pass (30 minutes by default). Moving a user to another OU is a change to the user (`orgUnitPath`), which Google's `users.watch` already reports as `update`.

The Directory API gives each user's `orgUnitPath` with the read-only user scope the sync has. Reading an OU itself (`orgunits.get`, for its id, current path and whether it exists) needs `admin.directory.orgunit.readonly`. `orgunits.get` takes a path or the OU's id.

## Decision

### Two settings, like the group ones

- `GOOGLE_DIRECTORY_ORG_UNITS`: OUs whose people get an account, like `GOOGLE_DIRECTORY_GROUPS`.
- `GOOGLE_DIRECTORY_TEAM_ORG_UNITS`: OUs that are teams too (needs `SCIM_GROUPS=on`), like `GOOGLE_DIRECTORY_TEAM_GROUPS`. Their people get an account as well.

Each is a comma-separated list of paths (`/Sales/EMEA`, a trailing `/` ignored; people are matched to an OU's path in any case) or ids (`id:03ph8a2z...`), at most 50 across both. An OU **holds the units below it**: `/Engineering` gives an account to someone in `/Engineering/Platform`. `/` is everyone in the customer; it can give accounts but can't be a team (a team of everyone is a group's job). At least one group or OU must be named; groups and OUs can be mixed, and a person is in scope if any of them holds them.

An **id** keeps naming the OU after it's renamed or moved, and lets an admin name an OU whose path has a comma. Every pass reads each named OU (but `/`) from Google first, so it knows the OU's id and current path whichever way it was named.

### Teams from OUs

A team OU's team is keyed by the OU's id (`externalId`, like a group's Directory id), so renaming or moving the OU renames its team rather than replacing it. Its name is the OU's path without the leading `/` (`Engineering/Platform`): paths are unique in a customer and names aren't (`/Sales/EMEA` and `/Support/EMEA`). A path longer than a group's name (256 characters) is cut and ends with the OU's id, so two long paths still get different names. A path and an id of the same OU are one team.

Because every person is in one OU, each is on the team of the **deepest** team OU that holds them: with `/Engineering` and `/Engineering/Platform` both teams, someone in `/Engineering/Platform/Infra` is on Platform, and someone in `/Engineering` on Engineering. Team groups come before team OUs in ADR 0162's "first one wins", so someone on a team group stays there. Everything else is the team groups' code: people join and leave as their OU changes, someone who moves between two team OUs moves team in the same pass, a team OU taken off the list is deleted like a team group, and teams the sync doesn't manage are left alone.

A team OU and a team group with the same name collide (team names are unique in a tenant): the second one's create fails, is listed in the pass's `failures`, and the pass is retried until an admin renames one.

### The scope only when needed

The service account asks for `admin.directory.orgunit.readonly` only when an OU other than `/` is named. Servers that don't use OUs, and those using `/` alone, ask for the same two scopes as before, so their domain-wide delegation needs no change. A server that names an OU without delegating the scope gets `sign_in` (or `forbidden` with option B's admin role), with a detail that names the third scope, and changes nobody.

### Fail-closed, as before

- An OU Google doesn't have is `org_unit_not_found`, and the pass changes nobody: a deleted or mistyped OU must not look like everyone in it leaving. That's why OUs are read at all, rather than matched by path from users alone.
- When any OU is named, a user without an `orgUnitPath` in Google's answer is `odd_answer`, for the same reason.
- `GOOGLE_DIRECTORY_MAX_REMOVALS`, the would-remove-everyone guard, held disables and the audit are unchanged; moving a whole OU's people out counts as removing them.

### Push covers OU moves

Moving someone out of a chosen OU is a user `update` in Google, so with `GOOGLE_DIRECTORY_PUSH=on` it starts a pass within seconds, nothing new needed. A customer that scopes by OU and moves leavers to a "Leavers" OU (a common offboarding step) has their access, Bots and machine stopped at once, which group membership couldn't give.

### Status and summary

`GET /api/scim/google` (and `botctl scim google`) shows `orgUnits` and `teamOrgUnits` as configured. Each pass's summary (and `scim.google_sync`) gains `orgUnits`: each OU named, with its current path (so an OU named by id shows where it is now), how many people in scope it holds, and whether it's a team. No new audit action and no migration.

## Consequences

- Workspace customers who organize by OU can provision and make teams without mirror groups, and their OU moves are pushed.
- Naming an OU needs one more read-only scope in domain-wide delegation (or **Organizational Units → Read** in option B's admin role). The guide lists it.
- Each pass reads each named OU once more (at most 50 calls), against the Directory API's quotas.
- An OU path is the team's name, so it is kept as SCIM keeps any group name.

## Alternatives considered

- **Match people by `orgUnitPath` alone, with no new scope.** No delegation change, but a deleted, renamed or mistyped OU would match nobody and look like everyone in it leaving, stopped only by `GOOGLE_DIRECTORY_MAX_REMOVALS`; and teams would be keyed by path, so a rename would delete a team and make a new one. Reading the OU fails closed and keeps teams across renames.
- **Exact OUs only (no units below).** Simpler to explain, but OUs are a tree for a reason: naming `/Engineering` and missing everyone in its sub-units is the surprise. Policies in Google are inherited the same way.
- **First team OU listed wins, as for groups.** Groups overlap at will, so the order is the only rule; OUs nest, and "the most specific unit" is what an admin expects. The deepest-wins rule also means listing order never matters among team OUs.
- **The OU's own name as the team's name.** Shorter, but sibling OUs in different branches often share names (`EMEA`, `Contractors`), which would collide.
- **A watch on group members, or the Reports API, for pushed group removals.** The Directory API has no member watch; the Reports API's activity feed needs an audit scope and is a log, not state (ADR 0216). OUs give pushed removals with the scopes the sync is built on.

## Not done

- OUs as role groups (an OU that gives a custom role). Role groups stay groups.
- Excluding a sub-unit of a named OU (`/Engineering` but not `/Engineering/Contractors`); name the sub-units wanted instead.
- Several Workspace customers (one tenant per server, as in ADR 0162).
