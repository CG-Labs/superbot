# 0253: SCIM group roles in the console

## Status

Accepted (24 Nov 2026). Part of [#51](https://github.com/CG-Labs/superbot/issues/51) (SCIM provisioning: group → role mapping). Closes the "Not done" of [ADR 0180](0180-scim-role-groups.md) (declaring and changing role groups in the console), on top of [ADR 0138](0138-scim-group-role-mapping.md) (groups mapped to roles) and [ADR 0206](0206-scim-team-role-groups.md) (team role groups), and follows [ADR 0182](0182-delegates-own-service-accounts.md)'s `choices` pattern.

Numbering: this number was reserved for this work.

## Context

Group-to-role mapping is how most enterprise customers will use SCIM: the IdP says who is in a group, and an admin decides what that group gives. The console's SCIM section listed mappings and role groups and removed them, but making one meant `botctl scim role map`, `botctl scim role-group add` or the API. Two things made that worse than an inconvenience:

- **Order matters.** A role group has to be declared before the IdP first pushes the group, or it becomes a team (ADR 0180). The admin setting up provisioning in Entra or Okta is in a browser, not a shell, and is the person most likely to push first.
- **The rules are subtle.** Which roles SCIM may give depends on the scope: never one that reaches admins there (`bots.manage` and `machines.manage` across the server, `machines.manage` in a team) and never a time-bound role (ADR 0197). Only team permissions count in a team. A form that offered every custom role would let an admin pick one the server refuses, or one that gives nothing in a team without saying so.

The Google sync adds a third: groups listed in `GOOGLE_DIRECTORY_ROLE_GROUPS` but never declared are skipped by every pass, and the only sign was `roleGroups.undeclared` in a pass's summary.

## Decision

### The server says what it would take

`GET /api/scim/role-mappings` and `GET /api/scim/role-groups` gain `choices`, worked out without auditing anything:

```json
{
  "roles": {
    "org":  [{ "id": "r1", "name": "Auditor", "applies": ["audit.view"] }],
    "team": [{ "id": "r1", "name": "Auditor", "applies": [] },
             { "id": "r2", "name": "Support lead", "applies": ["users.manage"] }]
  },
  "groups": [{ "tenant": "entra", "team": { "id": "t1", "name": "Support" }, "displayName": "Support", "scopes": ["team", "org"] }],
  "tenants": ["entra", "google"],
  "undeclared": [{ "tenant": "google", "displayName": "auditors@example.com" }]
}
```

- `roles` (both): the custom roles a mapping or role group may give in each scope, with what each gives there. One function, `scim::roles::givable`, decides: not time-bound and nothing reaching admins in that scope. The create routes check the same with their own refusals and audit events, and the database checks again as it saves. A test declares a role group and makes a mapping with every role in both scopes, and requires that exactly the offered ones are accepted, so the two can't drift.
- `groups` (mappings): each team group with the scopes it has no mapping in yet (a group has at most one per scope). A group with both mapped is left out.
- `tenants` (role groups): the tenants of SCIM tokens, the Google sync's tenant, and tenants that have groups or role groups, as suggestions. A role group may be declared before its tenant has a token, so the console's tenant field stays free text.
- `undeclared` (role groups): the Google sync's `GOOGLE_DIRECTORY_ROLE_GROUPS` with no declaration. A pass finds declarations by the group's Directory id as well as its email, and only Google knows the ids, so each pass that reads the role groups keeps their ids in memory, and the list is worked out live from the declarations, matched the way a pass matches them. Declaring or removing one shows at once. Before any pass since botd started, only emails can match, so a group declared only by its id shows until the first pass.

### In the console

Under **Group roles** in the SCIM section, shown only while `SCIM_GROUP_ROLES` is on:

- **Map group**: a team group, where the role applies (only the scopes still free for that group) and a role (only `roles` for that scope, each with what it gives there, or "gives nothing there"). The answer's grants and skips are summed up in the notice, skips by reason.
- **Declare role group**: tenant (with suggestions), the group's name as the IdP pushes it, an optional `externalId`, scope and role. The notice says to assign the group in the IdP now, since it waits until then.
- **Changing a role group's role**: each row's role is a picker of the roles its scope may give. Choosing one asks first (what the old role gave goes, then members are offered the new one), then sends `PATCH`.
- **Undeclared Google groups** are listed above the table; picking one fills in the tenant and name.

The server checks everything again; the console holds no rule of its own. Mappings still can't change their role (there is no `PATCH` for them): remove and map again, as before. The console is served by the same botd, so there is no fallback for a server without `choices`.

## Consequences

- An admin can set up group-driven roles end to end in the browser, in the order that works: declare, then assign in the IdP.
- The console never offers a role the server refuses, and says when a team-scoped role gives nothing.
- Each list reads the custom roles, team groups and SCIM tokens once more, and checks each role in memory. No migration, no new route, no new setting, no new audit event (the existing routes audit as before).
- `botctl` and the API are unchanged; their output gains `choices`.

## Alternatives considered

- **Offer every custom role and let the server refuse.** Simpler, but an admin learns the rules one 400 at a time, and every refusal is an audited, denied `scim.role_map_refused` that reviewers of the audit log then have to explain. Rejected, as in ADR 0182.
- **Copy the rules into the console.** The console would need the permission sets and reach rules, and would drift from the server. Rejected: the server works the list out with the same function.
- **A separate `choices` route.** One more route to secure and keep in step; the lists are read together anyway.
- **Declare undeclared Google groups automatically.** The admin would no longer choose the role, and a listed group's role is exactly the decision SCIM leaves to an admin. Rejected; one click fills the form instead.

## Not done

- Changing a mapping's role in place (needs a `PATCH` like role groups have).
- These screens in the Expo client: SCIM stays in the admin-only console (ADR 0032).
