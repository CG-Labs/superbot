# Provision users and teams with SCIM (Entra ID, Okta)

Lets your IdP create SuperBot users when people are assigned the app, keep their name and email current, and disable them when they leave. Disabling ends their sessions at once. With `SCIM_GROUPS=on`, the groups it pushes become [teams](#groups-as-teams), and people join and leave them as the IdP says. With `SCIM_GROUP_ROLES=on` as well, an admin can [map a group to a custom role](#groups-to-roles), or declare it a [role group](#role-groups) that gives a role and isn't a team. The [Enterprise User extension](#enterprise-attributes) (employee number, department, manager, …) is kept for admins and access reviews. Tokens [expire and rotate](#token-expiry-and-rotation). Design: [ADR 0023](../adr/0023-scim.md), [ADR 0095](../adr/0095-scim-groups-as-teams.md), [ADR 0138](../adr/0138-scim-group-role-mapping.md), [ADR 0176](../adr/0176-scim-enterprise-user-extension.md), [ADR 0180](../adr/0180-scim-role-groups.md), [ADR 0196](../adr/0196-scim-token-expiry-and-rotation.md).

SCIM never gives anyone a role above `SCIM_DEFAULT_ROLE` (member, or readonly), never a team role, and never admin; admins promote people as before. The IdP can't name a role: only an admin's mapping can give one. [Bulk](#bulk) is supported, for clients that batch.

You need: SuperBot on HTTPS at a fixed address, like `https://superbot.example.com`, and an admin's `botctl` on the server. Below, replace `superbot.example.com` with yours.

## 1. Turn SCIM on

In `.env` (or `deploy/docker/.env`), then restart botd:

```sh
SCIM=on
# SCIM_DEFAULT_ROLE=member          # or readonly; admin is refused
# SCIM_GROUPS=on                    # pushed groups become teams (off by default)
# SCIM_GROUP_ROLES=on               # admins may map groups to custom roles, and declare role groups (off by default; needs SCIM_GROUPS=on)
```

botd logs `SCIM: on at /scim/v2` on start, whether groups are teams, and whether they can carry roles. Off, `/scim/v2` answers 404.

## 2. Make a token

Each IdP connection is a **tenant** with its own tokens. A tenant only sees the users it provisioned.

**Link SSO if people sign in with the same IdP** (recommended). Then the IdP's `externalId` is the person's SSO subject, and each provisioned user can sign in with SSO straight away, as one user, never matched by email. Use the provider id from `SSO_PROVIDERS` ([Entra](entra.md), [OIDC/Okta](oidc.md)):

```sh
export SUPERBOT_PASSWORD=<your AUTH_PASSWORD>      # or SUPERBOT_TOKEN from botctl login
botctl scim token create entra --sso entra --label "Entra provisioning"
# Docker: docker compose exec -e SUPERBOT_PASSWORD botd botctl scim token create entra --sso entra
```

It prints an `sbp_…` token **once**. Paste it into the IdP, then forget it. Leave out `--sso` if people sign in with codes, or are linked by hand. A tenant's first token fixes its SSO link; all its tokens share it. It expires in a year (`--days N` for 1 to 730); see [Token expiry and rotation](#token-expiry-and-rotation).

```sh
botctl scim tokens                                   # ids, tenants, last use, expiry and state; never values
botctl scim token rotate <id>                        # a new token; the old one works 24 more hours
botctl scim token revoke <id>                        # its users stay as they are
```

## Token expiry and rotation

A SCIM token can deactivate everyone its tenant provisioned, so it doesn't live forever; but when it stops, **deprovisioning stops** too, so its end is announced well before. Design: [ADR 0196](../adr/0196-scim-token-expiry-and-rotation.md).

- **New tokens expire**, a year after they're made by default (`--days N`, or `expiresInDays` on `POST /api/scim/tokens`, 1 to 730). An expired token gets 401, like a revoked one.
- **Rotate before then.** `botctl scim token rotate <id>` (or **Rotate** in the console's SCIM section, or `POST /api/scim/tokens/<id>/rotate`) prints a new token for the same tenant, label and SSO link, once. The old one keeps working for 24 hours (`--keep-old-hours N`, 0 to 168; 0 stops it now), never past its own end. Paste the new token into the IdP (Entra: **Admin Credentials → Secret Token**, then **Test Connection**; Okta: **Provisioning → Integration → Authorization**), then check `botctl scim tokens`: the new token's last use shows the IdP switched. A token rotates once.
- **Tokens from before this** have no end and keep working; they're listed as `no_expiry` ("Never (rotate it)" in the console). Rotate them to give them one.
- **Warnings.** 14 days before a token ends, botd audits `scim.token_expiring`, and when it ends, `scim.token_expired`, each once, with `tenantWorking` (whether the tenant still has a working token) and `tenantEndsAt` (when its provisioning stops if nobody acts; null when one of its tokens never expires). `botctl scim tokens` lists `expiringTenants`, tenants whose every working token ends within 14 days, the console says so above the token table, and the [health score](../support/health-score.md#identity)'s identity signal is **watch** while any tenant is in it. Alert on `scim.token_expiring` in your SIEM ([ADR 0122](../adr/0122-siem-export-and-tamper-evident-audit.md)). Rotated and revoked tokens end as planned, without either event.

| `state` | Meaning |
|---------|---------|
| `active` | Works; ends more than 14 days from now |
| `expiring` | Works; ends within 14 days. Rotate it |
| `rotated` | Replaced; works until its `expiresAt` (the overlap) |
| `expired` | Ended; 401 |
| `revoked` | Revoked; 401 |
| `no_expiry` | Made before tokens expired; works until rotated or revoked |

## 3a. Microsoft Entra ID

In the [Microsoft Entra admin center](https://entra.microsoft.com): **Identity → Applications → Enterprise applications**. Use the enterprise app of your SuperBot SSO registration, or **New application → Create your own application → Integrate any other application you don't find in the gallery (Non-gallery)**.

1. **Provisioning → Get started**, **Provisioning Mode: Automatic**.
2. **Admin Credentials**: **Tenant URL** `https://superbot.example.com/scim/v2`, **Secret Token** the `sbp_…` token. **Test Connection**, then **Save**.
3. **Mappings**:
   - **Provision Microsoft Entra ID Groups**: with `SCIM_GROUPS=on`, leave it **Yes** (keep `displayName → displayName`, `objectId → externalId`, `members → members`). Otherwise set **Enabled** to **No**.
   - **Provision Microsoft Entra ID Users**: if the tenant links SSO (`--sso`), edit the **externalId** mapping: source attribute **objectId** (the default, `mailNickname`, is refused). Keep `userPrincipalName → userName`, `mail → emails[type eq "work"].value`, `Switch([IsSoftDeleted], …) → active`, the name mappings, and the [enterprise ones](#enterprise-attributes) (`employeeId`, `department`, `companyName`, `manager`, …). Others are ignored.
4. **Settings → Scope: Sync only assigned users and groups**. Assign people under **Users and groups**.
5. **Provisioning Status: On**, **Save**. Entra syncs about every 40 minutes; **Provision on demand** does one person now.

Removing someone from the app, or disabling or deleting them in Entra, sets `active` to false: SuperBot disables them and ends their sessions. When Entra deletes them for good (30 days after a soft delete), it sends `DELETE`; SuperBot keeps the disabled user and its audit history.

## 3b. Okta

In the Okta Admin Console, open SuperBot's app integration (the OIDC app from [oidc.md](oidc.md), or a new **SWA**/**OIDC** app for provisioning only).

1. **General → App Settings → Edit → Provisioning: SCIM**, **Save**.
2. **Provisioning → Integration → Edit**:
   - **SCIM connector base URL**: `https://superbot.example.com/scim/v2`
   - **Unique identifier field for users**: `userName`
   - **Supported provisioning actions**: **Push New Users**, **Push Profile Updates**, and with `SCIM_GROUPS=on`, **Push Groups**. Leave **Import Groups** off.
   - **Authentication Mode**: **HTTP Header**, **Authorization**: the `sbp_…` token.
   - **Test Connector Configuration**, then **Save**.
3. **Provisioning → To App → Edit**: enable **Create Users**, **Update User Attributes**, **Deactivate Users**. **Save**.
4. **Assignments**: assign people or groups (groups here only choose who is provisioned).
5. With `SCIM_GROUPS=on`: **Push Groups → Push Groups → Find groups by name**, pick the groups to be teams, and **Save**. Okta creates each one, or links it to a team an admin linked by name (below).

Okta sends its user id (`00u…`) as `externalId`. That is the `sub` in Okta's ID tokens, so `--sso okta` (your OIDC provider's id, with the default `SSO_OKTA_SUBJECT_CLAIM=sub`) links each person's SSO identity. Okta's placeholder password is ignored. Unassigning or deactivating someone sets `active` to false; Okta never deletes users.

## Google Workspace

Google pushes SCIM only to apps in its own catalog, so botd reads the Workspace directory instead: set `GOOGLE_DIRECTORY_SYNC=on`, and a read-only service account provisions the people in the groups you choose through the same code as SCIM. Setup: [google-workspace.md](google-workspace.md) ([ADR 0162](../adr/0162-google-workspace-directory-sync.md)). A SCIM connector in front of Google works too; use `--sso` only with the provider whose subjects it sends as `externalId`.

## What happens

| IdP does | SuperBot does |
|----------|---------------|
| Creates a user | A new user with `SCIM_DEFAULT_ROLE`. With `--sso`, its SSO identity too. If an admin already linked that identity to a user, that user is taken on instead |
| Updates name, email, `userName` | Updates the user. Roles never change |
| Sets `active: false` | Disables the user, ends all sessions, closes open screens, and pauses the routines that run for them ([ADR 0047](../adr/0047-disabled-users-routines.md)). Stops every run and queued message on their Bots and the runs on others' Bots that are for them, ends those runs' Bot tokens, and suspends their machine (`MACHINE_ON_DISABLE`, [ADR 0124](../adr/0124-deprovisioning-stops-bots-and-machines.md)). Still listed, so the IdP can reactivate |
| Sets `active: true` | Enables the user, and resumes the machine their deactivation suspended. Their paused routines stay paused until an admin resumes them (`botctl user resume-routines`) or hands them over (`botctl user handover`), unless `ROUTINES_ON_ENABLE=resume` |
| Deletes (`DELETE`) | Disables the user, ends sessions, pauses their routines, stops their Bots' runs, and suspends their machine; the tenant no longer sees it. Nothing is destroyed. Provisioning the same `externalId` again brings back the same user, and their machine |
| Sends the Enterprise User extension | Kept and shown back, to admins and in the access review; never used to give access ([below](#enterprise-attributes)) |
| Sends `roles`, `groups` on a user, a password, `title`, phone numbers | Ignored |

**The IdP is in charge.** For users it provisioned, the IdP decides name, email, and `active`: an admin can disable one in SuperBot, but the IdP's next update can enable them again. Remove people in the IdP.

**One person, one user.** Email never matches people. If a SuperBot user already has the email, the IdP gets a 409: link that user's SSO identity (`botctl user link <user> <provider> <subject>`) and retry, or change one of the emails. The owner account is never managed by SCIM.

**Audit.** Every change is logged with the token as the actor: `botctl audit --method scim_token`, or `--actor system:scim:<token id>`. Each deactivation or deletion also records `user.deprovisioned`, with the Bots it stopped and what happened to the machine (`suspended`, `held` until it finishes building, `failed` and retried by the reconciler, `already_suspended`, `kept`, or `none`). Bad tokens are logged as `scim.auth_failed` (throttled), with `reason` `missing`, `unknown`, `revoked`, or `expired`; a revoked or expired token names which one (and `rotatedTo`, the token that replaced it), so you can find the IdP still sending it. Tokens are logged as `scim.token_created`, `scim.token_rotated` (with `oldEndsAt`), `scim.token_revoked`, `scim.token_expiring` and `scim.token_expired`. A request with a valid token that's refused or fails (not a 404) is logged as `scim.request_failed` with its `status`, `reason` (the `scimType` in snake case, such as `uniqueness` or `invalid_value`, or `status_<code>`), `method` and `resource`, never its body; the [customer health score](../support/health-score.md#identity) counts them. Tokens themselves never are logged.

## Enterprise attributes

SuperBot keeps the [Enterprise User extension](https://www.rfc-editor.org/rfc/rfc7643#section-4.3) (`urn:ietf:params:scim:schemas:extension:enterprise:2.0:User`) on the users a tenant provisions, and lists it in `/Schemas` and in the User resource type's `schemaExtensions`, so Entra's SCIM Validator (schema discovery) and Okta's profile editor find it. Design: [ADR 0176](../adr/0176-scim-enterprise-user-extension.md).

| Attribute | Entra's default source | Kept as |
|-----------|------------------------|---------|
| `employeeNumber` | `employeeId` | Text, up to 128 characters |
| `costCenter` | `employeeOrgData.costCenter` | Text |
| `organization` | `companyName` | Text |
| `division` | `employeeOrgData.division` | Text |
| `department` | `department` | Text |
| `manager` | `manager` | Another user **this tenant** provisioned, by their SuperBot id |

- **Every shape Entra and Okta send.** In a `POST` or `PUT`, the extension object under its URN. In a `PATCH`, the full path (`urn:…:enterprise:2.0:User:department`), the extension's URN with an object of attributes (only those sent change), a path-less `value` holding either, and the bare names Entra has sent (`manager`). `manager` takes `{"value": "<id>"}`, Entra's `[{"value": "<id>", "$ref": …}]`, or the id itself; `remove` clears an attribute. A `PUT` without the extension clears it, as RFC 7644 says a replace does.
- **A manager is someone else in the tenant.** A `manager` that isn't a live user of the same tenant (unknown, the person themselves, deleted, or another tenant's) is dropped, and the user is saved without one. It is never refused, so a deactivation that carries a stale manager still goes through. Entra sends the manager once both people exist. A manager the tenant later deletes is no longer shown; the next write clears it.
- **Shown, never used for access.** The attributes come back on every SCIM read, with `manager.displayName` and `$ref`. Admins see `department`, `employeeNumber` and `manager` on each person in the [access review](../adr/0099-access-review-report.md) (`scim_department` and `scim_manager` in its CSV), to route each person to their manager for sign-off. They aren't in the report's digest, so a department change doesn't make a signed-off review stale. No role, team, Bot or machine depends on them.
- **Audited.** A change is in `user.updated`'s `changes`, like a name.
- **Google Workspace** fills `employeeNumber` (the `organization` external id), `organization`, `department` and `costCenter` from the person's primary organization, and `manager` from their `manager` relation, once the manager has an account too ([guide](google-workspace.md)).

## Groups as teams

With `SCIM_GROUPS=on`, each group the IdP pushes is a SuperBot [team](../adr/0087-team-accounts-and-machines.md): its members share Bots, get the team's machines, and are on its plan if it pays ([ADR 0093](../adr/0093-team-billing.md)).

| IdP does | SuperBot does |
|----------|---------------|
| Creates a group | A new team with that name, **no owner and no machines**. Give it an owner (`PUT /api/teams/<id>/members/<user> {"role":"owner"}`, or the console's Teams tab) and turn machines on (`PATCH /api/teams/<id> {"machines":true}`) |
| Adds a member | They join as a plain member, exactly as a team admin's add: the team's machine, its plan, and the seat sync. Disabled people join too, without a machine, and get the team's when they're enabled |
| Removes a member | They leave as a team admin's removal would: grants between teammates go, they're removed from teammates' machines and accounts, their team machine is suspended and destroyed after `TEAM_MACHINE_DAYS`, and the seat sync runs. Even the team's last owner (logged as `ownerless`) |
| Renames the group | Renames the team |
| Deletes the group | Its members leave, as above. A team the IdP made, left empty, is deleted, unless it pays for a plan; a team an admin linked, or one with people the IdP doesn't manage, stays, managed by hand again |
| Deletes a user | They also leave the team their group put them on |

**Only its own people.** A group holds only people this tenant provisioned. Adding anyone else is a 400. People on the team the tenant doesn't manage are never shown or removed. Someone on another team is a 409: a person is on one team at most, and SCIM never moves them; take them out of the other group first.

**Never a team role.** Everyone joins as `member`. Owners and admins are set in SuperBot, not the IdP.

**Teams made by hand** are invisible to SCIM until an admin links one to a tenant:

```sh
botctl scim group link entra <team id> --external-id <Entra group objectId>   # Entra
botctl scim group link okta <team id> --name "Sales"                          # Okta, by group name
botctl scim groups                                                            # links, their teams, and counts
botctl scim group unlink <team id>                                            # managed by hand again; nobody leaves
```

The IdP takes the team on when it pushes the group with that `externalId` (or, without one, that name), and then manages the tenant's people on it. Its owner and anyone else stay.

**Audit.** `scim.group_created`, `scim.group_adopted`, `scim.group_resumed` (a retried `POST` that had stopped partway), `scim.group_updated` (with `added`, `removed`, `ownerless`), `scim.group_deleted` (with `teamFate`), `scim.group_member_refused`, `scim.group_linked`, `scim.group_unlinked`, and each join and leave as `team.member_joined` (via `scim`) and `team.member_left` (reason `scim`), with the token as the actor.

## Bulk

`POST /scim/v2/Bulk` ([RFC 7644 section 3.7](https://www.rfc-editor.org/rfc/rfc7644#section-3.7)) sends many user and group changes in one request. Entra ID and Okta don't use it; other SCIM clients, connectors and sync scripts can. Design: [ADR 0153](../adr/0153-scim-bulk.md).

```json
{
  "schemas": ["urn:ietf:params:scim:api:messages:2.0:BulkRequest"],
  "failOnErrors": 1,
  "Operations": [
    { "method": "POST", "path": "/Users", "bulkId": "ada", "data": { "userName": "ada@example.com", "externalId": "00u1" } },
    { "method": "POST", "path": "/Groups", "bulkId": "eng", "data": { "displayName": "Eng", "members": [{ "value": "bulkId:ada" }] } },
    { "method": "PATCH", "path": "/Users/<id>", "data": { "Operations": [{ "op": "replace", "path": "active", "value": false }] } },
    { "method": "DELETE", "path": "/Users/<id>" }
  ]
}
```

**Each operation is its own request.** It goes through exactly what `POST /Users`, `PATCH /Groups/<id>` and the rest would do, with the same token: the same checks, the same tenant (another tenant's user or group is 404), the same deprovisioning when someone is deactivated or deleted, and the same audit events. Group operations need `SCIM_GROUPS=on`, as without Bulk.

**What runs, and in what order.**

- First the whole request is checked: `Operations` a list of at most 100; each `method` `POST`, `PUT`, `PATCH` or `DELETE`; each `path` `/Users` or `/Groups` for a `POST`, `/Users/<id>` or `/Groups/<id>` otherwise; a `bulkId` on every `POST`, each used once; `data` on all but `DELETE`; `failOnErrors` a whole number of at least 1. Any problem is a 400 naming the operation (`Operations[3]: ...`), and nothing runs.
- Then the operations run one at a time, in the order sent. The `POST` with a `bulkId` runs just before the first operation that uses `bulkId:<id>` (in its path, in its data such as a group member, or in a PATCH filter such as `members[value eq "bulkId:<id>"]`), so a group can list a user created later in the same request. Nothing else is reordered, so writes sent after that operation still run after it.
- Every operation is tried, whatever the others do. With `failOnErrors: n`, processing stops once `n` have failed. Nothing that worked is undone.
- A reference to a `bulkId` that no `POST` in the request has, to a `POST` that failed, or a circle of references fails that operation with 409, without running it.

**The answer** is 200 with a `BulkResponse` whenever the request was read, even if every operation failed, so read each one's `status`: what its own request would have answered (`201`, `200`, `204`, `404`, ...). Results are in the order the operations ran; any not listed weren't run. Each has its `method`, `bulkId` (if sent), `status`, `location` (except a failed `POST`), and, on failure, `response` with the SCIM error.

**Audit.** Each operation logs what its own request would, including `scim.request_failed` when it fails with anything but a 404 or a 429, so failed operations count in the health score though the Bulk request itself is 200. The whole request is also `scim.bulk`, with how many operations were sent, run and failed, why it stopped (`failOnErrors`, `rateLimited`), and each operation's method, path, `bulkId` and status.

## Groups to roles

With `SCIM_GROUP_ROLES=on` (and `SCIM_GROUPS=on`), an admin maps a tenant's group to a [custom role](../adr/0123-custom-roles.md). The group's members hold the role while they are in it: SCIM adding someone gives it, and their leaving the team, however they leave, takes it away. The IdP only says who is in the group; the role is always the admin's choice. Design: [ADR 0138](../adr/0138-scim-group-role-mapping.md).

```sh
botctl roles                                       # custom roles; make one with botctl role add
botctl scim groups                                 # groups, and the team id each one is
botctl scim role map <team id> "Support Lead"      # within the group's team (only its team permissions apply)
botctl scim role map <team id> Auditor --org       # across the server
botctl scim role-mappings                          # every mapping, how many people it gave the role to
botctl scim role show <mapping id>                 # who holds it through the mapping
botctl scim role unmap <mapping id>                # takes it back from them; roles given by hand stay
```

The console's SCIM section lists the mappings and removes them. Or the admin API: `GET`/`POST /api/scim/role-mappings` (`{"team": "<id>", "role": "<id or name>", "scope": "team" | "org"}`, team by default), `GET`/`DELETE /api/scim/role-mappings/<id>`.

A group has at most one role in its team and one across the server. Mapping it gives the role to the members it has now, and the response lists who got it and who was skipped, and why.

**Never admin.** A mapping is refused (400, audited as `scim.role_map_refused`) for `admin`, for a built-in role, and for any role whose permissions act on admins: across the server, `bots.manage` (anyone's Bots and routines) and `machines.manage` (anyone's machine); within a team, `machines.manage` (the team's machines, its owners' too). Other permissions keep their holders away from admins ([limits on delegates](../adr/0123-custom-roles.md#limits-on-delegates)). A mapped role can't gain those permissions later (409), nor be deleted while mapped (409).

**Only what it gave.** A mapping never changes:

- an admin or the owner account (across the server);
- anyone who holds a custom role already in that scope, given by hand or by another mapping;
- a read-only person (within a team: read-only people change nothing there).

Each skip is audited as `scim.role_skipped`. Taking a role away clears only one the mapping gave and nobody has changed since: an admin giving, changing or taking away that person's role by hand, or setting their built-in role, makes it theirs, and the mapping lets it be. Across the server, losing the role puts back the built-in role they had before (a read-only person the role made a member is read-only again).

**When it's taken away.** When they leave the group (by SCIM, by a team admin's removal, or a SCIM `DELETE` of the user), when the mapping is removed, and when the group goes (the IdP deletes it, or an admin unlinks it). Turning `SCIM_GROUP_ROLES` off stops new grants and new mappings; leaving still takes away what mappings gave, and a SCIM `DELETE` of the user takes away every mapped role they hold even with `SCIM_GROUPS` off.

**Audit.** `scim.role_mapped`, `scim.role_unmapped` (reason `mapping_removed` or `group_removed`, with who lost the role), `scim.role_map_refused`, `scim.role_skipped`, and each grant as `role.assigned` and `role.unassigned` with `via: "scim"`, the mapping, the tenant and (for team roles) the team, and a reason when taken away (`left_group`, `user_deleted`, `mapping_removed`, `group_removed`). A change of built-in role is `user.role_changed` (reason `scim_group`), with the same offboarding as any other change of role. A join's grant has the SCIM token as its actor; a mapping's, the admin.

## Role groups

Every group the IdP pushes is a team, and a person is on one team at most, so a group that only says who holds a role ("SuperBot Auditors", "Billing admins") can't be pushed next to the team groups its people are in: SCIM answers 409. Declare such a group a **role group** first. When the IdP pushes it, it isn't a team: anyone the tenant provisioned can be in it, and in any number of role groups, whatever team they're on. Its members hold its custom role across the server while they're in it. Needs `SCIM_GROUP_ROLES=on` (and `SCIM_GROUPS=on`). Design: [ADR 0180](../adr/0180-scim-role-groups.md).

```sh
botctl scim role-group add entra "SuperBot Auditors" Auditor           # by the name the IdP pushes
botctl scim role-group add entra Auditors Auditor --external-id <id>   # or by its externalId (Entra: the group's object id)
botctl scim role-groups                                                 # each one, waiting or pushed, and how many hold its role
botctl scim role-group show <id>                                        # members, and who holds the role through it
botctl scim role-group set-role <id> "Read-only auditor"                # gives another role: the old one goes, the new one is given
botctl scim role-group remove <id>                                      # takes its role back; roles given by hand stay
```

Declare the group before the IdP pushes it. A declaration waits, unseen by the IdP, until it sends a `POST /Groups` with that `externalId` (or, for a declaration without one, that `displayName`, any ASCII case); that group then becomes the role group, with the members it sent. A group that is a team already can't be declared (409): delete it in the IdP, or take it out of provisioning, then declare it and push it again. A tenant's team groups and role groups share names and `externalId`s, so neither can take one the other has. If your IdP sends no `externalId` for groups, declare by name.

The console's SCIM section lists role groups next to the mappings and removes them. Or the admin API: `GET`/`POST /api/scim/role-groups` (`{"tenant": "...", "displayName": "...", "externalId"?: "...", "role": "<id or name>"}`), `GET`/`PATCH` (`{"role": ...}`)/`DELETE /api/scim/role-groups/<id>`.

**One role each.** A person holds one custom role across the server. The oldest role group they're in (by when it was declared) that can give them one does; when it stops (they leave it, it's removed, or its role changes), the next role group they're in is offered. A role group follows the same rules as a [mapping](#groups-to-roles): never admin, a built-in role, or a role that acts on admins (400, `scim.role_map_refused` with `kind: "role_group"`); never over an admin, the owner account, or a custom role they hold already (by hand, a mapping, or another role group), each skip audited as `scim.role_skipped`; only what it gave is taken back, and a role given or changed by hand ends its claim. Losing it puts back the built-in role they had. Its role can't gain permissions that act on admins (409), nor be deleted (409), while a role group gives it.

**When it's taken away.** When they leave the group (by SCIM, or a SCIM `DELETE` of the user), when an admin removes the role group or gives it another role, and when the IdP deletes the group. An IdP `DELETE` empties the group and puts its declaration back to waiting, so pushing it again makes it a role group again, never a team. Removing the declaration (`botctl scim role-group remove`) ends it for good: if the IdP still pushes the group, its next `POST` makes it a team, so take it out of provisioning first. With `SCIM_GROUP_ROLES` off, a declared group the IdP pushes is still a role group, but gives nothing; leaving still takes away what it gave.

**Audit.** `scim.role_group_declared`, `scim.role_group_adopted` (the IdP pushed it), `scim.role_group_changed`, `scim.role_group_removed` (`wasPushed`), `scim.group_updated` and `scim.group_deleted` with `kind: "role"`, and each grant as `role.assigned` / `role.unassigned` with `via: "scim"`, `roleGroup`, `tenant` and a reason when taken away (`left_group`, `user_deleted`, `group_removed`, `role_group_removed`, `role_changed`). The target type is `scim_role_group`.

## Limits

600 requests a minute per tenant, then 429 with `Retry-After` (Entra and Okta wait and retry). An IP sending 20 bad tokens in 10 minutes gets 429 for its bad tokens for a while; a valid token from that IP still works, since Entra and Okta send from addresses they share with other customers. Bodies are capped at 64 KiB, or 1 MiB for groups (a `PUT` carries every member). Lists return at most 200 users or groups per page. No groups in groups.

Bulk: at most 100 operations (`maxOperations`) and 1 MiB (`maxPayloadSize`) a request, both in `ServiceProviderConfig`; more is a 413 and nothing runs. Each operation's `data` keeps its own request's cap (64 KiB for a user, 1 MiB for a group), and each operation after the first counts against the 600 a minute: one over it gets a 429 result, and the rest of the request isn't run.

## Troubleshooting

- **404 on every request**: `SCIM=on` isn't set, or botd wasn't restarted.
- **401**: the token is wrong, revoked, or expired (`botctl audit --action scim.auth_failed` says which). Make a new one, or rotate a working one; check the IdP sends `Authorization: Bearer sbp_…`.
- **401 just after a rotation**: the overlap ended before the IdP got the new token. Paste the new one into the IdP; if it's lost, rotate again (rotate the new token, which still works) or make one with `botctl scim token create`.
- **403 "Unknown Host"**: add the public hostname to `ALLOWED_HOSTS` (Compose adds `SUPERBOT_DOMAIN`).
- **400 "externalId is required" or "externalId: …"**: the tenant links SSO, and the IdP didn't send the person's subject. Entra: map **objectId** to **externalId**.
- **409 "Another SuperBot user has this email"**: see *One person, one user* above.
- **409 on a user that exists**: the IdP is creating someone this tenant already has. Entra and Okta look the user up first and then update instead; check the matching attribute is `userName`.
- **Group errors (501)**: `SCIM_GROUPS=on` isn't set. Set it, or turn group provisioning off in the IdP.
- **409 "Mapping SCIM groups to roles is off"**: set `SCIM_GROUP_ROLES=on` (with `SCIM_GROUPS=on`) and restart botd.
- **A member didn't get the mapped role**: `botctl audit --action scim.role_skipped` says why (`admin`, `owner`, `has_role`, `readonly`, `not_on_team`).
- **409 on adding a group member**: they're on another team. Take them out of that group (or team) first. If the group only says who holds a role, declare it a [role group](#role-groups) instead.
- **A role group member didn't get its role**: `botctl audit --action scim.role_skipped` says why (`has_role` means another role group, a mapping or an admin gave them one first).
- **A group meant as a role group became a team**: it was pushed before it was declared, or its declaration was removed. Delete it in the IdP, declare it, and push it again.
- **400 "isn't a user this tenant provisioned"**: provision the user before the group, or check the IdP sends the user's SuperBot id (it does once it has provisioned them).
- **Bulk 200, but nothing changed**: read each operation's `status` and `response`; a 200 only means the request was read.
- **Bulk 413**: more than 100 operations or 1 MiB. Split the request.
- **Bulk 409 "bulkId:…"**: the operation names a `bulkId` no `POST` in the same request has, or whose `POST` failed.
- **A manager doesn't show**: the manager isn't a user this tenant has provisioned (yet). Provision them, then use **Provision on demand** for the person (Entra) or push their profile again (Okta).
- **409 creating a group**: this tenant already has a group with that name or `externalId`. Names are unique per tenant in any ASCII case (`Eng` and `ENG` clash; `Équipe` and `éQUIPE` don't).
