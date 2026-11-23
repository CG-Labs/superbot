# 0176: The SCIM Enterprise User extension

## Status

Accepted (23 Nov 2026). Part of SCIM provisioning in M5, [#51](https://github.com/CG-Labs/superbot/issues/51). Builds on the SCIM stub and its review ([ADR 0023](0023-scim.md), [ADR 0026](0026-scim-review-hardening.md)), Bulk ([ADR 0153](0153-scim-bulk.md)), the Google Workspace sync ([ADR 0162](0162-google-workspace-directory-sync.md)), and the access-review report ([ADR 0099](0099-access-review-report.md)).

## Context

SuperBot kept only the core User schema. Everything else a client sent was accepted and dropped, including the Enterprise User extension (RFC 7643 section 4.3: `employeeNumber`, `costCenter`, `organization`, `division`, `department`, `manager`). That caused three problems:

- **Entra ID maps it by default.** A new non-gallery app's user mappings include `employeeId`, `department`, `companyName` and `manager`. Entra's SCIM Validator, in its "default attributes" mode, adds attributes with `PATCH` and expects to read them back by the joining property. Dropped attributes fail that test. With schema discovery, `/Schemas` didn't list the extension at all, so admins couldn't tell it was unsupported rather than broken.
- **Reviewers route by manager.** The usual SOC 2 access review (CC6.2, CC6.3) sends each person's access to their manager to confirm. The access-review report grouped people by tenant and team but had no manager or department. Reviewers had to join it with an HR export by hand.
- **Google had the data too.** The Directory API returns each person's organizations, external ids and relations, and the sync threw them away.

## Decision

### Kept on the SCIM user, read and written through SCIM

Six nullable columns on `scim_users`: `employee_number`, `cost_center`, `organization`, `division`, `department`, and `manager_id` (one migration, appended to the list). The handlers parse, store and render them with the rest of the user, so Bulk and the Google sync get them for free.

- **Discovery.** `/Schemas` lists the extension's schema (`/Schemas/urn:ietf:params:scim:schemas:extension:enterprise:2.0:User`). The User resource type has `schemaExtensions: [{schema, required: false}]`. `manager.$ref` and `manager.displayName` are `readOnly`.
- **Reads.** A user with any of them set lists the extension's URN in `schemas` and carries the object under that URN. `manager` is `{value, $ref, displayName}`. A user with none set looks exactly as before.
- **POST and PUT.** The extension object under its URN. A `PUT` without it clears it. That is RFC 7644's replace. Unlike `externalId` and `active`, which a `PUT` keeps when left out because Okta leaves them out, nothing has relied on these being kept.
- **PATCH.** Entra's SCIM documentation shows paths with the URN (`urn:…:User:manager`) and without it (`manager`), and `manager` values as an object, a list of one, or a plain id. botd accepts:
  - the full path;
  - the extension's URN with an object (only the attributes sent change);
  - a path-less `value` holding either form;
  - the bare names, which collide with nothing in the core schema.

  `remove` clears an attribute, or all of them for the URN. Strings are trimmed, refused with control characters, and capped at 128 characters (Entra's longest source, `department`, is 64). Errors are `invalidValue`, like any other attribute's.

### A manager is someone else in the tenant, or nobody

`manager.value` is the manager's SCIM `id`, which is their SuperBot user id. The write keeps it only if it names a live user of the **same tenant** who isn't the person themselves. That check is a subquery in the same statement as the write, so a manager deleted concurrently can't be kept. Anything else is stored as no manager:

- **Dropped, never refused.** A `PUT` or `PATCH` that deactivates someone often carries the rest of their profile. Refusing a stale manager would block the deprovisioning that matters most. Entra exports a reference only once both people exist, so a dropped manager is rare. The troubleshooting guide covers it.
- **Never another tenant's user, never a guess.** The id is checked against the tenant, so one tenant can't point at, or learn about, another's users (the same rule as group members, ADR 0095). Nothing is matched by email.
- **Reads hide a manager who has gone.** No foreign key is used, because a SCIM `DELETE` keeps the user. The read joins the manager live in the same tenant, so a deleted manager is no longer shown. The next write of that person clears the stale id, since the attributes it starts from no longer carry it.

### Shown to reviewers, never used for access

The access review's JSON shows each SCIM person's `department`, `employeeNumber` and `manager` (`{id, name}`). The CSV adds `scim_department` and `scim_manager` before `kind`. They are **not** in the report's digest. The digest is what a sign-off is bound to, and it moves only when access changes. A reorganisation that changes departments grants nothing, so it shouldn't make a signed-off review stale.

Nothing else reads these attributes: no role, team, Bot, machine, plan or residency rule depends on them. ADR 0138's group mappings stay the only way the IdP influences a role. Keying access on free-text HR fields an IdP admin can type would bypass that review.

### Audited like a name

A change is a key in `user.updated`'s `changes` (`department`, `manager` with user ids, …), with the token as the actor. These are work attributes the IdP already sends. No new event is added, and nothing goes in metrics.

### Google Workspace fills them

The sync asks the Directory API for `organizations(primary,name,department,costCenter)`, `externalIds(type,value)` and `relations(type,value)`. From these it takes:

- the primary organization (or the first) for `organization` (its name), `department` and `costCenter`;
- the `organization` external id for `employeeNumber`;
- the `manager` relation's email for `manager`.

The manager is resolved through the snapshot, from email to Directory id to the tenant's user, never by matching SuperBot users' emails. It is sent only once the manager has an account here. A manager made in the same pass is set on the next pass, as the plan's no-op comparison already handles. Divisions have no Directory field and stay empty.

## Consequences

- Entra's and Okta's default enterprise mappings round-trip, and the validator's add-and-read-back tests pass for them. `/Schemas` tells clients exactly what is kept.
- Reviewers can sort the access review by manager or department without an HR export, and a reorganisation doesn't void a sign-off.
- A manager outside the tenant, or one sent before they're provisioned, silently doesn't appear. The guide says how to resend.
- Six more columns of personal data per provisioned user, now listed in the [data flows](../security/data-flows.md#identity-providers-scim-inbound). Erasing a user ([ADR 0102](0102-erasing-a-users-data.md)) deletes their `scim_users` row with these attributes, and clears them as anyone's manager.

## Alternatives considered

- **Refuse an unknown manager (400).** Truer to "the value must be a resource id", but it would block a deactivation that carries one. Deprovisioning wins.
- **Store the manager as sent, unresolved.** That would show ids from other tenants, or nothing useful, and one tenant could probe for another's ids.
- **A JSON blob of every unknown attribute.** It would keep `title`, phone numbers and addresses too, with no schema to advertise and no limit on what's kept. The extension is standard, small, and what reviewers use.
- **Put department and manager in the access-review digest.** Every HR change would void sign-offs, which teaches reviewers to re-sign without looking.
- **Map Entra's `title`, Okta's custom attributes, or Google's custom schemas.** These are outside the standard extension. They can be added later the same way if customers ask.

## Not done

- Filtering on extension attributes (`urn:…:employeeNumber eq "…"`). Entra and Okta match on `userName` or `externalId`.
- Showing the attributes in the console's Users tab and the app (the access review and SCIM reads have them).
- A reviewer workflow that sends each manager their reports' rows.
