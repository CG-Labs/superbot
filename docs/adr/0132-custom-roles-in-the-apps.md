# 0132: Custom roles in the apps and botctl

## Status

Accepted (22 Nov 2026). Second slice of [#53](https://github.com/CG-Labs/superbot/issues/53) (M5, "Advanced RBAC"), on top of [ADR 0123](0123-custom-roles.md) (custom roles from fixed permissions). Follows [ADR 0021](0021-admin-portal.md) (the admin portal in the app) and [ADR 0032](0032-console-admin-only.md) (the admin-only console).

## Context

ADR 0123 put custom roles on the server: `/api/roles`, the fixed permission set, and the limits on delegates. It left the editor in the apps and `botctl role` commands for later, so admins built roles with `curl`. Admins need to see a role and what it adds up to before giving it, and to see what each person can do once they have one.

## Decision

### Where roles are managed

- **The app** (`/app/`, admins only) gets a **Roles** screen next to Users: built-in roles as read-only presets, custom roles with their base, permissions and holders, an editor (name, description, base, the fixed permissions as checkboxes), and giving and taking away across the server and within a team. A person's panel in **Users** gets a custom role picker and the list of what they can do.
- **The console** (`/console/`) gets a **Roles** tab with the same editor and holders, a **Custom role** column in **Users**, and a **Custom role here** column on each team's members in **Teams**.
- **`botctl`** gets `botctl roles` and `botctl role show | add | edit | rm | assign | unassign` (`--team` for within a team).

All three call the ADR 0123 API and nothing else; the server still checks every name, base, permission and limit. The editors only offer the permissions `GET /api/roles` lists, so a newer server's permissions show up without a client release, and a stored name the server doesn't know is shown as granting nothing and dropped on save.

### Effective permissions come from the server

Admin user views (`GET /api/users`, `GET /api/users/:id`) add `permissions`: what the person can do across the server, their built-in role's permissions plus their custom role's, the same list `GET /api/auth/me` gives them. The apps show it as is rather than working it out, so they can't drift from `rbac::granted`.

While editing a role, the editor previews what it would add up to from `GET /api/roles` (the base's preset from `builtIn`, then the checked permissions), which is how the server builds `effective`; the saved role's `effective` is the server's. Within a team, the apps show the role's permissions that the catalogue marks `team: true`.

### Confirmations

The apps ask before what silently changes someone's access: giving a custom role to an admin (they stop being one), and changing the base of a role people hold (they all move at once), taking a role away (they keep its base as a built-in role), and setting a built-in role for someone with a custom role (it clears the custom role). Deleting is offered only once nobody holds the role, as the server refuses it (409) otherwise.

## Alternatives considered

- **Work out effective permissions in the apps for each person.** They would need the matrix in `rbac::allows` copied into TypeScript and JavaScript, and would show the wrong thing after a server change. One field on admin user views is cheaper and always right.
- **A roles editor only in the app, with the console linking to it.** The console is the break-glass page and works with no app build, so it keeps a full editor.
- **Picking team members by email in a text field.** Team members are a short known list; the editors offer them from `GET /api/teams` instead, and the app says when a read-only member would get nothing.

## Consequences

- Admins can build, change, give and delete custom roles in either app or from a shell, and see what each person can do, without the API.
- `permissions` on admin user views is part of the API.
- Still to do for #53: SCIM group-to-role mapping and service accounts.
