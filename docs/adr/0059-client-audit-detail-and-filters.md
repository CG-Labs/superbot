# 0059: Audit log detail and filters in the client

## Status

Accepted (21 Nov 2026). Approvals follow-up 5 ([list](../approvals-followups.md), tracking issue [#13](https://github.com/CG-Labs/superbot/issues/13), M1). Extends the client's audit log ([ADR 0028](0028-client-admin-console-link-and-audit.md)) over the audit API ([ADR 0009](0009-audit-events.md), [ADR 0019](0019-audit-actors.md)). The Expo client is the primary interface ([ADR 0027](0027-expo-primary-hermes-default.md)).

## Context

ADR 0028 gave the client the console's audit view: action, who, person, sign-in method, outcome, dates, paging, and CSV export. Admins still couldn't answer the questions approvals raise from their phone:

- **Which Bot?** The API filters by `bot`, the client didn't.
- **Who approved what?** Approval decisions are three actions (`approval.approved`, `approval.denied`, `approval.expired`). Typing them is error-prone on a phone.
- **What else did that sign-in, or that Bot's owner, do?** The API filters by `session` and `onBehalfOf`; the client didn't.
- **The whole event.** Rows showed one clipped line of details, and a tap only added a few lines more.

## Decisions

### Filters

- **Kinds of action** are presets for the Action field: Approval decisions, Approvals and policy, Sign-ins, Bots and runs, Routines, Users and sign-ups, Machines, Secrets. Picking one writes its comma-separated list (`approval.approved,approval.denied,approval.expired`) into the field, so what's sent is always on screen and can be edited. The server ORs the list, so a separate "kind" filter would need a second, ANDed parameter the API doesn't have. Typing anything else unselects the preset.
- **Bot**: chips of the Bots the admin sees, sorted by name, sent as `bot=<id>` ("about this Bot", whoever acted). A Bot from a link that isn't in the list (deleted, say) still gets a chip with its id.
- **On behalf of** (email or id) and **Session** (id): text fields, sent as `onBehalfOf` and `session`.

No server change: these parameters already exist. A server test pins the exact query the client sends for "Approval decisions" with a Bot, in the list and the CSV.

### Event detail

Tapping a row opens the whole event: a side pane on wide screens (900 px and up, like Users), a full-screen sheet on phones. It shows:

- every field, labelled: local and UTC time, who and how they signed in, user or Bot id, email, role, IdP and subject, session, on behalf of, the Bot it's about, target, IP, user agent, event id;
- for approval decisions, the verdict (approved, approved for the rest of the run, denied, expired) and the call, tool, kind, note, run scope, and the rule it saved;
- details as indented JSON, selectable;
- **Copy event** (web) or **Share event** (phones, the share sheet, as elsewhere in the client), the event as the API sent it.

### Following an event

The detail offers "Only `<action>`", "Everything by `<person>`", "Everything about `<Bot>`" (the Bot it's about, and the acting Bot), "Everything in this session", and "Everything done for `<person>`". Each starts a **fresh** filter rather than narrowing the current one: following a session from a denied approval should show the whole session, not only its denials. Clear filters and the fields stay available to narrow it again.

### Links

`/audit?bot=<id>` (also `person`, `session`, `onBehalfOf`, `action`) opens the log filtered, filters shown. Bot details have an admin-only **Approvals and changes in the audit log** link that uses it. Other query parameters are ignored, and the server validates whatever arrives.

### Smaller

- Pull to refresh reloads the filter on screen.
- **Load more** shows "Loading…" and can't be pressed twice, so a slow page isn't requested again.

### Who

Unchanged from ADR 0028: admins only, from `me.permissions`. Non-admins don't get the sidebar entry, the Bot details link, or the screen, and the server refuses both audit routes to them (`rbac.rs`, and the new test).

## Consequences

- An admin on a phone can go from a Bot to its approval decisions, open one, see who decided it and how they signed in, and follow that session, then share the CSV.
- Bot chips grow with the number of Bots. Fine at team sizes; a searchable picker can replace them if an install has hundreds.
- The detail is built from the loaded row; there is no `GET /api/audit/<id>`. Links to one event can come with it if needed.

## Alternatives considered

- **A separate kind filter, ANDed with Action.** Needs a new API parameter for little gain: the preset-in-the-field approach does the same with one.
- **Narrowing pivots** (add to the current filter). Surprising during an investigation; the fields already let an admin narrow by hand.
- **Inline expand, as before.** Long details and the decision don't fit a list row on a phone, and it can't hold the follow-up actions.
