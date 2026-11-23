# 0184: botd's own data region

## Status

Accepted (23 Nov 2026). The sixth slice of [#58](https://github.com/CG-Labs/superbot/issues/58) (M5, "Contractual data residency"). Builds on [ADR 0129](0129-contractual-data-residency.md) (residency pins), [ADR 0155](0155-residency-reports.md) (residency reports), [ADR 0168](0168-residency-in-the-app.md) (residency in the app), [ADR 0171](0171-residency-startup-and-leavers.md) (refusing startup) and [ADR 0109](0109-server-backups-off-the-host.md) (server backups off the host). 0184 was reserved for this work.

## Context

A residency pin holds a person's machine and its backups to a region. It has never covered botd's own data: the database (accounts, chats, routines, sealed secrets, the audit log), the files beside it, and the server's backups. Those are wherever the operator runs botd. ADR 0129 listed this as a follow-up: "a data region for botd's own database and server backups, or a documented dedicated deployment per region".

That gap matters most. Chats are the content a residency customer cares about, and they are in botd's database, not on the machine. Today:

- the residency report says, for every pin, that botd's own data isn't covered, even on a server that runs in London with its backups in London;
- the DPA annex asks the Provider to write where the server is by hand, with nothing in the product to back it;
- nothing stops an operator who runs botd in London from pinning a customer to Frankfurt, which promises machines in Frankfurt while their chats stay in London.

botd can't see where its own disk is. It can see where server backups go, since it copies them (ADR 0109), and which store settings name them.

## Options

1. **Split botd's database by region**, with each pinned tenant's rows in a database in its region. A large change to every query, backups and the audit chain, and the server process still handles the data wherever it runs. Not now.
2. **A dedicated botd per region**, nothing new in the product. Already possible (one install per region, each with its own `MACHINE_REGIONS`), but the product can't say so: reports still list botd's data as not covered, and nothing stops a pin to the wrong region.
3. **The operator states botd's region; botd shows it, and can hold pins to it** (chosen). Makes option 2 something botd checks and reports, and gives a single-region server a full answer, with no new infrastructure.

## Decision

### Settings

- `SERVER_DATA_REGION=<region>`: the data region botd's database, files and on-host server backups (`BACKUP_DIR`) are in. One of `MACHINE_REGIONS` when there are any, else any region id. Unset: not stated.
- `SERVER_BACKUP_S3_DATA_REGION=<region>`: the region of the server backups' own store (`SERVER_BACKUP_S3_BUCKET`), like `MACHINE_BACKUP_S3_DATA_REGION` for machine backups. Refused without that bucket. When server backups go to the machine backups' store, `MACHINE_BACKUP_S3_DATA_REGION` says where it is. With no off-host copies, archives stay on botd's host, so they are where botd is.
- `RESIDENCY_SERVER_DATA=report|require` (default `report`).

All three are the operator's statement, as a host's `INCUS_REGION` tag is. botd logs them at startup.

### When botd's own data is in a region

botd's own data is in a pin's region when `SERVER_DATA_REGION` is that region and server backups' off-host copies, if any, go to a store said to be there. Otherwise each reason is named: the region isn't stated, botd is in another region, or the copies go to a store in another region or none.

Copies made earlier to a store botd no longer copies to (the store was changed) aren't deleted by botd and their region isn't known. They are counted and shown as a warning in reports and, while there are pins, in `GET /api/regions` and the startup log, without the store's address. They don't make a pin unkept, since nothing in botd can clear them; the operator deletes them in the old store.

### `report` (the default)

botd shows where its own data is and changes nothing else:

- the residency report has a `serverData` section: the stated region, where server backups are copied, the policy, whether it is in the pin's region and why not, and the count of earlier copies. Its Markdown has a "botd's own data" section. The "not covered" list names botd's own data, with why, only when it isn't in the pin's region. The report's `status` is unchanged: it is about the pin's people's data;
- `GET /api/me/residency` has `serverData: {region, inRegion, backupsInRegion, required}`, and the app's residency card says whether SuperBot's own copy of their account and chats is in the region, or that it is but its backups aren't;
- `GET /api/regions` has `residency.serverData`: the region, the copies' store, the policy and earlier copies.

### `require`

Every pin on the server is held to botd's own region. This is the "dedicated deployment per region" model, checked by botd:

- botd refuses to start unless `SERVER_DATA_REGION` is set and server backups' off-host copies, if any, go to a store in it;
- a pin to another region is refused (409, `user.residency_pin_refused` or `team.residency_pin_refused`, reason `server_data_outside`), after the region-ready check;
- a pin made to another region before (before `require`, or before `SERVER_DATA_REGION` changed) is one botd can't keep: it is warned about at startup and in `GET /api/regions`, refuses startup under `RESIDENCY_STARTUP=refuse` (ADR 0171), and its report's `status` is `data_outside` with botd's reasons in `outside`. The app's `status` agrees, and the card shows it as a warning rather than a line.

A provider with customers in two regions runs one botd in each, each with `require`.

### Not covered still

Running botd where `SERVER_DATA_REGION` says is the operator's part, as is where its staff reach it from. What a pin doesn't cover is otherwise unchanged (ADR 0129): Bots' own network calls, notifications, billing and sign-in providers.

## Consequences

- A single-region server can show a residency customer that their chats and account are in their region too, in the same sealed report, and the DPA annex can point at it.
- With `require`, an operator can't promise a region botd's own data isn't in. Serving two regions takes two installs, which is the honest shape until botd's database can be split.
- The statement is only as good as the operator's word. The report says "as the operator states it".
- Nothing changes for servers that set none of this: reports keep listing botd's data as not covered, with "botd's own data region isn't stated (SERVER_DATA_REGION)" as the reason.

## Not done (still on #58)

- In-region routes for Claude Code and Codex (they take no named endpoint yet). **Done** in [ADR 0192](0192-in-region-claude-code-and-codex-routes.md).
- Splitting botd's database by region, so one server can hold two regions' chats.
- Ending a kept pin by itself once the leaver's machine and backups are gone (ADR 0171).

## Tests

- Unit (`server_data.rs`): `RESIDENCY_SERVER_DATA` parsing; the regions checked against `MACHINE_REGIONS` and needing the store they describe; which store's setting counts for copies; when botd's data is in a region; `require` needing the region and the copies in it. (`residency_report.rs`): the "not covered" line and the Markdown section.
- End to end on the real router with the in-memory Linode provider (`machines_residency_tests.rs`):
  - with `report`, a pin in botd's region has a report saying its data is in the region and not listing it as not covered, in JSON and Markdown, with the digest over it; a pin elsewhere is still made, keeps `status: kept`, and its report says why; both people see it in the app; an earlier copy to another store is counted and warned about without its address; `GET /api/regions` shows it, adds no warning about botd's region, and warns about the earlier copy;
  - with `require`, user and team pins elsewhere are refused and audited as `server_data_outside`, a team pin in botd's region is made and botd starts; a pin made elsewhere before is warned about, refuses startup under `RESIDENCY_STARTUP=refuse` with `residency.startup_refused` naming it, and its report is `data_outside`.
- Client (`residency.test.ts`): the card's line for each case, and nothing from servers before it.
