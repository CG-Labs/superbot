# 0171: Refusing startup when a pin can't be kept, and keeping a leaver's pin

## Status

Accepted (23 Nov 2026). The fifth slice of [#58](https://github.com/CG-Labs/superbot/issues/58) (M5, "Contractual data residency"). Builds on [ADR 0129](0129-contractual-data-residency.md) (residency pins), [ADR 0155](0155-residency-reports.md) (residency reports), [ADR 0168](0168-residency-in-the-app.md) (residency in the app) and [ADR 0087](0087-team-accounts-and-machines.md) (teams). 0171 was reserved for this work.

## Context

ADR 0129 left two gaps it listed as follow-ups:

- **Startup only warns.** botd logs a warning for each pin it can't keep (for example, the region's backup store was removed from its settings) and starts anyway. Each action on that tenant's data is then refused, which is fail-closed for them, but nothing stops an operator from running a misconfigured server for weeks while pinned backups are skipped. Some providers would rather botd didn't start at all.
- **A leaver loses the pin.** A member who leaves a pinned team, is taken off it by an admin, or is removed by the identity provider (SCIM taking them out of the group, deleting them, or deleting the group) was no longer held by the team's pin. Their machine is suspended and destroyed later, and their backups are kept for their retention, so data made under the agreement stayed behind with nothing holding it. It could be restored or moved anywhere. The DPA asked the Provider to pin people by hand before they left, which can't be done for an IdP's removal.

Disabling someone (by an admin or SCIM) doesn't take them off their team, so the team's pin already held them.

## Options

For startup:

1. **Always refuse.** One tenant's missing store takes every tenant down, which is why ADR 0129 didn't.
2. **An opt-in setting** (chosen). The default stays as it is; an operator who promises residency to everyone on a server can choose to refuse.

For leavers:

1. **Refuse the leave, or the SCIM removal, while the team is pinned.** Deprovisioning can't wait: SCIM removals already go through even for a team's last owner (ADR 0095).
2. **A setting per pin** saying whether leavers keep it. More to set and show for little gain: keeping a pin only ever refuses more, and an admin can unpin a leaver with a reason.
3. **Always keep it** (chosen). The leaver gets a pin of their own, copied from the team's, in the same transaction as the leave.

## Decision

### `RESIDENCY_STARTUP=warn|refuse`

- `warn` (the default) is ADR 0129's behaviour: botd logs each pin it can't keep and starts.
- `refuse`: if any pin can't be kept when botd starts, botd records `residency.startup_refused` (a system actor, `startup`; outcome denied; with each pin's subject, region, reference and why), logs the reason and exits. Any other value is refused at startup.
- A pin can't be kept when its region isn't ready (not in `MACHINE_REGIONS`, Incus hosts untagged or none in the region, off-host backups on with no store there) or any of the data it holds is outside the region. These are the same checks as pinning (ADR 0129) and the report's `status` (ADR 0155), so a pin that was accepted is only refused at startup after a change to the server's settings or hosts.
- Model routes don't count. A pinned person whose plan has no in-region route (an open tier, Claude Code, Codex) has those runs refused one by one (ADR 0139). Counting them would stop most servers with a pin, since Claude Code and Codex have no in-region route yet.
- The check runs only with the control plane on. Without it, nothing botd does can move a pinned person's machine or backups.
- To recover, an operator puts back the region, host tags or store. To end the pin instead, they start with `warn`, unpin with a reason, and switch back. The error message says so.
- `GET /api/regions` shows the setting as `residency.startup`.

### A leaver keeps the team's pin

- When someone leaves a pinned team for any reason but erasure (they leave, an admin or a team admin removes them, the last member leaves and the team is deleted, or SCIM removes them from the group, deletes them or deletes the group), the team's pin is copied to them: same region and reference, `pinnedBy` the admin who pinned the team, `pinnedAt` the time they left, and `keptFrom` the team's id. Their own data region is set to the pinned region, as pinning does.
- The removal and the copy are one database transaction. If the copy fails, they stay on the team, and the failure is logged; the IdP's retry or the person tries again.
- If they already have their own pin (it must agree with the team's, ADR 0129), it stays as it is.
- An erasure keeps nothing: the pin would be deleted with the rest of their data.
- It is audited as `user.residency_pin_kept`, on the user, with the region, reference, team, team name and the leave's reason. The actor is whoever caused the leave.
- From then on it is the user's own pin, with all of ADR 0129's rules: their region can't change, a pinned team elsewhere won't take them, their machines, backups and restores stay in the region, and an admin ends it with a reason. An admin renewing it with a new reference (`PUT /api/users/{key}/residency`, same region) makes it an ordinary pin and clears `keptFrom`.

### Who sees the reference

A team pin's reference is shown only to admins and the team's owners and admins (ADR 0129, 0168). A leaver who was an ordinary member shouldn't learn it by leaving. So for a kept pin:

- `GET /api/me/residency` shows `keptFrom` (the team's id and name, null once the team is gone) instead of `reference`;
- the leaver's own self-service report has `reference: null` in the pin and in its pin changes;
- admins see the reference everywhere as before, with `keptFrom` on the pin in user views, `GET /api/regions` and reports.

### Reports

The report's pin has `keptFrom`. `user.residency_pin_kept` is one of the pin changes it lists. Its "not covered" list no longer says people who left a pinned team aren't held: they keep a pin of their own with its own report. A team's report still covers only its current members.

## Consequences

- An operator who sells residency to everyone on a server can make a misconfigured region stop the server, not only the pinned tenants' backups.
- Data made under a team's agreement stays held after its people leave, including when the IdP removes them, with no manual step and an audit entry for each.
- Leavers' pins accumulate. Each needs an admin to unpin it, with a reason, once their machine and backups are gone or the agreement no longer covers them. A leaver joining a team pinned to another region is refused until then.
- The DPA's annex no longer asks the Provider to pin leavers by hand.

## Not done (still on #58)

- A data region for botd's own database and server backups, or a dedicated deployment per region.
- In-region routes for Claude Code and Codex.
- Ending a kept pin by itself once the leaver's machine and backups are gone.

## Tests

- Unit (`residency.rs`): `RESIDENCY_STARTUP` parsing. (`db.rs`): the leave and the kept pin happen together or not at all; an existing own pin is left alone; erasure and a refused last-owner leave keep nothing; renewing clears `keptFrom`.
- End to end on the real router (`machines_residency_tests.rs`):
  - with the in-memory Linode provider, a member taken off a pinned team keeps its pin, audited, with her region held and a region change refused; she sees `keptFrom` and not the reference in the app and in her report (JSON and Markdown), while an admin's report has it; renewing makes it hers; an erased member keeps nothing; the last member leaving deletes the team and keeps the pin on her data;
  - with the Incus and S3 stand-ins, a pin whose region lost its store: `warn` only warns; `refuse` returns the reason and audits `residency.startup_refused` with the pin; a kept pin whose only gap is a model route doesn't refuse; after an unpin it starts.
