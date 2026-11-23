# 0205: Ending a leaver's kept pin once their data is gone

## Status

Accepted (23 Nov 2026). The eighth slice of [#58](https://github.com/CG-Labs/superbot/issues/58) (M5, "Contractual data residency"). Builds on [ADR 0129](0129-contractual-data-residency.md) (residency pins), [ADR 0171](0171-residency-startup-and-leavers.md) (a leaver keeps the team's pin), [ADR 0155](0155-residency-reports.md) (residency reports), [ADR 0168](0168-residency-in-the-app.md) (residency in the app), [ADR 0071](0071-off-host-machine-backups.md) (off-host backups and their retention) and [ADR 0108](0108-deleting-a-destroyed-machines-backups.md) (deleting a destroyed machine's backups). 0205 was reserved for this work.

## Context

Since ADR 0171, someone who leaves a pinned team keeps its pin as their own (`keptFrom` the team), so the machine and backups made under the team's agreement stay in its region after they go. That pin exists only for that data. Once their machine is destroyed (a released team machine is, after its grace period) and its backups are deleted (by retention, by `botctl machine delete-backups`, or by erasure), it holds nothing, yet it still refuses their region changes and any team pinned elsewhere. ADR 0171 left each one for an admin to unpin with a reason, so they pile up on servers whose people come and go, and the residency runbook told support to check by hand whether anything was left.

## Options

1. **Keep asking admins** (ADR 0171). Accurate, but the check is manual, easy to forget, and the leaver stays held with nothing to hold.
2. **End it when they leave if they have no data then.** Misses the usual case: the machine is suspended at the leave and destroyed later, and backups outlive it by their retention.
3. **End it on a timer** (a fixed number of days after the leave). Ends pins whose data is still there, or keeps them long after it's gone.
4. **End it once botd holds none of their machine data** (chosen). Checked on every reconcile pass, so it ends within one pass of the last backup going, with an opt-out.

## Decision

### When a kept pin ends

- A user's pin with `keptFrom` set ends when they have **no machine that isn't destroyed** (in any state: pending, running, suspended, destroying or in error) and **no machine backup that isn't deleted** (running and failed ones count: a failed upload may have written its object). These are the same records ADR 0129's `data_outside` check and the report read, so a pin ends only when the report would list no machine and no backups.
- The check and the delete are one SQL statement (`DELETE ... WHERE kept_from IS NOT NULL AND NOT EXISTS (machine) AND NOT EXISTS (backup) RETURNING *`). A machine or backup made in between keeps the pin, and an admin renewing it meanwhile (which clears `keptFrom`) keeps it as an ordinary pin. The sweep also takes the control-plane lock for each pin, as pinning and unpinning do.
- It runs in the reconcile pass (every `MACHINE_RECONCILE_SECONDS`, from startup), after machines, team machines and deprovisioning have been swept. The pass's result counts them as `keptPinsEnded`. It runs only with the control plane on, as pins only matter then.
- Only kept pins end. A pin an admin made, or renewed with a new reference, never ends by itself; nor does a team's.
- Their own data region stays as the pin set it, as after an unpin (ADR 0129): new machines still go there until an admin changes it, which is now allowed.

### What isn't counted

- **botd's own data** (their account, chats and the audit log). A pin never held it (ADR 0129); with `RESIDENCY_SERVER_DATA=require` botd's own region holds it whatever the pin (ADR 0184).
- **A restore's leftover copy at the provider** (ADR 0108). It is on a host in the pin's region, since restores elsewhere were refused while pinned, and once the machine is destroyed botd has no action that moves it: only `botctl machine delete-backups` deletes it. Ending the pin lets nothing reach it.
- **Linode's own backups** go with the Linode.

### `RESIDENCY_KEPT_PINS=end|keep`

- `end` (the default) ends kept pins as above.
- `keep` is ADR 0171's behaviour: a kept pin stays until an admin unpins it with a reason. Each kept pin that holds nothing any more is a residency warning (startup log, `GET /api/regions`, `botctl regions`) naming the user, so admins know it can go.
- Any other value stops botd at startup. `GET /api/regions` shows the setting as `residency.keptPins`.
- `end` is the default because ending such a pin only stops refusing actions on data that no longer exists; nothing it held moves. An operator whose agreements say leavers stay held after their data is gone (for example, until the customer confirms) chooses `keep`.

### Evidence and visibility

- Each end is audited as `user.residency_pin_ended` on the user, with the system actor `residency`, reason `data_gone`, the region, reference, `keptFrom` (the team's id), `teamName`, when and by whom the team was pinned (`pinnedAt`, `pinnedBy`), and their email (so erasure pseudonymises it like the rest).
- Residency reports list it among the pin's changes. As for `user.residency_pin_kept` (ADR 0171), a leaver's own report never shows the team's reference on it; admins' reports do.
- In the app, a kept pin says it ends by itself once their computer and its backups are gone (`keptFrom.endsWhenDataGone` in `GET /api/me/residency`, false with `keep`).
- The DPA's residency annex and the residency runbook say a leaver's pin ends once their machine data is gone, unless the Provider keeps such pins.

## Consequences

- Leavers' pins no longer pile up: each ends, audited, within one reconcile pass of their last machine data going, with no admin step.
- A leaver whose machine and backups are gone can be given another region or join a team pinned elsewhere without an unpin.
- A leaver who never had a machine loses the kept pin at the next pass after leaving. Nothing of theirs was on a machine for it to hold.
- Operators who want ADR 0171's manual end keep it with one setting, and are told which kept pins hold nothing.

## Not done (still on #58)

- Splitting botd's database by region, so one server can hold two regions' chats.

## Tests

- Unit (`residency.rs`): `RESIDENCY_KEPT_PINS` parsing. (`db.rs`): a kept pin stays while a machine in any state but destroyed, or a backup not yet deleted (failed included), is left, and ends once neither is, once; the region stays; renewed pins and team pins never end; someone with no data ends at once.
- End to end on the real router (`machines_residency_tests.rs`):
  - with the in-memory Linode provider, a member taken off a pinned team keeps its pin while her machine is there, and the app says it ends by itself; once the machine is destroyed, the next reconcile pass ends it (`keptPinsEnded: 1`), audited once as `user.residency_pin_ended` by the system with the team's reference and `data_gone`; she sees no pin, her region stays and can now be changed; a later pin of her own has a report listing the end without the team's reference, while an admin's has it; that ordinary pin never ends by itself;
  - with `RESIDENCY_KEPT_PINS=keep`, the pin stays after the machine is gone, the app says it won't end by itself, `GET /api/regions` shows `keep` and warns that it holds nothing, and the warning goes once an admin unpins it;
  - with the Incus and S3 stand-ins, a kept pin stays after the machine is destroyed while its backup is in the store, and ends on the pass after `DELETE /api/machines/{id}/backups`.
- Client (`residency.test.ts`): the line about a kept pin ending by itself shows only when the server says so, for the pin on your data or your own pin beside your team's.
