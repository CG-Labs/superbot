# 0085: Resizing machines on a tier change

## Status

Accepted (21 Nov 2026). Fifth slice of billing v0 ([#31](https://github.com/CG-Labs/superbot/issues/31), [roadmap](../ROADMAP.md)). Also covers resizing within a host's room on [#29](https://github.com/CG-Labs/superbot/issues/29). Builds on tier limits ([ADR 0040](0040-billing-v0-tier-limits.md)), Stripe subscriptions ([ADR 0042](0042-billing-checkout-portal-customers.md), [ADR 0050](0050-billing-period-token-usage.md)), storage limits ([ADR 0082](0082-storage-limits-per-tier.md)), the control plane ([ADR 0025](0025-control-plane-linode.md)), Incus machines ([ADR 0065](0065-incus-container-machines.md)) and placement by host load ([ADR 0081](0081-placing-machines-by-host-load.md)). It changes ADR 0040's rule that machines aren't resized when a tier changes.

## Context

A tier's `machineType` sets the size of the user's machine. Until now, a tier change from Stripe or an admin changed the user's limits, but their machine kept its old size. An admin had to resize it by hand, and the usage view flagged machines that no longer fit. An upgrade should give the bigger machine the user pays for. A downgrade should give back the bigger machine, but must never lose what's on it. Stripe redelivers webhooks, so asking twice must not resize twice. An Incus host may not have room to grow a container where it is.

## Decisions

### What asks for a resize

- A tier change asks for the machine to become the size the new tier gives (`size_for`). Two things change tiers: a Stripe subscription event the webhook applies (`user.tier_changed`, cause `stripe`, with the event id), and an admin's `PATCH /api/users/{key}` (cause `admin`).
- Asking is idempotent. The target comes from the user's tier at that moment, not from the event. A redelivered event finds the same target and changes nothing. A redelivery of an event already applied (Stripe's answer was lost, or botd stopped before asking) asks for a resize that was never asked for, but not again for one already settled. A newer change replaces an open request; a change back to the machine's size cancels it (`already_that_size`); a plan without `machineType` cancels it (`plan_sets_no_size`).
- Each request is stored on the machine row: state, target tier and plan, the size it started from, cause, event id, reason, message, attempts, next try, and when it was asked and last changed. It is audited as `machine.resize_queued` (with `replaces` when it superseded another).

### The reconciler does the work

- The reconciler (every minute, or `POST /api/machines/reconcile`) takes each open request under the control plane's lock. It first checks the request against the user's tier again, since the tier or `TIERS_FILE` may have moved on. States: `pending` (try on this pass), `waiting` (not safe yet, looked at on every pass), then `done`, `failed` or `cancelled`.
- It asks the provider for the machine first, as the manual resize does, so a resize whose answer was lost isn't sent twice. Linode resizes by its resize call (a cold migration that restarts the VM and grows the disk). Incus edits the container's limits live.
- Before each provider resize call (automatic or manual), botd stores the size it is sending (`resize_sent_tier`, `resize_sent_plan`). It is cleared only once the outcome is seen: the call's answer, or on a later pass a provider `get`. If the provider took that size, it's recorded (`machine.resized` with `settled: true`). The reconciler settles these first, even after the request was replaced, cancelled or failed.
- Tier changes don't take the control plane's lock, so one can land while the provider is resizing, or after an answer was lost. While a sent size is unsettled, a tier change back to botd's recorded size doesn't cancel. It asks for that size again, and the reconciler resizes back if the provider took the other size. After each resize, the reconciler checks the tier again too.
- Done is audited as `machine.resized` with `auto: true`, the cause, the event id and whether the provider was called. Provider failures that may pass (rate limits, the network, 5xx) are tried again with the rebuild backoff, up to 5 tries. Failing to read a plan's disk size from the provider counts as a provider failure too, rather than a wait. Other failures fail at once: `machine.resize_failed` (outcome failure) and an alert. A failed request isn't tried again by itself; the next tier change asks afresh, and an admin can resize by hand.

### Nothing is lost on a downgrade

A resize waits, saying why in plain words, while any of these is true. The order is most actionable first.

1. **`storage_over`:** the resize makes the machine smaller, and the user's storage ([ADR 0082](0082-storage-limits-per-tier.md)) is at or past the new tier's `maxStorageMb`. Growing removes nothing, so it never holds up a bigger size. "Storage is X used of the Small plan's Y. The machine moves to the Small size once that's deleted…"
2. **When the new disk is smaller, or botd can't tell it isn't:**
   - **`plan_disk_unknown`:** the provider can't say how big the new size's disk is.
   - **`disk_unknown`:** the machine hasn't reported its disk use in the last 15 minutes.
   - **`disk_too_full`:** what's on the disk is more than 90% of the new disk.

   Machines now report disk use (used and total bytes of the agent's home filesystem) with every heartbeat. A suspended machine's last report is trusted only if it was recent (15 minutes) when the machine was suspended, since its disk can't change while it's off. Machines record when they were suspended (`suspended_at`); one suspended before that was recorded waits for a fresh report. Linode's plan disk comes from `GET /linode/types/{plan}`; Incus reads it from the plan name (`c<cpus>-m<GiB>-d<GiB>`).
3. **`no_room`:** an Incus host hasn't room to grow the container where it is (below).
4. **`busy`:** Bots are running on the machine, and the resize would restart it (a VM) or shrink a container's CPUs, memory or disk. It waits at most 6 hours, then goes ahead, so a busy machine still ends up the size its plan says.

While the machine is pending, provisioning, in error, being rebuilt or being restored, the request waits too (`machine_not_ready`, `rebuilding`, `restoring`). If the machine is destroyed, it's cancelled.

Each wait is audited once per reason as `machine.resize_waiting`, not on every pass.

### Resizing within a host's room (#29)

- Growing an Incus container checks only the extra CPUs, memory and disk against its host's capacity (`INCUS_CAPACITY`, [ADR 0081](0081-placing-machines-by-host-load.md)). The machine already counts on its host, so a drained host may still grow what's on it. A host that is down or lost can't.
- While a sent size is unsettled (it may have reached the provider), its host counts the larger of the two sizes, whatever happened to the request since, so nothing else takes that room. The reservation ends only once the provider is checked. The machine's own retry doesn't count that room against itself.
- An automatic resize without room waits with `no_room` and alerts admins once: "A machine can't grow on its host". It goes ahead on the first pass after room frees up.
- A manual resize without room is refused with 409 and `machine.resize_refused` (reason `no_room`). Before this, it could push a host past its capacity. Moving the machine to another host is out of scope: it needs live migration, or a restore that loses work since the last backup.
- Linode places its own machines, so there's no room check there.

### Where it shows

- **Admins:**
  - `GET /api/users/{key}/machine/resize` gives the latest request, with plans, reason, message, attempts and next try.
  - `GET /api/machines/resizes` lists open requests.
  - The admin machine view and `GET /api/usage` carry `resize`.
  - `botctl machine resize <user> status` and `botctl machine resizes` read these. `botctl usage` prints "resizing to <plan> (<state>: <why>)".
- **Users:**
  - `GET /api/machine` and `GET /api/me/tier` (`machine.resize`) carry state, tiers, reason and message, without plans or host names. A `no_room` wait reads "The server it's on hasn't room for the Pro size yet." Provider errors show users a plain message; admins see the error itself.

## Consequences

- Upgrades take effect on the machine within a minute, with no admin.
- Downgrades never shrink a disk below what's on it. A user over the smaller plan's limits keeps the bigger machine until they delete files, and is told so. That could hold a downgrade indefinitely. Admins see it in `botctl machine resizes`.
- A Linode resize restarts the user's machine. Waiting for running Bots limits the damage, but a machine that is idle between runs is restarted without warning.
- Machine disk use is now reported, but storage limits ([ADR 0082](0082-storage-limits-per-tier.md)) don't count it yet. [ADR 0105](0105-machine-disk-use-in-storage-limits.md) counts what the machine's homes hold.
- Billing emails and yearly prices at checkout stay on #31.
