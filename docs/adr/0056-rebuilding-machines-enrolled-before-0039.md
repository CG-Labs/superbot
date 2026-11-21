# 0056: Rebuilding machines enrolled before ADR 0039

## Status

Accepted (21 Nov 2026). Next step on [#29](https://github.com/CG-Labs/superbot/issues/29) (M3, control plane). It builds on [ADR 0025](0025-control-plane-linode.md) (the control plane), [ADR 0031](0031-machine-enrollment-mtls.md) (enrollment and mTLS), [ADR 0035](0035-machine-firewall-auto-enroll.md) (firewall and first-boot enrollment), [ADR 0036](0036-bots-on-the-users-machine.md) (Bots on the user's machine), and [ADR 0039](0039-machine-harnesses-and-agent-upgrades.md) (harnesses and agent upgrades), and finishes what ADR 0039 left out.

## Context

Machines enrolled before ADR 0039 can't catch up by themselves. From the code at the time:

- **Agent.** Their unit runs `/usr/local/bin/superbot-machine` under `ProtectSystem=strict`, with only the state and Bots' folders writable, so the agent can't replace itself. It has no `/v1/upgrade`, no guard to put an old build back, and no `/usr/local/lib/superbot` layout.
- **Heartbeat.** It reports no `can` and no `build`: none of `upgrade`, `harnesses`, `logins`, `sync`, `bot_user`, `screens`, `teammates`, `teammate_removal`. Agents from before ADR 0036 report no job protocol either.
- **On disk.** No tools folder or harness CLIs, no `superbot-bots` user (ADR 0043), no screen programs or voxl (ADR 0045), and maybe no `botctl`.
- **Certificates and folders** are fine: they rotate, and the folder copy (ADR 0041) needs `sync`, which these agents lack.

So their Bots are refused as outdated or missing a harness, and today's messages say "reinstall it", which means SSH or the Lish console.

The only ways in through the old agent are its job API and its heartbeat. Its jobs run a known harness on its PATH with files written 0600; making it run anything else would mean exploiting our own sandbox. We won't use the agent as a code-execution channel, even to upgrade it.

## Decision

### Rebuild in place through the provider

The control plane asks the provider to rebuild the machine: `POST /linode/instances/{id}/rebuild` with `MACHINE_IMAGE`, `MACHINE_AUTHORIZED_KEYS`, a fresh random root password, and today's cloud-init user data (the same as a new machine's, ADR 0035) carrying a new one-time enrollment token. Linode wipes the disks and reinstalls. The machine keeps its Linode id, IP address and firewall, so nothing else in botd changes. First boot installs today's agent and unit, botctl, the Bots' user and screens, then enrolls. The usual follow-ups then do the rest: the harness plan, the Bots' user, and the folder copy if the machine is assigned.

`MachineProvider` gets `rebuild(id, RebuildSpec)`. Its `Debug` hides the user data, as `CreateSpec`'s does. The fake provider records it and keeps the user data it was sent, so tests boot the "rebuilt" machine with that token.

A machine is **legacy** when an answered heartbeat lacks `upgrade`. That is exactly the agents that can't use ADR 0039. Agents from before ADR 0036 count too.

### Never wipe work without an admin's say

A rebuild erases the machine's disks. Bots' memory and the user's facts are kept on botd, but files Bots made in `work/` exist only there. A machine **may hold work** if it is assigned now, or the audit log shows it was assigned (`placement.assigned`) or a Bot ran there (`bot.run_routed`). Such a machine is rebuilt only when an admin asks with `?discardWork=true`. Nothing does that by itself. Linode backups, when on, survive a rebuild, and the docs say so.

### Settings and control

`MACHINE_LEGACY_REBUILDS` needs `MACHINE_CONTROL_URL` and takes one of three values:

- `manual` (the default): rebuild only when an admin asks.
- `auto`: also queue each idle legacy machine that never held work, once.
- `off`: never.

Rebuilding also needs botd to ship `superbot-machine`. Otherwise a rebuilt machine would have no agent to install, so botd refuses.

The admin API:

- `POST /api/users/{key}/machine/rebuild[?discardWork=true]` asks for a rebuild and answers 202. It answers 409 when the agent can upgrade itself, the agent is held (the ADR 0039 hold), a rebuild is already underway, or the machine may hold work and `discardWork` isn't true.
- `GET` returns `legacy`, what the agent `lacks`, `mayHoldWork`, and the `rebuild`.
- `DELETE` cancels a rebuild that is still queued.
- `GET /api/machines/legacy` lists legacy machines.

The matching `botctl` commands are `machine legacy` and `machine rebuild <user> [--discard-work|status|cancel]`. All these routes are admin only. The old "reinstall it" messages now point at `botctl machine rebuild`.

### State, steps and retries

The rebuild's state lives in new `machines` columns (migration 25): `rebuild_state`, its id, who asked, `discardWork`, attempts, next try, when it was asked, when it entered its state, when it was sent, its last error, and the agent's version before. Each step is a conditional update naming the rebuild id and the states it may come from. Steps run under the control plane's lock, so a retry, a stale step or a racing cancel changes nothing.

- **queued**: on each pass, botd takes a fresh heartbeat.
  - If it's held, or no longer legacy, the rebuild is cancelled.
  - If the machine may now hold work and `discardWork` isn't set, it fails.
  - If it's busy, it waits a minute without counting a try.
  - If it doesn't answer, it backs off and counts a try.
  - Otherwise botd revokes unused tokens, mints a new one, and records the rebuild as `rebuilding` before calling the provider. That way a botd that stops mid-call waits instead of wiping twice.
- **The provider's answer**:
  - OK: the old disks' certificates are revoked (`rebuilt`, but not the new token).
  - Rate limited: nothing happened. The new token is revoked and it is queued again after the backoff.
  - A refusal: the rebuild fails and the new token is revoked.
  - A lost answer (transport error, 408, 5xx) may mean it happened. botd keeps the token and waits for the machine.
  - Before calling the provider, botd forgets the old agent's report, sent plans and upgrades, the folder-copy status, and the user's harness sessions. Doing it first means a botd that stops mid-call can't skip it. If the provider then refuses, the old agent reports again and Bots start new sessions.
  - Pending teammate removals there end once the disks are surely gone: on an OK, or when the machine comes back.
- **rebuilding**: the first heartbeat after the machine enrolls again (`enrolled_at` after the send) settles it. If the agent can upgrade, the state is `done` (`machine.rebuilt` with from and to versions and the build) and the folder copy starts if the machine is assigned. If not, it is `failed`. If it enrolls but never answers within 30 more minutes, it is `failed` (`no_heartbeat`). If the machine doesn't enroll within the enrollment timeout plus five minutes, it moves to **retrying**, unless it enrolled just then.
- **retrying**: after the backoff the rebuild is sent again with a new token, without needing a heartbeat, because the old agent may be gone. If the old agent still answers (the lost answer meant nothing happened), botd waits while it's busy. If the machine enrolled after all, the same `no_heartbeat` deadline applies, so it never waits forever.
- **Limits**: tries back off 1, 2, 4, 8, 16 minutes, capped at 30. After 5 tries the rebuild is `failed` and its token revoked. `done`, `failed` and `cancelled` are settled, and an admin can ask again. A failed rebuild that was sent may have left no agent to answer, so asking again then skips the heartbeat and goes straight to `retrying`. The work guard still applies. `auto` never re-queues a machine it already tried.

While a rebuild is queued, rebuilding or retrying, the user's routed runs are refused with `machine_rebuilding` ("your computer is being rebuilt with the latest setup"). Nothing runs on botd instead (ADR 0036). Each step is audited as `machine.rebuild_requested`, `machine.enroll_token_issued` (`via: rebuild`), `machine.rebuild_sent` (`answered: false` for a lost answer), `machine.cert_revoked`, `machine.rebuild_failed`, `machine.rebuild_cancelled` and `machine.rebuilt`.

### Self-host

Self-host doesn't change. Without the control plane the new routes answer 503 like the other machine routes, and without enrollment nothing here runs.

## Consequences

- Old machines catch up with no SSH. After that they upgrade themselves (ADR 0039), so rebuilds are a one-time step per machine.
- A rebuild costs the machine's local files. The may-hold-work rule and the explicit flag keep that the admin's call. The audit-log part of that rule is best effort once old events are pruned, so assigned machines are always treated as holding work.
- Harness logins made on the machine (ADR 0041) are lost and must be made again.
- The design relies on the provider's rebuild. Another provider behind `MachineProvider` needs an equivalent (reinstall in place with user data), or a delete and create with the same label.

## Not in this slice

- Copying files off a machine before a rebuild. Admins do it by hand or restore from backups.
- Rebuilding machines whose agent can upgrade itself, for example to change the image. That is still "destroy and request a new one".
