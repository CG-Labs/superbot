# 0105: Machines' disk use counts in tier storage limits

## Status

Accepted (22 Nov 2026). Part of the SOC 2 readiness checklist of M4, [#50](https://github.com/CG-Labs/superbot/issues/50); closes checklist row A1.1-2 in the [readiness checklist](../security/soc2-readiness-checklist.md). Builds on storage limits per tier ([ADR 0082](0082-storage-limits-per-tier.md)), resizing machines on a tier change ([ADR 0085](0085-resizing-machines-on-a-tier-change.md)), the control plane ([ADR 0025](0025-control-plane-linode.md)), Bots on the user's machine ([ADR 0036](0036-bots-on-the-users-machine.md)), machine enrollment over mTLS ([ADR 0031](0031-machine-enrollment-mtls.md)), the audit log ([ADR 0009](0009-audit-events.md)) and metrics ([ADR 0089](0089-metrics-and-structured-logs.md)).

0104 is the highest number on `main`. Open PR [#164](https://github.com/CG-Labs/superbot/pull/164) holds 0102.

## Context

ADR 0082 caps what one user's files take with the tier's `maxStorageMb`, but it only walks folders on the botd server. When a user's Bots work on their own machine, most of their files are on that machine, so their storage looked low and the cap never applied to it. ADR 0085 made heartbeats report disk use, but those numbers can't be charged to a user:

- `Disk {used, total}` comes from `statvfs` on the machine's root filesystem, so it includes the OS image, packages and caches. On a new machine that is already gigabytes the user never wrote.
- While the user's Bots work on the machine, botd still holds the copy of their working folder from before they moved. Counting that copy as well as the machine would count the same files twice.

Reports can also be missing (an older agent, or a machine that has never answered) or old (a machine that is suspended or unreachable). A good rule has to cover both without blocking anyone by mistake and without making the limit easy to get around.

## Decision

### What the machine reports

- The agent walks the homes its Bots and teammates write to (`SUPERBOT_HOME` and `SUPERBOT_TEAMMATES`) with the walker botd already uses for storage. That walker is now shared as `server/src/walk.rs`. It never follows a symlink, counts a hard-linked file once, and stops at 500,000 entries.
- Each heartbeat's `disk` gains `files` (bytes in those homes) and `partial` (some of it couldn't be read, or the walk hit the entry cap). Both fields are optional, so old agents and old botd keep working.
- The walk is never done on the request path. A heartbeat returns the last result and starts a new walk if that result is over 60 seconds old. The end of a job always starts one, so the next heartbeat includes what that job wrote. Only one walk runs at a time, and a request that arrives during a walk queues one more.
- botd asks for a heartbeat on every reconcile pass (`MACHINE_RECONCILE_SECONDS`, 60 by default) and when it checks the machine before a run. The storage check comes before that run's machine check, so it uses the previous report: usually under a minute plus one walk old while the machine is up.
- botd keeps the last report on the machine's row (`disk_files`, `disk_files_partial`, `disk_files_at`). A heartbeat without `files` leaves the stored report alone. A rebuild clears it, the same as the rest of the disk report.

### What counts

A user is *on a machine* when the control plane is on, routing isn't `off`, and their machine is assigned. Only then is their Bots' work on the machine. For a user on a machine:

- storage = their facts and Bots' folders on botd + what the machine last said its homes hold;
- their working folder on botd isn't walked or counted, since it is a frozen copy of files that also live on the machine;
- once the machine is unassigned, or routing is turned off, the working folder on botd counts again.

The cached measurement records whether it was taken for a user on a machine, so a change of placement causes a new walk.

### Old and missing reports

| Report | When | Counts |
|---|---|---|
| Fresh | Heard within 15 minutes (`DISK_FRESH_MS` of ADR 0085), or within 15 minutes of being suspended | Its bytes |
| Stale | Older than that | Its bytes, as last reported |
| Missing | The agent has never reported `files` | 0. The total is a lower bound (`partial: true`) |

- **Stale reports count at their last value.** Bots write only during runs, and a run needs the machine to answer, so a machine that has gone quiet has had nothing new written to it since its last report. Dropping old reports would let a user get under the limit by having their machine go quiet.
- **Missing reports count nothing and allow work.** Refusing would block every user whose machine runs an older agent until an operator upgrades it. The tier's `machineType` still caps that disk, as before this ADR. The view and the client say the number is "at least" what's shown and that the computer hasn't reported yet, and the metric below lets operators find these machines.

### What people are told

The existing checks are unchanged: a warning from 90% (once a day), and new messages and runs refused at 100%. They now use the total that includes the machine:

- A Bot whose owner's Bots work on a machine says "Delete files on the computer I work on" instead of "Delete files from the workspace". Someone sending a message is told to delete files "on the computer this Bot works on".
- `storage` in the usage views gains `machine: {used, report: fresh|stale|missing, partial, measuredAt}`. `used` is null until the machine first reports. `files` is null while the user is on a machine, and `partial` also covers a missing report. The client shows "at least: the computer hasn't said what it holds yet" or "as the computer said on <date>".
- ADR 0085's `storage_over` check, which stops a machine from shrinking while it holds more than the smaller tier allows, uses the same total, so it now sees what is on the machine.

### Audit and metrics

- No new audit event. `usage.storage_warning`, `bot.message_refused` and `bot.run_refused` (reason `storage_limit`) gain `used`, `partial` and `machine: {used, report, partial, measuredAt}` in their details, so a refusal shows which number it was based on and how old that number was.
- New gauge `superbot_machine_storage_reports{report="fresh|stale|missing"}`: assigned, not destroyed machines by the age of their last report. It is shown only when the control plane is on and routing isn't `off`. A non-zero `missing` count for long means agents that need upgrading.

## Consequences

- Storage limits now apply to users whose Bots work on their own machine. The OS, packages and caches on that machine aren't charged to them.
- A user just under the limit on a machine can pass it during one run, as on botd (ADR 0082 also checks only before a run). A run started within about a minute of the last one ended may also be checked before the machine has reported what that run wrote. The one after that sees it.
- Asking the machine during the check would make sending a message wait on the network, and on a timeout when the machine is down. It isn't done.
- A machine whose agent never reports still isn't counted. It shows up in the metric and in the user's view instead of being blocked.
- There are no new settings. Agents that predate this ADR keep working and are reported as missing until they are upgraded.
- Each machine walks its homes at most once a minute while it's being heartbeated, plus once after each job. The walk runs on its own thread, so health checks never wait for it.
