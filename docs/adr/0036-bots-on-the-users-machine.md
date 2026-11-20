# 0036: Bots run on their owner's machine

## Status

Accepted. Next slice of [#29](https://github.com/CG-Labs/superbot/issues/29) (M3). Builds on [ADR 0025](0025-control-plane-linode.md) (one machine per user), [ADR 0029](0029-per-user-isolation.md) (each run's owner, folder and token; the routing hook), [ADR 0031](0031-machine-enrollment-mtls.md) (enrollment, mutual TLS, the agent) and [ADR 0033](0033-tiers-model-routing.md) (each run's route comes from its owner's tier).

## Context

ADR 0031 gave botd an authenticated channel to each user's machine, but the agent turned every job down, so routing could only refuse. The owner's rule is one computer per user, not per Bot: all of a user's Bots share it, and nobody else's run there.

We need a way to run one harness turn on the machine and stream it back, with chat, approvals and audit working as they do on the server. We also need to choose who runs where and say plainly when it can't. Existing installs must not change.

## Decision

### Placement: who runs where

`MACHINE_ROUTING` has three modes:

| Mode | Behaviour |
|------|-----------|
| `off` (default) | Every Bot runs on this server, as before. Self-hosting never changes. |
| `assigned` | A user an admin **assigned** to their machine has their Bots run there; everyone else's run here, as before. The way to move users over one at a time. |
| `on` | Every Bot runs on its owner's assigned machine. Without one, the run is refused. |

(`1`, `true` and the like still mean `on`.) Any mode but `off` needs `LINODE_TOKEN`, and is a startup error without it.

Assignment is a separate step from having a machine: `PUT /api/users/{user}/placement` (admins; `botctl machine assign <user>`). Only a running, enrolled machine can be assigned. `DELETE` unassigns it (`botctl machine unassign`), and so does destroying the machine. Suspending it keeps the assignment, so the user's Bots are refused while it's suspended instead of quietly moving back here. `GET /api/users/{user}/placement` and `GET /api/machines/placements` (`botctl machine placement [<user>]`) show where each user's Bots run (`server`, `machine` or `nowhere`), and why.

The target comes from the **Bot's owner**, never the caller, so a Bot shared with others still runs on its owner's machine. An assigned user's Bots run there or not at all. Whenever the machine can't take the run, it is refused and never run here instead:

| Refusal (audit `reason`) | When |
|--------------------------|------|
| `no_machine`, `not_assigned` | `on`, and the owner has no machine, or it isn't assigned. |
| `machine_not_ready` | Assigned, but provisioning, suspended, failed, ... |
| `machine_not_enrolled` | No usable certificate (never enrolled, or revoked). |
| `machine_offline` | The agent didn't answer the check made just before the run. |
| `agent_outdated` | The agent speaks an older protocol. |
| `harness_missing` | The Bot's harness isn't on the machine's harness PATH. |
| `agent_incomplete` | `botctl` isn't on the machine, so approvals couldn't be asked for. |

A refused run says why in the chat, is given back to the owner's monthly run count (ADR 0033), and is audited as `bot.run_refused` (outcome `denied`, with owner and machine).

Assigning or unassigning clears the harness sessions of the user's Bots (`sessionsReset` in the audit): those sessions live on the old host, and resuming them on the new one would fail.

### Health

Before each run botd asks the agent for a heartbeat over mutual TLS, pinned to the machine's certificates (ADR 0031). It names the harness it needs: `GET /v1/heartbeat?bin=<harness>`. The answer now also carries the protocol version, the machine's folders (`layout`), any missing programs, and how many jobs are running. botd records it as before (`agent_seen_at`, `agent_error`). The reconciler's periodic heartbeat is unchanged.

### The job protocol (version 1)

botd still builds the harness command. The adapters stay in botd, and the agent knows nothing about harnesses, so harness-specific code stays in its adapter. The adapters now describe a run as data: the program, its arguments and environment, its stdin, any files to write first (such as the Hermes managed config or the Pi guard), and an optional cleanup command (stopping a leftover Hermes daemon). One runner, `machines::job`, carries that out. botd uses it for local runs and the agent uses it on the machine, so both behave the same.

- `POST /v1/jobs` with a `JobRequest`. It holds the protocol version, a job id, the Bot, owner and message ids, the program, args, env, cwd, stdin, files, cleanup, and the files to send back (`collect`). Unknown fields are rejected.
- The reply is a stream of NDJSON `JobEvent`s:
  - `started`;
  - `line`, one per stdout line, which botd's adapter parses exactly as it would locally;
  - `cleanup` and `error`, when a cleanup or the job itself fails;
  - `exit`, with the exit status, the end of stderr and the collected files;
  - `ping` every 15 s while the harness is quiet.

  botd gives up when the machine has been silent for 60 s, and says so in the chat. A machine's certificate says who answered, not that the answer is sane: botd keeps at most 16 MiB of one event and 1 MiB of a heartbeat or refusal, and stops listening beyond that.
- `POST /v1/jobs/{id}/abort` stops a job (stop, timeout, a missing approval hook, shutdown). The agent sends TERM to the harness's process group, then KILL 5 s later. If the stream hasn't ended 30 s after the abort, botd lets go. Whenever botd stops listening early (too much output, a lost stream), it sends the abort too. The agent also stops a job whose stream botd drops, which it notices by the next ping at the latest. Abort is honoured until the harness and its output have fully ended, so a harness that closes its output and keeps running is still stopped.

The agent checks each job before running it:
- the job's owner must be the user in the agent's own certificate (403 otherwise: "This machine runs only its own user's Bots");
- ids and program names must be plain names;
- every path must be inside its home;
- the program must be on its harness PATH.

It starts each harness from a clean environment: HOME, PATH (`SUPERBOT_HARNESS_PATH`) and LANG are its own, and botd's job env goes on top of that, minus HOME and PATH. Because nothing is inherited there, the job env carries every secret a local run would get, including the ones local runs inherit from botd's own environment (never botd's own secrets, such as `AUTH_PASSWORD`). Each machine runs at most 8 jobs at once (`SUPERBOT_MAX_JOBS`), and a job id that is already running is refused.

A new `protocol` number means an incompatible change. botd refuses runs on agents that report an older one (`agent_outdated`) rather than guessing.

### Folders, memory and facts

The agent reports its folders. Under `SUPERBOT_HOME` (default `<state dir>/home`):
- `work`, the user's workspace;
- `bots/<bot>`, each Bot's state and its `MEMORY.md`;
- `USER.md`, the user's facts.

A run there uses those paths in its system prompt, cwd and approval checks. Deleting inside the machine's `work` counts as inside the workspace.

botd keeps the source of truth for memory and facts, since the client and backups read them there. Each job carries the Bot's `MEMORY.md` and, when no other Bot of the same user is running there, the user's `USER.md`. That way one Bot's run can't overwrite another's edits to the facts. Both files come back in `exit`, and botd saves whatever changed. A file over 1 MiB doesn't come back: `exit` names it, the Bot says so in the chat, and the agent keeps the machine's copy instead of letting the next job's older one replace it. Once it's trimmed under the limit, it syncs again.

### Approvals and botctl from the machine

Bots on the machine call `botctl` there. Its approval hook asks botd before each risky tool, and the gate still fails closed. botctl talks to the agent's **relay** on loopback (`SUPERBOT_AGENT_API`, default `127.0.0.1:7444`), which passes `BOT_API` through. The relay forwards `/api/*` over mutual TLS to botd's machine port at `/v1/machines/{id}/api/*`, with only a few headers kept and requests capped at 32 MiB. botd then requires:
- the machine's certificate;
- a Bot token (`sbb_`) whose owner is that machine's user. Otherwise it answers 403 and audits `access.denied` with reason `another_users_bot` or `no_bot_token`.

It then hands the request to its own API router as if it came from loopback, so the usual auth, role caps (ADR 0029) and audit apply unchanged. Machines download botctl from botd (`/v1/botctl`, checked by hash, like the agent) before the agent starts. botd ships botctl next to itself already.

The agent's mTLS port now admits only the control plane's certificate, and keeps that connection alive across a whole run.

### Audit

| Event | Meaning |
|-------|---------|
| `placement.assigned`, `placement.unassigned` | An admin moved a user onto or off their machine (or destroying it did). Includes routing mode, reason and `sessionsReset`. |
| `bot.run_routed` | A run was sent to the owner's machine. Includes owner, machine, link and agent version. |
| `bot.run_refused` | A run that couldn't go where it must. |
| `harness.invoked`, `bot.run_finished` | As before, plus `host` (`server` or `machine`) and `machine`. |
| `access.denied` | A machine's relay was used without its user's Bot token. |

Approvals made from the machine are audited exactly as local ones.

## Consequences

- Existing installs don't change: routing is `off` unless set, and `assigned` changes nothing until an admin assigns someone.
- An assigned user's Bots run only on their own machine, under that machine's certificate, and are refused with a reason otherwise. User A's Bot never runs on user B's machine: botd routes by owner and pins B's certificates, and B's agent checks the owner against its own certificate.
- Chat, streaming, stop, timeouts, approvals, memory and audit work the same either way. A test runs a real agent over real mutual TLS on loopback with a stand-in harness. Nothing calls Linode: the provider is the in-memory fake.

## Not in this slice

- **Harness CLIs on the image.** Cloud-init installs the agent and botctl, not Claude, Codex, Pi or Hermes. Until an image or setup step adds them, the agent reports them missing and runs are refused with `harness_missing`.
- **Harness logins and server-wide secrets.** Per-user secrets reach the machine in the job env, as they reach local runs. Server-wide secrets do too. Harness logins (`~/.claude`, `~/.codex`) aren't moved yet.
- **The user's existing folder.** `WORKSPACE_DIR/users/<id>` on the server isn't copied to the machine. The machine's `work` starts empty.
- **Screens on machines.** Runs there get no screen yet.
- **The agent runs as root**, so a Bot there could read the agent's key. A separate OS user for Bots belongs with #30's OS isolation.
- **Agent upgrades.** A machine keeps the agent it installed. An outdated one is refused, not upgraded.
- **Firewall.** Restricting the agent port at the provider is [ADR 0035](0035-machine-firewall-auto-enroll.md) (`MACHINE_FIREWALL=on`, off by default). Without it, mutual TLS and the control-plane-only admit are the defence.
- **Per-peer connection limits** on botd's machine port.
- **Concurrent facts edits.** The `USER.md` guard is per botd process. Runs of one user's Bots in parallel can still lose an edit made by a run that didn't receive the file.
