# 0043: Bots run as their own OS user on the user's machine

## Status

Accepted. Next slice of [#29](https://github.com/CG-Labs/superbot/issues/29) (M3). Builds on [ADR 0031](0031-machine-enrollment-mtls.md) (enrollment, mutual TLS), [ADR 0035](0035-machine-firewall-auto-enroll.md) (firewall and lockdown), [ADR 0036](0036-bots-on-the-users-machine.md) (Bots on their owner's machine), [ADR 0039](0039-machine-harnesses-and-agent-upgrades.md) (harness CLIs, agent upgrades) and [ADR 0041](0041-machine-harness-logins-and-folder-copy.md) (logins, folder copy).

## Context

Since ADR 0036, the machine agent (`superbot-machine`) runs as root, and so does every Bot on the machine: harness runs, logins, cleanups. Root is needed by the agent itself, to replace its own binary (ADR 0039) and to keep its key (`identity.pem`). Bots don't need it. Today a Bot on its owner's machine can read the agent's key and act as that machine towards botd, or change the agent so it survives a reinstall of the harnesses.

The home Bots work in (`/var/lib/superbot-machine/home`: workspace, logins, the folder copy) is written by both the agent and the Bots. Once Bots stop being root, the agent writing into a folder a Bot owns becomes a classic hole: a link the Bot leaves there can turn root's write into a write anywhere, or root's read into a leak of the key.

Machines already running Bots as root need a way over, without a reinstall.

## Decision

### One unprivileged user for the machine's Bots

`MACHINE_BOT_USER=on` (default `off`; it needs `MACHINE_CONTROL_URL`) turns it on. Every Bot on a machine belongs to that machine's one user, so one OS user for all of them is enough: `superbot-bots`, a system user with its own group, no login shell, and the Bots' home as its home. It is never root, never in root's group, and never the agent's own user. The agent may be set to another name (`SUPERBOT_BOT_USER` in its `machine.env`); botd never names one.

The agent stays root. After the switch:

| What | Runs as |
|------|---------|
| Harness runs, their cleanups | `superbot-bots` (uid and gid set before exec; root's extra groups dropped; `USER` and `LOGNAME` set) |
| Harness logins (ADR 0041) | `superbot-bots`, in a terminal it owns |
| Files the agent writes or reads in the home: a job's files (memory, facts, harness configs), the files a job sends back, the folder copy, login checks and logouts, the working folders | `superbot-bots`'s file access (see below) |
| Harness installs (ADR 0039), upgrades, the key, the folder copy's chunks, the relay | root, outside the home |

**File access in the home.** The agent never touches the home as root once it belongs to the Bots. Each file step runs with the thread's file identity switched to the Bots' user (`setfsuid`, `setfsgid` and `setgroups`, called on that thread only and put back after, with no other task in between). The kernel checks permissions as that user, so a link a Bot left only leads where the Bots' user could go anyway. The folder copy's chunks stay in the root-only state folder; the agent opens one as root, then writes the file into the home as the Bots' user.

**Making the tools and home reachable.** The state folder becomes `0711`, so the Bots' user can pass through to its home and the tools but list or read nothing else there; the key stays `0600` root. Installed harness CLIs are made readable to others, as programs in `/usr` are. The home stays `0700`, owned by `superbot-bots`.

### Turning it on

1. botd sees, after a periodic heartbeat, that `MACHINE_BOT_USER=on`, the agent `can` do `bot_user`, it has no Bots' user yet (or set-up failed over 30 minutes ago), and it runs nothing. botd sends `PUT /v1/bot-user` over the pinned mutual-TLS channel. It asks again after 5 minutes if the agent didn't take it. An admin can ask now: `POST /api/users/{key}/machine/bot-user` (`botctl machine bot-user <user>`).
2. The agent refuses while jobs or logins run, and while an upgrade is being staged. Otherwise it marks itself `setting_up`, and from then until it's done starts no job, login, folder copy or upgrade.
3. It makes the user if it isn't there (`useradd --system --user-group ...`). A unit from before this change can't write `/etc` (`ProtectSystem=strict`), so if `useradd` fails, the agent asks systemd to run it outside the unit (`systemd-run --wait --collect`).
4. It hands the home to the user: it walks it opening each folder inside the last (`openat`, `O_NOFOLLOW`), and changes each file through its own descriptor. It never follows a link (a link itself changes owner), skips files with another hard link (they may be someone else's file), devices, pipes and sockets, and drops setuid and setgid bits. The home is made `0700`.
5. It makes the state folder `0711`, opens up the tools, saves `bot-user.json` (name, uid, gid) in the state folder, and reports `ready`.

On every start the agent reads `bot-user.json` and checks the user is still there with the same uid and gid, and still owns the home (handing it over again if not). systemd makes the state folder `0700` at each start in old units, so the agent makes it `0711` again. If anything doesn't check out, the agent reports `failed` and runs nothing: once botd has asked, no job runs as root again.

Heartbeats carry `bot_user: {state, user, uid, error, at}`; `state` is `setting_up`, `ready` or `failed`. botd keeps it with the agent's upkeep (`GET /api/users/{key}/machine/agent`).

**New machines.** With the setting on, cloud-init's first-boot script makes the user, and the agent's unit has `StateDirectoryMode=0711`. botd still asks after the first heartbeat, to hand over the home.

**Machines already enrolled.** An agent from ADR 0039 or later upgrades to botd's build (`MACHINE_AGENT_UPGRADES=auto`, or an admin), then botd asks as above. An agent enrolled before ADR 0039 can't upgrade itself; reinstall it.

### Routing

With the setting on, a routed run starts only once the machine's Bots' user is `ready`. Otherwise it is refused, and nothing runs on the server or another machine:

| Reason | When |
|--------|------|
| `agent_outdated` | The agent can't do `bot_user` (older than this change). |
| `bot_user_pending` | It hasn't been asked yet, or is setting up: "try again in a few minutes". |
| `bot_user_failed` | Setting up failed; the Bot asks the user to get an admin to look. botd asks again every 30 minutes. |

### Audit

| Event | Meaning |
|-------|---------|
| `machine.bot_user_requested` | botd asked the agent, with `user`. Outcome `failure` with `error` if the agent refused or didn't answer. |
| `machine.bot_user_ready` | A heartbeat showed the Bots' user ready, with `user` and `uid`. Once per change. |
| `machine.bot_user_failed` | Setting it up failed, with `error`. Once per failure. |
| `bot.run_refused` | Now also with reason `bot_user_pending` or `bot_user_failed`. |

## Choices where ADRs met

- **ADR 0036 left a separate OS user for later.** This is it, for machines only. On one server, per-user accounts (ADR 0037) already do the same job.
- **ADR 0039's agent upgrades are the way over** for machines already running. No reinstall, unless the agent is older than ADR 0039.
- **ADR 0041's logins and folder copy** keep their paths and checks. What they write is now the Bots' user's; logins made as root before the switch are handed over with the rest of the home.
- **ADR 0035's firewall** is unchanged: SSH is closed unless `MACHINE_SSH_SOURCES` opens it, and botd's mutual-TLS channel is the way in.
- **No database migration.** The state lives on the machine (`bot-user.json`) and in the agent's upkeep JSON botd already keeps.

## Consequences

- Self-hosting doesn't change. Without `MACHINE_CONTROL_URL` none of this runs; with it, nothing changes unless `MACHINE_BOT_USER=on`. The setting without `MACHINE_CONTROL_URL` is a startup error.
- A Bot on its owner's machine can no longer read the agent's key, change the agent, its unit or the harness CLIs, or reach other files only root can. It can still do anything the machine's network allows, as before.
- It can't be undone by turning the setting off: an agent that has a Bots' user keeps running Bots as it. That is the safe way round.
- Turning it on refuses routed runs on machines whose agent is too old (until upgraded) or still setting up (a few minutes at most).
- Handing over the home can't undo what a Bot did while it was root: a process it left running, or a file it changed outside the home. For full assurance, rebuild the machine (`DELETE` then `POST /api/users/{key}/machine`) with the setting on.
- Files in the home with another hard link stay as they were, and Bots may lose access to them. The agent logs how many it left.
- Tests run the real agent over real mutual TLS on loopback. They can't make users, so there the Bots' user is whoever runs the tests; the same code paths run. They cover:
  - a run refused (`bot_user_pending`) before set-up, never run another way;
  - botd asking once after a heartbeat, the agent setting up, the folder modes, and `machine.bot_user_ready` recorded once;
  - the run going ahead as that user, with `USER` set;
  - asking by hand, the agent view, and a restarted agent keeping it or refusing a user that isn't the one saved;
  - everything being off by default.

  A test as root, run by CI's isolation job, makes a real user and checks: the agent makes it and hands over the home; a link left in the home to a root file isn't written through; a run is that user and can't read the agent's key; the job's files, the folder copy and a login's terminal belong to that user. Unit tests cover the file-identity switch (refused, not ignored, without root), the hand-over never following links, keeping hard links and dropping setuid bits, when botd asks, and the routing refusals.

## Not in this slice

- **Screens on machines.** The viewer for a Bot's screen exists on the server ([computer.md](../computer.md)), not yet for Bots on a machine. The plan: the agent starts Xvfb, Openbox, D-Bus and voxl as the Bots' user (`POST /v1/screens/{bot}`), and serves a raw tunnel to that voxl port (`GET /v1/screens/{bot}/tunnel`, an HTTP upgrade over the same mutual-TLS channel). botd listens on a loopback port in the existing `/screen/69xx/` range and pipes each connection through a pinned tunnel. `GET /api/bots/:id/screen` keeps its Operate check, is audited for machine Bots, and rotates the token on the machine when access narrows. The machine image also needs those programs. Needs this slice first, since a screen must not run as root.
- **One user per Bot** on a machine. All of a machine's Bots belong to one person, so one user is enough for now.
- **Upgrading machines enrolled before ADR 0039**, and per-user containers on one virtualised server, as before.
