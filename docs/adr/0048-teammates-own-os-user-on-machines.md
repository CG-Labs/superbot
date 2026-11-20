# 0048: Teammates' own OS user on machines

## Status

Accepted (20 Nov 2026). A follow-up on [#30](https://github.com/CG-Labs/superbot/issues/30) (M3, per-user isolation). It closes the first limit of [ADR 0046](0046-shared-bots-under-isolation.md) ("one trust domain on the owner's computer") and builds on [ADR 0036](0036-bots-on-the-users-machine.md) (Bots on the user's machine), [ADR 0043](0043-bots-own-os-user-on-machines.md) (Bots' own OS user there) and [ADR 0045](0045-screens-on-machines.md) (screens there). Numbered 0048 because [ADR 0047](0047-disabled-users-routines.md) (disabled users' routines) took 0047 on `main` first.

## Context

What ADR 0046 does today, checked in the code before this change:

- A run of Ada's shared Bot for Bea (`for_other` in `runner.rs`) goes to Ada's machine, as the one `superbot-bots` user all of Ada's Bots share. Its `HOME` is the Bots' home, and its working folder is Ada's `work/`.
- botd keeps Ada's personal keys and `USER.md` out of the job, starts a fresh session and caps the Bot's access with the `askers` map. It also tells the harness not to open Ada's files.
- Nothing stops the run's tools from reading Ada's folder, her harness logins (`~/.claude`, `~/.codex`), other Bots' files and their memory. ADR 0046 names a separate OS user for teammates as the follow-up.
- The run also carries the Bot's token. That token is the same for every run of the Bot, so anything Bea's run leaves behind gets Ada's full access back as soon as Ada runs the Bot again.
- Screens are one per Bot, as `superbot-bots`, and Xvfb takes any local client. So Bea can watch Ada's screen, and Ada can watch Bea's, and any user on the machine can connect to either display.

## Decision

### `MACHINE_TEAMMATE_USERS=on|off`, off by default

The setting needs `MACHINE_CONTROL_URL` and `MACHINE_BOT_USER=on`, so the owner's own runs are never root. Teammate users exist only with isolated shared Bots. Routing on already forces `SHARED_BOTS=isolated`, and with routing off no run goes to a machine. Off, every path below is skipped: runs, screens and tokens behave as they do with ADR 0046. Self-hosts and existing machines change only when an admin sets it.

### A teammate's run is their own user, in their own home

With the setting on, a run of Ada's shared Bot for Bea goes to Ada's machine as Bea's own unprivileged user, `superbot-t-<12 hex of sha256(Bea's id)>`. The name is stable, and it fits the 32-character limit without exposing the id.

- **Before each run**, botd asks the agent with `PUT /v1/teammates/{user}` (`owner_id` in the body) over mTLS.
- **The agent** (`machines/teammates.rs`):
  - makes the user if needed (`useradd`, no login shell);
  - records its uid and gid in `teammates.json` (0600, in the state folder), and removes a user it just made if that record can't be written, so a later try isn't refused;
  - refuses an existing user it didn't record, root, its own uid, and the Bots' uid or gid;
  - makes the home `<state>/teammates/<user>` (`SUPERBOT_TEAMMATES`, 0711 root, apart from the Bots' home), 0700 and owned by that user, with `work/` and `bots/` inside;
  - refuses a home that is a link or belongs to someone else, and never follows one;
  - answers with the home's paths.
- **The job** (`JobRequest.for_user`) runs as that user, with `HOME`, `USER` and `LOGNAME` set to it. Its files, collects and working folder must lie inside that home: a teammate's job naming the Bots' home is refused, and so is an owner's job naming a teammate's home.
- **Harnesses** come from the agent's tools folder, which every user there may read. The Bots' home stays 0700 to the Bots' user.
- **botd** sends the teammate's job a working folder of `<home>/work`, the Bot's state in `<home>/bots/<bot>`, and no `USER.md` (as ADR 0046 already does). Approval checks judge it by that home.

A run is refused, never sent as the Bots' user, when:

| Refusal | When |
|---|---|
| `agent_outdated` | The agent doesn't say `can: teammates`. Upgrade it (ADR 0039). |
| `teammate_user_failed` | The agent couldn't make the user. Its words are in `detail` for admins only. |
| `teammate_no_key` | The harness has a machine login (Claude Code, Codex) and there's no server-wide key. The machine's logins live in the Bots' home, which the teammate's user can't read. |

What the Bot tells the people using it names whose computer it is, as in ADR 0046. It doesn't include the machine's errors.

### What a teammate's run keeps can't come back as the owner

A teammate-user run's `BOT_TOKEN` is bound to the teammate: `sbb_<bot>.<owner>.<teammate>.<HMAC>`, signed over all three. botd accepts it only while the Bot's latest run is still that teammate's (`App::acting_for`). Once Ada or anyone else runs the Bot, it's refused (`auth.login_failed`, reason `run_over`). So a process Bea's run left on the machine can't use the Bot with Ada's access after Ada's next run. A live-update stream it opened earlier closes at that point too; it never moves over to Ada's access. Ada's own token, and everything with the setting off, is as before.

### Screens are per person

With the setting on, each teammate who uses a shared Bot on a machine gets their own screen of it.

- **Where it runs**: as their own user, in their own home. Its display and port are its own, and it's kept under `<bot>@<user>` on botd and the agent. The agent's screen routes take `for_user` (PUT body) or `?for=` (DELETE, tunnel).
- **X cookies**: every display on such a machine takes an X cookie (MIT-MAGIC-COOKIE-1, `-auth`), written 0600 in that user's home. The owner's screen gets one too, so no OS user there can open another's display. Runs get `XAUTHORITY`. A screen started before the setting was turned on, without a cookie, is replaced on next use.
- **Who sees which**: `GET /api/bots/:id/screen` gives the caller their own screen. The owner gets the owner's. A teammate gets theirs, made on first view, after the same Operate check as before. A Bot token gets the screen of the person its latest run is for. Admins get the owner's, or a teammate's with `?for=<user>`. Anyone else asking for `?for=` is refused (403), and with the setting off `?for=` is a 400.
- **Losing access**: a teammate who can no longer operate the Bot loses their screen. Narrowing access closes it with reason `access_lost` instead of giving it a new token. So do the reaper and a new viewer connection. The owner's screen gets a new token as before.
- **Admin view**: admin listing and closing (`/api/users/{key}/machine/screens`) show `forUser`. Closing a Bot's screens closes everyone's.

### Audit

| Event | New |
|---|---|
| `machine.teammate_user_created` | A teammate's user was made on a machine: `owner`, `forUser`, `user`, `uid`, and `messageId` when a run asked |
| `bot.run_routed`, `harness.invoked` | `teammateUser` on teammate-user runs |
| `bot.run_refused` | Reasons `teammate_user_failed` (with `detail`) and `teammate_no_key` |
| `auth.login_failed` | Reason `run_over`: a teammate's token after their run was over |
| `machine.screen_*` | `forUser` on a teammate's screen; `machine.screen_closed` reason `access_lost` |

## Alternatives considered

- **A user per Bot, or per run.** A per-run user would leave nothing behind, but makes a user and home for every message and loses the teammate's working files between runs. A per-Bot user doesn't separate teammates from each other. Per teammate, per machine, matches what's being protected: one person's view of another's computer.
- **Containers or namespaces for teammates' runs.** These are stronger, and per-user containers are on the roadmap for everyone's runs. They'd need the container stack on every machine first. An OS user is what ADR 0043 already uses and what the agent can do today, and it doesn't rule containers out later.
- **Give teammates the owner's logins.** Copying `~/.claude` into the teammate's home hands Ada's subscription to Bea. Server-wide keys are ADR 0046's choice for exactly this reason.
- **Run teammates' jobs on the teammate's own machine.** Rejected in ADR 0046: the Bot's memory, folder and session are the owner's.
- **One shared screen with a cookie only.** A cookie stops other OS users connecting, but Bea and Ada would still watch and drive each other's work.
- **Per-run tokens for everyone.** That would cover owners' runs too. Binding only teammate-user runs closes the gap this ADR opens without changing every token.

## Consequences

- With the setting on, a teammate's run can no longer read the owner's folder, harness logins, other Bots' state or the agent's files. The root test proves this with real users (`machines_teammates_tests::as_root_...`, in CI's isolation job).
- With the setting on, a teammate's run of a Claude Code or Codex Bot needs a server-wide key; Pi and Hermes use API keys anyway. The message says so.
- A teammate's working files persist in their home on the owner's machine, which the owner's machine holds. Root on that machine (the agent, an admin) can read them, as with everything there.
- New code:
  - botd: `machines/teammate.rs`, the `MachineLink::teammate` step, `isolation::bot_token_for`, and per-user keys in `machines/screens.rs`.
  - Agent: `machines/teammates.rs`, `PUT /v1/teammates/{user}`, `JobRequest.for_user`, and `ScreenRequest.for_user` / `xauth`.
  - All fields are optional on the wire, so older agents and botds still talk.
- Tests:
  - On the router with a stand-in machine (`shared_bots_http_tests.rs`): paths, keys, the bound token, refusals and audit.
  - End to end over mTLS with the real agent (`machines_teammates_tests.rs`, `machines_screens_tests.rs`): homes, agent-side path checks, per-person screens with the ACL, and screens closing on lost access.
  - The display stack: cookies, and screens kept apart.
  - Off-by-default checks in each.

## Limits and follow-ups

- **No harness logins for teammates.** Only server-wide keys work for Claude Code and Codex. Per-teammate logins on the owner's machine are a follow-up, if wanted at all.
- **Teammate users are never removed.** A teammate who leaves, or loses every shared Bot of the owner's, keeps an idle user and home on that machine. Removing them on deprovisioning (SCIM) or on access loss is a follow-up.
- **`/tmp` and the network are shared** with the owner's Bots' user, as for any two users on one host. A private `/tmp` and egress limits come with per-user containers (M5).
- **Memory stays shared**, as ADR 0046 decided. The Bot's `MEMORY.md` goes to the teammate's run and comes back.
- **Harnesses installed only in the Bots' home** (not the tools folder) can't run for teammates. The check passes, but the job fails to start. Agent-installed harnesses are in the tools folder.
- **Quotas.** A teammate's home counts against the owner's disk.
