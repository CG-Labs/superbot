# 0046: Shared Bots under per-user isolation

## Status

Accepted (20 Nov 2026). A follow-up on [#30](https://github.com/CG-Labs/superbot/issues/30) (M3, per-user isolation): "where shared team Bots run", open question 1 in the [roadmap](../ROADMAP.md). It builds on [ADR 0017](0017-bot-acls.md) (Bot owners, sharing, grants), [ADR 0029](0029-per-user-isolation.md) (per-user isolation), [ADR 0036](0036-bots-on-the-users-machine.md) (Bots on the user's machine), [ADR 0043](0043-bots-own-os-user-on-machines.md) (Bots' own OS user on machines) and [ADR 0044](0044-client-personal-secrets.md) (whose secret a run gets), and changes ADR 0044's rule for one case.

0045 is taken by screens on machines (PR #103, #29), so this is 0046.

## Context

A Bot has one owner and is private or shared, with viewer and operator grants (ADR 0017). With `MACHINE_ROUTING` on, it runs on its owner's machine (ADR 0036), as the one `superbot-bots` user there that all the owner's Bots share (ADR 0043). Until now a Bot acted as its owner for everyone: when Bea used Ada's shared Bot, the run had Ada's access to other Bots, Ada's personal keys and Ada's facts (`USER.md`). So through Ada's shared Bot, Bea could ask Ada's private Bots things, spend and leak Ada's keys, and read Ada's facts. On one self-hosted server for one team that is the trust people expect. On a managed server where each person has their own computer, it isn't.

## Decision

### Where a shared Bot runs: always its owner's computer

A shared Bot runs where its owner's Bots run: on the owner's machine, or in the owner's folder (and Unix account, ADR 0037) on the server. Never on the asker's machine, never on the server instead of an assigned machine, and there is no team machine yet. `route::target` already looks this up by owner only; this ADR keeps that.

For a team Bot that should not depend on one person, make it with a team account (a user who stands for the team, with its own machine), not with a person's account.

### `SHARED_BOTS=open|isolated`

| Setting | Default when | What a run for someone other than the owner gets |
|---|---|---|
| `open` | `MACHINE_ROUTING=off` (self-host) | As before: the owner's access, keys and facts |
| `isolated` | `MACHINE_ROUTING=assigned` or `on` | Below |

`open` with routing on is a startup error: Bots on people's own computers need isolated shared Bots. Self-hosts can opt in with `SHARED_BOTS=isolated`. Self-host behaviour is unchanged by default.

### Isolated: a run is for someone, and gets no more than they could reach

Each run is **for** a person: whoever sent the chat message; for anything a Bot sends or asks with its token (a message, an `ask`), whomever that Bot's run is for (through any number of Bots); for a reply that comes back later, whomever the question was for; for a routine, whoever last wrote its instruction (`routines.author_id`, new); otherwise the owner. When that person isn't the owner, the run is a **teammate's run**:

| | Owner's own run | Teammate's run |
|---|---|---|
| Runs on | Owner's computer | Owner's computer |
| Working folder, memory | Owner's folder, the Bot's memory | Same |
| Access to other Bots | Owner's | The lesser of the owner's and the teammate's, Bot by Bot |
| Keys | Server-wide, then the owner's own | **Server-wide only** |
| Harness logins on the owner's machine | Yes | Yes (see Limits) |
| Owner's facts (`USER.md`) | In the prompt, sent to the machine and back | **Left out**: not in the prompt, not sent, not collected |
| Prompt | As before | Says whom it's for, and not to open or pass on the owner's private files |
| Harness session | Resumes the Bot's | **Fresh, and not kept**: the owner's holds their conversation, and some harnesses (Codex) keep a session's first instructions |
| Can make new Bots | Yes (owner's role allowing) | No (403) |

Admins count as teammates here: an admin's run of Ada's Bot gets no Ada keys, as admins never see personal values (ADR 0044).

**The cap.** botd keeps whom each Bot's latest run is for. A Bot's token then acts with `owner.within(asker)`: on each Bot, the lesser of what the owner and the asker can do. It applies to every route a Bot calls (`/api/bots`, messages, routines, `ask`, approvals, the event stream, the "Other Bots" list in the prompt). Bea's run of Ada's shared Bot can't see Ada's private Bots, nor Bea's private ones (Ada can't see those). It stays after the run, so whatever the run left behind is still capped until the owner's next run.

**Routines.** A routine runs for whoever wrote its instruction. Creating one sets its author; changing its instruction makes the editor its author; renaming or rescheduling doesn't. The instruction and its author are written together, so the scheduler never reads one without the other. Routines from before have no author and run for the owner, as they did. A routine made by a Bot is authored by whomever that Bot's run is for.

**Before each run** botd refuses it, gives back what it took, and audits why:

- `owner_disabled`: the owner is disabled. Their Bots don't run for anyone, routines included; a firing routine says so once, not on every firing.
- `asker_lost_access`: the person the run is for can no longer operate the Bot, e.g. a routine of someone whose grant was revoked.

**When the owner's machine is down.** The run is refused as before (ADR 0036), never moved. A shared Bot's chat is read by everyone who can see the Bot, so a teammate's run says whose computer it is and that it isn't ready ("I run on Ada's computer, and it isn't reachable right now"), with no errors, addresses, versions or commands; the owner's own run of a shared Bot keeps "your computer" but drops error text and versions. The machine's own words stay in the admin-only audit event (`details.detail`).

**New Bots are private** unless made shared, so sharing is a choice.

### Seeing it

Bot views add `runsOn` (`server`, `machine` or `nowhere`, when routing isn't off) and `sharedBots: "isolated"`. The client's Bot details say where it runs ("Runs on Ada's computer") and, when isolated, whose keys a run uses ("For you it uses the server's keys and your access, never Ada's own").

### Audit

| Event | New |
|---|---|
| `harness.invoked`, `bot.run_routed`, `bot.run_refused` | `forUser` on teammates' runs |
| `bot.run_refused` | Reasons `owner_disabled`, `asker_lost_access`; `detail` (the machine's error, version or state) on machine refusals |
| `access.denied` | Reason `asker_acl` (with `forUser`): the owner could, the asker can't |
| `routine.created` | `author` |
| `routine.updated` | `changes.author` when it moves |
| `server.started` | `sharedBots` |

## Alternatives considered

- **Run on the asker's computer.** The Bot's memory, folder, logins and session are the owner's, and machine agents refuse jobs for anyone but their owner (ADR 0036). Moving it would copy the owner's data to someone else's machine. No.
- **Run on the control plane.** A shell on the server that holds every user's data and the master key, for any shared Bot. No.
- **A team machine.** Right for real teams, but there is no team entity yet (owners are people). Deferred; a team account with its own machine gets most of it today.
- **The asker's keys.** ADR 0044's reasons still hold: the owner controls the Bot, so the asker's key would be exposed to them. Server-wide keys only is the one choice that exposes nobody's personal key.
- **Keep the owner's access for teammates** (as before). It lets anyone with operator access reach the owner's private Bots through a shared one. Kept only for `open`.
- **Check the asker's access per request with no saved asker.** A Bot's token names the Bot, not the run; botd needs to know the run's person anyway. Per-run tokens are a follow-up.

## Consequences

- ADR 0044's table changes when isolated: "Bea, through sharing or a grant" and "Bea's Bot, through `ask`" now get server-wide keys only. Open servers are unchanged.
- A teammate's run can fail where the owner's works: no login on the owner's machine and only the owner's own key means `harness_not_logged_in` for teammates. The message says an admin can log it in or save a server-wide key.
- Bots' memory is shared by everyone who uses the Bot, as before. The prompt says to keep private details out of it.
- Migration 18 adds `routines.author_id`.
- Tests on the real router (`shared_bots_http_tests.rs`): a teammate's run gets no owner key, fact or private Bot by any route (list, messages, routines, ask, new Bots), all audited; Bot-to-Bot chains and late replies keep the asker; routines run for their author and stop when the author loses access; a disabled owner's Bot doesn't run; self-host stays open; with routing on, a teammate's run goes to the owner's machine without the owner's keys or facts, never to the teammate's or another machine, and says whose computer it is without its errors.

## Limits and follow-ups

- **One trust domain on the owner's computer.** A teammate's run is still a shell on the owner's computer, as the owner's Bots' user (ADR 0043). Its tools can still open the owner's folder, other Bots' files and the harness logins there; botd only keeps the owner's keys and facts out of it and tells it not to. A separate OS user and home for teammates' runs on the machine, with their own logins, is the follow-up. Done, without the logins, behind `MACHINE_TEAMMATE_USERS=on` in [ADR 0047](0047-teammates-own-os-user-on-machines.md), which also binds those runs' tokens to the teammate and gives each person their own screen.
- **Team accounts and team machines** as first-class things, not a convention.
- **Per-run tokens**, so a token names the run's person, not only the Bot, and the cap needs no saved state.
- **A session per person**, so a teammate's chat with a shared Bot carries on between messages; today each teammate's run starts fresh.
- **Owner approval for risky steps in teammates' runs**, whatever the Bot's approval mode.
- **Open servers**: a disabled owner's shared Bots still run there (and stay a SCIM-05 follow-up).
- The event stream re-checks access every few seconds, so a cap takes up to that long to apply to an open stream.
