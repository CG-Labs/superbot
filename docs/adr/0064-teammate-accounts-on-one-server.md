# 0064: Teammates' own accounts and harness logins on one server

## Status

Accepted (21 Nov 2026). A follow-up on [#30](https://github.com/CG-Labs/superbot/issues/30) (M3, per-user isolation). It closes the "per-teammate logins on one server" item that [ADR 0062](0062-teammate-harness-logins.md) left open. It builds on [ADR 0037](0037-per-user-unix-accounts.md) (per-user accounts), [ADR 0046](0046-shared-bots-under-isolation.md) (isolated shared Bots) and ADR 0062 (teammates' logins on machines).

## Context

What the code did before this change:

- With `ISOLATION=users` (ADR 0037), each user's Bots run as that user's own Unix account, `sb-u-<id>`, with a home of its own where Claude Code and Codex keep their logins.
- With `SHARED_BOTS=isolated` (ADR 0046), Bea's run of Ada's shared Bot gets Bea's access and server-wide keys only. But it still ran as Ada's account, `sb-u-ada`, in Ada's folder. So it could read Ada's harness login files, and Ada's login logged it in. That is the thing ADR 0048 and ADR 0062 stopped on machines.
- On a machine, a teammate has their own OS user and their own login (ADR 0048, ADR 0062). One server had nothing like it.

## Decision

### A teammate gets an account of their own for each owner's Bots

With `ISOLATION=users` and `SHARED_BOTS=isolated`, Bea's run of a Bot Ada owns runs as an account made for that pair, not as Ada's:

- **Name**: `sb-t-<first 24 hex of sha256("<owner id>:<teammate id>")>`. Unix names are at most 32 characters, and two ids don't fit. 96 bits of hash make a collision out of reach.
- **Folders**: `ISOLATION_DIR/<owner>-<teammate>/` with the same layout as a user's (`home`, `workspace`, `memory`, `bots`, `settings`). User ids have no `-`, so the folder can't clash with a user's.
- **Made by the root helper**: `superbot-userctl ensure <owner> <teammate>`. The existing sudoers rule (`ensure *`) already allows it. The helper checks both ids, refuses the same id twice, and derives the name and folder itself. It never takes them from the caller. The account has no login shell, is not in botd's group, and only it can enter its folder. Ada's account can't, and neither can Bea's own `sb-u-bea`.
- **`superbot-run`** accepts `sb-t-` accounts (exactly 24 lowercase hex) as well as `sb-u-`, and still starts only inside the account's own folder.
- **One per pair, not one per teammate.** Bea's account for Ada's Bots is not her account for Cy's Bots, nor her own `sb-u-bea`. A Bot Ada controls can read what's in that account's home. So a login Bea makes there is only ever seen by Ada's Bots, which Bea chose to log in for.
- **The run**: its `HOME`, working folder, Bot state and settings are the pair's. Its token is bound to Bea (`isolation::bot_token_for`, as on machines; a per-run token since [ADR 0083](0083-per-run-tokens.md)) and stops working once the message is no longer hers. Bots that are Bea's own, or a run Ada asked for herself, are unchanged.

`ISOLATION_TEAMMATES=on|off` controls it. Unset means on when `ISOLATION=users` and `SHARED_BOTS=isolated`. `on` without both is a startup error. `off` keeps ADR 0046's behaviour (Ada's account) for anyone who needs time to move. `server.started` reports `isolationTeammates`.

### Without a login of their own, the run is refused

Before a teammate's Claude Code or Codex run, botd checks Bea's login in the pair account's home, **as that account** (`sudo` + `superbot-run` running a small `sh` script: a regular, non-empty file, never a link). So a link Bea's run plants can't reach a file the account couldn't read.

- **A server-wide key** still logs every teammate's run in, as before.
- **Otherwise**, a run with no login is refused with `teammate_not_logged_in`: "I didn't run: Claude Code isn't logged in for you on this server for Ada's Bots. Runs for teammates use their own login, never Ada's." The audit event `bot.run_refused` carries the account and `forUser`. The account is made anyway, so Bea can log in next.
- **It never falls back to Ada's login.** Ada's account and home are not on the run's path at all, so there is nothing to fall back to.

We chose refusing over falling back because falling back is exactly the leak this ADR closes. A run that uses Ada's login acts as Ada's subscription, and Bea's tools can read Ada's token.

### Bea logs in herself, from the same place as on machines

The apps already have ADR 0062's teammate login panel and `/api/machine/teammate/{owner}/harness-login*`. When Ada's Bots run on this server (no control plane, or the route is local), those endpoints act here instead of on a machine:

- `POST harness-login {harness}` makes the pair account if needed, then runs the harness's own login (`claude auth login`, `codex login`) as it, in a terminal on the server. The output streams back the same way and the pasted code is typed in. At most 4 logins run at once.
- `GET harness-logins` reports each harness's state, checked as the account (`on: "server"`). `DELETE harness-logins/{harness}` removes the files as the account, and only removes links, never what they point to.
- Admins use the same admin routes and `botctl machine teammates <owner> logins|logout <teammate>`. An admin can also start one for a teammate with `botctl user harness-login <teammate> <harness> --owner <owner>` (`POST /api/users/{teammate}/harness-login {owner}`), like ADR 0037's own logins. This needs Bea to be able to operate one of Ada's Bots (`offboard::wanted`).
- The Bot's details show the panel (`teammateLogins: true`) with "for Ada's Bots on this server" instead of "on Ada's computer".

### Memory

The Bot's memory is the Bot's (ADR 0046), and its original stays in `DATA_DIR`. A teammate's run gets a fresh copy in the pair's `memory` folder. After the run, what it wrote goes back to `DATA_DIR` if the Bot still has the same owner. Ada's own copy is then dropped, so her next run starts from the new memory. The pair's copy is removed. A copy that can't be saved (over the size limit, or the write fails) is never deleted: it is set aside as `<bot id>.md.unsaved` in the pair's `memory` folder and audited as `bot.memory_unsaved`, for an admin to recover. Ada's `USER.md` is never in the pair's folder.

### Audit

- `isolation.account_created|account_failed` carry `forUser` and the owner as target for a pair.
- `harness.login_started|login_input|login_aborted|login_finished` and `harness.logged_out` carry `forUser`, `account` and `on: "server"`.
- `harness.invoked` carries the run's `runAs` (the pair account) and `forUser`.
- Refusals: `bot.run_refused`, reason `teammate_not_logged_in`, with the harness as detail.

## Alternatives considered

- **Keep running as the owner's account.** Bea's run reads Ada's login and folder. Rejected.
- **Fall back to the owner's login when the teammate has none.** The same leak, only some of the time. Rejected.
- **Run as the teammate's own `sb-u-` account.** Ada's Bot would then reach Bea's own folder and logins, and Bea's other Bots' work. Rejected.
- **One account per teammate across all owners.** Ada's Bots would see a login Bea made for Cy's Bots. Rejected in favour of one per pair.
- **Copy the owner's credential to the teammate.** It is the same token. Rejected.

## Consequences

- Teammates who use Claude Code or Codex on a shared Bot on one server can do so with their own account and quota, without a server-wide key, and their runs can't read the owner's logins or folder or another teammate's.
- An existing install that turns on `SHARED_BOTS=isolated` with `ISOLATION=users` gets this by default. Teammates without a login of their own, and with no server-wide key, are refused until they log in. Set `ISOLATION_TEAMMATES=off` to keep the old behaviour for a while.
- **The trust model**: Bea's login sits in her pair account's home. Runs of Ada's Bots for Bea can read it, and Ada controls those Bots' instructions and memory. Root on the server can read it too. So logging in is Bea's choice, per owner. The panel says so.
- The tests: unit and HTTP tests in `server/`, and the as-root `isolation` job in CI (`deploy/test-isolation.sh`). It makes a pair account and checks its folder, that neither the owner's nor the teammate's own account can enter it, and that bad arguments are refused. Then it runs botd's real run path: Bea's run without a login is refused; she logs in as the pair account; her run reads her login and can't read Ada's login, home, workspace, memory or `USER.md`, Cy's pair, her own `sb-u-` login, or botd's data. Ada's run can't read Bea's login.

## Limits and follow-ups

- **Removing pair accounts when a teammate leaves.** ADR 0052 does this on machines. On one server, [ADR 0066](0066-removing-teammate-accounts-on-one-server.md) does it.
- **The network is shared**, as for every account on one server (ADR 0037). Egress limits are M5.
- **Pi and Hermes** use API keys. There is nothing to log in.
- **Team accounts and team machines** remain open on #30.
