# 0062: Teammates' own harness logins on the owner's machine

## Status

Accepted (21 Nov 2026). A follow-up on [#30](https://github.com/CG-Labs/superbot/issues/30) (M3, per-user isolation). It closes the "per-teammate harness logins" item that [ADR 0048](0048-teammates-own-os-user-on-machines.md) left open. It builds on [ADR 0041](0041-machine-harness-logins-and-folder-copy.md) (harness logins on machines), [ADR 0046](0046-shared-bots-under-isolation.md) (isolated shared Bots) and [ADR 0052](0052-teammate-offboarding-on-machines.md) (removing teammates' users). Numbered 0062 because [ADR 0061](0061-approval-notifications.md) took 0061 on `main` first.

## Context

What the code did before this change:

- With `MACHINE_TEAMMATE_USERS=on` (ADR 0048), Bea's run of Ada's shared Bot goes to Ada's machine as Bea's own OS user, `superbot-t-<12 hex>`, with a home of her own (0700).
- Claude Code and Codex log in through files in `HOME`. With `MACHINE_HARNESS_LOGINS=on` (ADR 0041), the machine's logins live in the Bots' home, and only Ada logs them in. Bea's user can't read them, which is the point.
- So Bea's Claude Code or Codex run was refused (`teammate_no_key`) unless an admin had saved a server-wide key. Pi and Hermes need no login there (they use API keys).
- The apps had no way to see or manage a harness login. The console and `botctl` could manage only Ada's own.

## Decision

### Bea logs in with her own account, as her own user, in her own home

With `MACHINE_HARNESS_LOGINS=on` and `MACHINE_TEAMMATE_USERS=on`, a teammate who can run one of Ada's Bots can log Claude Code or Codex in on Ada's machine with their own account.

- **The flow is ADR 0041's**: the harness's own `auth login` (or `login`) runs in a terminal on the machine, its output streams back, and the code the person pastes is typed in. The same recipe, the same timeouts, nothing typed is kept or audited.
- **The agent runs it as Bea's user, in Bea's home.** `LoginRequest` and `ForgetRequest` carry an optional `for_user`. The agent makes or checks Bea's user exactly as for her runs (`Teammates::ensure`), with her uid, her `HOME` and her terminal. The saved credential file is hers, inside her 0700 home.
- **One login per person per harness.** Ada and Bea can each log Claude Code in at the same time. The agent runs at most 4 logins at once.
- **Botd's API, for the teammate themselves** (`/api/machine/teammate/{owner}`): `POST harness-login` (a stream of events), `POST harness-login/{id}/input`, `DELETE harness-login/{id}`, `GET harness-logins`, `DELETE harness-logins/{harness}`. Reading needs `account`, changes need `write`. Bots are refused.
- **Who counts as a teammate** is what ADR 0052 already uses to keep a teammate's user (`offboard::wanted`): an active person, not the owner, who can operate one of the owner's Bots. Anyone else gets the same 404 as for an owner who doesn't exist.
- **Admins** see and log out a teammate's logins with `GET /api/users/{owner}/machine/teammates/{teammate}/harness-logins` and `DELETE .../harness-logins/{harness}`, and `botctl machine teammates <owner> logins|logout <teammate> [<harness>]`. Only the teammate logs in as themselves.
- **The apps**: a shared Bot's details show "Your Claude Code login" for teammates when the server sends `teammateLogins: true`. That is when logins and teammates' users are on, the Bot runs on its owner's machine, and its harness has a login. The panel shows the state, runs the login (with the link it prints and a box for the code), and logs out.

### A teammate's run uses their own login, never the owner's

Before a teammate's Claude Code or Codex run, botd asks Bea's user on the machine (`PUT /v1/teammates/{user}`, now with the login files to check). The agent answers with Bea's login states, checked as Bea's user in her home.

- **A server-wide key** still logs every teammate's run in, as before.
- **Otherwise** the run goes ahead only if Bea's own login there is `logged_in`. A login still running doesn't count. Else it is refused with `teammate_not_logged_in`: "Claude Code isn't logged in for you on Ada's computer. Runs for teammates there use their own login, never Ada's." Ada sees the same reason in the audit log.
- **Ada's login never counts for Bea**, and Bea's never counts for Cy. botd reads only the state Bea's own user reported for her.
- **An agent older than this** (no `teammate_logins` capability) keeps the old answer, `teammate_no_key`. botd sends `for_user` only to agents that advertise it.

### Isolation

- **Sessions are per person.** botd's login sessions record whose login each is. Ada can't type into or stop Bea's login through her own login API, and an admin can't through Ada's. Cy can't through his.
- **States are checked as the teammate's user.** The agent reads Bea's state as Bea's uid, so a link Bea plants can't reach a file her user couldn't read. A link Cy plants to Bea's file counts for nothing, because Cy's user can't open Bea's home. Logging out removes files as that user too, and only removes links, never what they point to.
- **The owner's heartbeat** reports only Ada's own logins, never her teammates'.
- **Asking never makes a user.** Botd's status call uses `GET /v1/teammates/{user}/logins`, which reports "logged out" for a teammate with no user yet and never creates one. Starting a login does make one, as a run would.
- **A teammate leaving** (ADR 0052) stops any login of theirs still running, and removing their home deletes the login.
- **Tested** end to end over mTLS (Bea's login lands in her home, not the Bots' or Cy's; nobody else can type into it, see it as theirs or remove it; only Bea's runs use it). An as-root test in CI's isolation job checks that Cy's user and the Bots' user can't read Bea's file and that Cy's planted link counts for nothing.

### Audit

The existing events gain who the login is for: `machine.harness_login_started|input|aborted|finished` and `machine.harness_logged_out` carry `forUser` and `teammateUser` for a teammate's login. Refusals are `bot.run_refused` with reason `teammate_not_logged_in` and the harness as detail.

## Alternatives considered

- **Use the owner's login for teammates.** That is what ADR 0048 set out to stop: Bea's runs could act as Ada's account, and Bea's tools could read Ada's token. Rejected.
- **Copy the owner's credential into the teammate's home.** It is the same token, so it has the same problem. Rejected.
- **Only server-wide keys.** That works for self-hosts that pay for one key, but it bills every teammate's run to one account and doesn't fit people who use their own subscriptions. Kept as the fallback.
- **Per-teammate logins on one server (`ISOLATION=users`, ADR 0037).** There, a teammate's run of a shared Bot still runs as the owner's `sb-u-` account (ADR 0046). A login of the teammate's own first needs per-teammate accounts for shared Bots on the server. Left as a follow-up.

## Consequences

- Teammates who use Claude Code or Codex on a shared Bot that runs on its owner's machine can do so without a server-wide key, under their own account and quota.
- **The trust model**: Bea's login sits in her home on Ada's machine. Bea's runs of Ada's Bot can read it, and Ada controls that Bot's instructions and memory. Root on the machine can read it too. So logging in there is Bea's choice, made per machine. The panel says it is her own login on Ada's computer. Her login is deleted when she leaves the team (ADR 0052) or logs out.
- When Bea starts a login, her user is made on the machine if it isn't there yet, just as her first run would make it. A refused run may also have made it already.
- botd and old agents interoperate. An old agent ignores the new query and never gets `for_user`, and its teammates' runs keep the old refusal.

## Limits and follow-ups

- **One server**: per-teammate logins under `ISOLATION=users` need per-teammate accounts for shared Bots there (see above). Done in [ADR 0064](0064-teammate-accounts-on-one-server.md).
- **Pi and Hermes** still use API keys. There is nothing to log in.
- **Team accounts and team machines** remain open on #30.
