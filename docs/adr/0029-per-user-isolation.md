# 0029: Per-user isolation (one computer per user)

## Status

Accepted. First slice of [#30](https://github.com/CG-Labs/superbot/issues/30) (M3). It follows the owner's decision of 19 Nov 2026 ([roadmap](../ROADMAP.md#decisions-19-nov-2026), decision 1): one computer per **user**, not per Bot; a user's Bots share it. It builds on [ADR 0017](0017-bot-acls.md) (Bot owners and ACLs), [ADR 0010](0010-secrets.md) (secrets), [ADR 0012](0012-users-sessions-rbac.md) (roles), [ADR 0019](0019-audit-actors.md) (audit actors) and [ADR 0025](0025-control-plane-linode.md) (one machine per user). It fixes AUTH-07 in the [auth review](../security/auth-review-2026-11.md). Routing modes, machine assignment and running Bots on the machine: [ADR 0036](0036-bots-on-the-users-machine.md).

## Context

ADR 0017 gave every Bot an owner and kept other people out of its chat, routines, screen and approvals. Under the API, though, every Bot still shared one computer:

- one working folder (`WORKSPACE_DIR`) and one `USER.md`, so user A's Bot could read user B's files and facts;
- one set of harness keys, so B's Bot spent A's API key;
- one Bot token for every run, and the Bot named itself with a header (AUTH-07), so one Bot could act as another;
- a Bot's token got the Bot role whoever owned it, so a read-only user's Bot could write.

Managed hosting will give each user a machine (ADR 0025). This ADR says what lives where, how work gets to the right machine, and what a single self-hosted server does until then.

## Decision

### What lives where

| Control plane (botd, the org's server) | Each user's computer |
|--------|---------|
| Users, roles, sign-in, sessions, SSO, SCIM | That user's Bots' runs (harness processes) |
| Bot records: owner, visibility, grants, settings | The user's working folder, shared by their Bots |
| Chat history, routines, approvals, policy | Harness logins and sessions (`~/.claude`, `~/.codex`, ...) |
| Audit log, billing, machine records | Screens (X displays, noVNC) |
| Secrets, sealed with the master key; sent to a run as env | Bot memory and `USER.md` once runs move there |

The control plane decides; the computer does. Every check (who may see or run a Bot, approvals) stays in the control plane, so a compromised computer can harm only its own user.

### Routing: the owner's machine

A Bot runs where its **owner's** computer is, whoever asked. A shared Bot that Bea uses is still Ada's Bot: it runs on Ada's computer, with Ada's folder and keys. That is what "shared" means (ADR 0017): Bea may use it, not move it.

`machines::route::target(db, control_plane, owner)` gives the target:

- `MACHINE_ROUTING=off` (default): `Local`, this server, in the owner's folders (below).
- `MACHINE_ROUTING=on`: the owner's machine, only when it is `running`. No machine, or one being built or suspended, is a refusal. It never falls back to this server or to another user's machine.

The runner asks before every run. A routed run hands a `Job { bot, owner, message }` to a `MachineLink` and audits `bot.run_routed`. A refusal posts a plain reason in the chat ("you don't have a computer…") and audits `bot.run_refused` with `no_machine`, `machine_not_ready` or `machine_unreachable`.

`MachineLink` is the seam the machine agent plugs into. The only real one today is `Unenrolled`, which refuses every job: until machines enroll over mutual TLS, botd can't send them work. So `MACHINE_ROUTING=on` needs `LINODE_TOKEN` and today refuses every run; leave it off. Tests use a recording link and a fake provider, with no Linode calls.

### The trust boundary

- **People** are checked by role (RBAC) and then by Bot ACL, as before.
- **Bots** get their own token per run: `sbb_<bot id>.<owner id>.<HMAC-SHA256>` over both, with a key made fresh at each start. botd checks it in constant time. A made-up token, another Bot's id with this Bot's MAC, a token from an earlier start, a deleted Bot's token, or one from before the Bot changed hands is a 401.
- **Handing a Bot over** stops its current and queued work: that work started in the old owner's folder with their keys. A Bot's live stream closes when the Bot is deleted, changes hands, or its owner is disabled, and follows its owner's role.
- **A Bot is who its token says.** An `X-SuperBot-Bot` header naming a different Bot is a 403 (`bot_mismatch`). `from` in `ask`, `handoff` and `approvals/check` must be the Bot itself (left out, it means itself). A Bot asking for another Bot's approval check gets `deny`.
- **A Bot can do no more than its owner.** Its role is capped by its owner's: a read-only user's Bot can't write (403, `owner_role`). A disabled owner's Bot can do nothing.
- **A Bot sees what its owner sees.** It reaches Bots through its owner's ACL: its own, its owner's other Bots, and Bots shared with its owner.
- **Secrets.** Each user can keep secrets of their own (`/api/me/secrets`). They reach only Bots that user owns, laid over the server-wide secrets. People can't save names botd itself uses (`PATH`, `BOT_TOKEN`, `LINODE_TOKEN`, `SSO_*`, ...). Values are never returned, only names. Admins can list a user's names and delete them all (`/api/users/{id}/secrets`). Each value is sealed with its user and name, so a row copied to another user doesn't open. A user's values are redacted only where their own Bots write (their chats, approvals, audit events, and messages their Bots send others), not from everyone's text: any member can save any value, and must not be able to erase words from other people's chats.

### Self-hosting on one server

One server plays both parts. It keeps one service account; isolation is by owner in the API and on disk:

| Thing | Where |
|-------|-------|
| A user's working folder | `WORKSPACE_DIR/users/<user id>/`, the Bot's working directory for every run |
| A user's facts | `DATA_DIR/users/<user id>/USER.md` |
| A Bot's memory | `DATA_DIR/bots/<id>/` (unchanged) |
| A user's harness keys | Their secrets, as env for their Bots only |

The approval policy counts the owner's folder as the workspace, so a delete in another user's folder counts as outside it. No API route serves files, so there is no HTTP path to another user's folder.

**Upgrading.** On first start, botd moves the old shared workspace and `USER.md` into the operator's folders (`users/operator/`), because every Bot was the operator's before ADR 0017. It writes a marker (`.superbot-layout`) and finishes a move a crash cut short. `DATA_DIR` never moves: a folder holding it stays put, and when `DATA_DIR` is the workspace itself nothing moves. Claude Code keys sessions by folder, so a Bot starts a fresh session after the move; memory files keep its context.

**Docker and the bash install** need no change. The backup script also copies `DATA_DIR/users`; the Docker archive already has all of `DATA_DIR`.

### Hosting options this maps to

- **One server, one account (today).** As above. Safe against the API and other users' Bots' tools only as far as the approval policy reaches; see Deferred.
- **One server, one Unix account per user.** The same folders, owned by per-user accounts, with each run started as its owner's account. Next step for single-host OS isolation.
- **One container per user** on a virtualised server, or **one VM per user** (Linode). The folders move into the user's computer; `MachineLink` carries runs there.

## Consequences

- AUTH-07 is fixed: one Bot can't act as another or exceed its owner.
- A user's Bots can't see another user's files, facts, keys, chat, screens or approvals through any route. A test walks every Bot, routine and approval route as another user, a read-only user and another user's Bot.
- botctl stops sending `X-SuperBot-Bot`; its token says who it is.
- Bot tokens die on restart. Runs don't outlive a restart anyway (they're reported as interrupted).
- New audit events: `bot.run_routed`, `bot.run_refused`; `secret.set` and `secret.deleted` carry `scope: "user"`; `access.denied` adds `bot_mismatch` and `owner_role`; `auth.login_failed` adds `bot_gone` and `bot_moved`.

## Deferred

- **OS isolation on one server** and **per-user harness logins**: done, behind `ISOLATION=users`, in [ADR 0037](0037-per-user-unix-accounts.md). With it off, all Bots run as one account and share its harness logins, as above.
- **Per-user screens.** Screens are per Bot and gated by ACL; the X displays share one account.
- **The machine agent.** Enrollment and mutual TLS are done ([ADR 0031](0031-machine-enrollment-mtls.md)); next, the run protocol behind `MachineLink`, then moving each user's folders, memory and logins onto their machine (#29).
- **Shared team Bots.** They run on their owner's computer. A team-owned computer is a later decision.
- **SCIM-05.** A disabled user's Bot can't use the API (its token can do nothing), but its routines still run; pausing or handing them over is open.
- **Client UI** for `/api/me/secrets`: done, the client's Your secrets screen ([ADR 0044](0044-client-personal-secrets.md)).
