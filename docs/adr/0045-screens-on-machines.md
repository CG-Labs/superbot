# 0045: Bots' screens on their owner's machine

## Status

Accepted. Next slice of [#29](https://github.com/CG-Labs/superbot/issues/29) (M3). Builds on [ADR 0008](0008-client-screen-auth.md) (screen auth in the client), [ADR 0031](0031-machine-enrollment-mtls.md) (enrollment, mutual TLS), [ADR 0035](0035-machine-firewall-auto-enroll.md) (firewall), [ADR 0036](0036-bots-on-the-users-machine.md) (Bots on their owner's machine), [ADR 0039](0039-machine-harnesses-and-agent-upgrades.md) (agent upgrades), [ADR 0041](0041-machine-harness-logins-and-folder-copy.md) (logins, folder copy) and [ADR 0043](0043-bots-own-os-user-on-machines.md) (the Bots' own user).

## Context

Since ADR 0036, a Bot whose owner is routed to a machine runs there, but its screen (Xvfb, Openbox, D-Bus, voxl; `docs/computer.md`) could only start on botd's server. That screen shows the wrong computer: the Bot's browser and files are on the machine. ADR 0043 named the design: the screen runs on the machine as the Bots' user, tunnelled to botd over the agent's mutual-TLS channel, behind the same Bot checks and audit.

Constraints:

- The machine's firewall (ADR 0035) lets in only the agent's port, from botd. No new inbound port.
- A screen must never run as root, and never show another user's machine or botd's own display in place of the machine's.
- The web app and the Expo client open `GET /api/bots/:id/screen`'s `/screen/<port>/?token=` link through the proxy's `/screen/69xx/` route, and voxl checks the token (ADR 0008). Clients shouldn't change.
- Old agents must be refused cleanly, not half-work.

## Decision

### Off by default; needs the Bots' user

`MACHINE_SCREENS=on` (default `off`) turns it on. It needs `MACHINE_BOT_USER=on`: botd won't start with screens on and the Bots' user off. `SCREEN_SIZE` and `SCREEN_IDLE_MINUTES` apply as for the server's own screens.

A Bot routed to a machine is shown from that machine or not at all. With `MACHINE_SCREENS=off`, its screen request is refused (`machine_screens_off`) and its runs get no display. botd's own screens serve only Bots that run on botd.

### On the machine: the agent runs the stack as the Bots' user

The agent (`superbot-machine`) answers, over the pinned mutual-TLS port it already has:

| Route | What |
|-------|------|
| `PUT /v1/screens/{bot}` `{protocol, ownerId, token, width, height, idleSecs}` | Start the Bot's screen, or give a running one a new token. Replies `{display, bus, started}`. |
| `DELETE /v1/screens/{bot}` | Stop it. |
| `GET /v1/screens/{bot}/tunnel` with `Upgrade: superbot-screen/1` | `101 Switching Protocols`, then the connection is piped to that screen's voxl on `127.0.0.1`. |

Each screen is Xvfb (`:101`, `:102`, ... with `-nolisten tcp`), dbus-daemon (a socket in the Bots' home), Openbox and voxl, all started with a cleared environment, the system `PATH` (never the harness's), the Bots' user's uid and gid, no extra groups, and killed with the agent. voxl listens only on loopback (`6901`, `6902`, ...) with botd's token as its password, no audio or file transfer. X's socket folder is the agent's own `/tmp/.X11-unix`, which jobs share. At most `SUPERBOT_MAX_SCREENS` (default 4) run at once.

The agent refuses:

- before botd has asked for the Bots' user (ADR 0043), or while it's not ready (`409`): a screen never runs as root;
- an owner that isn't the machine's (`403`), another screen protocol, a malformed Bot id or token, or a size outside 320x240 to 7680x4320 (`400`);
- while an upgrade is being staged (`503`), and when programs are missing (`422`).

A Bot's running job and each open tunnel hold its screen. The agent stops a screen idle for `idleSecs` with no holds, and one whose processes died. Tunnels are capped at 64 at once and 12 hours each.

The agent's heartbeat says `can: screens` and `screens: {protocol, missing, running, max}`. `missing` lists which of `Xvfb`, `openbox`, `dbus-daemon`, `voxl` aren't installed.

### On botd: a loopback port per open screen, piped through the agent

`GET /api/bots/:id/screen` keeps its checks: an authenticated session (or Bot token), `Operate` on the Bot (ADR 0024). Then, if the Bot's owner is routed to a machine:

1. Route as for runs (ADR 0036): no machine, not ready, offline, outdated, Bots' user pending, and so on are refused with their reasons, never served locally.
2. Ask the agent for a fresh heartbeat over mutual TLS. Refuse with `agent_outdated` if it lacks `can: screens` or speaks another screen protocol, and with `screen_stack_missing` (naming the programs) if it lacks any.
3. `PUT /v1/screens/{bot}` with botd's token for that Bot (a new random 128-bit token if it has none). The token is registered for redaction and never logged.
4. Listen on a free `127.0.0.1` port in `MACHINE_SCREEN_PORTS` (default `6960-6999`, inside the proxy's `/screen/69xx/` route and checked at start not to overlap botd's own screen ports).
5. Return `/screen/<port>/?token=<token>`, as for local screens. Clients don't change.

Each connection to that port is checked again before it's piped: the Bot still exists and is its owner's, and the owner is still routed to that machine, at the machine's current certificate pins. Then botd opens `/v1/screens/{bot}/tunnel` on the agent (HTTP/1.1 upgrade inside TLS) and pipes bytes both ways. voxl checks the token on the machine, so a guess at botd's loopback port gets nowhere without it.

The web and Expo clients' screen auth (ADR 0008) works unchanged: they get the same kind of link.

### Runs on the machine get the screen

A routed run with screens on starts or keeps the Bot's screen first. The run gets `DISPLAY`, `DBUS_SESSION_BUS_ADDRESS` and agent-browser's settings, as on botd, and its system prompt says the screen is on its owner's computer and how to hand off. If the screen can't start, the run goes ahead without one.

### Who may see it, and closing it

- Narrowing who may see a Bot (private, a grant removed or lowered) gives its open screen a new token at once: botd stops accepting the old one, cuts open viewers, and tells the agent. The agent replaces voxl with the new password and keeps the display, so the Bot's windows stay.
- Disabling a user, lowering their role, deleting them by SCIM, or revoking all their sessions does the same for every open machine screen, as for botd's own screens: a link doesn't know who opened it.
- A screen is closed (botd stops listening, the agent stops it) when its Bot is deleted, when the Bot or its owner leaves that machine, when idle for `SCREEN_IDLE_MINUTES` with no viewer and no run, or by an admin. A close waits for a start under way for that Bot, and a start re-checks the Bot afterwards, so a Bot deleted meanwhile leaves no screen running.

### Old agents and versions

The screen protocol is versioned separately (`SCREEN_PROTOCOL = 1`, in the request and the heartbeat). An agent without `can: screens` or with another version is `agent_outdated`; it upgrades with botd's build (ADR 0039). Requests with unknown fields are rejected.

### New machines

With screens on, cloud-init's first-boot script installs `xvfb openbox dbus-daemon dbus-x11 x11-utils fonts-noto-core` and voxl's runtime libraries after the agent starts, so enrolling never waits on it. If botd has a `voxl` binary next to it (or on its `PATH`), machines download it from `/v1/voxl` over the pinned channel, checked by SHA-256 like the agent. A failure there leaves the agent reporting what's missing; Bots still run.

### Audit and visibility

| Event | When |
|-------|------|
| `machine.screen_started` | The agent started a screen (`for`: `viewer` or `run`, `display`). |
| `machine.screen_opened` | A person was given a link, once per viewer per token (`port`, `display`, `viewer`). |
| `machine.screen_rotated` | Its token was replaced after access narrowed (`machineTold`). |
| `machine.screen_refused` | Denied, with `reason`, `owner`, `machine`. |
| `machine.screen_closed` | Closed, with `reason` (`bot_deleted`, `moved`, `idle`, `closed_by_admin`), `openMs`, `machineStopped`. |

Admins see a user's open screens and what the agent reports with `GET /api/users/{key}/machine/screens` (`botctl machine screens <user>`), and close one with `DELETE /api/users/{key}/machine/screens/{bot}` (`botctl machine screens <user> close <bot>`). `botctl machine agent <user>` shows `screens: {protocol, missing, running, max}`.

## Consequences

- No new inbound port on machines; the firewall is unchanged. The agent's TLS server now allows HTTP upgrades; botd's machine port doesn't.
- botd holds a viewer connection per open tunnel. Each is cheap (bytes copied both ways), and the agent caps them.
- voxl's password is in its environment, readable by processes of the Bots' user on the machine: a Bot can read its own screen's token. That's no more than it has: it already draws on that screen. It can't read the agent's key or another user's screens.
- All Bots of a machine share one OS user (ADR 0043), so a Bot could reach another of its owner's Bots' X display. Screens are work surfaces, not boundaries between one user's Bots, as on botd.
- Screens open on botd's side are kept in memory. After botd restarts, the next request reuses the agent's screen with a new token; the agent stops screens nobody uses.

## Alternatives considered

- **Open voxl's port on the machine to botd.** A second inbound port and firewall rule, and voxl's own TLS-less HTTP on the network. Rejected: the agent's mutual TLS already authenticates both ends.
- **Proxy through a new botd HTTP route.** Clients would need a new link shape and botd would reimplement voxl's WebSocket proxying. A raw byte pipe behind the existing `/screen/<port>/` route keeps clients and the proxy unchanged.
- **Fall back to botd's display when the machine can't show one.** The Bot's browser and files aren't there, and it would blur where a Bot runs. Rejected: refuse with the reason instead.
