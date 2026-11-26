# 0342: Per-user screens on one server

## Status

Accepted (26 Nov 2026). The last slice of [#30](https://github.com/CG-Labs/superbot/issues/30) (M3, per-user isolation): per-user screens on one server and in Docker Compose. It closes the "Per-user screens" item [ADR 0037](0037-per-user-unix-accounts.md) deferred and the "Screens with accounts on" item of [ADR 0058](0058-harness-os-user-by-default.md). It builds on ADR 0037 (per-user accounts), [ADR 0064](0064-teammate-accounts-on-one-server.md) (teammates' own accounts), [ADR 0045](0045-screens-on-machines.md) and [ADR 0048](0048-teammates-own-os-user-on-machines.md) (screens on machines, a cookie per teammate's display), and is checked by the red-team suite of [ADR 0145](0145-locked-down-run-users-and-red-team.md).

## Context

What the code did before this change:

- Each Bot's screen (Xvfb, Openbox, D-Bus, voxl; [ADR 0003](0003-computer.md)) ran as botd's account, with no X cookie, so any local process could open its display. With every Bot as botd's account that's no boundary lost.
- With `ISOLATION=users`, every user's runs are their own Unix account, so a display of botd's would let user B's run see and drive user A's browser. botd turned screens off instead, on a bash install and in Compose, where per-user accounts are the default. Computer use, a headline feature, needed `ISOLATION=off`.
- On machines, screens already run as the Bots' user, and a teammate's own display takes an X cookie only they hold (ADR 0045, 0048). One server had nothing like it.

What a screen shares on one host, and so what another account could use against it:

| Surface | Open to other accounts by default |
|---|---|
| The X display | Its sockets (`/tmp/.X11-unix/X<n>` and the abstract `@/tmp/.X11-unix/X<n>`) take any local client unless the server has a cookie |
| A display number | Any account can bind a display's sockets first, or leave files that stop Xvfb |
| The D-Bus session | A socket at a path botd chose |
| Shared memory | voxl and browsers use MIT-SHM; Xvfb's `-shmem` framebuffer would be a segment others may attach |
| The viewer | voxl's port: on loopback (or the compose network), which any account may also listen on before voxl does |
| The proxy route | `/screen/69xx/` passes the browser's request, with the app's session cookie, to whatever listens on that port |

## Options

| | Screens as each run's account, botd fronts the viewer | Screens as botd, X cookie only | A container or VM per screen | Screens stay off |
|---|---|---|---|---|
| Another account opens the display | No: cookie in the account's own folder; botd checks the server refuses clients without it | No, but the screen's processes are botd's: the run's browser is botd's | No | — |
| The run's browser and profile | The account's, in its folder | botd's | Separate | — |
| A squatted viewer port passes for the screen | No: botd holds the public port and checks whose each loopback connection reaches | Yes, unless also fronted | No | — |
| Works in Compose (no systemd, no namespaces for botd) | Yes: `sudo` and `superbot-run`, as runs | Yes | No | Yes |
| New privileged surface | None | None | Container runtime | None |

**Screens as each run's account, with botd fronting the viewer.**

## Decision

With `ISOLATION=users`, botd starts screens again, each as the account the Bot's runs use, through the same `sudo -n -E -u <account> -- superbot-run` path as runs (no new sudo rule). The owner's runs, and the people who may operate the Bot, use the owner's account's screen. With `ISOLATION_TEAMMATES` (ADR 0064) a teammate's run of a shared Bot uses their own account's screen, keyed `<bot>@<teammate>` as on machines, and the app opens a teammate's own; an admin opens one with `?for=<user>`. There is never a screen as botd's account while accounts are on.

### The display

- botd writes a new MIT-MAGIC-COOKIE-1 (FamilyWild, as `xauth` writes it) to `ISOLATION_DIR/<space>/settings/<bot>/screen.xauth`: botd's file, `0640`, which the account reads through the settings folder's ACL and can't change; no other account can enter the space. The run gets `XAUTHORITY` pointing at it. The file goes when the screen stops.
- Xvfb runs as the account: `:<n> -screen 0 WxHx24 -nolisten tcp -auth <cookie>`. Never `-ac`, never `-shmem`. Shared memory segments are then the clients' own, made `0600` (voxl, Chromium).
- Before anything else starts on it, botd checks the display from outside: the filesystem socket is a socket owned by the account; the peer of both sockets (`SO_PEERCRED`) is the account's uid; and a connection setup with no cookie is refused. An X server that couldn't read its cookie lets everyone in, so this is what makes the cookie real. A display that fails is killed, audited as `screen.start_failed` with the reason, and the next display is tried (three at most).
- Display numbers: an account's screen takes the first free one from `SCREEN_BASE + 1` (up to 200 past it), skipping any where an X server already answers on the abstract socket or where files are left that botd can't remove. `/tmp/.X11-unix` must be a sticky folder of root's or botd's, made by botd at start if missing (it is under the unit's `PrivateTmp`); otherwise screens stay off and the log says why. So no account removes or swaps another's socket, and one that grabs a display number only makes botd pick another.
- D-Bus runs as the account with its socket at `<home>/.tmp/bus-<n>`, inside the account's HOME (`0700` there). Openbox and voxl get `DISPLAY`, `XAUTHORITY` and the bus. Each program starts with an empty environment plus those, `LANG` and `SUPERBOT_PATH`.
- The browser profile is the account's: `ISOLATION_DIR/<space>/bots/<bot>/browser`. When botd stops a screen it asks agent-browser to close as the account, so the profile saves, then kills `sudo`, and `superbot-run` ends the screen's process group.

### The viewer

botd holds the screen's public port (`6800 + SCREEN_BASE + slot`, on `SCREEN_ADDR`) itself and runs voxl as the account on a fresh loopback port with the screen's token. For voxl, and for every viewer connection after, botd connects to that loopback port and reads `/proc/net/tcp`: the socket that accepted it must be the account's (botd waits up to 2 seconds for the accept; until then the kernel shows no owner). So a port another account bound first never gets a view or the token. botd hands out a link only after voxl answered as the account. A new token (someone lost access to the Bot) restarts voxl on a new loopback port and cuts every open view; the display and the Bot's apps keep running.

The public port is skipped if another account holds it, so botd never links to a port it doesn't own. Ports nobody holds are still reachable through the proxy's `/screen/69xx/` route, and any account may listen on one. The route therefore drops the `Cookie` header (`header_up -Cookie` in Compose's Caddyfile and the documented one): a viewer needs only its token, and the app's `__Host-superbot_session` cookie must never reach a port an account listens on. That also closes the same leak for `ISOLATION=users` installs before this change, where screens were off but the route was there.

### Lifecycle

- Screens start on a run's first need, or when someone with Operate opens one (botd makes the account and the Bot's folders if needed, as a run would, and holds a teammate's account from removal while it starts). Idle reaping, the `MAX_SCREENS` limit and rotation work per screen as before; rotating a Bot rotates all its screens, a teammate's too, and deleting a Bot stops them all.
- A teammate's account removal ([ADR 0066](0066-removing-teammate-accounts-on-one-server.md)) stops that account's screens first.
- The startup log says `Screens: on (each runs as its run's per-user account; viewers listen on <addr>)`.

### Tests

- Unit: Xvfb's arguments (no `-ac`, `-shmem` or TCP), the cookie file format, the no-cookie handshake, reading `/proc/net/tcp`, `held_by` against this process's own listener, the X11 folder check, the run's environment, and that accounts on never give a screen as botd (nor off one as an account).
- The isolation suite in CI (`deploy/test-isolation.sh`, now with Xvfb, Openbox and D-Bus, and a fake voxl that says which account it runs as): user A's screen runs as A, with its cookie in A's settings, and its view through botd's port shows A's account and opens only with A's token. User B's run, as B, opens its own screen but not A's: not without a cookie, not pointed at A's cookie (which it can't read), not with its own; it can't reach A's bus; a port B's account listens on is never taken for A's viewer; neither account has shared memory others may attach. A teammate's screen of a shared Bot is theirs, the owner's run can't open it nor theirs the owner's, and their account's removal stops it.
- Compose's smoke test: under per-user accounts a Bot's screen runs as its owner's account, botd's own account and another account can't open it or read its cookie, its view opens through Caddy only with its token, and Chromium opens on it as the account.

## Consequences

- Computer use works with per-user accounts, on a bash install and in Compose, which is the default there. `--no-isolation` is no longer needed for screens.
- Each screen costs a `sudo` and a `superbot-run` per program (four per screen), and a `/proc/net/tcp` read per view.
- The cookie, not the uid, is the display's lock: anything the account runs can open its own display, as on a desktop. People who can operate a shared Bot without their own account (no `ISOLATION_TEAMMATES`) share the owner's account's screen, as they share its runs.

## Deferred

- **A display that dies mid-run.** If an account's X server crashes while a run still points at its display number, another account could bind the freed abstract socket before botd restarts it, and the run's new X clients would connect there (X clients try the abstract socket first). botd restarts on the same number when it can. Closing it fully needs X clients that take a socket path, or a mount namespace per screen.
- **Audio and file transfer** in the viewer stay off, as before.
