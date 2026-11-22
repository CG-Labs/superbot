# Computer: each Bot's screen

Each Bot gets its own screen on the server, with a real browser. You can watch it live in the web app and take over.

## How it works

- **Screen:** a virtual display (Xvfb) with a window manager (Openbox) and its own D-Bus session. `botd` starts it on a Bot's first task and stops it after `SCREEN_IDLE_MINUTES` without use. Code: `server/src/screen.rs`.
- **Browser:** [agent-browser](https://github.com/vercel-labs/agent-browser). Each Bot has its own session and Chrome profile in `DATA_DIR/bots/<id>/browser`, so sign-ins persist. Chrome runs headed on the Bot's screen.
- **Desktop apps:** [agent-desktop](https://github.com/vercel-labs/agent-desktop) reads apps through the screen's accessibility bus.
- **Live view:** [voxl](https://github.com/tembo/voxl) streams each screen. `GET /api/bots/<id>/screen` returns `/screen/<port>/?token=...`. The page is view-only until you click **Take over**. The web app and the Expo client (iframe, or a WebView on phones) both show it; see [ADR 0008](adr/0008-client-screen-auth.md) for how the client keeps the password out of the link.
- **Handoff:** for logins, 2FA, or CAPTCHAs, a Bot runs `botctl handoff "<what it needs>"`. You get a card with **Open screen** and **Done**. The Bot's command waits for your answer. The client also flags the Bot in the sidebar ("Needs you"), pins a banner over its chat, and puts **Done** in the screen panel.

All tools are plain CLIs, so this works the same on every harness. The Bot's system prompt explains them.

At most `MAX_SCREENS` run at once. When all are in use, the least recently used screen of an idle Bot is stopped.

Screens are work surfaces, not security boundaries. All Bots run as one Linux user.

## On the owner's machine

With per-user machines ([ADR 0036](adr/0036-bots-on-the-users-machine.md)), a Bot whose owner is routed to a machine runs there, so its screen is there too. Turn it on with `MACHINE_SCREENS=on` (it needs the Bots' own user, on unless `MACHINE_BOT_USER=off`). The machine's agent runs Xvfb, Openbox, D-Bus and voxl as the Bots' user, `superbot-bots`, and botd shows it at the usual `/screen/<port>/` link by piping the viewer through the agent's mutual-TLS port. No port opens on the machine; its firewall is unchanged. botd's ports for these are `MACHINE_SCREEN_PORTS` (default 6960-6999), inside the proxy route below.

Such a Bot is shown from its machine or not at all, never from this server. When the machine is down, outdated, still setting up its Bots' user, or missing a program, the screen request says why. New machines install the programs at first boot; others need `xvfb openbox dbus-daemon` and `voxl` (from [`install-computer.sh`](../deploy/install-computer.sh), or the `voxl` binary placed next to botd, which new machines download). Design: [ADR 0045](adr/0045-screens-on-machines.md).

## Install

On Ubuntu 24.04 or later, as root:

```sh
deploy/install-computer.sh <user that runs botd>
```

Then add `AGENT_BROWSER_SKILLS_DIR=/opt/computer/share/agent-browser-skills` to botd's environment and restart it. It prints `Screens: on.`

With Docker Compose there's nothing to install: the published image has all of it, with Debian's Chromium (it has arm64 builds, unlike Chrome for Testing), and Compose's Caddy serves the `/screen/` route below from the `botd` container (`SCREEN_ADDR=0.0.0.0`). Chromium keeps its sandbox there too, through a seccomp profile Compose gives `botd` ([ADR 0107](adr/0107-chromium-sandbox-in-the-container.md)). See [Screens and computer use in Docker](../deploy/README.md#screens-and-computer-use-in-docker) and [ADR 0084](adr/0084-published-image-with-computer-use.md).

As on a bash install, screens are off while per-user accounts (`ISOLATION=users`) are on: per-user screens don't exist yet.

The script also adds 4 GB of swap and earlyoom, which kills the biggest Chrome before the server runs out of memory.

## Proxy

The live view needs `/screen/<port>/` routed to that local voxl port. With Caddy:

```
@screen path_regexp screen ^/screen/(69[0-9][0-9])/
handle @screen {
	uri strip_prefix /screen/{re.screen.1}
	reverse_proxy 127.0.0.1:{re.screen.1}
}
```

Ports are `6800 + SCREEN_BASE + slot`: 6901, 6902, ... by default. botd refuses to start if `SCREEN_BASE` and `MAX_SCREENS` put them outside this route's 6900-6999. voxl checks its own token, so the route needs no extra login.

## Sizing

One Bot with Chrome open uses about 0.5 to 1 GB of RAM. Streaming a busy screen uses about one CPU core. A 2 CPU, 8 GB server handles about 3 screens at once.
