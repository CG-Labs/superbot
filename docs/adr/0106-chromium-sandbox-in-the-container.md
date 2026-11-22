# 0106: Chromium's sandbox inside the container

## Status

Accepted (22 Nov 2026). [#50](https://github.com/CG-Labs/superbot/issues/50) (M4, SOC 2 readiness, CC6.8-3). Changes [ADR 0084](0084-published-image-with-computer-use.md) (the published image with computer use), which left the sandbox off.

0105 is on `main`, and open PR #164 holds 0102, so this is 0106.

## Context

ADR 0084 said Chromium in the published image ran without its sandbox because "Docker's seccomp profile blocks the user namespaces the sandbox needs". We checked that before changing anything. Two things turned it off, not one:

- **agent-browser adds `--no-sandbox` itself.** v0.43.0 (`cli/src/native/cdp/chrome.rs`, `should_disable_sandbox`) adds it whenever it sees `/.dockerenv`, `/run/.containerenv`, `docker`, `kubepods` or `lxc` in `/proc/1/cgroup`, a `CI` variable, or root. Nothing turns that off, and every Bot's browser goes through it. So even a container that could run the sandbox never got it.
- **Docker's default seccomp profile does block it.** It allows namespace flags in `clone` and `unshare` only with `CAP_SYS_ADMIN`, and `chroot` only with `CAP_SYS_CHROOT`; botd's container has neither. In a `debian:trixie-slim` container as a non-root user with `--cap-drop ALL`, `unshare -U true` fails with `EPERM`, and works with `seccomp=unconfined`. Debian's Chromium, started there with no `--no-sandbox`, stops with "No usable sandbox!".

The other usual suspects aren't in the way. botd runs as uid 10001, not root. The setuid sandbox (Debian's `chromium-sandbox`) isn't installed, and the image strips every setuid bit but sudo's, so Chromium's only option is its namespace sandbox: user, PID and network namespaces for each renderer, a `chroot` into an empty folder inside its own user namespace, and seccomp-BPF filters on top. The kernel allows unprivileged user namespaces. Docker's AppArmor profile (`docker-default`) declares no AppArmor 4 ABI, so Ubuntu 23.10+'s restriction on unprivileged user namespaces doesn't apply to it; CI's Ubuntu 24.04 runners show this.

The sandbox is what keeps a page that exploits a renderer bug inside that renderer. Without it, the page runs as the run's account, with its files, its harness logins and botd's API through the run's token. The image's Chromium is also as old as Debian's, behind upstream (ADR 0084).

## Decision

### botd's container gets Docker's own profile, plus three namespace rules

[`deploy/docker/seccomp-chromium.json`](../../deploy/docker/seccomp-chromium.json) is Docker's default profile (github.com/moby/profiles `seccomp/v0.1.0`, the one Docker 28 and 29 build in) with two rules added:

| Syscalls | Allowed | Why |
|---|---|---|
| `clone`, `unshare` | When no namespace flag besides `CLONE_NEWUSER`, `CLONE_NEWPID` and `CLONE_NEWNET` is set | The namespaces Chromium's sandbox makes for each renderer |
| `chroot` | Always | Chromium chroots into an empty folder inside its own user namespace; outside one, `CAP_SYS_CHROOT` is still needed and nobody in the container has it |

Mount, UTS, IPC and cgroup namespaces stay refused, in the container and in every user namespace made inside it, because seccomp filters are inherited (we checked `unshare -Ur unshare -m` fails). `deploy/docker/seccomp-chromium.sh` makes the file from the pinned upstream profile (checked by SHA-256) with `jq`, and CI fails if the committed file differs (`seccomp-chromium.sh --check` in the `docker` workflow), so nobody edits it by hand and an upgrade of the base profile is one pinned change.

Compose sets `security_opt: ["seccomp=./seccomp-chromium.json"]` on `botd` only. Caddy and the backup service keep Docker's default profile and `no-new-privileges`.

### The image's `chromium` keeps the sandbox on, whatever agent-browser asks

[`deploy/docker/chromium.sh`](../../deploy/docker/chromium.sh) is installed as `/usr/local/bin/chromium`, ahead of Debian's `/usr/bin/chromium` on `PATH`, and `AGENT_BROWSER_EXECUTABLE_PATH` points at it. It removes `--no-sandbox`, `--disable-namespace-sandbox` and `--disable-seccomp-filter-sandbox`, then runs Debian's launcher. (Debian's launcher resets `CHROMIUM_FLAGS`, so arguments are the only way in.) A shell script, not Rust: it's ten lines in front of a shell launcher, and it has to stay readable to whoever audits the image.

### One explicit way out: `SUPERBOT_CHROMIUM_SANDBOX=off`

Some hosts can't make user namespaces: rootless or locked-down runtimes, Kubernetes with its own seccomp policy, or a host that turned them off. For those, `SUPERBOT_CHROMIUM_SANDBOX=off` in `.env` makes the wrapper pass `--no-sandbox` and print that it did. It's `SUPERBOT_`-prefixed so a saved secret can't set it for a run (`SUPERBOT_` names are reserved). Anything but `on`, `off` or empty stops botd at start, and the wrapper refuses it too.

### Never a quiet fallback

There's no automatic fallback. With the sandbox on and no way to start it, Chromium stops with "No usable sandbox!", and agent-browser passes that to the Bot. botd also checks at start: when `AGENT_BROWSER_EXECUTABLE_PATH` names a browser and the sandbox is on, it starts it once, headless, on a blank page, in the background, and logs one of:

- `Chromium sandbox: on (checked: /usr/local/bin/chromium starts sandboxed).`
- `Chromium sandbox: on, but Chromium can't start sandboxed here, so Bots' browsers won't open: it found no usable sandbox (the container blocks user namespaces). ...`, with both ways to fix it;
- `Chromium sandbox: off (SUPERBOT_CHROMIUM_SANDBOX=off): ...`, as a warning, on every start.

The check runs whether or not screens are on, since Bots under per-user accounts can still start a headless browser. botd keeps running when it fails: the rest of SuperBot works without a browser, and refusing to start would take a whole server down over a host setting. A bash install's Chrome for Testing sets no `AGENT_BROWSER_EXECUTABLE_PATH`, so this check stays out of its way.

### Evidence: the smoke test

`deploy/docker/smoke-test.sh`, which CI runs on amd64 and arm64 against the images about to be published, now also checks, with a Bot's screen open:

- botd's log says `Chromium sandbox: on (checked`;
- agent-browser opens `chrome://sandbox` and it reads "You are adequately sandboxed", with the namespace sandbox as layer 1;
- no Chromium process has `--no-sandbox`, though agent-browser asked for it, and every renderer runs under a seccomp filter (`Seccomp: 2`);
- the same image under Docker's default profile refuses to start Chromium, with "No usable sandbox", instead of running it unsandboxed.

## Consequences

- Pages the Bots open in the published image are sandboxed again, as they are on a bash install (ADR 0003).
- botd's container can make user, PID and network namespaces. That's more kernel code within its reach (user namespaces have had local privilege-escalation bugs), in exchange for confining every page the Bots open, which is the larger risk. It's what a bash install on Ubuntu allows Chrome for Testing (ADR 0003's AppArmor profile).
- Compose installs that update the image but not the compose files (`git pull`) get "Chromium sandbox: on, but Chromium can't start sandboxed here" and no browser, until they pull. The upgrade steps in `deploy/README.md` already start with `git pull`.
- Running the image without Compose (`docker run`, Kubernetes) needs the profile, or the opt-out.
- When Docker's default profile changes, the pin in `seccomp-chromium.sh` moves with a deliberate change; until then botd keeps the older default.

## Alternatives considered

- **`seccomp=unconfined` for botd.** Simplest, but drops every seccomp rule Docker has, for every process in the container, to allow three.
- **The setuid sandbox (`chromium-sandbox`).** A second setuid-root program beside sudo, which the image and smoke test hold at one, for a sandbox Chromium keeps only as a fallback.
- **`CAP_SYS_ADMIN` for botd.** Docker's profile would then allow namespaces, and mounts, and much more besides.
- **Patching agent-browser, or asking upstream for a switch.** Worth doing, but the wrapper works with every release and also covers a run calling `chromium` itself. We'll drop it if agent-browser gets a switch.
- **Falling back to `--no-sandbox` when the sandbox can't start.** That's the quiet fallback CC6.8 asks us not to have.

## Not yet

- Incus machines (ADR 0065) use the bash install's Chrome for Testing, where agent-browser's container check may add `--no-sandbox` too (`lxc` in `/proc/1/cgroup`, depending on the cgroup namespace). Not checked here.
- An AppArmor profile of our own for botd's container.
- The opt-out shown to admins in the app, not only in botd's log.
