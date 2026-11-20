# 0037: Per-user Unix accounts on one server

## Status

Accepted. Next slice of [#30](https://github.com/CG-Labs/superbot/issues/30) (M3), after [ADR 0029](0029-per-user-isolation.md) (per-user folders, secrets and tokens). Off by default.

## Context

ADR 0029 gave each user their own folder, facts, keys and Bot tokens, but every Bot still runs as botd's one Unix account. So on one server:

- A Bot's shell can read and write another user's folder. Only the approval policy (in `ask` mode) stands in the way.
- `claude login` and `codex login` write to the one HOME, so every user's Bots share one harness login.
- A Bot can read botd's own files: the database, `.env`, the master key.

We want user A's runs unable to touch user B's folder or logins on the same host, by the kernel's rules, not by policy. Self-hosters who run alone shouldn't have to change anything.

## Options

| | Per-user Unix accounts | Namespaces per run (bubblewrap, `unshare`) | `systemd-run` per run | A container per user |
|---|---|---|---|---|
| Boundary | Kernel file permissions and uids | Mount namespace: the run sees only its folders | Same as accounts, plus unit sandboxing | Container runtime |
| Needs | `sudo`, `useradd`, `acl` | Unprivileged user namespaces, or a setuid `bwrap` | Root, or polkit over D-Bus, for every run | Docker or Podman and images |
| Works in Docker / Ubuntu 24.04 | Yes | Often not: Docker's seccomp blocks it; 24.04's AppArmor limits it | No systemd in Docker | Docker in Docker |
| Hides botd's own files | Yes (other owner) | Yes | Yes | Yes |
| Per-user HOME for logins | Natural: the account's home | Bind-mounted fake HOME, same uid | Natural | Natural |
| Stops reach a run's tools | Through `sudo` and a small wrapper | Yes | Yes (`systemctl stop`) | Yes |
| Maps to later steps | The machine agent runs as the user's account too | — | — | Close to "one container per user" (ADR 0029) |

Namespaces alone keep one uid, so anything that escapes the mount view (a socket, `/proc`) is the same user. `systemd-run` needs root per run and isn't in Docker. Containers are the right answer on a virtualised server, and that's already the machine path (#29). For one host, **per-user Unix accounts** give a real kernel boundary with the least machinery, and work wherever `sudo` does.

## Decision

`ISOLATION=users` runs each Bot's harness as its owner's account, `sb-u-<user id>`. Unset or `off` (the default) changes nothing.

### The privileged surface

botd stays unprivileged. It gets exactly two sudo rules, written by `deploy/install.sh --isolation` to `/etc/sudoers.d/superbot-isolation`:

```
Defaults!/usr/local/bin/superbot-run !syslog
superbot ALL=(%superbot-users) NOPASSWD:SETENV: /usr/local/bin/superbot-run
superbot ALL=(root) NOPASSWD: /usr/local/sbin/superbot-userctl ensure *
```

- **`superbot-run`** (Rust, not setuid, no privilege of its own) runs as the target account. It refuses root and any account not named `sb-u-<id>`, refuses a working folder outside that account's folders, sets HOME from the password database (never the caller's), a private `TMPDIR`, umask `0007`, and PATH from `SUPERBOT_PATH` (sudo resets PATH). It puts the run in its own process group and passes TERM on to all of it, then KILL after 5 seconds; it also dies with sudo. `-E` keeps the run's env (its Bot token and its owner's keys): those go only to that owner's account. `!syslog` keeps prompts (in argv) out of the system log.
- **`superbot-userctl ensure <id>`** (bash, root) makes or fixes one account and its folders. The id must be 1 to 27 lowercase letters and digits. Where folders go and botd's group come from root's `/etc/superbot/isolation.conf`, never from the caller. It checks every folder above `ISOLATION_DIR` is root's and only root's to write, never follows a link, and refuses an existing account with another home, uid 0, or membership in botd's group. It has no other command.

A Bot can't choose a uid or path: the account comes from the Bot's owner id in botd's database, the folders from root's config, and per-user accounts have no sudo rights at all. The sudoers file is checked with `visudo -c` before it's installed.

The unit gets a drop-in: `NoNewPrivileges=false` (sudo is setuid) and `ProtectProc=invisible`, so a run sees only its own account's processes, not other users' command lines or env. botd warns at startup if it can see other accounts' processes. The installer also makes the service home `0750`, so accounts can't read the database, `.env` or the master key.

### Layout

| Path (`ISOLATION_DIR`, default `/srv/superbot/users`) | Owner, mode | Holds |
|---|---|---|
| `./` | root, `0711` | Nothing listable |
| `<id>/` | root:botd, `2750`, ACL account `r-x` | Only that account and botd can enter |
| `<id>/home/` | account:botd, `2770` | The account's HOME: harness logins (`~/.claude`, `~/.codex`) |
| `<id>/workspace/` | account:botd, `2770` | Where the user's Bots work |
| `<id>/memory/` | root:botd, `2770`, ACL account `rwx` | `USER.md` and `<bot id>.md`, copies botd makes |

botd keeps its own copies of memory in `DATA_DIR`, so backups and handovers keep working. It seeds a run's copy (never overwriting, never through a link), and after each run reads it back with `O_NOFOLLOW`, only from a real folder it or root made, at most 1 MiB. When a Bot changes hands, its memory leaves the old owner's folder. `state_dir` stays in `DATA_DIR`; Claude Code and Codex don't use it.

### Runs

After machine routing (unchanged: a run sent to a machine never reaches this) and before the harness starts, botd makes the owner's account if it's new, then starts `sudo -n -E -u sb-u-<id> -- superbot-run <harness> ...` in the owner's workspace. If the account can't be made, or the harness can't run this way yet, the run is refused (`bot.run_refused`, with `isolation_harness` or `no_account`), the Bot says why, and the run is given back. It never falls back to botd's account.

Only **Claude Code and Codex** run this way. Pi's approval gate and Hermes's managed config and daemon live in files botd writes in a folder the run could change; they're refused until that's reworked. **Screens are off**: their X displays belong to botd's account.

### Harness logins

Each account has its own HOME, so each user's Bots use their own login. An admin, on the server as botd's account, runs:

```
botctl user harness-login <user> claude      # claude auth login
botctl user harness-login <user> codex       # codex login
botctl user harness-login <user> claude -- setup-token
```

botd makes the account if needed and returns the command; botctl runs it at the admin's terminal with a clean env. API: `POST /api/users/{key}/harness-login` `{harness, args?}`. `GET` and `POST /api/users/{key}/isolation` show and make the account (`botctl user isolation | isolate`). All are admin-only. Per-user API keys as secrets ([ADR 0029](0029-per-user-isolation.md)) still work and need no login.

### Audit

- `isolation.account_created` (account, home) and `isolation.account_failed` (account, error).
- `harness.login_started` (harness, account, whether custom arguments were given; never the arguments).
- `bot.run_refused` adds reasons `isolation_harness` and `no_account`.
- `harness.invoked` adds `runAs` (only when isolated). `server.started` adds `isolation`.

### Settings

| Setting | Meaning |
|---|---|
| `ISOLATION` | `users` turns it on. Default `off`. |
| `ISOLATION_DIR` | The users' folders. Default `/srv/superbot/users`. Must be root's, not writable by others, and not hold or sit in `DATA_DIR`. |
| `ISOLATION_SUDO`, `ISOLATION_USERCTL` | Paths of `sudo` and the helper, for unusual layouts. |

A half-made setup is a startup error, not a silent fallback.

## Consequences

- With the flag on, user B's Bot can't read or write user A's folder, logins, memory or facts, nor botd's data, nor sudo anywhere. A root-run test (`deploy/test-isolation.sh`, in CI) walks B's run through botd's real run path against A's files, under the unit's own sandboxing.
- With it off, nothing changes: the same folders, the same account, no sudo.
- Harness CLIs must be installed system-wide (`sudo npm install -g ...`), not in botd's `~/.local`.
- botd's account can run code as any per-user account. botd is already trusted with every user's keys, so this adds no new trust.
- Turning it off (`--no-isolation`) removes the sudo rule and drop-in. Accounts and their folders stay, as data.
- Switching either way doesn't move workspaces: a user's files stay in the old folder until an admin copies them (steps in `deploy/README.md`). Memory and `USER.md` carry over, since botd keeps the originals. Harness sessions live in the old HOME, so each Bot starts a fresh one, which botd already does when a session is lost.

## Deferred

- **The network.** Accounts share one network: a tool listening on `127.0.0.1` can be reached by other users' runs. Per-user network namespaces, or the machine agent, close this.
- **Pi and Hermes** under accounts.
- **Per-user screens.**
- **Shared team Bots**: a Bot runs as its owner. A team account is a later decision.
- **The client's personal-secrets screen.**
- **Running on the machine agent** (#29): the same account model, on the user's own machine.
- **Removing accounts** when a user is deleted (by hand for now: `userdel sb-u-<id>`).
