# 0058: Harnesses run as their own OS user by default

## Status

Accepted (21 Nov 2026). Approvals follow-up 2 ([list](../approvals-followups.md), tracking issue [#13](https://github.com/CG-Labs/superbot/issues/13), M1). It builds on [ADR 0037](0037-per-user-unix-accounts.md) (per-user Unix accounts), [ADR 0043](0043-bots-own-os-user-on-machines.md) and [ADR 0048](0048-teammates-own-os-user-on-machines.md) (OS users on machines), [ADR 0006](0006-docker-compose.md) (Docker Compose), and follows the defaults of [ADR 0055](0055-harness-sandbox-defaults.md).

## Context

A Bot that runs as botd's own Unix user can read `.env`, the database, botd's memory copies and the master key. Approvals check what a Bot asks to do, not what a program reads once it runs.

What already existed:

- **On machines** (ADR 0043, 0048): the root agent runs every Bot as the Bots' own user, and a teammate's runs as theirs. Done.
- **On the server** (ADR 0037): `ISOLATION=users` runs each user's Bots as `sb-u-<user id>`, which can't read botd's files. But it was off by default, only for Claude Code and Codex (Pi and Hermes Agent were refused), and only through `deploy/install.sh`: Docker Compose couldn't use it.

So the gap was the server: the default, Pi and Hermes, and Docker.

We looked at reusing the machine code. It switches users from a root agent (`setfsuid`, root-owned layout). botd isn't root and shouldn't be, so the machine path doesn't fit. ADR 0037's `sudo` + `superbot-run` + `superbot-userctl` already gives botd exactly two privileged actions; we extend that instead.

## Decision

### Pi and Hermes Agent under accounts

They were refused because botd writes files for them (Pi's approval guard extension, Hermes's managed config with the approval hook) into a folder the run could change, so a Bot could turn its own gate off. Each user's folder gets two more:

| Path (`ISOLATION_DIR/<user id>/`) | Owner, mode | Holds |
|---|---|---|
| `bots/` | root:botd, `2770`, ACL account `r-x`, default ACL account `rwx` | `<bot id>/`: the Bot's harness state (Pi sessions, `HERMES_HOME`), the account's to write |
| `settings/` | root:botd, `2770`, ACL account `r-x`, default ACL account `r-x` | `<bot id>/`: files botd writes for a run, the account's to read only |

`RunInput` gets `config_dir` beside `state_dir`; they're the same folder except with accounts. Before a run botd makes both `<bot id>` folders (never through a link, and only in folders root or botd made). It writes each file into `settings/<bot id>` itself (`0640`, its own, through `O_NOFOLLOW`, into folders it owns `0750`), so the account can read the guard and the managed config but can't change, replace or delete them. A path outside `settings/<bot id>` is refused, and the run with it.

Hermes's daemon is stopped after a run as the account (`superbot-run`, with the run's `PATH`), not as botd. The check for its pid file moves into that command, as botd may not be able to see it.

Harness logins stay per user for Claude Code and Codex (`botctl user harness-login`). Pi and Hermes use provider keys (env or saved secrets), which pass to the run as before.

### On by default for new installs

As with sandboxes (ADR 0055) and approvals (ADR 0007): new installs get it, existing installs keep what they had, and the startup log says how to opt in.

- **`deploy/install.sh`**: a run with no `.env` yet (a new install) and neither `--isolation` nor `--no-isolation` turns accounts on. `--upgrade`, and any host with `.env`, keep their setting, which still comes from root's sudoers rule, never from `.env`. `--no-isolation` opts out.
- **Docker Compose**: `.env.example` has `ISOLATION=users`, so `init.sh` gives new installs accounts. An `.env` from before has no `ISOLATION` and stays off. `init.sh --isolation` / `--no-isolation` switch it.
- **botd** with accounts off logs that every Bot can read `.env`, the database and the master key, and how to turn accounts on.

With accounts on, botd takes other users' access off `DATA_DIR`, `.env` and `SUPERBOT_MASTER_KEY_FILE` at start, and warns about any it can't change.

### Docker

The image carries what the installer sets up: `sudo` and `acl`, `superbot-run`, `superbot-userctl` in `/usr/local/sbin`, root's `/etc/superbot/isolation.conf`, and the same sudoers rule (from the installer's own function, checked with `visudo`). Every setuid bit except `sudo`'s is removed. `/srv/superbot/users` (root, `0711`) is a named volume, `users`.

The botd service keeps `cap_drop: [ALL]` and adds back only what sudo and the helper need: `CHOWN`, `DAC_OVERRIDE`, `FOWNER`, `FSETID`, `SETUID`, `SETGID`, `AUDIT_WRITE`. `no-new-privileges` is off for it, as for the systemd unit, since sudo is setuid. Runs lose every capability when sudo switches to the account. The backup and Caddy services keep everything dropped.

A recreated container starts with the image's `/etc/passwd`, so accounts are gone while their files in the `users` volume stay. `superbot-userctl` gives a re-made account the uid that owns its home, and new accounts a free system uid not used by any account's home, so files never change hands. Each account's group has the same id.

Hermes in the image is already outside botd's home (`/opt/hermes`). The installer, with accounts on, installs it system-wide too: root's checkout in `/opt/hermes`, linked from `/usr/local/bin/hermes`, checked by running it as `nobody`. Each run has its own `HERMES_HOME`, so the install holds only the program.

## Consequences

- New installs: no Bot, on any harness, can read botd's `.env`, database, master key or `DATA_DIR`, or another user's folder. Root tests (`deploy/test-isolation.sh`, in CI) check it for Claude Code, Pi and Hermes through botd's real run path, and the Compose smoke test checks it in the container, including botd's env in `/proc`.
- Existing installs: nothing changes until an admin opts in.
- Harness CLIs must be installed system-wide. In Docker, CLIs installed later with `npm i -g` land in botd's home and aren't on an account's PATH: bake them into the image (`SUPERBOT_HARNESSES`) instead.
- Docker gives the botd container a few capabilities and lets sudo raise privileges. Only root's two sudo rules use them, and the image has no other setuid program. Images with accounts off carry the same rules: botd's account can make accounts and start runs as them, which is no more than it can already do.
- In Docker, runs can see every process in the container (`ProtectProc` is systemd's). Other processes' env stays hidden (`/proc/<pid>/environ` is the owner's only), but command lines show. The installer's systemd path hides them.

## Deferred

- **The network**, as in ADR 0037: accounts share one network.
- **Screens** with accounts on.
- **Per-Bot accounts** on the server: a Bot runs as its owner's account. Machines already have the Bots' own user (ADR 0043).
- **Logins for Pi and Hermes** through `botctl user harness-login`: they use keys for now.
