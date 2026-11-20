# 0041: Harness logins and the user's folder on their machine

## Status

Accepted. Next slice of [#29](https://github.com/CG-Labs/superbot/issues/29) (M3). Builds on [ADR 0031](0031-machine-enrollment-mtls.md) (enrollment, mutual TLS), [ADR 0036](0036-bots-on-the-users-machine.md) (Bots on their owner's machine), [ADR 0037](0037-per-user-unix-accounts.md) (per-user harness logins on one server) and [ADR 0039](0039-machine-harnesses-and-agent-upgrades.md) (harness CLIs on machines).

## Context

After ADR 0039, a machine has Claude Code and Codex installed, but they have no login there. A user's runs work only if they saved an API key in their secrets. Most users sign in to Claude Code or Codex with their own subscription, as ADR 0037 lets them do on one server. Also, the machine's `work` folder starts empty, while the user's files, `USER.md` and their Bots' memory sit on the server.

We want both on the user's machine:

- harness logins, with the credentials kept only there;
- a copy of the folder they already have.

Both must stay off unless asked for, and must not change self-hosting.

## Decision

### Harness logins: the harness's own login, run on the machine

`MACHINE_HARNESS_LOGINS=on` (default `off`; it needs `MACHINE_CONTROL_URL`) turns them on. A login is the harness CLI's own login, run by the agent on the machine. Its credentials are written there by the CLI and never leave.

The recipes live in the adapters (`Adapter::machine_login`), so the agent and botd's machine code stay harness-agnostic:

| Harness | Command | Credential file in the machine's HOME | Keys that make it unnecessary |
|---------|---------|----------------------------------------|-------------------------------|
| `claude` | `claude auth login` | `.claude/.credentials.json` | `ANTHROPIC_API_KEY`, `ANTHROPIC_AUTH_TOKEN`, `CLAUDE_CODE_OAUTH_TOKEN` |
| `codex` | `codex login --device-auth` | `.codex/auth.json` | `OPENAI_API_KEY`, `CODEX_API_KEY` |

Pi and Hermes have no login there. They keep using API keys from secrets, as on one server. Unlike `botctl user harness-login` (ADR 0037), extra login arguments aren't accepted: a machine runs only the recipe. The agent takes only words from a fixed list in the wire protocol (`LOGIN_WORDS`, every adapter's recipe words, kept in step by a test), as it does for harness names (`HARNESS_BINS`). So what it runs is never the request's own text.

How a login runs:

1. An admin starts it: `POST /api/users/{key}/machine/harness-login {harness}` (`botctl machine harness-login <user> <claude|codex>`). The person themselves can use `POST /api/machine/harness-login`. Bots can't.
2. botd checks that the user's machine is running and enrolled, and that its agent `can` do `logins`. The machine doesn't need to be assigned yet, so a login can come before the switch. Then it sends `POST /v1/logins` over the pinned mutual-TLS channel, with a `LoginRequest` (id, harness, command arguments, credential files, timeout of 15 minutes).
3. The agent checks the request: a known harness that is installed there, arguments from that list, and credential paths inside HOME. It runs at most one login per harness and two in all. It runs the CLI in a pseudo-terminal of its own, with echo off, in its own session. It gets only the harness environment, so no secrets.
4. The agent streams what the terminal shows back as JSON lines (`LoginEvent`: `started`, `output`, `ping`, `error`, `exit`). botd relays them to the caller as `application/x-ndjson` and keeps none of it.
5. Lines the person types go to `POST .../harness-login/{id}/input`, then to the agent, then into the terminal. botd never stores them. The audit records only how many characters were sent.
6. When the CLI exits, or the timeout passes, or someone stops it (`DELETE .../harness-login/{id}`), the agent ends the whole process group. It then reports whether the credential file now exists. If the caller goes away, botd stops the login on the machine.

A running login counts like a job: the agent refuses an upgrade while one runs, the heartbeat's `jobs` count includes it (so botd doesn't send one), and it holds off harness updates. No login starts while an upgrade is being staged.

The heartbeat says whether each login exists. botd sends `cred=<harness>:<file>` in the heartbeat query, and the agent answers `logins: {harness: {state, since}}`:

- `state` is `logged_in` (a non-empty regular file, not a link), `logged_out`, or `logging_in`;
- `since` is the file's modification time.

The agent never reads the file's contents. `GET .../harness-logins` shows each harness's state and whether the user has a key in their secrets. `DELETE .../harness-logins/{harness}` (`botctl machine harness-logout`) removes the credential files on the machine; it is refused while that harness's login is running.

With logins on, a routed run of `claude` or `codex` goes ahead only if that harness is logged in on the machine, or the owner has one of its keys in their secrets (or the server-wide ones). Otherwise it is refused with `harness_not_logged_in`. The Bot tells the user how to fix it, and nothing runs on the server instead. An agent from before this change can't log in or report it, so its runs are refused as `agent_outdated` instead.

### The user's folder: copied once, checked, never over their changes

`MACHINE_FOLDER_SYNC=on` (default `off`; it needs `MACHINE_CONTROL_URL`) turns copying on. `MACHINE_FOLDER_SYNC_MAX_MB` (default 2048, at most 102400) caps the size of the folder. A bigger folder isn't copied at all.

What is copied:

- The working folder becomes `work/` on the machine. That is `WORKSPACE_DIR/users/<id>`, or the user's `workspace` with per-user accounts.
- **Seeds** are written only where the machine has no file yet:
  - `USER.md`;
  - each of the user's Bots' `bots/<bot>/MEMORY.md`.
- Only regular files are copied. Links, devices, unreadable files and names a machine can't hold are skipped and counted.

When it runs:

- When an admin assigns the user to their machine (`PUT /api/users/{key}/placement`), unless a copy finished before.
- When an admin asks: `POST /api/users/{key}/machine/folder-sync` (`botctl machine sync <user>`).
- After a heartbeat, if a first copy failed or was cut short (botd restarted): it is tried again every 15 minutes, up to 5 times. A folder that was too big is not retried.

How a copy runs, over the pinned mutual-TLS channel:

1. botd checks the agent `can` do `sync`. It lists the files and hashes each one with SHA-256. It never follows a link: not at the folder itself, not at any folder below it, and not at a file. It opens each folder and file by name inside the folder it already opened (`openat` with `O_NOFOLLOW`), and opens files non-blocking so a FIFO can't stall it. It notes each file's device and inode. With per-user accounts (`ISOLATION=users`) the user's own processes can change their folder during a copy, so this keeps a swapped-in link from sending a server file.
2. botd sends `POST /v1/sync` with the manifest (path, size, SHA-256, executable bit, whether it is a seed). The agent checks every path is under `work/`, or is `USER.md` or `bots/<id>/MEMORY.md`. It then answers which contents it still needs, and how many bytes of each it already holds.
3. botd sends those contents in 4 MiB chunks: `PUT /v1/sync/{id}/blobs/{sha256}?offset=`. It opens each file again the same way and sends it only if it is the same device and inode; otherwise the copy fails with `source_changed`. An empty content, or one the agent already holds whole, is sent as one empty chunk, so the agent checks and keeps it. The agent stores them under its state folder, by hash. A chunk at the wrong offset gets 409 with the right one. Once a content is whole, it is checked against its SHA-256; a mismatch gets 422 and is dropped. So a copy that is cut short picks up where it stopped. Leftover chunks are dropped after a week.
4. botd sends `POST /v1/sync/{id}/finish`. The agent places each file: it writes a temporary file with a new random name (owner-only, created new, never through a link, and never removing anything already there), checks it against the SHA-256 again, then renames it into place. Just before the rename, it checks the file there is still the one it looked at (inode, size, mode, change times). If nothing was there, the rename refuses to replace a file made meanwhile (`RENAME_NOREPLACE`). Either way, an edit made while the copy runs is kept and listed as a conflict. The agent records in `synced.json` the hash and exec bit of what it wrote.
5. The rules for each file:
   - Missing on the machine: written.
   - Already the same: left alone (`unchanged`).
   - Unchanged since the last copy: replaced. If only the exec bit changed on the server, only that bit is changed there.
   - Changed on the machine since the last copy, content or exec bit: kept, and listed as a conflict.
   - A seed the machine already has: kept.
   - Nothing on the machine is ever deleted.
6. The agent returns a report: copied, unchanged, seeded, kept, conflicts (the first 50), and bytes. botd stores the status in its settings table (`machine_folder_sync:<machine id>`). `GET .../folder-sync` (`botctl machine folder <user>`) shows it.

While a user's *first* copy runs, their routed runs are refused with `folder_copying` ("try again in a few minutes"). Later copies don't hold runs back. Each file is swapped in one rename, so a run sees either the old file or the new one.

botd stays the source of truth for memory and facts. Jobs still carry `MEMORY.md` and `USER.md` to the machine and back on every run (ADR 0036). The copy only seeds them, so it never overrides a newer copy on the machine.

### Audit

| Event | Meaning |
|-------|---------|
| `machine.harness_login_started` | A login was started, with `harness`, `loginId` and who started it. |
| `machine.harness_login_input` | A line was sent to it: `chars` only, never the text. |
| `machine.harness_login_finished` | It ended, with `loggedIn`, `success` and `status`. Outcome `failure` if no login was saved, or with `error` if the machine was lost. |
| `machine.harness_login_aborted` | It was stopped: `reason` is `asked` or `caller_left`. |
| `machine.harness_logged_out` | Its credential files were removed, with `removed`. |
| `machine.harness_login_changed` | A heartbeat showed a login appear or go, however it happened (`from`, `to`). |
| `machine.folder_sync_started` | A copy began: `trigger` is `assigned`, `admin` or `retry`. |
| `machine.folder_sync_finished` | It ended, with `files`, `bytes`, `sent`, `skipped`, `copied`, `unchanged`, `seeded`, `kept` and `conflicts`. |
| `machine.folder_sync_failed` | Outcome `failure`, with `reason` (`too_big`, `offline`, `agent_outdated`, `agent_error`, `source_changed`, `no_folder`) and `error`. |
| `bot.run_refused` | Now also with reason `harness_not_logged_in` or `folder_copying`. |

## Choices where ADRs met

- **ADR 0037 runs logins at the admin's terminal on the server.** A machine is reachable only through botd's mutual-TLS channel (ADR 0031, ADR 0035: no SSH by default). So the login runs on the machine, and botd relays its terminal. The terminal shows sign-in links and device codes, which pass through botd's memory but are never written down. What the person types does too. The credentials themselves never reach botd.
- **ADR 0039 left machine logins until per-user accounts (#30).** A machine belongs to one user, and runs there already skip per-user accounts (ADR 0037). So logins live in the agent's HOME, where every run on that machine finds them. A separate OS user for Bots on the machine stays future work, as in ADR 0036.
- **ADR 0036 sends per-user secrets in the job.** That stays. A key in the user's secrets is enough without a login, so turning logins on never breaks a user who relies on keys.
- **ADR 0036 makes botd the keeper of memory and facts.** The copy only seeds them, so it never undoes their sync back.
- **No database migration.** Folder status lives in the existing settings table, keyed by machine, and logins live only on the machine.

## Consequences

- Self-hosting doesn't change. Without `MACHINE_CONTROL_URL` none of this runs. With it, nothing changes unless `MACHINE_HARNESS_LOGINS=on` or `MACHINE_FOLDER_SYNC=on`. Any of the three settings without `MACHINE_CONTROL_URL` is a startup error, and so is `MACHINE_FOLDER_SYNC_MAX_MB` without `MACHINE_FOLDER_SYNC=on`.
- A user's own Claude Code or Codex subscription works on their machine. The credentials stay there: on the machine's disk, and in its Linode backups (`MACHINE_BACKUPS`).
- Turning logins on refuses routed `claude` and `codex` runs of users who have neither a login there nor a key. Turn it on once those users can log in.
- The agent runs as root and so do Bots there (ADR 0036). The link and path checks on landing files are a guard against mistakes, not a security boundary against a Bot on that same machine.
- The check before a rename and the rename are two steps, so an edit landing in that instant can still be replaced. Writes into a file someone holds open are not caught either. Both are far narrower than a whole copy, and the next copy lists the file as a conflict if it differs.
- Codex's device-code login may need device sign-in turned on in the person's ChatGPT security settings.
- Tests run the real agent over real mutual TLS on loopback, with a stand-in `claude` whose login reads a code in its terminal. They cover:
  - a run refused before the login, the login through the API with typed input, the run going ahead after, then logout and refusal again;
  - a key in the user's secrets being enough;
  - the code and the credentials never reaching botd's audit or database;
  - stopping a login, a login counting as busy for upgrades, and harnesses with no login;
  - the copy on assign: files (an empty one too), the exec bit, skipped links, seeds;
  - a second copy that sends nothing, a conflict kept on the machine, and a too-big folder;
  - an offline machine that is retried;
  - everything being off by default.

  Agent unit tests cover the terminal (no echo), resuming chunks, hash mismatches, empty files, exec bit changes, an edit made while placing being kept, temporary names that never remove what's there, and refusing paths outside the allowed ones or through links. botd unit tests cover listing without following links, and refusing a file swapped for a link or another file before it is sent.

## Not in this slice

- **A login screen in the client.** The API for the person themselves is there (`/api/machine/harness-login*`). botctl talks only to a server on its own machine, so for now an admin runs the login with them.
- **Turning off Claude Code's auto-updater** on machines (ADR 0039 noted the drift).
- **Copying back.** Files the Bots make on the machine stay there. Only memory and facts go back to botd, as before.
- **Deleting** files that were removed on the server, and moving a copy of `.claude`/`.codex` from a per-user account (ADR 0037) to the machine. People log in again there instead.
- Screens on machines, a separate OS user for Bots on the machine, upgrading machines enrolled before ADR 0039, and per-user containers on one virtualised server, as before.
