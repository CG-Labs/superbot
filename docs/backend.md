# Backend

One Rust binary, `botd`. It serves the landing page (`/`), the admin console (`/console/`), and the API, stores everything in SQLite, and runs each Bot on a coding-agent CLI. The client is served at `/app/` by Caddy ([deploy/README.md](../deploy/README.md)).

## Pages

- `/` and `/get-started`: the public landing page and the request-access form, from `site/`. Same page for everyone, no trackers or external assets ([ADR 0022](adr/0022-landing-and-signups.md)).
- `/console/`: the built-in admin and break-glass page (`web/`), for admins only: **Users** (add, roles, disable, sign-in codes, sign out everywhere), sign-up **Requests**, **Machines** (per-user machines from the control plane), the **Audit log**, and **Settings** (approval mode for all Bots, sign-in options, server secrets, SCIM tokens). It has no chat, Bots, or screens; those are in the app. It runs under a strict Content-Security-Policy. Members and read-only users go to `/app/`; signed-out visitors go to `/login`. `/console` redirects here ([ADR 0027](adr/0027-expo-primary-hermes-default.md), [ADR 0032](adr/0032-console-admin-only.md)).
- `/login`: the sign-in page, also for break-glass. Sign-in lands admins on `/console/` and everyone else on `/app/` (`landing` in `GET /api/auth/me`). Web SSO sign-ins land the same way.
- `/app/`: the client, the interface for everyone, when Caddy serves it. It picks up a session the sign-in page left in the browser. Without Caddy's client, botd sends admins to `/console/` and shows everyone else a "web app isn't installed" page.

botd embeds `site/` and `web/`. Set `SITE_DIR` or `WEB_DIR` to serve them from disk while editing.

## How it works

- **Bots** live in SQLite. Each Bot has a harness (`claude`, `codex`, `pi`, or `hermes`), an optional model, and a harness session id.
- **A message** is queued. Each Bot runs one task at a time, in order. Different Bots run in parallel.
- **A run** spawns the harness CLI in its owner's folder, streams its JSON events, and saves each text block as a chat bubble.
- **Live updates** go to the browser over one Server-Sent Events stream: new messages, streaming text, and what the Bot is doing ("Running: ls").
- **Memory** is plain files, re-sent in the system prompt every run. The Bot edits them itself:
  - `DATA_DIR/bots/<id>/MEMORY.md`: one Bot's job, rules, and work log.
  - `DATA_DIR/users/<owner>/USER.md`: facts about the Bot's owner, shared by that user's Bots.
- **The computer** is one per user: `WORKSPACE_DIR/users/<owner>/`, shared by that user's Bots. Each Bot gets its own API token and its owner's saved secrets. See [ADR 0029](adr/0029-per-user-isolation.md). With `ISOLATION=users`, each user's Bots also run as their own Unix account; see [One Unix account per user](#one-unix-account-per-user).
- **Routines** are cron schedules. Bots create them with the `botctl` CLI, which works from any harness's shell.
- **Bot to Bot**: a Bot runs `botctl ask "<Bot>" "<message>"`. The other Bot answers in its own chat and the reply prints back. If it takes over 9 minutes, the reply arrives later as a new message.
- **Model and effort** are saved per Bot. The app shows a picker in the chat. Unset means the harness default.
- **Choice cards**: a reply ending in a ` ```question ` JSON block becomes a multiple-choice card.
- **Approvals**: in `ask` mode, risky tool calls wait for a person. See [Approvals](#approvals).
- **Audit log**: admin actions go into an append-only table. See [Audit log](#audit-log).
- **Restarts**: queued messages run after a restart. A task that was running is reported as interrupted, not re-run, so it can't repeat an action like sending an email.

## Harness adapters

Each adapter is one file in `server/src/adapters/`. It builds the command line and maps the CLI's JSON lines to five events: session, text delta, text, tool, error.

- **Claude Code**: `claude -p --output-format stream-json --resume <id>`. System prompt via `--append-system-prompt`, fresh every run.
- **Codex**: `codex exec --json`, then `codex exec resume <id>`. Instructions via `-c developer_instructions=...`. Codex only reads them when a session starts, so later memory edits reach it through the memory file.
- **Pi**: `pi --mode json --session-dir <bot dir> --session-id <id>`. System prompt via `--append-system-prompt`.
- **Hermes Agent**: `hermes chat --oneshot --query-file - --format stream-json --source tool`, prompt on stdin, then `--resume <id>`. System prompt via `HERMES_EPHEMERAL_SYSTEM_PROMPT`. See [Hermes Agent](#hermes-agent).

All four run with the harness's own permission prompts off (`--dangerously-skip-permissions` and equivalents): nobody is at a terminal to answer them. In `ask` mode, each adapter adds a hook that runs `botctl hook <harness>` before every tool call instead:

- **Claude Code**: a `PreToolUse` command hook via `--settings`.
- **Codex**: the same hook via `-c hooks.PreToolUse=...` and `features.hooks=true`.
- **Pi**: a small generated extension (`--extension`) that runs the same command on `tool_call`.
- **Hermes Agent**: a `pre_tool_call` shell hook with `fail_closed: true`, in a Hermes managed config. Hermes runs hooks in its own folder, so the hook names the Bot's: `botctl hook hermes --cwd <workspace>`.

The server is still the computer, so treat it that way. Details and trade-offs: [ADR 0007](adr/0007-approvals.md).

### Hermes Agent

[Hermes Agent](https://github.com/NousResearch/hermes-agent) (Nous Research, MIT), tested on v0.23.2. Design: [ADR 0011](adr/0011-hermes-agent-backend.md) option (a), details in [ADR 0015](adr/0015-hermes-adapter.md).

- **Install**: `deploy/install.sh --with-hermes`, or `hermes` in `SUPERBOT_HARNESSES` for Docker ([deploy/README.md](../deploy/README.md)). Both pin a commit. Then pick Hermes Agent for a Bot in its settings, or set `DEFAULT_HARNESS=hermes`.
- **Provider and key**: save the key encrypted, e.g. `botctl secret set OPENROUTER_API_KEY < key.txt`. Saved secrets reach Hermes as env vars; Hermes hides its provider keys from the agent's shell. `SUPERBOT_HERMES_PROVIDER` and `SUPERBOT_HERMES_BASE_URL` in `.env` become `--provider` and `--base-url`; empty means Hermes's own config. The model is free text (Hermes can't list models without a prompt): the apps show a text field, and the web UI an "Other model…" choice. Effort maps to `--reasoning` (`none` to `ultra`).
- **Per Bot**: each Bot has its own Hermes data root, `DATA_DIR/bots/<id>/hermes`. The first run of a new Bot prepares Hermes's dependencies there: about 20 seconds and 0.5 GB, once.
- **Settings botd enforces** go in `DATA_DIR/bots/<id>/hermes-managed/config.yaml` (Hermes's managed scope, 0600, rewritten every run): the approval hook, tool env passthrough (variable names only, never values), Hermes's own memory off, and its cron tools off. botd owns memory and routines.
- **Daemon**: `hermes chat` hands the turn to a Hermes gateway daemon that outlives it. botd runs `hermes gateway stop --yes` for the Bot before and after every run, so stopping a Bot ends the turn and each run gets fresh env.
- **Approvals**: Hermes stops hooks after 300 seconds, so a Hermes Bot's approval waits at most 4 minutes, then counts as denied. Hermes's own dangerous-command prompt is off (`--yolo`): SuperBot's hook is the gate, like the other harnesses. Tools: `terminal` is a shell tool (its `workdir` counts as a folder the command runs in), `write_file` and `patch` are file tools, and text typed into a running program with `process_manage` is checked as a command.
- **Limits**: `execute_code` runs Python like `python3 script.py` does for other harnesses; the hook sees the tools a script calls, not the script's own system calls. If the hook can't run (crash, bad output, timeout), Hermes blocks the tool.

Add a harness: write one adapter file and add it to `get()` and `NAMES` in `adapters/mod.rs`.

## Run it

```sh
cargo build --release          # makes target/release/botd and target/release/botctl
cp .env.example .env           # fill it in
set -a; . ./.env; set +a
./target/release/botd
```

Settings are in [.env.example](../.env.example). Keep `botctl` next to `botd`: the server puts that folder on the Bots' PATH.

## Deploying on a Linux VPS

- Keep your server IP, domain, and secrets out of this repo. They go in `.env` on the server.

- Install the harness CLIs you want and log them in **as the user that runs `botd`**: `claude` (then `claude login` or `ANTHROPIC_API_KEY`), `codex` (`codex login` or `OPENAI_API_KEY`), `pi` (provider API key, e.g. `OPENROUTER_API_KEY`), `hermes` (provider API key, see [Hermes Agent](#hermes-agent)). Their env vars pass through to the Bots. With [one Unix account per user](#one-unix-account-per-user), install them system-wide and log them in per user with `botctl user harness-login` instead.
- Run `botd` as a normal user, not root. Claude Code refuses to skip permissions as root.
- Run it under systemd with `Restart=always`. It shuts down cleanly on SIGTERM.
- Put HTTPS in front (e.g. Caddy) and set `AUTH_PASSWORD` and `HOST=127.0.0.1` behind the proxy (recommended). The browser logs in with any username and that password.
- Set `ALLOWED_HOSTS` to the domain your proxy forwards (blocks DNS rebinding). See the one-command installer in [deploy/README.md](../deploy/README.md).
- Proxies must not buffer `/api/events` (it's an SSE stream).
- Set `TZ` to the user's time zone. Routines use it.
- Back up `DATA_DIR`. `WORKSPACE_DIR/users/<id>/` is each user's scratch and files.
- Sign-ups are on by default: anyone can ask for access at `/get-started`, and nothing happens until an admin approves. See [Sign-ups](#sign-ups).
- `GET /healthz` returns `{"ok":true}` without auth.

## Approvals

The policy decides what each tool call does: run, ask a person, or be blocked.

- **Modes**: `ask` pauses risky calls. `bypass` runs everything, as before (dev only).
- **Risky classes**, each set to `allow`, `ask` (default), or `deny`:
  - `shell_destructive`: `rm -rf` on the workspace or system paths, `git reset --hard`, `dd`, `mkfs`, `DROP TABLE`, `sudo`, ...
  - `file_delete`: deleting files outside the workspace.
  - `outbound_message`: mail CLIs, `gh pr create`/comments, chat webhooks, messaging MCP tools.
  - `network_install`: `apt`, `brew`, `npm i`, `pip install`, `cargo install`, `curl ... | sh`.
  - `git_push`: any `git push`, and `git config` that changes what a push does (a remote's push refspecs or mirroring, `push.*`, aliases).
- **Shell commands** are parsed like `sh`/`bash` reads them (`server/src/shell.rs`): every command in pipes, lists, groups, `$(…)`, backticks, `<(…)`, `${…}`, and expanding here-documents is checked. `$'…'` escapes are decoded as bash does. A command whose name is only known at run time (`$CMD`, `gi?`, `{git,x}`, `eval "$X"`, `bash -c "$S"`) counts as `shell_destructive`.
- **Scripts and hidden code** ([ADR 0053](adr/0053-smarter-command-analysis.md)): a script the command runs from the Bot's workspace (`./x.sh`, `bash x.sh`, `source x.sh`, `python3 x.py`, `node x.js`, Ruby, Perl, PHP) is read (at most 256 KiB, 32 files, never through a link out of the workspace) and classified like the command line; what it finds says where ("Pushes to a git remote (in deploy.sh)"). Inline code (`bash -c`, `python3 -c`, `node -e`, here-documents, here-strings, `echo … | sh`) is checked the same way. Shell is parsed; other languages are scanned for calls that run commands, run code, delete files, or send email. A script that is missing, too big, unreadable, outside the workspace, written by the same command, or on the Bot's own machine asks. Decoded or piped code (`base64 -d | sh`, `xxd -r`, `printf '\x..' | sh`, `eval "$(…)"`, `make | sh`) asks as `shell_destructive`, so it is approved one call at a time.
- **Folders**: a `cd` may fail or run in a subshell, so a relative path must be inside the workspace from every folder the command could be in. When a folder can't be known (`cd -`, `cd "$D"`, `popd`, `source`), relative deletes count as outside.
- **Shell tools** may send `command` or `cmd`, as text or argv. A shell call with neither, or two that differ, is denied.
- **Unreadable commands are denied**, whatever the classes or rules say: unclosed quotes or substitutions, syntax the parser doesn't know, over 1 MiB, nesting over 16 levels, or over 10,000 commands. The Bot is told why, so it can simplify the command.
- **Rules**: `deny` rules (the deny list) always block. `allow` rules skip asking, unless the class is `deny`. Patterns are globs (`*`, `?`) over the command, path, URL, or tool arguments. "Remember" on an approval saves an exact-match rule for that Bot.
- **Scope**: one global policy, plus optional per-Bot overrides.
- **Timeout**: an unanswered approval is denied after `timeoutMinutes` (default 10; at most 4 for Hermes Agent Bots). Stopping the Bot, the run ending, or a server restart also closes it.
- **Turning approvals on** stops any task that started in `bypass` (it has no hook), with a note to send it again.
- **Remember** saves an exact rule. Calls too long to store whole (over 4,000 characters) can be approved or denied, but not remembered.
- **Approve for this run** approves the call and, until that run ends, later calls of the same kind from the same Bot in the same run: the same tool, and no risky class or reason beyond the approved call's (a plain `git push` never covers a force push, nor `npm install` a `curl | sh`). Deletes outside the workspace are covered only when repeated exactly. Destructive shell commands, downloaded scripts, and typed input are approved one at a time. Nothing is saved: the grant ends when the run finishes, is stopped, times out, or the server restarts. Deny rules and deny classes still win. The approval's `runScope` says what it would cover (null when it can only be approved once). See [ADR 0051](adr/0051-approve-once-per-run.md).
- **Audit**: every request, decision, timeout, and policy or rule change is in the [audit log](#audit-log). A run approval is `approval.approved` with `scope: "run"`, the `runId`, and what it `covers`; each call it lets through is `policy.allowed` with the approval as its target.
- **Who decides**: a signed-in admin or member (see [users and roles](#users-sessions-and-roles)). Bots' token and read-only users get 403 on decisions; only admins change policy and rules.

Fresh installs start in `ask`. Installs from before approvals keep `bypass` until you opt in:

```sh
SUPERBOT_PASSWORD=<your AUTH_PASSWORD> botctl policy set global mode=ask
```

Or use the app: **Approvals → Edit risky actions, timeout, and rules** for all Bots, or a Bot's details for that Bot ([ADR 0049](adr/0049-policy-editor-in-the-apps.md)). Admins also have **Settings → Risky actions** in the admin console (`/console/#settings`) for all Bots. More operator commands: `botctl admin`. botctl only sends the password to a server on the same machine (loopback), since it speaks plain http; from elsewhere, use an SSH tunnel.

```sh
botctl policy set global timeout=15 git_push=deny   # never push, ask longer
botctl policy set <bot-id> mode=bypass              # one dev Bot runs freely
botctl policy set <bot-id> git_push=inherit         # back to the global action
botctl rule add deny "rm -rf /srv/*"                # deny list
botctl rule add allow "npm install*" --bot <bot-id> # this Bot may install npm packages
botctl approvals | botctl approve <id> [--run | --remember] | botctl deny <id>
```

Limits: the parser sees commands and the scripts they run, not what compiled programs do inside, and its scan of languages other than shell is a heuristic, so this catches mistakes and prompt injection, not a determined attacker. Bots run as the same OS user as `botd`. See [ADR 0007](adr/0007-approvals.md).

Each harness's hook is tested end to end against its real CLI at the pinned version (`server/tests/harness_e2e.rs`, the `harness-e2e` workflow), with a fake model; `deploy/harness-e2e.sh` runs the same checks with real models on a logged-in server. Codex runs hooks in `codex exec` from 0.141.0 ([ADR 0057](adr/0057-harness-hook-e2e-tests.md)). A guarded Codex run checks `codex --version` where and as whom it will run (this server, as the run's account with per-user accounts, or the owner's machine as a job) and is refused before it starts on anything older, or on a version it can't read: `bot.run_refused` with reason `harness_outdated` (and `version`) or `harness_version_unknown` (and `detail`), plus `minimum`, `host` and `machine`, and the Bot says how to update it. A version that passed is remembered for 10 minutes (on this server, until the `codex` file changes; on a machine, per user and working folder); a refusal never is, so the next run after an update goes through. Unguarded runs aren't checked, and the canary still stops a harness that skips the hook ([ADR 0059](adr/0059-refusing-guarded-runs-on-old-codex.md)).

### Harness sandboxes

On top of approvals, the policy's `sandbox` turns on the harness's own sandbox ([ADR 0055](adr/0055-harness-sandbox-defaults.md)). It is separate from the mode, so it holds in `bypass` too.

- **Codex** runs `codex exec` in `workspace-write` with the network on: commands write only in the workspace, `/tmp`, and the folders below.
- **Claude Code** gets its Bash sandbox: the same writes, its proxy for the network (any host, plus botd's API for `botctl`), and no way out of the sandbox for a command. Its file tools and hooks run outside it, as in Claude Code itself.
- **Pi** and **Hermes Agent** have no sandbox of their own to turn on, so their runs are unchanged.
- **Also writable**: the Bot's memory and facts folders, and package caches under HOME (`~/.cache`, `~/.npm`, `~/.cargo/registry` and `git`, `~/go/pkg/mod`, Bun, Yarn, Gradle, Maven), made as the run's user when missing so a first build works. With per-user accounts, also the account's own `TMPDIR` (`~/.tmp`). HOME itself, harness logins, and `~/.local` stay read-only. With Codex, a `.git` at the workspace's top is read-only too, so commit in a repo folder inside it.
- **Needs** unprivileged user namespaces, `bubblewrap`, and (Claude Code) `socat` on Linux; macOS has what it needs. The installer adds both packages. botd checks at start, per harness (Codex needs user namespaces; Claude Code also a working `bwrap` and `socat`): a harness whose sandbox can't start runs without it on the server, botd says so at start, the policy editors warn, and `harness.invoked` records `sandbox: "unavailable"`. Ubuntu 24.04 limits user namespaces with AppArmor; allow them for `bwrap` to use sandboxes there. The Docker image blocks them, so Compose runs go without.
- **Machines** check for themselves and say so with each run; runs there go without when their harness's sandbox can't start. An agent from before this check gets the sandbox settings anyway, recorded as `unverified`. If Codex's sandbox fails anyway (an agent from before this check), the run says to install bubblewrap or turn the sandbox off for that Bot.
- **Audit**: changes are `policy.updated`, like the rest of the policy. Each `harness.invoked` says `sandbox`: `on`, `off`, `unsupported` (Pi, Hermes), `unavailable`, or `unverified`.

Fresh installs start with it on. Installs from before keep it off (recorded as `policy.sandbox_initialized`) until you opt in:

```sh
botctl policy set global sandbox=on      # every Bot
botctl policy set <bot-id> sandbox=off   # one Bot that needs to write elsewhere
botctl policy set <bot-id> sandbox=inherit
```

## Secrets

API keys and tokens for Bots come from two places, first match wins:

1. **Environment**: `NAME=value` in `.env`, or `NAME_FILE=/path` (Docker/systemd secrets). Same for `AUTH_PASSWORD` (`AUTH_PASSWORD_FILE`).
2. **Saved secrets**, encrypted in SQLite: `botctl secret set OPENAI_API_KEY < key.txt` (value on stdin), `botctl secrets`, `botctl secret rm NAME`. Bots get them as environment variables from their next run. The exceptions are SSO client secrets (`SSO_<ID>_CLIENT_SECRET`), `TURNSTILE_SECRET` and `LINODE_TOKEN`: only botd uses them, and they (with their `_FILE` forms and every `SSO_*` variable) are kept out of Bots' environments.

Saved secrets and every approval's tool input are sealed with XChaCha20-Poly1305 under a master key: `SUPERBOT_MASTER_KEY` (64 hex chars), or the 0600 file in `SUPERBOT_MASTER_KEY_FILE` (default `~/.config/superbot/master.key`, created on first start). The key never lives in `DATA_DIR`, so backups don't carry it. botd won't start with a wrong key, or without the key once something is sealed.

Values never come back out: the API lists names only. Known values (saved and env secrets, `AUTH_PASSWORD`, the Bots' token, screen tokens, the key) and any session token, sign-in code, SSO handoff code, or SCIM token botd issued (`sbs_…`, `sbc_…`, `sbh_…`, `sbp_…`) are replaced by `[redacted]` in saved chats, approvals, the audit log, and live events. Upgrading seals old approval inputs and scrubs known values from saved chats on first start. Without [per-user accounts](#one-unix-account-per-user), Bots run as botd's OS user, so this protects copies of the database, not the running server. See [ADR 0010](adr/0010-secrets.md).

## Audit log

Admin actions are recorded in `audit_events` in `app.sqlite`: who (person, Bot, or system part), what (`bot.created`, `routine.disabled`, `approval.denied`, ...), the target, the outcome, the source IP and user agent, and a few scrubbed details. Logins and failed logins, Bot and routine changes, policy, rules, approvals, handoffs, Bot-token calls, Bot runs (`bot.run_finished`), and harness starts (`harness.invoked`) are all covered; the full list is in [ADR 0009](adr/0009-audit-events.md).

- **Who, exactly**: a person's id, name, email, and role when they acted; how they signed in (`password` = break-glass `AUTH_PASSWORD`, `code`, `sso`, `none`, `bot_token`, `scim_token`); for SSO, the IdP type (`entra`, `google`, `oidc`, `github`, `apple`, `saml`), its configured provider id, and their IdP subject; and the session id. A Bot (or a routine) records whose authority it used: its owner, as `onBehalfOf`. A Bot run is attributed to whoever queued it: the person who sent the chat, the Bot that asked, or the scheduler. Rows from before this was added leave these empty. Design: [ADR 0019](adr/0019-audit-actors.md).

- **Append-only**: no API edits or deletes rows, and SQLite triggers refuse `UPDATE` and any `DELETE` inside the retention window.
- **No secrets**: passwords, tokens, message bodies, and routine instructions are never recorded. Details are scrubbed and clipped anyway.
- **Retention**: `AUDIT_RETENTION_DAYS` (unset or `0` = keep forever, the default). Pruning runs every 6 hours and is itself logged. Backups copy the table with the rest of `app.sqlite`.
- **Source IP**: the peer, or the last `X-Forwarded-For` entry when the proxy is on loopback. Set `TRUST_FORWARDED_FOR=1` only when `botd` is reachable solely through your proxy (Compose sets it).
- **Read it**: the Audit log in the app or the admin console (filters and Export CSV), or:

```sh
export SUPERBOT_PASSWORD=<your AUTH_PASSWORD>
botctl audit --action 'bot.*' --from 2026-11-01            # newest first
botctl audit export --actor user --to 2026-11-30 > audit.csv
botctl audit --actor user:ada@example.com --method sso      # one person's SSO actions
botctl audit --on-behalf-of ada@example.com --action 'harness.*'   # what her Bots ran
botctl audit export --session <session id> > session.csv   # everything one sign-in did
```

CSV export is RFC 4180 with CRLF line endings, oldest first. Columns: `id,time,actor_kind,actor_id,actor_name,actor_subject,action,target_type,target_id,bot_id,outcome,ip,user_agent,details,actor_email,actor_role,auth_method,idp,idp_provider,session_id,on_behalf_of` (the last seven were added after the first fourteen, which keep their positions). Cells that start with `=`, `+`, `-`, `@`, tab, or CR get a leading `'` so spreadsheets don't treat them as formulas.

## Users, sessions, and roles

People are users with a role: **admin** (everything), **member** (use and manage Bots and routines, decide approvals), or **read-only** (see everything, change nothing). Admins also manage policy, the audit log, users, sessions, and saved secrets. One check per API route enforces it; unknown routes are admin-only. Design: [ADR 0012](adr/0012-users-sessions-rbac.md).

- **Owner**: made on first start as admin `operator` (name `USER_NAME`, email `OWNER_EMAIL`). `AUTH_PASSWORD` signs in as the owner (break-glass) while `AUTH_BREAK_GLASS` is on, the default. Set `AUTH_BREAK_GLASS=0` to ignore the password once admins sign in another way.
- **Everyone else**: signs in with Microsoft Entra ID, Google, GitHub, Apple, any OpenID Connect IdP (Okta, Keycloak, Auth0, …), or a SAML IdP (ADFS, Okta, …) through a Keycloak bridge when set up, several at once if you like ([Entra](sso/entra.md), [Google](sso/google.md), [GitHub](sso/github.md), [Apple](sso/apple.md), [OIDC](sso/oidc.md), [SAML](sso/saml.md), [ADR 0014](adr/0014-oidc-sso-entra.md), [ADR 0016](adr/0016-sso-multi-provider.md), [ADR 0018](adr/0018-sso-github-apple.md), [ADR 0020](adr/0020-saml-bridge.md)): an admin links their account at each IdP to a user (`botctl user link`), or just-in-time sign-up makes one. Email never links accounts. Or an admin gives them a one-time sign-in code, which they enter in the web app or client. Codes are single use and expire (default 1 hour).
- **Admin portal**: admins manage all of this in the app too (`/app/`, **Users** in the sidebar): approve or reject [requests for access](#sign-ups), add people, give them a one-time code (1 hour, 24 hours, or 7 days) with a ready-to-send invite and link, change roles, disable, sign out everywhere, link SSO accounts, and see each person's last sign-in and Bot access. Design: [ADR 0021](adr/0021-admin-portal.md).
- **Disabled users' routines** ([ADR 0047](adr/0047-disabled-users-routines.md)): disabling someone (portal, API, `botctl`, or SCIM) pauses every routine that runs for them: on their Bots (`owner_disabled`) or written by them on others' (`author_disabled`). The scheduler and runner refuse any routine whose owner or author is disabled anyway, and it can't be turned back on (409). Re-enabling leaves them paused until an admin resumes them (`botctl user resume-routines`), unless `ROUTINES_ON_ENABLE=resume`. An admin can hand a disabled user's Bots and routines to someone else (`botctl user handover <user> <to> [--resume]`); routines on Bots the new person can't use stay paused.
- **Sessions**: the sign-in page and the console get an HttpOnly cookie, the client and `botctl` a bearer token. They end after `SESSION_IDLE_TIMEOUT` without use (default `7d`) or `SESSION_MAX_AGE` after sign-in (default `30d`), on logout, or when an admin revokes them or disables the user. Only hashes are stored.

```sh
export SUPERBOT_PASSWORD=<your AUTH_PASSWORD>      # or: botctl login <code>, then export SUPERBOT_TOKEN=...
botctl user add alex@example.com "Alex" --role member
botctl user code alex@example.com                   # one-time code for Alex
botctl users | botctl sessions alex@example.com
botctl user role alex@example.com readonly | botctl user disable alex@example.com
botctl session revoke <id> | botctl session revoke-all alex@example.com
botctl user routines alex@example.com | botctl user resume-routines alex@example.com
botctl user handover alex@example.com sam@example.com --resume
botctl user link alex@example.com entra <object-id> | botctl user identities alex@example.com
```

### Sign-ups

People ask for access on the get-started page. An admin approves or rejects each request; approving makes the user and a one-time sign-in code (3 days by default), shown once. **No email is sent**: hand the code over yourself. Design: [ADR 0022](adr/0022-landing-and-signups.md). In the app, pending requests are under **Requests** at the top of **Users** ([ADR 0021](adr/0021-admin-portal.md)); from a shell:

```sh
botctl signup list                                  # pending; or approved, rejected, all
botctl signup approve <id> --role member            # prints the code once, and SSO providers to link
botctl signup reject <id> --reason "Not a customer"
```

- **Limits**: 5 requests per IP per hour, 16 KiB bodies, one pending request per email, at most 1000 pending. A hidden honeypot field and a duplicate both get the normal "received" answer, and nothing is saved.
- **Bot check**: set `TURNSTILE_SITE_KEY` and `TURNSTILE_SECRET` (or `TURNSTILE_SECRET_FILE`) to require [Cloudflare Turnstile](https://developers.cloudflare.com/turnstile/). Both or neither. If Cloudflare can't be reached, requests are refused.
- **Off**: `SIGNUPS=off` closes the form (the API answers 404).
- **SSO**: approving doesn't link an IdP account (email never links). The confirmation page and the approve response name the providers that fit; link with `botctl user link`.
- **Email hook**: `signups::notify` is called with each notice (received, approved with the code, rejected). It sends nothing today.
- **Audit**: `signup.submitted`, `signup.refused` (honeypot, throttled), `signup.approved` (with `user.created` and `user.login_code_created`), `signup.rejected`.

### SCIM provisioning

Entra ID, Okta, or another SCIM 2.0 client creates, updates, disables, and deletes users at `/scim/v2`. Users only; groups come later. Setup: [sso/scim.md](sso/scim.md). Design: [ADR 0023](adr/0023-scim.md).

```sh
botctl scim token create entra --sso entra          # the sbp_ token, once; --sso: externalId is the SSO subject
botctl scim tokens | botctl scim token revoke <id>
```

- **Off by default**: `SCIM=on` turns it on; off, `/scim/v2` answers 404. New users get `SCIM_DEFAULT_ROLE` (`member` or `readonly`; `admin` is refused at start). SCIM never changes roles.
- **Tenants**: each token belongs to a tenant (one IdP connection), which sees only the users it provisioned. Only token hashes are stored. Session tokens and the password don't work on `/scim/v2`, and SCIM tokens don't work on `/api`.
- **One user per person**: with `--sso`, provisioning links the person's SSO identity, or takes on the user an admin already linked it to. Email never matches: a user with the same email is a 409. Never the owner account.
- **Deprovisioning**: `active: false` disables the user and ends their sessions. `DELETE` does the same and hides the user from the tenant; nothing is destroyed, and the same `externalId` brings the same user back.
- **Limits**: 600 requests a minute per tenant, 20 bad tokens per IP in 10 minutes (then that IP's bad tokens get 429; a valid token from it still works, [ADR 0026](adr/0026-scim-review-hardening.md)), 64 KiB bodies, 200 users per page.
- **Audit**: actor `system` `scim:<token id>`, method `scim_token`. `user.created` (`reason: scim`), `user.updated`, `user.disabled`, `user.enabled`, `user.identity_linked`, `scim.user_linked`, `scim.user_deleted`, `scim.user_restored`, `scim.token_created`, `scim.token_revoked`, `scim.auth_failed` (throttled; `reason` is `missing`, `unknown`, or `revoked`, with the revoked token as target). A SCIM token sent to `/api` is logged as `auth.login_failed` with method `scim_token`.

### Shared and private Bots

Each Bot has an owner and is **shared** (everyone can use it) or **private** (only its owner, admins, and people it's granted to). Grants are **viewer** (read its chat) or **operator** (also run it). Only the owner or an admin changes a Bot's settings, deletes it, or changes who sees it; only an admin gives it to someone else. Read-only users can view, never run. A Bot acts with its owner's access, so it only sees and asks Bots its owner can. Bots from before this stay shared and belong to the owner account. Design: [ADR 0017](adr/0017-bot-acls.md).

```sh
botctl bot access <bot-id>                          # owner, visibility, grants
botctl bot private <bot-id> | botctl bot share <bot-id>
botctl bot grant <bot-id> alex@example.com operator # or viewer
botctl bot revoke <bot-id> alex@example.com
botctl bot owner <bot-id> alex@example.com          # admins only
```

### Tiers and model routing

Each user is on a **tier** (a plan). A tier lists the harness and model **routes** its users' Bots may run on, and limits per user: `maxBots`, and per billing period `monthlyRuns` and `monthlyTokens` (model tokens, as harnesses report them). Design: [ADR 0033](adr/0033-tiers-model-routing.md).

- **Default: nothing changes.** Without `TIERS_FILE` there is one tier, `self-host`: any harness and model, no limits.
- **Turn on**: copy [`deploy/tiers.example.json`](../deploy/tiers.example.json), edit it, set `TIERS_FILE` to its path, and restart. `DEFAULT_TIER` (or the file's `default`, else its first tier) is the tier for users without one. botd refuses to start on a bad file.
- **Managed tiers** (with routes): each run takes the route the Bot **owner's** tier picks (the Bot's model if the tier has it for that harness, else the harness's first route; provider and effort always from the route). A harness outside the tier doesn't run. Setting a model, effort or harness outside the owner's tier is a 403, for admins too. Only admins see model names; others see the plan.
- **Assign**: `botctl user tier alex@example.com pro` (or `default`), or `PATCH /api/users/:id {tier}`. Admins only; audited as `user.tier_changed`. `botctl tiers` lists them.
- **Audit**: `harness.invoked` records the tier and route; refusals are `bot.run_refused` with reason `tier_harness`, `tier_limit`, or `tier_token_limit`.

### Usage and token metering

Each run's model tokens are recorded for its Bot's **owner**, the same person its run counts for: one row per model with input, output, cache-read and cache-write tokens, the Bot, a run id, and the time. Hermes Agent, Claude Code, Codex and Pi report tokens; a run whose harness reports none is recorded as **unknown** (counted as a run, not as zero tokens). `harness.invoked` and `bot.run_finished` carry the `runId`, and `bot.run_finished` the run's tokens as `usage` (null when unknown). Design: [ADR 0050](adr/0050-billing-period-token-usage.md).

- **Billing period**: a user with a paid Stripe subscription counts runs and tokens in its period (a yearly plan's months, counted from its start); everyone else in the calendar month, UTC. Routine runs stay per UTC day.
- **Limit**: once a user's tokens reach their tier's `monthlyTokens`, their Bots' runs are refused until the next period: `bot.run_refused` (reason `tier_token_limit`, with `used`, `limit`, `period`) and a chat message saying when more start. The run that crosses it is audited as `usage.token_limit_reached` (by `billing`, on behalf of the user). Runs already going when the limit is reached finish, so use can pass the limit by those runs.
- **See it**: `GET /api/me/usage` and `botctl usage me` (yours), the client's Plan screen (offered with or without billing); a Bot you no longer own shows no name; `GET /api/users/{key}/usage` and `botctl usage user <user>` (admins); `GET /api/usage` and `botctl usage` add tokens per user.
- **Stripe meter** (off by default): set `STRIPE_METER_EVENT` to a Stripe meter's event name, with `STRIPE_SECRET_KEY`, and botd sends each run's tokens (for a user with a Stripe customer) as a meter event every minute, at most once each. A meter event Stripe refuses, or that can't reach it after five tries, is marked failed and audited as `billing.meter_failed`.

### One Unix account per user

With `ISOLATION=users`, each user's Bots run as that user's own Unix account, `sb-u-<user id>`, so one user's Bots can't read or write another's folder or harness logins, or botd's `DATA_DIR`, database, `.env`, and master key. **On for new installs** (`deploy/install.sh` and Docker Compose); an install from before keeps it off (unset or `off`), and botd's startup log says how to opt in: `deploy/install.sh --isolation`, or `ISOLATION=users` in Docker Compose's `.env`. Design: [ADR 0037](adr/0037-per-user-unix-accounts.md), [ADR 0058](adr/0058-harness-os-user-by-default.md).

- **Folders**: `ISOLATION_DIR/<user id>/` (default `/srv/superbot/users`) holds `home/` (the account's HOME, so its own `~/.claude` and `~/.codex`), `workspace/` (where its Bots work), `memory/` (copies of `USER.md` and each Bot's memory; botd keeps the originals in `DATA_DIR` and copies changes back after each run), `bots/<bot id>/` (a Bot's harness state: Pi's sessions, Hermes's `HERMES_HOME`), and `settings/<bot id>/` (Pi's approval guard and Hermes's managed config, which botd writes and the account can only read). Only that account and botd can open it.
- **How a run starts**: `sudo -n -E -u sb-u-<id> -- superbot-run <harness> ...`. botd may only start `superbot-run` as a per-user account, and `superbot-userctl ensure|remove|purge` as root to make an account or remove a leaving teammate's; nothing else. A user's account is made at their first run, or with `botctl user isolate <user>`.
- **Harness logins**: on the server, as botd's account, `botctl user harness-login <user> claude` (runs `claude auth login` as that user) or `codex`. `-- <args>` replaces the login arguments, e.g. `-- setup-token`. Pi and Hermes use provider keys. Per-user API keys as secrets still work too.
- **Limits**: screens are off. Harness CLIs must be installed system-wide (in Docker, baked into the image). Accounts share the network. botd takes other accounts' access off `DATA_DIR`, `.env` and `SUPERBOT_MASTER_KEY_FILE` at start, and warns about any it can't change.
- **Bots on their owner's machine** ([ADR 0036](adr/0036-bots-on-the-users-machine.md)) skip this: no account here, any harness the machine has, no sudo. Their memory syncs with botd's originals, and botd drops the stale copies in the user's folder here.
- **Turning it on or off** doesn't move files: work starts in the new folder, and the old one stays. Memory and `USER.md` carry over; harness sessions start fresh. To move files, see [deploy/README.md](../deploy/README.md#one-unix-account-per-user).
- **Audit**: `isolation.account_created`, `isolation.account_failed`, `harness.login_started`; `harness.invoked` adds `runAs`; refusals are `bot.run_refused` with reason `isolation_harness` or `no_account`.

### Shared Bots

A shared Bot always runs on its owner's computer ([ADR 0046](adr/0046-shared-bots-under-isolation.md)). `SHARED_BOTS=open` (the default with `MACHINE_ROUTING=off`) keeps the old rule: it acts as its owner for everyone. `SHARED_BOTS=isolated` (the default, and the only choice, otherwise): a run for anyone but the owner (the sender, the person behind an asking Bot, or a routine's author) gets the lesser of the owner's and that person's access to other Bots, server-wide keys only, and none of the owner's `USER.md`; it can't make Bots; a disabled owner's Bots don't run; new Bots are private. Bot views add `runsOn` and `sharedBots`. Audit: `forUser` on `harness.invoked`, `bot.run_routed` and `bot.run_refused`; refusals `owner_disabled`, `asker_lost_access`; `access.denied` with reason `asker_acl`; routines' `author`. A disabled user's routines are paused on every server, open or isolated ([ADR 0047](adr/0047-disabled-users-routines.md)).

**Teammates' own accounts on one server** ([ADR 0064](adr/0064-teammate-accounts-on-one-server.md)). With `ISOLATION=users` and `SHARED_BOTS=isolated`, a teammate's run of a Bot whose owner's Bots run on this server runs as an account of its own for that owner's Bots, never as the owner's: `sb-t-<first 24 hex of sha256("<owner>:<teammate>")>`, in `ISOLATION_DIR/<owner>-<teammate>/` (same layout as a user's), made by `superbot-userctl ensure <owner> <teammate>`. Neither the owner's account nor the teammate's own `sb-u-` account can enter it. `ISOLATION_TEAMMATES=on|off` (unset: on when both are set; `on` without them stops botd; `off` keeps the owner's account).
- **Logins**: the teammate logs Claude Code or Codex in from the Bot's details in the app, through the same API as on machines (`/api/machine/teammate/{owner}/harness-login*`, `on: "server"` in the view). The login runs as the pair account; its state is checked and logout removes files as that account. Admins: `botctl machine teammates <owner> logins|logout <teammate>`, or start one with `botctl user harness-login <teammate> <harness> --owner <owner>` (`POST /api/users/{teammate}/harness-login {"harness","owner"}`).
- **A run with no login of the teammate's own** and no server-wide key is refused (`bot.run_refused`, reason `teammate_not_logged_in`), never run on the owner's login.
- **Memory**: the run edits a fresh copy of the Bot's memory in the pair's folder; it goes back to `DATA_DIR` after the run. One that can't be saved is set aside as `<bot id>.md.unsaved` there and audited (`bot.memory_unsaved`). The owner's `USER.md` is never there.
- **Audit**: `isolation.account_created|account_failed`, `harness.login_*` and `harness.logged_out` carry `forUser` and `account`; `harness.invoked` carries the pair as `runAs`; `server.started` reports `isolationTeammates`.
- **Removed when the teammate leaves** ([ADR 0066](adr/0066-removing-teammate-accounts-on-one-server.md)): disabling, SCIM deprovisioning or deletion, or a Bot access change (grant revoked, made private, given away, deleted) queues the removal of each pair account whose teammate may no longer operate one of the owner's Bots (`offboard::wanted`), and a sweep at start and every 5 minutes finds the rest in the password file. `superbot-userctl remove` kills the account's processes as the account, hands its workspace to the owner's account (`workspace/from-teammates/<name>-<date>`; `ISOLATION_TEAMMATE_FILES=delete` holds it in `ISOLATION_DIR/.left/<id>` and `purge`s it after `ISOLATION_TEAMMATE_FILES_DAYS`), and deletes the folder, login, temp files, crontab and account. Never a user's own account. Pending until done, retried, cancelled only if never tried and not asked by an admin.
  - `GET /api/isolation/teammate-removals?state=pending|held|done|cancelled|open|all` → `{files, graceDays, removals}`; `GET /api/users/{key}/teammate-accounts` → `{userId, accounts: [{owner, teammate, account, wanted, removal}], removals}`; `POST /api/users/{owner}/teammate-accounts/{teammate}/remove`: now, even with access; 200 `{removal, removed}` when done, 202 `{removal, error?}` while pending. Admin only; 409 without teammate accounts. `botctl user teammates <user> [remove <teammate>]`, `botctl user teammate-removals [state]`.
  - Audit, against the owner with `forUser`, `account`, `reason`, `files`, `cleanupId`: `isolation.teammate_removal_queued`, `teammate_removed`, `teammate_removal_failed` (once per reason), `teammate_removal_cancelled`, `teammate_removal_forced`, `teammate_files_purged`, `teammate_files_purge_failed`. `server.started` reports `isolationTeammateFiles`.

### Per-user machines (managed hosting)

For CG-Labs managed hosting: botd can rent one Linode per user and track it. **Off by default**: without `LINODE_TOKEN` the machine endpoints answer 503 "control plane not configured", and nothing else changes. Self-hosted servers don't need it. Design: [ADR 0025](adr/0025-control-plane-linode.md).

- **Turn on**: `LINODE_TOKEN` (or `LINODE_TOKEN_FILE`; a Linode personal access token with Linodes read/write) and `MACHINE_REGIONS` (e.g. `gb-lon,de-fra-2`; the first is the default). botd refuses to start with a token and no regions.
- **Tiers**: `MACHINE_TIERS=starter=g6-standard-1,pro=g6-standard-2,max=g6-standard-4` (the default) maps tier names to Linode plans; the first is the default tier.
- **Other settings**: `MACHINE_IMAGE` (`linode/ubuntu24.04`), `MACHINE_BACKUPS` (`on`), `MACHINE_LABEL_PREFIX` (`superbot`; every label starts with it and every machine is tagged with it; each machine keeps the prefix it was made with), `MACHINE_AUTHORIZED_KEYS` (comma-separated SSH public keys for operators), `MACHINE_RECONCILE_SECONDS` (`60`).
- **What it does**: an admin requests a machine for a user; botd creates it (label `<prefix>-<machine id>`, so a retry never makes a second), then a reconciler marks it running, turns on backups, and finishes deletes. States: `pending`, `provisioning`, `running`, `suspended`, `destroying`, `destroyed`, `error`. Suspend powers it off; Linode still bills a powered-off machine.
- **Audit**: `machine.requested`, `machine.created`, `machine.running`, `machine.backups_enabled`, `machine.suspended`, `machine.resumed`, `machine.resized`, `machine.destroy_requested`, `machine.destroyed`, `machine.retried`, and failures (`machine.create_failed`, `machine.lost`, `machine.destroy_failed`, `machine.backups_failed`, or the action with outcome `failure`). The admin is the actor; the reconciler acts as `system:control_plane` on behalf of the user.
- **Enrollment and lockdown**: with `MACHINE_CONTROL_URL`, machines enroll for mTLS certificates ([ADR 0031](adr/0031-machine-enrollment-mtls.md)). With `MACHINE_FIREWALL=on` they sit behind one Linode Cloud Firewall that only lets the control plane reach the agent port, and enroll on first boot with no manual steps. A machine that misses its deadline (`MACHINE_ENROLL_TIMEOUT_MINUTES`) gets `enrollOverdueAt` and a `machine.enroll_timeout` event. Firewall changes are `machine.firewall_*` ([ADR 0035](adr/0035-machine-firewall-auto-enroll.md)).
- **Harness CLIs and agent upgrades**: with `MACHINE_HARNESSES`, each machine's agent installs those harness CLIs (pinned, checked by hash) and reports them in its heartbeat. Its agent upgrades itself to botd's build when an admin asks (`POST /api/users/{key}/machine/agent/upgrade`), or by itself with `MACHINE_AGENT_UPGRADES=auto`; `PUT|DELETE .../machine/agent/hold` holds it, `GET .../machine/agent` shows where it stands, and `POST .../machine/harnesses` sends the harness plan now. Audited as `machine.harness_*` and `machine.agent_upgrade*` ([ADR 0039](adr/0039-machine-harnesses-and-agent-upgrades.md)).
- **Rebuilding machines from before agent upgrades** ([ADR 0056](adr/0056-rebuilding-machines-enrolled-before-0039.md)): an agent whose heartbeat has no `upgrade` can't replace itself, so botd has the provider rebuild the machine in place (same id, IP and firewall) with today's first-boot user data and a new enrollment token. `POST /api/users/{key}/machine/rebuild[?discardWork=true]` asks (202; 409 if its agent can upgrade itself, it's held, or it may hold the user's files and `discardWork` isn't true); `GET` shows `legacy`, `lacks`, `mayHoldWork` and the `rebuild` (`queued`, `rebuilding`, `retrying`, `done`, `failed`, `cancelled`, with attempts, next try and error); `DELETE` cancels one not yet sent. `GET /api/machines/legacy` lists old machines. The reconciler sends it once the old agent is idle, waits for the machine to enroll again, sends it again after a backoff if it doesn't (at most 5 times), and the heartbeat after it enrolls marks it done and starts the folder copy. A lost provider answer counts as maybe sent: botd waits instead of wiping twice. While underway, routed runs are refused with `machine_rebuilding`. `MACHINE_LEGACY_REBUILDS`: `manual` (default), `auto` (idle machines never assigned and never ran a Bot), `off`. Audited as `machine.rebuild_requested`, `machine.rebuild_sent`, `machine.rebuild_failed`, `machine.rebuild_cancelled` and `machine.rebuilt`.
- **Harness logins and the user's folder** ([ADR 0041](adr/0041-machine-harness-logins-and-folder-copy.md)), each off by default:
  - With `MACHINE_HARNESS_LOGINS=on`, Claude Code and Codex log in on the user's machine with their own login. `POST /api/users/{key}/machine/harness-login {harness}` (or `/api/machine/harness-login` for yourself) streams the login's terminal as JSON lines. `POST .../harness-login/{id}/input {text}` types a line into it, and `DELETE .../harness-login/{id}` stops it. `GET .../harness-logins` shows each harness's state, and `DELETE .../harness-logins/{harness}` logs it out.
  - The credentials stay on the machine. botd stores neither the terminal output nor what is typed.
  - A routed `claude` or `codex` run with no login there and no key in the owner's secrets is refused with `harness_not_logged_in`.
  - With `MACHINE_FOLDER_SYNC=on` (and `MACHINE_FOLDER_SYNC_MAX_MB`, default 2048), assigning a user copies their working folder to `work/` on their machine, and seeds `USER.md` and their Bots' `MEMORY.md` where the machine has none. `POST .../machine/folder-sync` copies it again, and `GET` shows how the last copy went.
  - Each file is checked by SHA-256, the copy resumes where it stopped, files changed on the machine are kept, and nothing there is deleted. Runs wait for the first copy (`folder_copying`).
  - Audited as `machine.harness_login*`, `machine.harness_logged_out` and `machine.folder_sync_*`.
- **Bots' own user on machines** ([ADR 0043](adr/0043-bots-own-os-user-on-machines.md)), off by default: with `MACHINE_BOT_USER=on`, after a heartbeat botd asks each idle agent to run its Bots as the unprivileged `superbot-bots` user. The agent makes it if it must, hands it the Bots' home without following links, and from then on runs harnesses, logins and cleanups as it, and touches files in the home only with its access. Until it's ready, routed runs are refused with `bot_user_pending` (or `bot_user_failed`, or `agent_outdated` for an agent too old to do it). `POST /api/users/{key}/machine/bot-user` asks now; `GET .../machine/agent` shows `agent.botUser`. Audited as `machine.bot_user_requested`, `machine.bot_user_ready` and `machine.bot_user_failed`.
- **Screens on machines** ([ADR 0045](adr/0045-screens-on-machines.md)), off by default: with `MACHINE_SCREENS=on` (needs `MACHINE_BOT_USER=on`), `GET /api/bots/:id/screen` for a Bot routed to its owner's machine starts its screen there (Xvfb, Openbox, D-Bus, voxl as the Bots' user) and returns the usual `/screen/<port>/?token=` link. botd listens on a loopback port in `MACHINE_SCREEN_PORTS` and pipes each connection through the agent's mutual-TLS port (an HTTP upgrade), checking the route again each time. It is never shown from this server or another machine: refusals carry the route's reason, or `machine_screens_off`, `screen_stack_missing`, `screen_ports_full`, `screen_failed`. Runs there get its `DISPLAY`. Narrowing access gives it a new token. `GET /api/users/{key}/machine/screens` lists a user's open screens and `DELETE .../machine/screens/{bot}` closes one (admin). Audited as `machine.screen_started`, `machine.screen_opened`, `machine.screen_rotated`, `machine.screen_refused` and `machine.screen_closed`.
- **Teammates' own user on machines** ([ADR 0048](adr/0048-teammates-own-os-user-on-machines.md)), off by default: with `MACHINE_TEAMMATE_USERS=on` (needs `MACHINE_BOT_USER=on`), a run of a shared Bot for someone other than its owner goes to the owner's machine as that teammate's own user.
  - botd asks the agent with `PUT /v1/teammates/{user}`. The agent makes `superbot-t-<hash>` with a 0700 home under `<state>/teammates`, apart from the Bots' home, and runs the job (`for_user`) there. It refuses paths outside that home.
  - The run's `BOT_TOKEN` is bound to the teammate and refused (`run_over`) once the Bot's latest run is someone else's.
  - Refusals: `agent_outdated` (no `can: teammates`), `teammate_user_failed`, `teammate_no_key` (Claude Code or Codex with no server-wide key, and no way for the teammate to log in there), `teammate_not_logged_in` (the same, but the teammate can log in with their own account).
  - Their own harness logins ([ADR 0062](adr/0062-teammate-harness-logins.md)), with `MACHINE_HARNESS_LOGINS=on` too: a teammate logs Claude Code or Codex in on the owner's machine as their own user, in their own home, with `POST /api/machine/teammate/{owner}/harness-login {harness}` (a stream, as for the owner), `POST .../harness-login/{id}/input`, `DELETE .../harness-login/{id}`, `GET .../harness-logins` and `DELETE .../harness-logins/{harness}`. Only people who can operate one of the owner's Bots get past a 404. Their runs need that login or a server-wide key, never the owner's login. Admins: `GET /api/users/{owner}/machine/teammates/{teammate}/harness-logins`, `DELETE .../harness-logins/{harness}`. Bot views carry `teammateLogins: true` when this applies. The `machine.harness_login*` events carry `forUser` and `teammateUser`.
  - Screens are per person. `GET /api/bots/:id/screen` gives the caller their own (`?for=<user>` for admins). Every display takes an X cookie, and a teammate who loses the Bot loses their screen (`access_lost`).
  - Audited as `machine.teammate_user_created`, with `teammateUser` on `bot.run_routed` and `harness.invoked`, and `forUser` on `machine.screen_*`.
- **Teammates leaving machines** ([ADR 0052](adr/0052-teammate-offboarding-on-machines.md)), whenever machines are on: a teammate who is disabled, deprovisioned by SCIM, or can no longer operate any of the owner's Bots (grant revoked, Bot made private, given away or deleted) loses their user on the owner's machine.
  - botd queues a removal per machine (`teammate_cleanups`) and asks the agent with `POST /v1/teammates/{user}/remove`. The agent stops their jobs, screens and processes, deletes their home, temp files and user, and never touches the machine's own user or other teammates. Heartbeats list `teammates`, so ones missed are found too.
  - Removals run in the background, four at a time. Offline or outdated agents are asked again after each round of heartbeats until done; access coming back cancels one the agent was never asked for, and finishes one it was.
  - Work: `MACHINE_TEAMMATE_FILES=archive` (default) moves it to the owner's `work/from-teammates/`; `delete` holds it, then purges it after `MACHINE_TEAMMATE_FILES_DAYS` (default 7).
  - `GET /api/machines/teammate-removals?state=`, `GET /api/users/{key}/machine/teammates` and `POST .../machine/teammates/{teammate}/remove` (admin). Audited as `machine.teammate_removal_queued`, `machine.teammate_removed`, `machine.teammate_removal_failed`, `machine.teammate_removal_cancelled`, `machine.teammate_removal_forced` and `machine.teammate_files_purged`.
- **Not yet**: tying tiers to billing.

## API

All JSON. Auth: a session cookie (sign-in page and console) or `Authorization: Bearer <session token>` (client, `botctl`), or HTTP Basic with `AUTH_PASSWORD` while break-glass is on. Empty password requires `ALLOW_NO_AUTH=1` on loopback only. Each route needs a role permission (above); 401 without valid credentials, 403 when the role doesn't allow it. Bot routes also need access to that Bot: 404 for a Bot you can't see, 403 when you can see it but not do this.

- `GET /api/state`: user name, installed harnesses, the Bots you can see, global policy, pending approvals on those Bots. Each Bot's `handoff` is the id of its unanswered handoff card, or null; `owner` is `{id, name}`, `visibility` is `private` or `shared`, and `access` is yours: `view`, `operate`, or `manage`.
- `GET /api/events`: SSE stream (`message`, `draft`, `status`, `bot`, `botDeleted`, `approval`, `policy`, `resync`), only about Bots you can see
- `POST /api/bots` `{name, harness?, model?, color?, shape?, visibility?}`: you own it; shared unless `visibility` is `private`. 403 outside your tier's routes or past its `maxBots`. Each Bot has `tier: {name, label, managed}`; on a managed tier `model` and `effort` go to admins only, with `route` and `harnesses` (the owner's tier's)
- `PATCH /api/bots/:id` `{name?, hidden?, harness?, model?, effort?, prompts?}`, `DELETE /api/bots/:id`: owner or admin. `prompts` is the Bot's suggested prompts: up to 6 strings of up to 200 characters (trimmed, blanks and repeats dropped), `[]` for none, or `null` for the client's defaults. Every Bot view has `prompts` (null until set) ([ADR 0054](adr/0054-suggested-prompts.md))
- `GET /api/bots/:id/access` → `{botId, owner, visibility, access, grants?}` (grants for the owner and admins). `PATCH` `{visibility?, owner?}` (owner: admins only)
- `PUT /api/bots/:id/grants/:user` `{level: viewer|operator}`, `DELETE /api/bots/:id/grants/:user`: owner or admin; `:user` is an id or email
- `GET /api/harnesses/:name/models`: models and reasoning efforts the harness offers (Claude Code: aliases; Codex: `codex debug models`; Pi: `pi --list-models`; Hermes Agent: one entry with an empty `id`, meaning any model name, with its efforts). 403 for non-admins on a managed tier; `?tier=<name>` (admins): only that tier's models
- `GET /api/me/tier` → `{name, label, managed, limits: {maxBots, monthlyRuns, monthlyTokens}, usage: {period, runs, bots, tokens, periodStart, periodEnd, periodSource}}`: your plan, no model names. People only ([ADR 0033](adr/0033-tiers-model-routing.md))
- `GET /api/me/usage` → `{user, tier, period: {key, start, end, source}, tokens: {input, output, cacheRead, cacheWrite, total, runs, unreportedRuns, limit}, runs: {used, limit}, byBot: [...], byModel?: [...]}`: your own usage this billing period. People only; `byModel` only for admins or on a tier that lets you pick models. `GET /api/users/{key}/usage`: the same for anyone, admins only ([ADR 0050](adr/0050-billing-period-token-usage.md))
- `GET /api/tiers` → `{default, source, tiers: [{name, label, managed, limits, routes: "any" | [{harness, provider?, model, effort?}]}]}`: admins only
- `GET /api/setup` → `{progress: {step, dismissed, completedAt, completedBy, show}, steps, domain, signIn, tiers, approvals, checklist: [{id, label, done, detail}], done, total}`: the onboarding wizard's report, with commands and `.env` lines for what botd reads at startup; never secret values or models. `PATCH /api/setup` `{step?: domain|signin|tiers|finish, dismissed?, completed?}`; finishing, reopening, hiding, and showing again are audited as `setup.*`. Admins only ([ADR 0034](adr/0034-onboarding-wizard.md))
- `GET|POST /api/bots/:id/messages` `{text, answer?: {messageId, option}}`
- `POST /api/bots/:id/read`, `POST /api/bots/:id/stop`
- `GET|POST /api/bots/:id/routines` `{name, cron, instruction}`
- `PATCH|DELETE /api/routines/:id` `{enabled?, name?, cron?, instruction?}`. Text fields are trimmed and can't be empty; cron must parse. Turning one on (or creating it on) while its Bot's owner or its author is disabled is a 409. Routines carry `paused_reason` (`owner_disabled` | `author_disabled`), `paused_for` and `paused_at` when botd paused them ([ADR 0047](adr/0047-disabled-users-routines.md)); turning one on or off by hand clears them
- `GET /api/bots/:id/screen`: starts the Bot's screen and returns its live view URL. 503 while voxl isn't listening yet, or when all screens are in use
- `POST /api/handoff` `{from, text}`: `botctl handoff`; waits for the user's answer

Sign-in, users, and sessions ([ADR 0012](adr/0012-users-sessions-rbac.md)). Users and sessions are admin only:

- `POST /api/auth/login` `{password | code | sso + verifier, session?: "cookie" | "token", label?}` → `{user, session, token}`. No credentials needed. 429 after 10 failures from one IP in 10 minutes
- Single sign-on ([ADR 0014](adr/0014-oidc-sso-entra.md), [ADR 0016](adr/0016-sso-multi-provider.md), [ADR 0018](adr/0018-sso-github-apple.md), [ADR 0020](adr/0020-saml-bridge.md)), no credentials needed: `GET /api/auth/sso` → `{providers: [{id, label, type: "entra" | "google" | "oidc" | "github" | "apple" | "saml"}]}` in `SSO_PROVIDERS` order; `GET /api/auth/sso/:id/start?session=cookie|token&redirect=&challenge=&state=&label=` redirects to the IdP; `GET /api/auth/sso/:id/callback` is where it comes back
- `GET|POST /api/users/:id/identities` `{provider, subject, tenant?}`, `DELETE /api/users/:id/identities/:identity`: SSO identities linked to a user
- `POST /api/auth/logout`, `GET /api/auth/me`: the caller's user, role, permissions, and session
- `GET|POST /api/users` `{email, name?, role?}`, `GET|PATCH /api/users/:id-or-email` `{name?, email?, role?, status?: active|disabled, tier?: <name> | null}`. The owner can't be demoted or disabled, and admins can't demote or disable themselves (409). Listed and fetched users carry `lastLoginAt`, `lastLogin: {at, authMethod, idpProvider, idp}`, `identities`, and `pendingCodes: {count, expiresAt}` (never the codes) ([ADR 0021](adr/0021-admin-portal.md)), `tier` (theirs, or null for the default) and `plan` (the tier they're on, with this month's use)
- `POST /api/users/:id/login-codes` `{ttlMinutes?, replace?}` → `{code, expiresAt}`, `Cache-Control: no-store`. `replace: true` drops the user's unused codes first
- `GET /api/users/:id-or-email/bots` → `{user, active, bots: [{bot, owner, visibility, access, grant}]}`: the Bots that user can reach now and how ([ADR 0017](adr/0017-bot-acls.md))
- `GET /api/sessions?user=`, `DELETE /api/sessions/:id`, `DELETE /api/users/:id/sessions`
- `GET /api/users/:id-or-email/routines` → `{user, routines: [{id, name, cron, enabled, bot, authorId, pausedReason, pausedFor, pausedAt}]}`: routines that run for that user, and those paused for them. `POST /api/users/:id-or-email/routines/resume` → `{resumed, stillPaused}` turns back on the routines paused for them (409 while they're disabled); one whose owner or author is still disabled stays paused. `POST /api/users/:id-or-email/handover` `{to, resumeRoutines?}` → `{from, to, bots, routines, skipped, resumed}`: gives a disabled user's Bots to `to` and moves their routines (authorship and pauses) where `to` can operate the Bot; 409 if the user is active, 400 if `to` is them, disabled or read-only, 403 over `to`'s Bot limit ([ADR 0047](adr/0047-disabled-users-routines.md))
- `GET /api/users/:id-or-email/isolation` → `{isolation: "off"}`, or `{isolation: "users", account, root, home, workspace, memory, ready, harnesses}`; `POST` makes the account and its folders now (409 when off, 502 when that fails). `POST /api/users/:id-or-email/harness-login` `{harness: claude|codex, args?: [string]}` → `{account, home, command}`: the command `botctl user harness-login` runs ([ADR 0037](adr/0037-per-user-unix-accounts.md))

Sign-ups ([ADR 0022](adr/0022-landing-and-signups.md)). Submitting and the config are public; the rest is admin only:

- `GET /api/signups/config` → `{enabled, turnstileSiteKey, providers, teamSizes, signIns}`
- `POST /api/signups` `{name, email, company, teamSize, useCase, signIn: microsoft|google|github|apple|other, consent: true, website?, turnstileToken?}` → 202 `{ok, sso: [{id, label, type}]}`. 400 `{error, field}` for a bad field, 413 over 16 KiB, 429 with `Retry-After`, 503 when 1000 are pending, 404 when `SIGNUPS=off`
- `GET /api/signups?status=pending|approved|rejected|all&limit=` (newest first), `GET /api/signups/:id`. Each has `existingUser` when a user has that email
- `POST /api/signups/:id/approve` `{role?, ttlMinutes?}` → `{signup, user, code, expiresAt, emailed: false, sso}`. 409 when decided already or the email is a user's
- `POST /api/signups/:id/reject` `{reason?}`. 409 when decided already

SCIM ([ADR 0023](adr/0023-scim.md)). Tokens are admin only:

- `GET /api/scim/tokens` → `{enabled, defaultRole, tokens: [{id, tenant, label, ssoProvider, createdAt, createdBy, lastUsedAt, revokedAt, revokedBy}]}`
- `POST /api/scim/tokens` `{tenant, label?, sso?}` → 201 `{token, scimToken, enabled}`, the token once. 400 for a bad tenant name or SSO provider, 409 when the tenant links another provider
- `DELETE /api/scim/tokens/:id`
- `/scim/v2` (`Authorization: Bearer sbp_…`, `application/scim+json`): `GET /ServiceProviderConfig`, `/ResourceTypes`, `/Schemas`; `GET /Users?filter=userName eq "…"|externalId eq "…"&startIndex=&count=`, `POST /Users`, `GET|PUT|PATCH|DELETE /Users/:id`; `GET /Groups` is always empty, other group requests are 501. Errors use the SCIM error schema

Per-user machines ([ADR 0025](adr/0025-control-plane-linode.md)). 503 when the control plane is off. Admin only, except `GET /api/machine`:

- `GET /api/machine`: the caller's own machine `{id, tier, region, state, providerStatus, ipv4, backups, createdAt, updatedAt}`; 404 if none. Never anyone else's
- `GET /api/machines?state=`: every machine, destroyed ones too, newest first
- `GET /api/users/:id-or-email/machine`: the user's live machine `{id, userId, userEmail, provider, providerId, label, tag, tier, plan, region, state, providerStatus, ipv4, backups, lastError, createSentAt, createdAt, createdBy, updatedAt, destroyedAt}`; 404 if none
- `POST /api/users/:id-or-email/machine` `{tier?, region?}`: 202 on its way. Asking again returns the same machine (200); another tier or region is a 409 (resize instead). After an error, asking again retries, with the saved tier and region unless others are given. 502 `{error, machine}` if Linode refused; 409 for a disabled user
- `POST /api/users/:id-or-email/machine/suspend`, `/resume`, `/resize` `{tier}`: 200 with the machine (Linode is checked first, so a repeat, or a change already made there, calls nothing; resizing to the same tier applies a changed plan), 409 from the wrong state, 502 `{error, machine}` if Linode refused
- `DELETE /api/users/:id-or-email/machine`: 200 once deleted at Linode, 202 while it retries
- `POST /api/machines/reconcile` → `{checked, changed}`: one reconciler pass now
- `GET /api/machines/teammate-removals?state=pending|held|done|cancelled|open|all` → `{files, graceDays, removals, openByMachine}`: leaving teammates' removals ([ADR 0052](adr/0052-teammate-offboarding-on-machines.md)), newest first
- `GET /api/users/:id-or-email/machine/teammates` → `{machineId, canRemove, teammates, removals}`: teammates with a user on it, and whether each still should
- `POST /api/users/:id-or-email/machine/teammates/:teammate/remove`: remove that teammate's user now; 200 when done, 202 `{removal, error?}` while it's pending

Approvals, policy, and audit. Writes, decisions, the approvals list, and the audit log need a person (403 for the Bot token):

- `GET /api/policy`: global policy, class names, global rules. `PUT /api/policy` `{mode?, timeoutMinutes?, classes?: {<class>: allow|ask|deny}}`
- `GET /api/bots/:id/policy`: effective policy, override, rules. `PUT` (same body, merged into the override; `null` for `mode`, `timeoutMinutes`, or a class puts it back to the global value), `DELETE` (drop the override)
- `GET /api/policy/rules?bot=<id>`, `POST /api/policy/rules` `{action: allow|deny, pattern, tool?, botId?, note?}` (pattern up to 8000 characters, tool up to 200 with no spaces, note up to 500), `DELETE /api/policy/rules/:id`
- `GET /api/approvals?status=pending|approved|denied|expired|cancelled|all&bot=<id>&limit=`
- `POST /api/approvals/:id/approve`, `POST /api/approvals/:id/deny` `{remember?: "bot"|"global", scope?: "once"|"run", note?}`. Remember needs an admin. `scope: "run"` approves calls of the same kind for the rest of the run ([ADR 0051](adr/0051-approve-once-per-run.md)): approve only, not with `remember`, 400 when the approval's `runScope` is null, 409 if its run has ended. 409 if already decided. Approvals carry `runId`, `runScope: {covers, exact}` and, once approved, `scope`
- `POST /api/approvals/check` `{from, harness, run?, event}`: the hook's call. `run` is `SUPERBOT_RUN_ID`, set for each run; without it, run approvals don't apply. Waits for a decision. Replies `allow` or `deny`, then the reason, as plain text
- `GET /api/audit?from=&to=&action=&actor=&outcome=&bot=&limit=&before=<id>`: audit events, newest first, `{events, nextBefore}`. `from`/`to`: unix ms, RFC 3339, or `YYYY-MM-DD`. `action`: exact or `prefix.*`, comma-separated. `actor`: `user`, `bot`, or `system`, optionally `:<id>` (or `user:<email>`). Also `method` (comma-separated `password`, `code`, `sso`, `none`, `bot_token`, `scim_token`), `idp` (type), `idpProvider` (id), `subject` (`<issuer>|<sub>`), `session`, `onBehalfOf` (user id or email). Each event has `actorEmail`, `actorRole`, `authMethod`, `idp`, `idpProvider`, `sessionId`, `onBehalfOf`. `limit` 1 to 1000, default 100
- `GET /api/audit/export.csv` (same filters): CSV download, oldest first
- `GET /api/secrets`: `{secrets: [{name, store, writable, shadowedBy, forBots}]}`, names only; `forBots` is false for botd's own secrets (SSO client secrets, `TURNSTILE_SECRET`, `LINODE_TOKEN`). `PUT /api/secrets/:name` `{value}`, `DELETE /api/secrets/:name`. Admin only

## Not built yet

Sign-up emails, self-serve SSO linking, and sign-up retention ([ADR 0022](adr/0022-landing-and-signups.md)). SCIM groups, group-to-role mapping, and bulk ([ADR 0023](adr/0023-scim.md)). Enrollment and mTLS with per-user machines, moving a user's Bots onto theirs, and `botctl machine` commands ([ADR 0025](adr/0025-control-plane-linode.md)). Storage limits, resizing a user's machine when their tier changes, and billing emails ([#31](https://github.com/CG-Labs/superbot/issues/31)). Vault/Key Vault/Secret Manager stores and master-key rotation (the `SecretStore` trait is ready for them), per-Bot resource limits, Slack. Approvals follow-ups are in [approvals-followups.md](approvals-followups.md).

Computer use (each Bot's screen, browser, and live view) is in [computer.md](computer.md).
