# Backend

One Rust binary, `botd`. It serves the web app, stores everything in SQLite, and runs each Bot on a coding-agent CLI.

## How it works

- **Bots** live in SQLite. Each Bot has a harness (`claude`, `codex`, or `pi`), an optional model, and a harness session id.
- **A message** is queued. Each Bot runs one task at a time, in order. Different Bots run in parallel.
- **A run** spawns the harness CLI in the shared workspace, streams its JSON events, and saves each text block as a chat bubble.
- **Live updates** go to the browser over one Server-Sent Events stream: new messages, streaming text, and what the Bot is doing ("Running: ls").
- **Memory** is plain files, re-sent in the system prompt every run. The Bot edits them itself:
  - `DATA_DIR/bots/<id>/MEMORY.md`: one Bot's job, rules, and work log.
  - `DATA_DIR/USER.md`: facts about the user, shared by all Bots.
- **The computer** is `WORKSPACE_DIR`, shared by all Bots, like Grok Bot's shared VM.
- **Routines** are cron schedules. Bots create them with the `botctl` CLI, which works from any harness's shell.
- **Bot to Bot**: a Bot runs `botctl ask "<Bot>" "<message>"`. The other Bot answers in its own chat and the reply prints back. If it takes over 9 minutes, the reply arrives later as a new message.
- **Model and effort** are saved per Bot. The web app shows a faint picker above the input. Unset means the harness default.
- **Choice cards**: a reply ending in a ` ```question ` JSON block becomes a multiple-choice card.
- **Approvals**: in `ask` mode, risky tool calls wait for a person. See [Approvals](#approvals).
- **Restarts**: queued messages run after a restart. A task that was running is reported as interrupted, not re-run, so it can't repeat an action like sending an email.

## Harness adapters

Each adapter is one file in `server/src/adapters/`. It builds the command line and maps the CLI's JSON lines to five events: session, text delta, text, tool, error.

- **Claude Code**: `claude -p --output-format stream-json --resume <id>`. System prompt via `--append-system-prompt`, fresh every run.
- **Codex**: `codex exec --json`, then `codex exec resume <id>`. Instructions via `-c developer_instructions=...`. Codex only reads them when a session starts, so later memory edits reach it through the memory file.
- **Pi**: `pi --mode json --session-dir <bot dir> --session-id <id>`. System prompt via `--append-system-prompt`.

All three run with the harness's own permission prompts off (`--dangerously-skip-permissions` and equivalents): nobody is at a terminal to answer them. In `ask` mode, each adapter adds a hook that runs `botctl hook <harness>` before every tool call instead:

- **Claude Code**: a `PreToolUse` command hook via `--settings`.
- **Codex**: the same hook via `-c hooks.PreToolUse=...` and `features.hooks=true`.
- **Pi**: a small generated extension (`--extension`) that runs the same command on `tool_call`.

The server is still the computer, so treat it that way. Details and trade-offs: [ADR 0007](adr/0007-approvals.md).

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

- Install the harness CLIs you want and log them in **as the user that runs `botd`**: `claude` (then `claude login` or `ANTHROPIC_API_KEY`), `codex` (`codex login` or `OPENAI_API_KEY`), `pi` (provider API key, e.g. `OPENROUTER_API_KEY`). Their env vars pass through to the Bots.
- Run `botd` as a normal user, not root. Claude Code refuses to skip permissions as root.
- Run it under systemd with `Restart=always`. It shuts down cleanly on SIGTERM.
- Put HTTPS in front (e.g. Caddy) and set `AUTH_PASSWORD` and `HOST=127.0.0.1` behind the proxy (recommended). The browser logs in with any username and that password.
- Set `ALLOWED_HOSTS` to the domain your proxy forwards (blocks DNS rebinding). See the one-command installer in [deploy/README.md](../deploy/README.md).
- Proxies must not buffer `/api/events` (it's an SSE stream).
- Set `TZ` to the user's time zone. Routines use it.
- Back up `DATA_DIR`. `WORKSPACE_DIR` is the Bots' scratch and files.
- `GET /healthz` returns `{"ok":true}` without auth.

## Approvals

The policy decides what each tool call does: run, ask a person, or be blocked.

- **Modes**: `ask` pauses risky calls. `bypass` runs everything, as before (dev only).
- **Risky classes**, each set to `allow`, `ask` (default), or `deny`:
  - `shell_destructive`: `rm -rf` on the workspace or system paths, `git reset --hard`, `dd`, `mkfs`, `DROP TABLE`, `sudo`, ...
  - `file_delete`: deleting files outside the workspace.
  - `outbound_message`: mail CLIs, `gh pr create`/comments, chat webhooks, messaging MCP tools.
  - `network_install`: `apt`, `brew`, `npm i`, `pip install`, `cargo install`, `curl ... | sh`.
  - `git_push`: any `git push`.
- **Shell commands** are parsed like `sh`/`bash` reads them (`server/src/shell.rs`): every command in pipes, lists, groups, `$(…)`, backticks, `<(…)`, `${…}`, and expanding here-documents is checked. `$'…'` escapes are decoded as bash does. A command whose name is only known at run time (`$CMD`, `gi?`, `{git,x}`, `eval "$X"`, `bash -c "$S"`) counts as `shell_destructive`.
- **Folders**: a `cd` may fail or run in a subshell, so a relative path must be inside the workspace from every folder the command could be in. When a folder can't be known (`cd -`, `cd "$D"`, `popd`, `source`), relative deletes count as outside.
- **Shell tools** may send `command` or `cmd`, as text or argv. A shell call with neither, or two that differ, is denied.
- **Unreadable commands are denied**, whatever the classes or rules say: unclosed quotes or substitutions, syntax the parser doesn't know, over 1 MiB, nesting over 16 levels, or over 10,000 commands. The Bot is told why, so it can simplify the command.
- **Rules**: `deny` rules (the deny list) always block. `allow` rules skip asking, unless the class is `deny`. Patterns are globs (`*`, `?`) over the command, path, URL, or tool arguments. "Remember" on an approval saves an exact-match rule for that Bot.
- **Scope**: one global policy, plus optional per-Bot overrides.
- **Timeout**: an unanswered approval is denied after `timeoutMinutes` (default 10). Stopping the Bot, the run ending, or a server restart also closes it.
- **Turning approvals on** stops any task that started in `bypass` (it has no hook), with a note to send it again.
- **Remember** saves an exact rule. Calls too long to store whole (over 4,000 characters) can be approved or denied, but not remembered.
- **Audit**: every request, decision, timeout, and policy or rule change is in an append-only log (`GET /api/audit`).
- **Who decides**: only a person logged in with `AUTH_PASSWORD`. Bots' token gets 403 on decisions and policy changes.

Fresh installs start in `ask`. Installs from before approvals keep `bypass` until you opt in:

```sh
SUPERBOT_PASSWORD=<your AUTH_PASSWORD> botctl policy set global mode=ask
```

Or use the switch at the bottom of the web app's Approvals window. More operator commands: `botctl admin`. botctl only sends the password to a server on the same machine (loopback), since it speaks plain http; from elsewhere, use an SSH tunnel.

```sh
botctl policy set global timeout=15 git_push=deny   # never push, ask longer
botctl policy set <bot-id> mode=bypass              # one dev Bot runs freely
botctl rule add deny "rm -rf /srv/*"                # deny list
botctl rule add allow "npm install*" --bot <bot-id> # this Bot may install npm packages
botctl approvals | botctl approve <id> [--remember] | botctl deny <id>
```

Limits: the parser sees commands, not what scripts or programs do inside, so this catches mistakes and prompt injection, not a determined attacker. Bots run as the same OS user as `botd`. See [ADR 0007](adr/0007-approvals.md).

## Secrets

API keys and tokens for Bots come from two places, first match wins:

1. **Environment**: `NAME=value` in `.env`, or `NAME_FILE=/path` (Docker/systemd secrets). Same for `AUTH_PASSWORD` (`AUTH_PASSWORD_FILE`).
2. **Saved secrets**, encrypted in SQLite: `botctl secret set OPENAI_API_KEY < key.txt` (value on stdin), `botctl secrets`, `botctl secret rm NAME`. Bots get them as environment variables from their next run.

Saved secrets and every approval's tool input are sealed with XChaCha20-Poly1305 under a master key: `SUPERBOT_MASTER_KEY` (64 hex chars), or the 0600 file in `SUPERBOT_MASTER_KEY_FILE` (default `~/.config/superbot/master.key`, created on first start). The key never lives in `DATA_DIR`, so backups don't carry it. botd won't start with a wrong key, or without the key once something is sealed.

Values never come back out: the API lists names only. Known values (saved and env secrets, `AUTH_PASSWORD`, the Bots' token, screen tokens, the key) are replaced by `[redacted]` in saved chats, approvals, the audit log, and live events. Upgrading seals old approval inputs and scrubs known values from saved chats on first start. Bots run as the same OS user, so this protects copies of the database, not the running server. See [ADR 0010](adr/0010-secrets.md).

## API

All JSON. Browser auth: HTTP Basic with `AUTH_PASSWORD`. Empty password requires `ALLOW_NO_AUTH=1` on loopback only.

- `GET /api/state`: user name, installed harnesses, all Bots, global policy, pending approvals. Each Bot's `handoff` is the id of its unanswered handoff card, or null.
- `GET /api/events`: SSE stream (`message`, `draft`, `status`, `bot`, `botDeleted`, `approval`, `policy`, `resync`)
- `POST /api/bots` `{name, harness?, model?, color?, shape?}`
- `PATCH /api/bots/:id` `{name?, hidden?, harness?, model?, effort?}`, `DELETE /api/bots/:id`
- `GET /api/harnesses/:name/models`: models and reasoning efforts the harness offers (Claude Code: aliases; Codex: `codex debug models`; Pi: `pi --list-models`)
- `GET|POST /api/bots/:id/messages` `{text, answer?: {messageId, option}}`
- `POST /api/bots/:id/read`, `POST /api/bots/:id/stop`
- `GET|POST /api/bots/:id/routines` `{name, cron, instruction}`
- `PATCH|DELETE /api/routines/:id` `{enabled?, name?, cron?, instruction?}`. Text fields are trimmed and can't be empty; cron must parse.
- `GET /api/bots/:id/screen`: starts the Bot's screen and returns its live view URL. 503 while voxl isn't listening yet, or when all screens are in use
- `POST /api/handoff` `{from, text}`: `botctl handoff`; waits for the user's answer

Approvals and policy. Writes, decisions, the approvals list, and the audit log need a person (403 for the Bot token):

- `GET /api/policy`: global policy, class names, global rules. `PUT /api/policy` `{mode?, timeoutMinutes?, classes?: {<class>: allow|ask|deny}}`
- `GET /api/bots/:id/policy`: effective policy, override, rules. `PUT` (same body, merged into the override), `DELETE` (drop the override)
- `GET /api/policy/rules?bot=<id>`, `POST /api/policy/rules` `{action: allow|deny, pattern, tool?, botId?, note?}`, `DELETE /api/policy/rules/:id`
- `GET /api/approvals?status=pending|approved|denied|expired|cancelled|all&bot=<id>&limit=`
- `POST /api/approvals/:id/approve`, `POST /api/approvals/:id/deny` `{remember?: "bot"|"global", note?}`. 409 if already decided
- `POST /api/approvals/check` `{from, harness, event}`: the hook's call. Waits for a decision. Replies `allow` or `deny`, then the reason, as plain text
- `GET /api/audit?limit=&before=<id>`: audit events, newest first
- `GET /api/secrets`: `{secrets: [{name, store, writable, shadowedBy}]}`, names only. `PUT /api/secrets/:name` `{value}`, `DELETE /api/secrets/:name`. Person only

## Not built yet

Vault/Key Vault/Secret Manager stores and master-key rotation (the `SecretStore` trait is ready for them), per-Bot resource limits, Slack. Approvals follow-ups are in [approvals-followups.md](approvals-followups.md).

Computer use (each Bot's screen, browser, and live view) is in [computer.md](computer.md).
