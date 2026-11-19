# Backend

One Rust binary, `botd`. It serves the landing page (`/`), the admin console (`/console/`), and the API, stores everything in SQLite, and runs each Bot on a coding-agent CLI. The client is served at `/app/` by Caddy ([deploy/README.md](../deploy/README.md)).

## Pages

- `/` and `/get-started`: the public landing page and the request-access form, from `site/`. Same page for everyone, no trackers or external assets ([ADR 0022](adr/0022-landing-and-signups.md)).
- `/console/`: the built-in admin page (`web/`), for admins only. Members and read-only users go to `/app/`; signed-out visitors go to `/login`. `/console` redirects here ([ADR 0027](adr/0027-expo-primary-hermes-default.md)).
- `/login`: the sign-in page, also for break-glass. Sign-in lands admins on `/console/` and everyone else on `/app/` (`landing` in `GET /api/auth/me`). Web SSO sign-ins land the same way.
- `/app/`: the client, the interface for everyone, when Caddy serves it. It picks up a session the sign-in page left in the browser. Without Caddy's client, botd sends admins to `/console/` and shows everyone else a "web app isn't installed" page.

botd embeds `site/` and `web/`. Set `SITE_DIR` or `WEB_DIR` to serve them from disk while editing.

## How it works

- **Bots** live in SQLite. Each Bot has a harness (`claude`, `codex`, `pi`, or `hermes`), an optional model, and a harness session id.
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

- Install the harness CLIs you want and log them in **as the user that runs `botd`**: `claude` (then `claude login` or `ANTHROPIC_API_KEY`), `codex` (`codex login` or `OPENAI_API_KEY`), `pi` (provider API key, e.g. `OPENROUTER_API_KEY`), `hermes` (provider API key, see [Hermes Agent](#hermes-agent)). Their env vars pass through to the Bots.
- Run `botd` as a normal user, not root. Claude Code refuses to skip permissions as root.
- Run it under systemd with `Restart=always`. It shuts down cleanly on SIGTERM.
- Put HTTPS in front (e.g. Caddy) and set `AUTH_PASSWORD` and `HOST=127.0.0.1` behind the proxy (recommended). The browser logs in with any username and that password.
- Set `ALLOWED_HOSTS` to the domain your proxy forwards (blocks DNS rebinding). See the one-command installer in [deploy/README.md](../deploy/README.md).
- Proxies must not buffer `/api/events` (it's an SSE stream).
- Set `TZ` to the user's time zone. Routines use it.
- Back up `DATA_DIR`. `WORKSPACE_DIR` is the Bots' scratch and files.
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
  - `git_push`: any `git push`.
- **Shell commands** are parsed like `sh`/`bash` reads them (`server/src/shell.rs`): every command in pipes, lists, groups, `$(…)`, backticks, `<(…)`, `${…}`, and expanding here-documents is checked. `$'…'` escapes are decoded as bash does. A command whose name is only known at run time (`$CMD`, `gi?`, `{git,x}`, `eval "$X"`, `bash -c "$S"`) counts as `shell_destructive`.
- **Folders**: a `cd` may fail or run in a subshell, so a relative path must be inside the workspace from every folder the command could be in. When a folder can't be known (`cd -`, `cd "$D"`, `popd`, `source`), relative deletes count as outside.
- **Shell tools** may send `command` or `cmd`, as text or argv. A shell call with neither, or two that differ, is denied.
- **Unreadable commands are denied**, whatever the classes or rules say: unclosed quotes or substitutions, syntax the parser doesn't know, over 1 MiB, nesting over 16 levels, or over 10,000 commands. The Bot is told why, so it can simplify the command.
- **Rules**: `deny` rules (the deny list) always block. `allow` rules skip asking, unless the class is `deny`. Patterns are globs (`*`, `?`) over the command, path, URL, or tool arguments. "Remember" on an approval saves an exact-match rule for that Bot.
- **Scope**: one global policy, plus optional per-Bot overrides.
- **Timeout**: an unanswered approval is denied after `timeoutMinutes` (default 10; at most 4 for Hermes Agent Bots). Stopping the Bot, the run ending, or a server restart also closes it.
- **Turning approvals on** stops any task that started in `bypass` (it has no hook), with a note to send it again.
- **Remember** saves an exact rule. Calls too long to store whole (over 4,000 characters) can be approved or denied, but not remembered.
- **Audit**: every request, decision, timeout, and policy or rule change is in the [audit log](#audit-log).
- **Who decides**: a signed-in admin or member (see [users and roles](#users-sessions-and-roles)). Bots' token and read-only users get 403 on decisions; only admins change policy and rules.

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
2. **Saved secrets**, encrypted in SQLite: `botctl secret set OPENAI_API_KEY < key.txt` (value on stdin), `botctl secrets`, `botctl secret rm NAME`. Bots get them as environment variables from their next run. The exception is SSO client secrets (`SSO_<ID>_CLIENT_SECRET`): saved the same way, but only botd uses them, and every `SSO_*` variable is kept out of Bots' environments.

Saved secrets and every approval's tool input are sealed with XChaCha20-Poly1305 under a master key: `SUPERBOT_MASTER_KEY` (64 hex chars), or the 0600 file in `SUPERBOT_MASTER_KEY_FILE` (default `~/.config/superbot/master.key`, created on first start). The key never lives in `DATA_DIR`, so backups don't carry it. botd won't start with a wrong key, or without the key once something is sealed.

Values never come back out: the API lists names only. Known values (saved and env secrets, `AUTH_PASSWORD`, the Bots' token, screen tokens, the key) and any session token, sign-in code, SSO handoff code, or SCIM token botd issued (`sbs_…`, `sbc_…`, `sbh_…`, `sbp_…`) are replaced by `[redacted]` in saved chats, approvals, the audit log, and live events. Upgrading seals old approval inputs and scrubs known values from saved chats on first start. Bots run as the same OS user, so this protects copies of the database, not the running server. See [ADR 0010](adr/0010-secrets.md).

## Audit log

Admin actions are recorded in `audit_events` in `app.sqlite`: who (person, Bot, or system part), what (`bot.created`, `routine.disabled`, `approval.denied`, ...), the target, the outcome, the source IP and user agent, and a few scrubbed details. Logins and failed logins, Bot and routine changes, policy, rules, approvals, handoffs, Bot-token calls, Bot runs (`bot.run_finished`), and harness starts (`harness.invoked`) are all covered; the full list is in [ADR 0009](adr/0009-audit-events.md).

- **Who, exactly**: a person's id, name, email, and role when they acted; how they signed in (`password` = break-glass `AUTH_PASSWORD`, `code`, `sso`, `none`, `bot_token`, `scim_token`); for SSO, the IdP type (`entra`, `google`, `oidc`, `github`, `apple`, `saml`), its configured provider id, and their IdP subject; and the session id. A Bot (or a routine) records whose authority it used: its owner, as `onBehalfOf`. A Bot run is attributed to whoever queued it: the person who sent the chat, the Bot that asked, or the scheduler. Rows from before this was added leave these empty. Design: [ADR 0019](adr/0019-audit-actors.md).

- **Append-only**: no API edits or deletes rows, and SQLite triggers refuse `UPDATE` and any `DELETE` inside the retention window.
- **No secrets**: passwords, tokens, message bodies, and routine instructions are never recorded. Details are scrubbed and clipped anyway.
- **Retention**: `AUDIT_RETENTION_DAYS` (unset or `0` = keep forever, the default). Pruning runs every 6 hours and is itself logged. Backups copy the table with the rest of `app.sqlite`.
- **Source IP**: the peer, or the last `X-Forwarded-For` entry when the proxy is on loopback. Set `TRUST_FORWARDED_FOR=1` only when `botd` is reachable solely through your proxy (Compose sets it).
- **Read it**: the web app's Audit log (filters and Export CSV), or:

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
- **Sessions**: the web app gets an HttpOnly cookie, the client and `botctl` a bearer token. They end after `SESSION_IDLE_TIMEOUT` without use (default `7d`) or `SESSION_MAX_AGE` after sign-in (default `30d`), on logout, or when an admin revokes them or disables the user. Only hashes are stored.

```sh
export SUPERBOT_PASSWORD=<your AUTH_PASSWORD>      # or: botctl login <code>, then export SUPERBOT_TOKEN=...
botctl user add alex@example.com "Alex" --role member
botctl user code alex@example.com                   # one-time code for Alex
botctl users | botctl sessions alex@example.com
botctl user role alex@example.com readonly | botctl user disable alex@example.com
botctl session revoke <id> | botctl session revoke-all alex@example.com
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

## API

All JSON. Auth: a session cookie (web app) or `Authorization: Bearer <session token>` (client, `botctl`), or HTTP Basic with `AUTH_PASSWORD` while break-glass is on. Empty password requires `ALLOW_NO_AUTH=1` on loopback only. Each route needs a role permission (above); 401 without valid credentials, 403 when the role doesn't allow it. Bot routes also need access to that Bot: 404 for a Bot you can't see, 403 when you can see it but not do this.

- `GET /api/state`: user name, installed harnesses, the Bots you can see, global policy, pending approvals on those Bots. Each Bot's `handoff` is the id of its unanswered handoff card, or null; `owner` is `{id, name}`, `visibility` is `private` or `shared`, and `access` is yours: `view`, `operate`, or `manage`.
- `GET /api/events`: SSE stream (`message`, `draft`, `status`, `bot`, `botDeleted`, `approval`, `policy`, `resync`), only about Bots you can see
- `POST /api/bots` `{name, harness?, model?, color?, shape?, visibility?}`: you own it; shared unless `visibility` is `private`
- `PATCH /api/bots/:id` `{name?, hidden?, harness?, model?, effort?}`, `DELETE /api/bots/:id`: owner or admin
- `GET /api/bots/:id/access` → `{botId, owner, visibility, access, grants?}` (grants for the owner and admins). `PATCH` `{visibility?, owner?}` (owner: admins only)
- `PUT /api/bots/:id/grants/:user` `{level: viewer|operator}`, `DELETE /api/bots/:id/grants/:user`: owner or admin; `:user` is an id or email
- `GET /api/harnesses/:name/models`: models and reasoning efforts the harness offers (Claude Code: aliases; Codex: `codex debug models`; Pi: `pi --list-models`; Hermes Agent: one entry with an empty `id`, meaning any model name, with its efforts)
- `GET|POST /api/bots/:id/messages` `{text, answer?: {messageId, option}}`
- `POST /api/bots/:id/read`, `POST /api/bots/:id/stop`
- `GET|POST /api/bots/:id/routines` `{name, cron, instruction}`
- `PATCH|DELETE /api/routines/:id` `{enabled?, name?, cron?, instruction?}`. Text fields are trimmed and can't be empty; cron must parse.
- `GET /api/bots/:id/screen`: starts the Bot's screen and returns its live view URL. 503 while voxl isn't listening yet, or when all screens are in use
- `POST /api/handoff` `{from, text}`: `botctl handoff`; waits for the user's answer

Sign-in, users, and sessions ([ADR 0012](adr/0012-users-sessions-rbac.md)). Users and sessions are admin only:

- `POST /api/auth/login` `{password | code | sso + verifier, session?: "cookie" | "token", label?}` → `{user, session, token}`. No credentials needed. 429 after 10 failures from one IP in 10 minutes
- Single sign-on ([ADR 0014](adr/0014-oidc-sso-entra.md), [ADR 0016](adr/0016-sso-multi-provider.md), [ADR 0018](adr/0018-sso-github-apple.md), [ADR 0020](adr/0020-saml-bridge.md)), no credentials needed: `GET /api/auth/sso` → `{providers: [{id, label, type: "entra" | "google" | "oidc" | "github" | "apple" | "saml"}]}` in `SSO_PROVIDERS` order; `GET /api/auth/sso/:id/start?session=cookie|token&redirect=&challenge=&state=&label=` redirects to the IdP; `GET /api/auth/sso/:id/callback` is where it comes back
- `GET|POST /api/users/:id/identities` `{provider, subject, tenant?}`, `DELETE /api/users/:id/identities/:identity`: SSO identities linked to a user
- `POST /api/auth/logout`, `GET /api/auth/me`: the caller's user, role, permissions, and session
- `GET|POST /api/users` `{email, name?, role?}`, `GET|PATCH /api/users/:id-or-email` `{name?, email?, role?, status?: active|disabled}`. The owner can't be demoted or disabled, and admins can't demote or disable themselves (409). Listed and fetched users carry `lastLoginAt`, `lastLogin: {at, authMethod, idpProvider, idp}`, `identities`, and `pendingCodes: {count, expiresAt}` (never the codes) ([ADR 0021](adr/0021-admin-portal.md))
- `POST /api/users/:id/login-codes` `{ttlMinutes?, replace?}` → `{code, expiresAt}`, `Cache-Control: no-store`. `replace: true` drops the user's unused codes first
- `GET /api/users/:id-or-email/bots` → `{user, active, bots: [{bot, owner, visibility, access, grant}]}`: the Bots that user can reach now and how ([ADR 0017](adr/0017-bot-acls.md))
- `GET /api/sessions?user=`, `DELETE /api/sessions/:id`, `DELETE /api/users/:id/sessions`

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

Approvals, policy, and audit. Writes, decisions, the approvals list, and the audit log need a person (403 for the Bot token):

- `GET /api/policy`: global policy, class names, global rules. `PUT /api/policy` `{mode?, timeoutMinutes?, classes?: {<class>: allow|ask|deny}}`
- `GET /api/bots/:id/policy`: effective policy, override, rules. `PUT` (same body, merged into the override), `DELETE` (drop the override)
- `GET /api/policy/rules?bot=<id>`, `POST /api/policy/rules` `{action: allow|deny, pattern, tool?, botId?, note?}`, `DELETE /api/policy/rules/:id`
- `GET /api/approvals?status=pending|approved|denied|expired|cancelled|all&bot=<id>&limit=`
- `POST /api/approvals/:id/approve`, `POST /api/approvals/:id/deny` `{remember?: "bot"|"global", note?}`. Remember needs an admin. 409 if already decided
- `POST /api/approvals/check` `{from, harness, event}`: the hook's call. Waits for a decision. Replies `allow` or `deny`, then the reason, as plain text
- `GET /api/audit?from=&to=&action=&actor=&outcome=&bot=&limit=&before=<id>`: audit events, newest first, `{events, nextBefore}`. `from`/`to`: unix ms, RFC 3339, or `YYYY-MM-DD`. `action`: exact or `prefix.*`, comma-separated. `actor`: `user`, `bot`, or `system`, optionally `:<id>` (or `user:<email>`). Also `method` (comma-separated `password`, `code`, `sso`, `none`, `bot_token`, `scim_token`), `idp` (type), `idpProvider` (id), `subject` (`<issuer>|<sub>`), `session`, `onBehalfOf` (user id or email). Each event has `actorEmail`, `actorRole`, `authMethod`, `idp`, `idpProvider`, `sessionId`, `onBehalfOf`. `limit` 1 to 1000, default 100
- `GET /api/audit/export.csv` (same filters): CSV download, oldest first
- `GET /api/secrets`: `{secrets: [{name, store, writable, shadowedBy, forBots}]}`, names only; `forBots` is false for botd's own SSO client secrets. `PUT /api/secrets/:name` `{value}`, `DELETE /api/secrets/:name`. Admin only

## Not built yet

Sign-up emails, self-serve SSO linking, and sign-up retention ([ADR 0022](adr/0022-landing-and-signups.md)). SCIM groups, group-to-role mapping, and bulk ([ADR 0023](adr/0023-scim.md)). Vault/Key Vault/Secret Manager stores and master-key rotation (the `SecretStore` trait is ready for them), per-Bot resource limits, Slack. Approvals follow-ups are in [approvals-followups.md](approvals-followups.md).

Computer use (each Bot's screen, browser, and live view) is in [computer.md](computer.md).
