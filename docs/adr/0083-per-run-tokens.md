# 0083: Per-run tokens for every run, owners' own included

## Status

Accepted (21 Nov 2026). Part of [#30](https://github.com/CG-Labs/superbot/issues/30) (M3): the "per-run tokens for owners' runs" follow-up the roadmap listed. It changes how [ADR 0029](0029-per-user-isolation.md) issues and checks Bot tokens. It replaces the teammate-bound tokens of [ADR 0048](0048-teammates-own-os-user-on-machines.md) and [ADR 0064](0064-teammate-accounts-on-one-server.md) with the same per-run token. It is the per-run token [ADR 0046](0046-shared-bots-under-isolation.md) deferred.

0080 is the highest number on `main`. Open PR [#140](https://github.com/CG-Labs/superbot/pull/140) uses 0081, and another agent may take 0082, so this is 0083. Renumber it if a collision appears at merge.

## Context

What the code did before this change:

- **Owners' runs.** Every run of a Bot for its owner carried `sbb_<bot>.<owner>.<HMAC>`, signed with a key botd makes at each start. That token was the same for every run of the Bot until botd restarted. Anything a run left behind could keep acting as the Bot, with its owner's access, long after the run ended. This included a background process, a file in the workspace, a shell history, or a program on the Bot's screen. On machines, where the user's own processes live, it could do so through the agent's relay.
- **Teammates' runs.** A teammate's run in their own OS user (ADR 0048) or account (ADR 0064) carried `sbb_<bot>.<owner>.<teammate>.<HMAC>`. botd accepted it while the Bot's latest run was still that teammate's. It stopped working only once someone else ran the Bot, not when the run ended.
- **What was already right.** A token named one Bot and no other (AUTH-07). It could do no more than its owner's role. It died when the Bot was deleted or changed hands, and on restart. Runs never got a person's session, `SUPERBOT_TOKEN`, `AUTH_PASSWORD` or the master key (`adapters::SECRET_ENV`). Routines, chat and API messages all start runs through the same runner path.

So the gap was lifetime, not reach. An owner's token was long-lived, and a teammate's token lived for "until the next run".

## Decision

### Every run gets a token of its own

Each attempt of a run gets a new `BOT_TOKEN` as it starts: `sbb_<bot id>.<jti>.<HMAC-SHA256>`. `jti` is 16 random bytes in hex. The MAC is over the Bot and `jti`, with botd's per-start key. The token carries nothing else. What it may do is held by botd in `isolation::RunTokens`, an in-memory table keyed by `jti`:

| Field | Meaning |
|-------|---------|
| `bot`, `owner` | The Bot, and its owner when the run started |
| `run` | The run's id (`SUPERBOT_RUN_ID`, `runId` in the audit log) |
| `forUser` | For a teammate's run in their own OS user or account, the teammate. Their access caps the token, as before |
| `issuedAt`, `expiresAt` | Unix ms. The lifetime is the run timeout plus 60 seconds |

This is the same for chat, routines, `ask`/`handoff` replies and API messages, because they all run through `App::run_one`. It is also the same for every harness (Claude Code, Codex, Pi, Hermes Agent), because the token is made before the adapter starts and goes in the run's environment. The adapter never sees how it was made.

### It ends with the run

- **Revoked when the attempt ends.** This covers every way it can end: done, error, stopped, timeout, the hook canary, a lost session that is retried, or a panic. A guard (`LiveToken`) revokes the token when it drops. A retried attempt gets a new token.
- **Never past its expiry.** An entry past `expiresAt` is refused and dropped, even if botd never saw its run end.
- **Gone on restart.** The table and the key are in memory, so nothing outlives the process. This was already true.
- **Owner checks stay.** A token for a Bot since deleted (`bot_gone`) or that changed hands (`bot_moved`) is refused. So is any request its owner's role or state wouldn't allow (`owner_role`, a disabled owner). Handing a Bot over still stops its run, which revokes the token.
- **Open event streams close.** A Bot's `/api/events` stream checks every few seconds that its token is still live, and closes once it isn't.
- **Machines.** A routed run's token goes to the machine in the job's environment, as before. The agent's relay (`/v1/machines/{id}/api/...`) now checks the token against the same table and its owner against the machine's user. So what a run leaves on the owner's machine can't reach botd once the run is over.

### What a refusal says

`auth.login_failed` with `authMethod: bot_token` gives the reason:

| Reason | Meaning |
|--------|---------|
| `bad_token` | Forged, mangled, an old-format token, or signed by an earlier start |
| `run_over` | Revoked because its run ended, or never issued by this start. ADR 0048's reason, now for every run |
| `token_expired` | Past its expiry |
| `bot_gone` | The Bot was deleted (unchanged) |
| `bot_moved` | The Bot changed hands (unchanged) |

As before, these are throttled per client per window. Through the relay, a token that isn't live is `access.denied` with `no_bot_token`.

### Audit

Two new events follow the existing run events' conventions. They use the run's actor (`by`), the message as target, the Bot, `runId` and `messageId`:

- `bot.token_issued`: `{jti, runId, attempt, owner, forUser?, expiresAt, trigger, messageId, host, machine}`.
- `bot.token_revoked`: `{jti, runId, owner, forUser, reason: "run_ended", livedMs}`.

The detail is named `jti` (as in JWTs) and not `tokenId`, because the audit log redacts any field whose name contains "token". The secret itself is never logged. It is registered with the redactor, as before.

### What a run sees

Only its own `BOT_TOKEN`, `BOT_ID`, `BOT_API`, `SUPERBOT_RUN_ID`, its owner's and the server's harness keys, and what it was already given. It gets no person's session, no operator token, no password, no master or license key, no Stripe or SSO secrets, and not botd's token key. `run_space` no longer puts any token in the base environment. The token is added only at attempt start.

## Alternatives considered

- **Keep the signed per-Bot token and add a revocation list.** This is the same table, plus a token that means something without it. A stateless token is only worth having if it doesn't need the table, and ending a token with its run needs state.
- **A signed expiry in the token, with no table.** A run that ends early would leave a token live for the rest of its hour. Revocation at run end is the point of this change.
- **Bind every token to the run's asker, and drop the saved asker (ADR 0046).** The table makes this easy later. A token is live only during its run, and while that run is live, the saved asker is the run's. So the cap is already exact. Changing it now would widen this slice.
- **Hand runs a short-lived session of the owner's.** That is an owner-level credential inside the run, which is what this change removes.

## Tests

- **Unit tests, `isolation.rs`:** a token names one run of one Bot. Each run's token differs. Revoking or expiring one leaves the others alone. Another start's key is refused, and so is every forgery tried: another Bot's id or MAC, a mangled MAC, the old three-part form, another prefix.
- **HTTP tests, `run_tokens_http_tests.rs`, with real runs on the real router:**
  - An owner's run, started from her own session, gets a token that works only while the run is live. It is then refused (`run_over`), its open event stream closes, and both events are audited with matching `jti` and `runId`. The next run's token is new, and the old one stays dead.
  - The run's environment holds none of the owner's session, botd's key, a session token, or any `SECRET_ENV` name.
  - A live token can't act as another Bot, the owner's own or another user's. This holds through `X-SuperBot-Bot`, `from` in `ask` and approval checks, or its MAC under another Bot's id. It can't reach another user's Bot, admin routes or a person's own secrets. It can't write once its owner is made read-only (`owner_role`). Past its expiry it is refused (`token_expired`).
  - Claude Code, Codex, Pi and Hermes Agent each get a token that ends with their run.
- **Routing on:** `shared_bots_http_tests.rs` (a stand-in machine) shows each routed run's token is its own. A teammate's runs are bound to her. Neither hers nor the owner's works once their run is over. `machines_mtls_tests.rs` (the real agent over mutual TLS) shows the relay refuses a run's token once the run is over.
- **`ISOLATION=users`, as root in CI (`accounts_os_tests.rs`):** runs as a user's own account (Claude Code, Pi, Hermes) and as a teammate's account carry their own Bot's token, and none is live after the run.

## Consequences

- **The gap is closed.** What a run leaves behind, on this server or the user's machine, can't act as the Bot once the run ends. This holds whoever the run was for.
- **No change for harnesses or `botctl`.** They read `BOT_TOKEN` as before.
- **Something outside a run can't call botd as a Bot.** That was never supported, but a long-lived process a Bot started (a watcher calling `botctl`, say) used to keep working. It now gets 401 once its run ends.
- **Each attempt adds two audit events.**
- **Not done here.** The cap on a shared Bot still reads the saved asker (see Alternatives). Team accounts and machines remain on #30.
