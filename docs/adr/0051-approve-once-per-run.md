# 0051: Approve for the rest of a run

## Status

Accepted (20 Nov 2026). Approvals follow-up 8 ([list](../approvals-followups.md), tracking issue [#13](https://github.com/CG-Labs/superbot/issues/13), M1). It builds on [ADR 0007](0007-approvals.md) (approvals and the policy engine), [ADR 0009](0009-audit-events.md) (audit events), [ADR 0012](0012-users-sessions-rbac.md) (roles), [ADR 0017](0017-bot-acls.md) (Bot access), [ADR 0029](0029-per-user-isolation.md) (per-Bot tokens) and [ADR 0032](0032-console-admin-only.md) (the console is for admins).

## Context

A person answering an approval had two choices: approve or deny this one call, or (admins) remember it as a lasting exact-match rule. A task that pushes five times, or installs a few packages, asked five times. The only way to stop the asking was a permanent rule, which outlives the task and needs an admin.

What we needed: "approve this kind of call for the rest of this task", with no rule saved. That raised three questions the code had to answer:

- **What is a run?** Each Bot has at most one live run (`BotState.run`). `run_one` mints a run id (`r` + 8 hex), and its retry attempt keeps it. The Bot's `BOT_TOKEN` is per Bot, not per run (ADR 0029), so the token can't tell runs apart, and a hook call didn't say which run it came from.
- **What is "this kind of call"?** Rules are globs over the command. A glob made from one call is either exact (no help) or too broad (`git push*` also matches `git push --force`).
- **Where do people decide?** The Expo client's approvals inbox and the chat's approval cards. The admin console has no approvals of Bot actions on purpose (ADR 0032).

## Decision

### Approving takes a scope

`POST /api/approvals/{id}/approve` takes `scope: "once"` (the default, as before) or `"run"`. `run` approves this call and, for the rest of the run it came from, later calls of the same kind from the same Bot. Nothing is saved as a rule.

- Only an approval can have run scope: `deny` with `scope: "run"` is a 400. To keep denying, remember the denial.
- `scope: "run"` with `remember` is a 400: pick one.
- 400 when the approval's `runScope` is null (it can only be approved once), 409 when its run has ended or its hook stopped waiting.
- Each approval now has `runId`, `runScope: {covers, exact}` (what run scope would cover, or null), and `scope` (`once` or `run`, once approved).
- `botctl approve <id> --run` sends it.

### "The same kind": the classifier's own findings, never broader

The policy engine already explains each risky part of a call as a class and a short reason: `git_push` / "Pushes to a git remote", `network_install` / "Installs software (npm install)", `outbound_message` / "Posts to GitHub (gh pr comment)". A run grant is:

- the tool (`Bash`, `exec_command`, `terminal`, an MCP tool, ...), and
- the set of (class, reason) pairs the approved call had in classes set to `ask`.

A later call is covered when it uses the same tool and every (class, reason) it has in an `ask` class is in the grant. So:

- It never reaches another class, or another reason in the same class: a grant for `npm install` doesn't cover `pip install` or `curl … | sh`, and one for `gh pr comment` doesn't cover `mail`.
- Harmless commands around it don't matter: `git add . && git commit -m x && git push` is covered by a `git push` grant.
- A call that is riskier than the approved one asks again: `git push && npm install x` needs both in the grant.
- Force pushes and remote deletes (`--force`, `-f`, `+ref`, `:ref`, `--delete`, `--mirror`, `--prune`) now have their own reason, "Force-pushes or deletes on a git remote", so a plain push never covers them. They are still `git_push`.

Some calls are only ever approved one at a time, so their `runScope` is null and the client shows no run action:

- `shell_destructive`: its reasons ("Runs as root", "Runs a command only known when it runs", workspace wipes) don't say what would run next time.
- Unreadable commands (always denied anyway).
- "Runs a downloaded script" (`curl … | sh`): the script can change between calls.
- Typed input into a running program (Hermes `process_manage` write/submit): it may finish a command typed earlier.

Deletes outside the workspace (`file_delete`) name a path that may be relative to wherever the command runs, so their grant is exact: only the same call again, from the same folder.

The person sees what a grant covers before choosing: the client lists `runScope.covers` ("For this run, calls like this (Pushes to a git remote) won't ask again until the task ends. Nothing is saved as a rule.").

### Bound to one run of one Bot

- The runner sets `SUPERBOT_RUN_ID` in the harness's environment. `botctl hook` sends it as `run` with each check. It works the same for every harness, on the server or on a user's machine, and through per-user OS accounts, because the hook inherits the harness's environment.
- A check's `run` counts only if it is the Bot's live run id. Anything else (no run, a finished run, another Bot's run) is treated as no run: the call asks as before, and its approval has no `runScope`.
- Grants are kept in memory on the run itself (`Run.grants`), so each belongs to one run of one Bot. A check looks only at the calling Bot's own run, so sending another Bot's run id finds nothing. A grant is for whoever's run it is; any person who may decide that Bot's approvals may grant it, as with approving once.
- An older `botctl` sends no `run`, so its Bot simply keeps asking. That fails safe.

### Ends with the run

The grant is dropped when the run ends: done, failed, stopped, timed out, or the server restarts (it was never written down). The retry attempt of the same run keeps it, since it's the same task. Approving for a run whose run ended in the meantime is a 409. The next run starts with nothing.

### Deny still wins

A grant only turns an ask into an allow. The policy engine decides first: bypass, then deny rules, then classes. Deny rules, classes set to `deny`, and unreadable commands are refused before any grant is looked at, including when an admin tightens the policy mid-run. A call's findings are computed against the current policy each time.

### Who may grant it

The same people who may approve once: a signed-in admin or member with operator access to the Bot (ADR 0012, 0017). Read-only users and Bot tokens get 403; people who can't see the Bot get 404. It needs no admin, because it saves no rule and ends with the task.

### Audit

No new event names (ADR 0009):

- `approval.requested`: details gain `runId` and `runScope` (what run scope would cover, or null) when the call came from the live run.
- `approval.approved`: details gain `scope` (`once` or `run`); a run approval also has `runId`, `covers`, and `granted`.
- `policy.allowed`: each call a grant lets through, by the system actor `policy`, targeting the approval that granted it, with `scope: "run"` and `runId`. It's recorded for every such call, like an allow rule's.
- `bot.run_finished`: details gain `runGrants`, the approvals that granted something in that run, when there were any.

### Clients

The approvals card (in the inbox and in chat) gets **Approve for this run** between Deny and Approve when the approval has a `runScope` and the person may decide. The line above the buttons says what it covers and that it ends with the task and saves no rule. It's hidden while "Remember" is on, since the two don't combine. The client also runs in the browser at `/app/`, so web users get it there.

The admin console gets nothing: it has no approvals of Bot actions (ADR 0032), and adding an approvals inbox only for this would bring back what that decision took out.

## Consequences

- A task that pushes, installs, or posts several times asks once, if the person wants, without an admin and without a rule that outlives it.
- The grant is only as narrow as the classifier's reasons. A grant for "Posts to GitHub (gh pr comment)" covers comments on any PR for the rest of the task. The person sees that wording before choosing.
- Run ids now reach the harness's environment. They aren't secret: knowing one lets nothing happen without the Bot's token, and only the live run's id counts.
- A server restart drops grants along with the pending approvals, as before.

## Alternatives considered

- **A temporary rule** (a glob with an expiry). Globs from one call are too broad or too narrow, rules are persisted and admin-only, and cleanup after a crash would need its own job.
- **A per-run token** to identify the run. It would change how Bots authenticate (ADR 0029) for every call, not just hooks. A run id beside the existing token is enough, since the token already proves which Bot is asking.
- **Class-wide grants** ("allow git_push for this run"). Simpler, but broader than the approved call: a push grant would cover force pushes.
