# Approvals follow-ups

Work left after the approvals MVP ([ADR 0007](adr/0007-approvals.md)). Each item is meant to become one GitHub issue.

1. **End-to-end hook tests against real CLIs.** CI tests the policy, queue, and API, not the harnesses. Add a job (or a manual script) that runs Claude Code, Codex, and Pi with a fake model or a cheap key, triggers a `git push`, and checks it waits for approval. Pin the minimum Codex version that runs hooks in `codex exec`.
2. **Run harnesses as a separate OS user.** Bots share `botd`'s user, so a Bot could read `.env`, the database, or `botd`'s memory. Run each harness as a dedicated user (or in a container) with no read access to `DATA_DIR` secrets.
3. **Per-Bot tokens.** All Bots share one `BOT_TOKEN`, and `from` in `/api/approvals/check` is trusted. Issue a token per Bot run so one Bot can't file checks (or routines) as another.
4. **Policy editor in the apps.** The web app and client switch ask/bypass globally and per Bot. Add class actions, the timeout, and the rule list (view, add, delete), which today need `botctl` or the API.
5. **Audit export.** `GET /api/audit` is JSON only. Add CSV export and a viewer, as the M1 exit criteria ask.
6. **Notifications.** Approvals wait silently unless an app is open. Push notifications (client), email, or Slack, with a deep link to the approval.
7. **Smarter command analysis.** The shell classifier is lexical. Consider a real shell parser, resolving script files the Bot runs (`./cleanup.sh`), and flagging `eval`/`base64 -d | sh` patterns as risky.
8. **Approve once per run.** Let a person approve "this kind of call for the rest of this task" without saving a permanent rule.
9. **Sandbox defaults.** Turn on Codex's sandbox (`workspace-write`) and similar options as defense in depth, separate from approvals.
10. **Pi canary coverage.** The unguarded-run canary keys off shell tool names (`bash`, `shell`). Extend it to every tool once each harness reports hook calls reliably.
