# Approvals follow-ups

Work left after the approvals MVP ([ADR 0007](adr/0007-approvals.md)). Each item is meant to become one GitHub issue.

1. **End-to-end hook tests against real CLIs.** CI tests the policy, queue, and API, not the harnesses. Hermes Agent's hook path is tested against a stub CLI (`server/tests/hermes_e2e.rs`) and was checked by hand on v0.23.2. Add a job (or a manual script) that runs Claude Code, Codex, Pi, and Hermes with a fake model or a cheap key, triggers a `git push`, and checks it waits for approval. Pin the minimum Codex version that runs hooks in `codex exec`.
2. **Run harnesses as a separate OS user.** Bots share `botd`'s user, so a Bot could read `.env`, the database, or `botd`'s memory. Run each harness as a dedicated user (or in a container) with no read access to `DATA_DIR` secrets.
3. **Per-Bot tokens.** Done: each Bot run gets its own `BOT_TOKEN`, and `from` must be the Bot itself ([ADR 0028](adr/0028-per-user-isolation.md)).
4. **Policy editor in the apps.** The web app and client switch ask/bypass globally and per Bot. Add class actions, the timeout, and the rule list (view, add, delete), which today need `botctl` or the API.
5. **Audit export.** Done: CSV export, filters, and a viewer in the web app ([ADR 0009](adr/0009-audit-events.md)). The Expo client has no viewer yet.
6. **Notifications.** Approvals wait silently unless an app is open. Push notifications (client), email, or Slack, with a deep link to the approval.
7. **Smarter command analysis.** Commands are parsed (`server/src/shell.rs`), but script files the Bot runs (`./cleanup.sh`, `python x.py`) aren't read, and decoded payloads (`base64 -d | sh`) aren't flagged.
8. **Approve once per run.** Let a person approve "this kind of call for the rest of this task" without saving a permanent rule.
9. **Sandbox defaults.** Turn on Codex's sandbox (`workspace-write`) and similar options as defense in depth, separate from approvals.
10. **Pi canary coverage.** The unguarded-run canary keys off shell tool names (`bash`, `shell`, and Hermes's `terminal`). Extend it to every tool once each harness reports hook calls reliably.
