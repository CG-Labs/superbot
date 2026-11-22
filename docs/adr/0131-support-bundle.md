# 0131: Support bundle

## Status

Accepted (22 Nov 2026). First slice of enterprise support playbooks in M5, [#60](https://github.com/CG-Labs/superbot/issues/60), with the playbooks in [`docs/support/`](../support/README.md). Builds on structured logs ([ADR 0089](0089-metrics-and-structured-logs.md)), the status page ([ADR 0090](0090-status-page-and-uptime-slo.md)), the audit log and its redaction ([ADR 0009](0009-audit-events.md), [ADR 0019](0019-audit-actors.md)), secrets and their redaction from logs ([ADR 0010](0010-secrets.md)) and the setup wizard ([ADR 0034](0034-onboarding-wizard.md)).

Numbering: 0122 to 0130 are held by work in flight, so this is 0131.

## Context

A support ticket's first round is always the same questions: which version, what settings, is anything unhealthy, what did the logs say, and what failed recently. On a self-hosted or dedicated server only the customer can answer, and today that means pasting `.env` (secrets and all), `journalctl` output (whatever is in it) and screenshots. Enterprise support playbooks need one command that gathers it safely.

Three constraints:

- **Nothing secret, nothing personal.** The file leaves the customer's control. It must hold no secret values, chats, prompts, tool inputs, names, emails or IP addresses, and must stay so as settings and log lines are added.
- **Rust first, no new dependencies.** botd already holds the data; the bundle shouldn't need a shell script, `tar` on the host, or a compression crate.
- **Harness agnostic.** Nothing harness-specific in it beyond what botd already reports.

## Decision

### An admin API, saved by botctl

`GET /api/support/bundle` answers an admin with a tar file (`application/x-tar`, `Content-Disposition: attachment; filename="superbot-support-<UTC time>.tar"`, `Cache-Control: no-store`). It isn't in the RBAC table, so it takes the default for unlisted routes: admins only. Members, read-only users and Bots get 403, and so does anyone with a custom role, which can't hold the admin permission ([ADR 0123](0123-custom-roles.md)). Each bundle is audited as `support.bundle_created` with its name, size, files and counts.

`botctl support-bundle [-o <file>]` calls it with the operator's credentials (loopback only, as every operator command), reads the reply as bytes, and saves it under the server's name or the one given: created new (never over an existing file) and mode 0600. It prints the path and how to read it.

Building it in botd rather than in botctl means the same bundle from the console or an API client later, and only botd knows the secrets it must redact.

### A plain tar of text files

One folder, `superbot-support-<time>/`, in ustar format written by botd (about 40 lines: a 512-byte header per file, data padded to 512, two empty blocks at the end), with no compression. Every file is UTF-8 text or JSON, so a customer can read it all with `tar -xOf` before sending it. The bundle is tens of kilobytes; compression would save little and make it harder to inspect.

| File | Contents |
|---|---|
| `README.txt` | What the bundle is and what's never in it |
| `version.json` | botd's version, OS, architecture, kernel, whether in a container, start time and uptime (from the last `server.started` event), harnesses installed and the default |
| `config.json` | botd's settings from its environment, redacted; the names of those redacted; how many other variables the host had; the summary of the effective config `server.started` recorded; tiers' source, default, names and summary; the global approval policy |
| `health.json` | The status page's snapshot (components and open incidents), the setup checklist, the license summary and warnings, approvals waiting and the oldest one's age, run slots, the last 15 minutes' metrics, machine and host states and open RPO breaches, database encryption, server backups |
| `logs.jsonl` | The newest log lines botd wrote (below) |
| `audit-summary.json` | The last 7 days of audit events counted by action and outcome, and the newest 100 failures and denials with time, action, outcome, actor kind, sign-in method, IdP, target type, reason and trace id: never who, from where, or the details |
| `manifest.json` | Format version, creation time, each file's size, and counts of settings redacted, log lines and audit events |

`FORMAT` (1) is bumped when a file's shape changes.

### Recent logs from memory

botd keeps its newest 2,000 log lines in a ring buffer, rendered as JSON whatever `LOG_FORMAT` is (a line over 4 KiB has its long fields cut, so it stays JSON). Text-mode output is unchanged. It costs at most about 8 MB and a lock per line. A restart empties it: the bundle says where older logs are (journald, Docker). Reading journald from botd would need privileges or a dependency, and Compose has no journald.

Log lines already avoid emails, names, IPs, message text and tokens ([ADR 0089](0089-metrics-and-structured-logs.md)); the bundle scrubs them again (below) because free-text warnings can carry anything. It scrubs each line's fields, not the line as text, so every line stays one JSON object.

### Only botd's settings, redacted four ways

The process environment holds the host's variables too (shell, service manager, other software). The bundle shows a variable only if it's botd's: a name `.env.example` documents (compiled in, so the list moves with the docs), a SuperBot prefix (`SUPERBOT_`, `MACHINE_`, `INCUS_`, `SSO_`, `SMTP_` and the like), a provider key or base URL (`*_API_KEY`, `*_BASE_URL`), or a few standard ones (`TZ`, `RUST_LOG`, proxies). Others are only counted.

Each shown value is then redacted:

1. **By name.** A name that says secret (`redact::names_secret`: `KEY`, `TOKEN`, `SECRET`, `PASSWORD`, ...; plus `DSN`, `WEBHOOK`, `SALT`, `PASSPHRASE`, `COOKIE`, `HEADER`) becomes `[redacted]`, unless it ends `_FILE`, `_PATH` or `_DIR` (where a secret is, not what it is). `OWNER_EMAIL` and `USER_NAME` are left out as personal.
2. **By shape.** A value of 24 or more key-like characters with letters and digits (a generated secret) becomes `[redacted]`. Anything else goes through the audit log's redaction (`Bearer x`, `token=x`, `user:pass@` in URLs, known key prefixes) and a private key or age secret key blanks the whole value.
3. **URL origins only.** A URL's path and query become `/[redacted]`: Slack webhooks, Sentry DSNs and signed links carry their secret there.
4. **Emails** become `[email]`.
5. **IP addresses** become `[ip]` (a port after an IPv4 address stays); loopback and unspecified ones (`127.0.0.1`, `0.0.0.0`, `::1`) stay, since they say nothing about a network.
6. **The licensee's name** becomes `[name]`, in any case, as a whole word only (a short name like `IT` leaves `audit-summary.json` alone). The license, its warnings, the setup checklist and the settings botd started with all repeat it.

Every string in every JSON file, and each log line, goes through the same text scrubbing, and then the secrets botd knows (`redact::value`/`redact::text`: the sealed store's values, and the shapes of tokens botd issues). A bundle can contain only what botd chose to put in it, with secrets botd holds caught wherever they appear.

### Not in the bundle

Chats, prompts, tool inputs and outputs, files, harness transcripts, users and teams, and audit details. Users' machines' own logs aren't collected: support asks for them when needed.

## Alternatives considered

- **A shell script on the host** (`superbot-support.sh`): works when botd is down, but would read `.env` raw and redact with `sed`, which is where leaks come from. The support doc covers the botd-down case with two commands to run instead.
- **`tar.gz` via a crate**: smaller, but adds a dependency for a file of tens of kilobytes, and gzip makes "read it before you send it" harder.
- **Reading logs from journald**: complete, but needs privileges and doesn't exist under Compose.
- **Redacting the whole environment** instead of choosing botd's variables: unknown variables can hold anything in any shape (names, hostnames, ids in free text); an allow-list fails safe.
- **Uploading to the Provider directly**: needs an endpoint and credentials on every server, and takes the customer's review step away.

## Tests

- `support::tests`: secret-named settings lose their values; `_FILE`/`_PATH`/`_DIR` settings and plain ones are kept; secrets are found by shape in innocent names (URLs with credentials, paths and queries, `Bearer`, `token=`, key prefixes, random strings, private keys); a registered secret is redacted anywhere; IP addresses are masked and versions, times and Rust paths are not; the licensee is hidden in any case; emails and URLs are cut without eating neighbouring text; the environment shows only botd's settings, sorted, naming what it changed and counting the rest; the documented list parses from `.env.example`; the tar reads back with valid checksums, and the system `tar -tvf` agrees.
- `support_http_tests.rs`, on the real router: members, read-only users, a custom role with every delegable permission, and Bots get 403, nobody gets 401; an admin gets a tar with the right headers and the seven files, audited once with matching size; the bundle carries version, health (an approval waiting, the setup checklist, the license), config, the audit summary with a failed sign-in's reason, and a manifest whose sizes match; a registered secret, a session token, an email, a chat message and a webhook path, logged or audited, appear nowhere in it; nor do the installed license's licensee or IP addresses in a log line; settings are redacted by name, shape and known value, and host variables are left out.
- `botctl` tests: `support-bundle` options, only plain file names from `Content-Disposition`, and saved files private and never overwritten.
- `auth_review_http_tests.rs` checks the new route refuses callers without credentials, as for every route.

## Consequences

- Logs from before the last restart aren't in the bundle.
- A new setting with a secret in an unusual name and a short, non-random value could show. Mitigations: secrets botd holds are caught by value, the name list follows `redact::names_secret`, and the README asks the customer to read the bundle first.
- `.env.example` is compiled into botd, so the Dockerfile's build stage copies it.
- The setup checklist is in the bundle without the admins' emails.
- A follow-up could add the console button, a `--since` for audit, or machine agent logs.
