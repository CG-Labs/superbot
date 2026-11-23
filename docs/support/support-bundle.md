# Support bundle

One file with what support asks for first, made on the server and attached to a ticket. Design: [ADR 0131](../adr/0131-support-bundle.md).

## Make one

On the server, as an admin (`SUPERBOT_TOKEN`, or `SUPERBOT_PASSWORD`, as for any operator command; `botctl admin` lists them):

```sh
botctl support-bundle                    # saves superbot-support-<time>.tar here
botctl support-bundle -o /tmp/ticket.tar
```

Or press **Download support bundle** on the console's Support tab, or, from anything that can call the API as an admin, `GET /api/support/bundle`, which answers with the tar file. Each one is in the audit log as `support.bundle_created`.

The file is saved readable only by you, and never over an existing file.

## Read it before you send it

It's a plain tar of text files:

```sh
tar -tvf superbot-support-<time>.tar
tar -xOf superbot-support-<time>.tar | less
```

| File | What's in it |
|---|---|
| `README.txt` | What the bundle is and what's never in it |
| `version.json` | botd's version, OS and architecture, when it started, and the harnesses on the server |
| `config.json` | botd's settings from its environment, with secrets redacted (the names of the ones redacted are listed); other variables on the host are only counted. The settings botd started with, the tiers' names and summary, and the approval policy |
| `health.json` | The status page's checks and open incidents, the setup checklist, the license, approvals waiting and the oldest one's age, runs running and waiting, the last 15 minutes' metrics, machines and hosts, database encryption and server backups |
| `health-score.json` | The [customer health score](health-score.md) for the last 30 days and its signals: counts and reason codes only |
| `health-score-history.json` | The score botd recorded each day for the last 90 days ([history](health-score.md#history)): score, band and each signal's status |
| `logs.jsonl` | The newest lines botd logged since it started (up to 2,000), one JSON object each, whatever `LOG_FORMAT` is |
| `audit-summary.json` | The last 7 days of the audit log counted by action and outcome, and the newest 100 failures and denials with their reason code (a free-text reason shows as `[text]`) |
| `manifest.json` | The files and their sizes, and how many settings, log lines and audit events went in |

## What's never in it

Secret values, chats, prompts, tool inputs, files, names, emails or IP addresses. In detail:

- A setting whose name says it's secret (`_KEY`, `_TOKEN`, `_SECRET`, `PASSWORD`, `DSN`, `WEBHOOK`, `HEADERS` and the like) shows as `[redacted]`. One that says where a secret is kept (`_FILE`, `_PATH`, `_DIR`) shows the path, not the secret.
- A value that looks like a credential is redacted wherever it is: a long random string, `Bearer x`, `token=x`, `user:password@` in a URL, a known key prefix (`sk-`, `ghp_`, `AKIA` and others), a private key, and any secret botd holds (the sealed store, sessions and tokens it issues).
- URLs keep their scheme, host and port; paths and queries become `/[redacted]`, because some services put a secret there.
- Emails become `[email]`. `OWNER_EMAIL` and `USER_NAME` are left out.
- IP addresses become `[ip]`, except loopback and `0.0.0.0`, which say nothing about your network.
- The licensee's name (the organisation on the license) becomes `[name]` wherever it shows.
- The audit summary has actions, outcomes, times, sign-in methods, identity provider names and reason codes (a free-text reason, which can quote a path or a command, shows as `[text]`); never who, from where, or what they wrote.

If you find something you'd rather not send, delete it from the bundle and say so in the ticket. If you find a secret in it, don't send it, and tell `<security-email>`: that's a bug.

## Not in it, yet

- Logs from before botd last started: the bundle keeps the newest lines in memory. For older ones, `journalctl -u superbot -o cat` (installer) or `docker compose logs botd` (Compose), with `LOG_FORMAT=json`.
- Users' machines' own logs. Support asks for them when needed.
- Anything from a server that isn't running. Then send `journalctl -u superbot -n 500` and the output of `systemctl status superbot` instead, read first for the same things.
