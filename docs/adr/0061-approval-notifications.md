# 0061: Approval notifications by email and webhook

## Status

Accepted (21 Nov 2026). Approvals follow-up 6 ([list](../approvals-followups.md), tracking issue [#13](https://github.com/CG-Labs/superbot/issues/13), M1). It builds on [ADR 0007](0007-approvals.md) (approvals), [ADR 0009](0009-audit-events.md) (the audit log), [ADR 0010](0010-secrets.md) (secrets), [ADR 0017](0017-bot-acls.md) (who can operate a Bot), [ADR 0032](0032-console-admin-only.md) (the console) and [ADR 0049](0049-policy-editor-in-the-apps.md) (the policy editor). Mobile push is a separate M3 item ([#36](https://github.com/CG-Labs/superbot/issues/36)).

## Context

A pending approval only shows in an open app. With no app open, the Bot waits until the approval times out and is denied. A server needs a way to reach someone who can answer, without a paid service and without leaking what the Bot asked to run.

## Decision

### Two channels, off until an admin turns one on

- **Email** through the admin's own SMTP server. `SMTP_HOST` and `SMTP_FROM` turn it on; `SMTP_PORT`, `SMTP_TLS` (`starttls`, the default; `tls`; or `none`, only to this machine) and `SMTP_USERNAME` are optional. `SMTP_PASSWORD` is a secret: `.env`, `SMTP_PASSWORD_FILE`, or the sealed store (the console's Server secrets). botd's own SMTP client (`server/src/notify/smtp.rs`) sends one message per recipient, so recipients never see each other, and signs in only over TLS. STARTTLS must be offered, or it doesn't send.
- **An outgoing webhook**: a URL that gets a POST for each notice. The default format is Slack's incoming-webhook body (`{"text": …}`, which Slack, Mattermost, Rocket.Chat and Discord's `/slack` endpoints take). The `json` format is SuperBot's own (`type`, `bot`, `approvals`, `more`, `text`, `sentAt`), signed when `NOTIFY_WEBHOOK_SECRET` is set: `X-SuperBot-Signature: sha256=<HMAC-SHA256 of "<timestamp>.<body>">`, with the timestamp in `X-SuperBot-Timestamp` so a receiver can refuse replays. The URL must be https (http only to this machine) with no user name or password in it. Redirects aren't followed.

The settings live in botd's settings table (`notifications`), so no migration is needed. Both channels start off. Nothing reaches anyone until an admin turns one on.

### Global, and per Bot

Admins set the channels for all Bots, and each Bot can change them for itself:

- **Email on or off**, else it follows the global switch.
- **Webhook on or off**, else it follows the global switch. A Bot can have **its own webhook URL** (for example its team's channel) and format. Its own URL turns its webhook on unless it says off, and replaces the global URL for that Bot.

Webhook URLs carry their own token, so they are secrets, never settings: the global one is `NOTIFY_WEBHOOK_URL`, a Bot's is `NOTIFY_WEBHOOK_URL_BOT_<ID>`, saved in the sealed store, or set in `.env` (then they change there). The API takes a URL and only ever answers whether one is set and its host. Like `TURNSTILE_SECRET`, all of these are botd's own: no Bot gets them, harnesses run without them, and no user can save them as personal secrets.

### Who gets it

- **Webhook**: the channel behind the URL.
- **Email**: the addresses in the global list, and, unless an admin turns it off, each Bot's **deciders**: its owner and the people it grants operator to, while they are active, their role can approve, and they can still operate it. Not every member of a shared Bot, though all of them can operate it: that would email the whole company. Admins who want every approval list themselves. Addresses go once each.

Push (#36) is another `Channel` (`server/src/notify/mod.rs`): it gets the same notice and the same plan, and will reach the deciders' devices. Nothing else changes when it lands.

### What a notice says

Only what the approval card shows: the Bot's name, the tool, the risky class, why it asks, and the command, path or address. That is redacted like chat (registered secret values become `[REDACTED]`), made one line and cut to 200 characters. **Detail: minimal** leaves out the command and the reason, for channels many people read. The tool's input, files and chat are never sent.

Each approval links to:

- **the client**: `https://<domain>/app/home?approval=<id>`. The client has no page per approval; approvals are a modal on home. The link opens it with that approval first, says so when it's no longer waiting, and survives sign-in. The native apps open `superbot://home?approval=<id>` the same way.
- **the console**: `https://<domain>/console/#audit?target=approval:<id>`, the approval's audit trail (requested, notified, decided). The audit API takes a new filter for this: `target=<type>[:<id>]`.

The domain is `PUBLIC_URL`, else `SSO_PUBLIC_URL`, else the first `ALLOWED_HOSTS` name, as for billing. With none, notices go without links, and the settings say how to fix it.

### Throttling and dedup

- **Delay** (`delaySeconds`, 30 by default, up to 600): botd waits before sending. An approval answered by then, in an open app, sends nothing.
- **Once**: each approval is sent at most once.
- **Throttle** (`throttleSeconds`, 120 by default, up to 3600): after a notice for a Bot, its next approvals wait for the window's end and go as one digest (up to 10 listed, the rest counted). Approvals answered in the meantime drop out.
- **Deadlines win.** Neither the delay nor the throttle waits past half the time an approval has left, so a short approval (a one-minute timeout, say) is still noticed with time to answer. The digest goes early if one of its approvals needs it to.

The throttle lives in botd's memory. A restart forgets it, and pending approvals don't survive a restart either: their hooks fail closed.

### Audit

Each channel's attempt is one event: `notification.sent` (outcome `success`) or `notification.failed` (`failure`, also when only some recipients were refused). The details are `channel`, `kind` (`approval`, `digest` or `test`), `approvals`, and for email `to`, `delivered` and `refused`; for webhooks `host`, `format`, `own` and `status`. A failure adds `error`, redacted, which never holds the URL. The target is the approval, or the Bot for a digest. Settings changes are `notifications.updated`, with before and after, and `webhookUrl: set|removed` without the URL.

### Where it's set

- **The app**: the policy editor ([ADR 0049](0049-policy-editor-in-the-apps.md)) shows a Notifications card to admins: the global settings on the policy for all Bots, a Bot's own on its policy, with who its next approval reaches. Both have **Send a test**.
- **The console**: Settings has the global settings and a test. A Bot's own settings are in the app, as for its policy.
- **The API**, admins only: `GET/PUT /api/notifications`, `POST /api/notifications/test` (`{botId?}`), `GET/PUT /api/bots/{id}/notifications`. Saving refuses email without an SMTP server or anyone to send to, and a webhook without a URL.

A deleted Bot's settings and URL go with it.

## Consequences

- A self-hosted server can reach people with an SMTP server it already has, or a Slack (or compatible) webhook, both free.
- Notices leave the server. Admins choose where they go, and **minimal** keeps commands out of shared channels.
- A slow or broken SMTP server or webhook delays nothing: sends run apart from the approval and from each other, time out (20 s per SMTP step, 10 s per webhook), and are audited.
- Notification state isn't shared between servers. One botd per database is already the rule.

## Alternatives considered

- **A mail crate (lettre).** Pulls in another TLS and DNS stack. SuperBot needs a few hundred lines of SMTP on the TLS it already has.
- **Settings in `.env` only.** Restarts for every change, and no per-Bot settings. SMTP's server stays in `.env` because it rarely changes and holds a password.
- **Webhook URLs as plain settings.** Slack's URL is the credential. Anyone who reads the settings or the audit log could post to the channel.
- **Emailing every member of a shared Bot.** Too many people for one approval; the owner and operators are the ones who answer.
- **A page per approval in the client.** Approvals already live in one modal with everything to answer them; a link that opens it is enough.
