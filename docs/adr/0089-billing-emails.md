# 0089: Billing emails

## Status

Accepted (21 Nov 2026). Sixth slice of billing v0 ([#31](https://github.com/CG-Labs/superbot/issues/31), [roadmap](../ROADMAP.md)). Builds on tier limits and the Stripe webhook ([ADR 0040](0040-billing-v0-tier-limits.md)), checkout, the portal and customers ([ADR 0042](0042-billing-checkout-portal-customers.md)), billing-period token usage ([ADR 0050](0050-billing-period-token-usage.md)), storage limits ([ADR 0082](0082-storage-limits-per-tier.md)), resizing machines on a tier change ([ADR 0085](0085-resizing-machines-on-a-tier-change.md)), and the SMTP transport from approval notifications ([ADR 0061](0061-approval-notifications.md)).

Numbering: `main` has up to 0088, with 0086 left for other open work. No open PR adds an ADR, so this is 0089. Renumber it if a collision appears at merge.

## Context

Stripe changes people's plans by webhook, but until now nobody was told. A failed payment, a plan set to end, a downgrade waiting on the user's files, or a token limit reached showed only on the Plan screen, so people found out when Bots stopped. Stripe can send its own receipts and card-failure emails, but it doesn't know what a plan change does in SuperBot: the limits, the computer's size, or why a Bot was refused.

Stripe redelivers webhooks, sometimes many times, and events arrive out of order. An email must go once per thing that happened, however often it's told. Self-hosted servers have no billing, and many have no mail server, so nothing may change for them.

## Decisions

### What is sent

To the person the plan is for (the user the subscription is linked to, never a Stripe customer's email), as plain text:

| Email | When | Kind |
|---|---|---|
| Plan started | A user's first paying subscription starts, even for a tier an admin already gave them. Says when it renews. | Essential |
| Plan changed | A Stripe event moves a paying user to another tier. | Essential |
| Payment failed | A subscription that sets the plan moves into `past_due`. Says the plan stays while Stripe retries, and to update the card with **Manage billing**. | Essential |
| Plan ending | A subscription is set to cancel (`cancel_at`, or `cancel_at_period_end`). Says the date and the plan that follows. | Essential |
| Plan ended | A Stripe event takes the user off the paid tier (deleted, canceled, unpaid). Says whether it ended because payments failed. | Essential |
| Computer waiting | A Stripe plan change's resize waits on the user: storage over the new plan (`storage_over`) or files that won't fit the smaller disk (`disk_too_full`). Uses the wait message the app shows. | Essential |
| Computer couldn't resize | A Stripe plan change's resize failed. Says the plan applies anyway and an admin was told. | Essential |
| Tokens running low | A run ends with the owner past 80% of their tier's `monthlyTokens` this period. | Usage |
| Tokens used up | A run ends with them at the limit. Says when more start. | Usage |
| Storage nearly full | A run starts with storage past ADR 0082's 90% warning. | Usage |
| Storage full | A message or task is refused because storage is full. | Usage |

Plan started, changed and ended also say what the user's computer is doing about the change, read when the email is sent: moving (it may restart once, nothing is lost), waiting and why, done, or failed. That's only for the resize the same Stripe event asked for, and only with the control plane on.

### What isn't

- **Bots limit.** Making a Bot past `maxBots` is refused in the app, at once, to the person trying. An email adds nothing.
- **Runs and routine runs limits.** Same: the chat or routine says so as it's refused.
- **Receipts and invoices.** Stripe sends them, with the amounts and tax details it holds. SuperBot doesn't repeat prices.
- **Admin-made tier changes.** An admin tells the user. Only a Stripe-caused resize sends the computer emails.
- **A billing portal link.** A Stripe portal session URL is short-lived and signs in whoever holds it, so it must not sit in an inbox. Emails link to the Plan screen (`{PUBLIC_URL}/app/plan`), where **Manage billing** opens a fresh portal session after the user signs in.

### Once per thing that happened

- Each email has a key naming what asked for it, stored with it under a unique index. A second email with the same key isn't queued.
  - A Stripe event's emails: `stripe:<event id>:<kind>`.
  - A plan set to end: `stripe:<subscription id>:plan_ending:<end time>`, so `customer.subscription.updated` and a later redelivery or a second event saying the same thing send one email. A new end date sends again.
  - Usage: `usage:<user>:<tier>:<billing period>:<kind>`, so once a period per tier. A new plan or a new period can send again. Token emails follow the saved total after each run, not that run's share, so runs that finish together can't skip one. Storage emails don't wait for the chat's once-a-day warning.
  - Resizes: `resize:<machine>:<asked at>:<kind>`, so once per resize request and outcome.
- A subscription event's emails are queued in the same database transaction that records the event id and applies it ([ADR 0040](0040-billing-v0-tier-limits.md)). The event is recorded with its emails or not at all, and a redelivered event is a duplicate before any email is looked at.
- They're held until the webhook has followed the event (asked for any resize), then released, so the plan email can say what the computer is doing. If botd stops in between, they're due anyway after a minute.
- Which emails an event asks for follows what applying it changed (`Applied`), not the event alone. A stale, duplicate, superseded or other-user event changes nothing, so it sends nothing. A payment-failed email needs the move into `past_due`, so the retries Stripe sends while it stays there don't repeat it.

### Sending

- A sender task sends what's queued, oldest first, 20 at a time, woken when something is queued and every 30 seconds. It sends one email per SMTP message, through ADR 0061's transport and its settings (`SMTP_HOST`, `SMTP_PORT`, `SMTP_TLS`, `SMTP_FROM`, `SMTP_USERNAME`, `SMTP_PASSWORD`). There is no new provider.
- Each try is counted, with the time of the next, before the email is sent. A failed send is tried again after 1, 4, 16 and 64 minutes, then given up on after 5 tries.
- If botd can't save an email's outcome (a full disk, say), it logs it and stops sending until the next pass, so it doesn't send emails it can't mark sent. That email waits its backoff before another try.
- Just before sending, the sender skips an email whose user is gone (`no_user`) or has no email address (`no_address`), and a usage email for someone disabled (`inactive`) or opted out (`opted_out`). Essential emails go to disabled users: their plan and payment still matter.
- Queued emails are kept with their state (`pending`, `sent`, `skipped`, `failed`), tries and reason. They're small, and they're what stops a resend.

### Turning usage emails off

- Usage emails are on for everyone by default. Anyone can turn theirs off from the Plan screen's **Emails** card, or with `PUT /api/me/emails` `{usage: false}`. `GET /api/me/emails` gives `{on, usage, canChange}`, where `on` says the server sends billing emails at all; `GET /api/billing` has `emails: {on, usage}` too. The Plan screen reads `/api/me/emails` itself, so the card shows on a server that sends billing emails without checkout (no `STRIPE_SECRET_KEY`).
- Plan and payment emails can't be turned off: they're about money and the user's computer.
- Changing it needs write access (read-only people can't), and Bots can't. Each change is audited as `billing.email_settings_updated` with `usage: {from, to}`.
- Usage emails say how to turn them off, with the link.

### What's in an email

- What changed, in plain words: the plan's label from the tiers file, dates, token counts and storage sizes, and the link.
- Never a Stripe customer, subscription, price or event id, an amount, a card detail, a portal link, a machine's provider plan or host, an error from a provider, or a secret. The facts stored with each email are those same plain values. A test renders every kind and checks for provider ids.
- Plan labels come from the tiers file, so subjects are made one line (header injection).
- Templates are pure functions of the kind, the stored facts, the link and the computer line, tested directly.

### Audit

Every outcome is audited by `billing` on behalf of the user:

- `billing.email_sent` with the kind, key, Stripe event id (if any), address and tries.
- `billing.email_skipped` with the reason.
- `billing.email_failed` (outcome failure) with the tries, whether it will try again, and the mail server's error with secrets redacted. The error is for admins; it's never in an email.

### Configuration

- On only while billing is (`BILLING=on`, ADR 0068) and SMTP is set (`SMTP_HOST` and `SMTP_FROM`). Then emails go unless `BILLING_EMAILS=off`. `BILLING_EMAILS=on` without SMTP stops botd at start, with what to set. Any other value stops it too.
- They don't follow approval notifications' email switch ([ADR 0061](0061-approval-notifications.md)): a server can send billing emails without approval emails, and the other way round. Only the SMTP server is shared.
- Off, nothing is queued and nothing is sent. The Plan screen has no **Emails** card. Self-hosted servers, which have no billing, are unchanged.
- Without a public address (`PUBLIC_URL`, else `SSO_PUBLIC_URL`, else the first `ALLOWED_HOSTS`), emails go without links and say to open **Plan** in SuperBot.
- The start-up log says whether billing emails are on and through which mail server (host, port and TLS; not the sign-in name). `server.started` adds `billingEmails`.

## Consequences

- People hear about a failed payment, an ending plan, a waiting downgrade or a used-up allowance when it happens, not when a Bot stops.
- Webhook retries can't send twice, and an email can't go for an event that wasn't applied.
- Billing emails need a working SMTP server. A server that sells plans without one sends nothing, as before, and says so at start.
- An email queued while the mail server is down for longer than about 85 minutes is given up on, and audited.
- Usage emails go once a billing period per tier. Someone who frees storage and fills it again in the same period isn't told twice; the Plan screen and the refusal still say so.
- Not covered: yearly prices at checkout (still on #31), HTML emails, emails in other languages, and emails for team billing.
- It changes the "out of scope" emails of [ADR 0040](0040-billing-v0-tier-limits.md), [ADR 0042](0042-billing-checkout-portal-customers.md) and [ADR 0050](0050-billing-period-token-usage.md).
