# Subprocessors and outside services

Every outside service SuperBot's code can talk to, what it receives, and the setting that turns it on. Derived from the code in [`server/`](../../server/) and [`apps/client/`](../../apps/client/). Part of the [security pack](README.md).

Each one is **off until the operator configures it**. Which ones are actual subprocessors depends on who operates SuperBot and what they turn on: a managed provider lists the ones it uses; a self-hosting customer picks their own.

SuperBot sends nothing to CG-Labs. There is no telemetry, analytics or crash reporting in botd or the apps, and the licence key is checked offline ([ADR 0038](../adr/0038-self-host-license-key.md)).

## Services that receive customer data

| Service | Used for | What it receives | Turned on by |
|---------|----------|------------------|--------------|
| **Linode (Akamai)** | Per-user machines (VMs), Cloud Firewall (`MACHINE_FIREWALL=on`), Linode Backups ([ADR 0025](../adr/0025-control-plane-linode.md), [ADR 0035](../adr/0035-machine-firewall-auto-enroll.md)) | Hosts the user's machine and everything on it: working folder, Bot memory, harness logins. API calls carry labels, tags, region, size and cloud-init data. | `LINODE_TOKEN`, `MACHINE_REGIONS` |
| **Incus hosts** | Per-user containers ([ADR 0065](../adr/0065-incus-container-machines.md)) | As above. Run by the operator, or a hosting company the operator chooses. | `MACHINE_PROVIDER=incus`, `INCUS_URL` |
| **S3-compatible object storage** (AWS S3, Cloudflare R2, Backblaze B2, MinIO, or the customer's own) | Off-host machine backups ([ADR 0071](../adr/0071-off-host-machine-backups.md)) | Full disk copies of machines, including working folders, Bot memory and harness logins. Encrypted with age by botd before upload when recipients are set; plain otherwise. | `MACHINE_BACKUP_S3_BUCKET` and its endpoint and keys |
| **Model providers** (for example OpenRouter, Anthropic, OpenAI, or any endpoint in the tiers file) | Model calls made by the harness ([ADR 0033](../adr/0033-tiers-model-routing.md), [ADR 0077](../adr/0077-two-providers-through-tier-routing.md)) | Prompts, conversation, tool output and file contents the harness sends. | The tiers file (`TIERS_FILE`) and provider keys, or keys in secrets |
| **Anthropic, OpenAI** (through a person's own subscription) | Harness logins for Claude Code and Codex on machines ([ADR 0041](../adr/0041-machine-harness-logins-and-folder-copy.md)) | As above, under the person's own account. | `MACHINE_HARNESS_LOGINS=on`, and the person signing in |
| **Stripe** | Checkout, customer portal, plan changes by webhook, token metering, team seats ([ADR 0040](../adr/0040-billing-v0-tier-limits.md), [ADR 0042](../adr/0042-billing-checkout-portal-customers.md), [ADR 0050](../adr/0050-billing-period-token-usage.md), [ADR 0093](../adr/0093-team-billing.md)) | SuperBot user ID, team ID, plan name, email (when creating a customer), Stripe customer ID, token counts, a team's member count. Card details go to Stripe directly. | `BILLING=on`, `STRIPE_WEBHOOK_SECRET`; `STRIPE_SECRET_KEY` for checkout; `STRIPE_METER_EVENT` for metering |
| **Expo push service**, then **Apple APNs** and **Google FCM** | Push notifications ([ADR 0080](../adr/0080-client-push-notifications.md)) | Device push token, a title and a line naming the Bot, an app link. No commands, output or routine names. | `PUSH_PROVIDER=expo`, then each person's opt-in |
| **SMTP server** (the operator's) | Approval emails ([ADR 0061](../adr/0061-approval-notifications.md)); billing emails ([ADR 0091](../adr/0091-billing-emails.md)) | Recipient email; for approvals, the Bot, tool, risk class, reason and a shortened command; for billing, the plan name and dates, computer resize status and token and storage use (no Stripe ids, amounts or portal links). | SMTP settings and `SMTP_PASSWORD` |
| **Webhook receivers** (Slack, Mattermost, Discord, or any URL) | Approval notices ([ADR 0061](../adr/0061-approval-notifications.md)) | As approval emails. | `NOTIFY_WEBHOOK_URL`, or a per-Bot URL |
| **Identity providers** (Microsoft Entra ID, Google, Apple, GitHub, Okta and other OIDC, a Keycloak broker for SAML) | Sign-in ([ADR 0016](../adr/0016-sso-multi-provider.md), [ADR 0018](../adr/0018-sso-github-apple.md), [ADR 0020](../adr/0020-saml-bridge.md)) | Standard OIDC requests. botd receives the person's identity and email from the IdP. | `SSO_*` settings |
| **Cloudflare Turnstile** | Bot check on the public signup form ([ADR 0022](../adr/0022-landing-and-signups.md)) | The visitor's challenge answer and IP address, as Turnstile collects them. | `TURNSTILE_SECRET`, `TURNSTILE_SITE_KEY` |

## Services that receive no customer data

| Service | Used for |
|---------|----------|
| Let's Encrypt or ZeroSSL (through Caddy) | HTTPS certificates for the server's domain. |
| `images.linuxcontainers.org` | Incus base images (`INCUS_IMAGE_SERVER`, or `local`). |
| An error tracker that takes Sentry's protocol (Sentry, GlitchTip, Bugsink, or one the operator runs) | botd's panics and 5xx answers, off unless `ERROR_REPORT_DSN` is set: route templates, statuses, source locations, request ids and botd's version, scrubbed of secrets and emails; never a prompt, chat, path, body or user ([ADR 0113](../adr/0113-service-dashboards-and-error-reporting.md)). It sees the server's IP as the sender. |
| Node.js downloads and the npm registry | Installing harness CLIs on machines ([ADR 0039](../adr/0039-machine-harnesses-and-agent-upgrades.md)). |
| GitHub | The install script and releases. |
| Apple App Store, Google Play | Distributing the apps. |

## Planned

- A published subprocessor list for the managed service (M4, GDPR row of the [roadmap](../ROADMAP.md)). The [DPA template](dpa-template.md#annex-iii-subprocessors)'s Annex III is built from the table above for a provider to fill in with the services it really uses, and the [privacy policy template](privacy-policy-template.md) points to it; both are drafts for legal review.
