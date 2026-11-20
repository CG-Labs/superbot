# 0025: Control plane: one machine per user via the Linode API

## Status

Accepted, first slice of [#29](https://github.com/CG-Labs/superbot/issues/29) (M3). It follows the owner's decisions of 19 Nov 2026 ([roadmap](../ROADMAP.md#decisions-19-nov-2026)): one computer per **user** (decision 1), rented through the **Linode API** for now (decision 2), sized by **per-user tier** (decision 3). It builds on [ADR 0012](0012-users-sessions-rbac.md) (users, roles), [ADR 0010](0010-secrets.md) (secrets) and [ADR 0019](0019-audit-actors.md) (audit actors).

## Context

Managed hosting gives each user their own machine. Their Bots, workspace, harness logins and screens will live there. The org's shared data (users, roles, billing, audit) stays with the server that runs the org: the control plane.

This slice builds the control plane's bookkeeping and its Linode calls. It does not yet move any Bot onto a user's machine.

Two constraints shape it:

- **Self-host parity.** Most installs are one server and need none of this. It must be off unless configured, and cost nothing when off.
- **Real money.** Every create bills an account. A retried request, a crash, or two admins clicking at once must never make two machines.

## Decision

### It lives in botd, and is off by default

The control plane is a module of botd (`server/src/machines/`), not a new service. It reuses botd's users, RBAC, audit log and SQLite. A separate service would need its own copy of all of those first.

It turns on only when `LINODE_TOKEN` is set. Without the token:

- the machine endpoints return **503** with "The control plane is not configured on this server…";
- no reconciler runs;
- no Linode client is built.

`deploy/install.sh` and Compose are unchanged. `.env.example` lists the settings, commented out.

### Data model

A new `machines` table (migration 9). One row per machine, keyed by an opaque id (`m` + 8 hex):

| Column | Meaning |
|--------|---------|
| `user_id` | The user it belongs to (`users.id`). Every query names the user or the machine. |
| `provider`, `provider_id` | `linode` and the Linode id, once created. |
| `label` | `<prefix>-<id>`, unique per Linode account. The idempotency key (below). |
| `tag` | The label prefix when the row was saved. The machine is tagged with it and looked up by it, so changing `MACHINE_LABEL_PREFIX` later can't lose a machine. |
| `tier`, `plan`, `region` | The tier asked for, the Linode plan it maps to now, and the region. |
| `state` | Our lifecycle state (below). |
| `provider_status`, `ipv4`, `backups` | What Linode last said: its own status word, the public IPv4, whether backups are on. |
| `last_error` | The last provider error, if the last attempt failed. |
| `create_sent_at` | When a create was last sent. Cleared when Linode refuses it. |
| `created_at`, `created_by`, `updated_at`, `destroyed_at` | Bookkeeping. |

A partial unique index on `user_id WHERE state <> 'destroyed'` is the rule "one machine per user". Destroyed rows stay as history.

How it relates to the rest of the store:

- A machine belongs to a **user**, not a Bot (decision 1). A user's Bots will share it.
- There is no org table: one botd is one org ([roadmap](../ROADMAP.md#current-state-honest-audit)). The machine's org is the server's.
- **Roles don't change.** Admins manage machines. Members and read-only users can see only their own.
- `tier` is on the machine for now. When billing v0 lands, a per-user **entitlement** will own the tier and the machine will follow it. Until then an admin picks.

### State machine

`pending → provisioning → running ⇄ suspended`, any of those `→ destroying → destroyed`, and `error` for machines that need an admin. `machines::next(state, step)` is the whole table, and a test covers every pair.

| From | Step | To |
|------|------|----|
| pending | created (Linode accepted it, or we found ours) | provisioning |
| provisioning | ready (Linode says `running`) | running |
| running | suspend (shut down) | suspended |
| suspended | resume (boot) | running |
| running, suspended | resize | same |
| pending, provisioning | fail (Linode refused the create) | error |
| provisioning, running, suspended | fail (gone at Linode) | error |
| pending, provisioning, running, suspended, error | destroy | destroying |
| destroying | gone (deleted at Linode) | destroyed |
| error | retry (an admin asks again) | pending |

`destroyed` is final.

The provider's status is stored beside our state, not mixed into it. A machine is still `running` to us while Linode says `rebooting` after a resize.

### Tiers, regions and the image are config

Tiers map to Linode plans in `MACHINE_TIERS=starter=g6-standard-1,pro=g6-standard-2,max=g6-standard-4` (the default; the first is the default tier). Changing the mapping changes what new machines and resizes get. It never resizes existing machines by itself; resizing a machine to its own tier moves it to the tier's new plan.

Other settings:

- `MACHINE_REGIONS`: the allowed regions. Required with a token, because where data lives is a choice (UK/EU residency). The first is the default.
- `MACHINE_IMAGE`: default `linode/ubuntu24.04`.
- `MACHINE_BACKUPS`: Linode Backups for every machine; default on.
- `MACHINE_LABEL_PREFIX`: default `superbot`.
- `MACHINE_AUTHORIZED_KEYS`: operators' SSH public keys, installed at create.
- `MACHINE_RECONCILE_SECONDS`: default 60.

All are checked at startup: a bad value stops botd, like other settings.

### Idempotency

- **Same request twice.** `POST /api/users/:user/machine` returns the user's live machine with 200 instead of making another. The unique index makes that true even if two requests race past the check. Asking for a *different* tier or region is a 409: that is a resize, not a retry.
- **Lost answers.** Each machine's Linode label is fixed when the row is saved, before Linode is called. If a create reached Linode but its answer was lost (timeout, crash), the next attempt gets "label must be unique". The control plane then lists machines with the row's tag, finds the one with its label, and adopts it. It never makes a second.
- **Retries after an error.** The label stays the same, so an earlier create's machine would be adopted as it is. A retry that changes tier or region first looks for it by label: if it's there, the retry is refused (409); if Linode can't be asked, nothing changes (502). When a machine is adopted, its real plan and region are recorded.
- **Late creates.** A create that went unanswered may still make a machine. If such a row is destroyed before the machine shows up, it stays `destroying` for 15 minutes after the create was sent, looking for the label on each pass and deleting what it finds. Only then is it `destroyed`.
- **Serialised changes.** Handlers and the reconciler take one async lock per change. Every save is also a compare-and-set on the old state (`UPDATE … WHERE state = ?`), so a stale change loses instead of overwriting.
- **Actions check Linode first.** Suspend, resume and resize read the machine at Linode before acting. If it is already off, on, or on the plan, no call is made and only our state is updated. So a call whose answer was lost is neither repeated nor wrongly taken as done.
- **Repeats are no-ops.** Suspending a suspended machine, resuming a running one, or resizing to the current tier and plan returns 200 and records nothing, when Linode agrees.

### Reconciliation

A background loop (every `MACHINE_RECONCILE_SECONDS`, and on `POST /api/machines/reconcile`) visits each machine that isn't `destroyed` or `error`:

- **pending:** try the create again. Rate limits, network errors, timeouts and Linode outages (5xx) leave a machine pending with `last_error`. Linode refusals (other 4xx) put it in `error`.
- **provisioning:** mark it running once Linode says so.
- **running and suspended:** record Linode's status, address and backups. Turn backups on if they should be. If Linode doesn't have it any more, it goes to `error` (`machine.lost`).
- **destroying:** retry the delete until it works, and wait out late creates (above).

The reconciler never boots or shuts down a machine to undo a change made in the Linode console. It records what it sees and leaves the decision to an admin. Machines in `error` wait for an admin.

### Secrets

`LINODE_TOKEN` comes through the secret store's env layer (`LINODE_TOKEN` or `LINODE_TOKEN_FILE`, [ADR 0010](0010-secrets.md)). It is registered with the redactor at startup, so it can't leak into chats, events, or the audit log.

It is botd's alone. Bots never get it: `LINODE_TOKEN` and `LINODE_TOKEN_FILE` are stripped from harness and screen processes, and the secrets layer never adds it (from a file or the store) to a Bot's environment. Otherwise a Bot could call Linode directly and skip the admin-only routes. `TURNSTILE_SECRET` gets the same treatment.

The client keeps the token in a zeroizing string, sends it only as the `Authorization` header, and leaves it out of `Debug`. Errors carry Linode's error reasons or the transport error without the URL. A test checks that no error or debug string contains the token.

The API base URL is fixed (`https://api.linode.com/v4`); there is no setting to send the token elsewhere. Tests pass a local URL in code.

Linode requires a root password with an image. Each machine gets a fresh random one that is sent once and stored nowhere. Operators get in with `MACHINE_AUTHORIZED_KEYS`; the control plane uses enrollment ([ADR 0031](0031-machine-enrollment-mtls.md)).

Use a Linode token scoped to Linodes read/write only. With `MACHINE_FIREWALL=on` it also needs Firewalls read/write ([ADR 0035](0035-machine-firewall-auto-enroll.md)).

### API and audit

All under the admin role, except the caller's own view:

- `GET /api/machines?state=`
- `GET|POST|DELETE /api/users/:user/machine`, `POST …/machine/suspend`, `…/resume`, `…/resize {tier}`
- `POST /api/machines/reconcile`
- `GET /api/machine` (any signed-in person, not Bots): your own machine only, without provider ids, label or errors. There is no parameter to name someone else.

`rbac::classify` adds only the `GET /api/machine` arm. Everything under `users/…` and `machines/…` falls through to admin.

Every change is audited with target `machine:<id>` and `userId` in the details:

- `requested`, `created` (with `adopted`), `running`, `backups_enabled`, `suspended`, `resumed`, `resized` (from and to tier and plan), `destroy_requested`, `destroyed`, `retried`;
- failures with outcome `failure`: `create_failed`, `lost`, `destroy_failed`, `backups_failed`, or the attempted action.

An admin's changes carry their per-user actor ([ADR 0019](0019-audit-actors.md)). The reconciler acts as `system:control_plane` *on behalf of* the machine's user, so `/api/audit?onBehalfOf=<user>` shows a user's machine history.

### Testing without spending money

Nothing in tests or CI calls Linode:

- The Linode client is tested against a local HTTP stand-in: request shapes, paging, the `X-Filter` tag filter, error mapping, and that the token stays out of errors.
- The control plane and HTTP tests use an in-memory provider behind the same `MachineProvider` trait. It enforces unique labels and can be told to fail the next call.

## Deliberately out of scope

- **Talking to the machines.** Enrollment and mTLS between the control plane and each machine is the next slice. The plan: the machine boots with a one-time enrollment token (cloud-init user data); it calls the control plane over HTTPS to exchange it for a client certificate from a control-plane CA; after that every call is mTLS, pinned both ways. The certificate is revoked on destroy. Done in [ADR 0031](0031-machine-enrollment-mtls.md).
- **Moving Bots onto machines.** Running a user's Bots, workspace, harness logins and screens on their machine, and routing their chats there.
- **Billing and entitlements.** Tiers aren't tied to a subscription yet, and limits aren't enforced. Model routing per tier is separate (M3).
- **Lifecycle tied to users.** Disabling a user doesn't suspend their machine yet. A disabled user can't be given a new one.
- **Restore.** Linode backups are on, but restoring one (and the DR drill) is a separate item (M3).
- **Other providers and multi-org.** The trait allows another provider. One botd is still one org.
- **A UI and `botctl machine` commands.** The API comes first.
- **Cost controls.** Budgets and alerts, and suspending idle machines automatically. A suspended Linode is still billed; only destroying stops the bill.

## Consequences

- Self-hosted servers are unaffected: no token, no reconciler, and a 503 from the machine routes.
- Every create is safe to retry. The cost of that is one label per machine that must stay unique in the Linode account, and one list call after a "label taken" answer.
- Admin machine changes are serialised by one lock held across a Linode call (up to 30 s). That is fine for admin actions; bulk operations would need per-machine locks.
- The `machines` table is the source of truth for who has which machine. A machine made by hand in the Linode console with a `superbot-…` label is adopted only if its label matches a pending row.
