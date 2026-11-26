# 0325: Following GCP Secret Manager's change events

## Status

Accepted (26 Nov 2026). Part of secrets vault integration in M5, [#55](https://github.com/CG-Labs/superbot/issues/55). Does one of the ideas [ADR 0306](0306-following-vaults-change-events.md) and [ADR 0318](0318-vault-change-events-handoff-and-state.md) left for later: change events from Google Pub/Sub for GCP Secret Manager, reported through the same `watch_status` and metrics.

Numbered 0325 because it is the number reserved for this slice.

## Context

With `VAULT_EVENTS=1`, a rotation in Vault reaches new runs in about a second (ADR 0306). With GCP Secret Manager, it reaches them within `SECRETS_CACHE_SECONDS`, or at once only after someone runs `botctl secrets refresh` (ADR 0291).

Secret Manager can publish a Pub/Sub message to up to ten topics on a secret whenever the secret or one of its versions changes. Each message carries attributes `eventType` (`SECRET_CREATE`, `SECRET_UPDATE`, `SECRET_DELETE`, `SECRET_VERSION_ADD`, `SECRET_VERSION_ENABLE`, `SECRET_VERSION_DISABLE`, `SECRET_VERSION_DESTROY`, `SECRET_VERSION_DESTROY_SCHEDULED`, and two that announce no change: `SECRET_ROTATE`, a rotation reminder, and `TOPIC_CONFIGURED`, a test message) and `secretId` (the secret's resource name, by project number), and the secret's metadata as data. Google says new event types may be added.

ADR 0306 assumed the clouds' events need an endpoint on botd that each cloud can reach and whose signatures botd checks. For Pub/Sub that holds only for push subscriptions. A pull subscription is read by the subscriber over HTTPS with its own token, like botd's other calls to Google: no inbound endpoint, no signature to check, and messages wait in the subscription while botd is down or restarting.

## Options

1. **A push subscription to an endpoint on botd.** Needs botd reachable from Google, a public route through the firewall, and checking Google's OIDC tokens on each push. Most self-hosted servers aren't reachable, and it adds an unauthenticated route.
2. **A pull subscription, unary `pull`.** Chosen. Plain JSON over HTTPS with botd's existing token, through `reqwest` like every other Google call; a pull waits a while on the server when there is nothing, so an idle botd makes a request about once a minute.
3. **Streaming pull over gRPC.** Lower latency under load, but pulls in a gRPC stack and HTTP/2 streaming for a topic that sees a few messages a day.
4. **Polling secrets' metadata** (`updateTime`). One list per poll with nothing to set up, but it misses version changes (a new version doesn't touch the secret's `updateTime`), and it is the cache time again by another name.

## Decision

- **`GCP_SECRET_MANAGER_EVENTS=<subscription>`**, off by default: a subscription id in `GCP_SECRET_MANAGER_PROJECT`, or `projects/<project>/subscriptions/<id>` for one elsewhere. Checked as Google names them (3 to 255 characters, starting with a letter, not with `goog`). Read only with `SECRETS_BACKEND=gcp-secret-manager`, and listed among other backends' settings that are set by mistake. `GCP_PUBSUB_ENDPOINT` (default `https://pubsub.googleapis.com`, https or loopback) is for Private Service Connect or a proxy, and the offline check lists it while events are on.
- **Startup.** botd asks Pub/Sub `testIamPermissions` on the subscription for `pubsub.subscriptions.consume` (in `roles/pubsub.subscriber`), with its own token. If the subscription isn't there, botd's service account may not pull from it, or Pub/Sub refuses, botd doesn't start, and says which, as with `VAULT_EVENTS` (a setting that is on and can't work is a mistake to surface, not to hide).
- **Pulling.** A task on Secret Manager's runtime pulls up to 100 messages at a time, waiting up to 60 s for an answer; a pull that times out after connecting, before its answer starts, is an empty answer, not a failure. A `%` in the subscription id is escaped in the URL, so it names that subscription. Pulls that bring nothing are at least 1 s apart, in case Pub/Sub answers them at once. A 401 gets a new token and one more try.
- **Which messages.** Only `eventType` and `secretId` are read, never the data. A `SECRET_*` type other than `SECRET_ROTATE` and `TOPIC_CONFIGURED` counts as a change, so new types aren't missed. `secretId` must be a secret in botd's location (global, or `GCP_SECRET_MANAGER_LOCATION`), with botd's prefix, in the Bots' or botd's folder or, with `SECRETS_USER_FOLDERS=1`, a user's, for a name that folder may hold. The project isn't compared, as Google names it by number and botd by id; the name is read again from botd's own project either way, so a message about another project's secret costs one read at most.
- **Applying.** The change goes to the same queue and applying thread as Vault's (`changes::apply`, moved out of the Vault module): a name changed again before it is read waits once, past 1,024 names waiting everything is read again, startup settings are flagged for a restart (ADR 0291), and each read is cached, redacted and audited like any. Pub/Sub has no index like Vault's `vault_index`, so the read asks for the latest version as any read does.
- **Acknowledging.** Every message a pull brings is acknowledged once its change is queued, including those botd ignores, so none comes back. A message botd hasn't acknowledged is delivered again, so a botd that stops between queueing and acknowledging reads a name twice at worst.
- **Losses.** A pull or an acknowledgement that fails (Google out of reach, an error status, an answer that isn't a list of messages or that starts and then stalls, a sign-in that fails) counts as a loss: the state shows `not followed` with botd's own reason (`Pub/Sub answered 404 Not Found (NOT_FOUND) to a pull`), never Google's text or a URL. botd tries again after 1 s, doubling up to a minute. Once a pull works again, it reads every cached answer again, since messages may have been lost, gone past the subscription's retention, or the subscription may have been made again.
- **One subscription per botd.** Pub/Sub hands each message to one of a subscription's pullers, so two servers sharing one would each miss changes. The ops guide says so; botd can't tell.
- **What botd shows.** `secret.gcp_events` (`subscribed`, `lost` with the reason, `resumed`) against the subscription; `secret.cache_refreshed` with `trigger` `gcp-event` (with the event type) or `gcp-events-resumed`. The state goes through `Provider::watch_status` to `botctl secrets backend`, the setup report and `/metrics` with `backend="gcp-secret-manager"`, and ADR 0318's alert rules apply unchanged.

## Consequences

- No change unless `GCP_SECRET_MANAGER_EVENTS` is set.
- With it, a change to a secret that has the topic reaches new runs in a second or two. A secret created without `--topics` still reaches botd within the cache time; the ops guide shows `--topics` on create and `--add-topics` for existing secrets.
- One open HTTPS request to Pub/Sub most of the time, and one more request per message batch. Pub/Sub bills by message volume, which for secrets is tiny.
- Setup needs a topic, Secret Manager's service agent as its publisher, the topic on each of SuperBot's secrets, and a subscription per botd that botd's service account may pull from: [docs/ops/cloud-secrets.md](../ops/cloud-secrets.md#following-secret-managers-change-events).
- The code that applies changes, its queue and the stream's state moved from `vault/events.rs` to `secrets/changes.rs`, shared by both backends; Vault's behaviour is unchanged.
- Tested against the stand-in Google in `server/src/secrets/gcp/events.rs`, with a stand-in subscription that can refuse pulls or acknowledgements, hold pulls past botd's wait, or answer `testIamPermissions` as a missing subscription, a missing role or a disabled API:
  - Which messages count: each change type, new types, users' folders on and off, rotation reminders and test messages, other prefixes, folders, locations, reserved names and malformed names; and a pull's answer checked before anything is acknowledged.
  - End to end: a rotation lands with a cache time of an hour, one read for the change and none for ignored messages, every message acknowledged, a deletion and a user's folder applied, a refused token signed in again without a loss, audited without values.
  - Losses: a failing pull and a failing acknowledgement each count once, with botd's reason, and once pulls work everything cached is read again and a change made meanwhile lands; Pub/Sub out of reach the same. A pull held past botd's wait is no loss.
  - Startup refused for each of the three, never quoting Google; off by default; the setting and endpoint checked, and the endpoint listed only while events are on.
- Ideas for later, each for an issue of its own: Azure Event Grid and AWS EventBridge (both push, so they need botd reachable or a queue in between, such as Event Grid to a Storage queue or EventBridge to SQS, which botd could pull the same way), and a refresh button in the console.
