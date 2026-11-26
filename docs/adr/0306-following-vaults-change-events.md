# 0306: Following Vault's change events

## Status

Accepted (26 Nov 2026). Part of secrets vault integration in M5, [#55](https://github.com/CG-Labs/superbot/issues/55). Builds on the HashiCorp Vault provider ([ADR 0125](0125-external-secrets-backend-vault.md)) and the cache refresh of [ADR 0291](0291-refreshing-the-external-secrets-cache.md), which left "refreshes driven by the stores' own change events" for later.

Numbered 0306 because it is the number reserved for this slice; 0307 to 0310 are held by parallel work.

## Context

botd caches each answer from the external store for `SECRETS_CACHE_SECONDS` (300 by default). A value rotated in Vault reaches new runs when the cache runs out, or at once if an admin runs `botctl secrets refresh` (ADR 0291). Both leave a person in the loop: either the wait, or remembering the command after every rotation. Rotations are often automatic (a pipeline, a Vault plugin, a scheduled job), with nobody to run the command, so the old value lives on in botd for up to the cache time after it was revoked at its provider.

Vault Enterprise (1.16 and later) and HCP Vault Dedicated publish event notifications. A client subscribes over a WebSocket, `sys/events/subscribe/<event type>`, and gets a JSON CloudEvent for each change it may see: for KV v2, `kv-v2/data-write`, `data-patch`, `data-delete`, `delete`, `undelete`, `destroy` and `metadata-*`, each with the secret's path and a `vault_index`. Vault's community edition dropped the endpoint in 1.16, and OpenBao has none.

Of the ideas ADR 0291 and ADR 0298 left, this one removes the most delay for the least new surface: it stays in the Vault provider and the cache, adds one opt-in setting, and changes nothing for anyone who doesn't set it. The same for the clouds (Event Grid for Key Vault, Pub/Sub for Secret Manager, EventBridge for Secrets Manager) needs an endpoint on botd that each cloud can reach and that checks each cloud's signatures. That is a different design and stays for later.

## Options

1. **A shorter cache.** Every name is read that much more often, all the time, to catch a change that happens rarely; and a backend outage then fails runs sooner.
2. **Poll KV v2 metadata** for each name's `current_version`. Still one request per name per interval, and no faster than option 1 for the same load.
3. **Vault Agent templates or a sidecar** that writes files and signals botd. Another process per server; and botd reads Vault itself (ADR 0125).
4. **Subscribe to Vault's events, and read a name again when it changes.** Chosen. One open connection, no polling, a change lands in about a second, and the cache stays as the bound on staleness when an event is lost.

For the WebSocket client: a crate (`tokio-tungstenite`) would be a new dependency tree for one read-mostly stream. botd needs only the client side of RFC 6455's framing: a handshake over reqwest's upgraded connection (reqwest is already botd's HTTP client, with Vault's CA and no redirects), reading text, ping and close frames, and writing masked pings, pongs and a close. That is a few hundred lines with tests against RFC 6455's own examples, so it is written here.

## Decision

### Configuration

| Setting | Default | Meaning |
|---------|---------|---------|
| `VAULT_EVENTS` | `0` | `1`: follow Vault's change events (Vault Enterprise 1.16+, HCP Vault Dedicated) |

Only `SECRETS_BACKEND=vault` reads it; it is listed among the settings warned about with another backend. Anything but `1`, `0` or empty stops botd.

### Subscribing

botd subscribes to `sys/events/subscribe/kv-v2/*?json=true` in `VAULT_NAMESPACE`, with the token it reads with, right after its startup check of the folders. **botd doesn't start if Vault won't take the subscription**: an operator who turned this on should learn at once that it isn't working, not after a rotation is missed. The error says why: a 404 or 405 (the community edition, OpenBao or an old Vault), a 403 (the policy), a redirect (a standby that doesn't take subscriptions; point `VAULT_ADDR` at the active node or a performance standby), or the status. A 403 is tried once more with a new token, as for reads. The handshake's `Sec-WebSocket-Accept` must match, or it isn't a stream.

botd's policy needs `read` on `sys/events/subscribe/kv-v2/*`, and `list` and `subscribe`, with `subscribe_event_types`, on its folders' paths: `data/`, `metadata/`, and `delete/`, `undelete/` and `destroy/` for those events. The guide gives the stanzas.

### Following the stream

- **Which events.** Every KV v2 event is subscribed to, and only those for botd's own names are used: in `VAULT_KV_MOUNT` (by the event's `mount_path` or the path's first part), in the namespace, under `VAULT_KV_PREFIX`, in `bots/` or `server/`, or `users/<id>/` when `SECRETS_USER_FOLDERS=1`, and a name that folder holds (ADR 0174's rules: a shared name only in its own folder, a user's only names a user may save). Nested paths, reserved names and other mounts, prefixes and namespaces are ignored, and botd sends no request for them.
- **Reading again.** For each change botd reads the name again, on the thread that applies changes, one at a time, with `X-Vault-Index` set to the event's `vault_index`, so a performance standby that hasn't caught up with the write can't answer with the value from before it. The answer replaces what was cached exactly as a read does: cached, redacted, audited as `secret.read`, and an error leaves nothing cached for the name, so runs that need it are refused until Vault answers (fail closed). Like a refresh, it moves ADR 0291's epoch before it reads, so a read already in flight can't cache over it, and again as it caches its answer, so a read that began meanwhile (perhaps from a standby without the index) can't either. A change and a refresh never overlap: each waits for the other. The folder is listed again at once, at the same index, so a new or removed name shows straight away and a lagging standby can't cache a list from before the change. Changes are read in the order they came; a name changed again before it is read waits once, so a busy name can't hold up the rest. Each is read, and its folder listed, at the newest index seen so far, so no read asks for less than a change already applied. More than 1,024 names waiting make way for one read of everything cached, so the queue stays bounded; that read, and its lists, ask for the newest dropped change's `vault_index`, which covers the changes before it, as Vault sends events in order.
- **Names botd read at startup** (Stripe, Linode, Incus, ...) still need a restart. A change to one is logged as a warning and audited with `restart`, as a refresh flags it.
- **Audit.** Each change is `secret.cache_refreshed` by `system`/`secrets` against the name, with `trigger: vault-event`, the event type, and the refresh's details (the result: `changed`, `removed`, `added`, `unavailable`, ...; `restart`), never a value or digest.

### Staying subscribed

- **Pings.** botd pings every 30 s; any frame it sends must go out within 10 s, or the stream is lost. A stream whose server answered a ping once and then hasn't answered for 75 s is lost. A server that never answers is left alone: Vault answers pings, but botd doesn't depend on it.
- **New tokens.** Vault checks a subscription's token and policy as events come, so a stream on an expired token can go quiet rather than close. botd therefore subscribes again before the token it subscribed with is due: when botd would log in again (two thirds of the way through the login's lease), two thirds of the way through a given token's TTL (`lookup-self`), as soon as botd's token changes for any reason (Vault refused it, or Vault Agent wrote a new one to `VAULT_TOKEN_FILE`, which botd reads at each ping), and at least hourly; never sooner than 10 s. A timer of its own fires at that time, not the next ping. The new subscription is open before the old one is closed, and the old one is read until Vault closes it (2 s at most, the close included), so no event falls between them. If the new one fails, the old one is kept and botd tries again shortly. When the old token may have stopped events before the new subscription opened (botd's token changed, a renewal failed, a lease is shorter than 15 s, or the new subscription opened only after the old token's lease or TTL ran out, as with a slow login or a slow Vault), every cached answer is read again once it is open, as after a gap.
- **Gaps.** A stream that closes, breaks or stops answering is subscribed again, waiting 1 s and then twice as long each time up to a minute. Events may have been missed meanwhile, so once it is back botd reads every cached answer again (`ExternalStore::refresh`, waiting for an admin's refresh that is already running). Until then the cache time still bounds an answer's age. Losing the stream after startup never stops botd or its runs: the stream only makes answers fresher, and the cache rules ADR 0125 set are unchanged without it.
- **Audit.** `secret.vault_events` against Vault's address: `subscribed` at startup, `lost` (a failure, with botd's own reason, never Vault's text) and `resumed`; and the read after a gap as `secret.cache_refreshed` with `trigger: vault-events-resumed`.

### Where it runs

The stream runs on the Vault client's own runtime (`http::Worker`), outside its request permits, so it never takes a slot from reads. Applying a change to the cache blocks (a refresh reads everything), so that runs on a thread of its own, which the stream hands each change to. Both stop when the store does. The `Provider` trait gains `watch`, a no-op for the other backends.

## Consequences

- No change unless `VAULT_EVENTS=1` is set.
- With it, a value written, patched, deleted or destroyed in Vault reaches new Bot runs in about a second, with no command and whatever `SECRETS_CACHE_SECONDS` is. A longer cache time then costs little in freshness and rides out longer outages.
- Needs Vault Enterprise 1.16 or later, or HCP Vault Dedicated, and a policy with `subscribe`. On the community edition or OpenBao, botd refuses to start with it on and says so.
- Running Bots keep the environment they started with, as with a refresh. Short-lived credentials for each run aren't cached, so events don't touch them.
- One more connection to Vault per botd, kept open. A WebSocket needs HTTP/1.1 end to end: a proxy or load balancer in front of Vault must pass upgrades and allow long-lived connections.
- Threat model: events carry paths, never values, and Vault sends a subscriber only events its policy covers. botd uses an event only to decide what to read; the value still comes from an ordinary authenticated read. A forged or replayed event at worst makes botd read a name early.
- Tested against the stand-in Vault in `server/src/secrets/vault.rs`, which now serves the WebSocket stream, in `server/src/secrets/vault/events.rs`:
  - Framing against RFC 6455's examples: the accept key, masked and unmasked frames, 16- and 64-bit lengths, a fragmented message with a ping between its parts, and refusals of masked server frames, unmasked client frames, reserved bits, oversized and fragmented control frames, out-of-order frames, messages over 1 MiB and bad UTF-8.
  - Which events count: each KV v2 operation, absolute and mount-relative paths, users' folders only when on, and other prefixes, folders, nested paths, reserved names, mounts, namespaces and event types ignored; an index that couldn't be a header is dropped.
  - End to end: a rotation, a delete and a startup setting's change landing with an hour's cache, each read at the event's index and audited with no value; events for names botd doesn't read sending no request; a stream Vault closes while subscribing fails, then a dropped connection, then a server that stops answering pings, each lost, resumed and every cached answer read again; a new subscription for each new AppRole token, the old one closed after it, with no gap; a new token in `VAULT_TOKEN_FILE` and a renewal Vault refused at first each followed by reading everything again; a change's read never caching over a read in flight or a refresh begun meanwhile; startup refused for 404, 403, a redirect and 500, a refused token replaced from its file, and the setting checked.
  - No Vault Enterprise, cloud or network. The handshake and framing follow RFC 6455 and Vault's documented API; they have not been run against a real Vault Enterprise here.
- Ideas for later, each for an issue of its own: change events from Azure Event Grid, Google Pub/Sub and AWS EventBridge for the other backends, a refresh button in the console, and the stream's state in `botctl secrets backend` and `/metrics`.
- Ops guide: [docs/ops/vault.md](../ops/vault.md#following-vaults-change-events).
