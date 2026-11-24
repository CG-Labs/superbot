# 0237: Audit export to Google SecOps

## Status

Accepted (24 Nov 2026). Twelfth slice of [#56](https://github.com/CG-Labs/superbot/issues/56) in M5. Builds on the SIEM export ([ADR 0122](0122-siem-export-and-tamper-evident-audit.md)), several SIEMs with their own settings ([ADR 0191](0191-several-siems-with-their-own-headers.md)), self-checking lines ([ADR 0199](0199-self-checking-audit-lines.md)), the Azure Monitor sink ([ADR 0217](0217-audit-export-to-azure-monitor.md)), gzip ([ADR 0227](0227-gzip-for-the-audit-export.md)) and botd's Google sign-in for Secret Manager ([ADR 0136](0136-cloud-secret-managers.md)).

## Context

#56 asks for audit events streamed to SIEMs with tamper evidence. After ADR 0217, botd sends to HTTPS webhooks, syslog over TLS and Microsoft Sentinel. Google Security Operations (SecOps, formerly Chronicle), the SIEM our Google Cloud customers run, takes none of them directly:

1. **Its ingestion API needs short-lived tokens.** The supported way in is the Chronicle API's `logs:import`, called with an OAuth bearer token for the `cloud-platform` scope that lasts about an hour, so a static `Authorization` header stops working within the hour. The legacy Ingestion API, which took a long-lived key, is deprecated (it ends in July 2027).
2. **Its body is its own.** `logs:import` takes `{"inlineSource":{"logs":[...]}}`, each log's bytes base64 in `data`, with `logEntryTime` and a `collectionTime` that must be after it. At most 4 MB a request, uncompressed; Google suggests about 2 MB. It isn't JSON lines.
3. **It is regional.** Each instance answers only at its region's endpoint, `https://<location>-chronicle.googleapis.com`, under `projects/<project>/locations/<location>/instances/<customer id>/logTypes/<log type>`.
4. **The workaround is another agent.** Today a customer runs Bindplane or a SecOps forwarder beside botd, or a webhook feed with an API key. That is one more thing to secure and keep up, and a feed key is another long-lived secret.

Constraints: harness-agnostic and Rust only; no new dependencies; no secret in the URL or in events; the same delivery guarantees as the other sinks (in order, at least once, its own cursor, retention held); a Google token must never go to a host that isn't the instance's endpoint.

## Options

**How to reach SecOps**

1. **Document a forwarder** (Bindplane, the SecOps forwarder, a webhook feed). No code, but the problems above stay.
2. **A native sink** using `logs:import`, signing in as botd's own Google identity.

**How botd signs in**

1. **A service account key per sink.** Another long-lived secret to rotate.
2. **botd's Google identity**, the one Secret Manager uses: the metadata server's service account on Google Cloud (no secret), or a service account key where that isn't there. The sign-in code is shared rather than copied.

**What a log holds**

1. **UDM events** through `events:import`. Typed and searchable, but botd would map every action to UDM itself, and the copy could no longer check itself.
2. **The line exactly, as a raw log** of a log type the customer makes. Checks itself; searching it by field needs raw log search or a parser.

**How the sink is named**

1. **An `https://` URL** of the import endpoint, recognised by its host. Long, and easy to get the region wrong in one of its two places.
2. **Its own scheme**, `google-secops://<location>/<project>/<instance>/<log type>`, from which botd builds the endpoint and path.

## Decision

Option 2, then 2, 2 and 2.

- **The sink.** `AUDIT_EXPORT=google-secops://<location>/<project>/<instance>/<log type>`, named or not, in any place in the list. It is one of the up to four SIEMs (ADR 0191), with its own cursor (by location, project, instance and log type), retries, start, status (`googleSecOps` in `botctl audit siem`), failure events and metrics (`kind="google-secops"`). Headers aren't taken, and neither is gzip: Google doesn't document compressed bodies for `logs:import`, so `AUDIT_EXPORT_COMPRESS_<NAME>=gzip` for it stops botd, and the server-wide `AUDIT_EXPORT_COMPRESS=gzip` leaves it plain.
- **Checked at startup.** The location is lowercase letters, digits and inner `-`, starting with a letter (`us`, `eu`, `europe-west2`); the project a Google Cloud project id or number; the instance a UUID (lowercased); the log type capitals, digits and `_`, starting with a letter. No credentials, port, query or fragment. Requests go only to `https://<location>-chronicle.googleapis.com`, built from the location, so a token can't be sent elsewhere.
- **Signing in.** `AUDIT_EXPORT_GCP_AUTH` is `metadata` (the default) or `service-account-key`, read with the same `GCE_METADATA_HOST` and `GCP_SERVICE_ACCOUNT_KEY` (or `_FILE`) as Secret Manager. Unset, it takes `GCP_SECRET_MANAGER_AUTH`, so botd is one identity. `secrets::gcp::Google` now holds the sign-in both use: the metadata server's token, or a JWT signed with the key and exchanged at its `token_uri`, for the `cloud-platform` scope, kept while it is fresh. When Google answers 401, botd gets a new token and tries once more; only a second 401 counts as a failure. The token in use is redacted everywhere, held rather than registered (as in ADR 0217), since the metadata server hands out the same token until near its end. The identity needs `chronicle.logs.import` on the project: a custom role with only that, or Chronicle API Editor.
- **Logs.** Each event is one raw log: `data` is the JSON line exactly as every other sink gets it, base64; `logEntryTime` is the event's time; `collectionTime` is when botd sent it, at least a millisecond after the event, as the API requires. No labels or namespace. The customer makes a custom log type for it; botd ships no UDM parser.
- **Requests.** `POST <endpoint>/v1/projects/<project>/locations/<location>/instances/<instance>/logTypes/<log type>/logs:import`, `Content-Type: application/json`. A batch (up to 200 events) is split into bodies of at most 2 MB, sent in order; a log too big for that goes alone, still under the 4 MB a log. Any failure fails the batch, which is sent again whole. A 409 `ALREADY_EXISTS` counts as taken, since SecOps keeps what it already has; a retry can still repeat events, as at-least-once delivery always could, so de-duplicate on `host` and `id`. A 429 waits at least 30 seconds, as Google asks, or `Retry-After` up to 5 minutes, before the usual backoff. Errors carry Google's status name (such as `PERMISSION_DENIED`), never its message (which may quote the request), and a hint for 400, 401, 403, 404, 413 and 429. A failed sign-in is its own reason, `sign_in_failed`, beside `delivery_failed`.
- **Checking the copy.** Each raw log is the line byte for byte, so raw logs taken back out (the Data Export API writes them to a bucket the customer owns) go into `botctl audit verify-lines` one per line, and `chainHash` gives pins for `botctl audit verify --pin`.

## Consequences

- SecOps customers send audit events straight from botd, with no forwarder, no extra secret on Google Cloud, and the same identity as Secret Manager.
- The copy in SecOps checks itself, line by line and as a chain, like the archive and other SIEMs.
- Without a parser the events are raw logs: raw log search finds them by any field, but detections over UDM fields need a parser the customer writes. Shipping one is follow-up work.
- Secret Manager now signs in through the same functions as `secrets::gcp::Google`, with no change in behaviour; its tests pass unchanged.
- The chain and checks are unchanged; only where events go is new.
- Later, if asked: a UDM parser, labels and namespaces on each log, gzip if Google documents it, and Datadog's native API.
