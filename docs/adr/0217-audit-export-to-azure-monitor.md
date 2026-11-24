# 0217: Audit export to Azure Monitor, for Microsoft Sentinel

## Status

Accepted (24 Nov 2026). Tenth slice of [#56](https://github.com/CG-Labs/superbot/issues/56) in M5. Builds on the SIEM export ([ADR 0122](0122-siem-export-and-tamper-evident-audit.md)), several SIEMs with their own settings ([ADR 0191](0191-several-siems-with-their-own-headers.md)), self-checking lines ([ADR 0199](0199-self-checking-audit-lines.md)) and botd's Entra ID sign-in for Key Vault ([ADR 0136](0136-cloud-secret-managers.md), [ADR 0213](0213-entra-app-tokens-for-each-run.md)).

## Context

#56 asks for audit events streamed to SIEMs with tamper evidence. botd sends JSON lines over HTTPS with static headers, or syslog over TLS. Microsoft Sentinel, the SIEM most of our Entra ID customers already run, can take neither directly:

1. **Its ingestion API needs short-lived tokens.** Sentinel reads a Log Analytics workspace, and the supported way to write custom data there is Azure Monitor's Logs Ingestion API. Each request needs an Entra ID bearer token for `https://monitor.azure.com`, which lasts about an hour. A static `Authorization` header stops working within the hour. The older HTTP Data Collector API, which took a shared key, is deprecated, and Microsoft's support for it ended in September 2026.
2. **Its body is a JSON array**, at most 1 MB a request, of records matching a data collection rule's (DCR) stream. It isn't JSON lines. Fields over 64 KB are cut, and `id`, `TenantId`, `Type`, `Title` and `UniqueId` are reserved column names, so the line's own `id` can't be a column.
3. **The workaround is another agent.** Today a customer runs rsyslog with the Azure Monitor Agent, or a Logstash pipeline, beside botd. That is one more thing to secure and keep up, and it parses and rewrites every line, so the copy in Sentinel no longer checks itself (ADR 0199).

Constraints: harness-agnostic and Rust only; no new dependencies; no secret in the URL or in events; the same delivery guarantees as the other sinks (in order, at least once, its own cursor, retention held); an Entra token must never go to a host that isn't Azure's.

## Options

**How to reach Sentinel**

1. **Document a collector** (Azure Monitor Agent, Logstash, Fluent Bit). No code, but the problems above stay.
2. **OAuth client credentials for any webhook.** Generic, but each SIEM's body differs (Sentinel's is an array of stream records), and botd would hold a client secret for an app per SIEM.
3. **A native Azure Monitor sink** using the Logs Ingestion API, signing in as botd's own Azure identity.

**How botd signs in**

1. **A client secret per sink.** Another long-lived secret to rotate.
2. **botd's Azure identity**, the one Key Vault uses: a managed identity on Azure (no secret), workload identity on AKS or anywhere with federation (no secret), or a service principal's client secret where neither applies.

**What a record holds**

1. **The line's fields as columns.** Good for queries, but the copy can't check itself: `id` must be renamed, and a dynamic `details` comes back re-serialised in another key order.
2. **The line whole, as one string column.** Checks itself, but every query needs `parse_json`.
3. **Both:** the line whole as `Line`, plus a fixed set of typed columns taken from it.

**How the sink is named**

1. **An `https://` URL** recognised by its host. Implicit, and the URL Azure shows carries `?api-version`, which `AUDIT_EXPORT` refuses.
2. **Its own scheme**, `azure-monitor://<ingestion host>/<DCR immutable id>/<stream>`.

## Decision

Option 3, then 2, 3 and 2.

- **The sink.** `AUDIT_EXPORT=azure-monitor://<host>/<dcr>/<stream>`, named or not, in any place in the list. It is one of the up to four SIEMs (ADR 0191), with its own cursor (by host, rule and stream), retries, start (`AUDIT_EXPORT_START_<NAME>`), status, failure events and metrics (`kind="azure-monitor"`). Headers aren't taken: `AUDIT_EXPORT_HEADERS` and `AUDIT_EXPORT_HEADERS_<NAME>` for it stop botd.
- **Checked at startup.** The host must end in `.monitor.azure.com`, `.monitor.azure.us` or `.monitor.azure.cn` (the DCR's own logs ingestion endpoint or a DCE's, private link included), on port 443. That suffix picks the token's audience, and tokens go nowhere else. The rule is `dcr-` and 32 hex digits; the stream is `Custom-<name>` or `Microsoft-<table>`. No credentials, query or fragment.
- **Signing in.** `AUDIT_EXPORT_AZURE_AUTH` is `managed-identity` (the default), `workload-identity` or `client-secret`, with the same `AZURE_CLIENT_ID`, `AZURE_TENANT_ID`, `AZURE_CLIENT_SECRET` (or `_FILE`), `AZURE_FEDERATED_TOKEN_FILE`, `AZURE_AUTHORITY_HOST` and `IDENTITY_ENDPOINT` settings as Key Vault. Unset, it takes `AZURE_KEYVAULT_AUTH`, so botd is one identity. The Key Vault backend's sign-in code is shared rather than copied: `secrets::azure::Entra` signs in for one resource and keeps the token until two thirds of its life. When Azure answers 401, botd gets a new token and tries once more; only a second 401 counts as a failure. The token in use is redacted everywhere, held rather than registered: it leaves the redaction list only once no sink holds it, so a refresh that returns the same token, or two sinks given one cached token, never unmask it. The identity needs the Monitoring Metrics Publisher role on the DCR.
- **Records.** Each event is `TimeGenerated` (its time), 17 typed columns (`EventId`, `Host`, `Action`, `Outcome`, `ActorKind`, `ActorId`, `ActorName`, `ActorEmail`, `ActorRole`, `AuthMethod`, `TargetType`, `TargetId`, `BotId`, `SourceIp`, `SessionId`, `Details`, `ChainHash`), `LinePart`, and `Line`, the JSON line exactly as every other sink gets it, with `LinePart` 0. The columns are read from that line, so they hold no more than it does (redactions and erasures included). The guide gives the stream declaration and table to create.
- **Long lines.** Azure cuts a field over 64 KB, and an `audit.erased` names every row it changed, so erasing a long-lived user can make a longer line. A line over 32,000 bytes goes as several records, `LinePart` 1 to n, each with the same typed columns but an empty `Details`, and each `Line` a piece: `{"schema":"superbot.audit.part.v1","id":..,"host":..,"part":1,"parts":n,"text":..}`, with at most 16,000 bytes of the line in `text` (under 64 KB however much JSON escaping adds). `botctl audit verify-lines` joins the pieces of each event in order, from any order and with copies, and checks the line they make; a missing piece, or two that disagree, is unreadable.
- **Requests.** `POST <host>/dataCollectionRules/<dcr>/streams/<stream>?api-version=2023-01-01`, `Content-Type: application/json`. A batch (up to 200 events) is split into arrays of at most 1 MB, sent in order; any failure fails the batch, which is sent again whole. Azure keeps arrays it already took, so a retry can repeat events, as at-least-once delivery always could: de-duplicate on `Host`, `EventId` and `LinePart`. A 429 waits for `Retry-After` (at most 5 minutes) before the usual backoff. Errors carry Azure's error code, never its message (which may quote the request), and a hint for 400, 401, 403, 404 and 413. A failed sign-in is its own reason, `sign_in_failed`, beside `delivery_failed`.
- **Checking the copy.** `Line` goes into `botctl audit verify-lines` unchanged, for example from `az monitor log-analytics query ... -o tsv`, and `ChainHash` gives pins for `botctl audit verify --pin`.

## Consequences

- Sentinel customers send audit events straight from botd, with no collector, no extra secret on Azure or AKS, and the same identity as Key Vault.
- The copy in the workspace checks itself, line by line and as a chain, like the archive and other SIEMs. The typed columns are for detections and are not what is checked.
- Each event is stored twice in the workspace (columns and `Line`), roughly doubling ingestion. That buys the self-check; a DCR transformation can drop columns a customer doesn't want.
- No line is cut: a long one arrives in pieces, so a query over `Line` alone sees pieces of it, not the event's JSON, until `verify-lines` (or a KQL join on `EventId` and `LinePart`) puts them together. Only `audit.erased` lines get that long; their typed columns are on every piece. An erasure also names its rows in `audit.erased` events of at most 1,000 id ranges each (under 43 KB), however scattered the rows are, so no line grows without bound for syslog and HTTPS SIEMs either; the check counts the rows named across all of them.
- The chain and checks are unchanged; only where events go is new.
- Later, if asked: gzip of request bodies (`Content-Encoding: gzip`, which the API takes) and of archive objects, and other SIEMs' native APIs (Google SecOps, Datadog) that also need tokens or their own bodies.
