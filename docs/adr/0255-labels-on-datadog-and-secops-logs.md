# 0255: Labels on Datadog and SecOps logs

## Status

Accepted (24 Nov 2026). Fourteenth slice of [#56](https://github.com/CG-Labs/superbot/issues/56) in M5. Builds on several SIEMs with their own settings ([ADR 0191](0191-several-siems-with-their-own-headers.md)), the Google SecOps sink ([ADR 0237](0237-audit-export-to-google-secops.md)) and the Datadog sink ([ADR 0245](0245-audit-export-to-datadog.md)), which left Datadog tags and SecOps labels and namespaces for later.

## Context

#56 asks for audit events streamed to SIEMs with tamper evidence. botd sends them straight to Datadog and Google SecOps, but a customer with more than one botd, or one botd per tenant or environment, can't tell them apart where they land except by `host`, and can't fence them off:

1. **Datadog routes and restricts by tags.** Index filters, archive filters, log restriction queries (who may read which logs) and usage attribution all match tags, such as `env:prod` or `team:security`. A log sent through the Logs API has tags only from its `ddtags` field; botd sends none.
2. **SecOps restricts by ingestion labels and namespaces.** Data RBAC scopes allow or deny data by log type, namespace and ingestion labels, and only labels marked eligible (`rbacEnabled`) at ingestion count. A namespace also keeps assets with overlapping IPs apart. `logs:import` takes both per log (`labels`, `environmentNamespace`); botd sends neither, so every botd's events fall in one scope.
3. **The line must stay as it is.** Each log carries the exported line exactly, which is what makes the copy check itself. Labels can't go inside it.

Constraints: harness-agnostic and Rust only; no new dependencies; no change to the line or the chain; same delivery guarantees; settings shaped like the existing per-sink ones (`AUDIT_EXPORT_COMPRESS` and `_<NAME>`).

## Options

**One setting or one per SIEM**

1. **Per SIEM**, `AUDIT_EXPORT_DATADOG_TAGS` and `AUDIT_EXPORT_SECOPS_LABELS`. Each in its own syntax, but two settings for one idea, and a customer sending to both writes the same thing twice.
2. **One**, `AUDIT_EXPORT_LABELS=key=value,...`, and `AUDIT_EXPORT_LABELS_<NAME>` for a named sink, which each sink turns into its own form.

**Which characters**

1. **Whatever each SIEM takes.** Datadog lowercases tags and turns most punctuation into `_`, so the same label would read differently in each.
2. **The safe common set**: lowercase letters, digits, `_` and `-` in keys (starting with a letter), and `_-.:/` too in values.

**Data RBAC eligibility**

1. **Never**, or per label with more syntax.
2. **Always**: eligibility restricts no one until a scope names the label, and an audit log is what scopes exist for.

**Sinks that send the line alone** (webhook, syslog, archive, Azure Monitor, whose columns are its DCR's)

1. **Ignore the setting** for them.
2. **Refuse it**: a named setting for one stops botd, and a server-wide one when no sink can use it.

## Decision

Option 2 each time.

- **Settings.** `AUDIT_EXPORT_LABELS` is up to 10 `key=value` pairs split by commas, for every Datadog and SecOps sink; `AUDIT_EXPORT_LABELS_<NAME>` is a named sink's own and wins, and `off` gives that sink none. Keys are 1 to 63 lowercase letters, digits, `_` and `-`, starting with a letter; `host`, `source`, `service` and `device` are refused (botd's own, or Datadog's reserved). Values are 1 to 128 lowercase letters, digits and `_-.:/`. A key given twice stops botd. `AUDIT_EXPORT_NAMESPACE` (and `_<NAME>`, `off`) is a SecOps namespace: 1 to 63 letters, digits, `_` and `-`, starting with a letter. Plain settings, not secrets: they are in every log.
- **Datadog.** Each log gets `ddtags`, the labels as `key:value` joined by commas, the same on every log and every piece of a long line. A namespace for a Datadog sink stops botd (use a label).
- **SecOps.** Each raw log gets `labels`, `{"<key>": {"value": "<value>", "rbacEnabled": true}}`, and `environmentNamespace` when set.
- **Refused elsewhere.** `AUDIT_EXPORT_LABELS_<NAME>` or `AUDIT_EXPORT_NAMESPACE_<NAME>` for a sink that can't carry it stops botd, naming why; so does the server-wide one when no sink can. While export is off they're ignored, like the other export settings.
- **Shown.** The startup line says `tagged env:prod,...` or `labelled env=prod,..., in namespace prod`; `botctl audit siem` shows `datadog.tags`, `googleSecOps.labels` and `googleSecOps.namespace`.
- **Not evidence.** Labels go beside the line, not in it or the chain, so `botctl audit verify-lines` neither needs nor checks them. They route and restrict; they prove nothing.

## Consequences

- Several botd servers, tenants or environments land apart in Datadog and SecOps, and access to them can be scoped with restriction queries or data RBAC.
- One setting serves both SIEMs, and reads the same in each.
- Labels cost a few bytes a log, in Datadog's ingested bytes too.
- Changing labels doesn't move a sink's cursor: events already sent keep their old labels.
- The line, the chain and every check are unchanged.
- Later, if asked: a UDM parser or `events:import` for SecOps, labels that differ by event (by action or team), and gzip for SecOps if Google documents it.
