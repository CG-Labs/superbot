# 0266: Checking the running server for an air-gapped network

## Status

Accepted (25 Nov 2026). Thirteenth slice of [#59](https://github.com/CG-Labs/superbot/issues/59) (M5, "Air-gapped self-host"). Builds on the settings check ([ADR 0257](0257-checking-settings-for-air-gapped-networks.md)).

0266 was reserved for this work.

## Context

`botd offline check` (ADR 0257) reads `.env` and says which settings still reach the internet. It runs with no server, so it can't see three things botd reads at run time, and ADR 0257 listed them as not covered:

- Secrets saved with `botctl secret set` or the console (sealed in the database), or kept in a secrets manager. A Linode token, error-report DSN, approval webhook, a Bot's own webhook or `ANTHROPIC_BASE_URL` kept there wasn't seen. Even a setting's `_FILE` wasn't read.
- Native SAML metadata saved with `botctl sso saml <id> import`, which is in the database. The check said `check` for it.
- The hosts an OIDC provider's discovery document names besides its issuer: the authorization and token endpoints and the signing keys. An internal issuer can name a token endpoint on the internet.

So an operator with a clean `botd offline check` could still find out inside the network that an approval webhook went to Slack, or that sign-in failed at a cloud token endpoint.

## Decision

### `botctl offline check`, on the running server

```sh
botctl offline check [--internal <suffix or range>,...] [--json]
```

It calls `GET /api/offline-check[?internal=...]`. The server runs ADR 0257's judge, with the same 15 areas, words and exit rule, over what the running botd uses:

- **Its environment**, which systemd loads from `.env`.
- **Its secrets.** Each setting botd reads through its secrets (`LINODE_TOKEN`, `ERROR_REPORT_DSN`, `NOTIFY_WEBHOOK_URL`, the Anthropic settings, and each Bot's `NOTIFY_WEBHOOK_URL_BOT_*`) is filled in from where botd finds it: its `_FILE`, the sealed store or the secrets manager. The environment wins, as in botd. Each line names where the value came from, such as `NOTIFY_WEBHOOK_URL (saved in botd)`. Only hosts are shown, and the filled values are wiped after judging. A store that doesn't answer gives one `check` line naming the settings it couldn't read and why, not one per setting. A setting set both as `NAME` and `NAME_FILE` is that `check` line too, since botd refuses it, rather than judged.
- **What botd read at start.** `LINODE_TOKEN` and `ERROR_REPORT_DSN` are read once, at start, from the environment (or `_FILE`) and the secrets manager, never the sealed store. botd records what it read then, and the check judges that, since it is what botd still uses. If the value is different now, or is only saved in botd where start never looks, that is a `check` line saying to restart botd or move it.
- **Its SSO providers as loaded**, including native SAML metadata saved with botctl. A saved provider with no metadata imported yet is `check`, with the import command.
- **Each OIDC provider's discovery document**, read through sign-in's own cache, so it costs no extra request when sign-in fetched it recently. Its authorization endpoint, token endpoint and signing keys are judged like any other address. A document that doesn't load is `check`. It is fetched only when the issuer is not already on the internet, so the check never calls out from a network it is about to cut off.

The output is ADR 0257's text and JSON (format 1). The JSON adds `"from"` to a finding filled from a secret, and `settings.running: true`. botctl prints the text, or the JSON with `--json`, and exits 1 while anything is `internet`.

The route is admin-only, like the rest of the server's setup, and each run is audited as `offline.checked` with the counts, the `internal` list, the names of the settings on the internet and where filled values came from. The audit record never holds a value. A bad `internal` or an unknown parameter is a 400 and isn't recorded.

### The settings check reads `_FILE`s

`botd offline check` now reads the `_FILE` of the same settings, so a DSN kept in a file is judged with no server. Its output ends by pointing at `botctl offline check` for what only the running server can read.

### Considered

- **Give `botd offline check` the database and the secrets manager.** It would need the master key and the manager's credentials on the command line, and read a live database from a second process. The server already holds both.
- **Add the secrets to the health check or support check.** Those reports run on every server. This one is for one deployment shape, with its own exit status.
- **Probe each address.** As in ADR 0257, connections from inside the network say nothing certain. Only the discovery document is fetched, because botd fetches it anyway to sign people in.
- **Show each secret's value with its host.** A webhook URL is a credential. Hosts are enough to act on.

## Consequences

- An operator can check the server they are about to cut off as it runs, including what the console saved, and run it again after each change.
- The server check and the settings check share the judge, so a new area or rule applies to both.
- Tested:
  - Rust: saved values judged where they point and labelled by source (a sealed Bot webhook, a DSN from its `_FILE`, an Anthropic base URL), with the environment winning and no value in the text or JSON. A Bot webhook in a `_FILE` alone, and a setting set as both `NAME` and `NAME_FILE`, which is refused, not judged. A DSN changed since start is judged as botd read it, with a line to restart, and a token saved only in botd is said to be unused. A secrets manager that doesn't answer gives one `check` line and the environment's value is still used. Saved SAML metadata read from the loaded provider, a saved provider with nothing imported, discovery endpoints judged from a stand-in IdP (a token endpoint at Entra's host is `internet`), a discovery document that doesn't load, and an internet issuer not fetched. The settings check reads `_FILE`s, says when one can't be read, and points at the running check.
  - HTTP: only admins run it (members, custom roles and Bots are refused); each run is audited; bad parameters are refused and not recorded; a Bot webhook saved from the console is `internet` at Slack, named with its source, and its URL is never shown.
  - botctl: the request it builds from `--internal` and `--json`, and bad arguments.
- Not covered:
  - A user's own secrets and a Bot's own Codex or Pi configuration on its machine.
  - A discovery document for an issuer that is already `internet`: fixing the issuer comes first.
  - Settings a store can't read when the check runs, which are listed as `check`.
