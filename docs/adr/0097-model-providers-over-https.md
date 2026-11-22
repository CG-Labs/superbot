# 0097: Model providers reached only over HTTPS

## Status

Accepted (21 Nov 2026). Part of the SOC 2 readiness checklist of M4, [#50](https://github.com/CG-Labs/superbot/issues/50); closes checklist row CC6.7-1 in the [readiness checklist](../security/soc2-readiness-checklist.md). Amends [ADR 0077](0077-two-providers-through-tier-routing.md), whose tiers file took any `http(s)` base URL.

0096 is the highest number on `main`, and no open PR holds 0097.

## Context

A run sends the model provider the whole prompt (the user's messages, files the agent read, tool output) and the provider's API key. Over plain `http://` both cross the network unencrypted, readable and changeable by anyone on the path.

Where SuperBot itself picks a provider's URL, read from the code:

- **The tiers file's `providers`** ([ADR 0077](0077-two-providers-through-tier-routing.md), `server/src/tiers.rs`). Each `baseUrl` goes to Hermes as a named endpoint, with the key. It accepted `http` and `https`.
- **`SUPERBOT_HERMES_BASE_URL`** (`server/src/adapters/hermes.rs`). The server-wide endpoint for Hermes runs not routed to a tier endpoint, passed as `--base-url`. It was not checked at all.
- **Built-in providers** (a route's `openrouter`, or `SUPERBOT_HERMES_PROVIDER`) use Hermes's own URLs, which are HTTPS.
- Nothing else in botd calls a model provider. Claude Code, Codex and Pi reach theirs with their own settings: their own defaults (HTTPS), and settings the operator or user writes in the harness's own terms (`ANTHROPIC_BASE_URL` in `.env` or a saved secret, a Bot's `~/.codex/config.toml`, Pi's `models.json`, a Bot's own Hermes `config.yaml` on an open tier). botd passes those through without reading them.

## Decision

### HTTPS, or loopback

A model provider URL that SuperBot sets must be `https://`, or `http://` to this computer. Loopback is:

- an IPv4 address in `127.0.0.0/8`;
- the IPv6 address `::1`;
- the name `localhost`, in any case.

Nothing else counts, so the check needs no DNS lookup and can't be fooled by one:

- Another name is refused even if it resolves to `127.0.0.1` today (`localhost.evil.example`, `127.0.0.1.evil.example`, `localhost.`).
- Private addresses (`10.0.0.0/8`, `192.168.0.0/16`, `fd00::/8`, ...) are refused. A LAN is still a network, and the control is about the wire, not who owns it.
- `0.0.0.0`, `::` and IPv4-mapped IPv6 (`::ffff:127.0.0.1`) are refused.
- The host is read by the WHATWG URL parser, as Hermes and every HTTP client would read it, so `http://2130706433` and `http://0x7f.0.0.1` are `127.0.0.1` and allowed.
- A user or password in the URL was already refused for every scheme. That also stops `http://127.0.0.1@evil.example`, whose host is `evil.example`.

Local model servers (Ollama, vLLM, llama.cpp on the same host) keep working over `http://127.0.0.1`. A model server elsewhere needs TLS in front of it, or a TLS tunnel that ends on this host (stunnel, an SSH forward, a sidecar proxy), which is then a loopback URL.

### Where it applies

- **The tiers file.** Each provider's `baseUrl`, when the file is read.
- **`SUPERBOT_HERMES_BASE_URL`.** Adapters gained `check_env`, which checks the server settings an adapter reads from botd's environment at startup. Hermes's checks this one. It must parse as an `http(s)` URL with a host and no user or password, and pass the same rule. Before, any string went to `--base-url`.

Both use one function, `tiers::encrypted_or_loopback`. The adapter owns the Hermes variable, so the harness-specific name stays in its adapter.

### On upgrade: refuse to start

A server whose tiers file or `SUPERBOT_HERMES_BASE_URL` has a plain `http://` URL outside loopback **refuses to start**, like any other mistake in that file. The error names the setting, the file, the provider and the URL, and says why and what is allowed:

```text
Tiers: TIERS_FILE /home/superbot/tiers.json: provider "lan-model": baseUrl "http://10.0.0.7:8000/v1" must use https://: plain http:// would send prompts and the API key unencrypted, so it is allowed only to this computer (localhost, 127.0.0.0/8, ::1) (ADR 0097)
```

The other choice was to warn and skip the provider. We rejected it:

- **It changes what users get, quietly.** A skipped provider that a route names refuses every run on that route, or, as a fallback, drops out of the chain. Users would see failed or different runs while botd looks healthy, and a startup warning is easy to miss.
- **It fails open where it matters.** The point of the control is that prompts and keys never go out in the clear. Refusing to start is the fail-closed choice, and it's what the file does for every other mistake (ADR 0077), so operators already expect it.
- **The fix is one line.** Change the URL to `https://`, or to a loopback tunnel, and restart. Nothing in the database depends on the old URL.
- **It is rare.** The shipped example and every guide use HTTPS. A plain `http://` provider outside loopback was already sending keys in the clear.

The same goes for `SUPERBOT_HERMES_BASE_URL`: Hermes would otherwise send every unrouted run's prompt and key in the clear.

## Tests

- **Unit tests** (`server/src/tiers.rs`, `server/src/adapters/hermes.rs`):
  - accepted: `https` (any case, private hosts too), `http` to `127.0.0.1`, any `127/8` address, `localhost` in any case, `[::1]` and its long form, and the parser's other spellings of `127.0.0.1`;
  - refused: `http` to a public name, to private IPv4 and IPv6 addresses, to `0.0.0.0`, `::`, the metadata address, IPv4-mapped loopback, and names that only start with `localhost` or `127.0.0.1`;
  - refused as userinfo: `http://127.0.0.1@evil.example`, `http://localhost:x@evil.example`, and the same over `https`;
  - the error from a file names the file, the provider and the URL;
  - `SUPERBOT_HERMES_BASE_URL`: the same rule, a malformed value refused, and only the URL's origin said in the error, never a path or password that might carry a token.
- **End to end** (`server/tests/provider_https_only.rs`). The real `botd`:
  - exits at startup on a tiers file with a public `http://` provider, and on one with a private-network one, saying which provider and file;
  - starts with `https`, `http://127.0.0.1`, `http://localhost` and `http://[::1]` providers;
  - exits on a public `http://` `SUPERBOT_HERMES_BASE_URL`, and starts with a loopback one.

## Known limits

- **Harnesses' own settings aren't checked.** A URL the operator or a user gives a harness in its own terms (`ANTHROPIC_BASE_URL`, a Bot's Codex or Pi config, a Bot's own Hermes config on an open tier) is the harness's to use, and botd doesn't parse them. They are the operator's or user's own choice of endpoint, not one SuperBot picked. On a managed tier, Hermes's endpoint fields are pinned by botd's managed config ([ADR 0077](0077-two-providers-through-tier-routing.md)), so a Bot can't point a tier route elsewhere.
- **Certificates are the harness's.** HTTPS is verified by the harness's HTTP client, with the system's trust store. botd doesn't pin provider certificates.
- **Redirects.** A provider that redirects `https` to `http` is the harness client's to refuse. botd never contacts the provider itself.

## Consequences

- Prompts and keys to a provider SuperBot configures are encrypted on the wire, or never leave the host. CC6.7's model-provider gap is closed.
- A server with a plain `http://` remote provider stops at upgrade until the URL is fixed. The error says how.
- Adapters have a place to check their own server settings at startup (`check_env`).
