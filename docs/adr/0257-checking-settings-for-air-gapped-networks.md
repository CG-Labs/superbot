# 0257: Checking botd's settings for an air-gapped network

## Status

Accepted (24 Nov 2026). Twelfth slice of [#59](https://github.com/CG-Labs/superbot/issues/59) (M5, "Air-gapped self-host"). Builds on the offline install ([ADR 0128](0128-air-gapped-self-host.md)) and the bundles machines install from ([ADR 0210](0210-hermes-agent-on-air-gapped-machines.md), [ADR 0242](0242-harness-bundle-on-air-gapped-machines.md)).

0257 was reserved for this work.

## Context

The bundles, the release check and the installer get botd into a network with no internet. What botd then reaches is decided by `.env`, and many of its defaults are on the internet: Incus fetches images from `images.linuxcontainers.org`, an Entra or GitHub SSO provider defaults to Microsoft's or GitHub's hosts, machines fetch Node.js and npm packages unless given a bundle or mirror, and switches like `BILLING`, `PUSH_PROVIDER=expo` and Turnstile call public services. The guide's table says what to do for each, but nothing read an operator's settings and said which of them still reach out. The guide didn't mention `INCUS_IMAGE_SERVER` at all. An operator found out inside the network, when a Bot, a sign-in or a backup failed.

## Decision

### `botd offline check`

A subcommand, like `botd support check` and `botd harness pins`, that needs no running server:

```sh
botd offline check [--internal <suffix or range>,...] [--json] [--home <dir> | --env-file <file>]
```

It reads botd's settings the way `botd support check` does: the env file (`--home`'s `superbot/.env`, or `--env-file`) over the process environment. It parses each feature with botd's own code where there is some (`Sso::from_vars`, `Tiers::from_env`, `billing_flag`), and uses botd's own default addresses (`linode::API_URL`, `incus::DEFAULT_IMAGE_SERVER`, `mirror::NPM_REGISTRY`, `stripe::API`, `push::EXPO_URL`, `signups::TURNSTILE_VERIFY_URL`), so the check and botd can't disagree on a default. For each of 15 areas (sign-in, model providers, machines, harnesses on machines, billing, push, sign-up form, email, approval webhooks, backups, audit export, errors and traces, secrets manager, directory sync, license) it reports each address a setting names, or the default botd would use, as one of:

- `ok`: inside, or the feature is off. Inside means a private, loopback, link-local or shared (100.64/10) address, a unique-local or link-local IPv6 address, `localhost`, a single-label name, a name under a common internal suffix (`.internal`, `.local`, `.lan`, `.home.arpa`, `.corp`, `.intranet`, `.private`), or a suffix or range given with `--internal`.
- `internet`: a host under a service that is only on the internet (Stripe, Expo, Cloudflare, Linode, linuxcontainers.org, npm, Node.js, GitHub, Google, Microsoft Entra, Apple, Okta, Auth0, OneLogin, Anthropic, OpenAI, OpenRouter, Sentry, Datadog, Honeycomb, Grafana Cloud, Splunk Cloud, New Relic, Slack, Discord, public time-stamp authorities). Each line says what to change.
- `check`: anything botd can't place from the name: a public address, an unknown name, or AWS, Azure or Google Cloud, which a network can reach through a private endpoint. The line suggests the `--internal` to add if it is inside.

It exits 1 while anything is `internet` (or the settings can't be read), else 0, and 2 for a usage error. `--json` gives the same findings with a format number. A setting's userinfo (a DSN's key, an S3 URL's password) is never printed: only hosts.

### No connections, no lookups

The check opens no socket and resolves no name. Inside an air-gapped network a lookup of a public name may hang or be logged as an attempt, and a connected network's answer says nothing about the network it will run in. So it judges names and addresses only, and says `check` when that isn't enough.

### The installer runs it

`install.sh --offline` runs it at the end of an install (with `env -i`, so only `.env` counts, as for the service) and prints what it found: a clean line, the `check` lines, or a warning with the `internet` lines and the command to run again with `--internal`. It warns and doesn't stop: the operator may be installing on a connected staging host first, and a first install's `.env` has nothing on the internet anyway.

### Considered

- **Probe each address.** It would catch the unknowns, but means connections from inside the network, timeouts per address, and an answer that depends on where it runs. A separate, explicit probe could come later.
- **Refuse to start botd with internet settings when marked air-gapped.** A new mode switch that would have to know every feature's escape hatch, and break servers that reach one service, such as a cloud IdP, on purpose. A report the operator acts on is enough.
- **A list of allowed hosts instead of the internet list.** Every unknown host would be `internet`, so a correct internal setup under an unusual name would fail until listed. `check` with a suggested `--internal` says the same without claiming more than botd knows.
- **Put it in `botd support check`.** That report is for support and runs on any server. This one is for one deployment shape, with its own exit status the installer acts on.

## Consequences

- Operators see, before cutting a server off and after each change to `.env`, which settings still reach the internet and what to change.
- The guide has a section on the check, and says where Incus images come from.
- Each new feature that calls out needs a line in the check, or it is missed. The tests list every area, and the guide's table must name each.
- Tested:
  - Rust: addresses placed from the address alone (private, loopback, link-local, shared, IPv4-mapped IPv6, internal suffixes, the internet list, cloud services, near-misses like `notstripe.com`); `--internal` suffixes, ranges and bad values; hosts read from URLs and bare names, never with their userinfo. A fresh install reaches nothing and asks where models are. A connected server's defaults (billing, Expo, Turnstile, Linode, npm and Node.js for machines, Hermes's installer, vendor logins, Anthropic, Entra, GitHub, Google, Sentry, directory sync) are each `internet`, with no secret repeated. A server set up as the guide says (Incus with local images, both bundles, internal SSO, model endpoint, SMTP, webhooks, MinIO backups, audit export, time-stamp authority, traces and Vault) has nothing `internet` or `check`. Incus's default image server, the managed tiers' harnesses when none are named, tiers routes to Hermes's own providers, SSO metadata URLs, cloud secrets managers, and switches that are off. The report's order, counts, text and JSON; the CLI's exit codes; and that the guide's section names every area.
  - Shell (`deploy/test-offline.sh`, with a stand-in botd): the installer's summary says nothing reaches the internet, lists `check` lines, warns with the `internet` lines and the command to run again, says when the check couldn't run, passes botd no environment, and skips the check on online installs. The dry run says it would run it.
  - CI (`offline.yml` `install-offline`): the real install with no network says nothing reaches the internet, and the real botd flags `BILLING=on` as Stripe and an SMTP relay on a private address as inside.
- Not covered:
  - Secrets saved with `botctl secret set` or in a secrets manager aren't read, so a Linode token or error-report DSN kept there isn't seen.
  - A Bot's own Codex or Pi configuration on its machine.
  - Hosts an OIDC provider's discovery document names besides its issuer.
