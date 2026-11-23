# 0186: Harness installs on users' machines from mirrors inside an air-gapped network

## Status

Accepted (23 Nov 2026). Fifth slice of [#59](https://github.com/CG-Labs/superbot/issues/59) (M5, "Air-gapped self-host"). Builds on harness CLIs and agent upgrades on machines ([ADR 0039](0039-machine-harnesses-and-agent-upgrades.md)), the offline install ([ADR 0128](0128-air-gapped-self-host.md)) and every release's bundles checked end to end ([ADR 0172](0172-release-bundles-checked-end-to-end.md)).

0186 was reserved for this work.

## Context

The four slices before this one make botd install, upgrade and run with no network, and put its images in an internal registry. They stop at the server. SuperBot's point is that each person's Bots have a computer of their own, and with a control plane each machine installs its own harness CLIs ([ADR 0039](0039-machine-harnesses-and-agent-upgrades.md)): botd sends a plan of pins, and the agent downloads Node.js from `nodejs.org`, then `npm pack`s each harness from `registry.npmjs.org`, checking each against its pin.

In an air-gapped network neither host answers, so every machine's harnesses stay `failed` and its Bots can't run. The guide said nothing about it. Agent upgrades were never the problem: the agent downloads its new build from botd itself.

Air-gapped networks almost always have an artifact proxy already (Artifactory, Nexus, Verdaccio), with an npm remote and a generic remote for `nodejs.org/dist`, or a registry filled on the connected side, usually behind an internal CA.

## Decision

### Three settings, the same pins

- **`MACHINE_NODE_MIRROR`**: a base URL laid out as `https://nodejs.org/dist`. botd rewrites the plan's Node.js downloads to `<mirror>/v<version>/<the same file name>`. The SHA-256 per arch stays the pinned one.
- **`MACHINE_NPM_REGISTRY`**: an npm registry. The plan carries it (`npmRegistry`), and the agent gives it to npm as `npm_config_registry`, so the harness and every package it depends on come from there and nothing from npm's registry. The harness's own tarball is still checked against its pinned SHA-512 (or one in `name@version=<checksum>`) before it is installed. Its dependencies are checked, as before, against the SHA-512 the registry lists for them.
- **`MACHINE_MIRROR_CA_FILE`**: a PEM bundle of CA certificates. The plan carries it (`ca`). The agent trusts it besides its own roots for the plan's downloads, and gives it to npm as `NODE_EXTRA_CA_CERTS`, written into the download folder and removed with it. botd checks at start that it holds only certificates that parse, at most 64 KiB.

All three are `https://` with no login, query or fragment, need `MACHINE_CONTROL_URL`, and are refused at start otherwise. They apply to `MACHINE_HARNESSES` and to the managed tiers' default harnesses alike.

A mirror decides where the bytes come from, never what they are. That is why the pins stay in botd and are applied unchanged: a mirror serving a different Node.js or harness tarball fails that install, as a changed file at the public source would.

### The plan's new fields are left out when unset

`HarnessPlan` gains `npmRegistry` and `ca`, both skipped when empty. A server without mirrors sends the plan's JSON byte for byte as before, so its id doesn't change and no machine reinstalls anything after an upgrade.

Agents deny unknown fields, so an agent from before this would refuse a plan carrying them, or, if they were stripped, fetch from npm's registry and fail. New agents say `harness_mirrors` in their heartbeat. botd sends a plan with a registry or CA only to agents that say it. `POST /api/users/{key}/machine/harnesses` answers 409, saying to upgrade first, for one that doesn't. Agent upgrades come from botd, so that works with no internet. A Node.js mirror alone needs no new agent: it only changes URLs.

### Checking the mirrors from botd: `GET /api/machines/harness-mirror`

An empty or stale remote only shows up when a machine fails. So botd can fetch everything the current plan names, from where machines would and trusting the same CA, and check each against its pin before any machine needs it:

- each arch's Node.js tarball, against its SHA-256;
- each npm harness's package document, which must list the version, an `https` tarball and, with a pin, that same SHA-512; then the tarball, against the pin (or what the document lists, for an unpinned version);
- an installer script (Hermes Agent), against its SHA-256, marked as still needing GitHub and PyPI.

It answers with an entry per file and `ok` overall. Admins only: the route isn't in RBAC's delegable list, so it falls to admin, as other new routes do. `botctl machine mirror` calls it. It changes nothing and isn't audited, like other reads. With a remote that fetches on first use, it also fills the remote.

### Incus containers reach private mirrors only where the operator opens them

Incus containers drop all TCP and UDP to private, shared and link-local ranges and the Incus host ([ADR 0065](0065-incus-container-machines.md)), root's included. The one hole was botd's machine port, carved from the ranges when `MACHINE_CONTROL_URL` is a private IP. An internal mirror is almost always on a private address, so its downloads were dropped, and the check couldn't see it: it runs on botd, outside the containers' rules.

`INCUS_EGRESS_ALLOW` takes exact `address:port` pairs (`10.0.0.20:443,[fd00::20]:443`), carved the same way: that address is taken out of the ranges, then every other TCP port on it and all UDP to it are dropped. No ranges, no host names, no UDP: a name could move to another address, and a range would open more than one mirror. It applies to every container, like the deny list, and shows in `botctl machine substrate`. The check resolves each place it fetched from, every redirect it followed included (a mirror may send tarballs on to its storage), against the same deny list the fleet gives containers (every `INCUS_HOSTS` host too), and fails, saying what to do, for any address the machines' provider firewall would drop: the Incus ACL, or Linode's outbound rules ([ADR 0179](0179-outbound-rules-at-the-provider.md)). Linode gets no allow-list here: ADR 0179's rules are that ADR's to change, Linode needs the internet for its own API, and `MACHINE_FIREWALL_EGRESS=off` is there for a mirror they hold. The machines' own allow-lists ([ADR 0135](0135-run-limits-and-egress-allow-lists.md)) don't apply to root, which installs the harnesses, so they need no entry.

Considered instead: opening mirrors' addresses automatically from their URLs. botd would resolve the host names when it builds the rules, so the rules would silently follow DNS, and a typo'd URL would open whatever it names. The operator naming the address keeps the hole explicit and narrow.

### Hermes Agent stays as it is

Hermes has no npm package. Its pinned installer clones from GitHub and installs from PyPI, which a URL rewrite can't cover. Mirroring it would mean a git mirror, a PyPI mirror and changes to its installer's arguments, a separate piece of work. botd's startup line and the check name any harness still fetched from the internet. The guide says to leave `hermes` out of `MACHINE_HARNESSES` there, and to set it explicitly, since unset it defaults to the managed tiers' harness, Hermes on the shipped plans.

### Considered

- **botd serving the harness files itself** from the offline bundle, as it serves the agent binary. It needs no proxy, but npm harnesses aren't single files: Claude Code and Codex pull per-platform packages as optional dependencies. Bundling them would mean shipping and checking a dependency tree per arch, and redistributing third-party packages in our release. A registry is what npm already speaks, and what these networks already run. This stays a possible follow-up for networks with no registry at all.
- **Registry credentials** (a token for the npm remote). They would be a new secret sent to every machine and kept there. Internal remotes usually allow anonymous reads inside the network, so this slice needs none. A follow-up can add one, through the secrets store.
- **`npm_config_cafile`** instead of `NODE_EXTRA_CA_CERTS`. It replaces Node's roots rather than adding to them, which would break a registry with a public certificate and an internal Node.js mirror.

## Consequences

- An air-gapped server's machines install Claude Code, Codex and Pi from its own mirrors, with the same pins, and its Bots run on them.
- Operators can prove their mirrors are ready (`botctl machine mirror`) before any machine fails, and after every upgrade that moves a pin.
- Servers without mirrors see no change: the same plan JSON and id, and older agents keep getting their plans.
- Tested:
  - settings: refused URLs and CA files (empty, not PEM, a key in the bundle, not a certificate, too big, missing);
  - the plan rewrite keeps every pin and id, and agents without `harness_mirrors` aren't sent a plan with a registry or CA;
  - the check against a stand-in HTTPS mirror with a CA of its own: scoped names asked for as npm does, a missing CA, a pin the registry doesn't list, a tarball that differs, a wrong Node.js, an unknown version;
  - end to end on loopback with botd, the real agent over mutual TLS and the stand-in mirror: Node.js comes from the mirror over its CA, npm is given the registry and the CA, the check passes, then fails once the mirror's file changes;
  - the real npm, in a Node.js laid out as nodejs.org's tarballs are, installs a package and a dependency only the stand-in registry has, and refuses one that isn't pinned. CI runs this as root with networking off (`server.yml`, isolation job), and it fails without the CA or the dependency;
  - `INCUS_EGRESS_ALLOW`: parsing, the rules for several addresses and ports (botd and a mirror on one host, IPv6, a public one, the ends of a range), and the check failing until the mirror's address is allowed, or, on Linode, until the outbound rules are off. On a real Incus host (`incus-e2e`), a container reaches the allowed port on botd's host and still not the other ports.
- Not covered: Hermes Agent on machines without the internet, registries that need a login, and the machines' own OS packages (their image and apt mirror are the operator's, as for the server).
