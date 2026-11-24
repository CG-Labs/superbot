# 0242: Claude Code, Codex and Pi on air-gapped machines, from botd's harness bundle

## Status

Accepted (24 Nov 2026). Tenth slice of [#59](https://github.com/CG-Labs/superbot/issues/59) (M5, "Air-gapped self-host"). Builds on harness CLIs on machines ([ADR 0039](0039-machine-harnesses-and-agent-upgrades.md)), mirrors for them ([ADR 0186](0186-harness-installs-from-internal-mirrors.md)), Hermes on machines from botd ([ADR 0210](0210-hermes-agent-on-air-gapped-machines.md)) and the harness bundle for the server ([ADR 0232](0232-harness-cli-bundle-for-air-gapped-servers.md)).

0242 was reserved for this work.

## Context

Since ADR 0232, an air-gapped server runs Claude Code, Codex and Pi from a signed harness bundle, with their own Node.js and no npm mirror. Users' machines still install them as ADR 0039 does: Node.js from nodejs.org and the CLIs from npm's registry, or from the operator's mirrors of both (ADR 0186, ADR 0219). A network with no npm mirror, or none its machines may reach, had no way to give machines these harnesses. ADR 0232 left it open.

Hermes had the same gap, and ADR 0210 closed it: botd serves the Hermes bundle the operator carried in to enrolled machines, over the machine port's mutual TLS, and the agent swaps its tree into `/opt/hermes`. The harness bundle is the same kind of file: one folder of plain files, a `MANIFEST`, `SHA256SUMS` and a tree made for one prefix (`/opt/superbot-harnesses`). Its tree is relocatable and runs on its own Node.js.

## Decision

### botd serves the harness bundle: `MACHINE_HARNESS_BUNDLE`

`MACHINE_HARNESS_BUNDLE` names harness bundles, at most one per arch, as `MACHINE_HERMES_BUNDLE` names Hermes bundles: absolute paths, each with its `.sha256` beside it or `<path>=<sha-256>`. It needs `MACHINE_CONTROL_URL`. At start, botd checks each in full, with the same code it uses for Hermes bundles (`hermes_bundle::read`, now told which kind to expect):

- its SHA-256;
- one `superbot-harnesses-*` folder of plain files, its sums, `harnesses.tar` inside one `superbot-harnesses/` folder, every entry of the tree;
- its `MANIFEST`: `kind=harnesses`, `prefix=/opt/superbot-harnesses`, an arch, a Node.js line, and a pin line for each harness it names.

Then each npm harness in machines' plan must be in each bundle at exactly the plan's version, package and integrity, and each bundle's Node.js must be the plan's for its arch. That is the check `install.sh` makes against `botd harness pins`. botd won't start otherwise, and names the file and the pin. So a bundle can't change what machines run, only where it comes from, and goes only with the release it was made for. A Hermes bundle named here, or a harness bundle named in `MACHINE_HERMES_BUNDLE`, is refused.

botd serves them at `GET /v1/harnesses/<arch>` on the machine port, to enrolled machines only, as it serves Hermes bundles: the route checks the machine's certificate. The CLIs are their makers' builds, not code botd publishes.

### The plan: one tree, three harnesses

Each npm harness in the plan becomes `InstallSource::Bundle` with `holds: harnesses`. Its downloads are the same file for all three: `<MACHINE_CONTROL_URL>/v1/harnesses/<arch>` and that bundle's SHA-256. Its prefix is `/opt/superbot-harnesses`. Its program is `superbot/<name>`, the wrapper, and its readable folders are `bin`, `lib` and `superbot`. A plan left with no npm harness has no Node.js, since the tree brings its own.

`holds` is a new field. A plan without it is a Hermes bundle, so plans from before this ADR read as before. An older agent would refuse the field (`deny_unknown_fields`), so the agent now says `harness_cli_bundles` too, and botd sends such a plan only to agents that say it. `botctl machine harnesses <user>` says to upgrade the others first.

botd applies the harness bundles before the mirrors. The mirrors then find no npm harness and add no registry, no login and no CA. A plan with `hermes` also gets Hermes from `MACHINE_HERMES_BUNDLE`, as before. With both settings, machines need nothing outside the network but botd.

### The agent swaps the tree in once

The agent installs one harness at a time, so the first of the three downloads the bundle and swaps its tree in. That is ADR 0210's swap, with these changes:

- A swap is named for its prefix's folder (`superbot-harnesses`, or `hermes` as before), not for the harness. That name is used for its stage beside the prefix, its download folder, its `superbot-swap-*` unit, and the recovery of a swap cut short. So two harnesses never swap the same tree at once, and Hermes swaps are named as before.
- Before the tree moves into place, the agent readies it as `install.sh` does on a server: it must have `bin/node`, each harness its `MANIFEST` names in `bin/`, and no `superbot` folder of its own. In `superbot/` it writes each CLI's wrapper (byte for byte `install.sh`'s), a copy of the `MANIFEST`, and `bundle.sha256`, the SHA-256 of the bundle the tree came from. A test runs `install.sh`'s `harness_wrapper` and compares.
- The bundle must hold the harness at the plan's version, read from its `MANIFEST`. Then the swap goes on as for Hermes: open what other accounts run, check that `--version` answers with an empty home, and put the old tree back on any failure.
- A new tree replaces the old one for every harness linked into it, not only the one being installed. So each of those must answer `--version` in the new tree too, or the swap puts the old tree back.

For the next harness, if the tree in the prefix came from the same bundle (its `bundle.sha256`) and no swap cut short has left its stage beside it, the agent only checks that the tree's `MANIFEST` holds it at the plan's version, runs its wrapper's `--version`, and links it. There is no download and no swap, and it waits for running jobs only if it replaces an earlier install of that harness. A new bundle replaces the whole tree, so it waits for running jobs as an upgrade does. Every harness already linked to the tree then runs the new one. Its own entry in the plan changes too, so it is installed again by the quick path.

### `botctl machine mirror`

The check reads each served file again and checks it against its SHA-256, as for Hermes bundles. It now reads each URL once, so three harnesses from one bundle cost one read per arch. Each item's note names the setting it is served from.

### Considered

- **Leave machines on mirrors.** That was the only route. It needs an npm mirror machines can reach, which is the gap this closes.
- **A bundle per harness, or a tree per harness on the machine.** That means three copies of Node.js. The server's bundle is one file and one tree. Machines take the same file, so operators carry nothing new.
- **Serve the npm tarballs and run npm on the machine.** npm would still resolve every dependency from a registry.
- **Write the wrappers into the bundle.** The installer never takes a wrapper from a bundle (ADR 0232), so the agent doesn't either. The bundle can't name what runs as the program.
- **Link `bin/<name>` in the tree directly.** The CLIs find `node` on `PATH`. Machines have no Node.js of their own once the plan drops it, and the host's may be another version. The wrapper puts the tree's `bin` first, as on the server.
- **A new wire variant for harness bundles.** It would duplicate the Bundle checks, the swap and the recovery. A field with a default keeps one code path and old plans unchanged.

## Consequences

- Machines on a network with no npm mirror install Claude Code, Codex and Pi from the harness bundle the operator already carries in for the server, at exactly the release's pins, on the bundle's own Node.js. With `MACHINE_HERMES_BUNDLE` too, a machine needs nothing but botd.
- A machine needs about 400 MB free for the download and 1.1 GB under `/opt`, twice that while it replaces an earlier tree.
- Agents need this release. Older ones aren't sent such a plan, and keep what they have.
- A plan with `MACHINE_HARNESS_BUNDLE` has a new id, so every machine installs its npm harnesses again, once, from the bundle. The npm installs in the agent's tools folder stay until it is rebuilt.
- After a release moves a pin, botd won't start until `MACHINE_HARNESS_BUNDLE` names that release's bundles.
- Tested:
  - Rust, botd: harness bundles are read, refused under the Hermes kind (and the reverse), and refused for a missing or other tar, folder, file outside the top folder, Node.js, version, or pin line. botd refuses a bundle at other pins, one missing a harness the plan names, another Node.js, another prefix, two for one arch, or no `MACHINE_CONTROL_URL`. The plan gets one download per arch for every npm harness, loses its Node.js, keeps Hermes as it was, and passes the agent's own check. It goes only to agents that say `harness_cli_bundles`, and the mirrors add nothing to it. The served file is checked again on request.
  - Rust, agent: the tree is readied as `install.sh` does, with wrappers that match its output, and the wrapper runs a CLI on the tree's own Node.js. The first harness swaps the tree in, and the next links to it with no download. A harness at another version, or a bundle that doesn't hold it, is refused before anything moves. A tree that doesn't run a harness already linked to it is refused and the old one put back. After a swap cut short, the next harness swaps the tree in again rather than only linking to it. A new bundle swaps the whole tree, and the harnesses already linked to it run the new one. A harness bundle's program must be its own wrapper, with nothing after it. A swap spec from an older agent reads as Hermes.
  - End to end, over the machine port's mutual TLS: a client without a machine certificate gets 401. A machine installs Claude Code and Codex from botd's bundle, with no Node.js of its own and nothing left beside the prefix. `botctl machine mirror` passes, then fails once the file changes. CI runs it as root in a network namespace with only loopback.
- Not covered:
  - The real bundle on a machine. CI installs the real bundle on a server (ADR 0232); machines get the same file, but CI installs a stand-in tree on them.
  - aarch64 isn't installed in CI.
  - The release check (ADR 0172) still downloads only `superbot-offline-*`, not the Hermes or harness bundles.
