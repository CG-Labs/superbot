# 0247: The release check covers the Hermes and harness bundles

## Status

Accepted (24 Nov 2026). Eleventh slice of [#59](https://github.com/CG-Labs/superbot/issues/59) (M5, "Air-gapped self-host"). Extends the end-to-end release check ([ADR 0172](0172-release-bundles-checked-end-to-end.md)) to the Hermes bundles ([ADR 0200](0200-hermes-agent-bundle-for-air-gapped-installs.md)) and harness bundles ([ADR 0232](0232-harness-cli-bundle-for-air-gapped-servers.md)) that `release-bundle` attaches, as servers and machines take them ([ADR 0210](0210-hermes-agent-on-air-gapped-machines.md), [ADR 0242](0242-harness-bundle-on-air-gapped-machines.md)).

0247 was reserved for this work.

## Context

`release-bundle` attaches three kinds of signed file per arch: the offline bundle, the Hermes bundle and the harness bundle. `offline-release-check.yml` downloaded only the offline bundles. So nothing checked, after the release, that the other two were attached, signed by the offline workflow, built from the tag's commit for their arch, or at the pins of the release's own botd. A bundle at other pins is one `install.sh` refuses, and botd won't start with it in `MACHINE_HERMES_BUNDLE` or `MACHINE_HARNESS_BUNDLE`. An operator would find out inside the network, after carrying it in. ADR 0242 left this open.

## Decision

### Connected: `offline-release-check.sh online` checks both kinds for both arches

After the offline bundles, the check reads the pins from the release's own botd (`botd harness pins`, from the host arch's offline bundle), as `install.sh` does. The Hermes pin names the file, `superbot-hermes-<tag>-<arch>.tar.gz`. The harness bundle is `superbot-harnesses-<version>-<arch>.tar.gz`. For each:

- the same published-file checks as the offline bundle: the file, its `.sha256` and `.sigstore.json` are attached, the SHA-256 matches, the signature verifies against the offline workflow's identity, and `offline-bundle.sh verify` accepts it with the signature checked. That shared code is now one function.
- its `MANIFEST`: its arch, the tag's commit, and for Hermes the pinned commit and tag. For the harness bundle, the release's version, and every line `install.sh` wants at botd's pins (`harness_mismatch`), so a pin that differs is named the way the installer names it.
- its programs are built for its arch and need no newer glibc than `--max-glibc`: Node.js in the harness tree, and `.local/bin/*` and uv's Python in the Hermes tree. The inner tar is streamed, never unpacked. Only regular files are read, so the tree's links are never made. At least one program must be found.
- the file is hashed once more at the end, so a file changed while it was read is caught.

Then the release's botd checks all four as machines would take them: `botd harness check-bundles FILE...`. It is a new subcommand that runs the code botd runs at start for `MACHINE_HERMES_BUNDLE` and `MACHINE_HARNESS_BUNDLE` (`Bundles::from_env` and `apply`), against the plan for every harness it pins, and then the agent's own plan check. It prints one line per bundle with its SHA-256, and which harnesses machines would install from them. The check wants each bundle named with the SHA-256 it checked, and every pinned harness from the bundles.

Each bundle goes into `release-check.expected` as `hermes <arch> <file> <sha-256>` or `harnesses <arch> <file> <sha-256>`.

### Offline: each recorded bundle verifies with no network

`offline` wants all four lines, checks that each names a file of its kind and arch in the folder, and verifies each against its recorded SHA-256 and Sigstore's trusted root, as for the offline bundles. A record cut short, a name outside the folder or a bundle changed since is refused.

### The workflow installs from them

`offline-release-check.yml` downloads `superbot-hermes-*` and `superbot-harnesses-*` too. Its install with no network adds `--with-hermes --hermes-bundle ... --harness-bundle ...`, with the SHA-256s from the record. Then it checks that Hermes Agent and the harness CLIs came from their bundles, and that `hermes`, `claude`, `codex` and `pi` answer `--version` as `nobody` inside the namespace. It also installs `libatomic1`, which `--with-hermes` needs and an offline install can't fetch.

### `--without-harness-bundles`, for CI only

CI's own signed release (offline.yml `install-offline`) has no Hermes or harness bundles, and its bundles carry one runner's binaries. So its online check passes `--without-harness-bundles`. The record then says `harness-bundles skipped`, and `offline` warns that it skipped them. A wiring test checks that the published release's check never passes it.

### Considered

- **Check pins in shell only.** The shell can compare `MANIFEST` lines, but botd's start-up check also reads every tree entry, refuses two bundles for one arch, and builds the plan machines get. Running botd's own code gives the same answer botd gives at start, and needs no running server.
- **Check against `install.rs` pins from the checkout.** The workflow checks out the tag, but the bundles must match the botd that ships in the release. Reading them from that binary is what `install.sh` does.
- **Unpack each tree to check its programs.** A Hermes tree is large. Streaming the inner tar and keeping only the program paths is cheaper, and makes no links on the runner.
- **Install aarch64 too.** The runner is x86_64, so the aarch64 bundles are checked but not installed.

## Consequences

- A release whose Hermes or harness bundle is missing, unsigned, from another commit, at other pins than its botd, built for another arch, or not one botd would serve to machines fails its check. The weekly run catches a bundle replaced after the release.
- The check downloads two more files per arch, and installs Hermes Agent and the harness CLIs with no network.
- `botd harness check-bundles` is also a way for an operator to check bundles before setting `MACHINE_HERMES_BUNDLE` and `MACHINE_HARNESS_BUNDLE`.
- Tested:
  - Rust: `check-bundles` names each bundle with its SHA-256 and says what machines would take. It says what would still come from the internet. It refuses no file, a file not named as either kind, two bundles for one arch, another Hermes commit, a harness bundle missing a pinned CLI, a harness bundle named as a Hermes one, and a missing or wrong `.sha256`.
  - Shell, with stand-ins for cosign, skopeo and botd: a release with both kinds passes both phases and records them. The check refuses a missing bundle or signature, a wrong SHA-256 or signature, a bundle `verify` refuses, another Hermes commit, a missing or other harness pin, another commit or arch, a botd that won't say its pins, pins no Hermes, or won't serve the bundles, and programs for another arch or a newer glibc. Offline, it refuses a record missing a bundle, naming a file outside the folder, or with another SHA-256. `--without-harness-bundles` is recorded and said.
  - Wiring: the workflow downloads and installs both kinds, never skips them for a real release, and CI's own release says it skips them.
- Not covered:
  - The workflow's run against a real release. No release has been tagged yet, so it skips. It first runs on the first tag.
