# 0232: A harness bundle, for Claude Code, Codex and Pi on an air-gapped server

## Status

Accepted (24 Nov 2026). Ninth slice of [#59](https://github.com/CG-Labs/superbot/issues/59) (M5, "Air-gapped self-host"). Builds on the offline install ([ADR 0128](0128-air-gapped-self-host.md)), release bundles ([ADR 0140](0140-release-bundles-and-registry-mirrors.md)), harness CLIs on machines ([ADR 0039](0039-machine-harnesses-and-agent-upgrades.md)) and the Hermes bundle ([ADR 0200](0200-hermes-agent-bundle-for-air-gapped-installs.md)).

0232 was reserved for this work.

## Context

Bots on botd's own server run the harness CLIs installed there. Online, `install.sh` doesn't install them: its summary prints `npm install -g @anthropic-ai/claude-code`. Offline, it had no route at all. Since ADR 0200, Hermes Agent comes from its own bundle. Claude Code, Codex and Pi are npm packages, and the guide told operators to "install them from your npm mirror". That needs:

- an npm mirror inside the network that carries these packages and their native builds;
- a Node.js on the server, from a distro package or the operator's own copy;
- the operator to choose the versions. Nothing tied them to the release, so a server could run CLIs its botd's adapters were never tested with (ADR 0057 tests exactly the pins).

Many air-gapped networks have no npm mirror, or none that the server may reach. Machines already install the same CLIs from mirrors (ADR 0186, ADR 0219), at exact versions and integrity hashes `server/src/adapters/install.rs` pins. The server should get those same pins, from a file the operator carries in, as with the main bundle and Hermes.

An npm global install is relocatable once made. Node.js's tarball and `npm install -g --prefix DIR` leave a tree whose links are relative, and whose CLIs find their modules from their own path. Claude Code's and Codex's native builds are optional dependencies npm resolves for the platform at install time. So a tree made on a connected machine of the server's arch runs on the server with no network, wherever it's unpacked.

## Decision

### botd says what it pins: `botd harness pins`

The release's own botd prints its pins, one per line, from `install.rs`, the source machines use:

- `node <version> <arch> <sha256>` for each arch, from nodejs.org's `SHASUMS256.txt`;
- `npm <bin> <version> <package> <integrity>` for Claude Code, Codex and Pi;
- `hermes <bin> <commit> <tag> <sha256>`, which Hermes's own bundle covers.

It reads no settings and needs no database. Shell scripts take the pins from the binary instead of parsing Rust, so a pin bump needs no other edit. The builder and the installer both refuse output they don't fully understand. Each word must match its pattern. There must be a Node.js and at least one npm harness.

### A harness bundle, made where the network is

`deploy/offline-bundle.sh harnesses --out DIR [--version V] [--bin-dir DIR]` makes `superbot-harnesses-<version>-<arch>.tar.gz` and its `.sha256`. It runs on a connected machine of the server's arch, as any user:

- It takes the pins from `--bin-dir`'s botd, by default this checkout's `target/release/botd`.
- It downloads Node.js from nodejs.org and checks the tarball against the pinned SHA-256.
- For each npm harness, the tree's own npm packs the package from the builder's registry. The tarball must match the pinned integrity, or nothing is bundled. Then npm installs that file with `-g --prefix`, `--omit=dev` and a cache outside the tree, as machines do. npm checks the dependencies against the registry's hashes.
- It then checks the tree. Its `node --version` must be the pin, each package's `package.json` must have the pinned version, and each CLI's `--version` must say it. These run with no network when the builder is root. The tree must not hold `etc/npmrc`, which could carry the builder's registry login. Its links must stay inside it, as for Hermes trees, with no setuid or special files.
- It packs the tree as `harnesses.tar`, owned by 0 and sorted. That is about 400 MB gzipped and 1.1 GB unpacked on x86_64.
- The bundle holds `MANIFEST` and `SHA256SUMS` in one `superbot-harnesses-*` folder of plain files, as the main and Hermes bundles are laid out. `MANIFEST` has `kind=harnesses`, `version`, `prefix=/opt/superbot-harnesses` and `arch`. It also has one line per pin: `harnesses=claude codex pi`, `node=<version> <sha256>` and `harness_<bin>=<version> <package> <integrity>`.

`--tree DIR` packs a tree that is already installed, named `superbot-harnesses`; tests use it. It is checked the same way.

The bundle is named for the SuperBot release rather than for a harness, because it holds three harnesses and their pins change with SuperBot's.

### Installing: `--offline --harness-bundle FILE [--harness-bundle-sha256 HEX]`

Checks before anything changes, as `prepare_hermes_bundle` does:

- The bundle's signature or SHA-256 is checked. `--harness-bundle-sha256` gives the published value, or the installer reads the `.sha256` or `.sigstore.json` beside it, the same rule as the main bundle.
- The archive must be one `superbot-harnesses-*` folder of plain files. Its sums must match, `kind=harnesses`, this host's arch, and `prefix=/opt/superbot-harnesses`.
- `harnesses.tar` must stay inside one `superbot-harnesses/` folder, with no `..`, no hard link out, no setuid file and no special file.
- Its `MANIFEST` must carry every line the main bundle's botd pins for this arch. A missing or different line is refused and named ("claude is 2.1.0 …, not 2.1.1 …"). So a harness bundle goes only with the release it was made for, and the main bundle's signature covers the pins it is checked against.
- `--harness-bundle` without `--offline` is refused: online, operators install the CLIs with npm as before.

Then, after Hermes and before botd's unit starts:

1. It unpacks into a root-only staging folder beside `/opt/superbot-harnesses`, so the tree moves into place with one rename. It checks the tree again as files (links inside, followed through other links).
2. The installer writes each CLI's wrapper in `superbot/`, never taking one from the bundle. The wrapper puts the tree's `bin` first on `PATH`, so the CLI runs on its own Node.js whatever the host has, or none. It also sets `DISABLE_AUTOUPDATER=1`. The installer keeps a copy of the bundle's `MANIFEST` there too. The tree is made root's, readable and runnable by every account, writable by none.
3. It stops botd if it is running, so no Bot run is mid-swap. It moves the old tree aside and the new one in, then links `/usr/local/bin/<bin>` to each wrapper. Whatever was at a link's place (an operator's own `npm -g` install, say) is moved aside with a warning.
4. It runs Node.js, and each CLI's `--version` as `nobody` with an empty environment, and expects the pinned versions.
5. On any failure, or an exit it didn't see, it puts everything back: the links are removed, what they replaced returns, the new tree goes and the old one comes back. It starts botd again. Only after success does it delete the old tree and what the links replaced.

If the tree's `MANIFEST` already has every pin, the links are in place and the CLIs run, nothing is unpacked and botd isn't stopped.

### Upgrades keep what they have

An offline `--upgrade` without `--harness-bundle` leaves `/opt/superbot-harnesses` as it is. When the release pins other versions, it says which, and how to upgrade them. The summary's "Next steps" point offline installs at `--harness-bundle` instead of `npm install -g`.

### Releases

The `release-bundle` job builds the tag's botd, makes a harness bundle per arch from its pins, signs it with cosign as it signs the main and Hermes bundles, verifies it, and attaches it to the release. CI's `install-offline` job builds one from the PR's botd with the network. Inside the network namespace with only loopback, it installs from it, runs each CLI as `nobody` and as the service user, checks that an upgrade without the flag keeps the tree, and that running again reports it as already installed.

### Considered

- **Point operators at their npm mirror.** That was the old answer. It needs a mirror and a Node.js that many networks don't have, and lets the server drift from the release's pins.
- **Bundle npm tarballs, and run `npm install` on the server from them.** npm would still resolve each dependency, so it needs a registry. Bundling a full offline cache is larger and harder to check than the installed tree.
- **Install into `/usr/local` like `npm install -g`.** That mixes with the host's own Node.js and npm, and can't be swapped back in one step on failure.
- **Use the host's Node.js.** It may be missing, or older than the CLIs need. The pinned Node.js is the one machines use.
- **Parse `install.rs` in shell, as `install-harness-clis.sh` does for CI.** botd is in the main bundle anyway, and is what the installer must agree with. A `botd` subcommand can't drift from the code it prints.
- **One bundle per harness.** It would duplicate Node.js three times, and give operators three files to carry for one release.

## Consequences

- An air-gapped server runs Claude Code, Codex and Pi with no npm mirror and no host Node.js, at exactly the versions its botd's adapters are tested with. It needs one more file, about 400 MB, per release and arch.
- An offline install or upgrade with a harness bundle stops botd briefly while the tree swaps. One without it is unchanged.
- An operator's own `/usr/local/bin/claude` (or codex or pi) is replaced by the bundle's, with a warning, and put back if the install fails.
- The release has two more assets per arch: the bundle and its signature. The release check (ADR 0172) doesn't check them yet.
- Tested:
  - Rust: `botd harness pins` matches what machines are sent (`node()`, `install()`) for every pin. `install.sh` reads its output into the `MANIFEST` lines the bundle must carry. `botd harness` with anything else exits 2.
  - `deploy/test-offline.sh`, without root: a bundle builds from a stand-in tree at a stand-in botd's pins, with its links, a hard link and owner 0, and verifies. The builder refuses:
    - another Node.js, another package version, or a CLI whose `--version` says another;
    - `etc/npmrc`, a link out, or a folder not named `superbot-harnesses`;
    - a botd that pins nothing, or no botd.

    The installer refuses:
    - a changed `harnesses.tar`, a setuid file, a pipe, a file outside the top folder or a hard link out;
    - another kind, place or arch, no `harnesses.tar`, or no SHA-256 to check against;
    - a bundle at other pins or missing a harness;
    - another bundle's SHA-256;
    - malformed pins.

    Also tested without root: the wrapper, the flags, putting back on an exit mid-swap (old tree, the operator's own file and botd), the upgrade notice, and a dry run with `--harness-bundle` with no network.
  - CI (`offline.yml`), as root on Ubuntu 22.04 and 24.04: the real bundle, built from the PR's botd, installed with no network, as described above.
- Not covered:
  - Users' machines. They install the same pins from mirrors (ADR 0186, ADR 0219). Serving a harness bundle to machines with no npm mirror is still open.
  - aarch64 isn't installed in CI. The release job builds and verifies its bundle on an arm64 runner.
  - The release check (ADR 0172) downloads only `superbot-offline-*`, not the Hermes or harness bundles.
