# 0200: A Hermes bundle, for Hermes Agent on an air-gapped server

## Status

Accepted (23 Nov 2026). Sixth slice of [#59](https://github.com/CG-Labs/superbot/issues/59) (M5, "Air-gapped self-host"). Builds on the offline install ([ADR 0128](0128-air-gapped-self-host.md)), release bundles ([ADR 0140](0140-release-bundles-and-registry-mirrors.md)), one Hermes environment per computer ([ADR 0072](0072-one-hermes-environment-per-computer.md)) and harness installs from mirrors ([ADR 0186](0186-harness-installs-from-internal-mirrors.md)).

0200 was reserved for this work.

## Context

Hermes Agent is the managed tiers' default harness, and the only one with no npm package. `install.sh --with-hermes` runs Hermes's own installer, pinned by SHA-256. That installer clones Hermes from GitHub, then fetches uv, a uv-managed CPython, the Python packages from PyPI, and Node.js tools. So `--with-hermes` was refused with `--offline`. An air-gapped operator's only route to Hermes was to build their own Docker image. No route worked for the bash install, which most such operators use.

A PyPI mirror and a git mirror are not enough. Hermes's installer takes neither as an argument, and it also downloads uv, Python and Node.js from their own sites. We would have to patch or wrap a third-party installer and track every place it reaches.

What Hermes's installer leaves is self-contained, though. With `HOME=/opt/hermes`, everything it installs sits under that folder: the checkout, uv, the uv-managed Python, the venv with its packages, and the Node.js tools. Its links point inside it, and it has no devices or setuid files. It only runs where it was installed: the venvs and Hermes's install key (a hash of the checkout's path) name `/opt/hermes`. Copied to another server's `/opt/hermes`, it runs there with no network. That includes `deploy/hermes-share.sh`, which installs the `anthropic` extra from what is already there.

## Decision

### A separate Hermes bundle, made where the network is

`deploy/offline-bundle.sh hermes --out DIR` makes `superbot-hermes-<tag>-<arch>.tar.gz` plus its `.sha256`. It runs as root on a connected machine of the server's arch.

- It downloads Hermes's installer for the commit `server/src/adapters/install.rs` pins and checks its SHA-256. It refuses a commit that differs from the one `install.sh` pins.
- It runs the installer with `HOME=/opt/hermes` inside a private mount namespace. A tmpfs over `/opt` holds only a bind of a temp folder, so the build machine's own `/opt` (and any Hermes there) is never touched.
- It runs `hermes-share.sh` as the server would, then runs the result with `unshare --net` to prove it works with no network.
- It packs the tree as `hermes.tar`: owned by 0, sorted, without the uv and pnpm caches. That is about 1 GB gzipped and 2.7 GB unpacked.
- The bundle holds `MANIFEST` (`format=1`, `kind=hermes`, `hermes_tag`, `hermes_commit`, `prefix=/opt/hermes`, `arch`) and `SHA256SUMS`, in one `superbot-hermes-*` folder of plain files, as the main bundle is laid out.

`--tree DIR` packs a tree that is already installed. It must be a folder named `hermes`, at the pinned commit, installed for `/opt/hermes`, with no link out of it. Tests use this option.

The release workflow builds one Hermes bundle per arch, signs it keylessly under the same identity as the main bundle, and attaches it to the release. `offline-bundle.sh verify` takes either kind of bundle.

### Installing: `--offline --with-hermes --hermes-bundle FILE [--hermes-bundle-sha256 HEX]`

Before anything changes, the installer checks the Hermes bundle the same way it checks the main bundle:

- its SHA-256 against `--hermes-bundle-sha256` (else the `.sha256` beside it), or its signature;
- that it holds only plain files, and every file matches `SHA256SUMS`;
- that its `MANIFEST` says `kind=hermes`, this host's arch, `prefix=/opt/hermes`, and the exact commit this installer pins.

Then it reads `hermes.tar`'s listing. Only files, folders, symlinks and hard links are allowed, all under `hermes/`, with no `..`, no setuid or setgid bits, and hard links only to files inside it.

Hermes's install itself happens after the new binaries are in place, where `--with-hermes` always ran:

- It unpacks `hermes.tar` into a 0700 staging folder beside `/opt/hermes` (`/opt/.superbot-hermes.*`).
- It checks the files again: only files, folders and links, none setuid. Every link must stay inside the tree, and absolute links must point under `/opt/hermes`. Each link is followed through the tree as it will be at `/opt/hermes`, every link on the way included, so the check doesn't depend on what is on the host, and two links can't combine to leave (`a -> .` with `b -> a/../x`).
- It stops botd, moves the old `/opt/hermes` aside, and moves the new tree in.
- It runs `hermes-share.sh`, makes the tree readable by every account, links `/usr/local/bin/hermes`, and runs Hermes as `nobody`.
- Only then does it delete the old tree. On any failure, the old tree goes back and botd starts again with it. The staging folder is always removed.

With a bundle, Hermes is always installed system-wide in `/opt/hermes`, with or without per-user accounts, because that is the only place it runs. botd finds it on `PATH` as `/usr/local/bin/hermes`. Without per-user accounts, the installer warns if `.env`'s `PATH` still puts an earlier per-user Hermes first.

If `/opt/hermes` already holds the pinned commit and sharing it succeeds, the install says it is already installed and changes nothing.

### Upgrades keep what they have

`--upgrade` without `--with-hermes` does not touch Hermes, online or offline, as before. If the Hermes installed in `/opt/hermes` or the service user's home is at a different commit from the one this release pins, the installer now warns. It names the flag to use (`--with-hermes`, or offline `--with-hermes --hermes-bundle`). Nothing else changes on the `--upgrade --domain <d>` path.

`/opt/hermes` holds no Bot data: each Bot's Hermes state is in its own `HERMES_HOME` ([ADR 0072](0072-one-hermes-environment-per-computer.md)). Replacing the tree loses nothing.

### A fix for the online system-wide install

Hermes writes some files that every run reads as `0600`, such as its install's `facts.json` and its checkout's stamps. With per-user accounts (`/opt/hermes`, root-owned), no Bot's account could run Hermes, and the installer's own `nobody` check failed. CI only dry-runs that path, so this went unnoticed. The installer now gives every account read access to the parts runs use: the checkout, the installs, the tools and uv's Python. It does not do this for Hermes's own data root. Both the online and the offline paths go through this step.

### Considered

- **Hermes inside the main bundle.** That would add about 1 GB to every release bundle, for each arch, for operators who don't use Hermes. It would also be carried again with every SuperBot release, even when the Hermes pin hasn't moved, and it would change what the release check and `push` read. A separate bundle is carried once per Hermes pin.
- **PyPI, git and generic mirrors for Hermes's installer.** This would need patches to a third-party installer, which reaches GitHub, PyPI, astral.sh, python-build-standalone and nodejs.org, and that list can change with any Hermes release. The tree is what we test against anyway.
- **Running the installer at the server from a bundled cache** (uv's and pnpm's caches, a git bundle). That is still Hermes's installer deciding what to fetch. A cache miss shows up as a network error, on the server, during an upgrade.
- **Making the tree relocatable.** venvs and Hermes's install key both bind it to its path. Pinning the path to `/opt/hermes`, the system-wide path the installer already used, is simpler and is what the build tests.

## Consequences

- An air-gapped server runs Hermes Agent with the bash install. The release carries a signed Hermes bundle per arch, and operators can make their own the same way.
- The online `--with-hermes` install with per-user accounts now works for Bots' accounts.
- Hermes doesn't move with a plain `--upgrade`. The installer says when it should.
- Tested:
  - `test-offline.sh`:
    - a Hermes bundle builds from a stand-in tree with relative links, absolute links, a hard link and caches; the caches are left out and everything is owned by 0;
    - `verify` passes it;
    - refused: a changed `hermes.tar`, a setuid file, a pipe, paths outside `hermes/`, `..`, a hard link out, another kind, another prefix, a non-commit, a missing `hermes.tar`, no SHA-256;
    - the unpacked tree's link check: links to `/etc`, `../..` escapes, another folder, `/opt/hermes/../etc`, links that leave only through another link (relative or absolute), and a loop;
    - the bundle builder refuses: another commit, a tree for another place, a folder with another name, a link out, and building without root;
    - the installer refuses another arch, a commit it doesn't pin, and the main bundle's SHA-256 used for the Hermes bundle;
    - the flags matrix;
    - the pin notice;
    - a dry run of the whole offline install with Hermes, with no network.
  - `offline.yml`, on Ubuntu 22.04 and 24.04: builds a real Hermes bundle, connected, and verifies it. In the network namespace with no network, it then:
    - installs Hermes from the bundle with `--upgrade --with-hermes`, and runs `hermes --version` as `nobody` and as `superbot`;
    - runs an `--upgrade` without `--with-hermes`, which keeps the tree untouched;
    - re-runs the install with the bundle, which says Hermes is already installed.
  - By hand, as root with no network: a fresh install, a replacement of another commit, a rollback when the final check fails, and a rollback when sharing fails.
- Not covered:
  - Hermes Agent on users' own machines without the internet. Their agent still runs Hermes's installer. A follow-up could have botd serve this bundle's tree to them. [ADR 0210](0210-hermes-agent-on-air-gapped-machines.md) does.
  - Docker Compose, which still needs a custom image for Hermes.
  - The Hermes bundle in `offline-release-check`. Its signature is checked when it is attached, but the weekly end-to-end check doesn't install it yet.
  - npm registries that need a login.
