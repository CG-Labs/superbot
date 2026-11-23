# 0210: Hermes Agent on users' machines from botd's Hermes bundle

## Status

Accepted (23 Nov 2026). Seventh slice of [#59](https://github.com/CG-Labs/superbot/issues/59) (M5, "Air-gapped self-host"). Builds on harness CLIs on machines ([ADR 0039](0039-machine-harnesses-and-agent-upgrades.md)), harness installs from mirrors ([ADR 0186](0186-harness-installs-from-internal-mirrors.md)) and the Hermes bundle ([ADR 0200](0200-hermes-agent-bundle-for-air-gapped-installs.md)).

0210 was reserved for this work.

## Context

With a control plane, each user's machine installs the harness CLIs botd plans for it. ADR 0186 let machines fetch Node.js and the npm harnesses from the operator's mirrors. Hermes Agent was left out: its agent ran Hermes's installer, which reaches GitHub, PyPI, astral.sh and nodejs.org. So on a network without the internet, operators had to leave `hermes` out of `MACHINE_HARNESSES`, even though it is the managed tiers' default harness.

ADR 0200 solved the same problem for botd's own server with a Hermes bundle: Hermes at its pinned commit, as its installer leaves it in `/opt/hermes`, which runs there with no network. Operators already carry that bundle in, and every release attaches a signed one per arch. Machines can use the same file.

## Decision

### `MACHINE_HERMES_BUNDLE`: botd serves the bundle

`MACHINE_HERMES_BUNDLE` names the Hermes bundles botd serves, comma-separated, at most one per arch:

```sh
MACHINE_HERMES_BUNDLE=/var/lib/superbot/superbot-hermes-v0.23.3-x86_64.tar.gz,/var/lib/superbot/superbot-hermes-v0.23.3-aarch64.tar.gz
```

Each entry is an absolute path. Its SHA-256 comes from the `.sha256` file beside it, or is given as `<path>=<sha-256>`. It needs `MACHINE_CONTROL_URL`.

At start, botd reads each bundle in full and checks what `install.sh` checks, in Rust (`machines/hermes_bundle.rs`, shared with the agent):

- the file's SHA-256 against its pin;
- one `superbot-hermes-*` folder of plain files, each listed in `SHA256SUMS` with the right hash;
- a `MANIFEST` with `kind=hermes`, `prefix=/opt/hermes` and an arch;
- every `hermes.tar` entry: files, folders, symlinks and hard links only, under `hermes/`, with no `..`, no setuid or setgid bits, and hard links to files inside it;
- two bundles for the same arch are refused.

Each bundle must hold the Hermes commit machines' plan pins. A bundle changes where Hermes comes from, never which Hermes it is. botd won't start otherwise, and names the file. A server that runs `hermes@<commit>=<sha-256>` needs the bundle of that commit.

botd serves them at `GET /v1/hermes/<arch>` on the machine port. Only an enrolled machine gets one: the route asks for the machine's certificate and checks it as every other machine call does. The bundle is about 1 GB and is a build of third-party packages, not code botd publishes, so it isn't open to anyone who reaches the port. botd streams it from disk.

### The plan: a new install source, for agents that say they take it

The plan's Hermes entry becomes a `bundle` source:

- `downloads` by arch, each `<MACHINE_CONTROL_URL>/v1/hermes/<arch>` and its bundle's SHA-256;
- `prefix` (`/opt/hermes`), `bin` (`.hermes/superbot/hermes`);
- `readable`, the folders other accounts run: the checkout, its installs, its tools and uv's Python;
- `after`, `hermes-share.sh`, as before.

The source names no Hermes specifics. The Hermes recipe lives in `adapters/install.rs`, next to its pin.

Agents from before this refuse unknown sources. So agents now say `harness_bundles`, and botd sends a plan with a bundle only to those. `botctl machine harnesses <user>` says to upgrade first. Agents upgrade from botd itself, with no internet. Without `MACHINE_HERMES_BUNDLE`, the plan and its id stay as they were, so no machine installs anything again.

### The agent installs it as `install.sh` does

1. It downloads the bundle into its tools folder, showing its machine certificate and trusting the machine CA, and checks the SHA-256 the plan pins on the way.
2. It links `hermes` in its tools to `/opt/hermes/.hermes/superbot/hermes`, and links it back to what it was if any later step fails.
3. If a swap was cut short (the agent or machine restarted after step 6), it first puts the tree that swap moved aside back in `/opt/hermes`, and removes that swap's stage. Until an install is recorded, the tree it was replacing is the one kept.
4. It unpacks it into a root-only (0700) stage beside the prefix (`/opt/.superbot-hermes.<ms>/`). The gzip and `hermes.tar` inside it are read in one pass, so `hermes.tar` is never written out. Links are made last, after every file and folder, and every folder on the way must be a real folder. So no entry is written through a link the bundle made. Modes and times are kept, since Hermes compares its stamps' times.
5. It checks the tree on disk again, as `install.sh` does. Every link must stay inside it as it will be at `/opt/hermes`, followed through each link on the way, and absolute links must point under `/opt/hermes`.
   It also checks the `MANIFEST` is for the planned commit, `/opt/hermes` and this machine's arch.
6. It moves the old `/opt/hermes` into the stage and the new tree in, in one rename.
7. It runs `hermes-share.sh` with `HOME=/opt/hermes`. It then opens the `readable` folders to other accounts (`a+rX`, `go-w` everywhere), and checks the program answers `--version` with an empty home of its own.
8. It removes the old tree, and the install Hermes's installer left in its tools folder.

If anything after the move fails, it removes the new tree and puts the old one back. If even that fails, it keeps the old one in the stage and says where, and the next install puts it back (step 3). The stage and the download are removed either way. As with every harness, a running Bot finishes before the files are replaced.

### Outside the agent's unit

The agent's unit runs with `ProtectSystem=strict`, and only `/etc/superbot` and `/usr/local/lib/superbot` are writable, so the agent can't write `/opt`. A unit change would reach only new, restored and rebuilt machines, and current agents can't be rebuilt. So steps 3 to 7, and removing the old tree, run as `superbot-machine swap-in <spec>`, in a transient unit of their own: `systemd-run --wait --pipe --collect --unit=superbot-swap-hermes`, capped at an hour. The agent already makes users this way when its unit can't write `/etc` ([ADR 0043](0043-bots-own-os-user-on-machines.md)). The spec is a JSON file in the agent's tools folder, naming the checked download and what the plan says. The unit's name is fixed, so a swap still running from before an agent restart makes the next one fail and be retried, rather than run beside it. Where the agent can write beside the prefix, as in tests, it runs the same code in its own process.

### `botctl machine mirror` checks it too

`GET /api/machines/harness-mirror` reads each served file again and checks it against the SHA-256 in the plan. A bundle replaced on disk after botd started fails the check, which says to restart botd or put the file back. Machines fetch it from botd's own port, which they reach anyway, so the firewall check leaves it out.

### Considered

- **A bundle URL on the operator's web server**, as with the npm mirrors. That is one more service to run and keep in step with the pin, and the machines' firewall would need it opened. botd already has the file's checks, the CA machines trust, and a port they reach. A URL setting could be added later without changing the agent.
- **botd unpacking the tree and serving its files.** That means 2.7 GB in many files to check and serve, and a protocol for it. The one checked file is simpler, and the agent checks it again.
- **Calling `install.sh`'s functions on the machine.** The agent is Rust and doesn't carry the installer. A shared Rust module gives botd and the agent the same checks.
- **Serving the bundle to anyone who reaches the port**, as `/v1/agent` is. The agent binary is public code. The bundle is 1 GB of third-party packages, so an open route invites bandwidth abuse for no gain.
- **Making `/opt` writable in the agent's unit.** That reaches no machine enrolled before it, and it widens what the agent itself can write for one step that runs rarely.
- **A general "file from botd" source.** Only Hermes needs this today. The source is general (prefix, bin, readable, after), but botd only fills it from Hermes bundles.

## Consequences

- An air-gapped network's machines install Hermes Agent with no internet, from the bundle the operator already carries in for the server.
- A machine needs about 1 GB free in its tools folder for the download, and 2.7 GB under `/opt` (twice that while it replaces an earlier one).
- botd reads each bundle once at start, which takes some seconds per GB.
- A machine of an arch with no bundle fails its Hermes install, saying so. The other harnesses install as before.
- Replacing a bundle file needs a botd restart, and the new file must be for the same pin.
- Tested:
  - `hermes_bundle`: a stand-in bundle reads and unpacks as it was packed, with modes, times and links. It refuses a changed or unlisted file, another layout, setuid files, pipes, paths outside `hermes/` and `..`, hard links out, writes through a link the bundle made, and links that leave the tree (directly, through other links, or through `/opt/hermes/..`).
  - `hermes_serve`: the setting's forms, absolute paths, a missing `.sha256`, a wrong SHA-256, two bundles for one arch, another prefix, a file that isn't a bundle, and no `MACHINE_CONTROL_URL`. Also: the plan it makes, refusing a bundle of another commit, and the check catching a file changed on disk.
  - The agent: plan checks for the new source, and installing a bundle. That covers replacing an earlier tree, opening only the readable parts, removing the installer's old install, putting the old tree back when `after` fails, linking the installer's Hermes back when an install fails, putting back a tree an interrupted swap moved aside, and refusing another commit or a file that isn't the pinned one before anything moves.
  - Upkeep: the plan names botd's bundles, the managed tiers' default too, only agents that say `harness_bundles` are sent it, and the plan is unchanged without Hermes or without the setting.
  - End to end on loopback: the real agent installs Hermes from botd over mutual TLS, a caller without a machine certificate is refused, and the mirror check passes, then fails once the file changes. CI runs this again as root in a network namespace with no network.
- Not covered:
  - The swap through `systemd-run` on a real machine. Tests run the same code in-process, and the spec it reads round-trips.
  - Docker Compose, which still needs a custom image for Hermes.
  - npm registries that need a login.
  - The real Hermes bundle on a real machine in CI: the end-to-end test uses a stand-in tree. `offline.yml` installs the real one on a server (ADR 0200), and the agent runs the same `hermes-share.sh` on it.
