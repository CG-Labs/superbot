# 0284: Ubuntu's packages on users' machines from an apt mirror

## Status

Accepted (25 Nov 2026). Fifteenth slice of [#59](https://github.com/CG-Labs/superbot/issues/59) (M5, "Air-gapped self-host"). Builds on harness installs from internal mirrors ([ADR 0186](0186-harness-installs-from-internal-mirrors.md)), whose CA setting and `botctl machine mirror` check it reuses, and on per-user machine hardening ([ADR 0126](0126-per-user-machine-hardening.md)).

0284 was reserved for this work.

## Context

Users' machines run Ubuntu 24.04 (Incus `ubuntu/24.04/cloud`, Linode `linode/ubuntu24.04`). Their first boot installs packages with apt: `nftables` and `unattended-upgrades` for hardening, and the screen packages (Xvfb, Openbox, D-Bus, fonts, codecs) when screens are on. `unattended-upgrades` then takes security updates from the same sources, every day.

The rest of #59 took every other download off the internet: harnesses from mirrors or botd's bundles, images from an Incus image server inside the network or imported by hand. apt was left pointing at `archive.ubuntu.com` (`ports.ubuntu.com` on arm64). In an air-gapped network that fails quietly: the first boot can't install `nftables`, so the machine's egress rules never load, screens never work, and no security update ever arrives. `botd offline check` didn't mention it, so an operator had no way to know.

## Decision

### Two settings, one per Ubuntu archive

- `MACHINE_APT_MIRROR`: a mirror of `http://archive.ubuntu.com/ubuntu`, for amd64 machines.
- `MACHINE_APT_PORTS_MIRROR`: a mirror of `http://ports.ubuntu.com/ubuntu-ports`, for arm64 machines (containers on an arm64 Incus host).

Ubuntu publishes amd64 and arm64 from two archives with different layouts, so a mirror carries one or the other, and a single setting would have to guess. A machine with no mirror for its arch keeps Ubuntu's archive. Both are `https://` only, with no login, query or fragment, and only characters that need no quoting in a shell script or apt's sources. They need `MACHINE_CONTROL_URL`, since only enrolled machines get botd's first boot. botd won't start with a value it can't use.

`MACHINE_MIRROR_CA_FILE`, the harness mirrors' CA, is reused. apt trusts it for the mirrors' hosts alone (`Acquire::https::<host>::CAInfo`), besides the machine's roots, so it can't vouch for any other host. apt's per-host settings can't name an IPv6 literal (`::` is its separator), so botd refuses one with the CA set.

### A first-boot step before anything runs apt

First boot already runs the hardening step, then the screens step. A new step runs before both. It reads the arch (`dpkg --print-architecture`) and the codename (`/etc/os-release`), then:

- writes `/etc/apt/sources.list.d/ubuntu.sources` (deb822, as Ubuntu 24.04 does) with the mirror for its arch, the `<codename>`, `-updates` and `-security` suites, and the `main restricted universe multiverse` components;
- blanks `/etc/apt/sources.list` if the image filled it, so nothing still lists Ubuntu's archive;
- writes `/etc/cloud/cloud.cfg.d/90-superbot-apt.cfg` with `apt: preserve_sources_list: true`.

It is never fatal. With no mirror for the arch, or no codename to list, it leaves the sources alone and says so, and the step after it fails as it would have.

Backports are left out: mirrors often skip them, and apt fails `update` on a listed suite it can't find.

**Ubuntu's signatures stay.** The sources keep `Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg`, from the image's `ubuntu-keyring`. A mirror serves Ubuntu's own signed `InRelease`, so it can serve packages but can't change them, as the harness pins do for npm (ADR 0186). The cost is that a mirror re-signed with the operator's own key won't work; Artifactory, Nexus, aptly and apt-mirror all serve upstream's signature by default.

**Why a script, not cloud-init's `apt:` module.** cloud-init's `apt: primary:` would also write the sources. But Incus renders user data only when a container is created or copied, and a container restored onto another host from its backup is a new cloud-init instance: cloud-init would write the sources again from whatever it has then. The script writes them once, from botd's settings at enrollment, and the drop-in tells cloud-init to keep them, which also holds on Linode, where user data is re-read on rebuild. The script is also testable with stubs, like the other first-boot steps.

### `botctl machine mirror` reads it as apt would

`GET /api/machines/harness-mirror` now also checks each apt mirror set, from where machines would fetch, trusting what they would. It works with no harness plan (`MACHINE_HARNESSES=none`) too. For each arch:

- **Each suite's `InRelease`** (`ubuntu` items, one per suite): clearsigned, for `noble` and the suite asked for, listing the arch and the `main` and `universe` components, and not past its `Valid-Until`, which apt refuses. A `-updates` or `-security` suite whose `Date` is over 7 days old is a `warning`: machines get no security update newer than it. The release suite never changes, so it is never stale.
- **The release's package lists** (`ubuntu-packages`): `main` and `universe`'s `Packages.gz`, each checked against the size and SHA-256 its `InRelease` lists, then unpacked (with a cap) and searched for every package machines install (hardening's when hardening is on, the screens' when screens are on).

botd doesn't check Ubuntu's PGP signature: that needs Ubuntu's keyring on botd's server, which may not be Ubuntu. apt on every machine does. Mirror addresses the machines' firewall would drop are in `blocked`, as for the harness mirrors.

### `botd offline check` names it

Ubuntu's archive (`ubuntu.com`) joins the internet services the offline check knows. With Linode or Incus machines and no `MACHINE_APT_MIRROR`, the Machines area has an `internet` line for `archive.ubuntu.com`. With Incus and only one of the two settings, the other arch is a `check` line, since botd can't tell whether any host has that arch.

## Considered

- **Baking the sources into the Incus image.** Operators import images by hand (`INCUS_IMAGE_SERVER=local`) or mirror an image server; asking them to rebuild images for a URL is harder than a setting, and Linode's images can't be changed.
- **A proxy (`Acquire::http::Proxy`) to a caching apt proxy.** It keeps `archive.ubuntu.com` in the sources and needs the proxy to rewrite or reach upstream. A mirror URL works for both a proxy-style remote (Artifactory, Nexus) and a static mirror.
- **Serving Ubuntu's packages from botd.** botd would have to carry and refresh Ubuntu's archive, and security updates would be only as fresh as the last bundle. Operators already run apt mirrors for their other Ubuntu hosts.
- **Telling the agent to switch sources on existing machines.** That would rewrite a running machine's sources over the control plane, a new privileged action. This slice covers new ones.

## Consequences

- With the two settings, a new machine in an air-gapped network installs its hardening and screen packages, and takes security updates, from inside the network, still signed by Ubuntu.
- `botctl machine mirror` tells an operator before any machine needs it whether the mirror is complete and current, and `botd offline check` says when it's missing.
- Servers that set neither see no change: user data, first boot and the check are as before.
- Tested:
  - `machines::apt::tests`: settings are refused for `http`, a login, a query, a quote, an IPv6 address with a CA, and without `MACHINE_CONTROL_URL`; the CA is trusted for each mirror's host alone. The first-boot step, run with a stub `dpkg` against a stand-in root, writes sources for its arch only, blanks a filled `sources.list`, writes cloud-init's drop-in, and leaves everything alone for another arch or no codename, never failing. The check, against a stand-in HTTPS archive with a CA of its own, passes a good mirror, warns on a stale one, and names a changed package list, a missing package, another codename or suite, a missing arch or component, an expired or unreadable `Valid-Until`, a file that isn't clearsigned and a mirror that isn't there.
  - The real apt: with the sources and CA setting the first-boot step writes, `apt-get update` and `apt-get download` take a package from a stand-in archive signed with a throwaway key, over HTTPS with its own CA. apt refuses the mirror without the CA setting, a Release signed by another key, and a package changed after its index.
  - `machines::enroll::tests`: the user data carries the CA and its apt setting, and the step runs before hardening and screens; without the settings, user data is unchanged.
  - `machines_upkeep_tests`: `GET /api/machines/harness-mirror` with no harness plan checks both arches' mirrors, and fails on one broken suite alone.
  - `offline_check::tests`: Ubuntu's archive is `internet` until `MACHINE_APT_MIRROR` is set, and an Incus host with only one arch's mirror is a `check` for the other.
- Not covered:
  - Existing machines: they keep their sources until made again from the base image. A restore keeps the sources in the backup, so one taken before the mirror was set still uses Ubuntu's archive.
  - Mirrors re-signed with the operator's own key, which would need that key on every machine.
  - Ubuntu releases other than 24.04: the step lists the machine's own codename, but the check reads `noble`'s suites.
  - Reporting a machine's apt sources in its heartbeat. A failed install still shows as the hardening or screen step failing.
  - Importing Incus images inside the network, which stays the operator's ([guide](../ops/incus-containers.md)).
