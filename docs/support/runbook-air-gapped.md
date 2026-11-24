# Runbook: offline and air-gapped installs

An install or upgrade from an offline bundle fails, or an air-gapped server can't do something it needs the network for ([guide](../ops/air-gapped.md), [ADR 0128](../adr/0128-air-gapped-self-host.md), [ADR 0140](../adr/0140-release-bundles-and-registry-mirrors.md), [ADR 0147](../adr/0147-signatures-and-multi-arch-indexes-in-mirrors.md), [ADR 0172](../adr/0172-release-bundles-checked-end-to-end.md), [ADR 0186](../adr/0186-harness-installs-from-internal-mirrors.md), [ADR 0232](../adr/0232-harness-cli-bundle-for-air-gapped-servers.md)). Support can't reach the server: everything goes through the customer's admin, and files travel on their approved media. Severity: [2](severity.md#severities) if an upgrade left the server down (restore first, below), 3 for an install or upgrade that stopped before changing anything, 4 for questions.

## First five minutes

1. **Which bundle and how.** Its file name (version and arch), whether it came from the release page or `offline-bundle.sh`, and the command run (installer `--offline`, or `offline-bundle.sh load` or `push` for Compose and mirrors). The exact last lines of output.
2. **Is botd up?** `systemctl status superbot` (installer) or `docker compose ps` (Compose). If it was an upgrade and botd is down, go to [restore](#an-upgrade-left-it-down) now.
3. **Did the release pass its own check?** The latest [`offline-release-check`](../../.github/workflows/offline-release-check.yml) run for that tag ([checking a release](../ops/air-gapped.md#checking-a-release-end-to-end)). Green means the published bundles verified, pushed to a mirror and installed with no network; look at the customer's side first. Red means the release itself has a problem: see [escalate](#escalate-when).
4. **What's installed:** `/usr/local/share/superbot/offline-release` has the version the installer last put in.
5. **A support bundle** if botd runs: `botctl support-bundle`, read by the customer, carried out like any other file ([support bundle](support-bundle.md)).

## Failures and fixes

| Says | Usually | Fix |
|---|---|---|
| SHA-256 doesn't match | The bundle was damaged or changed in transit, or the recorded value is for another file | Copy it again; check the SHA-256 against the value recorded on the connected machine, not the `.sha256` that travelled with it |
| Stops with no SHA-256 and no verified signature | Neither `--bundle-sha256` nor a `.sigstore.json` with cosign and a trusted root | Pass `--bundle-sha256 <recorded value>`, or carry in Sigstore's trusted root separately and set `SIGSTORE_TRUSTED_ROOT` ([verifying](../ops/air-gapped.md#verifying-a-bundle)) |
| Signature from another identity | A fork's or another workflow's bundle | Refuse it. Get the bundle from the release page and verify it with the identity in the guide |
| A bundle older than the installed one is refused | Going back by installing an older bundle | Restore a backup made on the older version instead ([below](#an-upgrade-left-it-down)) |
| TLS certificate or key refused | Not a pair, expired, not for `--domain`, or a key with a passphrase | A full-chain PEM and an unencrypted key from their CA ([TLS](../ops/air-gapped.md#tls-certificates)) |
| `push`: digest differs, or refused | The registry changed the image, or a bundle from before OCI archives | Check the registry keeps images as pushed; use a newer bundle, or `load` ([mirrors](../ops/air-gapped.md#registry-mirrors)) |
| `cosign verify` against the mirror finds nothing | A bundle made before ADR 0147, an unsigned image, or the wrong identity or no `--trusted-root` | Push both arches' bundles of a current release, and verify with the identity and trusted root in the guide ([checking signatures](../ops/air-gapped.md#checking-signatures-in-the-mirror)). For old bundles, the digest pin is the check and `images/<name>.cosign.json` the record |
| `offline-release-check.sh offline` refuses to run | `github.com` answers from that host | Run it inside the air-gapped network, where the check means something |
| Bots can't reach a model | The tiers or harness settings point at a public provider | An internal OpenAI-compatible endpoint over `https://` ([model providers](../ops/air-gapped.md#model-providers)) |
| Harness logins (`claude login`) fail | They go through the vendor's website | API keys for the internal endpoint |
| A machine's harness stays `failed` ("couldn't download", "npm pack failed", "not the pinned") | Machines fetch Node.js and npm harnesses from the internet, or the mirrors lack the pinned files or serve other ones | Set `MACHINE_NODE_MIRROR`, `MACHINE_NPM_REGISTRY` and, for an internal CA, `MACHINE_MIRROR_CA_FILE`, then run `botctl machine mirror`: each line names the file and why it failed. Put the pinned versions in the mirror (never change the pins to match it) and `botctl machine harnesses <user>` ([harness CLIs on machines](../ops/air-gapped.md#harness-clis-on-users-machines)) |
| On Incus, a machine's harness fails with "couldn't download" but `botctl machine mirror` passed, or the check lists `blocked` | The mirror is on a private address, which machines' firewall drops | On Incus, add its exact `address:port` to `INCUS_EGRESS_ALLOW`; on Linode, move the mirror or set `MACHINE_FIREWALL_EGRESS=off`. Restart botd, check again, then `botctl machine harnesses <user>` ([harness CLIs on machines](../ops/air-gapped.md#harness-clis-on-users-machines)) |
| A machine's harness fails with "npm pack failed" and a 401 or 403, or `botctl machine mirror` says the registry refused the login or wants one | The registry asks for a login, and botd has none or a wrong one | Set `MACHINE_NPM_TOKEN`, or `MACHINE_NPM_USERNAME` and `MACHINE_NPM_PASSWORD`, to a read-only login for `MACHINE_NPM_REGISTRY`, restart botd, check again, then `botctl machine harnesses <user>` ([registries that need a login](../ops/air-gapped.md#registries-that-need-a-login)) |
| `botctl machine harnesses` says the agent is older than ADR 0219, or can't sign in to MACHINE_NPM_REGISTRY | Its agent can't fetch the registry's login | `botctl machine upgrade <user>` first: agents upgrade from botd, not the internet |
| `botctl machine harnesses` says the agent is older than ADR 0186 | Its agent can't use the mirrors | `botctl machine upgrade <user>` first: agents upgrade from botd, not the internet |
| "The harness bundle doesn't hold what this release pins (claude is …, not …)" | A harness bundle from another release, or one made from another checkout's botd | Use the harness bundle attached to the same release as the main bundle, or make it from that release tag with `offline-bundle.sh harnesses` ([harness CLIs on this server](../ops/air-gapped.md#harness-clis-on-this-server)) |
| An upgrade warns "The harness CLIs in /opt/superbot-harnesses aren't the ones this release pins" | `--upgrade` without `--harness-bundle` keeps the CLIs it has | Re-run the upgrade with `--harness-bundle` and that release's harness bundle |
| "The harness CLIs from … don't run here", and the installer put the old ones back | `/opt` mounted `noexec`, or a bundle for another distro's libraries | Check `findmnt /opt` and the `--version` line it printed; Ubuntu 22.04 or 24.04 runs release bundles. The previous CLIs and links are back, and botd restarted |
| `offline-bundle.sh harnesses`: "from your npm registry is sha512-…, but botd pins …" | The builder's npm registry serves another tarball under that version | Don't bundle it. Point npm at a registry that serves the original package (`npm config get registry`); if it is the public registry, escalate as possible tampering |
| Hermes Agent won't install on machines | Without `MACHINE_HERMES_BUNDLE`, machines run its installer, which needs GitHub and PyPI; with it, the agent is older than ADR 0210, the machine's arch has no bundle, or a bundle file changed after botd started | Set `MACHINE_HERMES_BUNDLE` to the release's Hermes bundles, one per arch, then `botctl machine mirror` and `botctl machine harnesses <user>`; upgrade older agents first, and restart botd after replacing a bundle ([Hermes on machines](../ops/air-gapped.md#hermes-agent-on-users-machines)) |

What needs the internet and what to use instead is in the [guide's table](../ops/air-gapped.md#what-needs-the-internet-and-what-to-do-instead): cloud identity providers, Linode machines, Stripe, push notifications.

## An upgrade left it down

1. Read the installer's last lines and botd's log (`journalctl -u superbot -n 200`). A migration or setting error is often fixed in place; send the lines to support, read first.
2. If it can't be fixed quickly, restore the backup made before the upgrade ([backup and restore](../ops/backup-restore.md)) with the bundle of the version it was made on. Keep the previous bundle until a new one has run well.
3. Status page and ticket updates as for any outage ([machine down or restore](runbook-machine-down.md#the-server-itself)).

## License

The license verifies offline. One that has ended keeps working for its 14-day grace period, then Bots stop. Renewal is a new key file from CG-Labs, carried in and installed with `botctl license install < key`. Admins are warned 30 days ahead, and the [health score](health-score.md#license) shows it at watch, so the TAM can start the transfer early.

## Escalate when

- A bundle from the release page, with the recorded SHA-256 and the right signing identity, fails its checks: possible tampering in the release, [Severity 1](escalation.md#security-incidents).
- The release's latest `offline-release-check` run is red: tell customers not to install that release until engineering has looked. If the run shows a signature or digest that doesn't match, treat it as possible tampering, as above.
- An upgrade fails on a migration with no backup to go back to.
- The customer needs a fix faster than the next release: engineering decides; there are no in-place patches.

## Afterwards

Note the cause in the ticket. If the customer's process lost the recorded SHA-256 or the trusted root, suggest they record both with the change ticket for each upgrade. Make sure the customer's record says which version and arch they run, for the next release notes.
