# Runbook: offline and air-gapped installs

An install or upgrade from an offline bundle fails, or an air-gapped server can't do something it needs the network for ([guide](../ops/air-gapped.md), [ADR 0128](../adr/0128-air-gapped-self-host.md), [ADR 0140](../adr/0140-release-bundles-and-registry-mirrors.md)). Support can't reach the server: everything goes through the customer's admin, and files travel on their approved media. Severity: [2](severity.md#severities) if an upgrade left the server down (restore first, below), 3 for an install or upgrade that stopped before changing anything, 4 for questions.

## First five minutes

1. **Which bundle and how.** Its file name (version and arch), whether it came from the release page or `offline-bundle.sh`, and the command run (installer `--offline`, or `offline-bundle.sh load` or `push` for Compose and mirrors). The exact last lines of output.
2. **Is botd up?** `systemctl status superbot` (installer) or `docker compose ps` (Compose). If it was an upgrade and botd is down, go to [restore](#an-upgrade-left-it-down) now.
3. **What's installed:** `/usr/local/share/superbot/offline-release` has the version the installer last put in.
4. **A support bundle** if botd runs: `botctl support-bundle`, read by the customer, carried out like any other file ([support bundle](support-bundle.md)).

## Failures and fixes

| Says | Usually | Fix |
|---|---|---|
| SHA-256 doesn't match | The bundle was damaged or changed in transit, or the recorded value is for another file | Copy it again; check the SHA-256 against the value recorded on the connected machine, not the `.sha256` that travelled with it |
| Stops with no SHA-256 and no verified signature | Neither `--bundle-sha256` nor a `.sigstore.json` with cosign and a trusted root | Pass `--bundle-sha256 <recorded value>`, or carry in Sigstore's trusted root separately and set `SIGSTORE_TRUSTED_ROOT` ([verifying](../ops/air-gapped.md#verifying-a-bundle)) |
| Signature from another identity | A fork's or another workflow's bundle | Refuse it. Get the bundle from the release page and verify it with the identity in the guide |
| A bundle older than the installed one is refused | Going back by installing an older bundle | Restore a backup made on the older version instead ([below](#an-upgrade-left-it-down)) |
| TLS certificate or key refused | Not a pair, expired, not for `--domain`, or a key with a passphrase | A full-chain PEM and an unencrypted key from their CA ([TLS](../ops/air-gapped.md#tls-certificates)) |
| `push`: digest differs, or refused | The registry changed the image, or a bundle from before OCI archives | Check the registry keeps images as pushed; use a newer bundle, or `load` ([mirrors](../ops/air-gapped.md#registry-mirrors)) |
| `cosign verify` against the mirror finds nothing | Signatures aren't copied into mirrors yet | Expected: the digest pin is the check, and `images/<name>.cosign.json` in the signed bundle is the record |
| Bots can't reach a model | The tiers or harness settings point at a public provider | An internal OpenAI-compatible endpoint over `https://` ([model providers](../ops/air-gapped.md#model-providers)) |
| Harness logins (`claude login`) fail | They go through the vendor's website | API keys for the internal endpoint |

What needs the internet and what to use instead is in the [guide's table](../ops/air-gapped.md#what-needs-the-internet-and-what-to-do-instead): cloud identity providers, Linode machines, Stripe, push notifications.

## An upgrade left it down

1. Read the installer's last lines and botd's log (`journalctl -u superbot -n 200`). A migration or setting error is often fixed in place; send the lines to support, read first.
2. If it can't be fixed quickly, restore the backup made before the upgrade ([backup and restore](../ops/backup-restore.md)) with the bundle of the version it was made on. Keep the previous bundle until a new one has run well.
3. Status page and ticket updates as for any outage ([machine down or restore](runbook-machine-down.md#the-server-itself)).

## License

The license verifies offline. One that has ended keeps working for its 14-day grace period, then Bots stop. Renewal is a new key file from CG-Labs, carried in and installed with `botctl license install < key`. Admins are warned 30 days ahead, and the [health score](health-score.md#license) shows it at watch, so the TAM can start the transfer early.

## Escalate when

- A bundle from the release page, with the recorded SHA-256 and the right signing identity, fails its checks: possible tampering in the release, [Severity 1](escalation.md#security-incidents).
- An upgrade fails on a migration with no backup to go back to.
- The customer needs a fix faster than the next release: engineering decides; there are no in-place patches.

## Afterwards

Note the cause in the ticket. If the customer's process lost the recorded SHA-256 or the trusted root, suggest they record both with the change ticket for each upgrade. Make sure the customer's record says which version and arch they run, for the next release notes.
