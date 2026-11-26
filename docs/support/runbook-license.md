# Runbook: license and seats

A self-hosted server's license is ending, has ended, won't install, or has no seat left for someone new. SuperBot has no free tier: without a usable license botd still starts and admins can still sign in and install a key, but Bots don't run and nobody new takes a seat ([ADR 0038](../adr/0038-self-host-license-key.md)). Severity: [1](severity.md#severities) when Bots have stopped on a production server because there's no usable license; 2 in the 14-day grace period after it ends, or when no seat is left and people who need to start can't; 3 for one person refused a seat with a workaround; 4 for a renewal coming up or a question about seats.

Renewals, more seats and new keys come from CG-Labs through the account owner; support owns the ticket meanwhile and keeps the customer working. The setting itself is in the [deploy guide](../../deploy/README.md#license).

## First five minutes

1. **What they see.** Bots refusing to run, a banner about the license, a key the console or `botctl license install` refused (and its message), or someone who can't be added or re-enabled.
2. **The license**, as an admin on the server:

   ```sh
   botctl license                                    # where it comes from, its mode, edition, seats in use, when it ends
   botctl audit 20 --action 'license.*'              # installs, removals, refusals, status changes, seats refused
   ```

   With botd down or before installing a key, `botd license check` says what botd makes of the license as its start reads it, and `--key-file <file>` judges a new key first, changing nothing ([ADR 0305](../adr/0305-the-license-through-offline-upgrades.md)). A support bundle carries the [health score](health-score.md#license)'s `license` signal (mode, usable, seats, days left), and `botd support check` its `license` finding ([support check](support-check.md#license)).
3. **Did anything change?** An upgrade (a release can stop trusting an old signing key), a rollback that put back an older key, a renewal for fewer seats, `LICENSE_KEY` or `LICENSE_KEY_FILE` edited, `TESTING_MODE` turned off, the server's clock.

## Modes

| Mode | What it means | Do |
|---|---|---|
| `active` | A license this server accepts, before its end | Nothing, unless it ends within 30 days (admins are warned, and the score is watch): start the renewal with the account owner now |
| `grace` | It ended less than 14 days ago and is still honoured | Severity 2: the renewal goes to the account owner today. Bots stop when the grace ends |
| `expired` | It ended more than 14 days ago: no longer a license | Bots have stopped. Install the renewed key; meanwhile nothing runs |
| `invalid` | A key is set that this server doesn't accept | `botctl license` says why, with one of the reasons below |
| `unlicensed` | No key at all | Install the key CG-Labs sent; a test server can run with `TESTING_MODE=on` instead |

## Reasons and fixes

Why a key isn't a license, from `botctl license`, `botd license check` or `license.refused` when an install was refused:

| Reason | Usually | Fix |
|---|---|---|
| `malformed` | Not a whole key: cut short, wrapped with extra characters, or another file | Paste the whole key, three parts separated by dots, or install from the file: `botctl license install <file>` |
| `bad_algorithm`, `wrong_audience`, `bad_claims` | Not a SuperBot self-host license, or one missing its licensee, id, edition, seats or dates | Ask CG-Labs for the key again, through the account owner |
| `unknown_key` | Signed with a key this release doesn't know: a newer key on an older botd, or an old key a newer release no longer trusts | Upgrade botd, or ask CG-Labs for a key signed with a key this release knows. After an upgrade, check with `botd license check` before and after ([upgrades](runbook-upgrade.md)) |
| `bad_signature` | The key was changed after it was issued, or wasn't issued by CG-Labs | Install the key as CG-Labs sent it. A key from anyone else is a [security](escalation.md#security-incidents) question |
| `not_yet_valid` | It starts later, or the server's clock is behind | Check the clock (`timedatectl`); install it once it starts |
| `expired` | The key being installed has already ended | Install the renewed key, not the old one |
| `set_in_env` | `LICENSE_KEY` or `LICENSE_KEY_FILE` sets the license, so the console and `botctl license install` can't change it | Change the setting in `.env` and restart botd, or remove it to manage the key from the console |
| `unreadable` | `LICENSE_KEY_FILE` names a file botd's user can't read | Fix the path or its owner and mode, then restart |
| `ambiguous` | Both `LICENSE_KEY` and `LICENSE_KEY_FILE` are set | Keep one, then restart |

Each install is audited as `license.installed`, each removal as `license.removed`, and each change of mode botd sees by itself (an end, a grace that runs out) as `license.status_changed`.

## Seats

A seat is an active user, the owner account aside. Over the limit nobody is signed out or disabled, but adding or re-enabling people is refused until a seat is free: by an admin, an invitation, SSO's just-in-time sign-up or SCIM (`status_403` in the [SCIM runbook](runbook-scim.md#reasons-and-fixes)). Each refusal is audited as `license.seat_refused`, with how many seats are used and allowed.

1. `botctl license` shows seats in use against the license's. The health score is watch at 90% and at risk when more people are active than it covers.
2. Free seats now: `botctl users` lists people; those who left should be disabled (`botctl user disable <user>`), by SCIM when the IdP's assignments are right.
3. Need more: the account owner asks CG-Labs for a key with more seats, then `botctl license install`.

## Bots stopped

Runs are refused with reason `unlicensed` (`bot.run_refused`), and each Bot says why in its chat.

1. `botctl license`: the mode and why. Fix it from the tables above.
2. A renewed key is the only fix on a production server. If it's coming, keep the customer updated hourly as Severity 1 until it's installed; never suggest `TESTING_MODE=on` for production, which turns billing off and puts a testing banner on every screen.
3. Air-gapped servers need the key carried in by hand ([air-gapped runbook](runbook-air-gapped.md#license)); check it with `botd license check --key-file <file>` before installing it.
4. Once installed, `botctl license` shows `active`, and Bots run again without a restart.

## Escalate when

- A key CG-Labs issued is refused with `bad_signature`, or `unknown_key` on the newest release.
- `botctl license` shows `active` but runs are still refused with reason `unlicensed`.
- The seat count doesn't match the people the customer sees as active.
- A renewal is late from CG-Labs and the grace period is ending: to the account owner and the support manager ([escalation](escalation.md)).

## Afterwards

Note the cause in the ticket. Put the new end date and seat count in the customer's record, and the renewal on the TAM's calendar 90 days ahead ([TAM cadence](tam.md#cadence)); `botctl tam-cadence` lists renewals within 90 days from the CRM's export ([TAM cadence check](tam-cadence.md)).
