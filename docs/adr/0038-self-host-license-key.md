# 0038: Self-host license key

## Status

Accepted (20 Nov 2026). Part of [#34](https://github.com/CG-Labs/superbot/issues/34) (M3, billing and licensing). Builds on users and RBAC ([ADR 0012](0012-users-sessions-rbac.md)), the audit log ([ADR 0009](0009-audit-events.md)), tiers ([ADR 0033](0033-tiers-model-routing.md)), and the setup wizard ([ADR 0034](0034-onboarding-wizard.md)).

0037 is per-user Unix accounts ([ADR 0037](0037-per-user-unix-accounts.md), [PR #94](https://github.com/CG-Labs/superbot/pull/94)), so this is 0038.

## Context

The roadmap's business model sells two things: managed hosting (Stripe, tiers) and a license for self-hosted servers. Self-host had no way to say who a server is licensed to or how many people it covers. The license has to work on servers with no outbound network, must not let a typo or an ended contract take a company's assistants offline, and must not be forgeable by editing a file or the database.

## Decision

### The key

A license is a compact JWT signed with Ed25519 (`alg: EdDSA`, a `kid` naming the signing key). Claims:

| Claim | Meaning |
|-------|---------|
| `iss`, `aud` | `CG-Labs`, and `superbot-self-host`. A token for any other audience is refused, so the same signing key can't be reused to mint something that passes as a license. |
| `sub` | The licensee, shown to admins. |
| `jti` | The license id, a slug. Audit events target it. |
| `iat`, `nbf`, `exp` | Issued, starts (optional), ends. Unix seconds. |
| `seats` | Active people it covers. Absent: unlimited. |
| `edition` | A name, e.g. `business`. |
| `features` | Names paid modules may check with `Status::allows`. Nothing in this repository is gated: every feature in the open source code works for everyone. |

Unknown claims are ignored, so older servers read newer licenses. botd checks only `EdDSA`, only `kid`s it knows, rejects `crit`, bounds the token at 8 KiB, and parses the payload only after the signature verifies. A license that hasn't started (`nbf`, 5 minutes' clock skew allowed) is invalid until it starts; a key set in the environment early takes over on its start date without a restart. Expiry is not a verification failure: an ended license is still a license, and the mode below decides what it means.

The public keys are built into botd (`TRUSTED` in `server/src/license/mod.rs`), so licenses work offline and nobody can add a key by editing the server. Test builds also trust a fixed test key; release builds don't. The private keys never enter this repository.

### Signing

`superbot-license` (a separate binary in `server/`, not shipped in the image or by the installer) is CG-Labs's offline tool:

- `keygen --out <file> [--kid <id>]`: a new key pair. The private key goes to the file (PKCS#8 PEM, mode `0600`, never overwritten); the line to add to `TRUSTED` is printed.
- `sign --key <file> --kid <id> --licensee <name> (--expires <date> | --days <n>) [--seats <n>] [--edition <name>] [--feature <name>]...`: prints a license, after checking it as botd will.
- `verify (--key <file> | --public <kid>=<key>) [--at <date>] [<license>]`: what a license grants, and whether it's valid on a date.

It includes the same `token.rs` as botd, so both sides read and write one format. Rotating keys: add the new public key to `TRUSTED`, sign with it, and keep the old one listed until every license it signed has ended.

### Installing

In order of precedence: `LICENSE_KEY`, else `LICENSE_KEY_FILE` (both from botd's environment; setting both is an error, reported like any bad key), else `DATA_DIR/license.key`. Admins write that file through `PUT /api/license {key}`, which the console (Settings, and the setup wizard's Plans step), `botctl license install`, and the installer's `--license-file` use. The file is written atomically, mode `0600`, and backups include it. It takes effect at once. When the environment sets the license, the API refuses to change it (`409`), and the console says to edit `.env`, as the wizard does for SSO secrets set there. `DELETE /api/license` removes the file. `GET /api/license` shows the license, its mode, seats used and allowed, and warnings, never the key. Bots never get it either: `LICENSE_KEY` is a reserved secret name (not listed, saved, or passed to a Bot, locally or on a remote machine), and both variables are stripped from harness and job environments like `AUTH_PASSWORD`.

### Modes

| Mode | When | Seats | Features |
|------|------|-------|----------|
| `community` | No license | 10 | none |
| `active` | Valid, not ended | the license's | the license's |
| `grace` | Ended less than 14 days ago | the license's | the license's |
| `expired` | Ended longer ago | 10 | none |
| `invalid` | Set, but not a license this server accepts | 10 | none |

A license never allows fewer than the community edition's 10. Admins are warned 30 days before it ends, in the console, the wizard, `botctl license`, and botd's start-up log.

**Nothing bricks.** botd never refuses to start over a license, and no mode disables a feature that works without one. A bad key is logged at start, shown with its reason, and the server runs as the community edition.

### Seats

A seat is an active user other than the owner (break-glass) account, which always works so admins can't be locked out. Seats are checked inside the same database lock and transaction as every way a person becomes active: an admin adding or re-enabling someone, SSO just-in-time sign-up, approving an access request, and SCIM creating or re-activating a user. So concurrent requests can't both take the last seat. The `Db` holds a seat-cap callback the license sets at start; nothing else needs threading through.

Over the limit (a license removed or ended, or seats lowered), nobody is signed out, disabled, or loses a session. Only adding or re-enabling people is refused, with a `403` that names the limit and what to do; SSO sends people to `/login?error=sso_no_seat`, and a refused access request stays pending. Disabling people, renaming them, or changing roles needs no seat. A SCIM user provisioned inactive takes no seat until it is activated.

With per-user Unix accounts on ([ADR 0037](0037-per-user-unix-accounts.md), `ISOLATION=users`), a seat is still a person, not an account: each active user has at most one `sb-u-<id>` account, and making it, or logging a harness in as it, takes no extra seat. A disabled user keeps their account and folders but holds no seat, so botd won't make their account or start a harness login as them (`400`), and their Bots can't run. Re-enabling them needs a seat as usual.

The community limit is the default for a server without a license, including existing ones. That is the point of the license, but it means an upgraded server with more than 10 active people keeps everyone and can't add more until it has a license. The setup wizard's new checklist item, the console, and the start-up log say so.

### Audit

| Event | When |
|-------|------|
| `license.installed` | An admin installs a key (from and to, never the key) |
| `license.refused` | A key was refused: its reason (`malformed`, `bad_signature`, `unknown_key`, `expired`, `set_in_env`, …) and `kid` |
| `license.removed` | An admin removes it |
| `license.status_changed` | botd noticed a change nobody made through the API: a new key in the environment, a license entering grace or ending, a key that stopped verifying. Checked at start and every 10 minutes, recorded once per change across restarts. |
| `license.seat_refused` | Someone needed a seat and none was free: how (`admin`, `enable`, `signup`, `sso`, `scim`), who, used, and the limit |

The routes fall into the RBAC default arm (admins only, never a Bot) and are listed in `rbac.rs`'s route test and the router walk. `server.started` records the license summary.

### Tests

- `license::tests`: a signed license round trips; tampered payloads, another key under a trusted `kid`, unknown keys, `none`/`HS256`/`RS256`, `crit`, missing `kid`, junk and oversized tokens are refused; claims are checked before signing and after verifying; PEM keys round trip; the modes follow the clock (active, warned, grace, expired); bad settings never stop the server.
- `license_http_tests.rs`: install and remove (admins only, file mode `0600`, key never returned, audited, read back on restart); invalid, tampered, foreign, unknown-key, and expired keys refused and audited; the seat limit on admin create and re-enable, sign-up approval, SCIM create and re-activation, and SSO just-in-time sign-up; the community limit and nobody locked out after a removal; grace from the environment (and the API refusing to change it); status changes audited once.
- `superbot-license` tests: keygen, sign, and verify round trip; bad arguments refused; keys never overwritten.
- CI: the installer's `--license-file` (dry run, refusal of a bad file, the real write as the service user).

## Consequences

- CG-Labs must run `superbot-license keygen` offline, keep the private key safe, and commit its public half to `TRUSTED` before selling a license. Until then, release builds trust no keys and every server is the community edition.
- Seat limits are honest-user enforcement: the source is open, so anyone can build botd without them. The license is for organisations that want a supported, licensed install, not DRM.
- The community limit applies to existing servers on upgrade. Nobody loses access, but large unlicensed installs can't add people until they have a license.
- Paid modules can gate themselves on `features` later without a new license format.
