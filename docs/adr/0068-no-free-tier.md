# 0068: No free tier; testing mode with billing off

## Status

Accepted (21 Nov 2026). Product decision by the owner. Replaces the community edition in [ADR 0038](0038-self-host-license-key.md) (self-host license), and changes how billing turns on from [ADR 0040](0040-billing-v0-tier-limits.md), [ADR 0042](0042-billing-checkout-portal-customers.md), and [ADR 0050](0050-billing-period-token-usage.md). Tiers and hidden models ([ADR 0033](0033-tiers-model-routing.md)) are unchanged.

0066 is taken by removing teammate accounts ([PR #124](https://github.com/CG-Labs/superbot/pull/124)) and 0067 by clearing enrollment data from containers ([PR #125](https://github.com/CG-Labs/superbot/pull/125)), so this is 0068.

## Context

ADR 0038 gave every server without a license a free "community edition": every feature, for up to 10 active people. The owner decided SuperBot has no free tier: no 10-seat community limit and no unlicensed free use. Every deployment runs on a paid tier. The tier names stay (Starter, Pro, Max, Enterprise, and the built-in self-host tier a license covers), and users never pick or see models.

We are still testing. Billing must stay off: no Stripe calls, no charges, and no real keys. Release builds trust no license signing keys yet (`TRUSTED` is empty), so no real server can have a valid license today. The dogfood server needs a way to run that is clearly not a free tier.

## Decision

### No license means no use, unless testing mode is on

| State | Seats | Bots run | Edition |
|-------|-------|----------|---------|
| License `active` or `grace` | the license's | yes | the license's |
| No license, or `expired` / `invalid`, `TESTING_MODE` off | 0 | no | `none` |
| No license, or `expired` / `invalid`, `TESTING_MODE=on` | no limit | yes | `testing` |

- **Unlicensed** (the mode was `community`) has no seats. Nobody new can be added or re-enabled, by any route (admin, sign-up approval, SSO just-in-time, SCIM), and every Bot run is refused with `bot.run_refused` (`reason: unlicensed`) and a plain reply: "this server has no SuperBot license, and SuperBot has no free tier". botd still starts, nobody is signed out, and admins can sign in (the owner account always works) to install a key. That is the only way out besides testing mode.
- A license allows exactly the seats it names. The old rule that a license never allows fewer than 10 is gone.
- An ended license keeps its grace period, then stops: no free fallback.
- **Testing mode** is `TESTING_MODE=on` in botd's environment (the installer's `--testing-mode` writes it). The operator has to turn it on: it is off by default, and nothing turns it on by itself. It lifts the seat limit, lets Bots run, and keeps billing off. A valid license always wins over it.
- Testing mode is loud, never silent: botd's start-up log warns about it, `GET /api/license` returns `testing: true` and edition `testing`, the console's License card and the setup wizard call it "Testing mode" and say billing is off, and the audit log records the change (`license.status_changed`, and `server.started` includes it in the license summary).
- The dogfood server runs with `TESTING_MODE=on`. Test servers built in the test suite start in testing mode for the same reason. Tests that check the unlicensed rules turn it off.

### Billing is off by default

- botd reads Stripe settings only with `BILLING=on`. Without it, no Stripe client is built, so no webhook, checkout, portal, or meter call can happen, even if `STRIPE_*` values are present. botd warns at start that they are ignored, naming the variables, never their values.
- `BILLING=on` with `TESTING_MODE=on` is refused at start. Testing mode always means billing off.
- Everyone sees it plainly. The Plan screen says "Billing is off during testing. Nothing is charged, and no payment details are taken." The billing API's 404 says the same. The console's License card shows "Billing is off during testing: SuperBot makes no Stripe calls and charges nothing." (`GET /api/license` → `billing`). The start-up log says "Billing: off during testing".

### Copy

The community edition and the 10-seat limit are removed from the code, the console, the setup wizard, the installer, `botctl`, the `.env` examples, the deploy guide, and the roadmap. The landing page and the app's copy already describe per-user plans by approval. Nothing describes a free plan.

## Tests

- `license::tests`: an unlicensed server has 0 seats, edition `none`, isn't usable, and warns admins; an ended license falls to 0 seats, not 10; a license allows exactly its seats; `TESTING_MODE` parses on and off and is off by default; testing mode lifts the limit, says billing is off, and loses to a license; an ended license on a test server keeps running and says why.
- `license_http_tests.rs`: without a license or testing mode, adding people is refused with a clear message, nobody is locked out, and the setup checklist isn't done; a license or testing mode fixes it; Bots don't run without a license or testing mode (audited as `unlicensed`) and run again with a license; sign-up approval, SCIM, and SSO sign-ups get no seat while unlicensed; the license view reports billing off.
- `billing::tests`: billing is off without `BILLING=on`, even with Stripe settings (which warn, without showing the secret); testing mode keeps it off and refuses `BILLING=on`; only `BILLING=on` reads the Stripe settings.
- Client: the Plan screen shows the billing-off message and no upgrade buttons.
- `deploy/test-install.sh`: only `--testing-mode` writes `TESTING_MODE=on`, and the help says there's no free tier.

## Consequences

- On upgrade, a server without a license and without `TESTING_MODE=on` stops running Bots and can't add people. That is intended. Today that is every real server, because release builds trust no signing keys yet, so the dogfood server (and any other test server) must set `TESTING_MODE=on` before it is upgraded.
- Enforcement is honest-user enforcement, as in ADR 0038: the source is open, so anyone can build botd without it.
- Turning billing on later takes `BILLING=on`, real Stripe keys, and testing mode off: three deliberate steps, so testing can't charge anyone by accident.
- Selling self-host licenses still needs CG-Labs to commit its public signing key to `TRUSTED` (ADR 0038).
