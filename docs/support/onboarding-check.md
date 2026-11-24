# Onboarding check

Where a customer stands on the [onboarding checklist](onboarding.md), worked out from botd's own settings and records ([ADR 0233](../adr/0233-onboarding-check.md)). For each of the 32 items it says whether botd sees it done, what's still open with the guide that does it, and what's left for a person to confirm with the customer. It's for the technical account manager or support engineer taking a customer from signed to live: run it at kickoff, at each weekly onboarding call, and before go-live is confirmed in writing.

`botctl onboarding` does it, on the customer's server, signed in as an admin (`BOTD_TOKEN`, or the password). The console's API serves the same report at `GET /api/support/onboarding`, and the console's Support tab shows it ([below](#in-the-console)). Every [support bundle](support-bundle.md) carries it too, as `onboarding.json` ([ADR 0243](../adr/0243-onboarding-check-in-the-console-and-the-bundle.md)).

## Running it

```sh
# Section by section, then what's open
botctl onboarding

# For the customer's onboarding record, as a Markdown checklist
botctl onboarding markdown > onboarding-check.md

# Items agreed at kickoff that this customer doesn't need
botctl onboarding --skip database_encryption,scim

# For a CRM or ticket system's hook
botctl onboarding json
```

| Option | What it does |
|---|---|
| `--skip <item,...>` | Items agreed at kickoff that this customer doesn't need, by id ([below](#the-items)), comma-separated. An open or to-confirm item becomes `skipped`. Write the agreement in the onboarding record too: the skip is how the check knows, not the record of it |
| `markdown` | A checklist per section for the onboarding record: ticked when done, struck through when it doesn't apply, and each open item with its guide. `--markdown` works too |
| `json` | The report as botd sends it ([below](#the-api)). `--json` works too |

It prints the report on stdout and exits 1 while any item is open, so a script can wait for go-live readiness. An unknown option or item id is an error, with the ids there are.

Each check is recorded in the audit log as `support.onboarding_checked`, with the open and skipped ids and the counts. The skips aren't kept anywhere else: pass them each time.

## What it says

Each item has one of five statuses:

| Status | Means | What to do |
|---|---|---|
| `done` | botd sees it done | Tick it in the onboarding record. Some say what's left to check by eye, like metrics' alert rules |
| `open` | botd sees it isn't done | Follow the detail and the guide. Go-live waits until no item is open |
| `confirm` | botd can't see it: it's in the support system, at the identity provider, or a person's to judge | Confirm it with the customer, then tick it in the record |
| `n/a` | It doesn't apply to this server, like data regions on a server that offers none | Nothing |
| `skipped` | Agreed at kickoff that this customer doesn't need it (`--skip`) | Nothing; check the agreement is in the record |

A skipped item that's done or doesn't apply anyway is listed at the end, so a stale skip can go.

Each item's detail is codes and counts, and provider ids such as `okta`: never a person's name or email, an address, a bucket or the licensee. So the report can go in the customer's onboarding record, or a ticket, as it is.

## The items

In the checklist's order. "botd sees" is what turns an item `done`; anything else stays `open` or `confirm`.

### 1. Kickoff

| Item | botd sees |
|---|---|
| `plan` | Always `confirm`: the plans this server sells and the seats in use, for the plan, seats and support tier agreed |
| `contacts` | Always `confirm`: contacts live in the support system |
| `deployment` | `done` when the license is in order; `open` in testing mode with no license, or when the license isn't in order (`botctl license`) |
| `region` | `confirm` when the server offers data regions (`MACHINE_REGIONS`); `n/a` when it offers none |
| `security_pack` | Always `confirm` |
| `go_live_date` | Always `confirm` |

### 2. Identity: SSO and SCIM

| Item | botd sees |
|---|---|
| `idp` | `done` when every single sign-on provider is ready (its secret or IdP metadata in place); `open` with none, or with one waiting |
| `sso_admin` | `done` when an active admin besides the owner account has signed in with SSO (an `auth.login` by SSO in the audit log) |
| `jit_allow_list` | `done` when just-in-time sign-up is off, or on with the allow-list botd requires before it starts; `n/a` with no provider |
| `mfa` | `done` when SuperBot requires a second factor (`AUTH_MFA=admins` or `all`); `confirm` when SSO relies on the identity provider's MFA, which botd can't see; `open` with neither |
| `scim` | `done` when SCIM has a working token (not revoked, expired or ending within 14 days), a working token was used in the last 30 days (a revoked one's use doesn't count), and SCIM has deprovisioned someone, which is the test the checklist asks for; `confirm` when SCIM is off |
| `break_glass` | `done` when break-glass sign-in is off (`AUTH_BREAK_GLASS=0`) |
| `signin_alerts` | `done` when suspicious sign-ins are reported (`SIGNIN_ALERTS`) |

### 3. Isolation

| Item | botd sees |
|---|---|
| `isolation` | `done` when every Bot runs on its owner's machine (`MACHINE_ROUTING=on`) or as its user's own Unix account (`ISOLATION=users`); `open` while any runs as botd's own account |
| `hardening` | `done` when machines are hardened at first boot (`MACHINE_HARDENING`), with the count of plans in `MACHINE_OWN_KERNEL_TIERS`; `n/a` with no machines |
| `approvals` | `confirm` when Bots ask before risky actions and every Bot's approval notice reaches someone: an email address, a webhook, or a decider's registered phone (with no Bots yet, the global settings); `open` when approvals are off (bypass) or some Bot's notice reaches no one |
| `teams` | Always `confirm`, with the count of teams |

### 4. Backups and recovery

| Item | botd sees |
|---|---|
| `server_backups` | `done` when server backups are copied off the host (`SERVER_BACKUP_S3_BUCKET`), the newest copy is within its RPO and was itself encrypted, and every backup target is encrypted (`botctl backups`) |
| `keys_off_host` | Always `confirm`: where the age identity and master key are kept is for two people to know |
| `database_encryption` | `done` when the database is encrypted at rest. Skip it if the customer doesn't require it |
| `machine_backups` | `done` when machines are backed up (off-host, or the provider's) and none is past its RPO (`botctl machine recovery`); `n/a` with no machines |
| `restore_drill` | Always `confirm`, with the machine restores botd recorded in the last 180 days. A drill's times against the RTO are for a person to record |
| `recovery_objectives` | Always `confirm` |

### 5. Data residency

| Item | botd sees |
|---|---|
| `residency_region` | `done` when a user or team has a region (or a residency pin exists) and `botctl regions` has no warnings; `n/a` with no data regions |
| `backup_region` | `done` when `MACHINE_BACKUP_RESIDENCY=strict`, or every region's machine backups go to a store in it; `n/a` with no data regions or no off-host machine backups. Where the server backups' bucket is stays for the customer to accept |
| `model_providers` | Always `confirm` |

### 6. Monitoring and go-live

| Item | botd sees |
|---|---|
| `status_page` | `confirm` when the status page is on, since botd can't see the outside probe on `/status.json`; `open` when it's off (`STATUS_PAGE=off`) |
| `metrics` | `done` when metrics are on (`METRICS_LISTEN`, last seen at botd's start). The alert rules and log shipping are still for a person to check |
| `setup` | `done` when every item of `botctl setup` is done; `open` names the ones that aren't |
| `first_bundle` | `done` once a support bundle has been made (`botctl support-bundle`) |
| `pilot` | Always `confirm`, with how many people signed in or used SuperBot in the last 7 days |
| `go_live` | Always `confirm`: go-live is confirmed in writing, with the support channels and escalation contacts |

## The API

`GET /api/support/onboarding`, for admins only (custom roles don't reach it, [ADR 0123](../adr/0123-custom-roles.md)). The one parameter is `skip`, the same comma-separated ids as `--skip`; any other is a 400. The JSON has:

- `format` (1), `checkedAt`, and `checklist` (`docs/support/onboarding.md`);
- `ready`: true when nothing is open;
- `counts`: `done`, `open`, `confirm`, `notApplicable` and `skipped`;
- `open`, `skipped` and `unneededSkips`: item ids;
- `sections`: each section's `id` and `title`, in order;
- `items`: each item's `id`, `section`, `label`, `status`, `detail` and `guide` (a path in this repository, with an anchor where the page has one).

## In the console

The console's Support tab has an **Onboarding** section under the health score. Type any skips agreed at kickoff (the same ids as `--skip`, comma-separated) and press **Check onboarding**: it shows the counts, whether anything is open, and each item by section with its status, what botd saw and its guide. It checks only when you press the button, not when the tab opens, since each check is recorded as `support.onboarding_checked`. For the onboarding record, use `botctl onboarding markdown`.

## In the support bundle

Each [support bundle](support-bundle.md) has `onboarding.json`: this report with no skips, since skips aren't kept anywhere. The bundle's own `support.bundle_created` event records it; it isn't a separate `support.onboarding_checked`. [Bundle triage](triage.md) lists the items open in it as `onboarding.open`, for the TAM, with no severity: an open onboarding item isn't an incident. It leaves out `first_bundle`, since the bundle is one, and items agreed at kickoff show as open there, so check them against the onboarding record.

## Where it fits

- **At kickoff**, run it with the customer to see what's open, and agree the skips.
- **At each weekly onboarding call**, run it again; paste the Markdown into the onboarding record.
- **Before go-live**, nothing may be open, and each `confirm` item is confirmed with the customer. Then confirm go-live in writing ([escalation](escalation.md)) and start the [success cadence](onboarding.md#success-cadence).
- **After go-live**, the [health score](health-score.md) (`botctl health-score`) takes over.
