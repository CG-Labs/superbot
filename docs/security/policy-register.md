# Policy register

The records the [policy set](policies/README.md) calls for that people keep, in one JSON file that `superbot-evidence register` checks against the policies' cadences and turns into a monthly [register bundle](soc2-evidence-plan.md#the-register-bundle) ([ADR 0204](../adr/0204-policy-register-checked-and-bundled.md)). Part of the SOC 2 Type II programme ([#57](https://github.com/CG-Labs/superbot/issues/57)). SuperBot is not SOC 2 certified; a register that checks shows records were kept and hold together, not that what they say happened, and the auditor decides what is enough.

## Keeping it

- **Private.** The register names people, so it lives in the security owner's evidence store, never in this repository. Start from the [template](policy-register-template.json), replace every `<...>` placeholder, date and zero digest, and give each person an id that isn't their name or email (`person-1`, `p-042`): ids are all the bundle carries.
- **As things happen.** Add a record when a role changes hands, a policy is approved, someone joins, acknowledges or trains, a risk is found or reviewed, management meets, a vendor is taken on or reviewed, or an exception is approved or reviewed. Records are only added or closed, never rewritten: the bundle's manifest records the register's SHA-256, and the register as read is kept beside each bundle.
- **Checked monthly**, with the other bundles:

```sh
superbot-evidence register register.json --policies docs/security/policies \
  --baseline baseline-<server>.json --from 2027-03-01 --to 2027-04-01
```

`--policies` is this repository's policy folder at the commit in force: each approval must be of that text (by SHA-256) and by someone holding the role the policy's header names as its Approver. Each `--baseline` is a server's `botctl evidence baseline json`, or the `baseline.json` in its evidence bundle, checked in the period; every setting it lists as excepted must have an approved exception in force that day. Without `--from` and `--to` the period is last month. It refuses a register that doesn't hold together, listing every problem, and writes nothing; otherwise it writes the bundle (never over a file) and prints what it found. Each finding is an exception in the bundle for the security owner to fix or explain, not a refusal.

## The format

One JSON object. Dates are `YYYY-MM-DD` (UTC days); a record dated on or after the period's end is left out of that period's bundle. Unknown fields are refused, so a typo can't hide a record. Ids are letters, digits, `.`, `_` and `-`, up to 64.

| Field | What it holds |
|-------|---------------|
| `superbotRegister` | The format, `1`. |
| `notes` | Free text for the register's keeper; never in the bundle. |
| `riskAppetite` | The highest risk score (likelihood times impact, 1 to 25) the risk owner may accept; above it, or with none set, only Management may. |
| `people` | Everyone with access to production systems or customer data: `id`, `name` (never in the bundle), `joined`, and `left` when they go. |
| `roles` | Assignments of the policies' roles (Management, Security owner, Engineering lead, Operator, People lead, Privacy lead): `role`, `holder`, `deputy`, `from`, and `until` when it ends. End the old assignment with `until` when a role changes hands, since a role's assignments mustn't overlap; each role needs a holder and a deputy, not the same person, every day. |
| `policyApprovals` | `policy` (its file name, such as `access-control`), `sha256` (`sha256sum` of the file as approved), `commit`, `approvedBy`, `approvedAt`. Each policy needs one within a year. |
| `acknowledgements` | `person`, `policy`, `at`. Everyone acknowledges the information security and acceptable use policies within 30 days of joining (or of the policy's first approval) and yearly. |
| `training` | `person`, `course`, `at`. Everyone takes `security-awareness` on the same terms. |
| `risks` | `id`, `title` (never in the bundle), `owner` (a role), `likelihood` and `impact` (1 to 5), `treatment` (`reduce`, `accept`, `transfer` or `avoid`), `controls` (readiness checklist row ids, such as `CC6.1-1`; a reduced risk needs one), `fraud`, `identified`, `reviewed` (dates), `closed`, `notes`; for an accepted risk, `acceptedBy`, `acceptedAt` and `acceptedUntil`, its next review. Each open risk is reviewed yearly, and at least one is a fraud risk. |
| `riskReviews` | Full reviews of the register: `at`, `by`. One a year. |
| `managementReviews` | `at`, `attendees`, `minutesSha256` (the minutes' SHA-256; the minutes go in the store). One a quarter, with Management and the security owner. |
| `vendors` | `id`, `tier` (`critical`, `high` or `low`), `hosting` (it runs the service, so its assurance report covers CC6.4), `since`, `until`, `assessed`, `approvedBy` (the security owner or Management), `reviewed` (dates), `notes`. Assessed before use and reviewed yearly. |
| `exceptions` | Exceptions to a policy: `id`, `policy`, `setting` (a [configuration baseline](configuration-baseline.md) setting, as in `BASELINE_EXCEPTIONS`), `approvedBy` (the security owner or Management), `approvedAt`, `ends` (within a year), `reviewed` (dates, each quarter), `closed`, `notes`. |

The cadences are the policies' ([information security](policies/information-security.md), [vendor management](policies/vendor-management.md), [the policy set](policies/README.md#adopting-them)): a year is 365 days and a quarter 92. Change them in the policies first, then in [`register.rs`](../../server/src/bin/superbot-evidence/register.rs), whose unit tests check the template against the policies.
