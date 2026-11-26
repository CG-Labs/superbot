# 0303: Branch protection judged against the policy

## Status

Accepted (26 Nov 2026). A slice of the SOC 2 Type II programme ([#57](https://github.com/CG-Labs/superbot/issues/57), M5). Changes the change-management bundle `superbot-evidence github` writes ([ADR 0148](0148-change-management-evidence-from-github.md)), and so what the coverage report counts for it ([ADR 0169](0169-evidence-coverage-report.md)). Serves readiness checklist row CC8.1-1, one of the rows the checklist says an auditor expects at least. No certification is claimed: SuperBot is not SOC 2 certified, no audit has started and no observation period has begun.

## Context

The draft [change management policy](../security/policies/change-management.md#reviews-and-segregation-of-duties) has `main` protected so that its reviews are enforced: a required approval, required status checks, no force pushes, no deletion, and administrators included. CC8.1-1 is a **Gap** because nothing protects `main` yet; turning it on is an admin's act, outside this repository.

The bundle already exported the protection as `branch-protection.json`, but only described it: nothing said whether it met the policy, and its manifest named CC8.1-1 for that file and for `pull-requests.json` whatever it said. So the coverage report counted every month of an unprotected `main` as covered for CC8.1-1, and once protection is on, a month it was weakened (an admin bypass added, a rule removed) would look the same as one it held. The description also left out who can bypass a ruleset, which is exactly what "administrators included" is about.

What a token can see makes this harder. Rules from active rulesets are shown to any token that can read the repository. Classic protection is shown only to tokens with Administration read, which the workflow's own token can't have. A ruleset's bypass list is shown only to tokens that can edit the ruleset. A judgement that treated what it couldn't see as fine would be worse than none.

## Decision

### Each setting judged, as far as the token sees

`branch-protection.json` gains `policy` and `exceptions`. For each of the policy's first four settings, every place that could enforce it is listed: each ruleset the branch's rules come from, classic protection, and the classic required checks that the branch itself shows to any token with whether they bind administrators (`enforcement_level` `everyone` or `non_admins`). A place enforces a setting or doesn't, or can't be seen, and nobody can bypass it there, someone can, or that can't be seen. To read who can bypass a ruleset, the export now reads each ruleset its rules come from once (`GET /repos/{repo}/rulesets/{id}`), keeping its id, name, source, enforcement and bypass actors by type, id and mode (ids only: no names).

- A setting is **met** when anything enforces it, **not met** when everything that could is seen not to, and **unknown** otherwise. An approval counts only when at least one is required.
- **Administrators included** is met when every setting that is enforced is enforced somewhere nobody can bypass: a ruleset whose bypass list is seen and empty, or classic protection with administrators included and, for pull request rules, nobody allowed to bypass them. It is not met when a setting is enforced only where someone can bypass it, or when nothing is enforced, and unknown while something that might enforce a setting without a bypass can't be seen. Any bypass actor counts, an app or deploy key as much as an admin: the policy has no exceptions for them, and an approved exception is the place to record one.
- `meetsPolicy` is true only when all five are met, false when any is not met, and null otherwise.

The exceptions are the settings not met, the settings the token couldn't see, and who can bypass the protection (each ruleset's bypass actors; classic protection not including administrators, or the number allowed to bypass its pull request rules, never their logins). The coverage report counts them with the other bundles' exceptions. The command's summary says whether the protection meets the policy and, when it can't tell, what it couldn't see and which token would.

### CC8.1-1 named only while it holds

The manifest names CC8.1-1 for `pull-requests.json` and `branch-protection.json` only while `meetsPolicy` is true, and records `protectionMeetsPolicy`. Otherwise `pull-requests.json` still names CC3.4-1 and CC8.1-2, since its pull requests are still the population to sample changes from, and `branch-protection.json` names nothing, being evidence of nothing else. The bundle's format is 2. This follows the alerts, egress, secrets and audit integrity files, which name their rows only for a period the control held ([ADR 0288](0288-alert-history-evidence-from-prometheus.md), [ADR 0285](0285-product-access-controls-in-the-evidence-bundle.md), [ADR 0261](0261-audit-integrity-evidence.md)).

The protection is as it stood at the export, not through the month: GitHub keeps no history of classic protection that a read-only token can read. The month's own exceptions (pull requests merged without an approval or checks, pushes straight to `main`) show a lapse during it, and are reviewed in full under the policy.

### A token that can see it

The `change-evidence` workflow keeps its own read-only token for everything, except that the change-management export uses a `CHANGE_EVIDENCE_TOKEN` secret when one is set: a fine-grained token with read-only Administration, Contents, Pull requests, Actions, Checks and Commit statuses, which sees classic protection. Where rulesets protect `main`, their bypass lists need a token that can edit them, which a scheduled workflow shouldn't hold: an admin makes that month's bundle (the manifest records a classic token's scopes, and the export warns when they can write), or the month stays unknown and the quarterly admin export covers it. The evidence plan's quarterly step now saves each ruleset as well as classic protection.

## Alternatives considered

- **Unknown counts as met**: the workflow's token would then name CC8.1-1 for a ruleset an admin can bypass, which is the case the policy's last setting exists for.
- **Judging the policy without reading rulesets**: the rules for a branch don't say who can bypass them, so administrators included could never be met from rules alone.
- **Shipping a ruleset to import**: every workflow here runs only on the paths it covers, so a required check would block every pull request that doesn't touch them; choosing which checks to require (or adding a check every pull request runs) is a decision for whoever turns protection on, not this slice.
- **Reading rule suites for bypasses during the month**: GitHub's rule insights record each bypassed push, which would show a lapse through the period, but they also need more than read access and cover rulesets only; later work if the auditor wants it.
- **Leaving `pull-requests.json`'s CC8.1-1 alone**: the coverage report would still show CC8.1-1 covered every month through that file, hiding the gap the judgement finds.

## Tests

- Unit tests in `changes.rs`: an unprotected branch meets none of the settings; a ruleset nobody can bypass meets all five whatever classic protection hides; a ruleset whose bypass list is hidden, or refused, leaves administrators included unknown; bypass actors make it not met where classic protection is seen, and unknown where it is hidden; a ruleset requiring no approvals is not an approval; neither rulesets nor classic protection seen leaves every setting unknown; classic protection with administrators included meets them, with someone allowed to bypass its pull request rules doesn't, counted and never named, and without administrators included doesn't, unless a ruleset nobody can bypass covers it; the branch's own required checks bind administrators or not by their enforcement level; the manifest names CC8.1-1 only while the policy is met, and `branch-protection.json` names nothing otherwise.
- `server/tests/change_evidence.rs`: the real binary against the stand-in GitHub reads the ruleset once; with a token the bypass list is hidden from, the four settings are met, administrators included is unknown, the summary says so, and the manifest leaves out CC8.1-1; with a token it's shown to (empty), the summary says the protection meets the policy and the manifest names CC8.1-1 for both files. The workflow test allows only its own token, or the `CHANGE_EVIDENCE_TOKEN` secret for the change-management export alone, still with read access only.
- `coverage.rs` counts `branch-protection.json`'s exceptions; the evidence plan's table still matches `SECTIONS`.

## Consequences

- Until `main` is protected, every change-management bundle says the policy is not met and the coverage report shows CC8.1-1 as a gap, which it is. The checklist row stays a **Gap**.
- Once an admin protects `main`, the monthly bundle shows it meeting the policy only if its token can see enough: with the workflow's own token alone, administrators included stays unknown. Setting `CHANGE_EVIDENCE_TOKEN` (classic protection), or an admin making the bundle (rulesets), closes that.
- A bypass actor added for convenience shows up the next month as an exception and a gap, to remove or record as an approved exception.
- Older change-management bundles (format 1) keep their manifests as written; the coverage report reads either.
