# Change management policy

How changes to SuperBot's code and to the managed service reach production: who reviews them, what must pass, and what happens in an emergency. Part of the [policy set](README.md). **Draft, not adopted. SuperBot is not SOC 2 certified.**

| Field | Value |
|-------|-------|
| Owner | Engineering lead |
| Approver | Management |
| Review | Yearly |
| Status | Draft, not yet approved |
| Controls | CC3.4-1, CC5.2-1, CC5.2-2, CC7.1-1, CC7.1-2, CC7.1-3, CC8.1-1, CC8.1-2, CC8.1-3 |

## Scope

- **Code changes**: anything merged to `main` in this repository, including dependencies, workflows and docs.
- **Releases**: tags and the images published from them.
- **Production changes**: upgrading a managed server or host, changing its settings, the tiers file, the hosting or storage accounts, DNS, or anything else that runs the service.

## Code changes

1. Every change reaches `main` through a pull request. Nobody pushes to `main` directly, and nobody rewrites its history.
2. CI must pass. It runs the tests for what changed: unit and HTTP-route tests including a walk of every route for the right role, isolation tests, backup and restore drills, the harness hook tests, the Incus suite, dependency and image scanning, and the docs checks ([`.github/workflows/`](../../../.github/workflows/)).
3. A significant design change has an ADR in [`docs/adr/`](../../adr/), in the same PR or before it.
4. A change that makes a statement in the [security pack](../README.md), a policy or the readiness checklist wrong fixes it in the same PR, and a change to a control says so in the PR description. This is how changes that affect controls are reviewed.
5. User-facing changes are added to [`CHANGELOG.md`](../../../CHANGELOG.md) in the same PR ([ADR 0111](../../adr/0111-changelog-and-github-releases.md)).

## Reviews and segregation of duties

- Every pull request is approved by someone other than its author before it merges. An automated reviewer's findings are answered, but don't count as the approval.
- `main` is protected in GitHub so that this is enforced: a required approval, required status checks, no force pushes, no deletion, and administrators included. The engineering lead exports these settings quarterly as evidence (checklist CC8.1-1).
- Each month's [change-management bundle](../soc2-evidence-plan.md#the-change-management-bundle) lists every pull request merged into `main` with its approvers and checks, and every commit that reached it without one ([ADR 0148](../../adr/0148-change-management-evidence-from-github.md)). The engineering lead reviews its exceptions (merged without an approval by someone other than the author, without required checks passing, or straight to `main`) and records why each happened, as an emergency change or otherwise.
- A change written by an agent is reviewed like anyone else's, by a person.
- Whoever approves a production change is not the person who makes it, except in an emergency.

## Dependencies and the supply chain

- Dependencies are pinned in lockfiles, and `cargo audit` and `npm audit` run on every lockfile change and weekly ([ADR 0092](../../adr/0092-dependency-vulnerability-scanning.md)). Findings are fixed, or accepted with a reason in [`.cargo/audit.toml`](../../../.cargo/audit.toml) or [`.grype.yaml`](../../../.grype.yaml), within the [information security policy's deadlines](information-security.md#vulnerability-management).
- GitHub Actions are pinned to full commit SHAs, updated by Dependabot ([ADR 0100](../../adr/0100-github-actions-pinned-by-commit.md)).
- Published images are scanned, signed with cosign and attested with build provenance and an SBOM ([ADR 0101](../../adr/0101-image-scanning-and-signing.md)). Operators verify signatures before deploying ([verifying the images](../../../deploy/README.md#verifying-the-images)).

## Releases

An engineering lead dates the version's section of `CHANGELOG.md` and tags `v<version>` on `main`; the `release` workflow checks it and publishes the GitHub release, and the docker workflow publishes the images. Only tags on `main` that pass the checks are released.

## Production changes

- Each production change is recorded before it is made: what, why, the risk, how to roll back, who approved it. A pull request, an issue or a change ticket all work.
- Planned changes that may interrupt the service are announced on the status page at least 48 hours ahead as maintenance, within the [SLO's](../../slo.md) limits.
- Managed servers run a released, signed image or binary, upgraded by changing `SUPERBOT_VERSION` or the installer's version, never a build from someone's machine. Before an upgrade the operator takes a backup and checks that it was copied off the host (`botctl backups`).
- After a change, the operator checks the service (health, `/status`, alerts) and checks the server against the [configuration baseline](information-security.md#configuration-baseline), the same or the next business day.
- Whoever makes a change has production access to that system on record ([access control policy](access-control.md#granting-access)).
- The engineering lead or operator enters each production change in the [policy register](../policy-register.md#production-changes), by id, with the change record's SHA-256, when it was recorded, approved, made and checked, and by whom; the monthly register bundle checks them against this policy ([ADR 0270](../../adr/0270-production-changes-in-the-register.md)).

## Emergency changes

When an incident needs a change faster than review allows, the incident commander may approve it ([incident response plan](incident-response.md)). The change is recorded in the incident, reviewed by a second person within 2 business days (someone who neither made nor approved it), and, if it was code, goes through a normal pull request within 5 business days. Emergency changes are listed in the next quarterly management review. They are entered in the policy register like any other production change, with the incident, the review and the pull request.
