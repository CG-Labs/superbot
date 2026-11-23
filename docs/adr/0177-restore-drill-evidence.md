# 0177: Restore drill evidence bundles

## Status

Accepted (23 Nov 2026). Sixth slice of the SOC 2 Type II programme ([#57](https://github.com/CG-Labs/superbot/issues/57), M5). Adds a fourth command to `superbot-evidence` ([ADR 0148](0148-change-management-evidence-from-github.md)) and a fourth kind of bundle to the coverage report ([ADR 0169](0169-evidence-coverage-report.md)), which deferred coverage of drill evidence. Serves A1.3 (recovery testing) in the [evidence plan](../security/soc2-evidence-plan.md#the-drill-bundle).

## Context

A1.3 asks that recovery is tested, and an auditor samples the tests across the observation period. SuperBot runs four restore drills in CI (the installer's server restore onto a fresh host, ADR 0030; the Compose restore; an Incus container restored from its off-host backup, ADR 0074; a lost host's container restored onto another, ADR 0076), and two scripts operators run on their own servers (`deploy/backup-drill.sh`, `deploy/machine-restore-drill.sh`). The evidence was scattered and short-lived:

- The change-management bundle's `workflow-runs.json` says a workflow ran, not whether its drill step passed: `incus-e2e.yml` runs many steps, and a run can fail after the drill passed, or pass with the drill skipped.
- The drill timings are in artifacts GitHub deletes (14 days for some) and were downloaded by hand, with nothing recording what was downloaded.
- The operator's drills left terminal output; the plan said to keep "the last line", which the server drill didn't print and a failed machine drill didn't either.
- The coverage report couldn't show a month without drills, and the A1.3-1 row had no automated evidence at all.

## Decision

### `superbot-evidence drills`

`superbot-evidence drills --repo <owner/name> [--branch <name>] [--record <saved drill output>]... [--from <YYYY-MM-DD> --to <YYYY-MM-DD>] [-o <file>] [--no-ci]`, with the binary's period rules, GET-only GitHub client, token handling and private, never-overwritten output. It writes a bundle in the change-management bundle's shape, folder `superbot-drills-<from>_<to>-<UTC time>/`, manifest kind `recovery-drills`, with two files:

- **`ci-drills.json`** from the GitHub Actions API: each drill workflow's runs on the branch created in the period (one listing per workflow, filtered by date on GitHub's side, pull requests excluded), the latest attempt's jobs, and, for drills that keep them, the run's artifacts. Each drill is named in code by workflow, job name prefix (so each matrix job counts) and step name prefix. A job that skipped the drill's timing step didn't attempt the drill (the Incus versions botd refuses pass the drill's step by checking the refusal, and restore nothing), so it is left out and counted per workflow. For every other matching job: the step's outcome (passed, failed, cancelled, not reached, unfinished, or step not found, which falls back to the job's times and says so), its start and duration, the run's commit, event and url, and the job's own drill artifacts (named for its matrix variant, as `restore-drill-zabbly`) with GitHub's digest and expiry. Counted by drill with the median and longest passing time, and the exceptions an auditor asks about first: not run in the period, never passed, failing at the end (each matrix variant's latest result, so one version passing doesn't hide another still failing), each failure, step not found, a pass without its artifact, and artifacts already expired.
- **`operator-drills.json`** from `--record`: each drill script prints a JSON record line when it finishes, passed or not: the timed one once the restore is measured, even when it is over the objective, and otherwise a failed one from an exit trap, so a drill that dies under `set -e` still leaves one (`{"superbotDrill":1,"drill":…,"finishedAt":…,"passed":…,"durationMs":…,"rtoMs":…}`, plus the RPO check for the server drill and the restore and backup ids for the machine drill). The tool reads the last such line of the saved output, keeps only its known fields (ids only when they are plain), the file's base name, size and SHA-256, and refuses a record of a version or drill it doesn't know, one that finished outside the period, a pass without its timing, the same output twice, or a file over 16 MiB. Records are sorted by when they finished, with their exceptions: failed, over the objective.

`--no-ci` makes the bundle from records alone, with no token or network: the operator's drills run on servers that may never see GitHub. The monthly `change-evidence.yml` job makes one from CI alone with the workflow's read-only token (it already has `actions: read`), in the same artifact as the other bundles; the operator adds their records by running the command themselves.

### What counts

A CI drill passed when its step succeeded. Each drill already fails its step when the restore runs over its objective, so the step's result is the verdict and its duration, which includes setting up, is an upper bound on the restore. Reading the precise restore time would mean downloading artifacts: GitHub serves them as zips through a redirect to another host, and the client follows no redirects and leaves the API host for nothing. The bundle records each artifact's digest instead, so a copy downloaded by hand can be checked against it.

The manifest maps a file to its criteria and checklist rows (`ci-drills.json`: A1.2, A1.3 and A1.3-1; `operator-drills.json`: A1.3, CC9.1 and A1.3-1, CC9.1-2) only when the file holds at least one drill. A bundle for a month with no drills still checks, and still covers the kind, but leaves the rows uncovered, so the coverage report shows that month as a gap for A1.3-1 instead of as evidence.

### Coverage

The coverage report knows the fourth prefix, kind and format, expects both files in every drill bundle, counts its exceptions, and maps its rows. A store without drill bundles now reports that kind as missing, so a store complete under ADR 0169 isn't complete until drill bundles are added; that is the intent.

## Alternatives considered

- **Download and parse the drill artifacts**: the restore's own timing, but needs a zip reader and following a redirect off the API host with the token stripped, for drills whose step already enforces the objective.
- **Count workflow runs only**: no new API calls, but a run's conclusion isn't the drill's, and the matrix jobs and steps would be lost.
- **Have botd record operator drills**: botd sees the machine drill's restore as `machine.restored` (in `backups.json` already), but not the server drill, which replaces botd itself; the saved output with its digest works for both.
- **A free-form drill log the operator writes**: no tooling, but nothing ties it to a run, and it can't be checked.

## Tests

- Unit tests in `drills.rs`: a drill step is found by name, timed and judged, with only its own artifacts and their expiry; skipped, failed and renamed steps; tallies and every exception; records read from realistic output, keeping only known fields and the file's base name, with each refusal; a month without drills maps no controls, and records alone map only theirs; each workflow listed once, runs outside the period and in progress left out, matrix jobs counted, an unreadable workflow recorded and a server error fatal; each drill's job, step and artifacts exist in its workflow and both scripts print their record; names don't collide with the other bundles; every file maps to real criteria and checklist rows, and the evidence plan's table and drill names match.
- `server/tests/drill_evidence.rs`: the real binary against a stand-in GitHub API, with three workflows (one unreadable), two matrix jobs and expired artifacts, plus two records: the summary, the token on every request, nothing from the logs or the token in the bundle, `tar -xf` and `sha256sum -c`, the manifest, both files' contents, and `coverage` checking the bundle and covering CC9.1-2; a record from another period and the same output twice write nothing, and nothing is written over a file. Then the real `deploy/machine-restore-drill.sh` against a stand-in `botctl`, and `deploy/backup-drill.sh`'s record function, feed `drills --no-ci`, whose bundle holds both records with their timings.
- `evidence_coverage.rs` and `coverage.rs`: the fourth kind is expected, verified, mapped to A1.3-1 and CC9.1-2, and reported missing when absent; `change_evidence.rs` checks the workflow makes the drill bundle.

## Consequences

- A1.3-1 stays a Gap: the production-hardware drill still has to be run ([#29](https://github.com/CG-Labs/superbot/issues/29)); its record now has a place. CC9.1-2's yearly test can be recorded the same way.
- Renaming a drill's job or step breaks the unit test, not months of evidence; a new drill needs an entry in `DRILLS` and the evidence plan.
- The record line is a format: changing its fields needs `superbotDrill` bumped and the tool updated.
- The bundle names GitHub workflows, commits, run urls and artifact names; it holds no logs or artifact contents, and from the operator's output only the record's fields and a digest.

## Deferred

- Downloading the drill artifacts into the bundle, or checking downloaded ones against their digests automatically.
- Drill evidence for the tabletop and the yearly host-loss drill on production hardware, which are records people keep.
