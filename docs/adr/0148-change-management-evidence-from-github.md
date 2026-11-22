# 0148: Change-management evidence exported from GitHub

## Status

Accepted (22 Nov 2026). Third slice of the SOC 2 Type II programme ([#57](https://github.com/CG-Labs/superbot/issues/57), M5). Builds the item [ADR 0142](0142-type-ii-evidence-bundles.md) deferred, exporting CI runs and merged pull requests from GitHub, in the bundle format it set, and writes the configuration baseline [ADR 0130](0130-policy-set-and-type-ii-evidence.md) deferred. Serves the [evidence plan](../security/soc2-evidence-plan.md) and the [change management policy](../security/policies/change-management.md).

## Context

For CC8.1 an auditor takes the population of changes in the observation period and samples it: was each authorised, tested and approved by someone other than its author, and did the controls that should enforce that (branch protection, required checks) exist? The plan asked the operator to run `gh pr list`, `gh run list` and `gh api .../protection` by hand each month and quarter. Three problems:

- **GitHub forgets.** Workflow logs and artifacts expire after 90 days, and an export not made at the time can't be made later.
- **`gh`'s output isn't the evidence.** `statusCheckRollup` doesn't say which checks were required, `reviews` doesn't say whether an approval came from the author, a Bot or after the merge, and nothing shows commits that reached `main` without a pull request.
- **botd can't do it.** botd doesn't know GitHub, and giving every server a GitHub token would put a credential where it isn't needed. `botctl` is a small HTTP/1.0 client with no TLS.

## Decision

### A separate Rust binary

`superbot-evidence github --repo <owner/name> [--branch <name>] [--from <YYYY-MM-DD> --to <YYYY-MM-DD>] [-o <file>] [--no-titles]` is a new binary in the `botd` crate (`server/src/bin/superbot-evidence/`). It uses dependencies the crate already has (reqwest with rustls, tokio, serde_json, sha2, chrono) and shares the period rules and the tar writer with botd through two small modules split out of the evidence and support bundles (`evidence_period.rs`, `ustar.rs`), so both bundles have the same periods: whole UTC days, `from` included and `to` not, last month by default, at most 400 days, ending no later than tomorrow. The branch defaults to the repository's default branch.

### A read-only token, kept out of everything

- The token comes only from `GITHUB_TOKEN` or `GH_TOKEN`. `--token` is refused, so it is never in shell history or a process list.
- It is sent only to the API's own host: `GITHUB_API_URL` (for GitHub Enterprise Server) must be `https://`, or `http://` to loopback for tests, with no credentials, query or fragment in it, and pagination follows a `Link` only on that host. Redirects aren't followed.
- A classic token with a write scope (`repo`, `public_repo`, `workflow`, any `write:` or `admin:`) gets a warning, and the manifest records its scopes and whether it can write. A fine-grained token or the workflow's own token has none to show.
- The bundle is never written if its bytes contain the token. It holds no pull request, review or comment bodies, commit messages, emails, logs or artifacts; people are GitHub logins; titles can be left out with `--no-titles`.
- Read permissions only: contents, pull requests, actions, checks and commit statuses. Classic branch protection needs admin to read; without it the bundle says so, with the status, and shows what rulesets and the branch's own `protected` field do show.

### What it collects

| File | Contents | Criteria |
|---|---|---|
| `pull-requests.json` | Every pull request merged into the branch in the period (listed by update time, newest first, stopping at the first updated before the period): number, title, author and their type, created, merged and who merged it (read from each pull request, since the list leaves it out), head and merge commit, each review's reviewer, state, time and commit, approvers, every check run and commit status on the head commit with whether it finished before the merge, each required check's result at the merge and now, checks failing at the merge, changes still requested at merge, and the CI runs on its merge commit. Every commit on the branch in the period with the pull request it came from, or none. A summary and exceptions | CC3.4, CC8.1 |
| `branch-protection.json` | The branch's `protected` field and required checks, its rulesets, and classic protection when the token can read it, reduced to what they enforce (who may push or dismiss reviews is left out; only whether pushes are restricted); a summary: pull request required, approvals, required checks, force pushes and deletions blocked, admins included, each `null` when unknown | CC8.1 |
| `workflow-runs.json` | Every Actions run created on the branch in the period: id, workflow file, event, status, conclusion, commit, attempt, times and url; counted by workflow and conclusion and by day, and the failed ones | CC4.1, CC5.2, CC7.1, CC8.1 |
| `manifest.json` | Kind `change-management`, format, the tool's version, the period, when it was made, the API host, repository, branch, request count and token scopes, counts, and each file's size, SHA-256, criteria and checklist rows | |
| `SHA256SUMS` | Every other file's digest, for `sha256sum -c` | |

Rules, so an auditor's sample reads the same as the summary:

- **An approval** is an `APPROVED` review by someone other than the author and not a Bot, submitted before the merge, and still that reviewer's latest decisive review (`APPROVED`, `CHANGES_REQUESTED` or `DISMISSED`). Whether it was on the merged head commit is recorded separately. Automated reviewers are listed but never count.
- **A required check** comes from the rulesets' `required_status_checks` and classic protection's contexts and checks, with the app each must come from when one is set. Its result is the one it had **at the merge**: the latest check run completed by then (from that app only, when one is set), or else the latest commit status set by then. It passes on `success`, `neutral` or `skipped` for a check run, or `success` for a status; a check still running at the merge didn't pass. A re-run that passed later is recorded as `passedNow`, and listed as an exception, never as a pass. With nothing required, the result is `null`, not `true`. Every check run (`filter=all`) and every status page is read, so history isn't lost to the latest result.
- **A failing check** is any check whose latest result by the merge failed, per name and app, or any status context whose latest state by the merge was `failure` or `error`.
- **Direct commits** are commits on the branch in the period that aren't a merged pull request's merge commit and that GitHub doesn't associate with one merged into the branch. At most 300 are looked up per bundle; the rest are counted as unchecked.
- The runs search returns at most 1,000 results, so a period with more is split by date until each part fits; a single day with more is marked truncated.
- A list longer than 200 pages is an error, not a shorter list.
- Rate limits are waited out (`Retry-After`, or the reset time, at most 65 minutes, 3 times), and 5xx answers retried, so a monthly run finishes rather than leaving a gap.

The folder is `superbot-changes-<from>_<to>-<UTC time>/`, not `superbot-evidence-`, so botd's monthly schedule never mistakes one for its own bundle in `EVIDENCE_DIR`. The tool saves with mode 0600, never over an existing file, and prints the exceptions, both digests and the command that checks it.

### A monthly workflow

[`change-evidence.yml`](../../.github/workflows/change-evidence.yml) runs on the 1st at 04:17 UTC and on demand with optional dates. Its permissions are read-only, it checks out without keeping credentials, builds the binary from the lockfile, runs it with the workflow's own token, writes the summary to the run's page and keeps the bundle as an artifact for 90 days, inside GitHub's retention, for the operator to copy to the evidence store. Its actions are pinned by commit like every other workflow ([ADR 0100](0100-github-actions-pinned-by-commit.md)).

### The configuration baseline

[`docs/security/configuration-baseline.md`](../security/configuration-baseline.md) lists each setting a managed server runs with, its value, why, and the `botctl` command, audit event or log line that checks it, and how to check a server quarterly and after changes. CI checks that every setting it names is documented in `.env.example` or the install guide. It moves CC5.1-1 from Gap to Partial: written, not approved, and no server checked yet.

## Alternatives considered

- **A `botctl` command**: one tool for operators, but `botctl` speaks HTTP/1.0 to botd without TLS; adding a TLS client and GitHub's API to it would grow the tool every server ships for something only the security owner runs.
- **botd fetching from GitHub monthly, beside its own bundle**: one schedule, but a GitHub token on every server, and self-hosters' servers have nothing to do with SuperBot's repository.
- **A shell script around `gh`**: short, but logic that decides what counts as an approval would live in jq, untested, and `gh`'s token handling and output would be the evidence format.
- **GitHub's audit log or an organisation export**: needs an organisation on a paid plan and admin access, and still doesn't say which pull request merged without an independent approval.

## Tests

- Unit tests in `superbot-evidence`: options (the token only from the environment, `--token` refused, repos and branches validated); the API base URL (HTTPS or loopback only), links followed only on its host, `Link` parsing and rate-limit waits; approvals (the author's, a Bot's, after the merge, and a later change request don't count; the final commit is recorded); required checks judged by their latest result by the merge, a run from another app never standing in for the required one, and a later pass recorded separately; failing checks by the merge; a merged list past the page cap failing; protection from rulesets and classic, and saying what it can't see; merged pull requests stopping at the first updated before the period; a runs search over 1,000 split by date; names, tokens and write scopes; and each file's criteria and rows existing in the control mapping and checklist and matching the evidence plan's table.
- `server/tests/change_evidence.rs` runs the real binary against a local server replaying recorded GitHub responses (`server/tests/fixtures/github/`, with placeholder names): it waits out a rate limit, follows pagination and stops at the period, reads who merged each pull request from the pull request itself, reads every check run and every page of statuses, sends the token only as a bearer header, saves a private tar that `tar` and `sha256sum -c` accept with matching manifest digests, finds the pull request merged without an independent approval, with a failing required check that another app's pass and a later re-run don't hide, and with a failing status on a second page, and the direct commit, reads protection from rulesets with classic protection unavailable, counts the runs, and never writes the token, a body, a review comment, a commit message or an email. It refuses without a token, off HTTPS and with `--token`, never overwrites a file, and checks the workflow's permissions are all read.

## Consequences

- No checklist row moves to **Done**. CC8.1-1 stays a Gap: an export shows `main` has no branch protection or ruleset yet, and the bundle would list every merge without an independent approval. It shows the gap rather than closing it; turning protection on is an owner's step.
- The bundle's protection is a snapshot at export, so it is made on the 1st; an admin's quarterly export of classic protection is still on the calendar, since the workflow's token can't read it.
- Logs and artifacts of runs kept as evidence are still downloaded by hand; the bundle lists every run's url.
- GitHub logins and pull request titles are in the bundle. The repository is public, so this adds nothing new, but a private repository's bundle is Confidential.
- The workflow's artifacts live 90 days on GitHub; the evidence store is where they are kept for the period and a year.

## Deferred

- Downloading the logs and artifacts of chosen runs into the bundle.
- Release and tag evidence (who tagged each release, from which commit).
- Exporting reviews of production changes outside GitHub.
