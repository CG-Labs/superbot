# 0111: A security policy, a changelog and a GitHub release per tag

## Status

Accepted (22 Nov 2026). Part of the SOC 2 readiness checklist of M4, [#50](https://github.com/CG-Labs/superbot/issues/50); closes row CC8.1-3 and makes row CC2.3-1 partial in the [readiness checklist](../security/soc2-readiness-checklist.md).

0108 is the highest number on `main`, and 0109 and 0110 are taken by pull requests in flight, so this is 0111. Renumber it if another ADR lands first.

## Context

Two checklist rows had nothing in the repository:

- **CC2.3-1, a vulnerability-disclosure policy and security contact.** There was no `SECURITY.md`, so a researcher had no private way to report a problem and no idea what would happen if they did. GitHub's private vulnerability reporting, the obvious channel for a public repository, is off.
- **CC8.1-3, release notes for each release.** The docker workflow turns a `v*` tag into semver image tags ([ADR 0084](0084-published-image-with-computer-use.md)), but there is no changelog, no GitHub release, and no tag yet. The only version anywhere is `server/Cargo.toml`'s `0.1.0` (the Expo client's `1.0.0` is the app stores' version, not SuperBot's). Nothing ties a tag to that version, so a tag could publish `latest` images with no record of what changed.

## Decision

- **`SECURITY.md` at the root**, where GitHub shows it: supported versions (before 1.0, only `main` and the newest release get fixes), reporting through GitHub's private vulnerability reporting only, what a report should hold, target times (acknowledge in 3 days, assess in 10, fix Critical and High in 30 and the rest in 90, with 90-day coordinated disclosure), scope, and safe harbour for good-faith research against one's own install. It names no email address or person. Turning private reporting on is a repository setting, so the file carries a marked operator TODO, and the checklist row stays partial until an owner does it and keeps a log of reports.
- **`CHANGELOG.md` in [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/) format**, seeded with a `0.1.0` section that sums up everything merged so far by area. The newest version may say `- Unreleased` instead of a date until it is tagged, and an optional `## [Unreleased]` section may sit on top. That way the version being worked towards is the one in `server/Cargo.toml`, and a release is just dating its section and tagging.
- **One version: `server/Cargo.toml`'s.** A tag `vX.Y.Z` must match it. Bumping the version without a changelog section, or adding a section without bumping it, fails CI.
- **`deploy/release-notes.sh` holds the logic**, so it can be run by hand and tested without GitHub: `check` (the format, a semver per section, no duplicates, newest first by semver and by date, no empty sections, the newest version is `server/Cargo.toml`'s, and every `v<semver>` tag has a dated section), `notes TAG` (all of that, plus the tag matches the version and its section is dated, then prints the section, with its relative links pointed at the tag's files, since a release page would resolve them against itself, and the release's image names), and `self-test` (fixtures for each rule, each asserting why it fails). It is a bash script next to the other deploy tools, so the server workflow's ShellCheck covers it too.
- **`.github/workflows/release.yml`**: a `changelog` job runs ShellCheck, the self-test and `check` on every pull request or push to `main` that touches `CHANGELOG.md`, `server/Cargo.toml`, the script or the workflow, and on every `v*` tag (path filters don't apply to tags). On a tag, a `release` job waits for it, refuses a tag whose commit isn't on `main`, writes the notes with `notes`, and creates the GitHub release with `gh release create --verify-tag` (a prerelease if the version has a `-`); a re-run edits the release instead. It uses only `gh`, which the runner has, and `actions/checkout` pinned by commit ([ADR 0100](0100-github-actions-pinned-by-commit.md)). The workflow is read-only; only the `release` job gets `contents: write`, the least that creating a release needs. `server/tests/release_workflow.rs` checks those permissions, the triggers, the order of the steps, and that the tag reaches the shell through `env`, in the `docs` workflow.
- **Tags stay manual.** Nothing in CI makes a tag or bumps the version. An engineering lead dates the section, merges that, and pushes the tag; the docker workflow publishes the images and this one the release.

## Alternatives considered

- **release-please, semantic-release or git-cliff, generating the changelog from commit messages.** Commit subjects here are written for reviewers, not operators, and several tools need write access to open release PRs or push tags. A hand-written changelog checked by CI is smaller and says what operators need. Generated notes can be added later as a draft to edit.
- **GitHub's generated release notes (`--generate-notes`).** A list of PR titles, with no place to call out security fixes or upgrade steps, and nothing in the repository to review. Rejected as the only record; CHANGELOG.md is reviewed with the code.
- **A third-party release action** (`softprops/action-gh-release` and the like). `gh` is already on the runner and does the same with no new code to trust.
- **Making the docker workflow create the release.** It already holds `packages`, `id-token` and `attestations` write; adding `contents: write` there widens a token that matters. A separate workflow keeps each token small, and a failed image scan doesn't stop the notes being published.
- **Releasing from any tag.** A tag on an unmerged branch would publish a release of unreviewed code. Rejected: only commits on `main`.
- **An email address for security reports.** Nobody is named to read one yet, and an unread address is worse than none. GitHub's private reporting needs no address; the owner can add one.

## Consequences

- An operator reads what changed in CHANGELOG.md or on the release page, and the release names the image tags to pull and how to verify them.
- Each user-facing PR should add a line to the newest section. CI doesn't enforce that per PR, only that the file stays well formed and matches the version and tags.
- Until a repository owner turns on private vulnerability reporting, the link in `SECURITY.md` doesn't offer the form; the checklist names that step.
- The first release, `v0.1.0`, needs its section dated and the tag pushed by hand. Its images also become `latest`, so Compose's default can move from `main` as ADR 0084 planned.
