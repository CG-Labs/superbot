# 0100: GitHub Actions pinned by commit

## Status

Accepted (22 Nov 2026). Part of the SOC 2 readiness checklist of M4, [#50](https://github.com/CG-Labs/superbot/issues/50); closes row CC5.2-1 of the [readiness checklist](../security/soc2-readiness-checklist.md).

0099 is the highest number on `main`, so this is 0100. Renumber it if another ADR lands first.

## Context

Every workflow referenced its actions by tag (`actions/checkout@v4`) or branch (`dtolnay/rust-toolchain@stable`). A tag or branch is a pointer the action's owner, or anyone who takes over their account, can move. Some of these jobs hold a token that can push images to GHCR ([`docker.yml`](../../.github/workflows/docker.yml), ADR 0084), so a moved tag could put other code into the published image with no change in this repository. SOC 2 CC5.2 (technology general controls) and CC8.1 (change management) expect what runs in CI to be what was reviewed.

## Decision

- **Every remote action is pinned to a full 40-character commit SHA, with the version it stands for in a trailing comment**: `uses: actions/checkout@<sha> # v4.4.0`. The SHA is what the existing floating tag pointed at when pinned, resolved from upstream with `git ls-remote`, so behaviour didn't change. The comment names the most specific release tag on that commit. `dtolnay/rust-toolchain` has no release tags, so it is pinned to the head of its `stable` branch and the comment says `stable`; the Rust toolchain it installs still follows stable, as before.
- **Dependabot updates them** ([`.github/dependabot.yml`](../../.github/dependabot.yml)): the `github-actions` ecosystem, weekly, every action in one grouped PR. Dependabot reads the version comment and moves the SHA and the comment together, so each update is a reviewed PR that says which release it moves to. It may not follow a branch pin, so if it doesn't propose one, `dtolnay/rust-toolchain` is bumped by hand when needed (re-resolve `stable` with `git ls-remote`).
- **CI refuses anything else** ([`server/tests/actions_pinned.rs`](../../server/tests/actions_pinned.rs)): every `uses:` in every YAML file under `.github/` (workflows, and composite actions if any are added) must be a full commit SHA with a version comment. Local actions (`./...`) are this repository's own reviewed code and pass. `docker://` images must be pinned by `@sha256:` digest. It reads lines, not YAML, so it fails closed: a `uses` key written any way but as a plain block key (quoted, in a flow mapping like `- { uses: ... }`, or with its value on the next line) is refused rather than skipped. It runs in the `docs` workflow on any change under `.github/`, and in the server workflow's `cargo test`. It is a Rust test, like the security pack's link check, so it needs no extra tool.

## Alternatives

- **Keep tags, trust the publishers.** Most of the actions are GitHub's or Docker's own, but tags are mutable and a compromised maintainer account is how past supply-chain attacks on Actions worked. Rejected.
- **SHA pins without a comment.** Equally safe, but a reviewer can't tell what version a SHA is, and Dependabot can't propose updates for it. Rejected.
- **Renovate instead of Dependabot.** Renovate also follows branch pins, but it is a third-party app with write access to the repository. Dependabot is built into GitHub and needs no extra app. We can switch if branch pins become a burden.
- **An organisation policy requiring SHA pins** (GitHub's allowed-actions setting). Worth turning on, but it lives outside this repository and a self-hoster's fork wouldn't have it. The test travels with the code; the setting can be added on top.
- **actionlint or zizmor in CI.** They lint far more than pinning. A dedicated test is a few dozen lines, has no download to trust, and fails with the exact file and line. Either can be added later for the other checks.
- **Vendoring actions into the repository.** Removes the dependency entirely, but means carrying and updating third-party code by hand. Rejected for the size of the gain.

## Consequences

- A new workflow step with a tag reference fails CI with the file, line and the reason; the author pins it (`git ls-remote https://github.com/<owner>/<repo> refs/tags/<tag>`, using the `^{}` line for annotated tags).
- Action updates arrive as one weekly Dependabot PR, reviewed like any other change. Security fixes in an action wait for that PR or a manual bump.
- Signed images with provenance (CC5.2-2) and container image scanning (CC7.1-3) are still open; they build on the same workflows.
