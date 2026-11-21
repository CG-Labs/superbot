# 0075: Hermes Agent upgrades through the suite, and a real hook timeout

## Status

Accepted (21 Nov 2026). Closes two items of the [ADR 0011 gate](0011-hermes-agent-backend.md#recommendation) for making Hermes Agent the managed default: one upstream upgrade taken through the test suite, and fail-closed on a hook timeout shown against the real Hermes. Part of [#33](https://github.com/CG-Labs/superbot/issues/33) (M3). Two providers through tier routing is the gate's last open item.

0073 is the concurrent-run cap and 0074 the machine RPO and RTO ([PR #133](https://github.com/CG-Labs/superbot/pull/133)), both on `main`, and no open PR holds 0075.

## Context

ADR 0011 set Hermes's supported-version policy: stable release tags only, never a canary, and upgrades only through the test suite. Two gate items were still open:

- **Upstream upgrade: not done.** Hermes was pinned to v0.23.2 (`ae2a81c`) when the adapter landed ([ADR 0015](0015-hermes-adapter.md)), and the pin hadn't moved. It lives in three places: `server/src/adapters/install.rs` (what machines install, and what the hook tests install, [ADR 0039](0039-machine-harnesses-and-agent-upgrades.md), [ADR 0057](0057-harness-hook-e2e-tests.md)), the Dockerfile and `deploy/install.sh`. Nothing checked that the three agree, that the commit is a stable tag's, or how to move it.
- **Fail-closed on hook timeout: not shown.** The managed config sets `fail_closed: true` with a timeout a minute above botd's approval wait (at most 300 s, Hermes's cap), and unit tests check that shape. But no test made the real Hermes time a hook out, so nothing proved Hermes blocks rather than allows when it does.

How Hermes ships, read from its repo on 21 Nov 2026:

- Stable releases are GitHub releases tagged `vMAJOR.MINOR.PATCH`, roughly weekly. Canaries ship daily as prereleases tagged `vX.Y.Z+canary.<time>`.
- Older stable releases also carry calendar tags (`v2026.9.24` is v0.21.5). Sorted as versions, those sit above every `v0.x`, so "the highest tag" isn't "the latest stable release". GitHub's latest release is.
- The installer clones the repo at a commit. The `hermes-agent` package on PyPI stops at 0.19.0 and isn't how Hermes is installed, so it isn't a source of truth.

## Decision

### The bump: v0.23.2 to v0.23.3

v0.23.3 (released 20 Nov 2026, commit `caafe53`) is the latest stable release. It rolls up about 370 merged pull requests since v0.23.2; its curated notes ship with v0.24.0. What matters to SuperBot didn't change:

- `scripts/install.sh` is byte-identical, so the pinned SHA-256 stays.
- `agent/shell_hooks.py` (the `pre_tool_call` contract: stdin JSON, exit 2 blocks, `fail_closed`, the 300 s cap) and `hermes_cli/stream_json.py` (the stream the adapter parses) are unchanged.
- Tool names are unchanged: the 70 names declared under `tools/` are the same, and so are the tool-search meta tools (`tool_search`, `tool_describe`, `tool_call`). The tool registry's change is internal.

No change to the adapter, `policy.rs`'s tool names, or the hook contract was needed. The suite passed on v0.23.3 unchanged (see [Results](#results)).

### The supported-version policy, as code

- **One source.** The Hermes pin in `install.rs` now holds its release tag next to its commit and installer SHA-256 (`Source::Hermes { tag, sha256 }`). A unit test, `hermes_is_pinned_to_one_stable_release_everywhere`, fails `cargo test` (the server workflow) unless the Dockerfile and `deploy/install.sh` install that commit and name that tag, and the tag is `vMAJOR.MINOR.PATCH`.
- **Checked upstream.** `deploy/hermes-pin.sh verify` checks that the tag is a published, non-prerelease release, that the pinned commit is that tag's commit (an annotated tag's target, through `git ls-remote`), and that the installer at it matches the pinned SHA-256. The `harness-e2e` workflow's Hermes job runs it first, on every change to the adapter or its pins and weekly. When a newer stable release is out, it warns (a workflow annotation) rather than fails, so a release upstream never breaks `main`.
- **Moved by one command.** `deploy/hermes-pin.sh bump [TAG]` (default: GitHub's latest release) refuses anything that isn't a published stable release, resolves the tag's commit and its installer's SHA-256, and rewrites the pin in `install.rs`, the Dockerfile, `deploy/install.sh`, and the docs that name it (`deploy/README.md`, `docs/backend.md`, `docs/ROADMAP.md`). It warns on a rollback and says when the installer itself changed, so its diff gets read before its new hash is trusted.
- **Run locally the way CI does.** `deploy/hermes-pin.sh test DIR [--footprint]` installs the pin under `DIR` and runs the Hermes hook tests (and the footprint).

### The upgrade procedure

1. `deploy/hermes-pin.sh bump` (or `bump vX.Y.Z` for a given release).
2. Read the upstream diff for what SuperBot relies on: `scripts/install.sh`, `agent/shell_hooks.py`, `hermes_cli/stream_json.py`, tool names, and the install layout `deploy/hermes-share.sh` uses ([ADR 0072](0072-one-hermes-environment-per-computer.md)).
3. `cargo test`, then `deploy/hermes-pin.sh test /tmp/hermes-clis`.
4. Open a pull request. The `harness-e2e` workflow runs `verify`, the approvals and canary tests, the hook timeout test and the footprint on the real CLI. Put what the adapter needed (ideally nothing) and the footprint report in it ([ADR 0070](0070-hermes-per-bot-footprint.md) asks for a report on every bump), and add a line to the log below.
5. If the latest stable release breaks something that can't be fixed in the adapter, pin the newest stable release that passes, and record why in the log.

### The hook timeout test

**A short timeout for tests.** botd's hook timeout is the approval wait plus a minute, and the shortest wait is two minutes, so a real timeout took at least three minutes. `SUPERBOT_TEST_HOOK_TIMEOUT_SECS` shortens every run's hook timeout to that many seconds (at least 2), with the approval wait at half of it so the gate still answers first. It only applies in testing mode (`TESTING_MODE=on` and no license, [ADR 0068](0068-no-free-tier.md)); a licensed server ignores it and says so at start, and an invalid value stops botd. It only shortens a timeout, never lengthens one. It isn't a product setting: on a real server it would make approvals fail closed while a person is still deciding.

**The test**, `hermes_hook_timeout_fails_closed` in `server/tests/harness_e2e.rs`: the real `botd` runs the real Hermes at the pin against the fake model, with `SUPERBOT_TEST_HOOK_TIMEOUT_SECS=3`. `botctl hook` is replaced by a stub that hangs for 90 s and then allows the call, so only Hermes timing the hook out and failing closed can stop the call. For a shell command (`terminal`) and a file write (`write_file`) it checks that:

- Hermes ran the hook, and the call never ran (its file doesn't exist);
- the run ended long before the stub would have answered, and not as unguarded;
- the agent was told why: Hermes's `hook ... failed closed: timed out after 3s` reaches the model as the tool's result;
- Hermes killed the hung hook rather than leaving it running;
- the managed config botd wrote has `timeout: 3`, `fail_closed: true` and `hooks_auto_accept: true`.

**It catches fail-open.** With the adapter changed to `fail_closed: false`, the test fails: Hermes allows the call after the timeout, the command runs, and the canary ends the run as unguarded.

CI runs it as its own step in the `harness-e2e` workflow's Hermes job, next to the approvals and canary tests.

## Results

On a 4-vCPU cloud VM (Ubuntu, kernel 6.12), Hermes Agent v0.23.3 installed by `deploy/install-harness-clis.sh` from the pin, fake model:

| Check | Result |
|-------|--------|
| `deploy/hermes-pin.sh verify` | v0.23.3 is `caafe53`, a stable release; installer matches |
| `bump` round trip (to v0.23.2 and back to latest) | every pinned file rewritten, then byte-identical to the original |
| Approvals end to end (`hermes_hooks_hold`) | pass: allowed, denied by rule, approved, denied; `write_file` allowed and denied |
| Canary (`unhooked_runs_stop`) | pass: a shell command and `write_file` that skip the hook end the run as unguarded |
| Hook timeout (`hermes_hook_timeout_fails_closed`) | pass: `terminal` and `write_file` each blocked in 8–13 s over two runs (the 3 s timeout plus Hermes starting) |
| Same, with `fail_closed: false` | fails as it should: the call runs |
| Footprint (`deploy/harness-footprint.sh --harness hermes`) | pass, about the same as v0.23.2 (below) |

The footprint next to the last run on `main` at v0.23.2 (the `harness-e2e` workflow's Footprint job, run 44899761454):

| Hermes | Install MiB | New Bot disk MiB | Peak PSS MiB/run | CPU s/run | 4 at once, peak PSS MiB | Runs that fit Starter / Pro / Max |
|--------|-------------|------------------|------------------|-----------|-------------------------|-----------------------------------|
| v0.23.2 (CI) | 2604 | 4.7 | 340 | 4.7 | 1223 | 4 / 10 / 22 |
| v0.23.3 (this VM) | 2619 | 4.6 | 342 | 5.5 | 1275 | 4 / 10 / 22 |

Nothing moved enough to revisit [ADR 0070](0070-hermes-per-bot-footprint.md) or the run caps in [ADR 0073](0073-concurrent-runs-per-machine.md). The pull request's own Footprint job reports v0.23.3 on CI's runner.

One thing showed up on this VM and not in CI: each Bot's run left a D-Bus session and `gnome-keyring-daemon` behind (about 6 MiB each). Both versions of Hermes run `gh auth token`, and `gh` on its own starts those two when the host has `dbus-launch` and GNOME Keyring installed, as this VM does and CI's runner doesn't. So it isn't from the bump, but a machine image with all three would collect them. Follow-up on [#33](https://github.com/CG-Labs/superbot/issues/33): keep `gh` from starting a session bus in Bot runs, or leave those packages out of managed images.

## Upgrade log

| Date | From | To | Adapter changes | Notes |
|------|------|----|-----------------|-------|
| 21 Nov 2026 | v0.23.2 (`ae2a81c`) | v0.23.3 (`caafe53`) | None | Installer, hook contract and stream format unchanged. |

## Consequences

- ADR 0011's gate: approvals end to end now pass in full (the canary and fail-closed on hook timeout, both against the real Hermes), footprint passes with its conditions met, and one upgrade has gone through the suite with no adapter changes. Two providers through tier routing is the only item left, so Hermes isn't the managed default yet.
- Every Hermes bump is one command, a unit test that keeps the three pins together, and the same workflow that tests approvals. The weekly run says when the pin falls behind.
- `verify` and `bump` depend on GitHub's API (with the workflow's token in CI, so its rate limit isn't a problem) and on Hermes keeping stable releases as non-prerelease `vX.Y.Z` releases. If upstream changes how it tags releases, `verify` fails and the policy needs a look.
- Not built: a bot that opens bump pull requests on its own. The weekly warning and the procedure above are enough while bumps are rare.
