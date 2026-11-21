# 0070: Hermes Agent's per-Bot footprint, measured

## Status

Accepted (21 Nov 2026). Records the measurement for item 2 of the [ADR 0011 checklist](0011-hermes-agent-backend.md#recommendation), the release checklist for making Hermes Agent the default harness on managed tiers ([ADR 0027](0027-expo-primary-hermes-default.md)). Part of [#33](https://github.com/CG-Labs/superbot/issues/33) (M3). The shared-environment condition and the update check are handled by [ADR 0072](0072-one-hermes-environment-per-host.md).

## Context

ADR 0011 made Hermes the managed default "only when it passes this gate", and its second item is: per-Bot memory and CPU on the smallest managed machine are measured and acceptable. ADR 0011 also listed the risk directly: "memory and CPU of a Python agent per Bot on a 4 GB machine (measure)". Nothing measured it yet.

The machines are one per user ([ADR 0025](0025-control-plane-linode.md), [ADR 0065](0065-incus-container-machines.md)), sized by tier in `MACHINE_TIERS`, with a tier's Bot limit from the tiers file ([ADR 0033](0033-tiers-model-routing.md), [ADR 0040](0040-billing-v0-tier-limits.md); numbers from `deploy/tiers.example.json`):

| Tier | Linode plan | Incus plan | vCPUs | Memory | Disk (smaller) | `maxBots` |
|------|-------------|------------|-------|--------|----------------|-----------|
| Starter | `g6-standard-1` | `c1-m2-d20` | 1 | 2 GiB | 20 GiB | 3 |
| Pro | `g6-standard-2` | `c2-m4-d40` | 2 | 4 GiB | 40 GiB | 10 |
| Max | `g6-standard-4` | `c4-m8-d80` | 4 | 8 GiB | 80 GiB | 30 |

## How it is measured

`server/tests/harness_footprint.rs` (ignored by `cargo test`) reuses the harness end-to-end setup ([ADR 0057](0057-harness-hook-e2e-tests.md)): the real `botd` runs each real CLI at its pinned version, approvals on (policy `ask`), against the same fake model, now in `server/tests/common/`. No keys are needed and nothing costs money. Per harness, on a fresh botd:

- **Cold start**: a new Bot's first run of one model turn with no tools. **Warm start**: the same, twice more. No model delay, so this is the harness's own time.
- **Typical run**: a prompt, one shell command through the approval hook (allowed), and a reply, three times. Each fake model call takes 1.5 s, so a run stays up about as long as with a fast model, and its processes can be sampled.
- **Memory**: every 50 ms, every process working for that botd (its folder or environment names botd's temp dir, which also catches daemons that leave botd's session) is summed: **RSS**, and **PSS** from `/proc/<pid>/smaps_rollup`. PSS splits shared pages between processes, so it is the number that adds up across Bots. The peak per run is reported.
- **CPU**: what botd waited for (its `cutime` + `cstime`: the CLI, its hooks, `hermes gateway stop`) plus processes outside botd's session (Hermes's gateway daemon), over the run.
- **Idle**: processes still running 30 s after every run (the concurrent Bots' included) ends, and their memory and CPU over 3 s.
- **Disk**: the install (the CLI's folder plus its runtime: Node.js for the npm CLIs; Hermes bundles its own), each Bot's state dir (`DATA_DIR/bots/<id>`), and what the CLI wrote to the home it ran in (shared by one OS user's Bots).
- **Concurrency**: 4 new Bots run the typical prompt at once (their first runs), then the same Bots again (the steady state).
- **Fit**: concurrent runs per tier by memory = (machine memory − 512 MiB for the OS and the machine agent) ÷ the worst of one run's peak PSS and an equal share of the concurrent peaks.

`deploy/harness-footprint.sh` runs it on any machine (`--install-clis DIR` installs the pinned CLIs first, `--cpus N` pins it to N CPUs, `--real` uses the harnesses' own logins and models, opt-in). The `harness-e2e` workflow's **Footprint** job runs it on the pinned CLIs and uploads `footprint.json` and `footprint.md` as the `harness-footprint` artifact (and in the job summary). It asserts only ceilings well above today's numbers (5 times or more for Hermes): cold start under 120 s, a run's peak PSS under 2 GiB, at most 128 MiB and 1 CPU-second (over 3 s) for all processes still running 30 s after a run, and every run actually ran its command. A stuck daemon or CLI breaks the third; the D-Bus helpers below don't.

## Results

4-vCPU, 16 GiB VM (Intel Xeon, kernel 6.12), commit `fe5c829`, pinned CLIs: Hermes Agent v0.23.2 (`ae2a81c`), Claude Code 2.1.329, Codex 0.171.0, Pi 1.5.2. Fake model, 1.5 s per call in typical and concurrent runs.

| | Hermes Agent | Claude Code | Codex | Pi |
|---|---|---|---|---|
| Install (with runtime) | **2,604 MiB** | 479 MiB | 543 MiB | 278 MiB |
| Per-Bot state | **487 MiB** | 0 | 0 | 0 |
| Home growth (once per OS user) | 0.1 MiB | 0.2 MiB | 106 MiB (plugin cache) | 0 |
| Cold start (new Bot) | **13.8 s**, 21 CPU s | 0.5 s | 0.4 s | 0.4 s |
| Warm start | **5.4 s**, 5.4 CPU s | 0.4 s | 0.2 s | 0.3 s |
| Typical run (wall, median) | 11.0 s | 3.4 s | 3.3 s | 3.3 s |
| Model calls per typical run | 4 | 2 | 2 | 2 |
| Peak PSS per run | **332–366 MiB** | 198 MiB | 163–189 MiB | 85 MiB |
| Peak RSS per run | 354 MiB | 201 MiB | 195 MiB | 111 MiB |
| CPU per typical run | **5.3 s** | 0.66 s | 0.33 s | 0.36 s |
| Processes per run (peak) | 4 | 1 | 6 | 1 |
| 4 new Bots at once | 1,465 MiB PSS, **90 CPU s**, 31 s | 552 MiB, 2.8 CPU s, 3.6 s | 264 MiB, 1.1 CPU s, 3.4 s | 336 MiB, 1.7 CPU s, 3.6 s |
| The same 4 again | 1,273 MiB PSS, 21 CPU s, 12 s | 574 MiB, 2.4 CPU s, 3.6 s | 278 MiB, 1.1 CPU s, 3.5 s | 284 MiB, 1.4 CPU s, 3.5 s |
| Left running when idle | 0 run processes; see below | 0 | 0 | 0 |

The same measurement pinned to one CPU (`--cpus 1`, 3 Bots at once), as on a Starter machine:

| | Hermes Agent | Claude Code | Codex | Pi |
|---|---|---|---|---|
| Cold start | **24.4 s** | 0.7 s | 0.4 s | 0.5 s |
| Typical run | 12.4 s | 3.6 s | 3.3 s | 3.4 s |
| 3 new Bots at once | **77.8 s** | 4.8 s | 3.8 s | 4.6 s |
| The same 3 again | **25.0 s** | 4.7 s | 3.9 s | 4.1 s |

Concurrent runs that fit each tier's machine by memory:

| | Starter (2 GiB, 3 Bots) | Pro (4 GiB, 10 Bots) | Max (8 GiB, 30 Bots) |
|---|---|---|---|
| Hermes Agent | 4 | 9–10 | 20–22 |
| Claude Code | 7 | 18 | 38 |
| Codex | 8 | 19 | 40 |
| Pi | 18 | 42 | 90 |

By disk every tier holds far more Bots than its limit: Hermes leaves room for 28 Bots on Starter's 20 GiB after its 2.6 GiB install and 4 GiB for the OS, 70 on Pro and 154 on Max.

### What the numbers say about Hermes

1. **Idle Bots cost nothing but disk.** botd starts each harness per run and stops Hermes's gateway daemon after every run ([ADR 0015](0015-hermes-adapter.md)), so no run process is left. Memory and CPU are paid only by Bots that are running.
2. **Each run costs about 8× the CPU and 1.7× the memory of Claude Code** (15× and 4× Pi). Each run starts Python twice (the `hermes chat` client and the gateway daemon it starts) and Hermes runs checks each time (`uv pip check`, `pip --version`, `ffmpeg -version`); we haven't profiled which part dominates. On one vCPU this shows: three warm Bots at once take 25 s where one takes 12 s, while the other harnesses barely slow down. Hermes also makes 4 model calls per run where the others make 2 (extra side calls), which adds model latency and, on real models, tokens.
3. **Every Bot builds its own Python environment.** Each Bot has its own `HERMES_HOME` (Hermes's isolation unit), and Hermes keeps dependency environments per data root: the Bot's first run runs `uv sync` into `HERMES_HOME/installs/<install>/environments/` (about 470 MiB, with its own uv cache). That is the 487 MiB per Bot, the 14 s (one CPU: 24 s) and 21 CPU-seconds of a new Bot's first run, and the 90 CPU-seconds when four new Bots start at once. Hermes can borrow the installing home's environment for some launches, but not under the adapter's per-Bot homes today.
4. **The install is 2.6 GiB**: `tools/` with its own Python (256 MiB), Node.js (230 MiB), ffmpeg (438 MiB), pnpm, npm, uv and ripgrep (1.05 GiB in all), its git checkout with `node_modules` (1.06 GiB), its first environment (467 MiB), and package caches (702 MiB). The parts share hard-linked files, so they add up to more than the total. The npm CLIs need 160–425 MiB plus Node.js (119 MiB).
5. **Daily update check.** Once a day per `HERMES_HOME` (so per Bot), Hermes checks GitHub for a newer release (`git ls-remote`, and `gh auth token` when the GitHub CLI is installed). On a host with a desktop D-Bus launcher, `gh` starts a `dbus-daemon` and `gnome-keyring-daemon` that stay (12 MiB per Bot: 36 MiB with three Bots, so the 128 MiB idle ceiling would trip at about ten); that is the "see below" in the idle row. Managed machines don't install `gh`, so this shouldn't happen there, but the check is still outbound traffic from every Bot.
6. **Every third run on a Bot took about 10 s longer** (11 s, 11 s, 21 s), on both machines and every time, with the same CPU and model calls. Not explained yet.

The fake model makes these numbers a floor. With a real model, contexts are larger, runs have more turns, and a long-running Python agent grows; and nothing here ran the browser or computer use.

## Checklist status (ADR 0011)

| Item | Status | Evidence |
|------|--------|----------|
| 1. End-to-end approval test on the pinned stable version, including fail-closed on hook timeout and the canary stopping a run whose hook was skipped | **Mostly passes.** The canary half passes. The timeout half is configured, not exercised: the managed config sets `fail_closed: true` with Hermes's 300 s timeout and a test checks it, but no test makes the real Hermes time a hook out | `harness_e2e` against the real Hermes ([ADR 0057](0057-harness-hook-e2e-tests.md), [ADR 0063](0063-canary-covers-every-hooked-tool.md)); `hermes_e2e` |
| 2. Per-Bot memory and CPU on the smallest managed machine measured and acceptable | **Measured; passes with conditions.** Memory: Starter runs 4 Hermes runs at once, above its 3 Bots; Pro 9–10 for 10; Max 20–22 for 30. CPU: a Starter's one vCPU spends about 5 s on each run and 20–25 s on each new Bot's first run | This ADR |
| 3. One upstream upgrade taken through the test suite without adapter changes, or with small ones | **Not done.** The pin hasn't moved since it was set ([PR #97](https://github.com/CG-Labs/superbot/pull/97)); v0.23.3 exists | `server/src/adapters/install.rs` |
| 4. Tier-to-model routing works with at least two providers | **Built, not shown.** Routes carry a provider to Hermes's `--provider` ([ADR 0033](0033-tiers-model-routing.md)), but tests and the example tiers use one provider (OpenRouter), and no run has gone through two real providers | `tiers_http_tests.rs`, `deploy/tiers.example.json` |

## Decision

1. **Hermes does not become the managed default yet.** Items 3 and 4 are open and item 1 has a gap, so the gate isn't passed. `DEFAULT_HARNESS` stays `claude`, and the control plane doesn't set it to `hermes` (ADR 0027's plan stands, gated). A tiers file whose routes name only Hermes, like the example's Starter, still gives its users Hermes: that is the operator's choice.
2. **The footprint doesn't block the switch.** Memory fits every tier for the Bots that typically run at once, and idle Bots cost nothing. Hermes is the heaviest harness on every axis, though, so these conditions go with it:
   - **Share one dependency environment across a machine's Bots** before Hermes is the default. That saves about 470 MiB of disk and 20 CPU-seconds per new Bot (a Starter with three new Bots spends 78 s on their first runs). Either point each Bot's Hermes at the installing home's environment (Hermes's borrowing, or a shared store), or start Bots from a prepared template home.
   - **Cap concurrent runs per machine by tier**, so routines firing in the same minute can't push a container past its hard memory limit: about 3 on Starter, 8 on Pro, 16 on Max with today's numbers. Pro and Max can't run all their Bots at once on Hermes.
   - **Check the footprint on every Hermes pin bump**: the Footprint job runs on changes to the adapter and its pins, and its report goes with the bump's PR. A bump that moves these numbers much needs this ADR updated.
   - **Measure once with a real model on a Starter-sized machine** before the switch (`deploy/harness-footprint.sh --real --cpus 1`), to replace this floor with real numbers.
3. **Keep the measurement as a test.** It runs in CI with only generous ceilings, so it reports rather than fails on a slow runner, and the same script runs on a real machine.

## Consequences

- ADR 0011's checklist now records each item's status; item 2 is measured, with the conditions above.
- `server/tests/harness_e2e.rs` shares its fake model and throwaway botd with the new test through `server/tests/common/`. The fake model can now hold each call for a set time and counts calls.
- The `harness-e2e` workflow gains a Footprint job (about 10 minutes: four CLI installs, a release build, the runs) on the same triggers as the hook tests.
- Follow-ups on [#33](https://github.com/CG-Labs/superbot/issues/33): a shared Hermes environment across Bots (done, [ADR 0072](0072-one-hermes-environment-per-host.md)); a per-machine concurrent-run cap by tier; a test that a hook timeout blocks in the real Hermes; a Hermes pin bump through the suite; two providers through tier routing; why every third Hermes run is 10 s slower; turning Hermes's update check off for managed Bots (done, ADR 0072).
- Not measured: the browser and computer use, screens (Xvfb and friends), per-user Unix accounts (`ISOLATION=users`), harness sandboxes (off here, as in the hook tests), and real model contexts.
