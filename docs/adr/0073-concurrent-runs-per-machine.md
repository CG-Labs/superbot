# 0073: A cap on concurrent Bot runs per machine, by tier

## Status

Accepted (21 Nov 2026). Meets the second condition [ADR 0070](0070-hermes-per-bot-footprint.md) set on Hermes Agent becoming the managed default: cap concurrent runs per machine by tier. The first, one shared Hermes environment per computer, is [ADR 0072](0072-one-hermes-environment-per-computer.md). Part of [#33](https://github.com/CG-Labs/superbot/issues/33) (M3), item 2 of the [ADR 0011 checklist](0011-hermes-agent-backend.md#recommendation).

0072 is the shared Hermes environment ([PR #131](https://github.com/CG-Labs/superbot/pull/131)) and no open PR holds 0073, so this is 0073.

## Context

ADR 0070 measured Hermes at about 330–370 MiB PSS per run, with nothing used while a Bot is idle. By memory, a Starter machine (2 GiB) fits 4 Hermes runs at once, Pro (4 GiB) 9–10, Max (8 GiB) 20–22, after 512 MiB for the OS and the machine agent. Pro and Max allow more Bots (10 and 30) than that, and routines that fire in the same minute start together, so nothing stopped a machine running more than fits. Containers have a hard memory limit ([ADR 0065](0065-incus-container-machines.md)); past it the kernel kills processes inside, a harness mid-task among them.

Before this, each Bot already ran one task at a time, in order (its own queue), but any number of Bots ran at once. The machine agent refused a ninth job (`SUPERBOT_MAX_JOBS`, 8), and that refusal failed the run.

## Decision

### Where the limiter lives

In botd's runner (`server/src/slots.rs`, used by `runner.rs`), not in the machine agent. botd already decides where each run goes ([ADR 0036](0036-bots-on-the-users-machine.md)), knows each owner's tier, owns the chat that shows a run's state, and holds the queue a run waits in. An agent-side limit could only refuse, and a refused run is a failed run. The agent's own `SUPERBOT_MAX_JOBS` stays as a backstop, raised to 32 by default so it sits above every tier's cap.

A run takes its slot after placement (so botd knows which computer it is on) and before anything starts there: the account, the harness, its screen. It keeps the slot until the run ends, retries and approval waits included.

### Per machine, not per user or per Bot

The limit is about memory on one computer, so a pool is one computer:

- **A user's machine**: one pool per machine, capped by the machine owner's tier (`concurrentRuns`). Every run there counts, including teammates' runs of the owner's shared Bots ([ADR 0046](0046-shared-bots-under-isolation.md)), which happen on the owner's machine.
- **This server**: one pool for every run here, whoever owns the Bot, capped by `MAX_CONCURRENT_RUNS`. Self-host and testing-mode servers run Bots here. A tier's cap describes its machine's size, so it doesn't apply to runs here.

One machine per user ([decision 1](../ROADMAP.md#decisions-19-nov-2026)) makes per machine and per user the same on managed hosting; the pool is keyed by machine so it stays right if that changes.

### The numbers

`concurrentRuns` is a tier limit in `TIERS_FILE` ([ADR 0040](0040-billing-v0-tier-limits.md)), at least 1. The shipped plans (`deploy/tiers.example.json`) use the numbers ADR 0070 proposed: the low end of each tier's measured fit, less headroom, because the fake model's numbers are a floor (real contexts are larger and a long-running Python agent grows):

| Tier | Machine | Hermes runs that fit (ADR 0070) | `concurrentRuns` | `maxBots` |
|------|---------|---------------------------------|------------------|-----------|
| Starter | 1 vCPU, 2 GiB | 4 | **3** | 3 |
| Pro | 2 vCPUs, 4 GiB | 9–10 | **8** | 10 |
| Max | 4 vCPUs, 8 GiB | 20–22 | **16** | 30 |

The cap counts runs of every harness. Hermes is the heaviest, and the managed default, so it sets the number; lighter harnesses on the same machine wait sooner than they strictly need to.

A machine whose owner's tier sets no cap gets `MAX_CONCURRENT_RUNS`. That setting is 8 by default: a Pro-sized 4 GiB computer, the size of the baseline self-host VPS. `0` or `off` turns the cap off. botd refuses to start on anything else, and logs the cap at start.

### Queue semantics

- **First come, first served per computer.** A run that finds the pool full, or others already waiting, joins the back of the line. A freed slot goes to the run at the front. A new run never jumps the line, even when a slot is about to free up.
- **Fair across Bots.** A Bot runs one task at a time, so it waits in a pool at most once. When its run ends, its next task joins the back, behind Bots already waiting. One busy Bot can't hold a computer while others wait.
- **Runs wait, they don't fail.** Nothing waits forever: the runs ahead each end within `RUN_TIMEOUT_MINUTES`. Waiting doesn't count toward the run's own time limit.
- **Every trigger queues the same way**: chat, routines, Bot-to-Bot messages and replies. A routine that fires at the cap is counted against `dailyRoutineRuns` when it fires (as before) and waits like any other run.
- **Bot-to-Bot asks never deadlock.** A Bot running `botctl ask` holds its slot while it waits for the answer. If the asked Bot's run waited for a slot in the same pool, a full pool of askers would wait on each other until their asks timed out. So a peer message whose asker holds a slot in that pool goes in over the cap, borrowing its asker's room. The pool can then pass its cap by the depth of a chain of asks, and other runs still wait until it's back under.
- **A cap change applies at the next run.** Each run brings its pool's current cap, so an upgrade lets waiting runs in, oldest first, and a downgrade only stops new ones going in.

### Seeing it, stopping it

- The Bot view (`GET /api/bots`, and the live `status` event) shows a waiting run as working, with `queued: { reason: "at_capacity", host: "server" | "machine", position, running, limit }` and a plain status line: "Queued, #2 in line: its computer runs 3 tasks at once". The position updates as the line moves. The Expo client shows that line where it shows run status (the chat, the Bot list and the Bot's details), and offers **Cancel** instead of **Stop**. Older clients show the same text from `status`.
- **Stop** on a waiting run takes it out of line: "Stopped.", its monthly and routine runs are given back, and the run behind moves up.
- Audit: `bot.run_queued` when a run has to wait (host, machine, limit, running, position, trigger, message) and `bot.run_dequeued` when it stops waiting (`result`: `started`, `stopped` or `shutdown`, and `waitedMs`). A run that starts at once records neither, so a quiet computer adds nothing to the log.

### Nothing leaks a slot

- A slot is a value the run holds; dropping it gives the slot back and lets the next run in. The run's task drops it however the run ends: done, failed, refused after placement, stopped, timed out, panicked. A waiting run that is stopped, or handed a slot as it stops, gives it back the same way.
- Slots live only in memory, never in the database, so there is no count to get out of step. A restarted botd holds none, which is the truth then: runs here died with botd, and a machine stops a job when botd's stream to it ends. A run waiting at shutdown is still queued in the database, so it runs after the restart (its monthly run is given back now and taken again then); a run that had started is reported as interrupted, as before.

## Tests

- `slots::tests`: runs past the cap wait and go in order; a new run goes behind those waiting; pools are per computer; positions update; leaving the line or a handed slot holds nothing; a panicking run gives its slot back; a bigger cap lets waiting runs in; no cap; an asked Bot borrows past the cap.
- `slots_http_tests.rs` on the real router and runner, with a stand-in harness held until the test lets it go: runs past this server's cap wait in order and the API says where and why (`queued`, the status line), with both audit events; a Bot that just ran goes behind the Bots waiting; stopping a queued run, and a failed run, free their slots; routines at the cap queue; without a cap every run starts; a restarted server holds no slots and runs what was waiting; an asked Bot runs when its asker holds the last slot; a machine's cap is its owner's tier's, through the real agent over mutual TLS, and a tier change applies at the next run.
- `tiers::tests`: `concurrentRuns` parses, is at least 1, and the shipped plans carry 3, 8 and 16.
- Client: `runQueue.test.ts` (the queued line, and older servers).

## Consequences

- A Pro or Max user whose Bots all fire at once now sees some of them queued instead of a container killing a harness, or the agent refusing the ninth job.
- A run waiting in `botctl handoff` or for an approval holds its slot, since its harness is still in memory. A Bot left waiting on a person can slow others on the same computer until it times out.
- Hermes isn't the managed default yet: the ADR 0011 gate still needs a Hermes pin bump through the test suite, two providers through tier routing, and a test that a hook timeout blocks in the real Hermes.
- Not built: an admin view of each computer's load, CPU-based caps (a Starter's one vCPU spends about 5 s on each Hermes run, ADR 0070), and a cap per user on this server.
