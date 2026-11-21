//! Per-Bot resource footprint of each harness CLI (ADR 0070, for ADR 0011's checklist):
//! the real `botd` runs Claude Code, Codex, Pi and Hermes Agent at the pinned versions
//! against the fake model from `harness_e2e`, and this measures, per harness:
//!
//! - disk for the install (the CLI and its runtime) and for one Bot's state;
//! - cold start (a new Bot's first run of one model turn) and warm start (its next ones);
//! - a typical run (a prompt, one shell command through the approval hook, a reply):
//!   peak memory (RSS and PSS summed over every process of the run), process count, CPU;
//! - idle: what is left running once a run ends, and its memory and CPU;
//! - several Bots running at once, and from that how many runs fit each tier's machine.
//!
//! The report goes to `$SUPERBOT_FOOTPRINT_OUT` (default `target/footprint`) as
//! `footprint.json` and `footprint.md`. Only generous ceilings are asserted, after the
//! report is written, so a slow runner reports numbers instead of failing.
//!
//! Ignored by `cargo test`. `deploy/harness-footprint.sh` runs it, and the `harness-e2e`
//! workflow's Footprint job runs it on the pinned CLIs and uploads the report.
//!
//! - `SUPERBOT_E2E_HARNESSES`, `SUPERBOT_E2E_REQUIRE`: as in `harness_e2e`.
//! - `SUPERBOT_E2E_MODEL=real`: the harnesses' own logins and models (opt-in; needs
//!   `SUPERBOT_E2E_BOT_MODEL` for Hermes). Model latency then dominates the timings.
//! - `SUPERBOT_FOOTPRINT_RUNS`: typical runs per harness (default 3).
//! - `SUPERBOT_FOOTPRINT_CONCURRENCY`: Bots running at once (default 4).
//! - `SUPERBOT_FOOTPRINT_MODEL_DELAY_MS`: how long each fake model call takes in typical
//!   and concurrent runs (default 1500), so a run stays up as long as with a fast model.
//! - `SUPERBOT_FOOTPRINT_RESERVE_MIB`: memory a machine keeps for the OS and the
//!   machine agent before any run (default 512).
//! - `SUPERBOT_FOOTPRINT_INSTALL_<BIN>`: the folder a CLI is installed in, when it can't
//!   be found from the binary (e.g. `SUPERBOT_FOOTPRINT_INSTALL_HERMES=/opt/hermes`).
//! - `SUPERBOT_FOOTPRINT_CEILINGS=off`: report only, assert nothing.
//! - `SUPERBOT_FOOTPRINT_CPUS`: set by the script's `--cpus` (which pins the run to that
//!   many CPUs), for the report.

mod common;

use common::*;
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const MIB: f64 = 1024.0 * 1024.0;
const SAMPLE_EVERY: Duration = Duration::from_millis(50);

/// The tiers' machines: the default Linode plans (ADR 0025) and Incus container sizes
/// (ADR 0065) in `MACHINE_TIERS`, with `maxBots` from `deploy/tiers.example.json`.
const TIERS: [(&str, &str, &str, u32, u64, u64, u32); 3] = [
    // name, Linode plan, Incus plan, vCPUs, memory MiB, disk GiB (smaller of the two), maxBots
    ("starter", "g6-standard-1", "c1-m2-d20", 1, 2048, 20, 3),
    ("pro", "g6-standard-2", "c2-m4-d40", 2, 4096, 40, 10),
    ("max", "g6-standard-4", "c4-m8-d80", 4, 8192, 80, 30),
];

/// Ceilings, asserted unless `SUPERBOT_FOOTPRINT_CEILINGS=off`: well above what the
/// pinned CLIs measure, so they catch a runaway, not a slow runner.
const MAX_COLD_START: Duration = Duration::from_secs(120);
const MAX_RUN_PSS_MIB: f64 = 2048.0;
/// What processes left running `QUIESCE` after a run may use, all together: a stuck
/// daemon or CLI breaks it, session helpers some CLIs start (12 MiB) don't.
const MAX_IDLE_MIB: f64 = 128.0;
const MAX_IDLE_CPU_S: f64 = 1.0;
const QUIESCE: Duration = Duration::from_secs(30);

fn env_num(name: &str, default: u64) -> u64 {
    std::env::var(name).ok().and_then(|v| v.trim().parse().ok()).unwrap_or(default)
}

// ---------------------------------------------------------------------------------
// /proc

fn clk_tck() -> f64 {
    // SAFETY: sysconf has no preconditions.
    (unsafe { libc::sysconf(libc::_SC_CLK_TCK) }).max(1) as f64
}

/// Fields after the command's closing paren in /proc/<pid>/stat (field 3 is index 0).
fn stat(pid: i32) -> Option<Vec<u64>> {
    let s = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let rest = s.rsplit_once(')')?.1;
    // State is a letter; keep the numeric fields at their positions.
    Some(rest.split_whitespace().map(|f| f.parse().unwrap_or(0)).collect())
}

/// utime + stime of `pid`, and cutime + cstime (children it waited for), in ticks.
fn cpu_ticks(pid: i32) -> Option<(u64, u64)> {
    let f = stat(pid)?;
    Some((f.get(11)? + f.get(12)?, f.get(13)? + f.get(14)?))
}

fn session_of(pid: i32) -> Option<u64> {
    stat(pid)?.get(3).copied()
}

/// RSS and PSS of `pid` in KiB. PSS splits shared pages between the processes that map
/// them, so summing it over processes doesn't count shared libraries twice.
fn memory_kib(pid: i32) -> (u64, u64) {
    let field = |text: &str, name: &str| {
        text.lines().find_map(|l| l.strip_prefix(name)).and_then(|v| v.split_whitespace().next()?.parse::<u64>().ok())
    };
    if let Ok(s) = std::fs::read_to_string(format!("/proc/{pid}/smaps_rollup")) {
        let rss = field(&s, "Rss:").unwrap_or(0);
        return (rss, field(&s, "Pss:").unwrap_or(rss));
    }
    let rss = std::fs::read_to_string(format!("/proc/{pid}/status")).ok().and_then(|s| field(&s, "VmRSS:")).unwrap_or(0);
    (rss, rss)
}

/// Processes that outlived a run by `QUIESCE` and keep running: counted as idle cost,
/// not against later runs.
static LINGERING: Mutex<Vec<i32>> = Mutex::new(Vec::new());

fn lingering() -> Vec<i32> {
    LINGERING.lock().unwrap().iter().copied().filter(|p| Path::new(&format!("/proc/{p}")).exists()).collect()
}

/// Processes working for this botd, other than botd and those lingering: their folder or
/// environment names its temp dir. That finds each run's CLI and hooks, and daemons that
/// left botd's session (Hermes's gateway), but not other botds or this test.
fn run_processes(dir: &str, botd: i32) -> Vec<i32> {
    let me = std::process::id() as i32;
    let linger = LINGERING.lock().unwrap().clone();
    all_processes(dir).into_iter().filter(|&pid| pid != botd && pid != me && !linger.contains(&pid)).collect()
}

/// Every process whose folder or environment names `dir`.
fn all_processes(dir: &str) -> Vec<i32> {
    let Ok(entries) = std::fs::read_dir("/proc") else { return Vec::new() };
    entries
        .filter_map(|e| e.ok()?.file_name().to_str()?.parse::<i32>().ok())
        .filter(|pid| {
            let in_dir = std::fs::read_link(format!("/proc/{pid}/cwd")).is_ok_and(|c| c.starts_with(dir));
            in_dir || std::fs::read(format!("/proc/{pid}/environ")).is_ok_and(|e| e.windows(dir.len()).any(|w| w == dir.as_bytes()))
        })
        .collect()
}

#[derive(Default, Clone)]
struct Usage {
    peak_rss_kib: u64,
    peak_pss_kib: u64,
    peak_procs: usize,
    /// Ticks of processes outside botd's session (daemons botd never waits for), last seen.
    detached_ticks: HashMap<i32, u64>,
    /// Commands seen, for the report.
    commands: HashSet<String>,
    /// Their command lines, shortened.
    cmdlines: HashSet<String>,
}

fn cmdline(pid: i32) -> String {
    let raw = std::fs::read(format!("/proc/{pid}/cmdline")).unwrap_or_default();
    let line = String::from_utf8_lossy(&raw).replace('\0', " ").trim().to_string();
    line.chars().take(160).collect()
}

fn comm(pid: i32) -> String {
    std::fs::read_to_string(format!("/proc/{pid}/comm")).unwrap_or_default().trim().to_string()
}

/// Samples the run processes every 50 ms until dropped, keeping the peaks.
struct Sampler {
    stop: Arc<AtomicBool>,
    usage: Arc<Mutex<Usage>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Sampler {
    fn start(dir: &str, botd: i32) -> Sampler {
        let (stop, usage) = (Arc::new(AtomicBool::new(false)), Arc::new(Mutex::new(Usage::default())));
        let (s, u, dir) = (stop.clone(), usage.clone(), dir.to_string());
        let sid = session_of(botd);
        let thread = std::thread::spawn(move || {
            while !s.load(Ordering::SeqCst) {
                let pids = run_processes(&dir, botd);
                let (mut rss, mut pss) = (0, 0);
                let mut u = u.lock().unwrap();
                for &pid in &pids {
                    let (r, p) = memory_kib(pid);
                    (rss, pss) = (rss + r, pss + p);
                    if session_of(pid) != sid
                        && let Some((own, _)) = cpu_ticks(pid)
                    {
                        u.detached_ticks.insert(pid, own);
                    }
                    if let Ok(c) = std::fs::read_to_string(format!("/proc/{pid}/comm")) {
                        u.commands.insert(c.trim().to_string());
                        u.cmdlines.insert(cmdline(pid));
                    }
                }
                u.peak_rss_kib = u.peak_rss_kib.max(rss);
                u.peak_pss_kib = u.peak_pss_kib.max(pss);
                u.peak_procs = u.peak_procs.max(pids.len());
                drop(u);
                std::thread::sleep(SAMPLE_EVERY);
            }
        });
        Sampler { stop, usage, thread: Some(thread) }
    }

    fn finish(mut self) -> Usage {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
        self.usage.lock().unwrap().clone()
    }
}

/// Disk used under `path` (allocated blocks, each hard-linked file once, links not followed).
fn disk_bytes(path: &Path) -> u64 {
    fn walk(p: &Path, seen: &mut HashSet<(u64, u64)>) -> u64 {
        let Ok(m) = std::fs::symlink_metadata(p) else { return 0 };
        if !seen.insert((m.dev(), m.ino())) {
            return 0;
        }
        let mut total = m.blocks() * 512;
        if m.is_dir()
            && let Ok(entries) = std::fs::read_dir(p)
        {
            for e in entries.flatten() {
                total += walk(&e.path(), seen);
            }
        }
        total
    }
    walk(path, &mut HashSet::new())
}

fn mib(bytes: u64) -> f64 {
    (bytes as f64 / MIB * 10.0).round() / 10.0
}

fn kib_mib(kib: u64) -> f64 {
    mib(kib * 1024)
}

fn secs(d: Duration) -> f64 {
    (d.as_secs_f64() * 100.0).round() / 100.0
}

// ---------------------------------------------------------------------------------
// Install size

/// Where `bin` is installed, and the runtime it needs, from the binary's real path:
/// npm CLIs live in a `node_modules` folder and need Node.js; Hermes's installer puts
/// its checkout and everything it runs on (Python, Node.js, uv, ffmpeg, caches) in one
/// `.hermes` folder around its `hermes-agent` checkout, so that folder is the install.
fn install_dirs(bin: &str) -> (Option<PathBuf>, Option<PathBuf>) {
    let over = std::env::var(format!("SUPERBOT_FOOTPRINT_INSTALL_{}", bin.to_uppercase())).ok().filter(|v| !v.is_empty());
    let exe = which(bin).and_then(|p| std::fs::canonicalize(p).ok()).map(unwrap_launcher);
    let ancestor = |p: &Path, name: &str| p.ancestors().find(|a| a.file_name().is_some_and(|n| n == name)).map(Path::to_path_buf);
    let install = over.map(PathBuf::from).or_else(|| {
        let exe = exe.as_deref()?;
        let root = ancestor(exe, if bin == "hermes" { "hermes-agent" } else { "node_modules" })?;
        root.parent().map(Path::to_path_buf)
    });
    let runtime = match bin {
        "hermes" => None,
        // Node.js: the folder holding its bin/ and lib/, or the binary alone.
        _ => which("node").and_then(|n| std::fs::canonicalize(n).ok()).map(|n| match n.parent() {
            Some(bin) if bin.file_name().is_some_and(|b| b == "bin") => bin.parent().map_or(n.clone(), Path::to_path_buf),
            _ => n,
        }),
    };
    (install, runtime)
}

/// Disk used by each entry under `dir`, `depth` levels down, those over 1 MiB.
fn breakdown(dir: &Path, depth: usize) -> Value {
    fn entries(dir: &Path, prefix: &str, depth: usize, out: &mut Vec<(String, u64)>) {
        for e in std::fs::read_dir(dir).into_iter().flatten().flatten() {
            let name = format!("{prefix}{}", e.file_name().to_string_lossy());
            let bytes = disk_bytes(&e.path());
            if bytes <= 1024 * 1024 {
                continue;
            }
            if depth > 1 && e.file_type().is_ok_and(|t| t.is_dir()) {
                entries(&e.path(), &format!("{name}/"), depth - 1, out);
            } else {
                out.push((name, bytes));
            }
        }
    }
    let mut parts = Vec::new();
    entries(dir, "", depth, &mut parts);
    Value::Object(parts.into_iter().map(|(n, b)| (n, json!(mib(b)))).collect())
}

/// `bin --version`'s first line. Hermes reads its install from the home it was installed
/// in, so it runs with that one.
fn version(bin: &str, install: Option<&Path>) -> String {
    let mut cmd = std::process::Command::new(bin);
    cmd.arg("--version");
    if let (Some(home), "hermes") = (install.and_then(Path::parent), bin) {
        cmd.env("HOME", home).env_remove("HERMES_HOME");
    }
    cmd.output().map(|o| String::from_utf8_lossy(&o.stdout).lines().next().unwrap_or_default().trim().to_string()).unwrap_or_default()
}

/// Follows a launcher script (`exec /path/to/real "$@"`) to what it runs, a few deep.
fn unwrap_launcher(mut exe: PathBuf) -> PathBuf {
    for _ in 0..3 {
        let text = match std::fs::metadata(&exe) {
            Ok(m) if m.len() < 4096 => std::fs::read_to_string(&exe).unwrap_or_default(),
            _ => break,
        };
        let next = text.starts_with("#!").then(|| text.lines().find_map(|l| l.trim().strip_prefix("exec ")?.split_whitespace().next().map(PathBuf::from))).flatten();
        match next.filter(|n| n.is_absolute()).and_then(|n| std::fs::canonicalize(n).ok()) {
            Some(n) => exe = n,
            None => break,
        }
    }
    exe
}

// ---------------------------------------------------------------------------------
// One run, measured

struct Measured {
    wall: Duration,
    result: String,
    text: String,
    model_calls: u64,
    usage: Usage,
    /// CPU seconds of the run's processes: what botd waited for, plus detached daemons.
    cpu_s: f64,
    /// CPU seconds of botd itself over the run (answering the hook, and this test's polls).
    botd_cpu_s: f64,
}

fn botd_ticks(b: &Botd) -> (u64, u64) {
    cpu_ticks(b.child.id() as i32).unwrap_or_default()
}

fn calls(b: &Botd) -> u64 {
    b.model.as_ref().map_or(0, |m| m.calls.load(Ordering::SeqCst))
}

/// Waits until no process of any run is left, up to `limit`: how long a run's
/// processes outlive its result (Hermes's daemon is stopped after the run ends). Those
/// still there at the limit are taken as lingering.
fn quiesce(b: &Botd, limit: Duration) -> Duration {
    let (dir, pid, start) = (b.dir.display().to_string(), b.child.id() as i32, Instant::now());
    loop {
        let left = run_processes(&dir, pid);
        if left.is_empty() {
            break;
        }
        if start.elapsed() >= limit {
            for p in &left {
                println!("lingering: {p} {}", cmdline(*p));
            }
            LINGERING.lock().unwrap().extend(left);
            break;
        }
        std::thread::sleep(SAMPLE_EVERY);
    }
    start.elapsed()
}

/// Sends one prompt to each Bot at once and waits for every run to finish, sampling all
/// of their processes together.
fn measure(b: &Botd, bots: &[String], prompts: &[String]) -> Measured {
    let (dir, pid) = (b.dir.display().to_string(), b.child.id() as i32);
    quiesce(b, QUIESCE);
    let (calls0, (own0, kids0)) = (calls(b), botd_ticks(b));
    let befores: Vec<usize> = bots.iter().map(|id| call(b, "GET", &format!("/api/bots/{id}/messages"), Value::Null).as_array().map_or(0, Vec::len)).collect();
    let sampler = Sampler::start(&dir, pid);
    let start = Instant::now();
    let ids: Vec<Value> = bots.iter().zip(prompts).map(|(id, p)| call(b, "POST", &format!("/api/bots/{id}/messages"), json!({ "text": p }))["id"].clone()).collect();
    let limit = Duration::from_secs(if real() { 600 } else { 300 });
    let finished: Vec<Value> = wait_for("the runs to finish", limit, || {
        let done: Vec<Value> = audit(b, "bot.run_finished").into_iter().map(|e| details(&e)).filter(|d| ids.contains(&d["messageId"])).collect();
        (done.len() == ids.len()).then_some(done)
    });
    let wall = start.elapsed();
    // Daemons and cleanup (`hermes gateway stop`) still count against the run.
    quiesce(b, QUIESCE);
    let usage = sampler.finish();
    let (own1, kids1) = botd_ticks(b);
    let tck = clk_tck();
    let detached: u64 = usage.detached_ticks.values().sum();
    let mut texts = Vec::new();
    for (id, before) in bots.iter().zip(befores) {
        let msgs = call(b, "GET", &format!("/api/bots/{id}/messages"), Value::Null);
        let fresh = msgs.as_array().map(|m| m[before.min(m.len())..].to_vec()).unwrap_or_default();
        texts.extend(fresh.iter().filter(|m| m["role"] == "bot").map(|m| m["text"].as_str().unwrap_or_default().to_string()));
    }
    let results: Vec<String> = finished.iter().map(|d| d["result"].as_str().unwrap_or_default().to_string()).collect();
    Measured {
        wall,
        result: results.join(","),
        text: texts.join("\n"),
        model_calls: calls(b) - calls0,
        cpu_s: ((kids1 - kids0 + detached) as f64 / tck * 100.0).round() / 100.0,
        botd_cpu_s: ((own1 - own0) as f64 / tck * 100.0).round() / 100.0,
        usage,
    }
}

fn run_json(m: &Measured) -> Value {
    json!({
        "wallS": secs(m.wall),
        "result": m.result,
        "modelCalls": m.model_calls,
        "peakRssMiB": kib_mib(m.usage.peak_rss_kib),
        "peakPssMiB": kib_mib(m.usage.peak_pss_kib),
        "peakProcesses": m.usage.peak_procs,
        "cpuS": m.cpu_s,
        "botdCpuS": m.botd_cpu_s,
    })
}

fn median(mut v: Vec<f64>) -> f64 {
    v.sort_by(|a, b| a.total_cmp(b));
    if v.is_empty() { 0.0 } else { v[v.len() / 2] }
}

fn max(v: impl IntoIterator<Item = f64>) -> f64 {
    v.into_iter().fold(0.0, f64::max)
}

// ---------------------------------------------------------------------------------
// One harness

struct Settings {
    runs: u64,
    concurrency: u64,
    delay: Duration,
    reserve_mib: u64,
}

/// Measures one harness. Returns its report and the ceilings it broke.
fn footprint(harness: &str, s: &Settings) -> (Value, Vec<String>) {
    let b = start(harness, false);
    let botd_pid = b.child.id() as i32;
    let id = call(&b, "GET", "/api/bots", Value::Null)[0]["id"].as_str().unwrap().to_string();
    // As in harness_e2e: the harness's own sandbox depends on the host, and the typical
    // run writes outside the workspace.
    call(&b, "PUT", "/api/policy", json!({ "sandbox": false }));
    // Hermes refuses a session without a model, and the fake endpoint has no default.
    let model = if real() { std::env::var("SUPERBOT_E2E_BOT_MODEL").ok().filter(|m| !m.is_empty()) } else { (harness == "hermes").then(|| MODEL.to_string()) };
    if let Some(m) = &model {
        call(&b, "PATCH", &format!("/api/bots/{id}"), json!({ "model": m }));
    }
    let proof = std::fs::canonicalize(b.dir.join("proof")).unwrap();
    let home = b.dir.join("home");
    let home0 = if real() { 0 } else { disk_bytes(&home) };
    let botd_idle0 = memory_kib(botd_pid);
    let delay = |d: Duration| {
        if let Some(m) = &b.model {
            m.set_delay(d);
        }
    };
    let hello = if real() { "Reply with the single word: ready. Use no tools.".to_string() } else { "hello".to_string() };
    let typical = |bot: &str, i: u64| prompt(&format!("touch {}", proof.join(format!("{bot}-{i}.marker")).display()));
    let mut broke = Vec::new();

    // Cold and warm start: one model turn, no tools, no model delay.
    delay(Duration::ZERO);
    let cold = measure(&b, std::slice::from_ref(&id), std::slice::from_ref(&hello));
    let warm: Vec<Measured> = (0..2).map(|_| measure(&b, std::slice::from_ref(&id), std::slice::from_ref(&hello))).collect();
    println!("{harness}: cold start {:.2}s, warm {:.2}s", cold.wall.as_secs_f64(), warm[0].wall.as_secs_f64());

    // Typical runs, each held open by the model's delay.
    delay(s.delay);
    let mut runs = Vec::new();
    for i in 0..s.runs {
        let m = measure(&b, std::slice::from_ref(&id), &[typical(&id, i)]);
        let marker = proof.join(format!("{id}-{i}.marker"));
        if !marker.exists() || (!real() && !m.text.contains(DONE)) {
            broke.push(format!("typical run {i} didn't run its command (result {}): {}", m.result, m.text));
        }
        println!("{harness}: run {i}: {:.2}s, peak PSS {:.0} MiB, CPU {:.2}s", m.wall.as_secs_f64(), kib_mib(m.usage.peak_pss_kib), m.cpu_s);
        runs.push(m);
    }

    // Idle: what's left once the last run ended (processes that outlived a run by
    // `QUIESCE` were moved to the lingering set), over a few seconds.
    let quiesced = quiesce(&b, QUIESCE);
    let linger = lingering();
    let linger_rss: u64 = linger.iter().map(|&p| memory_kib(p).0).sum();
    let linger_ticks0: u64 = linger.iter().filter_map(|&p| cpu_ticks(p).map(|t| t.0)).sum();
    let (botd_own0, _) = botd_ticks(&b);
    std::thread::sleep(Duration::from_secs(3));
    let linger_ticks1: u64 = linger.iter().filter_map(|&p| cpu_ticks(p).map(|t| t.0)).sum();
    let linger_cpu = (linger_ticks1.saturating_sub(linger_ticks0)) as f64 / clk_tck();
    let linger_list: Vec<Value> = linger.iter().map(|&p| json!({ "command": comm(p), "cmdline": cmdline(p), "rssMiB": kib_mib(memory_kib(p).0) })).collect();
    let (botd_own1, _) = botd_ticks(&b);
    let botd_idle = memory_kib(botd_pid);
    if kib_mib(linger_rss) > MAX_IDLE_MIB || linger_cpu > MAX_IDLE_CPU_S {
        broke.push(format!("processes left running after runs use {:.0} MiB and {linger_cpu:.2} CPU s in 3 s: {linger_list:?}", kib_mib(linger_rss)));
    }

    // Per-Bot state: the Bot's state dir, and what the CLI wrote to its home.
    let bot_state = disk_bytes(&b.dir.join("data/bots").join(&id));
    let bot_state_breakdown = breakdown(&b.dir.join("data/bots").join(&id), 3);
    let home_growth = if real() { None } else { Some(disk_bytes(&home).saturating_sub(home0)) };
    let home_breakdown = if real() { Value::Null } else { breakdown(&home, 3) };

    // Several Bots at once, each on its first run.
    let mut extra = Vec::new();
    for k in 0..s.concurrency {
        let mut body = json!({ "name": format!("Footprint {k}"), "harness": harness });
        if let Some(m) = &model {
            body["model"] = json!(m);
        }
        extra.push(call(&b, "POST", "/api/bots", body)["id"].as_str().unwrap().to_string());
    }
    let prompts: Vec<String> = extra.iter().map(|bot| typical(bot, 0)).collect();
    let together = measure(&b, &extra, &prompts);
    let ran = extra.iter().filter(|bot| proof.join(format!("{bot}-0.marker")).exists()).count();
    if ran != extra.len() {
        broke.push(format!("{ran} of {} concurrent runs ran their command (results {})", extra.len(), together.result));
    }
    println!("{harness}: {} at once: {:.2}s, peak PSS {:.0} MiB", s.concurrency, together.wall.as_secs_f64(), kib_mib(together.usage.peak_pss_kib));
    let new_bot_state = extra.iter().map(|bot| disk_bytes(&b.dir.join("data/bots").join(bot))).max().unwrap_or(0);
    // The same Bots again: the steady state, once each has run before.
    let prompts: Vec<String> = extra.iter().map(|bot| typical(bot, 1)).collect();
    let again = measure(&b, &extra, &prompts);
    let ran = extra.iter().filter(|bot| proof.join(format!("{bot}-1.marker")).exists()).count();
    if ran != extra.len() {
        broke.push(format!("{ran} of {} concurrent warm runs ran their command (results {})", extra.len(), again.result));
    }
    println!("{harness}: {} at once again: {:.2}s, peak PSS {:.0} MiB", s.concurrency, again.wall.as_secs_f64(), kib_mib(again.usage.peak_pss_kib));

    // Install.
    let (install, runtime) = install_dirs(harness);
    let install_path = install.clone();
    let install_bytes = install.as_deref().map(disk_bytes);
    let install_breakdown = install.as_deref().map(|i| breakdown(i, 1));
    let runtime_bytes = runtime.as_deref().map(disk_bytes);

    // Fit: concurrent runs per tier by memory, from the worst of one run alone and an
    // equal share of the concurrent peak.
    let share = |m: &Measured| kib_mib(m.usage.peak_pss_kib) / s.concurrency.max(1) as f64;
    let per_run_pss = max(runs.iter().map(|m| kib_mib(m.usage.peak_pss_kib)).chain([share(&together), share(&again)]));
    let per_run_cpu = median(runs.iter().map(|m| m.cpu_s).collect());
    // The Bot's own state; what the CLI writes to its home is shared by the Bots of one OS user.
    let per_bot_disk = mib(bot_state.max(new_bot_state));
    let home_disk = mib(home_growth.unwrap_or(0));
    let installed = mib(install_bytes.unwrap_or(0) + runtime_bytes.unwrap_or(0));
    let tiers: Vec<Value> = TIERS
        .iter()
        .map(|&(name, linode, incus, cpus, mem, disk_gib, max_bots)| {
            let usable = mem.saturating_sub(s.reserve_mib) as f64;
            let concurrent = if per_run_pss > 0.0 { (usable / per_run_pss).floor() as u64 } else { 0 };
            // Bots on disk: what's left after the install and 4 GiB for the OS.
            let free_disk = (disk_gib as f64 * 1024.0 - 4096.0 - installed - home_disk).max(0.0);
            // Null: a Bot's own state rounds to nothing, so disk doesn't limit Bots.
            let on_disk = (per_bot_disk >= 0.1).then(|| (free_disk / per_bot_disk).floor() as u64);
            json!({
                "tier": name, "linode": linode, "incus": incus, "vcpus": cpus, "memoryMiB": mem, "diskGiB": disk_gib,
                "maxBots": max_bots,
                "concurrentRunsByMemory": concurrent,
                "botsByDisk": on_disk,
                "maxBotsRunAtOnce": concurrent >= max_bots as u64,
            })
        })
        .collect();

    if cold.wall > MAX_COLD_START {
        broke.push(format!("cold start took {:?}, over {MAX_COLD_START:?}", cold.wall));
    }
    if per_run_pss > MAX_RUN_PSS_MIB {
        broke.push(format!("a run's peak PSS was {per_run_pss:.0} MiB, over {MAX_RUN_PSS_MIB} MiB"));
    }
    let mut commands: Vec<String> = runs.iter().chain([&together, &again]).flat_map(|m| m.usage.commands.iter().cloned()).collect::<HashSet<_>>().into_iter().collect();
    commands.sort();
    let mut cmdlines: Vec<String> = runs.iter().chain([&together, &again]).flat_map(|m| m.usage.cmdlines.iter().cloned()).collect::<HashSet<_>>().into_iter().collect();
    cmdlines.sort();

    let report = json!({
        "harness": harness,
        "version": version(harness, install_path.as_deref()),
        "model": if real() { "real" } else { "fake" },
        "install": {
            "path": install.map(|p| p.display().to_string()),
            "MiB": install_bytes.map(mib),
            "runtimePath": runtime.map(|p| p.display().to_string()),
            "runtimeMiB": runtime_bytes.map(mib),
            "breakdownMiB": install_breakdown,
        },
        "perBotState": {
            "stateDirMiB": mib(bot_state),
            "newBotStateDirMiB": mib(new_bot_state),
            "homeGrowthMiB": home_growth.map(mib),
            "breakdownMiB": bot_state_breakdown,
            "homeBreakdownMiB": home_breakdown,
        },
        "coldStart": run_json(&cold),
        "warmStart": warm.iter().map(run_json).collect::<Vec<_>>(),
        "typicalRuns": runs.iter().map(run_json).collect::<Vec<_>>(),
        "idle": {
            "quiesceS": secs(quiesced),
            "processesLeft": linger.len(),
            "lingering": linger_list,
            "lingeringRssMiB": kib_mib(linger_rss),
            "lingeringCpuS": (linger_cpu * 100.0).round() / 100.0,
            "botdRssMiB": kib_mib(botd_idle.0),
            "botdRssAtStartMiB": kib_mib(botd_idle0.0),
            "botdCpuS": ((botd_own1 - botd_own0) as f64 / clk_tck() * 100.0).round() / 100.0,
        },
        "concurrent": { "bots": s.concurrency, "run": run_json(&together), "again": run_json(&again) },
        "summary": {
            "coldStartS": secs(cold.wall),
            "warmStartS": median(warm.iter().map(|m| secs(m.wall)).collect()),
            "runWallS": median(runs.iter().map(|m| secs(m.wall)).collect()),
            "perRunPeakPssMiB": (per_run_pss * 10.0).round() / 10.0,
            "perRunPeakRssMiB": max(runs.iter().map(|m| kib_mib(m.usage.peak_rss_kib))),
            "perRunCpuS": per_run_cpu,
            "perRunPeakProcesses": runs.iter().map(|m| m.usage.peak_procs).max().unwrap_or(0),
            "idleProcesses": linger.len(),
            "idleRssMiB": kib_mib(linger_rss),
            "installMiB": installed,
            "perBotDiskMiB": per_bot_disk,
            "homeDiskMiB": home_disk,
        },
        "tiers": tiers,
        "processes": commands,
        "commandLines": cmdlines,
        "ceilingsBroken": broke,
    });
    let dir = b.dir.display().to_string();
    drop(b);
    // botd stops its runs and Hermes's daemons; anything else of theirs goes now.
    for p in all_processes(&dir) {
        // SAFETY: a process working for the botd this test started, which has stopped.
        unsafe { libc::kill(p, libc::SIGKILL) };
    }
    LINGERING.lock().unwrap().clear();
    (report, broke)
}

// ---------------------------------------------------------------------------------
// Report

fn machine() -> Value {
    let meminfo = std::fs::read_to_string("/proc/meminfo").unwrap_or_default();
    let mem_kib = meminfo.lines().find_map(|l| l.strip_prefix("MemTotal:")).and_then(|v| v.split_whitespace().next()?.parse::<u64>().ok()).unwrap_or(0);
    let cpu = std::fs::read_to_string("/proc/cpuinfo").unwrap_or_default().lines().find_map(|l| l.strip_prefix("model name")).map(|v| v.trim_start_matches([' ', '\t', ':']).to_string());
    let kernel = std::fs::read_to_string("/proc/sys/kernel/osrelease").unwrap_or_default().trim().to_string();
    let commit = std::env::var("GITHUB_SHA").ok().or_else(|| {
        let o = std::process::Command::new("git").args(["rev-parse", "HEAD"]).output().ok()?;
        o.status.success().then(|| String::from_utf8_lossy(&o.stdout).trim().to_string())
    });
    json!({
        "cpus": std::thread::available_parallelism().map(|n| n.get()).unwrap_or(0),
        "cpu": cpu,
        "memoryMiB": mem_kib / 1024,
        "kernel": kernel,
        "commit": commit,
        "ci": std::env::var("GITHUB_ACTIONS").is_ok(),
        "at": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
    })
}

fn markdown(report: &Value) -> String {
    let mut md = String::new();
    let m = &report["machine"];
    let s = &report["settings"];
    md.push_str("# Harness footprint\n\n");
    md.push_str(&format!(
        "Machine: {} CPUs{} ({}), {} MiB, kernel {}, commit `{}`, {}. Model: {}, {} ms per call in typical and concurrent runs; {} typical runs; {} Bots at once; {} MiB reserved per machine.\n\n",
        m["cpus"], if s["pinnedCpus"].is_string() { " (pinned)" } else { "" }, m["cpu"].as_str().unwrap_or("?"), m["memoryMiB"], m["kernel"].as_str().unwrap_or("?"),
        m["commit"].as_str().unwrap_or("?"), m["at"].as_str().unwrap_or("?"),
        s["model"].as_str().unwrap_or("?"), s["modelDelayMs"], s["runs"], s["concurrency"], s["reserveMiB"],
    ));
    md.push_str("| Harness | Version | Install MiB | Per-Bot disk MiB | Home MiB | Cold start s | Warm start s | Run s | Peak PSS MiB/run | Peak RSS MiB/run | CPU s/run | Processes/run | Idle processes (MiB) |\n");
    md.push_str("|---|---|---|---|---|---|---|---|---|---|---|---|---|\n");
    let harnesses = report["harnesses"].as_array().cloned().unwrap_or_default();
    for h in &harnesses {
        let x = &h["summary"];
        md.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} ({}) |\n",
            h["harness"].as_str().unwrap_or("?"), h["version"].as_str().unwrap_or("?"), x["installMiB"], x["perBotDiskMiB"], x["homeDiskMiB"],
            x["coldStartS"], x["warmStartS"], x["runWallS"], x["perRunPeakPssMiB"], x["perRunPeakRssMiB"], x["perRunCpuS"],
            x["perRunPeakProcesses"], x["idleProcesses"], x["idleRssMiB"],
        ));
    }
    md.push_str("\nConcurrent runs that fit each tier's machine by memory (machine memory less the reserve, over the peak PSS of one run):\n\n");
    md.push_str("| Harness |");
    for t in TIERS {
        md.push_str(&format!(" {} ({} MiB, maxBots {}) |", t.0, t.4, t.6));
    }
    md.push_str("\n|---|");
    md.push_str(&"---|".repeat(TIERS.len()));
    md.push('\n');
    for h in &harnesses {
        md.push_str(&format!("| {} |", h["harness"].as_str().unwrap_or("?")));
        for t in h["tiers"].as_array().into_iter().flatten() {
            md.push_str(&format!(" {}{} |", t["concurrentRunsByMemory"], if t["maxBotsRunAtOnce"] == true { "" } else { " (below maxBots)" }));
        }
        md.push('\n');
    }
    for h in &harnesses {
        let c = &h["concurrent"]["run"];
        md.push_str(&format!(
            "\n**{}**: {} new Bots at once peaked at {} MiB PSS ({} RSS) and {} processes, {} CPU s, in {} s; the same Bots again peaked at {} MiB PSS, {} CPU s, in {} s. Idle: {} processes left running ({} MiB: {}); botd {} MiB RSS. Processes seen: {}.\n",
            h["harness"].as_str().unwrap_or("?"), h["concurrent"]["bots"], c["peakPssMiB"], c["peakRssMiB"], c["peakProcesses"], c["cpuS"], c["wallS"],
            h["concurrent"]["again"]["peakPssMiB"], h["concurrent"]["again"]["cpuS"], h["concurrent"]["again"]["wallS"],
            h["idle"]["processesLeft"], h["idle"]["lingeringRssMiB"],
            h["idle"]["lingering"].as_array().map(|l| l.iter().filter_map(|x| x["command"].as_str()).collect::<Vec<_>>().join(", ")).unwrap_or_default(),
            h["idle"]["botdRssMiB"],
            h["processes"].as_array().map(|p| p.iter().filter_map(Value::as_str).collect::<Vec<_>>().join(", ")).unwrap_or_default(),
        ));
        for b in h["ceilingsBroken"].as_array().into_iter().flatten() {
            md.push_str(&format!("- Ceiling broken: {}\n", b.as_str().unwrap_or_default()));
        }
    }
    md
}

#[test]
#[ignore = "needs the harness CLIs; see deploy/harness-footprint.sh and the harness-e2e workflow"]
fn harness_footprint() {
    let s = Settings {
        runs: env_num("SUPERBOT_FOOTPRINT_RUNS", 3).max(1),
        concurrency: env_num("SUPERBOT_FOOTPRINT_CONCURRENCY", 4).max(1),
        delay: Duration::from_millis(env_num("SUPERBOT_FOOTPRINT_MODEL_DELAY_MS", 1500)),
        reserve_mib: env_num("SUPERBOT_FOOTPRINT_RESERVE_MIB", 512),
    };
    let out = std::env::var("SUPERBOT_FOOTPRINT_OUT").map(PathBuf::from).unwrap_or_else(|_| Path::new(env!("CARGO_MANIFEST_DIR")).join("../target/footprint"));
    std::fs::create_dir_all(&out).unwrap();
    let mut harnesses = Vec::new();
    let mut broke = BTreeMap::new();
    for (harness, bin) in [("hermes", "hermes"), ("claude", "claude"), ("codex", "codex"), ("pi", "pi")] {
        if !wanted(harness, bin) {
            continue;
        }
        let (report, b) = footprint(harness, &s);
        if !b.is_empty() {
            broke.insert(harness, b);
        }
        harnesses.push(report);
    }
    let report = json!({
        "machine": machine(),
        "settings": {
            "model": if real() { "real" } else { "fake" },
            "modelDelayMs": s.delay.as_millis() as u64,
            "runs": s.runs,
            "concurrency": s.concurrency,
            "reserveMiB": s.reserve_mib,
            "pinnedCpus": std::env::var("SUPERBOT_FOOTPRINT_CPUS").ok(),
        },
        "harnesses": harnesses,
    });
    std::fs::write(out.join("footprint.json"), serde_json::to_string_pretty(&report).unwrap()).unwrap();
    let md = markdown(&report);
    std::fs::write(out.join("footprint.md"), &md).unwrap();
    println!("\n{md}\nReport: {}", out.display());
    if std::env::var("SUPERBOT_FOOTPRINT_CEILINGS").as_deref() != Ok("off") {
        assert!(broke.is_empty(), "ceilings broken: {broke:#?}");
    }
}
