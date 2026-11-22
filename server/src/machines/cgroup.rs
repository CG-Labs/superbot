//! Limits per run on a user's machine (ADR 0135). The agent's unit is delegated its
//! cgroup (`Delegate=`), which the agent splits in two: `agent`, where it and what it
//! starts itself (screens, logins) live, and `runs`, which holds every Bot's run in a
//! cgroup of its own, with its CPU quota, memory, process count and IO weight.
//!
//! `runs` as a whole is held under the machine's memory, so the agent and the OS keep
//! room whatever the runs do. A run that goes over its memory is killed as a whole
//! (`memory.oom.group`); one that forks past its process limit gets errors; one that
//! wants more CPU waits. Each run's exit says what its cgroup saw, and botd audits it.
//!
//! A run enters its cgroup before it execs, so nothing it starts is ever outside it.
//! What a run leaves running stays in its cgroup, still held, until it exits; then
//! the next run's sweep removes the empty cgroup. Shared by both binaries.

#![allow(dead_code)]

use super::wire::{AppliedLimits, LimitReport, RunLimits, RunLimitsReport, RUN_LIMITS_ON, RUN_LIMITS_UNAVAILABLE};
use std::fs::File;
use std::os::fd::AsRawFd;
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

/// Runs' cgroups made and not yet dropped, by name: a sweep leaves them, even before
/// their process is in them. Held across a start's sweep, creation and registration.
type Live = Arc<Mutex<HashSet<String>>>;

/// The controllers a run's limits need, and one more applied where there is one.
pub const REQUIRED: [&str; 3] = ["cpu", "memory", "pids"];
pub const OPTIONAL: [&str; 1] = ["io"];
/// cpu.max's period: a quota is CPU time per 100 ms.
pub const PERIOD_US: u64 = 100_000;
/// What every run's limits come to at least, whatever the percentages say.
const MIN_MEMORY: u64 = 64 << 20;
const MIN_QUOTA_US: u64 = 1_000;
/// Share of the machine's memory all runs together may take: the rest is the agent's
/// and the OS's.
pub const RUNS_MEMORY_PERCENT: u64 = 90;
/// The agent's own CPU weight against all runs together (100 is the kernel's default),
/// so it still answers botd while runs are busy.
const AGENT_CPU_WEIGHT: &str = "400";

/// The defaults where a tier sets none (ADR 0135).
pub const DEFAULT: RunLimits = RunLimits { cpu_percent: 80, memory_percent: 75, pids: 1024, io_weight: 100 };

/// The cgroup this process is in, under `root` (cgroup v2 only), from
/// `/proc/self/cgroup`. An agent started again inside its own `agent` cgroup gets
/// the one above it.
pub fn own_base(proc_self_cgroup: &str, root: &Path) -> Option<PathBuf> {
    let path = proc_self_cgroup.lines().find_map(|l| l.strip_prefix("0::"))?.trim();
    let rel = path.trim_start_matches('/');
    let rel = rel.strip_suffix("/agent").or(if rel == "agent" { Some("") } else { None }).unwrap_or(rel);
    if rel.split('/').any(|c| c == "..") {
        return None;
    }
    Some(if rel.is_empty() { root.to_path_buf() } else { root.join(rel) })
}

/// The machine's memory as its runs see it: `MemTotal`, or less where a cgroup above
/// `base` holds it to less (a container without lxcfs, say).
pub fn machine_memory(base: &Path, root: &Path, meminfo: &str) -> u64 {
    let total = meminfo
        .lines()
        .find_map(|l| l.strip_prefix("MemTotal:"))
        .and_then(|v| v.trim().trim_end_matches("kB").trim().parse::<u64>().ok())
        .map_or(u64::MAX, |kb| kb.saturating_mul(1024));
    let mut least = total;
    let mut at = Some(base);
    while let Some(dir) = at {
        if let Ok(v) = std::fs::read_to_string(dir.join("memory.max"))
            && let Ok(n) = v.trim().parse::<u64>()
        {
            least = least.min(n);
        }
        if dir == root {
            break;
        }
        at = dir.parent();
    }
    least
}

/// One counter from a cgroup's `key value` file, 0 if it isn't there.
pub fn counter(text: &str, key: &str) -> u64 {
    text.lines()
        .find_map(|l| l.split_once(' ').filter(|(k, _)| *k == key).map(|(_, v)| v.trim()))
        .and_then(|v| v.parse().ok())
        .unwrap_or(0)
}

fn write(dir: &Path, file: &str, value: &str) -> Result<(), String> {
    std::fs::write(dir.join(file), value).map_err(|e| format!("{file} ← {value}: {e}"))
}

fn read(dir: &Path, file: &str) -> String {
    std::fs::read_to_string(dir.join(file)).unwrap_or_default()
}

fn mkdir(dir: &Path) -> Result<(), String> {
    match std::fs::create_dir(dir) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
        Err(e) => Err(format!("{}: {e}", dir.display())),
    }
}

/// The limits for a machine of `cpus` CPUs and `memory` bytes.
pub fn absolute(l: &RunLimits, cpus: u32, memory: u64, io: bool) -> AppliedLimits {
    let pct = |p: u32| u64::from(p.clamp(1, 100));
    AppliedLimits {
        cpu_quota_us: (u64::from(cpus.max(1)) * PERIOD_US * pct(l.cpu_percent) / 100).max(MIN_QUOTA_US),
        memory_bytes: (memory / 100).saturating_mul(pct(l.memory_percent)).max(MIN_MEMORY),
        pids: l.pids.max(1),
        io_weight: io.then_some(l.io_weight.clamp(1, 10_000)),
    }
}

/// Caps all runs' memory together below the machine's, so the agent always has room.
fn runs_memory(runs: &Path, memory: u64) -> Result<(), String> {
    let cap = if memory == u64::MAX { "max".to_string() } else { ((memory / 100) * RUNS_MEMORY_PERCENT).to_string() };
    write(runs, "memory.max", &cap)
}

/// The agent's delegated cgroup, set up for runs.
#[derive(Debug)]
pub struct Cgroups {
    base: PathBuf,
    runs: PathBuf,
    live: Live,
    controllers: Vec<String>,
    /// The machine's CPUs and memory, as last measured: a resize changes them live.
    size: Mutex<(u32, u64)>,
}

impl Cgroups {
    /// Splits `base` into `agent` and `runs`: every process in `base` moves to
    /// `agent` (the kernel allows controllers only on a cgroup with none of its own),
    /// then the controllers are turned on below it. `cpus` and `memory`: the machine's.
    pub fn setup(base: &Path, cpus: u32, memory: u64) -> Result<Cgroups, String> {
        let have = read(base, "cgroup.controllers");
        let have: Vec<&str> = have.split_whitespace().collect();
        let missing: Vec<&str> = REQUIRED.iter().copied().filter(|c| !have.contains(c)).collect();
        if !missing.is_empty() {
            return Err(format!("{} lacks the {} controller(s): is the unit delegated them?", base.display(), missing.join(", ")));
        }
        let agent = base.join("agent");
        mkdir(&agent)?;
        // Processes may fork while they move; a few passes catch them.
        for _ in 0..5 {
            let pids = read(base, "cgroup.procs");
            if pids.trim().is_empty() {
                break;
            }
            for pid in pids.split_whitespace() {
                // One that exited meanwhile can't be moved, and needn't be.
                let _ = write(&agent, "cgroup.procs", pid);
            }
        }
        let mut on: Vec<String> = Vec::new();
        for c in REQUIRED.iter().chain(OPTIONAL.iter()).filter(|c| have.contains(c)) {
            match write(base, "cgroup.subtree_control", &format!("+{c}")) {
                Ok(()) => on.push(c.to_string()),
                Err(e) if REQUIRED.contains(c) => return Err(e),
                Err(_) => {}
            }
        }
        let _ = write(&agent, "cpu.weight", AGENT_CPU_WEIGHT);
        let runs = base.join("runs");
        mkdir(&runs)?;
        for c in &on {
            if let Err(e) = write(&runs, "cgroup.subtree_control", &format!("+{c}"))
                && REQUIRED.contains(&c.as_str())
            {
                return Err(e);
            }
        }
        runs_memory(&runs, memory)?;
        let cg = Cgroups { base: base.to_path_buf(), runs, live: Live::default(), controllers: on, size: Mutex::new((cpus.max(1), memory)) };
        cg.sweep();
        Ok(cg)
    }

    pub fn base(&self) -> &Path {
        &self.base
    }

    /// Takes the machine's size as measured now, so runs follow a resize: the next
    /// run's limits, and the cap on all runs' memory together.
    pub fn resize(&self, cpus: u32, memory: u64) -> Result<(), String> {
        let mut size = self.size.lock().unwrap_or_else(|e| e.into_inner());
        if size.1 != memory {
            runs_memory(&self.runs, memory)?;
        }
        *size = (cpus.max(1), memory);
        Ok(())
    }

    pub fn report(&self) -> RunLimitsReport {
        RunLimitsReport { state: RUN_LIMITS_ON.into(), controllers: self.controllers.clone(), error: None }
    }

    pub fn unavailable(why: String) -> RunLimitsReport {
        RunLimitsReport { state: RUN_LIMITS_UNAVAILABLE.into(), controllers: vec![], error: Some(why) }
    }

    pub fn runs(&self) -> &Path {
        &self.runs
    }

    fn io(&self) -> bool {
        self.controllers.iter().any(|c| c == "io")
    }

    /// The limits `l` comes to on this machine.
    pub fn applied(&self, l: &RunLimits) -> AppliedLimits {
        let (cpus, memory) = *self.size.lock().unwrap_or_else(|e| e.into_inner());
        absolute(l, cpus, memory, self.io())
    }

    /// A cgroup for the run `name`, held to `l`. A name in use is refused, since its
    /// counters would be another run's.
    pub fn start(&self, name: &str, l: &RunLimits) -> Result<RunCgroup, String> {
        if name.is_empty() || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_') {
            return Err("a run's cgroup needs a plain name".into());
        }
        let mut live = self.live.lock().unwrap_or_else(|e| e.into_inner());
        self.sweep_except(&live);
        let dir = self.runs.join(name);
        std::fs::create_dir(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        let applied = self.applied(l);
        let set = || -> Result<File, String> {
            write(&dir, "cpu.max", &format!("{} {PERIOD_US}", applied.cpu_quota_us))?;
            write(&dir, "memory.max", &applied.memory_bytes.to_string())?;
            // Swap would let a run past its memory, slowly: none for runs.
            if dir.join("memory.swap.max").exists() {
                let _ = write(&dir, "memory.swap.max", "0");
            }
            write(&dir, "memory.oom.group", "1")?;
            write(&dir, "pids.max", &applied.pids.to_string())?;
            if let Some(w) = applied.io_weight {
                let _ = write(&dir, "io.weight", &format!("default {w}"));
            }
            std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(false)
                .open(dir.join("cgroup.procs"))
                .map_err(|e| format!("cgroup.procs: {e}"))
        };
        match set() {
            Ok(procs) => {
                live.insert(name.to_string());
                Ok(RunCgroup { dir, procs, applied, name: name.to_string(), live: self.live.clone() })
            }
            Err(e) => {
                let _ = std::fs::remove_dir(&dir);
                Err(e)
            }
        }
    }

    /// Removes runs' cgroups that nothing is in any more and no run holds.
    pub fn sweep(&self) {
        let live = self.live.lock().unwrap_or_else(|e| e.into_inner());
        self.sweep_except(&live);
    }

    fn sweep_except(&self, live: &HashSet<String>) {
        let Ok(entries) = std::fs::read_dir(&self.runs) else { return };
        for e in entries.flatten() {
            let p = e.path();
            let held = e.file_name().to_str().is_some_and(|n| live.contains(n));
            if !held && p.is_dir() && counter(&read(&p, "cgroup.events"), "populated") == 0 {
                let _ = std::fs::remove_dir(&p);
            }
        }
    }
}

/// One run's cgroup. Its process joins it through `procs` before it execs.
#[derive(Debug)]
pub struct RunCgroup {
    dir: PathBuf,
    procs: File,
    applied: AppliedLimits,
    name: String,
    live: Live,
}

impl RunCgroup {
    pub fn procs_fd(&self) -> std::os::fd::RawFd {
        self.procs.as_raw_fd()
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// What its cgroup saw so far.
    pub fn report(&self) -> LimitReport {
        let mem = read(&self.dir, "memory.events");
        LimitReport {
            enforced: true,
            oom_kills: counter(&mem, "oom_kill"),
            memory_max_hits: counter(&mem, "max"),
            pids_refused: counter(&read(&self.dir, "pids.events"), "max"),
            cpu_throttled_ms: counter(&read(&self.dir, "cpu.stat"), "throttled_usec") / 1000,
            applied: Some(self.applied),
            error: None,
        }
    }
}

impl Drop for RunCgroup {
    /// Gone once empty. What the run left running keeps it until the next sweep.
    fn drop(&mut self) {
        let mut live = self.live.lock().unwrap_or_else(|e| e.into_inner());
        live.remove(&self.name);
        let _ = std::fs::remove_dir(&self.dir);
    }
}

/// Moves the calling process into the cgroup whose `cgroup.procs` is `fd`, then
/// becomes `user`. For `pre_exec`: only async-signal-safe calls. Joining first is what
/// lets it in: once it is the Bots' user, it may no longer move itself.
pub fn enter(fd: std::os::fd::RawFd, user: Option<(u32, u32)>) -> std::io::Result<()> {
    let last = std::io::Error::last_os_error;
    // SAFETY: plain syscalls on an open fd and on this process's own ids.
    unsafe {
        if libc::write(fd, b"0".as_ptr().cast(), 1) != 1 {
            return Err(last());
        }
        if let Some((uid, gid)) = user {
            if libc::setgroups(0, std::ptr::null()) != 0 || libc::setgid(gid) != 0 || libc::setuid(uid) != 0 {
                return Err(last());
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_its_own_cgroup() {
        let root = Path::new("/sys/fs/cgroup");
        let s = "0::/system.slice/superbot-machine.service\n";
        assert_eq!(own_base(s, root).unwrap(), root.join("system.slice/superbot-machine.service"));
        // Restarted inside its own leaf: the one above.
        let s = "0::/system.slice/superbot-machine.service/agent\n";
        assert_eq!(own_base(s, root).unwrap(), root.join("system.slice/superbot-machine.service"));
        assert_eq!(own_base("0::/\n", root).unwrap(), root);
        // cgroup v1 only, or a path that climbs: none.
        assert_eq!(own_base("12:memory:/x\n", root), None);
        assert_eq!(own_base("0::/a/../../etc\n", root), None);
    }

    #[test]
    fn limits_come_to_shares_of_the_machine() {
        let a = absolute(&DEFAULT, 2, 4 << 30, true);
        assert_eq!(a.cpu_quota_us, 160_000, "80% of 2 CPUs per 100 ms");
        assert_eq!(a.memory_bytes, (4u64 << 30) / 100 * 75);
        assert_eq!((a.pids, a.io_weight), (1024, Some(100)));
        // Out-of-range shares are clamped, tiny machines get a floor, no io controller: no weight.
        let odd = RunLimits { cpu_percent: 500, memory_percent: 0, pids: 0, io_weight: 99_999 };
        let a = absolute(&odd, 0, 10 << 20, false);
        assert_eq!((a.cpu_quota_us, a.memory_bytes, a.pids, a.io_weight), (100_000, MIN_MEMORY, 1, None));
    }

    #[test]
    fn memory_is_the_least_of_meminfo_and_the_cgroups_above() {
        let dir = std::env::temp_dir().join(format!("sb-cg-mem-{}", std::process::id()));
        let base = dir.join("a/b");
        std::fs::create_dir_all(&base).unwrap();
        let meminfo = "MemTotal:        8000000 kB\nMemFree: 1 kB\n";
        assert_eq!(machine_memory(&base, &dir, meminfo), 8_000_000 * 1024);
        std::fs::write(dir.join("a/memory.max"), "2147483648\n").unwrap();
        std::fs::write(base.join("memory.max"), "max\n").unwrap();
        assert_eq!(machine_memory(&base, &dir, meminfo), 2 << 30);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn counters_are_read_by_name() {
        let ev = "low 0\nhigh 0\nmax 12\noom 2\noom_kill 1\noom_group_kill 1\n";
        assert_eq!((counter(ev, "max"), counter(ev, "oom_kill"), counter(ev, "absent")), (12, 1, 0));
        assert_eq!(counter("usage_usec 10\nthrottled_usec 2500000\n", "throttled_usec"), 2_500_000);
    }

    /// The same steps on a plain folder: what it writes where, without a kernel.
    #[test]
    fn setup_and_a_run_write_the_limits() {
        let base = std::env::temp_dir().join(format!("sb-cg-setup-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        std::fs::write(base.join("cgroup.controllers"), "cpuset cpu memory\n").unwrap();
        let e = Cgroups::setup(&base, 2, 4 << 30).unwrap_err();
        assert!(e.contains("pids"), "{e}");
        std::fs::write(base.join("cgroup.controllers"), "cpuset cpu io memory pids\n").unwrap();
        let cg = Cgroups::setup(&base, 2, 4 << 30).unwrap();
        assert_eq!(cg.report().controllers, ["cpu", "memory", "pids", "io"]);
        assert_eq!(read(&base.join("runs"), "memory.max"), ((4u64 << 30) / 100 * 90).to_string());
        assert_eq!(read(&base.join("agent"), "cpu.weight"), AGENT_CPU_WEIGHT);
        let run = cg.start("j1", &DEFAULT).unwrap();
        assert_eq!(read(run.dir(), "cpu.max"), "160000 100000");
        assert_eq!(read(run.dir(), "pids.max"), "1024");
        assert_eq!(read(run.dir(), "memory.oom.group"), "1");
        assert_eq!(read(run.dir(), "io.weight"), "default 100");
        assert!(cg.start("j1", &DEFAULT).is_err(), "a name in use");
        // A resize: the cap on all runs follows, and so do the next run's limits.
        cg.resize(4, 8 << 30).unwrap();
        assert_eq!(read(&base.join("runs"), "memory.max"), ((8u64 << 30) / 100 * 90).to_string());
        assert_eq!(cg.applied(&DEFAULT).cpu_quota_us, 320_000);
        cg.resize(2, 4 << 30).unwrap();
        // Another run's start doesn't sweep one whose process isn't in it yet.
        let j2 = cg.start("j2", &DEFAULT).unwrap();
        assert!(run.dir().exists() && j2.dir().exists());
        assert!(cg.start("../x", &DEFAULT).is_err());
        std::fs::write(run.dir().join("memory.events"), "max 3\noom_kill 1\n").unwrap();
        std::fs::write(run.dir().join("pids.events"), "max 7\n").unwrap();
        let r = run.report();
        assert!(r.enforced && r.oom_kills == 1 && r.memory_max_hits == 3 && r.pids_refused == 7, "{r:?}");
        std::fs::remove_dir_all(&base).unwrap();
    }
}
