//! Host capacity on `/metrics` (ADR 0106): each Incus host's machines, CPUs, memory
//! and disk as placement counts them against its INCUS_CAPACITY and
//! INCUS_MAX_MACHINES (ADR 0081), and what each host, botd's own included, says it has
//! and uses now. Hosts are labelled by their INCUS_HOSTS name, or `botd` for botd's
//! own host (`kind` tells them apart), so series grow with configured hosts only.

use super::metrics::{family, sample};
use crate::machines::placement::{self, HostLoad};
use crate::machines::State;
use crate::machines::provider::{DiskUse, HostStatus, HostUse};
use crate::AppState;
use std::path::Path;

const GIB: f64 = (1u64 << 30) as f64;
/// The `host` label of botd's own host.
pub const SERVER: &str = "botd";

/// Placement's view of every configured Incus host, then each host's use.
pub fn render(app: &AppState, out: &mut String) {
    let mut hosts = vec![Row { host: SERVER.into(), kind: "server", at_ms: crate::db::now(), u: server_use(&app.cfg.data_dir, &app.cfg.workspace) }];
    if let Some(cp) = app.control_plane.get().filter(|cp| cp.enabled())
        && let Some(h) = cp.hosts()
    {
        let loads = placement::loads(app, cp, h);
        render_loads(&loads, out);
        let waiting = app
            .db
            .machines(None)
            .iter()
            .filter(|m| cp.owns(m) && m.state != State::Destroyed && m.last_error.as_deref().is_some_and(placement::waiting))
            .count();
        family(out, "superbot_incus_machines_waiting_for_room", "gauge", "Machines waiting to be made because no Incus host has room for them (ADR 0081).");
        sample(out, "superbot_incus_machines_waiting_for_room", &[], waiting as f64);
        let misplaced = placement::misplaced(app, cp, h).len();
        family(out, "superbot_incus_machines_misplaced", "gauge", "Machines on an Incus host their team's dedication doesn't allow, left there by a team change until moved (ADR 0166).");
        sample(out, "superbot_incus_machines_misplaced", &[], misplaced as f64);
        let metrics = app.db.metrics();
        if metrics.wants_host_use() {
            for l in loads.iter().filter(|l| l.status != HostStatus::Lost) {
                let (at_ms, u) = metrics.host_use(&l.name);
                hosts.push(Row { host: l.name.clone(), kind: "incus", at_ms, u });
            }
        }
    }
    render_use(&hosts, out);
}

fn render_loads(loads: &[HostLoad], out: &mut String) {
    let each = |out: &mut String, name: &str, help: &str, v: &dyn Fn(&HostLoad) -> Option<f64>| {
        if loads.iter().any(|l| v(l).is_some()) {
            family(out, name, "gauge", help);
            for l in loads {
                if let Some(x) = v(l) {
                    sample(out, name, &[("host", &l.name)], x);
                }
            }
        }
    };
    each(out, "superbot_incus_host_up", "1 if the Incus host answered its last check (ADR 0076).", &|l| {
        Some((l.status == HostStatus::Up && l.failing_since.is_none()) as u8 as f64)
    });
    each(out, "superbot_incus_host_open", "1 if new machines may go on the Incus host: up, answered its last check and not drained (ADR 0081).", &|l| {
        Some(l.closed().is_none() as u8 as f64)
    });
    each(out, "superbot_incus_host_dedicated", "1 if the Incus host is dedicated to one team, whose machines go only on such hosts (ADR 0166).", &|l| {
        Some(l.dedicated.is_some() as u8 as f64)
    });
    each(out, "superbot_incus_host_machines", "Machines on the Incus host, as placement counts them.", &|l| Some(l.machines as f64));
    each(out, "superbot_incus_host_max_machines", "The Incus host's INCUS_MAX_MACHINES.", &|l| l.max_machines.map(|n| n as f64));
    each(out, "superbot_incus_host_allocated_cpus", "CPUs the plans of machines on the Incus host give them.", &|l| Some(l.used.cpus as f64));
    each(out, "superbot_incus_host_allocated_memory_bytes", "Memory the plans of machines on the Incus host give them.", &|l| {
        Some(l.used.memory_gib as f64 * GIB)
    });
    each(out, "superbot_incus_host_allocated_disk_bytes", "Disk the plans of machines on the Incus host give them.", &|l| {
        Some(l.used.disk_gib as f64 * GIB)
    });
    each(out, "superbot_incus_host_capacity_cpus", "CPUs the Incus host's machines may be given in all (INCUS_CAPACITY).", &|l| {
        l.capacity.map(|c| c.cpus as f64)
    });
    each(out, "superbot_incus_host_capacity_memory_bytes", "Memory the Incus host's machines may be given in all (INCUS_CAPACITY).", &|l| {
        l.capacity.map(|c| c.memory_gib as f64 * GIB)
    });
    each(out, "superbot_incus_host_capacity_disk_bytes", "Disk the Incus host's machines may be given in all (INCUS_CAPACITY).", &|l| {
        l.capacity.map(|c| c.disk_gib as f64 * GIB)
    });
}

/// One host's use: its label, kind (`server` or `incus`), and when it was read.
struct Row {
    host: String,
    kind: &'static str,
    at_ms: i64,
    u: HostUse,
}

/// Each family once, with a sample per host that has it: the text format wants a
/// family's samples together.
fn render_use(hosts: &[Row], out: &mut String) {
    let each = |out: &mut String, name: &str, help: &str, v: &dyn Fn(&HostUse) -> Option<f64>| {
        if hosts.iter().any(|h| v(&h.u).is_some()) {
            family(out, name, "gauge", help);
            for h in hosts {
                if let Some(x) = v(&h.u) {
                    sample(out, name, &[("host", &h.host), ("kind", h.kind)], x);
                }
            }
        }
    };
    family(out, "superbot_host_reading_timestamp_seconds", "gauge", "When the host's use was last read; 0 if it never has been (ADR 0106).");
    for h in hosts {
        sample(out, "superbot_host_reading_timestamp_seconds", &[("host", &h.host), ("kind", h.kind)], h.at_ms as f64 / 1000.0);
    }
    each(out, "superbot_host_cpus", "CPU threads the host has.", &|u| u.cpus.map(|n| n as f64));
    each(out, "superbot_host_load1", "The host's load average over 1 minute.", &|u| u.load.map(|l| l.0));
    each(out, "superbot_host_load5", "The host's load average over 5 minutes.", &|u| u.load.map(|l| l.1));
    each(out, "superbot_host_memory_bytes", "Memory the host has.", &|u| u.memory.map(|m| m.1 as f64));
    each(out, "superbot_host_memory_used_bytes", "Memory in use on the host (botd's own: all but what is available).", &|u| {
        u.memory.map(|m| m.0 as f64)
    });
    disk_family(hosts, out, "superbot_host_disk_bytes", "Space on the host's disk: an Incus host's storage pool, or the filesystems of botd's DATA_DIR and WORKSPACE_DIR.", |d| d.total);
    disk_family(hosts, out, "superbot_host_disk_used_bytes", "Space used on the host's disk (botd's own: all but what botd may still write).", |d| d.used);
}

fn disk_family(hosts: &[Row], out: &mut String, name: &str, help: &str, v: fn(&DiskUse) -> u64) {
    if hosts.iter().all(|h| h.u.disks.is_empty()) {
        return;
    }
    family(out, name, "gauge", help);
    for h in hosts {
        for d in &h.u.disks {
            sample(out, name, &[("host", &h.host), ("kind", h.kind), ("disk", d.name)], v(d) as f64);
        }
    }
}

/// botd's own host now: its CPUs, load and memory from `/proc`, and the filesystems
/// DATA_DIR and WORKSPACE_DIR are on (the second only if it is another one). Parts it
/// can't read are left out.
pub fn server_use(data_dir: &Path, workspace: &Path) -> HostUse {
    let read = |p: &str| std::fs::read_to_string(p).ok();
    let mut disks = Vec::new();
    let data = disk("data", data_dir);
    let ws = disk("workspace", workspace);
    if let Some((d, _)) = &data {
        disks.push(d.clone());
    }
    if let Some((w, dev)) = ws
        && data.as_ref().is_none_or(|(_, d)| *d != dev)
    {
        disks.push(w);
    }
    HostUse {
        cpus: cpus(),
        load: read("/proc/loadavg").as_deref().and_then(parse_loadavg),
        memory: read("/proc/meminfo").as_deref().and_then(parse_meminfo),
        disks,
    }
}

/// `/proc/loadavg`'s 1 and 5 minute averages.
pub fn parse_loadavg(s: &str) -> Option<(f64, f64)> {
    let mut it = s.split_whitespace().map(str::parse::<f64>);
    Some((it.next()?.ok()?, it.next()?.ok()?))
}

/// `/proc/meminfo` as (used, total) bytes: used is all but MemAvailable.
pub fn parse_meminfo(s: &str) -> Option<(u64, u64)> {
    let kb = |key: &str| {
        s.lines()
            .find_map(|l| l.strip_prefix(key)?.strip_prefix(':'))
            .and_then(|v| v.trim().trim_end_matches("kB").trim().parse::<u64>().ok())
            .map(|n| n * 1024)
    };
    let (total, available) = (kb("MemTotal")?, kb("MemAvailable")?);
    (total > 0).then(|| (total.saturating_sub(available), total))
}

#[cfg(unix)]
fn cpus() -> Option<u64> {
    // SAFETY: sysconf reads a system setting and touches no memory of ours.
    let n = unsafe { libc::sysconf(libc::_SC_NPROCESSORS_ONLN) };
    (n > 0).then_some(n as u64)
}

#[cfg(not(unix))]
fn cpus() -> Option<u64> {
    None
}

/// The filesystem `path` is on: its space, and its device to tell two apart.
#[cfg(unix)]
// statvfs's fields are 32-bit on macOS and 32-bit Linux.
#[allow(clippy::useless_conversion)]
pub(crate) fn disk(name: &'static str, path: &Path) -> Option<(DiskUse, u64)> {
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::MetadataExt;
    let dev = std::fs::metadata(path).ok()?.dev();
    let c = std::ffi::CString::new(path.as_os_str().as_bytes()).ok()?;
    let mut st = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    // SAFETY: `c` is a NUL-terminated path and `st` is written by statvfs before it is read.
    if unsafe { libc::statvfs(c.as_ptr(), st.as_mut_ptr()) } != 0 {
        return None;
    }
    // SAFETY: statvfs returned 0, so it filled `st`.
    let st = unsafe { st.assume_init() };
    let frsize = u64::from(st.f_frsize);
    let total = u64::from(st.f_blocks).saturating_mul(frsize);
    let avail = u64::from(st.f_bavail).saturating_mul(frsize);
    (total > 0).then(|| (DiskUse { name, used: total.saturating_sub(avail), total }, dev))
}

#[cfg(not(unix))]
pub(crate) fn disk(_: &'static str, _: &Path) -> Option<(DiskUse, u64)> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proc_files_parse() {
        assert_eq!(parse_loadavg("0.52 1.25 0.98 2/1234 5678\n"), Some((0.52, 1.25)));
        assert_eq!(parse_loadavg(""), None);
        assert_eq!(parse_loadavg("x 1"), None);
        let meminfo = "MemTotal:       16000000 kB\nMemFree:         1000000 kB\nMemAvailable:    4000000 kB\nBuffers:  1 kB\n";
        assert_eq!(parse_meminfo(meminfo), Some((12_000_000 * 1024, 16_000_000 * 1024)));
        assert_eq!(parse_meminfo("MemTotal: 100 kB\n"), None, "no MemAvailable");
        assert_eq!(parse_meminfo("MemTotal: 0 kB\nMemAvailable: 0 kB\n"), None);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn botds_own_host_reads_cpus_load_memory_and_one_disk_per_filesystem() {
        let dir = crate::db::temp_path("capacity");
        std::fs::create_dir_all(dir.join("ws")).unwrap();
        let u = server_use(&dir, &dir.join("ws"));
        assert!(u.cpus.is_some_and(|n| n > 0), "{u:?}");
        assert!(u.load.is_some(), "{u:?}");
        assert!(u.memory.is_some_and(|(used, total)| used <= total && total > 0), "{u:?}");
        assert_eq!(u.disks.len(), 1, "the workspace is on DATA_DIR's filesystem: {u:?}");
        let d = &u.disks[0];
        assert!(d.name == "data" && d.total > 0 && d.used <= d.total, "{u:?}");
        // A workspace on another filesystem counts as a second disk.
        let dev = disk("data", &dir).unwrap().1;
        if let Some(other) = ["/dev/shm", "/run", "/boot", "/"].into_iter().map(Path::new).find(|p| disk("workspace", p).is_some_and(|(_, d)| d != dev)) {
            let two = server_use(&dir, other);
            assert_eq!(two.disks.iter().map(|d| d.name).collect::<Vec<_>>(), ["data", "workspace"], "{other:?}: {two:?}");
        }
        let none = server_use(&dir.join("missing"), &dir.join("missing"));
        assert!(none.disks.is_empty(), "{none:?}");
    }

    #[test]
    fn each_family_is_written_once_with_a_sample_per_host_that_has_it() {
        let incus = HostUse {
            cpus: Some(16),
            load: Some((1.5, 1.25)),
            memory: Some((8 << 30, 64 << 30)),
            disks: vec![DiskUse { name: "pool", used: 100, total: 1000 }],
        };
        let server = HostUse { cpus: Some(4), disks: vec![DiskUse { name: "data", used: 5, total: 50 }], ..Default::default() };
        let rows = [
            Row { host: SERVER.into(), kind: "server", at_ms: 2_000, u: server },
            Row { host: "a".into(), kind: "incus", at_ms: 1_500, u: incus },
            Row { host: "b".into(), kind: "incus", at_ms: 0, u: HostUse::default() },
        ];
        let mut out = String::new();
        render_use(&rows, &mut out);
        for want in [
            r#"superbot_host_reading_timestamp_seconds{host="botd",kind="server"} 2"#,
            r#"superbot_host_reading_timestamp_seconds{host="a",kind="incus"} 1.5"#,
            r#"superbot_host_reading_timestamp_seconds{host="b",kind="incus"} 0"#,
            r#"superbot_host_cpus{host="botd",kind="server"} 4"#,
            r#"superbot_host_cpus{host="a",kind="incus"} 16"#,
            r#"superbot_host_load5{host="a",kind="incus"} 1.25"#,
            r#"superbot_host_memory_bytes{host="a",kind="incus"} 68719476736"#,
            r#"superbot_host_memory_used_bytes{host="a",kind="incus"} 8589934592"#,
            r#"superbot_host_disk_bytes{host="botd",kind="server",disk="data"} 50"#,
            r#"superbot_host_disk_used_bytes{host="a",kind="incus",disk="pool"} 100"#,
        ] {
            assert!(out.contains(want), "{want} in:\n{out}");
        }
        assert!(!out.contains(r#"superbot_host_cpus{host="b""#) && !out.contains(r#"superbot_host_load1{host="botd""#), "{out}");
        // The text format wants one HELP and TYPE per family, before all its samples.
        let mut seen = std::collections::BTreeSet::new();
        let mut current = String::new();
        for line in out.lines() {
            if let Some(name) = line.strip_prefix("# TYPE ").and_then(|l| l.split(' ').next()) {
                assert!(seen.insert(name.to_string()), "{name} twice:\n{out}");
                current = name.to_string();
            } else if !line.starts_with('#') {
                assert!(line.starts_with(&format!("{current}{{")), "{line} outside its family:\n{out}");
            }
        }
    }
}
