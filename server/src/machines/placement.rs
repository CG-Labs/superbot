//! Placing machines on Incus hosts by load (ADR 0081). Each host's load is what its
//! machines' plans take from it (CPUs, memory, disk) and how many there are, from
//! botd's own records: every machine on it that isn't destroyed, suspended ones
//! included (they keep their disk and come back with their limits), and restores on
//! their way to it. A host gets a new or restored machine only if it is up, answered
//! its last check, isn't drained by an admin, and has room for the machine's plan
//! under its INCUS_CAPACITY and INCUS_MAX_MACHINES. Of those, `spread` picks the one
//! least loaded after placing it, `fill` the first in the order configured. With no
//! room anywhere the machine isn't made: the request is refused, or the machine waits
//! with the reason, audited (`machine.placement_failed`) and alerted once.

use super::provider::{HostStatus, Hosts, Policy, Resources};
use super::{ControlPlane, State};
use crate::audit::{Outcome, Who};
use crate::db::Machine;
use crate::notify::{self, Alert};
use crate::runner::App;
use serde_json::{Value, json};
use std::collections::HashMap;

/// One host's load, and whether anything new may go there.
#[derive(Clone, Debug)]
pub struct HostLoad {
    pub name: String,
    pub status: HostStatus,
    pub failing_since: Option<i64>,
    pub drained: bool,
    pub capacity: Option<Resources>,
    pub max_machines: Option<u64>,
    pub machines: u64,
    pub used: Resources,
}

fn ratio(used: u64, cap: u64) -> f64 {
    if cap == 0 { f64::INFINITY } else { used as f64 / cap as f64 }
}

impl HostLoad {
    /// Why nothing new goes here, whatever its size.
    pub fn closed(&self) -> Option<String> {
        match self.status {
            HostStatus::Lost => Some(format!("{} was declared lost", self.name)),
            HostStatus::Down => Some(format!("{} is down", self.name)),
            HostStatus::Up if self.failing_since.is_some() => Some(format!("{} didn't answer its last check", self.name)),
            HostStatus::Up if self.drained => Some(format!("{} is drained", self.name)),
            HostStatus::Up => None,
        }
    }

    /// How loaded it would be with `need` on it too (the fullest of CPUs, memory, disk
    /// and machines, 1.0 when full), or why it hasn't room.
    pub fn room(&self, need: Resources) -> Result<f64, String> {
        let after = self.used.plus(need);
        let mut load: f64 = 0.0;
        if let Some(cap) = self.capacity {
            for (what, used, want, of) in [
                ("CPUs", after.cpus, need.cpus, cap.cpus),
                ("GiB of memory", after.memory_gib, need.memory_gib, cap.memory_gib),
                ("GiB of disk", after.disk_gib, need.disk_gib, cap.disk_gib),
            ] {
                if used > of {
                    return Err(format!("{} has {} of {of} {what} free, {want} needed", self.name, of.saturating_sub(used - want)));
                }
                load = load.max(ratio(used, of));
            }
        }
        if let Some(max) = self.max_machines {
            if self.machines + 1 > max {
                return Err(format!("{} has {} of {max} machines", self.name, self.machines));
            }
            load = load.max(ratio(self.machines + 1, max));
        }
        Ok(load)
    }

    pub fn view(&self) -> Value {
        let free = self.capacity.map(|c| Resources {
            cpus: c.cpus.saturating_sub(self.used.cpus),
            memory_gib: c.memory_gib.saturating_sub(self.used.memory_gib),
            disk_gib: c.disk_gib.saturating_sub(self.used.disk_gib),
        });
        json!({
            "machines": self.machines, "allocated": self.used, "capacity": self.capacity, "maxMachines": self.max_machines,
            "free": free, "open": self.closed().is_none(), "closed": self.closed(),
        })
    }
}

/// What `plan` takes from a host: nothing the provider can't size.
fn need(cp: &ControlPlane, plan: &str) -> Resources {
    cp.provider.as_deref().and_then(|p| p.plan_resources(plan)).unwrap_or_default()
}

/// Every configured host's load, in the order configured.
pub fn loads(app: &App, cp: &ControlPlane, h: &dyn Hosts) -> Vec<HostLoad> {
    let rows: HashMap<String, crate::db::MachineHost> = app.db.machine_hosts().into_iter().map(|r| (r.name.clone(), r)).collect();
    let mut out: Vec<HostLoad> = h
        .configured()
        .into_iter()
        .map(|c| {
            let row = rows.get(&c.name);
            HostLoad {
                failing_since: row.and_then(|r| r.failing_since),
                drained: row.is_some_and(|r| r.drained_at.is_some()),
                name: c.name,
                status: c.status,
                capacity: c.capacity,
                max_machines: c.max_machines,
                machines: 0,
                used: Resources::default(),
            }
        })
        .collect();
    let mut add = |host: &str, plan: &str| {
        if let Some(l) = out.iter_mut().find(|l| l.name == host) {
            l.machines += 1;
            l.used = l.used.plus(need(cp, plan));
        }
    };
    let live: Vec<Machine> = app.db.machines(None).into_iter().filter(|m| cp.owns(m) && m.state != State::Destroyed).collect();
    for m in &live {
        if let Some(pid) = &m.provider_id {
            add(&h.host_of(pid), &m.plan);
        }
    }
    // A restore onto another host takes room there from its import until its swap,
    // when the machine's record moves.
    for r in ["importing", "replacing"].into_iter().flat_map(|s| app.db.machine_restores_in(s)) {
        let (Some(to), Some(m)) = (r.to_host.as_deref(), live.iter().find(|m| m.id == r.machine_id)) else { continue };
        if m.provider_id.as_deref().map(|p| h.host_of(p)).as_deref() != Some(to) {
            add(to, &m.plan);
        }
    }
    out
}

/// Why no host can take a machine of `plan`.
fn none(plan: &str, why: Vec<String>) -> String {
    match why.is_empty() {
        true => format!("No Incus host can take a {plan} machine: none is configured."),
        false => format!("No Incus host has room for a {plan} machine: {}.", why.join("; ")),
    }
}

/// The host a new machine of `plan` goes on, other than `except`, by INCUS_PLACEMENT;
/// or why none can take it.
pub fn choose(app: &App, cp: &ControlPlane, plan: &str, except: Option<&str>) -> Result<String, String> {
    let Some(h) = cp.hosts() else { return Err(none(plan, Vec::new())) };
    let want = need(cp, plan);
    let (mut fits, mut why) = (Vec::new(), Vec::new());
    for (i, l) in loads(app, cp, h).into_iter().filter(|l| Some(l.name.as_str()) != except).enumerate() {
        match l.closed().map(Err).unwrap_or_else(|| l.room(want)) {
            Ok(load) => fits.push((load, l.machines, i, l.name)),
            Err(e) => why.push(e),
        }
    }
    if h.policy() == Policy::Spread {
        fits.sort_by(|a, b| a.0.total_cmp(&b.0).then(a.1.cmp(&b.1)).then(a.2.cmp(&b.2)));
    }
    fits.into_iter().next().map(|f| f.3).ok_or_else(|| none(plan, why))
}

/// Whether a machine of `plan` may go on `host`: open, with room.
pub fn fits(app: &App, cp: &ControlPlane, plan: &str, host: &str) -> Result<(), String> {
    let Some(h) = cp.hosts() else { return Ok(()) };
    let l = loads(app, cp, h).into_iter().find(|l| l.name == host).ok_or_else(|| format!("There's no Incus host \"{}\".", crate::audit::clip(host, 40)))?;
    match l.closed() {
        Some(why) => Err(format!("Host {why}; nothing new goes there.")),
        None => l.room(need(cp, plan)).map(drop).map_err(|e| format!("Host {e}.")),
    }
}

/// A machine (or a request for one, `m` None) that couldn't be placed: audited and
/// alerted.
pub fn failed(app: &crate::AppState, by: &Who, user_id: &str, m: Option<&Machine>, plan: &str, why: &str) {
    let mut e = by.event("machine.placement_failed").outcome(Outcome::Failure);
    e = match m {
        Some(m) => e.target("machine", &m.id),
        None => e.target("user", user_id),
    };
    app.db.record(&e.details(json!({ "userId": user_id, "plan": plan, "error": why })));
    let lines = vec![
        why.to_string(),
        "Add capacity (INCUS_CAPACITY, or another host in INCUS_HOSTS), undrain a host, or free room; `botctl machine hosts` shows each host's load.".into(),
    ];
    let a = Alert {
        event: "machine.placement_failed".into(),
        title: "No Incus host has room for a machine".into(),
        lines,
        target_type: if m.is_some() { "machine" } else { "user" }.into(),
        target_id: m.map_or(user_id, |m| &m.id).to_string(),
        link: None,
    };
    notify::alert(app, a, "machines");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host(name: &str, cap: Option<(u64, u64, u64)>, max: Option<u64>, machines: u64, used: (u64, u64, u64)) -> HostLoad {
        let r = |(cpus, memory_gib, disk_gib)| Resources { cpus, memory_gib, disk_gib };
        HostLoad {
            name: name.into(),
            status: HostStatus::Up,
            failing_since: None,
            drained: false,
            capacity: cap.map(r),
            max_machines: max,
            machines,
            used: r(used),
        }
    }

    #[test]
    fn room_is_the_fullest_of_cpus_memory_disk_and_machines() {
        let small = Resources { cpus: 2, memory_gib: 4, disk_gib: 40 };
        let h = host("a", Some((16, 64, 1000)), None, 3, (6, 12, 120));
        assert_eq!(h.room(small), Ok(0.5), "8 of 16 CPUs");
        let h = host("a", Some((16, 64, 1000)), Some(4), 3, (6, 12, 120));
        assert_eq!(h.room(small), Ok(1.0), "its 4th of 4 machines");
        let h = host("a", Some((16, 64, 1000)), Some(3), 3, (6, 12, 120));
        assert_eq!(h.room(small).unwrap_err(), "a has 3 of 3 machines");
        let h = host("a", Some((16, 64, 1000)), None, 7, (15, 12, 120));
        assert_eq!(h.room(small).unwrap_err(), "a has 1 of 16 CPUs free, 2 needed");
        let h = host("a", Some((16, 64, 100)), None, 1, (2, 4, 70));
        assert_eq!(h.room(small).unwrap_err(), "a has 30 of 100 GiB of disk free, 40 needed");
        assert_eq!(host("a", None, None, 50, (100, 200, 2000)).room(small), Ok(0.0), "no limits set");
    }

    #[test]
    fn closed_hosts_say_why() {
        let mut h = host("a", None, None, 0, (0, 0, 0));
        assert_eq!(h.closed(), None);
        h.drained = true;
        assert_eq!(h.closed().as_deref(), Some("a is drained"));
        h.failing_since = Some(1);
        assert_eq!(h.closed().as_deref(), Some("a didn't answer its last check"));
        h.status = HostStatus::Down;
        assert_eq!(h.closed().as_deref(), Some("a is down"));
        h.status = HostStatus::Lost;
        assert_eq!(h.closed().as_deref(), Some("a was declared lost"));
        let v = host("b", Some((8, 32, 500)), Some(10), 2, (4, 8, 80)).view();
        assert_eq!(v["free"], json!({ "cpus": 4, "memoryGiB": 24, "diskGiB": 420 }));
        assert_eq!((v["open"].as_bool(), v["allocated"]["cpus"].as_u64()), (Some(true), Some(4)));
    }
}
