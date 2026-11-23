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
//!
//! With hosts tagged by data region (ADR 0117), only hosts in the machine's region are
//! considered: one with no room there waits or is refused, never placed elsewhere.
//!
//! A host an admin dedicated to a team (ADR 0166) takes only that team's machines, and
//! a team with hosts of its own has its machines placed only there: with no room on
//! them it waits or is refused, never placed on a shared host. So a kernel escape from
//! a container on a dedicated host stays within one customer.

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
    /// Its data region, if hosts are tagged (ADR 0117).
    pub region: Option<String>,
    /// The team it is dedicated to (ADR 0166). None: shared.
    pub dedicated: Option<String>,
}

/// Whose machine is being placed, for hosts dedicated to a team (ADR 0166): its owner's
/// team, and whether that team has hosts of its own.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Tenant {
    pub team: Option<String>,
    pub own_hosts: bool,
}

impl Tenant {
    /// `user_id`'s: their team's (as a member or its service account), if any. A team's
    /// hosts count while dedicated to it, lost or unconfigured ones too, so losing its
    /// only host never sends its machines to a shared one.
    pub fn of(app: &App, user_id: &str) -> Tenant {
        let team = app.db.team_id_of(user_id);
        let own_hosts = team.as_deref().is_some_and(|t| app.db.machine_hosts().iter().any(|r| r.dedicated_team.as_deref() == Some(t)));
        Tenant { team, own_hosts }
    }
}

const OWN_HOSTS: &str = "this team's machines go only on its own hosts";

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

    /// Why a machine whose data stays in `region` can't go here, with tagged hosts.
    pub fn elsewhere(&self, region: &str) -> Option<String> {
        match &self.region {
            Some(r) if r != region => Some(format!("{} is in {r}", self.name)),
            _ => None,
        }
    }

    /// Why `t`'s machine can't go here, with hosts dedicated to teams (ADR 0166).
    pub fn not_for(&self, t: &Tenant) -> Option<String> {
        match (&self.dedicated, &t.team) {
            (Some(d), Some(team)) if d == team => None,
            (Some(_), _) => Some(format!("{} is dedicated to another team", self.name)),
            (None, _) if t.own_hosts => Some(format!("{} is shared, and {OWN_HOSTS}", self.name)),
            (None, _) => None,
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
            "free": free, "open": self.closed().is_none(), "closed": self.closed(), "region": self.region, "dedicatedTo": self.dedicated,
        })
    }
}

/// What `plan` takes from a host: nothing the provider can't size.
fn need(cp: &ControlPlane, plan: &str) -> Resources {
    cp.provider.as_deref().and_then(|p| p.plan_resources(plan)).unwrap_or_default()
}

/// What `m` takes on its host: its plan, or while a resize sent to the provider has an
/// unknown outcome (whatever has become of the request since), the larger of both
/// plans in each resource.
fn counted(cp: &ControlPlane, m: &Machine) -> Resources {
    let now = need(cp, &m.plan);
    match m.resize_sent_plan.as_deref().filter(|s| *s != m.plan) {
        Some(to) => {
            let to = need(cp, to);
            Resources { cpus: now.cpus.max(to.cpus), memory_gib: now.memory_gib.max(to.memory_gib), disk_gib: now.disk_gib.max(to.disk_gib) }
        }
        None => now,
    }
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
                region: c.region,
                dedicated: row.and_then(|r| r.dedicated_team.clone()),
            }
        })
        .collect();
    let mut add = |host: &str, takes: Resources| {
        if let Some(l) = out.iter_mut().find(|l| l.name == host) {
            l.machines += 1;
            l.used = l.used.plus(takes);
        }
    };
    let live: Vec<Machine> = app.db.machines(None).into_iter().filter(|m| cp.owns(m) && m.state != State::Destroyed).collect();
    for m in &live {
        match (&m.provider_id, &m.placed_on) {
            (Some(pid), _) => add(&h.host_of(pid), counted(cp, m)),
            // A create sent but not answered may have made it there.
            (None, Some(host)) => add(host, counted(cp, m)),
            (None, None) => {}
        }
    }
    // A restore onto another host takes room there from its import until its swap,
    // when the machine's record moves.
    for r in ["importing", "replacing"].into_iter().flat_map(|s| app.db.machine_restores_in(s)) {
        let (Some(to), Some(m)) = (r.to_host.as_deref(), live.iter().find(|m| m.id == r.machine_id)) else { continue };
        if m.provider_id.as_deref().map(|p| h.host_of(p)).as_deref() != Some(to) {
            add(to, need(cp, &m.plan));
        }
    }
    out
}

const NO_ROOM: &str = "No Incus host ";

/// Why no host can take a machine of `plan` (in `region`, with tagged hosts).
fn none(plan: &str, region: Option<&str>, why: Vec<String>) -> String {
    let within = region.map(|r| format!(" in {r}")).unwrap_or_default();
    match why.is_empty() {
        true => format!("{NO_ROOM}can take a {plan} machine{within}: none is configured."),
        false => format!("{NO_ROOM}has room for a {plan} machine{within}: {}.", why.join("; ")),
    }
}

/// Whether a machine's error says it is waiting for room, so it was announced already.
pub fn waiting(last_error: &str) -> bool {
    last_error.starts_with(NO_ROOM)
}

/// The host a new machine of `plan` for `t` goes on, other than `except`, by
/// INCUS_PLACEMENT; or why none can take it. With tagged hosts, only one in `region`
/// (ADR 0117); with dedicated hosts, only one `t` may use (ADR 0166).
pub fn choose(app: &App, cp: &ControlPlane, plan: &str, region: &str, t: &Tenant, except: Option<&str>) -> Result<String, String> {
    let Some(h) = cp.hosts() else { return Err(none(plan, None, Vec::new())) };
    let within = h.tagged().then_some(region);
    let want = need(cp, plan);
    let (mut fits, mut why) = (Vec::new(), Vec::new());
    for (i, l) in loads(app, cp, h).into_iter().filter(|l| Some(l.name.as_str()) != except).enumerate() {
        match l.elsewhere(region).or_else(|| l.not_for(t)).or_else(|| l.closed()).map(Err).unwrap_or_else(|| l.room(want)) {
            Ok(load) => fits.push((load, l.machines, i, l.name)),
            Err(e) => why.push(e),
        }
    }
    if h.policy() == Policy::Spread {
        fits.sort_by(|a, b| a.0.total_cmp(&b.0).then(a.1.cmp(&b.1)).then(a.2.cmp(&b.2)));
    }
    fits.into_iter().next().map(|f| f.3).ok_or_else(|| none(plan, within, why))
}

/// Whether a machine of `plan` for `t` whose data stays in `region` may go on `host`:
/// in that region (with tagged hosts), one `t` may use (ADR 0166), open, with room.
pub fn fits(app: &App, cp: &ControlPlane, plan: &str, region: &str, t: &Tenant, host: &str) -> Result<(), String> {
    let Some(h) = cp.hosts() else { return Ok(()) };
    let l = loads(app, cp, h).into_iter().find(|l| l.name == host).ok_or_else(|| format!("There's no Incus host \"{}\".", crate::audit::clip(host, 40)))?;
    if let Some(r) = &l.region
        && r != region
    {
        return Err(format!("Host {host} is in {r}, and this machine's data stays in {region} (ADR 0117)."));
    }
    if let Some(why) = l.not_for(t) {
        return Err(format!("Host {why} (ADR 0166)."));
    }
    match l.closed() {
        Some(why) => Err(format!("Host {why}; nothing new goes there.")),
        None => l.room(need(cp, plan)).map(drop).map_err(|e| format!("Host {e}.")),
    }
}

/// Whether machine `m` on `host` may grow to plan `to` where it is (ADR 0085): the
/// extra CPUs, memory and disk within the host's capacity. Its machine count doesn't
/// change, and a drained host still lets its own machines grow.
pub fn grow(app: &App, cp: &ControlPlane, host: &str, m: &Machine, to: &str) -> Result<(), String> {
    let Some(h) = cp.hosts() else { return Ok(()) };
    let (a, b) = (counted(cp, m), need(cp, to));
    let more = Resources {
        cpus: b.cpus.saturating_sub(a.cpus),
        memory_gib: b.memory_gib.saturating_sub(a.memory_gib),
        disk_gib: b.disk_gib.saturating_sub(a.disk_gib),
    };
    if more == Resources::default() {
        return Ok(());
    }
    let l = loads(app, cp, h).into_iter().find(|l| l.name == host).ok_or_else(|| format!("There's no Incus host \"{}\".", crate::audit::clip(host, 40)))?;
    if matches!(l.status, HostStatus::Down | HostStatus::Lost) {
        return Err(l.closed().unwrap_or_default());
    }
    let Some(cap) = l.capacity else { return Ok(()) };
    for (what, used, want, of) in [
        ("CPUs", l.used.cpus, more.cpus, cap.cpus),
        ("GiB of memory", l.used.memory_gib, more.memory_gib, cap.memory_gib),
        ("GiB of disk", l.used.disk_gib, more.disk_gib, cap.disk_gib),
    ] {
        if want > 0 && used.saturating_add(want) > of {
            return Err(format!("{} has {} of {of} {what} free, {want} more needed", l.name, of.saturating_sub(used)));
        }
    }
    Ok(())
}

/// A machine on a host its team's dedication doesn't allow (ADR 0166). Placement never
/// puts one there; a person who joins or leaves a team leaves their machine where it
/// was, until an admin moves it with a restore onto another host.
#[derive(Clone, Debug, PartialEq)]
pub struct Misplaced {
    pub machine_id: String,
    pub user_id: String,
    pub host: String,
    pub reason: String,
}

impl Misplaced {
    pub fn view(&self) -> Value {
        json!({ "machineId": self.machine_id, "userId": self.user_id, "host": self.host, "reason": self.reason })
    }
}

/// Every machine that isn't destroyed and is on (or sent to) a host it shouldn't be:
/// one dedicated to another team, or a shared one while its team has hosts of its own.
pub fn misplaced(app: &App, cp: &ControlPlane, h: &dyn Hosts) -> Vec<Misplaced> {
    let rows = app.db.machine_hosts();
    if rows.iter().all(|r| r.dedicated_team.is_none()) {
        return Vec::new();
    }
    let dedicated: HashMap<&str, &str> = rows.iter().filter_map(|r| Some((r.name.as_str(), r.dedicated_team.as_deref()?))).collect();
    let teams = app.db.team_ids();
    let mut out = Vec::new();
    for m in app.db.machines(None).into_iter().filter(|m| cp.owns(m) && m.state != State::Destroyed) {
        let Some(host) = m.provider_id.as_deref().map(|p| h.host_of(p)).or_else(|| m.placed_on.clone()) else { continue };
        let team = teams.get(&m.user_id).map(String::as_str);
        let reason = match (dedicated.get(host.as_str()), team) {
            (Some(d), Some(t)) if *d == t => continue,
            (Some(_), Some(_)) => format!("{host} is dedicated to another team"),
            (Some(_), None) => format!("{host} is dedicated to a team its owner isn't on"),
            (None, Some(t)) if dedicated.values().any(|d| *d == t) => format!("{host} is shared, and its owner's team has hosts of its own"),
            (None, _) => continue,
        };
        out.push(Misplaced { machine_id: m.id, user_id: m.user_id, host, reason });
    }
    out
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
    let mut lines = vec![
        why.to_string(),
        "Add capacity (INCUS_CAPACITY, or another host in INCUS_HOSTS), undrain a host, or free room; `botctl machine hosts` shows each host's load.".into(),
    ];
    if why.contains(OWN_HOSTS) {
        lines.push("Its team's machines go only on the hosts dedicated to it: add room there, or dedicate another (`botctl machine host dedicate <name> <team>`, ADR 0166).".into());
    }
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
            region: None,
            dedicated: None,
        }
    }

    #[test]
    fn dedicated_hosts_take_only_their_teams_machines_and_such_teams_go_nowhere_else() {
        let t = |team: Option<&str>, own_hosts| Tenant { team: team.map(String::from), own_hosts };
        let shared = host("a", None, None, 0, (0, 0, 0));
        let acme = HostLoad { dedicated: Some("acme".into()), ..host("b", None, None, 0, (0, 0, 0)) };
        assert_eq!(shared.not_for(&t(None, false)), None, "no team, shared host");
        assert_eq!(shared.not_for(&t(Some("globex"), false)), None, "a team without hosts of its own uses shared ones");
        assert_eq!(acme.not_for(&t(Some("acme"), true)), None);
        assert_eq!(acme.not_for(&t(Some("globex"), false)).as_deref(), Some("b is dedicated to another team"));
        assert_eq!(acme.not_for(&t(None, false)).as_deref(), Some("b is dedicated to another team"), "people in no team too");
        assert_eq!(shared.not_for(&t(Some("acme"), true)).as_deref(), Some("a is shared, and this team's machines go only on its own hosts"));
        assert_eq!(acme.view()["dedicatedTo"], "acme");
        assert!(shared.view()["dedicatedTo"].is_null());
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
        let mut lon = host("lon-1", None, None, 0, (0, 0, 0));
        assert_eq!(lon.elsewhere("de-fra-2"), None, "untagged hosts take any region");
        lon.region = Some("gb-lon".into());
        assert_eq!((lon.elsewhere("gb-lon"), lon.elsewhere("de-fra-2").as_deref()), (None, Some("lon-1 is in gb-lon")));
        assert_eq!(none("c1-m2-d20", Some("de-fra-2"), vec!["lon-1 is in gb-lon".into()]), "No Incus host has room for a c1-m2-d20 machine in de-fra-2: lon-1 is in gb-lon.");
        assert!(waiting(&none("c1-m2-d20", Some("de-fra-2"), vec![])), "a machine waiting for room in its region says so like any other");
        let v = host("b", Some((8, 32, 500)), Some(10), 2, (4, 8, 80)).view();
        assert_eq!(v["free"], json!({ "cpus": 4, "memoryGiB": 24, "diskGiB": 420 }));
        assert_eq!((v["open"].as_bool(), v["allocated"]["cpus"].as_u64()), (Some(true), Some(4)));
    }
}
