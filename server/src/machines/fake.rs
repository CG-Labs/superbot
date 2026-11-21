//! An in-memory provider for tests: no network, no money. Labels are unique, as at
//! Linode. A new machine is `provisioning` and a booted one `booting` until the next
//! `get`, which finds them `running`, so reconciliation has something to do.
//! Firewalls follow Linode's rules too: labels are unique, a machine is behind at most
//! one, a create naming a firewall puts the machine behind it, and deleting a machine
//! takes it off.

use super::provider::{
    CreateSpec, FirewallDevices, FirewallRule, Fut, MachineProvider, ProviderError, ProviderFirewall,
    ProviderMachine, RebuildSpec,
};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Mutex;

#[derive(Default)]
pub struct Fake {
    state: Mutex<State>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct FakeFirewall {
    pub id: String,
    pub label: String,
    pub tags: Vec<String>,
    pub rules: Vec<FirewallRule>,
    /// Set behind the control plane's back: rules of a shape it doesn't make.
    pub foreign: bool,
    pub enabled: bool,
    pub machines: BTreeSet<String>,
    /// Devices that aren't machines, e.g. a NodeBalancer someone put behind it.
    pub others: usize,
}

#[derive(Default)]
struct State {
    next: u64,
    machines: BTreeMap<String, ProviderMachine>,
    firewalls: BTreeMap<String, FakeFirewall>,
    /// One-shot failures, by operation name (`create`, `get`, `shutdown`, ...).
    fail: HashMap<&'static str, ProviderError>,
    /// One-shot lost answers: the operation is done, then fails with a transport error.
    lost: BTreeSet<&'static str>,
    calls: Vec<String>,
    /// The user data each create or rebuild was sent, by label: what the machine boots with.
    user_data: HashMap<String, String>,
    /// Plans' disks in bytes, where they differ from Linode's (`plan_disk`).
    disks: HashMap<String, Option<u64>>,
    /// One-shot hooks run as an operation starts, before it's done.
    during: HashMap<&'static str, Box<dyn FnOnce() + Send>>,
}

/// Linode's disks for the default tiers' plans, in GiB.
const DISKS_GIB: [(&str, u64); 3] = [("g6-standard-1", 50), ("g6-standard-2", 80), ("g6-standard-4", 160)];

fn refused(message: &str) -> ProviderError {
    ProviderError::Api {
        status: 400,
        message: message.into(),
    }
}

impl State {
    fn firewall_of(&self, machine: &str) -> Option<&FakeFirewall> {
        self.firewalls.values().find(|f| f.machines.contains(machine))
    }
}

impl Fake {
    fn with<T>(
        &self,
        op: &'static str,
        f: impl FnOnce(&mut State) -> Result<T, ProviderError>,
    ) -> Result<T, ProviderError> {
        let hook = self.state.lock().unwrap().during.remove(op);
        if let Some(h) = hook {
            h();
        }
        let mut s = self.state.lock().unwrap();
        s.calls.push(op.into());
        if let Some(e) = s.fail.remove(op) {
            return Err(e);
        }
        let out = f(&mut s);
        if out.is_ok() && s.lost.remove(op) {
            return Err(ProviderError::Transport("connection reset".into()));
        }
        out
    }

    fn update(
        &self,
        op: &'static str,
        id: &str,
        f: impl FnOnce(&mut ProviderMachine),
    ) -> Result<(), ProviderError> {
        self.with(op, |s| {
            s.machines.get_mut(id).map(f).ok_or(ProviderError::NotFound)
        })
    }

    /// The next `op` fails with `e`.
    pub fn fail_next(&self, op: &'static str, e: ProviderError) {
        self.state.lock().unwrap().fail.insert(op, e);
    }

    /// `f` runs while the next `op` is under way, as if something else happened meanwhile.
    pub fn during_next(&self, op: &'static str, f: impl FnOnce() + Send + 'static) {
        self.state.lock().unwrap().during.insert(op, Box::new(f));
    }

    /// The next `op` is done, but its answer is lost.
    pub fn lose_next(&self, op: &'static str) {
        self.state.lock().unwrap().lost.insert(op);
    }

    /// A machine made behind the control plane's back, e.g. by a create whose answer was lost.
    pub fn insert(&self, label: &str, plan: &str, region: &str, tags: &[&str]) -> String {
        let mut s = self.state.lock().unwrap();
        s.next += 1;
        let id = (1000 + s.next).to_string();
        let m = ProviderMachine {
            id: id.clone(),
            label: label.into(),
            status: "running".into(),
            plan: plan.into(),
            region: region.into(),
            ipv4: Some(format!("192.0.2.{}", s.next)),
            backups: false,
            tags: tags.iter().map(|t| t.to_string()).collect(),
            user_data: false,
        };
        s.machines.insert(id.clone(), m);
        id
    }

    /// Changed behind the control plane's back, e.g. by a call whose answer was lost.
    pub fn set(&self, id: &str, f: impl FnOnce(&mut ProviderMachine)) {
        f(self.state.lock().unwrap().machines.get_mut(id).unwrap());
    }

    /// Deleted behind the control plane's back.
    pub fn remove(&self, id: &str) {
        let mut s = self.state.lock().unwrap();
        s.machines.remove(id);
        for f in s.firewalls.values_mut() {
            f.machines.remove(id);
        }
    }

    pub fn machines(&self) -> Vec<ProviderMachine> {
        self.state
            .lock()
            .unwrap()
            .machines
            .values()
            .cloned()
            .collect()
    }

    pub fn firewalls(&self) -> Vec<FakeFirewall> {
        self.state
            .lock()
            .unwrap()
            .firewalls
            .values()
            .cloned()
            .collect()
    }

    /// A firewall changed behind the control plane's back, e.g. in the provider's console.
    pub fn set_firewall(&self, id: &str, f: impl FnOnce(&mut FakeFirewall)) {
        f(self.state.lock().unwrap().firewalls.get_mut(id).unwrap());
    }

    /// A firewall made behind the control plane's back.
    pub fn insert_firewall(&self, label: &str, machines: &[&str]) -> String {
        let mut s = self.state.lock().unwrap();
        s.next += 1;
        let id = (500 + s.next).to_string();
        s.firewalls.insert(
            id.clone(),
            FakeFirewall {
                id: id.clone(),
                label: label.into(),
                tags: Vec::new(),
                rules: Vec::new(),
                foreign: true,
                enabled: true,
                machines: machines.iter().map(|m| m.to_string()).collect(),
                others: 0,
            },
        );
        id
    }

    /// `plan`'s disk is `bytes` (None: the provider can't say).
    pub fn set_plan_disk(&self, plan: &str, bytes: Option<u64>) {
        self.state.lock().unwrap().disks.insert(plan.into(), bytes);
    }

    /// What the last create or rebuild for `label` carried as cloud-init user data.
    pub fn user_data(&self, label: &str) -> Option<String> {
        self.state.lock().unwrap().user_data.get(label).cloned()
    }

    pub fn calls(&self, op: &str) -> usize {
        self.state
            .lock()
            .unwrap()
            .calls
            .iter()
            .filter(|c| *c == op)
            .count()
    }

    /// Calls to any firewall operation.
    pub fn firewall_calls(&self) -> usize {
        self.state
            .lock()
            .unwrap()
            .calls
            .iter()
            .filter(|c| c.contains("firewall"))
            .count()
    }
}

fn view(f: &FakeFirewall) -> ProviderFirewall {
    ProviderFirewall {
        id: f.id.clone(),
        label: f.label.clone(),
        rules: (!f.foreign).then(|| f.rules.clone()),
        enabled: f.enabled,
    }
}

impl MachineProvider for Fake {
    fn name(&self) -> &'static str {
        "fake"
    }

    fn create<'a>(&'a self, spec: &'a CreateSpec) -> Fut<'a, ProviderMachine> {
        Box::pin(async move {
            self.with("create", |s| {
                if s.machines.values().any(|m| m.label == spec.label) {
                    return Err(ProviderError::LabelTaken);
                }
                if let Some(fw) = &spec.firewall_id
                    && !s.firewalls.contains_key(fw)
                {
                    return Err(refused("firewall_id: Not found"));
                }
                if let Some(ud) = &spec.user_data {
                    s.user_data.insert(spec.label.clone(), ud.clone());
                }
                s.next += 1;
                let id = (1000 + s.next).to_string();
                let m = ProviderMachine {
                    id: id.clone(),
                    label: spec.label.clone(),
                    status: "provisioning".into(),
                    plan: spec.plan.clone(),
                    region: spec.region.clone(),
                    ipv4: Some(format!("192.0.2.{}", s.next)),
                    backups: false,
                    tags: spec.tags.clone(),
                    user_data: false,
                };
                if let Some(fw) = &spec.firewall_id {
                    s.firewalls.get_mut(fw).unwrap().machines.insert(id.clone());
                }
                s.machines.insert(id, m.clone());
                Ok(m)
            })
        })
    }

    fn get<'a>(&'a self, id: &'a str) -> Fut<'a, ProviderMachine> {
        Box::pin(async move {
            self.with("get", |s| {
                let m = s.machines.get_mut(id).ok_or(ProviderError::NotFound)?;
                if matches!(m.status.as_str(), "provisioning" | "booting" | "rebuilding") {
                    m.status = "running".into();
                }
                Ok(m.clone())
            })
        })
    }

    fn list<'a>(&'a self, tag: &'a str) -> Fut<'a, Vec<ProviderMachine>> {
        Box::pin(async move {
            self.with("list", |s| {
                Ok(s.machines
                    .values()
                    .filter(|m| m.tags.iter().any(|t| t == tag))
                    .cloned()
                    .collect())
            })
        })
    }

    fn resize<'a>(&'a self, id: &'a str, plan: &'a str) -> Fut<'a, ()> {
        Box::pin(async move { self.update("resize", id, |m| m.plan = plan.into()) })
    }

    fn plan_disk<'a>(&'a self, plan: &'a str) -> Fut<'a, Option<u64>> {
        Box::pin(async move {
            self.with("plan_disk", |s| {
                Ok(s.disks.get(plan).copied().unwrap_or_else(|| DISKS_GIB.iter().find(|(p, _)| *p == plan).map(|(_, g)| g << 30)))
            })
        })
    }

    fn shutdown<'a>(&'a self, id: &'a str) -> Fut<'a, ()> {
        Box::pin(async move { self.update("shutdown", id, |m| m.status = "offline".into()) })
    }

    fn boot<'a>(&'a self, id: &'a str) -> Fut<'a, ()> {
        Box::pin(async move { self.update("boot", id, |m| m.status = "booting".into()) })
    }

    fn enable_backups<'a>(&'a self, id: &'a str) -> Fut<'a, ()> {
        Box::pin(async move { self.update("enable_backups", id, |m| m.backups = true) })
    }

    fn delete<'a>(&'a self, id: &'a str) -> Fut<'a, ()> {
        Box::pin(async move {
            self.with("delete", |s| {
                s.machines.remove(id);
                for f in s.firewalls.values_mut() {
                    f.machines.remove(id);
                }
                Ok(())
            })
        })
    }

    fn rebuild<'a>(&'a self, id: &'a str, spec: &'a RebuildSpec) -> Fut<'a, ()> {
        Box::pin(async move {
            self.with("rebuild", |s| {
                let m = s.machines.get_mut(id).ok_or(ProviderError::NotFound)?;
                m.status = "rebuilding".into();
                let label = m.label.clone();
                s.user_data.insert(label, spec.user_data.clone());
                Ok(())
            })
        })
    }

    fn find_firewall<'a>(&'a self, label: &'a str) -> Fut<'a, Option<ProviderFirewall>> {
        Box::pin(async move {
            self.with("find_firewall", |s| {
                Ok(s.firewalls.values().find(|f| f.label == label).map(view))
            })
        })
    }

    fn get_firewall<'a>(&'a self, id: &'a str) -> Fut<'a, ProviderFirewall> {
        Box::pin(async move {
            self.with("get_firewall", |s| {
                s.firewalls.get(id).map(view).ok_or(ProviderError::NotFound)
            })
        })
    }

    fn create_firewall<'a>(
        &'a self,
        label: &'a str,
        tags: &'a [String],
        rules: &'a [FirewallRule],
    ) -> Fut<'a, ProviderFirewall> {
        Box::pin(async move {
            self.with("create_firewall", |s| {
                if s.firewalls.values().any(|f| f.label == label) {
                    return Err(ProviderError::LabelTaken);
                }
                s.next += 1;
                let id = (500 + s.next).to_string();
                let f = FakeFirewall {
                    id: id.clone(),
                    label: label.into(),
                    tags: tags.to_vec(),
                    rules: rules.to_vec(),
                    foreign: false,
                    enabled: true,
                    machines: BTreeSet::new(),
                    others: 0,
                };
                let v = view(&f);
                s.firewalls.insert(id, f);
                Ok(v)
            })
        })
    }

    fn set_firewall_rules<'a>(&'a self, id: &'a str, rules: &'a [FirewallRule]) -> Fut<'a, ()> {
        Box::pin(async move {
            self.with("set_firewall_rules", |s| {
                let f = s.firewalls.get_mut(id).ok_or(ProviderError::NotFound)?;
                (f.rules, f.foreign) = (rules.to_vec(), false);
                Ok(())
            })
        })
    }

    fn enable_firewall<'a>(&'a self, id: &'a str) -> Fut<'a, ()> {
        Box::pin(async move {
            self.with("enable_firewall", |s| {
                s.firewalls.get_mut(id).ok_or(ProviderError::NotFound)?.enabled = true;
                Ok(())
            })
        })
    }

    fn firewall_devices<'a>(&'a self, id: &'a str) -> Fut<'a, FirewallDevices> {
        Box::pin(async move {
            self.with("firewall_devices", |s| {
                let f = s.firewalls.get(id).ok_or(ProviderError::NotFound)?;
                Ok(FirewallDevices {
                    machines: f.machines.iter().cloned().collect(),
                    others: f.others,
                })
            })
        })
    }

    fn attach_firewall<'a>(&'a self, id: &'a str, machine: &'a str) -> Fut<'a, ()> {
        Box::pin(async move {
            self.with("attach_firewall", |s| {
                if !s.firewalls.contains_key(id) {
                    return Err(ProviderError::NotFound);
                }
                if !s.machines.contains_key(machine) {
                    return Err(refused("id: Linode not found"));
                }
                if s.firewall_of(machine).is_some() {
                    return Err(refused("This Linode already has an active Firewall."));
                }
                s.firewalls
                    .get_mut(id)
                    .unwrap()
                    .machines
                    .insert(machine.into());
                Ok(())
            })
        })
    }

    fn detach_firewall<'a>(&'a self, id: &'a str, machine: &'a str) -> Fut<'a, ()> {
        Box::pin(async move {
            self.with("detach_firewall", |s| {
                if let Some(f) = s.firewalls.get_mut(id) {
                    f.machines.remove(machine);
                }
                Ok(())
            })
        })
    }

    fn delete_firewall<'a>(&'a self, id: &'a str) -> Fut<'a, ()> {
        Box::pin(async move {
            self.with("delete_firewall", |s| {
                s.firewalls.remove(id);
                Ok(())
            })
        })
    }
}
