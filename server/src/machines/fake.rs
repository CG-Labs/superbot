//! An in-memory provider for tests: no network, no money. Labels are unique, as at
//! Linode. A new machine is `provisioning` and a booted one `booting` until the next
//! `get`, which finds them `running`, so reconciliation has something to do.
//! Firewalls follow Linode's rules too: labels are unique, a machine is behind at most
//! one, a create naming a firewall puts the machine behind it, and deleting a machine
//! takes it off. Backups are Linode's too (`reports_backups`), though none is ever
//! taken by itself.

use super::provider::{
    CreateSpec, FirewallDevices, FirewallRule, Fut, MachineProvider, NetworkMember, ProviderError, ProviderFirewall,
    ProviderMachine, RebuildSpec, TeamNetwork,
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
    /// Machines with Linode interfaces only some of which are behind it (ADR 0226).
    pub partly: BTreeSet<String>,
    /// Devices that aren't machines, e.g. a NodeBalancer someone put behind it.
    pub others: usize,
}

/// A team network as Linode's VPCs are (ADR 0189): one subnet our machines join, and
/// whatever else is on it.
#[derive(Clone, Debug, PartialEq)]
pub struct FakeNetwork {
    pub id: String,
    pub label: String,
    pub region: String,
    pub subnet_id: String,
    pub subnet: String,
    pub members: BTreeSet<String>,
    /// Machines given an interface while running (ADR 0202): inactive, and members only
    /// from their next boot.
    pub pending: BTreeSet<String>,
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
    /// What `firewall_egress` reports, as Linode's outbound rules would be.
    egress: Option<serde_json::Value>,
    networks: BTreeMap<String, FakeNetwork>,
    /// Machines that take a team network's interface only once rebuilt (ADR 0212).
    team_nic_rebuild: BTreeSet<String>,
    /// Machines with Linode interfaces (ADR 0226): theirs are added and removed only
    /// while they are off.
    linode_interfaces: BTreeSet<String>,
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
        self.firewalls.values().find(|f| f.machines.contains(machine) || f.partly.contains(machine))
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
            last_backup_at: None,
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
        for n in s.networks.values_mut() {
            n.members.remove(id);
            n.pending.remove(id);
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

    /// Reports `rules` as the outbound rules its firewalls carry (ADR 0179).
    pub fn set_firewall_egress(&self, rules: serde_json::Value) {
        self.state.lock().unwrap().egress = Some(rules);
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
                partly: BTreeSet::new(),
                others: 0,
            },
        );
        id
    }

    pub fn networks(&self) -> Vec<FakeNetwork> {
        self.state.lock().unwrap().networks.values().cloned().collect()
    }

    /// The team network `machine` is on, if any.
    pub fn network_of(&self, machine: &str) -> Option<String> {
        self.state.lock().unwrap().networks.values().find(|n| n.members.contains(machine)).map(|n| n.id.clone())
    }

    /// The team network `machine` joins at its next boot, if any.
    pub fn joining(&self, machine: &str) -> Option<String> {
        self.state.lock().unwrap().networks.values().find(|n| n.pending.contains(machine)).map(|n| n.id.clone())
    }

    /// Puts `member` on network `id` behind the control plane's back: a machine of
    /// someone's, or a team's own service.
    pub fn join_network(&self, id: &str, member: &str) {
        self.state.lock().unwrap().networks.get_mut(id).unwrap().members.insert(member.into());
    }

    /// As if machine `id` were an Incus container made before ADR 0212.
    pub fn team_nic_needs_rebuild_for(&self, id: &str) {
        self.state.lock().unwrap().team_nic_rebuild.insert(id.into());
    }

    /// As if machine `id` were a Linode with Linode interfaces (ADR 0226).
    pub fn linode_interfaces_for(&self, id: &str) {
        self.state.lock().unwrap().linode_interfaces.insert(id.into());
    }

    /// As if network `id` was made under another label, e.g. another MACHINE_LABEL_PREFIX.
    pub fn relabel_network(&self, id: &str, label: &str) {
        self.state.lock().unwrap().networks.get_mut(id).unwrap().label = label.into();
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

fn net_view(n: &FakeNetwork, created: bool) -> TeamNetwork {
    TeamNetwork { id: n.id.clone(), label: n.label.clone(), region: n.region.clone(), subnet_id: n.subnet_id.clone(), subnet: n.subnet.clone(), created }
}

impl MachineProvider for Fake {
    fn name(&self) -> &'static str {
        "fake"
    }

    fn substrate(&self) -> &'static str {
        "vm"
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
                let net = match &spec.subnet_id {
                    None => None,
                    Some(sub) => Some(
                        s.networks.values().find(|n| n.subnet_id == *sub).map(|n| n.id.clone()).ok_or_else(|| refused("subnet_id: Not found"))?,
                    ),
                };
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
                    last_backup_at: None,
                    tags: spec.tags.clone(),
                    user_data: false,
                };
                if let Some(fw) = &spec.firewall_id {
                    s.firewalls.get_mut(fw).unwrap().machines.insert(id.clone());
                }
                if let Some(n) = net {
                    s.networks.get_mut(&n).unwrap().members.insert(id.clone());
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

    /// Interfaces added since its last boot come into use.
    fn boot<'a>(&'a self, id: &'a str) -> Fut<'a, ()> {
        Box::pin(async move {
            self.with("boot", |s| {
                s.machines.get_mut(id).ok_or(ProviderError::NotFound)?.status = "booting".into();
                for n in s.networks.values_mut() {
                    if n.pending.remove(id) {
                        n.members.insert(id.into());
                    }
                }
                Ok(())
            })
        })
    }

    fn enable_backups<'a>(&'a self, id: &'a str) -> Fut<'a, ()> {
        Box::pin(async move { self.update("enable_backups", id, |m| m.backups = true) })
    }

    /// As Linode's: when the last one succeeded is set with `set`.
    fn firewall_egress(&self) -> Option<serde_json::Value> {
        self.state.lock().unwrap().egress.clone()
    }

    fn reports_backups(&self) -> bool {
        true
    }

    fn delete<'a>(&'a self, id: &'a str) -> Fut<'a, ()> {
        Box::pin(async move {
            self.with("delete", |s| {
                s.machines.remove(id);
                for f in s.firewalls.values_mut() {
                    f.machines.remove(id);
                }
                for n in s.networks.values_mut() {
                    n.members.remove(id);
                    n.pending.remove(id);
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
                s.team_nic_rebuild.remove(id);
                Ok(())
            })
        })
    }

    fn team_nic_needs_rebuild<'a>(&'a self, id: &'a str) -> Fut<'a, bool> {
        Box::pin(async move { self.with("team_nic_needs_rebuild", |s| Ok(s.team_nic_rebuild.contains(id))) })
    }

    fn ensure_team_network<'a>(&'a self, label: &'a str, region: &'a str, subnet: &'a str) -> Fut<'a, TeamNetwork> {
        Box::pin(async move {
            self.with("ensure_team_network", |s| {
                let created = !s.networks.values().any(|n| n.label == label);
                if created {
                    s.next += 1;
                    let id = (700 + s.next).to_string();
                    let n = FakeNetwork {
                        id: id.clone(),
                        label: label.into(),
                        region: region.into(),
                        subnet_id: (800 + s.next).to_string(),
                        subnet: subnet.into(),
                        members: BTreeSet::new(),
                        pending: BTreeSet::new(),
                    };
                    s.networks.insert(id, n);
                }
                let n = s.networks.values().find(|n| n.label == label).unwrap();
                if n.region != region || n.subnet != subnet {
                    return Err(ProviderError::Api { status: 409, message: format!("VPC {label} is {} in {}", n.subnet, n.region) });
                }
                Ok(net_view(n, created))
            })
        })
    }

    fn team_networks<'a>(&'a self, prefix: &'a str) -> Fut<'a, Vec<TeamNetwork>> {
        Box::pin(async move {
            self.with("team_networks", |s| Ok(s.networks.values().filter(|n| n.label.starts_with(prefix)).map(|n| net_view(n, false)).collect()))
        })
    }

    fn team_network_members<'a>(&'a self, id: &'a str) -> Fut<'a, Vec<NetworkMember>> {
        Box::pin(async move {
            self.with("team_network_members", |s| {
                let n = s.networks.get(id).ok_or(ProviderError::NotFound)?;
                let member = |m: &String, active: bool| {
                    let needs_power_off = s.linode_interfaces.contains(m);
                    let config = if needs_power_off { String::new() } else { format!("{m}-config") };
                    NetworkMember { machine: m.clone(), config, interface: format!("{m}-vpc"), active, needs_power_off }
                };
                let on = |m: &String| s.machines.get(m).is_none_or(|x| x.status != "offline");
                Ok(n.members.iter().map(|m| member(m, on(m))).chain(n.pending.iter().map(|m| member(m, false))).collect())
            })
        })
    }

    /// As Linode's: never while it is in use, by a machine that booted with it.
    fn leave_team_network<'a>(&'a self, m: &'a NetworkMember) -> Fut<'a, ()> {
        Box::pin(async move {
            self.with("leave_team_network", |s| {
                let on = s.machines.get(&m.machine).is_some_and(|x| x.status != "offline");
                if on && s.linode_interfaces.contains(&m.machine) {
                    return Err(refused("The Linode must be powered off to delete interfaces."));
                }
                if on && s.networks.values().any(|n| n.members.contains(&m.machine)) {
                    return Err(refused("Cannot delete an active interface."));
                }
                for n in s.networks.values_mut() {
                    n.members.remove(&m.machine);
                    n.pending.remove(&m.machine);
                }
                Ok(())
            })
        })
    }

    /// As Linode's: in use from the machine's next boot.
    fn join_team_network<'a>(&'a self, machine: &'a str, network: &'a TeamNetwork) -> Fut<'a, ()> {
        Box::pin(async move {
            self.with("join_team_network", |s| {
                let Some(m) = s.machines.get(machine) else {
                    return Err(ProviderError::NotFound);
                };
                if s.linode_interfaces.contains(machine) && m.status != "offline" {
                    return Err(refused("The Linode must be powered off to add interfaces."));
                }
                if s.networks.values().any(|n| n.id != network.id && (n.members.contains(machine) || n.pending.contains(machine))) {
                    return Err(ProviderError::Api { status: 409, message: "it is on another VPC; it leaves that one first".into() });
                }
                let n = s.networks.values_mut().find(|n| n.subnet_id == network.subnet_id).ok_or_else(|| refused("subnet_id: Not found"))?;
                if !n.members.contains(machine) {
                    n.pending.insert(machine.into());
                }
                Ok(())
            })
        })
    }

    fn team_network_needs_power_off<'a>(&'a self, machine: &'a str) -> Fut<'a, bool> {
        Box::pin(async move { self.with("team_network_needs_power_off", |s| Ok(s.linode_interfaces.contains(machine))) })
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
                    partly: BTreeSet::new(),
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
                    partly: f.partly.iter().cloned().collect(),
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
                // As Linode's: the rest of its interfaces go behind the one it's partly behind.
                if s.firewalls[id].partly.contains(machine) {
                    let f = s.firewalls.get_mut(id).unwrap();
                    f.partly.remove(machine);
                    f.machines.insert(machine.into());
                    return Ok(());
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
                    f.partly.remove(machine);
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
