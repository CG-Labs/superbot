//! Several Incus hosts behind one provider (ADR 0076), so a machine can be made again
//! on another host when its own is lost. INCUS_URL is the first host, named by
//! INCUS_HOST_NAME (`main`); INCUS_HOSTS adds more as `name=https://<ip>:8443`, each
//! with its own pinned certificate (INCUS_SERVER_CERT_<NAME>) and, if they differ,
//! INCUS_PROJECT_<NAME>, INCUS_NETWORK_<NAME> and INCUS_STORAGE_POOL_<NAME>. botd's
//! client certificate is the same on every host.
//!
//! A machine's provider id is `<host>/<container>`; the container keeps the machine's
//! label wherever it is. New machines go on the first host that is up. A host the
//! control plane found down gets nothing new and isn't listed; a lost one is never
//! called again: deleting a machine there succeeds without it, and anything else
//! fails as unreachable, never as "not found", so no machine is taken for gone by a
//! host's silence. Every host's address is denied to every container, and the
//! firewall is kept the same on every host that is up.
//!
//! Hosts may be tagged with the data region they are in (INCUS_REGION, or
//! INCUS_REGION_<NAME> for one; ADR 0117): then a machine's region is its host's, and
//! placement keeps each machine on hosts in its region.

use super::{Credentials, DEFAULT_IMAGE, DEFAULT_TIERS, Incus, Settings, Size, host_cidr};
use crate::machines::provider::{
    ByteStream, CreateSpec, FirewallDevices, FirewallRule, Fut, HostInfo, HostStatus, HostUse, Hosts, MachineProvider,
    Policy, ProviderError, ProviderFirewall, ProviderMachine, RebuildSpec, Resources, RestoreSpec,
};
use crate::secrets::SecretStore;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::sync::Mutex;

pub const DEFAULT_HOST: &str = "main";
pub const DEFAULT_DOWN_MINUTES: i64 = 10;

pub struct Member {
    pub name: String,
    pub incus: Incus,
    /// What its machines may be given in all (ADR 0081). None: no limit.
    pub capacity: Option<Resources>,
    pub max_machines: Option<u64>,
    /// The data region it is in (ADR 0117). None: hosts aren't tagged.
    pub region: Option<String>,
}

impl Member {
    pub fn new(name: &str, incus: Incus) -> Member {
        Member { name: name.into(), incus, capacity: None, max_machines: None, region: None }
    }
}

pub struct Fleet {
    members: Vec<Member>,
    status: Mutex<HashMap<String, HostStatus>>,
    down_after_ms: i64,
    policy: Policy,
}

/// INCUS_CAPACITY: `c<cpus>-m<memory GiB>-d<disk GiB>`, as plans are, e.g. `c32-m128-d2000`.
pub fn capacity(raw: &str) -> Result<Resources, String> {
    let bad = || format!("\"{}\" isn't a capacity: c<cpus>-m<memory GiB>-d<disk GiB>, e.g. c32-m128-d2000", crate::audit::clip(raw, 40));
    let num = |s: &str, prefix: char| {
        s.strip_prefix(prefix)
            .filter(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()) && !n.starts_with('0'))
            .and_then(|n| n.parse::<u64>().ok())
            .filter(|n| *n <= 1 << 30)
    };
    let parts: Vec<&str> = raw.trim().split('-').collect();
    let [c, m, d] = parts[..] else { return Err(bad()) };
    Ok(Resources {
        cpus: num(c, 'c').ok_or_else(bad)?,
        memory_gib: num(m, 'm').ok_or_else(bad)?,
        disk_gib: num(d, 'd').ok_or_else(bad)?,
    })
}

/// Host names: as Incus names go, but short, so they read well in ids and settings.
pub fn host_name(s: &str) -> bool {
    crate::machines::slug(s, 32) && s.starts_with(|c: char| c.is_ascii_lowercase())
}

/// `b` and `eu-2` as INCUS_SERVER_CERT_B and INCUS_SERVER_CERT_EU_2 name them.
pub fn suffix(host: &str) -> String {
    host.to_ascii_uppercase().replace('-', "_")
}

/// `host/name`, or a bare name from before there were several hosts.
fn split(id: &str) -> (Option<&str>, &str) {
    match id.split_once('/') {
        Some((h, n)) => (Some(h), n),
        None => (None, id),
    }
}

fn lost(host: &str) -> ProviderError {
    ProviderError::Transport(format!("Incus host {host} was declared lost"))
}

fn no_host() -> ProviderError {
    ProviderError::Transport("no Incus host is up".into())
}

/// With tagged hosts, a machine is in its host's region.
fn prefixed(m: &Member, mut pm: ProviderMachine) -> ProviderMachine {
    pm.id = format!("{}/{}", m.name, pm.id);
    if let Some(r) = &m.region {
        pm.region = r.clone();
    }
    pm
}

/// One firewall from each host's copy: ours only if every copy is.
fn merged(mut found: Vec<ProviderFirewall>) -> ProviderFirewall {
    let mut f = found.remove(0);
    for o in found {
        if o.rules != f.rules {
            f.rules = None;
        }
        f.enabled &= o.enabled;
    }
    f
}

impl Fleet {
    pub fn new(members: Vec<Member>, down_after_ms: i64) -> Fleet {
        let status = members.iter().map(|m| (m.name.clone(), HostStatus::Up)).collect();
        Fleet { members, status: Mutex::new(status), down_after_ms, policy: Policy::default() }
    }

    pub fn with_policy(mut self, policy: Policy) -> Fleet {
        self.policy = policy;
        self
    }

    /// INCUS_URL and the INCUS_* settings for the first host, INCUS_HOSTS for the rest,
    /// INCUS_HOST_DOWN_MINUTES, and placement (ADR 0081): INCUS_PLACEMENT, and each
    /// host's INCUS_CAPACITY and INCUS_MAX_MACHINES (shared, unless `_<NAME>` sets
    /// that host's own, the first host's included). Capacity is set for every host or for none, so the
    /// least loaded host is one measure across them all. INCUS_REGION tags hosts with
    /// their data region (ADR 0117), also every host or none, so no machine lands on a
    /// host whose region nobody stated.
    pub fn from_env(store: &dyn SecretStore, var: &dyn Fn(&str) -> String) -> Result<Fleet, String> {
        let main = Some(var("INCUS_HOST_NAME").trim().to_string()).filter(|v| !v.is_empty()).unwrap_or(DEFAULT_HOST.into());
        if !host_name(&main) {
            return Err(format!("INCUS_HOST_NAME: \"{}\" isn't a host name: lowercase letters, digits and dashes", crate::audit::clip(&main, 40)));
        }
        let mut hosts: Vec<(String, Option<String>)> = vec![(main, None)];
        for entry in var("INCUS_HOSTS").split(',').map(str::trim).filter(|e| !e.is_empty()) {
            let (n, url) = entry
                .split_once('=')
                .map(|(n, u)| (n.trim().to_string(), u.trim().to_string()))
                .ok_or(format!("INCUS_HOSTS: \"{}\" isn't name=https://<incus-host-ip>:8443", crate::audit::clip(entry, 80)))?;
            if !host_name(&n) || hosts.iter().any(|(h, _)| *h == n) {
                return Err(format!("INCUS_HOSTS: \"{}\" isn't a host name, or is named twice (INCUS_HOST_NAME names INCUS_URL's)", crate::audit::clip(&n, 40)));
            }
            hosts.push((n, Some(url)));
        }
        let down = match var("INCUS_HOST_DOWN_MINUTES").trim() {
            "" => DEFAULT_DOWN_MINUTES,
            v => v.parse::<i64>().ok().filter(|m| (1..=1440).contains(m)).ok_or("INCUS_HOST_DOWN_MINUTES must be 1 to 1440")?,
        };
        let mut built: Vec<(String, Settings, Credentials)> = Vec::new();
        for (n, url) in &hosts {
            let sfx = url.as_ref().map(|_| suffix(n));
            let host_var = |k: &str| -> String {
                match (k, url, &sfx) {
                    ("INCUS_URL", Some(u), _) => u.clone(),
                    ("INCUS_PROJECT" | "INCUS_NETWORK" | "INCUS_STORAGE_POOL", Some(_), Some(s)) => {
                        Some(var(&format!("{k}_{s}"))).filter(|v| !v.trim().is_empty()).unwrap_or_else(|| var(k))
                    }
                    _ => var(k),
                }
            };
            let s = Settings::from_env(&host_var).map_err(|e| if url.is_some() { format!("INCUS_HOSTS ({n}): {e}") } else { e })?;
            if built.iter().any(|(_, o, _)| o.url == s.url && o.project == s.project) {
                return Err(format!("INCUS_HOSTS ({n}): another host is {} with project {} already", s.url, s.project));
            }
            built.push((n.clone(), s, Credentials::for_host(store, sfx.as_deref())?));
        }
        let policy = Policy::parse(&var("INCUS_PLACEMENT")).ok_or("INCUS_PLACEMENT must be spread or fill")?;
        let own = |k: &str, n: &str| -> (String, String) {
            let key = format!("{k}_{}", suffix(n));
            let v = var(&key);
            match v.trim() {
                "" => (k.to_string(), var(k)),
                _ => (key, v),
            }
        };
        let every: Vec<String> = built.iter().filter_map(|(_, s, _)| host_cidr(&s.url)).collect();
        let mut members = Vec::new();
        for (name, mut s, c) in built {
            s.deny.extend(every.iter().cloned());
            s.deny.sort();
            s.deny.dedup();
            let (key, raw) = own("INCUS_CAPACITY", &name);
            let cap = Some(raw.trim()).filter(|r| !r.is_empty()).map(capacity).transpose().map_err(|e| format!("{key}: {e}"))?;
            let (key, raw) = own("INCUS_MAX_MACHINES", &name);
            let max = match raw.trim() {
                "" => None,
                v => Some(v.parse::<u64>().ok().filter(|n| (1..=100_000).contains(n)).ok_or(format!("{key} must be 1 to 100000"))?),
            };
            let (key, raw) = own("INCUS_REGION", &name);
            let region = match raw.trim() {
                "" => None,
                r if crate::machines::slug(r, 32) => Some(r.to_string()),
                r => return Err(format!("{key}: \"{}\" isn't a region id: lowercase letters, digits and dashes, e.g. gb-lon", crate::audit::clip(r, 40))),
            };
            members.push(Member { capacity: cap, max_machines: max, region, ..Member::new(&name, Incus::new(s, c)?) });
        }
        if let Some(m) = members.iter().find(|m| m.region.is_none())
            && members.iter().any(|m| m.region.is_some())
        {
            return Err(format!(
                "INCUS_REGION: set for every Incus host or none; host {} has none (INCUS_REGION for all, INCUS_REGION_<NAME> for one)",
                m.name
            ));
        }
        if let Some(m) = members.iter().find(|m| m.capacity.is_none())
            && members.iter().any(|m| m.capacity.is_some())
        {
            return Err(format!(
                "INCUS_CAPACITY: set for every Incus host or none; host {} has none (INCUS_CAPACITY for all, INCUS_CAPACITY_<NAME> for one)",
                m.name
            ));
        }
        Ok(Fleet::new(members, down * 60_000).with_policy(policy))
    }

    fn member(&self, host: &str) -> Option<&Member> {
        self.members.iter().find(|m| m.name == host)
    }

    fn is(&self, host: &str, s: HostStatus) -> bool {
        self.status.lock().unwrap().get(host) == Some(&s)
    }

    /// The host and name in `id`, the first host for a bare one.
    fn parts<'a>(&'a self, id: &'a str) -> (&'a str, &'a str) {
        let (h, n) = split(id);
        (h.unwrap_or(&self.members[0].name), n)
    }

    /// The configured host `id` is on, unless it was declared lost.
    fn route<'a>(&'a self, id: &'a str) -> Result<(&'a Member, &'a str), ProviderError> {
        let (h, n) = self.parts(id);
        if self.is(h, HostStatus::Lost) {
            return Err(lost(h));
        }
        self.member(h)
            .map(|m| (m, n))
            .ok_or_else(|| ProviderError::Transport(format!("Incus host {h} isn't configured (INCUS_HOSTS)")))
    }

    /// Hosts that get new machines and the firewall: up, as far as botd knows.
    fn up(&self) -> Vec<&Member> {
        let s = self.status.lock().unwrap();
        self.members.iter().filter(|m| s.get(&m.name).is_none_or(|s| *s == HostStatus::Up)).collect()
    }

    fn need_up(&self) -> Result<Vec<&Member>, ProviderError> {
        Some(self.up()).filter(|u| !u.is_empty()).ok_or_else(no_host)
    }
}

impl MachineProvider for Fleet {
    fn name(&self) -> &'static str {
        "incus"
    }

    fn substrate(&self) -> &'static str {
        "container"
    }

    fn default_tiers(&self) -> &'static str {
        DEFAULT_TIERS
    }

    fn default_image(&self) -> &'static str {
        DEFAULT_IMAGE
    }

    fn check_plan(&self, plan: &str) -> Result<(), String> {
        Size::parse(plan).map(drop)
    }

    fn plan_view(&self, plan: &str) -> Option<Value> {
        Size::parse(plan).ok().map(|s| s.view())
    }

    fn plan_resources(&self, plan: &str) -> Option<Resources> {
        Size::parse(plan).ok().map(|s| Resources { cpus: s.cpus.into(), memory_gib: s.memory_gib.into(), disk_gib: s.disk_gib.into() })
    }

    /// The first host's settings, as with one host, and every host.
    fn settings(&self) -> Value {
        let mut v = self.members[0].incus.settings();
        v["hosts"] = json!(self
            .configured()
            .iter()
            .zip(&self.members)
            .map(|(h, m)| {
                let s = m.incus.base();
                json!({
                    "name": h.name, "url": h.url, "serverCertificate": h.fingerprint, "project": s.project, "network": s.network,
                    "storagePool": s.pool, "status": h.status, "capacity": h.capacity, "maxMachines": h.max_machines,
                    "region": h.region,
                })
            })
            .collect::<Vec<_>>());
        v["hostDownMinutes"] = json!(self.down_after_ms / 60_000);
        v["placement"] = json!(self.policy);
        v
    }

    /// Each host's checks, saying which host; none for a lost one.
    fn preflight<'a>(&'a self) -> Fut<'a, Vec<Value>> {
        Box::pin(async move {
            let mut out = Vec::new();
            for m in self.members.iter().filter(|m| !self.is(&m.name, HostStatus::Lost)) {
                for mut c in m.incus.preflight().await? {
                    c["host"] = json!(m.name);
                    out.push(c);
                }
            }
            Ok(out)
        })
    }

    /// On the first host that is up. The control plane places machines by load with
    /// `create_on`.
    fn create<'a>(&'a self, spec: &'a CreateSpec) -> Fut<'a, ProviderMachine> {
        Box::pin(async move {
            let host = self.placement().ok_or_else(no_host)?;
            self.create_on(&host, spec).await
        })
    }

    fn get<'a>(&'a self, id: &'a str) -> Fut<'a, ProviderMachine> {
        Box::pin(async move {
            let (m, n) = self.route(id)?;
            m.incus.get(n).await.map(|pm| prefixed(m, pm))
        })
    }

    /// From the hosts that are up: a down one's machines aren't there to adopt.
    fn list<'a>(&'a self, tag: &'a str) -> Fut<'a, Vec<ProviderMachine>> {
        Box::pin(async move {
            let mut out = Vec::new();
            for m in self.up() {
                out.extend(m.incus.list(tag).await?.into_iter().map(|pm| prefixed(m, pm)));
            }
            Ok(out)
        })
    }

    fn resize<'a>(&'a self, id: &'a str, plan: &'a str) -> Fut<'a, ()> {
        Box::pin(async move {
            let (m, n) = self.route(id)?;
            m.incus.resize(n, plan).await
        })
    }

    fn shutdown<'a>(&'a self, id: &'a str) -> Fut<'a, ()> {
        Box::pin(async move {
            let (m, n) = self.route(id)?;
            m.incus.shutdown(n).await
        })
    }

    fn boot<'a>(&'a self, id: &'a str) -> Fut<'a, ()> {
        Box::pin(async move {
            let (m, n) = self.route(id)?;
            m.incus.boot(n).await
        })
    }

    fn enable_backups<'a>(&'a self, id: &'a str) -> Fut<'a, ()> {
        Box::pin(async move {
            let (m, n) = self.route(id)?;
            m.incus.enable_backups(n).await
        })
    }

    /// On a lost host the machine went with it.
    fn delete<'a>(&'a self, id: &'a str) -> Fut<'a, ()> {
        Box::pin(async move {
            if self.is(self.parts(id).0, HostStatus::Lost) {
                return Ok(());
            }
            let (m, n) = self.route(id)?;
            m.incus.delete(n).await
        })
    }

    fn rebuild<'a>(&'a self, id: &'a str, spec: &'a RebuildSpec) -> Fut<'a, ()> {
        Box::pin(async move {
            let (m, n) = self.route(id)?;
            m.incus.rebuild(n, spec).await
        })
    }

    fn clear_user_data<'a>(&'a self, id: &'a str) -> Fut<'a, ()> {
        Box::pin(async move {
            let (m, n) = self.route(id)?;
            m.incus.clear_user_data(n).await
        })
    }

    fn exports(&self) -> bool {
        true
    }

    fn create_backup<'a>(&'a self, id: &'a str, backup: &'a str) -> Fut<'a, ()> {
        Box::pin(async move {
            let (m, n) = self.route(id)?;
            m.incus.create_backup(n, backup).await
        })
    }

    fn export_backup<'a>(&'a self, id: &'a str, backup: &'a str) -> Fut<'a, ByteStream> {
        Box::pin(async move {
            let (m, n) = self.route(id)?;
            m.incus.export_backup(n, backup).await
        })
    }

    fn delete_backup<'a>(&'a self, id: &'a str, backup: &'a str) -> Fut<'a, ()> {
        Box::pin(async move {
            let (m, n) = self.route(id)?;
            m.incus.delete_backup(n, backup).await
        })
    }

    /// On the host `name` says.
    fn import_backup<'a>(&'a self, name: &'a str, data: ByteStream) -> Fut<'a, ()> {
        Box::pin(async move {
            let (m, n) = self.route(name)?;
            m.incus.import_backup(n, data).await
        })
    }

    /// `staging` may be on another host than `id`: it is set up there, the old
    /// container deleted where it is (nothing to do on a lost host; an unreachable one
    /// fails the swap, leaving the machine as it was), and the copy given its name.
    fn replace_with<'a>(&'a self, id: &'a str, staging: &'a str, spec: &'a RestoreSpec) -> Fut<'a, ProviderMachine> {
        Box::pin(async move {
            let (from, n) = self.parts(id);
            let (to, staged) = self.route(staging)?;
            if from == to.name {
                return to.incus.replace_with(n, staged, spec).await.map(|pm| prefixed(to, pm));
            }
            to.incus.prepare(staged, spec).await?;
            if !self.is(from, HostStatus::Lost) {
                let (old, _) = self.route(id)?;
                old.incus.delete(n).await?;
            }
            to.incus.delete(n).await?;
            to.incus.rename(staged, n).await?;
            to.incus.get(n).await.map(|pm| prefixed(to, pm))
        })
    }

    /// Found only once every host that is up has it, so `create_firewall` fills in the rest.
    fn find_firewall<'a>(&'a self, label: &'a str) -> Fut<'a, Option<ProviderFirewall>> {
        Box::pin(async move {
            let mut found = Vec::new();
            for m in self.need_up()? {
                match m.incus.find_firewall(label).await? {
                    Some(f) => found.push(f),
                    None => return Ok(None),
                }
            }
            Ok(Some(merged(found)))
        })
    }

    fn get_firewall<'a>(&'a self, id: &'a str) -> Fut<'a, ProviderFirewall> {
        Box::pin(async move {
            let (mut found, mut missing) = (Vec::new(), false);
            for m in self.need_up()? {
                match m.incus.get_firewall(id).await {
                    Ok(f) => found.push(f),
                    Err(ProviderError::NotFound) => missing = true,
                    Err(e) => return Err(e),
                }
            }
            if found.is_empty() {
                return Err(ProviderError::NotFound);
            }
            let mut f = merged(found);
            if missing {
                f.rules = None;
            }
            Ok(f)
        })
    }

    /// On each host that is up and lacks it. `LabelTaken` if none did.
    fn create_firewall<'a>(&'a self, label: &'a str, tags: &'a [String], rules: &'a [FirewallRule]) -> Fut<'a, ProviderFirewall> {
        Box::pin(async move {
            let mut made = false;
            for m in self.need_up()? {
                if m.incus.find_firewall(label).await?.is_some() {
                    continue;
                }
                match m.incus.create_firewall(label, tags, rules).await {
                    Ok(_) => made = true,
                    Err(ProviderError::LabelTaken) => {}
                    Err(e) => return Err(e),
                }
            }
            if !made {
                return Err(ProviderError::LabelTaken);
            }
            self.get_firewall(label).await
        })
    }

    fn set_firewall_rules<'a>(&'a self, id: &'a str, rules: &'a [FirewallRule]) -> Fut<'a, ()> {
        Box::pin(async move {
            for m in self.need_up()? {
                m.incus.set_firewall_rules(id, rules).await?;
            }
            Ok(())
        })
    }

    fn enable_firewall<'a>(&'a self, id: &'a str) -> Fut<'a, ()> {
        Box::pin(async move {
            for m in self.need_up()? {
                m.incus.enable_firewall(id).await?;
            }
            Ok(())
        })
    }

    fn firewall_devices<'a>(&'a self, id: &'a str) -> Fut<'a, FirewallDevices> {
        Box::pin(async move {
            let up = self.need_up()?;
            let (mut out, mut missing) = (FirewallDevices::default(), 0);
            for m in &up {
                match m.incus.firewall_devices(id).await {
                    Ok(d) => {
                        out.machines.extend(d.machines.into_iter().map(|n| format!("{}/{n}", m.name)));
                        out.others += d.others;
                    }
                    Err(ProviderError::NotFound) => missing += 1,
                    Err(e) => return Err(e),
                }
            }
            if missing == up.len() {
                return Err(ProviderError::NotFound);
            }
            Ok(out)
        })
    }

    fn attach_firewall<'a>(&'a self, id: &'a str, machine: &'a str) -> Fut<'a, ()> {
        Box::pin(async move {
            let (m, n) = self.route(machine)?;
            m.incus.attach_firewall(id, n).await
        })
    }

    fn detach_firewall<'a>(&'a self, id: &'a str, machine: &'a str) -> Fut<'a, ()> {
        Box::pin(async move {
            if self.is(self.parts(machine).0, HostStatus::Lost) {
                return Ok(());
            }
            let (m, n) = self.route(machine)?;
            m.incus.detach_firewall(id, n).await
        })
    }

    fn delete_firewall<'a>(&'a self, id: &'a str) -> Fut<'a, ()> {
        Box::pin(async move {
            for m in self.need_up()? {
                m.incus.delete_firewall(id).await?;
            }
            Ok(())
        })
    }

    fn hosts(&self) -> Option<&dyn Hosts> {
        Some(self)
    }
}

impl Hosts for Fleet {
    fn configured(&self) -> Vec<HostInfo> {
        let s = self.status.lock().unwrap();
        self.members
            .iter()
            .map(|m| HostInfo {
                name: m.name.clone(),
                url: m.incus.base().url.clone(),
                fingerprint: m.incus.fingerprint().to_string(),
                status: s.get(&m.name).copied().unwrap_or(HostStatus::Up),
                capacity: m.capacity,
                max_machines: m.max_machines,
                region: m.region.clone(),
            })
            .collect()
    }

    fn policy(&self) -> Policy {
        self.policy
    }

    fn create_on<'a>(&'a self, host: &'a str, spec: &'a CreateSpec) -> Fut<'a, ProviderMachine> {
        Box::pin(async move {
            if !self.is(host, HostStatus::Up) {
                return Err(ProviderError::Transport(format!("Incus host {host} isn't up")));
            }
            let m = self.member(host).ok_or_else(|| ProviderError::Transport(format!("Incus host {host} isn't configured (INCUS_HOSTS)")))?;
            // A tagged host's region is botd's word for where it is, not a cluster member.
            if m.region.is_some() {
                let local = CreateSpec { region: super::LOCAL.into(), ..spec.clone() };
                return m.incus.create(&local).await.map(|pm| prefixed(m, pm));
            }
            m.incus.create(spec).await.map(|pm| prefixed(m, pm))
        })
    }

    fn on(&self, host: &str) -> Option<&dyn MachineProvider> {
        self.member(host).map(|m| &m.incus as &dyn MachineProvider)
    }

    fn host_of(&self, id: &str) -> String {
        self.parts(id).0.to_string()
    }

    fn id_on(&self, host: &str, name: &str) -> String {
        format!("{host}/{name}")
    }

    fn set_status(&self, host: &str, status: HostStatus) {
        self.status.lock().unwrap().insert(host.into(), status);
    }

    fn status(&self, host: &str) -> Option<HostStatus> {
        self.status.lock().unwrap().get(host).copied()
    }

    fn placement(&self) -> Option<String> {
        self.up().first().map(|m| m.name.clone())
    }

    fn down_after_ms(&self) -> i64 {
        self.down_after_ms
    }

    fn probe<'a>(&'a self, host: &'a str) -> Fut<'a, String> {
        Box::pin(async move {
            let m = self.member(host).ok_or_else(|| ProviderError::Transport(format!("Incus host {host} isn't configured (INCUS_HOSTS)")))?;
            m.incus.check_server().await
        })
    }

    fn host_use<'a>(&'a self, host: &'a str) -> Fut<'a, HostUse> {
        Box::pin(async move {
            if self.is(host, HostStatus::Lost) {
                return Err(lost(host));
            }
            let m = self.member(host).ok_or_else(|| ProviderError::Transport(format!("Incus host {host} isn't configured (INCUS_HOSTS)")))?;
            m.incus.host_use().await
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::machines::incus_standin::self_signed;
    use crate::secrets::env::EnvStore;

    fn store(extra: &[(&str, &str)]) -> (EnvStore, String) {
        let (cert, key) = self_signed("botd.test");
        let (server, _) = self_signed("incus.test");
        let mut pairs: Vec<(String, String)> =
            vec![("INCUS_CLIENT_CERT".into(), cert), ("INCUS_CLIENT_KEY".into(), key), ("INCUS_SERVER_CERT".into(), server.clone())];
        pairs.extend(extra.iter().map(|(k, v)| (k.to_string(), v.to_string())));
        let refs: Vec<(&str, &str)> = pairs.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
        (EnvStore::fixed(&refs), server)
    }

    fn vars(pairs: Vec<(&'static str, String)>) -> impl Fn(&str) -> String {
        move |k| pairs.iter().find(|(n, _)| *n == k).map(|(_, v)| v.clone()).unwrap_or_default()
    }

    #[test]
    fn hosts_come_from_the_environment() {
        // One host, as before: named main, and its id prefix is all that changes.
        let (s, _) = store(&[]);
        let one = Fleet::from_env(&s, &vars(vec![("INCUS_URL", "https://192.0.2.50".into())])).unwrap();
        assert_eq!(one.configured().iter().map(|h| h.name.as_str()).collect::<Vec<_>>(), ["main"]);
        assert_eq!((one.down_after_ms(), one.placement().as_deref()), (DEFAULT_DOWN_MINUTES * 60_000, Some("main")));
        assert_eq!(one.settings()["url"], "https://192.0.2.50:8443");

        // A second host with its own certificate and project; every host's address is
        // kept from every container.
        let (other, _) = self_signed("incus-b.test");
        let (s, _) = store(&[("INCUS_SERVER_CERT_EU_2", &other)]);
        let f = Fleet::from_env(
            &s,
            &vars(vec![
                ("INCUS_URL", "https://192.0.2.50".into()),
                ("INCUS_HOST_NAME", "eu-1".into()),
                ("INCUS_HOSTS", " eu-2 = https://198.51.100.7:9443 ".into()),
                ("INCUS_PROJECT_EU_2", "superbot-b".into()),
                ("INCUS_HOST_DOWN_MINUTES", "3".into()),
            ]),
        )
        .unwrap();
        let hosts = f.configured();
        assert_eq!(hosts.iter().map(|h| (h.name.as_str(), h.url.as_str())).collect::<Vec<_>>(), [("eu-1", "https://192.0.2.50:8443"), ("eu-2", "https://198.51.100.7:9443")]);
        assert_ne!(hosts[0].fingerprint, hosts[1].fingerprint, "each host's own certificate is pinned");
        assert_eq!((f.members[0].incus.base().project.as_str(), f.members[1].incus.base().project.as_str()), ("superbot", "superbot-b"));
        for m in &f.members {
            for c in ["192.0.2.50/32", "198.51.100.7/32"] {
                assert!(m.incus.base().deny.contains(&c.to_string()), "{}: {c}", m.name);
            }
        }
        assert_eq!(f.down_after_ms(), 3 * 60_000);
        assert_eq!(f.settings()["hosts"][1]["project"], "superbot-b");

        let base = |extra: Vec<(&'static str, String)>| {
            let mut v = vec![("INCUS_URL", "https://192.0.2.50".to_string())];
            v.extend(extra);
            vars(v)
        };
        for (extra, want) in [
            (vec![("INCUS_HOST_NAME", "Main".to_string())], "INCUS_HOST_NAME"),
            (vec![("INCUS_HOSTS", "https://198.51.100.7".to_string())], "isn't name="),
            (vec![("INCUS_HOSTS", "main=https://198.51.100.7".to_string())], "named twice"),
            (vec![("INCUS_HOSTS", "b=https://incus-b.internal".to_string())], "INCUS_HOSTS (b): INCUS_URL must name the Incus host by IP"),
            (vec![("INCUS_HOSTS", "b=https://192.0.2.50".to_string())], "another host is"),
            (vec![("INCUS_HOSTS", "b=https://198.51.100.7".to_string())], "INCUS_SERVER_CERT_B"),
            (vec![("INCUS_HOST_DOWN_MINUTES", "0".to_string())], "INCUS_HOST_DOWN_MINUTES"),
        ] {
            let e = Fleet::from_env(&s, &base(extra.clone())).err().unwrap();
            assert!(e.contains(want), "{extra:?}: {e}");
        }
        // The same daemon in another project is another host (as the real-host test uses).
        let (s, _) = store(&[("INCUS_SERVER_CERT_B", &other)]);
        assert!(Fleet::from_env(&s, &base(vec![("INCUS_HOSTS", "b=https://192.0.2.50".into()), ("INCUS_PROJECT_B", "superbot-b".into())])).is_ok());
    }

    #[test]
    fn capacity_and_placement_come_from_the_environment() {
        let (other, _) = self_signed("incus-b.test");
        let (s, _) = store(&[("INCUS_SERVER_CERT_B", &other)]);
        let two = |extra: Vec<(&'static str, String)>| {
            let mut v = vec![("INCUS_URL", "https://192.0.2.50".to_string()), ("INCUS_HOSTS", "b=https://198.51.100.7".to_string())];
            v.extend(extra);
            Fleet::from_env(&s, &vars(v))
        };
        let f = two(vec![]).unwrap();
        assert_eq!((f.policy(), f.configured()[1].capacity, f.configured()[1].max_machines), (Policy::Spread, None, None), "no limits unless set");

        // The first host's are every host's, unless a host sets its own.
        let f = two(vec![
            ("INCUS_CAPACITY", "c32-m128-d2000".into()),
            ("INCUS_CAPACITY_B", "c8-m32-d500".into()),
            ("INCUS_MAX_MACHINES", "40".into()),
            ("INCUS_PLACEMENT", "Fill".into()),
        ])
        .unwrap();
        let hosts = f.configured();
        assert_eq!(hosts[0].capacity, Some(Resources { cpus: 32, memory_gib: 128, disk_gib: 2000 }));
        assert_eq!(hosts[1].capacity, Some(Resources { cpus: 8, memory_gib: 32, disk_gib: 500 }));
        assert_eq!((hosts[0].max_machines, hosts[1].max_machines, f.policy()), (Some(40), Some(40), Policy::Fill));
        assert_eq!(f.settings()["hosts"][1]["capacity"]["memoryGiB"], 32);
        assert_eq!(f.plan_resources("c2-m4-d40"), Some(Resources { cpus: 2, memory_gib: 4, disk_gib: 40 }));
        let f = two(vec![("INCUS_CAPACITY", "c32-m128-d2000".into()), ("INCUS_CAPACITY_MAIN", "c8-m32-d500".into()), ("INCUS_MAX_MACHINES_MAIN", "5".into())]).unwrap();
        let hosts = f.configured();
        assert_eq!((hosts[0].capacity.map(|c| c.cpus), hosts[1].capacity.map(|c| c.cpus)), (Some(8), Some(32)), "the first host's own, too");
        assert_eq!((hosts[0].max_machines, hosts[1].max_machines), (Some(5), None));

        // Data regions (ADR 0117): every host tagged, or none.
        let f = two(vec![("INCUS_REGION", "gb-lon".into()), ("INCUS_REGION_B", "de-fra-2".into())]).unwrap();
        assert_eq!(f.configured().iter().map(|h| h.region.as_deref()).collect::<Vec<_>>(), [Some("gb-lon"), Some("de-fra-2")]);
        assert!(f.tagged() && !two(vec![]).unwrap().tagged());
        assert_eq!(f.settings()["hosts"][1]["region"], "de-fra-2");
        let pm = ProviderMachine {
            id: "superbot-m1".into(),
            label: "superbot-m1".into(),
            status: "running".into(),
            plan: "c1-m2-d20".into(),
            region: "local".into(),
            ipv4: None,
            backups: false,
            last_backup_at: None,
            tags: vec![],
            user_data: false,
        };
        assert_eq!((prefixed(&f.members[1], pm.clone()).region.as_str(), prefixed(&two(vec![]).unwrap().members[1], pm).region.as_str()), ("de-fra-2", "local"));

        for (extra, want) in [
            (vec![("INCUS_REGION_B", "de-fra-2".to_string())], "INCUS_REGION: set for every Incus host or none; host main"),
            (vec![("INCUS_REGION", "London".to_string())], "INCUS_REGION: \"London\" isn't a region id"),
            (vec![("INCUS_CAPACITY_B", "c8-m32-d500".to_string())], "set for every Incus host or none; host main"),
            (vec![("INCUS_CAPACITY", "32 cpus".to_string())], "INCUS_CAPACITY: \"32 cpus\" isn't a capacity"),
            (vec![("INCUS_CAPACITY", "c32-m128-d2000".to_string()), ("INCUS_CAPACITY_B", "c0-m1-d1".to_string())], "INCUS_CAPACITY_B:"),
            (vec![("INCUS_MAX_MACHINES_B", "0".to_string())], "INCUS_MAX_MACHINES_B must be 1 to 100000"),
            (vec![("INCUS_PLACEMENT", "random".to_string())], "INCUS_PLACEMENT must be spread or fill"),
        ] {
            let e = two(extra.clone()).err().unwrap();
            assert!(e.contains(want), "{extra:?}: {e}");
        }
    }

    #[tokio::test]
    async fn ids_name_their_host_and_a_lost_one_is_never_called() {
        let (other, _) = self_signed("incus-b.test");
        let (s, _) = store(&[("INCUS_SERVER_CERT_B", &other)]);
        let f = Fleet::from_env(
            &s,
            &vars(vec![("INCUS_URL", "https://192.0.2.50".into()), ("INCUS_HOSTS", "b=https://198.51.100.7".into())]),
        )
        .unwrap();
        assert_eq!((f.host_of("b/superbot-m1"), f.host_of("superbot-m1"), f.id_on("b", "x")), ("b".into(), "main".into(), "b/x".into()));
        assert!(matches!(f.route("nowhere/x"), Err(ProviderError::Transport(m)) if m.contains("isn't configured")));

        f.set_status("main", HostStatus::Down);
        assert_eq!(f.placement().as_deref(), Some("b"), "nothing new goes to a down host");
        let spec = CreateSpec {
            label: "superbot-m1".into(),
            plan: "c1-m2-d20".into(),
            region: "local".into(),
            image: DEFAULT_IMAGE.into(),
            tags: vec![],
            authorized_keys: vec![],
            user_data: None,
            firewall_id: None,
        };
        assert!(matches!(f.create_on("main", &spec).await, Err(ProviderError::Transport(m)) if m.contains("isn't up")));
        assert!(matches!(f.create_on("nowhere", &spec).await, Err(ProviderError::Transport(_))));
        f.set_status("b", HostStatus::Down);
        assert_eq!(f.placement(), None);
        assert!(matches!(f.find_firewall("superbot-fw").await, Err(ProviderError::Transport(m)) if m.contains("no Incus host is up")));

        // Lost: deletes succeed without calling it (192.0.2.50 would time out), the rest
        // say it's unreachable rather than that the machine is gone.
        f.set_status("main", HostStatus::Lost);
        f.set_status("gone", HostStatus::Lost);
        assert_eq!(f.delete("main/superbot-m1").await, Ok(()));
        assert_eq!(f.delete("gone/superbot-m2").await, Ok(()), "a lost host taken out of the settings");
        assert_eq!(f.detach_firewall("superbot-fw", "main/superbot-m1").await, Ok(()));
        for e in [f.get("main/superbot-m1").await.err(), f.boot("gone/superbot-m2").await.err()] {
            assert!(matches!(&e, Some(ProviderError::Transport(m)) if m.contains("declared lost")), "{e:?}");
        }
        f.set_status("b", HostStatus::Lost);
        assert!(f.preflight().await.unwrap().is_empty(), "a lost host isn't checked");
    }

    #[test]
    fn a_firewall_is_ours_only_if_every_copy_is() {
        let rule = FirewallRule { label: "a".into(), ports: "1".into(), sources: vec![] };
        let f = |rules: Option<Vec<FirewallRule>>, enabled| ProviderFirewall { id: "fw".into(), label: "fw".into(), rules, enabled };
        assert_eq!(merged(vec![f(Some(vec![rule.clone()]), true), f(Some(vec![rule.clone()]), true)]), f(Some(vec![rule.clone()]), true));
        assert_eq!(merged(vec![f(Some(vec![rule.clone()]), true), f(Some(vec![]), true)]).rules, None);
        assert!(!merged(vec![f(None, true), f(None, false)]).enabled);
    }
}
