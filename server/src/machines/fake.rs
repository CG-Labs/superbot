//! An in-memory provider for tests: no network, no money. Labels are unique, as at
//! Linode. A new machine is `provisioning` and a booted one `booting` until the next
//! `get`, which finds them `running`, so reconciliation has something to do.

use super::provider::{CreateSpec, Fut, MachineProvider, ProviderError, ProviderMachine};
use std::collections::{BTreeMap, HashMap};
use std::sync::Mutex;

#[derive(Default)]
pub struct Fake {
    state: Mutex<State>,
}

#[derive(Default)]
struct State {
    next: u64,
    machines: BTreeMap<String, ProviderMachine>,
    /// One-shot failures, by operation name (`create`, `get`, `shutdown`, ...).
    fail: HashMap<&'static str, ProviderError>,
    calls: Vec<String>,
    /// The user data each create was sent, by label: what the machine boots with.
    user_data: HashMap<String, String>,
}

impl Fake {
    fn with<T>(
        &self,
        op: &'static str,
        f: impl FnOnce(&mut State) -> Result<T, ProviderError>,
    ) -> Result<T, ProviderError> {
        let mut s = self.state.lock().unwrap();
        s.calls.push(op.into());
        if let Some(e) = s.fail.remove(op) {
            return Err(e);
        }
        f(&mut s)
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
        self.state.lock().unwrap().machines.remove(id);
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

    /// What the last create for `label` carried as cloud-init user data.
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
                };
                s.machines.insert(id, m.clone());
                Ok(m)
            })
        })
    }

    fn get<'a>(&'a self, id: &'a str) -> Fut<'a, ProviderMachine> {
        Box::pin(async move {
            self.with("get", |s| {
                let m = s.machines.get_mut(id).ok_or(ProviderError::NotFound)?;
                if matches!(m.status.as_str(), "provisioning" | "booting") {
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
                Ok(())
            })
        })
    }
}
