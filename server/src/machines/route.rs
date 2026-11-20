//! Where a Bot's work runs (ADR 0029, ADR 0036). Each user has one computer, and all of
//! their Bots share it. `MACHINE_ROUTING` picks:
//! - `off` (the default, and self-hosting): every Bot runs on this server, in its
//!   owner's folders.
//! - `assigned`: a user an admin assigned to their machine has their Bots run there;
//!   everyone else's run here, as before.
//! - `on`: every Bot runs on its owner's assigned machine, and is refused without one.
//!
//! A user who is assigned always runs there or not at all: a machine that is down,
//! unreachable, or unfit refuses the run, never sends it here instead. Only the owner's
//! own machine is ever picked, looked up by the Bot's owner.
//! `MachineLink` carries the work: mutual TLS to the machine's pinned certificate
//! (`enroll::Mtls`, ADR 0031), or nothing while enrollment is off.

use super::wire::{self, Heartbeat, JobEvent, JobRequest};
use super::{ControlPlane, State};
use crate::adapters::AbortReason;
use crate::db::Db;
use crate::runner::App;
use std::future::Future;
use std::pin::Pin;
use tokio::sync::{mpsc, watch};

/// MACHINE_ROUTING.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Routing {
    #[default]
    Off,
    Assigned,
    On,
}

impl Routing {
    pub fn parse(raw: &str) -> Result<Routing, String> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "" | "0" | "off" | "false" | "no" => Ok(Routing::Off),
            "assigned" => Ok(Routing::Assigned),
            "1" | "on" | "true" | "yes" => Ok(Routing::On),
            v => Err(format!("MACHINE_ROUTING must be off, assigned, or on, not \"{v}\"")),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Routing::Off => "off",
            Routing::Assigned => "assigned",
            Routing::On => "on",
        }
    }
}

/// A user's machine, as far as routing needs it.
#[derive(Clone, Debug, PartialEq)]
pub struct Assigned {
    pub machine_id: String,
    pub user_id: String,
    /// Where the machine answers. None until the provider gives it an address.
    pub address: Option<String>,
    /// Fingerprints of its usable certificates (ADR 0031): the only ones accepted from
    /// it. Empty until it enrolls.
    pub pins: Vec<String>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum Target {
    /// This server, in the owner's folders.
    Local,
    /// The owner's own machine.
    Machine(Assigned),
}

/// Why a Bot can't run now. The Bot says so; nothing runs elsewhere instead.
#[derive(Clone, Debug, PartialEq)]
pub enum Refusal {
    /// Routing is on and the owner has no machine.
    NoMachine,
    /// Routing is on and the owner's machine isn't assigned to them yet.
    NotAssigned,
    /// The owner's machine exists but isn't running (still being built, suspended, ...).
    NotReady(State),
    /// It is running, but its agent hasn't enrolled (or its certificates were revoked).
    NotEnrolled,
    /// Its agent didn't answer the check before the run.
    Offline(String),
    /// Its agent is too old to run Bots (its version).
    Outdated(String),
    /// The Bot's harness isn't installed on it.
    HarnessMissing(String),
    /// `botctl` isn't installed on it, so approvals can't be asked for there.
    NoBotctl,
}

impl Refusal {
    pub fn reason(&self) -> &'static str {
        match self {
            Refusal::NoMachine => "no_machine",
            Refusal::NotAssigned => "not_assigned",
            Refusal::NotReady(_) => "machine_not_ready",
            Refusal::NotEnrolled => "machine_not_enrolled",
            Refusal::Offline(_) => "machine_offline",
            Refusal::Outdated(_) => "agent_outdated",
            Refusal::HarnessMissing(_) => "harness_missing",
            Refusal::NoBotctl => "agent_incomplete",
        }
    }

    /// What the Bot tells the user.
    pub fn message(&self) -> String {
        match self {
            Refusal::NoMachine => "I can't run yet: you don't have a computer. Ask an admin to set one up for you.".into(),
            Refusal::NotAssigned => "I can't run yet: your computer isn't assigned to you. Ask an admin to assign it.".into(),
            Refusal::NotReady(s) => format!("I can't run yet: your computer is {}. Try again when it's running.", s.as_str()),
            Refusal::NotEnrolled => "I can't run yet: your computer hasn't connected to this server. Ask an admin to check on it.".into(),
            Refusal::Offline(e) => format!("I didn't run: your computer is offline ({e}). Try again soon; if it stays offline, ask an admin to check on it."),
            Refusal::Outdated(v) => format!("I didn't run: your computer's agent ({v}) is too old to run Bots. Ask an admin to update it."),
            Refusal::HarnessMissing(h) => format!("I didn't run: {h} isn't installed on your computer. Ask an admin to install it, or switch me to another harness."),
            Refusal::NoBotctl => "I didn't run: botctl isn't installed on your computer, so I couldn't ask you before risky steps. Ask an admin to install it.".into(),
        }
    }
}

/// The routing target for `user_id`'s Bots: this server or their own machine only.
/// Looked up by the owner, never by the Bot or the caller, so a Bot shared with others
/// still runs on its owner's machine.
pub fn target(db: &Db, cp: &ControlPlane, user_id: &str) -> Result<Target, Refusal> {
    if cp.routing == Routing::Off {
        return Ok(Target::Local);
    }
    let m = match db.user_machine(user_id).filter(|m| m.user_id == user_id) {
        Some(m) if m.assigned_at.is_some() => m,
        other => {
            return match (cp.routing, other) {
                (Routing::Assigned, _) => Ok(Target::Local),
                (_, None) => Err(Refusal::NoMachine),
                (_, Some(_)) => Err(Refusal::NotAssigned),
            };
        }
    };
    if m.state != State::Running {
        return Err(Refusal::NotReady(m.state));
    }
    let to = Assigned { machine_id: m.id.clone(), user_id: m.user_id.clone(), address: m.ipv4.clone(), pins: db.machine_pins(&m.id) };
    if to.pins.is_empty() {
        return Err(Refusal::NotEnrolled);
    }
    Ok(Target::Machine(to))
}

/// Whether the machine can run a job for `bin`, from its answer to the check.
pub fn fit(hb: &Heartbeat, bin: &str) -> Result<wire::Layout, Refusal> {
    let layout = hb.layout.clone().filter(|_| hb.protocol >= wire::PROTOCOL).ok_or_else(|| Refusal::Outdated(hb.version.clone()))?;
    if hb.missing.iter().any(|m| m == bin) {
        return Err(Refusal::HarnessMissing(bin.into()));
    }
    if layout.botctl.is_none() {
        return Err(Refusal::NoBotctl);
    }
    Ok(layout)
}

pub type Checked<'a> = Pin<Box<dyn Future<Output = Result<Heartbeat, String>> + Send + 'a>>;
pub type Ran<'a> = Pin<Box<dyn Future<Output = ()> + Send + 'a>>;

/// Hands work to a user's machine. botd never sends a job to any machine but the one
/// `target` picked for the Bot's owner, and over mutual TLS only to that machine's
/// own certificates (`enroll::Mtls`).
pub trait MachineLink: Send + Sync {
    fn name(&self) -> &'static str;
    /// Asks the machine how it is and whether `bins` are installed, and records it.
    fn check<'a>(&'a self, app: &'a App, to: &'a Assigned, bins: &'a [&'a str]) -> Checked<'a>;
    /// Runs `job` there, sending its events to `tx` until it ends. A job that can't
    /// start, or a machine lost on the way, ends with an `Error`.
    fn run<'a>(&'a self, to: &'a Assigned, job: JobRequest, abort: watch::Receiver<AbortReason>, tx: mpsc::Sender<JobEvent>) -> Ran<'a>;
}

/// While enrollment is off: nothing can be sent, so routed runs are refused.
pub struct Unenrolled;

const UNENROLLED: &str = "this server can't reach machines while machine enrollment is off";

impl MachineLink for Unenrolled {
    fn name(&self) -> &'static str {
        "unenrolled"
    }

    fn check<'a>(&'a self, _app: &'a App, _to: &'a Assigned, _bins: &'a [&'a str]) -> Checked<'a> {
        Box::pin(async { Err(UNENROLLED.to_string()) })
    }

    fn run<'a>(&'a self, _to: &'a Assigned, _job: JobRequest, _abort: watch::Receiver<AbortReason>, tx: mpsc::Sender<JobEvent>) -> Ran<'a> {
        Box::pin(async move {
            let _ = tx.send(JobEvent::Error { message: UNENROLLED.into() }).await;
        })
    }
}

#[cfg(test)]
pub mod recording {
    use super::*;
    use std::sync::Mutex;

    /// A link that keeps what it was sent, answers checks with `heartbeat`, and plays
    /// `script` back for every job.
    pub struct Recording {
        pub sent: Mutex<Vec<(Assigned, JobRequest)>>,
        pub heartbeat: Mutex<Result<Heartbeat, String>>,
        pub script: Mutex<Vec<JobEvent>>,
    }

    /// Records `m` as enrolled, with a certificate from a throwaway CA.
    pub fn enroll(db: &Db, m: &crate::db::Machine) {
        let ca = super::super::pki::Ca::from_seed(&[3; 32]).unwrap();
        let (_, csr) = super::super::pki::new_request(&m.id).unwrap();
        let issued = ca.issue_machine(&csr, &m.user_id, &m.id, 30).unwrap();
        let hash = crate::random_hex(8);
        db.add_machine_token(&m.id, &hash, crate::db::now() + 60_000, None).unwrap();
        let t = db.machine_token(&hash).unwrap().id;
        db.enroll_machine(t, &m.id, &m.user_id, &issued).unwrap();
    }

    pub fn layout() -> wire::Layout {
        wire::Layout {
            home: "/home/bots".into(),
            workspace: "/home/bots/work".into(),
            bots: "/home/bots/bots".into(),
            user_file: "/home/bots/USER.md".into(),
            api: "http://127.0.0.1:7444".into(),
            botctl: Some("/usr/local/bin/botctl".into()),
        }
    }

    impl Default for Recording {
        fn default() -> Recording {
            Recording {
                sent: Mutex::default(),
                heartbeat: Mutex::new(Ok(Heartbeat {
                    machine_id: String::new(),
                    user_id: String::new(),
                    version: "test".into(),
                    certificate: String::new(),
                    time: 0,
                    protocol: wire::PROTOCOL,
                    layout: Some(layout()),
                    missing: Vec::new(),
                    jobs: 0,
                })),
                script: Mutex::new(vec![
                    JobEvent::Started,
                    JobEvent::Exit { success: true, status: "exit status: 0".into(), stderr: String::new(), files: Default::default() },
                ]),
            }
        }
    }

    impl MachineLink for Recording {
        fn name(&self) -> &'static str {
            "recording"
        }

        fn check<'a>(&'a self, _app: &'a App, _to: &'a Assigned, _bins: &'a [&'a str]) -> Checked<'a> {
            let hb = self.heartbeat.lock().unwrap().clone();
            Box::pin(async move { hb })
        }

        fn run<'a>(&'a self, to: &'a Assigned, job: JobRequest, _abort: watch::Receiver<AbortReason>, tx: mpsc::Sender<JobEvent>) -> Ran<'a> {
            self.sent.lock().unwrap().push((to.clone(), job));
            let script = self.script.lock().unwrap().clone();
            Box::pin(async move {
                for e in script {
                    let _ = tx.send(e).await;
                }
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{Machine, NewMachine};

    fn machine(db: &Db, user: &str, state: State) -> Machine {
        let m = db
            .add_machine(&NewMachine { user_id: user, provider: "fake", label_prefix: "superbot", tier: "starter", plan: "g6-standard-1", region: "gb-lon", created_by: None })
            .unwrap_or_else(|_| panic!("machine for {user}"));
        set(db, &m.id, state);
        db.user_machine(user).unwrap()
    }

    fn set(db: &Db, id: &str, state: State) {
        let mut m = db.machine(id).unwrap();
        let from = m.state;
        m.state = state;
        assert!(db.save_machine(&m, from));
    }

    #[test]
    fn a_users_bots_route_to_their_own_assigned_machine_only() {
        let app = crate::runner::test_app();
        let db = &app.db;
        let a = db.create_user(None, Some("a@example.com"), "A", crate::rbac::Role::Member).unwrap();
        let b = db.create_user(None, Some("b@example.com"), "B", crate::rbac::Role::Member).unwrap();
        let off = ControlPlane::default();
        let on = ControlPlane { routing: Routing::On, ..ControlPlane::default() };
        let assigned = ControlPlane { routing: Routing::Assigned, ..ControlPlane::default() };
        assert_eq!(target(db, &off, &a.id), Ok(Target::Local), "routing off: this server");
        assert_eq!(target(db, &on, &a.id), Err(Refusal::NoMachine));
        assert_eq!(target(db, &assigned, &a.id), Ok(Target::Local), "not assigned: here, as before");

        let ma = machine(db, &a.id, State::Provisioning);
        assert_eq!(target(db, &on, &a.id), Err(Refusal::NotAssigned));
        assert_eq!(target(db, &assigned, &a.id), Ok(Target::Local));
        assert!(db.assign_machine(&ma.id, Some("admin")));
        for cp in [&on, &assigned] {
            assert_eq!(target(db, cp, &a.id), Err(Refusal::NotReady(State::Provisioning)), "assigned: there or nowhere");
        }
        set(db, &ma.id, State::Running);
        assert_eq!(target(db, &assigned, &a.id), Err(Refusal::NotEnrolled));
        recording::enroll(db, &ma);
        for cp in [&on, &assigned] {
            let Ok(Target::Machine(to)) = target(db, cp, &a.id) else { panic!("A's machine") };
            assert_eq!((to.machine_id.as_str(), to.user_id.as_str()), (ma.id.as_str(), a.id.as_str()));
            assert_eq!(to.pins.len(), 1);
        }
        assert_eq!(target(db, &on, &b.id), Err(Refusal::NoMachine), "B never gets A's machine");
        assert_eq!(target(db, &assigned, &b.id), Ok(Target::Local));
        set(db, &ma.id, State::Suspended);
        assert_eq!(target(db, &assigned, &a.id), Err(Refusal::NotReady(State::Suspended)), "never here instead");
        assert_eq!(target(db, &off, &a.id), Ok(Target::Local));

        assert!(db.unassign_machine(&ma.id));
        assert_eq!(target(db, &assigned, &a.id), Ok(Target::Local));
    }

    #[test]
    fn a_machine_must_be_fit_for_the_run() {
        let ok = Heartbeat {
            machine_id: "m".into(),
            user_id: "u".into(),
            version: "0.2.0".into(),
            certificate: String::new(),
            time: 0,
            protocol: wire::PROTOCOL,
            layout: Some(recording::layout()),
            missing: Vec::new(),
            jobs: 0,
        };
        assert_eq!(fit(&ok, "claude"), Ok(recording::layout()));
        let old = Heartbeat { protocol: 0, layout: None, version: "0.1.0".into(), ..ok.clone() };
        assert_eq!(fit(&old, "claude"), Err(Refusal::Outdated("0.1.0".into())));
        let missing = Heartbeat { missing: vec!["hermes".into()], ..ok.clone() };
        assert_eq!(fit(&missing, "hermes"), Err(Refusal::HarnessMissing("hermes".into())));
        let mut layout = recording::layout();
        layout.botctl = None;
        assert_eq!(fit(&Heartbeat { layout: Some(layout), ..ok }, "claude"), Err(Refusal::NoBotctl));
        for r in [Refusal::Offline("x".into()), Refusal::NotAssigned, Refusal::NoBotctl] {
            assert!(!r.message().is_empty() && !r.reason().is_empty());
        }
    }
}
