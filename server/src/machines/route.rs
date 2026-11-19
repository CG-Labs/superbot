//! Where a Bot's work runs (ADR 0028). Each user has one computer, and all of their
//! Bots share it. With routing off (self-hosting, and managed hosting until machines
//! enroll), every Bot runs on this server in its owner's folders. With MACHINE_ROUTING
//! on, a Bot runs only on its owner's machine: never here, and never on anyone else's.
//! `MachineLink` is the seam the machine agent plugs into; until it exists, nothing is
//! sent and runs are refused rather than falling back to this server.

use super::{ControlPlane, State};
use crate::db::{Db, Machine};
use std::future::Future;
use std::pin::Pin;

/// A user's machine, as far as routing needs it.
#[derive(Clone, Debug, PartialEq)]
pub struct Assigned {
    pub machine_id: String,
    pub user_id: String,
    /// Where the machine answers. None until the provider gives it an address.
    pub address: Option<String>,
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
    /// The owner's machine exists but isn't running (still being built, suspended, ...).
    NotReady(State),
    /// The machine is running but the work couldn't be handed to it.
    Unreachable(String),
}

impl Refusal {
    pub fn reason(&self) -> &'static str {
        match self {
            Refusal::NoMachine => "no_machine",
            Refusal::NotReady(_) => "machine_not_ready",
            Refusal::Unreachable(_) => "machine_unreachable",
        }
    }

    /// What the Bot tells the user.
    pub fn message(&self) -> String {
        match self {
            Refusal::NoMachine => "I can't run yet: you don't have a computer. Ask an admin to set one up for you.".into(),
            Refusal::NotReady(s) => format!("I can't run yet: your computer is {}. Try again when it's running.", s.as_str()),
            Refusal::Unreachable(e) => format!("I couldn't reach your computer: {e}"),
        }
    }
}

/// The routing target for `user_id`'s Bots: their own machine only. Looked up by the
/// owner, never by the Bot or the caller, so a Bot shared with others still runs on
/// its owner's machine.
pub fn target(db: &Db, cp: &ControlPlane, user_id: &str) -> Result<Target, Refusal> {
    if !cp.routing {
        return Ok(Target::Local);
    }
    let m = db.user_machine(user_id).ok_or(Refusal::NoMachine)?;
    if m.user_id != user_id {
        return Err(Refusal::NoMachine);
    }
    match m.state {
        State::Running => Ok(Target::Machine(assigned(&m))),
        s => Err(Refusal::NotReady(s)),
    }
}

fn assigned(m: &Machine) -> Assigned {
    Assigned { machine_id: m.id.clone(), user_id: m.user_id.clone(), address: m.ipv4.clone() }
}

/// One message for a Bot to work on, handed to its owner's machine.
#[derive(Clone, Debug, PartialEq)]
pub struct Job {
    pub bot_id: String,
    pub owner_id: String,
    pub message_id: i64,
}

pub type Dispatched<'a> = Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>>;

/// Hands work to a user's machine. The machine agent (enrollment, mutual TLS, and
/// the run protocol) implements this; botd never sends a job to any machine but the
/// one `target` picked for the Bot's owner.
pub trait MachineLink: Send + Sync {
    fn name(&self) -> &'static str;
    fn dispatch<'a>(&'a self, to: &'a Assigned, job: Job) -> Dispatched<'a>;
}

/// Until machines enroll: nothing can be sent, so routed runs are refused.
pub struct Unenrolled;

impl MachineLink for Unenrolled {
    fn name(&self) -> &'static str {
        "unenrolled"
    }

    fn dispatch<'a>(&'a self, _to: &'a Assigned, _job: Job) -> Dispatched<'a> {
        Box::pin(async { Err("this server can't send work to machines yet (no machine agent is enrolled)".to_string()) })
    }
}

#[cfg(test)]
pub mod recording {
    use super::*;
    use std::sync::Mutex;

    /// A link that keeps what it was sent.
    #[derive(Default)]
    pub struct Recording {
        pub sent: Mutex<Vec<(Assigned, Job)>>,
    }

    impl MachineLink for Recording {
        fn name(&self) -> &'static str {
            "recording"
        }

        fn dispatch<'a>(&'a self, to: &'a Assigned, job: Job) -> Dispatched<'a> {
            self.sent.lock().unwrap().push((to.clone(), job));
            Box::pin(async { Ok(()) })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::NewMachine;

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
    fn a_users_bots_route_to_their_own_machine_only() {
        let app = crate::runner::test_app();
        let db = &app.db;
        let a = db.create_user(None, Some("a@example.com"), "A", crate::rbac::Role::Member).unwrap();
        let b = db.create_user(None, Some("b@example.com"), "B", crate::rbac::Role::Member).unwrap();
        let off = ControlPlane::default();
        assert_eq!(target(db, &off, &a.id), Ok(Target::Local), "routing off: this server");

        let on = ControlPlane { routing: true, ..ControlPlane::default() };
        assert_eq!(target(db, &on, &a.id), Err(Refusal::NoMachine));
        let ma = machine(db, &a.id, State::Provisioning);
        assert_eq!(target(db, &on, &a.id), Err(Refusal::NotReady(State::Provisioning)));
        set(db, &ma.id, State::Running);
        let Ok(Target::Machine(to)) = target(db, &on, &a.id) else { panic!("A's machine") };
        assert_eq!((to.machine_id.as_str(), to.user_id.as_str()), (ma.id.as_str(), a.id.as_str()));
        assert_eq!(target(db, &on, &b.id), Err(Refusal::NoMachine), "B never gets A's machine");
        set(db, &ma.id, State::Suspended);
        assert_eq!(target(db, &on, &a.id), Err(Refusal::NotReady(State::Suspended)));
    }
}
