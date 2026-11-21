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
    /// The Bot's harness is still being installed on it (ADR 0039).
    HarnessInstalling(String),
    /// Its agent is replacing itself (ADR 0039).
    Upgrading,
    /// `botctl` isn't installed on it, so approvals can't be asked for there.
    NoBotctl,
    /// The Bot's harness isn't logged in there and the owner has no key for it (ADR 0041).
    NotLoggedIn(String),
    /// The owner's folder is being copied there for the first time (ADR 0041).
    FolderCopying,
    /// Bots' own user there isn't ready yet (ADR 0043).
    BotUserPending,
    /// Its agent couldn't set up the Bots' own user (ADR 0043).
    BotUserFailed,
    /// A teammate's run there needs a server-wide key for this harness, since it runs as
    /// the teammate's own user, outside the machine's logins (ADR 0048).
    NoTeammateKey(String),
    /// Its agent couldn't set up the teammate's own user (ADR 0048): its words.
    TeammateUserFailed(String),
    /// A teammate's run there needs their own login for this harness, in their own home
    /// there, or a server-wide key; the owner's login is never used for it (ADR 0062).
    TeammateNotLoggedIn(String),
    /// It is being rebuilt with today's agent, or is about to be (ADR 0056).
    Rebuilding,
    /// It is being made again from an off-host backup (ADR 0071).
    Restoring,
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
            Refusal::HarnessInstalling(_) => "harness_installing",
            Refusal::Upgrading => "agent_upgrading",
            Refusal::NoBotctl => "agent_incomplete",
            Refusal::NotLoggedIn(_) => "harness_not_logged_in",
            Refusal::FolderCopying => "folder_copying",
            Refusal::BotUserPending => "bot_user_pending",
            Refusal::BotUserFailed => "bot_user_failed",
            Refusal::NoTeammateKey(_) => "teammate_no_key",
            Refusal::TeammateUserFailed(_) => "teammate_user_failed",
            Refusal::TeammateNotLoggedIn(_) => "teammate_not_logged_in",
            Refusal::Rebuilding => "machine_rebuilding",
            Refusal::Restoring => "machine_restoring",
        }
    }

    /// The machine's own words, for the audit log: its error, version or state.
    pub fn detail(&self) -> Option<String> {
        match self {
            Refusal::Offline(e) | Refusal::Outdated(e) | Refusal::TeammateUserFailed(e) => Some(e.clone()),
            Refusal::NotReady(s) => Some(s.as_str().into()),
            Refusal::HarnessMissing(h) | Refusal::HarnessInstalling(h) | Refusal::NotLoggedIn(h) | Refusal::NoTeammateKey(h) | Refusal::TeammateNotLoggedIn(h) => {
                Some(h.clone())
            }
            _ => None,
        }
    }

    /// What the Bot tells the user.
    pub fn message(&self) -> String {
        self.message_in(true)
    }

    /// `message`, with the machine's own errors and versions only if `detail`: a shared
    /// Bot's chat is read by others than its owner (ADR 0046).
    pub fn message_in(&self, detail: bool) -> String {
        let quiet = |s: &str, wrap: fn(&str) -> String| if detail { wrap(s) } else { String::new() };
        match self {
            Refusal::NoMachine => "I can't run yet: you don't have a computer. Ask an admin to set one up for you.".into(),
            Refusal::NotAssigned => "I can't run yet: your computer isn't assigned to you. Ask an admin to assign it.".into(),
            Refusal::NotReady(s) => format!("I can't run yet: your computer is {}. Try again when it's running.", s.as_str()),
            Refusal::NotEnrolled => "I can't run yet: your computer hasn't connected to this server. Ask an admin to check on it.".into(),
            Refusal::Offline(e) => format!(
                "I didn't run: your computer is offline{}. Try again soon; if it stays offline, ask an admin to check on it.",
                quiet(e, |e| format!(" ({e})"))
            ),
            Refusal::Outdated(v) => format!("I didn't run: your computer's agent{} is too old to run Bots. Ask an admin to update it.", quiet(v, |v| format!(" ({v})"))),
            Refusal::HarnessMissing(h) => format!("I didn't run: {h} isn't installed on your computer. Ask an admin to install it, or switch me to another harness."),
            Refusal::HarnessInstalling(h) => format!("I didn't run: {h} is still being installed on your computer. Try again in a few minutes."),
            Refusal::Upgrading => "I didn't run: your computer's agent is updating itself. Try again in a minute.".into(),
            Refusal::NoBotctl => "I didn't run: botctl isn't installed on your computer, so I couldn't ask you before risky steps. Ask an admin to install it.".into(),
            Refusal::NotLoggedIn(h) => format!("I didn't run: {h} isn't logged in on your computer. Ask an admin to log it in there (`botctl machine harness-login <your email> {h}`), or save an API key for it in your secrets."),
            Refusal::FolderCopying => "I didn't run: your files are still being copied to your computer. Try again in a few minutes.".into(),
            Refusal::BotUserPending => "I didn't run: your computer is still setting up a separate account for your Bots. Try again in a few minutes.".into(),
            Refusal::BotUserFailed => "I didn't run: your computer couldn't set up a separate account for your Bots. Ask an admin to look at it (`botctl machine agent <your email>`).".into(),
            Refusal::NoTeammateKey(h) => format!("I didn't run: runs for your teammates use their own account on your computer, and {h} has no server-wide key for that. Ask an admin to save one."),
            Refusal::TeammateUserFailed(_) => "I didn't run: your computer couldn't set up a separate account for a teammate. Ask an admin to look at it (`botctl machine agent <your email>`).".into(),
            Refusal::TeammateNotLoggedIn(h) => format!("I didn't run: runs for your teammates use their own {h} login on your computer, never yours, and this one has none. They can log in from my details in the app, or an admin can save a server-wide key."),
            Refusal::Rebuilding => "I didn't run: your computer is being rebuilt with the latest setup. Try again in a few minutes.".into(),
            Refusal::Restoring => "I didn't run: your computer is being restored from a backup. Try again once an admin says it's back.".into(),
        }
    }

    /// What a shared Bot tells everyone who uses it (ADR 0046): whose computer it is,
    /// and never that computer's state, errors, or versions; those stay in the audit log.
    pub fn message_for(&self, owner: Option<&str>) -> String {
        let o = owner.unwrap_or("my owner");
        let why = match self {
            Refusal::NoMachine | Refusal::NotAssigned | Refusal::NotEnrolled => {
                return format!("I can't run yet: I run on {o}'s computer, and it isn't set up. {o} or an admin can fix that.");
            }
            Refusal::NotReady(_) | Refusal::Offline(_) => "it isn't reachable right now",
            Refusal::HarnessMissing(_) | Refusal::HarnessInstalling(_) => "it doesn't have my harness ready",
            Refusal::NotLoggedIn(h) => {
                return format!("I didn't run: {h} isn't logged in for me on {o}'s computer. An admin can log it in there, or save a server-wide key for it.");
            }
            Refusal::NoTeammateKey(h) => {
                return format!("I didn't run: on {o}'s computer, runs for teammates use a separate account, and {h} has no server-wide key for that. An admin can save one.");
            }
            Refusal::TeammateNotLoggedIn(h) => {
                return format!("I didn't run: {h} isn't logged in for you on {o}'s computer. Runs for teammates there use their own login, never {o}'s. Log in from my details in the app, or an admin can save a server-wide key.");
            }
            Refusal::TeammateUserFailed(_) => "it couldn't set up an account for you there",
            Refusal::Outdated(_)
            | Refusal::Upgrading
            | Refusal::NoBotctl
            | Refusal::FolderCopying
            | Refusal::BotUserPending
            | Refusal::BotUserFailed
            | Refusal::Rebuilding
            | Refusal::Restoring => {
                "it isn't ready to run Bots"
            }
        };
        format!("I didn't run: I run on {o}'s computer, and {why}. Try again later; if it lasts, tell {o} or an admin.")
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
    if super::rebuild::underway(&m) {
        return Err(Refusal::Rebuilding);
    }
    if super::backup::restoring(db, &m.id) {
        return Err(Refusal::Restoring);
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
    if hb.upgrade.as_ref().is_some_and(|u| u.state == wire::UPGRADE_STAGING) {
        return Err(Refusal::Upgrading);
    }
    if hb.missing.iter().any(|m| m == bin) {
        let installing = hb
            .harnesses
            .get(bin)
            .is_some_and(|h| h.state == wire::HARNESS_QUEUED || h.state == wire::HARNESS_INSTALLING);
        return Err(if installing { Refusal::HarnessInstalling(bin.into()) } else { Refusal::HarnessMissing(bin.into()) });
    }
    if layout.botctl.is_none() {
        return Err(Refusal::NoBotctl);
    }
    Ok(layout)
}

/// Whether the machine's login for `bin` lets a run start (ADR 0041): it's logged in
/// there, or the run has a key that makes a login unneeded (`keyed`).
/// An agent from before ADR 0041 can't log in or say whether it is, so it's outdated.
pub fn logged_in(hb: &Heartbeat, bin: &str, keyed: bool) -> Result<(), Refusal> {
    let there = hb.logins.get(bin).is_some_and(|l| l.state == wire::LOGGED_IN);
    if there || keyed {
        Ok(())
    } else if !hb.can.iter().any(|c| c == wire::CAN_LOGINS) {
        Err(Refusal::Outdated(hb.version.clone()))
    } else {
        Err(Refusal::NotLoggedIn(bin.into()))
    }
}

pub type Checked<'a> = Pin<Box<dyn Future<Output = Result<Heartbeat, String>> + Send + 'a>>;
pub type Ran<'a> = Pin<Box<dyn Future<Output = ()> + Send + 'a>>;
pub type Teammated<'a> = Pin<Box<dyn Future<Output = Result<wire::TeammateReply, String>> + Send + 'a>>;

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
    /// Makes sure `user_id`, a teammate of the machine's owner, has their own user
    /// there (ADR 0048), and says where its folders are.
    fn teammate<'a>(&'a self, to: &'a Assigned, user_id: &'a str) -> Teammated<'a>;
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

    fn teammate<'a>(&'a self, _to: &'a Assigned, _user_id: &'a str) -> Teammated<'a> {
        Box::pin(async { Err(UNENROLLED.to_string()) })
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
        /// Teammates it was asked to make users for, and what it answers.
        pub teammates: Mutex<Vec<String>>,
        pub teammate_error: Mutex<Option<String>>,
        /// Each teammate's own logins there (ADR 0062), as its answer says.
        pub teammate_logins: Mutex<std::collections::HashMap<String, std::collections::BTreeMap<String, wire::LoginStatus>>>,
    }

    /// Records `m` as enrolled, with a certificate from a throwaway CA.
    pub fn enroll(db: &Db, m: &crate::db::Machine) {
        let ca = super::super::pki::Ca::from_seed(&[3; 32]).unwrap();
        let (_, csr) = super::super::pki::new_request(&m.id).unwrap();
        let issued = ca.issue_machine(&csr, &m.user_id, &m.id, 30).unwrap();
        let hash = crate::random_hex(8);
        db.add_machine_token(&m.id, &hash, crate::db::now() + 60_000, None, crate::db::now() + 60_000).unwrap();
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
            sandbox: Some(crate::sandbox::Host { namespaces: true, programs: vec!["bwrap".into(), "socat".into()] }),
            caches: vec!["/home/bots/.npm".into()],
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
                    ..Heartbeat::default()
                })),
                script: Mutex::new(vec![
                    JobEvent::Started,
                    JobEvent::Exit { success: true, status: "exit status: 0".into(), stderr: String::new(), files: Default::default(), too_big: Vec::new() },
                ]),
                teammates: Mutex::default(),
                teammate_error: Mutex::default(),
                teammate_logins: Mutex::default(),
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

        fn teammate<'a>(&'a self, _to: &'a Assigned, user_id: &'a str) -> Teammated<'a> {
            let created = {
                let mut seen = self.teammates.lock().unwrap();
                let created = !seen.iter().any(|u| u == user_id);
                seen.push(user_id.to_string());
                created
            };
            let res = match self.teammate_error.lock().unwrap().clone() {
                Some(e) => Err(e),
                None => {
                    let mut r = teammate_reply(user_id, created);
                    r.logins = self.teammate_logins.lock().unwrap().get(user_id).cloned().unwrap_or_default();
                    Ok(r)
                }
            };
            Box::pin(async move { res })
        }
    }

    /// Where a stand-in machine keeps `user_id`'s teammate user.
    pub fn teammate_reply(user_id: &str, created: bool) -> wire::TeammateReply {
        let user = wire::teammate_user(user_id);
        let home = format!("/home/teammates/{user}");
        wire::TeammateReply { workspace: format!("{home}/work"), bots: format!("{home}/bots"), home, uid: 2001, user, created, logins: Default::default() }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{Machine, NewMachine};

    #[test]
    fn a_shared_bot_says_whose_computer_it_is_and_nothing_inside() {
        let all = [
            Refusal::NoMachine,
            Refusal::NotReady(State::Suspended),
            Refusal::Offline("connection refused at 192.0.2.7".into()),
            Refusal::Outdated("0.1.0-old".into()),
            Refusal::HarnessMissing("claude".into()),
            Refusal::NotLoggedIn("claude".into()),
            Refusal::BotUserFailed,
            Refusal::NoTeammateKey("claude".into()),
            Refusal::TeammateUserFailed("useradd failed at 192.0.2.7".into()),
            Refusal::TeammateNotLoggedIn("claude".into()),
            Refusal::Rebuilding,
            Refusal::Restoring,
        ];
        for r in &all {
            let m = r.message_for(Some("Ada"));
            assert!(m.contains("Ada's computer"), "{m}");
            assert!(!m.contains("your") && !m.contains("192.0.2.7") && !m.contains("0.1.0-old") && !m.contains("suspended") && !m.contains("botctl"), "{m}");
            let own = r.message_in(false);
            assert!(!own.contains("192.0.2.7") && !own.contains("0.1.0-old"), "{own}");
        }
        assert!(Refusal::Offline("refused".into()).message().contains("offline (refused)"), "the owner's private Bots keep the detail");
        assert!(Refusal::NoMachine.message_for(None).contains("my owner's computer"));
    }

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
    fn a_run_from_before_a_move_keeps_no_session() {
        let app = crate::runner::test_app();
        let db = &app.db;
        let a = db.create_user(None, Some("a@example.com"), "A", crate::rbac::Role::Member).unwrap();
        let bot = db.create_bot_owned("Bot", "#fff", "waddle", "claude", None, true, &a.id, crate::acl::Visibility::Private);
        let session = |db: &Db| db.bot(&bot.id).unwrap().session_id;
        let m = machine(db, &a.id, State::Running);
        let here = db.placed_at(&a.id);
        assert!(db.keep_session(&bot.id, "s1", here));
        assert!(!db.keep_session(&bot.id, "s1", here), "unchanged");

        let before = db.placed_at(&a.id);
        assert!(db.assign_machine(&m.id, None));
        db.forget_sessions_of(&a.id);
        assert!(!db.keep_session(&bot.id, "old", before), "the old host's run");
        assert_eq!(session(db), None);
        let there = db.placed_at(&a.id);
        assert!(there.is_some() && db.keep_session(&bot.id, "s2", there));

        assert!(db.unassign_machine(&m.id));
        db.forget_sessions_of(&a.id);
        assert!(!db.keep_session(&bot.id, "old", there));
        assert_eq!(session(db), None);
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
            ..Heartbeat::default()
        };
        assert_eq!(fit(&ok, "claude"), Ok(recording::layout()));
        let old = Heartbeat { protocol: 0, layout: None, version: "0.1.0".into(), ..ok.clone() };
        assert_eq!(fit(&old, "claude"), Err(Refusal::Outdated("0.1.0".into())));
        let missing = Heartbeat { missing: vec!["hermes".into()], ..ok.clone() };
        assert_eq!(fit(&missing, "hermes"), Err(Refusal::HarnessMissing("hermes".into())));
        let mut installing = missing.clone();
        installing.harnesses.insert("hermes".into(), wire::HarnessStatus { state: wire::HARNESS_INSTALLING.into(), ..Default::default() });
        assert_eq!(fit(&installing, "hermes"), Err(Refusal::HarnessInstalling("hermes".into())));
        installing.harnesses.get_mut("hermes").unwrap().state = wire::HARNESS_FAILED.into();
        assert_eq!(fit(&installing, "hermes"), Err(Refusal::HarnessMissing("hermes".into())), "a failed install is missing");
        let upgrading = Heartbeat { upgrade: Some(wire::UpgradeReport { state: wire::UPGRADE_STAGING.into(), ..Default::default() }), ..ok.clone() };
        assert_eq!(fit(&upgrading, "claude"), Err(Refusal::Upgrading));
        let mut layout = recording::layout();
        layout.botctl = None;
        assert_eq!(fit(&Heartbeat { layout: Some(layout), ..ok }, "claude"), Err(Refusal::NoBotctl));
        for r in [Refusal::Offline("x".into()), Refusal::NotAssigned, Refusal::NoBotctl, Refusal::Upgrading, Refusal::HarnessInstalling("pi".into())] {
            assert!(!r.message().is_empty() && !r.reason().is_empty());
        }
    }

    #[test]
    fn a_run_needs_its_harness_logged_in_there_or_a_key() {
        let mut hb = Heartbeat { version: "0.1.0".into(), ..Heartbeat::default() };
        assert_eq!(logged_in(&hb, "claude", false), Err(Refusal::Outdated("0.1.0".into())), "an agent that can't log in");
        assert_eq!(logged_in(&hb, "claude", true), Ok(()));
        hb.can.push(wire::CAN_LOGINS.into());
        assert_eq!(logged_in(&hb, "claude", false), Err(Refusal::NotLoggedIn("claude".into())));
        for (state, ok) in [(wire::LOGGED_OUT, false), (wire::LOGGING_IN, false), (wire::LOGGED_IN, true)] {
            hb.logins.insert("claude".into(), wire::LoginStatus { state: state.into(), since: None });
            assert_eq!(logged_in(&hb, "claude", false).is_ok(), ok, "{state}");
        }
        assert_eq!(Refusal::NotLoggedIn("claude".into()).reason(), "harness_not_logged_in");
        assert!(Refusal::NotLoggedIn("codex".into()).message().contains("botctl machine harness-login <your email> codex"));
        assert_eq!(Refusal::FolderCopying.reason(), "folder_copying");
        assert_eq!(Refusal::BotUserPending.reason(), "bot_user_pending");
        assert_eq!(Refusal::BotUserFailed.reason(), "bot_user_failed");
    }
}
