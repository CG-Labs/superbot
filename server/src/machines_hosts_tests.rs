//! Losing a whole Incus host (ADR 0076), end to end on loopback: two stand-ins for
//! Incus hosts behind one provider, the S3 stand-in for off-host backups, botd's
//! machine port and the real agent. A host that stops answering is found down; once
//! an admin declares it lost, its machines are made again on the other host from their
//! backups and enroll anew.

use crate::machines::agent::{self, Config};
use crate::machines::backup::{self, IDENTITY_PATH, Offsite, Retention, Settings};
use crate::machines::enroll::{self, Enrollment};
use crate::machines::firewall;
use crate::machines::hosts;
use crate::machines::incus::Incus;
use crate::machines::incus::fleet::{Fleet, Member};
use crate::machines::incus_standin::StandIn;
use crate::machines::provider::Policy;
use crate::machines::s3_standin;
use crate::machines::{ControlPlane, State};
use crate::tests::{audit_list, call};
use crate::users_http_tests::{parse, user_with};
use crate::*;
use tokio::net::TcpListener;
use zeroize::Zeroizing;

pub(crate) struct Env {
    pub(crate) port: u16,
    pub(crate) app: AppState,
    pub(crate) admin: String,
    pub(crate) a: StandIn,
    pub(crate) b: StandIn,
    pub(crate) c: StandIn,
    pub(crate) cp: Arc<ControlPlane>,
    pub(crate) e: Arc<Enrollment>,
    mport: u16,
    pub(crate) s3: s3_standin::StandIn,
    /// With hosts tagged by region, every region but the first has a store of its own.
    pub(crate) stores: Vec<(String, s3_standin::StandIn)>,
}

const AGENT: &str = "stand-in for the superbot-machine binary";
pub(crate) const DOWN_MS: i64 = 60_000;

pub(crate) fn host(name: &str, s: &StandIn, mport: u16) -> Member {
    s.w().projects.insert("superbot".into(), json!({ "restricted": "true", "restricted.backups": "allow" }));
    Member::new(name, Incus::new(s.settings(Some(("127.0.0.1".parse().unwrap(), mport))), s.credentials()).unwrap())
}

/// botd with Incus hosts `a` and `b`, enrollment, the firewall and backups on. New
/// machines go on the first host with room.
async fn serve() -> Env {
    serve_with(|a, b, _| Fleet::new(vec![a, b], DOWN_MS).with_policy(Policy::Fill)).await
}

/// As `serve`, with the fleet `build` makes of hosts `a`, `b` and `c`. With hosts tagged
/// by data region (ADR 0117), MACHINE_REGIONS is their tags, the first the default; its
/// backups go to the default store, said to be in it, and every other region's to its own.
pub(crate) async fn serve_with(build: impl FnOnce(Member, Member, Member) -> Fleet) -> Env {
    let machine_listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let agent_listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let (mport, aport) = (machine_listener.local_addr().unwrap().port(), agent_listener.local_addr().unwrap().port());
    drop(agent_listener);
    let (a, b, c) = (StandIn::start().await, StandIn::start().await, StandIn::start().await);
    let fleet = build(host("a", &a, mport), host("b", &b, mport), host("c", &c, mport));
    let s3 = s3_standin::StandIn::start().await;
    let mut tags: Vec<String> = Vec::new();
    for r in crate::machines::provider::Hosts::configured(&fleet).into_iter().filter_map(|h| h.region) {
        if !tags.contains(&r) {
            tags.push(r);
        }
    }
    let mut stores = Vec::new();
    for r in tags.iter().skip(1) {
        stores.push((r.clone(), s3_standin::StandIn::start().await));
    }
    let mut cp = ControlPlane::for_tests(Arc::new(fleet));
    cp.regions = if tags.is_empty() { vec!["local".into()] } else { tags.clone() };
    cp.routing = crate::machines::route::Routing::On;
    let e = cp.enroll_with(Enrollment::for_tests(9, mport, aport).with_agent(AGENT.as_bytes())).unwrap();
    cp.firewall_with(firewall::Settings { sources: Vec::new(), ssh: Vec::new() }).unwrap();
    let s = Settings {
        retention: Retention::retention("7").unwrap(),
        default_region: tags.first().cloned(),
        stores: stores.iter().map(|(r, st)| (r.clone(), st.settings())).collect(),
        regions: cp.regions.clone(),
        ..Settings::with(s3.settings(), "t/", Vec::new())
    };
    cp.offsite = Some(Arc::new(Offsite::new(s).unwrap()));
    let cp = Arc::new(cp);
    let shared = cp.clone();
    let (port, app, owner, _) = crate::tests::serve_app_with(move |a| a.machines = shared).await;
    hosts::load(&app, &cp).unwrap();
    tokio::spawn(enroll::serve(machine_listener, app.clone(), e.clone(), None));
    let (_, admin) = user_with(port, &owner, "ops@example.com", "admin").await;
    Env { port, app, admin, a, b, c, cp, e, mport, s3, stores }
}

pub(crate) async fn json_call(env: &Env, method: &str, path: &str, body: &str) -> (u16, Value) {
    let (code, body) = call(env.port, method, path, &env.admin, body).await;
    (code, parse(&body))
}

pub(crate) async fn events(env: &Env, action: &str) -> Vec<Value> {
    let (code, body) = call(env.port, "GET", &format!("/api/audit?action={action}&limit=200"), &env.admin, "").await;
    assert_eq!(code, 200, "{body}");
    audit_list(&body)
}

pub(crate) async fn reconcile(env: &Env) -> Value {
    let (code, r) = json_call(env, "POST", "/api/machines/reconcile", "").await;
    assert_eq!(code, 200, "{r}");
    r
}

pub(crate) fn config(env: &Env, machine_id: &str, token: &str) -> Config {
    Config {
        control_url: env.e.url.clone(),
        machine_id: machine_id.into(),
        ca_pem: env.e.ca_pem().into(),
        state_dir: crate::db::temp_path("agent"),
        listen: SocketAddr::from(([127, 0, 0, 1], env.e.agent_port)),
        token: Some(Zeroizing::new(token.to_string())),
        token_file: None,
        home: crate::db::temp_path("agent-home"),
        api_listen: SocketAddr::from(([127, 0, 0, 1], 0)),
        botctl: std::path::PathBuf::from("/nonexistent/botctl"),
        harness_path: "/usr/bin:/bin".into(),
        max_jobs: 8,
        tools: crate::db::temp_path("agent-tools"),
        exe: crate::db::temp_path("agent-exe"),
        bot_user: crate::machines::runas::current_user().unwrap(),
        allow_own_user: true,
        screens: crate::machines_mtls_tests::no_screens(),
        teammates: crate::db::temp_path("agent-teammates"),
        teammate_stand_in: None,
    }
}

/// A member's machine, running on host `a`: enrolled, with a file of theirs on its
/// disk, if `enroll`.
async fn machine(env: &Env, email: &str, enroll: bool) -> (String, crate::db::Machine) {
    machine_on(env, &env.a, "a", email, enroll).await
}

/// A member's machine, which placement must put on `host` (stand-in `s`).
pub(crate) async fn machine_on(env: &Env, s: &StandIn, host: &str, email: &str, enroll: bool) -> (String, crate::db::Machine) {
    let (uid, _) = user_with(env.port, &env.admin, email, "member").await;
    (uid.clone(), machine_for(env, s, host, &uid, enroll).await)
}

/// A machine for user `uid`, which placement must put on `host` (stand-in `s`).
pub(crate) async fn machine_for(env: &Env, s: &StandIn, host: &str, uid: &str, enroll: bool) -> crate::db::Machine {
    let (code, m) = json_call(env, "POST", &format!("/api/users/{uid}/machine"), "").await;
    assert_eq!(code, 202, "{m}");
    let m = env.app.db.machine(m["id"].as_str().unwrap()).unwrap();
    assert_eq!(m.provider_id.as_deref(), Some(format!("{host}/{}", m.label).as_str()), "placed on {host}");
    s.w().instances.get_mut(&m.label).unwrap().ip = "127.0.0.1".into();
    reconcile(env).await;
    if enroll {
        let user_data = s.instance(&m.label).unwrap().body["config"]["cloud-init.user-data"].as_str().unwrap().to_string();
        let at = user_data.find("content: \"sbe_").unwrap() + "content: \"".len();
        let token = user_data[at..].split('"').next().unwrap().to_string();
        agent::enroll(&config(env, &m.id, &token)).await.unwrap();
        reconcile(env).await;
        write(s, &m.label, "/home/user/notes.txt", "version 1");
        write(s, &m.label, IDENTITY_PATH, "the old agent's key");
    }
    env.app.db.machine(&m.id).unwrap()
}

pub(crate) fn write(s: &StandIn, label: &str, path: &str, content: &str) {
    s.w().instances.get_mut(label).unwrap().files.insert(path.into(), (content.as_bytes().to_vec(), "0644".into()));
}

pub(crate) fn read(s: &StandIn, label: &str, path: &str) -> Option<String> {
    s.instance(label)?.files.get(path).map(|(c, _)| String::from_utf8_lossy(c).into_owned())
}

pub(crate) async fn until(what: &str, mut f: impl FnMut() -> bool) {
    for _ in 0..200 {
        if f() {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    panic!("timed out waiting for {what}");
}

pub(crate) async fn back_up(env: &Env, uid: &str) -> crate::db::MachineBackup {
    let (code, b) = json_call(env, "POST", &format!("/api/users/{uid}/machine/backups"), "").await;
    assert_eq!(code, 202, "{b}");
    let id = b["id"].as_str().unwrap().to_string();
    until("the backup", || env.app.db.machine_backup(&id).is_some_and(|b| b.state != "running")).await;
    let b = env.app.db.machine_backup(&id).unwrap();
    assert_eq!(b.state, "done", "{:?}", b.error);
    b
}

pub(crate) async fn settled(env: &Env, id: &str) -> crate::db::MachineRestore {
    until("the restore", || env.app.db.machine_restore(id).is_some_and(|r| !matches!(r.state.as_str(), "importing" | "replacing"))).await;
    // It's enrolling before the restored machine boots; the restore holds the lock until then.
    drop(env.app.control_plane.get().unwrap().lock_ops().await);
    env.app.db.machine_restore(id).unwrap()
}

/// The token a restore left on the machine's disk, and its agent enrolling with it.
pub(crate) async fn enroll_again(env: &Env, s: &StandIn, m: &crate::db::Machine) {
    let token = read(s, &m.label, "/etc/superbot/enroll-token").expect("a fresh token on its disk");
    agent::enroll(&config(env, &m.id, &token)).await.unwrap();
    backup::follow_up(&env.app, &env.cp).await;
}

pub(crate) fn alerts_to(env: &Env, mail: &crate::notify::smtp::fake::Server) {
    let smtp = crate::notify::smtp::Smtp::for_test("127.0.0.1", mail.port, crate::notify::smtp::Tls::None, None, None);
    let _ = env.app.notifier.set(Arc::new(crate::notify::Notifier::new(Some(smtp), Some("https://bots.example.com".into()))));
    let s = crate::notify::Settings {
        email: crate::notify::EmailSettings { enabled: true, to: vec!["ops@example.com".into()], deciders: true },
        ..Default::default()
    };
    crate::notify::save(&env.app.db, &s);
}

pub(crate) async fn mail_with(mail: &crate::notify::smtp::fake::Server, subject: &str) -> crate::notify::smtp::fake::Received {
    let mut found = None;
    until(subject, || {
        found = mail.got.lock().unwrap().iter().find(|m| m.headers.contains(subject)).cloned();
        found.is_some()
    })
    .await;
    found.unwrap()
}

#[tokio::test]
async fn a_lost_hosts_machines_are_restored_onto_another_host_and_enroll_anew() {
    let env = serve().await;
    let mail = crate::notify::smtp::fake::start(Default::default()).await;
    alerts_to(&env, &mail);
    let (code, h) = json_call(&env, "GET", "/api/machines/hosts", "").await;
    assert_eq!(code, 200, "{h}");
    assert_eq!((h["hosts"][0]["name"].as_str(), h["hosts"][0]["state"].as_str(), h["hosts"][1]["name"].as_str()), (Some("a"), Some("up"), Some("b")), "{h}");
    assert_eq!(h["placement"].as_str(), Some("a"));

    let (ada, m) = machine(&env, "ada@example.com", true).await;
    let (bea, n) = machine(&env, "bea@example.com", false).await;
    // One with a restore underway when its host is lost, and one whose create (on a)
    // went unanswered as far as botd knows.
    let (dee, d) = machine(&env, "dee@example.com", true).await;
    let db = back_up(&env, &dee).await;
    let busy = crate::db::NewMachineRestore { id: "rbusy", machine: &d, backup_id: &db.id, by: None, rto_ms: None, from_host: None, to_host: None, reason: None };
    env.app.db.machine_restore_start(&busy).unwrap();
    assert!(!env.app.db.machine_pins(&d.id).is_empty());
    let (_, ed) = machine(&env, "ed@example.com", false).await;
    let b = back_up(&env, &ada).await;
    let (_, view) = json_call(&env, "GET", &format!("/api/users/{ada}/machine"), "").await;
    assert_eq!(view["host"].as_str(), Some("a"), "{view}");
    write(&env.a, &m.label, "/home/user/notes.txt", "version 2");
    let certs_before = env.app.db.machine_pins(&m.id);
    assert!(!certs_before.is_empty());

    // Host a stops answering. For a while it is only failing: nothing is taken for gone.
    env.a.w().down = true;
    let r = reconcile(&env).await;
    assert_eq!(r["hostsDown"].as_u64(), Some(0), "{r}");
    assert_eq!(env.app.db.machine(&m.id).unwrap().state, State::Running);
    assert!(events(&env, "machine.lost").await.is_empty(), "silence isn't loss");
    assert!(events(&env, "machine.host_down").await.is_empty());

    // After INCUS_HOST_DOWN_MINUTES it is down: audited and alerted once, and new
    // machines go elsewhere.
    env.app.db.machine_host_failing_backdate("a", DOWN_MS);
    let r = reconcile(&env).await;
    assert_eq!(r["hostsDown"].as_u64(), Some(1), "{r}");
    reconcile(&env).await;
    let down = events(&env, "machine.host_down").await;
    assert_eq!(down.len(), 1, "{down:?}");
    assert_eq!((down[0]["targetType"].as_str(), down[0]["targetId"].as_str(), down[0]["details"]["machines"].as_u64()), (Some("host"), Some("a"), Some(4)));
    let alert = mail_with(&mail, "Incus host a isn't answering").await;
    assert!(alert.body.contains("botctl machine host recover a"), "{}", alert.body);
    // A create a may have made isn't sent again elsewhere while a is down.
    let mut e = env.app.db.machine(&ed.id).unwrap();
    (e.state, e.provider_id, e.create_sent_at) = (State::Pending, None, Some(crate::db::now()));
    assert!(env.app.db.save_machine(&e, State::Running));
    reconcile(&env).await;
    let e = env.app.db.machine(&ed.id).unwrap();
    assert_eq!((e.state, e.provider_id.as_deref()), (State::Pending, None));
    assert!(e.last_error.as_deref().unwrap().contains("may have reached Incus host a"), "{:?}", e.last_error);
    assert!(env.b.instance(&ed.label).is_none(), "no second copy on b");
    let (cid, _) = user_with(env.port, &env.admin, "cy@example.com", "member").await;
    let (code, c) = json_call(&env, "POST", &format!("/api/users/{cid}/machine"), "").await;
    assert_eq!(code, 202, "{c}");
    assert!(c["providerId"].as_str().unwrap().starts_with("b/"), "{c}");
    let (_, rec) = json_call(&env, "GET", "/api/machines/recovery", "").await;
    assert_eq!(rec["hosts"][0]["state"].as_str(), Some("down"), "{rec}");
    let mine = rec["machines"].as_array().unwrap().iter().find(|v| v["machineId"] == m.id.as_str()).unwrap();
    assert_eq!(mine["host"].as_str(), Some("a"));

    // Down isn't lost: a restore elsewhere would leave two copies if it came back.
    let path = format!("/api/users/{ada}/machine/restore");
    let (code, e) = json_call(&env, "POST", &path, &json!({ "backupId": b.id, "host": "b" }).to_string()).await;
    assert!(code == 409 && e["error"].as_str().unwrap().contains("declare it lost"), "{e}");
    let (code, e) = json_call(&env, "POST", &path, &json!({ "backupId": b.id }).to_string()).await;
    assert!(code == 409 && e["error"].as_str().unwrap().contains("is down"), "{e}");
    let (code, e) = json_call(&env, "POST", "/api/machines/hosts/a/recover", &json!({ "to": "a" }).to_string()).await;
    assert_eq!(code, 400, "{e}");
    let (code, _) = json_call(&env, "POST", "/api/machines/hosts/a/recover", &json!({ "force": true }).to_string()).await;
    assert!((400..500).contains(&code), "unknown fields are refused: {code}");
    let (code, e) = json_call(&env, "POST", "/api/machines/hosts/nope/recover", "{}").await;
    assert_eq!(code, 404, "{e}");

    // Declared lost: certificates revoked, ada's machine restored onto b, bea's (no
    // backup) in error.
    env.b.w().addresses.insert(format!("{}-restore", m.label), "127.0.0.1".into());
    let (code, out) = json_call(&env, "POST", "/api/machines/hosts/a/recover", "{}").await;
    assert_eq!(code, 202, "{out}");
    assert_eq!((out["to"].as_str(), &out["toHosts"], out["declaredLost"].as_bool()), (None, &json!(["b"]), Some(true)), "{out}");
    assert_eq!((out["restoring"].as_array().unwrap().len(), out["unrestorable"][0]["userId"].as_str()), (1, Some(bea.as_str())), "{out}");
    assert_eq!(out["skipped"][0]["userId"].as_str(), Some(dee.as_str()), "{out}");
    assert!(env.app.db.machine_pins(&d.id).is_empty(), "revoked though its restore was underway");
    let rid = out["restoring"][0]["restore"]["id"].as_str().unwrap().to_string();
    let r = settled(&env, &rid).await;
    assert_eq!(r.state, "enrolling", "{:?}", r.error);
    assert_eq!((r.from_host.as_deref(), r.to_host.as_deref(), r.reason.as_deref()), (Some("a"), Some("b"), Some("host_lost")));
    let mm = env.app.db.machine(&m.id).unwrap();
    assert_eq!(mm.provider_id.as_deref(), Some(format!("b/{}", m.label).as_str()), "its record names its new host");
    assert_eq!(mm.state, State::Running);
    let i = env.b.instance(&m.label).unwrap();
    assert_eq!((i.status.as_str(), read(&env.b, &m.label, "/home/user/notes.txt").as_deref()), ("Running", Some("version 1")));
    assert!(env.b.instance(&format!("{}-restore", m.label)).is_none());
    assert_eq!(read(&env.b, &m.label, IDENTITY_PATH), None, "the backup's identity isn't trusted again");
    assert_eq!(i.body["devices"]["eth0"]["security.acls"], "superbot-fw", "behind the firewall on its new host");
    assert!(env.b.w().acls.contains_key("superbot-fw"));
    assert!(!i.body.to_string().contains("sbe_"), "no token in the provider's config");
    assert!(env.app.db.machine_pins(&m.id).is_empty(), "the old certificates are revoked");
    let revoked = events(&env, "machine.cert_revoked").await;
    assert!(revoked.iter().any(|e| e["targetId"] == m.id.as_str() && e["details"]["reason"] == "host_lost"), "{revoked:?}");
    let lost = events(&env, "machine.host_lost").await;
    assert_eq!((lost.len(), lost[0]["details"]["placement"].as_str()), (1, Some("fill")), "{lost:?}");
    let requested = events(&env, "machine.restore_requested").await;
    assert_eq!((requested[0]["details"]["fromHost"].as_str(), requested[0]["details"]["reason"].as_str()), (Some("a"), Some("host_lost")), "{requested:?}");
    let alert = mail_with(&mail, "Incus host a was declared lost").await;
    assert!(alert.body.contains("1 machines are being restored onto b"), "{}", alert.body);
    let nn = env.app.db.machine(&n.id).unwrap();
    assert_eq!(nn.state, State::Error);
    assert!(nn.last_error.as_deref().unwrap().contains("no off-host backup"), "{:?}", nn.last_error);
    let gone = events(&env, "machine.lost").await;
    assert_eq!((gone.len(), gone[0]["details"]["reason"].as_str(), gone[0]["targetId"].as_str()), (1, Some("host_lost"), Some(n.id.as_str())), "{gone:?}");
    assert!(env.app.db.assign_machine(&m.id, None));
    assert_eq!(env.cp.route(&env.app, &ada).err().map(|r| r.reason()), Some("machine_restoring"), "Bots wait until it enrolls");

    // Its agent enrolls with the fresh token: done, and timed against the RTO.
    enroll_again(&env, &env.b, &mm).await;
    let r = env.app.db.machine_restore(&rid).unwrap();
    assert_eq!(r.state, "done");
    assert!(r.duration_ms.is_some() && r.rto_ms.is_some());
    let pins = env.app.db.machine_pins(&m.id);
    assert!(pins.len() == 1 && !certs_before.contains(&pins[0]), "a new certificate");
    assert!(env.cp.route(&env.app, &ada).is_ok());
    let restored = events(&env, "machine.restored").await;
    assert_eq!((restored[0]["details"]["fromHost"].as_str(), restored[0]["details"]["toHost"].as_str()), (Some("a"), Some("b")), "{restored:?}");
    let (_, rec) = json_call(&env, "GET", "/api/machines/recovery", "").await;
    let mine = rec["machines"].as_array().unwrap().iter().find(|v| v["machineId"] == m.id.as_str()).unwrap();
    assert_eq!((mine["host"].as_str(), mine["lastRestore"]["toHost"].as_str()), (Some("b"), Some("b")), "{mine}");
    assert_eq!(back_up(&env, &ada).await.machine_id, m.id, "backed up on its new host");

    // A lost host is never called again, even if it comes back: its containers
    // would be second copies.
    env.a.w().down = false;
    let before = env.a.w().calls.len();
    reconcile(&env).await;
    let (code, h) = json_call(&env, "GET", "/api/machines/hosts?check=true", "").await;
    assert_eq!(code, 200);
    assert_eq!((h["hosts"][0]["state"].as_str(), h["hosts"][0]["machines"].as_u64()), (Some("lost"), Some(2)), "{h}");
    let e = env.app.db.machine(&ed.id).unwrap();
    assert!(e.provider_id.as_deref().is_some_and(|p| p.starts_with("b/")), "made on b once a is lost: {e:?}");
    let (code, _) = json_call(&env, "DELETE", &format!("/api/users/{bea}/machine"), "").await;
    assert_eq!(code, 200, "a machine on a lost host is destroyed without it");
    assert_eq!(env.app.db.machine(&n.id).unwrap().state, State::Destroyed);
    assert_eq!(env.a.w().calls.len(), before, "nothing went to the lost host");
    assert!(events(&env, "machine.host_up").await.is_empty());

    // Again: nothing left to do, and nothing announced twice.
    let (code, out) = json_call(&env, "POST", "/api/machines/hosts/a/recover", "{}").await;
    assert_eq!((code, out["declaredLost"].as_bool(), out["restoring"].as_array().map(Vec::len)), (202, Some(false), Some(0)), "{out}");
    assert_eq!(events(&env, "machine.host_lost").await.len(), 1);
}

#[tokio::test]
async fn a_host_that_comes_back_is_up_and_machines_move_between_hosts_that_are_up() {
    let env = serve().await;
    let (ada, m) = machine(&env, "ada@example.com", true).await;

    // Down for a while, then back: up again, audited, and not recoverable while it answers.
    env.a.w().down = true;
    reconcile(&env).await;
    env.app.db.machine_host_failing_backdate("a", DOWN_MS);
    reconcile(&env).await;
    env.a.w().down = false;
    let r = reconcile(&env).await;
    assert_eq!(r["hostsDown"].as_u64(), Some(0), "{r}");
    let up = events(&env, "machine.host_up").await;
    assert_eq!((up.len(), up[0]["targetId"].as_str()), (1, Some("a")), "{up:?}");
    let (code, e) = json_call(&env, "POST", "/api/machines/hosts/a/recover", "{}").await;
    assert!(code == 409 && e["error"].as_str().unwrap().contains("answers"), "{e}");
    assert_eq!(env.app.db.machine_host("a").unwrap().state, "up");

    // Moving one machine while both hosts answer: its old container is deleted.
    let b = back_up(&env, &ada).await;
    let path = format!("/api/users/{ada}/machine/restore");
    let (code, e) = json_call(&env, "POST", &path, &json!({ "backupId": b.id, "host": "nope" }).to_string()).await;
    assert_eq!(code, 400, "{e}");
    // It kept an older firewall (from before a label prefix change) that b doesn't have.
    let old = env.a.w().acls["superbot-fw"].clone();
    env.a.w().acls.insert("old-fw".into(), old);
    env.app.db.set_machine_firewall_id(&m.id, Some("old-fw"));
    let (code, r) = json_call(&env, "POST", &path, &json!({ "backupId": b.id, "host": "b" }).to_string()).await;
    assert_eq!(code, 202, "{r}");
    let r = settled(&env, r["restore"]["id"].as_str().unwrap()).await;
    assert_eq!((r.state.as_str(), r.reason.as_deref()), ("enrolling", None), "{:?}", r.error);
    assert!(env.a.instance(&m.label).is_none(), "no second copy on the old host");
    assert_eq!(read(&env.b, &m.label, "/home/user/notes.txt").as_deref(), Some("version 1"));
    let mm = env.app.db.machine(&m.id).unwrap();
    assert_eq!(mm.provider_id.as_deref(), Some(format!("b/{}", m.label).as_str()));
    assert_eq!((mm.firewall_id.as_deref(), env.b.instance(&m.label).unwrap().body["devices"]["eth0"]["security.acls"].as_str()), (Some("superbot-fw"), Some("superbot-fw")), "today's firewall on b");
    enroll_again(&env, &env.b, &mm).await;
    assert_eq!(env.app.db.machine_last_restore(&m.id).unwrap().state, "done");
}

#[tokio::test]
async fn hosts_are_pinned_and_ids_from_before_name_the_first_host() {
    let env = serve().await;
    let (_, m) = machine(&env, "ada@example.com", false).await;
    env.app.db.set_machine_provider_id(&m.id, &m.label);
    assert_eq!(hosts::load(&env.app, &env.cp).unwrap(), 1);
    assert_eq!(env.app.db.machine(&m.id).unwrap().provider_id.as_deref(), Some(format!("a/{}", m.label).as_str()));
    assert_eq!(hosts::load(&env.app, &env.cp).unwrap(), 0);

    // Another host under a known name is refused, so its machines aren't taken for its.
    let other = StandIn::start().await;
    let fleet = Fleet::new(vec![host("a", &other, env.mport), host("b", &env.b, env.mport)], DOWN_MS);
    let cp = ControlPlane::for_tests(Arc::new(fleet));
    let e = hosts::load(&env.app, &cp).unwrap_err();
    assert!(e.contains("Incus host a") && e.contains("certificate"), "{e}");

    // A host lost before stays lost after a restart.
    assert!(env.app.db.machine_host_lost("b", None));
    hosts::load(&env.app, &env.cp).unwrap();
    use crate::machines::provider::HostStatus;
    assert_eq!(env.cp.hosts().unwrap().status("b"), Some(HostStatus::Lost));
    assert_eq!(env.cp.hosts().unwrap().placement().as_deref(), Some("a"));
}
