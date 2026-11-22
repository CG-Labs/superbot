//! Off-host machine backups and restores (ADR 0071), end to end on loopback: the real
//! router, botd's machine port, the real agent, the Incus provider talking mutual TLS
//! to a stand-in for the Incus API, and a stand-in for an S3-compatible store.

use crate::machines::agent::{self, Agent, Config};
use crate::machines::backup::{self, IDENTITY_PATH, Offsite, Retention, Settings};
use crate::machines::enroll::{self, Enrollment};
use crate::machines::firewall;
use crate::machines::incus::Incus;
use crate::machines::incus_standin::StandIn;
use crate::machines::s3_standin;
use crate::machines::{ControlPlane, State};
use crate::tests::{audit_list, call};
use crate::users_http_tests::{parse, user_with};
use crate::*;
use tokio::net::TcpListener;
use zeroize::Zeroizing;

struct Env {
    port: u16,
    app: AppState,
    admin: String,
    incus: StandIn,
    s3: s3_standin::StandIn,
    cp: Arc<ControlPlane>,
    e: Arc<Enrollment>,
    agent_listener: Option<TcpListener>,
}

const AGENT: &str = "stand-in for the superbot-machine binary";
const DAY_MS: i64 = 86_400_000;

/// botd making containers on the stand-in, with enrollment, the firewall, and
/// backups to the S3 stand-in on, encrypted to `recipients`.
async fn serve(recipients: Vec<age::x25519::Recipient>) -> Env {
    let machine_listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let agent_listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let (mport, aport) = (machine_listener.local_addr().unwrap().port(), agent_listener.local_addr().unwrap().port());
    let incus = StandIn::start().await;
    incus.w().projects.insert("superbot".into(), json!({ "restricted": "true", "restricted.backups": "allow" }));
    let s3 = s3_standin::StandIn::start().await;
    let p = Incus::new(incus.settings(Some(("127.0.0.1".parse().unwrap(), mport))), incus.credentials()).unwrap();
    let mut cp = ControlPlane::for_tests(Arc::new(p));
    cp.regions = vec!["local".into()];
    cp.routing = crate::machines::route::Routing::On;
    let e = cp.enroll_with(Enrollment::for_tests(9, mport, aport).with_agent(AGENT.as_bytes())).unwrap();
    cp.firewall_with(firewall::Settings { sources: Vec::new(), ssh: Vec::new() }).unwrap();
    let s = Settings { retention: Retention::retention("7,pro=30").unwrap(), ..Settings::with(s3.settings(), "t/", recipients) };
    cp.offsite = Some(Arc::new(Offsite::new(s).unwrap()));
    let cp = Arc::new(cp);
    let c = cp.clone();
    let (port, app, owner, _) = crate::tests::serve_app_with(move |a| a.machines = c).await;
    tokio::spawn(enroll::serve(machine_listener, app.clone(), e.clone(), None));
    let (_, admin) = user_with(port, &owner, "ops@example.com", "admin").await;
    Env { port, app, admin, incus, s3, cp, e, agent_listener: Some(agent_listener) }
}

async fn json_call(env: &Env, method: &str, path: &str, body: &str) -> (u16, Value) {
    let (code, body) = call(env.port, method, path, &env.admin, body).await;
    (code, parse(&body))
}

async fn events(env: &Env, action: &str) -> Vec<Value> {
    let (code, body) = call(env.port, "GET", &format!("/api/audit?action={action}&limit=200"), &env.admin, "").await;
    assert_eq!(code, 200, "{body}");
    audit_list(&body)
}

async fn reconcile(env: &Env) {
    let (code, r) = json_call(env, "POST", "/api/machines/reconcile", "").await;
    assert_eq!(code, 200, "{r}");
}

fn config(env: &Env, machine_id: &str, token: &str) -> Config {
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

/// A member with a running container whose agent enrolled, with a file of theirs on
/// its disk: their id and the machine.
async fn enrolled(env: &mut Env, email: &str) -> (String, crate::db::Machine) {
    let (uid, _) = user_with(env.port, &env.admin, email, "member").await;
    let (code, m) = json_call(env, "POST", &format!("/api/users/{uid}/machine"), "").await;
    assert_eq!(code, 202, "{m}");
    let m = env.app.db.machine(m["id"].as_str().unwrap()).unwrap();
    env.incus.w().instances.get_mut(&m.label).unwrap().ip = "127.0.0.1".into();
    reconcile(env).await;
    let user_data = env.incus.instance(&m.label).unwrap().body["config"]["cloud-init.user-data"].as_str().unwrap().to_string();
    let at = user_data.find("content: \"sbe_").unwrap() + "content: \"".len();
    let token = user_data[at..].split('"').next().unwrap().to_string();
    let id = agent::enroll(&config(env, &m.id, &token)).await.unwrap();
    let agent = Agent::new(config(env, &m.id, &token), id).unwrap();
    tokio::spawn(agent::serve(env.agent_listener.take().unwrap(), agent));
    reconcile(env).await;
    let m = env.app.db.machine(&m.id).unwrap();
    assert_eq!(m.enrollment, "enrolled");
    assert!(env.incus.instance(&m.label).unwrap().body["config"].get("cloud-init.user-data").is_none(), "token cleared before any backup");
    write(env, &m.label, "/home/user/notes.txt", "version 1");
    write(env, &m.label, IDENTITY_PATH, "the old agent's key");
    (uid, m)
}

fn write(env: &Env, label: &str, path: &str, content: &str) {
    env.incus.w().instances.get_mut(label).unwrap().files.insert(path.into(), (content.as_bytes().to_vec(), "0644".into()));
}

fn read(env: &Env, label: &str, path: &str) -> Option<String> {
    env.incus.instance(label)?.files.get(path).map(|(c, _)| String::from_utf8_lossy(c).into_owned())
}

/// Polls until `f` holds, or fails the test after ten seconds.
async fn until(what: &str, mut f: impl FnMut() -> bool) {
    for _ in 0..200 {
        if f() {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    panic!("timed out waiting for {what}");
}

/// Backs the machine up through the API and waits for it to finish.
async fn back_up(env: &Env, uid: &str) -> crate::db::MachineBackup {
    let (code, b) = json_call(env, "POST", &format!("/api/users/{uid}/machine/backups"), "").await;
    assert_eq!((code, b["state"].as_str()), (202, Some("running")), "{b}");
    let id = b["id"].as_str().unwrap().to_string();
    until("the backup", || env.app.db.machine_backup(&id).is_some_and(|b| b.state != "running")).await;
    env.app.db.machine_backup(&id).unwrap()
}

async fn restore_until(env: &Env, uid: &str, body: Value, want: &str) -> crate::db::MachineRestore {
    let (code, r) = json_call(env, "POST", &format!("/api/users/{uid}/machine/restore"), &body.to_string()).await;
    assert_eq!((code, r["restore"]["state"].as_str()), (202, Some("importing")), "{r}");
    let id = r["restore"]["id"].as_str().unwrap().to_string();
    until(want, || env.app.db.machine_restore(&id).is_some_and(|r| !matches!(r.state.as_str(), "importing" | "replacing"))).await;
    // It's enrolling before the restored machine boots; the restore holds the lock until then.
    drop(env.app.control_plane.get().unwrap().lock_ops().await);
    let r = env.app.db.machine_restore(&id).unwrap();
    assert_eq!(r.state, want, "{:?}", r.error);
    // A restore is "enrolling" just before the copy boots, so the agent can enroll as
    // soon as it's up; wait for the boot too.
    if want == "enrolling" {
        let label = env.app.db.machine(&r.machine_id).unwrap().label;
        until("the copy to boot", || env.incus.instance(&label).is_some_and(|i| i.status == "Running")).await;
    }
    r
}

#[tokio::test]
async fn a_machine_is_backed_up_off_host_and_restored_to_enroll_anew() {
    let mut env = serve(Vec::new()).await;
    let (uid, m) = enrolled(&mut env, "ada@example.com").await;

    // Exported without snapshots, sent to the store with a manifest, and the
    // provider's copy deleted.
    let b = back_up(&env, &uid).await;
    assert_eq!(b.state, "done", "{:?}", b.error);
    assert!(!b.encrypted);
    assert_eq!(b.object_key, format!("t/machines/{}/{}.incus", m.id, b.id));
    assert_eq!(env.s3.keys(), vec![format!("t/machines/{}/{}.incus", m.id, b.id), format!("t/machines/{}/{}.json", m.id, b.id)]);
    let made = env.incus.calls("POST", &format!("/1.0/instances/{}/backups", m.label));
    assert_eq!(made.len(), 1);
    assert_eq!((made[0].body["instance_only"].as_bool(), made[0].body["optimized_storage"].as_bool()), (Some(true), Some(false)));
    assert!(made[0].body["expires_at"].as_str().is_some(), "expires by itself if botd stops");
    assert!(env.incus.w().backups.is_empty(), "deleted at the provider once sent");
    let stored = env.s3.w().objects[&b.object_key].clone();
    assert_eq!(b.size, Some(stored.len() as i64));
    assert!(String::from_utf8_lossy(&stored).contains("version 1"));
    let manifest: Value = serde_json::from_slice(&env.s3.w().objects[&format!("t/machines/{}/{}.json", m.id, b.id)]).unwrap();
    assert_eq!((manifest["format"].as_str(), manifest["machineId"].as_str(), manifest["sha256"].as_str()), (Some("superbot-machine-backup/1"), Some(m.id.as_str()), b.sha256.as_deref()));
    assert_eq!(b.expires_at, Some(b.created_at + 7 * DAY_MS), "the starter tier keeps the default");
    let created = events(&env, "machine.backup_created").await;
    assert_eq!((created.len(), created[0]["targetId"].as_str()), (1, Some(m.id.as_str())), "{created:?}");
    let (_, view) = json_call(&env, "GET", &format!("/api/users/{uid}/machine"), "").await;
    assert_eq!(view["lastBackup"]["id"].as_str(), Some(b.id.as_str()), "{view}");
    let (_, list) = json_call(&env, "GET", &format!("/api/users/{uid}/machine/backups"), "").await;
    assert_eq!(list["backups"][0]["id"].as_str(), Some(b.id.as_str()), "{list}");
    let (_, all) = json_call(&env, "GET", "/api/machines/backups", "").await;
    assert_eq!((all["settings"]["bucket"].as_str(), all["settings"]["encrypted"].as_bool()), (Some("backups"), Some(false)), "{all}");
    assert!(!all.to_string().contains(s3_standin::SECRET), "no credentials in the view");

    // Work since then, and a token in the old container's config, are both gone after.
    write(&env, &m.label, "/home/user/notes.txt", "version 2");
    let certs_before = env.app.db.machine_pins(&m.id);
    assert!(!certs_before.is_empty());
    let r = restore_until(&env, &uid, json!({ "backupId": b.id }), "enrolling").await;
    let i = env.incus.instance(&m.label).unwrap();
    assert!(env.incus.instance(&format!("{}-restore", m.label)).is_none(), "the copy took the old one's place");
    assert_eq!((i.status.as_str(), read(&env, &m.label, "/home/user/notes.txt").as_deref()), ("Running", Some("version 1")));
    assert_eq!(read(&env, &m.label, IDENTITY_PATH), None, "the backup's identity isn't trusted again");
    let token = read(&env, &m.label, "/etc/superbot/enroll-token").expect("a fresh token on its disk");
    assert!(token.starts_with("sbe_"), "{token}");
    assert_eq!(i.files["/etc/superbot/enroll-token"].1, "0600");
    let settings = read(&env, &m.label, "/etc/superbot/machine.env").unwrap();
    assert!(settings.contains(&format!("SUPERBOT_MACHINE_ID={}", m.id)) && settings.contains(&env.e.url), "{settings}");
    assert_eq!(read(&env, &m.label, "/etc/superbot/ca.pem").as_deref(), Some(env.e.ca_pem()));
    assert!(!i.body.to_string().contains("sbe_"), "no token in the provider's config (ADR 0067)");
    assert!(i.body["config"].get("snapshots.schedule").is_none(), "no snapshots until it enrolls");
    assert_eq!((i.body["config"]["security.privileged"].as_str(), i.body["config"]["security.idmap.isolated"].as_str()), (Some("false"), Some("true")));
    assert_eq!(i.body["devices"]["eth0"]["security.acls"], "superbot-fw", "today's firewall, not the backup's");
    assert!(env.app.db.machine_pins(&m.id).is_empty(), "the old certificates are revoked");
    assert_eq!(env.app.db.machine_tokens_unused(&m.id), 1, "only the fresh token");
    let revoked = events(&env, "machine.cert_revoked").await;
    assert_eq!(revoked[0]["details"]["reason"].as_str(), Some("restored"), "{revoked:?}");
    let issued = events(&env, "machine.enroll_token_issued").await;
    assert!(issued.iter().any(|e| e["details"]["via"] == "restore"), "{issued:?}");
    assert_eq!(events(&env, "machine.restore_requested").await.len(), 1);
    assert_eq!(env.app.db.machine(&m.id).unwrap().state, State::Running);

    // Bots wait, and nothing else starts, until it has enrolled again.
    assert!(env.app.db.assign_machine(&m.id, None));
    assert_eq!(env.cp.route(&env.app.db, &uid).err().map(|r| r.reason()), Some("machine_restoring"));
    let (code, again) = json_call(&env, "POST", &format!("/api/users/{uid}/machine/restore"), &json!({ "backupId": b.id }).to_string()).await;
    assert_eq!(code, 409, "{again}");
    let (code, busy) = json_call(&env, "POST", &format!("/api/users/{uid}/machine/backups"), "").await;
    assert_eq!(code, 409, "{busy}");
    let (code, rebuild) = json_call(&env, "POST", &format!("/api/users/{uid}/machine/rebuild"), "").await;
    assert_eq!(code, 409, "{rebuild}");

    // Its agent enrolls with the fresh token: the restore is done.
    let cfg = config(&env, &m.id, &token);
    agent::enroll(&cfg).await.unwrap();
    backup::follow_up(&env.app, &env.cp).await;
    let r = env.app.db.machine_restore(&r.id).unwrap();
    assert_eq!(r.state, "done");
    let pins = env.app.db.machine_pins(&m.id);
    assert_eq!(pins.len(), 1);
    assert!(!certs_before.contains(&pins[0]), "a new certificate");
    let restored = events(&env, "machine.restored").await;
    assert_eq!(restored.len(), 1, "{restored:?}");
    assert!(env.cp.route(&env.app.db, &uid).is_ok());
    let (_, status) = json_call(&env, "GET", &format!("/api/users/{uid}/machine/restore"), "").await;
    assert_eq!(status["restore"]["state"].as_str(), Some("done"), "{status}");
}

#[tokio::test]
async fn encrypted_backups_need_the_identity_and_a_failed_restore_leaves_the_machine() {
    let id = age::x25519::Identity::generate();
    let mut env = serve(vec![id.to_public()]).await;
    let (uid, m) = enrolled(&mut env, "ada@example.com").await;
    let b = back_up(&env, &uid).await;
    assert_eq!((b.state.as_str(), b.encrypted), ("done", true), "{:?}", b.error);
    assert!(b.object_key.ends_with(".incus.age"), "{}", b.object_key);
    let stored = env.s3.w().objects[&b.object_key].clone();
    assert!(stored.starts_with(b"age-encryption.org/v1"));
    assert!(!String::from_utf8_lossy(&stored).contains("version 1"), "nothing readable in the store");
    write(&env, &m.label, "/home/user/notes.txt", "version 2");

    // An identity is needed, and must be an age key; neither is echoed.
    let path = format!("/api/users/{uid}/machine/restore");
    let (code, e) = json_call(&env, "POST", &path, &json!({ "backupId": b.id }).to_string()).await;
    assert_eq!(code, 400, "{e}");
    let (code, e) = json_call(&env, "POST", &path, &json!({ "backupId": b.id, "identity": "AGE-SECRET-KEY-1SECRETISH" }).to_string()).await;
    assert!(code == 400 && !e.to_string().contains("SECRETISH"), "{e}");
    let (code, e) = json_call(&env, "POST", &path, &json!({ "backupId": "bnope" }).to_string()).await;
    assert_eq!(code, 404, "{e}");

    // The wrong key: the restore fails, the copy goes, and the machine is untouched.
    use age::secrecy::ExposeSecret;
    let wrong = age::x25519::Identity::generate().to_string().expose_secret().to_string();
    let r = restore_until(&env, &uid, json!({ "backupId": b.id, "identity": wrong }), "failed").await;
    assert!(r.error.as_deref().is_some_and(|e| e.contains("decrypting")), "{:?}", r.error);
    assert!(env.incus.instance(&format!("{}-restore", m.label)).is_none());
    assert_eq!(read(&env, &m.label, "/home/user/notes.txt").as_deref(), Some("version 2"));
    assert_eq!(read(&env, &m.label, IDENTITY_PATH).as_deref(), Some("the old agent's key"));
    assert!(!env.app.db.machine_pins(&m.id).is_empty(), "its certificate is kept");
    let failed = events(&env, "machine.restore_failed").await;
    assert_eq!(failed.len(), 1, "{failed:?}");
    assert!(!json!(failed).to_string().contains(&wrong));

    // A restore failing at the swap, after its token was minted, leaves the machine's
    // enrollment deadline as it was, so its backups go on.
    let right = id.to_string().expose_secret().to_string();
    let mut mm = env.app.db.machine(&m.id).unwrap();
    let fw = mm.firewall_id.take();
    env.app.db.save_machine(&mm, mm.state);
    let r = restore_until(&env, &uid, json!({ "backupId": b.id, "identity": right }), "failed").await;
    assert!(r.error.as_deref().is_some_and(|e| e.contains("firewall")), "{:?}", r.error);
    let mm = env.app.db.machine(&m.id).unwrap();
    assert_eq!((mm.enroll_by, mm.enroll_overdue_at), (None, None));
    assert_eq!(env.app.db.machine_tokens_unused(&m.id), 0);
    assert!(env.incus.instance(&format!("{}-restore", m.label)).is_none());
    assert_eq!(read(&env, &m.label, "/home/user/notes.txt").as_deref(), Some("version 2"));
    assert_eq!(back_up(&env, &uid).await.state, "done");
    let mut mm = env.app.db.machine(&m.id).unwrap();
    mm.firewall_id = fw;
    env.app.db.save_machine(&mm, mm.state);

    // The right one.
    restore_until(&env, &uid, json!({ "backupId": b.id, "identity": right }), "enrolling").await;
    assert_eq!(read(&env, &m.label, "/home/user/notes.txt").as_deref(), Some("version 1"));
    assert_eq!(read(&env, &m.label, IDENTITY_PATH), None);
    for e in ["machine.restore_requested", "machine.restore_failed", "machine.enroll_token_issued"] {
        assert!(!json!(events(&env, e).await).to_string().contains("AGE-SECRET-KEY"), "{e}");
    }
}

#[tokio::test]
async fn the_schedule_backs_up_only_enrolled_machines_and_keeps_the_newest() {
    let mut env = serve(Vec::new()).await;
    // Not yet enrolled: the provider still holds its token, so it isn't backed up.
    let (other, _) = user_with(env.port, &env.admin, "bea@example.com", "member").await;
    let (code, pending) = json_call(&env, "POST", &format!("/api/users/{other}/machine"), "").await;
    assert_eq!(code, 202, "{pending}");
    let (uid, m) = enrolled(&mut env, "ada@example.com").await;
    let (code, e) = json_call(&env, "POST", &format!("/api/users/{other}/machine/backups"), "").await;
    assert_eq!(code, 409, "{e}");

    // A restricted project blocks backups unless they're allowed; botd says how.
    env.incus.w().projects.insert("superbot".into(), json!({ "restricted": "true" }));
    let blocked = back_up(&env, &uid).await;
    assert!(blocked.state == "failed" && blocked.error.as_deref().is_some_and(|e| e.contains("restricted.backups=allow")), "{:?}", blocked.error);
    assert!(env.incus.w().backups.is_empty());
    env.incus.w().projects.insert("superbot".into(), json!({ "restricted": "true", "restricted.backups": "allow" }));
    env.app.db.machine_backup_backdate(&blocked.id, DAY_MS);

    assert_eq!(backup::pass(&env.app, &env.cp).await, 1, "only the enrolled one");
    assert_eq!(backup::pass(&env.app, &env.cp).await, 0, "not due again yet");
    let first = env.app.db.machine_last_backup(&m.id).unwrap();
    assert_eq!(first.created_by.as_deref(), Some("schedule"));

    // A store that refuses: failed, audited, and tried again after an hour, not at once.
    env.app.db.machine_backup_backdate(&first.id, DAY_MS);
    env.s3.w().fail = Some(("PUT".into(), 503));
    assert_eq!(backup::pass(&env.app, &env.cp).await, 0);
    let failed = env.app.db.machine_backups(&m.id).into_iter().find(|b| b.state == "failed").unwrap();
    assert_eq!(events(&env, "machine.backup_failed").await.len(), 2, "the blocked one, then this");
    assert!(env.incus.w().backups.is_empty(), "the provider's copy is deleted anyway");
    assert_eq!(backup::pass(&env.app, &env.cp).await, 0, "not straight away");
    env.app.db.machine_backup_backdate(&failed.id, 3_600_000);
    assert_eq!(backup::pass(&env.app, &env.cp).await, 1, "an hour later");
    let second = env.app.db.machine_last_backup(&m.id).unwrap();
    assert_ne!(second.id, first.id);

    // Past their retention, backups go from the store, but never a live machine's newest.
    env.app.db.machine_backup_backdate(&first.id, 30 * DAY_MS);
    env.app.db.machine_backup_backdate(&second.id, 30 * DAY_MS);
    assert_eq!(backup::prune(&env.app, env.cp.offsite.as_deref().unwrap()).await, 1);
    assert_eq!(env.app.db.machine_backup(&first.id).unwrap().state, "deleted");
    assert_eq!(env.app.db.machine_backup(&second.id).unwrap().state, "done");
    assert!(env.s3.keys().iter().all(|k| !k.contains(&first.id)), "{:?}", env.s3.keys());
    assert!(env.s3.keys().iter().any(|k| k.contains(&second.id)));
    let deleted = events(&env, "machine.backup_deleted").await;
    assert_eq!((deleted.len(), deleted[0]["details"]["reason"].as_str()), (1, Some("retention")), "{deleted:?}");

    // Once the machine is destroyed, its last backup goes too when it expires.
    let (code, _) = json_call(&env, "DELETE", &format!("/api/users/{uid}/machine"), "").await;
    assert_eq!(code, 200);
    assert_eq!(backup::prune(&env.app, env.cp.offsite.as_deref().unwrap()).await, 1);
    assert!(env.s3.keys().is_empty(), "{:?}", env.s3.keys());
}

#[tokio::test]
async fn a_destroyed_machines_backups_and_restore_copy_are_deleted_on_request() {
    let mut env = serve(Vec::new()).await;
    let (uid, m) = enrolled(&mut env, "ada@example.com").await;
    let (first, second) = (back_up(&env, &uid).await, back_up(&env, &uid).await);
    assert_eq!((first.state.as_str(), second.state.as_str()), ("done", "done"));
    // A restore that stopped part way left its copy of the disk beside the container.
    let copy = format!("{}-restore", m.label);
    let i = env.incus.instance(&m.label).unwrap();
    env.incus.w().instances.insert(copy.clone(), i);
    let n = crate::db::NewMachineRestore { id: "rleft", machine: &m, backup_id: &first.id, by: None, rto_ms: None, from_host: None, to_host: None, reason: None };
    env.app.db.machine_restore_start(&n).unwrap();
    assert!(env.app.db.machine_restore_move("rleft", &["importing"], "failed", Some("botd stopped mid-restore")));

    // Not while the machine exists: its backups are how it comes back.
    let path = format!("/api/machines/{}/backups", m.id);
    let (code, e) = json_call(&env, "DELETE", &path, "").await;
    assert_eq!(code, 409, "{e}");
    assert_eq!(env.s3.keys().len(), 4);

    let (code, _) = json_call(&env, "DELETE", &format!("/api/users/{uid}/machine"), "").await;
    assert_eq!(code, 200);
    let (code, v) = json_call(&env, "DELETE", &path, "").await;
    assert_eq!(code, 200, "{v}");
    assert_eq!((v["backups"].as_array().map(Vec::len), v["restoreCopies"].as_u64(), v["strays"].as_u64()), (Some(2), Some(1), Some(0)), "{v}");
    assert!(env.s3.keys().is_empty(), "{:?}", env.s3.keys());
    assert!(env.incus.instance(&copy).is_none(), "the restore's copy of the disk is gone too");
    assert!(env.app.db.machine_backups(&m.id).iter().all(|b| b.state == "deleted"));
    let deleted = events(&env, "machine.backup_deleted").await;
    assert!(deleted.len() == 2 && deleted.iter().all(|e| e["details"]["reason"] == "requested" && e["actorKind"] == "user"), "{deleted:?}");
    let (_, all) = json_call(&env, "GET", "/api/machines/backups", "").await;
    assert_eq!(all["backups"].as_array().map(Vec::len), Some(0), "{all}");
}

#[test]
fn backups_are_off_unless_configured_and_need_a_provider_that_exports() {
    let store = crate::secrets::env::EnvStore::fixed(&[("MACHINE_BACKUP_S3_ACCESS_KEY_ID", "AKID"), ("MACHINE_BACKUP_S3_SECRET_ACCESS_KEY", "s3cret-0123")]);
    let on = |k: &str| match k {
        "MACHINE_BACKUP_S3_BUCKET" => "backups".into(),
        "MACHINE_BACKUP_S3_ENDPOINT" => "https://s3.example.com".into(),
        _ => String::new(),
    };
    let e = ControlPlane::from_env(&store, on).err().unwrap();
    assert!(e.contains("needs the control plane"), "{e}");
    let linode = crate::secrets::env::EnvStore::fixed(&[
        ("LINODE_TOKEN", "tok"),
        ("MACHINE_BACKUP_S3_ACCESS_KEY_ID", "AKID"),
        ("MACHINE_BACKUP_S3_SECRET_ACCESS_KEY", "s3cret-0123"),
    ]);
    let e = ControlPlane::from_env(&linode, |k| if k == "MACHINE_REGIONS" { "gb-lon".into() } else { on(k) }).err().unwrap();
    assert!(e.contains("can't be exported"), "{e}");
    let off = ControlPlane::from_env(&linode, |k| if k == "MACHINE_REGIONS" { "gb-lon".into() } else { String::new() }).unwrap();
    assert!(off.offsite.is_none());
    assert!(off.describe().contains("off-host backups off"), "{}", off.describe());
}

/// Alerts by email to ops@example.com through a stand-in SMTP server (ADR 0061).
fn alerts_to(env: &Env, mail: &crate::notify::smtp::fake::Server) {
    let smtp = crate::notify::smtp::Smtp::for_test("127.0.0.1", mail.port, crate::notify::smtp::Tls::None, None, None);
    let _ = env.app.notifier.set(Arc::new(crate::notify::Notifier::new(Some(smtp), Some("https://bots.example.com".into()))));
    let s = crate::notify::Settings {
        email: crate::notify::EmailSettings { enabled: true, to: vec!["ops@example.com".into()], deciders: true },
        ..Default::default()
    };
    crate::notify::save(&env.app.db, &s);
}

async fn mail_with(mail: &crate::notify::smtp::fake::Server, subject: &str) -> crate::notify::smtp::fake::Received {
    let mut found = None;
    until(subject, || {
        found = mail.got.lock().unwrap().iter().find(|m| m.headers.contains(subject)).cloned();
        found.is_some()
    })
    .await;
    found.unwrap()
}

#[tokio::test]
async fn machines_past_their_rpo_are_flagged_alerted_and_cleared_by_a_backup() {
    let mut env = serve(Vec::new()).await;
    let mail = crate::notify::smtp::fake::start(Default::default()).await;
    alerts_to(&env, &mail);
    let (uid, m) = enrolled(&mut env, "ada@example.com").await;
    assert_eq!(m.tier, "starter");
    use crate::machines::recovery;

    // New, with nothing on it yet: within its RPO (26 hours on starter).
    assert_eq!(recovery::watch(&env.app, &env.cp), 0);
    let (code, r) = json_call(&env, "GET", "/api/machines/recovery", "").await;
    assert_eq!(code, 200, "{r}");
    assert_eq!((r["tracked"].as_u64(), r["breaching"].as_u64()), (Some(1), Some(0)), "{r}");
    let starter = r["objectives"].as_array().unwrap().iter().find(|o| o["tier"] == "starter").unwrap().clone();
    assert_eq!((starter["intervalHours"].as_i64(), starter["rpoHours"].as_i64(), starter["rtoMinutes"].as_i64()), (Some(24), Some(26), Some(60)), "{r}");
    assert_eq!(r["machines"][0]["rpoHours"].as_i64(), Some(26), "{r}");

    // 27 hours on with no backup: a breach, audited once and alerted.
    env.app.db.machine_backdate(&m.id, 27 * 3_600_000);
    assert_eq!(recovery::watch(&env.app, &env.cp), 1);
    assert_eq!(recovery::watch(&env.app, &env.cp), 1, "still open");
    let breached = events(&env, "machine.rpo_breached").await;
    assert_eq!(breached.len(), 1, "once, not every check: {breached:?}");
    assert_eq!((breached[0]["targetId"].as_str(), breached[0]["outcome"].as_str(), breached[0]["details"]["rpoHours"].as_i64()), (Some(m.id.as_str()), Some("failure"), Some(26)));
    let got = mail_with(&mail, "ada@example.com's machine has no off-host backup within its RPO").await;
    assert_eq!(got.to, ["ops@example.com"]);
    assert!(got.body.contains("No off-host backup of it yet.") && got.body.contains("https://bots.example.com/console/#machines"), "{}", got.body);
    let mut sent = Vec::new();
    for _ in 0..100 {
        sent = events(&env, "notification.sent").await;
        if !sent.is_empty() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert_eq!((sent[0]["targetId"].as_str(), sent[0]["details"]["event"].as_str()), (Some(m.id.as_str()), Some("machine.rpo_breached")), "{sent:?}");
    let (_, r) = json_call(&env, "GET", "/api/machines/recovery", "").await;
    assert_eq!(r["breaching"].as_u64(), Some(1), "{r}");
    assert!(r["breaches"][0]["endedAt"].is_null() && r["machines"][0]["breach"] == true, "{r}");
    let (_, view) = json_call(&env, "GET", &format!("/api/users/{uid}/machine"), "").await;
    assert_eq!((view["recovery"]["breach"].as_bool(), view["recovery"]["lastBackupAt"].is_null()), (Some(true), true), "{view}");
    // And /metrics shows it (ADR 0089), with the tier but not the machine or its user.
    let metrics = crate::obs::render(&env.app);
    assert_eq!(crate::obs_http_tests::total(&metrics, "superbot_machine_rpo_breaches_open"), 1.0, "{metrics}");
    assert_eq!(crate::obs_http_tests::total(&metrics, "superbot_machines_past_rpo{"), 1.0, "{metrics}");
    assert_eq!(crate::obs_http_tests::total(&metrics, "superbot_machines_rpo_tracked{"), 1.0, "{metrics}");
    assert!(crate::obs_http_tests::total(&metrics, "superbot_machine_backup_age_max_seconds{") >= 27.0 * 3600.0, "{metrics}");
    assert_eq!(crate::obs_http_tests::total(&metrics, r#"superbot_events_total{event="machine.rpo_breached",outcome="failure"}"#), 1.0, "{metrics}");
    assert_eq!(crate::obs_http_tests::total(&metrics, r#"superbot_machines{state="running"}"#), 1.0, "{metrics}");
    assert!(!metrics.contains(&m.id) && !metrics.contains(&uid) && !metrics.contains("ada@"), "{metrics}");

    // A backup ends it.
    let b = back_up(&env, &uid).await;
    assert_eq!(b.state, "done", "{:?}", b.error);
    assert_eq!(recovery::watch(&env.app, &env.cp), 0);
    let recovered = events(&env, "machine.rpo_recovered").await;
    assert_eq!((recovered.len(), recovered[0]["details"]["reason"].as_str()), (1, Some("backed_up")), "{recovered:?}");
    mail_with(&mail, "ada@example.com's machine is back within its RPO").await;
    let (_, r) = json_call(&env, "GET", "/api/machines/recovery", "").await;
    assert_eq!((r["breaching"].as_u64(), r["breaches"][0]["endReason"].as_str()), (Some(0), Some("backed_up")), "{r}");
    assert_eq!(r["machines"][0]["lastBackupAt"].as_i64(), Some(b.created_at), "{r}");
    let metrics = crate::obs::render(&env.app);
    assert_eq!(crate::obs_http_tests::total(&metrics, "superbot_machines_past_rpo{"), 0.0, "{metrics}");
    assert_eq!(crate::obs_http_tests::total(&metrics, "superbot_machine_rpo_breaches_open"), 0.0, "{metrics}");

    // Each tier on its own schedule and RPO: 13 hours is fine on starter (every 24 hours,
    // RPO 26), but due and past its RPO on pro (every 12, RPO 14).
    env.app.db.machine_backup_backdate(&b.id, 15 * 3_600_000);
    assert_eq!(backup::pass(&env.app, &env.cp).await, 0, "starter isn't due");
    assert_eq!(recovery::watch(&env.app, &env.cp), 0);
    let mut mm = env.app.db.machine(&m.id).unwrap();
    mm.tier = "pro".into();
    assert!(env.app.db.save_machine(&mm, mm.state));
    assert_eq!(recovery::watch(&env.app, &env.cp), 1, "past pro's 14 hours");
    assert_eq!(events(&env, "machine.rpo_breached").await[0]["details"]["rpoHours"].as_i64(), Some(14));
    assert_eq!(backup::pass(&env.app, &env.cp).await, 1, "due on pro's 12 hours");
    assert_eq!(recovery::watch(&env.app, &env.cp), 0);

    // A destroyed machine isn't held to it, and its open breach ends.
    env.app.db.machine_backup_backdate(&env.app.db.machine_last_backup(&m.id).unwrap().id, 15 * 3_600_000);
    assert_eq!(recovery::watch(&env.app, &env.cp), 1);
    let (code, _) = json_call(&env, "DELETE", &format!("/api/users/{uid}/machine"), "").await;
    assert_eq!(code, 200);
    assert_eq!(recovery::watch(&env.app, &env.cp), 0);
    let (_, r) = json_call(&env, "GET", "/api/machines/recovery", "").await;
    assert_eq!((r["tracked"].as_u64(), r["breaches"][0]["endReason"].as_str()), (Some(0), Some("destroyed")), "{r}");
}

#[tokio::test]
async fn restores_are_timed_against_their_tiers_rto() {
    let mut env = serve(Vec::new()).await;
    let mail = crate::notify::smtp::fake::start(Default::default()).await;
    alerts_to(&env, &mail);
    let (uid, m) = enrolled(&mut env, "ada@example.com").await;
    let b = back_up(&env, &uid).await;

    // Timed from the request to the agent enrolling again, within starter's 60 minutes.
    let r = restore_until(&env, &uid, json!({ "backupId": b.id }), "enrolling").await;
    assert_eq!((r.tier.as_deref(), r.rto_ms), (Some("starter"), Some(60 * 60_000)));
    let token = read(&env, &m.label, "/etc/superbot/enroll-token").unwrap();
    agent::enroll(&config(&env, &m.id, &token)).await.unwrap();
    backup::follow_up(&env.app, &env.cp).await;
    let r = env.app.db.machine_restore(&r.id).unwrap();
    assert_eq!(r.state, "done");
    let took = r.duration_ms.expect("timed");
    let enrolled_at = env.app.db.machine(&m.id).unwrap().enrolled_at.unwrap();
    assert_eq!(took, enrolled_at - r.created_at, "until it enrolled, not until botd looked");
    assert!(r.rto_exceeded_at.is_none());
    let restored = events(&env, "machine.restored").await;
    assert_eq!((restored[0]["details"]["durationMs"].as_i64(), restored[0]["details"]["withinRto"].as_bool()), (Some(took), Some(true)), "{restored:?}");
    let (_, rec) = json_call(&env, "GET", "/api/machines/recovery", "").await;
    assert_eq!((rec["restores"][0]["durationMs"].as_i64(), rec["restores"][0]["withinRto"].as_bool()), (Some(took), Some(true)), "{rec}");
    assert_eq!(rec["machines"][0]["lastRestore"]["withinRto"].as_bool(), Some(true), "{rec}");
    // What's on it now came from the backup, so it's covered from when the restore ended.
    assert!(rec["machines"][0]["coveredSince"].as_i64() >= r.finished_at, "{rec}");

    // Enrolled within its RTO, but botd only looks after it: on time, not late.
    let r = restore_until(&env, &uid, json!({ "backupId": b.id }), "enrolling").await;
    let token = read(&env, &m.label, "/etc/superbot/enroll-token").unwrap();
    agent::enroll(&config(&env, &m.id, &token)).await.unwrap();
    env.app.db.machine_restore_backdate(&r.id, 61 * 60_000);
    env.app.db.machine_restore_replaced_backdate(&r.id, 61 * 60_000);
    env.app.db.machine_enrolled_backdate(&m.id, 61 * 60_000);
    backup::follow_up(&env.app, &env.cp).await;
    let r = env.app.db.machine_restore(&r.id).unwrap();
    assert!(r.state == "done" && r.duration_ms.unwrap() <= 60 * 60_000 && r.rto_exceeded_at.is_none(), "{r:?}");
    assert!(events(&env, "machine.restore_rto_exceeded").await.is_empty());

    // Still underway past its RTO: audited and alerted once, then recorded as late.
    let r = restore_until(&env, &uid, json!({ "backupId": b.id }), "enrolling").await;
    env.app.db.machine_restore_backdate(&r.id, 61 * 60_000);
    backup::follow_up(&env.app, &env.cp).await;
    backup::follow_up(&env.app, &env.cp).await;
    let late = events(&env, "machine.restore_rto_exceeded").await;
    assert_eq!(late.len(), 1, "{late:?}");
    assert_eq!((late[0]["details"]["underway"].as_bool(), late[0]["details"]["rtoMs"].as_i64()), (Some(true), Some(3_600_000)), "{late:?}");
    let got = mail_with(&mail, "Restoring ada@example.com's machine took longer than its RTO").await;
    assert!(got.body.contains("RTO 60 minutes; it has taken 61 minutes."), "{}", got.body);
    let token = read(&env, &m.label, "/etc/superbot/enroll-token").unwrap();
    agent::enroll(&config(&env, &m.id, &token)).await.unwrap();
    backup::follow_up(&env.app, &env.cp).await;
    let r = env.app.db.machine_restore(&r.id).unwrap();
    assert!(r.state == "done" && r.duration_ms.unwrap() > 60 * 60_000 && r.rto_exceeded_at.is_some(), "{r:?}");
    assert_eq!(events(&env, "machine.restore_rto_exceeded").await.len(), 1, "not again when it finishes");
    let restored = events(&env, "machine.restored").await;
    assert_eq!(restored[0]["details"]["withinRto"].as_bool(), Some(false), "{restored:?}");

    // A failed restore is alerted too.
    let mut mm = env.app.db.machine(&m.id).unwrap();
    mm.firewall_id = None;
    env.app.db.save_machine(&mm, mm.state);
    restore_until(&env, &uid, json!({ "backupId": b.id }), "failed").await;
    let got = mail_with(&mail, "Restoring ada@example.com's machine failed").await;
    assert!(got.body.contains("firewall"), "{}", got.body);
}
