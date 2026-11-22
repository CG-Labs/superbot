//! Deprovisioning stops a person's Bots and machine (ADR 0124), on the real router with
//! the request shapes Okta and Entra ID send, a stand-in harness, and the in-memory
//! machine provider.

use crate::acl::Visibility;
use crate::machines::fake::Fake;
use crate::machines::provider::{MachineProvider, ProviderError};
use crate::machines::{ControlPlane, State};
use crate::scim_http_tests::{events, okta_user, scim, session_for, token};
use crate::tests::{call, serve_app_with};
use crate::users_http_tests::parse;
use crate::*;

const USERS: &str = "/scim/v2/Users";

struct World {
    port: u16,
    app: AppState,
    admin: String,
    scim: String,
    fake: Arc<Fake>,
}

async fn world(tweak: impl FnOnce(&mut ControlPlane)) -> World {
    let fake = Arc::new(Fake::default());
    let p: Arc<dyn MachineProvider> = fake.clone();
    let (port, app, admin, _) = serve_app_with(move |a| {
        a.scim.enabled = true;
        let mut cp = ControlPlane::for_tests(p);
        tweak(&mut cp);
        a.machines = Arc::new(cp);
    })
    .await;
    let (scim, _) = token(port, &admin, json!({ "tenant": "okta" })).await;
    World { port, app, admin, scim, fake }
}

/// A person the IdP provisions. Their SuperBot id.
async fn provision(w: &World, email: &str, external_id: &str) -> String {
    let (code, _, u) = scim(w.port, &w.scim, "POST", USERS, okta_user(email, external_id)).await;
    assert_eq!(code, 201, "{u}");
    u["id"].as_str().unwrap().to_string()
}

async fn set_active(w: &World, id: &str, active: bool) {
    let op = json!({ "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"], "Operations": [{ "op": "replace", "value": { "active": active } }] });
    let (code, _, body) = scim(w.port, &w.scim, "PATCH", &format!("{USERS}/{id}"), op).await;
    assert_eq!(code, 200, "{body}");
}

async fn reconcile(w: &World) -> Value {
    let (code, body) = call(w.port, "POST", "/api/machines/reconcile", &w.admin, "").await;
    assert_eq!(code, 200, "{body}");
    parse(&body)
}

/// A running machine for `user`.
async fn running_machine(w: &World, user: &str) -> String {
    let (code, m) = call(w.port, "POST", &format!("/api/users/{user}/machine"), &w.admin, "").await;
    assert_eq!(code, 202, "{m}");
    reconcile(w).await;
    let m = w.app.db.user_machine(user).unwrap();
    assert_eq!(m.state, State::Running);
    m.id
}

fn state(w: &World, machine: &str) -> State {
    w.app.db.machine(machine).unwrap().state
}

async fn deprovisioned(w: &World) -> Vec<Value> {
    events(w.port, &w.admin, "action=user.deprovisioned").await
}

/// A stand-in `claude` that writes its environment to `claude.env`, then answers only
/// once `claude.go` exists.
fn held_claude(app: &App) -> std::path::PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let dir = &app.cfg.bin_dir;
    let (env, go) = (dir.join("claude.env"), dir.join("claude.go"));
    let reply = r#"{"type":"assistant","message":{"content":[{"type":"text","text":"done"}]}}"#;
    let script = format!(
        "#!/bin/sh\n[ \"$1\" = --version ] && {{ echo 'claude 99.0.0'; exit 0; }}\nenv > '{e}.tmp' && mv '{e}.tmp' '{e}'\nwhile [ ! -f '{g}' ]; do sleep 0.05; done\nprintf '%s\\n' '{reply}'\n",
        e = env.display(),
        g = go.display()
    );
    let path = dir.join("claude");
    std::fs::write(&path, script).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    env
}

/// The `BOT_TOKEN` of the run the stand-in harness is in.
async fn run_token(env: &std::path::Path) -> String {
    for _ in 0..500 {
        if let Ok(s) = std::fs::read_to_string(env) {
            let _ = std::fs::remove_file(env);
            let t = s.lines().find_map(|l| l.strip_prefix("BOT_TOKEN=")).expect("a run token");
            return format!("Bearer {t}");
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("the harness never started");
}

async fn until(what: &str, f: impl Fn() -> bool) {
    for _ in 0..500 {
        if f() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("{what}");
}

async fn send(port: u16, who: &str, bot: &str, text: &str) {
    let (code, res) = call(port, "POST", &format!("/api/bots/{bot}/messages"), who, &json!({ "text": text }).to_string()).await;
    assert_eq!(code, 202, "{res}");
}

#[tokio::test]
async fn deactivating_stops_their_bots_run_and_queue_and_its_token() {
    let w = world(|_| {}).await;
    let ada = provision(&w, "ada@example.com", "00u1").await;
    let session = session_for(w.port, &w.admin, &ada).await;
    let env = held_claude(&w.app);
    let ops = w.app.db.create_bot_owned("Ops", "#fff", "waddle", "claude", None, false, &ada, Visibility::Private).id;
    send(w.port, &session, &ops, "first").await;
    send(w.port, &session, &ops, "second").await;
    let bot_token = run_token(&env).await;
    assert_eq!(call(w.port, "GET", "/api/bots", &bot_token, "").await.0, 200, "the run's token works while it runs");

    set_active(&w, &ada, false).await;
    until("Ada's run went on after she was deprovisioned", || w.app.live_run(&ops).is_none() && !w.app.busy(&ops)).await;
    assert_eq!(call(w.port, "GET", "/api/bots", &bot_token, "").await.0, 401, "the run's token died with it");
    assert_eq!(events(w.port, &w.admin, "action=harness.invoked").await.len(), 1, "the queued message never ran");

    let d = deprovisioned(&w).await;
    assert_eq!(d.len(), 1, "{d:?}");
    let e = &d[0];
    assert_eq!((e["targetId"].as_str(), e["actorId"].as_str().map(|a| a.starts_with("scim:")), e["authMethod"].as_str()), (Some(ada.as_str()), Some(true), Some("scim_token")));
    assert_eq!(e["details"]["via"], "scim");
    assert_eq!(e["details"]["botsStopped"], json!([ops]));
    assert_eq!(e["details"]["machine"]["state"], "none", "she has no machine");
}

#[tokio::test]
async fn deactivating_stops_runs_for_them_on_others_shared_bots() {
    let w = world(|_| {}).await;
    let al = provision(&w, "al@example.com", "00u2").await;
    let session = session_for(w.port, &w.admin, &al).await;
    let env = held_claude(&w.app);
    let desk = w.app.db.create_bot_owned("Desk", "#fff", "waddle", "claude", None, false, users::OPERATOR, Visibility::Shared).id;
    send(w.port, &session, &desk, "for me").await;
    run_token(&env).await;

    set_active(&w, &al, false).await;
    until("Al's run on the owner's Bot went on", || !w.app.busy(&desk)).await;
    let e = &deprovisioned(&w).await[0];
    assert_eq!((e["details"]["botsStopped"].clone(), e["details"]["runsForThemStopped"].clone()), (json!([]), json!([desk])));
}

#[tokio::test]
async fn deactivating_suspends_their_machine_and_reactivating_resumes_it() {
    let w = world(|_| {}).await;
    let ada = provision(&w, "ada@example.com", "00u1").await;
    let m = running_machine(&w, &ada).await;

    set_active(&w, &ada, false).await;
    assert_eq!(state(&w, &m), State::Suspended);
    assert!(w.app.db.disable_hold(&m));
    assert_eq!(w.fake.calls("shutdown"), 1);
    let off = events(w.port, &w.admin, "action=machine.suspended").await;
    assert!(off[0]["actorId"].as_str().unwrap().starts_with("scim:"), "{off:?}");
    assert_eq!(deprovisioned(&w).await[0]["details"]["machine"], json!({ "id": m, "state": "suspended" }));

    set_active(&w, &ada, true).await;
    assert_eq!(state(&w, &m), State::Running);
    assert!(!w.app.db.disable_hold(&m), "the hold ends with the disable");
    let back = events(w.port, &w.admin, "action=user.machine_resumed").await;
    assert_eq!((back.len(), back[0]["details"]["resumed"].as_bool()), (1, Some(true)), "{back:?}");

    // A machine an admin powered off by hand stays off whatever the IdP does.
    assert_eq!(call(w.port, "POST", &format!("/api/users/{ada}/machine/suspend"), &w.admin, "").await.0, 200);
    set_active(&w, &ada, false).await;
    assert_eq!(deprovisioned(&w).await[0]["details"]["machine"]["state"], "already_suspended");
    set_active(&w, &ada, true).await;
    assert_eq!(state(&w, &m), State::Suspended, "not ours to resume");
    assert_eq!(events(w.port, &w.admin, "action=user.machine_resumed").await.len(), 1);
}

#[tokio::test]
async fn a_machine_still_being_built_or_that_failed_to_stop_is_suspended_by_the_reconciler() {
    let w = world(|_| {}).await;
    let ada = provision(&w, "ada@example.com", "00u1").await;
    let (code, _) = call(w.port, "POST", &format!("/api/users/{ada}/machine"), &w.admin, "").await;
    assert_eq!(code, 202);
    let m = w.app.db.user_machine(&ada).unwrap().id;
    set_active(&w, &ada, false).await;
    assert_eq!(deprovisioned(&w).await[0]["details"]["machine"]["state"], "held");
    let pass = reconcile(&w).await;
    assert_eq!(state(&w, &m), State::Suspended, "{pass}");
    assert_eq!(pass["disabled"]["suspended"], 1, "{pass}");

    let bea = provision(&w, "bea@example.com", "00u3").await;
    let mb = running_machine(&w, &bea).await;
    w.fake.fail_next("shutdown", ProviderError::RateLimited);
    set_active(&w, &bea, false).await;
    assert_eq!(state(&w, &mb), State::Running);
    assert_eq!(deprovisioned(&w).await[0]["details"]["machine"]["state"], "failed");
    assert!(w.app.db.disable_hold(&mb), "kept, to try again");
    reconcile(&w).await;
    assert_eq!(state(&w, &mb), State::Suspended);
}

#[tokio::test]
async fn with_machine_on_disable_keep_the_machine_stays_up() {
    let w = world(|cp| cp.suspend_on_disable = false).await;
    let ada = provision(&w, "ada@example.com", "00u1").await;
    let m = running_machine(&w, &ada).await;
    set_active(&w, &ada, false).await;
    assert_eq!(state(&w, &m), State::Running);
    assert_eq!(deprovisioned(&w).await[0]["details"]["machine"], json!({ "id": m, "state": "kept" }));
    reconcile(&w).await;
    assert_eq!(state(&w, &m), State::Running);
}

#[tokio::test]
async fn an_admin_disabling_someone_does_the_same() {
    let w = world(|_| {}).await;
    let (code, u) = call(w.port, "POST", "/api/users", &w.admin, r#"{"email":"cy@example.com","role":"member"}"#).await;
    assert_eq!(code, 201, "{u}");
    let cy = parse(&u)["id"].as_str().unwrap().to_string();
    let m = running_machine(&w, &cy).await;
    assert_eq!(call(w.port, "PATCH", &format!("/api/users/{cy}"), &w.admin, r#"{"status":"disabled"}"#).await.0, 200);
    assert_eq!(state(&w, &m), State::Suspended);
    let e = &deprovisioned(&w).await[0];
    assert_eq!((e["details"]["via"].as_str(), e["actorId"].as_str()), (Some("admin"), Some("operator")));
    assert_eq!(call(w.port, "PATCH", &format!("/api/users/{cy}"), &w.admin, r#"{"status":"active"}"#).await.0, 200);
    assert_eq!(state(&w, &m), State::Running);
}

#[tokio::test]
async fn deleting_after_deactivating_is_safe_and_reprovisioning_brings_it_back() {
    let w = world(|_| {}).await;
    let ada = provision(&w, "ada@example.com", "00u1").await;
    let m = running_machine(&w, &ada).await;
    set_active(&w, &ada, false).await;
    let (code, _, _) = scim(w.port, &w.scim, "DELETE", &format!("{USERS}/{ada}"), Value::Null).await;
    assert_eq!(code, 204);
    let d = deprovisioned(&w).await;
    assert_eq!(d.len(), 2, "{d:?}");
    assert_eq!((d[0]["details"]["via"].as_str(), d[0]["details"]["machine"]["state"].as_str()), (Some("scim_delete"), Some("suspended")));
    assert_eq!(w.fake.calls("shutdown"), 1, "powered off once");

    assert_eq!(provision(&w, "ada@example.com", "00u1").await, ada, "the same person comes back");
    assert_eq!(state(&w, &m), State::Running);
}

#[tokio::test]
async fn a_run_token_acts_for_no_one_who_is_disabled() {
    let w = world(|_| {}).await;
    let ada = provision(&w, "ada@example.com", "00u1").await;
    let al = provision(&w, "al@example.com", "00u2").await;
    let ops = w.app.db.create_bot_owned("Ops", "#fff", "waddle", "claude", None, false, &ada, Visibility::Shared).id;
    let now = db::now();
    let (own, _) = w.app.run_tokens.issue(&ops, &ada, "r1", None, now, 60_000);
    let (for_al, _) = w.app.run_tokens.issue(&ops, &ada, "r2", Some(&al), now, 60_000);
    for t in [&own, &for_al] {
        assert_eq!(call(w.port, "GET", "/api/bots", &format!("Bearer {t}"), "").await.0, 200);
    }
    // Disabled behind botd's back, with the runs still live: the check stands on its own.
    w.app.db.update_user(&al, db::UserPatch { status: Some("disabled"), ..Default::default() }).unwrap();
    let (code, res) = call(w.port, "GET", "/api/bots", &format!("Bearer {for_al}"), "").await;
    assert_eq!(code, 403, "refused outright, not just shown no Bots: {res}");
    assert_eq!(call(w.port, "GET", "/api/bots", &format!("Bearer {own}"), "").await.0, 200, "Ada's own run goes on");
    w.app.db.update_user(&ada, db::UserPatch { status: Some("disabled"), ..Default::default() }).unwrap();
    assert_eq!(call(w.port, "GET", "/api/bots", &format!("Bearer {own}"), "").await.0, 403);
    let denied = events(w.port, &w.admin, "action=access.denied").await;
    let reasons: Vec<&str> = denied.iter().filter_map(|e| e["details"]["reason"].as_str()).collect();
    assert!(reasons.contains(&"for_user_disabled") && reasons.contains(&"owner_role"), "{denied:?}");
}

#[tokio::test]
async fn a_resume_the_provider_refused_is_tried_again() {
    let w = world(|_| {}).await;
    let ada = provision(&w, "ada@example.com", "00u1").await;
    let m = running_machine(&w, &ada).await;
    set_active(&w, &ada, false).await;
    w.fake.fail_next("boot", ProviderError::RateLimited);
    set_active(&w, &ada, true).await;
    assert_eq!(state(&w, &m), State::Suspended);
    assert!(w.app.db.disable_hold(&m), "kept until it comes back on");
    let pass = reconcile(&w).await;
    assert_eq!(state(&w, &m), State::Running, "{pass}");
    assert_eq!(pass["disabled"]["resumed"], 1, "{pass}");
    assert!(!w.app.db.disable_hold(&m));
}

#[tokio::test]
async fn a_machine_request_waiting_on_the_lock_makes_none_once_they_are_disabled() {
    let w = world(|_| {}).await;
    let ada = provision(&w, "ada@example.com", "00u1").await;
    let cp = w.app.control_plane.get().unwrap().clone();
    let lock = cp.lock_ops().await;
    let (port, admin, who) = (w.port, w.admin.clone(), ada.clone());
    let asked = tokio::spawn(async move { call(port, "POST", &format!("/api/users/{who}/machine"), &admin, "").await });
    tokio::time::sleep(Duration::from_millis(200)).await;
    w.app.db.update_user(&ada, db::UserPatch { status: Some("disabled"), ..Default::default() }).unwrap();
    drop(lock);
    let (code, body) = asked.await.unwrap();
    assert_eq!(code, 409, "{body}");
    assert!(w.app.db.user_machine(&ada).is_none() && w.fake.machines().is_empty());
}

#[tokio::test]
async fn a_run_for_someone_disabled_behind_its_back_acts_for_no_one_with_open_shared_bots() {
    let w = world(|_| {}).await;
    assert_eq!(w.app.shared_bots(), crate::acl::SharedBots::Open);
    let al = provision(&w, "al@example.com", "00u2").await;
    let session = session_for(w.port, &w.admin, &al).await;
    let env = held_claude(&w.app);
    let desk = w.app.db.create_bot_owned("Desk", "#fff", "waddle", "claude", None, false, users::OPERATOR, Visibility::Shared).id;
    send(w.port, &session, &desk, "for me").await;
    let t = run_token(&env).await;
    assert_eq!(call(w.port, "GET", "/api/bots", &t, "").await.0, 200);
    w.app.db.update_user(&al, db::UserPatch { status: Some("disabled"), ..Default::default() }).unwrap();
    assert_eq!(call(w.port, "GET", "/api/bots", &t, "").await.0, 403);
    w.app.stop(&desk);
}
