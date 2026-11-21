//! Rebuilding machines enrolled before ADR 0039 (ADR 0056), end to end on loopback:
//! botd, its machine port, the fake provider, a stand-in for an old agent (it answers
//! heartbeats as one from before ADR 0039 did, and nothing more), and the real agent
//! once the machine is "rebuilt". Nothing here talks to Linode.

use crate::machines::agent::{self, Agent};
use crate::machines::provider::ProviderError;
use crate::machines::rebuild::{MAX_ATTEMPTS, Rebuilds};
use crate::machines::{heartbeats, pki, reconcile};
use crate::machines_mtls_tests::{Env, config, events, json_call, machine_for, reply_after, send, serve_with, token_in};
use crate::*;
use std::sync::atomic::{AtomicU32, Ordering};
use tokio::net::TcpListener;

/// An agent from before ADR 0039: enrolled, answering heartbeats with no `can`.
struct Old {
    server: tokio::task::JoinHandle<()>,
    jobs: Arc<AtomicU32>,
    listen: SocketAddr,
}

async fn old_agent(env: &mut Env, mid: &str, token: &str) -> Old {
    let cfg = config(env, mid, Some(token));
    let id = agent::enroll(&cfg).await.unwrap();
    let (chain, key) = id.chain();
    let tls = Arc::new(pki::server_config(&pki::cert_der(&cfg.ca_pem).unwrap(), chain, key, true).unwrap());
    let jobs = Arc::new(AtomicU32::new(0));
    let (j, machine, user, fp) = (jobs.clone(), id.machine_id.clone(), id.user_id.clone(), id.fingerprint.clone());
    let router = axum::Router::new().route(
        "/v1/heartbeat",
        axum::routing::get(move || {
            let body = json!({
                "machineId": machine, "userId": user, "version": "0.3.0", "certificate": fp,
                "time": crate::db::now(), "protocol": 1, "jobs": j.load(Ordering::SeqCst),
            });
            async move { axum::Json(body) }
        }),
    );
    let server = tokio::spawn(pki::serve(env.agent_listener.take().unwrap(), Arc::new(move || tls.clone()), router, agent::admit));
    Old { server, jobs, listen: cfg.listen }
}

impl Old {
    /// The machine is wiped: the old agent is gone.
    async fn wipe(self) -> SocketAddr {
        self.server.abort();
        let _ = self.server.await;
        self.listen
    }
}

/// Today's agent, as the rebuilt machine's first boot starts it, enrolling with `token`.
async fn new_agent(env: &Env, listen: SocketAddr, mid: &str, token: &str) -> tokio::task::JoinHandle<()> {
    let mut cfg = config(env, mid, Some(token));
    cfg.exe = crate::db::temp_path("agent-lib").join("superbot-machine");
    std::fs::create_dir_all(cfg.exe.parent().unwrap()).unwrap();
    std::fs::write(&cfg.exe, "#!/bin/sh\necho 'superbot-machine new'\n").unwrap();
    let id = agent::enroll(&cfg).await.unwrap();
    let a = Agent::new(cfg, id).unwrap();
    tokio::spawn(agent::serve(TcpListener::bind(listen).await.unwrap(), a))
}

async fn rebuild_view(env: &Env, uid: &str) -> Value {
    let (code, v) = json_call(env, "GET", &format!("/api/users/{uid}/machine/rebuild"), "").await;
    assert_eq!(code, 200, "{v}");
    v
}

fn label(env: &Env, mid: &str) -> String {
    env.app.db.machine(mid).unwrap().label
}

#[tokio::test]
async fn an_admin_rebuilds_an_old_machine_and_it_comes_back_up_to_date() {
    let mut env = serve_with(|e| e).await;
    let (uid, mid, token) = machine_for(&env, "ada@example.com").await;
    let old = old_agent(&mut env, &mid, &token).await;
    let path = format!("/api/users/{uid}/machine/rebuild");
    let bot = env.app.db.create_bot_owned("Ada's", "#fff", "waddle", "claude", None, false, &uid, crate::acl::Visibility::Shared);

    assert_eq!(heartbeats(&env.app, &env.cp).await, Some(1));
    let v = rebuild_view(&env, &uid).await;
    assert_eq!((v["legacy"].as_bool(), v["rebuilds"].as_str(), v["mayHoldWork"].as_bool()), (Some(true), Some("manual"), Some(true)), "{v}");
    assert_eq!(v["lacks"].as_array().unwrap().len(), 8, "{v}");
    assert!(v["rebuild"].is_null());
    let (code, list) = json_call(&env, "GET", "/api/machines/legacy", "").await;
    assert_eq!((code, list["machines"][0]["machineId"].as_str()), (200, Some(mid.as_str())), "{list}");
    let (code, v) = json_call(&env, "POST", &format!("/api/users/{uid}/machine/agent/upgrade"), "").await;
    assert_eq!(code, 409);
    assert!(v["error"].as_str().unwrap().contains("botctl machine rebuild"), "the upgrade points at the rebuild: {v}");
    heartbeats(&env.app, &env.cp).await;
    assert!(events(&env, "machine.rebuild_requested").await.is_empty(), "manual by default");

    // It is assigned, so its disks may hold the user's files: only with discardWork.
    let (code, v) = json_call(&env, "POST", &path, "").await;
    assert_eq!(code, 409, "{v}");
    assert!(v["error"].as_str().unwrap().contains("discardWork"), "{v}");
    let (code, _) = json_call(&env, "POST", &format!("{path}?discardWork=yes"), "").await;
    assert_eq!(code, 400);
    let (code, _) = json_call(&env, "POST", &format!("{path}?wipe=true"), "").await;
    assert_eq!(code, 400);
    let (code, v) = json_call(&env, "POST", &path, r#"{"discardWork":true}"#).await;
    assert_eq!(code, 400, "a body is refused, never read as no: {v}");

    // Held at its build, it isn't rebuilt either.
    let (code, _) = json_call(&env, "PUT", &format!("/api/users/{uid}/machine/agent/hold"), "").await;
    assert_eq!(code, 200);
    let (code, v) = json_call(&env, "POST", &format!("{path}?discardWork=true"), "").await;
    assert_eq!(code, 409, "{v}");
    assert!(v["error"].as_str().unwrap().contains("held"), "{v}");
    let (code, _) = json_call(&env, "DELETE", &format!("/api/users/{uid}/machine/agent/hold"), "").await;
    assert_eq!(code, 200);

    // Busy: it waits without counting a try, and Bots don't start meanwhile.
    old.jobs.store(2, Ordering::SeqCst);
    let (code, v) = json_call(&env, "POST", &format!("{path}?discardWork=true"), "").await;
    assert_eq!(code, 202, "{v}");
    assert_eq!((v["rebuild"]["state"].as_str(), v["rebuild"]["attempts"].as_i64()), (Some("queued"), Some(0)), "{v}");
    assert!(v["rebuild"]["error"].as_str().unwrap().contains("2 jobs"), "{v}");
    assert_eq!(env.fake.calls("rebuild"), 0);
    let before = send(&env, &bot.id, "hello").await;
    assert!(reply_after(&env, &bot.id, before).await.contains("being rebuilt"));
    let refused = events(&env, "bot.run_refused").await;
    assert_eq!(refused[0]["details"]["reason"], "machine_rebuilding", "{refused:?}");

    // Queued, an admin can cancel it, and ask again.
    let (code, v) = json_call(&env, "DELETE", &path, "").await;
    assert_eq!((code, v["rebuild"]["state"].as_str()), (200, Some("cancelled")), "{v}");
    let cancelled = events(&env, "machine.rebuild_cancelled").await;
    assert_eq!(cancelled[0]["details"]["reason"], "admin");
    old.jobs.store(0, Ordering::SeqCst);
    let (code, v) = json_call(&env, "POST", &format!("{path}?discardWork=true"), "").await;
    assert_eq!(code, 202, "{v}");
    assert_eq!((v["rebuild"]["state"].as_str(), v["rebuild"]["attempts"].as_i64()), (Some("rebuilding"), Some(1)), "sent at once: {v}");
    assert_eq!(env.fake.calls("rebuild"), 1);
    let asked = events(&env, "machine.rebuild_requested").await;
    assert_eq!(asked.len(), 2);
    assert_eq!((asked[0]["actorKind"].as_str(), asked[0]["details"]["discardWork"].as_bool()), (Some("user"), Some(true)));
    assert_eq!(asked[0]["details"]["fromVersion"], "0.3.0");

    // Sent with a new token in today's user data; the old disks' certificates are gone.
    let ud = env.fake.user_data(&label(&env, &mid)).unwrap();
    let fresh = token_in(&ud);
    assert_ne!(fresh, token);
    assert!(ud.contains(&format!("SUPERBOT_MACHINE_ID={mid}")) && ud.contains("superbot-machine"), "{ud}");
    let issued = events(&env, "machine.enroll_token_issued").await;
    assert_eq!(issued[0]["details"]["via"], "rebuild", "{issued:?}");
    let sent = events(&env, "machine.rebuild_sent").await;
    assert_eq!((sent.len(), sent[0]["details"]["image"].as_str()), (1, Some("linode/ubuntu24.04")), "{sent:?}");
    let revoked = events(&env, "machine.cert_revoked").await;
    assert_eq!(revoked[0]["details"]["reason"], "rebuilt", "{revoked:?}");
    let m = env.app.db.machine(&mid).unwrap();
    assert_eq!((m.enrollment.as_str(), m.agent_upkeep.is_none(), m.assigned_at.is_some()), ("revoked", true, true));

    // On its way, it can't be called back or asked for twice.
    let (code, v) = json_call(&env, "DELETE", &path, "").await;
    assert_eq!(code, 409);
    assert!(v["error"].as_str().unwrap().contains("can't be called back"), "{v}");
    let (code, v) = json_call(&env, "POST", &format!("{path}?discardWork=true"), "").await;
    assert_eq!(code, 409);
    assert!(v["error"].as_str().unwrap().contains("already"), "{v}");
    reconcile(&env.app, &env.cp).await;
    assert_eq!(env.fake.calls("rebuild"), 1, "nothing sent again while it boots");

    // The rebuilt machine boots today's agent, which enrolls with the new token.
    let listen = old.wipe().await;
    let _new = new_agent(&env, listen, &mid, &fresh).await;
    assert_eq!(heartbeats(&env.app, &env.cp).await, Some(1));
    let v = rebuild_view(&env, &uid).await;
    assert_eq!((v["rebuild"]["state"].as_str(), v["legacy"].as_bool()), (Some("done"), Some(false)), "{v}");
    assert!(v["lacks"].as_array().unwrap().iter().all(|c| c != "upgrade"), "{v}");
    let done = events(&env, "machine.rebuilt").await;
    assert_eq!(done.len(), 1, "{done:?}");
    assert_eq!((done[0]["details"]["fromVersion"].as_str(), done[0]["actorKind"].as_str()), (Some("0.3.0"), Some("system")));
    assert!(done[0]["details"]["toBuild"].is_string(), "{done:?}");
    let (_, list) = json_call(&env, "GET", "/api/machines/legacy", "").await;
    assert!(list["machines"].as_array().unwrap().is_empty(), "{list}");

    // Its agent upgrades itself from now on, so it isn't rebuilt again.
    let (code, v) = json_call(&env, "POST", &format!("{path}?discardWork=true"), "").await;
    assert_eq!(code, 409);
    assert!(v["error"].as_str().unwrap().contains("botctl machine upgrade"), "{v}");
    heartbeats(&env.app, &env.cp).await;
    assert_eq!(events(&env, "machine.rebuilt").await.len(), 1, "finished once");
}

#[tokio::test]
async fn auto_rebuilds_only_idle_machines_that_never_ran_bots_and_gives_up_after_retries() {
    let mut env = serve_with(|mut e| {
        e.upkeep.rebuilds = Rebuilds::Auto;
        e
    })
    .await;
    let (uid, mid, token) = machine_for(&env, "bo@example.com").await;
    assert!(env.app.db.unassign_machine(&mid));
    let old = old_agent(&mut env, &mid, &token).await;

    old.jobs.store(1, Ordering::SeqCst);
    heartbeats(&env.app, &env.cp).await;
    assert!(events(&env, "machine.rebuild_requested").await.is_empty(), "never while busy");
    old.jobs.store(0, Ordering::SeqCst);
    heartbeats(&env.app, &env.cp).await;
    let asked = events(&env, "machine.rebuild_requested").await;
    assert_eq!((asked.len(), asked[0]["details"]["by"].as_str(), asked[0]["actorKind"].as_str()), (1, Some("auto"), Some("system")), "{asked:?}");
    heartbeats(&env.app, &env.cp).await;
    assert_eq!(events(&env, "machine.rebuild_requested").await.len(), 1, "queued once");

    // Rate limited: nothing happened, so it waits and tries again.
    env.fake.fail_next("rebuild", ProviderError::RateLimited);
    reconcile(&env.app, &env.cp).await;
    let v = rebuild_view(&env, &uid).await;
    assert_eq!((v["rebuild"]["state"].as_str(), v["rebuild"]["attempts"].as_i64()), (Some("queued"), Some(1)), "{v}");
    assert!(v["rebuild"]["nextAt"].as_i64().unwrap() > crate::db::now());
    let failed = events(&env, "machine.rebuild_failed").await;
    assert_eq!((failed[0]["details"]["reason"].as_str(), failed[0]["details"]["retrying"].as_bool()), (Some("rate_limited"), Some(true)));
    reconcile(&env.app, &env.cp).await;
    assert_eq!(env.fake.calls("rebuild"), 1, "not before its backoff");

    // The provider's answer is lost and nothing happened: the old agent is still there.
    env.app.db.machine_rebuild_due_now(&mid);
    env.fake.fail_next("rebuild", ProviderError::Transport("timed out".into()));
    reconcile(&env.app, &env.cp).await;
    let v = rebuild_view(&env, &uid).await;
    assert_eq!((v["rebuild"]["state"].as_str(), v["enrollment"].as_str()), (Some("rebuilding"), Some("enrolled")), "it waits to see: {v}");
    let sent = events(&env, "machine.rebuild_sent").await;
    assert_eq!(sent[0]["details"]["answered"], false, "{sent:?}");
    assert_eq!(heartbeats(&env.app, &env.cp).await, Some(1));
    assert_eq!(rebuild_view(&env, &uid).await["rebuild"]["state"], "rebuilding", "an old heartbeat doesn't finish it");

    // It doesn't come back in time: sent again once the old agent is idle.
    env.app.db.machine_rebuild_backdate(&mid, 3_600_000);
    reconcile(&env.app, &env.cp).await;
    let v = rebuild_view(&env, &uid).await;
    assert_eq!((v["rebuild"]["state"].as_str(), v["rebuild"]["attempts"].as_i64()), (Some("retrying"), Some(2)), "{v}");
    env.app.db.machine_rebuild_due_now(&mid);
    reconcile(&env.app, &env.cp).await;
    assert_eq!(env.fake.calls("rebuild"), 3);
    let v = rebuild_view(&env, &uid).await;
    assert_eq!((v["rebuild"]["state"].as_str(), v["enrollment"].as_str()), (Some("rebuilding"), Some("revoked")), "{v}");
    let _ = old.wipe().await;

    // The rebuilt machine never enrolls: it is sent again, up to the limit.
    for n in 3..MAX_ATTEMPTS {
        env.app.db.machine_rebuild_backdate(&mid, 3_600_000);
        reconcile(&env.app, &env.cp).await;
        assert_eq!(rebuild_view(&env, &uid).await["rebuild"]["state"], "retrying");
        env.app.db.machine_rebuild_due_now(&mid);
        reconcile(&env.app, &env.cp).await;
        assert_eq!(env.fake.calls("rebuild") as i64, n + 1);
    }
    env.app.db.machine_rebuild_backdate(&mid, 3_600_000);
    reconcile(&env.app, &env.cp).await;
    let v = rebuild_view(&env, &uid).await;
    assert_eq!((v["rebuild"]["state"].as_str(), v["rebuild"]["attempts"].as_i64()), (Some("failed"), Some(MAX_ATTEMPTS)), "{v}");
    let failed = events(&env, "machine.rebuild_failed").await;
    assert_eq!((failed[0]["details"]["reason"].as_str(), failed[0]["outcome"].as_str()), (Some("never_enrolled"), Some("failure")), "{failed:?}");
    env.app.db.machine_rebuild_due_now(&mid);
    reconcile(&env.app, &env.cp).await;
    assert_eq!(env.fake.calls("rebuild") as i64, MAX_ATTEMPTS, "settled");
    assert_eq!(env.app.db.machine_tokens_unused(&mid), 0, "its last token is revoked");

    // No agent is left to answer, yet an admin can ask again: it is sent at once.
    let (code, v) = json_call(&env, "POST", &format!("/api/users/{uid}/machine/rebuild"), "").await;
    assert_eq!(code, 202, "{v}");
    assert_eq!((v["rebuild"]["state"].as_str(), v["rebuild"]["attempts"].as_i64()), (Some("rebuilding"), Some(1)), "{v}");
    assert_eq!(env.fake.calls("rebuild") as i64, MAX_ATTEMPTS + 1);
    let asked = events(&env, "machine.rebuild_requested").await;
    assert_eq!((asked[0]["details"]["again"].as_bool(), asked[0]["details"]["fromVersion"].as_str()), (Some(true), Some("0.3.0")), "{asked:?}");
}

#[tokio::test]
async fn a_machine_that_enrolled_as_its_deadline_passed_but_never_answers_fails() {
    let mut env = serve_with(|e| e).await;
    let (uid, mid, token) = machine_for(&env, "fy@example.com").await;
    assert!(env.app.db.unassign_machine(&mid));
    let old = old_agent(&mut env, &mid, &token).await;
    heartbeats(&env.app, &env.cp).await;
    let (code, v) = json_call(&env, "POST", &format!("/api/users/{uid}/machine/rebuild"), "").await;
    assert_eq!(code, 202, "{v}");
    let fresh = token_in(&env.fake.user_data(&label(&env, &mid)).unwrap());
    let listen = old.wipe().await;
    let new = new_agent(&env, listen, &mid, &fresh).await;
    new.abort();
    let _ = new.await;

    // Moved on to retrying from a reading taken before it enrolled.
    let id = env.app.db.machine(&mid).unwrap().rebuild_id.unwrap();
    assert!(env.app.db.machine_rebuild_move(&mid, &id, &["rebuilding"], "retrying", false, Some(crate::db::now()), None));
    reconcile(&env.app, &env.cp).await;
    assert_eq!(rebuild_view(&env, &uid).await["rebuild"]["state"], "retrying", "it waits for an answer");
    env.app.db.machine_rebuild_backdate(&mid, 10 * 3_600_000);
    reconcile(&env.app, &env.cp).await;
    let v = rebuild_view(&env, &uid).await;
    assert_eq!(v["rebuild"]["state"], "failed", "{v}");
    assert_eq!(events(&env, "machine.rebuild_failed").await[0]["details"]["reason"], "no_heartbeat");
    assert_eq!(env.fake.calls("rebuild"), 1, "never wiped again");
}

#[tokio::test]
async fn a_refused_rebuild_fails_and_auto_never_wipes_a_machine_that_may_hold_work() {
    let mut env = serve_with(|mut e| {
        e.upkeep.rebuilds = Rebuilds::Auto;
        e
    })
    .await;
    let (uid, mid, token) = machine_for(&env, "cy@example.com").await;
    let old = old_agent(&mut env, &mid, &token).await;
    let path = format!("/api/users/{uid}/machine/rebuild");
    for _ in 0..3 {
        heartbeats(&env.app, &env.cp).await;
    }
    assert!(events(&env, "machine.rebuild_requested").await.is_empty(), "assigned: it may hold the user's files");

    // Its sessions are forgotten before the provider is asked, even if it then refuses:
    // a botd that stops mid-call mustn't leave sessions whose files may be erased.
    let bot = env.app.db.create_bot_owned("Cy's", "#fff", "waddle", "claude", None, false, &uid, crate::acl::Visibility::Shared);
    assert!(env.app.db.keep_session(&bot.id, "s1", env.app.db.placed_at(&uid)));
    env.fake.fail_next("rebuild", ProviderError::Api { status: 400, message: "image: Not found".into() });
    let (code, v) = json_call(&env, "POST", &format!("{path}?discardWork=true"), "").await;
    assert_eq!(code, 202, "{v}");
    assert_eq!(v["rebuild"]["state"], "failed", "{v}");
    assert!(v["rebuild"]["error"].as_str().unwrap().contains("image"), "{v}");
    let failed = events(&env, "machine.rebuild_failed").await;
    assert_eq!(failed[0]["details"]["reason"], "refused");
    assert!(env.app.db.bot(&bot.id).unwrap().session_id.is_none());
    let m = env.app.db.machine(&mid).unwrap();
    assert_eq!(m.enrollment, "enrolled", "a refused rebuild leaves the old agent as it was");
    assert_eq!(env.app.db.machine_tokens_unused(&mid), 0);
    assert_eq!(heartbeats(&env.app, &env.cp).await, Some(1));
    assert_eq!(events(&env, "machine.rebuild_requested").await.len(), 1, "auto doesn't try again after a failure");

    // Asked again, it goes.
    let (code, v) = json_call(&env, "POST", &format!("{path}?discardWork=true"), "").await;
    assert_eq!((code, v["rebuild"]["state"].as_str()), (202, Some("rebuilding")), "{v}");
    drop(old);
}

#[tokio::test]
async fn rebuilds_can_be_turned_off() {
    let mut env = serve_with(|mut e| {
        e.upkeep.rebuilds = Rebuilds::Off;
        e
    })
    .await;
    let (uid, mid, token) = machine_for(&env, "di@example.com").await;
    let _old = old_agent(&mut env, &mid, &token).await;
    heartbeats(&env.app, &env.cp).await;
    let (code, v) = json_call(&env, "POST", &format!("/api/users/{uid}/machine/rebuild?discardWork=true"), "").await;
    assert_eq!(code, 409);
    assert!(v["error"].as_str().unwrap().contains("MACHINE_LEGACY_REBUILDS=off"), "{v}");
    assert_eq!(rebuild_view(&env, &uid).await["legacy"], true, "it still says which are old");
    assert_eq!(env.fake.calls("rebuild"), 0);
}

#[tokio::test]
async fn a_rebuild_whose_answer_was_lost_finishes_when_the_machine_comes_back() {
    let mut env = serve_with(|e| e).await;
    let (uid, mid, token) = machine_for(&env, "ed@example.com").await;
    assert!(env.app.db.unassign_machine(&mid));
    let old = old_agent(&mut env, &mid, &token).await;
    heartbeats(&env.app, &env.cp).await;
    assert_eq!(rebuild_view(&env, &uid).await["mayHoldWork"], false, "never assigned through botd, never ran a Bot");

    env.fake.lose_next("rebuild");
    let (code, v) = json_call(&env, "POST", &format!("/api/users/{uid}/machine/rebuild"), "").await;
    assert_eq!(code, 202, "{v}");
    assert_eq!((v["rebuild"]["state"].as_str(), v["enrollment"].as_str()), (Some("rebuilding"), Some("enrolled")), "{v}");
    let fresh = token_in(&env.fake.user_data(&label(&env, &mid)).unwrap());

    let listen = old.wipe().await;
    let _new = new_agent(&env, listen, &mid, &fresh).await;
    let replaced = events(&env, "machine.cert_revoked").await;
    assert_eq!(replaced[0]["details"]["reason"], "replaced", "enrolling again replaces the old disks' certificate: {replaced:?}");
    assert_eq!(heartbeats(&env.app, &env.cp).await, Some(1));
    assert_eq!(rebuild_view(&env, &uid).await["rebuild"]["state"], "done");
    env.app.db.machine_rebuild_backdate(&mid, 3_600_000);
    reconcile(&env.app, &env.cp).await;
    assert_eq!(env.fake.calls("rebuild"), 1, "never sent twice");
}

#[tokio::test]
async fn a_machine_left_stopped_by_a_slow_rebuild_is_started_unless_it_was_suspended() {
    let mut env = serve_with(|e| e).await;
    let (uid, mid, token) = machine_for(&env, "flo@example.com").await;
    assert!(env.app.db.unassign_machine(&mid));
    let _old = old_agent(&mut env, &mid, &token).await;
    heartbeats(&env.app, &env.cp).await;
    env.fake.lose_next("rebuild");
    let (code, v) = json_call(&env, "POST", &format!("/api/users/{uid}/machine/rebuild"), "").await;
    assert_eq!((code, v["rebuild"]["state"].as_str()), (202, Some("rebuilding")), "{v}");
    let pid = env.app.db.machine(&mid).unwrap().provider_id.unwrap();

    // Suspended meanwhile: it stays off.
    env.fake.set(&pid, |m| m.status = "offline".into());
    let mut m = env.app.db.machine(&mid).unwrap();
    m.state = crate::machines::State::Suspended;
    assert!(env.app.db.save_machine(&m, crate::machines::State::Running));
    reconcile(&env.app, &env.cp).await;
    assert_eq!(env.fake.calls("boot"), 0, "a suspended machine isn't started");

    // Still meant to be running: started, under the lock, by the rebuild worker.
    m.state = crate::machines::State::Running;
    assert!(env.app.db.save_machine(&m, crate::machines::State::Suspended));
    reconcile(&env.app, &env.cp).await;
    assert_eq!(env.fake.calls("boot"), 1);
    reconcile(&env.app, &env.cp).await;
    assert_eq!(env.fake.calls("boot"), 1, "not again once it's up");
}
