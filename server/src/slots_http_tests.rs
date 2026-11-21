//! Runs at once per computer (ADR 0073) on the real router and runner: runs past the
//! cap wait their turn in order, fairly across Bots, show they're queued and why, and
//! are audited; routines queue too; a queued run can be stopped; slots come back when a
//! run fails or is stopped; a restarted server holds none; and a machine's cap is its
//! owner's tier's, through the real agent over mutual TLS.

use crate::acl::Visibility;
use crate::machines_mtls_tests::{agent_with, events, json_call, machine_for, send, serve_with, wait_for_event};
use crate::slots::SERVER;
use crate::tests::{audit_list, call, serve_app};
use crate::tiers::Tiers;
use crate::*;

/// A Claude Code stand-in that notes each run's Bot in `dir/order`, waits for
/// `dir/go-<bot>`, and then replies, or fails if `dir/fail-<bot>` is there.
pub(crate) fn gated_claude(app: &App, dir: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::create_dir_all(dir).unwrap();
    let script = format!(
        r#"#!/bin/sh
d='{}'
echo "$BOT_ID" >> "$d/order"
while [ ! -e "$d/go-$BOT_ID" ]; do sleep 0.05; done
rm -f "$d/go-$BOT_ID"
if [ -e "$d/fail-$BOT_ID" ]; then rm -f "$d/fail-$BOT_ID"; echo "it broke" >&2; exit 1; fi
printf '%s\n' '{{"type":"assistant","message":{{"content":[{{"type":"text","text":"done"}}]}}}}'
"#,
        dir.display()
    );
    let path = app.cfg.bin_dir.join("claude");
    std::fs::write(&path, script).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

fn order(dir: &std::path::Path) -> Vec<String> {
    std::fs::read_to_string(dir.join("order")).unwrap_or_default().lines().map(String::from).collect()
}

fn go(dir: &std::path::Path, bot: &str) {
    std::fs::write(dir.join(format!("go-{bot}")), "").unwrap();
}

async fn until(what: &str, f: impl Fn() -> bool) {
    for _ in 0..400 {
        if f() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("timed out waiting for {what}");
}

async fn say(port: u16, auth: &str, bot: &str, text: &str) {
    let (code, body) = call(port, "POST", &format!("/api/bots/{bot}/messages"), auth, &json!({ "text": text }).to_string()).await;
    assert_eq!(code, 202, "{body}");
}

async fn view(port: u16, auth: &str, bot: &str) -> Value {
    let (code, body) = call(port, "GET", "/api/bots", auth, "").await;
    assert_eq!(code, 200, "{body}");
    let list: Value = serde_json::from_str(&body).unwrap();
    list.as_array().unwrap().iter().find(|b| b["id"] == bot).cloned().unwrap()
}

async fn audit(port: u16, admin: &str, q: &str) -> Vec<Value> {
    let (code, body) = call(port, "GET", &format!("/api/audit?{q}&limit=500"), admin, "").await;
    assert_eq!(code, 200, "{body}");
    audit_list(&body)
}

fn bot(app: &App, name: &str) -> String {
    app.db.create_bot(name, "#fff", "waddle", "claude", None, false).id
}

fn waiting(app: &App, bot: &str) -> bool {
    app.slots.waiting(bot).is_some()
}

#[tokio::test]
async fn runs_past_the_servers_cap_wait_in_order_and_say_why() {
    let (port, app, admin, _) = serve_app().await;
    app.run_cap.set(Some(2)).unwrap();
    let dir = app.cfg.data_dir.join("gate");
    gated_claude(&app, &dir);
    let [a, b, c, d] = ["A", "B", "C", "D"].map(|n| bot(&app, n));
    say(port, &admin, &a, "one").await;
    say(port, &admin, &b, "two").await;
    until("two runs", || order(&dir).len() == 2).await;
    for x in [&c, &d] {
        say(port, &admin, x, "more").await;
        until("it to queue", || waiting(&app, x)).await;
    }
    assert_eq!(app.slots.load(SERVER), (2, 2));
    // Queued: the API says where it is in line, why, and on which computer.
    let v = view(port, &admin, &d).await;
    assert_eq!(v["working"], true, "{v}");
    assert_eq!(v["queued"], json!({ "reason": "at_capacity", "host": "server", "position": 2, "running": 2, "limit": 2 }));
    assert_eq!(v["status"], "Queued, #2 in line: this server runs 2 tasks at once");
    assert_eq!(view(port, &admin, &c).await["queued"]["position"], 1);
    assert!(view(port, &admin, &a).await.get("queued").is_none());
    let queued = audit(port, &admin, "action=bot.run_queued").await;
    assert_eq!(queued.len(), 2, "{queued:?}");
    let first = queued.iter().find(|e| e["botId"] == c.as_str()).unwrap();
    let dd = &first["details"];
    assert_eq!((dd["host"].as_str(), dd["limit"].as_u64(), dd["position"].as_u64(), dd["trigger"].as_str()), (Some("server"), Some(2), Some(1), Some("user")), "{first}");
    // Each freed slot goes to the run that waited longest.
    go(&dir, &b);
    until("C to start", || order(&dir).len() == 3).await;
    assert_eq!(order(&dir)[2], c);
    assert_eq!(view(port, &admin, &d).await["queued"]["position"], 1);
    go(&dir, &a);
    until("D to start", || order(&dir).len() == 4).await;
    assert_eq!(order(&dir), [a.clone(), b.clone(), c.clone(), d.clone()]);
    for x in [&c, &d] {
        go(&dir, x);
    }
    until("all to finish", || [&a, &b, &c, &d].iter().all(|x| !app.is_running(x))).await;
    assert_eq!(app.slots.load(SERVER), (0, 0));
    let dequeued = audit(port, &admin, "action=bot.run_dequeued").await;
    assert_eq!(dequeued.len(), 2, "{dequeued:?}");
    assert!(dequeued.iter().all(|e| e["details"]["result"] == "started" && e["outcome"] == "success" && e["details"]["waitedMs"].is_u64()), "{dequeued:?}");
    assert_eq!(audit(port, &admin, "action=bot.run_finished").await.len(), 4);
}

#[tokio::test]
async fn a_bot_that_just_ran_goes_behind_the_bots_already_waiting() {
    let (port, app, admin, _) = serve_app().await;
    app.run_cap.set(Some(1)).unwrap();
    let dir = app.cfg.data_dir.join("gate");
    gated_claude(&app, &dir);
    let (a, b) = (bot(&app, "Busy"), bot(&app, "Patient"));
    say(port, &admin, &a, "first").await;
    until("A to start", || order(&dir).len() == 1).await;
    say(port, &admin, &a, "second").await;
    say(port, &admin, &b, "only").await;
    until("B to queue", || waiting(&app, &b)).await;
    go(&dir, &a);
    until("B to start", || order(&dir).len() == 2).await;
    until("A's next to queue", || waiting(&app, &a)).await;
    assert_eq!(order(&dir), [a.clone(), b.clone()]);
    go(&dir, &b);
    until("A's second", || order(&dir).len() == 3).await;
    go(&dir, &a);
    until("all to finish", || !app.is_running(&a) && !app.is_running(&b) && !waiting(&app, &a)).await;
    assert_eq!(order(&dir), [a.clone(), b, a]);
}

#[tokio::test]
async fn a_queued_run_can_be_stopped_and_a_failed_run_frees_its_slot() {
    let (port, app, admin, _) = serve_app().await;
    app.run_cap.set(Some(1)).unwrap();
    let dir = app.cfg.data_dir.join("gate");
    gated_claude(&app, &dir);
    let [a, b, c] = ["A", "B", "C"].map(|n| bot(&app, n));
    say(port, &admin, &a, "one").await;
    until("A to start", || order(&dir).len() == 1).await;
    for x in [&b, &c] {
        say(port, &admin, x, "wait").await;
        until("it to queue", || waiting(&app, x)).await;
    }
    // Stopping a queued run takes it out of line and says so; the one behind moves up.
    let before = app.db.last_id();
    let (code, body) = call(port, "POST", &format!("/api/bots/{b}/stop"), &admin, "").await;
    assert_eq!(code, 200, "{body}");
    until("B to leave the line", || !waiting(&app, &b) && !app.db.replies_after(&b, before).is_empty()).await;
    assert_eq!(app.db.replies_after(&b, before)[0].text, "Stopped.");
    assert_eq!(view(port, &admin, &c).await["queued"]["position"], 1);
    assert_eq!(view(port, &admin, &b).await["working"], false);
    let left = audit(port, &admin, &format!("action=bot.run_dequeued&bot={b}")).await;
    assert_eq!((left[0]["details"]["result"].as_str(), left[0]["outcome"].as_str()), (Some("stopped"), Some("failure")), "{left:?}");
    // A run that fails gives its slot back.
    std::fs::write(dir.join(format!("fail-{a}")), "").unwrap();
    go(&dir, &a);
    until("C to start", || order(&dir).len() == 2).await;
    assert_eq!(order(&dir), [a.clone(), c.clone()]);
    let failed = audit(port, &admin, &format!("action=bot.run_finished&bot={a}")).await;
    assert_eq!(failed[0]["details"]["result"], "error", "{failed:?}");
    go(&dir, &c);
    until("C to finish", || !app.is_running(&c)).await;
    assert_eq!(app.slots.load(SERVER), (0, 0));
    assert!(!order(&dir).contains(&b), "the stopped run never ran");
}

#[tokio::test]
async fn routines_that_fire_at_the_cap_queue_too() {
    let (port, app, admin, _) = serve_app().await;
    app.run_cap.set(Some(1)).unwrap();
    let dir = app.cfg.data_dir.join("gate");
    gated_claude(&app, &dir);
    let (a, b) = (bot(&app, "Chat"), bot(&app, "Digest"));
    say(port, &admin, &a, "busy").await;
    until("A to start", || order(&dir).len() == 1).await;
    let r = app.db.add_routine(&b, "Digest", "0 9 * * *", "Sum up my email");
    cron::fire(&app, &r, db::now());
    until("the routine to queue", || waiting(&app, &b)).await;
    let queued = audit(port, &admin, &format!("action=bot.run_queued&bot={b}")).await;
    assert_eq!(queued[0]["details"]["trigger"], "routine", "{queued:?}");
    assert_eq!(view(port, &admin, &b).await["queued"]["position"], 1);
    go(&dir, &a);
    until("the routine to run", || order(&dir).len() == 2).await;
    go(&dir, &b);
    until("it to finish", || !app.is_running(&b)).await;
    assert_eq!(order(&dir), [a, b]);
}

#[tokio::test]
async fn without_a_cap_every_run_starts_at_once() {
    let (port, app, admin, _) = serve_app().await;
    app.run_cap.set(None).unwrap();
    let dir = app.cfg.data_dir.join("gate");
    gated_claude(&app, &dir);
    let bots: Vec<String> = (0..10).map(|i| bot(&app, &format!("B{i}"))).collect();
    for b in &bots {
        say(port, &admin, b, "go").await;
    }
    until("all ten", || order(&dir).len() == 10).await;
    assert!(bots.iter().all(|b| !waiting(&app, b)));
    for b in &bots {
        go(&dir, b);
    }
    until("all to finish", || bots.iter().all(|b| !app.is_running(b))).await;
    assert!(audit(port, &admin, "action=bot.run_queued").await.is_empty());
}

#[tokio::test]
async fn a_restarted_server_holds_no_slots_and_runs_what_was_waiting() {
    let dir = db::temp_path("restart");
    let app = runner::test_app_in(dir.clone());
    users::ensure_operator(&app.db, "Owner", None);
    app.run_cap.set(Some(1)).unwrap();
    let gate = dir.join("gate");
    gated_claude(&app, &gate);
    let (a, b) = (bot(&app, "Running"), bot(&app, "Waiting"));
    for x in [&a, &b] {
        let m = app.db.add_message(x, "user", "hi", None, false, Some("queued"));
        app.enqueue(m);
        until("it to start or queue", || order(&gate).contains(x) || waiting(&app, x)).await;
    }
    assert!(waiting(&app, &b));
    let waited = app.db.messages(&b, 10).into_iter().find(|m| m.role == "user").unwrap();
    app.shutdown();
    until("the old server to let go", || !waiting(&app, &b) && !app.is_running(&a)).await;
    assert_eq!(app.db.message(waited.id).unwrap().status.as_deref(), Some("queued"), "still queued for the next start");
    // The next start: nothing is running, so no slot is held, and the waiting run runs.
    let again = runner::test_app_in(dir.clone());
    again.run_cap.set(Some(1)).unwrap();
    assert_eq!(again.slots.load(SERVER), (0, 0));
    let before = again.db.last_id();
    again.recover();
    until("B to start", || order(&gate).len() == 2).await;
    assert_eq!(order(&gate), [a.clone(), b.clone()]);
    let interrupted: Vec<String> = again.db.replies_after(&a, before).into_iter().map(|m| m.text).collect();
    assert!(interrupted[0].contains("server restart interrupted"), "{interrupted:?}");
    go(&gate, &b);
    until("B to finish", || !again.is_running(&b) && !again.db.replies_after(&b, before).is_empty()).await;
    assert_eq!(again.db.replies_after(&b, before)[0].text, "done");
    assert_eq!(again.slots.load(SERVER), (0, 0));
    let shut = again.db.audit_events(&crate::audit::Filter { actions: vec!["bot.run_dequeued".into()], ..Default::default() }, 10, true);
    assert_eq!(shut[0].details["result"], "shutdown", "{:?}", shut[0]);
}

#[tokio::test]
async fn an_asked_bot_runs_even_when_its_asker_holds_the_last_slot() {
    let app = runner::test_app();
    users::ensure_operator(&app.db, "Owner", None);
    app.run_cap.set(Some(1)).unwrap();
    let dir = app.cfg.data_dir.join("gate");
    gated_claude(&app, &dir);
    let (asker, asked) = (app.db.create_bot("Asker", "#fff", "waddle", "claude", None, false), app.db.create_bot("Asked", "#fff", "waddle", "claude", None, false));
    let m = app.db.add_message(&asker.id, "user", "ask the other one", None, false, Some("queued"));
    app.enqueue(m);
    until("the asker to start", || order(&dir).len() == 1).await;
    // As `botctl ask` does from inside the asker's run.
    let ask = {
        let app = app.clone();
        let (from, to) = (asker.clone(), asked.clone());
        tokio::spawn(async move { app.ask(&from, &to, "what's up?", Duration::from_secs(20), &crate::audit::Who::system("test")).await })
    };
    until("the asked Bot to start", || order(&dir).len() == 2).await;
    assert!(!waiting(&app, &asked.id));
    go(&dir, &asked.id);
    assert_eq!(ask.await.unwrap().as_deref(), Some("done"));
    go(&dir, &asker.id);
    until("both to finish", || !app.is_running(&asker.id) && !app.is_running(&asked.id)).await;
}

#[tokio::test]
async fn an_ask_lets_the_asked_bots_waiting_run_borrow_its_askers_slot() {
    let app = runner::test_app();
    users::ensure_operator(&app.db, "Owner", None);
    app.run_cap.set(Some(1)).unwrap();
    let dir = app.cfg.data_dir.join("gate");
    gated_claude(&app, &dir);
    let (asker, asked) = (app.db.create_bot("Asker", "#fff", "waddle", "claude", None, false), app.db.create_bot("Asked", "#fff", "waddle", "claude", None, false));
    app.enqueue(app.db.add_message(&asker.id, "user", "ask the other one", None, false, Some("queued")));
    until("the asker to start", || order(&dir).len() == 1).await;
    // The asked Bot already waits on its own run when the ask comes in behind it.
    app.enqueue(app.db.add_message(&asked.id, "user", "earlier", None, false, Some("queued")));
    until("the asked Bot to queue", || waiting(&app, &asked.id)).await;
    let ask = {
        let app = app.clone();
        let (from, to) = (asker.clone(), asked.clone());
        tokio::spawn(async move { app.ask(&from, &to, "what's up?", Duration::from_secs(20), &crate::audit::Who::system("test")).await })
    };
    until("the waiting run to borrow", || order(&dir).len() == 2).await;
    go(&dir, &asked.id);
    until("the ask to run", || order(&dir).len() == 3).await;
    go(&dir, &asked.id);
    assert_eq!(ask.await.unwrap().as_deref(), Some("done"));
    let lent = app.db.audit_events(&crate::audit::Filter { actions: vec!["bot.run_dequeued".into()], ..Default::default() }, 10, true);
    assert_eq!(lent[0].details["result"], "lent", "{:?}", lent[0]);
    go(&dir, &asker.id);
    until("both to finish", || !app.is_running(&asker.id) && !app.is_running(&asked.id)).await;
    assert_eq!(app.slots.load(SERVER), (0, 0));
}

#[tokio::test]
async fn a_run_whose_owner_is_turned_off_while_it_waits_never_starts() {
    let (port, app, admin, _) = serve_app().await;
    app.run_cap.set(Some(1)).unwrap();
    let dir = app.cfg.data_dir.join("gate");
    gated_claude(&app, &dir);
    let ada = app.db.create_user(None, Some("ada@example.com"), "Ada", crate::rbac::Role::Member).unwrap();
    let a = bot(&app, "Busy");
    let b = app.db.create_bot_owned("Ada's", "#fff", "waddle", "claude", None, false, &ada.id, Visibility::Private).id;
    say(port, &admin, &a, "busy").await;
    until("A to start", || order(&dir).len() == 1).await;
    app.enqueue(app.db.add_message(&b, "user", "later", None, false, Some("queued")));
    until("Ada's run to queue", || waiting(&app, &b)).await;
    app.db.update_user(&ada.id, db::UserPatch { status: Some("disabled"), ..Default::default() }).unwrap();
    let before = app.db.last_id();
    go(&dir, &a);
    until("Ada's Bot to say why", || !waiting(&app, &b) && !app.db.replies_after(&b, before).is_empty()).await;
    assert!(app.db.replies_after(&b, before)[0].text.contains("turned off"));
    let refused = audit(port, &admin, &format!("action=bot.run_refused&bot={b}")).await;
    assert_eq!(refused[0]["details"]["reason"], "owner_disabled", "{refused:?}");
    until("A to finish", || !app.is_running(&a)).await;
    assert_eq!(order(&dir), [a]);
    assert_eq!(app.slots.load(SERVER), (0, 0));
}

#[tokio::test]
async fn a_machines_cap_is_its_owners_tiers() {
    let mut env = serve_with(|e| e).await;
    let (uid, mid, token) = machine_for(&env, "ada@example.com").await;
    let tiers = r#"{ "default": "solo", "tiers": [
        { "name": "solo", "routes": "any", "limits": { "concurrentRuns": 1 } },
        { "name": "duo", "routes": "any", "limits": { "concurrentRuns": 2 } } ] }"#;
    env.app.tiers.set(Arc::new(Tiers::parse(tiers, None).unwrap())).unwrap();
    // The server's own cap doesn't apply to runs on a user's machine.
    env.app.run_cap.set(Some(1)).unwrap();
    let harness = r#"#!/bin/sh
echo "$BOT_ID" >> "$HOME/order"
while [ ! -e "$HOME/go-$BOT_ID" ]; do sleep 0.05; done
printf '%s\n' '{"type":"assistant","message":{"content":[{"type":"text","text":"done"}]}}'
"#;
    let m = agent_with(&mut env, &mid, &token, harness).await;
    let mk = |n: &str| env.app.db.create_bot_owned(n, "#fff", "waddle", "claude", None, false, &uid, Visibility::Private).id;
    let [a, b, c] = ["A", "B", "C"].map(mk);
    let started = |home: &std::path::Path| std::fs::read_to_string(home.join("order")).unwrap_or_default().lines().count();
    send(&env, &a, "one").await;
    until("A to start on the machine", || started(&m.home) == 1).await;
    send(&env, &b, "two").await;
    until("B to queue", || waiting(&env.app, &b)).await;
    assert_eq!(env.app.slots.load(&mid), (1, 1));
    let (code, list) = json_call(&env, "GET", "/api/bots", "").await;
    assert_eq!(code, 200);
    let v = list.as_array().unwrap().iter().find(|x| x["id"] == b.as_str()).unwrap().clone();
    assert_eq!(v["queued"], json!({ "reason": "at_capacity", "host": "machine", "position": 1, "running": 1, "limit": 1 }), "{v}");
    assert_eq!(v["status"], "Queued, next in line: its computer runs 1 task at once");
    let q = &wait_for_event(&env, "bot.run_queued").await[0];
    assert_eq!((q["details"]["host"].as_str(), q["details"]["machine"].as_str()), (Some("machine"), Some(mid.as_str())), "{q}");
    // A bigger plan applies to the next run: C goes in beside A, and lets B in first.
    let (code, r) = json_call(&env, "PATCH", &format!("/api/users/{uid}"), &json!({ "tier": "duo" }).to_string()).await;
    assert_eq!(code, 200, "{r}");
    send(&env, &c, "three").await;
    until("B to start", || started(&m.home) == 2).await;
    until("C to queue behind", || waiting(&env.app, &c)).await;
    for x in [&a, &b, &c] {
        std::fs::write(m.home.join(format!("go-{x}")), "").unwrap();
    }
    until("all three", || started(&m.home) == 3 && [&a, &b, &c].iter().all(|x| !env.app.is_running(x) && !waiting(&env.app, x))).await;
    assert_eq!(env.app.slots.load(&mid), (0, 0));
    assert_eq!(events(&env, "bot.run_dequeued").await.len(), 2);
}
