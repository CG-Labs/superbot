//! Isolated shared Bots (ADR 0046), on the real router: a teammate who uses someone
//! else's shared Bot reaches through it only what they could reach themselves. Not the
//! owner's other Bots, personal keys, or facts; not another user's machine. A disabled
//! owner's Bots don't run; routines run for whoever wrote them. Nothing talks to Linode.

use crate::acl::{SharedBots, Visibility};
use crate::machines::fake::Fake;
use crate::machines::provider::MachineProvider;
use crate::machines::route::recording::Recording;
use crate::machines::route::{MachineLink, Routing};
use crate::machines::ControlPlane;
use crate::tests::{audit_list, call, serve_app, serve_app_with, BotKey};
use crate::users_http_tests::{parse, user_with};
use crate::*;

const KEY: &str = "SHARED_ISO_KEY";

struct World {
    port: u16,
    app: AppState,
    admin: String,
    key: BotKey,
    a_id: String,
    a: String,
    b_id: String,
    b: String,
    /// Ada's personal key, and a fact only her USER.md holds.
    secret: String,
    fact: String,
}

impl Drop for World {
    fn drop(&mut self) {
        let _ = crate::secrets::global().user_forget(&self.a_id);
        crate::secrets::redact::forget_for(&self.a_id, &self.secret);
    }
}

async fn world(port: u16, app: AppState, admin: String, key: BotKey) -> World {
    let (a_id, a) = user_with(port, &admin, "ada@example.com", "member").await;
    let (b_id, b) = user_with(port, &admin, "bea@example.com", "member").await;
    let secret = format!("sk-ada-{}", crate::random_hex(10));
    crate::secrets::global().user_put(&a_id, KEY, &secret).unwrap();
    let fact = format!("ada-only-fact-{}", crate::random_hex(6));
    let facts = app.user_file(&a_id).unwrap();
    std::fs::create_dir_all(facts.parent().unwrap()).unwrap();
    std::fs::write(&facts, format!("# About the user\n- Bank: {fact}\n")).unwrap();
    fake_claude(&app, &fact);
    World { port, app, admin, key, a_id, a, b_id, b, secret, fact }
}

/// Self-hosted, with isolated shared Bots turned on.
async fn isolated() -> World {
    let (port, app, admin, key) = serve_app().await;
    app.shared_bots.set(SharedBots::Isolated).unwrap();
    world(port, app, admin, key).await
}

/// A stand-in `claude` that reports whether it got Ada's key, her fact, a list naming
/// her private Bot "Ledger", and the note that the run is for someone else.
fn fake_claude(app: &App, fact: &str) {
    use std::os::unix::fs::PermissionsExt;
    let script = r#"#!/bin/sh
case "$*" in *"Who's asking"*) asking=yes;; *) asking=no;; esac
case "$*" in *FACT*) facts=yes;; *) facts=no;; esac
case "$*" in *Ledger*) ledger=yes;; *) ledger=no;; esac
printf '%s\n' "{\"type\":\"assistant\",\"message\":{\"content\":[{\"type\":\"text\",\"text\":\"key=${KEY:-none} facts=$facts ledger=$ledger asking=$asking\"}]}}"
"#;
    let path = app.cfg.bin_dir.join("claude");
    std::fs::write(&path, script.replace("FACT", fact).replace("KEY", KEY)).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

async fn events(w: &World, q: &str) -> Vec<Value> {
    let (code, body) = call(w.port, "GET", &format!("/api/audit?{q}&limit=500"), &w.admin, "").await;
    assert_eq!(code, 200, "{body}");
    audit_list(&body)
}

async fn reply_after(w: &World, bot: &str, before: i64) -> String {
    for _ in 0..300 {
        if let Some(m) = w.app.db.replies_after(bot, before).into_iter().next() {
            return m.text;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("no reply from {bot}");
}

/// Sends `text` as `who` and waits for the Bot's reply.
async fn run(w: &World, who: &str, bot: &str, text: &str) -> String {
    let before = w.app.db.last_id();
    let (code, body) = call(w.port, "POST", &format!("/api/bots/{bot}/messages"), who, &json!({ "text": text }).to_string()).await;
    assert_eq!(code, 202, "{body}");
    reply_after(w, bot, before).await
}

fn bot(w: &World, name: &str, owner: &str, v: Visibility) -> crate::db::Bot {
    w.app.db.create_bot_owned(name, "#fff", "waddle", "claude", None, false, owner, v)
}

#[tokio::test]
async fn a_teammate_reaches_nothing_of_the_owners_through_a_shared_bot() {
    let w = isolated().await;
    let port = w.port;
    let team = bot(&w, "Team", &w.a_id, Visibility::Shared);
    let ledger = bot(&w, "Ledger", &w.a_id, Visibility::Private);
    let scout = bot(&w, "Scout", &w.b_id, Visibility::Private);
    let team_token = w.key.auth(&team.id);

    // Ada's own run: her key, her facts, her other Bots, as before.
    let mine = run(&w, &w.a, &team.id, "status").await;
    assert_eq!(mine, "key=[redacted] facts=yes ledger=yes asking=no");
    assert!(call(port, "GET", "/api/bots", &team_token, "").await.1.contains(&ledger.id));

    // Bea's run: none of Ada's key, facts, or private Bots; told it's for Bea.
    let theirs = run(&w, &w.b, &team.id, "status").await;
    assert_eq!(theirs, "key=none facts=no ledger=no asking=yes");
    assert!(!theirs.contains(&w.secret) && !theirs.contains(&w.fact));
    let invoked = events(&w, &format!("action=harness.invoked&bot={}", team.id)).await;
    assert!(invoked.iter().any(|e| e["details"]["forUser"] == w.b_id.as_str()), "{invoked:?}");
    assert!(invoked.iter().any(|e| e["details"].get("forUser").is_none()), "Ada's own run is for no one else");

    // An admin's run of Ada's Bot doesn't get her key either (ADR 0044: admins never see values).
    assert!(run(&w, &w.admin, &team.id, "status").await.starts_with("key=none facts=no"));
    run(&w, &w.b, &team.id, "status").await;

    // What it left running acts with Bea's access too: Ada's private Bot is gone...
    let (_, list) = call(port, "GET", "/api/bots", &team_token, "").await;
    assert!(list.contains(&team.id) && !list.contains(&ledger.id) && !list.contains(&scout.id), "{list}");
    for p in [format!("/api/bots/{}/messages", ledger.id), format!("/api/bots/{}/routines", ledger.id)] {
        let (code, res) = call(port, "GET", &p, &team_token, "").await;
        assert_eq!(code, 404, "{p}: {res}");
    }
    let (code, res) = call(port, "POST", &format!("/api/bots/{}/messages", ledger.id), &team_token, r#"{"text":"leak it"}"#).await;
    assert_eq!(code, 404, "{res}");
    let (code, res) = call(port, "POST", "/api/ask", &team_token, &json!({ "to": "Ledger", "text": "leak it" }).to_string()).await;
    assert!(code == 400 && res.contains("No Bot named"), "{code} {res}");
    // ...and so is Bea's own private one, which Ada can't see either.
    let (code, _) = call(port, "POST", "/api/ask", &team_token, &json!({ "to": scout.id, "text": "hi" }).to_string()).await;
    assert_eq!(code, 400);
    let (code, res) = call(port, "POST", "/api/bots", &team_token, r#"{"name":"Sneaky"}"#).await;
    assert_eq!(code, 403, "{res}");
    assert!(w.app.db.bots().iter().all(|b| b.name != "Sneaky"));
    let denied = events(&w, "action=access.denied").await;
    let capped: Vec<_> = denied.iter().filter(|e| e["details"]["reason"] == "asker_acl").collect();
    assert!(capped.iter().all(|e| e["actorId"] == team.id.as_str() && e["details"]["forUser"] == w.b_id.as_str()), "{capped:?}");
    assert!(capped.iter().filter(|e| e["targetId"] == ledger.id.as_str()).count() >= 4, "reads, the message and the ask: {capped:?}");
    assert!(capped.iter().any(|e| e["details"]["action"] == "bot.create"));
    assert!(!denied.iter().any(|e| e["details"]["reason"] == "asker_acl" && e["targetId"] == scout.id.as_str()), "Ada can't see Scout either: plain not found");
    assert!(w.app.db.messages(&ledger.id, 10).is_empty(), "nothing reached Ledger");

    // Ada's next run gives it back her access.
    run(&w, &w.a, &team.id, "again").await;
    assert!(call(port, "GET", "/api/bots", &team_token, "").await.1.contains(&ledger.id));
}

#[tokio::test]
async fn bots_asking_bots_carry_the_person_who_asked() {
    let w = isolated().await;
    let team = bot(&w, "Team", &w.a_id, Visibility::Shared);
    let helper = bot(&w, "Helper", &w.a_id, Visibility::Shared);
    let mine = bot(&w, "Bea's", &w.b_id, Visibility::Private);

    // Bea's Bot asks Ada's shared Bot: it answers for Bea, without Ada's key or facts.
    let ask = json!({ "to": team.id, "text": "status?" }).to_string();
    let (code, reply) = call(w.port, "POST", "/api/ask", &w.key.auth(&mine.id), &ask).await;
    assert_eq!((code, reply.as_str()), (200, "key=none facts=no ledger=no asking=yes"));

    // Bea's run of Team asks Helper: still for Bea, two Bots down.
    run(&w, &w.b, &team.id, "hi").await;
    let (code, reply) = call(w.port, "POST", "/api/ask", &w.key.auth(&team.id), &json!({ "to": "Helper", "text": "?" }).to_string()).await;
    assert_eq!((code, reply.as_str()), (200, "key=none facts=no ledger=no asking=yes"));
    let invoked = events(&w, &format!("action=harness.invoked&bot={}", helper.id)).await;
    assert!(invoked.iter().all(|e| e["details"]["forUser"] == w.b_id.as_str()), "{invoked:?}");

    // A late reply runs for whoever the question was for.
    let msg = w.app.db.add_message_from(&helper.id, "peer", "later", None, false, Some("queued"), Some(&team.id));
    let by = audit::Who { actor: audit::Actor { asker: Some(w.b_id.clone()), ..audit::Actor::for_bot(&team) }, source: Default::default() };
    w.app.db.set_requested_by(msg.id, &by);
    let before = w.app.db.last_id();
    w.app.enqueue(w.app.db.message(msg.id).unwrap());
    let reply = reply_after(&w, &team.id, before).await;
    assert_eq!(reply, "key=none facts=no ledger=no asking=yes", "the reply's run is Bea's too");
}

#[tokio::test]
async fn routines_run_for_whoever_wrote_them() {
    let w = isolated().await;
    let team = bot(&w, "Team", &w.a_id, Visibility::Shared);
    let path = format!("/api/bots/{}/routines", team.id);
    let (code, r) = call(w.port, "POST", &path, &w.b, r#"{"name":"Daily","cron":"0 9 * * *","instruction":"report"}"#).await;
    assert_eq!(code, 201, "{r}");
    let id = parse(&r)["id"].as_str().unwrap().to_string();
    assert_eq!(parse(&r)["author_id"], w.b_id.as_str());
    let created = events(&w, "action=routine.created").await;
    assert_eq!(created[0]["details"]["author"], w.b_id.as_str());

    let fire = async |w: &World| {
        let before = w.app.db.last_id();
        cron::fire(&w.app, &w.app.db.routine(&id).unwrap(), db::now());
        reply_after(w, &team.id, before).await
    };
    assert_eq!(fire(&w).await, "key=none facts=no ledger=no asking=yes", "Bea's routine runs for Bea");
    // Renaming or rescheduling it doesn't change whom it runs for; rewriting it does.
    let rpath = format!("/api/routines/{id}");
    assert_eq!(call(w.port, "PATCH", &rpath, &w.a, r#"{"cron":"0 10 * * *"}"#).await.0, 200);
    assert_eq!(w.app.db.routine(&id).unwrap().author_id.as_deref(), Some(w.b_id.as_str()));
    assert_eq!(call(w.port, "PATCH", &rpath, &w.a, r#"{"instruction":"report, Ada's way"}"#).await.0, 200);
    assert_eq!(w.app.db.routine(&id).unwrap().author_id.as_deref(), Some(w.a_id.as_str()));
    let updated = events(&w, "action=routine.updated").await;
    assert!(updated.iter().any(|e| e["details"]["changes"]["author"]["to"] == w.a_id.as_str()), "{updated:?}");
    assert_eq!(fire(&w).await, "key=[redacted] facts=yes ledger=no asking=no");

    // Bea's routine on a Bot she loses: it stops running, and says why.
    let granted = bot(&w, "Granted", &w.a_id, Visibility::Private);
    assert_eq!(call(w.port, "PUT", &format!("/api/bots/{}/grants/{}", granted.id, w.b_id), &w.a, r#"{"level":"operator"}"#).await.0, 200);
    let (_, r) = call(w.port, "POST", &format!("/api/bots/{}/routines", granted.id), &w.b, r#"{"name":"R","cron":"0 9 * * *","instruction":"x"}"#).await;
    let gone = w.app.db.routine(parse(&r)["id"].as_str().unwrap()).unwrap();
    assert_eq!(call(w.port, "DELETE", &format!("/api/bots/{}/grants/{}", granted.id, w.b_id), &w.a, "").await.0, 200);
    let before = w.app.db.last_id();
    cron::fire(&w.app, &gone, db::now());
    let said = reply_after(&w, &granted.id, before).await;
    assert!(said.contains("can no longer use me"), "{said}");
    let refused = events(&w, "action=bot.run_refused").await;
    assert!(refused.iter().any(|e| e["details"]["reason"] == "asker_lost_access" && e["details"]["forUser"] == w.b_id.as_str()), "{refused:?}");
}

#[tokio::test]
async fn a_disabled_owners_shared_bot_does_not_run_for_anyone() {
    let w = isolated().await;
    let team = bot(&w, "Team", &w.a_id, Visibility::Shared);
    let (_, r) = call(w.port, "POST", &format!("/api/bots/{}/routines", team.id), &w.a, r#"{"name":"R","cron":"0 9 * * *","instruction":"x"}"#).await;
    let routine = w.app.db.routine(parse(&r)["id"].as_str().unwrap()).unwrap();
    assert_eq!(call(w.port, "PATCH", &format!("/api/users/{}", w.a_id), &w.admin, r#"{"status":"disabled"}"#).await.0, 200);

    let said = run(&w, &w.b, &team.id, "status").await;
    assert!(said.contains("owner's account is turned off"), "{said}");
    // Its routine keeps firing but doesn't run, and says so once.
    for _ in 0..2 {
        cron::fire(&w.app, &routine, db::now());
    }
    tokio::time::sleep(Duration::from_millis(300)).await;
    let bubbles = w.app.db.messages(&team.id, 50).into_iter().filter(|m| m.text.contains("turned off")).count();
    assert_eq!(bubbles, 1, "one bubble, not one per firing");
    let refused = events(&w, "action=bot.run_refused").await;
    assert_eq!(refused.iter().filter(|e| e["details"]["reason"] == "owner_disabled").count(), 3);
    assert!(events(&w, &format!("action=harness.invoked&bot={}", team.id)).await.is_empty(), "nothing ran");
}

#[tokio::test]
async fn self_host_keeps_open_shared_bots_unless_asked() {
    let (port, app, admin, key) = serve_app().await;
    assert_eq!(app.shared_bots(), SharedBots::Open);
    let w = world(port, app, admin, key).await;
    let team = bot(&w, "Team", &w.a_id, Visibility::Shared);
    bot(&w, "Ledger", &w.a_id, Visibility::Private);
    assert_eq!(run(&w, &w.b, &team.id, "status").await, "key=[redacted] facts=yes ledger=yes asking=no", "as before ADR 0046");
    let (_, made) = call(port, "POST", "/api/bots", &w.b, r#"{"name":"Mine"}"#).await;
    assert_eq!(parse(&made)["visibility"], "shared");
    assert!(parse(&made).get("sharedBots").is_none() && parse(&made).get("runsOn").is_none(), "{made}");

    let w = isolated().await;
    let (_, made) = call(w.port, "POST", "/api/bots", &w.b, r#"{"name":"Mine"}"#).await;
    assert_eq!((parse(&made)["visibility"].as_str(), parse(&made)["sharedBots"].as_str()), (Some("private"), Some("isolated")), "{made}");
}

/// With routing on: Ada's machine is up, enrolled, and assigned; Bea has none.
async fn routed() -> (World, Arc<Recording>) {
    let link = Arc::new(Recording::default());
    let (p, l): (Arc<dyn MachineProvider>, Arc<dyn MachineLink>) = (Arc::new(Fake::default()), link.clone());
    let (port, app, owner, key) = serve_app_with(|a| {
        let mut cp = ControlPlane::for_tests(p);
        (cp.routing, cp.link) = (Routing::On, l);
        a.machines = Arc::new(cp);
    })
    .await;
    assert_eq!(app.shared_bots(), SharedBots::Isolated, "the default with routing on");
    let (_, admin) = user_with(port, &owner, "ops@example.com", "admin").await;
    let w = world(port, app, admin, key).await;
    assert_eq!(call(port, "POST", &format!("/api/users/{}/machine", w.a_id), &w.admin, "{}").await.0, 202);
    assert_eq!(call(port, "POST", "/api/machines/reconcile", &w.admin, "").await.0, 200);
    let machine = w.app.db.user_machine(&w.a_id).unwrap();
    crate::machines::route::recording::enroll(&w.app.db, &machine);
    assert_eq!(call(port, "PUT", &format!("/api/users/{}/placement", w.a_id), &w.admin, "").await.0, 200);
    (w, link)
}

#[tokio::test]
async fn with_routing_on_a_teammates_run_stays_on_the_owners_machine_without_their_keys() {
    let (w, link) = routed().await;
    let team = bot(&w, "Team", &w.a_id, Visibility::Shared);
    let mine = bot(&w, "Bea's", &w.b_id, Visibility::Private);
    let machine = w.app.db.user_machine(&w.a_id).unwrap();

    run(&w, &w.a, &team.id, "go").await;
    run(&w, &w.b, &team.id, "go").await;
    let sent = link.sent.lock().unwrap().clone();
    assert_eq!(sent.len(), 2);
    assert!(sent.iter().all(|(to, job)| to.machine_id == machine.id && to.user_id == w.a_id && job.owner_id == w.a_id), "Ada's machine, whoever asked");
    let (ada, bea) = (&sent[0].1, &sent[1].1);
    let user_file = crate::machines::route::recording::layout().user_file;
    assert_eq!(ada.env.get(KEY), Some(&w.secret), "Ada's own run gets her key");
    assert!(ada.collect.contains(&user_file) && ada.args.iter().any(|a| a.contains(&w.fact)));
    assert!(!bea.env.contains_key(KEY) && !bea.env.values().any(|v| v == &w.secret), "Bea's run gets none of Ada's keys");
    assert!(!bea.files.iter().any(|f| f.path == user_file || f.body.contains(&w.fact)), "nor her facts");
    assert!(!bea.collect.contains(&user_file), "nor brings back her facts");
    assert!(!bea.args.iter().any(|a| a.contains(&w.fact)) && bea.args.iter().any(|a| a.contains("Who's asking")));
    let routed = events(&w, "action=bot.run_routed").await;
    assert!(routed.iter().any(|e| e["details"]["forUser"] == w.b_id.as_str()), "{routed:?}");

    // Everyone who can see it sees where it runs.
    let (_, list) = call(w.port, "GET", "/api/bots", &w.b, "").await;
    let view = |id: &str| parse(&list).as_array().unwrap().iter().find(|b| b["id"] == id).cloned().unwrap();
    assert_eq!((view(&team.id)["runsOn"].as_str(), view(&team.id)["sharedBots"].as_str()), (Some("machine"), Some("isolated")), "{list}");
    assert_eq!(view(&mine.id)["runsOn"], "nowhere", "{list}");

    // Bea's own Bot never borrows Ada's machine.
    let said = run(&w, &w.b, &mine.id, "hi").await;
    assert!(said.contains("you don't have a computer"), "{said}");
    assert_eq!(link.sent.lock().unwrap().len(), 2);

    // Ada's machine offline: Bea learns whose computer it is, not its errors.
    *link.heartbeat.lock().unwrap() = Err("connection refused at 192.0.2.7".into());
    let said = run(&w, &w.b, &team.id, "hi").await;
    let ada_name = w.app.db.user(&w.a_id).unwrap().name;
    assert!(said.contains(&format!("I run on {ada_name}'s computer")), "{said}");
    assert!(!said.contains("connection refused") && !said.contains("192.0.2.7"), "{said}");
    let refused = events(&w, "action=bot.run_refused").await;
    assert!(refused.iter().any(|e| e["details"]["reason"] == "machine_offline" && e["details"]["forUser"] == w.b_id.as_str()), "{refused:?}");

    // SHARED_BOTS=open can't be used with routing on.
    assert!(SharedBots::parse("open", true).is_err());
}
