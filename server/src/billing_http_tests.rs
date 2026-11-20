//! Billing v0 (ADR 0040) on the real router: each tier's limits on Bots, routine runs a
//! day, and machine size hold per user, are refused in plain words, and are audited;
//! admins see everyone's use against their limits; and Stripe's signed webhook, off
//! unless its secret is set, sets a user's tier from their subscription. Nothing here
//! talks to Stripe or Linode: Stripe events are fixtures, machines the fake provider.

use crate::acl::Visibility;
use crate::billing::{self, Billing};
use crate::machines::ControlPlane;
use crate::machines::fake::Fake;
use crate::machines::provider::MachineProvider;
use crate::tests::{audit_list, call, call_with, serve_app, serve_app_with};
use crate::tiers::{Tiers, EXAMPLE};
use crate::tiers_http_tests::{fake_claude, run};
use crate::users_http_tests::{parse, user_with};
use crate::*;

const SECRET: &str = "whsec_test_not_a_real_secret";
const UPDATED: &str = include_str!("../tests/fixtures/stripe/customer.subscription.updated.json");
const DELETED: &str = include_str!("../tests/fixtures/stripe/customer.subscription.deleted.json");

struct World {
    port: u16,
    app: AppState,
    admin: String,
    a_id: String,
    a: String,
    b_id: String,
    b: String,
    bots: crate::tests::BotKey,
}

/// A server on the example tiers (starter: 2 Bots, 3 runs a month, 2 routine runs a
/// day, g6-standard-1 machines), the fake machine provider, Ada and Bea (members), and
/// with `stripe`, the webhook on.
async fn world(stripe: bool) -> World {
    world_with(stripe.then(|| Billing::with_secret(SECRET))).await
}

async fn world_with(payments: Option<Billing>) -> World {
    let p: Arc<dyn MachineProvider> = Arc::new(Fake::default());
    let (port, app, admin, bots) = serve_app_with(|a| {
        a.machines = Arc::new(ControlPlane::for_tests(p));
        if let Some(b) = payments {
            a.payments = b;
        }
    })
    .await;
    app.tiers.set(Arc::new(Tiers::parse(EXAMPLE, None).unwrap())).unwrap();
    let (a_id, a) = user_with(port, &admin, "ada@example.com", "member").await;
    let (b_id, b) = user_with(port, &admin, "bea@example.com", "member").await;
    fake_claude(&app);
    World { port, app, admin, a_id, a, b_id, b, bots }
}

async fn audit(port: u16, admin: &str, q: &str) -> Vec<Value> {
    let (code, body) = call(port, "GET", &format!("/api/audit?{q}&limit=500"), admin, "").await;
    assert_eq!(code, 200, "{body}");
    audit_list(&body)
}

async fn set_tier(w: &World, user: &str, tier: Value) {
    let (code, body) = call(w.port, "PATCH", &format!("/api/users/{user}"), &w.admin, &json!({ "tier": tier }).to_string()).await;
    assert_eq!(code, 200, "{body}");
}

/// Waits until `bot` has `n` replies after message `after`.
async fn replies(app: &App, bot: &str, after: i64, n: usize) -> Vec<String> {
    for _ in 0..300 {
        let got = app.db.replies_after(bot, after);
        if got.len() >= n && !app.is_running(bot) {
            return got.into_iter().map(|m| m.text).collect();
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("{bot} didn't reply {n} times");
}

#[tokio::test]
async fn routine_runs_hold_per_user_per_day() {
    let w = world(false).await;
    let app = &w.app;
    let bot = app.db.create_bot_owned("Daily", "#fff", "waddle", "claude", None, false, &w.a_id, Visibility::Private);
    let r = app.db.add_routine(&bot.id, "Digest", "0 9 * * *", "Sum up my email");
    let before = app.db.last_id();
    let now = db::now();
    // Starter: 2 routine runs a day. Both run.
    cron::fire(app, &r, now);
    cron::fire(app, &r, now);
    let said = replies(app, &bot.id, before, 2).await;
    assert!(said.iter().all(|t| t.starts_with("model=claude-haiku-4-5")), "{said:?}");
    // The third and fourth are refused: audited each time, said once.
    cron::fire(app, &r, now);
    cron::fire(app, &r, now);
    let refused = audit(w.port, &w.admin, &format!("action=routine.run_refused&bot={}", bot.id)).await;
    assert_eq!(refused.len(), 2, "{refused:?}");
    let d = &refused[0]["details"];
    assert_eq!((d["reason"].as_str(), d["limit"].as_u64(), d["tier"].as_str(), d["owner"].as_str()), (Some("tier_routine_limit"), Some(2), Some("starter"), Some(w.a_id.as_str())));
    assert_eq!((refused[0]["outcome"].as_str(), refused[0]["onBehalfOf"].as_str()), (Some("denied"), Some(w.a_id.as_str())), "{:?}", refused[0]);
    assert_eq!(audit(w.port, &w.admin, &format!("action=routine.fired&bot={}", bot.id)).await.len(), 2);
    let errors: Vec<String> = app.db.messages(&bot.id, 50).into_iter().filter(|m| m.error).map(|m| m.text).collect();
    assert_eq!(errors.len(), 1, "{errors:?}");
    assert!(errors[0].contains("Starter plan allows 2 routine runs a day") && errors[0].contains("\"Digest\""), "{}", errors[0]);
    // No routine message was queued for the refused ones.
    assert_eq!(app.db.messages(&bot.id, 50).iter().filter(|m| m.role == "routine").count(), 2);

    // Ada sees it on her plan; Bea's day is her own.
    let (_, mine) = call(w.port, "GET", "/api/me/tier", &w.a, "").await;
    let mine = parse(&mine);
    assert_eq!((mine["usage"]["routineRuns"].as_u64(), mine["usage"]["day"].as_str()), (Some(2), Some(tiers::day(now).as_str())));
    assert_eq!(mine["limits"]["dailyRoutineRuns"], 2);
    let hers = app.db.create_bot_owned("Hers", "#fff", "waddle", "claude", None, false, &w.b_id, Visibility::Private);
    let hr = app.db.add_routine(&hers.id, "Hers", "0 9 * * *", "x");
    let before = app.db.last_id();
    cron::fire(app, &hr, now);
    replies(app, &hers.id, before, 1).await;
    // A routine run whose run is refused anyway (here, Bea's monthly runs are used up)
    // is given back.
    for _ in 0..2 {
        app.db.take_run(&w.b_id, &tiers::period(now), Some(3)).unwrap();
    }
    assert_eq!(app.db.routine_runs_used(&w.b_id, &tiers::day(now)), 1);
    let before = app.db.last_id();
    cron::fire(app, &hr, now);
    for _ in 0..300 {
        if app.db.messages(&hers.id, 50).iter().any(|m| m.id > before && m.error) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let refused = audit(w.port, &w.admin, &format!("action=bot.run_refused&bot={}", hers.id)).await;
    assert_eq!(refused[0]["details"]["reason"], "tier_limit", "{refused:?}");
    assert_eq!(app.db.routine_runs_used(&w.b_id, &tiers::day(now)), 1, "given back");
    // The next day starts again, and a plan without the limit has none.
    let tomorrow = now + 86_400_000;
    assert!(app.db.take_routine_run(&w.a_id, &tiers::day(tomorrow), Some(2)).is_ok());
    set_tier(&w, &w.a_id, json!("pro")).await;
    for _ in 0..5 {
        cron::fire(app, &r, now);
    }
    assert_eq!(audit(w.port, &w.admin, &format!("action=routine.run_refused&bot={}", bot.id)).await.len(), 2);
}

#[tokio::test]
async fn stopping_a_bot_gives_back_its_queued_routine_runs() {
    use std::os::unix::fs::PermissionsExt;
    let w = world(false).await;
    let app = &w.app;
    let slow = app.cfg.bin_dir.join("claude");
    std::fs::write(&slow, "#!/bin/sh\nexec sleep 10\n").unwrap();
    std::fs::set_permissions(&slow, std::fs::Permissions::from_mode(0o755)).unwrap();
    let bot = app.db.create_bot_owned("Slow", "#fff", "waddle", "claude", None, false, &w.a_id, Visibility::Private);
    let r = app.db.add_routine(&bot.id, "Digest", "0 9 * * *", "x");
    let now = db::now();
    // One runs, the second waits behind it; both count.
    cron::fire(app, &r, now);
    for _ in 0..300 {
        if app.is_running(&bot.id) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    cron::fire(app, &r, now);
    assert_eq!(app.db.routine_runs_used(&w.a_id, &tiers::day(now)), 2);
    // Stop drops the waiting one, so it doesn't count; the one that ran does.
    assert_eq!(call(w.port, "POST", &format!("/api/bots/{}/stop", bot.id), &w.a, "").await.0, 200);
    assert_eq!(app.db.routine_runs_used(&w.a_id, &tiers::day(now)), 1);
}

#[tokio::test]
async fn a_transfer_gives_queued_routine_runs_back_to_the_old_owner() {
    use std::os::unix::fs::PermissionsExt;
    let w = world(false).await;
    let app = &w.app;
    let slow = app.cfg.bin_dir.join("claude");
    std::fs::write(&slow, "#!/bin/sh\nexec sleep 10\n").unwrap();
    std::fs::set_permissions(&slow, std::fs::Permissions::from_mode(0o755)).unwrap();
    let bot = app.db.create_bot_owned("Slow", "#fff", "waddle", "claude", None, false, &w.a_id, Visibility::Private);
    let r = app.db.add_routine(&bot.id, "Digest", "0 9 * * *", "x");
    let (now, day) = (db::now(), tiers::day(db::now()));
    cron::fire(app, &r, now);
    for _ in 0..300 {
        if app.is_running(&bot.id) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    cron::fire(app, &r, now);
    app.db.take_routine_run(&w.b_id, &day, Some(2)).unwrap();
    // Given to Bea while a routine waits: Ada, who was charged for it, gets it back.
    let (code, body) = call(w.port, "PATCH", &format!("/api/bots/{}/access", bot.id), &w.admin, &json!({ "owner": w.b_id }).to_string()).await;
    assert_eq!(code, 200, "{body}");
    assert_eq!(app.db.routine_runs_used(&w.a_id, &day), 1);
    assert_eq!(app.db.routine_runs_used(&w.b_id, &day), 1, "Bea's own run is untouched");
}

#[tokio::test]
async fn a_routine_whose_bot_cant_start_gives_back_its_run() {
    let w = world(false).await;
    let app = &w.app;
    let bot = app.db.create_bot_owned("Gone", "#fff", "waddle", "no-such-harness", None, false, &w.a_id, Visibility::Private);
    let r = app.db.add_routine(&bot.id, "Digest", "0 9 * * *", "x");
    let now = db::now();
    let before = app.db.last_id();
    cron::fire(app, &r, now);
    let said = replies(app, &bot.id, before, 1).await;
    assert!(said[0].contains("Unknown harness"), "{said:?}");
    assert_eq!(app.db.routine_runs_used(&w.a_id, &tiers::day(now)), 0);
}

#[tokio::test]
async fn without_a_tiers_file_routines_bots_and_machines_are_unlimited() {
    let (port, app, admin, _) = serve_app().await;
    fake_claude(&app);
    let bot = app.db.create_bot("Busy", "#fff", "waddle", "claude", None, false);
    let r = app.db.add_routine(&bot.id, "Often", "* * * * *", "x");
    for _ in 0..6 {
        cron::fire(&app, &r, db::now());
    }
    assert_eq!(audit(port, &admin, "action=routine.fired").await.len(), 6);
    assert!(audit(port, &admin, "action=routine.run_refused").await.is_empty());
    for n in 0..5 {
        assert_eq!(call(port, "POST", "/api/bots", &admin, &json!({ "name": format!("B{n}") }).to_string()).await.0, 201);
    }
    let l = &app.tier_of(users::OPERATOR).limits;
    assert_eq!((l.max_bots, l.daily_routine_runs, l.machine_type.as_deref()), (None, None, None));
}

#[tokio::test]
async fn bot_limit_refusals_are_audited() {
    let w = world(false).await;
    for n in ["One", "Two"] {
        assert_eq!(call(w.port, "POST", "/api/bots", &w.a, &json!({ "name": n }).to_string()).await.0, 201);
    }
    let (code, res) = call(w.port, "POST", "/api/bots", &w.a, r#"{"name":"Three"}"#).await;
    assert_eq!(code, 403);
    assert!(res.contains("The Starter plan allows 2 Bots"), "{res}");
    let ev = audit(w.port, &w.admin, "action=bot.create_refused").await;
    assert_eq!(ev.len(), 1, "{ev:?}");
    assert_eq!((ev[0]["details"]["reason"].as_str(), ev[0]["details"]["limit"].as_u64(), ev[0]["targetId"].as_str()), (Some("tier_bot_limit"), Some(2), Some(w.a_id.as_str())));
    assert_eq!(ev[0]["outcome"], "denied");
    // Handing Ada a third is refused and audited too.
    let spare = w.app.db.create_bot_owned("Spare", "#fff", "waddle", "claude", None, false, &w.b_id, Visibility::Private);
    let (code, _) = call(w.port, "PATCH", &format!("/api/bots/{}/access", spare.id), &w.admin, &json!({ "owner": w.a_id }).to_string()).await;
    assert_eq!(code, 403);
    let ev = audit(w.port, &w.admin, "action=bot.transfer_refused").await;
    assert_eq!((ev.len(), ev[0]["details"]["to"].as_str(), ev[0]["details"]["reason"].as_str()), (1, Some(w.a_id.as_str()), Some("tier_bot_limit")));
}

#[tokio::test]
async fn machines_get_their_owners_plan_size() {
    let w = world(false).await;
    let (port, admin) = (w.port, &w.admin);
    let machine = |u: &str| format!("/api/users/{u}/machine");
    // Starter's machines are g6-standard-1 (MACHINE_TIERS' starter). Asking for pro's is refused.
    let (code, res) = call(port, "POST", &machine(&w.b_id), admin, r#"{"tier":"pro"}"#).await;
    assert_eq!(code, 403, "{res}");
    assert!(res.contains("plan (Starter) comes with g6-standard-1 machines, not g6-standard-2"), "{res}");
    assert!(w.app.db.user_machine(&w.b_id).is_none(), "nothing provisioned");
    let ev = audit(port, admin, "action=machine.refused").await;
    let d = &ev[0]["details"];
    assert_eq!((d["reason"].as_str(), d["action"].as_str(), d["askedPlan"].as_str(), d["allowedPlan"].as_str()), (Some("tier_machine_size"), Some("request"), Some("g6-standard-2"), Some("g6-standard-1")));
    assert_eq!((ev[0]["outcome"].as_str(), ev[0]["targetId"].as_str()), (Some("denied"), Some(w.b_id.as_str())));
    // Without a tier it gets the plan's size; asking for it by name works too.
    let (code, res) = call(port, "POST", &machine(&w.b_id), admin, "{}").await;
    assert_eq!(code, 202, "{res}");
    let m = w.app.db.user_machine(&w.b_id).unwrap();
    assert_eq!((m.tier.as_str(), m.plan.as_str()), ("starter", "g6-standard-1"));
    assert_eq!(call(port, "POST", &machine(&w.a_id), admin, r#"{"tier":"starter"}"#).await.0, 202);
    // Resizing past the plan is refused; once the plan allows it, it goes through.
    let (code, res) = call(port, "POST", &format!("{}/resize", machine(&w.a_id)), admin, r#"{"tier":"max"}"#).await;
    assert_eq!(code, 403, "{res}");
    assert_eq!(audit(port, admin, "action=machine.refused").await[0]["details"]["action"], "resize");
    assert_eq!(w.app.db.user_machine(&w.a_id).unwrap().plan, "g6-standard-1");
    set_tier(&w, &w.a_id, json!("pro")).await;
    assert_eq!(call(port, "POST", "/api/machines/reconcile", admin, "").await.0, 200);
    let (code, res) = call(port, "POST", &format!("{}/resize", machine(&w.a_id)), admin, r#"{"tier":"max"}"#).await;
    assert_eq!(code, 200, "{res}");
    assert_eq!(w.app.db.user_machine(&w.a_id).unwrap().plan, "g6-standard-4");
    // A plan's size that MACHINE_TIERS doesn't list is named after the plan.
    let solo = r#"{"tiers":[{"name":"solo","label":"Solo","routes":"any","limits":{"machineType":"g6-nanode-1"}}]}"#;
    let (port2, app2, owner2, _) = {
        let p: Arc<dyn MachineProvider> = Arc::new(Fake::default());
        serve_app_with(|a| a.machines = Arc::new(ControlPlane::for_tests(p))).await
    };
    app2.tiers.set(Arc::new(Tiers::parse(solo, None).unwrap())).unwrap();
    let (code, res) = call(port2, "POST", &machine(users::OPERATOR), &owner2, r#"{"tier":"pro"}"#).await;
    assert_eq!(code, 403, "{res}");
    assert_eq!(call(port2, "POST", &machine(users::OPERATOR), &owner2, "{}").await.0, 202);
    let m = app2.db.user_machine(users::OPERATOR).unwrap();
    assert_eq!((m.tier.as_str(), m.plan.as_str()), ("solo", "g6-nanode-1"));
    let (code, res) = call(port2, "POST", &format!("{}/resize", machine(users::OPERATOR)), &owner2, r#"{"tier":"nope"}"#).await;
    assert_eq!(code, 400);
    assert!(res.contains("starter, pro, max, solo"), "{res}");
    // A plan named like a MACHINE_TIERS entry of another size: asking for it by name gets the plan's size.
    let clash = r#"{"tiers":[{"name":"starter","label":"Starter","routes":"any","limits":{"machineType":"g6-dedicated-2"}}]}"#;
    let (port3, app3, owner3, _) = {
        let p: Arc<dyn MachineProvider> = Arc::new(Fake::default());
        serve_app_with(|a| a.machines = Arc::new(ControlPlane::for_tests(p))).await
    };
    app3.tiers.set(Arc::new(Tiers::parse(clash, None).unwrap())).unwrap();
    let (code, res) = call(port3, "POST", &machine(users::OPERATOR), &owner3, r#"{"tier":"starter"}"#).await;
    assert_eq!(code, 202, "{res}");
    let m = app3.db.user_machine(users::OPERATOR).unwrap();
    assert_eq!((m.tier.as_str(), m.plan.as_str()), ("starter", "g6-dedicated-2"));
}

#[tokio::test]
async fn admins_see_everyones_use_against_their_limits() {
    let w = world(false).await;
    let (port, admin) = (w.port, &w.admin);
    assert_eq!(call(port, "GET", "/api/usage", &w.a, "").await.0, 403);
    // Ada on pro makes 3 Bots and a pro-sized machine, then drops to starter.
    set_tier(&w, &w.a_id, json!("pro")).await;
    for n in ["One", "Two", "Three"] {
        assert_eq!(call(port, "POST", "/api/bots", &w.a, &json!({ "name": n }).to_string()).await.0, 201);
    }
    assert_eq!(call(port, "POST", &format!("/api/users/{}/machine", w.a_id), admin, r#"{"tier":"pro"}"#).await.0, 202);
    set_tier(&w, &w.a_id, Value::Null).await;
    let bot = w.app.db.create_bot_owned("Hers", "#fff", "waddle", "claude", None, false, &w.b_id, Visibility::Private);
    assert!(run(port, &w.app, &w.b, &bot.id).await.starts_with("model="));

    let (code, body) = call(port, "GET", "/api/usage", admin, "").await;
    assert_eq!(code, 200, "{body}");
    let v = parse(&body);
    assert_eq!(v["billing"], false);
    let find = |id: &str| v["users"].as_array().unwrap().iter().find(|u| u["user"]["id"] == id).unwrap().clone();
    let ada = find(&w.a_id);
    assert_eq!((ada["plan"]["name"].as_str(), ada["plan"]["usage"]["bots"].as_u64(), ada["plan"]["limits"]["maxBots"].as_u64()), (Some("starter"), Some(3), Some(2)));
    assert_eq!(ada["over"], json!(["bots", "machineType"]));
    assert_eq!((ada["machine"]["plan"].as_str(), ada["machine"]["fits"].as_bool()), (Some("g6-standard-2"), Some(false)));
    assert!(ada["plan"].get("routes").is_none() && !body.contains("claude-haiku"), "no model names: {body}");
    let bea = find(&w.b_id);
    assert_eq!((bea["plan"]["usage"]["runs"].as_u64(), bea["over"].clone(), bea["machine"].clone()), (Some(1), json!([]), Value::Null));
    // The admin portal's user view has the same use, and botctl reads it.
    let (_, user) = call(port, "GET", &format!("/api/users/{}", w.a_id), admin, "").await;
    assert_eq!(parse(&user)["plan"]["usage"]["routineRuns"], 0);
}

/// A fixture event with its user, id, creation time, and anything else changed.
fn event(fixture: &str, user: &str, id: &str, created: i64, f: impl FnOnce(&mut Value)) -> String {
    let mut v: Value = serde_json::from_str(&fixture.replace("{{USER_ID}}", user)).unwrap();
    v["id"] = json!(id);
    v["created"] = json!(created);
    f(&mut v);
    v.to_string()
}

/// Delivers `body` as Stripe does, signed now; `sign` may change the header.
async fn deliver(port: u16, body: &str, header: Option<String>) -> (u16, Value) {
    let header = header.unwrap_or_else(|| billing::sign(SECRET, body.as_bytes(), db::now() / 1000));
    let (code, _, res) = call_with(port, "POST", billing::PATH, "", &format!("Stripe-Signature: {header}\r\n"), body).await;
    (code, serde_json::from_str(&res).unwrap_or(Value::Null))
}

#[tokio::test]
async fn the_webhook_is_off_without_its_secret() {
    let w = world(false).await;
    let body = event(UPDATED, &w.a_id, "evt_1", 1_795_000_000, |_| {});
    let (code, res) = deliver(w.port, &body, None).await;
    assert_eq!(code, 404, "{res}");
    assert_eq!(w.app.db.user(&w.a_id).unwrap().tier, None);
    assert!(w.app.db.subscription(&w.a_id).is_none());
}

#[tokio::test]
async fn signed_subscription_events_set_the_users_tier() {
    let w = world(true).await;
    let (port, app, admin) = (w.port, &w.app, &w.admin);
    let tier = |u: &str| app.db.user(u).unwrap().tier;
    let body = event(UPDATED, &w.a_id, "evt_1", 1_795_000_000, |_| {});

    // Not Stripe: no signature, another secret's, an old one, or junk. Refused and audited.
    let now = db::now() / 1000;
    for (header, reason) in [
        (String::new(), "no_timestamp"),
        (billing::sign("whsec_someone_else", body.as_bytes(), now), "bad_signature"),
        (billing::sign(SECRET, body.as_bytes(), now - 3600), "too_old"),
        (billing::sign(SECRET, b"{}", now), "bad_signature"),
    ] {
        let (code, res) = deliver(port, &body, Some(header)).await;
        assert_eq!(code, 400, "{reason}: {res}");
        let ev = audit(port, admin, "action=billing.webhook_refused").await;
        assert_eq!(ev[0]["details"]["reason"], reason);
    }
    let junk = "not json";
    assert_eq!(deliver(port, junk, None).await.0, 400);
    assert_eq!(tier(&w.a_id), None, "nothing changed");

    // An active subscription to a pro price: Ada is on pro, audited as billing for her.
    let (code, res) = deliver(port, &body, None).await;
    assert_eq!((code, res["outcome"].as_str()), (200, Some("tier_changed")), "{res}");
    assert_eq!(tier(&w.a_id).as_deref(), Some("pro"));
    let changed = audit(port, admin, "action=user.tier_changed").await;
    let c = &changed[0];
    assert_eq!((c["actorId"].as_str(), c["onBehalfOf"].as_str(), c["targetId"].as_str()), (Some("billing"), Some(w.a_id.as_str()), Some(w.a_id.as_str())), "{c}");
    assert_eq!((c["details"]["from"].clone(), c["details"]["to"].as_str(), c["details"]["effectiveFrom"].as_str()), (Value::Null, Some("pro"), Some("starter")));
    assert_eq!((c["details"]["source"].as_str(), c["details"]["subscription"].as_str()), (Some("stripe"), Some("sub_test_ada")));
    let sub = app.db.subscription(&w.a_id).unwrap();
    assert_eq!((sub.status.as_str(), sub.price_id.as_deref(), sub.customer_id.as_deref(), sub.period_end), ("active", Some("price_pro_monthly"), Some("cus_test_ada"), Some(1_797_582_000)));
    // Ada's limits are pro's at once.
    let (_, mine) = call(port, "GET", "/api/me/tier", &w.a, "").await;
    assert_eq!(parse(&mine)["name"], "pro");

    // Redelivered: nothing more happens.
    let (code, res) = deliver(port, &body, None).await;
    assert_eq!((code, res["outcome"].as_str()), (200, Some("duplicate")));
    assert_eq!(audit(port, admin, "action=user.tier_changed").await.len(), 1);
    // Older than the last one applied (Stripe doesn't promise order): ignored.
    let stale = event(UPDATED, &w.a_id, "evt_0", 1_794_999_000, |v| v["data"]["object"]["status"] = json!("canceled"));
    assert_eq!(deliver(port, &stale, None).await.1["outcome"], "stale");
    assert_eq!(tier(&w.a_id).as_deref(), Some("pro"));
    // A price no tier lists: ignored and audited, the tier stays.
    let unknown = event(UPDATED, &w.a_id, "evt_2", 1_795_000_100, |v| v["data"]["object"]["items"]["data"][0]["price"]["id"] = json!("price_unlisted"));
    assert_eq!(deliver(port, &unknown, None).await.1["outcome"], "ignored");
    assert_eq!(audit(port, admin, "action=billing.event_ignored").await[0]["details"]["reason"], "unknown_price");
    assert_eq!(tier(&w.a_id).as_deref(), Some("pro"));
    // Events Stripe sends that botd doesn't use are fine.
    let invoice = json!({ "id": "evt_inv", "type": "invoice.paid", "created": 1_795_000_200, "data": { "object": {} } }).to_string();
    assert_eq!(deliver(port, &invoice, None).await, (200, json!({ "received": true, "outcome": "ignored" })));
    // An admin may still change it (support, comps) until the next event.
    set_tier(&w, &w.a_id, json!("self-host")).await;

    // Cancelled: back to the default tier. Even without its metadata, the subscription
    // already names her.
    let deleted = event(DELETED, &w.a_id, "evt_3", 1_795_100_000, |v| v["data"]["object"]["metadata"] = json!({}));
    let (code, res) = deliver(port, &deleted, None).await;
    assert_eq!((code, res["outcome"].as_str()), (200, Some("tier_changed")), "{res}");
    assert_eq!(tier(&w.a_id), None);
    let c = &audit(port, admin, "action=user.tier_changed").await[0];
    assert_eq!((c["details"]["from"].as_str(), c["details"]["effectiveTo"].as_str()), (Some("self-host"), Some("starter")));
    assert_eq!(app.db.subscription(&w.a_id).unwrap().status, "canceled");

    // Someone nobody knows, or another user's subscription: ignored.
    let nobody = event(UPDATED, "u-nobody", "evt_4", 1_795_200_000, |v| v["data"]["object"]["id"] = json!("sub_test_x"));
    assert_eq!(deliver(port, &nobody, None).await.1["outcome"], "ignored");
    assert_eq!(audit(port, admin, "action=billing.event_ignored").await[0]["details"]["reason"], "unknown_user");
    let theft = event(UPDATED, &w.b_id, "evt_5", 1_795_200_000, |_| {});
    assert_eq!(deliver(port, &theft, None).await.1["outcome"], "ignored");
    assert_eq!(audit(port, admin, "action=billing.event_ignored").await[0]["details"]["reason"], "subscription_of_another_user");
    assert_eq!((tier(&w.a_id), tier(&w.b_id)), (None, None));

    // Bea's own subscriptions, under her own customer.
    let bea = |v: &mut Value, id: &str| {
        v["data"]["object"]["id"] = json!(id);
        v["data"]["object"]["customer"] = json!("cus_test_bea");
    };
    // Bea moves to a subscription started after her first. The old one's events, late or
    // not, don't undo the move. One whose first payment hasn't gone through changes nothing.
    let pro = event(UPDATED, &w.b_id, "evt_6", 1_795_300_000, |v| bea(v, "sub_test_bea_1"));
    assert_eq!(deliver(port, &pro, None).await.1["outcome"], "tier_changed");
    let starter = event(UPDATED, &w.b_id, "evt_7", 1_795_300_100, |v| {
        bea(v, "sub_test_bea_2");
        v["data"]["object"]["created"] = json!(1_795_300_090);
        v["data"]["object"]["items"]["data"][0]["price"]["id"] = json!("price_starter_monthly");
    });
    assert_eq!(deliver(port, &starter, None).await.1["outcome"], "tier_changed");
    assert_eq!(tier(&w.b_id).as_deref(), Some("starter"));
    // An update to the old one made after the move, still active: recorded, but the newer plan stands.
    let late = event(UPDATED, &w.b_id, "evt_8a", 1_795_300_150, |v| bea(v, "sub_test_bea_1"));
    assert_eq!(deliver(port, &late, None).await.1["outcome"], "superseded");
    assert_eq!(tier(&w.b_id).as_deref(), Some("starter"));
    let old_gone = event(DELETED, &w.b_id, "evt_8", 1_795_300_200, |v| bea(v, "sub_test_bea_1"));
    assert_eq!(deliver(port, &old_gone, None).await.1["outcome"], "superseded");
    assert_eq!(tier(&w.b_id).as_deref(), Some("starter"));
    // One from before that cancellation, arriving after it, is stale.
    let later = event(UPDATED, &w.b_id, "evt_8b", 1_795_300_180, |v| bea(v, "sub_test_bea_1"));
    assert_eq!(deliver(port, &later, None).await.1["outcome"], "stale");
    assert_eq!(tier(&w.b_id).as_deref(), Some("starter"));
    assert_eq!(app.db.subscription(&w.b_id).unwrap().subscription_id, "sub_test_bea_2");
    // Ada's old plan is cancelled after her new one starts, but the cancellation arrives
    // first: the new one still applies.
    let cancelled = event(DELETED, &w.a_id, "evt_10", 1_795_400_100, |_| {});
    assert_eq!(deliver(port, &cancelled, None).await.1["outcome"], "unchanged");
    let replacement = event(UPDATED, &w.a_id, "evt_11", 1_795_400_000, |v| {
        v["data"]["object"]["id"] = json!("sub_test_ada_2");
        v["data"]["object"]["created"] = json!(1_795_399_000);
    });
    assert_eq!(deliver(port, &replacement, None).await.1["outcome"], "tier_changed");
    assert_eq!(tier(&w.a_id).as_deref(), Some("pro"));
    // Once the new one ends too, a late active event for the old one doesn't bring it back.
    let new_gone = event(DELETED, &w.a_id, "evt_12", 1_795_500_000, |v| v["data"]["object"]["id"] = json!("sub_test_ada_2"));
    assert_eq!(deliver(port, &new_gone, None).await.1["outcome"], "tier_changed");
    let old_late = event(UPDATED, &w.a_id, "evt_13", 1_795_400_050, |_| {});
    assert_eq!(deliver(port, &old_late, None).await.1["outcome"], "stale");
    assert_eq!(tier(&w.a_id), None);
    let incomplete = event(UPDATED, &w.b_id, "evt_9", 1_795_300_300, |v| {
        bea(v, "sub_test_bea_2");
        v["data"]["object"]["status"] = json!("incomplete");
    });
    assert_eq!(deliver(port, &incomplete, None).await.1["outcome"], "unchanged");
    assert_eq!(tier(&w.b_id).as_deref(), Some("starter"));

    // Admins see each subscription with the use.
    let (_, usage) = call(port, "GET", "/api/usage", admin, "").await;
    let usage = parse(&usage);
    assert_eq!(usage["billing"], true);
    let bea = usage["users"].as_array().unwrap().iter().find(|u| u["user"]["id"] == w.b_id.as_str()).unwrap().clone();
    assert_eq!((bea["subscription"]["status"].as_str(), bea["subscription"]["subscriptionId"].as_str()), (Some("incomplete"), Some("sub_test_bea_2")));
    let synced = audit(port, admin, "action=billing.subscription_synced").await;
    assert!(synced.iter().any(|e| e["details"]["outcome"] == "superseded"), "{synced:?}");
}

// Checkout, the customer portal, and customer links (ADR 0041). Stripe is a fake on
// loopback: nothing here reaches Stripe, and the key is made up.

const KEY: &str = "sk_test_not_a_real_key_for_tests";
const PUBLIC: &str = "https://bots.example.com";
const CHECKOUT_DONE: &str = include_str!("../tests/fixtures/stripe/checkout.session.completed.json");
const CUSTOMER_DELETED: &str = include_str!("../tests/fixtures/stripe/customer.deleted.json");

/// One request the fake Stripe got.
#[derive(Clone, Debug)]
struct Seen {
    path: String,
    auth: String,
    key: String,
    version: String,
    form: Vec<(String, String)>,
}

impl Seen {
    fn get(&self, k: &str) -> Option<&str> {
        self.form.iter().find(|(n, _)| n == k).map(|(_, v)| v.as_str())
    }
}

/// Stripe's API as far as botd uses it: answers from `replies` first, else a new
/// session; like Stripe, a repeated idempotency key gets the first answer again.
#[derive(Clone, Default)]
struct FakeStripe {
    seen: Arc<std::sync::Mutex<Vec<Seen>>>,
    replies: Arc<std::sync::Mutex<std::collections::VecDeque<(u16, Value)>>>,
    answered: Arc<std::sync::Mutex<HashMap<String, (u16, Value)>>>,
    /// Checkout sessions someone paid: no longer open, so they can't be expired.
    paid: Arc<std::sync::Mutex<std::collections::HashSet<String>>>,
}

impl FakeStripe {
    fn seen(&self) -> Vec<Seen> {
        self.seen.lock().unwrap().clone()
    }
    fn reply(&self, status: u16, body: Value) {
        self.replies.lock().unwrap().push_back((status, body));
    }
    fn pay(&self, session: &str) {
        self.paid.lock().unwrap().insert(session.into());
    }
    fn created(&self) -> Vec<Seen> {
        self.seen().into_iter().filter(|s| s.path == "/v1/checkout/sessions").collect()
    }
}

async fn fake_stripe() -> (String, FakeStripe) {
    use axum::extract::{OriginalUri, State as S};
    async fn handle(S(f): S<FakeStripe>, OriginalUri(uri): OriginalUri, headers: axum::http::HeaderMap, body: axum::body::Bytes) -> (StatusCode, Json<Value>) {
        let h = |k: &str| headers.get(k).and_then(|v| v.to_str().ok()).unwrap_or_default().to_string();
        let form = url::form_urlencoded::parse(&body).into_owned().collect();
        let seen = Seen { path: uri.path().into(), auth: h("authorization"), key: h("idempotency-key"), version: h("stripe-version"), form };
        f.seen.lock().unwrap().push(seen.clone());
        // Stripe replays answers by idempotency key, which only POSTs carry.
        if let Some((code, v)) = f.answered.lock().unwrap().get(&seen.key).filter(|_| !seen.key.is_empty()) {
            return (StatusCode::from_u16(*code).unwrap(), Json(v.clone()));
        }
        let n = f.seen.lock().unwrap().len();
        let session = seen.path.strip_prefix("/v1/checkout/sessions/").map(|r| r.trim_end_matches("/expire").to_string());
        let paid = session.as_ref().is_some_and(|id| f.paid.lock().unwrap().contains(id));
        let (code, v) = f.replies.lock().unwrap().pop_front().unwrap_or_else(|| match (seen.path.as_str(), session) {
            ("/v1/checkout/sessions", _) => (200, json!({ "id": format!("cs_test_{n}"), "object": "checkout.session", "url": format!("https://checkout.stripe.com/c/pay/cs_test_{n}") })),
            (p, Some(_)) if p.ends_with("/expire") && paid => (400, json!({ "error": { "type": "invalid_request_error", "message": "Only Checkout Sessions with a status of open can be expired." } })),
            (_, Some(id)) => (200, json!({ "id": id, "object": "checkout.session", "status": if paid { "complete" } else { "expired" } })),
            _ => (200, json!({ "id": format!("bps_test_{n}"), "object": "billing_portal.session", "url": format!("https://billing.stripe.com/p/session/test_{n}") })),
        });
        if code < 500 && !seen.key.is_empty() {
            f.answered.lock().unwrap().insert(seen.key, (code, v.clone()));
        }
        (StatusCode::from_u16(code).unwrap(), Json(v))
    }
    let f = FakeStripe::default();
    let r = axum::Router::new().route("/v1/{*rest}", axum::routing::post(handle).get(handle)).with_state(f.clone());
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, r).await.unwrap() });
    (url, f)
}

/// `world(true)` with checkout, against a fake Stripe.
async fn shop() -> (World, FakeStripe) {
    let (url, f) = fake_stripe().await;
    (world_with(Some(Billing::with_checkout(SECRET, KEY, &url, PUBLIC))).await, f)
}

async fn buy(w: &World, who: &str, tier: &str) -> (u16, Value) {
    let (code, body) = call(w.port, "POST", "/api/billing/checkout", who, &json!({ "tier": tier }).to_string()).await;
    (code, parse(&body))
}

#[tokio::test]
async fn checkout_is_off_without_the_secret_key() {
    for stripe in [false, true] {
        let w = world(stripe).await;
        let owned = w.app.db.create_bot_owned("Scout", "#fff", "waddle", "claude", None, false, &w.a_id, Visibility::Private);
        for who in [w.a.clone(), w.admin.clone(), w.bots.auth(&owned.id)] {
            for (m, p, body) in [("GET", "/api/billing", ""), ("POST", "/api/billing/checkout", r#"{"tier":"pro"}"#), ("POST", "/api/billing/portal", ""), ("POST", "/api/billing/checkout", "not json")] {
                let (code, res) = call(w.port, m, p, &who, body).await;
                assert_eq!((code, parse(&res)["error"].as_str()), (404, Some("Billing isn't set up on this server.")), "{m} {p} (webhook {stripe})");
            }
        }
        let (_, usage) = call(w.port, "GET", "/api/usage", &w.admin, "").await;
        assert_eq!((parse(&usage)["billing"].as_bool(), parse(&usage)["checkout"].as_bool()), (Some(stripe), Some(false)));
    }
}

#[tokio::test]
async fn people_buy_plans_with_a_price_through_stripe_checkout() {
    let (w, stripe) = shop().await;
    let port = w.port;

    // Ada sees her plan and use, and the plans she can buy, without their price ids.
    let (code, info) = call(port, "GET", "/api/billing", &w.a, "").await;
    assert_eq!(code, 200, "{info}");
    let info = parse(&info);
    assert_eq!((info["plan"]["name"].as_str(), info["plan"]["usage"]["runs"].as_u64()), (Some("starter"), Some(0)));
    let plans: Vec<(&str, bool)> = info["plans"].as_array().unwrap().iter().map(|p| (p["name"].as_str().unwrap(), p["current"] == true)).collect();
    assert_eq!(plans, [("starter", true), ("pro", false)]);
    assert!(!info.to_string().contains("price_"), "{info}");
    assert_eq!((info["portal"].as_bool(), &info["subscription"], info["canChange"].as_bool()), (Some(false), &Value::Null, Some(true)));

    // Read-only people see their plan but change nothing.
    let (_, ro) = user_with(port, &w.admin, "ro@example.com", "readonly").await;
    let (code, seen) = call(port, "GET", "/api/billing", &ro, "").await;
    assert_eq!((code, parse(&seen)["canChange"].as_bool()), (200, Some(false)), "{seen}");
    for p in ["/api/billing/checkout", "/api/billing/portal"] {
        assert_eq!(call(port, "POST", p, &ro, r#"{"tier":"pro"}"#).await.0, 403, "{p}");
    }

    // Bots can't, and only plans with a price are for sale.
    let bot = w.app.db.create_bot_owned("Scout", "#fff", "waddle", "claude", None, false, &w.a_id, Visibility::Private);
    for (m, p) in [("GET", "/api/billing"), ("POST", "/api/billing/checkout"), ("POST", "/api/billing/portal")] {
        assert_eq!(call(port, m, p, &w.bots.auth(&bot.id), r#"{"tier":"pro"}"#).await.0, 403, "{m} {p}");
    }
    for (tier, says) in [("self-host", "can't be bought here"), ("gold", "no plan called \"gold\""), ("", "Say which plan")] {
        let (code, res) = buy(&w, &w.a, tier).await;
        assert_eq!(code, 400, "{tier}: {res}");
        assert!(res["error"].as_str().unwrap().contains(says), "{res}");
    }
    assert!(stripe.seen().is_empty());

    // Pro: a Checkout Session for its first price, for Ada, back to the app's plan screen.
    let minute = db::now() / 60_000;
    let (code, res) = buy(&w, &w.a, "pro").await;
    assert_eq!(code, 200, "{res}");
    let url = res["url"].as_str().unwrap().to_string();
    assert!(url.starts_with("https://checkout.stripe.com/"), "{url}");
    let s = stripe.seen()[0].clone();
    assert_eq!((s.path.as_str(), s.auth.as_str(), s.version.as_str()), ("/v1/checkout/sessions", "Bearer sk_test_not_a_real_key_for_tests", stripe::VERSION));
    assert!(s.key.starts_with("superbot-checkout-"), "{s:?}");
    for (k, v) in [
        ("mode", "subscription"),
        ("line_items[0][price]", "price_pro_monthly"),
        ("line_items[0][quantity]", "1"),
        ("client_reference_id", w.a_id.as_str()),
        ("metadata[superbot_user_id]", w.a_id.as_str()),
        ("metadata[superbot_tier]", "pro"),
        ("subscription_data[metadata][superbot_user_id]", w.a_id.as_str()),
        ("customer_email", "ada@example.com"),
        ("success_url", "https://bots.example.com/app/plan?checkout=success"),
        ("cancel_url", "https://bots.example.com/app/plan?checkout=cancelled"),
    ] {
        assert_eq!(s.get(k), Some(v), "{k}: {s:?}");
    }
    assert_eq!(s.get("customer"), None);
    let expires: i64 = s.get("expires_at").unwrap().parse().unwrap();
    assert!((minute * 60 + 30 * 60 + 1..=(minute + 1) * 60 + 31 * 60).contains(&expires), "{expires}");
    // Another checkout closes the first page, so only one of them can be paid.
    let (_, again) = buy(&w, &w.a, "pro").await;
    let seen = stripe.seen();
    assert_eq!((seen[1].path.as_str(), seen[2].path.as_str()), ("/v1/checkout/sessions/cs_test_1/expire", "/v1/checkout/sessions"));
    assert!(seen[1].key.starts_with("superbot-expire-") && seen[2].key != s.key, "{seen:?}");
    assert_eq!(again["url"].as_str(), Some("https://checkout.stripe.com/c/pay/cs_test_3"));
    let created = audit(port, &w.admin, "action=billing.checkout_created").await;
    let c = created.last().unwrap();
    assert_eq!((c["actorId"].as_str(), c["targetId"].as_str(), c["outcome"].as_str()), (Some(w.a_id.as_str()), Some(w.a_id.as_str()), Some("success")), "{c}");
    assert_eq!((c["details"]["tier"].as_str(), c["details"]["price"].as_str(), c["details"]["session"].as_str()), (Some("pro"), Some("price_pro_monthly"), Some("cs_test_1")));

    // No billing account to manage until a checkout completes.
    let (code, res) = call(port, "POST", "/api/billing/portal", &w.a, "").await;
    assert_eq!(code, 409, "{res}");

    // Stripe says the checkout completed: Ada is linked to her new customer, once.
    let done = event(CHECKOUT_DONE, &w.a_id, "evt_c1", 1_794_990_000, |_| {});
    assert_eq!(deliver(port, &done, None).await, (200, json!({ "received": true, "outcome": "customer_linked" })));
    assert_eq!(deliver(port, &done, None).await.1["outcome"], "duplicate");
    assert_eq!(w.app.db.customer_of(&w.a_id).as_deref(), Some("cus_test_ada"));
    let linked = audit(port, &w.admin, "action=billing.customer_linked").await;
    assert_eq!(linked.len(), 1, "{linked:?}");
    let l = &linked[0];
    assert_eq!((l["actorId"].as_str(), l["onBehalfOf"].as_str(), l["targetId"].as_str()), (Some("billing"), Some(w.a_id.as_str()), Some(w.a_id.as_str())));
    assert_eq!((l["details"]["customer"].as_str(), l["details"]["via"].as_str()), (Some("cus_test_ada"), Some("checkout")));
    // Her subscription's events set the plan, as before.
    let sub = event(UPDATED, &w.a_id, "evt_s1", 1_795_000_000, |_| {});
    assert_eq!(deliver(port, &sub, None).await.1["outcome"], "tier_changed");
    let info = parse(&call(port, "GET", "/api/billing", &w.a, "").await.1);
    assert_eq!((info["plan"]["name"].as_str(), info["portal"].as_bool(), info["subscription"]["status"].as_str()), (Some("pro"), Some(true), Some("active")));
    assert_eq!(info["plans"][1]["current"], true);

    // Paying already: another checkout would bill her twice, so she's sent to the portal.
    let (code, res) = buy(&w, &w.a, "starter").await;
    assert_eq!((code, res["portal"].as_bool()), (409, Some(true)), "{res}");
    let denied = audit(port, &w.admin, "action=billing.checkout_created&outcome=denied").await;
    assert_eq!(denied[0]["details"]["reason"], "already_subscribed");
    let before = stripe.seen().len();
    let (code, res) = call(port, "POST", "/api/billing/portal", &w.a, "").await;
    assert_eq!(code, 200, "{res}");
    let portal = parse(&res)["url"].as_str().unwrap().to_string();
    assert!(portal.starts_with("https://billing.stripe.com/"), "{portal}");
    let p = stripe.seen()[before].clone();
    assert_eq!((p.path.as_str(), p.get("customer"), p.get("return_url")), ("/v1/billing_portal/sessions", Some("cus_test_ada"), Some("https://bots.example.com/app/plan")));
    assert!(p.key.starts_with("superbot-portal-"), "{p:?}");
    let opened = audit(port, &w.admin, "action=billing.portal_created").await;
    assert_eq!((opened[0]["actorId"].as_str(), opened[0]["details"]["customer"].as_str()), (Some(w.a_id.as_str()), Some("cus_test_ada")));

    // Bea's checkout knows nothing of Ada's customer.
    let (code, _) = buy(&w, &w.b, "starter").await;
    assert_eq!(code, 200);
    let s = stripe.seen().last().unwrap().clone();
    assert_eq!((s.get("customer"), s.get("customer_email"), s.get("line_items[0][price]")), (None, Some("bea@example.com"), Some("price_starter_monthly")));
    // After her plan ends, a linked customer checks out as that customer.
    let gone = event(DELETED, &w.a_id, "evt_s2", 1_795_100_000, |_| {});
    assert_eq!(deliver(port, &gone, None).await.1["outcome"], "tier_changed");
    assert_eq!(buy(&w, &w.a, "pro").await.0, 200);
    let s = stripe.seen().last().unwrap().clone();
    assert_eq!((s.get("customer"), s.get("customer_email")), (Some("cus_test_ada"), None));

    // The page links are for the person, never in the audit log; nor is the key.
    let all = call(port, "GET", "/api/audit?limit=500", &w.admin, "").await.1;
    assert!(!all.contains(&portal) && !all.contains(&url) && !all.contains(KEY), "{all}");
}

#[tokio::test]
async fn stripe_failures_are_retried_once_and_said_plainly() {
    let (w, stripe) = shop().await;
    // A 500, then an answer: retried with the same idempotency key.
    stripe.reply(500, json!({ "error": { "type": "api_error" } }));
    let (code, res) = buy(&w, &w.a, "pro").await;
    assert_eq!(code, 200, "{res}");
    let seen = stripe.seen();
    assert_eq!((seen.len(), seen[0].key == seen[1].key), (2, true), "{seen:?}");

    // Refused: not retried, and the person gets a plain 502.
    stripe.reply(400, json!({ "error": { "type": "invalid_request_error", "code": "resource_missing", "message": "No such price: 'price_pro_monthly'", "param": "line_items[0][price]" } }));
    let (code, res) = buy(&w, &w.b, "pro").await;
    assert_eq!(code, 502, "{res}");
    assert!(res["error"].as_str().unwrap().starts_with("Stripe couldn't open the checkout"), "{res}");
    assert_eq!(stripe.seen().len(), 3);
    let failed = audit(w.port, &w.admin, "action=billing.checkout_created&outcome=failure").await;
    assert_eq!(failed[0]["details"]["reason"], "HTTP 400 invalid_request_error resource_missing");

    // An answer without a link isn't a session.
    stripe.reply(200, json!({ "id": "cs_test_x", "url": null }));
    assert_eq!(buy(&w, &w.b, "starter").await.0, 502);

    // Nobody there at all.
    let closed = { tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.unwrap().local_addr().unwrap() };
    let w = world_with(Some(Billing::with_checkout(SECRET, KEY, &format!("http://{closed}"), PUBLIC))).await;
    let (code, res) = buy(&w, &w.a, "pro").await;
    assert_eq!(code, 502, "{res}");
    assert_eq!(audit(w.port, &w.admin, "action=billing.checkout_created&outcome=failure").await[0]["details"]["reason"], "no answer from Stripe");
}

#[tokio::test]
async fn only_one_checkout_page_can_be_paid() {
    let (w, stripe) = shop().await;
    assert_eq!(buy(&w, &w.a, "pro").await.0, 200);
    assert_eq!(w.app.db.open_checkout(&w.a_id).as_deref(), Some("cs_test_1"));

    // Ada paid on that page, and the webhook isn't here yet: no second checkout.
    stripe.pay("cs_test_1");
    let (code, res) = buy(&w, &w.a, "starter").await;
    assert_eq!(code, 409, "{res}");
    assert!(res["error"].as_str().unwrap().contains("went through"), "{res}");
    let paths: Vec<String> = stripe.seen().iter().skip(1).map(|s| s.path.clone()).collect();
    assert_eq!(paths, ["/v1/checkout/sessions/cs_test_1/expire", "/v1/checkout/sessions/cs_test_1"]);
    assert_eq!(stripe.created().len(), 1);
    let d = &audit(w.port, &w.admin, "action=billing.checkout_created&outcome=denied").await[0];
    assert_eq!((d["details"]["reason"].as_str(), d["details"]["session"].as_str()), (Some("checkout_completed"), Some("cs_test_1")));

    // Its completion closes it.
    let done = event(CHECKOUT_DONE, &w.a_id, "evt_c1", 1_794_990_000, |v| v["data"]["object"]["id"] = json!("cs_test_1"));
    assert_eq!(deliver(w.port, &done, None).await.1["outcome"], "customer_linked");
    assert_eq!(w.app.db.open_checkout(&w.a_id), None);

    // Bea's open page can't be closed while Stripe is down, so no second one opens.
    assert_eq!(buy(&w, &w.b, "pro").await.0, 200);
    let before = stripe.created().len();
    stripe.reply(503, json!({ "error": { "type": "api_error" } }));
    stripe.reply(503, json!({ "error": { "type": "api_error" } }));
    let (code, res) = buy(&w, &w.b, "starter").await;
    assert_eq!(code, 502, "{res}");
    assert_eq!(stripe.created().len(), before);
    let f = &audit(w.port, &w.admin, "action=billing.checkout_created&outcome=failure").await[0];
    assert_eq!(f["details"]["reason"], "last checkout: HTTP 503 api_error");
    // Once it answers, the old page is expired and a new one opens.
    assert_eq!(buy(&w, &w.b, "starter").await.0, 200);
    assert_eq!(stripe.created().len(), before + 1);

    // The old page closed but its replacement failed: trying again opens a new page,
    // never the closed one again, however soon.
    let (_, first) = buy(&w, &w.b, "pro").await;
    let first_key = stripe.created().last().unwrap().key.clone();
    stripe.reply(200, json!({ "id": "x", "object": "checkout.session", "status": "expired" }));
    stripe.reply(400, json!({ "error": { "type": "invalid_request_error" } }));
    assert_eq!(buy(&w, &w.b, "pro").await.0, 502);
    let (code, again) = buy(&w, &w.b, "pro").await;
    assert_eq!(code, 200, "{again}");
    assert_ne!(again["url"], first["url"]);
    assert!(stripe.created().iter().rev().take(2).all(|s| s.key != first_key));
}

#[tokio::test]
async fn too_many_sessions_at_once_are_refused() {
    let (w, stripe) = shop().await;
    for n in 0..10 {
        assert_eq!(buy(&w, &w.a, "pro").await.0, 200, "{n}");
    }
    let (code, res) = buy(&w, &w.a, "pro").await;
    assert_eq!(code, 429, "{res}");
    assert_eq!(stripe.created().len(), 10);
    // Per person: Bea still can.
    assert_eq!(buy(&w, &w.b, "pro").await.0, 200);
}

#[tokio::test]
async fn customers_tie_subscriptions_to_their_user() {
    let w = world(true).await;
    let port = w.port;
    let tier = |u: &str| w.app.db.user(u).unwrap().tier;
    let done = |user: &str, id: &str, f: &dyn Fn(&mut Value)| event(CHECKOUT_DONE, user, id, 1_794_990_000, f);
    assert_eq!(deliver(port, &done(&w.a_id, "evt_c1", &|_| {}), None).await.1["outcome"], "customer_linked");

    // A subscription made outside SuperBot's checkout, with no metadata, finds Ada
    // through her customer.
    let bare = event(UPDATED, &w.a_id, "evt_s1", 1_795_000_000, |v| {
        v["data"]["object"]["metadata"] = json!({});
        v["data"]["object"]["id"] = json!("sub_test_portal");
    });
    assert_eq!(deliver(port, &bare, None).await.1["outcome"], "tier_changed");
    assert_eq!(tier(&w.a_id).as_deref(), Some("pro"));

    // Ada's customer can't pay for Bea, whatever the metadata says.
    let theirs = event(UPDATED, &w.b_id, "evt_s2", 1_795_000_100, |v| v["data"]["object"]["id"] = json!("sub_test_bea"));
    assert_eq!(deliver(port, &theirs, None).await.1["outcome"], "ignored");
    assert_eq!(audit(port, &w.admin, "action=billing.event_ignored").await[0]["details"]["reason"], "customer_of_another_user");
    assert_eq!(tier(&w.b_id), None);
    assert!(w.app.db.subscription_by_id("sub_test_bea").is_none());
    let bea_with_adas = done(&w.b_id, "evt_c2", &|_| {});
    assert_eq!(deliver(port, &bea_with_adas, None).await.1["outcome"], "ignored");
    assert_eq!(audit(port, &w.admin, "action=billing.event_ignored").await[0]["details"]["reason"], "customer_of_another_user");

    // Ada keeps the customer she has; a second one is recorded as ignored.
    let second = done(&w.a_id, "evt_c3", &|v| v["data"]["object"]["customer"] = json!("cus_test_ada_2"));
    assert_eq!(deliver(port, &second, None).await.1["outcome"], "ignored");
    let i = &audit(port, &w.admin, "action=billing.event_ignored").await[0];
    assert_eq!((i["details"]["reason"].as_str(), i["details"]["linked"].as_str()), (Some("user_has_another_customer"), Some("cus_test_ada")));
    assert_eq!(w.app.db.customer_of(&w.a_id).as_deref(), Some("cus_test_ada"));

    // A session naming two people, or nobody known, or with no customer, links nobody.
    let mixed = done(&w.b_id, "evt_c4", &|v| v["data"]["object"]["client_reference_id"] = json!("someone-else"));
    let nobody = done("u-nobody", "evt_c5", &|v| v["data"]["object"]["customer"] = json!("cus_test_x"));
    let guest = done(&w.b_id, "evt_c6", &|v| v["data"]["object"]["customer"] = Value::Null);
    for (body, reason) in [(mixed, "user_mismatch"), (nobody, "unknown_user"), (guest, "no_customer")] {
        assert_eq!(deliver(port, &body, None).await.1["outcome"], "ignored", "{reason}");
        assert_eq!(audit(port, &w.admin, "action=billing.event_ignored").await[0]["details"]["reason"], reason);
    }
    assert_eq!(w.app.db.customer_of(&w.b_id), None);

    // A subscription event links its user's first customer too.
    let bea = event(UPDATED, &w.b_id, "evt_s3", 1_795_000_200, |v| {
        v["data"]["object"]["id"] = json!("sub_test_bea");
        v["data"]["object"]["customer"] = json!("cus_test_bea");
    });
    assert_eq!(deliver(port, &bea, None).await.1["outcome"], "tier_changed");
    assert_eq!(w.app.db.customer_of(&w.b_id).as_deref(), Some("cus_test_bea"));
    let l = &audit(port, &w.admin, "action=billing.customer_linked").await[0];
    assert_eq!((l["targetId"].as_str(), l["details"]["via"].as_str()), (Some(w.b_id.as_str()), Some("subscription")));

    // Stripe deletes Ada's customer: the link goes, once; a customer nobody has changes nothing.
    let deleted = event(CUSTOMER_DELETED, &w.a_id, "evt_d1", 1_795_600_000, |_| {});
    assert_eq!(deliver(port, &deleted, None).await.1["outcome"], "customer_unlinked");
    assert_eq!(deliver(port, &deleted, None).await.1["outcome"], "duplicate");
    assert_eq!(w.app.db.customer_of(&w.a_id), None);
    let u = &audit(port, &w.admin, "action=billing.customer_unlinked").await[0];
    assert_eq!((u["targetId"].as_str(), u["details"]["customer"].as_str()), (Some(w.a_id.as_str()), Some("cus_test_ada")));
    let unknown = event(CUSTOMER_DELETED, &w.a_id, "evt_d2", 1_795_600_100, |v| v["data"]["object"]["id"] = json!("cus_test_nobody"));
    assert_eq!(deliver(port, &unknown, None).await.1["outcome"], "unchanged");
    // Events that arrive after the deletion still end the plan, but can't link the customer again.
    let late = event(DELETED, &w.a_id, "evt_s4", 1_795_600_200, |v| {
        v["data"]["object"]["metadata"] = json!({});
        v["data"]["object"]["id"] = json!("sub_test_portal");
    });
    assert_eq!(deliver(port, &late, None).await.1["outcome"], "tier_changed");
    assert_eq!(tier(&w.a_id), None);
    let late_checkout = done(&w.a_id, "evt_c7", &|_| {});
    assert_eq!(deliver(port, &late_checkout, None).await.1["outcome"], "ignored");
    assert_eq!(audit(port, &w.admin, "action=billing.event_ignored").await[0]["details"]["reason"], "customer_deleted");
    assert_eq!(w.app.db.customer_of(&w.a_id), None);

    // Admins see who is linked to which customer.
    let usage = parse(&call(port, "GET", "/api/usage", &w.admin, "").await.1);
    let row = |id: &str| usage["users"].as_array().unwrap().iter().find(|u| u["user"]["id"] == id).unwrap().clone();
    assert_eq!((row(&w.a_id)["customer"].clone(), row(&w.b_id)["customer"].as_str()), (Value::Null, Some("cus_test_bea")));
}
