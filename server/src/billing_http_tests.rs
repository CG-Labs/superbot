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
}

/// A server on the example tiers (starter: 2 Bots, 3 runs a month, 2 routine runs a
/// day, g6-standard-1 machines), the fake machine provider, Ada and Bea (members), and
/// with `stripe`, the webhook on.
async fn world(stripe: bool) -> World {
    let p: Arc<dyn MachineProvider> = Arc::new(Fake::default());
    let (port, app, admin, _) = serve_app_with(|a| {
        a.machines = Arc::new(ControlPlane::for_tests(p));
        if stripe {
            a.billing = Billing::with_secret(SECRET);
        }
    })
    .await;
    app.tiers.set(Arc::new(Tiers::parse(EXAMPLE, None).unwrap())).unwrap();
    let (a_id, a) = user_with(port, &admin, "ada@example.com", "member").await;
    let (b_id, b) = user_with(port, &admin, "bea@example.com", "member").await;
    fake_claude(&app);
    World { port, app, admin, a_id, a, b_id, b }
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

    // Bea moves from one subscription to another; the old one's cancellation, arriving
    // after, doesn't undo the new one. One whose first payment hasn't gone through changes nothing.
    let pro = event(UPDATED, &w.b_id, "evt_6", 1_795_300_000, |v| v["data"]["object"]["id"] = json!("sub_test_bea_1"));
    assert_eq!(deliver(port, &pro, None).await.1["outcome"], "tier_changed");
    let starter = event(UPDATED, &w.b_id, "evt_7", 1_795_300_100, |v| {
        v["data"]["object"]["id"] = json!("sub_test_bea_2");
        v["data"]["object"]["items"]["data"][0]["price"]["id"] = json!("price_starter_monthly");
    });
    assert_eq!(deliver(port, &starter, None).await.1["outcome"], "tier_changed");
    assert_eq!(tier(&w.b_id).as_deref(), Some("starter"));
    let old_gone = event(DELETED, &w.b_id, "evt_8", 1_795_300_200, |v| v["data"]["object"]["id"] = json!("sub_test_bea_1"));
    assert_eq!(deliver(port, &old_gone, None).await.1["outcome"], "superseded");
    assert_eq!(tier(&w.b_id).as_deref(), Some("starter"));
    let incomplete = event(UPDATED, &w.b_id, "evt_9", 1_795_300_300, |v| {
        v["data"]["object"]["id"] = json!("sub_test_bea_2");
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
