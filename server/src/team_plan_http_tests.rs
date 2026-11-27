//! Server admins change a team's plan (ADR 0347) on the real router: with billing off
//! the plan is recorded with no Stripe call; a team that pays has its subscription moved
//! in Stripe and the webhook applies it; and members still paying for a plan of their
//! own are emailed, once per change, that they may cancel it. Stripe is a fake on
//! loopback and its events are fixtures: nothing here reaches Stripe, and the keys are
//! made up.

use crate::billing::Billing;
use crate::billing_http_tests::{DELETED, FakeStripe, KEY, PUBLIC, SECRET, UPDATED, World, audit, deliver, event, fake_stripe, world, world_with};
use crate::team_billing_http_tests::{team_event, tier};
use crate::users_http_tests::parse;
use crate::*;

async fn json_call(port: u16, method: &str, path: &str, who: &str, body: &str) -> (u16, Value) {
    let (code, body) = crate::tests::call(port, method, path, who, body).await;
    (code, parse(&body))
}

/// Alpha: Ada its owner, Bea a member.
async fn alpha(w: &World) -> String {
    let (code, v) = json_call(w.port, "POST", "/api/teams", &w.admin, &json!({ "name": "Alpha", "owner": w.a_id }).to_string()).await;
    assert_eq!(code, 201, "{v}");
    let id = v["id"].as_str().unwrap().to_string();
    assert_eq!(json_call(w.port, "PUT", &format!("/api/teams/{id}/members/{}", w.b_id), &w.admin, r#"{"role":"member"}"#).await.0, 200);
    id
}

async fn set(w: &World, team: &str, tier: Value) -> (u16, Value) {
    json_call(w.port, "PUT", &format!("/api/teams/{team}/plan"), &w.admin, &json!({ "tier": tier }).to_string()).await
}

/// Bea buys a Starter plan of her own.
async fn bea_pays(w: &World) {
    let body = event(UPDATED, &w.b_id, "evt_bea", 1_794_000_000, |v| {
        let o = &mut v["data"]["object"];
        o["id"] = json!("sub_test_bea");
        o["customer"] = json!("cus_test_bea");
        o["items"]["data"][0]["id"] = json!("si_test_bea");
        o["items"]["data"][0]["price"]["id"] = json!("price_starter_monthly");
    });
    assert_eq!(deliver(w.port, &body, None).await.0, 200);
    assert!(w.app.db.user_paying(&w.b_id).is_some());
}

/// The emails sent to `to` that tell them they may cancel their own plan.
fn covered(mailer: &billing_mail::fake::Mailer, to: &str) -> Vec<String> {
    mailer.sent().iter().filter(|m| m.to == to && m.subject.contains("you may cancel")).map(|m| m.subject.clone()).collect()
}

/// A checkout-enabled world against a fake Stripe.
async fn shop() -> (World, FakeStripe) {
    let (url, f) = fake_stripe().await;
    (world_with(Some(Billing::with_checkout(SECRET, KEY, &url, PUBLIC))).await, f)
}

#[tokio::test]
async fn with_billing_off_an_admin_records_the_teams_plan() {
    let w = world(false).await;
    let team = alpha(&w).await;
    let port = w.port;

    // Only server admins, a real plan, and a body that says which.
    let (code, v) = json_call(port, "PUT", &format!("/api/teams/{team}/plan"), &w.a, r#"{"tier":"pro"}"#).await;
    assert_eq!(code, 403, "{v}");
    for body in ["", "{}", r#"{"tier":3}"#, r#"{"tier":"pro","extra":1}"#, r#"{"tier":"max"}"#] {
        let (code, v) = json_call(port, "PUT", &format!("/api/teams/{team}/plan"), &w.admin, body).await;
        assert_eq!(code, 400, "{body}: {v}");
    }
    assert!(v_has(&json_call(port, "PUT", &format!("/api/teams/{team}/plan"), &w.admin, r#"{"tier":"max"}"#).await.1, "starter, pro, self-host"));
    assert_eq!(set(&w, "team_missing", json!("pro")).await.0, 404);
    assert_eq!((tier(&w, &w.a_id), tier(&w, &w.b_id)), ("starter".into(), "starter".into()));

    // The admin gives Alpha Pro: everyone on it is on Pro, recorded and audited.
    let (code, v) = set(&w, &team, json!("pro")).await;
    assert_eq!(code, 200, "{v}");
    assert_eq!(v["plan"], json!({ "current": { "name": "pro", "label": "Pro", "source": "admin" }, "given": "pro", "paid": false }), "{v}");
    assert_eq!((tier(&w, &w.a_id), tier(&w, &w.b_id)), ("pro".into(), "pro".into()));
    let changed = audit(port, &w.admin, "action=team.tier_changed").await;
    assert_eq!(changed.len(), 1, "{changed:?}");
    let d = &changed[0]["details"];
    assert_eq!((d["from"].clone(), d["to"].as_str(), d["effectiveTo"].as_str(), d["source"].as_str(), d["emailed"].as_i64()), (Value::Null, Some("pro"), Some("pro"), Some("admin"), Some(0)), "{d}");
    let moved = audit(port, &w.admin, "action=user.tier_changed").await;
    assert_eq!(moved.len(), 2, "{moved:?}");
    assert!(moved.iter().all(|e| e["details"]["source"] == "team" && e["details"]["via"] == "admin" && e["details"]["effectiveTo"] == "pro"), "{moved:?}");

    // The console's list shows the plan and the plans to pick from.
    let (_, list) = json_call(port, "GET", "/api/teams", &w.admin, "").await;
    assert_eq!(list["teams"][0]["plan"]["current"]["name"], "pro", "{list}");
    let names: Vec<&str> = list["plans"].as_array().unwrap().iter().map(|p| p["name"].as_str().unwrap()).collect();
    assert_eq!(names, ["starter", "pro", "self-host"]);
    assert_eq!(list["plans"][2]["priced"], false);
    // Members don't see the admin's view, but do see the plan, with nothing to change.
    let (_, mine) = json_call(port, "GET", "/api/team", &w.b, "").await;
    assert!(mine.get("plan").is_none(), "{mine}");
    assert_eq!(mine["billing"], json!({ "plan": { "name": "pro", "label": "Pro", "source": "admin" }, "canChange": false }), "{mine}");

    // The same plan again changes nothing; taking it away moves everyone back.
    assert_eq!(set(&w, &team, json!("pro")).await.0, 200);
    assert_eq!(audit(port, &w.admin, "action=team.tier_changed").await.len(), 1);
    let (code, v) = set(&w, &team, Value::Null).await;
    assert_eq!((code, &v["plan"]["current"], &v["plan"]["given"]), (200, &Value::Null, &Value::Null), "{v}");
    assert_eq!((tier(&w, &w.a_id), tier(&w, &w.b_id)), ("starter".into(), "starter".into()));
    assert_eq!(audit(port, &w.admin, "action=user.tier_changed").await.len(), 4);
    assert!(json_call(port, "GET", "/api/team", &w.b, "").await.1.get("billing").is_none());
    // Nothing was queued to email with billing off.
    assert!(w.app.db.billing_emails_of(&w.b_id, 10).is_empty());
}

fn v_has(v: &Value, s: &str) -> bool {
    v.to_string().contains(s)
}

#[tokio::test]
async fn members_still_paying_for_their_own_plan_are_told_once_per_change() {
    let (w, stripe) = shop().await;
    let team = alpha(&w).await;
    bea_pays(&w).await;
    let mailer = billing_mail::fake::install(&w.app, Some(PUBLIC));
    billing_mail::send_due(&w.app).await;
    let before = stripe.seen().len();

    // No subscription pays for Alpha: the plan is the admin's to give, with no Stripe call.
    let (code, v) = set(&w, &team, json!("pro")).await;
    assert_eq!(code, 200, "{v}");
    assert_eq!(stripe.seen().len(), before, "no Stripe call");
    // Queued with the plan, before anything is sent.
    assert!(w.app.db.billing_emails_of(&w.b_id, 10).iter().any(|q| q.kind == "personal_plan_covered" && q.facts.team_id.as_deref() == Some(team.as_str())));
    assert_eq!(tier(&w, &w.b_id), "pro", "the team's plan is over her own");
    billing_mail::send_due(&w.app).await;
    assert_eq!(covered(&mailer, "bea@example.com"), ["[SuperBot] Alpha's plan covers you: you may cancel your own Starter plan"]);
    assert!(covered(&mailer, "ada@example.com").is_empty(), "Ada pays for nothing of her own");
    let m = mailer.sent().into_iter().find(|m| m.subject.contains("you may cancel")).unwrap();
    assert!(m.body.contains("on the Pro plan now") && m.body.contains(&format!("{PUBLIC}/app/plan")) && !m.body.contains("sub_test") && !m.body.contains("price_"), "{}", m.body);
    assert_eq!(audit(w.port, &w.admin, "action=team.tier_changed").await[0]["details"]["emailed"], 1);

    // Her plan says the team's covers her, and no one on it can buy a plan meanwhile.
    let (_, mine) = json_call(w.port, "GET", "/api/billing", &w.b, "").await;
    assert_eq!((mine["teamPlan"]["tier"].as_str(), mine["teamPlan"]["source"].as_str()), (Some("pro"), Some("admin")), "{mine}");
    let (code, v) = json_call(w.port, "POST", "/api/billing/checkout", &w.a, r#"{"tier":"pro"}"#).await;
    assert_eq!((code, v["teamPays"].as_bool()), (409, Some(true)), "{v}");

    // The same plan again sends nothing; another change sends one more.
    assert_eq!(set(&w, &team, json!("pro")).await.0, 200);
    billing_mail::send_due(&w.app).await;
    assert_eq!(covered(&mailer, "bea@example.com").len(), 1);
    assert_eq!(set(&w, &team, json!("starter")).await.0, 200);
    billing_mail::send_due(&w.app).await;
    assert_eq!(covered(&mailer, "bea@example.com").len(), 2);

    // Cancelled before it's sent: nothing left to tell her.
    assert_eq!(set(&w, &team, json!("pro")).await.0, 200);
    let gone = event(DELETED, &w.b_id, "evt_bea_gone", 1_794_100_000, |v| v["data"]["object"]["id"] = json!("sub_test_bea"));
    assert_eq!(deliver(w.port, &gone, None).await.0, 200);
    billing_mail::send_due(&w.app).await;
    assert_eq!(covered(&mailer, "bea@example.com").len(), 2);
    let skipped = audit(w.port, &w.admin, "action=billing.email_skipped").await;
    assert!(skipped.iter().any(|e| e["details"]["reason"] == "not_needed"), "{skipped:?}");
}

#[tokio::test]
async fn an_email_about_a_team_they_left_isnt_sent() {
    let (w, _stripe) = shop().await;
    let alpha = alpha(&w).await;
    bea_pays(&w).await;
    let mailer = billing_mail::fake::install(&w.app, Some(PUBLIC));
    billing_mail::send_due(&w.app).await;

    // Alpha's plan is queued to tell Bea, but she moves to Beta, on a plan too, first.
    assert_eq!(set(&w, &alpha, json!("pro")).await.0, 200);
    assert_eq!(json_call(w.port, "DELETE", &format!("/api/teams/{alpha}/members/{}", w.b_id), &w.admin, "").await.0, 200);
    let (code, v) = json_call(w.port, "POST", "/api/teams", &w.admin, &json!({ "name": "Beta", "owner": w.b_id }).to_string()).await;
    assert_eq!(code, 201, "{v}");
    assert_eq!(set(&w, v["id"].as_str().unwrap(), json!("starter")).await.0, 200);
    billing_mail::send_due(&w.app).await;
    assert_eq!(covered(&mailer, "bea@example.com"), ["[SuperBot] Beta's plan covers you: you may cancel your own Starter plan"]);
    let skipped = audit(w.port, &w.admin, "action=billing.email_skipped").await;
    assert_eq!(skipped.iter().filter(|e| e["details"]["reason"] == "not_needed").count(), 1, "{skipped:?}");
}

#[tokio::test]
async fn a_team_that_pays_has_its_subscription_moved_in_stripe() {
    let (w, stripe) = shop().await;
    let team = alpha(&w).await;
    bea_pays(&w).await;
    let mailer = billing_mail::fake::install(&w.app, Some(PUBLIC));

    // Alpha starts paying for Pro: Bea, still paying for Starter, is told once.
    let pro = team_event(&team, "evt_t1", 1_795_000_000, |_| {});
    assert_eq!(deliver(w.port, &pro, None).await.1["outcome"], "tier_changed");
    assert_eq!(deliver(w.port, &pro, None).await.0, 200);
    billing_mail::send_due(&w.app).await;
    assert_eq!(covered(&mailer, "bea@example.com"), ["[SuperBot] Alpha's plan covers you: you may cancel your own Starter plan"]);

    // What Stripe can't do is refused and audited, with no Stripe call.
    let before = stripe.seen().len();
    for (tier, reason) in [(Value::Null, "team_pays"), (json!("self-host"), "no_price")] {
        let (code, v) = set(&w, &team, tier).await;
        assert_eq!(code, 409, "{reason}: {v}");
    }
    let refused = audit(w.port, &w.admin, "action=team.plan_change_requested&outcome=denied").await;
    let mut reasons: Vec<&str> = refused.iter().map(|e| e["details"]["reason"].as_str().unwrap()).collect();
    reasons.sort();
    assert_eq!(reasons, ["no_price", "team_pays"]);
    assert_eq!(stripe.seen().len(), before);

    // Starter: the subscription moves to its price, with prorations, for every seat.
    let (code, v) = set(&w, &team, json!("starter")).await;
    assert_eq!(code, 202, "{v}");
    assert_eq!((v["plan"]["current"]["name"].as_str(), v["plan"]["current"]["source"].as_str(), v["plan"]["paid"].as_bool()), (Some("pro"), Some("stripe"), Some(true)), "{v}");
    let posts: Vec<_> = stripe.seen().into_iter().filter(|s| s.path == "/v1/subscriptions/sub_test_alpha").collect();
    assert_eq!(posts.len(), 1);
    let p = &posts[0];
    assert_eq!(
        (p.get("items[0][id]"), p.get("items[0][price]"), p.get("items[0][quantity]"), p.get("proration_behavior")),
        (Some("si_test_alpha"), Some("price_starter_monthly"), Some("2"), Some("create_prorations"))
    );
    assert!(p.key.starts_with("superbot-team-plan-"), "{}", p.key);
    // Asked again (before Stripe's event, or after a round trip to another plan): it
    // reaches Stripe again under a key of its own, not the first one's answer.
    assert_eq!(set(&w, &team, json!("starter")).await.0, 202);
    let keys: Vec<String> = stripe.seen().into_iter().filter(|s| s.path == "/v1/subscriptions/sub_test_alpha").map(|s| s.key).collect();
    assert_eq!(keys.len(), 2);
    assert_ne!(keys[0], keys[1]);
    // Back to Pro before Starter's event: Stripe is asked for Pro's price, which undoes it,
    // though Pro is the plan Stripe last said.
    assert_eq!(set(&w, &team, json!("pro")).await.0, 202);
    let prices: Vec<String> = stripe.seen().into_iter().filter(|s| s.path == "/v1/subscriptions/sub_test_alpha").filter_map(|s| s.get("items[0][price]").map(String::from)).collect();
    assert_eq!(prices, ["price_starter_monthly", "price_starter_monthly", "price_pro_monthly"]);
    let asked = audit(w.port, &w.admin, "action=team.plan_change_requested&outcome=success").await;
    assert_eq!(asked.len(), 3, "{asked:?}");
    assert_eq!(tier(&w, &w.b_id), "pro", "nothing changes until Stripe says so");
    assert_eq!(set(&w, &team, json!("starter")).await.0, 202);

    // Stripe's event applies it, and Bea is told once more, once.
    let starter = team_event(&team, "evt_t2", 1_795_000_100, |v| v["data"]["object"]["items"]["data"][0]["price"]["id"] = json!("price_starter_monthly"));
    assert_eq!(deliver(w.port, &starter, None).await.1["outcome"], "tier_changed");
    assert_eq!(deliver(w.port, &starter, None).await.0, 200);
    assert_eq!(tier(&w, &w.b_id), "starter");
    billing_mail::send_due(&w.app).await;
    assert_eq!(covered(&mailer, "bea@example.com").len(), 2);
    assert!(covered(&mailer, "ada@example.com").is_empty());

    // A Stripe failure is a 502, audited, with the plan unchanged.
    stripe.reply(400, json!({ "error": { "type": "invalid_request_error", "message": "No such price" } }));
    let (code, v) = set(&w, &team, json!("pro")).await;
    assert_eq!(code, 502, "{v}");
    assert!(!v.to_string().contains("No such price"), "{v}");
    assert_eq!(audit(w.port, &w.admin, "action=team.plan_change_requested&outcome=failure").await.len(), 1);
    assert_eq!(tier(&w, &w.b_id), "starter");
}

#[tokio::test]
async fn a_team_that_pays_isnt_changed_here_with_billing_off() {
    let w = world(true).await;
    let team = alpha(&w).await;
    // Webhook only: Stripe's events arrive, but botd has no key to call Stripe with.
    assert_eq!(deliver(w.port, &team_event(&team, "evt_o1", 1_795_000_000, |_| {}), None).await.0, 200);
    assert!(w.app.db.team_paying(&team).is_some());
    let (code, v) = set(&w, &team, json!("starter")).await;
    assert_eq!(code, 409, "{v}");
    let refused = audit(w.port, &w.admin, "action=team.plan_change_requested").await;
    assert_eq!(refused[0]["details"]["reason"], "billing_off", "{refused:?}");
    assert_eq!(tier(&w, &w.b_id), "pro");
}
