//! Yearly and team-only prices at checkout (ADR 0346) on the real router: a tier's
//! `checkoutPrices` sell it monthly or yearly, at a team's own price, or to teams only,
//! and tiers without them sell their first price as before. Stripe is a fake on
//! loopback and its events are fixtures: nothing reaches Stripe, and the keys are made up.

use crate::billing::Billing;
use crate::billing_http_tests::{FakeStripe, KEY, PUBLIC, SECRET, Seen, UPDATED, World, audit, deliver, event, fake_stripe, world_on};
use crate::users_http_tests::parse;
use crate::*;

const TIERS: &str = r#"{
  "default": "starter",
  "tiers": [
    { "name": "starter", "label": "Starter", "routes": "any", "stripePrices": ["price_starter_monthly"] },
    { "name": "pro", "label": "Pro", "routes": "any",
      "stripePrices": ["price_pro_monthly", "price_pro_yearly", "price_pro_team_monthly", "price_pro_team_yearly"],
      "checkoutPrices": { "month": "price_pro_monthly", "year": "price_pro_yearly", "teamMonth": "price_pro_team_monthly", "teamYear": "price_pro_team_yearly" } },
    { "name": "business", "label": "Business", "routes": "any",
      "stripePrices": ["price_business_yearly"], "checkoutPrices": { "teamYear": "price_business_yearly" } },
    { "name": "self-host", "routes": "any" }
  ]
}"#;

async fn json_call(port: u16, method: &str, path: &str, who: &str, body: &str) -> (u16, Value) {
    let (code, body) = crate::tests::call(port, method, path, who, body).await;
    (code, parse(&body))
}

async fn shop() -> (World, FakeStripe) {
    let (url, f) = fake_stripe().await;
    (world_on(Some(Billing::with_checkout(SECRET, KEY, &url, PUBLIC)), TIERS, |_| {}).await, f)
}

fn sessions(f: &FakeStripe) -> Vec<Seen> {
    f.seen().into_iter().filter(|s| s.path == "/v1/checkout/sessions").collect()
}

fn names(plans: &Value) -> Vec<(String, Value)> {
    plans.as_array().unwrap().iter().map(|p| (p["name"].as_str().unwrap().to_string(), p["intervals"].clone())).collect()
}

#[tokio::test]
async fn people_buy_monthly_or_yearly_and_never_a_team_only_plan() {
    let (w, stripe) = shop().await;
    let port = w.port;

    // The plans Ada can buy: each sold interval, no price ids, no team-only plan.
    let (code, info) = json_call(port, "GET", "/api/billing", &w.a, "").await;
    assert_eq!(code, 200, "{info}");
    assert_eq!(names(&info["plans"]), [("starter".to_string(), Value::Null), ("pro".to_string(), json!(["month", "year"]))]);
    assert!(!info.to_string().contains("price_"), "{info}");

    // Refused before Stripe is asked: a team-only plan, an interval the plan isn't sold at, and a made-up interval.
    for (body, says) in [
        (json!({ "tier": "business" }), "The Business plan is for teams only"),
        (json!({ "tier": "business", "interval": "year" }), "for teams only"),
        (json!({ "tier": "starter", "interval": "year" }), "The Starter plan isn't sold yearly here"),
        (json!({ "tier": "pro", "interval": "week" }), "Say month or year"),
        (json!({ "tier": "pro", "interval": 12 }), "Say month or year"),
    ] {
        let (code, res) = json_call(port, "POST", "/api/billing/checkout", &w.a, &body.to_string()).await;
        assert_eq!(code, 400, "{body}: {res}");
        assert!(res["error"].as_str().unwrap().contains(says), "{body}: {res}");
    }
    assert!(stripe.seen().is_empty(), "{:?}", stripe.seen());

    // Yearly: the yearly price, for Ada, audited with its interval.
    let (code, res) = json_call(port, "POST", "/api/billing/checkout", &w.a, r#"{"tier":"pro","interval":"year"}"#).await;
    assert_eq!(code, 200, "{res}");
    let s = sessions(&stripe).pop().unwrap();
    assert_eq!((s.get("line_items[0][price]"), s.get("line_items[0][quantity]"), s.get("metadata[superbot_user_id]")), (Some("price_pro_yearly"), Some("1"), Some(w.a_id.as_str())));
    let made = audit(port, &w.admin, "action=billing.checkout_created&outcome=success").await;
    assert_eq!((made[0]["details"]["price"].as_str(), made[0]["details"]["interval"].as_str()), (Some("price_pro_yearly"), Some("year")), "{made:?}");

    // No interval, or monthly: the monthly price, as older apps buy it.
    for body in [r#"{"tier":"pro"}"#, r#"{"tier":"pro","interval":"month"}"#, r#"{"tier":"pro","interval":null}"#] {
        assert_eq!(json_call(port, "POST", "/api/billing/checkout", &w.a, body).await.0, 200, "{body}");
        assert_eq!(sessions(&stripe).pop().unwrap().get("line_items[0][price]"), Some("price_pro_monthly"), "{body}");
    }
    // A tier without checkoutPrices sells its first price, monthly, as before.
    assert_eq!(json_call(port, "POST", "/api/billing/checkout", &w.b, r#"{"tier":"starter","interval":"month"}"#).await.0, 200);
    assert_eq!(sessions(&stripe).pop().unwrap().get("line_items[0][price]"), Some("price_starter_monthly"));

    // Stripe's event for the yearly subscription sets her plan like a monthly one's.
    let sub = event(UPDATED, &w.a_id, "evt_y1", 1_795_000_000, |v| v["data"]["object"]["items"]["data"][0]["price"]["id"] = json!("price_pro_yearly"));
    assert_eq!(deliver(port, &sub, None).await.1["outcome"], "tier_changed");
    assert_eq!(w.app.tier_of(&w.a_id).name, "pro");
}

#[tokio::test]
async fn teams_buy_their_own_prices_and_team_only_plans() {
    let (w, stripe) = shop().await;
    let port = w.port;
    let (code, v) = json_call(port, "POST", "/api/teams", &w.admin, &json!({ "name": "Alpha", "owner": w.a_id }).to_string()).await;
    assert_eq!(code, 201, "{v}");
    let alpha = v["id"].as_str().unwrap().to_string();
    let (code, v) = json_call(port, "PUT", &format!("/api/teams/{alpha}/members/{}", w.b_id), &w.admin, r#"{"role":"member"}"#).await;
    assert_eq!(code, 200, "{v}");

    // The team's owner sees every plan sold to teams, at the team's intervals.
    let (_, mine) = json_call(port, "GET", "/api/team", &w.a, "").await;
    let plans = &mine["billing"]["plans"];
    assert_eq!(names(plans), [("starter".to_string(), Value::Null), ("pro".to_string(), json!(["month", "year"])), ("business".to_string(), json!(["year"]))]);
    assert!(!mine.to_string().contains("price_"), "{mine}");

    let buy = |body: &'static str| json_call(port, "POST", "/api/team/billing/checkout", &w.a, body);
    for (body, says) in [
        (r#"{"tier":"business","interval":"month"}"#, "The Business plan isn't sold monthly here"),
        (r#"{"tier":"starter","interval":"year"}"#, "isn't sold yearly"),
        (r#"{"tier":"pro","interval":"weekly"}"#, "Say month or year"),
    ] {
        let (code, res) = buy(body).await;
        assert_eq!(code, 400, "{body}: {res}");
        assert!(res["error"].as_str().unwrap().contains(says), "{body}: {res}");
    }
    assert!(stripe.seen().is_empty(), "{:?}", stripe.seen());

    // Pro for the team: its team price, a seat each, at the interval asked for, monthly by default.
    for (body, price) in [(r#"{"tier":"pro","interval":"year"}"#, "price_pro_team_yearly"), (r#"{"tier":"pro"}"#, "price_pro_team_monthly")] {
        let (code, res) = buy(body).await;
        assert_eq!(code, 200, "{body}: {res}");
        let s = sessions(&stripe).pop().unwrap();
        assert_eq!((s.get("line_items[0][price]"), s.get("line_items[0][quantity]"), s.get("metadata[superbot_team_id]")), (Some(price), Some("2"), Some(alpha.as_str())), "{body}");
    }
    // A team-only plan, at its only interval.
    assert_eq!(buy(r#"{"tier":"business"}"#).await.0, 200);
    assert_eq!(sessions(&stripe).pop().unwrap().get("line_items[0][price]"), Some("price_business_yearly"));
    let made = audit(port, &w.admin, "action=billing.checkout_created&outcome=success").await;
    let got: Vec<(&str, &str)> = made.iter().map(|e| (e["details"]["price"].as_str().unwrap(), e["details"]["interval"].as_str().unwrap())).collect();
    assert_eq!(got.len(), 3, "{made:?}");
    for want in [("price_pro_team_yearly", "year"), ("price_pro_team_monthly", "month"), ("price_business_yearly", "year")] {
        assert!(got.contains(&want), "{want:?} in {got:?}");
    }

    // Stripe's event for the team-only subscription gives everyone on the team its plan.
    let sub = event(UPDATED, "", "evt_t1", 1_795_000_000, |v| {
        let o = &mut v["data"]["object"];
        o["id"] = json!("sub_test_alpha");
        o["customer"] = json!("cus_test_alpha");
        o["metadata"] = json!({ "superbot_team_id": alpha, "superbot_paid_by": w.a_id });
        o["items"]["data"][0]["id"] = json!("si_test_alpha");
        o["items"]["data"][0]["quantity"] = json!(2);
        o["items"]["data"][0]["price"]["id"] = json!("price_business_yearly");
    });
    assert_eq!(deliver(port, &sub, None).await.1["outcome"], "tier_changed");
    assert_eq!((w.app.tier_of(&w.a_id).name.as_str(), w.app.tier_of(&w.b_id).name.as_str()), ("business", "business"));
    // Bea's own Plan screen shows the team's plan, and still offers no team-only plan for sale.
    let (_, hers) = json_call(port, "GET", "/api/billing", &w.b, "").await;
    assert_eq!(hers["plan"]["name"], "business", "{hers}");
    assert!(names(&hers["plans"]).iter().all(|(n, _)| n != "business"), "{hers}");
}

#[test]
fn startup_says_how_each_tier_is_sold() {
    let t = tiers::Tiers::parse(TIERS, None).unwrap();
    let said = billing::describe(true, true, false, &t);
    assert!(said.contains("starter (1), pro (4; people monthly and yearly, teams monthly and yearly), business (1; teams yearly)"), "{said}");
    assert!(!said.contains("price_"), "{said}");
}

#[tokio::test]
async fn billing_off_sells_nothing_whatever_the_prices() {
    let w = world_on(None, TIERS, |_| {}).await;
    for (path, body) in [("/api/billing/checkout", r#"{"tier":"pro","interval":"year"}"#), ("/api/team/billing/checkout", r#"{"tier":"business","interval":"year"}"#)] {
        let (code, res) = json_call(w.port, "POST", path, &w.a, body).await;
        assert_eq!(code, 404, "{path}: {res}");
    }
    assert!(audit(w.port, &w.admin, "action=billing.checkout_created").await.is_empty());
}
