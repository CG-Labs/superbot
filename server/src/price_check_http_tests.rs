//! Published prices checked against Stripe's (ADR 0350) on the real router, against a
//! fake Stripe on loopback: `GET /api/tiers/stripe-check` reads each tier's Stripe
//! prices with the secret key and reports drift; it calls nothing while billing or
//! checkout is off; and only people with billing.manage may run it. No network, no real
//! keys: the key is a placeholder and Stripe is a local axum server.

use crate::billing::Billing;
use crate::billing_http_tests::{KEY, PUBLIC, SECRET};
use crate::tests::{call, serve_app_with};
use crate::tiers::Tiers;
use crate::users_http_tests::{parse, user_with};
use crate::*;
use std::collections::HashMap;

const TIERS: &str = r#"{ "default": "pro", "tiers": [
  { "name": "pro", "label": "Pro", "routes": "any", "stripePrices": ["price_pro_monthly", "price_pro_yearly"],
    "publishedPrices": [{ "amount": 2900, "currency": "gbp", "interval": "month" }, { "amount": 29000, "currency": "gbp", "interval": "year" }] },
  { "name": "max", "label": "Max", "routes": "any", "stripePrices": ["price_max_monthly"] }
] }"#;

/// Stripe's prices endpoint: the price objects in `prices` by id, 404 for the rest, and
/// every request's path, query and Authorization header.
#[derive(Clone, Default)]
struct FakePrices {
    prices: Arc<std::sync::Mutex<HashMap<String, Value>>>,
    seen: Arc<std::sync::Mutex<Vec<(String, String, String)>>>,
}

impl FakePrices {
    fn set(&self, id: &str, amount: u64, interval: &str, active: bool) {
        let v = json!({ "id": id, "object": "price", "active": active, "currency": "gbp", "unit_amount": amount, "billing_scheme": "per_unit",
                        "type": "recurring", "recurring": { "interval": interval, "interval_count": 1, "usage_type": "licensed" }, "currency_options": {} });
        self.prices.lock().unwrap().insert(id.into(), v);
    }
}

async fn fake_prices() -> (String, FakePrices) {
    use axum::extract::{Path as P, RawQuery, State as S};
    async fn price(S(f): S<FakePrices>, P(id): P<String>, RawQuery(q): RawQuery, headers: axum::http::HeaderMap) -> (StatusCode, Json<Value>) {
        let auth = headers.get("authorization").and_then(|v| v.to_str().ok()).unwrap_or_default().to_string();
        f.seen.lock().unwrap().push((id.clone(), q.unwrap_or_default(), auth));
        match f.prices.lock().unwrap().get(&id) {
            Some(v) => (StatusCode::OK, Json(v.clone())),
            None => (StatusCode::NOT_FOUND, Json(json!({ "error": { "type": "invalid_request_error", "code": "resource_missing", "message": format!("No such price: '{id}'") } }))),
        }
    }
    let f = FakePrices::default();
    let r = axum::Router::new().route("/v1/prices/{id}", axum::routing::get(price)).with_state(f.clone());
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, r).await.unwrap() });
    (url, f)
}

async fn server(payments: Billing) -> (u16, AppState, String) {
    let (port, app, admin, _) = serve_app_with(|a| a.payments = payments).await;
    app.tiers.set(Arc::new(Tiers::parse(TIERS, None).unwrap())).unwrap();
    (port, app, admin)
}

async fn check(port: u16, who: &str) -> (u16, Value) {
    let (code, body) = call(port, "GET", "/api/tiers/stripe-check", who, "").await;
    (code, parse(&body))
}

#[tokio::test]
async fn matching_prices_pass_and_drift_is_reported() {
    let (url, f) = fake_prices().await;
    f.set("price_pro_monthly", 2900, "month", true);
    f.set("price_pro_yearly", 29000, "year", true);
    f.set("price_max_monthly", 9900, "month", true);
    let (port, _, admin) = server(Billing::with_checkout(SECRET, KEY, &url, PUBLIC)).await;

    let (code, v) = check(port, &admin).await;
    assert_eq!(code, 200, "{v}");
    assert_eq!(v["status"], "ok", "{v}");
    assert_eq!(v["detail"], "Every published price matches Stripe's (3 Stripe prices read).");
    assert_eq!(v["tiers"][0]["prices"][0], json!({ "id": "price_pro_monthly", "soldAtCheckout": true, "active": true, "charges": ["£29 / month"], "error": null }));
    assert_eq!(v["tiers"][1]["notes"][0], "no publishedPrices, so the page says \"Contact us\"; checkout charges £99 / month (price_max_monthly)");
    let seen = f.seen.lock().unwrap().clone();
    assert_eq!(seen.len(), 3, "each price once: {seen:?}");
    for (_, query, auth) in &seen {
        assert_eq!((query.as_str(), auth.as_str()), ("expand%5B%5D=currency_options", format!("Bearer {KEY}").as_str()));
    }

    // Stripe's monthly price moved; the published one didn't.
    f.set("price_pro_monthly", 3400, "month", true);
    // And the yearly one was archived.
    f.set("price_pro_yearly", 29000, "year", false);
    let (code, v) = check(port, &admin).await;
    assert_eq!(code, 200);
    assert_eq!(v["status"], "drift", "{v}");
    assert_eq!(
        v["tiers"][0]["problems"],
        json!([
            "the page shows £29 / month, but checkout charges £34 / month (price_pro_monthly)",
            "the page shows £290 / year, but no active Stripe price of the tier charges it: price_pro_yearly £290 / year (archived)"
        ])
    );
    let body = v.to_string();
    assert!(!body.contains(KEY) && !body.contains(SECRET), "{body}");
}

#[tokio::test]
async fn a_price_stripe_doesnt_have_is_drift_and_a_dead_stripe_leaves_it_unchecked() {
    let (url, f) = fake_prices().await;
    f.set("price_pro_monthly", 2900, "month", true);
    f.set("price_max_monthly", 9900, "month", true);
    let (port, _, admin) = server(Billing::with_checkout(SECRET, KEY, &url, PUBLIC)).await;
    let (_, v) = check(port, &admin).await;
    assert_eq!(v["status"], "drift", "{v}");
    assert_eq!(v["tiers"][0]["prices"][1]["error"], "no such price");
    assert!(v["tiers"][0]["problems"][0].as_str().unwrap().starts_with("Stripe has no price price_pro_yearly"), "{v}");

    // Nothing listens: every price is unread, so nothing is known to drift.
    let closed = { tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.unwrap().local_addr().unwrap() };
    let (port, _, admin) = server(Billing::with_checkout(SECRET, KEY, &format!("http://{closed}"), PUBLIC)).await;
    let (code, v) = check(port, &admin).await;
    assert_eq!(code, 200);
    assert_eq!(v["status"], "unchecked", "{v}");
    assert_eq!(v["tiers"][0]["unchecked"][0], "couldn't read price_pro_monthly from Stripe (no answer from Stripe)");
}

#[tokio::test]
async fn nothing_is_called_while_billing_or_checkout_is_off() {
    let (port, _, admin) = server(Billing::default()).await;
    let (code, v) = check(port, &admin).await;
    assert_eq!(code, 200, "{v}");
    assert_eq!(v["status"], "off");
    assert!(v["detail"].as_str().unwrap().starts_with("Billing is off"), "{v}");
    let (port, _, admin) = server(Billing::with_secret(SECRET)).await;
    let (_, v) = check(port, &admin).await;
    assert_eq!(v["status"], "off");
    assert!(v["detail"].as_str().unwrap().contains("without STRIPE_SECRET_KEY"), "{v}");
}

#[tokio::test]
async fn only_billing_managers_run_it_and_not_too_often() {
    let (url, f) = fake_prices().await;
    f.set("price_pro_monthly", 2900, "month", true);
    f.set("price_pro_yearly", 29000, "year", true);
    f.set("price_max_monthly", 9900, "month", true);
    let (port, _, admin) = server(Billing::with_checkout(SECRET, KEY, &url, PUBLIC)).await;
    let (_, member) = user_with(port, &admin, "ada@example.com", "member").await;
    assert_eq!(check(port, &member).await.0, 403);
    assert_eq!(check(port, "").await.0, 401);
    assert!(f.seen.lock().unwrap().is_empty(), "refused before Stripe is called");

    let (code, body) = call(port, "POST", "/api/roles", &admin, &json!({ "name": "Billing", "base": "member", "permissions": ["billing.manage"] }).to_string()).await;
    assert_eq!(code, 201, "{body}");
    let role = parse(&body)["id"].as_str().unwrap().to_string();
    let (bea_id, bea) = user_with(port, &admin, "bea@example.com", "member").await;
    let (code, body) = call(port, "PUT", &format!("/api/roles/{role}/users/{bea_id}"), &admin, "").await;
    assert_eq!(code, 200, "{body}");
    assert_eq!(check(port, &bea).await, (200, check(port, &admin).await.1));

    // Ten checks a minute, server-wide, so the route can't flood Stripe.
    let mut codes = Vec::new();
    for _ in 0..10 {
        codes.push(check(port, &admin).await.0);
    }
    assert!(codes.contains(&429), "{codes:?}");
    assert!(f.seen.lock().unwrap().len() <= 30, "at most ten checks of three prices");
}
