//! Published plans (ADR 0121) on the real router: `/api/plans` and `/pricing` answer
//! anyone once plans are published and 404 until then, list each sold tier's published
//! prices and enforced limits, and never show a Stripe price id, model or route.

use crate::plans::{Mode, Settings};
use crate::tests::{call, call_with, serve_app};
use crate::tiers::Tiers;
use crate::users_http_tests::parse;
use crate::*;

const TIERS: &str = r#"{
  "default": "starter",
  "tiers": [
    { "name": "starter", "label": "Starter", "routes": [{ "harness": "hermes", "provider": "openrouter", "model": "vendor/hidden-model" }],
      "limits": { "maxBots": 3, "monthlyRuns": 300, "machineType": "g6-standard-1", "maxStorageMb": 5000 },
      "stripePrices": ["price_starter_monthly_secret"],
      "publishedPrices": [{ "amount": 1900, "currency": "eur", "interval": "month" }] },
    { "name": "max", "label": "Max", "routes": "any", "limits": { "maxBots": 30 }, "stripePrices": ["price_max_monthly_secret"] },
    { "name": "self-host", "routes": "any" }
  ]
}"#;

fn header<'a>(head: &'a str, name: &str) -> Option<&'a str> {
    head.lines().find_map(|l| l.split_once(':').filter(|(k, _)| k.trim().eq_ignore_ascii_case(name)).map(|(_, v)| v.trim()))
}

async fn server(plans: Option<Settings>) -> (u16, AppState, String) {
    let (port, app, admin, _) = serve_app().await;
    app.tiers.set(Arc::new(Tiers::parse(TIERS, None).unwrap())).unwrap();
    if let Some(s) = plans {
        app.plans.set(s).unwrap();
    }
    (port, app, admin)
}

fn published(contact: Option<&str>) -> Settings {
    Settings { mode: Mode::On, published: true, contact: contact.map(String::from), checkout: false, signups: true }
}

#[tokio::test]
async fn nothing_is_published_unless_turned_on() {
    // A server whose plans settings were never set, as with billing off and PLANS_PAGE=auto.
    let (port, _, admin) = server(None).await;
    for path in ["/api/plans", "/pricing"] {
        let (code, body) = call(port, "GET", path, "", "").await;
        assert_eq!(code, 404, "{path}: {body}");
        assert!(body.contains("PLANS_PAGE") && !body.contains("Starter"), "{path}: {body}");
        assert_eq!(call(port, "GET", path, &admin, "").await.0, 404, "admins too: {path}");
    }
    let off = Settings::from_env(&|_| String::new(), false, false, true).unwrap();
    let (port, _, _) = server(Some(off)).await;
    assert_eq!(call(port, "GET", "/api/plans", "", "").await.0, 404, "auto with billing off");
    let off = Settings::from_env(&|k| if k == "PLANS_PAGE" { "off".into() } else { String::new() }, true, true, true).unwrap();
    let (port, _, _) = server(Some(off)).await;
    assert_eq!(call(port, "GET", "/pricing", "", "").await.0, 404, "off even with billing on");
}

#[tokio::test]
async fn anyone_reads_the_plans_without_secrets() {
    let (port, _, _) = server(Some(published(Some("https://example.com/contact")))).await;
    let (code, head, body) = call_with(port, "GET", "/api/plans", "", "", "").await;
    assert_eq!(code, 200, "{body}");
    assert!(header(&head, "content-type").is_some_and(|v| v.starts_with("application/json")), "{head}");
    assert_eq!(header(&head, "x-content-type-options"), Some("nosniff"));
    assert!(header(&head, "cache-control").is_some_and(|v| v.starts_with("public")), "{head}");
    let v = parse(&body);
    let names: Vec<&str> = v["plans"].as_array().unwrap().iter().map(|p| p["name"].as_str().unwrap()).collect();
    assert_eq!(names, ["starter", "max"], "self-host isn't sold: {v}");
    let starter = &v["plans"][0];
    assert_eq!(starter["label"], "Starter");
    assert_eq!(starter["prices"], json!([{ "amount": 1900, "currency": "eur", "interval": "month", "display": "€19 / month" }]));
    assert_eq!(starter["limits"]["maxBots"], 3);
    assert_eq!(starter["limits"]["monthlyTokens"], Value::Null, "no limit");
    assert_eq!(starter["limits"]["concurrentRuns"], crate::slots::DEFAULT_CAP, "the server's own cap when the tier sets none");
    assert_eq!(starter["machine"], Value::Null, "no control plane, so no size to publish");
    assert_eq!(v["plans"][1]["prices"], json!([]), "Max has no published price");
    assert_eq!(v["enterprise"], json!({ "label": "Enterprise", "contactUrl": "https://example.com/contact" }));
    assert_eq!((v["checkout"].as_bool(), v["buyUrl"].clone(), v["signupUrl"].as_str()), (Some(false), Value::Null, Some("/get-started")));
    for secret in ["price_", "hidden-model", "openrouter", "hermes", "g6-standard-1", "stripePrices", "routes", "self-host"] {
        assert!(!body.contains(secret), "{secret} leaked: {body}");
    }
}

#[tokio::test]
async fn the_pricing_page_renders_the_same_plans() {
    let (port, _, _) = server(Some(published(Some("mailto:sales@example.com")))).await;
    let (code, head, body) = call_with(port, "GET", "/pricing", "", "", "").await;
    assert_eq!(code, 200, "{body}");
    assert!(header(&head, "content-type").is_some_and(|v| v.starts_with("text/html")), "{head}");
    assert!(header(&head, "content-security-policy").is_some_and(|v| v.contains("default-src 'none'") && !v.contains("script")), "{head}");
    assert!(body.contains("<h2>Starter</h2>") && body.contains("€19 / month") && body.contains("3 Bots") && body.contains("5 GB of storage"), "{body}");
    assert!(body.contains("<h2>Max</h2>") && body.contains("<a href=\"mailto:sales@example.com\">Contact us</a>"), "{body}");
    assert!(body.contains("Contact sales") && body.contains("href=\"/get-started\"") && body.contains("href=\"/status\""), "{body}");
    assert!(!body.contains("<script") && !body.contains("price_") && !body.contains("hidden-model"), "{body}");
}

#[tokio::test]
async fn signed_in_people_see_published_prices_but_not_stripe_ids() {
    let (port, _, admin) = server(Some(published(None))).await;
    let (code, body) = call(port, "GET", "/api/me/tier", &admin, "").await;
    assert_eq!(code, 200, "{body}");
    let v = parse(&body);
    assert_eq!(v["publishedPrices"][0]["amount"], 1900, "{v}");
    assert!(!body.contains("price_starter"), "{body}");
    // Without a contact link there's no Enterprise entry, and Max says Contact us without one.
    let (_, page) = call(port, "GET", "/pricing", "", "").await;
    assert!(!page.contains("Contact sales") && page.contains("<p class=\"price\">Contact us</p>"), "{page}");
}
