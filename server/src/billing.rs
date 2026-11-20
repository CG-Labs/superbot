//! Billing v0 (ADR 0040): Stripe subscriptions set each user's tier. Off unless
//! `STRIPE_WEBHOOK_SECRET` is set, and then the only way in is Stripe's signed webhook at
//! `/billing/stripe/webhook`. botd never calls Stripe: no keys to Stripe's API, no
//! products, prices, or checkout here. The tiers file maps Stripe price ids to tiers
//! (`stripePrices`); a subscription event names its user in its metadata
//! (`superbot_user_id`), set by whatever starts the checkout.

use crate::audit::{Actor, Outcome, Who};
use crate::db::{Applied, Subscription};
use crate::runner::App;
use crate::secrets::SecretStore;
use crate::{AppState, Auth};
use aws_lc_rs::hmac;
use axum::body::Bytes;
use axum::extract::{Extension, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::{json, Value};
use std::sync::Arc;

pub const PATH: &str = "/billing/stripe/webhook";
/// Stripe's own default: a signature older (or newer) than this is refused.
pub const TOLERANCE_SECS: i64 = 300;
/// Subscription events are a few KiB; this is generous.
pub const MAX_BODY: usize = 512 * 1024;
/// The subscription metadata key naming the SuperBot user it pays for.
pub const USER_KEY: &str = "superbot_user_id";

/// Statuses that pay for the subscription's tier. `past_due` keeps it while Stripe
/// retries the card; Stripe moves it to `canceled` or `unpaid` when it gives up.
const PAYING: [&str; 3] = ["active", "trialing", "past_due"];
/// Statuses that end it: the user goes back to the default tier.
const ENDED: [&str; 4] = ["canceled", "unpaid", "incomplete_expired", "paused"];

#[derive(Default)]
pub struct Billing {
    /// The webhook signing secret (`whsec_...`). None: billing is off.
    secret: Option<String>,
    /// Refused deliveries recorded in the audit log, so junk can't flood it.
    refusals: crate::users::Limiter,
}

impl Billing {
    /// `STRIPE_WEBHOOK_SECRET` (or `_FILE`).
    pub fn from_env(store: &dyn SecretStore) -> Result<Billing, String> {
        let Some(s) = store.get("STRIPE_WEBHOOK_SECRET").map_err(|e| e.to_string())? else { return Ok(Billing::default()) };
        let s = s.expose().trim().to_string();
        if !s.starts_with("whsec_") || s.len() < 10 {
            return Err("STRIPE_WEBHOOK_SECRET must be the endpoint's signing secret from Stripe (whsec_...)".into());
        }
        crate::secrets::redact::register(&s);
        Ok(Billing::with_secret(&s))
    }

    pub fn with_secret(secret: &str) -> Billing {
        Billing { secret: Some(secret.into()), refusals: crate::users::Limiter::new(20, 60_000) }
    }

    pub fn enabled(&self) -> bool {
        self.secret.is_some()
    }
}

/// What startup prints. Takes only whether billing is on, so nothing secret can reach the log.
pub fn describe(enabled: bool, tiers: &crate::tiers::Tiers) -> String {
    if !enabled {
        return "off (set STRIPE_WEBHOOK_SECRET to take Stripe subscriptions)".into();
    }
    let priced: Vec<String> = tiers.all().iter().filter(|t| !t.stripe_prices.is_empty()).map(|t| format!("{} ({})", t.name, t.stripe_prices.len())).collect();
    match priced.is_empty() {
        true => format!("Stripe webhook at {PATH}, but no tier lists stripePrices, so no subscription sets a tier"),
        false => format!("Stripe webhook at {PATH}; prices for {}", priced.join(", ")),
    }
}

/// Checks a `Stripe-Signature` header (`t=<unix>,v1=<hex>[,v1=...]`) over the raw body:
/// HMAC-SHA256 of `<t>.<body>` with the endpoint secret, any `v1` matching, compared in
/// constant time, and `t` within `TOLERANCE_SECS` of `now`.
pub fn verify(secret: &str, header: &str, body: &[u8], now: i64) -> Result<(), &'static str> {
    let mut t: Option<i64> = None;
    let mut sigs: Vec<Vec<u8>> = Vec::new();
    for part in header.split(',') {
        match part.trim().split_once('=') {
            Some(("t", v)) => t = Some(v.parse().map_err(|_| "bad_timestamp")?),
            Some(("v1", v)) => sigs.extend(hex(v)),
            _ => {}
        }
    }
    let t = t.ok_or("no_timestamp")?;
    if sigs.is_empty() {
        return Err("no_signature");
    }
    if (now - t).abs() > TOLERANCE_SECS {
        return Err("too_old");
    }
    let key = hmac::Key::new(hmac::HMAC_SHA256, secret.as_bytes());
    let mut signed = format!("{t}.").into_bytes();
    signed.extend_from_slice(body);
    if sigs.iter().any(|s| hmac::verify(&key, &signed, s).is_ok()) { Ok(()) } else { Err("bad_signature") }
}

fn hex(s: &str) -> Option<Vec<u8>> {
    if s.len() != 64 {
        return None;
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok()).collect()
}

/// `<t>`'s `Stripe-Signature` header for `body`, as Stripe makes it. For tests and fixtures.
#[cfg(test)]
pub fn sign(secret: &str, body: &[u8], t: i64) -> String {
    let key = hmac::Key::new(hmac::HMAC_SHA256, secret.as_bytes());
    let mut signed = format!("{t}.").into_bytes();
    signed.extend_from_slice(body);
    let tag = hmac::sign(&key, &signed);
    format!("t={t},v1={}", tag.as_ref().iter().map(|b| format!("{b:02x}")).collect::<String>())
}

fn reply(code: StatusCode, v: Value) -> Response {
    (code, Json(v)).into_response()
}

fn system(on_behalf_of: Option<&str>) -> Who {
    let mut actor = Actor::system("billing");
    actor.on_behalf_of = on_behalf_of.map(String::from);
    Who { actor, source: Default::default() }
}

/// `POST /billing/stripe/webhook`: Stripe's events. 404 while billing is off, 400 for a
/// delivery that isn't Stripe's (bad, missing, or stale signature, or not an event),
/// else 200, also for events it doesn't use, so Stripe doesn't retry them.
pub async fn webhook(State(app): State<AppState>, Extension(a): Extension<Arc<Auth>>, headers: HeaderMap, body: Bytes) -> Response {
    let b = &a.billing;
    let Some(secret) = &b.secret else {
        return reply(StatusCode::NOT_FOUND, json!({ "error": "Billing is off on this server." }));
    };
    let header = headers.get("stripe-signature").and_then(|h| h.to_str().ok()).unwrap_or("");
    let now = crate::db::now() / 1000;
    if let Err(reason) = verify(secret, header, &body, now) {
        refused(&app, b, reason);
        return reply(StatusCode::BAD_REQUEST, json!({ "error": "The Stripe signature doesn't match." }));
    }
    let Ok(event) = serde_json::from_slice::<Value>(&body) else {
        refused(&app, b, "not_json");
        return reply(StatusCode::BAD_REQUEST, json!({ "error": "Not a Stripe event." }));
    };
    let (Some(id), Some(kind)) = (event["id"].as_str(), event["type"].as_str()) else {
        refused(&app, b, "not_an_event");
        return reply(StatusCode::BAD_REQUEST, json!({ "error": "Not a Stripe event." }));
    };
    if !kind.starts_with("customer.subscription.") {
        return reply(StatusCode::OK, json!({ "received": true, "outcome": "ignored" }));
    }
    match subscription_event(&app, id, kind, &event) {
        Ok(outcome) => reply(StatusCode::OK, json!({ "received": true, "outcome": outcome })),
        // Stripe retries a 500, which is right for a database hiccup.
        Err(e) => {
            eprintln!("billing: Stripe event {id}: {e}");
            reply(StatusCode::INTERNAL_SERVER_ERROR, json!({ "error": "Couldn't save the event; Stripe will retry." }))
        }
    }
}

fn refused(app: &App, b: &Billing, reason: &str) {
    let at = crate::db::now();
    if b.refusals.blocked("stripe", at).is_none() {
        b.refusals.fail("stripe", at);
        app.db.record(&system(None).event("billing.webhook_refused").outcome(Outcome::Denied).details(json!({ "reason": reason })));
    }
}

/// The parts of a Stripe subscription object botd reads.
struct Sub<'a> {
    id: &'a str,
    customer: Option<&'a str>,
    status: &'a str,
    user: Option<&'a str>,
    prices: Vec<&'a str>,
    period_end: Option<i64>,
}

fn read_sub(o: &Value) -> Option<Sub<'_>> {
    let items = o["items"]["data"].as_array().map(Vec::as_slice).unwrap_or_default();
    Some(Sub {
        id: o["id"].as_str().filter(|s| !s.is_empty())?,
        customer: o["customer"].as_str().or_else(|| o["customer"]["id"].as_str()),
        status: o["status"].as_str()?,
        user: o["metadata"][USER_KEY].as_str().map(str::trim).filter(|s| !s.is_empty()),
        prices: items.iter().filter_map(|i| i["price"]["id"].as_str()).collect(),
        period_end: o["current_period_end"].as_i64().or_else(|| items.iter().find_map(|i| i["current_period_end"].as_i64())),
    })
}

/// Applies a `customer.subscription.*` event: the tier its price pays for while it
/// pays, the default tier once it ends. Returns what happened, for the reply.
fn subscription_event(app: &App, event_id: &str, kind: &str, event: &Value) -> Result<&'static str, String> {
    let ignore = |reason: &str, user: Option<&str>, extra: Value| {
        let mut d = json!({ "reason": reason, "eventId": event_id, "type": kind });
        if let (Some(d), Value::Object(x)) = (d.as_object_mut(), extra) {
            d.extend(x);
        }
        let e = system(user).event("billing.event_ignored").outcome(Outcome::Failure).details(d);
        app.db.record(&match user {
            Some(u) => e.target("user", u),
            None => e,
        });
        Ok("ignored")
    };
    let Some(sub) = read_sub(&event["data"]["object"]) else {
        return ignore("not_a_subscription", None, json!({}));
    };
    // The metadata names the user; later events for the same subscription may not carry
    // it, so the subscription we already know names them too.
    let known = app.db.subscription_by_id(sub.id);
    let user = match sub.user.map(String::from).or_else(|| known.as_ref().map(|s| s.user_id.clone())) {
        Some(u) if app.db.user(&u).is_some() => u,
        other => return ignore("unknown_user", None, json!({ "subscription": sub.id, "user": other })),
    };
    let tiers = app.tiers();
    let priced = sub.prices.iter().find_map(|p| tiers.by_stripe_price(p).map(|t| (*p, t)));
    let ending = kind == "customer.subscription.deleted" || ENDED.contains(&sub.status);
    let (tier, set_tier) = if ending {
        (None, true)
    } else if PAYING.contains(&sub.status) {
        match priced {
            Some((_, t)) => (Some(t.name.clone()), true),
            None => return ignore("unknown_price", Some(&user), json!({ "subscription": sub.id, "prices": sub.prices })),
        }
    } else {
        // `incomplete`: the first payment hasn't gone through. Nothing changes yet.
        (None, false)
    };
    let row = Subscription {
        user_id: user.clone(),
        provider: "stripe".into(),
        customer_id: sub.customer.map(String::from),
        subscription_id: sub.id.into(),
        status: if kind == "customer.subscription.deleted" { "canceled".into() } else { sub.status.into() },
        price_id: priced.map(|(p, _)| p.to_string()).or_else(|| sub.prices.first().map(|p| p.to_string())),
        tier: tier.clone(),
        period_end: sub.period_end,
        event_created: event["created"].as_i64().unwrap_or(0),
        updated_at: 0,
    };
    let applied = app.db.apply_subscription(event_id, kind, &row, set_tier, ending)?;
    let details = json!({ "eventId": event_id, "type": kind, "subscription": sub.id, "status": row.status, "price": row.price_id, "tier": tier });
    let by = system(Some(&user));
    let outcome = match applied {
        Applied::Duplicate => return Ok("duplicate"),
        Applied::Stale => "stale",
        Applied::Superseded => "superseded",
        Applied::OtherUser => return ignore("subscription_of_another_user", Some(&user), json!({ "subscription": sub.id })),
        Applied::Unchanged => "unchanged",
        Applied::Changed { from, to } => {
            let effective = |t: &Option<String>| tiers.of(t.as_deref()).name.clone();
            let mut d = json!({ "from": from, "to": to, "effectiveFrom": effective(&from), "effectiveTo": effective(&to), "source": "stripe" });
            if let (Some(d), Value::Object(x)) = (d.as_object_mut(), details.clone()) {
                d.extend(x);
            }
            app.db.record(&by.event("user.tier_changed").target("user", &user).details(d));
            "tier_changed"
        }
    };
    let mut d = details;
    d["outcome"] = json!(outcome);
    app.db.record(&by.event("billing.subscription_synced").target("user", &user).details(d));
    Ok(outcome)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "whsec_test_not_a_real_secret";

    #[test]
    fn signatures_are_checked_like_stripe_does() {
        let body = br#"{"id":"evt_1","type":"customer.subscription.updated"}"#;
        let now = 1_800_000_000;
        let good = sign(SECRET, body, now);
        assert_eq!(verify(SECRET, &good, body, now), Ok(()));
        // Within the tolerance either way; outside it, refused even when signed.
        assert_eq!(verify(SECRET, &good, body, now + TOLERANCE_SECS), Ok(()));
        assert_eq!(verify(SECRET, &good, body, now + TOLERANCE_SECS + 1), Err("too_old"));
        assert_eq!(verify(SECRET, &good, body, now - TOLERANCE_SECS - 1), Err("too_old"));
        // Another secret, another body, or another timestamp than the one signed.
        assert_eq!(verify("whsec_other", &good, body, now), Err("bad_signature"));
        assert_eq!(verify(SECRET, &good, br#"{"id":"evt_2"}"#, now), Err("bad_signature"));
        let moved = good.replacen(&format!("t={now}"), &format!("t={}", now + 1), 1);
        assert_eq!(verify(SECRET, &moved, body, now), Err("bad_signature"));
        // Any v1 may match (Stripe sends several while a secret is being rolled); v0 never counts.
        let v1 = good.split_once("v1=").unwrap().1;
        let rolled = format!("t={now},v1={},v1={v1}", "0".repeat(64));
        assert_eq!(verify(SECRET, &rolled, body, now), Ok(()));
        assert_eq!(verify(SECRET, &format!("t={now},v0={v1}"), body, now), Err("no_signature"));
        // Malformed headers.
        assert_eq!(verify(SECRET, "", body, now), Err("no_timestamp"));
        assert_eq!(verify(SECRET, &format!("v1={v1}"), body, now), Err("no_timestamp"));
        assert_eq!(verify(SECRET, &format!("t=soon,v1={v1}"), body, now), Err("bad_timestamp"));
        assert_eq!(verify(SECRET, &format!("t={now},v1=zz"), body, now), Err("no_signature"));
        assert_eq!(verify(SECRET, &format!("t={now},v1={}", &v1[..62]), body, now), Err("no_signature"));
    }

    #[test]
    fn the_secret_is_checked_at_startup() {
        use crate::secrets::env::EnvStore;
        assert!(!Billing::from_env(&EnvStore::fixed(&[])).unwrap().enabled());
        assert!(Billing::from_env(&EnvStore::fixed(&[("STRIPE_WEBHOOK_SECRET", SECRET)])).unwrap().enabled());
        let e = Billing::from_env(&EnvStore::fixed(&[("STRIPE_WEBHOOK_SECRET", "sk_live_nope")])).err().unwrap();
        assert!(e.contains("whsec_"), "{e}");
    }
}
