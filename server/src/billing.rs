//! Billing v0: Stripe subscriptions set each user's tier (ADR 0040), and people buy and
//! manage them through Stripe's own pages (ADR 0042). Off unless `BILLING=on` and
//! `STRIPE_WEBHOOK_SECRET` are both set, and never in testing mode (ADR 0068); then Stripe's signed webhook at `/billing/stripe/webhook` is the only way a
//! tier changes. With `STRIPE_SECRET_KEY` too, botd also asks Stripe for a Checkout
//! Session (`POST /api/billing/checkout`) and a Billing Portal session
//! (`POST /api/billing/portal`) and hands back their links; it creates nothing else at
//! Stripe. The tiers file maps Stripe price ids to tiers (`stripePrices`); a subscription
//! names its user in its metadata (`superbot_user_id`, set by the checkout), or through
//! its customer, linked to the user when their checkout completes. With
//! `STRIPE_METER_EVENT` too (off by default), botd reports each run's model tokens to
//! that Stripe meter (ADR 0050); it never does without it. A team's plan, paid for by
//! the team for everyone on it, lives in `team_billing` (ADR 0093); events for it pass
//! through here first, and a team plan overrides its members' own.

use crate::audit::{Actor, Outcome, Who};
use crate::db::{Applied, Linked, Subscription};
use crate::runner::App;
use crate::secrets::SecretStore;
use crate::stripe::{self, Stripe};
use crate::tiers::{Buyer, Interval, Tier};
use crate::users::Caller;
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
/// Where the web client shows the plan; Stripe sends people back here.
pub const RETURN_PATH: &str = "/app/plan";
/// Checkout and portal sessions one person may start a minute.
const STARTS_PER_MINUTE: u32 = 10;
const OFF: &str = "Billing is off while SuperBot is in testing: nothing is charged.";
/// What people see while billing is off: we are in testing, so nothing calls Stripe.
pub const OFF_DETAIL: &str = "Billing is off during testing: SuperBot makes no Stripe calls and charges nothing.";
/// Stripe settings that do nothing while billing is off.
const STRIPE_VARS: [&str; 3] = ["STRIPE_WEBHOOK_SECRET", "STRIPE_SECRET_KEY", "STRIPE_METER_EVENT"];
/// How long a checkout page stays payable, in minutes past the current one. Stripe's
/// shortest is 30 minutes from creation; whole minutes keep a retried request identical.
pub(crate) const CHECKOUT_MINUTES: i64 = 31;

/// Statuses that pay for the subscription's tier. `past_due` keeps it while Stripe
/// retries the card; Stripe moves it to `canceled` or `unpaid` when it gives up.
pub(crate) const PAYING: [&str; 3] = ["active", "trialing", "past_due"];
/// Statuses that end it: the user goes back to the default tier.
pub const ENDED: [&str; 4] = ["canceled", "unpaid", "incomplete_expired", "paused"];
/// Ended for good: Stripe never moves a subscription out of these, so no later event,
/// even one from the same second, makes it pay again.
pub const FINAL: [&str; 2] = ["canceled", "incomplete_expired"];

#[derive(Default)]
pub struct Billing {
    /// The webhook signing secret (`whsec_...`). None: billing is off.
    secret: Option<String>,
    /// Refused deliveries recorded in the audit log, so junk can't flood it.
    refusals: crate::users::Limiter,
    /// Checkout and the customer portal (ADR 0042). None without `STRIPE_SECRET_KEY`.
    checkout: Option<Checkout>,
    /// Token metering (ADR 0050). None without `STRIPE_METER_EVENT`: the default.
    meter: Option<Arc<Meter>>,
    /// Team seats (ADR 0093): on with checkout.
    seats: Option<Arc<crate::team_billing::Seats>>,
}

/// Reports each run's tokens to a Stripe meter as meter events (ADR 0050).
pub struct Meter {
    stripe: Stripe,
    /// The meter's event name at Stripe.
    event: String,
}

/// Token rows sent to Stripe per pass.
const METER_BATCH: u32 = 100;
/// Passes a row may fail to reach Stripe before botd gives up on it.
const METER_TRIES: i64 = 5;
const METER_EVERY: std::time::Duration = std::time::Duration::from_secs(60);

/// What botd needs to send people to Stripe's pages and back.
pub struct Checkout {
    pub(crate) stripe: Stripe,
    /// The https address people open SuperBot at, with no trailing slash.
    pub(crate) public_url: String,
    starts: crate::users::Limiter,
    /// One checkout at a time per person, so two can't both be opened and paid.
    busy: std::sync::Mutex<std::collections::HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
}

/// `BILLING`: off unless set to on/1/true/yes.
pub fn billing_flag(raw: &str) -> Result<bool, String> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "on" | "yes" => Ok(true),
        "" | "0" | "false" | "off" | "no" => Ok(false),
        _ => Err(format!("BILLING must be on or off, not \"{raw}\"")),
    }
}

impl Billing {
    /// Billing as configured: off (no Stripe client at all) unless `BILLING=on`, which
    /// testing mode refuses. Also returns a warning when Stripe settings are present but
    /// ignored, so an operator isn't surprised either way.
    pub fn configured(store: &dyn SecretStore, var: &dyn Fn(&str) -> String, testing: bool) -> Result<(Billing, Option<String>), String> {
        let on = billing_flag(&var("BILLING"))?;
        if on && testing {
            return Err("BILLING=on can't be used with TESTING_MODE=on: testing mode keeps billing off. Unset one of them".into());
        }
        if on {
            return Billing::from_env(store, var).map(|b| (b, None));
        }
        // Only whether each is set: a secret (or its _FILE) is never read while billing is off.
        let set: Vec<&str> = STRIPE_VARS.into_iter().filter(|k| [k.to_string(), format!("{k}_FILE")].iter().any(|n| !var(n).trim().is_empty())).collect();
        let warning = (!set.is_empty()).then(|| format!("{} set, but billing is off (BILLING isn't on), so they're ignored and nothing calls Stripe.", set.join(", ")));
        Ok((Billing::default(), warning))
    }

    /// `STRIPE_WEBHOOK_SECRET` and `STRIPE_SECRET_KEY` (or their `_FILE`s), and for
    /// checkout, the public address from `var` (see `public_url`).
    pub fn from_env(store: &dyn SecretStore, var: &dyn Fn(&str) -> String) -> Result<Billing, String> {
        let key = store.get("STRIPE_SECRET_KEY").map_err(|e| e.to_string())?.map(|k| k.expose().trim().to_string()).filter(|k| !k.is_empty());
        let meter = meter_event(&var("STRIPE_METER_EVENT"))?;
        if meter.is_some() && key.is_none() {
            return Err("STRIPE_METER_EVENT needs STRIPE_SECRET_KEY, to send Stripe the meter events".into());
        }
        let Some(s) = store.get("STRIPE_WEBHOOK_SECRET").map_err(|e| e.to_string())? else {
            return match key {
                Some(_) => Err("STRIPE_SECRET_KEY needs STRIPE_WEBHOOK_SECRET too: without the webhook, a checkout would never change anyone's plan".into()),
                None => Ok(Billing::default()),
            };
        };
        let s = s.expose().trim().to_string();
        if !s.starts_with("whsec_") || s.len() < 10 {
            return Err("STRIPE_WEBHOOK_SECRET must be the endpoint's signing secret from Stripe (whsec_...)".into());
        }
        crate::secrets::redact::register(&s);
        let mut b = Billing::with_secret(&s);
        if let Some(key) = key {
            if !["sk_test_", "sk_live_", "rk_test_", "rk_live_"].iter().any(|p| key.starts_with(p)) || key.len() < 16 {
                return Err("STRIPE_SECRET_KEY must be a Stripe secret or restricted key (sk_... or rk_...), not the publishable key".into());
            }
            crate::secrets::redact::register(&key);
            let public = public_url(var)?;
            b.checkout = Some(Checkout::new(&key, stripe::API, &public));
            b.seats = Some(Arc::new(crate::team_billing::Seats::new(Stripe::new(&key, stripe::API))));
            b.meter = meter.map(|event| Arc::new(Meter { stripe: Stripe::new(&key, stripe::API), event }));
        }
        Ok(b)
    }

    pub fn with_secret(secret: &str) -> Billing {
        Billing { secret: Some(secret.into()), refusals: crate::users::Limiter::new(20, 60_000), checkout: None, meter: None, seats: None }
    }

    /// Team seat sync, while checkout is on.
    pub fn seats(&self) -> Option<Arc<crate::team_billing::Seats>> {
        self.seats.clone()
    }

    pub(crate) fn checkout(&self) -> Option<&Checkout> {
        self.checkout.as_ref()
    }

    /// `with_checkout`, reporting tokens to the meter `event` through the API at `api`.
    #[cfg(test)]
    pub fn with_metering(secret: &str, key: &str, api: &str, public_url: &str, event: &str) -> Billing {
        Billing { meter: Some(Arc::new(Meter { stripe: Stripe::new(key, api), event: event.into() })), ..Billing::with_checkout(secret, key, api, public_url) }
    }

    /// The token meter, when `STRIPE_METER_EVENT` turned it on.
    pub fn meter(&self) -> Option<Arc<Meter>> {
        self.meter.clone()
    }

    /// `with_secret`, with checkout through the Stripe API at `api` (a fake, in tests).
    #[cfg(test)]
    pub fn with_checkout(secret: &str, key: &str, api: &str, public_url: &str) -> Billing {
        Billing {
            checkout: Some(Checkout::new(key, api, public_url)),
            seats: Some(Arc::new(crate::team_billing::Seats::new(Stripe::new(key, api)))),
            ..Billing::with_secret(secret)
        }
    }

    pub fn enabled(&self) -> bool {
        self.secret.is_some()
    }

    pub fn checkout_enabled(&self) -> bool {
        self.checkout.is_some()
    }

    /// Whether billing is on, in words people can read (ADR 0068).
    pub fn status(&self) -> Value {
        match self.enabled() {
            true => json!({ "enabled": true, "checkout": self.checkout_enabled(), "detail": "Billing is on: Stripe subscriptions set people's plans." }),
            false => json!({ "enabled": false, "checkout": false, "detail": OFF_DETAIL }),
        }
    }
}

impl Checkout {
    fn new(key: &str, api: &str, public_url: &str) -> Checkout {
        Checkout {
            stripe: Stripe::new(key, api),
            public_url: public_url.trim_end_matches('/').into(),
            starts: crate::users::Limiter::new(STARTS_PER_MINUTE, 60_000),
            busy: Default::default(),
        }
    }

    pub(crate) fn lock(&self, user: &str) -> Arc<tokio::sync::Mutex<()>> {
        self.busy.lock().unwrap_or_else(|e| e.into_inner()).entry(user.to_string()).or_default().clone()
    }
}

/// The address Stripe sends people back to: `PUBLIC_URL`, else `SSO_PUBLIC_URL`, else
/// https and the first name in `ALLOWED_HOSTS` (the installer sets it to the domain).
/// https with no path; http only on loopback.
pub fn public_url(var: &dyn Fn(&str) -> String) -> Result<String, String> {
    let pick = |k: &str| Some(var(k).trim().trim_end_matches('/').to_string()).filter(|v| !v.is_empty());
    let host = var("ALLOWED_HOSTS").split(',').map(str::trim).find(|h| !h.is_empty()).map(|h| format!("https://{h}"));
    let Some(url) = pick("PUBLIC_URL").or_else(|| pick("SSO_PUBLIC_URL")).or(host) else {
        return Err("STRIPE_SECRET_KEY needs the address people open SuperBot at, for Stripe to send them back to: set PUBLIC_URL (like https://superbot.example.com) or ALLOWED_HOSTS".into());
    };
    let ok = url::Url::parse(&url).ok().is_some_and(|u| {
        let loopback = matches!(u.host_str(), Some("127.0.0.1" | "localhost" | "[::1]"));
        (u.scheme() == "https" || (u.scheme() == "http" && loopback)) && u.host_str().is_some() && u.path() == "/" && u.query().is_none() && u.fragment().is_none() && u.username().is_empty()
    });
    if !ok {
        return Err(format!("PUBLIC_URL must be an https address with no path, like https://superbot.example.com (http only on loopback), not {url}"));
    }
    Ok(url)
}

/// `STRIPE_METER_EVENT`: the event name of the Stripe meter to report tokens to. Empty: off.
pub fn meter_event(raw: &str) -> Result<Option<String>, String> {
    let name = raw.trim();
    if name.is_empty() {
        return Ok(None);
    }
    if name.len() > 100 || !name.chars().all(|c| c.is_ascii_alphanumeric() || "_-.".contains(c)) {
        return Err("STRIPE_METER_EVENT must be the event name of a Stripe meter (letters, digits, _ - and ., up to 100), like superbot_tokens".into());
    }
    Ok(Some(name.into()))
}

/// How a tier with `checkoutPrices` is sold, for the startup line: "; people monthly and
/// yearly, teams yearly". Empty without them: checkout sells the first price, as before.
fn sold_as(t: &Tier) -> String {
    if t.checkout_prices.is_none() {
        return String::new();
    }
    let at = |b: Buyer| {
        let i: Vec<String> = t.checkout_intervals(b).iter().map(|i| format!("{}ly", i.as_str())).collect();
        if i.is_empty() { None } else { Some(i.join(" and ")) }
    };
    let sold: Vec<String> = [("people", at(Buyer::Person)), ("teams", at(Buyer::Team))].into_iter().filter_map(|(who, i)| i.map(|i| format!("{who} {i}"))).collect();
    format!("; {}", sold.join(", "))
}

/// What startup prints. Takes only whether each part is on, so nothing secret can reach the log.
pub fn describe(enabled: bool, checkout: bool, metering: bool, tiers: &crate::tiers::Tiers) -> String {
    if !enabled {
        return "off during testing: no Stripe calls and no charges (BILLING=on and STRIPE_WEBHOOK_SECRET turn it on)".into();
    }
    let pages = match metering {
        true => "; reporting run tokens to a Stripe meter",
        false => "",
    };
    let priced: Vec<String> = tiers.all().iter().filter(|t| !t.stripe_prices.is_empty()).map(|t| format!("{} ({}{})", t.name, t.stripe_prices.len(), sold_as(t))).collect();
    let pages = match checkout {
        true => format!("; checkout and the customer portal on{pages}"),
        false => "; checkout off (set STRIPE_SECRET_KEY to sell plans in the app)".into(),
    };
    match priced.is_empty() {
        true => format!("Stripe webhook at {PATH}, but no tier lists stripePrices, so no subscription sets a tier{pages}"),
        false => format!("Stripe webhook at {PATH}; prices for {}{pages}", priced.join(", ")),
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

pub(crate) fn reply(code: StatusCode, v: Value) -> Response {
    (code, Json(v)).into_response()
}

pub(crate) fn system(on_behalf_of: Option<&str>) -> Who {
    let mut actor = Actor::system("billing");
    actor.on_behalf_of = on_behalf_of.map(String::from);
    Who { actor, source: Default::default() }
}

/// `POST /billing/stripe/webhook`: Stripe's events. 404 while billing is off, 400 for a
/// delivery that isn't Stripe's (bad, missing, or stale signature, or not an event),
/// else 200, also for events it doesn't use, so Stripe doesn't retry them.
pub async fn webhook(State(app): State<AppState>, Extension(a): Extension<Arc<Auth>>, headers: HeaderMap, body: Bytes) -> Response {
    let b = &a.payments;
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
    let handled = match kind {
        k if k.starts_with("customer.subscription.") => subscription_event(&app, id, kind, &event),
        "checkout.session.completed" => checkout_completed(&app, id, kind, &event),
        "customer.deleted" => customer_deleted(&app, id, kind, &event),
        _ => return reply(StatusCode::OK, json!({ "received": true, "outcome": "ignored" })),
    };
    match handled {
        Ok(outcome) => reply(StatusCode::OK, json!({ "received": true, "outcome": outcome })),
        // Stripe retries a 500, which is right for a database hiccup.
        Err(e) => {
            crate::obs::log::log_warn!("billing: Stripe event {id}: {e}");
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
pub(crate) struct Sub<'a> {
    pub id: &'a str,
    pub customer: Option<&'a str>,
    pub status: &'a str,
    pub user: Option<&'a str>,
    pub prices: Vec<&'a str>,
    pub period_start: Option<i64>,
    pub period_end: Option<i64>,
    pub created: Option<i64>,
    /// When Stripe will end it, Unix seconds (ADR 0091): `cancel_at`, or the period's
    /// end while `cancel_at_period_end`.
    pub cancel_at: Option<i64>,
}

fn read_sub(o: &Value) -> Option<Sub<'_>> {
    let items = o["items"]["data"].as_array().map(Vec::as_slice).unwrap_or_default();
    let period_end = o["current_period_end"].as_i64().or_else(|| items.iter().find_map(|i| i["current_period_end"].as_i64()));
    let cancel_at = o["cancel_at"].as_i64().or_else(|| period_end.filter(|_| o["cancel_at_period_end"].as_bool() == Some(true)));
    Some(Sub {
        id: o["id"].as_str().filter(|s| !s.is_empty())?,
        customer: customer_of(o),
        status: o["status"].as_str()?,
        user: o["metadata"][USER_KEY].as_str().map(str::trim).filter(|s| !s.is_empty()),
        prices: items.iter().filter_map(|i| i["price"]["id"].as_str()).collect(),
        period_start: o["current_period_start"].as_i64().or_else(|| items.iter().find_map(|i| i["current_period_start"].as_i64())),
        period_end,
        created: o["created"].as_i64(),
        cancel_at,
    })
}

/// Applies a `customer.subscription.*` event: the tier its price pays for while it
/// pays, the default tier once it ends. Returns what happened, for the reply.
/// Audits an event botd can't place (`billing.event_ignored`), and says so for the reply.
fn ignored(app: &App, event_id: &str, kind: &str, reason: &str, user: Option<&str>, extra: Value) -> Result<&'static str, String> {
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
}

/// Audits a new link between a user and their Stripe customer.
fn record_linked(app: &App, user: &str, customer: &str, via: &str, event_id: &str) {
    let d = json!({ "customer": customer, "via": via, "eventId": event_id });
    app.db.record(&system(Some(user)).event("billing.customer_linked").target("user", user).details(d));
}

pub(crate) fn customer_of(o: &Value) -> Option<&str> {
    o["customer"].as_str().or_else(|| o["customer"]["id"].as_str()).filter(|c| !c.is_empty())
}

/// What a subscription event says the subscription pays for.
pub(crate) struct Plan {
    /// The tier while it pays; None once it ends.
    pub tier: Option<String>,
    /// False while its first payment hasn't gone through (`incomplete`): nothing changes yet.
    pub set_tier: bool,
    pub ending: bool,
    pub status: String,
    /// The price that sets the tier, else its first.
    pub price: Option<String>,
}

/// The plan an event's subscription pays for. None: it pays, but for no tier's price.
pub(crate) fn plan_of(app: &App, kind: &str, sub: &Sub) -> Option<Plan> {
    let tiers = app.tiers();
    let priced = sub.prices.iter().find_map(|p| tiers.by_stripe_price(p).map(|t| (*p, t)));
    let ending = kind == "customer.subscription.deleted" || ENDED.contains(&sub.status);
    let (tier, set_tier) = if ending {
        (None, true)
    } else if PAYING.contains(&sub.status) {
        (Some(priced?.1.name.clone()), true)
    } else {
        (None, false)
    };
    Some(Plan {
        tier,
        set_tier,
        ending,
        status: if kind == "customer.subscription.deleted" { "canceled".into() } else { sub.status.into() },
        price: priced.map(|(p, _)| p.to_string()).or_else(|| sub.prices.first().map(|p| p.to_string())),
    })
}

fn subscription_event(app: &App, event_id: &str, kind: &str, event: &Value) -> Result<&'static str, String> {
    let ignore = |reason: &str, user: Option<&str>, extra: Value| ignored(app, event_id, kind, reason, user, extra);
    let Some(sub) = read_sub(&event["data"]["object"]) else {
        return ignore("not_a_subscription", None, json!({}));
    };
    if let Some(done) = crate::team_billing::subscription_event(app, event_id, kind, event, &sub) {
        return done;
    }
    // The metadata names the user; later events for the same subscription may not carry
    // it, so the subscription we already know names them too, and so does a customer
    // linked to them (ADR 0042), for subscriptions started outside SuperBot's checkout.
    let known = app.db.subscription_by_id(sub.id);
    let user = sub
        .user
        .map(String::from)
        .or_else(|| known.as_ref().map(|s| s.user_id.clone()))
        .or_else(|| sub.customer.and_then(|c| app.db.customer_user(c)));
    let user = match user {
        Some(u) if app.db.user(&u).is_some() => u,
        other => return ignore("unknown_user", None, json!({ "subscription": sub.id, "user": other })),
    };
    let tiers = app.tiers();
    let Some(plan) = plan_of(app, kind, &sub) else {
        return ignore("unknown_price", Some(&user), json!({ "subscription": sub.id, "prices": sub.prices }));
    };
    let (tier, set_tier, ending) = (plan.tier.clone(), plan.set_tier, plan.ending);
    let created = event["created"].as_i64().unwrap_or(0);
    let row = Subscription {
        user_id: user.clone(),
        provider: "stripe".into(),
        customer_id: sub.customer.map(String::from),
        subscription_id: sub.id.into(),
        status: plan.status.clone(),
        price_id: plan.price.clone(),
        tier: tier.clone(),
        period_start: sub.period_start,
        period_end: sub.period_end,
        started: sub.created.or(known.as_ref().map(|s| s.started)).unwrap_or(created),
        event_created: created,
        updated_at: 0,
    };
    let ev = crate::billing_mail::SubEvent { event_id, row: &row, cancel_at: sub.cancel_at, ending };
    let (applied, linked, emails) = app.db.apply_subscription(event_id, kind, &row, set_tier, &|c| crate::billing_mail::subscription_emails(app, &ev, c))?;
    if let (Some(Linked::New), Some(cus)) = (&linked, sub.customer) {
        record_linked(app, &user, cus, "subscription", event_id);
    }
    let details = json!({ "eventId": event_id, "type": kind, "subscription": sub.id, "status": row.status, "price": row.price_id, "tier": tier });
    let by = system(Some(&user));
    let outcome = match applied {
        Applied::Duplicate => {
            // Stripe redelivers what it got no answer for, so a resize the first delivery
            // didn't get to ask for is asked for now (ADR 0085); one asked for already isn't again.
            crate::machines::resize::follow(app, &by, &user, "stripe", Some(event_id), false);
            return Ok("duplicate");
        }
        Applied::Stale => "stale",
        Applied::Superseded => "superseded",
        Applied::OtherUser => return ignore("subscription_of_another_user", Some(&user), json!({ "subscription": sub.id })),
        Applied::CustomerOfAnotherUser => return ignore("customer_of_another_user", Some(&user), json!({ "subscription": sub.id, "customer": sub.customer })),
        Applied::Unchanged => "unchanged",
        Applied::Changed { from, to } => {
            // While their team pays (ADR 0093), its plan is theirs whatever their own says.
            let team = app.db.team_plan_of(&user).and_then(|s| s.tier);
            let effective = |t: &Option<String>| tiers.of(team.as_deref().or(t.as_deref())).name.clone();
            let mut d = json!({ "from": from, "to": to, "effectiveFrom": effective(&from), "effectiveTo": effective(&to), "source": "stripe" });
            if let (Some(d), Value::Object(x)) = (d.as_object_mut(), details.clone()) {
                d.extend(x);
            }
            app.db.record(&by.event("user.tier_changed").target("user", &user).details(d));
            crate::machines::resize::follow(app, &by, &user, "stripe", Some(event_id), true);
            "tier_changed"
        }
    };
    let mut d = details;
    d["outcome"] = json!(outcome);
    app.db.record(&by.event("billing.subscription_synced").target("user", &user).details(d));
    // Now that the resize is asked for, so the plan email can say what the computer is doing.
    if emails > 0 {
        app.db.release_billing_emails(event_id);
        crate::billing_mail::wake(app);
    }
    Ok(outcome)
}

/// `checkout.session.completed`: links the session's customer to the user it names
/// (`metadata.superbot_user_id`, else `client_reference_id`, both set by `checkout`).
/// The tier is set by the subscription's own events, which come separately.
fn checkout_completed(app: &App, event_id: &str, kind: &str, event: &Value) -> Result<&'static str, String> {
    let ignore = |reason: &str, user: Option<&str>, extra: Value| ignored(app, event_id, kind, reason, user, extra);
    let o = &event["data"]["object"];
    let field = |v: &Value| v.as_str().map(str::trim).filter(|s| !s.is_empty()).map(String::from);
    let session = o["id"].as_str().unwrap_or_default();
    if let Some(done) = crate::team_billing::checkout_completed(app, event_id, kind, o) {
        return done;
    }
    let (meta, reference) = (field(&o["metadata"][USER_KEY]), field(&o["client_reference_id"]));
    if let (Some(m), Some(r)) = (&meta, &reference)
        && m != r
    {
        return ignore("user_mismatch", None, json!({ "session": session, "user": m, "clientReferenceId": r }));
    }
    let user = match meta.or(reference) {
        Some(u) if app.db.user(&u).is_some() => u,
        other => return ignore("unknown_user", None, json!({ "session": session, "user": other })),
    };
    app.db.close_checkout(&user, session);
    let Some(cus) = customer_of(o) else {
        return ignore("no_customer", Some(&user), json!({ "session": session }));
    };
    let outcome = match app.db.link_customer(event_id, kind, &user, "stripe", cus, "checkout")? {
        None => "duplicate",
        Some(Linked::New) => {
            record_linked(app, &user, cus, "checkout", event_id);
            "customer_linked"
        }
        Some(Linked::Already) => "unchanged",
        Some(Linked::UserHasAnother(other)) => return ignore("user_has_another_customer", Some(&user), json!({ "session": session, "customer": cus, "linked": other })),
        Some(Linked::OfAnotherUser(_)) => return ignore("customer_of_another_user", Some(&user), json!({ "session": session, "customer": cus })),
        Some(Linked::Deleted) => return ignore("customer_deleted", Some(&user), json!({ "session": session, "customer": cus })),
    };
    Ok(outcome)
}

/// `customer.deleted`: the user or team (ADR 0093) it was linked to has no customer any
/// more, so their next checkout makes a new one. Stripe cancels the customer's
/// subscriptions itself, and sends their own events.
fn customer_deleted(app: &App, event_id: &str, kind: &str, event: &Value) -> Result<&'static str, String> {
    let Some(cus) = event["data"]["object"]["id"].as_str().filter(|c| !c.is_empty()) else {
        return ignored(app, event_id, kind, "not_a_customer", None, json!({}));
    };
    let Some(gone) = app.db.unlink_customer(event_id, kind, cus)? else { return Ok("duplicate") };
    let d = json!({ "customer": cus, "eventId": event_id });
    if let Some(user) = &gone.user {
        app.db.record(&system(Some(user)).event("billing.customer_unlinked").target("user", user).details(d.clone()));
    }
    if let Some(team) = &gone.team {
        app.db.record(&system(None).event("billing.customer_unlinked").target("team", team).details(d));
    }
    Ok(if gone == crate::db::Unlinked::default() { "unchanged" } else { "customer_unlinked" })
}

// Checkout and the customer portal (ADR 0042)

pub(crate) fn off() -> Response {
    reply(StatusCode::NOT_FOUND, json!({ "error": OFF }))
}

/// The person asking, never a Bot. Break-glass and loopback dev act as the owner account.
#[allow(clippy::result_large_err)]
pub(crate) fn person(app: &App, c: &Caller) -> Result<crate::db::User, Response> {
    crate::need_user(c.principal).map_err(IntoResponse::into_response)?;
    let id = c.user.as_ref().map_or(crate::users::OPERATOR, |u| u.id.as_str());
    app.db.user(id).ok_or_else(|| reply(StatusCode::NOT_FOUND, json!({ "error": "user not found" })))
}

/// Whether the user's paying subscription sets their tier now.
fn paying(app: &App, user: &str) -> Option<Subscription> {
    app.db.subscription(user).filter(|s| s.tier.is_some())
}

/// `GET /api/billing`: your plan and use, the plans you can buy (no price ids), your
/// subscription, and whether you have a billing account to manage. 404 while checkout
/// is off, which is how the client knows to hide its plan screen.
pub async fn info(State(app): State<AppState>, Extension(a): Extension<Arc<Auth>>, Extension(c): Extension<Caller>) -> Response {
    if a.payments.checkout.is_none() {
        return off();
    }
    let u = match person(&app, &c) {
        Ok(u) => u,
        Err(r) => return r,
    };
    crate::storage::warm(&app, std::slice::from_ref(&u.id)).await;
    let current = app.tier_of(&u.id).name.clone();
    let plans: Vec<Value> = app
        .tiers()
        .all()
        .iter()
        .filter(|t| !t.checkout_intervals(Buyer::Person).is_empty())
        .map(|t| {
            let mut v = t.sale_view(Buyer::Person);
            v["current"] = json!(t.name == current);
            v
        })
        .collect();
    let sub = paying(&app, &u.id);
    let team = app.db.team_plan_of(&u.id).map(|s| {
        let name = app.db.team(&s.team_id).map(|t| t.name);
        json!({ "id": s.team_id, "name": name, "tier": s.tier, "periodEnd": s.period_end })
    });
    reply(
        StatusCode::OK,
        json!({
            "plan": crate::tier_usage(&app, &u.id),
            "plans": plans,
            "subscription": sub.map(|s| json!({ "status": s.status, "tier": s.tier, "periodEnd": s.period_end })),
            "teamPlan": team,
            "portal": app.db.customer_of(&u.id).is_some(),
            "canChange": crate::rbac::allows(c.principal, crate::rbac::Perm::Write),
            "emails": crate::billing_mail::view(&app, &u.id),
        }),
    )
}

/// Counts a start for `user`; false once they've started too many this minute.
pub(crate) fn may_start(co: &Checkout, user: &str) -> bool {
    co.starts.hit(user, crate::db::now()).is_none()
}

/// What became of the person's last checkout page.
pub(crate) enum Last {
    /// None open, or expired now: a new one may open.
    Closed,
    /// Paid: its subscription is on the way.
    Paid,
    Unknown(stripe::Error),
}

/// Who a checkout page is for: a person, or a team (ADR 0093).
#[derive(Clone, Copy)]
pub(crate) enum Payer<'a> {
    User(&'a str),
    Team(&'a str),
}

impl Payer<'_> {
    pub(crate) fn open_checkout(self, app: &App) -> Option<String> {
        match self {
            Payer::User(u) => app.db.open_checkout(u),
            Payer::Team(t) => app.db.team_open_checkout(t),
        }
    }

    fn close_checkout(self, app: &App, session: &str) {
        match self {
            Payer::User(u) => app.db.close_checkout(u, session),
            Payer::Team(t) => app.db.close_team_checkout(t, session),
        }
    }

    /// Their part of an idempotency key: a team's can't be mistaken for a person's.
    pub(crate) fn key(self) -> String {
        match self {
            Payer::User(u) => u.to_string(),
            Payer::Team(t) => format!("team:{t}"),
        }
    }
}

/// Closes someone's open checkout before they're erased, holding checkout's own lock for
/// them until the guard drops. None: checkout is off.
pub(crate) async fn close_for_erasure(app: &App, a: &Auth, user_id: &str) -> Option<(tokio::sync::OwnedMutexGuard<()>, Last)> {
    let Some(co) = &a.payments.checkout else { return None };
    let guard = co.lock(user_id).lock_owned().await;
    Some((guard, close_last(app, &co.stripe, Payer::User(user_id)).await))
}

/// Expires the payer's open checkout page, if any, so it can't be paid as well as the
/// next. Stripe refuses to expire a page that isn't open; then its status says why.
pub(crate) async fn close_last(app: &App, stripe: &Stripe, payer: Payer<'_>) -> Last {
    let Some(id) = payer.open_checkout(app) else { return Last::Closed };
    if id.is_empty() || !id.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        payer.close_checkout(app, &id);
        return Last::Closed;
    }
    let key = stripe::idempotency_key("expire", &payer.key(), &[("session".into(), id.clone())], crate::db::now());
    let status = match stripe.post(&format!("/v1/checkout/sessions/{id}/expire"), &[], &key).await {
        Ok(v) => v["status"].as_str().map(String::from),
        Err(stripe::Error::Refused { status, .. }) if status < 500 => match stripe.get(&format!("/v1/checkout/sessions/{id}")).await {
            Ok(v) => v["status"].as_str().map(String::from),
            Err(stripe::Error::Refused { status: 404, .. }) => Some("expired".into()),
            Err(e) => return Last::Unknown(e),
        },
        Err(e) => return Last::Unknown(e),
    };
    match status.as_deref() {
        Some("expired") => {
            payer.close_checkout(app, &id);
            Last::Closed
        }
        Some("complete") => Last::Paid,
        _ => Last::Unknown(stripe::Error::Unreachable),
    }
}

/// Stripe's answer: the session's id and link, or a 502 that says only that Stripe
/// didn't make one. The server log gets the status and Stripe's error type and code.
#[allow(clippy::result_large_err)]
pub(crate) fn session(what: &str, user: &str, res: Result<Value, stripe::Error>) -> Result<(String, String), (Response, String)> {
    let got = res.and_then(|v| match (v["id"].as_str(), v["url"].as_str()) {
        (Some(id), Some(url)) if url.starts_with("https://") => Ok((id.to_string(), url.to_string())),
        _ => Err(stripe::Error::Unreachable),
    });
    got.map_err(|e| {
        crate::obs::log::log_warn!("billing: Stripe {what} session for {user}: {e}");
        let msg = format!("Stripe couldn't open the {what} just now. Try again in a minute; if it keeps happening, an admin can see why in the server log.");
        (reply(StatusCode::BAD_GATEWAY, json!({ "error": msg })), e.to_string())
    })
}

/// The interval a checkout asked for (ADR 0346). Left out (or null): the first the
/// tier is sold at, monthly before yearly, so older apps that never send one still
/// buy what they did. Err: neither month nor year.
pub(crate) fn asked_interval(raw: &Value) -> Result<Option<Interval>, String> {
    match raw {
        Value::Null => Ok(None),
        Value::String(s) => Interval::parse(s).map(Some).ok_or_else(|| "Say month or year: {\"tier\": \"<name>\", \"interval\": \"year\"}.".to_string()),
        _ => Err("Say month or year: {\"tier\": \"<name>\", \"interval\": \"year\"}.".into()),
    }
}

/// The price `buyer` checks `tier` out at, and its interval (ADR 0346). Err: a plain
/// reason it can't be bought that way.
pub(crate) fn sale_price(tier: &Tier, buyer: Buyer, asked: Option<Interval>) -> Result<(String, Interval), String> {
    let sold = tier.checkout_intervals(buyer);
    if sold.is_empty() {
        return Err(match buyer == Buyer::Person && tier.team_only() {
            true => format!("The {} plan is for teams only. A team's owners and admins buy it on the Team screen.", tier.label),
            false => format!("The {} plan can't be bought here.", tier.label),
        });
    }
    let interval = asked.unwrap_or(sold[0]);
    match tier.checkout_price(buyer, interval) {
        Some(p) => Ok((p.to_string(), interval)),
        None => Err(format!("The {} plan isn't sold {}ly here.", tier.label, interval.as_str())),
    }
}

/// `POST /api/billing/checkout {tier, interval?}`: a Stripe Checkout Session for the
/// tier's price at that interval (`month` or `year`; ADR 0346), for the person asking;
/// returns `{url}`, Stripe's page to pay on. Their subscription carries their user id,
/// and their customer if they have one. Refused for tiers without a price for people,
/// at an interval it isn't sold at, and while a subscription already pays for a plan
/// (that one is changed in the portal, or they'd pay twice).
pub async fn checkout(State(app): State<AppState>, Extension(a): Extension<Arc<Auth>>, Extension(c): Extension<Caller>, Extension(by): Extension<Who>, body: Bytes) -> Response {
    let Some(co) = &a.payments.checkout else { return off() };
    let u = match person(&app, &c) {
        Ok(u) => u,
        Err(r) => return r,
    };
    let bad = |code: StatusCode, msg: String| reply(code, json!({ "error": msg }));
    let v: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
    let Some(name) = v["tier"].as_str().map(str::trim).filter(|t| !t.is_empty()) else {
        return bad(StatusCode::BAD_REQUEST, "Say which plan: {\"tier\": \"<name>\"}.".into());
    };
    let asked = match asked_interval(&v["interval"]) {
        Ok(i) => i,
        Err(e) => return bad(StatusCode::BAD_REQUEST, e),
    };
    let tiers = app.tiers();
    let Some(tier) = tiers.get(name) else {
        return bad(StatusCode::BAD_REQUEST, format!("There's no plan called \"{name}\"."));
    };
    let (price, interval) = match sale_price(tier, Buyer::Person, asked) {
        Ok(x) => x,
        Err(e) => return bad(StatusCode::BAD_REQUEST, e),
    };
    let interval = interval.as_str();
    let event = |outcome: Outcome, d: Value| by.event("billing.checkout_created").target("user", &u.id).outcome(outcome).details(d);
    if let Some(s) = paying(&app, &u.id) {
        app.db.record(&event(Outcome::Denied, json!({ "tier": tier.name, "reason": "already_subscribed", "subscription": s.subscription_id })));
        return reply(StatusCode::CONFLICT, json!({ "error": "You already pay for a plan. Change it under Manage billing.", "portal": true }));
    }
    if let Some(s) = app.db.team_plan_of(&u.id) {
        app.db.record(&event(Outcome::Denied, json!({ "tier": tier.name, "reason": "team_pays", "team": s.team_id })));
        return reply(StatusCode::CONFLICT, json!({ "error": "Your team pays for your plan. Its owners and admins change it on the Team screen.", "teamPays": true }));
    }
    if !may_start(co, &u.id) {
        return bad(StatusCode::TOO_MANY_REQUESTS, "Too many checkouts at once. Try again in a minute.".into());
    }
    let lock = co.lock(&u.id);
    let _one_at_a_time = lock.lock().await;
    let last = app.db.open_checkout(&u.id);
    match close_last(&app, &co.stripe, Payer::User(&u.id)).await {
        Last::Closed => {}
        Last::Paid => {
            app.db.record(&event(Outcome::Denied, json!({ "tier": tier.name, "reason": "checkout_completed", "session": last })));
            return reply(StatusCode::CONFLICT, json!({ "error": "Your last checkout went through. Your plan changes as soon as Stripe confirms the payment." }));
        }
        Last::Unknown(e) => {
            crate::obs::log::log_warn!("billing: closing {}'s last Stripe checkout: {e}", u.id);
            app.db.record(&event(Outcome::Failure, json!({ "tier": tier.name, "reason": format!("last checkout: {e}"), "session": last })));
            return bad(StatusCode::BAD_GATEWAY, "Stripe couldn't open the checkout just now. Try again in a minute; if it keeps happening, an admin can see why in the server log.".into());
        }
    }
    let customer = app.db.customer_of(&u.id);
    let back = format!("{}{RETURN_PATH}", co.public_url);
    let mut form: Vec<(String, String)> = [
        ("mode", "subscription"),
        ("line_items[0][price]", price.as_str()),
        ("line_items[0][quantity]", "1"),
        ("client_reference_id", u.id.as_str()),
        ("metadata[superbot_user_id]", u.id.as_str()),
        ("metadata[superbot_tier]", tier.name.as_str()),
        ("subscription_data[metadata][superbot_user_id]", u.id.as_str()),
    ]
    .iter()
    .map(|(k, v)| (k.to_string(), v.to_string()))
    .collect();
    form.push(("success_url".into(), format!("{back}?checkout=success")));
    form.push(("cancel_url".into(), format!("{back}?checkout=cancelled")));
    match (&customer, &u.email) {
        (Some(cus), _) => form.push(("customer".into(), cus.clone())),
        (None, Some(email)) => form.push(("customer_email".into(), email.clone())),
        (None, None) => {}
    }
    let now = crate::db::now();
    let expires_at = (now / 60_000 + CHECKOUT_MINUTES) * 60;
    form.push(("expires_at".into(), expires_at.to_string()));
    // Each checkout is a new page (the last one was just closed), so only this request's
    // own retry may share its key: a key reused later would bring back a closed page.
    let mut keyed = form.clone();
    keyed.push(("request".into(), crate::random_hex(16)));
    let key = stripe::idempotency_key("checkout", &u.id, &keyed, now);
    match session("checkout", &u.id, co.stripe.post("/v1/checkout/sessions", &form, &key).await) {
        Ok((id, url)) => {
            app.db.set_open_checkout(&u.id, &id, expires_at);
            app.db.record(&event(Outcome::Success, json!({ "tier": tier.name, "price": price, "interval": interval, "session": id, "customer": customer })));
            reply(StatusCode::OK, json!({ "url": url }))
        }
        Err((r, reason)) => {
            app.db.record(&event(Outcome::Failure, json!({ "tier": tier.name, "price": price, "interval": interval, "reason": reason })));
            r
        }
    }
}

/// `POST /api/billing/portal`: a Stripe Billing Portal session for the person's own
/// customer, where they change or cancel their plan and see invoices; returns `{url}`.
/// 409 until a checkout has linked them to a customer.
pub async fn portal(State(app): State<AppState>, Extension(a): Extension<Arc<Auth>>, Extension(c): Extension<Caller>, Extension(by): Extension<Who>) -> Response {
    let Some(co) = &a.payments.checkout else { return off() };
    let u = match person(&app, &c) {
        Ok(u) => u,
        Err(r) => return r,
    };
    let Some(cus) = app.db.customer_of(&u.id) else {
        return reply(StatusCode::CONFLICT, json!({ "error": "There's no billing account to manage yet. Pick a plan first." }));
    };
    if !may_start(co, &u.id) {
        return reply(StatusCode::TOO_MANY_REQUESTS, json!({ "error": "Too many requests at once. Try again in a minute." }));
    }
    let form = vec![("customer".to_string(), cus.clone()), ("return_url".to_string(), format!("{}{RETURN_PATH}", co.public_url))];
    let key = stripe::idempotency_key("portal", &u.id, &form, crate::db::now());
    let event = |outcome: Outcome, d: Value| by.event("billing.portal_created").target("user", &u.id).outcome(outcome).details(d);
    match session("billing portal", &u.id, co.stripe.post("/v1/billing_portal/sessions", &form, &key).await) {
        // The link signs whoever has it in to the customer's billing: never logged.
        Ok((id, url)) => {
            app.db.record(&event(Outcome::Success, json!({ "customer": cus, "session": id })));
            reply(StatusCode::OK, json!({ "url": url }))
        }
        Err((r, reason)) => {
            app.db.record(&event(Outcome::Failure, json!({ "customer": cus, "reason": reason })));
            r
        }
    }
}

/// Sends the token rows waiting for Stripe's meter, oldest first, one meter event each
/// (ADR 0050). The event's `identifier` and idempotency key are the row's own, so
/// Stripe counts a resent row once. A row Stripe refuses, or that can't reach it after
/// `METER_TRIES` passes, is marked failed and audited (`billing.meter_failed`); nothing
/// is dropped silently. Returns how many went through.
pub async fn send_meter_events(app: &App, m: &Meter) -> usize {
    let mut sent = 0;
    for row in app.db.pending_meter(METER_BATCH) {
        let failed = |why: String| {
            app.db.meter_result(row.id, Some("failed"));
            let details = json!({ "runId": row.run_id, "usage": row.tokens, "attempts": row.attempts + 1, "error": why });
            app.db.record(&system(Some(&row.user_id)).event("billing.meter_failed").target("user", &row.user_id).outcome(Outcome::Failure).details(details));
        };
        let Some(customer) = row.customer.clone().or_else(|| app.db.customer_of(&row.user_id)) else {
            failed("no Stripe customer".into());
            continue;
        };
        let id = format!("superbot-{}-{}", row.run_id, row.id);
        let form: Vec<(String, String)> = [
            ("event_name", m.event.clone()),
            ("payload[stripe_customer_id]", customer),
            ("payload[value]", row.tokens.to_string()),
            ("identifier", id.clone()),
            ("timestamp", (row.at / 1000).to_string()),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v))
        .collect();
        match m.stripe.post("/v1/billing/meter_events", &form, &format!("{id}-meter")).await {
            Ok(_) => {
                app.db.meter_result(row.id, Some("sent"));
                sent += 1;
            }
            Err(e @ stripe::Error::Refused { status, .. }) if status != 429 && status < 500 => failed(e.to_string()),
            Err(e) if row.attempts + 1 >= METER_TRIES => failed(e.to_string()),
            Err(e) => {
                app.db.meter_result(row.id, None);
                // Stripe is down or busy: try the rest next pass.
                crate::obs::log::log_warn!("botd: Stripe meter: {e}; trying again in a minute");
                break;
            }
        }
    }
    sent
}

/// Reports tokens to Stripe every minute, while `STRIPE_METER_EVENT` is set.
pub fn start_metering(app: Arc<App>) {
    let Some(m) = app.meter.get().cloned() else { return };
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(METER_EVERY).await;
            send_meter_events(&app, &m).await;
        }
    });
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

    /// A store that fails the test if anything reads a secret from it.
    struct NeverRead;
    impl SecretStore for NeverRead {
        fn kind(&self) -> &'static str {
            "never-read"
        }
        fn get(&self, _: &str) -> Result<Option<crate::secrets::Secret>, crate::secrets::Error> {
            panic!("billing is off, yet a secret was read");
        }
        fn names(&self) -> Result<Vec<String>, crate::secrets::Error> {
            panic!("billing is off, yet the store was listed");
        }
    }

    #[test]
    fn billing_is_off_unless_turned_on_and_never_in_testing_mode() {
        use crate::secrets::env::EnvStore;
        let vars = |billing: &'static str| {
            move |k: &str| match k {
                "BILLING" => billing.to_string(),
                "STRIPE_WEBHOOK_SECRET" => SECRET.to_string(),
                _ => String::new(),
            }
        };
        let stripe = EnvStore::fixed(&[("STRIPE_WEBHOOK_SECRET", SECRET)]);
        // Off by default, even with Stripe settings present: no Stripe client, and a warning.
        let (b, warn) = Billing::configured(&NeverRead, &|_: &str| String::new(), false).unwrap();
        assert!(!b.enabled() && warn.is_none());
        let (b, warn) = Billing::configured(&NeverRead, &vars(""), false).unwrap();
        assert!(!b.enabled() && !b.checkout_enabled() && b.meter().is_none());
        let warn = warn.unwrap();
        assert!(warn.contains("STRIPE_WEBHOOK_SECRET") && warn.contains("nothing calls Stripe") && !warn.contains(SECRET), "{warn}");
        assert_eq!(b.status()["enabled"], json!(false));
        assert_eq!(b.status()["detail"], json!(OFF_DETAIL));
        // A secret given as a _FILE counts as set, and still isn't read.
        let file = |k: &str| if k == "STRIPE_SECRET_KEY_FILE" { "/run/secrets/stripe".to_string() } else { String::new() };
        assert!(Billing::configured(&NeverRead, &file, false).unwrap().1.unwrap().contains("STRIPE_SECRET_KEY"));
        // Testing mode keeps it off, and refuses BILLING=on outright.
        let (b, _) = Billing::configured(&NeverRead, &vars("off"), true).unwrap();
        assert!(!b.enabled());
        assert!(Billing::configured(&stripe, &vars("on"), true).err().unwrap().contains("TESTING_MODE"));
        // Only BILLING=on, outside testing, reads the Stripe settings.
        let (b, warn) = Billing::configured(&stripe, &vars("on"), false).unwrap();
        assert!(b.enabled() && warn.is_none());
        assert_eq!(b.status()["enabled"], json!(true));
        assert!(Billing::configured(&stripe, &vars("maybe"), false).err().unwrap().contains("BILLING"));
        assert!(describe(false, false, false, &crate::tiers::Tiers::default()).starts_with("off during testing"));
    }

    #[test]
    fn the_secret_is_checked_at_startup() {
        use crate::secrets::env::EnvStore;
        let none = |_: &str| String::new();
        assert!(!Billing::from_env(&EnvStore::fixed(&[]), &none).unwrap().enabled());
        assert!(Billing::from_env(&EnvStore::fixed(&[("STRIPE_WEBHOOK_SECRET", SECRET)]), &none).unwrap().enabled());
        let e = Billing::from_env(&EnvStore::fixed(&[("STRIPE_WEBHOOK_SECRET", "sk_live_nope")]), &none).err().unwrap();
        assert!(e.contains("whsec_"), "{e}");
    }

    #[test]
    fn checkout_needs_the_key_the_webhook_and_a_public_address() {
        use crate::secrets::env::EnvStore;
        const KEY: &str = "sk_test_not_a_real_key_000";
        let public = |k: &str| if k == "PUBLIC_URL" { "https://bots.example.com/".to_string() } else { String::new() };
        let load = |vars: &[(&str, &str)], var: &dyn Fn(&str) -> String| Billing::from_env(&EnvStore::fixed(vars), var);
        // The webhook alone, as in ADR 0040: no checkout.
        let b = load(&[("STRIPE_WEBHOOK_SECRET", SECRET)], &public).unwrap();
        assert!(b.enabled() && !b.checkout_enabled());
        let b = load(&[("STRIPE_WEBHOOK_SECRET", SECRET), ("STRIPE_SECRET_KEY", KEY)], &public).unwrap();
        assert!(b.checkout_enabled());
        assert_eq!(b.checkout.unwrap().public_url, "https://bots.example.com");
        // A key without the webhook would sell plans that never apply.
        let e = load(&[("STRIPE_SECRET_KEY", KEY)], &public).err().unwrap();
        assert!(e.contains("STRIPE_WEBHOOK_SECRET"), "{e}");
        // The publishable key, or anything else, is refused.
        for k in ["pk_test_1234567890abcdef", "whsec_1234567890abcdef", "sk_test_"] {
            let e = load(&[("STRIPE_WEBHOOK_SECRET", SECRET), ("STRIPE_SECRET_KEY", k)], &public).err().unwrap();
            assert!(e.contains("sk_") && !e.contains(k), "{e}");
        }
        assert!(load(&[("STRIPE_WEBHOOK_SECRET", SECRET), ("STRIPE_SECRET_KEY", "rk_live_restricted_key_00")], &public).unwrap().checkout_enabled());
        // No public address to come back to.
        let e = load(&[("STRIPE_WEBHOOK_SECRET", SECRET), ("STRIPE_SECRET_KEY", KEY)], &|_| String::new()).err().unwrap();
        assert!(e.contains("PUBLIC_URL"), "{e}");
    }

    #[test]
    fn the_public_address_comes_from_the_configured_domain() {
        let vars = |pairs: &'static [(&'static str, &'static str)]| move |k: &str| pairs.iter().find(|(n, _)| *n == k).map_or(String::new(), |(_, v)| v.to_string());
        assert_eq!(public_url(&vars(&[("ALLOWED_HOSTS", " bots.example.com, other.example.com")])).unwrap(), "https://bots.example.com");
        assert_eq!(public_url(&vars(&[("ALLOWED_HOSTS", "bots.example.com"), ("SSO_PUBLIC_URL", "https://sso.example.com/")])).unwrap(), "https://sso.example.com");
        assert_eq!(public_url(&vars(&[("SSO_PUBLIC_URL", "https://sso.example.com"), ("PUBLIC_URL", "https://pay.example.com")])).unwrap(), "https://pay.example.com");
        assert_eq!(public_url(&vars(&[("PUBLIC_URL", "http://127.0.0.1:3000")])).unwrap(), "http://127.0.0.1:3000");
        for bad in ["http://bots.example.com", "https://bots.example.com/app", "https://bots.example.com/?x=1", "https://user@bots.example.com", "bots.example.com", "ftp://bots.example.com"] {
            let pairs: &'static [(&'static str, &'static str)] = Box::leak(Box::new([("PUBLIC_URL", bad)]));
            assert!(public_url(&vars(pairs)).is_err(), "{bad}");
        }
        assert!(public_url(&vars(&[])).is_err());
    }
}
