//! Team billing (ADR 0093): a team pays for one plan for all its members. A team owner
//! or admin buys it through Stripe Checkout (`POST /api/team/billing/checkout`) and
//! manages it in Stripe's portal (`POST /api/team/billing/portal`); the subscription
//! is the team's, with its own Stripe customer, and names the team in its metadata
//! (`superbot_team_id`). While it pays, its tier is every member's (`App::tier_of`),
//! over a plan of their own, and their computers follow it. Its quantity is the
//! team's seats: botd keeps it at the team's member count as people join and leave,
//! with Stripe's prorations, and retries until Stripe has it.
//!
//! On only with billing and checkout (`BILLING=on`, the webhook and
//! `STRIPE_SECRET_KEY`, ADR 0042, 0068); otherwise nothing here calls Stripe, and teams
//! work as before.

use crate::audit::{Outcome, Who};
use crate::billing::{self, Last, Payer, Sub, reply};
use crate::db::{Applied, Linked, Team, TeamSubscription};
use crate::runner::App;
use crate::stripe::{self, Stripe};
use crate::users::Caller;
use crate::{AppState, Auth};
use axum::Json;
use axum::extract::rejection::JsonRejection;
use axum::extract::{Extension, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::{Value, json};
use std::sync::Arc;
use std::time::Duration;

/// The subscription and checkout metadata key naming the team that pays.
pub const TEAM_KEY: &str = "superbot_team_id";
/// And the owner or admin who opened the checkout.
pub const PAID_BY_KEY: &str = "superbot_paid_by";
/// Where the apps show the team; Stripe sends its owners and admins back here.
pub const RETURN_PATH: &str = "/app/team";
/// How often seats are checked, besides being woken when a team changes.
const EVERY: Duration = Duration::from_secs(60);
/// A seat update that failed waits 1, 4, 16, then 64 minutes, capped at an hour, and is
/// never given up on: a team must be billed for who's on it.
const BACKOFF_CAP_MS: i64 = 3_600_000;

/// Keeps each paying team's seats at its member count.
pub struct Seats {
    stripe: Stripe,
    wake: tokio::sync::Notify,
    /// One pass at a time, so no update is sent by two.
    busy: tokio::sync::Mutex<()>,
    /// Per team: a checkout opening, or the team going, one at a time.
    teams: std::sync::Mutex<std::collections::HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
}

impl Seats {
    pub fn new(stripe: Stripe) -> Seats {
        Seats { stripe, wake: tokio::sync::Notify::new(), busy: tokio::sync::Mutex::new(()), teams: Default::default() }
    }

    /// The Stripe client, for a server admin moving a team's subscription (ADR 0347).
    pub(crate) fn stripe(&self) -> &Stripe {
        &self.stripe
    }

    async fn hold(&self, team_id: &str) -> tokio::sync::OwnedMutexGuard<()> {
        let lock = self.teams.lock().unwrap_or_else(|e| e.into_inner()).entry(team_id.to_string()).or_default().clone();
        lock.lock_owned().await
    }
}

/// Whether teams can buy plans on this server.
pub fn on(app: &App) -> bool {
    app.team_seats.get().is_some()
}

/// Asks the seat sync to look now: a team's members changed, or its subscription did.
pub fn wake(app: &App) {
    if let Some(s) = app.team_seats.get() {
        s.wake.notify_one();
    }
}

fn team_event(by: &Who, action: &str, team: &str, details: Value) -> crate::audit::Event {
    let mut d = json!({ "team": team });
    if let (Some(d), Value::Object(x)) = (d.as_object_mut(), details) {
        d.extend(x);
    }
    by.event(action).target("team", team).details(d)
}

fn field(v: &Value) -> Option<String> {
    v.as_str().map(str::trim).filter(|s| !s.is_empty()).map(String::from)
}

fn ignored(app: &App, event_id: &str, kind: &str, reason: &str, team: Option<&str>, extra: Value) -> Result<&'static str, String> {
    let mut d = json!({ "reason": reason, "eventId": event_id, "type": kind });
    if let (Some(d), Value::Object(x)) = (d.as_object_mut(), extra) {
        d.extend(x);
    }
    let e = billing::system(None).event("billing.event_ignored").outcome(Outcome::Failure).details(d);
    app.db.record(&match team {
        Some(t) => e.target("team", t),
        None => e,
    });
    Ok("ignored")
}

/// Each member and the tier they're on now, to tell whose a change moved.
pub(crate) fn tiers_now(app: &App, team_id: &str) -> Vec<(String, String)> {
    app.db.team_members(team_id).into_iter().map(|m| (m.user_id.clone(), app.tier_of(&m.user_id).name.clone())).collect()
}

/// After a team's plan or members changed: each member whose tier moved from `before`
/// is audited (`user.tier_changed`, source `team`) and their computer follows it, as
/// it does an admin's or Stripe's change for them (ADR 0085). Returns how many moved.
pub(crate) fn follow(app: &App, team_id: &str, before: &[(String, String)], why: &Value, event_id: Option<&str>, fresh: bool) -> usize {
    let mut moved = 0;
    for (user, was) in before {
        let now = app.tier_of(user).name.clone();
        let by = billing::system(Some(user));
        if now != *was {
            let mut d = json!({ "effectiveFrom": was, "effectiveTo": now, "source": "team", "team": team_id, "eventId": event_id });
            if let (Some(d), Value::Object(x)) = (d.as_object_mut(), why.clone()) {
                d.extend(x);
            }
            app.db.record(&by.event("user.tier_changed").target("user", user).details(d));
            moved += 1;
        }
        if now != *was || !fresh {
            crate::machines::resize::follow(app, &by, user, "team", event_id, fresh);
        }
    }
    moved
}

/// After `user_id` joined or left `team_id`: if that moved their tier from `before`
/// (the team pays for another plan than theirs), it's audited and their computer
/// follows. The team's seats are brought in line either way.
pub fn member_changed(app: &App, team_id: &str, user_id: &str, before: &str, how: &str) {
    follow(app, team_id, &[(user_id.to_string(), before.to_string())], &json!({ "via": how }), None, true);
    wake(app);
}

/// Refuses to delete a team while a subscription pays for it: it'd go on charging for a
/// team that's gone. Audits the refusal.
pub async fn may_delete(app: &App, by: &Who, team_id: &str, how: &str) -> crate::Res<Option<tokio::sync::OwnedMutexGuard<()>>> {
    let refuse = |reason: &str, d: Value, msg: &str| {
        let mut d = d;
        d["reason"] = json!(reason);
        d["via"] = json!(how);
        app.db.record(&team_event(by, "team.delete_refused", team_id, d).outcome(Outcome::Denied));
        Err(crate::ApiError(StatusCode::CONFLICT, msg.into()))
    };
    const PAYS: &str = "The team pays for a plan. Cancel it under Manage billing on the Team screen first; the team can go once it has ended.";
    let held = match app.team_seats.get() {
        Some(seats) => Some(seats.hold(team_id).await),
        None => None,
    };
    if let Some(s) = app.db.team_paying(team_id) {
        return refuse("team_pays", json!({ "subscription": s.subscription_id }), PAYS);
    }
    let Some(seats) = app.team_seats.get() else {
        return match app.db.team_open_checkout(team_id) {
            Some(session) => refuse("checkout_open", json!({ "session": session }), "The team has a checkout open. Try again once it has expired."),
            None => Ok(held),
        };
    };
    let session = app.db.team_open_checkout(team_id);
    match billing::close_last(app, &seats.stripe, Payer::Team(team_id)).await {
        Last::Closed => Ok(held),
        Last::Paid => refuse("checkout_completed", json!({ "session": session }), PAYS),
        Last::Unknown(e) => {
            crate::obs::log::log_warn!("billing: closing team {team_id}'s last Stripe checkout before it goes: {e}");
            refuse("checkout_unknown", json!({ "session": session, "error": e.to_string() }), "Stripe couldn't say whether the team's checkout was paid. Try again in a minute.")
        }
    }
}

// Stripe's events (`billing::webhook`)

/// A `customer.subscription.*` event for a team's subscription: its metadata names a
/// team, botd knows it as one, or (naming no person) its customer is a team's. None:
/// it isn't one, and `billing` places it with a person.
pub(crate) fn subscription_event(app: &App, event_id: &str, kind: &str, event: &Value, sub: &Sub) -> Option<Result<&'static str, String>> {
    let o = &event["data"]["object"];
    let meta = field(&o["metadata"][TEAM_KEY]);
    let known = app.db.team_subscription_by_id(sub.id);
    let by_customer = sub.user.is_none().then(|| sub.customer.and_then(|c| app.db.customer_team(c))).flatten();
    if meta.is_none() && known.is_none() && by_customer.is_none() {
        return None;
    }
    Some(apply(app, event_id, kind, event, sub, meta, known, by_customer))
}

#[allow(clippy::too_many_arguments)]
fn apply(
    app: &App,
    event_id: &str,
    kind: &str,
    event: &Value,
    sub: &Sub,
    meta: Option<String>,
    known: Option<TeamSubscription>,
    by_customer: Option<String>,
) -> Result<&'static str, String> {
    let ignore = |reason: &str, team: Option<&str>, extra: Value| ignored(app, event_id, kind, reason, team, extra);
    // A team's subscription never names a person: one that names both pays for neither.
    if sub.user.is_some() {
        return ignore("ambiguous_payer", meta.as_deref().or(known.as_ref().map(|s| s.team_id.as_str())), json!({ "subscription": sub.id, "user": sub.user }));
    }
    let id = meta.or_else(|| known.as_ref().map(|s| s.team_id.clone())).or(by_customer);
    let Some(team) = id.as_deref().and_then(|t| app.db.team(t)) else {
        return ignore("unknown_team", None, json!({ "subscription": sub.id, "team": id }));
    };
    let Some(plan) = billing::plan_of(app, kind, sub) else {
        return ignore("unknown_price", Some(&team.id), json!({ "subscription": sub.id, "prices": sub.prices }));
    };
    let o = &event["data"]["object"];
    let items = o["items"]["data"].as_array().map(Vec::as_slice).unwrap_or_default();
    let item = items.iter().find(|i| i["price"]["id"].as_str() == plan.price.as_deref()).or(items.first());
    let created = event["created"].as_i64().unwrap_or(0);
    let row = TeamSubscription {
        team_id: team.id.clone(),
        provider: "stripe".into(),
        customer_id: sub.customer.map(String::from),
        subscription_id: sub.id.into(),
        status: plan.status.clone(),
        price_id: plan.price.clone(),
        tier: plan.tier.clone(),
        item_id: item.and_then(|i| field(&i["id"])),
        quantity: item.and_then(|i| i["quantity"].as_i64()),
        period_start: sub.period_start,
        period_end: sub.period_end,
        cancel_at: sub.cancel_at,
        started: sub.created.or(known.as_ref().map(|s| s.started)).unwrap_or(created),
        event_created: created,
        updated_at: 0,
        paid_by: field(&o["metadata"][PAID_BY_KEY]),
        seat_tries: 0,
        seat_failures: 0,
        seat_next_at: 0,
        seat_error: None,
    };
    let before = tiers_now(app, &team.id);
    let to: Vec<String> = app.db.team_members(&team.id).into_iter().filter(|m| m.role == crate::teams::OWNER || m.role == crate::teams::ADMIN).map(|m| m.user_id).collect();
    let payers = crate::billing_mail::personal_payers(app, &team.id);
    let ev = crate::billing_mail::TeamSubEvent { event_id, row: &row, ending: plan.ending, team: &team.name, to: &to, payers: &payers };
    let (applied, linked, emails) = app.db.apply_team_subscription(event_id, kind, &row, plan.set_tier, &|c| crate::billing_mail::team_subscription_emails(app, &ev, c))?;
    let by = billing::system(None);
    if let (Some(Linked::New), Some(cus)) = (&linked, sub.customer) {
        app.db.record(&team_event(&by, "billing.customer_linked", &team.id, json!({ "customer": cus, "via": "subscription", "eventId": event_id })));
    }
    let details = json!({ "eventId": event_id, "type": kind, "subscription": sub.id, "status": row.status, "price": row.price_id, "tier": row.tier, "quantity": row.quantity });
    if !matches!(applied, Applied::OtherUser | Applied::CustomerOfAnotherUser) {
        app.db.close_team_checkout_for(&team.id, sub.id);
    }
    let outcome = match applied {
        Applied::Duplicate => {
            // As for a person's: a resize the first delivery didn't get to ask for is asked for now.
            follow(app, &team.id, &before, &json!({}), Some(event_id), false);
            return Ok("duplicate");
        }
        Applied::Stale => "stale",
        Applied::Superseded => "superseded",
        Applied::OtherUser => return ignore("subscription_of_another_payer", Some(&team.id), json!({ "subscription": sub.id })),
        Applied::CustomerOfAnotherUser => return ignore("customer_of_another_payer", Some(&team.id), json!({ "subscription": sub.id, "customer": sub.customer })),
        Applied::Unchanged => "unchanged",
        Applied::Changed { from, to } => {
            // Without a paid plan, the one a server admin gave the team, if any (ADR 0347).
            let given = app.db.team(&team.id).and_then(|t| t.tier);
            let effective = |t: &Option<String>| app.tiers().of(t.as_deref().or(given.as_deref())).name.clone();
            let mut d = json!({ "from": from, "to": to, "effectiveFrom": effective(&from), "effectiveTo": effective(&to), "source": "stripe" });
            if let (Some(d), Value::Object(x)) = (d.as_object_mut(), details.clone()) {
                d.extend(x);
            }
            app.db.record(&team_event(&by, "team.tier_changed", &team.id, d));
            follow(app, &team.id, &before, &json!({ "subscription": sub.id }), Some(event_id), true);
            "tier_changed"
        }
    };
    let mut d = details;
    d["outcome"] = json!(outcome);
    app.db.record(&team_event(&by, "billing.subscription_synced", &team.id, d));
    if emails > 0 {
        app.db.release_billing_emails(event_id);
        crate::billing_mail::wake(app);
    }
    wake(app);
    Ok(outcome)
}

/// `checkout.session.completed` for a team's checkout: links its customer to the team.
/// None: the session names no team.
pub(crate) fn checkout_completed(app: &App, event_id: &str, kind: &str, o: &Value) -> Option<Result<&'static str, String>> {
    let id = field(&o["metadata"][TEAM_KEY])?;
    let ignore = |reason: &str, team: Option<&str>, extra: Value| ignored(app, event_id, kind, reason, team, extra);
    let session = o["id"].as_str().unwrap_or_default();
    if field(&o["metadata"][billing::USER_KEY]).is_some() {
        return Some(ignore("ambiguous_payer", Some(&id), json!({ "session": session })));
    }
    let Some(team) = app.db.team(&id) else {
        return Some(ignore("unknown_team", None, json!({ "session": session, "team": id })));
    };
    app.db.team_checkout_paid(&team.id, session, o["subscription"].as_str().or(o["subscription"]["id"].as_str()));
    let Some(cus) = billing::customer_of(o) else {
        return Some(ignore("no_customer", Some(&team.id), json!({ "session": session })));
    };
    Some(match app.db.link_team_customer(event_id, kind, &team.id, "stripe", cus) {
        Err(e) => Err(e),
        Ok(None) => Ok("duplicate"),
        Ok(Some(Linked::New)) => {
            let d = json!({ "customer": cus, "via": "checkout", "eventId": event_id, "paidBy": field(&o["metadata"][PAID_BY_KEY]) });
            app.db.record(&team_event(&billing::system(None), "billing.customer_linked", &team.id, d));
            Ok("customer_linked")
        }
        Ok(Some(Linked::Already)) => Ok("unchanged"),
        Ok(Some(Linked::UserHasAnother(other))) => ignore("team_has_another_customer", Some(&team.id), json!({ "session": session, "customer": cus, "linked": other })),
        Ok(Some(Linked::OfAnotherUser(_))) => ignore("customer_of_another_payer", Some(&team.id), json!({ "session": session, "customer": cus })),
        Ok(Some(Linked::Deleted)) => ignore("customer_deleted", Some(&team.id), json!({ "session": session, "customer": cus })),
    })
}

// Seats

fn backoff_ms(failures: i64) -> i64 {
    (60_000 * 4i64.pow(failures.clamp(1, 4) as u32 - 1)).min(BACKOFF_CAP_MS)
}

/// A Stripe subscription item id, safe to put in a path.
fn item_ok(id: &str) -> bool {
    id.starts_with("si_") && (4..=255).contains(&id.len()) && id.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// One pass: sets the quantity of each paying team subscription whose seats aren't its
/// member count (at least one), with Stripe's prorations, unless its last failure's
/// backoff hasn't passed. Each try has its own idempotency key: a quantity is absolute,
/// so sending one twice changes nothing, and a key reused after the team changed back
/// would get Stripe's old answer instead of an update. Returns the teams updated.
pub async fn sync_seats(app: &App) -> usize {
    let Some(s) = app.team_seats.get() else { return 0 };
    let _one = s.busy.lock().await;
    let mut synced = 0;
    for sub in app.db.teams_paying() {
        let want = app.db.team_member_count(&sub.team_id).max(1);
        if sub.quantity == Some(want) {
            if sub.seat_error.is_some() {
                app.db.team_seats_clear(&sub.subscription_id);
            }
            continue;
        }
        let at = crate::db::now();
        if sub.seat_next_at > at {
            continue;
        }
        let by = billing::system(None);
        let d = json!({ "subscription": sub.subscription_id, "from": sub.quantity, "to": want, "members": want });
        let failed = |error: String, d: Value| {
            let next = at + backoff_ms(sub.seat_failures + 1);
            let failures = app.db.team_seats_failed(&sub.subscription_id, &error, next);
            let mut d = d;
            d["error"] = json!(error);
            d["attempts"] = json!(failures);
            d["retrying"] = json!(true);
            d["retryAt"] = json!(next);
            app.db.record(&team_event(&by, "team.seats_sync_failed", &sub.team_id, d).outcome(Outcome::Failure));
        };
        let Some(item) = sub.item_id.as_deref().filter(|i| item_ok(i)) else {
            failed("the subscription has no item botd can update".into(), d);
            continue;
        };
        let tries = match app.db.team_seat_try(&sub.subscription_id) {
            Ok(n) => n,
            Err(e) => {
                crate::obs::log::log_warn!("billing: team seats: {e}");
                break;
            }
        };
        let form: Vec<(String, String)> = vec![("quantity".into(), want.to_string()), ("proration_behavior".into(), "create_prorations".into())];
        let mut keyed = form.clone();
        keyed.push(("subscription".into(), sub.subscription_id.clone()));
        keyed.push(("try".into(), tries.to_string()));
        let key = stripe::idempotency_key("seats", &format!("team:{}", sub.team_id), &keyed, 0);
        match s.stripe.post(&format!("/v1/subscription_items/{item}"), &form, &key).await {
            Ok(v) => {
                let got = v["quantity"].as_i64().unwrap_or(want);
                app.db.team_seats_synced(&sub.subscription_id, got);
                let mut d = d;
                d["to"] = json!(got);
                app.db.record(&team_event(&by, "team.seats_synced", &sub.team_id, d));
                synced += 1;
            }
            Err(e) => {
                crate::obs::log::log_warn!("billing: team seats for {}: {e}; trying again later", sub.team_id);
                failed(e.to_string(), d);
            }
        }
    }
    synced
}

/// Syncs seats every minute and whenever a team changes, while team billing is on.
pub fn start(app: Arc<App>) {
    let Some(s) = app.team_seats.get().cloned() else { return };
    tokio::spawn(async move {
        loop {
            sync_seats(&app).await;
            tokio::select! {
                _ = s.wake.notified() => {}
                _ = tokio::time::sleep(EVERY) => {}
            }
        }
    });
}

// What people see

/// The team's plan, as `GET /api/team` and `/api/teams` show it while team billing is
/// on: the plan for everyone on it; for its owners and admins (`manager`) and server
/// admins, the subscription, its seats, and the plans for sale. Never a Stripe id.
pub fn view(app: &App, team_id: &str, manager: bool) -> Option<Value> {
    // Without billing, only a plan a server admin gave the team, which no one here changes (ADR 0347).
    if !on(app) {
        let given = app.db.team(team_id)?.tier?;
        let tiers = app.tiers();
        let t = tiers.of(Some(&given));
        return Some(json!({ "plan": { "name": t.name, "label": t.label, "source": crate::team_plan::ADMIN }, "canChange": false }));
    }
    let paying = app.db.team_paying(team_id);
    let tiers = app.tiers();
    let plan = crate::team_plan::of(app, team_id).map(|(t, source)| {
        let t = tiers.of(Some(&t));
        json!({ "name": t.name, "label": t.label, "source": source })
    });
    let mut v = json!({ "plan": plan });
    if !manager {
        return Some(v);
    }
    let sub = app.db.team_subscription(team_id);
    let members = app.db.team_member_count(team_id);
    v["subscription"] = json!(sub.as_ref().map(|s| json!({ "status": s.status, "tier": s.tier, "periodEnd": s.period_end, "cancelAt": s.cancel_at })));
    v["seats"] = json!(paying.as_ref().map(|s| json!({
        "members": members,
        "billed": s.quantity,
        "syncing": s.quantity != Some(members.max(1)),
        "error": s.seat_error.as_ref().map(|_| "Stripe didn't take the new seat count yet. SuperBot keeps trying."),
    })));
    v["portal"] = json!(app.db.team_customer(team_id).is_some());
    v["plans"] = json!(tiers.all().iter().filter(|t| !t.stripe_prices.is_empty()).map(|t| t.view()).collect::<Vec<_>>());
    Some(v)
}

// Checkout and the portal, for a team's owners and admins

#[allow(clippy::result_large_err)]
fn managed(app: &AppState, c: &Caller) -> Result<(crate::db::User, Team), Response> {
    let (u, _, t) = crate::teams::my_team_for(app, c, crate::rbac::Perm::ManageBilling).map_err(IntoResponse::into_response)?;
    Ok((u, t))
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Buy {
    tier: String,
}

/// `POST /api/team/billing/checkout {tier}`: a Stripe Checkout Session for the team's
/// plan, a seat for each member; returns `{url}`. Owners and admins only. Refused for
/// tiers without a price, and while a subscription already pays for the team's plan.
pub async fn checkout(
    State(app): State<AppState>,
    Extension(a): Extension<Arc<Auth>>,
    Extension(c): Extension<Caller>,
    Extension(by): Extension<Who>,
    body: Result<Json<Buy>, JsonRejection>,
) -> Response {
    // Stripe calls go through the seat sync's client, set at startup, never one reached
    // through the request.
    let (Some(co), Some(sync)) = (a.payments.checkout(), app.team_seats.get()) else { return billing::off() };
    let (u, t) = match managed(&app, &c) {
        Ok(x) => x,
        Err(r) => return r,
    };
    let bad = |code: StatusCode, msg: String| reply(code, json!({ "error": msg }));
    let Some(name) = body.ok().map(|Json(b)| b.tier).map(|t| t.trim().to_string()).filter(|t| !t.is_empty()) else {
        return bad(StatusCode::BAD_REQUEST, "Say which plan: {\"tier\": \"<name>\"}.".into());
    };
    let tiers = app.tiers();
    let Some(tier) = tiers.get(&name) else {
        return bad(StatusCode::BAD_REQUEST, format!("There's no plan called \"{name}\"."));
    };
    let Some(price) = tier.stripe_prices.first() else {
        return bad(StatusCode::BAD_REQUEST, format!("The {} plan can't be bought here.", tier.label));
    };
    let event = |outcome: Outcome, d: Value| team_event(&by, "billing.checkout_created", &t.id, d).outcome(outcome);
    if !billing::may_start(co, &u.id) {
        return bad(StatusCode::TOO_MANY_REQUESTS, "Too many checkouts at once. Try again in a minute.".into());
    }
    let _one_at_a_time = sync.hold(&t.id).await;
    if app.db.team(&t.id).is_none() {
        return bad(StatusCode::NOT_FOUND, "You aren't on a team.".into());
    }
    if let Some(s) = app.db.team_paying(&t.id) {
        app.db.record(&event(Outcome::Denied, json!({ "tier": tier.name, "reason": "already_subscribed", "subscription": s.subscription_id })));
        return reply(StatusCode::CONFLICT, json!({ "error": "The team already pays for a plan. Change it under Manage billing.", "portal": true }));
    }
    let payer = Payer::Team(&t.id);
    let last = payer.open_checkout(&app);
    match billing::close_last(&app, &sync.stripe, payer).await {
        Last::Closed => {}
        Last::Paid => {
            app.db.record(&event(Outcome::Denied, json!({ "tier": tier.name, "reason": "checkout_completed", "session": last })));
            return reply(StatusCode::CONFLICT, json!({ "error": "The team's last checkout went through. Its plan changes as soon as Stripe confirms the payment." }));
        }
        Last::Unknown(e) => {
            crate::obs::log::log_warn!("billing: closing team {}'s last Stripe checkout: {e}", t.id);
            app.db.record(&event(Outcome::Failure, json!({ "tier": tier.name, "reason": format!("last checkout: {e}"), "session": last })));
            return bad(StatusCode::BAD_GATEWAY, "Stripe couldn't open the checkout just now. Try again in a minute; if it keeps happening, an admin can see why in the server log.".into());
        }
    }
    let seats = app.db.team_member_count(&t.id).max(1);
    let customer = app.db.team_customer(&t.id);
    let back = format!("{}{RETURN_PATH}", co.public_url);
    let mut form: Vec<(String, String)> = [
        ("mode", "subscription"),
        ("line_items[0][price]", price.as_str()),
        ("metadata[superbot_team_id]", t.id.as_str()),
        ("metadata[superbot_paid_by]", u.id.as_str()),
        ("metadata[superbot_tier]", tier.name.as_str()),
        ("subscription_data[metadata][superbot_team_id]", t.id.as_str()),
        ("subscription_data[metadata][superbot_paid_by]", u.id.as_str()),
    ]
    .iter()
    .map(|(k, v)| (k.to_string(), v.to_string()))
    .collect();
    form.push(("line_items[0][quantity]".into(), seats.to_string()));
    form.push(("success_url".into(), format!("{back}?checkout=success")));
    form.push(("cancel_url".into(), format!("{back}?checkout=cancelled")));
    match (&customer, &u.email) {
        (Some(cus), _) => form.push(("customer".into(), cus.clone())),
        (None, Some(email)) => form.push(("customer_email".into(), email.clone())),
        (None, None) => {}
    }
    let now = crate::db::now();
    let expires_at = (now / 60_000 + billing::CHECKOUT_MINUTES) * 60;
    form.push(("expires_at".into(), expires_at.to_string()));
    let mut keyed = form.clone();
    keyed.push(("request".into(), crate::random_hex(16)));
    let key = stripe::idempotency_key("checkout", &payer.key(), &keyed, now);
    match billing::session("checkout", &payer.key(), sync.stripe.post("/v1/checkout/sessions", &form, &key).await) {
        Ok((id, url)) => {
            app.db.set_team_open_checkout(&t.id, &id, expires_at);
            app.db.record(&event(Outcome::Success, json!({ "tier": tier.name, "price": price, "session": id, "customer": customer, "seats": seats })));
            reply(StatusCode::OK, json!({ "url": url }))
        }
        Err((r, reason)) => {
            app.db.record(&event(Outcome::Failure, json!({ "tier": tier.name, "price": price, "seats": seats, "reason": reason })));
            r
        }
    }
}

/// `POST /api/team/billing/portal`: a Stripe Billing Portal session for the team's
/// customer; returns `{url}`. Owners and admins only; 409 until the team has one.
pub async fn portal(State(app): State<AppState>, Extension(a): Extension<Arc<Auth>>, Extension(c): Extension<Caller>, Extension(by): Extension<Who>) -> Response {
    let (Some(co), Some(sync)) = (a.payments.checkout(), app.team_seats.get()) else { return billing::off() };
    let (u, t) = match managed(&app, &c) {
        Ok(x) => x,
        Err(r) => return r,
    };
    let Some(cus) = app.db.team_customer(&t.id) else {
        return reply(StatusCode::CONFLICT, json!({ "error": "The team has no billing account to manage yet. Pick a plan first." }));
    };
    if !billing::may_start(co, &u.id) {
        return reply(StatusCode::TOO_MANY_REQUESTS, json!({ "error": "Too many requests at once. Try again in a minute." }));
    }
    let payer = Payer::Team(&t.id).key();
    let form = vec![("customer".to_string(), cus.clone()), ("return_url".to_string(), format!("{}{RETURN_PATH}", co.public_url))];
    let key = stripe::idempotency_key("portal", &payer, &form, crate::db::now());
    let event = |outcome: Outcome, d: Value| team_event(&by, "billing.portal_created", &t.id, d).outcome(outcome);
    match billing::session("billing portal", &payer, sync.stripe.post("/v1/billing_portal/sessions", &form, &key).await) {
        // The link signs whoever has it in to the team's billing: never logged.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seat_retries_back_off_to_an_hour_and_never_stop() {
        assert_eq!([1, 2, 3, 4, 5, 50].map(backoff_ms), [60_000, 240_000, 960_000, 3_600_000, 3_600_000, 3_600_000]);
    }

    #[test]
    fn only_stripe_item_ids_go_in_the_path() {
        assert!(item_ok("si_test_ada"));
        for bad in ["", "si_", "si_../x", "sub_1", "si_a/b", "si_a?b=1"] {
            assert!(!item_ok(bad), "{bad}");
        }
    }
}
