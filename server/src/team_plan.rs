//! Server admins change a team's plan (ADR 0347): `PUT /api/teams/{id}/plan {tier}`,
//! from the console's Teams tab (`rbac::classify` leaves `teams` to admins).
//!
//! While a Stripe subscription pays for the team's plan (ADR 0093), botd moves that
//! subscription onto the tier's price, with Stripe's prorations, and the webhook applies
//! the change as it does any other. Otherwise the plan is the admin's to give: recorded on
//! the team and every member's while no subscription pays, with no Stripe call, so it
//! works the same with billing off (ADR 0068). Either way, each member still paying for a
//! plan of their own is emailed, once per change, that they may cancel it (ADR 0091).

use crate::audit::{Outcome, Who};
use crate::db::Team;
use crate::runner::App;
use crate::stripe;
use crate::tiers::Tier;
use crate::{ApiError, AppState, Res, bad, not_found};
use axum::Json;
use axum::extract::rejection::JsonRejection;
use axum::extract::{Extension, Path, State};
use axum::http::StatusCode;
use serde_json::{Value, json};

/// The plan's source: the team's paying subscription.
pub const STRIPE: &str = "stripe";
/// The plan's source: a server admin gave it.
pub const ADMIN: &str = "admin";

/// The team's plan and where it comes from: its paying subscription's tier, else the one
/// a server admin gave it.
pub fn of(app: &App, team_id: &str) -> Option<(String, &'static str)> {
    if let Some(t) = app.db.team_paying(team_id).and_then(|s| s.tier) {
        return Some((t, STRIPE));
    }
    app.db.team(team_id).and_then(|t| t.tier).map(|t| (t, ADMIN))
}

/// What server admins see of a team's plan: the plan everyone on it is on and its source,
/// the plan an admin gave it, and whether Stripe pays for it.
pub fn admin_view(app: &App, t: &Team) -> Value {
    let tiers = app.tiers();
    let current = of(app, &t.id).map(|(name, source)| {
        let tier = tiers.of(Some(&name));
        json!({ "name": tier.name, "label": tier.label, "source": source })
    });
    json!({ "current": current, "given": t.tier, "paid": app.db.team_paying(&t.id).is_some() })
}

/// The plans an admin can pick for a team. `priced`: a team that pays in Stripe can move
/// to it, as it has a Stripe price.
pub fn choices(app: &App) -> Value {
    json!(app.tiers().all().iter().map(|t| json!({ "name": t.name, "label": t.label, "priced": !t.stripe_prices.is_empty() })).collect::<Vec<_>>())
}

fn conflict(msg: impl Into<String>) -> ApiError {
    ApiError(StatusCode::CONFLICT, msg.into())
}

/// The tier asked for: Some(None) takes the plan away.
fn wanted<'a>(app: &'a App, body: Result<Json<Value>, JsonRejection>) -> Res<Option<&'a Tier>> {
    const SAY: &str = "Send {\"tier\": \"<plan>\"}, or {\"tier\": null} to take the team's plan away.";
    let Ok(Json(v)) = body else { return Err(bad(SAY)) };
    let Some(o) = v.as_object().filter(|o| o.len() == 1) else { return Err(bad(SAY)) };
    match o.get("tier") {
        Some(Value::Null) => Ok(None),
        Some(Value::String(name)) => {
            let tiers = app.tiers();
            let names = || tiers.all().iter().map(|t| t.name.as_str()).collect::<Vec<_>>().join(", ");
            tiers.get(name.trim()).map(Some).ok_or_else(|| bad(format!("There's no plan called \"{}\". Plans: {}.", name.trim(), names())))
        }
        _ => Err(bad(SAY)),
    }
}

/// `PUT /api/teams/{id}/plan {tier: name | null}`: the team's plan. Returns the team as
/// server admins see it: 200 once it applies, 202 while Stripe moves the subscription.
pub async fn put(State(app): State<AppState>, Extension(by): Extension<Who>, Path(id): Path<String>, body: Result<Json<Value>, JsonRejection>) -> Res<(StatusCode, Json<Value>)> {
    let t = app.db.team(&id).ok_or_else(|| not_found("Team"))?;
    let tier = wanted(&app, body)?;
    let code = match app.db.team_paying(&t.id) {
        Some(sub) => move_subscription(&app, &by, &t, &sub, tier).await?,
        None => give(&app, &by, &t, tier)?,
    };
    let t = app.db.team(&t.id).ok_or_else(|| not_found("Team"))?;
    Ok((code, Json(crate::teams::admin_view(&app, &t))))
}

/// No subscription pays: the plan is recorded on the team, with no Stripe call, and in
/// the same transaction the emails telling members paying for a plan of their own that
/// they may cancel it. Each member it moves is audited and their computer follows (ADR
/// 0085), as when the team pays. The same plan again changes nothing, but asks again
/// for any resize a change left unasked (botd stopped between, say).
fn give(app: &App, by: &Who, t: &Team, tier: Option<&Tier>) -> Res<StatusCode> {
    let to = tier.map(|x| x.name.clone());
    let why = |change: &str| json!({ "via": ADMIN, "change": change });
    if t.tier == to {
        let now = crate::team_billing::tiers_now(app, &t.id);
        crate::team_billing::follow(app, &t.id, &now, &why(""), None, false);
        return Ok(StatusCode::OK);
    }
    let before = crate::team_billing::tiers_now(app, &t.id);
    let change = crate::random_hex(8);
    let emails = match tier {
        Some(tier) if app.billing_mail.get().is_some() => {
            let payers = crate::billing_mail::personal_payers(app, &t.id);
            crate::billing_mail::covered(&format!("team_plan:{}:{change}", t.id), &t.id, &t.name, &tier.label, &payers, None)
        }
        _ => Vec::new(),
    };
    match app.db.set_team_tier(&t.id, to.as_deref(), &emails) {
        Ok(true) => crate::billing_mail::wake(app),
        Ok(false) => return Err(not_found("Team")),
        Err(e) => {
            crate::obs::log::log_warn!("botd: couldn't save team {}'s plan: {e}", t.id);
            return Err(ApiError(StatusCode::INTERNAL_SERVER_ERROR, "The team's plan couldn't be saved. Nothing changed; try again.".into()));
        }
    }
    let tiers = app.tiers();
    let effective = |x: &Option<String>| tiers.of(x.as_deref()).name.clone();
    let d = json!({ "from": t.tier, "to": to, "effectiveFrom": effective(&t.tier), "effectiveTo": effective(&to), "source": ADMIN, "change": change, "emailed": emails.len() });
    app.db.record(&crate::teams::team_event(by, "team.tier_changed", &t.id, d));
    crate::team_billing::follow(app, &t.id, &before, &why(&change), None, true);
    Ok(StatusCode::OK)
}

/// A Stripe subscription id or item id, safe to put in a path.
fn id_ok(id: &str, prefix: &str) -> bool {
    id.len() > prefix.len() && id.len() <= 255 && id.starts_with(prefix) && id.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// A subscription pays: it's moved to the tier's price in Stripe, with prorations, and
/// the webhook applies the plan once Stripe says it's done (202). Refused when billing is
/// off here, when the plan would go (only the team's managers cancel what they pay for),
/// and for a plan Stripe can't charge for.
async fn move_subscription(app: &App, by: &Who, t: &Team, sub: &crate::db::TeamSubscription, tier: Option<&Tier>) -> Res<StatusCode> {
    let from = sub.tier.clone();
    let event = |outcome: Outcome, d: Value| {
        let mut x = json!({ "from": from, "to": tier.map(|x| &x.name), "subscription": sub.subscription_id, "via": STRIPE });
        if let (Some(x), Value::Object(d)) = (x.as_object_mut(), d) {
            x.extend(d);
        }
        crate::teams::team_event(by, "team.plan_change_requested", &t.id, x).outcome(outcome)
    };
    let refuse = |reason: &str, msg: String| {
        app.db.record(&event(Outcome::Denied, json!({ "reason": reason })));
        Err(conflict(msg))
    };
    // Stripe calls go through the seat sync's client, set at startup with billing on.
    let Some(seats) = app.team_seats.get() else {
        return refuse("billing_off", "The team's plan is paid for in Stripe, and billing is off on this server, so it can't be changed here.".into());
    };
    let Some(tier) = tier else {
        return refuse("team_pays", "The team pays for its plan in Stripe. To end it, its owners or admins cancel it under Manage billing on the Team screen.".into());
    };
    if from.as_deref() == Some(tier.name.as_str()) {
        return Ok(StatusCode::OK);
    }
    let Some(price) = tier.stripe_prices.first() else {
        return refuse("no_price", format!("The {} plan has no Stripe price, so a team that pays can't move to it. Its owners or admins cancel the team's plan first.", tier.label));
    };
    let item = sub.item_id.as_deref().filter(|i| id_ok(i, "si_"));
    let (Some(item), true) = (item, id_ok(&sub.subscription_id, "sub_")) else {
        return refuse("no_item", "Stripe hasn't told SuperBot about the team's subscription in full yet. Try again in a minute.".into());
    };
    let seats_now = app.db.team_member_count(&t.id).max(1);
    let form: Vec<(String, String)> = vec![
        ("items[0][id]".into(), item.into()),
        ("items[0][price]".into(), price.clone()),
        ("items[0][quantity]".into(), seats_now.to_string()),
        ("proration_behavior".into(), "create_prorations".into()),
    ];
    // Its own key per request, kept across the client's retries of it: the same change
    // asked for again after the webhook (Pro, Starter, Pro) must reach Stripe again.
    let mut keyed = form.clone();
    keyed.push(("request".into(), crate::random_hex(8)));
    let key = stripe::idempotency_key("team-plan", &crate::billing::Payer::Team(&t.id).key(), &keyed, crate::db::now());
    match seats.stripe().post(&format!("/v1/subscriptions/{}", sub.subscription_id), &form, &key).await {
        Ok(_) => {
            app.db.record(&event(Outcome::Success, json!({ "price": price, "seats": seats_now })));
            Ok(StatusCode::ACCEPTED)
        }
        Err(e) => {
            crate::obs::log::log_warn!("billing: moving team {}'s Stripe subscription to {}: {e}", t.id, tier.name);
            app.db.record(&event(Outcome::Failure, json!({ "price": price, "error": e.to_string() })));
            Err(ApiError(StatusCode::BAD_GATEWAY, "Stripe couldn't change the team's plan just now. Try again in a minute; if it keeps happening, the server log says why.".into()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_stripe_ids_go_in_the_path() {
        assert!(id_ok("sub_test_alpha", "sub_") && id_ok("si_test_alpha", "si_"));
        for bad in ["", "sub_", "si_test", "sub_../x", "sub_a/b", "sub_a?b=1", "cus_test"] {
            assert!(!id_ok(bad, "sub_"), "{bad}");
        }
    }
}
