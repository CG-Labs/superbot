//! Residency for the people a pin holds (ADR 0168): the pin on their data, shown in the
//! app, and the residency report (ADR 0155) on it, fetched by themselves. Your own pin's
//! report is yours; your team's pin's report, which covers every member, is for the
//! team's owners and admins, who already see its members' machines (ADR 0087). A pin's
//! agreement reference is shown to the same people as on the Team screen (ADR 0129).
//! People only, never Bots. Reports are audited as admins' are, marked `selfService`,
//! and limited per person, since each one reads the audit log for its period.

use super::ControlPlane;
use super::residency::{self, outside};
use super::residency_report;
use crate::audit::Who;
use crate::db::{PinOn, ResidencyPin, TeamMember, User};
use crate::runner::App;
use crate::teams::{ADMIN, OWNER};
use crate::users::Caller;
use crate::{ApiError, AppState, Auth, Res, bad, need_user};
use axum::Json;
use axum::extract::{Extension, Query, State as AppS};
use axum::http::StatusCode;
use axum::response::Response;
use serde_json::{Value, json};
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, LazyLock, Mutex};

/// Reports one person may fetch from the app in `WINDOW_MS`.
pub const MAX_REPORTS: usize = 5;
const WINDOW_MS: i64 = 10 * 60 * 1000;

static RECENT: LazyLock<Mutex<HashMap<String, VecDeque<i64>>>> = LazyLock::new(Default::default);

fn me(c: &Caller) -> Res<User> {
    need_user(c.principal)?;
    c.user.clone().ok_or_else(|| ApiError(StatusCode::FORBIDDEN, "Sign in as a person to see your data's residency.".into()))
}

fn manages(m: Option<&TeamMember>) -> bool {
    m.is_some_and(|m| m.role == OWNER || m.role == ADMIN)
}

/// Takes one of `user_id`'s reports in the window ending `now`. Err: seconds until the next.
fn take(recent: &mut HashMap<String, VecDeque<i64>>, user_id: &str, now: i64) -> Result<(), i64> {
    recent.retain(|_, q| q.back().is_some_and(|t| now - t < WINDOW_MS));
    let q = recent.entry(user_id.to_string()).or_default();
    while q.front().is_some_and(|t| now - t >= WINDOW_MS) {
        q.pop_front();
    }
    if q.len() >= MAX_REPORTS {
        let first = q.front().copied().unwrap_or(now);
        return Err(((first + WINDOW_MS - now + 999) / 1000).max(1));
    }
    q.push_back(now);
    Ok(())
}

/// Which pin's report `u` asked for (`on`: `user`, `team`, or the one they can get,
/// their team's first) and may have.
fn pick(app: &App, u: &User, on: Option<&str>) -> Res<ResidencyPin> {
    let member = app.db.team_member(&u.id);
    let team = member.as_ref().and_then(|m| app.db.residency_pin(PinOn::Team, &m.team_id));
    let own = app.db.residency_pin(PinOn::User, &u.id);
    let lead = manages(member.as_ref());
    let not_lead = || ApiError(StatusCode::FORBIDDEN, "Only your team's owners and admins can get its residency report, since it covers everyone on the team. Ask one of them.".into());
    let none = |msg: &str| ApiError(StatusCode::NOT_FOUND, msg.into());
    match on {
        Some("user") => own.ok_or_else(|| match team {
            Some(_) => none("Your data has no residency pin of your own; your team's pin holds it."),
            None => none("Your data has no residency pin."),
        }),
        Some("team") => match team {
            Some(p) if lead => Ok(p),
            Some(_) => Err(not_lead()),
            None => Err(none("Your team's data has no residency pin.")),
        },
        Some(_) => Err(bad("on must be user or team")),
        None => match (team, own) {
            (Some(p), _) if lead => Ok(p),
            (_, Some(p)) => Ok(p),
            (Some(_), None) => Err(not_lead()),
            (None, None) => Err(none("Your data has no residency pin.")),
        },
    }
}

/// Your own pin's reference, or for one kept from a team you left (ADR 0171) that team
/// instead: its reference is the team's agreement, which only the team's owners and
/// admins see (ADR 0129). `endsWhenDataGone`: it ends by itself once botd holds none of
/// their machine data (ADR 0205).
fn own_pin_fields(app: &App, cp: &ControlPlane, p: &ResidencyPin, v: &mut Value) {
    match &p.kept_from {
        Some(t) => {
            v["keptFrom"] = json!({ "team": { "id": t, "name": app.db.team(t).map(|t| t.name) }, "endsWhenDataGone": cp.kept_pins == residency::KeptPins::End })
        }
        None => v["reference"] = json!(p.reference),
    }
}

/// `GET /api/me/residency`: the pin that holds your data (your team's, else your own), or
/// null; whether your machine and backups are in its region, your plan's model routes are
/// held there, your Bots run on a computer there (ADR 0267), and botd's own copy of your
/// account and chats is (ADR 0184), and whether
/// your Bots' chats are kept in the region's own chat store (ADR 0215); and which
/// reports you can get.
pub async fn view(AppS(app): AppS<AppState>, Extension(a): Extension<Arc<Auth>>, Extension(c): Extension<Caller>) -> Res {
    let u = me(&c)?;
    let cp = &*a.machines;
    let member = app.db.team_member(&u.id);
    let lead = manages(member.as_ref());
    let Some(p) = residency::of_user(&app, &u.id) else {
        return Ok(Json(json!({ "pin": null, "ownPin": null, "reports": [] })));
    };
    let own = app.db.residency_pin(PinOn::User, &u.id);
    let mut pin = json!({ "on": p.subject_type.as_str(), "region": p.region, "pinnedAt": p.pinned_at });
    match p.subject_type {
        PinOn::Team => {
            pin["team"] = json!({ "id": p.subject_id, "name": app.db.team(&p.subject_id).map(|t| t.name) });
            if lead {
                pin["reference"] = json!(p.reference);
            }
        }
        PinOn::User => own_pin_fields(&app, cp, &p, &mut pin),
    }
    let own_pin = own.as_ref().filter(|_| p.subject_type == PinOn::Team).map(|o| {
        let mut v = json!({ "region": o.region, "pinnedAt": o.pinned_at });
        own_pin_fields(&app, cp, o, &mut v);
        v
    });
    let mut reports = Vec::new();
    if p.subject_type == PinOn::Team && lead {
        reports.push("team");
    }
    if own.is_some() {
        reports.push("user");
    }
    let you = residency_report::person(&app, cp, &u.id, &p.region).unwrap_or(Value::Null);
    let kept = outside(&app, cp, &u.id, &p.region).is_empty() && super::chat_stores::outside(&app, &p.region, &u.id).is_empty() && cp.server_data.refuses(&p.region).is_empty();
    let status = if kept { "kept" } else { "data_outside" };
    let sd = &cp.server_data;
    let server_data = json!({
        "region": sd.region, "inRegion": sd.outside(&p.region).is_empty(), "backupsInRegion": sd.backups_in(&p.region),
        "required": sd.policy == super::server_data::Policy::Require,
    });
    let chats = super::chat_stores::against(&app, cp, &p.region, std::slice::from_ref(&u.id), server_data["inRegion"] == true);
    Ok(Json(json!({
        "pin": pin,
        "ownPin": own_pin,
        "status": status,
        "machine": you["machine"],
        "backups": you["backups"],
        "modelRoutes": { "inRegion": you["modelRoutes"]["inRegion"], "gap": you["modelRoutes"]["gap"] },
        "runs": you["runs"],
        "serverData": server_data,
        "chats": chats_view(&chats),
        "reports": reports,
    })))
}

/// What the app says about your chats, routines, approvals, Bots' memory, facts, sign-ins and own secrets (ADR 0215, ADR 0228, ADR 0276, ADR 0277, ADR 0283, ADR 0293): whether
/// the region has a store, whether they are all in the region, whether some are still to
/// move there, and how many backups of another region's store still hold them from before
/// they moved out. `signIns`: the store keeps sign-ins too, which servers before ADR 0283 don't;
/// `secrets`: and your own secrets, which servers before ADR 0293 don't.
fn chats_view(c: &Value) -> Value {
    let n = |k: &str| -> i64 { super::chat_stores::KINDS.iter().filter_map(|t| c[t][k].as_i64()).sum() };
    let moving = n("elsewhere") > 0 || (c["store"] == true && n("inServerDatabase") > 0);
    let earlier: i64 = c["earlierCopies"].as_array().into_iter().flatten().filter_map(|e| e["backups"].as_i64()).sum();
    json!({ "store": c["store"], "inRegion": c["inRegion"], "moving": moving, "earlierBackups": earlier, "signIns": true, "secrets": true })
}

/// `GET /api/me/residency/report[?on=user|team&from=&to=&format=markdown]`: the residency
/// report on your own pin, or on your team's if you are its owner or an admin.
pub async fn report(AppS(app): AppS<AppState>, Extension(a): Extension<Arc<Auth>>, Extension(c): Extension<Caller>, Extension(by): Extension<Who>, Query(q): Query<HashMap<String, String>>) -> Result<Response, ApiError> {
    let u = me(&c)?;
    let cp = &*a.machines;
    cp.need()?;
    let p = pick(&app, &u, q.get("on").map(String::as_str))?;
    let now = crate::db::now();
    residency_report::query(&q, now)?;
    let taken = take(&mut RECENT.lock().unwrap_or_else(|e| e.into_inner()), &u.id, now);
    if let Err(wait) = taken {
        return Err(ApiError(StatusCode::TOO_MANY_REQUESTS, format!("You can get {MAX_REPORTS} residency reports every 10 minutes. Try again in {wait} seconds.")));
    }
    residency_report::respond(&app, cp, &by, &p, &q, true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reports_are_limited_per_person_in_a_sliding_window() {
        let mut m = HashMap::new();
        for i in 0..MAX_REPORTS as i64 {
            assert_eq!(take(&mut m, "ada", 1_000 + i), Ok(()));
        }
        assert_eq!(take(&mut m, "ada", 2_000), Err(599), "the oldest frees up 10 minutes after it was taken");
        assert_eq!(take(&mut m, "bea", 2_000), Ok(()), "per person");
        assert_eq!(take(&mut m, "ada", 1_000 + WINDOW_MS), Ok(()));
        assert_eq!(take(&mut m, "ada", 1_000 + WINDOW_MS), Err(1), "never says wait 0 seconds");
        take(&mut m, "cy", 0).unwrap();
        take(&mut m, "dee", 5 * WINDOW_MS).unwrap();
        assert!(!m.contains_key("cy") && !m.contains_key("ada"), "people with nothing in the window are forgotten");
    }
}
