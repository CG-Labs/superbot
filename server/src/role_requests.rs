//! Requests for roles (ADR 0209): just-in-time access on top of time-bound roles (ADR
//! 0197). An admin marks a time-bound role requestable; a person asks for it for some
//! hours, across the server or within their own team, with a reason; another admin
//! approves (for those hours or fewer) or denies it. Approving gives the role by hand,
//! ending when the hours are up, so it stops granting by itself.
//!
//! A request never changes anyone's built-in role and never replaces a role they hold:
//! across the server the role's base must be the role they have, and in either scope they
//! must hold no other custom role there (the same one with an end is renewed). Everything
//! is checked when it's asked for and again, in one transaction, when it's approved.

use crate::audit::Who;
use crate::db::{CustomRole, RoleRequest, RoleRequestError, TeamMember, User};
use crate::rbac::{Principal, Role};
use crate::roles::{held, only_fields};
use crate::users::Caller;
use crate::{ApiError, App, AppState, Res, bad, not_found};
use axum::Json;
use axum::extract::{Extension, Path, Query, State};
use axum::http::StatusCode;
use serde_json::{Value, json};
use std::collections::HashMap;

/// How long a request waits for a decision before it lapses.
pub const PENDING_DAYS: i64 = 7;
/// The most pending requests one person may have.
pub const MAX_PENDING: usize = 5;
const STATUSES: [&str; 5] = ["pending", "approved", "denied", "cancelled", "lapsed"];

fn conflict(msg: impl Into<String>) -> ApiError {
    ApiError(StatusCode::CONFLICT, msg.into())
}

/// Why `u` can't be given `r` by request, across the server (`team` None) or in `team`,
/// as a code `why` explains. None: they can. `member` is their team membership.
pub fn refusal(u: &User, r: &CustomRole, team: Option<&str>, member: Option<&TeamMember>) -> Option<&'static str> {
    if u.service {
        return Some("service_account");
    }
    if !u.active() {
        return Some("disabled");
    }
    if u.role == Role::Admin {
        return Some("admin");
    }
    if !r.requestable || r.max_days.is_none() {
        return Some("not_requestable");
    }
    let (holds, ends) = match team {
        None if u.role != r.base => return Some("base"),
        None => (u.role_id.as_deref(), u.role_expires_at),
        Some(_) if u.role == Role::Readonly => return Some("readonly_team"),
        Some(t) => match member.filter(|m| m.team_id == t) {
            Some(m) => (m.role_id.as_deref(), m.role_expires_at),
            None => return Some("not_on_team"),
        },
    };
    match holds {
        None => None,
        Some(id) if id == r.id && ends.is_some() => None,
        Some(id) if id == r.id => Some("holds_it"),
        Some(_) => Some("holds_another"),
    }
}

/// A refusal in words: to the person asking (`you`), or to an admin about them.
pub fn why(code: &str, r: &CustomRole, u: &User, you: bool) -> String {
    let (subj, are, have) = if you { ("You", "You're", "you") } else { ("They", "They're", "they") };
    match code {
        "service_account" => "A service account holds its role for as long as it exists, so it can't request one.".into(),
        "disabled" => format!("{are} disabled."),
        "admin" => format!("{are} an admin, so {have} can do everything already."),
        "not_requestable" => format!("{} can't be requested now. An admin can give it by hand, or make it requestable.", r.name),
        "base" => format!(
            "{} is built on {}, and {} {}: a request never changes anyone's built-in role. An admin can give it by hand.",
            r.name,
            r.base.as_str(),
            if you { "you're" } else { "they're" },
            u.role.as_str()
        ),
        "readonly_team" => format!("{are} read-only, and read-only people change nothing, in a team too."),
        "not_on_team" => format!("{are} not on that team."),
        "holds_it" => format!("{subj} hold {} already, with no end.", r.name),
        "holds_another" => format!("{subj} hold another custom role there, and a request never replaces one. Ask an admin."),
        _ => "It can't be given.".into(),
    }
}

/// "8 hours", "1 day", "3 days".
pub fn duration(hours: i64) -> String {
    match hours {
        h if h % 24 == 0 => format!("{} day{}", h / 24, if h == 24 { "" } else { "s" }),
        1 => "1 hour".into(),
        h => format!("{h} hours"),
    }
}

/// Lapses the pending requests nobody can approve any more, each audited as
/// `role.request_lapsed` by the server, with why: `expired`, `not_requestable` or `disabled`.
pub fn lapse_due(app: &App) -> usize {
    let gone = app.db.lapse_role_requests(crate::db::now());
    let by = Who::system("roles");
    for (q, reason) in &gone {
        let name = app.db.custom_role(&q.role_id).map(|r| r.name);
        let d = json!({ "request": q.id, "name": name, "user": q.user_id, "scope": scope(q), "team": q.team_id, "hours": q.hours, "why": reason });
        app.db.record(&by.event("role.request_lapsed").target("role", &q.role_id).details(d));
    }
    gone.len()
}

fn scope(q: &RoleRequest) -> &'static str {
    if q.team_id.is_some() { "team" } else { "org" }
}

fn person_view(u: &User) -> Value {
    json!({ "id": u.id, "name": u.name, "email": u.email })
}

/// What they hold in the request's scope now, with its end, or null.
fn current(app: &App, q: &RoleRequest) -> Value {
    match &q.team_id {
        None => app.db.user(&q.user_id).map_or(Value::Null, |u| held(app, u.role_id.as_deref(), u.role_expires_at)),
        Some(t) => app.db.team_member(&q.user_id).filter(|m| &m.team_id == t).map_or(Value::Null, |m| held(app, m.role_id.as_deref(), m.role_expires_at)),
    }
}

pub fn view(app: &App, q: &RoleRequest) -> Value {
    let role = app.db.custom_role(&q.role_id);
    let mut v = json!({
        "id": q.id,
        "role": role.as_ref().map(|r| json!({ "id": r.id, "name": r.name, "maxDays": r.max_days, "permissions": r.perms().names(), "applies": if q.team_id.is_some() { r.perms().in_team().names() } else { r.perms().names() } })),
        "scope": scope(q),
        "team": q.team_id.as_deref().map(|t| json!({ "id": t, "name": app.db.team(t).map(|t| t.name) })),
        "user": app.db.user(&q.user_id).map(|u| person_view(&u)),
        "hours": q.hours, "reason": q.reason, "status": q.status,
        "createdAt": q.created_at, "expiresAt": q.expires_at, "decidedAt": q.decided_at,
        "decidedBy": q.decided_by.as_deref().map(|id| app.db.user(id).map_or_else(|| json!({ "id": id }), |u| person_view(&u))),
        "note": q.note, "grantedUntil": q.granted_until,
    });
    if q.status == "pending" {
        v["current"] = current(app, q);
    }
    v
}

fn request_error(app: &App, e: RoleRequestError, q: Option<&RoleRequest>, you: bool) -> ApiError {
    match e {
        RoleRequestError::Duplicate => conflict("You've asked for this role there already. Wait for an admin, or withdraw that request."),
        RoleRequestError::TooMany(n) => conflict(format!("You have {n} pending requests, the most there may be. Withdraw one first.")),
        RoleRequestError::NotPending(s) => conflict(match s.as_str() {
            "lapsed" => "This request lapsed already.".to_string(),
            "cancelled" => "This request was withdrawn already.".to_string(),
            s => format!("This request was {s} already."),
        }),
        RoleRequestError::Refused(code) => {
            let found = q.and_then(|q| Some((app.db.custom_role(&q.role_id)?, app.db.user(&q.user_id)?)));
            match found {
                Some((r, u)) => conflict(why(code, &r, &u, you)),
                None => conflict("It can't be given."),
            }
        }
        RoleRequestError::OverLimit(h) => ApiError(
            if you { StatusCode::BAD_REQUEST } else { StatusCode::CONFLICT },
            format!("This role can be given for at most {} now. {}", duration(h), if you { "Ask for fewer hours." } else { "Approve it for fewer hours." }),
        ),
        RoleRequestError::NotFound => not_found("Request"),
        RoleRequestError::Db(e) => ApiError(StatusCode::INTERNAL_SERVER_ERROR, e),
    }
}

/// The signed-in person: never a Bot, nor a service account (those can't reach `/api/me`).
fn person(c: &Caller) -> Res<&User> {
    if c.principal == Principal::Bot {
        return Err(ApiError(StatusCode::FORBIDDEN, "Only a signed-in person can request a role, not a Bot.".into()));
    }
    c.user.as_ref().filter(|u| !u.service).ok_or_else(|| conflict("Requests for roles are a signed-in person's. Sign in with a sign-in code or SSO."))
}

fn parse_text(v: &Value, field: &str, required: bool) -> Res<Option<String>> {
    match v {
        Value::Null if !required => Ok(None),
        Value::String(s) if s.trim().chars().count() <= 500 && !s.chars().any(|c| c.is_control() && c != '\n') => {
            let s = s.trim().to_string();
            match s.is_empty() {
                true if required => Err(bad(format!("{field} says why, in up to 500 characters"))),
                true => Ok(None),
                false => Ok(Some(s)),
            }
        }
        _ if required => Err(bad(format!("{field} says why, in up to 500 characters"))),
        _ => Err(bad(format!("{field} must be text, at most 500 characters"))),
    }
}

fn parse_hours(v: &Value, most: i64, what: &str) -> Res<i64> {
    v.as_i64().filter(|h| (1..=most).contains(h)).ok_or_else(|| bad(format!("hours must be a whole number from 1 to {most}{what}")))
}

/// The roles you may request, and in which scope; your requests, newest first.
fn mine_view(app: &App, u: &User) -> Value {
    let member = app.db.team_member(&u.id);
    let team = member.as_ref().and_then(|m| app.db.team(&m.team_id));
    let offer = |code: Option<&'static str>, r: &CustomRole| json!({ "ok": code.is_none(), "why": code.map(|c| why(c, r, u, true)) });
    let requestable: Vec<Value> = app
        .db
        .custom_roles()
        .iter()
        .filter(|r| r.requestable && r.max_days.is_some())
        .map(|r| {
            json!({
                "id": r.id, "name": r.name, "description": r.description, "base": r.base,
                "permissions": r.perms().names(), "teamPermissions": r.perms().in_team().names(),
                "maxDays": r.max_days, "maxHours": r.max_days.map(|d| d * 24),
                "org": offer(refusal(u, r, None, None), r),
                "team": member.as_ref().map(|m| offer(refusal(u, r, Some(&m.team_id), Some(m)), r)),
            })
        })
        .collect();
    let requests: Vec<Value> = app.db.role_requests(Some(&u.id), None, 50).iter().map(|q| view(app, q)).collect();
    json!({
        "requestable": requestable,
        "team": team.map(|t| json!({ "id": t.id, "name": t.name })),
        "requests": requests,
        "pendingDays": PENDING_DAYS,
        "maxPending": MAX_PENDING,
    })
}

/// `GET /api/me/role-requests`: the roles you may request, and your requests.
pub async fn mine(State(app): State<AppState>, Extension(c): Extension<Caller>) -> Res {
    lapse_due(&app);
    let u = person(&c)?;
    Ok(Json(mine_view(&app, u)))
}

/// `POST /api/me/role-requests` `{role, scope?: "org" | "team", hours, reason}`: asks for a
/// requestable role for `hours` from when it's approved, across the server or in your team.
pub async fn create(State(app): State<AppState>, Extension(c): Extension<Caller>, Extension(by): Extension<Who>, Json(v): Json<Value>) -> Res<(StatusCode, Json<Value>)> {
    only_fields(&v, &["role", "scope", "hours", "reason"])?;
    lapse_due(&app);
    crate::roles::expire_due(&app);
    let u = person(&c)?;
    let key = v["role"].as_str().map(str::trim).filter(|k| !k.is_empty()).ok_or_else(|| bad("role is a requestable role's id or name"))?;
    // Roles that can't be requested read as missing, so their names stay with admins.
    let r = app.db.find_custom_role(key).filter(|r| r.requestable && r.max_days.is_some()).ok_or_else(|| not_found("Requestable role"))?;
    let member = app.db.team_member(&u.id);
    let team = match v["scope"].as_str() {
        None if v["scope"].is_null() => None,
        Some("org") => None,
        Some("team") => Some(member.as_ref().map(|m| m.team_id.clone()).ok_or_else(|| conflict("You're not on a team."))?),
        _ => return Err(bad("scope must be org or team")),
    };
    let most = r.max_days.unwrap_or(0) * 24;
    let hours = parse_hours(&v["hours"], most, &format!(": {} is given for at most {}", r.name, duration(most)))?;
    let reason = parse_text(&v["reason"], "reason", true)?.unwrap_or_default();
    if let Some(code) = refusal(u, &r, team.as_deref(), member.as_ref()) {
        return Err(conflict(why(code, &r, u, true)));
    }
    let lapses = crate::db::now() + PENDING_DAYS * crate::roles::DAY;
    let q = app.db.create_role_request(&u.id, &r.id, team.as_deref(), hours, &reason, lapses, MAX_PENDING).map_err(|e| request_error(&app, e, None, true))?;
    let d = json!({ "request": q.id, "name": r.name, "user": u.id, "scope": scope(&q), "team": q.team_id, "hours": hours, "reason": reason, "lapsesAt": q.expires_at });
    app.db.record(&by.event("role.requested").target("role", &r.id).details(d));
    let who = u.email.clone().unwrap_or_else(|| u.name.clone());
    let place = match &q.team_id {
        Some(t) => format!("In the team {}.", app.db.team(t).map(|t| t.name).unwrap_or_default()),
        None => "Across the server.".into(),
    };
    let alert = crate::notify::Alert {
        event: "role.requested".into(),
        title: format!("{who} asks for {} for {}", r.name, duration(hours)),
        lines: vec![format!("Why: {reason}"), place, format!("Approve or deny it in Roles. It lapses in {PENDING_DAYS} days.")],
        target_type: "role".into(),
        target_id: r.id.clone(),
        link: None,
    };
    crate::notify::alert(&app, alert, "roles");
    Ok((StatusCode::CREATED, Json(view(&app, &q))))
}

/// `POST /api/me/role-requests/{id}/cancel`: withdraws your pending request.
pub async fn cancel(State(app): State<AppState>, Extension(c): Extension<Caller>, Extension(by): Extension<Who>, Path(id): Path<String>) -> Res {
    lapse_due(&app);
    let u = person(&c)?;
    let q = app.db.role_request(&id).filter(|q| q.user_id == u.id).ok_or_else(|| not_found("Request"))?;
    let q = app.db.close_role_request(&q.id, "cancelled", Some(&u.id), None, Some(&u.id)).ok_or_else(|| request_error(&app, RoleRequestError::NotPending(app.db.role_request(&q.id).map_or(q.status, |q| q.status)), None, true))?;
    let name = app.db.custom_role(&q.role_id).map(|r| r.name);
    app.db.record(&by.event("role.request_cancelled").target("role", &q.role_id).details(json!({ "request": q.id, "name": name, "user": q.user_id, "scope": scope(&q), "team": q.team_id })));
    Ok(Json(view(&app, &q)))
}

/// `GET /api/role-requests?status=pending|approved|denied|cancelled|lapsed|all` (admins):
/// pending ones by default, newest first, with how many are pending.
pub async fn list(State(app): State<AppState>, Query(params): Query<HashMap<String, String>>) -> Res {
    lapse_due(&app);
    crate::roles::expire_due(&app);
    let status = match params.get("status").map(String::as_str) {
        None | Some("pending") => Some("pending"),
        Some("all") => None,
        Some(s) if STATUSES.contains(&s) => Some(s),
        Some(_) => return Err(bad(format!("status must be all or one of: {}", STATUSES.join(", ")))),
    };
    let requests: Vec<Value> = app.db.role_requests(None, status, 200).iter().map(|q| view(&app, q)).collect();
    let pending = if status == Some("pending") { requests.len() } else { app.db.role_requests(None, Some("pending"), 200).len() };
    Ok(Json(json!({ "requests": requests, "pending": pending, "pendingDays": PENDING_DAYS })))
}

/// `POST /api/role-requests/{id}/approve` `{hours?, note?}` (admins): gives the role for the
/// hours asked for, or fewer, from now. Not your own request.
pub async fn approve(State(app): State<AppState>, Extension(by): Extension<Who>, Path(id): Path<String>, Json(v): Json<Value>) -> Res {
    only_fields(&v, &["hours", "note"])?;
    lapse_due(&app);
    crate::roles::expire_due(&app);
    let q = app.db.role_request(&id).ok_or_else(|| not_found("Request"))?;
    if by.actor.id.as_deref() == Some(q.user_id.as_str()) {
        return Err(conflict("You can't approve your own request. Ask another admin."));
    }
    let hours = if v["hours"].is_null() { None } else { Some(parse_hours(&v["hours"], q.hours, ": an approval can shorten a request, never lengthen it")?) };
    let note = parse_text(&v["note"], "note", false)?;
    let a = app
        .db
        .approve_role_request(&q.id, hours, by.actor.id.as_deref(), note.as_deref(), |s| refusal(s.user, s.role, s.request.team_id.as_deref(), s.member).map_or(Ok(()), Err))
        .map_err(|e| request_error(&app, e, Some(&q), false))?;
    let q = a.request;
    let r = app.db.custom_role(&q.role_id).ok_or_else(|| not_found("Role"))?;
    let granted = q.granted_until.unwrap_or_default();
    let hours = hours.unwrap_or(q.hours);
    let applies = if q.team_id.is_some() { r.perms().in_team().names() } else { r.perms().names() };
    let d = json!({ "request": q.id, "name": r.name, "user": q.user_id, "scope": scope(&q), "team": q.team_id, "hours": hours, "requestedHours": q.hours, "expiresAt": granted, "note": q.note });
    app.db.record(&by.event("role.request_approved").target("role", &r.id).details(d));
    let mut d = json!({
        "name": r.name, "user": q.user_id, "scope": scope(&q), "from": held(&app, a.before.0.as_deref(), a.before.1),
        "expiresAt": granted, "reason": q.reason, "request": q.id, "takenFromScim": a.taken,
    });
    match &q.team_id {
        Some(t) => {
            d["team"] = json!(t);
            d["applies"] = json!(applies);
        }
        None => d["takenFromSaml"] = json!(a.taken_saml),
    }
    app.db.record(&by.event("role.assigned").target("role", &r.id).details(d));
    Ok(Json(json!({ "request": view(&app, &q), "role": held(&app, Some(&r.id), Some(granted)), "applies": applies })))
}

/// `POST /api/role-requests/{id}/deny` `{note?}` (admins).
pub async fn deny(State(app): State<AppState>, Extension(by): Extension<Who>, Path(id): Path<String>, Json(v): Json<Value>) -> Res {
    only_fields(&v, &["note"])?;
    lapse_due(&app);
    let q = app.db.role_request(&id).ok_or_else(|| not_found("Request"))?;
    let note = parse_text(&v["note"], "note", false)?;
    let q = app
        .db
        .close_role_request(&q.id, "denied", by.actor.id.as_deref(), note.as_deref(), None)
        .ok_or_else(|| request_error(&app, RoleRequestError::NotPending(app.db.role_request(&q.id).map_or(q.status, |q| q.status)), None, false))?;
    let name = app.db.custom_role(&q.role_id).map(|r| r.name);
    app.db.record(&by.event("role.request_denied").target("role", &q.role_id).details(json!({ "request": q.id, "name": name, "user": q.user_id, "scope": scope(&q), "team": q.team_id, "note": q.note })));
    Ok(Json(view(&app, &q)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations_read_as_people_say_them() {
        assert_eq!(duration(1), "1 hour");
        assert_eq!(duration(8), "8 hours");
        assert_eq!(duration(24), "1 day");
        assert_eq!(duration(72), "3 days");
        assert_eq!(duration(30), "30 hours");
    }

    #[test]
    fn hours_are_whole_and_within_the_limit() {
        assert_eq!(parse_hours(&json!(8), 24, "").ok(), Some(8));
        assert_eq!(parse_hours(&json!(24), 24, "").ok(), Some(24));
        for bad in [json!(0), json!(25), json!(-1), json!(1.5), json!("8"), Value::Null] {
            assert!(parse_hours(&bad, 24, "").is_err(), "{bad}");
        }
    }
}
