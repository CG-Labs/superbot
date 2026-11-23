//! Custom roles (ADR 0123). An admin builds a role from a base built-in role (member or
//! read-only) and a fixed set of admin permissions (`rbac::DELEGABLE`), then gives it to
//! people across the server, or to a team's members within their team. The built-in
//! roles are presets of the same permissions and can't be changed. Everything here is
//! for admins only (`rbac::classify` leaves `/api/roles` to Admin), and audited. A SCIM
//! group can be mapped to a role (ADR 0138), and so can a native SAML provider's group
//! across the server (ADR 0160); their members hold it while in the group. A role given
//! by hand can end, and a time-bound role must (ADR 0197): it is taken away when it does.

use crate::audit::Who;
use crate::db::{CustomRole, RoleError, User};
use crate::rbac::{self, DELEGABLE, Perm, Perms, Principal, Role, TEAM_SCOPED};
use crate::users::{self, OPERATOR, need_user_key, user_view};
use crate::{ApiError, App, AppState, Res, bad, not_found};
use axum::Json;
use axum::extract::rejection::JsonRejection;
use axum::extract::{Extension, Path, State};
use axum::http::{HeaderMap, StatusCode, header};
use serde_json::{Value, json};

/// Names a custom role can't take, so a role never reads as a built-in one.
const RESERVED: [&str; 7] = ["admin", "member", "readonly", "read-only", "owner", "bot", "none"];

pub const DAY: i64 = 24 * 60 * 60_000;
/// The furthest ahead a role given by hand can end, and the most a time-bound role's limit can be.
pub const MAX_DAYS: i64 = 365;
/// How often ended roles are taken away. Until then they already grant nothing.
const SWEEP: std::time::Duration = std::time::Duration::from_secs(60);

fn conflict(msg: impl Into<String>) -> ApiError {
    ApiError(StatusCode::CONFLICT, msg.into())
}

/// The permissions a role can be built from, and which of them mean something in a team.
pub fn catalogue() -> Value {
    json!(DELEGABLE.iter().map(|p| json!({ "name": p.as_str(), "description": p.describe(), "team": TEAM_SCOPED.contains(p) })).collect::<Vec<_>>())
}

fn built_in() -> Value {
    let preset = |role: Role, name: &str| json!({ "id": role.as_str(), "name": name, "builtIn": true, "permissions": rbac::granted(Principal::User(role), Perms::NONE) });
    json!([preset(Role::Admin, "Admin"), preset(Role::Member, "Member"), preset(Role::Readonly, "Read-only")])
}

/// `{id, name}` of a custom role, or null.
pub fn summary(app: &AppState, role_id: Option<&str>) -> Value {
    match role_id.and_then(|id| app.db.custom_role(id)) {
        Some(r) => json!({ "id": r.id, "name": r.name }),
        None => Value::Null,
    }
}

/// `summary`, with when it ends if it does (ADR 0197).
pub fn held(app: &AppState, role_id: Option<&str>, ends: Option<i64>) -> Value {
    let mut v = summary(app, role_id);
    if let (Some(o), Some(t)) = (v.as_object_mut(), ends) {
        o.insert("expiresAt".into(), json!(t));
    }
    v
}

/// Takes away the roles whose end has passed, each audited as `role.expired` (ADR 0197).
/// They already granted nothing; this frees them, and says so.
pub fn expire_due(app: &App) -> usize {
    let gone = app.db.expire_custom_roles(crate::db::now());
    let by = Who::system("roles");
    for e in &gone {
        let name = app.db.custom_role(&e.role_id).map(|r| r.name);
        let mut d = json!({ "name": name, "user": e.user_id, "scope": if e.team_id.is_some() { "team" } else { "org" }, "expiresAt": e.expires_at });
        match &e.team_id {
            Some(t) => d["team"] = json!(t),
            None => d["keeps"] = json!(app.db.user(&e.user_id).map(|u| u.role)),
        }
        app.db.record(&by.event("role.expired").target("role", &e.role_id).details(d));
    }
    gone.len()
}

/// Sweeps ended roles every minute.
pub fn start(app: AppState) {
    tokio::spawn(async move {
        loop {
            expire_due(&app);
            tokio::time::sleep(SWEEP).await;
        }
    });
}

fn view(app: &AppState, r: &CustomRole) -> Value {
    let (users, teams) = app.db.custom_role_holders(&r.id);
    let perms = r.perms();
    // Names saved by another version of SuperBot, which this one doesn't know: shown, never granted.
    let unknown: Vec<&String> = r.permissions.iter().filter(|p| Perm::delegable(p).is_none()).collect();
    json!({
        "id": r.id, "name": r.name, "description": r.description, "base": r.base, "builtIn": false,
        "permissions": perms.names(), "unknown": unknown, "maxDays": r.max_days,
        "effective": rbac::granted(Principal::User(r.base), perms),
        "users": users.len(), "teamMembers": teams.len(), "scimMappings": app.db.scim_role_mappings_of_role(&r.id).len(),
        "samlMappings": app.db.saml_role_mappings_of_role(&r.id).len(), "scimRoleGroups": app.db.scim_role_groups_of_role(&r.id).len(),
        "createdAt": r.created_at, "createdBy": r.created_by, "updatedAt": r.updated_at,
    })
}

fn person(u: &User) -> Value {
    json!({ "id": u.id, "name": u.name, "email": u.email })
}

/// The SCIM mapping (ADR 0138) or role group (ADR 0180) that gave `user_id` their role
/// in `scope`, if one did.
fn scim_source(app: &AppState, user_id: &str, scope: &str) -> Option<String> {
    let mapped = app.db.scim_role_grants_of_user(user_id).into_iter().find(|g| g.scope == scope).map(|g| g.mapping_id);
    mapped.or_else(|| (scope == "org").then(|| app.db.scim_role_group_grant_of_user(user_id)).flatten().map(|g| g.group_id))
}

/// The SAML mapping that gave `user_id` their role across the server, if one did (ADR 0160).
fn saml_source(app: &AppState, user_id: &str) -> Option<String> {
    app.db.saml_role_grant_of_user(user_id).map(|g| g.mapping_id)
}

fn need_role(app: &AppState, key: &str) -> Res<CustomRole> {
    app.db.find_custom_role(key).ok_or_else(|| not_found("Role"))
}

fn role_error(e: RoleError) -> ApiError {
    match e {
        RoleError::NameTaken => conflict("A role with that name exists already."),
        RoleError::NotFound => not_found("Role"),
        RoleError::InUse(n) => conflict(format!("{n} {} still {} this role. Take it away from them first.", if n == 1 { "person" } else { "people" }, if n == 1 { "has" } else { "have" })),
        RoleError::Mapped(n) => conflict(format!("{n} {} to this role. Remove {} first.", if n == 1 { "SCIM group or SAML group is mapped" } else { "SCIM groups or SAML groups are mapped" }, if n == 1 { "that mapping" } else { "those mappings" })),
        RoleError::Reaches { via, mapping, scope, perms } => conflict(format!(
            "A {} group is mapped to this role {}, where {} would act on admins. Remove mapping {mapping} first, or leave {} out.",
            if via == "saml" { "SAML" } else { "SCIM" },
            if scope == "org" { "across the server" } else { "in its team" },
            perms.join(" and "),
            if perms.len() == 1 { "it" } else { "them" },
        )),
        RoleError::Standing { held, mapped } => {
            let mut why = Vec::new();
            if held > 0 {
                why.push(format!("{held} {} it with no end or a later one (give {} an earlier end, or take it away)", if held == 1 { "holds" } else { "hold" }, if held == 1 { "them" } else { "each" }));
            }
            if mapped > 0 {
                why.push(format!("{mapped} SCIM or SAML {} mapped to it (remove {})", if mapped == 1 { "group is" } else { "groups are" }, if mapped == 1 { "that mapping" } else { "those mappings" }));
            }
            conflict(format!("A time-bound role is only ever held until an end within its limit, and {}.", why.join(", and ")))
        }
        RoleError::Db(e) => ApiError(StatusCode::INTERNAL_SERVER_ERROR, e),
    }
}

/// Why a time-bound role can't go to `who` (ADR 0197): they would hold it with no end.
pub fn standing_refused(r: &CustomRole, who: &str) -> ApiError {
    conflict(format!("{} is time-bound: it's given only by hand, with an end, so {who} can't be given it. Give it by hand, or pick a role that isn't time-bound.", r.name))
}

fn parse_max_days(v: &Value) -> Res<Option<i64>> {
    match v {
        Value::Null => Ok(None),
        Value::Number(n) => n.as_i64().filter(|d| (1..=MAX_DAYS).contains(d)).map(Some).ok_or_else(|| bad(format!("maxDays must be 1 to {MAX_DAYS}, or null"))),
        _ => Err(bad(format!("maxDays must be a whole number of days, 1 to {MAX_DAYS}, or null for no limit"))),
    }
}

fn time(ms: i64) -> String {
    chrono::DateTime::from_timestamp_millis(ms).map(|t| t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)).unwrap_or_default()
}

/// A `PUT` giving a role: `{expiresAt?, reason?}`, or no body at all (ADR 0197).
struct Giving {
    until: Option<i64>,
    reason: Option<String>,
}

/// The body of a `PUT` that may have none: no body reads as `{}`, anything else must be JSON.
fn optional_body(headers: &HeaderMap, body: Result<Json<Value>, JsonRejection>) -> Res<Value> {
    let empty = match headers.get(header::CONTENT_LENGTH) {
        Some(n) => n.to_str().is_ok_and(|n| n.trim() == "0"),
        None => !headers.contains_key(header::TRANSFER_ENCODING),
    };
    match body {
        Ok(Json(v)) => Ok(v),
        Err(_) if empty => Ok(json!({})),
        Err(_) => Err(bad("Send a JSON object, or nothing.")),
    }
}

fn parse_giving(v: &Value, r: &CustomRole) -> Res<Giving> {
    only_fields(v, &["expiresAt", "reason"])?;
    let at = crate::db::now();
    let until = match &v["expiresAt"] {
        Value::Null => None,
        Value::Number(n) => Some(n.as_i64().filter(|t| *t > at).ok_or_else(|| bad("expiresAt must be a time ahead, in milliseconds since 1970"))?),
        _ => return Err(bad("expiresAt must be a time in milliseconds since 1970, or null for no end")),
    };
    let limit = r.max_days.unwrap_or(MAX_DAYS);
    match until {
        None if r.max_days.is_some() => return Err(bad(format!("{} is time-bound: give it with expiresAt, at most {limit} days ahead.", r.name))),
        Some(t) if t > at + limit * DAY => {
            let what = if r.max_days.is_some() { format!("{} can be given for at most {limit} days", r.name) } else { format!("A role can be given for at most {limit} days, or with no end") };
            return Err(bad(format!("{what}: expiresAt must be by {}.", time(at + limit * DAY))));
        }
        _ => {}
    }
    let reason = match &v["reason"] {
        Value::Null => None,
        Value::String(s) if s.trim().chars().count() <= 500 && !s.chars().any(|c| c.is_control() && c != '\n') => Some(s.trim().to_string()).filter(|s| !s.is_empty()),
        _ => return Err(bad("reason must be text, at most 500 characters")),
    };
    Ok(Giving { until, reason })
}

/// The role went, or was made time-bound with a shorter limit, between the check and the write.
fn gone_or_changed(app: &AppState, role_id: &str) -> ApiError {
    match app.db.custom_role(role_id) {
        Some(_) => conflict("The role changed meanwhile. Reload it and try again."),
        None => not_found("Role"),
    }
}

fn parse_name(v: &Value) -> Res<String> {
    let name = v.as_str().map(str::trim).unwrap_or_default();
    if name.is_empty() || name.chars().count() > 60 || name.chars().any(char::is_control) {
        return Err(bad("name must be 1 to 60 characters"));
    }
    if RESERVED.iter().any(|r| r.eq_ignore_ascii_case(name)) {
        return Err(bad(format!("\"{name}\" is a built-in role's name. Pick another.")));
    }
    Ok(name.to_string())
}

fn parse_description(v: &Value) -> Res<String> {
    match v {
        Value::Null => Ok(String::new()),
        Value::String(s) if s.trim().chars().count() <= 500 && !s.chars().any(|c| c.is_control() && c != '\n') => Ok(s.trim().to_string()),
        _ => Err(bad("description must be text, at most 500 characters")),
    }
}

fn parse_base(v: &Value) -> Res<Role> {
    match v.as_str().and_then(Role::parse) {
        Some(Role::Admin) => Err(bad("A custom role can't be based on admin: give the admin role itself instead.")),
        Some(r) => Ok(r),
        None => Err(bad("base must be member or readonly")),
    }
}

/// Deny by default: every name must be one of the fixed delegable permissions.
fn parse_perms(v: &Value) -> Res<Vec<&'static str>> {
    let allowed = || DELEGABLE.iter().map(|p| p.as_str()).collect::<Vec<_>>().join(", ");
    let list = v.as_array().ok_or_else(|| bad(format!("permissions must be a list of: {}", allowed())))?;
    let mut perms = Perms::NONE;
    for p in list {
        let name = p.as_str().unwrap_or_default();
        let perm = Perm::delegable(name).ok_or_else(|| bad(format!("Unknown permission \"{name}\". A custom role can hold: {}.", allowed())))?;
        perms = perms.with(perm);
    }
    Ok(perms.names())
}

fn only_fields(v: &Value, fields: &[&str]) -> Res<()> {
    let body = v.as_object().ok_or_else(|| bad("Send a JSON object."))?;
    match body.keys().find(|k| !fields.contains(&k.as_str())) {
        Some(k) => Err(bad(format!("Unknown field \"{k}\": send {}.", fields.join(", ")))),
        None => Ok(()),
    }
}

/// `GET /api/roles`: the permissions roles are built from, the built-in roles as presets
/// of them, and every custom role with how many people hold it.
pub async fn list(State(app): State<AppState>) -> Json<Value> {
    expire_due(&app);
    let roles: Vec<Value> = app.db.custom_roles().iter().map(|r| view(&app, r)).collect();
    Json(json!({ "permissions": catalogue(), "builtIn": built_in(), "roles": roles }))
}

/// `POST /api/roles` `{name, description?, base?: "member" | "readonly", permissions, maxDays?}`.
/// With `maxDays` it is time-bound (ADR 0197).
pub async fn create(State(app): State<AppState>, Extension(by): Extension<Who>, Json(v): Json<Value>) -> Res<(StatusCode, Json<Value>)> {
    only_fields(&v, &["name", "description", "base", "permissions", "maxDays"])?;
    let name = parse_name(&v["name"])?;
    let description = parse_description(&v["description"])?;
    let base = if v["base"].is_null() { Role::Member } else { parse_base(&v["base"])? };
    let perms = parse_perms(&v["permissions"])?;
    let max_days = parse_max_days(&v["maxDays"])?;
    let mut r = app.db.create_custom_role(&name, &description, base, &perms, by.actor.id.as_deref()).map_err(role_error)?;
    // Nobody holds a role just made, so this can't be refused.
    if max_days.is_some() {
        app.db.update_custom_role(&r.id, None, None, None, None, Some(max_days)).map_err(role_error)?;
        r = need_role(&app, &r.id)?;
    }
    app.db.record(&by.event("role.created").target("role", &r.id).details(json!({ "name": r.name, "base": r.base, "permissions": perms, "maxDays": r.max_days })));
    Ok((StatusCode::CREATED, Json(view(&app, &r))))
}

/// `GET /api/roles/{id}` (id or name): the role and who holds it.
pub async fn get(State(app): State<AppState>, Path(key): Path<String>) -> Res {
    expire_due(&app);
    let r = need_role(&app, &key)?;
    let (users, teams) = app.db.custom_role_holders(&r.id);
    let ends = app.db.custom_role_ends(&r.id);
    let mut v = view(&app, &r);
    v["holders"] = json!({
        "users": users.iter().filter_map(|id| app.db.user(id)).map(|u| {
            let mut p = person(&u);
            p["scimMapping"] = json!(scim_source(&app, &u.id, "org"));
            p["samlMapping"] = json!(saml_source(&app, &u.id));
            p["expiresAt"] = json!(ends.get(&(u.id.clone(), None)));
            p
        }).collect::<Vec<_>>(),
        "teams": teams.iter().filter_map(|(t, u)| Some(json!({
            "team": { "id": t, "name": app.db.team(t)?.name }, "user": person(&app.db.user(u)?), "scimMapping": scim_source(&app, u, "team"),
            "expiresAt": ends.get(&(u.clone(), Some(t.clone()))),
        }))).collect::<Vec<_>>(),
    });
    Ok(Json(v))
}

/// `PATCH /api/roles/{id}` `{name?, description?, base?, permissions?, maxDays?}`. A new base
/// applies at once to everyone who holds the role across the server, handled as any
/// other change of role is (`users::update_user`). `maxDays` makes it time-bound, or with
/// null not (ADR 0197).
pub async fn update(State(app): State<AppState>, Extension(by): Extension<Who>, Path(key): Path<String>, Json(v): Json<Value>) -> Res {
    only_fields(&v, &["name", "description", "base", "permissions", "maxDays"])?;
    expire_due(&app);
    let before = need_role(&app, &key)?;
    let name = (!v["name"].is_null()).then(|| parse_name(&v["name"])).transpose()?;
    let description = v.get("description").map(parse_description).transpose()?;
    let base = (!v["base"].is_null()).then(|| parse_base(&v["base"])).transpose()?.filter(|b| *b != before.base);
    let perms = (!v["permissions"].is_null()).then(|| parse_perms(&v["permissions"])).transpose()?;
    let max_days = v.get("maxDays").map(parse_max_days).transpose()?.filter(|m| *m != before.max_days);
    let moved = app.db.update_custom_role(&before.id, name.as_deref(), description.as_deref(), base, perms.as_deref(), max_days).map_err(role_error)?;
    let after = need_role(&app, &before.id)?;
    let mut changes = serde_json::Map::new();
    if before.name != after.name {
        changes.insert("name".into(), json!({ "from": before.name, "to": after.name }));
    }
    if before.description != after.description {
        changes.insert("description".into(), json!({ "from": before.description, "to": after.description }));
    }
    if before.base != after.base {
        changes.insert("base".into(), json!({ "from": before.base, "to": after.base }));
    }
    if before.perms() != after.perms() {
        changes.insert("permissions".into(), json!({ "from": before.perms().names(), "to": after.perms().names() }));
    }
    if before.max_days != after.max_days {
        changes.insert("maxDays".into(), json!({ "from": before.max_days, "to": after.max_days }));
    }
    if !changes.is_empty() {
        app.db.record(&by.event("role.updated").target("role", &after.id).details(json!({ "name": after.name, "changes": changes, "usersMoved": moved.len() })));
    }
    for id in &moved {
        app.db.record(&by.event("user.role_changed").target("user", id).details(json!({ "from": before.base, "to": after.base, "role": { "id": after.id, "name": after.name }, "reason": "role_updated" })));
        users::lost_access(&app, &by, id, crate::machines::offboard::ACCESS_LOST).await;
    }
    Ok(Json(view(&app, &after)))
}

/// `DELETE /api/roles/{id}`: only once nobody holds it.
pub async fn delete(State(app): State<AppState>, Extension(by): Extension<Who>, Path(key): Path<String>) -> Res {
    expire_due(&app);
    let r = need_role(&app, &key)?;
    app.db.delete_custom_role(&r.id).map_err(role_error)?;
    app.db.record(&by.event("role.deleted").target("role", &r.id).details(json!({ "name": r.name, "base": r.base, "permissions": r.perms().names() })));
    Ok(Json(json!({ "ok": true })))
}

/// `PUT /api/roles/{id}/users/{user}` `{expiresAt?, reason?}`: gives the role across the
/// server, until `expiresAt` or with no end (ADR 0197). Its base becomes their built-in
/// role, replacing admin if they were one, and stays it when the role ends. Not the owner
/// account, which stays an admin, and not yourself. Sent again, it moves the end.
pub async fn assign(State(app): State<AppState>, Extension(by): Extension<Who>, Path((key, user)): Path<(String, String)>, headers: HeaderMap, body: Result<Json<Value>, JsonRejection>) -> Res {
    expire_due(&app);
    let r = need_role(&app, &key)?;
    let giving = parse_giving(&optional_body(&headers, body)?, &r)?;
    let before = need_user_key(&app, &user)?;
    if before.id == OPERATOR {
        return Err(conflict("The owner (break-glass) account stays an admin."));
    }
    if by.actor.id.as_deref() == Some(before.id.as_str()) {
        return Err(conflict("You can't change your own role. Ask another admin."));
    }
    // Written even when they hold it already: SCIM may take it away between the read and
    // now. What to audit comes from what they held as it was written.
    let g = app.db.give_user_custom_role_until(&before.id, &r.id, giving.until).ok_or_else(|| gone_or_changed(&app, &r.id))?;
    let (had, was, ended) = (g.before.0, g.before.1.unwrap_or(before.role), g.before.2);
    if had.as_deref() != Some(r.id.as_str()) || ended != giving.until || g.taken.is_some() || g.taken_saml.is_some() {
        let from = held(&app, had.as_deref(), ended);
        let d = json!({ "name": r.name, "user": before.id, "scope": "org", "from": from, "expiresAt": giving.until, "reason": giving.reason, "takenFromScim": g.taken, "takenFromSaml": g.taken_saml });
        app.db.record(&by.event("role.assigned").target("role", &r.id).details(d));
    }
    let after = need_user_key(&app, &before.id)?;
    if was != after.role {
        app.db.record(&by.event("user.role_changed").target("user", &after.id).details(json!({ "from": was, "to": after.role, "role": { "id": r.id, "name": r.name } })));
        users::lost_access(&app, &by, &after.id, crate::machines::offboard::ACCESS_LOST).await;
    }
    Ok(Json(json!({ "user": user_view(&after), "role": held(&app, after.role_id.as_deref(), after.role_expires_at) })))
}

/// `DELETE /api/roles/{id}/users/{user}`: takes the role away. They keep its base as
/// their built-in role.
pub async fn unassign(State(app): State<AppState>, Extension(by): Extension<Who>, Path((key, user)): Path<(String, String)>) -> Res {
    expire_due(&app);
    let r = need_role(&app, &key)?;
    let u = need_user_key(&app, &user)?;
    let (scim, saml) = (scim_source(&app, &u.id, "org"), saml_source(&app, &u.id));
    if !app.db.clear_user_custom_role(&u.id, &r.id) {
        return Err(ApiError(StatusCode::NOT_FOUND, "They don't have this role.".into()));
    }
    app.db.record(&by.event("role.unassigned").target("role", &r.id).details(json!({ "name": r.name, "user": u.id, "scope": "org", "keeps": u.role, "scimMapping": scim, "samlMapping": saml })));
    let after = need_user_key(&app, &u.id)?;
    Ok(Json(json!({ "user": user_view(&after), "role": Value::Null })))
}

fn team_member(app: &AppState, team: &str, user: &str) -> Res<(crate::db::Team, User, crate::db::TeamMember)> {
    let t = app.db.team(team).ok_or_else(|| not_found("Team"))?;
    let u = need_user_key(app, user)?;
    let m = app.db.team_member(&u.id).filter(|m| m.team_id == t.id).ok_or_else(|| not_found("Team member"))?;
    Ok((t, u, m))
}

/// `PUT /api/roles/{id}/teams/{team}/users/{user}` `{expiresAt?, reason?}`: gives the role to
/// a team's member within that team, until `expiresAt` or with no end (ADR 0197). Only its
/// team permissions apply there (`rbac::TEAM_SCOPED`), and only while they stay on it;
/// their role across the server doesn't change.
pub async fn assign_in_team(State(app): State<AppState>, Extension(by): Extension<Who>, Path((key, team, user)): Path<(String, String, String)>, headers: HeaderMap, body: Result<Json<Value>, JsonRejection>) -> Res {
    expire_due(&app);
    let r = need_role(&app, &key)?;
    let giving = parse_giving(&optional_body(&headers, body)?, &r)?;
    let (t, u, _) = team_member(&app, &team, &user)?;
    if u.role == Role::Readonly {
        return Err(conflict("They're read-only, so they change nothing, in a team too. Make them a member first."));
    }
    let g = app.db.give_team_custom_role_until(&t.id, &u.id, &r.id, giving.until).ok_or_else(|| match app.db.team_member(&u.id).filter(|m| m.team_id == t.id) {
        Some(_) => gone_or_changed(&app, &r.id),
        None => not_found("Team member"),
    })?;
    let (had, ended) = g.before;
    if had.as_deref() != Some(r.id.as_str()) || ended != giving.until || g.taken.is_some() {
        let from = held(&app, had.as_deref(), ended);
        let d = json!({ "name": r.name, "user": u.id, "scope": "team", "team": t.id, "from": from, "applies": r.perms().in_team().names(), "expiresAt": giving.until, "reason": giving.reason, "takenFromScim": g.taken });
        app.db.record(&by.event("role.assigned").target("role", &r.id).details(d));
    }
    Ok(Json(json!({ "team": { "id": t.id, "name": t.name }, "user": person(&u), "role": held(&app, Some(&r.id), giving.until), "applies": r.perms().in_team().names() })))
}

/// `DELETE /api/roles/{id}/teams/{team}/users/{user}`.
pub async fn unassign_in_team(State(app): State<AppState>, Extension(by): Extension<Who>, Path((key, team, user)): Path<(String, String, String)>) -> Res {
    expire_due(&app);
    let r = need_role(&app, &key)?;
    let (t, u, m) = team_member(&app, &team, &user)?;
    let scim = scim_source(&app, &u.id, "team");
    if m.role_id.as_deref() != Some(r.id.as_str()) || !app.db.set_team_custom_role(&t.id, &u.id, None) {
        return Err(ApiError(StatusCode::NOT_FOUND, "They don't have this role in the team.".into()));
    }
    app.db.record(&by.event("role.unassigned").target("role", &r.id).details(json!({ "name": r.name, "user": u.id, "scope": "team", "team": t.id, "scimMapping": scim })));
    Ok(Json(json!({ "team": { "id": t.id, "name": t.name }, "user": person(&u), "role": Value::Null })))
}
