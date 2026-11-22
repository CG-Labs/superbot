//! Service accounts (ADR 0143): non-human callers for scripts and integrations. Each is a
//! `users` row of kind `service` holding a built-in or custom role (never admin), across
//! the server or within one team, with no email, password, identity or session, so it
//! can't sign in. It acts only through its API tokens: random, kept as hashes, shown once,
//! scoped, always expiring, rotatable and revocable. Whatever its role says, a request
//! never gets more than its owner (the person who made it, or an admin's pick) holds now.
//! Admins manage every service account; someone with `users.manage` only those they own.

use crate::audit::{Actor, ActorKind, Outcome, Source, Who};
use crate::db::{CustomRole, NewServiceToken, ServiceAccount, ServiceAccountPatch, ServiceToken, TeamMember, User};
use crate::rbac::{Perm, Perms, Principal, Role, Scope, PERMS};
use crate::users::{self, Caller, ServiceCaller};
use crate::{bad, not_found, ApiError, AppState, Res};
use axum::extract::{Extension, Path, State};
use axum::http::{header, HeaderValue, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::{json, Map, Value};

pub const TOKEN_PREFIX: &str = "sbsa_";
/// How a service account's request authenticated, in the audit log's `authMethod`.
pub const METHOD: &str = "service_token";
pub const DEFAULT_DAYS: i64 = 90;
pub const MAX_DAYS: i64 = 365;
/// How long a rotated token may keep working, so callers can switch over.
pub const MAX_KEEP_MINUTES: i64 = 24 * 60;
const DAY: i64 = 24 * 60 * 60_000;

// Authentication.

/// The caller a service account's token makes, or why it makes none. Read on every
/// request, so a revoked token, a disabled account, or an owner who lost access stops
/// working at once.
pub fn authenticate(app: &AppState, token: &str, source: &Source, at: i64) -> Result<Caller, &'static str> {
    let t = app.db.service_token_by_hash(&users::hash(token)).ok_or("unknown_token")?;
    let id = t.id.clone();
    let c = caller(app, t, at)?;
    app.db.touch_service_token(&id, at, source.ip.as_deref());
    Ok(c)
}

/// The caller token `id` makes now, if it still makes one: for what outlives the request
/// that opened it (the event stream), so it ends as soon as the token would be refused.
pub fn recheck(app: &AppState, id: &str, at: i64) -> Option<Caller> {
    caller(app, app.db.service_token(id)?, at).ok()
}

fn caller(app: &AppState, t: ServiceToken, at: i64) -> Result<Caller, &'static str> {
    if t.revoked_at.is_some() {
        return Err("revoked");
    }
    if t.expires_at <= at {
        return Err("expired");
    }
    let sa = app.db.service_account(&t.account_id).filter(|s| s.deleted_at.is_none()).ok_or("account_deleted")?;
    if !sa.user.active() {
        return Err("account_disabled");
    }
    // The database refuses an admin service account; this is the second lock.
    if sa.user.role == Role::Admin {
        return Err("admin_refused");
    }
    let owner = live_owner(app, &sa.owner_id).ok_or("owner_inactive")?;
    let scope = token_scope(&t).and(ceiling(app, &owner, sa.team_id.as_deref()));
    let mut c = Caller::person(&app.db, sa.user, None, METHOD);
    c.service = Some(ServiceCaller { token: t.id, owner: owner.id, scope });
    Ok(c)
}

/// The audit actor for a service account's request: the account, by id and name, with its
/// role, `service_token` as the method, and the token's id where a session's would be.
pub fn actor(u: &User, s: Option<&ServiceCaller>) -> Actor {
    Actor {
        kind: ActorKind::User,
        id: Some(u.id.clone()),
        name: Some(u.name.clone()),
        role: Some(u.role.as_str().into()),
        method: Some(METHOD.into()),
        session: s.map(|s| s.token.clone()),
        ..Default::default()
    }
}

/// What a service account may not do whatever its role: the routes about a person's own
/// sign-in, account, machine and plan, managing service accounts, owning Bots, screens,
/// and deciding approvals, which need a person.
pub fn person_only(method: &Method, path: &str) -> Option<&'static str> {
    let s: Vec<&str> = path.strip_prefix("/api/")?.split('/').collect();
    let m = if method == Method::HEAD { "GET" } else { method.as_str() };
    Some(match (m, s.as_slice()) {
        ("GET", ["auth", "me"]) => return None,
        (_, ["auth", ..]) => "A service account has no sign-in, session or second factor.",
        (_, ["me", ..] | ["machine", ..] | ["billing", ..] | ["team", "leave"] | ["team", "billing", ..]) => "This is about a person's own account, which a service account doesn't have.",
        (_, ["service-accounts", ..]) => "A service account can't manage service accounts.",
        ("POST", ["bots"]) => "A service account can't own Bots.",
        (_, ["bots", _, "screen"]) => "Screens are for people.",
        (_, ["approvals", _, "approve" | "deny"]) => "Deciding an approval needs a person.",
        _ => return None,
    })
}

/// The member a team's service account is in its team, so team routes see it as one (a
/// plain member with its team role), though it holds no seat and isn't on the team's list.
pub fn team_seat(app: &AppState, u: &User) -> Option<TeamMember> {
    if !u.service {
        return None;
    }
    let sa = app.db.service_account(&u.id).filter(|s| s.deleted_at.is_none())?;
    let team = app.db.team(sa.team_id.as_deref()?)?;
    Some(TeamMember { user_id: u.id.clone(), team_id: team.id, role: crate::teams::MEMBER.into(), joined_at: u.created_at, added_by: sa.created_by, role_id: sa.team_role_id })
}

/// `serviceAccount` in `GET /api/auth/me`: the token, its owner, and what it may use now.
pub fn whoami(app: &AppState, c: &Caller, s: &ServiceCaller) -> Value {
    let team = c.user.as_ref().and_then(|u| app.db.service_account(&u.id)).and_then(|sa| sa.team_id).and_then(|t| app.db.team(&t));
    json!({
        "token": s.token, "owner": app.db.user(&s.owner).map(|u| person(&u)), "scope": s.scope.names(),
        "team": team.map(|t| json!({ "id": t.id, "name": t.name })),
    })
}

// What a service account holds, and the most it may.

/// The owner, if they can still lend their permissions: an active person, not erased.
fn live_owner(app: &AppState, id: &str) -> Option<User> {
    app.db.user(id).filter(|u| u.active() && !u.service && u.erased_at.is_none())
}

/// Everything `owner` holds: across the server, and in `team` when a service account acts
/// there. A service account's requests never get more.
pub fn ceiling(app: &AppState, owner: &User, team: Option<&str>) -> Scope {
    let all = Scope::of(Principal::User(owner.role), app.db.user_perms(owner));
    all.or(team.map_or(Scope::NONE, |t| Scope::team(crate::teams::perms_in(app, &owner.id, t))))
}

/// What a token's scopes allow: all the account holds when it has none. Always `account`,
/// so any token can ask who it is (its other routes are a person's, see `person_only`).
fn token_scope(t: &ServiceToken) -> Scope {
    match &t.scopes {
        None => Scope::all(),
        Some(names) => names.iter().filter_map(|n| Perm::parse(n)).filter(|p| *p != Perm::Admin).fold(Scope::NONE.with(Perm::Account), Scope::with),
    }
}

/// A service account's roles, as it would hold them.
struct Roles {
    role: Role,
    /// Across the server when there's no team, else within it.
    custom: Option<CustomRole>,
    team: Option<crate::db::Team>,
}

impl Roles {
    fn of(app: &AppState, sa: &ServiceAccount) -> Roles {
        let custom = sa.user.role_id.as_deref().or(sa.team_role_id.as_deref()).and_then(|id| app.db.custom_role(id));
        Roles { role: sa.user.role, custom, team: sa.team_id.as_deref().and_then(|t| app.db.team(t)) }
    }

    fn org_role(&self) -> Option<&CustomRole> {
        self.custom.as_ref().filter(|_| self.team.is_none())
    }

    fn team_role(&self) -> Option<&CustomRole> {
        self.custom.as_ref().filter(|_| self.team.is_some())
    }

    /// Across the server: its built-in role, and its custom role's permissions there.
    fn org(&self) -> Scope {
        Scope::of(Principal::User(self.role), self.org_role().map_or(Perms::NONE, CustomRole::perms))
    }

    /// In its team: its team role's team permissions. None while read-only, as for people.
    fn in_team(&self) -> Scope {
        match self.team_role() {
            Some(r) if self.role != Role::Readonly => Scope::team(r.perms()),
            _ => Scope::NONE,
        }
    }

    fn holds(&self) -> Scope {
        self.org().or(self.in_team())
    }
}

// Parsing requests.

fn only_fields(v: &Value, fields: &[&str]) -> Res<()> {
    let body = v.as_object().ok_or_else(|| bad("Send a JSON object."))?;
    match body.keys().find(|k| !fields.contains(&k.as_str())) {
        Some(k) => Err(bad(format!("Unknown field \"{k}\": send {}.", fields.join(", ")))),
        None => Ok(()),
    }
}

fn parse_name(v: &Value, what: &str, max: usize) -> Res<String> {
    let name = v.as_str().map(str::trim).unwrap_or_default();
    if name.is_empty() || name.chars().count() > max || name.chars().any(char::is_control) {
        return Err(bad(format!("{what} must be 1 to {max} characters")));
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

/// `member`, `readonly`, or a custom role's id or name. Never admin.
fn parse_role(app: &AppState, v: &Value) -> Res<(Role, Option<CustomRole>)> {
    let key = v.as_str().map(str::trim).unwrap_or_default();
    match Role::parse(key) {
        Some(Role::Admin) => Err(bad("A service account can never be an admin. Give it member, readonly, or a custom role.")),
        Some(r) => Ok((r, None)),
        None => match app.db.find_custom_role(key).filter(|_| !key.is_empty()) {
            Some(r) => Ok((r.base, Some(r))),
            None => Err(bad("role must be member, readonly, or a custom role's id or name")),
        },
    }
}

fn parse_team(app: &AppState, v: &Value) -> Res<Option<crate::db::Team>> {
    match v {
        Value::Null => Ok(None),
        Value::String(id) => app.db.team(id.trim()).map(Some).ok_or_else(|| not_found("Team")),
        _ => Err(bad("team must be a team's id, or null")),
    }
}

fn parse_days(v: &Value) -> Res<i64> {
    match v {
        Value::Null => Ok(DEFAULT_DAYS),
        Value::Number(n) => n.as_i64().filter(|d| (1..=MAX_DAYS).contains(d)).ok_or_else(|| bad(format!("expiresInDays must be 1 to {MAX_DAYS}"))),
        _ => Err(bad(format!("expiresInDays must be a whole number of days, 1 to {MAX_DAYS}"))),
    }
}

/// A token's scopes: none (all the account holds), or permission names it holds.
fn parse_scopes(v: &Value, holds: Scope) -> Res<Option<Vec<&'static str>>> {
    let list = match v {
        Value::Null => return Ok(None),
        Value::Array(list) if !list.is_empty() => list,
        _ => return Err(bad("scopes must be a list of permission names, or left out for all the account holds")),
    };
    let mut scope = Scope::NONE;
    for s in list {
        let name = s.as_str().unwrap_or_default();
        let perm = Perm::parse(name).filter(|p| *p != Perm::Admin).ok_or_else(|| bad(format!("Unknown scope \"{name}\". Use permission names: {}.", scope_names().join(", "))))?;
        if !holds.has(perm) {
            return Err(bad(format!("This service account doesn't hold {name}, so a token can't have it.")));
        }
        scope = scope.with(perm);
    }
    Ok(Some(scope.names()))
}

/// Every permission a token can be scoped to: all but admin.
fn scope_names() -> Vec<&'static str> {
    PERMS.iter().filter(|p| **p != Perm::Admin).map(|p| p.as_str()).collect()
}

// Who may manage which.

fn forbidden(msg: impl Into<String>) -> ApiError {
    ApiError(StatusCode::FORBIDDEN, msg.into())
}

fn conflict(msg: impl Into<String>) -> ApiError {
    ApiError(StatusCode::CONFLICT, msg.into())
}

fn refuse(app: &AppState, by: &Who, limit: &str, target: Option<&str>, extra: Value, msg: String) -> ApiError {
    let mut d = json!({ "reason": "delegate_limit", "limit": limit });
    if let (Some(o), Value::Object(e)) = (d.as_object_mut(), extra) {
        o.extend(e);
    }
    let mut e = by.event("access.denied").outcome(Outcome::Denied).details(d);
    if let Some(t) = target {
        e = e.target("service_account", t);
    }
    app.db.record(&e);
    forbidden(msg)
}

/// The person calling. Service accounts never get here (`person_only`).
fn caller_person(c: &Caller) -> Res<User> {
    c.user.clone().filter(|u| !u.service).ok_or_else(|| conflict("Sign in as a person to manage service accounts."))
}

/// The live service account `key` names, if the caller may manage it: admins any, anyone
/// else only those they own.
fn need_account(app: &AppState, c: &Caller, by: &Who, key: &str) -> Res<ServiceAccount> {
    let sa = app.db.service_account(key).filter(|s| s.deleted_at.is_none()).ok_or_else(|| not_found("Service account"))?;
    if c.admin() || c.user.as_ref().is_some_and(|u| u.id == sa.owner_id) {
        return Ok(sa);
    }
    Err(refuse(app, by, "service_account_owner", Some(&sa.user.id), json!({}), "Only an admin, or the person who owns it, can manage a service account.".into()))
}

/// Refuses roles that would give a service account more than `owner` holds.
fn within(app: &AppState, by: &Who, owner: &User, roles: &Roles, target: Option<&str>) -> Res<()> {
    let cap = ceiling(app, owner, roles.team.as_ref().map(|t| t.id.as_str()));
    let missing: Vec<&str> = roles.holds().names().into_iter().filter(|n| Perm::parse(n).is_some_and(|p| !cap.has(p))).collect();
    if missing.is_empty() {
        return Ok(());
    }
    let msg = format!("A service account can't hold more than its owner. {} doesn't hold: {}.", owner.name, missing.join(", "));
    Err(refuse(app, by, "service_account_escalation", target, json!({ "owner": owner.id, "missing": missing }), msg))
}

// Views.

fn person(u: &User) -> Value {
    json!({ "id": u.id, "name": u.name, "email": u.email })
}

fn role_summary(r: Option<&CustomRole>) -> Value {
    r.map_or(Value::Null, |r| json!({ "id": r.id, "name": r.name }))
}

fn token_state(t: &ServiceToken, at: i64) -> &'static str {
    match (t.revoked_at, t.expires_at <= at) {
        (Some(_), _) => "revoked",
        (None, true) => "expired",
        (None, false) => "active",
    }
}

fn token_view(t: &ServiceToken, at: i64) -> Value {
    let mut v = serde_json::to_value(t).unwrap_or_default();
    v["state"] = json!(token_state(t, at));
    v["preview"] = json!(format!("{TOKEN_PREFIX}…{}", t.hint));
    v
}

fn view(app: &AppState, sa: &ServiceAccount) -> Value {
    let roles = Roles::of(app, sa);
    let owner = app.db.user(&sa.owner_id);
    let live = owner.as_ref().filter(|o| live_owner(app, &o.id).is_some());
    let at = crate::db::now();
    let tokens = app.db.service_tokens(&sa.user.id);
    let effective = live.map_or(Scope::NONE, |o| roles.holds().and(ceiling(app, o, roles.team.as_ref().map(|t| t.id.as_str()))));
    json!({
        "id": sa.user.id, "name": sa.user.name, "description": sa.description, "role": sa.user.role, "status": sa.user.status,
        "customRole": role_summary(roles.org_role()), "team": roles.team.as_ref().map(|t| json!({ "id": t.id, "name": t.name })),
        "teamRole": role_summary(roles.team_role()),
        "owner": owner.as_ref().map(person), "ownerActive": live.is_some(),
        "permissions": roles.org().names(), "teamPermissions": roles.in_team().names(),
        "effective": if sa.user.active() { effective.names() } else { Vec::new() },
        "tokens": tokens.iter().filter(|t| token_state(t, at) == "active").count(),
        "lastUsedAt": tokens.iter().filter_map(|t| t.last_used_at).max(),
        "createdAt": sa.user.created_at, "createdBy": sa.created_by, "updatedAt": sa.user.updated_at,
    })
}

fn no_store(code: StatusCode, v: Value) -> Response {
    let mut res = (code, Json(v)).into_response();
    res.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    res
}

// The admin API.

/// `GET /api/service-accounts`: every live one for admins; for anyone else, the ones they
/// own. With what a token can be scoped to, and how long tokens may last.
pub async fn list(State(app): State<AppState>, Extension(c): Extension<Caller>) -> Json<Value> {
    let me = c.user.as_ref().map(|u| u.id.as_str());
    let list: Vec<Value> = app.db.service_accounts().iter().filter(|s| s.deleted_at.is_none() && (c.admin() || Some(s.owner_id.as_str()) == me)).map(|s| view(&app, s)).collect();
    Json(json!({ "serviceAccounts": list, "scopes": scope_names(), "defaultDays": DEFAULT_DAYS, "maxDays": MAX_DAYS }))
}

/// `POST /api/service-accounts` `{name, description?, role?, team?}`. `role` is member,
/// readonly (the default), or a custom role; with `team`, a custom role applies only in
/// that team. Its owner is whoever makes it, and it can't hold more than they do.
pub async fn create(State(app): State<AppState>, Extension(c): Extension<Caller>, Extension(by): Extension<Who>, Json(v): Json<Value>) -> Res<(StatusCode, Json<Value>)> {
    only_fields(&v, &["name", "description", "role", "team"])?;
    let owner = caller_person(&c)?;
    let name = parse_name(&v["name"], "name", 60)?;
    let description = parse_description(&v["description"])?;
    let (role, custom) = if v["role"].is_null() { (Role::Readonly, None) } else { parse_role(&app, &v["role"])? };
    let team = parse_team(&app, &v["team"])?;
    let roles = Roles { role, custom, team };
    if roles.team_role().is_some() && role == Role::Readonly {
        return Err(conflict("A read-only role changes nothing, in a team too. Give it a role based on member."));
    }
    within(&app, &by, &owner, &roles, None)?;
    let org = roles.org_role().map(|r| r.id.as_str());
    let team_arg = roles.team.as_ref().map(|t| (t.id.as_str(), roles.team_role().map(|r| r.id.as_str())));
    let sa = app.db.create_service_account(&name, &description, role, org, team_arg, &owner.id, by.actor.id.as_deref()).map_err(|e| ApiError(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    app.db.record(&by.event("service_account.created").target("service_account", &sa.user.id).details(json!({
        "name": sa.user.name, "role": role, "customRole": role_summary(roles.org_role()), "team": roles.team.as_ref().map(|t| &t.id),
        "teamRole": role_summary(roles.team_role()), "owner": owner.id, "permissions": roles.holds().names(),
    })));
    Ok((StatusCode::CREATED, Json(view(&app, &sa))))
}

/// `GET /api/service-accounts/{id}`: the account and its tokens (never their secrets).
pub async fn get(State(app): State<AppState>, Extension(c): Extension<Caller>, Extension(by): Extension<Who>, Path(key): Path<String>) -> Res {
    let sa = need_account(&app, &c, &by, &key)?;
    let mut v = view(&app, &sa);
    let at = crate::db::now();
    v["tokenList"] = json!(app.db.service_tokens(&sa.user.id).iter().map(|t| token_view(t, at)).collect::<Vec<_>>());
    Ok(Json(v))
}

/// `PATCH /api/service-accounts/{id}` `{name?, description?, role?, team?, status?, owner?}`.
/// Only admins change the owner. The result must fit under the (new) owner.
pub async fn update(State(app): State<AppState>, Extension(c): Extension<Caller>, Extension(by): Extension<Who>, Path(key): Path<String>, Json(v): Json<Value>) -> Res {
    only_fields(&v, &["name", "description", "role", "team", "status", "owner"])?;
    let before = need_account(&app, &c, &by, &key)?;
    let id = before.user.id.clone();
    let was = Roles::of(&app, &before);
    let mut p = ServiceAccountPatch {
        name: (!v["name"].is_null()).then(|| parse_name(&v["name"], "name", 60)).transpose()?.filter(|n| *n != before.user.name),
        description: v.get("description").map(parse_description).transpose()?.filter(|d| *d != before.description),
        ..Default::default()
    };
    p.status = match v["status"].as_str() {
        None if v["status"].is_null() => None,
        Some("active") => Some("active"),
        Some("disabled") => Some("disabled"),
        _ => return Err(bad("status must be active or disabled")),
    }
    .filter(|s| *s != before.user.status);
    let owner = match &v["owner"] {
        Value::Null => app.db.user(&before.owner_id).ok_or_else(|| not_found("Owner"))?,
        o => {
            let o = o.as_str().and_then(|k| app.db.find_user(k.trim())).ok_or_else(|| not_found("Owner"))?;
            if o.id != before.owner_id {
                if !c.admin() {
                    return Err(refuse(&app, &by, "service_account_owner", Some(&id), json!({}), "Only an admin can change a service account's owner.".into()));
                }
                if live_owner(&app, &o.id).is_none() {
                    return Err(conflict("The owner must be an active person."));
                }
                p.owner = Some(o.id.clone());
            }
            o
        }
    };
    let (role, custom) = if v["role"].is_null() { (was.role, was.custom.clone()) } else { parse_role(&app, &v["role"])? };
    let team = if v.get("team").is_none() { was.team.clone() } else { parse_team(&app, &v["team"])? };
    let now = Roles { role, custom, team };
    if now.team_role().is_some() && role == Role::Readonly {
        return Err(conflict("A read-only role changes nothing, in a team too. Give it a role based on member."));
    }
    let ids = |r: &Roles| (r.role, r.org_role().map(|c| c.id.clone()), r.team.as_ref().map(|t| t.id.clone()), r.team_role().map(|c| c.id.clone()));
    let (role_now, org_now, team_now, team_role_now) = ids(&now);
    let roles_changed = ids(&was) != ids(&now);
    if roles_changed || p.owner.is_some() {
        within(&app, &by, &owner, &now, Some(&id))?;
    }
    if roles_changed {
        p.role = Some((role_now, org_now));
        p.team = Some(team_now.map(|t| (t, team_role_now)));
    }
    app.db.update_service_account(&id, &p).map_err(|_| not_found("Service account"))?;
    let after = app.db.service_account(&id).ok_or_else(|| not_found("Service account"))?;
    let mut changes = Map::new();
    let mut change = |k: &str, from: Value, to: Value| {
        if from != to {
            changes.insert(k.into(), json!({ "from": from, "to": to }));
        }
    };
    change("name", json!(before.user.name), json!(after.user.name));
    change("description", json!(before.description), json!(after.description));
    change("owner", json!(before.owner_id), json!(after.owner_id));
    change("role", json!(before.user.role), json!(after.user.role));
    change("customRole", role_summary(was.org_role()), role_summary(now.org_role()));
    change("team", json!(before.team_id), json!(after.team_id));
    change("teamRole", role_summary(was.team_role()), role_summary(now.team_role()));
    if roles_changed {
        change("permissions", json!(was.holds().names()), json!(now.holds().names()));
        // Open streams keep the Bot access they worked out; a new team or role changes it.
        app.send(json!({ "type": "resync" }));
    }
    if !changes.is_empty() {
        app.db.record(&by.event("service_account.updated").target("service_account", &id).details(json!({ "name": after.user.name, "changes": changes })));
    }
    // Another team shares other Bots with it: runs it asked for on Bots it can no longer
    // operate stop.
    if before.team_id != after.team_id {
        let viewer = crate::acl::Viewer::User { id: id.clone(), role: after.user.role };
        for bot in app.db.bots() {
            if app.live_run(&bot.id).is_some() && app.requested_by(&bot) == id && viewer.access(&app.db, &bot) < crate::acl::Access::Operate {
                app.stop(&bot.id);
            }
        }
    }
    if before.user.status != after.user.status {
        if after.user.active() {
            let resumed = crate::handover::user_enabled(&app, &by, &id);
            app.db.record(&by.event("service_account.enabled").target("service_account", &id).details(json!({ "name": after.user.name, "routinesResumed": resumed })));
        } else {
            let paused = crate::handover::user_disabled(&app, &by, &id);
            let stopped = app.stop_for_user(&id);
            app.db.record(&by.event("service_account.disabled").target("service_account", &id).details(json!({ "name": after.user.name, "routinesPaused": paused, "runsStopped": stopped })));
        }
    }
    Ok(Json(view(&app, &after)))
}

/// `DELETE /api/service-accounts/{id}`: for good. Its tokens are revoked, it's disabled and
/// the work it asked for stops; the audit log keeps naming it.
pub async fn delete(State(app): State<AppState>, Extension(c): Extension<Caller>, Extension(by): Extension<Who>, Path(key): Path<String>) -> Res {
    let sa = need_account(&app, &c, &by, &key)?;
    let revoked = app.db.delete_service_account(&sa.user.id, by.actor.id.as_deref()).ok_or_else(|| not_found("Service account"))?;
    let paused = crate::handover::user_disabled(&app, &by, &sa.user.id);
    let stopped = app.stop_for_user(&sa.user.id);
    app.db.record(&by.event("service_account.deleted").target("service_account", &sa.user.id).details(json!({ "name": sa.user.name, "tokensRevoked": revoked, "routinesPaused": paused, "runsStopped": stopped })));
    Ok(Json(json!({ "ok": true, "tokensRevoked": revoked })))
}

/// `GET /api/service-accounts/{id}/tokens`: newest first, revoked and expired ones too.
pub async fn list_tokens(State(app): State<AppState>, Extension(c): Extension<Caller>, Extension(by): Extension<Who>, Path(key): Path<String>) -> Res {
    let sa = need_account(&app, &c, &by, &key)?;
    let at = crate::db::now();
    Ok(Json(json!({ "tokens": app.db.service_tokens(&sa.user.id).iter().map(|t| token_view(t, at)).collect::<Vec<_>>() })))
}

fn need_active(sa: &ServiceAccount) -> Res<()> {
    if sa.user.active() {
        return Ok(());
    }
    Err(conflict("This service account is disabled. Enable it first."))
}

/// A new secret, its hash, and its last four characters.
fn mint() -> (String, String, String) {
    let token = users::new_secret(TOKEN_PREFIX);
    let hint = token[token.len() - 4..].to_string();
    (users::hash(&token), hint, token)
}

/// `POST /api/service-accounts/{id}/tokens` `{name?, scopes?, expiresInDays?}`. The token
/// is in the reply once; only its hash is kept. Scopes are permission names the account
/// holds (none: all it holds); it expires after `expiresInDays` (default 90, at most 365).
pub async fn create_token(State(app): State<AppState>, Extension(c): Extension<Caller>, Extension(by): Extension<Who>, Path(key): Path<String>, Json(v): Json<Value>) -> Res<Response> {
    only_fields(&v, &["name", "scopes", "expiresInDays"])?;
    let sa = need_account(&app, &c, &by, &key)?;
    need_active(&sa)?;
    let name = if v["name"].is_null() { "API token".to_string() } else { parse_name(&v["name"], "name", 60)? };
    let scopes = parse_scopes(&v["scopes"], Roles::of(&app, &sa).holds())?;
    let expires_at = crate::db::now() + parse_days(&v["expiresInDays"])? * DAY;
    let (hash, hint, token) = mint();
    let t = app
        .db
        .create_service_token(&NewServiceToken { account_id: &sa.user.id, name: &name, token_hash: &hash, hint: &hint, scopes: scopes.as_deref(), expires_at, created_by: by.actor.id.as_deref() })
        .ok_or_else(|| ApiError(StatusCode::INTERNAL_SERVER_ERROR, "Couldn't save the token.".into()))?;
    app.db.record(&by.event("service_token.created").target("service_token", &t.id).details(json!({ "account": sa.user.id, "accountName": sa.user.name, "name": t.name, "scopes": t.scopes, "expiresAt": t.expires_at })));
    let at = crate::db::now();
    Ok(no_store(StatusCode::CREATED, json!({ "token": token, "tokenInfo": token_view(&t, at), "serviceAccount": { "id": sa.user.id, "name": sa.user.name } })))
}

fn need_token(app: &AppState, sa: &ServiceAccount, id: &str) -> Res<ServiceToken> {
    app.db.service_token(id).filter(|t| t.account_id == sa.user.id).ok_or_else(|| not_found("Token"))
}

/// `POST /api/service-accounts/{id}/tokens/{token}/rotate` `{expiresInDays?, keepOldMinutes?}`:
/// a new token with the same name and scopes. The old one stops now, or after
/// `keepOldMinutes` (at most a day) so callers can switch over.
pub async fn rotate_token(State(app): State<AppState>, Extension(c): Extension<Caller>, Extension(by): Extension<Who>, Path((key, tid)): Path<(String, String)>, Json(v): Json<Value>) -> Res<Response> {
    only_fields(&v, &["expiresInDays", "keepOldMinutes"])?;
    let sa = need_account(&app, &c, &by, &key)?;
    need_active(&sa)?;
    let old = need_token(&app, &sa, &tid)?;
    let at = crate::db::now();
    if token_state(&old, at) != "active" || old.rotated_to.is_some() {
        return Err(conflict("This token is revoked, expired, or rotated already. Make a new one instead."));
    }
    let keep = match &v["keepOldMinutes"] {
        Value::Null => 0,
        Value::Number(n) => n.as_i64().filter(|m| (0..=MAX_KEEP_MINUTES).contains(m)).ok_or_else(|| bad(format!("keepOldMinutes must be 0 to {MAX_KEEP_MINUTES}")))?,
        _ => return Err(bad(format!("keepOldMinutes must be 0 to {MAX_KEEP_MINUTES}"))),
    };
    let expires_at = at + parse_days(&v["expiresInDays"])? * DAY;
    let scopes: Option<Vec<&str>> = old.scopes.as_ref().map(|s| s.iter().map(String::as_str).collect());
    let (hash, hint, token) = mint();
    let new = NewServiceToken { account_id: &sa.user.id, name: &old.name, token_hash: &hash, hint: &hint, scopes: scopes.as_deref(), expires_at, created_by: by.actor.id.as_deref() };
    let keep_until = (keep > 0).then_some(at + keep * 60_000);
    let t = app.db.rotate_service_token(&old.id, &new, keep_until, by.actor.id.as_deref()).ok_or_else(|| conflict("This token was revoked, expired, or rotated meanwhile."))?;
    let old_ends = keep_until.map_or(at, |u| u.min(old.expires_at));
    app.db.record(&by.event("service_token.rotated").target("service_token", &old.id).details(json!({
        "account": sa.user.id, "accountName": sa.user.name, "name": old.name, "to": t.id, "oldEndsAt": old_ends, "expiresAt": t.expires_at,
    })));
    Ok(no_store(StatusCode::CREATED, json!({ "token": token, "tokenInfo": token_view(&t, at), "replaced": { "id": old.id, "endsAt": old_ends }, "serviceAccount": { "id": sa.user.id, "name": sa.user.name } })))
}

/// `DELETE /api/service-accounts/{id}/tokens/{token}`: it stops working at once.
pub async fn revoke_token(State(app): State<AppState>, Extension(c): Extension<Caller>, Extension(by): Extension<Who>, Path((key, tid)): Path<(String, String)>) -> Res {
    let sa = need_account(&app, &c, &by, &key)?;
    let t = need_token(&app, &sa, &tid)?;
    if !app.db.revoke_service_token(&t.id, by.actor.id.as_deref(), "revoked") {
        return Err(not_found("Live token"));
    }
    app.db.record(&by.event("service_token.revoked").target("service_token", &t.id).details(json!({ "account": sa.user.id, "accountName": sa.user.name, "name": t.name })));
    Ok(Json(json!({ "ok": true })))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn person_only_routes() {
        let m = |s: &str| Method::from_bytes(s.as_bytes()).unwrap();
        for (method, path) in [
            ("POST", "/api/auth/logout"),
            ("POST", "/api/auth/mfa/enroll"),
            ("GET", "/api/auth/mfa"),
            ("GET", "/api/me/secrets"),
            ("PUT", "/api/me/push"),
            ("GET", "/api/machine"),
            ("POST", "/api/machine/harness-login"),
            ("GET", "/api/billing"),
            ("POST", "/api/billing/checkout"),
            ("POST", "/api/team/leave"),
            ("POST", "/api/team/billing/portal"),
            ("GET", "/api/service-accounts"),
            ("POST", "/api/service-accounts/sa1/tokens"),
            ("POST", "/api/bots"),
            ("GET", "/api/bots/b1/screen"),
            ("POST", "/api/approvals/a1/approve"),
            ("POST", "/api/approvals/a1/deny"),
        ] {
            assert!(person_only(&m(method), path).is_some(), "{method} {path}");
        }
        for (method, path) in [
            ("GET", "/api/auth/me"),
            ("HEAD", "/api/auth/me"),
            ("GET", "/api/state"),
            ("GET", "/api/audit"),
            ("GET", "/api/users"),
            ("POST", "/api/bots/b1/messages"),
            ("GET", "/api/team"),
            ("POST", "/api/team/invites"),
            ("GET", "/api/machines"),
            ("GET", "/api/approvals"),
            ("GET", "/"),
        ] {
            assert!(person_only(&m(method), path).is_none(), "{method} {path}");
        }
    }

    #[test]
    fn tokens_are_random_and_only_their_hash_and_hint_are_kept() {
        let (hash, hint, token) = mint();
        assert!(token.starts_with(TOKEN_PREFIX) && token.len() == TOKEN_PREFIX.len() + 64, "a prefix and 64 hex characters");
        assert_eq!((hash, hint.as_str()), (users::hash(&token), &token[token.len() - 4..]));
        assert_ne!(mint().2, token);
        // Never read as a session token, whose prefix is close.
        assert!(!token.starts_with(users::SESSION_PREFIX));
    }

    #[test]
    fn token_scopes_deny_by_default() {
        let t = |scopes: Option<Vec<&str>>| ServiceToken {
            id: "st1".into(), account_id: "sa1".into(), name: "t".into(), hint: "abcd".into(),
            scopes: scopes.map(|s| s.into_iter().map(String::from).collect()), created_at: 0, created_by: None, expires_at: 1,
            last_used_at: None, last_used_ip: None, revoked_at: None, revoked_by: None, revoked_reason: None, rotated_to: None,
        };
        assert_eq!(token_scope(&t(None)), Scope::all());
        assert_eq!(token_scope(&t(Some(vec!["read", "audit.view"]))).names(), ["account", "read", "audit.view"]);
        // Unknown names and admin, as a newer server or a hand edit might leave, grant nothing.
        assert_eq!(token_scope(&t(Some(vec!["admin", "secrets.manage", "Read", ""]))).names(), ["account"]);
        let member = Scope::of(Principal::User(Role::Member), Perms::NONE);
        assert_eq!(parse_scopes(&json!(["read", "write"]), member).unwrap(), Some(vec!["read", "write"]));
        assert_eq!(parse_scopes(&Value::Null, member).unwrap(), None);
        for bad_scopes in [json!([]), json!("read"), json!(["admin"]), json!(["audit.view"]), json!(["nope"]), json!([1])] {
            assert!(parse_scopes(&bad_scopes, member).is_err(), "{bad_scopes}");
        }
    }
}
