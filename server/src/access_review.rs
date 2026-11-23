//! The access-review report (SOC 2 CC6.3): everyone who can sign in, grouped by SCIM
//! tenant and team, with their role, status, second factor, last sign-in, Bot access,
//! live sessions and API tokens, and machine; exportable as CSV, and signed off by an
//! admin as an `access_review.completed` audit event. Admins only, by RBAC's default
//! arm. Metadata only: never a token, code, secret or IP address. Service accounts are
//! reviewed beside people: owner, roles, what their tokens can use today, Bot access,
//! and each live token's scopes, expiry and last use.
//! Design: docs/adr/0099-access-review-report.md, docs/adr/0165-service-accounts-in-access-reviews.md.

use crate::acl::Viewer;
use crate::db::{self, ServiceAccount, Session, User};
use crate::rbac::{Principal, Role};
use crate::users::{SessionConfig, OPERATOR};
use crate::{bad, need_user, ApiError, App, AppState, Auth, Res};
use crate::audit::{self, Who};
use axum::extract::{Extension, Query, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Arc;

pub const COMPLETED: &str = "access_review.completed";
pub const EXPORTED: &str = "access_review.exported";
/// The audit log clips strings to 500 characters, so notes stop there.
const MAX_NOTES: usize = 500;
/// Past sign-offs shown with the report.
const RECENT_REVIEWS: i64 = 20;
/// A live service token not used for this long (or never, since it was made) is flagged.
pub const UNUSED_DAYS: i64 = 90;
const DAY: i64 = 24 * 60 * 60_000;

/// One person in the report: the JSON shown, and the parts a change in access changes,
/// which the digest covers. Times a session was last used are left out of the digest,
/// so the reviewer's own requests don't change it under them.
struct Row {
    tenant: Option<String>,
    team: Option<(String, String)>,
    view: Value,
    stable: Value,
}

pub struct Report {
    pub generated_at: i64,
    pub digest: String,
    rows: Vec<Row>,
    /// Live service accounts, by name: the JSON shown and the parts the digest covers.
    services: Vec<(Value, Value)>,
}

fn session_view(s: &Session, cfg: &SessionConfig) -> Value {
    let ends = s.expires_at.min(s.created_at + cfg.max_ms).min(s.last_seen_at + cfg.idle_ms);
    json!({
        "id": s.id, "kind": s.kind, "method": s.method, "idpProvider": s.idp_provider, "label": s.label,
        "createdAt": s.created_at, "lastSeenAt": s.last_seen_at, "endsAt": ends, "mfa": s.mfa,
    })
}

/// The report as it stands now.
pub fn build(app: &App, a: &Auth) -> Report {
    build_with(app, &a.sessions)
}

/// The report, with sessions judged live by `sessions`' lifetimes.
pub fn build_with(app: &App, sessions: &SessionConfig) -> Report {
    let at = db::now();
    let users = app.db.users();
    let names: HashMap<&str, &str> = users.iter().map(|u| (u.id.as_str(), u.name.as_str())).collect();
    let mfa = app.db.mfa_enabled();
    let teams: HashMap<String, String> = app.db.teams().into_iter().map(|t| (t.id, t.name)).collect();
    let mut rows: Vec<Row> = users.iter().map(|u| person(app, sessions, u, at, &names, &mfa, &teams)).collect();
    rows.sort_by(|x, y| {
        let key = |r: &Row| (r.tenant.clone().unwrap_or_default(), r.team.as_ref().map(|t| t.1.to_lowercase()).unwrap_or_default(), r.team.as_ref().map(|t| t.0.clone()));
        key(x).cmp(&key(y)).then_with(|| x.view["name"].as_str().unwrap_or("").to_lowercase().cmp(&y.view["name"].as_str().unwrap_or("").to_lowercase())).then_with(|| x.view["id"].as_str().cmp(&y.view["id"].as_str()))
    });
    let mut stable: Vec<&Value> = rows.iter().map(|r| &r.stable).collect();
    stable.sort_by(|x, y| x[0].as_str().cmp(&y[0].as_str()));
    let mut services: Vec<(Value, Value)> = app.db.service_accounts().iter().filter(|s| s.deleted_at.is_none()).map(|s| service(app, s, at, &names, &teams)).collect();
    services.sort_by(|x, y| {
        let name = |v: &Value| v["name"].as_str().unwrap_or("").to_lowercase();
        name(&x.0).cmp(&name(&y.0)).then_with(|| x.0["id"].as_str().cmp(&y.0["id"].as_str()))
    });
    // Only when there are some, so reports from before service accounts keep their digests.
    let digest = if services.is_empty() {
        crate::users::hash(&json!(stable).to_string())
    } else {
        let mut held: Vec<&Value> = services.iter().map(|s| &s.1).collect();
        held.sort_by(|x, y| x[0].as_str().cmp(&y[0].as_str()));
        crate::users::hash(&json!({ "people": stable, "serviceAccounts": held }).to_string())
    };
    Report { generated_at: at, digest, rows, services }
}

/// One Bot a principal reaches, as the report lists it.
fn bot_view(b: &db::Bot, access: crate::acl::Access, of: &str, grant: Option<&crate::acl::Grant>, names: &HashMap<&str, &str>) -> Value {
    json!({
        "id": b.id, "name": b.name, "owner": { "id": b.owner_id, "name": names.get(b.owner_id.as_str()) },
        "own": b.owner_id == of, "visibility": b.visibility, "access": access, "grant": grant,
    })
}

/// Why a reviewer should look at a service account twice. Codes; the app words them.
fn service_flags(sa: &ServiceAccount, owner_active: bool, live: &[&db::ServiceToken], at: i64) -> Vec<&'static str> {
    let mut out = Vec::new();
    if !sa.user.active() {
        out.push("disabled");
    }
    if !owner_active {
        out.push("owner_inactive");
    }
    if live.iter().any(|t| t.scopes.is_none()) {
        out.push("unscoped_token");
    }
    if live.iter().any(|t| t.last_used_at.unwrap_or(t.created_at) <= at - UNUSED_DAYS * DAY) {
        out.push("unused_token");
    }
    out
}

/// A live service account (ADR 0165): who owns it, what it holds and can use today, the
/// Bots it reaches (by its role, team and grants, within its owner's), and its live tokens. Never a token's secret, hash or address.
fn service(app: &App, sa: &ServiceAccount, at: i64, names: &HashMap<&str, &str>, teams: &HashMap<String, String>) -> (Value, Value) {
    let h = crate::service_accounts::holdings(&app.db, sa);
    let u = &sa.user;
    let grants = app.db.user_grants(&u.id);
    // Within its owner's access, as its tokens get it (ADR 0170).
    let bots: Vec<Value> = Viewer::service(&app.db, &u.id, u.role).bots(&app.db).into_iter().map(|(b, access)| bot_view(&b, access, &u.id, grants.get(&b.id), names)).collect();
    let tokens = app.db.service_tokens(&u.id);
    let live: Vec<&db::ServiceToken> = tokens.iter().filter(|t| crate::service_accounts::token_state(t, at) == "active").collect();
    let role_view = |r: &crate::db::CustomRole, perms: crate::rbac::Perms| json!({ "id": r.id, "name": r.name, "permissions": perms.names() });
    let team = h.team.as_ref().map(|t| {
        let mut v = json!({ "id": t.id, "name": teams.get(&t.id).unwrap_or(&t.name), "role": crate::teams::MEMBER });
        if let Some(r) = &h.team_role {
            v["customRole"] = role_view(r, r.perms().in_team());
        }
        v
    });
    let view = json!({
        "id": u.id, "name": u.name, "description": sa.description, "role": u.role, "status": u.status,
        "createdAt": u.created_at, "createdBy": sa.created_by,
        "customRole": h.org_role.as_ref().map(|r| role_view(r, r.perms())),
        "team": team,
        "owner": h.owner.as_ref().map(|o| json!({ "id": o.id, "name": o.name, "email": o.email, "status": o.status })),
        "ownerActive": h.owner_active,
        "permissions": h.org.names(), "teamPermissions": h.in_team.names(), "effective": h.effective.names(),
        "botAccess": { "all": false, "bots": bots },
        "tokens": live.iter().map(|t| json!({
            "id": t.id, "name": t.name, "preview": crate::service_accounts::token_preview(t), "scopes": t.scopes,
            "createdAt": t.created_at, "expiresAt": t.expires_at, "lastUsedAt": t.last_used_at, "replaced": t.rotated_to.is_some(),
        })).collect::<Vec<_>>(),
        "flags": service_flags(sa, h.owner_active, &live, at),
    });
    // Not when a token was last used, so a script calling during the review changes nothing.
    let stable = json!([
        u.id, u.role, u.status,
        h.org_role.as_ref().map(|r| json!([r.id, r.perms().names()])),
        h.team.as_ref().map(|t| json!([t.id, h.team_role.as_ref().map(|r| json!([r.id, r.perms().in_team().names()]))])),
        sa.owner_id, h.owner_active, h.effective.names(),
        bots.iter().map(|b| json!([b["id"], b["access"], b["grant"]])).collect::<Vec<_>>(),
        live.iter().map(|t| json!([t.id, t.scopes, t.expires_at, t.rotated_to.is_some()])).collect::<Vec<_>>(),
    ]);
    (view, stable)
}

/// A role cell: the built-in role, and a custom role with its permissions when there is one.
fn with_custom(p: &Value) -> String {
    let role = p["role"].as_str().unwrap_or_default();
    match p["customRole"]["name"].as_str() {
        Some(name) => {
            let perms: Vec<&str> = p["customRole"]["permissions"].as_array().map(|a| a.iter().filter_map(Value::as_str).collect()).unwrap_or_default();
            format!("{role}; {name}: {}", perms.join(" "))
        }
        None => role.to_string(),
    }
}

fn person(app: &App, cfg: &SessionConfig, u: &User, at: i64, names: &HashMap<&str, &str>, mfa: &HashMap<String, i64>, teams: &HashMap<String, String>) -> Row {
    let scim = app.db.scim_user_of(&u.id);
    let member = app.db.team_member(&u.id);
    let team = member.as_ref().map(|m| (m.team_id.clone(), teams.get(&m.team_id).cloned().unwrap_or_else(|| m.team_id.clone())));
    let all_bots = u.role == Role::Admin;
    let bots: Vec<Value> = if all_bots {
        Vec::new()
    } else {
        let grants = app.db.user_grants(&u.id);
        Viewer::User { id: u.id.clone(), role: u.role }
            .bots(&app.db)
            .into_iter()
            .map(|(b, access)| bot_view(&b, access, &u.id, grants.get(&b.id), names))
            .collect()
    };
    let live = app.db.user_live_sessions(&u.id, at, cfg.idle_ms, cfg.max_ms);
    let (tokens, browsers): (Vec<&Session>, Vec<&Session>) = live.iter().partition(|s| s.kind == "token");
    let machine = app.db.user_machine(&u.id);
    let mfa_at = mfa.get(&u.id).copied();
    // Custom roles (ADR 0123): across the server, and within their team.
    let custom = u.role_id.as_deref().and_then(|id| app.db.custom_role(id));
    let team_custom = member.as_ref().and_then(|m| m.role_id.as_deref()).and_then(|id| app.db.custom_role(id));
    let role_view = |r: &crate::db::CustomRole, perms: crate::rbac::Perms| json!({ "id": r.id, "name": r.name, "permissions": perms.names() });
    let mut view = json!({
        "id": u.id, "name": u.name, "email": u.email, "role": u.role, "status": u.status, "breakGlass": u.id == OPERATOR, "tier": u.tier,
        "createdAt": u.created_at,
        "scim": scim.as_ref().map(|s| json!({ "tenant": s.tenant, "deleted": s.deleted_at.is_some() })),
        "team": member.as_ref().zip(team.as_ref()).map(|(m, t)| json!({ "id": t.0, "name": t.1, "role": m.role })),
        "mfa": { "enabled": mfa_at.is_some(), "enabledAt": mfa_at },
        "lastLogin": u.last_login_at.map(|at| json!({ "at": at, "method": u.last_login_method, "idpProvider": u.last_login_idp_provider })),
        "botAccess": { "all": all_bots, "bots": bots },
        "sessions": browsers.iter().map(|s| session_view(s, cfg)).collect::<Vec<_>>(),
        "apiTokens": tokens.iter().map(|s| session_view(s, cfg)).collect::<Vec<_>>(),
        "machine": machine.as_ref().map(|m| json!({ "id": m.id, "provider": m.provider, "state": m.state.as_str(), "enrollment": m.enrollment, "assignedAt": m.assigned_at })),
        "customRole": custom.as_ref().map(|r| role_view(r, r.perms())),
    });
    if let Some(r) = &team_custom {
        view["team"]["customRole"] = role_view(r, r.perms().in_team());
    }
    let ids = |list: &[&Session]| list.iter().map(|s| s.id.clone()).collect::<Vec<_>>();
    let mut stable = json!([
        u.id, u.role, u.status, u.email,
        scim.as_ref().map(|s| json!([s.tenant, s.deleted_at.is_some()])),
        member.as_ref().map(|m| json!([m.team_id, m.role])),
        mfa_at.is_some(),
        all_bots,
        bots.iter().map(|b| json!([b["id"], b["access"], b["grant"]])).collect::<Vec<_>>(),
        ids(&browsers), ids(&tokens),
        machine.as_ref().map(|m| json!([m.id, m.state.as_str(), m.assigned_at])),
    ]);
    // Only when there is one, so reports from before custom roles keep their digests.
    if custom.is_some() || team_custom.is_some() {
        let held = |r: &Option<crate::db::CustomRole>, team: bool| r.as_ref().map(|r| json!([r.id, if team { r.perms().in_team() } else { r.perms() }.names()]));
        if let Some(a) = stable.as_array_mut() {
            a.push(json!([held(&custom, false), held(&team_custom, true)]));
        }
    }
    Row { tenant: scim.map(|s| s.tenant), team, view, stable }
}

impl Report {
    /// Each person as the report shows them.
    pub fn people(&self) -> impl Iterator<Item = &Value> {
        self.rows.iter().map(|r| &r.view)
    }

    /// Each live service account as the report shows it, by name.
    pub fn service_accounts(&self) -> impl Iterator<Item = &Value> {
        self.services.iter().map(|s| &s.0)
    }

    /// Counts a reviewer looks at first, also kept on the sign-off.
    pub fn summary(&self) -> Value {
        let count = |f: &dyn Fn(&Value) -> bool| self.people().filter(|p| f(p)).count();
        let active = |p: &Value| p["status"] == "active";
        let len = |p: &Value, k: &str| p[k].as_array().map_or(0, Vec::len);
        json!({
            "people": self.rows.len(),
            "active": count(&active),
            "disabled": count(&|p| !active(p)),
            "admins": count(&|p| active(p) && p["role"] == "admin"),
            "activeWithoutMfa": count(&|p| active(p) && p["mfa"]["enabled"] != true),
            "scimManaged": count(&|p| p["scim"].is_object()),
            "browserSessions": self.people().map(|p| len(p, "sessions")).sum::<usize>(),
            "apiAccess": self.people().map(|p| len(p, "apiTokens")).sum::<usize>(),
            "machines": count(&|p| p["machine"].is_object()),
            "serviceAccounts": self.services.len(),
            "serviceApiAccess": self.service_accounts().map(|s| len(s, "tokens")).sum::<usize>(),
            "serviceAccountsFlagged": self.service_accounts().filter(|s| len(s, "flags") > 0).count(),
        })
    }

    /// People grouped by SCIM tenant, then team, in that order.
    fn groups(&self) -> Vec<Value> {
        let mut out: Vec<Value> = Vec::new();
        let mut last: Option<(&Option<String>, Option<&String>)> = None;
        for r in &self.rows {
            let key = (&r.tenant, r.team.as_ref().map(|t| &t.0));
            if last != Some(key) {
                out.push(json!({ "tenant": r.tenant, "team": r.team.as_ref().map(|t| json!({ "id": t.0, "name": t.1 })), "people": [] }));
                last = Some(key);
            }
            out.last_mut().unwrap()["people"].as_array_mut().unwrap().push(r.view.clone());
        }
        out
    }

    pub fn csv(&self) -> String {
        let c = audit::csv_cell;
        let time = |v: &Value| v.as_i64().map(rfc3339).unwrap_or_default();
        let s = |v: &Value| v.as_str().map(c).unwrap_or_default();
        let mut out = String::from(CSV_HEADER);
        let generated = rfc3339(self.generated_at);
        let bots = |p: &Value| {
            if p["botAccess"]["all"] == true {
                "all (admin)".to_string()
            } else {
                p["botAccess"]["bots"]
                    .as_array()
                    .map(|b| b.iter().map(|b| format!("{} ({}){}", b["name"].as_str().unwrap_or(""), b["access"].as_str().unwrap_or(""), b["grant"].as_str().map(|g| format!(" grant:{g}")).unwrap_or_default())).collect::<Vec<_>>().join("; "))
                    .unwrap_or_default()
            }
        };
        for r in &self.rows {
            let p = &r.view;
            let n = |k: &str| p[k].as_array().map_or(0, Vec::len).to_string();
            let cells = [
                c(&generated),
                r.tenant.as_deref().map(c).unwrap_or_default(),
                s(&p["team"]["name"]),
                c(&with_custom(&p["team"])),
                s(&p["id"]),
                s(&p["name"]),
                s(&p["email"]),
                c(&with_custom(p)),
                s(&p["status"]),
                p["scim"].is_object().to_string(),
                (p["breakGlass"] == true).to_string(),
                (p["mfa"]["enabled"] == true).to_string(),
                time(&p["mfa"]["enabledAt"]),
                time(&p["lastLogin"]["at"]),
                s(&p["lastLogin"]["method"]),
                c(&bots(p)),
                n("sessions"),
                n("apiTokens"),
                s(&p["machine"]["id"]),
                s(&p["machine"]["state"]),
                time(&p["machine"]["assignedAt"]),
                "person".into(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                c(&self.digest),
            ];
            out.push_str(&cells.join(","));
            out.push_str("\r\n");
        }
        // Service accounts can't sign in, so the sign-in, second-factor and machine cells are empty.
        for p in self.service_accounts() {
            let words = |v: &Value| v.as_array().map(|a| a.iter().filter_map(Value::as_str).collect::<Vec<_>>().join(" ")).unwrap_or_default();
            let owner = format!(
                "{} ({}){}",
                p["owner"]["name"].as_str().unwrap_or(""),
                p["owner"]["id"].as_str().unwrap_or(""),
                if p["ownerActive"] == true { "" } else { " inactive" }
            );
            let tokens = p["tokens"]
                .as_array()
                .map(|ts| {
                    ts.iter()
                        .map(|t| {
                            let scopes = if t["scopes"].is_array() { words(&t["scopes"]) } else { "all".into() };
                            let used = t["lastUsedAt"].as_i64().map_or_else(|| "never".into(), rfc3339);
                            format!("{} {} scopes:{} expires:{} last_used:{}", t["name"].as_str().unwrap_or(""), t["preview"].as_str().unwrap_or(""), scopes, time(&t["expiresAt"]), used)
                        })
                        .collect::<Vec<_>>()
                        .join("; ")
                })
                .unwrap_or_default();
            let cells = [
                c(&generated),
                String::new(),
                s(&p["team"]["name"]),
                if p["team"].is_object() { c(&with_custom(&p["team"])) } else { String::new() },
                s(&p["id"]),
                s(&p["name"]),
                String::new(),
                c(&with_custom(p)),
                s(&p["status"]),
                "false".into(),
                "false".into(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                c(&bots(p)),
                "0".into(),
                p["tokens"].as_array().map_or(0, Vec::len).to_string(),
                String::new(),
                String::new(),
                String::new(),
                "service_account".into(),
                c(&owner),
                c(&words(&p["effective"])),
                c(&tokens),
                c(&words(&p["flags"])),
                c(&self.digest),
            ];
            out.push_str(&cells.join(","));
            out.push_str("\r\n");
        }
        out
    }
}

pub const CSV_HEADER: &str = "generated_at,scim_tenant,team,team_role,user_id,name,email,role,status,scim_managed,break_glass,mfa,mfa_enabled_at,\
last_sign_in_at,last_sign_in_method,bot_access,browser_sessions,api_tokens,machine_id,machine_state,machine_assigned_at,\
kind,owner,effective_permissions,service_tokens,service_flags,report_digest\r\n";

fn rfc3339(ms: i64) -> String {
    chrono::DateTime::from_timestamp_millis(ms).map(|t| t.to_rfc3339_opts(chrono::SecondsFormat::Millis, true)).unwrap_or_default()
}

/// The latest sign-offs, newest first, from the audit log.
fn reviews(app: &App) -> Vec<Value> {
    let f = audit::Filter { actions: vec![COMPLETED.into()], ..Default::default() };
    app.db.audit_events(&f, RECENT_REVIEWS, false).iter().map(review_view).collect()
}

fn review_view(e: &db::AuditEvent) -> Value {
    json!({
        "eventId": e.id, "at": e.at, "time": e.time,
        "reviewer": { "id": e.actor_id, "name": e.actor_name, "email": e.actor_email, "role": e.actor_role, "method": e.auth_method },
        "digest": e.details["digest"], "summary": e.details["summary"], "notes": e.details["notes"],
    })
}

/// `GET /api/access-review`.
pub async fn get(State(app): State<AppState>, Extension(a): Extension<Arc<Auth>>, Extension(who): Extension<Principal>) -> Res {
    need_user(who)?;
    let r = build(&app, &a);
    Ok(Json(json!({
        "generatedAt": r.generated_at, "generatedTime": rfc3339(r.generated_at), "digest": r.digest,
        "summary": r.summary(), "groups": r.groups(), "serviceAccounts": r.service_accounts().collect::<Vec<_>>(), "reviews": reviews(&app),
    })))
}

/// `GET /api/access-review/export.csv[?digest=]`: one row per person, dated, with the
/// digest. With `digest`, a report that no longer matches is a 409, so the file is the
/// report on screen.
pub async fn export(State(app): State<AppState>, Extension(a): Extension<Arc<Auth>>, Extension(who): Extension<Principal>, Extension(by): Extension<Who>, Query(q): Query<HashMap<String, String>>) -> Result<Response, ApiError> {
    need_user(who)?;
    let r = build(&app, &a);
    if q.get("digest").is_some_and(|d| !crate::same(d.trim().as_bytes(), r.digest.as_bytes())) {
        return Err(changed());
    }
    app.db.record(&by.event(EXPORTED).target("access_review", &r.digest[..16]).details(json!({ "digest": r.digest, "summary": r.summary() })));
    let stamp = chrono::DateTime::from_timestamp_millis(r.generated_at).unwrap_or_default().format("%Y%m%d-%H%M%S");
    let headers = [
        (header::CONTENT_TYPE, "text/csv; charset=utf-8".to_string()),
        (header::CONTENT_DISPOSITION, format!("attachment; filename=\"superbot-access-review-{stamp}.csv\"")),
        (header::CACHE_CONTROL, "no-store".into()),
    ];
    Ok((headers, r.csv()).into_response())
}

/// `POST /api/access-review/complete` `{digest, notes?}`: the reviewer signs off on the
/// report they loaded. A digest that no longer matches is a 409, so a sign-off always
/// covers the access that was there when it was made.
pub async fn complete(State(app): State<AppState>, Extension(a): Extension<Arc<Auth>>, Extension(who): Extension<Principal>, Extension(by): Extension<Who>, Json(v): Json<Value>) -> Res<(StatusCode, Json<Value>)> {
    need_user(who)?;
    let digest = v["digest"].as_str().map(str::trim).filter(|d| !d.is_empty()).ok_or_else(|| bad("digest is required: the report's digest you reviewed"))?;
    let notes = match &v["notes"] {
        Value::Null => None,
        Value::String(n) if n.chars().count() <= MAX_NOTES => Some(n.trim()).filter(|n| !n.is_empty()),
        Value::String(_) => return Err(bad(format!("notes can be at most {MAX_NOTES} characters"))),
        _ => return Err(bad("notes must be text")),
    };
    let r = build(&app, &a);
    if !crate::same(digest.as_bytes(), r.digest.as_bytes()) {
        return Err(changed());
    }
    let details = json!({ "digest": r.digest, "generatedAt": r.generated_at, "summary": r.summary(), "notes": notes });
    let id = app.db.try_record(&by.event(COMPLETED).target("access_review", &r.digest[..16]).details(details)).map_err(|err| {
        crate::obs::log::log_warn!("access review: could not save the sign-off: {err}");
        ApiError(StatusCode::INTERNAL_SERVER_ERROR, "Couldn't save the sign-off; see the server log.".into())
    })?;
    let f = audit::Filter { actions: vec![COMPLETED.into()], actor_id: by.actor.id.clone(), ..Default::default() };
    let review = app.db.audit_events(&f, RECENT_REVIEWS, false).iter().find(|e| e.id == id).map(review_view).unwrap_or(Value::Null);
    Ok((StatusCode::CREATED, Json(json!({ "review": review }))))
}

fn changed() -> ApiError {
    ApiError(StatusCode::CONFLICT, "Access changed since this report was loaded. Reload it and review again.".into())
}
