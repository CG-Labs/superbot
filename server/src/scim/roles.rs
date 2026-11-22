//! SCIM groups mapped to custom roles (ADR 0138). An admin maps a tenant's group (a team,
//! ADR 0095) to a custom role (ADR 0123), across the server or within the group's team.
//! The IdP never names the role: it only changes who is in the group, and the group's
//! members get the role when SCIM puts them in it and lose it when they leave it, however
//! they leave. A mapping is never to admin, nor to a role whose permissions reach admins
//! (`rbac::REACHES_ADMINS`). Nobody who is an admin, or holds a custom role given by hand,
//! is changed, and only what a mapping gave is taken away. Off unless SCIM_GROUP_ROLES=on;
//! taking away works either way. Every change is audited.

use super::*;
use crate::db::{CustomRole, ScimRoleMapError, ScimRoleMapping};

pub const ORG: &str = "org";
pub const TEAM: &str = "team";
/// Why a grant was taken away: they left the group's team, the mapping was removed, or
/// the group went (deleted by the IdP, or unlinked by an admin).
pub const LEFT_GROUP: &str = "left_group";
pub const UNMAPPED: &str = "mapping_removed";
pub const GROUP_GONE: &str = "group_removed";

fn conflict(msg: impl Into<String>) -> ApiError {
    ApiError(StatusCode::CONFLICT, msg.into())
}

/// The permissions `role` would give in `scope` that reach admins. Empty: SCIM may give it.
pub fn reaching(role: &CustomRole, scope: &str) -> Vec<&'static str> {
    role.perms().reaching_admins(scope == TEAM)
}

/// What the role gives in the mapping's scope.
fn applies(role: &CustomRole, scope: &str) -> Vec<&'static str> {
    if scope == TEAM { role.perms().in_team().names() } else { role.perms().names() }
}

fn role_ref(role: Option<&CustomRole>) -> Value {
    role.map_or(Value::Null, |r| json!({ "id": r.id, "name": r.name }))
}

fn view(app: &AppState, m: &ScimRoleMapping) -> Value {
    let role = app.db.custom_role(&m.role_id);
    json!({
        "id": m.id, "tenant": m.tenant,
        "team": { "id": m.team_id, "name": app.db.team(&m.team_id).map(|t| t.name) },
        "group": app.db.scim_group(&m.tenant, &m.team_id).map(|g| g.display_name),
        "role": role_ref(role.as_ref()), "scope": m.scope,
        "applies": role.as_ref().map_or(vec![], |r| applies(r, &m.scope)),
        "grants": app.db.scim_role_grants(&m.id).len(),
        "createdAt": m.created_at, "createdBy": m.created_by,
    })
}

fn event(by: &Who, action: &str, m: &ScimRoleMapping, role: Option<&CustomRole>, details: Value) -> crate::audit::Event {
    let mut d = json!({ "mapping": m.id, "tenant": m.tenant, "team": m.team_id, "role": role_ref(role), "scope": m.scope });
    if let (Some(d), Value::Object(x)) = (d.as_object_mut(), details) {
        d.extend(x);
    }
    by.event(action).target("team", &m.team_id).details(d)
}

/// Gives `user_id` the mapping's role, or says why not: they're an admin or the owner
/// account, hold a custom role already (by hand, or the group's), are read-only (a team
/// role does nothing for them), aren't on the team any more, or the role now reaches
/// admins. Audited as any grant is, with `via: scim`.
async fn grant(app: &AppState, by: &Who, m: &ScimRoleMapping, role: &CustomRole, user_id: &str) -> Result<(), &'static str> {
    let before = app.db.user(user_id).ok_or("gone")?;
    let member = app.db.team_member(user_id).filter(|x| x.team_id == m.team_id).ok_or("not_on_team")?;
    if m.scope == ORG {
        if before.id == users::OPERATOR {
            return Err("owner");
        }
        if before.role == Role::Admin {
            return Err("admin");
        }
        if before.role_id.is_some() {
            return Err("has_role");
        }
    } else {
        if before.role == Role::Readonly {
            return Err("readonly");
        }
        if member.role_id.is_some() {
            return Err("has_role");
        }
    }
    if !reaching(role, &m.scope).is_empty() {
        return Err("reaches_admins");
    }
    if !app.db.grant_scim_role(m, user_id) {
        return Err("changed");
    }
    let mut d = json!({ "name": role.name, "user": user_id, "scope": m.scope, "from": null, "via": "scim", "mapping": m.id, "tenant": m.tenant });
    if m.scope == TEAM {
        d["team"] = json!(m.team_id);
        d["applies"] = json!(applies(role, TEAM));
    }
    app.db.record(&by.event("role.assigned").target("role", &role.id).details(d));
    if m.scope == ORG
        && let Some(after) = app.db.user(user_id)
        && after.role != before.role
    {
        app.db.record(
            &by.event("user.role_changed").target("user", user_id).details(json!({ "from": before.role, "to": after.role, "role": { "id": role.id, "name": role.name }, "reason": "scim_group" })),
        );
        users::lost_access(app, by, user_id, crate::machines::offboard::ACCESS_LOST).await;
    }
    Ok(())
}

fn skipped(app: &AppState, by: &Who, m: &ScimRoleMapping, role: &CustomRole, user_id: &str, reason: &str) {
    app.db.record(&event(by, "scim.role_skipped", m, Some(role), json!({ "user": user_id, "reason": reason })));
}

/// Takes away what the mapping gave `user_id`. Across the server their built-in role goes
/// back to the one they had before. Whether it had given them anything.
async fn take_away(app: &AppState, by: &Who, m: &ScimRoleMapping, user_id: &str, reason: &str) -> bool {
    let Some(r) = app.db.revoke_scim_role(m, user_id, reason == LEFT_GROUP) else { return false };
    let role = app.db.custom_role(&m.role_id);
    let mut d = json!({ "name": role.as_ref().map(|r| r.name.clone()), "user": user_id, "scope": m.scope, "via": "scim", "mapping": m.id, "tenant": m.tenant, "reason": reason, "held": r.cleared });
    if m.scope == TEAM {
        d["team"] = json!(m.team_id);
    } else {
        d["keeps"] = json!(r.role_after);
    }
    app.db.record(&by.event("role.unassigned").target("role", &m.role_id).details(d));
    if r.role_before != r.role_after {
        app.db.record(&by.event("user.role_changed").target("user", user_id).details(json!({ "from": r.role_before, "to": r.role_after, "role": role_ref(role.as_ref()), "reason": "scim_group" })));
        users::lost_access(app, by, user_id, crate::machines::offboard::ACCESS_LOST).await;
    }
    true
}

/// SCIM just put `user_id` in the group `team_id` is: they get the group's mapped roles.
/// Callers hold the group write lock.
pub(crate) async fn joined(app: &AppState, a: &Auth, by: &Who, tenant: &str, team_id: &str, user_id: &str) {
    if !a.scim.group_roles {
        return;
    }
    for m in app.db.scim_role_mappings_of(tenant, team_id) {
        let Some(role) = app.db.custom_role(&m.role_id) else { continue };
        if let Err(reason) = grant(app, by, &m, &role, user_id).await {
            skipped(app, by, &m, &role, user_id, reason);
        }
    }
}

/// `user_id` left `team_id`, by SCIM or any other way: what its group's mappings gave
/// them goes.
pub(crate) async fn left(app: &AppState, by: &Who, team_id: &str, user_id: &str) {
    for g in app.db.scim_role_grants_of_user(user_id) {
        if let Some(m) = app.db.scim_role_mapping(&g.mapping_id).filter(|m| m.team_id == team_id) {
            take_away(app, by, &m, user_id, LEFT_GROUP).await;
        }
    }
}

/// Removes a mapping and takes away everything it gave. Who lost it.
async fn unmap(app: &AppState, by: &Who, m: &ScimRoleMapping, reason: &str) -> Vec<String> {
    let mut revoked = Vec::new();
    for g in app.db.scim_role_grants(&m.id) {
        if take_away(app, by, m, &g.user_id, reason).await {
            revoked.push(g.user_id);
        }
    }
    app.db.delete_scim_role_mapping(&m.id);
    let role = app.db.custom_role(&m.role_id);
    app.db.record(&event(by, "scim.role_unmapped", m, role.as_ref(), json!({ "reason": reason, "revoked": revoked })));
    revoked
}

/// The group `team_id` is ends (the IdP deleted it, or an admin unlinked it): its
/// mappings go, with what they gave. Callers hold the group write lock.
pub(crate) async fn group_gone(app: &AppState, by: &Who, team_id: &str) {
    for m in app.db.scim_role_mappings_of_team(team_id) {
        unmap(app, by, &m, GROUP_GONE).await;
    }
}

// Admin API (under /api, admins only).

fn need(app: &AppState, id: &str) -> Res<ScimRoleMapping> {
    app.db.scim_role_mapping(id).ok_or_else(|| not_found("Mapping"))
}

/// Refuses a mapping, audited: SCIM never gives admin, or what reaches admins.
fn refused(app: &AppState, by: &Who, reason: &str, details: Value, msg: String) -> ApiError {
    let mut d = json!({ "reason": reason });
    if let (Some(d), Value::Object(x)) = (d.as_object_mut(), details) {
        d.extend(x);
    }
    app.db.record(&by.event("scim.role_map_refused").outcome(Outcome::Denied).details(d));
    bad(msg)
}

/// `GET /api/scim/role-mappings`: every mapping, and whether SCIM_GROUP_ROLES is on.
pub async fn list(State(app): State<AppState>, Extension(a): Extension<Arc<Auth>>) -> Json<Value> {
    let all: Vec<Value> = app.db.scim_role_mappings().iter().map(|m| view(&app, m)).collect();
    Json(json!({ "enabled": a.scim.group_roles, "groups": a.scim.groups, "mappings": all }))
}

/// `POST /api/scim/role-mappings {team, role, scope?: "team" | "org"}`: maps the group
/// `team` is to a custom role, within the team (the default) or across the server, and
/// gives it to the group's members now. 201 with who got it and who didn't, and why.
pub async fn create(State(app): State<AppState>, Extension(a): Extension<Arc<Auth>>, Extension(by): Extension<Who>, Json(v): Json<Value>) -> Res<(StatusCode, Json<Value>)> {
    let body = v.as_object().ok_or_else(|| bad("Send a JSON object."))?;
    if let Some(k) = body.keys().find(|k| !["team", "role", "scope"].contains(&k.as_str())) {
        return Err(bad(format!("Unknown field \"{k}\": send team, role, scope.")));
    }
    if !a.scim.group_roles {
        return Err(conflict("Mapping SCIM groups to roles is off on this server (SCIM_GROUP_ROLES=on turns it on, with SCIM_GROUPS=on)."));
    }
    let scope = match v["scope"].as_str().map(str::trim) {
        None if v["scope"].is_null() => TEAM,
        Some(TEAM) => TEAM,
        Some(ORG) => ORG,
        _ => return Err(bad("scope must be team (within the group's team) or org (across the server)")),
    };
    let key = v["role"].as_str().map(str::trim).filter(|k| !k.is_empty()).ok_or_else(|| bad("role must be a custom role's id or name"))?;
    match Role::parse(key) {
        Some(Role::Admin) => return Err(refused(&app, &by, "admin", json!({ "role": key, "scope": scope }), "A SCIM group can never be mapped to admin. Give admin by hand.".into())),
        Some(_) => {
            let msg = "A SCIM group maps only to a custom role. Members join with their built-in role as it is.".into();
            return Err(refused(&app, &by, "built_in", json!({ "role": key, "scope": scope }), msg));
        }
        None => {}
    }
    let team = v["team"].as_str().map(str::trim).unwrap_or_default();
    let _writes = a.scim.group_writes.lock().await;
    let role = app.db.find_custom_role(key).ok_or_else(|| not_found("Role"))?;
    let reaches = |role: &CustomRole, reach: Vec<&'static str>| {
        let d = json!({ "role": { "id": role.id, "name": role.name }, "scope": scope, "permissions": reach });
        let msg = format!(
            "{} holds {}, which {} on admins, so a SCIM group can't be given it {}. Give it by hand, or map a role without {}.",
            role.name,
            reach.join(" and "),
            if reach.len() == 1 { "acts" } else { "act" },
            if scope == ORG { "across the server" } else { "in a team" },
            if reach.len() == 1 { "it" } else { "them" },
        );
        refused(&app, &by, "reaches_admins", d, msg)
    };
    let reach = reaching(&role, scope);
    if !reach.is_empty() {
        return Err(reaches(&role, reach));
    }
    let g = app.db.scim_group_of_team(team).ok_or_else(|| not_found("SCIM group"))?;
    // The database checks the role's permissions again as it saves, against an edit meanwhile.
    let m = app.db.create_scim_role_mapping(&g.tenant, &g.team_id, &role.id, scope, by.actor.id.as_deref()).map_err(|e| match e {
        ScimRoleMapError::Taken => conflict(format!("This group is mapped to a role {} already. Remove that mapping first.", if scope == ORG { "across the server" } else { "in its team" })),
        ScimRoleMapError::Gone => not_found("SCIM group"),
        ScimRoleMapError::Reaches(reach) => reaches(&role, reach),
        ScimRoleMapError::Db(e) => ApiError(StatusCode::INTERNAL_SERVER_ERROR, e),
    })?;
    let role = app.db.custom_role(&m.role_id).ok_or_else(|| not_found("Role"))?;
    app.db.record(&event(&by, "scim.role_mapped", &m, Some(&role), json!({ "group": g.display_name, "applies": applies(&role, scope) })));
    let (mut granted, mut skips) = (Vec::new(), Vec::new());
    for u in app.db.scim_group_members(&g.tenant, &g.team_id, false) {
        match grant(&app, &by, &m, &role, &u.id).await {
            Ok(()) => granted.push(u.id),
            Err(reason) => {
                skipped(&app, &by, &m, &role, &u.id, reason);
                skips.push(json!({ "user": u.id, "reason": reason }));
            }
        }
    }
    let mut out = view(&app, &m);
    out["granted"] = json!(granted);
    out["skipped"] = json!(skips);
    Ok((StatusCode::CREATED, Json(out)))
}

/// `GET /api/scim/role-mappings/{id}`: the mapping and everyone it gave the role to.
pub async fn get(State(app): State<AppState>, Path(id): Path<String>) -> Res {
    let m = need(&app, &id)?;
    let mut v = view(&app, &m);
    v["holders"] = json!(
        app.db
            .scim_role_grants(&m.id)
            .iter()
            .map(|g| {
                let u = app.db.user(&g.user_id);
                json!({ "user": { "id": g.user_id, "name": u.as_ref().map(|u| u.name.clone()), "email": u.and_then(|u| u.email) }, "grantedAt": g.granted_at, "priorRole": g.prior_role })
            })
            .collect::<Vec<_>>()
    );
    Ok(Json(v))
}

/// `DELETE /api/scim/role-mappings/{id}`: removes the mapping and takes the role away from
/// everyone it gave it to. Roles given by hand stay.
pub async fn delete(State(app): State<AppState>, Extension(a): Extension<Arc<Auth>>, Extension(by): Extension<Who>, Path(id): Path<String>) -> Res {
    let _writes = a.scim.group_writes.lock().await;
    let m = need(&app, &id)?;
    let revoked = unmap(&app, &by, &m, UNMAPPED).await;
    Ok(Json(json!({ "ok": true, "revoked": revoked })))
}
