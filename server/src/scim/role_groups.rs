//! SCIM role groups (ADR 0180). Every SCIM group is otherwise a team (ADR 0095), and a
//! person is on one team at most, so an IdP's groups that only say who holds a role
//! ("Auditors", "Billing admins") couldn't be pushed next to the team groups their
//! people are in. An admin declares such a group for a tenant, by its `displayName` or
//! `externalId`, with the custom role it gives across the server (never admin, nor one
//! that reaches admins). When the IdP pushes that group it becomes a role group, not a
//! team: anyone the tenant provisioned can be in any number of them, and nothing but the
//! role follows membership. A person holds one custom role across the server, so the
//! oldest role group they're in that can give one does, and when it stops the next in
//! line is offered. Like a mapping (ADR 0138): never over an admin, the owner or a role
//! given by hand, only what it gave is taken back, and SCIM_GROUP_ROLES=off gives nothing
//! but still takes away. Until the IdP pushes it, a declaration is unseen by the IdP.

use super::groups::{self, Clause, Patched, GROUP_SCHEMA};
use super::*;
use crate::db::{CustomRole, ScimRoleGroup, ScimRoleGroupError};
use std::collections::HashSet;

/// Why a role group's role was taken away.
pub const LEFT_GROUP: &str = "left_group";
pub const USER_DELETED: &str = "user_deleted";
pub const GROUP_GONE: &str = "group_removed";
pub const REMOVED: &str = "role_group_removed";
pub const ROLE_CHANGED: &str = "role_changed";
const MAX_NAME: usize = 256;

// Reading, for SCIM: only the role groups the IdP has pushed.

/// The role group `id`, if this tenant's IdP has it.
pub fn pushed(app: &AppState, tenant: &str, id: &str) -> Option<ScimRoleGroup> {
    app.db.scim_role_group(id).filter(|g| g.tenant == tenant && g.provisioned_at.is_some())
}

/// The tenant's role groups its IdP has, oldest first.
pub fn all_pushed(app: &AppState, tenant: &str) -> Vec<ScimRoleGroup> {
    app.db.scim_role_groups(tenant).into_iter().filter(|g| g.provisioned_at.is_some()).collect()
}

pub fn matches(app: &AppState, g: &ScimRoleGroup, clauses: &[Clause]) -> bool {
    clauses.iter().all(|c| match c {
        Clause::Id(v) => g.id == *v,
        Clause::DisplayName(v) => g.display_name.eq_ignore_ascii_case(v),
        Clause::ExternalId(v) => g.external_id.as_deref() == Some(v.as_str()),
        Clause::Member(v) => app.db.scim_role_group_has(&g.id, v) && app.db.scim_user(&g.tenant, v).is_some(),
    })
}

/// A role group as SCIM shows it: a Group like any other.
pub fn resource(app: &AppState, base: &str, g: &ScimRoleGroup, members: bool) -> Value {
    let mut v = json!({
        "schemas": [GROUP_SCHEMA],
        "id": g.id,
        "displayName": g.display_name,
        "meta": { "resourceType": "Group", "created": rfc3339(g.provisioned_at.unwrap_or(g.created_at)), "lastModified": rfc3339(g.updated_at), "location": format!("{base}/Groups/{}", g.id) },
    });
    if let Some(x) = &g.external_id {
        v["externalId"] = json!(x);
    }
    if members {
        let list: Vec<Value> = app.db.scim_role_group_members(&g.tenant, &g.id).iter().map(|u| json!({ "value": u.id, "display": u.name, "type": "User", "$ref": format!("{base}/Users/{}", u.id) })).collect();
        v["members"] = json!(list);
    }
    v
}

fn write_error(e: ScimRoleGroupError) -> ScimError {
    match e {
        ScimRoleGroupError::DisplayName => uniqueness("Another group in this tenant has this displayName."),
        ScimRoleGroupError::ExternalId => uniqueness("Another group in this tenant has this externalId."),
        ScimRoleGroupError::Gone => missing("Group"),
        ScimRoleGroupError::Reaches(_) => server_error("The role group's role reaches admins"),
        ScimRoleGroupError::Db(e) => {
            crate::obs::log::log_warn!("scim: database error: {e}");
            server_error("Database error")
        }
    }
}

/// Whether a team group of `tenant` has this `displayName` (any ASCII case) or
/// `externalId`: role groups and team groups share a tenant's names, as Entra expects.
pub fn team_has(app: &AppState, tenant: &str, display_name: Option<&str>, external_id: Option<&str>) -> bool {
    display_name.is_some_and(|n| app.db.scim_group_find(tenant, None, Some(n)).is_some()) || external_id.is_some_and(|x| app.db.scim_group_find(tenant, Some(x), None).is_some())
}

/// Whether a role group of `tenant`, other than `except`, has this name or `externalId`.
pub fn role_group_has(app: &AppState, tenant: &str, display_name: Option<&str>, external_id: Option<&str>, except: Option<&str>) -> bool {
    let other = |g: ScimRoleGroup| Some(g.id.as_str()) != except;
    display_name.and_then(|n| app.db.scim_role_group_find(tenant, None, Some(n))).is_some_and(other)
        || external_id.and_then(|x| app.db.scim_role_group_find(tenant, Some(x), None)).is_some_and(other)
}

/// Refuses anyone the request would add who isn't a live user of this tenant. Being on a
/// team, or in other role groups, is no bar.
fn check_new(app: &AppState, c: &Caller, new: &[String]) -> ScimRes<()> {
    match new.iter().find(|id| app.db.scim_user(&c.token.tenant, id).is_none()) {
        Some(id) => Err(invalid(format!("{id} isn't a user this tenant provisioned. Provision the user first; SCIM groups only hold this tenant's users."))),
        None => Ok(()),
    }
}

// Roles.

fn role_ref(role: Option<&CustomRole>) -> Value {
    role.map_or(Value::Null, |r| json!({ "id": r.id, "name": r.name }))
}

/// Gives `user_id` the group's role across the server, or says why not: they aren't in
/// it, are an admin or the owner account, hold a custom role already (by hand, a mapping
/// or another role group), or the role now reaches admins. Audited as any grant is.
async fn grant(app: &AppState, by: &Who, g: &ScimRoleGroup, role: &CustomRole, user_id: &str) -> Result<(), &'static str> {
    let before = app.db.user(user_id).ok_or("gone")?;
    if !app.db.scim_role_group_has(&g.id, user_id) {
        return Err("not_in_group");
    }
    if before.id == users::OPERATOR {
        return Err("owner");
    }
    if before.role == Role::Admin {
        return Err("admin");
    }
    if before.role_id.is_some() {
        return Err("has_role");
    }
    if !role.perms().reaching_admins(false).is_empty() {
        return Err("reaches_admins");
    }
    if !app.db.grant_scim_role_group(g, user_id) {
        return Err("changed");
    }
    let d = json!({ "name": role.name, "user": user_id, "scope": "org", "from": null, "via": "scim", "roleGroup": g.id, "tenant": g.tenant });
    app.db.record(&by.event("role.assigned").target("role", &role.id).details(d));
    if let Some(after) = app.db.user(user_id)
        && after.role != before.role
    {
        app.db.record(&by.event("user.role_changed").target("user", user_id).details(json!({ "from": before.role, "to": after.role, "role": role_ref(Some(role)), "reason": "scim_group" })));
        users::lost_access(app, by, user_id, crate::machines::offboard::ACCESS_LOST).await;
    }
    Ok(())
}

fn skipped(app: &AppState, by: &Who, g: &ScimRoleGroup, role: &CustomRole, user_id: &str, reason: &str) {
    app.db.record(&by.event("scim.role_skipped").target("scim_role_group", &g.id).details(json!({
        "roleGroup": g.id, "tenant": g.tenant, "role": role_ref(Some(role)), "scope": "org", "user": user_id, "reason": reason,
    })));
}

/// Takes away what the group gave `user_id`; their built-in role goes back to the one
/// they had. Whether it had given them anything.
async fn take_away(app: &AppState, by: &Who, g: &ScimRoleGroup, user_id: &str, reason: &str) -> bool {
    let Some((given, r)) = app.db.revoke_scim_role_group(g, user_id, reason == LEFT_GROUP) else { return false };
    let role = app.db.custom_role(&given);
    let d = json!({
        "name": role.as_ref().map(|r| r.name.clone()), "user": user_id, "scope": "org", "via": "scim", "roleGroup": g.id, "tenant": g.tenant,
        "reason": reason, "held": r.cleared, "keeps": r.role_after,
    });
    app.db.record(&by.event("role.unassigned").target("role", &given).details(d));
    if r.role_before != r.role_after {
        app.db.record(&by.event("user.role_changed").target("user", user_id).details(json!({ "from": r.role_before, "to": r.role_after, "role": role_ref(role.as_ref()), "reason": "scim_group" })));
        users::lost_access(app, by, user_id, crate::machines::offboard::ACCESS_LOST).await;
    }
    true
}

/// A role group's role just went from `user_id`: the next role group they're in, oldest
/// declared first, that can give them one does. Skips here aren't audited; each group
/// audited them when it was offered.
async fn reoffer(app: &AppState, a: &Auth, by: &Who, user_id: &str) {
    if !a.scim.group_roles {
        return;
    }
    for g in app.db.scim_role_groups_of_user(user_id).into_iter().filter(|g| g.provisioned_at.is_some()) {
        let Some(role) = app.db.custom_role(&g.role_id) else { continue };
        if grant(app, by, &g, &role, user_id).await.is_ok() {
            return;
        }
    }
}

/// Offers the group's role to `user_id`, who has just joined it, or audits why not.
async fn offer(app: &AppState, a: &Auth, by: &Who, g: &ScimRoleGroup, user_id: &str) -> bool {
    if !a.scim.group_roles {
        return false;
    }
    let Some(role) = app.db.custom_role(&g.role_id) else { return false };
    match grant(app, by, g, &role, user_id).await {
        Ok(()) => true,
        Err(reason) => {
            skipped(app, by, g, &role, user_id, reason);
            false
        }
    }
}

// Membership.

#[derive(Default)]
struct Moved {
    added: Vec<String>,
    removed: Vec<String>,
    granted: Vec<String>,
    revoked: Vec<String>,
}

async fn change_members(app: &AppState, a: &Auth, c: &Caller, g: &ScimRoleGroup, gone: &[String], new: &[String]) -> Moved {
    let mut m = Moved::default();
    for id in gone {
        if app.db.remove_scim_role_group_member(&g.id, id) {
            m.removed.push(id.clone());
        }
        if take_away(app, &c.who, g, id, LEFT_GROUP).await {
            m.revoked.push(id.clone());
            reoffer(app, a, &c.who, id).await;
        }
    }
    for id in new {
        if app.db.add_scim_role_group_member(&g.id, id) {
            m.added.push(id.clone());
            if offer(app, a, &c.who, g, id).await {
                m.granted.push(id.clone());
            }
        }
    }
    m
}

fn record_update(app: &AppState, c: &Caller, before: &ScimRoleGroup, after: &ScimRoleGroup, moved: &Moved) {
    let mut changes = Map::new();
    for (k, from, to) in [("displayName", json!(before.display_name), json!(after.display_name)), ("externalId", json!(before.external_id), json!(after.external_id))] {
        if from != to {
            changes.insert(k.into(), json!({ "from": from, "to": to }));
        }
    }
    if changes.is_empty() && moved.added.is_empty() && moved.removed.is_empty() {
        return;
    }
    app.db.record(&c.who.event("scim.group_updated").target("scim_role_group", &after.id).details(json!({
        "tenant": after.tenant, "kind": "role", "roleGroup": after.id, "changes": changes, "added": moved.added, "removed": moved.removed, "granted": moved.granted, "revoked": moved.revoked,
    })));
}

// SCIM handlers, called by `groups`'s with the group write lock held.

/// A `POST /Groups` that names a declared role group: by its `externalId`, or, when the
/// declaration has none, its `displayName`. The IdP takes it on with the members sent.
/// None: no role group has this group's name or `externalId`, so it is a team. A role
/// group the IdP has already is a 409, as for teams.
pub(super) async fn create(app: &AppState, a: &Auth, c: &Caller, base: &str, d: &groups::Doc) -> ScimRes<Option<Response>> {
    match waiting_for(app, &c.token.tenant, d)? {
        Some(g) => adopt(app, a, c, base, &g, d).await.map(Some),
        None => Ok(None),
    }
}

/// The waiting declaration a `POST /Groups` of `d` takes on, if any.
fn waiting_for(app: &AppState, tenant: &str, d: &groups::Doc) -> ScimRes<Option<ScimRoleGroup>> {
    let by_ext = d.external_id.as_deref().and_then(|x| app.db.scim_role_group_find(tenant, Some(x), None));
    let by_name = app.db.scim_role_group_find(tenant, None, Some(&d.display_name));
    match (by_ext, by_name) {
        (Some(g), _) if g.provisioned_at.is_none() => Ok(Some(g)),
        (Some(_), _) => Err(uniqueness("A group with this externalId exists already")),
        (None, Some(g)) if g.provisioned_at.is_none() && g.declared_external_id.is_none() => Ok(Some(g)),
        (None, Some(_)) => Err(uniqueness("A group with this displayName exists already")),
        (None, None) => Ok(None),
    }
}

/// For the Google sync: `POST /Groups` of `d`, which must take on the waiting declaration
/// `id`. If it has gone or changed since the sync read it, nothing is written: the push
/// would otherwise make a team.
pub(crate) async fn push_declared(app: &AppState, a: &Auth, c: &Caller, id: &str, d: &groups::Doc) -> ScimRes<Response> {
    let _writes = a.scim.group_writes.lock().await;
    match waiting_for(app, &c.token.tenant, d)? {
        Some(g) if g.id == id => adopt(app, a, c, &base_url(&HeaderMap::new()), &g, d).await,
        _ => Err(ScimError::new(StatusCode::CONFLICT, None, "The role group's declaration changed during the pass, so the group wasn't pushed. The next pass tries again.")),
    }
}

async fn adopt(app: &AppState, a: &Auth, c: &Caller, base: &str, waiting: &ScimRoleGroup, d: &groups::Doc) -> ScimRes<Response> {
    let tenant = c.token.tenant.as_str();
    if team_has(app, tenant, Some(&d.display_name), d.external_id.as_deref()) {
        return Err(uniqueness("A group with this displayName or externalId exists already"));
    }
    let new = d.members.clone().unwrap_or_default();
    check_new(app, c, &new)?;
    let external_id = d.external_id.clone().or_else(|| waiting.external_id.clone());
    let g = app.db.save_scim_role_group(&waiting.id, external_id.as_deref(), &d.display_name, true).map_err(write_error)?;
    let role = app.db.custom_role(&g.role_id);
    app.db.record(&c.who.event("scim.role_group_adopted").target("scim_role_group", &g.id).details(json!({
        "tenant": tenant, "roleGroup": g.id, "externalId": g.external_id, "displayName": g.display_name, "role": role_ref(role.as_ref()), "declaredBy": g.created_by,
    })));
    let moved = change_members(app, a, c, &g, &[], &new).await;
    record_update(app, c, waiting, &g, &moved);
    let body = resource(app, base, &app.db.scim_role_group(&g.id).unwrap_or(g), true);
    let mut r = scim_json(StatusCode::CREATED, body.clone());
    if let Some(Ok(at)) = body["meta"]["location"].as_str().map(HeaderValue::from_str) {
        r.headers_mut().insert(header::LOCATION, at);
    }
    Ok(r)
}

/// Saves a PUT's or PATCH's attributes and members. `externalId` can be set once.
pub(super) async fn update(app: &AppState, a: &Auth, c: &Caller, before: &ScimRoleGroup, p: &Patched) -> ScimRes<ScimRoleGroup> {
    if let Some(old) = before.external_id.as_deref()
        && p.external_id.as_deref() != Some(old)
    {
        return Err(ScimError::new(StatusCode::BAD_REQUEST, Some("mutability"), "externalId can't change once set. Delete the group and push it again."));
    }
    let tenant = c.token.tenant.as_str();
    let renamed = !p.display_name.eq_ignore_ascii_case(&before.display_name);
    if team_has(app, tenant, renamed.then_some(p.display_name.as_str()), p.external_id.as_deref().filter(|_| before.external_id.is_none())) {
        return Err(uniqueness("Another group in this tenant has this displayName or externalId."));
    }
    let members = app.db.scim_role_group_member_ids(&before.id);
    let (gone, new) = p.delta(&members);
    check_new(app, c, &new)?;
    let g = app.db.save_scim_role_group(&before.id, p.external_id.as_deref(), &p.display_name, true).map_err(write_error)?;
    let moved = change_members(app, a, c, &g, &gone, &new).await;
    record_update(app, c, before, &g, &moved);
    Ok(app.db.scim_role_group(&g.id).unwrap_or(g))
}

/// The members a PUT or PATCH starts from: everyone stored, so a removed user the
/// tenant deleted is still taken out.
pub(super) fn patched(app: &AppState, g: &ScimRoleGroup) -> Patched {
    Patched::new(&g.display_name, g.external_id.as_deref(), &app.db.scim_role_group_member_ids(&g.id))
}

/// `DELETE /Groups/{id}` of a role group: everyone leaves it, losing what it gave (and
/// offered the next role group in line), and the declaration waits for the IdP again,
/// unseen, so pushing the group again makes it a role group again, never a team.
pub(super) async fn delete(app: &AppState, a: &Auth, c: &Caller, g: &ScimRoleGroup) -> ScimRes<Response> {
    let members = app.db.scim_role_group_member_ids(&g.id);
    let mut revoked = Vec::new();
    for id in &members {
        app.db.remove_scim_role_group_member(&g.id, id);
        if take_away(app, &c.who, g, id, GROUP_GONE).await {
            revoked.push(id.clone());
        }
    }
    if !app.db.reset_scim_role_group(&g.id) {
        return Err(server_error("The role group wasn't reset"));
    }
    for id in &revoked {
        reoffer(app, a, &c.who, id).await;
    }
    app.db.record(&c.who.event("scim.group_deleted").target("scim_role_group", &g.id).details(json!({
        "tenant": g.tenant, "kind": "role", "roleGroup": g.id, "externalId": g.external_id, "displayName": g.display_name, "removed": members, "revoked": revoked,
    })));
    Ok(StatusCode::NO_CONTENT.into_response())
}

/// A SCIM DELETE of `user_id`: they leave every role group, losing what it gave, so
/// restoring them by `externalId` brings no role back. Works whatever SCIM_GROUP_ROLES says.
pub(crate) async fn user_deleted(app: &AppState, a: &Auth, by: &Who, user_id: &str) {
    let _writes = a.scim.group_writes.lock().await;
    for g in app.db.scim_role_groups_of_user(user_id) {
        app.db.remove_scim_role_group_member(&g.id, user_id);
        take_away(app, by, &g, user_id, USER_DELETED).await;
    }
}

// Admin API (under /api, admins only).

fn conflict(msg: impl Into<String>) -> ApiError {
    ApiError(StatusCode::CONFLICT, msg.into())
}

fn need(app: &AppState, id: &str) -> Res<ScimRoleGroup> {
    app.db.scim_role_group(id).ok_or_else(|| not_found("Role group"))
}

fn view(app: &AppState, g: &ScimRoleGroup) -> Value {
    let role = app.db.custom_role(&g.role_id);
    json!({
        "id": g.id, "tenant": g.tenant, "displayName": g.display_name, "externalId": g.external_id,
        "declaredDisplayName": g.declared_display_name, "declaredExternalId": g.declared_external_id,
        "role": role_ref(role.as_ref()), "applies": role.as_ref().map_or(vec![], |r| r.perms().names()),
        "state": if g.provisioned_at.is_some() { "pushed" } else { "waiting" }, "pushedAt": g.provisioned_at,
        "members": app.db.scim_role_group_members(&g.tenant, &g.id).len(), "grants": app.db.scim_role_group_grants(&g.id).len(),
        "createdAt": g.created_at, "createdBy": g.created_by,
    })
}

/// Refuses a role, audited like a refused mapping: SCIM never gives admin, a built-in
/// role, or what reaches admins.
fn refused(app: &AppState, by: &Who, reason: &str, details: Value, msg: String) -> ApiError {
    let mut d = json!({ "reason": reason, "kind": "role_group", "scope": "org" });
    if let (Some(d), Value::Object(x)) = (d.as_object_mut(), details) {
        d.extend(x);
    }
    app.db.record(&by.event("scim.role_map_refused").outcome(Outcome::Denied).details(d));
    bad(msg)
}

fn reaches_msg(role: &CustomRole, reach: &[&str]) -> String {
    format!(
        "{} holds {}, which {} on admins, so a SCIM role group can't give it. Give it by hand, or pick a role without {}.",
        role.name,
        reach.join(" and "),
        if reach.len() == 1 { "acts" } else { "act" },
        if reach.len() == 1 { "it" } else { "them" },
    )
}

/// The custom role a request names, refused (and audited) if SCIM may not give it.
fn pick_role(app: &AppState, by: &Who, v: &Value) -> Res<CustomRole> {
    let key = v.as_str().map(str::trim).filter(|k| !k.is_empty()).ok_or_else(|| bad("role must be a custom role's id or name"))?;
    match Role::parse(key) {
        Some(Role::Admin) => return Err(refused(app, by, "admin", json!({ "role": key }), "A SCIM role group can never give admin. Give admin by hand.".into())),
        Some(_) => return Err(refused(app, by, "built_in", json!({ "role": key }), "A SCIM role group gives only a custom role. Members keep their built-in role as it is.".into())),
        None => {}
    }
    let role = app.db.find_custom_role(key).ok_or_else(|| not_found("Role"))?;
    let reach = role.perms().reaching_admins(false);
    if !reach.is_empty() {
        return Err(refused(app, by, "reaches_admins", json!({ "role": { "id": role.id, "name": role.name }, "permissions": reach }), reaches_msg(&role, &reach)));
    }
    Ok(role)
}

fn clean(v: &Value, k: &str, max: usize) -> Res<Option<String>> {
    match &v[k] {
        Value::Null => Ok(None),
        Value::String(s) if s.trim().is_empty() => Ok(None),
        Value::String(s) if s.chars().any(char::is_control) || s.trim().chars().count() > max => Err(bad(format!("{k} must be at most {max} characters, with no control characters"))),
        Value::String(s) => Ok(Some(s.trim().to_string())),
        _ => Err(bad(format!("{k} must be a string"))),
    }
}

fn only_fields(v: &Value, fields: &[&str]) -> Res<()> {
    let body = v.as_object().ok_or_else(|| bad("Send a JSON object."))?;
    match body.keys().find(|k| !fields.contains(&k.as_str())) {
        Some(k) => Err(bad(format!("Unknown field \"{k}\": send {}.", fields.join(", ")))),
        None => Ok(()),
    }
}

fn off() -> ApiError {
    conflict("SCIM role groups are off on this server (SCIM_GROUP_ROLES=on turns them on, with SCIM_GROUPS=on).")
}

/// `GET /api/scim/role-groups`: every tenant's role groups, and whether SCIM_GROUP_ROLES is on.
pub async fn list(State(app): State<AppState>, Extension(a): Extension<Arc<Auth>>) -> Json<Value> {
    let all: Vec<Value> = app.db.all_scim_role_groups().iter().map(|g| view(&app, g)).collect();
    Json(json!({ "enabled": a.scim.group_roles, "groups": a.scim.groups, "roleGroups": all }))
}

/// `POST /api/scim/role-groups {tenant, displayName, externalId?, role}`: declares that
/// the tenant's group with this `externalId` (or, with none, this `displayName`) is a
/// role group giving `role` across the server. It waits, unseen, until the IdP pushes it.
pub async fn create_api(State(app): State<AppState>, Extension(a): Extension<Arc<Auth>>, Extension(by): Extension<Who>, Json(v): Json<Value>) -> Res<(StatusCode, Json<Value>)> {
    only_fields(&v, &["tenant", "displayName", "externalId", "role"])?;
    if !a.scim.group_roles {
        return Err(off());
    }
    let tenant = tenant_name(&v["tenant"])?;
    let display_name = clean(&v, "displayName", MAX_NAME)?.ok_or_else(|| bad("displayName is required: the group's name as the IdP pushes it"))?;
    let external_id = clean(&v, "externalId", 256)?;
    let role = pick_role(&app, &by, &v["role"])?;
    let _writes = a.scim.group_writes.lock().await;
    if team_has(&app, &tenant, Some(&display_name), external_id.as_deref()) {
        return Err(conflict(format!("Tenant {tenant} has a team group with this displayName or externalId. A group is a team or a role group, not both.")));
    }
    let g = app.db.declare_scim_role_group(&tenant, &display_name, external_id.as_deref(), &role.id, by.actor.id.as_deref()).map_err(|e| match e {
        ScimRoleGroupError::DisplayName => conflict(format!("Tenant {tenant} has a role group with this displayName already.")),
        ScimRoleGroupError::ExternalId => conflict(format!("Tenant {tenant} has a role group with this externalId already.")),
        ScimRoleGroupError::Reaches(reach) => refused(&app, &by, "reaches_admins", json!({ "role": { "id": role.id, "name": role.name }, "permissions": reach }), reaches_msg(&role, &reach)),
        ScimRoleGroupError::Gone => not_found("Role"),
        ScimRoleGroupError::Db(e) => ApiError(StatusCode::INTERNAL_SERVER_ERROR, e),
    })?;
    app.db.record(&by.event("scim.role_group_declared").target("scim_role_group", &g.id).details(json!({
        "tenant": tenant, "roleGroup": g.id, "displayName": g.display_name, "externalId": g.external_id, "role": role_ref(Some(&role)), "applies": role.perms().names(),
    })));
    Ok((StatusCode::CREATED, Json(view(&app, &g))))
}

/// `GET /api/scim/role-groups/{id}`: the role group, its members, and who it gave the role to.
pub async fn get_api(State(app): State<AppState>, Path(id): Path<String>) -> Res {
    let g = need(&app, &id)?;
    let mut v = view(&app, &g);
    let person = |id: &str| {
        let u = app.db.user(id);
        json!({ "id": id, "name": u.as_ref().map(|u| u.name.clone()), "email": u.and_then(|u| u.email) })
    };
    v["people"] = json!(app.db.scim_role_group_members(&g.tenant, &g.id).iter().map(|u| person(&u.id)).collect::<Vec<_>>());
    v["holders"] = json!(app.db.scim_role_group_grants(&g.id).iter().map(|h| json!({ "user": person(&h.user_id), "grantedAt": h.granted_at, "priorRole": h.prior_role })).collect::<Vec<_>>());
    Ok(Json(v))
}

/// `PATCH /api/scim/role-groups/{id} {role}`: the group gives another role. What the old
/// one gave is taken away, then its members are offered the new one. Sent again, it
/// finishes what a restart cut short.
pub async fn update_api(State(app): State<AppState>, Extension(a): Extension<Arc<Auth>>, Extension(by): Extension<Who>, Path(id): Path<String>, Json(v): Json<Value>) -> Res {
    only_fields(&v, &["role"])?;
    if !a.scim.group_roles {
        return Err(off());
    }
    let role = pick_role(&app, &by, &v["role"])?;
    let _writes = a.scim.group_writes.lock().await;
    let before = need(&app, &id)?;
    // The same role again isn't a no-op: it finishes a change cut short by a restart,
    // taking away grants still on another role and offering it to members without one.
    // Skips were audited by the change itself, so only a real change audits them again.
    let changed = before.role_id != role.id;
    // The new role is saved, and checked, first: a role edited or deleted meanwhile leaves
    // every grant as it was. Each grant records the role it gave, which is what goes.
    let g = app.db.set_scim_role_group_role(&before.id, &role.id).map_err(|e| match e {
        ScimRoleGroupError::Reaches(reach) => refused(&app, &by, "reaches_admins", json!({ "role": { "id": role.id, "name": role.name }, "permissions": reach }), reaches_msg(&role, &reach)),
        ScimRoleGroupError::Gone => not_found("Role group or role"),
        e => ApiError(StatusCode::INTERNAL_SERVER_ERROR, format!("{e:?}")),
    })?;
    let role = app.db.custom_role(&role.id).unwrap_or(role);
    let mut revoked = Vec::new();
    for h in app.db.scim_role_group_grants(&g.id).into_iter().filter(|h| h.role_id != g.role_id) {
        if take_away(&app, &by, &g, &h.user_id, ROLE_CHANGED).await {
            revoked.push(h.user_id);
        }
    }
    let (mut granted, mut skips) = (Vec::new(), Vec::new());
    if g.provisioned_at.is_some() {
        let holds: HashSet<String> = app.db.scim_role_group_grants(&g.id).into_iter().map(|h| h.user_id).collect();
        for u in app.db.scim_role_group_members(&g.tenant, &g.id).into_iter().filter(|u| !holds.contains(&u.id)) {
            match grant(&app, &by, &g, &role, &u.id).await {
                Ok(()) => granted.push(u.id),
                Err(reason) => {
                    if changed {
                        skipped(&app, &by, &g, &role, &u.id, reason);
                    }
                    skips.push(json!({ "user": u.id, "reason": reason }));
                }
            }
        }
    }
    for id in revoked.iter().filter(|id| !granted.contains(id)) {
        reoffer(&app, &a, &by, id).await;
    }
    if changed || !revoked.is_empty() || !granted.is_empty() {
        let from = app.db.custom_role(&before.role_id);
        app.db.record(&by.event("scim.role_group_changed").target("scim_role_group", &g.id).details(json!({
            "tenant": g.tenant, "roleGroup": g.id, "displayName": g.display_name, "from": role_ref(from.as_ref()), "to": role_ref(Some(&role)), "revoked": revoked, "granted": granted,
        })));
    }
    let mut out = view(&app, &g);
    out["revoked"] = json!(revoked);
    out["granted"] = json!(granted);
    out["skipped"] = json!(skips);
    Ok(Json(out))
}

/// `DELETE /api/scim/role-groups/{id}`: the declaration goes, with the role it gave
/// everyone (each offered the next role group in line). Roles given by hand stay. If the
/// IdP still pushes the group, it becomes a team on its next push (with SCIM_GROUPS=on),
/// so take it out of the IdP's provisioning first; the answer says when it was pushed.
pub async fn delete_api(State(app): State<AppState>, Extension(a): Extension<Arc<Auth>>, Extension(by): Extension<Who>, Path(id): Path<String>) -> Res {
    let _writes = a.scim.group_writes.lock().await;
    let g = need(&app, &id)?;
    let mut revoked = Vec::new();
    for h in app.db.scim_role_group_grants(&g.id) {
        if take_away(&app, &by, &g, &h.user_id, REMOVED).await {
            revoked.push(h.user_id);
        }
    }
    if !app.db.delete_scim_role_group(&g.id) {
        return Err(not_found("Role group"));
    }
    for id in &revoked {
        reoffer(&app, &a, &by, id).await;
    }
    let pushed = g.provisioned_at.is_some();
    app.db.record(&by.event("scim.role_group_removed").target("scim_role_group", &g.id).details(json!({
        "tenant": g.tenant, "roleGroup": g.id, "displayName": g.display_name, "externalId": g.external_id, "role": role_ref(app.db.custom_role(&g.role_id).as_ref()), "revoked": revoked, "wasPushed": pushed,
    })));
    Ok(Json(json!({ "ok": true, "revoked": revoked, "wasPushed": pushed })))
}

/// Who is in the role group now (live users of its tenant), for callers (the Google
/// sync) that skip writes that change nothing.
pub fn member_set(app: &AppState, g: &ScimRoleGroup) -> HashSet<String> {
    app.db.scim_role_group_members(&g.tenant, &g.id).into_iter().map(|u| u.id).collect()
}
