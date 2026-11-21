//! SCIM Groups as teams (ADR 0095). With SCIM_GROUPS=on, each group a tenant provisions
//! is a SuperBot team (ADR 0087), and the group's members are the team's: adding one
//! joins them to the team (and gives them their machine), removing one takes them off
//! it through the same offboarding as any leaver. Members must be users the same tenant
//! provisioned. SCIM never sets roles in a team: members join as `member`, and server
//! admins (or the team's owners, once there are some) choose its owners and admins.
//! Only the IdP changes who's on a SCIM tenant's team; `teams::not_scim` refuses the
//! rest.

use crate::db::{self, ScimGroup, ScimGroupConflict, ScimGroupKey};
use crate::scim::{self, Caller, GROUP_SCHEMA, ScimError, ScimRes, attr, base_url, invalid, key, list, missing, page, parse_body, rfc3339, scim_json, server_error, text};
use crate::{ApiError, AppState, Auth};
use axum::body::Bytes;
use axum::extract::rejection::BytesRejection;
use axum::extract::{Extension, Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::IntoResponse;
use serde_json::{Value, json};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

/// Why a member left a team, in `team.member_left`.
pub const REMOVED: &str = "scim_removed";
pub const GROUP_DELETED: &str = "scim_group_deleted";
pub const USER_DELETED: &str = "scim_user_deleted";

fn off() -> ScimError {
    ScimError::new(
        StatusCode::NOT_IMPLEMENTED,
        None,
        "Group provisioning is off on this server (SCIM_GROUPS=on makes groups teams). Turn group provisioning off for this app, or ask the server's admins.",
    )
}

fn conflict(e: ScimGroupConflict) -> ScimError {
    match e {
        ScimGroupConflict::DisplayName => ScimError::new(StatusCode::CONFLICT, Some("uniqueness"), "Another group in this tenant has this displayName."),
        ScimGroupConflict::ExternalId => ScimError::new(StatusCode::CONFLICT, Some("uniqueness"), "Another group in this tenant has this externalId."),
        ScimGroupConflict::Gone => missing("Group"),
        ScimGroupConflict::Db(e) => {
            crate::obs::log::log_warn!("scim: database error: {e}");
            server_error("Database error")
        }
    }
}

fn from_api(e: ApiError) -> ScimError {
    let kind = (e.0 == StatusCode::CONFLICT).then_some("uniqueness");
    ScimError::new(e.0, kind, e.1)
}

// Discovery.

pub fn resource_type(base: &str) -> Value {
    json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"],
        "id": "Group", "name": "Group", "endpoint": "/Groups", "description": "Teams: each group's members are one SuperBot team",
        "schema": GROUP_SCHEMA, "schemaExtensions": [],
        "meta": { "resourceType": "ResourceType", "location": format!("{base}/ResourceTypes/Group") },
    })
}

pub fn schema(base: &str) -> Value {
    let mut members = scim::attribute("members", "complex", false, "none", "The team's members: users this tenant provisioned");
    members["multiValued"] = json!(true);
    members["subAttributes"] = json!([
        scim::attribute("value", "string", true, "none", "The user's SCIM id"),
        scim::attribute("display", "string", false, "none", "The user's name"),
        scim::attribute("$ref", "reference", false, "none", "The user's URI"),
    ]);
    json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Schema"],
        "id": GROUP_SCHEMA, "name": "Group", "description": "A SuperBot team",
        "attributes": [scim::attribute("displayName", "string", true, "server", "Unique in the tenant, any case; the team's name"), members],
        "meta": { "resourceType": "Schema", "location": format!("{base}/Schemas/{GROUP_SCHEMA}") },
    })
}

// Resources.

/// Whether a request wants `members` back: not when `excludedAttributes` names it, or
/// `attributes` doesn't. Entra asks for groups with `excludedAttributes=members`.
fn wants_members(q: &HashMap<String, String>) -> bool {
    let get = |k: &str| q.iter().find(|(name, _)| name.eq_ignore_ascii_case(k)).map(|(_, v)| v.as_str());
    let names = |v: &str| v.split(',').map(|a| scim::normal_path_in(a, GROUP_SCHEMA)).collect::<Vec<_>>();
    if get("excludedAttributes").is_some_and(|v| names(v).iter().any(|a| a == "members")) {
        return false;
    }
    get("attributes").filter(|v| !v.trim().is_empty()).is_none_or(|v| names(v).iter().any(|a| a == "members" || a.starts_with("members.")))
}

pub fn resource(app: &AppState, base: &str, g: &ScimGroup, members: bool) -> Value {
    let mut v = json!({
        "schemas": [GROUP_SCHEMA],
        "id": g.team.id,
        "displayName": g.display_name,
        "meta": { "resourceType": "Group", "created": rfc3339(g.created_at), "lastModified": rfc3339(g.updated_at.max(g.team.updated_at)), "location": format!("{base}/Groups/{}", g.team.id) },
    });
    if let Some(x) = &g.external_id {
        v["externalId"] = json!(x);
    }
    if members {
        let list: Vec<Value> = app
            .db
            .team_members(&g.team.id)
            .iter()
            .map(|m| json!({ "value": m.user_id, "display": app.db.user(&m.user_id).map(|u| u.name), "type": "User", "$ref": format!("{base}/Users/{}", m.user_id) }))
            .collect();
        v["members"] = json!(list);
    }
    v
}

/// A group as the IdP wants it: its name, `externalId`, and members by SCIM user id, in
/// the order sent, each once.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Want {
    pub display_name: String,
    pub external_id: Option<String>,
    pub members: Vec<String>,
}

impl Want {
    fn of(app: &AppState, g: &ScimGroup) -> Want {
        Want { display_name: g.display_name.clone(), external_id: g.external_id.clone(), members: app.db.team_members(&g.team.id).into_iter().map(|m| m.user_id).collect() }
    }

    fn add(&mut self, ids: Vec<String>) {
        for id in ids {
            if !self.members.contains(&id) {
                self.members.push(id);
            }
        }
    }
}

fn display_name(v: &Value) -> ScimRes<String> {
    text(v, "displayName", 256)?.ok_or_else(|| invalid("displayName is required"))
}

/// `members`: a list of `{value}` objects. Missing or null is none.
fn member_ids(v: &Value) -> ScimRes<Vec<String>> {
    let list = match v {
        Value::Null => return Ok(vec![]),
        Value::Array(l) => l,
        _ => return Err(invalid("members must be a list")),
    };
    let mut ids = Vec::new();
    for m in list {
        if !m.is_object() {
            return Err(invalid("Each member must be an object with a value"));
        }
        let id = text(attr(m, "value"), "members.value", 256)?.ok_or_else(|| invalid("Each member needs a value: the user's SCIM id"))?;
        if !ids.contains(&id) {
            ids.push(id);
        }
    }
    Ok(ids)
}

/// The group of a POST or PUT body. A PUT's `externalId` left out is kept.
pub fn from_resource(v: &Value, current: Option<&Want>) -> ScimRes<Want> {
    if !v.is_object() {
        return Err(ScimError::new(StatusCode::BAD_REQUEST, Some("invalidSyntax"), "Send the group as a JSON object"));
    }
    Ok(Want {
        display_name: display_name(attr(v, "displayName"))?,
        external_id: text(attr(v, "externalId"), "externalId", 256)?.or_else(|| current.and_then(|c| c.external_id.clone())),
        members: member_ids(attr(v, "members"))?,
    })
}

/// A member filter path, `members[value eq "<id>"]`: the id. Read from the path as sent,
/// since ids are case-sensitive.
fn member_path(path: &str) -> Option<ScimRes<String>> {
    let p = path.trim();
    let p = p.get(..GROUP_SCHEMA.len() + 1).filter(|x| x.eq_ignore_ascii_case(&format!("{GROUP_SCHEMA}:"))).map_or(p, |x| &p[x.len()..]);
    let inner = p.get(..8).filter(|x| x.eq_ignore_ascii_case("members[")).and(p.strip_suffix(']')).map(|x| &x[8..])?;
    let unsupported = || "Unsupported member filter: only members[value eq \"...\"]".to_string();
    Some(match scim::parse_eq(inner, GROUP_SCHEMA, &unsupported) {
        Ok((a, id)) if a == "value" => Ok(id),
        _ => Err(ScimError::new(StatusCode::BAD_REQUEST, Some("invalidFilter"), unsupported())),
    })
}

/// Applies a PatchOp (RFC 7644 section 3.5.2) as Entra ID and Okta send them: `add`,
/// `replace` and `remove` of `members` (a list; `remove` without one empties the group),
/// `remove` of `members[value eq "<id>"]`, and `add` or `replace` of `displayName` and
/// `externalId`. With no path, the value is an object of those attributes (Okta's
/// rename). `op` is any case. Other attributes are ignored.
pub fn apply_patch(w: &mut Want, v: &Value) -> ScimRes<()> {
    let syntax = |d: &str| ScimError::new(StatusCode::BAD_REQUEST, Some("invalidSyntax"), d);
    let ops = key(v, "Operations").and_then(Value::as_array).filter(|o| !o.is_empty()).ok_or_else(|| syntax("Operations must be a list of operations"))?;
    for op in ops {
        let kind = attr(op, "op").as_str().map(str::to_ascii_lowercase);
        let kind = match kind.as_deref() {
            Some(k @ ("add" | "replace" | "remove")) => k.to_string(),
            _ => return Err(syntax("op must be add, replace, or remove")),
        };
        let value = attr(op, "value");
        match attr(op, "path").as_str().map(str::trim).filter(|p| !p.is_empty()) {
            Some(path) => match member_path(path) {
                Some(id) if kind == "remove" => {
                    let id = id?;
                    w.members.retain(|m| *m != id);
                }
                Some(_) => return Err(invalid("A member filter path can only be removed; add members with the path members")),
                None => apply_path(w, &kind, path, value)?,
            },
            None if kind == "remove" => return Err(ScimError::new(StatusCode::BAD_REQUEST, Some("noTarget"), "remove needs a path")),
            None => {
                let obj = value.as_object().ok_or_else(|| syntax("Without a path, value must be an object of attributes"))?;
                let mut seen = HashSet::new();
                for (k, val) in obj {
                    if !seen.insert(scim::normal_path_in(k, GROUP_SCHEMA)) {
                        return Err(invalid(format!("{k} is sent more than once")));
                    }
                    apply_path(w, &kind, k, val)?;
                }
            }
        }
    }
    Ok(())
}

fn apply_path(w: &mut Want, op: &str, path: &str, v: &Value) -> ScimRes<()> {
    let remove = op == "remove";
    match scim::normal_path_in(path, GROUP_SCHEMA).as_str() {
        "displayname" if remove => return Err(invalid("displayName can't be removed")),
        "displayname" => w.display_name = display_name(v)?,
        "externalid" if remove => w.external_id = None,
        "externalid" => w.external_id = text(v, "externalId", 256)?,
        "members" if remove && v.is_null() => w.members.clear(),
        "members" if remove => {
            let gone = member_ids(v)?;
            w.members.retain(|m| !gone.contains(m));
        }
        "members" if op == "add" => w.add(member_ids(v)?),
        "members" => w.members = member_ids(v)?,
        _ => {}
    }
    Ok(())
}

// Changes.

/// Who `want` adds to and removes from the team, refused before anything changes if
/// someone added isn't a live user of this tenant, or is on another team.
fn plan(app: &AppState, c: &Caller, team_id: Option<&str>, want: &Want) -> ScimRes<(Vec<db::User>, Vec<String>)> {
    let now: Vec<String> = team_id.map(|t| app.db.team_members(t).into_iter().map(|m| m.user_id).collect()).unwrap_or_default();
    let mut add = Vec::new();
    for id in want.members.iter().filter(|id| !now.contains(id)) {
        let u = app.db.scim_user(&c.token.tenant, id).ok_or_else(|| invalid(format!("members: {id} isn't a user this tenant provisioned. Provision the user first.")))?;
        if app.db.team_id_of(id).is_some() {
            return Err(ScimError::new(
                StatusCode::CONFLICT,
                Some("uniqueness"),
                format!("members: {id} is on another team. A person is on one team at most: assign SuperBot only the groups that are teams, or remove them from the other group first."),
            ));
        }
        add.push(u.user);
    }
    let remove = now.into_iter().filter(|id| !want.members.contains(id)).collect();
    Ok((add, remove))
}

/// Puts `add` on the team together, or none of them if one joined another team since
/// [`plan`]: run before any other change, so a refused request changes nothing.
fn reserve(app: &AppState, c: &Caller, team: &db::Team, add: &[db::User]) -> ScimRes<Vec<String>> {
    crate::teams::scim_reserve(app, &c.who, team, add).map_err(from_api)
}

/// Takes `remove` off the team and finishes joining `add`, already [`reserve`]d.
async fn apply_members(app: &AppState, c: &Caller, team: &db::Team, add: &[db::User], tiers: &[String], remove: &[String]) {
    for id in remove {
        crate::teams::leave_as(app, &c.who, &team.id, id, REMOVED, false).await;
    }
    for (u, tier) in add.iter().zip(tiers) {
        if let Err(e) = crate::teams::scim_join(app, &c.who, team, u, tier).await {
            crate::obs::log::log_warn!("scim: {} joined team {} without finishing: {}", u.id, team.id, e.1);
        }
    }
}

fn need(app: &AppState, c: &Caller, id: &str) -> ScimRes<ScimGroup> {
    app.db.scim_group(&c.token.tenant, id).ok_or_else(|| missing("Group"))
}

/// Sets the group to `want`: its name and `externalId`, then its members. `externalId`
/// can be set once, never changed.
async fn update(app: &AppState, c: &Caller, g: &ScimGroup, want: &Want) -> ScimRes<ScimGroup> {
    if let Some(old) = g.external_id.as_deref()
        && want.external_id.as_deref() != Some(old)
    {
        return Err(ScimError::new(StatusCode::BAD_REQUEST, Some("mutability"), "externalId can't change once set. Delete the group and provision it again."));
    }
    let (add, remove) = plan(app, c, Some(&g.team.id), want)?;
    let tiers = reserve(app, c, &g.team, &add)?;
    if want.display_name != g.display_name || want.external_id != g.external_id {
        if let Err(e) = app.db.save_scim_group(&c.token.tenant, &g.team.id, &want.display_name, want.external_id.as_deref()) {
            crate::teams::scim_unreserve(app, &g.team, &add);
            return Err(conflict(e));
        }
        let mut changes = serde_json::Map::new();
        if want.display_name != g.display_name {
            changes.insert("displayName".into(), json!({ "from": g.display_name, "to": want.display_name }));
        }
        if want.external_id != g.external_id {
            changes.insert("externalId".into(), json!({ "from": g.external_id, "to": want.external_id }));
        }
        app.db.record(&group_event(c, "scim.group_updated", &g.team.id, json!({ "changes": changes })));
    }
    apply_members(app, c, &g.team, &add, &tiers, &remove).await;
    need(app, c, &g.team.id)
}

fn group_event(c: &Caller, action: &str, team_id: &str, details: Value) -> crate::audit::Event {
    let mut d = json!({ "tenant": c.token.tenant, "team": team_id });
    if let (Some(d), Value::Object(x)) = (d.as_object_mut(), details) {
        d.extend(x);
    }
    c.who.event(action).target("team", team_id).details(d)
}

// Handlers.

/// `GET /scim/v2/Groups?filter=&startIndex=&count=&excludedAttributes=`: the tenant's
/// groups. Off, an empty list, so IdPs' connection tests pass.
pub async fn list_groups(State(app): State<AppState>, Extension(a): Extension<Arc<Auth>>, Extension(c): Extension<Caller>, headers: HeaderMap, Query(q): Query<HashMap<String, String>>) -> ScimRes {
    let (start, count) = page(&q)?;
    if !a.scim.groups {
        return Ok(list(vec![], 0, start));
    }
    let filter = q.iter().find(|(k, _)| k.eq_ignore_ascii_case("filter")).map(|(_, v)| v.as_str()).filter(|f| !f.trim().is_empty());
    let key = filter.map(parse_filter).transpose().map_err(|e| ScimError::new(StatusCode::BAD_REQUEST, Some("invalidFilter"), e))?;
    let (total, groups) = app.db.scim_groups(&c.token.tenant, key.as_ref(), start - 1, count);
    let (base, members) = (base_url(&headers), wants_members(&q));
    Ok(list(groups.iter().map(|g| resource(&app, &base, g, members)).collect(), total, start))
}

/// Only `displayName eq "..."` (any case) and `externalId eq "..."` (exact).
pub fn parse_filter(s: &str) -> Result<ScimGroupKey, String> {
    let unsupported = || format!("Unsupported filter: only displayName eq \"...\" and externalId eq \"...\" are supported, not {}", s.trim().chars().take(100).collect::<String>());
    match scim::parse_eq(s, GROUP_SCHEMA, &unsupported)? {
        (a, v) if a == "displayname" => Ok(ScimGroupKey::DisplayName(v)),
        (a, v) if a == "externalid" => Ok(ScimGroupKey::ExternalId(v)),
        _ => Err(unsupported()),
    }
}

pub async fn get_group(State(app): State<AppState>, Extension(a): Extension<Arc<Auth>>, Extension(c): Extension<Caller>, headers: HeaderMap, Path(id): Path<String>, Query(q): Query<HashMap<String, String>>) -> ScimRes {
    if !a.scim.groups {
        return Err(missing("Group"));
    }
    Ok(scim_json(StatusCode::OK, resource(&app, &base_url(&headers), &need(&app, &c, &id)?, wants_members(&q))))
}

/// `POST /scim/v2/Groups`: a new team, with the members sent. A `displayName` or
/// `externalId` the tenant has already is a 409, so a retry makes no second team.
pub async fn create_group(State(app): State<AppState>, Extension(a): Extension<Arc<Auth>>, Extension(c): Extension<Caller>, headers: HeaderMap, body: Result<Bytes, BytesRejection>) -> ScimRes {
    if !a.scim.groups {
        return Err(off());
    }
    let want = from_resource(&parse_body(body)?, None)?;
    let _one = a.scim.group_writes.lock().await;
    let tenant = c.token.tenant.as_str();
    if let Some(ext) = &want.external_id
        && let Some(g) = app.db.scim_group_find(tenant, &ScimGroupKey::ExternalId(ext.clone()))
    {
        return Err(ScimError::new(StatusCode::CONFLICT, Some("uniqueness"), format!("A group with this externalId exists already: {}", g.team.id)));
    }
    if app.db.scim_group_find(tenant, &ScimGroupKey::DisplayName(want.display_name.clone())).is_some() {
        return Err(conflict(ScimGroupConflict::DisplayName));
    }
    let (add, _) = plan(&app, &c, None, &want)?;
    let team = app.db.create_scim_team(tenant, &want.display_name, want.external_id.as_deref(), c.who.actor.id.as_deref()).map_err(conflict)?;
    let tiers = match reserve(&app, &c, &team, &add) {
        Ok(t) => t,
        Err(e) => {
            app.db.unlink_scim_group(tenant, &team.id);
            app.db.delete_team(&team.id);
            return Err(e);
        }
    };
    app.db.record(&group_event(&c, "team.created", &team.id, json!({ "name": team.name, "machines": team.machines, "via": crate::teams::SCIM })));
    app.db.record(&group_event(&c, "scim.group_created", &team.id, json!({ "displayName": want.display_name, "externalId": want.external_id, "members": add.len() })));
    apply_members(&app, &c, &team, &add, &tiers, &[]).await;
    let body = resource(&app, &base_url(&headers), &need(&app, &c, &team.id)?, true);
    let mut r = scim_json(StatusCode::CREATED, body.clone());
    if let Some(Ok(at)) = body["meta"]["location"].as_str().map(HeaderValue::from_str) {
        r.headers_mut().insert(header::LOCATION, at);
    }
    Ok(r)
}

/// `PUT /scim/v2/Groups/{id}`: the whole group, its members included.
pub async fn replace_group(State(app): State<AppState>, Extension(a): Extension<Arc<Auth>>, Extension(c): Extension<Caller>, headers: HeaderMap, Path(id): Path<String>, body: Result<Bytes, BytesRejection>) -> ScimRes {
    if !a.scim.groups {
        return Err(off());
    }
    let v = parse_body(body)?;
    let _one = a.scim.group_writes.lock().await;
    let g = need(&app, &c, &id)?;
    let want = from_resource(&v, Some(&Want::of(&app, &g)))?;
    let after = update(&app, &c, &g, &want).await?;
    Ok(scim_json(StatusCode::OK, resource(&app, &base_url(&headers), &after, true)))
}

/// `PATCH /scim/v2/Groups/{id}`: what Entra ID and Okta send to add and remove members
/// and rename a group. Adding someone already on it, or removing someone who isn't, is
/// a no-op, so a retried PATCH changes nothing twice.
pub async fn patch_group(
    State(app): State<AppState>,
    Extension(a): Extension<Arc<Auth>>,
    Extension(c): Extension<Caller>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Query(q): Query<HashMap<String, String>>,
    body: Result<Bytes, BytesRejection>,
) -> ScimRes {
    if !a.scim.groups {
        return Err(off());
    }
    let v = parse_body(body)?;
    let _one = a.scim.group_writes.lock().await;
    let g = need(&app, &c, &id)?;
    let mut want = Want::of(&app, &g);
    apply_patch(&mut want, &v)?;
    let after = update(&app, &c, &g, &want).await?;
    Ok(scim_json(StatusCode::OK, resource(&app, &base_url(&headers), &after, wants_members(&q))))
}

/// `DELETE /scim/v2/Groups/{id}`: everyone leaves the team, then it goes. A team that
/// pays for a plan (ADR 0093) is kept, empty and no longer the tenant's, until a server
/// admin ends it: its people lose access at once either way.
pub async fn delete_group(State(app): State<AppState>, Extension(a): Extension<Arc<Auth>>, Extension(c): Extension<Caller>, Path(id): Path<String>) -> ScimRes {
    if !a.scim.groups {
        return Err(off());
    }
    let _one = a.scim.group_writes.lock().await;
    let g = need(&app, &c, &id)?;
    let members = app.db.team_members(&g.team.id);
    for m in &members {
        crate::teams::leave_as(&app, &c.who, &g.team.id, &m.user_id, GROUP_DELETED, false).await;
    }
    if !app.db.unlink_scim_group(&c.token.tenant, &g.team.id) {
        return Err(missing("Group"));
    }
    let deleted = match crate::team_billing::may_delete(&app, &c.who, &g.team.id, crate::teams::SCIM).await {
        Ok(_held) => app.db.delete_team(&g.team.id),
        Err(_) => false,
    };
    if deleted {
        app.db.record(&group_event(&c, "team.deleted", &g.team.id, json!({ "name": g.team.name, "reason": crate::teams::SCIM })));
    }
    app.db.record(&group_event(
        &c,
        "scim.group_deleted",
        &g.team.id,
        json!({ "displayName": g.display_name, "externalId": g.external_id, "membersRemoved": members.len(), "teamDeleted": deleted }),
    ));
    Ok(StatusCode::NO_CONTENT.into_response())
}

/// After the tenant deletes a user: off the team its group put them on.
pub async fn user_deleted(app: &AppState, a: &Auth, c: &Caller, user_id: &str) {
    let _one = a.scim.group_writes.lock().await;
    if let Some(team) = app.db.team_id_of(user_id)
        && app.db.scim_group(&c.token.tenant, &team).is_some()
    {
        crate::teams::leave_as(app, &c.who, &team, user_id, USER_DELETED, false).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn want() -> Want {
        Want { display_name: "Eng".into(), external_id: None, members: vec!["u1".into(), "u2".into()] }
    }

    #[test]
    fn groups_are_read_strictly() {
        let w = from_resource(&json!({ "schemas": [GROUP_SCHEMA], "displayName": "Eng", "externalId": "g-1", "members": [{ "value": "u1", "display": "Ada" }, { "value": "u1" }] }), None).unwrap();
        assert_eq!(w, Want { display_name: "Eng".into(), external_id: Some("g-1".into()), members: vec!["u1".into()] });
        let put = from_resource(&json!({ "DisplayName": "Eng 2" }), Some(&w)).unwrap();
        assert_eq!((put.external_id.as_deref(), put.members.len()), (Some("g-1"), 0), "PUT keeps externalId and replaces members");
        for bad in [
            json!([]),
            json!({}),
            json!({ "displayName": " " }),
            json!({ "displayName": "x".repeat(257) }),
            json!({ "displayName": "Eng", "members": "u1" }),
            json!({ "displayName": "Eng", "members": ["u1"] }),
            json!({ "displayName": "Eng", "members": [{ "display": "Ada" }] }),
        ] {
            assert!(from_resource(&bad, None).is_err(), "{bad}");
        }
    }

    #[test]
    fn patches_follow_entra_and_okta() {
        let mut w = want();
        // Entra: capitalized ops, members added and removed as lists, and by filter.
        apply_patch(
            &mut w,
            &json!({ "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"], "Operations": [
                { "op": "Add", "path": "members", "value": [{ "value": "u3" }, { "value": "u1" }] },
                { "op": "Remove", "path": "members", "value": [{ "value": "u2" }] },
                { "op": "Replace", "path": "displayName", "value": "Engineering" },
            ]}),
        )
        .unwrap();
        assert_eq!((w.display_name.as_str(), w.members.clone()), ("Engineering", vec!["u1".to_string(), "u3".to_string()]));
        // Okta: a member removed by filter, a rename without a path, members replaced.
        apply_patch(&mut w, &json!({ "Operations": [{ "op": "remove", "path": "members[value eq \"u3\"]" }] })).unwrap();
        assert_eq!(w.members, vec!["u1".to_string()]);
        apply_patch(&mut w, &json!({ "Operations": [{ "op": "replace", "value": { "id": "t1", "displayName": "Eng" } }] })).unwrap();
        assert_eq!(w.display_name, "Eng");
        apply_patch(&mut w, &json!({ "Operations": [{ "op": "replace", "path": "members", "value": [{ "value": "U9" }] }] })).unwrap();
        assert_eq!(w.members, vec!["U9".to_string()], "ids keep their case");
        apply_patch(&mut w, &json!({ "Operations": [{ "op": "remove", "path": "urn:ietf:params:scim:schemas:core:2.0:Group:members[value eq \"U9\"]" }] })).unwrap();
        assert!(w.members.is_empty());
        // Idempotent: removing who isn't there, adding who is.
        let mut x = want();
        apply_patch(&mut x, &json!({ "Operations": [{ "op": "remove", "path": "members[value eq \"nobody\"]" }, { "op": "add", "path": "members", "value": [{ "value": "u1" }] }] })).unwrap();
        assert_eq!(x, want());
        apply_patch(&mut x, &json!({ "Operations": [{ "op": "remove", "path": "members" }] })).unwrap();
        assert!(x.members.is_empty(), "remove without a value empties the group");
        apply_patch(&mut x, &json!({ "Operations": [{ "op": "add", "path": "externalId", "value": "g-1" }, { "op": "add", "path": "title", "value": "ignored" }] })).unwrap();
        assert_eq!(x.external_id.as_deref(), Some("g-1"));
        for bad in [
            json!({}),
            json!({ "Operations": [] }),
            json!({ "Operations": [{ "op": "move", "path": "members", "value": [] }] }),
            json!({ "Operations": [{ "op": "remove" }] }),
            json!({ "Operations": [{ "op": "remove", "path": "displayName" }] }),
            json!({ "Operations": [{ "op": "replace", "path": "displayName", "value": "" }] }),
            json!({ "Operations": [{ "op": "add", "path": "members[value eq \"u1\"]", "value": [] }] }),
            json!({ "Operations": [{ "op": "remove", "path": "members[display eq \"Ada\"]" }] }),
            json!({ "Operations": [{ "op": "remove", "path": "members[value eq u1]" }] }),
            json!({ "Operations": [{ "op": "add", "path": "members", "value": { "value": "u1" } }] }),
            json!({ "Operations": [{ "op": "replace", "value": { "displayName": "a", "DISPLAYNAME": "b" } }] }),
        ] {
            assert!(apply_patch(&mut want(), &bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn filters_and_attributes() {
        assert_eq!(parse_filter(r#"displayName eq "Eng""#), Ok(ScimGroupKey::DisplayName("Eng".into())));
        assert_eq!(parse_filter(r#"urn:ietf:params:scim:schemas:core:2.0:Group:externalId eq "g1""#), Ok(ScimGroupKey::ExternalId("g1".into())));
        for bad in ["", r#"userName eq "a""#, r#"displayName co "a""#, r#"displayName eq "a" and members[value eq "u1"]"#] {
            assert!(parse_filter(bad).is_err(), "{bad}");
        }
        let q = |k: &str, v: &str| HashMap::from([(k.to_string(), v.to_string())]);
        assert!(wants_members(&HashMap::new()));
        assert!(!wants_members(&q("excludedAttributes", "members")));
        assert!(!wants_members(&q("excludedAttributes", "displayName, Members")));
        assert!(!wants_members(&q("attributes", "displayName")));
        assert!(wants_members(&q("attributes", "displayName,members.value")));
    }
}
