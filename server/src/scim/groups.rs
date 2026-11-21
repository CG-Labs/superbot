//! SCIM 2.0 Groups as SuperBot teams (RFC 7643 section 4.2, ADR 0095). A tenant's group
//! is a team: one the IdP created with `POST /Groups`, or one an admin linked to the
//! tenant (`botctl scim group link`) for the IdP to take on. The group's members are
//! the team's members this tenant provisioned; people it didn't provision are never
//! touched, and never shown. Joining and leaving go through the same code as a team
//! admin's add and remove, so offboarding (ADR 0052, 0066) and team billing's seats
//! (ADR 0093) follow. SCIM never gives a team role: members join as `member`, and a
//! team the IdP made has no owner until a server admin names one. Off unless
//! SCIM_GROUPS=on as well as SCIM=on.

use super::*;
use crate::db::{ScimGroup, ScimGroupConflict, Team};
use crate::teams;
use std::collections::HashSet;

pub const GROUP_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:Group";
/// An Okta PUT carries the whole member list: about 100 bytes a member.
pub const MAX_BODY: usize = 1024 * 1024;
/// Entra ID allows group names up to 256 characters; a team's name is the first 100.
const MAX_NAME: usize = 256;
const TEAM_NAME: usize = 100;

fn off() -> ScimError {
    ScimError::new(StatusCode::NOT_IMPLEMENTED, None, "Group provisioning is off on this server (SCIM_GROUPS=on turns it on). Turn group provisioning off for this app, or ask the server's admins.")
}

fn group_conflict(e: ScimGroupConflict) -> ScimError {
    match e {
        ScimGroupConflict::DisplayName => uniqueness("Another group in this tenant has this displayName."),
        ScimGroupConflict::ExternalId => uniqueness("Another group in this tenant has this externalId."),
        ScimGroupConflict::Team => uniqueness("This team is another group already."),
        ScimGroupConflict::Gone => missing("Group"),
        ScimGroupConflict::Db(e) => {
            crate::obs::log::log_warn!("scim: database error: {e}");
            server_error("Database error")
        }
    }
}

// Filters: what Entra ID and Okta send to find a group, or to check a membership.

#[derive(Clone, Debug, PartialEq)]
pub enum Clause {
    Id(String),
    DisplayName(String),
    ExternalId(String),
    Member(String),
}

/// `s` split at each `and` outside quotes and brackets.
fn split_and(s: &str) -> Vec<&str> {
    let b = s.as_bytes();
    let (mut parts, mut start, mut i) = (Vec::new(), 0, 0);
    let (mut depth, mut quoted, mut escaped) = (0i32, false, false);
    while i < b.len() {
        let c = b[i];
        if quoted {
            match c {
                _ if escaped => escaped = false,
                b'\\' => escaped = true,
                b'"' => quoted = false,
                _ => {}
            }
        } else if c == b'"' {
            quoted = true;
        } else if c == b'[' {
            depth += 1;
        } else if c == b']' {
            depth -= 1;
        } else if depth == 0 && c.is_ascii_whitespace() {
            let rest = s[i..].trim_start();
            let after = rest.as_bytes().get(3);
            if rest.get(..3).is_some_and(|w| w.eq_ignore_ascii_case("and")) && after.is_some_and(u8::is_ascii_whitespace) {
                parts.push(&s[start..i]);
                i = s.len() - rest.len() + 3;
                start = i;
                continue;
            }
        }
        i += 1;
    }
    parts.push(&s[start..]);
    parts
}

/// One or more `attr eq "value"` joined by `and`: `displayName` (any ASCII case),
/// `externalId` and `id` (exactly), and a member as `members eq`, `members.value eq`,
/// or `members[value eq "..."]`.
pub fn parse_filter(s: &str) -> Result<Vec<Clause>, String> {
    let unsupported = || {
        format!(
            "Unsupported filter: only displayName, externalId, id, and members eq \"...\", joined with and, are supported, not {}",
            s.trim().chars().take(100).collect::<String>()
        )
    };
    let mut out = Vec::new();
    for part in split_and(s.trim()) {
        let part = part.trim();
        let lower = part.to_ascii_lowercase();
        if lower.starts_with("members[") {
            let inner = part.strip_suffix(']').map(|p| &p["members[".len()..]).ok_or_else(unsupported)?;
            let (attr, v) = attr_eq(inner).map_err(|e| e.unwrap_or_else(unsupported))?;
            if !attr.eq_ignore_ascii_case("value") {
                return Err(unsupported());
            }
            out.push(Clause::Member(v));
            continue;
        }
        let (attr, v) = attr_eq(part).map_err(|e| e.unwrap_or_else(unsupported))?;
        let attr = strip_schema(attr, GROUP_SCHEMA);
        out.push(match attr.to_ascii_lowercase().as_str() {
            "id" => Clause::Id(v),
            "displayname" => Clause::DisplayName(v),
            "externalid" => Clause::ExternalId(v),
            "members" | "members.value" => Clause::Member(v),
            _ => return Err(unsupported()),
        });
    }
    Ok(out)
}

fn matches(app: &AppState, g: &ScimGroup, clauses: &[Clause]) -> bool {
    clauses.iter().all(|c| match c {
        Clause::Id(v) => g.team_id == *v,
        // ASCII case only, as the database's NOCASE uniqueness and lookups compare.
        Clause::DisplayName(v) => g.display_name.eq_ignore_ascii_case(v),
        Clause::ExternalId(v) => g.external_id.as_deref() == Some(v.as_str()),
        Clause::Member(v) => app.db.team_id_of(v).as_deref() == Some(g.team_id.as_str()) && app.db.scim_user(&g.tenant, v).is_some(),
    })
}

// Resources.

/// Whether a GET wants `members`: not with `excludedAttributes=members` (Entra ID's
/// lookups), nor with an `attributes` list that leaves it out.
fn wants_members(q: &HashMap<String, String>) -> bool {
    let named = |k: &str| {
        q.iter().find(|(n, _)| n.eq_ignore_ascii_case(k)).map(|(_, v)| v.split(',').any(|a| strip_schema(a.trim(), GROUP_SCHEMA).eq_ignore_ascii_case("members")))
    };
    named("excludedAttributes") != Some(true) && named("attributes") != Some(false)
}

/// A group as SCIM shows it. `members` are the team's members this tenant provisioned.
pub fn resource(app: &AppState, base: &str, g: &ScimGroup, members: bool) -> Value {
    let mut v = json!({
        "schemas": [GROUP_SCHEMA],
        "id": g.team_id,
        "displayName": g.display_name,
        "meta": { "resourceType": "Group", "created": rfc3339(g.created_at), "lastModified": rfc3339(g.updated_at), "location": format!("{base}/Groups/{}", g.team_id) },
    });
    if let Some(x) = &g.external_id {
        v["externalId"] = json!(x);
    }
    if members {
        let list: Vec<Value> =
            app.db.scim_group_members(&g.tenant, &g.team_id, false).iter().map(|u| json!({ "value": u.id, "display": u.name, "type": "User", "$ref": format!("{base}/Users/{}", u.id) })).collect();
        v["members"] = json!(list);
    }
    v
}

fn group_resource_type(base: &str) -> Value {
    json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"],
        "id": "Group", "name": "Group", "endpoint": "/Groups", "description": "SuperBot teams",
        "schema": GROUP_SCHEMA, "schemaExtensions": [],
        "meta": { "resourceType": "ResourceType", "location": format!("{base}/ResourceTypes/Group") },
    })
}

fn group_schema(base: &str) -> Value {
    let mut members = attribute("members", "complex", false, "none", "The people on the team this tenant provisioned. Others on the team are never shown or changed.");
    members["multiValued"] = json!(true);
    let mut reference = attribute("$ref", "reference", false, "none", "The user's location");
    reference["referenceTypes"] = json!(["User"]);
    reference["mutability"] = json!("immutable");
    let mut value = attribute("value", "string", true, "none", "The id of a user this tenant provisioned");
    value["mutability"] = json!("immutable");
    let mut display = attribute("display", "string", false, "none", "The user's name");
    display["mutability"] = json!("readOnly");
    members["subAttributes"] = json!([value, display, reference, attribute("type", "string", false, "none", "User; groups in groups aren't supported")]);
    json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Schema"],
        "id": GROUP_SCHEMA, "name": "Group", "description": "A SuperBot team",
        "attributes": [attribute("displayName", "string", true, "server", "Unique in the tenant, any case; the team's name"), members],
        "meta": { "resourceType": "Schema", "location": format!("{base}/Schemas/{GROUP_SCHEMA}") },
    })
}

/// What discovery adds while groups are on.
pub fn resource_types(a: &Auth, base: &str) -> Vec<Value> {
    if a.scim.groups { vec![group_resource_type(base)] } else { vec![] }
}

pub fn resource_type(a: &Auth, base: &str, id: &str) -> Option<Value> {
    (a.scim.groups && id == "Group").then(|| group_resource_type(base))
}

pub fn schemas(a: &Auth, base: &str) -> Vec<Value> {
    if a.scim.groups { vec![group_schema(base)] } else { vec![] }
}

pub fn schema(a: &Auth, base: &str, id: &str) -> Option<Value> {
    (a.scim.groups && id == GROUP_SCHEMA).then(|| group_schema(base))
}

// Reading requests.

/// A group as a POST or PUT sends it. `members` is None when the body leaves it out.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Doc {
    pub display_name: String,
    pub external_id: Option<String>,
    pub members: Option<Vec<String>>,
}

fn display_name(v: &Value) -> ScimRes<String> {
    text(v, "displayName", MAX_NAME)?.ok_or_else(|| invalid("displayName is required"))
}

/// Member ids from a list of `{value, display?, type?, $ref?}`. Groups in groups aren't
/// supported. Each id once, in the order sent.
fn member_ids(v: &Value) -> ScimRes<Vec<String>> {
    let list = match v {
        Value::Null => return Ok(vec![]),
        Value::Array(l) => l.as_slice(),
        Value::Object(_) => std::slice::from_ref(v),
        _ => return Err(invalid("members must be a list of {\"value\": \"<user id>\"}")),
    };
    let (mut out, mut seen) = (Vec::new(), HashSet::new());
    for m in list {
        if !m.is_object() {
            return Err(invalid("Each member must be an object with a value"));
        }
        if attr(m, "type").as_str().is_some_and(|t| t.eq_ignore_ascii_case("group")) {
            return Err(invalid("Groups in groups aren't supported: send the people instead."));
        }
        let id = text(attr(m, "value"), "members.value", 64)?.ok_or_else(|| invalid("Each member needs a value: the user's id"))?;
        if seen.insert(id.clone()) {
            out.push(id);
        }
    }
    Ok(out)
}

/// The group in a POST or PUT body. `current` is the group a PUT replaces: an
/// `externalId` the body leaves out is kept from it.
pub fn from_resource(v: &Value, current: Option<&ScimGroup>) -> ScimRes<Doc> {
    if !v.is_object() {
        return Err(ScimError::new(StatusCode::BAD_REQUEST, Some("invalidSyntax"), "Send the group as a JSON object"));
    }
    Ok(Doc {
        display_name: display_name(attr(v, "displayName"))?,
        external_id: text(attr(v, "externalId"), "externalId", 256)?.or_else(|| current.and_then(|c| c.external_id.clone())),
        members: match key(v, "members") {
            None => None,
            Some(m) => Some(member_ids(m)?),
        },
    })
}

/// A group being patched: its attributes, and its members as a set, with the order
/// people were added in.
#[derive(Clone, Debug)]
pub struct Patched {
    pub display_name: String,
    pub external_id: Option<String>,
    pub members: HashSet<String>,
    order: Vec<String>,
}

impl Patched {
    pub fn new(display_name: &str, external_id: Option<&str>, members: &[String]) -> Patched {
        Patched { display_name: display_name.into(), external_id: external_id.map(String::from), members: members.iter().cloned().collect(), order: members.to_vec() }
    }

    fn add(&mut self, ids: Vec<String>) {
        for id in ids {
            if self.members.insert(id.clone()) {
                self.order.push(id);
            }
        }
    }

    fn remove(&mut self, ids: &[String]) {
        for id in ids {
            self.members.remove(id);
        }
    }

    fn replace(&mut self, ids: Vec<String>) {
        self.members.clear();
        self.add(ids);
    }

    /// Who comes off and who joins, from the members it started with: each once, in order.
    pub fn delta(&self, before: &[String]) -> (Vec<String>, Vec<String>) {
        let was: HashSet<&String> = before.iter().collect();
        let gone = before.iter().filter(|id| !self.members.contains(*id)).cloned().collect();
        let mut seen = HashSet::new();
        let new = self.order.iter().filter(|id| self.members.contains(*id) && !was.contains(id) && seen.insert(id.as_str())).cloned().collect();
        (gone, new)
    }
}

/// Applies a PatchOp to a group: `add`, `remove` and `replace` of `members` (Entra ID
/// sends `Add` and `Remove` with a list of `{value}`; Okta removes one by
/// `members[value eq "..."]` and can replace the whole list), and of `displayName` and
/// `externalId`. With no path, the value is an object of attributes (Okta's rename,
/// which also carries the `id`). Other attributes are ignored.
pub fn apply_patch(p: &mut Patched, v: &Value) -> ScimRes<()> {
    let syntax = |d: &str| ScimError::new(StatusCode::BAD_REQUEST, Some("invalidSyntax"), d);
    let ops = key(v, "Operations").and_then(Value::as_array).filter(|o| !o.is_empty()).ok_or_else(|| syntax("Operations must be a list of operations"))?;
    for op in ops {
        let kind = attr(op, "op").as_str().map(str::to_ascii_lowercase);
        let kind = match kind.as_deref() {
            Some(k @ ("add" | "replace" | "remove")) => k.to_string(),
            _ => return Err(syntax("op must be add, replace, or remove")),
        };
        let value = attr(op, "value");
        match attr(op, "path").as_str().map(str::trim).filter(|path| !path.is_empty()) {
            Some(path) => apply_path(p, &kind, path, value)?,
            None if kind == "remove" => return Err(ScimError::new(StatusCode::BAD_REQUEST, Some("noTarget"), "remove needs a path")),
            None => {
                let obj = value.as_object().ok_or_else(|| syntax("Without a path, value must be an object of attributes"))?;
                for (k, val) in obj {
                    apply_path(p, &kind, k, val)?;
                }
            }
        }
    }
    Ok(())
}

fn apply_path(p: &mut Patched, op: &str, path: &str, v: &Value) -> ScimRes<()> {
    let path = strip_schema(path, GROUP_SCHEMA);
    let normal = path.split_whitespace().collect::<Vec<_>>().join(" ");
    let lower = normal.to_ascii_lowercase();
    if lower.starts_with("members[") {
        let filter = normal.strip_suffix(']').map(|f| &f["members[".len()..]);
        let id = match filter.map(attr_eq) {
            Some(Ok((a, id))) if a.eq_ignore_ascii_case("value") => id,
            _ => return Err(ScimError::new(StatusCode::BAD_REQUEST, Some("invalidPath"), "Only members[value eq \"<user id>\"] is supported")),
        };
        if op != "remove" {
            return Err(ScimError::new(StatusCode::BAD_REQUEST, Some("invalidPath"), "A filtered members path can only be removed; add members with path members"));
        }
        p.remove(&[id]);
        return Ok(());
    }
    match (lower.as_str(), op) {
        ("members", "add") => p.add(member_ids(v)?),
        ("members", "replace") => p.replace(member_ids(v)?),
        ("members", _) if v.is_null() => p.members.clear(),
        ("members", _) => p.remove(&member_ids(v)?),
        ("displayname", "remove") => return Err(invalid("displayName can't be removed")),
        ("displayname", _) => p.display_name = display_name(v)?,
        ("externalid", "remove") => p.external_id = None,
        ("externalid", _) => p.external_id = text(v, "externalId", 256)?,
        _ => {}
    }
    Ok(())
}

// Membership.

/// Refuses anyone the request would add who isn't a live user of this tenant (400), or
/// is on another team (409, audited): SCIM never moves people between teams. Nothing
/// has changed when this fails.
fn check_new(app: &AppState, c: &Caller, team_id: Option<&str>, new: &[String]) -> ScimRes<()> {
    let tenant = &c.token.tenant;
    if let Some(id) = new.iter().find(|id| app.db.scim_user(tenant, id).is_none()) {
        return Err(invalid(format!("{id} isn't a user this tenant provisioned. Provision the user first; SCIM groups only hold this tenant's users.")));
    }
    let elsewhere: Vec<&String> = new.iter().filter(|id| app.db.team_id_of(id).is_some_and(|t| Some(t.as_str()) != team_id)).collect();
    if !elsewhere.is_empty() {
        let mut e = c.who.event("scim.group_member_refused").outcome(Outcome::Denied).details(json!({ "tenant": tenant, "users": elsewhere, "reason": "other_team" }));
        if let Some(t) = team_id {
            e = e.target("team", t);
        }
        app.db.record(&e);
        return Err(uniqueness(format!(
            "{} {} on another SuperBot team. A person is on one team at most: take them off the other group (or team) first.",
            elsewhere.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", "),
            if elsewhere.len() == 1 { "is" } else { "are" }
        )));
    }
    Ok(())
}

/// What a membership change did, for the audit log.
#[derive(Default)]
struct Moved {
    added: Vec<String>,
    removed: Vec<String>,
    owner_left: bool,
}

/// Takes `gone` off the team and puts `new` on it, through the team's own join and
/// leave. A join refused by a race (someone joined another team meanwhile) stops there
/// with a 409; what was done stays done, and the IdP's retry finishes it.
async fn change_members(app: &AppState, c: &Caller, team: &Team, gone: &[String], new: &[String]) -> ScimRes<Moved> {
    let mut m = Moved::default();
    for id in gone {
        let owner = app.db.team_member(id).is_some_and(|x| x.team_id == team.id && x.role == teams::OWNER);
        if teams::leave(app, &c.who, &team.id, id, teams::SCIM).await {
            m.owner_left |= owner;
            m.removed.push(id.clone());
        }
    }
    for id in new {
        let Some(u) = app.db.user(id) else { continue };
        match teams::join_from_scim(app, &c.who, team, &u).await {
            Ok(_) => m.added.push(id.clone()),
            Err(e) if e.0 == StatusCode::CONFLICT && app.db.team_id_of(id).as_deref() == Some(team.id.as_str()) => {}
            Err(e) => return Err(uniqueness(format!("{id}: {}", e.1))),
        }
    }
    Ok(m)
}

fn need(app: &AppState, c: &Caller, id: &str) -> ScimRes<(ScimGroup, Team)> {
    let g = app.db.scim_group(&c.token.tenant, id).ok_or_else(|| missing("Group"))?;
    let t = app.db.team(&g.team_id).ok_or_else(|| missing("Group"))?;
    Ok((g, t))
}

fn team_name(display_name: &str) -> String {
    display_name.chars().take(TEAM_NAME).collect()
}

/// Audits what a PATCH or PUT changed: the group's attributes, who joined and left
/// (each also has its `team.member_joined` or `team.member_left`), and whether the
/// team lost its last owner, which a server admin has to replace.
fn record_update(app: &AppState, c: &Caller, before: &ScimGroup, after: &ScimGroup, moved: &Moved) {
    let mut changes = Map::new();
    for (k, from, to) in [("displayName", json!(before.display_name), json!(after.display_name)), ("externalId", json!(before.external_id), json!(after.external_id))] {
        if from != to {
            changes.insert(k.into(), json!({ "from": from, "to": to }));
        }
    }
    if changes.is_empty() && moved.added.is_empty() && moved.removed.is_empty() {
        return;
    }
    let rest = app.db.team_members(&after.team_id);
    let ownerless = moved.owner_left && !rest.is_empty() && !rest.iter().any(|m| m.role == teams::OWNER);
    app.db.record(&c.who.event("scim.group_updated").target("team", &after.team_id).details(json!({
        "tenant": after.tenant, "team": after.team_id, "changes": changes, "added": moved.added, "removed": moved.removed, "ownerless": ownerless,
    })));
}

// Handlers.

/// `GET /scim/v2/Groups?filter=&startIndex=&count=&excludedAttributes=`: the tenant's
/// groups, oldest first. Off, an empty list, so IdPs' connection tests pass.
pub async fn list(State(app): State<AppState>, Extension(a): Extension<Arc<Auth>>, Extension(c): Extension<Caller>, headers: HeaderMap, Query(q): Query<HashMap<String, String>>) -> ScimRes {
    let (start, count) = page(&q)?;
    if !a.scim.groups {
        return Ok(super::list(vec![], 0, start));
    }
    let filter = q.iter().find(|(k, _)| k.eq_ignore_ascii_case("filter")).map(|(_, v)| v.as_str()).filter(|f| !f.trim().is_empty());
    let clauses = filter.map(parse_filter).transpose().map_err(|e| ScimError::new(StatusCode::BAD_REQUEST, Some("invalidFilter"), e))?.unwrap_or_default();
    let all: Vec<ScimGroup> = app.db.scim_groups(&c.token.tenant).into_iter().filter(|g| matches(&app, g, &clauses)).collect();
    let base = base_url(&headers);
    let members = wants_members(&q);
    let page: Vec<Value> = all.iter().skip((start - 1) as usize).take(count as usize).map(|g| resource(&app, &base, g, members)).collect();
    Ok(super::list(page, all.len() as i64, start))
}

/// `GET /scim/v2/Groups/{id}`, with its members unless `excludedAttributes=members`.
pub async fn get(State(app): State<AppState>, Extension(a): Extension<Arc<Auth>>, Extension(c): Extension<Caller>, headers: HeaderMap, Path(id): Path<String>, Query(q): Query<HashMap<String, String>>) -> ScimRes {
    if !a.scim.groups {
        return Err(missing("Group"));
    }
    let (g, _) = need(&app, &c, &id)?;
    Ok(scim_json(StatusCode::OK, resource(&app, &base_url(&headers), &g, wants_members(&q))))
}

/// `POST /scim/v2/Groups`: a new team, with no owner and no machines until an admin
/// gives them. Or an admin's link the IdP takes on: the one with this `externalId`, or,
/// with none set, this `displayName`. A group the tenant has already is a 409. A `POST`
/// whose joins stop partway (an admin put someone on another team meanwhile) leaves the
/// group waiting to be taken on, so the IdP's retry finishes it.
pub async fn create(State(app): State<AppState>, Extension(a): Extension<Arc<Auth>>, Extension(c): Extension<Caller>, headers: HeaderMap, body: Result<Bytes, BytesRejection>) -> ScimRes {
    if !a.scim.groups {
        return Err(off());
    }
    let d = from_resource(&parse_body(body)?, None)?;
    let tenant = c.token.tenant.as_str();
    let _writes = a.scim.group_writes.lock().await;
    let by_ext = d.external_id.as_deref().and_then(|x| app.db.scim_group_find(tenant, Some(x), None));
    let by_name = app.db.scim_group_find(tenant, None, Some(&d.display_name));
    let waiting = match (&by_ext, &by_name) {
        (Some(g), _) if g.provisioned_at.is_none() => Some(g.clone()),
        (Some(g), _) => return Err(uniqueness(format!("A group with this externalId exists already: {}", g.team_id))),
        (None, Some(g)) if g.provisioned_at.is_none() && g.external_id.is_none() => Some(g.clone()),
        (None, Some(_)) => return Err(uniqueness("A group with this displayName exists already")),
        (None, None) => None,
    };
    let new = d.members.clone().unwrap_or_default();
    let g = match waiting {
        Some(link) => {
            let before = app.db.scim_group_members(tenant, &link.team_id, true).into_iter().map(|u| u.id).collect::<Vec<_>>();
            let mut p = Patched::new(&link.display_name, link.external_id.as_deref(), &before);
            if let Some(m) = &d.members {
                p.replace(m.clone());
            }
            let (gone, joining) = p.delta(&before);
            check_new(&app, &c, Some(&link.team_id), &joining)?;
            let g = app.db.save_scim_group(tenant, &link.team_id, d.external_id.as_deref(), &d.display_name, &team_name(&d.display_name), true).map_err(group_conflict)?;
            let team = app.db.team(&g.team_id).ok_or_else(|| missing("Group"))?;
            let action = if link.origin == "scim" { "scim.group_resumed" } else { "scim.group_adopted" };
            app.db.record(&c.who.event(action).target("team", &g.team_id).details(json!({
                "tenant": tenant, "team": g.team_id, "externalId": g.external_id, "displayName": g.display_name, "linkedBy": link.created_by,
            })));
            let moved = change_members(&app, &c, &team, &gone, &joining).await.inspect_err(|_| app.db.reopen_scim_group(tenant, &g.team_id))?;
            record_update(&app, &c, &link, &g, &moved);
            g
        }
        None => {
            check_new(&app, &c, None, &new)?;
            let g = app.db.create_scim_group(tenant, d.external_id.as_deref(), &d.display_name, &team_name(&d.display_name), c.who.actor.id.as_deref()).map_err(group_conflict)?;
            let team = app.db.team(&g.team_id).ok_or_else(|| server_error("team not saved"))?;
            app.db.record(&teams::team_event(&c.who, "team.created", &team.id, json!({ "name": team.name, "owner": null, "machines": team.machines, "via": teams::SCIM, "tenant": tenant })));
            app.db.record(&c.who.event("scim.group_created").target("team", &team.id).details(json!({
                "tenant": tenant, "team": team.id, "externalId": g.external_id, "displayName": g.display_name,
            })));
            change_members(&app, &c, &team, &[], &new).await.inspect_err(|_| app.db.reopen_scim_group(tenant, &g.team_id))?;
            g
        }
    };
    let body = resource(&app, &base_url(&headers), &app.db.scim_group(tenant, &g.team_id).unwrap_or(g), true);
    let mut r = scim_json(StatusCode::CREATED, body.clone());
    if let Some(Ok(at)) = body["meta"]["location"].as_str().map(HeaderValue::from_str) {
        r.headers_mut().insert(header::LOCATION, at);
    }
    Ok(r)
}

/// Saves a group's new attributes and members. `externalId` can be set once, never
/// changed.
async fn update(app: &AppState, c: &Caller, before: &ScimGroup, team: &Team, p: &Patched, members: &[String]) -> ScimRes<ScimGroup> {
    if let Some(old) = before.external_id.as_deref()
        && p.external_id.as_deref() != Some(old)
    {
        return Err(ScimError::new(StatusCode::BAD_REQUEST, Some("mutability"), "externalId can't change once set. Delete the group and push it again."));
    }
    let (gone, new) = p.delta(members);
    check_new(app, c, Some(&team.id), &new)?;
    let g = app.db.save_scim_group(&c.token.tenant, &team.id, p.external_id.as_deref(), &p.display_name, &team_name(&p.display_name), true).map_err(group_conflict)?;
    let moved = change_members(app, c, team, &gone, &new).await?;
    record_update(app, c, before, &g, &moved);
    Ok(app.db.scim_group(&c.token.tenant, &team.id).unwrap_or(g))
}

/// `PUT /scim/v2/Groups/{id}`: the whole group (Okta's apps from the integration
/// wizard). The members sent replace the tenant's members; without `members`, they
/// stay as they are. An `externalId` left out is kept.
pub async fn replace(State(app): State<AppState>, Extension(a): Extension<Arc<Auth>>, Extension(c): Extension<Caller>, headers: HeaderMap, Path(id): Path<String>, body: Result<Bytes, BytesRejection>) -> ScimRes {
    if !a.scim.groups {
        return Err(off());
    }
    let v = parse_body(body)?;
    let _writes = a.scim.group_writes.lock().await;
    let (before, team) = need(&app, &c, &id)?;
    let d = from_resource(&v, Some(&before))?;
    let members: Vec<String> = app.db.scim_group_members(&c.token.tenant, &team.id, true).into_iter().map(|u| u.id).collect();
    let mut p = Patched::new(&d.display_name, d.external_id.as_deref(), &members);
    if let Some(m) = d.members {
        p.replace(m);
    }
    let g = update(&app, &c, &before, &team, &p, &members).await?;
    Ok(scim_json(StatusCode::OK, resource(&app, &base_url(&headers), &g, true)))
}

/// `PATCH /scim/v2/Groups/{id}`: 204, as Entra ID asks, and Okta accepts.
pub async fn patch(State(app): State<AppState>, Extension(a): Extension<Arc<Auth>>, Extension(c): Extension<Caller>, Path(id): Path<String>, body: Result<Bytes, BytesRejection>) -> ScimRes {
    if !a.scim.groups {
        return Err(off());
    }
    let v = parse_body(body)?;
    let _writes = a.scim.group_writes.lock().await;
    let (before, team) = need(&app, &c, &id)?;
    let members: Vec<String> = app.db.scim_group_members(&c.token.tenant, &team.id, true).into_iter().map(|u| u.id).collect();
    let mut p = Patched::new(&before.display_name, before.external_id.as_deref(), &members);
    apply_patch(&mut p, &v)?;
    update(&app, &c, &before, &team, &p, &members).await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

/// `DELETE /scim/v2/Groups/{id}`: the people this tenant provisioned leave the team, as
/// if removed one by one, and the link goes. A team the IdP made, left empty, is
/// deleted, unless it pays for a plan (ADR 0093), which keeps it until that's
/// cancelled. A team an admin linked, or one with people the IdP doesn't manage,
/// stays theirs.
pub async fn delete(State(app): State<AppState>, Extension(a): Extension<Arc<Auth>>, Extension(c): Extension<Caller>, Path(id): Path<String>) -> ScimRes {
    if !a.scim.groups {
        return Err(off());
    }
    let _writes = a.scim.group_writes.lock().await;
    let (g, team) = need(&app, &c, &id)?;
    let members: Vec<String> = app.db.scim_group_members(&c.token.tenant, &team.id, true).into_iter().map(|u| u.id).collect();
    let moved = change_members(&app, &c, &team, &members, &[]).await?;
    app.db.unlink_scim_group(&team.id);
    let left = app.db.team_members(&team.id).len();
    let fate = if g.origin == "scim" && left == 0 {
        match crate::team_billing::may_delete(&app, &c.who, &team.id, teams::SCIM).await {
            Ok(_held) if app.db.delete_team(&team.id) => {
                app.db.record(&teams::team_event(&c.who, "team.deleted", &team.id, json!({ "name": team.name, "reason": teams::SCIM })));
                "deleted"
            }
            Ok(_) => "kept",
            Err(_) => "kept_paying",
        }
    } else {
        "kept"
    };
    let ownerless = moved.owner_left && left > 0 && !app.db.team_members(&team.id).iter().any(|m| m.role == teams::OWNER);
    app.db.record(&c.who.event("scim.group_deleted").target("team", &team.id).details(json!({
        "tenant": g.tenant, "team": team.id, "externalId": g.external_id, "displayName": g.display_name, "origin": g.origin,
        "removed": moved.removed, "teamFate": fate, "ownerless": ownerless,
    })));
    Ok(StatusCode::NO_CONTENT.into_response())
}

/// A SCIM DELETE of a user takes them off a team their tenant's group put them on: the
/// IdP has them in no group any more.
pub async fn user_deleted(app: &AppState, a: &Auth, c: &Caller, user_id: &str) {
    if !a.scim.groups {
        return;
    }
    let _writes = a.scim.group_writes.lock().await;
    let Some(team_id) = app.db.team_id_of(user_id) else { return };
    let Some(g) = app.db.scim_group(&c.token.tenant, &team_id) else { return };
    let owner = app.db.team_member(user_id).is_some_and(|m| m.role == teams::OWNER);
    if teams::leave(app, &c.who, &team_id, user_id, teams::SCIM).await {
        record_update(app, c, &g, &g, &Moved { removed: vec![user_id.to_string()], owner_left: owner, ..Moved::default() });
    }
}

// Links (admin, under /api): `botctl scim group link`, `unlink`, `groups`.

fn link_view(app: &AppState, g: &ScimGroup) -> Value {
    let t = app.db.team(&g.team_id);
    let mut v = json!(g);
    v["teamName"] = json!(t.map(|t| t.name));
    v["members"] = json!(app.db.team_members(&g.team_id).len());
    v["provisionedMembers"] = json!(app.db.scim_group_members(&g.tenant, &g.team_id, false).len());
    v
}

/// `GET /api/scim/groups`: every tenant's groups and the teams they are.
pub async fn list_links(State(app): State<AppState>, Extension(a): Extension<Arc<Auth>>) -> Json<Value> {
    let groups: Vec<Value> = app.db.all_scim_groups().iter().map(|g| link_view(&app, g)).collect();
    Json(json!({ "enabled": a.scim.enabled, "groups": a.scim.groups, "links": groups }))
}

/// `POST /api/scim/groups {tenant, team, externalId?, displayName?}`: links a team that
/// exists to a tenant, so the IdP takes it on when it pushes the group with that
/// `externalId` (or, with none, that `displayName`, which defaults to the team's name).
/// Until then the team is as it was. A SCIM token never reaches a team without this.
pub async fn link(State(app): State<AppState>, Extension(a): Extension<Arc<Auth>>, Extension(by): Extension<Who>, Json(v): Json<Value>) -> Res<(StatusCode, Json<Value>)> {
    let tenant = tenant_name(&v["tenant"])?;
    let team = app.db.team(v["team"].as_str().unwrap_or("")).ok_or_else(|| not_found("Team"))?;
    let clean = |k: &str, max: usize| match &v[k] {
        Value::Null => Ok(None),
        Value::String(s) if s.trim().is_empty() => Ok(None),
        Value::String(s) if s.chars().any(char::is_control) || s.trim().chars().count() > max => Err(bad(format!("{k} must be at most {max} characters, with no control characters"))),
        Value::String(s) => Ok(Some(s.trim().to_string())),
        _ => Err(bad(format!("{k} must be a string"))),
    };
    let external_id = clean("externalId", 256)?;
    let display_name = clean("displayName", MAX_NAME)?.unwrap_or_else(|| team.name.clone());
    let _writes = a.scim.group_writes.lock().await;
    let g = app.db.link_scim_group(&tenant, &team.id, external_id.as_deref(), &display_name, by.actor.id.as_deref()).map_err(|e| match e {
        ScimGroupConflict::Team => ApiError(StatusCode::CONFLICT, "This team is linked to a SCIM group already. Unlink it first.".into()),
        ScimGroupConflict::DisplayName => ApiError(StatusCode::CONFLICT, format!("Tenant {tenant} has a group with this displayName already.")),
        ScimGroupConflict::ExternalId => ApiError(StatusCode::CONFLICT, format!("Tenant {tenant} has a group with this externalId already.")),
        ScimGroupConflict::Gone => not_found("Team"),
        ScimGroupConflict::Db(e) => ApiError(StatusCode::INTERNAL_SERVER_ERROR, e),
    })?;
    app.db.record(&by.event("scim.group_linked").target("team", &team.id).details(json!({ "tenant": tenant, "team": team.id, "externalId": g.external_id, "displayName": g.display_name })));
    Ok((StatusCode::CREATED, Json(link_view(&app, &g))))
}

/// `DELETE /api/scim/groups/{team}`: ends the link. Everyone stays on the team, which
/// admins and the team's managers manage by hand again; the IdP's group is 404 to it.
pub async fn unlink(State(app): State<AppState>, Extension(a): Extension<Arc<Auth>>, Extension(by): Extension<Who>, Path(team): Path<String>) -> Res {
    let _writes = a.scim.group_writes.lock().await;
    let g = app.db.unlink_scim_group(&team).ok_or_else(|| not_found("SCIM group"))?;
    app.db.record(&by.event("scim.group_unlinked").target("team", &team).details(json!({ "tenant": g.tenant, "team": team, "externalId": g.external_id, "displayName": g.display_name, "origin": g.origin })));
    Ok(Json(json!({ "ok": true })))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filters_find_groups_and_members() {
        assert_eq!(parse_filter(r#"displayName eq "Eng""#), Ok(vec![Clause::DisplayName("Eng".into())]));
        assert_eq!(parse_filter(r#"externalId eq "8aa1""#), Ok(vec![Clause::ExternalId("8aa1".into())]));
        assert_eq!(parse_filter(&format!("{GROUP_SCHEMA}:displayName eq \"Eng\"")), Ok(vec![Clause::DisplayName("Eng".into())]));
        assert_eq!(parse_filter(r#"id eq "t1" and members eq "u2""#), Ok(vec![Clause::Id("t1".into()), Clause::Member("u2".into())]));
        assert_eq!(parse_filter(r#"id eq "t1" AND members.value eq "u2""#), Ok(vec![Clause::Id("t1".into()), Clause::Member("u2".into())]));
        assert_eq!(parse_filter(r#"members[value eq "u2"] and id eq "t1""#), Ok(vec![Clause::Member("u2".into()), Clause::Id("t1".into())]));
        assert_eq!(parse_filter(r#"displayName eq "R and D""#), Ok(vec![Clause::DisplayName("R and D".into())]), "and inside quotes");
        for bad in ["", "displayName", r#"displayName ne "x""#, r#"displayName eq "x" or id eq "y""#, r#"members[display eq "x"]"#, r#"members[value eq "x""#, r#"owner eq "x""#, r#"displayName eq "x" and"#] {
            assert!(parse_filter(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn bodies_and_member_lists_are_read_strictly() {
        let d = from_resource(&json!({ "schemas": [GROUP_SCHEMA, "http://schemas.microsoft.com/2006/11/ResourceManagement/ADSCIM/2.0/Group"], "externalId": "8aa1", "displayName": "Eng", "meta": { "resourceType": "Group" } }), None).unwrap();
        assert_eq!(d, Doc { display_name: "Eng".into(), external_id: Some("8aa1".into()), members: None });
        let d = from_resource(&json!({ "displayName": "Eng", "members": [{ "value": "u1", "display": "Ada" }, { "value": "u1" }, { "value": "u2", "$ref": null }] }), None).unwrap();
        assert_eq!(d.members, Some(vec!["u1".into(), "u2".into()]), "each once");
        assert_eq!(from_resource(&json!({ "displayName": "Eng", "members": [] }), None).unwrap().members, Some(vec![]));
        for bad in [
            json!({}),
            json!({ "displayName": " " }),
            json!({ "displayName": "x".repeat(257) }),
            json!({ "displayName": "Eng", "members": "u1" }),
            json!({ "displayName": "Eng", "members": [{ "display": "Ada" }] }),
            json!({ "displayName": "Eng", "members": [{ "value": "g1", "type": "Group" }] }),
            json!({ "displayName": "Eng", "members": ["u1"] }),
        ] {
            assert!(from_resource(&bad, None).is_err(), "{bad}");
        }
    }

    #[test]
    fn patches_follow_entra_and_okta() {
        let start = ["u1".to_string(), "u2".to_string()];
        let mut p = Patched::new("Eng", Some("8aa1"), &start);
        // Entra: capitalized ops on members, with lists of {$ref, value}.
        apply_patch(&mut p, &json!({ "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"], "Operations": [
            { "op": "Add", "path": "members", "value": [{ "$ref": null, "value": "u3" }, { "$ref": null, "value": "u4" }] },
            { "op": "Remove", "path": "members", "value": [{ "$ref": null, "value": "u1" }] },
            { "op": "Replace", "path": "displayName", "value": "Engineering" },
        ]}))
        .unwrap();
        assert_eq!(p.display_name, "Engineering");
        assert_eq!(p.delta(&start), (vec!["u1".to_string()], vec!["u3".to_string(), "u4".to_string()]));
        // Okta: a filtered remove, an add, and a rename with no path that carries the id.
        let mut p = Patched::new("Eng", None, &start);
        apply_patch(&mut p, &json!({ "Operations": [
            { "op": "remove", "path": "members[value eq \"u2\"]" },
            { "op": "add", "path": "members", "value": [{ "value": "u5", "display": "e@example.com" }] },
            { "op": "replace", "value": { "id": "t1", "displayName": "Eng 2" } },
        ]}))
        .unwrap();
        assert_eq!((p.display_name.as_str(), p.delta(&start)), ("Eng 2", (vec!["u2".to_string()], vec!["u5".to_string()])));
        // A full replace of the members, then adding and removing the same person nets out.
        let mut p = Patched::new("Eng", None, &start);
        apply_patch(&mut p, &json!({ "Operations": [{ "op": "replace", "path": "members", "value": [{ "value": "u2" }, { "value": "u6" }] }, { "op": "add", "path": "members", "value": [{ "value": "u7" }] }, { "op": "remove", "path": "members", "value": [{ "value": "u7" }] }] })).unwrap();
        assert_eq!(p.delta(&start), (vec!["u1".to_string()], vec!["u6".to_string()]));
        let mut p = Patched::new("Eng", None, &start);
        apply_patch(&mut p, &json!({ "Operations": [{ "op": "remove", "path": "members" }] })).unwrap();
        assert_eq!(p.delta(&start).0, start.to_vec(), "remove with no value empties it");
        for bad in [
            json!({ "Operations": [] }),
            json!({ "Operations": [{ "op": "move", "path": "members" }] }),
            json!({ "Operations": [{ "op": "remove" }] }),
            json!({ "Operations": [{ "op": "remove", "path": "displayName" }] }),
            json!({ "Operations": [{ "op": "add", "path": "members[value eq \"u1\"]", "value": [] }] }),
            json!({ "Operations": [{ "op": "remove", "path": "members[display eq \"Ada\"]" }] }),
            json!({ "Operations": [{ "op": "add", "path": "members", "value": "u1" }] }),
            json!({ "Operations": [{ "op": "replace", "value": "Eng" }] }),
        ] {
            assert!(apply_patch(&mut Patched::new("Eng", None, &start), &bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn members_are_left_out_when_asked() {
        let q = |pairs: &[(&str, &str)]| pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect::<HashMap<_, _>>();
        assert!(wants_members(&q(&[])));
        assert!(!wants_members(&q(&[("excludedAttributes", "members")])));
        assert!(!wants_members(&q(&[("excludedattributes", "meta, Members")])));
        assert!(!wants_members(&q(&[("attributes", "displayName")])));
        assert!(wants_members(&q(&[("attributes", "displayName,members")])));
    }
}
