//! Native SAML groups (ADR 0160). A provider with `SSO_<ID>_GROUPS_ATTRIBUTE` reads the
//! groups the IdP's signed assertion puts someone in. `SSO_<ID>_REQUIRED_GROUPS` keeps out
//! anyone in none of them (`finish_saml`), and an admin may map one of the provider's groups
//! to a custom role (ADR 0123) across the server.
//!
//! The IdP never names the role: it only says who is in a group, and the admin decided what
//! the group gives. A mapping is never to admin or a built-in role, nor to a role whose
//! permissions reach admins (`rbac::REACHES_ADMINS`), and a mapped role can't gain such a
//! permission later. Each sign-in with the provider reconciles: someone in a mapped group
//! who holds no custom role gets the first matching mapping's role, unless they're an admin
//! or the owner account; someone whose grant's group the assertion no longer lists (or whose
//! groups are unknown) loses it. Only what a mapping gave is taken away. Any change of the
//! person's role by hand ends the mapping's claim on it, and no mapping, of any provider,
//! gives them anything until a sign-in with that provider no longer lists its group. Every
//! change is audited.
//!
//! With several IdPs of a federation (ADR 0287), each IdP names its own groups, so every
//! mapping names its IdP, and "the provider" above means the provider at that IdP: only a
//! sign-in there gives, keeps or takes back what the mapping gave.

use super::Provider;
use super::saml_sp::{Groups, MAX_GROUP_LEN};
use crate::audit::{Actor, Outcome, Source, Who};
use crate::db::{CustomRole, SamlRoleMapping, ScimRoleMapError, User};
use crate::rbac::Role;
use crate::users;
use crate::{ApiError, AppState, Auth, Res, bad, not_found};
use axum::Json;
use axum::extract::{Extension, Path, State};
use axum::http::StatusCode;
use serde_json::{Value, json};
use std::sync::Arc;

/// Why a grant was taken away: a sign-in no longer listed the group, listed no groups the
/// server could read, the mapping was removed, or the person's link to the IdP was.
pub const LEFT_GROUP: &str = "left_group";
pub const GROUPS_UNKNOWN: &str = "groups_unknown";
pub const UNMAPPED: &str = "mapping_removed";
pub const UNLINKED: &str = "unlinked";
/// The mapping is for an IdP the provider no longer has: one taken off `IDP_ENTITY_IDS`, or
/// its one IdP now that it lists several, or the reverse (ADR 0287).
pub const IDP_NOT_LISTED: &str = "idp_not_listed";

fn conflict(msg: impl Into<String>) -> ApiError {
    ApiError(StatusCode::CONFLICT, msg.into())
}

/// A group as an admin writes it, in `REQUIRED_GROUPS` or a mapping: trimmed, non-empty, no
/// longer than a value the assertion's groups are ever read with, no control characters.
/// Compared with what the IdP sends exactly, case included.
pub fn group_name(g: &str) -> Result<String, String> {
    let g = g.trim();
    if g.is_empty() {
        return Err("a group can't be empty".into());
    }
    if g.len() > MAX_GROUP_LEN {
        return Err(format!("a group is at most {MAX_GROUP_LEN} bytes; longer ones are never read from an assertion"));
    }
    if g.chars().any(char::is_control) {
        return Err("a group can't have control characters".into());
    }
    Ok(g.to_string())
}

/// The permissions `role` would give across the server that reach admins. Empty: a SAML
/// group may give it.
fn reaching(role: &CustomRole) -> Vec<&'static str> {
    role.perms().reaching_admins(false)
}

fn role_ref(role: Option<&CustomRole>) -> Value {
    role.map_or(Value::Null, |r| json!({ "id": r.id, "name": r.name }))
}

/// The groups attribute a native SAML provider reads, if it reads one.
fn groups_attribute(p: &Provider) -> Option<&str> {
    match &p.kind {
        super::Kind::SamlSp { attributes, .. } => attributes.groups.as_deref(),
        _ => None,
    }
}

/// The IdP whose mappings a sign-in at `p` vouched for by `issuer` follows: that IdP with
/// several, None (the provider's one IdP) otherwise.
fn idp_key<'a>(p: &Provider, issuer: &'a str) -> Option<&'a str> {
    p.several_idps().then_some(issuer)
}

/// Whether `m` is for one of `p`'s IdPs as `p` is configured now: one it lists, with several,
/// or its one IdP. Another mapping of `p`'s gives nothing.
fn serves(p: &Provider, m: &SamlRoleMapping) -> bool {
    m.provider == p.id
        && match &m.idp {
            Some(e) => p.several_idps() && p.idps().contains(e),
            None => !p.several_idps(),
        }
}

/// Adds the mapping's IdP to audit details, when it names one.
fn with_idp(d: &mut Value, m: &SamlRoleMapping) {
    if let Some(idp) = &m.idp {
        d["idp"] = json!(idp);
    }
}

fn view(app: &AppState, a: &Auth, m: &SamlRoleMapping) -> Value {
    let role = app.db.custom_role(&m.role_id);
    let p = a.sso.provider(&m.provider).filter(|p| p.saml_sp());
    let reads = p.and_then(|p| groups_attribute(p));
    json!({
        "id": m.id, "provider": m.provider, "idp": m.idp, "group": m.group, "groupsAttribute": reads, "active": reads.is_some() && p.is_some_and(|p| serves(p, m)),
        "role": role_ref(role.as_ref()), "applies": role.as_ref().map_or(vec![], |r| r.perms().names()),
        "grants": app.db.saml_role_grants(&m.id).len(),
        "createdAt": m.created_at, "createdBy": m.created_by,
    })
}

fn event(by: &Who, action: &str, m: &SamlRoleMapping, role: Option<&CustomRole>, details: Value) -> crate::audit::Event {
    let mut d = json!({ "mapping": m.id, "provider": m.provider, "group": m.group, "role": role_ref(role) });
    with_idp(&mut d, m);
    if let (Some(d), Value::Object(x)) = (d.as_object_mut(), details) {
        d.extend(x);
    }
    by.event(action).target("sso_provider", &m.provider).details(d)
}

/// Gives `user_id` the mapping's role, or says why not: they're the owner account or an
/// admin, hold a custom role already (by hand, from SCIM, or another SAML group), or the
/// role now reaches admins. Audited as any grant is, with `via: saml`.
async fn grant(app: &AppState, by: &Who, m: &SamlRoleMapping, role: &CustomRole, user_id: &str) -> Result<(), &'static str> {
    let before = app.db.user(user_id).ok_or("gone")?;
    if before.id == users::OPERATOR {
        return Err("owner");
    }
    if before.role == Role::Admin {
        return Err("admin");
    }
    if before.role_id.is_some() {
        return Err("has_role");
    }
    if !reaching(role).is_empty() {
        return Err("reaches_admins");
    }
    if !app.db.grant_saml_role(m, user_id) {
        return Err("changed");
    }
    let mut d = json!({ "name": role.name, "user": user_id, "scope": "org", "from": null, "via": "saml", "mapping": m.id, "provider": m.provider, "group": m.group });
    with_idp(&mut d, m);
    app.db.record(&by.event("role.assigned").target("role", &role.id).details(d));
    if let Some(after) = app.db.user(user_id)
        && after.role != before.role
    {
        app.db.record(&by.event("user.role_changed").target("user", user_id).details(json!({ "from": before.role, "to": after.role, "role": role_ref(Some(role)), "reason": "saml_group" })));
        users::lost_access(app, by, user_id, crate::machines::offboard::ACCESS_LOST).await;
    }
    Ok(())
}

fn skipped(app: &AppState, by: &Who, m: &SamlRoleMapping, role: &CustomRole, user_id: &str, reason: &str) {
    app.db.record(&event(by, "sso.saml_role_skipped", m, Some(role), json!({ "user": user_id, "reason": reason })));
}

/// Takes away what the mapping gave `user_id`; their built-in role goes back to the one
/// they had before. Whether it had given them anything.
async fn take_away(app: &AppState, by: &Who, m: &SamlRoleMapping, user_id: &str, reason: &str) -> bool {
    let Some(r) = app.db.revoke_saml_role(m, user_id) else { return false };
    let role = app.db.custom_role(&m.role_id);
    let mut d = json!({
        "name": role.as_ref().map(|r| r.name.clone()), "user": user_id, "scope": "org", "via": "saml", "mapping": m.id,
        "provider": m.provider, "group": m.group, "reason": reason, "held": r.cleared, "keeps": r.role_after,
    });
    with_idp(&mut d, m);
    app.db.record(&by.event("role.unassigned").target("role", &m.role_id).details(d));
    if r.role_before != r.role_after {
        app.db.record(&by.event("user.role_changed").target("user", user_id).details(json!({ "from": r.role_before, "to": r.role_after, "role": role_ref(role.as_ref()), "reason": "saml_group" })));
        users::lost_access(app, by, user_id, crate::machines::offboard::ACCESS_LOST).await;
    }
    true
}

/// `user` just signed in with `p`, whose signed assertion put them in `groups`: their role
/// follows `p`'s mappings. A grant from `p` stays while its group is listed and goes when
/// it isn't, or the groups are unknown (`Groups::Unknown`, or not read at all); then the
/// first of `p`'s mappings (oldest first) whose group is listed is tried. A grant an admin
/// changed by hand holds everything as it is until a sign-in with its own provider no
/// longer lists its group: no other provider can tell.
/// Grants from another provider's mappings are left alone. Done before the session starts.
/// With several IdPs, `issuer` (the IdP that signed the assertion) picks the mappings, and
/// a grant from another of `p`'s IdPs is left alone like another provider's; a grant from a
/// mapping `p` no longer serves goes (`idp_not_listed`), as that IdP can't vouch any more.
/// `give` false, for a sign-in refused after the IdP vouched for the groups: only take away.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn signed_in(app: &AppState, a: &Auth, source: &Source, p: &Provider, issuer: &str, user: &User, groups: &Groups, give: bool) {
    let _writes = a.sso.role_writes.lock().await;
    // An unlink that won the lock already took away what the provider gave.
    if !app.db.identities(&user.id).iter().any(|i| i.provider == p.id && (!p.several_idps() || i.issuer == issuer)) {
        return;
    }
    let by = Who { actor: Actor::system("sso"), source: source.clone() };
    let key = idp_key(p, issuer);
    let mine = |m: &SamlRoleMapping| m.provider == p.id && m.idp.as_deref() == key;
    let listed = groups.listed();
    if let Some(id) = app.db.saml_role_released(&user.id)
        && let Some(m) = app.db.saml_role_mapping(&id)
    {
        match listed {
            Some(l) if mine(&m) && !l.contains(&m.group) => {
                app.db.end_saml_role_release(&user.id, &m.id);
            }
            _ if m.provider == p.id && !serves(p, &m) => {
                app.db.end_saml_role_release(&user.id, &m.id);
            }
            _ => return,
        }
    }
    if let Some(g) = app.db.saml_role_grant_of_user(&user.id)
        && let Some(m) = app.db.saml_role_mapping(&g.mapping_id).filter(|m| m.provider == p.id)
    {
        if !serves(p, &m) {
            take_away(app, &by, &m, &user.id, IDP_NOT_LISTED).await;
        } else if mine(&m) {
            if listed.is_some_and(|l| l.contains(&m.group)) {
                return;
            }
            take_away(app, &by, &m, &user.id, if listed.is_some() { LEFT_GROUP } else { GROUPS_UNKNOWN }).await;
        }
    }
    let Some(listed) = listed.filter(|_| give) else { return };
    let Some(m) = app.db.saml_role_mappings_of(&p.id).into_iter().find(|m| mine(m) && listed.contains(&m.group)) else { return };
    let Some(role) = app.db.custom_role(&m.role_id) else { return };
    if let Err(reason) = grant(app, &by, &m, &role, &user.id).await {
        skipped(app, &by, &m, &role, &user.id, reason);
    }
}

/// An admin unlinked `user_id`'s identity at `provider`. With no identity there left (at
/// the mapping's IdP, for a mapping that names one), the IdP can't vouch for their groups
/// any more, so what its mappings gave them goes.
pub(crate) async fn unlinked(app: &AppState, a: &Auth, by: &Who, user_id: &str, provider: &str) {
    let gone = |m: &SamlRoleMapping| m.provider == provider && !app.db.identities(user_id).iter().any(|i| i.provider == provider && m.idp.as_ref().is_none_or(|e| i.issuer == *e));
    let _writes = a.sso.role_writes.lock().await;
    if let Some(g) = app.db.saml_role_grant_of_user(user_id)
        && let Some(m) = app.db.saml_role_mapping(&g.mapping_id).filter(|m| gone(m))
    {
        take_away(app, by, &m, user_id, UNLINKED).await;
    }
    if let Some(id) = app.db.saml_role_released(user_id)
        && app.db.saml_role_mapping(&id).is_some_and(|m| gone(&m))
    {
        app.db.end_saml_role_release(user_id, &id);
    }
}

/// Removes a mapping and takes away everything it gave. Who lost it.
async fn unmap(app: &AppState, by: &Who, m: &SamlRoleMapping) -> Vec<String> {
    let mut revoked = Vec::new();
    for g in app.db.saml_role_grants(&m.id) {
        if take_away(app, by, m, &g.user_id, UNMAPPED).await {
            revoked.push(g.user_id);
        }
    }
    app.db.delete_saml_role_mapping(&m.id);
    let role = app.db.custom_role(&m.role_id);
    app.db.record(&event(by, "sso.saml_role_unmapped", m, role.as_ref(), json!({ "reason": UNMAPPED, "revoked": revoked })));
    revoked
}

// Admin API (under /api, admins only).

fn need(app: &AppState, id: &str) -> Res<SamlRoleMapping> {
    app.db.saml_role_mapping(id).ok_or_else(|| not_found("Mapping"))
}

/// Refuses a mapping, audited: a SAML group never gives admin, or what reaches admins.
fn refused(app: &AppState, by: &Who, reason: &str, details: Value, msg: String) -> ApiError {
    let mut d = json!({ "reason": reason });
    if let (Some(d), Value::Object(x)) = (d.as_object_mut(), details) {
        d.extend(x);
    }
    app.db.record(&by.event("sso.saml_role_map_refused").outcome(Outcome::Denied).details(d));
    bad(msg)
}

/// `GET /api/sso/role-mappings`: every mapping, and the native SAML providers with the
/// groups attribute each reads and the groups it requires.
pub async fn list(State(app): State<AppState>, Extension(a): Extension<Arc<Auth>>) -> Json<Value> {
    let providers: Vec<Value> = a
        .sso
        .providers
        .iter()
        .filter(|p| p.saml_sp())
        .map(|p| {
            let required = match &p.kind {
                super::Kind::SamlSp { required_groups, .. } => required_groups.clone(),
                _ => vec![],
            };
            let idps = if p.several_idps() { p.idps() } else { &[] };
            json!({ "id": p.id, "label": p.label, "groupsAttribute": groups_attribute(p), "requiredGroups": required, "idps": idps })
        })
        .collect();
    let all: Vec<Value> = app.db.saml_role_mappings().iter().map(|m| view(&app, &a, m)).collect();
    Json(json!({ "providers": providers, "mappings": all }))
}

/// `POST /api/sso/role-mappings {provider, group, role, idp?}`: maps a native SAML provider's
/// group to a custom role across the server. With several IdPs, `idp` says whose group it
/// is (ADR 0287); with one, it's left out. Nobody gets it now: people get it as they next
/// sign in with the group in their assertion. 201 with the mapping.
pub async fn create(State(app): State<AppState>, Extension(a): Extension<Arc<Auth>>, Extension(by): Extension<Who>, Json(v): Json<Value>) -> Res<(StatusCode, Json<Value>)> {
    let body = v.as_object().ok_or_else(|| bad("Send a JSON object."))?;
    if let Some(k) = body.keys().find(|k| !["provider", "group", "role", "idp"].contains(&k.as_str())) {
        return Err(bad(format!("Unknown field \"{k}\": send provider, group, role, and idp with several IdPs.")));
    }
    let p = super::saml_provider(&a, v["provider"].as_str().unwrap_or(""))?;
    if groups_attribute(p).is_none() {
        let up = p.id.to_ascii_uppercase();
        return Err(conflict(format!("{} reads no groups. Set SSO_{up}_GROUPS_ATTRIBUTE to the assertion attribute the IdP sends groups in, and restart.", p.id)));
    }
    if !v["idp"].is_null() && !v["idp"].is_string() {
        return Err(bad("idp must be an IdP's entity ID"));
    }
    let idp = match (v["idp"].as_str().map(str::trim).filter(|e| !e.is_empty()), p.several_idps()) {
        (Some(e), true) => Some(p.issuer_at(e).map_err(bad)?),
        (None, true) => return Err(bad(format!("{} has several IdPs, each naming its own groups: say whose group it is with idp (botctl: --idp <entity ID>).", p.id))),
        (Some(_), false) => return Err(bad(format!("{} has one IdP: leave idp out.", p.id))),
        (None, false) => None,
    };
    let group = group_name(v["group"].as_str().unwrap_or("")).map_err(bad)?;
    let key = v["role"].as_str().map(str::trim).filter(|k| !k.is_empty()).ok_or_else(|| bad("role must be a custom role's id or name"))?;
    let mut at = json!({ "provider": p.id, "group": group, "role": key });
    if let Some(e) = &idp {
        at["idp"] = json!(e);
    }
    match Role::parse(key) {
        Some(Role::Admin) => return Err(refused(&app, &by, "admin", at, "A SAML group can never be mapped to admin. Give admin by hand.".into())),
        Some(_) => return Err(refused(&app, &by, "built_in", at, "A SAML group maps only to a custom role. People keep their built-in role otherwise.".into())),
        None => {}
    }
    let role = app.db.find_custom_role(key).ok_or_else(|| not_found("Role"))?;
    let reaches = |role: &CustomRole, reach: Vec<&'static str>| {
        let d = json!({ "provider": p.id, "idp": idp, "group": group, "role": { "id": role.id, "name": role.name }, "permissions": reach });
        let msg = format!(
            "{} holds {}, which {} on admins, so a SAML group can't be given it. Give it by hand, or map a role without {}.",
            role.name,
            reach.join(" and "),
            if reach.len() == 1 { "acts" } else { "act" },
            if reach.len() == 1 { "it" } else { "them" },
        );
        refused(&app, &by, "reaches_admins", d, msg)
    };
    let reach = reaching(&role);
    if !reach.is_empty() {
        return Err(reaches(&role, reach));
    }
    let _writes = a.sso.role_writes.lock().await;
    // The database checks the role's permissions again as it saves, against an edit meanwhile.
    let m = app.db.create_saml_role_mapping(&p.id, idp.as_deref(), &group, &role.id, by.actor.id.as_deref()).map_err(|e| match e {
        ScimRoleMapError::Taken => {
            let whose = idp.as_ref().map_or_else(|| p.id.clone(), |e| format!("{} at {e}", p.id));
            conflict(format!("{whose}'s group \"{group}\" is mapped to a role already. Remove that mapping first."))
        }
        ScimRoleMapError::Gone => not_found("Role"),
        ScimRoleMapError::Reaches(reach) => reaches(&role, reach),
        ScimRoleMapError::TimeBound => crate::roles::standing_refused(&role, "a SAML group"),
        ScimRoleMapError::Db(e) => ApiError(StatusCode::INTERNAL_SERVER_ERROR, e),
    })?;
    let role = app.db.custom_role(&m.role_id);
    app.db.record(&event(&by, "sso.saml_role_mapped", &m, role.as_ref(), json!({ "applies": role.as_ref().map_or(vec![], |r| r.perms().names()) })));
    Ok((StatusCode::CREATED, Json(view(&app, &a, &m))))
}

/// `GET /api/sso/role-mappings/{id}`: the mapping and everyone it gave the role to.
pub async fn get(State(app): State<AppState>, Extension(a): Extension<Arc<Auth>>, Path(id): Path<String>) -> Res {
    let m = need(&app, &id)?;
    let mut v = view(&app, &a, &m);
    v["holders"] = json!(
        app.db
            .saml_role_grants(&m.id)
            .iter()
            .map(|g| {
                let u = app.db.user(&g.user_id);
                json!({ "user": { "id": g.user_id, "name": u.as_ref().map(|u| u.name.clone()), "email": u.and_then(|u| u.email) }, "grantedAt": g.granted_at, "priorRole": g.prior_role })
            })
            .collect::<Vec<_>>()
    );
    Ok(Json(v))
}

/// `DELETE /api/sso/role-mappings/{id}`: removes the mapping and takes the role away from
/// everyone it gave it to, whether or not its provider is still configured. Roles given by
/// hand stay.
pub async fn delete(State(app): State<AppState>, Extension(a): Extension<Arc<Auth>>, Extension(by): Extension<Who>, Path(id): Path<String>) -> Res {
    let _writes = a.sso.role_writes.lock().await;
    let m = need(&app, &id)?;
    let revoked = unmap(&app, &by, &m).await;
    Ok(Json(json!({ "ok": true, "revoked": revoked })))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn group_names_are_what_an_assertion_can_carry() {
        assert_eq!(group_name("  SuperBot Users ").as_deref(), Ok("SuperBot Users"));
        assert_eq!(group_name("6f1c2a9e-0b7d-4c3e-9a51-2d8f4e6b1c70").as_deref(), Ok("6f1c2a9e-0b7d-4c3e-9a51-2d8f4e6b1c70"));
        assert!(group_name("").is_err() && group_name("   ").is_err());
        assert!(group_name(&"g".repeat(MAX_GROUP_LEN)).is_ok());
        assert!(group_name(&"g".repeat(MAX_GROUP_LEN + 1)).is_err());
        assert!(group_name("Admins\nEveryone").is_err() && group_name("Admins\u{0}").is_err());
    }
}
