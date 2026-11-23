//! SCIM 2.0 provisioning (RFC 7643, RFC 7644): an enterprise IdP (Entra ID, Okta, ...)
//! creates, updates, deactivates, and deletes SuperBot users under `/scim/v2`, and with
//! SCIM_GROUPS=on, pushes groups as teams (`groups`). The core User and Group schemas,
//! the Enterprise User extension (ADR 0176), and Bulk (`bulk`); sorting and ETags are
//! not supported. Each IdP connection is a tenant
//! with its own bearer tokens (`sbp_`, stored hashed), and sees only the users it
//! provisioned and the groups it made or an admin linked to it. The IdP never names a
//! role: with SCIM_GROUP_ROLES=on, an admin may map a group to a custom role, never
//! admin, and its members get and lose it with the group (`roles`).
//! Design: docs/adr/0023-scim.md, docs/adr/0095-scim-groups-as-teams.md,
//! docs/adr/0138-scim-group-role-mapping.md, docs/adr/0176-scim-enterprise-user-extension.md.

pub mod bulk;
pub mod google;
pub mod groups;
pub mod roles;

use crate::audit::{Actor, ActorKind, Outcome, Source, Who};
use crate::db::{self, Enterprise, NewIdentity, ScimConflict, ScimFields, ScimKey, ScimToken, ScimUser, User};
use crate::rbac::Role;
use crate::users::{self, Limiter};
use crate::{bad, not_found, ApiError, AppState, Auth, Res};
use axum::body::Bytes;
use axum::extract::rejection::BytesRejection;
use axum::extract::{Extension, Path, Query, Request, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::{json, Map, Value};
use std::collections::HashMap;
use std::sync::Arc;

pub const TOKEN_PREFIX: &str = "sbp_";
/// One user's attributes are a few hundred bytes. Bulk has its own limit (`bulk::MAX_PAYLOAD`).
pub const MAX_BODY: usize = 64 * 1024;
const CONTENT_TYPE: &str = "application/scim+json";
pub const USER_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:User";
pub const ENTERPRISE_SCHEMA: &str = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User";
/// The longest Enterprise User string kept. Entra's longest source (department) is 64.
const ENTERPRISE_MAX: usize = 128;
const LIST_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:ListResponse";
const ERROR_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:Error";
const MAX_COUNT: i64 = 200;
const DEFAULT_COUNT: i64 = 100;
/// Requests per tenant per minute. Entra and Okta back off on 429 with Retry-After.
const RATE_LIMIT: u32 = 600;
const RATE_WINDOW_MS: i64 = 60_000;
/// Requests with a missing, unknown, or revoked token, per client IP per 10 minutes.
const FAIL_LIMIT: u32 = 20;
const FAIL_WINDOW_MS: i64 = 10 * 60_000;
const DOCS: &str = "https://github.com/CG-Labs/superbot/blob/main/docs/sso/scim.md";

pub struct Scim {
    /// SCIM=on. Off by default: `/scim/v2` answers 404.
    pub enabled: bool,
    /// The role of users SCIM makes: member or readonly, never admin.
    pub default_role: Role,
    /// Requests per tenant.
    pub limiter: Limiter,
    /// Bad tokens per client IP.
    pub failures: Limiter,
    /// SCIM_GROUPS=on: groups are teams (ADR 0095). Off: `/Groups` lists none and
    /// refuses the rest, as before.
    pub groups: bool,
    /// SCIM_GROUP_ROLES=on: admins may map a group to a custom role, which its members
    /// get and lose with the group (ADR 0138). Off: no mapping is made and nothing is
    /// given; grants already made are still taken away.
    pub group_roles: bool,
    /// One group write at a time, so what a request checked still holds when it writes.
    pub group_writes: tokio::sync::Mutex<()>,
    /// GOOGLE_DIRECTORY_SYNC=on: Google Workspace's directory, read into one tenant (ADR 0162).
    pub google: Option<Arc<google::Directory>>,
}

impl Default for Scim {
    fn default() -> Scim {
        Scim {
            enabled: false,
            default_role: Role::Member,
            limiter: Limiter::new(RATE_LIMIT, RATE_WINDOW_MS),
            failures: Limiter::new(FAIL_LIMIT, FAIL_WINDOW_MS),
            groups: false,
            group_roles: false,
            group_writes: tokio::sync::Mutex::new(()),
            google: None,
        }
    }
}

fn on_off(name: &str, v: &str) -> Result<bool, String> {
    match v.trim().to_ascii_lowercase().as_str() {
        "" | "0" | "off" | "false" | "no" => Ok(false),
        "1" | "on" | "true" | "yes" => Ok(true),
        _ => Err(format!("{name} must be on or off, not \"{v}\"")),
    }
}

impl Scim {
    /// SCIM (off unless on), SCIM_DEFAULT_ROLE (member, the default, or readonly), and
    /// SCIM_GROUPS (off unless on; needs SCIM=on to do anything), and SCIM_GROUP_ROLES
    /// (off unless on; needs SCIM_GROUPS=on).
    pub fn from_env(scim: &str, role: &str, groups: &str, group_roles: &str) -> Result<Scim, String> {
        let enabled = on_off("SCIM", scim)?;
        let groups = on_off("SCIM_GROUPS", groups)?;
        let group_roles = on_off("SCIM_GROUP_ROLES", group_roles)?;
        if group_roles && !groups {
            return Err("SCIM_GROUP_ROLES=on needs SCIM_GROUPS=on: a group's role follows its members, and groups are teams.".into());
        }
        let default_role = match role.trim() {
            "" => Role::Member,
            r => match Role::parse(r) {
                Some(Role::Admin) => return Err("SCIM_DEFAULT_ROLE can't be admin: provisioning must not make admins. Promote people with botctl user role.".into()),
                Some(r) => r,
                None => return Err(format!("SCIM_DEFAULT_ROLE must be member or readonly, not \"{role}\"")),
            },
        };
        Ok(Scim { enabled, default_role, groups, group_roles, ..Scim::default() })
    }
}

// Errors (RFC 7644 section 3.12): a SCIM error body, the status as a string.

#[derive(Debug)]
pub struct ScimError {
    status: StatusCode,
    scim_type: Option<&'static str>,
    detail: String,
}

impl ScimError {
    fn new(status: StatusCode, scim_type: Option<&'static str>, detail: impl Into<String>) -> ScimError {
        ScimError { status, scim_type, detail: detail.into() }
    }

    fn body(&self) -> Value {
        let mut body = json!({ "schemas": [ERROR_SCHEMA], "status": self.status.as_u16().to_string(), "detail": self.detail });
        if let Some(t) = self.scim_type {
            body["scimType"] = json!(t);
        }
        body
    }
}

fn invalid(detail: impl Into<String>) -> ScimError {
    ScimError::new(StatusCode::BAD_REQUEST, Some("invalidValue"), detail)
}

fn uniqueness(detail: impl Into<String>) -> ScimError {
    ScimError::new(StatusCode::CONFLICT, Some("uniqueness"), detail)
}

fn missing(what: &str) -> ScimError {
    ScimError::new(StatusCode::NOT_FOUND, None, format!("{what} not found"))
}

fn server_error(detail: impl Into<String>) -> ScimError {
    ScimError::new(StatusCode::INTERNAL_SERVER_ERROR, None, detail)
}

impl IntoResponse for ScimError {
    fn into_response(self) -> Response {
        let mut r = scim_json(self.status, self.body());
        r.extensions_mut().insert(Failed(self.scim_type));
        r
    }
}

/// On an error response: its `scimType`, for [`request_failed`].
#[derive(Clone, Copy)]
struct Failed(Option<&'static str>);

/// A request with a valid token that the server refused or failed: the IdP's provisioning
/// is stuck until someone fixes it. Not a 404, which IdPs get in their normal course (a
/// lookup, or a delete already done). The reason is the `scimType` in snake case
/// (`invalid_syntax`), or the status: a code the support bundle and health score keep.
fn request_failed(app: &AppState, who: &Who, tenant: &str, method: &str, path: &str, r: &Response) {
    let status = r.status();
    if !(status.is_client_error() || status.is_server_error()) || status == StatusCode::NOT_FOUND {
        return;
    }
    let reason = match r.extensions().get::<Failed>().and_then(|f| f.0) {
        Some(t) => snake_case(t),
        None => format!("status_{}", status.as_u16()),
    };
    let resource = path.trim_start_matches('/').split('/').find(|s| !s.is_empty() && *s != "scim" && *s != "v2").unwrap_or("");
    let details = json!({ "tenant": tenant, "status": status.as_u16(), "reason": reason, "method": method, "resource": resource });
    app.db.record(&who.event("scim.request_failed").outcome(Outcome::Failure).details(details));
}

fn snake_case(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 4);
    for c in s.chars() {
        if c.is_ascii_uppercase() {
            out.push('_');
        }
        out.push(c.to_ascii_lowercase());
    }
    out
}

type ScimRes<T = Response> = Result<T, ScimError>;

fn scim_json(status: StatusCode, body: Value) -> Response {
    let mut r = (status, body.to_string()).into_response();
    let h = r.headers_mut();
    h.insert(header::CONTENT_TYPE, HeaderValue::from_static(CONTENT_TYPE));
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    r
}

fn too_many(retry: i64) -> Response {
    let mut r = ScimError::new(StatusCode::TOO_MANY_REQUESTS, None, "Too many requests. Try again later.").into_response();
    r.headers_mut().insert(header::RETRY_AFTER, HeaderValue::from(retry.max(1)));
    r
}

/// [`conflict`], but a refused seat is audited and explained (ADR 0038).
fn save_error(app: &AppState, c: &Caller, e: ScimConflict, user: Option<&str>, email: Option<&str>) -> ScimError {
    match e {
        ScimConflict::NoSeat => ScimError::new(StatusCode::FORBIDDEN, None, crate::license::refuse_seat(app, &c.who, "scim", user, email)),
        e => conflict(e),
    }
}

fn conflict(e: ScimConflict) -> ScimError {
    match e {
        ScimConflict::Email => uniqueness(
            "Another SuperBot user has this email. SCIM never matches people by email: an admin can link this person's SSO identity to that user (botctl user link) so this tenant takes it on, or change one of the emails.",
        ),
        ScimConflict::UserName => uniqueness("Another user in this tenant has this userName."),
        ScimConflict::ExternalId => uniqueness("Another user in this tenant has this externalId."),
        ScimConflict::Identity => uniqueness("This person's SSO identity is linked to another SuperBot user."),
        ScimConflict::OtherTenant => uniqueness("This person is managed by another SCIM tenant."),
        ScimConflict::Gone => missing("User"),
        ScimConflict::NoSeat => ScimError::new(StatusCode::FORBIDDEN, None, "No seats left."),
        ScimConflict::Db(e) => {
            crate::obs::log::log_warn!("scim: database error: {e}");
            server_error("Database error")
        }
    }
}

// Authentication: a tenant's bearer token, on every request.

/// The SCIM client: the token it sent, and the audit actor that token is.
#[derive(Clone)]
pub struct Caller {
    pub token: ScimToken,
    pub who: Who,
}

/// The audit actor for a token (ADR 0019's model): a system actor named for the token,
/// signed in with `scim_token`, and the SSO provider its tenant links, if any.
fn actor(a: &Auth, t: &ScimToken) -> Actor {
    let name = match &t.label {
        Some(l) => format!("SCIM {} ({l})", t.tenant),
        None => format!("SCIM {}", t.tenant),
    };
    Actor {
        kind: ActorKind::System,
        id: Some(format!("scim:{}", t.id)),
        name: Some(name),
        method: Some("scim_token".into()),
        idp: t.sso_provider.as_deref().and_then(|p| crate::sso::idp_type(a, p)).map(String::from),
        idp_provider: t.sso_provider.clone(),
        ..Default::default()
    }
}

/// A missing, unknown, or revoked token, throttled per IP. Never what was sent; for a
/// revoked one, which token it was, since a revoked token still in use may have leaked.
fn auth_failed(a: &Auth, app: &AppState, source: &Source, reason: &str, revoked: Option<&ScimToken>) {
    let Some(missed) = a.logins.failure(&format!("{}|scim", source.ip.as_deref().unwrap_or("")), db::now()) else { return };
    let actor = Actor { kind: ActorKind::System, id: Some("scim".into()), method: Some("scim_token".into()), ..Default::default() };
    let who = Who { actor, source: source.clone() };
    let mut details = json!({ "reason": reason, "unloggedSinceLast": missed });
    let mut e = who.event("scim.auth_failed").outcome(Outcome::Failure);
    if let Some(t) = revoked {
        details["tenant"] = json!(t.tenant);
        e = e.target("scim_token", &t.id);
    }
    app.db.record(&e.details(details));
}

/// `sbp_` and 64 hex digits, as `users::new_secret` makes them. Anything else is not
/// looked up.
fn token_shaped(t: &str) -> bool {
    t.strip_prefix(TOKEN_PREFIX).is_some_and(|h| h.len() == 64 && h.bytes().all(|b| b.is_ascii_hexdigit()))
}

/// Checks the Host, that SCIM is on, the token, the tenant's rate, and the client IP's
/// failures, before any SCIM handler runs. Session cookies and tokens, the break-glass
/// password, and the Bots' token never work here.
///
/// A valid token is never refused for its IP's failures: Entra and Okta send from
/// addresses they share with every customer, so anyone pointing their own IdP here with
/// a junk token could otherwise hold off deprovisioning. Tokens are 256 random bits, so
/// the IP limit only spares the database and the audit log, as sessions are spared.
pub async fn guard(State(a): State<Arc<Auth>>, mut req: Request, next: Next) -> Response {
    let host = req.headers().get(header::HOST).and_then(|v| v.to_str().ok()).unwrap_or("");
    if !a.hosts.iter().any(|h| h.eq_ignore_ascii_case(host)) {
        return (StatusCode::FORBIDDEN, "Unknown Host. Add it to ALLOWED_HOSTS.").into_response();
    }
    if !a.scim.enabled {
        return missing("SCIM is off on this server (SCIM=on turns it on);").into_response();
    }
    let Some(app) = a.app.clone() else {
        return server_error("No database").into_response();
    };
    let source = crate::request_source(&req, a.trust_forwarded);
    let (ip, at) = (source.ip.clone().unwrap_or_default(), db::now());
    let token = req.headers().get(header::AUTHORIZATION).and_then(|v| v.to_str().ok()).and_then(|h| h.strip_prefix("Bearer ")).map(str::trim).unwrap_or("");
    let hash = token_shaped(token).then(|| users::hash(token));
    let found = hash.as_deref().and_then(|h| app.db.live_scim_token(h, at));
    let Some(t) = found else {
        if let Some(retry) = a.scim.failures.blocked(&ip, at) {
            return too_many(retry);
        }
        a.scim.failures.fail(&ip, at);
        let revoked = hash.as_deref().and_then(|h| app.db.scim_token_by_hash(h));
        let reason = match (&revoked, token.is_empty()) {
            (Some(_), _) => "revoked",
            (None, true) => "missing",
            (None, false) => "unknown",
        };
        auth_failed(&a, &app, &source, reason, revoked.as_ref());
        let mut r = ScimError::new(StatusCode::UNAUTHORIZED, None, "A valid SCIM bearer token is required.").into_response();
        r.headers_mut().insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer realm=\"SuperBot SCIM\""));
        return r;
    };
    if let Some(retry) = a.scim.limiter.hit(&t.tenant, at) {
        return too_many(retry);
    }
    let who = Who { actor: actor(&a, &t), source };
    let (tenant, method, path) = (t.tenant.clone(), req.method().to_string(), req.uri().path().to_string());
    req.extensions_mut().insert(Caller { token: t, who: who.clone() });
    let r = next.run(req).await;
    request_failed(&app, &who, &tenant, &method, &path, &r);
    r
}

// Discovery (RFC 7644 section 4).

/// `https://<host>/scim/v2`, from the Host header (checked against ALLOWED_HOSTS).
/// Plain http only for loopback, where there is no proxy in front.
fn base_url(headers: &HeaderMap) -> String {
    let host = headers.get(header::HOST).and_then(|v| v.to_str().ok()).unwrap_or("");
    let name = match host.strip_prefix('[') {
        Some(rest) => rest.split(']').next().unwrap_or_default(),
        None => host.rsplit_once(':').map_or(host, |(h, _)| h),
    };
    let scheme = if crate::is_loopback_host(name) { "http" } else { "https" };
    format!("{scheme}://{host}/scim/v2")
}

fn list(resources: Vec<Value>, total: i64, start: i64) -> Response {
    scim_json(StatusCode::OK, json!({ "schemas": [LIST_SCHEMA], "totalResults": total, "startIndex": start, "itemsPerPage": resources.len(), "Resources": resources }))
}

pub async fn service_provider_config(headers: HeaderMap) -> Response {
    scim_json(
        StatusCode::OK,
        json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
            "documentationUri": DOCS,
            "patch": { "supported": true },
            "bulk": { "supported": true, "maxOperations": bulk::MAX_OPERATIONS, "maxPayloadSize": bulk::MAX_PAYLOAD },
            "filter": { "supported": true, "maxResults": MAX_COUNT },
            "changePassword": { "supported": false },
            "sort": { "supported": false },
            "etag": { "supported": false },
            "authenticationSchemes": [{
                "type": "oauthbearertoken", "name": "Bearer token", "primary": true,
                "description": "A per-tenant token from `botctl scim token create`, sent as Authorization: Bearer sbp_...",
                "documentationUri": DOCS,
            }],
            "meta": { "resourceType": "ServiceProviderConfig", "location": format!("{}/ServiceProviderConfig", base_url(&headers)) },
        }),
    )
}

fn user_resource_type(base: &str) -> Value {
    json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"],
        "id": "User", "name": "User", "endpoint": "/Users", "description": "People who can sign in to SuperBot",
        "schema": USER_SCHEMA, "schemaExtensions": [{ "schema": ENTERPRISE_SCHEMA, "required": false }],
        "meta": { "resourceType": "ResourceType", "location": format!("{base}/ResourceTypes/User") },
    })
}

pub async fn resource_types(Extension(a): Extension<Arc<Auth>>, headers: HeaderMap) -> Response {
    let base = base_url(&headers);
    let mut types = vec![user_resource_type(&base)];
    types.extend(groups::resource_types(&a, &base));
    let n = types.len() as i64;
    list(types, n, 1)
}

pub async fn resource_type(Extension(a): Extension<Arc<Auth>>, headers: HeaderMap, Path(id): Path<String>) -> ScimRes {
    let base = base_url(&headers);
    match id.as_str() {
        "User" => Ok(scim_json(StatusCode::OK, user_resource_type(&base))),
        _ => groups::resource_type(&a, &base, &id).map(|t| scim_json(StatusCode::OK, t)).ok_or_else(|| missing("Resource type")),
    }
}

fn attribute(name: &str, kind: &str, required: bool, uniqueness: &str, description: &str) -> Value {
    json!({
        "name": name, "type": kind, "multiValued": false, "description": description, "required": required,
        "caseExact": false, "mutability": "readWrite", "returned": "default", "uniqueness": uniqueness,
    })
}

fn user_schema(base: &str) -> Value {
    let sub = |name: &str, d: &str| attribute(name, "string", false, "none", d);
    let mut name = attribute("name", "complex", false, "none", "The person's name");
    name["subAttributes"] = json!([sub("formatted", "The full name"), sub("familyName", "Family name"), sub("givenName", "Given name")]);
    let mut emails = attribute("emails", "complex", false, "none", "Email addresses. SuperBot keeps one: the primary, else the work one, else the first.");
    emails["multiValued"] = json!(true);
    emails["subAttributes"] = json!([sub("value", "The address"), sub("type", "work, home, or other"), attribute("primary", "boolean", false, "none", "The address SuperBot keeps")]);
    json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Schema"],
        "id": USER_SCHEMA, "name": "User", "description": "A SuperBot user",
        "attributes": [
            attribute("userName", "string", true, "server", "Unique in the tenant, any case; usually the UPN or email"),
            name,
            attribute("displayName", "string", false, "none", "The name SuperBot shows"),
            emails,
            attribute("active", "boolean", false, "none", "false disables the user and ends their sessions"),
        ],
        "meta": { "resourceType": "Schema", "location": format!("{base}/Schemas/{USER_SCHEMA}") },
    })
}

fn enterprise_schema(base: &str) -> Value {
    let text = |name: &str, d: &str| attribute(name, "string", false, "none", d);
    let read_only = |mut v: Value| {
        v["mutability"] = json!("readOnly");
        v
    };
    let mut reference = attribute("$ref", "reference", false, "none", "The manager's SCIM resource");
    reference["referenceTypes"] = json!(["User"]);
    let mut manager = attribute("manager", "complex", false, "none", "The person's manager: another user this tenant provisioned. Anyone else is dropped.");
    manager["subAttributes"] = json!([
        text("value", "The manager's id in SuperBot"),
        read_only(reference),
        read_only(text("displayName", "The manager's shown name")),
    ]);
    json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Schema"],
        "id": ENTERPRISE_SCHEMA, "name": "EnterpriseUser", "description": "Enterprise User: kept for admins and access reviews, never used to grant access",
        "attributes": [
            text("employeeNumber", "The organization's number for the person"),
            text("costCenter", "Cost center"),
            text("organization", "Organization"),
            text("division", "Division"),
            text("department", "Department"),
            manager,
        ],
        "meta": { "resourceType": "Schema", "location": format!("{base}/Schemas/{ENTERPRISE_SCHEMA}") },
    })
}

pub async fn schemas(Extension(a): Extension<Arc<Auth>>, headers: HeaderMap) -> Response {
    let base = base_url(&headers);
    let mut all = vec![user_schema(&base), enterprise_schema(&base)];
    all.extend(groups::schemas(&a, &base));
    let n = all.len() as i64;
    list(all, n, 1)
}

pub async fn schema(Extension(a): Extension<Arc<Auth>>, headers: HeaderMap, Path(id): Path<String>) -> ScimRes {
    let base = base_url(&headers);
    match id.as_str() {
        USER_SCHEMA => Ok(scim_json(StatusCode::OK, user_schema(&base))),
        ENTERPRISE_SCHEMA => Ok(scim_json(StatusCode::OK, enterprise_schema(&base))),
        _ => groups::schema(&a, &base, &id).map(|s| scim_json(StatusCode::OK, s)).ok_or_else(|| missing("Schema")),
    }
}

pub async fn unknown() -> Response {
    missing("Endpoint").into_response()
}

// Filters (RFC 7644 section 3.4.2.2): only `userName eq "..."` and `externalId eq "..."`,
// which are what Entra ID and Okta send to find a user.

/// `attr` with its schema's URN in front of it taken off, in any case.
fn strip_schema<'a>(attr: &'a str, schema: &str) -> &'a str {
    attr.get(..schema.len() + 1).filter(|p| p.eq_ignore_ascii_case(&format!("{schema}:"))).map_or(attr, |p| &attr[p.len()..])
}

/// `attr eq "value"`: the attribute as sent, and the value, a JSON string of 1 to 512
/// characters that must be the whole rest. `Err(None)` is a filter of another shape;
/// `Err(Some(_))` says what's wrong with the value.
fn attr_eq(s: &str) -> Result<(&str, String), Option<String>> {
    let s = s.trim();
    let (attr, rest) = s.split_once(char::is_whitespace).ok_or(None)?;
    let (op, value) = rest.trim_start().split_once(char::is_whitespace).ok_or(None)?;
    if !op.eq_ignore_ascii_case("eq") {
        return Err(None);
    }
    let value = value.trim();
    if !value.starts_with('"') {
        return Err(Some("The filter's value must be a quoted string".into()));
    }
    // A JSON string: escapes are JSON's, and it must be the whole rest of the filter.
    let v: String = serde_json::from_str(value).map_err(|_| None)?;
    if v.is_empty() || v.chars().count() > 512 {
        return Err(Some("The filter's value must be 1 to 512 characters".into()));
    }
    Ok((attr, v))
}

pub fn parse_filter(s: &str) -> Result<ScimKey, String> {
    let s = s.trim();
    let unsupported = || format!("Unsupported filter: only userName eq \"...\" and externalId eq \"...\" are supported, not {}", s.chars().take(100).collect::<String>());
    let (attr, v) = attr_eq(s).map_err(|e| e.unwrap_or_else(unsupported))?;
    match strip_schema(attr, USER_SCHEMA).to_ascii_lowercase().as_str() {
        "username" => Ok(ScimKey::UserName(v)),
        "externalid" => Ok(ScimKey::ExternalId(v)),
        _ => Err(unsupported()),
    }
}

/// `startIndex` (1-based, default 1) and `count` (default 100, at most 200). Names in any case.
fn page(q: &HashMap<String, String>) -> ScimRes<(i64, i64)> {
    let get = |k: &str| q.iter().find(|(name, _)| name.eq_ignore_ascii_case(k)).map(|(_, v)| v.trim());
    let num = |k: &str, default: i64| match get(k) {
        None | Some("") => Ok(default),
        Some(v) => v.parse::<i64>().map_err(|_| invalid(format!("{k} must be a number"))),
    };
    Ok((num("startIndex", 1)?.max(1), num("count", DEFAULT_COUNT)?.clamp(0, MAX_COUNT)))
}

// Users.

/// A Unix ms time as RFC 3339, for `meta`.
fn rfc3339(ms: i64) -> String {
    chrono::DateTime::from_timestamp_millis(ms).map(|t| t.to_rfc3339_opts(chrono::SecondsFormat::Millis, true)).unwrap_or_default()
}

/// A user as SCIM shows it. Attributes without a value are left out, not null.
pub fn resource(base: &str, s: &ScimUser) -> Value {
    let u = &s.user;
    let mut name = Map::new();
    name.insert("formatted".into(), json!(s.formatted.as_deref().unwrap_or(&u.name)));
    if let Some(g) = &s.given_name {
        name.insert("givenName".into(), json!(g));
    }
    if let Some(f) = &s.family_name {
        name.insert("familyName".into(), json!(f));
    }
    let mut v = json!({
        "schemas": [USER_SCHEMA],
        "id": u.id,
        "userName": s.user_name,
        "name": name,
        "displayName": u.name,
        "active": u.active(),
        "meta": { "resourceType": "User", "created": rfc3339(s.created_at), "lastModified": rfc3339(s.updated_at.max(u.updated_at)), "location": format!("{base}/Users/{}", u.id) },
    });
    if let Some(x) = &s.external_id {
        v["externalId"] = json!(x);
    }
    if let Some(e) = &u.email {
        v["emails"] = json!([{ "value": e, "type": "work", "primary": true }]);
    }
    if !s.enterprise.is_empty() {
        let e = &s.enterprise;
        let mut ext = Map::new();
        for (k, x) in [("employeeNumber", &e.employee_number), ("costCenter", &e.cost_center), ("organization", &e.organization), ("division", &e.division), ("department", &e.department)] {
            if let Some(x) = x {
                ext.insert(k.into(), json!(x));
            }
        }
        if let Some(m) = &e.manager {
            ext.insert("manager".into(), json!({ "value": m, "$ref": format!("{base}/Users/{m}"), "displayName": s.manager_name }));
        }
        v["schemas"] = json!([USER_SCHEMA, ENTERPRISE_SCHEMA]);
        v[ENTERPRISE_SCHEMA] = Value::Object(ext);
    }
    v
}

/// What SCIM manages on a user, as a client last set it.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Attrs {
    pub user_name: String,
    pub external_id: Option<String>,
    pub given_name: Option<String>,
    pub family_name: Option<String>,
    /// As the IdP sent it. The name SuperBot shows is this, else `formatted`, else the parts.
    pub display_name: Option<String>,
    pub formatted: Option<String>,
    pub email: Option<String>,
    pub active: bool,
    pub enterprise: Enterprise,
}

impl Attrs {
    fn of(s: &ScimUser) -> Attrs {
        Attrs {
            user_name: s.user_name.clone(),
            external_id: s.external_id.clone(),
            given_name: s.given_name.clone(),
            family_name: s.family_name.clone(),
            display_name: s.display_name.clone(),
            formatted: s.formatted.clone(),
            email: s.user.email.clone(),
            active: s.user.active(),
            enterprise: s.enterprise.clone(),
        }
    }

    /// What the shown name is built from.
    fn names(&self) -> [Option<&str>; 5] {
        [Some(self.user_name.as_str()), self.display_name.as_deref(), self.formatted.as_deref(), self.given_name.as_deref(), self.family_name.as_deref()]
    }

    /// The name SuperBot shows: what the IdP called them, or their userName up to the `@`.
    fn shown_name(&self) -> String {
        let parts = [self.given_name.as_deref(), self.family_name.as_deref()].into_iter().flatten().collect::<Vec<_>>().join(" ");
        self.display_name
            .clone()
            .or_else(|| self.formatted.clone())
            .or_else(|| Some(parts).filter(|p| !p.is_empty()))
            .unwrap_or_else(|| self.user_name.split('@').next().unwrap_or(&self.user_name).to_string())
            .chars()
            .take(100)
            .collect()
    }
}

static NULL: Value = Value::Null;

/// An attribute of an object, by name in any case: SCIM attribute names are case-insensitive.
fn key<'a>(v: &'a Value, name: &str) -> Option<&'a Value> {
    v.as_object()?.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v)
}

/// `key`, with missing as null.
fn attr<'a>(v: &'a Value, name: &str) -> &'a Value {
    key(v, name).unwrap_or(&NULL)
}

/// A string attribute: trimmed, without control characters, at most `max` characters.
/// Missing, null, or empty is None.
fn text(v: &Value, field: &str, max: usize) -> ScimRes<Option<String>> {
    match v {
        Value::Null => Ok(None),
        Value::String(s) if s.trim().is_empty() => Ok(None),
        Value::String(s) if s.chars().any(char::is_control) => Err(invalid(format!("{field} has control characters"))),
        Value::String(s) if s.trim().chars().count() > max => Err(invalid(format!("{field} must be at most {max} characters"))),
        Value::String(s) => Ok(Some(s.trim().to_string())),
        _ => Err(invalid(format!("{field} must be a string"))),
    }
}

/// `active`: a boolean. Entra has sent "True" and "False" as strings, so those count too.
fn boolean(v: &Value, field: &str) -> ScimRes<bool> {
    match v {
        Value::Bool(b) => Ok(*b),
        Value::String(s) if s.eq_ignore_ascii_case("true") => Ok(true),
        Value::String(s) if s.eq_ignore_ascii_case("false") => Ok(false),
        _ => Err(invalid(format!("{field} must be true or false"))),
    }
}

fn email(v: &Value, field: &str) -> ScimRes<Option<String>> {
    let e = text(v, field, 254)?;
    match e {
        Some(e) if !users::valid_email(&e) => Err(invalid(format!("{field} must be an email address"))),
        e => Ok(e),
    }
}

/// From `emails`: the primary address, else the work one, else the first.
fn pick_email(v: &Value) -> ScimRes<Option<String>> {
    let list = match v {
        Value::Null => return Ok(None),
        Value::Array(l) => l,
        _ => return Err(invalid("emails must be a list")),
    };
    let chosen = list
        .iter()
        .find(|e| matches!(attr(e, "primary"), Value::Bool(true)) || attr(e, "primary").as_str().is_some_and(|p| p.eq_ignore_ascii_case("true")))
        .or_else(|| list.iter().find(|e| attr(e, "type").as_str().is_some_and(|t| t.eq_ignore_ascii_case("work"))))
        .or_else(|| list.first());
    chosen.map_or(Ok(None), |e| email(attr(e, "value"), "emails.value"))
}

fn set_name(a: &mut Attrs, v: &Value) -> ScimRes<()> {
    if !v.is_object() && !v.is_null() {
        return Err(invalid("name must be an object"));
    }
    a.given_name = text(attr(v, "givenName"), "name.givenName", 100)?;
    a.family_name = text(attr(v, "familyName"), "name.familyName", 100)?;
    a.formatted = text(attr(v, "formatted"), "name.formatted", 100)?;
    Ok(())
}

fn required_user_name(v: &Value) -> ScimRes<String> {
    text(v, "userName", 256)?.ok_or_else(|| invalid("userName is required"))
}

/// The attributes of a POST or PUT body. `current` is the user a PUT replaces: an
/// `externalId` or `active` the body leaves out is kept from it. Without `emails`, the
/// email is the userName when that is an address (Okta's default profile).
pub fn from_resource(v: &Value, current: Option<&Attrs>) -> ScimRes<Attrs> {
    if !v.is_object() {
        return Err(ScimError::new(StatusCode::BAD_REQUEST, Some("invalidSyntax"), "Send the user as a JSON object"));
    }
    let user_name = required_user_name(attr(v, "userName"))?;
    let mut a = Attrs {
        external_id: text(attr(v, "externalId"), "externalId", 256)?.or_else(|| current.and_then(|c| c.external_id.clone())),
        display_name: text(attr(v, "displayName"), "displayName", 100)?,
        email: pick_email(attr(v, "emails"))?.or_else(|| Some(user_name.clone()).filter(|n| users::valid_email(n))),
        user_name,
        active: match key(v, "active") {
            None | Some(Value::Null) => current.is_none_or(|c| c.active),
            Some(b) => boolean(b, "active")?,
        },
        ..Attrs::default()
    };
    set_name(&mut a, attr(v, "name"))?;
    set_enterprise(&mut a.enterprise, "replace", attr(v, ENTERPRISE_SCHEMA))?;
    Ok(a)
}

/// The Enterprise User attribute an extension sub-path names, lowercase, without the
/// URN: `department`, `manager`, `manager.value`.
fn enterprise_attr(name: &str) -> Option<&'static str> {
    Some(match name {
        "employeenumber" => "employeeNumber",
        "costcenter" => "costCenter",
        "organization" => "organization",
        "division" => "division",
        "department" => "department",
        "manager" => "manager",
        "manager.value" => "manager.value",
        _ => return None,
    })
}

/// The whole extension object: `replace` (and a POST or PUT) sets what it holds and
/// keeps what it leaves out of a PATCH; a POST or PUT starts from nothing.
fn set_enterprise(e: &mut Enterprise, op: &str, v: &Value) -> ScimRes<()> {
    match v {
        Value::Null => Ok(()),
        Value::Object(o) => {
            for (k, x) in o {
                if let Some(name) = enterprise_attr(&k.to_ascii_lowercase()) {
                    set_enterprise_attr(e, op, name, x)?;
                }
            }
            Ok(())
        }
        _ => Err(invalid(format!("{ENTERPRISE_SCHEMA} must be an object"))),
    }
}

/// A manager reference: `{"value": id}`, Entra's `[{"value": id, "$ref": ...}]`, or the id
/// itself. Whether it names someone in the tenant is checked when it's saved. `None` when
/// it holds only the read-only `$ref` or `displayName`, which leave the manager as it is.
fn manager_id(v: &Value) -> ScimRes<Option<Option<String>>> {
    match v {
        Value::Array(l) if l.len() > 1 => Err(invalid("manager takes one manager")),
        Value::Array(l) => l.first().map_or(Ok(Some(None)), manager_id),
        Value::Object(o) if !o.keys().any(|k| k.eq_ignore_ascii_case("value")) => Ok(None),
        Value::Object(_) => text(attr(v, "value"), "manager.value", 64).map(Some),
        v => text(v, "manager.value", 64).map(Some),
    }
}

fn set_enterprise_attr(e: &mut Enterprise, op: &str, name: &str, v: &Value) -> ScimRes<()> {
    let remove = op == "remove";
    let field = |v: &Value| if remove { Ok(None) } else { text(v, name, ENTERPRISE_MAX) };
    match name {
        "employeeNumber" => e.employee_number = field(v)?,
        "costCenter" => e.cost_center = field(v)?,
        "organization" => e.organization = field(v)?,
        "division" => e.division = field(v)?,
        "department" => e.department = field(v)?,
        _ if remove => e.manager = None,
        _ => {
            if let Some(m) = manager_id(v)? {
                e.manager = m;
            }
        }
    }
    Ok(())
}

/// Applies a PatchOp (RFC 7644 section 3.5.2): `add` and `replace` of `active`,
/// `userName`, `externalId`, `displayName`, `name` and its parts, and `emails`
/// (whole, or `emails[type eq "work"].value`); `remove` of the optional ones. With no
/// `path`, the value is an object of attributes (Okta's deactivation). `op` is any case
/// (Entra sends `Replace`). The Enterprise User extension's attributes, by their full
/// path (`urn:...:enterprise:2.0:User:department`), the extension's URN with an object,
/// or their bare names as Entra has sent them (`manager`). Attributes SuperBot doesn't
/// keep (title, phone numbers, roles, groups, a password) are ignored and never stored.
pub fn apply_patch(a: &mut Attrs, v: &Value) -> ScimRes<()> {
    let syntax = |d: &str| ScimError::new(StatusCode::BAD_REQUEST, Some("invalidSyntax"), d);
    let ops = v.as_object().and_then(|o| o.iter().find(|(k, _)| k.eq_ignore_ascii_case("Operations"))).map(|(_, ops)| ops);
    let ops = ops.and_then(Value::as_array).filter(|o| !o.is_empty()).ok_or_else(|| syntax("Operations must be a list of operations"))?;
    for op in ops {
        let kind = attr(op, "op").as_str().map(str::to_ascii_lowercase);
        let kind = match kind.as_deref() {
            Some(k @ ("add" | "replace" | "remove")) => k.to_string(),
            _ => return Err(syntax("op must be add, replace, or remove")),
        };
        let value = attr(op, "value");
        match attr(op, "path").as_str().map(str::trim).filter(|p| !p.is_empty()) {
            Some(path) => apply_path(a, &kind, path, value)?,
            None if kind == "remove" => return Err(ScimError::new(StatusCode::BAD_REQUEST, Some("noTarget"), "remove needs a path")),
            None => {
                let obj = value.as_object().ok_or_else(|| syntax("Without a path, value must be an object of attributes"))?;
                let mut seen = std::collections::HashSet::new();
                for (k, val) in obj {
                    if !seen.insert(normal_path(k)) {
                        return Err(invalid(format!("{k} is sent more than once")));
                    }
                    apply_path(a, &kind, k, val)?;
                }
            }
        }
    }
    Ok(())
}

/// A PATCH path without the core schema prefix, spaces collapsed, lowercase.
fn normal_path(path: &str) -> String {
    let path = path.get(..USER_SCHEMA.len() + 1).filter(|p| p.eq_ignore_ascii_case(&format!("{USER_SCHEMA}:"))).map_or(path, |p| &path[p.len()..]);
    path.split_whitespace().collect::<Vec<_>>().join(" ").to_ascii_lowercase()
}

fn apply_path(a: &mut Attrs, op: &str, path: &str, v: &Value) -> ScimRes<()> {
    let p = normal_path(path);
    let remove = op == "remove";
    let cant_remove = |f: &str| Err(invalid(format!("{f} can't be removed")));
    match p.as_str() {
        "active" if remove => return cant_remove("active"),
        "active" => a.active = boolean(v, "active")?,
        "username" if remove => return cant_remove("userName"),
        "username" => a.user_name = required_user_name(v)?,
        "externalid" if remove => a.external_id = None,
        "externalid" => a.external_id = text(v, "externalId", 256)?,
        "displayname" if remove => a.display_name = None,
        "displayname" => a.display_name = text(v, "displayName", 100)?,
        "name" if remove => (a.given_name, a.family_name, a.formatted) = (None, None, None),
        "name" => {
            // Replacing a complex attribute changes the parts sent and keeps the rest.
            if !v.is_object() {
                return Err(invalid("name must be an object"));
            }
            for (k, keep) in [("givenName", &mut a.given_name), ("familyName", &mut a.family_name), ("formatted", &mut a.formatted)] {
                if let Some(x) = key(v, k) {
                    *keep = text(x, &format!("name.{k}"), 100)?;
                }
            }
        }
        "name.givenname" => a.given_name = if remove { None } else { text(v, "name.givenName", 100)? },
        "name.familyname" => a.family_name = if remove { None } else { text(v, "name.familyName", 100)? },
        "name.formatted" => a.formatted = if remove { None } else { text(v, "name.formatted", 100)? },
        "emails" => a.email = if remove { None } else { pick_email(v)? },
        "emails[type eq \"work\"].value" | "emails[primary eq true].value" | "emails.value" => a.email = if remove { None } else { email(v, "emails.value")? },
        p => {
            let ext = ENTERPRISE_SCHEMA.to_ascii_lowercase();
            if p == ext {
                if remove || v.is_null() {
                    a.enterprise = Enterprise::default();
                } else {
                    set_enterprise(&mut a.enterprise, op, v)?;
                }
            } else if let Some(name) = enterprise_attr(p.strip_prefix(&format!("{ext}:")).unwrap_or(p)) {
                set_enterprise_attr(&mut a.enterprise, op, name, v)?;
            }
        }
    }
    Ok(())
}

/// The SSO identity a new user gets when the tenant links a provider: `externalId` is
/// that provider's subject for the person (Entra: the object id; Okta: the user id).
struct Link {
    provider: String,
    issuer: String,
    subject: String,
    tenant: Option<String>,
}

fn sso_link(a: &Auth, t: &ScimToken, external_id: Option<&str>) -> ScimRes<Option<Link>> {
    let Some(pid) = &t.sso_provider else { return Ok(None) };
    let p = a.sso.provider(pid).ok_or_else(|| server_error(format!("This SCIM tenant links the SSO provider {pid}, which isn't in SSO_PROVIDERS any more.")))?;
    let hint = if p.type_name() == "entra" { " Map the user's objectId to externalId in the provisioning attribute mappings." } else { "" };
    let ext = external_id.ok_or_else(|| invalid(format!("externalId is required: this tenant links the SSO provider {pid}, so externalId must be the person's subject there.{hint}")))?;
    let subject = p.subject(ext).map_err(|e| invalid(format!("externalId: {e}.{hint}")))?;
    let (issuer, tenant) = p.issuer_for(None).map_err(server_error)?;
    Ok(Some(Link { provider: pid.clone(), issuer, subject, tenant }))
}

fn fields<'a>(d: &'a Attrs, shown: &'a str, active: Option<bool>) -> ScimFields<'a> {
    ScimFields {
        user_name: &d.user_name,
        external_id: d.external_id.as_deref(),
        given_name: d.given_name.as_deref(),
        family_name: d.family_name.as_deref(),
        scim_display_name: d.display_name.as_deref(),
        formatted: d.formatted.as_deref(),
        display_name: shown,
        email: d.email.as_deref(),
        active,
        enterprise: &d.enterprise,
    }
}

/// Audits what changed on a user and acts on it: deactivating drops their unredeemed SSO
/// app codes, ends every session, and closes open screens (their links don't know who
/// opened them). `active` is what this request set, if it changed it.
async fn changed(app: &AppState, a: &Auth, c: &Caller, before_user: &User, before: Option<&ScimUser>, after: &ScimUser, active: Option<bool>) {
    let by = &c.who;
    let ev = |action: &str| by.event(action).target("user", &after.user.id);
    let mut changes = Map::new();
    let mut diff = |key: &str, from: Value, to: Value| {
        if from != to {
            changes.insert(key.into(), json!({ "from": from, "to": to }));
        }
    };
    diff("name", json!(before_user.name), json!(after.user.name));
    diff("email", json!(before_user.email), json!(after.user.email));
    if let Some(b) = before {
        diff("userName", json!(b.user_name), json!(after.user_name));
        diff("externalId", json!(b.external_id), json!(after.external_id));
        diff("givenName", json!(b.given_name), json!(after.given_name));
        diff("familyName", json!(b.family_name), json!(after.family_name));
        diff("displayName", json!(b.display_name), json!(after.display_name));
        diff("formatted", json!(b.formatted), json!(after.formatted));
        let (was, now) = (&b.enterprise, &after.enterprise);
        diff("employeeNumber", json!(was.employee_number), json!(now.employee_number));
        diff("costCenter", json!(was.cost_center), json!(now.cost_center));
        diff("organization", json!(was.organization), json!(now.organization));
        diff("division", json!(was.division), json!(now.division));
        diff("department", json!(was.department), json!(now.department));
        diff("manager", json!(was.manager), json!(now.manager));
    }
    if !changes.is_empty() {
        app.db.record(&ev("user.updated").details(json!({ "changes": changes, "tenant": c.token.tenant })));
    }
    match active {
        Some(true) => {
            let resumed = crate::handover::user_enabled(app, by, &after.user.id);
            app.db.record(&ev("user.enabled").details(json!({ "tenant": c.token.tenant, "routinesResumed": resumed })));
            crate::teams::user_enabled(app, by, &after.user.id).await;
            crate::deprovision::user_enabled(app, by, &after.user.id).await;
        }
        Some(false) => {
            a.sso.forget_user(&after.user.id);
            a.mfa.forget_user(&after.user.id);
            let n = app.db.revoke_user_sessions(&after.user.id, by.actor.id.as_deref().unwrap_or("scim"), "deprovisioned by SCIM");
            let paused = crate::handover::user_disabled(app, by, &after.user.id);
            app.db.record(&ev("user.disabled").details(json!({ "sessionsRevoked": n, "routinesPaused": paused, "tenant": c.token.tenant })));
            if let Some(screens) = &app.screens {
                screens.rotate_all().await;
            }
            crate::machines::screens::rotate_all(app).await;
            crate::machines::offboard::left(app, by, &after.user.id, crate::machines::offboard::DEPROVISIONED);
            crate::deprovision::user_disabled(app, by, &after.user.id, crate::deprovision::SCIM).await;
        }
        None => {}
    }
}

/// Saves `d` over an existing user. `taken` is a re-provisioning after DELETE or a user the
/// tenant takes on: the audit event for it, recorded once the save succeeded. Without
/// it, the user must still be the tenant's and live when the write runs. `externalId`
/// can be set once, never changed. The shown name is rebuilt only when a name attribute
/// changed, so an admin's rename lasts until the IdP sends a new name.
async fn update(app: &AppState, a: &Auth, c: &Caller, user: &User, before: Option<&ScimUser>, d: &Attrs, taken: Option<(&str, Value)>) -> ScimRes<ScimUser> {
    if let Some(old) = before.and_then(|b| b.external_id.as_deref())
        && d.external_id.as_deref() != Some(old)
    {
        return Err(ScimError::new(StatusCode::BAD_REQUEST, Some("mutability"), "externalId can't change once set. Delete the user and provision the person again."));
    }
    let shown = match before {
        Some(b) if Attrs::of(b).names() == d.names() => user.name.clone(),
        _ => d.shown_name(),
    };
    let active = (d.active != user.active()).then_some(d.active);
    let f = fields(d, &shown, active);
    app.db.save_scim_user(&c.token.tenant, &user.id, &f, taken.is_some()).map_err(|e| save_error(app, c, e, Some(&user.id), f.email))?;
    let after = app.db.scim_user(&c.token.tenant, &user.id).ok_or_else(|| server_error("user not saved"))?;
    if let Some((action, details)) = taken {
        app.db.record(&c.who.event(action).target("user", &user.id).details(details));
    }
    changed(app, a, c, user, before, &after, active).await;
    Ok(after)
}

/// The JSON body. A body over MAX_BODY, or one that can't be read, is a SCIM error too.
fn parse_body(body: Result<Bytes, BytesRejection>) -> ScimRes<Value> {
    let body = body.map_err(|e| ScimError::new(e.status(), None, e.body_text()))?;
    let v = serde_json::from_slice(&body).map_err(|e| ScimError::new(StatusCode::BAD_REQUEST, Some("invalidSyntax"), format!("Invalid JSON: {e}")))?;
    no_twice(&v)?;
    Ok(v)
}

/// Attribute names are case-insensitive, so `active` and `Active` in one object would
/// be the same attribute twice. Refused rather than guessed at, at any depth.
fn no_twice(v: &Value) -> ScimRes<()> {
    match v {
        Value::Object(o) => {
            let mut seen = std::collections::HashSet::new();
            for (k, x) in o {
                if !seen.insert(k.to_ascii_lowercase()) {
                    return Err(invalid(format!("{k} is sent more than once")));
                }
                no_twice(x)?;
            }
            Ok(())
        }
        Value::Array(l) => l.iter().try_for_each(no_twice),
        _ => Ok(()),
    }
}

fn need(app: &AppState, c: &Caller, id: &str) -> ScimRes<ScimUser> {
    app.db.scim_user(&c.token.tenant, id).ok_or_else(|| missing("User"))
}

/// `GET /scim/v2/Users?filter=&startIndex=&count=`: the tenant's users, deactivated
/// ones included; deleted ones are gone.
pub async fn list_users(State(app): State<AppState>, Extension(c): Extension<Caller>, headers: HeaderMap, Query(q): Query<HashMap<String, String>>) -> ScimRes {
    let (start, count) = page(&q)?;
    let filter = q.iter().find(|(k, _)| k.eq_ignore_ascii_case("filter")).map(|(_, v)| v.as_str()).filter(|f| !f.trim().is_empty());
    let key = filter.map(parse_filter).transpose().map_err(|e| ScimError::new(StatusCode::BAD_REQUEST, Some("invalidFilter"), e))?;
    let (total, users) = app.db.scim_list(&c.token.tenant, key.as_ref(), start - 1, count);
    let base = base_url(&headers);
    Ok(list(users.iter().map(|u| resource(&base, u)).collect(), total, start))
}

pub async fn get_user(State(app): State<AppState>, Extension(c): Extension<Caller>, headers: HeaderMap, Path(id): Path<String>) -> ScimRes {
    Ok(scim_json(StatusCode::OK, resource(&base_url(&headers), &need(&app, &c, &id)?)))
}

/// `POST /scim/v2/Users`. Idempotent on `externalId`: a user the tenant has gets 409; one
/// it deleted comes back, the same user. With a linked SSO provider, a person whose
/// identity an admin (or just-in-time sign-in) already linked to a user is that user.
/// Otherwise a new user, with the default role.
pub async fn create_user(State(app): State<AppState>, Extension(a): Extension<Arc<Auth>>, Extension(c): Extension<Caller>, headers: HeaderMap, body: Result<Bytes, BytesRejection>) -> ScimRes {
    let d = from_resource(&parse_body(body)?, None)?;
    let tenant = c.token.tenant.as_str();
    let base = base_url(&headers);
    let created = |s: &ScimUser| {
        let body = resource(&base, s);
        let mut r = scim_json(StatusCode::CREATED, body.clone());
        if let Some(Ok(at)) = body["meta"]["location"].as_str().map(HeaderValue::from_str) {
            r.headers_mut().insert(header::LOCATION, at);
        }
        Ok(r)
    };
    if let Some(ext) = &d.external_id
        && let Some(found) = app.db.scim_find(tenant, &ScimKey::ExternalId(ext.clone()))
    {
        if found.deleted_at.is_none() {
            return Err(uniqueness(format!("A user with this externalId exists already: {}", found.user.id)));
        }
        let restored = json!({ "tenant": tenant, "externalId": ext, "userName": d.user_name });
        let after = update(&app, &a, &c, &found.user.clone(), Some(&found), &d, Some(("scim.user_restored", restored))).await?;
        return created(&after);
    }
    if app.db.scim_find(tenant, &ScimKey::UserName(d.user_name.clone())).is_some() {
        return Err(uniqueness("A user with this userName exists already"));
    }
    let link = sso_link(&a, &c.token, d.external_id.as_deref())?;
    if let Some(l) = &link
        && let Some((_, user)) = app.db.identity(&l.issuer, &l.subject)
    {
        if user.id == users::OPERATOR {
            return Err(uniqueness("This identity belongs to the owner (break-glass) account, which SCIM never manages."));
        }
        // A user another tenant manages stays its own, even deleted there: only it may restore them.
        let mine = match app.db.scim_user_of(&user.id) {
            Some(o) if o.tenant != tenant => return Err(uniqueness("This person is managed by another SCIM tenant.")),
            Some(o) if o.deleted_at.is_none() => return Err(uniqueness("This person is provisioned already, under another externalId.")),
            o => o,
        };
        let linked = json!({ "tenant": tenant, "externalId": d.external_id, "userName": d.user_name, "provider": l.provider, "subject": l.subject });
        let action = if mine.is_some() { "scim.user_restored" } else { "scim.user_linked" };
        let after = update(&app, &a, &c, &user, None, &d, Some((action, linked))).await?;
        return created(&after);
    }
    let shown = d.shown_name();
    let created_by = c.who.actor.id.clone();
    let identity = link.as_ref().map(|l| NewIdentity {
        provider: &l.provider,
        issuer: &l.issuer,
        subject: &l.subject,
        tenant: l.tenant.as_deref(),
        email: None,
        created_by: created_by.as_deref(),
    });
    let f = fields(&d, &shown, Some(d.active));
    let user = app.db.create_scim_user(tenant, &f, a.scim.default_role, identity.as_ref()).map_err(|e| save_error(&app, &c, e, None, f.email))?;
    app.db.record(&c.who.event("user.created").target("user", &user.id).details(json!({
        "email": user.email, "name": user.name, "role": user.role, "reason": "scim",
        "tenant": tenant, "externalId": d.external_id, "userName": d.user_name, "active": d.active,
    })));
    if let Some(l) = &link
        && let Some(i) = app.db.identities(&user.id).first()
    {
        app.db.record(&c.who.event("user.identity_linked").target("user", &user.id).details(json!({ "identity": i.id, "provider": l.provider, "issuer": l.issuer, "subject": l.subject, "tenant": l.tenant })));
    }
    created(&need(&app, &c, &user.id)?)
}

/// `PUT /scim/v2/Users/{id}`: the whole user. An `externalId` or `active` left out is kept.
pub async fn replace_user(State(app): State<AppState>, Extension(a): Extension<Arc<Auth>>, Extension(c): Extension<Caller>, headers: HeaderMap, Path(id): Path<String>, body: Result<Bytes, BytesRejection>) -> ScimRes {
    let before = need(&app, &c, &id)?;
    let d = from_resource(&parse_body(body)?, Some(&Attrs::of(&before)))?;
    let after = update(&app, &a, &c, &before.user, Some(&before), &d, None).await?;
    Ok(scim_json(StatusCode::OK, resource(&base_url(&headers), &after)))
}

/// `PATCH /scim/v2/Users/{id}`. `active: false` disables the user and ends their sessions.
pub async fn patch_user(State(app): State<AppState>, Extension(a): Extension<Arc<Auth>>, Extension(c): Extension<Caller>, headers: HeaderMap, Path(id): Path<String>, body: Result<Bytes, BytesRejection>) -> ScimRes {
    let before = need(&app, &c, &id)?;
    let mut d = Attrs::of(&before);
    apply_patch(&mut d, &parse_body(body)?)?;
    let after = update(&app, &a, &c, &before.user, Some(&before), &d, None).await?;
    Ok(scim_json(StatusCode::OK, resource(&base_url(&headers), &after)))
}

/// `DELETE /scim/v2/Users/{id}`: the user is disabled, their sessions end, and the tenant
/// can't see them any more. Nothing is destroyed: the user and its audit history stay.
/// When taking them off their group's team fails (ADR 0171), the rest still happens and
/// the answer is a 500. The IdP's retry of that DELETE finishes taking them off.
pub async fn delete_user(State(app): State<AppState>, Extension(a): Extension<Arc<Auth>>, Extension(c): Extension<Caller>, Path(id): Path<String>) -> ScimRes {
    let Some(before) = app.db.scim_user(&c.token.tenant, &id) else {
        if groups::left_behind(&app, &a, &c, &id) {
            groups::user_deleted(&app, &a, &c, &id).await.map_err(server_error)?;
            return Ok(StatusCode::NO_CONTENT.into_response());
        }
        return Err(missing("User"));
    };
    if !app.db.delete_scim_user(&c.token.tenant, &id) {
        return Err(missing("User"));
    }
    a.sso.forget_user(&id);
    a.mfa.forget_user(&id);
    let n = app.db.revoke_user_sessions(&id, c.who.actor.id.as_deref().unwrap_or("scim"), "deleted by SCIM");
    let paused = crate::handover::user_disabled(&app, &c.who, &id);
    app.db.record(&c.who.event("scim.user_deleted").target("user", &id).details(json!({
        "tenant": c.token.tenant, "externalId": before.external_id, "userName": before.user_name, "sessionsRevoked": n, "routinesPaused": paused,
    })));
    if before.user.active()
        && let Some(screens) = &app.screens
    {
        screens.rotate_all().await;
    }
    if before.user.active() {
        crate::machines::screens::rotate_all(&app).await;
    }
    crate::machines::offboard::left(&app, &c.who, &id, crate::machines::offboard::DEPROVISIONED);
    let left = groups::user_deleted(&app, &a, &c, &id).await;
    roles::user_deleted(&app, &a, &c.who, &id).await;
    crate::deprovision::user_disabled(&app, &c.who, &id, crate::deprovision::SCIM_DELETE).await;
    left.map_err(server_error)?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

// Tokens (admin, under /api): made and revoked with botctl.

/// A tenant name: lowercase letters, digits, and dashes, like `entra` or `okta-prod`.
fn tenant_name(v: &Value) -> Res<String> {
    let t = v.as_str().map(str::trim).unwrap_or("");
    let ok = (1..=32).contains(&t.len()) && t.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-') && !t.starts_with('-');
    ok.then(|| t.to_string()).ok_or_else(|| bad("tenant must be 1 to 32 lowercase letters, digits, or dashes, like entra or okta"))
}

/// `GET /api/scim/tokens`: every token (never a value), and whether SCIM is on.
pub async fn list_tokens(State(app): State<AppState>, Extension(a): Extension<Arc<Auth>>) -> Json<Value> {
    Json(json!({ "enabled": a.scim.enabled, "defaultRole": a.scim.default_role, "groups": a.scim.groups, "groupRoles": a.scim.group_roles, "tokens": app.db.scim_tokens() }))
}

/// `POST /api/scim/tokens {tenant, label?, sso?}`. `sso` names a configured SSO provider
/// whose subjects this tenant's `externalId`s are; a tenant's first token sets it for
/// good. The token is returned once; only its hash is kept.
pub async fn create_token(State(app): State<AppState>, Extension(a): Extension<Arc<Auth>>, Extension(by): Extension<Who>, Json(v): Json<Value>) -> Res<Response> {
    let tenant = tenant_name(&v["tenant"])?;
    if a.scim.google.as_ref().is_some_and(|g| g.settings.tenant == tenant) {
        return Err(ApiError(StatusCode::CONFLICT, format!("Tenant {tenant} is the Google Workspace sync's (GOOGLE_DIRECTORY_TENANT), and it must be its only writer. Use another tenant name.")));
    }
    let label = users::clean_label(&v["label"]);
    let sso = match &v["sso"] {
        Value::Null => None,
        Value::String(s) if s.trim().is_empty() => None,
        Value::String(s) => Some(s.trim().to_ascii_lowercase()),
        _ => return Err(bad("sso must be an SSO provider id")),
    };
    if let Some(pid) = &sso {
        let p = a.sso.provider(pid).ok_or_else(|| {
            let known: Vec<&str> = a.sso.providers.iter().map(|p| p.id.as_str()).collect();
            bad(if known.is_empty() { "SSO is off: set SSO_PROVIDERS, or leave sso out".to_string() } else { format!("sso must be one of: {}", known.join(", ")) })
        })?;
        p.issuer_for(None).map_err(|e| bad(format!("SCIM can't link {pid}: {e}")))?;
    }
    let token = users::new_secret(TOKEN_PREFIX);
    let t = app.db.create_scim_token(&tenant, label.as_deref(), sso.as_deref(), &users::hash(&token), by.actor.id.as_deref()).map_err(|first| {
        let had = first.map_or("no SSO provider".to_string(), |p| format!("the SSO provider {p}"));
        ApiError(StatusCode::CONFLICT, format!("Tenant {tenant} links {had}; its tokens all must. Use a new tenant name for another link."))
    })?;
    app.db.record(&by.event("scim.token_created").target("scim_token", &t.id).details(json!({ "tenant": t.tenant, "label": t.label, "sso": t.sso_provider })));
    let mut res = (StatusCode::CREATED, Json(json!({ "token": token, "scimToken": t, "enabled": a.scim.enabled }))).into_response();
    res.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok(res)
}

/// `DELETE /api/scim/tokens/{id}`. The tenant's users stay as they are.
pub async fn revoke_token(State(app): State<AppState>, Extension(by): Extension<Who>, Path(id): Path<String>) -> Res {
    let t = app.db.scim_token(&id).filter(|t| t.revoked_at.is_none()).ok_or_else(|| not_found("SCIM token"))?;
    if !app.db.revoke_scim_token(&id, by.actor.id.as_deref().unwrap_or("")) {
        return Err(not_found("SCIM token"));
    }
    app.db.record(&by.event("scim.token_revoked").target("scim_token", &id).details(json!({ "tenant": t.tenant, "label": t.label })));
    Ok(Json(json!({ "ok": true })))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settings_are_off_by_default_and_never_make_admins() {
        let s = Scim::from_env("", "", "", "").unwrap();
        assert!(!s.enabled && !s.groups && !s.group_roles);
        assert_eq!(s.default_role, Role::Member);
        assert!(Scim::from_env("on", "", "", "").unwrap().enabled);
        assert!(!Scim::from_env("on", "", "", "").unwrap().groups, "groups need their own switch");
        assert!(Scim::from_env("on", "", "on", "").unwrap().groups);
        assert!(!Scim::from_env("on", "", "on", "").unwrap().group_roles, "and group roles theirs");
        assert!(Scim::from_env("on", "", "on", "on").unwrap().group_roles);
        assert!(Scim::from_env("on", "", "", "on").is_err(), "group roles need groups");
        assert!(Scim::from_env("on", "", "on", "admin").is_err());
        assert_eq!(Scim::from_env("on", "read-only", "", "").unwrap().default_role, Role::Readonly);
        assert!(Scim::from_env("maybe", "", "", "").is_err());
        assert!(Scim::from_env("on", "", "teams", "").is_err());
        assert!(Scim::from_env("on", "admin", "", "").is_err());
        assert!(Scim::from_env("on", "owner", "", "").is_err());
    }

    #[test]
    fn the_example_env_files_leave_scim_off() {
        for (name, text) in [(".env.example", include_str!("../../.env.example")), ("deploy/docker/.env.example", include_str!("../../deploy/docker/.env.example"))] {
            let vars: HashMap<&str, &str> = text.lines().filter(|l| !l.trim_start().starts_with('#')).filter_map(|l| l.split_once('=')).map(|(k, v)| (k.trim(), v.trim())).collect();
            let get = |k: &str| vars.get(k).copied().unwrap_or("");
            let s = Scim::from_env(get("SCIM"), get("SCIM_DEFAULT_ROLE"), get("SCIM_GROUPS"), get("SCIM_GROUP_ROLES")).unwrap_or_else(|e| panic!("{name}: {e}"));
            assert!(!s.enabled && !s.groups && !s.group_roles && vars.contains_key("SCIM"), "{name}");
            assert!(text.contains("SCIM_GROUPS"), "{name} documents SCIM_GROUPS");
            assert!(text.contains("SCIM_GROUP_ROLES"), "{name} documents SCIM_GROUP_ROLES");
            assert!(google::Settings::from_env(&|k| get(k).to_string(), &s, &|_| None).unwrap_or_else(|e| panic!("{name}: {e}")).is_none(), "{name}");
            assert!(vars.contains_key("GOOGLE_DIRECTORY_SYNC") && text.contains("GOOGLE_DIRECTORY_GROUPS"), "{name} documents the Google Workspace sync");
        }
    }

    #[test]
    fn filters() {
        assert_eq!(parse_filter(r#"userName eq "ada@example.com""#), Ok(ScimKey::UserName("ada@example.com".into())));
        assert_eq!(parse_filter(r#"  USERNAME  EQ  "Ada"  "#), Ok(ScimKey::UserName("Ada".into())));
        assert_eq!(parse_filter(r#"externalId eq "00u1""#), Ok(ScimKey::ExternalId("00u1".into())));
        assert_eq!(parse_filter(r#"urn:ietf:params:scim:schemas:core:2.0:User:userName eq "a""#), Ok(ScimKey::UserName("a".into())));
        assert_eq!(parse_filter(r#"userName eq "say \"hi\" \\ ok""#), Ok(ScimKey::UserName(r#"say "hi" \ ok"#.into())));
        for bad in [
            "",
            "userName",
            "userName eq",
            r#"userName ne "a""#,
            r#"userName co "a""#,
            r#"emails eq "a""#,
            "userName eq a",
            r#"userName eq """#,
            r#"userName eq "a" and active eq true"#,
            r#"userName eq "a" or userName eq "b""#,
            r#"userName eq "unterminated"#,
        ] {
            assert!(parse_filter(bad).is_err(), "{bad}");
        }
        assert!(parse_filter(&format!("userName eq \"{}\"", "x".repeat(513))).is_err());
    }

    fn ada() -> Attrs {
        from_resource(
            &json!({
                "schemas": [USER_SCHEMA], "userName": "ada@example.com", "externalId": "e1",
                "name": { "givenName": "Ada", "familyName": "Lovelace" },
                "emails": [{ "value": "home@example.com", "type": "home" }, { "value": "ada@work.example", "type": "work" }],
                "password": "never-kept", "title": "Countess", "roles": [{ "value": "admin" }],
            }),
            None,
        )
        .unwrap()
    }

    #[test]
    fn resources_are_read_strictly_and_extras_ignored() {
        let a = ada();
        assert_eq!((a.user_name.as_str(), a.external_id.as_deref(), a.email.as_deref(), a.active), ("ada@example.com", Some("e1"), Some("ada@work.example"), true));
        assert_eq!(a.shown_name(), "Ada Lovelace");
        let only = from_resource(&json!({ "userName": "grace@example.com" }), None).unwrap();
        assert_eq!((only.shown_name().as_str(), only.email.as_deref()), ("grace", Some("grace@example.com")));
        let upn = from_resource(&json!({ "userName": "grace" }), None).unwrap();
        assert_eq!(upn.email, None, "a userName that isn't an address isn't an email");
        let primary = from_resource(&json!({ "userName": "x", "emails": [{ "value": "a@example.com" }, { "value": "b@example.com", "primary": true }] }), None).unwrap();
        assert_eq!(primary.email.as_deref(), Some("b@example.com"));
        for bad in [
            json!({}),
            json!([]),
            json!({ "userName": "  " }),
            json!({ "userName": 7 }),
            json!({ "userName": "a\nb" }),
            json!({ "userName": "x", "active": "maybe" }),
            json!({ "userName": "x", "emails": [{ "value": "not-an-email" }] }),
            json!({ "userName": "x", "emails": "a@example.com" }),
            json!({ "userName": "x", "name": "Ada" }),
            json!({ "userName": "x", "displayName": "y".repeat(101) }),
        ] {
            assert!(from_resource(&bad, None).is_err(), "{bad}");
        }
        // A PUT keeps what it leaves out of externalId and active.
        let mut off = ada();
        off.active = false;
        let put = from_resource(&json!({ "userName": "ada@example.com" }), Some(&off)).unwrap();
        assert_eq!((put.external_id.as_deref(), put.active, put.email.as_deref()), (Some("e1"), false, Some("ada@example.com")));
        // Attribute names are case-insensitive, nested ones too.
        let odd = from_resource(&json!({ "USERNAME": "x@example.com", "Active": false, "Name": { "GivenName": "Ada" }, "Emails": [{ "Value": "a@example.com", "Primary": true }] }), None).unwrap();
        assert_eq!((odd.user_name.as_str(), odd.active, odd.given_name.as_deref(), odd.email.as_deref()), ("x@example.com", false, Some("Ada"), Some("a@example.com")));
    }

    #[test]
    fn patches_follow_entra_and_okta() {
        let mut a = ada();
        // Entra: capitalized ops, filtered email paths, booleans as strings.
        apply_patch(
            &mut a,
            &json!({ "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"], "Operations": [
                { "op": "Replace", "path": "emails[type eq \"work\"].value", "value": "new@work.example" },
                { "op": "Replace", "path": "name.familyName", "value": "King" },
                { "op": "Add", "path": "title", "value": "ignored" },
                { "op": "Replace", "path": "active", "value": "False" },
            ]}),
        )
        .unwrap();
        assert_eq!((a.email.as_deref(), a.family_name.as_deref(), a.active), (Some("new@work.example"), Some("King"), false));
        // Okta: no path, an object of attributes.
        apply_patch(&mut a, &json!({ "Operations": [{ "op": "replace", "value": { "active": true, "name": { "givenName": "Augusta" } } }] })).unwrap();
        assert_eq!((a.active, a.given_name.as_deref(), a.family_name.as_deref()), (true, Some("Augusta"), Some("King")), "name parts not sent are kept");
        apply_patch(&mut a, &json!({ "Operations": [{ "op": "Add", "value": { "displayName": "A. King", "name.givenName": "Ada" } }] })).unwrap();
        assert_eq!((a.display_name.as_deref(), a.given_name.as_deref()), (Some("A. King"), Some("Ada")));
        apply_patch(&mut a, &json!({ "Operations": [{ "op": "remove", "path": "name.familyName" }, { "op": "remove", "path": "emails" }] })).unwrap();
        assert_eq!((a.family_name.as_deref(), a.email.as_deref()), (None, None));
        apply_patch(&mut a, &json!({ "Operations": [{ "Op": "Replace", "Value": { "Name": { "FamilyName": "Byron" }, "ACTIVE": false } }] })).unwrap();
        assert_eq!((a.family_name.as_deref(), a.active), (Some("Byron"), false));
        // Without a displayName, the shown name follows name.formatted, then the parts.
        let mut n = Attrs { user_name: "u@example.com".into(), given_name: Some("Ada".into()), ..Attrs::default() };
        assert_eq!(n.shown_name(), "Ada");
        apply_patch(&mut n, &json!({ "Operations": [{ "op": "replace", "path": "name.formatted", "value": "Ada L." }] })).unwrap();
        assert_eq!(n.shown_name(), "Ada L.");
        apply_patch(&mut n, &json!({ "Operations": [{ "op": "replace", "path": "displayName", "value": "Countess" }] })).unwrap();
        assert_eq!(n.shown_name(), "Countess");
        apply_patch(&mut a, &json!({ "Operations": [{ "op": "replace", "path": "urn:ietf:params:scim:schemas:core:2.0:User:userName", "value": "ada2@example.com" }] })).unwrap();
        assert_eq!(a.user_name, "ada2@example.com");
        for bad in [
            json!({}),
            json!({ "Operations": [] }),
            json!({ "Operations": [{ "op": "move", "path": "active", "value": true }] }),
            json!({ "Operations": [{ "op": "remove" }] }),
            json!({ "Operations": [{ "op": "remove", "path": "userName" }] }),
            json!({ "Operations": [{ "op": "remove", "path": "active" }] }),
            json!({ "Operations": [{ "op": "replace", "value": true }] }),
            json!({ "Operations": [{ "op": "replace", "path": "active", "value": "yes" }] }),
            json!({ "Operations": [{ "op": "replace", "path": "userName", "value": "" }] }),
        ] {
            assert!(apply_patch(&mut ada(), &bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn the_same_attribute_twice_is_refused() {
        let body = |v: Value| parse_body(Ok(Bytes::from(v.to_string())));
        assert!(body(json!({ "userName": "x", "Active": false })).is_ok());
        for twice in [
            json!({ "userName": "x", "active": false, "Active": true }),
            json!({ "userName": "x", "name": { "givenName": "a", "GivenName": "b" } }),
            json!({ "userName": "x", "emails": [{ "value": "a@example.com", "Value": "b@example.com" }] }),
            json!({ "Operations": [{ "op": "replace", "value": { "active": false, "ACTIVE": true } }] }),
        ] {
            assert!(body(twice.clone()).is_err(), "{twice}");
        }
        let prefixed = json!({ "Operations": [{ "op": "replace", "value": { "active": false, "urn:ietf:params:scim:schemas:core:2.0:User:active": true } }] });
        assert!(apply_patch(&mut ada(), &prefixed).is_err());
    }

    #[test]
    fn tenant_names() {
        for ok in ["entra", "okta-prod", "g2"] {
            assert_eq!(tenant_name(&json!(ok)).unwrap(), ok);
        }
        for bad in [json!(""), json!("Entra"), json!("-x"), json!("a b"), json!("x".repeat(33)), json!(1)] {
            assert!(tenant_name(&bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn locations_use_https_except_on_loopback() {
        let h = |host: &str| {
            let mut m = HeaderMap::new();
            m.insert(header::HOST, host.parse().unwrap());
            base_url(&m)
        };
        assert_eq!(h("bots.example.com"), "https://bots.example.com/scim/v2");
        assert_eq!(h("127.0.0.1:3000"), "http://127.0.0.1:3000/scim/v2");
        assert_eq!(h("[::1]:3000"), "http://[::1]:3000/scim/v2");
    }
}
