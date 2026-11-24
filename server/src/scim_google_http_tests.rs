//! The Google Workspace sync (ADR 0162) end to end: a stand-in for Google's token
//! endpoint and Directory API, the real router, and each pass through SCIM's handlers.
//! People get accounts, follow Google, keep an admin's disable, and leave; team groups
//! become teams; a pass that can't read everything, or would remove too many people,
//! changes nobody.

use crate::db::ScimKey;
use crate::scim::google::push::Watch::{Groups, Users};
use crate::scim::google::{self, Directory, Settings};
use crate::scim_http_tests::{events, session_for, token};
use crate::tests::{call, call_with, serve_app_and_auth, serve_app_with};
use crate::users_http_tests::parse;
use crate::*;
use aws_lc_rs::encoding::AsDer;
use aws_lc_rs::signature::KeyPair;
use axum::extract::{Form, Path as UrlPath, Query, State as St};
use axum::http::HeaderMap;
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use std::collections::BTreeMap;
use std::sync::Mutex;
use zeroize::Zeroizing;

const TOKEN: &str = "ya29.stand-in";
/// The access token for the audit scope alone: the Reports API takes only it, the
/// Directory API never does.
const AUDIT_TOKEN: &str = "ya29.audit-stand-in";
const TENANT: &str = "google";

#[derive(Default)]
struct Dir {
    users: Vec<Value>,
    /// Group email to (id, name, members).
    groups: BTreeMap<String, (String, String, Vec<Value>)>,
    down: bool,
    odd: bool,
    refuse: bool,
    subjects: Vec<Option<String>>,
    public_key: Vec<u8>,
    /// Each watch asked for: its query and body.
    watches: Vec<(HashMap<String, String>, Value)>,
    /// Each channels.stop body.
    stops: Vec<Value>,
    /// Watches refused (403) once this many have been made.
    watch_limit: Option<usize>,
    /// Organizational units: (id, path, name).
    org_units: Vec<(String, String, String)>,
    /// The scopes each access token was asked for.
    scopes: Vec<String>,
    /// The audit scope isn't delegated: a token for it is refused.
    no_audit_scope: bool,
    /// Each Reports API watch asked for, and each channels.stop there.
    report_watches: Vec<(HashMap<String, String>, Value)>,
    report_stops: Vec<Value>,
}

type D = Arc<Mutex<Dir>>;

struct Google {
    url: String,
    dir: D,
    key: String,
}

impl Google {
    fn set(&self, f: impl FnOnce(&mut Dir)) {
        f(&mut self.dir.lock().unwrap());
    }

    fn members(&self, group: &str, members: Vec<Value>) {
        self.set(|d| d.groups.get_mut(group).unwrap().2 = members);
    }

    fn user(&self, id: &str, f: impl FnOnce(&mut Value)) {
        self.set(|d| f(d.users.iter_mut().find(|u| u["id"] == id).unwrap()));
    }
}

fn person(id: &str, email: &str, given: &str, suspended: bool) -> Value {
    json!({ "id": id, "primaryEmail": email, "name": { "givenName": given, "familyName": "Test", "fullName": format!("{given} Test") }, "suspended": suspended, "archived": false, "orgUnitPath": "/" })
}

fn member(id: &str) -> Value {
    json!({ "id": id, "type": "USER", "status": "ACTIVE" })
}

/// A page of two at a time, so every list takes several.
fn page(items: &[Value], q: &HashMap<String, String>, kind: &str, field: &str) -> Value {
    let from: usize = q.get("pageToken").and_then(|t| t.parse().ok()).unwrap_or(0);
    let mut v = json!({ "kind": kind });
    if from < items.len() {
        v[field] = json!(items[from..(from + 2).min(items.len())]);
    }
    if from + 2 < items.len() {
        v["nextPageToken"] = json!((from + 2).to_string());
    }
    v
}

fn gate(d: &Dir, h: &HeaderMap) -> Result<(), (StatusCode, Json<Value>)> {
    if d.down {
        return Err((StatusCode::SERVICE_UNAVAILABLE, Json(json!({ "error": { "code": 503, "status": "UNAVAILABLE", "message": "Backend Error" } }))));
    }
    if h.get("authorization").and_then(|v| v.to_str().ok()) != Some(&format!("Bearer {TOKEN}")) {
        return Err((StatusCode::UNAUTHORIZED, Json(json!({ "error": { "code": 401, "status": "UNAUTHENTICATED", "message": "Invalid Credentials" } }))));
    }
    Ok(())
}

async fn token_endpoint(St(d): St<D>, Form(form): Form<HashMap<String, String>>) -> (StatusCode, Json<Value>) {
    let mut d = d.lock().unwrap();
    let bad = || (StatusCode::UNAUTHORIZED, Json(json!({ "error": "unauthorized_client", "error_description": "Client is unauthorized to retrieve access tokens using this method." })));
    if d.refuse || form.get("grant_type").map(String::as_str) != Some("urn:ietf:params:oauth:grant-type:jwt-bearer") {
        return bad();
    }
    let jwt = form.get("assertion").cloned().unwrap_or_default();
    let Some((input, sig)) = jwt.rsplit_once('.') else { return bad() };
    let pk = aws_lc_rs::signature::UnparsedPublicKey::new(&aws_lc_rs::signature::RSA_PKCS1_2048_8192_SHA256, d.public_key.clone());
    if pk.verify(input.as_bytes(), &URL_SAFE_NO_PAD.decode(sig).unwrap_or_default()).is_err() {
        return bad();
    }
    let claims: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(input.split('.').nth(1).unwrap()).unwrap()).unwrap();
    let scope = claims["scope"].as_str().unwrap_or_default().to_string();
    assert_eq!(claims["iss"].as_str(), Some("sync@project-1.iam.gserviceaccount.com"));
    let audit = scope == google::push::REPORTS_SCOPE;
    assert!(audit || scope == google::SCOPES || scope == format!("{} {}", google::SCOPES, google::ORG_UNIT_SCOPE), "{scope}");
    d.scopes.push(scope);
    d.subjects.push(claims["sub"].as_str().map(String::from));
    if audit && d.no_audit_scope {
        return bad();
    }
    (StatusCode::OK, Json(json!({ "access_token": if audit { AUDIT_TOKEN } else { TOKEN }, "expires_in": 3599, "token_type": "Bearer" })))
}

async fn users(St(d): St<D>, h: HeaderMap, Query(q): Query<HashMap<String, String>>) -> (StatusCode, Json<Value>) {
    let d = d.lock().unwrap();
    if let Err(e) = gate(&d, &h) {
        return e;
    }
    assert_eq!((q.get("customer").map(String::as_str), q.get("projection").map(String::as_str)), (Some("my_customer"), Some("basic")));
    if d.odd {
        return (StatusCode::OK, Json(json!({ "kind": "admin#directory#users", "users": "everyone" })));
    }
    (StatusCode::OK, Json(page(&d.users, &q, "admin#directory#users", "users")))
}

async fn group(St(d): St<D>, h: HeaderMap, UrlPath(key): UrlPath<String>) -> (StatusCode, Json<Value>) {
    let d = d.lock().unwrap();
    if let Err(e) = gate(&d, &h) {
        return e;
    }
    match d.groups.get(&key) {
        Some((id, name, _)) => (StatusCode::OK, Json(json!({ "kind": "admin#directory#group", "id": id, "email": key, "name": name }))),
        None => (StatusCode::NOT_FOUND, Json(json!({ "error": { "code": 404, "message": "Resource Not Found: groupKey", "errors": [{ "reason": "notFound" }] } }))),
    }
}

async fn members(St(d): St<D>, h: HeaderMap, UrlPath(id): UrlPath<String>, Query(q): Query<HashMap<String, String>>) -> (StatusCode, Json<Value>) {
    let d = d.lock().unwrap();
    if let Err(e) = gate(&d, &h) {
        return e;
    }
    assert_eq!(q.get("includeDerivedMembership").map(String::as_str), Some("true"));
    let Some((_, (_, _, m))) = d.groups.iter().find(|(_, (gid, ..))| *gid == id) else { return (StatusCode::NOT_FOUND, Json(json!({}))) };
    (StatusCode::OK, Json(page(m, &q, "admin#directory#members", "members")))
}

async fn org_unit(St(d): St<D>, h: HeaderMap, UrlPath((customer, key)): UrlPath<(String, String)>) -> (StatusCode, Json<Value>) {
    let d = d.lock().unwrap();
    if let Err(e) = gate(&d, &h) {
        return e;
    }
    assert_eq!(customer, "my_customer");
    let found = d.org_units.iter().find(|(id, path, _)| *id == key || path.eq_ignore_ascii_case(&format!("/{key}")));
    match found {
        Some((id, path, name)) => (StatusCode::OK, Json(json!({ "kind": "admin#directory#orgUnit", "orgUnitId": id, "orgUnitPath": path, "name": name }))),
        None => (StatusCode::NOT_FOUND, Json(json!({ "error": { "code": 404, "message": "Org unit not found", "errors": [{ "reason": "notFound" }] } }))),
    }
}

async fn watch(St(d): St<D>, h: HeaderMap, Query(q): Query<HashMap<String, String>>, Json(body): Json<Value>) -> (StatusCode, Json<Value>) {
    let mut d = d.lock().unwrap();
    if let Err(e) = gate(&d, &h) {
        return e;
    }
    if d.watch_limit.is_some_and(|n| d.watches.len() >= n) {
        return (StatusCode::FORBIDDEN, Json(json!({ "error": { "code": 403, "status": "PERMISSION_DENIED", "message": "Not Authorized to access this resource/api" } })));
    }
    d.watches.push((q.clone(), body.clone()));
    let expires = db::now() + 6 * 3_600_000;
    let event = q.get("event").cloned().unwrap_or_default();
    (StatusCode::OK, Json(json!({ "kind": "api#channel", "id": body["id"], "resourceId": format!("r-{event}"), "token": body["token"], "expiration": expires.to_string() })))
}

fn gate_audit(h: &HeaderMap) -> Result<(), (StatusCode, Json<Value>)> {
    if h.get("authorization").and_then(|v| v.to_str().ok()) != Some(&format!("Bearer {AUDIT_TOKEN}")) {
        return Err((StatusCode::FORBIDDEN, Json(json!({ "error": { "code": 403, "status": "PERMISSION_DENIED", "message": "Request had insufficient authentication scopes." } }))));
    }
    Ok(())
}

async fn report_watch(St(d): St<D>, h: HeaderMap, Query(q): Query<HashMap<String, String>>, Json(body): Json<Value>) -> (StatusCode, Json<Value>) {
    let mut d = d.lock().unwrap();
    if let Err(e) = gate_audit(&h) {
        return e;
    }
    d.report_watches.push((q.clone(), body.clone()));
    let expires = db::now() + 6 * 3_600_000;
    let event = q.get("eventName").cloned().unwrap_or_default();
    (StatusCode::OK, Json(json!({ "kind": "api#channel", "id": body["id"], "resourceId": format!("a-{event}"), "token": body["token"], "expiration": expires.to_string() })))
}

async fn report_stop(St(d): St<D>, h: HeaderMap, Json(body): Json<Value>) -> (StatusCode, String) {
    let mut d = d.lock().unwrap();
    if let Err((code, _)) = gate_audit(&h) {
        return (code, String::new());
    }
    d.report_stops.push(body);
    (StatusCode::NO_CONTENT, String::new())
}

async fn stop_channel(St(d): St<D>, h: HeaderMap, Json(body): Json<Value>) -> (StatusCode, String) {
    let mut d = d.lock().unwrap();
    if let Err((code, _)) = gate(&d, &h) {
        return (code, String::new());
    }
    d.stops.push(body);
    (StatusCode::NO_CONTENT, String::new())
}

/// staff@ holds Ada, Bob, Cy (suspended), someone from outside, and eng@; eng@
/// ("Engineering", a team group) holds Ada, Eve, and someone not in the directory.
/// Dee is in neither.
async fn google_stand_in() -> Google {
    let kp = aws_lc_rs::rsa::KeyPair::generate(aws_lc_rs::rsa::KeySize::Rsa2048).unwrap();
    let pem = format!("-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n", STANDARD.encode(kp.as_der().unwrap().as_ref()));
    let mut dir = Dir { public_key: kp.public_key().as_ref().to_vec(), ..Dir::default() };
    dir.users = vec![
        person("101", "ada@example.com", "Ada", false),
        person("102", "bob@example.com", "Bob", false),
        person("103", "cy@example.com", "Cy", true),
        person("104", "dee@example.com", "Dee", false),
        person("105", "eve@example.com", "Eve", false),
    ];
    dir.groups.insert(
        "staff@example.com".into(),
        ("g1".into(), "Staff".into(), vec![member("101"), member("102"), member("103"), json!({ "type": "EXTERNAL", "status": "ACTIVE" }), json!({ "id": "g2", "type": "GROUP" })]),
    );
    dir.groups.insert("eng@example.com".into(), ("g2".into(), "Engineering".into(), vec![member("101"), member("105"), member("999")]));
    let dir = Arc::new(Mutex::new(dir));
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let url = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
    let r = Router::new()
        .route("/token", post(token_endpoint))
        .route("/admin/directory/v1/users", get(users))
        .route("/admin/directory/v1/groups/{key}", get(group))
        .route("/admin/directory/v1/groups/{id}/members", get(members))
        .route("/admin/directory/v1/customer/{customer}/orgunits/{*key}", get(org_unit))
        .route("/admin/directory/v1/users/watch", post(watch))
        .route("/admin/directory_v1/channels/stop", post(stop_channel))
        .route("/admin/reports/v1/activity/users/all/applications/admin/watch", post(report_watch))
        .route("/admin/reports_v1/channels/stop", post(report_stop))
        .with_state(dir.clone());
    tokio::spawn(async move { axum::serve(listener, r).await.unwrap() });
    let key =
        json!({ "type": "service_account", "client_email": "sync@project-1.iam.gserviceaccount.com", "private_key": pem, "private_key_id": "k1", "token_uri": format!("{url}/token") }).to_string();
    Google { url, dir, key }
}

fn settings(g: &Google) -> Settings {
    Settings {
        tenant: TENANT.into(),
        customer: "my_customer".into(),
        groups: vec!["staff@example.com".into()],
        teams: vec!["eng@example.com".into()],
        role_groups: vec![],
        org_units: vec![],
        team_org_units: vec![],
        sso: None,
        admin: Some("admin@example.com".into()),
        api: g.url.clone(),
        interval: std::time::Duration::from_secs(1800),
        max_removals: 10,
        push: None,
        push_groups: false,
    }
}

/// A Google SSO provider, so provisioned people sign in with Google. Returns its id.
fn google_sso(a: &mut Auth) -> String {
    let id = format!("g{}", random_hex(4));
    let up = id.to_ascii_uppercase();
    crate::secrets::global().put(&format!("SSO_{up}_CLIENT_SECRET"), "client-secret").unwrap();
    let port = a.hosts[0].rsplit(':').next().unwrap().to_string();
    let vars: HashMap<String, String> = HashMap::from([
        ("SSO_PROVIDERS".into(), id.clone()),
        (format!("SSO_{up}_TYPE"), "google".into()),
        (format!("SSO_{up}_CLIENT_ID"), "client-1".into()),
        ("SSO_PUBLIC_URL".into(), format!("http://127.0.0.1:{port}")),
    ]);
    a.sso = sso::Sso::from_vars(&|k| vars.get(k).cloned()).unwrap();
    id
}

struct World {
    port: u16,
    app: AppState,
    admin: String,
    sso: Option<String>,
    auth: Arc<Auth>,
}

impl World {
    fn dir(&self) -> Arc<Directory> {
        self.auth.scim.google.clone().unwrap()
    }
}

async fn world(g: &Google, with_sso: bool, tweak: impl FnOnce(&mut Settings)) -> World {
    let mut s = settings(g);
    tweak(&mut s);
    let key = g.key.clone();
    let mut sso = None;
    let (port, app, admin, _, _, auth) = serve_app_and_auth(|a| {
        a.scim.enabled = true;
        a.scim.groups = true;
        a.scim.group_roles = !s.role_groups.is_empty();
        if with_sso {
            let id = google_sso(a);
            s.sso = Some(id.clone());
            sso = Some(id);
        }
        let d = Directory::with_key(a.app.as_ref().unwrap(), s, Box::new(move || Ok(Some(Zeroizing::new(key.clone()))))).unwrap();
        a.scim.google = Some(Arc::new(d));
    })
    .await;
    World { port, app, admin, sso, auth }
}

async fn sync(w: &World, body: &str) -> (u16, Value) {
    let body = if body.is_empty() { "{}" } else { body };
    let (code, res) = call(w.port, "POST", "/api/scim/google/sync", &w.admin, body).await;
    (code, serde_json::from_str(&res).unwrap_or(json!({ "error": res })))
}

async fn synced(w: &World) -> Value {
    let (code, res) = sync(w, "").await;
    assert_eq!(code, 200, "{res}");
    assert_eq!(res["failed"], 0, "{res}");
    res
}

fn user_of(w: &World, google_id: &str) -> Option<db::ScimUser> {
    w.app.db.scim_find(TENANT, &ScimKey::ExternalId(google_id.into())).filter(|u| u.deleted_at.is_none())
}

fn uid(w: &World, google_id: &str) -> String {
    user_of(w, google_id).unwrap().user.id
}

fn active(w: &World, google_id: &str) -> bool {
    user_of(w, google_id).unwrap().user.active()
}

fn team_members(w: &World) -> Vec<String> {
    let g = w.app.db.scim_group_find(TENANT, Some("g2"), None).unwrap();
    let mut m: Vec<String> = w.app.db.scim_group_members(TENANT, &g.team_id, false).into_iter().map(|u| u.email.unwrap_or_default()).collect();
    m.sort();
    m
}

#[tokio::test]
async fn people_get_accounts_follow_google_and_leave() {
    let g = google_stand_in().await;
    let w = world(&g, true, |_| {}).await;
    let sso = w.sso.clone().unwrap();

    let res = synced(&w).await;
    assert_eq!((res["people"].as_u64(), res["created"].as_u64(), res["skippedSuspended"].as_u64(), res["outsideDomain"].as_u64()), (Some(4), Some(3), Some(1), Some(2)), "{res}");
    assert_eq!(res["teams"]["created"], 1, "{res}");
    assert_eq!(g.dir.lock().unwrap().subjects.last().cloned().flatten().as_deref(), Some("admin@example.com"), "it acts as the admin");
    let ada = user_of(&w, "101").unwrap();
    assert_eq!((ada.user.email.as_deref(), ada.user.name.as_str(), ada.user.role, ada.user.active()), (Some("ada@example.com"), "Ada Test", rbac::Role::Member, true));
    assert!(user_of(&w, "103").is_none() && user_of(&w, "104").is_none(), "suspended and out of scope people get nothing");
    let ids = w.app.db.identities(&ada.user.id);
    assert_eq!((ids.len(), ids[0].provider.as_str(), ids[0].subject.as_str()), (1, sso.as_str(), "101"), "they sign in with Google");
    assert_eq!(team_members(&w), vec!["ada@example.com", "eve@example.com"]);
    let created = w.app.db.audit_events(&crate::audit::Filter { actions: vec!["user.created".into()], target_id: Some(ada.user.id.clone()), ..Default::default() }, 5, false);
    assert_eq!(created[0].actor_id.as_deref(), Some(google::ACTOR_ID));
    let ev = events(w.port, &w.admin, "action=scim.google_sync").await;
    assert_eq!((ev[0]["outcome"].as_str(), ev[0]["details"]["created"].as_u64(), ev[0]["details"]["trigger"].as_str()), (Some("success"), Some(3), Some("admin")), "{}", ev[0]);

    let again = synced(&w).await;
    assert_eq!((again["created"].as_u64(), again["updated"].as_u64(), again["deleted"].as_u64(), again["teams"]["updated"].as_u64()), (Some(0), Some(0), Some(0), Some(0)), "{again}");

    g.user("101", |u| u["name"]["givenName"] = json!("Augusta"));
    g.user("102", |u| u["suspended"] = json!(true));
    let res = synced(&w).await;
    assert_eq!((res["updated"].as_u64(), res["disabled"].as_u64()), (Some(2), Some(1)), "{res}");
    assert_eq!(user_of(&w, "101").unwrap().given_name.as_deref(), Some("Augusta"));
    assert!(!active(&w, "102"), "suspended in Google: disabled here");

    g.user("102", |u| u["suspended"] = json!(false));
    assert_eq!(synced(&w).await["enabled"], 1);
    assert!(active(&w, "102"), "the sync disabled Bob, so it enables him again");

    let eve = uid(&w, "105");
    g.members("eng@example.com", vec![member("101"), member("102")]);
    let res = synced(&w).await;
    assert_eq!(res["deleted"], 1, "{res}");
    assert!(user_of(&w, "105").is_none(), "Eve left every group");
    assert!(!w.app.db.user(&eve).unwrap().active());
    assert_eq!(team_members(&w), vec!["ada@example.com", "bob@example.com"], "Bob joined the team");

    g.set(|d| d.groups.get_mut("eng@example.com").unwrap().1 = "Platform".into());
    synced(&w).await;
    assert_eq!(w.app.db.scim_group_find(TENANT, Some("g2"), None).unwrap().display_name, "Platform", "a renamed group renames its team");

    g.members("eng@example.com", vec![member("101"), member("102"), member("105")]);
    let res = synced(&w).await;
    assert_eq!(res["created"], 1, "{res}");
    assert_eq!(uid(&w, "105"), eve, "Eve comes back as the same user");
}

#[tokio::test]
async fn a_leaver_whose_pin_cant_be_kept_leaves_on_a_later_pass() {
    let g = google_stand_in().await;
    let w = world(&g, false, |_| {}).await;
    synced(&w).await;
    let eve = uid(&w, "105");
    let team = w.app.db.scim_group_find(TENANT, Some("g2"), None).unwrap().team_id;
    w.app.db.pin_residency(db::PinOn::Team, &team, "gb-lon", "MSA-7", None).unwrap();

    w.app.db.fail_pin_saves(true);
    g.members("eng@example.com", vec![member("101")]);
    let (code, res) = sync(&w, "").await;
    assert_eq!(code, 200, "{res}");
    assert!(res["failed"].as_u64() >= Some(1), "{res}");
    assert!(user_of(&w, "105").is_none() && !w.app.db.user(&eve).unwrap().active(), "Eve is deleted all the same");
    assert_eq!(w.app.db.team_id_of(&eve).as_deref(), Some(team.as_str()), "but stays on the team rather than leaving unpinned");

    w.app.db.fail_pin_saves(false);
    synced(&w).await;
    assert_eq!(w.app.db.team_id_of(&eve), None, "the next pass takes her off");
    assert!(w.app.db.residency_pin(db::PinOn::User, &eve).is_some_and(|p| p.kept_from.as_deref() == Some(team.as_str())), "keeping the team's pin");
    assert_eq!(team_members(&w), vec!["ada@example.com"]);
}

#[tokio::test]
async fn an_admins_disable_holds() {
    let g = google_stand_in().await;
    let w = world(&g, false, |_| {}).await;
    synced(&w).await;
    let ada = uid(&w, "101");
    assert_eq!(call(w.port, "PATCH", &format!("/api/users/{ada}"), &w.admin, r#"{"status":"disabled"}"#).await.0, 200);
    let res = synced(&w).await;
    assert_eq!((res["held"].clone(), res["updated"].as_u64()), (json!([ada]), Some(0)), "{res}");
    assert!(!active(&w, "101"), "Google has Ada active, but an admin disabled her");

    g.members("staff@example.com", vec![member("102")]);
    g.members("eng@example.com", vec![member("105")]);
    synced(&w).await;
    g.members("staff@example.com", vec![member("101"), member("102")]);
    let res = synced(&w).await;
    assert_eq!(res["held"], json!([ada]), "{res}");
    assert!(!active(&w, "101"), "removed and added back, she still waits for an admin");
    let res = synced(&w).await;
    assert_eq!((res["held"].clone(), res["enabled"].as_u64()), (json!([ada]), Some(0)), "{res}");
    assert!(!active(&w, "101"), "taking her back was no enable: the pass after still holds");

    assert_eq!(call(w.port, "PATCH", &format!("/api/users/{ada}"), &w.admin, r#"{"status":"active"}"#).await.0, 200);
    g.user("101", |u| u["suspended"] = json!(true));
    synced(&w).await;
    g.user("101", |u| u["suspended"] = json!(false));
    synced(&w).await;
    assert!(active(&w, "101"), "once enabled, she follows Google again");
}

#[tokio::test]
async fn taking_on_a_disabled_google_user_keeps_them_disabled() {
    let g = google_stand_in().await;
    let w = world(&g, true, |_| {}).await;
    let sso = w.sso.clone().unwrap();
    let (_, made) = call(w.port, "POST", "/api/users", &w.admin, r#"{"email":"fay@example.com","name":"Fay"}"#).await;
    let fay = parse(&made)["id"].as_str().unwrap().to_string();
    assert_eq!(call(w.port, "POST", &format!("/api/users/{fay}/identities"), &w.admin, &json!({ "provider": sso, "subject": "106" }).to_string()).await.0, 201);
    assert_eq!(call(w.port, "PATCH", &format!("/api/users/{fay}"), &w.admin, r#"{"status":"disabled"}"#).await.0, 200);
    g.set(|d| d.users.push(person("106", "fay@example.com", "Fay", false)));
    g.members("staff@example.com", vec![member("101"), member("102"), member("106")]);
    let res = synced(&w).await;
    assert_eq!(res["held"], json!([fay]), "{res}");
    assert_eq!(uid(&w, "106"), fay, "SCIM takes on the user her identity is linked to");
    assert!(!active(&w, "106"), "an admin disabled her before the sync took her on");
    synced(&w).await;
    assert!(!active(&w, "106"), "and the pass after that too");
}

#[tokio::test]
async fn people_already_here_get_their_google_identity() {
    let g = google_stand_in().await;
    let w = world(&g, true, |_| {}).await;
    synced(&w).await;
    let ada = uid(&w, "101");
    let i = w.app.db.identities(&ada).remove(0);
    w.app.db.unlink_identity(&ada, &i.id).unwrap();
    let res = synced(&w).await;
    assert_eq!(res["linked"], 1, "{res}");
    let ids = w.app.db.identities(&ada);
    assert_eq!((ids.len(), ids[0].subject.as_str()), (1, "101"), "she signs in with Google again");
    let ev = w.app.db.audit_events(&crate::audit::Filter { actions: vec!["user.identity_linked".into()], target_id: Some(ada.clone()), ..Default::default() }, 1, false);
    assert_eq!(ev[0].actor_id.as_deref(), Some(google::ACTOR_ID));
    assert_eq!(synced(&w).await["linked"], 0);
}

#[tokio::test]
async fn the_last_active_person_stays_without_force() {
    let g = google_stand_in().await;
    let w = world(&g, false, |s| s.teams = vec![]).await;
    synced(&w).await;
    let bob = uid(&w, "102");
    assert_eq!(call(w.port, "PATCH", &format!("/api/users/{bob}"), &w.admin, r#"{"status":"disabled"}"#).await.0, 200);
    g.members("staff@example.com", vec![member("102")]);
    let (code, res) = sync(&w, "").await;
    assert_eq!(code, 409, "{res}");
    assert!(res["error"].as_str().unwrap().contains("remove all 1"), "Google has Bob active, but he stays disabled here: {res}");
    assert!(active(&w, "101"));

    g.set(|d| d.users.push(person("106", "fay@example.com", "Fay", false)));
    g.members("staff@example.com", vec![member("102"), member("106")]);
    assert_eq!(call(w.port, "POST", "/api/users", &w.admin, r#"{"email":"fay@example.com"}"#).await.0, 201);
    let (code, res) = sync(&w, "").await;
    assert_eq!((code, res["created"].as_u64(), res["deleted"].as_u64(), res["failed"].as_u64()), (200, Some(0), Some(0), Some(2)), "{res}");
    assert!(active(&w, "101"), "Fay's account failed, so Ada isn't removed");
}

#[tokio::test]
async fn team_groups_move_and_aliases_are_one_team() {
    let g = google_stand_in().await;
    let w = world(&g, false, |s| s.teams.push("platform@example.com".into())).await;
    g.set(|d| {
        let eng = d.groups["eng@example.com"].clone();
        d.groups.insert("platform@example.com".into(), eng);
    });
    let res = synced(&w).await;
    assert_eq!(res["teams"]["created"], 1, "{res}");
    assert_eq!(team_members(&w), vec!["ada@example.com", "eve@example.com"]);
    let again = synced(&w).await;
    assert_eq!(again["teams"]["updated"], 0, "the alias never empties the team: {again}");
    assert_eq!(team_members(&w), vec!["ada@example.com", "eve@example.com"]);

    let old = w.app.db.scim_group_find(TENANT, Some("g2"), None).unwrap();
    w.app.db.save_scim_group(TENANT, &old.team_id, Some("g-old"), "Old", "Old", false).unwrap();
    let res = synced(&w).await;
    assert_eq!((res["teams"]["created"].as_u64(), res["teams"]["deleted"].as_u64()), (Some(1), Some(1)), "{res}");
    assert_eq!(team_members(&w), vec!["ada@example.com", "eve@example.com"], "people on a team no longer wanted join the new one in the same pass");
}

/// The emails on the team whose externalId is `ext`.
fn team_of(w: &World, ext: &str) -> Vec<String> {
    let Some(g) = w.app.db.scim_group_find(TENANT, Some(ext), None) else { return vec![] };
    let mut m: Vec<String> = w.app.db.scim_group_members(TENANT, &g.team_id, false).into_iter().map(|u| u.email.unwrap_or_default()).collect();
    m.sort();
    m
}

#[tokio::test]
async fn organizational_units_give_accounts_and_teams() {
    let g = google_stand_in().await;
    g.set(|d| {
        d.org_units = vec![
            ("id:03eng".into(), "/Engineering".into(), "Engineering".into()),
            ("id:03plat".into(), "/Engineering/Platform".into(), "Platform".into()),
            ("id:03sales".into(), "/Sales".into(), "Sales".into()),
        ];
    });
    for (id, unit) in [("101", "/Engineering/Platform"), ("102", "/Engineering"), ("103", "/Engineering"), ("104", "/Sales"), ("105", "/Marketing")] {
        g.user(id, |u| u["orgUnitPath"] = json!(unit));
    }
    let w = world(&g, false, |s| {
        s.groups = vec![];
        s.teams = vec![];
        s.org_units = vec!["/Sales".into()];
        s.team_org_units = vec!["/Engineering".into(), "id:03plat".into()];
    })
    .await;

    let res = synced(&w).await;
    assert_eq!((res["created"].as_u64(), res["skippedSuspended"].as_u64(), res["teams"]["created"].as_u64()), (Some(3), Some(1), Some(2)), "{res}");
    assert!(user_of(&w, "105").is_none(), "Eve's unit isn't named");
    assert_eq!(g.dir.lock().unwrap().scopes.last().unwrap(), &format!("{} {}", google::SCOPES, google::ORG_UNIT_SCOPE));
    assert_eq!(team_of(&w, "id:03plat"), vec!["ada@example.com"], "Ada is on the team of her deepest unit");
    assert_eq!(team_of(&w, "id:03eng"), vec!["bob@example.com"]);
    assert_eq!(w.app.db.scim_group_find(TENANT, Some("id:03plat"), None).unwrap().display_name, "Engineering/Platform");
    assert_eq!(
        res["orgUnits"],
        json!([
            { "orgUnit": "/Sales", "path": "/Sales", "people": 1, "team": false },
            { "orgUnit": "/Engineering", "path": "/Engineering", "people": 3, "team": true },
            { "orgUnit": "id:03plat", "path": "/Engineering/Platform", "people": 1, "team": true },
        ])
    );
    let again = synced(&w).await;
    assert_eq!((again["created"].as_u64(), again["updated"].as_u64(), again["teams"]["updated"].as_u64()), (Some(0), Some(0), Some(0)), "{again}");

    // Moves in Google: Ada up to Engineering, Eve into Platform, Bob out of every unit.
    g.user("101", |u| u["orgUnitPath"] = json!("/Engineering"));
    g.user("105", |u| u["orgUnitPath"] = json!("/Engineering/Platform"));
    g.user("102", |u| u["orgUnitPath"] = json!("/Marketing"));
    let res = synced(&w).await;
    assert_eq!((res["created"].as_u64(), res["deleted"].as_u64()), (Some(1), Some(1)), "{res}");
    assert!(user_of(&w, "102").is_none(), "Bob left every unit");
    assert_eq!((team_of(&w, "id:03eng"), team_of(&w, "id:03plat")), (vec!["ada@example.com".to_string()], vec!["eve@example.com".to_string()]));

    // Named by id, a renamed unit renames its team and keeps its people.
    let team = w.app.db.scim_group_find(TENANT, Some("id:03plat"), None).unwrap().team_id;
    g.set(|d| d.org_units[1].1 = "/Engineering/Core".into());
    g.user("105", |u| u["orgUnitPath"] = json!("/Engineering/Core"));
    synced(&w).await;
    let renamed = w.app.db.scim_group_find(TENANT, Some("id:03plat"), None).unwrap();
    assert_eq!((renamed.team_id, renamed.display_name.as_str()), (team, "Engineering/Core"));
    assert_eq!(team_of(&w, "id:03plat"), vec!["eve@example.com"]);

    let (_, status) = call(w.port, "GET", "/api/scim/google", &w.admin, "").await;
    let status = parse(&status);
    assert_eq!((status["orgUnits"].clone(), status["teamOrgUnits"].clone()), (json!(["/Sales"]), json!(["/Engineering", "id:03plat"])));

    // A unit Google no longer has changes nobody, rather than removing its people.
    g.set(|d| _ = d.org_units.remove(2));
    let (code, res) = sync(&w, "").await;
    assert_eq!(code, 502, "{res}");
    assert!(active(&w, "104"), "Dee stays");
    let ev = events(w.port, &w.admin, "action=scim.google_sync").await;
    assert_eq!((ev[0]["outcome"].as_str(), ev[0]["details"]["reason"].as_str()), (Some("failure"), Some("org_unit_not_found")), "{}", ev[0]);
}

#[tokio::test]
async fn a_user_without_a_unit_fails_the_pass_and_groups_come_before_units() {
    let g = google_stand_in().await;
    g.set(|d| d.org_units = vec![("id:03eng".into(), "/R&D".into(), "R&D".into())]);
    for id in ["101", "102", "105"] {
        g.user(id, |u| u["orgUnitPath"] = json!("/R&D"));
    }
    let w = world(&g, false, |s| s.team_org_units = vec!["/R&D".into()]).await;
    synced(&w).await;
    assert_eq!(team_members(&w), vec!["ada@example.com", "eve@example.com"], "the team group eng@ comes first");
    assert_eq!(team_of(&w, "id:03eng"), vec!["bob@example.com"]);

    g.user("102", |u| _ = u.as_object_mut().unwrap().remove("orgUnitPath"));
    let (code, res) = sync(&w, "").await;
    assert_eq!(code, 502, "{res}");
    assert_eq!(team_of(&w, "id:03eng"), vec!["bob@example.com"], "nobody was changed");
    let ev = events(w.port, &w.admin, "action=scim.google_sync").await;
    assert_eq!(ev[0]["details"]["reason"], "odd_answer", "{}", ev[0]);
}

#[tokio::test]
async fn declared_role_groups_give_roles_and_undeclared_ones_are_never_pushed() {
    let g = google_stand_in().await;
    g.set(|d| {
        d.groups.insert("auditors@example.com".into(), ("g3".into(), "Auditors".into(), vec![member("101"), member("104")]));
        d.groups.insert("billing@example.com".into(), ("g4".into(), "Billing".into(), vec![member("102")]));
    });
    let w = world(&g, false, |s| s.role_groups = vec!["auditors@example.com".into(), "billing@example.com".into()]).await;
    let (code, v) = call(w.port, "POST", "/api/roles", &w.admin, r#"{"name":"Auditor","base":"member","permissions":["audit.view"]}"#).await;
    assert_eq!(code, 201, "{v}");
    let auditor = parse(&v)["id"].as_str().unwrap().to_string();
    let (code, v) = call(w.port, "POST", "/api/scim/role-groups", &w.admin, &json!({ "tenant": TENANT, "displayName": "Auditors@example.com", "role": "Auditor" }).to_string()).await;
    assert_eq!(code, 201, "{v}");
    let gid = parse(&v)["id"].as_str().unwrap().to_string();

    let res = synced(&w).await;
    assert_eq!((res["created"].as_u64(), res["teams"]["created"].as_u64()), (Some(3), Some(1)), "{res}");
    assert_eq!(res["roleGroups"], json!({ "created": 1, "updated": 0, "deleted": 0, "undeclared": ["billing@example.com"] }), "{res}");
    assert!(user_of(&w, "104").is_none(), "a role group gives no account");
    let ada = uid(&w, "101");
    assert_eq!(w.app.db.user(&ada).unwrap().role_id.as_deref(), Some(auditor.as_str()));
    assert_eq!(team_members(&w), vec!["ada@example.com", "eve@example.com"], "and Ada is still on her team");
    let rg = w.app.db.scim_role_group(&gid).unwrap();
    assert_eq!((rg.external_id.as_deref(), rg.provisioned_at.is_some()), (Some("g3"), true));
    assert!(w.app.db.scim_group_find(TENANT, Some("g4"), None).is_none(), "Billing never became a team");
    let (_, status) = call(w.port, "GET", "/api/scim/google", &w.admin, "").await;
    assert_eq!(parse(&status)["roleGroups"], json!(["auditors@example.com", "billing@example.com"]));

    let again = synced(&w).await;
    assert_eq!((again["roleGroups"]["created"].as_u64(), again["roleGroups"]["updated"].as_u64()), (Some(0), Some(0)), "{again}");

    g.members("auditors@example.com", vec![member("102")]);
    let res = synced(&w).await;
    assert_eq!(res["roleGroups"]["updated"], 1, "{res}");
    let bob = uid(&w, "102");
    assert_eq!((w.app.db.user(&ada).unwrap().role_id, w.app.db.user(&bob).unwrap().role_id), (None, Some(auditor.clone())));

    // A pushed role group the directory no longer has is deleted, and its declaration waits.
    w.app.db.save_scim_role_group(&gid, Some("g-old"), "auditors@example.com", false).unwrap();
    let res = synced(&w).await;
    assert_eq!((res["roleGroups"]["deleted"].as_u64(), res["roleGroups"]["created"].as_u64()), (Some(1), Some(1)), "{res}");
    assert_eq!(w.app.db.scim_role_group(&gid).unwrap().external_id.as_deref(), Some("g3"));
    assert_eq!(w.app.db.user(&bob).unwrap().role_id.as_deref(), Some(auditor.as_str()));
}

#[tokio::test]
async fn a_pass_that_cant_read_everything_changes_nobody() {
    let g = google_stand_in().await;
    let w = world(&g, false, |_| {}).await;
    synced(&w).await;
    let before = |w: &World| ["101", "102", "105"].map(|id| user_of(w, id).map(|u| u.user.active()));
    let all = before(&w);
    for (break_it, reason) in [
        (Box::new(|d: &mut Dir| d.down = true) as Box<dyn Fn(&mut Dir)>, "google_error"),
        (Box::new(|d: &mut Dir| _ = d.groups.remove("eng@example.com")), "group_not_found"),
        (Box::new(|d: &mut Dir| d.odd = true), "odd_answer"),
        (Box::new(|d: &mut Dir| d.refuse = true), "sign_in"),
    ] {
        let saved = std::mem::take(&mut *g.dir.lock().unwrap());
        g.set(|d| {
            *d = Dir { users: saved.users.clone(), groups: saved.groups.clone(), public_key: saved.public_key.clone(), ..Dir::default() };
            break_it(d);
        });
        let (code, res) = sync(&w, "").await;
        assert_eq!(code, 502, "{reason}: {res}");
        assert_eq!(before(&w), all, "{reason}: nobody changed");
        let ev = events(w.port, &w.admin, "action=scim.google_sync").await;
        assert_eq!((ev[0]["outcome"].as_str(), ev[0]["details"]["reason"].as_str()), (Some("failure"), Some(reason)), "{}", ev[0]);
        let (_, status) = call(w.port, "GET", "/api/scim/google", &w.admin, "").await;
        assert_eq!(parse(&status)["last"]["reason"], reason);
        g.set(|d| *d = Dir { users: saved.users, groups: saved.groups, public_key: saved.public_key, ..Dir::default() });
    }
    let (_, status) = call(w.port, "GET", "/api/scim/google", &w.admin, "").await;
    assert_eq!(parse(&status)["lastSuccess"]["created"], 3, "the last good pass is kept");
}

#[tokio::test]
async fn the_health_check_counts_the_sync_as_provisioning() {
    let g = google_stand_in().await;
    let w = world(&g, false, |_| {}).await;
    let scim = || async {
        let (code, res) = call(w.port, "GET", "/api/support/health-check", &w.admin, "").await;
        assert_eq!(code, 200, "{res}");
        let r = parse(&res);
        let it = r["items"].as_array().unwrap().iter().find(|i| i["id"] == "scim").unwrap().clone();
        (it["status"].as_str().unwrap().to_string(), it["detail"].as_str().unwrap().to_string())
    };
    let (status, detail) = scim().await;
    assert_eq!((status.as_str(), detail.as_str()), ("open", "The Google Workspace sync has no successful pass in the last 30 days: botctl scim google."));

    synced(&w).await;
    let (status, detail) = scim().await;
    assert_eq!(status, "confirm", "no SCIM token is needed: {detail}");
    assert!(detail.starts_with("The Google Workspace sync passing in the last 30 days"), "{detail}");

    g.set(|d| d.down = true);
    assert_eq!(sync(&w, "").await.0, 502);
    let (status, detail) = scim().await;
    assert_eq!((status.as_str(), detail.as_str()), ("open", "The Google Workspace sync's latest pass didn't succeed (google_error): botctl scim google."));
}

#[tokio::test]
async fn mass_removals_wait_for_force() {
    let g = google_stand_in().await;
    let w = world(&g, false, |s| s.max_removals = 1).await;
    synced(&w).await;
    g.members("staff@example.com", vec![member("101")]);
    g.members("eng@example.com", vec![member("101")]);
    let (code, res) = sync(&w, "").await;
    assert_eq!(code, 409, "{res}");
    assert!(res["error"].as_str().unwrap().contains("GOOGLE_DIRECTORY_MAX_REMOVALS"), "{res}");
    assert!(user_of(&w, "102").is_some() && user_of(&w, "105").is_some(), "nobody was removed");
    let ev = events(w.port, &w.admin, "action=scim.google_sync").await;
    assert_eq!((ev[0]["outcome"].as_str(), ev[0]["details"]["reason"].as_str()), (Some("denied"), Some("too_many_removals")));

    assert_eq!(sync(&w, r#"{"force":"yes"}"#).await.0, 400);
    let (code, res) = sync(&w, r#"{"force":true}"#).await;
    assert_eq!((code, res["deleted"].as_u64()), (200, Some(2)), "{res}");
    let asked = events(w.port, &w.admin, "action=scim.google_sync_requested").await;
    assert_eq!(asked[0]["details"]["force"], true);

    g.members("staff@example.com", vec![]);
    g.members("eng@example.com", vec![]);
    let (code, res) = sync(&w, "").await;
    assert_eq!(code, 409, "{res}");
    assert!(res["error"].as_str().unwrap().contains("remove all 1"), "an empty answer never empties the tenant: {res}");
    assert!(user_of(&w, "101").is_some());
}

#[tokio::test]
async fn the_tenant_is_the_syncs_alone_and_admins_run_it() {
    let g = google_stand_in().await;
    let w = world(&g, false, |_| {}).await;
    let (code, res) = call(w.port, "POST", "/api/scim/tokens", &w.admin, &json!({ "tenant": TENANT }).to_string()).await;
    assert_eq!(code, 409, "{res}");
    token(w.port, &w.admin, json!({ "tenant": "okta" })).await;
    synced(&w).await;
    let ada = uid(&w, "101");
    let member_session = session_for(w.port, &w.admin, &ada).await;
    assert_eq!(call(w.port, "GET", "/api/scim/google", &member_session, "").await.0, 403);
    assert_eq!(call(w.port, "POST", "/api/scim/google/sync", &member_session, "").await.0, 403);
    let (code, status) = call(w.port, "GET", "/api/scim/google", &w.admin, "").await;
    let s = parse(&status);
    assert_eq!((code, s["enabled"].as_bool(), s["tenant"].as_str(), s["running"].as_bool()), (200, Some(true), Some(TENANT), Some(false)), "{s}");
    assert!(!status.contains("private_key"), "the key is never shown");

    let (port, app, admin, _) = serve_app_with(|a| a.scim.enabled = true).await;
    let (code, off) = call(port, "GET", "/api/scim/google", &admin, "").await;
    assert_eq!((code, parse(&off)["enabled"].as_bool()), (200, Some(false)));
    assert_eq!(call(port, "POST", "/api/scim/google/sync", &admin, "{}").await.0, 409, "off: nothing to run");
    token(port, &admin, json!({ "tenant": TENANT })).await;
    let key = g.key.clone();
    let e = Directory::with_key(&app, settings(&g), Box::new(move || Ok(Some(Zeroizing::new(key.clone()))))).err().unwrap();
    assert!(e.contains("only writer"), "{e}");
    let e = Directory::with_key(&app, Settings { tenant: "fresh".into(), ..settings(&g) }, Box::new(|| Ok(None))).err().unwrap();
    assert!(e.contains(google::CREDENTIALS), "{e}");
}

#[tokio::test]
async fn departments_and_managers_follow_google() {
    let g = google_stand_in().await;
    g.user("102", |u| {
        u["organizations"] = json!([{ "primary": true, "name": "Example Ltd", "department": "Sales", "costCenter": "CC-1" }]);
        u["externalIds"] = json!([{ "type": "organization", "value": "E-102" }]);
        u["relations"] = json!([{ "type": "manager", "value": "ada@example.com" }]);
    });
    let w = world(&g, false, |_| {}).await;
    synced(&w).await;
    let bob = user_of(&w, "102").unwrap();
    let want = db::Enterprise { employee_number: Some("E-102".into()), organization: Some("Example Ltd".into()), department: Some("Sales".into()), cost_center: Some("CC-1".into()), ..Default::default() };
    assert_eq!(bob.enterprise, want, "Ada was made in the same pass, so her manager comes next time");
    let res = synced(&w).await;
    assert_eq!(res["updated"], 1, "{res}");
    let bob = user_of(&w, "102").unwrap();
    assert_eq!((bob.enterprise.manager.as_deref(), bob.manager_name.as_deref()), (Some(uid(&w, "101").as_str()), Some("Ada Test")));
    assert_eq!(synced(&w).await["updated"], 0, "nothing changed");

    g.user("102", |u| {
        u["organizations"] = json!([{ "primary": true, "name": "Example Ltd", "department": "Support" }]);
        u["relations"] = json!([]);
    });
    synced(&w).await;
    let bob = user_of(&w, "102").unwrap();
    assert_eq!((bob.enterprise.department.as_deref(), bob.enterprise.cost_center.clone(), bob.enterprise.manager.clone()), (Some("Support"), None, None));
    let upd = w.app.db.audit_events(&crate::audit::Filter { actions: vec!["user.updated".into()], target_id: Some(bob.user.id.clone()), ..Default::default() }, 1, false);
    assert_eq!(upd[0].details["changes"]["department"], json!({ "from": "Sales", "to": "Support" }), "{:?}", upd[0].details);
}

// Push (ADR 0216): Google's watch channels start a pass at once.

const ADDRESS: &str = "https://superbot.example.com/scim/google/push";

/// A notification as Google sends one, to botd's push address.
async fn notify(w: &World, id: &str, token: &str, change: &str, resource: &str) -> u16 {
    let extra = format!("X-Goog-Channel-ID: {id}\r\nX-Goog-Channel-Token: {token}\r\nX-Goog-Resource-State: {change}\r\nX-Goog-Resource-ID: {resource}\r\nX-Goog-Message-Number: 2\r\n");
    let body = json!({ "kind": "admin#directory#user", "id": "102", "etag": "e", "primaryEmail": "bob@example.com" }).to_string();
    call_with(w.port, "POST", google::push::PATH, "", &extra, &body).await.0
}

/// The channel ids, tokens and resource ids of the last round of watches.
fn channels(g: &Google) -> Vec<(String, String, String)> {
    let d = g.dir.lock().unwrap();
    d.watches[d.watches.len() - 4..].iter().map(|(q, b)| (b["id"].as_str().unwrap().into(), b["token"].as_str().unwrap().into(), format!("r-{}", q["event"]))).collect()
}

fn stopped(g: &Google) -> Vec<(String, String)> {
    g.dir.lock().unwrap().stops.iter().map(|s| (s["id"].as_str().unwrap().into(), s["resourceId"].as_str().unwrap().into())).collect()
}

async fn push_status(w: &World) -> Value {
    let (code, status) = call(w.port, "GET", "/api/scim/google", &w.admin, "").await;
    assert_eq!(code, 200, "{status}");
    parse(&status)["push"].clone()
}

async fn eventually(what: &str, f: impl Fn() -> bool) {
    for _ in 0..200 {
        if f() {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    panic!("{what}");
}

#[tokio::test]
async fn google_pushes_a_change_and_a_pass_runs_at_once() {
    let g = google_stand_in().await;
    let w = world(&g, false, |s| s.push = Some(ADDRESS.into())).await;
    synced(&w).await;

    let next = google::push::renew(&w.auth, &w.dir(), Users).await;
    assert!(next > std::time::Duration::from_secs(4 * 3600), "{next:?}");
    let watches = g.dir.lock().unwrap().watches.clone();
    assert_eq!(watches.iter().map(|(q, _)| q["event"].as_str()).collect::<Vec<_>>(), ["add", "update", "delete", "undelete"]);
    for (q, b) in &watches {
        assert_eq!((q["customer"].as_str(), b["type"].as_str(), b["address"].as_str(), b["params"]["ttl"].as_str()), ("my_customer", Some("web_hook"), Some(ADDRESS), Some("21600")), "{b}");
    }
    let first = channels(&g);
    let ev = events(w.port, &w.admin, "action=scim.google_push_watching").await;
    assert_eq!((ev.len(), ev[0]["details"]["recovered"].as_bool(), ev[0]["actorId"].as_str()), (1, Some(false), Some(google::ACTOR_ID)), "{ev:?}");
    let p = push_status(&w).await;
    assert_eq!((p["enabled"].as_bool(), p["watching"].as_bool(), p["address"].as_str(), p["channels"].as_array().map(Vec::len)), (Some(true), Some(true), Some(ADDRESS), Some(4)), "{p}");

    // New channels before the old ones end, which are then stopped; renewals aren't audited.
    google::push::renew(&w.auth, &w.dir(), Users).await;
    let mut gone = stopped(&g);
    gone.sort();
    let mut want: Vec<(String, String)> = first.iter().map(|(id, _, r)| (id.clone(), r.clone())).collect();
    want.sort();
    assert_eq!(gone, want);
    assert_eq!(events(w.port, &w.admin, "action=scim.google_push_watching").await.len(), 1);

    // Google's first message on a channel says it started: no pass.
    let (id, token, resource) = channels(&g)[1].clone();
    assert_eq!(notify(&w, &id, &token, "sync", &resource).await, 200);
    assert_eq!(push_status(&w).await["notifications"], 0);

    // Only channels botd made are taken.
    assert_eq!(notify(&w, &id, "forged", "update", &resource).await, 401);
    assert_eq!(notify(&w, &first[1].0, &token, "update", &resource).await, 401, "a token is its own channel's");
    assert_eq!(notify(&w, "someone-elses", &token, "update", &resource).await, 401);
    assert_eq!(notify(&w, "", "", "update", "").await, 401);
    let refused = events(w.port, &w.admin, "action=scim.google_push_refused").await;
    assert_eq!((refused.len(), refused[0]["details"]["reason"].as_str(), refused[0]["outcome"].as_str()), (1, Some("bad_token"), Some("failure")), "throttled per address: {refused:?}");
    let p = push_status(&w).await;
    assert_eq!((p["refused"].as_u64(), p["notifications"].as_u64()), (Some(4), Some(0)), "{p}");
    assert_eq!(events(w.port, &w.admin, "action=scim.google_sync").await.len(), 1, "no pass for any of them");

    // Bob is suspended in Google, which says so: a pass runs within seconds, not 30 minutes.
    w.dir().push.forget_last_pass();
    google::start(w.auth.clone());
    g.user("102", |u| u["suspended"] = json!(true));
    assert_eq!(notify(&w, &id, &token, "update", &resource).await, 200);
    eventually("Bob is disabled by a pushed pass", || !active(&w, "102")).await;
    let ev = events(w.port, &w.admin, "action=scim.google_sync").await;
    assert_eq!((ev[0]["details"]["trigger"].as_str(), ev[0]["details"]["pushed"].clone(), ev[0]["details"]["disabled"].as_u64()), (Some("push"), json!(["update"]), Some(1)), "{}", ev[0]);
    let p = push_status(&w).await;
    assert_eq!(p["notifications"], 1, "{p}");
    assert!(p["lastNotificationAt"].is_i64(), "{p}");
}

#[tokio::test]
async fn channels_left_from_before_are_stopped_and_push_off_starts_no_pass() {
    let g = google_stand_in().await;
    let w = world(&g, false, |s| s.push = Some(ADDRESS.into())).await;
    google::push::renew(&w.auth, &w.dir(), Users).await;
    // A channel botd made before a restart: its token still checks out.
    let old = format!("superbot-{}", "0a".repeat(16));
    let token = google::push::channel_token(&old);
    assert_eq!(notify(&w, &old, &token, "update", "r-old").await, 200);
    eventually("the leftover channel is stopped", || stopped(&g).contains(&(old.clone(), "r-old".into()))).await;
    let p = push_status(&w).await;
    assert_eq!((p["leftoversStopped"].as_u64(), p["notifications"].as_u64()), (Some(1), Some(1)), "a leftover's change still counts: {p}");
    assert_eq!(w.dir().push.begin(), vec!["update"]);
    for (id, _, _) in channels(&g) {
        assert!(!stopped(&g).iter().any(|(s, _)| *s == id), "today's channels are kept");
    }

    // Push turned off: channels from when it was on are stopped, and start no pass.
    let g2 = google_stand_in().await;
    let off = world(&g2, false, |_| {}).await;
    assert_eq!(push_status(&off).await, json!({ "enabled": false }));
    assert_eq!(notify(&off, &old, &token, "update", "r-old").await, 200);
    eventually("the channel is stopped", || stopped(&g2).len() == 1).await;
    assert!(off.dir().push.begin().is_empty());
    assert_eq!(google::push::renew(&off.auth, &off.dir(), Users).await, std::time::Duration::from_secs(6 * 3600), "nothing to renew");
    assert!(g2.dir.lock().unwrap().watches.is_empty());

    // The sync off: nothing there.
    let (port, ..) = serve_app_with(|a| a.scim.enabled = true).await;
    let extra = format!("X-Goog-Channel-ID: {old}\r\nX-Goog-Channel-Token: {token}\r\nX-Goog-Resource-State: update\r\n");
    assert_eq!(call_with(port, "POST", google::push::PATH, "", &extra, "{}").await.0, 404);
}

#[tokio::test]
async fn a_watch_that_fails_keeps_the_old_channels_and_is_audited_once() {
    let g = google_stand_in().await;
    let w = world(&g, false, |s| s.push = Some(ADDRESS.into())).await;
    google::push::renew(&w.auth, &w.dir(), Users).await;
    let old = channels(&g);

    // Two new channels, then Google refuses: the two are stopped, the old four kept.
    g.set(|d| d.watch_limit = Some(6));
    assert_eq!(google::push::renew(&w.auth, &w.dir(), Users).await, std::time::Duration::from_secs(300));
    let made: Vec<String> = g.dir.lock().unwrap().watches[4..].iter().map(|(_, b)| b["id"].as_str().unwrap().to_string()).collect();
    assert_eq!(stopped(&g).into_iter().map(|(id, _)| id).collect::<Vec<_>>(), made);
    let p = push_status(&w).await;
    assert_eq!((p["watching"].as_bool(), p["failure"]["reason"].as_str()), (Some(true), Some("forbidden")), "{p}");
    let (id, token, resource) = old[1].clone();
    assert_eq!(notify(&w, &id, &token, "update", &resource).await, 200, "the old channels still deliver");
    assert_eq!(push_status(&w).await["notifications"], 1);
    google::push::renew(&w.auth, &w.dir(), Users).await;
    let failed = events(w.port, &w.admin, "action=scim.google_push_failed").await;
    assert_eq!((failed.len(), failed[0]["outcome"].as_str(), failed[0]["details"]["channelsLeft"].as_u64()), (1, Some("failure"), Some(4)), "once per failure: {failed:?}");

    // Google lets it again: new channels, the old ones stopped, and it says so.
    g.set(|d| d.watch_limit = None);
    google::push::renew(&w.auth, &w.dir(), Users).await;
    let gone = stopped(&g);
    assert!(old.iter().all(|(id, _, _)| gone.iter().any(|(s, _)| s == id)), "{gone:?}");
    let ev = events(w.port, &w.admin, "action=scim.google_push_watching").await;
    assert_eq!((ev.len(), ev[0]["details"]["recovered"].as_bool()), (2, Some(true)), "{ev:?}");
    assert!(push_status(&w).await["failure"].is_null());
}

// Group push (ADR 0244): the Reports API's admin activity for group members.

/// A Reports API notification: the activity is in the body, which botd doesn't read.
async fn notify_group(w: &World, id: &str, token: &str, event: &str, resource: &str) -> u16 {
    let extra = format!("X-Goog-Channel-ID: {id}\r\nX-Goog-Channel-Token: {token}\r\nX-Goog-Resource-State: {event}\r\nX-Goog-Resource-ID: {resource}\r\nX-Goog-Message-Number: 7\r\n");
    let params = json!([{ "name": "GROUP_EMAIL", "value": "staff@example.com" }, { "name": "USER_EMAIL", "value": "bob@example.com" }]);
    let body = json!({ "kind": "admin#reports#activity", "id": { "applicationName": "admin" }, "events": [{ "type": "GROUP_SETTINGS", "name": event, "parameters": params }] }).to_string();
    call_with(w.port, "POST", google::push::PATH, "", &extra, &body).await.0
}

fn group_channels(g: &Google) -> Vec<(String, String, String)> {
    let d = g.dir.lock().unwrap();
    d.report_watches[d.report_watches.len() - 3..].iter().map(|(q, b)| (b["id"].as_str().unwrap().into(), b["token"].as_str().unwrap().into(), format!("a-{}", q["eventName"]))).collect()
}

fn report_stopped(g: &Google) -> Vec<String> {
    g.dir.lock().unwrap().report_stops.iter().map(|s| s["id"].as_str().unwrap().to_string()).collect()
}

#[tokio::test]
async fn google_pushes_a_group_removal_and_the_leaver_goes_at_once() {
    let g = google_stand_in().await;
    let w = world(&g, false, |s| {
        s.push = Some(ADDRESS.into());
        s.push_groups = true;
    })
    .await;
    synced(&w).await;
    assert!(user_of(&w, "102").is_some());

    google::push::renew(&w.auth, &w.dir(), Users).await;
    let next = google::push::renew(&w.auth, &w.dir(), Groups).await;
    assert!(next > std::time::Duration::from_secs(4 * 3600), "{next:?}");
    let watches = g.dir.lock().unwrap().report_watches.clone();
    assert_eq!(watches.iter().map(|(q, _)| q["eventName"].as_str()).collect::<Vec<_>>(), google::push::GROUP_EVENTS);
    for (q, b) in &watches {
        assert!(!q.contains_key("customerId"), "my_customer is the Reports API's default: {q:?}");
        assert_eq!((b["type"].as_str(), b["address"].as_str(), b["params"]["ttl"].as_str()), (Some("web_hook"), Some(ADDRESS), Some("21600")), "{b}");
        assert!(b["id"].as_str().unwrap().starts_with("superbot-g-"), "{b}");
    }
    // Only the group channels' token carries the audit scope; no pass's does.
    let scopes = g.dir.lock().unwrap().scopes.clone();
    assert_eq!(scopes.iter().filter(|s| s.contains("audit")).collect::<Vec<_>>(), [google::push::REPORTS_SCOPE]);
    let ev = events(w.port, &w.admin, "action=scim.google_push_watching").await;
    let by = |watch: &str| ev.iter().find(|e| e["details"]["watch"] == watch).map(|e| e["details"]["events"].clone());
    assert_eq!((ev.len(), by("users"), by("groups")), (2, Some(json!(google::push::EVENTS)), Some(json!(google::push::GROUP_EVENTS))), "{ev:?}");
    let p = push_status(&w).await;
    assert_eq!((p["watching"].as_bool(), p["groups"]["watching"].as_bool(), p["channels"].as_array().map(Vec::len)), (Some(true), Some(true), Some(7)), "{p}");

    // Renewing one set leaves the other's channels alone.
    let users_before = channels(&g);
    google::push::renew(&w.auth, &w.dir(), Groups).await;
    assert_eq!(report_stopped(&g), watches.iter().map(|(_, b)| b["id"].as_str().unwrap().to_string()).collect::<Vec<_>>());
    assert!(stopped(&g).is_empty(), "no user channel was stopped");
    assert_eq!(channels(&g), users_before);
    assert_eq!(events(w.port, &w.admin, "action=scim.google_push_watching").await.len(), 2, "renewals aren't audited");

    // A forged group notification starts nothing.
    let (id, token, resource) = group_channels(&g)[1].clone();
    assert_eq!(notify_group(&w, &id, "forged", "REMOVE_GROUP_MEMBER", &resource).await, 401);
    assert_eq!(notify_group(&w, &id, &channels(&g)[0].1, "REMOVE_GROUP_MEMBER", &resource).await, 401, "a user channel's token isn't this one's");

    // Bob is taken out of staff@, and stays active in Google: Google's admin log says so,
    // and a pass deletes him within seconds instead of at the next schedule.
    w.dir().push.forget_last_pass();
    google::start(w.auth.clone());
    g.set(|d| d.groups.get_mut("staff@example.com").unwrap().2.retain(|m| m["id"] != "102"));
    // A generic resource state still names the event the channel was made for.
    assert_eq!(notify_group(&w, &id, &token, "exists", &resource).await, 200);
    eventually("Bob is deleted by a pushed pass", || user_of(&w, "102").is_none()).await;
    let ev = events(w.port, &w.admin, "action=scim.google_sync").await;
    assert_eq!((ev[0]["details"]["trigger"].as_str(), ev[0]["details"]["pushed"].clone(), ev[0]["details"]["deleted"].as_u64()), (Some("push"), json!(["REMOVE_GROUP_MEMBER"]), Some(1)), "{}", ev[0]);
    assert_eq!(push_status(&w).await["notifications"], 1);
}

#[tokio::test]
async fn group_push_fails_on_its_own_and_its_leftovers_are_stopped_where_they_live() {
    let g = google_stand_in().await;
    g.set(|d| d.no_audit_scope = true);
    let w = world(&g, false, |s| {
        s.push = Some(ADDRESS.into());
        s.push_groups = true;
        s.customer = "C01abc23".into();
    })
    .await;

    // The audit scope isn't delegated: user push and the passes don't care.
    google::push::renew(&w.auth, &w.dir(), Users).await;
    assert_eq!(google::push::renew(&w.auth, &w.dir(), Groups).await, std::time::Duration::from_secs(300));
    google::push::renew(&w.auth, &w.dir(), Groups).await;
    let p = push_status(&w).await;
    assert_eq!((p["watching"].as_bool(), p["failure"].clone(), p["groups"]["watching"].as_bool()), (Some(true), Value::Null, Some(false)), "{p}");
    assert_eq!(p["groups"]["failure"]["reason"], "sign_in", "{p}");
    assert!(p["groups"]["failure"]["detail"].as_str().unwrap().contains("admin.reports.audit.readonly"), "{p}");
    let failed = events(w.port, &w.admin, "action=scim.google_push_failed").await;
    assert_eq!((failed.len(), failed[0]["details"]["watch"].as_str(), failed[0]["details"]["channelsLeft"].as_u64()), (1, Some("groups"), Some(0)), "once: {failed:?}");
    assert!(g.dir.lock().unwrap().report_watches.is_empty());

    // Delegated: the group channels come, for the customer named, and say they recovered.
    g.set(|d| d.no_audit_scope = false);
    google::push::renew(&w.auth, &w.dir(), Groups).await;
    let watches = g.dir.lock().unwrap().report_watches.clone();
    assert!(watches.iter().all(|(q, _)| q["customerId"] == "C01abc23"), "{watches:?}");
    let ev = events(w.port, &w.admin, "action=scim.google_push_watching").await;
    let groups = ev.iter().find(|e| e["details"]["watch"] == "groups").unwrap();
    assert_eq!(groups["details"]["recovered"], true, "{groups}");
    assert!(push_status(&w).await["groups"]["failure"].is_null());

    // A group channel from before a restart is stopped on the Reports API, and still nudges.
    let old = format!("superbot-g-{}", "0b".repeat(16));
    let token = google::push::channel_token(&old);
    assert_eq!(notify_group(&w, &old, &token, "ADD_GROUP_MEMBER", "a-old").await, 200);
    eventually("the leftover group channel is stopped", || report_stopped(&g).contains(&old)).await;
    assert!(stopped(&g).is_empty(), "not on the Directory API");
    assert_eq!(w.dir().push.begin(), vec!["ADD_GROUP_MEMBER"]);

    // Group push off, user push on: group channels from before are stopped, none made.
    let g2 = google_stand_in().await;
    let users_only = world(&g2, false, |s| s.push = Some(ADDRESS.into())).await;
    assert_eq!(push_status(&users_only).await["groups"], json!({ "enabled": false }));
    assert_eq!(google::push::renew(&users_only.auth, &users_only.dir(), Groups).await, std::time::Duration::from_secs(6 * 3600), "nothing to renew");
    assert_eq!(notify_group(&users_only, &old, &token, "REMOVE_GROUP_MEMBER", "a-old").await, 200);
    eventually("the group channel is stopped", || report_stopped(&g2) == [old.clone()]).await;
    assert!(g2.dir.lock().unwrap().report_watches.is_empty());
}
