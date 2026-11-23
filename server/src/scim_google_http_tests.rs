//! The Google Workspace sync (ADR 0162) end to end: a stand-in for Google's token
//! endpoint and Directory API, the real router, and each pass through SCIM's handlers.
//! People get accounts, follow Google, keep an admin's disable, and leave; team groups
//! become teams; a pass that can't read everything, or would remove too many people,
//! changes nobody.

use crate::db::ScimKey;
use crate::scim::google::{self, Directory, Settings};
use crate::scim_http_tests::{events, session_for, token};
use crate::tests::{call, serve_app_with};
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
    json!({ "id": id, "primaryEmail": email, "name": { "givenName": given, "familyName": "Test", "fullName": format!("{given} Test") }, "suspended": suspended, "archived": false })
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
    assert_eq!((claims["iss"].as_str(), claims["scope"].as_str()), (Some("sync@project-1.iam.gserviceaccount.com"), Some(google::SCOPES)));
    d.subjects.push(claims["sub"].as_str().map(String::from));
    (StatusCode::OK, Json(json!({ "access_token": TOKEN, "expires_in": 3599, "token_type": "Bearer" })))
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
        sso: None,
        admin: Some("admin@example.com".into()),
        api: g.url.clone(),
        interval: std::time::Duration::from_secs(1800),
        max_removals: 10,
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
}

async fn world(g: &Google, with_sso: bool, tweak: impl FnOnce(&mut Settings)) -> World {
    let mut s = settings(g);
    tweak(&mut s);
    let key = g.key.clone();
    let mut sso = None;
    let (port, app, admin, _) = serve_app_with(|a| {
        a.scim.enabled = true;
        a.scim.groups = true;
        if with_sso {
            let id = google_sso(a);
            s.sso = Some(id.clone());
            sso = Some(id);
        }
        let d = Directory::with_key(a.app.as_ref().unwrap(), s, Box::new(move || Ok(Some(Zeroizing::new(key.clone()))))).unwrap();
        a.scim.google = Some(Arc::new(d));
    })
    .await;
    World { port, app, admin, sso }
}

async fn sync(w: &World, body: &str) -> (u16, Value) {
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
    assert_eq!(call(port, "POST", "/api/scim/google/sync", &admin, "").await.0, 409, "off: nothing to run");
    token(port, &admin, json!({ "tenant": TENANT })).await;
    let key = g.key.clone();
    let e = Directory::with_key(&app, settings(&g), Box::new(move || Ok(Some(Zeroizing::new(key.clone()))))).err().unwrap();
    assert!(e.contains("only writer"), "{e}");
    let e = Directory::with_key(&app, Settings { tenant: "fresh".into(), ..settings(&g) }, Box::new(|| Ok(None))).err().unwrap();
    assert!(e.contains(google::CREDENTIALS), "{e}");
}
