//! Requests for access from the public "Get started" form, and the admin endpoints
//! that approve or reject them. There is no self-serve tenancy or billing yet, so an
//! admin approves each request: that makes the user and a one-time sign-in code.
//! Design: docs/adr/0022-landing-and-signups.md.

use crate::audit::{Actor, ActorKind, Outcome, Source, Who};
use crate::db::{AddSignup, NewSignup, Signup, SignupError, User};
use crate::rbac::Role;
use crate::secrets::SecretStore;
use crate::sso::Provider;
use crate::users::{self, Limiter};
use crate::{bad, not_found, ApiError, AppState, Auth, Res};
use axum::body::Bytes;
use axum::extract::{Extension, Path, Query, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

pub const SIGN_INS: [&str; 5] = ["microsoft", "google", "github", "apple", "other"];
pub const TEAM_SIZES: [&str; 6] = ["1", "2-10", "11-50", "51-200", "201-1000", "1000+"];
/// The form is a few short fields; anything bigger isn't from it.
pub const MAX_BODY: usize = 16 * 1024;
/// Submissions per client IP per hour, valid or not.
const SUBMIT_LIMIT: u32 = 5;
const SUBMIT_WINDOW_MS: i64 = 60 * 60_000;
/// Past this many waiting requests the form stops taking more, so a flood can't fill the disk.
const MAX_PENDING: i64 = 1000;
/// Approval codes outlive the usual hour: the admin hands them over by hand.
const APPROVAL_CODE_MINUTES: i64 = 3 * 24 * 60;
const FIELDS: [&str; 9] = ["name", "email", "company", "teamSize", "useCase", "signIn", "consent", "website", "turnstileToken"];
pub const TURNSTILE_VERIFY_URL: &str = "https://challenges.cloudflare.com/turnstile/v0/siteverify";

/// Cloudflare Turnstile, on when TURNSTILE_SECRET is set.
pub struct Turnstile {
    pub secret: String,
    pub site_key: String,
    pub verify_url: String,
}

pub struct Signups {
    /// SIGNUPS=off closes the form.
    pub enabled: bool,
    pub turnstile: Option<Turnstile>,
    pub limiter: Limiter,
    http: OnceLock<reqwest::Client>,
}

impl Default for Signups {
    fn default() -> Signups {
        Signups { enabled: true, turnstile: None, limiter: Limiter::new(SUBMIT_LIMIT, SUBMIT_WINDOW_MS), http: OnceLock::new() }
    }
}

impl Signups {
    /// SIGNUPS (on unless 0/off), TURNSTILE_SECRET (or _FILE) and TURNSTILE_SITE_KEY.
    pub fn from_env(store: &dyn SecretStore, signups: &str, site_key: &str) -> Result<Signups, String> {
        let enabled = match signups.trim().to_ascii_lowercase().as_str() {
            "" | "1" | "on" | "true" | "yes" => true,
            "0" | "off" | "false" | "no" => false,
            _ => return Err(format!("SIGNUPS must be on or off, not \"{signups}\"")),
        };
        let secret = store.get("TURNSTILE_SECRET").map_err(|e| e.to_string())?;
        let site_key = site_key.trim();
        let turnstile = match (secret, site_key.is_empty()) {
            (None, true) => None,
            (Some(s), false) => {
                crate::secrets::redact::register(s.expose());
                Some(Turnstile { secret: s.expose().to_string(), site_key: site_key.into(), verify_url: TURNSTILE_VERIFY_URL.into() })
            }
            (Some(_), true) => return Err("TURNSTILE_SECRET needs TURNSTILE_SITE_KEY, the widget's public key".into()),
            (None, false) => return Err("TURNSTILE_SITE_KEY needs TURNSTILE_SECRET to check the answers".into()),
        };
        if !site_key.is_empty() && !site_key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-') {
            return Err("TURNSTILE_SITE_KEY has characters a site key doesn't".into());
        }
        Ok(Signups { enabled, turnstile, ..Signups::default() })
    }

    fn http(&self) -> &reqwest::Client {
        self.http.get_or_init(|| reqwest::Client::builder().timeout(Duration::from_secs(10)).build().expect("HTTP client"))
    }

    /// Asks Cloudflare whether the widget's token is good. Fails closed.
    async fn verified(&self, t: &Turnstile, token: &str, ip: Option<&str>) -> bool {
        if token.is_empty() || token.len() > 2048 {
            return false;
        }
        let mut form = vec![("secret", t.secret.as_str()), ("response", token)];
        if let Some(ip) = ip {
            form.push(("remoteip", ip));
        }
        let Ok(res) = self.http().post(&t.verify_url).form(&form).send().await else { return false };
        res.json::<Value>().await.is_ok_and(|v| v["success"] == true)
    }
}

/// What happened to a request, for whoever should hear about it. There is no mail
/// service yet, so nothing is sent and the admin shares the sign-in code by hand.
/// A mailer (SMTP or an email API, configured in the environment) plugs in here.
#[allow(dead_code, reason = "the fields are for a mailer, when there is one")]
pub enum Notice<'a> {
    Received(&'a Signup),
    Approved { signup: &'a Signup, user: &'a User, code: &'a str, expires_at: i64 },
    Rejected(&'a Signup),
}

/// Whether the person was told. Always false until a mailer exists.
pub fn notify(_notice: Notice) -> bool {
    false
}

/// A form field: a string, trimmed, 1 to `max` characters, without control
/// characters (newlines and tabs too, unless `multiline`).
fn text(v: &Value, field: &str, label: &str, max: usize, multiline: bool) -> Result<String, (String, String)> {
    let err = |m: String| (field.to_string(), m);
    let Some(s) = v[field].as_str() else {
        return Err(err(format!("{label} is required.")));
    };
    let s = s.replace("\r\n", "\n");
    let s = s.trim();
    if s.is_empty() {
        return Err(err(format!("{label} is required.")));
    }
    if s.chars().any(|c| c.is_control() && !(multiline && (c == '\n' || c == '\t'))) {
        return Err(err(format!("{label} has characters we can't take.")));
    }
    if s.chars().count() > max {
        return Err(err(format!("{label} must be at most {max} characters.")));
    }
    Ok(s.to_string())
}

pub struct Form {
    pub name: String,
    pub email: String,
    pub company: String,
    pub team_size: String,
    pub use_case: String,
    pub sign_in: String,
}

/// The form, strictly: known fields only, every one valid, and consent given.
pub fn parse(v: &Value) -> Result<Form, (String, String)> {
    let obj = v.as_object().ok_or_else(|| (String::new(), "Send the form as a JSON object.".to_string()))?;
    if let Some(k) = obj.keys().find(|k| !FIELDS.contains(&k.as_str())) {
        return Err((k.chars().take(40).collect(), "Unknown field.".into()));
    }
    let name = text(v, "name", "Name", 100, false)?;
    let email = text(v, "email", "Work email", 254, false)?;
    if !users::valid_email(&email) {
        return Err(("email".into(), "Enter a valid work email.".into()));
    }
    let company = text(v, "company", "Company", 120, false)?;
    let team_size = v["teamSize"].as_str().filter(|t| TEAM_SIZES.contains(t)).ok_or(("teamSize".to_string(), "Pick a team size.".to_string()))?;
    let use_case = text(v, "useCase", "What you want to use SuperBot for", 2000, true)?;
    let sign_in = v["signIn"].as_str().filter(|s| SIGN_INS.contains(s)).ok_or(("signIn".to_string(), "Pick how you'd like to sign in.".to_string()))?;
    if v["consent"] != true {
        return Err(("consent".into(), "Please agree so we can store your request and contact you about it.".into()));
    }
    if !matches!(v.get("turnstileToken"), None | Some(Value::String(_))) {
        return Err(("turnstileToken".into(), "Unknown verification answer.".into()));
    }
    Ok(Form { name, email, company, team_size: team_size.into(), use_case, sign_in: sign_in.into() })
}

/// The honeypot: a field people never see, so only scripts fill it in.
fn honeypot(v: &Value) -> bool {
    match v.get("website") {
        None | Some(Value::Null) => false,
        Some(Value::String(s)) => !s.is_empty(),
        Some(_) => true,
    }
}

fn picked(sign_in: &str, provider_type: &str) -> bool {
    match sign_in {
        "microsoft" => provider_type == "entra",
        "other" => matches!(provider_type, "oidc" | "saml"),
        s => provider_type == s,
    }
}

/// The single sign-on buttons this person could use after approval: the providers that
/// take their email's domain, and the ones of the kind they picked that don't go by
/// domain or take theirs.
pub fn sso_hint<'a>(providers: impl IntoIterator<Item = &'a Provider>, email: &str, sign_in: &str) -> Vec<Value> {
    providers
        .into_iter()
        .filter(|p| match p.takes_email(email) {
            Some(takes) => takes,
            None => picked(sign_in, p.type_name()),
        })
        .map(|p| json!({ "id": p.id, "label": p.label, "type": p.type_name() }))
        .collect()
}

fn no_store(mut res: Response) -> Response {
    res.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    res
}

fn field_error(field: &str, msg: &str) -> Response {
    (StatusCode::BAD_REQUEST, Json(json!({ "error": msg, "field": field }))).into_response()
}

/// `GET /api/signups/config`, public: what the form needs to know.
pub async fn config(Extension(a): Extension<Arc<Auth>>) -> Response {
    let providers: Vec<Value> = a.sso.providers.iter().filter(|p| p.ready()).map(|p| json!({ "label": p.label, "type": p.type_name() })).collect();
    no_store(
        Json(json!({
            "enabled": a.signups.enabled,
            "turnstileSiteKey": a.signups.turnstile.as_ref().map(|t| &t.site_key),
            "providers": providers,
            "teamSizes": TEAM_SIZES,
            "signIns": SIGN_INS,
        }))
        .into_response(),
    )
}

/// An anonymous visitor, as the audit log records them.
fn visitor(name: Option<&str>, email: Option<&str>) -> Actor {
    Actor { kind: ActorKind::User, id: None, name: name.map(String::from), email: email.map(String::from), ..Default::default() }
}

/// `POST /api/signups`, public. Every submission counts toward the per-IP limit. A
/// filled honeypot gets the same answer as a real request, so scripts learn nothing,
/// and so does a second request for an email that is already waiting.
pub async fn submit(State(app): State<AppState>, Extension(a): Extension<Arc<Auth>>, Extension(source): Extension<Source>, body: Bytes) -> Response {
    let s = &a.signups;
    if !s.enabled {
        return ApiError(StatusCode::NOT_FOUND, "Sign-ups are closed on this server.".into()).into_response();
    }
    let ip = source.ip.clone().unwrap_or_default();
    if let Some(retry) = s.limiter.hit(&ip, crate::db::now()) {
        let mut r = (StatusCode::TOO_MANY_REQUESTS, Json(json!({ "error": "Too many requests from your network. Try again later." }))).into_response();
        r.headers_mut().insert(header::RETRY_AFTER, HeaderValue::from(retry.max(1)));
        return r;
    }
    let Ok(v) = serde_json::from_slice::<Value>(&body) else {
        return field_error("", "Send the form as JSON.");
    };
    let refused = |reason: &str, form: Option<&Form>| {
        if let Some(missed) = a.logins.failure(&format!("{ip}|signup"), crate::db::now()) {
            let who = Who { actor: visitor(form.map(|f| f.name.as_str()), form.map(|f| f.email.as_str())), source: source.clone() };
            app.db.record(&who.event("signup.refused").outcome(Outcome::Denied).details(json!({ "reason": reason, "unloggedSinceLast": missed })));
        }
    };
    let accepted = |hint: Vec<Value>| no_store((StatusCode::ACCEPTED, Json(json!({ "ok": true, "sso": hint }))).into_response());
    if honeypot(&v) {
        refused("honeypot", None);
        return accepted(vec![]);
    }
    let form = match parse(&v) {
        Ok(f) => f,
        Err((field, msg)) => return field_error(&field, &msg),
    };
    if let Some(t) = &s.turnstile
        && !s.verified(t, v["turnstileToken"].as_str().unwrap_or(""), source.ip.as_deref()).await
    {
        refused("turnstile", Some(&form));
        return field_error("turnstileToken", "We couldn't verify you're a person. Try the check again.");
    }
    let hint = sso_hint(a.sso.providers.iter().filter(|p| p.ready()).map(|p| p.as_ref()), &form.email, &form.sign_in);
    let saved = app.db.add_signup(
        &NewSignup {
        name: &form.name,
        email: &form.email,
        company: &form.company,
        team_size: &form.team_size,
        use_case: &form.use_case,
        sign_in: &form.sign_in,
        ip: source.ip.as_deref(),
        user_agent: source.user_agent.as_deref(),
        },
        MAX_PENDING,
    );
    match saved {
        Ok(su) => {
            let who = Who { actor: visitor(Some(&su.name), Some(&su.email)), source: source.clone() };
            app.db.record(&who.event("signup.submitted").target("signup", &su.id).details(json!({ "company": su.company, "teamSize": su.team_size, "signIn": su.sign_in })));
            notify(Notice::Received(&su));
        }
        Err(AddSignup::Duplicate) => {}
        Err(AddSignup::Full) => {
            refused("full", Some(&form));
            return ApiError(StatusCode::SERVICE_UNAVAILABLE, "We can't take new requests right now. Please try again later.".into()).into_response();
        }
    }
    accepted(hint)
}

pub fn signup_view(app: &AppState, s: &Signup) -> Value {
    let mut v = serde_json::to_value(s).unwrap_or_default();
    v["existingUser"] = json!(s.status == "pending" && app.db.find_user(&s.email).is_some());
    v
}

/// `GET /api/signups?status=pending|approved|rejected|all&limit=`. Newest first.
pub async fn list(State(app): State<AppState>, Query(q): Query<HashMap<String, String>>) -> Res {
    let status = match q.get("status").map(String::as_str) {
        None | Some("" | "all") => None,
        Some(s @ ("pending" | "approved" | "rejected")) => Some(s),
        Some(_) => return Err(bad("status must be pending, approved, rejected, or all")),
    };
    let limit = match q.get("limit") {
        None => 200,
        Some(l) => l.parse::<u32>().ok().filter(|l| (1..=1000).contains(l)).ok_or_else(|| bad("limit must be 1 to 1000"))?,
    };
    Ok(Json(json!(app.db.signups(status, limit).iter().map(|s| signup_view(&app, s)).collect::<Vec<_>>())))
}

pub async fn get(State(app): State<AppState>, Path(id): Path<String>) -> Res {
    Ok(Json(signup_view(&app, &app.db.signup(&id).ok_or_else(|| not_found("Sign-up"))?)))
}

fn optional_json(body: &Bytes) -> Res<Value> {
    if body.iter().all(u8::is_ascii_whitespace) {
        return Ok(Value::Null);
    }
    serde_json::from_slice(body).map_err(|e| bad(format!("Invalid JSON: {e}")))
}

fn decide_error(e: SignupError) -> ApiError {
    match e {
        SignupError::NotFound => not_found("Sign-up"),
        SignupError::Closed(status) => ApiError(StatusCode::CONFLICT, format!("This request was {status} already.")),
        SignupError::EmailTaken => ApiError(
            StatusCode::CONFLICT,
            "A user with this email exists already. Reject the request, or give them a sign-in code (botctl user code).".into(),
        ),
        SignupError::Db(e) => ApiError(StatusCode::INTERNAL_SERVER_ERROR, e),
    }
}

/// `POST /api/signups/{id}/approve` `{role?, ttlMinutes?}`: makes the user (member by
/// default) and a one-time sign-in code, returned once. `sso` lists the providers the
/// person could link (`botctl user link`) to sign in without codes.
pub async fn approve(
    State(app): State<AppState>,
    Extension(a): Extension<Arc<Auth>>,
    Extension(by): Extension<Who>,
    Path(id): Path<String>,
    body: Bytes,
) -> Res<Response> {
    let v = optional_json(&body)?;
    let role = match &v["role"] {
        Value::Null => Role::Member,
        r => r.as_str().and_then(Role::parse).ok_or_else(|| bad("role must be admin, member, or readonly"))?,
    };
    let ttl = users::code_ttl(&v["ttlMinutes"], APPROVAL_CODE_MINUTES)?;
    let (su, user) = app.db.approve_signup(&id, role, by.actor.id.as_deref().unwrap_or("")).map_err(decide_error)?;
    users::record_created(&app, &by, &user, Some(&format!("sign-up {}", su.id)));
    let (code, expires) = users::issue_code(&app, &by, &user, ttl);
    app.db.record(&by.event("signup.approved").target("signup", &su.id).details(json!({ "userId": user.id, "email": su.email, "role": role })));
    let emailed = notify(Notice::Approved { signup: &su, user: &user, code: &code, expires_at: expires });
    let sso = sso_hint(a.sso.providers.iter().filter(|p| p.ready()).map(|p| p.as_ref()), &su.email, &su.sign_in);
    let body = json!({ "signup": signup_view(&app, &su), "user": users::user_view(&user), "code": code, "expiresAt": expires, "emailed": emailed, "sso": sso });
    Ok(no_store(Json(body).into_response()))
}

/// `POST /api/signups/{id}/reject` `{reason?}`. The reason is for admins; nobody is told.
pub async fn reject(State(app): State<AppState>, Extension(by): Extension<Who>, Path(id): Path<String>, body: Bytes) -> Res {
    let v = optional_json(&body)?;
    let reason = match &v["reason"] {
        Value::Null => None,
        Value::String(r) if r.trim().is_empty() => None,
        Value::String(r) if r.trim().chars().count() <= 500 && !r.chars().any(|c| c.is_control() && c != '\n') => Some(r.trim().to_string()),
        _ => return Err(bad("reason must be text, at most 500 characters")),
    };
    let su = app.db.reject_signup(&id, by.actor.id.as_deref().unwrap_or(""), reason.as_deref()).map_err(decide_error)?;
    app.db.record(&by.event("signup.rejected").target("signup", &su.id).details(json!({ "email": su.email, "reason": su.reason })));
    notify(Notice::Rejected(&su));
    Ok(Json(signup_view(&app, &su)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secrets::env::EnvStore;
    use crate::sso::{ClaimMap, Kind};

    fn good() -> Value {
        json!({
            "name": "Ada Lovelace", "email": "ada@example.com", "company": "Analytical Engines",
            "teamSize": "11-50", "useCase": "Research briefs\r\nand weekly reports", "signIn": "microsoft", "consent": true,
        })
    }

    #[test]
    fn the_form_is_parsed_strictly() {
        let f = parse(&good()).unwrap();
        assert_eq!((f.name.as_str(), f.use_case.as_str(), f.sign_in.as_str()), ("Ada Lovelace", "Research briefs\nand weekly reports", "microsoft"));
        let with = |k: &str, v: Value| {
            let mut g = good();
            g[k] = v;
            parse(&g).err().map(|(field, _)| field)
        };
        assert_eq!(with("name", json!("  ")), Some("name".into()));
        assert_eq!(with("name", json!("a\nb")), Some("name".into()), "one line");
        assert_eq!(with("name", json!("x".repeat(101))), Some("name".into()));
        assert_eq!(with("name", json!("é".repeat(100))), None, "characters, not bytes");
        assert_eq!(with("email", json!("not-an-email")), Some("email".into()));
        assert_eq!(with("company", json!(7)), Some("company".into()));
        assert_eq!(with("teamSize", json!("12")), Some("teamSize".into()));
        assert_eq!(with("useCase", json!("x".repeat(2001))), Some("useCase".into()));
        assert_eq!(with("useCase", json!("bell\u{7}")), Some("useCase".into()));
        assert_eq!(with("signIn", json!("okta")), Some("signIn".into()));
        assert_eq!(with("consent", json!("yes")), Some("consent".into()));
        assert_eq!(with("consent", json!(false)), Some("consent".into()));
        assert_eq!(with("admin", json!(true)), Some("admin".into()), "unknown fields are refused");
        assert_eq!(with("turnstileToken", json!(1)), Some("turnstileToken".into()));
        assert!(parse(&json!([1])).is_err());
        for (v, filled) in [(json!(null), false), (json!(""), false), (json!("https://spam.example"), true), (json!(0), true)] {
            let mut g = good();
            g["website"] = v;
            assert_eq!(honeypot(&g), filled);
        }
        assert!(!honeypot(&good()));
    }

    #[test]
    fn sso_hints_follow_the_email_and_the_pick() {
        let p = |id: &str, kind: Kind| Provider::new(id, id, kind, "client", "openid", None);
        let entra = p("work", Kind::Entra { authority: "https://login.microsoftonline.com".into(), tenant: "organizations".into(), allowed: vec![] });
        let google = p("g", Kind::Google { issuer: "https://accounts.google.com".into(), hosted_domains: vec!["example.com".into()] });
        let okta = p("okta", Kind::Oidc { issuer: "https://idp.example".into(), map: ClaimMap::default(), allowed_domains: vec![] });
        let adfs = p("adfs", Kind::Saml { issuer: "https://broker.example".into(), entity_id: "https://adfs.example".into(), alias: "adfs".into(), map: ClaimMap::default(), allowed_domains: vec!["corp.example".into()] });
        let all = [&entra, &google, &okta, &adfs];
        let ids = |email: &str, pick: &str| sso_hint(all, email, pick).iter().map(|v| v["id"].as_str().unwrap().to_string()).collect::<Vec<_>>();
        assert_eq!(ids("ada@example.com", "microsoft"), ["work", "g"], "their Workspace domain counts whatever they picked");
        assert_eq!(ids("ada@other.example", "google"), Vec::<String>::new(), "a Google provider for another domain doesn't");
        assert_eq!(ids("ada@other.example", "other"), ["okta"]);
        assert_eq!(ids("ada@other.example", "github"), Vec::<String>::new());
        assert_eq!(ids("ada@corp.example", "microsoft"), ["work", "adfs"], "a SAML IdP for their domain counts too");
    }

    #[test]
    fn settings() {
        let none = EnvStore::fixed(&[]);
        let s = Signups::from_env(&none, "", "").unwrap();
        assert!(s.enabled && s.turnstile.is_none());
        assert!(!Signups::from_env(&none, "off", "").unwrap().enabled);
        assert!(Signups::from_env(&none, "maybe", "").is_err());
        assert!(Signups::from_env(&none, "", "0x4AAA").is_err(), "a site key alone checks nothing");
        let secret = EnvStore::fixed(&[("TURNSTILE_SECRET", "0x4BBB")]);
        assert!(Signups::from_env(&secret, "", "").is_err());
        assert!(Signups::from_env(&secret, "", "<script>").is_err());
        let t = Signups::from_env(&secret, "", "0x4AAA").unwrap().turnstile.unwrap();
        assert_eq!((t.site_key.as_str(), t.verify_url.as_str()), ("0x4AAA", TURNSTILE_VERIFY_URL));
    }
}
