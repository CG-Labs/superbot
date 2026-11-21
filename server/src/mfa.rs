//! A second factor for local sign-ins (ADR 0094): six-digit TOTP codes (RFC 6238) from
//! an authenticator app, and one-time recovery codes. The break-glass password and
//! one-time sign-in codes ask for it; SSO sign-ins rely on the IdP's own MFA.
//!
//! Secrets are sealed with the master key under the user's id (ADR 0010). Recovery
//! codes are kept as HMACs under a key derived from the master key, so a copy of the
//! database alone can't test guesses. Codes and secrets are never logged.

use crate::audit::{Outcome, Source, Who};
use crate::db::{self, User};
use crate::rbac::{Principal, Role};
use crate::secrets::sealed;
use crate::users::{self, Caller, Limiter};
use crate::{bad, ApiError, AppState, Auth, Res};
use axum::extract::{Extension, Path, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use zeroize::Zeroizing;

/// A sign-in waiting for its second factor: `sbm_` + 256 random bits as hex.
pub const CHALLENGE_PREFIX: &str = "sbm_";
pub const STEP_MS: i64 = 30_000;
const DIGITS: u32 = 6;
/// Codes for one step either side of now also work, for clocks that drift.
const SKEW: i64 = 1;
const SECRET_BYTES: usize = 20;
pub const RECOVERY_CODES: usize = 10;
/// Ten base32 characters: 50 bits each.
const RECOVERY_LEN: usize = 10;
const CHALLENGE_TTL_MS: i64 = 5 * 60_000;
/// Wrong codes one challenge takes before the sign-in must start over.
const CHALLENGE_TRIES: u32 = 5;
const MAX_CHALLENGES: usize = 10_000;
/// Wrong codes per user, from any IP, before a pause. Only someone past the first factor
/// can spend these.
const USER_FAIL_LIMIT: u32 = 5;
const USER_FAIL_WINDOW_MS: i64 = 15 * 60_000;
pub const POLICY_KEY: &str = "mfa_policy";
const ISSUER: &str = "SuperBot";

// TOTP (RFC 6238 over RFC 4226 HOTP), with HMAC-SHA1: what authenticator apps support.

fn hotp(key: &[u8], counter: u64, digits: u32) -> String {
    use aws_lc_rs::hmac;
    let tag = hmac::sign(&hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, key), &counter.to_be_bytes());
    let h = tag.as_ref();
    let off = (h[h.len() - 1] & 0x0f) as usize;
    let bin = u32::from_be_bytes([h[off] & 0x7f, h[off + 1], h[off + 2], h[off + 3]]);
    format!("{:0width$}", bin % 10u32.pow(digits), width = digits as usize)
}

fn step_at(at_ms: i64) -> i64 {
    at_ms.div_euclid(STEP_MS)
}

/// The code an authenticator app shows at `at_ms`.
#[cfg(test)]
pub fn code_at(key: &[u8], at_ms: i64) -> String {
    hotp(key, step_at(at_ms) as u64, DIGITS)
}

/// The time step `code` is for, if it is right for now (give or take `SKEW`) and later
/// than `after`. Every candidate is compared, in constant time.
fn matching_step(key: &[u8], code: &str, at_ms: i64, after: i64) -> Option<i64> {
    let code: String = code.chars().filter(|c| !c.is_whitespace()).collect();
    if code.len() != DIGITS as usize || !code.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let now = step_at(at_ms);
    let mut found = None;
    for step in (now - SKEW..=now + SKEW).filter(|s| *s > 0) {
        if crate::same(code.as_bytes(), hotp(key, step as u64, DIGITS).as_bytes()) && step > after && found.is_none() {
            found = Some(step);
        }
    }
    found
}

const B32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// RFC 4648 base32, without padding: how authenticator apps take a secret.
pub fn base32(bytes: &[u8]) -> String {
    let (mut out, mut buf, mut bits) = (String::new(), 0u32, 0);
    for b in bytes {
        buf = (buf << 8) | u32::from(*b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(B32[((buf >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(B32[((buf << (5 - bits)) & 31) as usize] as char);
    }
    out
}

fn uri_part(s: &str) -> String {
    s.bytes()
        .map(|b| if b.is_ascii_alphanumeric() || b"-._~@".contains(&b) { (b as char).to_string() } else { format!("%{b:02X}") })
        .collect()
}

/// The `otpauth://` link authenticator apps open or scan.
pub fn otpauth_url(account: &str, secret_b32: &str) -> String {
    format!(
        "otpauth://totp/{ISSUER}:{}?secret={secret_b32}&issuer={ISSUER}&algorithm=SHA1&digits={DIGITS}&period={}",
        uri_part(account),
        STEP_MS / 1000
    )
}

/// The link as a QR code, an SVG element for a page to show.
fn qr_svg(url: &str) -> Option<String> {
    use qrcode::render::svg;
    let svg = qrcode::QrCode::with_error_correction_level(url, qrcode::EcLevel::M).ok()?.render::<svg::Color>().min_dimensions(200, 200).build();
    svg.find("<svg").map(|i| svg[i..].to_string())
}

fn open_secret(user_id: &str, sealed_secret: &str) -> Option<Zeroizing<Vec<u8>>> {
    sealed::cipher().open(&sealed::mfa_context(user_id), sealed_secret).ok()
}

// Recovery codes: `xxxxx-xxxxx`, from base32's lowercase letters and digits.

fn new_recovery_codes() -> Vec<String> {
    (0..RECOVERY_CODES)
        .map(|_| {
            let c = base32(&crate::random_bytes(7)).to_ascii_lowercase();
            format!("{}-{}", &c[..5], &c[5..RECOVERY_LEN])
        })
        .collect()
}

fn normalize_recovery(code: &str) -> Option<String> {
    let c: String = code.chars().filter(|c| !c.is_whitespace() && *c != '-').collect::<String>().to_ascii_lowercase();
    (c.len() == RECOVERY_LEN && c.bytes().all(|b| B32.contains(&b.to_ascii_uppercase()))).then_some(c)
}

/// The stored form of a recovery code: HMAC-SHA256 under a key derived from the master
/// key, bound to the user.
fn recovery_hash(user_id: &str, normalized: &str) -> String {
    use aws_lc_rs::hmac;
    let key = sealed::cipher().derive("mfa/recovery-codes");
    let tag = hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, &key[..]), format!("{user_id}:{normalized}").as_bytes());
    tag.as_ref().iter().map(|b| format!("{b:02x}")).collect()
}

fn recovery_hashes(user_id: &str, codes: &[String]) -> Vec<String> {
    codes.iter().filter_map(|c| normalize_recovery(c)).map(|c| recovery_hash(user_id, &c)).collect()
}

// Policy: who must have a second factor to sign in with a password or code.

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Policy {
    Off,
    /// Admins, which includes the owner (break-glass) account.
    Admins,
    All,
}

impl Policy {
    pub fn parse(s: &str) -> Option<Policy> {
        match s.trim().to_ascii_lowercase().as_str() {
            "off" | "none" => Some(Policy::Off),
            "admins" | "admin" => Some(Policy::Admins),
            "all" | "everyone" => Some(Policy::All),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Policy::Off => "off",
            Policy::Admins => "admins",
            Policy::All => "all",
        }
    }

    pub fn requires(self, u: &User) -> bool {
        match self {
            Policy::Off => false,
            Policy::Admins => u.role == Role::Admin || u.id == users::OPERATOR,
            Policy::All => true,
        }
    }
}

/// AUTH_MFA: unset leaves the policy to admins; `off`, `admins`, or `all` fixes it here.
pub fn policy_flag(raw: &str) -> Result<Option<Policy>, String> {
    if raw.trim().is_empty() {
        return Ok(None);
    }
    Policy::parse(raw).map(Some).ok_or_else(|| format!("AUTH_MFA must be off, admins, or all, not \"{raw}\""))
}

/// Sign-ins in progress and the per-user limiter. Held in memory: a restart ends them.
pub struct Mfa {
    /// AUTH_MFA: the policy, set in `.env`, which the API can't change.
    pub pinned: Option<Policy>,
    pending: Mutex<HashMap<String, Pending>>,
    limiter: Limiter,
}

impl Default for Mfa {
    fn default() -> Self {
        Mfa { pinned: None, pending: Mutex::default(), limiter: Limiter::new(USER_FAIL_LIMIT, USER_FAIL_WINDOW_MS) }
    }
}

#[derive(Clone)]
struct Pending {
    user_id: String,
    /// The first factor: "password" or "code".
    method: &'static str,
    expires_at: i64,
    tries: u32,
    /// A sign-in that must enrol: the new secret, saved only once a code proves it.
    enroll: Option<Arc<Zeroizing<Vec<u8>>>>,
}

impl Mfa {
    pub fn with_policy(pinned: Option<Policy>) -> Mfa {
        Mfa { pinned, ..Mfa::default() }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, Pending>> {
        self.pending.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn start(&self, p: Pending) -> String {
        let challenge = users::new_secret(CHALLENGE_PREFIX);
        let mut m = self.lock();
        let at = db::now();
        if m.len() >= MAX_CHALLENGES {
            m.retain(|_, p| p.expires_at > at);
            if m.len() >= MAX_CHALLENGES {
                m.clear();
            }
        }
        m.insert(users::hash(&challenge), p);
        challenge
    }

    fn live(&self, challenge: &str, at: i64) -> Option<Pending> {
        let mut m = self.lock();
        let key = users::hash(challenge);
        match m.get(&key) {
            Some(p) if p.expires_at > at => Some(p.clone()),
            Some(_) => {
                m.remove(&key);
                None
            }
            None => None,
        }
    }

    /// Counts a wrong code. True when the challenge has no tries left (and is gone).
    fn wrong(&self, challenge: &str) -> bool {
        let mut m = self.lock();
        let key = users::hash(challenge);
        let Some(p) = m.get_mut(&key) else { return true };
        p.tries += 1;
        if p.tries >= CHALLENGE_TRIES {
            m.remove(&key);
            return true;
        }
        false
    }

    fn end(&self, challenge: &str) {
        self.lock().remove(&users::hash(challenge));
    }

    /// Ends every sign-in waiting on this user's second factor.
    pub fn forget_user(&self, user_id: &str) {
        self.lock().retain(|_, p| p.user_id != user_id);
    }
}

pub fn policy(a: &Auth, db: &db::Db) -> Policy {
    a.mfa.pinned.unwrap_or_else(|| db.setting(POLICY_KEY).as_deref().and_then(Policy::parse).unwrap_or(Policy::Off))
}

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Need {
    None,
    /// They have a second factor: ask for it.
    Verify,
    /// The policy requires one and they have none yet: set it up now.
    Enroll,
}

pub fn need(a: &Auth, db: &db::Db, u: &User) -> Need {
    if db.mfa(&u.id).is_some_and(|m| m.confirmed_at.is_some()) {
        Need::Verify
    } else if policy(a, db).requires(u) {
        Need::Enroll
    } else {
        Need::None
    }
}

/// The break-glass password can't carry a second factor, so once the owner account
/// needs one, HTTP Basic stops working and the password works only at sign-in.
pub fn guards_password(a: &Auth) -> bool {
    match (a.app.as_ref(), a.operator()) {
        (Some(app), Some(op)) => need(a, &app.db, &op) != Need::None,
        _ => false,
    }
}

// Signing in.

fn no_store(mut r: Response) -> Response {
    r.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    r
}

/// 401 with what the client needs for the second step.
fn ask(error: &str, mode: &str, challenge: &str, extra: Value) -> Response {
    let mut body = json!({ "error": error, "mfa": mode, "challenge": challenge });
    if let (Some(b), Some(e)) = (body.as_object_mut(), extra.as_object()) {
        b.extend(e.clone());
    }
    no_store((StatusCode::UNAUTHORIZED, Json(body)).into_response())
}

fn account_name(u: &User) -> &str {
    u.email.as_deref().unwrap_or(&u.name)
}

/// What a client shows to set up an authenticator app.
fn setup_view(u: &User, secret: &[u8]) -> Value {
    let b32 = Zeroizing::new(base32(secret));
    let url = otpauth_url(account_name(u), &b32);
    json!({ "secret": *b32, "otpauthUrl": url, "qrSvg": qr_svg(&url) })
}

/// A wrong second factor: counted per IP and per user, and audited with the user as
/// actor. Never what was sent.
fn failed(a: &Auth, source: &Source, u: &User, factor: &str, first: &str, reason: &str) {
    let at = db::now();
    a.limiter.fail(source.ip.as_deref().unwrap_or(""), at);
    a.mfa.limiter.fail(&u.id, at);
    let who = Who { actor: users::actor(a, u, None, first), source: source.clone() };
    a.record(who.event("auth.login_failed").outcome(Outcome::Failure).details(json!({ "method": factor, "firstFactor": first, "reason": reason })));
}

enum Check {
    Ok(&'static str),
    Wrong(&'static str, &'static str),
    Missing,
}

/// Checks the `totp` or `recoveryCode` in `v` against the user's confirmed second
/// factor, and spends it.
fn check(db: &db::Db, user_id: &str, v: &Value, at: i64) -> Check {
    if let Some(code) = v["totp"].as_str().filter(|c| !c.trim().is_empty()) {
        let Some(row) = db.mfa(user_id).filter(|m| m.confirmed_at.is_some()) else { return Check::Wrong("totp", "not_enrolled") };
        let Some(key) = open_secret(user_id, &row.secret) else { return Check::Wrong("totp", "unreadable") };
        return match matching_step(&key, code, at, row.last_step) {
            Some(step) if db.mfa_use_step(user_id, step) => Check::Ok("totp"),
            Some(_) => Check::Wrong("totp", "replayed"),
            None if matching_step(&key, code, at, i64::MIN).is_some() => Check::Wrong("totp", "replayed"),
            None => Check::Wrong("totp", "wrong_code"),
        };
    }
    if let Some(code) = v["recoveryCode"].as_str().filter(|c| !c.trim().is_empty()) {
        let ok = normalize_recovery(code).is_some_and(|c| db.mfa_use_recovery(user_id, &recovery_hash(user_id, &c)));
        return if ok { Check::Ok("recovery_code") } else { Check::Wrong("recovery_code", "wrong_code") };
    }
    Check::Missing
}

/// After a good password or code: Ok when no second factor is needed, or `v` carries a
/// good one (its kind); else the reply that starts the second step.
pub fn gate(a: &Auth, u: &User, method: &'static str, v: &Value, source: &Source) -> Result<Option<&'static str>, Response> {
    let Some(app) = a.app.as_ref() else { return Ok(None) };
    let at = db::now();
    match need(a, &app.db, u) {
        Need::None => Ok(None),
        Need::Enroll => {
            if let Some(retry) = a.mfa.limiter.blocked(&u.id, at) {
                return Err(users::too_many(retry));
            }
            let secret = Arc::new(Zeroizing::new(crate::random_bytes(SECRET_BYTES)));
            let view = setup_view(u, &secret);
            let challenge = a.mfa.start(Pending { user_id: u.id.clone(), method, expires_at: at + CHALLENGE_TTL_MS, tries: 0, enroll: Some(secret) });
            Err(ask("This server requires two-factor authentication for your account. Add it to an authenticator app, then enter the code it shows.", "enroll", &challenge, view))
        }
        Need::Verify => {
            if let Some(retry) = a.mfa.limiter.blocked(&u.id, at) {
                return Err(users::too_many(retry));
            }
            let pending = || Pending { user_id: u.id.clone(), method, expires_at: at + CHALLENGE_TTL_MS, tries: 0, enroll: None };
            match check(&app.db, &u.id, v, at) {
                Check::Ok(kind) => Ok(Some(kind)),
                Check::Missing => Err(ask("Enter the code from your authenticator app, or a recovery code.", "totp", &a.mfa.start(pending()), json!({}))),
                Check::Wrong(kind, reason) => {
                    failed(a, source, u, kind, method, reason);
                    let challenge = a.mfa.start(Pending { tries: 1, ..pending() });
                    Err(ask("That code is wrong. Try again.", "totp", &challenge, json!({})))
                }
            }
        }
    }
}

/// `POST /api/auth/login` `{challenge, totp | recoveryCode, session?, label?}`: the
/// second step. A sign-in that had to enrol sends the first code from the new secret
/// and gets its recovery codes back with the session.
pub fn finish(a: &Auth, source: Source, challenge: &str, v: &Value, cookie: bool, label: Option<&str>) -> Response {
    let Some(app) = a.app.as_ref() else {
        return ApiError(StatusCode::SERVICE_UNAVAILABLE, "No database".into()).into_response();
    };
    let at = db::now();
    let ip = source.ip.clone().unwrap_or_default();
    let expired = || ApiError(StatusCode::UNAUTHORIZED, "That sign-in expired. Sign in again.".into()).into_response();
    let Some(p) = a.mfa.live(challenge, at) else {
        a.limiter.fail(&ip, at);
        a.login_failed(&source, "totp", Some("expired_challenge"));
        return expired();
    };
    let Some(user) = app.db.user(&p.user_id).filter(User::active) else {
        a.mfa.end(challenge);
        return expired();
    };
    if let Some(retry) = a.mfa.limiter.blocked(&user.id, at) {
        return users::too_many(retry);
    }
    let mode = if p.enroll.is_some() { "enroll" } else { "totp" };
    let wrong = |kind: &str, reason: &str| {
        failed(a, &source, &user, kind, p.method, reason);
        if a.mfa.wrong(challenge) {
            return ApiError(StatusCode::UNAUTHORIZED, "Too many wrong codes. Sign in again.".into()).into_response();
        }
        ask("That code is wrong. Try again.", mode, challenge, json!({}))
    };
    let (kind, recovery) = match &p.enroll {
        Some(secret) => {
            let Some(code) = v["totp"].as_str() else { return bad("Send the code your authenticator app shows (totp).").into_response() };
            let Some(step) = matching_step(secret, code, at, i64::MIN) else { return wrong("totp", "wrong_code") };
            let codes = new_recovery_codes();
            let sealed_secret = sealed::cipher().seal(&sealed::mfa_context(&user.id), secret);
            a.mfa.end(challenge);
            if !app.db.mfa_enable(&user.id, &sealed_secret, step, &recovery_hashes(&user.id, &codes)) {
                return ApiError(StatusCode::CONFLICT, "Two-factor authentication was already set up for this account. Sign in again.".into()).into_response();
            }
            let who = Who { actor: users::actor(a, &user, None, p.method), source: source.clone() };
            a.record(who.event("user.mfa_enabled").target("user", &user.id).details(json!({ "via": "sign_in", "recoveryCodes": codes.len() })));
            ("totp", Some(codes))
        }
        None => match check(&app.db, &user.id, v, at) {
            Check::Ok(kind) => {
                a.mfa.end(challenge);
                (kind, None)
            }
            Check::Wrong(kind, reason) => return wrong(kind, reason),
            Check::Missing => return bad("Send the code from your authenticator app (totp), or a recovery code (recoveryCode).").into_response(),
        },
    };
    signed_in(a, &user, p.method, kind, cookie, label, source, recovery)
}

/// Starts the session for a sign-in that passed both factors, and audits it.
#[allow(clippy::too_many_arguments)]
pub fn signed_in(a: &Auth, user: &User, method: &str, kind: &str, cookie: bool, label: Option<&str>, source: Source, recovery: Option<Vec<String>>) -> Response {
    let app = a.app.as_ref().expect("sessions need the database");
    let (s, token) = users::start_session(a, user, method, None, Some(kind), cookie, label, &source);
    let who = Who { actor: users::actor(a, user, Some(&s), method), source };
    let mut details = json!({ "method": method, "kind": s.kind, "label": s.label, "mfa": kind });
    if kind == "recovery_code" {
        details["recoveryCodesLeft"] = json!(app.db.mfa_recovery_left(&user.id));
    }
    app.db.record(&who.event("auth.login").target("session", &s.id).details(details));
    let extra = recovery.map_or_else(|| json!({}), |codes| json!({ "recoveryCodes": codes }));
    users::session_reply(a, user, &s, &token, extra)
}

// Managing your own second factor: `/api/auth/mfa`.

fn person(c: &Caller) -> Res<User> {
    match (&c.principal, &c.user) {
        (Principal::User(_), Some(u)) => Ok(u.clone()),
        _ => Err(ApiError(StatusCode::FORBIDDEN, "Only a signed-in person can do this, not a Bot.".into())),
    }
}

fn status_view(a: &Auth, app: &AppState, u: &User) -> Value {
    let row = app.db.mfa(&u.id);
    let p = policy(a, &app.db);
    json!({
        "enabled": row.as_ref().is_some_and(|m| m.confirmed_at.is_some()),
        "enabledAt": row.as_ref().and_then(|m| m.confirmed_at),
        "pending": row.as_ref().is_some_and(|m| m.confirmed_at.is_none()),
        "recoveryCodesLeft": app.db.mfa_recovery_left(&u.id),
        "required": p.requires(u),
        "policy": p.as_str(),
        "policyPinned": a.mfa.pinned.is_some(),
    })
}

/// `me`'s summary: whether this person has a second factor and must have one.
pub fn summary(a: &Auth, u: &User) -> Value {
    let Some(app) = a.app.as_ref() else { return Value::Null };
    json!({ "enabled": app.db.mfa(&u.id).is_some_and(|m| m.confirmed_at.is_some()), "required": policy(a, &app.db).requires(u) })
}

/// `GET /api/auth/mfa`.
pub async fn status(State(app): State<AppState>, Extension(a): Extension<Arc<Auth>>, Extension(c): Extension<Caller>) -> Res {
    let u = person(&c)?;
    Ok(Json(status_view(&a, &app, &u)))
}

/// `POST /api/auth/mfa/enroll`: a new secret to add to an authenticator app. Nothing
/// changes for sign-in until `confirm` gets a code from it.
pub async fn enroll(State(app): State<AppState>, Extension(c): Extension<Caller>) -> Res<Response> {
    let u = person(&c)?;
    let secret = Zeroizing::new(crate::random_bytes(SECRET_BYTES));
    if !app.db.mfa_begin(&u.id, &sealed::cipher().seal(&sealed::mfa_context(&u.id), &secret)) {
        return Err(ApiError(StatusCode::CONFLICT, "Two-factor authentication is already on. Turn it off first to use another app.".into()));
    }
    Ok(no_store(Json(setup_view(&u, &secret)).into_response()))
}

/// A wrong code on a settings call: limited and audited like a sign-in's, as a refusal.
fn refuse(a: &Auth, by: &Who, u: &User, kind: &str, reason: &str, path: &str) -> ApiError {
    let at = db::now();
    a.limiter.fail(by.source.ip.as_deref().unwrap_or(""), at);
    a.mfa.limiter.fail(&u.id, at);
    a.record(by.event("access.denied").outcome(Outcome::Denied).details(json!({ "method": "POST", "path": path, "need": kind, "reason": reason })));
    ApiError(StatusCode::FORBIDDEN, "That code is wrong.".into())
}

fn not_blocked(a: &Auth, u: &User) -> Res<()> {
    match a.mfa.limiter.blocked(&u.id, db::now()) {
        Some(retry) => Err(ApiError(StatusCode::TOO_MANY_REQUESTS, format!("Too many wrong codes. Try again in {} minutes.", (retry + 59) / 60))),
        None => Ok(()),
    }
}

/// `POST /api/auth/mfa/confirm` `{totp}`: turns the pending secret on and returns the
/// recovery codes, once.
pub async fn confirm(State(app): State<AppState>, Extension(a): Extension<Arc<Auth>>, Extension(c): Extension<Caller>, Extension(by): Extension<Who>, Json(v): Json<Value>) -> Res<Response> {
    let u = person(&c)?;
    not_blocked(&a, &u)?;
    let code = v["totp"].as_str().ok_or_else(|| bad("Send the code your authenticator app shows (totp)."))?;
    let row = app.db.mfa(&u.id).filter(|m| m.confirmed_at.is_none()).ok_or_else(|| ApiError(StatusCode::CONFLICT, "Start setting up two-factor authentication first.".into()))?;
    let key = open_secret(&u.id, &row.secret).ok_or_else(|| ApiError(StatusCode::CONFLICT, "Start setting up two-factor authentication again.".into()))?;
    let step = matching_step(&key, code, db::now(), i64::MIN).ok_or_else(|| refuse(&a, &by, &u, "totp", "wrong_code", "/api/auth/mfa/confirm"))?;
    let codes = new_recovery_codes();
    if !app.db.mfa_confirm(&u.id, &row.secret, step, &recovery_hashes(&u.id, &codes)) {
        return Err(ApiError(StatusCode::CONFLICT, "Setup changed in the meantime. Start again.".into()));
    }
    a.record(by.event("user.mfa_enabled").target("user", &u.id).details(json!({ "via": "settings", "recoveryCodes": codes.len() })));
    let mut view = status_view(&a, &app, &u);
    view["recoveryCodes"] = json!(codes);
    Ok(no_store(Json(view).into_response()))
}

/// The second factor in `v`, checked and spent, for a settings change.
fn prove(a: &Auth, app: &AppState, by: &Who, u: &User, v: &Value, path: &str) -> Res<&'static str> {
    not_blocked(a, u)?;
    match check(&app.db, &u.id, v, db::now()) {
        Check::Ok(kind) => Ok(kind),
        Check::Wrong(kind, reason) => Err(refuse(a, by, u, kind, reason, path)),
        Check::Missing => Err(bad("Send a code from your authenticator app (totp), or a recovery code (recoveryCode).")),
    }
}

/// `POST /api/auth/mfa/recovery-codes` `{totp | recoveryCode}`: new recovery codes in
/// place of the old ones.
pub async fn new_recovery(State(app): State<AppState>, Extension(a): Extension<Arc<Auth>>, Extension(c): Extension<Caller>, Extension(by): Extension<Who>, Json(v): Json<Value>) -> Res<Response> {
    let u = person(&c)?;
    if !app.db.mfa(&u.id).is_some_and(|m| m.confirmed_at.is_some()) {
        return Err(ApiError(StatusCode::CONFLICT, "Two-factor authentication is off.".into()));
    }
    let with = prove(&a, &app, &by, &u, &v, "/api/auth/mfa/recovery-codes")?;
    let codes = new_recovery_codes();
    if !app.db.mfa_replace_recovery(&u.id, &recovery_hashes(&u.id, &codes)) {
        return Err(ApiError(StatusCode::CONFLICT, "Two-factor authentication is off.".into()));
    }
    a.record(by.event("user.mfa_recovery_codes_created").target("user", &u.id).details(json!({ "count": codes.len(), "provedWith": with })));
    let mut view = status_view(&a, &app, &u);
    view["recoveryCodes"] = json!(codes);
    Ok(no_store(Json(view).into_response()))
}

/// `POST /api/auth/mfa/disable` `{totp | recoveryCode}`: turns your second factor off,
/// unless the policy requires it for you. A setup not yet confirmed is dropped without a code.
pub async fn disable(State(app): State<AppState>, Extension(a): Extension<Arc<Auth>>, Extension(c): Extension<Caller>, Extension(by): Extension<Who>, Json(v): Json<Value>) -> Res {
    let u = person(&c)?;
    match app.db.mfa(&u.id) {
        None => return Ok(Json(status_view(&a, &app, &u))),
        Some(m) if m.confirmed_at.is_none() => {
            app.db.mfa_delete(&u.id);
            return Ok(Json(status_view(&a, &app, &u)));
        }
        Some(_) => {}
    }
    if policy(&a, &app.db).requires(&u) {
        return Err(ApiError(StatusCode::CONFLICT, "This server requires two-factor authentication for your account, so it stays on. An admin can reset it if you lose your app.".into()));
    }
    let with = prove(&a, &app, &by, &u, &v, "/api/auth/mfa/disable")?;
    if app.db.mfa_delete(&u.id) {
        a.record(by.event("user.mfa_disabled").target("user", &u.id).details(json!({ "by": "self", "provedWith": with })));
    }
    Ok(Json(status_view(&a, &app, &u)))
}

/// `PUT /api/auth/mfa/policy` `{require: "off" | "admins" | "all"}` (admin). Sessions
/// already open stay open; each person's next password or code sign-in follows it.
pub async fn put_policy(State(app): State<AppState>, Extension(a): Extension<Arc<Auth>>, Extension(c): Extension<Caller>, Extension(by): Extension<Who>, Json(v): Json<Value>) -> Res {
    let u = person(&c)?;
    let to = v["require"].as_str().and_then(Policy::parse).ok_or_else(|| bad("require must be off, admins, or all"))?;
    if a.mfa.pinned.is_some() {
        return Err(ApiError(StatusCode::CONFLICT, "AUTH_MFA in botd's environment sets this policy. Change it there and restart.".into()));
    }
    let from = policy(&a, &app.db);
    if from != to {
        app.db.set_setting(POLICY_KEY, to.as_str());
        a.record(by.event("auth.mfa_policy_updated").details(json!({ "from": from.as_str(), "to": to.as_str() })));
    }
    Ok(Json(status_view(&a, &app, &u)))
}

/// `DELETE /api/users/{key}/mfa` (admin): resets someone's second factor, e.g. after a
/// lost phone. If the policy requires one, they set it up again at their next sign-in.
/// Admins turn off their own in their settings, which needs a code.
pub async fn reset(State(app): State<AppState>, Extension(a): Extension<Arc<Auth>>, Extension(by): Extension<Who>, Path(key): Path<String>) -> Res {
    let u = users::need_user_key(&app, &key)?;
    if by.actor.id.as_deref() == Some(u.id.as_str()) {
        return Err(ApiError(StatusCode::CONFLICT, "Turn off your own two-factor authentication in your settings. Another admin can reset it.".into()));
    }
    a.mfa.forget_user(&u.id);
    let had = app.db.mfa_delete(&u.id);
    if had {
        a.record(by.event("user.mfa_disabled").target("user", &u.id).details(json!({ "by": "admin" })));
    }
    Ok(Json(json!({ "reset": had, "user": users::user_view(&u) })))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc6238_test_vectors() {
        // RFC 6238 appendix B, HMAC-SHA1 with the 20-byte ASCII key, 8 digits.
        let key = b"12345678901234567890";
        for (secs, want) in [(59i64, "94287082"), (1111111109, "07081804"), (1111111111, "14050471"), (1234567890, "89005924"), (2000000000, "69279037"), (20000000000, "65353130")] {
            assert_eq!(hotp(key, (secs / 30) as u64, 8), want, "{secs}");
        }
        // RFC 4226 appendix D, the HOTP values at counters 0 to 2.
        assert_eq!([0, 1, 2].map(|c| hotp(key, c, 6)), ["755224", "287082", "359152"]);
        assert_eq!(code_at(key, 59_000), "287082");
    }

    #[test]
    fn base32_and_links() {
        assert_eq!(base32(b"12345678901234567890"), "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
        assert_eq!(base32(b"f"), "MY");
        assert_eq!(base32(b"foobar"), "MZXW6YTBOI");
        assert_eq!(base32(&[0u8; 20]).len(), 32);
        let url = otpauth_url("ada lovelace@example.com", "GEZDGNBV");
        assert_eq!(url, "otpauth://totp/SuperBot:ada%20lovelace@example.com?secret=GEZDGNBV&issuer=SuperBot&algorithm=SHA1&digits=6&period=30");
        let svg = qr_svg(&url).unwrap();
        assert!(svg.starts_with("<svg") && svg.ends_with("</svg>") && !svg.contains("<?xml"), "{svg}");
    }

    #[test]
    fn codes_match_their_window_once() {
        let key = crate::random_bytes(SECRET_BYTES);
        let at = 1_800_000_000_000;
        let now = step_at(at);
        let code = code_at(&key, at);
        assert_eq!(matching_step(&key, &code, at, 0), Some(now));
        assert_eq!(matching_step(&key, &format!(" {} {} ", &code[..3], &code[3..]), at, 0), Some(now), "spaces are fine");
        assert_eq!(matching_step(&key, &code, at + STEP_MS, 0), Some(now), "a step late");
        assert_eq!(matching_step(&key, &code, at - STEP_MS, 0), Some(now), "a step early");
        assert_eq!(matching_step(&key, &code, at + 2 * STEP_MS, 0), None, "too late");
        assert_eq!(matching_step(&key, &code, at, now), None, "a step already used");
        assert_eq!(matching_step(&key, &code_at(&key, at - STEP_MS), at, now - 1), None, "an earlier step after a later one");
        for junk in ["", "12345", "1234567", "abcdef", "12345a", "１２３４５６"] {
            assert_eq!(matching_step(&key, junk, at, 0), None, "{junk}");
        }
    }

    #[test]
    fn recovery_codes_are_random_and_normalized() {
        let codes = new_recovery_codes();
        assert_eq!(codes.len(), RECOVERY_CODES);
        for c in &codes {
            assert_eq!(c.len(), RECOVERY_LEN + 1, "{c}");
            assert_eq!(c.as_bytes()[5], b'-');
            assert_eq!(normalize_recovery(&c.to_ascii_uppercase().replace('-', " ")), normalize_recovery(c));
        }
        let mut sorted = codes.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), RECOVERY_CODES);
        assert_eq!(normalize_recovery("abcde-fghij").as_deref(), Some("abcdefghij"));
        for bad in ["", "abcde-fghi", "abcde-fghij1", "abcde-fgh1j", "abcde-fgh0j", "abcde_fghij"] {
            assert_eq!(normalize_recovery(bad), None, "{bad}");
        }
        let h = recovery_hash("u1", "abcdefghij");
        assert_eq!(h.len(), 64);
        assert_ne!(h, recovery_hash("u2", "abcdefghij"), "bound to the user");
        assert_ne!(h, users::hash("u1:abcdefghij"), "keyed, not a plain hash");
    }

    #[test]
    fn policy_parses_and_decides() {
        assert_eq!(policy_flag(""), Ok(None));
        assert_eq!(policy_flag(" Admins "), Ok(Some(Policy::Admins)));
        assert_eq!(policy_flag("all"), Ok(Some(Policy::All)));
        assert_eq!(policy_flag("off"), Ok(Some(Policy::Off)));
        assert!(policy_flag("sometimes").is_err());
        let db = db::Db::open(&db::temp_path("mfa-policy").join("app.sqlite")).unwrap();
        let owner = users::ensure_operator(&db, "Owner", None);
        let admin = db.create_user(None, Some("a@example.com"), "A", Role::Admin).unwrap();
        let member = db.create_user(None, Some("m@example.com"), "M", Role::Member).unwrap();
        assert_eq!([&owner, &admin, &member].map(|u| Policy::Admins.requires(u)), [true, true, false]);
        assert_eq!([&owner, &admin, &member].map(|u| Policy::All.requires(u)), [true, true, true]);
        assert_eq!([&owner, &admin, &member].map(|u| Policy::Off.requires(u)), [false, false, false]);
    }

    #[test]
    fn challenges_expire_run_out_and_end() {
        let m = Mfa::default();
        let at = db::now();
        let p = |exp: i64| Pending { user_id: "u1".into(), method: "code", expires_at: exp, tries: 0, enroll: None };
        let c = m.start(p(at + CHALLENGE_TTL_MS));
        assert!(c.starts_with(CHALLENGE_PREFIX) && c.len() == 4 + 64);
        assert!(m.live(&c, at).is_some());
        assert!(m.live(&c.replace("sbm_", "sbs_"), at).is_none());
        assert!(m.live(&c, at + CHALLENGE_TTL_MS).is_none(), "expired");
        assert!(m.live(&c, at).is_none(), "and gone");
        let c = m.start(p(at + CHALLENGE_TTL_MS));
        for _ in 1..CHALLENGE_TRIES {
            assert!(!m.wrong(&c));
        }
        assert!(m.wrong(&c), "the last try");
        assert!(m.live(&c, at).is_none());
        let c = m.start(p(at + CHALLENGE_TTL_MS));
        m.forget_user("u2");
        assert!(m.live(&c, at).is_some());
        m.forget_user("u1");
        assert!(m.live(&c, at).is_none());
    }

    #[test]
    fn secrets_and_recovery_codes_live_sealed_in_the_database() {
        let path = db::temp_path("mfa-db").join("app.sqlite");
        let db = db::Db::open(&path).unwrap();
        let u = db.create_user(None, Some("s@example.com"), "S", Role::Member).unwrap();
        let key = crate::random_bytes(SECRET_BYTES);
        let b32 = base32(&key);
        let sealed_secret = sealed::cipher().seal(&sealed::mfa_context(&u.id), &key);
        assert!(db.mfa_begin(&u.id, &sealed_secret));
        let row = db.mfa(&u.id).unwrap();
        assert!(row.confirmed_at.is_none() && row.secret.starts_with(sealed::PREFIX));
        assert_eq!(open_secret(&u.id, &row.secret).unwrap().as_slice(), key.as_slice());
        assert!(open_secret("someone-else", &row.secret).is_none(), "bound to its user");
        let codes = new_recovery_codes();
        assert!(!db.mfa_confirm(&u.id, "sb1:other", 5, &recovery_hashes(&u.id, &codes)), "only the secret that was checked");
        assert!(db.mfa_confirm(&u.id, &sealed_secret, 5, &recovery_hashes(&u.id, &codes)));
        assert!(!db.mfa_begin(&u.id, &sealed_secret), "on: turn it off first");
        assert!(!db.mfa_use_step(&u.id, 5) && db.mfa_use_step(&u.id, 6) && !db.mfa_use_step(&u.id, 6));
        assert_eq!(db.mfa_recovery_left(&u.id), RECOVERY_CODES as i64);
        let code = normalize_recovery(&codes[0]).unwrap();
        assert!(db.mfa_use_recovery(&u.id, &recovery_hash(&u.id, &code)));
        assert!(!db.mfa_use_recovery(&u.id, &recovery_hash(&u.id, &code)), "once");
        assert_eq!(db.mfa_recovery_left(&u.id), RECOVERY_CODES as i64 - 1);
        assert_eq!(db.mfa_enabled().keys().collect::<Vec<_>>(), [&u.id]);
        drop(db);
        let mut raw = std::fs::read(&path).unwrap();
        raw.extend(std::fs::read(path.with_extension("sqlite-wal")).unwrap_or_default());
        let has = |s: &str| raw.windows(s.len()).any(|w| w == s.as_bytes());
        assert!(!has(&b32) && !raw.windows(key.len()).any(|w| w == key.as_slice()), "the secret is never on disk in the clear");
        assert!(codes.iter().all(|c| !has(c) && !has(&normalize_recovery(c).unwrap())), "nor are recovery codes");
        let db = db::Db::open(&path).unwrap();
        assert!(db.mfa_delete(&u.id) && db.mfa(&u.id).is_none() && db.mfa_recovery_left(&u.id) == 0);
        assert!(!db.mfa_delete(&u.id));
    }
}
