//! Self-host license key (ADR 0038). A license is a JWT CG-Labs signs with Ed25519,
//! checked offline against the public keys below. It names the licensee, an edition, the
//! seats (active users) it covers, features, and when it ends.
//!
//! Nothing here stops a server. Without a license, or with one that is invalid or long
//! expired, botd runs as the community edition: every feature works, for up to
//! [`COMMUNITY_SEATS`] active users. A license that has just ended keeps its seats for
//! [`GRACE_DAYS`] more. Over the limit, nobody is signed out or disabled; adding or
//! re-enabling people is refused until a seat is free. The owner (break-glass) account
//! never takes a seat.
//!
//! The key comes from `LICENSE_KEY` or `LICENSE_KEY_FILE` (which win, as other settings
//! from the environment do), else `DATA_DIR/license.key`, which admins set with
//! `PUT /api/license` (the console, the setup wizard, `botctl license install`) or the
//! installer's `--license-file`.

// botd only verifies; the signing half is for superbot-license, and tests.
#[allow(dead_code)]
pub mod token;

use crate::audit::{Actor, Event, Outcome, Who};
use crate::db::{self, Db};
use crate::{ApiError, AppState, Res};
use axum::extract::{Extension, State};
use axum::http::StatusCode;
use axum::Json;
use serde::Serialize;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, RwLock};
pub use token::{Claims, Invalid, Key};

/// Active users a server without a valid license may have, the owner account aside.
pub const COMMUNITY_SEATS: u32 = 10;
/// Days an ended license keeps its seats and features, so a late renewal breaks nothing.
pub const GRACE_DAYS: i64 = 14;
/// Admins are warned this many days before a license ends.
pub const WARN_DAYS: i64 = 30;
/// The license in `DATA_DIR`, as `PUT /api/license` writes it.
pub const FILE: &str = "license.key";
const DAY_MS: i64 = 86_400_000;
const SEEN: &str = "license_seen";

/// CG-Labs's license signing keys: `(kid, Ed25519 public key in unpadded base64url)`, as
/// `superbot-license keygen` prints them. Public halves only; the private keys never
/// enter this repository. Keep old keys listed until every license they signed has ended.
const TRUSTED: &[(&str, &str)] = &[];

/// The keys licenses are checked against: [`TRUSTED`], and in tests a test key.
pub fn trusted() -> Vec<Key> {
    let keys = TRUSTED.iter().map(|(kid, public)| Key::parse(kid, public).expect("a built-in license key"));
    #[cfg(test)]
    let keys = keys.chain([test_keys::key()]);
    keys.collect()
}

/// Where the license came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Source {
    None,
    /// `LICENSE_KEY`.
    Env,
    /// `LICENSE_KEY_FILE`.
    EnvFile,
    /// `DATA_DIR/license.key`.
    File,
}

impl Source {
    fn from_env(self) -> bool {
        matches!(self, Source::Env | Source::EnvFile)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    /// No license: the community edition.
    Community,
    Active,
    /// Ended less than [`GRACE_DAYS`] ago: still honoured.
    Grace,
    /// Ended longer ago: the community edition again.
    Expired,
    /// Set, but not a license this server accepts: the community edition.
    Invalid,
}

/// Why the configured key isn't a license: its token's problem, or the setting's.
#[derive(Clone, Debug, PartialEq)]
pub struct Problem {
    pub code: &'static str,
    pub text: String,
}

impl From<Invalid> for Problem {
    fn from(e: Invalid) -> Problem {
        Problem { code: e.code(), text: e.text().into() }
    }
}

#[derive(Clone)]
struct Loaded {
    source: Source,
    /// The token, when one was read. Never shown or logged.
    token: Option<String>,
    license: Option<Result<Claims, Problem>>,
}

impl Loaded {
    fn none() -> Loaded {
        Loaded { source: Source::None, token: None, license: None }
    }
}

/// The license now, as everything that enforces it reads it.
#[derive(Clone, Debug)]
pub struct Status {
    pub mode: Mode,
    pub source: Source,
    pub claims: Option<Claims>,
    pub problem: Option<Problem>,
    pub at: i64,
}

fn date(ms: i64) -> String {
    chrono::DateTime::from_timestamp_millis(ms).unwrap_or_default().format("%Y-%m-%d").to_string()
}

impl Status {
    /// The license's seats and features count.
    pub fn licensed(&self) -> bool {
        matches!(self.mode, Mode::Active | Mode::Grace)
    }

    fn honoured(&self) -> Option<&Claims> {
        self.claims.as_ref().filter(|_| self.licensed())
    }

    /// Active users allowed now, the owner aside. None: unlimited. A license never
    /// allows fewer than the community edition.
    pub fn seat_cap(&self) -> Option<u32> {
        match self.honoured() {
            Some(c) => c.seats.map(|s| s.max(COMMUNITY_SEATS)),
            None => Some(COMMUNITY_SEATS),
        }
    }

    pub fn edition(&self) -> &str {
        self.honoured().map_or("community", |c| c.edition.as_str())
    }

    /// For paid modules: whether the license grants `feature` now.
    #[allow(dead_code)]
    pub fn allows(&self, feature: &str) -> bool {
        self.honoured().is_some_and(|c| c.features.iter().any(|f| f == feature))
    }

    pub fn expires_at(&self) -> Option<i64> {
        self.claims.as_ref().map(|c| c.exp * 1000)
    }

    pub fn grace_ends_at(&self) -> Option<i64> {
        self.expires_at().map(|e| e + GRACE_DAYS * DAY_MS)
    }

    /// What the audit log keeps of it: never the token.
    pub fn summary(&self) -> Value {
        let mut v = json!({ "mode": self.mode, "source": self.source, "edition": self.edition(), "seats": self.seat_cap() });
        if let Some(c) = &self.claims {
            v["id"] = json!(c.jti);
            v["licensee"] = json!(c.sub);
            v["expiresAt"] = json!(c.exp * 1000);
        }
        if let Some(p) = &self.problem {
            v["error"] = json!(p.code);
        }
        v
    }

    /// Changes when the license or its mode does; kept to audit changes once.
    fn marker(&self) -> String {
        match (&self.claims, &self.problem) {
            (Some(c), _) => format!("{:?}:{}", self.mode, c.jti).to_lowercase(),
            (None, Some(p)) => format!("invalid:{}", p.code),
            (None, None) => "community".into(),
        }
    }

    /// One sentence for admins.
    pub fn detail(&self) -> String {
        let community = format!("the community edition, free for up to {COMMUNITY_SEATS} active users");
        let seats = |c: &Claims| c.seats.map_or("unlimited seats".to_string(), |s| format!("{s} seat{}", if s == 1 { "" } else { "s" }));
        match (self.mode, &self.claims) {
            (Mode::Community, _) => format!("No license: {community}. Every feature works."),
            (Mode::Active, Some(c)) => format!("Licensed to {} ({}, {}) until {}.", c.sub, c.edition, seats(c), date(c.exp * 1000)),
            (Mode::Grace, Some(c)) => format!(
                "The license for {} ended on {}. It keeps working until {}; install the renewed key before then, or the server becomes {community}.",
                c.sub,
                date(c.exp * 1000),
                date(self.grace_ends_at().unwrap_or_default())
            ),
            (Mode::Expired, Some(c)) => format!("The license for {} ended on {}. Running as {community}.", c.sub, date(c.exp * 1000)),
            _ => format!("The license key isn't valid ({}). Running as {community}.", self.problem.as_ref().map_or("unknown", |p| p.code)),
        }
    }

    /// Things an admin should act on, given `used` seats.
    pub fn warnings(&self, used: u32) -> Vec<String> {
        let mut w = Vec::new();
        if let (Mode::Active, Some(exp)) = (self.mode, self.expires_at())
            && exp - self.at < WARN_DAYS * DAY_MS
        {
            w.push(format!("The license ends on {}. Ask CG-Labs for the renewed key.", date(exp)));
        }
        if matches!(self.mode, Mode::Grace | Mode::Expired | Mode::Invalid) {
            w.push(self.detail());
        }
        if let Some(cap) = self.seat_cap()
            && used > cap
        {
            w.push(format!("{used} people are active, over the {cap} seats allowed. Nobody is locked out, but nobody can be added or re-enabled until fewer than {cap} are active."));
        }
        w
    }

    /// The refusal people see when no seat is free.
    pub fn seat_error(&self, used: u32) -> String {
        let cap = self.seat_cap().unwrap_or(u32::MAX);
        match self.honoured() {
            Some(c) => format!("No seats left: the license for {} covers {cap} active users, and {used} are active. Disable someone, or ask CG-Labs for more seats.", c.sub),
            None => format!(
                "No seats left: without a license, SuperBot is free for up to {cap} active users, and {used} are active. Disable someone, or install a license key (console Settings, or botctl license install)."
            ),
        }
    }

    pub fn view(&self, used: u32) -> Value {
        let license = self.claims.as_ref().map(|c| {
            json!({
                "id": c.jti, "licensee": c.sub, "edition": c.edition, "seats": c.seats, "features": c.features,
                "issuedAt": c.iat * 1000, "startsAt": c.nbf.map(|n| n * 1000), "expiresAt": c.exp * 1000, "graceEndsAt": self.grace_ends_at(),
            })
        });
        let cap = self.seat_cap();
        json!({
            "mode": self.mode,
            "licensed": self.licensed(),
            "edition": self.edition(),
            "features": self.honoured().map_or(&[][..], |c| c.features.as_slice()),
            "source": self.source,
            "savable": !self.source.from_env(),
            "license": license,
            "error": self.problem.as_ref().map(|p| p.code),
            "problem": self.problem.as_ref().map(|p| p.text.clone()),
            "seats": { "limit": cap, "used": used, "available": cap.map(|c| c.saturating_sub(used)), "community": COMMUNITY_SEATS },
            "ok": matches!(self.mode, Mode::Community | Mode::Active),
            "detail": self.detail(),
            "warnings": self.warnings(used),
            "graceDays": GRACE_DAYS,
        })
    }
}

/// Why an admin's change didn't happen.
#[derive(Debug, PartialEq)]
pub enum ChangeError {
    /// `LICENSE_KEY` or `LICENSE_KEY_FILE` sets it; that wins.
    FromEnv,
    Invalid(Invalid),
    /// Ended on this date (ms).
    Expired(i64),
    NotInstalled,
    Io(String),
}

pub struct Licensing {
    keys: Vec<Key>,
    /// `DATA_DIR/license.key`.
    path: PathBuf,
    loaded: RwLock<Loaded>,
    /// Installs, removals, and the status-change check, one at a time: each reads, writes,
    /// and audits together.
    changing: Mutex<()>,
}

fn read_capped(path: &Path) -> std::io::Result<String> {
    use std::io::Read;
    let mut s = String::new();
    std::fs::File::open(path)?.take(token::MAX_TOKEN as u64 + 1).read_to_string(&mut s)?;
    Ok(s)
}

impl Licensing {
    /// Nothing loaded yet: the community edition.
    pub fn new(keys: Vec<Key>, data_dir: &Path) -> Licensing {
        Licensing { keys, path: data_dir.join(FILE), loaded: RwLock::new(Loaded::none()), changing: Mutex::new(()) }
    }

    fn check(&self, t: &str, now_ms: i64) -> Result<Claims, Invalid> {
        token::verify(t, &self.keys, now_ms / 1000)
    }

    fn loaded_from(&self, source: Source, raw: std::io::Result<String>) -> Loaded {
        match raw {
            Ok(t) if t.trim().is_empty() && source == Source::File => Loaded::none(),
            Ok(t) => {
                let t = t.trim().to_string();
                let license = Some(self.check(&t, db::now()).map_err(Problem::from));
                Loaded { source, token: Some(t), license }
            }
            Err(e) if source == Source::File && e.kind() == std::io::ErrorKind::NotFound => Loaded::none(),
            Err(e) => Loaded { source, token: None, license: Some(Err(Problem { code: "unreadable", text: format!("The license key file can't be read: {e}") })) },
        }
    }

    /// Reads `LICENSE_KEY`, else `LICENSE_KEY_FILE`, else `DATA_DIR/license.key`. Never
    /// fails: a bad key is reported, and the server runs as the community edition.
    pub fn load(&self, get: impl Fn(&str) -> String) {
        let (inline, file) = (get("LICENSE_KEY"), get("LICENSE_KEY_FILE"));
        let (inline, file) = (inline.trim(), file.trim());
        let loaded = match (inline.is_empty(), file.is_empty()) {
            (false, false) => Loaded {
                source: Source::Env,
                token: None,
                license: Some(Err(Problem { code: "ambiguous", text: "Both LICENSE_KEY and LICENSE_KEY_FILE are set. Keep one.".into() })),
            },
            (false, true) => self.loaded_from(Source::Env, Ok(inline.to_string())),
            (true, false) => self.loaded_from(Source::EnvFile, read_capped(Path::new(file))),
            (true, true) => self.loaded_from(Source::File, read_capped(&self.path)),
        };
        *self.loaded.write().unwrap_or_else(|e| e.into_inner()) = loaded;
    }

    pub fn status(&self) -> Status {
        self.status_at(db::now())
    }

    pub fn status_at(&self, now_ms: i64) -> Status {
        let l = self.loaded.read().unwrap_or_else(|e| e.into_inner());
        let (mode, claims, problem) = match &l.license {
            None => (Mode::Community, None, None),
            Some(Err(p)) => (Mode::Invalid, None, Some(p.clone())),
            Some(Ok(c)) => {
                let exp = c.exp * 1000;
                let mode = if now_ms < exp {
                    Mode::Active
                } else if now_ms < exp + GRACE_DAYS * DAY_MS {
                    Mode::Grace
                } else {
                    Mode::Expired
                };
                (mode, Some(c.clone()), None)
            }
        };
        Status { mode, source: l.source, claims, problem, at: now_ms }
    }

    pub fn seat_cap(&self) -> Option<u32> {
        self.status().seat_cap()
    }

    /// Saves `key` as this server's license and audits it. Refuses keys that aren't a
    /// license or have ended, and any change while the environment sets the license.
    pub fn install(&self, db: &Db, by: &Who, key: &str) -> Result<Status, ChangeError> {
        let _one = self.changing.lock().unwrap_or_else(|e| e.into_inner());
        let before = self.status();
        let refuse = |reason: &str, extra: Value| {
            let mut d = json!({ "reason": reason, "kid": token::kid_of(key) });
            if let (Some(o), Value::Object(e)) = (d.as_object_mut(), extra) {
                o.extend(e);
            }
            db.record(&by.event("license.refused").target("license", "server").outcome(Outcome::Failure).details(d));
        };
        if before.source.from_env() {
            refuse("set_in_env", json!({}));
            return Err(ChangeError::FromEnv);
        }
        let now = db::now();
        let claims = self.check(key, now).map_err(|e| {
            refuse(e.code(), json!({}));
            ChangeError::Invalid(e)
        })?;
        if claims.exp * 1000 <= now {
            refuse("expired", json!({ "id": claims.jti, "expiresAt": claims.exp * 1000 }));
            return Err(ChangeError::Expired(claims.exp * 1000));
        }
        let key = key.trim();
        let same = self.loaded.read().unwrap_or_else(|e| e.into_inner()).token.as_deref() == Some(key);
        if !same {
            write_private(&self.path, key).map_err(|e| ChangeError::Io(e.to_string()))?;
            *self.loaded.write().unwrap_or_else(|e| e.into_inner()) = Loaded { source: Source::File, token: Some(key.into()), license: Some(Ok(claims.clone())) };
            let after = self.status();
            db.record(&by.event("license.installed").target("license", &claims.jti).details(json!({ "from": changed_from(&before), "to": after.summary() })));
            db.set_setting(SEEN, &after.marker());
        }
        Ok(self.status())
    }

    /// Deletes `DATA_DIR/license.key`: the community edition again. Audited.
    pub fn remove(&self, db: &Db, by: &Who) -> Result<Status, ChangeError> {
        let _one = self.changing.lock().unwrap_or_else(|e| e.into_inner());
        let before = self.status();
        if before.source.from_env() {
            return Err(ChangeError::FromEnv);
        }
        match std::fs::remove_file(&self.path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound && before.source == Source::None => return Err(ChangeError::NotInstalled),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(ChangeError::Io(e.to_string())),
        }
        *self.loaded.write().unwrap_or_else(|e| e.into_inner()) = Loaded::none();
        let target = before.claims.as_ref().map_or("server", |c| c.jti.as_str());
        db.record(&by.event("license.removed").target("license", target).details(json!({ "from": before.summary() })));
        let after = self.status();
        db.set_setting(SEEN, &after.marker());
        Ok(after)
    }

    /// Audits a change nobody made through the API: a new key in the environment, a
    /// license entering its grace period or ending, a key that stopped verifying. Once
    /// per change, across restarts. A server that never had a license records nothing.
    pub fn observe(&self, db: &Db) {
        let _one = self.changing.lock().unwrap_or_else(|e| e.into_inner());
        let now = self.status();
        let mark = now.marker();
        let seen = db.setting(SEEN);
        if seen.as_deref() == Some(mark.as_str()) {
            return;
        }
        db.set_setting(SEEN, &mark);
        if seen.is_none() && now.mode == Mode::Community {
            return;
        }
        let target = now.claims.as_ref().map_or("server", |c| c.jti.as_str());
        let outcome = if now.licensed() || now.mode == Mode::Community { Outcome::Success } else { Outcome::Failure };
        db.record(&Event::new(Actor::system("license"), "license.status_changed").target("license", target).outcome(outcome).details(json!({ "from": seen, "to": now.summary() })));
    }
}

fn changed_from(before: &Status) -> Value {
    if before.mode == Mode::Community { Value::Null } else { before.summary() }
}

/// Written whole or not at all, readable by botd's user only.
fn write_private(path: &Path, contents: &str) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let tmp = path.with_extension(format!("tmp-{}", crate::short_id()));
    let res = (|| {
        let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&tmp)?;
        f.write_all(contents.as_bytes())?;
        f.write_all(b"\n")?;
        f.sync_all()?;
        std::fs::rename(&tmp, path)
    })();
    if res.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    res
}

/// Checks for status changes now and every 10 minutes, so a license ending is audited
/// even on a server nobody is using.
pub fn start(app: AppState) {
    app.license.observe(&app.db);
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(600));
        tick.tick().await;
        loop {
            tick.tick().await;
            app.license.observe(&app.db);
        }
    });
}

/// The 403 for a person who'd need a seat, and its audit event. `via` says how they
/// were being added: admin, enable, signup, sso, or scim.
pub fn refuse_seat(app: &AppState, who: &Who, via: &str, target: Option<&str>, email: Option<&str>) -> String {
    let s = app.license.status();
    let used = app.db.active_seats();
    let ev = who.event("license.seat_refused").outcome(Outcome::Denied);
    let ev = match target {
        Some(id) => ev.target("user", id),
        None => ev,
    };
    app.db.record(&ev.details(json!({ "via": via, "email": email, "used": used, "limit": s.seat_cap(), "mode": s.mode, "edition": s.edition() })));
    s.seat_error(used)
}

// HTTP (admins only: these fall into RBAC's default arm).

/// `GET /api/license`: the license, its mode, and the seats in use. Never the key.
pub async fn get(State(app): State<AppState>) -> Json<Value> {
    Json(app.license.status().view(app.db.active_seats()))
}

fn change_error(e: ChangeError) -> ApiError {
    match e {
        ChangeError::FromEnv => ApiError(
            StatusCode::CONFLICT,
            "botd's environment sets the license (LICENSE_KEY or LICENSE_KEY_FILE), and that wins. Change it in .env and restart botd.".into(),
        ),
        ChangeError::Invalid(i) => ApiError(StatusCode::BAD_REQUEST, i.text().into()),
        ChangeError::Expired(at) => ApiError(StatusCode::BAD_REQUEST, format!("This license ended on {}. Ask CG-Labs for the renewed key.", date(at))),
        ChangeError::NotInstalled => ApiError(StatusCode::NOT_FOUND, "No license is installed.".into()),
        ChangeError::Io(e) => ApiError(StatusCode::INTERNAL_SERVER_ERROR, format!("Couldn't save the license: {e}")),
    }
}

/// `PUT /api/license {key}`: checks the key and saves it to `DATA_DIR/license.key`.
pub async fn put(State(app): State<AppState>, Extension(by): Extension<Who>, Json(v): Json<Value>) -> Res {
    let key = v.get("key").and_then(Value::as_str).map(str::trim).filter(|k| !k.is_empty()).ok_or_else(|| crate::bad("Send {\"key\": \"<license key>\"}."))?;
    let s = app.license.install(&app.db, &by, key).map_err(change_error)?;
    Ok(Json(s.view(app.db.active_seats())))
}

/// `DELETE /api/license`: back to the community edition.
pub async fn delete(State(app): State<AppState>, Extension(by): Extension<Who>) -> Res {
    let s = app.license.remove(&app.db, &by).map_err(change_error)?;
    Ok(Json(s.view(app.db.active_seats())))
}

#[cfg(test)]
pub mod test_keys {
    //! A fixed key pair the test build trusts, and one it doesn't. Release builds trust
    //! only [`super::TRUSTED`].

    use super::token::{self, Claims, Key};
    use aws_lc_rs::signature::Ed25519KeyPair;

    pub const KID: &str = "test";

    pub fn signer() -> Ed25519KeyPair {
        Ed25519KeyPair::from_seed_unchecked(&[7; 32]).unwrap()
    }

    /// Signs as `test` too, but isn't the trusted test key.
    pub fn stranger() -> Ed25519KeyPair {
        Ed25519KeyPair::from_seed_unchecked(&[9; 32]).unwrap()
    }

    pub fn key() -> Key {
        Key::parse(KID, &token::public_b64(&signer())).unwrap()
    }

    /// A license for `seats`, ending `days` from now (negative: ended that long ago).
    pub fn claims(seats: Option<u32>, days: i64) -> Claims {
        let now = crate::db::now() / 1000;
        let exp = now + days * 86_400;
        Claims {
            iss: token::ISSUER.into(),
            aud: token::AUDIENCE.into(),
            sub: "Acme Ltd".into(),
            jti: format!("lic-{}", crate::short_id()),
            iat: exp.min(now) - 400 * 86_400,
            nbf: None,
            exp,
            seats,
            edition: "business".into(),
            features: vec!["sso".into(), "scim".into()],
        }
    }

    pub fn mint(c: &Claims) -> String {
        token::sign(&signer(), KID, c).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::test_keys::*;
    use super::token::*;
    use super::*;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
    use base64::Engine;

    fn lic(dir: &str) -> Licensing {
        let d = crate::db::temp_path(dir);
        std::fs::create_dir_all(&d).unwrap();
        Licensing::new(trusted(), &d)
    }

    fn env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> String {
        let m: std::collections::HashMap<String, String> = pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        move |k| m.get(k).cloned().unwrap_or_default()
    }

    #[test]
    fn a_signed_license_verifies_and_round_trips() {
        let c = claims(Some(25), 365);
        let t = mint(&c);
        assert_eq!(t.split('.').count(), 3);
        let got = verify(&t, &trusted(), crate::db::now() / 1000).unwrap();
        assert_eq!(got, c);
        assert_eq!(kid_of(&t).as_deref(), Some(KID));
        // Surrounding whitespace, as pasted from an email, is fine.
        assert!(verify(&format!("  {t}\n"), &trusted(), crate::db::now() / 1000).is_ok());
    }

    #[test]
    fn tampered_wrong_key_and_odd_tokens_are_refused() {
        let now = crate::db::now() / 1000;
        let c = claims(Some(25), 365);
        let t = mint(&c);
        let (head, rest) = t.split_once('.').unwrap();
        let (_, sig) = rest.split_once('.').unwrap();
        // More seats, same signature.
        let mut more = c.clone();
        more.seats = Some(5000);
        let tampered = format!("{head}.{}.{sig}", B64.encode(serde_json::to_string(&more).unwrap()));
        assert_eq!(verify(&tampered, &trusted(), now), Err(Invalid::BadSignature));
        // Signed by a key that claims to be the trusted one.
        assert_eq!(verify(&sign(&stranger(), KID, &c).unwrap(), &trusted(), now), Err(Invalid::BadSignature));
        // A key nobody trusts.
        assert_eq!(verify(&sign(&stranger(), "cg-2099", &c).unwrap(), &trusted(), now), Err(Invalid::UnknownKey));
        // Other algorithms, no kid, crit, junk.
        let payload = B64.encode(serde_json::to_string(&c).unwrap());
        for h in [r#"{"alg":"none","kid":"test"}"#, r#"{"alg":"HS256","kid":"test"}"#, r#"{"alg":"RS256","kid":"test"}"#, r#"{"alg":"EdDSA","kid":"test","crit":["x"]}"#] {
            assert_eq!(verify(&format!("{}.{payload}.{sig}", B64.encode(h)), &trusted(), now), Err(Invalid::BadAlgorithm), "{h}");
        }
        assert_eq!(verify(&format!("{}.{payload}.{sig}", B64.encode(r#"{"alg":"EdDSA"}"#)), &trusted(), now), Err(Invalid::UnknownKey));
        for junk in ["", "a.b", "a.b.c.d", "!!.!!.!!", &"x".repeat(MAX_TOKEN + 1)] {
            assert!(verify(junk, &trusted(), now).is_err(), "{junk}");
        }
        assert!(verify(&format!("{t}x"), &trusted(), now).is_err());
    }

    #[test]
    fn claims_are_checked_before_signing_and_after_verifying() {
        let now = crate::db::now() / 1000;
        let with = |f: &dyn Fn(&mut Claims)| {
            let mut c = claims(Some(5), 30);
            f(&mut c);
            c
        };
        for bad in [
            with(&|c| c.aud = "superbot-managed".into()),
            with(&|c| c.sub = " ".into()),
            with(&|c| c.jti = "Has Spaces".into()),
            with(&|c| c.edition = "".into()),
            with(&|c| c.seats = Some(0)),
            with(&|c| c.exp = c.iat),
            with(&|c| c.features = vec!["Not OK".into()]),
        ] {
            assert!(sign(&signer(), KID, &bad).is_err(), "{bad:?}");
        }
        // Signed by hand anyway: still refused, and the audience is its own error.
        let raw = |c: &Claims| {
            let signed = format!("{}.{}", B64.encode(r#"{"alg":"EdDSA","kid":"test"}"#), B64.encode(serde_json::to_string(c).unwrap()));
            format!("{signed}.{}", B64.encode(signer().sign(signed.as_bytes()).as_ref()))
        };
        assert_eq!(verify(&raw(&with(&|c| c.aud = "other".into())), &trusted(), now), Err(Invalid::WrongAudience));
        assert_eq!(verify(&raw(&with(&|c| c.seats = Some(0))), &trusted(), now), Err(Invalid::BadClaims));
        let not_json = format!("{}.{}", B64.encode(r#"{"alg":"EdDSA","kid":"test"}"#), B64.encode(r#"{"sub":"x"}"#));
        let signed = format!("{not_json}.{}", B64.encode(signer().sign(not_json.as_bytes()).as_ref()));
        assert_eq!(verify(&signed, &trusted(), now), Err(Invalid::BadClaims));
        // Starts next week.
        let later = with(&|c| c.nbf = Some(now + 7 * 86_400));
        assert_eq!(verify(&mint(&later), &trusted(), now), Err(Invalid::NotYetValid));
        // Claims we don't know yet are ignored, so older servers read newer licenses.
        let mut v = serde_json::to_value(claims(None, 30)).unwrap();
        v["support"] = json!("24x7");
        let c: Claims = serde_json::from_value(v).unwrap();
        assert_eq!(c.seats, None);
    }

    #[test]
    fn keys_and_pem_files_round_trip() {
        let pem = generate_pem().unwrap();
        assert!(pem.starts_with("-----BEGIN PRIVATE KEY-----\n"), "{pem}");
        let k = key_from_pem(&pem).unwrap();
        let public = public_b64(&k);
        let trusted = [Key::parse("cg-1", &public).unwrap()];
        let c = claims(Some(3), 10);
        assert_eq!(verify(&sign(&k, "cg-1", &c).unwrap(), &trusted, crate::db::now() / 1000).unwrap(), c);
        assert!(key_from_pem("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----").is_err());
        assert!(key_from_pem("ssh-ed25519 AAAA").is_err());
        assert!(Key::parse("x", "AAAA").is_err(), "32 bytes or nothing");
        // Release builds trust only the built-in keys; the test key is test-only.
        assert!(TRUSTED.iter().all(|(kid, _)| *kid != KID));
    }

    #[test]
    fn modes_follow_the_clock_and_seats_follow_the_mode() {
        let l = lic("lic-modes");
        assert_eq!(l.status().mode, Mode::Community);
        assert_eq!(l.seat_cap(), Some(COMMUNITY_SEATS));
        assert_eq!(l.status().edition(), "community");

        let c = claims(Some(50), 20);
        l.load(env(&[("LICENSE_KEY", &mint(&c))]));
        let exp = c.exp * 1000;
        let at = |ms: i64| l.status_at(ms);
        assert_eq!((at(exp - 1).mode, at(exp - 1).seat_cap()), (Mode::Active, Some(50)));
        assert!(at(exp - 1).warnings(3)[0].contains("ends on"), "warned before it ends");
        assert!(at(exp - 40 * DAY_MS).warnings(3).is_empty());
        assert!(at(exp - 1).allows("scim") && !at(exp - 1).allows("white-label"));
        // Ended: still honoured during the grace period.
        assert_eq!((at(exp).mode, at(exp).seat_cap()), (Mode::Grace, Some(50)));
        assert!(at(exp + GRACE_DAYS * DAY_MS - 1).licensed());
        // Then the community edition, and the license's features are gone.
        let gone = at(exp + GRACE_DAYS * DAY_MS);
        assert_eq!((gone.mode, gone.seat_cap(), gone.edition(), gone.allows("scim")), (Mode::Expired, Some(COMMUNITY_SEATS), "community", false));
        assert!(gone.seat_error(10).contains("without a license"));
        // Unlimited seats, and never fewer than the community edition.
        l.load(env(&[("LICENSE_KEY", &mint(&claims(None, 20)))]));
        assert_eq!(l.seat_cap(), None);
        l.load(env(&[("LICENSE_KEY", &mint(&claims(Some(3), 20)))]));
        assert_eq!(l.seat_cap(), Some(COMMUNITY_SEATS));
    }

    #[test]
    fn bad_settings_never_stop_the_server() {
        let l = lic("lic-bad");
        let c = mint(&claims(Some(50), 20));
        for (vars, code) in [
            (vec![("LICENSE_KEY", "not-a-license")], "malformed"),
            (vec![("LICENSE_KEY", c.as_str()), ("LICENSE_KEY_FILE", "/etc/x")], "ambiguous"),
            (vec![("LICENSE_KEY_FILE", "/nonexistent/license.key")], "unreadable"),
        ] {
            l.load(env(&vars));
            let s = l.status();
            assert_eq!((s.mode, s.problem.as_ref().map(|p| p.code), s.seat_cap()), (Mode::Invalid, Some(code), Some(COMMUNITY_SEATS)), "{vars:?}");
            assert!(s.detail().contains("community edition"));
        }
        // LICENSE_KEY_FILE, and the file in DATA_DIR.
        let f = crate::db::temp_path("lic-file");
        std::fs::create_dir_all(&f).unwrap();
        std::fs::write(f.join("k"), format!("{c}\n")).unwrap();
        l.load(env(&[("LICENSE_KEY_FILE", f.join("k").to_str().unwrap())]));
        assert_eq!((l.status().mode, l.status().source), (Mode::Active, Source::EnvFile));
        std::fs::write(&l.path, &c).unwrap();
        l.load(env(&[]));
        assert_eq!((l.status().mode, l.status().source), (Mode::Active, Source::File));
        std::fs::write(&l.path, "  \n").unwrap();
        l.load(env(&[]));
        assert_eq!(l.status().mode, Mode::Community, "an empty file is no license");
    }
}
