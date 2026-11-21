//! Self-host license key (ADR 0038). A license is a JWT CG-Labs signs with Ed25519,
//! checked offline against the public keys below. It names the licensee, an edition, the
//! seats (active users) it covers, features, and when it ends.
//!
//! SuperBot has no free tier (ADR 0068). Without a license, or with one that is invalid
//! or long expired, botd still starts and admins can still sign in and install a key, but
//! Bots don't run and nobody takes a seat. The one exception is testing mode
//! (`TESTING_MODE=on`), which an operator turns on for a test server: no license, billing
//! off, no seat limit, and every screen says so. A license that has just ended keeps its
//! seats for [`GRACE_DAYS`] more. Over the limit, nobody is signed out or disabled; adding
//! or re-enabling people is refused until a seat is free. The owner (break-glass) account
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
use axum::Json;
use axum::extract::{Extension, State};
use axum::http::StatusCode;
use serde::Serialize;
use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, RwLock};
pub use token::{Claims, Invalid, Key};

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
    let keys = TRUSTED
        .iter()
        .map(|(kid, public)| Key::parse(kid, public).expect("a built-in license key"));
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
    fn is_env(self) -> bool {
        matches!(self, Source::Env | Source::EnvFile)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    /// No license.
    Unlicensed,
    Active,
    /// Ended less than [`GRACE_DAYS`] ago: still honoured.
    Grace,
    /// Ended longer ago: no longer a license.
    Expired,
    /// Set, but not a license this server accepts.
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
        Problem {
            code: e.code(),
            text: e.text().into(),
        }
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
        Loaded {
            source: Source::None,
            token: None,
            license: None,
        }
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
    /// `TESTING_MODE=on`: the operator runs this server unlicensed, with billing off.
    pub testing_mode: bool,
}

/// `TESTING_MODE`: off unless set to on/1/true/yes.
pub fn testing_flag(raw: &str) -> Result<bool, String> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "on" | "yes" => Ok(true),
        "" | "0" | "false" | "off" | "no" => Ok(false),
        _ => Err(format!("TESTING_MODE must be on or off, not \"{raw}\"")),
    }
}

fn date(ms: i64) -> String {
    chrono::DateTime::from_timestamp_millis(ms)
        .unwrap_or_default()
        .format("%Y-%m-%d")
        .to_string()
}

impl Status {
    /// The license's seats and features count.
    pub fn licensed(&self) -> bool {
        matches!(self.mode, Mode::Active | Mode::Grace)
    }

    /// Running on testing mode: no license is honoured and `TESTING_MODE` is on. A license
    /// always wins over it.
    pub fn testing(&self) -> bool {
        self.testing_mode && !self.licensed()
    }

    /// Whether Bots may run: a license, or testing mode. Never a free tier.
    pub fn usable(&self) -> bool {
        self.licensed() || self.testing_mode
    }

    fn honoured(&self) -> Option<&Claims> {
        self.claims.as_ref().filter(|_| self.licensed())
    }

    /// Active users allowed now, the owner aside. None: unlimited. Without a license
    /// none, unless testing mode is on.
    pub fn seat_cap(&self) -> Option<u32> {
        match self.honoured() {
            Some(c) => c.seats,
            None if self.testing_mode => None,
            None => Some(0),
        }
    }

    pub fn edition(&self) -> &str {
        match self.honoured() {
            Some(c) => c.edition.as_str(),
            None if self.testing_mode => "testing",
            None => "none",
        }
    }

    /// For paid modules: whether the license grants `feature` now.
    #[allow(dead_code)]
    pub fn allows(&self, feature: &str) -> bool {
        self.honoured()
            .is_some_and(|c| c.features.iter().any(|f| f == feature))
    }

    pub fn expires_at(&self) -> Option<i64> {
        self.claims.as_ref().map(|c| c.exp * 1000)
    }

    pub fn grace_ends_at(&self) -> Option<i64> {
        self.expires_at().map(|e| e + GRACE_DAYS * DAY_MS)
    }

    /// What the audit log keeps of it: never the token.
    pub fn summary(&self) -> Value {
        let mut v = json!({ "mode": self.mode, "source": self.source, "edition": self.edition(), "seats": self.seat_cap(), "testing": self.testing() });
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
        let m = match (&self.claims, &self.problem) {
            (Some(c), _) => format!("{:?}:{}", self.mode, c.jti).to_lowercase(),
            (None, Some(p)) => format!("invalid:{}", p.code),
            (None, None) => "unlicensed".into(),
        };
        if self.testing() {
            format!("{m}:testing")
        } else {
            m
        }
    }

    /// One sentence or two for admins.
    pub fn detail(&self) -> String {
        let seats = |c: &Claims| {
            c.seats.map_or("unlimited seats".to_string(), |s| {
                format!("{s} seat{}", if s == 1 { "" } else { "s" })
            })
        };
        let then = if self.testing_mode {
            "Testing mode is on (TESTING_MODE), so the server keeps running with billing off."
                .to_string()
        } else {
            "Bots don't run and nobody new can be added until a license is installed; SuperBot has no free tier.".to_string()
        };
        match (self.mode, &self.claims) {
            (Mode::Unlicensed, _) if self.testing_mode => {
                "Testing mode (TESTING_MODE=on): no license, billing is off, and nothing is charged. For testing only, not production.".into()
            }
            (Mode::Unlicensed, _) => {
                "No license. SuperBot has no free tier: install the license key from CG-Labs, or set TESTING_MODE=on for a test server. Until then, Bots don't run and nobody new can be added.".into()
            }
            (Mode::Active, Some(c)) => format!("Licensed to {} ({}, {}) until {}.", c.sub, c.edition, seats(c), date(c.exp * 1000)),
            (Mode::Grace, Some(c)) => format!(
                "The license for {} ended on {}. It keeps working until {}; install the renewed key before then, or Bots stop running.",
                c.sub,
                date(c.exp * 1000),
                date(self.grace_ends_at().unwrap_or_default())
            ),
            (Mode::Expired, Some(c)) => format!("The license for {} ended on {}. {then}", c.sub, date(c.exp * 1000)),
            _ => format!("The license key isn't valid ({}). {then}", self.problem.as_ref().map_or("unknown", |p| p.code)),
        }
    }

    /// Why a run is refused while [`usable`](Self::usable) is false, for the Bot to say.
    pub fn run_refusal(&self) -> String {
        match self.mode {
            Mode::Expired => "I can't run: this server's SuperBot license has ended. Ask an admin to install the renewed key.".into(),
            Mode::Invalid => "I can't run: this server's SuperBot license key isn't valid. Ask an admin to install a valid key.".into(),
            _ => "I can't run: this server has no SuperBot license, and SuperBot has no free tier. Ask an admin to install the license key.".into(),
        }
    }

    /// Things an admin should act on, given `used` seats.
    pub fn warnings(&self, used: u32) -> Vec<String> {
        let mut w = Vec::new();
        if let (Mode::Active, Some(exp)) = (self.mode, self.expires_at())
            && exp - self.at < WARN_DAYS * DAY_MS
        {
            w.push(format!(
                "The license ends on {}. Ask CG-Labs for the renewed key.",
                date(exp)
            ));
        }
        if matches!(self.mode, Mode::Grace | Mode::Expired | Mode::Invalid) || !self.usable() {
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
            Some(c) => format!(
                "No seats left: the license for {} covers {cap} active users, and {used} are active. Disable someone, or ask CG-Labs for more seats.",
                c.sub
            ),
            None => format!(
                "No seats: this server has no license, and SuperBot has no free tier ({used} active). Install a license key (console Settings, or botctl license install), or set TESTING_MODE=on on a test server."
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
            "savable": !self.source.is_env(),
            "license": license,
            "error": self.problem.as_ref().map(|p| p.code),
            "problem": self.problem.as_ref().map(|p| p.text.clone()),
            "seats": { "limit": cap, "used": used, "available": cap.map(|c| c.saturating_sub(used)) },
            "testing": self.testing(),
            "usable": self.usable(),
            "ok": self.mode == Mode::Active || (self.mode == Mode::Unlicensed && self.testing_mode),
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
    /// `TESTING_MODE`, set once at start.
    testing: AtomicBool,
    /// Installs, removals, and the status-change check, one at a time: each reads, writes,
    /// and audits together.
    changing: Mutex<()>,
}

fn read_capped(path: &Path) -> std::io::Result<String> {
    use std::io::Read;
    let mut s = String::new();
    std::fs::File::open(path)?
        .take(token::MAX_TOKEN as u64 + 1)
        .read_to_string(&mut s)?;
    Ok(s)
}

impl Licensing {
    /// Nothing loaded yet, and testing mode off: unlicensed.
    pub fn new(keys: Vec<Key>, data_dir: &Path) -> Licensing {
        Licensing {
            keys,
            path: data_dir.join(FILE),
            loaded: RwLock::new(Loaded::none()),
            testing: AtomicBool::new(false),
            changing: Mutex::new(()),
        }
    }

    /// Turns testing mode (`TESTING_MODE`) on or off.
    pub fn set_testing(&self, on: bool) {
        self.testing.store(on, Ordering::Relaxed);
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
                Loaded {
                    source,
                    token: Some(t),
                    license,
                }
            }
            Err(e) if source == Source::File && e.kind() == std::io::ErrorKind::NotFound => {
                Loaded::none()
            }
            Err(e) => Loaded {
                source,
                token: None,
                license: Some(Err(Problem {
                    code: "unreadable",
                    text: format!("The license key file can't be read: {e}"),
                })),
            },
        }
    }

    /// Reads `LICENSE_KEY`, else `LICENSE_KEY_FILE`, else `DATA_DIR/license.key`. Never
    /// fails: a bad key is reported, and the server runs unlicensed.
    pub fn load(&self, get: impl Fn(&str) -> String) {
        let (inline, file) = (get("LICENSE_KEY"), get("LICENSE_KEY_FILE"));
        let (inline, file) = (inline.trim(), file.trim());
        let loaded = match (inline.is_empty(), file.is_empty()) {
            (false, false) => Loaded {
                source: Source::Env,
                token: None,
                license: Some(Err(Problem {
                    code: "ambiguous",
                    text: "Both LICENSE_KEY and LICENSE_KEY_FILE are set. Keep one.".into(),
                })),
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

    /// A key loaded before its start date becomes the license once that date passes.
    fn start_if_due(&self, now_ms: i64) {
        let waiting = {
            let l = self.loaded.read().unwrap_or_else(|e| e.into_inner());
            match (&l.license, &l.token) {
                (Some(Err(p)), Some(t)) if p.code == Invalid::NotYetValid.code() => t.clone(),
                _ => return,
            }
        };
        if let Ok(c) = self.check(&waiting, now_ms) {
            let mut l = self.loaded.write().unwrap_or_else(|e| e.into_inner());
            if l.token.as_deref() == Some(waiting.as_str()) {
                l.license = Some(Ok(c));
            }
        }
    }

    pub fn status_at(&self, now_ms: i64) -> Status {
        self.start_if_due(now_ms);
        let l = self.loaded.read().unwrap_or_else(|e| e.into_inner());
        let (mode, claims, problem) = match &l.license {
            None => (Mode::Unlicensed, None, None),
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
        Status {
            mode,
            source: l.source,
            claims,
            problem,
            at: now_ms,
            testing_mode: self.testing.load(Ordering::Relaxed),
        }
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
            db.record(
                &by.event("license.refused")
                    .target("license", "server")
                    .outcome(Outcome::Failure)
                    .details(d),
            );
        };
        if before.source.is_env() {
            refuse("set_in_env", json!({}));
            return Err(ChangeError::FromEnv);
        }
        let now = db::now();
        let claims = self.check(key, now).map_err(|e| {
            refuse(e.code(), json!({}));
            ChangeError::Invalid(e)
        })?;
        if claims.exp * 1000 <= now {
            refuse(
                "expired",
                json!({ "id": claims.jti, "expiresAt": claims.exp * 1000 }),
            );
            return Err(ChangeError::Expired(claims.exp * 1000));
        }
        let key = key.trim();
        let same = self
            .loaded
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .token
            .as_deref()
            == Some(key);
        if !same {
            write_private(&self.path, key).map_err(|e| ChangeError::Io(e.to_string()))?;
            *self.loaded.write().unwrap_or_else(|e| e.into_inner()) = Loaded {
                source: Source::File,
                token: Some(key.into()),
                license: Some(Ok(claims.clone())),
            };
            let after = self.status();
            db.record(
                &by.event("license.installed")
                    .target("license", &claims.jti)
                    .details(json!({ "from": changed_from(&before), "to": after.summary() })),
            );
            db.set_setting(SEEN, &after.marker());
        }
        Ok(self.status())
    }

    /// Deletes `DATA_DIR/license.key`: unlicensed again. Audited.
    pub fn remove(&self, db: &Db, by: &Who) -> Result<Status, ChangeError> {
        let _one = self.changing.lock().unwrap_or_else(|e| e.into_inner());
        let before = self.status();
        if before.source.is_env() {
            return Err(ChangeError::FromEnv);
        }
        match std::fs::remove_file(&self.path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound && before.source == Source::None => {
                return Err(ChangeError::NotInstalled);
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(ChangeError::Io(e.to_string())),
        }
        *self.loaded.write().unwrap_or_else(|e| e.into_inner()) = Loaded::none();
        let target = before.claims.as_ref().map_or("server", |c| c.jti.as_str());
        db.record(
            &by.event("license.removed")
                .target("license", target)
                .details(json!({ "from": before.summary() })),
        );
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
        if seen.is_none() && now.mode == Mode::Unlicensed && !now.testing() {
            return;
        }
        let target = now.claims.as_ref().map_or("server", |c| c.jti.as_str());
        let outcome = if now.usable() {
            Outcome::Success
        } else {
            Outcome::Failure
        };
        db.record(
            &Event::new(Actor::system("license"), "license.status_changed")
                .target("license", target)
                .outcome(outcome)
                .details(json!({ "from": seen, "to": now.summary() })),
        );
    }
}

fn changed_from(before: &Status) -> Value {
    if before.mode == Mode::Unlicensed {
        Value::Null
    } else {
        before.summary()
    }
}

/// Written whole or not at all, readable by botd's user only.
fn write_private(path: &Path, contents: &str) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let tmp = path.with_extension(format!("tmp-{}", crate::short_id()));
    let res = (|| {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)?;
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
pub fn refuse_seat(
    app: &AppState,
    who: &Who,
    via: &str,
    target: Option<&str>,
    email: Option<&str>,
) -> String {
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

/// The license as admins see it, with whether billing is on (ADR 0068).
pub fn view(app: &AppState, a: &crate::Auth) -> Value {
    let mut v = app.license.status().view(app.db.active_seats());
    v["billing"] = a.payments.status();
    v
}

/// `GET /api/license`: the license, its mode, the seats in use, and billing. Never the key.
pub async fn get(
    State(app): State<AppState>,
    Extension(a): Extension<std::sync::Arc<crate::Auth>>,
) -> Json<Value> {
    Json(view(&app, &a))
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
pub async fn put(
    State(app): State<AppState>,
    Extension(a): Extension<std::sync::Arc<crate::Auth>>,
    Extension(by): Extension<Who>,
    Json(v): Json<Value>,
) -> Res {
    let key = v
        .get("key")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|k| !k.is_empty())
        .ok_or_else(|| crate::bad("Send {\"key\": \"<license key>\"}."))?;
    app.license
        .install(&app.db, &by, key)
        .map_err(change_error)?;
    Ok(Json(view(&app, &a)))
}

/// `DELETE /api/license`: unlicensed again.
pub async fn delete(
    State(app): State<AppState>,
    Extension(a): Extension<std::sync::Arc<crate::Auth>>,
    Extension(by): Extension<Who>,
) -> Res {
    app.license.remove(&app.db, &by).map_err(change_error)?;
    Ok(Json(view(&app, &a)))
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
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;

    fn lic(dir: &str) -> Licensing {
        let d = crate::db::temp_path(dir);
        std::fs::create_dir_all(&d).unwrap();
        Licensing::new(trusted(), &d)
    }

    fn env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> String {
        let m: std::collections::HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
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
        let tampered = format!(
            "{head}.{}.{sig}",
            B64.encode(serde_json::to_string(&more).unwrap())
        );
        assert_eq!(
            verify(&tampered, &trusted(), now),
            Err(Invalid::BadSignature)
        );
        // Signed by a key that claims to be the trusted one.
        assert_eq!(
            verify(&sign(&stranger(), KID, &c).unwrap(), &trusted(), now),
            Err(Invalid::BadSignature)
        );
        // A key nobody trusts.
        assert_eq!(
            verify(&sign(&stranger(), "cg-2099", &c).unwrap(), &trusted(), now),
            Err(Invalid::UnknownKey)
        );
        // Other algorithms, no kid, crit, junk.
        let payload = B64.encode(serde_json::to_string(&c).unwrap());
        for h in [
            r#"{"alg":"none","kid":"test"}"#,
            r#"{"alg":"HS256","kid":"test"}"#,
            r#"{"alg":"RS256","kid":"test"}"#,
            r#"{"alg":"EdDSA","kid":"test","crit":["x"]}"#,
        ] {
            assert_eq!(
                verify(
                    &format!("{}.{payload}.{sig}", B64.encode(h)),
                    &trusted(),
                    now
                ),
                Err(Invalid::BadAlgorithm),
                "{h}"
            );
        }
        assert_eq!(
            verify(
                &format!("{}.{payload}.{sig}", B64.encode(r#"{"alg":"EdDSA"}"#)),
                &trusted(),
                now
            ),
            Err(Invalid::UnknownKey)
        );
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
            let signed = format!(
                "{}.{}",
                B64.encode(r#"{"alg":"EdDSA","kid":"test"}"#),
                B64.encode(serde_json::to_string(c).unwrap())
            );
            format!(
                "{signed}.{}",
                B64.encode(signer().sign(signed.as_bytes()).as_ref())
            )
        };
        assert_eq!(
            verify(&raw(&with(&|c| c.aud = "other".into())), &trusted(), now),
            Err(Invalid::WrongAudience)
        );
        assert_eq!(
            verify(&raw(&with(&|c| c.seats = Some(0))), &trusted(), now),
            Err(Invalid::BadClaims)
        );
        let not_json = format!(
            "{}.{}",
            B64.encode(r#"{"alg":"EdDSA","kid":"test"}"#),
            B64.encode(r#"{"sub":"x"}"#)
        );
        let signed = format!(
            "{not_json}.{}",
            B64.encode(signer().sign(not_json.as_bytes()).as_ref())
        );
        assert_eq!(verify(&signed, &trusted(), now), Err(Invalid::BadClaims));
        // Starts next week.
        let later = with(&|c| c.nbf = Some(now + 7 * 86_400));
        assert_eq!(
            verify(&mint(&later), &trusted(), now),
            Err(Invalid::NotYetValid)
        );
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
        assert_eq!(
            verify(
                &sign(&k, "cg-1", &c).unwrap(),
                &trusted,
                crate::db::now() / 1000
            )
            .unwrap(),
            c
        );
        assert!(
            key_from_pem("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----").is_err()
        );
        assert!(key_from_pem("ssh-ed25519 AAAA").is_err());
        assert!(Key::parse("x", "AAAA").is_err(), "32 bytes or nothing");
        // Release builds trust only the built-in keys; the test key is test-only.
        assert!(TRUSTED.iter().all(|(kid, _)| *kid != KID));
    }

    #[test]
    fn modes_follow_the_clock_and_seats_follow_the_mode() {
        let l = lic("lic-modes");
        let none = l.status();
        assert_eq!(
            (
                none.mode,
                none.seat_cap(),
                none.edition(),
                none.usable(),
                none.testing()
            ),
            (Mode::Unlicensed, Some(0), "none", false, false)
        );
        assert!(none.detail().contains("no free tier"), "{}", none.detail());
        assert_eq!(none.warnings(0), vec![none.detail()], "an admin is told");

        let c = claims(Some(50), 20);
        l.load(env(&[("LICENSE_KEY", &mint(&c))]));
        let exp = c.exp * 1000;
        let at = |ms: i64| l.status_at(ms);
        assert_eq!(
            (
                at(exp - 1).mode,
                at(exp - 1).seat_cap(),
                at(exp - 1).usable()
            ),
            (Mode::Active, Some(50), true)
        );
        assert!(
            at(exp - 1).warnings(3)[0].contains("ends on"),
            "warned before it ends"
        );
        assert!(at(exp - 40 * DAY_MS).warnings(3).is_empty());
        assert!(at(exp - 1).allows("scim") && !at(exp - 1).allows("white-label"));
        // Ended: still honoured during the grace period.
        assert_eq!((at(exp).mode, at(exp).seat_cap()), (Mode::Grace, Some(50)));
        assert!(at(exp + GRACE_DAYS * DAY_MS - 1).licensed());
        // Then no seats, no runs, and the license's features are gone. No free fallback.
        let gone = at(exp + GRACE_DAYS * DAY_MS);
        assert_eq!(
            (
                gone.mode,
                gone.seat_cap(),
                gone.edition(),
                gone.allows("scim"),
                gone.usable()
            ),
            (Mode::Expired, Some(0), "none", false, false)
        );
        assert!(gone.seat_error(10).contains("no free tier"));
        assert!(gone.run_refusal().contains("ended"));
        // Unlimited seats, and exactly what the license says otherwise.
        l.load(env(&[("LICENSE_KEY", &mint(&claims(None, 20)))]));
        assert_eq!(l.seat_cap(), None);
        l.load(env(&[("LICENSE_KEY", &mint(&claims(Some(3), 20)))]));
        assert_eq!(l.seat_cap(), Some(3));
    }

    #[test]
    fn testing_mode_is_explicit_loud_and_loses_to_a_license() {
        assert_eq!(testing_flag(""), Ok(false), "off by default");
        assert_eq!(
            (testing_flag("on"), testing_flag("TRUE"), testing_flag("0")),
            (Ok(true), Ok(true), Ok(false))
        );
        assert!(testing_flag("maybe").unwrap_err().contains("TESTING_MODE"));

        let l = lic("lic-testing");
        l.set_testing(true);
        let s = l.status();
        assert_eq!(
            (s.mode, s.seat_cap(), s.edition(), s.usable(), s.testing()),
            (Mode::Unlicensed, None, "testing", true, true)
        );
        assert!(s.detail().contains("billing is off"), "{}", s.detail());
        let v = s.view(3);
        assert_eq!(
            (
                v["testing"].as_bool(),
                v["usable"].as_bool(),
                v["ok"].as_bool()
            ),
            (Some(true), Some(true), Some(true))
        );
        assert_eq!(s.summary()["testing"], json!(true));
        // An ended license on a test server: still runs, and says why.
        let c = claims(Some(5), -(GRACE_DAYS + 1));
        l.load(env(&[("LICENSE_KEY", &mint(&c))]));
        let s = l.status();
        assert_eq!(
            (s.mode, s.usable(), s.testing(), s.seat_cap()),
            (Mode::Expired, true, true, None)
        );
        assert!(s.detail().contains("Testing mode is on"), "{}", s.detail());
        // A license wins: its seats, its edition, and not testing.
        l.load(env(&[("LICENSE_KEY", &mint(&claims(Some(5), 20)))]));
        let s = l.status();
        assert_eq!(
            (s.mode, s.seat_cap(), s.edition(), s.testing()),
            (Mode::Active, Some(5), "business", false)
        );
    }

    #[test]
    fn a_key_loaded_before_it_starts_takes_over_when_it_starts() {
        let l = lic("lic-later");
        let mut c = claims(Some(50), 20);
        let starts = crate::db::now() / 1000 + 7 * 86_400;
        c.nbf = Some(starts);
        l.load(env(&[("LICENSE_KEY", &mint(&c))]));
        let s = l.status();
        assert_eq!(
            (s.mode, s.problem.as_ref().map(|p| p.code), s.seat_cap()),
            (Mode::Invalid, Some("not_yet_valid"), Some(0))
        );
        let s = l.status_at(starts * 1000);
        assert_eq!(
            (s.mode, s.seat_cap(), s.source),
            (Mode::Active, Some(50), Source::Env)
        );
        assert_eq!(l.status().mode, Mode::Active, "kept, not checked again");
    }

    #[test]
    fn bad_settings_never_stop_the_server() {
        let l = lic("lic-bad");
        let c = mint(&claims(Some(50), 20));
        for (vars, code) in [
            (vec![("LICENSE_KEY", "not-a-license")], "malformed"),
            (
                vec![("LICENSE_KEY", c.as_str()), ("LICENSE_KEY_FILE", "/etc/x")],
                "ambiguous",
            ),
            (
                vec![("LICENSE_KEY_FILE", "/nonexistent/license.key")],
                "unreadable",
            ),
        ] {
            l.load(env(&vars));
            let s = l.status();
            assert_eq!(
                (s.mode, s.problem.as_ref().map(|p| p.code), s.seat_cap()),
                (Mode::Invalid, Some(code), Some(0)),
                "{vars:?}"
            );
            assert!(s.detail().contains("no free tier"));
        }
        // LICENSE_KEY_FILE, and the file in DATA_DIR.
        let f = crate::db::temp_path("lic-file");
        std::fs::create_dir_all(&f).unwrap();
        std::fs::write(f.join("k"), format!("{c}\n")).unwrap();
        l.load(env(&[("LICENSE_KEY_FILE", f.join("k").to_str().unwrap())]));
        assert_eq!(
            (l.status().mode, l.status().source),
            (Mode::Active, Source::EnvFile)
        );
        std::fs::write(&l.path, &c).unwrap();
        l.load(env(&[]));
        assert_eq!(
            (l.status().mode, l.status().source),
            (Mode::Active, Source::File)
        );
        std::fs::write(&l.path, "  \n").unwrap();
        l.load(env(&[]));
        assert_eq!(
            l.status().mode,
            Mode::Unlicensed,
            "an empty file is no license"
        );
    }
}
