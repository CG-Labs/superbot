//! Signed, externally timestamped checkpoints of the audit chain's head (ADR 0149).
//!
//! The chain (ADR 0122) has no secret: whoever can write `app.sqlite` can rebuild it. A
//! checkpoint adds two things a rebuild can't fake. Every `AUDIT_CHECKPOINT_MINUTES`
//! (and on `POST /api/audit/checkpoints`) botd signs the head, `(seq, hash, at)`, with an
//! Ed25519 key derived from the master key, and records it as an `audit.checkpoint`
//! event sealed straight onto that head. With `AUDIT_TIMESTAMP_URL` set, it then asks an
//! RFC 3161 time-stamping authority to countersign the checkpoint, and records the token
//! as `audit.checkpoint_timestamped`: proof from outside the host that the head existed
//! by then. Both events go to the SIEM with the rest, with what's needed to check them
//! there.
//!
//! Timestamping never holds up the audit log: a checkpoint waits in `audit_checkpoints`
//! until its token comes, tried again with backoff, and `audit.timestamp_failing` is
//! recorded once while the TSA keeps failing.

use crate::audit::{Actor, Event, Outcome, Who};
use crate::audit_chain::{GENESIS, Link, Row};
use crate::db::{Db, now};
use crate::obs::log::{log_info, log_warn};
use crate::obs::metrics;
use crate::runner::App;
use crate::tsa;
use aws_lc_rs::signature::{ED25519, Ed25519KeyPair, KeyPair, UnparsedPublicKey};
use base64::Engine;
use rusqlite::{Connection, OptionalExtension, params};
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub const CHECKPOINT: &str = "audit.checkpoint";
pub const TIMESTAMPED: &str = "audit.checkpoint_timestamped";
pub const KEY_ADDED: &str = "audit.checkpoint_key";
pub const FAILING: &str = "audit.timestamp_failing";
pub const RECOVERED: &str = "audit.timestamp_recovered";
/// Events about checkpoints: on their own they don't make another checkpoint due.
const OWN: [&str; 5] = [CHECKPOINT, TIMESTAMPED, KEY_ADDED, FAILING, RECOVERED];

const DOMAIN: &str = "superbot-audit-checkpoint-v1";
/// What the signing key is derived for from the master key's root (ADR 0099).
const PURPOSE: &str = "audit/checkpoint-signing/v1";
/// Settings key: every checkpoint key botd has signed with, `[{"id", "publicKey", "since"}]`.
pub const KEYS: &str = "audit_checkpoint_keys";

pub const DEFAULT_MINUTES: u64 = 60;
const MAX_MINUTES: u64 = 7 * 24 * 60;
const TICK: Duration = Duration::from_millis(if cfg!(test) { 50 } else { 60_000 });
const IDLE: Duration = Duration::from_millis(if cfg!(test) { 50 } else { 60_000 });
const FIRST_RETRY: Duration = Duration::from_millis(if cfg!(test) { 50 } else { 1_000 });
const LAST_RETRY: Duration = Duration::from_secs(5 * 60);
const TIMEOUT: Duration = Duration::from_secs(30);
/// Failed tries in a row before `audit.timestamp_failing` is recorded.
const FAILING_AFTER: u32 = 3;

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok()).collect()
}

fn b64() -> base64::engine::GeneralPurpose {
    base64::engine::general_purpose::STANDARD
}

/// The key's id: the first 8 bytes of its SHA-256, hex.
pub fn key_id(public: &[u8]) -> String {
    hex(&Sha256::digest(public)[..8])
}

/// An Ed25519 public key, as 64 hex digits.
pub fn parse_public_key(s: &str) -> Result<Vec<u8>, String> {
    match unhex(s.trim()) {
        Some(k) if k.len() == 32 => Ok(k),
        _ => Err(format!("a key is an Ed25519 public key in 64 hex digits, not \"{}\"", crate::audit::clip(s, 80))),
    }
}

/// What a checkpoint signs.
pub fn statement(seq: i64, hash: &str, at: i64, key: &str) -> String {
    format!("{DOMAIN}\nseq={seq}\nhash={hash}\nat={at}\nkey={key}")
}

/// What a checkpoint's RFC 3161 token stamps: the statement and its signature.
pub fn imprint(statement: &str, signature: &str) -> [u8; 32] {
    Sha256::digest(format!("{statement}\nsig={signature}").as_bytes()).into()
}

/// botd's signing key.
pub struct Key {
    pair: Ed25519KeyPair,
    pub public: Vec<u8>,
    pub id: String,
}

impl Key {
    /// Derived from the master key, so it lasts as long as that does and needs no storing.
    pub fn derive() -> Key {
        let seed = crate::secrets::sealed::cipher().derive(PURPOSE);
        Key::from_seed(&seed[..])
    }

    fn from_seed(seed: &[u8]) -> Key {
        let pair = Ed25519KeyPair::from_seed_unchecked(seed).expect("a 32-byte Ed25519 seed");
        let public = pair.public_key().as_ref().to_vec();
        Key { id: key_id(&public), public, pair }
    }

    pub fn sign(&self, message: &str) -> String {
        hex(self.pair.sign(message.as_bytes()).as_ref())
    }
}

/// Whether `signature` (hex) is `public`'s over `message`.
pub fn signed(public: &[u8], message: &str, signature: &str) -> bool {
    unhex(signature).is_some_and(|s| UnparsedPublicKey::new(&ED25519, public).verify(message.as_bytes(), &s).is_ok())
}

/// Where to get timestamps: the URL, and what the API, logs and events show of it.
#[derive(Clone, Debug)]
pub struct Tsa {
    pub url: String,
    pub shown: String,
}

impl Tsa {
    pub fn parse(raw: &str) -> Result<Tsa, String> {
        let bad = |why: &str| format!("AUDIT_TIMESTAMP_URL must be an RFC 3161 time-stamping URL, http(s)://<host>/<path>: {why}");
        let u = url::Url::parse(raw.trim()).map_err(|_| bad("it isn't a URL"))?;
        // Plain HTTP is fine: a token is signed, and what's sent is a hash.
        if !matches!(u.scheme(), "http" | "https") {
            return Err(bad("use http or https"));
        }
        let host = u.host_str().filter(|h| !h.is_empty()).ok_or_else(|| bad("no host"))?;
        if !u.username().is_empty() || u.password().is_some() {
            return Err(bad("no credentials in it"));
        }
        if u.query().is_some() || u.fragment().is_some() {
            return Err(bad("no query or fragment"));
        }
        let port = u.port().map(|p| format!(":{p}")).unwrap_or_default();
        Ok(Tsa { shown: format!("{}://{host}{port}", u.scheme()), url: u.to_string() })
    }
}

#[derive(Clone, Debug)]
pub struct Settings {
    /// Minutes between checkpoints; 0: only on request.
    pub every: u64,
    pub tsa: Option<Tsa>,
    /// What tokens must chain to; empty: any time-stamping certificate, shown as untrusted.
    pub trust: tsa::Trust,
}

impl Default for Settings {
    fn default() -> Settings {
        Settings { every: DEFAULT_MINUTES, tsa: None, trust: tsa::Trust::default() }
    }
}

impl Settings {
    /// `AUDIT_CHECKPOINT_MINUTES` (default 60, 0 for off), `AUDIT_TIMESTAMP_URL` (off by
    /// default) and `AUDIT_TIMESTAMP_CA_FILE` (PEM certificates tokens must chain to).
    pub fn from_env(get: &dyn Fn(&str) -> String) -> Result<Settings, String> {
        let every = match get("AUDIT_CHECKPOINT_MINUTES").trim() {
            "" => DEFAULT_MINUTES,
            "off" => 0,
            v => match v.parse::<u64>() {
                Ok(n) if n <= MAX_MINUTES => n,
                _ => {
                    return Err(format!("AUDIT_CHECKPOINT_MINUTES must be minutes from 0 (off) to {MAX_MINUTES}, not \"{v}\""));
                }
            },
        };
        let tsa = match get("AUDIT_TIMESTAMP_URL").trim() {
            "" | "off" => None,
            v => Some(Tsa::parse(v)?),
        };
        let trust = match get("AUDIT_TIMESTAMP_CA_FILE").trim() {
            "" => tsa::Trust::default(),
            path => {
                let pem = std::fs::read_to_string(path).map_err(|e| format!("AUDIT_TIMESTAMP_CA_FILE: couldn't read it: {e}"))?;
                tsa::Trust::from_pem(&pem).map_err(|e| format!("AUDIT_TIMESTAMP_CA_FILE: {e}"))?
            }
        };
        Ok(Settings { every, tsa, trust })
    }

    pub fn describe(&self) -> String {
        let every = match self.every {
            0 => "on request only (AUDIT_CHECKPOINT_MINUTES=0)".to_string(),
            n => format!("every {n} minutes while there are new events"),
        };
        let stamped = match (&self.tsa, self.trust.is_set()) {
            (None, _) => "not timestamped (AUDIT_TIMESTAMP_URL)".to_string(),
            (Some(t), true) => format!("timestamped by {} (tokens must chain to AUDIT_TIMESTAMP_CA_FILE)", t.shown),
            (Some(t), false) => format!("timestamped by {} (no AUDIT_TIMESTAMP_CA_FILE: the TSA isn't checked against a CA)", t.shown),
        };
        format!("signed {every}, {stamped}")
    }
}

#[derive(Default)]
struct Stamping {
    failures: u32,
    failing_since: Option<i64>,
    last_error: Option<String>,
    last_try: Option<i64>,
}

/// Checkpoints as this botd makes them: its settings, key and timestamping state.
pub struct Checkpoints {
    pub settings: Settings,
    pub key: Key,
    wake: tokio::sync::Notify,
    stamping: Mutex<Stamping>,
}

impl Checkpoints {
    fn new(settings: Settings) -> Checkpoints {
        Checkpoints { settings, key: Key::derive(), wake: tokio::sync::Notify::new(), stamping: Mutex::new(Stamping::default()) }
    }

    fn stamping(&self) -> std::sync::MutexGuard<'_, Stamping> {
        self.stamping.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Returns how many tries failed and since when, if it had been failing.
    fn stamped(&self) -> Option<(u32, i64)> {
        let mut s = self.stamping();
        s.last_try = Some(now());
        let was = s.failing_since.take().map(|t| (s.failures, t));
        s.failures = 0;
        s.last_error = None;
        was
    }

    /// True on the try that makes it count as failing.
    fn failed(&self, error: &str) -> bool {
        let mut s = self.stamping();
        s.last_try = Some(now());
        s.failures += 1;
        s.last_error = Some(error.into());
        if s.failures == FAILING_AFTER {
            s.failing_since = Some(now());
            return true;
        }
        false
    }
}

/// This botd's checkpoints; the defaults (hourly, no timestamps) until `start` sets them.
pub fn state(app: &App) -> &Arc<Checkpoints> {
    app.audit_checkpoints.get_or_init(|| Arc::new(Checkpoints::new(Settings::default())))
}

/// What timestamp tokens must chain to.
pub fn trust(app: &App) -> tsa::Trust {
    state(app).settings.trust.clone()
}

/// Starts making checkpoints, and timestamping them if a TSA is set.
pub fn start(app: &Arc<App>, settings: Settings) {
    let stamps = settings.tsa.is_some();
    if app.audit_checkpoints.set(Arc::new(Checkpoints::new(settings))).is_err() {
        log_warn!("Audit checkpoints: settings were already in use; keeping them.");
    }
    let cp = state(app).clone();
    remember_key(&app.db, &cp.key);
    tokio::spawn(schedule(app.clone(), cp.clone()));
    if stamps {
        tokio::spawn(stamp_all(app.clone(), cp));
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KnownKey {
    pub id: String,
    pub public_key: String,
    pub since: i64,
}

pub fn known_keys(db: &Db) -> Vec<KnownKey> {
    db.setting(KEYS).and_then(|v| serde_json::from_str(&v).ok()).unwrap_or_default()
}

/// Adds `key` to the keys botd has signed with, recording it the first time.
fn remember_key(db: &Db, key: &Key) {
    let mut keys = known_keys(db);
    if keys.iter().any(|k| k.id == key.id) {
        return;
    }
    keys.push(KnownKey { id: key.id.clone(), public_key: hex(&key.public), since: now() });
    db.set_setting(KEYS, &serde_json::to_string(&keys).unwrap_or_default());
    let e = Event::new(Actor::system("audit_checkpoint"), KEY_ADDED).target("audit", "chain");
    db.record(&e.details(json!({ "keyId": key.id, "publicKey": hex(&key.public), "algorithm": "Ed25519" })));
}

/// The keys a check trusts by default: botd's own now, and every one it signed with before.
pub fn trusted_keys(db: &Db) -> Vec<Vec<u8>> {
    let mut keys = vec![Key::derive().public];
    for k in known_keys(db) {
        if let Ok(p) = parse_public_key(&k.public_key) {
            if !keys.contains(&p) {
                keys.push(p);
            }
        }
    }
    keys
}

/// One checkpoint, as `audit_checkpoints` keeps it.
#[derive(Clone, Debug, PartialEq)]
pub struct Checkpoint {
    /// The `audit.checkpoint` event that carries it.
    pub id: i64,
    pub at: i64,
    pub seq: i64,
    pub hash: String,
    pub key_id: String,
    pub public_key: String,
    pub signature: String,
    /// `off` (no TSA when it was made), `pending` or `stamped`.
    pub tsa_status: String,
    pub tsa: Option<String>,
    /// The RFC 3161 TimeStampToken, base64 DER.
    pub tsa_token: Option<String>,
    pub tsa_time: Option<i64>,
    pub tsa_nonce: Option<String>,
    pub tsa_tries: i64,
    pub tsa_error: Option<String>,
    /// The `audit.checkpoint_timestamped` event that records the token.
    pub tsa_event_id: Option<i64>,
}

const COLS: &str = "event_id, at, seq, hash, key_id, public_key, signature, tsa_status, tsa, tsa_token, tsa_time, tsa_nonce, tsa_tries, tsa_error, tsa_event_id";

fn read(r: &rusqlite::Row) -> rusqlite::Result<Checkpoint> {
    Ok(Checkpoint {
        id: r.get(0)?,
        at: r.get(1)?,
        seq: r.get(2)?,
        hash: r.get(3)?,
        key_id: r.get(4)?,
        public_key: r.get(5)?,
        signature: r.get(6)?,
        tsa_status: r.get(7)?,
        tsa: r.get(8)?,
        tsa_token: r.get(9)?,
        tsa_time: r.get(10)?,
        tsa_nonce: r.get(11)?,
        tsa_tries: r.get(12)?,
        tsa_error: r.get(13)?,
        tsa_event_id: r.get(14)?,
    })
}

impl Checkpoint {
    pub fn statement(&self) -> String {
        statement(self.seq, &self.hash, self.at, &self.key_id)
    }

    pub fn imprint(&self) -> [u8; 32] {
        imprint(&self.statement(), &self.signature)
    }

    /// The API's shape, and what the SIEM export adds to the checkpoint's events.
    pub fn view(&self) -> Value {
        json!({
            "id": self.id, "at": self.at, "seq": self.seq, "hash": self.hash, "keyId": self.key_id, "publicKey": self.public_key,
            "signature": self.signature, "statement": self.statement(), "algorithm": "Ed25519",
            "timestamp": {
                "status": self.tsa_status, "tsa": self.tsa, "time": self.tsa_time, "token": self.tsa_token, "nonce": self.tsa_nonce,
                "imprint": hex(&self.imprint()), "tries": self.tsa_tries, "error": self.tsa_error, "event": self.tsa_event_id,
            },
        })
    }
}

/// The checkpoint carried by event `id`.
pub fn row(c: &Connection, id: i64) -> rusqlite::Result<Option<Checkpoint>> {
    c.query_row(&format!("SELECT {COLS} FROM audit_checkpoints WHERE event_id = ?"), [id], read).optional()
}

/// Records whose `audit.checkpoint` event is in the log: one without (a row added by hand)
/// is never shown, scheduled from or stamped, and `botctl audit verify` reports it.
const SEALED: &str = "EXISTS (SELECT 1 FROM audit_events e WHERE e.id = audit_checkpoints.event_id AND e.action = 'audit.checkpoint')";

/// Newest first, before event `before`.
pub fn list(c: &Connection, before: i64, limit: i64) -> rusqlite::Result<Vec<Checkpoint>> {
    let mut s = c.prepare(&format!("SELECT {COLS} FROM audit_checkpoints WHERE event_id < ? AND {SEALED} ORDER BY event_id DESC LIMIT ?"))?;
    s.query_map(params![before, limit], read)?.collect()
}

/// A record kept beside the chain, for the check: its checkpoint event and timestamp event,
/// and whether the log holds each as an event of its kind.
#[derive(Clone, Copy, Debug)]
pub struct Recorded {
    pub id: i64,
    pub stamp: Option<i64>,
    pub id_logged: bool,
    pub stamp_logged: bool,
}

/// Records whose event, or timestamp event, is from `first` to `last`.
pub fn recorded(c: &Connection, first: i64, last: i64) -> rusqlite::Result<Vec<Recorded>> {
    let mut s = c.prepare(&format!(
        "SELECT event_id, tsa_event_id, {SEALED},
           EXISTS (SELECT 1 FROM audit_events e WHERE e.id = audit_checkpoints.tsa_event_id AND e.action = '{TIMESTAMPED}')
         FROM audit_checkpoints WHERE event_id BETWEEN ?1 AND ?2 OR tsa_event_id BETWEEN ?1 AND ?2 ORDER BY event_id"
    ))?;
    s.query_map(params![first, last], |r| Ok(Recorded { id: r.get(0)?, stamp: r.get(1)?, id_logged: r.get(2)?, stamp_logged: r.get(3)? }))?.collect()
}

fn pending(c: &Connection) -> rusqlite::Result<Option<Checkpoint>> {
    c.query_row(&format!("SELECT {COLS} FROM audit_checkpoints WHERE tsa_status = 'pending' AND {SEALED} ORDER BY event_id LIMIT 1"), [], read).optional()
}

/// How the checkpoint came about, for its event.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Trigger {
    Schedule,
    Api,
}

/// Signs the chain's head as it is when the checkpoint is sealed onto it.
pub fn create(app: &App, by: &Who, trigger: Trigger) -> rusqlite::Result<Checkpoint> {
    let cp = state(app);
    remember_key(&app.db, &cp.key);
    let tsa = cp.settings.tsa.as_ref();
    let status = if tsa.is_some() { "pending" } else { "off" };
    let at = now();
    let trigger = match trigger {
        Trigger::Schedule => "schedule",
        Trigger::Api => "api",
    };
    let e = by.event(CHECKPOINT).target("audit", "chain");
    let id = app.db.record_with(&e, |c, id, head: Option<&Link>| {
        let (seq, hash) = head.map_or((0, GENESIS.to_string()), |h| (h.id, h.hash.clone()));
        let signature = cp.key.sign(&statement(seq, &hash, at, &cp.key.id));
        let public = hex(&cp.key.public);
        c.execute(
            "INSERT INTO audit_checkpoints (event_id, at, seq, hash, key_id, public_key, signature, tsa_status, tsa) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            params![id, at, seq, hash, cp.key.id, public, signature, status, tsa.map(|t| t.shown.clone())],
        )?;
        Ok(json!({ "seq": seq, "hash": hash, "at": at, "keyId": cp.key.id, "publicKey": public, "signature": signature, "trigger": trigger, "timestamp": status }))
    })?;
    if tsa.is_some() {
        cp.wake.notify_one();
    }
    app.db.with_conn(|c| row(c, id))?.ok_or(rusqlite::Error::QueryReturnedNoRows)
}

/// Whether a scheduled checkpoint is due: `every` has passed since the last one, and
/// something besides checkpoints happened since.
fn due(c: &Connection, every_ms: i64, at: i64) -> rusqlite::Result<bool> {
    let last: Option<(i64, i64)> = c.query_row(&format!("SELECT event_id, at FROM audit_checkpoints WHERE {SEALED} ORDER BY event_id DESC LIMIT 1"), [], |r| Ok((r.get(0)?, r.get(1)?))).optional()?;
    if last.is_some_and(|(_, t)| t + every_ms > at) {
        return Ok(false);
    }
    let marks = vec!["?"; OWN.len()].join(", ");
    let sql = format!("SELECT EXISTS(SELECT 1 FROM audit_events WHERE id > ? AND action NOT IN ({marks}))");
    let mut values: Vec<rusqlite::types::Value> = vec![last.map_or(0, |l| l.0).into()];
    values.extend(OWN.iter().map(|a| rusqlite::types::Value::Text(a.to_string())));
    c.query_row(&sql, rusqlite::params_from_iter(values), |r| r.get(0))
}

async fn schedule(app: Arc<App>, cp: Arc<Checkpoints>) {
    let every_ms = (cp.settings.every * 60_000) as i64;
    if every_ms == 0 {
        return;
    }
    let by = Who::system("audit_checkpoint");
    loop {
        tokio::time::sleep(TICK).await;
        match app.db.with_conn(|c| due(c, every_ms, now())) {
            Ok(true) => {
                if let Err(e) = create(&app, &by, Trigger::Schedule) {
                    log_warn!("WARNING: couldn't record an audit checkpoint: {e}");
                }
            }
            Ok(false) => {}
            Err(e) => log_warn!("Audit checkpoints: couldn't read the audit log: {e}"),
        }
    }
}

async fn stamp_all(app: Arc<App>, cp: Arc<Checkpoints>) {
    let Some(tsa) = cp.settings.tsa.clone() else {
        return;
    };
    let http = reqwest::Client::builder().timeout(TIMEOUT).redirect(reqwest::redirect::Policy::none()).build().expect("HTTP client");
    let mut wait = FIRST_RETRY;
    loop {
        let next = match app.db.with_conn(pending) {
            Ok(Some(c)) => c,
            Ok(None) => {
                tokio::select! {
                    _ = cp.wake.notified() => {}
                    _ = tokio::time::sleep(IDLE) => {}
                }
                continue;
            }
            Err(e) => {
                log_warn!("Audit timestamps: couldn't read the checkpoints: {e}");
                tokio::time::sleep(jitter(wait)).await;
                continue;
            }
        };
        match stamp(&app, &cp, &http, &tsa, &next).await {
            Ok(()) => {
                if let Some((tries, since)) = cp.stamped() {
                    log_info!("Audit timestamps: {} is stamping checkpoints again after {tries} failed tries.", tsa.shown);
                    let e = Event::new(Actor::system("audit_timestamp"), RECOVERED).target("audit", "chain");
                    app.db.record(&e.details(json!({ "tsa": tsa.shown, "failedTries": tries, "failingSince": since })));
                }
                wait = FIRST_RETRY;
            }
            Err((reason, e)) => {
                let e = crate::secrets::redact::text(&e).into_owned();
                let _ = app.db.with_conn(|c| c.execute("UPDATE audit_checkpoints SET tsa_tries = tsa_tries + 1, tsa_error = ? WHERE event_id = ? AND tsa_status = 'pending'", params![e, next.id]));
                if cp.failed(&e) {
                    log_warn!("WARNING: timestamping audit checkpoints with {} is failing ({e}); they wait and are tried again.", tsa.shown);
                    let pending: i64 = app.db.with_conn(|c| c.query_row("SELECT count(*) FROM audit_checkpoints WHERE tsa_status = 'pending'", [], |r| r.get(0))).unwrap_or(0);
                    let ev = Event::new(Actor::system("audit_timestamp"), FAILING).target("audit", "chain").outcome(Outcome::Failure);
                    app.db.record(&ev.details(json!({ "tsa": tsa.shown, "reason": reason, "error": e, "pending": pending, "checkpoint": next.id })));
                }
                tokio::time::sleep(jitter(wait)).await;
                wait = (wait * 2).min(LAST_RETRY);
            }
        }
    }
}

/// From three quarters to all of `d`, so many servers don't retry in step.
fn jitter(d: Duration) -> Duration {
    let r = crate::random_bytes(1)[0] as u32;
    d.mul_f64(0.75 + 0.25 * r as f64 / 255.0)
}

/// Asks the TSA for a token for `c`, checks it, and records it. Errors carry a reason code.
async fn stamp(app: &App, cp: &Checkpoints, http: &reqwest::Client, tsa: &Tsa, c: &Checkpoint) -> Result<(), (&'static str, String)> {
    let mut nonce = crate::random_bytes(8);
    // Positive with no leading zero, so it comes back in DER exactly as sent.
    nonce[0] = (nonce[0] & 0x7f) | 0x40;
    let imprint = c.imprint();
    let failed = |e: reqwest::Error| ("unreachable", format!("couldn't reach {}: {}", tsa.shown, e.without_url()));
    let mut r = http.post(&tsa.url).header(reqwest::header::CONTENT_TYPE, "application/timestamp-query").body(tsa::request(&imprint, &nonce)).send().await.map_err(failed)?;
    if !r.status().is_success() {
        return Err(("refused", format!("{} answered HTTP {}", tsa.shown, r.status().as_u16())));
    }
    let mut der = Vec::new();
    while let Some(chunk) = r.chunk().await.map_err(failed)? {
        der.extend_from_slice(&chunk);
        if der.len() > tsa::MAX_REPLY {
            return Err(("malformed", format!("{} sent more than {} KiB", tsa.shown, tsa::MAX_REPLY / 1024)));
        }
    }
    let invalid = |e: tsa::Invalid| (e.code, format!("{}: {}", tsa.shown, e.message));
    let token = tsa::token_from_reply(&der).map_err(invalid)?;
    let stamp = tsa::verify(&token, &imprint, Some(&nonce), &cp.settings.trust).map_err(invalid)?;
    let encoded = b64().encode(&token);
    let e = Who::system("audit_timestamp").event(TIMESTAMPED).target("audit", "chain");
    app.db
        .record_with(&e, |db, id, _| {
            let n = db.execute(
                "UPDATE audit_checkpoints SET tsa_status = 'stamped', tsa = ?, tsa_token = ?, tsa_time = ?, tsa_nonce = ?, tsa_event_id = ?, tsa_error = NULL
                 WHERE event_id = ? AND tsa_status = 'pending'",
                params![tsa.shown, encoded, stamp.time, hex(&nonce), id, c.id],
            )?;
            if n == 0 {
                return Err(rusqlite::Error::QueryReturnedNoRows);
            }
            Ok(json!({
                "checkpoint": c.id, "seq": c.seq, "hash": c.hash, "tsa": tsa.shown, "time": stamp.time, "serial": stamp.serial, "policy": stamp.policy,
                "tsaCert": stamp.tsa_cert, "tsaSubject": crate::audit::clip(&stamp.tsa_subject, 200), "trusted": stamp.trusted,
                "timestampSha256": hex(&Sha256::digest(&token)),
            }))
        })
        .map_err(|e| ("unsaved", format!("couldn't save the timestamp: {e}")))?;
    Ok(())
}

/// A checkpoint or timestamp that doesn't hold, and why.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Fault {
    pub id: i64,
    /// `malformed`, `head` (it names another head than the one it's sealed onto), `key`
    /// (signed by a key not trusted), `signature`, `record` (its record in
    /// `audit_checkpoints` differs, is gone, or has no event), or the token's own:
    /// `imprint`, `nonce`, `certificate`, `untrusted`, ...
    pub reason: &'static str,
    pub error: String,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Last {
    pub id: i64,
    pub seq: i64,
    pub hash: String,
    pub at: i64,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LastStamp {
    /// The checkpoint, and the event recording its token.
    pub checkpoint: i64,
    pub id: i64,
    pub time: i64,
    pub tsa: Option<String>,
}

/// The checkpoints a check walked past.
#[derive(Clone, Debug, Default, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Checked {
    pub checked: u64,
    pub timestamped: u64,
    /// Tokens whose TSA chains to `AUDIT_TIMESTAMP_CA_FILE`; null when that isn't set.
    pub trusted_timestamps: Option<u64>,
    pub broken: u64,
    pub first_broken: Option<Fault>,
    pub last: Option<Last>,
    pub last_timestamp: Option<LastStamp>,
    /// The ids of the keys trusted.
    pub keys: Vec<String>,
}

type Lookup<'a> = Box<dyn FnMut(i64) -> Option<Checkpoint> + 'a>;

/// Checks checkpoints as the chain's verifier walks past them.
pub struct Checker<'a> {
    keys: Vec<Vec<u8>>,
    trust: &'a tsa::Trust,
    lookup: Lookup<'a>,
    /// Checkpoint events walked.
    walked: BTreeSet<i64>,
    /// Timestamp events walked, and the checkpoint each names.
    stamps: BTreeMap<i64, i64>,
    report: Checked,
}

impl<'a> Checker<'a> {
    pub fn new(keys: Vec<Vec<u8>>, trust: &'a tsa::Trust, lookup: Lookup<'a>) -> Checker<'a> {
        let report = Checked { keys: keys.iter().map(|k| key_id(k)).collect(), trusted_timestamps: trust.is_set().then_some(0), ..Default::default() };
        Checker { keys, trust, lookup, walked: BTreeSet::new(), stamps: BTreeMap::new(), report }
    }

    fn broke(&mut self, f: Fault) {
        self.report.broken += 1;
        if self.report.first_broken.as_ref().is_none_or(|b| f.id < b.id) {
            self.report.first_broken = Some(f);
        }
    }

    /// A row the chain holds, after `before` (None: not known): None, or why it breaks the
    /// chain (`checkpoint`, `timestamp`).
    pub fn feed(&mut self, r: &Row, before: Option<i64>) -> Option<&'static str> {
        match crate::audit_chain::action(r)? {
            CHECKPOINT => {
                self.report.checked += 1;
                self.walked.insert(r.id);
                let found = (self.lookup)(r.id);
                match check_checkpoint(r.id, r.prev.as_deref(), crate::audit_chain::details(r).as_ref(), before, found.as_ref(), &self.keys) {
                    Ok(()) => {
                        let d = crate::audit_chain::details(r).unwrap_or_default();
                        let num = |k: &str| d[k].as_i64().unwrap_or_default();
                        self.report.last = Some(Last { id: r.id, seq: num("seq"), hash: d["hash"].as_str().unwrap_or_default().into(), at: num("at") });
                        None
                    }
                    Err(f) => {
                        self.broke(f);
                        Some("checkpoint")
                    }
                }
            }
            TIMESTAMPED => {
                let d = crate::audit_chain::details(r);
                let cp = d.as_ref().and_then(|d| d["checkpoint"].as_i64());
                let found = cp.and_then(|id| (self.lookup)(id));
                // Retention keeps a record while its timestamp event is in the log, so a
                // missing one was removed by hand.
                if let Some(cp) = cp {
                    self.stamps.insert(r.id, cp);
                }
                match check_stamp(r.id, d.as_ref(), found.as_ref(), self.trust) {
                    Ok((c, s)) => {
                        self.report.timestamped += 1;
                        if let (Some(n), Some(true)) = (self.report.trusted_timestamps.as_mut(), s.trusted) {
                            *n += 1;
                        }
                        self.report.last_timestamp = Some(LastStamp { checkpoint: c.id, id: r.id, time: s.time, tsa: c.tsa.clone() });
                        None
                    }
                    Err(f) => {
                        self.broke(f);
                        Some("timestamp")
                    }
                }
            }
            _ => None,
        }
    }

    /// Records kept beside the chain with an event from `lo` to `hi`: each must name events
    /// walked, events logged after the walk (`last`, the last row walked), or, for a
    /// checkpoint pruned (up to `pruned`), the timestamp event that keeps it. Returns the
    /// breaks, by event.
    pub fn recorded(&mut self, rows: &[Recorded], lo: i64, hi: i64, last: Option<i64>, pruned: Option<i64>) -> Vec<(i64, &'static str)> {
        let within = |id: i64| (lo..=hi).contains(&id);
        let after = |id: i64| last.is_none_or(|l| id > l);
        let mut out = Vec::new();
        for r in rows {
            let id = r.id;
            if within(id) && !self.walked.contains(&id) && !(after(id) && r.id_logged) {
                let was_pruned = pruned.is_some_and(|p| id <= p);
                let kept = was_pruned && r.stamp.is_some_and(|t| !within(t) || self.stamps.get(&t) == Some(&id));
                if !kept {
                    let error = if was_pruned {
                        format!("checkpoint {id} was pruned, yet its record stayed without a timestamp event")
                    } else {
                        format!("a checkpoint record names event {id}, which isn't a checkpoint")
                    };
                    self.broke(Fault { id, reason: "record", error });
                    out.push((id, "checkpoint"));
                }
            }
            if let Some(t) = r.stamp.filter(|&t| within(t)) {
                let fine = if after(t) { r.stamp_logged } else { self.stamps.get(&t) == Some(&id) };
                if !fine {
                    self.broke(Fault { id: t, reason: "record", error: format!("checkpoint {id}'s token names event {t}, which doesn't record it") });
                    out.push((t, "timestamp"));
                }
            }
        }
        out
    }

    pub fn finish(self) -> Checked {
        self.report
    }
}

fn fault(id: i64, reason: &'static str, error: impl Into<String>) -> Fault {
    Fault { id, reason, error: error.into() }
}

/// Checks the `audit.checkpoint` event `id`, sealed onto `prev` after event `before`,
/// against its details, its signature, the keys trusted, and its record.
pub fn check_checkpoint(id: i64, prev: Option<&str>, d: Option<&Value>, before: Option<i64>, found: Option<&Checkpoint>, keys: &[Vec<u8>]) -> Result<(), Fault> {
    check_signed(id, prev, d, before, keys)?;
    let d = d.ok_or_else(|| fault(id, "malformed", "the checkpoint's details are missing a field"))?;
    let (s, n) = (|k: &str| d[k].as_str().unwrap_or_default(), |k: &str| d[k].as_i64().unwrap_or_default());
    let Some(c) = found else {
        return Err(fault(id, "record", "its record, with any timestamp, is gone"));
    };
    if (c.seq, c.hash.as_str(), c.at, c.key_id.as_str(), c.public_key.as_str(), c.signature.as_str()) != (n("seq"), s("hash"), n("at"), s("keyId"), s("publicKey"), s("signature")) {
        return Err(fault(id, "record", "its record differs from the event"));
    }
    Ok(())
}

/// The part of [`check_checkpoint`] that needs only the event: it names the head it is
/// sealed onto, and one of `keys` signed it. What the archive check uses (ADR 0163).
pub fn check_signed(id: i64, prev: Option<&str>, d: Option<&Value>, before: Option<i64>, keys: &[Vec<u8>]) -> Result<(), Fault> {
    let malformed = || fault(id, "malformed", "the checkpoint's details are missing a field");
    let d = d.ok_or_else(malformed)?;
    let s = |k: &str| d[k].as_str().ok_or_else(malformed);
    let n = |k: &str| d[k].as_i64().ok_or_else(malformed);
    let (seq, hash, at, kid, public, signature) = (n("seq")?, s("hash")?, n("at")?, s("keyId")?, s("publicKey")?, s("signature")?);
    if Some(hash) != prev || before.is_some_and(|b| b != seq) {
        return Err(fault(id, "head", format!("it signs event {seq}'s hash, not the head it is sealed onto")));
    }
    let public = parse_public_key(public).map_err(|e| fault(id, "malformed", e))?;
    if key_id(&public) != kid {
        return Err(fault(id, "key", format!("its key id {kid} isn't its key's")));
    }
    if !keys.contains(&public) {
        return Err(fault(id, "key", format!("signed by key {kid}, which isn't trusted")));
    }
    if !signed(&public, &statement(seq, hash, at, kid), signature) {
        return Err(fault(id, "signature", "its signature doesn't verify"));
    }
    Ok(())
}

/// Checks the `audit.checkpoint_timestamped` event `id` against the checkpoint record it
/// names and the RFC 3161 token stored there.
pub fn check_stamp<'c>(id: i64, d: Option<&Value>, found: Option<&'c Checkpoint>, trust: &tsa::Trust) -> Result<(&'c Checkpoint, tsa::Stamp), Fault> {
    let d = d.ok_or_else(|| fault(id, "malformed", "the timestamp's details are missing"))?;
    let Some(c) = found else {
        return Err(fault(id, "record", "the checkpoint it stamps has no record"));
    };
    if c.tsa_event_id != Some(id) || c.tsa_status != "stamped" || d["checkpoint"].as_i64() != Some(c.id) {
        return Err(fault(id, "record", format!("checkpoint {}'s record doesn't name this timestamp", c.id)));
    }
    let token = c.tsa_token.as_deref().and_then(|t| b64().decode(t).ok()).ok_or_else(|| fault(id, "record", "the stored token is missing or isn't base64"))?;
    if d["timestampSha256"].as_str() != Some(hex(&Sha256::digest(&token)).as_str()) {
        return Err(fault(id, "record", "the stored token isn't the one recorded"));
    }
    let nonce = c.tsa_nonce.as_deref().and_then(unhex);
    let s = tsa::verify(&token, &c.imprint(), nonce.as_deref(), trust).map_err(|e| fault(id, e.code, e.message))?;
    if Some(s.time) != c.tsa_time || d["time"].as_i64() != Some(s.time) {
        return Err(fault(id, "record", "the token's time isn't the one recorded"));
    }
    Ok((c, s))
}

/// What the SIEM export adds to checkpoint events: the record with its statement and
/// token, so the SIEM can check both without botd.
pub fn export_extras(db: &Db, rows: &[crate::db::AuditEvent]) -> BTreeMap<i64, Value> {
    let mut out = BTreeMap::new();
    for e in rows {
        let id = match e.action.as_str() {
            CHECKPOINT => Some(e.id),
            TIMESTAMPED => e.details["checkpoint"].as_i64(),
            _ => None,
        };
        if let Some(c) = id.and_then(|id| db.with_conn(|c| row(c, id)).ok().flatten()) {
            let mut v = c.view();
            if e.action == CHECKPOINT {
                // Its token comes later, with its own event.
                v["timestamp"] = json!({ "status": if c.tsa_status == "off" { "off" } else { "pending" }, "tsa": c.tsa });
            }
            out.insert(e.id, v);
        }
    }
    out
}

fn chain_head(c: &Connection) -> rusqlite::Result<Option<Link>> {
    c.query_row("SELECT id, chain_hash FROM audit_events WHERE chain_hash IS NOT NULL ORDER BY id DESC LIMIT 1", [], |r| Ok(Link { id: r.get(0)?, hash: r.get(1)? })).optional()
}

/// `GET /api/audit/chain` and `botctl audit chain`: the head, the last checkpoint and
/// timestamp, the export's lag, and the last check's result.
pub fn view(app: &App) -> rusqlite::Result<Value> {
    let cp = state(app);
    let (head, count, last, stamped, pending, last_stamp) = app.db.with_conn(|c| -> rusqlite::Result<_> {
        let count: i64 = c.query_row("SELECT count(*) FROM audit_checkpoints", [], |r| r.get(0))?;
        let last = list(c, i64::MAX, 1)?.pop();
        let stamped: i64 = c.query_row("SELECT count(*) FROM audit_checkpoints WHERE tsa_status = 'stamped'", [], |r| r.get(0))?;
        let pending: i64 = c.query_row("SELECT count(*) FROM audit_checkpoints WHERE tsa_status = 'pending'", [], |r| r.get(0))?;
        let last_stamp = c.query_row(&format!("SELECT {COLS} FROM audit_checkpoints WHERE tsa_status = 'stamped' AND {SEALED} ORDER BY event_id DESC LIMIT 1"), [], read).optional()?;
        Ok((chain_head(c)?, count, last, stamped, pending, last_stamp))
    })?;
    let s = cp.stamping();
    let verified = app.db.audit_events(&crate::audit::Filter { actions: vec!["audit.verified".into()], ..Default::default() }, 1, false).into_iter().next();
    let verification = verified.map(|e| {
        let d = &e.details;
        json!({
            "id": e.id, "at": e.at, "time": e.time, "by": e.actor_name.clone().or(e.actor_id.clone()), "actorKind": e.actor_kind,
            "ok": d["ok"], "reason": d["reason"], "checked": d["checked"], "broken": d["broken"], "firstBroken": d["firstBroken"],
            "head": d["head"], "range": d["range"], "checkpoints": d["checkpoints"],
        })
    });
    let events = app.db.audit_head();
    Ok(json!({
        "head": head,
        "events": events,
        "anchor": app.db.audit_chain_anchor(),
        "checkpoints": {
            "everyMinutes": cp.settings.every,
            "count": count,
            "key": { "id": cp.key.id, "publicKey": hex(&cp.key.public), "algorithm": "Ed25519" },
            "behind": last.as_ref().map_or(events, |c| (events - c.id).max(0)),
            "last": last.map(|c| c.view()),
        },
        "timestamps": {
            "enabled": cp.settings.tsa.is_some(),
            "tsa": cp.settings.tsa.as_ref().map(|t| t.shown.clone()),
            "trustAnchors": cp.settings.trust.len(),
            "stamped": stamped,
            "pending": pending,
            "failing": s.failing_since.is_some(),
            "failingSince": s.failing_since,
            "failedTries": s.failures,
            "lastError": s.last_error,
            "lastTry": s.last_try,
            "last": last_stamp.map(|c| json!({ "checkpoint": c.id, "event": c.tsa_event_id, "time": c.tsa_time, "tsa": c.tsa })),
        },
        "export": match app.audit_export.get() {
            Some(x) => x.view(events),
            None => json!({ "enabled": false }),
        },
        "verification": verification,
    }))
}

type HttpError = (axum::http::StatusCode, String);

fn internal(e: impl std::fmt::Display) -> HttpError {
    (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
}

/// `GET /api/audit/chain`. Admins only.
pub async fn get_chain(axum::extract::State(app): axum::extract::State<Arc<App>>) -> Result<axum::Json<Value>, HttpError> {
    view(&app).map(axum::Json).map_err(internal)
}

#[derive(serde::Deserialize)]
pub struct ListQuery {
    limit: Option<i64>,
    before: Option<i64>,
}

/// `GET /api/audit/checkpoints[?limit=<n>&before=<id>]`: newest first, with their tokens. Admins only.
pub async fn get_list(axum::extract::State(app): axum::extract::State<Arc<App>>, axum::extract::Query(q): axum::extract::Query<ListQuery>) -> Result<axum::Json<Value>, HttpError> {
    let limit = q.limit.unwrap_or(50).clamp(1, 500);
    let rows = app.db.with_conn(|c| list(c, q.before.unwrap_or(i64::MAX), limit)).map_err(internal)?;
    let next = (rows.len() as i64 == limit).then(|| rows.last().map(|c| c.id)).flatten();
    Ok(axum::Json(json!({ "checkpoints": rows.iter().map(Checkpoint::view).collect::<Vec<_>>(), "next": next })))
}

/// `POST /api/audit/checkpoints`: signs the head now. Admins only.
pub async fn post(axum::extract::State(app): axum::extract::State<Arc<App>>, axum::Extension(by): axum::Extension<Who>) -> Result<(axum::http::StatusCode, axum::Json<Value>), HttpError> {
    let c = create(&app, &by, Trigger::Api).map_err(internal)?;
    Ok((axum::http::StatusCode::CREATED, axum::Json(c.view())))
}

/// `GET /api/audit/checkpoints/key`: the public key checkpoints are signed with, and
/// every one used before. Admins only.
pub async fn get_key(axum::extract::State(app): axum::extract::State<Arc<App>>) -> axum::Json<Value> {
    let cp = state(&app);
    axum::Json(json!({ "id": cp.key.id, "publicKey": hex(&cp.key.public), "algorithm": "Ed25519", "statement": DOMAIN, "keys": known_keys(&app.db) }))
}

/// When the last checkpoint was signed and stamped, and how many wait for a timestamp.
pub fn render(app: &App, out: &mut String) {
    let Some(cp) = app.audit_checkpoints.get() else {
        return;
    };
    let (signed, stamped, pending) = app
        .db
        .with_conn(|c| -> rusqlite::Result<_> {
            let one = |sql: String| c.query_row(&sql, [], |r| r.get::<_, Option<i64>>(0));
            Ok((one(format!("SELECT max(at) FROM audit_checkpoints WHERE {SEALED}"))?, one(format!("SELECT max(tsa_time) FROM audit_checkpoints WHERE {SEALED}"))?, one("SELECT count(*) FROM audit_checkpoints WHERE tsa_status = 'pending'".into())?))
        })
        .unwrap_or_default();
    if let Some(t) = signed {
        metrics::family(out, "superbot_audit_checkpoint_last_timestamp_seconds", "gauge", "When botd last signed a checkpoint of the audit chain (ADR 0149).");
        metrics::sample(out, "superbot_audit_checkpoint_last_timestamp_seconds", &[], t as f64 / 1000.0);
    }
    if cp.settings.tsa.is_none() {
        return;
    }
    metrics::family(out, "superbot_audit_timestamp_pending_checkpoints", "gauge", "Audit checkpoints waiting for an RFC 3161 timestamp.");
    metrics::sample(out, "superbot_audit_timestamp_pending_checkpoints", &[], pending.unwrap_or(0) as f64);
    metrics::family(out, "superbot_audit_timestamp_failing", "gauge", "1 while timestamping audit checkpoints keeps failing.");
    metrics::sample(out, "superbot_audit_timestamp_failing", &[], cp.stamping().failing_since.is_some() as u8 as f64);
    if let Some(t) = stamped {
        metrics::family(out, "superbot_audit_timestamp_last_timestamp_seconds", "gauge", "The TSA's time on the newest audit checkpoint token.");
        metrics::sample(out, "superbot_audit_timestamp_last_timestamp_seconds", &[], t as f64 / 1000.0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit_chain::{Options, Range, verify_with};
    use crate::tsa::fake::FakeTsa;

    fn settings(vars: &[(&str, &str)]) -> Result<Settings, String> {
        let map: std::collections::HashMap<&str, &str> = vars.iter().copied().collect();
        Settings::from_env(&|k| map.get(k).map(|v| v.to_string()).unwrap_or_default())
    }

    #[test]
    fn settings_default_to_hourly_with_no_timestamps() {
        let s = settings(&[]).unwrap();
        assert_eq!((s.every, s.tsa.is_none(), s.trust.is_set()), (60, true, false));
        assert_eq!(settings(&[("AUDIT_CHECKPOINT_MINUTES", "0")]).unwrap().every, 0);
        assert_eq!(settings(&[("AUDIT_CHECKPOINT_MINUTES", "off")]).unwrap().every, 0);
        for bad in ["-1", "x", "100000"] {
            assert!(settings(&[("AUDIT_CHECKPOINT_MINUTES", bad)]).is_err(), "{bad}");
        }
        let s = settings(&[("AUDIT_TIMESTAMP_URL", "http://tsa.example:8080/tsr")]).unwrap();
        assert_eq!(s.tsa.unwrap().shown, "http://tsa.example:8080");
        for bad in ["ftp://tsa.example/", "https://user:pw@tsa.example/", "https://tsa.example/?key=1", "nope"] {
            assert!(settings(&[("AUDIT_TIMESTAMP_URL", bad)]).is_err(), "{bad}");
        }
        assert!(settings(&[("AUDIT_TIMESTAMP_CA_FILE", "/nonexistent/ca.pem")]).unwrap_err().contains("AUDIT_TIMESTAMP_CA_FILE"));
        let dir = crate::db::temp_path("checkpoint-ca");
        let path = dir.join("ca.pem");
        std::fs::write(&path, FakeTsa::new().ca_pem).unwrap();
        assert_eq!(settings(&[("AUDIT_TIMESTAMP_CA_FILE", path.to_str().unwrap())]).unwrap().trust.len(), 1);
    }

    #[test]
    fn signatures_verify_only_for_their_statement_and_key() {
        let k = Key::from_seed(&[7; 32]);
        let other = Key::from_seed(&[8; 32]);
        let s = statement(41, &"a".repeat(64), 1_000, &k.id);
        let sig = k.sign(&s);
        assert!(signed(&k.public, &s, &sig));
        assert!(!signed(&other.public, &s, &sig));
        assert!(!signed(&k.public, &statement(42, &"a".repeat(64), 1_000, &k.id), &sig));
        assert!(!signed(&k.public, &s, "zz"));
        assert_eq!(k.id.len(), 16);
        assert_eq!(parse_public_key(&hex(&k.public)).unwrap(), k.public);
        assert!(parse_public_key("abc").is_err());
        // Derived from the master key: the same every time.
        assert_eq!(Key::derive().public, Key::derive().public);
    }

    fn checks(app: &App, o: Options) -> crate::audit_chain::Report {
        verify_with(&app.db, &o)
    }

    fn some_events(app: &App, n: usize) -> Vec<i64> {
        (0..n).map(|i| app.db.try_record(&Event::new(Actor::system("test"), "test.thing").details(json!({ "n": i }))).unwrap()).collect()
    }

    #[test]
    fn checkpoints_sign_the_head_they_are_sealed_onto() {
        let app = crate::runner::test_app();
        some_events(&app, 3);
        remember_key(&app.db, &state(&app).key);
        let head = app.db.with_conn(chain_head).unwrap().unwrap();
        let c = create(&app, &Who::system("test"), Trigger::Api).unwrap();
        assert_eq!((c.seq, c.hash.as_str(), c.tsa_status.as_str()), (head.id, head.hash.as_str(), "off"));
        assert!(signed(&parse_public_key(&c.public_key).unwrap(), &c.statement(), &c.signature));
        some_events(&app, 2);
        create(&app, &Who::system("test"), Trigger::Schedule).unwrap();
        let r = checks(&app, Options::default());
        let k = r.checkpoints.clone().unwrap();
        assert!(r.ok, "{r:?}");
        assert_eq!((k.checked, k.broken, k.last.as_ref().map(|l| l.seq)), (2, 0, Some(c.id + 2)), "{k:?}");
        // The key is on record, as an event and in the history a later check trusts.
        assert_eq!(known_keys(&app.db).len(), 1);
        assert_eq!(app.db.audit_events(&crate::audit::Filter { actions: vec![KEY_ADDED.into()], ..Default::default() }, 10, false).len(), 1);
        // Another key isn't trusted when it's pinned instead.
        let r = checks(&app, Options { keys: Some(vec![Key::from_seed(&[9; 32]).public]), ..Default::default() });
        assert_eq!((r.ok, r.first_broken.as_ref().map(|b| (b.id, b.reason))), (false, Some((c.id, "checkpoint"))));
        assert_eq!(r.checkpoints.unwrap().first_broken.unwrap().reason, "key");
    }

    fn reseal(app: &App, from: i64) {
        crate::audit_chain::reseal_from(&app.db, from);
    }

    #[test]
    fn an_edited_row_is_caught_even_resealed() {
        let app = crate::runner::test_app();
        let ids = some_events(&app, 3);
        create(&app, &Who::system("test"), Trigger::Api).unwrap();
        some_events(&app, 1);
        // Someone with the database rewrites an event and rebuilds the chain from there.
        app.db.execute_raw("DROP TRIGGER audit_events_no_update").unwrap();
        app.db.execute_raw(&format!("UPDATE audit_events SET details = '{{\"n\":99}}' WHERE id = {}", ids[1])).unwrap();
        let r = checks(&app, Options::default());
        assert_eq!(r.first_broken.as_ref().map(|b| (b.id, b.reason)), Some((ids[1], "contents")));
        reseal(&app, ids[1]);
        let r = checks(&app, Options::default());
        let k = r.checkpoints.clone().unwrap();
        // The chain holds again, but the signed checkpoint names the old head.
        assert!(!r.ok, "{r:?}");
        assert_eq!(k.first_broken.as_ref().map(|f| f.reason), Some("head"), "{k:?}");
    }

    #[test]
    fn a_deleted_row_is_caught_even_resealed() {
        let app = crate::runner::test_app();
        let ids = some_events(&app, 4);
        let c = create(&app, &Who::system("test"), Trigger::Api).unwrap();
        app.db.execute_raw("DROP TRIGGER audit_events_no_delete").unwrap();
        app.db.execute_raw(&format!("DELETE FROM audit_events WHERE id = {}", ids[2])).unwrap();
        let r = checks(&app, Options::default());
        assert_eq!(r.first_broken.as_ref().map(|b| (b.id, b.reason)), Some((ids[3], "link")));
        app.db.execute_raw("DROP TRIGGER audit_events_no_update").unwrap();
        reseal(&app, ids[3]);
        let r = checks(&app, Options::default());
        assert!(!r.ok);
        assert_eq!(r.first_broken.as_ref().map(|b| (b.id, b.reason)), Some((c.id, "checkpoint")), "{r:?}");
    }

    #[test]
    fn a_forged_checkpoint_is_caught() {
        let app = crate::runner::test_app();
        some_events(&app, 2);
        let c = create(&app, &Who::system("test"), Trigger::Api).unwrap();
        some_events(&app, 1);
        // A checkpoint signed with another key, sealed properly onto the chain.
        let forger = Key::from_seed(&[1; 32]);
        let head = app.db.with_conn(chain_head).unwrap().unwrap();
        let at = now();
        let sig = forger.sign(&statement(head.id, &head.hash, at, &forger.id));
        let forged = app
            .db
            .record_with(&Event::new(Actor::system("audit_checkpoint"), CHECKPOINT), |db, id, _| {
                db.execute(
                    "INSERT INTO audit_checkpoints (event_id, at, seq, hash, key_id, public_key, signature, tsa_status) VALUES (?, ?, ?, ?, ?, ?, ?, 'off')",
                    params![id, at, head.id, head.hash, forger.id, hex(&forger.public), sig],
                )?;
                Ok(json!({ "seq": head.id, "hash": head.hash, "at": at, "keyId": forger.id, "publicKey": hex(&forger.public), "signature": sig }))
            })
            .unwrap();
        let r = checks(&app, Options::default());
        assert_eq!((r.first_broken.as_ref().map(|b| (b.id, b.reason)), r.checkpoints.unwrap().first_broken.unwrap().reason), (Some((forged, "checkpoint")), "key"));

        // The right key over the wrong statement doesn't pass either.
        let app = crate::runner::test_app();
        let ids = some_events(&app, 2);
        let c2 = create(&app, &Who::system("test"), Trigger::Api).unwrap();
        app.db.execute_raw("DROP TRIGGER audit_checkpoints_signed").unwrap();
        app.db.execute_raw(&format!("UPDATE audit_checkpoints SET seq = 1 WHERE event_id = {}", c2.id)).unwrap();
        let r = checks(&app, Options::default());
        assert_eq!(r.checkpoints.unwrap().first_broken.unwrap().reason, "record");
        // And a record with no event behind it is named.
        app.db
            .execute_raw(&format!(
                "INSERT INTO audit_checkpoints (event_id, at, seq, hash, key_id, public_key, signature, tsa_status) VALUES ({}, 0, 0, '{}', '{}', '{}', '{}', 'off')",
                ids[0], GENESIS, c.key_id, c.public_key, c.signature
            ))
            .unwrap();
        let r = checks(&app, Options::default());
        assert_eq!(r.first_broken.as_ref().map(|b| (b.id, b.reason)), Some((ids[0], "checkpoint")), "{r:?}");

        // Nor can a record past the head pose as the newest checkpoint, or put off the next.
        let app = crate::runner::test_app();
        some_events(&app, 1);
        let c = create(&app, &Who::system("test"), Trigger::Api).unwrap();
        some_events(&app, 1);
        let far = c.id + 1000;
        app.db
            .execute_raw(&format!(
                "INSERT INTO audit_checkpoints (event_id, at, seq, hash, key_id, public_key, signature, tsa_status) VALUES ({far}, {}, 0, '{}', '{}', '{}', '{}', 'off')",
                i64::MAX / 2, GENESIS, c.key_id, c.public_key, c.signature
            ))
            .unwrap();
        let r = checks(&app, Options::default());
        assert_eq!((r.ok, r.first_broken.as_ref().map(|b| (b.id, b.reason))), (false, Some((far, "checkpoint"))), "{r:?}");
        assert_eq!(view(&app).unwrap()["checkpoints"]["last"]["id"], c.id);
        assert!(app.db.with_conn(|x| due(x, 60_000, c.at + 60_000)).unwrap(), "scheduled from the real checkpoint");
    }

    #[test]
    fn ranges_check_only_their_rows_and_say_so() {
        let app = crate::runner::test_app();
        let ids = some_events(&app, 5);
        let c = create(&app, &Who::system("test"), Trigger::Api).unwrap();
        some_events(&app, 3);
        let r = checks(&app, Options { range: Range { from: Some(ids[2]), to: Some(c.id) }, ..Default::default() });
        assert!(r.ok, "{r:?}");
        assert_eq!((r.first, r.head.as_ref().map(|h| h.id), r.checkpoints.as_ref().unwrap().checked), (Some(ids[2]), Some(c.id), 1));
        // A pin outside the range is neither checked nor a failure.
        let pins = vec![Link { id: c.id + 2, hash: "0".repeat(64) }];
        let r = checks(&app, Options { pins, range: Range { from: None, to: Some(c.id) }, ..Default::default() });
        assert_eq!((r.ok, r.pins[0].result), (true, "outside"));
        // A break before the range isn't seen; one inside is.
        app.db.execute_raw("DROP TRIGGER audit_events_no_update").unwrap();
        app.db.execute_raw(&format!("UPDATE audit_events SET details = '{{\"n\":99}}' WHERE id = {}", ids[1])).unwrap();
        assert!(checks(&app, Options { range: Range { from: Some(ids[2]), to: None }, ..Default::default() }).ok);
        let r = checks(&app, Options { range: Range { from: Some(ids[1]), to: None }, ..Default::default() });
        assert_eq!(r.first_broken.map(|b| (b.id, b.reason)), Some((ids[1], "contents")));
    }

    /// Stamps `c` as the stamper does, with the fake TSA's token: the token and its event.
    fn stamp_by_hand(app: &App, fake: &FakeTsa, c: &Checkpoint) -> (Vec<u8>, i64) {
        app.db.execute_raw(&format!("UPDATE audit_checkpoints SET tsa_status = 'pending', tsa = 'http://tsa.test' WHERE event_id = {}", c.id)).unwrap();
        let mut nonce = crate::random_bytes(8);
        nonce[0] = (nonce[0] & 0x7f) | 0x40;
        let token = fake.token(&c.imprint(), Some(&nonce), 1_795_386_498_000);
        let ev = app
            .db
            .record_with(&Event::new(Actor::system("audit_timestamp"), TIMESTAMPED), |db, id, _| {
                db.execute(
                    "UPDATE audit_checkpoints SET tsa_status = 'stamped', tsa_token = ?, tsa_time = ?, tsa_nonce = ?, tsa_event_id = ? WHERE event_id = ?",
                    params![b64().encode(&token), 1_795_386_498_000i64, hex(&nonce), id, c.id],
                )?;
                Ok(json!({ "checkpoint": c.id, "time": 1_795_386_498_000i64, "timestampSha256": hex(&Sha256::digest(&token)) }))
            })
            .unwrap();
        (token, ev)
    }

    #[test]
    fn a_range_counts_a_later_erasure_only_as_part_of_the_chain() {
        let app = crate::runner::test_app();
        let ids = some_events(&app, 3);
        app.db.execute_raw("DROP TRIGGER audit_events_no_update").unwrap();
        app.db.execute_raw(&format!("UPDATE audit_events SET chain_salt = NULL WHERE id = {}", ids[1])).unwrap();
        let erased = app.db.with_conn(|c| crate::audit_chain::insert_erased(c, "p", &[ids[1]])).unwrap();
        some_events(&app, 1);
        let range = Range { from: Some(ids[0]), to: Some(ids[2]) };
        let r = checks(&app, Options { range, ..Default::default() });
        assert!(r.ok, "{r:?}");
        assert_eq!(r.range, Some(Range { from: Some(ids[0]), to: None }), "walked on past the erasure to the head");
        assert!(checks(&app, Options { range: Range { from: Some(ids[2]), to: Some(ids[2]) }, ..Default::default() }).range.unwrap().to.is_some(), "only as far as needed");
        // Someone clears another row and widens the erasure to name it, resealing just that event.
        app.db.execute_raw(&format!("UPDATE audit_events SET chain_salt = NULL WHERE id = {}", ids[0])).unwrap();
        app.db.execute_raw(&format!("UPDATE audit_events SET details = json_set(details, '$.rows', json('[[{}, {}]]')) WHERE id = {erased}", ids[0], ids[1])).unwrap();
        let row = app.db.audit_chain_rows(erased - 1, 1).unwrap().remove(0);
        let s = crate::audit_chain::seal(row.prev.as_deref().unwrap(), &row.fixed, &row.erasable);
        app.db.execute_raw(&format!("UPDATE audit_events SET chain_hash = '{}', chain_salt = '{}', chain_digest = '{}' WHERE id = {erased}", s.hash, s.salt, s.digest)).unwrap();
        let r = checks(&app, Options { range, ..Default::default() });
        assert_eq!((r.ok, r.first_broken.map(|b| (b.id, b.reason))), (false, Some((erased + 1, "link"))), "the erasure no longer links to what follows");
    }

    #[test]
    fn timestamps_are_checked_from_the_token() {
        let app = crate::runner::test_app();
        let fake = FakeTsa::new();
        some_events(&app, 2);
        let c = create(&app, &Who::system("test"), Trigger::Api).unwrap();
        let (_, ev) = stamp_by_hand(&app, &fake, &c);
        let r = checks(&app, Options::default());
        let k = r.checkpoints.clone().unwrap();
        assert!(r.ok, "{r:?}");
        assert_eq!((k.timestamped, k.trusted_timestamps, k.last_timestamp.map(|l| l.id)), (1, None, Some(ev)));
        let trust = tsa::Trust::from_pem(&fake.ca_pem).unwrap();
        let k = checks(&app, Options { trust, ..Default::default() }).checkpoints.unwrap();
        assert_eq!(k.trusted_timestamps, Some(1));
        let r = checks(&app, Options { trust: tsa::Trust::from_pem(&FakeTsa::new().ca_pem).unwrap(), ..Default::default() });
        assert_eq!((r.first_broken.map(|b| (b.id, b.reason)), r.checkpoints.unwrap().first_broken.unwrap().reason), (Some((ev, "timestamp")), "untrusted"));

        // Swapping in a token for something else is caught.
        app.db.execute_raw("DROP TRIGGER audit_checkpoints_signed").unwrap();
        let nonce = app.db.with_conn(|x| row(x, c.id)).unwrap().unwrap().tsa_nonce.and_then(|n| unhex(&n)).unwrap();
        let other = fake.token(&[0; 32], Some(&nonce), 1_795_386_498_000);
        app.db.execute_raw(&format!("UPDATE audit_checkpoints SET tsa_token = '{}' WHERE event_id = {}", b64().encode(&other), c.id)).unwrap();
        assert_eq!(checks(&app, Options::default()).checkpoints.unwrap().first_broken.unwrap().reason, "record");
        // Even with the event's hash of it rewritten and the chain resealed.
        app.db.execute_raw("DROP TRIGGER audit_events_no_update").unwrap();
        app.db.execute_raw(&format!("UPDATE audit_events SET details = json_set(details, '$.timestampSha256', '{}') WHERE id = {ev}", hex(&Sha256::digest(&other)))).unwrap();
        reseal(&app, ev);
        assert_eq!(checks(&app, Options::default()).checkpoints.unwrap().first_broken.unwrap().reason, "imprint");
    }

    #[test]
    fn retention_keeps_a_record_while_its_timestamp_event_is_in_the_log() {
        let app = crate::runner::test_app();
        let fake = FakeTsa::new();
        some_events(&app, 2);
        let c = create(&app, &Who::system("test"), Trigger::Api).unwrap();
        let (token, ev) = stamp_by_hand(&app, &fake, &c);
        let later = some_events(&app, 1)[0];
        // Ages events up to `last` past a 30-day window and prunes them.
        let prune_to = |last: i64| {
            app.db.execute_raw("DROP TRIGGER IF EXISTS audit_events_no_update").unwrap();
            app.db.execute_raw(&format!("UPDATE audit_events SET at = {} WHERE id <= {last}", now() - 40 * 86_400_000)).unwrap();
            reseal(&app, i64::MIN);
            app.db.set_audit_retention(Some(30));
            app.db.prune_audit(None).unwrap().1.map(|a| a.id)
        };
        // A long outage: the checkpoint goes before the timestamp event that came late.
        assert_eq!(prune_to(c.id), Some(c.id));
        assert!(app.db.with_conn(|x| row(x, c.id)).unwrap().is_some(), "kept for its timestamp event");
        let rows = app.db.audit_events(&crate::audit::Filter::default(), 100, true);
        assert_eq!(export_extras(&app.db, &rows)[&ev]["timestamp"]["token"].as_str(), Some(b64().encode(&token).as_str()));
        let r = checks(&app, Options::default());
        assert_eq!((r.ok, r.checkpoints.as_ref().unwrap().timestamped), (true, 1), "{r:?}");
        // A pruned checkpoint's record kept with no timestamp event is named.
        let stray = c.id - 1;
        app.db
            .execute_raw(&format!(
                "INSERT INTO audit_checkpoints (event_id, at, seq, hash, key_id, public_key, signature, tsa_status) VALUES ({stray}, 0, 0, '{}', '{}', '{}', '{}', 'off')",
                GENESIS, c.key_id, c.public_key, c.signature
            ))
            .unwrap();
        let r = checks(&app, Options::default());
        assert_eq!((r.ok, r.checkpoints.unwrap().first_broken.map(|f| (f.id, f.reason))), (false, Some((stray, "record"))));
        app.db.execute_raw(&format!("DELETE FROM audit_checkpoints WHERE event_id = {stray}")).unwrap();
        // Deleting the kept record doesn't let its timestamp event pass unchecked.
        app.db.execute_raw(&format!("CREATE TABLE kept AS SELECT * FROM audit_checkpoints WHERE event_id = {}", c.id)).unwrap();
        app.db.execute_raw(&format!("DELETE FROM audit_checkpoints WHERE event_id = {}", c.id)).unwrap();
        let r = checks(&app, Options::default());
        assert_eq!((r.first_broken.map(|b| (b.id, b.reason)), r.checkpoints.unwrap().first_broken.map(|f| f.reason)), (Some((ev, "timestamp")), Some("record")));
        app.db.execute_raw("INSERT INTO audit_checkpoints SELECT * FROM kept").unwrap();
        // Once its timestamp event goes too, so does the record.
        assert_eq!(prune_to(ev), Some(ev));
        assert!(app.db.with_conn(|x| row(x, c.id)).unwrap().is_none());
        let r = checks(&app, Options::default());
        assert_eq!((r.ok, r.first), (true, Some(later)), "{r:?}");
    }

    #[test]
    fn due_only_after_the_interval_and_new_events() {
        let app = crate::runner::test_app();
        let due_at = |t: i64| app.db.with_conn(|c| due(c, 60_000, t)).unwrap();
        some_events(&app, 1);
        assert!(due_at(now()));
        let c = create(&app, &Who::system("test"), Trigger::Schedule).unwrap();
        assert!(!due_at(c.at + 120_000), "only checkpoint events since");
        some_events(&app, 1);
        assert!(!due_at(c.at + 30_000));
        assert!(due_at(c.at + 60_000));
    }

    #[test]
    fn exports_carry_the_record() {
        let app = crate::runner::test_app();
        some_events(&app, 1);
        let c = create(&app, &Who::system("test"), Trigger::Api).unwrap();
        let rows = app.db.audit_events(&crate::audit::Filter::default(), 100, true);
        let extras = export_extras(&app.db, &rows);
        assert_eq!(extras.len(), 1);
        let v = &extras[&c.id];
        assert_eq!((v["statement"].as_str(), v["timestamp"]["status"].as_str()), (Some(c.statement().as_str()), Some("off")));
    }
}
