//! Whether every backup target is encrypted (ADR 0114): the server's archives in
//! BACKUP_DIR (superbot-backup, ADR 0030), their off-host copies (ADR 0109), machines'
//! off-host backups (ADR 0071) and regional chat stores' off-host copies (ADR 0246). All
//! use age, and botd only ever holds public keys.
//!
//! SUPERBOT_BACKUP_ENCRYPTION says what a plain target means: `auto` (the default) warns
//! at startup, keeps the setup checklist's item open and shows it in `/metrics`;
//! `required` refuses to start, and botd never copies a plain archive off the host;
//! `off` keeps backups plain by choice, which `/metrics` and the audit log still show.
//! Every change of policy or of which targets are plain is audited once, as
//! `server.backup_encryption_changed`.

use crate::audit::{Actor, Event};
use crate::machines::{backup, chat_store_copies};
use crate::obs::metrics;
use crate::runner::App;
use crate::server_backups::{self, ServerBackups};
use crate::AppState;
use serde_json::{Value, json};
use std::time::Duration;

/// Settings key: the last policy and plain targets audited, as `state_key` writes it.
const STATE: &str = "backup_encryption_state";
const ACTOR: &str = "backup-encryption";
/// How often botd looks again: a new archive may change what's encrypted.
const EVERY: Duration = Duration::from_secs(60);

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Policy {
    Auto,
    Required,
    Off,
}

impl Policy {
    pub fn as_str(self) -> &'static str {
        match self {
            Policy::Auto => "auto",
            Policy::Required => "required",
            Policy::Off => "off",
        }
    }

    /// SUPERBOT_BACKUP_ENCRYPTION: auto (or unset), required or off.
    pub fn from_env(var: &dyn Fn(&str) -> String) -> Result<Policy, String> {
        match var("SUPERBOT_BACKUP_ENCRYPTION").trim().to_ascii_lowercase().as_str() {
            "" | "auto" => Ok(Policy::Auto),
            "required" => Ok(Policy::Required),
            "off" => Ok(Policy::Off),
            other => Err(format!("SUPERBOT_BACKUP_ENCRYPTION must be auto, required or off, not \"{}\"", crate::audit::clip(other, 20))),
        }
    }
}

/// One backup target and whether what it holds now is encrypted.
#[derive(Clone, Debug, PartialEq)]
pub struct Target {
    /// `server_archives`, `server_copies`, `machines` or `chat_stores`: the label in `/metrics`.
    pub id: &'static str,
    pub label: &'static str,
    pub encrypted: bool,
    pub detail: String,
}

fn target(id: &'static str, label: &'static str, encrypted: bool, detail: String) -> Target {
    Target { id, label, encrypted, detail }
}

/// Every target this server has, from its settings and the newest archive in BACKUP_DIR.
/// `machines`: the off-host machine backups' settings, when they're on; `regional`: the
/// regional chat stores' off-host copies' (ADR 0246).
pub fn targets(sb: &ServerBackups, machines: Option<&backup::Settings>, regional: Option<&chat_store_copies::Settings>) -> Vec<Target> {
    let newest = server_backups::archives(&sb.dir).pop();
    let archives_encrypted = match &newest {
        Some(a) => a.encrypted,
        None => sb.archive_recipients,
    };
    let detail = match (&newest, sb.archive_recipients) {
        (Some(a), _) if a.encrypted => format!("superbot-backup encrypts them with age (newest: {})", a.name),
        (Some(a), true) => format!("the newest, {}, is plain; superbot-backup encrypts the next one to SUPERBOT_BACKUP_AGE_RECIPIENTS", a.name),
        (Some(a), false) => format!("the newest, {}, is plain: set SUPERBOT_BACKUP_AGE_RECIPIENTS", a.name),
        (None, true) => "none yet; superbot-backup encrypts them to SUPERBOT_BACKUP_AGE_RECIPIENTS".into(),
        (None, false) => format!("superbot-backup writes them plain into {}: set SUPERBOT_BACKUP_AGE_RECIPIENTS", sb.dir.display()),
    };
    let mut out = vec![target("server_archives", "Server archives on this host", archives_encrypted, detail)];
    if let Some(t) = &sb.target {
        let (encrypted, detail) = match (archives_encrypted, t.recipients.is_empty()) {
            (true, _) => (true, "copied as superbot-backup encrypted them".to_string()),
            (false, false) => (true, format!("plain archives are encrypted on the way to {} age recipients", t.recipients.len())),
            (false, true) => (false, "plain archives are copied plain: set SUPERBOT_BACKUP_AGE_RECIPIENTS (or SERVER_BACKUP_AGE_RECIPIENTS)".to_string()),
        };
        out.push(target("server_copies", "Server backups off this host", encrypted, detail));
    }
    if let Some(m) = machines {
        let detail = match m.recipients.len() {
            0 => "machines' backups are stored plain: set MACHINE_BACKUP_AGE_RECIPIENTS".to_string(),
            n => format!("encrypted to {n} age recipients"),
        };
        out.push(target("machines", "Machines' off-host backups", !m.recipients.is_empty(), detail));
    }
    if let Some(c) = regional {
        let detail = match c.recipients.len() {
            0 => "regional chat stores' backups are copied plain: set REGION_DATA_AGE_RECIPIENTS".to_string(),
            n => format!("encrypted to {n} age recipients"),
        };
        out.push(target("chat_stores", "Regional chat stores' off-host copies", !c.recipients.is_empty(), detail));
    }
    out
}

/// What the settings promise, not what's on disk now: with `required`, botd refuses to
/// start unless every target is set to be encrypted. An archive written plain before the
/// recipients were set doesn't stop botd, but it is never copied off the host plain.
pub fn check(sb: &ServerBackups, machines: Option<&backup::Settings>, regional: Option<&chat_store_copies::Settings>) -> Result<(), String> {
    if sb.encryption != Policy::Required {
        return Ok(());
    }
    let mut missing = Vec::new();
    if !sb.archive_recipients {
        missing.push("server archives (set SUPERBOT_BACKUP_AGE_RECIPIENTS)");
    }
    if sb.target.as_ref().is_some_and(|t| !sb.archive_recipients && t.recipients.is_empty()) {
        missing.push("server backups off this host (set SUPERBOT_BACKUP_AGE_RECIPIENTS, or SERVER_BACKUP_AGE_RECIPIENTS)");
    }
    if machines.is_some_and(|m| m.recipients.is_empty()) {
        missing.push("machines' off-host backups (set MACHINE_BACKUP_AGE_RECIPIENTS)");
    }
    if regional.is_some_and(|c| c.recipients.is_empty()) {
        missing.push("regional chat stores' off-host copies (set REGION_DATA_AGE_RECIPIENTS)");
    }
    match missing.is_empty() {
        true => Ok(()),
        false => Err(format!(
            "SUPERBOT_BACKUP_ENCRYPTION=required, but these backups would be plain: {}. Set the age public keys, or SUPERBOT_BACKUP_ENCRYPTION=auto (docs/ops/backup-restore.md#encryption)",
            missing.join("; ")
        )),
    }
}

fn machines(app: &App) -> Option<&backup::Settings> {
    app.control_plane.get().and_then(|cp| cp.offsite.as_ref()).map(|o| &o.s)
}

fn regional(app: &App) -> Option<&chat_store_copies::Settings> {
    app.control_plane.get().and_then(|cp| cp.chat_copies.as_deref()).map(|c| c.settings())
}

/// This server's targets now; none before server backups are set up.
pub fn current(app: &App) -> Option<(Policy, Vec<Target>)> {
    let sb = app.server_backups.get()?;
    Some((sb.encryption, targets(sb, machines(app), regional(app))))
}

/// The lines botd logs at startup: one summary, then a warning per plain target unless
/// plaintext was chosen (`off`).
pub fn startup_lines(policy: Policy, ts: &[Target]) -> (String, Vec<String>) {
    let plain: Vec<&Target> = ts.iter().filter(|t| !t.encrypted).collect();
    let summary = match (plain.is_empty(), policy) {
        (true, _) => format!("every target is encrypted ({}), SUPERBOT_BACKUP_ENCRYPTION={}", ts.iter().map(|t| t.id).collect::<Vec<_>>().join(", "), policy.as_str()),
        (false, Policy::Off) => format!(
            "plain by choice (SUPERBOT_BACKUP_ENCRYPTION=off): {}; anyone who gets a copy can read it",
            plain.iter().map(|t| t.id).collect::<Vec<_>>().join(", ")
        ),
        (false, _) => format!("{} of {} targets are plain, SUPERBOT_BACKUP_ENCRYPTION={}", plain.len(), ts.len(), policy.as_str()),
    };
    let warnings = match policy {
        Policy::Off => Vec::new(),
        _ => plain
            .iter()
            .map(|t| format!("{} aren't encrypted: {}. Anyone who gets a copy can read every chat and Bot's memory in it (docs/ops/backup-restore.md#encryption, ADR 0114).", t.label, t.detail))
            .collect(),
    };
    (summary, warnings)
}

fn state_key(policy: Policy, ts: &[Target]) -> String {
    let plain: Vec<&str> = ts.iter().filter(|t| !t.encrypted).map(|t| t.id).collect();
    format!("{} plain={}", policy.as_str(), plain.join(","))
}

/// Audits a change of policy or of which targets are plain, once. True if it recorded one.
pub fn watch(app: &App) -> bool {
    static WATCHING: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _one = WATCHING.lock().unwrap_or_else(|e| e.into_inner());
    let Some((policy, ts)) = current(app) else { return false };
    let key = state_key(policy, &ts);
    let previous = app.db.setting(STATE);
    if previous.as_deref() == Some(key.as_str()) {
        return false;
    }
    let ids = |enc: bool| ts.iter().filter(|t| t.encrypted == enc).map(|t| t.id).collect::<Vec<_>>();
    let plain = ids(false);
    let d = json!({
        "policy": policy.as_str(),
        "encrypted": ids(true),
        "unencrypted": plain,
        "plaintextAllowed": policy == Policy::Off && !plain.is_empty(),
        "previous": previous,
    });
    // The state is saved only once the event is, so a failed write is tried again next minute;
    // a crash in between repeats the event rather than losing it.
    if let Err(e) = app.db.try_record(&Event::new(Actor::system(ACTOR), "server.backup_encryption_changed").target("server", "backups").details(d)) {
        crate::obs::log::log_warn!("backup encryption: could not record the change, will try again: {e}");
        return false;
    }
    app.db.set_setting(STATE, &key);
    true
}

/// Audits the state at startup, then looks again every minute.
pub fn start(app: AppState) {
    watch(&app);
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(EVERY);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            watch(&app);
        }
    });
}

/// For `GET /api/backups` and `server.started`.
pub fn view(app: &App) -> Value {
    let Some((policy, ts)) = current(app) else { return Value::Null };
    json!({
        "policy": policy.as_str(),
        "allEncrypted": ts.iter().all(|t| t.encrypted),
        "targets": ts.iter().map(|t| json!({ "id": t.id, "label": t.label, "encrypted": t.encrypted, "detail": t.detail })).collect::<Vec<_>>(),
    })
}

/// The setup checklist's item: done when every target is encrypted. Plain by choice
/// (`off`) stays open, saying so.
pub fn checklist(app: &App) -> (bool, String) {
    let Some((policy, ts)) = current(app) else { return (false, "Server backups aren't set up on this server.".into()) };
    let plain: Vec<&Target> = ts.iter().filter(|t| !t.encrypted).collect();
    if plain.is_empty() {
        return (true, format!("Encrypted with age: {}. Keep the age identity off this host; restoring needs it.", ts.iter().map(|t| t.label.to_lowercase()).collect::<Vec<_>>().join(", ")));
    }
    let list = plain.iter().map(|t| format!("{}: {}", t.label, t.detail)).collect::<Vec<_>>().join(". ");
    match policy {
        Policy::Off => (false, format!("Plain by choice (SUPERBOT_BACKUP_ENCRYPTION=off). {list}.")),
        _ => (false, format!("{list}. See docs/ops/backup-restore.md#encryption.")),
    }
}

/// The gauges `/metrics` shows: each target's encryption, and whether plaintext is allowed.
pub fn render(app: &App, out: &mut String) {
    let Some((policy, ts)) = current(app) else { return };
    metrics::family(out, "superbot_backup_encrypted", "gauge", "1 when a backup target is age-encrypted, 0 when it is plain (ADR 0114).");
    for t in &ts {
        metrics::sample(out, "superbot_backup_encrypted", &[("target", t.id)], t.encrypted as u8 as f64);
    }
    metrics::family(out, "superbot_backup_plaintext_allowed", "gauge", "1 when SUPERBOT_BACKUP_ENCRYPTION=off keeps backups plain by choice.");
    metrics::sample(out, "superbot_backup_plaintext_allowed", &[], (policy == Policy::Off) as u8 as f64);
}
