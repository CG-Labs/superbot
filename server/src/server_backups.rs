//! Off-host copies of the server's own backups (ADR 0109). `superbot-backup` (ADR 0030)
//! writes archives of `DATA_DIR` into `BACKUP_DIR`, from the installer's timer or the
//! Compose sidecar. botd watches that folder and copies the newest finished archive to
//! S3-compatible storage with the same client as machine backups (ADR 0071): to
//! `SERVER_BACKUP_S3_BUCKET`, or, when that isn't set, to the machine backups' bucket
//! under its own `server/` prefix. An archive superbot-backup already encrypted is
//! copied as it is; a plain one is age-encrypted on the way when botd has recipients.
//! Each copy has a manifest beside it, is audited, kept for `SERVER_BACKUP_RETENTION_DAYS`
//! (the newest always), and held to an RPO that is alerted and shown in `/metrics`.
//!
//! With no target, nothing is copied and the gap is shown: a warning at startup, the
//! setup checklist, `GET /api/backups`, and `superbot_server_backup_off_host 0`.

use crate::audit::{Actor, Event, Outcome, Who};
use crate::db::{NewServerBackup, ServerBackup, now};
use crate::machines::backup;
use crate::machines::provider::ByteStream;
use crate::machines::s3::{self, S3};
use crate::notify::{self, Alert};
use crate::obs::metrics;
use crate::runner::App;
use crate::secrets::SecretStore;
use crate::{ApiError, AppState, Res};
use axum::Json;
use axum::body::Bytes;
use axum::extract::{Extension, State};
use axum::http::StatusCode;
use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncReadExt;

/// The settings that name a store of the server's own.
pub const NAME: &str = "SERVER_BACKUP_S3";
/// The manifest's format, beside each copy in the store.
pub const FORMAT: &str = "superbot-server-backup/1";
/// The RPO when neither SERVER_BACKUP_RPO_HOURS nor SUPERBOT_BACKUP_INTERVAL says: the
/// daily archive plus ADR 0074's headroom for a failed copy and its retry.
pub const DEFAULT_RPO_HOURS: i64 = 24 + backup::RPO_HEADROOM_HOURS;
pub const DEFAULT_RETENTION_DAYS: i64 = 30;
/// A copy that failed is tried again after this long.
pub const RETRY_MS: i64 = 30 * 60_000;
/// How often botd looks for a new archive.
pub const EVERY: Duration = Duration::from_secs(60);
const HOUR_MS: i64 = 3_600_000;
const DAY_MS: i64 = 86_400_000;
/// Settings keys: when copies were first turned on, and when the open RPO breach began.
const SINCE: &str = "server_backup_since";
const BREACH: &str = "server_backup_rpo_breach";
/// The console page alerts link to.
const PAGE: &str = "audit";
const ACTOR: &str = "server-backups";

/// SERVER_BACKUP_OFF_HOST: `auto` copies when a target is set, `on` refuses to start
/// without one, `off` never copies.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Mode {
    Auto,
    On,
    Off,
}

impl Mode {
    pub fn as_str(self) -> &'static str {
        match self {
            Mode::Auto => "auto",
            Mode::On => "on",
            Mode::Off => "off",
        }
    }
}

/// Which settings name the store: the server's own, or the machine backups'.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Source {
    Own,
    Machines,
}

impl Source {
    pub fn as_str(self) -> &'static str {
        match self {
            Source::Own => NAME,
            Source::Machines => s3::MACHINES,
        }
    }
}

/// Where copies go.
pub struct Target {
    pub s3: S3,
    pub store: s3::Settings,
    /// Starts every key, ending in `/` unless empty; copies go under `<prefix>server/`.
    pub prefix: String,
    pub source: Source,
    /// Who plain archives are encrypted to on the way. Empty: they're copied as they are.
    pub recipients: Vec<age::x25519::Recipient>,
}

impl Target {
    pub fn new(store: s3::Settings, prefix: &str, source: Source, recipients: Vec<age::x25519::Recipient>) -> Result<Target, String> {
        Ok(Target { s3: S3::new(store.clone())?, store, prefix: prefix.into(), source, recipients })
    }

    fn folder(&self) -> String {
        format!("{}server/", self.prefix)
    }

    /// Which copies count: only those made to this store and folder.
    pub fn destination(&self) -> String {
        format!("{}/{}/{}", self.store.endpoint, self.store.bucket, self.folder())
    }
}

pub struct ServerBackups {
    pub mode: Mode,
    /// Where superbot-backup writes archives.
    pub dir: PathBuf,
    /// None: archives stay on this host.
    pub target: Option<Target>,
    pub rpo_ms: i64,
    /// None: botd never deletes copies (the bucket's own lifecycle rules do).
    pub retention_days: Option<i64>,
    /// SUPERBOT_BACKUP_AGE_RECIPIENTS (or `_FILE`) is set, so superbot-backup encrypts
    /// archives. Only whether it is set: botd never reads the keys (ADR 0114).
    pub archive_recipients: bool,
    /// SUPERBOT_BACKUP_ENCRYPTION (ADR 0114).
    pub encryption: crate::backup_encryption::Policy,
}

fn rpo_hours(var: &dyn Fn(&str) -> String) -> Result<i64, String> {
    let raw = var("SERVER_BACKUP_RPO_HOURS");
    if !raw.trim().is_empty() {
        return raw
            .trim()
            .parse::<i64>()
            .ok()
            .filter(|h| (2..=744).contains(h))
            .ok_or(format!("SERVER_BACKUP_RPO_HOURS: \"{}\" isn't 2 to 744 hours", crate::audit::clip(raw.trim(), 20)));
    }
    // Compose's sidecar archives every SUPERBOT_BACKUP_INTERVAL seconds; botd reads it
    // only as a hint, so a value it can't read changes nothing.
    match var("SUPERBOT_BACKUP_INTERVAL").trim().parse::<i64>() {
        Ok(s) if s > 0 => Ok(((s + HOUR_MS / 1000 - 1) / (HOUR_MS / 1000) + backup::RPO_HEADROOM_HOURS).min(744)),
        _ => Ok(DEFAULT_RPO_HOURS),
    }
}

fn retention(raw: &str) -> Result<Option<i64>, String> {
    match raw.trim() {
        "" => Ok(Some(DEFAULT_RETENTION_DAYS)),
        r if r.eq_ignore_ascii_case("off") => Ok(None),
        r => r
            .parse::<i64>()
            .ok()
            .filter(|d| (1..=3650).contains(d))
            .map(Some)
            .ok_or(format!("SERVER_BACKUP_RETENTION_DAYS: \"{}\" isn't off or 1 to 3650 days", crate::audit::clip(r, 20))),
    }
}

impl ServerBackups {
    /// SERVER_BACKUP_OFF_HOST (auto), BACKUP_DIR (`backups` beside DATA_DIR, as
    /// superbot-backup has it in both installs), SERVER_BACKUP_S3_BUCKET with its
    /// ENDPOINT, REGION, PREFIX and keys, else MACHINE_BACKUP_S3_*'s store,
    /// SERVER_BACKUP_AGE_RECIPIENTS (or `_FILE`; with the machines' store, theirs when
    /// unset), SERVER_BACKUP_RPO_HOURS and SERVER_BACKUP_RETENTION_DAYS.
    pub fn from_env(store: &dyn SecretStore, var: &dyn Fn(&str) -> String, data_dir: &Path) -> Result<ServerBackups, String> {
        let mode = match var("SERVER_BACKUP_OFF_HOST").trim().to_ascii_lowercase().as_str() {
            "" | "auto" => Mode::Auto,
            "on" => Mode::On,
            "off" => Mode::Off,
            other => return Err(format!("SERVER_BACKUP_OFF_HOST must be auto, on or off, not \"{}\"", crate::audit::clip(other, 20))),
        };
        let dir = match var("BACKUP_DIR").trim() {
            "" => data_dir.parent().unwrap_or(Path::new(".")).join("backups"),
            d => PathBuf::from(d),
        };
        let rpo_ms = rpo_hours(var)? * HOUR_MS;
        let retention_days = retention(&var("SERVER_BACKUP_RETENTION_DAYS"))?;
        let set = |k: &&&str| !var(k).trim().is_empty();
        let own = !var("SERVER_BACKUP_S3_BUCKET").trim().is_empty();
        if !own && let Some(k) = ["SERVER_BACKUP_S3_ENDPOINT", "SERVER_BACKUP_S3_REGION", "SERVER_BACKUP_S3_PREFIX"].iter().find(set) {
            return Err(format!("{k} is set but SERVER_BACKUP_S3_BUCKET isn't; set the bucket or unset {k}"));
        }
        let target = if mode == Mode::Off {
            None
        } else if own {
            let s = s3::Settings::from_env_named(NAME, store, var)?;
            let prefix = backup::prefix("SERVER_BACKUP_S3_PREFIX", &var("SERVER_BACKUP_S3_PREFIX"))?;
            let recipients = backup::recipients_from_env("SERVER_BACKUP_AGE_RECIPIENTS", var)?;
            Some(Target::new(s, &prefix, Source::Own, recipients)?)
        } else if !var("MACHINE_BACKUP_S3_BUCKET").trim().is_empty() {
            let s = s3::Settings::from_env(store, var)?;
            let prefix = backup::prefix("MACHINE_BACKUP_S3_PREFIX", &var("MACHINE_BACKUP_S3_PREFIX"))?;
            let mut recipients = backup::recipients_from_env("SERVER_BACKUP_AGE_RECIPIENTS", var)?;
            if recipients.is_empty() {
                recipients = backup::recipients_from_env("MACHINE_BACKUP_AGE_RECIPIENTS", var)?;
            }
            Some(Target::new(s, &prefix, Source::Machines, recipients)?)
        } else {
            None
        };
        if target.is_none() && mode == Mode::Auto {
            let needs = ["SERVER_BACKUP_RPO_HOURS", "SERVER_BACKUP_RETENTION_DAYS", "SERVER_BACKUP_AGE_RECIPIENTS", "SERVER_BACKUP_AGE_RECIPIENTS_FILE"];
            if let Some(k) = needs.iter().find(set) {
                return Err(format!("{k} is set but there is nowhere to copy server backups to; set SERVER_BACKUP_S3_BUCKET or unset {k}"));
            }
        }
        if mode == Mode::On && target.is_none() {
            return Err("SERVER_BACKUP_OFF_HOST=on, but no store is set: set SERVER_BACKUP_S3_BUCKET (or MACHINE_BACKUP_S3_BUCKET) and its endpoint and keys".into());
        }
        let archive_recipients = ["SUPERBOT_BACKUP_AGE_RECIPIENTS", "SUPERBOT_BACKUP_AGE_RECIPIENTS_FILE"].iter().any(|k| !var(k).trim().is_empty());
        let encryption = crate::backup_encryption::Policy::from_env(var)?;
        Ok(ServerBackups { mode, dir, target, rpo_ms, retention_days, archive_recipients, encryption })
    }

    /// For tests: copying to `target` from `dir`, with the defaults.
    #[cfg(test)]
    pub fn with(dir: &Path, target: Option<Target>) -> ServerBackups {
        ServerBackups {
            mode: Mode::Auto,
            dir: dir.into(),
            target,
            rpo_ms: DEFAULT_RPO_HOURS * HOUR_MS,
            retention_days: Some(DEFAULT_RETENTION_DAYS),
            archive_recipients: false,
            encryption: crate::backup_encryption::Policy::Auto,
        }
    }

    fn kept(&self) -> String {
        match self.retention_days {
            Some(d) => format!("kept {d} days"),
            None => "kept until the bucket's own rules delete them".into(),
        }
    }

    /// For botd's startup log.
    pub fn describe(&self) -> String {
        let dir = self.dir.display();
        match &self.target {
            Some(t) => format!(
                "copying archives from {dir} to {}/{}/{} ({}), RPO {}h, {}, {}",
                t.store.endpoint,
                t.store.bucket,
                t.folder(),
                t.source.as_str(),
                self.rpo_ms / HOUR_MS,
                self.kept(),
                if t.recipients.is_empty() {
                    "plain archives copied unencrypted (set SUPERBOT_BACKUP_AGE_RECIPIENTS)".to_string()
                } else {
                    format!("plain archives encrypted to {} age recipients on the way", t.recipients.len())
                }
            ),
            None => format!("off ({}): archives in {dir} stay on this host", self.why_not().unwrap_or_default()),
        }
    }

    /// Why nothing is copied, if it isn't: shown in the startup warning, the setup
    /// checklist and `GET /api/backups`.
    pub fn why_not(&self) -> Option<String> {
        match (&self.target, self.mode) {
            (Some(_), _) => None,
            (None, Mode::Off) => Some("SERVER_BACKUP_OFF_HOST=off".into()),
            (None, _) => Some("no store is set: SERVER_BACKUP_S3_BUCKET, or MACHINE_BACKUP_S3_BUCKET".into()),
        }
    }

    /// The warning botd logs, and shows admins, while archives stay on this host.
    pub fn warning(&self) -> Option<String> {
        let why = self.why_not()?;
        Some(format!(
            "server backups stay on this host ({why}), so losing the host loses them. Copy them off with SERVER_BACKUP_S3_BUCKET (docs/ops/backup-restore.md, ADR 0109)."
        ))
    }
}

// Archives

/// A finished archive superbot-backup wrote.
#[derive(Clone, Debug, PartialEq)]
pub struct Archive {
    pub name: String,
    pub path: PathBuf,
    /// When it was made: the time in its name, else when it was written.
    pub created_at: i64,
    /// Its place among archives made in the same second (`-1`, `-2`, ...).
    pub seq: u32,
    /// superbot-backup encrypted it (`.age`).
    pub encrypted: bool,
}

/// The time in an archive's name: `superbot-YYYYmmdd-HHMMSS...`, UTC.
pub fn named_time(name: &str) -> Option<i64> {
    let stamp = name.strip_prefix("superbot-")?.get(..15)?;
    chrono::NaiveDateTime::parse_from_str(stamp, "%Y%m%d-%H%M%S").ok().map(|t| t.and_utc().timestamp_millis())
}

/// superbot-backup's `-n` after the time, for a second archive in the same second; 0 without.
pub fn named_seq(name: &str) -> u32 {
    let rest = name.strip_prefix("superbot-").and_then(|n| n.get(15..)).unwrap_or_default();
    rest.strip_prefix('-').and_then(|r| r.split('.').next()).and_then(|n| n.parse().ok()).unwrap_or(0)
}

/// Whether `name` is an archive superbot-backup finished: it writes `.partial-*` first and
/// renames it when done. Plain names only, as they become keys in the store.
fn archive_name(name: &str) -> Option<bool> {
    let plain = name.len() <= 100 && name.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b));
    if !plain || !name.starts_with("superbot-") {
        return None;
    }
    if name.ends_with(".tar.gz.age") {
        Some(true)
    } else if name.ends_with(".tar.gz") {
        Some(false)
    } else {
        None
    }
}

/// Every finished archive in `dir`, oldest first. Links and folders aren't archives.
pub fn archives(dir: &Path) -> Vec<Archive> {
    let Ok(entries) = std::fs::read_dir(dir) else { return Vec::new() };
    let mut out: Vec<Archive> = entries
        .filter_map(Result::ok)
        .filter_map(|e| {
            let name = e.file_name().into_string().ok()?;
            let encrypted = archive_name(&name)?;
            let meta = std::fs::symlink_metadata(e.path()).ok().filter(|m| m.is_file())?;
            let written = meta.modified().ok().and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok()).map_or(0, |d| d.as_millis() as i64);
            Some(Archive { created_at: named_time(&name).unwrap_or(written), seq: named_seq(&name), path: e.path(), name, encrypted })
        })
        .collect();
    out.sort_by(|a, b| (a.created_at, a.seq, &a.name).cmp(&(b.created_at, b.seq, &b.name)));
    out
}

fn manifest_key(object: &str) -> String {
    let base = object.strip_suffix(".age").unwrap_or(object);
    format!("{}.json", base.strip_suffix(".tar.gz").unwrap_or(base))
}

/// The file, a MiB at a time.
fn read(file: tokio::fs::File) -> ByteStream {
    Box::pin(futures_util::stream::unfold(Some(file), |f| async move {
        let mut f = f?;
        let mut buf = vec![0u8; 1 << 20];
        match f.read(&mut buf).await {
            Ok(0) => None,
            Ok(n) => {
                buf.truncate(n);
                Some((Ok(Bytes::from(buf)), Some(f)))
            }
            Err(e) => Some((Err(e), None)),
        }
    }))
}

fn event(action: &str, b: &ServerBackup, details: Value) -> Event {
    Event::new(Actor::system(ACTOR), action).target("server_backup", &b.id).details(details)
}

fn time(ms: i64) -> String {
    chrono::DateTime::from_timestamp_millis(ms).map(|t| t.format("%Y-%m-%d %H:%M UTC").to_string()).unwrap_or_default()
}

fn ago(ms: i64) -> String {
    let h = ms as f64 / HOUR_MS as f64;
    if h < 1.0 { format!("{} minutes", (ms / 60_000).max(0)) } else { format!("{h:.1} hours") }
}

fn alert(app: &AppState, action: &str, title: &str, lines: Vec<String>) {
    let a = Alert { event: action.into(), title: title.into(), lines, target_type: "server".into(), target_id: "backups".into(), link: None };
    notify::alert(app, a, PAGE);
}

// Copies

/// The archive to copy now, if one is due: the newest, unless it's copied or being
/// copied to this store, is no newer than its newest copy there, or failed less than
/// RETRY_MS ago.
pub fn due(app: &App, sb: &ServerBackups) -> Option<Archive> {
    let dest = sb.target.as_ref()?.destination();
    let newest = archives(&sb.dir).pop()?;
    if app.db.server_last_backup(&dest).is_some_and(|b| (b.created_at, named_seq(&b.archive)) >= (newest.created_at, newest.seq)) {
        return None;
    }
    match app.db.server_backups_of(&dest, &newest.name).first() {
        None => Some(newest),
        Some(b) if b.state == "failed" && now() - b.started_at >= RETRY_MS => Some(newest),
        Some(_) => None,
    }
}

/// Copies `a` to the store with its manifest. None if a copy is running already.
async fn copy(app: &App, sb: &ServerBackups, t: &Target, a: &Archive, by: Option<&Who>) -> Option<ServerBackup> {
    let botd_encrypts = !a.encrypted && !t.recipients.is_empty();
    let object = format!("{}{}{}", t.folder(), a.name, if botd_encrypts { ".age" } else { "" });
    let encrypted_by = if a.encrypted { Some("archive") } else if botd_encrypts { Some("botd") } else { None };
    let id = format!("sb{}", crate::random_hex(8));
    let dest = t.destination();
    let n = NewServerBackup { id: &id, archive: &a.name, destination: &dest, object_key: &object, created_at: a.created_at, encrypted_by };
    let b = app.db.server_backup_start(&n)?;
    let res: Result<(u64, String), String> = async {
        if !a.encrypted && !botd_encrypts && sb.encryption == crate::backup_encryption::Policy::Required {
            return Err(format!(
                "SUPERBOT_BACKUP_ENCRYPTION=required: {} is plain and botd has no recipients to encrypt it to, so it isn't copied (set SERVER_BACKUP_AGE_RECIPIENTS, or let superbot-backup write an encrypted archive)",
                a.name
            ));
        }
        let file = tokio::fs::File::open(&a.path).await.map_err(|e| format!("opening {} in BACKUP_DIR: {e}", a.name))?;
        let recipients = if botd_encrypts { &t.recipients[..] } else { &[] };
        let (size, sha) = backup::send(&t.s3, recipients, read(file), &object, "BACKUP_DIR").await?;
        let manifest = json!({
            "format": FORMAT, "copyId": b.id, "archive": a.name, "createdAt": a.created_at, "copiedAt": now(),
            "object": object, "size": size, "sha256": sha, "encrypted": b.encrypted, "encryptedBy": encrypted_by,
            "recipients": if botd_encrypts { t.recipients.iter().map(|r| r.to_string()).collect::<Vec<_>>() } else { Vec::new() },
            "botdVersion": env!("CARGO_PKG_VERSION"),
        });
        if let Err(e) = t.s3.put(&manifest_key(&object), serde_json::to_vec_pretty(&manifest).unwrap_or_default()).await {
            let _ = t.s3.delete(&object).await;
            return Err(e);
        }
        Ok((size, sha))
    }
    .await;
    let requested = by.and_then(|w| w.actor.id.clone());
    match res {
        Ok((size, sha)) => {
            let expires = sb.retention_days.map(|d| a.created_at + d * DAY_MS);
            if app.db.server_backup_end(&b.id, Some((size as i64, &sha, expires)), None) {
                let d = json!({
                    "archive": a.name, "object": object, "bucket": t.store.bucket, "store": t.source.as_str(), "size": size, "sha256": sha,
                    "encrypted": b.encrypted, "encryptedBy": encrypted_by, "createdAt": a.created_at, "expiresAt": expires, "requestedBy": requested,
                });
                app.db.record(&event("server.backup_copied", &b, d));
            }
        }
        Err(e) => {
            crate::obs::log::log_warn!("Server backups: copying {} off the host failed: {e}", a.name);
            if app.db.server_backup_end(&b.id, None, Some(&e)) {
                let d = json!({ "archive": a.name, "object": object, "bucket": t.store.bucket, "error": e, "requestedBy": requested });
                app.db.record(&event("server.backup_copy_failed", &b, d).outcome(Outcome::Failure));
            }
        }
    }
    app.db.server_backup(&id)
}

/// Deletes copies in this store older than the retention set now, never the newest.
/// With retention off, nothing. Returns how many went.
pub async fn prune(app: &App, sb: &ServerBackups, t: &Target) -> usize {
    let Some(days) = sb.retention_days else { return 0 };
    let cutoff = now() - days * DAY_MS;
    let dest = t.destination();
    let newest = app.db.server_last_backup(&dest).map(|b| b.id);
    let mut gone = 0;
    for b in app.db.server_backups_in("done").into_iter().filter(|b| b.destination == dest && b.created_at <= cutoff) {
        if newest.as_ref() == Some(&b.id) {
            continue;
        }
        let res = match t.s3.delete(&b.object_key).await {
            Ok(()) => t.s3.delete(&manifest_key(&b.object_key)).await,
            Err(e) => Err(e),
        };
        match res {
            Ok(()) if app.db.server_backup_deleted(&b.id) => {
                gone += 1;
                let d = json!({ "archive": b.archive, "object": b.object_key, "reason": "retention", "retentionDays": days, "createdAt": b.created_at });
                app.db.record(&event("server.backup_deleted", &b, d));
            }
            Ok(()) => {}
            Err(e) => crate::obs::log::log_warn!("Server backups: deleting {} past its retention: {e}", b.archive),
        }
    }
    gone
}

/// Where the server's backups stand against the RPO.
pub struct Status {
    pub last: Option<ServerBackup>,
    /// The newest moment whose data is off the host: the newest copied archive was made,
    /// or, before the first copy, copies were turned on.
    pub covered_since: Option<i64>,
    pub breach: bool,
    pub breached_at: Option<i64>,
}

/// When copies to `dest` were turned on: SINCE holds `<ms> <destination>`.
fn since(app: &App, dest: &str) -> Option<i64> {
    let v = app.db.setting(SINCE)?;
    let (ms, d) = v.split_once(' ')?;
    if d == dest { ms.parse().ok() } else { None }
}

/// Starts the RPO clock for a store copies weren't going to before.
fn mark_since(app: &App, t: &Target) {
    let dest = t.destination();
    if since(app, &dest).is_none() {
        app.db.set_setting(SINCE, &format!("{} {dest}", now()));
    }
}

pub fn status(app: &App, sb: &ServerBackups) -> Status {
    let dest = sb.target.as_ref().map(Target::destination);
    let last = dest.as_deref().and_then(|d| app.db.server_last_backup(d));
    let covered_since = last.as_ref().map(|b| b.created_at).or_else(|| dest.as_deref().and_then(|d| since(app, d)));
    let breach = sb.target.is_some() && covered_since.is_some_and(|c| now() - c > sb.rpo_ms);
    let breached_at = app.db.setting(BREACH).and_then(|s| s.parse().ok());
    Status { last, covered_since, breach, breached_at }
}

/// Opens or closes the RPO breach, audited and alerted. True while it's open.
pub fn watch(app: &AppState, sb: &ServerBackups) -> bool {
    // Both the RPO timer and a pass watch: one at a time, so a breach opens once.
    static WATCHING: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _one = WATCHING.lock().unwrap_or_else(|e| e.into_inner());
    let st = status(app, sb);
    match (st.breach, st.breached_at) {
        (true, None) => {
            let at = now();
            app.db.set_setting(BREACH, &at.to_string());
            let dest = sb.target.as_ref().map(Target::destination);
            let failed = app
                .db
                .server_backups(20)
                .into_iter()
                .find(|b| b.state == "failed" && dest.as_ref() == Some(&b.destination) && st.covered_since.is_none_or(|c| b.created_at >= c));
            let d = json!({
                "rpoHours": sb.rpo_ms / HOUR_MS, "lastBackupAt": st.last.as_ref().map(|b| b.created_at), "coveredSince": st.covered_since,
                "breachedAt": at, "lastError": failed.as_ref().and_then(|f| f.error.clone()),
            });
            app.db.record(&Event::new(Actor::system(ACTOR), "server.backup_rpo_breached").target("server", "backups").details(d).outcome(Outcome::Failure));
            let mut lines = vec![
                format!("RPO {} hours.", sb.rpo_ms / HOUR_MS),
                match &st.last {
                    Some(b) => format!("Newest archive off the host: {} ({} ago).", time(b.created_at), ago(at - b.created_at)),
                    None => "No archive has been copied off the host yet.".into(),
                },
            ];
            match failed.and_then(|f| f.error) {
                Some(e) => lines.push(format!("The last copy failed: {e}")),
                None if archives(&sb.dir).last().is_none_or(|a| st.covered_since.is_some_and(|c| a.created_at <= c)) => {
                    lines.push(format!("No newer archive in {}: check superbot-backup's timer or sidecar.", sb.dir.display()))
                }
                None => {}
            }
            alert(app, "server.backup_rpo_breached", "Server backups are past their RPO", lines);
            true
        }
        (false, Some(at)) => {
            app.db.clear_setting(BREACH);
            // Only a copy that landed is a recovery: a new store's RPO clock is not.
            let copied = st.last.as_ref().map(|b| b.created_at);
            let reason = match copied {
                _ if sb.target.is_none() => "off",
                Some(c) if c > at - sb.rpo_ms => "backed_up",
                None => "store_changed",
                Some(_) => "objective_changed",
            };
            let d = json!({ "reason": reason, "breachedAt": at, "durationMs": now() - at, "coveredSince": st.covered_since });
            app.db.record(&Event::new(Actor::system(ACTOR), "server.backup_rpo_recovered").target("server", "backups").details(d));
            if reason == "backed_up" {
                let lines = vec![format!("They were past their RPO for {}.", ago(now() - at)), format!("Newest archive off the host: {}.", copied.map(time).unwrap_or_default())];
                alert(app, "server.backup_rpo_recovered", "Server backups are back within their RPO", lines);
            }
            false
        }
        (open, _) => open,
    }
}

/// One pass: copies past their retention go, the newest archive is copied if it's due,
/// and the RPO is checked. Returns the copy it made, if any.
pub async fn pass(app: &AppState) -> Option<ServerBackup> {
    let sb = app.server_backups.get()?.clone();
    let t = sb.target.as_ref()?;
    prune(app, &sb, t).await;
    let made = match due(app, &sb) {
        Some(a) => copy(app, &sb, t, &a, None).await,
        None => None,
    };
    watch(app, &sb);
    made
}

/// What a botd that stopped mid-copy left: copies running end as failed. Their uploads
/// were never completed, so the store holds no object of them, only parts. Returns them.
fn interrupted(app: &App) -> Vec<ServerBackup> {
    let mut cut = Vec::new();
    for b in app.db.server_backups_in("running") {
        if app.db.server_backup_end(&b.id, None, Some("botd stopped while it was running")) {
            let d = json!({ "archive": b.archive, "object": b.object_key, "error": "interrupted" });
            app.db.record(&event("server.backup_copy_failed", &b, d).outcome(Outcome::Failure));
            cut.push(b);
        }
    }
    cut
}

/// Aborts the parts copies cut off by a restart left in this store, uploads begun before
/// `before` only, so a copy started since is never touched. Returns how many went.
pub async fn abort_cut_off(t: &Target, cut: &[ServerBackup], before: i64) -> usize {
    let dest = t.destination();
    let mut gone = 0;
    for b in cut.iter().filter(|b| b.destination == dest) {
        match t.s3.abort_unfinished(&b.object_key, before).await {
            Ok(n) => gone += n,
            Err(e) => crate::obs::log::log_warn!("Server backups: aborting the upload of {} a restart cut off: {e}", b.archive),
        }
    }
    gone
}

/// Copies archives off the host from startup, when a store is set, and checks the RPO on
/// its own timer so a slow upload can't hold back the alert. Without a store, a breach
/// left open by an earlier start is closed.
pub fn start(app: AppState) {
    let Some(sb) = app.server_backups.get().cloned() else { return };
    let Some(t) = &sb.target else {
        watch(&app, &sb);
        return;
    };
    mark_since(&app, t);
    let (started, cut) = (now(), interrupted(&app));
    let (a, s) = (app.clone(), sb.clone());
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(EVERY);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            watch(&a, &s);
        }
    });
    tokio::spawn(async move {
        if let Some(t) = &sb.target {
            abort_cut_off(t, &cut, started).await;
        }
        let mut tick = tokio::time::interval(EVERY);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            pass(&app).await;
        }
    });
}

// Views

/// What admins see: where copies go (no credentials), the RPO, the newest copies, and
/// the warning while archives stay on this host.
pub fn view(app: &App, sb: &ServerBackups) -> Value {
    let st = status(app, sb);
    let target = sb.target.as_ref().map(|t| {
        json!({
            "source": t.source.as_str(), "endpoint": t.store.endpoint, "bucket": t.store.bucket, "region": t.store.region,
            "prefix": t.folder(), "destination": t.destination(), "encryptsPlainArchives": !t.recipients.is_empty(),
            "recipients": t.recipients.iter().map(|r| r.to_string()).collect::<Vec<_>>(),
        })
    });
    let newest = archives(&sb.dir).pop();
    json!({
        "offHost": sb.target.is_some(),
        "mode": sb.mode.as_str(),
        "backupDir": sb.dir,
        "target": target,
        "rpoHours": sb.rpo_ms / HOUR_MS,
        "retentionDays": sb.retention_days,
        "warning": sb.warning(),
        "encryption": crate::backup_encryption::view(app),
        "newestArchive": newest.map(|a| json!({ "name": a.name, "createdAt": a.created_at, "encrypted": a.encrypted })),
        "lastBackupAt": st.last.as_ref().map(|b| b.created_at),
        "coveredSince": st.covered_since,
        "ageMs": st.covered_since.filter(|_| sb.target.is_some()).map(|c| (now() - c).max(0)),
        "breach": st.breach,
        "breachedAt": st.breached_at,
        "backups": app.db.server_backups(50),
    })
}

/// The setup checklist's item: done once an archive is copied off the host and the
/// newest copy is within the RPO.
pub fn checklist(app: &App) -> (bool, String) {
    let Some(sb) = app.server_backups.get() else {
        return (false, "Server backups stay on this host, so losing the host loses them. Set SERVER_BACKUP_S3_BUCKET to copy them off (ADR 0109).".into());
    };
    let Some(t) = &sb.target else { return (false, sb.warning().unwrap_or_default()) };
    let st = status(app, sb);
    let to = format!("{}/{}", t.store.bucket, t.folder());
    let rpo = sb.rpo_ms / HOUR_MS;
    match (&st.last, st.breach) {
        (Some(b), false) => (true, format!("Copied to {to}; the newest copy is from {} ({} ago), within the RPO of {rpo} hours.", time(b.created_at), ago(now() - b.created_at))),
        (None, false) => (false, format!("Copying to {to}; the first archive goes when superbot-backup next writes one. RPO {rpo} hours.")),
        (Some(b), true) => (false, format!("Copying to {to}, but the newest copy is {} old, past the RPO of {rpo} hours. See botctl backups.", ago(now() - b.created_at))),
        (None, true) => (false, format!("Copying to {to}, but nothing has been copied within the RPO of {rpo} hours. See botctl backups.")),
    }
}

/// The gauges `/metrics` shows (ADR 0089): whether archives leave the host and, when
/// they do, how old the newest copy is against the RPO.
pub fn render(app: &App, out: &mut String) {
    let Some(sb) = app.server_backups.get() else { return };
    metrics::family(out, "superbot_server_backup_off_host", "gauge", "1 when server backups are copied off this host (ADR 0109); 0 when they stay on it.");
    metrics::sample(out, "superbot_server_backup_off_host", &[], sb.target.is_some() as u8 as f64);
    if sb.target.is_none() {
        return;
    }
    let st = status(app, sb);
    metrics::family(out, "superbot_server_backup_rpo_seconds", "gauge", "The RPO server backups are held to.");
    metrics::sample(out, "superbot_server_backup_rpo_seconds", &[], sb.rpo_ms as f64 / 1000.0);
    if let Some(c) = st.covered_since {
        metrics::family(out, "superbot_server_backup_age_seconds", "gauge", "Age of the newest archive copied off the host (before the first, time since copies were turned on).");
        metrics::sample(out, "superbot_server_backup_age_seconds", &[], (now() - c).max(0) as f64 / 1000.0);
    }
    metrics::family(out, "superbot_server_backup_past_rpo", "gauge", "1 while the newest archive off the host is older than the RPO.");
    metrics::sample(out, "superbot_server_backup_past_rpo", &[], st.breach as u8 as f64);
    if let Some(b) = &st.last {
        metrics::family(out, "superbot_server_backup_last_copy_timestamp_seconds", "gauge", "When the newest archive copied off the host was made.");
        metrics::sample(out, "superbot_server_backup_last_copy_timestamp_seconds", &[], b.created_at as f64 / 1000.0);
        metrics::family(out, "superbot_server_backup_last_copy_size_bytes", "gauge", "The newest copy's size in the store.");
        metrics::sample(out, "superbot_server_backup_last_copy_size_bytes", &[], b.size.unwrap_or(0) as f64);
    }
}

// HTTP

fn conflict(msg: impl Into<String>) -> ApiError {
    ApiError(StatusCode::CONFLICT, msg.into())
}

fn settings(app: &App) -> Result<Arc<ServerBackups>, ApiError> {
    app.server_backups.get().cloned().ok_or_else(|| conflict("Server backups aren't set up on this server."))
}

/// `GET /api/backups` (admins): `view`.
pub async fn get(State(app): State<AppState>) -> Res {
    let sb = settings(&app)?;
    Ok(Json(view(&app, &sb)))
}

/// `POST /api/backups` (admins): copies the newest archive now if it isn't copied yet,
/// and answers with `view` and the copy made, if any. 409 while archives stay on this host.
pub async fn copy_now(State(app): State<AppState>, Extension(by): Extension<Who>) -> Res {
    let sb = settings(&app)?;
    let Some(t) = &sb.target else { return Err(conflict(sb.warning().unwrap_or_default())) };
    let made = match due(&app, &sb) {
        Some(a) => copy(&app, &sb, t, &a, Some(&by)).await,
        None => None,
    };
    watch(&app, &sb);
    let mut v = view(&app, &sb);
    v["copied"] = json!(made);
    Ok(Json(v))
}
