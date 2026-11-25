//! Offline support diagnostics (ADR 0187): `botd support check` and `botd support bundle`
//! run on the server without botd, so they work when it won't start, before an upgrade and
//! after a restore: the times the support bundle (ADR 0131), which botd makes, can't be had.
//! They read botd's settings (its environment, or the installer's `.env`) and only read
//! DATA_DIR: the database is opened read-only, the data lock is looked up in `/proc/locks`
//! rather than taken, and nothing is created there.
//!
//! `check` prints each finding (ok, info, warn, fail) with what to do and where it's
//! explained, and exits 1 on any failure, so an upgrade script can stop on it. `bundle`
//! saves the same findings, botd's settings with secrets redacted, and the service's newest
//! log lines as a tar for a ticket, through the support bundle's redaction.

use crate::database_encryption::{self, DbKey, Format};
use crate::secrets::key::{self, MasterKey};
use crate::secrets::redact::{self, MARK};
use crate::support;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Bumped when a file's shape changes, so support tools can tell bundles apart.
pub const FORMAT: u32 = 1;
const HOUR_MS: i64 = 3_600_000;
const DAY_MS: i64 = 24 * HOUR_MS;
const MIB: u64 = 1 << 20;
const GIB: u64 = 1 << 30;
/// The daily timer's interval and its 2 hours of slack, as the server backups' RPO (ADR 0109).
const BACKUP_STALE_MS: i64 = 26 * HOUR_MS;
const BACKUP_LOST_MS: i64 = 7 * DAY_MS;
/// Before an upgrade, a backup older than this loses what happened since if the upgrade is undone.
const BACKUP_FRESH_MS: i64 = HOUR_MS;
const LICENSE_SOON_MS: i64 = 14 * DAY_MS;
const LOG_LINES: usize = 2_000;
const LOG_LINE_CHARS: usize = 2_000;
/// What is read of a `--logs` file, from its end: enough for `LOG_LINES` long lines.
const LOG_TAIL_BYTES: u64 = 8 << 20;
const DOC: &str = "docs/support/support-check.md";

const USAGE: &str = "Usage: botd support check [--before-upgrade] [--json] [--home <dir> | --env-file <file>]
       botd support bundle [-o <file> | -o -] [--logs <file> | --no-logs] [--home <dir> | --env-file <file>]

Run on the server, as the user botd runs as (or root), with botd up or down.
  --home <dir>       the installer's layout: settings from <dir>/superbot/.env
                     (sudo -u superbot botd support check --home /home/superbot)
  --env-file <file>  settings from this file, over botd's environment
Docs: docs/support/support-check.md";

const README: &str = "SuperBot offline support bundle
===============================

Made by `botd support bundle` on the server, without botd running (ADR 0187), for a
support ticket. Check it before you send it: every file is plain text.

  version.json   this botd's version and schema, the OS and architecture
  check.json     what `botd support check` found: botd running or not, DATA_DIR, disk,
                 the database (format, size, schema, integrity), the master key (where
                 it is, never what), local backups and the license
  config.json    botd's settings, secrets redacted (the names of the ones redacted
                 are listed); other variables are only counted
  logs.txt       the service's newest log lines (at most 2,000), redacted
  manifest.json  what is in this bundle and how much was redacted

Never in it: secret values, chats, prompts, files, emails, IP addresses or the
licensee's name. A secret-named setting shows as [redacted], an email as [email], an IP
address as [ip] (loopback and 0.0.0.0 stay), the licensee as [name]; URLs keep only
their scheme, host and port. If you find anything you would rather not send, delete it
and say so in the ticket.
";

// Settings

/// botd's settings as this tool sees them: an env file's, over the process environment.
pub struct Settings {
    file: Option<PathBuf>,
    home: Option<PathBuf>,
    from_file: BTreeMap<String, String>,
    process: BTreeMap<String, String>,
}

/// A systemd `EnvironmentFile` or Compose `.env`: `KEY=value` lines, `#` comments, an
/// optional `export`, and quotes around a value dropped. A line ending in an unescaped `\`
/// goes on in the next, as systemd joins them; a comment line never does (systemd 254 on).
pub fn parse_env_file(text: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let (mut lines, mut cont) = (Vec::new(), String::new());
    for raw in text.lines() {
        if cont.is_empty() && raw.trim_start().starts_with(['#', ';']) {
            continue;
        }
        if (raw.len() - raw.trim_end_matches('\\').len()) % 2 == 1 {
            cont.push_str(&raw[..raw.len() - 1]);
            continue;
        }
        cont.push_str(raw);
        lines.push(std::mem::take(&mut cont));
    }
    if !cont.is_empty() {
        lines.push(cont);
    }
    for line in &lines {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.strip_prefix("export ").unwrap_or(line);
        let Some((k, v)) = line.split_once('=') else { continue };
        let k = k.trim();
        if k.is_empty() || !k.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_') {
            continue;
        }
        let v = v.trim();
        let v = b"\"'".iter().find_map(|&q| v.strip_prefix(q as char).and_then(|r| r.strip_suffix(q as char))).unwrap_or(v);
        out.insert(k.to_string(), v.to_string());
    }
    out
}

impl Settings {
    pub fn new(file: Option<(PathBuf, BTreeMap<String, String>)>, home: Option<PathBuf>, process: BTreeMap<String, String>) -> Settings {
        let (file, from_file) = file.map_or((None, BTreeMap::new()), |(p, m)| (Some(p), m));
        Settings { file, home, from_file, process }
    }

    /// From the command line: `--home` reads `<dir>/superbot/.env` if it's there, `--env-file` the file named.
    pub fn load(home: Option<&str>, env_file: Option<&str>) -> Result<Settings, String> {
        let process = std::env::vars_os().filter_map(|(k, v)| Some((k.into_string().ok()?, v.into_string().ok()?))).collect();
        let home = home.map(PathBuf::from);
        let file = match (env_file, &home) {
            (Some(f), _) => Some(PathBuf::from(f)),
            (None, Some(h)) => Some(h.join("superbot").join(".env")).filter(|p| p.exists()),
            (None, None) => None,
        };
        let file = match file {
            Some(p) => {
                let text = std::fs::read_to_string(&p).map_err(|e| format!("{}: {e}", p.display()))?;
                Some((p, parse_env_file(&text)))
            }
            None => None,
        };
        Ok(Settings::new(file, home, process))
    }

    pub fn get(&self, k: &str) -> String {
        self.from_file.get(k).or_else(|| self.process.get(k)).map(|v| v.trim().to_string()).unwrap_or_default()
    }

    /// A path setting as botd sees it: with `--home`, a relative one is under the install
    /// directory, where the installer's unit runs botd (`WorkingDirectory`).
    pub fn resolve(&self, v: &str) -> PathBuf {
        match &self.home {
            Some(h) if Path::new(v).is_relative() => h.join("superbot").join(v),
            _ => PathBuf::from(v),
        }
    }

    fn path(&self, k: &str, under_home: &[&str]) -> Option<PathBuf> {
        let v = self.get(k);
        if !v.is_empty() {
            return Some(self.resolve(&v));
        }
        self.home.as_ref().map(|h| under_home.iter().fold(h.clone(), |p, part| p.join(part)))
    }

    pub fn data_dir(&self) -> PathBuf {
        self.path("DATA_DIR", &["superbot", "data"]).unwrap_or_else(|| self.resolve("data"))
    }

    pub fn backup_dir(&self) -> Option<PathBuf> {
        self.path("BACKUP_DIR", &["superbot", "backups"])
    }

    /// Every variable, the file's over the process's.
    pub fn vars(&self) -> Vec<(String, String)> {
        let mut all = self.process.clone();
        all.extend(self.from_file.clone());
        all.into_iter().collect()
    }

    pub(crate) fn source(&self) -> Value {
        json!({ "envFile": self.file.as_ref().map(|p| p.display().to_string()), "home": self.home.as_ref().map(|p| p.display().to_string()) })
    }
}

// Findings

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Level {
    Ok,
    Info,
    Warn,
    Fail,
}

impl Level {
    fn word(self) -> &'static str {
        match self {
            Level::Ok => "ok",
            Level::Info => "info",
            Level::Warn => "warn",
            Level::Fail => "fail",
        }
    }
}

#[derive(Clone, Debug)]
pub struct Finding {
    pub id: &'static str,
    pub level: Level,
    pub summary: String,
    pub fix: Option<String>,
    pub details: Value,
}

impl Finding {
    fn new(id: &'static str, level: Level, summary: impl Into<String>) -> Finding {
        Finding { id, level, summary: summary.into(), fix: None, details: Value::Null }
    }

    fn fix(mut self, fix: impl Into<String>) -> Finding {
        self.fix = Some(fix.into());
        self
    }

    fn details(mut self, d: Value) -> Finding {
        self.details = d;
        self
    }

    fn json(&self) -> Value {
        json!({ "id": self.id, "status": self.level, "summary": self.summary, "fix": self.fix, "doc": format!("{DOC}#{}", self.id), "details": self.details })
    }
}

fn mb(bytes: u64) -> String {
    if bytes >= GIB { format!("{:.1} GiB", bytes as f64 / GIB as f64) } else { format!("{:.1} MiB", bytes as f64 / MIB as f64) }
}

fn hours(ms: i64) -> String {
    if ms < HOUR_MS { format!("{} minutes", (ms / 60_000).max(0)) } else if ms < 2 * DAY_MS { format!("{:.1} hours", ms as f64 / HOUR_MS as f64) } else { format!("{} days", ms / DAY_MS) }
}

fn date(ms: i64) -> String {
    chrono::DateTime::from_timestamp_millis(ms).map(|t| t.format("%Y-%m-%d %H:%M UTC").to_string()).unwrap_or_default()
}

/// `0.1.0`, `1.2.3-rc.1` as numbers to compare; pre-release tags are ignored.
fn semver(v: &str) -> Option<(u64, u64, u64)> {
    let mut p = v.trim().trim_start_matches('v').split(['-', '+']).next()?.split('.').map(|n| n.parse::<u64>().ok());
    Some((p.next()??, p.next().flatten().unwrap_or(0), p.next().flatten().unwrap_or(0)))
}

/// The process holding a `flock` on `file`, from `/proc/locks`: botd holds one on its data
/// lock all the time it runs. Read, never taken, so a botd starting now isn't turned away.
fn lock_holder(file: &Path, proc_locks: &str) -> Option<u32> {
    use std::os::unix::fs::MetadataExt;
    let ino = std::fs::metadata(file).ok()?.ino();
    proc_locks.lines().find_map(|l| {
        let f: Vec<&str> = l.split_whitespace().collect();
        let (kind, pid, dev) = (f.get(1)?, f.get(4)?, f.get(5)?);
        let inode: u64 = dev.rsplit(':').next()?.parse().ok()?;
        (*kind == "FLOCK" && inode == ino).then(|| pid.parse().ok()).flatten()
    })
}

/// Whether botd answers `GET /healthz` at `addr`.
fn healthz(addr: &str) -> bool {
    let Some(sock) = std::net::ToSocketAddrs::to_socket_addrs(addr).ok().and_then(|mut a| a.next()) else { return false };
    let Ok(mut s) = std::net::TcpStream::connect_timeout(&sock, Duration::from_secs(2)) else { return false };
    let _ = s.set_read_timeout(Some(Duration::from_secs(3)));
    let _ = s.set_write_timeout(Some(Duration::from_secs(3)));
    if s.write_all(format!("GET /healthz HTTP/1.0\r\nHost: {addr}\r\n\r\n").as_bytes()).is_err() {
        return false;
    }
    let mut head = [0u8; 64];
    let n = s.read(&mut head).unwrap_or(0);
    let line = String::from_utf8_lossy(&head[..n]);
    line.starts_with("HTTP/1.") && line.split_whitespace().nth(1) == Some("200")
}

/// Where botd listens, as this host reaches it: a wildcard `HOST` means loopback.
fn listen_addr(s: &Settings) -> String {
    let host = s.get("HOST");
    let host = match host.as_str() {
        "" | "0.0.0.0" | "::" | "[::]" => "127.0.0.1",
        h => h,
    };
    let port = Some(s.get("PORT")).filter(|p| !p.is_empty()).unwrap_or_else(|| "3000".into());
    if host.contains(':') && !host.starts_with('[') { format!("[{host}]:{port}") } else { format!("{host}:{port}") }
}

/// `in_container`: run in a container of its own, which can't see another container's process or loopback.
fn check_botd(s: &Settings, data_dir: &Path, in_container: bool) -> Finding {
    let locks = std::fs::read_to_string("/proc/locks").unwrap_or_default();
    let holder = lock_holder(&data_dir.join("app.sqlite-lock"), &locks);
    let addr = listen_addr(s);
    let answers = healthz(&addr);
    let details = json!({ "pid": holder, "address": addr, "healthz": answers });
    let f = match (holder, answers) {
        (Some(pid), true) => Finding::new("botd", Level::Ok, format!("running (pid {pid}); /healthz answers on {addr}")),
        (Some(pid), false) => Finding::new("botd", Level::Warn, format!("running (pid {pid}), but /healthz doesn't answer on {addr}"))
            .fix("It may still be starting: schema changes on a large database take a while. If it stays like this, read its newest log lines (journalctl -u superbot -n 200, or docker compose logs --tail 200 botd)."),
        (None, true) => Finding::new("botd", Level::Warn, format!("/healthz answers on {addr}, but nothing holds this DATA_DIR's lock"))
            .fix("That botd uses another DATA_DIR. Point this check at its settings with --home or --env-file."),
        (None, false) if in_container => Finding::new("botd", Level::Info, "not seen from this container: a separate container can't see the botd service's process or its loopback port")
            .fix("docker compose ps says whether botd runs. While it does, run this check in it: docker compose exec botd botd support check."),
        (None, false) => Finding::new("botd", Level::Warn, "isn't running")
            .fix("Start it (sudo systemctl start superbot, or docker compose up -d). If it stops again, its last log lines say why; botd support bundle collects them for a ticket."),
    };
    f.details(details)
}

fn check_data_dir(data_dir: &Path) -> Finding {
    let shown = data_dir.display();
    match std::fs::read_dir(data_dir) {
        Ok(entries) => Finding::new("data_dir", Level::Ok, format!("{shown}: {} entries", entries.count())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Finding::new("data_dir", Level::Fail, format!("{shown} doesn't exist"))
            .fix("Check DATA_DIR (pass --home or --env-file to read botd's own settings). After a lost host, restore it: docs/support/runbook-server-restore.md."),
        Err(e) => Finding::new("data_dir", Level::Fail, format!("{shown}: {e}")).fix("Run this as the user botd runs as (sudo -u superbot ...), or as root."),
    }
}

fn check_disk(data_dir: &Path, db_bytes: u64, before_upgrade: bool) -> Finding {
    let Some((d, _)) = crate::obs::capacity::disk("data", data_dir) else {
        return Finding::new("disk", Level::Info, "couldn't read the free space where DATA_DIR is");
    };
    let free = d.total.saturating_sub(d.used);
    let pct = free as f64 * 100.0 / d.total.max(1) as f64;
    let details = json!({ "freeBytes": free, "totalBytes": d.total, "freePercent": (pct * 10.0).round() / 10.0, "databaseBytes": db_bytes });
    let summary = format!("{} free of {} ({pct:.0}%) where DATA_DIR is", mb(free), mb(d.total));
    let fix = "Free some space (old archives in BACKUP_DIR, journald's logs, docker system prune) or grow the disk. botd and SQLite stop writing when it's full.";
    let f = if free < 512 * MIB || pct < 2.0 {
        Finding::new("disk", Level::Fail, summary).fix(fix)
    } else if free < 2 * GIB || pct < 10.0 {
        Finding::new("disk", Level::Warn, summary).fix(fix)
    } else if before_upgrade && free < 2 * db_bytes + GIB {
        Finding::new("disk", Level::Warn, format!("{summary}: tight for a backup of the {} database and the upgrade", mb(db_bytes))).fix(fix)
    } else {
        Finding::new("disk", Level::Ok, summary)
    };
    f.details(details)
}

/// The master key (`inline`/`file`, else `default`), as botd finds it, never created.
fn find_key(s: &Settings, inline: &str, file: &str, default: Option<PathBuf>, data_dir: &Path) -> Result<Option<(MasterKey, String)>, String> {
    let (text, path) = (s.get(inline), s.get(file));
    if !text.is_empty() {
        if !path.is_empty() {
            return Err(format!("set {inline} or {file}, not both"));
        }
        return MasterKey::parse(&text).map(|k| Some((k, inline.to_string()))).map_err(|e| format!("{inline}: {e}"));
    }
    let Some(path) = Some(path).filter(|p| !p.is_empty()).map(|p| s.resolve(&p)).or(default) else { return Ok(None) };
    let real = |p: &Path| std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf());
    if real(&path).starts_with(real(data_dir)) {
        return Err(format!("{} is inside DATA_DIR, which backups copy. Keep the master key elsewhere.", path.display()));
    }
    if std::fs::symlink_metadata(&path).is_err() {
        return Ok(None);
    }
    key::read_file(&path).map(|k| Some((k, path.display().to_string())))
}

struct Keys {
    current: Result<Option<(MasterKey, String)>, String>,
    previous: Result<Option<(MasterKey, String)>, String>,
}

impl Keys {
    fn find(s: &Settings, data_dir: &Path) -> Keys {
        let default = match &s.home {
            Some(h) => Some(h.join(".config").join("superbot").join("master.key")),
            None => key::default_path(),
        };
        let keys = Keys {
            current: find_key(s, "SUPERBOT_MASTER_KEY", "SUPERBOT_MASTER_KEY_FILE", default, data_dir),
            previous: find_key(s, "SUPERBOT_MASTER_KEY_PREVIOUS", "SUPERBOT_MASTER_KEY_PREVIOUS_FILE", None, data_dir),
        };
        for (k, _) in keys.all() {
            k.register_redactions();
        }
        keys
    }

    fn all(&self) -> impl Iterator<Item = &(MasterKey, String)> {
        self.current.as_ref().ok().into_iter().flatten().chain(self.previous.as_ref().ok().into_iter().flatten())
    }
}

/// The master keys botd would start with, as `s` sets them: the current one, then the
/// previous one mid-rotation. For other offline commands (`botd chat-store`, ADR 0256).
pub(crate) fn master_keys(s: &Settings, data_dir: &Path) -> Result<Vec<MasterKey>, String> {
    let keys = Keys::find(s, data_dir);
    let mut out = Vec::new();
    for k in [keys.current, keys.previous] {
        out.extend(k?.map(|(k, _)| k));
    }
    Ok(out)
}

fn check_master_key(keys: &Keys, format: Option<Format>) -> Finding {
    let previous = match &keys.previous {
        Ok(Some((_, from))) => format!("; the previous key from {from} too (a rotation in progress)"),
        _ => String::new(),
    };
    match (&keys.current, &keys.previous) {
        (Err(e), _) | (_, Err(e)) => Finding::new("master_key", Level::Fail, e.clone()).fix("botd won't start like this. Fix the setting or the file: docs/ops/master-key-rotation.md."),
        (Ok(Some((_, from))), _) => Finding::new("master_key", Level::Ok, format!("found, from {from}{previous}")).details(json!({ "source": from })),
        (Ok(None), _) if format == Some(Format::Encrypted) => Finding::new("master_key", Level::Fail, "none found, and the database is encrypted")
            .fix("Put the master key back where .env says (SUPERBOT_MASTER_KEY_FILE, or SUPERBOT_MASTER_KEY) before you start botd: without it the database can't be opened."),
        (Ok(None), _) => Finding::new("master_key", Level::Warn, "none found (SUPERBOT_MASTER_KEY, SUPERBOT_MASTER_KEY_FILE or ~/.config/superbot/master.key)")
            .fix("A new install makes one at first start. After a restore or a move, put the old key back first, or the secrets saved under it can't be read."),
    }
}

/// When botd last started on a database, and its version.
type LastStart = Option<(i64, String)>;

/// What botd recorded of copying archives off the host (ADR 0109): the newest finished
/// copy's archive and time, and the copies that failed since.
#[derive(Clone, Debug, Default)]
struct Copies {
    newest: Option<(String, i64)>,
    failed_since: i64,
}

struct Database {
    finding: Finding,
    format: Option<Format>,
    bytes: u64,
    /// None when the database couldn't be read.
    copies: Option<Copies>,
}

fn check_database(data_dir: &Path, keys: &Keys) -> Database {
    let path = data_dir.join("app.sqlite");
    let shown = path.display().to_string();
    let size = |p: &Path| std::fs::metadata(p).map(|m| m.len()).unwrap_or(0);
    let (bytes, wal) = (size(&path), size(&data_dir.join("app.sqlite-wal")));
    let format = match database_encryption::format(&path) {
        Ok(f) => f,
        Err(e) => return Database { finding: Finding::new("database", Level::Fail, e).fix("Run this as the user botd runs as, or as root."), format: None, bytes, copies: None },
    };
    let restore = "Restore the newest good backup: docs/support/runbook-server-restore.md. Never edit app.sqlite by hand.";
    let key: Option<DbKey> = match format {
        Format::Missing => {
            let f = Finding::new("database", Level::Warn, format!("no database at {shown}"))
                .fix("A new install makes one at first start. After a restore, the archive didn't land in this DATA_DIR: check DATA_DIR and restore again.");
            return Database { finding: f, format: Some(format), bytes, copies: None };
        }
        Format::Plain => None,
        Format::Encrypted => {
            let found: Vec<DbKey> = keys.all().map(|(k, _)| DbKey::derive(k)).collect();
            match found.into_iter().find(|k| database_encryption::opens(&path, k)) {
                Some(k) => Some(k),
                None => {
                    let summary = if keys.all().next().is_none() { "encrypted, and no master key was found to open it" } else { "encrypted, and the master key doesn't open it (wrong key)" };
                    let f = Finding::new("database", Level::Fail, summary)
                        .fix("Use the master key this database was made with (the one kept off-host with the backups). If it's lost, the database can't be read.");
                    return Database { finding: f, format: Some(format), bytes, copies: None };
                }
            }
        }
    };
    let encrypted = format == Format::Encrypted;
    let read = || -> rusqlite::Result<(i64, String, LastStart, Copies)> {
        let c = database_encryption::open_read_only(&path, key.as_ref())?;
        let version: i64 = c.query_row("PRAGMA user_version", [], |r| r.get(0))?;
        let integrity: String = c.query_row("PRAGMA quick_check", [], |r| r.get(0))?;
        let started = c
            .query_row("SELECT at, details FROM audit_events WHERE action = 'server.started' ORDER BY id DESC LIMIT 1", [], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?)))
            .ok()
            .map(|(at, d)| (at, serde_json::from_str::<Value>(&d).ok().and_then(|v| v["version"].as_str().map(String::from)).unwrap_or_default()));
        let newest = c
            .query_row("SELECT archive, created_at FROM server_backups WHERE state = 'done' ORDER BY created_at DESC LIMIT 1", [], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))
            .ok();
        let since = newest.as_ref().map_or(0, |(_, at)| *at);
        let failed_since = c.query_row("SELECT COUNT(*) FROM server_backups WHERE state = 'failed' AND created_at > ?", [since], |r| r.get(0)).unwrap_or(0);
        Ok((version, integrity, started, Copies { newest, failed_since }))
    };
    let (version, integrity, started, off_host) = match read() {
        Ok(r) => r,
        Err(e) => {
            let f = Finding::new("database", Level::Fail, format!("{shown} can't be read: {e}")).fix(restore);
            return Database { finding: f, format: Some(format), bytes, copies: None };
        }
    };
    let ours = crate::db::schema_version();
    let mine = env!("CARGO_PKG_VERSION");
    let copies = database_encryption::plain_copies(data_dir);
    let mut level = Level::Ok;
    let mut notes = Vec::new();
    let mut fixes = Vec::new();
    if integrity != "ok" {
        level = Level::Fail;
        notes.push(format!("SQLite's integrity check failed: {}", support::scrub_text(&integrity)));
        fixes.push(restore.to_string());
    }
    if version > ours {
        level = Level::Fail;
        notes.push(format!("made by a newer botd (schema {version}; this botd {mine} knows {ours})"));
        fixes.push("Don't start this botd on it: install the version it was on again, or restore a backup made on this one (docs/support/runbook-upgrade.md#going-back).".into());
    } else if version < ours {
        level = level.max(Level::Info);
        notes.push(format!("{} schema changes run at this botd's next start (schema {version} to {ours})", ours - version));
    }
    if let Some((_, v)) = &started
        && let (Some(last), Some(this)) = (semver(v), semver(mine))
        && last > this
    {
        level = level.max(Level::Warn);
        notes.push(format!("botd {v} ran on it last; this is {mine}"));
        fixes.push("Run the version it was on, or restore a backup made on this one.".into());
    }
    if encrypted && !copies.is_empty() {
        level = level.max(Level::Warn);
        notes.push(format!("{} plain copies left beside it by encrypting it", copies.len()));
        fixes.push("Once botd runs well on the encrypted database, delete the plain copies (docs/ops/database-encryption.md).".into());
    }
    let mut summary = format!("{}, {} (WAL {}), schema {version} of {ours}, integrity {}", if encrypted { "encrypted" } else { "plain" }, mb(bytes), mb(wal), if integrity == "ok" { "ok" } else { "failed" });
    if let Some((at, v)) = &started {
        summary.push_str(&format!("; last started by botd {v} at {}", date(*at)));
    }
    for n in &notes {
        summary.push_str("; ");
        summary.push_str(n);
    }
    let mut f = Finding::new("database", level, summary).details(json!({
        "encrypted": encrypted,
        "bytes": bytes,
        "walBytes": wal,
        "schema": version,
        "schemaKnown": ours,
        "integrity": integrity == "ok",
        "lastStartedVersion": started.as_ref().map(|(_, v)| v),
        "lastStartedAt": started.as_ref().map(|(at, _)| support::rfc3339(*at)),
        "plainCopies": copies.len(),
    }));
    if !fixes.is_empty() {
        f = f.fix(fixes.join(" "));
    }
    Database { finding: f, format: Some(format), bytes, copies: Some(off_host) }
}

/// Whether the archives leave the host, as botd is set to copy them and as it recorded doing it.
#[derive(Clone, Copy, Debug, PartialEq)]
enum OffHost {
    /// botd copied the newest archive.
    Copied,
    /// botd is set to copy them, but its record shows no copy of the newest, or can't be read.
    Unconfirmed,
    /// `SERVER_BACKUP_OFF_HOST=off`: the operator copies them, which this check can't see.
    ByOperator,
    None,
}

fn check_backups(s: &Settings, now_ms: i64, before_upgrade: bool, copies: Option<&Copies>) -> Finding {
    let back_up = "Back up now: sudo systemctl start superbot-backup.service (Compose: docker compose exec botd superbot-backup).";
    let Some(dir) = s.backup_dir() else {
        return Finding::new("backups", Level::Info, "BACKUP_DIR isn't set here, so local archives weren't looked at")
            .fix("Pass --home or --env-file with botd's settings, or set BACKUP_DIR (Compose: /backups).");
    };
    let shown = dir.display();
    if std::fs::read_dir(&dir).is_err() {
        let level = if before_upgrade { Level::Fail } else { Level::Warn };
        return Finding::new("backups", level, format!("{shown} can't be read or doesn't exist: no backups found on this host")).fix(back_up);
    }
    let archives = crate::server_backups::archives(&dir);
    let Some(newest) = archives.last() else {
        let level = if before_upgrade { Level::Fail } else { Level::Warn };
        return Finding::new("backups", level, format!("no archives in {shown}")).fix(back_up);
    };
    let age = (now_ms - newest.created_at).max(0);
    let store = !s.get("SERVER_BACKUP_S3_BUCKET").is_empty() || !s.get("MACHINE_BACKUP_S3_BUCKET").is_empty();
    let copied = copies.and_then(|c| c.newest.as_ref());
    let off_host = if s.get("SERVER_BACKUP_OFF_HOST").eq_ignore_ascii_case("off") {
        OffHost::ByOperator
    } else if !store {
        OffHost::None
    } else if copied.is_some_and(|(_, at)| *at >= newest.created_at) {
        OffHost::Copied
    } else {
        OffHost::Unconfirmed
    };
    let mut summary = format!(
        "{} archive{} in {shown}; the newest, {}, is {} old{}",
        archives.len(),
        if archives.len() == 1 { "" } else { "s" },
        newest.name,
        hours(age),
        if newest.encrypted { " and encrypted" } else { "" }
    );
    let failed = copies.map_or(0, |c| c.failed_since);
    summary.push_str(&match (off_host, copied, copies) {
        (OffHost::Copied, _, _) => "; botd copied the newest off this host".to_string(),
        (OffHost::Unconfirmed, _, None) => "; botd is set to copy them off this host, but its record of copies couldn't be read, so that's unconfirmed".to_string(),
        (OffHost::Unconfirmed, Some((name, at)), _) => format!("; botd's newest copy off this host is of {name}, {} old", hours((now_ms - at).max(0))),
        (OffHost::Unconfirmed, None, _) => "; botd is set to copy them off this host, but has no finished copy".to_string(),
        (OffHost::ByOperator, _, _) => "; botd doesn't copy them off this host (SERVER_BACKUP_OFF_HOST=off), and copies you make aren't checked here".to_string(),
        (OffHost::None, _, _) => "; they stay on this host".to_string(),
    });
    if failed > 0 && off_host != OffHost::ByOperator {
        summary.push_str(&format!(" ({failed} failed since)"));
    }
    let off_host_word = match off_host {
        OffHost::Copied => "copied",
        OffHost::Unconfirmed => "unconfirmed",
        OffHost::ByOperator => "operator",
        OffHost::None => "none",
    };
    let details = json!({ "archives": archives.len(), "newest": newest.name, "ageHours": age / HOUR_MS, "encrypted": newest.encrypted, "offHost": off_host_word, "copiesFailedSince": failed });
    let f = if age > BACKUP_LOST_MS {
        Finding::new("backups", Level::Fail, summary).fix(format!("Backups have stopped: journalctl -u superbot-backup (or docker compose logs backup) says why. {back_up}"))
    } else if age > BACKUP_STALE_MS {
        Finding::new("backups", Level::Warn, summary).fix(format!("The daily backup missed its run: journalctl -u superbot-backup says why. {back_up}"))
    } else if before_upgrade && age > BACKUP_FRESH_MS {
        Finding::new("backups", Level::Warn, summary).fix(format!("Take one just before the upgrade, so undoing it loses nothing. {back_up}"))
    } else if off_host == OffHost::None {
        Finding::new("backups", Level::Warn, summary).fix("A lost host loses them too: give botd a store (SERVER_BACKUP_S3_*, docs/ops/backup-restore.md#off-site-copies).")
    } else if off_host == OffHost::Unconfirmed {
        Finding::new("backups", Level::Warn, summary)
            .fix("botd copies each archive within a minute while it runs. With it up, botctl backups shows the store, its copies and their errors; botctl backups copy copies the newest now.")
    } else if off_host == OffHost::ByOperator {
        Finding::new("backups", Level::Info, summary).fix("Check your own copies (rclone, restic, rsync) hold this archive.")
    } else {
        Finding::new("backups", Level::Ok, summary)
    };
    f.details(details)
}

/// A setting as botd's license loader reads it, with `LICENSE_KEY_FILE` taken from where
/// the service runs.
fn license_setting(s: &Settings, k: &str) -> String {
    let v = s.get(k);
    if k == "LICENSE_KEY_FILE" && !v.is_empty() { s.resolve(&v).display().to_string() } else { v }
}

/// The license as botd would load it, and the licensee's name to hide in a bundle.
fn check_license(s: &Settings, data_dir: &Path, now_ms: i64) -> (Finding, Vec<String>) {
    let lic = crate::license::Licensing::new(crate::license::trusted(), data_dir);
    let testing = crate::license::testing_flag(&s.get("TESTING_MODE"));
    lic.set_testing(*testing.as_ref().unwrap_or(&false));
    lic.load(|k| license_setting(s, k));
    let st = lic.status();
    let names: Vec<String> = st.claims.as_ref().map(|c| c.sub.trim().to_string()).filter(|n| n.len() >= 2).into_iter().collect();
    let details = json!({ "mode": st.mode, "edition": st.edition(), "expiresAt": st.expires_at().map(support::rfc3339) });
    let fix = "Install the license key from CG-Labs (botctl license install, or the console's Settings), or set TESTING_MODE=on on a test server.";
    let f = if let Err(e) = testing {
        Finding::new("license", Level::Fail, e).fix("botd won't start like this: TESTING_MODE is on or off.")
    } else if st.mode == crate::license::Mode::Grace {
        Finding::new("license", Level::Warn, st.detail()).fix(fix)
    } else if st.licensed() && st.expires_at().is_some_and(|e| e - now_ms < LICENSE_SOON_MS) {
        Finding::new("license", Level::Warn, st.detail()).fix("Install the renewed key before it ends.")
    } else if st.licensed() {
        Finding::new("license", Level::Ok, st.detail())
    } else if st.testing() {
        Finding::new("license", Level::Info, st.detail())
    } else {
        Finding::new("license", Level::Fail, st.detail()).fix(fix)
    };
    (f.details(details), names)
}

pub struct Report {
    pub before_upgrade: bool,
    pub at: i64,
    pub data_dir: PathBuf,
    pub source: Value,
    pub findings: Vec<Finding>,
    /// The licensee, hidden in a bundle.
    names: Vec<String>,
}

/// Every check, in the order support reads them.
pub fn run(s: &Settings, before_upgrade: bool, now_ms: i64) -> Report {
    let data_dir = s.data_dir();
    let keys = Keys::find(s, &data_dir);
    let db = check_database(&data_dir, &keys);
    let (license, names) = check_license(s, &data_dir, now_ms);
    let findings = vec![
        check_botd(s, &data_dir, Path::new("/.dockerenv").exists()),
        check_data_dir(&data_dir),
        check_disk(&data_dir, db.bytes, before_upgrade),
        db.finding,
        check_master_key(&keys, db.format),
        check_backups(s, now_ms, before_upgrade, db.copies.as_ref()),
        license,
    ];
    Report { before_upgrade, at: now_ms, data_dir, source: s.source(), findings, names }
}

impl Report {
    pub fn failed(&self) -> bool {
        self.findings.iter().any(|f| f.level == Level::Fail)
    }

    fn count(&self, l: Level) -> usize {
        self.findings.iter().filter(|f| f.level == l).count()
    }

    pub fn json(&self) -> Value {
        json!({
            "botd": env!("CARGO_PKG_VERSION"),
            "schema": crate::db::schema_version(),
            "checkedAt": support::rfc3339(self.at),
            "beforeUpgrade": self.before_upgrade,
            "dataDir": self.data_dir.display().to_string(),
            "settings": self.source,
            "failed": self.failed(),
            "findings": self.findings.iter().map(Finding::json).collect::<Vec<_>>(),
        })
    }

    pub fn text(&self) -> String {
        let mut out = format!(
            "SuperBot support check: botd {} (schema {}), {}{}\nDATA_DIR {}{}\n\n",
            env!("CARGO_PKG_VERSION"),
            crate::db::schema_version(),
            date(self.at),
            if self.before_upgrade { ", before an upgrade" } else { "" },
            self.data_dir.display(),
            self.source["envFile"].as_str().map(|f| format!(" (settings from {f})")).unwrap_or_default(),
        );
        for f in &self.findings {
            out.push_str(&format!("{:<5} {:<11} {}\n", f.level.word(), f.id, f.summary));
            if let Some(fix) = &f.fix {
                out.push_str(&format!("{:18}{fix}\n", ""));
            }
        }
        let (fails, warns) = (self.count(Level::Fail), self.count(Level::Warn));
        out.push('\n');
        out.push_str(&match (fails, warns) {
            (0, 0) => "All clear.".to_string(),
            (0, w) => format!("{w} warning{}, no failures.", if w == 1 { "" } else { "s" }),
            (f, w) => format!("{f} failed, {w} warning{}.{}", if w == 1 { "" } else { "s" }, if self.before_upgrade { " Fix the failures before you upgrade." } else { "" }),
        });
        out.push_str(&format!(" What each check means and what to do: {DOC}\n"));
        out
    }
}

// The offline bundle

pub enum Logs {
    None,
    File(PathBuf),
    Journal,
}

impl Logs {
    /// The journal on a systemd host, nothing in a container (its logs are the runtime's).
    fn default_here() -> Logs {
        if Path::new("/run/systemd/system").exists() && !Path::new("/.dockerenv").exists() { Logs::Journal } else { Logs::None }
    }

    fn read(&self) -> Result<String, String> {
        match self {
            Logs::None => Err("no logs: pass --logs <file>, e.g. docker compose logs --no-color --tail 2000 botd > botd.log".into()),
            Logs::File(p) => tail(p, LOG_TAIL_BYTES).map_err(|e| format!("{}: {e}", p.display())),
            Logs::Journal => {
                let o = std::process::Command::new("journalctl")
                    .args(["-u", "superbot", "-n", &LOG_LINES.to_string(), "-o", "cat", "--no-pager", "-q"])
                    .output()
                    .map_err(|e| format!("journalctl: {e}"))?;
                if !o.status.success() {
                    return Err(format!("journalctl: {}", String::from_utf8_lossy(&o.stderr).trim()));
                }
                let text = String::from_utf8_lossy(&o.stdout).into_owned();
                if text.trim().is_empty() {
                    return Err("journalctl had no lines for superbot (run as root, or in the systemd-journal group, to read them)".into());
                }
                Ok(text)
            }
        }
    }
}

/// The last `max` bytes of a file, from its first whole line, so a large log isn't read whole.
fn tail(path: &Path, max: u64) -> std::io::Result<String> {
    use std::io::{Seek, SeekFrom};
    let mut f = std::fs::File::open(path)?;
    let len = f.metadata()?.len();
    let start = len.saturating_sub(max);
    f.seek(SeekFrom::Start(start))?;
    let mut b = Vec::with_capacity((len - start) as usize);
    f.take(max).read_to_end(&mut b)?;
    if start > 0 {
        let first = b.iter().position(|&c| c == b'\n').map_or(b.len(), |i| i + 1);
        b.drain(..first);
    }
    Ok(String::from_utf8_lossy(&b).into_owned())
}

/// The newest `LOG_LINES` lines, each cut to `LOG_LINE_CHARS` and redacted, and how many.
fn scrub_logs(text: &str, names: &[String]) -> (String, usize) {
    let lines: Vec<&str> = text.lines().collect();
    let kept = &lines[lines.len().saturating_sub(LOG_LINES)..];
    let mut out = String::new();
    for l in kept {
        let clean = support::hide(&redact::text(&support::scrub_text(l)), names);
        let cut: String = clean.chars().take(LOG_LINE_CHARS).collect();
        out.push_str(&cut);
        if cut.len() < clean.len() {
            out.push('…');
        }
        out.push('\n');
    }
    (out, kept.len())
}

pub struct Offline {
    pub name: String,
    pub tar: Vec<u8>,
    pub redacted_settings: usize,
    pub log_lines: usize,
    pub failed: bool,
}

pub fn bundle(s: &Settings, logs: &Logs, now_ms: i64) -> Offline {
    let vars = s.vars();
    for (k, v) in &vars {
        if support::setting(k, v).0 == MARK {
            redact::register(v);
        }
    }
    let report = run(s, false, now_ms);
    let names = report.names.clone();
    let stamp = chrono::DateTime::from_timestamp_millis(now_ms).map(|t| t.format("%Y%m%dT%H%M%SZ").to_string()).unwrap_or_default();
    let name = format!("superbot-support-offline-{stamp}");
    let (env, redacted, other) = support::environment(&vars);
    let config = json!({ "settings": s.source(), "environment": env, "redacted": redacted, "otherVariables": other });
    let version = json!({
        "product": "SuperBot",
        "botd": env!("CARGO_PKG_VERSION"),
        "schema": crate::db::schema_version(),
        "bundleFormat": FORMAT,
        "offline": true,
        "createdAt": support::rfc3339(now_ms),
        "os": std::env::consts::OS,
        "arch": std::env::consts::ARCH,
        "kernel": std::fs::read_to_string("/proc/sys/kernel/osrelease").ok().map(|k| k.trim().to_string()),
        "container": Path::new("/.dockerenv").exists(),
    });
    let (log_text, log_lines) = match logs.read() {
        Ok(t) => scrub_logs(&t, &names),
        Err(e) => (format!("# {}\n", support::hide(&support::scrub_text(&e), &names)), 0),
    };
    let mut files: Vec<(&str, Vec<u8>)> = vec![
        ("README.txt", README.as_bytes().to_vec()),
        ("version.json", support::json_file(version, &names)),
        ("check.json", support::json_file(report.json(), &names)),
        ("config.json", support::json_file(config, &names)),
        ("logs.txt", redact::text(&log_text).into_owned().into_bytes()),
    ];
    let listed: Vec<(String, usize)> = files.iter().map(|(n, b)| (n.to_string(), b.len())).collect();
    let manifest = json!({
        "format": FORMAT,
        "offline": true,
        "botd": env!("CARGO_PKG_VERSION"),
        "createdAt": support::rfc3339(now_ms),
        "files": listed.iter().map(|(n, b)| json!({ "name": n, "bytes": b })).collect::<Vec<_>>(),
        "redactedSettings": redacted.len(),
        "logLines": log_lines,
    });
    files.push(("manifest.json", support::json_file(manifest, &[])));
    let entries: Vec<(String, Vec<u8>)> = files.into_iter().map(|(n, b)| (format!("{name}/{n}"), b)).collect();
    Offline { tar: crate::ustar::tar(&entries, (now_ms / 1000).max(0) as u64), name, redacted_settings: redacted.len(), log_lines, failed: report.failed() }
}

/// Writes a new file only its owner can read; never over an existing one.
fn save_private(path: &Path, bytes: &[u8]) -> Result<(), String> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(path).and_then(|mut f| f.write_all(bytes)).map_err(|e| format!("{}: {e}", path.display()))
}

// The command line

#[derive(Debug, Default, PartialEq)]
struct Args<'a> {
    before_upgrade: bool,
    json: bool,
    home: Option<&'a str>,
    env_file: Option<&'a str>,
    out: Option<&'a str>,
    logs: Option<&'a str>,
    no_logs: bool,
}

fn parse<'a>(cmd: &str, rest: &[&'a str]) -> Result<Args<'a>, String> {
    let mut a = Args::default();
    let mut it = rest.iter();
    while let Some(&arg) = it.next() {
        let mut value = || it.next().copied().ok_or_else(|| format!("{arg} needs a value\n{USAGE}"));
        match (cmd, arg) {
            ("check", "--before-upgrade") => a.before_upgrade = true,
            ("check", "--json") => a.json = true,
            ("bundle", "-o" | "--output") => a.out = Some(value()?),
            ("bundle", "--logs") => a.logs = Some(value()?),
            ("bundle", "--no-logs") => a.no_logs = true,
            (_, "--home") => a.home = Some(value()?),
            (_, "--env-file") => a.env_file = Some(value()?),
            _ => return Err(format!("Unknown option {arg}\n{USAGE}")),
        }
    }
    if a.home.is_some() && a.env_file.is_some() {
        return Err(format!("Use --home or --env-file, not both\n{USAGE}"));
    }
    if a.logs.is_some() && a.no_logs {
        return Err(format!("Use --logs or --no-logs, not both\n{USAGE}"));
    }
    Ok(a)
}

/// `botd support <check|bundle> ...`: prints the result and returns the exit code: 0, 1 when
/// a check failed or the bundle couldn't be saved, 2 for a usage error.
pub fn cli(args: &[String]) -> i32 {
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let (cmd, rest) = match args.split_first() {
        Some((&c @ ("check" | "bundle"), rest)) => (c, rest),
        _ => {
            eprintln!("{USAGE}");
            return 2;
        }
    };
    let a = match parse(cmd, rest) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("{e}");
            return 2;
        }
    };
    let s = match Settings::load(a.home, a.env_file) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("botd support: {e}");
            return 1;
        }
    };
    let now = crate::db::now();
    if cmd == "check" {
        let r = run(&s, a.before_upgrade, now);
        if a.json {
            println!("{}", serde_json::to_string_pretty(&r.json()).unwrap_or_default());
        } else {
            print!("{}", r.text());
        }
        return i32::from(r.failed());
    }
    let logs = match (a.logs, a.no_logs) {
        (Some(f), _) => Logs::File(PathBuf::from(f)),
        (None, true) => Logs::None,
        (None, false) => Logs::default_here(),
    };
    let b = bundle(&s, &logs, now);
    if a.out == Some("-") {
        let mut out = std::io::stdout().lock();
        if let Err(e) = out.write_all(&b.tar).and_then(|_| out.flush()) {
            eprintln!("botd support: {e}");
            return 1;
        }
        eprintln!("Wrote {} ({} KB) to stdout. Read it before you attach it to a ticket.", b.name, b.tar.len().div_ceil(1024));
        return 0;
    }
    let path = PathBuf::from(a.out.map(String::from).unwrap_or_else(|| format!("{}.tar", b.name)));
    if let Err(e) = save_private(&path, &b.tar) {
        eprintln!("botd support: {e}");
        return 1;
    }
    let shown = path.display();
    println!(
        "Saved {shown} ({} KB: {} settings redacted, {} log lines). It has no secrets, emails or chats, but read it before you attach it to a ticket:\n  tar -tvf {shown}\n  tar -xOf {shown} | less{}",
        b.tar.len().div_ceil(1024),
        b.redacted_settings,
        b.log_lines,
        if b.failed { "\nSome checks failed: botd support check says which, and what to do." } else { "" }
    );
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::support::tests::untar;

    fn settings(file: &[(&str, &str)], process: &[(&str, &str)]) -> Settings {
        let map = |v: &[(&str, &str)]| v.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect::<BTreeMap<_, _>>();
        Settings::new((!file.is_empty()).then(|| (PathBuf::from("/srv/superbot/.env"), map(file))), None, map(process))
    }

    /// A DATA_DIR and BACKUP_DIR of their own, a master key outside both, and testing mode.
    struct Server {
        data: PathBuf,
        backups: PathBuf,
        key_file: PathBuf,
    }

    impl Server {
        fn new(tag: &str) -> Server {
            let root = crate::db::temp_path(tag);
            let (data, backups, keys) = (root.join("data"), root.join("backups"), root.join("keys"));
            for d in [&data, &backups, &keys] {
                std::fs::create_dir_all(d).unwrap();
            }
            let key_file = keys.join("master.key");
            save_private(&key_file, format!("{}\n", MasterKey::generate().base64().as_str()).as_bytes()).unwrap();
            Server { data, backups, key_file }
        }

        fn settings(&self, extra: &[(&str, &str)]) -> Settings {
            let (d, b, k) = (self.data.display().to_string(), self.backups.display().to_string(), self.key_file.display().to_string());
            let mut file = vec![("DATA_DIR", d.as_str()), ("BACKUP_DIR", b.as_str()), ("SUPERBOT_MASTER_KEY_FILE", k.as_str()), ("TESTING_MODE", "on"), ("PORT", "1")];
            file.extend_from_slice(extra);
            settings(&file, &[])
        }

        fn key(&self) -> MasterKey {
            key::read_file(&self.key_file).unwrap()
        }

        fn archive(&self, ms_ago: i64, suffix: &str) {
            let at = chrono::DateTime::from_timestamp_millis(crate::db::now() - ms_ago).unwrap();
            std::fs::write(self.backups.join(format!("superbot-{}{suffix}", at.format("%Y%m%d-%H%M%S"))), b"x").unwrap();
        }
    }

    fn finding<'a>(r: &'a Report, id: &str) -> &'a Finding {
        r.findings.iter().find(|f| f.id == id).unwrap_or_else(|| panic!("no {id} finding"))
    }

    #[test]
    fn env_files_read_like_systemd_and_compose_read_them() {
        let m = parse_env_file("# a comment\nPORT=3000\n export DATA_DIR = \"/srv/data\" \nNAME='two words'\nEMPTY=\nbad line\n=x\nweird-name=1\nURL=https://x/?a=b\n");
        assert_eq!(m.get("PORT").map(String::as_str), Some("3000"));
        assert_eq!(m.get("DATA_DIR").map(String::as_str), Some("/srv/data"));
        assert_eq!(m.get("NAME").map(String::as_str), Some("two words"));
        assert_eq!(m.get("EMPTY").map(String::as_str), Some(""));
        assert_eq!(m.get("URL").map(String::as_str), Some("https://x/?a=b"), "only the first = splits");
        assert_eq!(m.len(), 5, "{m:?}");

        let m = parse_env_file("LIST=/a.tar.gz,\\\n  /b.tar.gz\r\nNEXT=1\nPATHS=C:\\\\\nLAST=x\\");
        assert_eq!(m.get("LIST").map(String::as_str), Some("/a.tar.gz,  /b.tar.gz"), "{m:?}");
        assert_eq!(m.get("NEXT").map(String::as_str), Some("1"));
        assert_eq!(m.get("PATHS").map(String::as_str), Some("C:\\\\"), "an escaped \\ ends the line");
        assert_eq!(m.get("LAST").map(String::as_str), Some("x"), "{m:?}");

        let m = parse_env_file("# MACHINE_HARNESS_BUNDLE=/old.tar.gz,\\\nMACHINE_HARNESS_BUNDLE=/new.tar.gz\n; ends in \\\nNEXT=2\n");
        assert_eq!(m.get("MACHINE_HARNESS_BUNDLE").map(String::as_str), Some("/new.tar.gz"), "a comment takes no line with it: {m:?}");
        assert_eq!(m.get("NEXT").map(String::as_str), Some("2"), "{m:?}");
    }

    #[test]
    fn the_env_file_wins_and_home_gives_the_installers_paths() {
        let s = settings(&[("DATA_DIR", "/srv/data")], &[("DATA_DIR", "/elsewhere"), ("PORT", "4000")]);
        assert_eq!(s.data_dir(), PathBuf::from("/srv/data"));
        assert_eq!(s.get("PORT"), "4000");
        assert_eq!(s.backup_dir(), None);
        let home = Settings::new(None, Some(PathBuf::from("/home/superbot")), BTreeMap::new());
        assert_eq!(home.data_dir(), PathBuf::from("/home/superbot/superbot/data"));
        assert_eq!(home.backup_dir(), Some(PathBuf::from("/home/superbot/superbot/backups")));
        let relative: BTreeMap<String, String> = [("DATA_DIR", "state"), ("BACKUP_DIR", "/var/backups/superbot")].map(|(k, v)| (k.to_string(), v.to_string())).into();
        let home = Settings::new(None, Some(PathBuf::from("/home/superbot")), relative);
        assert_eq!(home.data_dir(), PathBuf::from("/home/superbot/superbot/state"), "relative to where the unit runs botd");
        assert_eq!(home.backup_dir(), Some(PathBuf::from("/var/backups/superbot")));
        assert_eq!(home.resolve("keys/master.key"), PathBuf::from("/home/superbot/superbot/keys/master.key"));
        let lic: BTreeMap<String, String> = [("LICENSE_KEY_FILE", "license.key")].map(|(k, v)| (k.to_string(), v.to_string())).into();
        assert_eq!(license_setting(&Settings::new(None, Some(PathBuf::from("/home/superbot")), lic.clone()), "LICENSE_KEY_FILE"), "/home/superbot/superbot/license.key");
        assert_eq!(license_setting(&Settings::new(None, None, lic), "LICENSE_KEY_FILE"), "license.key", "without --home, as botd would from here");
        assert_eq!(Settings::new(None, None, BTreeMap::new()).data_dir(), PathBuf::from("data"), "botd's own default");
        assert!(Settings::load(None, Some("/nonexistent/.env")).err().unwrap().contains("/nonexistent/.env"));
    }

    #[test]
    fn options_are_parsed_per_command() {
        assert_eq!(parse("check", &["--before-upgrade", "--json", "--home", "/h"]), Ok(Args { before_upgrade: true, json: true, home: Some("/h"), ..Args::default() }));
        assert_eq!(parse("bundle", &["-o", "t.tar", "--logs", "b.log", "--env-file", "e"]), Ok(Args { out: Some("t.tar"), logs: Some("b.log"), env_file: Some("e"), ..Args::default() }));
        assert!(parse("bundle", &["--before-upgrade"]).unwrap_err().starts_with("Unknown option"));
        assert!(parse("check", &["--home", "/h", "--env-file", "e"]).unwrap_err().contains("not both"));
        assert!(parse("bundle", &["--logs", "a", "--no-logs"]).unwrap_err().contains("not both"));
        assert!(parse("check", &["--home"]).unwrap_err().contains("needs a value"));
        assert_eq!(cli(&["nope".to_string()]), 2);
    }

    #[test]
    fn a_healthy_server_passes_and_the_report_says_so() {
        let srv = Server::new("check-ok");
        drop(crate::db::Db::open(&srv.data.join("app.sqlite")).unwrap());
        srv.archive(10 * 60_000, ".tar.gz.age");
        let db = crate::db::Db::open(&srv.data.join("app.sqlite")).unwrap();
        let newest = crate::server_backups::archives(&srv.backups).pop().unwrap();
        let copy = crate::db::NewServerBackup { id: "sb1", archive: &newest.name, destination: "s3/b/server", object_key: "k", created_at: newest.created_at, encrypted_by: Some("archive") };
        let started = db.server_backup_start(&copy).unwrap();
        assert!(db.server_backup_end(&started.id, Some((1, "00", None)), None));
        drop(db);
        let r = run(&srv.settings(&[("SERVER_BACKUP_S3_BUCKET", "b")]), true, crate::db::now());
        for id in ["data_dir", "database", "master_key", "backups"] {
            assert_eq!(finding(&r, id).level, Level::Ok, "{id}: {:?}", finding(&r, id));
        }
        let db = finding(&r, "database");
        assert!(db.summary.starts_with("plain, ") && db.summary.contains(&format!("schema {0} of {0}", crate::db::schema_version())), "{}", db.summary);
        assert_eq!(db.details["integrity"], true);
        assert_eq!(finding(&r, "license").level, Level::Info, "testing mode");
        let expected = if Path::new("/.dockerenv").exists() { Level::Info } else { Level::Warn };
        assert_eq!(finding(&r, "botd").level, expected, "nothing runs on it");
        assert!(finding(&r, "backups").summary.contains("encrypted; botd copied the newest off this host"), "{}", finding(&r, "backups").summary);
        assert!(!r.failed());
        let text = r.text();
        assert!(text.contains("before an upgrade") && text.contains("ok    database") && text.contains("docs/support/support-check.md"), "{text}");
        let j = r.json();
        assert_eq!(j["findings"].as_array().unwrap().len(), 7);
        assert_eq!(j["findings"][3]["doc"], "docs/support/support-check.md#database");
    }

    #[test]
    fn an_encrypted_database_opens_only_with_its_key() {
        let srv = Server::new("check-encrypted");
        let path = srv.data.join("app.sqlite");
        drop(crate::db::Db::open_keyed(&path, &DbKey::derive(&srv.key())));
        let r = run(&srv.settings(&[]), false, crate::db::now());
        let db = finding(&r, "database");
        assert_eq!(db.level, Level::Ok, "{db:?}");
        assert!(db.summary.starts_with("encrypted, "), "{}", db.summary);
        save_private(&srv.data.join("app.sqlite-plain-20261101T000000Z"), b"x").unwrap();
        assert_eq!(finding(&run(&srv.settings(&[]), false, crate::db::now()), "database").level, Level::Warn, "a plain copy left beside it");

        let other = MasterKey::generate();
        let r = run(&srv.settings(&[("SUPERBOT_MASTER_KEY_FILE", ""), ("SUPERBOT_MASTER_KEY", other.base64().as_str())]), false, crate::db::now());
        assert_eq!(finding(&r, "database").level, Level::Fail);
        assert!(finding(&r, "database").summary.contains("wrong key"));
        assert_eq!(finding(&r, "master_key").summary, "found, from SUPERBOT_MASTER_KEY");

        let previous = srv.key_file.display().to_string();
        let r = run(&srv.settings(&[("SUPERBOT_MASTER_KEY_FILE", ""), ("SUPERBOT_MASTER_KEY", other.base64().as_str()), ("SUPERBOT_MASTER_KEY_PREVIOUS_FILE", &previous)]), false, crate::db::now());
        assert_ne!(finding(&r, "database").level, Level::Fail, "the previous key opens it mid-rotation");

        let r = run(&srv.settings(&[("SUPERBOT_MASTER_KEY_FILE", "/nonexistent/master.key")]), false, crate::db::now());
        assert!(finding(&r, "database").summary.contains("no master key"));
        assert_eq!(finding(&r, "master_key").level, Level::Fail, "an encrypted database needs it");
        assert!(r.failed() && r.text().contains("2 failed"), "{}", r.text());
    }

    #[test]
    fn a_database_from_a_newer_botd_or_a_broken_one_fails() {
        let srv = Server::new("check-newer");
        let path = srv.data.join("app.sqlite");
        let db = crate::db::Db::open(&path).unwrap();
        db.record(&crate::audit::Event::new(crate::audit::Actor::system("server"), "server.started").details(json!({ "version": "99.0.0" })));
        drop(db);
        let c = rusqlite::Connection::open(&path).unwrap();
        c.execute_batch(&format!("PRAGMA user_version = {};", crate::db::schema_version() + 3)).unwrap();
        drop(c);
        let db = finding(&run(&srv.settings(&[]), false, crate::db::now()), "database").clone();
        assert_eq!(db.level, Level::Fail);
        assert!(db.summary.contains("made by a newer botd") && db.summary.contains("botd 99.0.0 ran on it last"), "{}", db.summary);
        assert!(db.fix.unwrap().contains("runbook-upgrade.md#going-back"));

        let c = rusqlite::Connection::open(&path).unwrap();
        c.execute_batch(&format!("PRAGMA user_version = {};", crate::db::schema_version() - 2)).unwrap();
        drop(c);
        let db = finding(&run(&srv.settings(&[]), false, crate::db::now()), "database").clone();
        assert!(db.summary.contains("2 schema changes run at this botd's next start"), "{}", db.summary);

        std::fs::remove_file(&path).unwrap();
        let _ = std::fs::remove_file(srv.data.join("app.sqlite-wal"));
        let _ = std::fs::remove_file(srv.data.join("app.sqlite-shm"));
        std::fs::write(&path, b"SQLite format 3\0this is not a database at all, just bytes").unwrap();
        assert_eq!(finding(&run(&srv.settings(&[]), false, crate::db::now()), "database").level, Level::Fail);
        std::fs::remove_file(&path).unwrap();
        let r = run(&srv.settings(&[]), false, crate::db::now());
        assert_eq!(finding(&r, "database").level, Level::Warn, "no database yet");
        assert_eq!(finding(&r, "master_key").level, Level::Ok);
    }

    #[test]
    fn backups_are_judged_by_age_and_where_they_go() {
        let srv = Server::new("check-backups");
        let level = |s: &Settings, before| finding(&run(s, before, crate::db::now()), "backups").level;
        let off = srv.settings(&[("SERVER_BACKUP_S3_BUCKET", "b")]);
        assert_eq!(level(&off, false), Level::Warn, "none");
        assert_eq!(level(&off, true), Level::Fail, "none before an upgrade");
        std::fs::write(srv.backups.join(".partial-abc"), b"x").unwrap();
        srv.archive(3 * HOUR_MS, ".tar.gz");
        let f = finding(&run(&off, false, crate::db::now()), "backups").clone();
        assert_eq!(f.level, Level::Warn, "a bucket set but no database to confirm a copy: {f:?}");
        assert!(f.summary.contains("unconfirmed"), "{}", f.summary);

        let db = crate::db::Db::open(&srv.data.join("app.sqlite")).unwrap();
        let newest = crate::server_backups::archives(&srv.backups).pop().unwrap();
        let failed = db.server_backup_start(&crate::db::NewServerBackup { id: "f1", archive: &newest.name, destination: "s3/b", object_key: "k1", created_at: newest.created_at, encrypted_by: None }).unwrap();
        assert!(db.server_backup_end(&failed.id, None, Some("upload refused")));
        drop(db);
        let f = finding(&run(&off, false, crate::db::now()), "backups").clone();
        assert_eq!(f.level, Level::Warn, "only a failed copy: {f:?}");
        assert!(f.summary.contains("has no finished copy") && f.summary.contains("1 failed since"), "{}", f.summary);

        let db = crate::db::Db::open(&srv.data.join("app.sqlite")).unwrap();
        let done = db.server_backup_start(&crate::db::NewServerBackup { id: "d1", archive: &newest.name, destination: "s3/b", object_key: "k2", created_at: newest.created_at, encrypted_by: None }).unwrap();
        assert!(db.server_backup_end(&done.id, Some((1, "00", None)), None));
        drop(db);
        assert_eq!(level(&off, false), Level::Ok, "botd copied the newest");
        assert_eq!(level(&off, true), Level::Warn, "take a fresh one first");
        srv.archive(10 * 60_000, ".tar.gz");
        let f = finding(&run(&off, false, crate::db::now()), "backups").clone();
        assert_eq!(f.level, Level::Warn, "a newer archive than the newest copy");
        assert!(f.summary.contains(&format!("newest copy off this host is of {}", newest.name)), "{}", f.summary);

        assert_eq!(level(&srv.settings(&[]), false), Level::Warn, "they stay on this host");
        let by_you = finding(&run(&srv.settings(&[("SERVER_BACKUP_S3_BUCKET", "b"), ("SERVER_BACKUP_OFF_HOST", "off")]), false, crate::db::now()), "backups").clone();
        assert_eq!(by_you.level, Level::Info, "off wins over a bucket, and the operator's copies aren't seen");
        assert!(by_you.summary.contains("doesn't copy them") && by_you.summary.contains("aren't checked"), "{}", by_you.summary);
        let stale = Server::new("check-backups-stale");
        stale.archive(2 * DAY_MS, ".tar.gz");
        assert_eq!(level(&stale.settings(&[("SERVER_BACKUP_S3_BUCKET", "b")]), false), Level::Warn);
        let lost = Server::new("check-backups-lost");
        lost.archive(8 * DAY_MS, ".tar.gz");
        assert_eq!(level(&lost.settings(&[("SERVER_BACKUP_S3_BUCKET", "b")]), false), Level::Fail);
        let f = finding(&run(&settings(&[("DATA_DIR", "/nonexistent")], &[]), false, crate::db::now()), "backups").clone();
        assert_eq!(f.level, Level::Info, "no BACKUP_DIR to look in");
    }

    #[test]
    fn a_missing_data_dir_and_no_license_fail() {
        let r = run(&settings(&[("DATA_DIR", "/nonexistent/superbot-data")], &[]), false, crate::db::now());
        assert_eq!(finding(&r, "data_dir").level, Level::Fail);
        assert_eq!(finding(&r, "license").level, Level::Fail, "no free tier");
        assert!(finding(&r, "license").fix.as_deref().unwrap().contains("TESTING_MODE=on"));
        assert!(r.failed());
        let r = run(&settings(&[("DATA_DIR", "/nonexistent"), ("TESTING_MODE", "maybe")], &[]), false, crate::db::now());
        assert_eq!(finding(&r, "license").level, Level::Fail, "a setting botd refuses");
    }

    #[test]
    fn a_running_botd_is_seen_by_its_lock_and_health() {
        let srv = Server::new("check-running");
        let db = srv.data.join("app.sqlite");
        let lock = crate::database_encryption::lock_data_dir(&db).unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port().to_string();
        let server = std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let mut buf = [0u8; 512];
            let n = s.read(&mut buf).unwrap();
            assert!(String::from_utf8_lossy(&buf[..n]).starts_with("GET /healthz HTTP/1.0\r\n"));
            s.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 11\r\n\r\n{\"ok\":true}").unwrap();
        });
        let f = check_botd(&srv.settings(&[("PORT", &port), ("HOST", "0.0.0.0")]), &srv.data, false);
        server.join().unwrap();
        if std::path::Path::new("/proc/locks").exists() {
            assert_eq!(f.level, Level::Ok, "{f:?}");
            assert_eq!(f.details["pid"], std::process::id());
        }
        assert_eq!(f.details["healthz"], true);
        drop(lock);
        let gone = check_botd(&srv.settings(&[]), &srv.data, false);
        assert_eq!((gone.level, &gone.details["pid"]), (Level::Warn, &Value::Null), "released");
        let unseen = check_botd(&srv.settings(&[]), &srv.data, true);
        assert_eq!(unseen.level, Level::Info, "a separate container can't tell");
        assert!(unseen.fix.as_deref().unwrap_or_default().contains("docker compose exec"), "{unseen:?}");
    }

    #[test]
    fn lock_holders_are_read_from_proc_locks() {
        use std::os::unix::fs::MetadataExt;
        let dir = crate::db::temp_path("check-locks");
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("app.sqlite-lock");
        std::fs::write(&f, b"").unwrap();
        let ino = std::fs::metadata(&f).unwrap().ino();
        let locks = format!("1: POSIX  ADVISORY  WRITE 11 fd:01:{ino} 0 EOF\n2: -> FLOCK  ADVISORY  WRITE 12 fd:01:{ino} 0 EOF\n3: FLOCK  ADVISORY  WRITE 4242 fd:01:{ino} 0 EOF\n");
        assert_eq!(lock_holder(&f, &locks), Some(4242));
        assert_eq!(lock_holder(&f, "1: FLOCK  ADVISORY  WRITE 4242 fd:01:1 0 EOF\n"), None);
        assert_eq!(lock_holder(&dir.join("missing"), &locks), None);
        assert_eq!(listen_addr(&settings(&[("HOST", "::1"), ("PORT", "8080")], &[])), "[::1]:8080");
        assert_eq!(listen_addr(&settings(&[], &[])), "127.0.0.1:3000");
    }

    #[test]
    fn versions_compare_as_numbers() {
        assert!(semver("0.10.0") > semver("0.9.9"));
        assert_eq!(semver("v1.2.3-rc.1"), Some((1, 2, 3)));
        assert_eq!(semver("1"), Some((1, 0, 0)));
        assert_eq!(semver(""), None);
    }

    #[test]
    fn the_offline_bundle_carries_no_secret_email_ip_or_licensee() {
        let srv = Server::new("check-bundle");
        drop(crate::db::Db::open(&srv.data.join("app.sqlite")).unwrap());
        srv.archive(HOUR_MS, ".tar.gz");
        let api_key = format!("sk-ant-api03-{}", crate::random_hex(12));
        let password = format!("plain words {}", crate::random_hex(4));
        let log = srv.data.parent().unwrap().join("botd.log");
        let long = "é".repeat(LOG_LINE_CHARS + 10);
        std::fs::write(&log, format!("start\nmodel call failed with key {api_key}\nlogin {password} from 203.0.113.9 by ops@example.com\n{long}\n")).unwrap();
        let s = srv.settings(&[("ANTHROPIC_API_KEY", &api_key), ("AUTH_PASSWORD", &password), ("OWNER_EMAIL", "owner@example.com"), ("SMTP_URL", "smtps://u:hunter2hunter2@smtp.example.com:465"), ("ALLOWED_HOSTS", "10.1.2.3")]);
        let b = bundle(&s, &Logs::File(log), crate::db::now());
        assert!(b.name.starts_with("superbot-support-offline-"));
        let files = untar(&b.tar);
        let names: Vec<String> = files.iter().map(|(n, _)| n.strip_prefix(&format!("{}/", b.name)).unwrap().to_string()).collect();
        assert_eq!(names, ["README.txt", "version.json", "check.json", "config.json", "logs.txt", "manifest.json"]);
        let all: String = files.iter().map(|(_, b)| String::from_utf8(b.clone()).expect("plain text")).collect();
        for leak in [api_key.as_str(), password.as_str(), "owner@example.com", "ops@example.com", "hunter2hunter2", "203.0.113.9", "10.1.2.3"] {
            assert!(!all.contains(leak), "{leak} leaked");
        }
        let text = |n: &str| String::from_utf8(files.iter().find(|(f, _)| f.ends_with(n)).unwrap().1.clone()).unwrap();
        let config: Value = serde_json::from_str(&text("config.json")).unwrap();
        assert_eq!(config["environment"]["ANTHROPIC_API_KEY"], MARK);
        assert_eq!(config["settings"]["envFile"], "/srv/superbot/.env");
        assert!(config["redacted"].as_array().unwrap().iter().any(|n| n == "AUTH_PASSWORD"));
        let logs = text("logs.txt");
        assert!(logs.contains("model call failed with key [redacted]") && logs.contains("[ip]") && logs.contains("[email]"), "{logs}");
        assert!(logs.lines().last().unwrap().ends_with('…') && logs.lines().last().unwrap().chars().count() == LOG_LINE_CHARS + 1);
        let check: Value = serde_json::from_str(&text("check.json")).unwrap();
        assert_eq!(check["findings"].as_array().unwrap().len(), 7);
        let manifest: Value = serde_json::from_str(&text("manifest.json")).unwrap();
        assert_eq!(manifest["logLines"], 4);
        assert_eq!(manifest["offline"], true);
        assert!(b.redacted_settings >= 4);

        let b = bundle(&s, &Logs::None, crate::db::now());
        assert!(String::from_utf8_lossy(&untar(&b.tar)[4].1).starts_with("# no logs: pass --logs"));
        redact::forget(&api_key);
        redact::forget(&password);
    }

    #[test]
    fn a_secret_across_the_cut_is_redacted_whole() {
        let secret = format!("passphrase words {}", crate::random_hex(8));
        redact::register(&secret);
        let line = format!("{}{secret} tail", "x".repeat(LOG_LINE_CHARS - 5));
        let (out, _) = scrub_logs(&line, &[]);
        assert!(!out.contains(&secret[..5]) && out.contains("[red"), "{out}");
        redact::forget(&secret);
    }

    #[test]
    fn only_the_end_of_a_large_log_file_is_read() {
        let dir = crate::db::temp_path("check-tail");
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("big.log");
        std::fs::write(&f, (0..10_000).map(|i| format!("line {i}\n")).collect::<String>()).unwrap();
        let t = tail(&f, 100).unwrap();
        assert!(t.len() <= 100 && t.starts_with("line ") && t.ends_with("line 9999\n"), "{t}");
        assert_eq!(tail(&f, 1 << 20).unwrap().lines().count(), 10_000, "a small file is read whole");
    }

    #[test]
    fn the_licensee_is_hidden_from_log_lines() {
        let names = vec!["Acme Ltd".to_string()];
        let (out, n) = scrub_logs(&(0..LOG_LINES + 5).map(|i| format!("line {i} for Acme Ltd")).collect::<Vec<_>>().join("\n"), &names);
        assert_eq!(n, LOG_LINES);
        assert!(out.starts_with("line 5 for [name]\n"), "the newest lines are kept");
    }

    #[test]
    fn the_cli_saves_a_bundle_once_and_check_exits_on_failure() {
        let srv = Server::new("check-cli");
        let env = srv.data.parent().unwrap().join(".env");
        std::fs::write(&env, format!("DATA_DIR={}\nTESTING_MODE=on\nPORT=1\n", srv.data.display())).unwrap();
        let out = srv.data.parent().unwrap().join("t.tar");
        let args = |a: &[&str]| a.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let (e, o) = (env.display().to_string(), out.display().to_string());
        assert_eq!(cli(&args(&["bundle", "--env-file", &e, "--no-logs", "-o", &o])), 0);
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&out).unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(cli(&args(&["bundle", "--env-file", &e, "--no-logs", "-o", &o])), 1, "never over an existing file");
        assert_eq!(cli(&args(&["check", "--env-file", &e, "--json"])), 0, "a warning isn't a failure");
        let bad = srv.data.parent().unwrap().join("bad.env");
        std::fs::write(&bad, "DATA_DIR=/nonexistent/superbot\n").unwrap();
        assert_eq!(cli(&args(&["check", "--env-file", &bad.display().to_string()])), 1);
    }
}
