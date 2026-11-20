//! Copying a user's folder to their machine (ADR 0041), botd's side. With
//! MACHINE_FOLDER_SYNC=on, assigning a user to their machine copies their working
//! folder (`WORKSPACE_DIR/users/<id>`, or their `workspace` with per-user accounts) to
//! `work/` there, and seeds their facts and their Bots' memory where the machine has
//! none; an admin can copy it again at any time. Over mutual TLS to that machine only,
//! each file checked against its SHA-256 on both ends, chunked and resumable, and never
//! deleting or overwriting anything changed on the machine. botd keeps the memory and
//! facts: jobs still carry them both ways (ADR 0036). Every copy is audited.
//!
//! - MACHINE_FOLDER_SYNC: `on` or `off` (the default).
//! - MACHINE_FOLDER_SYNC_MAX_MB: the largest folder copied (default 2048). A bigger one
//!   isn't copied at all.

use super::enroll::{self, Enrollment};
use super::wire::{self, BlobReply, Heartbeat, SyncFile, SyncManifest, SyncPlan, SyncReport};
use super::{ControlPlane, State, event, system};
use crate::audit::{Outcome, Who};
use crate::db::{Machine, now};
use crate::runner::App;
use crate::users::need_user_key;
use crate::{ApiError, AppState, Res};
use axum::Json;
use axum::extract::{Extension, Path as UrlPath, State as AppS};
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

pub const DEFAULT_MAX_MB: u64 = 2048;
/// The most files a copy lists.
pub const MAX_FILES: usize = 100_000;
const CHUNK: usize = 4 << 20;
/// A copy that failed or was cut short is tried again this long after, this many times.
const RETRY_MS: i64 = 15 * 60_000;
const MAX_ATTEMPTS: u32 = 5;
const KEY: &str = "machine_folder_sync:";

#[derive(Clone, Debug, PartialEq)]
pub struct Settings {
    pub max_bytes: u64,
}

impl Settings {
    pub fn from_env(var: &dyn Fn(&str) -> String) -> Result<Option<Settings>, String> {
        let on = match var("MACHINE_FOLDER_SYNC").trim() {
            "" | "off" => false,
            "on" => true,
            v => return Err(format!("MACHINE_FOLDER_SYNC must be on or off, not \"{v}\"")),
        };
        let max = var("MACHINE_FOLDER_SYNC_MAX_MB");
        if !on {
            return match max.trim() {
                "" => Ok(None),
                _ => Err("MACHINE_FOLDER_SYNC_MAX_MB needs MACHINE_FOLDER_SYNC=on".into()),
            };
        }
        let mb = match max.trim() {
            "" => DEFAULT_MAX_MB,
            m => m
                .parse::<u64>()
                .ok()
                .filter(|m| (1..=100 * 1024).contains(m))
                .ok_or("MACHINE_FOLDER_SYNC_MAX_MB must be 1 to 102400")?,
        };
        Ok(Some(Settings { max_bytes: mb << 20 }))
    }
}

/// The machines whose folder is being copied now.
#[derive(Default)]
pub struct Copying(Mutex<HashSet<String>>);

impl Copying {
    fn lock(&self) -> std::sync::MutexGuard<'_, HashSet<String>> {
        self.0.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn has(&self, machine_id: &str) -> bool {
        self.lock().contains(machine_id)
    }
}

/// Holds a machine's place in `Copying` until the copy ends, however it ends.
struct Claim(Arc<Enrollment>, String);

impl Claim {
    fn take(e: &Arc<Enrollment>, machine_id: &str) -> Option<Claim> {
        e.copying.lock().insert(machine_id.to_string()).then(|| Claim(e.clone(), machine_id.to_string()))
    }
}

impl Drop for Claim {
    fn drop(&mut self) {
        self.0.copying.lock().remove(&self.1);
    }
}

/// How a machine's folder copy went, kept in botd's settings by machine.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Status {
    /// `copying`, `done` or `failed`.
    pub state: String,
    pub trigger: String,
    pub by: Option<String>,
    pub started_at: i64,
    pub finished_at: Option<i64>,
    /// When a copy last finished. Kept through later failures.
    pub done_at: Option<i64>,
    /// Failed copies since the last one that finished.
    pub attempts: u32,
    pub files: u64,
    pub bytes: u64,
    /// Bytes sent this time; less than `bytes` when the machine had the rest.
    pub sent: u64,
    /// Files left out: links, devices, unreadable files, names a machine can't hold.
    pub skipped: u64,
    pub report: Option<SyncReport>,
    pub reason: Option<String>,
    pub error: Option<String>,
}

fn load(app: &App, machine_id: &str) -> Option<Status> {
    app.db.setting(&format!("{KEY}{machine_id}")).and_then(|s| serde_json::from_str(&s).ok())
}

fn save(app: &App, machine_id: &str, s: &Status) {
    app.db.set_setting(&format!("{KEY}{machine_id}"), &serde_json::to_string(s).unwrap_or_default());
}

/// Why a copy failed, in a word for the audit log, and what happened.
#[derive(Debug)]
pub struct Failed {
    pub reason: &'static str,
    pub error: String,
}

fn failed(reason: &'static str, error: impl Into<String>) -> Failed {
    Failed {
        reason,
        error: error.into(),
    }
}

fn sha_reader(mut r: impl Read) -> std::io::Result<String> {
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 64 << 10];
    loop {
        let n = r.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(h.finalize().iter().map(|b| format!("{b:02x}")).collect())
}

/// What a copy sends: each file's entry and where it is on this server.
#[derive(Debug, Default)]
pub struct Listing {
    pub files: Vec<(SyncFile, PathBuf)>,
    pub skipped: u64,
}

impl Listing {
    fn bytes(&self) -> u64 {
        self.files.iter().map(|(f, _)| f.size).sum()
    }

    fn add(&mut self, path: String, on_disk: PathBuf, seed: bool, max_bytes: u64) -> Result<(), Failed> {
        use std::os::unix::fs::PermissionsExt;
        let opened = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags_nofollow()
            .open(&on_disk)
            .and_then(|f| Ok((f.metadata()?, f)));
        let Ok((meta, file)) = opened else {
            self.skipped += 1;
            return Ok(());
        };
        if !meta.is_file() {
            self.skipped += 1;
            return Ok(());
        }
        if self.files.len() >= MAX_FILES {
            return Err(failed("too_big", format!("The folder has over {MAX_FILES} files.")));
        }
        if self.bytes() + meta.len() > max_bytes {
            return Err(failed("too_big", format!("The folder is over {} MiB (MACHINE_FOLDER_SYNC_MAX_MB).", max_bytes >> 20)));
        }
        let Ok(sha256) = sha_reader(file) else {
            self.skipped += 1;
            return Ok(());
        };
        self.files.push((
            SyncFile {
                path,
                size: meta.len(),
                sha256,
                exec: meta.permissions().mode() & 0o100 != 0,
                seed,
            },
            on_disk,
        ));
        Ok(())
    }
}

trait NoFollow {
    fn custom_flags_nofollow(&mut self) -> &mut Self;
}

impl NoFollow for std::fs::OpenOptions {
    fn custom_flags_nofollow(&mut self) -> &mut Self {
        use std::os::unix::fs::OpenOptionsExt;
        self.custom_flags(libc::O_NOFOLLOW)
    }
}

/// Every regular file under `root`, as `work/<path>`. Links are never followed.
fn walk(root: &Path, out: &mut Listing, max_bytes: u64) -> Result<(), Failed> {
    let mut dirs = vec![(root.to_path_buf(), String::from("work"))];
    while let Some((dir, rel)) = dirs.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            out.skipped += 1;
            continue;
        };
        let mut entries: Vec<_> = entries.flatten().collect();
        entries.sort_by_key(|e| e.file_name());
        for entry in entries {
            let Some(name) = entry.file_name().to_str().map(String::from) else {
                out.skipped += 1;
                continue;
            };
            let path = format!("{rel}/{name}");
            let Ok(kind) = entry.file_type() else {
                out.skipped += 1;
                continue;
            };
            if !wire::home_path(&path) {
                out.skipped += 1;
            } else if kind.is_dir() {
                dirs.push((entry.path(), path));
            } else if kind.is_file() {
                out.add(path, entry.path(), false, max_bytes)?;
            } else {
                out.skipped += 1;
            }
        }
    }
    Ok(())
}

/// The user's folder, facts and Bots' memory, as a copy sends them.
pub fn list(app: &App, user_id: &str, max_bytes: u64) -> Result<Listing, Failed> {
    let root = app.workspace_for(user_id).ok_or_else(|| failed("no_folder", "The user has no folder on this server."))?;
    let mut out = Listing::default();
    walk(&root, &mut out, max_bytes)?;
    if let Some(p) = app.data_user_file(user_id).filter(|p| p.is_file()) {
        out.add("USER.md".into(), p, true, max_bytes)?;
    }
    for bot in app.db.bots().into_iter().filter(|b| b.owner_id == user_id) {
        let path = format!("bots/{}/MEMORY.md", bot.id);
        if let Some(p) = app.data_memory_file(&bot.id).filter(|p| p.is_file() && wire::home_path(&path)) {
            out.add(path, p, true, max_bytes)?;
        }
    }
    Ok(out)
}

/// Sends one content from `have` on, chunk by chunk. A chunk the agent refuses for its
/// offset is sent again from where the agent says it is.
async fn send(client: &reqwest::Client, url: &str, file: &Path, mut have: u64, size: u64, sent: &mut u64) -> Result<(), Failed> {
    use tokio::io::{AsyncReadExt, AsyncSeekExt};
    let mut f = tokio::fs::File::open(file).await.map_err(|e| failed("source_changed", format!("{}: {e}", file.display())))?;
    let mut tries = 0;
    while have < size {
        f.seek(std::io::SeekFrom::Start(have)).await.map_err(|e| failed("source_changed", e.to_string()))?;
        let mut chunk = vec![0u8; CHUNK.min((size - have) as usize)];
        f.read_exact(&mut chunk)
            .await
            .map_err(|_| failed("source_changed", format!("{} changed while it was being copied.", file.display())))?;
        let n = chunk.len() as u64;
        let r = client
            .put(format!("{url}?offset={have}"))
            .body(chunk)
            .send()
            .await
            .map_err(|e| failed("offline", format!("Lost the machine: {}", enroll::without_url(e))))?;
        let code = r.status().as_u16();
        let reply: Value = r.json().await.unwrap_or(Value::Null);
        match code {
            200 => {
                let b: BlobReply = serde_json::from_value(reply).map_err(|_| failed("agent_error", "Its agent's answer wasn't a chunk receipt."))?;
                *sent += n;
                have = b.have;
                if b.done {
                    return Ok(());
                }
            }
            409 if tries < 3 => {
                tries += 1;
                have = reply["have"].as_u64().ok_or_else(|| failed("agent_error", "Its agent refused a chunk."))?;
            }
            422 => return Err(failed("source_changed", format!("{} changed while it was being copied.", file.display()))),
            _ => {
                let why = reply["error"].as_str().unwrap_or("no reason given");
                return Err(failed("agent_error", format!("Its agent refused a chunk ({code}): {why}")));
            }
        }
    }
    Ok(())
}

/// One copy to `m`, start to end.
async fn copy(app: &AppState, e: &Enrollment, m: &Machine, max_bytes: u64, status: &mut Status) -> Result<SyncReport, Failed> {
    let hb = enroll::heartbeat(app, e, m).await.map_err(|why| failed("offline", format!("Its agent didn't answer: {why}")))?;
    if !hb.can.iter().any(|c| c == wire::CAN_SYNC) {
        return Err(failed("agent_outdated", "Its agent can't take a folder: it is older than ADR 0041. Upgrade it."));
    }
    let listing = {
        let (app, user_id) = (app.clone(), m.user_id.clone());
        tokio::task::spawn_blocking(move || list(&app, &user_id, max_bytes))
            .await
            .map_err(|e| failed("agent_error", e.to_string()))??
    };
    status.files = listing.files.len() as u64;
    status.bytes = listing.bytes();
    status.skipped = listing.skipped;
    let manifest = SyncManifest {
        sync_id: format!("s{}", crate::random_hex(8)),
        files: listing.files.iter().map(|(f, _)| f.clone()).collect(),
    };
    let agent_err = |code: u16, reply: &Value| {
        failed("agent_error", format!("Its agent refused ({code}): {}", reply["error"].as_str().unwrap_or("no reason given")))
    };
    let (code, reply) = e
        .call_agent(app, m, reqwest::Method::POST, "/v1/sync", &manifest)
        .await
        .map_err(|why| failed("offline", format!("Its agent didn't answer: {why}")))?;
    if code != 200 {
        return Err(agent_err(code, &reply));
    }
    let plan: SyncPlan = serde_json::from_value(reply).map_err(|_| failed("agent_error", "Its agent's answer wasn't a plan."))?;
    let address = m.ipv4.clone().ok_or_else(|| failed("offline", "The machine has no address."))?;
    let client = e.upload_client(app.db.machine_pins(&m.id)).map_err(|why| failed("offline", why))?;
    for need in &plan.need {
        let Some((_, on_disk)) = listing.files.iter().find(|(f, _)| f.sha256 == need.sha256) else {
            return Err(failed("agent_error", "Its agent asked for content that isn't in the folder."));
        };
        let url = e.agent_url(&address, &format!("/v1/sync/{}/blobs/{}", manifest.sync_id, need.sha256));
        send(&client, &url, on_disk, need.have, need.size, &mut status.sent).await?;
    }
    let (code, reply) = e
        .call_agent(app, m, reqwest::Method::POST, &format!("/v1/sync/{}/finish", manifest.sync_id), &json!({}))
        .await
        .map_err(|why| failed("offline", format!("Its agent didn't answer: {why}")))?;
    if code != 200 {
        return Err(agent_err(code, &reply));
    }
    serde_json::from_value(reply).map_err(|_| failed("agent_error", "Its agent's answer wasn't a report."))
}

/// Copies the user's folder to `m` in the background, unless a copy is running.
/// Returns whether it started one.
pub fn start(app: &AppState, e: &Arc<Enrollment>, m: &Machine, by: &Who, trigger: &str) -> bool {
    let Some(settings) = e.folder.clone() else { return false };
    let Some(claim) = Claim::take(e, &m.id) else { return false };
    let before = load(app, &m.id).unwrap_or_default();
    let mut status = Status {
        state: "copying".into(),
        trigger: trigger.into(),
        by: by.actor.id.clone(),
        started_at: now(),
        done_at: before.done_at,
        attempts: before.attempts,
        ..Status::default()
    };
    save(app, &m.id, &status);
    app.db.record(&event(by, "machine.folder_sync_started", m, json!({ "trigger": trigger })));
    let (app, e, m, by) = (app.clone(), e.clone(), m.clone(), by.clone());
    tokio::spawn(async move {
        let _claim = claim;
        let res = copy(&app, &e, &m, settings.max_bytes, &mut status).await;
        status.finished_at = Some(now());
        match res {
            Ok(r) => {
                status.state = "done".into();
                status.done_at = status.finished_at;
                status.attempts = 0;
                let d = json!({ "trigger": status.trigger, "files": status.files, "bytes": status.bytes, "sent": status.sent, "skipped": status.skipped,
                    "copied": r.copied, "unchanged": r.unchanged, "seeded": r.seeded, "kept": r.kept, "conflicts": r.conflict_count });
                status.report = Some(r);
                app.db.record(&event(&by, "machine.folder_sync_finished", &m, d));
            }
            Err(f) => {
                status.state = "failed".into();
                status.attempts += 1;
                app.db.record(
                    &event(&by, "machine.folder_sync_failed", &m, json!({ "trigger": status.trigger, "reason": f.reason, "error": f.error, "sent": status.sent }))
                        .outcome(Outcome::Failure),
                );
                status.reason = Some(f.reason.into());
                status.error = Some(f.error);
            }
        }
        save(&app, &m.id, &status);
    });
    true
}

/// A user was just assigned to `m`: their folder goes there, unless it has before.
pub fn assigned(app: &AppState, cp: &ControlPlane, m: &Machine, by: &Who) {
    if let Some(e) = &cp.enrollment
        && load(app, &m.id).is_none_or(|s| s.done_at.is_none())
    {
        start(app, e, m, by, "assigned");
    }
}

/// After a heartbeat: a first copy that failed or was cut short (botd restarted) is
/// tried again, a few times, unless its folder was too big.
pub fn follow_up(app: &AppState, e: &Arc<Enrollment>, m: &Machine, hb: &Heartbeat) {
    if e.folder.is_none() || m.assigned_at.is_none() || e.copying.has(&m.id) || !hb.can.iter().any(|c| c == wire::CAN_SYNC) {
        return;
    }
    let Some(s) = load(app, &m.id) else { return };
    let due = s.done_at.is_none()
        && s.reason.as_deref() != Some("too_big")
        && s.attempts < MAX_ATTEMPTS
        && (s.state == "copying" || s.finished_at.is_some_and(|at| now() - at >= RETRY_MS));
    if due {
        start(app, e, m, &system(m), "retry");
    }
}

/// The user's first copy is running: their Bots wait for it.
pub fn first_copy_running(app: &App, e: &Enrollment, machine_id: &str) -> bool {
    e.folder.is_some() && e.copying.has(machine_id) && load(app, machine_id).is_none_or(|s| s.done_at.is_none())
}

fn view(app: &App, e: &Enrollment, m: &Machine) -> Value {
    json!({
        "machineId": m.id,
        "folderSync": if e.folder.is_some() { "on" } else { "off" },
        "maxMb": e.folder.as_ref().map(|f| f.max_bytes >> 20),
        "copying": e.copying.has(&m.id),
        "status": load(app, &m.id),
    })
}

fn control_plane(app: &App) -> Res<&ControlPlane> {
    app.control_plane
        .get()
        .map(|cp| &**cp)
        .ok_or_else(|| ApiError(StatusCode::SERVICE_UNAVAILABLE, super::NOT_CONFIGURED.into()))
}

// Admin API, under `/api/users/{key}/machine/folder-sync` (admin only, rbac::classify).

/// `GET`: how the last copy went.
pub async fn get(AppS(app): AppS<AppState>, UrlPath(key): UrlPath<String>) -> Res {
    let e = enroll::need(control_plane(&app)?)?;
    let u = need_user_key(&app, &key)?;
    let m = app.db.user_machine(&u.id).ok_or_else(|| crate::not_found("Machine"))?;
    Ok(Json(view(&app, e, &m)))
}

/// `POST`: copies the folder again now (202). Files changed on the machine are kept.
pub async fn now_copy(
    AppS(app): AppS<AppState>,
    Extension(by): Extension<Who>,
    UrlPath(key): UrlPath<String>,
) -> Res<(StatusCode, Json<Value>)> {
    let e = enroll::need(control_plane(&app)?)?;
    if e.folder.is_none() {
        return Err(ApiError(StatusCode::CONFLICT, "Folder copies are off. Set MACHINE_FOLDER_SYNC=on to turn them on.".into()));
    }
    let u = need_user_key(&app, &key)?;
    let m = app.db.user_machine(&u.id).ok_or_else(|| crate::not_found("Machine"))?;
    if !u.active() {
        return Err(ApiError(StatusCode::FORBIDDEN, "That user is disabled.".into()));
    }
    if m.state != State::Running || m.enrollment != "enrolled" {
        return Err(ApiError(
            StatusCode::CONFLICT,
            format!("Their machine is {} and its agent is {}; it must be running and enrolled.", m.state.as_str(), m.enrollment),
        ));
    }
    if !start(&app, e, &m, &by, "admin") {
        return Err(ApiError(StatusCode::CONFLICT, "Their folder is being copied already.".into()));
    }
    Ok((StatusCode::ACCEPTED, Json(view(&app, e, &m))))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> String {
        let pairs: Vec<(String, String)> = pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        move |k| pairs.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone()).unwrap_or_default()
    }

    #[test]
    fn settings_are_off_by_default_and_checked() {
        assert_eq!(Settings::from_env(&env(&[])), Ok(None));
        assert_eq!(Settings::from_env(&env(&[("MACHINE_FOLDER_SYNC", "on")])), Ok(Some(Settings { max_bytes: DEFAULT_MAX_MB << 20 })));
        assert_eq!(
            Settings::from_env(&env(&[("MACHINE_FOLDER_SYNC", "on"), ("MACHINE_FOLDER_SYNC_MAX_MB", "5")])),
            Ok(Some(Settings { max_bytes: 5 << 20 }))
        );
        assert!(Settings::from_env(&env(&[("MACHINE_FOLDER_SYNC", "yes")])).is_err());
        assert!(Settings::from_env(&env(&[("MACHINE_FOLDER_SYNC_MAX_MB", "5")])).is_err(), "a limit without copies is a mistake");
        assert!(Settings::from_env(&env(&[("MACHINE_FOLDER_SYNC", "on"), ("MACHINE_FOLDER_SYNC_MAX_MB", "0")])).is_err());
    }

    #[test]
    fn a_listing_holds_regular_files_only_and_stops_at_the_limit() {
        let root = std::env::temp_dir().join(format!("superbot-folder-{}", crate::short_id()));
        std::fs::create_dir_all(root.join("sub")).unwrap();
        std::fs::write(root.join("a.txt"), "hello").unwrap();
        std::fs::write(root.join("sub/b.sh"), "#!/bin/sh\n").unwrap();
        std::fs::set_permissions(root.join("sub/b.sh"), std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
        std::os::unix::fs::symlink("/etc/passwd", root.join("link")).unwrap();
        std::fs::write(root.join("bad\nname"), "x").unwrap();
        let mut l = Listing::default();
        walk(&root, &mut l, 1 << 20).unwrap();
        let got: Vec<(&str, u64, bool)> = l.files.iter().map(|(f, _)| (f.path.as_str(), f.size, f.exec)).collect();
        assert_eq!(got, [("work/a.txt", 5, false), ("work/sub/b.sh", 10, true)]);
        assert_eq!(l.skipped, 2, "the link and the name a machine can't hold");
        assert_eq!(l.files[0].0.sha256, "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824");
        let mut small = Listing::default();
        assert_eq!(walk(&root, &mut small, 8).unwrap_err().reason, "too_big");
    }
}
