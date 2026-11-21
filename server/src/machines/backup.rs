//! Off-host backups of machines (ADR 0071): each running, enrolled machine is exported
//! by its provider (an Incus backup of the container, without its snapshots) on a
//! schedule and streamed to S3-compatible object storage, age-encrypted to public
//! recipients when MACHINE_BACKUP_AGE_RECIPIENTS is set, as server backups are (ADR
//! 0030). Each is kept for its tier's retention; the newest of a live machine is
//! always kept. Off unless MACHINE_BACKUP_S3_BUCKET is set, so self-hosted servers
//! never see it.
//!
//! A restore makes the machine again from one of its own backups: imported beside it,
//! given today's isolation, size and firewall (never the backup's), its old identity
//! removed and a fresh one-time token written, then swapped in for the old container
//! and started. Its old certificates and tokens are revoked, so nothing enrolled from
//! the backup's disk is trusted again; it enrolls anew like a rebuilt machine (ADR
//! 0056). Backups are only taken once the provider holds no enrollment token for the
//! machine (ADR 0067), so none is in a backup's config.
//!
//! - backup: `running`, then `done` or `failed`; `deleted` once past its retention.
//! - restore: `importing` (copied from the store to the provider), `replacing` (put in
//!   the old one's place), `enrolling` (started, waiting for its agent), then `done`
//!   or `failed`. Routing refuses the machine's Bots until it is done.

use super::enroll::{self, Enrollment};
use super::provider::{ByteStream, MachineProvider, RestoreSpec};
use super::s3::{self, S3};
use super::{ControlPlane, State, Step, conflict, event, next, observe, system};
use crate::audit::{Outcome, Who};
use crate::db::{Machine, MachineBackup, MachineRestore, NewMachineBackup, now};
use crate::runner::App;
use crate::secrets::SecretStore;
use crate::users::need_user_key;
use crate::{AppState, Auth, Res, bad, not_found};
use aws_lc_rs::digest;
use axum::Json;
use axum::body::Bytes;
use axum::extract::{Extension, Path, State as AppS};
use axum::http::StatusCode;
use futures_util::StreamExt;
use serde::Deserialize;
use serde_json::{Value, json};
use std::io::{Read, Write};
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub const DEFAULT_INTERVAL_HOURS: i64 = 24;
pub const DEFAULT_RETENTION_DAYS: i64 = 14;
/// A failed backup is tried again after this long, or the interval if sooner.
const RETRY_MS: i64 = 3_600_000;
/// How much longer than the enrollment timeout a restored machine has to enroll.
const BOOT_SLACK_MS: i64 = 10 * 60_000;
/// The agent's certificate and key on its disk, which a restore must not bring back.
pub const IDENTITY_PATH: &str = "/var/lib/superbot-machine/identity.pem";
/// The manifest's format, beside each backup in the store.
const FORMAT: &str = "superbot-machine-backup/1";
const DAY_MS: i64 = 86_400_000;

/// MACHINE_BACKUP_RETENTION: days, for every tier (`14`) or per tier
/// (`7,pro=30,max=90`: 7 for the rest).
#[derive(Clone, Debug, PartialEq)]
pub struct Retention {
    pub default: i64,
    pub tiers: Vec<(String, i64)>,
}

impl Retention {
    pub fn parse(raw: &str) -> Result<Retention, String> {
        let days = |s: &str| {
            s.trim()
                .parse::<i64>()
                .ok()
                .filter(|d| (1..=3650).contains(d))
                .ok_or(format!("MACHINE_BACKUP_RETENTION: \"{}\" isn't 1 to 3650 days", crate::audit::clip(s.trim(), 20)))
        };
        let mut r = Retention { default: DEFAULT_RETENTION_DAYS, tiers: Vec::new() };
        let mut bare = false;
        for part in raw.split(',').map(str::trim).filter(|p| !p.is_empty()) {
            match part.split_once('=') {
                None if bare => return Err("MACHINE_BACKUP_RETENTION has two defaults".into()),
                None => {
                    r.default = days(part)?;
                    bare = true;
                }
                Some((tier, d)) => {
                    let tier = tier.trim();
                    if !super::slug(tier, 32) || r.tiers.iter().any(|(t, _)| t == tier) {
                        return Err(format!("MACHINE_BACKUP_RETENTION: \"{}\" isn't a tier, or is listed twice", crate::audit::clip(tier, 32)));
                    }
                    r.tiers.push((tier.into(), days(d)?));
                }
            }
        }
        Ok(r)
    }

    pub fn days(&self, tier: &str) -> i64 {
        self.tiers.iter().find(|(t, _)| t == tier).map_or(self.default, |(_, d)| *d)
    }

    fn view(&self) -> Value {
        let tiers: serde_json::Map<String, Value> = self.tiers.iter().map(|(t, d)| (t.clone(), json!(d))).collect();
        json!({ "defaultDays": self.default, "tiers": tiers })
    }
}

/// age recipients, one per line or comma: `age1...`. Comments start with `#`.
pub fn recipients(raw: &str) -> Result<Vec<age::x25519::Recipient>, String> {
    raw.lines()
        .map(str::trim)
        .filter(|l| !l.starts_with('#'))
        .flat_map(|l| l.split(',').map(str::trim))
        .filter(|r| !r.is_empty())
        .map(|r| {
            age::x25519::Recipient::from_str(r)
                .map_err(|_| format!("MACHINE_BACKUP_AGE_RECIPIENTS: \"{}\" isn't an age public key (age1...)", crate::audit::clip(r, 24)))
        })
        .collect()
}

/// age identities, as `age-keygen` writes them. Never echoed back.
pub fn identities(raw: &str) -> Result<Vec<age::x25519::Identity>, String> {
    let ids: Vec<_> = raw
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| age::x25519::Identity::from_str(l).map_err(|_| "identity: that isn't an age secret key (AGE-SECRET-KEY-1...)".to_string()))
        .collect::<Result<_, _>>()?;
    if ids.is_empty() {
        return Err("identity: no age secret key in it (AGE-SECRET-KEY-1...)".into());
    }
    Ok(ids)
}

/// Where backups go, how often, how long they're kept, and who can read them.
pub struct Settings {
    pub s3: s3::Settings,
    /// Starts every key, ending in `/` unless empty.
    pub prefix: String,
    pub recipients: Vec<age::x25519::Recipient>,
    pub interval_ms: i64,
    pub retention: Retention,
}

impl Settings {
    /// MACHINE_BACKUP_S3_BUCKET turns it on and needs MACHINE_BACKUP_S3_ENDPOINT and the
    /// keys (`s3::Settings::from_env`); MACHINE_BACKUP_S3_PREFIX (`superbot/`),
    /// MACHINE_BACKUP_AGE_RECIPIENTS (or `_FILE`), MACHINE_BACKUP_INTERVAL_HOURS (24)
    /// and MACHINE_BACKUP_RETENTION (14 days) are optional. None: off.
    pub fn from_env(store: &dyn SecretStore, var: &dyn Fn(&str) -> String) -> Result<Option<Settings>, String> {
        if var("MACHINE_BACKUP_S3_BUCKET").trim().is_empty() {
            let stray = [
                "MACHINE_BACKUP_S3_ENDPOINT",
                "MACHINE_BACKUP_AGE_RECIPIENTS",
                "MACHINE_BACKUP_AGE_RECIPIENTS_FILE",
                "MACHINE_BACKUP_INTERVAL_HOURS",
                "MACHINE_BACKUP_RETENTION",
            ];
            if let Some(k) = stray.iter().find(|k| !var(k).trim().is_empty()) {
                return Err(format!("{k} is set but MACHINE_BACKUP_S3_BUCKET isn't, so machine backups are off; set the bucket or unset {k}"));
            }
            return Ok(None);
        }
        let s3 = s3::Settings::from_env(store, var)?;
        let mut prefix = var("MACHINE_BACKUP_S3_PREFIX").trim().trim_start_matches('/').to_string();
        if var("MACHINE_BACKUP_S3_PREFIX").is_empty() {
            prefix = "superbot/".into();
        }
        if prefix.len() > 200 || !prefix.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-/".contains(&b)) || prefix.contains("//") {
            return Err("MACHINE_BACKUP_S3_PREFIX: letters, digits, dots, dashes, underscores and single slashes".into());
        }
        if !prefix.is_empty() && !prefix.ends_with('/') {
            prefix.push('/');
        }
        let mut raw = var("MACHINE_BACKUP_AGE_RECIPIENTS");
        let file = var("MACHINE_BACKUP_AGE_RECIPIENTS_FILE");
        if !file.trim().is_empty() {
            if !raw.trim().is_empty() {
                return Err("Set MACHINE_BACKUP_AGE_RECIPIENTS or MACHINE_BACKUP_AGE_RECIPIENTS_FILE, not both".into());
            }
            raw = std::fs::read_to_string(file.trim()).map_err(|e| format!("MACHINE_BACKUP_AGE_RECIPIENTS_FILE: {e}"))?;
        }
        let hours = Some(var("MACHINE_BACKUP_INTERVAL_HOURS"))
            .filter(|h| !h.trim().is_empty())
            .map_or(Ok(DEFAULT_INTERVAL_HOURS), |h| {
                h.trim().parse::<i64>().ok().filter(|h| (1..=720).contains(h)).ok_or("MACHINE_BACKUP_INTERVAL_HOURS must be 1 to 720")
            })?;
        Ok(Some(Settings {
            s3,
            prefix,
            recipients: recipients(&raw)?,
            interval_ms: hours * 3_600_000,
            retention: Retention::parse(&var("MACHINE_BACKUP_RETENTION"))?,
        }))
    }
}

/// Off-host backups, on: the settings and the store.
pub struct Offsite {
    pub s: Settings,
    pub s3: S3,
}

impl Offsite {
    pub fn new(s: Settings) -> Result<Offsite, String> {
        Ok(Offsite { s3: S3::new(s.s3.clone())?, s })
    }

    pub fn describe(&self) -> String {
        format!(
            "to {}/{} every {}h, kept {} days{}, {}",
            self.s.s3.endpoint,
            self.s.s3.bucket,
            self.s.interval_ms / 3_600_000,
            self.s.retention.default,
            if self.s.retention.tiers.is_empty() { "" } else { " (some tiers differ)" },
            if self.s.recipients.is_empty() { "not encrypted".to_string() } else { format!("encrypted to {} age recipients", self.s.recipients.len()) }
        )
    }

    /// For admins. No credentials.
    pub fn view(&self) -> Value {
        json!({
            "endpoint": self.s.s3.endpoint,
            "bucket": self.s.s3.bucket,
            "region": self.s.s3.region,
            "prefix": self.s.prefix,
            "encrypted": !self.s.recipients.is_empty(),
            "recipients": self.s.recipients.iter().map(|r| r.to_string()).collect::<Vec<_>>(),
            "intervalHours": self.s.interval_ms / 3_600_000,
            "retention": self.s.retention.view(),
        })
    }

    fn key(&self, m: &Machine, id: &str) -> String {
        format!("{}machines/{}/{id}.incus{}", self.s.prefix, m.id, if self.s.recipients.is_empty() { "" } else { ".age" })
    }
}

fn manifest_key(object_key: &str) -> String {
    let base = object_key.strip_suffix(".age").unwrap_or(object_key);
    format!("{}.json", base.strip_suffix(".incus").unwrap_or(base))
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// The provider's name for a backup while it is being made.
fn provider_name(b: &MachineBackup) -> String {
    format!("superbot-{}", b.id)
}

/// The imported copy's name while it is set up beside the machine.
fn staging(m: &Machine) -> String {
    format!("{}-restore", m.label)
}

fn provider_id(m: &Machine) -> String {
    m.provider_id.clone().unwrap_or_else(|| m.label.clone())
}

// Encryption and the bytes' way through.

/// Where age writes: taken a chunk at a time and sent on.
#[derive(Clone, Default)]
struct Sink(Arc<Mutex<Vec<u8>>>);

impl Write for Sink {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Sink {
    fn take(&self) -> Vec<u8> {
        std::mem::take(&mut self.0.lock().unwrap())
    }
}

/// Sends the provider's export to the store, encrypted if set: its size and SHA-256 as
/// stored. A failed upload leaves no parts behind.
async fn upload(off: &Offsite, mut data: ByteStream, key: &str) -> Result<(u64, String), String> {
    let mut up = off.s3.upload(key).await?;
    let sink = Sink::default();
    let mut enc = if off.s.recipients.is_empty() {
        None
    } else {
        let e = age::Encryptor::with_recipients(off.s.recipients.iter().map(|r| r as &dyn age::Recipient)).map_err(|e| e.to_string())?;
        Some(e.wrap_output(sink.clone()).map_err(|e| e.to_string())?)
    };
    let res: Result<(), String> = async {
        while let Some(chunk) = data.next().await {
            let chunk = chunk.map_err(|e| format!("reading the backup from the provider: {e}"))?;
            match enc.as_mut() {
                Some(w) => {
                    w.write_all(&chunk).map_err(|e| e.to_string())?;
                    up.write(&sink.take()).await?;
                }
                None => up.write(&chunk).await?,
            }
        }
        if let Some(w) = enc.take() {
            w.finish().map_err(|e| e.to_string())?;
            up.write(&sink.take()).await?;
        }
        Ok(())
    }
    .await;
    match res {
        Ok(()) => up.finish().await,
        Err(e) => {
            up.abort().await;
            Err(e)
        }
    }
}

/// The stored object's bytes, failing at the end unless they are the size and SHA-256
/// recorded when it was made.
fn checked(inner: impl futures_util::Stream<Item = reqwest::Result<Bytes>> + Send + 'static, sha: String, size: i64) -> ByteStream {
    struct St {
        inner: std::pin::Pin<Box<dyn futures_util::Stream<Item = reqwest::Result<Bytes>> + Send>>,
        hash: Option<digest::Context>,
        n: i64,
        sha: String,
        size: i64,
    }
    let st = St { inner: Box::pin(inner), hash: Some(digest::Context::new(&digest::SHA256)), n: 0, sha, size };
    Box::pin(futures_util::stream::unfold(st, |mut st| async move {
        st.hash.as_ref()?;
        match st.inner.next().await {
            Some(Ok(b)) => {
                st.hash.as_mut().unwrap().update(&b);
                st.n += b.len() as i64;
                Some((Ok(b), st))
            }
            Some(Err(e)) => {
                st.hash = None;
                Some((Err(std::io::Error::other(format!("reading the backup from the store: {}", e.without_url()))), st))
            }
            None => {
                let sum = hex(st.hash.take().unwrap().finish().as_ref());
                if sum == st.sha && st.n == st.size {
                    None
                } else {
                    Some((Err(std::io::Error::other("the backup in the store doesn't match its checksum")), st))
                }
            }
        }
    }))
}

/// A blocking reader over chunks sent from async code.
struct Chunks {
    rx: tokio::sync::mpsc::Receiver<Result<Bytes, std::io::Error>>,
    buf: Bytes,
}

impl Read for Chunks {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        while self.buf.is_empty() {
            match self.rx.blocking_recv() {
                Some(Ok(b)) => self.buf = b,
                Some(Err(e)) => return Err(e),
                None => return Ok(0),
            }
        }
        let n = out.len().min(self.buf.len());
        out[..n].copy_from_slice(&self.buf[..n]);
        self.buf = self.buf.slice(n..);
        Ok(n)
    }
}

/// Decrypts `input` with `ids` on a blocking thread, as it arrives.
fn decrypt(mut input: ByteStream, ids: Vec<age::x25519::Identity>) -> ByteStream {
    let (in_tx, in_rx) = tokio::sync::mpsc::channel(4);
    let (out_tx, out_rx) = tokio::sync::mpsc::channel::<Result<Bytes, std::io::Error>>(4);
    tokio::spawn(async move {
        while let Some(c) = input.next().await {
            let stop = c.is_err();
            if in_tx.send(c).await.is_err() || stop {
                break;
            }
        }
    });
    tokio::task::spawn_blocking(move || {
        let run = || -> std::io::Result<()> {
            let other = |e: age::DecryptError| std::io::Error::other(format!("decrypting the backup: {e}"));
            let d = age::Decryptor::new(Chunks { rx: in_rx, buf: Bytes::new() }).map_err(other)?;
            let mut r = d.decrypt(ids.iter().map(|i| i as &dyn age::Identity)).map_err(other)?;
            let mut buf = vec![0u8; 64 * 1024];
            loop {
                let n = r.read(&mut buf)?;
                if n == 0 || out_tx.blocking_send(Ok(Bytes::copy_from_slice(&buf[..n]))).is_err() {
                    return Ok(());
                }
            }
        };
        if let Err(e) = run() {
            let _ = out_tx.blocking_send(Err(e));
        }
    });
    Box::pin(futures_util::stream::unfold(out_rx, |mut rx| async move { rx.recv().await.map(|c| (c, rx)) }))
}

// Backups

/// Why `m` can't be backed up now, if it can't.
fn unable(app: &App, cp: &ControlPlane, m: &Machine) -> Option<String> {
    if !cp.owns(m) {
        return Some(format!("It is at {}, not this server's provider.", m.provider));
    }
    if m.state != State::Running {
        return Some(format!("It is {}; only running machines are backed up.", m.state.as_str()));
    }
    if m.enrollment != "enrolled" || m.enroll_by.is_some() {
        return Some("Its agent hasn't enrolled with its latest token, so the provider may still hold that token (ADR 0067).".into());
    }
    if super::rebuild::underway(m) {
        return Some("A rebuild is underway.".into());
    }
    if app.db.machine_restoring(&m.id).is_some() {
        return Some("A restore is underway.".into());
    }
    None
}

/// Starts a backup of `m`: checked and recorded under the lock, so it can't race a
/// restore or another backup. `who`: the admin, or None for the schedule.
async fn begin(app: &App, cp: &ControlPlane, off: &Offsite, m: &Machine, who: Option<&str>) -> Result<MachineBackup, String> {
    let p = cp.provider.as_deref().ok_or(super::NOT_CONFIGURED)?;
    if let Some(why) = unable(app, cp, m) {
        return Err(why);
    }
    let pm = p.get(&provider_id(m)).await.map_err(|e| e.to_string())?;
    if pm.user_data {
        return Err("The provider still holds its enrollment token; it is backed up once that is cleared (ADR 0067).".into());
    }
    let id = format!("b{}", crate::random_hex(8));
    let key = off.key(m, &id);
    let n = NewMachineBackup { id: &id, machine: m, object_key: &key, encrypted: !off.s.recipients.is_empty(), created_by: Some(who.unwrap_or("schedule")) };
    app.db.machine_backup_start(&n).ok_or_else(|| "A backup of it is running already.".to_string())
}

/// Makes the backup at the provider, sends it to the store with its manifest, and
/// deletes the provider's copy. Runs without the lock: a restore waits for it.
async fn run(app: &App, cp: &ControlPlane, off: &Offsite, m: &Machine, b: &MachineBackup, by: &Who) {
    let Some(p) = cp.provider.as_deref() else { return };
    let (pid, name) = (provider_id(m), provider_name(b));
    let res: Result<(u64, String), String> = async {
        p.create_backup(&pid, &name).await.map_err(|e| e.to_string())?;
        let sent = match p.export_backup(&pid, &name).await {
            Ok(data) => upload(off, data, &b.object_key).await,
            Err(e) => Err(e.to_string()),
        };
        if let Err(e) = p.delete_backup(&pid, &name).await {
            eprintln!("Machine backups: deleting {name} at the provider: {e} (it expires by itself)");
        }
        let (size, sha) = sent?;
        let manifest = json!({
            "format": FORMAT, "backupId": b.id, "machineId": m.id, "userId": m.user_id, "label": m.label,
            "provider": m.provider, "tier": m.tier, "plan": m.plan, "createdAt": b.created_at, "object": b.object_key,
            "size": size, "sha256": sha, "encrypted": b.encrypted,
            "recipients": off.s.recipients.iter().map(|r| r.to_string()).collect::<Vec<_>>(),
        });
        if let Err(e) = off.s3.put(&manifest_key(&b.object_key), serde_json::to_vec_pretty(&manifest).unwrap_or_default()).await {
            let _ = off.s3.delete(&b.object_key).await;
            return Err(e);
        }
        Ok((size, sha))
    }
    .await;
    let m = app.db.machine(&m.id).unwrap_or_else(|| m.clone());
    match res {
        Ok((size, sha)) => {
            let expires = b.created_at + off.s.retention.days(&b.tier) * DAY_MS;
            if app.db.machine_backup_end(&b.id, Some((size as i64, &sha, expires)), None) {
                let d = json!({ "backupId": b.id, "size": size, "sha256": sha, "encrypted": b.encrypted, "object": b.object_key, "expiresAt": expires, "by": b.created_by });
                app.db.record(&event(by, "machine.backup_created", &m, d));
            }
        }
        Err(e) => {
            if app.db.machine_backup_end(&b.id, None, Some(&e)) {
                let d = json!({ "backupId": b.id, "error": e, "by": b.created_by });
                app.db.record(&event(by, "machine.backup_failed", &m, d).outcome(Outcome::Failure));
            }
        }
    }
}

/// Whether `m` is due a scheduled backup.
fn due(app: &App, off: &Offsite, m: &Machine) -> bool {
    let at = now();
    match app.db.machine_backups(&m.id).into_iter().find(|b| b.state != "deleted") {
        None => true,
        Some(b) if b.state == "running" => false,
        Some(b) if b.state == "failed" => at - b.created_at >= RETRY_MS.min(off.s.interval_ms),
        Some(b) => at - b.created_at >= off.s.interval_ms,
    }
}

/// Deletes backups past their retention from the store, but never a live machine's
/// newest. Returns how many went.
pub async fn prune(app: &App, off: &Offsite) -> usize {
    let at = now();
    let mut gone = 0;
    for b in app.db.machine_backups_in("done").into_iter().filter(|b| b.expires_at.is_some_and(|e| e <= at)) {
        let m = app.db.machine(&b.machine_id);
        let live = m.as_ref().is_some_and(|m| m.state != State::Destroyed);
        if live && app.db.machine_last_backup(&b.machine_id).is_some_and(|l| l.id == b.id) {
            continue;
        }
        let res = match off.s3.delete(&b.object_key).await {
            Ok(()) => off.s3.delete(&manifest_key(&b.object_key)).await,
            Err(e) => Err(e),
        };
        match res {
            Ok(()) if app.db.machine_backup_deleted(&b.id) => {
                gone += 1;
                let d = json!({ "backupId": b.id, "object": b.object_key, "reason": "retention", "createdAt": b.created_at, "expiresAt": b.expires_at });
                if let Some(m) = &m {
                    app.db.record(&event(&system(m), "machine.backup_deleted", m, d));
                }
            }
            Ok(()) => {}
            Err(e) => eprintln!("Machine backups: deleting {} past its retention: {e}", b.id),
        }
    }
    gone
}

/// One pass: what's past its retention goes, restores that enrolled finish, and every
/// machine that's due is backed up, one at a time. Returns how many were backed up.
pub async fn pass(app: &AppState, cp: &ControlPlane) -> usize {
    let Some(off) = cp.offsite.as_deref() else { return 0 };
    prune(app, off).await;
    follow_up(app, cp).await;
    let ids: Vec<String> = app
        .db
        .machines(Some(State::Running))
        .into_iter()
        .filter(|m| unable(app, cp, m).is_none() && due(app, off, m))
        .map(|m| m.id)
        .collect();
    let mut made = 0;
    for id in ids {
        let started = {
            let _g = cp.ops.lock().await;
            match app.db.machine(&id).filter(|m| unable(app, cp, m).is_none() && due(app, off, m)) {
                Some(m) => begin(app, cp, off, &m, None).await.ok().map(|b| (m, b)),
                None => None,
            }
        };
        if let Some((m, b)) = started {
            run(app, cp, off, &m, &b, &system(&m)).await;
            made += app.db.machine_backup(&b.id).is_some_and(|b| b.state == "done") as usize;
        }
    }
    made
}

/// What a botd that stopped mid-way left: backups running end as failed (the provider's
/// copy expires by itself), and restores not yet started end as failed too. Returns
/// those restores, whose imported copies `clean_up` deletes.
fn interrupted(app: &App) -> Vec<MachineRestore> {
    let mut left = Vec::new();
    for b in app.db.machine_backups_in("running") {
        if app.db.machine_backup_end(&b.id, None, Some("botd stopped while it was running"))
            && let Some(m) = app.db.machine(&b.machine_id)
        {
            let d = json!({ "backupId": b.id, "error": "interrupted", "by": b.created_by });
            app.db.record(&event(&system(&m), "machine.backup_failed", &m, d).outcome(Outcome::Failure));
        }
    }
    for st in ["importing", "replacing"] {
        for r in app.db.machine_restores_in(st) {
            if let Some(m) = app.db.machine(&r.machine_id) {
                fail_restore(app, &system(&m), &m, &r, &[st], "botd stopped mid-restore; check the machine and restore again");
            }
            left.push(r);
        }
    }
    left
}

/// Deletes the copies interrupted restores imported, trying again a few times while the
/// provider is busy. A copy is left alone once a newer restore of its machine began.
async fn clean_up(app: &App, cp: &ControlPlane, mut left: Vec<MachineRestore>) {
    let Some(p) = cp.provider.as_deref() else { return };
    for _ in 0..5 {
        let mut again = Vec::new();
        for r in left {
            let Some(m) = app.db.machine(&r.machine_id) else { continue };
            let _g = cp.ops.lock().await;
            if app.db.machine_last_restore(&m.id).is_some_and(|l| l.id != r.id) {
                continue;
            }
            // Stopped between deleting the old container and renaming the copy, the copy
            // is all that's left of the machine.
            if r.state == "replacing" && p.get(&provider_id(&m)).await.is_err() {
                eprintln!("Machine backups: kept {}'s restore copy: its container is gone", m.id);
                continue;
            }
            if let Err(e) = p.delete(&staging(&m)).await {
                eprintln!("Machine backups: deleting {}'s interrupted restore copy: {e}", m.id);
                again.push(r);
            }
        }
        if again.is_empty() {
            return;
        }
        left = again;
        tokio::time::sleep(Duration::from_secs(60)).await;
    }
}

/// Backs up due machines and follows restores, from startup, when backups are on.
pub fn start(app: AppState, cp: Arc<ControlPlane>) {
    if cp.offsite.is_none() || !cp.enabled() {
        return;
    }
    let left = interrupted(&app);
    let (a, c) = (app.clone(), cp.clone());
    tokio::spawn(async move {
        clean_up(&a, &c, left).await;
        let mut tick = tokio::time::interval(c.reconcile_every.max(Duration::from_secs(60)));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            pass(&a, &c).await;
        }
    });
    // Apart from backups, which can take hours, so a restored machine is seen to be back.
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(cp.reconcile_every);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            follow_up(&app, &cp).await;
        }
    });
}

// Restores

fn fail_restore(app: &App, by: &Who, m: &Machine, r: &MachineRestore, from: &[&str], error: &str) {
    if app.db.machine_restore_move(&r.id, from, "failed", Some(error)) {
        app.db.revoke_machine_tokens(&m.id);
        let d = json!({ "restoreId": r.id, "backupId": r.backup_id, "error": error, "by": r.created_by });
        app.db.record(&event(by, "machine.restore_failed", m, d).outcome(Outcome::Failure));
    }
}

/// Restores whose machine enrolled again are done; ones that didn't in time failed.
pub async fn follow_up(app: &AppState, cp: &ControlPlane) {
    let Some(e) = cp.enrollment.as_deref() else { return };
    for r in app.db.machine_restores_in("enrolling") {
        // A restore boots its machine under the lock, so what's read before it is stale.
        let _g = cp.ops.lock().await;
        let Some(r) = app.db.machine_restore(&r.id).filter(|r| r.state == "enrolling") else { continue };
        let Some(m) = app.db.machine(&r.machine_id) else { continue };
        let since = r.replaced_at.unwrap_or(r.created_at);
        if m.enrollment == "enrolled" && m.enrolled_at.is_some_and(|t| t >= since) {
            if app.db.machine_restore_move(&r.id, &["enrolling"], "done", None) {
                let by = system(&m);
                app.db.record(&event(&by, "machine.restored", &m, json!({ "restoreId": r.id, "backupId": r.backup_id, "by": r.created_by })));
                if m.assigned_at.is_some() {
                    super::folder::assigned(app, cp, &m, &by);
                }
            }
        } else if !matches!(m.state, State::Running) || now() > since + e.enroll_timeout_ms + BOOT_SLACK_MS {
            let why = if m.state == State::Running {
                format!("It didn't enroll again within {} minutes of the restore.", (e.enroll_timeout_ms + BOOT_SLACK_MS) / 60_000)
            } else {
                format!("The machine is {}.", m.state.as_str())
            };
            fail_restore(app, &system(&m), &m, &r, &["enrolling"], &why);
        }
    }
}

/// Copies the backup from the store into the provider beside the machine.
async fn import(off: &Offsite, p: &dyn MachineProvider, m: &Machine, b: &MachineBackup, ids: Vec<age::x25519::Identity>) -> Result<(), String> {
    let name = staging(m);
    p.delete(&name).await.map_err(|e| format!("clearing an earlier restore's copy: {e}"))?;
    let res = off.s3.get(&b.object_key).await?;
    let data = checked(res.bytes_stream(), b.sha256.clone().unwrap_or_default(), b.size.unwrap_or(-1));
    let data = if b.encrypted { decrypt(data, ids) } else { data };
    // The provider only sees the upload break; this says why.
    let why = Arc::new(Mutex::new(None::<String>));
    let seen = why.clone();
    let data: ByteStream = Box::pin(data.inspect(move |c| {
        if let Err(e) = c {
            seen.lock().unwrap().get_or_insert_with(|| e.to_string());
        }
    }));
    if let Err(e) = p.import_backup(&name, data).await {
        let _ = p.delete(&name).await;
        return Err(why.lock().unwrap().take().unwrap_or_else(|| e.to_string()));
    }
    Ok(())
}

/// Puts the imported copy in the machine's place with a fresh token, under the lock.
async fn replace(app: &App, cp: &ControlPlane, e: &Enrollment, r: &MachineRestore, by: &Who) -> Result<(), String> {
    let p = cp.provider.as_deref().ok_or(super::NOT_CONFIGURED)?;
    let mut m = app.db.machine(&r.machine_id).ok_or("The machine is gone.")?;
    if !matches!(m.state, State::Running | State::Suspended | State::Error) {
        return Err(format!("The machine is {} now.", m.state.as_str()));
    }
    if !app.db.machine_restore_move(&r.id, &["importing"], "replacing", None) {
        return Err("The restore changed meanwhile.".into());
    }
    app.db.revoke_machine_tokens(&m.id);
    let who = by.actor.id.as_deref();
    let prior = (m.enroll_by, m.enroll_overdue_at);
    let (token, expires) = e.mint_token(app, &m.id, who)?;
    app.db.record(&event(by, "machine.enroll_token_issued", &m, json!({ "expiresAt": expires, "via": "restore", "restoreId": r.id })));
    let spec = RestoreSpec {
        plan: m.plan.clone(),
        tags: cp.spec(&m, None).tags,
        authorized_keys: cp.authorized_keys.clone(),
        firewall_id: m.firewall_id.clone(),
        files: e.restore_files(&m, &token),
        remove: vec![IDENTITY_PATH.into()],
    };
    let pid = provider_id(&m);
    if let Err(err) = p.replace_with(&pid, &staging(&m), &spec).await {
        app.db.restore_enroll_by(&m.id, prior.0, prior.1);
        return Err(err.to_string());
    }
    // What the old disk's agent said and held is gone with it, as after a rebuild. All
    // of it, and the time enrollment counts from, before it boots: enrollment doesn't
    // take the lock, and the new agent mustn't lose its certificate to this.
    app.db.machine_rebuilt_reset(&m.id);
    app.db.forget_sessions_of(&m.user_id);
    super::folder::forget(app, &m.id);
    enroll::revoke_certs(app, by, &m, "restored");
    app.db.machine_restore_move(&r.id, &["replacing"], "enrolling", None);
    let from = m.state;
    let booted = match p.boot(&pid).await {
        Ok(()) => p.get(&pid).await,
        Err(e) => Err(e),
    };
    match booted {
        Ok(pm) => {
            observe(&mut m, &pm);
            m.state = next(from, Step::Restored).unwrap_or(from);
            m.last_error = None;
            app.db.save_machine(&m, from);
            if from == State::Suspended {
                app.db.record(&event(by, "machine.resumed", &m, json!({ "via": "restore", "restoreId": r.id })));
            }
            Ok(())
        }
        Err(err) => {
            let why = format!("starting the restored machine: {err}");
            m.state = next(from, Step::Fail).unwrap_or(State::Error);
            m.last_error = Some(why.clone());
            app.db.save_machine(&m, from);
            Err(why)
        }
    }
}

/// The whole restore after it was asked for: import, then replace under the lock.
async fn restore(app: AppState, cp: Arc<ControlPlane>, r: MachineRestore, b: MachineBackup, ids: Vec<age::x25519::Identity>, by: Who) {
    let (Some(off), Some(p), Some(e)) = (cp.offsite.as_deref(), cp.provider.as_deref(), cp.enrollment.as_deref()) else { return };
    let Some(m) = app.db.machine(&r.machine_id) else { return };
    if let Err(why) = import(off, p, &m, &b, ids).await {
        let _g = cp.ops.lock().await;
        return fail_restore(&app, &by, &m, &r, &["importing"], &why);
    }
    let _g = cp.ops.lock().await;
    if let Err(why) = replace(&app, &cp, e, &r, &by).await {
        let _ = p.delete(&staging(&m)).await;
        let m = app.db.machine(&m.id).unwrap_or(m);
        fail_restore(&app, &by, &m, &r, &["importing", "replacing", "enrolling"], &why);
    }
}

// HTTP, under `/api/users/{key}/machine/backups|restore` and `/api/machines/backups`
// (admin only, rbac::classify).

fn need(a: &Auth) -> Res<(&ControlPlane, &Offsite)> {
    let cp = &*a.machines;
    cp.need()?;
    let off = cp.offsite.as_deref().ok_or_else(|| {
        conflict("Off-host machine backups are off on this server. Set MACHINE_BACKUP_S3_BUCKET and the rest (docs/ops/incus-containers.md).".into())
    })?;
    Ok((cp, off))
}

fn need_machine(app: &AppState, key: &str) -> Res<Machine> {
    let u = need_user_key(app, key)?;
    app.db.user_machine(&u.id).ok_or_else(|| not_found("Machine"))
}

fn view(app: &App, m: &Machine) -> Value {
    json!({
        "machineId": m.id,
        "userId": m.user_id,
        "state": m.state,
        "backups": app.db.machine_backups(&m.id),
        "restore": app.db.machine_last_restore(&m.id),
    })
}

/// `GET /api/machines/backups`: the settings, and every backup not deleted.
pub async fn list_all(AppS(app): AppS<AppState>, Extension(a): Extension<Arc<Auth>>) -> Res {
    let (_, off) = need(&a)?;
    let mut all: Vec<MachineBackup> = ["running", "done", "failed"].iter().flat_map(|s| app.db.machine_backups_in(s)).collect();
    all.sort_by(|x, y| (y.created_at, &y.id).cmp(&(x.created_at, &x.id)));
    Ok(Json(json!({ "settings": off.view(), "backups": all })))
}

/// `GET /api/users/{key}/machine/backups`: the machine's backups and latest restore.
pub async fn list(AppS(app): AppS<AppState>, Extension(a): Extension<Arc<Auth>>, Path(key): Path<String>) -> Res {
    need(&a)?;
    Ok(Json(view(&app, &need_machine(&app, &key)?)))
}

/// `POST /api/users/{key}/machine/backups`: backs it up now. 202 with the backup; the
/// audit log and `GET` say how it went.
pub async fn create(
    AppS(app): AppS<AppState>,
    Extension(a): Extension<Arc<Auth>>,
    Extension(by): Extension<Who>,
    Path(key): Path<String>,
) -> Res<(StatusCode, Json<Value>)> {
    let (cp, off) = need(&a)?;
    let m = need_machine(&app, &key)?;
    let b = {
        let _g = cp.ops.lock().await;
        let m = app.db.machine(&m.id).ok_or_else(|| not_found("Machine"))?;
        cp.need_own(&m)?;
        begin(&app, cp, off, &m, by.actor.id.as_deref()).await.map_err(conflict)?
    };
    let cp = a.machines.clone();
    let (task_app, task_b) = (app.clone(), b.clone());
    tokio::spawn(async move {
        if let (Some(off), Some(m)) = (cp.offsite.as_deref(), task_app.db.machine(&task_b.machine_id)) {
            run(&task_app, &cp, off, &m, &task_b, &by).await;
        }
    });
    Ok((StatusCode::ACCEPTED, Json(json!(b))))
}

/// `{backupId, identity?}`: `identity` is the age secret key for an encrypted backup.
/// Used for this restore only, never stored or logged.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RestoreBody {
    backup_id: String,
    #[serde(default)]
    identity: Option<String>,
}

/// `GET /api/users/{key}/machine/restore`: its latest restore.
pub async fn restore_status(AppS(app): AppS<AppState>, Extension(a): Extension<Arc<Auth>>, Path(key): Path<String>) -> Res {
    need(&a)?;
    let m = need_machine(&app, &key)?;
    Ok(Json(json!({ "machineId": m.id, "restore": app.db.machine_last_restore(&m.id) })))
}

/// `POST /api/users/{key}/machine/restore` `{backupId, identity?}`: makes the machine
/// again from one of its own backups. Everything on it since is lost. 202; the audit
/// log and `GET` say how it went.
pub async fn restore_request(
    AppS(app): AppS<AppState>,
    Extension(a): Extension<Arc<Auth>>,
    Extension(by): Extension<Who>,
    Path(key): Path<String>,
    Json(req): Json<RestoreBody>,
) -> Res<(StatusCode, Json<Value>)> {
    let (cp, _) = need(&a)?;
    if cp.enrollment.is_none() {
        return Err(conflict("A restored machine enrolls again, so it needs enrollment on (MACHINE_CONTROL_URL).".into()));
    }
    let m = need_machine(&app, &key)?;
    let _g = cp.ops.lock().await;
    let m = app.db.machine(&m.id).ok_or_else(|| not_found("Machine"))?;
    cp.need_own(&m)?;
    let b = app
        .db
        .machine_backup(req.backup_id.trim())
        .filter(|b| b.machine_id == m.id)
        .ok_or_else(|| not_found("Backup of this machine"))?;
    if b.state != "done" {
        return Err(conflict(format!("That backup is {}; only finished ones can be restored.", b.state)));
    }
    if !matches!(m.state, State::Running | State::Suspended | State::Error) {
        return Err(conflict(format!("The machine is {}; it can be restored when it's running, suspended or in error.", m.state.as_str())));
    }
    if super::rebuild::underway(&m) {
        return Err(conflict("A rebuild is underway.".into()));
    }
    if let Some(r) = app.db.machine_restoring(&m.id) {
        return Err(conflict(format!("A restore is {} already.", r.state)));
    }
    if app.db.machine_backups(&m.id).iter().any(|b| b.state == "running") {
        return Err(conflict("A backup of it is running; restore once it's done.".into()));
    }
    let ids = match (b.encrypted, req.identity.as_deref().filter(|i| !i.trim().is_empty())) {
        (true, None) => return Err(bad("That backup is encrypted: send its age identity as \"identity\" (botctl machine restore ... --identity <file>).")),
        (true, Some(raw)) => identities(raw).map_err(bad)?,
        (false, _) => Vec::new(),
    };
    let id = format!("r{}", crate::random_hex(8));
    let r = app
        .db
        .machine_restore_start(&id, &m.id, &b.id, by.actor.id.as_deref())
        .ok_or_else(|| conflict("A restore is underway already.".into()))?;
    let d = json!({ "restoreId": r.id, "backupId": b.id, "backupCreatedAt": b.created_at, "encrypted": b.encrypted, "was": m.state });
    app.db.record(&event(&by, "machine.restore_requested", &m, d));
    tokio::spawn(restore(app.clone(), a.machines.clone(), r.clone(), b, ids, by));
    Ok((StatusCode::ACCEPTED, Json(json!({ "machineId": m.id, "restore": r }))))
}

/// The newest finished backup, as the machine's views show it.
pub fn last(app: &App, machine_id: &str) -> Value {
    app.db
        .machine_last_backup(machine_id)
        .map_or(Value::Null, |b| json!({ "id": b.id, "at": b.created_at, "size": b.size, "encrypted": b.encrypted, "expiresAt": b.expires_at }))
}

/// Why a Bot can't run on the machine now, if a restore is underway.
pub fn restoring(db: &crate::db::Db, machine_id: &str) -> bool {
    db.machine_restoring(machine_id).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secrets::env::EnvStore;

    #[test]
    fn retention_per_tier() {
        assert_eq!(Retention::parse("").unwrap(), Retention { default: 14, tiers: vec![] });
        let r = Retention::parse("7, pro=30 ,max=90").unwrap();
        assert_eq!((r.days("starter"), r.days("pro"), r.days("max")), (7, 30, 90));
        assert_eq!(Retention::parse("pro=30").unwrap().days("starter"), DEFAULT_RETENTION_DAYS);
        for bad in ["0", "7,8", "pro=0", "pro=30,pro=40", "Pro=3", "x", "pro=", "4000"] {
            assert!(Retention::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn keys_and_names() {
        assert_eq!(manifest_key("p/machines/m1/b1.incus.age"), "p/machines/m1/b1.json");
        assert_eq!(manifest_key("p/machines/m1/b1.incus"), "p/machines/m1/b1.json");
    }

    #[test]
    fn settings_are_off_unless_a_bucket_is_set() {
        let keys = EnvStore::fixed(&[("MACHINE_BACKUP_S3_ACCESS_KEY_ID", "AKID"), ("MACHINE_BACKUP_S3_SECRET_ACCESS_KEY", "s3cret-0123")]);
        let with = |vars: &[(&str, &str)]| {
            let vars: Vec<(String, String)> = vars.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
            Settings::from_env(&keys, &move |k| vars.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone()).unwrap_or_default())
        };
        assert!(with(&[]).unwrap().is_none());
        let stray = with(&[("MACHINE_BACKUP_RETENTION", "7")]).err().unwrap();
        assert!(stray.contains("MACHINE_BACKUP_S3_BUCKET"), "{stray}");
        let base = [("MACHINE_BACKUP_S3_BUCKET", "backups"), ("MACHINE_BACKUP_S3_ENDPOINT", "https://s3.example.com")];
        let s = with(&base).unwrap().unwrap();
        assert_eq!((s.prefix.as_str(), s.interval_ms, s.recipients.len()), ("superbot/", 24 * 3_600_000, 0));
        let id = age::x25519::Identity::generate();
        let public = id.to_public().to_string();
        let s = with(&[base[0], base[1], ("MACHINE_BACKUP_S3_PREFIX", "/acme/m"), ("MACHINE_BACKUP_AGE_RECIPIENTS", &format!("# ops\n{public}")), ("MACHINE_BACKUP_INTERVAL_HOURS", "6")])
            .unwrap()
            .unwrap();
        assert_eq!((s.prefix.as_str(), s.interval_ms, s.recipients.len()), ("acme/m/", 6 * 3_600_000, 1));
        for bad in [
            &[base[0]][..],
            &[base[0], base[1], ("MACHINE_BACKUP_AGE_RECIPIENTS", "age1nope")],
            &[base[0], base[1], ("MACHINE_BACKUP_INTERVAL_HOURS", "0")],
            &[base[0], base[1], ("MACHINE_BACKUP_S3_PREFIX", "a b")],
            &[base[0], ("MACHINE_BACKUP_S3_ENDPOINT", "http://s3.example.com")],
        ] {
            assert!(with(bad).is_err(), "{bad:?}");
        }
        let no_keys = Settings::from_env(&EnvStore::fixed(&[]), &|k| match k {
            "MACHINE_BACKUP_S3_BUCKET" => "backups".into(),
            "MACHINE_BACKUP_S3_ENDPOINT" => "https://s3.example.com".into(),
            _ => String::new(),
        });
        assert!(no_keys.err().unwrap().contains("MACHINE_BACKUP_S3_"));
    }

    #[test]
    fn identities_never_echo_the_key() {
        let id = age::x25519::Identity::generate();
        use age::secrecy::ExposeSecret;
        let secret = id.to_string().expose_secret().to_string();
        assert_eq!(identities(&format!("# created: now\n{secret}\n")).unwrap().len(), 1);
        let e = identities("AGE-SECRET-KEY-1NOTAKEY").err().unwrap();
        assert!(!e.contains("NOTAKEY"), "{e}");
        assert!(identities("# nothing").is_err());
    }

    #[tokio::test]
    async fn encrypts_and_decrypts_as_a_stream() {
        let id = age::x25519::Identity::generate();
        let data: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
        let sink = Sink::default();
        let mut w = age::Encryptor::with_recipients(std::iter::once(&id.to_public() as &dyn age::Recipient)).unwrap().wrap_output(sink.clone()).unwrap();
        for c in data.chunks(7000) {
            w.write_all(c).unwrap();
        }
        w.finish().unwrap();
        let sealed = sink.take();
        assert_ne!(&sealed[..data.len().min(sealed.len())], &data[..data.len().min(sealed.len())]);
        let input: ByteStream = Box::pin(futures_util::stream::iter(sealed.chunks(5000).map(|c| Ok(Bytes::copy_from_slice(c))).collect::<Vec<_>>()));
        let mut out = Vec::new();
        let mut s = decrypt(input, vec![id]);
        while let Some(c) = s.next().await {
            out.extend_from_slice(&c.unwrap());
        }
        assert_eq!(out, data);

        let other = age::x25519::Identity::generate();
        let input: ByteStream = Box::pin(futures_util::stream::iter(vec![Ok(Bytes::from(sealed))]));
        let mut s = decrypt(input, vec![other]);
        let e = s.next().await.unwrap().unwrap_err();
        assert!(e.to_string().contains("decrypting"), "{e}");
    }
}
