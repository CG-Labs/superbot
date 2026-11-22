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
//! A destroyed machine's backups can also be deleted at once on request (ADR 0108), by an
//! admin or with the erasure of its user (ADR 0102).
//!
//! - backup: `running`, then `done` or `failed`; `deleted` once past its retention, or
//!   once deleted on request.
//! - restore: `importing` (copied from the store to the provider), `replacing` (put in
//!   the old one's place), `enrolling` (started, waiting for its agent), then `done`
//!   or `failed`. Routing refuses the machine's Bots until it is done.

use super::enroll::{self, Enrollment};
use super::provider::{ByteStream, HostStatus, MachineProvider, RestoreSpec};
use super::s3::{self, S3};
use super::{ControlPlane, State, Step, conflict, event, next, observe, system};
use crate::audit::{Outcome, Who};
use crate::db::{Machine, MachineBackup, MachineRestore, NewMachineBackup, NewMachineRestore, now};
use crate::runner::App;
use crate::secrets::SecretStore;
use crate::users::need_user_key;
use crate::{ApiError, AppState, Auth, Res, bad, not_found};
use aws_lc_rs::digest;
use axum::Json;
use axum::body::Bytes;
use axum::extract::{Extension, Path, State as AppS};
use axum::http::StatusCode;
use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::io::{Read, Write};
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub const DEFAULT_INTERVAL_HOURS: i64 = 24;
/// The schedule when MACHINE_BACKUP_INTERVAL_HOURS is unset (ADR 0074): the default
/// tiers' targets. Any other tier gets the bare value.
pub const DEFAULT_INTERVALS: &str = "24,pro=12,max=6";
pub const DEFAULT_RETENTION_DAYS: i64 = 14;
/// A tier's RPO when MACHINE_BACKUP_RPO_HOURS doesn't name one: its interval plus this,
/// which covers one failed attempt and its retry an hour later, and the export itself.
pub const RPO_HEADROOM_HOURS: i64 = 2;
/// The least a set RPO may exceed its tier's interval by: the retry alone.
pub const RPO_MIN_HEADROOM_HOURS: i64 = 1;
pub const DEFAULT_RTO_MINUTES: i64 = 60;
const HOUR_MS: i64 = 3_600_000;
/// A failed backup is tried again after this long, or the interval if sooner.
const RETRY_MS: i64 = HOUR_MS;
/// How much longer than the enrollment timeout a restored machine has to enroll.
const BOOT_SLACK_MS: i64 = 10 * 60_000;
/// The agent's certificate and key on its disk, which a restore must not bring back.
pub const IDENTITY_PATH: &str = "/var/lib/superbot-machine/identity.pem";
/// The manifest's format, beside each backup in the store.
const FORMAT: &str = "superbot-machine-backup/1";
const DAY_MS: i64 = 86_400_000;

/// A number for every tier (`14`) or per tier (`7,pro=30,max=90`: 7 for the rest), as
/// MACHINE_BACKUP_RETENTION, MACHINE_BACKUP_INTERVAL_HOURS, MACHINE_BACKUP_RPO_HOURS and
/// MACHINE_RESTORE_RTO_MINUTES take it. `default` None: the setting's own fallback.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct PerTier {
    pub default: Option<i64>,
    pub tiers: Vec<(String, i64)>,
}

impl PerTier {
    pub fn parse(var: &str, raw: &str, range: std::ops::RangeInclusive<i64>, unit: &str) -> Result<PerTier, String> {
        let value = |s: &str| {
            s.trim().parse::<i64>().ok().filter(|d| range.contains(d)).ok_or(format!(
                "{var}: \"{}\" isn't {} to {} {unit}",
                crate::audit::clip(s.trim(), 20),
                range.start(),
                range.end()
            ))
        };
        let mut r = PerTier::default();
        for part in raw.split(',').map(str::trim).filter(|p| !p.is_empty()) {
            match part.split_once('=') {
                None if r.default.is_some() => return Err(format!("{var} has two defaults")),
                None => r.default = Some(value(part)?),
                Some((tier, d)) => {
                    let tier = tier.trim();
                    if !super::slug(tier, 32) || r.tiers.iter().any(|(t, _)| t == tier) {
                        return Err(format!("{var}: \"{}\" isn't a tier, or is listed twice", crate::audit::clip(tier, 32)));
                    }
                    r.tiers.push((tier.into(), value(d)?));
                }
            }
        }
        Ok(r)
    }

    pub fn get(&self, tier: &str) -> Option<i64> {
        self.tiers.iter().find(|(t, _)| t == tier).map(|(_, d)| *d).or(self.default)
    }

    pub fn or(&self, tier: &str, fallback: i64) -> i64 {
        self.get(tier).unwrap_or(fallback)
    }

    fn names(&self) -> impl Iterator<Item = &str> {
        self.tiers.iter().map(|(t, _)| t.as_str())
    }
}

/// Retention in days (MACHINE_BACKUP_RETENTION), 14 for tiers it doesn't name.
pub type Retention = PerTier;

impl Retention {
    pub fn retention(raw: &str) -> Result<Retention, String> {
        PerTier::parse("MACHINE_BACKUP_RETENTION", raw, 1..=3650, "days")
    }

    pub fn days(&self, tier: &str) -> i64 {
        self.or(tier, DEFAULT_RETENTION_DAYS)
    }

    fn view(&self) -> Value {
        let tiers: serde_json::Map<String, Value> = self.tiers.iter().map(|(t, d)| (t.clone(), json!(d))).collect();
        json!({ "defaultDays": self.default.unwrap_or(DEFAULT_RETENTION_DAYS), "tiers": tiers })
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
    /// Hours between a machine's backups (ADR 0074).
    pub interval: PerTier,
    /// Hours a machine may go without a newer backup before it breaches its RPO. Tiers
    /// not named: their interval plus RPO_HEADROOM_HOURS.
    pub rpo: PerTier,
    /// Minutes a restore may take, from the request to the machine enrolling again.
    pub rto: PerTier,
    pub retention: Retention,
}

impl Settings {
    /// For tests: the default schedule, targets and retention.
    #[cfg(test)]
    pub fn with(s3: s3::Settings, prefix: &str, recipients: Vec<age::x25519::Recipient>) -> Settings {
        Settings {
            s3,
            prefix: prefix.into(),
            recipients,
            interval: PerTier::parse("", DEFAULT_INTERVALS, 1..=720, "hours").unwrap(),
            rpo: PerTier::default(),
            rto: PerTier::default(),
            retention: Retention::default(),
        }
    }

    pub fn interval_ms(&self, tier: &str) -> i64 {
        self.interval.or(tier, DEFAULT_INTERVAL_HOURS) * HOUR_MS
    }

    pub fn rpo_ms(&self, tier: &str) -> i64 {
        self.rpo.get(tier).map_or(self.interval_ms(tier) + RPO_HEADROOM_HOURS * HOUR_MS, |h| h * HOUR_MS)
    }

    pub fn rto_ms(&self, tier: &str) -> i64 {
        self.rto.or(tier, DEFAULT_RTO_MINUTES) * 60_000
    }

    /// Every tier the settings name, with "" standing for the rest.
    fn named(&self) -> Vec<String> {
        let mut out = vec![String::new()];
        for t in self.interval.names().chain(self.rpo.names()).chain(self.rto.names()).chain(self.retention.names()) {
            if !out.iter().any(|o| o == t) {
                out.push(t.into());
            }
        }
        out
    }

    /// Each tier's targets, for `tiers` and then the rest.
    pub fn objectives(&self, tiers: &[String]) -> Value {
        let row = |t: &str| {
            json!({
                "tier": if t.is_empty() { Value::Null } else { json!(t) },
                "intervalHours": self.interval_ms(t) / HOUR_MS,
                "rpoHours": self.rpo_ms(t) / HOUR_MS,
                "rtoMinutes": self.rto_ms(t) / 60_000,
                "retentionDays": self.retention.days(t),
            })
        };
        let mut out: Vec<Value> = tiers.iter().map(|t| row(t)).collect();
        out.push(row(""));
        json!(out)
    }

    /// MACHINE_BACKUP_S3_BUCKET turns it on and needs MACHINE_BACKUP_S3_ENDPOINT and the
    /// keys (`s3::Settings::from_env`); MACHINE_BACKUP_S3_PREFIX (`superbot/`),
    /// MACHINE_BACKUP_AGE_RECIPIENTS (or `_FILE`), MACHINE_BACKUP_INTERVAL_HOURS
    /// (DEFAULT_INTERVALS), MACHINE_BACKUP_RPO_HOURS (interval + 2), MACHINE_RESTORE_RTO_MINUTES
    /// (60) and MACHINE_BACKUP_RETENTION (14 days) are optional. None: off. `tiers`: the
    /// control plane's, which every tier these name must be one of (empty: unchecked).
    pub fn from_env(store: &dyn SecretStore, var: &dyn Fn(&str) -> String, tiers: &[String]) -> Result<Option<Settings>, String> {
        if var("MACHINE_BACKUP_S3_BUCKET").trim().is_empty() {
            let stray = [
                "MACHINE_BACKUP_S3_ENDPOINT",
                "MACHINE_BACKUP_AGE_RECIPIENTS",
                "MACHINE_BACKUP_AGE_RECIPIENTS_FILE",
                "MACHINE_BACKUP_INTERVAL_HOURS",
                "MACHINE_BACKUP_RPO_HOURS",
                "MACHINE_RESTORE_RTO_MINUTES",
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
        let interval_raw = var("MACHINE_BACKUP_INTERVAL_HOURS");
        let mut interval = PerTier::parse("MACHINE_BACKUP_INTERVAL_HOURS", &interval_raw, 1..=720, "hours")?;
        let mut named = Vec::new();
        if interval_raw.trim().is_empty() {
            interval = PerTier::parse("MACHINE_BACKUP_INTERVAL_HOURS", DEFAULT_INTERVALS, 1..=720, "hours")?;
        } else {
            named.extend(interval.names().map(|t| ("MACHINE_BACKUP_INTERVAL_HOURS", t.to_string())));
        }
        let rpo = PerTier::parse("MACHINE_BACKUP_RPO_HOURS", &var("MACHINE_BACKUP_RPO_HOURS"), 2..=744, "hours")?;
        let rto = PerTier::parse("MACHINE_RESTORE_RTO_MINUTES", &var("MACHINE_RESTORE_RTO_MINUTES"), 5..=1440, "minutes")?;
        let retention = Retention::retention(&var("MACHINE_BACKUP_RETENTION"))?;
        named.extend(rpo.names().map(|t| ("MACHINE_BACKUP_RPO_HOURS", t.to_string())));
        named.extend(rto.names().map(|t| ("MACHINE_RESTORE_RTO_MINUTES", t.to_string())));
        named.extend(retention.names().map(|t| ("MACHINE_BACKUP_RETENTION", t.to_string())));
        if let Some((v, t)) = named.iter().find(|(_, t)| !tiers.is_empty() && !tiers.contains(t)) {
            return Err(format!("{v}: \"{t}\" isn't one of the machine tiers ({})", tiers.join(", ")));
        }
        let s = Settings { s3, prefix, recipients: recipients(&raw)?, interval, rpo, rto, retention };
        for t in s.named() {
            let (every, rpo) = (s.interval_ms(&t) / HOUR_MS, s.rpo_ms(&t) / HOUR_MS);
            if rpo < every + RPO_MIN_HEADROOM_HOURS {
                let which = if t.is_empty() { "the default tier".to_string() } else { format!("tier {t}") };
                return Err(format!(
                    "MACHINE_BACKUP_RPO_HOURS: {which}'s RPO ({rpo}h) must be at least its backup interval ({every}h) plus {RPO_MIN_HEADROOM_HOURS}h, so one failed backup can be retried in time"
                ));
            }
        }
        Ok(Some(s))
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
        let per_tier = |p: &PerTier| if p.tiers.is_empty() { "" } else { " (some tiers differ)" };
        format!(
            "to {}/{} every {}h{}, RPO {}h, RTO {}m, kept {} days{}, {}",
            self.s.s3.endpoint,
            self.s.s3.bucket,
            self.s.interval_ms("") / HOUR_MS,
            per_tier(&self.s.interval),
            self.s.rpo_ms("") / HOUR_MS,
            self.s.rto_ms("") / 60_000,
            self.s.retention.days(""),
            per_tier(&self.s.retention),
            if self.s.recipients.is_empty() { "not encrypted".to_string() } else { format!("encrypted to {} age recipients", self.s.recipients.len()) }
        )
    }

    /// For admins. No credentials. `tiers`: the control plane's, for the objectives.
    pub fn view(&self, tiers: &[String]) -> Value {
        json!({
            "endpoint": self.s.s3.endpoint,
            "bucket": self.s.s3.bucket,
            "region": self.s.s3.region,
            "prefix": self.s.prefix,
            "encrypted": !self.s.recipients.is_empty(),
            "recipients": self.s.recipients.iter().map(|r| r.to_string()).collect::<Vec<_>>(),
            "intervalHours": self.s.interval_ms("") / HOUR_MS,
            "retention": self.s.retention.view(),
            "objectives": self.s.objectives(tiers),
        })
    }

    fn key(&self, m: &Machine, id: &str) -> String {
        format!("{}{id}.incus{}", machine_prefix(&self.s.prefix, &m.id), if self.s.recipients.is_empty() { "" } else { ".age" })
    }
}

/// Where a machine's objects go under the store's prefix. Ends in `/`, so one machine's
/// never takes in another's whose id starts the same.
fn machine_prefix(prefix: &str, machine_id: &str) -> String {
    format!("{prefix}machines/{machine_id}/")
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

/// The imported copy's id while it is set up beside the machine: on the host the
/// restore is onto, where the provider has several (ADR 0076).
fn staging(p: &dyn MachineProvider, m: &Machine, r: &MachineRestore) -> String {
    let name = format!("{}-restore", m.label);
    match (p.hosts(), r.to_host.as_deref()) {
        (Some(h), Some(to)) => h.id_on(to, &name),
        _ => name,
    }
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
    if let Some(why) = super::hosts::unreachable(cp, m) {
        return Some(why);
    }
    None
}

/// Why `m` can't be backed up now, for alerts.
pub(super) fn unable_now(app: &App, cp: &ControlPlane, m: &Machine) -> Option<String> {
    unable(app, cp, m)
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
            crate::obs::log::log_warn!("Machine backups: deleting {name} at the provider: {e} (it expires by itself)");
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

/// Whether `m` is due a scheduled backup, on its tier's interval.
fn due(app: &App, off: &Offsite, m: &Machine) -> bool {
    let (at, every) = (now(), off.s.interval_ms(&m.tier));
    match app.db.machine_backups(&m.id).into_iter().find(|b| b.state != "deleted") {
        None => true,
        Some(b) if b.state == "running" => false,
        Some(b) if b.state == "failed" => at - b.created_at >= RETRY_MS.min(every),
        Some(b) => at - b.created_at >= every,
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
            Err(e) => crate::obs::log::log_warn!("Machine backups: deleting {} past its retention: {e}", b.id),
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
    // Nearest its RPO first, so a long round spends its time where it's most needed.
    let mut queue: Vec<(i64, String)> = app
        .db
        .machines(Some(State::Running))
        .into_iter()
        .filter(|m| unable(app, cp, m).is_none() && due(app, off, m))
        .map(|m| (super::recovery::covered_since(app, &m) + off.s.rpo_ms(&m.tier), m.id))
        .collect();
    queue.sort();
    let mut made = 0;
    for (_, id) in queue {
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
fn interrupted(app: &AppState) -> Vec<MachineRestore> {
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
                crate::obs::log::log_warn!("Machine backups: kept {}'s restore copy: its container is gone", m.id);
                continue;
            }
            if let Err(e) = p.delete(&staging(p, &m, &r)).await {
                crate::obs::log::log_warn!("Machine backups: deleting {}'s interrupted restore copy: {e}", m.id);
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
    // RPOs are checked here too, so a long backup round can't hide a breach.
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(cp.reconcile_every);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            follow_up(&app, &cp).await;
            super::recovery::watch(&app, &cp);
        }
    });
}

// Restores

fn fail_restore(app: &AppState, by: &Who, m: &Machine, r: &MachineRestore, from: &[&str], error: &str) {
    if app.db.machine_restore_move(&r.id, from, "failed", Some(error)) {
        app.db.revoke_machine_tokens(&m.id);
        let d = json!({ "restoreId": r.id, "backupId": r.backup_id, "error": error, "by": r.created_by });
        app.db.record(&event(by, "machine.restore_failed", m, d).outcome(Outcome::Failure));
        super::recovery::restore_failed(app, m, r, error);
    }
}

/// Restores whose machine enrolled again are done, timed against their RTO; ones that
/// didn't in time failed. Restores still underway past their RTO are reported.
pub async fn follow_up(app: &AppState, cp: &ControlPlane) {
    let Some(e) = cp.enrollment.as_deref() else { return };
    super::recovery::overdue(app);
    for r in app.db.machine_restores_in("enrolling") {
        // A restore boots its machine under the lock, so what's read before it is stale.
        let _g = cp.ops.lock().await;
        let Some(r) = app.db.machine_restore(&r.id).filter(|r| r.state == "enrolling") else { continue };
        let Some(m) = app.db.machine(&r.machine_id) else { continue };
        let since = r.replaced_at.unwrap_or(r.created_at);
        if super::recovery::enrolled(&m, &r) {
            let took = super::recovery::took(&m, &r);
            if app.db.machine_restore_done(&r.id, took) {
                let by = system(&m);
                let mut d = super::recovery::restored(app, &m, &r, took);
                d["restoreId"] = json!(r.id);
                d["backupId"] = json!(r.backup_id);
                d["by"] = json!(r.created_by);
                if r.to_host.is_some() {
                    (d["fromHost"], d["toHost"], d["reason"]) = (json!(r.from_host), json!(r.to_host), json!(r.reason));
                }
                app.db.record(&event(&by, "machine.restored", &m, d));
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
async fn import(off: &Offsite, p: &dyn MachineProvider, m: &Machine, r: &MachineRestore, b: &MachineBackup, ids: Vec<age::x25519::Identity>) -> Result<(), String> {
    let name = staging(p, m, r);
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
    // Onto another host, today's firewall must be there before the copy is put behind it.
    // An older one the machine kept (after a label prefix change) may not be.
    let moving = r.to_host.is_some() && r.from_host != r.to_host;
    let mut firewall_id = m.firewall_id.clone();
    if moving && let Some(fw) = &cp.firewall {
        match super::firewall::ensure(app, fw, p, by).await {
            Ok(id) => firewall_id = Some(id),
            Err(err) => {
                app.db.restore_enroll_by(&m.id, prior.0, prior.1);
                return Err(format!("setting up the firewall on host {}: {err}", r.to_host.as_deref().unwrap_or_default()));
            }
        }
    }
    let spec = RestoreSpec {
        plan: m.plan.clone(),
        tags: cp.spec(&m, None).tags,
        authorized_keys: cp.authorized_keys.clone(),
        firewall_id: firewall_id.clone(),
        files: e.restore_files(&m, &token),
        remove: vec![IDENTITY_PATH.into()],
    };
    let pm = match p.replace_with(&provider_id(&m), &staging(p, &m, r), &spec).await {
        Ok(pm) => pm,
        Err(err) => {
            app.db.restore_enroll_by(&m.id, prior.0, prior.1);
            return Err(err.to_string());
        }
    };
    // On another host it has another id from now on, whatever happens next.
    let pid = pm.id.clone();
    if m.provider_id.as_deref() != Some(pid.as_str()) {
        app.db.set_machine_provider_id(&m.id, &pid);
        m.provider_id = Some(pid.clone());
    }
    if m.firewall_id != firewall_id {
        app.db.set_machine_firewall_id(&m.id, firewall_id.as_deref());
        m.firewall_id = firewall_id;
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
pub(super) async fn restore(app: AppState, cp: Arc<ControlPlane>, r: MachineRestore, b: MachineBackup, ids: Vec<age::x25519::Identity>, by: Who) {
    let (Some(off), Some(p), Some(e)) = (cp.offsite.as_deref(), cp.provider.as_deref(), cp.enrollment.as_deref()) else { return };
    let Some(m) = app.db.machine(&r.machine_id) else { return };
    if let Err(why) = import(off, p, &m, &r, &b, ids).await {
        let _g = cp.ops.lock().await;
        return fail_restore(&app, &by, &m, &r, &["importing"], &why);
    }
    let _g = cp.ops.lock().await;
    if let Err(why) = replace(&app, &cp, e, &r, &by).await {
        let _ = p.delete(&staging(p, &m, &r)).await;
        let m = app.db.machine(&m.id).unwrap_or(m);
        fail_restore(&app, &by, &m, &r, &["importing", "replacing", "enrolling"], &why);
    }
}

// HTTP, under `/api/users/{key}/machine/backups|restore` and `/api/machines/backups`
// (admin only, rbac::classify).

pub(super) fn need(a: &Auth) -> Res<(&ControlPlane, &Offsite)> {
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
    let tiers: Vec<String> = a.machines.tiers.iter().map(|(t, _)| t.clone()).collect();
    Ok(Json(json!({ "settings": off.view(&tiers), "backups": all })))
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

/// `{backupId, identity?, host?}`: `identity` is the age secret key for an encrypted
/// backup, used for this restore only, never stored or logged. `host`: the Incus host
/// to restore onto, where there are several (ADR 0076); its own host by default.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RestoreBody {
    backup_id: String,
    #[serde(default)]
    identity: Option<String>,
    #[serde(default)]
    host: Option<String>,
}

/// `GET /api/users/{key}/machine/restore`: its latest restore.
pub async fn restore_status(AppS(app): AppS<AppState>, Extension(a): Extension<Arc<Auth>>, Path(key): Path<String>) -> Res {
    need(&a)?;
    let m = need_machine(&app, &key)?;
    Ok(Json(json!({ "machineId": m.id, "restore": app.db.machine_last_restore(&m.id) })))
}

/// Why `m` can't be restored now, if it can't.
pub(super) fn cannot_restore(app: &App, m: &Machine) -> Option<String> {
    if !matches!(m.state, State::Running | State::Suspended | State::Error) {
        return Some(format!("The machine is {}; it can be restored when it's running, suspended or in error.", m.state.as_str()));
    }
    if super::rebuild::underway(m) {
        return Some("A rebuild is underway.".into());
    }
    if let Some(r) = app.db.machine_restoring(&m.id) {
        return Some(format!("A restore is {} already.", r.state));
    }
    if app.db.machine_backups(&m.id).iter().any(|b| b.state == "running") {
        return Some("A backup of it is running; restore once it's done.".into());
    }
    None
}

/// Where a restore takes a machine, when the provider has several hosts (ADR 0076).
#[derive(Clone, Debug, Default)]
pub(super) struct Move {
    pub from: Option<String>,
    pub to: Option<String>,
    /// `host_lost`, or None when an admin asked for this machine.
    pub reason: Option<&'static str>,
}

/// Records a restore of `m` from `b`, for the caller to run (`restore`). The caller
/// holds the lock and checked `cannot_restore`. None if one began meanwhile.
pub(super) fn begin_restore(app: &App, cp: &ControlPlane, m: &Machine, b: &MachineBackup, by: &Who, mv: &Move) -> Option<MachineRestore> {
    let off = cp.offsite.as_deref()?;
    let id = format!("r{}", crate::random_hex(8));
    let n = NewMachineRestore {
        id: &id,
        machine: m,
        backup_id: &b.id,
        by: by.actor.id.as_deref(),
        rto_ms: Some(off.s.rto_ms(&m.tier)),
        from_host: mv.from.as_deref(),
        to_host: mv.to.as_deref(),
        reason: mv.reason,
    };
    let r = app.db.machine_restore_start(&n)?;
    let mut d = json!({ "restoreId": r.id, "backupId": b.id, "backupCreatedAt": b.created_at, "encrypted": b.encrypted, "was": m.state, "rtoMs": r.rto_ms });
    if mv.to.is_some() {
        (d["fromHost"], d["toHost"], d["reason"]) = (json!(mv.from), json!(mv.to), json!(mv.reason));
    }
    app.db.record(&event(by, "machine.restore_requested", m, d));
    Some(r)
}

/// `POST /api/users/{key}/machine/restore` `{backupId, identity?, host?}`: makes the
/// machine again from one of its own backups. Everything on it since is lost. 202; the
/// audit log and `GET` say how it went.
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
    if let Some(why) = cannot_restore(&app, &m) {
        return Err(conflict(why));
    }
    let mv = super::hosts::restore_move(&app, cp, &m, req.host.as_deref().map(str::trim).filter(|h| !h.is_empty()))?;
    let ids = match (b.encrypted, req.identity.as_deref().filter(|i| !i.trim().is_empty())) {
        (true, None) => return Err(bad("That backup is encrypted: send its age identity as \"identity\" (botctl machine restore ... --identity <file>).")),
        (true, Some(raw)) => identities(raw).map_err(bad)?,
        (false, _) => Vec::new(),
    };
    let r = begin_restore(&app, cp, &m, &b, &by, &mv).ok_or_else(|| conflict("A restore is underway already.".into()))?;
    tokio::spawn(restore(app.clone(), a.machines.clone(), r.clone(), b, ids, by));
    Ok((StatusCode::ACCEPTED, Json(json!({ "machineId": m.id, "restore": r }))))
}

// Deleting a destroyed machine's backups on request (ADR 0108)

/// Why a request to delete a machine's backups was refused, in `machine.backups_delete_refused`.
const NOT_DESTROYED: &str = "not_destroyed";
const BACKUP_RUNNING: &str = "backup_running";
const RESTORING: &str = "restoring";
const STORE_OFF: &str = "store_off";
/// Why an admin's request deleted backups, in `machine.backup_deleted` and `machine.backups_deleted`.
pub const REQUESTED: &str = "requested";

/// What deleting a machine's backups removed.
#[derive(Clone, Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Purged {
    /// The recorded backups marked deleted now.
    pub backups: Vec<String>,
    /// Objects found under the machine's prefix in the store once those were gone.
    pub strays: usize,
    /// In a bucket that keeps old versions: the versions and delete markers deleted for good.
    pub versions: usize,
    /// Restore copies the provider was asked to delete (none may have been left).
    pub restore_copies: usize,
}

/// What a backup's data object and manifest both start with: `<...>/<backup-id>.`.
fn backup_stem(object_key: &str) -> String {
    let manifest = manifest_key(object_key);
    manifest.strip_suffix("json").unwrap_or(&manifest).to_string()
}

/// Deletes every version and delete marker under `prefix` for good. How many.
async fn delete_versions(off: &Offsite, prefix: &str) -> Result<usize, String> {
    let all = off.s3.versions(prefix).await?;
    for (key, id) in &all {
        off.s3.delete_version(key, id).await?;
    }
    Ok(all.len())
}

/// Asks the provider to delete any copy a restore of `m` left beside it, on the host
/// each restore went to. Hosts declared lost are skipped, as nothing there is reached
/// again; so is a machine another provider made. How many it asked for.
async fn clear_restore_copies(app: &App, cp: &ControlPlane, m: &Machine) -> Result<usize, String> {
    let Some(p) = cp.provider.as_deref().filter(|_| cp.owns(m)) else { return Ok(0) };
    let mut names: Vec<String> = Vec::new();
    for r in app.db.machine_restores(&m.id) {
        let name = staging(p, m, &r);
        if let Some(h) = p.hosts()
            && h.status(&h.host_of(&name)) == Some(HostStatus::Lost)
        {
            continue;
        }
        if !names.contains(&name) {
            names.push(name);
        }
    }
    for name in &names {
        p.delete(name).await.map_err(|e| format!("deleting the restore copy {name} at the provider: {e}"))?;
    }
    Ok(names.len())
}

/// Deletes every backup of `m`, which must be destroyed: each recorded one's objects
/// in the store (marked `deleted` and audited `machine.backup_deleted` with `reason`),
/// whatever else is left under the machine's prefix there, and copies a restore left at
/// the provider. A backup still running, or a restore underway, refuses it. Stops at the
/// first failure; what went stays gone, so asking again finishes. `reason`: `requested`,
/// or `user_erased` from an erasure (ADR 0102).
pub async fn purge(app: &App, cp: &ControlPlane, off: &Offsite, by: &Who, m: &Machine, reason: &str) -> Res<Purged> {
    let refuse = |why: &str, msg: String| {
        app.db.record(&event(by, "machine.backups_delete_refused", m, json!({ "reason": why, "for": reason })).outcome(Outcome::Denied));
        Err(conflict(msg))
    };
    if m.state != State::Destroyed {
        let msg = format!(
            "The machine is {}; only a destroyed machine's backups are deleted on request, and a live machine's go when their retention ends.",
            m.state.as_str()
        );
        return refuse(NOT_DESTROYED, msg);
    }
    let kept: Vec<MachineBackup> = app.db.machine_backups(&m.id).into_iter().filter(|b| b.state != "deleted").collect();
    if kept.iter().any(|b| b.state == "running") {
        return refuse(BACKUP_RUNNING, "A backup of it is still running; ask again once it has ended.".into());
    }
    if app.db.machine_restoring(&m.id).is_some() {
        return refuse(RESTORING, "A restore of it is underway; ask again once it has ended.".into());
    }
    let mut done = Purged::default();
    let prefix = machine_prefix(&off.s.prefix, &m.id);
    let res: Result<(), String> = async {
        // In a bucket that keeps old versions, a plain delete only hides the bytes.
        let versioned = off.s3.versioned().await?;
        for b in &kept {
            if versioned {
                done.versions += delete_versions(off, &backup_stem(&b.object_key)).await?;
            } else {
                off.s3.delete(&b.object_key).await?;
                off.s3.delete(&manifest_key(&b.object_key)).await?;
            }
            if app.db.machine_backup_deleted(&b.id) {
                let d = json!({ "backupId": b.id, "object": b.object_key, "reason": reason, "createdAt": b.created_at, "expiresAt": b.expires_at });
                app.db.record(&event(by, "machine.backup_deleted", m, d));
                done.backups.push(b.id.clone());
            }
        }
        if versioned {
            let (now, all) = (off.s3.list(&prefix).await?.len(), delete_versions(off, &prefix).await?);
            done.strays += now;
            done.versions += all;
        } else {
            for key in off.s3.list(&prefix).await? {
                off.s3.delete(&key).await?;
                done.strays += 1;
            }
        }
        done.restore_copies = clear_restore_copies(app, cp, m).await?;
        Ok(())
    }
    .await;
    if let Err(e) = res {
        let left = app.db.machine_backups(&m.id).iter().filter(|b| b.state != "deleted").count();
        let d = json!({ "reason": reason, "error": e, "backups": done.backups, "left": left });
        app.db.record(&event(by, "machine.backups_delete_failed", m, d).outcome(Outcome::Failure));
        let msg = format!("Deleting its backups stopped: {e}. {} went and {left} are left; ask again to finish.", done.backups.len());
        return Err(ApiError(StatusCode::BAD_GATEWAY, msg));
    }
    let d = json!({ "reason": reason, "backups": done.backups, "strays": done.strays, "versions": done.versions, "restoreCopies": done.restore_copies });
    app.db.record(&event(by, "machine.backups_deleted", m, d));
    Ok(done)
}

/// `DELETE /api/machines/{id}/backups`: deletes every backup of a destroyed machine now,
/// not when their retention ends (ADR 0108). 409 while the machine exists.
pub async fn delete_all(AppS(app): AppS<AppState>, Extension(a): Extension<Arc<Auth>>, Extension(by): Extension<Who>, Path(id): Path<String>) -> Res {
    let m = app.db.machine(id.trim()).ok_or_else(|| not_found("Machine"))?;
    let (cp, off) = need(&a).inspect_err(|_| {
        let why = if a.machines.provider.is_none() { "not_configured" } else { STORE_OFF };
        app.db.record(&event(&by, "machine.backups_delete_refused", &m, json!({ "reason": why, "for": REQUESTED })).outcome(Outcome::Denied));
    })?;
    let done = purge(&app, cp, off, &by, &m, REQUESTED).await?;
    let mut v = json!(done);
    (v["machineId"], v["userId"]) = (json!(m.id), json!(m.user_id));
    Ok(Json(v))
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
        assert_eq!(Retention::retention("").unwrap(), Retention { default: None, tiers: vec![] });
        assert_eq!(Retention::retention("").unwrap().days("pro"), DEFAULT_RETENTION_DAYS);
        let r = Retention::retention("7, pro=30 ,max=90").unwrap();
        assert_eq!((r.days("starter"), r.days("pro"), r.days("max")), (7, 30, 90));
        assert_eq!(Retention::retention("pro=30").unwrap().days("starter"), DEFAULT_RETENTION_DAYS);
        for bad in ["0", "7,8", "pro=0", "pro=30,pro=40", "Pro=3", "x", "pro=", "4000"] {
            assert!(Retention::retention(bad).is_err(), "{bad}");
        }
        let e = PerTier::parse("MACHINE_RESTORE_RTO_MINUTES", "2", 5..=1440, "minutes").unwrap_err();
        assert_eq!(e, "MACHINE_RESTORE_RTO_MINUTES: \"2\" isn't 5 to 1440 minutes");
    }

    #[test]
    fn keys_and_names() {
        assert_eq!(manifest_key("p/machines/m1/b1.incus.age"), "p/machines/m1/b1.json");
        assert_eq!(manifest_key("p/machines/m1/b1.incus"), "p/machines/m1/b1.json");
        assert_eq!(machine_prefix("p/", "m1"), "p/machines/m1/");
        assert_eq!(machine_prefix("", "m1"), "machines/m1/");
        assert!(!format!("{}b1.incus", machine_prefix("p/", "m10")).starts_with(&machine_prefix("p/", "m1")), "m1's sweep leaves m10's alone");
        assert_eq!(manifest_key(&format!("{}b1.incus.age", machine_prefix("p/", "m1"))), "p/machines/m1/b1.json", "the manifest is under it too");
        for k in ["p/machines/m1/b1.incus.age", "p/machines/m1/b1.incus"] {
            let stem = backup_stem(k);
            assert_eq!(stem, "p/machines/m1/b1.");
            assert!(k.starts_with(&stem) && manifest_key(k).starts_with(&stem) && !"p/machines/m1/b10.incus".starts_with(&stem));
        }
    }

    #[test]
    fn settings_are_off_unless_a_bucket_is_set() {
        let keys = EnvStore::fixed(&[("MACHINE_BACKUP_S3_ACCESS_KEY_ID", "AKID"), ("MACHINE_BACKUP_S3_SECRET_ACCESS_KEY", "s3cret-0123")]);
        let with = |vars: &[(&str, &str)]| {
            let vars: Vec<(String, String)> = vars.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
            Settings::from_env(&keys, &move |k| vars.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone()).unwrap_or_default(), &[])
        };
        assert!(with(&[]).unwrap().is_none());
        let stray = with(&[("MACHINE_BACKUP_RETENTION", "7")]).err().unwrap();
        assert!(stray.contains("MACHINE_BACKUP_S3_BUCKET"), "{stray}");
        let base = [("MACHINE_BACKUP_S3_BUCKET", "backups"), ("MACHINE_BACKUP_S3_ENDPOINT", "https://s3.example.com")];
        let s = with(&base).unwrap().unwrap();
        assert_eq!((s.prefix.as_str(), s.interval_ms("starter"), s.recipients.len()), ("superbot/", 24 * HOUR_MS, 0));
        let id = age::x25519::Identity::generate();
        let public = id.to_public().to_string();
        let s = with(&[base[0], base[1], ("MACHINE_BACKUP_S3_PREFIX", "/acme/m"), ("MACHINE_BACKUP_AGE_RECIPIENTS", &format!("# ops\n{public}")), ("MACHINE_BACKUP_INTERVAL_HOURS", "6")])
            .unwrap()
            .unwrap();
        assert_eq!((s.prefix.as_str(), s.interval_ms("pro"), s.recipients.len()), ("acme/m/", 6 * HOUR_MS, 1));
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
        }, &[]);
        assert!(no_keys.err().unwrap().contains("MACHINE_BACKUP_S3_"));
    }

    fn settings(vars: &[(&str, &str)], tiers: &[&str]) -> Result<Settings, String> {
        let keys = EnvStore::fixed(&[("MACHINE_BACKUP_S3_ACCESS_KEY_ID", "AKID"), ("MACHINE_BACKUP_S3_SECRET_ACCESS_KEY", "s3cret-0123")]);
        let mut all: Vec<(String, String)> = vec![("MACHINE_BACKUP_S3_BUCKET".into(), "backups".into()), ("MACHINE_BACKUP_S3_ENDPOINT".into(), "https://s3.example.com".into())];
        all.extend(vars.iter().map(|(k, v)| (k.to_string(), v.to_string())));
        let tiers: Vec<String> = tiers.iter().map(|t| t.to_string()).collect();
        Settings::from_env(&keys, &move |k| all.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone()).unwrap_or_default(), &tiers).map(Option::unwrap)
    }

    #[test]
    fn each_tier_has_a_schedule_rpo_and_rto() {
        let tiers = ["starter", "pro", "max"];
        // The defaults: the default tiers' targets, and the bare value for any other.
        let s = settings(&[], &tiers).unwrap();
        let row = |s: &Settings, t: &str| (s.interval_ms(t) / HOUR_MS, s.rpo_ms(t) / HOUR_MS, s.rto_ms(t) / 60_000);
        assert_eq!([row(&s, "starter"), row(&s, "pro"), row(&s, "max"), row(&s, "team")], [(24, 26, 60), (12, 14, 60), (6, 8, 60), (24, 26, 60)]);
        let o = s.objectives(&["starter".into(), "max".into()]);
        assert_eq!((o[1]["tier"].as_str(), o[1]["rpoHours"].as_i64(), o[2]["tier"].is_null()), (Some("max"), Some(8), true), "{o}");

        // Set, the schedule replaces the defaults entirely; unnamed RPOs follow it.
        let s = settings(&[("MACHINE_BACKUP_INTERVAL_HOURS", "12,max=1"), ("MACHINE_BACKUP_RPO_HOURS", "pro=24"), ("MACHINE_RESTORE_RTO_MINUTES", "90,max=30")], &tiers).unwrap();
        assert_eq!([row(&s, "starter"), row(&s, "pro"), row(&s, "max")], [(12, 14, 90), (12, 24, 90), (1, 3, 30)]);

        // An RPO too tight for its schedule, or a tier botd doesn't have, is refused.
        let e = settings(&[("MACHINE_BACKUP_RPO_HOURS", "max=6")], &tiers).err().unwrap();
        assert!(e.contains("tier max's RPO (6h) must be at least its backup interval (6h) plus 1h"), "{e}");
        let e = settings(&[("MACHINE_BACKUP_RPO_HOURS", "24")], &tiers).err().unwrap();
        assert!(e.contains("the default tier's RPO (24h)"), "{e}");
        assert!(settings(&[("MACHINE_BACKUP_INTERVAL_HOURS", "24"), ("MACHINE_BACKUP_RPO_HOURS", "25")], &tiers).is_ok(), "an hour's headroom is enough");
        let e = settings(&[("MACHINE_BACKUP_INTERVAL_HOURS", "24,prro=6")], &tiers).err().unwrap();
        assert!(e.contains("\"prro\" isn't one of the machine tiers (starter, pro, max)"), "{e}");
        assert!(settings(&[("MACHINE_RESTORE_RTO_MINUTES", "team=30")], &tiers).is_err());
        assert!(settings(&[], &["team"]).is_ok(), "the built-in schedule's tiers needn't exist");
        for bad in [("MACHINE_BACKUP_RPO_HOURS", "1"), ("MACHINE_RESTORE_RTO_MINUTES", "0"), ("MACHINE_BACKUP_INTERVAL_HOURS", "721")] {
            assert!(settings(&[bad], &tiers).is_err(), "{bad:?}");
        }
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
        let e = s.next().await.unwrap().err().unwrap();
        assert!(e.to_string().contains("decrypting"), "{e}");
    }
}
