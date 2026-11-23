//! Checking the audit log's write-once archive (ADR 0163): `GET /api/audit/verify?archive=on`
//! and `botctl audit verify --archive`.
//!
//! botd lists every version of every object under the archive's prefix and reads the one
//! it wrote first, which Object Lock keeps however the key was written to since; a later
//! version that differs is a failure. Each object must be what its key and metadata say
//! and be locked; the chain must run on from event to event and object to object with no
//! gap; each signed checkpoint in it must hold under the trusted keys; and the archive
//! must reach as far as botd says it delivered. Then every event in it must have the same
//! hash in this server's log, which catches a log rebuilt from a changed event on: its
//! own chain holds, but it no longer matches what was archived.
//!
//! botd's daily self-check does the same for what is new since its last pass (ADR 0183):
//! objects past the head that pass reached, picking the chain up from it, and any object
//! the store says was written to since, wherever its events fall.

use crate::audit_archive::{Archive, Lock};
use crate::audit_chain::{Link, Range};
use crate::audit_export::Exporter;
use crate::db::now;
use crate::machines::s3::{ObjectVersion, S3};
use crate::runner::App;
use rusqlite::types::Value as Sql;
use rusqlite::OptionalExtension;
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::BTreeMap;

/// Objects read at once.
const PARALLEL: usize = 4;
/// How far the store's clock may run behind botd's: an object written this long before
/// the last pass began is still read as new.
const CLOCK_SKEW_MS: i64 = 60 * 60 * 1000;
/// Far above what 10,000 events take; an object larger than this isn't botd's.
const MAX_OBJECT_BYTES: usize = 256 * 1024 * 1024;
/// Problems the report lists; it counts them all.
const MAX_LISTED: usize = 20;

/// Something in the archive that doesn't hold, and why: `stray` (a key under the prefix
/// botd didn't name), `unreadable`, `overwritten` (a later version of the object differs
/// from the one botd wrote), `metadata` (its key or metadata doesn't match its events),
/// `unlocked`, `order` (its events are out of order), `link` (an event doesn't link to the
/// one before: an object is missing, or isn't botd's), `checkpoint`, `behind` (the archive
/// ends before the last event botd delivered to it), `start` (it begins after the first
/// event botd sent it), or, against this server's log,
/// `mismatch` (the event here has another hash), `contents` (it has the same hash, but the
/// archive's copy says something else) and `missing` (it's gone, and retention didn't delete it).
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Problem {
    pub key: Option<String>,
    pub id: Option<i64>,
    pub reason: &'static str,
    pub error: String,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Checked {
    pub ok: bool,
    pub archive: String,
    pub objects: u64,
    /// Objects outside the range checked.
    pub skipped: u64,
    /// Events read, repeats included.
    pub events: u64,
    /// Events an earlier object holds too, as a restarted export can leave.
    pub repeated: u64,
    /// Versions of an object besides the first, the same as it (a retried batch).
    pub retried: u64,
    /// Objects whose newest version is a delete marker: hidden, yet still there.
    pub hidden: u64,
    pub locked: u64,
    /// Objects whose lock has ended, so the store no longer protects them.
    pub lock_expired: u64,
    /// Signed checkpoints in the archive that hold.
    pub checkpoints: u64,
    /// The first event, and the newest with its hash.
    pub first: Option<i64>,
    pub head: Option<Link>,
    /// The last event botd had delivered to the archive when the check began.
    pub delivered: i64,
    /// The first event of the first batch botd cut for this archive, where it must begin.
    /// None for an archive started before botd recorded it.
    pub start: Option<i64>,
    /// The head of the last passing check, which this one picked up from: only what is
    /// new since was read. None for a check of the whole archive.
    pub after: Option<i64>,
    /// Events whose hash this server's log has (`matched`), had before retention deleted
    /// them (`gone`), differs from (`mismatched`) or lacks (`missing`).
    pub matched: u64,
    /// Events with this server's hash but other contents: a changed copy in the archive.
    pub altered: u64,
    pub gone: u64,
    pub mismatched: u64,
    pub missing: u64,
    pub problems: u64,
    /// The first problems found, in id order.
    pub first_problems: Vec<Problem>,
    /// Set when the archive couldn't be listed or the log read; the check then fails.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Events of this server's log that differ from the archive or are missing.
    #[serde(skip)]
    pub local_breaks: Vec<i64>,
}

/// What botd wrote with an object, from its headers.
#[derive(Clone, Debug, Default)]
pub struct Meta {
    pub schema: Option<String>,
    pub first_id: Option<i64>,
    pub last_id: Option<i64>,
    pub events: Option<u64>,
    pub chain_prev: Option<String>,
    pub chain_head: Option<String>,
    pub lock_mode: Option<String>,
    /// ms.
    pub retain_until: Option<i64>,
}

impl Meta {
    pub fn from_headers(h: &reqwest::header::HeaderMap) -> Meta {
        let s = |k: &str| h.get(k).and_then(|v| v.to_str().ok()).map(|v| v.trim().to_string()).filter(|v| !v.is_empty());
        let n = |k: &str| s(k).and_then(|v| v.parse::<i64>().ok());
        Meta {
            schema: s("x-amz-meta-superbot-schema"),
            first_id: n("x-amz-meta-superbot-first-id"),
            last_id: n("x-amz-meta-superbot-last-id"),
            events: s("x-amz-meta-superbot-events").and_then(|v| v.parse().ok()),
            chain_prev: s("x-amz-meta-superbot-chain-prev"),
            chain_head: s("x-amz-meta-superbot-chain-head"),
            lock_mode: s("x-amz-object-lock-mode"),
            retain_until: s("x-amz-object-lock-retain-until-date").and_then(|t| chrono::DateTime::parse_from_rfc3339(&t).ok()).map(|t| t.timestamp_millis()),
        }
    }
}

/// The ids a key names: `<prefix>/<yyyy>/<mm>/<dd>/<first id>-<last id>.jsonl`.
pub fn ids(prefix: &str, key: &str) -> Option<(i64, i64)> {
    let rest = key.strip_prefix(prefix)?.strip_prefix('/')?;
    let parts: Vec<&str> = rest.split('/').collect();
    let digits = |s: &str, n: usize| s.len() == n && s.bytes().all(|b| b.is_ascii_digit());
    let [y, m, d, name] = parts.as_slice() else { return None };
    if !(digits(y, 4) && digits(m, 2) && digits(d, 2)) {
        return None;
    }
    let (first, last) = name.strip_suffix(".jsonl")?.split_once('-')?;
    if !(digits(first, 20) && digits(last, 20)) {
        return None;
    }
    let (first, last) = (first.parse().ok()?, last.parse().ok()?);
    (first <= last).then_some((first, last))
}

/// One event as the archive holds it.
struct Line {
    id: i64,
    prev: String,
    hash: String,
    action: String,
    details: Value,
    /// The whole line, to compare with this server's row.
    raw: Value,
}

fn lines(body: &[u8]) -> Result<Vec<Line>, String> {
    let text = std::str::from_utf8(body).map_err(|_| "it isn't UTF-8 text".to_string())?;
    let mut out = Vec::new();
    for (n, l) in text.split_terminator('\n').enumerate() {
        let bad = |why: &str| format!("line {} {why}", n + 1);
        let v: Value = serde_json::from_str(l).map_err(|_| bad("isn't JSON"))?;
        if v["schema"].as_str() != Some(crate::audit_export::SCHEMA) {
            return Err(bad(&format!("isn't a {} event", crate::audit_export::SCHEMA)));
        }
        let (Some(id), Some(prev), Some(hash)) = (v["id"].as_i64(), v["chainPrev"].as_str(), v["chainHash"].as_str()) else {
            return Err(bad("has no id, chainPrev or chainHash"));
        };
        out.push(Line { id, prev: prev.into(), hash: hash.into(), action: v["action"].as_str().unwrap_or_default().into(), details: v["details"].clone(), raw: v });
    }
    if out.is_empty() {
        return Err("it holds no events".into());
    }
    Ok(out)
}

/// What this server's log holds for the events from `lo` to `hi`, by id: each hash (one
/// that isn't text counts as none), and each row as the export writes it.
#[derive(Clone, Debug, Default)]
pub struct Local {
    pub hashes: BTreeMap<i64, Option<String>>,
    pub rows: BTreeMap<i64, Row>,
}

/// A row of this server's log, in the export's shape. `erased`: an erasure has cleared
/// its salt, so only the fields it can't rewrite are still the archive's.
#[derive(Clone, Debug)]
pub struct Row {
    pub event: Value,
    pub erased: bool,
}

/// [`crate::audit_chain::FIXED`] and [`crate::audit_chain::ERASABLE`], as the export names them.
const FIXED_FIELDS: [&str; 11] = ["id", "at", "actorKind", "action", "targetType", "botId", "outcome", "actorRole", "authMethod", "idp", "idpProvider"];
const ERASABLE_FIELDS: [&str; 10] = ["actorId", "actorName", "actorSubject", "targetId", "ip", "userAgent", "details", "actorEmail", "sessionId", "onBehalfOf"];

/// The first field the hash covers in which the archive's event differs from this server's
/// row with the same hash. The archive's hashes aren't bound to its contents on their own:
/// the salted digest that binds them stays here.
fn differing(archived: &Value, row: &Row) -> Option<&'static str> {
    let fields = FIXED_FIELDS.iter().chain(if row.erased { [].iter() } else { ERASABLE_FIELDS.iter() }).chain(["chainPrev"].iter());
    fields.copied().find(|f| {
        let (a, h) = (archived.get(*f).unwrap_or(&Value::Null), row.event.get(*f).unwrap_or(&Value::Null));
        if *f == "details" { !redacted_from(a, h) } else { a != h }
    })
}

/// Whether `archived` is `here` as the export wrote it: equal, except that each
/// `[redacted]` in an archived string stands for whatever a secret known then covered.
fn redacted_from(archived: &Value, here: &Value) -> bool {
    match (archived, here) {
        (Value::String(a), Value::String(h)) => redacted_text(a, h),
        (Value::Array(a), Value::Array(h)) => a.len() == h.len() && a.iter().zip(h).all(|(a, h)| redacted_from(a, h)),
        (Value::Object(a), Value::Object(h)) => a.len() == h.len() && a.iter().all(|(k, v)| h.get(k).is_some_and(|h| redacted_from(v, h))),
        _ => archived == here,
    }
}

fn redacted_text(archived: &str, here: &str) -> bool {
    let parts: Vec<&str> = archived.split(crate::secrets::redact::MARK).collect();
    let [first, middle @ .., last] = parts.as_slice() else { return archived == here };
    if here.len() < first.len() + last.len() || !here.starts_with(first) || !here.ends_with(last) {
        return false;
    }
    let mut rest = &here[first.len()..here.len() - last.len()];
    for p in middle {
        match rest.find(p) {
            Some(i) => rest = &rest[i + p.len()..],
            None => return false,
        }
    }
    true
}

/// Walks the archive's objects in id order, as [`crate::audit_chain::Verifier`] walks rows.
pub struct Walker<'a> {
    rep: Checked,
    lock: Lock,
    keys: &'a [Vec<u8>],
    /// The last event walked, which the next must link to. None at the start, and after an
    /// object that couldn't be read (already a failure).
    last: Option<Link>,
}

impl<'a> Walker<'a> {
    pub fn new(a: &Archive, delivered: i64, keys: &'a [Vec<u8>]) -> Walker<'a> {
        Walker { rep: Checked { archive: a.shown(), delivered, ..Default::default() }, lock: a.lock, keys, last: None }
    }

    pub fn starting_at(mut self, start: Option<i64>) -> Walker<'a> {
        self.rep.start = start;
        self
    }

    /// Carries on from the last passing check: the next event must link to its head, and
    /// events up to it are repeats, still compared with the log.
    pub fn resuming(mut self, since: Option<&Since>) -> Walker<'a> {
        if let Some(s) = since {
            self.rep.after = Some(s.head.id);
            self.rep.head = Some(s.head.clone());
            self.last = Some(s.head.clone());
        }
        self
    }

    fn problem(&mut self, key: Option<&str>, id: Option<i64>, reason: &'static str, error: String) {
        self.rep.problems += 1;
        if self.rep.first_problems.len() < MAX_LISTED {
            self.rep.first_problems.push(Problem { key: key.map(String::from), id, reason, error });
        }
    }

    pub fn stray(&mut self, key: &str) {
        self.problem(Some(key), None, "stray", "botd didn't write this key: it isn't <prefix>/<yyyy>/<mm>/<dd>/<first id>-<last id>.jsonl".into());
    }

    pub fn skipped(&mut self) {
        self.rep.skipped += 1;
    }

    /// An object that couldn't be read: the next one starts the chain again.
    pub fn unreadable(&mut self, key: &str, error: String) {
        self.rep.objects += 1;
        self.problem(Some(key), None, "unreadable", error);
        self.last = None;
    }

    pub fn overwritten(&mut self, key: &str, error: String) {
        self.problem(Some(key), None, "overwritten", error);
    }

    pub fn versions(&mut self, retried: u64, hidden: bool) {
        self.rep.retried += retried;
        self.rep.hidden += hidden as u64;
    }

    /// The ids of the events in an object's body, to look up in this server's log.
    pub fn span(body: &[u8]) -> Option<(i64, i64)> {
        let l = lines(body).ok()?;
        Some((l.iter().map(|l| l.id).min()?, l.iter().map(|l| l.id).max()?))
    }

    /// One object: the ids its key names, what was stored with it, its body, and this
    /// server's hashes for its events (and the anchor, for those retention deleted).
    pub fn object(&mut self, key: &str, named: (i64, i64), meta: &Meta, body: &[u8], local: &Local, anchor: Option<&Link>) {
        let events = match lines(body) {
            Ok(l) => l,
            Err(e) => return self.unreadable(key, format!("{key}: {e}")),
        };
        self.rep.objects += 1;
        let k = Some(key);
        let (first, last) = (&events[0], &events[events.len() - 1]);
        let mut wrong = Vec::new();
        if (first.id, last.id) != named {
            wrong.push(format!("its key names events {} to {}, it holds {} to {}", named.0, named.1, first.id, last.id));
        }
        let expect = [
            ("schema", meta.schema.clone(), Some(crate::audit_export::SCHEMA.to_string())),
            ("first-id", meta.first_id.map(|v| v.to_string()), Some(first.id.to_string())),
            ("last-id", meta.last_id.map(|v| v.to_string()), Some(last.id.to_string())),
            ("events", meta.events.map(|v| v.to_string()), Some(events.len().to_string())),
            ("chain-prev", meta.chain_prev.clone(), Some(first.prev.clone())),
            ("chain-head", meta.chain_head.clone(), Some(last.hash.clone())),
        ];
        for (name, got, want) in expect {
            if got != want {
                wrong.push(format!("x-amz-meta-superbot-{name} is {}, not {}", got.as_deref().unwrap_or("missing"), want.unwrap_or_default()));
            }
        }
        if !wrong.is_empty() {
            self.problem(k, Some(first.id), "metadata", format!("{key}: {}", wrong.join("; ")));
        }
        if self.lock != Lock::Off {
            match (meta.lock_mode.as_deref(), meta.retain_until) {
                (Some(_), Some(until)) if until > now() => self.rep.locked += 1,
                (Some(_), Some(_)) => self.rep.lock_expired += 1,
                _ => self.problem(k, Some(first.id), "unlocked", format!("{key} has no lock (botd reads it with s3:GetObjectRetention)")),
            }
        }
        if events.windows(2).any(|w| w[1].id <= w[0].id) {
            self.problem(k, Some(first.id), "order", format!("{key}'s events aren't in id order"));
        }

        for e in &events {
            self.rep.events += 1;
            self.compare(key, e, local, anchor);
            if self.rep.head.as_ref().is_some_and(|h| e.id <= h.id) {
                self.rep.repeated += 1;
                // Its details aren't covered by the hash compared, so its signature still must hold.
                if e.action == crate::audit_checkpoint::CHECKPOINT
                    && let Err(f) = crate::audit_checkpoint::check_signed(e.id, Some(&e.prev), Some(&e.details), None, self.keys)
                {
                    self.problem(k, Some(e.id), "checkpoint", format!("checkpoint {} ({}), repeated in {key}: {}", e.id, f.reason, f.error));
                }
                continue;
            }
            let before = self.last.take();
            let linked = match &before {
                Some(l) if l.hash != e.prev => {
                    self.problem(k, Some(e.id), "link", format!("event {} doesn't link to event {} before it: events are missing from the archive, or these aren't botd's", e.id, l.id));
                    false
                }
                Some(_) => true,
                None => false,
            };
            if e.action == crate::audit_checkpoint::CHECKPOINT {
                let seq = before.as_ref().filter(|_| linked).map(|l| l.id);
                match crate::audit_checkpoint::check_signed(e.id, Some(&e.prev), Some(&e.details), seq, self.keys) {
                    Ok(()) => self.rep.checkpoints += 1,
                    Err(f) => self.problem(k, Some(e.id), "checkpoint", format!("checkpoint {} ({}): {}", e.id, f.reason, f.error)),
                }
            }
            self.rep.first.get_or_insert(e.id);
            let link = Link { id: e.id, hash: e.hash.clone() };
            self.rep.head = Some(link.clone());
            self.last = Some(link);
        }
    }

    fn compare(&mut self, key: &str, e: &Line, local: &Local, anchor: Option<&Link>) {
        let differs = match (local.hashes.get(&e.id), anchor) {
            (Some(Some(h)), _) if *h == e.hash => {
                match local.rows.get(&e.id).and_then(|r| differing(&e.raw, r)) {
                    None => self.rep.matched += 1,
                    Some(field) => {
                        self.rep.altered += 1;
                        self.problem(Some(key), Some(e.id), "contents", format!("event {}'s {field} in {key} differs from this server's, under the same hash: the archive's copy was changed", e.id));
                    }
                }
                return;
            }
            (Some(_), _) => Some(("mismatch", format!("event {} here doesn't have the hash the archive holds", e.id))),
            // Retention deleted it, keeping the last one's hash as the anchor.
            (None, Some(a)) if a.id == e.id && a.hash != e.hash => Some(("mismatch", format!("the anchor, event {}, doesn't have the hash the archive holds", e.id))),
            (None, Some(a)) if e.id <= a.id => {
                self.rep.gone += 1;
                return;
            }
            (None, _) => Some(("missing", format!("event {} isn't in this server's log, and retention didn't delete it", e.id))),
        };
        if let Some((reason, error)) = differs {
            if reason == "mismatch" {
                self.rep.mismatched += 1;
            } else {
                self.rep.missing += 1;
            }
            self.rep.local_breaks.push(e.id);
            self.problem(Some(key), Some(e.id), reason, error);
        }
    }

    /// Resuming: the head the last pass reached must still have its hash in this server's
    /// log. A log rebuilt from any event up to it changes that hash, so this catches one
    /// rebuilt where the objects already checked, which aren't read again.
    pub fn head_held(&mut self, here: Option<&Option<String>>, anchor: Option<&Link>) {
        let Some(id) = self.rep.after else { return };
        let Some(head) = self.rep.head.clone().filter(|h| h.id == id) else { return };
        let error = match (here, anchor) {
            (Some(Some(h)), _) if *h == head.hash => return,
            (Some(_), _) => ("mismatch", format!("event {id}, where the last check of the archive ended, no longer has the hash it had then here: the log was rebuilt")),
            (None, Some(a)) if a.id == id && a.hash != head.hash => ("mismatch", format!("the anchor, event {id}, where the last check of the archive ended, no longer has the hash it had then")),
            (None, Some(a)) if id <= a.id => return,
            (None, _) => ("missing", format!("event {id}, where the last check of the archive ended, isn't in this server's log, and retention didn't delete it")),
        };
        match error.0 {
            "mismatch" => self.rep.mismatched += 1,
            _ => self.rep.missing += 1,
        }
        self.rep.local_breaks.push(id);
        self.problem(None, Some(id), error.0, error.1);
    }

    /// The archive couldn't be listed, or the log read: the check fails.
    pub fn fail(&mut self, error: String) {
        self.rep.error = Some(crate::secrets::redact::text(&error).into_owned());
    }

    /// `batches`: botd has cut a batch for this archive, so it has written to it.
    pub fn finish(mut self, range: Range, batches: bool) -> Checked {
        let (d, start) = (self.rep.delivered, self.rep.start);
        let head = self.rep.head.as_ref().map_or(0, |h| h.id);
        // The part of the range botd has delivered to the archive, which must all be there.
        let lo = range.from.into_iter().chain(start).max();
        let hi = range.to.map_or(d, |t| t.min(d));
        // Without a recorded start, a range ending before `delivered` that read nothing may
        // lie before the archive began.
        let can_tell = start.is_some() || head > 0 || range.to.is_none_or(|t| d <= t);
        if self.rep.error.is_none() && hi > head && lo.is_none_or(|l| hi >= l) && (head > 0 || batches) && can_tell {
            let from = (head + 1).max(lo.unwrap_or(1));
            let error = match head {
                0 => format!("botd delivered events up to {d} to the archive, but it holds none from {from} to {hi}: objects are missing from it"),
                _ => format!("botd delivered events up to {d} to the archive, but it ends at {head}: objects are missing from it"),
            };
            self.problem(None, Some(from), "behind", error);
        }
        // Resuming, the start was checked before, and a gap after the head is a `link`.
        if let (Some(l), Some(first)) = (lo.filter(|_| start.is_some() && self.rep.after.is_none()), self.rep.first)
            && self.rep.error.is_none()
            && first > l
            && l <= hi
        {
            let error = match start == Some(l) {
                true => format!("botd's first batch for this archive began at event {l}, but the archive begins at {first}: objects are missing from its start"),
                false => format!("the archive has no events from {l} to {}, which botd delivered to it: objects are missing from it", first - 1),
            };
            self.problem(None, Some(l), "start", error);
        }
        let mut rep = self.rep;
        rep.ok = rep.problems == 0 && rep.error.is_none();
        rep
    }
}

/// An object to read: its key, the ids it names, and its versions, newest first.
struct Object {
    key: String,
    named: (i64, i64),
    versions: Vec<String>,
    hidden: bool,
    /// When the store last took a version or delete marker of it, in ms; `i64::MAX` when
    /// the listing doesn't say, so it always counts as new.
    modified: i64,
}

/// One object read: its first version's headers and body, and whether a later version differs.
struct Read {
    object: Object,
    first: Result<(Meta, Vec<u8>), String>,
    overwritten: Option<String>,
}

/// `version` as listed, `null` included: an object written before versioning was on has
/// that id, and reading without one would give the newest version instead.
async fn body(s3: &S3, key: &str, version: &str) -> Result<(Meta, Vec<u8>), String> {
    let res = s3.get_version(key, Some(version)).await?;
    if res.content_length().is_some_and(|n| n as usize > MAX_OBJECT_BYTES) {
        return Err(format!("{key} is larger than any batch botd writes"));
    }
    let meta = Meta::from_headers(res.headers());
    let bytes = res.bytes().await.map_err(|e| format!("reading {key} was cut off: {}", e.without_url()))?;
    if bytes.len() > MAX_OBJECT_BYTES {
        return Err(format!("{key} is larger than any batch botd writes"));
    }
    Ok((meta, bytes.to_vec()))
}

async fn read(s3: &S3, object: Object) -> Read {
    let Some((oldest, newer)) = object.versions.split_last() else {
        return Read { first: Err(format!("{} has no version to read", object.key)), overwritten: None, object };
    };
    let first = body(s3, &object.key, oldest).await;
    let mut overwritten = None;
    if let Ok((_, b)) = &first {
        for v in newer {
            match body(s3, &object.key, v).await {
                Ok((_, other)) if other == *b => {}
                Ok(_) => {
                    overwritten = Some(format!("{}: version {v} differs from the one botd wrote, which is what was checked", object.key));
                    break;
                }
                Err(e) => {
                    overwritten = Some(format!("{e} (a later version of it)"));
                    break;
                }
            }
        }
    }
    Read { object, first, overwritten }
}

/// Groups a listing into botd's objects in id order; other keys are strays.
fn objects(prefix: &str, listed: Vec<ObjectVersion>, w: &mut Walker) -> Vec<Object> {
    let mut by_key: BTreeMap<String, Object> = BTreeMap::new();
    for v in listed {
        let Some(named) = ids(prefix, &v.key) else {
            if !v.marker && !by_key.contains_key(&v.key) {
                w.stray(&v.key);
                by_key.insert(v.key.clone(), Object { key: v.key, named: (0, -1), versions: Vec::new(), hidden: false, modified: 0 });
            }
            continue;
        };
        let o = by_key.entry(v.key.clone()).or_insert_with(|| Object { key: v.key.clone(), named, versions: Vec::new(), hidden: false, modified: 0 });
        o.modified = o.modified.max(v.modified.unwrap_or(i64::MAX));
        if v.marker {
            o.hidden |= v.latest;
        } else {
            o.versions.push(v.version);
        }
    }
    let mut out: Vec<Object> = by_key.into_values().filter(|o| o.named.0 <= o.named.1 && !o.versions.is_empty()).collect();
    out.sort_by(|a, b| (a.named, &a.key).cmp(&(b.named, &b.key)));
    out
}

/// One query, so an erasure can't land between reading a row's salt and its fields.
/// `details` is read as stored: the export redacted it with the secrets known then.
fn local(app: &App, lo: i64, hi: i64) -> rusqlite::Result<Local> {
    use crate::audit_chain::{ERASABLE, FIXED};
    let cols: Vec<&str> = FIXED.iter().chain(ERASABLE.iter()).copied().collect();
    let fields: Vec<&str> = FIXED_FIELDS.iter().chain(ERASABLE_FIELDS.iter()).copied().collect();
    let sql = format!("SELECT chain_hash, chain_salt IS NULL, chain_prev, {} FROM audit_events WHERE id BETWEEN ?1 AND ?2", cols.join(", "));
    let json = |col: &str, v: Sql| match (col, v) {
        ("details", Sql::Text(t)) => serde_json::from_str(&t).unwrap_or(Value::Null),
        (_, Sql::Integer(n)) => Value::from(n),
        (_, Sql::Real(f)) => Value::from(f),
        (_, Sql::Text(t)) => Value::String(t),
        _ => Value::Null,
    };
    app.db.with_conn(|c| {
        let mut s = c.prepare(&sql)?;
        let mut rows = s.query([lo, hi])?;
        let mut out = Local::default();
        while let Some(r) = rows.next()? {
            let mut event = serde_json::Map::new();
            event.insert("chainPrev".into(), json("chain_prev", r.get(2)?));
            for (i, (col, field)) in cols.iter().zip(&fields).enumerate() {
                event.insert(field.to_string(), json(col, r.get(3 + i)?));
            }
            let Some(id) = event["id"].as_i64() else { continue };
            let hash = match r.get::<_, Sql>(0)? {
                Sql::Text(t) => Some(t),
                _ => None,
            };
            out.hashes.insert(id, hash);
            out.rows.insert(id, Row { event: Value::Object(event), erased: r.get(1)? });
        }
        Ok(out)
    })
}

/// What botd knew of the archive when a check began, read before the listing so that
/// what was delivered by then is in it.
#[derive(Clone, Debug)]
pub struct Basis {
    /// How far botd says it got.
    pub delivered: i64,
    /// Whether it has cut any batch for this archive.
    pub batches: bool,
    /// The first event of its first batch, if recorded.
    pub start: Option<i64>,
}

impl Basis {
    pub fn read(app: &App, x: &Exporter) -> Basis {
        Basis {
            delivered: x.delivered(),
            batches: app.db.audit_export_cursor(&format!("{}#batch", x.sink.id)).is_some(),
            start: app.db.audit_export_cursor(&format!("{}#start", x.sink.id)),
        }
    }
}

/// Where the last passing check of an archive got to: its head, and when it began (ms).
#[derive(Clone, Debug, PartialEq)]
pub struct Since {
    pub head: Link,
    pub at: i64,
}

/// Beside the sink's cursors, so another archive starts with a whole check.
fn since_key(sink: &str) -> String {
    format!("audit_export:{sink}#checked")
}

fn read_pass(c: &rusqlite::Connection, sink: &str) -> rusqlite::Result<Option<Since>> {
    let raw: Option<String> = c.query_row("SELECT value FROM settings WHERE key = ?", [since_key(sink)], |r| r.get(0)).optional()?;
    let parsed = || -> Option<Since> {
        let v: Value = serde_json::from_str(raw.as_deref()?).ok()?;
        let head = Link::parse(&format!("{}:{}", v["id"].as_i64()?, v["hash"].as_str()?)).ok()?;
        Some(Since { head, at: v["at"].as_i64()? })
    };
    Ok(parsed())
}

pub fn last_pass(app: &App, sink: &str) -> Option<Since> {
    app.db.with_conn(|c| read_pass(c, sink)).ok().flatten()
}

/// Only a pass further on than the saved one replaces it: checks can overlap (the daily
/// one and one by hand), and the one that began first may finish last.
fn save_pass(app: &App, sink: &str, s: &Since) -> rusqlite::Result<bool> {
    let v = json!({ "id": s.head.id, "hash": s.head.hash, "at": s.at }).to_string();
    app.db.with_conn(|c| {
        if read_pass(c, sink)?.is_some_and(|old| (old.head.id, old.at) >= (s.head.id, s.at)) {
            return Ok(false);
        }
        c.execute("INSERT INTO settings (key, value) VALUES (?1, ?2) ON CONFLICT(key) DO UPDATE SET value = ?2", [since_key(sink), v]).map(|_| true)
    })
}

/// Saves a passing check's head as where the next daily check picks up. A check that
/// failed, reached nothing, or was overtaken leaves the last pass as it was.
fn passed(app: &App, sink: &str, c: &Checked, at: i64) {
    let Some(head) = c.head.clone().filter(|_| c.ok) else { return };
    if let Err(e) = save_pass(app, sink, &Since { head, at }) {
        crate::obs::log::log_warn!("Audit archive: couldn't save how far its check got ({e}); the next daily check reads from the last pass.");
    }
}

/// `archive=on`: the whole archive, or `range`. A whole check that passes is where the
/// daily check picks up next.
pub async fn check_by_hand(app: &App, x: &Exporter, a: &Archive, range: Range, keys: &[Vec<u8>]) -> Checked {
    let at = now();
    let c = check(app, a, &Basis::read(app, x), range, None, keys).await;
    if range.from.is_none() && range.to.is_none() {
        passed(app, &x.sink.id, &c, at);
    }
    c
}

/// The daily check: what is new since the last pass, or the whole archive before the first.
pub async fn check_new(app: &App, x: &Exporter, a: &Archive, keys: &[Vec<u8>]) -> Checked {
    let at = now();
    let since = last_pass(app, &x.sink.id);
    let c = check(app, a, &Basis::read(app, x), Range::default(), since.as_ref(), keys).await;
    passed(app, &x.sink.id, &c, at);
    c
}

/// Checks the archive `a` within `range` against itself and this server's log, trusting
/// checkpoints signed by `keys`. With `since`, only objects past its head, or written to
/// since it began, are read, and the chain carries on from its head.
pub async fn check(app: &App, a: &Archive, basis: &Basis, range: Range, since: Option<&Since>, keys: &[Vec<u8>]) -> Checked {
    use futures_util::StreamExt;
    let (delivered, batches) = (basis.delivered, basis.batches);
    let mut w = Walker::new(a, delivered, keys).starting_at(basis.start).resuming(since);
    let s3 = match S3::new(a.s3.clone()) {
        Ok(s) => s.called("the audit archive"),
        Err(e) => {
            w.fail(e);
            return w.finish(range, batches);
        }
    };
    let listed = match s3.object_versions(&format!("{}/", a.prefix)).await {
        Ok(l) => l,
        Err(e) => {
            w.fail(format!("{e} (botd lists the archive's versions: s3:ListBucketVersions on the bucket)"));
            return w.finish(range, batches);
        }
    };
    let mut todo = Vec::new();
    let old = |o: &Object| since.is_some_and(|s| o.named.1 <= s.head.id && o.modified < s.at - CLOCK_SKEW_MS);
    for o in objects(&a.prefix, listed, &mut w) {
        if range.from.is_some_and(|f| o.named.1 < f) || range.to.is_some_and(|t| o.named.0 > t) || old(&o) {
            w.skipped();
        } else {
            w.versions(o.versions.len() as u64 - 1, o.hidden);
            todo.push(o);
        }
    }
    if let Some(s) = since {
        match local(app, s.head.id, s.head.id) {
            Ok(here) => w.head_held(here.hashes.get(&s.head.id), app.db.audit_chain_anchor().as_ref()),
            Err(e) => {
                w.fail(format!("couldn't read event {} of the audit log: {e}", s.head.id));
                return w.finish(range, batches);
            }
        }
    }
    let s3 = &s3;
    let mut reads = futures_util::stream::iter(todo).map(|o| read(s3, o)).buffered(PARALLEL);
    while let Some(r) = reads.next().await {
        let key = r.object.key.clone();
        if let Some(e) = r.overwritten {
            w.overwritten(&key, e);
        }
        let (meta, body) = match r.first {
            Ok(b) => b,
            Err(e) => {
                w.unreadable(&key, e);
                continue;
            }
        };
        let (lo, hi) = Walker::span(&body).unwrap_or(r.object.named);
        let here = match local(app, lo, hi) {
            Ok(l) => l,
            Err(e) => {
                w.fail(format!("couldn't read the audit log from event {lo} to {hi}: {e}"));
                break;
            }
        };
        w.object(&key, r.object.named, &meta, &body, &here, app.db.audit_chain_anchor().as_ref());
    }
    w.finish(range, batches)
}

/// What `audit.verified` records of an archive check: counts and the first problem.
pub fn summary(c: &Checked) -> Value {
    serde_json::json!({
        "ok": c.ok, "archive": c.archive, "objects": c.objects, "skipped": c.skipped, "events": c.events, "first": c.first, "head": c.head, "delivered": c.delivered, "start": c.start, "after": c.after,
        "matched": c.matched, "altered": c.altered, "gone": c.gone, "mismatched": c.mismatched, "missing": c.missing, "locked": c.locked, "lockExpired": c.lock_expired,
        "checkpoints": c.checkpoints, "problems": c.problems, "firstProblem": c.first_problems.first(), "error": c.error,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit_chain::GENESIS;
    use serde_json::json;

    fn archive(lock: &str) -> Archive {
        crate::audit_archive::tests::archive(&[("AUDIT_EXPORT_S3_LOCK", lock)]).unwrap()
    }

    /// Event n's hash on the test chain: n in 64 digits.
    fn hash(n: i64) -> String {
        format!("{n:064}")
    }

    fn line(id: i64) -> String {
        let prev = if id == 1 { GENESIS.to_string() } else { hash(id - 1) };
        json!({ "schema": crate::audit_export::SCHEMA, "id": id, "action": "test.x", "chainPrev": prev, "chainHash": hash(id), "details": {} }).to_string()
    }

    fn body(ids: impl Iterator<Item = i64>) -> Vec<u8> {
        ids.map(|i| line(i) + "\n").collect::<String>().into_bytes()
    }

    fn meta(from: i64, to: i64) -> Meta {
        Meta {
            schema: Some(crate::audit_export::SCHEMA.into()),
            first_id: Some(from),
            last_id: Some(to),
            events: Some((to - from + 1) as u64),
            chain_prev: Some(if from == 1 { GENESIS.into() } else { hash(from - 1) }),
            chain_head: Some(hash(to)),
            lock_mode: Some("COMPLIANCE".into()),
            retain_until: Some(now() + 86_400_000),
        }
    }

    fn local(to: i64) -> Local {
        hashes(1..=to)
    }

    fn hashes(ids: impl Iterator<Item = i64>) -> Local {
        Local { hashes: ids.map(|i| (i, Some(hash(i)))).collect(), ..Default::default() }
    }

    fn walk(objects: &[(i64, i64)], lock: &str, delivered: i64, here: &Local) -> Checked {
        let a = archive(lock);
        let mut w = Walker::new(&a, delivered, &[]);
        for &(f, t) in objects {
            w.object(&format!("prod/2026/11/23/{f:020}-{t:020}.jsonl"), (f, t), &meta(f, t), &body(f..=t), here, None);
        }
        w.finish(Range::default(), true)
    }

    fn reasons(c: &Checked) -> Vec<&'static str> {
        c.first_problems.iter().map(|p| p.reason).collect()
    }

    #[test]
    fn keys_name_their_ids() {
        assert_eq!(ids("prod", "prod/2026/11/23/00000000000000000001-00000000000000000200.jsonl"), Some((1, 200)));
        for bad in [
            "prod/2026/11/23/1-200.jsonl",
            "prod/2026/11/23/00000000000000000201-00000000000000000200.jsonl",
            "prod/2026/11/00000000000000000001-00000000000000000200.jsonl",
            "prod/2026/11/23/00000000000000000001-00000000000000000200.json",
            "other/2026/11/23/00000000000000000001-00000000000000000200.jsonl",
            "prod/README",
        ] {
            assert_eq!(ids("prod", bad), None, "{bad}");
        }
    }

    #[test]
    fn a_whole_archive_holds() {
        let c = walk(&[(1, 3), (4, 4), (5, 9)], "bucket", 9, &local(9));
        assert!(c.ok, "{c:?}");
        assert_eq!((c.objects, c.events, c.first, c.head.as_ref().map(|h| h.id), c.matched, c.locked), (3, 9, Some(1), Some(9), 9, 3));
    }

    #[test]
    fn gaps_and_a_short_archive_are_named() {
        let c = walk(&[(1, 3), (7, 9)], "bucket", 9, &local(9));
        assert_eq!((c.ok, reasons(&c), c.first_problems[0].id), (false, vec!["link"], Some(7)));
        let c = walk(&[(1, 3), (4, 6)], "bucket", 9, &local(9));
        assert_eq!((reasons(&c), c.first_problems[0].id), (vec!["behind"], Some(7)));
        assert!(walk(&[], "bucket", 9, &local(9)).first_problems.iter().any(|p| p.reason == "behind"), "batches were cut, yet nothing is there");
        let a = archive("bucket");
        assert!(Walker::new(&a, 9, &[]).finish(Range::default(), false).ok, "nothing cut yet (AUDIT_EXPORT_START=new)");
        assert!(Walker::new(&a, 9, &[]).finish(Range { from: None, to: Some(5) }, true).ok, "outside the range");
    }

    #[test]
    fn this_servers_log_is_held_to_the_archive() {
        let mut here = local(6);
        here.hashes.insert(4, Some(hash(40)));
        here.hashes.remove(&5);
        let c = walk(&[(1, 6)], "bucket", 6, &here);
        assert_eq!((c.matched, c.mismatched, c.missing, c.local_breaks.clone()), (4, 1, 1, vec![4, 5]));
        assert_eq!(reasons(&c), ["mismatch", "missing"]);
        // Pruned by retention: gone, with the anchor's hash still checked.
        let a = archive("bucket");
        let mut w = Walker::new(&a, 6, &[]);
        let anchor = Link { id: 3, hash: hash(3) };
        let here = hashes(4..=6);
        w.object("prod/2026/11/23/00000000000000000001-00000000000000000006.jsonl", (1, 6), &meta(1, 6), &body(1..=6), &here, Some(&anchor));
        let c = w.finish(Range::default(), true);
        assert_eq!((c.ok, c.gone, c.matched), (true, 3, 3), "{c:?}");
        let mut w = Walker::new(&a, 6, &[]);
        let wrong = Link { id: 3, hash: hash(30) };
        w.object("prod/2026/11/23/00000000000000000001-00000000000000000006.jsonl", (1, 6), &meta(1, 6), &body(1..=6), &here, Some(&wrong));
        assert_eq!(w.finish(Range::default(), true).local_breaks, [3]);
    }

    #[test]
    fn objects_must_be_what_they_say_and_locked() {
        let a = archive("bucket");
        let key = "prod/2026/11/23/00000000000000000001-00000000000000000003.jsonl";
        let mut w = Walker::new(&a, 3, &[]);
        let mut m = meta(1, 3);
        m.chain_head = Some(hash(2));
        m.lock_mode = None;
        w.object(key, (1, 4), &m, &body(1..=3), &local(3), None);
        let c = w.finish(Range::default(), true);
        assert_eq!(reasons(&c), ["metadata", "unlocked"]);
        assert!(c.first_problems[0].error.contains("names events 1 to 4") && c.first_problems[0].error.contains("chain-head"), "{c:?}");
        // An ended lock is counted, not a failure; with the lock off nothing is asked.
        let mut w = Walker::new(&a, 3, &[]);
        let mut m = meta(1, 3);
        m.retain_until = Some(now() - 1);
        w.object(key, (1, 3), &m, &body(1..=3), &local(3), None);
        let c = w.finish(Range::default(), true);
        assert_eq!((c.ok, c.lock_expired, c.locked), (true, 1, 0));
        let off = archive("off");
        let mut w = Walker::new(&off, 3, &[]);
        let mut m = meta(1, 3);
        m.lock_mode = None;
        w.object(key, (1, 3), &m, &body(1..=3), &local(3), None);
        assert!(w.finish(Range::default(), true).ok);
        // Out of order, unreadable, and not botd's at all.
        let mut w = Walker::new(&a, 3, &[]);
        w.object(key, (1, 3), &meta(1, 3), &body([1, 3, 2].into_iter()), &local(3), None);
        w.object(key, (1, 3), &meta(1, 3), b"{not json\n", &local(3), None);
        w.stray("prod/README");
        assert_eq!(reasons(&w.finish(Range::default(), true)), ["metadata", "order", "link", "unreadable", "stray"]);
    }

    #[test]
    fn repeats_are_counted_and_still_compared() {
        let c = walk(&[(1, 5), (1, 3), (4, 6)], "bucket", 6, &local(6));
        assert!(c.ok, "{c:?}");
        assert_eq!((c.events, c.repeated, c.matched, c.head.as_ref().map(|h| h.id)), (11, 5, 11, Some(6)));
    }

    #[test]
    fn checkpoints_must_be_signed_by_a_trusted_key() {
        let key = crate::audit_checkpoint::Key::derive();
        let cp = |seq: i64, signer: &crate::audit_checkpoint::Key| {
            let at = 1_795_000_000_000;
            let statement = crate::audit_checkpoint::statement(seq, &hash(seq), at, &signer.id);
            json!({ "seq": seq, "hash": hash(seq), "at": at, "keyId": signer.id, "publicKey": crate::sigv4::hex(&signer.public), "signature": signer.sign(&statement) })
        };
        let lines_with = |details: Value| -> Vec<u8> {
            let mut b = body(1..=2);
            b.extend(
                (json!({ "schema": crate::audit_export::SCHEMA, "id": 3, "action": crate::audit_checkpoint::CHECKPOINT, "chainPrev": hash(2), "chainHash": hash(3), "details": details }).to_string()
                    + "\n")
                    .as_bytes(),
            );
            b
        };
        let a = archive("bucket");
        let trusted = vec![key.public.clone()];
        let key3 = "prod/2026/11/23/00000000000000000001-00000000000000000003.jsonl";
        let mut w = Walker::new(&a, 3, &trusted);
        w.object(key3, (1, 3), &meta(1, 3), &lines_with(cp(2, &key)), &local(3), None);
        let c = w.finish(Range::default(), true);
        assert_eq!((c.ok, c.checkpoints), (true, 1), "{c:?}");
        let mut w = Walker::new(&a, 3, &[]);
        w.object(key3, (1, 3), &meta(1, 3), &lines_with(cp(2, &key)), &local(3), None);
        let c = w.finish(Range::default(), true);
        assert_eq!(reasons(&c), ["checkpoint"]);
        assert!(c.first_problems[0].error.contains("(key)"), "{c:?}");
        let mut w = Walker::new(&a, 3, &trusted);
        let mut forged = cp(2, &key);
        forged["at"] = json!(1);
        w.object(key3, (1, 3), &meta(1, 3), &lines_with(forged.clone()), &local(3), None);
        assert!(w.finish(Range::default(), true).first_problems[0].error.contains("(signature)"));
        // A repeat of the batch, with the same hashes but a forged checkpoint, is still checked.
        let mut w = Walker::new(&a, 3, &trusted);
        w.object(key3, (1, 3), &meta(1, 3), &lines_with(cp(2, &key)), &local(3), None);
        w.object("prod/2026/11/24/00000000000000000001-00000000000000000003.jsonl", (1, 3), &meta(1, 3), &lines_with(forged), &local(3), None);
        let c = w.finish(Range::default(), true);
        assert_eq!((reasons(&c), c.repeated, c.checkpoints), (vec!["checkpoint"], 3, 1), "{c:?}");
        assert!(c.first_problems[0].error.contains("(signature), repeated in prod/2026/11/24/"), "{c:?}");
    }

    #[test]
    fn an_archived_copy_must_say_what_this_servers_row_says() {
        let a = archive("bucket");
        let key = "prod/2026/11/23/00000000000000000001-00000000000000000003.jsonl";
        let row = |id: i64, details: Value, erased: bool| {
            let mut v: Value = serde_json::from_str(&line(id)).unwrap();
            v["details"] = details;
            v.as_object_mut().unwrap().remove("schema");
            Row { event: v, erased }
        };
        let mut here = local(3);
        here.rows = (1..=3).map(|i| (i, row(i, json!({}), false))).collect();
        let mut w = Walker::new(&a, 3, &[]);
        w.object(key, (1, 3), &meta(1, 3), &body(1..=3), &here, None);
        let c = w.finish(Range::default(), true);
        assert_eq!((c.ok, c.matched, c.altered), (true, 3, 0), "{c:?}");
        // Same hashes, other details: the archive's copy was changed.
        here.rows.insert(2, row(2, json!({ "n": 1 }), false));
        let mut w = Walker::new(&a, 3, &[]);
        w.object(key, (1, 3), &meta(1, 3), &body(1..=3), &here, None);
        let c = w.finish(Range::default(), true);
        assert_eq!((reasons(&c), c.altered, c.local_breaks.clone()), (vec!["contents"], 1, vec![]), "{c:?}");
        assert!(c.first_problems[0].error.contains("event 2's details"), "{c:?}");
        // Erased here since: only the fields an erasure can't rewrite are compared.
        here.rows.insert(2, row(2, json!({ "n": 1 }), true));
        let mut w = Walker::new(&a, 3, &[]);
        w.object(key, (1, 3), &meta(1, 3), &body(1..=3), &here, None);
        assert!(w.finish(Range::default(), true).ok);
        let mut r = row(2, json!({}), true);
        r.event["action"] = json!("test.other");
        here.rows.insert(2, r);
        let mut w = Walker::new(&a, 3, &[]);
        w.object(key, (1, 3), &meta(1, 3), &body(1..=3), &here, None);
        assert!(w.finish(Range::default(), true).first_problems[0].error.contains("event 2's action"));
    }

    #[test]
    fn details_may_have_been_redacted_on_the_way_out() {
        let row = |details: Value| Row { event: json!({ "details": details }), erased: false };
        let archived = |details: Value| json!({ "details": details });
        let here = json!({ "k": "token sk-live-0123456789 for b", "n": [1, "x"] });
        assert_eq!(differing(&archived(here.clone()), &row(here.clone())), None);
        assert_eq!(differing(&archived(json!({ "k": "token [redacted] for b", "n": [1, "x"] })), &row(here.clone())), None, "a secret known when it was exported");
        assert_eq!(differing(&archived(json!({ "k": "[redacted][redacted]", "n": [1, "x"] })), &row(here.clone())), None);
        for forged in [json!({ "k": "token [redacted] for c", "n": [1, "x"] }), json!({ "k": "token for b", "n": [1, "x"] }), json!({ "k": "token [redacted] for b", "n": [1] }), json!({ "k": "[redacted]" })] {
            assert_eq!(differing(&archived(forged.clone()), &row(here.clone())), Some("details"), "{forged}");
        }
        assert!(!redacted_text("ab[redacted]ba", "aba"), "the ends can't overlap");
    }

    #[test]
    fn compared_fields_are_the_chains_columns() {
        let camel = |c: &str| {
            let mut parts = c.split('_');
            parts.next().unwrap().to_string() + &parts.map(|p| p[..1].to_uppercase() + &p[1..]).collect::<String>()
        };
        assert_eq!(FIXED_FIELDS.to_vec(), crate::audit_chain::FIXED.iter().map(|c| camel(c)).collect::<Vec<_>>());
        assert_eq!(ERASABLE_FIELDS.to_vec(), crate::audit_chain::ERASABLE.iter().map(|c| camel(c)).collect::<Vec<_>>());
    }

    #[test]
    fn the_archive_must_begin_where_botd_started_it() {
        let a = archive("bucket");
        let walk_from = |start: i64, objects: &[(i64, i64)], range: Range| {
            let mut w = Walker::new(&a, 9, &[]).starting_at(Some(start));
            for &(f, t) in objects {
                w.object(&format!("prod/2026/11/23/{f:020}-{t:020}.jsonl"), (f, t), &meta(f, t), &body(f..=t), &local(9), None);
            }
            w.finish(range, true)
        };
        let c = walk_from(1, &[(4, 6), (7, 9)], Range::default());
        assert_eq!((c.ok, reasons(&c), c.first_problems[0].id), (false, vec!["start"], Some(1)), "{c:?}");
        assert!(walk_from(1, &[(1, 3), (4, 9)], Range::default()).ok);
        assert!(walk_from(4, &[(4, 6), (7, 9)], Range::default()).ok, "started later (AUDIT_EXPORT_START=new, or after retention)");
        assert!(walk_from(1, &[(4, 6), (7, 9)], Range { from: Some(4), to: None }).ok, "a range from later doesn't ask");
        assert!(walk(&[(4, 9)], "bucket", 9, &local(9)).ok, "no start recorded");
    }

    #[test]
    fn a_daily_check_carries_on_from_the_last_pass() {
        let a = archive("bucket");
        let since = |hash_of_6: String| Since { head: Link { id: 6, hash: hash_of_6 }, at: now() };
        let pass = since(hash(6));
        let resume = |delivered: i64, objects: &[(i64, i64)], s: &Since, here: &Local| {
            let mut w = Walker::new(&a, delivered, &[]).starting_at(Some(1)).resuming(Some(s));
            w.head_held(here.hashes.get(&s.head.id), None);
            for &(f, t) in objects {
                w.object(&format!("prod/2026/11/24/{f:020}-{t:020}.jsonl"), (f, t), &meta(f, t), &body(f..=t), here, None);
            }
            w.finish(Range::default(), true)
        };
        let c = resume(9, &[(7, 9)], &pass, &local(9));
        assert!(c.ok, "{c:?}");
        assert_eq!((c.after, c.first, c.head.as_ref().map(|h| h.id), c.events, c.matched), (Some(6), Some(7), Some(9), 3, 3));
        // Nothing new is fine while botd delivered nothing more, and `behind` once it did.
        assert!(resume(6, &[], &pass, &local(6)).ok);
        let c = resume(9, &[], &pass, &local(9));
        assert_eq!((reasons(&c), c.first_problems[0].id), (vec!["behind"], Some(7)), "{c:?}");
        // A gap right after the head is a `link`, not a `start`.
        let c = resume(9, &[(8, 9)], &pass, &local(9));
        assert_eq!((reasons(&c), c.first_problems[0].id), (vec!["link"], Some(8)), "{c:?}");
        // A copy of events already checked, read because it was written since: repeats, still compared.
        let c = resume(9, &[(4, 6), (7, 9)], &pass, &local(9));
        assert_eq!((c.ok, c.repeated, c.matched), (true, 3, 6), "{c:?}");
        let mut rebuilt = local(9);
        rebuilt.hashes.insert(5, Some(hash(50)));
        assert_eq!(reasons(&resume(9, &[(4, 6), (7, 9)], &pass, &rebuilt)), ["mismatch"]);
    }

    #[test]
    fn an_overtaken_check_doesnt_move_the_last_pass_back() {
        let app = crate::runner::test_app();
        let pass = |id: i64, at: i64| Since { head: Link { id, hash: hash(id) }, at };
        assert_eq!(last_pass(&app, "s3://x"), None);
        assert!(save_pass(&app, "s3://x", &pass(9, 2_000)).unwrap());
        // Began first, finished last: older, and not saved over the newer one.
        assert!(!save_pass(&app, "s3://x", &pass(6, 1_000)).unwrap());
        assert!(!save_pass(&app, "s3://x", &pass(9, 1_000)).unwrap());
        assert_eq!(last_pass(&app, "s3://x"), Some(pass(9, 2_000)));
        // Nothing new since, a day on: the same head, a later start.
        assert!(save_pass(&app, "s3://x", &pass(9, 3_000)).unwrap());
        assert!(save_pass(&app, "s3://x", &pass(12, 2_500)).unwrap());
        assert_eq!((last_pass(&app, "s3://x"), last_pass(&app, "s3://y")), (Some(pass(12, 2_500)), None), "kept per archive");
    }

    #[test]
    fn the_last_pass_must_still_hold_in_this_servers_log() {
        let a = archive("bucket");
        let pass = Since { head: Link { id: 6, hash: hash(6) }, at: now() };
        let held = |here: Option<&Option<String>>, anchor: Option<&Link>| {
            let mut w = Walker::new(&a, 6, &[]).resuming(Some(&pass));
            w.head_held(here, anchor);
            w.finish(Range::default(), true)
        };
        assert!(held(Some(&Some(hash(6))), None).ok);
        // Rebuilt from any event up to it: the head's hash here changed.
        let c = held(Some(&Some(hash(60))), None);
        assert_eq!((reasons(&c), c.local_breaks.clone(), c.mismatched), (vec!["mismatch"], vec![6], 1), "{c:?}");
        assert!(c.first_problems[0].error.contains("the log was rebuilt"), "{c:?}");
        assert_eq!(reasons(&held(None, None)), ["missing"]);
        // Deleted by retention since: the anchor's hash is checked when it is the head.
        assert!(held(None, Some(&Link { id: 9, hash: hash(9) })).ok);
        assert!(held(None, Some(&Link { id: 6, hash: hash(6) })).ok);
        assert_eq!(reasons(&held(None, Some(&Link { id: 6, hash: hash(60) }))), ["mismatch"]);
        // A whole check has no last pass to hold.
        let mut w = Walker::new(&a, 0, &[]);
        w.head_held(Some(&Some(hash(60))), None);
        assert!(w.finish(Range::default(), false).ok);
    }

    #[test]
    fn a_range_must_hold_what_botd_delivered_in_it() {
        let a = archive("bucket");
        let walk_range = |start: Option<i64>, objects: &[(i64, i64)], range: Range| {
            let mut w = Walker::new(&a, 9, &[]).starting_at(start);
            for &(f, t) in objects {
                w.object(&format!("prod/2026/11/23/{f:020}-{t:020}.jsonl"), (f, t), &meta(f, t), &body(f..=t), &local(9), None);
            }
            w.finish(range, true)
        };
        // 4 to 6 deleted: the objects either side are outside the range, so nothing is read.
        let c = walk_range(Some(1), &[], Range { from: Some(4), to: Some(6) });
        assert_eq!((reasons(&c), c.first_problems[0].id), (vec!["behind"], Some(4)), "{c:?}");
        assert!(c.first_problems[0].error.contains("none from 4 to 6"), "{c:?}");
        let c = walk_range(Some(1), &[(1, 3)], Range { from: None, to: Some(6) });
        assert_eq!((reasons(&c), c.first_problems[0].id), (vec!["behind"], Some(4)), "{c:?}");
        let c = walk_range(Some(1), &[(7, 9)], Range { from: Some(5), to: None });
        assert_eq!((reasons(&c), c.first_problems[0].id), (vec!["start"], Some(5)), "{c:?}");
        assert!(c.first_problems[0].error.contains("no events from 5 to 6"), "{c:?}");
        assert!(walk_range(Some(1), &[(4, 6)], Range { from: Some(4), to: Some(6) }).ok);
        assert!(walk_range(Some(7), &[], Range { from: None, to: Some(6) }).ok, "before the archive began");
        assert!(walk_range(None, &[], Range { from: Some(4), to: Some(6) }).ok, "no start recorded: can't tell");
    }
}
