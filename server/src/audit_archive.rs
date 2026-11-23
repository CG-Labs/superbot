//! The audit log's write-once archive (ADR 0153): the SIEM export's third sink,
//! `AUDIT_EXPORT=s3://<bucket>[/<prefix>]`. Events go out in batches, one JSON-lines
//! object per batch, to any S3-compatible store, each object locked with S3 Object
//! Lock so nobody (botd, root on the host, whoever holds the store's keys) can change
//! or delete it before its retention ends.
//!
//! botd refuses a bucket without Object Lock, and after every write reads the object's
//! headers back to see that it really is locked: a store that ignores the lock headers
//! is a failing export, not a silent gap. `AUDIT_EXPORT_S3_LOCK=off` turns both off for
//! a plain bucket.

use crate::db::{now, AuditEvent};
use crate::machines::s3::{self, S3};
use crate::secrets::SecretStore;
use base64::Engine;
use serde_json::{json, Value};

/// Events an object holds at most.
pub const MAX_EVENTS: i64 = 10_000;
const MAX_RETAIN_DAYS: u32 = 36_500;
const MAX_BATCH_SECONDS: i64 = 86_400;
/// The prefix when `AUDIT_EXPORT` names only a bucket.
const PREFIX: &str = "superbot-audit";
/// The failure reason (on `audit.export_failing`) when the store isn't write-once.
pub const NOT_WRITE_ONCE: &str = "not_write_once";

/// How each object is locked.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Lock {
    /// By the bucket's default retention, which must be set.
    Bucket,
    /// In compliance mode: nobody can shorten or remove it, not even the account's root.
    Compliance,
    /// In governance mode: those with `s3:BypassGovernanceRetention` can.
    Governance,
    /// Not at all: a plain bucket.
    Off,
}

impl Lock {
    pub fn name(self) -> &'static str {
        match self {
            Lock::Bucket => "bucket",
            Lock::Compliance => "compliance",
            Lock::Governance => "governance",
            Lock::Off => "off",
        }
    }

    /// The `x-amz-object-lock-mode` botd asks for, if it asks for one.
    fn mode(self) -> Option<&'static str> {
        match self {
            Lock::Compliance => Some("COMPLIANCE"),
            Lock::Governance => Some("GOVERNANCE"),
            _ => None,
        }
    }
}

/// Where the archive goes and how it is kept.
pub struct Archive {
    pub s3: s3::Settings,
    pub bucket: String,
    pub prefix: String,
    pub lock: Lock,
    /// Days each object is locked for, with an explicit mode.
    pub retain_days: Option<u32>,
    /// How long the oldest waiting event waits for more before its batch goes.
    pub batch_ms: i64,
}

impl std::fmt::Debug for Archive {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Archive(s3://{}/{} at {})", self.bucket, self.prefix, self.s3.endpoint)
    }
}

impl Archive {
    /// `AUDIT_EXPORT=s3://<bucket>[/<prefix>]` and the `AUDIT_EXPORT_S3_*` settings:
    /// `_ENDPOINT`, `_REGION` (us-east-1), `_LOCK` (bucket), `_RETAIN_DAYS`,
    /// `_BATCH_SECONDS` (300), and the keys `_ACCESS_KEY_ID` and `_SECRET_ACCESS_KEY` from
    /// the secret store.
    pub fn from_env(raw: &str, get: &dyn Fn(&str) -> String, store: &dyn SecretStore) -> Result<Archive, String> {
        let bad = |why: &str| format!("AUDIT_EXPORT must be s3://<bucket>[/<prefix>] for the S3 archive: {why}");
        let u = url::Url::parse(raw.trim()).map_err(|_| bad("it isn't a URL"))?;
        if !u.username().is_empty() || u.password().is_some() || u.query().is_some() || u.fragment().is_some() || u.port().is_some() {
            return Err(bad("only a bucket and a prefix; the store's address is AUDIT_EXPORT_S3_ENDPOINT and its keys are secrets"));
        }
        let bucket = u.host_str().unwrap_or_default().to_string();
        if !s3::bucket_name(&bucket) {
            return Err(bad(&format!("\"{}\" isn't a bucket name", crate::audit::clip(&bucket, 70))));
        }
        // From the text as written: the URL parser would quietly drop `..` segments.
        let written = raw.trim().get("s3://".len()..).unwrap_or_default();
        let prefix = written.split_once('/').map(|(_, p)| p).unwrap_or_default().trim_matches('/');
        let prefix = if prefix.is_empty() { PREFIX.to_string() } else { prefix.to_string() };
        let segment_ok = |s: &str| !s.is_empty() && s != "." && s != ".." && s.bytes().all(|c| c.is_ascii_alphanumeric() || b"-_.".contains(&c));
        if prefix.len() > 256 || !prefix.split('/').all(segment_ok) {
            return Err(bad("the prefix takes letters, digits, '-', '_' and '.', in segments split by '/'"));
        }

        let lock = match get("AUDIT_EXPORT_S3_LOCK").trim().to_ascii_lowercase().as_str() {
            "" | "bucket" => Lock::Bucket,
            "compliance" => Lock::Compliance,
            "governance" => Lock::Governance,
            "off" => Lock::Off,
            other => return Err(format!("AUDIT_EXPORT_S3_LOCK must be bucket, compliance, governance or off, not \"{}\"", crate::audit::clip(other, 40))),
        };
        let days = get("AUDIT_EXPORT_S3_RETAIN_DAYS");
        let retain_days = match (lock.mode(), days.trim()) {
            (Some(_), "") => return Err(format!("AUDIT_EXPORT_S3_RETAIN_DAYS is needed with AUDIT_EXPORT_S3_LOCK={}: how many days each object is locked for", lock.name())),
            (Some(_), d) => match d.parse::<u32>() {
                Ok(n) if (1..=MAX_RETAIN_DAYS).contains(&n) => Some(n),
                _ => return Err(format!("AUDIT_EXPORT_S3_RETAIN_DAYS must be a whole number of days from 1 to {MAX_RETAIN_DAYS}")),
            },
            (None, "") => None,
            (None, _) => return Err(format!("AUDIT_EXPORT_S3_RETAIN_DAYS goes with AUDIT_EXPORT_S3_LOCK=compliance or governance, not {}", lock.name())),
        };
        let batch_ms = match get("AUDIT_EXPORT_S3_BATCH_SECONDS").trim() {
            "" => 300_000,
            s => match s.parse::<i64>() {
                Ok(n) if (0..=MAX_BATCH_SECONDS).contains(&n) => n * 1000,
                _ => return Err(format!("AUDIT_EXPORT_S3_BATCH_SECONDS must be from 0 to {MAX_BATCH_SECONDS}")),
            },
        };

        let name = "AUDIT_EXPORT_S3";
        let endpoint = get("AUDIT_EXPORT_S3_ENDPOINT");
        if endpoint.trim().is_empty() {
            return Err("AUDIT_EXPORT_S3_ENDPOINT is needed with an s3:// AUDIT_EXPORT, e.g. https://s3.<region>.amazonaws.com".into());
        }
        let key = |k: &str| -> Result<String, String> {
            let v = store.get(k).map_err(|e| e.to_string())?.ok_or(format!("{k} (or {k}_FILE) is needed with an s3:// AUDIT_EXPORT"))?;
            Ok(v.expose().trim().to_string())
        };
        let secret = key("AUDIT_EXPORT_S3_SECRET_ACCESS_KEY")?;
        crate::secrets::redact::register(&secret);
        let access = key("AUDIT_EXPORT_S3_ACCESS_KEY_ID")?;
        let region = Some(get("AUDIT_EXPORT_S3_REGION")).filter(|r| !r.trim().is_empty()).unwrap_or("us-east-1".into());
        let s3 = s3::Settings::named(name, &endpoint, &bucket, &region, &access, &secret)?;
        Ok(Archive { s3, bucket, prefix, lock, retain_days, batch_ms })
    }

    /// What logs, the API and the audit log show.
    pub fn shown(&self) -> String {
        format!("s3://{}/{}", self.bucket, self.prefix)
    }

    /// Names the cursor: the same bucket and prefix in another store starts again.
    pub fn id(&self) -> String {
        let at = self.s3.endpoint.split_once("://").map(|(_, h)| h).unwrap_or(&self.s3.endpoint);
        format!("s3://{at}/{}/{}", self.bucket, self.prefix)
    }

    pub fn describe(&self) -> String {
        let lock = match (self.lock, self.retain_days) {
            (Lock::Bucket, _) => "each locked by the bucket's default retention".to_string(),
            (Lock::Off, _) => "not locked (AUDIT_EXPORT_S3_LOCK=off)".to_string(),
            (l, d) => format!("each locked in {} mode for {} days", l.name(), d.unwrap_or_default()),
        };
        format!("as JSON-lines objects at {} every {} s or {MAX_EVENTS} events, {lock}", self.s3.endpoint, self.batch_ms / 1000)
    }

    /// `<prefix>/<yyyy>/<mm>/<dd>/<first id>-<last id>.jsonl`, dated by the first event,
    /// ids zero-padded so keys sort in order. A retried batch has the same key.
    pub fn key(&self, first: &AuditEvent, last: &AuditEvent) -> String {
        let day = chrono::DateTime::from_timestamp_millis(first.at).unwrap_or_default().format("%Y/%m/%d");
        format!("{}/{day}/{:020}-{:020}.jsonl", self.prefix, first.id, last.id)
    }

    /// `GET /api/audit/siem`'s `archive`: how objects are kept, and the last one written.
    pub fn view(&self, last: Option<&Value>) -> Value {
        json!({
            "endpoint": self.s3.endpoint,
            "bucket": self.bucket,
            "prefix": self.prefix,
            "lock": self.lock.name(),
            "retainDays": self.retain_days,
            "batchSeconds": self.batch_ms / 1000,
            "lastObject": last,
        })
    }
}

/// The archive's client, and whether the bucket was found write-once.
pub struct Client {
    s3: S3,
    checked: bool,
}

type Failure = (&'static str, String);

fn header(h: &reqwest::header::HeaderMap, name: &str) -> Option<String> {
    h.get(name).and_then(|v| v.to_str().ok()).map(|v| v.trim().to_string()).filter(|v| !v.is_empty())
}

impl Client {
    pub fn new(a: &Archive) -> Client {
        Client { s3: S3::new(a.s3.clone()).expect("S3 client").called("the audit archive"), checked: false }
    }

    /// The bucket has Object Lock on, and a default retention when that is what locks.
    async fn check_bucket(&self, a: &Archive) -> Result<(), Failure> {
        let off = "or set AUDIT_EXPORT_S3_LOCK=off for a bucket that isn't write-once";
        let xml = self.s3.object_lock().await.map_err(|e| ("delivery_failed", e))?;
        let enabled = xml.as_deref().and_then(|x| s3::tag(x, "ObjectLockEnabled")).is_some_and(|v| v == "Enabled");
        if !enabled {
            return Err((NOT_WRITE_ONCE, format!("the bucket {} doesn't have Object Lock on: make one with it ({off})", a.bucket)));
        }
        if a.lock == Lock::Bucket && xml.as_deref().and_then(|x| s3::tag(x, "DefaultRetention")).is_none() {
            return Err((
                NOT_WRITE_ONCE,
                format!("the bucket {} has Object Lock but no default retention: set one, or AUDIT_EXPORT_S3_LOCK=compliance with AUDIT_EXPORT_S3_RETAIN_DAYS ({off})", a.bucket),
            ));
        }
        Ok(())
    }

    /// Writes one batch as one object and returns what was written. With a lock, checks
    /// the bucket first (until that passes) and reads the object's lock back after.
    pub async fn send(&mut self, a: &Archive, rows: &[AuditEvent], body: Vec<u8>) -> Result<Value, Failure> {
        let r = self.write(a, rows, body).await;
        if r.is_err() {
            self.checked = false;
        }
        r
    }

    async fn write(&mut self, a: &Archive, rows: &[AuditEvent], body: Vec<u8>) -> Result<Value, Failure> {
        let (Some(first), Some(last)) = (rows.first(), rows.last()) else { return Err(("delivery_failed", "an empty batch".into())) };
        if a.lock != Lock::Off && !self.checked {
            self.check_bucket(a).await?;
            self.checked = true;
        }
        let key = a.key(first, last);
        let bytes = body.len();
        let sha = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, &body);
        let mut headers: Vec<(&str, String)> = vec![
            ("content-type", "application/x-ndjson".into()),
            // Object Lock writes need a checksum (Content-MD5 or one of these).
            ("x-amz-sdk-checksum-algorithm", "SHA256".into()),
            ("x-amz-checksum-sha256", base64::engine::general_purpose::STANDARD.encode(sha.as_ref())),
            ("x-amz-meta-superbot-schema", crate::audit_export::SCHEMA.into()),
            ("x-amz-meta-superbot-first-id", first.id.to_string()),
            ("x-amz-meta-superbot-last-id", last.id.to_string()),
            ("x-amz-meta-superbot-events", rows.len().to_string()),
            ("x-amz-meta-superbot-chain-prev", first.chain_prev.clone().unwrap_or_default()),
            ("x-amz-meta-superbot-chain-head", last.chain_hash.clone().unwrap_or_default()),
        ];
        let wanted = match (a.lock.mode(), a.retain_days) {
            (Some(mode), Some(days)) => {
                let until = chrono::Utc::now() + chrono::Duration::days(days as i64);
                headers.push(("x-amz-object-lock-mode", mode.into()));
                headers.push(("x-amz-object-lock-retain-until-date", until.format("%Y-%m-%dT%H:%M:%SZ").to_string()));
                Some((mode, until.timestamp_millis() / 1000 * 1000))
            }
            _ => None,
        };
        let put = self.s3.put_with(&key, body, &headers).await.map_err(|e| ("delivery_failed", e))?;
        let version = header(&put, "x-amz-version-id").filter(|v| v != "null");
        let mut out = json!({ "key": key, "version": version, "events": rows.len(), "bytes": bytes, "firstId": first.id, "lastId": last.id, "at": now() });
        if a.lock == Lock::Off {
            return Ok(out);
        }
        let Some(version) = version else {
            return Err((NOT_WRITE_ONCE, format!("the audit archive kept no version of {key}: the bucket isn't versioned, so it can't be write-once")));
        };
        let got = self.s3.head(&key, Some(&version)).await.map_err(|e| ("delivery_failed", format!("{e} (reading back {key})")))?;
        if header(&got, "content-length").and_then(|l| l.parse::<usize>().ok()) != Some(bytes) {
            return Err(("delivery_failed", format!("the audit archive holds a different {key} than was written")));
        }
        let mode = header(&got, "x-amz-object-lock-mode");
        let until = header(&got, "x-amz-object-lock-retain-until-date").and_then(|t| chrono::DateTime::parse_from_rfc3339(&t).ok()).map(|t| t.timestamp_millis());
        let (Some(mode), Some(until)) = (mode, until) else {
            return Err((NOT_WRITE_ONCE, format!("the audit archive stored {key} without a lock: the store ignores Object Lock")));
        };
        let short = match wanted {
            Some((m, at_least)) => !mode.eq_ignore_ascii_case(m) || until < at_least,
            None => until <= now(),
        };
        if short {
            return Err((NOT_WRITE_ONCE, format!("the audit archive locked {key} in {mode} mode until {until} (ms), not as asked")));
        }
        out["lockMode"] = json!(mode.to_ascii_lowercase());
        out["retainUntil"] = json!(until);
        Ok(out)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::secrets::env::EnvStore;

    pub(crate) fn archive(vars: &[(&str, &str)]) -> Result<Archive, String> {
        let base = [("AUDIT_EXPORT_S3_ENDPOINT", "https://s3.example.net"), ("AUDIT_EXPORT_S3_ACCESS_KEY_ID", "AKID"), ("AUDIT_EXPORT_S3_SECRET_ACCESS_KEY", "archive-secret-0123456789")];
        let mut all: Vec<(&str, &str)> = base.to_vec();
        all.extend_from_slice(vars);
        let map: std::collections::HashMap<String, String> = all.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        let raw = map.get("AUDIT_EXPORT").cloned().unwrap_or("s3://audit-archive/prod".into());
        Archive::from_env(&raw, &|k| map.get(k).cloned().unwrap_or_default(), &EnvStore::fixed(&all))
    }

    #[test]
    fn settings_are_checked() {
        let a = archive(&[]).unwrap();
        assert_eq!((a.bucket.as_str(), a.prefix.as_str(), a.lock, a.retain_days, a.batch_ms), ("audit-archive", "prod", Lock::Bucket, None, 300_000));
        assert_eq!((a.shown(), a.id()), ("s3://audit-archive/prod".to_string(), "s3://s3.example.net/audit-archive/prod".to_string()));
        assert!(a.describe().contains("bucket's default retention"), "{}", a.describe());
        assert!(!format!("{a:?}").contains("archive-secret"));
        assert_eq!(archive(&[("AUDIT_EXPORT", "s3://audit-archive")]).unwrap().prefix, "superbot-audit");
        assert_eq!(archive(&[("AUDIT_EXPORT", "s3://audit-archive/a/b.c/")]).unwrap().prefix, "a/b.c");
        let c = archive(&[("AUDIT_EXPORT_S3_LOCK", "Compliance"), ("AUDIT_EXPORT_S3_RETAIN_DAYS", "2555"), ("AUDIT_EXPORT_S3_BATCH_SECONDS", "0")]).unwrap();
        assert_eq!((c.lock, c.retain_days, c.batch_ms), (Lock::Compliance, Some(2555), 0));
        assert!(c.describe().contains("compliance mode for 2555 days"), "{}", c.describe());
        assert_eq!(archive(&[("AUDIT_EXPORT_S3_LOCK", "off")]).unwrap().lock, Lock::Off);

        for (vars, why) in [
            (vec![("AUDIT_EXPORT", "s3://No_Caps/x")], "bucket name"),
            (vec![("AUDIT_EXPORT", "s3://bucket/../x")], "prefix"),
            (vec![("AUDIT_EXPORT", "s3://bucket/a//b")], "prefix"),
            (vec![("AUDIT_EXPORT", "s3://bucket/a b")], "prefix"),
            (vec![("AUDIT_EXPORT", "s3://key:secret@bucket/x")], "only a bucket"),
            (vec![("AUDIT_EXPORT", "s3://bucket/x?token=y")], "only a bucket"),
            (vec![("AUDIT_EXPORT_S3_LOCK", "forever")], "AUDIT_EXPORT_S3_LOCK"),
            (vec![("AUDIT_EXPORT_S3_LOCK", "governance")], "RETAIN_DAYS is needed"),
            (vec![("AUDIT_EXPORT_S3_LOCK", "compliance"), ("AUDIT_EXPORT_S3_RETAIN_DAYS", "0")], "from 1"),
            (vec![("AUDIT_EXPORT_S3_LOCK", "compliance"), ("AUDIT_EXPORT_S3_RETAIN_DAYS", "40000")], "from 1"),
            (vec![("AUDIT_EXPORT_S3_RETAIN_DAYS", "30")], "goes with"),
            (vec![("AUDIT_EXPORT_S3_BATCH_SECONDS", "-1")], "BATCH_SECONDS"),
            (vec![("AUDIT_EXPORT_S3_ENDPOINT", "http://s3.example.net")], "AUDIT_EXPORT_S3_ENDPOINT"),
            (vec![("AUDIT_EXPORT_S3_ENDPOINT", " ")], "AUDIT_EXPORT_S3_ENDPOINT is needed"),
        ] {
            let e = archive(&vars).unwrap_err();
            assert!(e.contains(why), "{vars:?}: {e}");
        }
        let e = Archive::from_env("s3://bucket/x", &|k| if k == "AUDIT_EXPORT_S3_ENDPOINT" { "https://s3.example.net".into() } else { String::new() }, &EnvStore::fixed(&[])).unwrap_err();
        assert!(e.contains("AUDIT_EXPORT_S3_SECRET_ACCESS_KEY"), "{e}");
    }

    #[test]
    fn keys_sort_by_id_under_the_first_events_day() {
        let a = archive(&[]).unwrap();
        let mut first = crate::audit_export::tests::event("success");
        first.at = 1_795_000_000_000;
        let mut last = first.clone();
        last.id = 12_345;
        assert_eq!(a.key(&first, &last), "prod/2026/11/18/00000000000000000007-00000000000000012345.jsonl");
    }
}
