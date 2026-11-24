//! A small S3 client for off-host machine backups (ADR 0071): path-style requests
//! signed with AWS Signature Version 4, which AWS S3, Cloudflare R2, Backblaze B2,
//! MinIO and most S3-compatible stores accept. Only what backups need: multipart
//! uploads, small puts, streaming gets, listings and deletes (of old versions too, in a
//! versioned bucket). The secret key signs requests and
//! goes nowhere else: not in errors, logs, or `Debug`.

use crate::secrets::SecretStore;
use crate::sigv4::{self, hex, Scope};
pub use crate::sigv4::{canonical_query, encode, sha256_hex};
use aws_lc_rs::digest;
use reqwest::Method;
use std::time::Duration;

/// Parts of a multipart upload. S3 allows 10,000, so up to 160 GB a backup.
pub const PART_SIZE: usize = 16 * 1024 * 1024;
/// How long a request may go without a byte before it is given up.
const SILENCE: Duration = Duration::from_secs(120);

/// Where backups go and the key that signs for them.
#[derive(Clone)]
pub struct Settings {
    /// `scheme://host[:port]`, nothing after it.
    pub endpoint: String,
    /// What the request's `Host` header carries, and so what is signed.
    host: String,
    pub bucket: String,
    pub region: String,
    pub access_key: String,
    secret: String,
}

impl std::fmt::Debug for Settings {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.debug_struct("Settings")
            .field("endpoint", &self.endpoint)
            .field("bucket", &self.bucket)
            .field("region", &self.region)
            .field("access_key", &self.access_key)
            .field("secret", &"[redacted]")
            .finish()
    }
}

/// S3 bucket names: 3 to 63 lowercase letters, digits, dots and dashes.
pub fn bucket_name(b: &str) -> bool {
    (3..=63).contains(&b.len())
        && b.bytes().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'.' || c == b'-')
        && b.starts_with(|c: char| c.is_ascii_alphanumeric())
        && b.ends_with(|c: char| c.is_ascii_alphanumeric())
}

/// The settings' names start with this for machine backups (ADR 0071).
pub const MACHINES: &str = "MACHINE_BACKUP_S3";

impl Settings {
    /// `endpoint` must be https, or http to a loopback address (a local MinIO).
    #[cfg(test)]
    pub fn new(endpoint: &str, bucket: &str, region: &str, access_key: &str, secret: &str) -> Result<Settings, String> {
        Settings::named(MACHINES, endpoint, bucket, region, access_key, secret)
    }

    /// `new`, with errors naming `{name}_ENDPOINT`, `{name}_BUCKET` and so on.
    pub fn named(name: &str, endpoint: &str, bucket: &str, region: &str, access_key: &str, secret: &str) -> Result<Settings, String> {
        let bad = || format!("{name}_ENDPOINT must be https://host[:port], not \"{}\"", crate::audit::clip(endpoint, 80));
        let u = url::Url::parse(endpoint.trim()).map_err(|_| bad())?;
        let loopback = match u.host() {
            Some(url::Host::Ipv4(a)) => a.is_loopback(),
            Some(url::Host::Ipv6(a)) => a.is_loopback(),
            Some(url::Host::Domain(d)) => d == "localhost",
            None => false,
        };
        if !(u.scheme() == "https" || (u.scheme() == "http" && loopback))
            || !u.username().is_empty()
            || u.password().is_some()
            || !matches!(u.path(), "" | "/")
            || u.query().is_some()
            || u.fragment().is_some()
        {
            return Err(bad());
        }
        let host = match (u.host_str(), u.port()) {
            (Some(h), Some(p)) => format!("{h}:{p}"),
            (Some(h), None) => h.to_string(),
            _ => return Err(bad()),
        };
        if !bucket_name(bucket) {
            return Err(format!("{name}_BUCKET: \"{}\" isn't a bucket name", crate::audit::clip(bucket, 70)));
        }
        let region = region.trim();
        if region.is_empty() || !region.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_') {
            return Err(format!("{name}_REGION must be a region name, e.g. us-east-1 (auto for R2)"));
        }
        if access_key.is_empty() || access_key.chars().any(|c| c.is_whitespace() || c.is_control()) {
            return Err(format!("{name}_ACCESS_KEY_ID is empty or has spaces in it"));
        }
        if secret.is_empty() || secret.chars().any(|c| c.is_whitespace() || c.is_control()) {
            return Err(format!("{name}_SECRET_ACCESS_KEY is empty or has spaces in it"));
        }
        Ok(Settings {
            endpoint: format!("{}://{host}", u.scheme()),
            host,
            bucket: bucket.into(),
            region: region.into(),
            access_key: access_key.into(),
            secret: secret.into(),
        })
    }

    /// MACHINE_BACKUP_S3_ENDPOINT, _BUCKET, _REGION (us-east-1), and the keys from the
    /// secret store: MACHINE_BACKUP_S3_ACCESS_KEY_ID and _SECRET_ACCESS_KEY (or `_FILE`).
    pub fn from_env(store: &dyn SecretStore, var: &dyn Fn(&str) -> String) -> Result<Settings, String> {
        Settings::from_env_named(MACHINES, store, var)
    }

    /// `from_env`, from the settings whose names start with `name` (`SERVER_BACKUP_S3`).
    pub fn from_env_named(name: &str, store: &dyn SecretStore, var: &dyn Fn(&str) -> String) -> Result<Settings, String> {
        let endpoint = var(&format!("{name}_ENDPOINT"));
        if endpoint.trim().is_empty() {
            return Err(format!("{name}_ENDPOINT is needed with {name}_BUCKET, e.g. https://s3.<region>.amazonaws.com"));
        }
        let get = |k: &str| -> Result<String, String> {
            let v = store.get(k).map_err(|e| e.to_string())?.ok_or(format!("{k} (or {k}_FILE) is needed with {name}_BUCKET"))?;
            Ok(v.expose().trim().to_string())
        };
        let region = Some(var(&format!("{name}_REGION"))).filter(|r| !r.trim().is_empty()).unwrap_or("us-east-1".into());
        let secret = get(&format!("{name}_SECRET_ACCESS_KEY"))?;
        crate::secrets::redact::register(&secret);
        let key = get(&format!("{name}_ACCESS_KEY_ID"))?;
        Settings::named(name, &endpoint, var(&format!("{name}_BUCKET")).trim(), &region, &key, &secret)
    }
}

/// The text of the first `<tag>` in `xml`, unescaped.
pub fn tag(xml: &str, name: &str) -> Option<String> {
    let open = format!("<{name}>");
    let at = xml.find(&open)? + open.len();
    let end = xml[at..].find(&format!("</{name}>"))? + at;
    Some(
        xml[at..end]
            .replace("&quot;", "\"")
            .replace("&apos;", "'")
            .replace("&lt;", "<")
            .replace("&gt;", ">")
            .replace("&amp;", "&"),
    )
}

/// One version of an object, or a delete marker, as a listing of versions gives it.
#[derive(Clone, Debug, PartialEq)]
pub struct ObjectVersion {
    pub key: String,
    pub version: String,
    pub latest: bool,
    pub marker: bool,
    /// `LastModified`, in ms: when the store took it, which no writer can set.
    pub modified: Option<i64>,
}

/// The `<Version>`s and `<DeleteMarker>`s of a `ListVersionsResult`, in its order.
fn listed_versions(xml: &str) -> Vec<ObjectVersion> {
    let mut out = Vec::new();
    let mut rest = xml;
    loop {
        let (v, d) = (rest.find("<Version>"), rest.find("<DeleteMarker>"));
        let (at, marker) = match (v, d) {
            (Some(v), Some(d)) => (v.min(d), d < v),
            (Some(v), None) => (v, false),
            (None, Some(d)) => (d, true),
            (None, None) => return out,
        };
        let (open, close) = if marker { ("<DeleteMarker>", "</DeleteMarker>") } else { ("<Version>", "</Version>") };
        let start = at + open.len();
        let end = rest[start..].find(close).map_or(rest.len(), |e| start + e);
        let item = &rest[start..end];
        if let (Some(key), Some(version)) = (tag(item, "Key"), tag(item, "VersionId")) {
            let modified = tag(item, "LastModified").and_then(|t| chrono::DateTime::parse_from_rfc3339(&t).ok()).map(|t| t.timestamp_millis());
            out.push(ObjectVersion { key, version, latest: tag(item, "IsLatest").as_deref() == Some("true"), marker, modified });
        }
        rest = &rest[end..];
    }
}

/// S3's error body in a few words, never the request. `what` names the store.
fn refusal(what: &str, status: reqwest::StatusCode, body: &str) -> String {
    let code = tag(body, "Code").unwrap_or_else(|| status.canonical_reason().unwrap_or("error").into());
    let msg = tag(body, "Message").map(|m| format!(": {m}")).unwrap_or_default();
    crate::audit::clip(&format!("{what} refused ({}): {code}{msg}", status.as_u16()), 300)
}

pub struct S3 {
    s: Settings,
    http: reqwest::Client,
    /// Bytes per part of a multipart upload.
    pub part_size: usize,
    /// What errors call the store.
    what: &'static str,
}

impl std::fmt::Debug for S3 {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        self.s.fmt(f)
    }
}

impl S3 {
    pub fn new(s: Settings) -> Result<S3, String> {
        let http = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(10))
            .read_timeout(SILENCE)
            .user_agent(concat!("superbot-botd/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|e| format!("backup store client: {e}"))?;
        Ok(S3 { s, http, part_size: PART_SIZE, what: "the backup store" })
    }

    /// The same client, with errors calling the store `what` ("the audit archive").
    pub fn called(mut self, what: &'static str) -> S3 {
        self.what = what;
        self
    }

    async fn send(&self, method: Method, key: Option<&str>, query: &[(&str, &str)], body: Vec<u8>) -> Result<reqwest::Response, String> {
        self.send_with(method, key, query, &[], body).await
    }

    /// `send`, with more headers (lowercase names), all of them signed.
    async fn send_with(&self, method: Method, key: Option<&str>, query: &[(&str, &str)], extra: &[(&str, String)], body: Vec<u8>) -> Result<reqwest::Response, String> {
        let uri = match key {
            None => format!("/{}", encode(&self.s.bucket, false)),
            Some(k) => format!("/{}/{}", encode(&self.s.bucket, false), encode(k, true)),
        };
        let q = canonical_query(query);
        let payload = sha256_hex(&body);
        let amz_date = chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
        let mut headers = vec![("host", self.s.host.as_str()), ("x-amz-content-sha256", payload.as_str()), ("x-amz-date", amz_date.as_str())];
        headers.extend(extra.iter().map(|(k, v)| (*k, v.as_str())));
        let scope = Scope { amz_date: &amz_date, region: &self.s.region, service: "s3" };
        let (signed, sig) = sigv4::signature(&self.s.secret, &scope, method.as_str(), &uri, &q, &headers, &payload);
        let auth = scope.authorization(&self.s.access_key, &signed, &sig);
        let url = if q.is_empty() { format!("{}{uri}", self.s.endpoint) } else { format!("{}{uri}?{q}", self.s.endpoint) };
        let mut req = self.http.request(method, url).header("x-amz-content-sha256", &payload).header("x-amz-date", &amz_date).header("authorization", auth);
        for (k, v) in extra {
            req = req.header(*k, v);
        }
        let res = req.body(body).send().await.map_err(|e| format!("couldn't reach {}: {}", self.what, e.without_url()))?;
        if res.status().is_success() {
            return Ok(res);
        }
        let status = res.status();
        let text = res.text().await.unwrap_or_default();
        Err(refusal(self.what, status, &text))
    }

    async fn text(&self, res: reqwest::Response) -> Result<String, String> {
        res.text().await.map_err(|e| format!("{}'s answer was cut off: {}", self.what, e.without_url()))
    }

    /// A small object in one request, with more headers (lowercase names, signed):
    /// Object Lock retention, a checksum, metadata. The answer's headers.
    pub async fn put_with(&self, key: &str, body: Vec<u8>, headers: &[(&str, String)]) -> Result<reqwest::header::HeaderMap, String> {
        self.send_with(Method::PUT, Some(key), &[], headers, body).await.map(|r| r.headers().clone())
    }

    /// An object's headers, of one version when given.
    pub async fn head(&self, key: &str, version: Option<&str>) -> Result<reqwest::header::HeaderMap, String> {
        let q: Vec<(&str, &str)> = version.map(|v| ("versionId", v)).into_iter().collect();
        self.send(Method::HEAD, Some(key), &q, Vec::new()).await.map(|r| r.headers().clone())
    }

    /// The bucket's Object Lock configuration (`GET ?object-lock`), or None when it has
    /// none: Object Lock was never turned on.
    pub async fn object_lock(&self) -> Result<Option<String>, String> {
        match self.send(Method::GET, None, &[("object-lock", "")], Vec::new()).await {
            Ok(res) => Ok(Some(self.text(res).await?)),
            Err(e) if e.contains("ObjectLockConfigurationNotFound") || e.contains("(404)") || e.contains("(501)") => Ok(None),
            Err(e) => Err(format!("{e} (botd asks whether the bucket is write-once: s3:GetBucketObjectLockConfiguration)")),
        }
    }

    /// A small object in one request.
    pub async fn put(&self, key: &str, body: Vec<u8>) -> Result<(), String> {
        self.send(Method::PUT, Some(key), &[], body).await.map(drop)
    }

    /// The object, to read as a stream.
    pub async fn get(&self, key: &str) -> Result<reqwest::Response, String> {
        self.send(Method::GET, Some(key), &[], Vec::new()).await
    }

    /// Succeeds if it is already gone.
    pub async fn delete(&self, key: &str) -> Result<(), String> {
        match self.send(Method::DELETE, Some(key), &[], Vec::new()).await {
            Ok(_) => Ok(()),
            Err(e) if e.contains("(404)") => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// Every key under `prefix`, a page of up to 1,000 at a time.
    pub async fn list(&self, prefix: &str) -> Result<Vec<String>, String> {
        let mut keys = Vec::new();
        let mut token: Option<String> = None;
        loop {
            let mut q = vec![("list-type", "2"), ("prefix", prefix)];
            if let Some(t) = token.as_deref() {
                q.push(("continuation-token", t));
            }
            let res = self.send(Method::GET, None, &q, Vec::new()).await?;
            let xml = self.text(res).await?;
            keys.extend(xml.split("<Contents>").skip(1).filter_map(|c| tag(c, "Key")));
            token = match (tag(&xml, "IsTruncated").as_deref(), tag(&xml, "NextContinuationToken")) {
                (Some("true"), Some(t)) if !t.is_empty() && token.as_deref() != Some(t.as_str()) => Some(t),
                (Some("true"), _) => return Err("the backup store's listing was cut off without a way to go on".into()),
                _ => return Ok(keys),
            };
        }
    }

    /// Whether the bucket keeps old versions (versioning on, or suspended with some kept),
    /// so a plain delete leaves the bytes behind a delete marker. A store with no
    /// versioning at all says it doesn't implement it.
    pub async fn versioned(&self) -> Result<bool, String> {
        match self.send(Method::GET, None, &[("versioning", "")], Vec::new()).await {
            Ok(res) => Ok(matches!(tag(&self.text(res).await?, "Status").as_deref(), Some("Enabled" | "Suspended"))),
            Err(e) if e.contains("(501)") || e.contains("NotImplemented") => Ok(false),
            Err(e) => Err(format!("{e} (botd asks whether the bucket keeps old versions: s3:GetBucketVersioning)")),
        }
    }

    /// Every version and delete marker of every key under `prefix`, as `(key, version id)`.
    pub async fn versions(&self, prefix: &str) -> Result<Vec<(String, String)>, String> {
        Ok(self.object_versions(prefix).await?.into_iter().map(|v| (v.key, v.version)).collect())
    }

    /// Every version and delete marker of every key under `prefix`, in the store's order:
    /// by key, newest first within one.
    pub async fn object_versions(&self, prefix: &str) -> Result<Vec<ObjectVersion>, String> {
        let mut out = Vec::new();
        let mut after: Option<(String, String)> = None;
        loop {
            let mut q = vec![("versions", ""), ("prefix", prefix)];
            if let Some((k, v)) = after.as_ref() {
                q.push(("key-marker", k));
                q.push(("version-id-marker", v));
            }
            let res = self.send(Method::GET, None, &q, Vec::new()).await?;
            let xml = self.text(res).await?;
            out.extend(listed_versions(&xml));
            let next = (tag(&xml, "NextKeyMarker"), tag(&xml, "NextVersionIdMarker"));
            after = match (tag(&xml, "IsTruncated").as_deref(), next) {
                (Some("true"), (Some(k), Some(v))) if !k.is_empty() && after.as_ref() != Some(&(k.clone(), v.clone())) => Some((k, v)),
                (Some("true"), _) => return Err(format!("{}'s listing of versions was cut off without a way to go on", self.what)),
                _ => return Ok(out),
            };
        }
    }

    /// One version of an object (the current one when `version` is None), to read.
    pub async fn get_version(&self, key: &str, version: Option<&str>) -> Result<reqwest::Response, String> {
        let q: Vec<(&str, &str)> = version.map(|v| ("versionId", v)).into_iter().collect();
        self.send(Method::GET, Some(key), &q, Vec::new()).await
    }

    /// Deletes one version for good, or a delete marker. Succeeds if it is already gone.
    pub async fn delete_version(&self, key: &str, version_id: &str) -> Result<(), String> {
        match self.send(Method::DELETE, Some(key), &[("versionId", version_id)], Vec::new()).await {
            Ok(_) => Ok(()),
            Err(e) if e.contains("(404)") => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// Makes the bucket, or finds it made (the end-to-end test's own store).
    #[cfg(test)]
    pub async fn create_bucket(&self) -> Result<(), String> {
        match self.send(Method::PUT, None, &[], Vec::new()).await {
            Ok(_) => Ok(()),
            Err(e) if e.contains("BucketAlreadyOwnedByYou") => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// Aborts unfinished multipart uploads of exactly `key` started before `before` (ms),
    /// such as one cut off by a restart. Returns how many went.
    pub async fn abort_unfinished(&self, key: &str, before: i64) -> Result<usize, String> {
        self.abort_where(key, before, |k| k == key).await
    }

    /// `abort_unfinished`, for every key under `prefix`.
    pub async fn abort_unfinished_under(&self, prefix: &str, before: i64) -> Result<usize, String> {
        self.abort_where(prefix, before, |k| k.starts_with(prefix)).await
    }

    async fn abort_where(&self, prefix: &str, before: i64, of: impl Fn(&str) -> bool) -> Result<usize, String> {
        let res = self.send(Method::GET, None, &[("prefix", prefix), ("uploads", "")], Vec::new()).await?;
        let xml = self.text(res).await?;
        let mut gone = 0;
        for u in xml.split("<Upload>").skip(1) {
            let started = tag(u, "Initiated").and_then(|t| chrono::DateTime::parse_from_rfc3339(&t).ok()).map(|t| t.timestamp_millis());
            if let (Some(k), Some(id)) = (tag(u, "Key"), tag(u, "UploadId"))
                && of(&k)
                && started.is_some_and(|s| s < before)
            {
                self.send(Method::DELETE, Some(&k), &[("uploadId", &id)], Vec::new()).await?;
                gone += 1;
            }
        }
        Ok(gone)
    }

    /// Starts writing `key` in parts.
    pub async fn upload(&self, key: &str) -> Result<Upload<'_>, String> {
        let res = self.send(Method::POST, Some(key), &[("uploads", "")], Vec::new()).await?;
        let xml = self.text(res).await?;
        let id = tag(&xml, "UploadId").filter(|i| !i.is_empty()).ok_or("the backup store didn't start the upload")?;
        Ok(Upload {
            s3: self,
            key: key.into(),
            id,
            buf: Vec::new(),
            parts: Vec::new(),
            size: 0,
            hash: digest::Context::new(&digest::SHA256),
        })
    }
}

/// An object written in parts, and the size and SHA-256 of what was written.
pub struct Upload<'a> {
    s3: &'a S3,
    key: String,
    id: String,
    buf: Vec<u8>,
    parts: Vec<(usize, String)>,
    size: u64,
    hash: digest::Context,
}

impl Upload<'_> {
    async fn part(&mut self) -> Result<(), String> {
        let n = self.parts.len() + 1;
        let body = std::mem::take(&mut self.buf);
        let res = self
            .s3
            .send(Method::PUT, Some(&self.key), &[("partNumber", &n.to_string()), ("uploadId", &self.id)], body)
            .await?;
        let etag = res
            .headers()
            .get("etag")
            .and_then(|e| e.to_str().ok())
            .map(String::from)
            .ok_or("the backup store didn't take a part")?;
        self.parts.push((n, etag));
        Ok(())
    }

    pub async fn write(&mut self, b: &[u8]) -> Result<(), String> {
        self.hash.update(b);
        self.size += b.len() as u64;
        self.buf.extend_from_slice(b);
        while self.buf.len() >= self.s3.part_size {
            let rest = self.buf.split_off(self.s3.part_size);
            self.part().await?;
            self.buf = rest;
        }
        Ok(())
    }

    /// Ends the upload: the object's size and SHA-256. If that fails, the parts go.
    pub async fn finish(mut self) -> Result<(u64, String), String> {
        match self.complete().await {
            Ok(()) => Ok((self.size, hex(self.hash.finish().as_ref()))),
            Err(e) => {
                self.abort().await;
                Err(e)
            }
        }
    }

    async fn complete(&mut self) -> Result<(), String> {
        if !self.buf.is_empty() || self.parts.is_empty() {
            self.part().await?;
        }
        let mut xml = String::from("<CompleteMultipartUpload>");
        for (n, etag) in &self.parts {
            let etag = etag.replace('&', "&amp;").replace('"', "&quot;");
            xml.push_str(&format!("<Part><PartNumber>{n}</PartNumber><ETag>{etag}</ETag></Part>"));
        }
        xml.push_str("</CompleteMultipartUpload>");
        let res = self.s3.send(Method::POST, Some(&self.key), &[("uploadId", &self.id)], xml.into_bytes()).await?;
        // S3 may answer 200 and still fail the upload.
        let body = self.s3.text(res).await?;
        if body.contains("<Error>") {
            return Err(refusal(self.s3.what, reqwest::StatusCode::OK, &body));
        }
        Ok(())
    }

    /// Drops the parts written so far.
    pub async fn abort(self) {
        let _ = self.s3.send(Method::DELETE, Some(&self.key), &[("uploadId", &self.id)], Vec::new()).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settings_are_checked() {
        let ok = Settings::new("https://s3.example.com", "my-backups", "us-east-1", "AKID", "secret").unwrap();
        assert_eq!((ok.endpoint.as_str(), ok.host.as_str()), ("https://s3.example.com", "s3.example.com"));
        assert!(!format!("{ok:?}").contains("secret\""), "{ok:?}");
        let local = Settings::new("http://127.0.0.1:9000/", "b-1", "auto", "AKID", "secret").unwrap();
        assert_eq!(local.host, "127.0.0.1:9000");
        for (endpoint, bucket, region, key, secret) in [
            ("http://s3.example.com", "bucket", "us-east-1", "AKID", "s"),
            ("https://u:p@s3.example.com", "bucket", "us-east-1", "AKID", "s"),
            ("https://s3.example.com/path", "bucket", "us-east-1", "AKID", "s"),
            ("https://s3.example.com", "No_Caps", "us-east-1", "AKID", "s"),
            ("https://s3.example.com", "ab", "us-east-1", "AKID", "s"),
            ("https://s3.example.com", "bucket", "us east", "AKID", "s"),
            ("https://s3.example.com", "bucket", "us-east-1", "", "s"),
            ("https://s3.example.com", "bucket", "us-east-1", "AKID", "s s"),
        ] {
            assert!(Settings::new(endpoint, bucket, region, key, secret).is_err(), "{endpoint} {bucket} {region}");
        }
        let e = Settings::named("SERVER_BACKUP_S3", "http://s3.example.com", "bucket", "us-east-1", "AKID", "s").unwrap_err();
        assert!(e.starts_with("SERVER_BACKUP_S3_ENDPOINT "), "{e}");
        let e = Settings::named("SERVER_BACKUP_S3", "https://s3.example.com", "bucket", "us-east-1", "AKID", "s s").unwrap_err();
        assert!(e.starts_with("SERVER_BACKUP_S3_SECRET_ACCESS_KEY "), "{e}");
    }

    #[test]
    fn reads_tags() {
        assert_eq!(tag("<a><UploadId>x&amp;y</UploadId></a>", "UploadId").as_deref(), Some("x&y"));
        assert_eq!(tag("<a></a>", "UploadId"), None);
        let r = refusal("the backup store", reqwest::StatusCode::FORBIDDEN, "<Error><Code>AccessDenied</Code><Message>no</Message></Error>");
        assert_eq!(r, "the backup store refused (403): AccessDenied: no");
    }

    #[test]
    fn reads_versions_in_order() {
        let xml = "<ListVersionsResult><Name>b</Name>\
            <DeleteMarker><Key>a&amp;b</Key><VersionId>3</VersionId><IsLatest>true</IsLatest></DeleteMarker>\
            <Version><Key>a&amp;b</Key><VersionId>2</VersionId><IsLatest>false</IsLatest></Version>\
            <Version><Key>a&amp;b</Key><VersionId>1</VersionId><IsLatest>false</IsLatest><LastModified>2026-11-23T07:00:00.000Z</LastModified></Version>\
            <Version><Key>c</Key><VersionId>null</VersionId><IsLatest>true</IsLatest></Version></ListVersionsResult>";
        let v = listed_versions(xml);
        let got: Vec<(&str, &str, bool, bool)> = v.iter().map(|v| (v.key.as_str(), v.version.as_str(), v.latest, v.marker)).collect();
        assert_eq!(got, [("a&b", "3", true, true), ("a&b", "2", false, false), ("a&b", "1", false, false), ("c", "null", true, false)]);
        assert_eq!(v.iter().map(|v| v.modified).collect::<Vec<_>>(), [None, None, Some(1_795_417_200_000), None]);
        assert!(listed_versions("<ListVersionsResult></ListVersionsResult>").is_empty());
    }
}
