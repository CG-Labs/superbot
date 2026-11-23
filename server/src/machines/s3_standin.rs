//! A stand-in for an S3-compatible store, for tests: plain HTTP on loopback, path-style
//! buckets, and every request's SigV4 signature checked against the one key it knows.
//! Objects and multipart uploads live in memory, and every call is recorded.

use super::s3::{self, Settings};
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, State};
use axum::http::{HeaderMap, Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

pub const BUCKET: &str = "backups";
pub const ACCESS_KEY: &str = "AKIDSTANDIN";
pub const SECRET: &str = "standin-secret-key-0123456789";

/// One version's size, `x-amz-meta-*` headers and lock.
pub type Stored = (usize, Vec<(String, String)>, Option<(String, String)>);

/// An unfinished multipart upload: its key, when it began, and its parts.
type Unfinished = (String, i64, BTreeMap<u32, Vec<u8>>);

#[derive(Default)]
pub struct World {
    pub objects: BTreeMap<String, Vec<u8>>,
    /// By upload id.
    uploads: BTreeMap<String, Unfinished>,
    /// `METHOD path?query`, in order.
    pub calls: Vec<String>,
    /// The next request with this method fails with this status.
    pub fail: Option<(String, u16)>,
    /// Keys per listing page; S3's 1,000 when unset.
    pub page: Option<usize>,
    /// The bucket's versioning status (`Enabled`, `Suspended`), if it was ever turned on.
    pub versioning: Option<&'static str>,
    /// Old versions and delete markers, `(key, version id, is a marker)`. Current objects
    /// are listed as version `current`.
    pub old: Vec<(String, String, bool)>,
    /// The bucket's Object Lock configuration (`GET ?object-lock`), if it has one.
    pub object_lock: Option<String>,
    /// Takes the lock headers and keeps nothing, as a store without Object Lock might.
    pub ignore_lock: bool,
    /// Each current object's lock: `(mode, retain until)`.
    pub locks: BTreeMap<String, (String, String)>,
    /// Each current object's `x-amz-meta-*` headers and its version id.
    pub meta: BTreeMap<String, (Vec<(String, String)>, String)>,
    /// Every version written with a checksum: `(key, version)` to its size, metadata and lock.
    pub versions: BTreeMap<(String, String), Stored>,
    /// Those versions' bodies, and each key's version ids in the order written.
    pub bodies: BTreeMap<(String, String), Vec<u8>>,
    pub history: BTreeMap<String, Vec<String>>,
    next: u32,
}

impl World {
    /// What overwriting or deleting `key` leaves behind in a versioned bucket.
    fn keep(&mut self, key: &str, marker: bool) {
        if self.versioning != Some("Enabled") {
            return;
        }
        if self.objects.contains_key(key) {
            self.next += 1;
            self.old.push((key.into(), format!("v{}", self.next), false));
        }
        if marker {
            self.next += 1;
            self.old.push((key.into(), format!("v{}", self.next), true));
        }
    }
}

pub struct StandIn {
    pub url: String,
    pub world: Arc<Mutex<World>>,
}

impl StandIn {
    pub async fn start() -> StandIn {
        let world = Arc::new(Mutex::new(World::default()));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
        let router = axum::Router::new()
            .fallback(handle)
            .layer(DefaultBodyLimit::disable())
            .with_state(world.clone());
        tokio::spawn(async move { axum::serve(listener, router).await });
        StandIn { url, world }
    }

    pub fn settings(&self) -> Settings {
        Settings::new(&self.url, BUCKET, "us-east-1", ACCESS_KEY, SECRET).unwrap()
    }

    pub fn w(&self) -> std::sync::MutexGuard<'_, World> {
        self.world.lock().unwrap()
    }

    /// Keys stored, in order.
    pub fn keys(&self) -> Vec<String> {
        self.w().objects.keys().cloned().collect()
    }

    /// The keys of unfinished multipart uploads.
    pub fn unfinished(&self) -> Vec<String> {
        self.w().uploads.values().map(|(k, _, _)| k.clone()).collect()
    }

    /// Leaves an upload of `key` unfinished, begun `ago` ms back, as a writer that stopped would.
    pub fn leave_unfinished(&self, key: &str, ago: i64) {
        let mut w = self.w();
        w.next += 1;
        let id = format!("upload-{}", w.next);
        w.uploads.insert(id, (key.into(), crate::db::now() - ago, BTreeMap::from([(1, b"half".to_vec())])));
    }
}

fn xml(status: StatusCode, body: String) -> Response {
    (status, [("content-type", "application/xml")], body).into_response()
}

fn error(status: StatusCode, code: &str) -> Response {
    xml(status, format!("<?xml version=\"1.0\"?><Error><Code>{code}</Code><Message>stand-in says no</Message></Error>"))
}

/// Whether the request carries a good signature by our key for its body.
fn signed(method: &Method, uri: &Uri, headers: &HeaderMap, body: &[u8]) -> bool {
    let h = |k: &str| headers.get(k).and_then(|v| v.to_str().ok()).unwrap_or_default().to_string();
    let auth = h("authorization");
    let Some(rest) = auth.strip_prefix("AWS4-HMAC-SHA256 ") else { return false };
    let field = |name: &str| {
        rest.split(", ")
            .find_map(|p| p.strip_prefix(&format!("{name}=")))
            .unwrap_or_default()
            .to_string()
    };
    let credential = field("Credential");
    let mut c = credential.split('/');
    let (key, date, region) = (c.next().unwrap_or_default(), c.next().unwrap_or_default(), c.next().unwrap_or_default());
    let amz_date = h("x-amz-date");
    if key != ACCESS_KEY || amz_date.len() != 16 || !amz_date.starts_with(date) {
        return false;
    }
    let payload = h("x-amz-content-sha256");
    if payload != s3::sha256_hex(body) {
        return false;
    }
    let names = field("SignedHeaders");
    let values: Vec<(String, String)> = names.split(';').map(|n| (n.to_string(), h(n))).collect();
    let pairs: Vec<(&str, &str)> = values.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    let query: Vec<(String, String)> = url::form_urlencoded::parse(uri.query().unwrap_or_default().as_bytes()).into_owned().collect();
    let q: Vec<(&str, &str)> = query.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    let scope = crate::sigv4::Scope { amz_date: &amz_date, region, service: "s3" };
    let (_, sig) = crate::sigv4::signature(SECRET, &scope, method.as_str(), uri.path(), &s3::canonical_query(&q), &pairs, &payload);
    !names.is_empty() && names.contains("host") && sig == field("Signature")
}

async fn handle(State(world): State<Arc<Mutex<World>>>, method: Method, uri: Uri, headers: HeaderMap, body: Bytes) -> Response {
    let mut w = world.lock().unwrap();
    w.calls.push(format!("{method} {}", uri.path_and_query().map(|p| p.as_str()).unwrap_or_default()));
    if !signed(&method, &uri, &headers, &body) {
        return error(StatusCode::FORBIDDEN, "SignatureDoesNotMatch");
    }
    if let Some((m, status)) = w.fail.clone()
        && m == method.as_str()
    {
        w.fail = None;
        return error(StatusCode::from_u16(status).unwrap(), "InternalError");
    }
    let query: BTreeMap<String, String> = url::form_urlencoded::parse(uri.query().unwrap_or_default().as_bytes()).into_owned().collect();
    let path = percent_decode(uri.path());
    let Some(rest) = path.strip_prefix(&format!("/{BUCKET}")) else {
        return error(StatusCode::NOT_FOUND, "NoSuchBucket");
    };
    let key = rest.trim_start_matches('/').to_string();
    match (method.as_str(), key.is_empty()) {
        ("GET", true) if query.contains_key("uploads") => {
            let prefix = query.get("prefix").cloned().unwrap_or_default();
            let mut out = String::from("<ListMultipartUploadsResult>");
            for (id, (k, at, _)) in w.uploads.iter().filter(|(_, (k, _, _))| k.starts_with(&prefix)) {
                let at = chrono::DateTime::from_timestamp_millis(*at).unwrap_or_default().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
                out.push_str(&format!("<Upload><Key>{k}</Key><UploadId>{id}</UploadId><Initiated>{at}</Initiated></Upload>"));
            }
            out.push_str("</ListMultipartUploadsResult>");
            xml(StatusCode::OK, out)
        }
        ("GET", true) if query.contains_key("object-lock") => match w.object_lock.clone() {
            Some(c) => xml(StatusCode::OK, c),
            None => error(StatusCode::NOT_FOUND, "ObjectLockConfigurationNotFoundError"),
        },
        ("GET", true) if query.contains_key("versioning") => {
            let status = w.versioning.map(|s| format!("<Status>{s}</Status>")).unwrap_or_default();
            xml(StatusCode::OK, format!("<VersioningConfiguration>{status}</VersioningConfiguration>"))
        }
        ("GET", true) if query.contains_key("versions") => {
            let prefix = query.get("prefix").cloned().unwrap_or_default();
            let after = (query.get("key-marker").cloned().unwrap_or_default(), query.get("version-id-marker").cloned().unwrap_or_default());
            let page = w.page.unwrap_or(1000);
            // Keys written with a checksum list their real versions, newest first, as S3
            // does; others list the current object as `current`, then what `old` holds.
            let mut found: Vec<(String, String, bool, bool)> = Vec::new();
            let keys: std::collections::BTreeSet<&String> = w.objects.keys().chain(w.history.keys()).chain(w.old.iter().map(|(k, _, _)| k)).collect();
            for k in keys.into_iter().filter(|k| k.starts_with(&prefix)) {
                match w.history.get(k) {
                    Some(written) => {
                        let gone = !w.objects.contains_key(k);
                        let markers: Vec<&(String, String, bool)> = w.old.iter().filter(|(o, _, m)| o == k && *m).collect();
                        for (i, (_, v, _)) in markers.iter().rev().enumerate() {
                            found.push((k.clone(), v.clone(), true, gone && i == 0));
                        }
                        for (i, v) in written.iter().rev().enumerate() {
                            found.push((k.clone(), v.clone(), false, !gone && i == 0));
                        }
                    }
                    None => {
                        let mut mine: Vec<(String, String, bool, bool)> = w.old.iter().filter(|(o, _, _)| o == k).map(|(o, v, m)| (o.clone(), v.clone(), *m, false)).collect();
                        if w.objects.contains_key(k) {
                            mine.push((k.clone(), "current".into(), false, true));
                        }
                        mine.sort();
                        found.extend(mine);
                    }
                }
            }
            if !after.0.is_empty()
                && let Some(i) = found.iter().position(|(k, v, _, _)| (k, v) == (&after.0, &after.1))
            {
                found.drain(..=i);
            }
            let mut out = String::from("<ListVersionsResult>");
            for (k, v, marker, latest) in found.iter().take(page) {
                let tag = if *marker { "DeleteMarker" } else { "Version" };
                out.push_str(&format!("<{tag}><Key>{}</Key><VersionId>{v}</VersionId><IsLatest>{latest}</IsLatest></{tag}>", k.replace('&', "&amp;")));
            }
            if found.len() > page {
                let (k, v, _, _) = &found[page - 1];
                out.push_str(&format!("<IsTruncated>true</IsTruncated><NextKeyMarker>{}</NextKeyMarker><NextVersionIdMarker>{v}</NextVersionIdMarker>", k.replace('&', "&amp;")));
            } else {
                out.push_str("<IsTruncated>false</IsTruncated>");
            }
            out.push_str("</ListVersionsResult>");
            xml(StatusCode::OK, out)
        }
        ("GET", true) => {
            let prefix = query.get("prefix").cloned().unwrap_or_default();
            let after = query.get("continuation-token").cloned().unwrap_or_default();
            let page = w.page.unwrap_or(1000);
            let found: Vec<(&String, &Vec<u8>)> = w.objects.iter().filter(|(k, _)| k.starts_with(&prefix) && **k > after).collect();
            let mut out = String::from("<ListBucketResult>");
            for (k, v) in found.iter().take(page) {
                out.push_str(&format!("<Contents><Key>{}</Key><Size>{}</Size></Contents>", k.replace('&', "&amp;"), v.len()));
            }
            if found.len() > page {
                out.push_str(&format!("<IsTruncated>true</IsTruncated><NextContinuationToken>{}</NextContinuationToken>", found[page - 1].0.replace('&', "&amp;")));
            } else {
                out.push_str("<IsTruncated>false</IsTruncated>");
            }
            out.push_str("</ListBucketResult>");
            xml(StatusCode::OK, out)
        }
        ("HEAD", false) => match query.get("versionId").cloned().or_else(|| w.meta.get(&key).map(|(_, v)| v.clone())).and_then(|v| w.versions.get(&(key.clone(), v.clone())).map(|s| (v, s.clone()))) {
            Some((version, (size, meta, lock))) => {
                let mut h = vec![("content-length".to_string(), size.to_string()), ("x-amz-version-id".to_string(), version)];
                h.extend(meta);
                if let Some((mode, until)) = lock {
                    h.push(("x-amz-object-lock-mode".into(), mode));
                    h.push(("x-amz-object-lock-retain-until-date".into(), until));
                }
                let mut res = StatusCode::OK.into_response();
                for (k, v) in h {
                    res.headers_mut().insert(axum::http::HeaderName::from_bytes(k.as_bytes()).unwrap(), v.parse().unwrap());
                }
                res
            }
            None => StatusCode::NOT_FOUND.into_response(),
        },
        ("PUT", false) if headers.contains_key("x-amz-checksum-sha256") || headers.contains_key("x-amz-object-lock-mode") => {
            use base64::Engine;
            let h = |k: &str| headers.get(k).and_then(|v| v.to_str().ok()).map(String::from);
            let sum = base64::engine::general_purpose::STANDARD.encode(aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, &body).as_ref());
            if h("x-amz-checksum-sha256").as_deref() != Some(sum.as_str()) {
                return error(StatusCode::BAD_REQUEST, "BadDigest");
            }
            let lock = match (w.object_lock.clone(), h("x-amz-object-lock-mode"), h("x-amz-object-lock-retain-until-date")) {
                _ if w.ignore_lock => None,
                (Some(_), Some(mode), Some(until)) => Some((mode, until)),
                (Some(c), None, None) => match (s3::tag(&c, "Mode"), s3::tag(&c, "Days").and_then(|d| d.parse::<i64>().ok())) {
                    (Some(mode), Some(days)) => Some((mode, (chrono::Utc::now() + chrono::Duration::days(days)).to_rfc3339_opts(chrono::SecondsFormat::Millis, true))),
                    _ => None,
                },
                (None, Some(_), _) => return error(StatusCode::BAD_REQUEST, "InvalidRequest"),
                _ => None,
            };
            w.keep(&key, false);
            w.next += 1;
            let version = format!("v{}", w.next);
            let meta: Vec<(String, String)> = headers.iter().filter(|(k, _)| k.as_str().starts_with("x-amz-meta-")).map(|(k, v)| (k.to_string(), v.to_str().unwrap_or_default().to_string())).collect();
            w.versions.insert((key.clone(), version.clone()), (body.len(), meta.clone(), lock.clone()));
            w.bodies.insert((key.clone(), version.clone()), body.to_vec());
            w.history.entry(key.clone()).or_default().push(version.clone());
            w.meta.insert(key.clone(), (meta, version.clone()));
            match lock {
                Some(l) => w.locks.insert(key.clone(), l),
                None => w.locks.remove(&key),
            };
            w.objects.insert(key, body.to_vec());
            let mut res = StatusCode::OK.into_response();
            if w.versioning == Some("Enabled") {
                res.headers_mut().insert("x-amz-version-id", version.parse().unwrap());
            }
            res
        }
        ("PUT", false) => match (query.get("partNumber"), query.get("uploadId")) {
            (Some(n), Some(id)) => {
                let Some((_, _, parts)) = w.uploads.get_mut(id) else { return error(StatusCode::NOT_FOUND, "NoSuchUpload") };
                parts.insert(n.parse().unwrap_or(0), body.to_vec());
                (StatusCode::OK, [("etag", format!("\"{}\"", s3::sha256_hex(&body)))]).into_response()
            }
            _ => {
                w.keep(&key, false);
                w.objects.insert(key, body.to_vec());
                StatusCode::OK.into_response()
            }
        },
        ("POST", false) if query.contains_key("uploads") => {
            w.next += 1;
            let id = format!("upload-{}", w.next);
            w.uploads.insert(id.clone(), (key.clone(), crate::db::now(), BTreeMap::new()));
            xml(StatusCode::OK, format!("<InitiateMultipartUploadResult><Key>{key}</Key><UploadId>{id}</UploadId></InitiateMultipartUploadResult>"))
        }
        ("POST", false) if query.contains_key("uploadId") => {
            let id = &query["uploadId"];
            let Some((k, _, parts)) = w.uploads.remove(id) else { return error(StatusCode::NOT_FOUND, "NoSuchUpload") };
            let text = String::from_utf8_lossy(&body).to_string();
            let mut data = Vec::new();
            for p in text.split("<Part>").skip(1) {
                let n: u32 = s3::tag(p, "PartNumber").and_then(|n| n.parse().ok()).unwrap_or(0);
                let etag = s3::tag(p, "ETag").unwrap_or_default();
                match parts.get(&n) {
                    Some(b) if etag == format!("\"{}\"", s3::sha256_hex(b)) => data.extend_from_slice(b),
                    _ => return error(StatusCode::BAD_REQUEST, "InvalidPart"),
                }
            }
            w.keep(&k, false);
            w.objects.insert(k, data);
            xml(StatusCode::OK, "<CompleteMultipartUploadResult></CompleteMultipartUploadResult>".into())
        }
        ("DELETE", false) if query.contains_key("uploadId") => {
            w.uploads.remove(&query["uploadId"]);
            StatusCode::NO_CONTENT.into_response()
        }
        ("DELETE", false) if query.contains_key("versionId") => {
            let v = &query["versionId"];
            let locked = w.versions.get(&(key.clone(), v.clone())).is_some_and(|(_, _, l)| l.is_some());
            if locked || (v == "current" && w.locks.contains_key(&key)) {
                return error(StatusCode::FORBIDDEN, "AccessDenied");
            }
            if v == "current" {
                w.objects.remove(&key);
            } else {
                w.old.retain(|(k, id, _)| !(*k == key && id == v));
            }
            StatusCode::NO_CONTENT.into_response()
        }
        ("DELETE", false) => {
            if w.versioning != Some("Enabled") {
                w.history.remove(&key);
                w.bodies.retain(|(k, _), _| *k != key);
            }
            w.keep(&key, true);
            w.objects.remove(&key);
            StatusCode::NO_CONTENT.into_response()
        }
        ("GET", false) => match query.get("versionId").map(|v| w.bodies.get(&(key.clone(), v.clone()))).unwrap_or_else(|| w.objects.get(&key)) {
            Some(b) => {
                // As S3 does: the version's metadata and lock come with its body.
                let mut res = (StatusCode::OK, b.clone()).into_response();
                let version = query.get("versionId").cloned().or_else(|| w.meta.get(&key).map(|(_, v)| v.clone()));
                let stored = version.and_then(|v| w.versions.get(&(key.clone(), v.clone())).map(|s| (v, s.clone())));
                if let Some((version, (_, meta, lock))) = stored {
                    let mut h = vec![("x-amz-version-id".to_string(), version)];
                    h.extend(meta);
                    if let Some((mode, until)) = lock {
                        h.push(("x-amz-object-lock-mode".into(), mode));
                        h.push(("x-amz-object-lock-retain-until-date".into(), until));
                    }
                    for (k, v) in h {
                        res.headers_mut().insert(axum::http::HeaderName::from_bytes(k.as_bytes()).unwrap(), v.parse().unwrap());
                    }
                }
                res
            }
            None => error(StatusCode::NOT_FOUND, "NoSuchKey"),
        },
        _ => error(StatusCode::METHOD_NOT_ALLOWED, "MethodNotAllowed"),
    }
}

fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%'
            && i + 2 < b.len()
            && let Ok(x) = u8::from_str_radix(&s[i + 1..i + 3], 16)
        {
            out.push(x);
            i += 3;
            continue;
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::machines::s3::S3;

    #[tokio::test]
    async fn uploads_in_parts_and_reads_back() {
        let s = StandIn::start().await;
        let mut c = S3::new(s.settings()).unwrap();
        c.part_size = 4;
        let mut up = c.upload("p/a b.bin").await.unwrap();
        up.write(b"hello ").await.unwrap();
        up.write(b"world").await.unwrap();
        let (size, sha) = up.finish().await.unwrap();
        assert_eq!((size, sha), (11, s3::sha256_hex(b"hello world")));
        assert_eq!(s.keys(), ["p/a b.bin"]);
        assert_eq!(s.w().calls.iter().filter(|c| c.contains("partNumber")).count(), 3, "4 + 4 + 3 bytes");
        let got = c.get("p/a b.bin").await.unwrap().bytes().await.unwrap();
        assert_eq!(&got[..], b"hello world");
        c.put("p/m.json", b"{}".to_vec()).await.unwrap();
        assert_eq!(c.list("p/").await.unwrap(), ["p/a b.bin", "p/m.json"]);
        c.put("p/x&y", Vec::new()).await.unwrap();
        c.put("q/other", Vec::new()).await.unwrap();
        s.w().page = Some(1);
        assert_eq!(c.list("p/").await.unwrap(), ["p/a b.bin", "p/m.json", "p/x&y"], "every page, unescaped");
        assert_eq!(s.w().calls.iter().filter(|c| c.contains("list-type")).count(), 1 + 3);
        s.w().page = None;
        c.delete("p/x&y").await.unwrap();
        c.delete("p/a b.bin").await.unwrap();
        c.delete("p/a b.bin").await.unwrap();
        assert!(c.get("p/a b.bin").await.unwrap_err().contains("NoSuchKey"));

        let bad = S3::new(Settings::new(&s.url, BUCKET, "us-east-1", ACCESS_KEY, "wrong-secret").unwrap()).unwrap();
        let e = bad.put("x", Vec::new()).await.unwrap_err();
        assert!(e.contains("SignatureDoesNotMatch") && !e.contains("wrong-secret"), "{e}");
    }

    #[tokio::test]
    async fn old_versions_are_listed_page_by_page_and_deleted_for_good() {
        let s = StandIn::start().await;
        let c = S3::new(s.settings()).unwrap();
        assert!(!c.versioned().await.unwrap());
        s.w().fail = Some(("GET".into(), 501));
        assert!(!c.versioned().await.unwrap(), "a store without versioning keeps none");
        s.w().fail = Some(("GET".into(), 403));
        assert!(c.versioned().await.unwrap_err().contains("s3:GetBucketVersioning"));

        s.w().versioning = Some("Enabled");
        assert!(c.versioned().await.unwrap());
        c.put("p/a", b"one".to_vec()).await.unwrap();
        c.put("p/a", b"two".to_vec()).await.unwrap();
        c.put("p/b&c", b"x".to_vec()).await.unwrap();
        c.put("q/other", b"y".to_vec()).await.unwrap();
        c.delete("p/b&c").await.unwrap();
        assert_eq!(c.list("p/").await.unwrap(), ["p/a"], "a plain delete only hides it");
        s.w().page = Some(1);
        let v = c.versions("p/").await.unwrap();
        assert_eq!(v.len(), 4, "p/a now and before, p/b&c before and its marker: {v:?}");
        assert!(v.iter().any(|(k, _)| k == "p/b&c"), "unescaped: {v:?}");
        assert_eq!(s.w().calls.iter().filter(|c| c.contains("versions=")).count(), 4);
        for (k, id) in &v {
            c.delete_version(k, id).await.unwrap();
        }
        assert!(c.versions("p/").await.unwrap().is_empty());
        assert_eq!(s.keys(), ["q/other"]);
        c.delete_version("p/a", "gone").await.unwrap();
        s.w().versioning = Some("Suspended");
        assert!(c.versioned().await.unwrap(), "suspended still keeps what it kept");
    }

    #[tokio::test]
    async fn each_locked_version_keeps_its_own_lock() {
        let s = StandIn::start().await;
        s.w().versioning = Some("Enabled");
        s.w().object_lock = Some("<ObjectLockConfiguration><ObjectLockEnabled>Enabled</ObjectLockEnabled></ObjectLockConfiguration>".into());
        let c = S3::new(s.settings()).unwrap();
        let put = |body: &'static [u8], until: &'static str| {
            use base64::Engine;
            let sum = base64::engine::general_purpose::STANDARD.encode(aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, body).as_ref());
            let c = &c;
            async move {
                let h = [("x-amz-checksum-sha256", sum), ("x-amz-object-lock-mode", "GOVERNANCE".to_string()), ("x-amz-object-lock-retain-until-date", until.to_string())];
                c.put_with("a/x", body.to_vec(), &h).await.unwrap().get("x-amz-version-id").unwrap().to_str().unwrap().to_string()
            }
        };
        let first = put(b"one", "2030-01-01T00:00:00Z").await;
        let second = put(b"three", "2031-01-01T00:00:00Z").await;
        let h = c.head("a/x", Some(&first)).await.unwrap();
        assert_eq!((h["content-length"].to_str().unwrap(), h["x-amz-object-lock-retain-until-date"].to_str().unwrap()), ("3", "2030-01-01T00:00:00Z"));
        assert_eq!(c.head("a/x", None).await.unwrap()["x-amz-version-id"].to_str().unwrap(), second);
        assert!(c.delete_version("a/x", &first).await.unwrap_err().contains("AccessDenied"), "the older version is locked too");
    }

    #[tokio::test]
    async fn a_failed_completion_drops_the_parts() {
        let s = StandIn::start().await;
        let mut c = S3::new(s.settings()).unwrap();
        c.part_size = 4;
        let mut up = c.upload("p/x").await.unwrap();
        up.write(b"hello world").await.unwrap();
        s.w().fail = Some(("POST".into(), 500));
        assert!(up.finish().await.is_err());
        let w = s.w();
        assert!(w.uploads.is_empty() && w.objects.is_empty());
        assert!(w.calls.last().unwrap().starts_with("DELETE /backups/p/x?uploadId="), "{:?}", w.calls);
    }
}
