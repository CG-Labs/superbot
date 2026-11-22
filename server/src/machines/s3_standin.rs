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

#[derive(Default)]
pub struct World {
    pub objects: BTreeMap<String, Vec<u8>>,
    uploads: BTreeMap<String, (String, BTreeMap<u32, Vec<u8>>)>,
    /// `METHOD path?query`, in order.
    pub calls: Vec<String>,
    /// The next request with this method fails with this status.
    pub fail: Option<(String, u16)>,
    /// Keys per listing page; S3's 1,000 when unset.
    pub page: Option<usize>,
    next: u32,
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
    let (_, sig) = s3::signature(SECRET, region, &amz_date, method.as_str(), uri.path(), &s3::canonical_query(&q), &pairs, &payload);
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
        ("PUT", false) => match (query.get("partNumber"), query.get("uploadId")) {
            (Some(n), Some(id)) => {
                let Some((_, parts)) = w.uploads.get_mut(id) else { return error(StatusCode::NOT_FOUND, "NoSuchUpload") };
                parts.insert(n.parse().unwrap_or(0), body.to_vec());
                (StatusCode::OK, [("etag", format!("\"{}\"", s3::sha256_hex(&body)))]).into_response()
            }
            _ => {
                w.objects.insert(key, body.to_vec());
                StatusCode::OK.into_response()
            }
        },
        ("POST", false) if query.contains_key("uploads") => {
            w.next += 1;
            let id = format!("upload-{}", w.next);
            w.uploads.insert(id.clone(), (key.clone(), BTreeMap::new()));
            xml(StatusCode::OK, format!("<InitiateMultipartUploadResult><Key>{key}</Key><UploadId>{id}</UploadId></InitiateMultipartUploadResult>"))
        }
        ("POST", false) if query.contains_key("uploadId") => {
            let id = &query["uploadId"];
            let Some((k, parts)) = w.uploads.remove(id) else { return error(StatusCode::NOT_FOUND, "NoSuchUpload") };
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
            w.objects.insert(k, data);
            xml(StatusCode::OK, "<CompleteMultipartUploadResult></CompleteMultipartUploadResult>".into())
        }
        ("DELETE", false) if query.contains_key("uploadId") => {
            w.uploads.remove(&query["uploadId"]);
            StatusCode::NO_CONTENT.into_response()
        }
        ("DELETE", false) => {
            w.objects.remove(&key);
            StatusCode::NO_CONTENT.into_response()
        }
        ("GET", false) => match w.objects.get(&key) {
            Some(b) => (StatusCode::OK, b.clone()).into_response(),
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
