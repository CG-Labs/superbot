//! A small S3 client for off-host machine backups (ADR 0071): path-style requests
//! signed with AWS Signature Version 4, which AWS S3, Cloudflare R2, Backblaze B2,
//! MinIO and most S3-compatible stores accept. Only what backups need: multipart
//! uploads, small puts, streaming gets, listings and deletes (of old versions too, in a
//! versioned bucket). The secret key signs requests and
//! goes nowhere else: not in errors, logs, or `Debug`.

use crate::secrets::SecretStore;
use aws_lc_rs::{digest, hmac};
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
fn bucket_name(b: &str) -> bool {
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

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

pub fn sha256_hex(b: &[u8]) -> String {
    hex(digest::digest(&digest::SHA256, b).as_ref())
}

fn mac(key: &[u8], msg: &[u8]) -> Vec<u8> {
    hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, key), msg).as_ref().to_vec()
}

/// URI-encodes as SigV4 wants: everything but unreserved characters, and `/` too
/// unless `keep_slash`.
pub fn encode(s: &str, keep_slash: bool) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) || (keep_slash && b == b'/') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// The canonical query string: each name and value encoded, sorted.
pub fn canonical_query(query: &[(&str, &str)]) -> String {
    let mut q: Vec<(String, String)> = query.iter().map(|(k, v)| (encode(k, false), encode(v, false))).collect();
    q.sort();
    q.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>().join("&")
}

/// A request's SigV4 signature, and the signed header names. `uri` is already
/// encoded; `headers` are lowercase names with trimmed values.
#[allow(clippy::too_many_arguments)]
pub fn signature(
    secret: &str,
    region: &str,
    amz_date: &str,
    method: &str,
    uri: &str,
    query: &str,
    headers: &[(&str, &str)],
    payload_hash: &str,
) -> (String, String) {
    let mut h: Vec<(&str, &str)> = headers.to_vec();
    h.sort();
    let signed = h.iter().map(|(k, _)| *k).collect::<Vec<_>>().join(";");
    let canonical_headers: String = h.iter().map(|(k, v)| format!("{k}:{}\n", v.trim())).collect();
    let canonical = format!("{method}\n{uri}\n{query}\n{canonical_headers}\n{signed}\n{payload_hash}");
    let date = &amz_date[..8];
    let scope = format!("{date}/{region}/s3/aws4_request");
    let to_sign = format!("AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}", sha256_hex(canonical.as_bytes()));
    let k = mac(format!("AWS4{secret}").as_bytes(), date.as_bytes());
    let k = mac(&k, region.as_bytes());
    let k = mac(&k, b"s3");
    let k = mac(&k, b"aws4_request");
    (signed, hex(&mac(&k, to_sign.as_bytes())))
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

/// S3's error body in a few words, never the request.
fn refusal(status: reqwest::StatusCode, body: &str) -> String {
    let code = tag(body, "Code").unwrap_or_else(|| status.canonical_reason().unwrap_or("error").into());
    let msg = tag(body, "Message").map(|m| format!(": {m}")).unwrap_or_default();
    crate::audit::clip(&format!("the backup store refused ({}): {code}{msg}", status.as_u16()), 300)
}

pub struct S3 {
    s: Settings,
    http: reqwest::Client,
    /// Bytes per part of a multipart upload.
    pub part_size: usize,
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
        Ok(S3 { s, http, part_size: PART_SIZE })
    }

    async fn send(&self, method: Method, key: Option<&str>, query: &[(&str, &str)], body: Vec<u8>) -> Result<reqwest::Response, String> {
        let uri = match key {
            None => format!("/{}", encode(&self.s.bucket, false)),
            Some(k) => format!("/{}/{}", encode(&self.s.bucket, false), encode(k, true)),
        };
        let q = canonical_query(query);
        let payload = sha256_hex(&body);
        let amz_date = chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
        let headers = [("host", self.s.host.as_str()), ("x-amz-content-sha256", payload.as_str()), ("x-amz-date", amz_date.as_str())];
        let (signed, sig) = signature(&self.s.secret, &self.s.region, &amz_date, method.as_str(), &uri, &q, &headers, &payload);
        let auth = format!(
            "AWS4-HMAC-SHA256 Credential={}/{}/{}/s3/aws4_request, SignedHeaders={signed}, Signature={sig}",
            self.s.access_key,
            &amz_date[..8],
            self.s.region
        );
        let url = if q.is_empty() { format!("{}{uri}", self.s.endpoint) } else { format!("{}{uri}?{q}", self.s.endpoint) };
        let res = self
            .http
            .request(method, url)
            .header("x-amz-content-sha256", &payload)
            .header("x-amz-date", &amz_date)
            .header("authorization", auth)
            .body(body)
            .send()
            .await
            .map_err(|e| format!("couldn't reach the backup store: {}", e.without_url()))?;
        if res.status().is_success() {
            return Ok(res);
        }
        let status = res.status();
        let text = res.text().await.unwrap_or_default();
        Err(refusal(status, &text))
    }

    async fn text(res: reqwest::Response) -> Result<String, String> {
        res.text().await.map_err(|e| format!("the backup store's answer was cut off: {}", e.without_url()))
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
            let xml = S3::text(res).await?;
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
            Ok(res) => Ok(matches!(tag(&S3::text(res).await?, "Status").as_deref(), Some("Enabled" | "Suspended"))),
            Err(e) if e.contains("(501)") || e.contains("NotImplemented") => Ok(false),
            Err(e) => Err(format!("{e} (botd asks whether the bucket keeps old versions: s3:GetBucketVersioning)")),
        }
    }

    /// Every version and delete marker of every key under `prefix`, as `(key, version id)`.
    pub async fn versions(&self, prefix: &str) -> Result<Vec<(String, String)>, String> {
        let mut out = Vec::new();
        let mut after: Option<(String, String)> = None;
        loop {
            let mut q = vec![("versions", ""), ("prefix", prefix)];
            if let Some((k, v)) = after.as_ref() {
                q.push(("key-marker", k));
                q.push(("version-id-marker", v));
            }
            let res = self.send(Method::GET, None, &q, Vec::new()).await?;
            let xml = S3::text(res).await?;
            for item in xml.split("<Version>").skip(1).chain(xml.split("<DeleteMarker>").skip(1)) {
                if let (Some(k), Some(v)) = (tag(item, "Key"), tag(item, "VersionId")) {
                    out.push((k, v));
                }
            }
            let next = (tag(&xml, "NextKeyMarker"), tag(&xml, "NextVersionIdMarker"));
            after = match (tag(&xml, "IsTruncated").as_deref(), next) {
                (Some("true"), (Some(k), Some(v))) if !k.is_empty() && after.as_ref() != Some(&(k.clone(), v.clone())) => Some((k, v)),
                (Some("true"), _) => return Err("the backup store's listing of versions was cut off without a way to go on".into()),
                _ => return Ok(out),
            };
        }
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

    /// Starts writing `key` in parts.
    pub async fn upload(&self, key: &str) -> Result<Upload<'_>, String> {
        let res = self.send(Method::POST, Some(key), &[("uploads", "")], Vec::new()).await?;
        let xml = S3::text(res).await?;
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
        let body = S3::text(res).await?;
        if body.contains("<Error>") {
            return Err(refusal(reqwest::StatusCode::OK, &body));
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

    /// AWS's own example: GET Object, from the SigV4 documentation for S3.
    #[test]
    fn signs_as_aws_documents() {
        let (signed, sig) = signature(
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "us-east-1",
            "20130524T000000Z",
            "GET",
            "/test.txt",
            "",
            &[
                ("host", "examplebucket.s3.amazonaws.com"),
                ("range", "bytes=0-9"),
                ("x-amz-content-sha256", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
                ("x-amz-date", "20130524T000000Z"),
            ],
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        );
        assert_eq!(signed, "host;range;x-amz-content-sha256;x-amz-date");
        assert_eq!(sig, "f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41");
    }

    #[test]
    fn encodes_keys_and_queries() {
        assert_eq!(encode("a b/c~d+e", true), "a%20b/c~d%2Be");
        assert_eq!(encode("a/b", false), "a%2Fb");
        assert_eq!(canonical_query(&[("uploadId", "x/y"), ("partNumber", "2")]), "partNumber=2&uploadId=x%2Fy");
        assert_eq!(canonical_query(&[("uploads", "")]), "uploads=");
    }

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
        let r = refusal(reqwest::StatusCode::FORBIDDEN, "<Error><Code>AccessDenied</Code><Message>no</Message></Error>");
        assert_eq!(r, "the backup store refused (403): AccessDenied: no");
    }
}
