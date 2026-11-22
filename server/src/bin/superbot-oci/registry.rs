//! A small OCI distribution client: manifests, blobs, and the referrers API, with the bearer
//! token and basic logins registries ask for. Logins, CAs and plain HTTP come from config.rs.

use crate::config::{Credentials, Settings};
use crate::{digest_ok, sha256_digest, tag_ok};
use reqwest::header::{ACCEPT, AUTHORIZATION, CONTENT_LENGTH, CONTENT_TYPE, LOCATION, WWW_AUTHENTICATE};
use reqwest::{Method, StatusCode};
use serde_json::Value;
use std::io::Write;
use std::path::Path;
use std::sync::Mutex;

pub const OCI_INDEX: &str = "application/vnd.oci.image.index.v1+json";
pub const OCI_MANIFEST: &str = "application/vnd.oci.image.manifest.v1+json";
const ACCEPT_MANIFESTS: &str = "application/vnd.oci.image.index.v1+json, application/vnd.oci.image.manifest.v1+json, \
    application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.docker.distribution.manifest.v2+json";
/// Registries must take manifests of at least 4 MiB; nothing we copy is near it.
const MAX_MANIFEST: usize = 4 << 20;

/// A repository: `HOST[:PORT]/PATH`. The host has a dot or a port, or is localhost.
#[derive(Clone, Debug, PartialEq)]
pub struct Repo {
    pub host: String,
    pub path: String,
}

impl std::fmt::Display for Repo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.host, self.path)
    }
}

fn component_ok(c: &str) -> bool {
    // [a-z0-9]+ separated by one of . _ __ -+
    let b = c.as_bytes();
    !b.is_empty() && b[0].is_ascii_alphanumeric() && b[b.len() - 1].is_ascii_alphanumeric() && c.bytes().all(|x| x.is_ascii_lowercase() || x.is_ascii_digit() || matches!(x, b'.' | b'_' | b'-')) && !c.contains("..")
}

impl Repo {
    pub fn parse(s: &str) -> Result<Repo, String> {
        let bad = || format!("\"{s}\" isn't HOST[:PORT]/PATH (a host with a dot or a port, or localhost; a lowercase path)");
        let (host, path) = s.split_once('/').ok_or_else(bad)?;
        let name = host.split(':').next().unwrap_or_default();
        let host_ok = (host.contains('.') || host.contains(':') || name == "localhost")
            && name.starts_with(|c: char| c.is_ascii_alphanumeric())
            && name.bytes().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'-'))
            && host.split_once(':').is_none_or(|(_, p)| !p.is_empty() && p.bytes().all(|c| c.is_ascii_digit()));
        if !host_ok || !path.split('/').all(component_ok) {
            return Err(bad());
        }
        let path = if (host == "docker.io") && !path.contains('/') { format!("library/{path}") } else { path.to_string() };
        Ok(Repo { host: host.to_string(), path })
    }

    /// `HOST/PATH@sha256:...`
    pub fn parse_digested(s: &str) -> Result<(Repo, String), String> {
        let (r, d) = s.split_once('@').ok_or(format!("\"{s}\" isn't HOST/PATH@DIGEST"))?;
        if !digest_ok(d) {
            return Err(format!("\"{d}\" isn't a sha256 digest"));
        }
        Ok((Repo::parse(r)?, d.to_string()))
    }

    /// `HOST/PATH:TAG`
    pub fn parse_tagged(s: &str) -> Result<(Repo, String), String> {
        let at = s.rfind(':').filter(|&i| !s[i..].contains('/')).ok_or(format!("\"{s}\" isn't HOST/PATH:TAG"))?;
        let (r, t) = (&s[..at], &s[at + 1..]);
        if !tag_ok(t) {
            return Err(format!("\"{t}\" isn't a tag"));
        }
        Ok((Repo::parse(r)?, t.to_string()))
    }

    fn api_host(&self) -> &str {
        if self.host == "docker.io" { "registry-1.docker.io" } else { &self.host }
    }
}

/// Splits `Bearer realm="a",service="b"` into its scheme and parameters.
pub fn parse_challenge(h: &str) -> (String, Vec<(String, String)>) {
    let h = h.trim();
    let (scheme, rest) = h.split_once(' ').unwrap_or((h, ""));
    let mut params = Vec::new();
    let mut rest = rest.trim();
    while !rest.is_empty() {
        let Some((k, after)) = rest.split_once('=') else { break };
        let k = k.trim().trim_start_matches(',').trim().to_ascii_lowercase();
        let after = after.trim_start();
        let (v, next) = if let Some(q) = after.strip_prefix('"') {
            let end = q.find('"').unwrap_or(q.len());
            (q[..end].to_string(), q.get(end + 1..).unwrap_or(""))
        } else {
            let end = after.find(',').unwrap_or(after.len());
            (after[..end].trim().to_string(), &after[end..])
        };
        params.push((k, v));
        rest = next.trim_start().trim_start_matches(',').trim_start();
    }
    (scheme.to_ascii_lowercase(), params)
}

fn chain(e: &dyn std::error::Error) -> String {
    let mut s = e.to_string();
    let mut cur = e.source();
    while let Some(c) = cur {
        s += &format!(": {c}");
        cur = c.source();
    }
    s
}

pub enum Body<'a> {
    Empty,
    Bytes(&'a [u8], &'a str),
    File(&'a Path),
}

pub struct Client {
    http: reqwest::Client,
    base: String,
    pub repo: Repo,
    push: bool,
    creds: Option<Credentials>,
    authz: Mutex<Option<String>>,
}

/// What a manifest PUT told us.
pub struct Put {
    /// The registry set `OCI-Subject`: it lists the manifest in its referrers API itself.
    pub indexed_subject: bool,
}

impl Client {
    pub async fn new(settings: &Settings, repo: &Repo, push: bool) -> Result<Client, String> {
        let mut b = reqwest::Client::builder().connect_timeout(std::time::Duration::from_secs(30)).user_agent(concat!("superbot-oci/", env!("CARGO_PKG_VERSION")));
        let mut certs = Vec::new();
        for (path, pem) in settings.ca_pems(&repo.host) {
            certs.push(reqwest::Certificate::from_pem(&pem).map_err(|e| format!("{}: {e}", path.display()))?);
        }
        if !certs.is_empty() {
            b = b.tls_certs_merge(certs);
        }
        let http = b.build().map_err(|e| e.to_string())?;
        let creds = settings.credentials(&repo.host, &repo.path)?;
        let mut c = Client { http, base: format!("https://{}", repo.api_host()), repo: repo.clone(), push, creds, authz: Mutex::new(None) };
        if settings.insecure(&repo.host, &repo.path) && c.http.get(format!("{}/v2/", c.base)).send().await.is_err() {
            c.base = format!("http://{}", repo.api_host());
        }
        Ok(c)
    }

    fn url(&self, rest: &str) -> String {
        format!("{}/v2/{}/{rest}", self.base, self.repo.path)
    }

    async fn send(&self, method: Method, url: &str, headers: &[(reqwest::header::HeaderName, String)], body: &Body<'_>) -> Result<reqwest::Response, String> {
        for attempt in 0..2 {
            let mut rb = self.http.request(method.clone(), url);
            for (k, v) in headers {
                rb = rb.header(k, v);
            }
            if let Some(a) = self.authz.lock().unwrap().clone() {
                rb = rb.header(AUTHORIZATION, a);
            }
            rb = match body {
                Body::Empty => rb,
                Body::Bytes(b, t) => rb.header(CONTENT_TYPE, *t).body(b.to_vec()),
                Body::File(p) => {
                    let f = tokio::fs::File::open(p).await.map_err(|e| format!("{}: {e}", p.display()))?;
                    let len = f.metadata().await.map_err(|e| format!("{}: {e}", p.display()))?.len();
                    rb.header(CONTENT_TYPE, "application/octet-stream").header(CONTENT_LENGTH, len).body(reqwest::Body::from(f))
                }
            };
            let res = rb.send().await.map_err(|e| format!("{} {url}: {}", method, chain(&e)))?;
            if res.status() == StatusCode::UNAUTHORIZED && attempt == 0 {
                let challenge = res.headers().get(WWW_AUTHENTICATE).and_then(|v| v.to_str().ok()).unwrap_or_default().to_string();
                self.authenticate(&challenge).await?;
                continue;
            }
            return Ok(res);
        }
        unreachable!()
    }

    async fn authenticate(&self, challenge: &str) -> Result<(), String> {
        let host = &self.repo.host;
        let login = format!("log in with skopeo login {host} (or docker login)");
        let (scheme, params) = parse_challenge(challenge);
        let param = |k: &str| params.iter().find(|(n, _)| n == k).map(|(_, v)| v.as_str());
        let header = match scheme.as_str() {
            "basic" => {
                let (u, p) = self.creds.as_ref().ok_or(format!("{host} wants a login: {login}"))?;
                format!("Basic {}", base64::Engine::encode(&base64::engine::general_purpose::STANDARD, format!("{u}:{p}")))
            }
            "bearer" => {
                let realm = param("realm").ok_or(format!("{host} asked for a token without saying where to get one"))?;
                let mut url = url::Url::parse(realm).map_err(|e| format!("{host}'s token realm {realm}: {e}"))?;
                let scope = format!("repository:{}:{}", self.repo.path, if self.push { "pull,push" } else { "pull" });
                {
                    let mut q = url.query_pairs_mut();
                    if let Some(s) = param("service") {
                        q.append_pair("service", s);
                    }
                    q.append_pair("scope", &scope);
                }
                let mut rb = self.http.get(url.as_str());
                if let Some((u, p)) = &self.creds {
                    rb = rb.basic_auth(u, Some(p));
                }
                let res = rb.send().await.map_err(|e| format!("{host}'s token service: {}", chain(&e)))?;
                if !res.status().is_success() {
                    let why = if self.creds.is_some() { "refused the login" } else { "wants a login" };
                    return Err(format!("{host} {why} for {scope} (HTTP {}): {login}", res.status().as_u16()));
                }
                let v: Value = res.json().await.map_err(|e| format!("{host}'s token service: {e}"))?;
                let token = v["token"].as_str().or(v["access_token"].as_str()).filter(|t| !t.is_empty()).ok_or(format!("{host}'s token service gave no token"))?;
                format!("Bearer {token}")
            }
            _ => return Err(format!("{host} refused the request (HTTP 401): {login}")),
        };
        *self.authz.lock().unwrap() = Some(header);
        Ok(())
    }

    async fn failure(what: String, res: reqwest::Response) -> String {
        let code = res.status().as_u16();
        let body = res.text().await.unwrap_or_default();
        let detail: String = body.chars().take(300).collect();
        format!("{what}: HTTP {code} {}", detail.trim())
    }

    /// A manifest by tag or digest; None if there is none. One asked for by digest is checked.
    pub async fn manifest(&self, reference: &str) -> Result<Option<Vec<u8>>, String> {
        let res = self.send(Method::GET, &self.url(&format!("manifests/{reference}")), &[(ACCEPT, ACCEPT_MANIFESTS.into())], &Body::Empty).await?;
        if res.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !res.status().is_success() {
            return Err(Self::failure(format!("Couldn't read {}:{reference}", self.repo), res).await);
        }
        let bytes = res.bytes().await.map_err(|e| e.to_string())?.to_vec();
        if bytes.len() > MAX_MANIFEST {
            return Err(format!("{}:{reference} is larger than a manifest can be", self.repo));
        }
        if digest_ok(reference) && sha256_digest(&bytes) != reference {
            return Err(format!("{}@{reference} came back as {}: refusing it", self.repo, sha256_digest(&bytes)));
        }
        Ok(Some(bytes))
    }

    pub async fn put_manifest(&self, reference: &str, bytes: &[u8], media_type: &str) -> Result<Put, String> {
        let res = self.send(Method::PUT, &self.url(&format!("manifests/{reference}")), &[], &Body::Bytes(bytes, media_type)).await?;
        if !res.status().is_success() {
            return Err(Self::failure(format!("Couldn't push {}:{reference}", self.repo), res).await);
        }
        let want = sha256_digest(bytes);
        if let Some(got) = res.headers().get("docker-content-digest").and_then(|v| v.to_str().ok())
            && got != want
        {
            return Err(format!("{} stored {}:{reference} as {got}, not {want}", self.repo.host, self.repo));
        }
        Ok(Put { indexed_subject: res.headers().contains_key("oci-subject") })
    }

    /// The referrers the registry lists for DIGEST, or None if it has no referrers API.
    pub async fn referrers(&self, digest: &str) -> Result<Option<Vec<Value>>, String> {
        let res = self.send(Method::GET, &self.url(&format!("referrers/{digest}")), &[(ACCEPT, OCI_INDEX.into())], &Body::Empty).await?;
        if matches!(res.status(), StatusCode::NOT_FOUND | StatusCode::METHOD_NOT_ALLOWED | StatusCode::BAD_REQUEST) {
            return Ok(None);
        }
        if !res.status().is_success() {
            return Err(Self::failure(format!("Couldn't list what refers to {}@{digest}", self.repo), res).await);
        }
        let is_index = res.headers().get(CONTENT_TYPE).and_then(|v| v.to_str().ok()).is_some_and(|t| t.starts_with(OCI_INDEX));
        let v: Value = match res.json().await {
            Ok(v) => v,
            Err(_) if !is_index => return Ok(None),
            Err(e) => return Err(format!("{}'s referrers for {digest}: {e}", self.repo)),
        };
        match v["manifests"].as_array() {
            Some(m) => Ok(Some(m.clone())),
            None if !is_index => Ok(None),
            None => Err(format!("{}'s referrers for {digest} aren't an index", self.repo)),
        }
    }

    pub async fn blob_exists(&self, digest: &str) -> Result<bool, String> {
        let res = self.send(Method::HEAD, &self.url(&format!("blobs/{digest}")), &[], &Body::Empty).await?;
        match res.status() {
            s if s.is_success() => Ok(true),
            StatusCode::NOT_FOUND => Ok(false),
            _ => Err(Self::failure(format!("Couldn't check {}@{digest}", self.repo), res).await),
        }
    }

    /// Downloads a blob into DEST, refusing it unless it hashes to DIGEST or if it is over MAX.
    pub async fn fetch_blob(&self, digest: &str, dest: &Path, max: u64) -> Result<(), String> {
        use sha2::Digest;
        let mut res = self.send(Method::GET, &self.url(&format!("blobs/{digest}")), &[], &Body::Empty).await?;
        if !res.status().is_success() {
            return Err(Self::failure(format!("Couldn't read {}@{digest}", self.repo), res).await);
        }
        let part = dest.with_extension("part");
        let mut f = std::fs::File::create(&part).map_err(|e| format!("{}: {e}", part.display()))?;
        let mut h = sha2::Sha256::new();
        let mut n: u64 = 0;
        while let Some(chunk) = res.chunk().await.map_err(|e| format!("{}@{digest}: {}", self.repo, chain(&e)))? {
            n += chunk.len() as u64;
            if n > max {
                let _ = std::fs::remove_file(&part);
                return Err(format!("{}@{digest} is over {} MiB: refusing it", self.repo, max >> 20));
            }
            h.update(&chunk);
            f.write_all(&chunk).map_err(|e| format!("{}: {e}", part.display()))?;
        }
        let got = format!("sha256:{}", h.finalize().iter().map(|b| format!("{b:02x}")).collect::<String>());
        if got != digest {
            let _ = std::fs::remove_file(&part);
            return Err(format!("{}@{digest} came back as {got}: refusing it", self.repo));
        }
        std::fs::rename(&part, dest).map_err(|e| format!("{}: {e}", dest.display()))
    }

    /// Uploads SRC as DIGEST unless the registry has it; the registry checks the digest.
    pub async fn push_blob(&self, digest: &str, src: &Path) -> Result<(), String> {
        if self.blob_exists(digest).await? {
            return Ok(());
        }
        let res = self.send(Method::POST, &self.url("blobs/uploads/"), &[(CONTENT_LENGTH, "0".into())], &Body::Empty).await?;
        if res.status() != StatusCode::ACCEPTED {
            return Err(Self::failure(format!("Couldn't start an upload to {}", self.repo), res).await);
        }
        let loc = res.headers().get(LOCATION).and_then(|v| v.to_str().ok()).ok_or(format!("{} started an upload without a Location", self.repo.host))?;
        let base = url::Url::parse(&self.base).map_err(|e| e.to_string())?;
        let mut url = base.join(loc).map_err(|e| format!("{}'s upload location {loc}: {e}", self.repo.host))?;
        url.query_pairs_mut().append_pair("digest", digest);
        let res = self.send(Method::PUT, url.as_str(), &[], &Body::File(src)).await?;
        if !res.status().is_success() {
            return Err(Self::failure(format!("Couldn't upload {}@{digest}", self.repo), res).await);
        }
        Ok(())
    }
}

/// A manifest's media type: its own `mediaType`, else an index if it lists manifests.
pub fn media_type(m: &Value) -> &str {
    m["mediaType"].as_str().unwrap_or(if m.get("manifests").is_some() { OCI_INDEX } else { OCI_MANIFEST })
}

pub fn is_index(m: &Value) -> bool {
    m.get("manifests").is_some_and(Value::is_array)
}

/// The blobs an image manifest names: its config and layers.
pub fn blobs_of(m: &Value) -> Result<Vec<String>, String> {
    let mut out: Vec<String> = m["config"]["digest"].as_str().into_iter().map(String::from).collect();
    out.extend(m["layers"].as_array().into_iter().flatten().filter_map(|l| l["digest"].as_str()).map(String::from));
    if let Some(bad) = out.iter().find(|d| !digest_ok(d)) {
        return Err(format!("a manifest names {bad}, which isn't a sha256 digest"));
    }
    Ok(out)
}
