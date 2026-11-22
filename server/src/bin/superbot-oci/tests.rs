//! superbot-oci against an in-process registry: with and without the referrers API, behind a
//! token login, and one that changes what it stores. The published image is shaped like the
//! docker workflow's: a two-arch index with BuildKit attestation manifests, cosign signatures
//! (`--recursive`) on all five, a provenance attestation on the index, and a cosign `.sig` tag.

use crate::config::{Settings, credentials_in, insecure_in};
use crate::layout::{Layout, ROLE};
use crate::registry::{Client, OCI_INDEX, OCI_MANIFEST, Repo, next_link, parse_challenge};
use crate::{fetch, push, sha256_digest};
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

const BUNDLE: &str = "application/vnd.dev.sigstore.bundle.v0.3+json";
const EMPTY: &str = "application/vnd.oci.empty.v1+json";

#[derive(Default)]
struct Store {
    blobs: HashMap<String, Vec<u8>>,
    manifests: HashMap<(String, String), Vec<u8>>,
    tags: HashMap<(String, String), String>,
    next_upload: u64,
    writes: usize,
    /// The Authorization header on each blob upload.
    upload_auth: Vec<String>,
}

#[derive(Default, Clone, Copy)]
struct Mode {
    referrers_api: bool,
    login: bool,
    rewrite_tags: bool,
    /// Referrers one to a page, linked by `Link: <...>; rel="next"`.
    paged: bool,
    /// ... with the next page on another origin.
    page_elsewhere: bool,
    /// Uploads go to another origin (storage behind the registry), which takes them without a login.
    upload_elsewhere: bool,
    /// Manifests come back larger than a manifest can be.
    huge: bool,
    /// Referrers pages are empty and link to themselves.
    page_loop: bool,
}

struct Fake {
    store: Mutex<Store>,
    mode: Mode,
    addr: String,
}

const TOKEN: &str = "t0ken";
const LOGIN: (&str, &str) = ("ci", "secret");

fn reply(code: StatusCode, headers: &[(&str, String)], body: Vec<u8>) -> Response {
    let mut r = (code, body).into_response();
    for (k, v) in headers {
        r.headers_mut().insert(axum::http::HeaderName::from_bytes(k.as_bytes()).unwrap(), v.parse().unwrap());
    }
    r
}

impl Store {
    fn blob(&mut self, bytes: &[u8]) -> String {
        let d = sha256_digest(bytes);
        self.blobs.insert(d.clone(), bytes.to_vec());
        d
    }

    fn manifest(&mut self, repo: &str, m: &Value) -> (String, usize) {
        let bytes = serde_json::to_vec(m).unwrap();
        let d = sha256_digest(&bytes);
        self.manifests.insert((repo.into(), d.clone()), bytes.clone());
        (d, bytes.len())
    }

    fn resolve(&self, repo: &str, reference: &str) -> Option<String> {
        if reference.starts_with("sha256:") { Some(reference.to_string()) } else { self.tags.get(&(repo.into(), reference.into())).cloned() }
    }

    fn get(&self, repo: &str, reference: &str) -> Option<Vec<u8>> {
        self.manifests.get(&(repo.into(), self.resolve(repo, reference)?)).cloned()
    }

    fn referrers(&self, repo: &str, subject: &str) -> Vec<Value> {
        let mut out: Vec<Value> = self
            .manifests
            .iter()
            .filter(|((r, _), _)| r == repo)
            .filter_map(|((_, d), b)| {
                let m: Value = serde_json::from_slice(b).ok()?;
                (m["subject"]["digest"] == subject).then(|| {
                    json!({ "mediaType": m["mediaType"], "digest": d, "size": b.len(),
                        "artifactType": m["artifactType"].as_str().or(m["config"]["mediaType"].as_str()), "annotations": m["annotations"] })
                })
            })
            .collect();
        out.sort_by_key(|v| v["digest"].as_str().unwrap().to_string());
        out
    }
}

async fn handle(State(f): State<Arc<Fake>>, method: Method, uri: Uri, headers: HeaderMap, body: Bytes) -> Response {
    let path = uri.path();
    let auth = headers.get("authorization").and_then(|v| v.to_str().ok()).unwrap_or_default();
    if path == "/token" {
        let want = format!("Basic {}", base64::Engine::encode(&base64::engine::general_purpose::STANDARD, format!("{}:{}", LOGIN.0, LOGIN.1)));
        return if auth == want { reply(StatusCode::OK, &[], json!({ "token": TOKEN }).to_string().into_bytes()) } else { reply(StatusCode::UNAUTHORIZED, &[], vec![]) };
    }
    let elsewhere = format!("http://localhost:{}", f.addr.rsplit_once(':').unwrap().1);
    let signed_upload = f.mode.upload_elsewhere && method == Method::PUT && path.contains("/blobs/uploads/") && uri.query().unwrap_or_default().contains("state=x");
    if f.mode.login && auth != format!("Bearer {TOKEN}") && !signed_upload {
        let challenge = format!(r#"Bearer realm="http://{}/token",service="fake",scope="repository:x:pull""#, f.addr);
        return reply(StatusCode::UNAUTHORIZED, &[("www-authenticate", challenge)], vec![]);
    }
    let Some(rest) = path.strip_prefix("/v2/") else { return reply(StatusCode::NOT_FOUND, &[], vec![]) };
    if rest.is_empty() {
        return reply(StatusCode::OK, &[], b"{}".to_vec());
    }
    let mut s = f.store.lock().unwrap();
    if let Some((repo, id)) = rest.split_once("/blobs/uploads/") {
        if method == Method::POST && id.is_empty() {
            s.next_upload += 1;
            let origin = if f.mode.upload_elsewhere { elsewhere.as_str() } else { "" };
            return reply(StatusCode::ACCEPTED, &[("location", format!("{origin}/v2/{repo}/blobs/uploads/u{}?state=x", s.next_upload))], vec![]);
        }
        s.upload_auth.push(auth.to_string());
        let digest = uri.query().unwrap_or_default().split('&').find_map(|kv| kv.strip_prefix("digest=")).unwrap_or_default().replace("%3A", ":");
        if method != Method::PUT || !uri.query().unwrap_or_default().contains("state=x") || sha256_digest(&body) != digest {
            return reply(StatusCode::BAD_REQUEST, &[], b"DIGEST_INVALID".to_vec());
        }
        s.writes += 1;
        s.blobs.insert(digest.clone(), body.to_vec());
        return reply(StatusCode::CREATED, &[("docker-content-digest", digest)], vec![]);
    }
    if let Some((repo, reference)) = rest.rsplit_once("/manifests/") {
        if method == Method::PUT {
            let Ok(m) = serde_json::from_slice::<Value>(&body) else { return reply(StatusCode::BAD_REQUEST, &[], b"MANIFEST_INVALID".to_vec()) };
            let d = sha256_digest(&body);
            if reference.starts_with("sha256:") && reference != d {
                return reply(StatusCode::BAD_REQUEST, &[], b"DIGEST_INVALID".to_vec());
            }
            // As distribution does: an index's manifests and an image's blobs must be there first.
            let children: Vec<&str> = m["manifests"].as_array().into_iter().flatten().filter_map(|e| e["digest"].as_str()).collect();
            if children.iter().any(|c| !s.manifests.contains_key(&(repo.to_string(), c.to_string()))) {
                return reply(StatusCode::BAD_REQUEST, &[], b"MANIFEST_BLOB_UNKNOWN".to_vec());
            }
            let blobs = crate::registry::blobs_of(&m).unwrap();
            if blobs.iter().any(|b| !s.blobs.contains_key(b)) {
                return reply(StatusCode::BAD_REQUEST, &[], b"BLOB_UNKNOWN".to_vec());
            }
            s.writes += 1;
            s.manifests.insert((repo.into(), d.clone()), body.to_vec());
            if !reference.starts_with("sha256:") {
                s.tags.insert((repo.into(), reference.into()), d.clone());
            }
            let mut h = vec![("docker-content-digest", d)];
            if f.mode.referrers_api
                && let Some(subject) = m["subject"]["digest"].as_str()
            {
                h.push(("oci-subject", subject.to_string()));
            }
            return reply(StatusCode::CREATED, &h, vec![]);
        }
        let Some(mut bytes) = s.get(repo, reference) else { return reply(StatusCode::NOT_FOUND, &[], b"MANIFEST_UNKNOWN".to_vec()) };
        if f.mode.rewrite_tags && !reference.starts_with("sha256") {
            bytes.push(b'\n');
        }
        let mt = serde_json::from_slice::<Value>(&bytes).unwrap()["mediaType"].as_str().unwrap_or(OCI_MANIFEST).to_string();
        if f.mode.huge {
            bytes = vec![b' '; 5 << 20];
        }
        return reply(StatusCode::OK, &[("content-type", mt)], if method == Method::HEAD { vec![] } else { bytes });
    }
    if let Some((repo, digest)) = rest.rsplit_once("/referrers/") {
        if !f.mode.referrers_api {
            return reply(StatusCode::NOT_FOUND, &[], b"404 page not found".to_vec());
        }
        if f.mode.page_loop {
            let h = [("content-type", OCI_INDEX.to_string()), ("link", format!("</v2/{repo}/referrers/{digest}?from=0>; rel=\"next\""))];
            return reply(StatusCode::OK, &h, json!({ "schemaVersion": 2, "mediaType": OCI_INDEX, "manifests": [] }).to_string().into_bytes());
        }
        let all = s.referrers(repo, digest);
        let (from, n) = match f.mode.paged {
            true => (uri.query().and_then(|q| q.strip_prefix("from=")).and_then(|n| n.parse().ok()).unwrap_or(0), 1),
            false => (0, all.len()),
        };
        let page: Vec<Value> = all.iter().skip(from).take(n).cloned().collect();
        let mut h = vec![("content-type", OCI_INDEX.to_string())];
        if from + n < all.len() {
            let origin = if f.mode.page_elsewhere { elsewhere.as_str() } else { "" };
            h.push(("link", format!("<{origin}/v2/{repo}/referrers/{digest}?from={}>; rel=\"next\"", from + n)));
        }
        let index = json!({ "schemaVersion": 2, "mediaType": OCI_INDEX, "manifests": page });
        return reply(StatusCode::OK, &h, index.to_string().into_bytes());
    }
    if let Some((_, digest)) = rest.rsplit_once("/blobs/") {
        return match s.blobs.get(digest) {
            Some(b) => reply(StatusCode::OK, &[], if method == Method::HEAD { vec![] } else { b.clone() }),
            None => reply(StatusCode::NOT_FOUND, &[], vec![]),
        };
    }
    reply(StatusCode::NOT_FOUND, &[], vec![])
}

async fn serve(mode: Mode) -> Arc<Fake> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let f = Arc::new(Fake { store: Mutex::new(Store::default()), mode, addr });
    let app = axum::Router::new().fallback(handle).with_state(f.clone());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    f
}

fn tmp(tag: &str) -> PathBuf {
    static N: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let d = std::env::temp_dir().join(format!("superbot-oci-{tag}-{}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// Settings that reach these registries over plain HTTP, as registries.conf would, with LOGIN
/// in an auth file if given.
fn settings(regs: &[&Fake], login: Option<(&str, &str)>) -> Settings {
    let d = tmp("conf");
    let conf: String = regs.iter().map(|r| format!("[[registry]]\nlocation = \"{}\"\ninsecure = true # lab only\n\n", r.addr)).collect();
    std::fs::write(d.join("registries.conf"), conf).unwrap();
    let mut auth_files = Vec::new();
    if let Some((u, p)) = login {
        let auths: serde_json::Map<String, Value> =
            regs.iter().map(|r| (r.addr.clone(), json!({ "auth": base64::Engine::encode(&base64::engine::general_purpose::STANDARD, format!("{u}:{p}")) }))).collect();
        std::fs::write(d.join("auth.json"), json!({ "auths": auths }).to_string()).unwrap();
        auth_files.push(d.join("auth.json"));
    }
    Settings { auth_files, cert_dirs: vec![], registries_confs: vec![d.join("registries.conf")] }
}

struct Published {
    index: String,
    amd64: String,
    arm64: String,
    att_amd64: String,
    att_arm64: String,
    /// subject → its cosign signature
    sigs: HashMap<String, String>,
    provenance: String,
    provenance_sig: String,
    legacy_tag: String,
}

const REPO: &str = "cg/app";

fn artifact(s: &mut Store, fallback: bool, subject: &str, subject_size: usize, subject_type: &str, kind: &str) -> String {
    let empty = s.blob(b"{}");
    let layer = s.blob(format!("{{\"bundle\":\"{kind} {subject}\"}}").as_bytes());
    let m = json!({ "schemaVersion": 2, "mediaType": OCI_MANIFEST, "artifactType": BUNDLE,
        "config": { "mediaType": EMPTY, "digest": empty, "size": 2 },
        "layers": [{ "mediaType": BUNDLE, "digest": layer, "size": format!("{{\"bundle\":\"{kind} {subject}\"}}").len() }],
        "subject": { "mediaType": subject_type, "digest": subject, "size": subject_size },
        "annotations": { "dev.sigstore.bundle.predicateType": kind } });
    let (d, size) = s.manifest(REPO, &m);
    if fallback {
        let t = subject.replacen(':', "-", 1);
        let mut list = s.get(REPO, &t).map(|b| serde_json::from_slice::<Value>(&b).unwrap()["manifests"].as_array().cloned().unwrap()).unwrap_or_default();
        list.push(json!({ "mediaType": OCI_MANIFEST, "digest": d, "size": size, "artifactType": BUNDLE, "annotations": { "dev.sigstore.bundle.predicateType": kind } }));
        let (fd, _) = s.manifest(REPO, &json!({ "schemaVersion": 2, "mediaType": OCI_INDEX, "manifests": list }));
        s.tags.insert((REPO.into(), t), fd);
    }
    d
}

fn image(s: &mut Store, arch: &str) -> (String, usize) {
    let config = s.blob(format!(r#"{{"architecture":"{arch}","os":"linux","rootfs":{{"type":"layers","diff_ids":[]}}}}"#).as_bytes());
    let layer = s.blob(format!("{arch} layer").as_bytes());
    s.manifest(
        REPO,
        &json!({ "schemaVersion": 2, "mediaType": OCI_MANIFEST,
        "config": { "mediaType": "application/vnd.oci.image.config.v1+json", "digest": config, "size": 1 },
        "layers": [{ "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip", "digest": layer, "size": 1 }] }),
    )
}

fn attestation(s: &mut Store, of: &str) -> (String, usize) {
    let config = s.blob(br#"{"architecture":"unknown","os":"unknown"}"#);
    let sbom = s.blob(format!(r#"{{"predicateType":"https://spdx.dev/Document","subject":"{of}"}}"#).as_bytes());
    let prov = s.blob(format!(r#"{{"predicateType":"https://slsa.dev/provenance/v0.2","subject":"{of}"}}"#).as_bytes());
    s.manifest(
        REPO,
        &json!({ "schemaVersion": 2, "mediaType": OCI_MANIFEST,
        "config": { "mediaType": "application/vnd.oci.image.config.v1+json", "digest": config, "size": 1 },
        "layers": [{ "mediaType": "application/vnd.in-toto+json", "digest": sbom, "size": 1, "annotations": { "in-toto.io/predicate-type": "https://spdx.dev/Document" } },
                   { "mediaType": "application/vnd.in-toto+json", "digest": prov, "size": 1, "annotations": { "in-toto.io/predicate-type": "https://slsa.dev/provenance/v0.2" } }] }),
    )
}

fn entry(d: &str, size: usize, arch: &str, of: Option<&str>) -> Value {
    match of {
        None => json!({ "mediaType": OCI_MANIFEST, "digest": d, "size": size, "platform": { "architecture": arch, "os": "linux" } }),
        Some(of) => json!({ "mediaType": OCI_MANIFEST, "digest": d, "size": size, "platform": { "architecture": "unknown", "os": "unknown" },
            "annotations": { "vnd.docker.reference.digest": of, "vnd.docker.reference.type": "attestation-manifest" } }),
    }
}

/// The docker workflow's output, as REPO:1.0.0 in F. EXTRA adds a platform no bundle will hold.
fn publish(f: &Fake, extra: bool) -> Published {
    let fallback = !f.mode.referrers_api;
    let mut s = f.store.lock().unwrap();
    let (amd64, amd64_n) = image(&mut s, "amd64");
    let (arm64, arm64_n) = image(&mut s, "arm64");
    let (att_amd64, att_amd64_n) = attestation(&mut s, &amd64);
    let (att_arm64, att_arm64_n) = attestation(&mut s, &arm64);
    let mut entries =
        vec![entry(&amd64, amd64_n, "amd64", None), entry(&arm64, arm64_n, "arm64", None), entry(&att_amd64, att_amd64_n, "", Some(&amd64)), entry(&att_arm64, att_arm64_n, "", Some(&arm64))];
    if extra {
        let (s390x, n) = image(&mut s, "s390x");
        entries.push(entry(&s390x, n, "s390x", None));
    }
    let (index, index_n) = s.manifest(REPO, &json!({ "schemaVersion": 2, "mediaType": OCI_INDEX, "manifests": entries }));
    s.tags.insert((REPO.into(), "1.0.0".into()), index.clone());
    let mut sigs = HashMap::new();
    for (d, n, t) in [(&index, index_n, OCI_INDEX), (&amd64, amd64_n, OCI_MANIFEST), (&arm64, arm64_n, OCI_MANIFEST), (&att_amd64, att_amd64_n, OCI_MANIFEST), (&att_arm64, att_arm64_n, OCI_MANIFEST)]
    {
        sigs.insert(d.clone(), artifact(&mut s, fallback, d, n, t, "https://sigstore.dev/cosign/sign/v1"));
    }
    let provenance = artifact(&mut s, fallback, &index, index_n, OCI_INDEX, "https://slsa.dev/provenance/v1");
    let prov_n = s.get(REPO, &provenance).unwrap().len();
    let provenance_sig = artifact(&mut s, fallback, &provenance, prov_n, OCI_MANIFEST, "https://sigstore.dev/cosign/sign/v1");
    let simple = s.blob(br#"{"critical":{}}"#);
    let empty = s.blob(b"{}");
    let (legacy, _) = s.manifest(
        REPO,
        &json!({ "schemaVersion": 2, "mediaType": OCI_MANIFEST,
        "config": { "mediaType": "application/vnd.oci.image.config.v1+json", "digest": empty, "size": 2 },
        "layers": [{ "mediaType": "application/vnd.dev.cosign.simplesigning.v1+json", "digest": simple, "size": 15 }] }),
    );
    let legacy_tag = format!("{}.sig", amd64.replacen(':', "-", 1));
    s.tags.insert((REPO.into(), legacy_tag.clone()), legacy);
    Published { index, amd64, arm64, att_amd64, att_arm64, sigs, provenance, provenance_sig, legacy_tag }
}

fn repo(f: &Fake, path: &str) -> Repo {
    Repo { host: f.addr.clone(), path: path.into() }
}

fn digests(l: &Layout, role: &str) -> Vec<String> {
    let mut v: Vec<String> = l.entries.iter().filter(|e| e["annotations"][ROLE] == role).map(|e| Layout::digest(e).to_string()).collect();
    v.sort();
    v
}

fn sorted(mut v: Vec<String>) -> Vec<String> {
    v.sort();
    v
}

/// A bundle's unit for ARCH: its image as an OCI layout, and what fetch wrote.
async fn unit(f: &Fake, p: &Published, image: &str, cfg: &Settings) -> PathBuf {
    let d = tmp("unit");
    fetch::fetch(cfg, &repo(f, REPO), &p.index, image, &d.join("signatures")).await.unwrap();
    let mut w = crate::layout::Writer::create(&d.join("image")).unwrap();
    let s = f.store.lock().unwrap();
    let bytes = s.get(REPO, image).unwrap();
    let m: Value = serde_json::from_slice(&bytes).unwrap();
    for b in crate::registry::blobs_of(&m).unwrap() {
        w.put(&b, &s.blobs[&b]).unwrap();
    }
    w.put(image, &bytes).unwrap();
    w.add(json!({ "mediaType": OCI_MANIFEST, "digest": image, "size": bytes.len() }), "image", Some("1.0.0"));
    w.finish().unwrap();
    d
}

#[tokio::test]
async fn fetch_takes_one_arch_and_everything_signed_about_it() {
    for api in [false, true] {
        let src = serve(Mode { referrers_api: api, ..Mode::default() }).await;
        let p = publish(&src, false);
        let out = tmp("fetch").join("sig");
        let got = fetch::fetch(&settings(&[&src], None), &repo(&src, REPO), &p.index, &p.amd64, &out).await.unwrap();
        let l = Layout::open(&out).unwrap();
        assert_eq!(digests(&l, "index"), std::slice::from_ref(&p.index), "api={api}");
        assert_eq!(digests(&l, "attestation"), std::slice::from_ref(&p.att_amd64), "only this arch's attestation manifest (api={api})");
        let want = sorted(vec![p.sigs[&p.index].clone(), p.sigs[&p.amd64].clone(), p.sigs[&p.att_amd64].clone(), p.provenance.clone(), p.provenance_sig.clone()]);
        assert_eq!(digests(&l, "referrer"), want, "the index's, this arch's and its attestation's, and a referrer's own (api={api})");
        assert!(!digests(&l, "referrer").contains(&p.sigs[&p.arm64]), "not the other arch's");
        assert_eq!(l.entries.iter().filter(|e| e["annotations"][ROLE] == "tag").map(|e| e["annotations"][crate::layout::REF_NAME].as_str().unwrap()).collect::<Vec<_>>(), [p.legacy_tag.as_str()]);
        assert_eq!((got.referrers, got.tags, got.attestations), (5, 1, 1));
        for e in &l.entries {
            let m: Value = serde_json::from_slice(&l.read(Layout::digest(e)).unwrap()).unwrap();
            for b in crate::registry::blobs_of(&m).unwrap() {
                l.read(&b).unwrap();
            }
        }
        let prov = l.entries.iter().find(|e| e["digest"] == p.provenance.as_str()).unwrap();
        assert_eq!(prov["artifactType"], BUNDLE);
        assert_eq!(prov["annotations"]["dev.sigstore.bundle.predicateType"], "https://slsa.dev/provenance/v1");
    }
}

#[tokio::test]
async fn fetch_refuses_what_doesnt_match_its_digest_or_index() {
    let src = serve(Mode::default()).await;
    let p = publish(&src, false);
    let cfg = settings(&[&src], None);
    let e = fetch::fetch(&cfg, &repo(&src, REPO), &p.index, &p.sigs[&p.index], &tmp("x").join("o")).await.unwrap_err();
    assert!(e.contains("doesn't list"), "{e}");
    let e = fetch::fetch(&cfg, &repo(&src, REPO), &p.amd64, &p.arm64, &tmp("x").join("o")).await.unwrap_err();
    assert!(e.contains("is one image, not an index"), "{e}");
    {
        let mut s = src.store.lock().unwrap();
        let m: Value = serde_json::from_slice(&s.get(REPO, &p.att_amd64).unwrap()).unwrap();
        let layer = m["layers"][0]["digest"].as_str().unwrap().to_string();
        s.blobs.insert(layer, b"tampered".to_vec());
    }
    let e = fetch::fetch(&cfg, &repo(&src, REPO), &p.index, &p.amd64, &tmp("x").join("o")).await.unwrap_err();
    assert!(e.contains("came back as"), "{e}");
    {
        let mut s = src.store.lock().unwrap();
        let k = (REPO.to_string(), p.sigs[&p.index].clone());
        let mut b = s.manifests[&k].clone();
        b.push(b' ');
        s.manifests.insert(k, b);
    }
    let e = fetch::fetch(&cfg, &repo(&src, REPO), &p.index, &p.arm64, &tmp("x").join("o")).await.unwrap_err();
    assert!(e.contains("came back as"), "a manifest that isn't its digest: {e}");
}

#[tokio::test]
async fn push_two_arches_puts_up_the_signed_index_with_everything_signed() {
    for api in [false, true] {
        let src = serve(Mode::default()).await;
        let mirror = serve(Mode { referrers_api: api, ..Mode::default() }).await;
        let p = publish(&src, false);
        let cfg = settings(&[&src, &mirror], None);
        let units = [unit(&src, &p, &p.amd64, &cfg).await, unit(&src, &p, &p.arm64, &cfg).await];
        assert_eq!(push::push(&cfg, &repo(&mirror, "mirror/app"), "1.0.0", &units, true).await.unwrap(), p.index, "--check says what the tag will name");
        assert_eq!(mirror.store.lock().unwrap().writes, 0, "--check writes nothing");
        let top = push::push(&cfg, &repo(&mirror, "mirror/app"), "1.0.0", &units, false).await.unwrap();
        assert_eq!(top, p.index, "the tag names the signed index, unchanged (api={api})");
        {
            let s = mirror.store.lock().unwrap();
            assert_eq!(s.resolve("mirror/app", "1.0.0"), Some(p.index.clone()));
            for d in [&p.index, &p.amd64, &p.arm64, &p.att_amd64, &p.att_arm64, &p.provenance, &p.provenance_sig] {
                assert!(s.get("mirror/app", d).is_some(), "{d} is in the mirror (api={api})");
            }
            for subject in [&p.index, &p.amd64, &p.arm64, &p.att_amd64, &p.att_arm64] {
                let listed: Vec<String> = match api {
                    true => s.referrers("mirror/app", subject).iter().map(|v| v["digest"].as_str().unwrap().to_string()).collect(),
                    false => {
                        let b = s.get("mirror/app", &subject.replacen(':', "-", 1)).expect("a fallback tag");
                        serde_json::from_slice::<Value>(&b).unwrap()["manifests"].as_array().unwrap().iter().map(|v| v["digest"].as_str().unwrap().to_string()).collect()
                    }
                };
                assert!(listed.contains(&p.sigs[subject]), "{subject}'s signature is listed for it (api={api})");
            }
            if api {
                assert!(s.get("mirror/app", &p.index.replacen(':', "-", 1)).is_none(), "no fallback tag where the registry has the API");
            } else {
                let b = s.get("mirror/app", &p.index.replacen(':', "-", 1)).unwrap();
                let v: Value = serde_json::from_slice(&b).unwrap();
                let prov = v["manifests"].as_array().unwrap().iter().find(|e| e["digest"] == p.provenance.as_str()).unwrap();
                assert_eq!(prov["artifactType"], BUNDLE);
                assert!(prov["annotations"].get(ROLE).is_none(), "our own annotations stay in the bundle");
            }
            assert!(s.get("mirror/app", &p.legacy_tag).is_some(), "the cosign .sig tag");
        }
        // What cosign would do: find them again in the mirror.
        let again = tmp("again").join("o");
        let got = fetch::fetch(&cfg, &repo(&mirror, "mirror/app"), &p.index, &p.arm64, &again).await.unwrap();
        assert_eq!((got.referrers, got.attestations), (5, 1), "api={api}");
    }
}

#[tokio::test]
async fn push_one_arch_tags_that_image_with_its_signatures() {
    let src = serve(Mode::default()).await;
    let mirror = serve(Mode::default()).await;
    let p = publish(&src, false);
    let cfg = settings(&[&src, &mirror], None);
    let u = unit(&src, &p, &p.amd64, &cfg).await;
    let top = push::push(&cfg, &repo(&mirror, "m/app"), "1.0.0", std::slice::from_ref(&u), false).await.unwrap();
    assert_eq!(top, p.amd64);
    {
        let s = mirror.store.lock().unwrap();
        assert_eq!(s.resolve("m/app", "1.0.0"), Some(p.amd64.clone()));
        assert!(s.get("m/app", &p.index).is_none(), "no index without the other arch");
        assert!(s.get("m/app", &p.sigs[&p.amd64]).is_some() && s.get("m/app", &p.legacy_tag).is_some(), "the image's signatures");
        assert!(s.get("m/app", &p.att_amd64).is_some() && s.get("m/app", &p.sigs[&p.att_amd64]).is_some(), "its attestation manifest, signed");
        assert!(s.get("m/app", &p.att_arm64).is_none(), "not the other arch's");
        assert!(s.get("m/app", &p.sigs[&p.index]).is_none(), "nothing whose subject isn't there");
    }
    // Without signatures (an unsigned image, or an older bundle) the image still goes up.
    std::fs::remove_dir_all(u.join("signatures")).unwrap();
    assert_eq!(push::push(&cfg, &repo(&mirror, "m/plain"), "1", &[u], false).await.unwrap(), p.amd64);
}

#[tokio::test]
async fn push_keeps_what_a_fallback_tag_lists_already() {
    let src = serve(Mode::default()).await;
    let mirror = serve(Mode::default()).await;
    let p = publish(&src, false);
    let cfg = settings(&[&src, &mirror], None);
    let other = {
        let mut s = mirror.store.lock().unwrap();
        let empty = s.blob(b"{}");
        let (d, n) = s.manifest(
            "m/app",
            &json!({ "schemaVersion": 2, "mediaType": OCI_MANIFEST, "artifactType": "x/y",
            "config": { "mediaType": EMPTY, "digest": empty, "size": 2 }, "layers": [], "subject": { "mediaType": OCI_MANIFEST, "digest": p.amd64, "size": 1 } }),
        );
        json!({ "mediaType": OCI_MANIFEST, "digest": d, "size": n, "artifactType": "x/y" })
    };
    {
        let mut s = mirror.store.lock().unwrap();
        let (d, _) = s.manifest("m/app", &json!({ "schemaVersion": 2, "mediaType": OCI_INDEX, "manifests": [other.clone()] }));
        s.tags.insert(("m/app".into(), p.amd64.replacen(':', "-", 1)), d);
    }
    push::push(&cfg, &repo(&mirror, "m/app"), "1.0.0", &[unit(&src, &p, &p.amd64, &cfg).await], false).await.unwrap();
    let s = mirror.store.lock().unwrap();
    let v: Value = serde_json::from_slice(&s.get("m/app", &p.amd64.replacen(':', "-", 1)).unwrap()).unwrap();
    let listed: Vec<&Value> = v["manifests"].as_array().unwrap().iter().collect();
    assert_eq!(listed[0], &other, "what was there stays, first");
    assert!(listed.iter().any(|e| e["digest"] == p.sigs[&p.amd64].as_str()));
}

#[tokio::test]
async fn push_refuses_what_cant_make_the_index_before_writing_anything() {
    let src = serve(Mode::default()).await;
    let mirror = serve(Mode::default()).await;
    let p = publish(&src, true);
    let cfg = settings(&[&src, &mirror], None);
    let (a, b) = (unit(&src, &p, &p.amd64, &cfg).await, unit(&src, &p, &p.arm64, &cfg).await);
    let e = push::push(&cfg, &repo(&mirror, "m/app"), "1", &[a.clone(), b.clone()], false).await.unwrap_err();
    assert!(e.contains("also lists linux/s390x") && e.contains("add the bundles for those arches"), "{e}");
    let e = push::push(&cfg, &repo(&mirror, "m/app"), "1", &[a.clone(), b.clone()], true).await.unwrap_err();
    assert!(e.contains("also lists linux/s390x"), "--check refuses it too: {e}");
    let e = push::push(&cfg, &repo(&mirror, "m/app"), "1", &[a.clone(), a.clone()], false).await.unwrap_err();
    assert!(e.contains("same image") && e.contains("linux/amd64"), "{e}");
    let unsigned = tmp("unsigned");
    std::fs::create_dir_all(unsigned.join("image")).unwrap();
    for f in ["oci-layout", "index.json"] {
        std::fs::copy(b.join("image").join(f), unsigned.join("image").join(f)).unwrap();
    }
    copy_dir(&b.join("image/blobs"), &unsigned.join("image/blobs"));
    let e = push::push(&cfg, &repo(&mirror, "m/app"), "1", &[a.clone(), unsigned], false).await.unwrap_err();
    assert!(e.contains("has no signed multi-arch index"), "{e}");
    let other = serve(Mode::default()).await;
    let q = publish(&other, false);
    let cfg2 = settings(&[&src, &mirror, &other], None);
    let c = unit(&other, &q, &q.arm64, &cfg2).await;
    let e = push::push(&cfg2, &repo(&mirror, "m/app"), "1", &[a, c], false).await.unwrap_err();
    assert!(e.contains("different multi-arch indexes"), "{e}");
    assert_eq!(mirror.store.lock().unwrap().writes, 0, "nothing was pushed");
}

#[tokio::test]
async fn fetch_follows_every_page_of_referrers_from_the_registry_alone() {
    let src = serve(Mode { referrers_api: true, paged: true, ..Mode::default() }).await;
    let p = publish(&src, false);
    let cfg = settings(&[&src], None);
    let got = fetch::fetch(&cfg, &repo(&src, REPO), &p.index, &p.arm64, &tmp("paged").join("o")).await.unwrap();
    assert_eq!((got.referrers, got.attestations), (5, 1), "the index's signature and provenance are on different pages");
    let src = serve(Mode { referrers_api: true, paged: true, page_elsewhere: true, ..Mode::default() }).await;
    let p = publish(&src, false);
    let e = fetch::fetch(&cfg_for(&src), &repo(&src, REPO), &p.index, &p.arm64, &tmp("paged").join("o")).await.unwrap_err();
    assert!(e.contains("continue on http://localhost:") && e.contains("refusing it"), "{e}");
    let src = serve(Mode { referrers_api: true, page_loop: true, ..Mode::default() }).await;
    let p = publish(&src, false);
    let e = fetch::fetch(&cfg_for(&src), &repo(&src, REPO), &p.index, &p.arm64, &tmp("paged").join("o")).await.unwrap_err();
    assert!(e.contains("link back to a page already read"), "empty pages that link to themselves end: {e}");
}

fn cfg_for(f: &Fake) -> Settings {
    settings(&[f], None)
}

#[tokio::test]
async fn an_oversized_manifest_is_refused_without_reading_it_all() {
    let src = serve(Mode { huge: true, ..Mode::default() }).await;
    let p = publish(&src, false);
    let e = fetch::fetch(&cfg_for(&src), &repo(&src, REPO), &p.index, &p.arm64, &tmp("huge").join("o")).await.unwrap_err();
    assert!(e.contains("is over 4096 KiB"), "{e}");
}

#[tokio::test]
async fn the_login_goes_to_the_registry_alone_not_to_an_upload_elsewhere() {
    let src = serve(Mode::default()).await;
    let mirror = serve(Mode { login: true, upload_elsewhere: true, ..Mode::default() }).await;
    let p = publish(&src, false);
    let cfg = settings(&[&src, &mirror], Some(LOGIN));
    let units = [unit(&src, &p, &p.amd64, &cfg).await, unit(&src, &p, &p.arm64, &cfg).await];
    assert_eq!(push::push(&cfg, &repo(&mirror, "m/app"), "1", &units, false).await.unwrap(), p.index);
    let s = mirror.store.lock().unwrap();
    assert!(!s.upload_auth.is_empty() && s.upload_auth.iter().all(String::is_empty), "{:?}", s.upload_auth);
}

#[tokio::test]
async fn a_registry_on_https_cant_send_us_to_http() {
    let c = Client::new(&Settings::default(), &Repo::parse("reg.test/a").unwrap(), true).await.unwrap();
    for bad in ["http://reg.test/v2/a/blobs/uploads/1", "http://storage.test/u/1", "ftp://reg.test/x"] {
        assert!(c.resolve(bad, "upload location").unwrap_err().contains("isn't HTTPS"), "{bad}");
    }
    assert_eq!(c.resolve("/v2/a/blobs/uploads/1?s=x", "upload location").unwrap().as_str(), "https://reg.test/v2/a/blobs/uploads/1?s=x");
    assert!(c.resolve("https://storage.test/u/1", "upload location").is_ok(), "storage elsewhere, over HTTPS, without our login");
    assert_eq!(next_link(r#"</v2/a/referrers/x?n=2>; rel="next""#), Some("/v2/a/referrers/x?n=2"));
    assert_eq!(next_link(r#"<https://a.test/p>; rel="prev", </q>; rel=next"#), Some("/q"));
    assert_eq!(next_link("</q>"), None);
}

/// A cosign `.sig` manifest for SIGS, each a layer, with a config that lists them as cosign's does.
fn legacy_sig(s: &mut Store, repo: &str, sigs: &[&str]) -> String {
    let layers: Vec<Value> = sigs
        .iter()
        .map(|sig| {
            let d = s.blob(sig.as_bytes());
            json!({ "mediaType": "application/vnd.dev.cosign.simplesigning.v1+json", "digest": d, "size": sig.len(), "annotations": { "dev.cosignproject.cosign/signature": sig } })
        })
        .collect();
    let config = json!({ "architecture": "", "os": "", "config": {}, "rootfs": { "type": "layers", "diff_ids": layers.iter().map(|l| l["digest"].clone()).collect::<Vec<_>>() },
        "history": sigs.iter().map(|_| json!({ "created": "0001-01-01T00:00:00Z" })).collect::<Vec<_>>() });
    let cb = serde_json::to_vec(&config).unwrap();
    let cd = s.blob(&cb);
    s.manifest(repo, &json!({ "schemaVersion": 2, "mediaType": OCI_MANIFEST, "config": { "mediaType": "application/vnd.oci.image.config.v1+json", "digest": cd, "size": cb.len() }, "layers": layers })).0
}

fn sig_layers(s: &Store, repo: &str, tag: &str) -> Vec<String> {
    let m: Value = serde_json::from_slice(&s.get(repo, tag).expect("the tag")).unwrap();
    let cfg: Value = serde_json::from_slice(&s.blobs[m["config"]["digest"].as_str().unwrap()]).unwrap();
    let layers: Vec<String> = m["layers"].as_array().unwrap().iter().map(|l| l["annotations"]["dev.cosignproject.cosign/signature"].as_str().unwrap().to_string()).collect();
    assert_eq!(cfg["rootfs"]["diff_ids"].as_array().unwrap().len(), layers.len(), "the config lists every layer");
    assert_eq!(cfg["history"].as_array().unwrap().len(), layers.len());
    layers
}

#[tokio::test]
async fn cosign_tags_keep_every_signature_from_every_bundle_and_the_mirror() {
    let src = serve(Mode::default()).await;
    let mirror = serve(Mode::default()).await;
    let p = publish(&src, false);
    let cfg = settings(&[&src, &mirror], None);
    let t = format!("{}.sig", p.index.replacen(':', "-", 1));
    {
        let mut s = src.store.lock().unwrap();
        let d = legacy_sig(&mut s, REPO, &["first"]);
        s.tags.insert((REPO.into(), t.clone()), d);
    }
    let older = unit(&src, &p, &p.arm64, &cfg).await;
    {
        let mut s = src.store.lock().unwrap();
        let d = legacy_sig(&mut s, REPO, &["first", "again"]);
        s.tags.insert((REPO.into(), t.clone()), d);
    }
    let newer = unit(&src, &p, &p.amd64, &cfg).await;
    {
        let mut s = mirror.store.lock().unwrap();
        let d = legacy_sig(&mut s, "m/app", &["mirror's own"]);
        s.tags.insert(("m/app".into(), t.clone()), d);
    }
    assert_eq!(push::push(&cfg, &repo(&mirror, "m/app"), "1", &[newer.clone(), older.clone()], false).await.unwrap(), p.index);
    assert_eq!(sig_layers(&mirror.store.lock().unwrap(), "m/app", &t), ["mirror's own", "first", "again"], "the older bundle, last, takes nothing away");
    // Again: nothing new, so the tag stays as it is.
    let before = mirror.store.lock().unwrap().tags[&("m/app".to_string(), t.clone())].clone();
    push::push(&cfg, &repo(&mirror, "m/app"), "1", &[older, newer], false).await.unwrap();
    assert_eq!(mirror.store.lock().unwrap().tags[&("m/app".to_string(), t)], before);
}

#[test]
fn merging_cosign_tags_keeps_the_config_in_step() {
    let part = |sigs: &[&str]| {
        let layers: Vec<Value> = sigs.iter().map(|s| json!({ "digest": format!("sha256:{}", s.repeat(64).chars().take(64).collect::<String>()) })).collect();
        let cfg = json!({ "rootfs": { "type": "layers", "diff_ids": layers.iter().map(|l| l["digest"].clone()).collect::<Vec<_>>() }, "history": sigs.iter().map(|s| json!({ "comment": s })).collect::<Vec<_>>() });
        (json!({ "schemaVersion": 2, "config": { "digest": "x" }, "layers": layers }), serde_json::to_vec(&cfg).unwrap(), ())
    };
    let (m, cfg, from) = push::merge_cosign_tag(&[part(&["a", "b"]), part(&["b", "c"])]).unwrap();
    let digests: Vec<&str> = m["layers"].as_array().unwrap().iter().map(|l| l["digest"].as_str().unwrap()).collect();
    assert_eq!(digests.iter().map(|d| &d[7..8]).collect::<Vec<_>>(), ["a", "b", "c"]);
    assert_eq!(from, [0, 0, 1]);
    let cfg: Value = serde_json::from_slice(&cfg).unwrap();
    assert_eq!(cfg["rootfs"]["diff_ids"].as_array().unwrap().iter().map(|d| d.as_str().unwrap()).collect::<Vec<_>>(), digests);
    assert_eq!(cfg["history"].as_array().unwrap().iter().map(|h| h["comment"].as_str().unwrap()).collect::<Vec<_>>(), ["a", "b", "c"]);
    assert_eq!(m["config"]["digest"], sha256_digest(&serde_json::to_vec(&cfg).unwrap()));
}

fn copy_dir(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for e in std::fs::read_dir(from).unwrap() {
        let e = e.unwrap();
        if e.file_type().unwrap().is_dir() {
            copy_dir(&e.path(), &to.join(e.file_name()));
        } else {
            std::fs::copy(e.path(), to.join(e.file_name())).unwrap();
        }
    }
}

#[tokio::test]
async fn a_registry_that_changes_the_tag_is_caught() {
    let src = serve(Mode::default()).await;
    let mirror = serve(Mode { rewrite_tags: true, ..Mode::default() }).await;
    let p = publish(&src, false);
    let cfg = settings(&[&src, &mirror], None);
    let units = [unit(&src, &p, &p.amd64, &cfg).await, unit(&src, &p, &p.arm64, &cfg).await];
    let e = push::push(&cfg, &repo(&mirror, "m/app"), "1.0.0", &units, false).await.unwrap_err();
    assert!(e.contains("after the push, not") && e.contains(&p.index), "{e}");
}

#[tokio::test]
async fn logs_in_with_the_operators_credentials() {
    let src = serve(Mode { login: true, ..Mode::default() }).await;
    let p = publish(&src, false);
    fetch::fetch(&settings(&[&src], Some(LOGIN)), &repo(&src, REPO), &p.index, &p.amd64, &tmp("login").join("o")).await.unwrap();
    let e = fetch::fetch(&settings(&[&src], Some(("ci", "wrong"))), &repo(&src, REPO), &p.index, &p.amd64, &tmp("login").join("o")).await.unwrap_err();
    assert!(e.contains("refused the login") && e.contains("skopeo login"), "{e}");
    let e = fetch::fetch(&settings(&[&src], None), &repo(&src, REPO), &p.index, &p.amd64, &tmp("login").join("o")).await.unwrap_err();
    assert!(e.contains("wants a login"), "{e}");
}

#[test]
fn registries_conf_marks_registries_insecure_as_containers_does() {
    let v2 = "unqualified-search-registries = [\"docker.io\"]\n\n[[registry]]\nlocation = \"lab.test:5000\" # plain HTTP\ninsecure = true\n\n[[registry]]\nprefix = \"corp.test/team\"\nlocation = \"mirror.corp.test/team\"\ninsecure = true\n[[registry.mirror]]\nlocation = \"other.test\"\ninsecure = false\n\n[[registry]]\nlocation = \"*.dev.test\"\ninsecure = true\n\n[[registry]]\nlocation = \"tls.test\"\n";
    let one = |t: &str, h: &str, p: &str| insecure_in(&[t.to_string()], h, p);
    assert!(one(v2, "lab.test:5000", "x/y"));
    assert!(!one(v2, "lab.test", "x/y"), "the port is part of the location");
    assert!(one(v2, "corp.test", "team/app") && !one(v2, "corp.test", "teams/app"), "a prefix covers its path");
    assert!(one(v2, "a.dev.test", "app") && !one(v2, "dev.test", "app"));
    assert!(!one(v2, "tls.test", "app") && !one(v2, "other.test", "app"));
    let v1 = "[registries.insecure]\nregistries = ['old.test:5000', \"older.test\"]\n";
    assert!(one(v1, "old.test:5000", "a") && one(v1, "older.test", "a") && !one(v1, "new.test", "a"));
    assert!(!one("# location = \"lab.test:5000\"\n# insecure = true\n", "lab.test:5000", "a"));
    // The most specific registry decides, and a later file's registry replaces an earlier one's.
    let wide = "[[registry]]\nlocation = \"*.corp.test\"\ninsecure = true\n[[registry]]\nlocation = \"reg.corp.test\"\ninsecure = false\n[[registry]]\nprefix = \"lab.test/secure\"\nlocation = \"lab.test/secure\"\n";
    assert!(one(wide, "old.corp.test", "a") && !one(wide, "reg.corp.test", "a"), "insecure = false for one host wins over *.corp.test");
    assert!(one(v2, "lab.test:5000", "secure/a"));
    let both = [v2.to_string(), "[[registry]]\nlocation = \"lab.test:5000\"\ninsecure = false\n".to_string()];
    assert!(!insecure_in(&both, "lab.test:5000", "a"), "a drop-in that says insecure = false wins");
    assert!(insecure_in(&both, "corp.test", "team/a"), "and leaves the others alone");
}

#[test]
fn credentials_come_from_auth_files_as_docker_and_skopeo_write_them() {
    let b64 = |s: &str| base64::Engine::encode(&base64::engine::general_purpose::STANDARD, s);
    let no_helper = |_: &str, _: &str| -> Result<Option<(String, String)>, String> { panic!("no helper here") };
    let f = json!({ "auths": {
        "reg.test": { "auth": b64("a:1") },
        "reg.test/team": { "auth": b64("b:2") },
        "https://index.docker.io/v1/": { "auth": b64("hub:3") },
        "http://old.test:5000/v2/": { "username": "c", "password": "4:5" } } });
    let c = |h: &str, p: &str| credentials_in(&f, h, p, &no_helper).unwrap().map(|(u, p)| format!("{u}:{p}"));
    assert_eq!(c("reg.test", "other/app").as_deref(), Some("a:1"));
    assert_eq!(c("reg.test", "team/app").as_deref(), Some("b:2"), "the longest matching key");
    assert_eq!(c("docker.io", "library/alpine").as_deref(), Some("hub:3"));
    assert_eq!(c("old.test:5000", "x").as_deref(), Some("c:4:5"));
    assert_eq!(c("none.test", "x"), None);
    let helpers = json!({ "auths": { "reg.test": {} }, "credHelpers": { "ecr.test": "ecr" }, "credsStore": "desktop" });
    let seen = Mutex::new(Vec::new());
    let helper = |h: &str, server: &str| {
        seen.lock().unwrap().push(format!("{h} {server}"));
        Ok::<_, String>(Some(("u".to_string(), "s".to_string())))
    };
    credentials_in(&helpers, "ecr.test", "x", &helper).unwrap();
    credentials_in(&helpers, "reg.test", "x", &helper).unwrap();
    credentials_in(&helpers, "docker.io", "x", &helper).unwrap();
    assert_eq!(*seen.lock().unwrap(), ["ecr ecr.test", "desktop reg.test", "desktop https://index.docker.io/v1/"]);
    assert!(credentials_in(&json!({ "auths": { "reg.test": { "auth": "%%%" } } }), "reg.test", "x", &no_helper).is_err());
}

#[test]
fn references_and_challenges_parse() {
    assert_eq!(Repo::parse("localhost:5001/mirror/app").unwrap(), Repo { host: "localhost:5001".into(), path: "mirror/app".into() });
    assert_eq!(Repo::parse("docker.io/alpine").unwrap().path, "library/alpine");
    for bad in ["app", "mirror/app", "reg.test/App", "reg.test/a//b", "reg.test:x/a", "reg.test/a..b", "-reg.test/a"] {
        assert!(Repo::parse(bad).is_err(), "{bad}");
    }
    let (r, t) = Repo::parse_tagged("reg.test:5000/a/b:1.2.3").unwrap();
    assert_eq!((r.host.as_str(), r.path.as_str(), t.as_str()), ("reg.test:5000", "a/b", "1.2.3"));
    assert!(Repo::parse_tagged("reg.test:5000/a/b").is_err(), "the port isn't a tag");
    assert!(Repo::parse_digested(&format!("reg.test/a@sha256:{}", "0".repeat(64))).is_ok());
    assert!(Repo::parse_digested("reg.test/a@sha256:abc").is_err());
    let (scheme, params) = parse_challenge(r#"Bearer realm="https://auth.test/token",service="reg.test",scope="repository:a/b:pull,push""#);
    assert_eq!(scheme, "bearer");
    assert_eq!(params, [("realm".into(), "https://auth.test/token".into()), ("service".into(), "reg.test".into()), ("scope".into(), "repository:a/b:pull,push".into())]);
    assert_eq!(parse_challenge("Basic realm=Registry").1, [("realm".to_string(), "Registry".to_string())]);
}
