//! A stand-in for an operator's mirrors, for tests (ADR 0186): HTTPS on loopback with a
//! CA of its own, Node.js tarballs laid out as nodejs.org/dist and npm packages as a
//! registry serves them (a package document per name, scoped names as `@scope%2fname`,
//! tarballs under `<name>/-/`), and any other file a test puts there, such as an Ubuntu
//! archive's (ADR 0284). Every path asked for is recorded.

use super::wire::{Download, HarnessInstall, HarnessPlan, InstallSource, NodeRuntime};
use axum::http::{StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use base64::Engine;
use serde_json::{Value, json};
use sha2::{Digest, Sha256, Sha512};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

#[derive(Default)]
struct World {
    files: BTreeMap<String, Vec<u8>>,
    /// By name, then version: the tarball's path and the SHA-512 the document lists.
    packages: BTreeMap<String, BTreeMap<String, (String, String)>>,
    calls: Vec<String>,
    /// `Mirror::url`, for the tarballs' URLs.
    base: String,
    /// Paths answered with a 302 to a URL.
    redirects: BTreeMap<String, String>,
    /// The `Authorization` the registry (`/npm/`) wants, and what `/v1/npm-login`
    /// hands out, standing in for botd (ADR 0219).
    login: Option<String>,
    served_login: Option<Value>,
    /// Paths asked for with an `Authorization` header.
    authorized: Vec<String>,
}

pub struct Mirror {
    /// `https://127.0.0.1:<port>`, or empty for `ca_only`.
    pub url: String,
    /// The same server on another port, as a mirror's separate storage would be.
    pub other: String,
    ca_pem: String,
    world: Arc<Mutex<World>>,
}

fn sri(b: &[u8]) -> String {
    format!("sha512-{}", base64::engine::general_purpose::STANDARD.encode(Sha512::digest(b)))
}

/// nodejs.org's name for this machine's arch.
pub fn node_arch() -> &'static str {
    if std::env::consts::ARCH == "aarch64" { "arm64" } else { "x64" }
}

fn ca() -> (rcgen::Certificate, rcgen::Issuer<'static, rcgen::KeyPair>) {
    let key = rcgen::KeyPair::generate().unwrap();
    let mut p = rcgen::CertificateParams::new(vec![]).unwrap();
    p.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    p.distinguished_name.push(rcgen::DnType::CommonName, "Stand-in mirror CA");
    let cert = p.self_signed(&key).unwrap();
    (cert, rcgen::Issuer::new(p, key))
}

async fn handle(axum::extract::State(w): axum::extract::State<Arc<Mutex<World>>>, headers: axum::http::HeaderMap, uri: Uri) -> Response {
    let path = uri.path().to_string();
    let mut w = w.lock().unwrap();
    w.calls.push(path.clone());
    let auth = headers.get("authorization").and_then(|v| v.to_str().ok());
    if auth.is_some() {
        w.authorized.push(path.clone());
    }
    if path == "/v1/npm-login" {
        return match &w.served_login {
            Some(v) => ([("content-type", "application/json")], v.to_string()).into_response(),
            None => StatusCode::NOT_FOUND.into_response(),
        };
    }
    if path.starts_with("/npm/") && w.login.as_deref().is_some_and(|want| auth != Some(want)) {
        return (StatusCode::UNAUTHORIZED, [("www-authenticate", "Basic realm=\"stand-in\"")], "log in").into_response();
    }
    if let Some(to) = w.redirects.get(&path) {
        return (StatusCode::FOUND, [("location", to.clone())]).into_response();
    }
    if let Some(b) = w.files.get(&path) {
        return (StatusCode::OK, b.clone()).into_response();
    }
    let name = path.strip_prefix("/npm/").map(|n| n.replace("%2f", "/").replace("%2F", "/"));
    if let Some(versions) = name.as_ref().and_then(|n| w.packages.get(n)) {
        let base = w.base.clone();
        let versions: serde_json::Map<String, Value> = versions
            .iter()
            .map(|(v, (tarball, integrity))| {
                (v.clone(), json!({ "name": name, "version": v, "dist": { "tarball": format!("{base}{tarball}"), "integrity": integrity } }))
            })
            .collect();
        let latest = versions.keys().last().cloned();
        let doc = json!({ "name": name, "dist-tags": { "latest": latest }, "versions": versions });
        return ([("content-type", "application/json")], doc.to_string()).into_response();
    }
    StatusCode::NOT_FOUND.into_response()
}

impl Mirror {
    /// A CA and nothing serving: for settings that only read its certificate.
    pub fn ca_only() -> Mirror {
        Mirror { url: String::new(), other: String::new(), ca_pem: ca().0.pem(), world: Default::default() }
    }

    pub async fn serve() -> Mirror {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let second = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let other = format!("https://127.0.0.1:{}", second.local_addr().unwrap().port());
        let (ca_cert, issuer) = ca();
        let key = rcgen::KeyPair::generate().unwrap();
        let mut p = rcgen::CertificateParams::new(vec!["127.0.0.1".into(), "localhost".into()]).unwrap();
        p.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
        let cert = p.signed_by(&key, &issuer).unwrap();
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let tls = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert.der().clone()], rustls::pki_types::PrivateKeyDer::Pkcs8(key.serialize_der().into()))
            .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls));
        let url = format!("https://127.0.0.1:{port}");
        let world = Arc::new(Mutex::new(World { base: url.clone(), ..Default::default() }));
        let app = axum::Router::new().fallback(handle).with_state(world.clone());
        for listener in [listener, second] {
            let (acceptor, app) = (acceptor.clone(), app.clone());
            tokio::spawn(async move {
                loop {
                    let Ok((tcp, _)) = listener.accept().await else { return };
                    let (acceptor, app) = (acceptor.clone(), app.clone());
                    tokio::spawn(async move {
                        let Ok(stream) = acceptor.accept(tcp).await else { return };
                        let svc = hyper_util::service::TowerToHyperService::new(app);
                        let _ = hyper::server::conn::http1::Builder::new().serve_connection(hyper_util::rt::TokioIo::new(stream), svc).await;
                    });
                }
            });
        }
        Mirror { url, other, ca_pem: ca_cert.pem(), world }
    }

    /// Answers `path` with a redirect to `/stored<path>` on `other`, which serves it.
    pub fn redirect_to_other(&self, path: &str) {
        let mut w = self.world.lock().unwrap();
        let body = w.files[path].clone();
        w.files.insert(format!("/stored{path}"), body);
        w.redirects.insert(path.into(), format!("{}/stored{path}", self.other));
    }

    /// Answers `path` with a redirect to `to`.
    pub fn redirect(&self, path: &str, to: &str) {
        self.world.lock().unwrap().redirects.insert(path.into(), to.into());
    }

    /// Answers `path` with a redirect to `/stored<path>` on this same host and port:
    /// outside the registry's path, though npm's key for the host still matches.
    pub fn redirect_within(&self, path: &str) {
        let mut w = self.world.lock().unwrap();
        let body = w.files[path].clone();
        w.files.insert(format!("/stored{path}"), body);
        w.redirects.insert(path.into(), format!("{}/stored{path}", self.url));
    }

    pub fn ca_pem(&self) -> String {
        self.ca_pem.clone()
    }

    /// Where `MACHINE_NODE_MIRROR` would point.
    pub fn node_base(&self) -> String {
        format!("{}/node", self.url)
    }

    /// Where `MACHINE_NPM_REGISTRY` would point.
    pub fn registry(&self) -> String {
        format!("{}/npm/", self.url)
    }

    /// Serves `tarball` as Node.js `version` for this arch, and pins it.
    pub fn node(&self, version: &str, tarball: &[u8]) -> NodeRuntime {
        let path = format!("/node/v{version}/node-v{version}-linux-{}.tar.xz", node_arch());
        self.world.lock().unwrap().files.insert(path.clone(), tarball.to_vec());
        let sha256 = Sha256::digest(tarball).iter().map(|b| format!("{b:02x}")).collect();
        NodeRuntime { version: version.into(), downloads: [(std::env::consts::ARCH.to_string(), Download { url: format!("{}{path}", self.url), sha256 })].into() }
    }

    /// Publishes `tarball` as `name@version`; returns its SHA-512.
    pub fn package(&self, name: &str, version: &str, tarball: &[u8]) -> String {
        let file = name.rsplit('/').next().unwrap();
        let path = format!("/npm/{name}/-/{file}-{version}.tgz");
        let integrity = sri(tarball);
        let mut w = self.world.lock().unwrap();
        w.files.insert(path.clone(), tarball.to_vec());
        w.packages.entry(name.into()).or_default().insert(version.into(), (path, integrity.clone()));
        integrity
    }

    /// Serves other bytes for `name@version`, still listed with the old SHA-512.
    pub fn replace_tarball(&self, name: &str, version: &str, tarball: &[u8]) {
        let mut w = self.world.lock().unwrap();
        let path = w.packages[name][version].0.clone();
        w.files.insert(path, tarball.to_vec());
    }

    /// A plan of npm harnesses `(name, package, version, pin)` on `node`, from here.
    pub fn plan(&self, node: &NodeRuntime, npm: Vec<(&str, &str, &str, Option<String>)>) -> HarnessPlan {
        HarnessPlan {
            node: Some(node.clone()),
            harnesses: npm
                .into_iter()
                .map(|(name, package, version, integrity)| HarnessInstall {
                    name: name.into(),
                    version: version.into(),
                    source: InstallSource::Npm { package: package.into(), integrity },
                })
                .collect(),
            npm_registry: Some(self.registry()),
            ca: Some(self.ca_pem()),
            npm_login: self.world.lock().unwrap().login.is_some(),
        }
    }

    /// Serves `body` at `path`, replacing what was there.
    pub fn file(&self, path: &str, body: &[u8]) {
        self.world.lock().unwrap().files.insert(path.into(), body.to_vec());
    }

    pub fn calls(&self) -> Vec<String> {
        self.world.lock().unwrap().calls.clone()
    }

    /// From now on the registry answers 401 to any request without `authorization`.
    pub fn require(&self, authorization: &str) {
        self.world.lock().unwrap().login = Some(authorization.into());
    }

    /// Serves `login` at `/v1/npm-login`, as botd would to an enrolled machine.
    pub fn serve_login(&self, login: &super::wire::NpmLogin) {
        self.world.lock().unwrap().served_login = Some(serde_json::to_value(login).unwrap());
    }

    /// The paths asked for with an `Authorization` header.
    pub fn authorized(&self) -> Vec<String> {
        self.world.lock().unwrap().authorized.clone()
    }
}
