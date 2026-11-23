//! A stand-in for an Incus host's REST API, for tests: mutual TLS like the real one
//! (any client certificate gets through the handshake; only trusted ones get answers),
//! sync and async replies, operations to wait on, ETags, and Incus's errors. It keeps
//! instances, network ACLs, and projects in memory and records every call.
//!
//! An instance's PUT replaces its writable fields and ignores the rest; a PATCH merges
//! config and devices into them, an empty config value unsetting the key. Both honour
//! `If-Match`, apply to a running container in place, and never restart it.

use super::incus::{Credentials, PRIVATE, Settings};
use super::pki;
use axum::body::Bytes;
use axum::extract::{Extension, State};
use axum::http::{HeaderMap, Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use rustls::DigitallySignedStruct;
use rustls::client::danger::HandshakeSignatureValid;
use rustls::pki_types::{CertificateDer, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

#[derive(Clone, Debug)]
pub struct Call {
    pub method: String,
    pub path: String,
    pub query: String,
    pub body: Value,
    pub if_match: Option<String>,
}

#[derive(Clone, Debug)]
pub struct Instance {
    pub project: String,
    /// What a PUT replaces: config, devices, profiles, description, and the rest.
    pub body: Value,
    pub status: String,
    pub ip: String,
    pub location: String,
    pub source: Value,
    pub rebuilt: usize,
    /// Times it was started: by its create, or a start.
    pub boots: usize,
    /// Its disk: path to content and mode. Copied by backups.
    pub files: BTreeMap<String, (Vec<u8>, String)>,
}

#[derive(Clone, Debug)]
struct Op {
    status: String,
    err: String,
    instances: Vec<String>,
    pending: Option<(String, Instance)>,
    /// A held rebuild: the instance and its new source.
    rebuild: Option<(String, Value)>,
}

#[derive(Default)]
pub struct World {
    pub instances: BTreeMap<String, Instance>,
    pub acls: BTreeMap<String, Value>,
    pub projects: BTreeMap<String, Value>,
    /// Managed networks by name: `incusbr0`, the bridge, and any made (ADR 0212).
    pub networks: BTreeMap<String, Value>,
    pub calls: Vec<Call>,
    /// Creates stay running until `release`.
    pub hold_creates: bool,
    /// Rebuilds stay running until `release`.
    pub hold_rebuilds: bool,
    /// The next operation fails with this.
    pub fail_op: Option<String>,
    /// The next create is answered with this status and error at once, as for a
    /// cluster member or image that isn't there (404).
    pub fail_create: Option<(u16, String)>,
    /// Addresses to give containers by name, instead of 10.20.0.x.
    pub addresses: BTreeMap<String, String>,
    /// The next this many instance PUTs and PATCHes find that another client changed
    /// the instance (`user.other-client`) since it was read.
    pub races: usize,
    /// API extensions this Incus lacks, as an older release would.
    pub missing_extensions: Vec<String>,
    /// The `server_version` it reports, if not the stand-in's own.
    pub version: Option<String>,
    /// Instance backups by instance and name: the export file's bytes.
    pub backups: BTreeMap<(String, String), Vec<u8>>,
    /// Every request fails as from a host that is gone, and isn't recorded.
    pub down: bool,
    /// What `GET /1.0/resources` answers (ADR 0106).
    pub resources: Value,
    /// What `GET /1.0/storage-pools/default/resources` answers; null: an error.
    pub pool_resources: Value,
    /// `GET .../resources` is recorded and never answered.
    pub stall_resources: bool,
    /// `GET /1.0/instances/<name>` is recorded and never answered.
    pub stall_instances: bool,
    ops: BTreeMap<String, Op>,
    trusted: Vec<String>,
    next_ip: u8,
    next_op: u32,
}

pub struct StandIn {
    pub url: String,
    pub server_pem: String,
    pub cert_pem: String,
    pub key_pem: String,
    pub world: Arc<Mutex<World>>,
}

/// A new self-signed certificate and its key, in PEM.
pub fn self_signed(host: &str) -> (String, String) {
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = rcgen::CertificateParams::new(vec![host.to_string()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    (cert.pem(), key.serialize_pem())
}

/// Lets any client certificate through the handshake, as Incus does; the handler
/// decides whether it is trusted.
#[derive(Debug)]
struct AnyClient(Arc<rustls::crypto::CryptoProvider>);

impl ClientCertVerifier for AnyClient {
    fn offer_client_auth(&self) -> bool {
        true
    }
    fn client_auth_mandatory(&self) -> bool {
        false
    }
    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        &[]
    }
    fn verify_client_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        Ok(ClientCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

impl StandIn {
    /// Serves on a free local port with project `superbot` restricted, network
    /// `incusbr0`, and pool `default`.
    pub async fn start() -> StandIn {
        let (server_pem, server_key) = self_signed("incus.test");
        let (cert_pem, key_pem) = self_signed("botd.test");
        let mut w = World {
            trusted: vec![pki::fingerprint(&pki::cert_der(&cert_pem).unwrap())],
            next_ip: 10,
            resources: json!({
                "cpu": { "architecture": "x86_64", "total": 16 },
                "memory": { "used": 8u64 << 30, "total": 64u64 << 30 },
                "load": { "average1min": 1.5, "average5min": 1.25, "average10min": 1.0, "processes": 300 },
            }),
            pool_resources: json!({ "space": { "used": 100u64 << 30, "total": 1000u64 << 30 }, "inodes": { "used": 1, "total": 2 } }),
            ..World::default()
        };
        w.projects.insert("superbot".into(), json!({ "restricted": "true" }));
        w.projects.insert("default".into(), json!({}));
        w.networks.insert("incusbr0".into(), json!({ "type": "bridge", "managed": true, "config": { "ipv4.address": "10.20.0.1/24" } }));
        let world = Arc::new(Mutex::new(w));
        let provider = pki::provider();
        let config = Arc::new(
            rustls::ServerConfig::builder_with_provider(provider.clone())
                .with_protocol_versions(&[&rustls::version::TLS13])
                .unwrap()
                .with_client_cert_verifier(Arc::new(AnyClient(provider)))
                .with_single_cert(
                    vec![pki::cert_der(&server_pem).unwrap()],
                    pki::key_der(&server_key).unwrap(),
                )
                .unwrap(),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let router = axum::Router::new().fallback(handle).with_state(world.clone());
        tokio::spawn(pki::serve(listener, Arc::new(move || config.clone()), router, pki::lifetime));
        StandIn {
            url: format!("https://127.0.0.1:{port}"),
            server_pem,
            cert_pem,
            key_pem,
            world,
        }
    }

    pub fn credentials(&self) -> Credentials {
        Credentials {
            cert: pki::cert_der(&self.cert_pem).unwrap(),
            key: pki::key_der(&self.key_pem).unwrap(),
            server: pki::cert_der(&self.server_pem).unwrap(),
        }
    }

    /// Settings for botd reaching this stand-in, with `control` as botd's machine
    /// address.
    pub fn settings(&self, control: Option<(std::net::IpAddr, u16)>) -> Settings {
        let mut deny: Vec<String> = PRIVATE.iter().map(|s| s.to_string()).collect();
        deny.push("127.0.0.1/32".into());
        deny.sort();
        Settings {
            url: self.url.clone(),
            project: "superbot".into(),
            network: "incusbr0".into(),
            pool: "default".into(),
            image_server: Some(super::incus::DEFAULT_IMAGE_SERVER.into()),
            deny,
            control,
            allow: Vec::new(),
        }
    }

    pub fn w(&self) -> std::sync::MutexGuard<'_, World> {
        self.world.lock().unwrap()
    }

    pub fn calls(&self, method: &str, prefix: &str) -> Vec<Call> {
        self.w()
            .calls
            .iter()
            .filter(|c| c.method == method && c.path.starts_with(prefix))
            .cloned()
            .collect()
    }

    pub fn instance(&self, name: &str) -> Option<Instance> {
        self.w().instances.get(name).cloned()
    }

    /// Finishes held creates and rebuilds.
    pub fn release(&self) {
        let mut w = self.w();
        let mut made = Vec::new();
        let mut rebuilt = Vec::new();
        for o in w.ops.values_mut().filter(|o| o.status == "Running") {
            o.status = "Success".into();
            made.extend(o.pending.take());
            rebuilt.extend(o.rebuild.take());
        }
        for (n, i) in made {
            w.instances.insert(n, i);
        }
        for (n, source) in rebuilt {
            if let Some(i) = w.instances.get_mut(&n) {
                i.rebuilt += 1;
                i.source = source;
            }
        }
    }
}

fn reply(status: StatusCode, v: Value, etag: Option<String>) -> Response {
    let mut r = (status, axum::Json(v)).into_response();
    if let Some(e) = etag {
        r.headers_mut().insert("etag", e.parse().unwrap());
    }
    r
}

fn extensions(missing: &[String]) -> Vec<&'static str> {
    ["network_acl", "network_bridge_acl_devices", "instances_rebuild", "instance_create_start", "instance_get_full", "network_ovn_isolated"]
        .into_iter()
        .filter(|x| !missing.iter().any(|m| m == x))
        .collect()
}

fn sync(meta: Value) -> Response {
    reply(StatusCode::OK, json!({ "type": "sync", "status": "Success", "status_code": 200, "metadata": meta }), None)
}

fn err(code: u16, msg: &str) -> Response {
    reply(
        StatusCode::from_u16(code).unwrap(),
        json!({ "type": "error", "error": msg, "error_code": code }),
        None,
    )
}

fn etag(v: &Value) -> String {
    format!("\"{}\"", pki::fingerprint(v.to_string().as_bytes()))
}

/// What an instance PUT may change (Incus's `InstancePut`).
const WRITABLE: [&str; 7] = ["architecture", "config", "devices", "ephemeral", "profiles", "stateful", "description"];

fn writable(v: &Value) -> Value {
    let mut out = json!({});
    for k in WRITABLE {
        if let Some(x) = v.get(k) {
            out[k] = x.clone();
        }
    }
    out
}

/// A PATCH merged into an instance: config keys set (an empty value unsets one),
/// devices replaced by name, other writable fields replaced.
fn patched(cur: &Value, patch: &Value) -> Value {
    let mut out = cur.clone();
    for k in WRITABLE {
        let Some(x) = patch.get(k) else { continue };
        match (k, x.as_object(), out[k].as_object_mut()) {
            ("config" | "devices", Some(add), Some(have)) => {
                for (key, val) in add {
                    if k == "config" && val.as_str() == Some("") {
                        have.remove(key);
                    } else {
                        have.insert(key.clone(), val.clone());
                    }
                }
            }
            _ => out[k] = x.clone(),
        }
    }
    out
}

fn instance_url(n: &str, project: &str) -> String {
    if project == "default" {
        format!("/1.0/instances/{n}")
    } else {
        format!("/1.0/instances/{n}?project={project}")
    }
}

fn op_json(id: &str, o: &Op) -> Value {
    json!({ "id": id, "class": "task", "status": o.status, "err": o.err, "resources": { "instances": o.instances } })
}

impl World {
    /// Starts an async operation on `instances`, done unless `pending` is held.
    fn op(&mut self, instances: Vec<String>, pending: Option<(String, Instance)>) -> (Response, bool) {
        self.op_with(instances, pending, None)
    }

    fn op_with(
        &mut self,
        instances: Vec<String>,
        pending: Option<(String, Instance)>,
        rebuild: Option<(String, Value)>,
    ) -> (Response, bool) {
        self.next_op += 1;
        let id = format!("00000000-0000-4000-8000-{:012x}", self.next_op);
        let failed = self.fail_op.take();
        let held = failed.is_none()
            && ((pending.is_some() && self.hold_creates) || (rebuild.is_some() && self.hold_rebuilds));
        let o = Op {
            status: match (&failed, held) {
                (Some(_), _) => "Failure".into(),
                (None, true) => "Running".into(),
                _ => "Success".into(),
            },
            err: failed.clone().unwrap_or_default(),
            instances,
            pending: if held { pending } else { None },
            rebuild: if held { rebuild } else { None },
        };
        let body = json!({ "type": "async", "status": "Operation created", "status_code": 100, "operation": format!("/1.0/operations/{id}"), "metadata": op_json(&id, &o) });
        self.ops.insert(id, o);
        (reply(StatusCode::ACCEPTED, body, None), failed.is_none() && !held)
    }

    fn used_by(&self, acl: &str) -> Vec<String> {
        self.instances
            .iter()
            .filter(|(_, i)| {
                i.body["devices"].as_object().is_some_and(|d| {
                    d.values()
                        .any(|dev| dev["security.acls"].as_str().is_some_and(|a| a.split(',').any(|x| x == acl)))
                })
            })
            .map(|(n, i)| instance_url(n, &i.project))
            .collect()
    }

    fn instance_json(&self, n: &str, i: &Instance, state: bool) -> Value {
        let mut v = i.body.clone();
        v["name"] = json!(n);
        v["project"] = json!(i.project);
        v["status"] = json!(i.status);
        v["type"] = json!("container");
        v["location"] = json!(i.location);
        if state {
            let addresses = if i.status == "Running" {
                json!([
                    { "family": "inet", "address": i.ip, "netmask": "24", "scope": "global" },
                    { "family": "inet6", "address": "fe80::216:3eff:fe00:1", "netmask": "64", "scope": "link" },
                ])
            } else {
                json!([])
            };
            v["state"] = json!({ "status": i.status, "network": { "eth0": { "addresses": addresses } } });
        }
        v
    }

    /// What a restricted project refuses, as Incus would.
    fn refused(&self, project: &str, body: &Value) -> Option<String> {
        let p = self.projects.get(project)?;
        if p["restricted"] != "true" {
            return None;
        }
        let c = &body["config"];
        if c["security.privileged"] == "true" {
            return Some("Privileged containers are forbidden".into());
        }
        if c["security.nesting"] == "true" {
            return Some("Container nesting is forbidden".into());
        }
        // Incus's low-level container options, refused unless
        // restricted.containers.lowlevel=allow.
        let lowlevel = [
            "boot.host_shutdown_timeout",
            "limits.memory.swap",
            "linux.kernel_modules",
            "raw.apparmor",
            "raw.idmap",
            "raw.lxc",
            "raw.seccomp",
            "security.guestapi.images",
            "security.idmap.base",
            "security.idmap.size",
        ];
        if let Some(k) = c.as_object().and_then(|c| c.keys().find(|k| lowlevel.contains(&k.as_str()))) {
            return Some(format!("Use of low-level config \"{k}\" on container is forbidden"));
        }
        let devices = body["devices"].as_object().cloned().unwrap_or_default();
        for d in devices.values() {
            if d["type"] == "disk" && d["path"] != "/" {
                return Some("Disk devices other than the root disk are forbidden".into());
            }
            if d["type"] == "nic" && d["network"].as_str().is_none_or(|n| n.is_empty()) {
                return Some("Only managed network devices are allowed".into());
            }
            // Without networks of its own, the default project's that the access list
            // names, if it names any.
            let access = p["restricted.networks.access"].as_str().unwrap_or_default();
            if let Some(n) = d["network"].as_str().filter(|_| d["type"] == "nic" && !access.is_empty() && p["features.networks"] != "true")
                && !access.split(',').any(|a| a.trim() == n)
            {
                return Some(format!("Network \"{n}\" is not allowed in project"));
            }
        }
        None
    }

    fn networks_exist(&self, body: &Value) -> Option<String> {
        let devices = body["devices"].as_object().cloned().unwrap_or_default();
        devices
            .values()
            .filter(|d| d["type"] == "nic")
            .filter_map(|d| d["network"].as_str())
            .find(|n| !self.networks.contains_key(*n))
            .map(|n| format!("Failed loading network \"{n}\": Network not found"))
    }

    fn acls_exist(&self, body: &Value) -> Option<String> {
        let devices = body["devices"].as_object().cloned().unwrap_or_default();
        devices
            .values()
            .filter_map(|d| d["security.acls"].as_str())
            .flat_map(|a| a.split(',').filter(|x| !x.is_empty()).map(String::from).collect::<Vec<_>>())
            .find(|a| !self.acls.contains_key(a))
            .map(|a| format!("Network ACL {a:?} not found"))
    }
}

/// Marks a response never to be sent.
#[derive(Clone)]
struct Stall;

async fn handle(
    State(world): State<Arc<Mutex<World>>>,
    Extension(peer): Extension<pki::Peer>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let r = respond(&world, peer, method, uri, headers, body);
    if r.extensions().get::<Stall>().is_some() {
        return std::future::pending().await;
    }
    r
}

fn respond(world: &Mutex<World>, peer: pki::Peer, method: Method, uri: Uri, headers: HeaderMap, body: Bytes) -> Response {
    let mut w = world.lock().unwrap();
    if w.down {
        return err(503, "the host is down");
    }
    let trusted = peer
        .cert
        .as_ref()
        .is_some_and(|c| w.trusted.contains(&pki::fingerprint(c)));
    if !trusted {
        return err(403, "not authorized");
    }
    let query: BTreeMap<String, String> = url::form_urlencoded::parse(uri.query().unwrap_or_default().as_bytes())
        .into_owned()
        .collect();
    let project = query.get("project").cloned().unwrap_or("default".into());
    let recursion = query.get("recursion").cloned().unwrap_or_default();
    let header = |k: &str| headers.get(k).and_then(|v| v.to_str().ok()).map(String::from);
    let raw = header("content-type").is_some_and(|c| c == "application/octet-stream");
    let bytes = body;
    let body: Value = if raw { json!({ "bytes": bytes.len() }) } else { serde_json::from_slice(&bytes).unwrap_or(Value::Null) };
    w.calls.push(Call {
        method: method.to_string(),
        path: uri.path().to_string(),
        query: uri.query().unwrap_or_default().to_string(),
        body: body.clone(),
        if_match: header("if-match"),
    });
    let one_instance = method == Method::GET && uri.path().strip_prefix("/1.0/instances/").is_some_and(|n| !n.is_empty() && !n.contains('/'));
    if (w.stall_resources && uri.path().ends_with("/resources")) || (w.stall_instances && one_instance) {
        let mut r = Response::default();
        r.extensions_mut().insert(Stall);
        return r;
    }
    let if_match = header("if-match");
    let parts: Vec<&str> = uri.path().trim_start_matches('/').split('/').collect();
    match (method.as_str(), &parts[..]) {
        ("POST", ["1.0", "instances"]) if raw => {
            let Some(n) = header("x-incus-name") else {
                return err(400, "No name provided");
            };
            if w.instances.contains_key(&n) {
                return err(500, &format!("Instance {n:?} already exists"));
            }
            let Ok(saved) = serde_json::from_slice::<Value>(&bytes) else {
                return err(400, "Failed to read the backup file");
            };
            let mut kept = saved["body"].clone();
            if let Some(pool) = header("x-incus-pool") {
                kept["devices"]["root"]["pool"] = json!(pool);
            }
            if let Some(why) = w.refused(&project, &kept).or_else(|| w.acls_exist(&kept)).or_else(|| w.networks_exist(&kept)) {
                return err(400, &why);
            }
            let files = saved["files"]
                .as_object()
                .into_iter()
                .flatten()
                .map(|(p, f)| (p.clone(), (f[0].as_str().unwrap_or_default().as_bytes().to_vec(), f[1].as_str().unwrap_or_default().to_string())))
                .collect();
            w.next_ip += 1;
            let ip = w.addresses.get(&n).cloned().unwrap_or(format!("10.20.0.{}", w.next_ip));
            let i = Instance {
                project: project.clone(),
                body: kept,
                status: "Stopped".into(),
                ip,
                location: "none".into(),
                source: json!({ "type": "backup" }),
                rebuilt: 0,
                boots: 0,
                files,
            };
            let (r, done) = w.op(vec![instance_url(&n, &project)], None);
            if done {
                w.instances.insert(n, i);
            }
            r
        }
        ("GET", ["1.0"]) => sync(json!({
            "auth": "trusted",
            "api_extensions": extensions(&w.missing_extensions),
            "environment": { "server_version": w.version.clone().unwrap_or("standin".into()) },
        })),
        ("GET", ["1.0", "projects", p]) => match w.projects.get(*p) {
            Some(c) => reply(
                StatusCode::OK,
                json!({ "type": "sync", "status": "Success", "status_code": 200, "metadata": { "name": p, "config": c, "description": "" } }),
                Some(etag(c)),
            ),
            None => err(404, "Project not found"),
        },
        ("PUT", ["1.0", "projects", p]) => {
            let Some(c) = w.projects.get(*p) else { return err(404, "Project not found") };
            if if_match.as_ref().is_some_and(|e| *e != etag(c)) {
                return err(412, "ETag doesn't match");
            }
            w.projects.insert(p.to_string(), body["config"].clone());
            sync(json!({}))
        }
        ("GET", ["1.0", "networks"]) => {
            let list: Vec<Value> = w
                .networks
                .iter()
                .map(|(n, v)| {
                    if recursion.is_empty() {
                        json!(format!("/1.0/networks/{n}"))
                    } else {
                        let mut v = v.clone();
                        v["name"] = json!(n);
                        v
                    }
                })
                .collect();
            sync(json!(list))
        }
        ("POST", ["1.0", "networks"]) => {
            let Some(n) = body["name"].as_str().map(String::from) else {
                return err(400, "No name provided");
            };
            let pc = w.projects.get(&project).cloned().unwrap_or_default();
            let access = pc["restricted.networks.access"].as_str().unwrap_or_default();
            if pc["restricted"] == "true" && pc["features.networks"] != "true" && !access.is_empty() && !access.split(',').any(|a| a.trim() == n) {
                return err(403, "Network not allowed in project");
            }
            if w.networks.contains_key(&n) {
                return err(409, "The network already exists");
            }
            if body["type"] != "ovn" {
                return err(400, "The stand-in makes only OVN networks");
            }
            let mut v = body.clone();
            v.as_object_mut().unwrap().remove("name");
            v["managed"] = json!(true);
            w.networks.insert(n, v);
            sync(json!({}))
        }
        ("GET", ["1.0", "networks", n]) if w.networks.contains_key(*n) => {
            let mut v = w.networks[*n].clone();
            v["name"] = json!(n);
            sync(v)
        }
        ("GET", ["1.0", "resources"]) => sync(w.resources.clone()),
        ("GET", ["1.0", "storage-pools", "default", "resources"]) if !w.pool_resources.is_null() => sync(w.pool_resources.clone()),
        ("GET", ["1.0", "storage-pools", _, "resources"]) => err(404, "Not found"),
        ("GET", ["1.0", "storage-pools", p]) if *p == "default" => sync(json!({ "name": p, "driver": "zfs" })),
        ("GET", ["1.0", "storage-pools", p]) if *p == "plain" => sync(json!({ "name": p, "driver": "dir" })),
        ("GET", ["1.0", "networks" | "storage-pools", _]) => err(404, "Not found"),
        ("GET", ["1.0", "instances"]) => {
            let list: Vec<Value> = w
                .instances
                .iter()
                .filter(|(_, i)| i.project == project)
                .map(|(n, i)| {
                    if recursion.is_empty() {
                        json!(instance_url(n, &i.project))
                    } else {
                        w.instance_json(n, i, recursion == "2")
                    }
                })
                .collect();
            sync(json!(list))
        }
        ("POST", ["1.0", "instances"]) => {
            if let Some((status, why)) = w.fail_create.take() {
                return err(status, &why);
            }
            let Some(n) = body["name"].as_str().map(String::from) else {
                return err(400, "No name provided");
            };
            if w.instances.contains_key(&n) || w.ops.values().any(|o| o.pending.as_ref().is_some_and(|(p, _)| *p == n)) {
                return err(500, &format!("Instance {n:?} already exists"));
            }
            if let Some(why) = w.refused(&project, &body).or_else(|| w.acls_exist(&body)).or_else(|| w.networks_exist(&body)) {
                return err(400, &why);
            }
            w.next_ip += 1;
            let ip = w.addresses.get(&n).cloned().unwrap_or(format!("10.20.0.{}", w.next_ip));
            let mut kept = body.clone();
            for k in ["name", "source", "start", "type"] {
                kept.as_object_mut().unwrap().remove(k);
            }
            kept["architecture"] = json!("x86_64");
            kept["ephemeral"] = json!(false);
            kept["stateful"] = json!(false);
            let i = Instance {
                project: project.clone(),
                body: kept,
                status: if body["start"] == true { "Running".into() } else { "Stopped".into() },
                ip,
                location: query.get("target").cloned().unwrap_or("none".into()),
                source: body["source"].clone(),
                rebuilt: 0,
                boots: (body["start"] == true) as usize,
                files: BTreeMap::new(),
            };
            let (r, done) = w.op(vec![instance_url(&n, &project)], Some((n.clone(), i.clone())));
            if done {
                w.instances.insert(n, i);
            }
            r
        }
        (m, ["1.0", "instances", n, rest @ ..]) => {
            let n = n.to_string();
            let Some(mut i) = w.instances.get(&n).filter(|i| i.project == project).cloned() else {
                return err(404, "Instance not found");
            };
            if matches!(m, "PUT" | "PATCH") && rest.is_empty() && w.races > 0 {
                w.races -= 1;
                let change = format!("change {}", w.races + 1);
                let other = w.instances.get_mut(&n).unwrap();
                other.body["config"]["user.other-client"] = json!(change);
                i = other.clone();
            }
            let tag = etag(&i.body);
            match (m, rest) {
                ("GET", []) => reply(
                    StatusCode::OK,
                    json!({ "type": "sync", "status": "Success", "status_code": 200, "metadata": w.instance_json(&n, &i, recursion == "1") }),
                    Some(tag),
                ),
                ("PUT", []) => {
                    if if_match.as_ref().is_some_and(|e| *e != tag) {
                        return err(412, "ETag doesn't match");
                    }
                    if let Some(why) = w.refused(&project, &body).or_else(|| w.acls_exist(&body)).or_else(|| w.networks_exist(&body)) {
                        return err(400, &why);
                    }
                    let (r, done) = w.op(vec![instance_url(&n, &project)], None);
                    if done {
                        w.instances.get_mut(&n).unwrap().body = writable(&body);
                    }
                    r
                }
                ("PATCH", []) => {
                    if if_match.as_ref().is_some_and(|e| *e != tag) {
                        return err(412, "ETag doesn't match");
                    }
                    let next = patched(&i.body, &body);
                    if let Some(why) = w.refused(&project, &next).or_else(|| w.acls_exist(&next)).or_else(|| w.networks_exist(&next)) {
                        return err(400, &why);
                    }
                    w.instances.get_mut(&n).unwrap().body = next;
                    sync(json!({}))
                }
                ("DELETE", []) => {
                    if i.status != "Stopped" {
                        return err(400, "Instance is running");
                    }
                    let (r, done) = w.op(vec![instance_url(&n, &project)], None);
                    if done {
                        w.instances.remove(&n);
                    }
                    r
                }
                ("PUT", ["state"]) => {
                    let status = match (body["action"].as_str(), i.status.as_str()) {
                        (Some("start"), "Running") => return err(400, "The instance is already running"),
                        (Some("stop"), "Stopped") => return err(400, "The instance is already stopped"),
                        (Some("start"), _) => "Running",
                        (Some("stop"), _) => "Stopped",
                        _ => return err(400, "Unknown action"),
                    };
                    let (r, done) = w.op(vec![instance_url(&n, &project)], None);
                    if done {
                        let i = w.instances.get_mut(&n).unwrap();
                        i.boots += (status == "Running") as usize;
                        i.status = status.into();
                    }
                    r
                }
                ("POST", []) => {
                    let Some(to) = body["name"].as_str().map(String::from) else {
                        return err(400, "No name provided");
                    };
                    if i.status != "Stopped" {
                        return err(400, "Renaming of running instance not allowed");
                    }
                    if w.instances.contains_key(&to) {
                        return err(409, &format!("Instance {to:?} already exists"));
                    }
                    let (r, done) = w.op(vec![instance_url(&n, &project)], None);
                    if done {
                        let i = w.instances.remove(&n).unwrap();
                        w.instances.insert(to, i);
                    }
                    r
                }
                ("POST", ["backups"]) => {
                    let Some(b) = body["name"].as_str().map(String::from) else {
                        return err(400, "No name provided");
                    };
                    if w.backups.contains_key(&(n.clone(), b.clone())) {
                        return err(409, "Backup already exists");
                    }
                    let pc = w.projects.get(&project).cloned().unwrap_or_default();
                    if pc["restricted"] == "true" && pc["restricted.backups"] != "allow" {
                        return err(500, &format!("Project {project:?} doesn't allow for backup creation"));
                    }
                    let files: serde_json::Map<String, Value> = i
                        .files
                        .iter()
                        .map(|(p, (c, m))| (p.clone(), json!([String::from_utf8_lossy(c), m])))
                        .collect();
                    let saved = json!({ "body": i.body, "files": files, "instanceOnly": body["instance_only"] });
                    let (r, done) = w.op(vec![instance_url(&n, &project)], None);
                    if done {
                        w.backups.insert((n.clone(), b), saved.to_string().into_bytes());
                    }
                    r
                }
                ("GET", ["backups", b, "export"]) => match w.backups.get(&(n.clone(), b.to_string())) {
                    Some(bytes) => (StatusCode::OK, [("content-type", "application/octet-stream")], bytes.clone()).into_response(),
                    None => err(404, "Backup not found"),
                },
                ("DELETE", ["backups", b]) => {
                    if w.backups.remove(&(n.clone(), b.to_string())).is_none() {
                        return err(404, "Backup not found");
                    }
                    w.op(vec![instance_url(&n, &project)], None).0
                }
                (m @ ("POST" | "GET" | "DELETE"), ["files"]) => {
                    let Some(path) = query.get("path").cloned() else {
                        return err(400, "Missing path argument");
                    };
                    let i = w.instances.get_mut(&n).unwrap();
                    match m {
                        "POST" => {
                            let mode = header("x-incus-mode").unwrap_or("0644".into());
                            i.files.insert(path, (bytes.to_vec(), mode));
                            sync(json!({}))
                        }
                        "GET" => match i.files.get(&path) {
                            Some((c, _)) => (StatusCode::OK, c.clone()).into_response(),
                            None => err(404, "Not found"),
                        },
                        _ => match i.files.remove(&path) {
                            Some(_) => sync(json!({})),
                            None => err(404, "Not found"),
                        },
                    }
                }
                ("POST", ["rebuild"]) => {
                    if i.status != "Stopped" {
                        return err(400, "Instance must be stopped to be rebuilt");
                    }
                    let (r, done) =
                        w.op_with(vec![instance_url(&n, &project)], None, Some((n.clone(), body["source"].clone())));
                    if done {
                        let i = w.instances.get_mut(&n).unwrap();
                        i.rebuilt += 1;
                        i.source = body["source"].clone();
                    }
                    r
                }
                _ => err(404, "Not found"),
            }
        }
        ("GET", ["1.0", "operations"]) => {
            let mut by: BTreeMap<String, Vec<Value>> = BTreeMap::new();
            for (id, o) in &w.ops {
                by.entry(o.status.to_ascii_lowercase()).or_default().push(op_json(id, o));
            }
            sync(json!(by))
        }
        ("GET", ["1.0", "operations", id, "wait"]) => match w.ops.get(*id) {
            Some(o) => sync(op_json(id, o)),
            None => err(404, "Operation not found"),
        },
        ("POST", ["1.0", "network-acls"]) => {
            let Some(n) = body["name"].as_str().map(String::from) else {
                return err(400, "No name provided");
            };
            if w.acls.contains_key(&n) {
                return err(400, "The network ACL already exists");
            }
            let mut acl = body.clone();
            acl.as_object_mut().unwrap().remove("name");
            w.acls.insert(n, acl);
            reply(StatusCode::CREATED, json!({ "type": "sync", "status": "Success", "status_code": 200, "metadata": {} }), None)
        }
        (m, ["1.0", "network-acls", n]) => {
            let n = n.to_string();
            let Some(acl) = w.acls.get(&n).cloned() else {
                return err(404, "Network ACL not found");
            };
            let tag = etag(&acl);
            match m {
                "GET" => {
                    let mut v = acl.clone();
                    v["name"] = json!(n);
                    v["used_by"] = json!(w.used_by(&n));
                    reply(
                        StatusCode::OK,
                        json!({ "type": "sync", "status": "Success", "status_code": 200, "metadata": v }),
                        Some(tag),
                    )
                }
                "PUT" => {
                    if if_match.as_ref().is_some_and(|e| *e != tag) {
                        return err(412, "ETag doesn't match");
                    }
                    w.acls.insert(n, body);
                    sync(json!({}))
                }
                "DELETE" => {
                    if !w.used_by(&n).is_empty() {
                        return err(400, "Cannot delete an ACL that is in use");
                    }
                    w.acls.remove(&n);
                    sync(json!({}))
                }
                _ => err(405, "Method not allowed"),
            }
        }
        _ => err(404, "Not found"),
    }
}
