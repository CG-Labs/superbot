//! System containers on an Incus host behind `MachineProvider` (ADR 0065): a user's
//! machine is an unprivileged container with its own systemd, cloud-init, and OS
//! users, enrolled and reached exactly like a Linode. botd talks to the Incus REST API
//! over mutual TLS, pinned to the host's certificate. The client key goes in the TLS
//! handshake and nowhere else: not in errors, logs, or `Debug`.
//!
//! What keeps one container from another, the host, and botd's data:
//! - every container: unprivileged, its own id range (`security.idmap.isolated`), no
//!   nesting, no `/dev/incus` (`security.guestapi`), no profiles, one root disk from
//!   the pool and one NIC; nothing of the host's is mounted;
//! - the NIC: port isolation (no frames to other containers), MAC/IPv4/IPv6 spoofing
//!   filters, and the machines' network ACL (the firewall, ADR 0035): inbound only
//!   what the firewall's rules allow, outbound open to the internet but dropped to
//!   private, shared, and link-local ranges, the Incus host, and INCUS_EGRESS_DENY,
//!   except botd's machine port when MACHINE_CONTROL_URL is in one of those;
//! - the project must be restricted (`restricted=true`, nothing loosened to
//!   `allow`), checked before every create, so Incus itself refuses privileged
//!   containers, nesting, and host paths there.

use super::provider::{
    CreateSpec, FirewallDevices, FirewallRule, Fut, MachineProvider, ProviderError, ProviderFirewall,
    ProviderMachine, RebuildSpec,
};
use super::pki;
use crate::secrets::SecretStore;
use reqwest::{Method, StatusCode};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use serde_json::{Map, Value, json};
use std::net::IpAddr;
use std::time::Duration;

/// Plans: CPUs, memory GiB, disk GiB.
pub const DEFAULT_TIERS: &str = "starter=c1-m2-d20,pro=c2-m4-d40,max=c4-m8-d80";
/// A cloud variant, so cloud-init runs the enrollment user data.
pub const DEFAULT_IMAGE: &str = "ubuntu/24.04/cloud";
pub const DEFAULT_IMAGE_SERVER: &str = "https://images.linuxcontainers.org";
/// The region of a host that isn't a cluster. Anything else is a cluster member.
pub const LOCAL: &str = "local";
const DEFAULT_PORT: u16 = 8443;
/// Never reachable from a container, whatever the host's own addresses are.
pub const PRIVATE: [&str; 7] = [
    "10.0.0.0/8",
    "100.64.0.0/10",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "fc00::/7",
    "fe80::/10",
];
/// Project settings that would let a container out if set to `allow`.
const LOOSENED: [&str; 13] = [
    "restricted.containers.nesting",
    "restricted.containers.privilege",
    "restricted.containers.lowlevel",
    "restricted.containers.interception",
    "restricted.devices.disk",
    "restricted.devices.nic",
    "restricted.devices.proxy",
    "restricted.devices.unix-char",
    "restricted.devices.unix-block",
    "restricted.devices.unix-hotplug",
    "restricted.devices.usb",
    "restricted.devices.gpu",
    "restricted.devices.pci",
];
/// How long a create waits for the container before reporting it as provisioning.
/// A first create on a host also downloads the image, which takes longer; the
/// reconciler picks it up then.
const CREATE_WAIT: u64 = 20;
const STOP_WAIT: u64 = 30;
const FORCE_WAIT: u64 = 20;
const EDIT_WAIT: u64 = 30;
const REBUILD_WAIT: u64 = 60;

/// What a plan gives a container.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Size {
    pub cpus: u32,
    pub memory_gib: u32,
    pub disk_gib: u32,
}

impl Size {
    /// `c<cpus>-m<memory GiB>-d<disk GiB>`, e.g. `c2-m4-d40`.
    pub fn parse(plan: &str) -> Result<Size, String> {
        let bad = || {
            format!(
                "\"{}\" isn't an Incus plan: c<cpus>-m<memory GiB>-d<disk GiB>, e.g. c2-m4-d40",
                crate::audit::clip(plan, 40)
            )
        };
        let num = |s: &str, prefix: char, max: u32| {
            s.strip_prefix(prefix)
                .filter(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()) && !n.starts_with('0'))
                .and_then(|n| n.parse::<u32>().ok())
                .filter(|n| *n <= max)
        };
        let parts: Vec<&str> = plan.split('-').collect();
        let [c, m, d] = parts[..] else {
            return Err(bad());
        };
        Ok(Size {
            cpus: num(c, 'c', 256).ok_or_else(bad)?,
            memory_gib: num(m, 'm', 4096).ok_or_else(bad)?,
            disk_gib: num(d, 'd', 65536).ok_or_else(bad)?,
        })
    }

    /// Enough for a desktop and a few harnesses, not for a fork bomb.
    pub fn processes(&self) -> u32 {
        (self.memory_gib * 1024).max(2048)
    }

    fn limits(&self) -> [(&'static str, String); 5] {
        [
            ("limits.cpu", self.cpus.to_string()),
            ("limits.memory", format!("{}GiB", self.memory_gib)),
            ("limits.memory.enforce", "hard".into()),
            ("limits.memory.swap", "false".into()),
            ("limits.processes", self.processes().to_string()),
        ]
    }

    pub fn view(&self) -> Value {
        json!({ "cpus": self.cpus, "memoryGiB": self.memory_gib, "diskGiB": self.disk_gib, "processes": self.processes() })
    }
}

/// One rule of a network ACL, as Incus has it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Rule {
    pub action: String,
    pub protocol: String,
    pub source: String,
    pub destination: String,
    pub destination_port: String,
    pub description: String,
    pub enabled: bool,
}

impl Rule {
    fn json(&self) -> Value {
        let mut v = json!({ "action": self.action, "state": if self.enabled { "enabled" } else { "disabled" } });
        for (k, x) in [
            ("protocol", &self.protocol),
            ("source", &self.source),
            ("destination", &self.destination),
            ("destination_port", &self.destination_port),
            ("description", &self.description),
        ] {
            if !x.is_empty() {
                v[k] = json!(x);
            }
        }
        v
    }

    fn read(v: &Value) -> Option<Rule> {
        let text = |k: &str| v[k].as_str().unwrap_or_default().replace(' ', "");
        if ["source_port", "icmp_type", "icmp_code"]
            .iter()
            .any(|k| v[*k].as_str().is_some_and(|s| !s.is_empty()))
        {
            return None;
        }
        Some(Rule {
            action: v["action"].as_str()?.into(),
            protocol: text("protocol"),
            source: text("source"),
            destination: text("destination"),
            destination_port: text("destination_port"),
            description: v["description"].as_str().unwrap_or_default().into(),
            enabled: !matches!(v["state"].as_str(), Some("disabled" | "logged")),
        })
    }

    /// What the rule does, whatever it is called or whether it is on.
    fn effect(&self) -> (String, String, String, String, String) {
        (
            self.action.clone(),
            self.protocol.clone(),
            self.source.clone(),
            self.destination.clone(),
            self.destination_port.clone(),
        )
    }
}

/// An address as a number, and whether it is IPv6.
fn number(ip: IpAddr) -> (bool, u128) {
    match ip {
        IpAddr::V4(a) => (false, u32::from(a) as u128),
        IpAddr::V6(a) => (true, u128::from(a)),
    }
}

fn address(v6: bool, n: u128) -> IpAddr {
    if v6 {
        IpAddr::V6(n.into())
    } else {
        IpAddr::V4((n as u32).into())
    }
}

/// A canonical CIDR's first and last address.
fn span(cidr: &str) -> Option<(bool, u128, u128)> {
    let (ip, len) = cidr.split_once('/')?;
    let (v6, n) = number(ip.parse().ok()?);
    let len: u32 = len.parse().ok()?;
    let bits = if v6 { 128 } else { 32 };
    if len > bits {
        return None;
    }
    let host = if len == bits {
        0
    } else if v6 {
        u128::MAX >> len
    } else {
        (1u128 << (32 - len)) - 1
    };
    Some((v6, n & !host, n | host))
}

fn piece(v6: bool, lo: u128, hi: u128) -> String {
    if lo == hi {
        address(v6, lo).to_string()
    } else {
        format!("{}-{}", address(v6, lo), address(v6, hi))
    }
}

/// The outbound rules every container gets: TCP and UDP dropped to `deny`, but for
/// `control` (botd's machine address and port) when it falls inside it. Everything
/// else outbound is allowed, so harnesses reach their APIs and package mirrors.
pub fn egress(deny: &[String], control: Option<(IpAddr, u16)>) -> Vec<Rule> {
    let mut out = Vec::new();
    let mut carved = false;
    for (v6, family) in [(false, "IPv4"), (true, "IPv6")] {
        let mut dest = Vec::new();
        for c in deny {
            let Some((is6, lo, hi)) = span(c) else { continue };
            if is6 != v6 {
                continue;
            }
            let inside = control
                .map(|(ip, _)| number(ip))
                .filter(|(c6, n)| *c6 == v6 && (lo..=hi).contains(n));
            match inside {
                None => dest.push(c.clone()),
                Some((_, n)) => {
                    carved = true;
                    if n > lo {
                        dest.push(piece(v6, lo, n - 1));
                    }
                    if n < hi {
                        dest.push(piece(v6, n + 1, hi));
                    }
                }
            }
        }
        if dest.is_empty() {
            continue;
        }
        for protocol in ["tcp", "udp"] {
            out.push(Rule {
                action: "drop".into(),
                protocol: protocol.into(),
                destination: dest.join(","),
                description: format!("superbot: no {protocol} to private or host addresses ({family})"),
                enabled: true,
                ..Rule::default()
            });
        }
    }
    if let (true, Some((ip, port))) = (carved, control) {
        let ports: Vec<String> = [(1u32, port as u32 - 1), (port as u32 + 1, 65535)]
            .into_iter()
            .filter(|(lo, hi)| lo <= hi)
            .map(|(lo, hi)| if lo == hi { lo.to_string() } else { format!("{lo}-{hi}") })
            .collect();
        if !ports.is_empty() {
            out.push(Rule {
                action: "drop".into(),
                protocol: "tcp".into(),
                destination: ip.to_string(),
                destination_port: ports.join(","),
                description: "superbot: only the machine port on the control plane".into(),
                enabled: true,
                ..Rule::default()
            });
        }
        out.push(Rule {
            action: "drop".into(),
            protocol: "udp".into(),
            destination: ip.to_string(),
            description: "superbot: no udp to the control plane".into(),
            enabled: true,
            ..Rule::default()
        });
    }
    out
}

/// The firewall's rules as an ACL's inbound rules.
fn ingress(rules: &[FirewallRule]) -> Vec<Rule> {
    rules
        .iter()
        .flat_map(|r| {
            let (v6, v4): (Vec<&String>, Vec<&String>) = r.sources.iter().partition(|s| s.contains(':'));
            [v4, v6].into_iter().filter(|s| !s.is_empty()).map(|sources| Rule {
                action: "allow".into(),
                protocol: "tcp".into(),
                source: sources.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(","),
                destination_port: r.ports.clone(),
                description: r.label.clone(),
                enabled: true,
                ..Rule::default()
            })
        })
        .collect()
}

/// An ACL's inbound rules as the firewall's, or None if they aren't of the shape
/// `ingress` makes. Rules split by address family are joined again.
fn our_ingress(rules: &[Rule]) -> Option<Vec<FirewallRule>> {
    let mut out: Vec<FirewallRule> = Vec::new();
    for r in rules {
        if r.action != "allow" || r.protocol != "tcp" || !r.destination.is_empty() || r.source.is_empty() {
            return None;
        }
        let sources = r
            .source
            .split(',')
            .map(|s| super::firewall::cidr(s).ok())
            .collect::<Option<Vec<_>>>()?;
        match out.last_mut() {
            Some(last) if last.label == r.description && last.ports == r.destination_port => {
                last.sources.extend(sources)
            }
            _ => out.push(FirewallRule {
                label: r.description.clone(),
                ports: r.destination_port.clone(),
                sources,
            }),
        }
    }
    for r in &mut out {
        r.sources.sort();
        r.sources.dedup();
    }
    Some(out)
}

/// Lowercase letters, digits, and inner dashes, starting with a letter: what an
/// instance or ACL name may be here, and never anything a URL path would bend.
fn name(n: &str) -> Result<&str, ProviderError> {
    let ok = !n.is_empty()
        && n.len() <= 63
        && n.starts_with(|c: char| c.is_ascii_lowercase())
        && !n.ends_with('-')
        && n.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
    if ok {
        Ok(n)
    } else {
        Err(ProviderError::Api {
            status: 400,
            message: "not an Incus name".into(),
        })
    }
}

fn slug(s: &str) -> bool {
    name(s).is_ok()
}

/// `https://host[:port]` with nothing else in it: the base URL and the host.
fn https_base(var: &str, raw: &str) -> Result<(String, url::Host<String>), String> {
    let bad = || format!("{var} must be https://host[:port], not \"{}\"", crate::audit::clip(raw, 80));
    let u = url::Url::parse(raw.trim()).map_err(|_| bad())?;
    if u.scheme() != "https"
        || !u.username().is_empty()
        || u.password().is_some()
        || !matches!(u.path(), "" | "/")
        || u.query().is_some()
        || u.fragment().is_some()
    {
        return Err(bad());
    }
    let host = u.host().ok_or_else(bad)?.to_owned();
    let port = u.port().unwrap_or(DEFAULT_PORT);
    Ok((format!("https://{}:{port}", u.host_str().unwrap_or_default()), host))
}

fn ip_of(host: &url::Host<String>) -> Option<IpAddr> {
    match host {
        url::Host::Ipv4(a) => Some(IpAddr::V4(*a)),
        url::Host::Ipv6(a) => Some(IpAddr::V6(*a)),
        url::Host::Domain(_) => None,
    }
}

/// Where and how botd reaches the Incus host. No credentials.
#[derive(Clone, Debug)]
pub struct Settings {
    pub url: String,
    pub project: String,
    pub network: String,
    pub pool: String,
    /// None: images already on the host, by alias.
    pub image_server: Option<String>,
    /// What containers never reach, canonical CIDRs.
    pub deny: Vec<String>,
    /// botd's machine address and port, when it is an IP.
    pub control: Option<(IpAddr, u16)>,
}

impl Settings {
    /// INCUS_URL (needed), INCUS_PROJECT, INCUS_NETWORK, INCUS_STORAGE_POOL,
    /// INCUS_IMAGE_SERVER, INCUS_EGRESS_DENY, and MACHINE_CONTROL_URL.
    pub fn from_env(var: &dyn Fn(&str) -> String) -> Result<Settings, String> {
        let or = |k: &str, d: &str| Some(var(k).trim().to_string()).filter(|v| !v.is_empty()).unwrap_or_else(|| d.into());
        let raw = var("INCUS_URL");
        if raw.trim().is_empty() {
            return Err("INCUS_URL is needed with MACHINE_PROVIDER=incus, e.g. https://<incus-host>:8443".into());
        }
        let (url, host) = https_base("INCUS_URL", &raw)?;
        let mut names = Vec::new();
        for (k, d) in [("INCUS_PROJECT", "superbot"), ("INCUS_NETWORK", "incusbr0"), ("INCUS_STORAGE_POOL", "default")] {
            let v = or(k, d);
            if !slug(&v) {
                return Err(format!("{k}: \"{}\" isn't an Incus name", crate::audit::clip(&v, 40)));
            }
            names.push(v);
        }
        if names[0] == "default" {
            return Err("INCUS_PROJECT can't be the default project: make a restricted one for SuperBot (docs/ops/incus-containers.md)".into());
        }
        let image_server = match or("INCUS_IMAGE_SERVER", DEFAULT_IMAGE_SERVER).as_str() {
            "local" => None,
            s => {
                https_base("INCUS_IMAGE_SERVER", s)?;
                Some(s.trim_end_matches('/').to_string())
            }
        };
        let mut deny: Vec<String> = PRIVATE.iter().map(|s| s.to_string()).collect();
        for c in var("INCUS_EGRESS_DENY").split(',').map(str::trim).filter(|s| !s.is_empty()) {
            deny.push(super::firewall::cidr(c).map_err(|e| format!("INCUS_EGRESS_DENY: {e}"))?);
        }
        if let Some(ip) = ip_of(&host) {
            deny.push(super::firewall::cidr(&ip.to_string())?);
        }
        deny.sort();
        deny.dedup();
        let control = url::Url::parse(var("MACHINE_CONTROL_URL").trim())
            .ok()
            .and_then(|u| Some((ip_of(&u.host()?.to_owned())?, u.port_or_known_default()?)));
        let [project, network, pool] = <[String; 3]>::try_from(names).unwrap();
        Ok(Settings { url, project, network, pool, image_server, deny, control })
    }
}

/// botd's client certificate and key, and the Incus host's certificate it pins.
pub struct Credentials {
    pub cert: CertificateDer<'static>,
    pub key: PrivateKeyDer<'static>,
    pub server: CertificateDer<'static>,
}

impl Credentials {
    /// INCUS_CLIENT_CERT, INCUS_CLIENT_KEY, INCUS_SERVER_CERT (PEM, or `_FILE`).
    pub fn from_store(store: &dyn SecretStore) -> Result<Credentials, String> {
        let get = |k: &str| -> Result<String, String> {
            let v = store
                .get(k)
                .map_err(|e| e.to_string())?
                .ok_or(format!("{k} (or {k}_FILE) is needed with MACHINE_PROVIDER=incus"))?;
            Ok(v.expose().trim().to_string())
        };
        let key = get("INCUS_CLIENT_KEY")?;
        crate::secrets::redact::register(&key);
        Ok(Credentials {
            cert: pki::cert_der(&get("INCUS_CLIENT_CERT")?).map_err(|e| format!("INCUS_CLIENT_CERT: {e}"))?,
            key: pki::key_der(&key).map_err(|e| format!("INCUS_CLIENT_KEY: {e}"))?,
            server: pki::cert_der(&get("INCUS_SERVER_CERT")?).map_err(|e| format!("INCUS_SERVER_CERT: {e}"))?,
        })
    }
}

pub struct Incus {
    s: Settings,
    egress: Vec<Rule>,
    pin: String,
    http: reqwest::Client,
}

impl std::fmt::Debug for Incus {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.debug_struct("Incus")
            .field("url", &self.s.url)
            .field("project", &self.s.project)
            .field("server", &self.pin)
            .field("key", &"[redacted]")
            .finish()
    }
}

/// An answer from Incus: the metadata, the operation it started if any, and the ETag.
struct Reply {
    metadata: Value,
    operation: Option<String>,
    etag: Option<String>,
}

fn api(status: u16, message: impl Into<String>) -> ProviderError {
    ProviderError::Api {
        status,
        message: crate::audit::clip(&message.into(), 300),
    }
}

/// Incus's `{"type": "error", "error": ..., "error_code": ...}` as one of ours. Taken
/// names come back as 400, 409, or 500 depending on the endpoint, so the words decide.
fn error(status: StatusCode, v: &Value) -> ProviderError {
    let message = v["error"]
        .as_str()
        .filter(|m| !m.is_empty())
        .unwrap_or(status.canonical_reason().unwrap_or("error"));
    if message.contains("already exists") {
        return ProviderError::LabelTaken;
    }
    match status {
        StatusCode::NOT_FOUND => ProviderError::NotFound,
        StatusCode::TOO_MANY_REQUESTS => ProviderError::RateLimited,
        _ => api(status.as_u16(), message),
    }
}

fn operation_id(op: &str) -> Result<&str, ProviderError> {
    let id = op.strip_prefix("/1.0/operations/").unwrap_or(op);
    if !id.is_empty() && id.len() <= 64 && id.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-') {
        Ok(id)
    } else {
        Err(ProviderError::Transport("Incus sent an operation we couldn't read".into()))
    }
}

/// The instance an Incus URL names, and its project.
fn instance_of(url: &str) -> Option<(String, String)> {
    let u = url::Url::parse(&format!("https://incus{url}")).ok()?;
    let n = u.path().strip_prefix("/1.0/instances/")?;
    if n.is_empty() || n.contains('/') {
        return None;
    }
    let project = u
        .query_pairs()
        .find(|(k, _)| k == "project")
        .map_or("default".to_string(), |(_, v)| v.into_owned());
    Some((n.to_string(), project))
}

/// The container as a provider machine.
fn machine(v: &Value) -> Result<ProviderMachine, ProviderError> {
    let n = v["name"]
        .as_str()
        .ok_or_else(|| ProviderError::Transport("Incus sent an instance we couldn't read".into()))?;
    let config = &v["config"];
    let text = |k: &str| config[k].as_str().unwrap_or_default().to_string();
    let ipv4 = v["state"]["network"]["eth0"]["addresses"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|a| a["family"] == "inet" && a["scope"] == "global")
        .and_then(|a| a["address"].as_str())
        .map(String::from);
    Ok(ProviderMachine {
        id: n.into(),
        label: n.into(),
        status: v["status"].as_str().unwrap_or("unknown").to_ascii_lowercase(),
        plan: text("user.superbot.plan"),
        region: match v["location"].as_str() {
            None | Some("" | "none") => LOCAL.into(),
            Some(l) => l.into(),
        },
        ipv4,
        backups: !text("snapshots.schedule").is_empty(),
        tags: text("user.superbot.tags")
            .split(',')
            .filter(|t| !t.is_empty())
            .map(String::from)
            .collect(),
    })
}

/// A container whose create is still running: not there yet, but not gone.
fn provisioning(n: &str) -> ProviderMachine {
    ProviderMachine {
        id: n.into(),
        label: n.into(),
        status: "provisioning".into(),
        plan: String::new(),
        region: String::new(),
        ipv4: None,
        backups: false,
        tags: Vec::new(),
    }
}

/// SSH keys for root, as Linode puts them (ADR 0025); cloud-init merges this under
/// the enrollment user data.
fn vendor_data(keys: &[String]) -> String {
    let mut out = String::from("#cloud-config\ndisable_root: false\nssh_authorized_keys:\n");
    for k in keys {
        out.push_str(&format!("  - {}\n", Value::from(k.as_str())));
    }
    out
}

impl Incus {
    pub fn new(s: Settings, c: Credentials) -> Result<Incus, String> {
        let pin = pki::fingerprint(&c.server);
        let (tls, _) = pki::pinned_client_config(vec![pin.clone()], vec![c.cert], c.key)?;
        let http = reqwest::Client::builder()
            .tls_backend_preconfigured(tls)
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(REBUILD_WAIT + 30))
            .user_agent(concat!("superbot-botd/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|e| format!("Incus client: {e}"))?;
        let egress = egress(&s.deny, s.control);
        Ok(Incus { s, egress, pin, http })
    }

    async fn call(
        &self,
        method: Method,
        path: &str,
        query: &[(&str, &str)],
        body: Option<&Value>,
        if_match: Option<&str>,
    ) -> Result<Reply, ProviderError> {
        let q = {
            let mut q = url::form_urlencoded::Serializer::new(String::new());
            q.append_pair("project", &self.s.project);
            for (k, v) in query {
                q.append_pair(k, v);
            }
            q.finish()
        };
        let mut req = self.http.request(method, format!("{}{path}?{q}", self.s.url));
        if let Some(b) = body {
            req = req.json(b);
        }
        if let Some(e) = if_match {
            req = req.header("If-Match", e);
        }
        // reqwest's errors name the URL, which holds no credentials.
        let res = req
            .send()
            .await
            .map_err(|e| ProviderError::Transport(format!("Incus: {}", e.without_url())))?;
        let status = res.status();
        let etag = res
            .headers()
            .get("etag")
            .and_then(|e| e.to_str().ok())
            .map(String::from);
        let text = res
            .text()
            .await
            .map_err(|e| ProviderError::Transport(format!("Incus: {}", e.without_url())))?;
        let v: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
        if !status.is_success() || v["type"] == "error" {
            return Err(error(status, &v));
        }
        Ok(Reply {
            operation: (v["type"] == "async")
                .then(|| v["operation"].as_str().map(String::from))
                .flatten(),
            metadata: v["metadata"].clone(),
            etag,
        })
    }

    /// Waits up to `secs` for an operation. True once it succeeded; false while it
    /// still runs. A failed one is Incus refusing.
    async fn wait(&self, op: &str, secs: u64) -> Result<bool, ProviderError> {
        let id = operation_id(op)?;
        let timeout = secs.to_string();
        match self
            .call(Method::GET, &format!("/1.0/operations/{id}/wait"), &[("timeout", &timeout)], None, None)
            .await
        {
            Ok(r) => match r.metadata["status"].as_str() {
                Some("Success") => Ok(true),
                Some("Failure" | "Cancelled") => Err(api(
                    400,
                    r.metadata["err"].as_str().filter(|e| !e.is_empty()).unwrap_or("the operation failed"),
                )),
                _ => Ok(false),
            },
            // Done and forgotten already.
            Err(ProviderError::NotFound) => Ok(true),
            Err(e) => Err(e),
        }
    }

    /// The reply's operation finished within `secs`, or an error saying what is
    /// still going on, which the reconciler retries.
    async fn finish(&self, r: Reply, secs: u64, doing: &str) -> Result<(), ProviderError> {
        let Some(op) = r.operation else { return Ok(()) };
        if self.wait(&op, secs).await? {
            Ok(())
        } else {
            Err(ProviderError::Transport(format!("Incus is still {doing}")))
        }
    }

    async fn instance(&self, n: &str) -> Result<Value, ProviderError> {
        Ok(self
            .call(Method::GET, &format!("/1.0/instances/{}", name(n)?), &[("recursion", "1")], None, None)
            .await?
            .metadata)
    }

    /// Whether a create of `n` is still running.
    async fn creating(&self, n: &str) -> Result<bool, ProviderError> {
        let ops = self.call(Method::GET, "/1.0/operations", &[("recursion", "1")], None, None).await?;
        let url = format!("/1.0/instances/{n}");
        Ok(ops
            .metadata
            .as_object()
            .into_iter()
            .flat_map(|o| o.values())
            .filter_map(Value::as_array)
            .flatten()
            .filter(|op| matches!(op["status"].as_str(), Some("Running" | "Pending")))
            .flat_map(|op| op["resources"]["instances"].as_array().cloned().unwrap_or_default())
            .any(|u| u.as_str().and_then(instance_of).is_some_and(|(i, p)| i == n && p == self.s.project) || u == url.as_str()))
    }

    /// Changes the instance's config and devices with `f`, retrying if it changed
    /// meanwhile.
    async fn edit(&self, n: &str, f: impl Fn(&mut Value)) -> Result<(), ProviderError> {
        let path = format!("/1.0/instances/{}", name(n)?);
        for _ in 0..3 {
            let r = self.call(Method::GET, &path, &[], None, None).await?;
            let v = &r.metadata;
            let mut put = json!({
                "architecture": v["architecture"],
                "config": v["config"],
                "devices": v["devices"],
                "ephemeral": v["ephemeral"],
                "profiles": v["profiles"],
                "stateful": v["stateful"],
                "description": v["description"],
            });
            f(&mut put);
            match self.call(Method::PUT, &path, &[], Some(&put), r.etag.as_deref()).await {
                Err(ProviderError::Api { status: 412, .. }) => continue,
                res => return self.finish(res?, EDIT_WAIT, "changing the container").await,
            }
        }
        Err(ProviderError::Transport("the container kept changing at Incus".into()))
    }

    async fn status(&self, n: &str) -> Result<String, ProviderError> {
        Ok(self.instance(n).await?["status"].as_str().unwrap_or_default().to_string())
    }

    async fn set_state(&self, n: &str, action: &str, force: bool, secs: u64) -> Result<(), ProviderError> {
        let body = json!({ "action": action, "force": force, "timeout": if force { -1 } else { secs as i64 }, "stateful": false });
        let r = self
            .call(Method::PUT, &format!("/1.0/instances/{}/state", name(n)?), &[], Some(&body), None)
            .await?;
        self.finish(r, secs + 5, &format!("{action}ing the container")).await
    }

    /// Stops it: cleanly if `force` is off and that works in time, else at once.
    async fn stop(&self, n: &str, force: bool) -> Result<(), ProviderError> {
        if self.status(n).await? == "Stopped" {
            return Ok(());
        }
        if !force {
            match self.set_state(n, "stop", false, STOP_WAIT).await {
                Ok(()) => return Ok(()),
                Err(ProviderError::Api { .. }) => {}
                Err(e) => return Err(e),
            }
        }
        self.set_state(n, "stop", true, FORCE_WAIT).await
    }

    async fn start(&self, n: &str) -> Result<(), ProviderError> {
        if self.status(n).await? == "Running" {
            return Ok(());
        }
        self.set_state(n, "start", false, FORCE_WAIT).await
    }

    /// Refuses to make containers unless the project keeps them in (module docs).
    async fn check_project(&self) -> Result<(), ProviderError> {
        let p = self
            .call(Method::GET, &format!("/1.0/projects/{}", self.s.project), &[], None, None)
            .await?
            .metadata;
        let c = &p["config"];
        let refuse = |why: String| {
            api(
                409,
                format!(
                    "Incus project {} {why}, so botd won't make containers in it (docs/ops/incus-containers.md)",
                    self.s.project
                ),
            )
        };
        if c["restricted"] != "true" {
            return Err(refuse("isn't restricted (restricted=true)".into()));
        }
        if let Some(k) = LOOSENED.iter().find(|k| c[**k] == "allow") {
            return Err(refuse(format!("allows {k}")));
        }
        if c["restricted.devices.disk.paths"].as_str().is_some_and(|p| !p.is_empty()) {
            return Err(refuse("lets containers mount host paths (restricted.devices.disk.paths)".into()));
        }
        if c["restricted.idmap.uid"].as_str().is_some_and(|p| !p.is_empty())
            || c["restricted.idmap.gid"].as_str().is_some_and(|p| !p.is_empty())
        {
            return Err(refuse("lets containers map host ids (restricted.idmap.*)".into()));
        }
        Ok(())
    }

    fn source(&self, image: &str) -> Value {
        match &self.s.image_server {
            Some(server) => json!({ "type": "image", "alias": image, "server": server, "protocol": "simplestreams" }),
            None => json!({ "type": "image", "alias": image }),
        }
    }

    /// The one NIC: on the network, cut off from every other container, unable to
    /// claim another address, behind `acl`.
    fn nic(&self, acl: &str) -> Value {
        json!({
            "type": "nic",
            "network": self.s.network,
            "name": "eth0",
            "security.port_isolation": "true",
            "security.mac_filtering": "true",
            "security.ipv4_filtering": "true",
            "security.ipv6_filtering": "true",
            "security.acls": acl,
            "security.acls.default.ingress.action": "drop",
            "security.acls.default.egress.action": "allow",
        })
    }

    fn root(&self, size: &Size) -> Value {
        json!({ "type": "disk", "path": "/", "pool": self.s.pool, "size": format!("{}GiB", size.disk_gib) })
    }

    fn acl_body(&self, ingress_rules: &[Rule], description: &Value, config: &Value) -> Value {
        json!({
            "description": description,
            "config": config,
            "ingress": ingress_rules.iter().map(Rule::json).collect::<Vec<_>>(),
            "egress": self.egress.iter().map(Rule::json).collect::<Vec<_>>(),
        })
    }

    fn firewall(&self, v: &Value) -> Result<ProviderFirewall, ProviderError> {
        let n = v["name"]
            .as_str()
            .ok_or_else(|| ProviderError::Transport("Incus sent an ACL we couldn't read".into()))?;
        let read = |k: &str| -> Option<Vec<Rule>> { v[k].as_array()?.iter().map(Rule::read).collect() };
        let (ingress_rules, egress_rules) = (read("ingress"), read("egress"));
        let enabled = [&ingress_rules, &egress_rules]
            .iter()
            .all(|r| r.as_ref().is_none_or(|r| r.iter().all(|x| x.enabled)));
        let ours = |got: &[Rule], want: &[Rule]| {
            let mut a: Vec<_> = got.iter().map(Rule::effect).collect();
            let mut b: Vec<_> = want.iter().map(Rule::effect).collect();
            a.sort();
            b.sort();
            a == b
        };
        let rules = match (ingress_rules, egress_rules) {
            (Some(i), Some(e)) if ours(&e, &self.egress) => our_ingress(&i),
            _ => None,
        };
        Ok(ProviderFirewall {
            id: n.into(),
            label: n.into(),
            rules,
            enabled,
        })
    }

    async fn acl(&self, id: &str) -> Result<Reply, ProviderError> {
        self.call(Method::GET, &format!("/1.0/network-acls/{}", name(id)?), &[], None, None)
            .await
    }

    /// Rewrites the ACL with `ingress_rules` and our outbound rules.
    async fn put_acl(&self, id: &str, change: impl Fn(&Value) -> Vec<Rule>) -> Result<(), ProviderError> {
        for _ in 0..3 {
            let r = self.acl(id).await?;
            let body = self.acl_body(&change(&r.metadata), &r.metadata["description"], &r.metadata["config"]);
            match self
                .call(Method::PUT, &format!("/1.0/network-acls/{}", name(id)?), &[], Some(&body), r.etag.as_deref())
                .await
            {
                Err(ProviderError::Api { status: 412, .. }) => continue,
                res => return res.map(drop),
            }
        }
        Err(ProviderError::Transport("the ACL kept changing at Incus".into()))
    }

    async fn check(&self, check: &str, f: impl Future<Output = Result<String, ProviderError>>) -> Value {
        match f.await {
            Ok(detail) => json!({ "check": check, "ok": true, "detail": detail }),
            Err(e) => json!({ "check": check, "ok": false, "detail": e.to_string() }),
        }
    }
}

impl MachineProvider for Incus {
    fn name(&self) -> &'static str {
        "incus"
    }

    fn substrate(&self) -> &'static str {
        "container"
    }

    fn default_tiers(&self) -> &'static str {
        DEFAULT_TIERS
    }

    fn default_image(&self) -> &'static str {
        DEFAULT_IMAGE
    }

    fn check_plan(&self, plan: &str) -> Result<(), String> {
        Size::parse(plan).map(drop)
    }

    fn plan_view(&self, plan: &str) -> Option<Value> {
        Size::parse(plan).ok().map(|s| s.view())
    }

    fn settings(&self) -> Value {
        json!({
            "url": self.s.url,
            "serverCertificate": self.pin,
            "project": self.s.project,
            "network": self.s.network,
            "storagePool": self.s.pool,
            "imageServer": self.s.image_server.as_deref().unwrap_or("local"),
            "egressDenied": self.s.deny,
            "controlPlane": self.s.control.map(|(ip, port)| format!("{ip}:{port}")),
            "egressRules": self.egress.iter().map(Rule::json).collect::<Vec<_>>(),
            "isolation": [
                "unprivileged, with its own id range (security.idmap.isolated)",
                "no nesting, no /dev/incus (security.guestapi=false), no profiles",
                "one root disk from the pool; no host paths",
                "one NIC with port isolation and MAC/IPv4/IPv6 filtering",
                "the machines' network ACL: inbound only the firewall's rules; outbound no TCP/UDP to egressDenied",
                "a restricted project, checked before every create",
            ],
        })
    }

    fn preflight<'a>(&'a self) -> Fut<'a, Vec<Value>> {
        Box::pin(async move {
            let mut out = vec![
                self.check("server", async {
                    let v = self.call(Method::GET, "/1.0", &[], None, None).await?.metadata;
                    if v["auth"] != "trusted" {
                        return Err(api(403, "Incus doesn't trust botd's client certificate yet"));
                    }
                    let have = |x: &str| v["api_extensions"].as_array().is_some_and(|a| a.iter().any(|e| e == x));
                    let missing: Vec<&str> = ["network_acl", "instances_rebuild", "instance_create_start"]
                        .into_iter()
                        .filter(|x| !have(x))
                        .collect();
                    if !missing.is_empty() {
                        return Err(api(400, format!("Incus lacks API extensions: {}", missing.join(", "))));
                    }
                    Ok(format!("Incus {} trusts botd", v["environment"]["server_version"].as_str().unwrap_or("?")))
                })
                .await,
            ];
            out.push(
                self.check("project", async {
                    self.check_project().await?;
                    Ok(format!("{} is restricted", self.s.project))
                })
                .await,
            );
            out.push(
                self.check("network", async {
                    let n = self
                        .call(Method::GET, &format!("/1.0/networks/{}", self.s.network), &[], None, None)
                        .await?
                        .metadata;
                    if n["type"] != "bridge" || n["managed"] != true {
                        return Err(api(400, format!("{} isn't a managed bridge", self.s.network)));
                    }
                    Ok(format!("{} is a managed bridge", self.s.network))
                })
                .await,
            );
            out.push(
                self.check("storage pool", async {
                    let p = self
                        .call(Method::GET, &format!("/1.0/storage-pools/{}", self.s.pool), &[], None, None)
                        .await?
                        .metadata;
                    let driver = p["driver"].as_str().unwrap_or("?");
                    if driver == "dir" {
                        return Err(api(400, format!("{} uses the dir driver, which doesn't enforce disk sizes; use zfs, btrfs or lvm", self.s.pool)));
                    }
                    Ok(format!("{} ({driver})", self.s.pool))
                })
                .await,
            );
            Ok(out)
        })
    }

    fn create<'a>(&'a self, spec: &'a CreateSpec) -> Fut<'a, ProviderMachine> {
        Box::pin(async move {
            let size = Size::parse(&spec.plan).map_err(|m| api(400, m))?;
            let n = name(&spec.label)?;
            let acl = spec
                .firewall_id
                .as_deref()
                .ok_or_else(|| api(400, "containers are made behind the machines' firewall (MACHINE_FIREWALL=on)"))?;
            name(acl)?;
            self.check_project().await?;
            let mut config = Map::new();
            for (k, v) in [
                ("security.privileged", "false"),
                ("security.nesting", "false"),
                ("security.idmap.isolated", "true"),
                ("security.guestapi", "false"),
            ] {
                config.insert(k.into(), json!(v));
            }
            for (k, v) in size.limits() {
                config.insert(k.into(), json!(v));
            }
            config.insert("user.superbot.tag".into(), json!(spec.tags.first().cloned().unwrap_or_default()));
            config.insert("user.superbot.tags".into(), json!(spec.tags.join(",")));
            config.insert("user.superbot.plan".into(), json!(spec.plan));
            if let Some(ud) = &spec.user_data {
                config.insert("cloud-init.user-data".into(), json!(ud));
            }
            if !spec.authorized_keys.is_empty() {
                config.insert("cloud-init.vendor-data".into(), json!(vendor_data(&spec.authorized_keys)));
            }
            let body = json!({
                "name": n,
                "type": "container",
                "start": true,
                "profiles": [],
                "description": "SuperBot machine",
                "source": self.source(&spec.image),
                "config": config,
                "devices": { "root": self.root(&size), "eth0": self.nic(acl) },
            });
            let target: Vec<(&str, &str)> = if spec.region == LOCAL {
                Vec::new()
            } else {
                vec![("target", spec.region.as_str())]
            };
            let r = self.call(Method::POST, "/1.0/instances", &target, Some(&body), None).await?;
            if let Some(op) = &r.operation {
                self.wait(op, CREATE_WAIT).await?;
            }
            self.get(n).await
        })
    }

    fn get<'a>(&'a self, id: &'a str) -> Fut<'a, ProviderMachine> {
        Box::pin(async move {
            match self.instance(id).await {
                Ok(v) => machine(&v),
                Err(ProviderError::NotFound) if self.creating(id).await? => Ok(provisioning(id)),
                Err(e) => Err(e),
            }
        })
    }

    fn list<'a>(&'a self, tag: &'a str) -> Fut<'a, Vec<ProviderMachine>> {
        Box::pin(async move {
            let r = self.call(Method::GET, "/1.0/instances", &[("recursion", "2")], None, None).await?;
            r.metadata
                .as_array()
                .into_iter()
                .flatten()
                .filter(|v| v["config"]["user.superbot.tag"] == tag)
                .map(machine)
                .collect()
        })
    }

    fn resize<'a>(&'a self, id: &'a str, plan: &'a str) -> Fut<'a, ()> {
        Box::pin(async move {
            let size = Size::parse(plan).map_err(|m| api(400, m))?;
            self.edit(id, |put| {
                for (k, v) in size.limits() {
                    put["config"][k] = json!(v);
                }
                put["config"]["user.superbot.plan"] = json!(plan);
                match put["devices"]["root"].as_object_mut() {
                    Some(root) => {
                        root.insert("size".into(), json!(format!("{}GiB", size.disk_gib)));
                    }
                    None => put["devices"]["root"] = self.root(&size),
                }
            })
            .await
        })
    }

    fn shutdown<'a>(&'a self, id: &'a str) -> Fut<'a, ()> {
        Box::pin(async move { self.stop(id, false).await })
    }

    fn boot<'a>(&'a self, id: &'a str) -> Fut<'a, ()> {
        Box::pin(async move { self.start(id).await })
    }

    /// Daily snapshots on the container's own pool, a week kept. Not off the host.
    fn enable_backups<'a>(&'a self, id: &'a str) -> Fut<'a, ()> {
        Box::pin(async move {
            self.edit(id, |put| {
                put["config"]["snapshots.schedule"] = json!("@daily");
                put["config"]["snapshots.expiry"] = json!("7d");
                put["config"]["snapshots.pattern"] = json!("superbot-%d");
            })
            .await
        })
    }

    fn delete<'a>(&'a self, id: &'a str) -> Fut<'a, ()> {
        Box::pin(async move {
            match self.stop(id, true).await {
                Ok(()) | Err(ProviderError::NotFound) => {}
                Err(e) => return Err(e),
            }
            match self
                .call(Method::DELETE, &format!("/1.0/instances/{}", name(id)?), &[], None, None)
                .await
            {
                Ok(r) => self.finish(r, FORCE_WAIT, "deleting the container").await,
                Err(ProviderError::NotFound) => Ok(()),
                Err(e) => Err(e),
            }
        })
    }

    fn rebuild<'a>(&'a self, id: &'a str, spec: &'a RebuildSpec) -> Fut<'a, ()> {
        Box::pin(async move {
            self.stop(id, true).await?;
            self.edit(id, |put| {
                put["config"]["cloud-init.user-data"] = json!(spec.user_data);
                if spec.authorized_keys.is_empty() {
                    if let Some(c) = put["config"].as_object_mut() {
                        c.remove("cloud-init.vendor-data");
                    }
                } else {
                    put["config"]["cloud-init.vendor-data"] = json!(vendor_data(&spec.authorized_keys));
                }
            })
            .await?;
            let r = self
                .call(
                    Method::POST,
                    &format!("/1.0/instances/{}/rebuild", name(id)?),
                    &[],
                    Some(&json!({ "source": self.source(&spec.image) })),
                    None,
                )
                .await?;
            self.finish(r, REBUILD_WAIT, "rebuilding the container").await?;
            self.start(id).await
        })
    }

    fn find_firewall<'a>(&'a self, label: &'a str) -> Fut<'a, Option<ProviderFirewall>> {
        Box::pin(async move {
            match self.acl(label).await {
                Ok(r) => self.firewall(&r.metadata).map(Some),
                Err(ProviderError::NotFound) => Ok(None),
                Err(e) => Err(e),
            }
        })
    }

    fn get_firewall<'a>(&'a self, id: &'a str) -> Fut<'a, ProviderFirewall> {
        Box::pin(async move { self.firewall(&self.acl(id).await?.metadata) })
    }

    fn create_firewall<'a>(
        &'a self,
        label: &'a str,
        tags: &'a [String],
        rules: &'a [FirewallRule],
    ) -> Fut<'a, ProviderFirewall> {
        Box::pin(async move {
            let mut body = self.acl_body(
                &ingress(rules),
                &json!("SuperBot machines: inbound from the control plane, outbound not to private addresses"),
                &json!({ "user.superbot.tag": tags.first().cloned().unwrap_or_default() }),
            );
            body["name"] = json!(name(label)?);
            self.call(Method::POST, "/1.0/network-acls", &[], Some(&body), None).await?;
            self.get_firewall(label).await
        })
    }

    fn set_firewall_rules<'a>(&'a self, id: &'a str, rules: &'a [FirewallRule]) -> Fut<'a, ()> {
        Box::pin(async move { self.put_acl(id, |_| ingress(rules)).await })
    }

    fn enable_firewall<'a>(&'a self, id: &'a str) -> Fut<'a, ()> {
        Box::pin(async move {
            self.put_acl(id, |cur| {
                cur["ingress"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(Rule::read)
                    .map(|r| Rule { enabled: true, ..r })
                    .collect()
            })
            .await
        })
    }

    fn firewall_devices<'a>(&'a self, id: &'a str) -> Fut<'a, FirewallDevices> {
        Box::pin(async move {
            let mut out = FirewallDevices::default();
            for u in self.acl(id).await?.metadata["used_by"].as_array().into_iter().flatten() {
                match u.as_str().and_then(instance_of) {
                    Some((n, project)) if project == self.s.project => out.machines.push(n),
                    _ => out.others += 1,
                }
            }
            Ok(out)
        })
    }

    fn attach_firewall<'a>(&'a self, id: &'a str, machine: &'a str) -> Fut<'a, ()> {
        Box::pin(async move {
            let acl = name(id)?;
            self.edit(machine, |put| put["devices"]["eth0"] = self.nic(acl)).await
        })
    }

    fn detach_firewall<'a>(&'a self, id: &'a str, machine: &'a str) -> Fut<'a, ()> {
        Box::pin(async move {
            let res = self
                .edit(machine, |put| {
                    let eth0 = &mut put["devices"]["eth0"];
                    if eth0["security.acls"] == id
                        && let Some(nic) = eth0.as_object_mut()
                    {
                        nic.insert("security.acls".into(), json!(""));
                    }
                })
                .await;
            match res {
                Ok(()) | Err(ProviderError::NotFound) => Ok(()),
                Err(e) => Err(e),
            }
        })
    }

    fn delete_firewall<'a>(&'a self, id: &'a str) -> Fut<'a, ()> {
        Box::pin(async move {
            match self
                .call(Method::DELETE, &format!("/1.0/network-acls/{}", name(id)?), &[], None, None)
                .await
            {
                Ok(_) | Err(ProviderError::NotFound) => Ok(()),
                Err(e) => Err(e),
            }
        })
    }
}

#[cfg(test)]
mod tests;
