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
    ByteStream, CreateSpec, DiskUse, FirewallDevices, FirewallRule, Fut, HostUse, MachineProvider, NetworkMember,
    ProviderError, ProviderFirewall, ProviderMachine, RebuildSpec, RestoreFile, RestoreSpec, TeamNetwork,
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
/// Making a backup of a container, or importing one, copies its whole disk.
const BACKUP_WAIT: u64 = 4 * 3600;
/// Incus deletes a backup left behind (botd stopped mid-export) after this long.
const BACKUP_EXPIRY_HOURS: i64 = 24;
/// Where the enrollment user data goes. The image renders it into the container's
/// NoCloud seed when the container is first started after a create or rebuild, so
/// removing it later changes nothing inside a container that has started.
const USER_DATA: &str = "cloud-init.user-data";
/// Rendered into the seed the same way. Every container is made with [`NETWORK_CONFIG`].
const NETWORK_KEY: &str = "cloud-init.network-config";
/// eth0 as the image's default has it, and the team NIC (ADR 0212) whenever it is
/// plugged in, by DHCP with neither routes nor DNS from it, so the container's default
/// route and resolver stay eth0's. `optional`: a container with no team NIC boots as
/// before.
const NETWORK_CONFIG: &str = "version: 2\nethernets:\n  eth0:\n    dhcp4: true\n  eth1:\n    optional: true\n    dhcp4: true\n    dhcp4-overrides:\n      use-dns: false\n      use-routes: false\n";
/// The NIC a team member's container is on its team's network through (ADR 0212).
pub const TEAM_NIC: &str = "eth1";
/// Set on containers made or rebuilt with [`NETWORK_CONFIG`], whose cloud-init brings up
/// a team NIC plugged in later. One made before can't join without a rebuild.
const TEAM_NIC_READY: &str = "user.superbot.team-nic";
/// Marks the OVN networks botd made for teams; no other network is ever listed as one.
const TEAM_NETWORK_MARK: &str = "user.superbot.team-network";
const TEAM_NETWORK_REGION: &str = "user.superbot.region";

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

    /// No `limits.memory.swap`: a restricted project counts it as a low-level option
    /// and refuses the container. Whether containers swap is the host's choice.
    fn limits(&self) -> [(&'static str, String); 4] {
        [
            ("limits.cpu", self.cpus.to_string()),
            ("limits.memory", format!("{}GiB", self.memory_gib)),
            ("limits.memory.enforce", "hard".into()),
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
pub(crate) fn number(ip: IpAddr) -> (bool, u128) {
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
pub(crate) fn span(cidr: &str) -> Option<(bool, u128, u128)> {
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

/// Whether `egress(deny, open)` drops TCP to `ip`:`port`.
pub fn drops(deny: &[String], open: &[(IpAddr, u16)], ip: IpAddr, port: u16) -> bool {
    let (v6, n) = number(ip);
    !open.contains(&(ip, port)) && deny.iter().filter_map(|c| span(c)).any(|(is6, lo, hi)| is6 == v6 && (lo..=hi).contains(&n))
}

fn piece(v6: bool, lo: u128, hi: u128) -> String {
    if lo == hi {
        address(v6, lo).to_string()
    } else {
        format!("{}-{}", address(v6, lo), address(v6, hi))
    }
}

/// The outbound rules every container gets: TCP and UDP dropped to `deny`, but for
/// the TCP addresses and ports in `open` (botd's machine port, INCUS_EGRESS_ALLOW)
/// that fall inside it. Everything else outbound is allowed, so harnesses reach
/// their APIs and package mirrors.
pub fn egress(deny: &[String], open: &[(IpAddr, u16)]) -> Vec<Rule> {
    let mut out = Vec::new();
    let mut carved = std::collections::BTreeMap::<IpAddr, Vec<u16>>::new();
    for (v6, family) in [(false, "IPv4"), (true, "IPv6")] {
        let mut dest = Vec::new();
        for c in deny {
            let Some((is6, lo, hi)) = span(c) else { continue };
            if is6 != v6 {
                continue;
            }
            let mut holes: Vec<u128> = Vec::new();
            for &(ip, port) in open {
                let (o6, n) = number(ip);
                if o6 == v6 && (lo..=hi).contains(&n) {
                    holes.push(n);
                    carved.entry(ip).or_default().push(port);
                }
            }
            holes.sort();
            holes.dedup();
            if holes.is_empty() {
                dest.push(c.clone());
                continue;
            }
            let mut from = Some(lo);
            for n in holes {
                if let Some(f) = from.filter(|f| *f < n) {
                    dest.push(piece(v6, f, n - 1));
                }
                from = n.checked_add(1).filter(|f| *f <= hi);
            }
            if let Some(f) = from.filter(|f| *f <= hi) {
                dest.push(piece(v6, f, hi));
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
    for (ip, mut open) in carved {
        open.sort();
        open.dedup();
        let mut ports = Vec::new();
        let mut from = 1u32;
        for p in open.iter().map(|p| *p as u32).chain([65536]) {
            if from < p {
                ports.push(if from == p - 1 { from.to_string() } else { format!("{from}-{}", p - 1) });
            }
            from = p + 1;
        }
        let which: Vec<String> = open.iter().map(u16::to_string).collect();
        if !ports.is_empty() {
            out.push(Rule {
                action: "drop".into(),
                protocol: "tcp".into(),
                destination: ip.to_string(),
                destination_port: ports.join(","),
                description: format!("superbot: only tcp port {} on {ip}", which.join(",")),
                enabled: true,
                ..Rule::default()
            });
        }
        out.push(Rule {
            action: "drop".into(),
            protocol: "udp".into(),
            destination: ip.to_string(),
            description: format!("superbot: no udp to {ip}"),
            enabled: true,
            ..Rule::default()
        });
    }
    out
}

/// The outbound rule of a team network's ACL (ADR 0212): only to the team's subnet. The
/// NIC drops everything else both ways but for replies and what Incus always lets
/// through to the network's router (DHCP, DNS, neighbour discovery), so a container
/// reaches the team's services, never a teammate's container or past the network.
fn team_egress(subnet: &str) -> Vec<Rule> {
    vec![Rule {
        action: "allow".into(),
        destination: subnet.into(),
        description: "superbot: only the team's own network".into(),
        enabled: true,
        ..Rule::default()
    }]
}

/// An OVN network's `ipv4.address` (the router's, as `10.248.0.1/22`) as its subnet.
fn subnet_of(addr: &str) -> Option<String> {
    let (v6, lo, _) = span(addr)?;
    let len = addr.split_once('/')?.1;
    (!v6).then(|| format!("{}/{len}", address(false, lo)))
}

/// A team network's router: the subnet's first address, as OVN's `ipv4.address` has it.
fn router_of(subnet: &str) -> Option<String> {
    let (v6, lo, hi) = span(subnet)?;
    let len = subnet.split_once('/')?.1;
    (!v6 && lo < hi).then(|| format!("{}/{len}", address(false, lo + 1)))
}

/// Whether two canonical CIDRs share an address.
fn overlap(a: &str, b: &str) -> bool {
    matches!((span(a), span(b)), (Some((a6, alo, ahi)), Some((b6, blo, bhi))) if a6 == b6 && alo <= bhi && blo <= ahi)
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

/// The Incus host's own address in an `INCUS_URL`, as a CIDR, so containers are kept
/// off every host's API, not just their own's.
pub(crate) fn host_cidr(url: &str) -> Option<String> {
    let (_, host) = https_base("INCUS_URL", url).ok()?;
    super::firewall::cidr(&ip_of(&host)?.to_string()).ok()
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
    /// The part of `deny` named for this host: INCUS_EGRESS_DENY and the Incus hosts,
    /// kept even where an entry repeats one of PRIVATE's ranges.
    pub kept: Vec<String>,
    /// botd's machine address and port, when it is an IP.
    pub control: Option<(IpAddr, u16)>,
    /// INCUS_EGRESS_ALLOW: TCP addresses and ports containers reach though `deny`
    /// holds them, such as internal mirrors (ADR 0186).
    pub allow: Vec<(IpAddr, u16)>,
}

impl Settings {
    /// Everything carved out of `deny`: botd's machine port, then INCUS_EGRESS_ALLOW.
    pub fn open(&self) -> Vec<(IpAddr, u16)> {
        self.control.into_iter().chain(self.allow.iter().copied()).collect()
    }
}

/// INCUS_EGRESS_ALLOW: comma-separated `address:port`, IPv6 in brackets, e.g.
/// `10.0.0.20:443,[fd00::20]:8443`. Exact addresses only, so no range is opened.
pub fn egress_allow(raw: &str) -> Result<Vec<(IpAddr, u16)>, String> {
    let mut out = Vec::new();
    for a in raw.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        let sa: std::net::SocketAddr = a
            .parse()
            .map_err(|_| format!("INCUS_EGRESS_ALLOW: {a:?} isn't an address and port, e.g. 10.0.0.20:443 or [fd00::20]:443"))?;
        if sa.port() == 0 || sa.ip().is_unspecified() {
            return Err(format!("INCUS_EGRESS_ALLOW: {a:?} needs a real address and port"));
        }
        out.push((sa.ip(), sa.port()));
    }
    out.sort();
    out.dedup();
    Ok(out)
}

impl Settings {
    /// INCUS_URL (needed), INCUS_PROJECT, INCUS_NETWORK, INCUS_STORAGE_POOL,
    /// INCUS_IMAGE_SERVER, INCUS_EGRESS_DENY, INCUS_EGRESS_ALLOW, and MACHINE_CONTROL_URL.
    pub fn from_env(var: &dyn Fn(&str) -> String) -> Result<Settings, String> {
        let or = |k: &str, d: &str| Some(var(k).trim().to_string()).filter(|v| !v.is_empty()).unwrap_or_else(|| d.into());
        let raw = var("INCUS_URL");
        if raw.trim().is_empty() {
            return Err("INCUS_URL is needed with MACHINE_PROVIDER=incus, e.g. https://<incus-host>:8443".into());
        }
        let (url, host) = https_base("INCUS_URL", &raw)?;
        let host_ip = ip_of(&host).ok_or(
            "INCUS_URL must name the Incus host by IP address, so containers can be kept off it, e.g. https://<incus-host-ip>:8443",
        )?;
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
        let mut kept = Vec::new();
        for c in var("INCUS_EGRESS_DENY").split(',').map(str::trim).filter(|s| !s.is_empty()) {
            kept.push(super::firewall::cidr(c).map_err(|e| format!("INCUS_EGRESS_DENY: {e}"))?);
        }
        kept.push(super::firewall::cidr(&host_ip.to_string())?);
        kept.sort();
        kept.dedup();
        let mut deny: Vec<String> = PRIVATE.iter().map(|s| s.to_string()).chain(kept.iter().cloned()).collect();
        deny.sort();
        deny.dedup();
        let control = url::Url::parse(var("MACHINE_CONTROL_URL").trim())
            .ok()
            .and_then(|u| Some((ip_of(&u.host()?.to_owned())?, u.port_or_known_default()?)));
        let allow = egress_allow(&var("INCUS_EGRESS_ALLOW"))?;
        let [project, network, pool] = <[String; 3]>::try_from(names).unwrap();
        Ok(Settings { url, project, network, pool, image_server, deny, kept, control, allow })
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
    #[cfg(test)]
    pub fn from_store(store: &dyn SecretStore) -> Result<Credentials, String> {
        Credentials::for_host(store, None)
    }

    /// The same client certificate and key, and the certificate of the host whose
    /// INCUS_SERVER_CERT_<suffix> it is (ADR 0076). None: INCUS_SERVER_CERT.
    pub fn for_host(store: &dyn SecretStore, suffix: Option<&str>) -> Result<Credentials, String> {
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
            server: {
                let k = suffix.map_or("INCUS_SERVER_CERT".to_string(), |s| format!("INCUS_SERVER_CERT_{s}"));
                pki::cert_der(&get(&k)?).map_err(|e| format!("{k}: {e}"))?
            },
        })
    }
}

pub struct Incus {
    s: Settings,
    egress: Vec<Rule>,
    /// MACHINE_TEAM_NETWORK_SUBNET with MACHINE_TEAM_NETWORK=ovn (ADR 0212), for the
    /// preflight check and admins; team networks are made with the subnet asked for.
    team_subnet: Option<String>,
    pin: String,
    http: reqwest::Client,
    /// For backups' bytes (ADR 0071): no overall timeout, but not silent for long.
    stream: reqwest::Client,
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

/// Before 7.0.1 (so every 6.0 LTS release), changing a network ACL used by a NIC of a
/// container outside the default project fails while applying it, after the new rules
/// are saved, so the firewall Incus enforces no longer matches the ACL (ADR 0069).
const MIN_VERSION: &str = "7.0.1";

/// Whether an Incus `server_version` is older than [`MIN_VERSION`]. One botd can't read
/// isn't refused for it; the API extensions are still checked.
fn too_old(version: &str) -> bool {
    let parse = |v: &str| -> Option<Vec<u32>> {
        let parts: Option<Vec<u32>> = v.split('.').map(|p| p.parse().ok()).collect();
        parts.map(|mut p| {
            p.resize(3, 0);
            p
        })
    };
    match (parse(version), parse(MIN_VERSION)) {
        (Some(v), Some(min)) => v < min,
        _ => false,
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
        last_backup_at: None,
        tags: text("user.superbot.tags")
            .split(',')
            .filter(|t| !t.is_empty())
            .map(String::from)
            .collect(),
        user_data: !text(USER_DATA).is_empty(),
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
        last_backup_at: None,
        tags: Vec::new(),
        user_data: false,
    }
}

/// `GET /1.0/resources` and `GET /1.0/storage-pools/<pool>/resources` as a host's use
/// (ADR 0106). Load needs the `resources_load` extension; without it, it's absent.
pub(crate) fn host_use(r: &Value, pool: Option<&Value>) -> HostUse {
    let total = |v: &Value| v["total"].as_u64().filter(|t| *t > 0);
    let load = &r["load"];
    HostUse {
        cpus: total(&r["cpu"]),
        load: (load["processes"].as_u64().unwrap_or(0) > 0)
            .then(|| Some((load["average1min"].as_f64()?, load["average5min"].as_f64()?)))
            .flatten(),
        memory: total(&r["memory"]).map(|t| (r["memory"]["used"].as_u64().unwrap_or(0), t)),
        disks: pool
            .and_then(|p| total(&p["space"]).map(|t| DiskUse { name: "pool", used: p["space"]["used"].as_u64().unwrap_or(0), total: t }))
            .into_iter()
            .collect(),
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
        let (tls, _) = pki::pinned_client_config(vec![pin.clone()], vec![c.cert.clone()], c.key.clone_key())?;
        let http = reqwest::Client::builder()
            .tls_backend_preconfigured(tls)
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(REBUILD_WAIT + 30))
            .user_agent(concat!("superbot-botd/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|e| format!("Incus client: {e}"))?;
        let (tls, _) = pki::pinned_client_config(vec![pin.clone()], vec![c.cert], c.key)?;
        let stream = reqwest::Client::builder()
            .tls_backend_preconfigured(tls)
            .connect_timeout(Duration::from_secs(5))
            .read_timeout(Duration::from_secs(300))
            .user_agent(concat!("superbot-botd/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|e| format!("Incus client: {e}"))?;
        let egress = egress(&s.deny, &s.open());
        Ok(Incus { s, egress, team_subnet: None, pin, http, stream })
    }

    /// With team networks on (ADR 0212): refused if `subnet` meets anything containers
    /// reach through eth0 or are kept off: botd's machine address, INCUS_EGRESS_ALLOW,
    /// INCUS_EGRESS_DENY or an Incus host. Through the team NIC's route the first would
    /// be unreachable and the last let through.
    pub fn with_team_subnet(mut self, subnet: &str) -> Result<Incus, String> {
        let why = |what: &str| format!("MACHINE_TEAM_NETWORK_SUBNET: {subnet} meets {what}; pick a range apart from it");
        for (ip, _) in self.s.open() {
            if drops(&[subnet.to_string()], &[], ip, 0) {
                return Err(why(&format!("{ip}, which containers reach botd or an INCUS_EGRESS_ALLOW address at")));
            }
        }
        if let Some(c) = self.s.kept.iter().find(|c| overlap(subnet, c)) {
            return Err(why(&format!("{c}, which containers are kept off (INCUS_EGRESS_DENY or an Incus host)")));
        }
        self.team_subnet = Some(subnet.to_string());
        Ok(self)
    }

    pub(crate) fn base(&self) -> &Settings {
        &self.s
    }

    /// The SHA-256 of the host certificate botd pins.
    pub(crate) fn fingerprint(&self) -> &str {
        &self.pin
    }

    fn url(&self, path: &str, query: &[(&str, &str)]) -> String {
        let mut q = url::form_urlencoded::Serializer::new(String::new());
        q.append_pair("project", &self.s.project);
        for (k, v) in query {
            q.append_pair(k, v);
        }
        format!("{}{path}?{}", self.s.url, q.finish())
    }

    async fn call(
        &self,
        method: Method,
        path: &str,
        query: &[(&str, &str)],
        body: Option<&Value>,
        if_match: Option<&str>,
    ) -> Result<Reply, ProviderError> {
        let mut req = self.http.request(method, self.url(path, query));
        if let Some(b) = body {
            req = req.json(b);
        }
        if let Some(e) = if_match {
            req = req.header("If-Match", e);
        }
        self.reply(req).await
    }

    async fn reply(&self, req: reqwest::RequestBuilder) -> Result<Reply, ProviderError> {
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

    /// Like `finish`, for operations that copy a whole disk: waited on a minute at a
    /// time, up to `secs`.
    async fn finish_long(&self, r: Reply, secs: u64, doing: &str) -> Result<(), ProviderError> {
        let Some(op) = r.operation else { return Ok(()) };
        let until = std::time::Instant::now() + Duration::from_secs(secs);
        while !self.wait(&op, 60).await? {
            if std::time::Instant::now() >= until {
                return Err(ProviderError::Transport(format!("Incus is still {doing}")));
            }
        }
        Ok(())
    }

    /// Writes a file into a stopped container, as root.
    async fn push(&self, n: &str, f: &RestoreFile) -> Result<(), ProviderError> {
        let req = self
            .http
            .post(self.url(&format!("/1.0/instances/{}/files", name(n)?), &[("path", &f.path)]))
            .header("Content-Type", "application/octet-stream")
            .header("X-Incus-uid", "0")
            .header("X-Incus-gid", "0")
            .header("X-Incus-mode", format!("{:04o}", f.mode))
            .header("X-Incus-type", "file")
            .header("X-Incus-write", "overwrite")
            .body(f.content.clone());
        self.reply(req).await.map(drop)
    }

    /// Succeeds if it isn't there.
    async fn remove_file(&self, n: &str, path: &str) -> Result<(), ProviderError> {
        match self.call(Method::DELETE, &format!("/1.0/instances/{}/files", name(n)?), &[("path", path)], None, None).await {
            Ok(_) | Err(ProviderError::NotFound) => Ok(()),
            Err(ProviderError::Api { message, .. }) if message.to_ascii_lowercase().contains("no such file") => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// The instance with its runtime state (addresses): `recursion=1` on one instance
    /// is the `instance_get_full` API extension, which preflight checks for.
    async fn instance(&self, n: &str) -> Result<Value, ProviderError> {
        Ok(self
            .call(Method::GET, &format!("/1.0/instances/{}", name(n)?), &[("recursion", "1")], None, None)
            .await?
            .metadata)
    }

    /// Whether an operation on `n` (its create, a rebuild) is still running.
    async fn busy(&self, n: &str) -> Result<bool, ProviderError> {
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
        if self.busy(n).await? {
            return Err(ProviderError::Transport("Incus is still working on the container (a rebuild?)".into()));
        }
        self.set_state(n, "start", false, FORCE_WAIT).await
    }

    /// Refuses to make containers unless the project keeps them in (module docs).
    /// That Incus trusts botd and is new enough, with every API extension botd uses.
    /// Checked before every create, so botd never makes a container it can't keep
    /// behind its firewall.
    pub(crate) async fn check_server(&self) -> Result<String, ProviderError> {
        let v = self.call(Method::GET, "/1.0", &[], None, None).await?.metadata;
        if v["auth"] != "trusted" {
            return Err(api(403, "Incus doesn't trust botd's client certificate yet"));
        }
        let version = v["environment"]["server_version"].as_str().unwrap_or("?");
        if too_old(version) {
            return Err(api(
                400,
                format!("Incus {version} is too old: botd needs {MIN_VERSION} or later, which can change a network ACL that containers in a restricted project use"),
            ));
        }
        let have = |x: &str| v["api_extensions"].as_array().is_some_and(|a| a.iter().any(|e| e == x));
        let missing: Vec<&str> = [
            "network_acl",
            "network_bridge_acl_devices",
            "instances_rebuild",
            "instance_create_start",
            "instance_get_full",
        ]
        .into_iter()
        .filter(|x| !have(x))
        .collect();
        if !missing.is_empty() {
            return Err(api(400, format!("Incus lacks API extensions: {}", missing.join(", "))));
        }
        Ok(format!("Incus {version} trusts botd"))
    }

    /// What the host has and uses now (ADR 0106): its CPU threads, load and memory, and
    /// the space in machines' storage pool. A pool that won't say leaves the disk out.
    pub(crate) async fn host_use(&self) -> Result<HostUse, ProviderError> {
        let r = self.call(Method::GET, "/1.0/resources", &[], None, None).await?.metadata;
        let pool = self.call(Method::GET, &format!("/1.0/storage-pools/{}/resources", self.s.pool), &[], None, None).await;
        Ok(host_use(&r, pool.ok().map(|p| p.metadata).as_ref()))
    }

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

    /// That team networks can be made here with `subnet` (ADR 0212): Incus makes isolated
    /// OVN networks (`network_ovn_isolated`), and `subnet` is apart from the bridge
    /// containers' eth0 is on, whose route the team NIC's would otherwise take over.
    async fn check_team(&self, subnet: &str) -> Result<String, ProviderError> {
        let v = self.call(Method::GET, "/1.0", &[], None, None).await?.metadata;
        if !v["api_extensions"].as_array().is_some_and(|a| a.iter().any(|e| e == "network_ovn_isolated")) {
            return Err(api(400, "Incus lacks the network_ovn_isolated API extension, which team networks (isolated OVN networks) need"));
        }
        let bridge = &self.s.network;
        let b = self.call(Method::GET, &format!("/1.0/networks/{bridge}"), &[], None, None).await?.metadata;
        if let Some(theirs) = b["config"]["ipv4.address"].as_str().and_then(subnet_of)
            && overlap(subnet, &theirs)
        {
            return Err(api(409, format!("MACHINE_TEAM_NETWORK_SUBNET {subnet} meets {bridge}'s {theirs}, which containers' eth0 is on; pick another range")));
        }
        Ok(format!("isolated OVN networks with {subnet}, apart from {bridge}"))
    }

    /// A restricted project without networks of its own (`features.networks`) lets its
    /// containers use only the default project's networks named in
    /// `restricted.networks.access`, when that is set: a team network is added to it.
    /// That loosens nothing: it names one more network, made by botd for one team.
    async fn allow_network(&self, n: &str) -> Result<(), ProviderError> {
        let path = format!("/1.0/projects/{}", self.s.project);
        for _ in 0..3 {
            let r = self.call(Method::GET, &path, &[], None, None).await?;
            let c = &r.metadata["config"];
            let access = c["restricted.networks.access"].as_str().unwrap_or_default().trim().to_string();
            if c["restricted"] != "true" || c["features.networks"] == "true" || access.is_empty() || access.split(',').any(|a| a.trim() == n) {
                return Ok(());
            }
            let mut put = json!({ "config": r.metadata["config"], "description": r.metadata["description"] });
            put["config"]["restricted.networks.access"] = json!(format!("{access},{n}"));
            match self.call(Method::PUT, &path, &[], Some(&put), r.etag.as_deref()).await {
                Err(ProviderError::Api { status: 412, .. }) => continue,
                res => return res.map(drop),
            }
        }
        Err(ProviderError::Transport("the project kept changing at Incus".into()))
    }

    /// The ACL on team network `n`'s NICs, named after it: nothing inbound, so teammates'
    /// machines stay apart as the firewall keeps them on Linode, and only `subnet`
    /// outbound. Replies come back: OVN's ACLs are stateful. Made if missing, and set
    /// again if anything else is in it.
    async fn ensure_team_acl(&self, n: &str, subnet: &str) -> Result<(), ProviderError> {
        let want: Vec<Value> = team_egress(subnet).iter().map(Rule::json).collect();
        let description = json!("SuperBot: one team's network; nothing in, out only to its subnet (ADR 0212)");
        for _ in 0..3 {
            let r = match self.acl(n).await {
                Ok(r) => r,
                Err(ProviderError::NotFound) => {
                    let body = json!({ "name": n, "description": description, "config": {}, "ingress": [], "egress": want });
                    return match self.call(Method::POST, "/1.0/network-acls", &[], Some(&body), None).await {
                        Ok(_) | Err(ProviderError::LabelTaken) => Ok(()),
                        Err(e) => Err(e),
                    };
                }
                Err(e) => return Err(e),
            };
            let rules = |k: &str| -> Option<Vec<Rule>> { r.metadata[k].as_array().map(|a| a.iter().filter_map(Rule::read).collect()) };
            let only = |k: &str, want: Vec<Rule>| {
                r.metadata[k].as_array().map(Vec::len) == Some(want.len()) && rules(k).is_some_and(|got| got == want)
            };
            if only("ingress", Vec::new()) && only("egress", team_egress(subnet)) {
                return Ok(());
            }
            let body = json!({ "description": description, "config": r.metadata["config"], "ingress": [], "egress": want });
            match self.call(Method::PUT, &format!("/1.0/network-acls/{n}"), &[], Some(&body), r.etag.as_deref()).await {
                Err(ProviderError::Api { status: 412, .. }) => continue,
                res => return res.map(drop),
            }
        }
        Err(ProviderError::Transport("the team network's ACL kept changing at Incus".into()))
    }

    /// An OVN network botd made for a team, as a team network. Its subnet is empty if
    /// it has lost its IPv4 address.
    fn team_network(v: &Value, created: bool) -> Option<TeamNetwork> {
        let n = v["name"].as_str().filter(|n| slug(n))?;
        (v["type"] == "ovn" && v["config"][TEAM_NETWORK_MARK] == "true").then(|| TeamNetwork {
            id: n.into(),
            label: n.into(),
            region: v["config"][TEAM_NETWORK_REGION].as_str().unwrap_or_default().into(),
            subnet_id: n.into(),
            subnet: v["config"]["ipv4.address"].as_str().and_then(subnet_of).unwrap_or_default(),
            created,
        })
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

    /// The NIC on team network `network` (ADR 0212): behind the network's own ACL,
    /// dropping what it doesn't let through both ways, and unable to claim another
    /// address.
    fn team_nic(&self, network: &str) -> Value {
        json!({
            "type": "nic",
            "network": network,
            "name": TEAM_NIC,
            "security.mac_filtering": "true",
            "security.ipv4_filtering": "true",
            "security.ipv6_filtering": "true",
            "security.acls": network,
            "security.acls.default.ingress.action": "drop",
            "security.acls.default.egress.action": "drop",
        })
    }

    /// Whether `dev`, as device `key`, is exactly a team NIC.
    fn is_team_nic(&self, key: &str, dev: &Value) -> bool {
        key == TEAM_NIC && dev["network"].as_str().is_some_and(|n| slug(n) && *dev == self.team_nic(n))
    }

    /// Whether the container's network is what `attach_firewall` sets: no profiles,
    /// eth0 exactly `nic(acl)`, and no other NIC but a team NIC.
    fn covered(&self, v: &Value, acl: &str) -> bool {
        let devices = match v.get("expanded_devices") {
            Some(d) if d.is_object() => d,
            _ => &v["devices"],
        };
        v["profiles"].as_array().is_none_or(Vec::is_empty)
            && devices.as_object().is_some_and(|d| {
                d.get("eth0") == Some(&self.nic(acl))
                    && d.iter().all(|(k, dev)| k == "eth0" || dev["type"] != "nic" || self.is_team_nic(k, dev))
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

    /// Sets up the imported copy as the machine: today's isolation, size, tags, and NIC
    /// behind the firewall, whatever its backup said, none of its cloud-init user data,
    /// and `spec`'s files. It is left stopped, under its own name.
    pub(crate) async fn prepare(&self, staging: &str, spec: &RestoreSpec) -> Result<(), ProviderError> {
        let size = Size::parse(&spec.plan).map_err(|m| api(400, m))?;
        let staging = name(staging)?;
        let acl = name(
            spec.firewall_id
                .as_deref()
                .ok_or_else(|| api(400, "containers are restored behind the machines' firewall (MACHINE_FIREWALL=on)"))?,
        )?;
        self.check_server().await?;
        self.check_project().await?;
        self.stop(staging, true).await?;
        self.edit(staging, |put| {
            if !put["config"].is_object() {
                put["config"] = json!({});
            }
            let c = put["config"].as_object_mut().unwrap();
            // Snapshots start again once it has enrolled and its token file is gone.
            for k in [USER_DATA, "cloud-init.vendor-data", "snapshots.schedule", "snapshots.expiry", "snapshots.pattern"] {
                c.remove(k);
            }
            for (k, v) in [
                ("security.privileged", "false"),
                ("security.nesting", "false"),
                ("security.idmap.isolated", "true"),
                ("security.guestapi", "false"),
            ] {
                c.insert(k.into(), json!(v));
            }
            for (k, v) in size.limits() {
                c.insert(k.into(), json!(v));
            }
            c.insert("user.superbot.tag".into(), json!(spec.tags.first().cloned().unwrap_or_default()));
            c.insert("user.superbot.tags".into(), json!(spec.tags.join(",")));
            c.insert("user.superbot.plan".into(), json!(spec.plan));
            if !spec.authorized_keys.is_empty() {
                c.insert("cloud-init.vendor-data".into(), json!(vendor_data(&spec.authorized_keys)));
            }
            put["devices"] = json!({ "root": self.root(&size), "eth0": self.nic(acl) });
            put["profiles"] = json!([]);
            put["description"] = json!("SuperBot machine");
        })
        .await?;
        for f in &spec.files {
            self.push(staging, f).await?;
        }
        for path in &spec.remove {
            self.remove_file(staging, path).await?;
        }
        Ok(())
    }

    /// Gives the restored container the machine's name, once the old one is gone.
    pub(crate) async fn rename(&self, staging: &str, id: &str) -> Result<(), ProviderError> {
        let (staging, id) = (name(staging)?, name(id)?);
        let r = self
            .call(Method::POST, &format!("/1.0/instances/{staging}"), &[], Some(&json!({ "name": id })), None)
            .await?;
        self.finish(r, EDIT_WAIT, "renaming the restored container").await
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
            "egressAllowed": self.s.allow.iter().map(|(ip, port)| std::net::SocketAddr::new(*ip, *port).to_string()).collect::<Vec<_>>(),
            "egressRules": self.egress.iter().map(Rule::json).collect::<Vec<_>>(),
            "isolation": [
                "unprivileged, with its own id range (security.idmap.isolated)",
                "no nesting, no /dev/incus (security.guestapi=false), no profiles",
                "one root disk from the pool; no host paths",
                "one NIC with port isolation and MAC/IPv4/IPv6 filtering",
                "the machines' network ACL: inbound only the firewall's rules; outbound no TCP/UDP to egressDenied",
                "a restricted project, checked before every create",
            ],
            "teamNetwork": self.team_subnet.as_ref().map(|subnet| json!({
                "kind": "ovn",
                "subnet": subnet,
                "nic": format!("{TEAM_NIC}, MAC/IPv4/IPv6 filtering, its network's ACL: nothing in, out only to the team's subnet"),
                "network": "isolated OVN (no uplink, no NAT, DHCP without a gateway)",
            })),
        })
    }

    fn preflight<'a>(&'a self) -> Fut<'a, Vec<Value>> {
        Box::pin(async move {
            let mut out = vec![
                self.check("server", self.check_server()).await,
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
            if let Some(subnet) = &self.team_subnet {
                out.push(self.check("team network", self.check_team(subnet)).await);
            }
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
            self.check_server().await?;
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
                config.insert(USER_DATA.into(), json!(ud));
            }
            if !spec.authorized_keys.is_empty() {
                config.insert("cloud-init.vendor-data".into(), json!(vendor_data(&spec.authorized_keys)));
            }
            config.insert(NETWORK_KEY.into(), json!(NETWORK_CONFIG));
            config.insert(TEAM_NIC_READY.into(), json!(TEAM_NIC));
            let mut devices = json!({ "root": self.root(&size), "eth0": self.nic(acl) });
            if let Some(net) = &spec.subnet_id {
                devices[TEAM_NIC] = self.team_nic(name(net)?);
            }
            let body = json!({
                "name": n,
                "type": "container",
                "start": true,
                "profiles": [],
                "description": "SuperBot machine",
                "source": self.source(&spec.image),
                "config": config,
                "devices": devices,
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
                Err(ProviderError::NotFound) if self.busy(id).await? => Ok(provisioning(id)),
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

    /// Gone counts as deleted only once no create of it is still running, which
    /// would make it after all; until then the reconciler keeps trying.
    fn delete<'a>(&'a self, id: &'a str) -> Fut<'a, ()> {
        Box::pin(async move {
            let res = match self.stop(id, true).await {
                Ok(()) => {
                    self.call(Method::DELETE, &format!("/1.0/instances/{}", name(id)?), &[], None, None)
                        .await
                }
                Err(e) => Err(e),
            };
            match res {
                Ok(r) => self.finish(r, FORCE_WAIT, "deleting the container").await,
                Err(ProviderError::NotFound) if self.busy(id).await? => Err(ProviderError::Transport(
                    "Incus is still creating the container; it's deleted once made".into(),
                )),
                Err(ProviderError::NotFound) => Ok(()),
                Err(e) => Err(e),
            }
        })
    }

    fn rebuild<'a>(&'a self, id: &'a str, spec: &'a RebuildSpec) -> Fut<'a, ()> {
        Box::pin(async move {
            self.stop(id, true).await?;
            self.edit(id, |put| {
                put["config"][USER_DATA] = json!(spec.user_data);
                put["config"][NETWORK_KEY] = json!(NETWORK_CONFIG);
                put["config"][TEAM_NIC_READY] = json!(TEAM_NIC);
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
            // Slower than that, it's left stopped: the rebuild worker starts it once
            // Incus is done, if it's still meant to be running.
            self.finish(r, REBUILD_WAIT, "rebuilding the container").await?;
            self.start(id).await
        })
    }

    /// Drops the key with a GET and an If-Match PUT of the rest, as `incus config
    /// unset` does; a PATCH with an empty value only usually unsets a key. Incus
    /// applies it to a running container in place, and a change made meanwhile
    /// fails the If-Match, so it is read again and kept.
    fn clear_user_data<'a>(&'a self, id: &'a str) -> Fut<'a, ()> {
        Box::pin(async move {
            let res = self
                .edit(id, |put| {
                    if let Some(c) = put["config"].as_object_mut() {
                        c.remove(USER_DATA);
                    }
                })
                .await;
            match res {
                Ok(()) | Err(ProviderError::NotFound) => Ok(()),
                Err(e) => Err(e),
            }
        })
    }

    fn exports(&self) -> bool {
        true
    }

    /// Without snapshots, which hold older states of the disk, and expiring by itself
    /// should botd stop before deleting it.
    fn create_backup<'a>(&'a self, id: &'a str, backup: &'a str) -> Fut<'a, ()> {
        Box::pin(async move {
            let p = self
                .call(Method::GET, &format!("/1.0/projects/{}", self.s.project), &[], None, None)
                .await?
                .metadata;
            if p["config"]["restricted"] == "true" && p["config"]["restricted.backups"] != "allow" {
                let pr = &self.s.project;
                return Err(api(
                    409,
                    format!("Incus project {pr} blocks backups: run `incus project set {pr} restricted.backups=allow` (docs/ops/incus-containers.md)"),
                ));
            }
            let expires = chrono::Utc::now() + chrono::Duration::hours(BACKUP_EXPIRY_HOURS);
            let body = json!({
                "name": name(backup)?,
                "expires_at": expires.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
                "instance_only": true,
                "optimized_storage": false,
            });
            let r = self
                .call(Method::POST, &format!("/1.0/instances/{}/backups", name(id)?), &[], Some(&body), None)
                .await?;
            self.finish_long(r, BACKUP_WAIT, "making the backup").await
        })
    }

    fn export_backup<'a>(&'a self, id: &'a str, backup: &'a str) -> Fut<'a, ByteStream> {
        Box::pin(async move {
            use futures_util::TryStreamExt;
            let path = format!("/1.0/instances/{}/backups/{}/export", name(id)?, name(backup)?);
            let res = self
                .stream
                .get(self.url(&path, &[]))
                .send()
                .await
                .map_err(|e| ProviderError::Transport(format!("Incus: {}", e.without_url())))?;
            let status = res.status();
            if !status.is_success() {
                let v: Value = res.json().await.unwrap_or(Value::Null);
                return Err(error(status, &v));
            }
            let bytes = res.bytes_stream().map_err(|e| std::io::Error::other(format!("Incus: {}", e.without_url())));
            Ok(Box::pin(bytes) as ByteStream)
        })
    }

    fn delete_backup<'a>(&'a self, id: &'a str, backup: &'a str) -> Fut<'a, ()> {
        Box::pin(async move {
            let path = format!("/1.0/instances/{}/backups/{}", name(id)?, name(backup)?);
            match self.call(Method::DELETE, &path, &[], None, None).await {
                Ok(r) => self.finish(r, EDIT_WAIT, "deleting the backup").await,
                Err(ProviderError::NotFound) => Ok(()),
                Err(e) => Err(e),
            }
        })
    }

    /// Into the project and pool botd uses, whatever the backup says.
    fn import_backup<'a>(&'a self, n: &'a str, data: ByteStream) -> Fut<'a, ()> {
        Box::pin(async move {
            self.check_server().await?;
            self.check_project().await?;
            let req = self
                .stream
                .post(self.url("/1.0/instances", &[]))
                .header("Content-Type", "application/octet-stream")
                .header("X-Incus-name", name(n)?)
                .header("X-Incus-pool", &self.s.pool)
                .body(reqwest::Body::wrap_stream(data));
            let r = self.reply(req).await?;
            self.finish_long(r, BACKUP_WAIT, "importing the backup").await
        })
    }

    fn replace_with<'a>(&'a self, id: &'a str, staging: &'a str, spec: &'a RestoreSpec) -> Fut<'a, ProviderMachine> {
        Box::pin(async move {
            self.prepare(staging, spec).await?;
            self.delete(id).await?;
            self.rename(staging, id).await?;
            self.get(id).await
        })
    }

    /// An isolated OVN network (no uplink) with `subnet`, its router on the first
    /// address, handing out addresses with no gateway, and its ACL (ADR 0212). The
    /// project's network access list names it first, where there is one.
    fn ensure_team_network<'a>(&'a self, label: &'a str, region: &'a str, subnet: &'a str) -> Fut<'a, TeamNetwork> {
        Box::pin(async move {
            let n = name(label)?;
            let router = router_of(subnet).ok_or_else(|| api(400, format!("{subnet} isn't an IPv4 range a team network can have")))?;
            self.check_team(subnet).await?;
            // A restricted project sees only the networks its access list names, so it
            // comes before looking; the ACL waits until the network is known to match.
            self.allow_network(n).await?;
            let path = format!("/1.0/networks/{n}");
            let mut created = false;
            let v = match self.call(Method::GET, &path, &[], None, None).await {
                Ok(r) => r.metadata,
                Err(ProviderError::NotFound) => {
                    let body = json!({
                        "name": n,
                        "type": "ovn",
                        "description": "SuperBot: one team's machines (ADR 0212)",
                        "config": {
                            "network": "none",
                            "ipv4.address": router,
                            "ipv4.nat": "false",
                            "ipv4.dhcp": "true",
                            "ipv4.dhcp.gateway": "none",
                            "ipv6.address": "none",
                            TEAM_NETWORK_MARK: "true",
                            TEAM_NETWORK_REGION: region,
                        },
                    });
                    match self.call(Method::POST, "/1.0/networks", &[], Some(&body), None).await {
                        Ok(_) => created = true,
                        Err(ProviderError::LabelTaken) => {}
                        Err(e) => return Err(e),
                    }
                    self.call(Method::GET, &path, &[], None, None).await?.metadata
                }
                Err(e) => return Err(e),
            };
            let refused = |m: String| api(409, m);
            let t = Self::team_network(&v, created).ok_or_else(|| refused(format!("network {n} is there already, and isn't an OVN network botd made for a team")))?;
            if t.region != region {
                return Err(refused(format!("team network {n} is for {}, not {region}", t.region)));
            }
            if t.subnet != subnet {
                return Err(refused(format!("team network {n}'s subnet is {}, not MACHINE_TEAM_NETWORK_SUBNET's {subnet}", t.subnet)));
            }
            self.ensure_team_acl(n, subnet).await?;
            Ok(t)
        })
    }

    /// Every OVN network botd made for a team whose name starts with `prefix`.
    fn team_networks<'a>(&'a self, prefix: &'a str) -> Fut<'a, Vec<TeamNetwork>> {
        Box::pin(async move {
            let r = self.call(Method::GET, "/1.0/networks", &[("recursion", "1")], None, None).await?;
            Ok(r.metadata
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|v| Self::team_network(v, false))
                .filter(|t| t.label.starts_with(prefix))
                .collect())
        })
    }

    /// This project's containers with a NIC on network `id`. Plugged in, a NIC is in use
    /// whenever the container runs.
    fn team_network_members<'a>(&'a self, id: &'a str) -> Fut<'a, Vec<NetworkMember>> {
        Box::pin(async move {
            let id = name(id)?;
            let list = self.call(Method::GET, "/1.0/instances", &[("recursion", "1")], None, None).await?.metadata;
            let mut out = Vec::new();
            for v in list.as_array().into_iter().flatten() {
                let Some(machine) = v["name"].as_str() else { continue };
                let devices = match v.get("expanded_devices") {
                    Some(d) if d.is_object() => d,
                    _ => &v["devices"],
                };
                for (k, dev) in devices.as_object().into_iter().flatten() {
                    if dev["type"] == "nic" && dev["network"] == id {
                        out.push(NetworkMember { machine: machine.into(), config: String::new(), interface: k.clone(), active: true });
                    }
                }
            }
            Ok(out)
        })
    }

    /// Unplugs the NIC, from a running container too. Never eth0, the machine's own.
    fn leave_team_network<'a>(&'a self, m: &'a NetworkMember) -> Fut<'a, ()> {
        Box::pin(async move {
            let nic = name(&m.interface)?;
            if nic == "eth0" {
                return Err(api(400, "eth0 is the machine's own NIC, never a team network's"));
            }
            let res = self
                .edit(&m.machine, |put| {
                    if let Some(d) = put["devices"].as_object_mut()
                        && d.get(nic).is_some_and(|dev| dev["type"] == "nic")
                    {
                        d.remove(nic);
                    }
                })
                .await;
            match res {
                Ok(()) | Err(ProviderError::NotFound) => Ok(()),
                Err(e) => Err(e),
            }
        })
    }

    /// Plugs the team NIC into the container, running or not. Refused for one whose
    /// cloud-init wouldn't bring it up (made before ADR 0212), or whose eth1 is
    /// something else.
    fn join_team_network<'a>(&'a self, machine: &'a str, n: &'a TeamNetwork) -> Fut<'a, ()> {
        Box::pin(async move {
            let net = name(&n.subnet_id)?;
            let v = self.call(Method::GET, &format!("/1.0/instances/{}", name(machine)?), &[], None, None).await?.metadata;
            let refused = |m: &str| api(409, m);
            if v["config"][TEAM_NIC_READY] != TEAM_NIC {
                return Err(refused("it was made before team networks on Incus, so it wouldn't bring up a team NIC; rebuild it to join its team's network"));
            }
            match v["devices"].get(TEAM_NIC) {
                Some(d) if *d == self.team_nic(net) => return Ok(()),
                Some(d) if d["type"] == "nic" => return Err(refused("it is on another network through eth1; it leaves that one first")),
                Some(_) => return Err(refused("its device eth1 isn't a NIC botd put there")),
                None => {}
            }
            self.edit(machine, |put| put["devices"][TEAM_NIC] = self.team_nic(net)).await
        })
    }

    fn team_network_hotplug(&self) -> bool {
        true
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

    /// Machines are this project's containers naming the ACL whose network is still
    /// exactly as attached; one changed since (another default, a filter off, a second
    /// NIC) counts as another device, so the reconciler attaches it again.
    fn firewall_devices<'a>(&'a self, id: &'a str) -> Fut<'a, FirewallDevices> {
        Box::pin(async move {
            let acl = name(id)?;
            let mut out = FirewallDevices::default();
            let used_by = self.acl(acl).await?.metadata["used_by"].clone();
            let ours: Vec<String> = used_by
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|u| u.as_str().and_then(instance_of))
                .filter(|(_, project)| *project == self.s.project)
                .map(|(n, _)| n)
                .collect();
            out.others = used_by.as_array().map_or(0, Vec::len) - ours.len();
            if ours.is_empty() {
                return Ok(out);
            }
            let list = self.call(Method::GET, "/1.0/instances", &[("recursion", "1")], None, None).await?.metadata;
            for n in ours {
                let found = list.as_array().into_iter().flatten().find(|v| v["name"] == n.as_str());
                if found.is_some_and(|v| self.covered(v, acl)) {
                    out.machines.push(n);
                } else {
                    out.others += 1;
                }
            }
            Ok(out)
        })
    }

    /// Puts the whole isolated NIC back as eth0, and drops profiles and other NICs but
    /// a team NIC (ADR 0212).
    fn attach_firewall<'a>(&'a self, id: &'a str, machine: &'a str) -> Fut<'a, ()> {
        Box::pin(async move {
            let acl = name(id)?;
            self.edit(machine, |put| {
                if let Some(d) = put["devices"].as_object_mut() {
                    d.retain(|k, dev| k == "eth0" || dev["type"] != "nic" || self.is_team_nic(k, dev));
                }
                put["devices"]["eth0"] = self.nic(acl);
                put["profiles"] = json!([]);
            })
            .await
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

/// For the end-to-end test against a real Incus host (ADR 0069): what botd never does
/// itself, such as looking inside a container.
#[cfg(test)]
impl Incus {
    /// A call to the API, waiting up to `secs` for any operation it starts. The
    /// metadata, or the operation's once it is done.
    pub async fn raw(&self, method: Method, path: &str, body: Option<&Value>, secs: u64) -> Result<Value, ProviderError> {
        let (path, query) = path.split_once('?').unwrap_or((path, ""));
        let query: Vec<(&str, &str)> = query.split('&').filter_map(|kv| kv.split_once('=')).collect();
        let r = self.call(method, path, &query, body, None).await?;
        let Some(op) = r.operation else { return Ok(r.metadata) };
        let id = operation_id(&op)?.to_string();
        let done = self
            .call(Method::GET, &format!("/1.0/operations/{id}/wait"), &[("timeout", &secs.to_string())], None, None)
            .await?
            .metadata;
        match done["status"].as_str() {
            Some("Success") => Ok(done),
            _ => Err(api(400, format!("{}: {}", done["status"], done["err"]))),
        }
    }

    /// Runs `cmd` in container `n` as root: its exit code, stdout and stderr.
    pub async fn exec(&self, n: &str, cmd: &[&str]) -> Result<(i64, String, String), ProviderError> {
        let body = json!({
            "command": cmd,
            "interactive": false,
            "wait-for-websocket": false,
            "record-output": true,
            "environment": { "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" },
        });
        let op = self.raw(Method::POST, &format!("/1.0/instances/{}/exec", name(n)?), Some(&body), 120).await?;
        let code = op["metadata"]["return"].as_i64().unwrap_or(-1);
        let mut out = [String::new(), String::new()];
        for (i, fd) in ["1", "2"].iter().enumerate() {
            if let Some(log) = op["metadata"]["output"][fd].as_str() {
                let url = format!("{}{}?project={}", self.s.url, log, self.s.project);
                let res = self.http.get(url).send().await.map_err(|e| ProviderError::Transport(e.to_string()))?;
                out[i] = res.text().await.map_err(|e| ProviderError::Transport(e.to_string()))?;
                let _ = self.http.delete(format!("{}{}?project={}", self.s.url, log, self.s.project)).send().await;
            }
        }
        let [stdout, stderr] = out;
        Ok((code, stdout, stderr))
    }
}

pub mod fleet;

#[cfg(test)]
mod tests;
