//! Linode API v4 behind `MachineProvider`. Only `https://api.linode.com/v4` in
//! production; tests point it at a local stand-in. The token goes in the
//! Authorization header and nowhere else: not in errors, logs, or `Debug`.

use super::provider::{
    CreateSpec, FirewallDevices, FirewallRule, Fut, MachineProvider, NetworkMember, ProviderError, ProviderFirewall,
    ProviderMachine, RebuildSpec, TeamNetwork,
};
use base64::Engine;
use reqwest::{Method, StatusCode};
use serde_json::{Value, json};
use std::net::IpAddr;
use std::time::Duration;
use zeroize::Zeroizing;

mod interfaces;
pub use interfaces::Generation;

pub const API_URL: &str = "https://api.linode.com/v4";
const PAGE_SIZE: u32 = 500;
/// 50,000 machines; past that something is wrong with the paging, not the fleet.
const MAX_PAGES: u32 = 100;

pub struct Linode {
    token: Zeroizing<String>,
    base: String,
    http: reqwest::Client,
    /// What the machines' firewall drops on the way out (ADR 0179). Empty: nothing.
    outbound: Vec<Outbound>,
    /// Which kind of interfaces new Linodes get (MACHINE_LINODE_INTERFACES, ADR 0226).
    generation: Generation,
}

/// Linode takes at most this many addresses in one rule.
pub const MAX_ADDRESSES: usize = 255;
pub const CONTROL_RULE: &str = "control-plane-port";

/// One outbound rule of the machines' firewall (ADR 0179): `action` (`ACCEPT` or
/// `DROP`) for `protocol` (`TCP` or `UDP`) to `destinations` (canonical CIDRs,
/// sorted), on `ports` or, when None, every port. Linode applies them in order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Outbound {
    pub label: String,
    pub action: String,
    pub protocol: String,
    pub ports: Option<String>,
    pub destinations: Vec<String>,
}

/// The outbound rules that keep every process on a Linode, root included, off `deny`:
/// TCP and UDP dropped there, but for TCP to botd's machine port (`control`) when
/// botd's address falls inside it, which is let through first. ICMP stays open, as
/// IPv6 neighbour discovery needs it, and so does Linode's metadata service, which
/// its firewall never filters.
pub fn outbound(deny: &[String], control: Option<(IpAddr, u16)>) -> Result<Vec<Outbound>, String> {
    let mut deny = deny.to_vec();
    deny.sort();
    deny.dedup();
    if deny.is_empty() {
        return Ok(Vec::new());
    }
    if deny.len() > MAX_ADDRESSES {
        return Err(format!(
            "MACHINE_EGRESS_DENY: Linode's firewall takes at most {MAX_ADDRESSES} ranges in a rule, and the machines' deny list has {}; join ranges, or set MACHINE_FIREWALL_EGRESS=off",
            deny.len()
        ));
    }
    let mut out = Vec::new();
    if let Some((ip, port)) = control {
        let (v6, n) = super::incus::number(ip);
        let inside = deny
            .iter()
            .filter_map(|c| super::incus::span(c))
            .any(|(is6, lo, hi)| is6 == v6 && (lo..=hi).contains(&n));
        if inside {
            out.push(Outbound {
                label: CONTROL_RULE.into(),
                action: "ACCEPT".into(),
                protocol: "TCP".into(),
                ports: Some(port.to_string()),
                destinations: vec![super::firewall::cidr(&ip.to_string())?],
            });
        }
    }
    for protocol in ["TCP", "UDP"] {
        out.push(Outbound {
            label: format!("no-private-{}", protocol.to_ascii_lowercase()),
            action: "DROP".into(),
            protocol: protocol.into(),
            ports: None,
            destinations: deny.clone(),
        });
    }
    Ok(out)
}

/// `rules` letting TCP and UDP through to the team networks' subnet (ADR 0189), after
/// botd's port and before the drops. A Linode reaches that range only on its own
/// team's VPC, which only its team's machines join; on any other the range has no
/// route. With no outbound rules (MACHINE_FIREWALL_EGRESS=off) there is nothing to let
/// through.
pub fn with_team_subnet(mut rules: Vec<Outbound>, subnet: &str) -> Vec<Outbound> {
    if rules.is_empty() {
        return rules;
    }
    let at = rules.iter().take_while(|r| r.label == CONTROL_RULE).count();
    for (i, protocol) in ["TCP", "UDP"].into_iter().enumerate() {
        rules.insert(
            at + i,
            Outbound {
                label: format!("team-network-{}", protocol.to_ascii_lowercase()),
                action: "ACCEPT".into(),
                protocol: protocol.into(),
                ports: None,
                destinations: vec![subnet.to_string()],
            },
        );
    }
    rules
}

pub fn outbound_json(rules: &[Outbound]) -> Value {
    json!(rules
        .iter()
        .map(|r| json!({ "label": r.label, "action": r.action, "protocol": r.protocol, "ports": r.ports, "to": r.destinations }))
        .collect::<Vec<_>>())
}

impl std::fmt::Debug for Linode {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.debug_struct("Linode")
            .field("base", &self.base)
            .field("token", &"[redacted]")
            .finish()
    }
}

impl Linode {
    pub fn new(token: &str, base: &str) -> Linode {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent(concat!("superbot-botd/", env!("CARGO_PKG_VERSION")))
            .build()
            .expect("HTTP client");
        Linode {
            token: Zeroizing::new(token.trim().to_string()),
            base: base.trim_end_matches('/').to_string(),
            http,
            outbound: Vec::new(),
            generation: Generation::default(),
        }
    }

    /// The machines' firewall drops `rules`' traffic on the way out, and a firewall
    /// without exactly these is set again.
    pub fn with_outbound(mut self, rules: Vec<Outbound>) -> Linode {
        self.outbound = rules;
        self
    }

    /// New Linodes get `g`'s interfaces.
    pub fn with_interfaces(mut self, g: Generation) -> Linode {
        self.generation = g;
        self
    }

    fn firewall(&self, v: &Value) -> Result<ProviderFirewall, ProviderError> {
        let id = v["id"]
            .as_u64()
            .ok_or_else(|| ProviderError::Transport("Linode sent a firewall we couldn't read".into()))?;
        Ok(ProviderFirewall {
            id: id.to_string(),
            label: v["label"].as_str().unwrap_or_default().into(),
            rules: our_rules(&v["rules"], &self.outbound),
            enabled: v["status"] == "enabled",
        })
    }

    async fn call(
        &self,
        method: Method,
        path: &str,
        filter: Option<&Value>,
        body: Option<&Value>,
    ) -> Result<Value, ProviderError> {
        let mut req = self
            .http
            .request(method, format!("{}{path}", self.base))
            .bearer_auth(self.token.as_str());
        if let Some(f) = filter {
            req = req.header("X-Filter", f.to_string());
        }
        if let Some(b) = body {
            req = req.json(b);
        }
        // reqwest's errors name the URL, which holds no credentials.
        let res = req
            .send()
            .await
            .map_err(|e| ProviderError::Transport(e.without_url().to_string()))?;
        let status = res.status();
        let text = res
            .text()
            .await
            .map_err(|e| ProviderError::Transport(e.without_url().to_string()))?;
        let v: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
        if status.is_success() {
            return Ok(v);
        }
        Err(error(status, &v))
    }

    /// Every item of a paged list.
    async fn all(&self, path: &str, filter: Option<&Value>) -> Result<Vec<Value>, ProviderError> {
        let mut out = Vec::new();
        for page in 1..=MAX_PAGES {
            let v = self
                .call(
                    Method::GET,
                    &format!("{path}?page={page}&page_size={PAGE_SIZE}"),
                    filter,
                    None,
                )
                .await?;
            out.extend(v["data"].as_array().cloned().unwrap_or_default());
            if page >= v["pages"].as_u64().unwrap_or(1) as u32 {
                break;
            }
        }
        Ok(out)
    }

    /// Every device behind the firewall.
    async fn devices(&self, id: &str) -> Result<Vec<Device>, ProviderError> {
        Ok(self
            .all(&format!("/networking/firewalls/{}/devices", path_id(id)?), None)
            .await?
            .iter()
            .map(device)
            .collect())
    }
}

/// One device behind a firewall: a Linode with configuration-profile interfaces, one
/// of a Linode's own interfaces (ADR 0226), or anything else (a NodeBalancer).
#[derive(Clone, Debug, PartialEq)]
enum Device {
    Linode { device: u64, linode: String },
    Interface { device: u64, linode: String, interface: u64 },
    Other,
}

impl Device {
    /// The device's id and its Linode's, if it is a Linode or one of its interfaces.
    fn of_linode(&self) -> Option<(u64, &str)> {
        match self {
            Device::Linode { device, linode } | Device::Interface { device, linode, .. } => Some((*device, linode)),
            Device::Other => None,
        }
    }
}

fn device(d: &Value) -> Device {
    let e = &d["entity"];
    let parsed = || -> Option<Device> {
        let device = d["id"].as_u64()?;
        match e["type"].as_str()? {
            "linode" => Some(Device::Linode { device, linode: e["id"].as_u64()?.to_string() }),
            "linode_interface" => {
                let interface = e["id"].as_u64()?;
                // Its Linode, from `parent_entity`, or else from the entity's URL.
                let linode = match &e["parent_entity"] {
                    p if p["type"] == "linode" => p["id"].as_u64()?,
                    _ => interfaces::linode_in_url(e["url"].as_str()?, interface)?,
                };
                Some(Device::Interface { device, linode: linode.to_string(), interface })
            }
            _ => None,
        }
    };
    parsed().unwrap_or(Device::Other)
}

fn addresses(cidrs: &[String]) -> Value {
    let (v6, v4): (Vec<&String>, Vec<&String>) = cidrs.iter().partition(|s| s.contains(':'));
    let mut addresses = json!({});
    if !v4.is_empty() {
        addresses["ipv4"] = json!(v4);
    }
    if !v6.is_empty() {
        addresses["ipv6"] = json!(v6);
    }
    addresses
}

/// A rule's addresses, canonical and sorted, or None if one isn't an address.
fn read_addresses(a: &Value) -> Option<Vec<String>> {
    let mut out = Vec::new();
    for family in ["ipv4", "ipv6"] {
        for a in a[family].as_array().into_iter().flatten() {
            out.push(super::firewall::cidr(a.as_str()?).ok()?);
        }
    }
    out.sort();
    out.dedup();
    Some(out)
}

/// Our rules as Linode's: inbound dropped but for each rule, outbound open but for
/// `outbound`, in order.
fn rules_body(rules: &[FirewallRule], outbound: &[Outbound]) -> Value {
    let inbound: Vec<Value> = rules
        .iter()
        .map(|r| {
            json!({ "label": r.label, "action": "ACCEPT", "protocol": "TCP", "ports": r.ports, "addresses": addresses(&r.sources) })
        })
        .collect();
    let outbound: Vec<Value> = outbound
        .iter()
        .map(|o| {
            let mut v = json!({ "label": o.label, "action": o.action, "protocol": o.protocol, "addresses": addresses(&o.destinations) });
            if let Some(p) = &o.ports {
                v["ports"] = json!(p);
            }
            v
        })
        .collect();
    json!({ "inbound_policy": "DROP", "outbound_policy": "ACCEPT", "inbound": inbound, "outbound": outbound })
}

/// One of Linode's outbound rules as ours. No ports, or all of them, is every port.
fn read_outbound(x: &Value) -> Option<Outbound> {
    let action = x["action"].as_str().filter(|a| matches!(*a, "ACCEPT" | "DROP"))?;
    let protocol = x["protocol"].as_str().filter(|p| matches!(*p, "TCP" | "UDP"))?;
    let ports = match &x["ports"] {
        Value::Null => None,
        Value::String(p) => Some(p.replace(' ', "")).filter(|p| !p.is_empty() && p != "1-65535"),
        _ => return None,
    };
    Some(Outbound {
        label: x["label"].as_str()?.into(),
        action: action.into(),
        protocol: protocol.into(),
        ports,
        destinations: read_addresses(&x["addresses"])?,
    })
}

/// Linode's rules as ours, or None if they aren't of the shape we make: outbound must
/// be exactly `outbound`, in the same order.
fn our_rules(r: &Value, outbound: &[Outbound]) -> Option<Vec<FirewallRule>> {
    if r["inbound_policy"] != "DROP" || r["outbound_policy"] != "ACCEPT" {
        return None;
    }
    let out = match &r["outbound"] {
        Value::Null => Vec::new(),
        v => v.as_array()?.iter().map(read_outbound).collect::<Option<Vec<_>>>()?,
    };
    if out != outbound {
        return None;
    }
    r["inbound"]
        .as_array()?
        .iter()
        .map(|x| {
            if x["action"] != "ACCEPT" || x["protocol"] != "TCP" {
                return None;
            }
            Some(FirewallRule {
                label: x["label"].as_str()?.into(),
                ports: x["ports"].as_str()?.replace(' ', ""),
                sources: read_addresses(&x["addresses"])?,
            })
        })
        .collect()
}

/// Linode's `{"errors": [{"field", "reason"}]}`, as one of ours.
fn error(status: StatusCode, v: &Value) -> ProviderError {
    let errors = v["errors"].as_array().cloned().unwrap_or_default();
    let label_taken = errors.iter().any(|e| {
        e["field"] == "label"
            && e["reason"]
                .as_str()
                .is_some_and(|r| r.to_ascii_lowercase().contains("unique"))
    });
    match status {
        StatusCode::NOT_FOUND => ProviderError::NotFound,
        StatusCode::TOO_MANY_REQUESTS => ProviderError::RateLimited,
        StatusCode::BAD_REQUEST if label_taken => ProviderError::LabelTaken,
        _ => {
            let reasons: Vec<String> = errors
                .iter()
                .filter_map(|e| {
                    let reason = e["reason"].as_str()?;
                    Some(match e["field"].as_str() {
                        Some(f) => format!("{f}: {reason}"),
                        None => reason.to_string(),
                    })
                })
                .collect();
            let message = if reasons.is_empty() {
                status.canonical_reason().unwrap_or("error").to_string()
            } else {
                reasons.join("; ")
            };
            ProviderError::Api {
                status: status.as_u16(),
                message: crate::audit::clip(&message, 300),
            }
        }
    }
}

fn machine(v: &Value) -> Result<ProviderMachine, ProviderError> {
    let bad = || ProviderError::Transport("Linode sent a machine we couldn't read".into());
    let id = v["id"].as_u64().ok_or_else(bad)?;
    let text = |k: &str| v[k].as_str().unwrap_or_default().to_string();
    Ok(ProviderMachine {
        id: id.to_string(),
        label: text("label"),
        status: text("status"),
        plan: text("type"),
        region: text("region"),
        ipv4: v["ipv4"]
            .as_array()
            .and_then(|a| a.first())
            .and_then(Value::as_str)
            .map(String::from),
        backups: v["backups"]["enabled"].as_bool().unwrap_or(false),
        last_backup_at: v["backups"]["last_successful"].as_str().and_then(time),
        tags: v["tags"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(Value::as_str)
                    .map(String::from)
                    .collect()
            })
            .unwrap_or_default(),
        user_data: false,
    })
}

/// A Linode time, in ms. Linode writes UTC without a zone (`2018-01-01T00:01:01`).
fn time(s: &str) -> Option<i64> {
    chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S%.f")
        .map(|t| t.and_utc().timestamp_millis())
        .or_else(|_| chrono::DateTime::parse_from_rfc3339(s).map(|t| t.timestamp_millis()))
        .ok()
}

/// The subnet of a team's VPC that its machines join (ADR 0189).
pub const SUBNET_LABEL: &str = "machines";

/// A VPC as a team network: its `machines` subnet, which must have a range.
fn network(v: &Value, created: bool) -> Result<TeamNetwork, ProviderError> {
    let bad = || ProviderError::Transport("Linode sent a VPC we couldn't read".into());
    let id = v["id"].as_u64().ok_or_else(bad)?;
    let label = v["label"].as_str().unwrap_or_default().to_string();
    let subnet = v["subnets"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|s| s["label"] == SUBNET_LABEL)
        .ok_or_else(|| ProviderError::Api { status: 409, message: format!("VPC {label} has no {SUBNET_LABEL} subnet") })?;
    let range = subnet["ipv4"].as_str().and_then(|r| super::firewall::cidr(r).ok()).ok_or_else(bad)?;
    Ok(TeamNetwork {
        id: id.to_string(),
        label,
        region: v["region"].as_str().unwrap_or_default().into(),
        subnet_id: subnet["id"].as_u64().ok_or_else(bad)?.to_string(),
        subnet: range,
        created,
    })
}

/// Linode ids are numbers; anything else never reaches a URL path.
fn path_id(id: &str) -> Result<&str, ProviderError> {
    if !id.is_empty() && id.len() <= 20 && id.bytes().all(|b| b.is_ascii_digit()) {
        Ok(id)
    } else {
        Err(ProviderError::Api {
            status: 400,
            message: "not a Linode id".into(),
        })
    }
}

/// Linode wants a root password with any image. Nobody needs it: people come in with
/// `authorized_keys`, and the control plane through enrollment (ADR 0025). So it is
/// random, sent once, and kept nowhere.
fn root_pass() -> Zeroizing<String> {
    Zeroizing::new(format!(
        "Sb-{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(crate::random_bytes(32))
    ))
}

impl MachineProvider for Linode {
    fn name(&self) -> &'static str {
        "linode"
    }

    fn substrate(&self) -> &'static str {
        "vm"
    }

    fn settings(&self) -> Value {
        json!({
            "firewallEgress": if self.outbound.is_empty() { "off" } else { "on" },
            "egressRules": outbound_json(&self.outbound),
            "interfaces": self.generation.as_str(),
        })
    }

    fn firewall_egress(&self) -> Option<Value> {
        Some(outbound_json(&self.outbound))
    }

    fn create<'a>(&'a self, spec: &'a CreateSpec) -> Fut<'a, ProviderMachine> {
        Box::pin(async move {
            let pass = root_pass();
            let mut body = json!({
                "label": spec.label,
                "region": spec.region,
                "type": spec.plan,
                "image": spec.image,
                "root_pass": pass.as_str(),
                "tags": spec.tags,
                "booted": true,
            });
            if !spec.authorized_keys.is_empty() {
                body["authorized_keys"] = json!(spec.authorized_keys);
            }
            if let Some(ud) = &spec.user_data {
                body["metadata"] = json!({
                    "user_data": base64::engine::general_purpose::STANDARD.encode(ud)
                });
            }
            let number = |id: &Option<String>| -> Result<Option<u64>, ProviderError> {
                id.as_deref().map(|i| Ok(path_id(i)?.parse::<u64>().unwrap_or_default())).transpose()
            };
            interfaces::create(&mut body, self.generation, number(&spec.firewall_id)?, number(&spec.subnet_id)?)?;
            match self.call(Method::POST, "/linode/instances", None, Some(&body)).await {
                Ok(v) => machine(&v),
                Err(ProviderError::Api { status, message }) if message.contains("interface_generation") => Err(ProviderError::Api {
                    status,
                    message: format!("{message}; MACHINE_LINODE_INTERFACES={} must be a kind the account allows", self.generation.as_str()),
                }),
                Err(e) => Err(e),
            }
        })
    }

    fn get<'a>(&'a self, id: &'a str) -> Fut<'a, ProviderMachine> {
        Box::pin(async move {
            machine(
                &self
                    .call(
                        Method::GET,
                        &format!("/linode/instances/{}", path_id(id)?),
                        None,
                        None,
                    )
                    .await?,
            )
        })
    }

    fn list<'a>(&'a self, tag: &'a str) -> Fut<'a, Vec<ProviderMachine>> {
        Box::pin(async move {
            let filter = json!({ "tags": tag });
            self.all("/linode/instances", Some(&filter))
                .await?
                .iter()
                .map(machine)
                .collect()
        })
    }

    fn resize<'a>(&'a self, id: &'a str, plan: &'a str) -> Fut<'a, ()> {
        Box::pin(async move {
            let body =
                json!({ "type": plan, "allow_auto_disk_resize": true, "migration_type": "cold" });
            self.call(
                Method::POST,
                &format!("/linode/instances/{}/resize", path_id(id)?),
                None,
                Some(&body),
            )
            .await
            .map(drop)
        })
    }

    /// `GET /linode/types/{plan}`: its `disk`, in MiB. Reads only; costs nothing.
    fn plan_disk<'a>(&'a self, plan: &'a str) -> Fut<'a, Option<u64>> {
        Box::pin(async move {
            if !super::slug(plan, 64) {
                return Ok(None);
            }
            let v = self.call(Method::GET, &format!("/linode/types/{plan}"), None, None).await?;
            Ok(v["disk"].as_u64().map(|mib| mib.saturating_mul(1 << 20)))
        })
    }

    fn shutdown<'a>(&'a self, id: &'a str) -> Fut<'a, ()> {
        Box::pin(async move {
            self.call(
                Method::POST,
                &format!("/linode/instances/{}/shutdown", path_id(id)?),
                None,
                None,
            )
            .await
            .map(drop)
        })
    }

    fn boot<'a>(&'a self, id: &'a str) -> Fut<'a, ()> {
        Box::pin(async move {
            self.call(
                Method::POST,
                &format!("/linode/instances/{}/boot", path_id(id)?),
                None,
                None,
            )
            .await
            .map(drop)
        })
    }

    fn enable_backups<'a>(&'a self, id: &'a str) -> Fut<'a, ()> {
        Box::pin(async move {
            self.call(
                Method::POST,
                &format!("/linode/instances/{}/backups/enable", path_id(id)?),
                None,
                None,
            )
            .await
            .map(drop)
        })
    }

    /// Linode Backups: daily, kept apart from the Linode's disks, and restored from
    /// Linode's console onto it or a new Linode.
    fn reports_backups(&self) -> bool {
        true
    }

    fn delete<'a>(&'a self, id: &'a str) -> Fut<'a, ()> {
        Box::pin(async move {
            match self
                .call(
                    Method::DELETE,
                    &format!("/linode/instances/{}", path_id(id)?),
                    None,
                    None,
                )
                .await
            {
                Ok(_) | Err(ProviderError::NotFound) => Ok(()),
                Err(e) => Err(e),
            }
        })
    }

    fn rebuild<'a>(&'a self, id: &'a str, spec: &'a RebuildSpec) -> Fut<'a, ()> {
        Box::pin(async move {
            let pass = root_pass();
            let mut body = json!({
                "image": spec.image,
                "root_pass": pass.as_str(),
                "booted": true,
                "metadata": { "user_data": base64::engine::general_purpose::STANDARD.encode(&spec.user_data) },
            });
            if !spec.authorized_keys.is_empty() {
                body["authorized_keys"] = json!(spec.authorized_keys);
            }
            self.call(
                Method::POST,
                &format!("/linode/instances/{}/rebuild", path_id(id)?),
                None,
                Some(&body),
            )
            .await
            .map(drop)
        })
    }

    /// VPCs are free. Labels are unique per account, so a create that lost a race finds
    /// the winner's.
    fn ensure_team_network<'a>(&'a self, label: &'a str, region: &'a str, subnet: &'a str) -> Fut<'a, TeamNetwork> {
        Box::pin(async move {
            let filter = json!({ "label": label });
            let found = self.all("/vpcs", Some(&filter)).await?.into_iter().find(|v| v["label"] == label);
            let v = match found {
                Some(v) => v,
                None => {
                    let body = json!({
                        "label": label, "region": region, "description": "SuperBot: one team's machines (ADR 0189)",
                        "subnets": [{ "label": SUBNET_LABEL, "ipv4": subnet }],
                    });
                    match self.call(Method::POST, "/vpcs", None, Some(&body)).await {
                        Ok(v) => return network(&v, true),
                        Err(ProviderError::LabelTaken) => self
                            .all("/vpcs", Some(&filter))
                            .await?
                            .into_iter()
                            .find(|v| v["label"] == label)
                            .ok_or(ProviderError::LabelTaken)?,
                        Err(e) => return Err(e),
                    }
                }
            };
            if v["region"] != region {
                return Err(ProviderError::Api { status: 409, message: format!("VPC {label} is in {}, not {region}", v["region"].as_str().unwrap_or("?")) });
            }
            let n = match network(&v, false) {
                Err(ProviderError::Api { status: 409, .. }) => {
                    let id = v["id"].as_u64().unwrap_or_default();
                    let body = json!({ "label": SUBNET_LABEL, "ipv4": subnet });
                    self.call(Method::POST, &format!("/vpcs/{id}/subnets"), None, Some(&body)).await?;
                    let v = self.call(Method::GET, &format!("/vpcs/{id}"), None, None).await?;
                    network(&v, false)?
                }
                n => n?,
            };
            if n.subnet != subnet {
                return Err(ProviderError::Api {
                    status: 409,
                    message: format!("VPC {label}'s {SUBNET_LABEL} subnet is {}, not MACHINE_TEAM_NETWORK_SUBNET's {subnet}", n.subnet),
                });
            }
            Ok(n)
        })
    }

    /// Every VPC whose label starts with `prefix`, even one whose `machines` subnet was
    /// renamed or removed (its subnet left empty): machines on it still have to leave.
    fn team_networks<'a>(&'a self, prefix: &'a str) -> Fut<'a, Vec<TeamNetwork>> {
        Box::pin(async move {
            let mut out = Vec::new();
            for v in self.all("/vpcs", None).await? {
                if !v["label"].as_str().is_some_and(|l| l.starts_with(prefix)) {
                    continue;
                }
                out.push(match network(&v, false) {
                    Ok(n) => n,
                    Err(_) => TeamNetwork {
                        id: v["id"].as_u64().ok_or_else(|| ProviderError::Transport("Linode sent a VPC we couldn't read".into()))?.to_string(),
                        label: v["label"].as_str().unwrap_or_default().into(),
                        region: v["region"].as_str().unwrap_or_default().into(),
                        subnet_id: String::new(),
                        subnet: String::new(),
                        created: false,
                    },
                });
            }
            Ok(out)
        })
    }

    fn team_network_members<'a>(&'a self, id: &'a str) -> Fut<'a, Vec<NetworkMember>> {
        Box::pin(async move {
            let mut out = Vec::new();
            for s in self.all(&format!("/vpcs/{}/subnets", path_id(id)?), None).await? {
                for l in s["linodes"].as_array().into_iter().flatten() {
                    let Some(machine) = l["id"].as_u64() else { continue };
                    for i in l["interfaces"].as_array().into_iter().flatten() {
                        let Some(interface) = i["id"].as_u64() else { continue };
                        // Unsaid is taken as active: it is left only once the machine is off.
                        let active = i["active"].as_bool().unwrap_or(true);
                        // No profile: a Linode interface (ADR 0226), taken off only while
                        // the Linode is off.
                        let (config, needs_power_off) = match &i["config_id"] {
                            Value::Null => (String::new(), true),
                            c => match c.as_u64() {
                                Some(c) => (c.to_string(), false),
                                None => continue,
                            },
                        };
                        out.push(NetworkMember { machine: machine.to_string(), config, interface: interface.to_string(), active, needs_power_off });
                    }
                }
            }
            Ok(out)
        })
    }

    fn leave_team_network<'a>(&'a self, m: &'a NetworkMember) -> Fut<'a, ()> {
        Box::pin(async move {
            let path = if m.config.is_empty() {
                format!("/linode/instances/{}/interfaces/{}", path_id(&m.machine)?, path_id(&m.interface)?)
            } else {
                format!(
                    "/linode/instances/{}/configs/{}/interfaces/{}",
                    path_id(&m.machine)?,
                    path_id(&m.config)?,
                    path_id(&m.interface)?
                )
            };
            match self.call(Method::DELETE, &path, None, None).await {
                Ok(_) | Err(ProviderError::NotFound) => Ok(()),
                Err(e) => Err(e),
            }
        })
    }

    /// Configuration-profile interfaces, as a create's are (ADR 0189), appended to the
    /// Linode's one profile: its public interface first if the profile lists none (an
    /// empty list is Linode's public default, and a VPC interface alone would become
    /// the primary), then the VPC's. Linode puts them in place at the next boot.
    /// A Linode with Linode interfaces is given a VPC interface of its own instead,
    /// behind its public interface's firewall, while it is off (ADR 0226).
    fn join_team_network<'a>(&'a self, machine: &'a str, n: &'a TeamNetwork) -> Fut<'a, ()> {
        Box::pin(async move {
            let id = path_id(machine)?;
            let subnet: u64 = path_id(&n.subnet_id)?.parse().unwrap_or_default();
            let refused = |message: String| ProviderError::Api { status: 409, message };
            let l = self.call(Method::GET, &format!("/linode/instances/{id}"), None, None).await?;
            if interfaces::has_linode_interfaces(&l) {
                return self.join_with_linode_interfaces(id, &l, subnet).await;
            }
            let configs = self.all(&format!("/linode/instances/{id}/configs"), None).await?;
            let [c] = configs.as_slice() else {
                return Err(refused(format!("it has {} configuration profiles; one is needed to know which it boots", configs.len())));
            };
            let config = c["id"].as_u64().ok_or_else(|| ProviderError::Transport("Linode sent a configuration profile we couldn't read".into()))?;
            let interfaces = c["interfaces"].as_array().cloned().unwrap_or_default();
            if let Some(v) = interfaces.iter().find(|i| i["purpose"] == "vpc") {
                return if v["subnet_id"].as_u64() == Some(subnet) { Ok(()) } else { Err(refused("it is on another VPC; it leaves that one first".into())) };
            }
            let path = format!("/linode/instances/{id}/configs/{config}/interfaces");
            if interfaces.is_empty() {
                self.call(Method::POST, &path, None, Some(&json!({ "purpose": "public" }))).await?;
            } else if interfaces[0]["purpose"] != "public" {
                return Err(refused("its first interface isn't its public one, which must stay the primary".into()));
            }
            self.call(Method::POST, &path, None, Some(&json!({ "purpose": "vpc", "subnet_id": subnet }))).await?;
            Ok(())
        })
    }

    fn team_network_needs_power_off<'a>(&'a self, machine: &'a str) -> Fut<'a, bool> {
        Box::pin(async move {
            let l = self.call(Method::GET, &format!("/linode/instances/{}", path_id(machine)?), None, None).await?;
            Ok(interfaces::has_linode_interfaces(&l))
        })
    }

    fn find_firewall<'a>(&'a self, label: &'a str) -> Fut<'a, Option<ProviderFirewall>> {
        Box::pin(async move {
            let filter = json!({ "label": label });
            for f in self.all("/networking/firewalls", Some(&filter)).await? {
                let f = self.firewall(&f)?;
                if f.label == label {
                    return Ok(Some(f));
                }
            }
            Ok(None)
        })
    }

    fn get_firewall<'a>(&'a self, id: &'a str) -> Fut<'a, ProviderFirewall> {
        Box::pin(async move {
            let v = self
                .call(
                    Method::GET,
                    &format!("/networking/firewalls/{}", path_id(id)?),
                    None,
                    None,
                )
                .await?;
            self.firewall(&v)
        })
    }

    fn create_firewall<'a>(
        &'a self,
        label: &'a str,
        tags: &'a [String],
        rules: &'a [FirewallRule],
    ) -> Fut<'a, ProviderFirewall> {
        Box::pin(async move {
            let body = json!({ "label": label, "tags": tags, "rules": rules_body(rules, &self.outbound) });
            self.firewall(
                &self
                    .call(Method::POST, "/networking/firewalls", None, Some(&body))
                    .await?,
            )
        })
    }

    fn set_firewall_rules<'a>(&'a self, id: &'a str, rules: &'a [FirewallRule]) -> Fut<'a, ()> {
        Box::pin(async move {
            self.call(
                Method::PUT,
                &format!("/networking/firewalls/{}/rules", path_id(id)?),
                None,
                Some(&rules_body(rules, &self.outbound)),
            )
            .await
            .map(drop)
        })
    }

    fn enable_firewall<'a>(&'a self, id: &'a str) -> Fut<'a, ()> {
        Box::pin(async move {
            self.call(
                Method::PUT,
                &format!("/networking/firewalls/{}", path_id(id)?),
                None,
                Some(&json!({ "status": "enabled" })),
            )
            .await
            .map(drop)
        })
    }

    /// A Linode with Linode interfaces counts as covered only once every public and
    /// VPC interface it has is behind the firewall; one only partly behind is `partly`,
    /// so the sweep attaches the rest to this firewall, not another (ADR 0226).
    fn firewall_devices<'a>(&'a self, id: &'a str) -> Fut<'a, FirewallDevices> {
        Box::pin(async move {
            let mut out = FirewallDevices::default();
            let mut by_linode: std::collections::BTreeMap<String, std::collections::BTreeSet<u64>> = Default::default();
            for d in self.devices(id).await? {
                match d {
                    Device::Linode { linode, .. } => out.machines.push(linode),
                    Device::Interface { linode, interface, .. } => {
                        by_linode.entry(linode).or_default().insert(interface);
                    }
                    Device::Other => out.others += 1,
                }
            }
            for (linode, behind) in by_linode {
                match self.linode_interfaces(&linode).await {
                    Ok(all) if interfaces::all_behind(&all, &behind) => out.machines.push(linode),
                    Ok(_) => out.partly.push(linode),
                    Err(ProviderError::NotFound) => out.others += 1,
                    Err(e) => return Err(e),
                }
            }
            Ok(out)
        })
    }

    /// From the Linode's side: its own firewalls, or each interface's.
    fn firewall_covers<'a>(&'a self, id: &'a str, machine: &'a str) -> Fut<'a, bool> {
        Box::pin(async move {
            let (fw, linode) = (path_id(id)?, path_id(machine)?);
            let l = match self.call(Method::GET, &format!("/linode/instances/{linode}"), None, None).await {
                Err(ProviderError::NotFound) => return Ok(false),
                l => l?,
            };
            let has = |firewalls: &[Value]| firewalls.iter().any(|f| f["id"].as_u64().is_some_and(|f| f.to_string() == fw));
            if !interfaces::has_linode_interfaces(&l) {
                return Ok(has(&self.all(&format!("/linode/instances/{linode}/firewalls"), None).await?));
            }
            let filtered = interfaces::filtered(&self.linode_interfaces(linode).await?);
            if filtered.is_empty() {
                return Ok(false);
            }
            for i in filtered {
                if !has(&self.interface_firewalls(linode, i).await?) {
                    return Ok(false);
                }
            }
            Ok(true)
        })
    }

    /// The Linode itself, or each of its public and VPC Linode interfaces not behind
    /// the firewall yet. Linode refuses an interface behind another firewall.
    fn attach_firewall<'a>(&'a self, id: &'a str, machine: &'a str) -> Fut<'a, ()> {
        Box::pin(async move {
            let (fw, linode) = (path_id(id)?, path_id(machine)?);
            let l = self.call(Method::GET, &format!("/linode/instances/{linode}"), None, None).await?;
            let add = async |entity: u64, kind: &str| {
                let body = json!({ "id": entity, "type": kind });
                self.call(Method::POST, &format!("/networking/firewalls/{fw}/devices"), None, Some(&body)).await.map(drop)
            };
            if !interfaces::has_linode_interfaces(&l) {
                return add(linode.parse().unwrap_or_default(), "linode").await;
            }
            let filtered = interfaces::filtered(&self.linode_interfaces(linode).await?);
            if filtered.is_empty() {
                return Err(ProviderError::Api { status: 409, message: "it has no public or VPC interface for a firewall to cover".into() });
            }
            let behind: Vec<u64> = self
                .devices(fw)
                .await?
                .into_iter()
                .filter_map(|d| match d {
                    Device::Interface { linode: l, interface, .. } if l == linode => Some(interface),
                    _ => None,
                })
                .collect();
            for i in filtered.into_iter().filter(|i| !behind.contains(i)) {
                add(i, "linode_interface").await?;
            }
            Ok(())
        })
    }

    /// Every device of the Linode's: itself, or each of its interfaces.
    fn detach_firewall<'a>(&'a self, id: &'a str, machine: &'a str) -> Fut<'a, ()> {
        Box::pin(async move {
            let devices = match self.devices(id).await {
                Err(ProviderError::NotFound) => return Ok(()),
                d => d?,
            };
            for d in devices {
                let Some((device, _)) = d.of_linode().filter(|(_, l)| *l == machine) else { continue };
                match self.call(Method::DELETE, &format!("/networking/firewalls/{}/devices/{device}", path_id(id)?), None, None).await {
                    Ok(_) | Err(ProviderError::NotFound) => {}
                    Err(e) => return Err(e),
                }
            }
            Ok(())
        })
    }

    fn delete_firewall<'a>(&'a self, id: &'a str) -> Fut<'a, ()> {
        Box::pin(async move {
            match self
                .call(
                    Method::DELETE,
                    &format!("/networking/firewalls/{}", path_id(id)?),
                    None,
                    None,
                )
                .await
            {
                Ok(_) | Err(ProviderError::NotFound) => Ok(()),
                Err(e) => Err(e),
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::extract::{Path, Query, State};
    use axum::http::HeaderMap;
    use axum::routing::{get, post};
    use axum::{Json, Router};
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    const TOKEN: &str = "linode-test-token-0123456789";

    /// What the stand-in saw: method, path, X-Filter, body.
    type Seen = Arc<Mutex<Vec<(String, String, Option<String>, Value)>>>;

    fn instance(id: u64, label: &str, status: &str) -> Value {
        json!({
            "id": id, "label": label, "status": status, "type": "g6-standard-1", "region": "gb-lon",
            "ipv4": ["192.0.2.10", "192.168.1.1"], "backups": { "enabled": false }, "tags": ["superbot"],
        })
    }

    /// A local stand-in for api.linode.com. It refuses any request without the token,
    /// says label "taken" is taken, and pages lists two at a time.
    async fn fake_api() -> (Linode, Seen) {
        let seen: Seen = Arc::default();
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let port = listener.local_addr().unwrap().port();
        let record = |s: &Seen, method: &str, path: String, h: &HeaderMap, body: Value| {
            s.lock().unwrap().push((
                method.into(),
                path,
                h.get("x-filter").map(|v| v.to_str().unwrap().to_string()),
                body,
            ));
        };
        let authed = |h: &HeaderMap| {
            h.get("authorization").and_then(|v| v.to_str().ok()) == Some(&format!("Bearer {TOKEN}"))
        };
        let unauthorized = || {
            (
                StatusCode::UNAUTHORIZED,
                Json(json!({ "errors": [{ "reason": "Invalid Token" }] })),
            )
        };
        let r = Router::new()
            .route(
                "/v4/linode/instances",
                post(move |State(s): State<Seen>, h: HeaderMap, Json(b): Json<Value>| async move {
                    record(&s, "POST", "/linode/instances".into(), &h, b.clone());
                    if !authed(&h) {
                        return unauthorized();
                    }
                    if b["label"] == "taken" {
                        return (StatusCode::BAD_REQUEST, Json(json!({ "errors": [{ "field": "label", "reason": "Label must be unique among your linodes" }] })));
                    }
                    if b["type"] == "g6-nope" {
                        return (StatusCode::BAD_REQUEST, Json(json!({ "errors": [{ "field": "type", "reason": "A valid plan type by that ID was not found" }] })));
                    }
                    (StatusCode::OK, Json(json!({ "label": b["label"], "status": "provisioning", "id": 42, "type": b["type"], "region": b["region"], "ipv4": [], "backups": { "enabled": false }, "tags": b["tags"] })))
                })
                .get(move |State(s): State<Seen>, h: HeaderMap, Query(q): Query<HashMap<String, String>>| async move {
                    let page: u64 = q["page"].parse().unwrap();
                    record(&s, "GET", format!("/linode/instances?page={page}&page_size={}", q["page_size"]), &h, Value::Null);
                    if !authed(&h) {
                        return unauthorized();
                    }
                    let all: Vec<Value> = (1..=3).map(|i| instance(i, &format!("superbot-m{i}"), "running")).collect();
                    let data: Vec<Value> = all.into_iter().skip((page as usize - 1) * 2).take(2).collect();
                    (StatusCode::OK, Json(json!({ "data": data, "page": page, "pages": 2, "results": 3 })))
                }),
            )
            .route(
                "/v4/linode/instances/{id}",
                get(move |State(s): State<Seen>, h: HeaderMap, Path(id): Path<u64>| async move {
                    record(&s, "GET", format!("/linode/instances/{id}"), &h, Value::Null);
                    match id {
                        7 | 8 => (StatusCode::OK, Json(instance(id, &format!("superbot-m{id}"), "running"))),
                        21..=25 => (StatusCode::OK, Json(instance(id, &format!("superbot-m{id}"), "running"))),
                        26 => {
                            let mut m = instance(26, "superbot-m26", "running");
                            m["interface_generation"] = json!("linode");
                            (StatusCode::OK, Json(m))
                        }
                        6 => {
                            let mut m = instance(6, "superbot-m6", "running");
                            m["backups"] = json!({ "available": true, "enabled": true, "last_successful": "2026-11-21T03:14:07",
                                "schedule": { "day": "Scheduling", "window": "Scheduling" } });
                            (StatusCode::OK, Json(m))
                        }
                        _ => (StatusCode::NOT_FOUND, Json(json!({ "errors": [{ "reason": "Not found" }] }))),
                    }
                })
                .delete(move |State(s): State<Seen>, h: HeaderMap, Path(id): Path<u64>| async move {
                    record(&s, "DELETE", format!("/linode/instances/{id}"), &h, Value::Null);
                    match id {
                        7 => (StatusCode::OK, Json(json!({}))),
                        _ => (StatusCode::NOT_FOUND, Json(json!({ "errors": [{ "reason": "Not found" }] }))),
                    }
                }),
            )
            .route(
                "/v4/linode/instances/{id}/{*action}",
                post(move |State(s): State<Seen>, h: HeaderMap, Path((id, action)): Path<(u64, String)>, body: axum::body::Bytes| async move {
                    let b = serde_json::from_slice(&body).unwrap_or(Value::Null);
                    record(&s, "POST", format!("/linode/instances/{id}/{action}"), &h, b);
                    match id {
                        7 | 21..=26 => (StatusCode::OK, Json(json!({}))),
                        8 => (StatusCode::TOO_MANY_REQUESTS, Json(json!({ "errors": [{ "reason": "Too many requests" }] }))),
                        _ => (StatusCode::BAD_REQUEST, Json(json!({ "errors": [{ "reason": "Linode busy." }] }))),
                    }
                })
                // Configuration profiles for joining a team's VPC (ADR 0202): 21 lists no
                // interfaces (Linode's public default), 22 its public one, 23 is on the
                // VPC already, 24 has two profiles, 25 is on another VPC.
                .get(move |State(s): State<Seen>, h: HeaderMap, Path((id, action)): Path<(u64, String)>| async move {
                    record(&s, "GET", format!("/linode/instances/{id}/{action}"), &h, Value::Null);
                    let config = |n: u64, interfaces: Value| json!({ "id": n, "label": "My Ubuntu Profile", "interfaces": interfaces });
                    let public = json!({ "id": 1, "purpose": "public", "primary": false, "active": true });
                    let vpc = |subnet: u64| json!({ "id": 2, "purpose": "vpc", "subnet_id": subnet, "vpc_id": 5, "active": false });
                    let data = match (id, action.as_str()) {
                        (21, "configs") => json!([config(210, json!([]))]),
                        (22, "configs") => json!([config(220, json!([public]))]),
                        (23, "configs") => json!([config(230, json!([public, vpc(50)]))]),
                        (24, "configs") => json!([config(240, json!([])), config(241, json!([]))]),
                        (25, "configs") => json!([config(250, json!([public, vpc(70)]))]),
                        _ => return (StatusCode::NOT_FOUND, Json(json!({ "errors": [{ "reason": "Not found" }] }))),
                    };
                    (StatusCode::OK, Json(json!({ "data": data, "page": 1, "pages": 1, "results": 1 })))
                })
                .delete(move |State(s): State<Seen>, h: HeaderMap, Path((id, action)): Path<(u64, String)>| async move {
                    record(&s, "DELETE", format!("/linode/instances/{id}/{action}"), &h, Value::Null);
                    match id {
                        7 => (StatusCode::OK, Json(json!({}))),
                        8 => (StatusCode::BAD_REQUEST, Json(json!({ "errors": [{ "reason": "Cannot delete an active interface." }] }))),
                        _ => (StatusCode::NOT_FOUND, Json(json!({ "errors": [{ "reason": "Not found" }] }))),
                    }
                }),
            )
            // VPCs, as Linode answers: `superbot-team-a-gb-lon` is there with its subnet,
            // `-bare-` has none yet, `-far-` is in another region, `-odd-` has another
            // range, and `office` isn't ours.
            .route(
                "/v4/vpcs",
                get(move |State(s): State<Seen>, h: HeaderMap, Query(q): Query<HashMap<String, String>>| async move {
                    record(&s, "GET", format!("/vpcs?page={}&page_size={}", q["page"], q["page_size"]), &h, Value::Null);
                    let vpc = |id: u64, label: &str, region: &str, subnets: Value| json!({ "id": id, "label": label, "region": region, "subnets": subnets });
                    let machines = |id: u64, range: &str| json!([{ "id": id, "label": "machines", "ipv4": range, "linodes": [] }]);
                    let all = [
                        vpc(5, "superbot-team-a-gb-lon", "gb-lon", machines(50, "10.248.0.0/22")),
                        vpc(6, "superbot-team-bare-gb-lon", "gb-lon", json!([])),
                        vpc(7, "superbot-team-far-gb-lon", "us-east", machines(70, "10.248.0.0/22")),
                        vpc(8, "superbot-team-odd-gb-lon", "gb-lon", machines(80, "10.9.0.0/24")),
                        vpc(4, "office", "gb-lon", machines(40, "10.248.0.0/22")),
                    ];
                    let label = h.get("x-filter").and_then(|f| serde_json::from_str::<Value>(f.to_str().unwrap()).ok()).map(|f| f["label"].clone());
                    let data: Vec<Value> = all.into_iter().filter(|v| label.as_ref().is_none_or(|l| v["label"] == *l)).collect();
                    (StatusCode::OK, Json(json!({ "data": data, "page": 1, "pages": 1, "results": 1 })))
                })
                .post(move |State(s): State<Seen>, h: HeaderMap, Json(b): Json<Value>| async move {
                    record(&s, "POST", "/vpcs".into(), &h, b.clone());
                    if b["label"] == "taken-vpc" {
                        return (StatusCode::BAD_REQUEST, Json(json!({ "errors": [{ "field": "label", "reason": "Label must be unique among your VPCs" }] })));
                    }
                    (StatusCode::OK, Json(json!({ "id": 9, "label": b["label"], "region": b["region"],
                        "subnets": [{ "id": 90, "label": b["subnets"][0]["label"], "ipv4": b["subnets"][0]["ipv4"], "linodes": [] }] })))
                }),
            )
            .route(
                "/v4/vpcs/{id}",
                get(move |State(s): State<Seen>, h: HeaderMap, Path(id): Path<u64>| async move {
                    record(&s, "GET", format!("/vpcs/{id}"), &h, Value::Null);
                    (StatusCode::OK, Json(json!({ "id": id, "label": "superbot-team-bare-gb-lon", "region": "gb-lon",
                        "subnets": [{ "id": 61, "label": "machines", "ipv4": "10.248.0.0/22" }] })))
                }),
            )
            .route(
                "/v4/vpcs/{id}/subnets",
                get(move |State(s): State<Seen>, h: HeaderMap, Path(id): Path<u64>| async move {
                    record(&s, "GET", format!("/vpcs/{id}/subnets"), &h, Value::Null);
                    (StatusCode::OK, Json(json!({ "data": [
                        { "id": 50, "label": "machines", "ipv4": "10.248.0.0/22", "linodes": [
                            { "id": 7, "interfaces": [{ "id": 701, "active": true, "config_id": 70 }] },
                            { "id": 12, "interfaces": [{ "id": 1201, "active": false, "config_id": null }] },
                        ] },
                        { "id": 51, "label": "services", "ipv4": "10.250.0.0/24", "linodes": [
                            { "id": 30, "interfaces": [{ "id": 3001, "active": true, "config_id": 300 }] },
                            { "id": 31, "interfaces": [{ "id": 3101, "active": false, "config_id": 310 }] },
                        ] },
                    ], "page": 1, "pages": 1, "results": 2 })))
                })
                .post(move |State(s): State<Seen>, h: HeaderMap, Path(id): Path<u64>, Json(b): Json<Value>| async move {
                    record(&s, "POST", format!("/vpcs/{id}/subnets"), &h, b.clone());
                    (StatusCode::OK, Json(json!({ "id": 61, "label": b["label"], "ipv4": b["ipv4"] })))
                }),
            )
            .route(
                "/v4/linode/types/{id}",
                get(move |State(s): State<Seen>, h: HeaderMap, Path(id): Path<String>| async move {
                    record(&s, "GET", format!("/linode/types/{id}"), &h, Value::Null);
                    if !authed(&h) {
                        return unauthorized();
                    }
                    match id.as_str() {
                        "g6-standard-1" => (StatusCode::OK, Json(json!({ "id": id, "disk": 51200, "memory": 2048, "vcpus": 1 }))),
                        _ => (StatusCode::NOT_FOUND, Json(json!({ "errors": [{ "reason": "Not found" }] }))),
                    }
                }),
            )
            .route(
                "/v4/networking/firewalls",
                post(move |State(s): State<Seen>, h: HeaderMap, Json(b): Json<Value>| async move {
                    record(&s, "POST", "/networking/firewalls".into(), &h, b.clone());
                    if b["label"] == "taken-fw" {
                        return (StatusCode::BAD_REQUEST, Json(json!({ "errors": [{ "field": "label", "reason": "Label must be unique" }] })));
                    }
                    (StatusCode::OK, Json(json!({ "id": 77, "label": b["label"], "rules": b["rules"], "status": "enabled", "tags": b["tags"] })))
                })
                .get(move |State(s): State<Seen>, h: HeaderMap, Query(q): Query<HashMap<String, String>>| async move {
                    record(&s, "GET", format!("/networking/firewalls?page={}&page_size={}", q["page"], q["page_size"]), &h, Value::Null);
                    // As Linode answers: its own spellings of addresses and ports, and
                    // a near-namesake the filter would have matched as a prefix.
                    let ours = json!({ "id": 77, "label": "superbot-fw", "status": "disabled", "rules": {
                        "inbound_policy": "DROP", "outbound_policy": "ACCEPT", "outbound": [], "version": 3,
                        "inbound": [{ "label": "agent-from-control-plane", "action": "ACCEPT", "protocol": "TCP", "ports": "7443",
                            "addresses": { "ipv4": ["192.0.2.1/32"], "ipv6": ["2001:DB8::1/128"] } }] } });
                    let other = json!({ "id": 78, "label": "superbot-fw-old", "status": "enabled", "rules": { "inbound_policy": "ACCEPT", "outbound_policy": "ACCEPT", "inbound": [], "outbound": [] } });
                    (StatusCode::OK, Json(json!({ "data": [other, ours], "page": 1, "pages": 1, "results": 2 })))
                }),
            )
            .route(
                "/v4/networking/firewalls/{id}",
                axum::routing::delete(move |State(s): State<Seen>, h: HeaderMap, Path(id): Path<u64>| async move {
                    record(&s, "DELETE", format!("/networking/firewalls/{id}"), &h, Value::Null);
                    match id {
                        77 => (StatusCode::OK, Json(json!({}))),
                        _ => (StatusCode::NOT_FOUND, Json(json!({ "errors": [{ "reason": "Not found" }] }))),
                    }
                })
                .put(move |State(s): State<Seen>, h: HeaderMap, Path(id): Path<u64>, Json(b): Json<Value>| async move {
                    record(&s, "PUT", format!("/networking/firewalls/{id}"), &h, b);
                    (StatusCode::OK, Json(json!({})))
                })
                .get(move |State(s): State<Seen>, h: HeaderMap, Path(id): Path<u64>| async move {
                    record(&s, "GET", format!("/networking/firewalls/{id}"), &h, Value::Null);
                    match id {
                        78 => (StatusCode::OK, Json(json!({ "id": 78, "label": "superbot-fw-old", "status": "enabled",
                            "rules": { "inbound_policy": "ACCEPT", "outbound_policy": "ACCEPT", "inbound": [], "outbound": [] } }))),
                        _ => (StatusCode::NOT_FOUND, Json(json!({ "errors": [{ "reason": "Not found" }] }))),
                    }
                }),
            )
            .route(
                "/v4/networking/firewalls/{id}/rules",
                axum::routing::put(move |State(s): State<Seen>, h: HeaderMap, Path(id): Path<u64>, Json(b): Json<Value>| async move {
                    record(&s, "PUT", format!("/networking/firewalls/{id}/rules"), &h, b);
                    (StatusCode::OK, Json(json!({})))
                }),
            )
            .route(
                "/v4/networking/firewalls/{id}/devices",
                get(move |State(s): State<Seen>, h: HeaderMap, Path(id): Path<u64>| async move {
                    record(&s, "GET", format!("/networking/firewalls/{id}/devices"), &h, Value::Null);
                    match id {
                        77 => (StatusCode::OK, Json(json!({ "data": [
                            { "id": 9001, "entity": { "id": 7, "type": "linode", "label": "superbot-m7" } },
                            { "id": 9002, "entity": { "id": 3, "type": "nodebalancer", "label": "lb" } },
                        ], "page": 1, "pages": 1, "results": 2 }))),
                        _ => (StatusCode::NOT_FOUND, Json(json!({ "errors": [{ "reason": "Not found" }] }))),
                    }
                })
                .post(move |State(s): State<Seen>, h: HeaderMap, Path(id): Path<u64>, Json(b): Json<Value>| async move {
                    record(&s, "POST", format!("/networking/firewalls/{id}/devices"), &h, b);
                    (StatusCode::OK, Json(json!({ "id": 9003 })))
                }),
            )
            .route(
                "/v4/networking/firewalls/{id}/devices/{device}",
                axum::routing::delete(move |State(s): State<Seen>, h: HeaderMap, Path((id, device)): Path<(u64, u64)>| async move {
                    record(&s, "DELETE", format!("/networking/firewalls/{id}/devices/{device}"), &h, Value::Null);
                    (StatusCode::OK, Json(json!({})))
                }),
            )
            .with_state(seen.clone());
        tokio::spawn(async move { axum::serve(listener, r).await.unwrap() });
        (
            Linode::new(TOKEN, &format!("http://127.0.0.1:{port}/v4")),
            seen,
        )
    }

    fn spec(label: &str) -> CreateSpec {
        CreateSpec {
            label: label.into(),
            plan: "g6-standard-1".into(),
            region: "gb-lon".into(),
            image: "linode/ubuntu24.04".into(),
            tags: vec!["superbot".into(), "superbot-user-u1".into()],
            authorized_keys: vec!["ssh-ed25519 AAAAC3Nza test@example".into()],
            user_data: None,
            firewall_id: None,
            subnet_id: None,
        }
    }

    #[tokio::test]
    async fn create_sends_the_spec_and_a_random_root_password() {
        let (api, seen) = fake_api().await;
        let m = api.create(&spec("superbot-m1")).await.unwrap();
        assert_eq!(
            (
                m.id.as_str(),
                m.label.as_str(),
                m.status.as_str(),
                m.plan.as_str(),
                m.ipv4.as_deref()
            ),
            ("42", "superbot-m1", "provisioning", "g6-standard-1", None)
        );
        let again = api.create(&spec("superbot-m2")).await.unwrap();
        assert_eq!(again.id, "42");
        {
            let seen = seen.lock().unwrap();
            let body = &seen[0].3;
            assert_eq!(
                (seen[0].0.as_str(), seen[0].1.as_str()),
                ("POST", "/linode/instances")
            );
            assert_eq!(
                (
                    body["type"].as_str(),
                    body["region"].as_str(),
                    body["image"].as_str(),
                    body["booted"].as_bool()
                ),
                (
                    Some("g6-standard-1"),
                    Some("gb-lon"),
                    Some("linode/ubuntu24.04"),
                    Some(true)
                )
            );
            assert_eq!(body["tags"], json!(["superbot", "superbot-user-u1"]));
            assert_eq!(
                body["authorized_keys"],
                json!(["ssh-ed25519 AAAAC3Nza test@example"])
            );
            let (p1, p2) = (
                body["root_pass"].as_str().unwrap(),
                seen[1].3["root_pass"].as_str().unwrap(),
            );
            assert!(
                p1.len() >= 40 && p1 != p2,
                "a fresh strong password per machine"
            );
            assert!(
                body.get("metadata").is_none(),
                "no user data unless enrollment is on"
            );
        }

        let with = CreateSpec {
            user_data: Some("#cloud-config\n".into()),
            ..spec("superbot-m3")
        };
        api.create(&with).await.unwrap();
        let sent = seen.lock().unwrap().last().unwrap().3.clone();
        assert_eq!(
            sent["metadata"]["user_data"],
            json!("I2Nsb3VkLWNvbmZpZwo="),
            "base64, as Linode wants"
        );
    }

    #[tokio::test]
    async fn errors_are_mapped_and_never_carry_the_token() {
        let (api, _) = fake_api().await;
        assert_eq!(
            api.create(&spec("taken")).await,
            Err(ProviderError::LabelTaken)
        );
        let mut s = spec("superbot-m3");
        s.plan = "g6-nope".into();
        let e = api.create(&s).await.unwrap_err();
        assert_eq!(
            e,
            ProviderError::Api {
                status: 400,
                message: "type: A valid plan type by that ID was not found".into()
            }
        );
        assert_eq!(api.get("9").await, Err(ProviderError::NotFound));
        assert_eq!(api.shutdown("8").await, Err(ProviderError::RateLimited));
        assert_eq!(
            api.boot("9").await,
            Err(ProviderError::Api {
                status: 400,
                message: "Linode busy.".into()
            })
        );
        assert!(
            matches!(
                api.get("../account").await,
                Err(ProviderError::Api { status: 400, .. })
            ),
            "ids never reach the path unchecked"
        );

        let wrong = Linode {
            token: Zeroizing::new("wrong".into()),
            ..Linode::new("x", &api.base)
        };
        let e = wrong.list("superbot").await.unwrap_err();
        assert_eq!(
            e,
            ProviderError::Api {
                status: 401,
                message: "Invalid Token".into()
            }
        );
        let unreachable = Linode::new(TOKEN, "http://127.0.0.1:1/v4");
        let e = unreachable.get("7").await.unwrap_err();
        assert!(matches!(e, ProviderError::Transport(_)), "{e:?}");
        for text in [e.to_string(), format!("{e:?}"), format!("{unreachable:?}")] {
            assert!(!text.contains(TOKEN), "{text}");
        }
    }

    #[tokio::test]
    async fn firewalls() {
        let (api, seen) = fake_api().await;
        let rules = vec![
            FirewallRule {
                label: "agent-from-control-plane".into(),
                ports: "7443".into(),
                sources: vec!["192.0.2.1/32".into(), "2001:db8::1/128".into()],
            },
            FirewallRule {
                label: "ssh-from-operators".into(),
                ports: "22".into(),
                sources: vec!["203.0.113.0/24".into()],
            },
        ];
        let made = api
            .create_firewall("superbot-fw", &["superbot".into()], &rules)
            .await
            .unwrap();
        assert_eq!(
            (made.id.as_str(), made.rules.as_deref()),
            ("77", Some(&rules[..])),
            "what we sent reads back as ours"
        );
        assert_eq!(
            api.create_firewall("taken-fw", &[], &rules).await,
            Err(ProviderError::LabelTaken)
        );
        let found = api.find_firewall("superbot-fw").await.unwrap().unwrap();
        assert_eq!(found.id, "77", "the exact label, not a namesake");
        assert!(made.enabled && !found.enabled, "a disabled one is told apart");
        assert_eq!(
            found.rules,
            Some(vec![rules[0].clone()]),
            "Linode's spelling of an address is the same address"
        );
        assert_eq!(api.find_firewall("superbot-fw-x").await.unwrap(), None);
        let old = api.get_firewall("78").await.unwrap();
        assert_eq!(
            (old.label.as_str(), old.enabled, old.rules),
            ("superbot-fw-old", true, None),
            "an open inbound policy isn't ours"
        );
        assert_eq!(api.get_firewall("79").await, Err(ProviderError::NotFound));
        api.set_firewall_rules("77", &rules[..1]).await.unwrap();
        api.enable_firewall("77").await.unwrap();
        assert_eq!(
            api.firewall_devices("77").await.unwrap(),
            FirewallDevices {
                machines: vec!["7".into()],
                partly: Vec::new(),
                others: 1
            },
            "Linodes by id; anything else counted"
        );
        api.attach_firewall("77", "8").await.unwrap();
        api.detach_firewall("77", "7").await.unwrap();
        api.detach_firewall("77", "8").await.unwrap();
        api.detach_firewall("79", "7").await.unwrap();
        api.delete_firewall("77").await.unwrap();
        api.delete_firewall("78").await.unwrap();
        assert!(api.attach_firewall("77", "../7").await.is_err());
        let behind = CreateSpec {
            firewall_id: Some("77".into()),
            ..spec("superbot-m9")
        };
        api.create(&behind).await.unwrap();

        let seen = seen.lock().unwrap();
        let calls: Vec<(&str, &str)> = seen
            .iter()
            .map(|(m, p, _, _)| (m.as_str(), p.as_str()))
            .collect();
        assert_eq!(
            calls,
            [
                ("POST", "/networking/firewalls"),
                ("POST", "/networking/firewalls"),
                ("GET", "/networking/firewalls?page=1&page_size=500"),
                ("GET", "/networking/firewalls?page=1&page_size=500"),
                ("GET", "/networking/firewalls/78"),
                ("GET", "/networking/firewalls/79"),
                ("PUT", "/networking/firewalls/77/rules"),
                ("PUT", "/networking/firewalls/77"),
                ("GET", "/networking/firewalls/77/devices"),
                ("GET", "/linode/instances/8"),
                ("POST", "/networking/firewalls/77/devices"),
                ("GET", "/networking/firewalls/77/devices"),
                ("DELETE", "/networking/firewalls/77/devices/9001"),
                ("GET", "/networking/firewalls/77/devices"),
                ("GET", "/networking/firewalls/79/devices"),
                ("DELETE", "/networking/firewalls/77"),
                ("DELETE", "/networking/firewalls/78"),
                ("POST", "/linode/instances"),
            ],
            "attach asks which kind of interfaces the Linode has; detach finds the device for the Linode; one not behind it is left alone"
        );
        assert_eq!(
            seen[0].3,
            json!({ "label": "superbot-fw", "tags": ["superbot"], "rules": {
                "inbound_policy": "DROP", "outbound_policy": "ACCEPT", "outbound": [],
                "inbound": [
                    { "label": "agent-from-control-plane", "action": "ACCEPT", "protocol": "TCP", "ports": "7443",
                      "addresses": { "ipv4": ["192.0.2.1/32"], "ipv6": ["2001:db8::1/128"] } },
                    { "label": "ssh-from-operators", "action": "ACCEPT", "protocol": "TCP", "ports": "22",
                      "addresses": { "ipv4": ["203.0.113.0/24"] } },
                ] } })
        );
        assert_eq!(seen[2].2.as_deref(), Some(r#"{"label":"superbot-fw"}"#));
        assert_eq!(seen[6].3["inbound"].as_array().unwrap().len(), 1);
        assert_eq!(seen[7].3, json!({ "status": "enabled" }));
        assert_eq!(seen[10].3, json!({ "id": 8, "type": "linode" }));
        assert_eq!(seen[17].3["firewall_id"], json!(77), "behind it from the first boot");
        assert_eq!(seen[17].3["interface_generation"], "legacy_config", "the kind the firewall covers");
    }

    #[test]
    fn only_our_shape_of_rules_reads_as_ours() {
        let base = json!({ "inbound_policy": "DROP", "outbound_policy": "ACCEPT", "outbound": [], "inbound": [
            { "label": "a", "action": "ACCEPT", "protocol": "TCP", "ports": "7443", "addresses": { "ipv4": ["192.0.2.1/32"] } }] });
        assert!(our_rules(&base, &[]).is_some());
        for (path, v) in [
            ("/inbound_policy", json!("ACCEPT")),
            ("/outbound_policy", json!("DROP")),
            ("/outbound", json!([{ "action": "DROP", "protocol": "TCP" }])),
            ("/inbound/0/action", json!("DROP")),
            ("/inbound/0/protocol", json!("UDP")),
            ("/inbound/0/addresses/ipv4/0", json!("not an address")),
        ] {
            let mut r = base.clone();
            *r.pointer_mut(path).unwrap() = v;
            assert_eq!(our_rules(&r, &[]), None, "{path}");
        }
    }

    fn private() -> Vec<String> {
        crate::machines::incus::PRIVATE.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn outbound_drops_tcp_and_udp_to_the_deny_list() {
        let deny = [private(), vec!["203.0.113.0/24".into()]].concat();
        let rules = outbound(&deny, Some(("198.51.100.9".parse().unwrap(), 8443))).unwrap();
        let mut sorted = deny.clone();
        sorted.sort();
        assert_eq!(
            rules,
            ["TCP", "UDP"].map(|p| Outbound {
                label: format!("no-private-{}", p.to_ascii_lowercase()),
                action: "DROP".into(),
                protocol: p.into(),
                ports: None,
                destinations: sorted.clone(),
            }),
            "a public control plane needs no way through"
        );
        assert_eq!(outbound(&[], None).unwrap(), [], "nothing to deny, nothing sent");
        let many: Vec<String> = (0..=MAX_ADDRESSES).map(|i| format!("198.51.{}.{}/32", i / 256, i % 256)).collect();
        let e = outbound(&many, None).unwrap_err();
        assert!(e.contains("255") && e.contains("MACHINE_FIREWALL_EGRESS=off"), "{e}");
    }

    #[test]
    fn a_control_plane_on_a_denied_address_keeps_only_its_port() {
        for (ip, cidr) in [("10.1.2.3", "10.1.2.3/32"), ("fd00::7", "fd00::7/128")] {
            let rules = outbound(&private(), Some((ip.parse().unwrap(), 8443))).unwrap();
            assert_eq!(rules.len(), 3, "{rules:?}");
            assert_eq!(
                rules[0],
                Outbound {
                    label: CONTROL_RULE.into(),
                    action: "ACCEPT".into(),
                    protocol: "TCP".into(),
                    ports: Some("8443".into()),
                    destinations: vec![cidr.into()],
                },
                "first, so Linode lets it through before the drops"
            );
            assert!(rules[1..].iter().all(|r| r.action == "DROP" && r.ports.is_none()));
        }
        let v6_in_v4 = outbound(&["10.0.0.0/8".into()], Some(("fd00::7".parse().unwrap(), 8443))).unwrap();
        assert_eq!(v6_in_v4.len(), 2, "an address of the other family is never inside");
    }

    #[test]
    fn outbound_reads_back_in_linodes_spelling_and_in_order() {
        let ours = outbound(&private(), Some(("10.1.2.3".parse().unwrap(), 8443))).unwrap();
        let body = rules_body(&[], &ours);
        assert_eq!(body["outbound_policy"], "ACCEPT");
        assert_eq!(
            body["outbound"][0],
            json!({ "label": CONTROL_RULE, "action": "ACCEPT", "protocol": "TCP", "ports": "8443", "addresses": { "ipv4": ["10.1.2.3/32"] } })
        );
        assert_eq!(
            body["outbound"][1]["addresses"],
            json!({ "ipv4": ["10.0.0.0/8", "100.64.0.0/10", "169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16"], "ipv6": ["fc00::/7", "fe80::/10"] })
        );
        assert!(body["outbound"][1].get("ports").is_none(), "every port");
        assert_eq!(our_rules(&body, &ours), Some(vec![]), "what we send reads back as ours");

        let mut linode = body.clone();
        linode["outbound"][1]["ports"] = json!("1-65535");
        linode["outbound"][2]["ports"] = Value::Null;
        linode["outbound"][1]["addresses"]["ipv6"] = json!(["FE80::/10", "fc00::/7"]);
        assert_eq!(our_rules(&linode, &ours), Some(vec![]), "Linode's spelling of every port and an address");

        let mut swapped = body.clone();
        swapped["outbound"].as_array_mut().unwrap().swap(0, 1);
        assert_eq!(our_rules(&swapped, &ours), None, "a drop before the control plane's way through cuts it off");
        let mut fewer = body.clone();
        fewer["outbound"].as_array_mut().unwrap().pop();
        assert_eq!(our_rules(&fewer, &ours), None, "UDP open again");
        let mut narrower = body.clone();
        narrower["outbound"][1]["addresses"]["ipv4"].as_array_mut().unwrap().remove(2);
        assert_eq!(our_rules(&narrower, &ours), None, "metadata's range let through");
        let mut icmp = body.clone();
        icmp["outbound"][2]["protocol"] = json!("ICMP");
        assert_eq!(our_rules(&icmp, &ours), None);
        assert_eq!(our_rules(&rules_body(&[], &[]), &ours), None, "a firewall from before this is set again");
        assert_eq!(our_rules(&body, &[]), None, "and set back when it's turned off");
    }

    #[tokio::test]
    async fn the_firewall_is_made_and_set_with_its_outbound_rules() {
        let (api, seen) = fake_api().await;
        let ours = outbound(&private(), None).unwrap();
        let api = api.with_outbound(ours.clone());
        let rule = FirewallRule { label: "agent-from-control-plane".into(), ports: "7443".into(), sources: vec!["192.0.2.1/32".into()] };
        let made = api.create_firewall("superbot-fw", &["superbot".into()], std::slice::from_ref(&rule)).await.unwrap();
        assert_eq!(made.rules, Some(vec![rule.clone()]), "made with them, read back as ours");
        let found = api.find_firewall("superbot-fw").await.unwrap().unwrap();
        assert_eq!(found.rules, None, "one without them is not ours, so the reconciler sets it again");
        api.set_firewall_rules(&found.id, std::slice::from_ref(&rule)).await.unwrap();
        assert_eq!(api.firewall_egress(), Some(outbound_json(&ours)));
        assert_eq!(api.settings()["firewallEgress"], "on");
        assert_eq!(Linode::new(TOKEN, "http://127.0.0.1:1").settings()["firewallEgress"], "off");

        let seen = seen.lock().unwrap();
        for i in [0, 2] {
            let rules = if i == 0 { &seen[i].3["rules"] } else { &seen[i].3 };
            assert_eq!(rules["outbound"].as_array().unwrap().len(), 2, "{}: {rules}", seen[i].1);
            assert_eq!(rules["outbound"][0]["action"], "DROP");
            assert_eq!(rules["outbound"][1]["protocol"], "UDP");
        }
        assert_eq!(seen[2].1, "/networking/firewalls/77/rules");
    }

    #[test]
    fn the_team_subnet_is_let_through_after_botds_port_and_before_the_drops() {
        let public = with_team_subnet(outbound(&private(), None).unwrap(), "10.248.0.0/22");
        let labels: Vec<&str> = public.iter().map(|r| r.label.as_str()).collect();
        assert_eq!(labels, ["team-network-tcp", "team-network-udp", "no-private-tcp", "no-private-udp"]);
        assert!(public[..2].iter().all(|r| r.action == "ACCEPT" && r.ports.is_none() && r.destinations == ["10.248.0.0/22"]));
        let private_botd = with_team_subnet(outbound(&private(), Some(("10.1.2.3".parse().unwrap(), 8443))).unwrap(), "10.248.0.0/22");
        let labels: Vec<&str> = private_botd.iter().map(|r| r.label.as_str()).collect();
        assert_eq!(labels, [CONTROL_RULE, "team-network-tcp", "team-network-udp", "no-private-tcp", "no-private-udp"]);
        assert_eq!(with_team_subnet(Vec::new(), "10.248.0.0/22"), [], "outbound open: nothing to let through");
        let body = rules_body(&[], &private_botd);
        assert_eq!(our_rules(&body, &private_botd), Some(vec![]), "reads back as ours");
        assert_eq!(our_rules(&body, &outbound(&private(), Some(("10.1.2.3".parse().unwrap(), 8443))).unwrap()), None, "and a firewall without it is set again");
    }

    #[tokio::test]
    async fn a_machine_joins_its_teams_subnet_from_its_first_boot() {
        let (api, seen) = fake_api().await;
        api.create(&CreateSpec { subnet_id: Some("50".into()), firewall_id: Some("77".into()), ..spec("superbot-m1") }).await.unwrap();
        api.create(&spec("superbot-m2")).await.unwrap();
        assert!(api.create(&CreateSpec { subnet_id: Some("../5".into()), ..spec("superbot-m3") }).await.is_err(), "ids are checked");
        let seen = seen.lock().unwrap();
        assert_eq!(seen.len(), 2);
        let b = &seen[0].3;
        assert_eq!(b["interfaces"], json!([{ "purpose": "public" }, { "purpose": "vpc", "subnet_id": 50 }]), "public first: the primary");
        assert_eq!(b["interface_generation"], "legacy_config", "so the Linode's firewall covers the VPC interface");
        assert_eq!(b["firewall_id"], 77);
        assert!(seen[1].3.get("interfaces").is_none(), "no team: Linode's public default");
        assert_eq!(seen[1].3["interface_generation"], "legacy_config", "never the account's default kind, which the firewall on the Linode may not cover");
    }

    #[tokio::test]
    async fn a_teams_vpc_is_found_or_made_with_its_subnet() {
        let (api, seen) = fake_api().await;
        let found = api.ensure_team_network("superbot-team-a-gb-lon", "gb-lon", "10.248.0.0/22").await.unwrap();
        assert_eq!(
            found,
            TeamNetwork { id: "5".into(), label: "superbot-team-a-gb-lon".into(), region: "gb-lon".into(), subnet_id: "50".into(), subnet: "10.248.0.0/22".into(), created: false }
        );
        let made = api.ensure_team_network("superbot-team-new-gb-lon", "gb-lon", "10.248.0.0/22").await.unwrap();
        assert_eq!((made.id.as_str(), made.subnet_id.as_str(), made.created), ("9", "90", true));
        let bare = api.ensure_team_network("superbot-team-bare-gb-lon", "gb-lon", "10.248.0.0/22").await.unwrap();
        assert_eq!((bare.id.as_str(), bare.subnet_id.as_str(), bare.created), ("6", "61", false), "its subnet added");
        let far = api.ensure_team_network("superbot-team-far-gb-lon", "gb-lon", "10.248.0.0/22").await.unwrap_err();
        assert!(far.to_string().contains("is in us-east, not gb-lon"), "{far}");
        let odd = api.ensure_team_network("superbot-team-odd-gb-lon", "gb-lon", "10.248.0.0/22").await.unwrap_err();
        assert!(odd.to_string().contains("is 10.9.0.0/24, not MACHINE_TEAM_NETWORK_SUBNET's 10.248.0.0/22"), "{odd}");
        assert_eq!(api.ensure_team_network("taken-vpc", "gb-lon", "10.248.0.0/22").await, Err(ProviderError::LabelTaken), "lost a race to a VPC we can't see");

        let seen = seen.lock().unwrap();
        let calls: Vec<(&str, &str)> = seen.iter().map(|(m, p, _, _)| (m.as_str(), p.as_str())).collect();
        assert_eq!(
            calls,
            [
                ("GET", "/vpcs?page=1&page_size=500"),
                ("GET", "/vpcs?page=1&page_size=500"),
                ("POST", "/vpcs"),
                ("GET", "/vpcs?page=1&page_size=500"),
                ("POST", "/vpcs/6/subnets"),
                ("GET", "/vpcs/6"),
                ("GET", "/vpcs?page=1&page_size=500"),
                ("GET", "/vpcs?page=1&page_size=500"),
                ("GET", "/vpcs?page=1&page_size=500"),
                ("POST", "/vpcs"),
                ("GET", "/vpcs?page=1&page_size=500"),
            ]
        );
        assert_eq!(seen[0].2.as_deref(), Some(r#"{"label":"superbot-team-a-gb-lon"}"#), "found by its exact label");
        assert_eq!(
            seen[2].3,
            json!({ "label": "superbot-team-new-gb-lon", "region": "gb-lon", "description": "SuperBot: one team's machines (ADR 0189)",
                "subnets": [{ "label": "machines", "ipv4": "10.248.0.0/22" }] })
        );
        assert_eq!(seen[4].3, json!({ "label": "machines", "ipv4": "10.248.0.0/22" }));
    }

    #[tokio::test]
    async fn team_networks_their_members_and_leaving() {
        let (api, seen) = fake_api().await;
        let nets = api.team_networks("superbot-team-").await.unwrap();
        let labels: Vec<&str> = nets.iter().map(|n| n.label.as_str()).collect();
        assert_eq!(
            labels,
            ["superbot-team-a-gb-lon", "superbot-team-bare-gb-lon", "superbot-team-far-gb-lon", "superbot-team-odd-gb-lon"],
            "ours only, and one whose subnet is gone too: its machines may still have to leave"
        );
        assert_eq!((nets[0].subnet.as_str(), nets[1].subnet.as_str(), nets[1].subnet_id.as_str()), ("10.248.0.0/22", "", ""));
        let members = api.team_network_members("5").await.unwrap();
        assert_eq!(
            members,
            [
                NetworkMember { machine: "7".into(), config: "70".into(), interface: "701".into(), active: true, needs_power_off: false },
                NetworkMember { machine: "12".into(), config: String::new(), interface: "1201".into(), active: false, needs_power_off: true },
                NetworkMember { machine: "30".into(), config: "300".into(), interface: "3001".into(), active: true, needs_power_off: false },
                NetworkMember { machine: "31".into(), config: "310".into(), interface: "3101".into(), active: false, needs_power_off: false },
            ],
            "every subnet's; a Linode interface has no profile and goes only while its Linode is off; one added since its boot is inactive"
        );
        api.leave_team_network(&members[0]).await.unwrap();
        api.leave_team_network(&NetworkMember { machine: "7".into(), ..members[1].clone() }).await.unwrap();
        let gone = NetworkMember { machine: "9".into(), ..members[0].clone() };
        api.leave_team_network(&gone).await.unwrap();
        let active = NetworkMember { machine: "8".into(), ..members[0].clone() };
        assert!(matches!(api.leave_team_network(&active).await, Err(ProviderError::Api { status: 400, .. })));
        assert!(api.leave_team_network(&NetworkMember { config: "../1".into(), ..members[0].clone() }).await.is_err());
        assert!(api.team_network_members("../5").await.is_err());
        let seen = seen.lock().unwrap();
        let paths: Vec<&str> = seen.iter().map(|s| s.1.as_str()).collect();
        assert_eq!(
            paths,
            [
                "/vpcs?page=1&page_size=500",
                "/vpcs/5/subnets",
                "/linode/instances/7/configs/70/interfaces/701",
                "/linode/instances/7/interfaces/1201",
                "/linode/instances/9/configs/70/interfaces/701",
                "/linode/instances/8/configs/70/interfaces/701",
            ]
        );
        assert!(seen[0].2.is_none(), "every VPC, filtered here");
    }

    #[tokio::test]
    async fn an_existing_linode_joins_its_teams_vpc_at_its_next_boot() {
        let (api, seen) = fake_api().await;
        let n = TeamNetwork { id: "5".into(), label: "superbot-team-a-gb-lon".into(), region: "gb-lon".into(), subnet_id: "50".into(), subnet: "10.248.0.0/22".into(), created: false };
        // No interfaces listed: its public one is put first, then the VPC's.
        api.join_team_network("21", &n).await.unwrap();
        // Its public one listed already: only the VPC's.
        api.join_team_network("22", &n).await.unwrap();
        // On it already, or joining at its next boot: nothing to do.
        api.join_team_network("23", &n).await.unwrap();
        let refused = |r: Result<(), ProviderError>, why: &str| match r {
            Err(ProviderError::Api { status: 409, message }) => assert!(message.contains(why), "{message}"),
            other => panic!("{why}: {other:?}"),
        };
        refused(api.join_team_network("24", &n).await, "2 configuration profiles");
        refused(api.join_team_network("25", &n).await, "another VPC");
        // Linode interfaces have a path of their own (`linode/interfaces.rs`); this one
        // is running, so nothing is sent.
        refused(api.join_team_network("26", &n).await, "only while it is powered off");
        assert!(api.join_team_network("../21", &n).await.is_err());
        assert!(api.join_team_network("21", &TeamNetwork { subnet_id: "5/0".into(), ..n.clone() }).await.is_err());
        let seen = seen.lock().unwrap();
        let posts: Vec<(&str, &Value)> = seen.iter().filter(|s| s.0 == "POST").map(|s| (s.1.as_str(), &s.3)).collect();
        assert_eq!(
            posts,
            [
                ("/linode/instances/21/configs/210/interfaces", &json!({ "purpose": "public" })),
                ("/linode/instances/21/configs/210/interfaces", &json!({ "purpose": "vpc", "subnet_id": 50 })),
                ("/linode/instances/22/configs/220/interfaces", &json!({ "purpose": "vpc", "subnet_id": 50 })),
            ],
            "public first, the primary; nothing sent for one refused or on it already"
        );
        assert!(!seen.iter().any(|s| s.1.contains("..")), "a bad id never reaches a path");
    }

    #[test]
    fn a_create_spec_never_shows_its_user_data() {
        let s = CreateSpec {
            user_data: Some("enroll-token: sbe_secret".into()),
            ..spec("superbot-m1")
        };
        let d = format!("{s:?}");
        assert!(!d.contains("sbe_secret") && d.contains("[redacted]"), "{d}");
    }

    #[tokio::test]
    async fn get_list_and_actions() {
        let (api, seen) = fake_api().await;
        let m = api.get("7").await.unwrap();
        assert_eq!(
            (
                m.id.as_str(),
                m.running(),
                m.ipv4.as_deref(),
                m.backups,
                m.region.as_str()
            ),
            ("7", true, Some("192.0.2.10"), false, "gb-lon")
        );

        let all = api.list("superbot").await.unwrap();
        assert_eq!(
            all.iter().map(|m| m.label.as_str()).collect::<Vec<_>>(),
            ["superbot-m1", "superbot-m2", "superbot-m3"],
            "every page"
        );

        api.resize("7", "g6-standard-2").await.unwrap();
        api.shutdown("7").await.unwrap();
        api.boot("7").await.unwrap();
        api.enable_backups("7").await.unwrap();
        api.delete("7").await.unwrap();
        api.delete("9").await.unwrap();

        let seen = seen.lock().unwrap();
        let calls: Vec<(&str, &str)> = seen
            .iter()
            .map(|(m, p, _, _)| (m.as_str(), p.as_str()))
            .collect();
        assert_eq!(
            calls,
            [
                ("GET", "/linode/instances/7"),
                ("GET", "/linode/instances?page=1&page_size=500"),
                ("GET", "/linode/instances?page=2&page_size=500"),
                ("POST", "/linode/instances/7/resize"),
                ("POST", "/linode/instances/7/shutdown"),
                ("POST", "/linode/instances/7/boot"),
                ("POST", "/linode/instances/7/backups/enable"),
                ("DELETE", "/linode/instances/7"),
                ("DELETE", "/linode/instances/9"),
            ]
        );
        assert_eq!(seen[1].2.as_deref(), Some(r#"{"tags":"superbot"}"#));
        assert_eq!(
            seen[3].3,
            json!({ "type": "g6-standard-2", "allow_auto_disk_resize": true, "migration_type": "cold" })
        );
    }

    #[tokio::test]
    async fn the_last_successful_backup_is_read_from_the_linode() {
        let (api, seen) = fake_api().await;
        assert!(api.reports_backups());
        let m = api.get("6").await.unwrap();
        let at = chrono::DateTime::parse_from_rfc3339("2026-11-21T03:14:07Z").unwrap().timestamp_millis();
        assert_eq!((m.backups, m.last_backup_at), (true, Some(at)), "UTC, as Linode means it");
        let none = api.get("7").await.unwrap();
        assert_eq!((none.backups, none.last_backup_at), (false, None));
        assert!(api.list("superbot").await.unwrap().iter().all(|m| m.last_backup_at.is_none()));
        let paths: Vec<String> = seen.lock().unwrap().iter().map(|s| s.1.clone()).collect();
        assert_eq!(paths.len(), 4, "read with the machine, no call of its own: {paths:?}");
    }

    #[test]
    fn linode_times_are_utc() {
        assert_eq!(time("1970-01-01T00:00:01"), Some(1000));
        assert_eq!(time("1970-01-01T00:00:01.5"), Some(1500));
        assert_eq!(time("1970-01-01T01:00:01+01:00"), Some(1000));
        assert_eq!(time("yesterday"), None);
        assert_eq!(time(""), None);
    }

    #[tokio::test]
    async fn a_plans_disk_is_read_from_its_type() {
        let (api, seen) = fake_api().await;
        assert_eq!(api.plan_disk("g6-standard-1").await.unwrap(), Some(50 << 30));
        assert!(matches!(api.plan_disk("g6-nope").await, Err(ProviderError::NotFound)));
        assert_eq!(api.plan_disk("../instances").await.unwrap(), None, "not a plan id: never sent");
        let paths: Vec<String> = seen.lock().unwrap().iter().map(|s| s.1.clone()).collect();
        assert_eq!(paths, ["/linode/types/g6-standard-1", "/linode/types/g6-nope"]);
    }

    #[tokio::test]
    async fn rebuild_sends_user_data_and_a_fresh_root_password() {
        let (api, seen) = fake_api().await;
        let spec = RebuildSpec {
            image: "linode/ubuntu24.04".into(),
            authorized_keys: vec!["ssh-ed25519 AAAA operator".into()],
            user_data: "#cloud-config\nsecret-token".into(),
        };
        assert!(!format!("{spec:?}").contains("secret-token"), "the token never reaches a log");
        api.rebuild("7", &spec).await.unwrap();
        api.rebuild("7", &spec).await.unwrap();
        assert_eq!(api.rebuild("8", &spec).await, Err(ProviderError::RateLimited));
        assert!(matches!(api.rebuild("9", &spec).await, Err(ProviderError::Api { status: 400, .. })));
        assert!(api.rebuild("../7", &spec).await.is_err(), "ids are checked before they reach a path");

        let seen = seen.lock().unwrap();
        assert_eq!(seen[0].1, "/linode/instances/7/rebuild");
        let b = &seen[0].3;
        assert_eq!(b["image"], "linode/ubuntu24.04");
        assert_eq!(b["booted"], true);
        assert_eq!(b["authorized_keys"], json!(["ssh-ed25519 AAAA operator"]));
        let ud = base64::engine::general_purpose::STANDARD.decode(b["metadata"]["user_data"].as_str().unwrap()).unwrap();
        assert_eq!(ud, b"#cloud-config\nsecret-token");
        let pass = b["root_pass"].as_str().unwrap();
        assert!(pass.len() >= 32);
        assert_ne!(seen[1].3["root_pass"].as_str().unwrap(), pass, "a new root password each time");
        assert_eq!(seen.len(), 4);
    }
}
