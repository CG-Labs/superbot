//! `botd offline check` (ADR 0257): which of botd's settings would reach outside an
//! air-gapped network, before it goes live there. It reads botd's settings as `botd support
//! check` does (its environment, or the installer's `.env`), and opens no connection and
//! resolves no name. Every address a setting names, or botd's default where none is set, is
//! judged from the address alone: inside (loopback, private, a name only internal resolvers
//! answer, or under `--internal`), on the internet (a service that is only there: Stripe,
//! npm's registry, linuxcontainers.org), or to check (a cloud service, which a private
//! endpoint can bring inside, or a name botd can't place). It exits 1 while anything is on
//! the internet, so the installer and scripts can say so.

use crate::support_check::Settings;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::net::IpAddr;
use std::path::Path;

/// Bumped when the JSON's shape changes.
pub const FORMAT: u32 = 1;
pub const DOC: &str = "docs/ops/air-gapped.md#checking-settings-before-going-offline";
const USAGE: &str = "Usage: botd offline check [--internal <suffix or range>,...] [--json] [--home <dir> | --env-file <file>]

Which of botd's settings would reach outside an air-gapped network. Opens no connection.
  --internal <list>  DNS suffixes (corp.example) or address ranges (203.0.113.0/24) inside
                     your network, besides private addresses and internal names; may repeat
  --home <dir>       the installer's layout: settings from <dir>/superbot/.env
                     (sudo -u superbot botd offline check --home /home/superbot)
  --env-file <file>  settings from this file, over botd's environment
  --json             the findings as JSON
Exits 1 while a setting reaches the internet.
Docs: docs/ops/air-gapped.md#checking-settings-before-going-offline";

/// Services that are only on the internet, by the DNS suffix they answer under.
const INTERNET: &[(&str, &str)] = &[
    ("stripe.com", "Stripe"),
    ("exp.host", "Expo's push service"),
    ("expo.dev", "Expo"),
    ("challenges.cloudflare.com", "Cloudflare Turnstile"),
    ("r2.cloudflarestorage.com", "Cloudflare R2"),
    ("linode.com", "Linode"),
    ("linodeobjects.com", "Linode Object Storage"),
    ("backblazeb2.com", "Backblaze B2"),
    ("linuxcontainers.org", "linuxcontainers.org's image server"),
    ("npmjs.org", "npm's registry"),
    ("nodejs.org", "nodejs.org"),
    ("github.com", "GitHub"),
    ("githubusercontent.com", "GitHub"),
    ("ghcr.io", "GitHub's container registry"),
    ("admin.googleapis.com", "Google Workspace"),
    ("google.com", "Google"),
    ("microsoftonline.com", "Microsoft Entra ID"),
    ("apple.com", "Apple"),
    ("okta.com", "Okta"),
    ("oktapreview.com", "Okta"),
    ("auth0.com", "Auth0"),
    ("onelogin.com", "OneLogin"),
    ("anthropic.com", "Anthropic"),
    ("claude.ai", "Anthropic"),
    ("openai.com", "OpenAI"),
    ("chatgpt.com", "OpenAI"),
    ("openrouter.ai", "OpenRouter"),
    ("sentry.io", "Sentry"),
    ("datadoghq.com", "Datadog"),
    ("datadoghq.eu", "Datadog"),
    ("ddog-gov.com", "Datadog"),
    ("honeycomb.io", "Honeycomb"),
    ("grafana.net", "Grafana Cloud"),
    ("splunkcloud.com", "Splunk Cloud"),
    ("newrelic.com", "New Relic"),
    ("slack.com", "Slack"),
    ("discord.com", "Discord"),
    ("office.com", "Microsoft 365"),
    ("gmail.com", "Gmail"),
    ("sendgrid.net", "SendGrid"),
    ("mailgun.org", "Mailgun"),
    ("digicert.com", "DigiCert"),
    ("sectigo.com", "Sectigo"),
    ("globalsign.com", "GlobalSign"),
    ("freetsa.org", "FreeTSA"),
    ("sigstore.dev", "Sigstore"),
];

/// Cloud services a private endpoint (AWS PrivateLink, Azure Private Link, Private Service
/// Connect) can serve inside a network under the same names.
const CLOUD: &[(&str, &str)] = &[
    ("amazonaws.com", "AWS"),
    ("amazonaws.com.cn", "AWS"),
    ("googleapis.com", "Google Cloud"),
    ("azure.net", "Azure"),
    ("azure.com", "Azure"),
    ("azure.cn", "Azure"),
    ("windows.net", "Azure"),
];

/// Suffixes no public resolver answers: reserved for private use, or by convention.
const INTERNAL_SUFFIXES: &[&str] = &["internal", "local", "localdomain", "lan", "home.arpa", "intranet", "corp", "private"];

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Status {
    Ok,
    Check,
    Internet,
}

impl Status {
    pub fn word(self) -> &'static str {
        match self {
            Status::Ok => "ok",
            Status::Check => "check",
            Status::Internet => "internet",
        }
    }
}

/// The guide's "What needs the internet" rows, and the other settings that name an address.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Area {
    License,
    SignIn,
    Models,
    Machines,
    MachineHarnesses,
    Billing,
    Push,
    Signups,
    Email,
    Webhooks,
    Backups,
    Audit,
    Observability,
    Secrets,
    Directory,
}

impl Area {
    pub const ALL: [Area; 15] = [
        Area::License,
        Area::SignIn,
        Area::Models,
        Area::Machines,
        Area::MachineHarnesses,
        Area::Billing,
        Area::Push,
        Area::Signups,
        Area::Email,
        Area::Webhooks,
        Area::Backups,
        Area::Audit,
        Area::Observability,
        Area::Secrets,
        Area::Directory,
    ];

    pub fn id(self) -> &'static str {
        match self {
            Area::License => "license",
            Area::SignIn => "sign_in",
            Area::Models => "models",
            Area::Machines => "machines",
            Area::MachineHarnesses => "machine_harnesses",
            Area::Billing => "billing",
            Area::Push => "push",
            Area::Signups => "signups",
            Area::Email => "email",
            Area::Webhooks => "webhooks",
            Area::Backups => "backups",
            Area::Audit => "audit",
            Area::Observability => "observability",
            Area::Secrets => "secrets",
            Area::Directory => "directory",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Area::License => "License",
            Area::SignIn => "Sign-in",
            Area::Models => "Model providers",
            Area::Machines => "Machines",
            Area::MachineHarnesses => "Harnesses on machines",
            Area::Billing => "Billing",
            Area::Push => "Push notifications",
            Area::Signups => "Sign-up form",
            Area::Email => "Email",
            Area::Webhooks => "Approval webhooks",
            Area::Backups => "Backups",
            Area::Audit => "Audit export",
            Area::Observability => "Errors and traces",
            Area::Secrets => "Secrets manager",
            Area::Directory => "Directory sync",
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Finding {
    pub area: Area,
    pub status: Status,
    /// The setting that names the address, or turns the feature on.
    pub setting: Option<String>,
    pub host: Option<String>,
    pub detail: String,
}

/// Where an address is, judged from the address alone.
#[derive(Debug, PartialEq)]
pub enum Place {
    Inside(String),
    Internet(&'static str),
    Cloud(&'static str),
    Unknown,
}

/// What `--internal` adds to the network: DNS suffixes and address ranges.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Internal {
    suffixes: Vec<String>,
    ranges: Vec<(IpAddr, u8)>,
}

impl Internal {
    /// Each value a comma-separated list of DNS suffixes, addresses or CIDR ranges.
    pub fn parse(values: &[&str]) -> Result<Internal, String> {
        let mut out = Internal::default();
        for raw in values.iter().flat_map(|v| v.split(',')).map(str::trim).filter(|v| !v.is_empty()) {
            let bad = || format!("--internal: \"{raw}\" is neither a DNS suffix like corp.example nor an address range like 10.20.0.0/16");
            let (addr, bits) = raw.split_once('/').map_or((raw, None), |(a, b)| (a, Some(b)));
            if let Ok(ip) = addr.trim_start_matches('[').trim_end_matches(']').parse::<IpAddr>() {
                let ip = ip.to_canonical();
                let max = if ip.is_ipv4() { 32 } else { 128 };
                let bits = match bits {
                    None => max,
                    Some(b) => b.parse::<u8>().ok().filter(|b| *b <= max).ok_or_else(bad)?,
                };
                out.ranges.push((ip, bits));
                continue;
            }
            let name = raw.trim_matches('.').to_ascii_lowercase();
            let label_ok = |l: &str| (1..=63).contains(&l.len()) && !l.starts_with('-') && !l.ends_with('-') && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-');
            if bits.is_some() || name.len() > 253 || !name.split('.').all(label_ok) {
                return Err(bad());
            }
            out.suffixes.push(name);
        }
        Ok(out)
    }

    /// As given, for the report.
    pub fn listed(&self) -> Vec<String> {
        let ranges = self.ranges.iter().map(|(ip, bits)| if *bits == if ip.is_ipv4() { 32 } else { 128 } { ip.to_string() } else { format!("{ip}/{bits}") });
        self.suffixes.iter().cloned().chain(ranges).collect()
    }

    fn holds(&self, ip: IpAddr) -> bool {
        self.ranges.iter().any(|(net, bits)| in_range(*net, *bits, ip))
    }
}

fn in_range(net: IpAddr, bits: u8, ip: IpAddr) -> bool {
    match (net, ip) {
        (IpAddr::V4(n), IpAddr::V4(a)) => {
            let mask = u32::MAX.checked_shl(32 - u32::from(bits)).unwrap_or(0);
            u32::from(n) & mask == u32::from(a) & mask
        }
        (IpAddr::V6(n), IpAddr::V6(a)) => {
            let mask = u128::MAX.checked_shl(128 - u32::from(bits)).unwrap_or(0);
            u128::from(n) & mask == u128::from(a) & mask
        }
        _ => false,
    }
}

/// `host` is `suffix`, or a name under it.
fn under(host: &str, suffix: &str) -> bool {
    host.strip_suffix(suffix).is_some_and(|rest| rest.is_empty() || rest.ends_with('.'))
}

/// Where `host` (a name or an address) is, from the host alone.
pub fn place(host: &str, internal: &Internal) -> Place {
    let h = host.trim().trim_start_matches('[').trim_end_matches(']').trim_end_matches('.').to_ascii_lowercase();
    if let Ok(ip) = h.parse::<IpAddr>() {
        let ip = ip.to_canonical();
        if internal.holds(ip) {
            return Place::Inside("in a range given with --internal".into());
        }
        let why = match ip {
            IpAddr::V4(v) if v.is_loopback() => "loopback, this machine",
            IpAddr::V4(v) if v.is_private() => "a private address",
            IpAddr::V4(v) if v.is_link_local() => "a link-local address",
            IpAddr::V4(v) if in_range(IpAddr::V4([100, 64, 0, 0].into()), 10, IpAddr::V4(v)) => "a shared address (100.64.0.0/10), used inside networks",
            IpAddr::V6(v) if v.is_loopback() => "loopback, this machine",
            IpAddr::V6(v) if in_range("fc00::".parse().unwrap(), 7, IpAddr::V6(v)) => "a unique local address",
            IpAddr::V6(v) if in_range("fe80::".parse().unwrap(), 10, IpAddr::V6(v)) => "a link-local address",
            _ => return Place::Unknown,
        };
        return Place::Inside(why.into());
    }
    if let Some(s) = internal.suffixes.iter().find(|s| under(&h, s)) {
        return Place::Inside(format!("under {s}, given with --internal"));
    }
    if under(&h, "localhost") {
        return Place::Inside("loopback, this machine".into());
    }
    if !h.contains('.') {
        return Place::Inside("a single-label name, which only your network's resolvers answer".into());
    }
    if let Some(s) = INTERNAL_SUFFIXES.iter().find(|s| under(&h, s)) {
        return Place::Inside(format!("under .{s}, which only internal resolvers answer"));
    }
    if let Some((_, service)) = INTERNET.iter().find(|(d, _)| under(&h, d)) {
        return Place::Internet(service);
    }
    if let Some((_, cloud)) = CLOUD.iter().find(|(d, _)| under(&h, d)) {
        return Place::Cloud(cloud);
    }
    Place::Unknown
}

/// The host a setting's value names: a URL's, or a bare `host[:port]`. Never its user or path.
/// `text` with each URL's user and password left out, as a parser's error may quote them.
fn scrub(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(i) = rest.find("://") {
        out.push_str(&rest[..i + 3]);
        rest = &rest[i + 3..];
        let end = rest.find(|c: char| matches!(c, '/' | '?' | '#' | '"' | '\'' | ')' | ',' | '>' | '\\') || c.is_whitespace()).unwrap_or(rest.len());
        if let Some(at) = rest[..end].rfind('@') {
            rest = &rest[at + 1..];
        }
    }
    out.push_str(rest);
    out
}

pub fn host_of(value: &str) -> Option<String> {
    let v = value.trim();
    if v.is_empty() {
        return None;
    }
    if let Ok(ip) = v.trim_start_matches('[').trim_end_matches(']').parse::<IpAddr>() {
        return Some(ip.to_string());
    }
    let url = if v.contains("://") { url::Url::parse(v).ok()? } else { url::Url::parse(&format!("https://{v}")).ok()? };
    let host = url.host_str()?.trim_start_matches('[').trim_end_matches(']').trim_end_matches('.').to_ascii_lowercase();
    (!host.is_empty()).then_some(host)
}

/// What `--internal` would take for `host`: the address, or the name's parent domain.
fn suggest(host: &str) -> String {
    let labels: Vec<&str> = host.split('.').collect();
    if host.parse::<IpAddr>().is_ok() || labels.len() < 3 { host.to_string() } else { labels[1..].join(".") }
}

const INSIDE: &str = "Use one inside your network";
const MODEL_FIX: &str = "Use a model server inside your network, or a provider's private endpoint (docs/ops/air-gapped.md#model-providers)";
const S3_FIX: &str = "Use an S3-compatible store inside your network (MinIO, Ceph)";
const HARNESS_FIX: &str = "Set MACHINE_HARNESS_BUNDLE to this release's harness bundle, or MACHINE_NODE_MIRROR and MACHINE_NPM_REGISTRY to your mirrors (docs/ops/air-gapped.md#harness-clis-on-users-machines)";
const AUDIT_FIX: &str = "Send it to a SIEM or syslog collector inside your network";
const SECRETS_FIX: &str = "Use a secrets manager inside your network, a private endpoint, or botd's own store (SECRETS_BACKEND unset)";

struct Judge<'a> {
    vars: &'a BTreeMap<String, String>,
    internal: &'a Internal,
    out: Vec<Finding>,
}

impl<'a> Judge<'a> {
    fn get(&self, k: &str) -> &'a str {
        self.vars.get(k).map_or("", |v| v.trim())
    }

    fn set(&self, k: &str) -> bool {
        !self.get(k).is_empty()
    }

    fn push(&mut self, area: Area, status: Status, setting: Option<&str>, host: Option<&str>, detail: String) {
        self.out.push(Finding { area, status, setting: setting.map(String::from), host: host.map(String::from), detail: scrub(&detail) });
    }

    /// Each address a provider says it reaches, or why its settings don't read.
    fn reaches(&mut self, area: Area, setting: &str, found: Result<Vec<(&'static str, String, &'static str)>, String>, fix: &str) {
        match found {
            Ok(list) => {
                for (k, url, what) in list {
                    self.address(area, k, &url, what, fix);
                }
            }
            Err(e) => self.push(area, Status::Check, Some(setting), None, format!("the settings don't read ({e}), so botd won't start with them. Fix them and check again")),
        }
    }

    fn var(&self) -> impl Fn(&str) -> String + 'a {
        let vars = self.vars;
        move |k: &str| vars.get(k).cloned().unwrap_or_default()
    }

    fn ok(&mut self, area: Area, detail: impl Into<String>) {
        self.push(area, Status::Ok, None, None, detail.into());
    }

    /// `what`, at the address `value` names, which `setting` names or would; `fix` is what to
    /// do when it is on the internet.
    fn address(&mut self, area: Area, setting: &str, value: &str, what: &str, fix: &str) {
        let Some(host) = host_of(value) else {
            self.push(area, Status::Check, Some(setting), None, format!("{what}: {setting} names no host botd can read"));
            return;
        };
        let (status, detail) = match place(&host, self.internal) {
            Place::Inside(why) => (Status::Ok, format!("{what} at {host}: {why}")),
            Place::Internet(service) => (Status::Internet, format!("{what} at {host}: {service}, on the internet. {fix}")),
            Place::Cloud(cloud) => (
                Status::Check,
                format!("{what} at {host}: {cloud}, inside your network only through a private endpoint. If yours is one, add --internal {host}"),
            ),
            Place::Unknown => (
                Status::Check,
                format!("{what} at {host}: botd can't tell whether this is inside your network. If it is, add --internal {}", suggest(&host)),
            ),
        };
        self.push(area, status, Some(setting), Some(&host), detail);
    }

    fn or<'b>(&'b self, k: &str, default: &'b str) -> &'b str {
        Some(self.get(k)).filter(|v| !v.is_empty()).unwrap_or(default)
    }

    fn sign_in(&mut self) {
        if !self.set("SSO_PROVIDERS") {
            return self.ok(Area::SignIn, "SSO is off: passwords and TOTP need no network");
        }
        let vars = self.vars;
        match crate::sso::Sso::from_vars(&|k| vars.get(k).cloned()) {
            Err(e) => self.push(Area::SignIn, Status::Check, Some("SSO_PROVIDERS"), None, format!("the SSO settings don't read ({e}), so botd won't start with them. Fix them and check again")),
            Ok(sso) => {
                for p in &sso.providers {
                    if matches!(&p.kind, crate::sso::Kind::SamlSp { source: crate::sso::IdpSource::Saved, .. }) {
                        let detail = format!(
                            "SSO provider {}: native SAML with the IdP's metadata saved with botctl, which this check doesn't read. Check that its sign-in and logout URLs are inside your network",
                            p.id
                        );
                        self.push(Area::SignIn, Status::Check, Some("SSO_PROVIDERS"), None, detail);
                    }
                    for (setting, url, what) in p.reaches() {
                        let what = format!("SSO provider {}'s {what}", p.id);
                        self.address(Area::SignIn, &setting, &url, &what, "Sign in with an identity provider inside your network (ADFS, Keycloak, or another OIDC or SAML IdP)");
                    }
                }
            }
        }
    }

    /// The tiers file, when it reads: its endpoints, and the managed tiers' default harnesses.
    fn models(&mut self) -> Option<crate::tiers::Tiers> {
        let mut named = false;
        let mut tiers = None;
        if self.set("TIERS_FILE") {
            let vars = self.vars;
            match crate::tiers::Tiers::from_env(|k| vars.get(k).map(|v| v.trim().to_string()).unwrap_or_default()) {
                Err(e) => self.push(Area::Models, Status::Check, Some("TIERS_FILE"), None, format!("the tiers file doesn't read ({e}), so botd won't start with it")),
                Ok(t) => {
                    for e in t.providers() {
                        named = true;
                        self.address(Area::Models, "TIERS_FILE", &e.base_url, &format!("Model endpoint {} in the tiers file", e.name), MODEL_FIX);
                    }
                    let endpoints: Vec<&str> = t.providers().iter().map(|e| e.name.as_str()).collect();
                    let mut own: Vec<&str> = t
                        .all()
                        .iter()
                        .flat_map(|tier| tier.routes.iter().flatten())
                        .flat_map(|r| r.provider.iter().map(String::as_str).chain(r.fallback.iter().map(|f| f.provider.as_str())))
                        .filter(|p| !endpoints.contains(p))
                        .collect();
                    own.sort_unstable();
                    own.dedup();
                    for p in own {
                        named = true;
                        let detail = format!("Hermes Agent's provider {p}, which the tiers file's routes name but its providers don't: Hermes calls that provider's own endpoint. Name one inside your network in the file's providers");
                        self.push(Area::Models, Status::Check, Some("TIERS_FILE"), None, detail);
                    }
                    tiers = Some(t);
                }
            }
        }
        for (k, what) in [("ANTHROPIC_BASE_URL", "Claude Code's endpoint"), ("SUPERBOT_HERMES_BASE_URL", "Hermes Agent's endpoint")] {
            if self.set(k) {
                named = true;
                let value = self.get(k);
                self.address(Area::Models, k, value, what, MODEL_FIX);
            }
        }
        if !self.set("ANTHROPIC_BASE_URL") && ["ANTHROPIC_API_KEY", "ANTHROPIC_API_KEY_FILE", "ANTHROPIC_AUTH_TOKEN"].iter().any(|k| self.set(k)) {
            named = true;
            self.address(Area::Models, "ANTHROPIC_BASE_URL", "https://api.anthropic.com", "Claude Code with an API key and no ANTHROPIC_BASE_URL", MODEL_FIX);
        }
        if !self.set("SUPERBOT_HERMES_BASE_URL") && self.set("SUPERBOT_HERMES_PROVIDER") {
            named = true;
            let detail = format!(
                "Hermes Agent's provider {} with no SUPERBOT_HERMES_BASE_URL: Hermes calls that provider's own endpoint. Set SUPERBOT_HERMES_BASE_URL to one inside your network",
                self.get("SUPERBOT_HERMES_PROVIDER")
            );
            self.push(Area::Models, Status::Check, Some("SUPERBOT_HERMES_PROVIDER"), None, detail);
        }
        if !named {
            self.push(
                Area::Models,
                Status::Check,
                None,
                None,
                "no model endpoint in botd's settings: Bots use each harness's default provider, on the internet, unless their own settings name one inside your network. Set TIERS_FILE, ANTHROPIC_BASE_URL or SUPERBOT_HERMES_BASE_URL (docs/ops/air-gapped.md#model-providers)".into(),
            );
        }
        tiers
    }

    /// Whether botd manages users' machines.
    fn machines(&mut self) -> bool {
        let linode = self.set("LINODE_TOKEN") || self.set("LINODE_TOKEN_FILE");
        let incus = self.get("MACHINE_PROVIDER").eq_ignore_ascii_case("incus");
        if linode {
            self.address(Area::Machines, "LINODE_TOKEN", crate::machines::linode::API_URL, "Linode's API, for users' machines", "Use Incus hosts inside your network (MACHINE_PROVIDER=incus), or no machines");
        }
        if incus {
            let url = self.get("INCUS_URL").to_string();
            self.address(Area::Machines, "INCUS_URL", &url, "The Incus host", INSIDE);
            let hosts = self.get("INCUS_HOSTS").to_string();
            for (name, url) in hosts.split(',').filter_map(|e| e.split_once('=')) {
                self.address(Area::Machines, "INCUS_HOSTS", url, &format!("Incus host {}", name.trim()), INSIDE);
            }
            match self.get("INCUS_IMAGE_SERVER") {
                "local" => self.ok(Area::Machines, "Incus base images: imported on each host by hand (INCUS_IMAGE_SERVER=local)"),
                v => {
                    let server = if v.is_empty() { crate::machines::incus::DEFAULT_IMAGE_SERVER.to_string() } else { v.to_string() };
                    self.address(
                        Area::Machines,
                        "INCUS_IMAGE_SERVER",
                        &server,
                        "Incus base images",
                        "Import ubuntu/24.04/cloud on each Incus host and set INCUS_IMAGE_SERVER=local, or point it at an image server inside your network (docs/ops/incus-containers.md)",
                    );
                }
            }
        }
        if !linode && !incus {
            self.ok(Area::Machines, "off: botd manages no users' machines");
        }
        linode || incus
    }

    fn machine_harnesses(&mut self, tiers: Option<&crate::tiers::Tiers>) {
        let raw = self.get("MACHINE_HARNESSES").to_string();
        let names: Vec<String> = if raw.eq_ignore_ascii_case("none") {
            Vec::new()
        } else if raw.is_empty() {
            let own;
            let tiers = match tiers {
                Some(t) => t,
                None => {
                    own = crate::tiers::Tiers::self_host();
                    &own
                }
            };
            tiers.managed_defaults().iter().map(|h| h.to_ascii_lowercase()).collect()
        } else {
            raw.split([',', ' ', '\t', '\n'])
                .map(|i| i.split(['@', '=']).next().unwrap_or("").trim().to_ascii_lowercase())
                .filter(|n| !n.is_empty())
                .collect()
        };
        if names.is_empty() {
            self.ok(Area::MachineHarnesses, "machines get no harness CLIs from botd");
        }
        let npm: Vec<&str> = names.iter().map(String::as_str).filter(|n| *n != "hermes").collect();
        if !npm.is_empty() {
            let list = npm.join(", ");
            if self.set("MACHINE_HARNESS_BUNDLE") {
                self.ok(Area::MachineHarnesses, format!("{list} from botd's harness bundle (MACHINE_HARNESS_BUNDLE)"));
            } else {
                let node = self.or("MACHINE_NODE_MIRROR", "https://nodejs.org/dist").to_string();
                let registry = self.or("MACHINE_NPM_REGISTRY", crate::machines::mirror::NPM_REGISTRY).to_string();
                self.address(Area::MachineHarnesses, "MACHINE_NODE_MIRROR", &node, &format!("Node.js for {list} on machines"), HARNESS_FIX);
                self.address(Area::MachineHarnesses, "MACHINE_NPM_REGISTRY", &registry, &format!("{list} on machines"), HARNESS_FIX);
            }
        }
        if names.iter().any(|n| n == "hermes") {
            if self.set("MACHINE_HERMES_BUNDLE") {
                self.ok(Area::MachineHarnesses, "hermes from botd's Hermes bundle (MACHINE_HERMES_BUNDLE)");
            } else {
                self.address(
                    Area::MachineHarnesses,
                    "MACHINE_HERMES_BUNDLE",
                    "https://raw.githubusercontent.com/NousResearch/hermes-agent",
                    "Hermes Agent's installer on machines",
                    "Set MACHINE_HERMES_BUNDLE to this release's Hermes bundle (docs/ops/air-gapped.md#hermes-agent-on-users-machines)",
                );
            }
        }
        if self.get("MACHINE_HARNESS_LOGINS").eq_ignore_ascii_case("on") {
            self.push(
                Area::MachineHarnesses,
                Status::Internet,
                Some("MACHINE_HARNESS_LOGINS"),
                None,
                "people sign Claude Code and Codex in on Anthropic's and OpenAI's websites, on the internet. Leave MACHINE_HARNESS_LOGINS off and give Bots keys for an endpoint inside your network".into(),
            );
        }
    }

    fn switched(&mut self) {
        match crate::billing::billing_flag(self.get("BILLING")) {
            Ok(true) => self.address(Area::Billing, "BILLING", crate::stripe::API, "Billing", "Leave BILLING off, the default"),
            Ok(false) => self.ok(Area::Billing, "off"),
            Err(e) => self.push(Area::Billing, Status::Check, Some("BILLING"), None, e),
        }
        if self.get(crate::notify::push::PROVIDER).eq_ignore_ascii_case("expo") {
            self.address(Area::Push, crate::notify::push::PROVIDER, crate::notify::push::EXPO_URL, "Push notifications", "Leave PUSH_PROVIDER unset: approvals still go by email and webhook");
        } else {
            self.ok(Area::Push, "off");
        }
        if self.set("TURNSTILE_SITE_KEY") {
            self.address(Area::Signups, "TURNSTILE_SITE_KEY", crate::signups::TURNSTILE_VERIFY_URL, "The sign-up form's bot check", "Unset TURNSTILE_SITE_KEY and TURNSTILE_SECRET");
        } else {
            self.ok(Area::Signups, "no Turnstile check on the sign-up form");
        }
        if self.set("SMTP_HOST") {
            let host = self.get("SMTP_HOST").to_string();
            self.address(Area::Email, "SMTP_HOST", &host, "Email", "Send through an SMTP relay inside your network");
        } else {
            self.ok(Area::Email, "off");
        }
        let hooks: Vec<(String, String)> =
            self.vars.iter().filter(|(k, v)| (*k == "NOTIFY_WEBHOOK_URL" || k.starts_with("NOTIFY_WEBHOOK_URL_BOT_")) && !v.trim().is_empty()).map(|(k, v)| (k.clone(), v.clone())).collect();
        for (k, v) in &hooks {
            self.address(Area::Webhooks, k, v, "Approval notices", "Send them to a chat server or receiver inside your network");
        }
        if hooks.is_empty() {
            self.ok(Area::Webhooks, "off");
        }
        let google = matches!(self.get("GOOGLE_DIRECTORY_SYNC").to_ascii_lowercase().as_str(), "on" | "true" | "1" | "yes");
        if google {
            let api = self.or("GOOGLE_DIRECTORY_API_URL", "https://admin.googleapis.com").to_string();
            self.address(Area::Directory, "GOOGLE_DIRECTORY_API_URL", &api, "Google Workspace directory sync", "Turn GOOGLE_DIRECTORY_SYNC off and provision with SCIM from an identity provider inside your network");
        } else {
            self.ok(Area::Directory, "off");
        }
    }

    /// Each region's store `<prefix>_<REGION>_BUCKET` names, at its `_ENDPOINT`.
    fn regional_stores(&mut self, prefix: &str, what: &str) -> bool {
        let regions: Vec<String> = self
            .vars
            .iter()
            .filter(|(_, v)| !v.trim().is_empty())
            .filter_map(|(k, _)| k.strip_prefix(prefix)?.strip_prefix('_')?.strip_suffix("_BUCKET").filter(|r| !r.is_empty()).map(String::from))
            .collect();
        for r in &regions {
            let k = format!("{prefix}_{r}_ENDPOINT");
            let v = self.get(&k).to_string();
            self.address(Area::Backups, &k, &v, &format!("{what} for {}", r.to_ascii_lowercase().replace('_', "-")), S3_FIX);
        }
        !regions.is_empty()
    }

    fn backups(&mut self) {
        let mut any = false;
        if !self.get("SERVER_BACKUP_OFF_HOST").eq_ignore_ascii_case("off") && self.set("SERVER_BACKUP_S3_BUCKET") {
            any = true;
            let v = self.get("SERVER_BACKUP_S3_ENDPOINT").to_string();
            self.address(Area::Backups, "SERVER_BACKUP_S3_ENDPOINT", &v, "Server backups' S3 store", S3_FIX);
        }
        if self.set("MACHINE_BACKUP_S3_BUCKET") {
            any = true;
            let v = self.get("MACHINE_BACKUP_S3_ENDPOINT").to_string();
            self.address(Area::Backups, "MACHINE_BACKUP_S3_ENDPOINT", &v, "Machine backups' S3 store", S3_FIX);
        }
        any |= self.regional_stores(crate::machines::s3::MACHINES, "Machine backups' S3 store");
        any |= self.regional_stores(crate::machines::chat_store_copies::NAME, "Chat store backups' S3 store");
        if !any {
            self.ok(Area::Backups, "no off-host store: server backups stay on this host");
        }
    }

    fn audit(&mut self) {
        let raw = self.get("AUDIT_EXPORT").to_string();
        let mut any = false;
        if !raw.eq_ignore_ascii_case("off") {
            for entry in raw.split(',').map(str::trim).filter(|e| !e.is_empty()) {
                any = true;
                let sink = match entry.split_once('=') {
                    Some((name, rest)) if !name.contains(['/', ':']) => rest.trim(),
                    _ => entry,
                };
                let lower = sink.to_ascii_lowercase();
                let var = self.var();
                if lower.starts_with("s3://") {
                    let v = self.get("AUDIT_EXPORT_S3_ENDPOINT").to_string();
                    self.address(Area::Audit, "AUDIT_EXPORT_S3_ENDPOINT", &v, "The audit archive's S3 store", S3_FIX);
                } else if let Some(rest) = lower.strip_prefix("google-secops://") {
                    let location = rest.split(['/', ':']).next().unwrap_or_default();
                    self.address(Area::Audit, "AUDIT_EXPORT", &crate::audit_secops::endpoint(location), "Audit export to Google SecOps", AUDIT_FIX);
                    let (k, method) = if self.set("AUDIT_EXPORT_GCP_AUTH") { ("AUDIT_EXPORT_GCP_AUTH", var("AUDIT_EXPORT_GCP_AUTH")) } else { ("GCP_SECRET_MANAGER_AUTH", var("GCP_SECRET_MANAGER_AUTH")) };
                    self.reaches(Area::Audit, k, crate::secrets::gcp::sign_in_reaches(&var, k, &method), AUDIT_FIX);
                } else if let Some(rest) = lower.strip_prefix("datadog://") {
                    let site = rest.split(['/', '?', '#']).next().unwrap_or_default();
                    self.address(Area::Audit, "AUDIT_EXPORT", &crate::audit_datadog::intake(site), "Audit export to Datadog", AUDIT_FIX);
                } else if lower.starts_with("azure-monitor://") {
                    self.address(Area::Audit, "AUDIT_EXPORT", sink, "Audit export to Azure Monitor", AUDIT_FIX);
                    let (k, method) = if self.set("AUDIT_EXPORT_AZURE_AUTH") { ("AUDIT_EXPORT_AZURE_AUTH", var("AUDIT_EXPORT_AZURE_AUTH")) } else { ("AZURE_KEYVAULT_AUTH", var("AZURE_KEYVAULT_AUTH")) };
                    self.reaches(Area::Audit, k, crate::secrets::azure::sign_in_reaches(&var, k, &method, false), AUDIT_FIX);
                } else {
                    self.address(Area::Audit, "AUDIT_EXPORT", sink, "Audit export", AUDIT_FIX);
                }
            }
        }
        if self.set("AUDIT_TIMESTAMP_URL") {
            any = true;
            let v = self.get("AUDIT_TIMESTAMP_URL").to_string();
            self.address(Area::Audit, "AUDIT_TIMESTAMP_URL", &v, "Audit checkpoints' timestamp authority", "Use a timestamp authority inside your network, or unset AUDIT_TIMESTAMP_URL");
        }
        if !any {
            self.ok(Area::Audit, "off: the audit log stays in botd's database");
        }
    }

    fn observability(&mut self) {
        let mut any = false;
        for (k, what, fix) in [
            ("ERROR_REPORT_DSN", "Error reports", "Use a Sentry-compatible tracker inside your network, or unset ERROR_REPORT_DSN"),
            ("TRACES_OTLP_ENDPOINT", "Traces", "Use an OTLP collector inside your network, or unset TRACES_OTLP_ENDPOINT"),
        ] {
            if self.set(k) {
                any = true;
                let v = self.get(k).to_string();
                self.address(Area::Observability, k, &v, what, fix);
            }
        }
        if !any {
            self.ok(Area::Observability, "off");
        }
    }

    fn secrets(&mut self) {
        let backend = self.get("SECRETS_BACKEND").to_ascii_lowercase();
        match backend.as_str() {
            "" | "local" => self.ok(Area::Secrets, "botd's own sealed store"),
            "vault" => {
                let v = self.get("VAULT_ADDR").to_string();
                self.address(Area::Secrets, "VAULT_ADDR", &v, "HashiCorp Vault", SECRETS_FIX);
            }
            "azure-keyvault" => {
                let v = self.get("AZURE_KEYVAULT_URL").to_string();
                self.address(Area::Secrets, "AZURE_KEYVAULT_URL", &v, "Azure Key Vault", SECRETS_FIX);
                let var = self.var();
                let found = crate::secrets::azure::sign_in_reaches(&var, "AZURE_KEYVAULT_AUTH", &var("AZURE_KEYVAULT_AUTH"), self.set("AZURE_RUN_CREDENTIALS"));
                self.reaches(Area::Secrets, "AZURE_KEYVAULT_AUTH", found, SECRETS_FIX);
            }
            "gcp-secret-manager" => {
                let found = crate::secrets::gcp::reaches(&self.var());
                self.reaches(Area::Secrets, "SECRETS_BACKEND", found, SECRETS_FIX);
            }
            "aws" => {
                let found = crate::secrets::aws::reaches(&self.var());
                self.reaches(Area::Secrets, "SECRETS_BACKEND", found, SECRETS_FIX);
            }
            other => self.push(Area::Secrets, Status::Check, Some("SECRETS_BACKEND"), None, format!("SECRETS_BACKEND={other} isn't one botd knows, so botd won't start with it")),
        }
    }
}

/// Every finding for botd's settings `vars`, in the order of [`Area::ALL`].
pub fn judge(vars: &BTreeMap<String, String>, internal: &Internal) -> Vec<Finding> {
    let mut j = Judge { vars, internal, out: Vec::new() };
    j.ok(Area::License, "checked against keys built into botd, with no network: botd never calls home");
    j.sign_in();
    let tiers = j.models();
    if j.machines() {
        j.machine_harnesses(tiers.as_ref());
    } else {
        j.ok(Area::MachineHarnesses, "no users' machines to install them on");
    }
    j.switched();
    j.backups();
    j.audit();
    j.observability();
    j.secrets();
    let mut out = j.out;
    out.sort_by_key(|f| Area::ALL.iter().position(|a| *a == f.area));
    out
}

pub struct Report {
    pub findings: Vec<Finding>,
    pub internal: Vec<String>,
    pub source: Value,
}

impl Report {
    pub fn count(&self, s: Status) -> usize {
        self.findings.iter().filter(|f| f.status == s).count()
    }

    /// Nothing reaches the internet.
    pub fn offline(&self) -> bool {
        self.count(Status::Internet) == 0
    }

    pub fn json(&self) -> Value {
        let findings: Vec<Value> = self
            .findings
            .iter()
            .map(|f| json!({ "area": f.area.id(), "status": f.status.word(), "setting": f.setting, "host": f.host, "detail": f.detail }))
            .collect();
        json!({
            "format": FORMAT,
            "offline": self.offline(),
            "counts": { "ok": self.count(Status::Ok), "check": self.count(Status::Check), "internet": self.count(Status::Internet) },
            "internal": self.internal,
            "settings": self.source,
            "findings": findings,
            "doc": DOC,
        })
    }

    /// The internet first, then what to check, then the rest, each in area order.
    pub fn text(&self) -> String {
        let mut out = String::from("botd offline check: what botd's settings reach outside an air-gapped network (ADR 0257)\n");
        match self.source["envFile"].as_str() {
            Some(f) => out += &format!("Settings: {f}, over botd's environment\n"),
            None => out += "Settings: botd's environment\n",
        }
        if !self.internal.is_empty() {
            out += &format!("Inside, besides private addresses: {}\n", self.internal.join(", "));
        }
        let mut shown: Vec<&Finding> = self.findings.iter().collect();
        shown.sort_by_key(|f| std::cmp::Reverse(f.status));
        for f in shown {
            let setting = f.setting.as_ref().map(|s| format!("{s}: ")).unwrap_or_default();
            out += &format!("  {:<9} {:<22} {setting}{}\n", f.status.word(), f.area.label(), f.detail);
        }
        let (internet, check, ok) = (self.count(Status::Internet), self.count(Status::Check), self.count(Status::Ok));
        out += &format!("{internet} reach the internet, {check} to check, {ok} inside or off.\n");
        out += if internet > 0 {
            "Change the settings marked internet before the network goes offline: botd, or the machines it runs, would try to reach them.\n"
        } else {
            "Nothing botd's settings name is on the internet.\n"
        };
        out += &format!("Docs: {DOC}\n");
        out
    }
}

pub fn run(s: &Settings, internal: &Internal) -> Report {
    let vars: BTreeMap<String, String> = s.vars().into_iter().collect();
    Report { findings: judge(&vars, internal), internal: internal.listed(), source: s.source() }
}

struct Args<'a> {
    json: bool,
    home: Option<&'a str>,
    env_file: Option<&'a str>,
    internal: Vec<&'a str>,
}

fn parse<'a>(rest: &[&'a str]) -> Result<Args<'a>, String> {
    let mut a = Args { json: false, home: None, env_file: None, internal: Vec::new() };
    let mut it = rest.iter();
    while let Some(&flag) = it.next() {
        if flag == "--json" {
            a.json = true;
            continue;
        }
        let slot = match flag {
            "--home" => &mut a.home,
            "--env-file" => &mut a.env_file,
            "--internal" => {
                let v = it.next().ok_or(format!("--internal needs a value\n{USAGE}"))?;
                a.internal.push(*v);
                continue;
            }
            _ => return Err(format!("Unknown option {flag}\n{USAGE}")),
        };
        *slot = Some(*it.next().ok_or(format!("{flag} needs a value\n{USAGE}"))?);
    }
    if a.home.is_some() && a.env_file.is_some() {
        return Err(format!("Use --home or --env-file, not both\n{USAGE}"));
    }
    Ok(a)
}

/// `botd offline check ...`: prints the findings and returns 0, 1 while a setting reaches
/// the internet or the settings can't be read, or 2 for a usage error.
pub fn cli(args: &[String]) -> i32 {
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let Some((&"check", rest)) = args.split_first() else {
        eprintln!("{USAGE}");
        return 2;
    };
    let a = match parse(rest) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("{e}");
            return 2;
        }
    };
    let internal = match Internal::parse(&a.internal) {
        Ok(i) => i,
        Err(e) => {
            eprintln!("{e}\n{USAGE}");
            return 2;
        }
    };
    let s = match Settings::load(a.home, a.env_file) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("botd offline: {e}");
            return 1;
        }
    };
    // Relative files in botd's settings (TIERS_FILE, SAML metadata) are under the install
    // directory, where the installer's unit runs botd.
    if let Some(dir) = a.home.map(|h| Path::new(h).join("superbot")).filter(|d| d.is_dir()) {
        let _ = std::env::set_current_dir(dir);
    }
    let r = run(&s, &internal);
    if a.json {
        println!("{}", serde_json::to_string_pretty(&r.json()).unwrap_or_default());
    } else {
        print!("{}", r.text());
    }
    i32::from(!r.offline())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vars(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    fn internal(list: &[&str]) -> Internal {
        Internal::parse(list).unwrap()
    }

    fn findings(pairs: &[(&str, &str)], inside: &[&str]) -> Vec<Finding> {
        judge(&vars(pairs), &internal(inside))
    }

    fn of(f: &[Finding], area: Area) -> Vec<&Finding> {
        f.iter().filter(|x| x.area == area).collect()
    }

    fn by(f: &[Finding], setting: &str) -> Finding {
        f.iter().find(|x| x.setting.as_deref() == Some(setting)).unwrap_or_else(|| panic!("no finding for {setting}: {f:#?}")).clone()
    }

    fn statuses(f: &[Finding], s: Status) -> Vec<String> {
        f.iter().filter(|x| x.status == s).map(|x| x.setting.clone().unwrap_or_else(|| x.area.id().into())).collect()
    }

    fn temp_file(tag: &str, text: &str) -> String {
        let p = crate::db::temp_path(tag).join(tag);
        std::fs::write(&p, text).unwrap();
        p.display().to_string()
    }

    #[test]
    fn addresses_are_placed_from_the_address_alone() {
        let none = Internal::default();
        for (host, why) in [
            ("127.0.0.1", "loopback"),
            ("[::1]", "loopback"),
            ("10.1.2.3", "a private address"),
            ("172.16.0.9", "a private address"),
            ("192.168.1.1", "a private address"),
            ("169.254.169.254", "link-local"),
            ("100.64.3.4", "shared address"),
            ("fd00::20", "unique local"),
            ("fe80::1", "link-local"),
            ("::ffff:10.0.0.1", "a private address"),
            ("localhost", "loopback"),
            ("api.localhost", "loopback"),
            ("minio", "single-label"),
            ("vault.internal", "under .internal"),
            ("mail.corp.", "under .corp"),
            ("idp.home.arpa", "under .home.arpa"),
        ] {
            match place(host, &none) {
                Place::Inside(w) => assert!(w.contains(why), "{host}: {w}"),
                other => panic!("{host} should be inside, not {other:?}"),
            }
        }
        for (host, service) in [
            ("api.stripe.com", "Stripe"),
            ("STRIPE.COM", "Stripe"),
            ("registry.npmjs.org", "npm's registry"),
            ("images.linuxcontainers.org", "linuxcontainers.org's image server"),
            ("login.microsoftonline.com", "Microsoft Entra ID"),
            ("o1.ingest.sentry.io", "Sentry"),
            ("admin.googleapis.com", "Google Workspace"),
            ("raw.githubusercontent.com", "GitHub"),
        ] {
            assert_eq!(place(host, &none), Place::Internet(service), "{host}");
        }
        assert_eq!(place("s3.eu-west-2.amazonaws.com", &none), Place::Cloud("AWS"));
        assert_eq!(place("kv1.vault.azure.net", &none), Place::Cloud("Azure"));
        assert_eq!(place("secretmanager.googleapis.com", &none), Place::Cloud("Google Cloud"));
        for host in ["notstripe.com", "stripe.com.evil.example", "idp.corp.example", "203.0.113.7", "2001:db8::1", "8.8.8.8"] {
            assert_eq!(place(host, &none), Place::Unknown, "{host}");
        }
    }

    #[test]
    fn internal_suffixes_and_ranges_come_inside() {
        let i = internal(&["corp.example, .Lab.Example.", "203.0.113.0/24", "2001:db8::/32", "198.51.100.7"]);
        assert_eq!(i.listed(), ["corp.example", "lab.example", "203.0.113.0/24", "2001:db8::/32", "198.51.100.7"]);
        for host in ["corp.example", "idp.corp.example", "x.lab.example", "203.0.113.200", "2001:db8:5::1", "198.51.100.7", "::ffff:203.0.113.1"] {
            assert!(matches!(place(host, &i), Place::Inside(_)), "{host}");
        }
        for host in ["notcorp.example", "corp.example.com", "203.0.114.1", "198.51.100.8", "2001:db9::1"] {
            assert!(!matches!(place(host, &i), Place::Inside(_)), "{host}");
        }
        assert!(matches!(place("api.stripe.com", &internal(&["stripe.com"])), Place::Inside(_)), "the operator's word wins");
        assert_eq!(internal(&["0.0.0.0/0"]).listed(), ["0.0.0.0/0"]);
        assert!(matches!(place("8.8.8.8", &internal(&["0.0.0.0/0"])), Place::Inside(_)));
        for bad in ["10.0.0.0/33", "fd00::/129", "under_score.example", "a..b", "corp.example/8", "-bad.example", "10.0.0.0/x"] {
            let e = Internal::parse(&[bad]).unwrap_err();
            assert!(e.contains("--internal") && e.contains(bad), "{bad}: {e}");
        }
        assert_eq!(Internal::parse(&["", " , "]).unwrap(), Internal::default());
    }

    #[test]
    fn hosts_are_read_from_urls_and_bare_names_never_with_their_user() {
        for (v, want) in [
            ("https://key-abc@o1.ingest.sentry.io/42", Some("o1.ingest.sentry.io")),
            ("https://user:pw@s3.example.net:9000/bucket", Some("s3.example.net")),
            ("syslog+tls://siem.corp.example:6514", Some("siem.corp.example")),
            ("azure-monitor://dce.westeurope-1.ingest.monitor.azure.com/dcr-1/Custom-A", Some("dce.westeurope-1.ingest.monitor.azure.com")),
            ("smtp.corp.example", Some("smtp.corp.example")),
            ("smtp.corp.example:587", Some("smtp.corp.example")),
            ("10.0.0.5", Some("10.0.0.5")),
            ("[fd00::5]:8443", Some("fd00::5")),
            ("fd00::5", Some("fd00::5")),
            ("https://[fd00::5]:8443/", Some("fd00::5")),
            ("HTTPS://Vault.Internal./v1", Some("vault.internal")),
            ("", None),
            ("   ", None),
            ("https://", None),
        ] {
            assert_eq!(host_of(v).as_deref(), want, "{v}");
        }
    }

    #[test]
    fn a_fresh_install_reaches_nothing_and_asks_where_models_are() {
        let f = findings(&[], &[]);
        for a in Area::ALL {
            assert!(!of(&f, a).is_empty(), "no finding for {}", a.id());
        }
        let order: Vec<usize> = f.iter().map(|x| Area::ALL.iter().position(|a| *a == x.area).unwrap()).collect();
        assert!(order.windows(2).all(|w| w[0] <= w[1]), "findings in area order");
        assert!(statuses(&f, Status::Internet).is_empty(), "{f:#?}");
        assert_eq!(statuses(&f, Status::Check), ["models"]);
        assert!(of(&f, Area::Models)[0].detail.contains("no model endpoint"));
        assert!(of(&f, Area::License)[0].detail.contains("never calls home"));
    }

    #[test]
    fn connected_defaults_are_each_named_with_what_to_do() {
        let f = findings(
            &[
                ("BILLING", "on"),
                ("PUSH_PROVIDER", "expo"),
                ("TURNSTILE_SITE_KEY", "0x4AAA"),
                ("LINODE_TOKEN", "t"),
                ("MACHINE_HARNESSES", "claude@2.1.0,hermes"),
                ("MACHINE_HARNESS_LOGINS", "on"),
                ("ANTHROPIC_API_KEY", "sk-ant-not-real"),
                ("SSO_PROVIDERS", "entra,github"),
                ("SSO_PUBLIC_URL", "https://bot.corp.example"),
                ("SSO_ENTRA_CLIENT_ID", "c1"),
                ("SSO_ENTRA_TENANT", "11111111-2222-3333-4444-555555555555"),
                ("SSO_GITHUB_CLIENT_ID", "Iv1.abc"),
                ("SSO_GITHUB_ALLOWED_ORGS", "acme"),
                ("ERROR_REPORT_DSN", "https://secret-key-0123@o1.ingest.sentry.io/1"),
                ("GOOGLE_DIRECTORY_SYNC", "on"),
            ],
            &[],
        );
        let internet = statuses(&f, Status::Internet);
        for want in [
            "BILLING",
            "PUSH_PROVIDER",
            "TURNSTILE_SITE_KEY",
            "LINODE_TOKEN",
            "MACHINE_NODE_MIRROR",
            "MACHINE_NPM_REGISTRY",
            "MACHINE_HERMES_BUNDLE",
            "MACHINE_HARNESS_LOGINS",
            "ANTHROPIC_BASE_URL",
            "SSO_ENTRA_AUTHORITY",
            "SSO_GITHUB_URL",
            "SSO_GITHUB_API_URL",
            "ERROR_REPORT_DSN",
            "GOOGLE_DIRECTORY_API_URL",
        ] {
            assert!(internet.iter().any(|s| s == want), "{want} should reach the internet: {internet:?}");
        }
        assert_eq!(by(&f, "BILLING").host.as_deref(), Some("api.stripe.com"));
        assert!(by(&f, "BILLING").detail.contains("Leave BILLING off"));
        assert!(by(&f, "MACHINE_NPM_REGISTRY").detail.contains("claude on machines at registry.npmjs.org"), "{}", by(&f, "MACHINE_NPM_REGISTRY").detail);
        assert!(by(&f, "MACHINE_NPM_REGISTRY").detail.contains("MACHINE_HARNESS_BUNDLE"));
        assert!(by(&f, "MACHINE_HERMES_BUNDLE").detail.contains("Set MACHINE_HERMES_BUNDLE"));
        assert_eq!(by(&f, "SSO_GITHUB_API_URL").host.as_deref(), Some("api.github.com"));
        assert!(by(&f, "LINODE_TOKEN").detail.contains("MACHINE_PROVIDER=incus"));
        let all = format!("{f:?}");
        assert!(!all.contains("secret-key-0123") && !all.contains("sk-ant-not-real"), "no setting's secret is repeated: {all}");
    }

    #[test]
    fn a_server_ready_to_go_offline_reaches_nothing() {
        let tiers = temp_file(
            "offline-tiers.json",
            r#"{"providers":{"local":{"protocol":"openai-chat","baseUrl":"https://10.0.0.40/v1","keySecret":"TIER_LOCAL_KEY"}},
                "tiers":[{"name":"pro","routes":[{"harness":"hermes","provider":"local","model":"m"}]}]}"#,
        );
        let f = findings(
            &[
                ("TIERS_FILE", &tiers),
                ("SUPERBOT_HERMES_BASE_URL", "https://llm.corp.example/v1"),
                ("SSO_PROVIDERS", "corp"),
                ("SSO_PUBLIC_URL", "https://bot.corp.example"),
                ("SSO_CORP_TYPE", "oidc"),
                ("SSO_CORP_ISSUER", "https://idp.corp.example/realms/superbot"),
                ("SSO_CORP_CLIENT_ID", "superbot"),
                ("MACHINE_PROVIDER", "incus"),
                ("INCUS_URL", "https://10.0.0.5:8443"),
                ("INCUS_HOSTS", "b=https://10.0.0.6:8443"),
                ("INCUS_IMAGE_SERVER", "local"),
                ("MACHINE_HARNESSES", "claude,codex,hermes"),
                ("MACHINE_HARNESS_BUNDLE", "/srv/superbot-harnesses-1.0.0-x86_64.tar.gz"),
                ("MACHINE_HERMES_BUNDLE", "/srv/superbot-hermes-v1.0.0-x86_64.tar.gz"),
                ("SMTP_HOST", "mail.internal"),
                ("NOTIFY_WEBHOOK_URL", "https://chat.corp.example/hooks/a"),
                ("NOTIFY_WEBHOOK_URL_BOT_A1B2C3D4", "https://10.0.0.9/hook"),
                ("SERVER_BACKUP_S3_BUCKET", "server"),
                ("SERVER_BACKUP_S3_ENDPOINT", "https://minio.internal:9000"),
                ("MACHINE_BACKUP_S3_BUCKET", "machines"),
                ("MACHINE_BACKUP_S3_ENDPOINT", "https://minio.internal:9000"),
                ("MACHINE_BACKUP_S3_GB_LON_BUCKET", "machines-lon"),
                ("MACHINE_BACKUP_S3_GB_LON_ENDPOINT", "https://10.1.0.10:9000"),
                ("REGION_DATA_S3_DE_FRA_2_BUCKET", "chats-fra"),
                ("REGION_DATA_S3_DE_FRA_2_ENDPOINT", "https://minio-fra.internal"),
                ("AUDIT_EXPORT", "splunk=https://siem.corp.example:8088/services/collector,s3://audit/superbot"),
                ("AUDIT_EXPORT_S3_ENDPOINT", "https://minio.internal:9000"),
                ("AUDIT_TIMESTAMP_URL", "http://tsa.internal/tsr"),
                ("TRACES_OTLP_ENDPOINT", "https://otel.internal:4318"),
                ("SECRETS_BACKEND", "vault"),
                ("VAULT_ADDR", "https://vault.internal:8200"),
            ],
            &["corp.example"],
        );
        assert!(statuses(&f, Status::Internet).is_empty() && statuses(&f, Status::Check).is_empty(), "{f:#?}");
        let set: Vec<String> = f.iter().filter_map(|x| x.setting.clone()).collect();
        for want in [
            "TIERS_FILE",
            "SUPERBOT_HERMES_BASE_URL",
            "SSO_CORP_ISSUER",
            "INCUS_URL",
            "INCUS_HOSTS",
            "SMTP_HOST",
            "NOTIFY_WEBHOOK_URL",
            "NOTIFY_WEBHOOK_URL_BOT_A1B2C3D4",
            "SERVER_BACKUP_S3_ENDPOINT",
            "MACHINE_BACKUP_S3_ENDPOINT",
            "MACHINE_BACKUP_S3_GB_LON_ENDPOINT",
            "REGION_DATA_S3_DE_FRA_2_ENDPOINT",
            "AUDIT_EXPORT",
            "AUDIT_EXPORT_S3_ENDPOINT",
            "AUDIT_TIMESTAMP_URL",
            "TRACES_OTLP_ENDPOINT",
            "VAULT_ADDR",
        ] {
            assert!(set.iter().any(|s| s == want), "{want} was judged: {set:?}");
        }
        let harnesses: Vec<&str> = of(&f, Area::MachineHarnesses).iter().map(|x| x.detail.as_str()).collect();
        assert_eq!(harnesses, ["claude, codex from botd's harness bundle (MACHINE_HARNESS_BUNDLE)", "hermes from botd's Hermes bundle (MACHINE_HERMES_BUNDLE)"]);
        assert!(of(&f, Area::Machines).iter().any(|x| x.detail.contains("INCUS_IMAGE_SERVER=local")));
        assert_eq!(by(&f, "AUDIT_EXPORT").host.as_deref(), Some("siem.corp.example"));
        assert!(by(&f, "SSO_CORP_ISSUER").detail.contains("under corp.example, given with --internal"));
    }

    #[test]
    fn incus_fetches_its_images_from_the_internet_unless_told_otherwise() {
        let base = [("MACHINE_PROVIDER", "incus"), ("INCUS_URL", "https://10.0.0.5:8443"), ("MACHINE_HARNESSES", "none")];
        let f = findings(&base, &[]);
        let images = by(&f, "INCUS_IMAGE_SERVER");
        assert_eq!((images.status, images.host.as_deref()), (Status::Internet, Some("images.linuxcontainers.org")));
        assert!(images.detail.contains("set INCUS_IMAGE_SERVER=local"));
        assert_eq!(of(&f, Area::MachineHarnesses)[0].detail, "machines get no harness CLIs from botd");
        let mirror = findings(&[base[0], base[1], ("INCUS_IMAGE_SERVER", "https://images.internal")], &[]);
        assert_eq!(by(&mirror, "INCUS_IMAGE_SERVER").status, Status::Ok);
        let f = findings(&[base[0], base[1], ("MACHINE_HARNESSES", "pi"), ("MACHINE_NODE_MIRROR", "https://nexus.internal/node"), ("MACHINE_NPM_REGISTRY", "https://10.0.0.20/npm/")], &[]);
        assert_eq!((by(&f, "MACHINE_NODE_MIRROR").status, by(&f, "MACHINE_NPM_REGISTRY").status), (Status::Ok, Status::Ok));
        let missing = findings(&[base[0]], &[]);
        assert_eq!(by(&missing, "INCUS_URL").status, Status::Check);
    }

    #[test]
    fn machines_take_the_managed_tiers_harnesses_when_none_are_named() {
        let tiers = temp_file(
            "offline-tiers-managed.json",
            r#"{"tiers":[{"name":"pro","defaultHarness":"codex","routes":[{"harness":"codex","model":"gpt-5-codex"},{"harness":"hermes","provider":"openrouter","model":"m","fallback":[{"provider":"nous","model":"n"}]}]}]}"#,
        );
        let f = findings(&[("TIERS_FILE", &tiers), ("LINODE_TOKEN", "t")], &[]);
        assert!(by(&f, "MACHINE_NPM_REGISTRY").detail.starts_with("codex on machines"), "{f:#?}");
        let routes: Vec<&str> = of(&f, Area::Models).iter().filter(|x| x.status == Status::Check).map(|x| x.detail.as_str()).collect();
        assert_eq!(routes.len(), 2, "{routes:?}");
        assert!(routes[0].starts_with("Hermes Agent's provider nous,") && routes[1].starts_with("Hermes Agent's provider openrouter,"), "{routes:?}");
        let bad = findings(&[("TIERS_FILE", "/nonexistent/offline-tiers.json")], &[]);
        let t = by(&bad, "TIERS_FILE");
        assert_eq!(t.status, Status::Check);
        assert!(t.detail.contains("won't start"), "{}", t.detail);
    }

    #[test]
    fn sign_in_names_each_providers_addresses() {
        let saml = temp_file("offline-saml.xml", "not metadata");
        let bad = findings(&[("SSO_PROVIDERS", "corp"), ("SSO_PUBLIC_URL", "https://bot.corp.example"), ("SSO_CORP_TYPE", "saml"), ("SSO_CORP_IDP_ENTITY_ID", "http://idp.corp.example/x"), ("SSO_CORP_IDP_METADATA_FILE", &saml)], &[]);
        let f = by(&bad, "SSO_PROVIDERS");
        assert_eq!(f.status, Status::Check);
        assert!(f.detail.contains("don't read") && f.detail.contains("SSO_CORP_IDP_METADATA_FILE"), "{}", f.detail);
        let url = findings(
            &[
                ("SSO_PROVIDERS", "adfs"),
                ("SSO_PUBLIC_URL", "https://bot.corp.example"),
                ("SSO_ADFS_TYPE", "saml"),
                ("SSO_ADFS_IDP_ENTITY_ID", "http://adfs.corp.example/adfs/services/trust"),
                ("SSO_ADFS_IDP_METADATA_URL", "https://adfs.corp.example/FederationMetadata/2007-06/FederationMetadata.xml"),
            ],
            &[],
        );
        let m = by(&url, "SSO_ADFS_IDP_METADATA_URL");
        assert_eq!((m.status, m.host.as_deref()), (Status::Check, Some("adfs.corp.example")));
        assert!(m.detail.ends_with("add --internal corp.example"), "{}", m.detail);
        let google = findings(&[("SSO_PROVIDERS", "google"), ("SSO_PUBLIC_URL", "https://bot.corp.example"), ("SSO_GOOGLE_CLIENT_ID", "c.apps.googleusercontent.com")], &[]);
        assert_eq!((by(&google, "SSO_GOOGLE_ISSUER").status, by(&google, "SSO_GOOGLE_ISSUER").host.as_deref()), (Status::Internet, Some("accounts.google.com")));
    }

    #[test]
    fn native_saml_names_the_hosts_its_metadata_sends_people_to() {
        use crate::sso::saml_sp::test_idp;
        let xml = temp_file("offline-idp.xml", &test_idp::metadata());
        let base = [("SSO_PROVIDERS", "corp"), ("SSO_PUBLIC_URL", "https://bot.corp.example"), ("SSO_CORP_TYPE", "saml"), ("SSO_CORP_IDP_ENTITY_ID", test_idp::IDP)];
        let with_file: Vec<(&str, &str)> = base.iter().copied().chain([("SSO_CORP_IDP_METADATA_FILE", xml.as_str())]).collect();
        let f = findings(&with_file, &[]);
        let page = by(&f, "SSO_CORP_IDP_METADATA_FILE");
        assert_eq!((page.status, page.host.as_deref()), (Status::Check, Some("idp.example")), "{f:#?}");
        assert!(page.detail.starts_with("SSO provider corp's sign-in page at idp.example"), "{}", page.detail);
        assert_eq!(by(&findings(&with_file, &["idp.example"]), "SSO_CORP_IDP_METADATA_FILE").status, Status::Ok);
        let saved = findings(&base, &[]);
        let s = by(&saved, "SSO_PROVIDERS");
        assert_eq!(s.status, Status::Check);
        assert!(s.detail.contains("saved with botctl, which this check doesn't read"), "{}", s.detail);
    }

    #[test]
    fn audit_sinks_are_judged_at_the_hosts_they_send_to() {
        let secops = findings(&[("AUDIT_EXPORT", "google-secops://eu/my-project/01234567-89ab-cdef-0123-456789abcdef/SUPERBOT_AUDIT")], &[]);
        let to = by(&secops, "AUDIT_EXPORT");
        assert_eq!((to.status, to.host.as_deref()), (Status::Check, Some("eu-chronicle.googleapis.com")), "{secops:#?}");
        assert_eq!(by(&secops, "GCE_METADATA_HOST").status, Status::Ok, "the metadata server is link-local");
        let key = findings(&[("AUDIT_EXPORT", "google-secops://us/my-project/01234567-89ab-cdef-0123-456789abcdef/SUPERBOT_AUDIT"), ("AUDIT_EXPORT_GCP_AUTH", "service-account-key")], &[]);
        assert_eq!(by(&key, "GCP_SERVICE_ACCOUNT_KEY").host.as_deref(), Some("oauth2.googleapis.com"));
        let dd = findings(&[("AUDIT_EXPORT", "siem=datadog://datadoghq.eu")], &[]);
        let to = by(&dd, "AUDIT_EXPORT");
        assert_eq!((to.status, to.host.as_deref()), (Status::Internet, Some("http-intake.logs.datadoghq.eu")));
        let azure = findings(&[("AUDIT_EXPORT", "azure-monitor://s.eastus-1.ingest.monitor.azure.com/dcr-00000000000000000000000000000000/Custom-A"), ("AUDIT_EXPORT_AZURE_AUTH", "client-secret")], &[]);
        assert_eq!(by(&azure, "AUDIT_EXPORT").status, Status::Check);
        assert_eq!(by(&azure, "AZURE_AUTHORITY_HOST").status, Status::Internet);
        let bad = by(&findings(&[("AUDIT_EXPORT", "google-secops://eu/p/i/T"), ("AUDIT_EXPORT_GCP_AUTH", "password")], &[]), "AUDIT_EXPORT_GCP_AUTH");
        assert_eq!(bad.status, Status::Check);
    }

    #[test]
    fn secrets_managers_name_the_hosts_they_sign_in_at() {
        let aws = [("SECRETS_BACKEND", "aws"), ("AWS_REGION", "eu-west-2"), ("AWS_ENDPOINT_URL_SECRETS_MANAGER", "https://vpce.internal"), ("AWS_WEB_IDENTITY_TOKEN_FILE", "/var/run/token"), ("AWS_ROLE_ARN", "arn:aws:iam::123456789012:role/botd")];
        let f = findings(&aws, &[]);
        assert_eq!(by(&f, "AWS_ENDPOINT_URL_SECRETS_MANAGER").status, Status::Ok);
        let sts = by(&f, "AWS_ENDPOINT_URL_STS");
        assert_eq!((sts.status, sts.host.as_deref()), (Status::Check, Some("sts.eu-west-2.amazonaws.com")));
        let cn = findings(&[("SECRETS_BACKEND", "aws"), ("AWS_REGION", "cn-north-1")], &[]);
        assert_eq!(by(&cn, "AWS_ENDPOINT_URL_SECRETS_MANAGER").host.as_deref(), Some("secretsmanager.cn-north-1.amazonaws.com.cn"));
        assert!(cn.iter().all(|x| x.setting.as_deref() != Some("AWS_ENDPOINT_URL_STS")), "STS only for web identity and runs");
        let none = by(&findings(&[("SECRETS_BACKEND", "aws")], &[]), "SECRETS_BACKEND");
        assert!(none.status == Status::Check && none.detail.contains("AWS_SECRETS_MANAGER_REGION"), "{}", none.detail);
        let gcp = findings(&[("SECRETS_BACKEND", "gcp-secret-manager"), ("GCP_SECRET_MANAGER_LOCATION", "europe-west2"), ("GCP_RUN_CREDENTIALS", "sa@p.iam.gserviceaccount.com TOKEN=accessToken boundary=b.json")], &[]);
        assert_eq!(by(&gcp, "GCP_SECRET_MANAGER_ENDPOINT").host.as_deref(), Some("secretmanager.europe-west2.rep.googleapis.com"));
        assert_eq!(by(&gcp, "GCP_IAM_CREDENTIALS_ENDPOINT").host.as_deref(), Some("iamcredentials.googleapis.com"));
        assert_eq!(by(&gcp, "GCP_STS_ENDPOINT").host.as_deref(), Some("sts.googleapis.com"));
        let azure = findings(&[("SECRETS_BACKEND", "azure-keyvault"), ("AZURE_KEYVAULT_URL", "https://kv1.vault.azure.net"), ("AZURE_RUN_CREDENTIALS", "x")], &[]);
        assert_eq!(by(&azure, "IDENTITY_ENDPOINT").status, Status::Ok);
        assert_eq!(by(&azure, "AZURE_AUTHORITY_HOST").status, Status::Internet, "a managed identity trades its token at Entra ID for runs");
    }

    #[test]
    fn no_users_or_passwords_reach_the_report() {
        assert_eq!(scrub("bad https://user:hunter2@host.example/x and s3://k@minio:9000 \"ftp://a@b\""), "bad https://host.example/x and s3://minio:9000 \"ftp://b\"");
        assert_eq!(scrub("no URL: a@b"), "no URL: a@b");
        let tiers = temp_file("offline-tiers-creds.json", r#"{"providers":{"x":{"protocol":"openai-chat","baseUrl":"ftp://user:hunter2@llm.example/v1","keySecret":"TIER_X"}},"tiers":[{"name":"t"}]}"#);
        let f = findings(&[("TIERS_FILE", &tiers), ("VAULT_ADDR", "https://u:hunter2@vault.internal"), ("SECRETS_BACKEND", "vault")], &[]);
        let all = format!("{f:?}");
        assert!(by(&f, "TIERS_FILE").status == Status::Check && !all.contains("hunter2"), "{all}");
    }

    #[test]
    fn cloud_services_are_to_check_until_a_private_endpoint_is_named() {
        let aws = [("SECRETS_BACKEND", "aws"), ("AWS_REGION", "eu-west-2")];
        let f = by(&findings(&aws, &[]), "AWS_ENDPOINT_URL_SECRETS_MANAGER");
        assert_eq!((f.status, f.host.as_deref()), (Status::Check, Some("secretsmanager.eu-west-2.amazonaws.com")));
        assert!(f.detail.contains("private endpoint") && f.detail.ends_with("add --internal secretsmanager.eu-west-2.amazonaws.com"), "{}", f.detail);
        assert_eq!(by(&findings(&aws, &["secretsmanager.eu-west-2.amazonaws.com"]), "AWS_ENDPOINT_URL_SECRETS_MANAGER").status, Status::Ok);
        let azure = findings(&[("SECRETS_BACKEND", "azure-keyvault"), ("AZURE_KEYVAULT_URL", "https://kv1.vault.azure.net"), ("AZURE_KEYVAULT_AUTH", "client-secret")], &[]);
        assert_eq!(by(&azure, "AZURE_KEYVAULT_URL").status, Status::Check);
        assert_eq!(by(&azure, "AZURE_AUTHORITY_HOST").status, Status::Internet);
        let managed = findings(&[("SECRETS_BACKEND", "azure-keyvault"), ("AZURE_KEYVAULT_URL", "https://kv1.vault.azure.net")], &[]);
        assert!(managed.iter().all(|x| x.setting.as_deref() != Some("AZURE_AUTHORITY_HOST")));
        let gcp = findings(&[("SECRETS_BACKEND", "gcp-secret-manager")], &[]);
        assert_eq!(by(&gcp, "GCP_SECRET_MANAGER_ENDPOINT").host.as_deref(), Some("secretmanager.googleapis.com"));
        assert_eq!(by(&findings(&[("SECRETS_BACKEND", "consul")], &[]), "SECRETS_BACKEND").status, Status::Check);
    }

    #[test]
    fn every_regions_backup_store_is_judged() {
        let f = findings(
            &[
                ("REGION_DATA_S3_GB_LON_BUCKET", "chats"),
                ("REGION_DATA_S3_GB_LON_ENDPOINT", "https://s3.eu-central-003.backblazeb2.com"),
                ("REGION_DATA_S3_DE_FRA_2_BUCKET", "chats-fra"),
                ("MACHINE_BACKUP_S3_US_EAST_BUCKET", "m"),
                ("MACHINE_BACKUP_S3_US_EAST_ENDPOINT", "https://us-east-1.linodeobjects.com"),
                ("REGION_DATA_S3_PREFIX", "superbot/"),
            ],
            &[],
        );
        let b2 = by(&f, "REGION_DATA_S3_GB_LON_ENDPOINT");
        assert_eq!(b2.status, Status::Internet);
        assert!(b2.detail.starts_with("Chat store backups' S3 store for gb-lon at s3.eu-central-003.backblazeb2.com"), "{}", b2.detail);
        assert_eq!(by(&f, "REGION_DATA_S3_DE_FRA_2_ENDPOINT").status, Status::Check, "a bucket with no endpoint");
        assert_eq!(by(&f, "MACHINE_BACKUP_S3_US_EAST_ENDPOINT").status, Status::Internet);
        assert_eq!(of(&f, Area::Backups).len(), 3, "{f:#?}");
    }

    #[test]
    fn switches_that_are_off_reach_nothing() {
        let f = findings(
            &[("BILLING", "off"), ("PUSH_PROVIDER", "off"), ("AUDIT_EXPORT", "off"), ("SERVER_BACKUP_OFF_HOST", "off"), ("SERVER_BACKUP_S3_BUCKET", "b"), ("GOOGLE_DIRECTORY_SYNC", "off"), ("MACHINE_HARNESSES", "claude")],
            &[],
        );
        assert!(statuses(&f, Status::Internet).is_empty(), "{f:#?}");
        assert_eq!(of(&f, Area::MachineHarnesses)[0].detail, "no users' machines to install them on");
        let bad = by(&findings(&[("BILLING", "maybe")], &[]), "BILLING");
        assert_eq!(bad.status, Status::Check);
    }

    #[test]
    fn the_report_puts_the_internet_first_and_counts_each() {
        let v = vars(&[("BILLING", "on"), ("SMTP_HOST", "smtp.corp.example")]);
        let r = Report { findings: judge(&v, &Internal::default()), internal: Vec::new(), source: json!({ "envFile": "/home/sb/superbot/.env", "home": "/home/sb" }) };
        assert!(!r.offline());
        let text = r.text();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines[1], "Settings: /home/sb/superbot/.env, over botd's environment");
        assert!(lines[2].starts_with("  internet  Billing                BILLING: Billing at api.stripe.com"), "{text}");
        assert!(lines[3].starts_with("  check     Model providers"), "{text}");
        assert!(lines[4].starts_with("  check     Email                  SMTP_HOST: Email at smtp.corp.example"), "{text}");
        assert!(text.contains("1 reach the internet, 2 to check, 12 inside or off.") && text.contains("Change the settings marked internet"), "{text}");
        assert!(text.ends_with(&format!("Docs: {DOC}\n")));
        let j = r.json();
        assert_eq!(j["format"], FORMAT);
        assert_eq!(j["offline"], false);
        assert_eq!(j["counts"], json!({ "ok": 12, "check": 2, "internet": 1 }));
        assert_eq!(j["findings"][5], json!({ "area": "billing", "status": "internet", "setting": "BILLING", "host": "api.stripe.com", "detail": by(&r.findings, "BILLING").detail }));
        let clean = Report { findings: judge(&vars(&[]), &Internal::default()), internal: vec!["corp.example".into()], source: json!({}) };
        assert!(clean.offline());
        assert!(clean.text().contains("Settings: botd's environment\nInside, besides private addresses: corp.example\n"));
        assert!(clean.text().contains("Nothing botd's settings name is on the internet."));
    }

    #[test]
    fn the_command_line_reads_an_env_file_and_exits_by_what_it_found() {
        let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>();
        for bad in [
            &["check", "--bogus"][..],
            &["check", "--home"],
            &["check", "--internal"],
            &["check", "--home", "/h", "--env-file", "/f"],
            &["check", "--internal", "a..b"],
            &["verify"],
            &[],
        ] {
            assert_eq!(cli(&s(bad)), 2, "{bad:?}");
        }
        let a = parse(&["--json", "--internal", "corp.example", "--internal", "10.0.0.0/8", "--env-file", "/f"]).unwrap();
        assert!(a.json && a.env_file == Some("/f") && a.home.is_none());
        assert_eq!(a.internal, ["corp.example", "10.0.0.0/8"]);
        let online = temp_file("offline-online.env", "BILLING=on\n");
        assert_eq!(cli(&s(&["check", "--env-file", &online, "--json"])), 1);
        assert_eq!(cli(&s(&["check", "--env-file", &online, "--internal", "stripe.com"])), 0);
        let offline = temp_file("offline-offline.env", "SMTP_HOST=10.0.0.25\nSMTP_FROM=bots@corp.example\n");
        assert_eq!(cli(&s(&["check", "--env-file", &offline])), 0);
        assert_eq!(cli(&s(&["check", "--env-file", "/nonexistent/offline.env"])), 1);
    }

    #[test]
    fn the_guide_explains_the_check_and_each_area() {
        let guide = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../docs/ops/air-gapped.md")).unwrap();
        let (_, section) = guide.split_once("\n## Checking settings before going offline\n").expect("the guide has the check's section");
        let section = section.split("\n## ").next().unwrap();
        for want in ["botd offline check", "--internal", "--home", "--env-file", "--json", "internet", "check", "install.sh --offline"] {
            assert!(section.contains(want), "the section mentions {want}");
        }
        for a in Area::ALL {
            assert!(section.contains(&format!("| {} |", a.label())), "the section's table has {}", a.label());
        }
        assert!(guide.contains("INCUS_IMAGE_SERVER"), "the guide says where Incus images come from");
    }
}
