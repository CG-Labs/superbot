//! Harness CLIs on users' machines from mirrors inside the operator's network
//! (ADR 0186). botd's plan names nodejs.org and npm's registry; with
//! MACHINE_NODE_MIRROR and MACHINE_NPM_REGISTRY it names the operator's copies instead,
//! and MACHINE_MIRROR_CA_FILE the CA they're signed by. The pins don't change: Node.js
//! is checked against its pinned SHA-256 and each npm harness against its pinned
//! SHA-512 wherever it comes from, so a mirror can serve them but not change them.
//! `GET /api/machines/harness-mirror` fetches everything the plan names from where
//! machines would, and checks each against its pin, before any machine needs it.
//!
//! A registry that needs a login (ADR 0219) gets MACHINE_NPM_TOKEN, or
//! MACHINE_NPM_USERNAME and MACHINE_NPM_PASSWORD, from botd's secrets. The plan only
//! says one is needed (`npmLogin`); agents fetch it from botd's machine port for each
//! install, and the check signs in with it as npm would.

use super::tools::{self, MAX_CA};
use super::wire::{self, HarnessPlan, InstallSource};
use crate::secrets::SecretStore;
use crate::{ApiError, AppState, Res};
use axum::Json;
use axum::extract::State as AppS;
use axum::http::StatusCode;
use base64::Engine;
use serde_json::{Value, json};
use sha2::{Digest, Sha256, Sha512};
use std::sync::{Arc, Mutex};
use zeroize::Zeroizing;

/// npm's own registry, what a plan without MACHINE_NPM_REGISTRY uses.
pub const NPM_REGISTRY: &str = "https://registry.npmjs.org/";
/// The largest file the check fetches, as the agent's largest download.
const MAX_FILE: u64 = 256 << 20;
/// The largest package document. npm's abbreviated ones are far smaller.
const MAX_PACKUMENT: u64 = 64 << 20;

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Mirrors {
    /// MACHINE_NODE_MIRROR, laid out as `https://nodejs.org/dist`, with no trailing `/`.
    pub node: Option<String>,
    /// MACHINE_NPM_REGISTRY, ending in `/`.
    pub npm: Option<String>,
    /// MACHINE_MIRROR_CA_FILE's certificates, and the file they came from.
    pub ca: Option<(String, String)>,
    /// How machines sign in to `npm` (ADR 0219).
    pub login: Option<Login>,
}

/// How machines, and botd's check, sign in to MACHINE_NPM_REGISTRY (ADR 0219).
#[derive(Clone, PartialEq)]
pub enum Login {
    /// MACHINE_NPM_TOKEN: npm's `_authToken`, sent as `Bearer`.
    Token(Zeroizing<String>),
    /// MACHINE_NPM_USERNAME and MACHINE_NPM_PASSWORD: npm's `_auth` (base64 of
    /// `user:password`), sent as `Basic`.
    Basic { username: String, auth: Zeroizing<String> },
}

impl std::fmt::Debug for Login {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Login::Token(_) => f.write_str("Login::Token(…)"),
            Login::Basic { username, .. } => write!(f, "Login::Basic({username}, …)"),
        }
    }
}

/// The longest MACHINE_NPM_USERNAME.
const MAX_USERNAME: usize = 256;

impl Login {
    fn from_env(store: &dyn SecretStore, var: &dyn Fn(&str) -> String) -> Result<Option<Login>, String> {
        let secret = |k: &str| store.get(k).map_err(|e| format!("{k}: {e}")).map(|s| s.map(|s| Zeroizing::new(s.expose().to_string())));
        let token = secret("MACHINE_NPM_TOKEN")?;
        let password = secret("MACHINE_NPM_PASSWORD")?;
        let username = var("MACHINE_NPM_USERNAME").trim().to_string();
        let login = match (token, username.is_empty(), password) {
            (None, true, None) => return Ok(None),
            (Some(_), false, _) | (Some(_), _, Some(_)) => {
                return Err("set MACHINE_NPM_TOKEN, or MACHINE_NPM_USERNAME and MACHINE_NPM_PASSWORD, not both".into());
            }
            (None, false, None) => return Err("MACHINE_NPM_USERNAME needs MACHINE_NPM_PASSWORD".into()),
            (None, true, Some(_)) => return Err("MACHINE_NPM_PASSWORD needs MACHINE_NPM_USERNAME".into()),
            (Some(t), true, None) => {
                let t = Zeroizing::new(t.trim().to_string());
                if !tools::npmrc_value(&t) {
                    return Err(format!(
                        "MACHINE_NPM_TOKEN must be 1 to {} letters, digits and - . _ ~ + / = :, as registry tokens are",
                        tools::MAX_LOGIN
                    ));
                }
                crate::secrets::redact::register(&t);
                Login::Token(t)
            }
            (None, false, Some(p)) => {
                if username.len() > MAX_USERNAME || username.contains(':') || username.chars().any(char::is_control) {
                    return Err(format!("MACHINE_NPM_USERNAME must be up to {MAX_USERNAME} characters, without : or control characters"));
                }
                if p.is_empty() || p.chars().any(char::is_control) {
                    return Err("MACHINE_NPM_PASSWORD must have no control characters".into());
                }
                let auth = Zeroizing::new(base64::engine::general_purpose::STANDARD.encode(format!("{username}:{}", p.as_str())));
                if !tools::npmrc_value(&auth) {
                    return Err(format!("MACHINE_NPM_USERNAME and MACHINE_NPM_PASSWORD are over {} bytes together", tools::MAX_LOGIN * 3 / 4));
                }
                crate::secrets::redact::register(&p);
                crate::secrets::redact::register(&auth);
                Login::Basic { username, auth }
            }
        };
        Ok(Some(login))
    }

    /// `token` or `basic`, for the check and the audit log: never the value.
    pub fn kind(&self) -> &'static str {
        match self {
            Login::Token(_) => "token",
            Login::Basic { .. } => "basic",
        }
    }

    /// The `Authorization` header npm would send.
    pub fn header(&self) -> String {
        match self {
            Login::Token(t) => format!("Bearer {}", t.as_str()),
            Login::Basic { auth, .. } => format!("Basic {}", auth.as_str()),
        }
    }

    /// What `GET /v1/npm-login` sends an enrolled machine for `registry`.
    pub fn wire(&self, registry: &str) -> wire::NpmLogin {
        let (token, auth) = match self {
            Login::Token(t) => (Some(t.as_str().to_string()), None),
            Login::Basic { auth, .. } => (None, Some(auth.as_str().to_string())),
        };
        wire::NpmLogin { registry: registry.into(), token, auth }
    }

    fn describe(&self) -> String {
        match self {
            Login::Token(_) => "signing in with MACHINE_NPM_TOKEN".into(),
            Login::Basic { username, .. } => format!("signing in as {username} (MACHINE_NPM_USERNAME)"),
        }
    }
}

/// An https URL with no login, query or fragment, without its trailing `/`.
fn base(key: &str, raw: &str) -> Result<Option<String>, String> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Ok(None);
    }
    let bad = || format!("{key} must be an https URL with no login, query or fragment, like https://mirror.corp.example/nodejs, not \"{raw}\"");
    let u = url::Url::parse(raw).map_err(|_| bad())?;
    if u.scheme() != "https" || u.host().is_none() || !u.username().is_empty() || u.password().is_some() || u.query().is_some() || u.fragment().is_some() || raw.len() > 1024 {
        return Err(bad());
    }
    Ok(Some(u.as_str().trim_end_matches('/').to_string()))
}

impl Mirrors {
    /// Settings from `var`; the registry's login from `store`, botd's secrets.
    pub fn from_env(var: &dyn Fn(&str) -> String, store: &dyn SecretStore) -> Result<Option<Mirrors>, String> {
        let node = base("MACHINE_NODE_MIRROR", &var("MACHINE_NODE_MIRROR"))?;
        let npm = base("MACHINE_NPM_REGISTRY", &var("MACHINE_NPM_REGISTRY"))?.map(|u| format!("{u}/"));
        let file = var("MACHINE_MIRROR_CA_FILE").trim().to_string();
        let login = Login::from_env(store, var)?;
        if login.is_some() && npm.is_none() {
            return Err("MACHINE_NPM_TOKEN, MACHINE_NPM_USERNAME and MACHINE_NPM_PASSWORD need MACHINE_NPM_REGISTRY: botd sends a registry login only to the operator's own registry".into());
        }
        if node.is_none() && npm.is_none() {
            if !file.is_empty() {
                return Err("MACHINE_MIRROR_CA_FILE needs MACHINE_NODE_MIRROR or MACHINE_NPM_REGISTRY".into());
            }
            return Ok(None);
        }
        let ca = if file.is_empty() {
            None
        } else {
            let meta = std::fs::metadata(&file).map_err(|e| format!("MACHINE_MIRROR_CA_FILE ({file}): {e}"))?;
            if meta.len() > MAX_CA as u64 {
                return Err(format!("MACHINE_MIRROR_CA_FILE ({file}) is over {} KiB", MAX_CA >> 10));
            }
            let pem = std::fs::read_to_string(&file).map_err(|e| format!("MACHINE_MIRROR_CA_FILE ({file}): {e}"))?;
            tools::ca_bundle(&pem).map_err(|e| format!("MACHINE_MIRROR_CA_FILE ({file}): {e}"))?;
            Some((pem, file))
        };
        Ok(Some(Mirrors { node, npm, ca, login }))
    }

    /// `plan` as machines fetch it here: the same pins, from the mirrors. A plan with
    /// nothing a mirror serves is left as it is.
    pub fn apply(&self, mut plan: HarnessPlan) -> HarnessPlan {
        let npm = plan.harnesses.iter().any(|h| matches!(h.source, InstallSource::Npm { .. }));
        let mut mirrored = false;
        if let (Some(base), Some(n)) = (&self.node, plan.node.as_mut()) {
            for d in n.downloads.values_mut() {
                let file = d.url.rsplit('/').next().unwrap_or_default().to_string();
                d.url = format!("{base}/v{}/{file}", n.version);
            }
            mirrored = true;
        }
        if npm && let Some(r) = &self.npm {
            plan.npm_registry = Some(r.clone());
            plan.npm_login = self.login.is_some();
            mirrored = true;
        }
        if mirrored {
            plan.ca = self.ca.as_ref().map(|(pem, _)| pem.clone());
        }
        plan
    }

    pub fn describe(&self, plan: Option<&HarnessPlan>) -> String {
        let mut s = format!(
            "harness mirrors: Node.js from {}, npm from {}",
            self.node.as_deref().unwrap_or("nodejs.org"),
            self.npm.as_deref().unwrap_or("npm's registry")
        );
        if let Some(l) = &self.login {
            s.push_str(&format!(" {}", l.describe()));
        }
        if let Some((_, file)) = &self.ca {
            s.push_str(&format!(", their CA from {file}"));
        }
        let unmirrored = unmirrored(plan);
        if !unmirrored.is_empty() {
            s.push_str(&format!(
                "; {} still download from the internet (Hermes Agent's installer reaches GitHub and PyPI): set MACHINE_HERMES_BUNDLE, or leave them out of MACHINE_HARNESSES, on a network without it",
                unmirrored.join(", ")
            ));
        }
        s
    }
}

/// The harnesses in `plan` no mirror serves: those with an installer script.
pub fn unmirrored(plan: Option<&HarnessPlan>) -> Vec<String> {
    plan.map_or(vec![], |p| p.harnesses.iter().filter(|h| matches!(h.source, InstallSource::Script { .. })).map(|h| h.name.clone()).collect())
}

/// Whether only an agent that says `CAN_HARNESS_MIRRORS` can install `plan`.
pub fn needs_agent_support(plan: &HarnessPlan) -> bool {
    plan.npm_registry.is_some() || plan.ca.is_some()
}

/// Whether npm would send `registry`'s login with a request for `url`: its key starts
/// with the registry's (host, port and path; not the scheme).
pub fn under_registry(url: &str, registry: &str) -> bool {
    matches!((tools::nerf_dart(url), tools::nerf_dart(registry)), (Some(u), Some(r)) if u.starts_with(&r))
}

/// The check's requests, signed in to the registry as npm would be, and nowhere else.
/// A redirect to another host or port drops the login (reqwest does), as npm does.
struct Fetch<'a> {
    http: reqwest::Client,
    registry: &'a str,
    login: Option<&'a Login>,
}

impl Fetch<'_> {
    async fn get(&self, url: &str, accept: Option<&str>) -> Result<reqwest::Response, String> {
        let mut req = self.http.get(url);
        if let Some(a) = accept {
            req = req.header("accept", a);
        }
        let ours = under_registry(url, self.registry);
        if let Some(l) = self.login.filter(|_| ours) {
            req = req.header("authorization", l.header());
        }
        let r = req.send().await.map_err(|e| format!("couldn't fetch {url}: {}", error_chain(&e.without_url())))?;
        let code = r.status();
        if ours && (code == StatusCode::UNAUTHORIZED || code == StatusCode::FORBIDDEN) {
            return Err(match self.login {
                Some(l) => format!("the registry refused botd's login ({code}) for {url}: check {}", if l.kind() == "token" { "MACHINE_NPM_TOKEN" } else { "MACHINE_NPM_USERNAME and MACHINE_NPM_PASSWORD" }),
                None => format!("the registry wants a login ({code}) for {url}: set MACHINE_NPM_TOKEN, or MACHINE_NPM_USERNAME and MACHINE_NPM_PASSWORD"),
            });
        }
        r.error_for_status().map_err(|e| format!("couldn't fetch {url}: {}", error_chain(&e.without_url())))
    }
}

/// `url`'s SHA-256 (hex) and SHA-512 (npm's `sha512-<base64>`), read up to `max` bytes.
async fn digests(http: &Fetch<'_>, url: &str, max: u64) -> Result<(String, String), String> {
    let mut r = http.get(url, None).await?;
    let (mut a, mut b, mut n) = (Sha256::new(), Sha512::new(), 0u64);
    while let Some(chunk) = r.chunk().await.map_err(|e| format!("{url}: {}", error_chain(&e.without_url())))? {
        n += chunk.len() as u64;
        if n > max {
            return Err(format!("{url} is over {} MiB", max >> 20));
        }
        a.update(&chunk);
        b.update(&chunk);
    }
    let hex: String = a.finalize().iter().map(|x| format!("{x:02x}")).collect();
    Ok((hex, format!("sha512-{}", base64::engine::general_purpose::STANDARD.encode(b.finalize()))))
}

/// An error with its causes, so a TLS failure says why.
fn error_chain(e: &dyn std::error::Error) -> String {
    let mut s = e.to_string();
    let mut cause = e.source();
    while let Some(c) = cause {
        let text = c.to_string();
        if !s.contains(&text) {
            s.push_str(&format!(": {text}"));
        }
        cause = c.source();
    }
    s
}

/// The registry's tarball and SHA-512 for `package@version`.
async fn listed(http: &Fetch<'_>, package: &str, version: &str) -> Result<(String, Option<String>), String> {
    let url = format!("{}{}", http.registry, package.replace('/', "%2f"));
    let mut r = http.get(&url, Some("application/vnd.npm.install-v1+json; q=1.0, application/json; q=0.8")).await?;
    let mut body = Vec::new();
    while let Some(chunk) = r.chunk().await.map_err(|e| format!("{url}: {}", error_chain(&e.without_url())))? {
        if (body.len() + chunk.len()) as u64 > MAX_PACKUMENT {
            return Err(format!("{url} is over {} MiB", MAX_PACKUMENT >> 20));
        }
        body.extend_from_slice(&chunk);
    }
    let v: Value = serde_json::from_slice(&body).map_err(|_| format!("{url} isn't an npm package document"))?;
    let dist = &v["versions"][version]["dist"];
    let tarball = dist["tarball"].as_str().ok_or(format!("the registry has no {package}@{version}"))?;
    Ok((tarball.to_string(), dist["integrity"].as_str().map(String::from)))
}

/// One npm harness: listed with its pinned SHA-512, and its tarball really that.
async fn npm(http: &Fetch<'_>, package: &str, version: &str, pin: Option<&str>) -> (Option<String>, Result<(), String>) {
    let (tarball, integrity) = match listed(http, package, version).await {
        Ok(l) => l,
        Err(e) => return (None, Err(e)),
    };
    let res = async {
        if !tarball.starts_with("https://") {
            return Err(format!("the registry lists {tarball} for it, which isn't https"));
        }
        if let (Some(pin), Some(listed)) = (pin, integrity.as_deref())
            && pin != listed
        {
            return Err(format!("the registry lists {listed} for it, not the pinned {pin}"));
        }
        let want = pin.or(integrity.as_deref()).ok_or("the registry lists no SHA-512 for it, and there is no pin")?;
        let (_, got) = digests(http, &tarball, MAX_FILE).await?;
        if got != want {
            return Err(format!("its tarball has {got}, not {}", if pin.is_some() { format!("the pinned {want}") } else { format!("the listed {want}") }));
        }
        Ok(())
    }
    .await;
    (Some(tarball), res)
}

/// Fetches everything `plan` names from where machines would, with the CA they'd
/// trust and, when the plan says the registry needs one, the login they'd use (`login`),
/// and checks each against its pin. The Hermes bundles botd serves (`hermes`) are read
/// again from disk: machines fetch them from botd itself.
pub async fn check(plan: &HarnessPlan, hermes: Option<&super::hermes_serve::Bundles>, login: Option<&Login>) -> Value {
    // Every redirect followed, so `reach` checks where the files really came from.
    let hops = Arc::new(Mutex::new(Vec::<String>::new()));
    let seen = hops.clone();
    let follow = reqwest::redirect::Policy::custom(move |a| {
        seen.lock().unwrap().push(a.url().to_string());
        if a.previous().len() >= 10 { a.error("too many redirects") } else { a.follow() }
    });
    let http = match tools::download_builder(None, plan.ca.as_deref()).and_then(|b| b.redirect(follow).build().map_err(|e| e.to_string())) {
        Ok(h) => h,
        Err(e) => return json!({ "ok": false, "error": format!("the mirrors' CA: {e}"), "items": [] }),
    };
    let registry = plan.npm_registry.as_deref().unwrap_or(NPM_REGISTRY);
    if plan.npm_login && login.is_none() {
        return json!({ "ok": false, "error": "the plan's registry needs a login, and botd has none (MACHINE_NPM_TOKEN)", "items": [] });
    }
    let http = Fetch { http, registry, login: login.filter(|_| plan.npm_login) };
    let item = |mut v: Value, res: Result<(), String>| {
        v["ok"] = json!(res.is_ok());
        if let Err(e) = res {
            v["error"] = json!(e);
        }
        v
    };
    let mut items = Vec::new();
    if let Some(n) = &plan.node {
        for (arch, d) in &n.downloads {
            let res = digests(&http, &d.url, MAX_FILE).await.and_then(|(got, _)| {
                if got == d.sha256 { Ok(()) } else { Err(format!("it has SHA-256 {got}, not the pinned {}", d.sha256)) }
            });
            items.push(item(json!({ "name": "node", "version": n.version, "arch": arch, "url": d.url }), res));
        }
    }
    for h in &plan.harnesses {
        match &h.source {
            InstallSource::Npm { package, integrity } => {
                let (url, res) = npm(&http, package, &h.version, integrity.as_deref()).await;
                items.push(item(json!({ "name": h.name, "version": h.version, "package": package, "url": url }), res));
            }
            InstallSource::Script { url, sha256, .. } => {
                let res = digests(&http, url, MAX_FILE).await.and_then(|(got, _)| {
                    if got == *sha256 { Ok(()) } else { Err(format!("it has SHA-256 {got}, not the pinned {sha256}")) }
                });
                let mut v = item(json!({ "name": h.name, "version": h.version, "url": url }), res);
                v["note"] = json!("Its installer then downloads from GitHub and PyPI, which no mirror setting covers.");
                items.push(v);
            }
            InstallSource::Bundle { downloads, .. } => {
                for (arch, d) in downloads {
                    let res = match hermes {
                        Some(b) => b.recheck(arch, &d.sha256).await,
                        None => Err("botd serves no Hermes bundles (MACHINE_HERMES_BUNDLE)".into()),
                    };
                    let mut v = item(json!({ "name": h.name, "version": h.version, "arch": arch, "url": d.url }), res);
                    v["note"] = json!("Served by botd from MACHINE_HERMES_BUNDLE, to enrolled machines over the machine port.");
                    items.push(v);
                }
            }
        }
    }
    let ok = items.iter().all(|i| i["ok"] == true);
    let mut redirects = hops.lock().unwrap().clone();
    redirects.sort();
    redirects.dedup();
    json!({ "ok": ok, "npmRegistry": registry, "npmLogin": http.login.map(Login::kind), "ca": plan.ca.is_some(), "items": items, "redirects": redirects })
}

/// The provider firewall's outbound rules for machines, when they bind root: the
/// addresses they drop, what is carved out of them, and how to open one more.
pub struct Outbound {
    pub deny: Vec<String>,
    pub open: Vec<(std::net::IpAddr, u16)>,
    pub fix: fn(std::net::SocketAddr) -> String,
}

impl Outbound {
    /// Incus containers' network ACL (ADR 0065), or Linode's outbound rules (ADR 0179).
    pub fn from_env(var: &dyn Fn(&str) -> String) -> Option<Outbound> {
        if var("MACHINE_PROVIDER").trim() == "incus" {
            let s = super::incus::Settings::from_env(var).ok()?;
            // As the fleet does: every container is also kept off every INCUS_HOSTS host.
            let mut deny = s.deny.clone();
            for (_, url) in var("INCUS_HOSTS").split(',').filter_map(|e| e.split_once('=')) {
                let url = url.trim().to_string();
                if let Ok(h) = super::incus::Settings::from_env(&|k| if k == "INCUS_URL" { url.clone() } else { var(k) }) {
                    deny.extend(h.deny);
                }
            }
            deny.sort();
            deny.dedup();
            return Some(Outbound {
                open: s.open(),
                deny,
                fix: |a| format!("Incus containers' firewall drops it: add {a} to INCUS_EGRESS_ALLOW."),
            });
        }
        if !super::firewall::egress_from_env(var).ok()? {
            return None;
        }
        Some(Outbound {
            deny: super::firewall::egress_deny(var).ok()?,
            open: super::firewall::control_from_env(var).into_iter().collect(),
            fix: |a| format!("Machines' provider firewall drops {a} (ADR 0179): put the mirror on an address it doesn't hold, or set MACHINE_FIREWALL_EGRESS=off."),
        })
    }
}

/// Where `check` fetched from that machines can't reach: the check runs on botd,
/// outside the machines' firewall, so a mirror on a private address passes here but
/// not there.
pub async fn reach(v: &mut Value, out: &Outbound) {
    let mut urls: Vec<String> = vec![v["npmRegistry"].as_str().unwrap_or(NPM_REGISTRY).to_string()];
    for i in v["items"].as_array().into_iter().flatten() {
        if i["note"].is_null()
            && let Some(u) = i["url"].as_str()
        {
            urls.push(u.to_string());
        }
    }
    urls.extend(v["redirects"].as_array().into_iter().flatten().filter_map(Value::as_str).map(String::from));
    let mut places: Vec<(String, u16)> = urls
        .iter()
        .filter_map(|u| url::Url::parse(u).ok())
        .filter_map(|u| Some((u.host_str()?.trim_matches(['[', ']']).to_string(), u.port_or_known_default()?)))
        .collect();
    places.sort();
    places.dedup();
    let mut blocked = Vec::new();
    for (host, port) in places {
        let Ok(addrs) = tokio::net::lookup_host((host.as_str(), port)).await else { continue };
        for a in addrs {
            if super::incus::drops(&out.deny, &out.open, a.ip(), port) {
                blocked.push(json!({
                    "host": host,
                    "address": a.to_string(),
                    "error": format!("Machines can't reach {host} at {a}. {}", (out.fix)(a)),
                }));
            }
        }
    }
    if !blocked.is_empty() {
        v["ok"] = json!(false);
    }
    v["blocked"] = json!(blocked);
}

/// `GET /api/machines/harness-mirror` (admins): `check` on the harness plan machines
/// get. Nothing is installed or changed.
pub async fn check_now(AppS(app): AppS<AppState>) -> Res<Json<Value>> {
    let cp = app.control_plane.get().ok_or_else(|| ApiError(StatusCode::SERVICE_UNAVAILABLE, super::NOT_CONFIGURED.into()))?;
    let e = super::enroll::need(cp)?;
    let plan = e
        .upkeep
        .plan
        .clone()
        .ok_or_else(|| ApiError(StatusCode::CONFLICT, "MACHINE_HARNESSES is none, so machines get no harnesses to check.".into()))?;
    let mut v = check(&plan, e.upkeep.hermes.as_ref(), e.upkeep.mirrors.as_ref().and_then(|m| m.login.as_ref())).await;
    if let Some(out) = Outbound::from_env(&|k| std::env::var(k).unwrap_or_default()) {
        reach(&mut v, &out).await;
    }
    v["mirrors"] = json!({
        "node": e.upkeep.mirrors.as_ref().and_then(|m| m.node.clone()),
        "npm": e.upkeep.mirrors.as_ref().and_then(|m| m.npm.clone()),
        "caFile": e.upkeep.mirrors.as_ref().and_then(|m| m.ca.as_ref().map(|(_, f)| f.clone())),
        "npmLogin": e.upkeep.mirrors.as_ref().and_then(|m| m.login.as_ref().map(Login::kind)),
    });
    Ok(Json(v))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::machines::standin_mirror::Mirror;
    use crate::secrets::env::EnvStore;

    fn env(pairs: &[(&str, String)]) -> impl Fn(&str) -> String {
        let pairs: Vec<(String, String)> = pairs.iter().map(|(k, v)| (k.to_string(), v.clone())).collect();
        move |k: &str| pairs.iter().find(|(key, _)| key == k).map(|(_, v)| v.clone()).unwrap_or_default()
    }

    fn from(pairs: &[(&str, String)]) -> Result<Option<Mirrors>, String> {
        Mirrors::from_env(&env(pairs), &EnvStore::fixed(&[]))
    }

    #[test]
    fn settings_are_checked_at_start() {
        assert_eq!(from(&[]).unwrap(), None, "off by default");
        let m = from(&[
            ("MACHINE_NODE_MIRROR", " https://mirror.corp.example/nodejs/dist/ ".into()),
            ("MACHINE_NPM_REGISTRY", "https://mirror.corp.example/api/npm/npm-remote".into()),
        ])
        .unwrap()
        .unwrap();
        assert_eq!(m.node.as_deref(), Some("https://mirror.corp.example/nodejs/dist"));
        assert_eq!(m.npm.as_deref(), Some("https://mirror.corp.example/api/npm/npm-remote/"), "npm's registry ends in /");
        assert!(m.ca.is_none());
        for (k, v) in [
            ("MACHINE_NODE_MIRROR", "http://mirror.corp.example/nodejs"),
            ("MACHINE_NODE_MIRROR", "mirror.corp.example"),
            ("MACHINE_NPM_REGISTRY", "https://user:secret@mirror.corp.example/npm/"),
            ("MACHINE_NPM_REGISTRY", "https://mirror.corp.example/npm/?token=x"),
            ("MACHINE_NPM_REGISTRY", "https://mirror.corp.example/npm/#x"),
        ] {
            assert!(from(&[(k, v.into())]).is_err(), "{k}={v}");
        }
        let alone = from(&[("MACHINE_MIRROR_CA_FILE", "/etc/ssl/corp.pem".into())]).unwrap_err();
        assert!(alone.contains("needs MACHINE_NODE_MIRROR"), "{alone}");

        let dir = crate::db::temp_path("mirror-ca");
        std::fs::create_dir_all(&dir).unwrap();
        let mirror = Mirror::ca_only();
        let good = dir.join("ca.pem");
        std::fs::write(&good, format!("{}\n{}", mirror.ca_pem(), Mirror::ca_only().ca_pem())).unwrap();
        let with = |file: &std::path::Path| from(&[("MACHINE_NPM_REGISTRY", "https://npm.corp.example".into()), ("MACHINE_MIRROR_CA_FILE", file.display().to_string())]);
        let m = with(&good).unwrap().unwrap();
        assert_eq!(m.ca.as_ref().map(|(_, f)| f.as_str()), Some(good.to_str().unwrap()));
        assert_eq!(tools::ca_bundle(&m.ca.unwrap().0), Ok(2), "a bundle of two CAs");
        for (name, body) in [
            ("empty.pem", String::new()),
            ("text.pem", "not a certificate\n".to_string()),
            ("key.pem", format!("{}\n-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n", mirror.ca_pem())),
            ("junk.pem", "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n".to_string()),
            ("big.pem", mirror.ca_pem().repeat(200)),
        ] {
            let f = dir.join(name);
            std::fs::write(&f, body).unwrap();
            assert!(with(&f).is_err(), "{name}");
        }
        assert!(with(&dir.join("missing.pem")).unwrap_err().contains("missing.pem"));
    }

    #[test]
    fn mirrors_change_where_the_plan_comes_from_never_its_pins() {
        let claude = crate::adapters::install::install("claude", None, None).unwrap();
        let hermes = crate::adapters::install::install("hermes", None, None).unwrap();
        let plan = crate::adapters::install::plan(vec![claude.clone(), hermes.clone()]);
        let m = Mirrors {
            node: Some("https://mirror.corp.example/nodejs".into()),
            npm: Some("https://npm.corp.example/".into()),
            ca: Some((Mirror::ca_only().ca_pem(), "/etc/ssl/corp.pem".into())),
            login: None,
        };
        let out = m.apply(plan.clone());
        let n = out.node.as_ref().unwrap();
        for (arch, name) in [("x86_64", "x64"), ("aarch64", "arm64")] {
            let d = &n.downloads[arch];
            assert_eq!(d.url, format!("https://mirror.corp.example/nodejs/v{0}/node-v{0}-linux-{name}.tar.xz", n.version));
            assert_eq!(d.sha256, plan.node.as_ref().unwrap().downloads[arch].sha256, "the same pin");
        }
        assert_eq!(out.harnesses, plan.harnesses, "the same harnesses and pins; Hermes's installer is not mirrored");
        assert_eq!(out.npm_registry.as_deref(), Some("https://npm.corp.example/"));
        assert!(out.ca.is_some() && needs_agent_support(&out));
        tools::check(&out).unwrap();
        assert_eq!(unmirrored(Some(&out)), ["hermes"]);
        assert!(m.describe(Some(&out)).contains("hermes still download"), "{}", m.describe(Some(&out)));

        let only_node = Mirrors { node: m.node.clone(), ..Default::default() };
        let out = only_node.apply(plan.clone());
        assert!(!needs_agent_support(&out), "agents from before ADR 0186 can fetch Node.js from a mirror");
        assert_eq!(serde_json::to_value(&out).unwrap().get("npmRegistry"), None);

        let hermes_only = crate::adapters::install::plan(vec![hermes]);
        assert_eq!(m.apply(hermes_only.clone()), hermes_only, "nothing to mirror, so the plan and its id stay");
        assert_eq!(plan.id(), crate::adapters::install::plan(vec![claude, crate::adapters::install::install("hermes", None, None).unwrap()]).id());
    }

    #[test]
    fn a_registry_login_comes_from_botds_secrets_and_is_checked_at_start() {
        let registry = ("MACHINE_NPM_REGISTRY", "https://npm.corp.example/api/npm/remote".to_string());
        let with = |vars: &[(&str, String)], secrets: &[(&str, &str)]| Mirrors::from_env(&env(vars), &EnvStore::fixed(secrets));
        assert_eq!(with(std::slice::from_ref(&registry), &[]).unwrap().unwrap().login, None, "none by default");

        let token = "eyJ2ZXIiOiIyIn0.cmVmdGtu-_~+/=:Zm9v";
        let m = with(std::slice::from_ref(&registry), &[("MACHINE_NPM_TOKEN", &format!(" {token}\n"))]).unwrap().unwrap();
        assert_eq!(m.login, Some(Login::Token(Zeroizing::new(token.into()))), "trimmed");
        assert_eq!(m.login.as_ref().unwrap().header(), format!("Bearer {token}"));
        assert_eq!(format!("{:?}", m.login), "Some(Login::Token(…))", "never printed");
        assert!(crate::secrets::redact::text(&format!("saw {token}")).contains(crate::secrets::redact::MARK), "redacted wherever botd writes it");
        let w = m.login.as_ref().unwrap().wire("https://npm.corp.example/api/npm/remote/");
        assert_eq!((w.token.as_deref(), w.auth.as_deref()), (Some(token), None));
        assert!(!format!("{w:?}").contains(token));

        // From a file, as a Docker or systemd secret.
        let dir = crate::db::temp_path("npm-login");
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("token");
        std::fs::write(&file, format!("{token}\n")).unwrap();
        let m = with(std::slice::from_ref(&registry), &[("MACHINE_NPM_TOKEN_FILE", file.to_str().unwrap())]).unwrap().unwrap();
        assert_eq!(m.login.unwrap().kind(), "token");

        // A user and password: npm's `_auth`.
        let user = ("MACHINE_NPM_USERNAME", "svc-superbot@corp.example".to_string());
        let m = with(&[registry.clone(), user.clone()], &[("MACHINE_NPM_PASSWORD", "p@ss word;#${HOME}")]).unwrap().unwrap();
        let auth = base64::engine::general_purpose::STANDARD.encode("svc-superbot@corp.example:p@ss word;#${HOME}");
        let login = m.login.unwrap();
        assert_eq!(login.header(), format!("Basic {auth}"));
        assert_eq!(login.wire("r").auth.as_deref(), Some(auth.as_str()), "base64, so nothing in the password reaches npm's config as it is");
        assert_eq!(format!("{login:?}"), "Login::Basic(svc-superbot@corp.example, …)");

        for (vars, secrets, why) in [
            (vec![], vec![("MACHINE_NPM_TOKEN", "abc")], "need MACHINE_NPM_REGISTRY"),
            (vec![registry.clone(), user.clone()], vec![("MACHINE_NPM_TOKEN", "abc"), ("MACHINE_NPM_PASSWORD", "x")], "not both"),
            (vec![registry.clone()], vec![("MACHINE_NPM_TOKEN", "abc"), ("MACHINE_NPM_PASSWORD", "x")], "not both"),
            (vec![registry.clone(), user.clone()], vec![], "needs MACHINE_NPM_PASSWORD"),
            (vec![registry.clone()], vec![("MACHINE_NPM_PASSWORD", "x")], "needs MACHINE_NPM_USERNAME"),
            (vec![registry.clone()], vec![("MACHINE_NPM_TOKEN", "a\nb")], "as registry tokens are"),
            (vec![registry.clone()], vec![("MACHINE_NPM_TOKEN", "abc;comment")], "as registry tokens are"),
            (vec![registry.clone()], vec![("MACHINE_NPM_TOKEN", "${NPM_TOKEN}")], "as registry tokens are"),
            (vec![registry.clone()], vec![("MACHINE_NPM_TOKEN", "a b")], "as registry tokens are"),
            (vec![registry.clone(), ("MACHINE_NPM_USERNAME", "a:b".into())], vec![("MACHINE_NPM_PASSWORD", "x")], "without :"),
            (vec![registry.clone(), user.clone()], vec![("MACHINE_NPM_PASSWORD", "a\nb")], "no control characters"),
            (vec![registry.clone(), user.clone()], vec![("MACHINE_NPM_PASSWORD", &"x".repeat(4000))], "over"),
        ] {
            let err = with(&vars, &secrets).unwrap_err();
            assert!(err.contains(why), "{vars:?} {:?}: {err}", secrets.iter().map(|(k, _)| k).collect::<Vec<_>>());
            assert!(!err.contains("a\nb") && !err.contains("abc"), "the value isn't in the error: {err}");
        }
        assert!(with(&[registry], &[("MACHINE_NPM_TOKEN", &"t".repeat(tools::MAX_LOGIN + 1))]).is_err());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_login_only_flags_the_plan_and_only_for_the_registry() {
        let claude = crate::adapters::install::install("claude", None, None).unwrap();
        let hermes = crate::adapters::install::install("hermes", None, None).unwrap();
        let plan = crate::adapters::install::plan(vec![claude.clone()]);
        let token = "s3cr3t-registry-token-0001";
        let m = Mirrors { npm: Some("https://npm.corp.example/".into()), login: Some(Login::Token(Zeroizing::new(token.into()))), ..Default::default() };
        let out = m.apply(plan.clone());
        assert!(out.npm_login && needs_agent_support(&out));
        let json = serde_json::to_string(&out).unwrap();
        assert!(json.contains("\"npmLogin\":true") && !json.contains(token), "the plan says a login is needed, never what it is: {json}");
        tools::check(&out).unwrap();
        assert!(m.describe(Some(&out)).contains("npm from https://npm.corp.example/ signing in with MACHINE_NPM_TOKEN"), "{}", m.describe(Some(&out)));
        let without = Mirrors { login: None, ..m.clone() }.apply(plan.clone());
        assert!(!without.npm_login && serde_json::to_value(&without).unwrap().get("npmLogin").is_none(), "left out, so the plan's id stays");
        assert_ne!(out.id(), without.id());
        let hermes_only = crate::adapters::install::plan(vec![hermes]);
        assert!(!m.apply(hermes_only).npm_login, "no npm harness, no registry, no login");
        assert!(tools::check(&HarnessPlan { npm_registry: None, ..out }).unwrap_err().contains("names none"));

        assert!(under_registry("https://npm.corp.example/@corp%2fx", "https://npm.corp.example/"));
        assert!(under_registry("http://npm.corp.example/x/-/x-1.0.0.tgz", "https://npm.corp.example/"), "npm matches without the scheme");
        let r = "https://mirror.corp.example:8443/api/npm/remote/";
        assert!(under_registry("https://mirror.corp.example:8443/api/npm/remote/x/-/x-1.tgz", r));
        for url in [
            "https://mirror.corp.example:8443/api/npm/remote2/x",
            "https://mirror.corp.example:8443/api/generic/node/v24/node.tar.xz",
            "https://mirror.corp.example/api/npm/remote/x",
            "https://storage.corp.example/api/npm/remote/x",
            "not a url",
        ] {
            assert!(!under_registry(url, r), "{url}");
        }
    }

    #[tokio::test]
    async fn the_check_signs_in_to_the_registry_as_machines_would_and_nowhere_else() {
        let mirror = Mirror::serve().await;
        let node = mirror.node("0.0.1", b"a node tarball");
        let pin = mirror.package("@corp/fake-claude", "9.9.9", b"claude's tarball");
        mirror.package("fake-codex", "1.0.0", b"codex's tarball");
        mirror.redirect_to_other("/npm/fake-codex/-/fake-codex-1.0.0.tgz");
        let token = Login::Token(Zeroizing::new("stand-in-token-7c1e".into()));
        mirror.require(&token.header());
        let plan = mirror.plan(&node, vec![("claude", "@corp/fake-claude", "9.9.9", Some(pin)), ("codex", "fake-codex", "1.0.0", None)]);
        assert!(plan.npm_login);

        let v = check(&plan, None, Some(&token)).await;
        assert_eq!(v["ok"], true, "{v}");
        assert_eq!(v["npmLogin"], "token", "{v}");
        let authorized = mirror.authorized();
        assert!(authorized.iter().any(|p| p == "/npm/@corp%2ffake-claude") && authorized.iter().any(|p| p == "/npm/@corp/fake-claude/-/fake-claude-9.9.9.tgz"), "{authorized:?}");
        assert!(authorized.iter().all(|p| p.starts_with("/npm/")), "not to Node.js's mirror, nor to the storage a redirect sends it to: {authorized:?}");
        assert!(mirror.calls().iter().any(|p| p.starts_with("/stored/")), "{:?}", mirror.calls());

        // No login where the plan wants one, a login the registry refuses, and one the
        // plan doesn't ask for (not sent).
        let v = check(&plan, None, None).await;
        assert_eq!(v["ok"], false);
        assert!(v["error"].as_str().unwrap().contains("MACHINE_NPM_TOKEN"), "{v}");
        let wrong = Login::Basic { username: "svc".into(), auth: Zeroizing::new("c3ZjOm5vcGU=".into()) };
        let v = check(&plan, None, Some(&wrong)).await;
        assert_eq!(v["ok"], false);
        let err = v["items"][1]["error"].as_str().unwrap();
        assert!(err.contains("refused botd's login (401 Unauthorized)") && err.contains("MACHINE_NPM_USERNAME and MACHINE_NPM_PASSWORD"), "{err}");
        assert!(!v.to_string().contains("c3ZjOm5vcGU="), "{v}");
        let before = mirror.authorized().len();
        let v = check(&HarnessPlan { npm_login: false, ..plan.clone() }, None, Some(&token)).await;
        assert_eq!(v["ok"], false);
        assert_eq!(v["npmLogin"], Value::Null);
        assert!(v["items"][1]["error"].as_str().unwrap().contains("the registry wants a login (401 Unauthorized)"), "{v}");
        assert_eq!(mirror.authorized().len(), before, "a plan without a login sends none");
    }

    #[test]
    fn only_admins_check_the_mirrors() {
        let perm = crate::rbac::classify(&axum::http::Method::GET, "/api/machines/harness-mirror");
        assert!(matches!(perm, crate::rbac::Perm::Admin));
    }

    #[tokio::test]
    async fn the_check_fetches_everything_from_the_mirror_and_holds_it_to_the_pins() {
        let mirror = Mirror::serve().await;
        let node = mirror.node("0.0.1", b"a node tarball");
        let good = mirror.package("@corp/fake-claude", "9.9.9", b"claude's tarball");
        mirror.package("fake-codex", "1.0.0", b"codex's tarball");
        let plan = mirror.plan(&node, vec![("claude", "@corp/fake-claude", "9.9.9", Some(good.clone())), ("codex", "fake-codex", "1.0.0", None)]);

        let v = check(&plan, None, None).await;
        assert_eq!(v["ok"], true, "{v}");
        assert_eq!(v["items"].as_array().unwrap().len(), 3, "{v}");
        assert!(v["items"][1]["url"].as_str().unwrap().starts_with(&mirror.url), "{v}");
        let calls = mirror.calls();
        assert!(calls.iter().any(|c| c == "/npm/@corp%2ffake-claude"), "scoped packages are asked for as npm does: {calls:?}");

        // No CA: the mirror's certificate isn't trusted.
        let v = check(&HarnessPlan { ca: None, ..plan.clone() }, None, None).await;
        assert_eq!(v["ok"], false);
        assert!(v["items"][0]["error"].as_str().unwrap().contains("couldn't fetch"), "{v}");

        // A pin the registry doesn't list, a tarball that isn't what the registry lists,
        // a Node.js that isn't the pinned one, a version it doesn't have.
        mirror.replace_tarball("fake-codex", "1.0.0", b"something else");
        let wrong_pin = format!("sha512-{}", base64::engine::general_purpose::STANDARD.encode([1u8; 64]));
        let mut bad = mirror.plan(&node, vec![("claude", "@corp/fake-claude", "9.9.9", Some(wrong_pin)), ("codex", "fake-codex", "1.0.0", None), ("pi", "fake-codex", "2.0.0", None)]);
        bad.node.as_mut().unwrap().downloads.values_mut().for_each(|d| d.sha256 = "b".repeat(64));
        let v = check(&bad, None, None).await;
        assert_eq!(v["ok"], false);
        let errors: Vec<&str> = v["items"].as_array().unwrap().iter().map(|i| i["error"].as_str().unwrap_or("")).collect();
        assert!(errors[0].contains("not the pinned"), "{errors:?}");
        assert!(errors[1].contains("not the pinned"), "{errors:?}");
        assert!(errors[2].contains("not the listed"), "{errors:?}");
        assert!(errors[3].contains("has no fake-codex@2.0.0"), "{errors:?}");
    }

    #[tokio::test]
    async fn the_check_says_when_machines_firewall_drops_the_mirror() {
        let mirror = Mirror::serve().await;
        let node = mirror.node("0.0.1", b"a node tarball");
        let pin = mirror.package("fake-codex", "1.0.0", b"codex's tarball");
        let plan = mirror.plan(&node, vec![("codex", "fake-codex", "1.0.0", Some(pin))]);
        let at = url::Url::parse(&mirror.url).unwrap();
        let here = format!("{}:{}", at.host_str().unwrap(), at.port().unwrap());
        let incus = |allow: &str| {
            Outbound::from_env(&env(&[
                ("MACHINE_PROVIDER", "incus".into()),
                ("INCUS_URL", "https://192.0.2.50".into()),
                ("INCUS_EGRESS_DENY", "127.0.0.0/8".into()),
                ("INCUS_EGRESS_ALLOW", allow.to_string()),
            ]))
            .unwrap()
        };

        let mut v = check(&plan, None, None).await;
        assert_eq!(v["ok"], true, "{v}");
        reach(&mut v, &incus("")).await;
        assert_eq!(v["ok"], false, "{v}");
        let blocked = v["blocked"].as_array().unwrap();
        assert_eq!(blocked.len(), 1, "one place, however many files: {v}");
        assert!(blocked[0]["error"].as_str().unwrap().contains(&format!("add {here} to INCUS_EGRESS_ALLOW")), "{v}");

        let mut v = check(&plan, None, None).await;
        reach(&mut v, &incus(&here)).await;
        assert_eq!(v["ok"], true, "{v}");
        assert_eq!(v["blocked"], json!([]));

        // Linode's outbound rules (ADR 0179), with loopback in MACHINE_EGRESS_DENY.
        let linode = |egress: &str| {
            Outbound::from_env(&env(&[
                ("MACHINE_FIREWALL", "on".into()),
                ("MACHINE_CONTROL_URL", "https://192.0.2.1:8444".into()),
                ("MACHINE_EGRESS_DENY", "127.0.0.0/8".into()),
                ("MACHINE_FIREWALL_EGRESS", egress.to_string()),
            ]))
        };
        let mut v = check(&plan, None, None).await;
        reach(&mut v, &linode("").unwrap()).await;
        assert_eq!(v["ok"], false, "{v}");
        assert!(v["blocked"][0]["error"].as_str().unwrap().contains("MACHINE_FIREWALL_EGRESS=off"), "{v}");
        assert!(linode("off").is_none(), "no outbound rules, nothing to check");
        assert!(Outbound::from_env(&env(&[])).is_none());

        // Another Incus host on the mirror's address: containers are kept off it too.
        let fleet = Outbound::from_env(&env(&[
            ("MACHINE_PROVIDER", "incus".into()),
            ("INCUS_URL", "https://192.0.2.50".into()),
            ("INCUS_HOSTS", "b=https://127.0.0.1:8443".into()),
        ]))
        .unwrap();
        let mut v = check(&plan, None, None).await;
        reach(&mut v, &fleet).await;
        assert_eq!(v["blocked"].as_array().unwrap().len(), 1, "{v}");
    }

    #[tokio::test]
    async fn the_check_follows_redirects_and_checks_where_they_go() {
        let mirror = Mirror::serve().await;
        let node = mirror.node("0.0.1", b"a node tarball");
        let pin = mirror.package("fake-codex", "1.0.0", b"codex's tarball");
        mirror.redirect_to_other("/npm/fake-codex/-/fake-codex-1.0.0.tgz");
        let plan = mirror.plan(&node, vec![("codex", "fake-codex", "1.0.0", Some(pin))]);
        let at = url::Url::parse(&mirror.url).unwrap();
        let here = format!("{}:{}", at.host_str().unwrap(), at.port().unwrap());
        let other = url::Url::parse(&mirror.other).unwrap();
        let there = format!("{}:{}", other.host_str().unwrap(), other.port().unwrap());

        let mut v = check(&plan, None, None).await;
        assert_eq!(v["ok"], true, "the redirected tarball is still the pinned one: {v}");
        assert_eq!(v["redirects"], json!([format!("{}/stored/npm/fake-codex/-/fake-codex-1.0.0.tgz", mirror.other)]));
        let incus = Outbound::from_env(&env(&[
            ("MACHINE_PROVIDER", "incus".into()),
            ("INCUS_URL", "https://192.0.2.50".into()),
            ("INCUS_EGRESS_DENY", "127.0.0.0/8".into()),
            ("INCUS_EGRESS_ALLOW", here),
        ]))
        .unwrap();
        reach(&mut v, &incus).await;
        assert_eq!(v["ok"], false, "{v}");
        let blocked = v["blocked"].as_array().unwrap();
        assert_eq!(blocked.len(), 1, "{v}");
        assert_eq!(blocked[0]["address"], json!(there), "{v}");
    }
}
