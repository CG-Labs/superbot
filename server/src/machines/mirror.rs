//! Harness CLIs on users' machines from mirrors inside the operator's network
//! (ADR 0186). botd's plan names nodejs.org and npm's registry; with
//! MACHINE_NODE_MIRROR and MACHINE_NPM_REGISTRY it names the operator's copies instead,
//! and MACHINE_MIRROR_CA_FILE the CA they're signed by. The pins don't change: Node.js
//! is checked against its pinned SHA-256 and each npm harness against its pinned
//! SHA-512 wherever it comes from, so a mirror can serve them but not change them.
//! `GET /api/machines/harness-mirror` fetches everything the plan names from where
//! machines would, and checks each against its pin, before any machine needs it.

use super::tools::{self, MAX_CA};
use super::wire::{HarnessPlan, InstallSource};
use crate::{ApiError, AppState, Res};
use axum::Json;
use axum::extract::State as AppS;
use axum::http::StatusCode;
use base64::Engine;
use serde_json::{Value, json};
use sha2::{Digest, Sha256, Sha512};

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
    pub fn from_env(var: &dyn Fn(&str) -> String) -> Result<Option<Mirrors>, String> {
        let node = base("MACHINE_NODE_MIRROR", &var("MACHINE_NODE_MIRROR"))?;
        let npm = base("MACHINE_NPM_REGISTRY", &var("MACHINE_NPM_REGISTRY"))?.map(|u| format!("{u}/"));
        let file = var("MACHINE_MIRROR_CA_FILE").trim().to_string();
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
        Ok(Some(Mirrors { node, npm, ca }))
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
        if let Some((_, file)) = &self.ca {
            s.push_str(&format!(", their CA from {file}"));
        }
        let unmirrored = unmirrored(plan);
        if !unmirrored.is_empty() {
            s.push_str(&format!(
                "; {} still download from the internet (Hermes Agent's installer reaches GitHub and PyPI): leave them out of MACHINE_HARNESSES on a network without it",
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

/// `url`'s SHA-256 (hex) and SHA-512 (npm's `sha512-<base64>`), read up to `max` bytes.
async fn digests(http: &reqwest::Client, url: &str, max: u64) -> Result<(String, String), String> {
    let mut r = http
        .get(url)
        .send()
        .await
        .and_then(reqwest::Response::error_for_status)
        .map_err(|e| format!("couldn't fetch {url}: {}", error_chain(&e.without_url())))?;
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
async fn listed(http: &reqwest::Client, registry: &str, package: &str, version: &str) -> Result<(String, Option<String>), String> {
    let url = format!("{registry}{}", package.replace('/', "%2f"));
    let mut r = http
        .get(&url)
        .header("accept", "application/vnd.npm.install-v1+json; q=1.0, application/json; q=0.8")
        .send()
        .await
        .and_then(reqwest::Response::error_for_status)
        .map_err(|e| format!("couldn't fetch {url}: {}", error_chain(&e.without_url())))?;
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
async fn npm(http: &reqwest::Client, registry: &str, package: &str, version: &str, pin: Option<&str>) -> (Option<String>, Result<(), String>) {
    let (tarball, integrity) = match listed(http, registry, package, version).await {
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
/// trust, and checks each against its pin.
pub async fn check(plan: &HarnessPlan) -> Value {
    let http = match tools::download_client(None, plan.ca.as_deref()) {
        Ok(h) => h,
        Err(e) => return json!({ "ok": false, "error": format!("the mirrors' CA: {e}"), "items": [] }),
    };
    let registry = plan.npm_registry.as_deref().unwrap_or(NPM_REGISTRY);
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
                let (url, res) = npm(&http, registry, package, &h.version, integrity.as_deref()).await;
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
        }
    }
    let ok = items.iter().all(|i| i["ok"] == true);
    json!({ "ok": ok, "npmRegistry": registry, "ca": plan.ca.is_some(), "items": items })
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
    let mut v = check(&plan).await;
    v["mirrors"] = json!({
        "node": e.upkeep.mirrors.as_ref().and_then(|m| m.node.clone()),
        "npm": e.upkeep.mirrors.as_ref().and_then(|m| m.npm.clone()),
        "caFile": e.upkeep.mirrors.as_ref().and_then(|m| m.ca.as_ref().map(|(_, f)| f.clone())),
    });
    Ok(Json(v))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::machines::standin_mirror::Mirror;

    fn env(pairs: &[(&str, String)]) -> impl Fn(&str) -> String {
        let pairs: Vec<(String, String)> = pairs.iter().map(|(k, v)| (k.to_string(), v.clone())).collect();
        move |k: &str| pairs.iter().find(|(key, _)| key == k).map(|(_, v)| v.clone()).unwrap_or_default()
    }

    #[test]
    fn settings_are_checked_at_start() {
        assert_eq!(Mirrors::from_env(&env(&[])).unwrap(), None, "off by default");
        let m = Mirrors::from_env(&env(&[
            ("MACHINE_NODE_MIRROR", " https://mirror.corp.example/nodejs/dist/ ".into()),
            ("MACHINE_NPM_REGISTRY", "https://mirror.corp.example/api/npm/npm-remote".into()),
        ]))
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
            assert!(Mirrors::from_env(&env(&[(k, v.into())])).is_err(), "{k}={v}");
        }
        let alone = Mirrors::from_env(&env(&[("MACHINE_MIRROR_CA_FILE", "/etc/ssl/corp.pem".into())])).unwrap_err();
        assert!(alone.contains("needs MACHINE_NODE_MIRROR"), "{alone}");

        let dir = crate::db::temp_path("mirror-ca");
        std::fs::create_dir_all(&dir).unwrap();
        let mirror = Mirror::ca_only();
        let good = dir.join("ca.pem");
        std::fs::write(&good, format!("{}\n{}", mirror.ca_pem(), Mirror::ca_only().ca_pem())).unwrap();
        let with = |file: &std::path::Path| Mirrors::from_env(&env(&[("MACHINE_NPM_REGISTRY", "https://npm.corp.example".into()), ("MACHINE_MIRROR_CA_FILE", file.display().to_string())]));
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

        let only_node = Mirrors { node: m.node.clone(), npm: None, ca: None };
        let out = only_node.apply(plan.clone());
        assert!(!needs_agent_support(&out), "agents from before ADR 0186 can fetch Node.js from a mirror");
        assert_eq!(serde_json::to_value(&out).unwrap().get("npmRegistry"), None);

        let hermes_only = crate::adapters::install::plan(vec![hermes]);
        assert_eq!(m.apply(hermes_only.clone()), hermes_only, "nothing to mirror, so the plan and its id stay");
        assert_eq!(plan.id(), crate::adapters::install::plan(vec![claude, crate::adapters::install::install("hermes", None, None).unwrap()]).id());
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

        let v = check(&plan).await;
        assert_eq!(v["ok"], true, "{v}");
        assert_eq!(v["items"].as_array().unwrap().len(), 3, "{v}");
        assert!(v["items"][1]["url"].as_str().unwrap().starts_with(&mirror.url), "{v}");
        let calls = mirror.calls();
        assert!(calls.iter().any(|c| c == "/npm/@corp%2ffake-claude"), "scoped packages are asked for as npm does: {calls:?}");

        // No CA: the mirror's certificate isn't trusted.
        let v = check(&HarnessPlan { ca: None, ..plan.clone() }).await;
        assert_eq!(v["ok"], false);
        assert!(v["items"][0]["error"].as_str().unwrap().contains("couldn't fetch"), "{v}");

        // A pin the registry doesn't list, a tarball that isn't what the registry lists,
        // a Node.js that isn't the pinned one, a version it doesn't have.
        mirror.replace_tarball("fake-codex", "1.0.0", b"something else");
        let wrong_pin = format!("sha512-{}", base64::engine::general_purpose::STANDARD.encode([1u8; 64]));
        let mut bad = mirror.plan(&node, vec![("claude", "@corp/fake-claude", "9.9.9", Some(wrong_pin)), ("codex", "fake-codex", "1.0.0", None), ("pi", "fake-codex", "2.0.0", None)]);
        bad.node.as_mut().unwrap().downloads.values_mut().for_each(|d| d.sha256 = "b".repeat(64));
        let v = check(&bad).await;
        assert_eq!(v["ok"], false);
        let errors: Vec<&str> = v["items"].as_array().unwrap().iter().map(|i| i["error"].as_str().unwrap_or("")).collect();
        assert!(errors[0].contains("not the pinned"), "{errors:?}");
        assert!(errors[1].contains("not the pinned"), "{errors:?}");
        assert!(errors[2].contains("not the listed"), "{errors:?}");
        assert!(errors[3].contains("has no fake-codex@2.0.0"), "{errors:?}");
    }
}
