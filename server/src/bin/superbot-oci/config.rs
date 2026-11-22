//! Registry logins, CAs and plain-HTTP registries, read from where skopeo (containers/image) and
//! Docker keep them, so an operator who can `skopeo copy` to their registry needs nothing new:
//! - logins: `$REGISTRY_AUTH_FILE`, `$XDG_RUNTIME_DIR/containers/auth.json`,
//!   `~/.config/containers/auth.json`, `~/.docker/config.json` (`auths`, `credHelpers`, `credsStore`);
//! - CAs: `*.crt` in `/etc/containers/certs.d/HOST[:PORT]/`, `~/.config/containers/certs.d/...`
//!   and `/etc/docker/certs.d/...`, on top of the system's;
//! - plain HTTP: `insecure = true` for the registry in `registries.conf` or its `.d` folders.

use base64::Engine;
use serde_json::Value;
use std::path::PathBuf;

#[derive(Clone, Debug, Default)]
pub struct Settings {
    pub auth_files: Vec<PathBuf>,
    pub cert_dirs: Vec<PathBuf>,
    pub registries_confs: Vec<PathBuf>,
}

pub type Credentials = (String, String);
/// Runs a credential helper (its name, the server) for a login.
pub type Helper<'a> = &'a dyn Fn(&str, &str) -> Result<Option<Credentials>, String>;

fn env(k: &str) -> Option<String> {
    std::env::var(k).ok().filter(|v| !v.is_empty())
}

/// FILE, then FILE.d/*.conf in name order.
fn conf_and_dropins(file: PathBuf) -> Vec<PathBuf> {
    let mut d = file.clone().into_os_string();
    d.push(".d");
    let mut dropins: Vec<PathBuf> = std::fs::read_dir(PathBuf::from(d))
        .map(|r| r.filter_map(Result::ok).map(|e| e.path()).filter(|p| p.extension().is_some_and(|e| e == "conf")).collect())
        .unwrap_or_default();
    dropins.sort();
    std::iter::once(file).chain(dropins).collect()
}

impl Settings {
    pub fn from_env() -> Settings {
        let home = env("HOME").map(PathBuf::from);
        let config = env("XDG_CONFIG_HOME").map(PathBuf::from).or_else(|| home.as_ref().map(|h| h.join(".config")));
        let mut auth_files = Vec::new();
        auth_files.extend(env("REGISTRY_AUTH_FILE").map(PathBuf::from));
        auth_files.extend(env("XDG_RUNTIME_DIR").map(|d| PathBuf::from(d).join("containers/auth.json")));
        auth_files.extend(config.as_ref().map(|c| c.join("containers/auth.json")));
        auth_files.extend(env("DOCKER_CONFIG").map(|d| PathBuf::from(d).join("config.json")).or_else(|| home.as_ref().map(|h| h.join(".docker/config.json"))));
        let mut cert_dirs = vec![PathBuf::from("/etc/containers/certs.d")];
        cert_dirs.extend(config.as_ref().map(|c| c.join("containers/certs.d")));
        cert_dirs.push(PathBuf::from("/etc/docker/certs.d"));
        let mut registries_confs = conf_and_dropins(env("CONTAINERS_REGISTRIES_CONF").map_or_else(|| PathBuf::from("/etc/containers/registries.conf"), PathBuf::from));
        registries_confs.extend(config.map(|c| conf_and_dropins(c.join("containers/registries.conf"))).unwrap_or_default());
        Settings { auth_files, cert_dirs, registries_confs }
    }

    /// The login for HOST (with its port) and repository PATH: the first file that has one.
    pub fn credentials(&self, host: &str, path: &str) -> Result<Option<Credentials>, String> {
        for f in &self.auth_files {
            let Ok(text) = std::fs::read_to_string(f) else { continue };
            let json: Value = serde_json::from_str(&text).map_err(|e| format!("{}: {e}", f.display()))?;
            if let Some(c) = credentials_in(&json, host, path, &|helper, server| run_helper(helper, server)).map_err(|e| format!("{}: {e}", f.display()))? {
                return Ok(Some(c));
            }
        }
        Ok(None)
    }

    /// PEM CA certificates for HOST (with its port), from every certs.d folder.
    pub fn ca_pems(&self, host: &str) -> Vec<(PathBuf, Vec<u8>)> {
        let mut out = Vec::new();
        for d in &self.cert_dirs {
            let Ok(rd) = std::fs::read_dir(d.join(host)) else { continue };
            let mut files: Vec<PathBuf> = rd.filter_map(Result::ok).map(|e| e.path()).filter(|p| p.extension().is_some_and(|e| e == "crt")).collect();
            files.sort();
            out.extend(files.into_iter().filter_map(|p| std::fs::read(&p).ok().map(|b| (p, b))));
        }
        out
    }

    /// Whether registries.conf lets HOST/PATH be reached over plain HTTP.
    pub fn insecure(&self, host: &str, path: &str) -> bool {
        self.registries_confs.iter().filter_map(|f| std::fs::read_to_string(f).ok()).any(|t| insecure_in(&t, host, path))
    }
}

/// Docker Hub's names for itself in auth files and credential helpers.
fn hub(host: &str) -> bool {
    matches!(host, "docker.io" | "index.docker.io" | "registry-1.docker.io")
}

/// An auth file key without its scheme and `/v1/`-style suffix: `https://index.docker.io/v1/`
/// is `docker.io`.
fn auth_key(k: &str) -> String {
    let k = k.strip_prefix("https://").or_else(|| k.strip_prefix("http://")).unwrap_or(k);
    let k = k.trim_end_matches('/');
    let k = k.strip_suffix("/v1").or_else(|| k.strip_suffix("/v2")).unwrap_or(k);
    if hub(k.split('/').next().unwrap_or(k)) {
        let rest = k.split_once('/').map(|(_, r)| r);
        return rest.map_or_else(|| "docker.io".into(), |r| format!("docker.io/{r}"));
    }
    k.to_string()
}

/// The login an auth file (Docker's config.json or containers' auth.json) has for HOST/PATH:
/// its credential helper for HOST, else the `auths` entry with the longest matching key
/// (`host`, or `host/namespace`), else its `credsStore`.
pub fn credentials_in(json: &Value, host: &str, path: &str, helper: Helper) -> Result<Option<Credentials>, String> {
    let host = if hub(host) { "docker.io" } else { host };
    let server = if host == "docker.io" { "https://index.docker.io/v1/" } else { host };
    if let Some(h) = json["credHelpers"].as_object().and_then(|m| m.iter().find(|(k, _)| auth_key(k) == host)).and_then(|(_, v)| v.as_str()) {
        return helper(h, server);
    }
    let full = format!("{host}/{path}");
    let best = json["auths"].as_object().and_then(|m| {
        m.iter()
            .map(|(k, v)| (auth_key(k), v))
            .filter(|(k, _)| *k == host || full == *k || full.starts_with(&format!("{k}/")))
            .max_by_key(|(k, _)| k.len())
            .map(|(_, v)| v)
    });
    if let Some(entry) = best {
        if let Some(a) = entry["auth"].as_str().filter(|a| !a.is_empty()) {
            let raw = base64::engine::general_purpose::STANDARD.decode(a.trim()).map_err(|_| format!("the login for {host} isn't base64"))?;
            let pair = String::from_utf8(raw).map_err(|_| format!("the login for {host} isn't text"))?;
            let (u, p) = pair.split_once(':').ok_or(format!("the login for {host} isn't user:password"))?;
            return Ok(Some((u.to_string(), p.to_string())));
        }
        if let (Some(u), Some(p)) = (entry["username"].as_str(), entry["password"].as_str()) {
            return Ok(Some((u.to_string(), p.to_string())));
        }
    }
    match json["credsStore"].as_str().filter(|s| !s.is_empty()) {
        Some(store) => helper(store, server),
        None => Ok(None),
    }
}

/// `docker-credential-<helper> get`, as Docker and skopeo run it.
fn run_helper(helper: &str, server: &str) -> Result<Option<Credentials>, String> {
    use std::io::Write;
    if !helper.bytes().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_' | b'.')) {
        return Err(format!("credential helper \"{helper}\" isn't a plain name"));
    }
    let bin = format!("docker-credential-{helper}");
    let mut child = std::process::Command::new(&bin)
        .arg("get")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| format!("{bin}: {e}"))?;
    child.stdin.take().map(|mut i| i.write_all(server.as_bytes())).transpose().map_err(|e| format!("{bin}: {e}"))?;
    let out = child.wait_with_output().map_err(|e| format!("{bin}: {e}"))?;
    if !out.status.success() {
        let why = String::from_utf8_lossy(&out.stdout).to_string() + &String::from_utf8_lossy(&out.stderr);
        return if why.to_lowercase().contains("not found") { Ok(None) } else { Err(format!("{bin} get: {}", why.trim())) };
    }
    let v: Value = serde_json::from_slice(&out.stdout).map_err(|e| format!("{bin} get: {e}"))?;
    match (v["Username"].as_str(), v["Secret"].as_str()) {
        (Some(u), Some(s)) if !s.is_empty() => Ok(Some((u.to_string(), s.to_string()))),
        _ => Ok(None),
    }
}

/// A TOML string or bool value, enough for registries.conf's keys.
fn toml_value(v: &str) -> &str {
    let v = v.trim();
    v.strip_prefix('"').and_then(|s| s.strip_suffix('"')).or_else(|| v.strip_prefix('\'').and_then(|s| s.strip_suffix('\''))).unwrap_or(v)
}

/// The text before a `#` that isn't inside quotes.
fn uncomment(line: &str) -> &str {
    let mut quote = None;
    for (i, c) in line.char_indices() {
        match (c, quote) {
            ('"' | '\'', None) => quote = Some(c),
            (q, Some(open)) if q == open => quote = None,
            ('#', None) => return &line[..i],
            _ => {}
        }
    }
    line
}

/// Whether a registries.conf pattern (`host[:port][/path]`, or `*.domain`) covers HOST/PATH.
fn covers(pattern: &str, host: &str, path: &str) -> bool {
    let full = format!("{host}/{path}");
    if let Some(domain) = pattern.strip_prefix("*.") {
        return host.split(':').next().is_some_and(|h| h.ends_with(&format!(".{domain}")));
    }
    pattern == host || pattern == full || full.starts_with(&format!("{pattern}/"))
}

/// Whether one registries.conf (version 2 `[[registry]]` tables, or version 1's
/// `[registries.insecure]` list) marks HOST/PATH insecure.
pub fn insecure_in(text: &str, host: &str, path: &str) -> bool {
    #[derive(Default)]
    struct Block {
        location: Option<String>,
        prefix: Option<String>,
        insecure: bool,
    }
    let mut blocks: Vec<Block> = Vec::new();
    let mut in_registry = false;
    let mut in_v1_insecure = false;
    let mut v1: Vec<String> = Vec::new();
    for raw in text.lines() {
        let line = uncomment(raw).trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with('[') {
            in_registry = line.replace(' ', "") == "[[registry]]";
            in_v1_insecure = line.replace(' ', "") == "[registries.insecure]";
            if in_registry {
                blocks.push(Block::default());
            }
            continue;
        }
        let Some((k, v)) = line.split_once('=') else { continue };
        let k = k.trim();
        if in_registry && let Some(b) = blocks.last_mut() {
            match k {
                "location" => b.location = Some(toml_value(v).to_string()),
                "prefix" => b.prefix = Some(toml_value(v).to_string()),
                "insecure" => b.insecure = toml_value(v) == "true",
                _ => {}
            }
        } else if in_v1_insecure && k == "registries" {
            let list = v.trim().trim_start_matches('[').trim_end_matches(']');
            v1.extend(list.split(',').map(toml_value).filter(|s| !s.is_empty()).map(String::from));
        }
    }
    blocks.iter().any(|b| b.insecure && b.prefix.as_ref().or(b.location.as_ref()).is_some_and(|p| covers(p, host, path))) || v1.iter().any(|p| covers(p, host, path))
}
