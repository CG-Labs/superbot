//! Harness CLIs on the machine (ADR 0039). botd sends a `HarnessPlan`; this installs
//! it under the tools folder, one harness at a time, and keeps what it did in a state
//! file, so a restart carries on where it stopped. It knows npm packages and installer
//! scripts, not harnesses: what to install comes from botd's adapters. Shared by the
//! agent binary and botd's tests, so it uses nothing of botd's but `wire`.
//!
//! Under the tools folder (`SUPERBOT_TOOLS`, default `<state dir>/tools`):
//! - `bin/`: what's on the harness PATH: `node`, `npm`, `npx` and each harness.
//! - `node-<version>/`: Node.js, from the plan's pinned, SHA-256-checked tarball.
//! - `lib/node_modules/`: npm harnesses (`npm install -g --prefix <tools>`).
//! - `scripts/<name>/`: HOME for a harness's own installer script.
//! - `state.json`: the plan, and what is installed.

// Shared by two binaries, each of which uses only part of it.
#![allow(dead_code)]

use super::wire::{self, HarnessInstall, HarnessPlan, HarnessStatus, InstallSource, NodeRuntime};
use base64::Engine;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};
use std::collections::BTreeMap;
use std::path::{Component, Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::AsyncWriteExt;

/// The largest download: Node.js is about 30 MiB.
const MAX_DOWNLOAD: u64 = 256 << 20;
/// The largest installer script.
const MAX_SCRIPT: u64 = 4 << 20;
/// How long one install step may take. Hermes's installer builds a Python env.
const STEP_TIMEOUT: Duration = Duration::from_secs(60 * 60);
const STATE_FILE: &str = "state.json";

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as i64)
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Saved {
    plan: Option<HarnessPlan>,
    /// The Node.js version in `node-<version>`, once installed.
    node: Option<String>,
    /// What is installed, by harness name.
    installed: BTreeMap<String, String>,
    status: BTreeMap<String, HarnessStatus>,
}

pub struct Tools {
    pub dir: PathBuf,
    saved: Mutex<Saved>,
    wake: tokio::sync::Notify,
    http: reqwest::Client,
    /// Jobs that may be using the tools, and whether an install is replacing some.
    gate: Mutex<Gate>,
    gate_open: tokio::sync::Notify,
}

#[derive(Default)]
struct Gate {
    jobs: usize,
    replacing: bool,
}

/// A job's hold on the tools: nothing it may be using is replaced until it is dropped.
pub struct JobPermit(Arc<Tools>);

impl Drop for JobPermit {
    fn drop(&mut self) {
        self.0.gate().jobs -= 1;
        self.0.gate_open.notify_waiters();
    }
}

/// An install's hold on the tools: no job starts until it is dropped.
struct Replacing<'a>(&'a Tools);

impl Drop for Replacing<'_> {
    fn drop(&mut self) {
        self.0.gate().replacing = false;
    }
}

/// A plain token: what versions and names may be.
fn token(s: &str, max: usize) -> bool {
    !s.is_empty()
        && s.len() <= max
        && s.bytes().all(|b| b.is_ascii_alphanumeric() || b"._+-".contains(&b))
        && s.starts_with(|c: char| c.is_ascii_alphanumeric())
}

fn hex64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

/// `sha512-` and 64 bytes of standard base64, as npm writes `integrity`.
fn sri(s: &str) -> bool {
    s.strip_prefix("sha512-").is_some_and(|b| {
        base64::engine::general_purpose::STANDARD
            .decode(b)
            .is_ok_and(|d| d.len() == 64)
    })
}

fn npm_name(s: &str) -> bool {
    let part = |p: &str| token(p, 214) && !p.contains('+') && p.bytes().all(|b| !b.is_ascii_uppercase());
    let ok = match s.strip_prefix('@').and_then(|r| r.split_once('/')) {
        Some((scope, name)) => part(scope) && part(name),
        None => !s.starts_with('@') && part(s),
    };
    ok && s.len() <= 214
}

fn https(url: &str) -> bool {
    url::Url::parse(url).is_ok_and(|u| {
        u.scheme() == "https"
            && u.host().is_some()
            && u.username().is_empty()
            && u.password().is_none()
    }) && url.len() <= 2048
}

/// A path under a folder: relative, with no `..`.
fn relative(p: &str) -> bool {
    !p.is_empty()
        && p.len() <= 256
        && Path::new(p)
            .components()
            .all(|c| matches!(c, Component::Normal(_)))
}

/// Why the agent won't take `plan`, if it won't.
pub fn check(plan: &HarnessPlan) -> Result<(), String> {
    let mut seen = Vec::new();
    let mut npm = false;
    for h in &plan.harnesses {
        if wire::harness_bin(&h.name).is_none() {
            return Err(format!("{} isn't a harness this machine runs.", h.name));
        }
        if seen.contains(&h.name) {
            return Err(format!("{} is in the plan twice.", h.name));
        }
        seen.push(h.name.clone());
        if !token(&h.version, 64) || h.version == "latest" {
            return Err(format!("{}: \"{}\" isn't an exact version.", h.name, h.version));
        }
        match &h.source {
            InstallSource::Npm { package, integrity } => {
                npm = true;
                if !npm_name(package) {
                    return Err(format!("{}: \"{package}\" isn't an npm package.", h.name));
                }
                if !h.version.starts_with(|c: char| c.is_ascii_digit()) {
                    return Err(format!("{}: \"{}\" isn't an exact version.", h.name, h.version));
                }
                if integrity.as_deref().is_some_and(|i| !sri(i)) {
                    return Err(format!("{}: the integrity isn't sha512-<base64>.", h.name));
                }
            }
            InstallSource::Script { url, sha256, args, bin } => {
                if !https(url) || !hex64(sha256) || !relative(bin) {
                    return Err(format!("{}: the installer needs an https URL, its SHA-256 and a relative bin.", h.name));
                }
                if args.len() > 32 || args.iter().any(|a| a.len() > 256 || a.contains('\0')) {
                    return Err(format!("{}: too many or too long installer arguments.", h.name));
                }
            }
        }
    }
    match &plan.node {
        None if npm => Err("npm harnesses need Node.js in the plan.".into()),
        None => Ok(()),
        Some(n) => {
            if !token(&n.version, 32) {
                return Err("Node.js: that isn't a version.".into());
            }
            match n.downloads.iter().find(|(arch, d)| !token(arch, 32) || !https(&d.url) || !hex64(&d.sha256)) {
                Some((arch, _)) => Err(format!("Node.js for {arch}: it needs an https URL and its SHA-256.")),
                None => Ok(()),
            }
        }
    }
}

/// An installed program: an executable file, with symlinks resolved.
fn runnable(p: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(p).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
}

/// `link` pointing at `target`, replaced in one rename.
fn symlink(target: &Path, link: &Path) -> Result<(), String> {
    let tmp = link.with_extension("link-tmp");
    let _ = std::fs::remove_file(&tmp);
    std::os::unix::fs::symlink(target, &tmp)
        .and_then(|()| std::fs::rename(&tmp, link))
        .map_err(|e| format!("{}: {e}", link.display()))
}

/// The end of a program's output, for an error message.
fn tail(b: &[u8]) -> String {
    let s = String::from_utf8_lossy(b);
    let s = s.trim();
    let start = s.char_indices().rev().nth(600).map_or(0, |(i, _)| i);
    s[start..].to_string()
}

impl Tools {
    /// `extra_root`: a CA trusted for downloads besides the system's (the control
    /// plane's, so botd could serve them too).
    pub fn new(dir: PathBuf, extra_root: Option<&str>) -> Result<Arc<Tools>, String> {
        std::fs::create_dir_all(dir.join("bin")).map_err(|e| format!("{}: {e}", dir.display()))?;
        let mut b = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(15))
            .read_timeout(Duration::from_secs(60));
        if let Some(pem) = extra_root {
            let c = reqwest::Certificate::from_pem(pem.as_bytes()).map_err(|e| e.to_string())?;
            b = b.tls_certs_merge([c]);
        }
        let saved = std::fs::read(dir.join(STATE_FILE))
            .ok()
            .and_then(|b| serde_json::from_slice::<Saved>(&b).ok())
            .unwrap_or_default();
        let t = Arc::new(Tools {
            dir,
            saved: Mutex::new(saved),
            wake: tokio::sync::Notify::new(),
            http: b.build().map_err(|e| e.to_string())?,
            gate: Mutex::default(),
            gate_open: tokio::sync::Notify::new(),
        });
        // An install a restart cut short starts again.
        {
            let mut s = t.lock();
            for st in s.status.values_mut() {
                if st.state == wire::HARNESS_INSTALLING {
                    st.state = wire::HARNESS_QUEUED.into();
                }
            }
        }
        Ok(t)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Saved> {
        self.saved.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn gate(&self) -> std::sync::MutexGuard<'_, Gate> {
        self.gate.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Lets a job start, unless an install is replacing harness files right now.
    pub fn job_permit(self: &Arc<Self>) -> Option<JobPermit> {
        let mut g = self.gate();
        if g.replacing {
            return None;
        }
        g.jobs += 1;
        Some(JobPermit(self.clone()))
    }

    /// Waits until no job is running, then keeps new ones from starting.
    async fn replacing(&self) -> Replacing<'_> {
        loop {
            let open = self.gate_open.notified();
            tokio::pin!(open);
            open.as_mut().enable();
            {
                let mut g = self.gate();
                if g.jobs == 0 {
                    g.replacing = true;
                    return Replacing(self);
                }
            }
            open.await;
        }
    }

    /// Whether installing `h` replaces files a running job may use: an installed
    /// harness, or the Node.js npm harnesses run on.
    fn replaces(&self, h: &HarnessInstall, node: Option<&NodeRuntime>) -> bool {
        let s = self.lock();
        let npm = matches!(h.source, InstallSource::Npm { .. });
        s.installed.contains_key(&h.name) || (npm && s.node.is_some() && node.is_some_and(|n| s.node.as_deref() != Some(&n.version)))
    }

    fn save(&self, s: &Saved) {
        let tmp = self.dir.join("state.json.tmp");
        if std::fs::write(&tmp, serde_json::to_vec_pretty(s).unwrap_or_default()).is_ok() {
            let _ = std::fs::rename(tmp, self.dir.join(STATE_FILE));
        }
    }

    pub fn bin_dir(&self) -> PathBuf {
        self.dir.join("bin")
    }

    /// The plan's id, and each harness's status, for the heartbeat.
    pub fn report(&self) -> (Option<String>, BTreeMap<String, HarnessStatus>) {
        let s = self.lock();
        (s.plan.as_ref().map(HarnessPlan::id), s.status.clone())
    }

    /// Takes `plan` as the one to install. A harness already at its version is left
    /// alone; one that failed is tried again, and npm harnesses are installed again
    /// on a new Node.js. Harnesses no longer planned stay installed, since a Bot may be
    /// using one.
    pub fn set_plan(&self, plan: HarnessPlan) -> Result<(), String> {
        check(&plan)?;
        let mut s = self.lock();
        let at = now_ms();
        let new_node = plan.node.as_ref().is_some_and(|n| s.node.as_deref() != Some(&n.version));
        let mut status = BTreeMap::new();
        for h in &plan.harnesses {
            let have = s.installed.get(&h.name).cloned();
            let old = s.status.get(&h.name);
            // Only the very same recipe carries on; a corrected one is installed again.
            let same = s.plan.as_ref().is_some_and(|p| p.harnesses.contains(h));
            let npm = matches!(h.source, InstallSource::Npm { .. });
            let st = if have.as_deref() == Some(&h.version) && !(npm && new_node) && runnable(&self.bin_dir().join(&h.name)) {
                HarnessStatus { version: have, wanted: Some(h.version.clone()), state: wire::HARNESS_INSTALLED.into(), error: None, at: old.map_or(at, |o| o.at) }
            } else if same && old.is_some_and(|o| o.state == wire::HARNESS_INSTALLING) {
                old.cloned().unwrap_or_default()
            } else {
                HarnessStatus { version: have, wanted: Some(h.version.clone()), state: wire::HARNESS_QUEUED.into(), error: None, at }
            };
            status.insert(h.name.clone(), st);
        }
        for (name, version) in &s.installed {
            status.entry(name.clone()).or_insert_with(|| HarnessStatus {
                version: Some(version.clone()),
                wanted: None,
                state: wire::HARNESS_INSTALLED.into(),
                error: None,
                at,
            });
        }
        s.status = status;
        s.plan = Some(plan);
        self.save(&s);
        drop(s);
        self.wake.notify_one();
        Ok(())
    }

    fn next(&self) -> Option<(HarnessInstall, Option<NodeRuntime>)> {
        let mut s = self.lock();
        let plan = s.plan.clone()?;
        let h = plan
            .harnesses
            .iter()
            .find(|h| s.status.get(&h.name).is_some_and(|st| st.state == wire::HARNESS_QUEUED))?
            .clone();
        if let Some(st) = s.status.get_mut(&h.name) {
            st.state = wire::HARNESS_INSTALLING.into();
            st.at = now_ms();
        }
        self.save(&s);
        Some((h, plan.node))
    }

    fn finish(&self, h: &HarnessInstall, res: Result<String, String>) {
        let mut s = self.lock();
        let at = now_ms();
        let still = s.plan.as_ref().is_some_and(|p| p.harnesses.contains(h));
        if let Ok(v) = &res {
            s.installed.insert(h.name.clone(), v.clone());
        }
        let version = s.installed.get(&h.name).cloned();
        let Some(st) = s.status.get_mut(&h.name) else { return };
        // A new plan for it came meanwhile: that one is queued already.
        if still && st.state == wire::HARNESS_INSTALLING {
            *st = match res {
                Ok(_) => HarnessStatus { version, wanted: Some(h.version.clone()), state: wire::HARNESS_INSTALLED.into(), error: None, at },
                Err(e) => HarnessStatus { version, wanted: Some(h.version.clone()), state: wire::HARNESS_FAILED.into(), error: Some(e), at },
            };
        } else {
            st.version = version;
        }
        self.save(&s);
    }

    /// Installs what's queued, one at a time, until stopped. Replacing what a job may
    /// be using waits for running jobs to end, and no job starts until it's done.
    pub async fn work(self: Arc<Self>) {
        loop {
            while let Some((h, node)) = self.next() {
                let _replacing = if self.replaces(&h, node.as_ref()) { Some(self.replacing().await) } else { None };
                let res = self.install(&h, node.as_ref()).await;
                if let Err(e) = &res {
                    eprintln!("Installing {} {}: {e}", h.name, h.version);
                } else {
                    println!("Installed {} {}.", h.name, h.version);
                }
                self.finish(&h, res);
            }
            self.wake.notified().await;
        }
    }

    async fn install(&self, h: &HarnessInstall, node: Option<&NodeRuntime>) -> Result<String, String> {
        let dl = self.dir.join(".dl");
        let _ = std::fs::remove_dir_all(&dl);
        std::fs::create_dir_all(&dl).map_err(|e| e.to_string())?;
        let res = match &h.source {
            InstallSource::Npm { package, integrity } => {
                self.node(node.ok_or("npm harnesses need Node.js")?).await?;
                self.npm(package, &h.version, integrity.as_deref()).await
            }
            InstallSource::Script { url, sha256, args, bin } => self.script(&h.name, url, sha256, args, bin).await,
        };
        let _ = std::fs::remove_dir_all(&dl);
        res.map(|()| h.version.clone())
    }

    /// Downloads `url` into `.dl`, checking its SHA-256 on the way. Nothing that fails
    /// the check is kept.
    async fn download(&self, url: &str, sha256: &str, max: u64) -> Result<PathBuf, String> {
        let file = self.dir.join(".dl").join(format!("download-{}", now_ms()));
        let res = async {
            let mut r = self
                .http
                .get(url)
                .send()
                .await
                .and_then(reqwest::Response::error_for_status)
                .map_err(|e| format!("couldn't download {url}: {}", e.without_url()))?;
            let mut out = tokio::fs::File::create(&file).await.map_err(|e| e.to_string())?;
            let (mut hash, mut n) = (Sha256::new(), 0u64);
            while let Some(chunk) = r.chunk().await.map_err(|e| format!("{url}: {}", e.without_url()))? {
                n += chunk.len() as u64;
                if n > max {
                    return Err(format!("{url} is over {} MiB", max >> 20));
                }
                hash.update(&chunk);
                out.write_all(&chunk).await.map_err(|e| e.to_string())?;
            }
            out.flush().await.map_err(|e| e.to_string())?;
            let got: String = hash.finalize().iter().map(|b| format!("{b:02x}")).collect();
            if got != sha256 {
                return Err(format!("{url} has SHA-256 {got}, not the pinned {sha256}"));
            }
            Ok(())
        }
        .await;
        match res {
            Ok(()) => Ok(file),
            Err(e) => {
                let _ = std::fs::remove_file(&file);
                Err(e)
            }
        }
    }

    /// Runs a program with only `env`, and returns its stdout.
    async fn run(&self, program: &str, args: &[&str], env: &[(&str, String)], cwd: &Path) -> Result<Vec<u8>, String> {
        let mut cmd = tokio::process::Command::new(program);
        cmd.args(args)
            .current_dir(cwd)
            .env_clear()
            .envs(env.iter().map(|(k, v)| (*k, v.as_str())))
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        let child = cmd.spawn().map_err(|e| format!("couldn't start {program}: {e}"))?;
        let out = tokio::time::timeout(STEP_TIMEOUT, child.wait_with_output())
            .await
            .map_err(|_| format!("{program} took over {} minutes", STEP_TIMEOUT.as_secs() / 60))?
            .map_err(|e| format!("{program}: {e}"))?;
        if !out.status.success() {
            let why = tail(&out.stderr);
            return Err(format!("{program} {} failed ({}): {why}", args.first().unwrap_or(&""), out.status));
        }
        Ok(out.stdout)
    }

    /// PATH for installers: the tools first, so npm finds this node.
    fn path(&self) -> String {
        format!("{}:/usr/local/bin:/usr/bin:/bin", self.bin_dir().display())
    }

    async fn node(&self, n: &NodeRuntime) -> Result<(), String> {
        let have = self.lock().node.clone();
        if have.as_deref() == Some(&n.version) && runnable(&self.bin_dir().join("node")) {
            return Ok(());
        }
        let arch = std::env::consts::ARCH;
        let d = n.downloads.get(arch).ok_or(format!("the plan has no Node.js for {arch}"))?;
        let file = self.download(&d.url, &d.sha256, MAX_DOWNLOAD).await?;
        let into = self.dir.join(".dl/node");
        std::fs::create_dir_all(&into).map_err(|e| e.to_string())?;
        let (f, i) = (file.display().to_string(), into.display().to_string());
        self.run("tar", &["-xJf", &f, "-C", &i, "--no-same-owner"], &[("PATH", "/usr/bin:/bin".into())], &self.dir)
            .await?;
        let top: Vec<PathBuf> = std::fs::read_dir(&into)
            .map_err(|e| e.to_string())?
            .filter_map(|e| e.ok().map(|e| e.path()))
            .collect();
        let [top] = top.as_slice() else {
            return Err("the Node.js tarball isn't one folder".into());
        };
        let name = format!("node-{}", n.version);
        let to = self.dir.join(&name);
        let _ = std::fs::remove_dir_all(&to);
        std::fs::rename(top, &to).map_err(|e| e.to_string())?;
        for b in ["node", "npm", "npx"] {
            if b == "node" && !runnable(&to.join("bin/node")) {
                return Err("the Node.js tarball has no bin/node".into());
            }
            if to.join("bin").join(b).exists() {
                symlink(&Path::new("..").join(&name).join("bin").join(b), &self.bin_dir().join(b))?;
            }
        }
        let mut s = self.lock();
        let old = s.node.replace(n.version.clone());
        self.save(&s);
        drop(s);
        if let Some(old) = old.filter(|o| *o != n.version) {
            let _ = std::fs::remove_dir_all(self.dir.join(format!("node-{old}")));
        }
        Ok(())
    }

    fn npm_env(&self) -> Vec<(&'static str, String)> {
        vec![
            ("PATH", self.path()),
            ("HOME", self.dir.display().to_string()),
            ("LANG", "C.UTF-8".into()),
            ("npm_config_cache", self.dir.join(".npm").display().to_string()),
            ("npm_config_update_notifier", "false".into()),
            ("npm_config_fund", "false".into()),
            ("npm_config_audit", "false".into()),
        ]
    }

    /// `npm pack`s the package, checks the tarball against the pinned SHA-512 (or, with
    /// none pinned, against what the registry says), then installs that tarball.
    async fn npm(&self, package: &str, version: &str, integrity: Option<&str>) -> Result<(), String> {
        let npm = self.bin_dir().join("npm").display().to_string();
        let (env, dl) = (self.npm_env(), self.dir.join(".dl"));
        let spec = format!("{package}@{version}");
        let out = self
            .run(&npm, &["pack", &spec, "--pack-destination", &dl.display().to_string(), "--json"], &env, &dl)
            .await?;
        #[derive(Deserialize)]
        struct Packed {
            filename: String,
            integrity: String,
        }
        let packed: Vec<Packed> = serde_json::from_slice(&out).map_err(|_| "npm pack's answer wasn't JSON".to_string())?;
        let [p] = packed.as_slice() else {
            return Err("npm pack made more or less than one tarball".into());
        };
        let name = Path::new(&p.filename).file_name().ok_or("npm pack named no file")?;
        let file = dl.join(name);
        let bytes = std::fs::read(&file).map_err(|e| format!("{}: {e}", file.display()))?;
        let got = format!("sha512-{}", base64::engine::general_purpose::STANDARD.encode(Sha512::digest(&bytes)));
        let want = integrity.unwrap_or(&p.integrity);
        if got != want {
            return Err(format!("{spec}'s tarball has {got}, not the pinned {want}"));
        }
        let f = file.display().to_string();
        let prefix = self.dir.display().to_string();
        self.run(&npm, &["install", "-g", "--prefix", &prefix, "--omit=dev", "--no-fund", "--no-audit", &f], &env, &dl)
            .await?;
        let manifest = self.dir.join("lib/node_modules").join(package).join("package.json");
        let installed = std::fs::read(&manifest)
            .ok()
            .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
            .and_then(|v| v["version"].as_str().map(String::from));
        if installed.as_deref() != Some(version) {
            return Err(format!("npm installed {}, not {version}", installed.unwrap_or_else(|| "nothing".into())));
        }
        Ok(())
    }

    async fn script(&self, name: &str, url: &str, sha256: &str, args: &[String], bin: &str) -> Result<(), String> {
        let file = self.download(url, sha256, MAX_SCRIPT).await?;
        let home = self.dir.join("scripts").join(name);
        std::fs::create_dir_all(&home).map_err(|e| e.to_string())?;
        let f = file.display().to_string();
        let mut argv: Vec<&str> = vec![&f];
        argv.extend(args.iter().map(String::as_str));
        let env = [("PATH", self.path()), ("HOME", home.display().to_string()), ("LANG", "C.UTF-8".into())];
        self.run("bash", &argv, &env, &home).await?;
        let target = home.join(bin);
        if !runnable(&target) {
            return Err(format!("the installer left no program at {bin}"));
        }
        symlink(&target, &self.bin_dir().join(name))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn npm(name: &str, package: &str, version: &str) -> HarnessInstall {
        HarnessInstall {
            name: name.into(),
            version: version.into(),
            source: InstallSource::Npm { package: package.into(), integrity: None },
        }
    }

    #[test]
    fn plans_are_checked_before_anything_runs() {
        let node = Some(NodeRuntime {
            version: "24.22.3".into(),
            downloads: BTreeMap::from([("x86_64".into(), wire::Download { url: "https://nodejs.org/n.tar.xz".into(), sha256: "a".repeat(64) })]),
        });
        let plan = |harnesses: Vec<HarnessInstall>, node: Option<NodeRuntime>| HarnessPlan { node, harnesses };
        assert!(check(&plan(vec![npm("claude", "@anthropic-ai/claude-code", "2.1.329")], node.clone())).is_ok());
        assert!(check(&plan(vec![], None)).is_ok());
        for (h, why) in [
            (npm("sh", "x", "1.0.0"), "not a harness"),
            (npm("claude", "@anthropic-ai/claude-code", "latest"), "a tag"),
            (npm("claude", "@anthropic-ai/claude-code", "^2.1.0"), "a range"),
            (npm("claude", "@anthropic-ai/claude-code", "v2"), "not a version"),
            (npm("claude", "../evil", "1.0.0"), "a path"),
            (npm("claude", "@Anthropic/claude", "1.0.0"), "upper case"),
            (npm("claude", "https://example.com/x.tgz", "1.0.0"), "a URL"),
        ] {
            assert!(check(&plan(vec![h], node.clone())).is_err(), "{why}");
        }
        let mut bad_sri = npm("codex", "@openai/codex", "0.171.0");
        bad_sri.source = InstallSource::Npm { package: "@openai/codex".into(), integrity: Some("sha1-abc".into()) };
        assert!(check(&plan(vec![bad_sri], node.clone())).is_err());
        assert!(check(&plan(vec![npm("pi", "p", "1.0.0")], None)).is_err(), "npm needs Node.js");
        assert!(
            check(&plan(vec![npm("pi", "p", "1.0.0"), npm("pi", "p", "1.0.1")], node.clone())).is_err(),
            "twice"
        );
        let script = |url: &str, sha: &str, bin: &str| HarnessInstall {
            name: "hermes".into(),
            version: "ae2a81cc".into(),
            source: InstallSource::Script { url: url.into(), sha256: sha.into(), args: vec![], bin: bin.into() },
        };
        let sha = "c".repeat(64);
        assert!(check(&plan(vec![script("https://example.com/i.sh", &sha, ".hermes/bin/hermes")], None)).is_ok());
        for (s, why) in [
            (script("http://example.com/i.sh", &sha, "bin/hermes"), "plain http"),
            (script("https://example.com/i.sh", "abc", "bin/hermes"), "no checksum"),
            (script("https://example.com/i.sh", &sha, "../bin/hermes"), "climbs out"),
            (script("https://example.com/i.sh", &sha, "/usr/bin/hermes"), "absolute"),
        ] {
            assert!(check(&plan(vec![s], None)).is_err(), "{why}");
        }
        let mut n = node.clone().unwrap();
        n.downloads.insert("aarch64".into(), wire::Download { url: "https://nodejs.org/n.tar.xz".into(), sha256: "short".into() });
        assert!(check(&plan(vec![], Some(n))).is_err());
    }

    #[test]
    fn a_recipe_corrected_mid_install_is_installed_again() {
        let dir = std::env::temp_dir().join(format!("superbot-tools-corrected-{}", now_ms()));
        let t = Tools::new(dir, None).unwrap();
        let node = NodeRuntime {
            version: "24.22.3".into(),
            downloads: BTreeMap::from([("x86_64".into(), wire::Download { url: "https://nodejs.org/n.tar.xz".into(), sha256: "a".repeat(64) })]),
        };
        let with = |integrity: Option<String>| HarnessPlan {
            node: Some(node.clone()),
            harnesses: vec![HarnessInstall {
                source: InstallSource::Npm { package: "@anthropic-ai/claude-code".into(), integrity },
                ..npm("claude", "@anthropic-ai/claude-code", "2.1.329")
            }],
        };
        let sum = |b: u8| Some(format!("sha512-{}", base64::engine::general_purpose::STANDARD.encode([b; 64])));
        t.set_plan(with(sum(1))).unwrap();
        let (old, _) = t.next().unwrap();
        t.set_plan(with(sum(1))).unwrap();
        assert_eq!(t.report().1["claude"].state, wire::HARNESS_INSTALLING, "the same recipe carries on");
        t.set_plan(with(sum(2))).unwrap();
        assert_eq!(t.report().1["claude"].state, wire::HARNESS_QUEUED);
        t.finish(&old, Err("bad checksum".into()));
        assert_eq!(t.report().1["claude"].state, wire::HARNESS_QUEUED, "the old run's end doesn't count");
        let (new, _) = t.next().unwrap();
        assert_eq!(new, with(sum(2)).harnesses[0]);
    }

    #[test]
    fn a_new_node_reinstalls_npm_harnesses() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("superbot-tools-node-{}", now_ms()));
        let t = Tools::new(dir, None).unwrap();
        let claude = t.bin_dir().join("claude");
        std::fs::write(&claude, "#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&claude, std::fs::Permissions::from_mode(0o755)).unwrap();
        {
            let mut s = t.lock();
            s.node = Some("24.22.3".into());
            s.installed.insert("claude".into(), "2.1.329".into());
        }
        let on = |version: &str| HarnessPlan {
            node: Some(NodeRuntime {
                version: version.into(),
                downloads: BTreeMap::from([("x86_64".into(), wire::Download { url: "https://nodejs.org/n.tar.xz".into(), sha256: "a".repeat(64) })]),
            }),
            harnesses: vec![npm("claude", "@anthropic-ai/claude-code", "2.1.329")],
        };
        t.set_plan(on("24.22.3")).unwrap();
        assert_eq!(t.report().1["claude"].state, wire::HARNESS_INSTALLED);
        t.set_plan(on("24.22.4")).unwrap();
        assert_eq!(t.report().1["claude"].state, wire::HARNESS_QUEUED, "a plan that only moves Node.js is applied");
        let (h, node) = t.next().unwrap();
        assert!(t.replaces(&h, node.as_ref()), "running Bots use the old Node.js");
    }

    #[tokio::test]
    async fn replacing_waits_for_running_jobs_and_holds_new_ones() {
        let dir = std::env::temp_dir().join(format!("superbot-tools-gate-{}", now_ms()));
        let t = Tools::new(dir, None).unwrap();
        let job = t.job_permit().unwrap();
        let (got_tx, got_rx) = tokio::sync::oneshot::channel();
        let (done_tx, done_rx) = tokio::sync::oneshot::channel::<()>();
        let t2 = t.clone();
        let install = tokio::spawn(async move {
            let _r = t2.replacing().await;
            let _ = got_tx.send(());
            let _ = done_rx.await;
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!install.is_finished() && t.job_permit().is_some(), "it waits, and jobs still start");
        drop(job);
        tokio::time::timeout(Duration::from_secs(5), got_rx).await.unwrap().unwrap();
        assert!(t.job_permit().is_none(), "no job starts while files are replaced");
        let _ = done_tx.send(());
        install.await.unwrap();
        assert!(t.job_permit().is_some());
    }

    #[test]
    fn sri_is_sha512_base64() {
        let good = format!("sha512-{}", base64::engine::general_purpose::STANDARD.encode([7u8; 64]));
        assert!(sri(&good));
        assert!(!sri("sha512-AAAA"));
        assert!(!sri(&good.replace("sha512", "sha256")));
    }
}
