//! The agent replacing itself with botd's build (ADR 0038). botd asks with an
//! `UpgradeRequest`; the agent downloads `/v1/agent` (and `/v1/botctl`) from botd over
//! the CA-pinned channel, checks each against the SHA-256 botd sent, checks the new
//! agent runs, then swaps each file in one rename, keeping the old one as `.prev`, and
//! restarts. The new agent is on trial until botd's first heartbeat reaches it; if
//! none does in time, it puts the old one back and restarts. If it can't even start,
//! the unit's guard (`ExecStartPre`, written by cloud-init) does that after three tries.
//! Shared by the agent binary and botd's tests, so it uses nothing of botd's but `wire`.
//!
//! In the state dir: `upgrade-trial.json` while a new agent is on trial (its starts
//! are counted in `upgrade-trial.starts`), and `upgrade-last.json`, how the last one went.

// Shared by two binaries, each of which uses only part of it.
#![allow(dead_code)]

use super::wire::{self, UpgradeReport, UpgradeRequest};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

pub const TRIAL_FILE: &str = "upgrade-trial.json";
pub const STARTS_FILE: &str = "upgrade-trial.starts";
pub const LAST_FILE: &str = "upgrade-last.json";
/// The largest binary botd may send.
pub const MAX_BINARY: usize = 256 << 20;
/// Shortest and longest trial botd may ask for.
pub const TRIAL_SECS: std::ops::RangeInclusive<u64> = 30..=86_400;

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as i64)
}

pub fn sha256_hex(b: &[u8]) -> String {
    Sha256::digest(b).iter().map(|x| format!("{x:02x}")).collect()
}

fn suffixed(p: &Path, s: &str) -> PathBuf {
    let mut o = p.as_os_str().to_owned();
    o.push(s);
    PathBuf::from(o)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TrialFile {
    report: UpgradeReport,
    trial_secs: u64,
}

pub struct Upgrader {
    /// The agent's binary, replaced in place.
    pub exe: PathBuf,
    /// botctl beside it, replaced too when botd sends one.
    pub botctl: PathBuf,
    state_dir: PathBuf,
    /// SHA-256 of `exe` when the agent started. None: it can't upgrade itself.
    pub build: Option<String>,
    version: String,
    staging: AtomicBool,
    trial: Mutex<Option<(UpgradeReport, tokio::time::Instant)>>,
    /// The upgrade being staged, for the heartbeat.
    current: Mutex<Option<UpgradeReport>>,
}

/// A whole file, written to `path` and synced, with `mode`.
fn write_file(path: &Path, bytes: &[u8], mode: u32) -> Result<(), String> {
    let _ = std::fs::remove_file(path);
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(path)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    f.write_all(bytes)
        .and_then(|()| f.sync_all())
        .map_err(|e| format!("{}: {e}", path.display()))
}

fn write_json<T: Serialize>(path: &Path, v: &T) -> Result<(), String> {
    let tmp = suffixed(path, ".tmp");
    write_file(&tmp, &serde_json::to_vec_pretty(v).unwrap_or_default(), 0o600)?;
    std::fs::rename(&tmp, path).map_err(|e| format!("{}: {e}", path.display()))
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Option<T> {
    serde_json::from_slice(&std::fs::read(path).ok()?).ok()
}

/// Keeps `path` as `path.prev` and puts `path.new` in its place, in one rename.
fn swap(path: &Path) -> Result<(), String> {
    let (new, prev) = (suffixed(path, ".new"), suffixed(path, ".prev"));
    let _ = std::fs::remove_file(&prev);
    std::fs::hard_link(path, &prev)
        .or_else(|_| std::fs::copy(path, &prev).map(|_| ()))
        .map_err(|e| format!("keeping {}: {e}", path.display()))?;
    std::fs::rename(&new, path).map_err(|e| format!("replacing {}: {e}", path.display()))
}

/// Puts `path.prev` back, if it is there.
fn restore(path: &Path) -> Result<bool, String> {
    let prev = suffixed(path, ".prev");
    if !prev.exists() {
        return Ok(false);
    }
    std::fs::rename(&prev, path).map_err(|e| format!("restoring {}: {e}", path.display()))?;
    Ok(true)
}

impl Upgrader {
    /// Reads what an earlier upgrade left. A trial for this very build starts now; one
    /// for another build means the old agent is back (the guard put it back), so that
    /// upgrade rolled back.
    pub fn new(exe: PathBuf, state_dir: PathBuf, version: &str) -> Upgrader {
        let build = std::fs::read(&exe).ok().map(|b| sha256_hex(&b));
        let botctl = exe.with_file_name("botctl");
        let u = Upgrader {
            exe,
            botctl,
            state_dir,
            build,
            version: version.into(),
            staging: AtomicBool::new(false),
            trial: Mutex::new(None),
            current: Mutex::new(None),
        };
        if let Some(t) = read_json::<TrialFile>(&u.state_dir.join(TRIAL_FILE)) {
            if u.build.as_deref() == Some(&t.report.to_build) {
                let left = Duration::from_secs(t.trial_secs.clamp(*TRIAL_SECS.start(), *TRIAL_SECS.end()));
                let mut r = t.report;
                r.state = wire::UPGRADE_TRIAL.into();
                *u.trial.lock().unwrap() = Some((r, tokio::time::Instant::now() + left));
            } else {
                u.end(t.report, wire::UPGRADE_ROLLED_BACK, Some("the new agent didn't start, so the old one was put back".into()));
            }
        }
        u
    }

    /// Records how an upgrade ended, and clears the trial.
    fn end(&self, mut r: UpgradeReport, state: &str, reason: Option<String>) {
        r.state = state.into();
        r.reason = reason;
        r.at = now_ms();
        let _ = write_json(&self.state_dir.join(LAST_FILE), &r);
        let _ = std::fs::remove_file(self.state_dir.join(TRIAL_FILE));
        let _ = std::fs::remove_file(self.state_dir.join(STARTS_FILE));
    }

    pub fn staging(&self) -> bool {
        self.staging.load(Ordering::SeqCst)
    }

    /// What the heartbeat says about upgrades.
    pub fn report(&self) -> Option<UpgradeReport> {
        if let Some(r) = self.current.lock().unwrap().clone() {
            return Some(r);
        }
        if let Some((r, _)) = self.trial.lock().unwrap().clone() {
            return Some(r);
        }
        read_json(&self.state_dir.join(LAST_FILE))
    }

    /// When an untested new agent must have been reached by botd.
    pub fn trial_deadline(&self) -> Option<tokio::time::Instant> {
        self.trial.lock().unwrap().as_ref().map(|(_, d)| *d)
    }

    /// botd reached this agent: the new build is kept, and the old one let go.
    pub fn commit(&self) -> bool {
        let Some((r, _)) = self.trial.lock().unwrap().take() else {
            return false;
        };
        for p in [&self.exe, &self.botctl] {
            let _ = std::fs::remove_file(suffixed(p, ".prev"));
        }
        self.end(r, wire::UPGRADE_DONE, None);
        true
    }

    /// No heartbeat came in time: the old agent goes back. The caller restarts.
    pub fn roll_back(&self, why: &str) -> Result<(), String> {
        let Some((r, _)) = self.trial.lock().unwrap().take() else {
            return Ok(());
        };
        let res = restore(&self.botctl).and_then(|_| restore(&self.exe));
        let reason = match &res {
            Ok(_) => why.to_string(),
            Err(e) => format!("{why}; {e}"),
        };
        self.end(r, wire::UPGRADE_ROLLED_BACK, Some(reason));
        res.map(|_| ())
    }

    /// Why this agent won't start `req` now, if it won't. `busy`: jobs are running.
    pub fn refuse(&self, req: &UpgradeRequest, busy: usize) -> Option<(u16, String)> {
        let ok_version = !req.version.is_empty()
            && req.version.len() <= 64
            && req.version.bytes().all(|b| b.is_ascii_alphanumeric() || b"._+-".contains(&b));
        let hex = |s: &str| s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
        if !ok_version || !hex(&req.sha256) || req.botctl_sha256.as_deref().is_some_and(|s| !hex(s)) {
            return Some((400, "That isn't an upgrade: a version and SHA-256 hashes.".into()));
        }
        if req.id.is_empty() || req.id.len() > 64 || !req.id.bytes().all(|b| b.is_ascii_alphanumeric()) {
            return Some((400, "The upgrade id isn't a plain name.".into()));
        }
        if !TRIAL_SECS.contains(&req.trial_secs) {
            return Some((400, format!("trialSecs must be {} to {}.", TRIAL_SECS.start(), TRIAL_SECS.end())));
        }
        let Some(build) = &self.build else {
            return Some((409, format!("This agent can't replace itself: {} isn't readable.", self.exe.display())));
        };
        if *build == req.sha256 {
            return Some((409, "This agent is that build already.".into()));
        }
        if self.trial.lock().unwrap().is_some() {
            return Some((409, "This agent is on trial after an upgrade; wait for it to finish.".into()));
        }
        if busy > 0 {
            return Some((409, format!("This machine is running {busy} jobs; upgrade it when they're done.")));
        }
        None
    }

    /// Marks an upgrade as started. False if one already is.
    pub fn begin(&self, req: &UpgradeRequest) -> bool {
        if self.staging.swap(true, Ordering::SeqCst) {
            return false;
        }
        *self.current.lock().unwrap() = Some(UpgradeReport {
            id: req.id.clone(),
            state: wire::UPGRADE_STAGING.into(),
            from_version: self.version.clone(),
            from_build: self.build.clone().unwrap_or_default(),
            to_version: req.version.clone(),
            to_build: req.sha256.clone(),
            reason: None,
            at: now_ms(),
        });
        true
    }

    /// Writes the new files beside the old ones, checks them and swaps them in.
    /// `fetch` downloads botd's `/v1/agent` or `/v1/botctl`. Ok: restart now. Err:
    /// nothing was replaced, and the heartbeat says why.
    pub async fn stage<F, Fut>(&self, req: &UpgradeRequest, fetch: F) -> Result<(), String>
    where
        F: Fn(&'static str) -> Fut,
        Fut: std::future::Future<Output = Result<Vec<u8>, String>>,
    {
        let res = self.stage_inner(req, fetch).await;
        if let Err(e) = &res {
            let report = self.current.lock().unwrap().take();
            for p in [&self.exe, &self.botctl] {
                let _ = std::fs::remove_file(suffixed(p, ".new"));
            }
            if let Some(r) = report {
                self.end(r, wire::UPGRADE_FAILED, Some(e.clone()));
            }
            self.staging.store(false, Ordering::SeqCst);
        }
        res
    }

    async fn stage_inner<F, Fut>(&self, req: &UpgradeRequest, fetch: F) -> Result<(), String>
    where
        F: Fn(&'static str) -> Fut,
        Fut: std::future::Future<Output = Result<Vec<u8>, String>>,
    {
        let mut files = vec![(self.exe.clone(), "/v1/agent", req.sha256.clone())];
        if let Some(sha) = &req.botctl_sha256
            && self.botctl.is_file()
        {
            files.push((self.botctl.clone(), "/v1/botctl", sha.clone()));
        }
        for (path, from, sha) in &files {
            let bytes = fetch(from).await?;
            let got = sha256_hex(&bytes);
            if got != *sha {
                return Err(format!("{from} from the control plane has SHA-256 {got}, not {sha}"));
            }
            write_file(&suffixed(path, ".new"), &bytes, 0o755)?;
        }
        let out = version_of(&suffixed(&self.exe, ".new")).await?;
        let said = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if !out.status.success() || said != format!("superbot-machine {}", req.version) {
            return Err(format!("the new agent says \"{}\", not superbot-machine {}", clip(&said), req.version));
        }
        let mut report = self.current.lock().unwrap().clone().unwrap_or_default();
        report.state = wire::UPGRADE_TRIAL.into();
        report.at = now_ms();
        let _ = std::fs::remove_file(self.state_dir.join(STARTS_FILE));
        write_json(&self.state_dir.join(TRIAL_FILE), &TrialFile { report, trial_secs: req.trial_secs })?;
        // botctl first: if the agent's swap fails, botctl goes back too.
        let mut done: Vec<&PathBuf> = Vec::new();
        for (path, _, _) in files.iter().rev() {
            if let Err(e) = swap(path) {
                for p in done {
                    let _ = restore(p);
                }
                let _ = std::fs::remove_file(self.state_dir.join(TRIAL_FILE));
                return Err(e);
            }
            done.push(path);
        }
        Ok(())
    }
}

/// What `exe --version` prints. A thread forking while the file was still open for
/// writing makes it "busy" for a moment, so that is tried again.
async fn version_of(exe: &Path) -> Result<std::process::Output, String> {
    let mut tries = 0;
    loop {
        let run = tokio::process::Command::new(exe)
            .arg("--version")
            .env_clear()
            .stdin(std::process::Stdio::null())
            .kill_on_drop(true)
            .output();
        match tokio::time::timeout(Duration::from_secs(20), run).await {
            Err(_) => return Err("the new agent didn't answer --version".into()),
            Ok(Err(e)) if e.raw_os_error() == Some(26) && tries < 20 => {
                tries += 1;
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            Ok(Err(e)) => return Err(format!("the new agent doesn't run here: {e}")),
            Ok(Ok(out)) => return Ok(out),
        }
    }
}

fn clip(s: &str) -> String {
    s.chars().take(80).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn upgrader(name: &str, old: &[u8]) -> (Upgrader, PathBuf) {
        let dir = std::env::temp_dir().join(format!("superbot-upgrade-{name}-{}", now_ms()));
        let state = dir.join("state");
        std::fs::create_dir_all(&state).unwrap();
        let exe = dir.join("superbot-machine");
        write_file(&exe, old, 0o755).unwrap();
        write_file(&dir.join("botctl"), b"old botctl", 0o755).unwrap();
        (Upgrader::new(exe, state.clone(), "0.1.0"), state)
    }

    fn req(new: &[u8]) -> UpgradeRequest {
        UpgradeRequest {
            id: "u1".into(),
            version: "0.1.0".into(),
            sha256: sha256_hex(new),
            botctl_sha256: Some(sha256_hex(b"new botctl")),
            trial_secs: 60,
        }
    }

    const NEW: &[u8] = b"#!/bin/sh\necho superbot-machine 0.1.0\n";

    async fn serve(from: &'static str) -> Result<Vec<u8>, String> {
        Ok(match from {
            "/v1/agent" => NEW.to_vec(),
            _ => b"new botctl".to_vec(),
        })
    }

    #[tokio::test]
    async fn a_checked_build_is_swapped_in_and_kept_once_botd_reaches_it() {
        let (u, state) = upgrader("swap", b"old agent");
        let r = req(NEW);
        assert_eq!(u.refuse(&r, 1).map(|(c, _)| c), Some(409), "busy");
        assert!(u.refuse(&r, 0).is_none());
        assert!(u.begin(&r) && !u.begin(&r), "one at a time");
        u.stage(&r, serve).await.unwrap();
        assert_eq!(std::fs::read(&u.exe).unwrap(), NEW);
        assert_eq!(std::fs::read(suffixed(&u.exe, ".prev")).unwrap(), b"old agent");
        assert_eq!(std::fs::read(&u.botctl).unwrap(), b"new botctl");
        assert!(state.join(TRIAL_FILE).exists());

        // The restart: the new build finds its trial.
        let next = Upgrader::new(u.exe.clone(), state.clone(), "0.1.0");
        assert_eq!(next.build.as_deref(), Some(r.sha256.as_str()));
        assert_eq!(next.report().map(|r| r.state), Some(wire::UPGRADE_TRIAL.to_string()));
        assert!(next.trial_deadline().is_some());
        assert_eq!(next.refuse(&req(b"newer"), 0).map(|(c, _)| c), Some(409), "not while on trial");
        assert!(next.commit() && !next.commit());
        let last = next.report().unwrap();
        assert_eq!((last.state.as_str(), last.id.as_str(), last.from_build.as_str()), (wire::UPGRADE_DONE, "u1", sha256_hex(b"old agent").as_str()));
        assert!(!suffixed(&u.exe, ".prev").exists() && !state.join(TRIAL_FILE).exists());
        assert_eq!(next.refuse(&r, 0).map(|(c, _)| c), Some(409), "that build already");
    }

    #[tokio::test]
    async fn a_build_that_fails_its_checks_changes_nothing() {
        let (u, _) = upgrader("bad", b"old agent");
        let mut r = req(NEW);
        r.sha256 = sha256_hex(b"something else");
        assert!(u.begin(&r));
        let err = u.stage(&r, serve).await.unwrap_err();
        assert!(err.contains("SHA-256"), "{err}");
        assert_eq!(std::fs::read(&u.exe).unwrap(), b"old agent");
        assert!(!suffixed(&u.exe, ".new").exists());
        let last = u.report().unwrap();
        assert_eq!(last.state, wire::UPGRADE_FAILED);
        assert!(!u.staging(), "it can be tried again");

        // Right hash, but it isn't an agent of that version.
        let liar: &'static [u8] = b"#!/bin/sh\necho superbot-machine 9.9.9\n";
        let r = UpgradeRequest { sha256: sha256_hex(liar), botctl_sha256: None, ..req(liar) };
        assert!(u.begin(&r));
        let err = u.stage(&r, move |_| async move { Ok(liar.to_vec()) }).await.unwrap_err();
        assert!(err.contains("9.9.9"), "{err}");
        assert_eq!(std::fs::read(&u.exe).unwrap(), b"old agent");
    }

    #[tokio::test]
    async fn a_new_agent_botd_never_reaches_puts_the_old_one_back() {
        let (u, state) = upgrader("rollback", b"old agent");
        let r = req(NEW);
        assert!(u.begin(&r));
        u.stage(&r, serve).await.unwrap();
        let next = Upgrader::new(u.exe.clone(), state.clone(), "0.1.0");
        next.roll_back("no heartbeat").unwrap();
        assert_eq!(std::fs::read(&u.exe).unwrap(), b"old agent");
        assert_eq!(std::fs::read(&u.botctl).unwrap(), b"old botctl");
        let last = next.report().unwrap();
        assert_eq!((last.state.as_str(), last.reason.as_deref()), (wire::UPGRADE_ROLLED_BACK, Some("no heartbeat")));

        // The guard put it back instead: the old agent says so when it starts.
        let (u, state) = upgrader("guarded", b"old agent");
        assert!(u.begin(&r));
        u.stage(&r, serve).await.unwrap();
        restore(&u.exe).unwrap();
        let old = Upgrader::new(u.exe.clone(), state.clone(), "0.1.0");
        assert_eq!(old.report().map(|r| r.state), Some(wire::UPGRADE_ROLLED_BACK.to_string()));
        assert!(!state.join(TRIAL_FILE).exists());
    }

    #[test]
    fn requests_are_checked() {
        let (u, _) = upgrader("checks", b"old agent");
        for bad in [
            UpgradeRequest { version: "1 0".into(), ..req(NEW) },
            UpgradeRequest { sha256: "ABC".into(), ..req(NEW) },
            UpgradeRequest { id: "../x".into(), ..req(NEW) },
            UpgradeRequest { trial_secs: 1, ..req(NEW) },
        ] {
            assert_eq!(u.refuse(&bad, 0).map(|(c, _)| c), Some(400), "{bad:?}");
        }
        let none = Upgrader::new(PathBuf::from("/nonexistent/superbot-machine"), std::env::temp_dir(), "0.1.0");
        assert_eq!(none.build, None);
        assert_eq!(none.refuse(&req(NEW), 0).map(|(c, _)| c), Some(409));
    }
}
