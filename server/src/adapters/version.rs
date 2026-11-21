//! Harness CLI versions, for a guarded run whose harness needs a minimum release to
//! run SuperBot's hook (`Adapter::hooks_since`, ADR 0059). Read from `<bin> --version`
//! where the run happens: here, or the owner's machine as a job.
//!
//! Fails closed: a version that can't be read or parsed refuses the run like one too
//! old. Only a version that passed is remembered, for `PASS_FOR`, so a refused run
//! that an admin fixes goes through on the next try.

use crate::machines::wire::JobEvent;
use std::cmp::Ordering;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

/// How long `--version` may take before the run is refused.
pub const PROBE_TIMEOUT: Duration = Duration::from_secs(15);
/// How long a version that passed is trusted where nothing says it changed.
const PASS_FOR: Duration = Duration::from_secs(600);

/// A semantic version: `major.minor.patch`, an optional pre-release, and build
/// metadata, which is ignored.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Version {
    major: u64,
    minor: u64,
    patch: u64,
    pre: Vec<Ident>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Ident {
    Num(u64),
    Alnum(String),
}

impl Ord for Ident {
    /// Semver: numbers by value, below words, which compare as ASCII.
    fn cmp(&self, other: &Self) -> Ordering {
        match (self, other) {
            (Ident::Num(a), Ident::Num(b)) => a.cmp(b),
            (Ident::Num(_), Ident::Alnum(_)) => Ordering::Less,
            (Ident::Alnum(_), Ident::Num(_)) => Ordering::Greater,
            (Ident::Alnum(a), Ident::Alnum(b)) => a.cmp(b),
        }
    }
}

impl PartialOrd for Ident {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Version {
    /// Semver precedence: a pre-release comes before its release (0.141.0-alpha.1 <
    /// 0.141.0), and a shorter pre-release before a longer one it starts.
    fn cmp(&self, other: &Self) -> Ordering {
        (self.major, self.minor, self.patch).cmp(&(other.major, other.minor, other.patch)).then_with(|| {
            match (self.pre.is_empty(), other.pre.is_empty()) {
                (true, true) => Ordering::Equal,
                (true, false) => Ordering::Greater,
                (false, true) => Ordering::Less,
                (false, false) => self.pre.cmp(&other.pre),
            }
        })
    }
}

impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl std::fmt::Display for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)?;
        let pre: Vec<String> = self
            .pre
            .iter()
            .map(|i| match i {
                Ident::Num(n) => n.to_string(),
                Ident::Alnum(s) => s.clone(),
            })
            .collect();
        if !pre.is_empty() {
            write!(f, "-{}", pre.join("."))?;
        }
        Ok(())
    }
}

impl Version {
    /// Exactly one version, with an optional leading `v`: `0.141.0`, `v1.2.3-alpha.1+abc`.
    /// Not `0.141`, `0.141.0.1`, `latest` or an empty pre-release part.
    pub fn parse(s: &str) -> Option<Version> {
        let s = s.strip_prefix('v').unwrap_or(s);
        let s = s.split_once('+').map_or(s, |(v, build)| if build_ok(build) { v } else { "" });
        let (core, pre) = s.split_once('-').map_or((s, None), |(c, p)| (c, Some(p)));
        let nums: Vec<u64> = core.split('.').map(number).collect::<Option<_>>()?;
        let [major, minor, patch] = nums[..] else { return None };
        let pre = match pre {
            None => Vec::new(),
            Some(p) => p.split('.').map(ident).collect::<Option<_>>()?,
        };
        Some(Version { major, minor, patch, pre })
    }

    /// The first version in what a CLI's `--version` printed: `codex-cli 0.141.0`.
    pub fn find(output: &str) -> Option<Version> {
        output
            .split(|c: char| c.is_whitespace() || matches!(c, '(' | ')' | ',' | ';' | '"' | '\''))
            .find_map(Version::parse)
    }
}

/// Digits only: no sign, no blanks, and small enough to hold.
fn number(s: &str) -> Option<u64> {
    if s.is_empty() || s.len() > 18 || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse().ok()
}

fn ident(s: &str) -> Option<Ident> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
        return None;
    }
    Some(number(s).map_or_else(|| Ident::Alnum(s.to_string()), Ident::Num))
}

fn build_ok(s: &str) -> bool {
    s.split('.').all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'))
}

/// Why a harness can't run guarded where it is.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Short {
    /// It is this release, older than the one that runs the hook.
    Old(String),
    /// Its version couldn't be read: why.
    Unknown(String),
}

/// Whether what `--version` said (or why it couldn't run) is at least `min`.
pub fn assess(min: &str, said: Result<String, String>) -> Result<(), Short> {
    let min = Version::parse(min).expect("adapters name exact versions");
    let out = said.map_err(Short::Unknown)?;
    let line = out.lines().map(str::trim).find(|l| !l.is_empty()).unwrap_or_default();
    match Version::find(&out) {
        Some(v) if v >= min => Ok(()),
        Some(v) => Err(Short::Old(v.to_string())),
        None if line.is_empty() => Err(Short::Unknown("--version printed nothing".into())),
        None => Err(Short::Unknown(format!("--version printed \"{}\"", super::short(line)))),
    }
}

/// Places whose harness passed, by key (`key_here`, or a machine's), and when.
static PASSED: Mutex<Option<HashMap<String, Instant>>> = Mutex::new(None);

/// Whether `key`'s harness passed less than `PASS_FOR` ago.
pub fn passed(key: &str) -> bool {
    let mut p = PASSED.lock().unwrap_or_else(|e| e.into_inner());
    let map = p.get_or_insert_default();
    map.retain(|_, at| at.elapsed() < PASS_FOR);
    map.contains_key(key)
}

pub fn pass(key: String) {
    PASSED.lock().unwrap_or_else(|e| e.into_inner()).get_or_insert_default().insert(key, Instant::now());
}

/// `bin` as a run here starting in `cwd` would find it on `path`: relative entries,
/// and empty ones (the current folder), are from `cwd`. The file it resolves to, so
/// that replacing it (an update) changes the cache key.
pub fn resolve(bin: &str, path: &str, cwd: &Path) -> Option<PathBuf> {
    use std::os::unix::fs::PermissionsExt;
    path.split(':').map(|d| cwd.join(d).join(bin)).find_map(|p| {
        let real = p.canonicalize().ok()?;
        let m = real.metadata().ok()?;
        (m.is_file() && m.permissions().mode() & 0o111 != 0).then_some(real)
    })
}

/// The cache key for `bin` here: where it resolves, and that file's size and last change.
pub fn key_here(bin: &str, real: &Path) -> String {
    let m = real.metadata().ok();
    let changed = m.as_ref().and_then(|m| m.modified().ok()).and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok());
    format!("here:{bin}:{}:{}:{}", real.display(), m.map_or(0, |m| m.len()), changed.map_or(0, |d| d.as_nanos()))
}

/// `<real> --version` on this server, in `cwd`, without botd's secrets: its stdout, or why not.
pub async fn read_here(real: &Path, path: &str, cwd: &Path) -> Result<String, String> {
    let mut cmd = tokio::process::Command::new(real);
    cmd.arg("--version").env("PATH", path).current_dir(cwd).stdin(std::process::Stdio::null()).kill_on_drop(true);
    for k in super::secret_env() {
        cmd.env_remove(k);
    }
    match tokio::time::timeout(PROBE_TIMEOUT, cmd.output()).await {
        Err(_) => Err(format!("{} --version didn't answer in {} seconds", real.display(), PROBE_TIMEOUT.as_secs())),
        Ok(Err(e)) => Err(format!("{} --version: {e}", real.display())),
        Ok(Ok(o)) if !o.status.success() => Err(failed(&o.status.to_string(), &String::from_utf8_lossy(&o.stderr))),
        Ok(Ok(o)) => Ok(String::from_utf8_lossy(&o.stdout).into_owned()),
    }
}

/// What a `--version` job printed: its stdout if it exited well, else why not.
pub async fn read_job(mut rx: mpsc::Receiver<JobEvent>) -> Result<String, String> {
    let mut out = String::new();
    while let Some(ev) = rx.recv().await {
        match ev {
            JobEvent::Line { line } => {
                out.push_str(&line);
                out.push('\n');
            }
            JobEvent::Exit { success: true, .. } => return Ok(out),
            JobEvent::Exit { status, stderr, .. } => return Err(failed(&status, &stderr)),
            JobEvent::Error { message } | JobEvent::Cleanup { why: message } => return Err(message),
            JobEvent::Started | JobEvent::Ping => {}
        }
    }
    Err("the computer stopped answering".into())
}

fn failed(status: &str, stderr: &str) -> String {
    match stderr.lines().map(str::trim).rfind(|l| !l.is_empty()) {
        Some(l) => format!("--version {status}: {}", super::short(l)),
        None => format!("--version {status}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(s: &str) -> Version {
        Version::parse(s).unwrap_or_else(|| panic!("{s} parses"))
    }

    #[test]
    fn versions_parse_exactly() {
        assert_eq!(v("0.141.0"), Version { major: 0, minor: 141, patch: 0, pre: vec![] });
        assert_eq!(v("v1.2.3"), v("1.2.3"));
        assert_eq!(v("0.141.0+build.7"), v("0.141.0"), "build metadata is ignored");
        assert_eq!(v("0.141.0-alpha.3").to_string(), "0.141.0-alpha.3");
        assert_eq!(v("1.0.0-x-y.2").pre, vec![Ident::Alnum("x-y".into()), Ident::Num(2)]);
        for bad in [
            "", "v", "0.141", "0.141.", ".141.0", "0.141.0.1", "0.141.x", "0..0", "-1.0.0", "1.0.0-", "1.0.0-alpha..1",
            "1.0.0+", "1.0.0+a..b", "1.0.0-al pha", "latest", "codex-cli", "1.0.0_1", "99999999999999999999.0.0", "+1.0.0", " 1.0.0",
        ] {
            assert_eq!(Version::parse(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn versions_compare_by_semver_precedence() {
        let order = [
            "0.0.0", "0.9.0", "0.99.0", "0.140.9", "0.141.0-alpha", "0.141.0-alpha.1", "0.141.0-alpha.2", "0.141.0-alpha.10", "0.141.0-alpha.beta",
            "0.141.0-beta", "0.141.0-rc.1", "0.141.0", "0.141.1", "0.142.0-alpha.1", "0.142.0", "1.0.0",
        ];
        for w in order.windows(2) {
            assert!(v(w[0]) < v(w[1]), "{} < {}", w[0], w[1]);
        }
        assert_eq!(v("0.141.0+a").cmp(&v("0.141.0+b")), Ordering::Equal);
    }

    #[test]
    fn the_version_is_found_in_what_the_cli_prints() {
        for (out, want) in [
            ("codex-cli 0.171.0\n", Some("0.171.0")),
            ("codex-cli 0.141.0-alpha.3", Some("0.141.0-alpha.3")),
            ("codex 0.141.0 (node v22.23.5)", Some("0.141.0")),
            ("2.1.329 (Claude Code)", Some("2.1.329")),
            ("Hermes Agent v0.23.2", Some("0.23.2")),
            ("version: \"1.5.2\",", Some("1.5.2")),
            ("codex-cli dev", None),
            ("codex-cli 0.141", None),
            ("", None),
        ] {
            assert_eq!(Version::find(out).map(|v| v.to_string()).as_deref(), want, "{out:?}");
        }
    }

    #[test]
    fn too_old_unknown_and_new_enough() {
        let min = "0.141.0";
        let said = |s: &str| Ok(s.to_string());
        assert_eq!(assess(min, said("codex-cli 0.141.0\n")), Ok(()));
        assert_eq!(assess(min, said("codex-cli 0.171.0")), Ok(()));
        assert_eq!(assess(min, said("codex-cli 0.142.0-alpha.1")), Ok(()));
        assert_eq!(assess(min, said("codex-cli 0.140.0")), Err(Short::Old("0.140.0".into())));
        assert_eq!(assess(min, said("codex-cli 0.141.0-alpha.3")), Err(Short::Old("0.141.0-alpha.3".into())), "before its release");
        assert_eq!(assess(min, said("codex-cli 0.0.0")), Err(Short::Old("0.0.0".into())), "a build from source says 0.0.0");
        assert_eq!(assess(min, said("\n\n")), Err(Short::Unknown("--version printed nothing".into())));
        assert_eq!(assess(min, said("codex-cli dev\nmore")), Err(Short::Unknown("--version printed \"codex-cli dev\"".into())));
        assert_eq!(assess(min, Err("not found".into())), Err(Short::Unknown("not found".into())));
    }

    #[tokio::test]
    async fn read_here_runs_the_cli_and_the_cache_follows_the_file() {
        use std::os::unix::fs::PermissionsExt;
        let dir = crate::db::temp_path("version");
        let bin = dir.join("codex");
        let write = |body: &str| {
            std::fs::write(&bin, format!("#!/bin/sh\n{body}\n")).unwrap();
            std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
        };
        let path = format!("/nonexistent:{}:/usr/bin:/bin", dir.display());
        let elsewhere = Path::new("/").to_path_buf();
        assert_eq!(resolve("codex", "/nonexistent:/also-not", &elsewhere), None);
        write("echo 'codex-cli 0.140.0'");
        let real = resolve("codex", &path, &elsewhere).unwrap();
        assert_eq!(read_here(&real, &path, &elsewhere).await.as_deref(), Ok("codex-cli 0.140.0\n"));
        // Relative and empty entries are from the run's folder, as its harness finds them.
        let parent = dir.parent().unwrap();
        let name = dir.file_name().unwrap().to_str().unwrap();
        for (p, from) in [(format!("{name}:/usr/bin"), parent), (":/usr/bin".into(), dir.as_path()), (format!("./{name}"), parent)] {
            assert_eq!(resolve("codex", &p, from).as_ref(), Some(&real), "{p:?} from {}", from.display());
        }
        assert_eq!(resolve("codex", name, &elsewhere), None, "not from botd's folder");
        let key = key_here("codex", &real);
        assert!(!passed(&key));
        pass(key.clone());
        assert!(passed(&key));
        std::thread::sleep(Duration::from_millis(20));
        write("echo 'boom' >&2; exit 3");
        assert_ne!(key_here("codex", &real), key, "an update is a new key");
        let err = read_here(&real, &path, &elsewhere).await.unwrap_err();
        assert!(err.contains("exit status: 3") && err.ends_with("boom"), "{err}");
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(resolve("codex", &path, &elsewhere), None, "not executable");
    }

    #[tokio::test]
    async fn read_job_takes_stdout_or_the_reason() {
        let send = |evs: Vec<JobEvent>| {
            let (tx, rx) = mpsc::channel(16);
            for e in evs {
                tx.try_send(e).unwrap();
            }
            read_job(rx)
        };
        let exit = |success: bool, stderr: &str| JobEvent::Exit { success, status: "exit status: 1".into(), stderr: stderr.into(), files: Default::default(), too_big: vec![] };
        let ok = send(vec![JobEvent::Started, JobEvent::Line { line: "codex-cli 0.171.0".into() }, JobEvent::Ping, exit(true, "")]).await;
        assert_eq!(ok.as_deref(), Ok("codex-cli 0.171.0\n"));
        assert_eq!(send(vec![exit(false, "warn\nbad flag\n")]).await, Err("--version exit status: 1: bad flag".into()));
        assert_eq!(send(vec![JobEvent::Error { message: "codex isn't installed on this machine.".into() }]).await, Err("codex isn't installed on this machine.".into()));
        assert_eq!(send(vec![JobEvent::Line { line: "codex-cli 0.171.0".into() }]).await, Err("the computer stopped answering".into()));
    }
}
