//! Harness sandboxes (ADR 0055): what this host has to start one, and the folders
//! outside the workspace a sandboxed Bot still writes to. Shared by botd, the machine
//! agent, which reports both in its layout, and `superbot-run`.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Package and build caches under HOME. Without them `npm install`, `cargo build`, or
/// `pip install` fail in a sandbox that keeps HOME read-only. Never folders that hold
/// programs or settings (`~/.local`, `~/.cargo/bin`, `~/.config`): a Bot that could
/// change those could change what runs outside its sandbox later.
pub const CACHE_DIRS: [&str; 9] = [".cache", ".npm", ".cargo/registry", ".cargo/git", "go/pkg/mod", ".bun/install/cache", ".yarn/berry/cache", ".gradle/caches", ".m2/repository"];

/// The cache folders that exist under `home`. A missing one isn't listed: Codex refuses
/// to start a sandbox with a writable folder that doesn't exist. Links aren't followed.
pub fn caches(home: &Path) -> Vec<PathBuf> {
    CACHE_DIRS.iter().map(|d| home.join(d)).filter(|p| plain_down_to(home, p)).collect()
}

/// [`caches`], after making the missing ones (mode 0700, the folders on the way 0755,
/// whatever the umask). Run it as the user the run
/// is, in that user's HOME, so the folders are theirs. Never through a link: a folder
/// on the way that is a link, or not a folder, leaves that cache out.
pub fn ensure_caches(home: &Path) -> Vec<PathBuf> {
    use std::os::unix::fs::DirBuilderExt;
    if !std::fs::symlink_metadata(home).is_ok_and(|m| m.is_dir()) {
        return vec![];
    }
    for d in CACHE_DIRS {
        let mut at = home.to_path_buf();
        let last = Path::new(d).components().count();
        for (i, c) in Path::new(d).components().enumerate() {
            at.push(c);
            // Folders on the way stay searchable so botd can still check the path to
            // a per-user account's caches on later runs ([`makeable_caches`]).
            let mode = if i + 1 == last { 0o700 } else { 0o755 };
            match std::fs::symlink_metadata(&at) {
                Ok(m) if m.file_type().is_dir() => continue,
                Ok(_) => break,
                Err(_) if std::fs::DirBuilder::new().mode(mode).create(&at).is_ok() => {
                    let _ = std::fs::set_permissions(&at, std::os::unix::fs::PermissionsExt::from_mode(mode));
                }
                Err(_) => break,
            }
        }
    }
    caches(home)
}

/// The caches [`ensure_caches`] will have under `home`, seen by someone who can look
/// but not make them there (botd, in a per-user account's HOME): those whose folders
/// that already exist are all real folders.
pub fn makeable_caches(home: &Path) -> Vec<PathBuf> {
    if !std::fs::symlink_metadata(home).is_ok_and(|m| m.is_dir()) {
        return vec![];
    }
    CACHE_DIRS
        .iter()
        .map(|d| home.join(d))
        .filter(|p| {
            let mut at = home.to_path_buf();
            p.strip_prefix(home).unwrap_or(p).components().all(|c| {
                at.push(c);
                match std::fs::symlink_metadata(&at) {
                    Ok(m) => m.file_type().is_dir(),
                    Err(e) => e.kind() == std::io::ErrorKind::NotFound,
                }
            })
        })
        .collect()
}

/// Whether every folder from `home` (exclusive) down to `p` is a real folder, not a link.
fn plain_down_to(home: &Path, p: &Path) -> bool {
    let Ok(rel) = p.strip_prefix(home) else { return false };
    let mut at = home.to_path_buf();
    rel.components().all(|c| {
        at.push(c);
        std::fs::symlink_metadata(&at).is_ok_and(|m| m.file_type().is_dir())
    })
}

/// Programs a harness's sandbox may need on Linux, checked by [`host`].
pub const PROGRAMS: [&str; 2] = ["bwrap", "socat"];

/// What a host has for harness sandboxes. Each harness says what its own needs
/// (`Adapter::sandbox_needs`): Codex brings its own bubblewrap, Claude Code uses the
/// system's and socat.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Host {
    /// Unprivileged user namespaces work (Linux), or the OS sandbox is there (macOS).
    pub namespaces: bool,
    /// Of [`PROGRAMS`], the ones that work here: `bwrap` only when it can make a
    /// sandbox, `socat` when it is on PATH. All of them on macOS, which needs none.
    pub programs: Vec<String>,
}

impl Host {
    /// Whether a sandbox that needs `programs` can start here.
    pub fn has(&self, programs: &[&str]) -> bool {
        self.namespaces && programs.iter().all(|n| self.programs.iter().any(|p| p == n))
    }
}

/// [`Host`] for this machine, checked once per process. Containers and some
/// distributions (Ubuntu 24.04's AppArmor) block user namespaces.
pub fn host() -> Host {
    host_as(None)
}

/// [`Host`] for runs as the user `(uid, gid)`, checked as that user once per process:
/// root may make namespaces an unprivileged user can't.
pub fn host_as(ids: Option<(u32, u32)>) -> Host {
    type Checked = Vec<(Option<(u32, u32)>, Host)>;
    static HOSTS: std::sync::Mutex<Checked> = std::sync::Mutex::new(Vec::new());
    let mut hosts = HOSTS.lock().unwrap_or_else(|e| e.into_inner());
    if let Some((_, h)) = hosts.iter().find(|(i, _)| *i == ids) {
        return h.clone();
    }
    let h = probe(ids);
    hosts.push((ids, h.clone()));
    h
}

#[cfg(target_os = "macos")]
fn probe(_ids: Option<(u32, u32)>) -> Host {
    Host { namespaces: Path::new("/usr/bin/sandbox-exec").exists(), programs: PROGRAMS.map(String::from).into() }
}

#[cfg(target_os = "linux")]
fn probe(ids: Option<(u32, u32)>) -> Host {
    use std::os::unix::process::CommandExt;
    let ok = |bin: &str, args: &[&str]| {
        let mut c = std::process::Command::new(bin);
        if let Some((uid, gid)) = ids {
            c.uid(uid).gid(gid).current_dir("/");
        }
        c.args(args)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
    };
    let bwrap = ok("bwrap", &["--unshare-user", "--unshare-net", "--ro-bind", "/", "/", "true"]);
    let namespaces = bwrap || ok("unshare", &["--user", "--map-root-user", "--net", "true"]);
    let on_path = |name: &str| std::env::var_os("PATH").is_some_and(|p| std::env::split_paths(&p).any(|d| d.join(name).is_file()));
    let programs = PROGRAMS.iter().filter(|n| if **n == "bwrap" { bwrap } else { on_path(n) }).map(|n| n.to_string()).collect();
    Host { namespaces, programs }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn probe(_ids: Option<(u32, u32)>) -> Host {
    Host::default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_home(name: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        let home = std::env::temp_dir().join(format!("sandbox-{name}-{}-{nanos}", std::process::id()));
        std::fs::create_dir_all(&home).unwrap();
        home
    }

    #[test]
    fn a_user_is_checked_as_that_user() {
        // SAFETY: plain getters.
        let me = unsafe { (libc::getuid(), libc::getgid()) };
        assert_eq!(host_as(Some(me)), host(), "this process's own user sees what it sees");
        assert_eq!(host_as(Some(me)), host_as(Some(me)), "checked once");
    }

    #[test]
    fn only_cache_folders_that_exist_and_are_not_links() {
        let home = temp_home("caches");
        std::fs::create_dir_all(home.join(".cargo/registry")).unwrap();
        std::fs::create_dir_all(home.join(".npm")).unwrap();
        std::fs::create_dir_all(home.join("elsewhere/mod")).unwrap();
        std::fs::create_dir_all(home.join("go/pkg")).unwrap();
        std::os::unix::fs::symlink(home.join("elsewhere"), home.join(".cache")).unwrap();
        std::os::unix::fs::symlink(home.join("elsewhere/mod"), home.join("go/pkg/mod")).unwrap();
        std::fs::create_dir_all(home.join("linked")).unwrap();
        std::os::unix::fs::symlink(home.join("linked"), home.join(".bun")).unwrap();
        std::fs::create_dir_all(home.join("linked/install/cache")).unwrap();
        assert_eq!(caches(&home), [home.join(".npm"), home.join(".cargo/registry")]);
        assert!(caches(Path::new("/no/such/home")).is_empty());
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn missing_caches_are_made_but_never_through_a_link() {
        use std::os::unix::fs::PermissionsExt;
        let home = temp_home("ensure");
        let outside = temp_home("outside");
        std::os::unix::fs::symlink(&outside, home.join(".gradle")).unwrap();
        std::fs::write(home.join(".m2"), "not a folder").unwrap();
        let made = ensure_caches(&home);
        let want: Vec<PathBuf> = CACHE_DIRS.iter().filter(|d| !d.starts_with(".gradle") && !d.starts_with(".m2")).map(|d| home.join(d)).collect();
        assert_eq!(made, want);
        assert!(!outside.join("caches").exists(), "nothing made through the link");
        assert_eq!(std::fs::metadata(home.join(".cargo/registry")).unwrap().permissions().mode() & 0o777, 0o700);
        assert_eq!(std::fs::metadata(home.join(".cargo")).unwrap().permissions().mode() & 0o777, 0o755, "the way there stays searchable");
        assert_eq!(ensure_caches(&home), want, "the same again");
        let fresh = temp_home("fresh");
        std::os::unix::fs::symlink(&outside, fresh.join(".npm")).unwrap();
        let listed = makeable_caches(&fresh);
        assert!(!listed.contains(&fresh.join(".npm")) && listed.contains(&fresh.join(".cargo/registry")));
        assert_eq!(ensure_caches(&fresh), listed, "what was listed is what gets made");
        let _ = std::fs::remove_dir_all(&fresh);
        assert!(ensure_caches(Path::new("/no/such/home")).is_empty());
        let _ = std::fs::remove_dir_all(&home);
        let _ = std::fs::remove_dir_all(&outside);
    }

    #[test]
    fn a_sandbox_starts_only_with_what_it_needs() {
        let h = Host { namespaces: true, programs: vec!["socat".into()] };
        assert!(h.has(&[]));
        assert!(h.has(&["socat"]) && !h.has(&["bwrap", "socat"]));
        assert!(!Host { namespaces: false, programs: PROGRAMS.map(String::from).into() }.has(&[]));
        let wire: Host = serde_json::from_str(r#"{"namespaces":true,"programs":["bwrap"]}"#).unwrap();
        assert!(wire.has(&["bwrap"]));
    }
}
