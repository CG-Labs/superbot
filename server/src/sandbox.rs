//! Harness sandboxes (ADR 0055): whether this host can start one, and the folders
//! outside the workspace a sandboxed Bot still writes to. Shared by botd and the
//! machine agent, which reports both in its layout.

use std::path::{Path, PathBuf};

/// Package and build caches under HOME. Without them `npm install`, `cargo build`, or
/// `pip install` fail in a sandbox that keeps HOME read-only. Never folders that hold
/// programs or settings (`~/.local`, `~/.cargo/bin`, `~/.config`): a Bot that could
/// change those could change what runs outside its sandbox later.
pub const CACHE_DIRS: [&str; 9] = [".cache", ".npm", ".cargo/registry", ".cargo/git", "go/pkg/mod", ".bun/install/cache", ".yarn/berry/cache", ".gradle/caches", ".m2/repository"];

/// The cache folders that exist under `home`. A missing one isn't listed: Codex refuses
/// to start a sandbox with a writable folder that doesn't exist. Links aren't followed.
pub fn caches(home: &Path) -> Vec<PathBuf> {
    CACHE_DIRS
        .iter()
        .map(|d| home.join(d))
        .filter(|p| ancestors_plain(home, p) && std::fs::symlink_metadata(p).is_ok_and(|m| m.is_dir()))
        .collect()
}

/// Whether every folder from `home` (exclusive) down to `p` is a real folder, not a link.
fn ancestors_plain(home: &Path, p: &Path) -> bool {
    let Ok(rel) = p.strip_prefix(home) else { return false };
    let mut at = home.to_path_buf();
    rel.components().all(|c| {
        at.push(c);
        std::fs::symlink_metadata(&at).is_ok_and(|m| m.file_type().is_dir())
    })
}

/// Whether harness sandboxes can start here. On Linux, Codex and Claude Code build
/// theirs with unprivileged user namespaces (bubblewrap), which containers and some
/// distributions block; then Codex fails every command and Claude Code runs them
/// unsandboxed. Checked once per process.
pub fn available() -> bool {
    static AVAILABLE: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *AVAILABLE.get_or_init(probe)
}

#[cfg(target_os = "macos")]
fn probe() -> bool {
    Path::new("/usr/bin/sandbox-exec").exists()
}

#[cfg(target_os = "linux")]
fn probe() -> bool {
    let ok = |bin: &str, args: &[&str]| {
        std::process::Command::new(bin)
            .args(args)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
    };
    ok("bwrap", &["--unshare-user", "--unshare-net", "--ro-bind", "/", "/", "true"]) || ok("unshare", &["--user", "--map-root-user", "--net", "true"])
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn probe() -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_cache_folders_that_exist_and_are_not_links() {
        let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        let home = std::env::temp_dir().join(format!("sandbox-caches-{}-{nanos}", std::process::id()));
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
}
