//! Paths on disk. Config roots (`DATA_DIR`, `WORKSPACE_DIR`) are made absolute,
//! stripped of `..`, created, and canonicalized once at startup. Every path under a
//! root is built with [`child`], so ids and generated names can't leave their root.

use std::io;
use std::path::{Component, Path, PathBuf};

/// The canonical form of a configured folder, created if needed. `..` parts are
/// resolved first, so `../data` works, but the result never keeps one.
pub fn root(dir: &str) -> io::Result<PathBuf> {
    let mut p = PathBuf::new();
    for c in std::path::absolute(dir)?.components() {
        match c {
            Component::ParentDir => {
                p.pop();
            }
            Component::CurDir => {}
            c => p.push(c),
        }
    }
    let s = p
        .to_str()
        .ok_or_else(|| io::Error::other(format!("{dir}: path is not UTF-8")))?;
    if s.contains("..") {
        return Err(io::Error::other(format!(
            "{dir}: folder names can't contain \"..\""
        )));
    }
    std::fs::create_dir_all(s)?;
    std::fs::canonicalize(s)
}

/// The canonical form of an existing folder. Resolve a root with this before
/// handing it to [`child`], so the prefix check there compares real paths.
pub fn canonical(dir: &Path) -> Option<PathBuf> {
    std::fs::canonicalize(dir).ok()
}

/// `root/name` when `name` is one plain file or folder name. None for empty names,
/// `.`, anything with `..`, path separators, or NUL.
pub fn child(root: &Path, name: &str) -> Option<PathBuf> {
    if name.is_empty() || name == "." || name.contains("..") || name.contains(['/', '\\', '\0']) {
        return None;
    }
    let p = root.join(name);
    if p.starts_with(root) && p.parent() == Some(root) {
        Some(p)
    } else {
        None
    }
}

/// Whether `path`, as another computer reported it, names something strictly under
/// its absolute folder `root`, with no `.` or `..` parts on the way.
pub fn under(root: &str, path: &str) -> bool {
    let root = Path::new(root);
    root.is_absolute()
        && Path::new(path).strip_prefix(root).is_ok_and(|rest| {
            rest.components().next().is_some()
                && rest.components().all(|c| matches!(c, Component::Normal(_)))
        })
        && !path.contains("/./")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn under_stays_strictly_inside() {
        assert!(under("/home/bots", "/home/bots/.npm"));
        assert!(under("/home/bots", "/home/bots/.cargo/registry"));
        for bad in [
            "/home/bots",
            "/home/bots/",
            "/home/bots/../etc",
            "/home/bots/./x",
            "/home/botsx/.npm",
            "relative/.npm",
            "/etc",
        ] {
            assert!(!under("/home/bots", bad), "{bad}");
        }
        assert!(!under("relative", "relative/x"));
    }

    #[test]
    fn child_keeps_plain_names_inside_the_root() {
        let r = Path::new("/srv/data");
        assert_eq!(child(r, "bots"), Some(PathBuf::from("/srv/data/bots")));
        assert_eq!(
            child(r, "MEMORY.md"),
            Some(PathBuf::from("/srv/data/MEMORY.md"))
        );
        for bad in [
            "",
            ".",
            "..",
            "../etc",
            "a/b",
            "/etc/passwd",
            "a\\b",
            "x..y",
            "a\0b",
        ] {
            assert_eq!(child(r, bad), None, "{bad:?}");
        }
    }

    #[test]
    fn root_resolves_dots_and_is_canonical() {
        let id = crate::short_id();
        let r = root(&format!("../target/test-paths-{id}/a/../b/./c")).unwrap();
        assert!(r.is_absolute() && r.is_dir());
        assert!(r.ends_with(format!("target/test-paths-{id}/b/c")));
        let base = r.parent().and_then(Path::parent).unwrap();
        assert!(!base.join("a").exists());
        std::fs::remove_dir_all(base).unwrap();
    }
}
