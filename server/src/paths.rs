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
    let s = p.to_str().ok_or_else(|| io::Error::other(format!("{dir}: path is not UTF-8")))?;
    if s.contains("..") {
        return Err(io::Error::other(format!("{dir}: folder names can't contain \"..\"")));
    }
    std::fs::create_dir_all(s)?;
    std::fs::canonicalize(s)
}

/// `root/name` when `name` is one plain file or folder name. None for empty names,
/// `.`, anything with `..`, path separators, or NUL.
pub fn child(root: &Path, name: &str) -> Option<PathBuf> {
    if name.is_empty() || name == "." || name.contains("..") || name.contains(['/', '\\', '\0']) {
        return None;
    }
    let p = root.join(name);
    if p.starts_with(root) && p.parent() == Some(root) { Some(p) } else { None }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn child_keeps_plain_names_inside_the_root() {
        let r = Path::new("/srv/data");
        assert_eq!(child(r, "bots"), Some(PathBuf::from("/srv/data/bots")));
        assert_eq!(child(r, "MEMORY.md"), Some(PathBuf::from("/srv/data/MEMORY.md")));
        for bad in ["", ".", "..", "../etc", "a/b", "/etc/passwd", "a\\b", "x..y", "a\0b"] {
            assert_eq!(child(r, bad), None, "{bad:?}");
        }
    }

    #[test]
    fn root_resolves_dots_and_is_canonical() {
        let base = crate::db::temp_path("paths");
        let r = root(&format!("{}/a/../b/./c", base.display())).unwrap();
        assert_eq!(r, std::fs::canonicalize(base.join("b/c")).unwrap());
        assert!(r.is_dir());
        assert!(!base.join("a").exists());
    }
}
