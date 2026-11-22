//! Adding up what folders hold, for storage limits (ADR 0082) and the machine agent's
//! report of the homes on a machine (ADR 0105). Shared by botd and the agent binary,
//! so it uses nothing of botd's.

// Shared by two binaries, each of which uses only part of it.
#![allow(dead_code)]

use std::path::PathBuf;

/// Files and folders one measurement visits at most; past it, the total is a lower bound.
pub const MAX_ENTRIES: u64 = 500_000;

/// Adds up file sizes, never following a link (a link counts as itself), and counts each
/// file once across every walk, even when roots overlap or files are hard links. Folders
/// that can't be read, and anything past `max` entries, are left out: the total is partial.
///
/// Bots can change these folders while they're walked, so each folder is opened from its
/// already-open parent, one name at a time, refusing links: one swapped for a link after
/// it was listed can't lead the walk (with the walker's wider access) outside.
pub struct Walker {
    inodes: std::collections::HashSet<(u64, u64)>,
    seen: u64,
    max: u64,
    partial: bool,
}

/// An open folder, and the names in it with what `lstat` says about each.
pub(crate) struct Dir(std::os::fd::OwnedFd);

impl Dir {
    const FLAGS: libc::c_int = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC;

    pub(crate) fn open(path: &std::path::Path) -> std::io::Result<Dir> {
        use std::os::unix::fs::OpenOptionsExt;
        let f = std::fs::OpenOptions::new().read(true).custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW).open(path)?;
        Ok(Dir(f.into()))
    }

    /// The folder `name` in this one; an error if it's anything else now, a link included.
    pub(crate) fn child(&self, name: &std::ffi::CStr) -> std::io::Result<Dir> {
        use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
        // SAFETY: `self.0` is an open folder and `name` a NUL-terminated name.
        let fd = unsafe { libc::openat(self.0.as_raw_fd(), name.as_ptr(), Self::FLAGS) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: openat returned a new descriptor that nothing else owns.
        Ok(Dir(unsafe { OwnedFd::from_raw_fd(fd) }))
    }

    /// Each name here (not `.` or `..`) with its `lstat`, or None where that failed; at
    /// most `limit` of them, so a folder of millions is never read whole.
    pub(crate) fn entries(&self, limit: u64) -> std::io::Result<Vec<(std::ffi::CString, Option<libc::stat>)>> {
        use std::os::fd::{AsRawFd, IntoRawFd};
        let dup = self.0.try_clone()?.into_raw_fd();
        // SAFETY: `dup` is an open folder that the stream now owns and closes.
        let stream = unsafe { libc::fdopendir(dup) };
        if stream.is_null() {
            let e = std::io::Error::last_os_error();
            // SAFETY: fdopendir failed, so `dup` is still ours to close.
            unsafe { libc::close(dup) };
            return Err(e);
        }
        // The copy shares the folder's read position: start from the top.
        // SAFETY: `stream` is open.
        unsafe { libc::rewinddir(stream) };
        let mut out = Vec::new();
        while (out.len() as u64) < limit {
            // SAFETY: `stream` is open; the entry is read before the next call.
            let e = unsafe { libc::readdir(stream) };
            if e.is_null() {
                break;
            }
            // SAFETY: `d_name` is NUL-terminated within the entry.
            let name = unsafe { std::ffi::CStr::from_ptr((*e).d_name.as_ptr()) };
            if name == c"." || name == c".." {
                continue;
            }
            // SAFETY: an all-zero stat is valid; fstatat fills it in.
            let mut st: libc::stat = unsafe { std::mem::zeroed() };
            // SAFETY: as above; AT_SYMLINK_NOFOLLOW describes a link, not its target.
            let ok = unsafe { libc::fstatat(self.0.as_raw_fd(), name.as_ptr(), &mut st, libc::AT_SYMLINK_NOFOLLOW) } == 0;
            out.push((name.to_owned(), ok.then_some(st)));
        }
        // SAFETY: `stream` is open and closed once.
        unsafe { libc::closedir(stream) };
        Ok(out)
    }
}

impl Walker {
    pub fn new(max: u64) -> Walker {
        Walker { inodes: Default::default(), seen: 0, max, partial: false }
    }

    /// Whether some of what was walked couldn't be read, or there was too much.
    pub fn partial(&self) -> bool {
        self.partial
    }

    fn size(&mut self, dev: u64, ino: u64, len: u64) -> u64 {
        if self.inodes.insert((dev, ino)) { len } else { 0 }
    }

    /// The bytes under `roots` not counted by an earlier call. Blocking.
    pub fn add(&mut self, roots: &[PathBuf]) -> u64 {
        use std::os::unix::fs::MetadataExt;
        use std::rc::Rc;
        let mut total = 0u64;
        // Folders still to list. Each queued name is opened from its parent, which stays
        // open until its last child is: as many open folders as the walk is deep.
        let mut stack: Vec<Rc<Dir>> = Vec::new();
        let mut queued: Vec<(Rc<Dir>, std::ffi::CString)> = Vec::new();
        for r in roots {
            match std::fs::symlink_metadata(r) {
                Ok(m) if m.is_dir() => match Dir::open(r) {
                    Ok(d) => stack.push(Rc::new(d)),
                    Err(_) => self.partial = true,
                },
                Ok(m) => total = total.saturating_add(self.size(m.dev(), m.ino(), m.len())),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => self.partial = true,
            }
        }
        loop {
            let dir = match stack.pop() {
                Some(d) => d,
                None => match queued.pop() {
                    Some((parent, name)) => match parent.child(&name) {
                        Ok(d) => Rc::new(d),
                        // Gone, or now a file or a link: not a folder to walk any more.
                        Err(e) if matches!(e.raw_os_error(), Some(libc::ENOENT | libc::ENOTDIR | libc::ELOOP)) => continue,
                        Err(_) => {
                            self.partial = true;
                            continue;
                        }
                    },
                    None => break,
                },
            };
            // One past what's left, so going over the cap is noticed below.
            let Ok(entries) = dir.entries(self.max.saturating_sub(self.seen).saturating_add(1)) else {
                self.partial = true;
                continue;
            };
            for (name, st) in entries {
                self.seen += 1;
                if self.seen > self.max {
                    self.partial = true;
                    return total;
                }
                let Some(st) = st else {
                    self.partial = true;
                    continue;
                };
                if st.st_mode & libc::S_IFMT == libc::S_IFDIR {
                    queued.push((dir.clone(), name));
                } else {
                    #[allow(clippy::unnecessary_cast)]
                    let (dev, ino, len) = (st.st_dev as u64, st.st_ino as u64, st.st_size.max(0) as u64);
                    total = total.saturating_add(self.size(dev, ino, len));
                }
            }
        }
        total
    }
}

/// The bytes under `roots`, and whether that's a lower bound. Blocking.
pub fn walk(roots: &[PathBuf], max: u64) -> (u64, bool) {
    let mut w = Walker::new(max);
    let n = w.add(roots);
    (n, w.partial)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp(name: &str) -> PathBuf {
        let at = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_nanos();
        let p = std::env::temp_dir().join(format!("superbot-{name}-{}-{at}", std::process::id()));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn walking_counts_files_once_and_never_follows_links() {
        let root = temp("storage-walk");
        let mine = root.join("mine");
        let theirs = root.join("theirs");
        std::fs::create_dir_all(mine.join("deep/er")).unwrap();
        std::fs::create_dir_all(&theirs).unwrap();
        std::fs::write(mine.join("a.txt"), vec![0u8; 1000]).unwrap();
        std::fs::write(mine.join("deep/er/b.bin"), vec![0u8; 2500]).unwrap();
        std::fs::write(theirs.join("big"), vec![0u8; 1_000_000]).unwrap();
        // A link to someone else's folder or file counts as the link, not what it points at.
        std::os::unix::fs::symlink(&theirs, mine.join("to-theirs")).unwrap();
        std::os::unix::fs::symlink(theirs.join("big"), mine.join("big-link")).unwrap();
        // A hard link is the same file: counted once.
        std::fs::hard_link(mine.join("a.txt"), mine.join("deep/a-again.txt")).unwrap();
        let (n, partial) = walk(std::slice::from_ref(&mine), MAX_ENTRIES);
        assert!(!partial);
        let links = std::fs::symlink_metadata(mine.join("to-theirs")).unwrap().len() + std::fs::symlink_metadata(mine.join("big-link")).unwrap().len();
        assert_eq!(n, 3500 + links);
        // A root that isn't there is nothing; overlapping roots count once.
        assert_eq!(walk(&[root.join("nope")], MAX_ENTRIES), (0, false));
        assert_eq!(walk(&[mine.clone(), mine.join("deep")], MAX_ENTRIES).0, n);
        // Too much to walk: a lower bound, said to be one.
        let (some, partial) = walk(std::slice::from_ref(&mine), 2);
        assert!(partial && some <= n);
        // A folder bigger than what's left is read only that far.
        let dir = Dir::open(&mine).unwrap();
        assert_eq!(dir.entries(2).unwrap().len(), 2);
        assert_eq!(dir.entries(100).unwrap().len(), 4);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_folder_it_cant_read_makes_it_partial() {
        use std::os::unix::fs::PermissionsExt;
        if nix_root() {
            return; // root reads everything
        }
        let root = temp("storage-locked");
        std::fs::create_dir_all(root.join("locked")).unwrap();
        std::fs::write(root.join("open.txt"), vec![0u8; 10]).unwrap();
        std::fs::write(root.join("locked/x"), vec![0u8; 10]).unwrap();
        std::fs::set_permissions(root.join("locked"), std::fs::Permissions::from_mode(0o000)).unwrap();
        let (n, partial) = walk(std::slice::from_ref(&root), MAX_ENTRIES);
        std::fs::set_permissions(root.join("locked"), std::fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!((n, partial), (10, true));
        let _ = std::fs::remove_dir_all(&root);
    }

    fn nix_root() -> bool {
        std::fs::read_to_string("/proc/self/status").is_ok_and(|s| s.lines().any(|l| l.starts_with("Uid:") && l.split_whitespace().nth(1) == Some("0")))
    }

    #[test]
    fn a_folder_swapped_for_a_link_isnt_opened() {
        let root = temp("storage-swap");
        std::fs::create_dir_all(root.join("mine/sub")).unwrap();
        std::fs::create_dir_all(root.join("theirs")).unwrap();
        let dir = Dir::open(&root.join("mine")).unwrap();
        assert!(dir.child(c"sub").is_ok());
        // Listed as a folder, then swapped for a link before it's opened.
        std::fs::remove_dir(root.join("mine/sub")).unwrap();
        std::os::unix::fs::symlink(root.join("theirs"), root.join("mine/sub")).unwrap();
        assert!(matches!(dir.child(c"sub").err().and_then(|e| e.raw_os_error()), Some(libc::ENOTDIR | libc::ELOOP)));
        // A root that's a link isn't walked either.
        assert!(Dir::open(&root.join("mine/sub")).is_err());
        let _ = std::fs::remove_dir_all(&root);
    }
}
