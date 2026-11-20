//! Copying the user's folder onto their machine (ADR 0041), the agent's side. botd
//! sends a manifest (path, size, SHA-256); the agent says which contents it still
//! needs; botd sends those in chunks, which land under the state folder by SHA-256, so
//! a copy cut short picks up where it stopped and sending again changes nothing; then
//! the agent puts each file in place, checked against its hash. A file changed on the
//! machine since the last copy is left as it is, and nothing here is ever deleted.
//! Shared by the agent binary and botd's tests, so it uses nothing of botd's but `wire`.

// Shared by two binaries, each of which uses only part of it.
#![allow(dead_code)]

use super::runas::{self, Ids};
use super::wire::{self, BlobReply, SyncFile, SyncManifest, SyncNeed, SyncPlan, SyncReport};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, RwLock};

/// Hard limits, whatever botd sends. botd's own (`MACHINE_FOLDER_SYNC_MAX_MB`) is lower.
pub const MAX_FILES: usize = 200_000;
pub const MAX_TOTAL: u64 = 100 << 30;
/// Chunks left from a copy that never finished are dropped after a week.
const STALE_SECS: u64 = 7 * 24 * 3600;
const SYNCED: &str = "synced.json";
const MAX_CONFLICTS: usize = 50;

pub type Refused = (u16, String);

struct Active {
    sync_id: String,
    files: Vec<SyncFile>,
    /// The contents still to come, by SHA-256, with their sizes.
    need: HashMap<String, u64>,
}

#[derive(Default)]
struct State {
    active: Option<Active>,
}

pub struct Landing {
    home: PathBuf,
    /// `<state dir>/sync`: `blobs/` and `synced.json`.
    dir: PathBuf,
    state: Mutex<State>,
    /// The Bots' user, who owns the home and everything put there (ADR 0043). The
    /// contents wait in `dir` as root; files in the home are made as this user.
    user: RwLock<Option<Ids>>,
}

fn hex64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

fn plain(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Where a copied file may go: the working folder, the user's facts, or a Bot's memory.
pub fn allowed(p: &str) -> bool {
    if !wire::home_path(p) {
        return false;
    }
    let parts: Vec<&str> = p.split('/').collect();
    match parts.as_slice() {
        ["work", _, ..] => true,
        ["USER.md"] => true,
        ["bots", id, "MEMORY.md"] => plain(id),
        _ => false,
    }
}

fn hash_reader(mut r: impl Read) -> std::io::Result<String> {
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 64 << 10];
    loop {
        let n = r.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(h.finalize().iter().map(|b| format!("{b:02x}")).collect())
}

fn open_nofollow(p: &Path) -> std::io::Result<std::fs::File> {
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(p)
}

pub fn hash_file(p: &Path) -> std::io::Result<String> {
    hash_reader(open_nofollow(p)?)
}

/// What the last copy wrote at a path.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
struct Synced {
    sha256: String,
    exec: bool,
}

/// A file as it was when looked at, to tell whether anyone has touched it since.
#[derive(Clone, Copy, Debug, PartialEq)]
struct Stamp {
    dev: u64,
    ino: u64,
    len: u64,
    mode: u32,
    mtime: (i64, i64),
    ctime: (i64, i64),
}

impl Stamp {
    fn of(m: &std::fs::Metadata) -> Stamp {
        use std::os::unix::fs::MetadataExt;
        Stamp {
            dev: m.dev(),
            ino: m.ino(),
            len: m.len(),
            mode: m.mode(),
            mtime: (m.mtime(), m.mtime_nsec()),
            ctime: (m.ctime(), m.ctime_nsec()),
        }
    }
}

/// A file at a destination: its hash, owner exec bit, and stamp.
#[derive(Clone, Debug, PartialEq)]
struct Here {
    sha256: String,
    exec: bool,
    stamp: Stamp,
}

/// What is at a destination now.
#[derive(Debug, PartialEq)]
enum Dest {
    Missing,
    File(Here),
    /// A link, a folder, or a file where a folder should be: never written through.
    Blocked,
}

fn dest(home: &Path, rel: &str) -> Dest {
    let parts: Vec<&str> = rel.split('/').collect();
    let mut at = home.to_path_buf();
    for (i, part) in parts.iter().enumerate() {
        at.push(part);
        let last = i + 1 == parts.len();
        match std::fs::symlink_metadata(&at) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Dest::Missing,
            Err(_) => return Dest::Blocked,
            Ok(m) if last && m.is_file() => return here(&at).map(Dest::File).unwrap_or(Dest::Blocked),
            Ok(m) if !last && m.is_dir() => {}
            Ok(_) => return Dest::Blocked,
        }
    }
    Dest::Blocked
}

/// Hashes a file, stamping it after so a change while hashing shows as a change later.
fn here(p: &Path) -> std::io::Result<Here> {
    use std::os::unix::fs::PermissionsExt;
    let mut f = open_nofollow(p)?;
    let sha256 = hash_reader(&mut f)?;
    let m = f.metadata()?;
    if !m.is_file() {
        return Err(std::io::Error::other("not a file"));
    }
    Ok(Here {
        sha256,
        exec: m.permissions().mode() & 0o100 != 0,
        stamp: Stamp::of(&m),
    })
}

/// What a copy does with one file.
#[derive(Debug, PartialEq)]
enum Act {
    Write,
    /// Already the same.
    Same,
    /// The same content; only the exec bit changed on the server.
    Exec,
    /// Changed on the machine (or, for a seed, there at all): left alone.
    Keep,
}

/// Why a file wasn't put in place.
enum Missed {
    /// It changed on the machine while the copy was putting it there.
    Raced,
    Failed(String),
}

/// Moves `tmp` to `to` only if nothing is at `to`.
fn rename_noreplace(tmp: &Path, to: &Path) -> std::io::Result<()> {
    use std::os::unix::ffi::OsStrExt;
    let c = |p: &Path| std::ffi::CString::new(p.as_os_str().as_bytes()).map_err(std::io::Error::other);
    let (a, b) = (c(tmp)?, c(to)?);
    // SAFETY: two valid C strings.
    let r = unsafe { libc::renameat2(libc::AT_FDCWD, a.as_ptr(), libc::AT_FDCWD, b.as_ptr(), libc::RENAME_NOREPLACE) };
    if r == 0 { Ok(()) } else { Err(std::io::Error::last_os_error()) }
}

/// Whether the file at `p` is still the one stamped.
fn untouched(p: &Path, was: &Stamp) -> bool {
    std::fs::symlink_metadata(p).is_ok_and(|m| m.is_file() && Stamp::of(&m) == *was)
}

/// Makes the folders above `rel` one at a time, 0700, refusing any that is a link.
fn make_parents(home: &Path, rel: &str) -> std::io::Result<PathBuf> {
    let parts: Vec<&str> = rel.split('/').collect();
    let mut at = home.to_path_buf();
    for part in &parts[..parts.len() - 1] {
        at.push(part);
        match std::fs::symlink_metadata(&at) {
            Ok(m) if m.is_dir() => {}
            Ok(_) => return Err(std::io::Error::other(format!("{} isn't a folder", at.display()))),
            Err(_) => std::fs::DirBuilder::new().mode(0o700).create(&at)?,
        }
    }
    Ok(at)
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

impl Landing {
    pub fn new(home: PathBuf, state_dir: &Path) -> Result<Landing, String> {
        let dir = state_dir.join("sync");
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir.join("blobs"))
            .map_err(|e| format!("{}: {e}", dir.display()))?;
        let l = Landing {
            home,
            dir,
            state: Mutex::default(),
            user: RwLock::default(),
        };
        l.sweep();
        Ok(l)
    }

    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Holds off copies until dropped, while the home changes hands.
    pub fn hold(&self) -> impl Drop + '_ {
        self.state()
    }

    /// From now on, works in the home as `ids`.
    pub fn set_user(&self, ids: Ids) {
        *self.user.write().unwrap_or_else(|e| e.into_inner()) = Some(ids);
    }

    /// Runs `f` with the home's owner's file access.
    fn in_home<T>(&self, f: impl FnOnce() -> T) -> Result<T, String> {
        let ids = *self.user.read().unwrap_or_else(|e| e.into_inner());
        runas::as_user(ids, f).map_err(|e| format!("Couldn't act as the Bots' user: {e}"))
    }

    fn blob(&self, sha: &str, done: bool) -> PathBuf {
        self.dir
            .join("blobs")
            .join(format!("{sha}.{}", if done { "blob" } else { "part" }))
    }

    /// Drops chunks a week old.
    fn sweep(&self) {
        let Ok(entries) = std::fs::read_dir(self.dir.join("blobs")) else {
            return;
        };
        for e in entries.flatten() {
            let old = e
                .metadata()
                .ok()
                .and_then(|m| m.modified().ok())
                .and_then(|t| t.elapsed().ok())
                .is_some_and(|age| age.as_secs() > STALE_SECS);
            if old {
                let _ = std::fs::remove_file(e.path());
            }
        }
    }

    /// The last copy's hash and exec bit of each file it wrote, so a later copy can tell
    /// a file nobody touched (updated) from one changed on the machine (left alone).
    fn synced(&self) -> BTreeMap<String, Synced> {
        std::fs::read(self.dir.join(SYNCED))
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default()
    }

    fn save_synced(&self, s: &BTreeMap<String, Synced>) -> std::io::Result<()> {
        let p = self.dir.join(SYNCED);
        let tmp = self.dir.join(format!("{SYNCED}.tmp"));
        let _ = std::fs::remove_file(&tmp);
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)?;
        f.write_all(&serde_json::to_vec(s).unwrap_or_default())?;
        f.sync_all()?;
        std::fs::rename(tmp, p)
    }

    /// What to do with `f`: write it if nothing is there, or (not a seed) if what is
    /// there, content and exec bit, is what the last copy wrote.
    fn wanted(f: &SyncFile, now: &Dest, synced: &BTreeMap<String, Synced>) -> Act {
        let ours = |h: &Here| {
            synced.get(&f.path)
                == Some(&Synced {
                    sha256: h.sha256.clone(),
                    exec: h.exec,
                })
        };
        match now {
            Dest::Missing => Act::Write,
            Dest::File(h) if h.sha256 == f.sha256 && (f.seed || h.exec == f.exec) => Act::Same,
            Dest::File(h) if !f.seed && ours(h) && h.sha256 == f.sha256 => Act::Exec,
            Dest::File(h) if !f.seed && ours(h) => Act::Write,
            _ => Act::Keep,
        }
    }

    /// `POST /v1/sync`: takes the manifest and says what contents are still needed.
    /// A new manifest replaces one that never finished; its chunks stay.
    pub fn plan(&self, m: SyncManifest) -> Result<SyncPlan, Refused> {
        let bad = |s: String| Err((400, s));
        if !plain(&m.sync_id) {
            return bad("The copy's id isn't a plain name.".into());
        }
        if m.files.len() > MAX_FILES {
            return bad(format!("Over {MAX_FILES} files."));
        }
        let total: u64 = m.files.iter().map(|f| f.size).sum();
        if total > MAX_TOTAL {
            return bad(format!("Over {} GiB.", MAX_TOTAL >> 30));
        }
        let mut seen = HashSet::new();
        for f in &m.files {
            if !allowed(&f.path) || !hex64(&f.sha256) {
                return bad(format!("{} can't be copied here.", f.path));
            }
            if !seen.insert(f.path.as_str()) {
                return bad(format!("{} is listed twice.", f.path));
            }
        }
        let mut st = self.state();
        let synced = self.synced();
        let dests: Vec<Dest> = self
            .in_home(|| m.files.iter().map(|f| dest(&self.home, &f.path)).collect())
            .map_err(|e| (500, e))?;
        let mut need: HashMap<String, u64> = HashMap::new();
        for (f, now) in m.files.iter().zip(&dests) {
            if Self::wanted(f, now, &synced) == Act::Write
                && !self.blob(&f.sha256, true).exists()
            {
                need.insert(f.sha256.clone(), f.size);
            }
        }
        let mut list: Vec<SyncNeed> = need
            .iter()
            .map(|(sha, size)| {
                let part = self.blob(sha, false);
                let mut have = std::fs::symlink_metadata(&part).map_or(0, |m| m.len());
                if have > *size {
                    let _ = std::fs::remove_file(&part);
                    have = 0;
                }
                SyncNeed {
                    sha256: sha.clone(),
                    size: *size,
                    have,
                }
            })
            .collect();
        list.sort_by(|a, b| a.sha256.cmp(&b.sha256));
        st.active = Some(Active {
            sync_id: m.sync_id.clone(),
            files: m.files,
            need,
        });
        Ok(SyncPlan {
            sync_id: m.sync_id,
            need: list,
        })
    }

    /// `PUT /v1/sync/{id}/blobs/{sha}?offset=`: adds a chunk. One at the wrong offset is
    /// refused with what is held, so botd sends from there. Whole, it's checked.
    pub fn put(&self, id: &str, sha: &str, offset: u64, body: &[u8]) -> Result<BlobReply, (Refused, Option<BlobReply>)> {
        let st = self.state();
        let size = match st.active.as_ref() {
            Some(a) if a.sync_id == id => match a.need.get(sha) {
                Some(s) => *s,
                None => return Err(((404, "That content isn't part of this copy.".into()), None)),
            },
            _ => return Err(((404, "No such copy. Start it again.".into()), None)),
        };
        if self.blob(sha, true).exists() {
            return Ok(BlobReply { have: size, done: true });
        }
        let part = self.blob(sha, false);
        let have = std::fs::symlink_metadata(&part).map_or(0, |m| m.len());
        if offset != have {
            return Err((
                (409, format!("Expected offset {have}.")),
                Some(BlobReply { have, done: false }),
            ));
        }
        let io = |e: std::io::Error| ((500, e.to_string()), None);
        if have + body.len() as u64 > size {
            let _ = std::fs::remove_file(&part);
            return Err(((400, "That's more than the file's size.".into()), None));
        }
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .create(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&part)
            .map_err(io)?;
        f.write_all(body).map_err(io)?;
        let have = have + body.len() as u64;
        if have < size {
            return Ok(BlobReply { have, done: false });
        }
        f.sync_all().map_err(io)?;
        let got = hash_file(&part).map_err(io)?;
        if got != sha {
            let _ = std::fs::remove_file(&part);
            return Err(((422, format!("The content's SHA-256 is {got}, not {sha}.")), None));
        }
        std::fs::rename(&part, self.blob(sha, true)).map_err(io)?;
        Ok(BlobReply { have, done: true })
    }

    /// Writes one file next to where it goes, checks it, and moves it into place, only
    /// if what was there (`was`) is still there untouched.
    fn place(&self, f: &SyncFile, was: &Dest) -> Result<(), Missed> {
        let blob = self.blob(&f.sha256, true);
        let from = open_nofollow(&blob).map_err(|_| Missed::Failed(format!("The content of {} hasn't arrived.", f.path)))?;
        self.in_home(|| self.place_from(f, was, from)).map_err(Missed::Failed)?
    }

    fn place_from(&self, f: &SyncFile, was: &Dest, mut from: std::fs::File) -> Result<(), Missed> {
        let fail = |e: String| Missed::Failed(e);
        let parent = make_parents(&self.home, &f.path).map_err(|e| fail(e.to_string()))?;
        let (tmp, mut to) = (0..16)
            .find_map(|_| {
                let mut r = [0u8; 8];
                aws_lc_rs::rand::fill(&mut r).ok()?;
                // Not named after the file: a name near the 255-byte limit leaves no room.
                let tmp = parent.join(format!(".superbot-sync-{:016x}", u64::from_le_bytes(r)));
                let opened = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(if f.exec { 0o700 } else { 0o600 })
                    .custom_flags(libc::O_NOFOLLOW)
                    .open(&tmp);
                match opened {
                    Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => None,
                    other => Some(other.map(|to| (tmp.clone(), to)).map_err(|e| format!("{}: {e}", tmp.display()))),
                }
            })
            .unwrap_or_else(|| Err(format!("No free name next to {}.", f.path)))
            .map_err(fail)?;
        let mut h = Sha256::new();
        let mut buf = vec![0u8; 64 << 10];
        let copied = (|| -> std::io::Result<()> {
            loop {
                let n = from.read(&mut buf)?;
                if n == 0 {
                    break;
                }
                h.update(&buf[..n]);
                to.write_all(&buf[..n])?;
            }
            to.sync_all()
        })();
        let got: String = h.finalize().iter().map(|b| format!("{b:02x}")).collect();
        let drop = |m: Missed| {
            let _ = std::fs::remove_file(&tmp);
            Err(m)
        };
        if let Err(e) = copied {
            return drop(fail(format!("{}: {e}", f.path)));
        }
        if got != f.sha256 {
            return drop(fail(format!("{} didn't match its SHA-256 once written.", f.path)));
        }
        let at = self.home.join(&f.path);
        let moved = match was {
            Dest::Missing => rename_noreplace(&tmp, &at),
            Dest::File(h) if untouched(&at, &h.stamp) => std::fs::rename(&tmp, &at),
            _ => return drop(Missed::Raced),
        };
        match moved {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => drop(Missed::Raced),
            Err(e) => drop(fail(format!("{}: {e}", f.path))),
        }
    }

    /// Sets the owner exec bit of the file at `path`, only if it is still the one stamped.
    fn set_exec(&self, f: &SyncFile, was: &Here) -> Result<(), Missed> {
        use std::os::unix::fs::PermissionsExt;
        let at = self.home.join(&f.path);
        let file = open_nofollow(&at).map_err(|_| Missed::Raced)?;
        let m = file.metadata().map_err(|e| Missed::Failed(e.to_string()))?;
        if !m.is_file() || Stamp::of(&m) != was.stamp {
            return Err(Missed::Raced);
        }
        let mode = m.permissions().mode() & 0o7777;
        let mode = if f.exec { mode | 0o100 } else { mode & !0o100 };
        file.set_permissions(std::fs::Permissions::from_mode(mode))
            .map_err(|e| Missed::Failed(format!("{}: {e}", f.path)))
    }

    /// `POST /v1/sync/{id}/finish`: puts every file in place. What it wrote is
    /// remembered even if it stops partway, so trying again finishes the job.
    pub fn finish(&self, id: &str) -> Result<SyncReport, Refused> {
        let mut st = self.state();
        let active = match st.active.take() {
            Some(a) if a.sync_id == id => a,
            other => {
                st.active = other;
                return Err((404, "No such copy. Start it again.".into()));
            }
        };
        let mut synced = self.synced();
        let mut r = SyncReport {
            sync_id: active.sync_id.clone(),
            ..SyncReport::default()
        };
        let mut failed = None;
        let mine = |f: &SyncFile| Synced {
            sha256: f.sha256.clone(),
            exec: f.exec,
        };
        for f in &active.files {
            let now = match self.in_home(|| dest(&self.home, &f.path)) {
                Ok(now) => now,
                Err(e) => {
                    failed = Some(e);
                    break;
                }
            };
            let done = match (Self::wanted(f, &now, &synced), &now) {
                (Act::Same, _) => {
                    r.unchanged += 1;
                    if !f.seed {
                        synced.insert(f.path.clone(), mine(f));
                    }
                    continue;
                }
                (Act::Write, _) => self.place(f, &now).map(|()| r.bytes += f.size),
                (Act::Exec, Dest::File(h)) => self.in_home(|| self.set_exec(f, h)).unwrap_or_else(|e| Err(Missed::Failed(e))),
                _ => Err(Missed::Raced),
            };
            match done {
                Ok(()) if f.seed => r.seeded += 1,
                Ok(()) => {
                    r.copied += 1;
                    synced.insert(f.path.clone(), mine(f));
                }
                Err(Missed::Failed(e)) => {
                    failed = Some(e);
                    break;
                }
                Err(Missed::Raced) if f.seed => r.kept += 1,
                Err(Missed::Raced) => {
                    r.conflict_count += 1;
                    if r.conflicts.len() < MAX_CONFLICTS {
                        r.conflicts.push(f.path.clone());
                    }
                }
            }
        }
        if let Err(e) = self.save_synced(&synced) {
            failed.get_or_insert(format!("Couldn't save what was copied: {e}"));
        }
        if let Some(e) = failed {
            // The chunks stay, so the next copy needn't send them again.
            st.active = Some(active);
            return Err((500, e));
        }
        for sha in active.files.iter().map(|f| &f.sha256).collect::<HashSet<_>>() {
            let _ = std::fs::remove_file(self.blob(sha, true));
        }
        Ok(r)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(tag: &str) -> PathBuf {
        let t = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let d = std::env::temp_dir().join(format!("superbot-landing-{tag}-{}-{t}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn sha(b: &[u8]) -> String {
        Sha256::digest(b).iter().map(|x| format!("{x:02x}")).collect()
    }

    fn file(path: &str, body: &[u8]) -> SyncFile {
        SyncFile {
            path: path.into(),
            size: body.len() as u64,
            sha256: sha(body),
            exec: false,
            seed: false,
        }
    }

    fn manifest(id: &str, files: &[SyncFile]) -> SyncManifest {
        SyncManifest {
            sync_id: id.into(),
            files: files.to_vec(),
        }
    }

    /// Sends each needed content whole, like botd.
    fn copy(l: &Landing, id: &str, files: &[(&str, &[u8])]) -> SyncReport {
        let fs: Vec<SyncFile> = files.iter().map(|(p, b)| file(p, b)).collect();
        let plan = l.plan(manifest(id, &fs)).unwrap();
        for n in plan.need {
            let body = files.iter().find(|(_, b)| sha(b) == n.sha256).unwrap().1;
            l.put(id, &n.sha256, n.have, &body[n.have as usize..]).unwrap();
        }
        l.finish(id).unwrap()
    }

    #[test]
    fn only_the_working_folder_facts_and_memory_can_be_written() {
        for ok in ["work/a.txt", "work/x/y/z", "USER.md", "bots/b1/MEMORY.md"] {
            assert!(allowed(ok), "{ok}");
        }
        for no in ["work", "work/../x", "/work/a", ".ssh/authorized_keys", "bots/../MEMORY.md", "bots/b1/x", "work/a\nb", "work//a"] {
            assert!(!allowed(no), "{no}");
        }
    }

    #[test]
    fn a_copy_lands_checked_and_a_second_changes_nothing() {
        let (home, state) = (scratch("home"), scratch("state"));
        let l = Landing::new(home.clone(), &state).unwrap();
        let r = copy(&l, "s1", &[("work/a.txt", b"hello"), ("work/d/b.txt", b"there"), ("work/same.txt", b"hello")]);
        assert_eq!((r.copied, r.unchanged, r.conflict_count, r.bytes), (3, 0, 0, 15));
        assert_eq!(std::fs::read(home.join("work/d/b.txt")).unwrap(), b"there");
        let mode = |p: &str| std::os::unix::fs::PermissionsExt::mode(&std::fs::metadata(home.join(p)).unwrap().permissions()) & 0o777;
        assert_eq!((mode("work/a.txt"), mode("work/d")), (0o600, 0o700));
        let plan = l.plan(manifest("s2", &[file("work/a.txt", b"hello")])).unwrap();
        assert!(plan.need.is_empty());
        let r = l.finish("s2").unwrap();
        assert_eq!((r.copied, r.unchanged), (0, 1));
        assert!(std::fs::read_dir(state.join("sync/blobs")).unwrap().next().is_none(), "used chunks are dropped");
    }

    #[test]
    fn a_file_changed_on_the_machine_is_kept_and_an_untouched_one_is_updated() {
        let (home, state) = (scratch("home"), scratch("state"));
        let l = Landing::new(home.clone(), &state).unwrap();
        copy(&l, "s1", &[("work/edited.txt", b"v1"), ("work/plain.txt", b"v1")]);
        std::fs::write(home.join("work/edited.txt"), b"the Bot's edit").unwrap();
        std::fs::write(home.join("work/mine.txt"), b"made on the machine").unwrap();
        let r = copy(&l, "s2", &[("work/edited.txt", b"v2"), ("work/plain.txt", b"v2"), ("work/mine.txt", b"server's")]);
        assert_eq!((r.copied, r.conflict_count), (1, 2));
        assert_eq!(r.conflicts, vec!["work/edited.txt".to_string(), "work/mine.txt".to_string()]);
        assert_eq!(std::fs::read(home.join("work/edited.txt")).unwrap(), b"the Bot's edit");
        assert_eq!(std::fs::read(home.join("work/plain.txt")).unwrap(), b"v2");
    }

    #[test]
    fn seeds_never_replace_and_links_are_never_written_through() {
        let (home, state, outside) = (scratch("home"), scratch("state"), scratch("outside"));
        let l = Landing::new(home.clone(), &state).unwrap();
        std::fs::create_dir_all(home.join("work")).unwrap();
        std::fs::write(home.join("USER.md"), b"machine's facts").unwrap();
        std::os::unix::fs::symlink(&outside, home.join("work/out")).unwrap();
        let mut seeds = vec![file("USER.md", b"botd's facts"), file("bots/b1/MEMORY.md", b"memory")];
        seeds.iter_mut().for_each(|s| s.seed = true);
        let plan = l.plan(manifest("s1", &[seeds.clone(), vec![file("work/out/x", b"escape")]].concat())).unwrap();
        assert_eq!(plan.need.len(), 1, "only the memory: the facts exist and the link is blocked");
        l.put("s1", &plan.need[0].sha256, 0, b"memory").unwrap();
        let r = l.finish("s1").unwrap();
        assert_eq!((r.seeded, r.kept, r.conflict_count), (1, 1, 1));
        assert_eq!(std::fs::read(home.join("USER.md")).unwrap(), b"machine's facts");
        assert_eq!(std::fs::read(home.join("bots/b1/MEMORY.md")).unwrap(), b"memory");
        assert!(!outside.join("x").exists());
    }

    #[test]
    fn a_cut_short_upload_resumes_and_bad_content_is_refused() {
        let (home, state) = (scratch("home"), scratch("state"));
        let l = Landing::new(home.clone(), &state).unwrap();
        let body = b"0123456789".repeat(10);
        let f = file("work/big.bin", &body);
        let plan = l.plan(manifest("s1", std::slice::from_ref(&f))).unwrap();
        assert_eq!(plan.need[0].have, 0);
        assert_eq!(l.put("s1", &f.sha256, 0, &body[..40]).unwrap(), BlobReply { have: 40, done: false });
        let (refused, held) = l.put("s1", &f.sha256, 10, &body[10..]).unwrap_err();
        assert_eq!((refused.0, held.unwrap().have), (409, 40));
        // botd starts over (say, after a restart): the agent still holds the first 40 bytes.
        let plan = l.plan(manifest("s2", std::slice::from_ref(&f))).unwrap();
        assert_eq!(plan.need[0].have, 40);
        assert!(l.put("s2", &f.sha256, 40, &body[40..]).unwrap().done);
        assert_eq!(l.finish("s2").unwrap().copied, 1);
        assert_eq!(std::fs::read(home.join("work/big.bin")).unwrap(), body);

        let wrong = file("work/w.txt", b"right");
        l.plan(manifest("s3", std::slice::from_ref(&wrong))).unwrap();
        assert_eq!(l.put("s3", &wrong.sha256, 0, b"wrong").unwrap_err().0.0, 422);
        assert_eq!(l.put("s3", &wrong.sha256, 0, b"too long").unwrap_err().0.0, 400);
        assert!(l.finish("s3").is_err(), "nothing to put in place");
        assert!(!home.join("work/w.txt").exists());
        assert_eq!(l.put("nope", &wrong.sha256, 0, b"right").unwrap_err().0.0, 404);
    }

    #[test]
    fn an_edit_while_placing_is_kept_and_nothing_next_to_it_is_removed() {
        let (home, state, outside) = (scratch("home"), scratch("state"), scratch("outside"));
        let l = Landing::new(home.clone(), &state).unwrap();
        copy(&l, "s1", &[("work/a.txt", b"v1")]);
        std::fs::write(outside.join("t"), b"theirs").unwrap();
        std::os::unix::fs::symlink(outside.join("t"), home.join("work/.superbot-sync")).unwrap();

        let (a, b) = (file("work/a.txt", b"v2"), file("work/b.txt", b"new"));
        let plan = l.plan(manifest("s2", &[a.clone(), b.clone()])).unwrap();
        for n in &plan.need {
            let body: &[u8] = if n.sha256 == a.sha256 { b"v2" } else { b"new" };
            l.put("s2", &n.sha256, 0, body).unwrap();
        }
        let (was_a, was_b) = (dest(&home, &a.path), dest(&home, &b.path));
        assert!(matches!(was_a, Dest::File(_)) && was_b == Dest::Missing);
        std::thread::sleep(std::time::Duration::from_millis(5));
        std::fs::write(home.join("work/a.txt"), b"edited meanwhile").unwrap();
        std::fs::write(home.join("work/b.txt"), b"made meanwhile").unwrap();
        assert!(matches!(l.place(&a, &was_a), Err(Missed::Raced)));
        assert!(matches!(l.place(&b, &was_b), Err(Missed::Raced)));
        assert_eq!(std::fs::read(home.join("work/a.txt")).unwrap(), b"edited meanwhile");
        assert_eq!(std::fs::read(home.join("work/b.txt")).unwrap(), b"made meanwhile");
        assert_eq!(std::fs::read(outside.join("t")).unwrap(), b"theirs");
        assert!(std::fs::symlink_metadata(home.join("work/.superbot-sync")).unwrap().is_symlink(), "never removed");
        let left: Vec<_> = std::fs::read_dir(home.join("work")).unwrap().flatten().map(|e| e.file_name()).collect();
        assert_eq!(left.len(), 3, "no temp files left behind: {left:?}");
    }

    #[test]
    fn an_exec_bit_changed_on_the_server_follows_unless_changed_on_the_machine() {
        let (home, state) = (scratch("home"), scratch("state"));
        let l = Landing::new(home.clone(), &state).unwrap();
        let mode = |p: &str| std::os::unix::fs::PermissionsExt::mode(&std::fs::metadata(home.join(p)).unwrap().permissions()) & 0o777;
        let run = |id: &str, files: &[SyncFile]| {
            assert!(l.plan(manifest(id, files)).unwrap().need.is_empty());
            l.finish(id).unwrap()
        };
        copy(&l, "s1", &[("work/x.sh", b"echo"), ("work/y.sh", b"echo y")]);
        let (mut x, mut y) = (file("work/x.sh", b"echo"), file("work/y.sh", b"echo y"));
        x.exec = true;
        let r = run("s2", &[x.clone(), y.clone()]);
        assert_eq!((r.copied, r.unchanged, mode("work/x.sh")), (1, 1, 0o700));
        let r = run("s3", &[x.clone(), y.clone()]);
        assert_eq!((r.copied, r.unchanged), (0, 2), "a second copy changes nothing");

        std::fs::set_permissions(home.join("work/y.sh"), std::os::unix::fs::PermissionsExt::from_mode(0o700)).unwrap();
        x.exec = false;
        y.exec = false;
        let r = run("s4", &[x, y]);
        assert_eq!((r.copied, r.conflicts.clone()), (1, vec!["work/y.sh".to_string()]));
        assert_eq!((mode("work/x.sh"), mode("work/y.sh")), (0o600, 0o700));
    }

    #[test]
    fn an_empty_file_and_a_name_at_the_limit_land() {
        let (home, state) = (scratch("home"), scratch("state"));
        let l = Landing::new(home.clone(), &state).unwrap();
        let long = format!("work/{}", "n".repeat(255));
        let r = copy(&l, "s1", &[("work/empty", b""), (&long, b"a name at the limit")]);
        assert_eq!(r.copied, 2);
        assert_eq!(std::fs::read(home.join("work/empty")).unwrap(), b"");
        assert_eq!(std::fs::read(home.join(&long)).unwrap(), b"a name at the limit");
    }

    #[test]
    fn bad_manifests_are_refused() {
        let l = Landing::new(scratch("home"), &scratch("state")).unwrap();
        let ok = file("work/a", b"a");
        let mut bad_sha = ok.clone();
        bad_sha.sha256 = "ABC".into();
        for files in [vec![file("../etc/passwd", b"x")], vec![bad_sha], vec![ok.clone(), ok.clone()]] {
            assert_eq!(l.plan(manifest("s1", &files)).unwrap_err().0, 400);
        }
        assert_eq!(l.plan(manifest("a/b", &[ok])).unwrap_err().0, 400);
    }
}
