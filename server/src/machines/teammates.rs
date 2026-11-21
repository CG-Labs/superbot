//! Teammates' own OS users on a machine (ADR 0048). When someone other than the
//! machine's user runs one of that user's shared Bots there, the run gets an OS user and
//! home of its own (`superbot-t-<hash of their id>`, home `<state>/teammates/<that>`),
//! never the Bots' user (ADR 0043) the owner's runs share. The owner's home (their
//! folder copy, harness logins, facts, the Bots' memory) is `0700` the Bots' user's, so
//! a teammate's run can't open it; theirs is `0700` theirs, so the owner's runs can't
//! open it either. Each teammate's user is recorded the first time it's made, and
//! checked against that record after, so a user someone else made by that name is
//! never taken for theirs. When a teammate leaves (ADR 0052), `remove` stops their
//! processes, takes their `work` folder aside (to be archived to the owner, held, or
//! deleted), deletes the rest of their home and their user, and drops their record.
//! Shared by the agent binary and botd's tests.

// Shared by two binaries, each of which uses only part of it.
#![allow(dead_code)]

use super::runas::{self, Ids};
use super::wire;
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{DirBuilderExt, MetadataExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

const RECORD: &str = "teammates.json";
/// Removals done, by cleanup id (the last `KEEP_REMOVED`), in the state folder too.
const REMOVED: &str = "teammates-removed.json";
const KEEP_REMOVED: usize = 1000;
/// In the teammates' folder: work removals took aside, one folder per removal. Root's,
/// `0700`; never a teammate's user name.
const LEFT: &str = ".left";
/// Where teammates leave files besides their home.
const TEMP_DIRS: [&str; 3] = ["/tmp", "/var/tmp", "/dev/shm"];

/// Finds, makes and removes OS users, and stops their processes. The system's on a
/// machine; tests, which can't make users, use a stand-in or a fake.
pub trait OsUsers: Send + Sync {
    fn lookup(&self, name: &str) -> Option<Ids>;
    fn add(&self, name: &str, home: &Path) -> Result<Ids, String>;
    /// Whether it deleted the user.
    fn remove(&self, name: &str) -> Result<bool, String>;
    /// Stops every process running as `uid`. How many it stopped.
    fn stop_all(&self, uid: u32) -> Result<u32, String>;
    /// Deletes what `uid` owns at the top of the shared temporary folders. How many.
    fn clear_temp(&self, uid: u32) -> u32;
}

/// The machine's own users and processes.
pub struct System;

impl OsUsers for System {
    fn lookup(&self, name: &str) -> Option<Ids> {
        runas::lookup(name).map(|(ids, _)| ids)
    }

    fn add(&self, name: &str, home: &Path) -> Result<Ids, String> {
        runas::ensure_user_as(name, home, "SuperBot teammate")
    }

    fn remove(&self, name: &str) -> Result<bool, String> {
        runas::remove_user(name).map(|()| true)
    }

    fn stop_all(&self, uid: u32) -> Result<u32, String> {
        let mut stopped = BTreeSet::new();
        for _ in 0..50 {
            let left = pids_of(uid);
            if left.is_empty() {
                return Ok(stopped.len() as u32);
            }
            for pid in left {
                // A pid can be reused once its process is gone, so it's signalled
                // through a pidfd, opened before its owner is checked again: while the
                // process the pidfd names is alive (as the signal needs), the pid is its.
                // SAFETY: plain integers; the descriptor is owned on success.
                let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid as libc::c_long, 0 as libc::c_long) };
                if fd < 0 {
                    let e = std::io::Error::last_os_error();
                    if e.raw_os_error() == Some(libc::ENOSYS) {
                        return Err("this kernel can't stop processes safely (needs Linux 5.3 or later)".into());
                    }
                    continue;
                }
                // SAFETY: a new descriptor, owned only here.
                let fd = unsafe { std::os::fd::OwnedFd::from_raw_fd(fd as libc::c_int) };
                if !runs_as(pid, uid) {
                    continue;
                }
                // SAFETY: an open pidfd, a signal number and no extra info.
                let sent = unsafe {
                    libc::syscall(libc::SYS_pidfd_send_signal, fd.as_raw_fd() as libc::c_long, libc::SIGKILL as libc::c_long, std::ptr::null::<libc::siginfo_t>(), 0 as libc::c_long)
                };
                if sent == 0 {
                    stopped.insert(pid);
                }
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        Err(format!("processes of uid {uid} kept running"))
    }

    fn clear_temp(&self, uid: u32) -> u32 {
        let mut n = 0;
        for dir in TEMP_DIRS {
            let Ok(entries) = std::fs::read_dir(dir) else {
                continue;
            };
            for e in entries.flatten() {
                let p = e.path();
                let Ok(m) = std::fs::symlink_metadata(&p) else {
                    continue;
                };
                if m.uid() != uid {
                    continue;
                }
                // remove_dir_all never follows a link, and their processes are stopped,
                // so nothing swaps one in meanwhile.
                let gone = if m.is_dir() {
                    std::fs::remove_dir_all(&p)
                } else {
                    std::fs::remove_file(&p)
                };
                n += gone.is_ok() as u32;
            }
        }
        n
    }
}

/// Running processes whose real, effective or saved uid is `uid`, but not zombies
/// (they're gone; their parent just hasn't been told), init, or this agent.
fn pids_of(uid: u32) -> Vec<u32> {
    let me = std::process::id();
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return Vec::new();
    };
    entries
        .flatten()
        .filter_map(|e| e.file_name().to_str()?.parse::<u32>().ok())
        .filter(|pid| *pid > 1 && *pid != me)
        .filter(|pid| runs_as(*pid, uid))
        .collect()
}

/// Whether `pid` is a live process whose real, effective or saved uid is `uid`.
fn runs_as(pid: u32, uid: u32) -> bool {
    let Ok(s) = std::fs::read_to_string(format!("/proc/{pid}/status")) else {
        return false;
    };
    let uid = uid.to_string();
    let zombie = s
        .lines()
        .find_map(|l| l.strip_prefix("State:"))
        .is_some_and(|st| st.trim_start().starts_with('Z'));
    let theirs = s
        .lines()
        .find_map(|l| l.strip_prefix("Uid:"))
        .is_some_and(|ids| ids.split_whitespace().take(3).any(|i| i == uid));
    theirs && !zombie
}

/// Every teammate runs as one existing user (whoever runs the tests): nothing is made,
/// deleted or stopped.
pub struct StandIn;

impl OsUsers for StandIn {
    fn lookup(&self, name: &str) -> Option<Ids> {
        runas::lookup(name).map(|(ids, _)| ids)
    }

    fn add(&self, name: &str, _home: &Path) -> Result<Ids, String> {
        self.lookup(name).ok_or_else(|| format!("no user {name} to stand in"))
    }

    fn remove(&self, _name: &str) -> Result<bool, String> {
        Ok(false)
    }

    fn stop_all(&self, _uid: u32) -> Result<u32, String> {
        Ok(0)
    }

    fn clear_temp(&self, _uid: u32) -> u32 {
        0
    }
}

/// What becomes of a leaving teammate's `work` folder.
#[derive(Clone, Debug, PartialEq)]
pub enum Files {
    /// To `<home>/work/from-teammates/<name>`, given to `ids` (the Bots' user), so the
    /// owner's Bots have it.
    Archive { home: PathBuf, ids: Ids, name: String },
    /// Aside, root's alone, until `purge`.
    Hold,
    Delete,
}

/// What `remove` did.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Removal {
    pub user: String,
    pub already_gone: bool,
    pub user_removed: bool,
    pub processes_stopped: u32,
    pub temp_removed: u32,
    /// `archived`, `held`, `deleted` or `none`.
    pub files: &'static str,
    pub archived_to: Option<PathBuf>,
}

impl Removal {
    pub fn reply(&self, jobs_stopped: u32, screens_stopped: u32) -> wire::TeammateRemoved {
        wire::TeammateRemoved {
            user: self.user.clone(),
            already_gone: self.already_gone,
            user_removed: self.user_removed,
            jobs_stopped,
            screens_stopped,
            processes_stopped: self.processes_stopped,
            temp_removed: self.temp_removed,
            files: self.files.into(),
            archived_to: self.archived_to.as_ref().map(|p| p.display().to_string()),
        }
    }
}

/// While it lives, the teammate is being removed: no run or screen of theirs starts.
pub struct Leaving<'a>(&'a Teammates, String);

impl Drop for Leaving<'_> {
    fn drop(&mut self) {
        self.0.leaving().remove(&self.1);
    }
}

/// A teammate's user on this machine, ready for their runs.
#[derive(Clone, Debug, PartialEq)]
pub struct Teammate {
    pub user: String,
    pub ids: Ids,
    pub home: PathBuf,
    /// Made just now.
    pub created: bool,
}

impl Teammate {
    pub fn workspace(&self) -> PathBuf {
        self.home.join("work")
    }

    pub fn bots(&self) -> PathBuf {
        self.home.join("bots")
    }

    pub fn reply(&self) -> wire::TeammateReply {
        let p = |p: PathBuf| p.display().to_string();
        wire::TeammateReply {
            user: self.user.clone(),
            uid: self.ids.uid,
            home: p(self.home.clone()),
            workspace: p(self.workspace()),
            bots: p(self.bots()),
            created: self.created,
            logins: Default::default(),
        }
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
struct Saved {
    user: String,
    uid: u32,
    gid: u32,
}

/// A removal done, kept by its cleanup id so asking again repeats its answer.
#[derive(serde::Serialize, serde::Deserialize)]
struct Removed {
    user_id: String,
    user: String,
    files: String,
    archived_to: Option<PathBuf>,
    at: i64,
}

impl Removed {
    fn of(user_id: &str, r: &Removal) -> Removed {
        let at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_millis() as i64);
        Removed {
            user_id: user_id.to_string(),
            user: r.user.clone(),
            files: r.files.to_string(),
            archived_to: r.archived_to.clone(),
            at,
        }
    }

    fn replay(&self) -> Removal {
        Removal {
            user: self.user.clone(),
            already_gone: true,
            files: match self.files.as_str() {
                "archived" => "archived",
                "held" => "held",
                "deleted" => "deleted",
                _ => "none",
            },
            archived_to: self.archived_to.clone(),
            ..Removal::default()
        }
    }
}

/// Writes `body` to `path` (0600) whole or not at all.
fn write_private(path: &Path, body: &[u8]) -> Result<(), String> {
    let tmp = path.with_extension("tmp");
    let write = || -> std::io::Result<()> {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let _ = std::fs::remove_file(&tmp);
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)?;
        f.write_all(body)?;
        f.sync_all()?;
        std::fs::rename(&tmp, path)
    };
    write().map_err(|e| format!("{}: {e}", path.display()))
}

pub struct Teammates {
    /// Holds one home per teammate. Root's, `0711`: each can pass to their own.
    root: PathBuf,
    /// The agent's state folder, where the record is kept (root's, `0600`).
    state_dir: PathBuf,
    /// Tests can't make users: every teammate runs as this existing one instead.
    stand_in: Option<String>,
    os_users: Arc<dyn OsUsers>,
    /// One teammate made or removed at a time, and the record written by one at a time.
    making: Mutex<()>,
    /// Teammates being removed now, by id.
    leaving: Mutex<HashSet<String>>,
}

impl Teammates {
    pub fn new(root: PathBuf, state_dir: PathBuf, stand_in: Option<String>) -> Teammates {
        let os_users: Arc<dyn OsUsers> = if stand_in.is_some() {
            Arc::new(StandIn)
        } else {
            Arc::new(System)
        };
        Teammates::with_os_users(root, state_dir, stand_in, os_users)
    }

    pub fn with_os_users(
        root: PathBuf,
        state_dir: PathBuf,
        stand_in: Option<String>,
        os_users: Arc<dyn OsUsers>,
    ) -> Teammates {
        Teammates {
            root,
            state_dir,
            stand_in,
            os_users,
            making: Mutex::new(()),
            leaving: Mutex::default(),
        }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    fn leaving(&self) -> std::sync::MutexGuard<'_, HashSet<String>> {
        self.leaving.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Marks `user_id` as leaving until the guard drops. None if they already are.
    pub fn start_leaving(&self, user_id: &str) -> Option<Leaving<'_>> {
        self.leaving()
            .insert(user_id.to_string())
            .then(|| Leaving(self, user_id.to_string()))
    }

    pub fn is_leaving(&self, user_id: &str) -> bool {
        self.leaving().contains(user_id)
    }

    /// The ids of the teammates who have a user here.
    pub fn known(&self) -> Vec<String> {
        self.record()
            .map(|r| r.into_keys().collect())
            .unwrap_or_default()
    }

    /// Where removal `cleanup_id` keeps the work it took aside.
    pub fn held(&self, cleanup_id: &str) -> PathBuf {
        self.root.join(LEFT).join(cleanup_id)
    }

    fn record(&self) -> Result<BTreeMap<String, Saved>, String> {
        let path = self.state_dir.join(RECORD);
        match std::fs::read(&path) {
            Ok(b) => serde_json::from_slice(&b).map_err(|e| format!("{}: {e}", path.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(BTreeMap::new()),
            Err(e) => Err(format!("{}: {e}", path.display())),
        }
    }

    fn save(&self, r: &BTreeMap<String, Saved>) -> Result<(), String> {
        let body = serde_json::to_vec(r).map_err(|e| e.to_string())?;
        write_private(&self.state_dir.join(RECORD), &body)
    }

    /// Where `user_id`'s home is, whether or not it's made yet.
    pub fn home_of(&self, user_id: &str) -> PathBuf {
        self.root.join(wire::teammate_user(user_id))
    }

    /// `user_id`'s user and home if they have them here, never made: still the user
    /// recorded for them, passing `check`, with a home that's a folder of theirs (not a
    /// link). None if any of that isn't so.
    pub fn existing(&self, user_id: &str, check: impl Fn(Ids) -> Result<(), String>) -> Option<Teammate> {
        let _one = self.making.lock().unwrap_or_else(|e| e.into_inner());
        if self.leaving().contains(user_id) {
            return None;
        }
        let s = self.record().ok()?.remove(user_id)?;
        let ids = Ids { uid: s.uid, gid: s.gid };
        let name = self.stand_in.clone().unwrap_or_else(|| wire::teammate_user(user_id));
        if s.user != name || self.os_users.lookup(&s.user) != Some(ids) || check(ids).is_err() {
            return None;
        }
        let home = self.home_of(user_id);
        let theirs = std::fs::symlink_metadata(&home).is_ok_and(|m| m.is_dir() && m.uid() == ids.uid);
        theirs.then_some(Teammate { user: s.user, ids, home, created: false })
    }

    /// `user_id`'s user and home, made if this is their first run here. `check` refuses
    /// ids that must never be a teammate's (root, the agent's, the Bots' user's).
    pub fn ensure(
        &self,
        user_id: &str,
        check: impl Fn(Ids) -> Result<(), String>,
    ) -> Result<Teammate, String> {
        let _one = self.making.lock().unwrap_or_else(|e| e.into_inner());
        // Checked under the lock, so a request that waited out a removal can't undo it.
        if self.leaving().contains(user_id) {
            return Err("that teammate's user is being removed".into());
        }
        let name = self
            .stand_in
            .clone()
            .unwrap_or_else(|| wire::teammate_user(user_id));
        let home = self.home_of(user_id);
        let mut record = self.record()?;
        // A removal that deleted the user and home but stopped before dropping the
        // record leaves nothing of theirs: start again rather than refuse for good.
        if record.get(user_id).is_some_and(|s| self.os_users.lookup(&s.user).is_none())
            && std::fs::symlink_metadata(&home).is_err()
        {
            record.remove(user_id);
            self.save(&record)?;
        }
        let (ids, created) = match record.get(user_id) {
            Some(s) => {
                let want = Ids {
                    uid: s.uid,
                    gid: s.gid,
                };
                match self.os_users.lookup(&s.user) {
                    Some(ids) if s.user == name && ids == want => (want, false),
                    Some(_) => return Err(format!("{} isn't the user it was.", s.user)),
                    None => return Err(format!("{} is gone.", s.user)),
                }
            }
            None => {
                if self.stand_in.is_none() && self.os_users.lookup(&name).is_some() {
                    return Err(format!(
                        "{name} is already a user here, but this agent didn't make it for that teammate."
                    ));
                }
                let ids = self.os_users.add(&name, &home)?;
                record.insert(
                    user_id.to_string(),
                    Saved {
                        user: name.clone(),
                        uid: ids.uid,
                        gid: ids.gid,
                    },
                );
                // A user left without its record would be refused as someone else's
                // on every later try, so one that can't be kept is taken back.
                if let Err(e) = check(ids).and_then(|_| self.save(&record)) {
                    if self.stand_in.is_none()
                        && let Err(undo) = self.os_users.remove(&name)
                    {
                        return Err(format!("{e}; and couldn't remove {name}: {undo}"));
                    }
                    return Err(e);
                }
                (ids, true)
            }
        };
        check(ids)?;
        self.make_home(&home, ids)?;
        Ok(Teammate {
            user: name,
            ids,
            home,
            created,
        })
    }

    /// The teammates' folder (root's, `0711`) and this teammate's home in it (theirs,
    /// `0700`), with their working and Bots' folders. A home that's someone else's, or a
    /// link, is refused rather than taken over.
    fn make_home(&self, home: &Path, ids: Ids) -> Result<(), String> {
        let at = |p: &Path, e: std::io::Error| format!("{}: {e}", p.display());
        match std::fs::symlink_metadata(&self.root) {
            Ok(m) if m.is_dir() => {}
            Ok(_) => return Err(format!("{} isn't a folder.", self.root.display())),
            Err(_) => std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o711)
                .create(&self.root)
                .map_err(|e| at(&self.root, e))?,
        }
        runas::chmod_dir(&self.root, 0o711).map_err(|e| at(&self.root, e))?;
        match std::fs::symlink_metadata(home) {
            Ok(m) if m.is_dir() && m.uid() == ids.uid => {}
            Ok(_) => {
                return Err(format!(
                    "{} belongs to someone else, or isn't a folder.",
                    home.display()
                ));
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                std::fs::DirBuilder::new()
                    .mode(0o700)
                    .create(home)
                    .map_err(|e| at(home, e))?;
                runas::hand_over(home, ids).map_err(|e| at(home, e))?;
            }
            Err(e) => return Err(at(home, e)),
        }
        runas::as_user(Some(ids), || -> std::io::Result<()> {
            for d in [home.join("work"), home.join("bots")] {
                std::fs::DirBuilder::new()
                    .recursive(true)
                    .mode(0o700)
                    .create(d)?;
            }
            Ok(())
        })
        .and_then(|r| r)
        .map_err(|e| at(home, e))
    }

    /// `user_id` left (ADR 0052): their processes stop, their `work` folder goes where
    /// `files` says, and the rest of their home, their files in temporary folders,
    /// their user and their record go. Only a user this agent recorded for them is
    /// stopped or deleted, and only if it's still the one recorded and `check` passes.
    /// Each step can be done again, so a removal that failed part-way is finished by
    /// asking again with the same `cleanup_id`; once done, asking again changes nothing.
    pub fn remove(
        &self,
        user_id: &str,
        cleanup_id: &str,
        files: &Files,
        check: impl Fn(Ids) -> Result<(), String>,
    ) -> Result<Removal, String> {
        let _one = self.making.lock().unwrap_or_else(|e| e.into_inner());
        // Done before, with its answer lost: say so again. A user made for them since
        // is a new one, and isn't this removal's to delete.
        let mut done = self.removed()?;
        if let Some(d) = done.get(cleanup_id).filter(|d| d.user_id == user_id) {
            return Ok(d.replay());
        }
        let mut record = self.record()?;
        let home = self.home_of(user_id);
        let held = self.held(cleanup_id);
        let at = |p: &Path, e: std::io::Error| format!("{}: {e}", p.display());
        let saved = record.get(user_id);
        let mut out = Removal {
            user: saved.map_or_else(|| wire::teammate_user(user_id), |s| s.user.clone()),
            files: "none",
            ..Removal::default()
        };
        let there = |p: &Path| std::fs::symlink_metadata(p).is_ok();
        if saved.is_none() && !there(&home) && !there(&held) {
            out.already_gone = true;
            return Ok(out);
        }
        // A user by that name that isn't the recorded one isn't theirs: left alone.
        let ids = match saved {
            Some(s) => {
                let want = Ids {
                    uid: s.uid,
                    gid: s.gid,
                };
                match self.os_users.lookup(&s.user) {
                    Some(ids) if ids == want => {
                        check(want)?;
                        Some(want)
                    }
                    Some(_) => return Err(format!("{} isn't the user it was; left alone.", s.user)),
                    None => None,
                }
            }
            None => None,
        };
        if let Some(ids) = ids {
            out.processes_stopped = self.os_users.stop_all(ids.uid)?;
        }
        // The teammates' folder is root's, so their home can't be swapped for a link;
        // `work` in it can, and a rename moves the link, not what it points to.
        match std::fs::symlink_metadata(&home) {
            Ok(m) if m.is_dir() => {
                let work = home.join("work");
                if there(&work) {
                    if there(&held) {
                        return Err(format!("{} is there already.", held.display()));
                    }
                    self.make_left()?;
                    std::fs::rename(&work, &held).map_err(|e| at(&work, e))?;
                }
                std::fs::remove_dir_all(&home).map_err(|e| at(&home, e))?;
            }
            Ok(_) => std::fs::remove_file(&home).map_err(|e| at(&home, e))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(at(&home, e)),
        }
        if let Some(ids) = ids {
            out.temp_removed = self.os_users.clear_temp(ids.uid);
            out.user_removed = self.os_users.remove(&out.user)?;
        }
        let their_uid = saved.map(|s| s.uid);
        out.files = match std::fs::symlink_metadata(&held) {
            Err(_) => "none",
            Ok(m) if !m.is_dir() => {
                std::fs::remove_file(&held).map_err(|e| at(&held, e))?;
                "none"
            }
            Ok(_) => match files {
                Files::Archive { home, ids, name } => {
                    // Their user is gone and the folder is root's: nothing changes it now.
                    if let Some(uid) = their_uid {
                        runas::unshare_links(&held, uid).map_err(|e| at(&held, e))?;
                    }
                    runas::hand_over(&held, *ids).map_err(|e| at(&held, e))?;
                    let to = runas::move_into(
                        &held,
                        home,
                        &["work", wire::TEAMMATE_ARCHIVE_DIR],
                        name,
                        *ids,
                    )
                    .map_err(|e| format!("moving their work to {}: {e}", home.display()))?;
                    out.archived_to = Some(to);
                    "archived"
                }
                Files::Hold => {
                    runas::hand_over(&held, own_ids()).map_err(|e| at(&held, e))?;
                    "held"
                }
                Files::Delete => {
                    std::fs::remove_dir_all(&held).map_err(|e| at(&held, e))?;
                    "deleted"
                }
            },
        };
        if record.remove(user_id).is_some() {
            self.save(&record)?;
        }
        done.insert(cleanup_id.to_string(), Removed::of(user_id, &out));
        while done.len() > KEEP_REMOVED {
            let oldest = done.iter().min_by_key(|(_, d)| d.at).map(|(k, _)| k.clone());
            oldest.map(|k| done.remove(&k));
        }
        self.save_removed(&done)?;
        Ok(out)
    }

    fn removed(&self) -> Result<BTreeMap<String, Removed>, String> {
        let path = self.state_dir.join(REMOVED);
        match std::fs::read(&path) {
            Ok(b) => serde_json::from_slice(&b).map_err(|e| format!("{}: {e}", path.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(BTreeMap::new()),
            Err(e) => Err(format!("{}: {e}", path.display())),
        }
    }

    fn save_removed(&self, r: &BTreeMap<String, Removed>) -> Result<(), String> {
        let body = serde_json::to_vec(r).map_err(|e| e.to_string())?;
        write_private(&self.state_dir.join(REMOVED), &body)
    }

    /// Deletes the work removal `cleanup_id` held aside. Whether there was any.
    pub fn purge(&self, cleanup_id: &str) -> Result<bool, String> {
        let _one = self.making.lock().unwrap_or_else(|e| e.into_inner());
        let held = self.held(cleanup_id);
        let at = |e: std::io::Error| format!("{}: {e}", held.display());
        match std::fs::symlink_metadata(&held) {
            Ok(m) if m.is_dir() => std::fs::remove_dir_all(&held).map_err(at).map(|()| true),
            Ok(_) => std::fs::remove_file(&held).map_err(at).map(|()| true),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(at(e)),
        }
    }

    /// The folder held work waits in: root's, `0700`, never a link.
    fn make_left(&self) -> Result<(), String> {
        let left = self.root.join(LEFT);
        let at = |e: std::io::Error| format!("{}: {e}", left.display());
        match std::fs::symlink_metadata(&left) {
            Ok(m) if m.is_dir() => {}
            Ok(_) => return Err(format!("{} isn't a folder.", left.display())),
            Err(_) => std::fs::DirBuilder::new()
                .mode(0o700)
                .create(&left)
                .map_err(at)?,
        }
        runas::chmod_dir(&left, 0o700).map_err(at)
    }
}

/// The agent's own user and group.
fn own_ids() -> Ids {
    // SAFETY: no arguments.
    unsafe {
        Ids {
            uid: libc::geteuid(),
            gid: libc::getegid(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn me() -> Ids {
        // SAFETY: no arguments.
        unsafe {
            Ids {
                uid: libc::geteuid(),
                gid: libc::getegid(),
            }
        }
    }

    #[test]
    fn a_teammate_gets_a_private_home_once_and_is_checked_after() {
        let d = std::env::temp_dir().join(format!("superbot-teammates-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        let state = d.join("state");
        std::fs::create_dir_all(&state).unwrap();
        let t = Teammates::new(d.join("teammates"), state.clone(), runas::current_user());
        let first = t.ensure("u-bea", |_| Ok(())).unwrap();
        assert!(first.created);
        assert_eq!(first.ids, me());
        assert_eq!(
            first.home,
            d.join("teammates").join(wire::teammate_user("u-bea"))
        );
        let mode = |p: &Path| std::fs::symlink_metadata(p).unwrap().permissions().mode() & 0o7777;
        assert_eq!(mode(&d.join("teammates")), 0o711);
        assert_eq!(mode(&first.home), 0o700);
        assert!(first.workspace().is_dir() && first.bots().is_dir());
        assert_eq!(mode(&state.join(RECORD)), 0o600);

        let again = t.ensure("u-bea", |_| Ok(())).unwrap();
        assert!(!again.created, "made once");
        assert_eq!(again.home, first.home);
        assert_ne!(
            t.ensure("u-cy", |_| Ok(())).unwrap().home,
            first.home,
            "each teammate their own home"
        );

        assert!(
            t.ensure("u-dee", |_| Err("no".into())).is_err(),
            "refused ids"
        );

        // A record that can't be written leaves nothing behind, so a later try works.
        let gone = d.join("gone");
        let t2 = Teammates::new(d.join("teammates"), gone.clone(), runas::current_user());
        assert!(t2.ensure("u-fay", |_| Ok(())).is_err());
        std::fs::create_dir_all(&gone).unwrap();
        assert!(t2.ensure("u-fay", |_| Ok(())).unwrap().created);

        // A record naming another uid than the user has now runs nothing.
        let r = std::fs::read_to_string(state.join(RECORD)).unwrap();
        std::fs::write(
            state.join(RECORD),
            r.replacen(&format!("\"uid\":{}", me().uid), "\"uid\":4000000", 1),
        )
        .unwrap();
        let e = t.ensure("u-bea", |_| Ok(())).unwrap_err();
        assert!(e.contains("isn't the user it was"), "{e}");

        // A home that's a link is refused, not followed.
        let link = t.home_of("u-eve");
        std::os::unix::fs::symlink(&state, &link).unwrap();
        let e = t.ensure("u-eve", |_| Ok(())).unwrap_err();
        assert!(e.contains("belongs to someone else"), "{e}");
    }

    /// Users in memory, every one with the test's own ids, so the homes it makes count
    /// as theirs. Says what it removed and stopped.
    #[derive(Default)]
    struct Fake {
        users: Mutex<BTreeMap<String, Ids>>,
        removed: Mutex<Vec<String>>,
        stopped: Mutex<u32>,
        refuse_removal: Mutex<bool>,
    }

    impl OsUsers for Fake {
        fn lookup(&self, name: &str) -> Option<Ids> {
            self.users.lock().unwrap().get(name).copied()
        }

        fn add(&self, name: &str, _home: &Path) -> Result<Ids, String> {
            self.users.lock().unwrap().insert(name.into(), me());
            Ok(me())
        }

        fn remove(&self, name: &str) -> Result<bool, String> {
            if *self.refuse_removal.lock().unwrap() {
                return Err("userdel: user is busy".into());
            }
            self.users.lock().unwrap().remove(name);
            self.removed.lock().unwrap().push(name.into());
            Ok(true)
        }

        fn stop_all(&self, _uid: u32) -> Result<u32, String> {
            *self.stopped.lock().unwrap() += 1;
            Ok(2)
        }

        fn clear_temp(&self, _uid: u32) -> u32 {
            1
        }
    }

    #[test]
    fn a_leaving_teammate_is_removed_alone_and_their_work_goes_to_the_owner() {
        let d = std::env::temp_dir().join(format!("superbot-teammates-rm-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        let (state, owner) = (d.join("state"), d.join("owner"));
        std::fs::create_dir_all(&state).unwrap();
        std::fs::create_dir_all(owner.join("work")).unwrap();
        std::fs::write(owner.join("work/plan.md"), "ada's").unwrap();
        let fake = Arc::new(Fake::default());
        let t = Teammates::with_os_users(d.join("teammates"), state.clone(), None, fake.clone());
        let bea = t.ensure("ubea", |_| Ok(())).unwrap();
        let cy = t.ensure("ucy", |_| Ok(())).unwrap();
        std::fs::write(bea.workspace().join("notes.md"), "bea's").unwrap();
        std::fs::create_dir_all(bea.home.join(".claude")).unwrap();
        std::fs::write(bea.home.join(".claude/.credentials.json"), "secret").unwrap();
        std::fs::write(cy.workspace().join("notes.md"), "cy's").unwrap();
        let archive = Files::Archive {
            home: owner.clone(),
            ids: me(),
            name: "bea".into(),
        };

        let r = t.remove("ubea", "c1", &archive, |_| Ok(())).unwrap();
        assert_eq!((r.files, r.user_removed, r.processes_stopped, r.temp_removed), ("archived", true, 2, 1));
        let to = owner.join("work/from-teammates/bea");
        assert_eq!(r.archived_to.as_deref(), Some(to.as_path()));
        assert_eq!(std::fs::read_to_string(to.join("notes.md")).unwrap(), "bea's");
        assert!(!bea.home.exists(), "their home, logins and all, is gone");
        assert!(!t.held("c1").exists());
        // Nobody else is touched: the owner's work, the other teammate, their user.
        assert_eq!(std::fs::read_to_string(owner.join("work/plan.md")).unwrap(), "ada's");
        assert_eq!(std::fs::read_to_string(cy.workspace().join("notes.md")).unwrap(), "cy's");
        assert_eq!(t.known(), ["ucy"]);
        assert_eq!(*fake.removed.lock().unwrap(), std::slice::from_ref(&bea.user));
        assert!(fake.lookup(&cy.user).is_some());

        // Again, as when its answer was lost: the same answer, nothing done.
        let again = t.remove("ubea", "c1", &archive, |_| Ok(())).unwrap();
        assert!(again.already_gone && again.files == "archived", "{again:?}");
        assert_eq!(again.archived_to.as_deref(), Some(to.as_path()));
        assert_eq!(fake.removed.lock().unwrap().len(), 1);
        assert_eq!(*fake.stopped.lock().unwrap(), 1);

        // Back again later: a fresh user and home, which that old removal never touches.
        let back = t.ensure("ubea", |_| Ok(())).unwrap();
        assert!(back.created);
        std::fs::write(back.workspace().join("new.md"), "bea's new").unwrap();
        assert!(t.remove("ubea", "c1", &archive, |_| Ok(())).unwrap().already_gone);
        assert_eq!(std::fs::read_to_string(back.workspace().join("new.md")).unwrap(), "bea's new");
        assert!(t.known().contains(&"ubea".to_string()) && fake.lookup(&back.user).is_some());

        // Held, then purged.
        let r = t.remove("ucy", "c2", &Files::Hold, |_| Ok(())).unwrap();
        assert_eq!(r.files, "held");
        assert_eq!(std::fs::read_to_string(t.held("c2").join("notes.md")).unwrap(), "cy's");
        let mode = |p: &Path| std::fs::symlink_metadata(p).unwrap().permissions().mode() & 0o7777;
        assert_eq!((mode(&t.held("c2")), mode(&d.join("teammates/.left"))), (0o700, 0o700));
        assert!(t.purge("c2").unwrap());
        assert!(!t.purge("c2").unwrap());

        // A removal that fails part-way finishes when asked again.
        let eve = t.ensure("ueve", |_| Ok(())).unwrap();
        std::fs::write(eve.workspace().join("notes.md"), "eve's").unwrap();
        *fake.refuse_removal.lock().unwrap() = true;
        assert!(t.remove("ueve", "c3", &Files::Delete, |_| Ok(())).unwrap_err().contains("busy"));
        assert!(t.known().contains(&"ueve".to_string()), "kept until it's done");
        *fake.refuse_removal.lock().unwrap() = false;
        let r = t.remove("ueve", "c3", &Files::Delete, |_| Ok(())).unwrap();
        assert_eq!((r.files, r.user_removed), ("deleted", true));
        assert!(!t.held("c3").exists() && !eve.home.exists());

        // One that stopped after deleting the user and home, before dropping the record:
        // a later run starts afresh instead of finding the user gone for good.
        let gus = t.ensure("ugus", |_| Ok(())).unwrap();
        fake.users.lock().unwrap().remove(&gus.user);
        std::fs::remove_dir_all(&gus.home).unwrap();
        assert!(t.ensure("ugus", |_| Ok(())).unwrap().created);

        // Refused ids, or a user that isn't the recorded one: nothing is touched.
        let fay = t.ensure("ufay", |_| Ok(())).unwrap();
        assert!(t.remove("ufay", "c4", &Files::Delete, |_| Err("root".into())).is_err());
        fake.users.lock().unwrap().insert(fay.user.clone(), Ids { uid: 4_000_000, gid: 4_000_000 });
        let e = t.remove("ufay", "c4", &Files::Delete, |_| Ok(())).unwrap_err();
        assert!(e.contains("isn't the user it was"));
        assert!(fay.home.is_dir() && t.known().contains(&"ufay".to_string()));

        // While a removal runs, no run or screen of theirs gets their user.
        let leaving = t.start_leaving("ubea").unwrap();
        assert!(t.start_leaving("ubea").is_none());
        assert!(t.ensure("ubea", |_| Ok(())).unwrap_err().contains("being removed"));
        drop(leaving);
        assert!(t.ensure("ubea", |_| Ok(())).is_ok());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn teammate_users_are_plain_and_distinct() {
        let (a, b) = (wire::teammate_user("u1"), wire::teammate_user("u2"));
        assert_ne!(a, b);
        assert!(
            runas::plain_user(&a) && a.len() <= 32 && a.starts_with(wire::TEAMMATE_USER_PREFIX),
            "{a}"
        );
        assert_ne!(a, wire::BOT_USER);
    }
}
