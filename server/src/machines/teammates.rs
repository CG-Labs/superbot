//! Teammates' own OS users on a machine (ADR 0047). When someone other than the
//! machine's user runs one of that user's shared Bots there, the run gets an OS user and
//! home of its own (`superbot-t-<hash of their id>`, home `<state>/teammates/<that>`),
//! never the Bots' user (ADR 0043) the owner's runs share. The owner's home (their
//! folder copy, harness logins, facts, the Bots' memory) is `0700` the Bots' user's, so
//! a teammate's run can't open it; theirs is `0700` theirs, so the owner's runs can't
//! open it either. Each teammate's user is recorded the first time it's made, and
//! checked against that record after, so a user someone else made by that name is
//! never taken for theirs. Shared by the agent binary and botd's tests.

// Shared by two binaries, each of which uses only part of it.
#![allow(dead_code)]

use super::runas::{self, Ids};
use super::wire;
use std::collections::BTreeMap;
use std::os::unix::fs::{DirBuilderExt, MetadataExt};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

const RECORD: &str = "teammates.json";

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
        }
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
struct Saved {
    user: String,
    uid: u32,
    gid: u32,
}

pub struct Teammates {
    /// Holds one home per teammate. Root's, `0711`: each can pass to their own.
    root: PathBuf,
    /// The agent's state folder, where the record is kept (root's, `0600`).
    state_dir: PathBuf,
    /// Tests can't make users: every teammate runs as this existing one instead.
    stand_in: Option<String>,
    /// One teammate made at a time, and the record written by one at a time.
    making: Mutex<()>,
}

impl Teammates {
    pub fn new(root: PathBuf, state_dir: PathBuf, stand_in: Option<String>) -> Teammates {
        Teammates { root, state_dir, stand_in, making: Mutex::new(()) }
    }

    pub fn root(&self) -> &Path {
        &self.root
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
        let path = self.state_dir.join(RECORD);
        let tmp = path.with_extension("tmp");
        let body = serde_json::to_vec(r).map_err(|e| e.to_string())?;
        let write = || -> std::io::Result<()> {
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;
            let _ = std::fs::remove_file(&tmp);
            let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&tmp)?;
            f.write_all(&body)?;
            f.sync_all()?;
            std::fs::rename(&tmp, &path)
        };
        write().map_err(|e| format!("{}: {e}", path.display()))
    }

    /// Where `user_id`'s home is, whether or not it's made yet.
    pub fn home_of(&self, user_id: &str) -> PathBuf {
        self.root.join(wire::teammate_user(user_id))
    }

    /// `user_id`'s user and home, made if this is their first run here. `check` refuses
    /// ids that must never be a teammate's (root, the agent's, the Bots' user's).
    pub fn ensure(&self, user_id: &str, check: impl Fn(Ids) -> Result<(), String>) -> Result<Teammate, String> {
        let _one = self.making.lock().unwrap_or_else(|e| e.into_inner());
        let name = self.stand_in.clone().unwrap_or_else(|| wire::teammate_user(user_id));
        let home = self.home_of(user_id);
        let mut record = self.record()?;
        let (ids, created) = match record.get(user_id) {
            Some(s) => {
                let want = Ids { uid: s.uid, gid: s.gid };
                match runas::lookup(&s.user) {
                    Some((ids, _)) if s.user == name && ids == want => (want, false),
                    Some(_) => return Err(format!("{} isn't the user it was.", s.user)),
                    None => return Err(format!("{} is gone.", s.user)),
                }
            }
            None => {
                if self.stand_in.is_none() && runas::lookup(&name).is_some() {
                    return Err(format!("{name} is already a user here, but this agent didn't make it for that teammate."));
                }
                let ids = runas::ensure_user_as(&name, &home, "SuperBot teammate")?;
                check(ids)?;
                record.insert(user_id.to_string(), Saved { user: name.clone(), uid: ids.uid, gid: ids.gid });
                self.save(&record)?;
                (ids, true)
            }
        };
        check(ids)?;
        self.make_home(&home, ids)?;
        Ok(Teammate { user: name, ids, home, created })
    }

    /// The teammates' folder (root's, `0711`) and this teammate's home in it (theirs,
    /// `0700`), with their working and Bots' folders. A home that's someone else's, or a
    /// link, is refused rather than taken over.
    fn make_home(&self, home: &Path, ids: Ids) -> Result<(), String> {
        let at = |p: &Path, e: std::io::Error| format!("{}: {e}", p.display());
        match std::fs::symlink_metadata(&self.root) {
            Ok(m) if m.is_dir() => {}
            Ok(_) => return Err(format!("{} isn't a folder.", self.root.display())),
            Err(_) => std::fs::DirBuilder::new().recursive(true).mode(0o711).create(&self.root).map_err(|e| at(&self.root, e))?,
        }
        runas::chmod_dir(&self.root, 0o711).map_err(|e| at(&self.root, e))?;
        match std::fs::symlink_metadata(home) {
            Ok(m) if m.is_dir() && m.uid() == ids.uid => {}
            Ok(_) => return Err(format!("{} belongs to someone else, or isn't a folder.", home.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                std::fs::DirBuilder::new().mode(0o700).create(home).map_err(|e| at(home, e))?;
                runas::hand_over(home, ids).map_err(|e| at(home, e))?;
            }
            Err(e) => return Err(at(home, e)),
        }
        runas::as_user(Some(ids), || -> std::io::Result<()> {
            for d in [home.join("work"), home.join("bots")] {
                std::fs::DirBuilder::new().recursive(true).mode(0o700).create(d)?;
            }
            Ok(())
        })
        .and_then(|r| r)
        .map_err(|e| at(home, e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn me() -> Ids {
        // SAFETY: no arguments.
        unsafe { Ids { uid: libc::geteuid(), gid: libc::getegid() } }
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
        assert_eq!(first.home, d.join("teammates").join(wire::teammate_user("u-bea")));
        let mode = |p: &Path| std::fs::symlink_metadata(p).unwrap().permissions().mode() & 0o7777;
        assert_eq!(mode(&d.join("teammates")), 0o711);
        assert_eq!(mode(&first.home), 0o700);
        assert!(first.workspace().is_dir() && first.bots().is_dir());
        assert_eq!(mode(&state.join(RECORD)), 0o600);

        let again = t.ensure("u-bea", |_| Ok(())).unwrap();
        assert!(!again.created, "made once");
        assert_eq!(again.home, first.home);
        assert_ne!(t.ensure("u-cy", |_| Ok(())).unwrap().home, first.home, "each teammate their own home");

        assert!(t.ensure("u-dee", |_| Err("no".into())).is_err(), "refused ids");

        // A record naming another uid than the user has now runs nothing.
        let r = std::fs::read_to_string(state.join(RECORD)).unwrap();
        std::fs::write(state.join(RECORD), r.replacen(&format!("\"uid\":{}", me().uid), "\"uid\":4000000", 1)).unwrap();
        let e = t.ensure("u-bea", |_| Ok(())).unwrap_err();
        assert!(e.contains("isn't the user it was"), "{e}");

        // A home that's a link is refused, not followed.
        let link = t.home_of("u-eve");
        std::os::unix::fs::symlink(&state, &link).unwrap();
        let e = t.ensure("u-eve", |_| Ok(())).unwrap_err();
        assert!(e.contains("belongs to someone else"), "{e}");
    }

    #[test]
    fn teammate_users_are_plain_and_distinct() {
        let (a, b) = (wire::teammate_user("u1"), wire::teammate_user("u2"));
        assert_ne!(a, b);
        assert!(runas::plain_user(&a) && a.len() <= 32 && a.starts_with(wire::TEAMMATE_USER_PREFIX), "{a}");
        assert_ne!(a, wire::BOT_USER);
    }
}
