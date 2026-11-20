//! Per-user Unix accounts on one server (ADR 0037). With `ISOLATION=users` each user's
//! Bots run as that user's own account, `sb-u-<user id>`, started through sudo and
//! `superbot-run`, in that user's folders under `ISOLATION_DIR/<user id>`:
//!
//! - `home`: the account's HOME, so harness logins (`~/.claude`, `~/.codex`) are per user;
//! - `workspace`: the working folder all of the user's Bots share;
//! - `memory`: `USER.md` and each Bot's `<bot id>.md`, which botd reads for the prompt
//!   and copies back to `DATA_DIR` after each run (backups, handovers, turning it off).
//!
//! The account and every path come from the Bot owner's id, never from a Bot. botd's
//! service user may run `superbot-run` as members of `superbot-users` and
//! `superbot-userctl ensure <id>` as root, nothing else (deploy/install.sh). Off by
//! default: then runs work as in ADR 0029.

use crate::passwd;
use std::ffi::OsString;
use std::io::{self, Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// Every per-user account's name starts with this.
pub const PREFIX: &str = "sb-u-";
/// Unix account names are at most 32 bytes.
const MAX_ID: usize = 32 - PREFIX.len();
/// Harnesses that run under an account so far. Pi and Hermes keep files botd writes
/// (Pi's approval gate, Hermes's managed config and daemon) in a folder the run could change.
pub const HARNESSES: [&str; 2] = ["claude", "codex"];
pub const DEFAULT_DIR: &str = "/srv/superbot/users";
const DEFAULT_SUDO: &str = "/usr/bin/sudo";
const DEFAULT_USERCTL: &str = "/usr/local/sbin/superbot-userctl";
/// The most of a memory or facts file botd reads back from a user's folder.
pub const MAX_FILE: u64 = 1 << 20;

#[derive(Clone, Debug)]
pub struct Isolation {
    /// `ISOLATION_DIR`: one folder per user, made by `superbot-userctl`.
    pub root: PathBuf,
    pub sudo: PathBuf,
    /// `superbot-run`, next to botd.
    pub runner: PathBuf,
    pub userctl: PathBuf,
}

/// How one run starts as its owner's account.
#[derive(Clone, Debug, PartialEq)]
pub struct RunAs {
    pub sudo: PathBuf,
    pub runner: PathBuf,
    pub account: String,
}

impl RunAs {
    /// `sudo -n -E -u <account> -- superbot-run <bin> <args>`. `-n`: never a password
    /// prompt; `-E`: the run's env (its token and its owner's keys) goes through, which
    /// the sudoers rule allows only for `superbot-run`.
    pub fn argv(&self, bin: &str, args: impl IntoIterator<Item = String>) -> Vec<OsString> {
        let mut v: Vec<OsString> = vec![self.sudo.clone().into(), "-n".into(), "-E".into(), "-u".into(), self.account.clone().into(), "--".into()];
        v.push(self.runner.clone().into());
        v.push(bin.into());
        v.extend(args.into_iter().map(OsString::from));
        v
    }
}

/// `sb-u-<id>`, or None when the id can't be part of an account name: 1 to 27 lowercase
/// letters and digits. Nothing else reaches sudo or `useradd`.
pub fn account(user_id: &str) -> Option<String> {
    let ok = !user_id.is_empty() && user_id.len() <= MAX_ID && user_id.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit());
    ok.then(|| format!("{PREFIX}{user_id}"))
}

impl Isolation {
    /// `ISOLATION=users` turns it on; unset or `off` leaves it off. On, it checks what
    /// the installer sets up, so a half-made setup stops botd instead of running Bots
    /// unisolated.
    pub fn from_env(get: impl Fn(&str) -> String, bin_dir: &Path, data_dir: &Path) -> Result<Option<Isolation>, String> {
        match get("ISOLATION").trim() {
            "" | "off" => return Ok(None),
            "users" => {}
            other => return Err(format!("ISOLATION must be off or users, not {other:?}")),
        }
        let or = |k: &str, d: &str| Some(get(k)).map(|v| v.trim().to_string()).filter(|v| !v.is_empty()).unwrap_or_else(|| d.into());
        let root = PathBuf::from(or("ISOLATION_DIR", DEFAULT_DIR));
        if !root.is_absolute() || root.components().any(|c| matches!(c, std::path::Component::ParentDir)) || root.parent().is_none() {
            return Err(format!("ISOLATION_DIR must be an absolute folder below /, not {}", root.display()));
        }
        let meta = std::fs::symlink_metadata(&root).map_err(|e| format!("ISOLATION_DIR {}: {e}. Run deploy/install.sh --isolation.", root.display()))?;
        if !meta.is_dir() || meta.uid() != 0 || meta.mode() & 0o022 != 0 {
            return Err(format!("ISOLATION_DIR {} must be a folder owned by root that only root can write", root.display()));
        }
        let data = std::fs::canonicalize(data_dir).unwrap_or_else(|_| data_dir.to_path_buf());
        if data.starts_with(&root) || root.starts_with(&data) {
            return Err("ISOLATION_DIR and DATA_DIR must not hold each other".into());
        }
        let iso = Isolation {
            root,
            sudo: or("ISOLATION_SUDO", DEFAULT_SUDO).into(),
            runner: bin_dir.join("superbot-run"),
            userctl: or("ISOLATION_USERCTL", DEFAULT_USERCTL).into(),
        };
        for (what, p) in [("sudo", &iso.sudo), ("superbot-run", &iso.runner), ("superbot-userctl", &iso.userctl)] {
            if !p.is_file() {
                return Err(format!("{what} isn't at {}. Run deploy/install.sh --isolation.", p.display()));
            }
        }
        Ok(Some(iso))
    }

    /// `ISOLATION_DIR/<id>`. None when the id can't name an account.
    pub fn user_root(&self, user_id: &str) -> Option<PathBuf> {
        account(user_id)?;
        crate::paths::child(&self.root, user_id)
    }
    pub fn home(&self, user_id: &str) -> Option<PathBuf> {
        Some(self.user_root(user_id)?.join("home"))
    }
    pub fn workspace(&self, user_id: &str) -> Option<PathBuf> {
        Some(self.user_root(user_id)?.join("workspace"))
    }
    pub fn memory_dir(&self, user_id: &str) -> Option<PathBuf> {
        Some(self.user_root(user_id)?.join("memory"))
    }
    /// `memory/USER.md`: facts about the user, for their Bots.
    pub fn user_file(&self, user_id: &str) -> Option<PathBuf> {
        Some(self.memory_dir(user_id)?.join("USER.md"))
    }
    /// `memory/<bot id>.md`: one Bot's memory, in its owner's folder.
    pub fn memory_file(&self, owner_id: &str, bot_id: &str) -> Option<PathBuf> {
        crate::paths::child(&self.memory_dir(owner_id)?, bot_id)?;
        Some(self.memory_dir(owner_id)?.join(format!("{bot_id}.md")))
    }

    pub fn run_as(&self, user_id: &str) -> Option<RunAs> {
        Some(RunAs { sudo: self.sudo.clone(), runner: self.runner.clone(), account: account(user_id)? })
    }

    /// The account exists with the home `superbot-userctl` gives it, and its folders are
    /// there, made by root.
    pub fn ready(&self, user_id: &str) -> bool {
        let (Some(name), Some(home), Some(root)) = (account(user_id), self.home(user_id), self.user_root(user_id)) else { return false };
        let made_by_root = |p: &Path| std::fs::symlink_metadata(p).is_ok_and(|m| m.is_dir() && m.uid() == 0);
        passwd::by_name(&name).is_some_and(|a| a.uid != 0 && a.home == home) && made_by_root(&root) && trusted_dir(&root.join("memory"))
    }

    /// Makes the user's account and folders if they aren't there, with the root helper.
    /// Ok(true): made now. Blocking.
    pub fn ensure(&self, user_id: &str) -> Result<bool, String> {
        account(user_id).ok_or_else(|| format!("{user_id:?} can't be part of a Unix account name"))?;
        if self.ready(user_id) {
            return Ok(false);
        }
        let out = Command::new(&self.sudo)
            .arg("-n")
            .arg(&self.userctl)
            .args(["ensure", user_id])
            .stdin(Stdio::null())
            .output()
            .map_err(|e| format!("couldn't start {}: {e}", self.sudo.display()))?;
        if !out.status.success() {
            let err = String::from_utf8_lossy(&out.stderr);
            let last = err.trim().lines().last().unwrap_or_default();
            return Err(format!("superbot-userctl ensure failed ({}){}", out.status, if last.is_empty() { String::new() } else { format!(": {last}") }));
        }
        if !self.ready(user_id) {
            return Err("superbot-userctl ran, but the account or its folders still aren't there".into());
        }
        Ok(true)
    }
}

/// Whether this process sees another account's processes in /proc (pid 1, root's). With
/// `ProtectProc=invisible` it doesn't, so runs can't read each other's command lines.
pub fn others_visible() -> bool {
    // SAFETY: geteuid can't fail.
    let me = unsafe { libc::geteuid() };
    std::fs::metadata("/proc/1").is_ok_and(|m| m.uid() != me)
}

/// A folder botd may read and write in: a real folder (not a link) made by root or botd,
/// so a Bot's account can't have swapped it for one that leads elsewhere.
pub fn trusted_dir(p: &Path) -> bool {
    // SAFETY: geteuid can't fail.
    let me = unsafe { libc::geteuid() };
    std::fs::symlink_metadata(p).is_ok_and(|m| m.is_dir() && (m.uid() == 0 || m.uid() == me))
}

/// A file a Bot's account can write, read without following a link or waiting on a
/// pipe. None unless it's a plain file of at most `max` bytes in a trusted folder.
pub fn read_plain(path: &Path, max: u64) -> Option<String> {
    if !path.parent().is_some_and(trusted_dir) {
        return None;
    }
    let mut f = std::fs::OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK).open(path).ok()?;
    let m = f.metadata().ok()?;
    if !m.is_file() || m.len() > max {
        return None;
    }
    let mut s = String::new();
    Read::by_ref(&mut f).take(max).read_to_string(&mut s).ok()?;
    Some(s)
}

/// Writes `text` to a new file at `path` in a trusted folder, unless something is there
/// already. Never follows a link. Ok(true) if it wrote.
pub fn seed(path: &Path, text: &str) -> io::Result<bool> {
    if !path.parent().is_some_and(trusted_dir) {
        return Err(io::Error::other(format!("{} isn't a folder botd made", path.parent().unwrap_or(path).display())));
    }
    // The run's account edits it in place, through the folder's inherited ACL.
    let f = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o660).custom_flags(libc::O_NOFOLLOW).open(path);
    match f {
        Ok(mut f) => {
            f.write_all(text.as_bytes())?;
            f.set_permissions(std::fs::Permissions::from_mode(0o660))?;
            Ok(true)
        }
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => Ok(false),
        Err(e) => Err(e),
    }
}

/// Removes the entry at `path` (a link is removed, never followed) in a trusted folder.
pub fn remove(path: &Path) {
    if path.parent().is_some_and(trusted_dir) {
        let _ = std::fs::remove_file(path);
    }
}

/// What logs each harness in. Run as the user's account, at a terminal.
pub fn login_args(harness: &str) -> Option<&'static [&'static str]> {
    match harness {
        "claude" => Some(&["auth", "login"]),
        "codex" => Some(&["login"]),
        _ => None,
    }
}

/// Admin API: a user's account, making it now, and logging a harness in as them
/// (`botctl user isolation | isolate | harness-login`). Under `/api/users`, so admins only.
pub mod http {
    use super::{Isolation, HARNESSES, account, login_args};
    use crate::audit::Who;
    use crate::users::need_user_key;
    use crate::{ApiError, AppState, Res, bad};
    use axum::Json;
    use axum::extract::{Extension, Path as UrlPath, State};
    use axum::http::StatusCode;
    use serde_json::{Value, json};

    fn need_on(app: &AppState) -> Res<std::sync::Arc<Isolation>> {
        app.isolation.get().cloned().ok_or_else(|| {
            ApiError(StatusCode::CONFLICT, "Per-user accounts are off. Set ISOLATION=users (deploy/install.sh --isolation) to turn them on.".into())
        })
    }

    fn failed(user: &str, e: String) -> ApiError {
        ApiError(StatusCode::BAD_GATEWAY, format!("Couldn't set up {user}'s account: {e}"))
    }

    fn view(iso: &Isolation, user_id: &str) -> Value {
        json!({
            "isolation": "users", "user": user_id, "account": account(user_id), "root": iso.user_root(user_id),
            "home": iso.home(user_id), "workspace": iso.workspace(user_id), "memory": iso.memory_dir(user_id),
            "ready": iso.ready(user_id), "harnesses": HARNESSES,
        })
    }

    /// `GET /api/users/{key}/isolation`
    pub async fn get(State(app): State<AppState>, UrlPath(key): UrlPath<String>) -> Res {
        let u = need_user_key(&app, &key)?;
        Ok(Json(match app.isolation() {
            Some(iso) => view(iso, &u.id),
            None => json!({ "isolation": "off", "user": u.id }),
        }))
    }

    /// `POST /api/users/{key}/isolation`: makes the user's account and folders now
    /// rather than at their first run.
    pub async fn ensure(State(app): State<AppState>, Extension(by): Extension<Who>, UrlPath(key): UrlPath<String>) -> Res {
        let iso = need_on(&app)?;
        let u = need_user_key(&app, &key)?;
        app.ensure_account(&u.id, &by).await.map_err(|e| failed(&u.id, e))?;
        Ok(Json(view(&iso, &u.id)))
    }

    /// `POST /api/users/{key}/harness-login` `{harness, args?}`: makes the account if
    /// needed and returns the command that runs the harness's login as it, for
    /// `botctl user harness-login` to run at the admin's terminal on the server. The
    /// login lands in that user's HOME, for their Bots only.
    pub async fn harness_login(
        State(app): State<AppState>,
        Extension(by): Extension<Who>,
        UrlPath(key): UrlPath<String>,
        Json(v): Json<Value>,
    ) -> Res {
        let iso = need_on(&app)?;
        let u = need_user_key(&app, &key)?;
        if !u.active() {
            return Err(bad("That user is disabled"));
        }
        let harness = v["harness"].as_str().unwrap_or_default();
        let default = login_args(harness).ok_or_else(|| bad(format!("harness must be one of: {}", HARNESSES.join(", "))))?;
        let custom = !matches!(v.get("args"), None | Some(Value::Null));
        let args: Vec<String> = match v.get("args") {
            None | Some(Value::Null) => default.iter().map(|s| s.to_string()).collect(),
            Some(Value::Array(a)) if a.len() <= 16 => a
                .iter()
                .map(|x| x.as_str().filter(|s| s.len() <= 200 && !s.contains('\0')).map(String::from))
                .collect::<Option<_>>()
                .ok_or_else(|| bad("args must be up to 16 strings"))?,
            _ => return Err(bad("args must be up to 16 strings")),
        };
        let run_as = app.ensure_account(&u.id, &by).await.map_err(|e| failed(&u.id, e))?;
        // Not the arguments: they could hold a key.
        let details = json!({ "harness": harness, "account": run_as.account, "customArgs": custom });
        app.db.record(&by.event("harness.login_started").target("user", &u.id).details(details));
        let command: Vec<String> = run_as.argv(harness, args).into_iter().map(|s| s.to_string_lossy().into_owned()).collect();
        let home = iso.home(&u.id);
        Ok(Json(json!({ "user": u.id, "account": run_as.account, "harness": harness, "home": home, "command": command })))
    }
}

#[cfg(test)]
pub(crate) fn for_tests(root: &Path, sudo: &str) -> Isolation {
    Isolation { root: root.to_path_buf(), sudo: sudo.into(), runner: "/usr/local/bin/superbot-run".into(), userctl: DEFAULT_USERCTL.into() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accounts_come_only_from_plain_user_ids() {
        assert_eq!(account("u1a2b3c4d").as_deref(), Some("sb-u-u1a2b3c4d"));
        assert_eq!(account("operator").as_deref(), Some("sb-u-operator"));
        assert_eq!(account(&"a".repeat(27)).map(|a| a.len()), Some(32));
        for bad in ["", "..", "../u2", "a/b", "U1", "a-b", "a b", "root;id", "a\0b", &"a".repeat(28)] {
            assert_eq!(account(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn each_users_folders_stay_under_their_own_root() {
        let iso = for_tests(Path::new("/srv/superbot/users"), DEFAULT_SUDO);
        assert_eq!(iso.home("u1").unwrap(), Path::new("/srv/superbot/users/u1/home"));
        assert_eq!(iso.workspace("u1").unwrap(), Path::new("/srv/superbot/users/u1/workspace"));
        assert_eq!(iso.user_file("u1").unwrap(), Path::new("/srv/superbot/users/u1/memory/USER.md"));
        assert_eq!(iso.memory_file("u1", "b1").unwrap(), Path::new("/srv/superbot/users/u1/memory/b1.md"));
        for bad in ["", "..", "../u2", "a/b", "/etc", "U1"] {
            assert_eq!(iso.user_root(bad), None, "{bad:?}");
            assert_eq!(iso.home(bad), None, "{bad:?}");
            assert_eq!(iso.run_as(bad), None, "{bad:?}");
        }
        for bad in ["", "..", "../b2", "a/b"] {
            assert_eq!(iso.memory_file("u1", bad), None, "{bad:?}");
        }
    }

    #[test]
    fn a_run_starts_only_as_its_owners_account() {
        let iso = for_tests(Path::new("/srv/superbot/users"), DEFAULT_SUDO);
        let argv = iso.run_as("ub").unwrap().argv("claude", ["-p".to_string(), "--".into(), "-u root".into()]);
        let want: Vec<OsString> =
            ["/usr/bin/sudo", "-n", "-E", "-u", "sb-u-ub", "--", "/usr/local/bin/superbot-run", "claude", "-p", "--", "-u root"].map(OsString::from).into();
        assert_eq!(argv, want, "the account is fixed before `--`; nothing the run passes can change it");
    }

    #[test]
    fn off_unless_asked_and_on_only_when_set_up() {
        let tmp = crate::db::temp_path("iso-env");
        let bin = tmp.join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        let parse = |mode: &str, dir: &str| {
            let get = |k: &str| match k {
                "ISOLATION" => mode.to_string(),
                "ISOLATION_DIR" => dir.to_string(),
                _ => String::new(),
            };
            Isolation::from_env(get, &bin, &tmp)
        };
        assert!(parse("", "").unwrap().is_none());
        assert!(parse("off", "").unwrap().is_none());
        assert!(parse("on", "").unwrap_err().contains("off or users"));
        for dir in ["relative/dir", "/srv/../etc", "/"] {
            assert!(parse("users", dir).unwrap_err().contains("absolute"), "{dir}");
        }
        assert!(parse("users", "/no/such/superbot/dir").unwrap_err().contains("install.sh --isolation"));
        // A folder botd's own account can write: refused, or its Bots could plant files there.
        let mine = tmp.join("users");
        std::fs::create_dir_all(&mine).unwrap();
        let err = parse("users", mine.to_str().unwrap()).unwrap_err();
        assert!(err.contains("owned by root"), "{err}");
    }

    #[test]
    fn files_from_a_bots_folder_are_read_and_written_without_following_links() {
        use std::os::unix::fs::symlink;
        let dir = crate::db::temp_path("iso-files");
        let secret = dir.join("secret");
        std::fs::write(&secret, "botd only").unwrap();
        let mem = dir.join("memory");
        std::fs::create_dir_all(&mem).unwrap();

        std::fs::write(mem.join("b1.md"), "# B1").unwrap();
        assert_eq!(read_plain(&mem.join("b1.md"), MAX_FILE).as_deref(), Some("# B1"));
        symlink(&secret, mem.join("b2.md")).unwrap();
        assert_eq!(read_plain(&mem.join("b2.md"), MAX_FILE), None, "a link is never followed");
        assert_eq!(seed(&mem.join("b2.md"), "x").unwrap(), false, "nor written through");
        assert_eq!(std::fs::read_to_string(&secret).unwrap(), "botd only");
        remove(&mem.join("b2.md"));
        assert!(std::fs::symlink_metadata(mem.join("b2.md")).is_err() && secret.exists(), "removing drops the link, not its target");

        let fifo = std::ffi::CString::new(mem.join("b3.md").to_str().unwrap()).unwrap();
        // SAFETY: a valid path.
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
        assert_eq!(read_plain(&mem.join("b3.md"), MAX_FILE), None, "a pipe isn't waited on");
        std::fs::write(mem.join("big.md"), "x".repeat(11)).unwrap();
        assert_eq!(read_plain(&mem.join("big.md"), 10), None);

        assert!(seed(&mem.join("b4.md"), "# B4").unwrap());
        assert!(!seed(&mem.join("b4.md"), "other").unwrap(), "never overwrites");
        assert_eq!(std::fs::read_to_string(mem.join("b4.md")).unwrap(), "# B4");
        assert_eq!(std::fs::metadata(mem.join("b4.md")).unwrap().mode() & 0o777, 0o660);

        // A folder swapped for a link: nothing in it is read or written.
        let swapped = dir.join("swapped");
        symlink(&dir, &swapped).unwrap();
        assert_eq!(read_plain(&swapped.join("secret"), MAX_FILE), None);
        assert!(seed(&swapped.join("new.md"), "x").is_err());
        assert!(!dir.join("new.md").exists());
    }
}
