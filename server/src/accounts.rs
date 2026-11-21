//! Per-user Unix accounts on one server (ADR 0037). With `ISOLATION=users` each user's
//! Bots run as that user's own account, `sb-u-<user id>`, started through sudo and
//! `superbot-run`, in that user's folders under `ISOLATION_DIR/<user id>`:
//!
//! - `home`: the account's HOME, so harness logins (`~/.claude`, `~/.codex`) are per user;
//! - `workspace`: the working folder all of the user's Bots share;
//! - `memory`: `USER.md` and each Bot's `<bot id>.md`, which botd reads for the prompt
//!   and copies back to `DATA_DIR` after each run (backups, handovers, turning it off);
//! - `bots/<bot id>`: a Bot's harness state (Pi's sessions, Hermes's data root), the run's;
//! - `settings/<bot id>`: files botd writes for a Bot's runs (Pi's approval gate, Hermes's
//!   managed config), which the run reads and can't change (ADR 0058).
//!
//! The account and every path come from the Bot owner's id, never from a Bot. botd's
//! service user may run `superbot-run` as members of `superbot-users` and
//! `superbot-userctl ensure <id>` as root, nothing else (deploy/install.sh). The
//! installer and Compose turn it on for new installs (ADR 0058); unset, runs work as
//! in ADR 0029.

use crate::machines::wire::JobRequest;
use crate::passwd;
use std::ffi::OsString;
use std::io::{self, Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// Every per-user account's name starts with this.
pub const PREFIX: &str = "sb-u-";
/// Unix account names are at most 32 bytes.
const MAX_ID: usize = 32 - PREFIX.len();
/// Harnesses that run under an account: all of them.
pub const HARNESSES: [&str; 4] = ["claude", "codex", "pi", "hermes"];
/// Harnesses an admin logs in for a user (`botctl user harness-login`). Pi and Hermes
/// take API keys from secrets.
pub const LOGINS: [&str; 2] = ["claude", "codex"];
/// Checks a missing file as the run's account, then runs the cleanup: botd can't see into
/// the run's state, and must not follow links the run left there.
const CLEANUP_IF_EXISTS: &str = "[ -e \"$1\" ] || exit 0; shift; exec \"$@\"";
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
    /// One account setup at a time, so two first runs don't both run `useradd`.
    setup: std::sync::Arc<std::sync::Mutex<()>>,
}

/// How one run starts as its owner's account.
#[derive(Clone, Debug, PartialEq)]
pub struct RunAs {
    pub sudo: PathBuf,
    pub runner: PathBuf,
    pub account: String,
    /// `ISOLATION_DIR/<user id>/settings`: the only place a job's files are written.
    pub settings: PathBuf,
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

    fn argv_strings(&self, bin: &str, args: Vec<String>) -> (String, Vec<String>) {
        let mut argv = self.argv(bin, args).into_iter().map(|s| s.to_string_lossy().into_owned());
        (argv.next().unwrap_or_default(), argv.collect())
    }

    /// The same job, started as this account. Only for jobs on this server. Its files
    /// are written now, by botd, into the user's `settings` folder, where the account
    /// can read them and not change them; a file anywhere else is refused. Its cleanup
    /// runs as the account too: botd can't stop the account's processes.
    pub fn prepare(&self, mut job: JobRequest) -> Result<JobRequest, String> {
        for f in std::mem::take(&mut job.files) {
            write_shared(&self.settings, Path::new(&f.path), &f.body).map_err(|e| format!("Couldn't write {}: {e}", f.path))?;
        }
        (job.bin, job.args) = self.argv_strings(&job.bin, std::mem::take(&mut job.args));
        // sudo resets PATH; superbot-run puts this one back.
        if let Some(path) = job.env.get("PATH").cloned() {
            job.env.insert("SUPERBOT_PATH".into(), path);
        }
        if let Some(c) = job.cleanup.as_mut() {
            let check = std::mem::replace(&mut c.when_exists, c.cwd.clone());
            let mut args = vec!["-c".to_string(), CLEANUP_IF_EXISTS.into(), "sh".into(), check, std::mem::take(&mut c.bin)];
            args.append(&mut c.args);
            (c.bin, c.args) = self.argv_strings("/bin/sh", args);
            if let Some(path) = c.env.get("PATH").cloned() {
                c.env.insert("SUPERBOT_PATH".into(), path);
            }
        }
        Ok(job)
    }
}

/// Writes `body` to `path` under `base` (a user's `settings` folder, made by root), for
/// the user's account to read and never change. Folders on the way are made 0750 by
/// botd, and must be botd's own; the file is 0640. Nobody else can write there, so the
/// account can't swap anything in. Through the folder's ACL the account may read.
pub fn write_shared(base: &Path, path: &Path, body: &str) -> io::Result<()> {
    let rel = path.strip_prefix(base).map_err(|_| io::Error::other(format!("{} is outside {}", path.display(), base.display())))?;
    if !trusted_dir(base) {
        return Err(io::Error::other(format!("{} isn't a folder root made", base.display())));
    }
    let parts: Vec<_> = rel.components().collect();
    let (Some((std::path::Component::Normal(name), dirs)), false) = (parts.split_last(), parts.len() < 2) else {
        return Err(io::Error::other(format!("{} isn't a file in a Bot's folder under {}", path.display(), base.display())));
    };
    let mut dir = base.to_path_buf();
    for d in dirs {
        let std::path::Component::Normal(d) = d else { return Err(io::Error::other("not a plain path")) };
        dir.push(d);
        own_dir(&dir)?;
    }
    let tmp = dir.join(format!(".{}.tmp", name.to_string_lossy()));
    remove(&tmp);
    let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o640).custom_flags(libc::O_NOFOLLOW).open(&tmp)?;
    f.write_all(body.as_bytes())?;
    // The group bits set the ACL's mask, so the account can read it whatever the umask.
    f.set_permissions(std::fs::Permissions::from_mode(0o640))?;
    std::fs::rename(&tmp, dir.join(name))
}

/// Makes `dir` (0750, or keeps it) and checks it's a real folder botd owns.
fn own_dir(dir: &Path) -> io::Result<()> {
    match std::fs::DirBuilder::new().mode(0o750).create(dir) {
        Err(e) if e.kind() != io::ErrorKind::AlreadyExists => return Err(e),
        _ => {}
    }
    let m = std::fs::symlink_metadata(dir)?;
    // SAFETY: geteuid can't fail.
    if !m.is_dir() || m.uid() != unsafe { libc::geteuid() } {
        return Err(io::Error::other(format!("{} isn't botd's folder", dir.display())));
    }
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o750))
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
            setup: Default::default(),
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

    /// `bots/<bot id>`: the Bot's harness state, which its runs write.
    pub fn bot_state(&self, owner_id: &str, bot_id: &str) -> Option<PathBuf> {
        crate::paths::child(&self.user_root(owner_id)?.join("bots"), bot_id)
    }
    /// `settings/<bot id>`: what botd writes for the Bot's runs, read-only to them.
    pub fn bot_settings(&self, owner_id: &str, bot_id: &str) -> Option<PathBuf> {
        crate::paths::child(&self.user_root(owner_id)?.join("settings"), bot_id)
    }

    /// Makes the Bot's state and settings folders in its owner's folder, once the account
    /// is there. The state folder is botd's, with the account's full access by the
    /// parent's default ACL; anything else the account left in its place (a link, a file)
    /// is removed first, so the run starts in a real folder. botd never writes in it.
    pub fn make_bot_dirs(&self, owner_id: &str, bot_id: &str) -> io::Result<()> {
        let (Some(state), Some(settings)) = (self.bot_state(owner_id, bot_id), self.bot_settings(owner_id, bot_id)) else {
            return Err(io::Error::other(format!("{owner_id:?} or {bot_id:?} can't name a folder")));
        };
        for p in [&state, &settings] {
            if !p.parent().is_some_and(trusted_dir) {
                return Err(io::Error::other(format!("{} isn't a folder root made", p.parent().unwrap_or(p).display())));
            }
        }
        if std::fs::symlink_metadata(&state).is_ok_and(|m| !m.is_dir()) {
            std::fs::remove_file(&state)?;
        }
        match std::fs::DirBuilder::new().mode(0o770).create(&state) {
            Ok(()) => std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o770))?,
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e),
        }
        own_dir(&settings)
    }

    pub fn run_as(&self, user_id: &str) -> Option<RunAs> {
        Some(RunAs { sudo: self.sudo.clone(), runner: self.runner.clone(), account: account(user_id)?, settings: self.user_root(user_id)?.join("settings") })
    }

    /// The account exists with the home `superbot-userctl` gives it, and its folders are
    /// there, made by root. An account made before a folder was added isn't ready, so
    /// the helper runs again and adds it.
    pub fn ready(&self, user_id: &str) -> bool {
        let (Some(name), Some(home), Some(root)) = (account(user_id), self.home(user_id), self.user_root(user_id)) else { return false };
        let made_by_root = |p: &Path| std::fs::symlink_metadata(p).is_ok_and(|m| m.is_dir() && m.uid() == 0);
        passwd::by_name(&name).is_some_and(|a| a.uid != 0 && a.home == home)
            && made_by_root(&root)
            && ["memory", "bots", "settings"].iter().all(|d| trusted_dir(&root.join(d)))
    }

    /// Makes the user's account and folders if they aren't there, with the root helper.
    /// Ok(true): made now. Blocking.
    pub fn ensure(&self, user_id: &str) -> Result<bool, String> {
        account(user_id).ok_or_else(|| format!("{user_id:?} can't be part of a Unix account name"))?;
        let _one = self.setup.lock().unwrap_or_else(|e| e.into_inner());
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

/// Takes other accounts' access off botd's own files (DATA_DIR, `.env`, the master key
/// file), so no per-user account can read them. Returns the ones it couldn't close.
pub fn close_to_others(paths: &[PathBuf]) -> Vec<String> {
    use std::os::unix::fs::PermissionsExt;
    // SAFETY: geteuid can't fail.
    let me = unsafe { libc::geteuid() };
    let mut open = Vec::new();
    for p in paths {
        let Ok(m) = std::fs::metadata(p) else { continue };
        let mode = m.permissions().mode();
        if mode & 0o007 == 0 {
            continue;
        }
        if m.uid() != me || std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode & 0o7770)).is_err() {
            open.push(p.display().to_string());
        }
    }
    open
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

/// Admin API: a user's account, making it now, and logging a harness in as them
/// (`botctl user isolation | isolate | harness-login`). Under `/api/users`, so admins only.
pub mod http {
    use super::{Isolation, HARNESSES, LOGINS, account};
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
            "ready": iso.ready(user_id), "harnesses": HARNESSES, "logins": LOGINS,
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
    /// rather than at their first run. Only for active users: a disabled one holds no
    /// seat (ADR 0038) and their Bots can't run.
    pub async fn ensure(State(app): State<AppState>, Extension(by): Extension<Who>, UrlPath(key): UrlPath<String>) -> Res {
        let iso = need_on(&app)?;
        let u = need_user_key(&app, &key)?;
        if !u.active() {
            return Err(bad("That user is disabled"));
        }
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
        let adapter = LOGINS.contains(&harness).then(|| crate::adapters::get(harness)).flatten();
        let (bin, default) = adapter
            .and_then(|a| Some((a.bin(), a.login_args()?)))
            .ok_or_else(|| bad(format!("harness must be one of: {}", LOGINS.join(", "))))?;
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
        let command: Vec<String> = run_as.argv(bin, args).into_iter().map(|s| s.to_string_lossy().into_owned()).collect();
        let home = iso.home(&u.id);
        Ok(Json(json!({ "user": u.id, "account": run_as.account, "harness": harness, "home": home, "command": command })))
    }
}

#[cfg(test)]
pub(crate) fn for_tests(root: &Path, sudo: &str) -> Isolation {
    Isolation { root: root.to_path_buf(), sudo: sudo.into(), runner: "/usr/local/bin/superbot-run".into(), userctl: DEFAULT_USERCTL.into(), setup: Default::default() }
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
        assert!(!seed(&mem.join("b2.md"), "x").unwrap(), "nor written through");
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

    #[test]
    fn botds_own_files_are_closed_to_other_accounts() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("sb-close-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("data")).unwrap();
        std::fs::write(dir.join(".env"), "AUTH_PASSWORD=x\n").unwrap();
        std::fs::set_permissions(dir.join("data"), std::fs::Permissions::from_mode(0o2755)).unwrap();
        std::fs::set_permissions(dir.join(".env"), std::fs::Permissions::from_mode(0o644)).unwrap();
        let paths = [dir.join("data"), dir.join(".env"), dir.join("missing")];
        assert!(close_to_others(&paths).is_empty());
        let mode = |p: &str| std::fs::metadata(dir.join(p)).unwrap().permissions().mode() & 0o7777;
        assert_eq!((mode("data"), mode(".env")), (0o2750, 0o640));
        // Root's files can't be changed; they're named instead.
        if unsafe { libc::geteuid() } != 0 {
            assert_eq!(close_to_others(&["/etc/passwd".into()]), ["/etc/passwd"]);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn pi_and_hermes_get_their_own_folders_in_the_owners() {
        let iso = for_tests(Path::new("/srv/superbot/users"), DEFAULT_SUDO);
        assert_eq!(iso.bot_state("u1", "b1").unwrap(), Path::new("/srv/superbot/users/u1/bots/b1"));
        assert_eq!(iso.bot_settings("u1", "b1").unwrap(), Path::new("/srv/superbot/users/u1/settings/b1"));
        assert_eq!(iso.run_as("u1").unwrap().settings, Path::new("/srv/superbot/users/u1/settings"));
        for bad in ["", "..", "a/b"] {
            assert_eq!(iso.bot_state("u1", bad), None, "{bad:?}");
            assert_eq!(iso.bot_settings("u1", bad), None, "{bad:?}");
        }
        assert_eq!(iso.bot_state("U1", "b1"), None);
        for h in ["claude", "codex", "pi", "hermes"] {
            assert!(HARNESSES.contains(&h), "{h} runs as its owner's account");
        }
    }

    #[test]
    fn a_bots_folders_are_made_real_and_the_settings_stay_botds() {
        use std::os::unix::fs::symlink;
        let root = crate::db::temp_path("bot-dirs");
        let iso = for_tests(&root, DEFAULT_SUDO);
        let elsewhere = crate::db::temp_path("bot-dirs-elsewhere");
        assert!(iso.make_bot_dirs("u1", "b1").is_err(), "no folders from root yet");
        for d in ["bots", "settings"] {
            std::fs::create_dir_all(root.join("u1").join(d)).unwrap();
        }
        // The account left a link where the Bot's state goes: it's dropped, not followed.
        symlink(&elsewhere, root.join("u1/bots/b1")).unwrap();
        iso.make_bot_dirs("u1", "b1").unwrap();
        let state = std::fs::symlink_metadata(iso.bot_state("u1", "b1").unwrap()).unwrap();
        assert!(state.is_dir() && state.mode() & 0o777 == 0o770);
        let settings = std::fs::symlink_metadata(iso.bot_settings("u1", "b1").unwrap()).unwrap();
        assert!(settings.is_dir() && settings.mode() & 0o777 == 0o750);
        iso.make_bot_dirs("u1", "b1").unwrap();
        // A settings folder botd didn't make is refused.
        symlink(&elsewhere, root.join("u1/settings/b2")).unwrap();
        assert!(iso.make_bot_dirs("u1", "b2").is_err());
    }

    #[test]
    fn isolated_jobs_write_only_into_settings_and_clean_up_as_the_account() {
        use crate::machines::wire::{JobCleanup, JobFile, PROTOCOL};
        use std::collections::BTreeMap;
        let root = crate::db::temp_path("prepare");
        let settings = root.join("u1/settings");
        std::fs::create_dir_all(&settings).unwrap();
        let run_as = RunAs { sudo: "/usr/bin/sudo".into(), runner: "/opt/superbot/bin/superbot-run".into(), account: "sb-u-u1".into(), settings: settings.clone() };
        let file = |p: &Path| JobFile { path: p.display().to_string(), body: "{}".into() };
        let state = root.join("u1/bots/b1");
        let job = JobRequest {
            protocol: PROTOCOL,
            job_id: String::new(),
            bot_id: String::new(),
            owner_id: String::new(),
            message_id: 0,
            bin: "hermes".into(),
            args: vec!["chat".into()],
            env: BTreeMap::from([("PATH".into(), "/usr/local/bin:/usr/bin".into())]),
            cwd: root.join("u1/workspace").display().to_string(),
            stdin: None,
            files: vec![file(&settings.join("b1/superbot-guard.ts")), file(&settings.join("b1/hermes-managed/config.yaml"))],
            cleanup: Some(JobCleanup {
                when_exists: state.join("hermes/gateway.pid").display().to_string(),
                bin: "hermes".into(),
                args: vec!["gateway".into(), "stop".into()],
                env: BTreeMap::from([("PATH".into(), "/usr/bin".into())]),
                cwd: state.display().to_string(),
                timeout_secs: 60,
            }),
            collect: vec![],
            for_user: None,
        };
        let ready = run_as.prepare(job.clone()).unwrap();
        assert!(ready.files.is_empty(), "botd wrote them already");
        for (p, mode) in [("b1", 0o750), ("b1/hermes-managed", 0o750), ("b1/superbot-guard.ts", 0o640), ("b1/hermes-managed/config.yaml", 0o640)] {
            assert_eq!(std::fs::symlink_metadata(settings.join(p)).unwrap().mode() & 0o777, mode, "{p}");
        }
        assert_eq!(ready.bin, "/usr/bin/sudo");
        assert_eq!(ready.args[..7], ["-n", "-E", "-u", "sb-u-u1", "--", "/opt/superbot/bin/superbot-run", "hermes"]);
        assert_eq!(ready.env["SUPERBOT_PATH"], "/usr/local/bin:/usr/bin");
        let c = ready.cleanup.unwrap();
        assert_eq!(c.when_exists, state.display().to_string(), "botd checks only the folder it made");
        assert_eq!(c.bin, "/usr/bin/sudo");
        assert_eq!(c.args[..10], ["-n", "-E", "-u", "sb-u-u1", "--", "/opt/superbot/bin/superbot-run", "/bin/sh", "-c", CLEANUP_IF_EXISTS, "sh"]);
        assert_eq!(c.args[10..], [state.join("hermes/gateway.pid").display().to_string(), "hermes".into(), "gateway".into(), "stop".into()]);
        assert_eq!(c.env["SUPERBOT_PATH"], "/usr/bin");

        // The check really runs the cleanup only when the file is there.
        let sh = |path: &Path| Command::new("/bin/sh").args(["-c", CLEANUP_IF_EXISTS, "sh"]).arg(path).args(["echo", "ran"]).output().unwrap();
        assert_eq!(String::from_utf8_lossy(&sh(&root.join("missing")).stdout), "");
        assert_eq!(String::from_utf8_lossy(&sh(&settings).stdout), "ran\n");

        // Nowhere else: not the run's state, not outside the user's folder, not through a link.
        for p in [state.join("x.ts"), root.join("u2/settings/b1/x.ts"), settings.join("../../x.ts"), settings.join("x.ts")] {
            let mut bad = job.clone();
            bad.files = vec![file(&p)];
            assert!(run_as.prepare(bad).is_err(), "{}", p.display());
        }
        let elsewhere = crate::db::temp_path("prepare-elsewhere");
        std::os::unix::fs::symlink(&elsewhere, settings.join("b9")).unwrap();
        let mut bad = job.clone();
        bad.files = vec![file(&settings.join("b9/x.ts"))];
        assert!(run_as.prepare(bad).is_err());
        assert!(!elsewhere.join("x.ts").exists());
    }

    #[test]
    fn account_setups_never_overlap() {
        let dir = crate::db::temp_path("setup");
        let log = dir.join("log");
        let sudo = dir.join("sudo");
        std::fs::write(&sudo, format!("#!/bin/sh\necho start >>'{0}'\nsleep 0.3\necho end >>'{0}'\nexit 1\n", log.display())).unwrap();
        std::fs::set_permissions(&sudo, std::fs::Permissions::from_mode(0o755)).unwrap();
        let iso = for_tests(&dir, sudo.to_str().unwrap());
        let runs: Vec<_> = (0..2).map(|_| std::thread::spawn({ let iso = iso.clone(); move || iso.ensure("u1") })).collect();
        for r in runs {
            assert!(r.join().unwrap().is_err());
        }
        assert_eq!(std::fs::read_to_string(&log).unwrap(), "start\nend\nstart\nend\n");
    }
}
