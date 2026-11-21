//! Harness logins on a machine (ADR 0041). The agent runs a harness CLI's own login in
//! a pseudo-terminal, since logins expect one, streams what it writes, and types the
//! lines it is sent. What the login saves stays on the machine: the agent only checks
//! whether a credential file exists, never reads one. It knows no harness: botd sends
//! the command and where its credentials go. Shared by the agent binary and botd, which
//! runs teammates' logins on its own server with it (ADR 0064), so it uses nothing of
//! botd's but `wire`.

// Shared by two binaries, each of which uses only part of it.
#![allow(dead_code)]

use super::runas::{self, Ids};
use super::wire::{self, LoginEvent, LoginRequest};
use std::collections::{BTreeMap, HashMap};
use std::io::{Read, Write};
use std::os::fd::{FromRawFd, OwnedFd};
use std::path::Path;
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::{mpsc, watch};

/// The longest line a login takes.
pub const MAX_INPUT: usize = 4096;
/// How long a login may wait for its user, at most and at least.
pub const MAX_SECS: u64 = 1800;
pub const MIN_SECS: u64 = 30;
/// Logins at once; one per harness for each person (the owner, and each teammate).
const MAX_LOGINS: usize = 4;
const GRACE: Duration = Duration::from_secs(3);

struct Session {
    harness: String,
    /// The teammate it's for (ADR 0062); None: the owner.
    for_user: Option<String>,
    /// The terminal's controlling side, for typing into it.
    input: Arc<Mutex<std::fs::File>>,
    stop: watch::Sender<bool>,
}

/// The logins running now, by id.
#[derive(Default)]
pub struct Logins {
    sessions: Mutex<HashMap<String, Session>>,
}

/// Why a request was refused: an HTTP status and a message.
pub type Refused = (u16, String);

fn plain(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// A login to run: the harness CLI and its arguments. On a machine, each is one of
/// `wire`'s own words (`check`); botd's own logins on its server start the CLI through
/// `superbot-run` as a teammate's account (ADR 0064).
#[derive(Debug, PartialEq)]
pub struct Command {
    pub bin: String,
    pub args: Vec<String>,
}

/// Whether `r` is a login this agent will run, `has` saying which harnesses are installed.
pub fn check(r: &LoginRequest, has: impl Fn(&str) -> bool) -> Result<Command, Refused> {
    let bad = |m: &str| Err((400, m.to_string()));
    if !plain(&r.login_id) {
        return bad("The login id isn't a plain name.");
    }
    let Some(bin) = wire::harness_bin(&r.harness) else {
        return bad("That isn't a harness this machine runs.");
    };
    let Some(args) = r
        .args
        .iter()
        .map(|a| wire::login_word(a))
        .collect::<Option<Vec<_>>>()
    else {
        return bad("The login's arguments aren't ones a machine login takes.");
    };
    if r.files.is_empty() || r.files.len() > 4 || !r.files.iter().all(|f| wire::home_path(f)) {
        return bad("Credential files must be paths inside HOME.");
    }
    if !has(bin) {
        return Err((422, format!("{bin} isn't installed on this machine.")));
    }
    Ok(Command {
        bin: bin.into(),
        args: args.into_iter().map(String::from).collect(),
    })
}

/// `f` under `home`, if it is a plain relative path there.
fn under(home: &Path, f: &str) -> Option<std::path::PathBuf> {
    if f.contains("..") {
        return None;
    }
    if !wire::home_path(f) {
        return None;
    }
    Some(home.join(f))
}

/// When the newest of `files` (relative to `home`) last changed, if one is there. A
/// link counts as none: a credential is a plain file the login wrote.
pub fn logged_in(home: &Path, files: &[String]) -> Option<i64> {
    files
        .iter()
        .filter_map(|f| under(home, f))
        .filter_map(|p| std::fs::symlink_metadata(p).ok())
        .filter(|m| m.is_file() && m.len() > 0)
        .filter_map(|m| m.modified().ok())
        .filter_map(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_millis() as i64)
        .max()
}

/// Logs out: removes `files` (relative to `home`). Returns how many were there.
pub fn forget(home: &Path, files: &[String]) -> u32 {
    let mut n = 0;
    for p in files.iter().filter_map(|f| under(home, f)) {
        // Removing a link removes the link, never what it points to.
        if std::fs::symlink_metadata(&p).is_ok_and(|m| !m.is_dir())
            && std::fs::remove_file(&p).is_ok()
        {
            n += 1;
        }
    }
    n
}

/// A new pseudo-terminal, 120x40, that doesn't echo: a typed code isn't sent back.
fn open_pty() -> std::io::Result<(OwnedFd, OwnedFd)> {
    let err = std::io::Error::last_os_error;
    // SAFETY: plain libc calls on descriptors this function owns; each result is checked.
    unsafe {
        let m = libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC);
        if m < 0 {
            return Err(err());
        }
        let master = OwnedFd::from_raw_fd(m);
        if libc::grantpt(m) != 0 || libc::unlockpt(m) != 0 {
            return Err(err());
        }
        let mut name = [0 as libc::c_char; 128];
        if libc::ptsname_r(m, name.as_mut_ptr(), name.len()) != 0 {
            return Err(err());
        }
        let s = libc::open(
            name.as_ptr(),
            libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC,
        );
        if s < 0 {
            return Err(err());
        }
        let slave = OwnedFd::from_raw_fd(s);
        let size = libc::winsize {
            ws_row: 40,
            ws_col: 120,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        libc::ioctl(s, libc::TIOCSWINSZ, &size);
        let mut t: libc::termios = std::mem::zeroed();
        if libc::tcgetattr(s, &mut t) == 0 {
            t.c_lflag &= !(libc::ECHO | libc::ECHONL);
            libc::tcsetattr(s, libc::TCSANOW, &t);
        }
        Ok((master, slave))
    }
}

fn kill_group(pid: u32, signal: libc::c_int) {
    // SAFETY: signals the process group the login leads (it called setsid).
    unsafe {
        libc::kill(-(pid as libc::pid_t), signal);
    }
}

/// Sends what the terminal shows, as text, until it closes. A character split between
/// reads is kept for the next.
fn read_terminal(mut from: std::fs::File, tx: mpsc::Sender<LoginEvent>) {
    let mut buf = [0u8; 4096];
    let mut held: Vec<u8> = Vec::new();
    loop {
        let n = match from.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        held.extend_from_slice(&buf[..n]);
        let upto = match std::str::from_utf8(&held) {
            Ok(_) => held.len(),
            Err(e) if e.error_len().is_none() => e.valid_up_to(),
            Err(_) => held.len(),
        };
        let text = String::from_utf8_lossy(&held[..upto]).into_owned();
        held.drain(..upto);
        if !text.is_empty() && tx.blocking_send(LoginEvent::Output { text }).is_err() {
            break;
        }
    }
}

/// Removes a login from the running ones when it ends, however it ends.
struct Registered(Arc<Logins>, String);

impl Drop for Registered {
    fn drop(&mut self) {
        self.0.sessions().remove(&self.1);
    }
}

impl Logins {
    fn sessions(&self) -> std::sync::MutexGuard<'_, HashMap<String, Session>> {
        self.sessions.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// The harnesses logging in now, for anyone.
    pub fn running(&self) -> Vec<String> {
        self.sessions()
            .values()
            .map(|s| s.harness.clone())
            .collect()
    }

    /// The harnesses logging in now for `for_user` (None: the owner) only.
    pub fn running_for(&self, for_user: Option<&str>) -> Vec<String> {
        self.sessions()
            .values()
            .filter(|s| s.for_user.as_deref() == for_user)
            .map(|s| s.harness.clone())
            .collect()
    }

    /// Stops every login of teammate `user_id`. How many there were.
    pub fn abort_for(&self, user_id: &str) -> u32 {
        let s = self.sessions();
        let theirs: Vec<&Session> = s
            .values()
            .filter(|s| s.for_user.as_deref() == Some(user_id))
            .collect();
        for t in &theirs {
            let _ = t.stop.send(true);
        }
        theirs.len() as u32
    }

    /// Starts the login, `run` (from `check`) in `home` with exactly `env`, as `user`
    /// if one is given (ADR 0043; a teammate's own, ADR 0062). Its events come on the
    /// receiver, which ends after `Exit` or `Error`; `stop` (or `abort`) ends it early.
    pub fn start(
        self: &Arc<Self>,
        r: &LoginRequest,
        run: &Command,
        home: &Path,
        env: &BTreeMap<String, String>,
        user: Option<Ids>,
    ) -> Result<(mpsc::Receiver<LoginEvent>, watch::Sender<bool>), Refused> {
        let (master, slave) =
            open_pty().map_err(|e| (500, format!("Couldn't open a terminal: {e}")))?;
        if let Some(ids) = user {
            use std::os::fd::AsRawFd;
            // SAFETY: an open descriptor; the login's user owns its terminal.
            if unsafe { libc::fchown(slave.as_raw_fd(), ids.uid, ids.gid) } != 0 {
                return Err((
                    500,
                    format!(
                        "Couldn't give the terminal to the Bots' user: {}",
                        std::io::Error::last_os_error()
                    ),
                ));
            }
        }
        let input = std::fs::File::from(master);
        let reader = input.try_clone().map_err(|e| (500, e.to_string()))?;
        let (stop_tx, mut stop_rx) = watch::channel(false);
        {
            let mut s = self.sessions();
            if s.values()
                .any(|s| s.harness == r.harness && s.for_user == r.for_user)
            {
                return Err((
                    409,
                    format!("A {} login is already running here.", r.harness),
                ));
            }
            if s.len() >= MAX_LOGINS || s.contains_key(&r.login_id) {
                return Err((
                    409,
                    "Another login is running here. Try again when it's done.".into(),
                ));
            }
            s.insert(
                r.login_id.clone(),
                Session {
                    harness: r.harness.clone(),
                    for_user: r.for_user.clone(),
                    input: Arc::new(Mutex::new(input)),
                    stop: stop_tx.clone(),
                },
            );
        }
        let registered = Registered(self.clone(), r.login_id.clone());
        let stdio = |fd: &OwnedFd| fd.try_clone().map(Stdio::from);
        let (Ok(i), Ok(o), Ok(e)) = (stdio(&slave), stdio(&slave), stdio(&slave)) else {
            return Err((500, "Couldn't set up the terminal.".into()));
        };
        let mut cmd = tokio::process::Command::new(&run.bin);
        cmd.args(&run.args)
            .current_dir(home)
            .env_clear()
            .envs(env)
            .env("TERM", "xterm-256color")
            .stdin(i)
            .stdout(o)
            .stderr(e)
            .kill_on_drop(true);
        if let Some(ids) = user {
            cmd.uid(ids.uid).gid(ids.gid);
        }
        // SAFETY: only async-signal-safe calls between fork and exec.
        unsafe {
            cmd.pre_exec(|| {
                if libc::setsid() < 0 || libc::ioctl(0, libc::TIOCSCTTY, 0) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut child = cmd
            .spawn()
            .map_err(|e| (500, format!("Couldn't start {}: {e}", run.bin)))?;
        drop(slave);
        let pid = child.id();
        let (tx, rx) = mpsc::channel::<LoginEvent>(256);
        // First, before anything it shows.
        let _ = tx.try_send(LoginEvent::Started {
            login_id: r.login_id.clone(),
        });
        let reading = {
            let tx = tx.clone();
            tokio::task::spawn_blocking(move || read_terminal(reader, tx))
        };
        let (home, files) = (home.to_path_buf(), r.files.clone());
        let timeout = Duration::from_secs(r.timeout_secs.clamp(MIN_SECS, MAX_SECS));
        tokio::spawn(async move {
            let _registered = registered;
            let mut status = tokio::select! {
                s = child.wait() => Some(s),
                _ = stop_rx.wait_for(|s| *s) => None,
                _ = tokio::time::sleep(timeout) => None,
            };
            if status.is_none() {
                if let Some(pid) = pid {
                    kill_group(pid, libc::SIGTERM);
                }
                status = match tokio::time::timeout(GRACE, child.wait()).await {
                    Ok(s) => Some(s),
                    Err(_) => {
                        if let Some(pid) = pid {
                            kill_group(pid, libc::SIGKILL);
                        }
                        Some(child.wait().await)
                    }
                };
            }
            // What it wrote last comes before its exit, unless something it started
            // holds the terminal open.
            let _ = tokio::time::timeout(GRACE, reading).await;
            let status = status.expect("set above");
            let logged_in =
                runas::as_user(user, || logged_in(&home, &files).is_some()).unwrap_or(false);
            let _ = tx
                .send(LoginEvent::Exit {
                    success: status.as_ref().is_ok_and(|s| s.success()),
                    status: status
                        .map(|s| s.to_string())
                        .unwrap_or_else(|e| e.to_string()),
                    logged_in,
                })
                .await;
        });
        Ok((rx, stop_tx))
    }

    /// Types `text` and Enter into the login.
    pub fn input(&self, id: &str, text: &str) -> Result<(), Refused> {
        if text.len() > MAX_INPUT || text.chars().any(char::is_control) {
            return Err((400, "Send one plain line.".into()));
        }
        let input = self
            .sessions()
            .get(id)
            .map(|s| s.input.clone())
            .ok_or((404, "No such login is running.".to_string()))?;
        let mut f = input.lock().unwrap_or_else(|e| e.into_inner());
        f.write_all(format!("{text}\r").as_bytes())
            .and_then(|_| f.flush())
            .map_err(|e| (500, e.to_string()))
    }

    /// Stops a login. Returns whether it was running.
    pub fn abort(&self, id: &str) -> bool {
        match self.sessions().get(id) {
            Some(s) => {
                let _ = s.stop.send(true);
                true
            }
            None => false,
        }
    }
}

/// The raw descriptor, for tests that look at the terminal's settings.
#[cfg(test)]
fn echoes(fd: &OwnedFd) -> bool {
    // SAFETY: reads the settings of a descriptor the caller owns.
    unsafe {
        let mut t: libc::termios = std::mem::zeroed();
        libc::tcgetattr(std::os::fd::AsRawFd::as_raw_fd(fd), &mut t);
        t.c_lflag & libc::ECHO != 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A stand-in CLI at `path`, run as a login is.
    // Run through sh rather than exec'ing the script: a parallel test's fork can still hold
    // the script open for writing, and exec then fails with ETXTBSY.
    fn fake(path: &Path) -> Command {
        Command {
            bin: "/bin/sh".into(),
            args: vec![path.to_str().unwrap().into(), "auth".into(), "login".into()],
        }
    }

    fn scratch(tag: &str) -> std::path::PathBuf {
        let t = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let d =
            std::env::temp_dir().join(format!("superbot-login-{tag}-{}-{t}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn req(files: &[&str]) -> LoginRequest {
        LoginRequest {
            login_id: "l1".into(),
            harness: "claude".into(),
            args: vec!["auth".into(), "login".into()],
            files: files.iter().map(|f| f.to_string()).collect(),
            timeout_secs: 60,
            for_user: None,
        }
    }

    #[test]
    fn only_plain_logins_of_installed_harnesses_run() {
        assert_eq!(
            check(&req(&[".claude/.credentials.json"]), |_| true),
            Ok(Command {
                bin: "claude".into(),
                args: vec!["auth".into(), "login".into()]
            })
        );
        assert_eq!(check(&req(&[".claude/x"]), |_| false).unwrap_err().0, 422);
        for files in [&[][..], &["/etc/shadow"], &["../x"], &[".claude/../../x"]] {
            assert_eq!(
                check(&req(files), |_| true).unwrap_err().0,
                400,
                "{files:?}"
            );
        }
        let mut r = req(&["a"]);
        r.harness = "sh".into();
        assert!(check(&r, |_| true).is_err());
        let mut r = req(&["a"]);
        r.login_id = "../x".into();
        assert!(check(&r, |_| true).is_err());
        let mut r = req(&["a"]);
        r.args.push("a\nb".into());
        assert!(check(&r, |_| true).is_err());
        let mut r = req(&["a"]);
        r.args.push("--dangerously-skip-permissions".into());
        assert_eq!(
            check(&r, |_| true).unwrap_err().0,
            400,
            "only a login's own words"
        );
    }

    #[test]
    fn a_login_is_a_plain_file_and_forgetting_removes_only_links_and_files() {
        let home = scratch("files");
        let files = vec![".claude/.credentials.json".to_string()];
        assert_eq!(logged_in(&home, &files), None);
        std::fs::create_dir_all(home.join(".claude")).unwrap();
        let outside = scratch("outside").join("keep");
        std::fs::write(&outside, "keep").unwrap();
        std::os::unix::fs::symlink(&outside, home.join(&files[0])).unwrap();
        assert_eq!(logged_in(&home, &files), None, "a link isn't a login");
        assert_eq!(forget(&home, &files), 1);
        assert_eq!(std::fs::read_to_string(&outside).unwrap(), "keep");
        std::fs::write(home.join(&files[0]), "{}").unwrap();
        assert!(logged_in(&home, &files).is_some());
        assert_eq!(forget(&home, &files), 1);
        assert_eq!(logged_in(&home, &files), None);
        assert_eq!(forget(&home, &["../../etc/passwd".into()]), 0);
    }

    #[test]
    fn the_terminal_does_not_echo() {
        let (_m, s) = open_pty().unwrap();
        assert!(!echoes(&s));
    }

    #[tokio::test]
    async fn a_login_reads_a_typed_line_in_a_terminal_and_reports_its_file() {
        let home = scratch("run");
        let bin = home.join("fake-login");
        std::fs::write(
            &bin,
            "#!/bin/sh\n[ -t 0 ] || { echo 'no terminal'; exit 4; }\nprintf 'Paste the code: '\nread code\n\
             [ \"$code\" = ok ] || { echo bad; exit 1; }\nmkdir -p .claude && echo '{}' > .claude/.credentials.json\necho done\n",
        )
        .unwrap();
        std::fs::set_permissions(&bin, std::os::unix::fs::PermissionsExt::from_mode(0o755))
            .unwrap();
        let logins = Arc::new(Logins::default());
        let r = req(&[".claude/.credentials.json"]);
        let env = BTreeMap::from([("PATH".to_string(), "/usr/bin:/bin".to_string())]);
        let (mut rx, _stop) = logins.start(&r, &fake(&bin), &home, &env, None).unwrap();
        assert_eq!(logins.running(), vec!["claude".to_string()]);
        assert_eq!(
            logins
                .start(&r, &fake(&bin), &home, &env, None)
                .unwrap_err()
                .0,
            409
        );
        let mut shown = String::new();
        let mut typed = false;
        let exit = loop {
            let e = tokio::time::timeout(Duration::from_secs(10), rx.recv())
                .await
                .unwrap()
                .unwrap();
            match e {
                LoginEvent::Output { text } => {
                    shown.push_str(&text);
                    if !typed && shown.contains("Paste the code") {
                        logins.input("l1", "ok").unwrap();
                        typed = true;
                    }
                }
                LoginEvent::Exit { .. } => break e,
                _ => {}
            }
        };
        assert_eq!(
            exit,
            LoginEvent::Exit {
                success: true,
                status: "exit status: 0".into(),
                logged_in: true
            },
            "{shown}"
        );
        assert!(
            shown.contains("done") && !shown.contains("ok\r"),
            "{shown:?}"
        );
        assert!(logins.running().is_empty());
        assert_eq!(logins.input("l1", "x").unwrap_err().0, 404);
        assert_eq!(logins.input("l1", "a\u{1b}b").unwrap_err().0, 400);
    }

    #[tokio::test]
    async fn an_aborted_login_is_stopped() {
        let home = scratch("run");
        let bin = home.join("slow-login");
        std::fs::write(&bin, "#!/bin/sh\necho waiting\nsleep 60\n").unwrap();
        std::fs::set_permissions(&bin, std::os::unix::fs::PermissionsExt::from_mode(0o755))
            .unwrap();
        let logins = Arc::new(Logins::default());
        let r = req(&[".claude/.credentials.json"]);
        let env = BTreeMap::from([("PATH".to_string(), "/usr/bin:/bin".to_string())]);
        let (mut rx, _stop) = logins.start(&r, &fake(&bin), &home, &env, None).unwrap();
        let _ = rx.recv().await;
        assert!(logins.abort("l1"));
        let exit = loop {
            if let e @ LoginEvent::Exit { .. } =
                tokio::time::timeout(Duration::from_secs(10), rx.recv())
                    .await
                    .unwrap()
                    .unwrap()
            {
                break e;
            }
        };
        assert!(matches!(
            exit,
            LoginEvent::Exit {
                success: false,
                logged_in: false,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn each_person_has_their_own_login_per_harness_and_a_leaving_teammates_stop() {
        let home = scratch("people");
        let bin = home.join("slow-login");
        std::fs::write(&bin, "#!/bin/sh\necho waiting\nsleep 60\n").unwrap();
        std::fs::set_permissions(&bin, std::os::unix::fs::PermissionsExt::from_mode(0o755))
            .unwrap();
        let logins = Arc::new(Logins::default());
        let env = BTreeMap::from([("PATH".to_string(), "/usr/bin:/bin".to_string())]);
        let for_user = |id: &str, who: Option<&str>| LoginRequest {
            login_id: id.into(),
            for_user: who.map(String::from),
            ..req(&[".claude/.credentials.json"])
        };
        let (mut owner, _s1) = logins
            .start(&for_user("l1", None), &fake(&bin), &home, &env, None)
            .unwrap();
        let (mut bea, _s2) = logins
            .start(
                &for_user("l2", Some("u-bea")),
                &fake(&bin),
                &home,
                &env,
                None,
            )
            .unwrap();
        let (_cy, _s3) = logins
            .start(
                &for_user("l3", Some("u-cy")),
                &fake(&bin),
                &home,
                &env,
                None,
            )
            .unwrap();
        assert_eq!(
            logins
                .start(
                    &for_user("l4", Some("u-bea")),
                    &fake(&bin),
                    &home,
                    &env,
                    None
                )
                .unwrap_err()
                .0,
            409,
            "one each"
        );
        assert_eq!(logins.running_for(None), ["claude"], "the owner's own only");
        assert_eq!(logins.running_for(Some("u-bea")), ["claude"]);
        assert!(logins.running_for(Some("u-dan")).is_empty());

        assert_eq!(logins.abort_for("u-bea"), 1);
        let ended = async |rx: &mut mpsc::Receiver<LoginEvent>| loop {
            match tokio::time::timeout(Duration::from_secs(10), rx.recv())
                .await
                .unwrap()
            {
                Some(LoginEvent::Exit { .. }) | None => break true,
                _ => {}
            }
        };
        assert!(ended(&mut bea).await);
        assert!(logins.running_for(Some("u-bea")).is_empty());
        assert_eq!(logins.running_for(Some("u-cy")), ["claude"], "Cy's goes on");
        assert_eq!(logins.running_for(None), ["claude"], "and the owner's");
        assert!(logins.abort("l1"));
        assert!(ended(&mut owner).await);
    }
}
