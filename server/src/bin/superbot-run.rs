//! superbot-run: starts one harness as a per-user account, when per-user isolation is
//! on (ADR 0037). botd runs
//!
//!   sudo -n -E -u sb-u-<user id> -- superbot-run <harness> [args...]
//!
//! It isn't privileged: it has only the rights of the account sudo switched to. It fixes
//! what the run sees (HOME from the password database, never the caller's; a umask that
//! keeps new files from other accounts; PATH from SUPERBOT_PATH, which sudo resets) and
//! passes a stop on to every process of the run, which botd can't signal itself.

#[path = "../passwd.rs"]
mod passwd;

use std::os::unix::fs::DirBuilderExt;
use std::path::Path;
use std::process::ExitCode;
use std::time::Duration;
use tokio::signal::unix::{signal, SignalKind};

const PREFIX: &str = "sb-u-";
/// How long a stopped run has to exit before KILL. Under botd's 5 seconds.
const GRACE: Duration = Duration::from_secs(4);
const DEFAULT_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
/// Settings that would point the harness at another account's files.
const DROP: [&str; 6] = ["XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_CACHE_HOME", "XDG_STATE_HOME", "XDG_RUNTIME_DIR", "MAIL"];

fn fail(msg: &str) -> ExitCode {
    eprintln!("superbot-run: {msg}");
    ExitCode::from(126)
}

/// Only per-user accounts run harnesses: never root, never botd's own account.
fn account_ok(name: &str, uid: u32) -> bool {
    uid != 0
        && name
            .strip_prefix(PREFIX)
            .is_some_and(|id| !id.is_empty() && id.len() <= 27 && id.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit()))
}

/// A run starts inside the account's own folders: `ISOLATION_DIR/<user id>`, its HOME's parent.
fn inside(home: &Path, cwd: &Path) -> bool {
    home.parent().is_some_and(|root| root.parent().is_some() && cwd.starts_with(root))
}

fn exit_code(status: std::io::Result<std::process::ExitStatus>) -> ExitCode {
    use std::os::unix::process::ExitStatusExt;
    match status {
        Ok(s) => ExitCode::from(s.code().or(s.signal().map(|n| 128 + n)).unwrap_or(1).clamp(0, 255) as u8),
        Err(_) => ExitCode::from(1),
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let mut args = std::env::args_os().skip(1);
    let Some(bin) = args.next() else { return fail("usage: superbot-run <harness> [args...]") };
    // SAFETY: getuid can't fail.
    let uid = unsafe { libc::getuid() };
    let Some(me) = passwd::by_uid(uid) else { return fail("this uid has no account") };
    if !account_ok(&me.name, uid) {
        return fail(&format!("refusing to run as this account: only per-user SuperBot accounts ({PREFIX}<user id>) run harnesses"));
    }
    let (Ok(home), Ok(cwd)) = (std::fs::canonicalize(&me.home), std::env::current_dir().and_then(std::fs::canonicalize)) else {
        return fail("the account's home or the working folder is missing");
    };
    if !inside(&home, &cwd) {
        return fail("refusing to start outside the account's own folders");
    }
    // SAFETY: plain syscalls on this process.
    unsafe {
        libc::umask(0o007);
        libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM);
    }
    // SAFETY: as above.
    if unsafe { libc::getppid() } == 1 {
        return fail("the sudo that started this is gone");
    }
    let (Ok(mut term), Ok(mut int), Ok(mut hup)) = (signal(SignalKind::terminate()), signal(SignalKind::interrupt()), signal(SignalKind::hangup())) else {
        return fail("couldn't watch for signals");
    };

    // botd's /tmp is shared by every account's runs; this one isn't.
    let tmp = home.join(".tmp");
    let _ = std::fs::DirBuilder::new().mode(0o700).create(&tmp);
    let mut cmd = tokio::process::Command::new(&bin);
    cmd.args(args)
        .env("TMPDIR", &tmp)
        .env("HOME", &home)
        .env("USER", &me.name)
        .env("LOGNAME", &me.name)
        .env("PATH", std::env::var_os("SUPERBOT_PATH").unwrap_or(DEFAULT_PATH.into()))
        .env_remove("SUPERBOT_PATH");
    for k in DROP {
        cmd.env_remove(k);
    }
    // SAFETY: isatty only reads fd 0's state.
    let tty = unsafe { libc::isatty(0) } == 1;
    // A run gets its own process group, so a stop reaches its tools too. A login at a
    // terminal stays in the terminal's group, or it couldn't read from it.
    if !tty {
        cmd.process_group(0);
    }
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => return fail(&format!("couldn't start {}: {e}", bin.to_string_lossy())),
    };
    let Some(pid) = child.id().map(|p| p as i32) else { return exit_code(child.wait().await) };
    let target = if tty { pid } else { -pid };
    tokio::select! {
        s = child.wait() => {
            // Tools it left behind could hold botd's pipe open, and once this process is
            // gone nothing botd may signal can reach them, so they end with the run.
            if !tty {
                end_group(target).await;
            }
            return exit_code(s);
        }
        _ = term.recv() => {}
        _ = int.recv() => {}
        _ = hup.recv() => {}
    }
    // Everything left of the run gets KILL before botd's own KILL, 5 seconds after its
    // TERM, takes sudo and this process away: tools that ignore TERM, or outlive the harness.
    let deadline = tokio::time::Instant::now() + GRACE;
    // SAFETY: signals this account's own processes.
    unsafe { libc::kill(target, libc::SIGTERM) };
    let exited = tokio::time::timeout_at(deadline, child.wait()).await.is_ok();
    if !tty {
        end_group_by(target, deadline).await;
    } else if !exited {
        // SAFETY: as above.
        unsafe { libc::kill(target, libc::SIGKILL) };
    }
    let _ = child.wait().await;
    ExitCode::from(143)
}

/// TERM to what's left of the run's group, then KILL after the grace period.
async fn end_group(group: i32) {
    if group_left(group) {
        // SAFETY: signals this account's own processes.
        unsafe { libc::kill(group, libc::SIGTERM) };
        end_group_by(group, tokio::time::Instant::now() + GRACE).await;
    }
}

/// Waits for the group to empty until `deadline`, then KILLs what's left.
async fn end_group_by(group: i32, deadline: tokio::time::Instant) {
    while group_left(group) && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    if group_left(group) {
        // SAFETY: signals this account's own processes.
        unsafe { libc::kill(group, libc::SIGKILL) };
    }
}

fn group_left(group: i32) -> bool {
    // SAFETY: signal 0 only checks that the group still has a process.
    (unsafe { libc::kill(group, 0) }) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_per_user_accounts_run_harnesses() {
        assert!(account_ok("sb-u-u1a2b3c4d", 1001));
        assert!(account_ok("sb-u-operator", 1002));
        for (name, uid) in [("root", 0), ("sb-u-x", 0), ("superbot", 999), ("sb-u-", 1001), ("sb-u-UPPER", 1001), ("sb-u-a.b", 1001), ("sb-u-a-b", 1001), ("sbu-x", 1001)] {
            assert!(!account_ok(name, uid), "{name}");
        }
        assert!(!account_ok(&format!("sb-u-{}", "a".repeat(28)), 1001));
    }

    #[test]
    fn runs_start_only_in_the_accounts_own_folders() {
        let home = Path::new("/srv/superbot/users/u1/home");
        assert!(inside(home, Path::new("/srv/superbot/users/u1/workspace")));
        assert!(inside(home, Path::new("/srv/superbot/users/u1/home")));
        assert!(inside(home, Path::new("/srv/superbot/users/u1")));
        assert!(!inside(home, Path::new("/srv/superbot/users/u2/workspace")));
        assert!(!inside(home, Path::new("/srv/superbot/users/u10")));
        assert!(!inside(home, Path::new("/home/superbot/superbot/data")));
        assert!(!inside(Path::new("/home"), Path::new("/etc")), "a home at the top has no folder of its own");
    }
}
