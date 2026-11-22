//! Chromium's sandbox where botd runs in the published image (ADR 0106). The image's
//! `chromium` (deploy/docker/chromium.sh) keeps the sandbox on unless
//! SUPERBOT_CHROMIUM_SANDBOX=off; botd checks once at start that it can actually come up,
//! so a host that blocks it says so in botd's log, not only in a Bot's failed browser.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;
use tokio::process::Command;

/// SUPERBOT_CHROMIUM_SANDBOX: on (the default) or off, exactly, as the image's `chromium`
/// reads it. True when on.
pub fn parse_sandbox(s: &str) -> Result<bool, String> {
    match s {
        "" | "on" => Ok(true),
        "off" => Ok(false),
        v => Err(format!("SUPERBOT_CHROMIUM_SANDBOX must be on or off, not \"{v}\"")),
    }
}

/// The browser agent-browser starts, when the environment names one (the image does).
pub fn browser() -> Option<PathBuf> {
    std::env::var_os("AGENT_BROWSER_EXECUTABLE_PATH").map(PathBuf::from).filter(|p| p.is_file())
}

/// Why Chromium couldn't start, from its stderr.
fn reason(stderr: &str) -> String {
    if stderr.contains("No usable sandbox") {
        return "it found no usable sandbox (the container blocks user namespaces)".into();
    }
    let last = stderr.lines().rev().map(str::trim).find(|l| !l.is_empty()).unwrap_or("no output");
    format!("it stopped: {}", last.chars().take(300).collect::<String>())
}

/// Starts `browser` once, headless, on a blank page, with its sandbox (it has no
/// --no-sandbox; Chromium then stops rather than run without one). Ok if it did.
pub async fn check(browser: &Path) -> Result<(), String> {
    let profile = std::env::temp_dir().join(format!("superbot-chromium-check-{}", std::process::id()));
    let mut cmd = Command::new(browser);
    cmd.args(["--headless", "--disable-gpu", "--no-first-run", "--dump-dom", "about:blank"])
        .arg(format!("--user-data-dir={}", profile.display()))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    crate::adapters::strip_secret_env(cmd.as_std_mut());
    let out = tokio::time::timeout(Duration::from_secs(60), cmd.output()).await;
    let _ = std::fs::remove_dir_all(&profile);
    match out {
        Err(_) => Err("it didn't finish loading a blank page within 60 s".into()),
        Ok(Err(e)) => Err(format!("couldn't start {}: {e}", browser.display())),
        Ok(Ok(o)) if o.status.success() => Ok(()),
        Ok(Ok(o)) => Err(reason(&String::from_utf8_lossy(&o.stderr))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sandbox_setting() {
        assert_eq!(parse_sandbox(""), Ok(true));
        assert_eq!(parse_sandbox("on"), Ok(true));
        assert_eq!(parse_sandbox("off"), Ok(false));
        assert!(parse_sandbox(" off ").is_err());
        assert!(parse_sandbox("no").unwrap_err().contains("on or off"));
    }

    #[test]
    fn names_a_missing_sandbox() {
        let err = "[1:1:ERROR:zygote_host_impl_linux.cc:130] No usable sandbox! If this is a Debian system...";
        assert!(reason(err).contains("no usable sandbox"));
        assert_eq!(reason("one\nlast line\n\n"), "it stopped: last line");
        assert_eq!(reason(""), "it stopped: no output");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn reports_a_browser_that_fails() {
        use std::os::unix::fs::PermissionsExt;
        let t = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        let dir = std::env::temp_dir().join(format!("superbot-chromium-test-{}-{t}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let fake = |name: &str, script: &str| {
            let p = dir.join(name);
            std::fs::write(&p, script).unwrap();
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
            p
        };
        let ok = fake("ok", "#!/bin/sh\ncase \"$*\" in *--no-sandbox*) exit 1 ;; esac\nexit 0\n");
        assert_eq!(check(&ok).await, Ok(()));
        let blocked = fake("blocked", "#!/bin/sh\necho 'ERROR: No usable sandbox! Try --no-sandbox' >&2\nexit 1\n");
        assert!(check(&blocked).await.unwrap_err().contains("no usable sandbox"));
        assert!(check(&dir.join("missing")).await.unwrap_err().contains("couldn't start"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
