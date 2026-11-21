//! Runs one harness job (ADR 0036): stops what the harness left running, writes its
//! files, starts it, and reports what happens as `JobEvent`s. botd runs Bots on this
//! server with it, and the machine agent runs them on a user's machine, so both
//! behave the same. Shared by both binaries, so it uses nothing of botd's but `wire`.

// Shared by two binaries, each of which uses only part of it.
#![allow(dead_code)]

use super::runas::{self, Ids};
use super::wire::{JobCleanup, JobEvent, JobFile, JobRequest};
use std::collections::BTreeMap;
use std::future::Future;
use std::path::Path;
use std::process::Stdio;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, BufReader};
use tokio::process::Command;
use tokio::sync::mpsc;

/// Largest file a job sends back (`collect`).
pub const MAX_COLLECT: u64 = 1 << 20;

/// What the host adds to every job's environment.
#[derive(Clone, Default)]
pub struct Host {
    /// Start from an empty environment instead of this process's.
    pub clear_env: bool,
    /// Variables of this process that jobs must not inherit.
    pub remove: Vec<String>,
    /// Set before the job's own `env`.
    pub env: BTreeMap<String, String>,
    /// Run as this user, and touch the job's files as it (ADR 0043).
    pub user: Option<Ids>,
}

impl Host {
    fn command(&self, bin: &str, env: &BTreeMap<String, String>) -> Command {
        let mut cmd = Command::new(bin);
        if self.clear_env {
            cmd.env_clear();
        }
        for k in &self.remove {
            cmd.env_remove(k);
        }
        cmd.envs(&self.env).envs(env);
        if let Some(ids) = self.user {
            cmd.uid(ids.uid).gid(ids.gid);
        }
        cmd
    }

    /// Runs `f` with the job's file access.
    fn files<T>(&self, f: impl FnOnce() -> T) -> Result<T, String> {
        runas::as_user(self.user, f).map_err(|e| format!("Couldn't act as the Bots' user: {e}"))
    }
}

/// Kills the job's process group if the job is dropped before it exits.
struct Group(Option<u32>);

impl Drop for Group {
    fn drop(&mut self) {
        if let Some(pid) = self.0 {
            kill_group(pid, "KILL");
        }
    }
}

/// How long a stopped harness gets between TERM and KILL.
const STOP_GRACE: Duration = Duration::from_secs(5);

fn kill_group(pid: u32, signal: &str) {
    let _ = std::process::Command::new("kill")
        .args([format!("-{signal}"), "--".into(), format!("-{pid}")])
        .stderr(Stdio::null())
        .status();
}

/// Writes `body` to `path`, mode 0600, making missing folders 0700. Atomic: a
/// reader never sees half a file.
pub fn write_private(path: &Path, body: &str) -> std::io::Result<()> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    let dir = path.parent().ok_or(std::io::ErrorKind::InvalidInput)?;
    let name = path.file_name().ok_or(std::io::ErrorKind::InvalidInput)?;
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)?;
    let tmp = dir.join(format!(".{}.tmp", name.to_string_lossy()));
    std::fs::write(&tmp, body)?;
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
    std::fs::rename(tmp, path)
}

/// Skips a `collect` file that's too big to send back: it's newer than any copy the
/// job brings, which can only be from before it grew.
fn write_files(files: &[JobFile], collect: &[String]) -> Result<(), String> {
    for f in files {
        if collect.contains(&f.path) && too_big(&f.path) {
            continue;
        }
        write_private(Path::new(&f.path), &f.body)
            .map_err(|e| format!("Couldn't write {}: {e}", f.path))?;
    }
    Ok(())
}

/// Runs a cleanup command if its `when_exists` file is there. The error says why it
/// failed, in a few words.
pub async fn cleanup(host: &Host, c: &JobCleanup) -> Result<(), String> {
    if !host.files(|| Path::new(&c.when_exists).exists())? {
        return Ok(());
    }
    let label = format!("`{} {}`", c.bin, c.args.join(" "));
    let mut cmd = host.command(&c.bin, &c.env);
    let child = cmd
        .args(&c.args)
        .current_dir(&c.cwd)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .process_group(0)
        .kill_on_drop(true)
        .spawn();
    let mut child = child.map_err(|e| format!("{label} didn't start: {e}"))?;
    let mut group = Group(child.id());
    let done = tokio::time::timeout(Duration::from_secs(c.timeout_secs), child.wait()).await;
    if let Ok(Ok(_)) = done {
        group.0 = None;
    }
    match done {
        Ok(Ok(s)) if s.success() => Ok(()),
        Ok(Ok(s)) => Err(format!("{label} failed: {s}")),
        Ok(Err(e)) => Err(e.to_string()),
        Err(_) => Err(format!("{label} took over {} seconds", c.timeout_secs)),
    }
}

/// The last few lines of a harness's stderr: enough to say why it failed.
fn tail(stderr: &str) -> String {
    let lines: Vec<&str> = stderr.trim().lines().rev().take(3).collect();
    lines.into_iter().rev().collect::<Vec<_>>().join("\n")
}

fn too_big(path: &str) -> bool {
    std::fs::metadata(path).is_ok_and(|m| m.is_file() && m.len() > MAX_COLLECT)
}

/// The `collect` files to send back, and those too big to.
fn collect(paths: &[String]) -> (BTreeMap<String, String>, Vec<String>) {
    let (big, rest): (Vec<&String>, Vec<&String>) = paths.iter().partition(|p| too_big(p));
    let files = rest
        .into_iter()
        .filter(|p| std::fs::metadata(p).is_ok_and(|m| m.is_file()))
        .filter_map(|p| Some((p.clone(), std::fs::read_to_string(p).ok()?)))
        .collect();
    (files, big.into_iter().cloned().collect())
}

/// Runs `job` until it exits or `abort` resolves, sending what happens to `tx`. A
/// cleanup that fails before the run stops it there. Dropping the future kills the
/// harness.
pub async fn run(
    host: &Host,
    job: &JobRequest,
    abort: impl Future<Output = ()>,
    tx: &mpsc::Sender<JobEvent>,
) {
    if let Some(c) = &job.cleanup
        && let Err(why) = cleanup(host, c).await
    {
        let _ = tx.send(JobEvent::Cleanup { why }).await;
        return;
    }
    match host.files(|| write_files(&job.files, &job.collect)).and_then(|r| r) {
        Ok(()) => run_child(host, job, abort, tx).await,
        Err(message) => {
            let _ = tx.send(JobEvent::Error { message }).await;
        }
    }
    if let Some(c) = &job.cleanup
        && let Err(why) = cleanup(host, c).await
    {
        let _ = tx.send(JobEvent::Cleanup { why }).await;
    }
}

async fn run_child(
    host: &Host,
    job: &JobRequest,
    abort: impl Future<Output = ()>,
    tx: &mpsc::Sender<JobEvent>,
) {
    let mut cmd = host.command(&job.bin, &job.env);
    let child = cmd
        .args(&job.args)
        .current_dir(&job.cwd)
        .stdin(if job.stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        // Its own group, so stopping it stops everything it started.
        .process_group(0)
        .kill_on_drop(true)
        .spawn();
    let mut child = match child {
        Ok(c) => c,
        Err(e) => {
            let message = format!("Couldn't start {}: {e}", job.bin);
            let _ = tx.send(JobEvent::Error { message }).await;
            return;
        }
    };
    let mut group = Group(child.id());
    let _ = tx.send(JobEvent::Started).await;
    if let (Some(text), Some(mut pipe)) = (job.stdin.clone(), child.stdin.take()) {
        tokio::spawn(async move {
            use tokio::io::AsyncWriteExt;
            let _ = pipe.write_all(text.as_bytes()).await;
        });
    }
    let mut stderr = child.stderr.take().expect("piped");
    let mut stderr_task = tokio::spawn(async move {
        let mut s = String::new();
        let _ = stderr.read_to_string(&mut s).await;
        s
    });

    // Abort is honoured until the end: a harness can close its output and keep running.
    let mut abort = std::pin::pin!(abort);
    let mut aborted = false;
    let stop = |aborted: &mut bool| {
        *aborted = true;
        if let Some(pid) = group.0 {
            kill_group(pid, "TERM");
            tokio::spawn(async move {
                tokio::time::sleep(STOP_GRACE).await;
                kill_group(pid, "KILL");
            });
        }
    };
    // JSON lines. Split only on "\n": some harnesses put U+2028 inside JSON strings.
    let mut lines = BufReader::new(child.stdout.take().expect("piped")).split(b'\n');
    loop {
        tokio::select! {
            line = lines.next_segment() => match line {
                Ok(Some(bytes)) => {
                    let line = String::from_utf8_lossy(&bytes).into_owned();
                    // No one is listening: stop it, and still wait for it to exit.
                    if tx.send(JobEvent::Line { line }).await.is_err() && !aborted {
                        stop(&mut aborted);
                    }
                }
                _ => break,
            },
            _ = &mut abort, if !aborted => stop(&mut aborted),
        }
    }
    let status = loop {
        tokio::select! {
            status = child.wait() => break status,
            _ = &mut abort, if !aborted => stop(&mut aborted),
        }
    };
    // Something it started may still hold stderr open; once stopped, don't wait for it.
    let stderr = loop {
        tokio::select! {
            s = &mut stderr_task => break s.unwrap_or_default(),
            _ = &mut abort, if !aborted => stop(&mut aborted),
            _ = tokio::time::sleep(STOP_GRACE * 2), if aborted => {
                stderr_task.abort();
                break String::new();
            }
        }
    };
    group.0 = None;
    let (files, too_big) = host.files(|| collect(&job.collect)).unwrap_or_default();
    let _ = tx
        .send(JobEvent::Exit {
            success: status.as_ref().is_ok_and(|s| s.success()),
            status: status
                .map(|s| s.to_string())
                .unwrap_or_else(|e| e.to_string()),
            stderr: tail(&stderr),
            files,
            too_big,
        })
        .await;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn job(script: &str, dir: &Path) -> JobRequest {
        JobRequest {
            protocol: super::super::wire::PROTOCOL,
            job_id: "j1".into(),
            bot_id: "b1".into(),
            owner_id: "u1".into(),
            for_user: None,
            message_id: 1,
            bin: "sh".into(),
            args: vec!["-c".into(), script.into()],
            env: BTreeMap::from([("GREETING".into(), "hi".into())]),
            cwd: dir.display().to_string(),
            stdin: Some("from stdin".into()),
            files: vec![JobFile {
                path: dir.join("deep/conf.json").display().to_string(),
                body: "{}".into(),
            }],
            cleanup: None,
            collect: vec![
                dir.join("out.md").display().to_string(),
                dir.join("absent").display().to_string(),
            ],
        }
    }

    async fn events(host: &Host, j: &JobRequest, abort: bool) -> Vec<JobEvent> {
        let (tx, mut rx) = mpsc::channel(64);
        let stop = async move {
            if abort {
                tokio::time::sleep(Duration::from_millis(300)).await;
            } else {
                std::future::pending::<()>().await;
            }
        };
        run(host, j, stop, &tx).await;
        drop(tx);
        let mut out = Vec::new();
        while let Some(e) = rx.recv().await {
            out.push(e);
        }
        out
    }

    #[tokio::test]
    async fn a_job_writes_files_streams_lines_and_sends_back_files() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("job-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let j = job(
            "cat deep/conf.json; echo; echo \"$GREETING $(cat)\"; echo note > out.md; echo oops >&2; exit 3",
            &dir,
        );
        let ev = events(&Host::default(), &j, false).await;
        let lines: Vec<&str> = ev
            .iter()
            .filter_map(|e| match e {
                JobEvent::Line { line } => Some(line.as_str()),
                _ => None,
            })
            .collect();
        assert_eq!(lines, ["{}", "hi from stdin"]);
        assert_eq!(ev[0], JobEvent::Started);
        let Some(JobEvent::Exit {
            success,
            stderr,
            files,
            ..
        }) = ev.last()
        else {
            panic!("{ev:?}")
        };
        assert!(!success);
        assert_eq!(stderr, "oops");
        assert_eq!(files.len(), 1);
        assert_eq!(files[&dir.join("out.md").display().to_string()], "note\n");
        let mode = std::fs::metadata(dir.join("deep/conf.json"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);

        // Too big to send back: reported, and the next job's older copy doesn't replace it.
        let big = dir.join("out.md").display().to_string();
        let mut grow = job("head -c 1048577 /dev/zero | tr '\\0' a > out.md", &dir);
        grow.files.push(JobFile {
            path: big.clone(),
            body: "old".into(),
        });
        for _ in 0..2 {
            let ev = events(&Host::default(), &grow, false).await;
            let Some(JobEvent::Exit { files, too_big, .. }) = ev.last() else {
                panic!("{ev:?}")
            };
            assert!(files.is_empty());
            assert_eq!(too_big, std::slice::from_ref(&big));
            grow.args[1] = "true".into();
        }
        assert_eq!(std::fs::metadata(&big).unwrap().len(), MAX_COLLECT + 1);
        std::fs::remove_file(&big).unwrap();

        // Aborted: the whole group stops, so the run ends long before the sleep would.
        let started = std::time::Instant::now();
        let ev = events(&Host::default(), &job("sleep 30 & sleep 30", &dir), true).await;
        assert!(started.elapsed() < Duration::from_secs(10));
        assert!(matches!(
            ev.last(),
            Some(JobEvent::Exit { success: false, .. })
        ));
        // Even once it has closed its output and only waits.
        let started = std::time::Instant::now();
        let quiet = job("exec 1>&- 2>&-; sleep 30 & sleep 30", &dir);
        let ev = events(&Host::default(), &quiet, true).await;
        assert!(started.elapsed() < Duration::from_secs(10));
        assert!(matches!(
            ev.last(),
            Some(JobEvent::Exit { success: false, .. })
        ));

        // A harness that isn't there, and a file that can't be written.
        let mut missing = job("", &dir);
        missing.bin = "superbot-no-such-harness".into();
        let ev = events(&Host::default(), &missing, false).await;
        assert!(
            matches!(&ev[..], [JobEvent::Error { message }] if message.contains("Couldn't start superbot-no-such-harness"))
        );
        let mut unwritable = job("", &dir);
        unwritable.files[0].path = "/proc/superbot-no-such-dir/x".into();
        let ev = events(&Host::default(), &unwritable, false).await;
        assert!(
            matches!(&ev[..], [JobEvent::Error { message }] if message.contains("Couldn't write"))
        );

        // A failed cleanup before the run stops it there.
        let mut c = job("echo ran", &dir);
        c.cleanup = Some(JobCleanup {
            when_exists: dir.display().to_string(),
            bin: "false".into(),
            args: vec!["stop".into()],
            env: BTreeMap::new(),
            cwd: dir.display().to_string(),
            timeout_secs: 5,
        });
        let ev = events(&Host::default(), &c, false).await;
        assert!(
            matches!(&ev[..], [JobEvent::Cleanup { why }] if why.contains("`false stop` failed"))
        );

        // A host that clears the environment passes only what it sets.
        let host = Host {
            clear_env: true,
            remove: Vec::new(),
            env: BTreeMap::from([("PATH".into(), "/usr/bin:/bin".into())]),
            user: None,
        };
        let ev = events(&host, &job("echo \"[$HOME]\"", &dir), false).await;
        assert!(ev.contains(&JobEvent::Line { line: "[]".into() }), "{ev:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
