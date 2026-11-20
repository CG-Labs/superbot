//! Bots' screens on a machine (ADR 0045): for each Bot, a virtual display (Xvfb), a
//! window manager (openbox) and a session bus (dbus-daemon), all as the Bots' user,
//! and voxl, the viewer, on loopback. Nothing listens beyond loopback: botd reaches a
//! viewer only through the agent's tunnel, and voxl checks botd's token itself.
//! Shared by the agent binary and botd's tests, so it uses nothing of botd's.

// Shared by two binaries, each of which uses only part of it.
#![allow(dead_code)]

use super::runas::{self, Ids};
use super::wire;
use std::collections::HashMap;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::process::{Child, Command};
use zeroize::Zeroizing;

/// The system's program folders. Not the harness PATH: a Bot can't put a program of
/// its own in front of these.
pub const SYSTEM_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

/// Viewer connections at once, across every screen.
pub const MAX_TUNNELS: usize = 64;

#[derive(Clone, Debug)]
pub struct Settings {
    /// Where `SCREEN_PROGRAMS` are looked for.
    pub path: String,
    /// Holds X's sockets (`.X11-unix`) and lock files: the agent's own `/tmp`, which
    /// its jobs share.
    pub tmp: PathBuf,
    /// Screen `n` (from 1) is display `:display_base + n`, its viewer on loopback port
    /// `port_base + n`.
    pub display_base: u32,
    pub port_base: u16,
    pub max: u32,
}

impl Default for Settings {
    fn default() -> Settings {
        Settings {
            path: SYSTEM_PATH.into(),
            tmp: "/tmp".into(),
            display_base: 100,
            port_base: 6900,
            max: 4,
        }
    }
}

struct Screen {
    slot: u32,
    token: Zeroizing<String>,
    idle: Duration,
    used: Instant,
    x: Child,
    bus: Child,
    wm: Child,
    /// None only while it's being replaced for a new token.
    viewer: Option<Child>,
}

impl Screen {
    fn alive(&mut self) -> bool {
        let up = |c: &mut Child| matches!(c.try_wait(), Ok(None));
        up(&mut self.x) && up(&mut self.bus) && up(&mut self.wm) && self.viewer.as_mut().is_none_or(up)
    }
}

pub struct Screens {
    s: Settings,
    home: PathBuf,
    user: String,
    live: Mutex<HashMap<String, Screen>>,
    /// Jobs and tunnels of each Bot: while it has any, its screen stays up.
    holds: Mutex<HashMap<String, usize>>,
    /// One start or token change at a time; heartbeats never wait for it.
    changing: tokio::sync::Mutex<()>,
    tunnels: Arc<tokio::sync::Semaphore>,
}

/// Keeps a Bot's screen up until dropped.
pub struct Hold(Arc<Screens>, String);

impl Drop for Hold {
    fn drop(&mut self) {
        let mut holds = self.0.holds();
        if let Some(n) = holds.get_mut(&self.1) {
            *n -= 1;
            if *n == 0 {
                holds.remove(&self.1);
            }
        }
        drop(holds);
        if let Some(s) = self.0.live().get_mut(&self.1) {
            s.used = Instant::now();
        }
    }
}

type Failure = (u16, String);

fn fail(code: u16, msg: impl Into<String>) -> Failure {
    (code, msg.into())
}

impl Screens {
    /// `home` is the Bots' home, `user` the Bots' user by name.
    pub fn new(s: Settings, home: PathBuf, user: String) -> Screens {
        Screens {
            s,
            home,
            user,
            live: Mutex::default(),
            holds: Mutex::default(),
            changing: tokio::sync::Mutex::new(()),
            tunnels: Arc::new(tokio::sync::Semaphore::new(MAX_TUNNELS)),
        }
    }

    fn live(&self) -> std::sync::MutexGuard<'_, HashMap<String, Screen>> {
        self.live.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn holds(&self) -> std::sync::MutexGuard<'_, HashMap<String, usize>> {
        self.holds.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// `name`, if it's an executable file on the screen PATH.
    fn find(&self, name: &str) -> Option<PathBuf> {
        self.s.path.split(':').filter(|d| d.starts_with('/')).map(|d| Path::new(d).join(name)).find(|p| {
            std::fs::metadata(p).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
        })
    }

    /// Of `SCREEN_PROGRAMS`, those this machine doesn't have.
    pub fn missing(&self) -> Vec<String> {
        wire::SCREEN_PROGRAMS.iter().filter(|p| self.find(p).is_none()).map(|p| p.to_string()).collect()
    }

    pub fn report(&self) -> wire::ScreenReport {
        let mut running: Vec<String> = self.live().keys().cloned().collect();
        running.sort();
        wire::ScreenReport {
            protocol: wire::SCREEN_PROTOCOL,
            missing: self.missing(),
            running,
            max: self.s.max,
        }
    }

    fn display(&self, slot: u32) -> u32 {
        self.s.display_base + slot
    }

    fn port(&self, slot: u32) -> u16 {
        self.s.port_base + slot as u16
    }

    fn bus_path(&self, slot: u32) -> PathBuf {
        self.home.join(".screens").join(format!("bus-{}", self.display(slot)))
    }

    fn reply(&self, slot: u32, started: bool) -> wire::ScreenReply {
        wire::ScreenReply {
            display: format!(":{}", self.display(slot)),
            bus: format!("unix:path={}", self.bus_path(slot).display()),
            started,
        }
    }

    /// Keeps `bot`'s screen up while the hold lives.
    pub fn hold(self: &Arc<Self>, bot: &str) -> Hold {
        *self.holds().entry(bot.to_string()).or_default() += 1;
        Hold(self.clone(), bot.to_string())
    }

    /// The loopback port of `bot`'s viewer, if its screen is up, for one more tunnel.
    /// The permit is the tunnel's share of `MAX_TUNNELS`.
    pub fn tunnel(self: &Arc<Self>, bot: &str) -> Result<(u16, Hold, tokio::sync::OwnedSemaphorePermit), Failure> {
        let port = {
            let mut live = self.live();
            let s = live.get_mut(bot).filter(|s| s.viewer.is_some());
            let s = s.and_then(|s| s.alive().then_some(s)).ok_or_else(|| fail(404, "No screen is up for that Bot here."))?;
            s.used = Instant::now();
            self.port(s.slot)
        };
        let permit = self.tunnels.clone().try_acquire_owned().map_err(|_| fail(503, "This machine has too many screen viewers open."))?;
        Ok((port, self.hold(bot), permit))
    }

    /// Starts `bot`'s screen as `ids`, or, if it's up, keeps it and lets only `token`
    /// view it from now on: only the viewer restarts, so what's on the screen stays.
    pub async fn ensure(&self, bot: &str, r: &wire::ScreenRequest, ids: Ids) -> Result<wire::ScreenReply, Failure> {
        let _one = self.changing.lock().await;
        let idle = Duration::from_secs(r.idle_secs.clamp(60, 86_400));
        let old_viewer = {
            let mut live = self.live();
            let alive = live.get_mut(bot).map(|s| s.alive());
            match live.get_mut(bot).filter(|_| alive == Some(true)) {
                Some(s) => {
                    s.used = Instant::now();
                    s.idle = idle;
                    if s.token.as_str() == r.token {
                        return Ok(self.reply(s.slot, false));
                    }
                    Some((s.slot, s.viewer.take()))
                }
                None => {
                    live.remove(bot);
                    None
                }
            }
        };
        if let Some((slot, viewer)) = old_viewer {
            if let Some(mut v) = viewer {
                let _ = v.kill().await;
            }
            let voxl = self.find("voxl").ok_or_else(|| fail(422, "This machine has no voxl."))?;
            return match self.start_viewer(&voxl, slot, &r.token, ids).await {
                Ok(v) => {
                    if let Some(s) = self.live().get_mut(bot) {
                        s.viewer = Some(v);
                        s.token = Zeroizing::new(r.token.clone());
                    }
                    Ok(self.reply(slot, false))
                }
                Err(e) => {
                    self.live().remove(bot);
                    Err(e)
                }
            };
        }
        let slot = self.free_slot()?;
        let s = self.start(slot, r, ids, idle).await?;
        self.live().insert(bot.to_string(), s);
        Ok(self.reply(slot, true))
    }

    /// The lowest slot no screen holds whose viewer port nothing else listens on.
    fn free_slot(&self) -> Result<u32, Failure> {
        let live = self.live();
        if live.len() >= self.s.max as usize {
            return Err(fail(503, format!("This machine shows {} screens already. Try again when one closes.", self.s.max)));
        }
        (1..=self.s.max)
            .filter(|n| !live.values().any(|s| s.slot == *n))
            .find(|n| std::net::TcpListener::bind(("127.0.0.1", self.port(*n))).is_ok())
            .ok_or_else(|| fail(503, "Every screen port on this machine is taken."))
    }

    fn command(&self, program: &Path, ids: Ids, env: &[(&str, String)]) -> Command {
        let mut c = Command::new(program);
        c.env_clear()
            .env("HOME", &self.home)
            .env("PATH", &self.s.path)
            .env("USER", &self.user)
            .env("LOGNAME", &self.user)
            .env("LANG", "C.UTF-8")
            .envs(env.iter().map(|(k, v)| (*k, v.as_str())))
            .current_dir(&self.home)
            .uid(ids.uid)
            .gid(ids.gid)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true);
        c
    }

    /// `/tmp/.X11-unix`, made world-writable and sticky, as X expects, if it isn't there.
    fn x11_dir(&self) -> Result<PathBuf, Failure> {
        let d = self.s.tmp.join(".X11-unix");
        let bad = |e: std::io::Error| fail(500, format!("{}: {e}", d.display()));
        match std::fs::symlink_metadata(&d) {
            Ok(m) if m.is_dir() => Ok(d),
            Ok(_) => Err(fail(500, format!("{} isn't a folder.", d.display()))),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                std::fs::DirBuilder::new().mode(0o1777).create(&d).map_err(bad)?;
                runas::chmod_dir(&d, 0o1777).map_err(bad)?;
                Ok(d)
            }
            Err(e) => Err(bad(e)),
        }
    }

    async fn start(&self, slot: u32, r: &wire::ScreenRequest, ids: Ids, idle: Duration) -> Result<Screen, Failure> {
        let find = |p: &str| self.find(p).ok_or_else(|| fail(422, format!("This machine has no {p}.")));
        let (xvfb, openbox, dbus, voxl) = (find("Xvfb")?, find("openbox")?, find("dbus-daemon")?, find("voxl")?);
        let n = self.display(slot);
        let x11 = self.x11_dir()?;
        let socket = x11.join(format!("X{n}"));
        let bus = self.bus_path(slot);
        let run = self.home.join(".screens");
        // A screen that died leaves its sockets and lock; they're the Bots' user's.
        runas::as_user(Some(ids), || -> std::io::Result<()> {
            std::fs::DirBuilder::new().recursive(true).mode(0o700).create(&run)?;
            for p in [&socket, &self.s.tmp.join(format!(".X{n}-lock")), &bus] {
                let _ = std::fs::remove_file(p);
            }
            Ok(())
        })
        .and_then(|r| r)
        .map_err(|e| fail(500, format!("{}: {e}", run.display())))?;

        let size = format!("{}x{}x24", r.width, r.height);
        let spawn = |c: &mut Command, what: &str| c.spawn().map_err(|e| fail(500, format!("{what} didn't start: {e}")));
        let mut x = spawn(self.command(&xvfb, ids, &[]).args([format!(":{n}"), "-screen".into(), "0".into(), size, "-nolisten".into(), "tcp".into()]), "Xvfb")?;
        let mut ready = false;
        for _ in 0..100 {
            if std::fs::symlink_metadata(&socket).is_ok() {
                ready = true;
                break;
            }
            if !matches!(x.try_wait(), Ok(None)) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        if !ready {
            return Err(fail(503, "The virtual display didn't start."));
        }
        let display = ("DISPLAY", format!(":{n}"));
        let address = ("DBUS_SESSION_BUS_ADDRESS", format!("unix:path={}", bus.display()));
        let bus_child = spawn(
            self.command(&dbus, ids, &[]).args(["--session".to_string(), "--nofork".into(), format!("--address={}", address.1)]),
            "dbus-daemon",
        )?;
        let wm = spawn(&mut self.command(&openbox, ids, &[display.clone(), address.clone()]), "openbox")?;
        let viewer = self.start_viewer(&voxl, slot, &r.token, ids).await?;
        Ok(Screen {
            slot,
            token: Zeroizing::new(r.token.clone()),
            idle,
            used: Instant::now(),
            x,
            bus: bus_child,
            wm,
            viewer: Some(viewer),
        })
    }

    /// voxl on loopback, for display `slot`, with `token` as its password; returns once
    /// it answers.
    async fn start_viewer(&self, voxl: &Path, slot: u32, token: &str, ids: Ids) -> Result<Child, Failure> {
        let port = self.port(slot);
        let mut cmd = self.command(voxl, ids, &[("DISPLAY", format!(":{}", self.display(slot))), ("VOXL_PASSWORD", token.to_string())]);
        cmd.args(["--addr", "127.0.0.1", "--port", &port.to_string(), "--allowed-hosts", "*"])
            .args(["--audio-enabled", "false", "--file-transfers", "none", "--enable-clipboard", "true"]);
        let mut v = cmd.spawn().map_err(|e| fail(500, format!("voxl didn't start: {e}")))?;
        for _ in 0..200 {
            if !matches!(v.try_wait(), Ok(None)) {
                break;
            }
            if tokio::net::TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
                return Ok(v);
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        let _ = v.kill().await;
        Err(fail(503, "The screen's viewer didn't start."))
    }

    /// Stops `bot`'s screen, after any start or token change under way. Returns
    /// whether one was up.
    pub async fn stop(&self, bot: &str) -> bool {
        let _one = self.changing.lock().await;
        let gone = self.live().remove(bot);
        if let Some(s) = &gone {
            println!("Screen :{} of Bot {bot} stopped.", self.display(s.slot));
        }
        gone.is_some()
    }

    /// Stops screens that died, and those idle past their time with no job or viewer.
    pub fn reap(&self) {
        let held: Vec<String> = self.holds().keys().cloned().collect();
        let mut live = self.live();
        let before: Vec<String> = live.keys().cloned().collect();
        live.retain(|bot, s| s.alive() && (held.contains(bot) || s.used.elapsed() < s.idle));
        for bot in before.iter().filter(|b| !live.contains_key(*b)) {
            println!("Screen of Bot {bot} stopped: idle or gone.");
        }
    }

    /// Reaps every 30 seconds, for as long as the screens exist.
    pub fn reap_in_background(self: &Arc<Self>) {
        let weak = Arc::downgrade(self);
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(30));
            loop {
                tick.tick().await;
                match weak.upgrade() {
                    Some(s) => s.reap(),
                    None => return,
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn script(dir: &Path, name: &str, body: &str) {
        let p = dir.join(name);
        std::fs::write(&p, body).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    fn me() -> Ids {
        // SAFETY: no arguments.
        unsafe { Ids { uid: libc::geteuid(), gid: libc::getegid() } }
    }

    /// Stand-ins: an Xvfb that makes its socket, and a voxl that listens on its port.
    fn fakes() -> (Arc<Screens>, PathBuf) {
        static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!("superbot-screens-{}-{n}", std::process::id()));
        let (bin, tmp, home) = (root.join("bin"), root.join("tmp"), root.join("home"));
        for d in [&bin, &tmp, &home] {
            std::fs::create_dir_all(d).unwrap();
        }
        script(&bin, "Xvfb", &format!("#!/bin/sh\nn=${{1#:}}\nmkdir -p {x}\n: > {x}/X$n\nexec sleep 60\n", x = tmp.join(".X11-unix").display()));
        script(&bin, "dbus-daemon", "#!/bin/sh\nexec sleep 60\n");
        script(&bin, "openbox", "#!/bin/sh\nexec sleep 60\n");
        script(
            &bin,
            "voxl",
            "#!/usr/bin/env python3\nimport socket, sys, time\nport = int(sys.argv[sys.argv.index('--port') + 1])\ns = socket.socket()\ns.bind(('127.0.0.1', port))\ns.listen()\ntime.sleep(60)\n",
        );
        let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let free = probe.local_addr().unwrap().port();
        drop(probe);
        let s = Settings { path: format!("{}:/usr/bin:/bin", bin.display()), tmp, display_base: 100, port_base: free - 1, max: 2 };
        (Arc::new(Screens::new(s, home, runas::current_user().unwrap())), root)
    }

    fn req(token: &str) -> wire::ScreenRequest {
        wire::ScreenRequest { protocol: wire::SCREEN_PROTOCOL, owner_id: "u1".into(), token: token.into(), width: 800, height: 600, idle_secs: 60 }
    }

    #[tokio::test]
    async fn a_screen_whose_window_manager_died_is_started_again() {
        let (screens, _root) = fakes();
        let a = "a".repeat(32);
        assert!(screens.ensure("b1", &req(&a), me()).await.unwrap().started);
        let wm = screens.live().get_mut("b1").unwrap().wm.id().unwrap();
        unsafe { libc::kill(wm as i32, libc::SIGKILL) };
        for _ in 0..100 {
            if !screens.live().get_mut("b1").unwrap().alive() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(screens.ensure("b1", &req(&a), me()).await.unwrap().started, "rebuilt, not reused");
        assert!(screens.stop("b1").await);
    }

    #[tokio::test]
    async fn a_screen_starts_once_keeps_its_display_across_tokens_and_stops() {
        let (screens, root) = fakes();
        assert!(screens.missing().is_empty(), "{:?}", screens.missing());
        let a = "a".repeat(32);
        let first = screens.ensure("b1", &req(&a), me()).await.unwrap();
        assert!(first.started);
        assert_eq!(first.display, ":101");
        assert!(first.bus.ends_with("/home/.screens/bus-101"), "{}", first.bus);
        let mode = std::fs::metadata(root.join("tmp/.X11-unix")).unwrap().permissions().mode();
        assert_eq!(mode & 0o7777, 0o1777);

        let again = screens.ensure("b1", &req(&a), me()).await.unwrap();
        assert_eq!((again.display.as_str(), again.started), (":101", false));
        let rotated = screens.ensure("b1", &req(&"b".repeat(32)), me()).await.unwrap();
        assert_eq!((rotated.display.as_str(), rotated.started), (":101", false), "a new token keeps the screen");
        let (port, _hold, _permit) = screens.tunnel("b1").unwrap();
        assert!(tokio::net::TcpStream::connect(("127.0.0.1", port)).await.is_ok(), "the new viewer listens");

        assert_eq!(screens.report().running, vec!["b1".to_string()]);
        assert!(screens.tunnel("b2").is_err(), "no screen, no tunnel");
        assert!(screens.stop("b1").await);
        assert!(!screens.stop("b1").await);
        assert!(screens.report().running.is_empty());
    }

    #[tokio::test]
    async fn idle_screens_are_reaped_unless_held() {
        let (screens, _root) = fakes();
        let a = "a".repeat(32);
        screens.ensure("b1", &req(&a), me()).await.unwrap();
        screens.ensure("b2", &req(&a), me()).await.unwrap();
        let full = screens.ensure("b3", &req(&a), me()).await.unwrap_err();
        assert_eq!(full.0, 503, "{full:?}");
        let hold = screens.hold("b1");
        for s in screens.live().values_mut() {
            s.used = Instant::now() - Duration::from_secs(120);
        }
        screens.reap();
        assert_eq!(screens.report().running, vec!["b1".to_string()], "a job or viewer keeps it");
        drop(hold);
        screens.reap();
        assert_eq!(screens.report().running, vec!["b1".to_string()], "idle counts from when the last hold ended");
        screens.live().get_mut("b1").unwrap().used = Instant::now() - Duration::from_secs(120);
        screens.reap();
        assert!(screens.report().running.is_empty());
    }

    #[test]
    fn programs_are_found_only_on_the_screen_path() {
        let s = Screens::new(Settings { path: "/nonexistent:relative".into(), ..Settings::default() }, "/nonexistent".into(), "x".into());
        assert_eq!(s.missing(), wire::SCREEN_PROGRAMS.map(String::from).to_vec());
    }
}
