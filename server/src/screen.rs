//! Each Bot's screen: a virtual display (Xvfb) with a window manager (Openbox) and
//! its own D-Bus session (agent-desktop reads apps through it), streamed to the web
//! app by voxl. Started on first use, stopped when idle. Off when Xvfb isn't installed.
//! A screen is a work surface, not a security boundary: every Bot runs as one user.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::OnceLock;
use std::time::{Duration, Instant};
use tokio::process::{Child, Command};
use tokio::sync::Mutex;

static LISTEN: OnceLock<IpAddr> = OnceLock::new();

/// SCREEN_ADDR: an IP address, or empty for loopback.
pub(crate) fn parse_listen_addr(s: &str) -> Result<IpAddr, String> {
    match s.trim() {
        "" => Ok(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        v => v.parse().map_err(|_| format!("SCREEN_ADDR must be an IP address such as 127.0.0.1 or 0.0.0.0, not \"{v}\"")),
    }
}

/// Sets where screen viewers listen, once at startup.
pub fn init_listen_addr(s: &str) -> Result<IpAddr, String> {
    let addr = parse_listen_addr(s)?;
    let _ = LISTEN.set(addr);
    Ok(addr)
}

/// Where screen viewers (voxl, and botd's ports for machine screens) listen. Loopback unless
/// SCREEN_ADDR moves them for a proxy on another host, such as Compose's Caddy container.
/// Each viewer's token guards it either way.
pub fn listen_addr() -> IpAddr {
    LISTEN.get().copied().unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST))
}

/// The address botd dials to reach a viewer listening on `listen`.
fn dial_addr(listen: IpAddr) -> IpAddr {
    match listen {
        IpAddr::V4(a) if a.is_unspecified() => IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(a) if a.is_unspecified() => IpAddr::V6(Ipv6Addr::LOCALHOST),
        a => a,
    }
}

pub struct Screens {
    max: u16,
    idle: Duration,
    /// Display numbers are base+slot; voxl ports are 6800+base+slot (6901, 6902, ...).
    base: u16,
    /// Width and height from SCREEN_SIZE.
    size: (u32, u32),
    run_dir: PathBuf,
    live: Mutex<HashMap<String, Screen>>,
}

struct Screen {
    slot: u16,
    token: String,
    used: Instant,
    procs: Vec<Child>,
    /// voxl, kept apart so a new token restarts only the viewer, not the display.
    viewer: Option<Child>,
}

impl Screen {
    fn alive(&mut self) -> bool {
        self.procs.iter_mut().chain(self.viewer.as_mut()).all(|c| matches!(c.try_wait(), Ok(None)))
    }
}

fn new_token() -> String {
    let token: String = crate::random_bytes(16).iter().map(|x| format!("{x:02x}")).collect();
    crate::secrets::redact::register(&token);
    token
}

/// voxl streams the display. Its own token login guards the stream; the proxy in front adds HTTPS.
fn spawn_viewer(display: &str, port: u16, token: &str) -> std::io::Result<Option<Child>> {
    if !on_path("voxl") {
        return Ok(None);
    }
    spawn(
        Command::new("voxl")
            .args(["--addr", &listen_addr().to_string(), "--port", &port.to_string(), "--allowed-hosts", "*"])
            .args(["--audio-enabled", "false", "--file-transfers", "none", "--enable-clipboard", "true"])
            .env("DISPLAY", display)
            .env("VOXL_PASSWORD", token),
    )
    .map(Some)
}

/// What a Bot run and the web app need to reach a screen.
pub struct Info {
    pub display: String,
    pub bus: String,
    pub port: u16,
    pub token: String,
}

pub fn on_path(bin: &str) -> bool {
    std::env::var_os("PATH").is_some_and(|p| std::env::split_paths(&p).any(|d| d.join(bin).is_file()))
}

fn spawn(cmd: &mut Command) -> std::io::Result<Child> {
    crate::adapters::strip_secret_env(cmd.as_std_mut());
    cmd.stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).kill_on_drop(true).spawn()
}

/// `WIDTHxHEIGHT` within sane bounds, else the default 1280x800. Only these
/// numbers reach Xvfb's command line.
pub(crate) fn parse_size(s: &str) -> (u32, u32) {
    s.trim()
        .split_once('x')
        .and_then(|(w, h)| Some((w.parse::<u32>().ok()?, h.parse::<u32>().ok()?)))
        .filter(|(w, h)| (320..=7680).contains(w) && (240..=4320).contains(h))
        .unwrap_or((1280, 800))
}

/// Leftovers of display `n` that would stop Xvfb from starting.
fn x11_paths(n: u16) -> Option<(PathBuf, PathBuf)> {
    let sock = crate::paths::child(Path::new("/tmp/.X11-unix"), &format!("X{n}"))?;
    let lock = crate::paths::child(Path::new("/tmp"), &format!(".X{n}-lock"))?;
    Some((sock, lock))
}

/// The agent-browser session that belongs to a Bot.
pub fn browser_session(bot_id: &str) -> String {
    format!("bot-{bot_id}")
}

impl Screens {
    pub fn from_env(run_dir: PathBuf) -> Option<Screens> {
        let num = |k: &str, d: u64| crate::env(k, &d.to_string()).parse::<u64>().unwrap_or(d);
        if crate::env("SCREENS", "on") == "off" || !on_path("Xvfb") || !on_path("openbox") {
            return None;
        }
        std::fs::create_dir_all(&run_dir).ok()?;
        Some(Screens {
            max: num("MAX_SCREENS", 3).clamp(1, 50) as u16,
            idle: Duration::from_secs(60 * num("SCREEN_IDLE_MINUTES", 10)),
            base: num("SCREEN_BASE", 100).clamp(1, 1000) as u16,
            size: parse_size(&crate::env("SCREEN_SIZE", "1280x800")),
            run_dir,
            live: Mutex::default(),
        })
    }

    /// The voxl ports these screens may use, first to last.
    pub fn ports(&self) -> (u16, u16) {
        (6800 + self.base + 1, 6800 + self.base + self.max)
    }

    fn bus_path(&self, n: u16) -> Option<PathBuf> {
        crate::paths::child(&crate::paths::canonical(&self.run_dir)?, &format!("bus-{n}"))
    }

    fn info(&self, s: &Screen) -> Info {
        let n = self.base + s.slot;
        Info {
            display: format!(":{n}"),
            bus: format!("unix:path={}", self.bus_path(n).unwrap_or_default().display()),
            port: 6800 + n,
            token: s.token.clone(),
        }
    }

    /// The Bot's screen, started if needed. When all are in use, the least recently
    /// used screen of a Bot that isn't working is stopped. None if none can be.
    pub async fn ensure(&self, bot_id: &str, busy: impl Fn(&str) -> bool) -> Option<Info> {
        let mut live = self.live.lock().await;
        if let Some(s) = live.get_mut(bot_id) {
            if s.alive() {
                s.used = Instant::now();
                return Some(self.info(s));
            }
            let s = live.remove(bot_id).unwrap(); // something crashed: start over
            stop(bot_id, s).await;
        }
        if live.len() >= self.max as usize {
            let victim = live.iter().filter(|(id, _)| !busy(id)).min_by_key(|(_, s)| s.used).map(|(id, _)| id.clone())?;
            let s = live.remove(&victim).unwrap();
            stop(&victim, s).await;
        }
        let slot = (1..=self.max).find(|n| live.values().all(|s| s.slot != *n))?;
        match self.start(slot).await {
            Ok(s) => {
                let info = self.info(&s);
                live.insert(bot_id.to_string(), s);
                Some(info)
            }
            Err(e) => {
                eprintln!("Screen {slot} failed to start: {e}");
                None
            }
        }
    }

    async fn start(&self, slot: u16) -> std::io::Result<Screen> {
        let mut s = Screen { slot, token: new_token(), used: Instant::now(), procs: Vec::new(), viewer: None };
        let Info { display, bus, port, .. } = self.info(&s);
        let n = self.base + slot;

        let (sock, lock) = x11_paths(n).ok_or_else(|| std::io::Error::other("bad display number"))?;
        let _ = std::fs::remove_file(&lock);
        let _ = std::fs::remove_file(&sock);
        let (w, h) = self.size;
        s.procs.push(spawn(Command::new("Xvfb").args([&display, "-screen", "0", &format!("{w}x{h}x24"), "-nolisten", "tcp"]))?);
        for _ in 0..50 {
            if sock.exists() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        if !sock.exists() {
            return Err(std::io::Error::other("Xvfb didn't open its display"));
        }

        let bus_path = self.bus_path(n).ok_or_else(|| std::io::Error::other("no screens folder"))?;
        let _ = std::fs::remove_file(&bus_path);
        s.procs.push(spawn(Command::new("dbus-daemon").args(["--session", "--nofork", &format!("--address={bus}")]))?);
        s.procs.push(spawn(Command::new("openbox").env("DISPLAY", &display).env("DBUS_SESSION_BUS_ADDRESS", &bus))?);
        s.viewer = spawn_viewer(&display, port, &s.token)?;
        Ok(s)
    }

    /// Gives a running screen a new token and restarts its viewer, so earlier links
    /// and open views stop working while the display and the Bot's apps keep going.
    /// For when someone loses access to the Bot: the proxy doesn't ask `botd`.
    pub async fn rotate_token(&self, bot_id: &str) {
        let mut live = self.live.lock().await;
        let Some(s) = live.get_mut(bot_id) else { return };
        if let Some(mut v) = s.viewer.take() {
            let _ = v.kill().await;
        }
        let old = std::mem::replace(&mut s.token, new_token());
        crate::secrets::redact::forget(&old);
        let Info { display, port, .. } = self.info(s);
        match spawn_viewer(&display, port, &s.token) {
            Ok(v) => s.viewer = v,
            Err(e) => {
                eprintln!("Screen viewer for {bot_id} failed to restart: {e}");
                let s = live.remove(bot_id).unwrap();
                stop(bot_id, s).await;
            }
        }
    }

    /// `rotate_token` for every running screen.
    pub async fn rotate_all(&self) {
        let ids: Vec<String> = self.live.lock().await.keys().cloned().collect();
        for id in ids {
            self.rotate_token(&id).await;
        }
    }

    /// Stops screens that nobody used for a while.
    pub async fn reap(&self, busy: impl Fn(&str) -> bool) {
        let mut live = self.live.lock().await;
        let idle: Vec<String> =
            live.iter().filter(|(id, s)| !busy(id) && s.used.elapsed() > self.idle).map(|(id, _)| id.clone()).collect();
        for id in idle {
            let s = live.remove(&id).unwrap();
            stop(&id, s).await;
        }
    }

    pub async fn remove(&self, bot_id: &str) {
        let s = self.live.lock().await.remove(bot_id);
        if let Some(s) = s {
            stop(bot_id, s).await;
        }
    }
}

/// Polls a viewer's port every 100 ms until it accepts a connection. False after `tries`.
pub async fn wait_for_port(port: u16, tries: u32) -> bool {
    let addr = dial_addr(listen_addr());
    for _ in 0..tries {
        if tokio::net::TcpStream::connect((addr, port)).await.is_ok() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    false
}

/// Closes the Bot's browser cleanly (so its profile saves), then kills the screen.
async fn stop(bot_id: &str, s: Screen) {
    if on_path("agent-browser") {
        let close = Command::new("agent-browser").args(["--session", &browser_session(bot_id), "close"]).stdin(Stdio::null()).output();
        let _ = tokio::time::timeout(Duration::from_secs(10), close).await;
    }
    crate::secrets::redact::forget(&s.token);
    drop(s); // kill_on_drop stops Xvfb, D-Bus, Openbox, and voxl
}

/// Environment for a Bot's harness, so its tools draw on its own screen and keep
/// their own browser profile (sign-ins persist).
pub fn bot_env(info: &Info, bot_id: &str, bot_dir: &Path) -> HashMap<String, String> {
    let profile = bot_dir.join("browser");
    HashMap::from([
        ("DISPLAY".into(), info.display.clone()),
        ("DBUS_SESSION_BUS_ADDRESS".into(), info.bus.clone()),
        ("AGENT_BROWSER_SESSION".into(), browser_session(bot_id)),
        ("AGENT_BROWSER_PROFILE".into(), profile.display().to_string()),
        ("AGENT_BROWSER_HEADED".into(), "1".into()),
        ("AGENT_BROWSER_NO_XVFB".into(), "1".into()),
        ("AGENT_BROWSER_ARGS".into(), "--start-maximized".into()),
        // Lets agent-desktop read GTK, Qt, and Chromium apps on this screen.
        ("QT_ACCESSIBILITY".into(), "1".into()),
        ("ACCESSIBILITY_ENABLED".into(), "1".into()),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn waits_for_a_listener() {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        assert!(wait_for_port(port, 1).await);
        drop(listener);
        assert!(!wait_for_port(port, 2).await);
    }

    #[tokio::test]
    async fn sees_a_late_listener() {
        let probe = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let port = probe.local_addr().unwrap().port();
        drop(probe);
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(250)).await;
            let l = tokio::net::TcpListener::bind(("127.0.0.1", port)).await.unwrap();
            tokio::time::sleep(Duration::from_secs(2)).await;
            drop(l);
        });
        assert!(wait_for_port(port, 20).await);
    }

    #[test]
    fn screen_size_is_two_numbers_or_the_default() {
        assert_eq!(parse_size("1920x1080"), (1920, 1080));
        assert_eq!(parse_size(" 800x600 "), (800, 600));
        for bad in ["", "1280", "x800", "1280x800 -ac", "1280x800x24", "-nolisten", "99999x99999", "1x1", "1280x800;rm -rf /"] {
            assert_eq!(parse_size(bad), (1280, 800), "{bad:?}");
        }
    }

    #[tokio::test]
    async fn a_new_token_keeps_the_display_running() {
        let dir = std::env::temp_dir().join(format!("superbot-screens-{}", crate::short_id()));
        let screens = Screens { max: 1, idle: Duration::from_secs(60), base: 100, size: (1280, 800), run_dir: dir, live: Mutex::default() };
        let display = spawn(Command::new("sleep").arg("30")).unwrap();
        let s = Screen { slot: 1, token: new_token(), used: Instant::now(), procs: vec![display], viewer: None };
        screens.live.lock().await.insert("b1".into(), s);
        let before = screens.ensure("b1", |_| true).await.unwrap().token;

        screens.rotate_token("b1").await;
        let after = screens.ensure("b1", |_| true).await.unwrap().token;
        assert_ne!(before, after);
        assert_eq!(after.len(), 32);
        assert!(screens.live.lock().await.get_mut("b1").unwrap().alive(), "same display, not restarted");
        screens.rotate_token("nobody").await;
        screens.remove("b1").await;
    }

    #[test]
    fn screen_addr_is_an_ip_or_loopback() {
        assert_eq!(parse_listen_addr(""), Ok(IpAddr::V4(Ipv4Addr::LOCALHOST)));
        assert_eq!(parse_listen_addr(" 0.0.0.0 "), Ok(IpAddr::V4(Ipv4Addr::UNSPECIFIED)));
        assert_eq!(parse_listen_addr("::"), Ok(IpAddr::V6(Ipv6Addr::UNSPECIFIED)));
        for bad in ["localhost", "0.0.0.0:6901", "botd", "127.0.0.1 --allowed-hosts"] {
            assert!(parse_listen_addr(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn botd_dials_a_wildcard_viewer_on_loopback() {
        assert_eq!(dial_addr(IpAddr::V4(Ipv4Addr::UNSPECIFIED)), IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(dial_addr(IpAddr::V6(Ipv6Addr::UNSPECIFIED)), IpAddr::V6(Ipv6Addr::LOCALHOST));
        let lan: IpAddr = "172.18.0.2".parse().unwrap();
        assert_eq!(dial_addr(lan), lan);
    }

    #[test]
    fn display_leftovers_stay_in_their_folders() {
        let (sock, lock) = x11_paths(101).unwrap();
        assert_eq!(sock, PathBuf::from("/tmp/.X11-unix/X101"));
        assert_eq!(lock, PathBuf::from("/tmp/.X101-lock"));
    }
}
