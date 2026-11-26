//! Each Bot's screen: a virtual display (Xvfb) with a window manager (Openbox) and
//! its own D-Bus session (agent-desktop reads apps through it), streamed to the web
//! app by voxl. Started on first use, stopped when idle. Off when Xvfb isn't installed.
//!
//! With ISOLATION=off every Bot runs as botd's user, so a screen is a work surface, not
//! a security boundary. With per-user accounts (ADR 0342) each screen runs as its run's
//! account: a teammate's run of a shared Bot gets its own. Its X server lets in only the
//! cookie botd writes into that account's read-only settings folder, botd checks the
//! display is the account's and refuses clients without it, and botd holds the viewer's
//! public port itself, piping each viewer to the account's voxl only once that loopback
//! port is the account's.

use crate::accounts::{Isolation, RunAs, Space};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4};
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};
use tokio::net::{TcpListener, TcpStream};
use tokio::process::{Child, Command};
use tokio::sync::Mutex;

static LISTEN: OnceLock<IpAddr> = OnceLock::new();

/// The ports the proxy's `/screen/<port>/` route serves (Caddyfiles in deploy/ and docs/computer.md).
pub const PROXY_PORTS: std::ops::RangeInclusive<u16> = 6900..=6999;

/// Where X servers put their sockets, shared by every account on the host.
const X11_DIR: &str = "/tmp/.X11-unix";
/// How many display numbers past SCREEN_BASE an account's screen may take: another
/// account may hold some, or have left files there botd can't remove.
const DISPLAYS: u16 = 200;
/// The display's cookie, in the Bot's settings folder of the run's account.
const COOKIE: &str = "screen.xauth";
/// `Screens::ensure`'s answer when every screen is in use by a working Bot.
pub const ALL_BUSY: &str = "every screen is in use";

/// Viewer ports outside PROXY_PORTS would hand out links the proxy can't open.
fn check_ports((first, last): (u16, u16)) -> Result<(), String> {
    if PROXY_PORTS.contains(&first) && PROXY_PORTS.contains(&last) {
        return Ok(());
    }
    Err(format!(
        "screen ports {first}-{last} are outside 6900-6999, the proxy's /screen/ route; set SCREEN_BASE between {} and {} (with MAX_SCREENS={}), or SCREENS=off",
        PROXY_PORTS.start() - 6801,
        PROXY_PORTS.end() - 6800 - (last - first + 1),
        last - first + 1
    ))
}

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
    /// An account's screen keeps the port and picks a free display from base+1 up.
    base: u16,
    /// Width and height from SCREEN_SIZE.
    size: (u32, u32),
    run_dir: PathBuf,
    /// ISOLATION=users: every screen runs as an account (ADR 0342), none as botd's.
    isolated: bool,
    /// By `key`: the Bot's id, or `<bot>@<teammate>` for a teammate's own (ADR 0342).
    live: Mutex<HashMap<String, Screen>>,
}

struct Screen {
    bot: String,
    slot: u16,
    display: u16,
    token: String,
    used: Instant,
    procs: Vec<Child>,
    /// voxl, kept apart so a new token restarts only the viewer, not the display.
    viewer: Option<Child>,
    /// The account it runs as; None with ISOLATION=off.
    owner: Option<Owner>,
    /// An account's screen: botd's listener on the public port, and the task piping it
    /// to voxl. Dropping that task cuts every open view.
    front: Option<Arc<TcpListener>>,
    serving: Option<Serving>,
}

impl Screen {
    fn alive(&mut self) -> bool {
        self.procs.iter_mut().chain(self.viewer.as_mut()).all(|c| matches!(c.try_wait(), Ok(None)))
    }
}

/// Aborts the task when dropped.
struct Serving(tokio::task::JoinHandle<()>);

impl Drop for Serving {
    fn drop(&mut self) {
        self.0.abort();
    }
}

fn new_token() -> String {
    let token: String = crate::random_bytes(16).iter().map(|x| format!("{x:02x}")).collect();
    crate::secrets::redact::register(&token);
    token
}

const VOXL_ARGS: [&str; 8] = ["--audio-enabled", "false", "--file-transfers", "none", "--enable-clipboard", "true", "--allowed-hosts", "*"];

/// voxl streams the display. Its own token login guards the stream; the proxy in front adds HTTPS.
fn spawn_viewer(display: &str, port: u16, token: &str) -> std::io::Result<Option<Child>> {
    if !on_path("voxl") {
        return Ok(None);
    }
    spawn(
        Command::new("voxl")
            .args(["--addr", &listen_addr().to_string(), "--port", &port.to_string()])
            .args(VOXL_ARGS)
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
    /// The display's cookie: always for an account's screen, and a teammate's on a machine.
    pub xauthority: Option<String>,
    /// Where the Bot's browser keeps its profile there; None: the caller's.
    pub profile: Option<PathBuf>,
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
    let sock = crate::paths::child(Path::new(X11_DIR), &format!("X{n}"))?;
    let lock = crate::paths::child(Path::new("/tmp"), &format!(".X{n}-lock"))?;
    Some((sock, lock))
}

/// The agent-browser session that belongs to a Bot.
pub fn browser_session(bot_id: &str) -> String {
    format!("bot-{bot_id}")
}

/// The account a screen runs as under ISOLATION=users (ADR 0342), and its files there.
#[derive(Clone, Debug)]
pub struct Owner {
    run: RunAs,
    uid: u32,
    /// The account's HOME: where its programs start; its D-Bus socket is in `.tmp` there.
    home: PathBuf,
    /// `settings/<bot>/screen.xauth`: written by botd, read-only to the account.
    cookie: PathBuf,
    /// `bots/<bot>`: the Bot's state there, where its browser keeps its profile.
    state: PathBuf,
}

impl Owner {
    /// The account `space`'s runs of `bot_id` use. None until that account exists.
    pub fn new(iso: &Isolation, space: Space, bot_id: &str) -> Option<Owner> {
        let run = iso.run_as_in(space)?;
        let uid = crate::passwd::by_name(&run.account)?.uid;
        Some(Owner { uid, home: iso.home_in(space)?, cookie: iso.bot_settings_in(space, bot_id)?.join(COOKIE), state: iso.bot_state_in(space, bot_id)?, run })
    }

    fn key(&self, bot_id: &str) -> String {
        crate::machines::wire::screen_key(bot_id, self.run.teammate.as_deref())
    }

    fn bus(&self, n: u16) -> PathBuf {
        self.home.join(".tmp").join(format!("bus-{n}"))
    }

    /// Starts `bin` as the account through `superbot-run`, with nothing of botd's
    /// environment but `env`.
    fn spawn(&self, bin: &str, args: Vec<String>, env: &[(&str, String)]) -> std::io::Result<Child> {
        let (sudo, argv) = self.run.argv_strings(bin, args);
        let mut cmd = Command::new(sudo);
        cmd.args(argv).current_dir(&self.home).env_clear().env("LANG", "C.UTF-8");
        // sudo resets PATH; superbot-run puts this one back.
        if let Some(p) = std::env::var_os("PATH") {
            cmd.env("SUPERBOT_PATH", p);
        }
        cmd.envs(env.iter().map(|(k, v)| (*k, v.as_str())));
        cmd.stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).kill_on_drop(true).spawn()
    }
}

/// With per-user accounts, every account's X server puts its socket in X11_DIR: a
/// sticky folder of root's or botd's, so no account removes or swaps another's, and
/// botd can make it if it isn't there.
fn shared_x11_dir(dir: &Path) -> Result<(), String> {
    let bad = |e: std::io::Error| format!("{}: {e}", dir.display());
    if let Err(e) = std::fs::symlink_metadata(dir) {
        if e.kind() != std::io::ErrorKind::NotFound {
            return Err(bad(e));
        }
        std::fs::DirBuilder::new().mode(0o1777).create(dir).map_err(bad)?;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o1777)).map_err(bad)?;
    }
    let m = std::fs::symlink_metadata(dir).map_err(bad)?;
    // SAFETY: geteuid can't fail.
    let me = unsafe { libc::geteuid() };
    if !m.is_dir() || m.mode() & 0o1000 == 0 || (m.uid() != 0 && m.uid() != me) {
        return Err(format!("{} must be a sticky folder of root's or botd's", dir.display()));
    }
    Ok(())
}

impl Screens {
    /// `isolated`: ISOLATION=users is on, so each screen runs as its run's account.
    pub fn from_env(run_dir: PathBuf, isolated: bool) -> Option<Screens> {
        let num = |k: &str, d: u64| crate::env(k, &d.to_string()).parse::<u64>().unwrap_or(d);
        if crate::env("SCREENS", "on") == "off" || !on_path("Xvfb") || !on_path("openbox") {
            return None;
        }
        if isolated && let Err(e) = shared_x11_dir(Path::new(X11_DIR)) {
            crate::obs::log::log_warn!("Screens: off, since per-user screens need it: {e}");
            return None;
        }
        std::fs::create_dir_all(&run_dir).ok()?;
        Some(Screens {
            max: num("MAX_SCREENS", 3).clamp(1, 50) as u16,
            idle: Duration::from_secs(60 * num("SCREEN_IDLE_MINUTES", 10)),
            base: num("SCREEN_BASE", 100).clamp(1, 1000) as u16,
            size: parse_size(&crate::env("SCREEN_SIZE", "1280x800")),
            run_dir,
            isolated,
            live: Mutex::default(),
        })
    }

    /// The voxl ports these screens may use, first to last.
    pub fn ports(&self) -> (u16, u16) {
        (6800 + self.base + 1, 6800 + self.base + self.max)
    }

    /// Errs when the proxy's `/screen/` route can't reach these screens' ports.
    pub fn check_ports(&self) -> Result<(), String> {
        check_ports(self.ports())
    }

    fn bus_path(&self, n: u16) -> Option<PathBuf> {
        crate::paths::child(&crate::paths::canonical(&self.run_dir)?, &format!("bus-{n}"))
    }

    fn port(&self, slot: u16) -> u16 {
        6800 + self.base + slot
    }

    fn info(&self, s: &Screen) -> Info {
        let bus = match &s.owner {
            Some(o) => o.bus(s.display),
            None => self.bus_path(s.display).unwrap_or_default(),
        };
        Info {
            display: format!(":{}", s.display),
            bus: format!("unix:path={}", bus.display()),
            port: self.port(s.slot),
            token: s.token.clone(),
            xauthority: s.owner.as_ref().map(|o| o.cookie.display().to_string()),
            profile: s.owner.as_ref().map(|o| o.state.join("browser")),
        }
    }

    /// The Bot's screen, started if needed: with per-user accounts, the one of `owner`,
    /// the account its runs use (`Owner::new`). When all are in use, the least recently
    /// used screen of a Bot that isn't working is stopped. Err: why none could start,
    /// `ALL_BUSY` when every screen is in use.
    pub async fn ensure(&self, bot_id: &str, owner: Option<&Owner>, busy: impl Fn(&str) -> bool) -> Result<Info, String> {
        // Never a screen as botd's account while accounts are on, nor one as an account while they're off.
        if self.isolated != owner.is_some() {
            return Err("no account for this screen".into());
        }
        let key = owner.map_or_else(|| bot_id.to_string(), |o| o.key(bot_id));
        let mut live = self.live.lock().await;
        let mut was = None;
        if let Some(s) = live.get_mut(&key) {
            if s.alive() {
                s.used = Instant::now();
                return Ok(self.info(s));
            }
            let s = live.remove(&key).unwrap(); // something crashed: start over
            was = Some(s.display);
            stop(s).await;
        }
        if live.len() >= self.max as usize {
            let victim = live.iter().filter(|(_, s)| !busy(&s.bot)).min_by_key(|(_, s)| s.used).map(|(k, _)| k.clone()).ok_or(ALL_BUSY)?;
            let s = live.remove(&victim).unwrap();
            stop(s).await;
        }
        let started = match owner {
            Some(o) => self.start_as(&live, bot_id, o, was).await,
            None => match (1..=self.max).find(|n| live.values().all(|s| s.slot != *n)) {
                Some(slot) => self.start(bot_id, slot).await.map_err(|e| e.to_string()),
                None => Err(ALL_BUSY.into()),
            },
        };
        match started {
            Ok(s) => {
                let info = self.info(&s);
                live.insert(key, s);
                Ok(info)
            }
            Err(e) => {
                crate::obs::log::log_warn!("Screen of Bot {bot_id} failed to start: {e}");
                Err(e)
            }
        }
    }

    async fn start(&self, bot_id: &str, slot: u16) -> std::io::Result<Screen> {
        let n = self.base + slot;
        let mut s = Screen {
            bot: bot_id.into(),
            slot,
            display: n,
            token: new_token(),
            used: Instant::now(),
            procs: Vec::new(),
            viewer: None,
            owner: None,
            front: None,
            serving: None,
        };
        let Info { display, bus, port, .. } = self.info(&s);

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

    /// An account's screen (ADR 0342): botd takes a free public port first, then a
    /// display that nobody holds, and runs everything on it as the account.
    async fn start_as(&self, live: &HashMap<String, Screen>, bot_id: &str, o: &Owner, was: Option<u16>) -> Result<Screen, String> {
        let mut front = None;
        for slot in (1..=self.max).filter(|n| live.values().all(|s| s.slot != *n)) {
            // Taken by another account, it's skipped: botd never hands out a port it doesn't hold.
            if let Ok(l) = TcpListener::bind((listen_addr(), self.port(slot))).await {
                front = Some((slot, Arc::new(l)));
                break;
            }
        }
        let (slot, listener) = front.ok_or(ALL_BUSY)?;
        let taken: Vec<u16> = live.values().map(|s| s.display).collect();
        let first = self.base + 1;
        let candidates = was.into_iter().chain(first..first + DISPLAYS).filter(|n| !taken.contains(n));
        let mut tried = 0;
        let mut last = String::from("no free display");
        for n in candidates {
            if tried == 3 {
                break;
            }
            if !display_clear(n) {
                continue;
            }
            tried += 1;
            match self.display_as(o, n).await {
                Ok(procs) => {
                    let mut s = Screen {
                        bot: bot_id.into(),
                        slot,
                        display: n,
                        token: new_token(),
                        used: Instant::now(),
                        procs,
                        viewer: None,
                        owner: Some(o.clone()),
                        front: Some(listener),
                        serving: None,
                    };
                    if on_path("voxl") {
                        start_viewer_as(&mut s).await?;
                    }
                    return Ok(s);
                }
                Err(e) => last = format!("display :{n}: {e}"),
            }
        }
        Err(last)
    }

    /// Xvfb, D-Bus and Openbox for display `n`, as the account. Its X server takes only
    /// a new cookie botd writes now, and is checked to be the account's and to refuse
    /// clients without it before anything else starts.
    async fn display_as(&self, o: &Owner, n: u16) -> Result<Vec<Child>, String> {
        let (sock, _) = x11_paths(n).ok_or("bad display number")?;
        let secret = zeroize::Zeroizing::new(crate::random_bytes(16));
        let cookie: [u8; 16] = secret.as_slice().try_into().map_err(|_| "no cookie")?;
        let entry = zeroize::Zeroizing::new(xauth_entry(n, &cookie));
        crate::accounts::write_shared_bytes(&o.run.settings, &o.cookie, &entry).map_err(|e| format!("couldn't write the cookie: {e}"))?;
        let (w, h) = self.size;
        // Never -shmem: that framebuffer would be shared memory any account could attach.
        let xargs = xvfb_args(n, (w, h), &o.cookie);
        let mut x = o.spawn("Xvfb", xargs, &[]).map_err(|e| format!("Xvfb didn't start: {e}"))?;
        let mut up = false;
        for _ in 0..100 {
            if std::fs::symlink_metadata(&sock).is_ok() {
                up = true;
                break;
            }
            if !matches!(x.try_wait(), Ok(None)) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        if !up {
            return Err("Xvfb didn't open its display".into());
        }
        let uid = o.uid;
        let checked = tokio::task::spawn_blocking(move || check_display(&sock, n, uid)).await.unwrap_or_else(|e| Err(e.to_string()));
        if let Err(e) = checked {
            return Err(format!("refused: {e}"));
        }
        let display = format!(":{n}");
        let bus = format!("unix:path={}", o.bus(n).display());
        // dbus-daemon won't take a path a socket was left at.
        let dbus = o
            .spawn("/bin/sh", vec!["-c".into(), DBUS.into(), "sh".into(), o.bus(n).display().to_string(), bus.clone()], &[])
            .map_err(|e| format!("dbus-daemon didn't start: {e}"))?;
        let env = [("DISPLAY", display), ("XAUTHORITY", o.cookie.display().to_string()), ("DBUS_SESSION_BUS_ADDRESS", bus)];
        let wm = o.spawn("openbox", Vec::new(), &env).map_err(|e| format!("openbox didn't start: {e}"))?;
        Ok(vec![x, dbus, wm])
    }

    /// Gives a running screen a new token and restarts its viewer, so earlier links
    /// and open views stop working while the display and the Bot's apps keep going.
    /// For when someone loses access to the Bot: the proxy doesn't ask `botd`. Every
    /// screen of the Bot, a teammate's own too.
    pub async fn rotate_token(&self, bot_id: &str) {
        let mut live = self.live.lock().await;
        let keys: Vec<String> = live.iter().filter(|(_, s)| s.bot == bot_id).map(|(k, _)| k.clone()).collect();
        for key in keys {
            let Some(s) = live.get_mut(&key) else { continue };
            s.serving = None;
            if let Some(mut v) = s.viewer.take() {
                let _ = v.kill().await;
            }
            let old = std::mem::replace(&mut s.token, new_token());
            crate::secrets::redact::forget(&old);
            let restarted = if s.owner.is_some() {
                start_viewer_as(s).await
            } else {
                let Info { display, port, .. } = self.info(s);
                spawn_viewer(&display, port, &s.token).map(|v| s.viewer = v).map_err(|e| e.to_string())
            };
            if let Err(e) = restarted {
                crate::obs::log::log_warn!("Screen viewer for {key} failed to restart: {e}");
                let s = live.remove(&key).unwrap();
                stop(s).await;
            }
        }
    }

    /// `rotate_token` for every running screen.
    pub async fn rotate_all(&self) {
        let mut bots: Vec<String> = self.live.lock().await.values().map(|s| s.bot.clone()).collect();
        bots.sort();
        bots.dedup();
        for id in bots {
            self.rotate_token(&id).await;
        }
    }

    /// Stops screens that nobody used for a while.
    pub async fn reap(&self, busy: impl Fn(&str) -> bool) {
        let mut live = self.live.lock().await;
        let idle: Vec<String> =
            live.iter().filter(|(_, s)| !busy(&s.bot) && s.used.elapsed() > self.idle).map(|(k, _)| k.clone()).collect();
        for k in idle {
            let s = live.remove(&k).unwrap();
            stop(s).await;
        }
    }

    /// Stops every screen of the Bot, a teammate's own too.
    pub async fn remove(&self, bot_id: &str) {
        self.remove_where(|s| s.bot == bot_id).await;
    }

    /// Stops every screen that runs as `account`: before the account itself goes.
    pub async fn remove_account(&self, account: &str) {
        self.remove_where(|s| s.owner.as_ref().is_some_and(|o| o.run.account == account)).await;
    }

    async fn remove_where(&self, gone: impl Fn(&Screen) -> bool) {
        let stopped: Vec<Screen> = {
            let mut live = self.live.lock().await;
            let keys: Vec<String> = live.iter().filter(|(_, s)| gone(s)).map(|(k, _)| k.clone()).collect();
            keys.iter().filter_map(|k| live.remove(k)).collect()
        };
        for s in stopped {
            stop(s).await;
        }
    }
}

/// One Xauthority entry: an MIT-MAGIC-COOKIE-1 for display `n` on any host
/// (FamilyWild), as X's own `xauth` writes it. A machine's agent writes the same.
fn xauth_entry(n: u16, cookie: &[u8; 16]) -> Vec<u8> {
    let mut entry = 0xffffu16.to_be_bytes().to_vec();
    for field in [&b""[..], n.to_string().as_bytes(), b"MIT-MAGIC-COOKIE-1", cookie] {
        entry.extend_from_slice(&(field.len() as u16).to_be_bytes());
        entry.extend_from_slice(field);
    }
    entry
}

/// Removes a stale bus socket, then runs the session bus there in its place.
const DBUS: &str = r#"rm -f -- "$1"; exec dbus-daemon --session --nofork --address="$2""#;

/// Xvfb's arguments for an account's display `n`: no TCP, and only `cookie` gets in.
fn xvfb_args(n: u16, (w, h): (u32, u32), cookie: &Path) -> Vec<String> {
    vec![format!(":{n}"), "-screen".into(), "0".into(), format!("{w}x{h}x24"), "-nolisten".into(), "tcp".into(), "-auth".into(), cookie.display().to_string()]
}

/// The name of display `n`'s socket in the abstract namespace, where X clients on Linux
/// look first.
fn abstract_name(n: u16) -> String {
    format!("{X11_DIR}/X{n}")
}

fn connect_abstract(n: u16) -> std::io::Result<std::os::unix::net::UnixStream> {
    use std::os::linux::net::SocketAddrExt;
    let addr = std::os::unix::net::SocketAddr::from_abstract_name(abstract_name(n).as_bytes())?;
    std::os::unix::net::UnixStream::connect_addr(&addr)
}

/// Whether display `n` is free to start on: no X server answers there, and nothing is
/// left in its place that botd can't remove (another account's file in a folder of root's).
fn display_clear(n: u16) -> bool {
    if connect_abstract(n).is_ok() {
        return false;
    }
    let Some((sock, lock)) = x11_paths(n) else { return false };
    [sock, lock].iter().all(|p| match std::fs::remove_file(p) {
        Ok(()) => true,
        Err(e) => e.kind() == std::io::ErrorKind::NotFound,
    })
}

/// The uid of the process at the other end of a Unix socket.
fn peer_uid(s: &std::os::unix::net::UnixStream) -> Option<u32> {
    use std::os::fd::AsRawFd;
    let mut cred = libc::ucred { pid: 0, uid: 0, gid: 0 };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: `cred` and `len` are valid for the call, which writes at most `len` bytes.
    let r = unsafe { libc::getsockopt(s.as_raw_fd(), libc::SOL_SOCKET, libc::SO_PEERCRED, (&raw mut cred).cast(), &mut len) };
    (r == 0).then_some(cred.uid)
}

/// An X connection setup with no cookie (little-endian, protocol 11.0); the reply's
/// first byte is 1 when the server lets the client in.
const NO_COOKIE: [u8; 12] = [b'l', 0, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0];

/// Whether the X server on `s` lets in a client that has no cookie.
fn lets_anyone_in(s: &mut std::os::unix::net::UnixStream) -> std::io::Result<bool> {
    use std::io::{Read, Write};
    s.set_read_timeout(Some(Duration::from_secs(3)))?;
    s.write_all(&NO_COOKIE)?;
    let mut status = [0u8; 1];
    s.read_exact(&mut status)?;
    Ok(status[0] == 1)
}

/// Display `n` (socket `sock`) is the account's, on both its sockets, and lets no one
/// in without its cookie: an X server that couldn't read the cookie lets everyone in.
fn check_display(sock: &Path, n: u16, uid: u32) -> Result<(), String> {
    let m = std::fs::symlink_metadata(sock).map_err(|e| e.to_string())?;
    if !m.file_type().is_socket() || m.uid() != uid {
        return Err(format!("{} isn't the account's socket", sock.display()));
    }
    let mut s = std::os::unix::net::UnixStream::connect(sock).map_err(|e| e.to_string())?;
    if peer_uid(&s) != Some(uid) {
        return Err(format!("another account's X server answers at {}", sock.display()));
    }
    let a = connect_abstract(n).map_err(|e| format!("no X server at @{}: {e}", abstract_name(n)))?;
    if peer_uid(&a) != Some(uid) {
        return Err(format!("another account's X server answers at @{}", abstract_name(n)));
    }
    match lets_anyone_in(&mut s) {
        Ok(false) => Ok(()),
        Ok(true) => Err("the X server lets clients in without its cookie".into()),
        Err(e) => Err(format!("the X server didn't answer: {e}")),
    }
}

/// A loopback port nobody listens on now, for an account's voxl.
fn free_loopback_port() -> std::io::Result<u16> {
    Ok(std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?.local_addr()?.port())
}

/// voxl as the account on a loopback port, and botd's front piping its public port to
/// it once it answers there as the account.
async fn start_viewer_as(s: &mut Screen) -> Result<(), String> {
    let (Some(o), Some(front)) = (s.owner.clone(), s.front.clone()) else { return Err("not an account's screen".into()) };
    let inner = free_loopback_port().map_err(|e| e.to_string())?;
    let env = [("DISPLAY", format!(":{}", s.display)), ("XAUTHORITY", o.cookie.display().to_string()), ("VOXL_PASSWORD", s.token.clone())];
    let mut args: Vec<String> = ["--addr", "127.0.0.1", "--port", &inner.to_string()].map(String::from).into();
    args.extend(VOXL_ARGS.map(String::from));
    let mut v = o.spawn("voxl", args, &env).map_err(|e| format!("voxl didn't start: {e}"))?;
    for _ in 0..200 {
        if !matches!(v.try_wait(), Ok(None)) {
            break;
        }
        if let Ok(c) = TcpStream::connect((Ipv4Addr::LOCALHOST, inner)).await {
            if !held_by(&c, o.uid).await {
                return Err(format!("another account listens on the viewer's port {inner}"));
            }
            s.viewer = Some(v);
            s.serving = Some(Serving(tokio::spawn(serve(front, inner, o.uid))));
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    Err("voxl didn't start".into())
}

/// botd's front for an account's screen: each viewer is piped to voxl on `inner`, as
/// long as that port is still `uid`'s. Aborting it cuts every open view.
async fn serve(front: Arc<TcpListener>, inner: u16, uid: u32) {
    let mut views = tokio::task::JoinSet::new();
    loop {
        let Ok((mut client, _)) = front.accept().await else {
            tokio::time::sleep(Duration::from_millis(100)).await;
            continue;
        };
        while views.try_join_next().is_some() {}
        views.spawn(async move {
            let Ok(mut up) = TcpStream::connect((Ipv4Addr::LOCALHOST, inner)).await else { return };
            if !held_by(&up, uid).await {
                crate::obs::log::log_warn!("Screen viewer: port {inner} isn't the screen's account's any more; view refused.");
                return;
            }
            let _ = tokio::io::copy_bidirectional(&mut client, &mut up).await;
        });
    }
}

/// Whether the far end of loopback connection `c` belongs to `uid`: the owner of the
/// socket that accepted it, from /proc/net/tcp. Until it's accepted it has no owner
/// there, so this waits up to 2 seconds for that; one never accepted isn't `uid`'s.
pub(crate) async fn held_by(c: &TcpStream, uid: u32) -> bool {
    let (Ok(SocketAddr::V4(ours)), Ok(SocketAddr::V4(theirs))) = (c.local_addr(), c.peer_addr()) else { return false };
    for _ in 0..100 {
        if let Ok(table) = tokio::fs::read_to_string("/proc/net/tcp").await
            && let Some(owner) = far_uid(&table, ours, theirs)
        {
            return owner == uid;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    false
}

/// In /proc/net/tcp's `table`, the owner of the socket at `theirs` connected to `ours`,
/// once accepted (it has an inode).
fn far_uid(table: &str, ours: SocketAddrV4, theirs: SocketAddrV4) -> Option<u32> {
    let hex = |a: SocketAddrV4| format!("{:08X}:{:04X}", u32::from_ne_bytes(a.ip().octets()), a.port());
    let (local, remote) = (hex(theirs), hex(ours));
    table.lines().skip(1).find_map(|l| {
        let f: Vec<&str> = l.split_whitespace().collect();
        let here = f.get(1)?.eq_ignore_ascii_case(&local) && f.get(2)?.eq_ignore_ascii_case(&remote) && *f.get(9)? != "0";
        here.then(|| f.get(7)?.parse().ok()).flatten()
    })
}

/// Polls a viewer's port every 100 ms until it accepts a connection. False after `tries`.
pub async fn wait_for_port(port: u16, tries: u32) -> bool {
    let addr = dial_addr(listen_addr());
    for _ in 0..tries {
        if TcpStream::connect((addr, port)).await.is_ok() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    false
}

/// Closes the Bot's browser cleanly (so its profile saves), as whoever it runs as, then
/// kills the screen.
async fn stop(mut s: Screen) {
    s.serving = None;
    if on_path("agent-browser") {
        let args = vec!["--session".to_string(), browser_session(&s.bot), "close".into()];
        match &s.owner {
            Some(o) => {
                if let Ok(mut c) = o.spawn("agent-browser", args, &[]) {
                    let _ = tokio::time::timeout(Duration::from_secs(10), c.wait()).await;
                }
            }
            None => {
                let close = Command::new("agent-browser").args(args).stdin(Stdio::null()).output();
                let _ = tokio::time::timeout(Duration::from_secs(10), close).await;
            }
        }
    }
    if let Some(o) = &s.owner {
        crate::accounts::remove(&o.cookie);
    }
    crate::secrets::redact::forget(&s.token);
    drop(s); // kill_on_drop stops Xvfb, D-Bus, Openbox, and voxl (or the sudo each runs under)
}

/// Environment for a Bot's harness, so its tools draw on its own screen and keep
/// their own browser profile (sign-ins persist): the screen's, or in `bot_dir`.
pub fn bot_env(info: &Info, bot_id: &str, bot_dir: &Path) -> HashMap<String, String> {
    let profile = info.profile.clone().unwrap_or_else(|| bot_dir.join("browser"));
    let mut env = HashMap::from([
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
    ]);
    if let Some(x) = &info.xauthority {
        env.insert("XAUTHORITY".into(), x.clone());
    }
    env
}

#[cfg(test)]
mod tests {
    use super::*;

    fn screens(isolated: bool) -> Screens {
        let dir = std::env::temp_dir().join(format!("superbot-screens-{}", crate::short_id()));
        Screens { max: 1, idle: Duration::from_secs(60), base: 100, size: (1280, 800), run_dir: dir, isolated, live: Mutex::default() }
    }

    fn screen(bot: &str, procs: Vec<Child>) -> Screen {
        Screen { bot: bot.into(), slot: 1, display: 101, token: new_token(), used: Instant::now(), procs, viewer: None, owner: None, front: None, serving: None }
    }

    #[tokio::test]
    async fn waits_for_a_listener() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        assert!(wait_for_port(port, 1).await);
        drop(listener);
        assert!(!wait_for_port(port, 2).await);
    }

    #[tokio::test]
    async fn sees_a_late_listener() {
        let probe = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let port = probe.local_addr().unwrap().port();
        drop(probe);
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(250)).await;
            let l = TcpListener::bind(("127.0.0.1", port)).await.unwrap();
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
        let screens = screens(false);
        let display = spawn(Command::new("sleep").arg("30")).unwrap();
        screens.live.lock().await.insert("b1".into(), screen("b1", vec![display]));
        let before = screens.ensure("b1", None, |_| true).await.unwrap().token;

        screens.rotate_token("b1").await;
        let after = screens.ensure("b1", None, |_| true).await.unwrap().token;
        assert_ne!(before, after);
        assert_eq!(after.len(), 32);
        assert!(screens.live.lock().await.get_mut("b1").unwrap().alive(), "same display, not restarted");
        screens.rotate_token("nobody").await;
        screens.remove("b1").await;
    }

    #[tokio::test]
    async fn a_bots_screens_all_turn_over_and_go_together() {
        let screens = screens(false);
        for key in ["b1", "b1@u2", "b2"] {
            let bot = key.split('@').next().unwrap();
            screens.live.lock().await.insert(key.into(), screen(bot, vec![spawn(Command::new("sleep").arg("30")).unwrap()]));
        }
        let before = tokens(&screens, &["b1", "b1@u2", "b2"]).await;
        screens.rotate_token("b1").await;
        let after = tokens(&screens, &["b1", "b1@u2", "b2"]).await;
        assert_ne!(before[0], after[0]);
        assert_ne!(before[1], after[1], "a teammate's own screen of the Bot too");
        assert_eq!(before[2], after[2], "another Bot's screen keeps its token");
        screens.remove("b1").await;
        let left: Vec<String> = screens.live.lock().await.keys().cloned().collect();
        assert_eq!(left, vec!["b2".to_string()]);
    }

    async fn tokens(screens: &Screens, keys: &[&str]) -> Vec<String> {
        let live = screens.live.lock().await;
        keys.iter().map(|k| live[*k].token.clone()).collect()
    }

    #[tokio::test]
    async fn accounts_on_means_no_screen_as_botd_and_off_none_as_an_account() {
        let on = screens(true);
        assert!(on.ensure("b1", None, |_| false).await.is_err(), "never botd's own display with accounts on");
        let iso = crate::accounts::for_tests(&std::env::temp_dir(), "/bin/false");
        let me = crate::passwd::by_uid(unsafe { libc::getuid() }).unwrap();
        let run = iso.run_as_in(Space::User("u1")).unwrap();
        let o = Owner { run, uid: me.uid, home: me.home.clone(), cookie: "/nonexistent/c".into(), state: "/nonexistent/s".into() };
        assert!(screens(false).ensure("b1", Some(&o), |_| false).await.is_err());
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
    fn screen_ports_stay_inside_the_proxy_route() {
        for ok in [(6901, 6903), (6900, 6999), (6951, 6953)] {
            assert!(check_ports(ok).is_ok(), "{ok:?}");
        }
        for bad in [(6801, 6803), (7001, 7003), (6990, 7002)] {
            assert!(check_ports(bad).is_err(), "{bad:?}");
        }
        assert!(check_ports((7001, 7003)).unwrap_err().contains("between 99 and 196"));
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

    #[test]
    fn an_accounts_display_takes_only_its_cookie_and_no_tcp_or_shared_framebuffer() {
        let args = xvfb_args(107, (800, 600), Path::new("/srv/u/settings/b1/screen.xauth")).join(" ");
        assert_eq!(args, ":107 -screen 0 800x600x24 -nolisten tcp -auth /srv/u/settings/b1/screen.xauth");
        for never in ["-ac", "-shmem", "-listen", "+extension"] {
            assert!(!args.contains(never), "{args}");
        }
    }

    #[test]
    fn the_account_with_the_listener_owns_a_loopback_connection() {
        let ours: SocketAddrV4 = "127.0.0.1:41000".parse().unwrap();
        let theirs: SocketAddrV4 = "127.0.0.1:6901".parse().unwrap();
        let hex = |a: SocketAddrV4| format!("{:08X}:{:04X}", u32::from_ne_bytes(a.ip().octets()), a.port());
        let row = |i: u32, local: SocketAddrV4, remote: SocketAddrV4, uid: u32| {
            format!("{i:4}: {} {} 01 00000000:00000000 00:00000000 00000000 {uid:5}        0 1234 1 0000000000000000 20 4 30 10 -1", hex(local), hex(remote))
        };
        let head = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode";
        let table = [head.to_string(), row(0, theirs, "0.0.0.0:0".parse().unwrap(), 2001), row(1, ours, theirs, 999), row(2, theirs, ours, 2001)].join("\n");
        assert_eq!(far_uid(&table, ours, theirs), Some(2001), "the accepted socket, not botd's own end or the listener");
        let elsewhere: SocketAddrV4 = "127.0.0.1:41001".parse().unwrap();
        assert_eq!(far_uid(&table, elsewhere, theirs), None);
        let waiting = row(3, theirs, elsewhere, 0).replace(" 1234 ", " 0 ");
        assert_eq!(far_uid(&[head.to_string(), waiting].join("\n"), elsewhere, theirs), None, "not accepted yet: no owner to go by");
    }

    #[tokio::test]
    async fn botd_tells_whose_listener_a_connection_reached() {
        let l = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let port = l.local_addr().unwrap().port();
        let c = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let me = unsafe { libc::getuid() };
        assert!(!held_by(&c, me).await, "never accepted: nobody's");
        let _accepted = l.accept().await.unwrap();
        assert!(held_by(&c, me).await, "this process's own listener");
        assert!(!held_by(&c, me + 1).await, "not anyone else's");
        let c2 = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let (checked, _) = tokio::join!(held_by(&c2, me), async { tokio::time::sleep(Duration::from_millis(200)).await; l.accept().await.unwrap() });
        assert!(checked, "accepted while botd waits");
    }

    #[test]
    fn x11_sockets_must_sit_in_a_sticky_folder_nobody_else_owns() {
        let dir = std::env::temp_dir().join(format!("superbot-x11-{}", crate::short_id()));
        let x11 = dir.join(".X11-unix");
        std::fs::create_dir_all(&dir).unwrap();
        shared_x11_dir(&x11).unwrap();
        let m = std::fs::metadata(&x11).unwrap();
        assert_eq!(m.mode() & 0o7777, 0o1777, "made world-writable and sticky, as X expects");
        std::fs::set_permissions(&x11, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(shared_x11_dir(&x11).is_err(), "not sticky: anyone could swap another's socket");
        std::fs::remove_dir(&x11).unwrap();
        std::os::unix::fs::symlink(&dir, &x11).unwrap();
        assert!(shared_x11_dir(&x11).is_err(), "a link isn't the folder");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_display_that_lets_anyone_in_is_refused() {
        use std::io::{Read, Write};
        let dir = std::env::temp_dir().join(format!("superbot-x-{}", crate::short_id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("X0");
        let l = std::os::unix::net::UnixListener::bind(&path).unwrap();
        let answer = |status: u8| {
            let (mut c, _) = l.accept().unwrap();
            let mut setup = [0u8; 12];
            c.read_exact(&mut setup).unwrap();
            assert_eq!(setup, NO_COOKIE);
            c.write_all(&[status]).unwrap();
        };
        for (status, open) in [(1, true), (0, false), (2, false)] {
            let mut s = std::os::unix::net::UnixStream::connect(&path).unwrap();
            assert_eq!(peer_uid(&s), Some(unsafe { libc::getuid() }));
            let asked = std::thread::scope(|t| {
                t.spawn(|| answer(status));
                lets_anyone_in(&mut s).unwrap()
            });
            assert_eq!(asked, open, "status {status}");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_cookie_file_is_what_xauth_writes_and_what_machines_write() {
        let e = xauth_entry(101, &[7; 16]);
        assert_eq!(e, crate::machines::display::xauth_entry(101, &[7; 16]));
        assert_eq!(&e[..4], &[0xff, 0xff, 0, 0]);
        assert_eq!(e.len(), 2 + 2 + 2 + 3 + 2 + 18 + 2 + 16);
    }

    #[test]
    fn a_run_on_an_accounts_screen_gets_its_cookie_and_profile_there() {
        let info = Info {
            display: ":104".into(),
            bus: "unix:path=/srv/u/home/.tmp/bus-104".into(),
            port: 6901,
            token: String::new(),
            xauthority: Some("/srv/u/settings/b1/screen.xauth".into()),
            profile: Some("/srv/u/bots/b1/browser".into()),
        };
        let env = bot_env(&info, "b1", Path::new("/data/bots/b1"));
        assert_eq!(env["XAUTHORITY"], "/srv/u/settings/b1/screen.xauth");
        assert_eq!(env["AGENT_BROWSER_PROFILE"], "/srv/u/bots/b1/browser");
        let plain = bot_env(&Info { xauthority: None, profile: None, ..info }, "b1", Path::new("/data/bots/b1"));
        assert!(!plain.contains_key("XAUTHORITY"));
        assert_eq!(plain["AGENT_BROWSER_PROFILE"], "/data/bots/b1/browser");
    }
}
