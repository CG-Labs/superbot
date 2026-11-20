//! Bots' screens on their owner's machine (ADR 0045), botd's side. With
//! MACHINE_SCREENS=on, a Bot routed to its owner's machine gets its screen there: the
//! agent runs the display, window manager, session bus and voxl as the Bots' own user,
//! and botd shows it at the usual `/screen/<port>/` path by listening on a loopback port
//! of its own (MACHINE_SCREEN_PORTS) and piping each connection through the agent's
//! mutual-TLS port, pinned to that machine's certificates. Nothing new listens on the
//! machine beyond loopback, and its firewall is unchanged.
//!
//! `GET /api/bots/:id/screen` keeps its checks (Operate on the Bot). A Bot whose owner
//! is routed to a machine is shown from that machine or not at all: never this
//! server's own display, never another user's machine. The viewer token is botd's;
//! narrowing who may see the Bot gives it a new one and cuts open viewers. Every open,
//! start, new token, refusal and close is audited. Off, nothing here does anything.

use super::enroll::Enrollment;
use super::route::{Assigned, Refusal, Target};
use super::wire::{self, Heartbeat, ScreenReply, ScreenRequest};
use crate::audit::{Event, Outcome, Who};
use crate::db::{Bot, now};
use crate::runner::App;
use crate::users::need_user_key;
use crate::{ApiError, AppState, Res};
use axum::Json;
use axum::extract::{Path, State as AppS};
use axum::http::{StatusCode, header};
use serde_json::{Value, json};
use std::collections::{BTreeSet, HashMap};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use zeroize::Zeroizing;

pub const OFF: &str = "Screens on machines are off. Set MACHINE_SCREENS=on to turn them on.";
/// botd's loopback ports for machine screens, inside the proxy's `/screen/69xx/` route.
pub const DEFAULT_PORTS: (u16, u16) = (6960, 6999);
const PORT_RANGE: std::ops::RangeInclusive<u16> = 6900..=6999;
/// How long a start may take on the machine: Xvfb, then voxl.
const START_SECS: u64 = 30;

#[derive(Clone, Debug, PartialEq)]
pub struct Settings {
    /// botd's loopback ports, first to last.
    pub ports: (u16, u16),
    pub width: u32,
    pub height: u32,
    /// A screen no one has asked for, viewed or run on this long is stopped.
    pub idle_ms: i64,
}

/// MACHINE_SCREENS (off, the default, or on) and MACHINE_SCREEN_PORTS. Screens run only
/// as the Bots' own user, so they need MACHINE_BOT_USER=on. SCREEN_SIZE and
/// SCREEN_IDLE_MINUTES are shared with this server's own screens.
pub fn from_env(var: &dyn Fn(&str) -> String, bot_user: bool) -> Result<Option<Settings>, String> {
    match var("MACHINE_SCREENS").trim() {
        "" | "off" => return Ok(None),
        "on" => {}
        v => return Err(format!("MACHINE_SCREENS must be on or off, not \"{v}\"")),
    }
    if !bot_user {
        return Err("MACHINE_SCREENS=on needs MACHINE_BOT_USER=on: a screen never runs as root".into());
    }
    let ports = match var("MACHINE_SCREEN_PORTS").trim() {
        "" => DEFAULT_PORTS,
        p => p
            .split_once('-')
            .and_then(|(a, b)| Some((a.trim().parse::<u16>().ok()?, b.trim().parse::<u16>().ok()?)))
            .filter(|(a, b)| a <= b && PORT_RANGE.contains(a) && PORT_RANGE.contains(b))
            .ok_or(format!("MACHINE_SCREEN_PORTS must be <first>-<last> within 6900-6999 (the proxy's /screen/ route), not \"{p}\""))?,
    };
    let (width, height) = crate::screen::parse_size(&var("SCREEN_SIZE"));
    let minutes = var("SCREEN_IDLE_MINUTES").trim().parse::<i64>().unwrap_or(10).clamp(1, 24 * 60);
    Ok(Some(Settings { ports, width, height, idle_ms: minutes * 60_000 }))
}

/// Stops the task when dropped.
struct Abort(tokio::task::JoinHandle<()>);

impl Drop for Abort {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// A Bot's screen on its owner's machine, as botd knows it.
struct Open {
    machine_id: String,
    owner_id: String,
    token: Zeroizing<String>,
    /// botd's loopback port and the task accepting on it, once someone has viewed it.
    port: Option<(u16, Abort)>,
    /// Who was given a link since the last new token: each is audited once.
    viewers: BTreeSet<String>,
    since: i64,
    used: i64,
    /// Dropped or bumped, every open viewer connection ends.
    cut: watch::Sender<u64>,
    tunnels: Arc<AtomicUsize>,
}

/// Machine screens botd shows, by Bot id; and one start or new token per Bot at a time.
#[derive(Default)]
pub struct Shown {
    open: Mutex<HashMap<String, Open>>,
    busy: Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
}

impl Shown {
    fn open(&self) -> std::sync::MutexGuard<'_, HashMap<String, Open>> {
        self.open.lock().unwrap_or_else(|e| e.into_inner())
    }

    async fn one_at_a_time(&self, bot: &str) -> tokio::sync::OwnedMutexGuard<()> {
        let m = self.busy.lock().unwrap_or_else(|e| e.into_inner()).entry(bot.to_string()).or_default().clone();
        m.lock_owned().await
    }
}

/// Why a machine screen can't be shown.
#[derive(Clone, Debug, PartialEq)]
pub enum Why {
    Route(Refusal),
    /// MACHINE_SCREENS is off, but the Bot runs on a machine.
    Off,
    /// The machine lacks some of `SCREEN_PROGRAMS`.
    Missing(Vec<String>),
    /// botd has no loopback port left for it.
    NoPort,
    /// The agent wouldn't or couldn't start it.
    Failed(u16, String),
}

impl Why {
    pub fn reason(&self) -> &'static str {
        match self {
            Why::Route(r) => r.reason(),
            Why::Off => "machine_screens_off",
            Why::Missing(_) => "screen_stack_missing",
            Why::NoPort => "screen_ports_full",
            Why::Failed(..) => "screen_failed",
        }
    }

    fn status(&self) -> StatusCode {
        match self {
            Why::Route(Refusal::NoMachine | Refusal::NotAssigned | Refusal::Outdated(_) | Refusal::BotUserFailed) | Why::Off | Why::Missing(_) => {
                StatusCode::CONFLICT
            }
            _ => StatusCode::SERVICE_UNAVAILABLE,
        }
    }

    pub fn message(&self) -> String {
        let at = "This Bot runs on its owner's computer";
        match self {
            Why::Route(Refusal::NoMachine) => format!("{at}, and they don't have one yet. Ask an admin to set one up."),
            Why::Route(Refusal::NotAssigned) => format!("{at}, which isn't assigned to them yet."),
            Why::Route(Refusal::NotReady(s)) => format!("{at}, which is {}. Try again when it's running.", s.as_str()),
            Why::Route(Refusal::NotEnrolled) => format!("{at}, which hasn't connected to this server yet."),
            Why::Route(Refusal::Offline(e)) => format!("{at}, which is offline ({e}). Try again soon."),
            Why::Route(Refusal::Outdated(v)) => format!("{at}, whose agent ({v}) is too old to show screens. Ask an admin to upgrade it."),
            Why::Route(Refusal::Upgrading) => format!("{at}, whose agent is updating itself. Try again in a minute."),
            Why::Route(Refusal::BotUserPending) => format!("{at}, which is still setting up a separate account for its Bots. Try again in a few minutes."),
            Why::Route(Refusal::BotUserFailed) => format!("{at}, which couldn't set up a separate account for its Bots. Ask an admin to look at it."),
            Why::Route(r) => format!("{at}, which can't show its screen now ({}).", r.reason()),
            Why::Off => format!("{at}, and screens there are off on this server (MACHINE_SCREENS)."),
            Why::Missing(m) => format!("{at}, which can't show screens: it's missing {}. Ask an admin to install them there.", m.join(", ")),
            Why::NoPort => "All machine screen ports on this server are in use. Try again when a screen closes.".into(),
            Why::Failed(_, e) => format!("{at}, which couldn't start the screen: {e}"),
        }
    }
}

/// Whether the machine can show screens, from its heartbeat. An agent from before
/// screens, or speaking another screen protocol, is outdated.
pub fn fit(e: &Enrollment, hb: &Heartbeat) -> Result<(), Why> {
    let report = hb.screens.as_ref().filter(|s| {
        hb.protocol >= wire::PROTOCOL && hb.can.iter().any(|c| c == wire::CAN_SCREENS) && s.protocol == wire::SCREEN_PROTOCOL
    });
    let report = report.ok_or_else(|| Why::Route(Refusal::Outdated(hb.version.clone())))?;
    super::botuser::check_run(e, hb).map_err(Why::Route)?;
    if hb.upgrade.as_ref().is_some_and(|u| u.state == wire::UPGRADE_STAGING) {
        return Err(Why::Route(Refusal::Upgrading));
    }
    if !report.missing.is_empty() {
        return Err(Why::Missing(report.missing.clone()));
    }
    Ok(())
}

fn screen_event(by: &Who, action: &str, machine_id: &str, bot: &str, extra: Value) -> Event {
    let mut d = json!({ "botId": bot });
    if let (Some(d), Value::Object(x)) = (d.as_object_mut(), extra) {
        d.extend(x);
    }
    by.event(action).target("machine", machine_id).bot(bot).details(d)
}

fn enrollment(app: &App) -> Option<&Arc<Enrollment>> {
    app.control_plane.get()?.enrollment.as_ref()
}

/// Asks `to`'s agent to start `bot`'s screen with `token`, or give it that token.
async fn put(e: &Enrollment, s: &Settings, to: &Assigned, bot: &str, token: &str) -> Result<ScreenReply, Why> {
    let address = to.address.as_deref().ok_or_else(|| Why::Route(Refusal::Offline("it has no address yet".into())))?;
    let client = e.upload_client(to.pins.clone(), START_SECS).map_err(|m| Why::Route(Refusal::Offline(m)))?;
    let body = ScreenRequest {
        protocol: wire::SCREEN_PROTOCOL,
        owner_id: to.user_id.clone(),
        token: token.into(),
        width: s.width,
        height: s.height,
        idle_secs: (s.idle_ms / 1000) as u64,
    };
    let r = client
        .put(e.agent_url(address, &format!("/v1/screens/{bot}")))
        .json(&body)
        .send()
        .await
        .map_err(|err| Why::Route(Refusal::Offline(format!("its agent didn't answer: {}", super::enroll::without_url(err)))))?;
    let code = r.status().as_u16();
    let text = r.text().await.unwrap_or_default();
    if code != 200 {
        let msg = serde_json::from_str::<wire::ErrorReply>(&text).map(|e| e.error).unwrap_or_else(|_| format!("its agent answered {code}"));
        return Err(Why::Failed(code, msg));
    }
    serde_json::from_str(&text).map_err(|_| Why::Failed(502, "its agent's answer wasn't a screen".into()))
}

/// Starts `bot`'s screen on `to`, or keeps it, with the token botd holds for it (a new
/// one if it has none). One left on another machine, or for another owner, is closed
/// first. Records the open screen.
async fn ensure(app: &App, e: &Enrollment, s: &Settings, by: &Who, bot: &Bot, to: &Assigned, why: &str) -> Result<(ScreenReply, Zeroizing<String>), Why> {
    let elsewhere = e.shown.open().get(&bot.id).is_some_and(|o| o.machine_id != to.machine_id || o.owner_id != bot.owner_id);
    if elsewhere {
        close_locked(app, e, by, &bot.id, "moved").await;
    }
    let token = e.shown.open().get(&bot.id).map(|o| o.token.clone());
    let token = token.unwrap_or_else(|| Zeroizing::new(crate::random_hex(16)));
    crate::secrets::redact::register(&token);
    let reply = put(e, s, to, &bot.id, &token).await?;
    if app.db.bot(&bot.id).is_none_or(|b| b.owner_id != bot.owner_id) {
        let path = format!("/v1/screens/{}", bot.id);
        if let Some(m) = app.db.machine(&to.machine_id) {
            let _ = e.call_agent(app, &m, reqwest::Method::DELETE, &path, &()).await;
        }
        return Err(Why::Failed(409, "the Bot was deleted or given to someone else meanwhile".into()));
    }
    let at = now();
    {
        let mut open = e.shown.open();
        match open.get_mut(&bot.id).filter(|o| o.machine_id == to.machine_id && o.token == token) {
            Some(o) => o.used = at,
            None => drop(open.insert(
                bot.id.clone(),
                Open {
                    machine_id: to.machine_id.clone(),
                    owner_id: bot.owner_id.clone(),
                    token: token.clone(),
                    port: None,
                    viewers: BTreeSet::new(),
                    since: at,
                    used: at,
                    cut: watch::channel(0).0,
                    tunnels: Arc::default(),
                },
            )),
        }
    }
    if reply.started {
        app.db.record(&screen_event(by, "machine.screen_started", &to.machine_id, &bot.id, json!({ "display": reply.display, "for": why })));
    }
    Ok((reply, token))
}

/// Where `bot` is shown, if its owner's Bots run on a machine: `Ok(None)` when they run
/// on this server. Never this server's display for a Bot routed to a machine.
pub async fn target(app: &App, bot: &Bot) -> Result<Option<(Arc<Enrollment>, Settings, Assigned)>, Why> {
    let Some(cp) = app.control_plane.get() else { return Ok(None) };
    let to = match cp.route(&app.db, &bot.owner_id) {
        Ok(Target::Local) => return Ok(None),
        Ok(Target::Machine(to)) => to,
        Err(r) => return Err(Why::Route(r)),
    };
    let e = cp.enrollment.clone().ok_or_else(|| Why::Route(Refusal::Offline("machine enrollment is off on this server".into())))?;
    let s = e.screens.clone().ok_or(Why::Off)?;
    Ok(Some((e, s, to)))
}

/// `GET /api/bots/:id/screen` for a Bot on its owner's machine: its screen there,
/// started if need be, as a `/screen/<port>/?token=` link. `Ok(None)`: the Bot runs on
/// this server, which shows it as before. The caller has checked access to the Bot;
/// `still` checks it again once the screen is this request's to hand out, since a new
/// token made meanwhile must not reach someone who just lost access.
pub async fn open(app: &AppState, by: &Who, bot: &Bot, still: impl Fn() -> Res<()>) -> Res<Option<String>> {
    let refused = |machine: Option<&str>, w: Why| {
        let d = json!({ "reason": w.reason(), "owner": bot.owner_id, "machine": machine });
        let e = by.event("machine.screen_refused").bot(&bot.id).outcome(Outcome::Denied).details(d);
        app.db.record(&match machine {
            Some(m) => e.target("machine", m),
            None => e.target("bot", &bot.id),
        });
        ApiError(w.status(), w.message())
    };
    let (e, s, to) = match target(app, bot).await {
        Ok(None) => return Ok(None),
        Ok(Some(t)) => t,
        Err(w) => return Err(refused(None, w)),
    };
    let _one = e.shown.one_at_a_time(&bot.id).await;
    let hb = super::enroll::check(app, &e, &to).await.map_err(|m| refused(Some(&to.machine_id), Why::Route(Refusal::Offline(m))))?;
    fit(&e, &hb).map_err(|w| refused(Some(&to.machine_id), w))?;
    let (reply, token) = ensure(app, &e, &s, by, bot, &to, "viewer").await.map_err(|w| refused(Some(&to.machine_id), w))?;
    still()?;
    let viewer = by.actor.id.clone().unwrap_or_default();
    let (port, first) = listen(app, &e, &s, &bot.id, &viewer).map_err(|w| refused(Some(&to.machine_id), w))?;
    if first {
        let d = json!({ "port": port, "display": reply.display, "viewer": viewer });
        app.db.record(&screen_event(by, "machine.screen_opened", &to.machine_id, &bot.id, d));
    }
    Ok(Some(format!("/screen/{port}/?token={}", token.as_str())))
}

/// botd's loopback port for `bot`'s open screen, listening from now if it wasn't; and
/// whether `viewer` is new to it.
fn listen(app: &AppState, e: &Enrollment, s: &Settings, bot: &str, viewer: &str) -> Result<(u16, bool), Why> {
    let mut open = e.shown.open();
    let taken: Vec<u16> = open.values().filter_map(|o| o.port.as_ref().map(|p| p.0)).collect();
    let o = open.get_mut(bot).ok_or_else(|| Why::Failed(503, "it closed meanwhile".into()))?;
    o.used = now();
    if o.port.is_none() {
        let l = (s.ports.0..=s.ports.1)
            .filter(|p| !taken.contains(p))
            .find_map(|p| std::net::TcpListener::bind(("127.0.0.1", p)).ok().map(|l| (p, l)));
        let (port, l) = l.ok_or(Why::NoPort)?;
        l.set_nonblocking(true).map_err(|err| Why::Failed(500, err.to_string()))?;
        let l = TcpListener::from_std(l).map_err(|err| Why::Failed(500, err.to_string()))?;
        o.port = Some((port, Abort(tokio::spawn(accept(app.clone(), bot.to_string(), l)))));
    }
    let port = o.port.as_ref().map_or(0, |p| p.0);
    Ok((port, o.viewers.insert(viewer.to_string())))
}

async fn accept(app: AppState, bot: String, l: TcpListener) {
    loop {
        let Ok((tcp, _)) = l.accept().await else {
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            continue;
        };
        let (app, bot) = (app.clone(), bot.clone());
        tokio::spawn(async move {
            if let Err(why) = tunnel(&app, &bot, tcp).await {
                eprintln!("Screen of Bot {bot}: {why}");
            }
        });
    }
}

/// One viewer connection, piped to the Bot's voxl through its machine's agent. Checked
/// afresh each time: the Bot is still its owner's, and its owner still routed to that
/// machine, reached at its current certificates.
async fn tunnel(app: &AppState, bot: &str, mut tcp: TcpStream) -> Result<(), String> {
    let e = enrollment(app).ok_or("machine enrollment is off")?.clone();
    let (machine_id, owner, mut cut, tunnels) = {
        let open = e.shown.open();
        let o = open.get(bot).ok_or("it isn't open")?;
        (o.machine_id.clone(), o.owner_id.clone(), o.cut.subscribe(), o.tunnels.clone())
    };
    let still = app.db.bot(bot).is_some_and(|b| b.owner_id == owner);
    let to = match app.control_plane.get().map(|cp| cp.route(&app.db, &owner)) {
        Some(Ok(Target::Machine(to))) if still && to.machine_id == machine_id => to,
        _ => {
            close(app, &Who::system("control_plane"), bot, "moved").await;
            return Err("its Bot or owner moved off that machine".into());
        }
    };
    let address = to.address.as_deref().ok_or("its machine has no address")?;
    let client = e.tunnel_client(to.pins.clone())?;
    let r = client
        .get(e.agent_url(address, &format!("/v1/screens/{bot}/tunnel")))
        .header(header::CONNECTION, "upgrade")
        .header(header::UPGRADE, wire::SCREEN_UPGRADE)
        .send()
        .await
        .map_err(|err| format!("its agent didn't answer: {}", super::enroll::without_url(err)))?;
    if r.status() != StatusCode::SWITCHING_PROTOCOLS {
        return Err(format!("its agent answered {}", r.status().as_u16()));
    }
    let mut up = r.upgrade().await.map_err(|err| format!("the tunnel didn't open: {}", super::enroll::without_url(err)))?;
    struct Count(Arc<AtomicUsize>);
    impl Drop for Count {
        fn drop(&mut self) {
            self.0.fetch_sub(1, Ordering::SeqCst);
        }
    }
    tunnels.fetch_add(1, Ordering::SeqCst);
    let _count = Count(tunnels);
    tokio::select! {
        _ = tokio::io::copy_bidirectional(&mut up, &mut tcp) => {}
        _ = cut.changed() => {}
    }
    if let Some(o) = e.shown.open().get_mut(bot) {
        o.used = now();
    }
    Ok(())
}

/// The screen's environment for a run of `bot` on `to`, starting it there if need be.
/// None when screens are off or the machine can't show one: the Bot runs without.
pub async fn for_run(app: &App, bot: &Bot, to: &Assigned, state_dir: &std::path::Path) -> Option<HashMap<String, String>> {
    let e = enrollment(app)?.clone();
    let s = e.screens.clone()?;
    let _one = e.shown.one_at_a_time(&bot.id).await;
    let by = Who::system("runner");
    match ensure(app, &e, &s, &by, bot, to, "run").await {
        Ok((reply, _)) => {
            let info = crate::screen::Info { display: reply.display, bus: reply.bus, port: 0, token: String::new() };
            Some(crate::screen::bot_env(&info, &bot.id, state_dir))
        }
        Err(w) => {
            eprintln!("Screen of Bot {} on machine {}: {}", bot.id, to.machine_id, w.message());
            None
        }
    }
}

/// Who may see `bot` narrowed: a new token for its screen, if one is open, and every
/// open viewer is cut off. botd stops showing the old token at once; the machine is
/// told now, or at the next open.
pub async fn rotate(app: &App, bot: &str) {
    let Some(e) = enrollment(app).cloned() else { return };
    let _one = e.shown.one_at_a_time(bot).await;
    let owner = e.shown.open().get(bot).map(|o| o.owner_id.clone());
    let Some(owner) = owner else { return };
    if app.db.bot(bot).is_none_or(|b| b.owner_id != owner) {
        close_locked(app, &e, &Who::system("control_plane"), bot, "moved").await;
        return;
    }
    let token = Zeroizing::new(crate::random_hex(16));
    crate::secrets::redact::register(&token);
    let machine = {
        let mut open = e.shown.open();
        let Some(o) = open.get_mut(bot) else { return };
        o.token = token.clone();
        o.port = None;
        o.viewers.clear();
        o.cut.send_modify(|n| *n += 1);
        o.machine_id.clone()
    };
    let by = Who::system("control_plane");
    let told = match (app.db.bot(bot), e.screens.clone(), app.db.machine(&machine)) {
        (Some(b), Some(s), Some(m)) => {
            let to = Assigned { machine_id: m.id.clone(), user_id: m.user_id.clone(), address: m.ipv4.clone(), pins: app.db.machine_pins(&m.id) };
            put(&e, &s, &to, &b.id, &token).await.is_ok()
        }
        _ => false,
    };
    app.db.record(&screen_event(&by, "machine.screen_rotated", &machine, bot, json!({ "machineTold": told })));
}

/// Stops showing `bot`'s machine screen and asks its agent to stop it, after any start
/// or new token for it under way.
pub async fn close(app: &App, by: &Who, bot: &str, reason: &str) -> bool {
    let Some(e) = enrollment(app).cloned() else { return false };
    let _one = e.shown.one_at_a_time(bot).await;
    close_locked(app, &e, by, bot, reason).await
}

/// `rotate` for every open machine screen, when someone loses access: a link doesn't
/// know who opened it, so they all change.
pub async fn rotate_all(app: &App) {
    let Some(e) = enrollment(app) else { return };
    let bots: Vec<String> = e.shown.open().keys().cloned().collect();
    for bot in bots {
        rotate(app, &bot).await;
    }
}

async fn close_locked(app: &App, e: &Enrollment, by: &Who, bot: &str, reason: &str) -> bool {
    let Some(o) = e.shown.open().remove(bot) else { return false };
    let stopped = match app.db.machine(&o.machine_id) {
        Some(m) => e.call_agent(app, &m, reqwest::Method::DELETE, &format!("/v1/screens/{bot}"), &()).await.is_ok_and(|(c, _)| c == 204 || c == 404),
        None => false,
    };
    let d = json!({ "reason": reason, "openMs": now() - o.since, "machineStopped": stopped });
    app.db.record(&screen_event(by, "machine.screen_closed", &o.machine_id, bot, d));
    true
}

/// Closes screens no one has asked for, viewed or run on lately, and those whose Bot or
/// owner left that machine. After every round of heartbeats.
pub async fn reap(app: &App) {
    let Some(e) = enrollment(app).cloned() else { return };
    let Some(s) = e.screens.clone() else { return };
    let at = now();
    let due: Vec<(String, &'static str)> = {
        let open = e.shown.open();
        open.iter()
            .filter_map(|(bot, o)| {
                let here = app.db.bot(bot).filter(|b| b.owner_id == o.owner_id);
                let routed = app.control_plane.get().map(|cp| cp.route(&app.db, &o.owner_id));
                let moved = here.is_none() || !matches!(routed, Some(Ok(Target::Machine(ref to))) if to.machine_id == o.machine_id);
                let idle = at - o.used >= s.idle_ms && o.tunnels.load(Ordering::SeqCst) == 0 && !app.is_running(bot);
                match (moved, idle) {
                    (true, _) => Some((bot.clone(), "moved")),
                    (_, true) => Some((bot.clone(), "idle")),
                    _ => None,
                }
            })
            .collect()
    };
    let by = Who::system("control_plane");
    for (bot, reason) in due {
        close(app, &by, &bot, reason).await;
    }
}

/// `GET /api/users/{key}/machine/screens`: the user's Bots' screens botd shows from
/// their machine, and what its agent last said of screens.
pub async fn list(AppS(app): AppS<AppState>, Path(key): Path<String>) -> Res {
    let cp = app.control_plane.get().ok_or_else(|| ApiError(StatusCode::SERVICE_UNAVAILABLE, super::NOT_CONFIGURED.into()))?;
    let e = super::enroll::need(cp)?;
    let u = need_user_key(&app, &key)?;
    let m = app.db.user_machine(&u.id).ok_or_else(|| crate::not_found("Machine"))?;
    let screens: Vec<Value> = {
        let open = e.shown.open();
        let mut v: Vec<Value> = open
            .iter()
            .filter(|(_, o)| o.machine_id == m.id)
            .map(|(bot, o)| {
                json!({
                    "botId": bot, "since": o.since, "usedAt": o.used, "port": o.port.as_ref().map(|p| p.0),
                    "viewers": o.viewers.len(), "connections": o.tunnels.load(Ordering::SeqCst),
                })
            })
            .collect();
        v.sort_by(|a, b| a["botId"].as_str().cmp(&b["botId"].as_str()));
        v
    };
    let agent = m.agent_upkeep.as_ref().map(|u| u["screens"].clone()).unwrap_or(Value::Null);
    Ok(Json(json!({ "machineId": m.id, "on": e.screens.is_some(), "screens": screens, "agent": agent })))
}

/// `DELETE /api/users/{key}/machine/screens/{bot}`: stops showing a Bot's screen and
/// stops it on the machine.
pub async fn close_now(
    AppS(app): AppS<AppState>,
    axum::extract::Extension(by): axum::extract::Extension<Who>,
    Path((key, bot)): Path<(String, String)>,
) -> Res<StatusCode> {
    let cp = app.control_plane.get().ok_or_else(|| ApiError(StatusCode::SERVICE_UNAVAILABLE, super::NOT_CONFIGURED.into()))?;
    let e = super::enroll::need(cp)?;
    if e.screens.is_none() {
        return Err(ApiError(StatusCode::CONFLICT, OFF.into()));
    }
    let u = need_user_key(&app, &key)?;
    let open = e.shown.open().get(&bot).map(|o| o.owner_id.clone());
    if open.as_deref() != Some(u.id.as_str()) {
        return Err(crate::not_found("Screen"));
    }
    close(&app, &by, &bot, "closed_by_admin").await;
    Ok(StatusCode::NO_CONTENT)
}

/// What the agent's last heartbeat said of screens, for `botctl machine agent`.
pub fn upkeep_json(hb: &Heartbeat) -> Value {
    match &hb.screens {
        Some(s) if hb.can.iter().any(|c| c == wire::CAN_SCREENS) => {
            json!({ "protocol": s.protocol, "missing": s.missing, "running": s.running, "max": s.max })
        }
        _ => Value::Null,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> String {
        let m: HashMap<String, String> = pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        move |k| m.get(k).cloned().unwrap_or_default()
    }

    #[test]
    fn settings_are_off_by_default_and_need_the_bots_own_user() {
        assert_eq!(from_env(&env(&[]), true), Ok(None));
        assert_eq!(from_env(&env(&[("MACHINE_SCREENS", "off")]), false), Ok(None));
        let e = from_env(&env(&[("MACHINE_SCREENS", "on")]), false).unwrap_err();
        assert!(e.contains("MACHINE_BOT_USER=on"), "{e}");
        assert!(from_env(&env(&[("MACHINE_SCREENS", "yes")]), true).is_err());
        let s = from_env(&env(&[("MACHINE_SCREENS", "on")]), true).unwrap().unwrap();
        assert_eq!((s.ports, s.width, s.height, s.idle_ms), (DEFAULT_PORTS, 1280, 800, 600_000));
        let s = from_env(&env(&[("MACHINE_SCREENS", "on"), ("MACHINE_SCREEN_PORTS", "6950-6955"), ("SCREEN_SIZE", "1024x768"), ("SCREEN_IDLE_MINUTES", "3")]), true)
            .unwrap()
            .unwrap();
        assert_eq!((s.ports, s.width, s.height, s.idle_ms), ((6950, 6955), 1024, 768, 180_000));
        for bad in ["7000-7010", "6990-6980", "6950", "a-b", "6899-6950"] {
            assert!(from_env(&env(&[("MACHINE_SCREENS", "on"), ("MACHINE_SCREEN_PORTS", bad)]), true).is_err(), "{bad}");
        }
    }

    fn hb() -> Heartbeat {
        Heartbeat {
            version: "0.2.0".into(),
            protocol: wire::PROTOCOL,
            can: vec![wire::CAN_BOT_USER.into(), wire::CAN_SCREENS.into()],
            bot_user: Some(wire::BotUserStatus { state: wire::BOT_USER_READY.into(), ..Default::default() }),
            screens: Some(wire::ScreenReport { protocol: wire::SCREEN_PROTOCOL, max: 4, ..Default::default() }),
            ..Default::default()
        }
    }

    #[test]
    fn only_a_current_agent_with_the_whole_stack_and_its_bots_user_shows_screens() {
        let e = Enrollment::for_tests(1, 1, 1).with_bot_user();
        assert_eq!(fit(&e, &hb()), Ok(()));
        let outdated = Err(Why::Route(Refusal::Outdated("0.2.0".into())));
        assert_eq!(fit(&e, &Heartbeat { screens: None, ..hb() }), outdated, "from before screens");
        assert_eq!(fit(&e, &Heartbeat { can: vec![wire::CAN_BOT_USER.into()], ..hb() }), outdated);
        let other = wire::ScreenReport { protocol: wire::SCREEN_PROTOCOL + 1, ..Default::default() };
        assert_eq!(fit(&e, &Heartbeat { screens: Some(other), ..hb() }), outdated, "another screen protocol");
        let pending = Heartbeat { bot_user: None, ..hb() };
        assert_eq!(fit(&e, &pending), Err(Why::Route(Refusal::BotUserPending)));
        let missing = wire::ScreenReport { protocol: wire::SCREEN_PROTOCOL, missing: vec!["voxl".into()], ..Default::default() };
        let w = fit(&e, &Heartbeat { screens: Some(missing), ..hb() }).unwrap_err();
        assert_eq!((w.reason(), w.status()), ("screen_stack_missing", StatusCode::CONFLICT));
        assert!(w.message().contains("missing voxl"), "{}", w.message());
        let staging = Heartbeat { upgrade: Some(wire::UpgradeReport { state: wire::UPGRADE_STAGING.into(), ..Default::default() }), ..hb() };
        assert_eq!(fit(&e, &staging), Err(Why::Route(Refusal::Upgrading)));
    }
}
