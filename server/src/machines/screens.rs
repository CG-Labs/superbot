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
//!
//! With MACHINE_TEAMMATE_USERS=on (ADR 0048), a teammate's runs of a shared Bot get a
//! screen of their own, as their own OS user, apart from the owner's: kept under
//! `wire::screen_key`, shown only to that teammate (and admins, who may ask for it),
//! and closed once they can no longer operate the Bot. Every display then takes an X
//! cookie, so one OS user on the machine can't open another's.

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
const PORT_RANGE: std::ops::RangeInclusive<u16> = crate::screen::PROXY_PORTS;
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
    bot_id: String,
    /// The teammate whose own screen of the Bot this is (ADR 0048); None: the owner's.
    for_user: Option<String>,
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

/// Machine screens botd shows, by `wire::screen_key`; and one start or new token per
/// Bot at a time, for all its screens.
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

    /// The keys of `bot`'s open screens: its owner's and its teammates'.
    fn keys_of(&self, bot: &str) -> Vec<String> {
        self.open().iter().filter(|(_, o)| o.bot_id == bot).map(|(k, _)| k.clone()).collect()
    }
}

/// The agent's path for a screen, with `?for=` for a teammate's.
fn agent_path(bot: &str, for_user: Option<&str>, rest: &str) -> String {
    match for_user {
        Some(u) => format!("/v1/screens/{bot}{rest}?for={u}"),
        None => format!("/v1/screens/{bot}{rest}"),
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
/// screens, or speaking another screen protocol, is outdated; so is one that can't
/// keep teammates' screens apart from the owner's, once those are on (ADR 0048).
pub fn fit(e: &Enrollment, hb: &Heartbeat) -> Result<(), Why> {
    if e.teammate_users {
        super::teammate::fit(hb).map_err(Why::Route)?;
    }
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

fn screen_event(by: &Who, action: &str, machine_id: &str, bot: &str, for_user: Option<&str>, extra: Value) -> Event {
    let mut d = json!({ "botId": bot });
    if let Some(u) = for_user {
        d["forUser"] = json!(u);
    }
    if let (Some(d), Value::Object(x)) = (d.as_object_mut(), extra) {
        d.extend(x);
    }
    by.event(action).target("machine", machine_id).bot(bot).details(d)
}

fn enrollment(app: &App) -> Option<&Arc<Enrollment>> {
    app.control_plane.get()?.enrollment.as_ref()
}

/// Asks `to`'s agent to start `bot`'s screen (`for_user`'s own, if given) with `token`,
/// or give it that token.
async fn put(e: &Enrollment, s: &Settings, to: &Assigned, bot: &str, for_user: Option<&str>, token: &str) -> Result<ScreenReply, Why> {
    let address = to.address.as_deref().ok_or_else(|| Why::Route(Refusal::Offline("it has no address yet".into())))?;
    let client = e.upload_client(to.pins.clone(), START_SECS).map_err(|m| Why::Route(Refusal::Offline(m)))?;
    let body = ScreenRequest {
        protocol: wire::SCREEN_PROTOCOL,
        owner_id: to.user_id.clone(),
        token: token.into(),
        width: s.width,
        height: s.height,
        idle_secs: (s.idle_ms / 1000) as u64,
        for_user: for_user.map(str::to_string),
        xauth: e.teammate_users,
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

/// Starts `bot`'s screen on `to` (`for_user`'s own, if given), or keeps it, with the
/// token botd holds for it (a new one if it has none). One left on another machine, or
/// for another owner, is closed first. Records the open screen.
#[allow(clippy::too_many_arguments)]
async fn ensure(app: &App, e: &Enrollment, s: &Settings, by: &Who, bot: &Bot, for_user: Option<&str>, to: &Assigned, why: &str) -> Result<(ScreenReply, Zeroizing<String>), Why> {
    let key = wire::screen_key(&bot.id, for_user);
    let elsewhere = e.shown.open().get(&key).is_some_and(|o| o.machine_id != to.machine_id || o.owner_id != bot.owner_id);
    if elsewhere {
        close_locked(app, e, by, &key, "moved").await;
    }
    let token = e.shown.open().get(&key).map(|o| o.token.clone());
    let token = token.unwrap_or_else(|| Zeroizing::new(crate::random_hex(16)));
    crate::secrets::redact::register(&token);
    let reply = put(e, s, to, &bot.id, for_user, &token).await?;
    if app.db.bot(&bot.id).is_none_or(|b| b.owner_id != bot.owner_id) {
        let path = agent_path(&bot.id, for_user, "");
        if let Some(m) = app.db.machine(&to.machine_id) {
            let _ = e.call_agent(app, &m, reqwest::Method::DELETE, &path, &()).await;
        }
        return Err(Why::Failed(409, "the Bot was deleted or given to someone else meanwhile".into()));
    }
    let at = now();
    {
        let mut open = e.shown.open();
        match open.get_mut(&key).filter(|o| o.machine_id == to.machine_id && o.token == token) {
            Some(o) => o.used = at,
            None => drop(open.insert(
                key.clone(),
                Open {
                    bot_id: bot.id.clone(),
                    for_user: for_user.map(str::to_string),
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
        app.db.record(&screen_event(by, "machine.screen_started", &to.machine_id, &bot.id, for_user, json!({ "display": reply.display, "for": why })));
    }
    Ok((reply, token))
}

/// Where `bot` is shown, if its owner's Bots run on a machine: `Ok(None)` when they run
/// on this server. Never this server's display for a Bot routed to a machine.
pub async fn target(app: &App, bot: &Bot) -> Result<Option<(Arc<Enrollment>, Settings, Assigned)>, Why> {
    let Some(cp) = app.control_plane.get() else { return Ok(None) };
    let to = match cp.route(app, &bot.owner_id) {
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
/// `still` checks it again once no new token for it is under way, before anything starts:
/// a revocation that finished meanwhile must not hand out the new token. `for_user`: the
/// teammate whose own screen of it this is (ADR 0048), made their user there if need be.
pub async fn open(app: &AppState, by: &Who, bot: &Bot, for_user: Option<&str>, still: impl Fn() -> Res<()>) -> Res<Option<String>> {
    let refused = |machine: Option<&str>, w: Why| {
        let d = json!({ "reason": w.reason(), "owner": bot.owner_id, "machine": machine, "forUser": for_user });
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
    still()?;
    let hb = super::enroll::check(app, &e, &to).await.map_err(|m| refused(Some(&to.machine_id), Why::Route(Refusal::Offline(m))))?;
    fit(&e, &hb).map_err(|w| refused(Some(&to.machine_id), w))?;
    if let Some(u) = for_user {
        let t = super::teammate::ask(&e, &to, u).await.map_err(|m| refused(Some(&to.machine_id), Why::Route(Refusal::TeammateUserFailed(m))))?;
        if t.created {
            let d = json!({ "owner": bot.owner_id, "forUser": u, "user": t.user, "uid": t.uid });
            app.db.record(&by.event("machine.teammate_user_created").target("machine", &to.machine_id).bot(&bot.id).details(d));
        }
        super::offboard::seen(app, &to.machine_id, u);
    }
    let (reply, token) = ensure(app, &e, &s, by, bot, for_user, &to, "viewer").await.map_err(|w| refused(Some(&to.machine_id), w))?;
    let viewer = by.actor.id.clone().unwrap_or_default();
    let key = wire::screen_key(&bot.id, for_user);
    let (port, first) = listen(app, &e, &s, &key, &viewer).map_err(|w| refused(Some(&to.machine_id), w))?;
    if first {
        let d = json!({ "port": port, "display": reply.display, "viewer": viewer });
        app.db.record(&screen_event(by, "machine.screen_opened", &to.machine_id, &bot.id, for_user, d));
    }
    Ok(Some(format!("/screen/{port}/?token={}", token.as_str())))
}

/// botd's port (on SCREEN_ADDR, loopback by default) for the open screen under `key`,
/// listening from now if it wasn't; and whether `viewer` is new to it.
fn listen(app: &AppState, e: &Enrollment, s: &Settings, key: &str, viewer: &str) -> Result<(u16, bool), Why> {
    let mut open = e.shown.open();
    let taken: Vec<u16> = open.values().filter_map(|o| o.port.as_ref().map(|p| p.0)).collect();
    let o = open.get_mut(key).ok_or_else(|| Why::Failed(503, "it closed meanwhile".into()))?;
    o.used = now();
    if o.port.is_none() {
        let l = (s.ports.0..=s.ports.1)
            .filter(|p| !taken.contains(p))
            .find_map(|p| std::net::TcpListener::bind((crate::screen::listen_addr(), p)).ok().map(|l| (p, l)));
        let (port, l) = l.ok_or(Why::NoPort)?;
        l.set_nonblocking(true).map_err(|err| Why::Failed(500, err.to_string()))?;
        let l = TcpListener::from_std(l).map_err(|err| Why::Failed(500, err.to_string()))?;
        o.port = Some((port, Abort(tokio::spawn(accept(app.clone(), key.to_string(), l)))));
    }
    let port = o.port.as_ref().map_or(0, |p| p.0);
    Ok((port, o.viewers.insert(viewer.to_string())))
}

async fn accept(app: AppState, key: String, l: TcpListener) {
    loop {
        let Ok((tcp, _)) = l.accept().await else {
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            continue;
        };
        let (app, key) = (app.clone(), key.clone());
        tokio::spawn(async move {
            if let Err(why) = tunnel(&app, &key, tcp).await {
                crate::obs::log::log_warn!("Screen {key}: {why}");
            }
        });
    }
}

/// Whether the teammate a screen is for can still operate its Bot (ADR 0048).
fn still_theirs(app: &App, bot: &Bot, for_user: Option<&str>) -> bool {
    for_user.is_none_or(|u| crate::acl::Viewer::person(&app.db, u).access(&app.db, bot) >= crate::acl::Access::Operate)
}

/// One viewer connection, piped to the Bot's voxl through its machine's agent. Checked
/// afresh each time: the Bot is still its owner's, its owner still routed to that
/// machine, reached at its current certificates, and a teammate's screen still theirs.
async fn tunnel(app: &AppState, key: &str, mut tcp: TcpStream) -> Result<(), String> {
    let e = enrollment(app).ok_or("machine enrollment is off")?.clone();
    let (bot, for_user, machine_id, owner, mut cut, tunnels) = {
        let open = e.shown.open();
        let o = open.get(key).ok_or("it isn't open")?;
        (o.bot_id.clone(), o.for_user.clone(), o.machine_id.clone(), o.owner_id.clone(), o.cut.subscribe(), o.tunnels.clone())
    };
    let bot = bot.as_str();
    let here = app.db.bot(bot).filter(|b| b.owner_id == owner);
    if here.as_ref().is_some_and(|b| !still_theirs(app, b, for_user.as_deref())) {
        close_key(app, &Who::system("control_plane"), bot, key, "access_lost").await;
        return Err("the teammate it's for can no longer use its Bot".into());
    }
    let to = match app.control_plane.get().map(|cp| cp.route(app, &owner)) {
        Some(Ok(Target::Machine(to))) if here.is_some() && to.machine_id == machine_id => to,
        _ => {
            close(app, &Who::system("control_plane"), bot, "moved").await;
            return Err("its Bot or owner moved off that machine".into());
        }
    };
    let address = to.address.as_deref().ok_or("its machine has no address")?;
    let client = e.tunnel_client(to.pins.clone())?;
    let r = client
        .get(e.agent_url(address, &agent_path(bot, for_user.as_deref(), "/tunnel")))
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
    if let Some(o) = e.shown.open().get_mut(key) {
        o.used = now();
    }
    Ok(())
}

/// Holds `bot`'s lock as a start or new token would, until dropped.
#[cfg(test)]
pub async fn hold_for_tests(e: &Enrollment, bot: &str) -> tokio::sync::OwnedMutexGuard<()> {
    e.shown.one_at_a_time(bot).await
}

/// The screen's environment for a run of `bot` on `to`, starting it there if need be:
/// `for_user`'s own, for a teammate's run as their own user (ADR 0048). None when
/// screens are off or the machine can't show one: the Bot runs without.
pub async fn for_run(app: &App, bot: &Bot, for_user: Option<&str>, to: &Assigned, state_dir: &std::path::Path) -> Option<HashMap<String, String>> {
    let e = enrollment(app)?.clone();
    let s = e.screens.clone()?;
    let _one = e.shown.one_at_a_time(&bot.id).await;
    let by = Who::system("runner");
    match ensure(app, &e, &s, &by, bot, for_user, to, "run").await {
        Ok((reply, _)) => {
            let info = crate::screen::Info { display: reply.display, bus: reply.bus, port: 0, token: String::new() };
            let mut env = crate::screen::bot_env(&info, &bot.id, state_dir);
            if let Some(x) = reply.xauthority {
                env.insert("XAUTHORITY".into(), x);
            }
            Some(env)
        }
        Err(w) => {
            crate::obs::log::log_warn!("Screen of Bot {} on machine {}: {}", bot.id, to.machine_id, w.message());
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
    for key in e.shown.keys_of(bot) {
        rotate_key(app, &e, bot, &key).await;
    }
}

async fn rotate_key(app: &App, e: &Enrollment, bot: &str, key: &str) {
    let open = e.shown.open().get(key).map(|o| (o.owner_id.clone(), o.for_user.clone()));
    let Some((owner, for_user)) = open else { return };
    let by = Who::system("control_plane");
    let Some(b) = app.db.bot(bot).filter(|b| b.owner_id == owner) else {
        close_locked(app, e, &by, key, "moved").await;
        return;
    };
    // A teammate who lost the Bot loses their screen of it (ADR 0048).
    if !still_theirs(app, &b, for_user.as_deref()) {
        close_locked(app, e, &by, key, "access_lost").await;
        return;
    }
    let token = Zeroizing::new(crate::random_hex(16));
    crate::secrets::redact::register(&token);
    let machine = {
        let mut open = e.shown.open();
        let Some(o) = open.get_mut(key) else { return };
        o.token = token.clone();
        o.port = None;
        o.viewers.clear();
        o.cut.send_modify(|n| *n += 1);
        o.machine_id.clone()
    };
    let told = match (e.screens.clone(), app.db.machine(&machine)) {
        (Some(s), Some(m)) => {
            let to = Assigned { machine_id: m.id.clone(), user_id: m.user_id.clone(), address: m.ipv4.clone(), pins: app.db.machine_pins(&m.id) };
            put(e, &s, &to, &b.id, for_user.as_deref(), &token).await.is_ok()
        }
        _ => false,
    };
    app.db.record(&screen_event(&by, "machine.screen_rotated", &machine, bot, for_user.as_deref(), json!({ "machineTold": told })));
}

/// Stops showing `bot`'s machine screens, its owner's and its teammates', and asks its
/// agent to stop them, after any start or new token for it under way.
pub async fn close(app: &App, by: &Who, bot: &str, reason: &str) -> bool {
    let Some(e) = enrollment(app).cloned() else { return false };
    let _one = e.shown.one_at_a_time(bot).await;
    let mut closed = false;
    for key in e.shown.keys_of(bot) {
        closed |= close_locked(app, &e, by, &key, reason).await;
    }
    closed
}

/// `close` for one of `bot`'s screens.
async fn close_key(app: &App, by: &Who, bot: &str, key: &str, reason: &str) -> bool {
    let Some(e) = enrollment(app).cloned() else { return false };
    let _one = e.shown.one_at_a_time(bot).await;
    close_locked(app, &e, by, key, reason).await
}

/// Closes `user_id`'s own screens on the machine, when they leave it (ADR 0052). How
/// many it closed.
pub async fn close_for(app: &App, by: &Who, machine_id: &str, user_id: &str, reason: &str) -> usize {
    let Some(e) = enrollment(app) else { return 0 };
    let theirs: Vec<(String, String)> = e
        .shown
        .open()
        .iter()
        .filter(|(_, o)| o.machine_id == machine_id && o.for_user.as_deref() == Some(user_id))
        .map(|(k, o)| (o.bot_id.clone(), k.clone()))
        .collect();
    let mut closed = 0;
    for (bot, key) in theirs {
        closed += close_key(app, by, &bot, &key, reason).await as usize;
    }
    closed
}

/// `rotate` for every open machine screen, when someone loses access: a link doesn't
/// know who opened it, so they all change. Also every Bot whose first start may be
/// under way: it isn't open until that ends, and `rotate` waits for it.
pub async fn rotate_all(app: &App) {
    let Some(e) = enrollment(app) else { return };
    let mut bots: BTreeSet<String> = e.shown.open().values().map(|o| o.bot_id.clone()).collect();
    bots.extend(e.shown.busy.lock().unwrap_or_else(|e| e.into_inner()).keys().cloned());
    for bot in bots {
        rotate(app, &bot).await;
    }
}

async fn close_locked(app: &App, e: &Enrollment, by: &Who, key: &str, reason: &str) -> bool {
    let Some(o) = e.shown.open().remove(key) else { return false };
    let path = agent_path(&o.bot_id, o.for_user.as_deref(), "");
    let stopped = match app.db.machine(&o.machine_id) {
        Some(m) => e.call_agent(app, &m, reqwest::Method::DELETE, &path, &()).await.is_ok_and(|(c, _)| c == 204 || c == 404),
        None => false,
    };
    let d = json!({ "reason": reason, "openMs": now() - o.since, "machineStopped": stopped });
    app.db.record(&screen_event(by, "machine.screen_closed", &o.machine_id, &o.bot_id, o.for_user.as_deref(), d));
    true
}

/// Closes screens no one has asked for, viewed or run on lately, those whose Bot or
/// owner left that machine, and teammates' whose teammate lost the Bot. After every
/// round of heartbeats.
pub async fn reap(app: &App) {
    let Some(e) = enrollment(app).cloned() else { return };
    let Some(s) = e.screens.clone() else { return };
    let at = now();
    let due: Vec<(String, String, &'static str)> = {
        let open = e.shown.open();
        open.iter()
            .filter_map(|(key, o)| {
                let here = app.db.bot(&o.bot_id).filter(|b| b.owner_id == o.owner_id);
                let routed = app.control_plane.get().map(|cp| cp.route(app, &o.owner_id));
                let moved = here.is_none() || !matches!(routed, Some(Ok(Target::Machine(ref to))) if to.machine_id == o.machine_id);
                let lost = here.as_ref().is_some_and(|b| !still_theirs(app, b, o.for_user.as_deref()));
                let idle = at - o.used >= s.idle_ms && o.tunnels.load(Ordering::SeqCst) == 0 && !app.is_running(&o.bot_id);
                let reason = if moved {
                    "moved"
                } else if lost {
                    "access_lost"
                } else if idle {
                    "idle"
                } else {
                    return None;
                };
                Some((o.bot_id.clone(), key.clone(), reason))
            })
            .collect()
    };
    let by = Who::system("control_plane");
    for (bot, key, reason) in due {
        close_key(app, &by, &bot, &key, reason).await;
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
            .map(|(_, o)| {
                json!({
                    "botId": o.bot_id, "forUser": o.for_user, "since": o.since, "usedAt": o.used, "port": o.port.as_ref().map(|p| p.0),
                    "viewers": o.viewers.len(), "connections": o.tunnels.load(Ordering::SeqCst),
                })
            })
            .collect();
        v.sort_by(|a, b| (a["botId"].as_str(), a["forUser"].as_str()).cmp(&(b["botId"].as_str(), b["forUser"].as_str())));
        v
    };
    let agent = m.agent_upkeep.as_ref().map(|u| u["screens"].clone()).unwrap_or(Value::Null);
    Ok(Json(json!({ "machineId": m.id, "on": e.screens.is_some(), "screens": screens, "agent": agent })))
}

/// `DELETE /api/users/{key}/machine/screens/{bot}`: stops showing a Bot's screens, its
/// owner's and its teammates', and stops them on the machine.
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
    let mine = e.shown.open().values().any(|o| o.bot_id == bot && o.owner_id == u.id);
    if !mine {
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
