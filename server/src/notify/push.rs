//! Mobile push notifications (ADR 0080, #36): a pending approval reaches its deciders'
//! phones, and a finished routine reaches the phones of the person it ran for. Off until
//! an operator sets `PUSH_PROVIDER=expo`; then each person opts in per phone, in the
//! app's Settings.
//!
//! A device belongs to the session that registered it and goes when that session ends
//! (sign-out, revoke, a disabled user). Each push is checked at send time against the
//! session, the person, and their access, so nothing reaches someone who can't open it.
//! A push says only that something is waiting and for which Bot: no command, tool,
//! reason, routine name, or output. The app fetches those after it opens.

use super::{Channel, Links, Notice, NoticeKind, Offer, Plan, Sent, Throttle, clip, stored};
use crate::acl::{Access, Viewer};
use crate::audit::{Actor, Event, Outcome, Who};
use crate::db::{Bot, Db, Message as ChatMessage, PushDevice, PushKind, PushPut};
use crate::runner::App;
use crate::users::{Caller, SessionConfig};
use crate::{ApiError, AppState, Res, bad};
use axum::Json;
use axum::extract::{Extension, State};
use axum::http::StatusCode;
use futures_util::future::BoxFuture;
use serde_json::{Value, json};
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// `expo` turns push on; unset or `off` leaves it off.
pub const PROVIDER: &str = "PUSH_PROVIDER";
/// Optional: Expo's access token, for projects with enhanced push security on.
pub const EXPO_ACCESS_TOKEN: &str = "EXPO_ACCESS_TOKEN";
pub const EXPO_URL: &str = "https://exp.host/--/api/v2/push/send";
/// Expo takes at most this many messages per request.
const BATCH: usize = 100;
const TIMEOUT: Duration = Duration::from_secs(10);
/// Pushes per person per hour; past it they're dropped, and the audit log says so.
pub const PER_HOUR: usize = 30;
/// After a routine's push for a person and Bot, the next ones in this window go as one.
pub const ROUTINE_WINDOW: Duration = Duration::from_secs(600);
const HOUR: Duration = Duration::from_secs(3600);

/// One push to one device.
#[derive(Clone, PartialEq)]
pub struct Message {
    pub to: String,
    pub title: String,
    pub body: String,
    pub data: Value,
}

impl std::fmt::Debug for Message {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Message").field("title", &self.title).field("body", &self.body).field("data", &self.data).finish_non_exhaustive()
    }
}

/// What the provider did with one message.
#[derive(Clone, Debug, PartialEq)]
pub enum Ticket {
    Ok,
    /// The device is gone (the app was removed, or its token replaced): forget it.
    Gone,
    /// Never holds the token.
    Failed(String),
}

/// Where pushes go out. Expo's service today; APNs or FCM directly would be another.
pub trait Provider: Send + Sync {
    fn name(&self) -> &'static str;
    /// Whether `token` is one of this provider's device addresses.
    fn token_ok(&self, token: &str) -> bool;
    /// One ticket per message, in order.
    fn send<'a>(&'a self, msgs: &'a [Message]) -> BoxFuture<'a, Vec<Ticket>>;
}

/// `ExponentPushToken[…]` (or `ExpoPushToken[…]`), as `getExpoPushTokenAsync` returns it.
pub fn expo_token_ok(t: &str) -> bool {
    let inner = t.strip_prefix("ExponentPushToken[").or_else(|| t.strip_prefix("ExpoPushToken[")).and_then(|r| r.strip_suffix(']'));
    inner.is_some_and(|i| (1..=200).contains(&i.len()) && i.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'))
}

/// Expo's push service, which hands each message to APNs or FCM. Free; the app's build
/// carries the Apple and Google credentials (ADR 0080 lists them).
pub struct Expo {
    http: reqwest::Client,
    url: String,
}

impl Expo {
    pub fn new(url: impl Into<String>) -> Expo {
        let http = reqwest::Client::builder().timeout(TIMEOUT).redirect(reqwest::redirect::Policy::none()).build().expect("reqwest client");
        Expo { http, url: url.into() }
    }

    async fn post(&self, chunk: &[Message], access: Option<&str>) -> Result<Vec<Ticket>, String> {
        let body: Vec<Value> = chunk.iter().map(|m| json!({ "to": m.to, "title": m.title, "body": m.body, "data": m.data, "sound": "default", "priority": "high" })).collect();
        let mut req = self.http.post(&self.url).header(reqwest::header::ACCEPT, "application/json").header(reqwest::header::USER_AGENT, concat!("SuperBot/", env!("CARGO_PKG_VERSION"))).json(&body);
        if let Some(a) = access {
            req = req.bearer_auth(a);
        }
        let res = req.send().await.map_err(|e| if e.is_timeout() { "Expo didn't answer in time".to_string() } else { format!("couldn't reach Expo: {}", e.without_url()) })?;
        let status = res.status();
        let v: Value = res.json().await.unwrap_or(Value::Null);
        if !status.is_success() {
            let code = v["errors"][0]["code"].as_str().map(code_only).map(|c| format!(" ({c})")).unwrap_or_default();
            return Err(format!("Expo answered HTTP {}{code}", status.as_u16()));
        }
        let data = v["data"].as_array().cloned().unwrap_or_default();
        Ok((0..chunk.len())
            .map(|i| match data.get(i) {
                Some(t) if t["status"] == "ok" => Ticket::Ok,
                Some(t) => match t["details"]["error"].as_str() {
                    Some("DeviceNotRegistered") => Ticket::Gone,
                    Some(code) => Ticket::Failed(code_only(code)),
                    None => Ticket::Failed("Expo refused it".into()),
                },
                None => Ticket::Failed("Expo sent no ticket for it".into()),
            })
            .collect())
    }
}

/// An error code, never a message: Expo's messages quote the token.
fn code_only(code: &str) -> String {
    code.chars().filter(|c| c.is_ascii_alphanumeric() || *c == '_').take(64).collect()
}

impl Provider for Expo {
    fn name(&self) -> &'static str {
        "expo"
    }

    fn token_ok(&self, token: &str) -> bool {
        expo_token_ok(token)
    }

    fn send<'a>(&'a self, msgs: &'a [Message]) -> BoxFuture<'a, Vec<Ticket>> {
        Box::pin(async move {
            let access = stored(EXPO_ACCESS_TOKEN);
            if let Some(a) = &access {
                crate::secrets::redact::register(a.expose());
            }
            let mut out = Vec::with_capacity(msgs.len());
            for chunk in msgs.chunks(BATCH) {
                match self.post(chunk, access.as_ref().map(|a| a.expose())).await {
                    Ok(t) => out.extend(t),
                    Err(e) => out.extend(chunk.iter().map(|_| Ticket::Failed(e.clone()))),
                }
            }
            out
        })
    }
}

/// Push, once an operator turns it on: the provider, and the limits on what reaches whom.
pub struct Push {
    provider: Box<dyn Provider>,
    /// A device's session must still be live by these to get anything.
    pub sessions: SessionConfig,
    pub per_hour: usize,
    pub routine_window: Duration,
    sent: Mutex<HashMap<String, VecDeque<Instant>>>,
    routines: Mutex<Throttle>,
}

impl Push {
    pub fn new(provider: Box<dyn Provider>, sessions: SessionConfig) -> Push {
        Push { provider, sessions, per_hour: PER_HOUR, routine_window: ROUTINE_WINDOW, sent: Mutex::default(), routines: Mutex::default() }
    }

    /// `PUSH_PROVIDER`: unset or `off` (the default) leaves push off.
    pub fn from_env(var: &dyn Fn(&str) -> String, sessions: SessionConfig) -> Result<Option<Push>, String> {
        match var(PROVIDER).trim().to_ascii_lowercase().as_str() {
            "" | "off" => Ok(None),
            "expo" => Ok(Some(Push::new(Box::new(Expo::new(EXPO_URL)), sessions))),
            other => Err(format!("{PROVIDER} must be expo or off, not \"{other}\"")),
        }
    }

    pub fn provider(&self) -> &'static str {
        self.provider.name()
    }

    pub fn token_ok(&self, token: &str) -> bool {
        self.provider.token_ok(token)
    }

    /// The live devices of `users` that want `kind`, from this provider.
    pub fn devices(&self, db: &Db, users: &[String], kind: PushKind) -> Vec<PushDevice> {
        let at = crate::db::now();
        let mut seen: Vec<&String> = Vec::new();
        let mut out = Vec::new();
        for u in users {
            if seen.contains(&u) {
                continue;
            }
            seen.push(u);
            out.extend(db.live_push_devices(u, kind, at, self.sessions.idle_ms, self.sessions.max_ms).into_iter().filter(|d| d.provider == self.provider()));
        }
        out
    }

    /// Takes one push from `user`'s hourly allowance. False: it's used up.
    fn allow(&self, user: &str, now: Instant) -> bool {
        let mut sent = self.sent.lock().unwrap_or_else(|e| e.into_inner());
        sent.retain(|_, q| q.back().is_some_and(|t| now.duration_since(*t) < HOUR));
        let q = sent.entry(user.to_string()).or_default();
        while q.front().is_some_and(|t| now.duration_since(*t) >= HOUR) {
            q.pop_front();
        }
        if q.len() >= self.per_hour {
            return false;
        }
        q.push_back(now);
        true
    }

    /// One push to each device, past each person's hourly limit. Devices the provider
    /// says are gone come back in `Sent::gone`, to forget.
    pub async fn send(&self, devices: &[PushDevice], title: &str, body: &str, data: &Value) -> Sent {
        let now = Instant::now();
        let mut users: Vec<&str> = Vec::new();
        let mut limited: Vec<&str> = Vec::new();
        for d in devices {
            if !users.contains(&d.user_id.as_str()) && !limited.contains(&d.user_id.as_str()) {
                if self.allow(&d.user_id, now) { users.push(&d.user_id) } else { limited.push(&d.user_id) }
            }
        }
        let to: Vec<&PushDevice> = devices.iter().filter(|d| users.contains(&d.user_id.as_str())).collect();
        let msgs: Vec<Message> = to.iter().map(|d| Message { to: d.token.clone(), title: title.into(), body: body.into(), data: data.clone() }).collect();
        let tickets = if msgs.is_empty() { Vec::new() } else { self.provider.send(&msgs).await };
        let mut s = Sent::default();
        for (d, t) in to.iter().zip(tickets.iter().chain(std::iter::repeat(&Ticket::Failed("no ticket".into())))) {
            match t {
                Ticket::Ok => s.delivered += 1,
                Ticket::Gone => s.gone.push(Gone { device: d.id.clone(), user: d.user_id.clone(), token_hash: crate::users::hash(&d.token) }),
                Ticket::Failed(e) => {
                    s.failed += 1;
                    s.error.get_or_insert_with(|| e.clone());
                }
            }
        }
        let mut detail = json!({ "provider": self.provider(), "users": users, "devices": to.len() });
        if !limited.is_empty() {
            detail["limited"] = json!(limited);
        }
        if !s.gone.is_empty() {
            detail["removed"] = json!(s.gone.len());
        }
        s.detail = detail;
        s
    }
}

/// A device the provider said is gone, and the token it said that about.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Gone {
    pub device: String,
    pub user: String,
    pub token_hash: String,
}

/// Forgets devices the provider says are gone, each audited. A device whose token was
/// replaced while the answer was on its way keeps the new one.
pub fn forget_gone(db: &Db, gone: &[Gone]) {
    for g in gone {
        if db.delete_push_device_with(&g.device, &g.token_hash) {
            let e = Event::new(Actor::system("notifications"), "push.unregistered").target("push_device", &g.device);
            db.record(&e.details(json!({ "userId": g.user, "reason": "provider_gone" })));
        }
    }
}

/// What a push about a notice says. Nothing a Bot asked to run, whatever the detail
/// setting: phones show it on the lock screen.
pub fn approval_message(n: &Notice) -> Option<(String, String, Value)> {
    let first = n.items.first().map(|i| i.approval_id.as_str());
    let link = |id: Option<&str>| id.map_or_else(|| "/home".to_string(), |id| format!("/home?approval={id}"));
    Some(match n.kind {
        NoticeKind::Approval => {
            ("Approval needed".into(), format!("{} is waiting for your approval.", n.bot_name), json!({ "type": "approval", "botId": n.bot_id, "approvalId": first, "url": link(first) }))
        }
        NoticeKind::Digest => (
            "Approvals waiting".into(),
            format!("{} approvals are waiting for {}.", n.items.len() + n.more, n.bot_name),
            json!({ "type": "approval", "botId": n.bot_id, "approvalId": first, "url": link(first) }),
        ),
        NoticeKind::Test => (
            "SuperBot".into(),
            format!("This is a test. Approvals for {} will reach this phone.", if n.bot_name.is_empty() { "your Bots" } else { &n.bot_name }),
            json!({ "type": "test", "url": "/home" }),
        ),
        NoticeKind::Alert => return None,
    })
}

/// Approvals as a notification channel: to the devices `Notifier::plan` found.
pub struct PushChannel(pub Arc<Push>);

impl Channel for PushChannel {
    fn name(&self) -> &'static str {
        "push"
    }

    fn send<'a>(&'a self, n: &'a Notice, plan: &'a Plan, _links: &'a Links) -> BoxFuture<'a, Option<Result<Sent, String>>> {
        Box::pin(async move {
            if plan.push.is_empty() {
                return None;
            }
            let (title, body, data) = approval_message(n)?;
            Some(Ok(self.0.send(&plan.push, &title, &body, &data).await))
        })
    }
}

/// The person a routine's run is for: its author, else its Bot's owner (ADR 0046).
fn routine_person(bot: &Bot, msg: &ChatMessage) -> String {
    msg.requested_by.as_ref().and_then(|w| w.actor.asker.clone()).unwrap_or_else(|| bot.owner_id.clone())
}

/// A routine's run is over: its person's phones hear of it, once now and then at most
/// once per window for the same Bot, folding the rest into one. Returns at once.
pub fn routine_done(app: &Arc<App>, bot: &Bot, msg: &ChatMessage) {
    let Some(push) = app.notifier.get().and_then(|n| n.push.clone()) else {
        return;
    };
    let person = routine_person(bot, msg);
    if push.devices(&app.db, std::slice::from_ref(&person), PushKind::Routines).is_empty() {
        return;
    }
    let key = format!("{person}\n{}", bot.id);
    let now = Instant::now();
    let window = push.routine_window;
    let offer = push.routines.lock().unwrap_or_else(|e| e.into_inner()).offer(&key, &msg.id.to_string(), window, now + window, now);
    let (app, bot_id) = (app.clone(), bot.id.clone());
    match offer {
        Offer::Now => {
            tokio::spawn(async move { send_routines(&app, &push, &bot_id, &person, 1).await });
        }
        Offer::Held(Some(wait)) => {
            tokio::spawn(async move {
                tokio::time::sleep(wait).await;
                let n = push.routines.lock().unwrap_or_else(|e| e.into_inner()).take(&key, Instant::now()).len();
                if n > 0 {
                    send_routines(&app, &push, &bot_id, &person, n).await;
                }
            });
        }
        Offer::Held(None) | Offer::Duplicate => {}
    }
}

async fn send_routines(app: &App, push: &Push, bot_id: &str, person: &str, count: usize) {
    let Some(bot) = app.db.bot(bot_id) else {
        return;
    };
    // Access may have changed since the routine ran.
    if Viewer::person(&app.db, person).access(&app.db, &bot) < Access::View {
        return;
    }
    let devices = push.devices(&app.db, &[person.to_string()], PushKind::Routines);
    if devices.is_empty() {
        return;
    }
    let name = clip(&bot.name);
    let body = if count == 1 { format!("{name} finished a scheduled routine.") } else { format!("{name} finished {count} scheduled routines.") };
    let data = json!({ "type": "routine", "botId": bot.id, "url": format!("/home?bot={}", bot.id) });
    let s = push.send(&devices, "Routine finished", &body, &data).await;
    forget_gone(&app.db, &s.gone);
    let ok = s.failed == 0;
    let mut d = s.detail;
    d["channel"] = json!("push");
    d["kind"] = json!("routine");
    d["routines"] = json!(count);
    d["delivered"] = json!(s.delivered);
    if !ok {
        d["failed"] = json!(s.failed);
        d["error"] = json!(s.error.map(|e| crate::secrets::redact::text(&e).into_owned()));
        crate::obs::log::log_warn!("Notification by push failed: {}", d["error"].as_str().unwrap_or("see the audit log"));
    }
    let e = Event::new(Actor::system("notifications"), if ok { "notification.sent" } else { "notification.failed" })
        .outcome(if ok { Outcome::Success } else { Outcome::Failure })
        .target("bot", &bot.id)
        .bot(&bot.id);
    app.db.record(&e.details(d));
}

// The app's own device, for the session it signs in with: `/api/me/push`.

fn view(push: Option<&Push>, d: Option<&PushDevice>) -> Value {
    json!({
        "available": push.is_some(),
        "provider": push.map(|p| p.provider()),
        "device": d.map(|d| json!({
            "id": d.id,
            "platform": d.platform,
            "approvals": d.approvals,
            "routines": d.routines,
            "createdAt": d.created_at,
            "updatedAt": d.updated_at,
        })),
    })
}

/// The person and the session a device would belong to. Bots and callers without a
/// session (the shared password, loopback dev) have neither.
fn signed_in(c: &Caller) -> Res<(&crate::db::User, &crate::db::Session)> {
    if c.principal == crate::rbac::Principal::Bot {
        return Err(ApiError(StatusCode::FORBIDDEN, "Bots don't get push notifications".into()));
    }
    match (&c.user, &c.session) {
        (Some(u), Some(s)) => Ok((u, s)),
        _ => Err(ApiError(StatusCode::CONFLICT, "Push notifications need a signed-in session. Sign in with a sign-in code or SSO.".into())),
    }
}

fn push_of(app: &App) -> Option<Arc<Push>> {
    app.notifier.get().and_then(|n| n.push.clone())
}

/// `GET /api/me/push`: whether the server sends push, and this session's device.
pub async fn get_mine(State(app): State<AppState>, Extension(c): Extension<Caller>) -> Res {
    let (_, s) = signed_in(&c)?;
    let push = push_of(&app);
    Ok(Json(view(push.as_deref(), app.db.session_push_device(&s.id).as_ref())))
}

fn flag(v: &Value, name: &str, or: bool) -> Res<bool> {
    match v.get(name) {
        None | Some(Value::Null) => Ok(or),
        Some(Value::Bool(b)) => Ok(*b),
        Some(_) => Err(bad(format!("{name} must be true or false"))),
    }
}

/// `PUT /api/me/push` `{token, platform: "ios"|"android", approvals?, routines?}`:
/// this session's device, in place of any it had.
pub async fn put_mine(State(app): State<AppState>, Extension(c): Extension<Caller>, Extension(by): Extension<Who>, Json(v): Json<Value>) -> Res {
    let (u, s) = signed_in(&c)?;
    let Some(push) = push_of(&app) else {
        return Err(ApiError(StatusCode::CONFLICT, format!("Push notifications are off on this server. An admin can turn them on with {PROVIDER}=expo.")));
    };
    let token = v["token"].as_str().map(str::trim).filter(|t| push.token_ok(t)).ok_or_else(|| bad("token must be an Expo push token"))?;
    let platform = match v["platform"].as_str() {
        Some(p @ ("ios" | "android")) => p,
        _ => return Err(bad("platform must be ios or android")),
    };
    let had = app.db.session_push_device(&s.id);
    let approvals = flag(&v, "approvals", had.as_ref().is_none_or(|d| d.approvals))?;
    let routines = flag(&v, "routines", had.as_ref().is_none_or(|d| d.routines))?;
    let (d, change) = app.db.put_push_device(&u.id, &s.id, push.provider(), token, platform, approvals, routines);
    let details = json!({ "provider": d.provider, "platform": d.platform, "approvals": d.approvals, "routines": d.routines });
    match change {
        PushPut::Added | PushPut::Moved => {
            let mut details = details;
            details["moved"] = json!(change == PushPut::Moved);
            app.db.record(&by.event("push.registered").target("push_device", &d.id).details(details));
        }
        PushPut::Updated => app.db.record(&by.event("push.updated").target("push_device", &d.id).details(details)),
        PushPut::Unchanged => {}
    }
    Ok(Json(view(Some(&push), Some(&d))))
}

/// `DELETE /api/me/push`: this session's device stops getting pushes.
pub async fn delete_mine(State(app): State<AppState>, Extension(c): Extension<Caller>, Extension(by): Extension<Who>) -> Res {
    let (_, s) = signed_in(&c)?;
    if let Some(d) = app.db.delete_session_push_device(&s.id) {
        app.db.record(&by.event("push.unregistered").target("push_device", &d.id).details(json!({ "platform": d.platform, "reason": "user" })));
    }
    Ok(Json(view(push_of(&app).as_deref(), None)))
}

#[cfg(test)]
pub mod fake {
    //! A provider for tests: keeps what it was asked to send, and answers `Gone` for
    //! the tokens in `gone`.
    use super::*;

    #[derive(Clone, Default)]
    pub struct Recorder {
        pub sent: Arc<Mutex<Vec<Message>>>,
        pub gone: Arc<Mutex<Vec<String>>>,
    }

    impl Recorder {
        pub fn to(&self, token: &str) -> Vec<Message> {
            self.sent.lock().unwrap().iter().filter(|m| m.to == token).cloned().collect()
        }
    }

    impl Provider for Recorder {
        fn name(&self) -> &'static str {
            "expo"
        }

        fn token_ok(&self, token: &str) -> bool {
            expo_token_ok(token)
        }

        fn send<'a>(&'a self, msgs: &'a [Message]) -> BoxFuture<'a, Vec<Ticket>> {
            Box::pin(async move {
                self.sent.lock().unwrap().extend(msgs.iter().cloned());
                let gone = self.gone.lock().unwrap();
                msgs.iter().map(|m| if gone.contains(&m.to) { Ticket::Gone } else { Ticket::Ok }).collect()
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::routing::post;

    #[test]
    fn expo_tokens_are_recognised() {
        assert!(expo_token_ok("ExponentPushToken[xxxxxxxxxxxxxxxxxxxxxx]"));
        assert!(expo_token_ok("ExpoPushToken[a-b_C9]"));
        for bad in ["", "ExponentPushToken[]", "ExponentPushToken[a b]", "ExponentPushToken[x", "https://example.com/x", "ExponentPushToken[x]\n"] {
            assert!(!expo_token_ok(bad), "{bad:?}");
        }
    }

    #[test]
    fn off_unless_an_operator_names_a_provider() {
        let env = |v: &'static str| {
            move |k: &str| {
                if k == PROVIDER { v.to_string() } else { String::new() }
            }
        };
        assert!(Push::from_env(&env(""), SessionConfig::default()).unwrap().is_none());
        assert!(Push::from_env(&env("off"), SessionConfig::default()).unwrap().is_none());
        assert_eq!(Push::from_env(&env(" Expo "), SessionConfig::default()).unwrap().unwrap().provider(), "expo");
        assert!(Push::from_env(&env("apns"), SessionConfig::default()).is_err());
    }

    #[test]
    fn each_person_gets_at_most_the_hourly_limit() {
        let mut p = Push::new(Box::new(fake::Recorder::default()), SessionConfig::default());
        p.per_hour = 2;
        let t0 = Instant::now();
        assert!(p.allow("a", t0) && p.allow("a", t0));
        assert!(!p.allow("a", t0), "the third in the hour is dropped");
        assert!(p.allow("b", t0), "per person");
        assert!(p.allow("a", t0 + HOUR), "the hour moves on");
    }

    #[test]
    fn pushes_never_carry_what_a_bot_asked_to_run() {
        let n = Notice {
            kind: NoticeKind::Approval,
            bot_id: "b1".into(),
            bot_name: "Ops".into(),
            items: vec![super::super::Item {
                approval_id: "a1".into(),
                tool: "Bash".into(),
                class: "git_push".into(),
                class_label: "Pushes to a git remote".into(),
                reason: Some("Pushes to a git remote".into()),
                subject: Some("git push origin main".into()),
                expires_at: 0,
                link: None,
                console_link: None,
            }],
            more: 0,
            alert: None,
        };
        let (title, body, data) = approval_message(&n).unwrap();
        let all = format!("{title} {body} {data}");
        assert_eq!((title.as_str(), body.as_str()), ("Approval needed", "Ops is waiting for your approval."));
        assert_eq!((data["url"].as_str(), data["approvalId"].as_str()), (Some("/home?approval=a1"), Some("a1")));
        for secret in ["git push", "Bash", "Pushes to"] {
            assert!(!all.contains(secret), "{all}");
        }
        assert!(approval_message(&Notice { kind: NoticeKind::Alert, ..n }).is_none(), "alerts are for admins' email and webhook");
    }

    /// Expo's API on loopback: answers with `tickets`, keeps each request.
    async fn fake_expo(status: u16, answer: Value) -> (String, Arc<Mutex<Vec<(axum::http::HeaderMap, Value)>>>) {
        type S = (Arc<Mutex<Vec<(axum::http::HeaderMap, Value)>>>, Value, u16);
        let got: Arc<Mutex<Vec<(axum::http::HeaderMap, Value)>>> = Arc::default();
        let app = axum::Router::new().route(
            "/push/send",
            post(|State((got, answer, status)): State<S>, headers: axum::http::HeaderMap, Json(body): Json<Value>| async move {
                got.lock().unwrap().push((headers, body));
                (StatusCode::from_u16(status).unwrap(), Json(answer))
            }),
        );
        let l = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let url = format!("http://127.0.0.1:{}/push/send", l.local_addr().unwrap().port());
        tokio::spawn(axum::serve(l, app.with_state((got.clone(), answer, status))).into_future());
        (url, got)
    }

    fn msg(to: &str) -> Message {
        Message { to: to.into(), title: "Approval needed".into(), body: "Ops is waiting for your approval.".into(), data: json!({ "url": "/home?approval=a1" }) }
    }

    #[tokio::test]
    async fn expo_gets_titles_and_links_and_says_which_devices_are_gone() {
        let tickets = json!({ "data": [
            { "status": "ok", "id": "t1" },
            { "status": "error", "message": "\"ExponentPushToken[gone1]\" is not a registered push notification recipient", "details": { "error": "DeviceNotRegistered" } },
            { "status": "error", "message": "\"ExponentPushToken[big1]\" message too big", "details": { "error": "MessageTooBig" } },
        ] });
        let (url, got) = fake_expo(200, tickets).await;
        let out = Expo::new(url).send(&[msg("ExponentPushToken[ok1]"), msg("ExponentPushToken[gone1]"), msg("ExponentPushToken[big1]")]).await;
        assert_eq!(out, vec![Ticket::Ok, Ticket::Gone, Ticket::Failed("MessageTooBig".into())], "codes, never the message that quotes the token");
        let (headers, body) = got.lock().unwrap()[0].clone();
        assert_eq!(body.as_array().unwrap().len(), 3);
        assert_eq!((body[0]["to"].as_str(), body[0]["title"].as_str(), body[0]["data"]["url"].as_str()), (Some("ExponentPushToken[ok1]"), Some("Approval needed"), Some("/home?approval=a1")));
        assert!(headers.get("authorization").is_none(), "no access token set");
    }

    #[tokio::test]
    async fn a_refused_request_fails_every_message_without_quoting_tokens() {
        let (url, _) = fake_expo(400, json!({ "errors": [{ "code": "PUSH_TOO_MANY_EXPERIENCE_IDS", "message": "ExponentPushToken[x1] and ExponentPushToken[x2] are for different projects" }] })).await;
        let out = Expo::new(url).send(&[msg("ExponentPushToken[x1]"), msg("ExponentPushToken[x2]")]).await;
        assert_eq!(out.len(), 2);
        for t in out {
            let Ticket::Failed(e) = t else { panic!("{t:?}") };
            assert_eq!(e, "Expo answered HTTP 400 (PUSH_TOO_MANY_EXPERIENCE_IDS)");
        }
        let gone = Expo::new("http://127.0.0.1:1/push/send").send(&[msg("ExponentPushToken[x1]")]).await;
        assert!(matches!(&gone[0], Ticket::Failed(e) if !e.contains("x1")), "{gone:?}");
    }

    #[tokio::test]
    async fn requests_go_in_batches_of_a_hundred() {
        let (url, got) = fake_expo(200, json!({ "data": [] })).await;
        let msgs: Vec<Message> = (0..150).map(|i| msg(&format!("ExponentPushToken[t{i}]"))).collect();
        let out = Expo::new(url).send(&msgs).await;
        assert_eq!(out.len(), 150);
        let sizes: Vec<usize> = got.lock().unwrap().iter().map(|(_, b)| b.as_array().unwrap().len()).collect();
        assert_eq!(sizes, [100, 50]);
    }
}
