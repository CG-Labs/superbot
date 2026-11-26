//! Approval notifications (ADR 0061): a pending approval reaches the people who can
//! answer it when no app is open. Email through the admin's SMTP server, and an outgoing
//! webhook (Slack-compatible or SuperBot JSON), set globally and per Bot. Off until an
//! admin turns a channel on; nothing here needs a paid service.
//!
//! Each notice links to the approval in the client (`/app/home?approval=<id>`) and to its
//! audit trail in the console. It shows no more than the approval card does (the Bot, the
//! tool, the risky class, the reason, and the command cut short), and with `detail:
//! minimal` less. Each approval is sent once; a Bot that asks again within the throttle
//! window has the rest folded into one digest at its end. Every send and failure is an
//! audit event.
//!
//! Channels share one shape (`Channel`): mobile push (ADR 0080, #36) is another one,
//! reaching the devices of the same `Plan::deciders`.

pub mod api;
pub mod push;
pub mod smtp;
pub mod webhook;

use crate::acl::{Access, Grant, Viewer};
use crate::audit::{Actor, Event, Outcome};
use crate::db::{Approval, Bot, Db, PushDevice, PushKind, User};
use crate::rbac::{self, Perm, Principal};
use crate::runner::App;
use crate::secrets;
use futures_util::future::BoxFuture;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use webhook::Format;

const SETTINGS_KEY: &str = "notifications";
pub const MAX_RECIPIENTS: usize = 20;
pub const MAX_DELAY_SECONDS: u32 = 600;
pub const MAX_THROTTLE_SECONDS: u32 = 3600;
pub const DEFAULT_DELAY_SECONDS: u32 = 30;
pub const DEFAULT_THROTTLE_SECONDS: u32 = 120;
/// Approvals listed in one digest; the rest are counted.
const MAX_ITEMS: usize = 10;
/// The command as a notice shows it, at most.
const SUBJECT_CHARS: usize = 200;
/// Approval ids remembered as sent, so none goes twice.
const SEEN: usize = 10_000;

/// How much of each approval a notice shows.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Detail {
    /// The approval card's fields, with the command cut short.
    #[default]
    Summary,
    /// The Bot, the risky class, and the link: nothing it asked to run.
    Minimal,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct EmailSettings {
    pub enabled: bool,
    /// Addresses that get every notice.
    pub to: Vec<String>,
    /// Also the Bot's owner and the people it grants operator to, who can approve.
    pub deciders: bool,
}

impl Default for EmailSettings {
    fn default() -> Self {
        EmailSettings { enabled: false, to: Vec::new(), deciders: true }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct WebhookSettings {
    pub enabled: bool,
    pub format: Format,
}

/// One Bot's changes on top of the global settings. Unset fields follow them.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct BotSettings {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<bool>,
    /// Unset: on when the Bot has its own webhook URL, else the global switch.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub webhook: Option<bool>,
    /// The format for its own webhook URL.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub format: Option<Format>,
}

impl BotSettings {
    pub fn is_empty(&self) -> bool {
        self == &BotSettings::default()
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Settings {
    pub email: EmailSettings,
    pub webhook: WebhookSettings,
    /// Wait this long before sending; an approval answered by then sends nothing.
    pub delay_seconds: u32,
    /// After a notice for a Bot, its next approvals wait this long and go as one digest.
    pub throttle_seconds: u32,
    pub detail: Detail,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub bots: BTreeMap<String, BotSettings>,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            email: EmailSettings::default(),
            webhook: WebhookSettings::default(),
            delay_seconds: DEFAULT_DELAY_SECONDS,
            throttle_seconds: DEFAULT_THROTTLE_SECONDS,
            detail: Detail::Summary,
            bots: BTreeMap::new(),
        }
    }
}

impl Settings {
    /// Everything but the Bots' own settings, for the audit log and the global view.
    pub fn global(&self) -> Settings {
        Settings { bots: BTreeMap::new(), ..self.clone() }
    }
}

/// The saved settings. Unreadable ones count as the default: everything off.
pub fn load(db: &Db) -> Settings {
    db.setting(SETTINGS_KEY).and_then(|v| serde_json::from_str(&v).ok()).unwrap_or_default()
}

pub fn save(db: &Db, s: &Settings) {
    db.set_setting(SETTINGS_KEY, &serde_json::to_string(s).unwrap());
}

fn stored(name: &str) -> Option<secrets::Secret> {
    secrets::global().get(name).ok().flatten()
}

/// For sending: a secret that can't be read (an external store down, ADR 0125) refuses
/// the send rather than counting as unset, so nothing goes out unsigned or unauthenticated.
pub(crate) fn needed(name: &str) -> Result<Option<secrets::Secret>, String> {
    needed_from(secrets::global(), name)
}

fn needed_from(s: &secrets::Secrets, name: &str) -> Result<Option<secrets::Secret>, String> {
    s.get(name).map_err(|e| format!("{name} couldn't be read from the secret store ({})", e.kind()))
}

pub fn secret_set(name: &str) -> bool {
    stored(name).is_some()
}

/// `{email?: {enabled?, to?, deciders?}, webhook?: {enabled?, format?}, delaySeconds?,
/// throttleSeconds?, detail?}`. The webhook's URL is a secret and is handled apart.
pub fn apply_patch(s: &Settings, v: &Value) -> Result<Settings, String> {
    let mut out = s.clone();
    if !v.is_object() {
        return Err("Send a JSON object".into());
    }
    let flag = |v: &Value, name: &str| v.as_bool().ok_or(format!("{name} must be true or false"));
    if let Some(e) = v.get("email").filter(|e| !e.is_null()) {
        if let Some(b) = e.get("enabled").filter(|b| !b.is_null()) {
            out.email.enabled = flag(b, "email.enabled")?;
        }
        if let Some(b) = e.get("deciders").filter(|b| !b.is_null()) {
            out.email.deciders = flag(b, "email.deciders")?;
        }
        if let Some(to) = e.get("to").filter(|t| !t.is_null()) {
            out.email.to = recipients(to)?;
        }
    }
    if let Some(w) = v.get("webhook").filter(|w| !w.is_null()) {
        if let Some(b) = w.get("enabled").filter(|b| !b.is_null()) {
            out.webhook.enabled = flag(b, "webhook.enabled")?;
        }
        if let Some(f) = w.get("format").filter(|f| !f.is_null()) {
            out.webhook.format = f.as_str().and_then(Format::parse).ok_or("webhook.format must be \"slack\" or \"json\"")?;
        }
    }
    let seconds = |name: &str, max: u32| -> Result<Option<u32>, String> {
        match v.get(name).filter(|n| !n.is_null()) {
            None => Ok(None),
            Some(n) => n.as_u64().filter(|n| *n <= max as u64).map(|n| Some(n as u32)).ok_or(format!("{name} must be 0 to {max}")),
        }
    };
    if let Some(d) = seconds("delaySeconds", MAX_DELAY_SECONDS)? {
        out.delay_seconds = d;
    }
    if let Some(t) = seconds("throttleSeconds", MAX_THROTTLE_SECONDS)? {
        out.throttle_seconds = t;
    }
    if let Some(d) = v.get("detail").filter(|d| !d.is_null()) {
        out.detail = match d.as_str() {
            Some("summary") => Detail::Summary,
            Some("minimal") => Detail::Minimal,
            _ => return Err("detail must be \"summary\" or \"minimal\"".into()),
        };
    }
    Ok(out)
}

/// A list of addresses, or one string of them split by commas, spaces, or new lines.
pub fn recipients(v: &Value) -> Result<Vec<String>, String> {
    let raw: Vec<String> = match v {
        Value::String(s) => s.split([',', ';', ' ', '\n', '\t']).map(String::from).collect(),
        Value::Array(a) => a.iter().map(|x| x.as_str().map(String::from).ok_or("email.to must be a list of addresses")).collect::<Result<_, _>>()?,
        _ => return Err("email.to must be a list of addresses".into()),
    };
    let mut out: Vec<String> = Vec::new();
    for a in raw.iter().map(|a| a.trim()).filter(|a| !a.is_empty()) {
        if !smtp::address_ok(a) {
            return Err(format!("\"{a}\" isn't an email address"));
        }
        if !out.iter().any(|o| o.eq_ignore_ascii_case(a)) {
            out.push(a.to_string());
        }
    }
    if out.len() > MAX_RECIPIENTS {
        return Err(format!("At most {MAX_RECIPIENTS} addresses"));
    }
    Ok(out)
}

/// A Bot's patch: `{email?, webhook?: true|false|null, format?: "slack"|"json"|null}`,
/// `null` following the global settings again.
pub fn apply_bot_patch(o: &BotSettings, v: &Value) -> Result<BotSettings, String> {
    let mut out = o.clone();
    if !v.is_object() {
        return Err("Send a JSON object".into());
    }
    for (name, field) in [("email", &mut out.email), ("webhook", &mut out.webhook)] {
        match v.get(name) {
            None => {}
            Some(Value::Null) => *field = None,
            Some(Value::Bool(b)) => *field = Some(*b),
            Some(_) => return Err(format!("{name} must be true, false, or null")),
        }
    }
    match v.get("format") {
        None => {}
        Some(Value::Null) => out.format = None,
        Some(f) => out.format = Some(f.as_str().and_then(Format::parse).ok_or("format must be \"slack\", \"json\", or null")?),
    }
    Ok(out)
}

/// The people who can answer a Bot's approvals: its owner and those it grants operator,
/// while active, allowed to approve, and still able to operate it. Admins aren't added
/// for every Bot; list them in `email.to`. Never a service account granted operator: only
/// a person decides an approval (ADR 0143, 0170).
pub fn deciders(db: &Db, bot: &Bot) -> Vec<User> {
    let mut ids = vec![bot.owner_id.clone()];
    for g in db.grants(&bot.id).into_iter().filter(|g| g.level == Grant::Operator) {
        if !ids.contains(&g.user_id) {
            ids.push(g.user_id);
        }
    }
    ids.into_iter()
        .filter_map(|id| db.user(&id))
        .filter(|u| !u.service && u.active() && rbac::allows(Principal::User(u.role), Perm::Approve) && Viewer::person(db, &u.id).access(db, bot) >= Access::Operate)
        .collect()
}

/// Where one notice goes, worked out for one Bot (or for no Bot: a test of the global settings).
#[derive(Clone, Debug, Default)]
pub struct Plan {
    /// Who can answer. Email reaches them when `email.deciders` is on; push reaches
    /// their phones that opted in.
    pub deciders: Vec<User>,
    pub email: Vec<String>,
    /// The secret holding the URL, and the format.
    pub webhook: Option<(String, Format)>,
    /// The deciders' live devices that want approvals (ADR 0080).
    pub push: Vec<PushDevice>,
}

impl Plan {
    pub fn is_empty(&self) -> bool {
        self.email.is_empty() && self.webhook.is_none() && self.push.is_empty()
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Item {
    pub approval_id: String,
    pub tool: String,
    pub class: String,
    pub class_label: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// The command, path, or address, redacted and cut short. None with `detail: minimal`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    pub expires_at: i64,
    pub link: Option<String>,
    pub console_link: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NoticeKind {
    Approval,
    Digest,
    Test,
    /// About the server, not an approval (ADR 0074): `Notice::alert`.
    Alert,
}

impl NoticeKind {
    fn as_str(self) -> &'static str {
        match self {
            NoticeKind::Approval => "approval",
            NoticeKind::Digest => "digest",
            NoticeKind::Test => "test",
            NoticeKind::Alert => "alert",
        }
    }
}

/// Something admins need to act on, such as a machine past its RPO (ADR 0074). It goes
/// to the global email list and webhook, never to a Bot's deciders or own webhook; and to
/// its `audience`, when it has one.
#[derive(Clone, Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Alert {
    /// The audit action it reports, e.g. `machine.rpo_breached`.
    pub event: String,
    pub title: String,
    pub lines: Vec<String>,
    pub target_type: String,
    pub target_id: String,
    /// The console page it's about; the notifier fills it in from PUBLIC_URL.
    pub link: Option<String>,
    /// The app page its audience acts on it in; the notifier fills it in from PUBLIC_URL.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app_link: Option<String>,
    #[serde(skip)]
    pub audience: Option<Audience>,
}

/// People who can act on an alert themselves, beside the global list and webhook (ADR
/// 0302): email reaches them while email and `email.deciders` are on, and push their phones
/// that want approvals.
#[derive(Clone, Debug, Default)]
pub struct Audience {
    pub people: Vec<User>,
    /// Who they are, for the notice's link: "the team's owners and admins".
    pub who: String,
    /// The app page they act on it in: `team`.
    pub page: &'static str,
    /// What their phones show, which a lock screen may too: no names, no reasons.
    pub push_title: String,
    pub push_body: String,
    /// The push's `type`, which the app opens `page` for.
    pub push_type: &'static str,
}

#[derive(Clone, Debug)]
pub struct Notice {
    pub kind: NoticeKind,
    pub bot_id: String,
    pub bot_name: String,
    pub items: Vec<Item>,
    /// Approvals left out of a long digest.
    pub more: usize,
    pub alert: Option<Alert>,
}

/// `14:32 UTC`.
pub fn clock(ms: i64) -> String {
    chrono::DateTime::from_timestamp_millis(ms).map(|t| t.format("%H:%M UTC").to_string()).unwrap_or_default()
}

fn clip(s: &str) -> String {
    let one_line: String = s.split_whitespace().collect::<Vec<_>>().join(" ");
    if one_line.chars().count() <= SUBJECT_CHARS {
        return one_line;
    }
    let cut: String = one_line.chars().take(SUBJECT_CHARS - 1).collect();
    format!("{cut}…")
}

impl Notice {
    pub fn summary(&self) -> String {
        match self.kind {
            NoticeKind::Approval => format!("{} is waiting for approval to run {}", self.bot_name, self.items.first().map_or("a tool", |i| i.tool.as_str())),
            NoticeKind::Digest => format!("{} approvals are waiting for {}", self.items.len() + self.more, self.bot_name),
            NoticeKind::Test if self.bot_id.is_empty() => "Test notification from SuperBot".into(),
            NoticeKind::Test => format!("Test notification from SuperBot for {}", self.bot_name),
            NoticeKind::Alert => self.alert.as_ref().map_or_else(|| "SuperBot alert".into(), |a| clip(&a.title)),
        }
    }

    pub fn email_subject(&self) -> String {
        format!("[SuperBot] {}", self.summary())
    }

    pub fn email_body(&self, app_link: Option<&str>) -> String {
        let now = crate::db::now();
        let mut out = String::new();
        if let (NoticeKind::Alert, Some(a)) = (self.kind, &self.alert) {
            out.push_str(&format!("{}\n\n", clip(&a.title)));
            for l in &a.lines {
                out.push_str(&format!("  {}\n", clip(l)));
            }
            if let (Some(l), Some(who)) = (&a.app_link, a.audience.as_ref().map(|w| &w.who)) {
                out.push_str(&format!("\n  Open it in SuperBot ({who}): {l}"));
            }
            if let Some(l) = &a.link {
                out.push_str(&format!("\n  Console (admins): {l}\n"));
            }
            out.push_str("\n--\nSuperBot sends alerts like this to the notification email list and webhook set in the console's Settings");
            match &a.audience {
                Some(w) => out.push_str(&format!(", and to {} when email also goes to the people who can answer.\n", w.who)),
                None => out.push_str(".\n"),
            }
            return out;
        }
        match self.kind {
            NoticeKind::Alert => {}
            NoticeKind::Test => {
                out.push_str("This is a test. Notifications about approvals will reach you here.\n");
                if let Some(l) = app_link {
                    out.push_str(&format!("\nOpen SuperBot: {l}\n"));
                }
            }
            NoticeKind::Approval => out.push_str(&format!("{} is waiting for your approval.\n", self.bot_name)),
            NoticeKind::Digest => out.push_str(&format!("{} approvals are waiting for {}.\n", self.items.len() + self.more, self.bot_name)),
        }
        for i in &self.items {
            out.push_str(&format!("\n  {}\n  Tool: {}\n", i.class_label, i.tool));
            if let Some(r) = i.reason.as_deref().filter(|r| *r != i.class_label) {
                out.push_str(&format!("  Why it asks: {r}\n"));
            }
            if let Some(s) = &i.subject {
                out.push_str(&format!("  {s}\n"));
            }
            let mins = ((i.expires_at - now).max(0) as f64 / 60_000.0).ceil() as i64;
            out.push_str(&format!("\n  Denied at {} (in {} minute{}) unless someone answers.\n", clock(i.expires_at), mins, if mins == 1 { "" } else { "s" }));
            if let Some(l) = &i.link {
                out.push_str(&format!("  Open it in SuperBot: {l}\n"));
            }
            if let Some(l) = &i.console_link {
                out.push_str(&format!("  Audit log (admins): {l}\n"));
            }
        }
        if self.more > 0 {
            out.push_str(&format!("\n…and {} more.\n", self.more));
        }
        out.push_str("\n--\nSuperBot sends this when a Bot waits for approval. Admins choose who gets it in the app's approval policy or the console's Settings.\n");
        out
    }
}

/// The client's and console's addresses, from PUBLIC_URL (as billing finds it).
#[derive(Clone, Debug, Default)]
pub struct Links {
    pub base: Option<String>,
}

impl Links {
    pub fn app(&self) -> Option<String> {
        self.base.as_ref().map(|b| format!("{b}/app/"))
    }

    /// An app page: `team`.
    pub fn page(&self, page: &str) -> Option<String> {
        self.base.as_ref().map(|b| format!("{b}/app/{page}"))
    }

    pub fn approval(&self, id: &str) -> Option<String> {
        self.base.as_ref().map(|b| format!("{b}/app/home?approval={id}"))
    }

    pub fn audit(&self, id: &str) -> Option<String> {
        self.base.as_ref().map(|b| format!("{b}/console/#audit?target=approval:{id}"))
    }

    /// A console page: `machines`, `audit?target=machine:<id>`.
    pub fn console(&self, page: &str) -> Option<String> {
        self.base.as_ref().map(|b| format!("{b}/console/#{page}"))
    }
}

/// What a channel did with one notice.
#[derive(Clone, Debug, Default)]
pub struct Sent {
    pub delivered: usize,
    pub failed: usize,
    /// The first failure, never holding a secret.
    pub error: Option<String>,
    /// For the audit log: recipients, the webhook's host.
    pub detail: Value,
    /// Push devices the provider says are gone, to forget.
    pub gone: Vec<push::Gone>,
}

/// One way notices reach people. `send` returns None when the plan leaves this channel
/// off. Email, webhooks, and mobile push (`push::PushChannel`, to the devices of
/// `plan.deciders`).
pub trait Channel: Send + Sync {
    fn name(&self) -> &'static str;
    fn send<'a>(&'a self, notice: &'a Notice, plan: &'a Plan, links: &'a Links) -> BoxFuture<'a, Option<Result<Sent, String>>>;
}

pub struct Email {
    pub smtp: smtp::Smtp,
}

impl Channel for Email {
    fn name(&self) -> &'static str {
        "email"
    }

    fn send<'a>(&'a self, n: &'a Notice, plan: &'a Plan, links: &'a Links) -> BoxFuture<'a, Option<Result<Sent, String>>> {
        Box::pin(async move {
            if plan.email.is_empty() {
                return None;
            }
            let password = match needed(smtp::PASSWORD) {
                Ok(p) => p,
                Err(e) => return Some(Err(e)),
            };
            let (subject, body) = (n.email_subject(), n.email_body(links.app().as_deref()));
            let mails: Vec<smtp::Mail> = plan.email.iter().map(|to| smtp::Mail { to: to.clone(), subject: subject.clone(), body: body.clone() }).collect();
            Some(self.smtp.send(password.as_ref().map(|p| p.expose()), &mails).await.map(|results| {
                let failed: Vec<(&String, &String)> = plan.email.iter().zip(&results).filter_map(|(to, r)| r.as_ref().err().map(|e| (to, e))).collect();
                Sent {
                    delivered: results.len() - failed.len(),
                    failed: failed.len(),
                    error: failed.first().map(|(to, e)| format!("{to}: {e}")),
                    detail: json!({ "to": plan.email, "refused": failed.iter().map(|(to, _)| to).collect::<Vec<_>>() }),
                    gone: Vec::new(),
                }
            }))
        })
    }
}

pub struct Webhook {
    pub http: reqwest::Client,
}

impl Channel for Webhook {
    fn name(&self) -> &'static str {
        "webhook"
    }

    fn send<'a>(&'a self, n: &'a Notice, plan: &'a Plan, _links: &'a Links) -> BoxFuture<'a, Option<Result<Sent, String>>> {
        Box::pin(async move {
            let (name, format) = plan.webhook.as_ref()?;
            let url = match needed(name) {
                Ok(Some(url)) => url,
                Ok(None) => return Some(Err(format!("{name} isn't set"))),
                Err(e) => return Some(Err(e)),
            };
            secrets::redact::register(url.expose());
            let signing = match needed(webhook::SIGNING) {
                Ok(s) => s,
                Err(e) => return Some(Err(e)),
            };
            let mut detail = json!({ "host": webhook::host_of(url.expose()), "format": format, "own": name != webhook::URL });
            Some(Ok(match webhook::post(&self.http, url.expose(), *format, n, signing.as_ref().map(|s| s.expose())).await {
                Ok(status) => {
                    detail["status"] = json!(status);
                    Sent { delivered: 1, detail, ..Default::default() }
                }
                Err(e) => Sent { failed: 1, error: Some(e), detail, ..Default::default() },
            }))
        })
    }
}

/// Per-Bot windows: after a notice, a Bot's next approvals are held and go as one digest
/// when the window ends, or sooner if one of them must go out before its deadline. Each
/// approval is offered once.
#[derive(Default)]
pub struct Throttle {
    last: HashMap<String, Instant>,
    held: HashMap<String, Held>,
    seen: HashSet<String>,
    order: VecDeque<String>,
}

#[derive(Debug, PartialEq)]
pub enum Offer {
    /// Already offered.
    Duplicate,
    Now,
    /// Held for the digest. `Some`: it moved the flush earlier (or is the first held), so
    /// flush after this long.
    Held(Option<Duration>),
}

struct Held {
    ids: Vec<String>,
    due: Instant,
}

impl Throttle {
    /// `by`: the latest this approval may go out, ahead of its deadline.
    pub fn offer(&mut self, bot: &str, id: &str, window: Duration, by: Instant, now: Instant) -> Offer {
        if !self.seen.insert(id.to_string()) {
            return Offer::Duplicate;
        }
        self.order.push_back(id.to_string());
        if self.order.len() > SEEN
            && let Some(old) = self.order.pop_front()
        {
            self.seen.remove(&old);
        }
        match self.last.get(bot) {
            Some(t) if !window.is_zero() && now < *t + window && by > now => {
                let due = (*t + window).min(by);
                let held = self.held.entry(bot.to_string()).or_insert_with(|| Held { ids: Vec::new(), due });
                held.ids.push(id.to_string());
                if held.ids.len() == 1 || due < held.due {
                    held.due = due;
                    Offer::Held(Some(due - now))
                } else {
                    Offer::Held(None)
                }
            }
            _ => {
                self.last.insert(bot.to_string(), now);
                Offer::Now
            }
        }
    }

    /// The held approvals once they're due; a new window starts if there were any.
    pub fn take(&mut self, bot: &str, now: Instant) -> Vec<String> {
        if !self.held.get(bot).is_some_and(|h| h.due <= now) {
            return Vec::new();
        }
        let ids = self.held.remove(bot).map(|h| h.ids).unwrap_or_default();
        self.last.insert(bot.to_string(), now);
        ids
    }
}

pub struct Notifier {
    pub smtp: Option<smtp::Smtp>,
    /// Set when an operator turns push on (`PUSH_PROVIDER`).
    pub push: Option<Arc<push::Push>>,
    pub links: Links,
    channels: Vec<Box<dyn Channel>>,
    throttle: Mutex<Throttle>,
}

impl Notifier {
    pub fn new(smtp: Option<smtp::Smtp>, public_url: Option<String>) -> Notifier {
        let mut channels: Vec<Box<dyn Channel>> = Vec::new();
        if let Some(s) = &smtp {
            channels.push(Box::new(Email { smtp: s.clone() }));
        }
        channels.push(Box::new(Webhook { http: webhook::client() }));
        Notifier { smtp, push: None, links: Links { base: public_url }, channels, throttle: Mutex::default() }
    }

    /// Adds push as a channel for approvals, and for routines (`push::routine_done`).
    pub fn with_push(mut self, p: push::Push) -> Notifier {
        let p = Arc::new(p);
        self.channels.push(Box::new(push::PushChannel(p.clone())));
        self.push = Some(p);
        self
    }

    /// SMTP from the environment (`smtp::Smtp::from_env`); push from PUSH_PROVIDER, its
    /// devices live while their sessions are by `sessions`; links from PUBLIC_URL,
    /// SSO_PUBLIC_URL, or the first ALLOWED_HOSTS name.
    pub fn from_env(var: &dyn Fn(&str) -> String, sessions: crate::users::SessionConfig) -> Result<Notifier, String> {
        let smtp = smtp::Smtp::from_env(var)?;
        let push = push::Push::from_env(var, sessions)?;
        let n = Notifier::new(smtp, crate::billing::public_url(var).ok());
        Ok(match push {
            Some(p) => n.with_push(p),
            None => n,
        })
    }

    /// What startup prints.
    pub fn describe(&self, s: &Settings) -> String {
        let email = match (&self.smtp, s.email.enabled) {
            (None, _) => "email off (set SMTP_HOST and SMTP_FROM)".to_string(),
            (Some(m), on) => format!("email {} through {}", if on { "on" } else { "ready, off" }, m.describe()),
        };
        let hook = match (secret_set(webhook::URL), s.webhook.enabled) {
            (true, true) => "webhook on",
            (true, false) => "webhook set, off",
            (false, _) => "no global webhook",
        };
        let push = match &self.push {
            Some(p) => format!("push through {}", p.provider()),
            None => format!("push off (set {}=expo)", push::PROVIDER),
        };
        let links = if self.links.base.is_some() { "" } else { "; links off (set PUBLIC_URL)" };
        format!("{email}; {hook}; {push}{links}")
    }

    /// Whether anything can be sent at all: push, or email or a webhook for the server or
    /// for any Bot, by the same rules as `plan`.
    pub fn any_channel(&self, db: &Db, s: &Settings) -> bool {
        let global_hook = secret_set(webhook::URL);
        if self.push.is_some() || (self.smtp.is_some() && s.email.enabled) || (global_hook && s.webhook.enabled) {
            return true;
        }
        db.bots().iter().any(|b| {
            let o = s.bots.get(&b.id).cloned().unwrap_or_default();
            let own = secret_set(&webhook::bot_secret(&b.id));
            (self.smtp.is_some() && o.email == Some(true)) || ((own || global_hook) && o.webhook.unwrap_or(own))
        })
    }

    /// Where a notice for `bot` goes now. No Bot: the global settings alone.
    pub fn plan(&self, db: &Db, bot: Option<&Bot>, s: &Settings) -> Plan {
        let o = bot.and_then(|b| s.bots.get(&b.id)).cloned().unwrap_or_default();
        let deciders = bot.map(|b| deciders(db, b)).unwrap_or_default();
        let mut email: Vec<String> = Vec::new();
        if self.smtp.is_some() && o.email.unwrap_or(s.email.enabled) {
            let theirs = deciders.iter().filter(|_| s.email.deciders).filter_map(|u| u.email.clone()).filter(|e| smtp::address_ok(e));
            for a in s.email.to.iter().cloned().chain(theirs) {
                if !email.iter().any(|e| e.eq_ignore_ascii_case(&a)) {
                    email.push(a);
                }
            }
        }
        let own = bot.map(|b| webhook::bot_secret(&b.id)).filter(|n| secret_set(n));
        let webhook = if o.webhook.unwrap_or(own.is_some() || s.webhook.enabled) {
            match own {
                Some(n) => Some((n, o.format.unwrap_or(s.webhook.format))),
                None => secret_set(webhook::URL).then(|| (webhook::URL.to_string(), s.webhook.format)),
            }
        } else {
            None
        };
        let push = match (&self.push, bot) {
            (Some(p), Some(_)) => p.devices(db, &deciders.iter().map(|u| u.id.clone()).collect::<Vec<_>>(), PushKind::Approvals),
            _ => Vec::new(),
        };
        Plan { deciders, email, webhook, push }
    }

    fn item(&self, a: &Approval, owner: &str, detail: Detail) -> Item {
        let class_label = crate::policy::CLASSES.iter().find(|(c, _)| *c == a.class).map_or("Needs approval", |(_, l)| *l).to_string();
        let shown = |s: &str| clip(&secrets::redact::text_for(&[owner], s));
        Item {
            approval_id: a.id.clone(),
            tool: clip(&a.tool),
            class: a.class.clone(),
            class_label,
            reason: (detail == Detail::Summary).then(|| shown(&a.reason)),
            subject: (detail == Detail::Summary).then(|| shown(&a.subject)),
            expires_at: a.expires_at,
            link: self.links.approval(&a.id),
            console_link: self.links.audit(&a.id),
        }
    }

    pub fn notice(&self, bot: &Bot, approvals: &[Approval], detail: Detail) -> Notice {
        let items: Vec<Item> = approvals.iter().take(MAX_ITEMS).map(|a| self.item(a, &bot.owner_id, detail)).collect();
        Notice {
            kind: if approvals.len() == 1 { NoticeKind::Approval } else { NoticeKind::Digest },
            bot_id: bot.id.clone(),
            bot_name: clip(&bot.name),
            items,
            more: approvals.len().saturating_sub(MAX_ITEMS),
            alert: None,
        }
    }

    /// A new pending approval: sends it after the delay, unless it's answered by then or
    /// the throttle holds it for a digest. Returns at once.
    pub fn requested(self: &Arc<Self>, app: &Arc<App>, a: &Approval) {
        let s = load(&app.db);
        let Some(bot) = app.db.bot(&a.bot_id) else { return };
        if self.plan(&app.db, Some(&bot), &s).is_empty() {
            return;
        }
        let (me, app, id, expires_at) = (self.clone(), app.clone(), a.id.clone(), a.expires_at);
        tokio::spawn(async move {
            let delay = Duration::from_secs(s.delay_seconds as u64).min(half_left(expires_at));
            if !delay.is_zero() {
                tokio::time::sleep(delay).await;
            }
            if !pending(&app.db, &id) {
                return;
            }
            let window = Duration::from_secs(load(&app.db).throttle_seconds as u64);
            let now = Instant::now();
            let offer = me.throttle.lock().unwrap_or_else(|e| e.into_inner()).offer(&bot.id, &id, window, now + half_left(expires_at), now);
            match offer {
                Offer::Now => me.send_pending(&app, &bot.id, &[id]).await,
                Offer::Held(Some(wait)) => {
                    tokio::time::sleep(wait).await;
                    let ids = me.throttle.lock().unwrap_or_else(|e| e.into_inner()).take(&bot.id, Instant::now());
                    me.send_pending(&app, &bot.id, &ids).await;
                }
                Offer::Held(None) | Offer::Duplicate => {}
            }
        });
    }

    /// Sends the approvals among `ids` still pending, as one notice.
    async fn send_pending(&self, app: &App, bot_id: &str, ids: &[String]) {
        let waiting: Vec<Approval> = ids.iter().filter_map(|id| app.db.approval(id)).filter(|a| a.status == "pending").collect();
        let Some(bot) = app.db.bot(bot_id) else { return };
        if waiting.is_empty() {
            return;
        }
        let s = load(&app.db);
        let plan = self.plan(&app.db, Some(&bot), &s);
        if plan.is_empty() {
            return;
        }
        let n = self.notice(&bot, &waiting, s.detail);
        self.deliver(app, &n, &plan, false).await;
    }

    /// A test through every channel the plan has on, now, past the delay and throttle.
    pub async fn test(&self, app: &App, bot: Option<&Bot>) -> Result<Vec<Value>, String> {
        let s = load(&app.db);
        let plan = self.plan(&app.db, bot, &s);
        if plan.is_empty() {
            return Err(match bot {
                Some(b) => format!("Nothing would reach anyone for {}: turn on email or a webhook, or have a decider turn on push in the app, first", b.name),
                None => "Nothing would reach anyone: turn on email with an address, or set a webhook, first".into(),
            });
        }
        let n = Notice { kind: NoticeKind::Test, bot_id: bot.map(|b| b.id.clone()).unwrap_or_default(), bot_name: bot.map(|b| clip(&b.name)).unwrap_or_default(), items: Vec::new(), more: 0, alert: None };
        Ok(self.deliver(app, &n, &plan, true).await)
    }

    /// Where an alert goes: the global email list and webhook, and its audience (ADR 0302):
    /// their addresses while email and `email.deciders` are on, and their phones that want
    /// approvals. Read-only people, service accounts and disabled people are never in it.
    pub fn alert_plan(&self, db: &Db, a: &Alert, s: &Settings) -> Plan {
        let mut plan = self.plan(db, None, s);
        let Some(w) = &a.audience else { return plan };
        let people: Vec<User> = w.people.iter().filter(|u| !u.service && u.active() && rbac::allows(Principal::User(u.role), Perm::Approve)).cloned().collect();
        if self.smtp.is_some() && s.email.enabled && s.email.deciders {
            for e in people.iter().filter_map(|u| u.email.clone()).filter(|e| smtp::address_ok(e)) {
                if !plan.email.iter().any(|x| x.eq_ignore_ascii_case(&e)) {
                    plan.email.push(e);
                }
            }
        }
        if let Some(p) = &self.push {
            plan.push = p.devices(db, &people.iter().map(|u| u.id.clone()).collect::<Vec<_>>(), PushKind::Approvals);
        }
        plan.deciders = people;
        plan
    }

    /// An alert to the global email list and webhook, and its audience, now. `page`: the
    /// console page it links to. Nothing when none of them is on.
    pub async fn alert(&self, app: &App, mut a: Alert, page: &str) -> Vec<Value> {
        let plan = self.alert_plan(&app.db, &a, &load(&app.db));
        if plan.is_empty() {
            return Vec::new();
        }
        a.title = secrets::redact::text(&a.title).into_owned();
        a.lines = a.lines.iter().map(|l| secrets::redact::text(l).into_owned()).collect();
        a.link = self.links.console(page);
        a.app_link = a.audience.as_ref().and_then(|w| self.links.page(w.page));
        let n = Notice { kind: NoticeKind::Alert, bot_id: String::new(), bot_name: String::new(), items: Vec::new(), more: 0, alert: Some(a) };
        self.deliver(app, &n, &plan, false).await
    }

    async fn deliver(&self, app: &App, n: &Notice, plan: &Plan, test: bool) -> Vec<Value> {
        let mut out = Vec::new();
        let ids: Vec<&str> = n.items.iter().map(|i| i.approval_id.as_str()).collect();
        // Channels go out together, so a slow mail server can't hold a webhook past the deadline.
        let results = futures_util::future::join_all(self.channels.iter().map(|ch| ch.send(n, plan, &self.links))).await;
        for (ch, r) in self.channels.iter().zip(results) {
            let Some(r) = r else { continue };
            let (ok, mut d) = match r {
                Ok(s) => {
                    push::forget_gone(&app.db, &s.gone);
                    let mut d = s.detail;
                    d["delivered"] = json!(s.delivered);
                    if s.failed > 0 {
                        d["failed"] = json!(s.failed);
                        d["error"] = json!(s.error.map(|e| secrets::redact::text(&e).into_owned()));
                    }
                    (s.failed == 0, d)
                }
                Err(e) => (false, json!({ "error": secrets::redact::text(&e) })),
            };
            d["channel"] = json!(ch.name());
            d["kind"] = json!(n.kind.as_str());
            match &n.alert {
                Some(a) => d["event"] = json!(a.event),
                None => d["approvals"] = json!(ids),
            }
            if test {
                d["test"] = json!(true);
            }
            let mut e = Event::new(Actor::system("notifications"), if ok { "notification.sent" } else { "notification.failed" }).outcome(if ok { Outcome::Success } else { Outcome::Failure });
            e = match (&n.alert, ids.as_slice(), n.bot_id.as_str()) {
                (Some(a), _, _) => e.target(&a.target_type, &a.target_id),
                (None, [one], _) => e.target("approval", one),
                (None, _, "") => e.target("notifications", "global"),
                (None, _, b) => e.target("bot", b),
            };
            if !n.bot_id.is_empty() {
                e = e.bot(&n.bot_id);
            }
            if !ok {
                crate::obs::log::log_warn!("Notification by {} failed: {}", ch.name(), d["error"].as_str().unwrap_or("see the audit log"));
            }
            out.push(json!({ "channel": ch.name(), "ok": ok, "delivered": d["delivered"], "error": d["error"] }));
            app.db.record(&e.details(d));
        }
        out
    }
}

/// Half the time an approval has left: the delay and the throttle never wait past this,
/// so a notice still leaves people time to answer.
fn half_left(expires_at: i64) -> Duration {
    Duration::from_millis((expires_at - crate::db::now()).max(0) as u64 / 2)
}

fn pending(db: &Db, id: &str) -> bool {
    db.approval(id).is_some_and(|a| a.status == "pending")
}

/// Hands a new pending approval to the notifier, if botd has one.
pub fn requested(app: &Arc<App>, a: &Approval) {
    if let Some(n) = app.notifier.get() {
        n.requested(app, a);
    }
}

/// Sends an alert to the global channels apart from the caller, if botd has a notifier.
pub fn alert(app: &Arc<App>, a: Alert, page: &'static str) {
    if let Some(n) = app.notifier.get() {
        let (n, app) = (n.clone(), app.clone());
        tokio::spawn(async move {
            n.alert(&app, a, page).await;
        });
    }
}

/// A routine's run is over: the person it ran for hears of it on their phones (ADR 0080).
pub fn routine_done(app: &Arc<App>, bot: &Bot, msg: &crate::db::Message) {
    push::routine_done(app, bot, msg);
}

/// A deleted Bot's own settings and webhook URL go with it.
pub fn forget_bot(app: &App, bot_id: &str) {
    let mut s = load(&app.db);
    if s.bots.remove(bot_id).is_some() {
        save(&app.db, &s);
    }
    let name = webhook::bot_secret(bot_id);
    if matches!(secrets::global().source(&name), Ok(Some((_, true)))) {
        let _ = secrets::global().delete(&name);
    }
}

#[cfg(test)]
pub(crate) mod tests;
