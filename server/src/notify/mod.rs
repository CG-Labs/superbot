//! Approval notifications (ADR 0060): a pending approval reaches the people who can
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
//! Channels share one shape (`Channel`): mobile push (#36) is another one, reaching the
//! same `Plan::deciders`.

pub mod api;
pub mod smtp;
pub mod webhook;

use crate::acl::{Access, Grant, Viewer};
use crate::audit::{Actor, Event, Outcome};
use crate::db::{Approval, Bot, Db, User};
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
/// for every Bot; list them in `email.to`.
pub fn deciders(db: &Db, bot: &Bot) -> Vec<User> {
    let mut ids = vec![bot.owner_id.clone()];
    for g in db.grants(&bot.id).into_iter().filter(|g| g.level == Grant::Operator) {
        if !ids.contains(&g.user_id) {
            ids.push(g.user_id);
        }
    }
    ids.into_iter()
        .filter_map(|id| db.user(&id))
        .filter(|u| u.active() && rbac::allows(Principal::User(u.role), Perm::Approve) && Viewer::person(db, &u.id).access(db, bot) >= Access::Operate)
        .collect()
}

/// Where one notice goes, worked out for one Bot (or for no Bot: a test of the global settings).
#[derive(Clone, Debug, Default)]
pub struct Plan {
    /// Who can answer. Email reaches them when `email.deciders` is on; push (#36) will too.
    pub deciders: Vec<User>,
    pub email: Vec<String>,
    /// The secret holding the URL, and the format.
    pub webhook: Option<(String, Format)>,
}

impl Plan {
    pub fn is_empty(&self) -> bool {
        self.email.is_empty() && self.webhook.is_none()
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
}

impl NoticeKind {
    fn as_str(self) -> &'static str {
        match self {
            NoticeKind::Approval => "approval",
            NoticeKind::Digest => "digest",
            NoticeKind::Test => "test",
        }
    }
}

#[derive(Clone, Debug)]
pub struct Notice {
    pub kind: NoticeKind,
    pub bot_id: String,
    pub bot_name: String,
    pub items: Vec<Item>,
    /// Approvals left out of a long digest.
    pub more: usize,
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
        }
    }

    pub fn email_subject(&self) -> String {
        format!("[SuperBot] {}", self.summary())
    }

    pub fn email_body(&self, app_link: Option<&str>) -> String {
        let now = crate::db::now();
        let mut out = String::new();
        match self.kind {
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

    pub fn approval(&self, id: &str) -> Option<String> {
        self.base.as_ref().map(|b| format!("{b}/app/home?approval={id}"))
    }

    pub fn audit(&self, id: &str) -> Option<String> {
        self.base.as_ref().map(|b| format!("{b}/console/#audit?target=approval:{id}"))
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
}

/// One way notices reach people. `send` returns None when the plan leaves this channel
/// off. Email and webhooks today; mobile push (#36) is another, sending to the devices of
/// `plan.deciders`.
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
            let password = stored(smtp::PASSWORD);
            let (subject, body) = (n.email_subject(), n.email_body(links.app().as_deref()));
            let mails: Vec<smtp::Mail> = plan.email.iter().map(|to| smtp::Mail { to: to.clone(), subject: subject.clone(), body: body.clone() }).collect();
            Some(self.smtp.send(password.as_ref().map(|p| p.expose()), &mails).await.map(|results| {
                let failed: Vec<(&String, &String)> = plan.email.iter().zip(&results).filter_map(|(to, r)| r.as_ref().err().map(|e| (to, e))).collect();
                Sent {
                    delivered: results.len() - failed.len(),
                    failed: failed.len(),
                    error: failed.first().map(|(to, e)| format!("{to}: {e}")),
                    detail: json!({ "to": plan.email, "refused": failed.iter().map(|(to, _)| to).collect::<Vec<_>>() }),
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
            let Some(url) = stored(name) else { return Some(Err(format!("{name} isn't set"))) };
            secrets::redact::register(url.expose());
            let signing = stored(webhook::SIGNING);
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
/// when the window ends. Each approval is offered once.
#[derive(Default)]
pub struct Throttle {
    last: HashMap<String, Instant>,
    held: HashMap<String, Vec<String>>,
    seen: HashSet<String>,
    order: VecDeque<String>,
}

#[derive(Debug, PartialEq)]
pub enum Offer {
    /// Already offered.
    Duplicate,
    Now,
    /// Held for the digest. `Some`: the first held, so flush after this long.
    Held(Option<Duration>),
}

impl Throttle {
    pub fn offer(&mut self, bot: &str, id: &str, window: Duration, now: Instant) -> Offer {
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
            Some(t) if !window.is_zero() && now < *t + window => {
                let held = self.held.entry(bot.to_string()).or_default();
                held.push(id.to_string());
                Offer::Held((held.len() == 1).then(|| *t + window - now))
            }
            _ => {
                self.last.insert(bot.to_string(), now);
                Offer::Now
            }
        }
    }

    /// The held approvals; a new window starts if there were any.
    pub fn take(&mut self, bot: &str, now: Instant) -> Vec<String> {
        let ids = self.held.remove(bot).unwrap_or_default();
        if !ids.is_empty() {
            self.last.insert(bot.to_string(), now);
        }
        ids
    }
}

pub struct Notifier {
    pub smtp: Option<smtp::Smtp>,
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
        Notifier { smtp, links: Links { base: public_url }, channels, throttle: Mutex::default() }
    }

    /// SMTP from the environment (`smtp::Smtp::from_env`); links from PUBLIC_URL,
    /// SSO_PUBLIC_URL, or the first ALLOWED_HOSTS name.
    pub fn from_env(var: &dyn Fn(&str) -> String) -> Result<Notifier, String> {
        let smtp = smtp::Smtp::from_env(var)?;
        Ok(Notifier::new(smtp, crate::billing::public_url(var).ok()))
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
        let links = if self.links.base.is_some() { "" } else { "; links off (set PUBLIC_URL)" };
        format!("{email}; {hook}{links}")
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
        Plan { deciders, email, webhook }
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
        let (me, app, id) = (self.clone(), app.clone(), a.id.clone());
        tokio::spawn(async move {
            if s.delay_seconds > 0 {
                tokio::time::sleep(Duration::from_secs(s.delay_seconds as u64)).await;
            }
            if !pending(&app.db, &id) {
                return;
            }
            let window = Duration::from_secs(load(&app.db).throttle_seconds as u64);
            let offer = me.throttle.lock().unwrap_or_else(|e| e.into_inner()).offer(&bot.id, &id, window, Instant::now());
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
                Some(b) => format!("Nothing would reach anyone for {}: turn on email or a webhook first", b.name),
                None => "Nothing would reach anyone: turn on email with an address, or set a webhook, first".into(),
            });
        }
        let n = Notice { kind: NoticeKind::Test, bot_id: bot.map(|b| b.id.clone()).unwrap_or_default(), bot_name: bot.map(|b| clip(&b.name)).unwrap_or_default(), items: Vec::new(), more: 0 };
        Ok(self.deliver(app, &n, &plan, true).await)
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
            d["approvals"] = json!(ids);
            if test {
                d["test"] = json!(true);
            }
            let mut e = Event::new(Actor::system("notifications"), if ok { "notification.sent" } else { "notification.failed" }).outcome(if ok { Outcome::Success } else { Outcome::Failure });
            e = match (ids.as_slice(), n.bot_id.as_str()) {
                ([one], _) => e.target("approval", one),
                (_, "") => e.target("notifications", "global"),
                (_, b) => e.target("bot", b),
            };
            if !n.bot_id.is_empty() {
                e = e.bot(&n.bot_id);
            }
            if !ok {
                eprintln!("Notification by {} failed: {}", ch.name(), d["error"].as_str().unwrap_or("see the audit log"));
            }
            out.push(json!({ "channel": ch.name(), "ok": ok, "delivered": d["delivered"], "error": d["error"] }));
            app.db.record(&e.details(d));
        }
        out
    }
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
