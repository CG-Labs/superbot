//! Audit log: who did what, when, and from where. Rows are append-only: SQLite
//! triggers refuse UPDATE, and DELETE of anything younger than the retention
//! window (`AUDIT_RETENTION_DAYS`). Never put secrets or message bodies in an
//! event; `details` is scrubbed on write as a second line of defense.
//! Design: docs/adr/0008-audit-events.md.

use crate::db::{now, AuditEvent};
use crate::runner::App;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ActorKind {
    User,
    Bot,
    System,
}

impl ActorKind {
    pub fn as_str(self) -> &'static str {
        match self {
            ActorKind::User => "user",
            ActorKind::Bot => "bot",
            ActorKind::System => "system",
        }
    }
}

/// Who acted. Today a person is the single `AUTH_PASSWORD` operator (id `operator`).
/// With multi-user sign-in, `id` becomes the user's id and `subject` their IdP
/// subject (`<issuer>|<sub>`). A Bot's id comes from `botctl` and is self-reported
/// until Bots get their own tokens.
#[derive(Clone, Debug, PartialEq)]
pub struct Actor {
    pub kind: ActorKind,
    pub id: Option<String>,
    pub name: Option<String>,
    pub subject: Option<String>,
}

impl Actor {
    pub fn operator() -> Actor {
        Actor { kind: ActorKind::User, id: Some("operator".into()), name: None, subject: None }
    }

    pub fn bot(id: Option<&str>, name: Option<&str>) -> Actor {
        Actor { kind: ActorKind::Bot, id: id.map(String::from), name: name.map(String::from), subject: None }
    }

    /// `part` names the component: `server`, `scheduler`, `approvals`, `retention`, ...
    pub fn system(part: &str) -> Actor {
        Actor { kind: ActorKind::System, id: Some(part.into()), name: None, subject: None }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Outcome {
    Success,
    /// The actor tried and it didn't work, e.g. a wrong password.
    Failure,
    /// Refused by auth or policy.
    Denied,
}

impl Outcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Outcome::Success => "success",
            Outcome::Failure => "failure",
            Outcome::Denied => "denied",
        }
    }
}

/// Where a request came from, when there was one.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Source {
    pub ip: Option<String>,
    pub user_agent: Option<String>,
}

/// An actor plus the request they acted through.
#[derive(Clone, Debug)]
pub struct Who {
    pub actor: Actor,
    pub source: Source,
}

impl Who {
    pub fn system(part: &str) -> Who {
        Who { actor: Actor::system(part), source: Source::default() }
    }

    pub fn event(&self, action: &str) -> Event {
        Event { source: self.source.clone(), ..Event::new(self.actor.clone(), action) }
    }
}

/// One audit event before it is written. `action` is `<noun>.<verb>`, e.g. `bot.created`.
#[derive(Clone, Debug)]
pub struct Event {
    pub actor: Actor,
    pub action: String,
    pub target_type: Option<String>,
    pub target_id: Option<String>,
    pub bot_id: Option<String>,
    pub outcome: Outcome,
    pub source: Source,
    pub details: Value,
}

impl Event {
    pub fn new(actor: Actor, action: &str) -> Event {
        Event {
            actor,
            action: action.into(),
            target_type: None,
            target_id: None,
            bot_id: None,
            outcome: Outcome::Success,
            source: Source::default(),
            details: json!({}),
        }
    }

    pub fn target(mut self, kind: &str, id: &str) -> Event {
        self.target_type = Some(kind.into());
        self.target_id = Some(id.into());
        self
    }

    /// The Bot this event concerns, for filtering.
    pub fn bot(mut self, id: &str) -> Event {
        self.bot_id = Some(id.into());
        self
    }

    pub fn outcome(mut self, o: Outcome) -> Event {
        self.outcome = o;
        self
    }

    pub fn details(mut self, d: Value) -> Event {
        self.details = d;
        self
    }
}

// Scrubbing: keys that name secrets lose their values; strings lose anything that
// looks like a credential and are cut to a bounded length.

pub const REDACTED: &str = "[redacted]";
const MAX_STRING: usize = 500;
const MAX_ARRAY: usize = 100;
const SECRET_WORDS: [&str; 11] =
    ["password", "passwd", "secret", "token", "authorization", "cookie", "apikey", "api_key", "api-key", "private_key", "credential"];
/// Prefixes of well-known API keys and tokens (OpenAI/Anthropic, GitHub, GitLab, Slack, AWS, Google, JWTs).
const TOKEN_PREFIXES: [&str; 15] =
    ["sk-", "sk_live_", "sk_test_", "ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_", "glpat-", "xoxb-", "xoxp-", "AKIA", "AIza", "eyJ"];

fn secret_name(k: &str) -> bool {
    let k = k.to_ascii_lowercase();
    SECRET_WORDS.iter().any(|w| k.contains(w))
}

pub fn scrub(v: Value) -> Value {
    match v {
        Value::Object(m) => Value::Object(
            m.into_iter()
                .map(|(k, v)| {
                    let v = if secret_name(&k) && !v.is_null() { json!(REDACTED) } else { scrub(v) };
                    (k, v)
                })
                .collect(),
        ),
        Value::Array(a) => Value::Array(a.into_iter().take(MAX_ARRAY).map(scrub).collect()),
        Value::String(s) => Value::String(clip(&redact_text(&s), MAX_STRING)),
        v => v,
    }
}

/// Cuts to `max` characters and drops control characters other than newline and tab.
pub fn clip(s: &str, max: usize) -> String {
    let mut out: String = s.chars().filter(|c| !c.is_control() || *c == '\n' || *c == '\t').take(max).collect();
    if s.chars().count() > max {
        out.push('…');
    }
    out
}

/// Masks credentials in free text such as a shell command: `Bearer <x>`,
/// `--password <x>`, `token=<x>`, `user:pass@` in URLs, and known key formats.
pub fn redact_text(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut next = Mask::None;
    for piece in s.split_inclusive(char::is_whitespace) {
        let word = piece.trim_end();
        let gap = &piece[word.len()..];
        if word.is_empty() {
            out.push_str(gap);
            continue;
        }
        let (masked, after) = match next {
            Mask::Word if !is_auth_scheme(word) => (REDACTED.to_string(), Mask::None),
            Mask::Password => match word.split_once(':') {
                Some((user, _)) => (format!("{user}:{REDACTED}"), Mask::None),
                None => redact_word(word),
            },
            _ => redact_word(word),
        };
        next = after;
        out.push_str(&masked);
        out.push_str(gap);
    }
    out
}

/// What to mask in the next word.
#[derive(Clone, Copy, PartialEq)]
enum Mask {
    None,
    Word,
    /// `user:password` after `-u` (curl and friends): only the password.
    Password,
}

fn is_auth_scheme(word: &str) -> bool {
    let bare = word.trim_matches(|c| c == '"' || c == '\'');
    bare.eq_ignore_ascii_case("bearer") || bare.eq_ignore_ascii_case("basic")
}

fn known_token(s: &str) -> bool {
    s.len() >= 20 && TOKEN_PREFIXES.iter().any(|p| s.starts_with(p))
}

/// One whitespace-separated word. Returns the word to write and what to mask in the next one.
fn redact_word(word: &str) -> (String, Mask) {
    if is_auth_scheme(word) {
        return (word.into(), Mask::Word); // Authorization: Bearer <x>
    }
    if word.starts_with('-') && !word.contains('=') && secret_name(word) {
        return (word.into(), Mask::Word); // --password <x>
    }
    if word == "-u" || word == "--user" || word == "--proxy-user" {
        return (word.into(), Mask::Password);
    }
    let bare = word.trim_matches(|c| c == '"' || c == '\'');
    if let Some(i) = bare.find(['=', ':']) {
        let (key, value) = (&bare[..i], &bare[i + 1..]);
        if secret_name(key) {
            if value.is_empty() || value == "'" || value == "\"" {
                return (word.into(), Mask::Word); // password: <x>
            }
            return (format!("{key}{}{REDACTED}", &bare[i..=i]), Mask::None);
        }
        if (key == "--user" || key == "-u")
            && let Some((user, _)) = value.split_once(':')
        {
            return (format!("{key}={user}:{REDACTED}"), Mask::None);
        }
    }
    let mut s = bare.to_string();
    if let Some(at) = s.find("://").map(|i| i + 3) {
        let host_end = s[at..].find(['/', '?', '#']).map_or(s.len(), |i| at + i);
        if let Some(u) = s[at..host_end].rfind('@') {
            s.replace_range(at..at + u, REDACTED);
        }
    }
    if let Some(q) = s.find('?') {
        let query: Vec<String> = s[q + 1..]
            .split('&')
            .map(|kv| match kv.split_once('=') {
                Some((k, _)) if secret_name(k) => format!("{k}={REDACTED}"),
                _ => kv.to_string(),
            })
            .collect();
        s = format!("{}?{}", &s[..q], query.join("&"));
    }
    if s.split(['=', ':', '/', '?', '&']).any(known_token) {
        return (REDACTED.into(), Mask::None);
    }
    if s == bare { (word.into(), Mask::None) } else { (s, Mask::None) }
}

// Queries: `GET /api/audit` and the CSV export share these filters.

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Filter {
    /// Unix ms, inclusive.
    pub from: Option<i64>,
    /// Unix ms, exclusive.
    pub to: Option<i64>,
    /// Exact actions, or prefixes written `approval.*`.
    pub actions: Vec<String>,
    pub actor_kind: Option<String>,
    pub actor_id: Option<String>,
    pub outcome: Option<String>,
    pub bot_id: Option<String>,
    /// Paging cursors: event ids.
    pub before: Option<i64>,
    pub after: Option<i64>,
}

fn plain_id(s: &str) -> bool {
    !s.is_empty() && s.len() <= 128 && s.chars().all(|c| c.is_ascii_alphanumeric() || "-_.:@|".contains(c))
}

/// Unix ms, RFC 3339 (`2026-11-19T13:00:00Z`), or a UTC date (`2026-11-19`).
/// A date as the end of a range means the end of that day.
pub fn parse_time(s: &str, end: bool) -> Result<i64, String> {
    let s = s.trim();
    if let Ok(ms) = s.parse::<i64>() {
        return Ok(ms);
    }
    if let Ok(t) = chrono::DateTime::parse_from_rfc3339(s) {
        return Ok(t.timestamp_millis());
    }
    if let Ok(d) = chrono::NaiveDate::parse_from_str(s, "%Y-%m-%d") {
        let d = if end { d.succ_opt().ok_or("Date out of range")? } else { d };
        return Ok(d.and_hms_opt(0, 0, 0).unwrap().and_utc().timestamp_millis());
    }
    Err(format!("Invalid time \"{s}\": use unix milliseconds, RFC 3339, or YYYY-MM-DD"))
}

impl Filter {
    /// `?from=&to=&action=a,b.*&actor=user|bot|system[:id]&outcome=&bot=&before=&after=`
    pub fn from_query(q: &HashMap<String, String>) -> Result<Filter, String> {
        let get = |k: &str| q.get(k).map(|v| v.trim()).filter(|v| !v.is_empty());
        let mut f = Filter {
            from: get("from").map(|v| parse_time(v, false)).transpose()?,
            to: get("to").map(|v| parse_time(v, true)).transpose()?,
            ..Default::default()
        };
        for a in get("action").unwrap_or_default().split(',').map(str::trim).filter(|a| !a.is_empty()) {
            let name = a.strip_suffix(".*").unwrap_or(a);
            if a != "*" && (name.is_empty() || name.len() > 64 || !name.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '.')) {
                return Err(format!("Invalid action filter \"{a}\""));
            }
            if a != "*" {
                f.actions.push(a.into());
            }
        }
        if f.actions.len() > 20 {
            return Err("At most 20 actions".into());
        }
        if let Some(a) = get("actor") {
            let (kind, id) = a.split_once(':').map_or((a, None), |(k, i)| (k, Some(i)));
            if !["user", "bot", "system"].contains(&kind) {
                return Err("actor must be user, bot, or system, optionally with :<id>".into());
            }
            if id.is_some_and(|i| !plain_id(i)) {
                return Err("Invalid actor id".into());
            }
            f.actor_kind = Some(kind.into());
            f.actor_id = id.map(String::from);
        }
        if let Some(o) = get("outcome") {
            if !["success", "failure", "denied"].contains(&o) {
                return Err("outcome must be success, failure, or denied".into());
            }
            f.outcome = Some(o.into());
        }
        if let Some(b) = get("bot") {
            if !plain_id(b) {
                return Err("Invalid bot id".into());
            }
            f.bot_id = Some(b.into());
        }
        let cursor = |k: &str| get(k).map(|v| v.parse::<i64>().map_err(|_| format!("{k} must be an event id"))).transpose();
        f.before = cursor("before")?;
        f.after = cursor("after")?;
        Ok(f)
    }

    /// The filter as recorded on `audit.exported`.
    pub fn describe(&self) -> Value {
        json!({
            "from": self.from, "to": self.to, "actions": self.actions, "actorKind": self.actor_kind,
            "actorId": self.actor_id, "outcome": self.outcome, "botId": self.bot_id,
        })
    }
}

// CSV export (RFC 4180): CRLF line ends, quotes doubled, and cells that a
// spreadsheet would run as a formula start with an apostrophe.

pub const CSV_HEADER: &str =
    "id,time,actor_kind,actor_id,actor_name,actor_subject,action,target_type,target_id,bot_id,outcome,ip,user_agent,details\r\n";

pub fn csv_cell(s: &str) -> String {
    let s = if s.starts_with(['=', '+', '-', '@', '\t', '\r']) { format!("'{s}") } else { s.to_string() };
    if s.contains([',', '"', '\r', '\n']) {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s
    }
}

pub fn csv_row(e: &AuditEvent) -> String {
    let o = |v: &Option<String>| v.as_deref().map(csv_cell).unwrap_or_default();
    let cells = [
        e.id.to_string(),
        csv_cell(&e.time),
        csv_cell(&e.actor_kind),
        o(&e.actor_id),
        o(&e.actor_name),
        o(&e.actor_subject),
        csv_cell(&e.action),
        o(&e.target_type),
        o(&e.target_id),
        o(&e.bot_id),
        csv_cell(&e.outcome),
        o(&e.ip),
        o(&e.user_agent),
        csv_cell(&e.details.to_string()),
    ];
    format!("{}\r\n", cells.join(","))
}

// Logins. Every request carries HTTP Basic credentials, so a "login" is the first
// good request from a client (IP + user agent), or the first after 30 idle minutes.
// Failures are throttled so a password-guessing flood can't fill the disk.

const SESSION_GAP_MS: i64 = 30 * 60_000;
const FAIL_WINDOW_MS: i64 = 60_000;
const MAX_FAIL_EVENTS_PER_WINDOW: u32 = 60;
const MAX_CLIENTS: usize = 10_000;

#[derive(Default)]
pub struct Logins(Mutex<LoginState>);

#[derive(Default)]
struct LoginState {
    seen: HashMap<String, i64>,
    /// Per client (IP and method): when its last failure was logged, and failures since then that weren't.
    failures: HashMap<String, (i64, u64)>,
    /// All IPs: start of the current window, and failures logged in it.
    window: (i64, u32),
}

impl Logins {
    /// True when this good request starts a new session for `client`.
    pub fn success(&self, client: &str, at: i64) -> bool {
        let mut s = self.0.lock().unwrap_or_else(|e| e.into_inner());
        let fresh = s.seen.get(client).is_none_or(|t| at - t >= SESSION_GAP_MS);
        if fresh && s.seen.len() >= MAX_CLIENTS {
            s.seen.retain(|_, t| at - *t < SESSION_GAP_MS);
            if s.seen.len() >= MAX_CLIENTS {
                s.seen.clear();
            }
        }
        s.seen.insert(client.into(), at);
        fresh
    }

    /// Some(n) when this failure should be logged; n is how many from `client` weren't since the last one.
    pub fn failure(&self, client: &str, at: i64) -> Option<u64> {
        let mut s = self.0.lock().unwrap_or_else(|e| e.into_inner());
        if at - s.window.0 >= FAIL_WINDOW_MS {
            s.window = (at, 0);
        }
        let budget = s.window.1 < MAX_FAIL_EVENTS_PER_WINDOW;
        if !s.failures.contains_key(client) && s.failures.len() >= MAX_CLIENTS {
            s.failures.retain(|_, (t, _)| at - *t < FAIL_WINDOW_MS);
            if s.failures.len() >= MAX_CLIENTS {
                s.failures.clear();
            }
        }
        let entry = s.failures.entry(client.into()).or_insert((at - FAIL_WINDOW_MS, 0));
        if at - entry.0 < FAIL_WINDOW_MS || !budget {
            entry.1 += 1;
            return None;
        }
        let missed = entry.1;
        *entry = (at, 0);
        s.window.1 += 1;
        Some(missed)
    }
}

// Retention: `AUDIT_RETENTION_DAYS` (unset or 0 = keep forever).

const MAX_RETENTION_DAYS: u32 = 36_500;
const PRUNE_EVERY: Duration = Duration::from_secs(6 * 60 * 60);

pub fn retention_days(raw: &str) -> Result<Option<u32>, String> {
    match raw.trim() {
        "" | "0" => Ok(None),
        v => match v.parse::<u32>() {
            Ok(d) if (1..=MAX_RETENTION_DAYS).contains(&d) => Ok(Some(d)),
            _ => Err(format!("AUDIT_RETENTION_DAYS must be a number of days from 1 to {MAX_RETENTION_DAYS}, or 0 to keep forever")),
        },
    }
}

/// Saves the retention setting (the delete trigger reads it), logs a change, and prunes every few hours.
pub fn start_retention(app: Arc<App>, days: Option<u32>) {
    let before = app.db.audit_retention();
    if before != days {
        app.db.set_audit_retention(days);
        app.db.record(&Event::new(Actor::system("retention"), "audit.retention_changed").details(json!({ "before": before, "after": days })));
    }
    let Some(days) = days else { return };
    tokio::spawn(async move {
        loop {
            prune(&app, days);
            tokio::time::sleep(PRUNE_EVERY).await;
        }
    });
}

pub fn prune(app: &App, days: u32) {
    let cutoff = now() - days as i64 * 86_400_000;
    match app.db.prune_audit(cutoff) {
        Ok(0) => {}
        Ok(n) => app.db.record(&Event::new(Actor::system("retention"), "audit.pruned").details(json!({ "deleted": n, "olderThan": cutoff, "retentionDays": days }))),
        Err(e) => eprintln!("audit retention: {e}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csv_cells_are_quoted_and_formula_safe() {
        assert_eq!(csv_cell("plain"), "plain");
        assert_eq!(csv_cell("a,b"), "\"a,b\"");
        assert_eq!(csv_cell("say \"hi\""), "\"say \"\"hi\"\"\"");
        assert_eq!(csv_cell("two\nlines"), "\"two\nlines\"");
        assert_eq!(csv_cell("=HYPERLINK(\"http://x\")"), "\"'=HYPERLINK(\"\"http://x\"\")\"");
        for (raw, safe) in [("=1+1", "'=1+1"), ("+1", "'+1"), ("-1", "'-1"), ("@SUM(A1)", "'@SUM(A1)"), ("\tx", "'\tx")] {
            assert_eq!(csv_cell(raw), safe, "{raw:?}");
        }
        assert_eq!(csv_cell("\rx"), "\"'\rx\"");
        assert_eq!(csv_cell("a=b"), "a=b");
    }

    #[test]
    fn csv_rows_have_every_column() {
        let e = AuditEvent {
            id: 7,
            at: 0,
            time: "1970-01-01T00:00:00.000Z".into(),
            actor_kind: "bot".into(),
            actor_id: Some("b1".into()),
            actor_name: Some("=cmd|' /C calc'!A0".into()),
            actor_subject: None,
            action: "routine.created".into(),
            target_type: Some("routine".into()),
            target_id: Some("r1".into()),
            bot_id: Some("b1".into()),
            outcome: "success".into(),
            ip: Some("192.0.2.1".into()),
            user_agent: Some("botctl".into()),
            details: json!({ "name": "a,b" }),
        };
        let row = csv_row(&e);
        assert!(row.ends_with("\r\n"));
        assert_eq!(row, "7,1970-01-01T00:00:00.000Z,bot,b1,'=cmd|' /C calc'!A0,,routine.created,routine,r1,b1,success,192.0.2.1,botctl,\"{\"\"name\"\":\"\"a,b\"\"}\"\r\n");
        assert_eq!(CSV_HEADER.trim_end().split(',').count(), 14);
    }

    #[test]
    fn secrets_are_scrubbed() {
        let v = scrub(json!({
            "password": "hunter2", "apiKey": "x", "botToken": "y", "nested": { "Authorization": "Basic abc" }, "name": "ok",
            "subject": "curl -H 'Authorization: Bearer abc123' https://me:pw@example.com/x?token=t0p&b=1 --password p4ss",
        }));
        assert_eq!(v["password"], REDACTED);
        assert_eq!(v["apiKey"], REDACTED);
        assert_eq!(v["botToken"], REDACTED);
        assert_eq!(v["nested"]["Authorization"], REDACTED);
        assert_eq!(v["name"], "ok");
        let s = v["subject"].as_str().unwrap();
        for leak in ["abc123", "me:pw", "t0p", "p4ss"] {
            assert!(!s.contains(leak), "{leak} in {s}");
        }
        assert!(s.starts_with("curl -H 'Authorization: Bearer [redacted]"), "{s}");
        assert_eq!(redact_text("export OPENAI_API_KEY=sk-proj-abcdefghijklmnopqrstuvwx"), "export OPENAI_API_KEY=[redacted]");
        assert_eq!(redact_text("git push origin ghp_abcdefghijklmnopqrstuvwxyz0123"), "git push origin [redacted]");
        assert_eq!(redact_text("ls -la  /tmp\nrm x"), "ls -la  /tmp\nrm x");
        assert_eq!(redact_text("password: hunter2"), "password: [redacted]");
        assert_eq!(redact_text("curl -u admin:hunter2 https://x"), "curl -u admin:[redacted] https://x");
        assert_eq!(redact_text("curl --user=admin:hunter2 x"), "curl --user=admin:[redacted] x");
        assert_eq!(redact_text("git push -u origin main"), "git push -u origin main");
        let long = scrub(json!("x".repeat(2000)));
        assert_eq!(long.as_str().unwrap().chars().count(), MAX_STRING + 1);
    }

    #[test]
    fn filters_parse_and_reject() {
        let q = |pairs: &[(&str, &str)]| Filter::from_query(&pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect());
        let f = q(&[("from", "2026-11-01"), ("to", "2026-11-01"), ("action", "bot.created, approval.*"), ("actor", "bot:abc"), ("outcome", "denied")]).unwrap();
        assert_eq!(f.to.unwrap() - f.from.unwrap(), 86_400_000);
        assert_eq!(f.actions, ["bot.created", "approval.*"]);
        assert_eq!((f.actor_kind.as_deref(), f.actor_id.as_deref()), (Some("bot"), Some("abc")));
        assert_eq!(q(&[("from", "2026-11-19T13:00:00Z")]).unwrap().from, Some(1_795_093_200_000));
        assert_eq!(q(&[("from", "2026-11-19T14:00:00+01:00")]).unwrap().from, Some(1_795_093_200_000));
        assert_eq!(q(&[("from", "1700000000000")]).unwrap().from, Some(1_700_000_000_000));
        assert_eq!(q(&[("action", "*")]).unwrap().actions.len(), 0);
        for bad in [("from", "yesterday"), ("action", "x'; DROP"), ("actor", "admin"), ("actor", "bot:a b"), ("outcome", "ok"), ("before", "x")] {
            assert!(q(&[bad]).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn logins_are_once_per_session_and_failures_are_throttled() {
        let l = Logins::default();
        assert!(l.success("1.2.3.4|ua", 0));
        assert!(!l.success("1.2.3.4|ua", 60_000));
        assert!(l.success("1.2.3.4|other", 60_000));
        assert!(!l.success("1.2.3.4|ua", 60_000 + SESSION_GAP_MS - 1));
        assert!(l.success("1.2.3.4|ua", 60_000 + 2 * SESSION_GAP_MS));

        assert_eq!(l.failure("1.2.3.4", 0), Some(0));
        assert_eq!(l.failure("1.2.3.4", 1), None);
        assert_eq!(l.failure("1.2.3.4", 2), None);
        assert_eq!(l.failure("1.2.3.4", FAIL_WINDOW_MS), Some(2));
        // Many IPs: at most MAX_FAIL_EVENTS_PER_WINDOW events per window in total.
        let l = Logins::default();
        let logged = (0..500).filter(|i| l.failure(&format!("10.0.0.{i}"), 5).is_some()).count();
        assert_eq!(logged, MAX_FAIL_EVENTS_PER_WINDOW as usize);
    }

    #[test]
    fn retention_setting() {
        assert_eq!(retention_days(""), Ok(None));
        assert_eq!(retention_days("0"), Ok(None));
        assert_eq!(retention_days("365"), Ok(Some(365)));
        assert!(retention_days("-1").is_err());
        assert!(retention_days("forever").is_err());
        assert!(retention_days("99999").is_err());
    }
}
