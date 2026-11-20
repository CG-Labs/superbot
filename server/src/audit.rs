//! Audit log: who did what, when, and from where. Rows are append-only: SQLite
//! triggers refuse UPDATE, and DELETE of anything younger than the retention
//! window (`AUDIT_RETENTION_DAYS`). Never put secrets or message bodies in an
//! event; `details` is scrubbed on write as a second line of defense.
//! Design: docs/adr/0009-audit-events.md; per-user actors and IdP: 0019-audit-actors.md.

use crate::db::{now, AuditEvent, Bot};
use crate::runner::App;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[derive(Clone, Copy, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ActorKind {
    User,
    Bot,
    #[default]
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

/// Who acted. A person is a user (`operator` is the owner and break-glass account),
/// with their email and role at the time, and how they signed in: the method, the SSO
/// provider and its type, their IdP subject (`<issuer>|<sub>`), and the session the
/// request came with. A Bot's id is the one its own token names (ADR 0029);
/// `on_behalf_of` names the person a Bot or the scheduler acted for (the Bot's owner).
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Actor {
    pub kind: ActorKind,
    pub id: Option<String>,
    pub name: Option<String>,
    pub subject: Option<String>,
    #[serde(default)]
    pub email: Option<String>,
    /// `admin`, `member`, or `readonly`, as it was when they acted.
    #[serde(default)]
    pub role: Option<String>,
    /// `password` (the break-glass AUTH_PASSWORD), `code`, `sso`, `none`
    /// (ALLOW_NO_AUTH), or `bot_token`. None for the system.
    #[serde(default)]
    pub method: Option<String>,
    /// The SSO provider's type (`entra`, `google`, `oidc`, `github`, `apple`, `saml`) and its
    /// configured id (from SSO_PROVIDERS), as `idp` and `provider` are in sign-in details.
    #[serde(default)]
    pub idp: Option<String>,
    #[serde(default)]
    pub idp_provider: Option<String>,
    /// The session id (never its token).
    #[serde(default)]
    pub session: Option<String>,
    #[serde(default)]
    pub on_behalf_of: Option<String>,
}

impl Actor {
    pub fn operator() -> Actor {
        Actor { kind: ActorKind::User, id: Some("operator".into()), ..Default::default() }
    }

    pub fn bot(id: Option<&str>, name: Option<&str>) -> Actor {
        Actor { kind: ActorKind::Bot, id: id.map(String::from), name: name.map(String::from), ..Default::default() }
    }

    /// A Bot, acting for its owner (ADR 0017: Bots act with their owner's access).
    pub fn for_bot(b: &Bot) -> Actor {
        Actor { on_behalf_of: Some(b.owner_id.clone()), ..Actor::bot(Some(&b.id), Some(&b.name)) }
    }

    /// `part` names the component: `server`, `scheduler`, `approvals`, `retention`, ...
    pub fn system(part: &str) -> Actor {
        Actor { kind: ActorKind::System, id: Some(part.into()), ..Default::default() }
    }

    pub fn method(mut self, m: &str) -> Actor {
        self.method = Some(m.into());
        self
    }

    pub fn on_behalf_of(mut self, user: &str) -> Actor {
        self.on_behalf_of = Some(user.into());
        self
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
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Source {
    pub ip: Option<String>,
    pub user_agent: Option<String>,
}

/// An actor plus the request they acted through. Saved with a queued message, so
/// the run it starts is attributed to whoever asked for it, even after a restart.
#[derive(Clone, Debug, Serialize, Deserialize)]
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
const TOKEN_PREFIXES: [&str; 19] =
    ["sk-", "sk_live_", "sk_test_", "ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_", "glpat-", "xoxb-", "xoxp-", "AKIA", "AIza", "eyJ", "sbs_", "sbc_", "sbh_", "sbp_"];

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
        // Masks the whole string before clipping: cutting first could hide the context
        // that marks a secret (a URL's `@`, a closing quote). Masking is linear.
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
    let s = &redact_pairs(s);
    let mut out = String::with_capacity(s.len());
    let mut next = Mask::None;
    for piece in s.split_inclusive(char::is_whitespace) {
        let word = piece.trim_end();
        let gap = &piece[word.len()..];
        if word.is_empty() {
            out.push_str(gap);
            continue;
        }
        if let Mask::Quoted(q) = next {
            // Still inside a quoted secret: drop words up to the closing quote.
            if let Some(i) = word.find(q) {
                next = Mask::None;
                let rest = &word[i + 1..];
                if !rest.is_empty() {
                    let (masked, after) = redact_word(rest);
                    next = after;
                    out.push_str(&masked);
                    out.push_str(gap);
                }
            }
            continue;
        }
        let (masked, after) = match next {
            Mask::Word if !is_auth_scheme(word) => (REDACTED.to_string(), quoted(word)),
            Mask::Password => match word.split_once(':') {
                Some((user, _)) => (format!("{user}:{REDACTED}"), quoted(word)),
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

/// Masks the value of every secret-named `key: value` or `key=value` anywhere in the
/// text, so a secret isn't missed for following a harmless key in the same word, as in
/// tool arguments shown as JSON (`{"message":"hi","token":"x"}`, also escaped or cut short).
fn redact_pairs(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let (mut copied, mut i) = (0, 0);
    // Quotes seen before `counted`, single and double: whether a pair sits inside a quoted argument.
    let (mut counted, mut quotes) = (0, [0usize; 2]);
    while i < b.len() {
        if !key_char(b[i]) || (i > 0 && key_char(b[i - 1])) {
            i += 1;
            continue;
        }
        let key_end = i + b[i..].iter().take_while(|&&c| key_char(c)).count();
        // Closing quotes and brackets may sit between key and separator: `"token":`, `user[password]=`.
        let mut j = key_end + b[key_end..].iter().take_while(|&&c| matches!(c, b'"' | b'\'' | b'\\' | b'[' | b']')).count();
        j += b[j..].iter().take_while(|&&c| c == b' ').count();
        let is_pair = j < b.len() && matches!(b[j], b':' | b'=') && !b[j..].starts_with(b"://");
        if !is_pair || !secret_name(&s[i..key_end]) {
            i = key_end;
            continue;
        }
        // `"token": 1` is JSON: a bare value ends at `,`, `}`, or `]`. Otherwise it's a
        // shell or form argument, which ends only where the shell word (or field) does.
        let json = b[key_end..j].contains(&b'"');
        for &c in &b[counted..i] {
            quotes[0] += (c == b'\'') as usize;
            quotes[1] += (c == b'"') as usize;
        }
        counted = i;
        let outer = match quotes {
            _ if json => None,
            [singles, _] if singles % 2 == 1 => Some('\''),
            [_, doubles] if doubles % 2 == 1 => Some('"'),
            _ => None,
        };
        j += 1;
        j += b[j..].iter().take_while(|&&c| c == b' ').count();
        let open = b[j..].iter().take_while(|&&c| matches!(c, b'"' | b'\'' | b'\\')).count();
        let mut start = j + open;
        let word = |at: usize| if json { json_word(b, at) } else { shell_word(s, at, outer) };
        let scheme = b[start..].iter().take_while(|&&c| c.is_ascii_alphabetic()).count();
        if open == 0 && is_auth_scheme(&s[start..start + scheme]) && b.get(start + scheme) == Some(&b' ') {
            // Authorization: Bearer <x>: keep the scheme, mask the credential.
            start += scheme;
            start += b[start..].iter().take_while(|&&c| c == b' ').count();
        }
        let end = match &s[j..j + open] {
            "" if start < b.len() && matches!(b[start], b'{' | b'[') => closing_bracket(&b[start..]).map_or(b.len(), |n| start + n),
            "" => word(start),
            "\"" => start + string_end(&b[start..]).unwrap_or(b.len() - start),
            q => s[start..].find(q).map_or(b.len(), |n| start + n),
        };
        if end > start {
            out.push_str(&s[copied..start]);
            out.push_str(REDACTED);
            copied = end;
        }
        i = end.max(key_end);
    }
    out.push_str(&s[copied..]);
    out
}

/// End of a bare JSON value (number, `true`, ...).
fn json_word(b: &[u8], at: usize) -> usize {
    at + b[at..].iter().take_while(|&&c| !c.is_ascii_whitespace() && !b",}]\"".contains(&c)).count()
}

/// End of an unquoted shell or form value. Inside a quoted argument (`outer`) it runs
/// to the closing quote or the next `&` field; outside, to whitespace, `&`, or `;`,
/// taking any quoted part along (`pa"ss word"`).
fn shell_word(s: &str, at: usize, outer: Option<char>) -> usize {
    let b = s.as_bytes();
    let mut e = at;
    while e < b.len() {
        let c = b[e];
        match outer {
            Some(q) if c == q as u8 || c == b'&' => break,
            Some(_) => e += 1,
            None if c.is_ascii_whitespace() || c == b'&' || c == b';' => break,
            None if c == b'"' || c == b'\'' => e = s[e + 1..].find(c as char).map_or(b.len(), |n| e + n + 2),
            None => e += 1,
        }
    }
    e
}

fn key_char(c: u8) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, b'_' | b'-' | b'.' | b'%')
}

/// Length of a JSON string body up to (not including) its closing quote.
fn string_end(b: &[u8]) -> Option<usize> {
    let mut escaped = false;
    for (n, &c) in b.iter().enumerate() {
        match c {
            _ if escaped => escaped = false,
            b'\\' => escaped = true,
            b'"' => return Some(n),
            _ => {}
        }
    }
    None
}

/// Length of a `{...}` or `[...]` value, brackets included.
fn closing_bracket(b: &[u8]) -> Option<usize> {
    let mut depth = 0usize;
    let mut n = 0;
    while n < b.len() {
        match b[n] {
            b'{' | b'[' => depth += 1,
            b'}' | b']' => {
                depth -= 1;
                if depth == 0 {
                    return Some(n + 1);
                }
            }
            b'"' => n += string_end(&b[n + 1..])? + 1,
            _ => {}
        }
        n += 1;
    }
    None
}

/// After masking a secret in `word`: if it opens a quote it doesn't close, the
/// secret runs on into the next words.
fn quoted(word: &str) -> Mask {
    let open = |q: char| word.matches(q).count() % 2 == 1;
    let first = word.chars().find(|c| matches!(c, '\'' | '"'));
    let other = if first == Some('"') { '\'' } else { '"' };
    first.into_iter().chain([other]).find(|&q| open(q)).map_or(Mask::None, Mask::Quoted)
}

/// What to mask in the next word.
#[derive(Clone, Copy, PartialEq)]
enum Mask {
    None,
    Word,
    /// `user:password` after `-u` (curl and friends): only the password.
    Password,
    /// The rest of a quoted secret, up to this closing quote.
    Quoted(char),
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
        if key.bytes().all(key_char) && secret_name(key) {
            if value.is_empty() {
                return (word.into(), Mask::Word); // password: <x>
            }
            // Already masked by redact_pairs, up to a quote or the next field.
            if let Some(rest) = value.trim_start_matches(['"', '\'', '\\']).strip_prefix(REDACTED)
                && (rest.is_empty() || rest.starts_with(['"', '\'', '\\', '&', ';']))
            {
                return (word.into(), quoted(word));
            }
            return (format!("{key}{}{REDACTED}", &bare[i..=i]), quoted(word));
        }
        if (key == "--user" || key == "-u")
            && let Some((user, _)) = value.split_once(':')
        {
            return (format!("{key}={user}:{REDACTED}"), quoted(word));
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
    /// `actor=user:<email>` for an email no current user has (an older address).
    pub actor_email: Option<String>,
    /// Sign-in methods: `password`, `code`, `sso`, `none`, `bot_token`.
    pub methods: Vec<String>,
    /// SSO provider type, and configured provider id.
    pub idp: Option<String>,
    pub idp_provider: Option<String>,
    /// IdP subject, `<issuer>|<sub>`, exactly.
    pub subject: Option<String>,
    pub session_id: Option<String>,
    /// A user id: events by Bots (or routines) acting for that person.
    pub on_behalf_of: Option<String>,
    pub outcome: Option<String>,
    pub bot_id: Option<String>,
    /// Paging cursors: event ids.
    pub before: Option<i64>,
    pub after: Option<i64>,
}

fn plain_id(s: &str) -> bool {
    !s.is_empty() && s.len() <= 128 && s.chars().all(|c| c.is_ascii_alphanumeric() || "-_.:@|".contains(c))
}

fn word(s: &str) -> bool {
    !s.is_empty() && s.len() <= 32 && s.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-')
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
    /// `?from=&to=&action=a,b.*&actor=user|bot|system[:id]&outcome=&bot=&before=&after=`,
    /// and for people: `actor=user:<email>`, `method=sso,password`, `idp=entra` (the type),
    /// `idpProvider=<id>`, `subject=<issuer|sub>`, `session=<id>`, `onBehalfOf=<user id or email>`.
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
            f.actor_kind = Some(kind.into());
            match id {
                Some(email) if kind == "user" && email.contains('@') => {
                    if !crate::users::valid_email(email) {
                        return Err("Invalid actor email".into());
                    }
                    f.actor_email = Some(email.into());
                }
                Some(i) if !plain_id(i) => return Err("Invalid actor id".into()),
                _ => f.actor_id = id.map(String::from),
            }
        }
        for m in get("method").unwrap_or_default().split(',').map(str::trim).filter(|m| !m.is_empty()) {
            if !word(m) {
                return Err(format!("Invalid method filter \"{m}\""));
            }
            f.methods.push(m.into());
        }
        if f.methods.len() > 10 {
            return Err("At most 10 methods".into());
        }
        let id = |k: &str| get(k).map(|v| if plain_id(v) { Ok(v.to_string()) } else { Err(format!("Invalid {k}")) }).transpose();
        f.idp_provider = id("idpProvider")?;
        f.session_id = id("session")?;
        f.on_behalf_of = match get("onBehalfOf") {
            Some(e) if e.contains('@') && !crate::users::valid_email(e) => return Err("Invalid onBehalfOf".into()),
            Some(e) if e.contains('@') => Some(e.into()),
            _ => id("onBehalfOf")?,
        };
        f.idp = get("idp").map(|v| if word(v) { Ok(v.to_string()) } else { Err("Invalid idp".to_string()) }).transpose()?;
        if let Some(s) = get("subject") {
            if s.len() > 256 || s.chars().any(char::is_control) {
                return Err("Invalid subject".into());
            }
            f.subject = Some(s.into());
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

    /// Emails become user ids where a user has that email now, so a person's events
    /// match whatever address they had then. `find` looks a user up by id or email.
    pub fn resolve_users(&mut self, find: impl Fn(&str) -> Option<String>) {
        if let Some(id) = self.actor_email.as_deref().and_then(&find) {
            self.actor_id = Some(id);
            self.actor_email = None;
        }
        if let Some(id) = self.on_behalf_of.as_deref().filter(|k| k.contains('@')).and_then(&find) {
            self.on_behalf_of = Some(id);
        }
    }

    /// The filter as recorded on `audit.exported`.
    pub fn describe(&self) -> Value {
        json!({
            "from": self.from, "to": self.to, "actions": self.actions, "actorKind": self.actor_kind,
            "actorId": self.actor_id, "actorEmail": self.actor_email, "methods": self.methods, "idp": self.idp,
            "idpProvider": self.idp_provider, "subject": self.subject, "sessionId": self.session_id, "onBehalfOf": self.on_behalf_of,
            "outcome": self.outcome, "botId": self.bot_id,
        })
    }
}

// CSV export (RFC 4180): CRLF line ends, quotes doubled, and cells that a
// spreadsheet would run as a formula start with an apostrophe. The actor columns
// added with per-user actors (ADR 0019) come last, so scripts that read the first
// fourteen by position keep working.

pub const CSV_HEADER: &str = "id,time,actor_kind,actor_id,actor_name,actor_subject,action,target_type,target_id,bot_id,outcome,ip,user_agent,details,\
actor_email,actor_role,auth_method,idp,idp_provider,session_id,on_behalf_of\r\n";

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
        o(&e.actor_email),
        o(&e.actor_role),
        o(&e.auth_method),
        o(&e.idp),
        o(&e.idp_provider),
        o(&e.session_id),
        o(&e.on_behalf_of),
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
    match app.db.prune_audit() {
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
            actor_email: None,
            actor_role: None,
            auth_method: Some("bot_token".into()),
            idp: None,
            idp_provider: None,
            session_id: None,
            on_behalf_of: Some("u1".into()),
        };
        let row = csv_row(&e);
        assert!(row.ends_with("\r\n"));
        assert_eq!(
            row,
            "7,1970-01-01T00:00:00.000Z,bot,b1,'=cmd|' /C calc'!A0,,routine.created,routine,r1,b1,success,192.0.2.1,botctl,\"{\"\"name\"\":\"\"a,b\"\"}\",,,bot_token,,,,u1\r\n"
        );
        let header: Vec<&str> = CSV_HEADER.trim_end().split(',').collect();
        assert_eq!(header.len(), 21);
        assert_eq!(header[..14].join(","), "id,time,actor_kind,actor_id,actor_name,actor_subject,action,target_type,target_id,bot_id,outcome,ip,user_agent,details", "old columns stay put");
        let sso = AuditEvent {
            actor_kind: "user".into(),
            actor_id: Some("u1".into()),
            actor_name: Some("Ada".into()),
            actor_subject: Some("https://login.example/t1/v2.0|oid-1".into()),
            actor_email: Some("ada@example.com".into()),
            actor_role: Some("admin".into()),
            auth_method: Some("sso".into()),
            idp: Some("entra".into()),
            idp_provider: Some("work".into()),
            session_id: Some("s1".into()),
            on_behalf_of: None,
            ..e
        };
        let row = csv_row(&sso);
        let cells: Vec<&str> = row.trim_end().rsplitn(8, ',').collect();
        assert_eq!(cells[..7], ["", "s1", "work", "entra", "sso", "admin", "ada@example.com"]);
    }

    #[test]
    fn actors_round_trip_for_queued_runs() {
        let owner = Bot {
            id: "b1".into(),
            name: "Scout".into(),
            color: String::new(),
            shape: String::new(),
            harness: "claude".into(),
            model: None,
            effort: None,
            session_id: None,
            primary: false,
            hidden: false,
            unread: false,
            created_at: 0,
            owner_id: "u1".into(),
            visibility: crate::acl::Visibility::Private,
        };
        let a = Actor::for_bot(&owner).method("bot_token");
        assert_eq!((a.kind, a.id.as_deref(), a.name.as_deref()), (ActorKind::Bot, Some("b1"), Some("Scout")));
        assert_eq!((a.on_behalf_of.as_deref(), a.method.as_deref()), (Some("u1"), Some("bot_token")));
        let who = Who { actor: a.clone(), source: Source { ip: Some("192.0.2.1".into()), user_agent: None } };
        let back: Who = serde_json::from_str(&serde_json::to_string(&who).unwrap()).unwrap();
        assert_eq!((back.actor, back.source), (a, who.source));
        let old: Who = serde_json::from_str(r#"{"actor":{"kind":"user","id":"operator","name":null,"subject":null},"source":{"ip":null,"userAgent":null}}"#).unwrap();
        assert_eq!(old.actor, Actor::operator(), "fields added later default to empty");
        assert_eq!(Actor::system("scheduler").on_behalf_of("u1").kind, ActorKind::System);
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
        assert_eq!(redact_text("botctl login sbc_0123456789abcdef0123456789"), "botctl login [redacted]");
        assert_eq!(redact_text("SUPERBOT_TOKEN=sbs_0123456789abcdef0123456789 botctl"), "SUPERBOT_TOKEN=[redacted] botctl");
        assert_eq!(redact_text("ls -la  /tmp\nrm x"), "ls -la  /tmp\nrm x");
        assert_eq!(redact_text("password: hunter2"), "password: [redacted]");
        assert_eq!(redact_text("curl -u admin:hunter2 https://x"), "curl -u admin:[redacted] https://x");
        assert_eq!(redact_text("curl --user=admin:hunter2 x"), "curl --user=admin:[redacted] x");
        assert_eq!(redact_text("git push -u origin main"), "git push -u origin main");
        // Quoted secrets with spaces are masked to the closing quote.
        assert_eq!(redact_text("tool --password 'my secret pass' --verbose"), "tool --password [redacted] --verbose");
        assert_eq!(redact_text("tool --password=\"my secret pass\" x"), "tool --password=\"[redacted]\" x");
        assert_eq!(redact_text("export DB_PASSWORD='a b c'; run"), "export DB_PASSWORD='[redacted]'; run");
        assert_eq!(redact_text("curl -u 'admin:my pass word' https://x"), "curl -u 'admin:[redacted] https://x");
        assert_eq!(redact_text("curl --user=\"admin:my pass\" https://x"), "curl --user=\"admin:[redacted] https://x");
        assert_eq!(redact_text("run \"password=my secret\" next"), "run \"password=[redacted]\" next");
        assert_eq!(redact_text("login --token \"it's a secret\" ok"), "login --token [redacted] ok");
        assert_eq!(redact_text("tool --password 'never closed and more"), "tool --password [redacted] ");
        assert_eq!(redact_text("echo 'hello world' --password 'x y'"), "echo 'hello world' --password [redacted] ");
        // Secrets after a harmless key, as in MCP tool arguments, plain, escaped, nested, or cut short.
        assert_eq!(redact_text(r#"mcp__send {"message":"hello","token":"hunter2"}"#), r#"mcp__send {"message":"hello","token":"[redacted]"}"#);
        assert_eq!(redact_text(r#"mcp__send {"text":"a b","api_key":"x \"y\" z","n":1}"#), r#"mcp__send {"text":"a b","api_key":"[redacted]","n":1}"#);
        assert_eq!(redact_text(r#"x {"body":"{\"password\":\"hunter2\"}"}"#), r#"x {"body":"{\"password\":\"[redacted]\"}"}"#);
        assert_eq!(redact_text(r#"x {"credentials":{"user":"a","pass":"hunter2"},"ok":true}"#), r#"x {"credentials":[redacted],"ok":true}"#);
        assert_eq!(redact_text(r#"x {"a":1,"secret":"hunter2 and more"#), r#"x {"a":1,"secret":"[redacted]"#);
        assert_eq!(redact_text("a=1&password=hunter2&b=2"), "a=1&password=[redacted]&b=2");
        assert_eq!(
            redact_text("curl --data 'user[password]=hunter2&user[name]=a' https://x"),
            "curl --data 'user[password]=[redacted]&user[name]=a' https://x"
        );
        assert_eq!(redact_text("user[password][]=hunter2"), "user[password][]=[redacted]");
        assert_eq!(redact_text("user%5Bpassword%5D=hunter2&x=1"), "user%5Bpassword%5D=[redacted]&x=1");
        assert_eq!(redact_text("curl --password=abc,def}x] https://x"), "curl --password=[redacted] https://x");
        assert_eq!(redact_text("tool --token=ab\"c d\"e next"), "tool --token=[redacted] next");
        assert_eq!(redact_text("curl -d 'password=a b,c&x=1' u"), "curl -d 'password=[redacted]&x=1' u");
        assert_eq!(redact_text("PASSWORD=abc;echo ok"), "PASSWORD=[redacted];echo ok");
        assert_eq!(redact_text(r#"{"message":"my token is mine","n":2}"#), r#"{"message":"my token is mine","n":2}"#);
        assert_eq!(redact_text("token=é€x y"), "token=[redacted] y");
        assert_eq!(redact_text("pässword=ü token:'é"), "pässword=ü token:'[redacted]");
        // Linear in the input: many secret pairs after many quotes.
        let big = "'a' ".repeat(50_000) + &"token=x ".repeat(50_000);
        let t = std::time::Instant::now();
        assert!(!redact_text(&big).contains("=x"));
        assert!(t.elapsed() < std::time::Duration::from_secs(2), "{:?}", t.elapsed());
        let url = format!("https://user:{}@example.com/x", "p".repeat(1_100));
        let v = scrub(json!({ "subject": format!("git clone {url}") }));
        assert!(!v["subject"].as_str().unwrap().contains("ppp"), "{v}");
        // Cut-short or odd input never panics.
        for odd in ["token=", "password:\"", "token={", "secret=\"\\", "key: [1, {", "token\\\":\\\"x"] {
            redact_text(odd);
        }
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
    fn person_filters_parse_and_reject() {
        let q = |pairs: &[(&str, &str)]| Filter::from_query(&pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect());
        let f = q(&[
            ("actor", "user:ada@example.com"),
            ("method", "sso, password"),
            ("idpProvider", "work-entra"),
            ("idp", "entra"),
            ("subject", "https://login.microsoftonline.com/t1/v2.0|oid 1"),
            ("session", "s0123abcd"),
            ("onBehalfOf", "u42"),
        ])
        .unwrap();
        assert_eq!((f.actor_kind.as_deref(), f.actor_id.as_deref(), f.actor_email.as_deref()), (Some("user"), None, Some("ada@example.com")));
        assert_eq!(f.methods, ["sso", "password"]);
        assert_eq!((f.idp_provider.as_deref(), f.idp.as_deref(), f.session_id.as_deref()), (Some("work-entra"), Some("entra"), Some("s0123abcd")));
        assert_eq!((f.subject.as_deref(), f.on_behalf_of.as_deref()), (Some("https://login.microsoftonline.com/t1/v2.0|oid 1"), Some("u42")));
        let d = f.describe();
        assert_eq!((d["actorEmail"].as_str(), d["methods"][1].as_str(), d["onBehalfOf"].as_str()), (Some("ada@example.com"), Some("password"), Some("u42")));
        // A Bot's id never becomes an email lookup.
        let bot = q(&[("actor", "bot:a@b")]).unwrap();
        assert_eq!((bot.actor_id.as_deref(), bot.actor_email), (Some("a@b"), None));
        // An email resolves to whoever has it now; an unknown one stays an email.
        let mut f = q(&[("actor", "user:ada@example.com"), ("onBehalfOf", "ada@example.com")]).unwrap();
        f.resolve_users(|k| (k == "ada@example.com").then(|| "u1".to_string()));
        assert_eq!((f.actor_id.as_deref(), f.actor_email, f.on_behalf_of.as_deref()), (Some("u1"), None, Some("u1")));
        let mut f = q(&[("actor", "user:old@example.com")]).unwrap();
        f.resolve_users(|_| None);
        assert_eq!((f.actor_id, f.actor_email.as_deref()), (None, Some("old@example.com")));
        // Any address a user can have can be searched, not only id-shaped ones.
        let long = format!("{}@example.com", "a".repeat(140));
        for email in ["ada+work@example.com", "zoë@example.com", long.as_str()] {
            let f = q(&[("actor", &format!("user:{email}")), ("onBehalfOf", email)]).unwrap();
            assert_eq!((f.actor_email.as_deref(), f.on_behalf_of.as_deref()), (Some(email), Some(email)));
        }
        let many = ["sso"; 11].join(",");
        for bad in [
            ("method", "SSO"),
            ("method", "sso;drop"),
            ("method", many.as_str()),
            ("idpProvider", "a b"),
            ("idp", "Entra"),
            ("session", "s1'--"),
            ("onBehalfOf", "u 1"),
            ("onBehalfOf", "a b@example.com"),
            ("actor", "user:a b@example.com"),
            ("actor", "user:@example.com"),
            ("actor", "bot:a+b"),
            ("subject", "a\nb"),
        ] {
            assert!(q(&[bad]).is_err(), "{bad:?}");
        }
        assert!(q(&[("subject", &"x".repeat(257))]).is_err());
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
