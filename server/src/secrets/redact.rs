//! Redaction of known secret values. Every secret botd knows (its stores' values, the
//! login password, the Bots' token, screen tokens, the master key, and secret-looking
//! environment variables) becomes `[redacted]` before text is saved to SQLite, pushed
//! to clients, or written to the audit log. Exact values only, plus the session tokens
//! and sign-in codes botd issues (by shape): a secret botd was never told about can't
//! be recognized here.

use rusqlite::{params, Connection};
use serde_json::Value;
use std::borrow::Cow;
use std::sync::RwLock;

pub const MARK: &str = "[redacted]";
/// Shorter values are too likely to be ordinary words.
pub const MIN_LEN: usize = 8;

/// Longest first, so a secret that contains another is replaced whole.
static KNOWN: RwLock<Vec<String>> = RwLock::new(Vec::new());

pub fn register(value: &str) {
    let v = value.trim();
    if v.chars().count() < MIN_LEN || v.contains(MARK) {
        return;
    }
    let mut known = KNOWN.write().unwrap_or_else(|e| e.into_inner());
    if !known.iter().any(|k| k == v) {
        known.push(v.to_string());
        known.sort_by_key(|k| std::cmp::Reverse(k.len()));
    }
}

/// For values found only by guessing from a variable's name: registered when they look
/// generated (long, no spaces, not a path, has a digit), so a setting like
/// `KEYBOARD=standard` doesn't erase the word "standard" from chats.
pub fn register_if_random(value: &str) {
    let v = value.trim();
    if v.len() >= 12 && !v.contains(char::is_whitespace) && !v.starts_with('/') && v.bytes().any(|b| b.is_ascii_digit()) {
        register(v);
    }
}

pub fn forget(value: &str) {
    KNOWN.write().unwrap_or_else(|e| e.into_inner()).retain(|k| k != value.trim());
}

pub fn known() -> Vec<String> {
    KNOWN.read().unwrap_or_else(|e| e.into_inner()).clone()
}

pub fn text(s: &str) -> Cow<'_, str> {
    let known = KNOWN.read().unwrap_or_else(|e| e.into_inner());
    if !known.iter().any(|k| s.contains(k.as_str())) && next_issued(s).is_none() {
        return Cow::Borrowed(s);
    }
    let mut out = s.to_string();
    for k in known.iter() {
        if out.contains(k.as_str()) {
            out = out.replace(k.as_str(), MARK);
        }
    }
    Cow::Owned(strip_issued(&out))
}

/// Session tokens, sign-in codes, and SSO handoff codes botd issues. Only their hashes are kept, so they
/// can't be registered; they're recognized by shape: a prefix and 64 hex digits.
const ISSUED: [&str; 3] = [crate::users::SESSION_PREFIX, crate::users::CODE_PREFIX, crate::sso::HANDOFF_PREFIX];
const ISSUED_HEX: usize = 64;

/// Where the first issued token in `s` starts, and its length.
fn next_issued(s: &str) -> Option<(usize, usize)> {
    ISSUED
        .iter()
        .flat_map(|p| s.match_indices(p).map(move |(i, _)| (i, p.len() + ISSUED_HEX)))
        .filter(|&(i, len)| s.as_bytes().get(i + len - ISSUED_HEX..i + len).is_some_and(|h| h.iter().all(u8::is_ascii_hexdigit)))
        .min()
}

fn strip_issued(s: &str) -> String {
    let (mut out, mut rest) = (String::with_capacity(s.len()), s);
    while let Some((i, len)) = next_issued(rest) {
        out.push_str(&rest[..i]);
        out.push_str(MARK);
        rest = &rest[i + len..];
    }
    out.push_str(rest);
    out
}

/// Every string in a JSON value, at any depth. Keys are left alone.
pub fn value(v: Value) -> Value {
    match v {
        Value::String(s) => match text(&s) {
            Cow::Borrowed(_) => Value::String(s),
            Cow::Owned(r) => Value::String(r),
        },
        Value::Array(a) => Value::Array(a.into_iter().map(value).collect()),
        Value::Object(o) => Value::Object(o.into_iter().map(|(k, v)| (k, value(v))).collect()),
        other => other,
    }
}

/// Names that mention a secret (`AWS_ACCESS_KEY_ID`, `OPENAI_API_KEY`, ...).
pub fn names_secret(name: &str) -> bool {
    let n = name.to_ascii_uppercase();
    ["KEY", "TOKEN", "SECRET", "PASSWORD", "PASSWD", "CREDENTIAL", "PRIVATE"].iter().any(|w| n.contains(w))
}

/// Environment variable names whose values are treated as secrets: they mention one
/// and don't look like they hold a path or an id instead.
pub fn looks_secret(name: &str) -> bool {
    let n = name.to_ascii_uppercase();
    names_secret(&n) && !["_FILE", "_PATH", "_DIR", "_SOCK", "_ID"].iter().any(|s| n.ends_with(s))
}

/// Redacts known secrets already saved in chat text, choice cards, and approval
/// subjects. Safe to run on every start. The audit log is append-only, so its rows are
/// redacted when read instead; approval inputs are sealed, and redacted before sealing.
pub fn scrub_rows(c: &Connection) -> rusqlite::Result<usize> {
    let tx = c.unchecked_transaction()?;
    let mut n = 0;
    for s in known() {
        for (table, col) in [("messages", "text"), ("approvals", "subject")] {
            n += tx.execute(&format!("UPDATE {table} SET {col} = replace({col}, ?1, ?2) WHERE instr({col}, ?1) > 0"), params![s, MARK])?;
        }
    }
    // Choice cards and saved requesters are JSON, where a secret with quotes or
    // backslashes is escaped, so they're parsed and redacted value by value.
    for col in ["question", "requested_by"] {
        let rows: Vec<(i64, String)> = {
            let mut s = tx.prepare(&format!("SELECT id, {col} FROM messages WHERE {col} IS NOT NULL"))?;
            s.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?.collect::<rusqlite::Result<_>>()?
        };
        for (id, raw) in rows {
            let Ok(json) = serde_json::from_str::<Value>(&raw) else { continue };
            let clean = value(json.clone());
            if clean != json {
                n += tx.execute(&format!("UPDATE messages SET {col} = ? WHERE id = ?"), params![clean.to_string(), id])?;
            }
        }
    }
    tx.commit()?;
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn unique(tag: &str) -> String {
        format!("{tag}-{}", crate::random_hex(12))
    }

    #[test]
    fn known_values_are_replaced_everywhere() {
        let key = unique("sk-test");
        let longer = format!("{key}-and-more");
        register(&key);
        register(&longer);
        register("short");
        assert_eq!(text(&format!("use {key} now")), "use [redacted] now");
        assert_eq!(text(&format!("{longer}!")), "[redacted]!", "the longer secret goes whole");
        assert_eq!(text("short words stay"), "short words stay");
        assert!(matches!(text("nothing here"), Cow::Borrowed(_)));
        let v = value(json!({ "subject": format!("curl -H 'x: {key}'"), "list": [key.clone(), 3], "n": 1, key.clone(): "keys stay" }));
        assert_eq!(v["subject"], "curl -H 'x: [redacted]'");
        assert_eq!(v["list"], json!(["[redacted]", 3]));
        assert_eq!(v[key.as_str()], "keys stay");
        forget(&key);
        assert!(text(&key).contains(&key));
        forget(&longer);
    }

    #[test]
    fn issued_tokens_are_redacted_by_shape() {
        let session = crate::users::new_secret(crate::users::SESSION_PREFIX);
        let code = crate::users::new_secret(crate::users::CODE_PREFIX);
        assert_eq!(text(&format!("my code is {code}, token {session}.")), "my code is [redacted], token [redacted].");
        assert_eq!(value(json!({ "t": format!("Bearer {session}") }))["t"], "Bearer [redacted]");
        for s in ["sbs_", "sbc_abc", "sbs_x", "the sbc_ prefix"] {
            assert!(matches!(text(s), Cow::Borrowed(_)), "{s}");
        }
        let short = format!("sbs_{}", "a".repeat(ISSUED_HEX - 1));
        assert_eq!(text(&short), short.as_str(), "too short to be a token");
    }

    #[test]
    fn guessed_values_must_look_random() {
        let key = unique("sk-ant-api03");
        for v in ["standard", "/home/u/.ssh/id_ed25519", "two words 12345678", "short1"] {
            register_if_random(v);
            assert!(!known().iter().any(|k| k == v), "{v}");
        }
        register_if_random(&key);
        assert_eq!(text(&key), MARK);
        forget(&key);
    }

    #[test]
    fn secret_looking_names() {
        for n in ["ANTHROPIC_API_KEY", "OPENAI_API_KEY", "CLAUDE_CODE_OAUTH_TOKEN", "AUTH_PASSWORD", "GITHUB_TOKEN", "db_secret"] {
            assert!(looks_secret(n), "{n}");
        }
        for n in ["PATH", "HOME", "GIT_AUTHOR_NAME", "SSH_AUTH_SOCK", "SUPERBOT_MASTER_KEY_FILE", "AWS_ACCESS_KEY_ID", "TZ"] {
            assert!(!looks_secret(n), "{n}");
        }
    }

    #[test]
    fn saved_rows_are_scrubbed_once() {
        let path = crate::db::temp_path("scrub").join("app.sqlite");
        let db = crate::db::Db::open(&path).unwrap();
        let bot = db.create_bot("A", "#fff", "waddle", "claude", None, true);
        let secret = unique("hunter2\"hunter2\\");
        // Saved before botd knew the value, e.g. by an older version.
        let m = db.add_message(&bot.id, "bot", &format!("the key is {secret}"), Some(&json!({ "title": secret, "options": ["a"] })), false, None);
        let ua = format!("curl/8 {secret}");
        let who = crate::audit::Who { actor: crate::audit::Actor::operator(), source: crate::audit::Source { ip: None, user_agent: Some(ua) } };
        db.set_requested_by(m.id, &who);
        register(&secret);
        let c = Connection::open(&path).unwrap();
        assert_eq!(scrub_rows(&c).unwrap(), 3);
        let m = db.message(m.id).unwrap();
        assert_eq!(m.text, "the key is [redacted]");
        assert_eq!(m.question.unwrap()["title"], MARK);
        assert_eq!(m.requested_by.unwrap().source.user_agent.as_deref(), Some("curl/8 [redacted]"));
        assert_eq!(scrub_rows(&c).unwrap(), 0, "idempotent");
        forget(&secret);
    }
}
