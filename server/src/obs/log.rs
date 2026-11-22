//! botd's log lines (ADR 0089). `LOG_FORMAT=text`, the default, prints them as plain
//! text, as botd always has. `LOG_FORMAT=json` prints one JSON object per line, with
//! `ts`, `level` and `msg`, and adds a line for each request and each run, with their ids.
//!
//! What goes in a structured line is chosen field by field: ids botd makes (request,
//! run, message, Bot, and trace and span ids when traces are on), harness names, route
//! templates and classes, statuses and timings.
//! Never a path as sent, a query string, a body, a name, an email, or a token.
//!
//! The newest lines are also kept in memory, in JSON, for the support bundle (ADR 0131).

use serde_json::{Map, Value, json};
use std::sync::atomic::{AtomicBool, Ordering};

static JSON: AtomicBool = AtomicBool::new(false);

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Format {
    #[default]
    Text,
    Json,
}

impl Format {
    pub fn parse(v: &str) -> Result<Format, String> {
        match v.trim().to_ascii_lowercase().as_str() {
            "" | "text" => Ok(Format::Text),
            "json" => Ok(Format::Json),
            other => Err(format!("LOG_FORMAT must be text or json, not \"{other}\"")),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Format::Text => "text",
            Format::Json => "json",
        }
    }
}

pub fn set_format(f: Format) {
    JSON.store(f == Format::Json, Ordering::Relaxed);
}

pub fn json() -> bool {
    JSON.load(Ordering::Relaxed)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Level {
    Info,
    Warn,
}

impl Level {
    fn as_str(self) -> &'static str {
        match self {
            Level::Info => "info",
            Level::Warn => "warn",
        }
    }
}

/// A line of botd's own text: printed as is (info to stdout, warnings to stderr), or
/// as `{"ts", "level", "msg"}` on the same stream, with the trace's ids inside a kept span.
/// Secrets botd knows and the tokens it issues are `[redacted]` first: an error a provider
/// echoes back can carry a key, and journald keeps what botd prints.
pub fn line(level: Level, msg: &str) {
    let msg = &*crate::secrets::redact::text(msg);
    let rendered = render(level, msg.strip_prefix("WARNING: ").unwrap_or(msg), traced(json!({})));
    if json() {
        write(level, rendered.clone());
    } else {
        match level {
            Level::Info => println!("{msg}"),
            Level::Warn => eprintln!("{msg}"),
        }
    }
    recent::push(rendered);
}

/// Inside a span that's kept (ADR 0118), `fields` with its `traceId` and `spanId`.
fn traced(mut fields: Value) -> Value {
    if let (Value::Object(f), Some(c)) = (&mut fields, super::trace::current_sampled())
        && f.get("traceId").is_none_or(Value::is_null)
    {
        f.insert("traceId".into(), json!(c.trace_id()));
        f.insert("spanId".into(), json!(c.span_id()));
    }
    fields
}

/// A structured line, `msg` naming what happened (`http.request`, `run.finished`), with
/// `fields` beside it. Only in JSON format: text logs stay as they were. Inside a span
/// that's kept (ADR 0118), it names the span's `traceId` and `spanId` too.
pub fn event(level: Level, msg: &str, fields: Value) {
    let rendered = render(level, msg, traced(fields));
    #[cfg(test)]
    captured::push(&rendered);
    if json() {
        write(level, rendered.clone());
    }
    recent::push(rendered);
}

/// Never panics on a failed write: structured lines are also written from the panic
/// hook, where a second panic aborts botd.
fn write(level: Level, line: String) {
    use std::io::Write;
    let _ = match level {
        Level::Info => writeln!(std::io::stdout().lock(), "{line}"),
        Level::Warn => writeln!(std::io::stderr().lock(), "{line}"),
    };
}

pub fn render(level: Level, msg: &str, fields: Value) -> String {
    let mut m = Map::new();
    m.insert("ts".into(), json!(chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)));
    m.insert("level".into(), json!(level.as_str()));
    m.insert("msg".into(), json!(msg));
    if let Value::Object(f) = fields {
        for (k, v) in f {
            if !matches!(k.as_str(), "ts" | "level" | "msg") && !v.is_null() {
                m.insert(k, v);
            }
        }
    }
    Value::Object(m).to_string()
}

/// `println!` through `LOG_FORMAT`.
macro_rules! log_info {
    ($($t:tt)*) => { $crate::obs::log::line($crate::obs::log::Level::Info, &format!($($t)*)) };
}

/// `eprintln!` through `LOG_FORMAT`.
macro_rules! log_warn {
    ($($t:tt)*) => { $crate::obs::log::line($crate::obs::log::Level::Warn, &format!($($t)*)) };
}

pub(crate) use {log_info, log_warn};

/// The newest lines botd logged, as JSON whatever `LOG_FORMAT` is, kept in memory for
/// the support bundle (ADR 0131). A restart forgets them; journald or Docker keeps the rest.
pub mod recent {
    use serde_json::{Value, json};
    use std::collections::VecDeque;
    use std::sync::Mutex;

    pub const KEEP: usize = 2_000;
    /// Longer lines are cut, a field at a time so each stays JSON: one huge warning
    /// mustn't crowd out the rest.
    pub const MAX_LINE: usize = 4_096;
    const MAX_FIELD: usize = 1_024;

    static LINES: Mutex<VecDeque<String>> = Mutex::new(VecDeque::new());

    pub fn push(mut line: String) {
        if line.len() > MAX_LINE {
            line = shorten(&line);
        }
        let mut l = LINES.lock().unwrap_or_else(|e| e.into_inner());
        if l.len() >= KEEP {
            l.pop_front();
        }
        l.push_back(line);
    }

    /// Oldest first.
    pub fn lines() -> Vec<String> {
        LINES.lock().unwrap_or_else(|e| e.into_inner()).iter().cloned().collect()
    }

    fn shorten(line: &str) -> String {
        let mut v: Value = serde_json::from_str(line).unwrap_or_else(|_| json!({ "msg": line }));
        clip(&mut v);
        let s = v.to_string();
        if s.len() <= MAX_LINE {
            return s;
        }
        json!({ "level": v["level"], "msg": v["msg"], "ts": v["ts"], "cut": true }).to_string()
    }

    fn clip(v: &mut Value) {
        match v {
            Value::String(s) if s.len() > MAX_FIELD => {
                let mut end = MAX_FIELD;
                while !s.is_char_boundary(end) {
                    end -= 1;
                }
                s.truncate(end);
                s.push('…');
            }
            Value::Array(a) => a.iter_mut().for_each(clip),
            Value::Object(o) => o.values_mut().for_each(clip),
            _ => {}
        }
    }
}

/// Structured lines, kept in test builds so tests can read what would be logged.
#[cfg(test)]
pub mod captured {
    use std::sync::Mutex;

    static LINES: Mutex<Vec<String>> = Mutex::new(Vec::new());
    const KEEP: usize = 20_000;

    pub fn push(line: &str) {
        let mut l = LINES.lock().unwrap_or_else(|e| e.into_inner());
        if l.len() >= KEEP {
            l.drain(..KEEP / 2);
        }
        l.push(line.to_string());
    }

    /// Every kept line that contains `needle`, parsed.
    pub fn with(needle: &str) -> Vec<serde_json::Value> {
        LINES.lock().unwrap_or_else(|e| e.into_inner()).iter().filter(|l| l.contains(needle)).filter_map(|l| serde_json::from_str(l).ok()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::obs::trace::{Kind, Tracer, within};
    use crate::secrets::redact;

    #[test]
    fn plain_lines_never_carry_a_known_value_or_an_issued_token() {
        let marker = crate::random_hex(6);
        let value = format!("plain-words-{}", crate::random_hex(8));
        let issued = format!("{}{}", crate::users::SESSION_PREFIX, "ab".repeat(32));
        redact::register(&value);
        line(Level::Warn, &format!("WARNING: {marker} provider echoed {value} and {issued}"));
        redact::forget(&value);
        let kept: Vec<Value> = recent::lines().iter().filter(|l| l.contains(&marker)).map(|l| serde_json::from_str(l).unwrap()).collect();
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0]["msg"], format!("{marker} provider echoed [redacted] and [redacted]"));
        assert_eq!(kept[0]["level"], "warn");
    }

    #[tokio::test]
    async fn plain_lines_and_events_name_a_kept_trace() {
        let t = Tracer::default();
        assert_eq!(traced(json!({})), json!({}), "outside a span, nothing");
        t.capture(1.0, false);
        let span = t.span("run claude", Kind::Internal, None);
        let c = span.sampled().unwrap();
        let line = within(&span, async { render(Level::Warn, "x", traced(json!({}))) }).await;
        let line: Value = serde_json::from_str(&line).unwrap();
        assert_eq!((line["traceId"].as_str(), line["spanId"].as_str()), (Some(c.trace_id().as_str()), Some(c.span_id().as_str())), "{line}");
        t.capture(0.0, false);
        let dropped = t.span("run claude", Kind::Internal, None);
        assert_eq!(within(&dropped, async { traced(json!({})) }).await, json!({}), "an unsampled trace isn't named");
    }
}
