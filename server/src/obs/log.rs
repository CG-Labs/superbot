//! botd's log lines (ADR 0089). `LOG_FORMAT=text`, the default, prints them as plain
//! text, as botd always has. `LOG_FORMAT=json` prints one JSON object per line, with
//! `ts`, `level` and `msg`, and adds a line for each request and each run, with their ids.
//!
//! What goes in a structured line is chosen field by field: ids botd makes (request,
//! run, message, Bot), harness names, route templates and classes, statuses and timings.
//! Never a path as sent, a query string, a body, a name, an email, or a token.

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
/// as `{"ts", "level", "msg"}` on the same stream.
pub fn line(level: Level, msg: &str) {
    if !json() {
        match level {
            Level::Info => println!("{msg}"),
            Level::Warn => eprintln!("{msg}"),
        }
        return;
    }
    let msg = msg.strip_prefix("WARNING: ").unwrap_or(msg);
    write(level, render(level, msg, json!({})));
}

/// A structured line, `msg` naming what happened (`http.request`, `run.finished`), with
/// `fields` beside it. Only in JSON format: text logs stay as they were.
pub fn event(level: Level, msg: &str, fields: Value) {
    let rendered = (json() || cfg!(test)).then(|| render(level, msg, fields));
    #[cfg(test)]
    if let Some(r) = &rendered {
        captured::push(r);
    }
    if json()
        && let Some(r) = rendered
    {
        write(level, r);
    }
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
