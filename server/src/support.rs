//! Support bundles (ADR 0131): one tarball an admin attaches to a support ticket, holding
//! what support asks for first: botd's version, its settings with secrets taken out,
//! health and status, the newest log lines, and a summary of the audit log. Built on
//! request by `GET /api/support/bundle` (admins), which `botctl support-bundle` saves.
//!
//! Never in it: secret values, chats, prompts, tool inputs, files, names, emails or IP
//! addresses. Settings are redacted by name and by shape; then every string goes through
//! botd's own redaction (known secret values, the tokens botd issues, credential shapes)
//! before it is written.

use crate::audit::{self, Who};
use crate::db::{AuditEvent, now};
use crate::runner::App;
use crate::secrets::redact::{self, MARK};
use crate::{ApiError, AppState, Auth, Res};
use axum::extract::{ConnectInfo, Extension, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::Arc;

/// Bumped when a file's shape changes, so support tools can tell bundles apart.
pub const FORMAT: u32 = 1;
const AUDIT_DAYS: i64 = 7;
/// Newest events read for the summary; older ones in the window are counted as truncated.
const AUDIT_SCAN: i64 = 20_000;
const PROBLEMS: usize = 100;
const RECENT_MINUTES: i64 = 15;
/// Settings that name a person rather than configure botd.
const PERSONAL: [&str; 2] = ["USER_NAME", "OWNER_EMAIL"];
/// Words in a setting's name that make its whole value secret, beside `redact::names_secret`'s:
/// an error tracker's DSN and a webhook URL carry their credential inside, and headers
/// (`TRACES_OTLP_HEADERS`) carry an exporter's key under any header name it likes.
const SECRET_WORDS: [&str; 6] = ["DSN", "WEBHOOK", "SALT", "PASSPHRASE", "COOKIE", "HEADER"];
/// Settings that say where a secret is kept, not what it is.
const PATH_SUFFIXES: [&str; 3] = ["_FILE", "_PATH", "_DIR"];
/// The settings botd documents. The bundle carries these and settings that look like
/// SuperBot's or a harness provider's, and only counts the rest of the host's environment.
const DOCUMENTED: &str = include_str!("../../.env.example");
const PREFIXES: [&str; 13] = ["SUPERBOT_", "MACHINE_", "INCUS_", "SERVER_BACKUP_", "SMTP_", "SSO_", "SIGNIN_", "TRACES_", "HERMES_", "LINODE_", "NOTIFY_", "PUSH_", "TIER_"];
const SUFFIXES: [&str; 2] = ["_API_KEY", "_BASE_URL"];
const EXTRA: [&str; 8] = ["TZ", "RUST_LOG", "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "STATE_DIRECTORY", "WEB_DIR", "SITE_DIR"];

const README: &str = "SuperBot support bundle
=======================

Made by botd for a support ticket (docs/support/README.md, ADR 0131). Check it before
you send it: every file is plain text.

  version.json        botd's version, OS, uptime, and the harnesses on this server
  config.json         botd's settings from its environment, secrets redacted (other
                      variables are only counted); the settings it started with; tiers
                      and the approval policy
  health.json         the status page's checks and open incidents, the setup checklist,
                      license, approvals waiting, runs, machines, database and backups
  logs.jsonl          the newest lines botd logged since it started (at most 2,000)
  audit-summary.json  the last 7 days of the audit log, counted by action and outcome,
                      and the newest failures and denials (no names, emails or addresses)
  manifest.json       what is in this bundle and how much was redacted

Never in it: secret values, chats, prompts, tool inputs, files, emails, IP addresses,
or the licensee's name. A secret-named setting shows as [redacted], an email as [email],
an IP address as [ip] (loopback and 0.0.0.0 stay), the licensee as [name]; URLs keep
only their scheme, host and port. If you find anything you would rather not send,
delete it and say so in the ticket.
";

// Redaction

/// A setting as the bundle shows it, and whether anything was taken out.
pub fn setting(name: &str, value: &str) -> (String, bool) {
    let upper = name.to_ascii_uppercase();
    if value.trim().is_empty() {
        return (value.to_string(), false);
    }
    if PERSONAL.contains(&upper.as_str()) {
        return (MARK.into(), true);
    }
    let path = PATH_SUFFIXES.iter().any(|s| upper.ends_with(s));
    if !path && (redact::names_secret(&upper) || SECRET_WORDS.iter().any(|w| upper.contains(w))) {
        return (MARK.into(), true);
    }
    let shown = if looks_random(value.trim()) { MARK.to_string() } else { scrub_text(value) };
    let changed = shown != value;
    (shown, changed)
}

/// Free text with credentials taken out: known secret values and the tokens botd issues,
/// credential shapes (`Bearer x`, `token=x`, `user:pass@`, known key prefixes), private
/// keys, URL paths and queries (where some services put the secret), and emails.
pub fn scrub_text(s: &str) -> String {
    if s.contains("PRIVATE KEY") || s.contains("AGE-SECRET-KEY-") {
        return MARK.into();
    }
    let s = audit::redact_text(s);
    let s = origins_only(&s);
    let s = redact::text(&s).into_owned();
    mask_ips(&mask_emails(&s))
}

/// A generated-looking value (an API key, a password from a generator): long, one word
/// of letters, digits and base64 punctuation, with both letters and digits.
fn looks_random(v: &str) -> bool {
    v.len() >= 24
        && v.bytes().all(|c| c.is_ascii_alphanumeric() || b"+=_-".contains(&c))
        && v.bytes().any(|c| c.is_ascii_digit())
        && v.bytes().any(|c| c.is_ascii_alphabetic())
}

/// Every URL cut to its scheme, host and port: a Slack or Teams webhook's secret is its path.
pub fn origins_only(s: &str) -> String {
    let ends = |c: char| c == ',' || c == '"' || c == '\'' || c.is_whitespace();
    let (mut out, mut rest) = (String::with_capacity(s.len()), s);
    while let Some(i) = rest.find("://") {
        let host_start = i + 3;
        let after = &rest[host_start..];
        let host_len = after.find(|c: char| ends(c) || matches!(c, '/' | '?' | '#')).unwrap_or(after.len());
        let tail = &after[host_len..];
        let path_len = if tail.starts_with(['/', '?', '#']) { tail.find(ends).unwrap_or(tail.len()) } else { 0 };
        out.push_str(&rest[..host_start + host_len]);
        match &tail[..path_len] {
            "" | "/" => out.push_str(&tail[..path_len]),
            _ => out.push_str("/[redacted]"),
        }
        rest = &tail[path_len..];
    }
    out.push_str(rest);
    out
}

/// Email addresses become `[email]`.
pub fn mask_emails(s: &str) -> String {
    let b = s.as_bytes();
    let local = |c: u8| c.is_ascii_alphanumeric() || b"._%+-".contains(&c);
    let domain = |c: u8| c.is_ascii_alphanumeric() || b".-".contains(&c);
    let (mut out, mut copied, mut i) = (String::with_capacity(s.len()), 0, 0);
    while let Some(at) = s[i..].find('@').map(|n| i + n) {
        let start = (copied..at).rev().take_while(|&k| local(b[k])).last().unwrap_or(at);
        let len = b[at + 1..].iter().take_while(|&&c| domain(c)).count();
        let dom = s[at + 1..at + 1 + len].trim_end_matches(['.', '-']);
        if start < at && dom.contains('.') && !dom.starts_with(['.', '-']) {
            out.push_str(&s[copied..start]);
            out.push_str("[email]");
            copied = at + 1 + dom.len();
            i = copied;
        } else {
            i = at + 1;
        }
    }
    out.push_str(&s[copied..]);
    out
}

/// IP addresses become `[ip]`, a port after an IPv4 address stays. Loopback and unspecified
/// addresses (`127.0.0.1`, `0.0.0.0`, `::1`) say nothing about a network and stay too.
pub fn mask_ips(s: &str) -> String {
    let b = s.as_bytes();
    let part = |c: u8| c.is_ascii_hexdigit() || c == b'.' || c == b':';
    let word = |c: u8| c.is_ascii_alphanumeric() || c == b'_';
    let (mut out, mut copied, mut i) = (String::with_capacity(s.len()), 0, 0);
    while i < b.len() {
        if !part(b[i]) {
            i += 1;
            continue;
        }
        let end = i + b[i..].iter().take_while(|&&c| part(c)).count();
        let inside_word = (i > 0 && word(b[i - 1])) || b.get(end).is_some_and(|&c| word(c));
        let run = s[i..end].trim_end_matches(['.', ':']);
        let ip = run.parse::<std::net::IpAddr>().ok().map(|ip| (ip, run.len())).or_else(|| {
            let (v4, _) = run.split_once(':')?;
            v4.parse::<std::net::Ipv4Addr>().ok().map(|ip| (ip.into(), v4.len()))
        });
        if let (false, Some((ip, len))) = (inside_word, ip)
            && !ip.is_loopback()
            && !ip.is_unspecified()
        {
            out.push_str(&s[copied..i]);
            out.push_str("[ip]");
            copied = i + len;
        }
        i = end;
    }
    out.push_str(&s[copied..]);
    out
}

/// Every string in `v` through [`scrub_text`] and [`hide`]. Keys are botd's own and stay.
fn scrub_value(v: Value, names: &[String]) -> Value {
    match v {
        Value::String(s) => Value::String(hide(&scrub_text(&s), names)),
        Value::Array(a) => Value::Array(a.into_iter().map(|v| scrub_value(v, names)).collect()),
        Value::Object(o) => Value::Object(o.into_iter().map(|(k, v)| (k, scrub_value(v, names))).collect()),
        other => other,
    }
}

/// `names` (the licensee) become `[name]`, in any ASCII case, as whole words only, so a
/// short name like `IT` leaves `audit-summary.json` alone.
pub fn hide(s: &str, names: &[String]) -> String {
    let word = |c: Option<char>| c.is_some_and(|c| c.is_alphanumeric() || c == '_');
    let mut out = s.to_string();
    for n in names {
        let (lower, needle) = (out.to_ascii_lowercase(), n.to_ascii_lowercase());
        let mut next = String::with_capacity(out.len());
        let mut at = 0;
        for (i, _) in lower.match_indices(&needle) {
            let end = i + needle.len();
            if i < at || word(out[..i].chars().next_back()) || word(out[end..].chars().next()) {
                continue;
            }
            next.push_str(&out[at..i]);
            next.push_str("[name]");
            at = i + needle.len();
        }
        next.push_str(&out[at..]);
        out = next;
    }
    out
}

/// What the bundle hides by name: the licensee, which the license, the setup checklist and
/// the settings botd started with all repeat.
fn names(app: &App) -> Vec<String> {
    app.license.status().claims.map(|c| c.sub.trim().to_string()).filter(|n| n.len() >= 2).into_iter().collect()
}

/// The environment as the bundle shows it, sorted, and the names whose values were changed.
pub fn environment(vars: &[(String, String)]) -> (BTreeMap<String, String>, Vec<String>, usize) {
    let mut shown = BTreeMap::new();
    let mut redacted = Vec::new();
    let mut other = 0;
    for (k, v) in vars {
        if !ours(k) {
            other += 1;
            continue;
        }
        let (value, changed) = setting(k, v);
        if changed {
            redacted.push(k.clone());
        }
        shown.insert(k.clone(), value);
    }
    redacted.sort();
    (shown, redacted, other)
}

/// Whether a variable is one of botd's settings, so the bundle shows it.
pub fn ours(name: &str) -> bool {
    static NAMES: std::sync::LazyLock<std::collections::HashSet<&'static str>> = std::sync::LazyLock::new(|| DOCUMENTED.lines().filter_map(documented).collect());
    NAMES.contains(name) || EXTRA.contains(&name) || PREFIXES.iter().any(|p| name.starts_with(p)) || SUFFIXES.iter().any(|x| name.ends_with(x))
}

/// The setting a `.env.example` line documents, set or commented out: `PORT=3000`, `# TZ=UTC`.
fn documented(line: &str) -> Option<&str> {
    let (name, _) = line.trim_start_matches(['#', ' ']).split_once('=')?;
    let plain = name.bytes().next().is_some_and(|c| c.is_ascii_uppercase()) && name.bytes().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == b'_');
    plain.then_some(name)
}

// The files

fn rfc3339(ms: i64) -> String {
    chrono::DateTime::from_timestamp_millis(ms).map(|t| t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)).unwrap_or_default()
}

fn last_start(app: &App) -> Option<AuditEvent> {
    let f = audit::Filter { actions: vec!["server.started".into()], ..Default::default() };
    app.db.audit_events(&f, 1, false).pop()
}

fn version(app: &App, started: Option<&AuditEvent>, now_ms: i64) -> Value {
    json!({
        "product": "SuperBot",
        "botd": env!("CARGO_PKG_VERSION"),
        "bundleFormat": FORMAT,
        "createdAt": rfc3339(now_ms),
        "os": std::env::consts::OS,
        "arch": std::env::consts::ARCH,
        "kernel": std::fs::read_to_string("/proc/sys/kernel/osrelease").ok().map(|k| k.trim().to_string()),
        "container": std::path::Path::new("/.dockerenv").exists(),
        "startedAt": started.map(|e| e.time.clone()),
        "uptimeSeconds": started.map(|e| (now_ms - e.at).max(0) / 1000),
        "harnesses": { "installed": crate::adapters::installed(), "default": app.cfg.default_harness },
    })
}

fn config(app: &App, vars: &[(String, String)], started: Option<&AuditEvent>) -> (Value, usize) {
    let (env, redacted, other) = environment(vars);
    let t = app.tiers();
    let policy = app.db.global_policy();
    let n = redacted.len();
    let v = json!({
        "environment": env,
        "redacted": redacted,
        "otherVariables": other,
        "startedWith": started.map(|e| e.details.clone()),
        "tiers": {
            "source": t.source,
            "default": t.default_tier().name,
            "names": t.all().iter().map(|x| x.name.clone()).collect::<Vec<_>>(),
            "summary": t.describe(),
        },
        "policy": { "mode": policy.mode, "sandbox": policy.sandbox, "timeoutMinutes": policy.timeout_minutes, "classes": policy.classes },
    });
    (v, n)
}

fn health(app: &App, setup: Value, now_ms: i64) -> Value {
    let policy = app.db.global_policy();
    let (pending, oldest) = app.db.approvals_pending();
    let (held, waiting) = app.slots.totals();
    let r = app.db.metrics().recent(now_ms, RECENT_MINUTES);
    let license = app.license.status();
    let machines = app.control_plane.get().filter(|cp| cp.enabled()).map(|cp| {
        let mut hosts: BTreeMap<String, usize> = BTreeMap::new();
        for h in app.db.machine_hosts() {
            *hosts.entry(h.state).or_default() += 1;
        }
        json!({
            "controlPlane": cp.describe(),
            "byState": app.db.machine_state_counts().into_iter().collect::<BTreeMap<_, _>>(),
            "hostsByState": hosts,
            "rpoBreachesOpen": app.db.machine_rpo_breaches_open().len(),
        })
    });
    json!({
        "status": crate::status::snapshot(app, now_ms),
        "setup": setup,
        "license": { "summary": license.summary(), "detail": license.detail(), "warnings": license.warnings(app.db.active_seats()) },
        "approvals": {
            "mode": policy.mode,
            "pending": pending,
            "oldestPendingSeconds": oldest.map(|t| (now_ms - t).max(0) / 1000),
            "timeoutMinutes": policy.timeout_minutes,
        },
        "runs": { "holdingSlots": held, "waiting": waiting, "capPerComputer": app.run_cap.get().copied().flatten() },
        "lastMinutes": {
            "minutes": RECENT_MINUTES,
            "requests": r.requests, "errors": r.errors,
            "runsDone": r.runs_done, "runsFailed": r.runs_failed,
            "noticesSent": r.notices_sent, "noticesFailed": r.notices_failed,
        },
        "machines": machines,
        "database": crate::database_encryption::view(app),
        "serverBackups": app.server_backups.get().map(|sb| crate::server_backups::view(app, sb)),
    })
}

/// An audit reason as the bundle shows it: a code (`not_linked`, `wrong_tenant`) as is,
/// anything else as `[text]`, since free-text reasons can quote a tool's input (a path,
/// a command) or a person.
pub fn reason_code(r: &str) -> &str {
    let code = !r.is_empty() && r.len() <= 64 && r.bytes().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || b"_.:-".contains(&c));
    if code { r } else { "[text]" }
}

/// The last `AUDIT_DAYS` of the audit log, counted, with the newest failures and denials:
/// what happened and how it ended, never who (names, emails, subjects) or from where.
fn audit_summary(app: &App, now_ms: i64) -> (Value, usize) {
    let from = now_ms - AUDIT_DAYS * 86_400_000;
    let events = app.db.audit_events(&audit::Filter { from: Some(from), ..Default::default() }, AUDIT_SCAN, false);
    let mut outcomes: BTreeMap<&str, u64> = BTreeMap::new();
    let mut actions: BTreeMap<&str, BTreeMap<&str, u64>> = BTreeMap::new();
    for e in &events {
        *outcomes.entry(&e.outcome).or_default() += 1;
        *actions.entry(&e.action).or_default().entry(&e.outcome).or_default() += 1;
    }
    let mut by_action: Vec<(&str, u64, &BTreeMap<&str, u64>)> = actions.iter().map(|(a, o)| (*a, o.values().sum(), o)).collect();
    by_action.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(b.0)));
    let problems: Vec<Value> = events
        .iter()
        .filter(|e| e.outcome != "success")
        .take(PROBLEMS)
        .map(|e| {
            json!({
                "time": e.time,
                "action": e.action,
                "outcome": e.outcome,
                "actorKind": e.actor_kind,
                "authMethod": e.auth_method,
                "idp": e.idp,
                "targetType": e.target_type,
                "reason": e.details.get("reason").and_then(Value::as_str).map(reason_code),
                "traceId": e.details.get("traceId").and_then(Value::as_str),
            })
        })
        .collect();
    let v = json!({
        "from": rfc3339(from),
        "to": rfc3339(now_ms),
        "days": AUDIT_DAYS,
        "events": events.len(),
        "truncated": events.len() as i64 >= AUDIT_SCAN,
        "retentionDays": app.db.audit_retention(),
        "byOutcome": outcomes,
        "byAction": by_action.iter().map(|(a, n, o)| json!({ "action": a, "total": n, "outcomes": o })).collect::<Vec<_>>(),
        "recentProblems": problems,
    });
    (v, events.len())
}

/// The newest log lines, each scrubbed field by field so it stays one JSON object.
fn logs(names: &[String]) -> (String, usize) {
    let lines = crate::obs::log::recent::lines();
    let n = lines.len();
    let mut out = String::new();
    for l in lines {
        let v = serde_json::from_str::<Value>(&l).unwrap_or_else(|_| json!({ "msg": l }));
        out.push_str(&redact::value(scrub_value(v, names)).to_string());
        out.push('\n');
    }
    (out, n)
}

/// JSON, pretty, with every string through botd's redaction once more.
fn json_file(v: Value, names: &[String]) -> Vec<u8> {
    let v = redact::value(scrub_value(v, names));
    let mut s = serde_json::to_string_pretty(&v).unwrap_or_default();
    s.push('\n');
    redact::text(&s).into_owned().into_bytes()
}

pub struct Bundle {
    pub name: String,
    pub tar: Vec<u8>,
    pub files: Vec<(String, usize)>,
    pub redacted_settings: usize,
    pub log_lines: usize,
    pub audit_events: usize,
}

/// The whole bundle. `vars` is botd's environment; `setup`, the setup wizard's checklist.
pub fn build(app: &App, vars: &[(String, String)], setup: Value, now_ms: i64) -> Bundle {
    let stamp = chrono::DateTime::from_timestamp_millis(now_ms).map(|t| t.format("%Y%m%dT%H%M%SZ").to_string()).unwrap_or_default();
    let name = format!("superbot-support-{stamp}");
    let started = last_start(app);
    let (config, redacted_settings) = config(app, vars, started.as_ref());
    let (audit, audit_events) = audit_summary(app, now_ms);
    let names = names(app);
    let (logs, log_lines) = logs(&names);
    let mut files: Vec<(&str, Vec<u8>)> = vec![
        ("README.txt", README.as_bytes().to_vec()),
        ("version.json", json_file(version(app, started.as_ref(), now_ms), &names)),
        ("config.json", json_file(config, &names)),
        ("health.json", json_file(health(app, setup, now_ms), &names)),
        ("logs.jsonl", redact::text(&logs).into_owned().into_bytes()),
        ("audit-summary.json", json_file(audit, &names)),
    ];
    let listed: Vec<(String, usize)> = files.iter().map(|(n, b)| (n.to_string(), b.len())).collect();
    let manifest = json!({
        "format": FORMAT,
        "botd": env!("CARGO_PKG_VERSION"),
        "createdAt": rfc3339(now_ms),
        "files": listed.iter().map(|(n, b)| json!({ "name": n, "bytes": b })).collect::<Vec<_>>(),
        "redactedSettings": redacted_settings,
        "logLines": log_lines,
        "auditEvents": audit_events,
    });
    files.push(("manifest.json", json_file(manifest, &[])));
    let entries: Vec<(String, Vec<u8>)> = files.into_iter().map(|(n, b)| (format!("{name}/{n}"), b)).collect();
    let files = entries.iter().map(|(n, b)| (n.clone(), b.len())).collect();
    Bundle { tar: tar(&entries, (now_ms / 1000).max(0) as u64), name, files, redacted_settings, log_lines, audit_events }
}

// Tar

/// A ustar archive of plain files, readable by any `tar`. Names must fit in 100 bytes.
pub fn tar(entries: &[(String, Vec<u8>)], mtime: u64) -> Vec<u8> {
    fn octal(field: &mut [u8], v: u64) {
        let w = field.len() - 1;
        field[..w].copy_from_slice(format!("{v:0w$o}").as_bytes());
        field[w] = 0;
    }
    let mut out = Vec::new();
    for (name, data) in entries {
        assert!(name.len() <= 100, "tar names fit in 100 bytes: {name}");
        let mut h = [0u8; 512];
        h[..name.len()].copy_from_slice(name.as_bytes());
        octal(&mut h[100..108], 0o600);
        octal(&mut h[108..116], 0);
        octal(&mut h[116..124], 0);
        octal(&mut h[124..136], data.len() as u64);
        octal(&mut h[136..148], mtime);
        h[148..156].fill(b' ');
        h[156] = b'0';
        h[257..263].copy_from_slice(b"ustar\0");
        h[263..265].copy_from_slice(b"00");
        h[265..273].copy_from_slice(b"superbot");
        h[297..305].copy_from_slice(b"superbot");
        let sum: u32 = h.iter().map(|&b| u32::from(b)).sum();
        h[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
        out.extend_from_slice(&h);
        out.extend_from_slice(data);
        out.resize(out.len().div_ceil(512) * 512, 0);
    }
    out.resize(out.len() + 1024, 0);
    out
}

// HTTP

type Peer = Option<Extension<ConnectInfo<SocketAddr>>>;

/// `GET /api/support/bundle` (admins): the bundle as a tarball to save. Audited.
pub async fn bundle(State(app): State<AppState>, Extension(a): Extension<Arc<Auth>>, Extension(by): Extension<Who>, headers: HeaderMap, peer: Peer) -> Res<Response> {
    let setup = crate::setup::report(&app, &a, &headers, peer.map(|Extension(ConnectInfo(p))| p.ip()));
    let setup = json!({ "checklist": setup["checklist"], "done": setup["done"], "total": setup["total"] });
    let vars: Vec<(String, String)> = std::env::vars_os().filter_map(|(k, v)| Some((k.into_string().ok()?, v.into_string().ok()?))).collect();
    let built = {
        let app = app.clone();
        tokio::task::spawn_blocking(move || build(&app, &vars, setup, now())).await
    }
    .map_err(|e| ApiError(StatusCode::INTERNAL_SERVER_ERROR, format!("Couldn't make the support bundle: {e}")))?;
    app.db.record(&by.event("support.bundle_created").details(json!({
        "name": built.name,
        "bytes": built.tar.len(),
        "files": built.files.iter().map(|(n, _)| n.rsplit('/').next().unwrap_or(n)).collect::<Vec<_>>(),
        "redactedSettings": built.redacted_settings,
        "logLines": built.log_lines,
        "auditEvents": built.audit_events,
    })));
    let mut res = built.tar.into_response();
    let h = res.headers_mut();
    h.insert(header::CONTENT_TYPE, HeaderValue::from_static("application/x-tar"));
    if let Ok(v) = HeaderValue::from_str(&format!("attachment; filename=\"{}.tar\"", built.name)) {
        h.insert(header::CONTENT_DISPOSITION, v);
    }
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    h.insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    Ok(res)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    fn shown(name: &str, value: &str) -> String {
        setting(name, value).0
    }

    #[test]
    fn secret_named_settings_lose_their_values() {
        for (k, v) in [
            ("ANTHROPIC_API_KEY", "sk-ant-api03-abcdefghijklmnop"),
            ("AUTH_PASSWORD", "correct horse battery staple"),
            ("LINODE_TOKEN", "abc"),
            ("SSO_ENTRA_CLIENT_SECRET", "s3cr3t-value"),
            ("SERVER_BACKUP_S3_SECRET_ACCESS_KEY", "wJalrXUtnFEMI/K7MDENG"),
            ("AWS_ACCESS_KEY_ID", "AKIAIOSFODNN7EXAMPLE"),
            ("INCUS_CLIENT_KEY", "-----BEGIN EC PRIVATE KEY-----\nMHc\n-----END EC PRIVATE KEY-----"),
            ("ERROR_REPORT_DSN", "https://public@o1.ingest.example.com/2"),
            ("NOTIFY_WEBHOOK_URL", "https://hooks.slack.com/services/T0/B0/XYZ"),
            ("NOTIFY_WEBHOOK_URL_BOT_A1B2C3D4", "https://example.com/hook"),
            ("LICENSE_KEY", "eyJhbGciOiJFZERTQSJ9.e30.sig"),
            ("OWNER_EMAIL", "owner@example.com"),
            ("USER_NAME", "Ada Lovelace"),
            ("TRACES_OTLP_HEADERS", "x-honeycomb-team=abc123,x-honeycomb-dataset=production"),
        ] {
            assert_eq!(setting(k, v), (MARK.to_string(), true), "{k}");
        }
    }

    #[test]
    fn where_a_secret_lives_stays_and_plain_settings_are_kept() {
        assert_eq!(setting("SUPERBOT_MASTER_KEY_FILE", "/etc/superbot/master.key"), ("/etc/superbot/master.key".into(), false));
        assert_eq!(setting("LICENSE_KEY_FILE", "/data/license.key"), ("/data/license.key".into(), false));
        for (k, v) in [("PORT", "3000"), ("ISOLATION", "users"), ("MACHINE_TIERS", "starter=g6-standard-1,pro=g6-standard-2"), ("TZ", "Europe/London"), ("DEFAULT_TIER", "starter"), ("CORS_ORIGINS", "https://a.example.com,https://b.example.com")] {
            assert_eq!(setting(k, v), (v.to_string(), false), "{k}");
        }
        assert_eq!(setting("EMPTY", ""), (String::new(), false));
    }

    #[test]
    fn secrets_are_found_by_shape_in_innocent_settings() {
        assert_eq!(shown("SMTP_URL", "smtps://mailer:hunter2hunter2@smtp.example.com:465"), "smtps://[redacted]@smtp.example.com:465");
        assert_eq!(shown("SOME_URL", "https://example.com/v1/hooks/abc123?sig=xyz"), "https://example.com/[redacted]");
        assert_eq!(shown("SSO_PUBLIC_URL", "https://bots.example.com/"), "https://bots.example.com/");
        assert_eq!(shown("RANDOM_THING", "Zx81kq0Pp2LmN4vB7cR9tY3wQ6"), MARK, "generated-looking");
        assert_eq!(shown("EXTRA_ARGS", "--header Authorization: Bearer abcdef123456"), "--header Authorization: Bearer [redacted]");
        assert_eq!(shown("HELPER", "token=abcdef123456 mode=fast"), "token=[redacted] mode=fast");
        assert_eq!(shown("GITHUBISH", "ghp_abcdefghijklmnopqrstuvwxyz0123"), MARK);
        assert_eq!(shown("ALERT_TO", "ops@example.com, oncall@example.org"), "[email], [email]");
        let session = crate::users::new_secret(crate::users::SESSION_PREFIX);
        assert_eq!(shown("LEFTOVER", &format!("x {session}")), "x [redacted]", "a session token botd issued");
    }

    #[test]
    fn a_known_secret_is_redacted_wherever_it_shows() {
        let secret = format!("plain-words-{}", crate::random_hex(6));
        redact::register(&secret);
        assert_eq!(shown("INNOCENT_NAME", &format!("before {secret} after")), "before [redacted] after");
        assert_eq!(scrub_value(json!({ "deep": [{ "x": secret.clone() }] }), &[]), json!({ "deep": [{ "x": "[redacted]" }] }));
        redact::forget(&secret);
    }

    #[test]
    fn the_environment_is_sorted_and_names_what_it_changed() {
        let vars: Vec<(String, String)> =
            [("PORT", "3000"), ("OPENAI_API_KEY", "sk-proj-abc"), ("LS_COLORS", "x"), ("bad name", "y"), ("ALLOWED_HOSTS", "a.example.com"), ("TMUX", "/tmp/t"), ("SSO_OKTA_ISSUER", "https://example.okta.com")]
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect();
        let (env, redacted, other) = environment(&vars);
        assert_eq!(env.keys().collect::<Vec<_>>(), ["ALLOWED_HOSTS", "OPENAI_API_KEY", "PORT", "SSO_OKTA_ISSUER"]);
        assert_eq!(env["OPENAI_API_KEY"], MARK);
        assert_eq!(redacted, ["OPENAI_API_KEY"]);
        assert_eq!(other, 3, "the host's own variables are only counted");
    }

    #[test]
    fn botds_settings_come_from_the_documented_example() {
        let names: Vec<&str> = DOCUMENTED.lines().filter_map(documented).collect();
        assert!(names.len() > 150, "{}", names.len());
        for name in ["PORT", "AUTH_PASSWORD", "TZ", "ISOLATION", "SUPERBOT_MASTER_KEY_FILE", "ERROR_REPORT_DSN"] {
            assert!(names.contains(&name) && ours(name), "{name}");
        }
        assert_eq!(documented("# A comment, not a setting: x=y"), None);
        for name in ["HOME", "USER", "TMUX", "SSH_AUTH_SOCK", "HOSTNAME", "INVOCATION_ID"] {
            assert!(!ours(name), "{name}");
        }
        assert!(ours("ANTHROPIC_API_KEY") && ours("OPENAI_BASE_URL") && ours("SUPERBOT_ANYTHING"));
    }

    #[test]
    fn emails_and_urls_are_cut_without_eating_their_neighbours() {
        assert_eq!(mask_emails("from a.b+c@mail.example.co.uk."), "from [email].");
        assert_eq!(mask_emails("@handle and x@y and me@host"), "@handle and x@y and me@host", "not addresses");
        assert_eq!(mask_emails("é a@b.io é"), "é [email] é");
        assert_eq!(origins_only("see https://h.example.com:8443/a/b, then http://x"), "see https://h.example.com:8443/[redacted], then http://x");
        assert_eq!(origins_only("\"https://h/p?q\""), "\"https://h/[redacted]\"");
    }

    #[test]
    fn ip_addresses_are_masked_and_nothing_else() {
        assert_eq!(mask_ips("HOST=10.0.0.5, peer 203.0.113.9:8443."), "HOST=[ip], peer [ip]:8443.");
        assert_eq!(mask_ips("[2001:db8::1]:443 or fe80::1%eth0 ::ffff:198.51.100.2"), "[[ip]]:443 or [ip]%eth0 [ip]");
        assert_eq!(mask_ips("http://192.168.1.20:3000/x"), "http://[ip]:3000/x");
        let kept = "0.0.0.0 127.0.0.1 [::1]:3000 :: at 18:22:54 on 2026-11-22T18:22:54Z, v0.5.0, 1.5s, superbot::support, deadbeef, cafe:beef, a1.2.3.4, 1.2.3.4b";
        assert_eq!(mask_ips(kept), kept);
        assert_eq!(scrub_text("from 198.51.100.7"), "from [ip]");
        assert_eq!(setting("HOST", "10.1.2.3"), ("[ip]".into(), true));
        assert_eq!(setting("HOST", "0.0.0.0"), ("0.0.0.0".into(), false));
    }

    #[test]
    fn only_reason_codes_leave_the_audit_log() {
        for code in ["not_linked", "wrong_tenant", "mfa.required", "scim:conflict", "http-429"] {
            assert_eq!(reason_code(code), code);
        }
        for text in ["Deletes /clients/Jane Smith/notes.txt outside the workspace", "rm -rf build", "Not_Linked", "", &"a".repeat(65)] {
            assert_eq!(reason_code(text), "[text]", "{text}");
        }
    }

    #[test]
    fn the_licensee_is_hidden_in_any_case() {
        let names = vec!["Acme Ltd".to_string()];
        assert_eq!(hide("Licensed to Acme Ltd; ACME LTD; acme ltd.", &names), "Licensed to [name]; [name]; [name].");
        assert_eq!(hide("Acme é Ltd, Acme Ltdx, xAcme Ltd", &names), "Acme é Ltd, Acme Ltdx, xAcme Ltd", "whole words only");
        let it = vec!["IT".to_string()];
        assert_eq!(hide("audit-summary.json, licensed to IT (it).", &it), "audit-summary.json, licensed to [name] ([name]).");
        assert_eq!(scrub_value(json!({ "a": ["for Acme Ltd"] }), &names), json!({ "a": ["for [name]"] }));
    }

    #[test]
    fn log_lines_stay_json_whatever_they_say() {
        let marker = crate::random_hex(6);
        crate::obs::log::line(crate::obs::log::Level::Info, &format!("Stored secrets: none ({marker}). token=abc123 \"quoted\""));
        crate::obs::log::line(crate::obs::log::Level::Warn, &format!("{marker}-long {}", "é".repeat(5_000)));
        let (out, _) = logs(&[]);
        let mine: Vec<Value> = out.lines().filter(|l| l.contains(&marker)).map(|l| serde_json::from_str(l).expect("each line is JSON")).collect();
        assert_eq!(mine.len(), 2, "{out}");
        assert_eq!(mine[0]["msg"], format!("Stored secrets: [redacted] ({marker}). token=[redacted] \"quoted\""));
        let long = mine[1]["msg"].as_str().unwrap();
        assert!(long.ends_with('…') && long.len() <= 1_024 + '…'.len_utf8(), "cut a field at a time: {}", long.len());
        assert_eq!(mine[1]["level"], "warn");
    }

    /// Reads a ustar archive back: each file's name and contents, checking every checksum.
    pub fn untar(b: &[u8]) -> Vec<(String, Vec<u8>)> {
        let mut out = Vec::new();
        let mut at = 0;
        while at + 512 <= b.len() && b[at..at + 512].iter().any(|&c| c != 0) {
            let h = &b[at..at + 512];
            let field = |r: std::ops::Range<usize>| std::str::from_utf8(&h[r]).unwrap().trim_matches(|c: char| c == '\0' || c == ' ').to_string();
            let mut copy = h.to_vec();
            copy[148..156].fill(b' ');
            let sum: u32 = copy.iter().map(|&c| u32::from(c)).sum();
            assert_eq!(u32::from_str_radix(&field(148..156), 8).unwrap(), sum, "checksum");
            assert_eq!(&h[257..263], b"ustar\0");
            let size = usize::from_str_radix(&field(124..136), 8).unwrap();
            out.push((field(0..100), b[at + 512..at + 512 + size].to_vec()));
            at += 512 + size.div_ceil(512) * 512;
        }
        assert!(b[at..].iter().all(|&c| c == 0) && b.len() - at >= 1024, "two zero blocks end it");
        out
    }

    #[test]
    fn the_tarball_reads_back_and_tar_agrees() {
        let entries = vec![("b/one.txt".to_string(), b"hello\n".to_vec()), ("b/empty".to_string(), Vec::new()), ("b/big.bin".to_string(), vec![7u8; 1500])];
        let t = tar(&entries, 1_700_000_000);
        assert_eq!(t.len() % 512, 0);
        assert_eq!(untar(&t), entries);
        let dir = crate::db::temp_path("support-tar");
        let file = dir.join("t.tar");
        std::fs::write(&file, &t).unwrap();
        if let Ok(o) = std::process::Command::new("tar").arg("-tvf").arg(&file).output() {
            let listed = String::from_utf8_lossy(&o.stdout);
            assert!(o.status.success() && ["b/one.txt", "b/empty", "b/big.bin"].iter().all(|n| listed.contains(n)), "{listed}");
        }
    }
}
