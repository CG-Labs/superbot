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
/// an error tracker's DSN and a webhook URL carry their credential inside.
const SECRET_WORDS: [&str; 5] = ["DSN", "WEBHOOK", "SALT", "PASSPHRASE", "COOKIE"];
/// Settings that say where a secret is kept, not what it is.
const PATH_SUFFIXES: [&str; 3] = ["_FILE", "_PATH", "_DIR"];
/// Process noise that says nothing about botd.
const SKIP: [&str; 2] = ["LS_COLORS", "_"];

const README: &str = "SuperBot support bundle
=======================

Made by botd for a support ticket (docs/support/README.md, ADR 0131). Check it before
you send it: every file is plain text.

  version.json        botd's version, OS, uptime, and the harnesses on this server
  config.json         botd's environment, secrets redacted; the settings it started with;
                      tiers and the approval policy
  health.json         the status page's checks and open incidents, the setup checklist,
                      license, approvals waiting, runs, machines, database and backups
  logs.jsonl          the newest lines botd logged since it started (at most 2,000)
  audit-summary.json  the last 7 days of the audit log, counted by action and outcome,
                      and the newest failures and denials (no names, emails or addresses)
  manifest.json       what is in this bundle and how much was redacted

Never in it: secret values, chats, prompts, tool inputs, files, names, emails or IP
addresses. A secret-named setting shows as [redacted]; URLs keep only their scheme,
host and port. If you find anything you would rather not send, delete it and say so
in the ticket.
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
    mask_emails(&s)
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

/// Every string in `v` through [`scrub_text`]. Keys are botd's own and stay.
fn scrub_value(v: Value) -> Value {
    match v {
        Value::String(s) => Value::String(scrub_text(&s)),
        Value::Array(a) => Value::Array(a.into_iter().map(scrub_value).collect()),
        Value::Object(o) => Value::Object(o.into_iter().map(|(k, v)| (k, scrub_value(v))).collect()),
        other => other,
    }
}

/// The environment as the bundle shows it, sorted, and the names whose values were changed.
pub fn environment(vars: &[(String, String)]) -> (BTreeMap<String, String>, Vec<String>) {
    let mut shown = BTreeMap::new();
    let mut redacted = Vec::new();
    for (k, v) in vars {
        let named = k.bytes().next().is_some_and(|c| c.is_ascii_alphabetic() || c == b'_') && k.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_');
        if !named || SKIP.contains(&k.as_str()) {
            continue;
        }
        let (value, changed) = setting(k, v);
        if changed {
            redacted.push(k.clone());
        }
        shown.insert(k.clone(), value);
    }
    redacted.sort();
    (shown, redacted)
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
    let (env, redacted) = environment(vars);
    let t = app.tiers();
    let policy = app.db.global_policy();
    let n = redacted.len();
    let v = json!({
        "environment": env,
        "redacted": redacted,
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
                "reason": e.details.get("reason").and_then(Value::as_str).map(|r| audit::clip(r, 120)),
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

fn logs() -> (String, usize) {
    let lines = crate::obs::log::recent::lines();
    let n = lines.len();
    let mut out = String::new();
    for l in lines {
        out.push_str(&scrub_text(&l));
        out.push('\n');
    }
    (out, n)
}

/// JSON, pretty, with every string through botd's redaction once more.
fn json_file(v: Value) -> Vec<u8> {
    let v = redact::value(scrub_value(v));
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
    let (logs, log_lines) = logs();
    let mut files: Vec<(&str, Vec<u8>)> = vec![
        ("README.txt", README.as_bytes().to_vec()),
        ("version.json", json_file(version(app, started.as_ref(), now_ms))),
        ("config.json", json_file(config)),
        ("health.json", json_file(health(app, setup, now_ms))),
        ("logs.jsonl", redact::text(&logs).into_owned().into_bytes()),
        ("audit-summary.json", json_file(audit)),
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
    files.push(("manifest.json", json_file(manifest)));
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
        assert_eq!(scrub_value(json!({ "deep": [{ "x": secret.clone() }] })), json!({ "deep": [{ "x": "[redacted]" }] }));
        redact::forget(&secret);
    }

    #[test]
    fn the_environment_is_sorted_and_names_what_it_changed() {
        let vars: Vec<(String, String)> = [("PORT", "3000"), ("OPENAI_API_KEY", "sk-proj-abc"), ("LS_COLORS", "x"), ("bad name", "y"), ("ALLOWED_HOSTS", "a.example.com")]
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        let (env, redacted) = environment(&vars);
        assert_eq!(env.keys().collect::<Vec<_>>(), ["ALLOWED_HOSTS", "OPENAI_API_KEY", "PORT"]);
        assert_eq!(env["OPENAI_API_KEY"], MARK);
        assert_eq!(redacted, ["OPENAI_API_KEY"]);
    }

    #[test]
    fn emails_and_urls_are_cut_without_eating_their_neighbours() {
        assert_eq!(mask_emails("from a.b+c@mail.example.co.uk."), "from [email].");
        assert_eq!(mask_emails("@handle and x@y and me@host"), "@handle and x@y and me@host", "not addresses");
        assert_eq!(mask_emails("é a@b.io é"), "é [email] é");
        assert_eq!(origins_only("see https://h.example.com:8443/a/b, then http://x"), "see https://h.example.com:8443/[redacted], then http://x");
        assert_eq!(origins_only("\"https://h/p?q\""), "\"https://h/[redacted]\"");
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
