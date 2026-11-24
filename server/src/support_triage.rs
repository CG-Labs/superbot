//! Support triage (ADR 0220, #60): the Provider's first read of a customer's support
//! bundle. `botctl support-triage` opens a bundle from `botctl support-bundle` (ADR 0131)
//! or `botd support bundle` (ADR 0187), as the tar the customer sent, gzipped or not, or
//! unpacked, and says what it shows: each problem with the evidence in the bundle, the
//! severity it suggests (docs/support/severity.md), the runbook to open and what to do
//! next, then the questions the bundle can't answer. Support still sets the severity.
//!
//! A bundle comes from outside, so reading it is bounded: only the files bundles have,
//! only plain files, at most `MAX_BYTES` in all, and every string from it is cut and
//! stripped of control characters before it's printed. It never writes the bundle to
//! disk. Runs offline: no botd, no ticket system.

use crate::support_report::{Plan, Target, parse_time};
use chrono::{DateTime, FixedOffset, SecondsFormat, Utc};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::path::Path;

pub const USAGE: &str = "Usage: botctl support-triage <bundle.tar | bundle.tar.gz | folder | -> [--plan <plan>]
    [--latest <version>] [--production] [--as-of <time>] [--markdown | --json]";

/// A bundle, unpacked, at most this big; botd's own are well under 1 MiB.
pub const MAX_BYTES: u64 = 64 << 20;
/// The newest bundle formats this reads: `botctl support-bundle`'s, `botd support bundle`'s.
pub const ONLINE_FORMAT: u64 = 2;
pub const OFFLINE_FORMAT: u64 = 1;
/// Every file either bundle has. Anything else in the tar is left unread.
pub const FILES: [&str; 11] =
    ["README.txt", "version.json", "config.json", "health.json", "health-score.json", "health-score-history.json", "logs.jsonl", "audit-summary.json", "check.json", "logs.txt", "manifest.json"];
const ONLINE_FILES: [&str; 7] = ["version.json", "config.json", "health.json", "health-score.json", "health-score-history.json", "logs.jsonl", "audit-summary.json"];
const OFFLINE_FILES: [&str; 4] = ["version.json", "check.json", "config.json", "logs.txt"];
/// Longest text taken from the bundle into the triage, in characters.
const TEXT: usize = 240;
/// A bundle older than this may not show the problem as it is now.
const STALE_HOURS: i64 = 24;
/// botd started this recently before the bundle: a restart, or a crash it came back from.
const RESTART_SECONDS: i64 = 600;
/// Most frequent log messages listed.
const TOP: usize = 5;
/// Audit failures and denials of one kind in the bundle's 7 days that make a warning.
const AUDIT_WARN: u64 = 10;

/// The reason codes only SAML sign-in gives (runbook-saml.md's reasons table). Codes both
/// runbooks have (`not_linked`, `idp_error`, `wrong_audience`, `unknown_state`) go to the
/// sign-in one, and to the SAML one too when the failures were SAML sign-ins.
pub const SAML_REASONS: [&str; 14] = [
    "authn_context",
    "bad_encryption",
    "bad_signature",
    "cbc_unsigned_response",
    "encrypted_assertion",
    "expired",
    "idp_initiated_loop",
    "in_response_to_mismatch",
    "not_yet_valid",
    "transient_subject",
    "unsigned",
    "weak_algorithm",
    "wrong_destination",
    "wrong_recipient",
];

// Reading a bundle

/// The bundle's files by name, and the folder they were in.
#[derive(Debug, Default)]
pub struct Bundle {
    pub name: String,
    files: BTreeMap<String, Vec<u8>>,
}

impl Bundle {
    #[cfg(test)]
    pub fn from_files(name: &str, files: Vec<(&str, Vec<u8>)>) -> Bundle {
        Bundle { name: name.into(), files: files.into_iter().map(|(n, b)| (n.to_string(), b)).collect() }
    }

    fn text(&self, name: &str) -> Option<String> {
        self.files.get(name).map(|b| String::from_utf8_lossy(b).into_owned())
    }

    /// A JSON file: `None` if it isn't there, `Err` if it is but doesn't parse.
    fn json(&self, name: &str) -> Option<Result<Value, String>> {
        self.files.get(name).map(|b| serde_json::from_slice(b).map_err(|e| format!("{name} isn't JSON: {e}")))
    }

    fn has(&self, name: &str) -> bool {
        self.files.contains_key(name)
    }
}

/// A file's name inside a bundle: `<folder>/<file>` or `<file>`, else not one of ours.
fn place(path: &str) -> Option<(Option<&str>, &str)> {
    let parts: Vec<&str> = path.trim_start_matches("./").split('/').filter(|p| !p.is_empty()).collect();
    match parts.as_slice() {
        [file] if FILES.contains(file) => Some((None, file)),
        [folder, file] if FILES.contains(file) && *folder != ".." => Some((Some(folder), file)),
        _ => None,
    }
}

fn too_big() -> String {
    format!("over {} MiB unpacked: not a support bundle", MAX_BYTES >> 20)
}

/// Reads at most `MAX_BYTES`, refusing anything larger.
fn bounded(r: impl Read, what: &str) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    r.take(MAX_BYTES + 1).read_to_end(&mut out).map_err(|e| format!("{what}: {e}"))?;
    if out.len() as u64 > MAX_BYTES {
        return Err(format!("{what}: {}", too_big()));
    }
    Ok(out)
}

/// A bundle from a tar's bytes, gzipped or not.
pub fn read_tar(bytes: &[u8]) -> Result<Bundle, String> {
    let plain;
    let bytes = if bytes.starts_with(&[0x1f, 0x8b]) {
        plain = bounded(flate2::read::GzDecoder::new(bytes), "the gzip")?;
        &plain[..]
    } else {
        bytes
    };
    let mut b = Bundle::default();
    let mut total = 0u64;
    let mut archive = tar::Archive::new(bytes);
    for entry in archive.entries().map_err(|e| format!("not a tar file: {e}"))? {
        let entry = entry.map_err(|e| format!("a damaged tar file: {e}"))?;
        if !entry.header().entry_type().is_file() {
            continue;
        }
        let path = entry.path().map_err(|e| format!("a damaged tar file: {e}"))?.to_string_lossy().into_owned();
        let Some((folder, file)) = place(&path) else { continue };
        total = total.saturating_add(entry.size());
        if total > MAX_BYTES {
            return Err(too_big());
        }
        if b.files.contains_key(file) {
            return Err(format!("two {file} in the tar: send one bundle at a time"));
        }
        let data = bounded(entry, file)?;
        if let Some(folder) = folder {
            b.name = folder.to_string();
        }
        b.files.insert(file.to_string(), data);
    }
    if b.files.is_empty() {
        return Err("no support bundle files in it (version.json, health.json, check.json and the rest)".into());
    }
    Ok(b)
}

/// A bundle someone unpacked: the folder with its files, or the folder holding that one.
pub fn read_dir(dir: &Path) -> Result<Bundle, String> {
    let shown = dir.display();
    let holds = |d: &Path| FILES.iter().any(|f| d.join(f).is_file());
    let dir = if holds(dir) {
        dir.to_path_buf()
    } else {
        let inner: Vec<_> = std::fs::read_dir(dir).map_err(|e| format!("{shown}: {e}"))?.filter_map(Result::ok).map(|e| e.path()).filter(|p| p.is_dir() && holds(p)).collect();
        match inner.as_slice() {
            [one] => one.clone(),
            [] => return Err(format!("{shown} has no support bundle files")),
            _ => return Err(format!("{shown} has more than one bundle: name the one to read")),
        }
    };
    let mut b = Bundle { name: dir.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default(), ..Default::default() };
    let mut total = 0u64;
    for f in FILES {
        let p = dir.join(f);
        let Ok(meta) = std::fs::symlink_metadata(&p) else { continue };
        if !meta.is_file() {
            continue;
        }
        total = total.saturating_add(meta.len());
        if total > MAX_BYTES {
            return Err(too_big());
        }
        let file = std::fs::File::open(&p).map_err(|e| format!("{}: {e}", p.display()))?;
        b.files.insert(f.to_string(), bounded(file, f)?);
    }
    Ok(b)
}

// Options

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Format {
    Text,
    Markdown,
    Json,
}

#[derive(Clone, Debug)]
pub struct Options {
    pub plan: Option<Plan>,
    pub latest: Option<(u64, u64, u64)>,
    pub production: bool,
    pub as_of: DateTime<Utc>,
}

impl Options {
    pub fn new(as_of: DateTime<Utc>) -> Options {
        Options { plan: None, latest: None, production: false, as_of }
    }
}

/// `1.2.3`, `v1.2`, `1.2.3-rc.1`: the numbers.
pub fn semver(v: &str) -> Option<(u64, u64, u64)> {
    let core = v.trim().trim_start_matches('v').split(['-', '+']).next()?;
    let mut n = core.split('.').map(|p| p.parse::<u64>().ok());
    let major = n.next()??;
    let minor = n.next().unwrap_or(Some(0))?;
    let patch = n.next().unwrap_or(Some(0))?;
    n.next().is_none().then_some((major, minor, patch))
}

/// `botctl support-triage ...`: the bundle (`-` for stdin), the options and the format.
pub fn parse_args(rest: &[&str], now: DateTime<Utc>) -> Result<(String, Options, Format), String> {
    let mut o = Options::new(now);
    let (mut source, mut format) = (None, Format::Text);
    let mut it = rest.iter();
    while let Some(&a) = it.next() {
        let mut value = |flag: &str| it.next().copied().ok_or_else(|| format!("{flag} needs a value\n{USAGE}"));
        match a {
            "--plan" => {
                let v = value(a)?;
                o.plan = Some(Plan::parse(v).ok_or_else(|| format!("--plan {v}: one of self-host, starter, pro, max, enterprise"))?);
            }
            "--latest" => {
                let v = value(a)?;
                o.latest = Some(semver(v).ok_or_else(|| format!("--latest {v} isn't a version like 1.4.2"))?);
            }
            "--as-of" => {
                let v = value(a)?;
                o.as_of = parse_time(v, FixedOffset::east_opt(0).unwrap()).ok_or_else(|| format!("--as-of {v} isn't a time"))?;
            }
            "--production" => o.production = true,
            "--markdown" => format = Format::Markdown,
            "--json" => format = Format::Json,
            "-h" | "--help" => return Err(USAGE.into()),
            s if s.starts_with("--") => return Err(format!("unknown option {s}\n{USAGE}")),
            s if source.is_none() => source = Some(s.to_string()),
            s => return Err(format!("one bundle at a time: {s}\n{USAGE}")),
        }
    }
    Ok((source.ok_or_else(|| USAGE.to_string())?, o, format))
}

// Findings

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    Info,
    Warn,
    Fail,
}

impl Level {
    pub fn as_str(self) -> &'static str {
        match self {
            Level::Info => "info",
            Level::Warn => "warn",
            Level::Fail => "fail",
        }
    }
}

/// One thing the bundle shows.
#[derive(Clone, Debug, PartialEq)]
pub struct Finding {
    pub id: String,
    pub level: Level,
    /// The severity this alone suggests, 1 to 4, if it suggests one.
    pub severity: Option<u8>,
    pub summary: String,
    /// Where in the bundle: a file, and what in it.
    pub evidence: String,
    /// Under docs/, as `support/runbook-x.md#anchor`.
    pub runbooks: Vec<&'static str>,
    pub next: Option<String>,
}

impl Finding {
    fn new(id: impl Into<String>, level: Level, severity: Option<u8>, summary: impl Into<String>, evidence: impl Into<String>) -> Finding {
        Finding { id: id.into(), level, severity, summary: summary.into(), evidence: evidence.into(), runbooks: Vec::new(), next: None }
    }

    fn runbook(mut self, r: &'static str) -> Finding {
        if !self.runbooks.contains(&r) {
            self.runbooks.push(r);
        }
        self
    }

    fn next(mut self, n: impl Into<String>) -> Finding {
        self.next = Some(n.into());
        self
    }

    fn json(&self) -> Value {
        json!({
            "id": self.id, "level": self.level.as_str(), "severity": self.severity, "summary": self.summary,
            "evidence": self.evidence, "runbooks": self.runbooks.iter().map(|r| format!("docs/{r}")).collect::<Vec<_>>(), "next": self.next,
        })
    }
}

/// Bundle text as it may be shown: control characters out, one line, at most `TEXT` long.
pub fn clean(s: &str) -> String {
    let one: String = s.chars().map(|c| if c.is_control() { ' ' } else { c }).collect();
    let one = one.split_whitespace().collect::<Vec<_>>().join(" ");
    if one.chars().count() <= TEXT { one } else { format!("{}…", one.chars().take(TEXT).collect::<String>()) }
}

fn str_at<'a>(v: &'a Value, key: &str) -> Option<&'a str> {
    v.get(key).and_then(Value::as_str)
}

fn u64_at(v: &Value, key: &str) -> u64 {
    v.get(key).and_then(Value::as_u64).unwrap_or(0)
}

/// `1 warning`, `3 warnings`.
fn many(n: u64, one: &str, more: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { more })
}

fn percent(part: u64, whole: u64) -> u64 {
    part.saturating_mul(100).checked_div(whole).unwrap_or(0)
}

fn duration(secs: i64) -> String {
    match secs {
        s if s < 120 => format!("{s} s"),
        s if s < 7200 => format!("{} min", s / 60),
        s if s < 172_800 => format!("{} h", s / 3600),
        s => format!("{} days", s / 86_400),
    }
}

fn ms_time(v: &Value) -> Option<String> {
    match v {
        Value::Number(n) => n.as_i64().and_then(DateTime::from_timestamp_millis).map(|t| t.to_rfc3339_opts(SecondsFormat::Secs, true)),
        Value::String(s) => Some(clean(s)),
        _ => None,
    }
}

/// `code ×n, code ×n`, from `[{ "code": .., "count": .. }]`.
fn reasons(v: Option<&Value>) -> Vec<(String, u64)> {
    v.and_then(Value::as_array).into_iter().flatten().filter_map(|r| Some((clean(str_at(r, "code")?), u64_at(r, "count")))).collect()
}

fn counted(list: &[(String, u64)]) -> String {
    list.iter().map(|(c, n)| format!("{c} ×{n}")).collect::<Vec<_>>().join(", ")
}

// The rules

/// What a status page component's level suggests, and the runbook.
fn component(id: &str, status: &str) -> Option<(Level, Option<u8>, &'static str)> {
    let book = match id {
        "api" | "database" => "support/runbook-machine-down.md#the-server-itself",
        "machines" => "support/runbook-machine-down.md",
        "runners" => "support/runbook-harness-outage.md",
        "notifications" => "support/runbook-approvals-stuck.md",
        _ => "support/runbook-major-incident.md",
    };
    let server = matches!(id, "api" | "database");
    Some(match status {
        "major_outage" if server => (Level::Fail, Some(1), book),
        "major_outage" | "partial_outage" if id != "notifications" => (Level::Fail, Some(2), book),
        "major_outage" => (Level::Fail, Some(2), book),
        "partial_outage" | "degraded_performance" => (Level::Warn, Some(3), book),
        "under_maintenance" => (Level::Info, None, book),
        _ => return None,
    })
}

fn status_rules(health: &Value, out: &mut Vec<Finding>) {
    let status = &health["status"];
    for c in status["components"].as_array().into_iter().flatten() {
        let (Some(id), Some(level)) = (str_at(c, "id"), str_at(c, "status")) else { continue };
        let Some((lvl, sev, book)) = component(id, level) else { continue };
        let name = str_at(c, "name").map(clean).unwrap_or_else(|| clean(id));
        let note = str_at(c, "note").map(|n| format!(": {}", clean(n))).unwrap_or_default();
        let mut f =
            Finding::new(format!("status.{}", clean(id)), lvl, sev, format!("{name} is {}{note}", level.replace('_', " ")), format!("health.json status.components {}", clean(id))).runbook(book);
        if sev == Some(1) {
            f = f.runbook("support/runbook-major-incident.md").next("Run it as a Severity 1: post on the status page within 15 minutes.");
        }
        out.push(f);
    }
    for i in status["incidents"].as_array().into_iter().flatten().filter(|i| str_at(i, "state").is_some_and(|s| s != "resolved")) {
        let title = str_at(i, "title").map(clean).unwrap_or_default();
        let since = ms_time(&i["createdAt"]).map(|t| format!(", since {t}")).unwrap_or_default();
        let (impact, state) = (str_at(i, "impact").map(clean).unwrap_or_default(), str_at(i, "state").map(clean).unwrap_or_default());
        out.push(
            Finding::new("status.incident", Level::Info, None, format!("Open status page incident \"{title}\" ({impact}, {state}{since})"), "health.json status.incidents")
                .runbook("support/incident-review.md")
                .next("It's already being worked on: link this ticket to it rather than opening a second incident."),
        );
    }
}

fn health_rules(health: &Value, version: Option<&Value>, out: &mut Vec<Finding>) {
    let last = &health["lastMinutes"];
    let minutes = u64_at(last, "minutes").max(1);
    let (pending, oldest) = (u64_at(&health["approvals"], "pending"), health["approvals"]["oldestPendingSeconds"].as_i64());
    let (sent, failed) = (u64_at(last, "noticesSent"), u64_at(last, "noticesFailed"));
    if pending > 0 && failed > 0 && sent == 0 {
        out.push(
            Finding::new(
                "approvals.unheard",
                Level::Fail,
                Some(2),
                format!("{} waiting and every notification failed in the last {minutes} minutes ({failed}): Bots wait for people who never hear", many(pending, "approval", "approvals")),
                "health.json approvals, lastMinutes",
            )
            .runbook("support/runbook-approvals-stuck.md"),
        );
    } else {
        if failed > 0 {
            out.push(
                Finding::new(
                    "notifications.failed",
                    Level::Warn,
                    Some(3),
                    format!("{failed} of {} notifications failed in the last {minutes} minutes", failed.saturating_add(sent)),
                    "health.json lastMinutes",
                )
                .runbook("support/runbook-approvals-stuck.md"),
            );
        }
        if pending > 0 && oldest.is_some_and(|s| s >= 1800) {
            let age = duration(oldest.unwrap_or(0));
            out.push(
                Finding::new("approvals.waiting", Level::Warn, Some(3), format!("{} waiting, the oldest for {age}", many(pending, "approval", "approvals")), "health.json approvals")
                    .runbook("support/runbook-approvals-stuck.md"),
            );
        }
    }
    let waiting = u64_at(&health["runs"], "waiting");
    if waiting > 0 {
        let cap = health["runs"]["capPerComputer"].as_u64().map(|c| format!(" (at most {c} at once per computer)")).unwrap_or_default();
        out.push(
            Finding::new("runs.waiting", Level::Warn, Some(3), format!("{} waiting for a slot{cap}", many(waiting, "run", "runs")), "health.json runs")
                .runbook("support/runbook-run-limits-egress.md#run-limits"),
        );
    }
    let (requests, errors) = (u64_at(last, "requests"), u64_at(last, "errors"));
    if requests >= 20 && percent(errors, requests) >= 5 {
        let p = percent(errors, requests);
        let (lvl, sev) = if p >= 25 { (Level::Fail, Some(2)) } else { (Level::Warn, Some(3)) };
        out.push(
            Finding::new("api.errors", lvl, sev, format!("{errors} of {requests} requests ({p}%) failed in the last {minutes} minutes"), "health.json lastMinutes")
                .runbook("support/runbook-machine-down.md#the-server-itself")
                .next("Ask for the X-Request-Id of a failing request; it matches botd's log line."),
        );
    }
    let (done, runs_failed) = (u64_at(last, "runsDone"), u64_at(last, "runsFailed"));
    let runs = done.saturating_add(runs_failed);
    if runs >= 4 && percent(runs_failed, runs) >= 20 {
        let p = percent(runs_failed, runs);
        let (lvl, sev) = if p >= 50 { (Level::Fail, Some(2)) } else { (Level::Warn, Some(3)) };
        out.push(
            Finding::new("runs.failing", lvl, sev, format!("{runs_failed} of {} Bot runs ({p}%) failed in the last {minutes} minutes", runs), "health.json lastMinutes")
                .runbook("support/runbook-harness-outage.md"),
        );
    }
    let machines = &health["machines"];
    let errored = u64_at(&machines["byState"], "error");
    if errored > 0 {
        out.push(
            Finding::new("machines.error", Level::Warn, Some(3), format!("{} in error", many(errored, "user's machine is", "users' machines are")), "health.json machines.byState")
                .runbook("support/runbook-machine-down.md#one-machine"),
        );
    }
    let hosts_down = u64_at(&machines["hostsByState"], "down").saturating_add(u64_at(&machines["hostsByState"], "lost"));
    if hosts_down > 0 {
        out.push(
            Finding::new("machines.hosts", Level::Fail, Some(2), format!("{} down or lost", many(hosts_down, "Incus host", "Incus hosts")), "health.json machines.hostsByState")
                .runbook("support/runbook-machine-down.md#a-whole-incus-host"),
        );
    }
    let breaches = u64_at(machines, "rpoBreachesOpen");
    if breaches > 0 {
        out.push(
            Finding::new(
                "machines.rpo",
                Level::Fail,
                Some(2),
                format!("{} past {} backup RPO", many(breaches, "user's machine", "users' machines"), if breaches == 1 { "its" } else { "their" }),
                "health.json machines.rpoBreachesOpen",
            )
            .runbook("support/runbook-machine-down.md#restore-one-machine"),
        );
    }
    let none = version.and_then(|v| v["harnesses"]["installed"].as_array()).is_some_and(Vec::is_empty);
    if none && machines.is_null() {
        out.push(
            Finding::new("harness.none", Level::Fail, Some(2), "No harness is installed on the server and it has no managed machines: no Bot can run", "version.json harnesses.installed")
                .runbook("support/runbook-harness-outage.md"),
        );
    }
    let checklist = &health["setup"]["checklist"];
    let open: Vec<String> = checklist.as_array().into_iter().flatten().filter(|i| i["done"] == false).filter_map(|i| str_at(i, "label").or(str_at(i, "id")).map(clean)).collect();
    if !open.is_empty() {
        let total = checklist.as_array().map_or(0, Vec::len);
        out.push(
            Finding::new("setup.open", Level::Info, Some(4), format!("Setup checklist {} of {total} done; open: {}", total - open.len(), open.join("; ")), "health.json setup.checklist")
                .runbook("support/onboarding.md")
                .next("Raise them with the customer's admin; the TAM tracks them at the next health check."),
        );
    }
}

/// The runbook a set of sign-in reason codes points at.
fn sign_in_books(codes: &[String], saml_used: bool) -> Vec<&'static str> {
    let saml = saml_used || codes.iter().any(|c| SAML_REASONS.contains(&c.as_str()));
    let other = codes.iter().any(|c| !SAML_REASONS.contains(&c.as_str()));
    let mut books = Vec::new();
    if saml {
        books.push("support/runbook-saml.md#reasons-and-fixes");
    }
    if other || !saml {
        books.push("support/runbook-sign-in.md#reasons-and-fixes");
    }
    books
}

fn signal_rules(score: &Value, out: &mut Vec<Finding>) {
    for s in score["signals"].as_array().into_iter().flatten() {
        let (Some(id), Some(status)) = (str_at(s, "id"), str_at(s, "status")) else { continue };
        let risk = match status {
            "risk" => true,
            "watch" => false,
            _ => continue,
        };
        let facts = &s["facts"];
        let summary = str_at(s, "summary").map(clean).unwrap_or_default();
        let label = str_at(s, "label").map(clean).unwrap_or_else(|| clean(id));
        let word = if risk { "at risk" } else { "watch" };
        let f = |lvl: Level, sev: Option<u8>| Finding::new(format!("signal.{}", clean(id)), lvl, sev, format!("{label} {word}: {summary}"), format!("health-score.json signals {}", clean(id)));
        let finding = match id {
            "adoption" => f(Level::Info, None).runbook("support/health-score.md#adoption").next("For the TAM: raise it at the next check-in."),
            "runs" => {
                let refused = reasons(facts.get("refusedReasons"));
                let mut x = f(if risk { Level::Warn } else { Level::Info }, risk.then_some(3)).runbook("support/runbook-harness-outage.md");
                if refused.iter().any(|(c, _)| c.starts_with("egress")) || u64_at(facts, "runLimited") > 0 {
                    x = x.runbook("support/runbook-run-limits-egress.md");
                }
                if !refused.is_empty() {
                    x.summary.push_str(&format!(" Refused: {}.", counted(&refused)));
                }
                x
            }
            "identity" => {
                let (sso, scim) = (reasons(facts.get("ssoReasons")), reasons(facts.get("scimReasons")));
                let mut x = f(if risk { Level::Fail } else { Level::Warn }, Some(if risk { 2 } else { 3 }));
                if u64_at(facts, "ssoFailed") > 0 || !sso.is_empty() {
                    for b in sign_in_books(&sso.iter().map(|(c, _)| c.clone()).collect::<Vec<_>>(), false) {
                        x = x.runbook(b);
                    }
                }
                if u64_at(facts, "scimFailed") > 0 || u64_at(facts, "scimTenantsExpiring") > 0 || !scim.is_empty() {
                    x = x.runbook("sso/scim.md");
                }
                let mut why = Vec::new();
                if !sso.is_empty() {
                    why.push(format!("sign-in {}", counted(&sso)));
                }
                if !scim.is_empty() {
                    why.push(format!("SCIM {}", counted(&scim)));
                }
                if !why.is_empty() {
                    x.summary.push_str(&format!(" Reasons: {}.", why.join("; ")));
                }
                x.runbook("support/health-score.md#identity")
            }
            "backups" => {
                let x = if risk { f(Level::Fail, Some(2)) } else { f(Level::Warn, None) };
                x.runbook("support/runbook-machine-down.md").runbook("ops/backup-restore.md")
            }
            "approvals" => f(if risk { Level::Warn } else { Level::Info }, risk.then_some(3)).runbook("support/runbook-approvals-stuck.md"),
            "license" => {
                let x = if risk { f(Level::Fail, Some(2)) } else { f(Level::Info, Some(4)) };
                x.runbook("support/health-score.md#license").next("Renewals and seats go to the account owner; `botctl license` on the server shows the detail.")
            }
            _ => f(if risk { Level::Warn } else { Level::Info }, None),
        };
        out.push(finding);
    }
    if str_at(score, "band") == Some("at_risk") {
        let n = score["score"].as_u64().map(|n| n.to_string()).unwrap_or_else(|| "?".into());
        out.push(
            Finding::new("score.at_risk", Level::Info, None, format!("Health score {n} of 100: at risk"), "health-score.json score, band")
                .runbook("support/escalation.md")
                .next("Tell the TAM and the support manager: the customer's owner hears this week with a plan."),
        );
    }
}

fn history_rules(history: &Value, out: &mut Vec<Finding>) {
    let t = &history["trend"];
    let Some(change) = t["change"].as_i64() else { return };
    let band = |k: &str| str_at(t, k).map(clean).unwrap_or_default();
    if change <= -15 || (band("fromBand") == "healthy" && band("toBand") != "healthy") {
        let worse: Vec<String> = t["worse"].as_array().into_iter().flatten().filter_map(Value::as_str).map(clean).collect();
        let worse = if worse.is_empty() { String::new() } else { format!("; worse: {}", worse.join(", ")) };
        out.push(
            Finding::new(
                "score.falling",
                Level::Warn,
                None,
                format!(
                    "Health score fell {} points, from {} ({}) on {} to {} ({}) on {}{worse}",
                    change.saturating_neg(),
                    t["fromScore"],
                    band("fromBand"),
                    band("from"),
                    t["toScore"],
                    band("toBand"),
                    band("to")
                ),
                "health-score-history.json trend",
            )
            .runbook("support/health-score.md#history")
            .next("Something changed when it started to fall: ask what (an upgrade, the identity provider, a policy)."),
        );
    }
}

/// Where an audit action's failures and denials point: a group and its runbook.
fn audit_group(action: &str) -> (&'static str, &'static str, Option<&'static str>) {
    let (family, _) = action.split_once('.').unwrap_or((action, ""));
    if action.contains("residency") || action == "user.region_change_refused" {
        return ("residency", "residency refusals", Some("support/runbook-residency.md#refusals-and-fixes"));
    }
    match family {
        "auth" | "sso" => ("sign_in", "sign-in failures", None),
        "scim" => ("scim", "SCIM provisioning failures", Some("sso/scim.md")),
        "access" | "role" => ("access", "access denials", Some("support/runbook-custom-roles.md#why-a-holder-is-refused")),
        "approval" => ("approvals", "approval failures", Some("support/runbook-approvals-stuck.md")),
        "harness" => ("harness", "harness failures", Some("support/runbook-harness-outage.md")),
        "license" => ("license", "license refusals", Some("support/health-score.md#license")),
        "machine" | "isolation" if action != "machine.run_limited" => ("machines", "machine failures", Some("support/runbook-machine-down.md")),
        _ if matches!(action, "bot.run_refused" | "routine.run_refused" | "machine.run_limited" | "usage.token_limit_reached") => {
            ("run_limits", "runs refused or held to limits", Some("support/runbook-run-limits-egress.md"))
        }
        "bot" if action.ends_with("_refused") => ("access", "access denials", Some("support/runbook-custom-roles.md#why-a-holder-is-refused")),
        _ => ("other", "other failures and denials", None),
    }
}

fn audit_rules(audit: &Value, out: &mut Vec<Finding>) {
    struct Group {
        what: &'static str,
        book: Option<&'static str>,
        actions: BTreeMap<String, u64>,
        reasons: BTreeMap<String, u64>,
        saml: bool,
    }
    let mut groups: BTreeMap<&'static str, Group> = BTreeMap::new();
    for a in audit["byAction"].as_array().into_iter().flatten() {
        let Some(action) = str_at(a, "action") else { continue };
        let bad: u64 = a["outcomes"].as_object().into_iter().flatten().filter(|(o, _)| o.as_str() != "success").filter_map(|(_, n)| n.as_u64()).fold(0u64, u64::saturating_add);
        if bad == 0 {
            continue;
        }
        let (key, what, book) = audit_group(action);
        let g = groups.entry(key).or_insert_with(|| Group { what, book, actions: BTreeMap::new(), reasons: BTreeMap::new(), saml: false });
        let n = g.actions.entry(clean(action)).or_default();
        *n = n.saturating_add(bad);
        g.saml |= action.starts_with("sso.saml") || action.starts_with("auth.slo") || action == "auth.saml_idp_initiated";
    }
    for p in audit["recentProblems"].as_array().into_iter().flatten() {
        let Some(action) = str_at(p, "action") else { continue };
        let Some(g) = groups.get_mut(audit_group(action).0) else { continue };
        if let Some(r) = str_at(p, "reason") {
            *g.reasons.entry(clean(r)).or_default() += 1;
        }
        g.saml |= str_at(p, "authMethod") == Some("saml");
    }
    let days = u64_at(audit, "days");
    let to = str_at(audit, "to").map(clean).unwrap_or_default();
    for (key, g) in groups {
        let total = g.actions.values().copied().fold(0u64, u64::saturating_add);
        let mut actions: Vec<(String, u64)> = g.actions.into_iter().collect();
        actions.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        let mut reasons: Vec<(String, u64)> = g.reasons.into_iter().collect();
        reasons.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        let why = if reasons.is_empty() { String::new() } else { format!(" (newest reasons: {})", counted(&reasons[..reasons.len().min(TOP)])) };
        let lvl = if total >= AUDIT_WARN && key != "other" { Level::Warn } else { Level::Info };
        let mut f = Finding::new(
            format!("audit.{key}"),
            lvl,
            None,
            format!("{total} {} in the {days} days to {to}: {}{why}", g.what, counted(&actions[..actions.len().min(TOP)])),
            "audit-summary.json byAction, recentProblems",
        );
        if key == "sign_in" {
            let codes: Vec<String> = reasons.iter().map(|(c, _)| c.clone()).collect();
            for b in sign_in_books(&codes, g.saml) {
                f = f.runbook(b);
            }
        }
        if let Some(b) = g.book {
            f = f.runbook(b);
        }
        out.push(f);
    }
    if audit["truncated"] == true {
        out.push(
            Finding::new("audit.truncated", Level::Info, None, "The audit summary hit its limit: counts cover only the newest events", "audit-summary.json truncated")
                .next("`botctl audit` on the server has the rest."),
        );
    }
}

/// A log message with its numbers and ids taken out, so repeats count together.
fn shape(msg: &str) -> String {
    let mut out = String::new();
    let mut digits = false;
    for c in clean(msg).chars() {
        if c.is_ascii_digit() {
            if !digits {
                out.push('#');
            }
            digits = true;
        } else {
            digits = false;
            out.push(c);
        }
    }
    out
}

/// A log line's level and message: JSON lines as botd writes them (after any prefix a
/// collector adds), else the text, with `None` for a level text logs don't carry.
fn log_line(line: &str) -> Option<(Option<String>, String)> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    if let Some(at) = line.find('{')
        && let Ok(v) = serde_json::from_str::<Value>(&line[at..])
        && let Some(msg) = str_at(&v, "msg")
    {
        return Some((str_at(&v, "level").map(str::to_ascii_lowercase), msg.to_string()));
    }
    Some((None, line.to_string()))
}

fn sounds_bad(msg: &str) -> bool {
    let m = msg.to_ascii_lowercase();
    ["error", "fail", "refused", "can't", "couldn't", "cannot", "denied", "panic", "timed out", "unreachable"].iter().any(|w| m.contains(w))
}

fn log_rules(file: &str, text: &str, out: &mut Vec<Finding>) {
    if text.trim_start().starts_with("# no logs") {
        out.push(
            Finding::new("logs.none", Level::Info, None, "No log lines in the bundle", file)
                .runbook("support/support-check.md#the-offline-bundle")
                .next("Ask for them: `botd support bundle --logs botd.log` with the service's log saved as botd.log (journalctl -u superbot -o cat, or docker compose logs botd)."),
        );
        return;
    }
    let (mut lines, mut problems, mut panics) = (0u64, 0u64, 0u64);
    let mut top: BTreeMap<String, u64> = BTreeMap::new();
    for (level, msg) in text.lines().filter_map(log_line) {
        lines += 1;
        let panic = msg.contains("panicked");
        panics += u64::from(panic);
        let bad = panic
            || match level.as_deref() {
                Some(l) => matches!(l, "warn" | "warning" | "error" | "fatal"),
                None => sounds_bad(&msg),
            };
        if bad {
            problems += 1;
            *top.entry(shape(&msg)).or_default() += 1;
        }
    }
    if panics > 0 {
        out.push(
            Finding::new(
                "logs.panic",
                Level::Warn,
                None,
                format!("botd panicked {} in its newest {}", if panics == 1 { "once".to_string() } else { format!("{panics} times") }, many(lines, "log line", "log lines")),
                file,
            )
            .runbook("support/escalation.md")
            .next("A panic is a bug: send the bundle to level 3 through the issue tracker, and link the issue."),
        );
    }
    if problems > 0 {
        let mut top: Vec<(String, u64)> = top.into_iter().collect();
        top.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        let list = top.iter().take(TOP).map(|(m, n)| format!("×{n} {m}")).collect::<Vec<_>>().join(" | ");
        let what = if file == "logs.jsonl" { many(problems, "warning", "warnings") } else { many(problems, "line that reports a failure", "lines that report a failure") };
        out.push(Finding::new("logs.problems", Level::Info, None, format!("{what} in the newest {}; most frequent: {list}", many(lines, "log line", "log lines")), file));
    }
}

/// `botd support check`'s findings, as the offline bundle carries them.
fn check_rules(check: &Value, out: &mut Vec<Finding>) {
    for c in check["findings"].as_array().into_iter().flatten() {
        let (Some(id), Some(status)) = (str_at(c, "id"), str_at(c, "status")) else { continue };
        let summary = str_at(c, "summary").map(clean).unwrap_or_default();
        let not_running = id == "botd" && status != "ok" && summary.contains("isn't running");
        let (lvl, sev, book) = match (id, status) {
            ("botd", _) if not_running => (Level::Fail, Some(1), "support/runbook-machine-down.md#the-server-itself"),
            ("data_dir" | "database" | "master_key", "fail") => (Level::Fail, Some(1), "support/runbook-server-restore.md"),
            ("disk", "fail") => (Level::Fail, Some(1), "support/runbook-machine-down.md#the-server-itself"),
            ("backups", "fail") => (Level::Fail, Some(2), "ops/backup-restore.md"),
            ("license", "fail") => (Level::Fail, Some(2), "support/health-score.md#license"),
            (_, "fail") => (Level::Fail, Some(2), "support/support-check.md#the-checks"),
            ("database" | "disk", "warn") => (Level::Warn, Some(3), "support/support-check.md#the-checks"),
            (_, "warn") => (Level::Warn, None, "support/support-check.md#the-checks"),
            _ => continue,
        };
        let mut f = Finding::new(format!("check.{}", clean(id)), lvl, sev, format!("{}: {summary}", clean(id)), format!("check.json findings {}", clean(id))).runbook(book);
        if let Some(fix) = str_at(c, "fix") {
            f = f.next(clean(fix));
        }
        if not_running {
            f.summary.push_str(" (unless it was stopped on purpose, for an upgrade or a restore)");
            f = f.runbook("support/runbook-major-incident.md");
        }
        out.push(f);
    }
    if check["beforeUpgrade"] == true {
        out.push(
            Finding::new("check.before_upgrade", Level::Info, None, "Checked before an upgrade (--before-upgrade)", "check.json beforeUpgrade").runbook("support/runbook-upgrade.md#before-an-upgrade"),
        );
    }
}

fn version_rules(v: &Value, kind: Kind, o: &Options, out: &mut Vec<Finding>) {
    let known = match kind {
        Kind::Online => ONLINE_FORMAT,
        Kind::Offline => OFFLINE_FORMAT,
    };
    if let Some(f) = v["bundleFormat"].as_u64().filter(|f| *f > known) {
        out.push(
            Finding::new(
                "bundle.format",
                Level::Info,
                None,
                format!("Made by a newer botd (bundle format {f}; this botctl reads {known}): files or fields it doesn't know are left out"),
                "version.json bundleFormat",
            )
            .next("Upgrade botctl for a complete triage."),
        );
    }
    let botd = str_at(v, "botd").unwrap_or_default();
    if let (Some(latest), Some(theirs)) = (o.latest, semver(botd))
        && theirs < latest
    {
        let (a, b, c) = latest;
        let lvl = if (theirs.0, theirs.1) < (latest.0, latest.1) { Level::Warn } else { Level::Info };
        out.push(
            Finding::new("version.behind", lvl, None, format!("botd {} is behind the latest release, {a}.{b}.{c}", clean(botd)), "version.json botd")
                .runbook("support/runbook-upgrade.md#before-an-upgrade")
                .next("Check the changelog for a fix before digging: an upgrade may be the answer."),
        );
    }
    if let Some(up) = v["uptimeSeconds"].as_i64().filter(|s| (0..RESTART_SECONDS).contains(s)) {
        out.push(
            Finding::new(
                "botd.restarted",
                Level::Info,
                None,
                format!("botd started {} before the bundle was made: a restart, or a crash it came back from", duration(up)),
                "version.json uptimeSeconds",
            )
            .next("Ask whether someone restarted it; the logs from before are in journalctl or docker compose logs, not the bundle."),
        );
    }
}

// The triage

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Online,
    Offline,
}

impl Kind {
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::Online => "online",
            Kind::Offline => "offline",
        }
    }
}

pub struct Triage {
    pub name: String,
    pub kind: Kind,
    pub botd: Option<String>,
    pub created_at: Option<DateTime<Utc>>,
    pub as_of: DateTime<Utc>,
    pub testing: bool,
    pub production: bool,
    pub plan: Option<Plan>,
    pub findings: Vec<Finding>,
    pub missing: Vec<&'static str>,
}

/// Severity names, as severity.md has them.
pub fn severity_name(s: u8) -> &'static str {
    match s {
        1 => "Critical",
        2 => "High",
        3 => "Normal",
        _ => "Low",
    }
}

/// The triage of a bundle.
pub fn triage(b: &Bundle, o: &Options) -> Result<Triage, String> {
    let kind = if b.has("check.json") || b.has("logs.txt") {
        Kind::Offline
    } else if ["health.json", "health-score.json", "audit-summary.json", "logs.jsonl"].iter().any(|f| b.has(f)) {
        Kind::Online
    } else {
        return Err("neither health.json nor check.json is in it: not a support bundle, or too much was taken out".into());
    };
    let mut out = Vec::new();
    let mut read = |name: &str| -> Option<Value> {
        match b.json(name)? {
            Ok(v) => Some(v),
            Err(e) => {
                out.push(Finding::new("bundle.unreadable", Level::Warn, None, clean(&e), name.to_string()).next("Ask for a fresh bundle, sent as made."));
                None
            }
        }
    };
    let version = read("version.json");
    let (health, score, history, audit, check) = match kind {
        Kind::Online => (read("health.json"), read("health-score.json"), read("health-score-history.json"), read("audit-summary.json"), None),
        Kind::Offline => (None, None, None, None, read("check.json")),
    };
    let mut findings = out;
    if let Some(v) = &version {
        version_rules(v, kind, o, &mut findings);
    }
    if let Some(h) = &health {
        status_rules(h, &mut findings);
        health_rules(h, version.as_ref(), &mut findings);
    }
    if let Some(s) = &score {
        signal_rules(s, &mut findings);
    }
    if let Some(h) = &history {
        history_rules(h, &mut findings);
    }
    if let Some(a) = &audit {
        audit_rules(a, &mut findings);
    }
    if let Some(c) = &check {
        check_rules(c, &mut findings);
    }
    let log_file = if kind == Kind::Online { "logs.jsonl" } else { "logs.txt" };
    if let Some(t) = b.text(log_file) {
        log_rules(log_file, &t, &mut findings);
    }
    let created_at = version.as_ref().and_then(|v| str_at(v, "createdAt")).and_then(|t| DateTime::parse_from_rfc3339(t).ok()).map(|t| t.with_timezone(&Utc));
    if let Some(c) = created_at {
        let hours = (o.as_of - c).num_hours();
        if hours >= STALE_HOURS {
            findings.push(
                Finding::new("bundle.stale", Level::Info, None, format!("The bundle was made {} before this triage", duration(hours * 3600)), "version.json createdAt")
                    .next("If the problem is happening now, ask for a fresh one."),
            );
        }
    }
    let testing = health.as_ref().is_some_and(|h| h["license"]["summary"]["testing"] == true)
        || check.as_ref().is_some_and(|c| c["findings"].as_array().into_iter().flatten().any(|f| f["id"] == "license" && f["details"]["edition"] == "testing"));
    findings.sort_by(|a, b| b.level.cmp(&a.level).then(a.severity.unwrap_or(9).cmp(&b.severity.unwrap_or(9))));
    let expected: &[&str] = if kind == Kind::Online { &ONLINE_FILES } else { &OFFLINE_FILES };
    let missing = expected.iter().copied().filter(|f| !b.has(f)).collect();
    Ok(Triage {
        name: if b.name.is_empty() { "(unnamed)".into() } else { clean(&b.name) },
        kind,
        botd: version.as_ref().and_then(|v| str_at(v, "botd")).map(clean),
        created_at,
        as_of: o.as_of,
        testing,
        production: o.production,
        plan: o.plan,
        findings,
        missing,
    })
}

impl Triage {
    /// Whether testing mode holds the suggestion to Severity 3 (severity.md: Severity 1 and
    /// 2 are for production).
    fn capped(&self) -> bool {
        self.testing && !self.production && self.findings.iter().any(|f| f.severity.is_some_and(|s| s < 3))
    }

    /// The severity the bundle suggests, and the findings that set it.
    pub fn severity(&self) -> Option<(u8, Vec<&Finding>)> {
        let top = self.findings.iter().filter_map(|f| f.severity).min()?;
        let by: Vec<&Finding> = self.findings.iter().filter(|f| f.severity == Some(top)).collect();
        Some((if self.capped() { top.max(3) } else { top }, by))
    }

    /// Whether the bundle suggests Severity 1 or 2, after testing mode's cap.
    pub fn failed(&self) -> bool {
        self.severity().is_some_and(|(s, _)| s <= 2)
    }

    fn runbooks(&self) -> Vec<String> {
        let mut seen = BTreeSet::new();
        let mut out = Vec::new();
        for f in &self.findings {
            for r in &f.runbooks {
                let page = r.split('#').next().unwrap_or(r);
                if page.starts_with("support/runbook-") && seen.insert(page) {
                    out.push(format!("docs/{page}"));
                }
            }
        }
        out
    }

    fn target(&self) -> Option<String> {
        let (plan, (sev, _)) = (self.plan?, self.severity()?);
        let agreed = if plan == Plan::Enterprise { " (the Enterprise default; the agreement's target wins)" } else { "" };
        Some(format!("First response for Severity {sev} on {}: {}{agreed}", plan.id(), Target::default_for(plan, sev).describe()))
    }

    /// What support still needs from the customer, given what the bundle has.
    pub fn questions(&self) -> Vec<String> {
        let mut q = vec![
            "Who and how many are affected: everyone, a team, one person, one Bot?".to_string(),
            "Since when, in UTC, and what changed just before: an upgrade, a setting, the identity provider?".into(),
            "The error text, and the X-Request-Id of a failing request.".into(),
        ];
        if self.kind == Kind::Offline {
            q.push("Once botd is back, a `botctl support-bundle` too: the offline bundle has no health, score or audit summary.".into());
        }
        if !self.missing.is_empty() {
            q.push(format!("The files taken out of the bundle ({}), or why they were.", self.missing.join(", ")));
        }
        q
    }

    fn made(&self) -> String {
        match self.created_at {
            Some(c) => format!("made {}", c.to_rfc3339_opts(SecondsFormat::Secs, true)),
            None => "made at an unknown time".into(),
        }
    }

    fn verdict(&self) -> String {
        match self.severity() {
            Some((s, by)) => format!("Suggested severity: {s} ({}), from {}", severity_name(s), by.iter().map(|f| f.id.as_str()).collect::<Vec<_>>().join(", ")),
            None => "Suggested severity: none from the bundle; size it from what the customer says".into(),
        }
    }

    fn cap_note(&self) -> Option<&'static str> {
        self.capped().then_some("Testing mode: not production, so Severity 3 at most unless the agreement says otherwise (--production if it is production).")
    }

    pub fn json(&self) -> Value {
        let sev = self.severity();
        json!({
            "bundle": {
                "name": self.name, "kind": self.kind.as_str(), "botd": self.botd,
                "createdAt": self.created_at.map(|c| c.to_rfc3339_opts(SecondsFormat::Secs, true)), "missing": self.missing, "testing": self.testing,
            },
            "asOf": self.as_of.to_rfc3339_opts(SecondsFormat::Secs, true),
            "suggestedSeverity": sev.as_ref().map(|(s, _)| *s),
            "severityFrom": sev.as_ref().map(|(_, by)| by.iter().map(|f| f.id.clone()).collect::<Vec<_>>()).unwrap_or_default(),
            "cappedForTesting": self.capped(),
            "plan": self.plan.map(Plan::id),
            "responseTarget": self.target(),
            "failed": self.failed(),
            "findings": self.findings.iter().map(Finding::json).collect::<Vec<_>>(),
            "runbooks": self.runbooks(),
            "questions": self.questions(),
        })
    }

    pub fn text(&self) -> String {
        let mut out = format!("Support triage of {} ({} bundle, botd {}, {})\n", self.name, self.kind.as_str(), self.botd.as_deref().unwrap_or("?"), self.made());
        out.push_str(&format!("{}\n", self.verdict()));
        for line in [self.cap_note().map(str::to_string), self.target()].into_iter().flatten() {
            out.push_str(&format!("{line}\n"));
        }
        out.push('\n');
        if self.findings.is_empty() {
            out.push_str("Nothing in the bundle stands out.\n");
        }
        for f in &self.findings {
            let sev = f.severity.map(|s| format!("sev {s}")).unwrap_or_default();
            out.push_str(&format!("{:<5} {:<6} {:<22} {}\n", f.level.as_str(), sev, f.id, f.summary));
            out.push_str(&format!("{:35}evidence: {}\n", "", f.evidence));
            for r in &f.runbooks {
                out.push_str(&format!("{:35}read:     docs/{r}\n", ""));
            }
            if let Some(n) = &f.next {
                out.push_str(&format!("{:35}next:     {n}\n", ""));
            }
        }
        let books = self.runbooks();
        if !books.is_empty() {
            out.push_str("\nRunbooks to open:\n");
            for b in books {
                out.push_str(&format!("  {b}\n"));
            }
        }
        out.push_str("\nAsk the customer:\n");
        for q in self.questions() {
            out.push_str(&format!("  - {q}\n"));
        }
        out
    }

    /// For the ticket's internal note: escaped so bundle text can't break the table or
    /// add HTML.
    pub fn markdown(&self) -> String {
        let md = |s: &str| s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('|', "\\|");
        let link = |r: &str| format!("[{}](docs/{r})", r.split('#').next().unwrap_or(r).rsplit('/').next().unwrap_or(r));
        let mut out = format!("## Support triage: {}\n\n", md(&self.name));
        out.push_str(&format!("{} bundle, botd {}, {}.\n\n", self.kind.as_str(), md(self.botd.as_deref().unwrap_or("?")), self.made()));
        out.push_str(&format!("**{}**\n", md(&self.verdict())));
        for line in [self.cap_note().map(str::to_string), self.target()].into_iter().flatten() {
            out.push_str(&format!("\n{}\n", md(&line)));
        }
        out.push('\n');
        if self.findings.is_empty() {
            out.push_str("Nothing in the bundle stands out.\n");
        } else {
            out.push_str("| Level | Severity | Finding | Evidence | Read |\n|---|---|---|---|---|\n");
            for f in &self.findings {
                let sev = f.severity.map(|s| s.to_string()).unwrap_or_default();
                let next = f.next.as_ref().map(|n| format!("<br>Next: {}", md(n))).unwrap_or_default();
                let read = f.runbooks.iter().map(|r| link(r)).collect::<Vec<_>>().join(", ");
                out.push_str(&format!("| {} | {sev} | `{}` {}{next} | {} | {read} |\n", f.level.as_str(), md(&f.id), md(&f.summary), md(&f.evidence)));
            }
        }
        out.push_str("\n### Ask the customer\n\n");
        for q in self.questions() {
            out.push_str(&format!("- {}\n", md(&q)));
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(s: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(s).unwrap().with_timezone(&Utc)
    }

    fn opts() -> Options {
        Options::new(at("2026-11-24T06:00:00Z"))
    }

    fn version() -> Value {
        json!({ "product": "SuperBot", "botd": "1.4.0", "bundleFormat": 2, "createdAt": "2026-11-24T05:00:00Z", "uptimeSeconds": 86_400, "harnesses": { "installed": ["hermes"], "default": "hermes" } })
    }

    fn healthy() -> Value {
        json!({
            "status": { "status": "operational", "components": [{ "id": "api", "name": "API", "status": "operational", "note": null }], "incidents": [] },
            "setup": { "checklist": [{ "id": "domain", "label": "A public address with HTTPS", "done": true }], "done": 1, "total": 1 },
            "license": { "summary": { "edition": "business", "testing": false }, "warnings": [] },
            "approvals": { "mode": "ask", "pending": 0, "oldestPendingSeconds": null, "timeoutMinutes": 10 },
            "runs": { "holdingSlots": 0, "waiting": 0, "capPerComputer": null },
            "lastMinutes": { "minutes": 15, "requests": 200, "errors": 0, "runsDone": 10, "runsFailed": 0, "noticesSent": 3, "noticesFailed": 0 },
            "machines": null,
        })
    }

    fn online(files: Vec<(&str, Value)>) -> Bundle {
        let mut all: BTreeMap<&str, Value> = [
            ("version.json", version()),
            ("health.json", healthy()),
            ("health-score.json", json!({ "score": 95, "band": "healthy", "signals": [] })),
            ("health-score-history.json", json!({ "points": [], "trend": null })),
            ("audit-summary.json", json!({ "days": 7, "to": "2026-11-24T05:00:00Z", "byAction": [], "recentProblems": [], "truncated": false })),
            ("config.json", json!({})),
        ]
        .into_iter()
        .collect();
        for (n, v) in files {
            all.insert(n, v);
        }
        let mut files: Vec<(&str, Vec<u8>)> = all.into_iter().map(|(n, v)| (n, serde_json::to_vec(&v).unwrap())).collect();
        files.push(("logs.jsonl", b"{\"ts\":\"2026-11-24T04:59:00Z\",\"level\":\"info\",\"msg\":\"listening\"}\n".to_vec()));
        Bundle::from_files("superbot-support-20261124T050000Z", files)
    }

    fn ids(t: &Triage) -> Vec<&str> {
        t.findings.iter().map(|f| f.id.as_str()).collect()
    }

    fn find<'a>(t: &'a Triage, id: &str) -> &'a Finding {
        t.findings.iter().find(|f| f.id == id).unwrap_or_else(|| panic!("no {id} in {:?}", ids(t)))
    }

    #[test]
    fn a_healthy_bundle_suggests_nothing_and_asks_the_usual_questions() {
        let t = triage(&online(vec![]), &opts()).unwrap();
        assert!(t.findings.is_empty(), "{:?}", t.findings);
        assert_eq!((t.kind, t.severity(), t.failed()), (Kind::Online, None, false));
        assert_eq!(t.questions().len(), 3);
        let text = t.text();
        assert!(text.contains("Suggested severity: none from the bundle") && text.contains("Nothing in the bundle stands out") && text.contains("X-Request-Id"), "{text}");
        assert!(t.missing.is_empty(), "{:?}", t.missing);
    }

    #[test]
    fn the_status_page_sets_the_severity_by_component() {
        let mut h = healthy();
        h["status"]["components"] = json!([
            { "id": "api", "name": "API", "status": "major_outage", "note": "5xx on 60% of requests" },
            { "id": "machines", "name": "Machines", "status": "partial_outage" },
            { "id": "runners", "name": "Harness runners", "status": "degraded_performance" },
            { "id": "notifications", "name": "Notifications", "status": "partial_outage" },
            { "id": "database", "name": "Database", "status": "operational" },
        ]);
        h["status"]["incidents"] = json!([{ "title": "API errors", "impact": "major", "state": "investigating", "createdAt": 1_795_496_400_000_i64 }, { "title": "Old", "state": "resolved" }]);
        let t = triage(&online(vec![("health.json", h)]), &opts()).unwrap();
        let api = find(&t, "status.api");
        assert_eq!((api.level, api.severity), (Level::Fail, Some(1)));
        assert_eq!(api.summary, "API is major outage: 5xx on 60% of requests");
        assert!(api.runbooks.contains(&"support/runbook-major-incident.md"), "{:?}", api.runbooks);
        assert_eq!(find(&t, "status.machines").severity, Some(2));
        assert_eq!(find(&t, "status.runners").severity, Some(3));
        assert_eq!((find(&t, "status.notifications").level, find(&t, "status.notifications").severity), (Level::Warn, Some(3)));
        assert!(!ids(&t).contains(&"status.database"));
        let incident = find(&t, "status.incident");
        assert!(incident.summary.contains("\"API errors\" (major, investigating, since 2026-11-24T05:00:00Z)"), "{}", incident.summary);
        assert_eq!(t.findings.iter().filter(|f| f.id == "status.incident").count(), 1, "resolved ones aren't open");
        let (sev, by) = t.severity().unwrap();
        assert_eq!((sev, by.iter().map(|f| f.id.as_str()).collect::<Vec<_>>()), (1, vec!["status.api"]));
        assert!(t.failed());
        assert_eq!(t.findings[0].id, "status.api", "the worst first");
    }

    #[test]
    fn approvals_runs_and_machines_from_the_last_minutes() {
        let mut h = healthy();
        h["approvals"] = json!({ "pending": 4, "oldestPendingSeconds": 3000 });
        h["lastMinutes"] = json!({ "minutes": 15, "requests": 100, "errors": 30, "runsDone": 2, "runsFailed": 6, "noticesSent": 0, "noticesFailed": 5 });
        h["runs"]["waiting"] = json!(3);
        h["runs"]["capPerComputer"] = json!(2);
        h["machines"] = json!({ "byState": { "running": 9, "error": 2 }, "hostsByState": { "up": 2, "down": 1 }, "rpoBreachesOpen": 1 });
        h["setup"]["checklist"] = json!([{ "id": "domain", "label": "A public address with HTTPS", "done": true }, { "id": "backups", "label": "Server backups copied off this host", "done": false }]);
        let t = triage(&online(vec![("health.json", h)]), &opts()).unwrap();
        let unheard = find(&t, "approvals.unheard");
        assert_eq!((unheard.level, unheard.severity), (Level::Fail, Some(2)));
        assert!(!ids(&t).contains(&"approvals.waiting") && !ids(&t).contains(&"notifications.failed"), "one finding, not three: {:?}", ids(&t));
        assert_eq!(find(&t, "api.errors").summary, "30 of 100 requests (30%) failed in the last 15 minutes");
        assert_eq!(find(&t, "api.errors").severity, Some(2));
        assert_eq!(find(&t, "runs.failing").severity, Some(2), "6 of 8");
        assert_eq!(find(&t, "runs.waiting").summary, "3 runs waiting for a slot (at most 2 at once per computer)");
        assert_eq!(find(&t, "machines.error").severity, Some(3));
        assert_eq!(find(&t, "machines.hosts").severity, Some(2));
        assert_eq!(find(&t, "machines.rpo").severity, Some(2));
        assert_eq!(find(&t, "setup.open").summary, "Setup checklist 1 of 2 done; open: Server backups copied off this host");
        assert!(!ids(&t).contains(&"harness.none"), "managed machines run the harnesses");

        let mut h = healthy();
        h["approvals"] = json!({ "pending": 1, "oldestPendingSeconds": 1799 });
        h["lastMinutes"] = json!({ "minutes": 15, "requests": 19, "errors": 19, "runsDone": 3, "runsFailed": 0, "noticesSent": 1, "noticesFailed": 1 });
        let t = triage(&online(vec![("health.json", h)]), &opts()).unwrap();
        assert_eq!(ids(&t), ["notifications.failed"], "too few requests to judge, and the approval is young");
    }

    #[test]
    fn no_harness_and_no_machines_means_no_bot_can_run() {
        let mut v = version();
        v["harnesses"]["installed"] = json!([]);
        let t = triage(&online(vec![("version.json", v)]), &opts()).unwrap();
        assert_eq!((find(&t, "harness.none").severity, t.failed()), (Some(2), true));
    }

    #[test]
    fn score_signals_point_at_their_runbooks() {
        let score = json!({ "score": 40, "band": "at_risk", "signals": [
            { "id": "identity", "label": "Sign-in and SCIM", "status": "risk", "summary": "34 of 134 single sign-on attempts failed.", "facts": { "ssoFailed": 34, "ssoReasons": [{ "code": "bad_signature", "count": 30 }, { "code": "not_linked", "count": 4 }], "scimFailed": 7, "scimReasons": [{ "code": "uniqueness", "count": 7 }] } },
            { "id": "backups", "label": "Backups", "status": "risk", "summary": "Server backups are past their RPO.", "facts": {} },
            { "id": "runs", "label": "Bot runs", "status": "watch", "summary": "6% failed.", "facts": { "refusedReasons": [{ "code": "egress_policy_pending", "count": 3 }], "runLimited": 0 } },
            { "id": "license", "label": "License", "status": "watch", "summary": "Ends in 20 days.", "facts": {} },
            { "id": "adoption", "label": "Adoption", "status": "watch", "summary": "45% active.", "facts": {} },
            { "id": "approvals", "label": "Approvals", "status": "ok", "summary": "fine", "facts": {} },
        ]});
        let t = triage(&online(vec![("health-score.json", score)]), &opts()).unwrap();
        let id = find(&t, "signal.identity");
        assert_eq!((id.level, id.severity), (Level::Fail, Some(2)));
        assert_eq!(id.runbooks, ["support/runbook-saml.md#reasons-and-fixes", "support/runbook-sign-in.md#reasons-and-fixes", "sso/scim.md", "support/health-score.md#identity"]);
        assert!(id.summary.ends_with("Reasons: sign-in bad_signature ×30, not_linked ×4; SCIM uniqueness ×7."), "{}", id.summary);
        assert_eq!(find(&t, "signal.backups").severity, Some(2));
        let runs = find(&t, "signal.runs");
        assert_eq!((runs.level, runs.severity), (Level::Info, None));
        assert!(runs.runbooks.contains(&"support/runbook-run-limits-egress.md") && runs.summary.contains("Refused: egress_policy_pending ×3."), "{runs:?}");
        assert_eq!(find(&t, "signal.license").severity, Some(4));
        assert_eq!(find(&t, "signal.adoption").severity, None);
        assert!(!ids(&t).contains(&"signal.approvals"));
        assert!(find(&t, "score.at_risk").next.as_ref().unwrap().contains("support manager"));
    }

    #[test]
    fn sign_in_codes_choose_the_runbook() {
        assert_eq!(sign_in_books(&["bad_signature".into()], false), ["support/runbook-saml.md#reasons-and-fixes"]);
        assert_eq!(sign_in_books(&["not_linked".into()], false), ["support/runbook-sign-in.md#reasons-and-fixes"]);
        assert_eq!(sign_in_books(&["not_linked".into()], true), ["support/runbook-saml.md#reasons-and-fixes", "support/runbook-sign-in.md#reasons-and-fixes"]);
        assert_eq!(sign_in_books(&[], false), ["support/runbook-sign-in.md#reasons-and-fixes"]);
        assert_eq!(sign_in_books(&[], true), ["support/runbook-saml.md#reasons-and-fixes"]);
    }

    #[test]
    fn a_falling_score_is_flagged() {
        let falling = json!({ "trend": { "from": "2026-11-01", "to": "2026-11-23", "fromScore": 85, "toScore": 60, "change": -25, "fromBand": "healthy", "toBand": "watch", "worse": ["identity"] } });
        let t = triage(&online(vec![("health-score-history.json", falling)]), &opts()).unwrap();
        assert_eq!(find(&t, "score.falling").summary, "Health score fell 25 points, from 85 (healthy) on 2026-11-01 to 60 (watch) on 2026-11-23; worse: identity");
        let steady = json!({ "trend": { "fromScore": 70, "toScore": 60, "change": -10, "fromBand": "watch", "toBand": "watch", "worse": [] } });
        assert!(triage(&online(vec![("health-score-history.json", steady)]), &opts()).unwrap().findings.is_empty());
    }

    #[test]
    fn audit_failures_are_grouped_by_runbook() {
        let audit = json!({ "days": 7, "to": "2026-11-24T05:00:00Z", "truncated": true,
            "byAction": [
                { "action": "auth.login_failed", "total": 14, "outcomes": { "failure": 12 } },
                { "action": "auth.login", "total": 200, "outcomes": { "success": 200 } },
                { "action": "access.denied", "total": 3, "outcomes": { "denied": 3 } },
                { "action": "machine.residency_refused", "total": 1, "outcomes": { "denied": 1 } },
                { "action": "bot.run_refused", "total": 2, "outcomes": { "denied": 2 } },
                { "action": "machine.run_limited", "total": 1, "outcomes": { "denied": 1 } },
                { "action": "billing.email_failed", "total": 1, "outcomes": { "failure": 1 } },
            ],
            "recentProblems": [
                { "action": "auth.login_failed", "outcome": "failure", "authMethod": "saml", "reason": "not_linked" },
                { "action": "auth.login_failed", "outcome": "failure", "authMethod": "sso", "reason": "not_linked" },
                { "action": "auth.login_failed", "outcome": "failure", "authMethod": "password", "reason": "[text]" },
            ] });
        let t = triage(&online(vec![("audit-summary.json", audit)]), &opts()).unwrap();
        let sign_in = find(&t, "audit.sign_in");
        assert_eq!(sign_in.level, Level::Warn, "10 or more");
        assert_eq!(sign_in.summary, "12 sign-in failures in the 7 days to 2026-11-24T05:00:00Z: auth.login_failed ×12 (newest reasons: not_linked ×2, [text] ×1)");
        assert_eq!(sign_in.runbooks, ["support/runbook-saml.md#reasons-and-fixes", "support/runbook-sign-in.md#reasons-and-fixes"], "SAML was used");
        assert_eq!(find(&t, "audit.access").level, Level::Info);
        assert_eq!(find(&t, "audit.residency").runbooks, ["support/runbook-residency.md#refusals-and-fixes"]);
        assert_eq!(find(&t, "audit.run_limits").summary, "3 runs refused or held to limits in the 7 days to 2026-11-24T05:00:00Z: bot.run_refused ×2, machine.run_limited ×1");
        assert!(find(&t, "audit.other").runbooks.is_empty());
        assert!(ids(&t).contains(&"audit.truncated"));
        assert!(t.findings.iter().all(|f| f.severity.is_none()), "the audit log counts; the status says how bad");
    }

    #[test]
    fn logs_are_counted_by_message_and_panics_go_to_engineering() {
        let mut b = online(vec![]);
        let lines = [
            r#"{"level":"warn","msg":"model call failed: 503 after 1200 ms"}"#,
            r#"{"level":"warn","msg":"model call failed: 502 after 900 ms"}"#,
            r#"{"level":"info","msg":"run finished"}"#,
            r#"{"level":"warn","msg":"thread 'tokio' panicked at src/x.rs:1"}"#,
        ];
        b.files.insert("logs.jsonl".into(), lines.join("\n").into_bytes());
        let t = triage(&b, &opts()).unwrap();
        assert_eq!(find(&t, "logs.problems").summary, "3 warnings in the newest 4 log lines; most frequent: ×2 model call failed: # after # ms | ×1 thread 'tokio' panicked at src/x.rs:#");
        assert!(find(&t, "logs.panic").next.as_ref().unwrap().contains("level 3"));
    }

    fn offline(check: Value, logs: &str) -> Bundle {
        let v = json!({ "botd": "1.3.2", "bundleFormat": 1, "createdAt": "2026-11-24T05:00:00Z", "offline": true, "schema": 67 });
        Bundle::from_files(
            "superbot-support-offline-20261124T050000Z",
            vec![("version.json", serde_json::to_vec(&v).unwrap()), ("check.json", serde_json::to_vec(&check).unwrap()), ("config.json", b"{}".to_vec()), ("logs.txt", logs.as_bytes().to_vec())],
        )
    }

    fn check(findings: Value) -> Value {
        json!({ "beforeUpgrade": false, "findings": findings })
    }

    #[test]
    fn the_offline_check_sets_the_severity_and_brings_its_fixes() {
        let c = check(json!([
            { "id": "botd", "status": "warn", "summary": "isn't running", "fix": "Start it (sudo systemctl start superbot)." },
            { "id": "database", "status": "fail", "summary": "schema 70 is newer than this botd's 67", "fix": "Install the botd that last ran on it." },
            { "id": "disk", "status": "warn", "summary": "4% free" },
            { "id": "backups", "status": "warn", "summary": "no archives" },
            { "id": "license", "status": "info", "summary": "Testing mode", "details": { "edition": "business" } },
        ]));
        let t = triage(&offline(c, "botd-1  | {\"level\":\"warn\",\"msg\":\"database is locked\"}\nError: schema 70 is newer\nlistening on :3000\n"), &opts()).unwrap();
        assert_eq!(t.kind, Kind::Offline);
        let botd = find(&t, "check.botd");
        assert_eq!((botd.level, botd.severity), (Level::Fail, Some(1)));
        assert!(botd.summary.ends_with("(unless it was stopped on purpose, for an upgrade or a restore)") && botd.next.as_deref() == Some("Start it (sudo systemctl start superbot)."), "{botd:?}");
        assert_eq!(find(&t, "check.database").runbooks, ["support/runbook-server-restore.md"]);
        assert_eq!(find(&t, "check.disk").severity, Some(3));
        assert_eq!((find(&t, "check.backups").level, find(&t, "check.backups").severity), (Level::Warn, None));
        assert!(!ids(&t).contains(&"check.license"));
        assert_eq!(find(&t, "logs.problems").summary, "2 lines that report a failure in the newest 3 log lines; most frequent: ×1 Error: schema # is newer | ×1 database is locked");
        assert!(t.questions().iter().any(|q| q.contains("`botctl support-bundle` too")));
        assert_eq!(t.severity().unwrap().0, 1);

        let quiet = check(json!([{ "id": "botd", "status": "ok", "summary": "running, pid 7" }]));
        let t = triage(&offline(quiet, "# no logs: pass --logs <file>\n"), &opts()).unwrap();
        assert_eq!(ids(&t), ["logs.none"]);
    }

    #[test]
    fn testing_mode_caps_the_severity_unless_its_production() {
        let c = check(json!([
            { "id": "botd", "status": "warn", "summary": "isn't running" },
            { "id": "license", "status": "info", "summary": "Testing mode", "details": { "edition": "testing" } },
        ]));
        let b = offline(c, "");
        let t = triage(&b, &opts()).unwrap();
        assert_eq!((t.testing, t.severity().unwrap().0), (true, 3));
        assert!(t.text().contains("Testing mode: not production"), "{}", t.text());
        let mut o = opts();
        o.production = true;
        assert_eq!(triage(&b, &o).unwrap().severity().unwrap().0, 1);
        let mut h = healthy();
        h["license"]["summary"]["testing"] = json!(true);
        let t = triage(&online(vec![("health.json", h)]), &opts()).unwrap();
        assert!(t.testing && t.severity().is_none() && t.cap_note().is_none(), "nothing to cap");
    }

    #[test]
    fn versions_age_and_formats() {
        let mut v = version();
        v["uptimeSeconds"] = json!(90);
        v["bundleFormat"] = json!(3);
        let mut o = opts();
        o.as_of = at("2026-11-27T05:00:00Z");
        o.latest = semver("1.6.1");
        let t = triage(&online(vec![("version.json", v.clone())]), &o).unwrap();
        assert_eq!(find(&t, "version.behind").level, Level::Warn, "a minor release behind");
        assert_eq!(find(&t, "botd.restarted").summary, "botd started 90 s before the bundle was made: a restart, or a crash it came back from");
        assert!(find(&t, "bundle.format").summary.contains("bundle format 3; this botctl reads 2"));
        assert_eq!(find(&t, "bundle.stale").summary, "The bundle was made 3 days before this triage");
        o.latest = semver("1.4.3");
        assert_eq!(find(&triage(&online(vec![("version.json", v.clone())]), &o).unwrap(), "version.behind").level, Level::Info);
        o.latest = semver("1.4.0");
        assert!(!ids(&triage(&online(vec![("version.json", v)]), &o).unwrap()).contains(&"version.behind"));
        assert_eq!(semver("v1.2"), Some((1, 2, 0)));
        assert_eq!(semver("1.2.3-rc.1"), Some((1, 2, 3)));
        assert_eq!(semver("1.x"), None);
        assert_eq!(semver("1.2.3.4"), None);
    }

    #[test]
    fn the_plan_gives_the_response_target() {
        let mut h = healthy();
        h["status"]["components"] = json!([{ "id": "machines", "name": "Machines", "status": "major_outage" }]);
        h["machines"] = json!({});
        let mut o = opts();
        o.plan = Some(Plan::Pro);
        let t = triage(&online(vec![("health.json", h.clone())]), &o).unwrap();
        assert_eq!(t.target().unwrap(), "First response for Severity 2 on pro: 4 business h");
        o.plan = Some(Plan::Enterprise);
        let t = triage(&online(vec![("health.json", h)]), &o).unwrap();
        assert_eq!(t.json()["responseTarget"], "First response for Severity 2 on enterprise: 2 h, 24×7 (the Enterprise default; the agreement's target wins)");
    }

    #[test]
    fn bundle_text_is_cleaned_and_escaped() {
        let mut h = healthy();
        h["status"]["incidents"] = json!([{ "title": "evil \u{1b}[31m<script>|x|\nnext", "impact": "minor", "state": "identified" }]);
        let t = triage(&online(vec![("health.json", h)]), &opts()).unwrap();
        let s = &find(&t, "status.incident").summary;
        assert!(!s.contains('\u{1b}') && !s.contains('\n'), "{s:?}");
        let md = t.markdown();
        assert!(md.contains("&lt;script&gt;\\|x\\|") && !md.contains("<script>"), "{md}");
        assert_eq!(clean(&"a".repeat(TEXT + 5)).chars().count(), TEXT + 1);
    }

    #[test]
    fn broken_or_partial_bundles_say_so() {
        let mut b = online(vec![]);
        b.files.insert("health.json".into(), b"{not json".to_vec());
        b.files.remove("audit-summary.json");
        let t = triage(&b, &opts()).unwrap();
        assert_eq!(find(&t, "bundle.unreadable").evidence, "health.json");
        assert_eq!(t.missing, ["audit-summary.json"]);
        assert!(t.questions().iter().any(|q| q.contains("audit-summary.json")));
        let nothing = Bundle::from_files("x", vec![("README.txt", b"hi".to_vec())]);
        assert!(triage(&nothing, &opts()).err().unwrap().contains("not a support bundle"));
    }

    #[test]
    fn extreme_numbers_from_a_crafted_bundle_dont_panic() {
        let big = u64::MAX;
        let mut h = healthy();
        h["lastMinutes"] = json!({ "minutes": big, "requests": big, "errors": big, "runsDone": big, "runsFailed": big, "noticesSent": big, "noticesFailed": big });
        h["approvals"] = json!({ "pending": big, "oldestPendingSeconds": i64::MAX });
        h["machines"] = json!({ "byState": { "error": big }, "hostsByState": { "down": big, "lost": big }, "rpoBreachesOpen": big });
        let audit = json!({ "byAction": [{ "action": "auth.login_failed", "outcomes": { "failure": big, "denied": big } }, { "action": "auth.slo_failed", "outcomes": { "failure": big } }] });
        let history = json!({ "trend": { "change": i64::MIN, "fromBand": "healthy", "toBand": "at_risk" } });
        let mut v = version();
        v["uptimeSeconds"] = json!(i64::MIN);
        let t = triage(&online(vec![("health.json", h), ("audit-summary.json", audit), ("health-score-history.json", history), ("version.json", v)]), &opts()).unwrap();
        assert!(find(&t, "audit.sign_in").summary.starts_with(&format!("{big} sign-in failures")), "saturates");
        assert!(find(&t, "score.falling").summary.starts_with(&format!("Health score fell {} points", i64::MAX)));
        assert!(t.failed() && !ids(&t).contains(&"botd.restarted"), "a negative uptime is no restart");
        let _ = (t.text(), t.markdown(), t.json());
    }

    fn tar_of(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut t = tar::Builder::new(Vec::new());
        for (name, data) in entries {
            let mut h = tar::Header::new_ustar();
            h.set_size(data.len() as u64);
            h.set_mode(0o600);
            h.set_cksum();
            t.append_data(&mut h, name, *data).unwrap();
        }
        t.into_inner().unwrap()
    }

    #[test]
    fn tars_gzipped_or_not_and_folders_read_the_same() {
        let v = serde_json::to_vec(&version()).unwrap();
        let h = serde_json::to_vec(&healthy()).unwrap();
        let plain = tar_of(&[("superbot-support-x/version.json", &v), ("superbot-support-x/health.json", &h), ("superbot-support-x/notes.txt", b"ignored"), ("other/deeper/version.json", b"ignored")]);
        let b = read_tar(&plain).unwrap();
        assert_eq!((b.name.as_str(), b.files.keys().map(String::as_str).collect::<Vec<_>>()), ("superbot-support-x", vec!["health.json", "version.json"]));
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        std::io::Write::write_all(&mut gz, &plain).unwrap();
        assert_eq!(read_tar(&gz.finish().unwrap()).unwrap().files, b.files);

        let dir = std::env::temp_dir().join(format!("support-triage-{}-{}", std::process::id(), chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)));
        let inner = dir.join("superbot-support-x");
        std::fs::create_dir_all(&inner).unwrap();
        std::fs::write(inner.join("version.json"), &v).unwrap();
        std::fs::write(inner.join("health.json"), &h).unwrap();
        assert_eq!(read_dir(&dir).unwrap().files, b.files, "the folder holding the bundle");
        assert_eq!(read_dir(&inner).unwrap().name, "superbot-support-x");
        std::fs::create_dir_all(dir.join("second")).unwrap();
        std::fs::write(dir.join("second/version.json"), &v).unwrap();
        assert!(read_dir(&dir).unwrap_err().contains("more than one bundle"));
        std::fs::remove_dir_all(&dir).unwrap();

        assert!(read_tar(&tar_of(&[("a/version.json", &v), ("b/version.json", &v)])).unwrap_err().contains("two version.json"));
        assert!(read_tar(&tar_of(&[("readme.md", b"x")])).unwrap_err().contains("no support bundle files"));
        assert!(read_tar(b"definitely not a tar file, just some words that go on for a while").is_err());
    }

    #[test]
    fn a_gzip_bomb_is_refused() {
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
        let zeros = vec![0u8; 1 << 20];
        for _ in 0..(MAX_BYTES >> 20) + 1 {
            std::io::Write::write_all(&mut gz, &zeros).unwrap();
        }
        let bomb = gz.finish().unwrap();
        assert!(bomb.len() < 1 << 20);
        assert!(read_tar(&bomb).unwrap_err().contains("not a support bundle"));
    }

    #[test]
    fn options_are_parsed() {
        let now = at("2026-11-24T06:00:00Z");
        let (src, o, f) = parse_args(&["b.tar", "--plan", "Enterprise", "--latest", "v1.5.0", "--production", "--as-of", "2026-11-25T00:00:00Z", "--markdown"], now).unwrap();
        assert_eq!((src.as_str(), o.plan, o.latest, o.production, o.as_of, f), ("b.tar", Some(Plan::Enterprise), Some((1, 5, 0)), true, at("2026-11-25T00:00:00Z"), Format::Markdown));
        assert_eq!(parse_args(&["-", "--json"], now).unwrap().2, Format::Json);
        for bad in [&["--plan", "gold", "b"][..], &["b", "--latest", "new"], &["b", "--as-of", "soon"], &["b", "c"], &["b", "--nope"], &[], &["b", "--plan"]] {
            assert!(parse_args(bad, now).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn every_runbook_named_exists_and_saml_codes_match_the_runbooks() {
        let docs = Path::new(env!("CARGO_MANIFEST_DIR")).join("../docs");
        let code = include_str!("support_triage.rs");
        let mut named = BTreeSet::new();
        for (i, _) in code.match_indices("\"support/").chain(code.match_indices("\"sso/")).chain(code.match_indices("\"ops/")) {
            let end = code[i + 1..].find('"').unwrap();
            let r = &code[i + 1..i + 1 + end];
            if r.contains(".md") {
                named.insert(r);
            }
        }
        assert!(named.len() >= 15, "{named:?}");
        for r in named {
            let (page, anchor) = r.split_once('#').unwrap_or((r, ""));
            let md = std::fs::read_to_string(docs.join(page)).unwrap_or_else(|e| panic!("docs/{page}: {e}"));
            if !anchor.is_empty() {
                let slugs: Vec<String> = md
                    .lines()
                    .filter(|l| l.starts_with('#'))
                    .map(|l| l.trim_start_matches('#').trim().to_lowercase().chars().filter(|c| c.is_alphanumeric() || *c == ' ' || *c == '-' || *c == '_').collect::<String>().replace(' ', "-"))
                    .collect();
                assert!(slugs.iter().any(|s| s == anchor), "docs/{page} has no #{anchor}: {slugs:?}");
            }
        }
        let reasons = |page: &str| -> BTreeSet<String> {
            let md = std::fs::read_to_string(docs.join(page)).unwrap();
            let section = md.split("## Reasons and fixes").nth(1).unwrap().split("\n## ").next().unwrap().to_string();
            section.split('`').skip(1).step_by(2).filter(|c| c.chars().all(|c| c.is_ascii_lowercase() || c == '_')).map(String::from).collect()
        };
        let (saml, sign_in) = (reasons("support/runbook-saml.md"), reasons("support/runbook-sign-in.md"));
        let only_saml: BTreeSet<String> = saml.difference(&sign_in).cloned().collect();
        let ours: BTreeSet<String> = SAML_REASONS.iter().map(|s| s.to_string()).collect();
        assert_eq!(ours, only_saml, "SAML_REASONS is runbook-saml.md's reasons that runbook-sign-in.md doesn't have");
    }
}
