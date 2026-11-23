//! Vulnerability-management evidence (ADR 0154): for a period, every Dependabot and code
//! scanning alert that was open at any time in it, each judged against the remediation
//! window for its severity (the information security policy's: 30 days for Critical and
//! High, 90 for Medium and Low), and the findings the repository accepts with a reason
//! (`.cargo/audit.toml`, `.grype.yaml`), as a dated bundle in the shape of the
//! change-management bundle (ADR 0148).
//!
//! Never in it: the token, dismissal comments, advisory descriptions, code snippets or
//! alert messages. People are named by their GitHub logins.

use crate::changes::{all, enc, json_file, login, ms, rfc3339, sha256, valid_branch};
use crate::github::{Api, Failure};
use crate::period::Period;
use serde_json::{Value, json};
use std::collections::BTreeMap;

/// Bumped when a file's shape changes, so tools reading bundles can tell them apart.
pub const FORMAT: u32 = 1;
pub const PREFIX: &str = "superbot-vulns-";
const DAY_MS: i64 = 86_400_000;
pub const SEVERITIES: [&str; 5] = ["critical", "high", "medium", "low", "unknown"];

/// One file of the bundle and the criteria and checklist rows it is evidence for. The
/// evidence plan's vulnerability table must match.
pub struct Section {
    pub file: &'static str,
    pub criteria: &'static [&'static str],
    pub rows: &'static [&'static str],
}

pub const SECTIONS: [Section; 2] = [
    Section { file: "vulnerability-alerts.json", criteria: &["CC4.2", "CC7.1"], rows: &["CC4.2-1", "CC7.1-2", "CC7.1-3"] },
    Section { file: "accepted-findings.json", criteria: &["CC7.1"], rows: &["CC7.1-2"] },
];

/// The files that list findings accepted with a reason, read at the branch's head.
const ACCEPTED: [(&str, &str); 2] = [(".cargo/audit.toml", "cargo-audit"), (".grype.yaml", "grype")];

const README: &str = "SuperBot vulnerability-management evidence bundle
=================================================

Made by superbot-evidence from the GitHub API with a read-only token, for a SOC 2 Type II
evidence store (docs/security/soc2-evidence-plan.md, ADR 0154). It covers the period in
manifest.json: from its first day (00:00 UTC) up to, not including, its last. Alerts are
judged as of the period's end; their state now and the accepted findings are as of
createdAt, which may be after the period.

  vulnerability-alerts.json  every Dependabot and code scanning alert open at any time in
                             the period: severity, when it was opened and closed, how
                             (fixed or dismissed, with the reason's code), the date it was
                             due under the remediation windows in manifest.json, and
                             whether it was closed in time or overdue at the period's end;
                             counted by severity, with the exceptions
  accepted-findings.json     the findings the repository accepts with a reason, from
                             .cargo/audit.toml (cargo audit) and .grype.yaml (image scan)
  manifest.json              what is in this bundle, the period, the windows, and each
                             file's SHA-256
  SHA256SUMS                 the same digests, for `sha256sum -c SHA256SUMS`

Never in it: the token, dismissal comments, advisory descriptions, code snippets or alert
messages. People are named by their GitHub logins. GitHub keeps only each alert's latest
state: an alert dismissed and reopened shows only its latest closing.
";

/// Days to fix or accept a finding, by severity. Unknown takes the strictest window.
#[derive(Clone, Debug, PartialEq)]
pub struct Windows(pub BTreeMap<&'static str, i64>);

impl Default for Windows {
    /// The draft information security policy's, matching `SECURITY.md`.
    fn default() -> Windows {
        Windows(BTreeMap::from([("critical", 30), ("high", 30), ("medium", 90), ("low", 90)]))
    }
}

impl Windows {
    /// `critical=30,high=30,medium=90,low=90`, any of them; the rest keep the default.
    pub fn parse(s: &str) -> Result<Windows, String> {
        let mut w = Windows::default();
        for part in s.split(',').map(str::trim).filter(|p| !p.is_empty()) {
            let (k, v) = part.split_once('=').ok_or(format!("--windows takes severity=days, not {part}"))?;
            let key = SEVERITIES[..4].iter().find(|s| **s == k.trim()).ok_or(format!("--windows: {k} isn't critical, high, medium or low"))?;
            let days: i64 = v.trim().parse().ok().filter(|d| (1..=365).contains(d)).ok_or(format!("--windows: {k} needs 1 to 365 days, not {v}"))?;
            w.0.insert(key, days);
        }
        Ok(w)
    }

    pub fn days(&self, severity: &str) -> i64 {
        self.0.get(severity).copied().unwrap_or_else(|| self.0.values().copied().min().unwrap_or(30))
    }

    fn view(&self) -> Value {
        json!({ "days": self.0, "unknownSeverity": self.days("unknown"), "source": "the information security policy's vulnerability management section (a draft until adopted), unless --windows was given" })
    }
}

// Reading GitHub

/// What a source said when it couldn't be read: GitHub's status and message.
#[derive(Clone, Debug, PartialEq)]
pub struct Unavailable {
    pub status: u16,
    pub message: String,
}

/// A listing, or why the token can't see it (401, 403, 404: not allowed, turned off, or
/// never analysed), which is recorded rather than failing the bundle.
fn listing(api: &mut dyn Api, first: &str) -> Result<Result<Vec<Value>, Unavailable>, Failure> {
    match all(api, first, None) {
        Ok(v) => Ok(Ok(v)),
        Err(f) if matches!(f.status, 401 | 403 | 404) => Ok(Err(Unavailable { status: f.status, message: f.message.chars().take(200).collect() })),
        Err(f) => Err(f),
    }
}

fn unavailable_view(u: &Unavailable, why: &str) -> Value {
    json!({ "available": false, "status": u.status, "message": u.message, "why": why })
}

// Alerts

/// `critical`, `high`, `medium`, `low` or `unknown`, and where it came from.
fn severity(source: &str, a: &Value) -> (&'static str, &'static str) {
    let known = |s: Option<&str>| s.and_then(|s| SEVERITIES[..4].iter().copied().find(|k| s.eq_ignore_ascii_case(k)));
    if source == "dependabot" {
        if let Some(s) = known(a["security_advisory"]["severity"].as_str()).or_else(|| known(a["security_vulnerability"]["severity"].as_str())) {
            return (s, "advisory");
        }
        return ("unknown", "none");
    }
    if let Some(s) = known(a["rule"]["security_severity_level"].as_str()) {
        return (s, "security severity");
    }
    match a["rule"]["severity"].as_str() {
        Some("error") => ("high", "rule severity error"),
        Some("warning") => ("medium", "rule severity warning"),
        Some("note") => ("low", "rule severity note"),
        _ => ("unknown", "none"),
    }
}

/// When an alert was closed and how; None while it is open. A closed alert without its
/// own time falls back to when it was last updated, and says so.
fn closed(a: &Value) -> Option<(i64, &'static str, bool)> {
    let how = match a["state"].as_str()? {
        "fixed" => "fixed",
        "dismissed" => "dismissed",
        "auto_dismissed" => "auto_dismissed",
        _ => return None,
    };
    let own = match how {
        "fixed" => ms(&a["fixed_at"]),
        "dismissed" => ms(&a["dismissed_at"]),
        _ => ms(&a["auto_dismissed_at"]).or_else(|| ms(&a["dismissed_at"])),
    };
    match own {
        Some(t) => Some((t, how, false)),
        None => ms(&a["updated_at"]).map(|t| (t, how, true)),
    }
}

fn days_between(a: i64, b: i64) -> f64 {
    ((b - a) as f64 / DAY_MS as f64 * 10.0).round() / 10.0
}

/// One alert, judged as of `as_of` (the period's end, or now if that is sooner). None when
/// it wasn't open at any time in the period.
pub fn alert_view(source: &str, a: &Value, p: &Period, as_of: i64, w: &Windows) -> Option<Value> {
    let opened = ms(&a["created_at"])?;
    let shut = closed(a);
    let (start, end) = (p.start_ms(), p.end_ms());
    if opened >= end || shut.is_some_and(|(t, _, _)| t < start) {
        return None;
    }
    let (sev, sev_from) = severity(source, a);
    let window = w.days(sev);
    let due = opened + window * DAY_MS;
    let closed_by_end = shut.filter(|(t, _, _)| *t < end);
    let open_at_end = closed_by_end.is_none();
    let overdue = open_at_end && due < as_of;
    let within = match closed_by_end {
        Some((t, _, _)) => json!(t <= due),
        None if overdue => json!(false),
        None => Value::Null,
    };
    let number = a["number"].as_u64().unwrap_or_default();
    let mut v = json!({
        "id": format!("{source}#{number}"),
        "source": source,
        "number": number,
        "url": a["html_url"],
        "severity": sev,
        "severityFrom": sev_from,
        "stateNow": a["state"],
        "createdAt": a["created_at"],
        "closedAt": shut.map(|(t, _, _)| rfc3339(t)),
        "closedAtApproximate": shut.is_some_and(|(_, _, approx)| approx),
        "closedHow": shut.map(|(_, how, _)| how),
        "dismissedReason": a["dismissed_reason"],
        "dismissedBy": login(&a["dismissed_by"]),
        "fixWithinDays": window,
        "dueAt": rfc3339(due),
        "openAtStart": opened < start,
        "openedInPeriod": opened >= start,
        "closedInPeriod": closed_by_end.is_some(),
        "openAtEnd": open_at_end,
        "daysToClose": closed_by_end.map(|(t, _, _)| days_between(opened, t)),
        "daysOpenAtEnd": open_at_end.then(|| days_between(opened, as_of)),
        "withinWindow": within,
        "overdueAtEnd": overdue,
    });
    if source == "dependabot" {
        let pkg = &a["dependency"]["package"];
        v["advisory"] = json!({ "ghsa": a["security_advisory"]["ghsa_id"], "cve": a["security_advisory"]["cve_id"] });
        v["package"] = json!({
            "ecosystem": pkg["ecosystem"], "name": pkg["name"], "manifest": a["dependency"]["manifest_path"], "scope": a["dependency"]["scope"],
            "firstPatchedVersion": a["security_vulnerability"]["first_patched_version"]["identifier"],
        });
    } else {
        v["rule"] = json!({ "id": a["rule"]["id"], "tool": a["tool"]["name"], "toolVersion": a["tool"]["version"] });
        v["location"] = json!({ "path": a["most_recent_instance"]["location"]["path"], "ref": a["most_recent_instance"]["ref"], "category": a["most_recent_instance"]["category"] });
    }
    Some(v)
}

fn median(mut xs: Vec<f64>) -> Value {
    if xs.is_empty() {
        return Value::Null;
    }
    xs.sort_by(f64::total_cmp);
    let n = xs.len();
    json!(if n % 2 == 1 { xs[n / 2] } else { ((xs[n / 2 - 1] + xs[n / 2]) / 2.0 * 10.0).round() / 10.0 })
}

/// Counts by severity, and the alerts an auditor would ask about.
pub fn tally(alerts: &[Value]) -> (Value, Value) {
    let is = |a: &Value, k: &str| a[k] == true;
    let mut by = serde_json::Map::new();
    for sev in SEVERITIES {
        let of: Vec<&Value> = alerts.iter().filter(|a| a["severity"] == sev).collect();
        let closed: Vec<&&Value> = of.iter().filter(|a| is(a, "closedInPeriod")).collect();
        by.insert(
            sev.into(),
            json!({
                "openAtStart": of.iter().filter(|a| is(a, "openAtStart")).count(),
                "opened": of.iter().filter(|a| is(a, "openedInPeriod")).count(),
                "closed": closed.len(),
                "fixed": closed.iter().filter(|a| a["closedHow"] == "fixed").count(),
                "dismissed": closed.iter().filter(|a| a["closedHow"] != "fixed").count(),
                "closedWithinWindow": closed.iter().filter(|a| a["withinWindow"] == true).count(),
                "closedLate": closed.iter().filter(|a| a["withinWindow"] == false).count(),
                "openAtEnd": of.iter().filter(|a| is(a, "openAtEnd")).count(),
                "overdueAtEnd": of.iter().filter(|a| is(a, "overdueAtEnd")).count(),
                "medianDaysToClose": median(closed.iter().filter_map(|a| a["daysToClose"].as_f64()).collect()),
            }),
        );
    }
    let ids = |keep: &dyn Fn(&Value) -> bool| -> Vec<Value> { alerts.iter().filter(|a| keep(a)).map(|a| a["id"].clone()).collect() };
    let exceptions = json!({
        "closedLate": ids(&|a| is(a, "closedInPeriod") && a["withinWindow"] == false),
        "overdueAtEnd": ids(&|a| is(a, "overdueAtEnd")),
        "dismissedWithoutReason": ids(&|a| is(a, "closedInPeriod") && a["closedHow"] == "dismissed" && !a["dismissedReason"].is_string()),
        "noSeverity": ids(&|a| a["severity"] == "unknown"),
    });
    (Value::Object(by), exceptions)
}

// Accepted findings

/// `.cargo/audit.toml`'s `[advisories] ignore` list: each id, with the comment lines
/// above it as its reason.
pub fn cargo_audit_accepted(text: &str) -> Vec<Value> {
    let (mut out, mut inside, mut notes) = (Vec::new(), false, Vec::<String>::new());
    for line in text.lines().map(str::trim) {
        let line = if inside {
            line
        } else if line.starts_with("ignore") && line.contains('[') {
            inside = true;
            line.split_once('[').map_or("", |(_, r)| r.trim())
        } else {
            continue;
        };
        if let Some(c) = line.strip_prefix('#') {
            notes.push(c.trim().to_string());
            continue;
        }
        for id in line.split(']').next().unwrap_or_default().split(',').filter_map(quoted) {
            let reason = notes.join(" ");
            out.push(json!({ "id": id, "reason": (!reason.is_empty()).then_some(reason.clone()), "hasReason": !reason.is_empty() }));
            notes.clear();
        }
        if line.contains(']') {
            break;
        }
    }
    out
}

fn quoted(s: &str) -> Option<String> {
    let s = s.trim();
    let inner = s.strip_prefix('"').and_then(|r| r.strip_suffix('"')).or_else(|| s.strip_prefix('\'').and_then(|r| r.strip_suffix('\'')))?;
    (!inner.is_empty()).then(|| inner.to_string())
}

/// A one-line YAML scalar: a quoted string's inside, or plain text up to a ` #` comment.
fn yaml_value(s: &str) -> String {
    let s = s.trim();
    if let Some(q) = s.chars().next().filter(|c| *c == '"' || *c == '\'') {
        if let Some(end) = s[1..].find(q) {
            return s[1..1 + end].to_string();
        }
    }
    uncomment(s).to_string()
}

fn uncomment(s: &str) -> &str {
    if s.starts_with('#') {
        return "";
    }
    s.split(" #").next().unwrap_or_default().trim()
}

/// A YAML block scalar's header (`>`, `|-`, `>+2`, then perhaps a comment), unquoted:
/// Some(true) when its lines fold.
fn block_header(v: &str) -> Option<bool> {
    let head = v.split(" #").next().unwrap_or_default().trim();
    let fold = match head.chars().next()? {
        '>' => true,
        '|' => false,
        _ => return None,
    };
    head[1..].chars().all(|c| c == '-' || c == '+' || c.is_ascii_digit()).then_some(fold)
}

/// `.grype.yaml`'s `ignore:` list: each entry's vulnerability, package, location and reason.
pub fn grype_accepted(text: &str) -> Vec<Value> {
    let mut out: Vec<Value> = Vec::new();
    let mut inside = false;
    // A block scalar reason (`reason: >` or `|`): the key's indent, whether lines fold, and the lines so far.
    let mut block: Option<(usize, bool, Vec<String>)> = None;
    let indent = |l: &str| l.len() - l.trim_start().len();
    for raw in text.lines() {
        let line = raw.trim();
        if let Some((at, fold, lines)) = &mut block {
            if line.is_empty() || indent(raw) > *at {
                lines.push(line.to_string());
                continue;
            }
            let joined = lines.join(if *fold { " " } else { "\n" }).trim().to_string();
            if let Some(e) = out.last_mut().filter(|_| !joined.is_empty()) {
                e["reason"] = json!(joined);
                e["hasReason"] = json!(true);
            }
            block = None;
        }
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        if !raw.starts_with(' ') && !raw.starts_with('-') {
            inside = uncomment(line) == "ignore:";
            continue;
        }
        if !inside {
            continue;
        }
        let (item, field) = match line.strip_prefix("- ") {
            Some(rest) => (true, rest.trim()),
            None => (false, line),
        };
        if item {
            out.push(json!({ "id": Value::Null, "package": Value::Null, "location": Value::Null, "reason": Value::Null, "hasReason": false }));
        }
        let Some(e) = out.last_mut() else { continue };
        let Some((k, v)) = field.split_once(':') else { continue };
        if k.trim() == "reason" {
            if let Some(fold) = block_header(v) {
                let key_at = indent(raw) + if item { 2 } else { 0 };
                block = Some((key_at, fold, Vec::new()));
                continue;
            }
        }
        let v = yaml_value(v);
        match k.trim() {
            "vulnerability" if !v.is_empty() => e["id"] = json!(v),
            "name" if !v.is_empty() => e["package"] = json!(v),
            "location" if !v.is_empty() => e["location"] = json!(v),
            "reason" if !v.is_empty() => {
                e["reason"] = json!(v);
                e["hasReason"] = json!(true);
            }
            _ => {}
        }
    }
    if let Some((_, fold, lines)) = block {
        let joined = lines.join(if fold { " " } else { "\n" }).trim().to_string();
        if let Some(e) = out.last_mut().filter(|_| !joined.is_empty()) {
            e["reason"] = json!(joined);
            e["hasReason"] = json!(true);
        }
    }
    out
}

fn accepted_file(path: &str, tool: &str, reply: &Result<Value, Unavailable>) -> Value {
    let r = match reply {
        Ok(r) => r,
        Err(u) => return json!({ "path": path, "tool": tool, "available": false, "status": u.status }),
    };
    let text = r["content"].as_str().map(|c| c.chars().filter(|c| !c.is_whitespace()).collect::<String>()).and_then(|c| base64::Engine::decode(&base64::engine::general_purpose::STANDARD, c).ok()).and_then(|b| String::from_utf8(b).ok());
    let Some(text) = text else { return json!({ "path": path, "tool": tool, "available": false, "why": "GitHub didn't send the file's text" }) };
    let findings = if tool == "cargo-audit" { cargo_audit_accepted(&text) } else { grype_accepted(&text) };
    json!({
        "path": path, "tool": tool, "available": true, "blobSha": r["sha"], "url": r["html_url"],
        "total": findings.len(), "withoutReason": findings.iter().filter(|f| f["hasReason"] != true).count(), "findings": findings,
    })
}

// Collecting

pub struct Options {
    pub repo: String,
    pub branch: Option<String>,
    pub period: Period,
    pub windows: Windows,
}

pub struct Collected {
    pub repo: Value,
    pub branch: String,
    pub dependabot: Result<usize, Unavailable>,
    pub code_scanning: Result<usize, Unavailable>,
    pub alerts: Vec<Value>,
    pub accepted: Vec<Value>,
    pub as_of: i64,
}

/// Everything for the bundle, read from GitHub. `now_ms` caps the judging time when the
/// period ends tomorrow.
pub fn collect(api: &mut dyn Api, o: &Options, now_ms: i64) -> Result<Collected, Failure> {
    let repo = &o.repo;
    let info = api.get(&format!("/repos/{repo}"))?.body;
    let branch = o.branch.clone().or_else(|| info["default_branch"].as_str().map(String::from)).unwrap_or_else(|| "main".into());
    if !valid_branch(&branch) {
        return Err(Failure::new(0, format!("{branch} isn't a branch name this tool reads")));
    }
    let p = &o.period;
    let as_of = p.end_ms().min(now_ms);
    let dependabot = listing(api, &format!("/repos/{repo}/dependabot/alerts?sort=created&direction=asc&per_page=100"))?;
    let code_scanning = listing(api, &format!("/repos/{repo}/code-scanning/alerts?ref={}&sort=created&direction=asc&per_page=100", enc(&format!("refs/heads/{branch}"))))?;
    let mut alerts = Vec::new();
    for (source, list) in [("dependabot", &dependabot), ("code-scanning", &code_scanning)] {
        alerts.extend(list.as_ref().into_iter().flatten().filter_map(|a| alert_view(source, a, p, as_of, &o.windows)));
    }
    alerts.sort_by_key(|a| (ms(&a["createdAt"]), a["source"].as_str().map(String::from), a["number"].as_u64()));
    let mut accepted = Vec::new();
    for (path, tool) in ACCEPTED {
        let reply = match api.get(&format!("/repos/{repo}/contents/{path}?ref={}", enc(&branch))) {
            Ok(r) => Ok(r.body),
            Err(f) if matches!(f.status, 401 | 403 | 404) => Err(Unavailable { status: f.status, message: f.message }),
            Err(f) => return Err(f),
        };
        accepted.push(accepted_file(path, tool, &reply));
    }
    let repo_view = json!({ "fullName": info["full_name"], "private": info["private"], "defaultBranch": info["default_branch"], "url": info["html_url"] });
    let count = |r: &Result<Vec<Value>, Unavailable>| r.as_ref().map(Vec::len).map_err(Clone::clone);
    Ok(Collected { repo: repo_view, branch, dependabot: count(&dependabot), code_scanning: count(&code_scanning), alerts, accepted, as_of })
}

// The bundle

fn source_view(r: &Result<usize, Unavailable>, why: &str, of: &[Value], source: &str) -> Value {
    match r {
        Ok(n) => json!({ "available": true, "alertsRead": n, "inPeriod": of.iter().filter(|a| a["source"] == source).count() }),
        Err(u) => unavailable_view(u, why),
    }
}

fn alerts_file(c: &Collected, w: &Windows) -> Value {
    let (by, exceptions) = tally(&c.alerts);
    json!({
        "repository": c.repo["fullName"],
        "branch": c.branch,
        "judgedAsOf": rfc3339(c.as_of),
        "windows": w.view(),
        "basis": "an alert is in the period if it was opened before its end and not closed before its start; it is closed in time if it was fixed or dismissed by its due date (opened plus its severity's window), and overdue if still open at the period's end past that date",
        "sources": {
            "dependabot": source_view(&c.dependabot, "Dependabot alerts need the token's Dependabot alerts read permission (vulnerability-alerts: read in a workflow) and Dependabot alerts turned on", &c.alerts, "dependabot"),
            "codeScanning": source_view(&c.code_scanning, "code scanning alerts need security-events read access, and an analysis uploaded for the branch", &c.alerts, "code-scanning"),
        },
        "summary": { "total": c.alerts.len(), "bySeverity": by },
        "exceptions": exceptions,
        "alerts": c.alerts,
    })
}

/// A bundle's name, without `.tar`.
pub fn name(p: &Period, now_ms: i64) -> String {
    let stamp = chrono::DateTime::from_timestamp_millis(now_ms).map(|t| t.format("%Y%m%dT%H%M%SZ").to_string()).unwrap_or_default();
    format!("{PREFIX}{}-{stamp}", p.label())
}

pub fn build(c: &Collected, p: &Period, w: &Windows, src: &crate::changes::Source, now_ms: i64) -> crate::changes::Bundle {
    let name = name(p, now_ms);
    let created = rfc3339(now_ms);
    let period = json!({ "from": p.from.to_string(), "to": p.to.to_string(), "days": p.days() });
    let mut alerts = alerts_file(c, w);
    alerts["periodCovered"] = period.clone();
    let accepted = json!({ "repository": c.repo["fullName"], "branch": c.branch, "asOf": created, "files": c.accepted });
    let mut files: Vec<(&str, Vec<u8>)> = vec![
        ("README.txt", README.as_bytes().to_vec()),
        ("vulnerability-alerts.json", json_file(&alerts)),
        ("accepted-findings.json", json_file(&accepted)),
    ];
    let listed: Vec<Value> = files
        .iter()
        .map(|(n, b)| {
            let s = SECTIONS.iter().find(|s| s.file == *n);
            json!({ "name": n, "bytes": b.len(), "sha256": sha256(b), "criteria": s.map(|s| s.criteria).unwrap_or_default(), "checklist": s.map(|s| s.rows).unwrap_or_default() })
        })
        .collect();
    let manifest = json!({
        "product": "SuperBot",
        "kind": "vulnerability-management",
        "format": FORMAT,
        "tool": concat!("superbot-evidence ", env!("CARGO_PKG_VERSION")),
        "createdAt": created,
        "period": period,
        "windows": w.view(),
        "source": {
            "api": src.api_host, "repository": c.repo["fullName"], "private": c.repo["private"], "branch": c.branch,
            "requests": src.requests,
            "tokenScopes": src.scopes,
            "tokenCanWrite": src.scopes.as_deref().map(crate::changes::can_write),
            "dependabot": c.dependabot.is_ok(),
            "codeScanning": c.code_scanning.is_ok(),
        },
        "alerts": c.alerts.len(),
        "files": listed,
        "notIncluded": "the token, dismissal comments, advisory descriptions, code snippets and alert messages",
    });
    files.push(("manifest.json", json_file(&manifest)));
    let sums: String = files.iter().map(|(n, b)| format!("{}  {n}\n", sha256(b))).collect();
    let manifest_sha256 = sha256(&files.last().expect("the manifest").1);
    files.push(("SHA256SUMS", sums.into_bytes()));
    let entries: Vec<(String, Vec<u8>)> = files.iter().map(|(n, b)| (format!("{name}/{n}"), b.clone())).collect();
    let tar = crate::ustar::tar(&entries, (now_ms / 1000).max(0) as u64);
    crate::changes::Bundle { sha256: sha256(&tar), manifest_sha256, name, tar }
}

/// The lines printed after saving.
pub fn summary(c: &Collected) -> String {
    let (by, ex) = tally(&c.alerts);
    let sum = |k: &str| SEVERITIES.iter().map(|s| by[*s][k].as_u64().unwrap_or_default()).sum::<u64>();
    let mut out = format!(
        "{} alerts open at some time in the period: {} closed in it ({} fixed, {} dismissed), {} open at its end.",
        c.alerts.len(),
        sum("closed"),
        sum("fixed"),
        sum("dismissed"),
        sum("openAtEnd")
    );
    for (k, label) in [
        ("closedLate", "Closed after their due date"),
        ("overdueAtEnd", "Open past their due date at the period's end"),
        ("dismissedWithoutReason", "Dismissed without a reason"),
        ("noSeverity", "Without a severity (given the strictest window)"),
    ] {
        if let Some(v) = ex[k].as_array().filter(|v| !v.is_empty()) {
            out += &format!("\n  {label}: {}", v.iter().filter_map(Value::as_str).collect::<Vec<_>>().join(", "));
        }
    }
    for (label, r) in [("Dependabot alerts", &c.dependabot), ("Code scanning alerts", &c.code_scanning)] {
        if let Err(u) = r {
            out += &format!("\n  {label} weren't readable (GitHub answered {}): the bundle says so.", u.status);
        }
    }
    for f in &c.accepted {
        let path = f["path"].as_str().unwrap_or_default();
        if f["available"] == true {
            out += &format!("\n  {path}: {} accepted findings, {} without a reason.", f["total"], f["withoutReason"]);
        } else {
            let why = f["status"].as_u64().map_or_else(|| f["why"].as_str().unwrap_or("unreadable").to_string(), |s| format!("GitHub answered {s}"));
            out += &format!("\n  {path} wasn't readable ({why}): its accepted findings aren't in the bundle.");
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::github::Reply;
    use std::collections::HashMap;

    fn period() -> Period {
        let d = |s: &str| chrono::NaiveDate::parse_from_str(s, "%Y-%m-%d").unwrap();
        Period { from: d("2026-10-01"), to: d("2026-11-01") }
    }

    fn end() -> i64 {
        period().end_ms()
    }

    fn dep(n: u64, sev: &str, created: &str, state: &str, closed_at: Option<&str>) -> Value {
        let mut a = json!({
            "number": n, "state": state, "created_at": created, "updated_at": "2026-11-20T00:00:00Z", "html_url": format!("https://github.com/o/r/security/dependabot/{n}"),
            "dependency": { "package": { "ecosystem": "rust", "name": "crate-x" }, "manifest_path": "Cargo.lock", "scope": "runtime" },
            "security_advisory": { "ghsa_id": format!("GHSA-{n}"), "cve_id": null, "severity": sev, "summary": "advisory summary never kept", "description": "advisory description never kept" },
            "security_vulnerability": { "severity": sev, "first_patched_version": { "identifier": "1.2.3" } },
            "dismissed_comment": "dismissal comment never kept",
        });
        match state {
            "fixed" => a["fixed_at"] = json!(closed_at),
            "dismissed" => {
                a["dismissed_at"] = json!(closed_at);
                a["dismissed_reason"] = json!("tolerable_risk");
                a["dismissed_by"] = json!({ "login": "maintainer-m" });
            }
            _ => {}
        }
        a
    }

    fn view(a: &Value) -> Option<Value> {
        alert_view("dependabot", a, &period(), end(), &Windows::default())
    }

    #[test]
    fn alerts_open_in_the_period_are_judged_against_their_window() {
        assert!(view(&dep(1, "high", "2026-11-01T00:00:00Z", "open", None)).is_none(), "opened after the period");
        assert!(view(&dep(2, "high", "2026-08-01T00:00:00Z", "fixed", Some("2026-09-30T23:59:59Z"))).is_none(), "closed before it");

        let v = view(&dep(3, "critical", "2026-10-02T00:00:00Z", "fixed", Some("2026-10-20T00:00:00Z"))).unwrap();
        assert_eq!((v["withinWindow"].clone(), v["closedHow"].clone(), v["daysToClose"].as_f64(), v["dueAt"].as_str()), (json!(true), json!("fixed"), Some(18.0), Some("2026-11-01T00:00:00Z")));
        assert_eq!((v["openedInPeriod"].clone(), v["closedInPeriod"].clone(), v["openAtEnd"].clone()), (json!(true), json!(true), json!(false)));

        let late = view(&dep(4, "high", "2026-09-01T00:00:00Z", "fixed", Some("2026-10-15T00:00:00Z"))).unwrap();
        assert_eq!((late["withinWindow"].clone(), late["openAtStart"].clone()), (json!(false), json!(true)), "30 days for High; fixed on day 44");

        let overdue = view(&dep(5, "high", "2026-09-15T00:00:00Z", "open", None)).unwrap();
        assert_eq!((overdue["overdueAtEnd"].clone(), overdue["withinWindow"].clone(), overdue["daysOpenAtEnd"].as_f64()), (json!(true), json!(false), Some(47.0)));

        let not_yet = view(&dep(6, "medium", "2026-09-15T00:00:00Z", "open", None)).unwrap();
        assert_eq!((not_yet["overdueAtEnd"].clone(), not_yet["withinWindow"].clone(), not_yet["fixWithinDays"].as_i64()), (json!(false), Value::Null, Some(90)), "90 days for Medium: not yet due");

        let after = view(&dep(7, "high", "2026-09-01T00:00:00Z", "fixed", Some("2026-11-05T00:00:00Z"))).unwrap();
        assert_eq!((after["openAtEnd"].clone(), after["closedInPeriod"].clone(), after["overdueAtEnd"].clone(), after["stateNow"].clone()), (json!(true), json!(false), json!(true), json!("fixed")), "fixed after the period: open and overdue at its end");

        let dismissed = view(&dep(8, "low", "2026-10-01T00:00:00Z", "dismissed", Some("2026-10-03T00:00:00Z"))).unwrap();
        assert_eq!((dismissed["closedHow"].clone(), dismissed["dismissedReason"].clone(), dismissed["dismissedBy"].clone()), (json!("dismissed"), json!("tolerable_risk"), json!("maintainer-m")));
        let text = dismissed.to_string();
        assert!(!text.contains("never kept"), "no comments or advisory text: {text}");
        assert_eq!(dismissed["advisory"]["ghsa"], "GHSA-8");

        let mut approx = dep(9, "high", "2026-10-01T00:00:00Z", "fixed", None);
        approx["updated_at"] = json!("2026-10-05T00:00:00Z");
        let v = view(&approx).unwrap();
        assert_eq!((v["closedAtApproximate"].clone(), v["withinWindow"].clone()), (json!(true), json!(true)), "a fixed alert without fixed_at falls back to updated_at, and says so");

        let early = alert_view("dependabot", &dep(10, "high", "2026-10-01T00:00:00Z", "open", None), &period(), period().start_ms() + 5 * DAY_MS, &Windows::default()).unwrap();
        assert_eq!(early["overdueAtEnd"], false, "judged as of now when the period hasn't ended");
    }

    #[test]
    fn code_scanning_severity_comes_from_the_security_level_then_the_rule() {
        let cs = |level: Option<&str>, rule: Option<&str>| json!({ "number": 1, "state": "open", "created_at": "2026-10-02T00:00:00Z", "rule": { "id": "CVE-2026-1", "security_severity_level": level, "severity": rule, "description": "never kept" }, "tool": { "name": "Grype", "version": "0.1" }, "most_recent_instance": { "ref": "refs/heads/main", "location": { "path": "/usr/bin/age" }, "message": { "text": "message never kept" } } });
        let sev = |a: &Value| alert_view("code-scanning", a, &period(), end(), &Windows::default()).unwrap()["severity"].as_str().unwrap().to_string();
        assert_eq!(sev(&cs(Some("critical"), Some("warning"))), "critical");
        assert_eq!(sev(&cs(None, Some("error"))), "high");
        assert_eq!(sev(&cs(None, Some("note"))), "low");
        let v = alert_view("code-scanning", &cs(None, None), &period(), end(), &Windows::default()).unwrap();
        assert_eq!((v["severity"].as_str(), v["fixWithinDays"].as_i64(), v["id"].as_str()), (Some("unknown"), Some(30), Some("code-scanning#1")), "unknown gets the strictest window");
        assert_eq!((v["rule"]["tool"].as_str(), v["location"]["path"].as_str()), (Some("Grype"), Some("/usr/bin/age")));
        assert!(!v.to_string().contains("never kept"));
    }

    #[test]
    fn tallies_and_exceptions() {
        let alerts: Vec<Value> = [
            dep(3, "critical", "2026-10-02T00:00:00Z", "fixed", Some("2026-10-20T00:00:00Z")),
            dep(4, "high", "2026-09-01T00:00:00Z", "fixed", Some("2026-10-15T00:00:00Z")),
            dep(5, "high", "2026-09-15T00:00:00Z", "open", None),
            dep(8, "low", "2026-10-01T00:00:00Z", "dismissed", Some("2026-10-03T00:00:00Z")),
        ]
        .iter()
        .filter_map(view)
        .collect();
        let mut no_reason = view(&dep(11, "medium", "2026-10-01T00:00:00Z", "dismissed", Some("2026-10-02T00:00:00Z"))).unwrap();
        no_reason["dismissedReason"] = Value::Null;
        let alerts = [alerts, vec![no_reason]].concat();
        let (by, ex) = tally(&alerts);
        assert_eq!(by["high"], json!({ "openAtStart": 2, "opened": 0, "closed": 1, "fixed": 1, "dismissed": 0, "closedWithinWindow": 0, "closedLate": 1, "openAtEnd": 1, "overdueAtEnd": 1, "medianDaysToClose": 44.0 }));
        assert_eq!((by["critical"]["closedWithinWindow"].as_u64(), by["low"]["dismissed"].as_u64(), by["unknown"]["opened"].as_u64()), (Some(1), Some(1), Some(0)));
        assert_eq!(ex, json!({ "closedLate": ["dependabot#4"], "overdueAtEnd": ["dependabot#5"], "dismissedWithoutReason": ["dependabot#11"], "noSeverity": [] }));
        assert_eq!(median(vec![1.0, 4.0, 2.0, 10.0]), json!(3.0));
    }

    #[test]
    fn windows_default_to_the_policy_and_can_be_set() {
        let d = Windows::default();
        assert_eq!((d.days("critical"), d.days("high"), d.days("medium"), d.days("low"), d.days("unknown")), (30, 30, 90, 90, 30));
        let w = Windows::parse("critical=7, high=14").unwrap();
        assert_eq!((w.days("critical"), w.days("high"), w.days("low"), w.days("unknown")), (7, 14, 90, 7));
        for bad in ["critical", "urgent=3", "high=0", "high=400", "high=x"] {
            assert!(Windows::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn accepted_findings_are_read_with_their_reasons() {
        let cargo = include_str!("../../../../.cargo/audit.toml");
        let got = cargo_audit_accepted(cargo);
        assert!(!got.is_empty() && got.iter().all(|f| f["hasReason"] == true && f["id"].as_str().is_some_and(|i| i.starts_with("RUSTSEC-"))), "{got:?}");
        let inline = cargo_audit_accepted("[advisories]\nignore = [\"RUSTSEC-1\", \"RUSTSEC-2\"]\n");
        assert_eq!(inline.iter().map(|f| (f["id"].as_str().unwrap(), f["hasReason"].as_bool().unwrap())).collect::<Vec<_>>(), [("RUSTSEC-1", false), ("RUSTSEC-2", false)]);
        let two = cargo_audit_accepted("ignore = [\n  # why one\n  \"A\",\n  \"B\",\n  # why\n  # three\n  \"C\",\n]\nother = [\"D\"]\n");
        assert_eq!(two.iter().map(|f| (f["id"].as_str().unwrap(), f["reason"].as_str())).collect::<Vec<_>>(), [("A", Some("why one")), ("B", None), ("C", Some("why three"))]);

        let grype = grype_accepted(include_str!("../../../../.grype.yaml"));
        assert!(!grype.is_empty() && grype.iter().all(|f| f["hasReason"] == true && f["id"].is_string() && f["package"].is_string()), "{grype:?}");
        assert_eq!(grype[0]["location"], "/usr/bin/age*");
        let opening = cargo_audit_accepted("ignore = [\"RUSTSEC-1\",\n  # why two\n  \"RUSTSEC-2\",\n]\n");
        assert_eq!(opening.iter().map(|f| f["id"].as_str().unwrap()).collect::<Vec<_>>(), ["RUSTSEC-1", "RUSTSEC-2"], "an entry on the opening line counts");
        let blocks = grype_accepted("ignore:\n  - vulnerability: CVE-4\n    reason: >\n      folded over\n      two lines\n    package:\n      name: zlib\n  - vulnerability: CVE-5\n    reason: |-\n      kept\n      apart\n  - vulnerability: CVE-6\n    reason: >\n");
        assert_eq!(blocks.iter().map(|f| (f["id"].as_str().unwrap(), f["reason"].as_str(), f["hasReason"].as_bool().unwrap())).collect::<Vec<_>>(), [("CVE-4", Some("folded over two lines"), true), ("CVE-5", Some("kept\napart"), true), ("CVE-6", None, false)], "block scalars keep their text, and an empty one is no reason");
        assert_eq!(blocks[0]["package"], "zlib");
        let quoted_marks = grype_accepted("ignore:\n  - vulnerability: CVE-7\n    reason: \"> 30 days needed upstream\"\n  - vulnerability: CVE-8\n    reason: |-  # a comment\n      kept\n");
        let commented = grype_accepted("ignore: # accepted findings\n  - vulnerability: CVE-9 # note\n    reason: \"a # in quotes\" # note\n");
        assert_eq!((commented.len(), commented[0]["id"].as_str(), commented[0]["reason"].as_str()), (1, Some("CVE-9"), Some("a # in quotes")), "comments after a key or value are not part of it");
        assert_eq!(quoted_marks.iter().map(|f| f["reason"].as_str()).collect::<Vec<_>>(), [Some("> 30 days needed upstream"), Some("kept")], "a quoted reason starting with > is text, not a block");
        let g = grype_accepted("ignore:\n  # CVE-YYYY-NNNNN example\n  - vulnerability: CVE-1\n    package:\n      name: zlib\n  - vulnerability: \"CVE-2\"\n    reason: 'fixed upstream'\nother:\n  - vulnerability: CVE-3\n");
        assert_eq!(g.iter().map(|f| (f["id"].as_str().unwrap(), f["reason"].as_str())).collect::<Vec<_>>(), [("CVE-1", None), ("CVE-2", Some("fixed upstream"))]);
    }

    struct Fake(HashMap<String, Result<(Value, Option<String>), u16>>);

    impl Api for Fake {
        fn get(&mut self, path: &str) -> Result<Reply, Failure> {
            match self.0.get(path).cloned() {
                Some(Ok((body, next))) => Ok(Reply { body, next }),
                Some(Err(s)) => Err(Failure::new(s, format!("GitHub answered {s} for {path}: Dependabot alerts are disabled"))),
                None => Err(Failure::new(500, format!("no fixture for {path}"))),
            }
        }
    }

    #[test]
    fn a_source_the_token_cant_read_is_recorded_not_fatal() {
        let mut f = Fake(HashMap::new());
        f.0.insert("/repos/o/r".into(), Ok((json!({ "full_name": "o/r", "default_branch": "main" }), None)));
        f.0.insert("/repos/o/r/dependabot/alerts?sort=created&direction=asc&per_page=100".into(), Err(403));
        f.0.insert(format!("/repos/o/r/code-scanning/alerts?ref={}&sort=created&direction=asc&per_page=100", enc("refs/heads/main")), Ok((json!([dep(1, "high", "2026-10-05T00:00:00Z", "open", None)]), Some("cs-2".into()))));
        f.0.insert("cs-2".into(), Ok((json!([]), None)));
        f.0.insert("/repos/o/r/contents/.cargo/audit.toml?ref=main".into(), Err(404));
        let toml = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, "ignore = [\n # reason\n \"RUSTSEC-9\",\n]\n");
        let wrapped = format!("{}\n{}", &toml[..10], &toml[10..]);
        f.0.insert("/repos/o/r/contents/.grype.yaml?ref=main".into(), Ok((json!({ "content": wrapped, "sha": "abc" }), None)));
        let o = Options { repo: "o/r".into(), branch: None, period: period(), windows: Windows::default() };
        let c = collect(&mut f, &o, i64::MAX).unwrap();
        assert_eq!(c.dependabot.as_ref().unwrap_err().status, 403);
        assert_eq!((c.code_scanning.clone(), c.alerts.len()), (Ok(1), 1));
        assert_eq!((c.accepted[0]["available"].clone(), c.accepted[0]["status"].clone()), (json!(false), json!(404)));
        assert_eq!(c.accepted[1]["available"], true, "decoded across GitHub's line breaks");
        let s = summary(&c);
        assert!(s.contains("Dependabot alerts weren't readable (GitHub answered 403)") && s.contains("1 alerts open"), "{s}");
        assert!(s.contains(".cargo/audit.toml wasn't readable (GitHub answered 404)"), "{s}");
        let mut broken = Fake(HashMap::new());
        broken.0.insert("/repos/o/r".into(), Ok((json!({ "default_branch": "main" }), None)));
        assert_eq!(collect(&mut broken, &o, i64::MAX).err().map(|f| f.status), Some(500), "a server error is a failure, not a gap");
    }

    #[test]
    fn names_never_collide_with_the_other_bundles() {
        let n = name(&period(), 1_795_000_000_000);
        assert!(n.starts_with("superbot-vulns-2026-10-01_2026-11-01-") && n.ends_with('Z'), "{n}");
        assert!(n.len() + "/vulnerability-alerts.json".len() <= 100, "fits a ustar name");
        assert!(!n.starts_with("superbot-evidence-") && !n.starts_with(crate::changes::PREFIX));
    }

    /// Every file maps to criteria the control mapping has and checklist rows the readiness
    /// checklist has, each under one of its criteria, and the evidence plan's vulnerability
    /// table lists each file with them.
    #[test]
    fn every_file_maps_to_real_controls_and_the_evidence_plan_says_so() {
        let mapping = include_str!("../../../../docs/security/soc2-control-mapping.md");
        let checklist = include_str!("../../../../docs/security/soc2-readiness-checklist.md");
        let plan = include_str!("../../../../docs/security/soc2-evidence-plan.md");
        for s in &SECTIONS {
            for c in s.criteria {
                assert!(mapping.contains(&format!("| {c} ")), "{}: {c} isn't a criterion of the control mapping", s.file);
            }
            for r in s.rows {
                assert!(checklist.contains(&format!("| {r} |")), "{}: {r} isn't a row of the readiness checklist", s.file);
                assert!(s.criteria.iter().any(|c| r.starts_with(&format!("{c}-"))), "{}: {r} isn't under one of its criteria", s.file);
            }
            let line = plan.lines().find(|l| l.starts_with(&format!("| `{}` |", s.file))).unwrap_or_else(|| panic!("the evidence plan's vulnerability table has no row for `{}`", s.file));
            for id in s.criteria.iter().chain(s.rows) {
                assert!(line.contains(id), "the evidence plan's row for `{}` doesn't name {id}", s.file);
            }
        }
        let info = include_str!("../../../../docs/security/policies/information-security.md");
        let d = Windows::default();
        assert!(info.contains(&format!("| Critical, High | {} days |", d.days("critical"))) && info.contains(&format!("| Medium, Low | {} days |", d.days("medium"))), "the default windows are the policy's");
        assert_eq!((d.days("critical"), d.days("medium")), (d.days("high"), d.days("low")));
    }
}
