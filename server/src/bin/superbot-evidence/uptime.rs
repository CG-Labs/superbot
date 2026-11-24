//! Uptime evidence (ADR 0249): the availability SLO (docs/slo.md) measured from the
//! outside probe's own checks of `/status.json`, for a period. Each minute is up when any
//! check in it succeeded, down when it had checks and all of them failed, and unmeasured
//! when it had none; announced maintenance doesn't count, up to 4 hours a month. Each
//! calendar month and the period are judged against the server's objective and every
//! plan's, with the error budget spent, every outage (and the ones that spent more than a
//! quarter of the 30-day budget, which need a written review), and the gaps in the probe's
//! record. The checks come from Prometheus (the blackbox exporter's `probe_success`) or
//! from files any other probe exports. A dated bundle in the shape of the change-management
//! bundle (ADR 0148).
//!
//! Never in it: the token, the Prometheus address, or labels other than the probe's job and
//! location; only checks' results and times.

use crate::changes::{json_file, rfc3339, sha256};
use crate::period::Period;
use crate::prometheus::{self, Api};
use chrono::{Datelike, NaiveDate};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

/// Bumped when a file's shape changes, so tools reading bundles can tell them apart.
pub const FORMAT: u32 = 1;
pub const PREFIX: &str = "superbot-uptime-";
/// The largest checks file read: a month of checks every 30 seconds from a few places is a
/// few MiB.
pub const MAX_CHECKS_BYTES: u64 = 64 << 20;
/// The probe deploy/README.md sets up and the `SuperBotStatusProbeFailing` alert reads.
pub const DEFAULT_QUERY: &str = r#"probe_success{job="superbot-status"}"#;
/// The objective a server is run to by default: its strictest plan's, as the burn-rate
/// rules' `superbot:slo_availability:target`. In hundredths of a percent.
pub const DEFAULT_OBJECTIVE: u32 = 9990;
/// docs/slo.md's objectives per plan, in hundredths of a percent; a test checks its table.
pub const PLANS: [(&str, u32); 4] = [("Starter", 9950), ("Pro", 9990), ("Max", 9990), ("Enterprise", 9995)];
/// Announced maintenance that doesn't count, per calendar month (docs/slo.md).
pub const MAINTENANCE_MINUTES_A_MONTH: usize = 240;
/// The error budget's rolling window (docs/slo.md). An outage that spent more than a
/// quarter of its budget needs a written review.
pub const WINDOW_MINUTES: u64 = 30 * 1440;
/// A run of unmeasured minutes this long is listed as a gap in the probe's record.
pub const GAP_MINUTES: usize = 5;
/// How much of the period one Prometheus request reads: a day of checks every 30 seconds
/// is 2,880 samples a series.
const CHUNK_SECS: i64 = 86_400;
/// Labels shown for a Prometheus series: the job, and where the probe ran. The rest (the
/// target's address above all) stay out.
const SHOWN_LABELS: [&str; 7] = ["job", "location", "region", "probe", "site", "zone", "source"];

/// One file of the bundle and the criteria and checklist rows it is evidence for. The
/// evidence plan's uptime table must match. The manifest maps it to them only when the
/// probe's gaps are within the objective's error budget for the period, so a month the
/// probe didn't watch shows as a gap in the coverage report.
pub struct Section {
    pub file: &'static str,
    pub criteria: &'static [&'static str],
    pub rows: &'static [&'static str],
}

pub const SECTIONS: [Section; 1] = [Section { file: "uptime.json", criteria: &["A1.1"], rows: &["A1.1-3"] }];

const README: &str = "SuperBot uptime evidence bundle
===============================

Made by superbot-evidence, for a SOC 2 Type II evidence store
(docs/security/soc2-evidence-plan.md, ADR 0249). It covers the period in manifest.json:
from its first day (00:00 UTC) up to, not including, its last.

  uptime.json    the availability SLO (docs/slo.md) measured from the outside probe's
                 checks of /status.json: each calendar month and the period against the
                 server's objective and every plan's, the error budget spent, every
                 outage and those needing a written review, each day's down, unmeasured
                 and maintenance minutes, the gaps in the probe's record, and the
                 exceptions
  manifest.json  what is in this bundle, the period, where the checks came from, and
                 each file's SHA-256
  SHA256SUMS     the same digests, for `sha256sum -c SHA256SUMS`

Never in it: the token, the Prometheus address, or any label but the probe's job and
location. A minute is down when it had checks and every one failed, so the probe's
own record is the evidence: keep its export (or the checks files named in
manifest.json, by SHA-256) beside this bundle.
";

// The checks

/// One check of the probe: when, whether `/status.json` answered 2xx, and which series
/// (a probe location, or a file) it came from.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Check {
    pub at_ms: i64,
    pub ok: bool,
    pub series: usize,
}

/// The probe's checks and where they came from.
#[derive(Debug, Default)]
pub struct Probe {
    /// For the manifest: Prometheus and the query, or each file with its SHA-256.
    pub source: Value,
    /// Each series as shown in the bundle: an id and the labels kept.
    pub series: Vec<Value>,
    pub checks: Vec<Check>,
    pub requests: u64,
}

/// One label matcher of a series selector: `location=~"lon|fra"`.
struct Matcher {
    label: String,
    op: &'static str,
    value: String,
}

/// A series selector, parsed: the metric name (maybe empty) and its label matchers. Only a
/// selector can be read as a range vector of raw samples (`probe_success{job="superbot-status"}`).
/// Values are quoted as PromQL quotes them (`"`, `'` or a raw `` ` ``), so a regex's brackets
/// are part of its value.
fn parse_selector(s: &str) -> Option<(String, Vec<Matcher>)> {
    if s.len() > 512 || s.contains(['\n', '\r']) {
        return None;
    }
    let s = s.trim();
    let name_end = s.find(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == ':')).unwrap_or(s.len());
    let name = &s[..name_end];
    if name.starts_with(|c: char| c.is_ascii_digit()) {
        return None;
    }
    let rest = s[name_end..].trim_start();
    let mut matchers = Vec::new();
    if !rest.is_empty() {
        let mut cs = rest.strip_prefix('{')?.chars().peekable();
        let skip = |cs: &mut std::iter::Peekable<std::str::Chars>| {
            while cs.next_if(|c| c.is_whitespace()).is_some() {}
        };
        loop {
            skip(&mut cs);
            if cs.next_if_eq(&'}').is_some() {
                break;
            }
            let mut label = String::new();
            while let Some(c) = cs.next_if(|c| c.is_ascii_alphanumeric() || *c == '_') {
                label.push(c);
            }
            if label.is_empty() || label.starts_with(|c: char| c.is_ascii_digit()) {
                return None;
            }
            skip(&mut cs);
            let op = match (cs.next()?, cs.peek().copied()) {
                ('=', Some('~')) => "=~",
                ('=', _) => "=",
                ('!', Some('=')) => "!=",
                ('!', Some('~')) => "!~",
                _ => return None,
            };
            if op.len() == 2 {
                cs.next();
            }
            skip(&mut cs);
            let quote = cs.next().filter(|q| ['"', '\'', '`'].contains(q))?;
            let mut value = String::new();
            loop {
                match cs.next()? {
                    c if c == quote => break,
                    '\\' if quote != '`' => value.push(cs.next()?),
                    c => value.push(c),
                }
            }
            matchers.push(Matcher { label, op, value });
            skip(&mut cs);
            match cs.next()? {
                ',' => continue,
                '}' => break,
                _ => return None,
            }
        }
        if cs.any(|c| !c.is_whitespace()) {
            return None;
        }
    }
    (!name.is_empty() || !matchers.is_empty()).then(|| (name.to_string(), matchers))
}

/// `--query`: a series selector.
pub fn valid_selector(s: &str) -> bool {
    parse_selector(s).is_some()
}

/// The query as the bundle records it: the metric, each matcher's label and operator, and
/// the values of the job and location labels when plain; any other value (a target's
/// address, say) is left out.
fn shown_query(selector: &str) -> String {
    let Some((name, matchers)) = parse_selector(selector) else { return "<not a selector>".into() };
    if matchers.is_empty() {
        return name;
    }
    let shown: Vec<String> = matchers
        .iter()
        .map(|m| {
            let value = if SHOWN_LABELS.contains(&m.label.as_str()) && m.value.bytes().all(|c| c.is_ascii_alphanumeric() || b"._:-/|".contains(&c)) { m.value.as_str() } else { "<not recorded>" };
            format!("{}{}\"{value}\"", m.label, m.op)
        })
        .collect();
    format!("{name}{{{}}}", shown.join(","))
}

/// Which server a Prometheus series probed: the blackbox exporter's `target`, or the
/// `instance` it is usually relabelled to.
fn target_of(labels: &serde_json::Map<String, Value>) -> String {
    labels.get("target").or_else(|| labels.get("instance")).and_then(Value::as_str).unwrap_or_default().to_string()
}

fn plain(s: &str, max: usize) -> bool {
    !s.is_empty() && s.len() <= max && s.bytes().all(|c| c.is_ascii_alphanumeric() || b"._:-/".contains(&c))
}

/// One series of a Prometheus answer as the bundle shows it: an id from all its labels,
/// and the job and location labels when their values are plain.
fn series_view(labels: &serde_json::Map<String, Value>) -> Value {
    let canonical: BTreeMap<&String, &Value> = labels.iter().collect();
    let id = format!("prometheus-{}", &sha256(serde_json::to_string(&canonical).unwrap_or_default().as_bytes())[..12]);
    let shown: serde_json::Map<String, Value> = SHOWN_LABELS.iter().filter_map(|k| labels.get(*k).and_then(Value::as_str).filter(|v| plain(v, 64)).map(|v| (k.to_string(), json!(v)))).collect();
    json!({ "id": id, "labels": shown })
}

/// Every check of `selector` in the period, a day at a time, from Prometheus' raw samples.
/// Each request reads a minute more than its day, and only the day's samples are kept, so
/// none is missed at a boundary or counted twice.
pub fn fetch(api: &mut dyn Api, selector: &str, p: &Period) -> Result<Probe, String> {
    let (start, end) = (p.start_ms() / 1000, p.end_ms() / 1000);
    let mut keys: BTreeMap<String, usize> = BTreeMap::new();
    let mut targets: BTreeSet<String> = BTreeSet::new();
    let mut probe = Probe { source: json!({ "kind": "prometheus", "query": shown_query(selector), "basis": "raw samples of a range vector, read a day at a time" }), ..Probe::default() };
    let mut t = start;
    while t < end {
        let to = (t + CHUNK_SECS).min(end);
        let data = api.query(&format!("{selector}[{}s]", to - t + 60), to)?;
        probe.requests += 1;
        if data["resultType"] != "matrix" {
            return Err(format!("Prometheus answered a {} for {selector}: give a series selector, as {DEFAULT_QUERY}", data["resultType"].as_str().unwrap_or("result")));
        }
        for r in data["result"].as_array().into_iter().flatten() {
            let labels = r["metric"].as_object().cloned().unwrap_or_default();
            let key = serde_json::to_string(&labels.iter().collect::<BTreeMap<_, _>>()).unwrap_or_default();
            for v in r["values"].as_array().into_iter().flatten() {
                let Some(secs) = v[0].as_f64() else { continue };
                let at_ms = (secs * 1000.0).round() as i64;
                if at_ms < t * 1000 || at_ms >= to * 1000 {
                    continue;
                }
                let Some(value) = v[1].as_str().and_then(|s| s.parse::<f64>().ok()).filter(|x| !x.is_nan()) else { continue };
                let n = keys.len();
                let series = *keys.entry(key.clone()).or_insert_with(|| {
                    targets.insert(target_of(&labels));
                    probe.series.push(series_view(&labels));
                    n
                });
                probe.checks.push(Check { at_ms, ok: value > 0.0, series });
            }
        }
        t = to;
    }
    if targets.len() > 1 {
        return Err(format!(
            "{selector} returns the probe of {} servers, and one server's answers would hide another's outages: measure one at a time, adding its target to --query ({}{{job=\"superbot-status\",instance=\"<its status URL>\"}})",
            targets.len(),
            parse_selector(selector).map(|(n, _)| n).filter(|n| !n.is_empty()).unwrap_or_else(|| "probe_success".into())
        ));
    }
    Ok(probe)
}

fn parse_time(s: &str) -> Option<i64> {
    if let Ok(t) = chrono::DateTime::parse_from_rfc3339(s) {
        return Some(t.timestamp_millis());
    }
    let secs: f64 = s.parse().ok().filter(|x: &f64| x.is_finite() && *x > 0.0)?;
    Some((secs * 1000.0).round() as i64)
}

fn parse_ok(s: &str) -> Option<bool> {
    match s.to_ascii_lowercase().as_str() {
        "1" | "true" | "up" => Some(true),
        "0" | "false" | "down" => Some(false),
        _ => None,
    }
}

/// A checks file any probe can export: one check a line, `<time>,<result>[,<location>]`,
/// the time as RFC 3339 or Unix seconds, the result `1`, `true` or `up` for a 2xx answer
/// and `0`, `false` or `down` for anything else; `#` comments are skipped, and so is a
/// first line of column names (letters only, no digits), so a mistyped first check is
/// refused rather than taken for a header. Each location is a series of its own.
pub fn read_checks(file: &str, bytes: &[u8], probe: &mut Probe) -> Result<(), String> {
    let text = std::str::from_utf8(bytes).map_err(|_| format!("{file} isn't UTF-8 text"))?;
    let name = Path::new(file).file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    let mut local: BTreeMap<String, usize> = BTreeMap::new();
    let (mut bad, mut read, mut first) = (Vec::new(), 0usize, true);
    for (i, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let cells: Vec<&str> = line.split(',').map(str::trim).collect();
        let header = first && cells.iter().all(|c| !c.is_empty() && c.chars().all(|c| c.is_alphabetic() || " _-()./".contains(c)));
        first = false;
        if header {
            continue;
        }
        let parsed = match cells.as_slice() {
            [t, r] | [t, r, _] => parse_time(t).zip(parse_ok(r)),
            _ => None,
        };
        let Some((at_ms, ok)) = parsed else {
            bad.push(i + 1);
            continue;
        };
        let location = cells.get(2).copied().unwrap_or_default();
        if !location.is_empty() && !plain(location, 64) {
            bad.push(i + 1);
            continue;
        }
        let n = probe.series.len();
        let series = *local.entry(location.to_string()).or_insert_with(|| {
            let id = if location.is_empty() { name.clone() } else { format!("{name}:{location}") };
            probe.series.push(json!({ "id": id, "labels": if location.is_empty() { json!({}) } else { json!({ "location": location }) } }));
            n
        });
        probe.checks.push(Check { at_ms, ok, series });
        read += 1;
    }
    if !bad.is_empty() {
        let shown: Vec<String> = bad.iter().take(5).map(usize::to_string).collect();
        return Err(format!("{file}: line {} {} not <time>,<result>[,<location>] (time as RFC 3339 or Unix seconds; result 1/0, true/false or up/down; location plain)", shown.join(", "), if bad.len() == 1 { "is" } else { "are" }));
    }
    if read == 0 {
        return Err(format!("{file} holds no checks"));
    }
    let files = probe.source.as_object_mut().and_then(|o| o.get_mut("files")).and_then(Value::as_array_mut);
    let entry = json!({ "file": name, "bytes": bytes.len(), "sha256": sha256(bytes), "checks": read });
    match files {
        Some(f) => f.push(entry),
        None => probe.source = json!({ "kind": "files", "files": [entry] }),
    }
    Ok(())
}

// Maintenance

/// A window of announced maintenance, from `--maintenance <from>/<to>` (RFC 3339).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Window {
    pub from_ms: i64,
    pub to_ms: i64,
}

pub fn parse_window(s: &str, p: &Period) -> Result<Window, String> {
    let hint = "--maintenance takes <from>/<to>, both RFC 3339 (2026-10-14T01:00:00Z/2026-10-14T02:30:00Z)";
    let (a, b) = s.split_once('/').ok_or(format!("{s}: {hint}"))?;
    let t = |x: &str| chrono::DateTime::parse_from_rfc3339(x.trim()).map(|t| t.timestamp_millis()).map_err(|_| format!("{s}: {hint}"));
    let w = Window { from_ms: t(a)?, to_ms: t(b)? };
    if w.to_ms <= w.from_ms {
        return Err(format!("{s}: the window must end after it starts"));
    }
    if w.to_ms <= p.start_ms() || w.from_ms >= p.end_ms() {
        return Err(format!("{s}: the window is outside the period {} to {}", p.from, p.to));
    }
    Ok(w)
}

// Judging the minutes

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Minute {
    Unmeasured,
    Up,
    Down,
}

/// The period's minutes, judged from the checks: up when any check in the minute
/// succeeded, down when every one failed, unmeasured with none. The count of checks
/// outside the period is returned too.
pub fn minutes(checks: &[Check], p: &Period) -> (Vec<Minute>, usize) {
    let n = (p.days() * 1440) as usize;
    let mut out = vec![Minute::Unmeasured; n];
    let mut outside = 0;
    for c in checks {
        if c.at_ms < p.start_ms() || c.at_ms >= p.end_ms() {
            outside += 1;
            continue;
        }
        let i = ((c.at_ms - p.start_ms()) / 60_000) as usize;
        out[i] = match (out[i], c.ok) {
            (_, true) | (Minute::Up, false) => Minute::Up,
            _ => Minute::Down,
        };
    }
    (out, outside)
}

fn minute_ms(p: &Period, i: usize) -> i64 {
    p.start_ms() + i as i64 * 60_000
}

/// The calendar months of the period, as `(YYYY-MM, first minute, end minute)`.
fn months(p: &Period) -> Vec<(String, usize, usize)> {
    let mut out = Vec::new();
    let mut m = p.from.with_day(1).unwrap_or(p.from);
    while m < p.to {
        let next = if m.month() == 12 { NaiveDate::from_ymd_opt(m.year() + 1, 1, 1) } else { NaiveDate::from_ymd_opt(m.year(), m.month() + 1, 1) }.unwrap_or(p.to);
        let (a, b) = (m.max(p.from), next.min(p.to));
        out.push((m.format("%Y-%m").to_string(), ((a - p.from).num_days() * 1440) as usize, ((b - p.from).num_days() * 1440) as usize));
        m = next;
    }
    out
}

/// Which minutes announced maintenance excuses: those starting inside a window, up to
/// `MAINTENANCE_MINUTES_A_MONTH` each calendar month; and, per month, the minutes in
/// windows past that limit, which count as usual.
pub fn excused(windows: &[Window], p: &Period) -> (Vec<bool>, BTreeMap<String, usize>) {
    let n = (p.days() * 1440) as usize;
    let mut out = vec![false; n];
    let mut over = BTreeMap::new();
    for (month, a, b) in months(p) {
        let mut used = 0;
        for (i, slot) in out.iter_mut().enumerate().take(b).skip(a) {
            let t = minute_ms(p, i);
            if windows.iter().any(|w| t >= w.from_ms && t < w.to_ms) {
                if used < MAINTENANCE_MINUTES_A_MONTH {
                    *slot = true;
                    used += 1;
                } else {
                    *over.entry(month.clone()).or_insert(0) += 1;
                }
            }
        }
    }
    (out, over)
}

fn percent(bp: u32) -> f64 {
    f64::from(bp) / 100.0
}

fn round(x: f64, places: i32) -> f64 {
    let f = 10f64.powi(places);
    (x * f).round() / f
}

/// Whether `down` of `total` minutes meets an objective of `bp` hundredths of a percent:
/// exact, in integers.
pub fn meets(down: u64, total: u64, bp: u32) -> bool {
    down * 10_000 <= total * u64::from(10_000 - bp)
}

fn budget(total: u64, bp: u32) -> f64 {
    total as f64 * f64::from(10_000 - bp) / 10_000.0
}

/// One stretch of minutes judged against the objective and every plan's.
fn judge(m: &[Minute], ex: &[bool], a: usize, b: usize, objective: u32) -> Value {
    let total = (b - a) as u64;
    let count = |f: &dyn Fn(usize) -> bool| (a..b).filter(|&i| f(i)).count() as u64;
    let down = count(&|i| m[i] == Minute::Down && !ex[i]);
    let unmeasured = count(&|i| m[i] == Minute::Unmeasured && !ex[i]);
    let excused = count(&|i| ex[i]);
    let excused_down = count(&|i| ex[i] && m[i] == Minute::Down);
    let availability = if total == 0 { 100.0 } else { round((total - down) as f64 * 100.0 / total as f64, 4) };
    let against = |bp: u32| {
        let b = budget(total, bp);
        json!({
            "objectivePercent": percent(bp), "met": meets(down, total, bp),
            "budgetMinutes": round(b, 1), "budgetSpentPercent": if b > 0.0 { round(down as f64 * 100.0 / b, 1) } else { 0.0 },
        })
    };
    let plans: Vec<Value> = PLANS
        .iter()
        .map(|(plan, bp)| {
            let mut v = against(*bp);
            v["plan"] = json!(plan);
            v
        })
        .collect();
    json!({
        "minutes": total,
        "downMinutes": down,
        "unmeasuredMinutes": unmeasured,
        "maintenanceMinutes": excused,
        "downInMaintenanceMinutes": excused_down,
        "availabilityPercent": availability,
        "measuredPercent": if total == 0 { 0.0 } else { round(count(&|i| m[i] != Minute::Unmeasured) as f64 * 100.0 / total as f64, 3) },
        "objective": against(objective),
        "plans": plans,
        "probeGapsWithinBudget": unmeasured as f64 <= budget(total, objective),
    })
}

/// Runs of `want` minutes (ignoring excused ones) as `(first, end)`.
fn runs(m: &[Minute], ex: &[bool], want: Minute) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    let mut start = None;
    for i in 0..=m.len() {
        let hit = i < m.len() && m[i] == want && !ex[i];
        match (hit, start) {
            (true, None) => start = Some(i),
            (false, Some(s)) => {
                out.push((s, i));
                start = None;
            }
            _ => {}
        }
    }
    out
}

/// Everything in `uptime.json` but the period, from the checks.
pub fn assess(probe: &Probe, windows: &[Window], p: &Period, objective: u32) -> Value {
    let (m, outside) = minutes(&probe.checks, p);
    let (ex, over) = excused(windows, p);
    let total = m.len();
    let review_minutes = budget(WINDOW_MINUTES, objective) / 4.0;
    let outages: Vec<Value> = runs(&m, &ex, Minute::Down)
        .into_iter()
        .map(|(a, b)| {
            let from = minute_ms(p, a);
            let mins = (b - a) as u64;
            json!({
                "id": format!("outage-{}", chrono::DateTime::from_timestamp_millis(from).map(|t| t.format("%Y%m%dT%H%MZ").to_string()).unwrap_or_default()),
                "from": rfc3339(from), "to": rfc3339(minute_ms(p, b)), "minutes": mins,
                "windowBudgetSpentPercent": round(mins as f64 * 100.0 / budget(WINDOW_MINUTES, objective), 1),
                "needsReview": mins as f64 > review_minutes,
                "ongoingAtEnd": b == total,
            })
        })
        .collect();
    let gaps: Vec<Value> = runs(&m, &ex, Minute::Unmeasured).into_iter().filter(|(a, b)| b - a >= GAP_MINUTES).map(|(a, b)| json!({ "from": rfc3339(minute_ms(p, a)), "to": rfc3339(minute_ms(p, b)), "minutes": b - a })).collect();
    let by_month: Vec<Value> = months(p)
        .into_iter()
        .map(|(month, a, b)| {
            let mut v = judge(&m, &ex, a, b, objective);
            v["month"] = json!(month);
            v["maintenanceOverLimitMinutes"] = json!(over.get(&month).copied().unwrap_or(0));
            v
        })
        .collect();
    let by_day: Vec<Value> = (0..p.days() as usize)
        .map(|d| {
            let (a, b) = (d * 1440, (d + 1) * 1440);
            let count = |f: &dyn Fn(usize) -> bool| (a..b).filter(|&i| f(i)).count();
            json!({
                "date": (p.from + chrono::Days::new(d as u64)).to_string(),
                "downMinutes": count(&|i| m[i] == Minute::Down && !ex[i]),
                "unmeasuredMinutes": count(&|i| m[i] == Minute::Unmeasured && !ex[i]),
                "maintenanceMinutes": count(&|i| ex[i]),
            })
        })
        .collect();
    let series: Vec<Value> = probe
        .series
        .iter()
        .enumerate()
        .map(|(i, s)| {
            let of: Vec<&Check> = probe.checks.iter().filter(|c| c.series == i && c.at_ms >= p.start_ms() && c.at_ms < p.end_ms()).collect();
            let mut v = s.clone();
            v["checks"] = json!(of.len());
            v["failed"] = json!(of.iter().filter(|c| !c.ok).count());
            v["first"] = json!(of.iter().map(|c| c.at_ms).min().map(rfc3339));
            v["last"] = json!(of.iter().map(|c| c.at_ms).max().map(rfc3339));
            v
        })
        .collect();
    let maintenance: Vec<Value> = windows
        .iter()
        .map(|w| {
            let inside = (0..total).filter(|&i| (w.from_ms..w.to_ms).contains(&minute_ms(p, i)));
            let (mut minutes, mut excused_n) = (0, 0);
            for i in inside {
                minutes += 1;
                excused_n += usize::from(ex[i]);
            }
            json!({ "from": rfc3339(w.from_ms), "to": rfc3339(w.to_ms), "minutesInPeriod": minutes, "excusedMinutes": excused_n })
        })
        .collect();
    let mut summary = judge(&m, &ex, 0, total, objective);
    summary["checks"] = json!(probe.checks.len() - outside);
    summary["checksOutsidePeriod"] = json!(outside);
    summary["outages"] = json!(outages.len());
    let months_where = |f: &dyn Fn(&Value) -> bool| -> Vec<Value> { by_month.iter().filter(|v| f(v)).map(|v| v["month"].clone()).collect() };
    let exceptions = json!({
        "objectiveMissed": months_where(&|v| v["objective"]["met"] == false),
        "budgetHalfSpent": months_where(&|v| v["objective"]["budgetSpentPercent"].as_f64().is_some_and(|x| x >= 50.0)),
        "outagesNeedingReview": outages.iter().filter(|o| o["needsReview"] == true).map(|o| o["id"].clone()).collect::<Vec<_>>(),
        "ongoingAtEnd": outages.iter().filter(|o| o["ongoingAtEnd"] == true).map(|o| o["id"].clone()).collect::<Vec<_>>(),
        "probeGaps": gaps.iter().map(|g| json!(format!("{}/{}", g["from"].as_str().unwrap_or_default(), g["to"].as_str().unwrap_or_default()))).collect::<Vec<_>>(),
        "probeGapsOverBudget": months_where(&|v| v["probeGapsWithinBudget"] == false),
        "maintenanceOverLimit": months_where(&|v| v["maintenanceOverLimitMinutes"].as_u64().is_some_and(|x| x > 0)),
    });
    json!({
        "basis": format!("a minute is up when any check of the probe in it succeeded, down when it had checks and every one failed (no answer, a timeout, or anything but a 2xx; /status.json answers 503 in a major outage), and unmeasured when it had none; availability is the share of minutes that weren't down (docs/slo.md), so unmeasured minutes aren't down, and the period's evidence counts only while they fit in the objective's error budget; minutes starting in announced maintenance aren't down, up to {MAINTENANCE_MINUTES_A_MONTH} a calendar month; an outage needs a written review when it spent more than a quarter of the 30-day error budget ({} minutes at the objective)", round(review_minutes, 1)),
        "objectivePercent": percent(objective),
        "plans": PLANS.iter().map(|(plan, bp)| json!({ "plan": plan, "objectivePercent": percent(*bp) })).collect::<Vec<_>>(),
        "source": probe.source,
        "series": series,
        "maintenance": maintenance,
        "summary": summary,
        "exceptions": exceptions,
        "byMonth": by_month,
        "outages": outages,
        "probeGaps": gaps,
        "byDay": by_day,
    })
}

// The bundle

/// A bundle's name, without `.tar`.
pub fn name(p: &Period, now_ms: i64) -> String {
    let stamp = chrono::DateTime::from_timestamp_millis(now_ms).map(|t| t.format("%Y%m%dT%H%M%SZ").to_string()).unwrap_or_default();
    format!("{PREFIX}{}-{stamp}", p.label())
}

pub fn build(uptime: &Value, p: &Period, requests: u64, now_ms: i64) -> crate::changes::Bundle {
    let name = name(p, now_ms);
    let period = json!({ "from": p.from.to_string(), "to": p.to.to_string(), "days": p.days() });
    let mut u = uptime.clone();
    u["periodCovered"] = period.clone();
    let mapped = u["summary"]["probeGapsWithinBudget"] == true;
    let mut files: Vec<(&str, Vec<u8>)> = vec![("README.txt", README.as_bytes().to_vec()), ("uptime.json", json_file(&u))];
    let listed: Vec<Value> = files
        .iter()
        .map(|(n, b)| {
            let s = SECTIONS.iter().find(|s| s.file == *n).filter(|_| mapped);
            json!({ "name": n, "bytes": b.len(), "sha256": sha256(b), "criteria": s.map(|s| s.criteria).unwrap_or_default(), "checklist": s.map(|s| s.rows).unwrap_or_default() })
        })
        .collect();
    let manifest = json!({
        "product": "SuperBot",
        "kind": "availability",
        "format": FORMAT,
        "tool": concat!("superbot-evidence ", env!("CARGO_PKG_VERSION")),
        "createdAt": rfc3339(now_ms),
        "period": period,
        "source": { "probe": u["source"], "requests": requests },
        "objectivePercent": u["objectivePercent"],
        "availabilityPercent": u["summary"]["availabilityPercent"],
        "checks": u["summary"]["checks"],
        "files": listed,
        "notIncluded": "the token, the Prometheus address, and probe labels other than its job and location",
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
pub fn summary(u: &Value) -> String {
    let s = &u["summary"];
    let mut out = format!(
        "{} checks: {}% available against an objective of {}% ({} minutes down, {}% of the error budget), {} unmeasured, {} excused for maintenance, {} outages.",
        s["checks"], s["availabilityPercent"], u["objectivePercent"], s["downMinutes"], s["objective"]["budgetSpentPercent"], s["unmeasuredMinutes"], s["maintenanceMinutes"], s["outages"]
    );
    for m in u["byMonth"].as_array().into_iter().flatten() {
        out += &format!("\n  {}: {}%, {}", m["month"].as_str().unwrap_or_default(), m["availabilityPercent"], if m["objective"]["met"] == true { "met" } else { "missed" });
    }
    for (k, label) in [
        ("objectiveMissed", "Objective missed in"),
        ("budgetHalfSpent", "Half the error budget or more spent in"),
        ("outagesNeedingReview", "Outages needing a written review"),
        ("ongoingAtEnd", "Down at the period's end"),
        ("probeGapsOverBudget", "Probe gaps longer than the error budget in (the bundle maps no controls)"),
        ("maintenanceOverLimit", "Maintenance past 4 hours, counted as usual, in"),
    ] {
        if let Some(v) = u["exceptions"][k].as_array().filter(|v| !v.is_empty()) {
            out += &format!("\n  {label}: {}", v.iter().filter_map(Value::as_str).collect::<Vec<_>>().join(", "));
        }
    }
    if let Some(n) = u["exceptions"]["probeGaps"].as_array().map(Vec::len).filter(|n| *n > 0) {
        out += &format!("\n  {n} gaps of {GAP_MINUTES} minutes or more in the probe's record: listed in uptime.json");
    }
    out
}

// The command

/// `--objective`: a percentage with at most two decimals, at least 90 and under 100, in
/// hundredths of a percent.
pub fn parse_objective(s: &str) -> Result<u32, String> {
    let hint = format!("--objective takes a percentage such as 99.9 (at least 90, under 100, two decimals at most), not {s}");
    let (whole, frac) = s.trim().split_once('.').unwrap_or((s.trim(), "0"));
    if whole.is_empty() || !whole.bytes().all(|c| c.is_ascii_digit()) || frac.is_empty() || frac.len() > 2 || !frac.bytes().all(|c| c.is_ascii_digit()) {
        return Err(hint);
    }
    let bp = whole.parse::<u32>().map_err(|_| hint.clone())? * 100 + format!("{frac:0<2}").parse::<u32>().map_err(|_| hint.clone())?;
    (9000..10_000).contains(&bp).then_some(bp).ok_or(hint)
}

#[derive(Default)]
struct Args {
    prometheus: Option<String>,
    query: Option<String>,
    checks: Vec<String>,
    maintenance: Vec<String>,
    objective: Option<String>,
    from: Option<String>,
    to: Option<String>,
    out: Option<String>,
}

fn parse_args(args: &[String]) -> Result<Args, String> {
    let mut a = Args::default();
    let mut it = args.iter();
    while let Some(flag) = it.next() {
        let value = |it: &mut std::slice::Iter<String>| it.next().filter(|v| !v.starts_with("--") && !v.is_empty()).cloned().ok_or(format!("{flag} needs a value"));
        let slot = match flag.as_str() {
            "--checks" => {
                a.checks.push(value(&mut it)?);
                continue;
            }
            "--maintenance" => {
                a.maintenance.push(value(&mut it)?);
                continue;
            }
            "--token" | "-t" => return Err("Pass a Prometheus token in PROMETHEUS_TOKEN, never on the command line, where other users and shell history see it.".into()),
            "--prometheus" => &mut a.prometheus,
            "--query" => &mut a.query,
            "--objective" => &mut a.objective,
            "--from" => &mut a.from,
            "--to" => &mut a.to,
            "-o" | "--out" => &mut a.out,
            _ => return Err(format!("Unknown option {flag}.\n\n{}", crate::USAGE)),
        };
        if slot.is_some() {
            return Err(format!("{flag} is given twice"));
        }
        *slot = Some(value(&mut it)?);
    }
    match (&a.prometheus, a.checks.is_empty()) {
        (None, true) => return Err(format!("Give --prometheus <url> or at least one --checks <file>.\n\n{}", crate::USAGE)),
        (Some(_), false) => return Err("Give --prometheus or --checks, not both: one probe's record per bundle.".into()),
        _ => {}
    }
    if a.query.is_some() && a.prometheus.is_none() {
        return Err("--query is for --prometheus".into());
    }
    if a.query.as_deref().is_some_and(|q| !valid_selector(q)) {
        return Err(format!("--query must be a series selector, as {DEFAULT_QUERY}: no functions or ranges"));
    }
    Ok(a)
}

pub fn run(args: &[String], now: chrono::DateTime<chrono::Utc>) -> Result<String, String> {
    run_with(args, now, &|k| std::env::var(k).ok())
}

fn run_with(args: &[String], now: chrono::DateTime<chrono::Utc>, env: &dyn Fn(&str) -> Option<String>) -> Result<String, String> {
    let a = parse_args(args)?;
    let p = Period::parse(a.from.as_deref(), a.to.as_deref(), now.date_naive())?;
    if p.end_ms() > now.timestamp_millis() {
        return Err(format!("The period ends at {} UTC, which hasn't come yet: a minute not yet passed can't be judged", p.to));
    }
    let objective = a.objective.as_deref().map(parse_objective).transpose()?.unwrap_or(DEFAULT_OBJECTIVE);
    let windows = a.maintenance.iter().map(|w| parse_window(w, &p)).collect::<Result<Vec<_>, _>>()?;
    let mut probe = Probe::default();
    let token = env("PROMETHEUS_TOKEN");
    if let Some(url) = &a.prometheus {
        let mut http = prometheus::Http::new(url, token.clone())?;
        probe = fetch(&mut http, a.query.as_deref().unwrap_or(DEFAULT_QUERY), &p)?;
    }
    let mut seen = Vec::new();
    for f in &a.checks {
        let size = std::fs::metadata(f).map_err(|e| format!("{f}: {e}"))?.len();
        if size > MAX_CHECKS_BYTES {
            return Err(format!("{f} is over {} MiB, larger than a month of checks", MAX_CHECKS_BYTES >> 20));
        }
        let bytes = std::fs::read(f).map_err(|e| format!("{f}: {e}"))?;
        let digest = sha256(&bytes);
        if seen.contains(&digest) {
            return Err(format!("{f} is the same file as another --checks"));
        }
        seen.push(digest);
        read_checks(f, &bytes, &mut probe)?;
    }
    let u = assess(&probe, &windows, &p, objective);
    if u["summary"]["checks"] == 0 {
        return Err(format!("The probe has no checks from {} to {}: check --query or the --checks files (the bundle would show nothing)", p.from, p.to));
    }
    let b = build(&u, &p, probe.requests, now.timestamp_millis());
    if token.as_deref().map(str::trim).filter(|t| !t.is_empty()).is_some_and(|t| b.tar.windows(t.len()).any(|w| w == t.as_bytes())) {
        return Err("The bundle would contain the token, so it wasn't written.".into());
    }
    let file = a.out.clone().unwrap_or_else(|| format!("{}.tar", b.name));
    crate::save_private(&file, &b.tar)?;
    Ok(format!(
        "Saved {file} ({} KB) for {} to {} (not included).\n{}\nManifest SHA-256: {}\nBundle SHA-256: {}\nKeep it in the evidence store, with the probe's own export; to check it:\n  tar -xf {} && (cd {} && sha256sum -c SHA256SUMS)",
        b.tar.len().div_ceil(1024),
        p.from,
        p.to,
        summary(&u),
        b.manifest_sha256,
        b.sha256,
        crate::quote(&file),
        crate::quote(&b.name),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn day(s: &str) -> NaiveDate {
        NaiveDate::parse_from_str(s, "%Y-%m-%d").unwrap()
    }

    fn period() -> Period {
        Period { from: day("2026-10-01"), to: day("2026-11-01") }
    }

    fn at(s: &str) -> i64 {
        chrono::DateTime::parse_from_rfc3339(s).unwrap().timestamp_millis()
    }

    /// Checks every 30 seconds over `p`, failing in each `[from, to)` given.
    fn probe(p: &Period, down: &[(&str, &str)]) -> Probe {
        let windows: Vec<(i64, i64)> = down.iter().map(|(a, b)| (at(a), at(b))).collect();
        let checks = (p.start_ms()..p.end_ms()).step_by(30_000).map(|t| Check { at_ms: t, ok: !windows.iter().any(|(a, b)| t >= *a && t < *b), series: 0 }).collect();
        Probe { source: json!({ "kind": "test" }), series: vec![json!({ "id": "s", "labels": {} })], checks, requests: 0 }
    }

    #[test]
    fn a_minute_is_down_only_when_every_check_in_it_failed() {
        let p = Period { from: day("2026-10-01"), to: day("2026-10-02") };
        let c = |s: &str, ok: bool, series: usize| Check { at_ms: at(s), ok, series };
        let checks = [
            c("2026-10-01T00:00:00Z", false, 0),
            c("2026-10-01T00:00:30Z", false, 0),
            c("2026-10-01T00:01:00Z", false, 0),
            c("2026-10-01T00:01:30Z", true, 0),
            c("2026-10-01T00:02:10Z", false, 0),
            c("2026-10-01T00:03:00Z", false, 0),
            c("2026-10-01T00:03:20Z", true, 1),
            c("2026-10-02T00:00:00Z", false, 0),
            c("2026-09-30T23:59:59Z", false, 0),
        ];
        let (m, outside) = minutes(&checks, &p);
        assert_eq!(&m[..5], [Minute::Down, Minute::Up, Minute::Down, Minute::Up, Minute::Unmeasured], "one success makes the minute up, from any location; a lone failed check is down");
        assert_eq!((m.len(), outside), (1440, 2), "the period's end is the next period's first minute");
    }

    #[test]
    fn a_month_with_a_short_and_a_long_outage() {
        let p = period();
        let mut pr = probe(&p, &[("2026-10-03T10:00:00Z", "2026-10-03T10:04:00Z"), ("2026-10-20T22:30:00Z", "2026-10-20T23:20:00Z")]);
        pr.checks.retain(|c| !(c.at_ms >= at("2026-10-10T00:00:00Z") && c.at_ms < at("2026-10-10T00:07:00Z")));
        let u = assess(&pr, &[], &p, DEFAULT_OBJECTIVE);
        let s = &u["summary"];
        assert_eq!((s["minutes"].as_u64(), s["downMinutes"].as_u64(), s["unmeasuredMinutes"].as_u64()), (Some(44_640), Some(54), Some(7)));
        assert_eq!(s["availabilityPercent"].as_f64(), Some(99.879));
        assert_eq!((s["objective"]["met"].as_bool(), s["objective"]["budgetMinutes"].as_f64(), s["objective"]["budgetSpentPercent"].as_f64()), (Some(false), Some(44.6), Some(121.0)));
        let plans: Vec<(String, bool)> = s["plans"].as_array().unwrap().iter().map(|x| (x["plan"].as_str().unwrap().to_string(), x["met"].as_bool().unwrap())).collect();
        assert_eq!(plans, [("Starter".to_string(), true), ("Pro".into(), false), ("Max".into(), false), ("Enterprise".into(), false)]);
        let outages = u["outages"].as_array().unwrap();
        assert_eq!(outages.iter().map(|o| (o["id"].as_str().unwrap(), o["minutes"].as_u64().unwrap(), o["needsReview"].as_bool().unwrap())).collect::<Vec<_>>(), [("outage-20261003T1000Z", 4, false), ("outage-20261020T2230Z", 50, true)], "a quarter of 43.2 minutes is 10.8");
        assert_eq!(outages[1]["to"], "2026-10-20T23:20:00Z");
        assert_eq!(u["probeGaps"][0]["minutes"], 7);
        let ex = &u["exceptions"];
        assert_eq!((ex["objectiveMissed"].clone(), ex["budgetHalfSpent"].clone(), ex["outagesNeedingReview"].clone()), (json!(["2026-10"]), json!(["2026-10"]), json!(["outage-20261020T2230Z"])));
        assert_eq!((ex["probeGaps"].clone(), ex["probeGapsOverBudget"].clone(), ex["ongoingAtEnd"].clone()), (json!(["2026-10-10T00:00:00Z/2026-10-10T00:07:00Z"]), json!([]), json!([])));
        assert_eq!(u["byDay"][19]["downMinutes"], 50);
        assert_eq!(u["byDay"].as_array().unwrap().len(), 31);

        let starter = assess(&pr, &[], &p, 9950);
        assert_eq!((starter["summary"]["objective"]["met"].as_bool(), starter["outages"][1]["needsReview"].as_bool()), (Some(true), Some(false)), "a quarter of 3 h 36 min is 54 minutes");
    }

    #[test]
    fn announced_maintenance_is_excused_up_to_four_hours_a_month() {
        let p = period();
        let pr = probe(&p, &[("2026-10-14T01:00:00Z", "2026-10-14T06:00:00Z"), ("2026-10-31T23:58:00Z", "2026-11-01T00:00:00Z")]);
        let w = parse_window("2026-10-14T01:00:00Z/2026-10-14T06:00:00Z", &p).unwrap();
        let u = assess(&pr, &[w], &p, DEFAULT_OBJECTIVE);
        let s = &u["summary"];
        assert_eq!((s["maintenanceMinutes"].as_u64(), s["downInMaintenanceMinutes"].as_u64(), s["downMinutes"].as_u64()), (Some(240), Some(240), Some(62)), "the fifth hour counts, and so do the last two minutes");
        assert_eq!((u["maintenance"][0]["minutesInPeriod"].as_u64(), u["maintenance"][0]["excusedMinutes"].as_u64()), (Some(300), Some(240)));
        assert_eq!(u["byMonth"][0]["maintenanceOverLimitMinutes"], 60);
        assert_eq!(u["exceptions"]["maintenanceOverLimit"], json!(["2026-10"]));
        assert_eq!(u["exceptions"]["ongoingAtEnd"], json!(["outage-20261031T2358Z"]));
        assert_eq!(u["outages"][0]["id"], "outage-20261014T0500Z", "the outage starts where the excuse ends");
        for bad in ["2026-10-14T01:00:00Z", "2026-10-14T02:00:00Z/2026-10-14T01:00:00Z", "2026-11-02T00:00:00Z/2026-11-02T01:00:00Z", "yesterday/today"] {
            assert!(parse_window(bad, &p).is_err(), "{bad}");
        }
    }

    #[test]
    fn a_month_the_probe_mostly_missed_maps_no_controls() {
        let p = period();
        let mut pr = probe(&p, &[]);
        pr.checks.retain(|c| c.at_ms < at("2026-10-31T23:00:00Z"));
        let u = assess(&pr, &[], &p, DEFAULT_OBJECTIVE);
        assert_eq!((u["summary"]["availabilityPercent"].as_f64(), u["summary"]["probeGapsWithinBudget"].as_bool()), (Some(100.0), Some(false)), "an hour unmeasured is more than 44.6 minutes of budget");
        assert_eq!(u["exceptions"]["probeGapsOverBudget"], json!(["2026-10"]));
        let manifest = |u: &Value| -> Value {
            let b = build(u, &p, 0, p.end_ms() + 60_000);
            let entries = crate::coverage::untar(&b.tar).unwrap();
            serde_json::from_slice(&entries.iter().find(|(n, _)| n.ends_with("/manifest.json")).unwrap().1).unwrap()
        };
        let m = manifest(&u);
        assert!(m["files"].as_array().unwrap().iter().all(|f| f["checklist"] == json!([])), "{m}");
        let full = assess(&probe(&p, &[]), &[], &p, DEFAULT_OBJECTIVE);
        let m = manifest(&full);
        assert_eq!((m["kind"].as_str(), m["files"][1]["name"].as_str(), m["files"][1]["checklist"].clone(), m["files"][1]["criteria"].clone()), (Some("availability"), Some("uptime.json"), json!(["A1.1-3"]), json!(["A1.1"])));
        assert_eq!((m["availabilityPercent"].as_f64(), m["checks"].as_u64()), (Some(100.0), Some(89_280)));
    }

    #[test]
    fn months_are_judged_on_their_own() {
        let p = Period { from: day("2026-10-15"), to: day("2026-11-15") };
        let u = assess(&probe(&p, &[("2026-11-02T00:00:00Z", "2026-11-02T00:30:00Z")]), &[], &p, DEFAULT_OBJECTIVE);
        let months: Vec<(&str, u64, bool)> = u["byMonth"].as_array().unwrap().iter().map(|m| (m["month"].as_str().unwrap(), m["minutes"].as_u64().unwrap(), m["objective"]["met"].as_bool().unwrap())).collect();
        assert_eq!(months, [("2026-10", 17 * 1440, true), ("2026-11", 14 * 1440, false)], "30 minutes is over 14 days' budget of 20.2");
    }

    #[test]
    fn checks_files_from_any_probe() {
        let mut pr = Probe::default();
        let csv = "time,up,location\n# exported from a hosted checker\n2026-10-01T00:00:00Z,1,lon\n1790812830,0,lon\n2026-10-01T00:00:10+00:00,down,fra\n\n";
        read_checks("/srv/probe/october.csv", csv.as_bytes(), &mut pr).unwrap();
        assert_eq!(pr.checks.iter().map(|c| (c.ok, c.series)).collect::<Vec<_>>(), [(true, 0), (false, 0), (false, 1)]);
        assert_eq!(pr.checks[1].at_ms, 1_790_812_830_000);
        assert_eq!(pr.series, [json!({ "id": "october.csv:lon", "labels": { "location": "lon" } }), json!({ "id": "october.csv:fra", "labels": { "location": "fra" } })]);
        assert_eq!((pr.source["files"][0]["file"].as_str(), pr.source["files"][0]["checks"].as_u64()), (Some("october.csv"), Some(3)), "the file's name, never its folder");
        read_checks("second.csv", b"# a comment first\nTimestamp (UTC),Status\n2026-10-02T00:00:00Z,true\n", &mut pr).unwrap();
        assert_eq!((pr.series.len(), pr.source["files"].as_array().unwrap().len()), (3, 2));
        for (bad, want) in [
            ("2026-10-01T00:00:00Z,1\nnot a line\n2026-10-01T00:01:00Z,maybe\n", "line 2, 3 are not"),
            ("2026-10-01T00:00:00Z,1,a location; rm\n", "line 1 is not"),
            ("time,up\n", "holds no checks"),
            ("2026-10-01T00:00:00Z,dwon\n2026-10-01T00:01:00Z,1\n", "line 1 is not"),
            ("2026-10-01T00:00:00Z,1\ntime,up\n", "line 2 is not"),
        ] {
            let e = read_checks("x.csv", bad.as_bytes(), &mut Probe::default()).unwrap_err();
            assert!(e.contains(want), "{want}: {e}");
        }
    }

    struct Fake {
        answers: HashMap<i64, Value>,
        asked: Vec<(String, i64)>,
    }

    impl Api for Fake {
        fn query(&mut self, query: &str, time_s: i64) -> Result<Value, String> {
            self.asked.push((query.to_string(), time_s));
            self.answers.get(&time_s).cloned().ok_or(format!("no fixture for {time_s}"))
        }
    }

    #[test]
    fn prometheus_is_read_a_day_at_a_time_without_double_counting() {
        let p = Period { from: day("2026-10-01"), to: day("2026-10-03") };
        let (d1, d2) = (p.start_ms() / 1000 + 86_400, p.end_ms() / 1000);
        let series = |labels: Value, values: Vec<(i64, &str)>| json!({ "metric": labels, "values": values.iter().map(|(t, v)| json!([*t as f64, v])).collect::<Vec<_>>() });
        let lon = json!({ "__name__": "probe_success", "job": "superbot-status", "instance": "https://bots.example.com/status.json", "location": "lon" });
        let fra = json!({ "__name__": "probe_success", "job": "superbot-status", "instance": "https://bots.example.com/status.json", "location": "fra" });
        let mut f = Fake { answers: HashMap::new(), asked: Vec::new() };
        f.answers.insert(d1, json!({ "resultType": "matrix", "result": [series(lon.clone(), vec![(d1 - 86_460, "1"), (d1 - 86_400, "1"), (d1 - 30, "0"), (d1, "1")])] }));
        f.answers.insert(d2, json!({ "resultType": "matrix", "result": [series(lon, vec![(d1, "1"), (d1 + 30, "NaN")]), series(fra, vec![(d1 + 60, "0")])] }));
        let pr = fetch(&mut f, DEFAULT_QUERY, &p).unwrap();
        assert_eq!(f.asked, [(format!("{DEFAULT_QUERY}[86460s]"), d1), (format!("{DEFAULT_QUERY}[86460s]"), d2)]);
        assert_eq!(pr.checks.iter().map(|c| (c.at_ms / 1000, c.ok, c.series)).collect::<Vec<_>>(), [(d1 - 86_400, true, 0), (d1 - 30, false, 0), (d1, true, 0), (d1 + 60, false, 1)], "each sample once, in the day it belongs to; NaN is no check");
        assert_eq!(pr.series[0]["labels"], json!({ "job": "superbot-status", "location": "lon" }), "never the target's address");
        assert!(pr.series[0]["id"].as_str().unwrap().starts_with("prometheus-") && pr.series[0]["id"] != pr.series[1]["id"]);
        assert!(!serde_json::to_string(&pr.series).unwrap().contains("example.com"));
        assert_eq!(pr.requests, 2);
        let mut vector = Fake { answers: HashMap::from([(d1, json!({ "resultType": "vector", "result": [] }))]), asked: Vec::new() };
        assert!(fetch(&mut vector, "up", &p).unwrap_err().contains("series selector"));
        let server = |target: &str| json!({ "__name__": "probe_success", "job": "superbot-status", "instance": target, "location": "lon" });
        let two = json!({ "resultType": "matrix", "result": [series(server("https://a.example.com/status.json"), vec![(d1 - 30, "0")]), series(server("https://b.example.com/status.json"), vec![(d1 - 30, "1")])] });
        let mut both = Fake { answers: HashMap::from([(d1, two.clone()), (d2, two)]), asked: Vec::new() };
        let e = fetch(&mut both, DEFAULT_QUERY, &p).unwrap_err();
        assert!(e.contains("probe of 2 servers") && e.contains("instance=") && !e.contains("example.com"), "one server's answers never hide another's: {e}");
        let one = |extra: Vec<Value>| {
            let result: Vec<Value> = std::iter::once(series(server("https://a.example.com/status.json"), vec![(d1 - 30, "1")])).chain(extra).collect();
            json!({ "resultType": "matrix", "result": result })
        };
        let moved = series(server("https://b.example.com/status.json"), vec![(d2, "1")]);
        let mut renamed = Fake { answers: HashMap::from([(d1, one(vec![])), (d2, one(vec![moved]))]), asked: Vec::new() };
        let pr = fetch(&mut renamed, DEFAULT_QUERY, &p).unwrap();
        assert_eq!((pr.series.len(), pr.checks.len()), (1, 1), "a target first seen at the period's end isn't in it");
        let pr = fetch(&mut f, r#"probe_success{job="superbot-status",instance="https://bots.example.com/status.json"}"#, &p).unwrap();
        assert_eq!(pr.source["query"], r#"probe_success{job="superbot-status",instance="<not recorded>"}"#);
    }

    #[test]
    fn selectors_objectives_and_options() {
        for ok in [DEFAULT_QUERY, "probe_success", r#"{__name__="probe_success",location=~"lon|fra"}"#, "probe_success{}", r#"probe_success{location=~"lon[12]", job = 'superbot-status',}"#, r#"probe_success{instance=~`https://.*\.example\.com/(status)`}"#, r#"probe_success{a="say \"}\" twice"}"#] {
            assert!(valid_selector(ok), "{ok}");
        }
        for bad in ["", "{}", "avg_over_time(probe_success[5m])", "probe_success[1d]", "probe_success{a=\"b\"} or up", "1x", "probe_success{a=\"b\"}{c=\"d\"}", "probe_success{a=b}", "probe_success{a=\"b\"", "probe_success{a==\"b\"}", "probe_success{1a=\"b\"}", "probe_success{a=\"b\" c=\"d\"}"] {
            assert!(!valid_selector(bad), "{bad}");
        }
        assert_eq!(shown_query(DEFAULT_QUERY), DEFAULT_QUERY);
        assert_eq!(shown_query(r#"probe_success{job="superbot-status",instance="https://bots.example.com/status.json",location=~"lon|fra"}"#), r#"probe_success{job="superbot-status",instance="<not recorded>",location=~"lon|fra"}"#, "never the target's address");
        assert_eq!(shown_query(r#"probe_success{location=~"lon[12]"}"#), r#"probe_success{location=~"<not recorded>"}"#);
        assert_eq!((parse_objective("99.9"), parse_objective("99.95"), parse_objective("99"), parse_objective("90")), (Ok(9990), Ok(9995), Ok(9900), Ok(9000)));
        for bad in ["100", "89.99", "99.999", "99,9", "-99", "", "99.", "abc"] {
            assert!(parse_objective(bad).is_err(), "{bad}");
        }
        assert!(meets(43, 43_200, 9990) && !meets(44, 43_200, 9990));
        let args = |s: &[&str]| s.iter().map(|x| x.to_string()).collect::<Vec<_>>();
        let a = parse_args(&args(&["--prometheus", "https://prom.example.com", "--query", "probe_success", "--maintenance", "a/b", "--objective", "99.5", "-o", "u.tar"])).unwrap();
        assert_eq!((a.prometheus.as_deref(), a.query.as_deref(), a.maintenance.len(), a.objective.as_deref(), a.out.as_deref()), (Some("https://prom.example.com"), Some("probe_success"), 1, Some("99.5"), Some("u.tar")));
        for (bad, want) in [
            (&[][..], "--prometheus <url> or at least one --checks"),
            (&["--prometheus", "https://p", "--checks", "c.csv"], "not both"),
            (&["--checks", "c.csv", "--query", "up"], "--query is for --prometheus"),
            (&["--prometheus", "https://p", "--query", "rate(x[5m])"], "series selector"),
            (&["--prometheus", "https://p", "--token", "s3cret"], "PROMETHEUS_TOKEN"),
            (&["--prometheus", "https://p", "--prometheus", "https://q"], "given twice"),
            (&["--checks"], "needs a value"),
            (&["--checks", "c.csv", "--bogus"], "Unknown option"),
        ] {
            let e = parse_args(&args(bad)).err().unwrap_or_default();
            assert!(e.contains(want) && !e.contains("s3cret"), "{bad:?}: {e}");
        }
        let now = chrono::DateTime::parse_from_rfc3339("2026-10-31T12:00:00Z").unwrap().with_timezone(&chrono::Utc);
        let e = run_with(&args(&["--checks", "c.csv", "--from", "2026-10-01", "--to", "2026-11-01"]), now, &|_| None).unwrap_err();
        assert!(e.contains("hasn't come yet"), "{e}");
    }

    /// The plans and the maintenance limit are docs/slo.md's; the review threshold is its
    /// "more than a quarter of the budget".
    #[test]
    fn objectives_are_the_slos() {
        let slo = include_str!("../../../../docs/slo.md");
        for (plan, bp) in PLANS {
            let row = slo.lines().find(|l| l.starts_with(&format!("| {plan} |"))).unwrap_or_else(|| panic!("docs/slo.md has no row for {plan}"));
            let shown = format!("{}%", percent(bp));
            assert!(row.contains(&format!("| {shown} |")) || row.contains(&format!("| {shown},")), "{plan}: docs/slo.md's row doesn't say {shown}: {row}");
        }
        assert!(slo.contains("at most 4 hours a month") && MAINTENANCE_MINUTES_A_MONTH == 4 * 60);
        assert!(slo.contains("more than a quarter of the budget"));
        assert!(slo.contains("rolling 30-day window") && WINDOW_MINUTES == 30 * 1440);
        assert!(slo.contains("every 30 seconds") && slo.contains("both checks in it fail"));
        let readme = include_str!("../../../../deploy/README.md");
        assert!(readme.contains("job_name: superbot-status") && DEFAULT_QUERY.contains("superbot-status"));
        let rules = include_str!("../../../../deploy/prometheus/superbot-slo.rules.yml");
        assert!(rules.contains(DEFAULT_QUERY), "the alert and the default query read the same probe");
    }

    #[test]
    fn names_never_collide_with_the_other_bundles() {
        let n = name(&period(), 1_795_000_000_000);
        assert!(n.starts_with("superbot-uptime-2026-10-01_2026-11-01-") && n.ends_with('Z'), "{n}");
        assert!(n.len() + "/manifest.json".len() <= 100, "fits a ustar name");
        assert!(![crate::changes::PREFIX, crate::vulns::PREFIX, crate::drills::PREFIX, crate::register::PREFIX, "superbot-evidence-"].iter().any(|p| n.starts_with(p)));
    }

    /// The file maps to criteria the control mapping has and checklist rows the readiness
    /// checklist has, and the evidence plan's uptime table lists it with them.
    #[test]
    fn every_file_maps_to_real_controls_and_the_evidence_plan_says_so() {
        let mapping = include_str!("../../../../docs/security/soc2-control-mapping.md");
        let checklist = include_str!("../../../../docs/security/soc2-readiness-checklist.md");
        let plan = include_str!("../../../../docs/security/soc2-evidence-plan.md");
        let section = plan.split("## The uptime bundle").nth(1).and_then(|s| s.split("\n## ").next()).expect("the evidence plan has an uptime bundle section");
        for s in &SECTIONS {
            for c in s.criteria {
                assert!(mapping.contains(&format!("| {c} ")), "{}: {c} isn't a criterion of the control mapping", s.file);
            }
            for r in s.rows {
                assert!(checklist.contains(&format!("| {r} |")), "{}: {r} isn't a row of the readiness checklist", s.file);
                assert!(s.criteria.iter().any(|c| r.starts_with(&format!("{c}-"))), "{}: {r} isn't under one of its criteria", s.file);
            }
            let line = section.lines().find(|l| l.starts_with(&format!("| `{}` |", s.file))).unwrap_or_else(|| panic!("the evidence plan's uptime table has no row for `{}`", s.file));
            for id in s.criteria.iter().chain(s.rows) {
                assert!(line.contains(id), "the evidence plan's row for `{}` doesn't name {id}", s.file);
            }
        }
    }
}
