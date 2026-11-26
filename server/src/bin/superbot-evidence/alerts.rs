//! Alert history evidence (ADR 0288): what the operator's Prometheus alerted on through a
//! period, and whether it was watching. Every SuperBot alert that fired, as episodes read
//! from Prometheus' own `ALERTS` series, with its severity and how long it fired; the
//! stretches Prometheus scraped nothing from botd (`up{job="superbot"}` by default), when
//! no alert could fire; the alerting rules loaded as the bundle is made, against the rule
//! files shipped in `deploy/prometheus/` (or the operator's own); and, where Prometheus
//! scrapes Alertmanager, the notifications it sent and failed to send each day. A dated
//! bundle in the shape of the change-management bundle (ADR 0148).
//!
//! Never in it: the token, the Prometheus address, rule files' paths, rules' expressions or
//! errors, or labels other than the alert's name, severity, job and the few the shipped
//! rules group by that name no host (`harness`, `route_class`, `provider`, `tier`).

use crate::changes::{json_file, rfc3339, sha256};
use crate::period::Period;
use crate::prometheus::{self, Api};
use crate::uptime;
use chrono::{Datelike, NaiveDate};
use serde_json::{Map, Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

/// Bumped when a file's shape changes, so tools reading bundles can tell them apart.
pub const FORMAT: u32 = 1;
pub const PREFIX: &str = "superbot-alerts-";
pub const FILE: &str = "alerts.json";
/// Prometheus' record of every alert firing, one sample each rule evaluation.
pub const ALERTS_QUERY: &str = r#"ALERTS{alertstate="firing"}"#;
/// The scrape of botd the shipped rules read (deploy/README.md names the job `superbot`):
/// while Prometheus has none of its samples, no SuperBot alert can fire.
pub const DEFAULT_WATCH: &str = r#"up{job="superbot"}"#;
const SENT: &str = "alertmanager_notifications_total";
const FAILED: &str = "alertmanager_notifications_failed_total";
/// Samples further apart than this split an alert into two episodes, and a stretch this
/// long without a sample of the watch series is a gap. Rules are evaluated and botd
/// scraped every 30 to 60 seconds in deploy/README.md; 5 minutes is Prometheus' lookback.
pub const GAP_MINUTES: i64 = 5;
/// An episode that fired longer than this is listed for the auditor to ask what was done.
pub const LONG_FIRING_MINUTES: i64 = 24 * 60;
/// A loaded rule whose last evaluation is older than this when the bundle is made isn't
/// being evaluated.
const STALE_EVALUATION_MINUTES: i64 = 10;
/// How much of the period one Prometheus request reads.
const CHUNK_SECS: i64 = 86_400;
/// The largest rule file read with `--rules`.
pub const MAX_RULES_BYTES: u64 = 1 << 20;
/// Labels shown for an alert: what it is and how severe. The rest (an instance or host
/// above all) only go into the series' digest.
const SHOWN_LABELS: [&str; 7] = ["alertname", "severity", "job", "harness", "route_class", "provider", "tier"];

/// The rule files `deploy/prometheus/` ships, expected loaded unless `--rules` names others.
pub const SHIPPED: [(&str, &str); 9] = [
    ("superbot-backup-encryption.rules.yml", include_str!("../../../../deploy/prometheus/superbot-backup-encryption.rules.yml")),
    ("superbot-backups.rules.yml", include_str!("../../../../deploy/prometheus/superbot-backups.rules.yml")),
    ("superbot-capacity.rules.yml", include_str!("../../../../deploy/prometheus/superbot-capacity.rules.yml")),
    ("superbot-database-encryption.rules.yml", include_str!("../../../../deploy/prometheus/superbot-database-encryption.rules.yml")),
    ("superbot-errors.rules.yml", include_str!("../../../../deploy/prometheus/superbot-errors.rules.yml")),
    ("superbot-health-score.rules.yml", include_str!("../../../../deploy/prometheus/superbot-health-score.rules.yml")),
    ("superbot-server-backups.rules.yml", include_str!("../../../../deploy/prometheus/superbot-server-backups.rules.yml")),
    ("superbot-signin.rules.yml", include_str!("../../../../deploy/prometheus/superbot-signin.rules.yml")),
    ("superbot-slo.rules.yml", include_str!("../../../../deploy/prometheus/superbot-slo.rules.yml")),
];

/// One file of the bundle and the criteria and checklist rows it is evidence for. The
/// evidence plan's alerts table must match. The manifest maps it to them only while
/// Prometheus watched within the error budget and every expected rule is loaded, healthy
/// and evaluated, so a month it didn't shows as a gap in the coverage report.
pub struct Section {
    pub file: &'static str,
    pub criteria: &'static [&'static str],
    pub rows: &'static [&'static str],
}

pub const SECTIONS: [Section; 1] = [Section { file: FILE, criteria: &["CC2.1", "CC7.2", "A1.1"], rows: &["CC2.1-1", "CC7.2-1", "A1.1-1"] }];

const README: &str = "SuperBot alert history evidence bundle
======================================

Made by superbot-evidence, for a SOC 2 Type II evidence store
(docs/security/soc2-evidence-plan.md, ADR 0288). It covers the period in manifest.json:
from its first day (00:00 UTC) up to, not including, its last.

  alerts.json    what the operator's Prometheus alerted on: every SuperBot alert that
                 fired, as episodes with their severity and how long they fired; each
                 rule expected, whether it is loaded, healthy and evaluated now, and
                 what it fired in the period; the stretches Prometheus scraped nothing
                 from botd, when no alert could fire; Alertmanager's notifications sent
                 and failed each day; and the exceptions
  manifest.json  what is in this bundle, the period, the rules expected, and each
                 file's SHA-256
  SHA256SUMS     the same digests, for `sha256sum -c SHA256SUMS`

Never in it: the token, the Prometheus address, rule files' paths, expressions or
errors, or labels that name a host. Each page needs its response on record (a ticket,
or an incident in the policy register): this bundle is the list to sample from.
";

// The rules expected

/// An alerting rule a rule file defines, with the severity label it gives.
#[derive(Clone, Debug, PartialEq)]
pub struct Rule {
    pub name: String,
    pub severity: String,
    pub file: String,
}

fn valid_name(s: &str) -> bool {
    !s.is_empty() && s.len() <= 128 && !s.starts_with(|c: char| c.is_ascii_digit()) && s.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b':')
}

fn plain(s: &str, max: usize) -> bool {
    !s.is_empty() && s.len() <= max && s.bytes().all(|c| c.is_ascii_alphanumeric() || b"._:-/".contains(&c))
}

fn unquote(s: &str) -> &str {
    s.trim().trim_matches(|c| c == '"' || c == '\'')
}

/// The alerting rules of a Prometheus rule file: each `alert:` and the `severity:` label
/// under it. Recording rules are skipped. A file with none is refused, as is a name that
/// isn't a metric name.
pub fn parse_rules(file: &str, text: &str) -> Result<Vec<Rule>, String> {
    let mut out: Vec<Rule> = Vec::new();
    let mut open = false;
    for line in text.lines() {
        let t = line.trim();
        if t.starts_with('#') {
            continue;
        }
        let t = t.strip_prefix("- ").map(str::trim_start).unwrap_or(t);
        if let Some(rest) = t.strip_prefix("alert:") {
            let name = unquote(rest.split(" #").next().unwrap_or_default());
            if !valid_name(name) {
                return Err(format!("{file}: {name:?} isn't an alert name"));
            }
            out.push(Rule { name: name.to_string(), severity: String::new(), file: file.to_string() });
            open = true;
        } else if t.starts_with("record:") || (line.trim_start().starts_with("- name:")) {
            open = false;
        } else if let Some(s) = t.strip_prefix("severity:").filter(|_| open) {
            if let Some(r) = out.last_mut().filter(|r| r.severity.is_empty()) {
                r.severity = unquote(s.split(" #").next().unwrap_or_default()).to_string();
            }
        }
    }
    if out.is_empty() {
        return Err(format!("{file} holds no alerting rules (- alert: <name>)"));
    }
    Ok(out)
}

/// The rules the shipped files define, each once.
pub fn shipped() -> Vec<Rule> {
    let mut out: Vec<Rule> = Vec::new();
    for (file, text) in SHIPPED {
        for r in parse_rules(file, text).expect("the shipped rule files parse") {
            if !out.iter().any(|x| x.name == r.name) {
                out.push(r);
            }
        }
    }
    out
}

// Reading Prometheus

/// One series of raw samples: its labels and the times of its samples, in milliseconds.
type Series = (Map<String, Value>, Vec<i64>);

/// What Prometheus showed for the period.
#[derive(Debug, Default)]
pub struct Collected {
    /// `ALERTS` series by their canonical labels.
    pub alerts: BTreeMap<String, Series>,
    /// Every sample time of the watch series, merged.
    pub watch: Vec<i64>,
    /// `/api/v1/rules`' answer, or why it couldn't be read.
    pub rules: Option<Result<Value, String>>,
    /// For each day: notifications sent and failed by integration, or none recorded.
    pub notifications: Vec<Option<(BTreeMap<String, u64>, BTreeMap<String, u64>)>>,
    pub requests: u64,
}

fn canonical(labels: &Map<String, Value>) -> String {
    serde_json::to_string(&labels.iter().collect::<BTreeMap<_, _>>()).unwrap_or_default()
}

/// Every raw sample of `selector` in the period, a day at a time: each request reads a
/// minute more than its day and keeps only the day's samples, as the uptime bundle does.
fn samples(api: &mut dyn Api, selector: &str, p: &Period, requests: &mut u64) -> Result<BTreeMap<String, Series>, String> {
    let (start, end) = (p.start_ms() / 1000, p.end_ms() / 1000);
    let mut out: BTreeMap<String, Series> = BTreeMap::new();
    let mut t = start;
    while t < end {
        let to = (t + CHUNK_SECS).min(end);
        let data = api.query(&format!("{selector}[{}s]", to - t + 60), to)?;
        *requests += 1;
        if data["resultType"] != "matrix" {
            return Err(format!("Prometheus answered a {} for {selector}: give a series selector", data["resultType"].as_str().unwrap_or("result")));
        }
        for r in data["result"].as_array().into_iter().flatten() {
            let labels = r["metric"].as_object().cloned().unwrap_or_default();
            let entry = out.entry(canonical(&labels)).or_insert_with(|| (labels.clone(), Vec::new()));
            for v in r["values"].as_array().into_iter().flatten() {
                let Some(secs) = v[0].as_f64() else { continue };
                let at_ms = (secs * 1000.0).round() as i64;
                if at_ms < t * 1000 || at_ms >= to * 1000 || v[1].as_str().and_then(|s| s.parse::<f64>().ok()).is_none_or(f64::is_nan) {
                    continue;
                }
                entry.1.push(at_ms);
            }
        }
        t = to;
    }
    out.retain(|_, (_, times)| !times.is_empty());
    for (_, times) in out.values_mut() {
        times.sort_unstable();
        times.dedup();
    }
    Ok(out)
}

/// A day's notifications by integration, from Prometheus' `increase()` over the day,
/// rounded; none when Prometheus has no such series (it doesn't scrape Alertmanager).
fn per_integration(data: &Value) -> Option<BTreeMap<String, u64>> {
    let result = data["result"].as_array().filter(|r| !r.is_empty())?;
    let mut out = BTreeMap::new();
    for r in result {
        let name = r["metric"]["integration"].as_str().filter(|s| plain(s, 64)).unwrap_or("other").to_string();
        let n = r["value"][1].as_str().and_then(|s| s.parse::<f64>().ok()).filter(|x| x.is_finite() && *x >= 0.0).unwrap_or(0.0);
        *out.entry(name).or_insert(0) += n.round() as u64;
    }
    Some(out)
}

/// Everything the bundle reads from Prometheus.
pub fn collect(api: &mut dyn Api, watch: &str, p: &Period) -> Result<Collected, String> {
    let mut c = Collected::default();
    let mut requests = 0;
    c.watch = samples(api, watch, p, &mut requests)?.into_values().flat_map(|(_, t)| t).collect();
    c.watch.sort_unstable();
    c.watch.dedup();
    if c.watch.is_empty() {
        return Err(format!("Prometheus has no samples of {} from {} to {}: check --watch, which must be botd's scrape (the bundle would show nothing)", uptime::shown_query(watch), p.from, p.to));
    }
    c.alerts = samples(api, ALERTS_QUERY, p, &mut requests)?;
    for d in 0..p.days() {
        let at = p.start_ms() / 1000 + (d + 1) * 86_400;
        let sent = api.query(&format!("sum by (integration) (increase({SENT}[86400s]))"), at)?;
        let failed = api.query(&format!("sum by (integration) (increase({FAILED}[86400s]))"), at)?;
        requests += 2;
        c.notifications.push(per_integration(&sent).map(|s| (s, per_integration(&failed).unwrap_or_default())));
    }
    c.rules = Some(api.rules());
    requests += 1;
    c.requests = requests;
    Ok(c)
}

// Judging

fn minutes_of(ms: i64) -> i64 {
    (ms.max(0) + 59_999) / 60_000
}

/// The stretches with no watch sample for longer than `GAP_MINUTES`, the period's edges
/// included, as `(from, to)` in milliseconds.
pub fn watch_gaps(times: &[i64], p: &Period) -> Vec<(i64, i64)> {
    let gap = GAP_MINUTES * 60_000;
    let points: Vec<i64> = std::iter::once(p.start_ms()).chain(times.iter().copied().filter(|t| *t >= p.start_ms() && *t < p.end_ms())).chain(std::iter::once(p.end_ms())).collect();
    points.windows(2).filter(|w| w[1] - w[0] > gap).map(|w| (w[0], w[1])).collect()
}

fn overlap(a: (i64, i64), b: (i64, i64)) -> i64 {
    (a.1.min(b.1) - a.0.max(b.0)).max(0)
}

/// The calendar months of the period, as `(YYYY-MM, start, end)` in milliseconds.
fn months(p: &Period) -> Vec<(String, i64, i64)> {
    let mut out = Vec::new();
    let mut m = p.from.with_day(1).unwrap_or(p.from);
    while m < p.to {
        let next = if m.month() == 12 { NaiveDate::from_ymd_opt(m.year() + 1, 1, 1) } else { NaiveDate::from_ymd_opt(m.year(), m.month() + 1, 1) }.unwrap_or(p.to);
        let part = Period { from: m.max(p.from), to: next.min(p.to) };
        out.push((m.format("%Y-%m").to_string(), part.start_ms(), part.end_ms()));
        m = next;
    }
    out
}

fn shown(labels: &Map<String, Value>) -> Value {
    Value::Object(SHOWN_LABELS.iter().filter_map(|k| labels.get(*k).and_then(Value::as_str).filter(|v| plain(v, 64)).map(|v| (k.to_string(), json!(v)))).collect())
}

fn stamp(ms: i64) -> String {
    chrono::DateTime::from_timestamp_millis(ms).map(|t| t.format("%Y%m%dT%H%MZ").to_string()).unwrap_or_default()
}

/// The alert's episodes: runs of its samples no more than `GAP_MINUTES` apart.
fn episodes(c: &Collected, expected: &[Rule], p: &Period) -> (Vec<Value>, usize) {
    let gap = GAP_MINUTES * 60_000;
    let mut out = Vec::new();
    let mut skipped = 0;
    for (key, (labels, times)) in &c.alerts {
        let name = labels.get("alertname").and_then(Value::as_str).unwrap_or_default();
        if !valid_name(name) || !(name.starts_with("SuperBot") || expected.iter().any(|r| r.name == name)) {
            skipped += times.len();
            continue;
        }
        let digest = sha256(key.as_bytes());
        let severity = labels.get("severity").and_then(Value::as_str).filter(|s| plain(s, 32)).unwrap_or("none");
        let mut start = 0;
        for i in 1..=times.len() {
            if i < times.len() && times[i] - times[i - 1] <= gap {
                continue;
            }
            let (from, to) = (times[start], times[i - 1]);
            out.push(json!({
                "id": format!("{name}-{}-{}", stamp(from), &digest[..6]),
                "alert": name,
                "severity": severity,
                "series": format!("prometheus-{}", &digest[..12]),
                "labels": shown(labels),
                "from": rfc3339(from),
                "lastSeen": rfc3339(to),
                "minutes": minutes_of(to - from).max(1),
                "firingAtStart": from - p.start_ms() <= gap,
                "firingAtEnd": p.end_ms() - to <= gap,
            }));
            start = i;
        }
    }
    out.sort_by(|a, b| (a["from"].as_str(), a["id"].as_str()).cmp(&(b["from"].as_str(), b["id"].as_str())));
    (out, skipped)
}

/// A loaded rule as the bundle shows it, from `/api/v1/rules`.
struct Loaded {
    group: String,
    health: String,
    severity: String,
    last_ms: Option<i64>,
    for_secs: Option<f64>,
}

fn loaded(data: &Value) -> BTreeMap<String, Vec<Loaded>> {
    let mut out: BTreeMap<String, Vec<Loaded>> = BTreeMap::new();
    for g in data["groups"].as_array().into_iter().flatten() {
        let group = g["name"].as_str().filter(|s| plain(s, 128)).unwrap_or("<not recorded>").to_string();
        for r in g["rules"].as_array().into_iter().flatten() {
            if r["type"].as_str().is_some_and(|t| t != "alerting") {
                continue;
            }
            let Some(name) = r["name"].as_str().filter(|n| valid_name(n)) else { continue };
            let last_ms = r["lastEvaluation"].as_str().and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok()).map(|t| t.timestamp_millis()).filter(|t| *t > 0);
            out.entry(name.to_string()).or_default().push(Loaded {
                group: group.clone(),
                health: r["health"].as_str().filter(|s| plain(s, 16)).unwrap_or("unknown").to_string(),
                severity: r["labels"]["severity"].as_str().filter(|s| plain(s, 32)).unwrap_or("none").to_string(),
                last_ms,
                for_secs: r["duration"].as_f64(),
            });
        }
    }
    out
}

/// Consecutive day indices as `from/to` date ranges, `to` not included.
fn day_ranges(days: &[i64], p: &Period) -> Vec<Value> {
    let date = |d: i64| (p.from + chrono::Days::new(d as u64)).to_string();
    let mut out = Vec::new();
    let mut i = 0;
    while i < days.len() {
        let mut j = i;
        while j + 1 < days.len() && days[j + 1] == days[j] + 1 {
            j += 1;
        }
        out.push(json!(format!("{}/{}", date(days[i]), date(days[j] + 1))));
        i = j + 1;
    }
    out
}

/// Why the rules couldn't be read, as the bundle records it: the HTTP status at most, since
/// Prometheus' or a proxy's error text can name hosts and paths.
fn unreadable(e: &str) -> String {
    let status = e.strip_prefix("Prometheus answered ").and_then(|r| r.get(..3)).filter(|s| s.bytes().all(|b| b.is_ascii_digit()));
    match status {
        Some(s) => format!("the rules API answered {s}"),
        None if e.starts_with("Prometheus didn't answer") => "the rules API didn't answer".into(),
        None if e.starts_with("Prometheus' answer isn't JSON") => "the rules API's answer isn't JSON".into(),
        None => "the rules API couldn't be read".into(),
    }
}

/// Everything in `alerts.json` but the period.
pub fn assess(c: &Collected, expected: &[Rule], p: &Period, now_ms: i64) -> Value {
    let total_minutes = p.days() * 1440;
    let gaps = watch_gaps(&c.watch, p);
    let unwatched: i64 = minutes_of(gaps.iter().map(|g| g.1 - g.0).sum());
    let (eps, skipped) = episodes(c, expected, p);
    let ids = |f: &dyn Fn(&Value) -> bool| -> Vec<Value> { eps.iter().filter(|e| f(e)).map(|e| e["id"].clone()).collect() };

    let (rules_view, rules_read) = match &c.rules {
        Some(Ok(data)) => (Some(loaded(data)), None),
        Some(Err(e)) => (None, Some(unreadable(e))),
        None => (None, Some("not read".to_string())),
    };
    let stale = |l: &Loaded| l.last_ms.is_none_or(|t| now_ms - t > STALE_EVALUATION_MINUTES * 60_000);
    let (mut not_loaded, mut unhealthy, mut not_evaluating, mut severity_changed) = (Vec::new(), Vec::new(), Vec::new(), Vec::new());
    let rules: Vec<Value> = expected
        .iter()
        .map(|r| {
            let of: Vec<&Value> = eps.iter().filter(|e| e["alert"] == r.name.as_str()).collect();
            let mut v = json!({
                "name": r.name, "file": r.file, "severity": if r.severity.is_empty() { "none" } else { r.severity.as_str() },
                "episodes": of.len(),
                "firingMinutes": of.iter().filter_map(|e| e["minutes"].as_i64()).sum::<i64>(),
                "longestMinutes": of.iter().filter_map(|e| e["minutes"].as_i64()).max().unwrap_or(0),
            });
            if let Some(view) = &rules_view {
                let ls = view.get(&r.name).map(Vec::as_slice).unwrap_or_default();
                v["loaded"] = json!(!ls.is_empty());
                v["groups"] = json!(ls.iter().map(|l| l.group.clone()).collect::<BTreeSet<_>>());
                v["health"] = json!(ls.iter().map(|l| l.health.clone()).collect::<BTreeSet<_>>());
                v["lastEvaluation"] = json!(ls.iter().filter_map(|l| l.last_ms).min().map(rfc3339));
                v["forSeconds"] = json!(ls.iter().filter_map(|l| l.for_secs).next());
                v["severityLoaded"] = json!(ls.iter().map(|l| l.severity.clone()).collect::<BTreeSet<_>>());
                if ls.is_empty() {
                    not_loaded.push(json!(r.name));
                } else {
                    if ls.iter().any(|l| l.health == "err") {
                        unhealthy.push(json!(r.name));
                    }
                    if ls.iter().any(|l| stale(l)) {
                        not_evaluating.push(json!(r.name));
                    }
                    let want = if r.severity.is_empty() { "none" } else { r.severity.as_str() };
                    if let Some(l) = ls.iter().find(|l| l.severity != want) {
                        severity_changed.push(json!(format!("{} ({want} expected, {} loaded)", r.name, l.severity)));
                    }
                }
            }
            v
        })
        .collect();
    let other_loaded: Vec<Value> = rules_view.as_ref().map(|v| v.keys().filter(|n| n.starts_with("SuperBot") && !expected.iter().any(|r| &r.name == *n)).map(|n| json!(n)).collect()).unwrap_or_default();

    let day_of = |ms: i64| ((ms - p.start_ms()) / 86_400_000) as usize;
    let mut started = vec![(0usize, 0usize); p.days() as usize];
    for e in &eps {
        let from = e["from"].as_str().and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok()).map(|t| t.timestamp_millis()).unwrap_or(p.start_ms());
        if let Some(s) = started.get_mut(day_of(from)) {
            s.0 += 1;
            s.1 += usize::from(e["severity"] == "page");
        }
    }
    let (mut sent_total, mut failed_total, mut failed, mut unrecorded) = (0u64, 0u64, Vec::new(), Vec::new());
    let by_day: Vec<Value> = (0..p.days())
        .map(|d| {
            let span = (p.start_ms() + d * 86_400_000, p.start_ms() + (d + 1) * 86_400_000);
            let n = c.notifications.get(d as usize).cloned().flatten();
            let date = (p.from + chrono::Days::new(d as u64)).to_string();
            match &n {
                Some((s, f)) => {
                    sent_total += s.values().sum::<u64>();
                    failed_total += f.values().sum::<u64>();
                    failed.extend(f.iter().filter(|(_, n)| **n > 0).map(|(i, n)| json!(format!("{date} {i} {n}"))));
                }
                None => unrecorded.push(d),
            }
            json!({
                "date": date,
                "episodesStarted": started[d as usize].0,
                "pagesStarted": started[d as usize].1,
                "unwatchedMinutes": minutes_of(gaps.iter().map(|g| overlap(*g, span)).sum()),
                "notifications": n.map(|(s, f)| json!({ "sent": s, "failed": f })),
            })
        })
        .collect();
    let by_month: Vec<Value> = months(p)
        .into_iter()
        .map(|(month, a, b)| {
            let mins = (b - a) / 60_000;
            let un = minutes_of(gaps.iter().map(|g| overlap(*g, (a, b))).sum());
            json!({ "month": month, "minutes": mins, "unwatchedMinutes": un, "watchGapsWithinBudget": uptime::meets(un as u64, mins as u64, uptime::DEFAULT_OBJECTIVE) })
        })
        .collect();
    let severities: BTreeMap<String, usize> = eps.iter().fold(BTreeMap::new(), |mut m, e| {
        *m.entry(e["severity"].as_str().unwrap_or("none").to_string()).or_insert(0) += 1;
        m
    });
    let within = uptime::meets(unwatched as u64, total_minutes as u64, uptime::DEFAULT_OBJECTIVE);
    let exceptions = json!({
        "pages": ids(&|e| e["severity"] == "page"),
        "firingOverADay": ids(&|e| e["minutes"].as_i64().is_some_and(|m| m > LONG_FIRING_MINUTES)),
        "firingAtEnd": ids(&|e| e["firingAtEnd"] == true),
        "watchGaps": gaps.iter().map(|g| json!(format!("{}/{}", rfc3339(g.0), rfc3339(g.1)))).collect::<Vec<_>>(),
        "watchGapsOverBudget": by_month.iter().filter(|m| m["watchGapsWithinBudget"] == false).map(|m| m["month"].clone()).collect::<Vec<_>>(),
        "rulesUnreadable": rules_read.iter().map(|e| json!(e)).collect::<Vec<_>>(),
        "rulesNotLoaded": not_loaded,
        "rulesUnhealthy": unhealthy,
        "rulesNotEvaluating": not_evaluating,
        "rulesSeverityChanged": severity_changed,
        "notificationsFailed": failed,
        "notificationsNotRecorded": day_ranges(&unrecorded, p),
    });
    let maps = within && ["rulesUnreadable", "rulesNotLoaded", "rulesUnhealthy", "rulesNotEvaluating"].iter().all(|k| exceptions[k].as_array().is_some_and(Vec::is_empty));
    json!({
        "basis": format!("an alert fired while Prometheus recorded it in ALERTS{{alertstate=\"firing\"}}; samples of one series no more than {GAP_MINUTES} minutes apart are one episode, from its first sample to its last; Prometheus watched while it had samples of the watch series (botd's scrape) no more than {GAP_MINUTES} minutes apart, and the bundle maps its controls only while the unwatched minutes fit in the 99.9% error budget and every expected rule is loaded, healthy and evaluated in the last {STALE_EVALUATION_MINUTES} minutes when the bundle is made; the rules are as of then, not through the period; notifications are Alertmanager's own counters, as Prometheus' increase() over each day, rounded"),
        "summary": {
            "minutes": total_minutes,
            "unwatchedMinutes": unwatched,
            "watchedPercent": ((total_minutes - unwatched) as f64 * 100_000.0 / total_minutes as f64).round() / 1000.0,
            "watchGapsWithinBudget": within,
            "episodes": eps.len(),
            "bySeverity": severities,
            "alertsThatFired": eps.iter().filter_map(|e| e["alert"].as_str()).collect::<BTreeSet<_>>(),
            "firingMinutes": eps.iter().filter_map(|e| e["minutes"].as_i64()).sum::<i64>(),
            "rulesExpected": expected.len(),
            "rulesLoaded": rules.iter().filter(|r| r["loaded"] == true).count(),
            "notificationsSent": sent_total,
            "notificationsFailed": failed_total,
            "otherAlertSamplesSkipped": skipped,
            "mapsControls": maps,
        },
        "exceptions": exceptions,
        "rules": rules,
        "otherSuperBotRulesLoaded": other_loaded,
        "episodes": eps,
        "watchGaps": gaps.iter().map(|g| json!({ "from": rfc3339(g.0), "to": rfc3339(g.1), "minutes": minutes_of(g.1 - g.0) })).collect::<Vec<_>>(),
        "byMonth": by_month,
        "byDay": by_day,
    })
}

// The bundle

/// A bundle's name, without `.tar`.
pub fn name(p: &Period, now_ms: i64) -> String {
    let stamp = chrono::DateTime::from_timestamp_millis(now_ms).map(|t| t.format("%Y%m%dT%H%M%SZ").to_string()).unwrap_or_default();
    format!("{PREFIX}{}-{stamp}", p.label())
}

pub fn build(alerts: &Value, source: &Value, p: &Period, now_ms: i64) -> crate::changes::Bundle {
    let name = name(p, now_ms);
    let period = json!({ "from": p.from.to_string(), "to": p.to.to_string(), "days": p.days() });
    let mut a = alerts.clone();
    a["periodCovered"] = period.clone();
    let mapped = a["summary"]["mapsControls"] == true;
    let mut files: Vec<(&str, Vec<u8>)> = vec![("README.txt", README.as_bytes().to_vec()), (FILE, json_file(&a))];
    let listed: Vec<Value> = files
        .iter()
        .map(|(n, b)| {
            let s = SECTIONS.iter().find(|s| s.file == *n).filter(|_| mapped);
            json!({ "name": n, "bytes": b.len(), "sha256": sha256(b), "criteria": s.map(|s| s.criteria).unwrap_or_default(), "checklist": s.map(|s| s.rows).unwrap_or_default() })
        })
        .collect();
    let manifest = json!({
        "product": "SuperBot",
        "kind": "alerting",
        "format": FORMAT,
        "tool": concat!("superbot-evidence ", env!("CARGO_PKG_VERSION")),
        "createdAt": rfc3339(now_ms),
        "period": period,
        "source": source,
        "episodes": a["summary"]["episodes"],
        "unwatchedMinutes": a["summary"]["unwatchedMinutes"],
        "files": listed,
        "notIncluded": "the token, the Prometheus address, rule files' paths, rules' expressions and errors, and alert labels that could name a host",
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
pub fn summary(a: &Value) -> String {
    let s = &a["summary"];
    let mut out = format!(
        "{} alert episodes ({} pages), {} firing minutes; Prometheus unwatched {} minutes ({}% watched); {} of {} expected rules loaded; {} notifications sent, {} failed.",
        s["episodes"],
        s["bySeverity"]["page"].as_u64().unwrap_or(0),
        s["firingMinutes"],
        s["unwatchedMinutes"],
        s["watchedPercent"],
        s["rulesLoaded"],
        s["rulesExpected"],
        s["notificationsSent"],
        s["notificationsFailed"],
    );
    for (k, label) in [
        ("pages", "Pages, each needing its response on record"),
        ("firingOverADay", "Fired for more than a day"),
        ("firingAtEnd", "Still firing at the period's end"),
        ("watchGapsOverBudget", "Prometheus unwatched longer than the error budget in (the bundle maps no controls)"),
        ("rulesUnreadable", "Prometheus' rules couldn't be read (the bundle maps no controls)"),
        ("rulesNotLoaded", "Expected rules not loaded (the bundle maps no controls)"),
        ("rulesUnhealthy", "Rules failing to evaluate (the bundle maps no controls)"),
        ("rulesNotEvaluating", "Rules not evaluated in the last 10 minutes (the bundle maps no controls)"),
        ("rulesSeverityChanged", "Rules loaded with another severity"),
        ("notificationsFailed", "Notifications failed"),
        ("notificationsNotRecorded", "No Alertmanager notifications recorded (Prometheus doesn't scrape it?)"),
    ] {
        if let Some(v) = a["exceptions"][k].as_array().filter(|v| !v.is_empty()) {
            out += &format!("\n  {label}: {}", v.iter().filter_map(Value::as_str).collect::<Vec<_>>().join(", "));
        }
    }
    if let Some(n) = a["exceptions"]["watchGaps"].as_array().map(Vec::len).filter(|n| *n > 0) {
        out += &format!("\n  {n} stretches of more than {GAP_MINUTES} minutes with nothing scraped from botd: listed in alerts.json");
    }
    out
}

// The command

#[derive(Default)]
struct Args {
    prometheus: Option<String>,
    watch: Option<String>,
    rules: Vec<String>,
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
            "--rules" => {
                a.rules.push(value(&mut it)?);
                continue;
            }
            "--token" | "-t" => return Err("Pass a Prometheus token in PROMETHEUS_TOKEN, never on the command line, where other users and shell history see it.".into()),
            "--prometheus" => &mut a.prometheus,
            "--watch" => &mut a.watch,
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
    if a.prometheus.is_none() {
        return Err(format!("Give --prometheus <url>: the Prometheus that evaluates SuperBot's alert rules.\n\n{}", crate::USAGE));
    }
    if a.watch.as_deref().is_some_and(|q| !uptime::valid_selector(q)) {
        return Err(format!("--watch must be a series selector, as {DEFAULT_WATCH}: no functions or ranges"));
    }
    Ok(a)
}

/// The rules expected loaded and where they came from: each `--rules` file, or the
/// shipped files.
fn expected(files: &[String]) -> Result<(Vec<Rule>, Value), String> {
    if files.is_empty() {
        return Ok((shipped(), json!({ "kind": "shipped", "files": SHIPPED.iter().map(|(f, _)| f).collect::<Vec<_>>() })));
    }
    let (mut rules, mut listed, mut seen): (Vec<Rule>, Vec<Value>, Vec<String>) = (Vec::new(), Vec::new(), Vec::new());
    for f in files {
        let size = std::fs::metadata(f).map_err(|e| format!("{f}: {e}"))?.len();
        if size > MAX_RULES_BYTES {
            return Err(format!("{f} is over {} MiB, larger than any rule file", MAX_RULES_BYTES >> 20));
        }
        let bytes = std::fs::read(f).map_err(|e| format!("{f}: {e}"))?;
        let digest = sha256(&bytes);
        if seen.contains(&digest) {
            return Err(format!("{f} is the same file as another --rules"));
        }
        seen.push(digest.clone());
        let base = Path::new(f).file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        let text = std::str::from_utf8(&bytes).map_err(|_| format!("{f} isn't UTF-8 text"))?;
        let parsed = parse_rules(&base, text)?;
        listed.push(json!({ "file": base, "bytes": bytes.len(), "sha256": digest, "alerts": parsed.len() }));
        for r in parsed {
            if !rules.iter().any(|x| x.name == r.name) {
                rules.push(r);
            }
        }
    }
    Ok((rules, json!({ "kind": "files", "files": listed })))
}

pub fn run(args: &[String], now: chrono::DateTime<chrono::Utc>) -> Result<String, String> {
    run_with(args, now, &|k| std::env::var(k).ok())
}

fn run_with(args: &[String], now: chrono::DateTime<chrono::Utc>, env: &dyn Fn(&str) -> Option<String>) -> Result<String, String> {
    let a = parse_args(args)?;
    let p = Period::parse(a.from.as_deref(), a.to.as_deref(), now.date_naive())?;
    if p.end_ms() > now.timestamp_millis() {
        return Err(format!("The period ends at {} UTC, which hasn't come yet: make the bundle once it has", p.to));
    }
    let (rules, rules_source) = expected(&a.rules)?;
    let watch = a.watch.clone().unwrap_or_else(|| DEFAULT_WATCH.into());
    let token = env("PROMETHEUS_TOKEN");
    let mut http = prometheus::Http::new(a.prometheus.as_deref().unwrap_or_default(), token.clone())?;
    let c = collect(&mut http, &watch, &p)?;
    let alerts = assess(&c, &rules, &p, now.timestamp_millis());
    let source = json!({ "watch": uptime::shown_query(&watch), "alerts": ALERTS_QUERY, "notifications": [SENT, FAILED], "rulesExpected": rules_source, "requests": c.requests });
    let b = build(&alerts, &source, &p, now.timestamp_millis());
    if token.as_deref().map(str::trim).filter(|t| !t.is_empty()).is_some_and(|t| b.tar.windows(t.len()).any(|w| w == t.as_bytes())) {
        return Err("The bundle would contain the token, so it wasn't written.".into());
    }
    let file = a.out.clone().unwrap_or_else(|| format!("{}.tar", b.name));
    crate::save_private(&file, &b.tar)?;
    let unread = match &c.rules {
        Some(Err(e)) => format!("The rules couldn't be read (the bundle records only why, not this): {e}\n"),
        _ => String::new(),
    };
    Ok(format!(
        "{unread}Saved {file} ({} KB) for {} to {} (not included), in {} requests.\n{}\nManifest SHA-256: {}\nBundle SHA-256: {}\nKeep it in the evidence store; to check it:\n  tar -xf {} && (cd {} && sha256sum -c SHA256SUMS)",
        b.tar.len().div_ceil(1024),
        p.from,
        p.to,
        c.requests,
        summary(&alerts),
        b.manifest_sha256,
        b.sha256,
        crate::quote(&file),
        crate::quote(&b.name),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn day(s: &str) -> NaiveDate {
        NaiveDate::parse_from_str(s, "%Y-%m-%d").unwrap()
    }

    fn at(s: &str) -> i64 {
        chrono::DateTime::parse_from_rfc3339(s).unwrap().timestamp_millis()
    }

    fn period() -> Period {
        Period { from: day("2026-10-01"), to: day("2026-11-01") }
    }

    /// A stand-in Prometheus: botd scraped every 30 seconds but in `unwatched`, alerts
    /// firing as given (evaluated every minute), notifications from Alertmanager on the
    /// days given, and the rules as given.
    struct Fake {
        unwatched: Vec<(i64, i64)>,
        firing: Vec<(Value, i64, i64)>,
        notified: BTreeMap<i64, (Value, Value)>,
        rules: Result<Value, String>,
        asked: Vec<(String, i64)>,
    }

    impl Fake {
        fn new() -> Fake {
            Fake { unwatched: Vec::new(), firing: Vec::new(), notified: BTreeMap::new(), rules: Ok(rules_answer(&shipped(), at("2026-11-01T00:05:00Z"))), asked: Vec::new() }
        }
    }

    fn rules_answer(rules: &[Rule], last_ms: i64) -> Value {
        let rules: Vec<Value> = rules.iter().map(|r| json!({ "type": "alerting", "name": r.name, "health": "ok", "lastError": "", "labels": { "severity": r.severity }, "lastEvaluation": rfc3339(last_ms), "duration": 300, "query": "secret_expr{instance=\"db.internal\"}" })).collect();
        json!({ "groups": [{ "name": "superbot-alerts", "file": "/etc/prometheus/superbot.rules.yml", "rules": rules }] })
    }

    impl Api for Fake {
        fn query(&mut self, query: &str, time_s: i64) -> Result<Value, String> {
            self.asked.push((query.to_string(), time_s));
            if query.starts_with("sum by (integration)") {
                let pick = self.notified.get(&time_s).map(|(s, f)| if query.contains("failed") { f.clone() } else { s.clone() });
                return Ok(json!({ "resultType": "vector", "result": pick.unwrap_or(json!([])) }));
            }
            let (selector, range) = query.rsplit_once('[').unwrap();
            let from = (time_s - range.trim_end_matches("s]").parse::<i64>().unwrap()) * 1000;
            let to = time_s * 1000;
            let result: Vec<Value> = if selector == ALERTS_QUERY {
                self.firing
                    .iter()
                    .map(|(labels, a, b)| json!({ "metric": labels, "values": (*a..=*b).step_by(60_000).filter(|t| *t > from && *t <= to).map(|t| json!([t as f64 / 1000.0, "1"])).collect::<Vec<_>>() }))
                    .collect()
            } else {
                let values: Vec<Value> = (from - from % 30_000..=to).step_by(30_000).filter(|t| *t > from && *t <= to && !self.unwatched.iter().any(|(a, b)| t >= a && t < b)).map(|t| json!([t as f64 / 1000.0, "1"])).collect();
                vec![json!({ "metric": { "__name__": "up", "job": "superbot", "instance": "botd.internal:8080" }, "values": values })]
            };
            Ok(json!({ "resultType": "matrix", "result": result }))
        }

        fn rules(&mut self) -> Result<Value, String> {
            self.rules.clone()
        }
    }

    fn alert(name: &str, severity: &str, instance: &str) -> Value {
        json!({ "__name__": "ALERTS", "alertname": name, "alertstate": "firing", "severity": severity, "job": "superbot", "instance": instance })
    }

    fn now() -> i64 {
        at("2026-11-01T00:06:00Z")
    }

    #[test]
    fn the_shipped_rules_parse_with_their_severities() {
        let rules = shipped();
        assert!(rules.len() >= 30, "{}", rules.len());
        let get = |n: &str| rules.iter().find(|r| r.name == n).unwrap_or_else(|| panic!("{n}"));
        assert_eq!((get("SuperBotDown").severity.as_str(), get("SuperBotDown").file.as_str()), ("page", "superbot-slo.rules.yml"));
        assert_eq!(get("SuperBotSignInFromNewNetwork").severity, "ticket");
        assert_eq!(get("SuperBotHostDiskFull").file, "superbot-capacity.rules.yml");
        assert!(rules.iter().all(|r| ["page", "ticket"].contains(&r.severity.as_str())), "every shipped alert has a severity");
        let all: usize = SHIPPED.iter().map(|(_, t)| t.matches("- alert:").count()).sum();
        assert_eq!(rules.len(), all, "each alert of the shipped files, once");
        let dir: BTreeSet<String> = std::fs::read_dir(concat!(env!("CARGO_MANIFEST_DIR"), "/../deploy/prometheus")).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().into_owned()).filter(|n| n.ends_with(".rules.yml")).collect();
        assert_eq!(dir, SHIPPED.iter().map(|(f, _)| f.to_string()).collect::<BTreeSet<_>>(), "every rule file deploy/prometheus ships is expected");
    }

    #[test]
    fn rule_files_parse_and_refuse() {
        let text = "groups:\n  - name: mine\n    rules:\n      - record: job:x:rate5m\n        expr: rate(x[5m])\n        labels:\n          severity: page\n      - alert: \"MyAlert\"  # ours\n        expr: x > 1\n        labels:\n          team: ops\n          severity: 'ticket'\n        annotations:\n          description: \"severity: page in the text\"\n      - expr: y > 1\n        alert: Second\n";
        let r = parse_rules("mine.yml", text).unwrap();
        assert_eq!(r, [Rule { name: "MyAlert".into(), severity: "ticket".into(), file: "mine.yml".into() }, Rule { name: "Second".into(), severity: String::new(), file: "mine.yml".into() }], "a recording rule's labels are no alert's");
        assert!(parse_rules("rec.yml", "groups:\n  - name: r\n    rules:\n      - record: a\n        expr: b\n").unwrap_err().contains("no alerting rules"));
        assert!(parse_rules("bad.yml", "      - alert: 9lives\n").unwrap_err().contains("isn't an alert name"));
    }

    #[test]
    fn episodes_watch_gaps_rules_and_notifications() {
        let p = period();
        let mut f = Fake::new();
        f.unwatched = vec![(at("2026-10-09T12:00:00Z"), at("2026-10-09T12:20:00Z"))];
        f.firing = vec![
            (alert("SuperBotDown", "page", "botd.internal:8080"), at("2026-10-03T10:00:00Z"), at("2026-10-03T10:09:00Z")),
            (alert("SuperBotDown", "page", "botd.internal:8080"), at("2026-10-03T10:20:00Z"), at("2026-10-03T10:25:00Z")),
            (alert("SuperBotHostDiskFilling", "ticket", "incus-7.internal"), at("2026-10-20T00:00:00Z"), at("2026-10-31T23:59:00Z")),
            (alert("NodeExporterDown", "page", "x"), at("2026-10-05T00:00:00Z"), at("2026-10-05T00:10:00Z")),
        ];
        let d = |s: &str| day(s).and_hms_opt(0, 0, 0).unwrap().and_utc().timestamp() + 86_400;
        f.notified.insert(d("2026-10-03"), (json!([{ "metric": { "integration": "email" }, "value": [0, "2.0000004"] }, { "metric": { "integration": "webhook" }, "value": [0, "2"] }]), json!([{ "metric": { "integration": "webhook" }, "value": [0, "1"] }])));
        for dd in ["2026-10-01", "2026-10-02", "2026-10-04"] {
            f.notified.insert(d(dd), (json!([{ "metric": { "integration": "email" }, "value": [0, "0"] }]), json!([])));
        }
        let mut rules = shipped();
        rules.retain(|r| r.name != "SuperBotPanics");
        let mut answer = rules_answer(&rules, at("2026-11-01T00:05:30Z"));
        let list = answer["groups"][0]["rules"].as_array_mut().unwrap();
        for r in list.iter_mut() {
            if r["name"] == "SuperBotSignInFromNewNetwork" {
                r["labels"]["severity"] = json!("none-at-all");
            }
            if r["name"] == "SuperBotHostDiskFull" {
                r["health"] = json!("err");
                r["lastError"] = json!("query timed out on db.internal");
            }
            if r["name"] == "SuperBotRunQueueBacklog" {
                r["lastEvaluation"] = json!("0001-01-01T00:00:00Z");
            }
        }
        f.rules = Ok(answer);

        let c = collect(&mut f, DEFAULT_WATCH, &p).unwrap();
        assert_eq!(c.requests, 31 + 31 + 62 + 1);
        assert_eq!(f.asked[0], (format!("{DEFAULT_WATCH}[86460s]"), p.start_ms() / 1000 + 86_400));
        let a = assess(&c, &shipped(), &p, now());
        let s = &a["summary"];
        assert_eq!((s["episodes"].as_u64(), s["bySeverity"]["page"].as_u64(), s["bySeverity"]["ticket"].as_u64()), (Some(3), Some(2), Some(1)), "a gap of more than 5 minutes is a second episode");
        assert_eq!(s["otherAlertSamplesSkipped"], 11, "someone else's alert isn't SuperBot's");
        let ep = a["episodes"].as_array().unwrap();
        assert_eq!((ep[0]["alert"].as_str(), ep[0]["minutes"].as_i64(), ep[0]["lastSeen"].as_str()), (Some("SuperBotDown"), Some(9), Some("2026-10-03T10:09:00Z")));
        assert!(ep[0]["id"].as_str().unwrap().starts_with("SuperBotDown-20261003T1000Z-"));
        assert_eq!(ep[0]["labels"], json!({ "alertname": "SuperBotDown", "severity": "page", "job": "superbot" }), "never the instance");
        assert_eq!((ep[2]["firingAtEnd"].as_bool(), ep[2]["minutes"].as_i64()), (Some(true), Some(17_279)));
        assert_eq!((s["unwatchedMinutes"].as_i64(), s["watchGapsWithinBudget"].as_bool()), (Some(21), Some(true)), "20.5 minutes between samples is within 44.6");
        let ex = &a["exceptions"];
        assert_eq!(ex["pages"].as_array().unwrap().len(), 2);
        assert_eq!((ex["firingOverADay"].clone(), ex["firingAtEnd"].clone()), (json!([ep[2]["id"]]), json!([ep[2]["id"]])));
        assert_eq!(ex["watchGaps"], json!(["2026-10-09T11:59:30Z/2026-10-09T12:20:00Z"]));
        assert_eq!((ex["rulesNotLoaded"].clone(), ex["rulesUnhealthy"].clone(), ex["rulesNotEvaluating"].clone()), (json!(["SuperBotPanics"]), json!(["SuperBotHostDiskFull"]), json!(["SuperBotRunQueueBacklog"])));
        assert_eq!(ex["rulesSeverityChanged"], json!(["SuperBotSignInFromNewNetwork (ticket expected, none-at-all loaded)"]));
        assert_eq!((ex["notificationsFailed"].clone(), ex["notificationsNotRecorded"].clone()), (json!(["2026-10-03 webhook 1"]), json!(["2026-10-05/2026-11-01"])));
        assert_eq!((s["notificationsSent"].as_u64(), s["notificationsFailed"].as_u64()), (Some(4), Some(1)));
        assert_eq!(s["mapsControls"], false, "a rule not loaded, failing or not evaluated maps nothing");
        let down = a["rules"].as_array().unwrap().iter().find(|r| r["name"] == "SuperBotDown").unwrap();
        assert_eq!((down["episodes"].as_u64(), down["firingMinutes"].as_i64(), down["loaded"].as_bool(), down["groups"].clone()), (Some(2), Some(14), Some(true), json!(["superbot-alerts"])));
        assert_eq!((a["byDay"][2]["episodesStarted"].as_u64(), a["byDay"][2]["pagesStarted"].as_u64(), a["byDay"][8]["unwatchedMinutes"].as_i64()), (Some(2), Some(2), Some(21)));
        let text = serde_json::to_string(&a).unwrap();
        for never in ["internal", "secret_expr", "/etc/prometheus", "timed out"] {
            assert!(!text.contains(never), "{never} is in alerts.json");
        }

        f.rules = Ok(rules_answer(&shipped(), at("2026-11-01T00:05:30Z")));
        let c = collect(&mut f, DEFAULT_WATCH, &p).unwrap();
        let clean = assess(&c, &shipped(), &p, now());
        assert_eq!(clean["summary"]["mapsControls"], true);
        f.rules = Err("Prometheus answered 502: <html>no upstream prom-internal.example:9090/etc/prometheus</html>".into());
        let c = collect(&mut f, DEFAULT_WATCH, &p).unwrap();
        let unread = assess(&c, &shipped(), &p, now());
        assert_eq!((unread["summary"]["mapsControls"].as_bool(), unread["exceptions"]["rulesUnreadable"].clone()), (Some(false), json!(["the rules API answered 502"])));
        assert_eq!(unread["rules"][0].get("loaded"), None, "unknown, not false");
        let text = serde_json::to_string(&unread).unwrap();
        assert!(!text.contains("prom-internal") && !text.contains("/etc/prometheus"), "an error's text stays out of alerts.json");
        for (raw, kept) in [
            ("Prometheus didn't answer: connect to 10.0.0.9 refused", "the rules API didn't answer"),
            ("Prometheus' answer isn't JSON: expected value at line 1", "the rules API's answer isn't JSON"),
            ("Prometheus answered abc", "the rules API couldn't be read"),
            ("this Prometheus can't list its rules", "the rules API couldn't be read"),
        ] {
            assert_eq!(unreadable(raw), kept);
        }
    }

    #[test]
    fn a_month_prometheus_mostly_missed_maps_no_controls() {
        let p = period();
        let mut f = Fake::new();
        f.unwatched = vec![(at("2026-10-31T23:00:00Z"), at("2026-11-01T00:00:00Z"))];
        let c = collect(&mut f, DEFAULT_WATCH, &p).unwrap();
        let a = assess(&c, &shipped(), &p, now());
        assert_eq!((a["summary"]["unwatchedMinutes"].as_i64(), a["summary"]["mapsControls"].as_bool()), (Some(61), Some(false)));
        assert_eq!(a["exceptions"]["watchGapsOverBudget"], json!(["2026-10"]));
        let manifest = |a: &Value| -> Value {
            let b = build(a, &json!({}), &p, now());
            let entries = crate::coverage::untar(&b.tar).unwrap();
            serde_json::from_slice(&entries.iter().find(|(n, _)| n.ends_with("/manifest.json")).unwrap().1).unwrap()
        };
        assert!(manifest(&a)["files"].as_array().unwrap().iter().all(|f| f["checklist"] == json!([])));
        let mut f = Fake::new();
        let full = assess(&collect(&mut f, DEFAULT_WATCH, &p).unwrap(), &shipped(), &p, now());
        let m = manifest(&full);
        assert_eq!((m["kind"].as_str(), m["files"][1]["name"].as_str(), m["files"][1]["checklist"].clone()), (Some("alerting"), Some(FILE), json!(["CC2.1-1", "CC7.2-1", "A1.1-1"])));
        assert_eq!(full["summary"]["watchedPercent"].as_f64(), Some(100.0));

        let mut empty = Fake::new();
        empty.unwatched = vec![(p.start_ms() - 86_400_000, p.end_ms() + 86_400_000)];
        assert!(collect(&mut empty, DEFAULT_WATCH, &p).unwrap_err().contains("no samples of up{job=\"superbot\"}"));
    }

    #[test]
    fn edges_and_ranges() {
        let p = Period { from: day("2026-10-01"), to: day("2026-10-02") };
        let gaps = watch_gaps(&[at("2026-10-01T00:06:00Z"), at("2026-10-01T00:07:00Z"), at("2026-10-01T23:50:00Z")], &p);
        assert_eq!(gaps, [(p.start_ms(), at("2026-10-01T00:06:00Z")), (at("2026-10-01T00:07:00Z"), at("2026-10-01T23:50:00Z")), (at("2026-10-01T23:50:00Z"), p.end_ms())]);
        assert!(watch_gaps(&[at("2026-10-01T00:04:00Z"), at("2026-10-01T00:09:00Z"), at("2026-10-01T00:14:00Z")], &Period { from: day("2026-10-01"), to: day("2026-10-01") }).is_empty(), "nothing outside the period");
        let q = period();
        assert_eq!(day_ranges(&[0, 1, 2, 5, 30], &q), [json!("2026-10-01/2026-10-04"), json!("2026-10-06/2026-10-07"), json!("2026-10-31/2026-11-01")]);
        let two = Period { from: day("2026-10-15"), to: day("2026-11-15") };
        assert_eq!(months(&two).iter().map(|m| (m.0.as_str(), (m.2 - m.1) / 86_400_000)).collect::<Vec<_>>(), [("2026-10", 17), ("2026-11", 14)]);
    }

    #[test]
    fn options() {
        let args = |s: &[&str]| s.iter().map(|x| x.to_string()).collect::<Vec<_>>();
        let a = parse_args(&args(&["--prometheus", "https://prom.example.com", "--watch", "up{job=\"botd\"}", "--rules", "a.yml", "--rules", "b.yml", "-o", "a.tar"])).unwrap();
        assert_eq!((a.prometheus.as_deref(), a.watch.as_deref(), a.rules.len(), a.out.as_deref()), (Some("https://prom.example.com"), Some("up{job=\"botd\"}"), 2, Some("a.tar")));
        for (bad, want) in [
            (&[][..], "Give --prometheus"),
            (&["--prometheus", "https://p", "--watch", "rate(up[5m])"], "series selector"),
            (&["--prometheus", "https://p", "--token", "s3cret"], "PROMETHEUS_TOKEN"),
            (&["--prometheus", "https://p", "--prometheus", "https://q"], "given twice"),
            (&["--prometheus", "https://p", "--rules"], "needs a value"),
            (&["--prometheus", "https://p", "--checks", "c.csv"], "Unknown option"),
        ] {
            let e = parse_args(&args(bad)).err().unwrap_or_default();
            assert!(e.contains(want) && !e.contains("s3cret"), "{bad:?}: {e}");
        }
        let now = chrono::DateTime::parse_from_rfc3339("2026-10-31T12:00:00Z").unwrap().with_timezone(&chrono::Utc);
        let e = run_with(&args(&["--prometheus", "https://p", "--from", "2026-10-01", "--to", "2026-11-01"]), now, &|_| None).unwrap_err();
        assert!(e.contains("hasn't come yet"), "{e}");
    }

    /// The default watch is the scrape job deploy/README.md names and the rules read.
    #[test]
    fn the_watch_is_the_scrape_the_rules_read() {
        let readme = include_str!("../../../../deploy/README.md");
        assert!(readme.contains("scrape jobs are named `superbot`") && DEFAULT_WATCH.contains("job=\"superbot\""));
        let slo = SHIPPED.iter().find(|(f, _)| *f == "superbot-slo.rules.yml").unwrap().1;
        assert!(slo.contains("up{job=\"superbot\"}"), "SuperBotDown reads the same scrape");
    }

    #[test]
    fn names_never_collide_with_the_other_bundles() {
        let n = name(&period(), 1_795_000_000_000);
        assert!(n.starts_with("superbot-alerts-2026-10-01_2026-11-01-") && n.ends_with('Z'), "{n}");
        assert!(n.len() + "/manifest.json".len() <= 100, "fits a ustar name");
        assert!(![crate::changes::PREFIX, crate::vulns::PREFIX, crate::drills::PREFIX, crate::register::PREFIX, crate::uptime::PREFIX, "superbot-evidence-"].iter().any(|p| n.starts_with(p)));
    }

    /// The file maps to criteria the control mapping has and checklist rows the readiness
    /// checklist has, and the evidence plan's alerts table lists it with them.
    #[test]
    fn every_file_maps_to_real_controls_and_the_evidence_plan_says_so() {
        let mapping = include_str!("../../../../docs/security/soc2-control-mapping.md");
        let checklist = include_str!("../../../../docs/security/soc2-readiness-checklist.md");
        let plan = include_str!("../../../../docs/security/soc2-evidence-plan.md");
        let section = plan.split("## The alerts bundle").nth(1).and_then(|s| s.split("\n## ").next()).expect("the evidence plan has an alerts bundle section");
        for s in &SECTIONS {
            for c in s.criteria {
                assert!(mapping.contains(&format!("| {c} ")), "{}: {c} isn't a criterion of the control mapping", s.file);
            }
            for r in s.rows {
                assert!(checklist.contains(&format!("| {r} |")), "{}: {r} isn't a row of the readiness checklist", s.file);
                assert!(s.criteria.iter().any(|c| r.starts_with(&format!("{c}-"))), "{}: {r} isn't under one of its criteria", s.file);
            }
            let line = section.lines().find(|l| l.starts_with(&format!("| `{}` |", s.file))).unwrap_or_else(|| panic!("the evidence plan's alerts table has no row for `{}`", s.file));
            for id in s.criteria.iter().chain(s.rows) {
                assert!(line.contains(id), "the evidence plan's row for `{}` doesn't name {id}", s.file);
            }
        }
    }
}
