//! botd's counters and histograms, in Prometheus' text format (ADR 0089).
//!
//! Every label value is a `&'static str` from a fixed list (route classes, methods,
//! status classes, harness names, run results, audit actions), or a code-defined
//! reason capped at `MAX_REASONS` distinct values. Nothing a person types, no user or
//! Bot id, and no email can become a label, so the number of series stays bounded.

use std::collections::BTreeMap;
use std::fmt::Write;
use std::sync::Mutex;

/// Request latency buckets, in seconds.
pub const HTTP_BUCKETS: [f64; 12] = [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0];
/// Run duration buckets, in seconds: a run may take up to `RUN_TIMEOUT_MINUTES` (60).
pub const RUN_BUCKETS: [f64; 11] = [1.0, 5.0, 15.0, 30.0, 60.0, 120.0, 300.0, 600.0, 1200.0, 1800.0, 3600.0];

/// What `run_one` reports a finished run as (`bot.run_finished`'s `result`).
pub const RUN_RESULTS: [&str; 8] = ["done", "error", "timeout", "stopped", "interrupted", "account_removed", "unguarded", "policy"];

/// Audit actions counted in `superbot_events_total`: what an operator alerts on.
pub const EVENTS: [&str; 30] = [
    "auth.login",
    "auth.login_failed",
    "access.denied",
    "approval.requested",
    "approval.approved",
    "approval.denied",
    "approval.expired",
    "bot.run_queued",
    "bot.run_refused",
    "machine.backup_created",
    "machine.backup_failed",
    "machine.backups_failed",
    "machine.rpo_breached",
    "machine.rpo_recovered",
    "machine.restore_requested",
    "machine.restored",
    "machine.restore_failed",
    "machine.restore_rto_exceeded",
    "machine.create_failed",
    "machine.destroy_failed",
    "machine.enroll_failed",
    "machine.enroll_timeout",
    "machine.lost",
    "machine.host_down",
    "machine.host_lost",
    "machine.host_up",
    "machine.agent_upgrade_failed",
    "notification.sent",
    "notification.failed",
    "server.started",
];

const OUTCOMES: [&str; 3] = ["success", "failure", "denied"];
const METHODS: [&str; 7] = ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"];
/// Distinct refusal reasons kept; any more count as `other`.
pub const MAX_REASONS: usize = 32;

#[derive(Default, Clone)]
struct Histogram {
    /// Cumulative: `le[i]` counts observations at most `bounds[i]`.
    le: Vec<u64>,
    sum: f64,
    count: u64,
}

impl Histogram {
    fn observe(&mut self, bounds: &[f64], v: f64) {
        if self.le.len() != bounds.len() {
            self.le = vec![0; bounds.len()];
        }
        for (n, b) in self.le.iter_mut().zip(bounds) {
            if v <= *b {
                *n += 1;
            }
        }
        self.sum += v;
        self.count += 1;
    }
}

#[derive(Default)]
struct Inner {
    http: BTreeMap<(&'static str, &'static str, &'static str), u64>,
    http_seconds: BTreeMap<&'static str, Histogram>,
    runs: BTreeMap<(&'static str, &'static str), u64>,
    run_seconds: BTreeMap<&'static str, Histogram>,
    runs_active: BTreeMap<&'static str, i64>,
    refused: BTreeMap<String, u64>,
    events: BTreeMap<(&'static str, &'static str), u64>,
    reconciles: u64,
    reconcile_last: Option<(i64, f64)>,
}

/// One per database, so each test's app counts on its own.
#[derive(Default)]
pub struct Metrics(Mutex<Inner>);

/// `v` if it's in `list`, as the list's own `&'static str`; else `other`.
pub fn known(list: &[&'static str], v: &str) -> &'static str {
    list.iter().find(|x| **x == v).copied().unwrap_or("other")
}

pub fn harness(name: &str) -> &'static str {
    known(&crate::adapters::NAMES, name)
}

pub fn method(m: &str) -> &'static str {
    known(&METHODS, m)
}

pub fn status_class(code: u16) -> &'static str {
    match code {
        100..=199 => "1xx",
        200..=299 => "2xx",
        300..=399 => "3xx",
        400..=499 => "4xx",
        _ => "5xx",
    }
}

/// A reason as botd's code spells them (`storage_limit`), or `other`.
fn reason(r: &str) -> String {
    let ok = !r.is_empty() && r.len() <= 40 && r.bytes().all(|b| b.is_ascii_lowercase() || b == b'_');
    if ok { r.to_string() } else { "other".into() }
}

/// Takes one off a harness's active runs when dropped, however the run ends.
pub struct Active<'a> {
    m: &'a Metrics,
    harness: &'static str,
}

impl Drop for Active<'_> {
    fn drop(&mut self) {
        *self.m.lock().runs_active.entry(self.harness).or_default() -= 1;
    }
}

impl Metrics {
    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.0.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn request(&self, class: &'static str, method: &'static str, code: u16, seconds: f64) {
        let mut m = self.lock();
        *m.http.entry((class, method, status_class(code))).or_default() += 1;
        m.http_seconds.entry(class).or_default().observe(&HTTP_BUCKETS, seconds);
    }

    pub fn run_started(&self, harness_name: &str) -> Active<'_> {
        let h = harness(harness_name);
        *self.lock().runs_active.entry(h).or_default() += 1;
        Active { m: self, harness: h }
    }

    pub fn run_finished(&self, harness_name: &str, result: &str, seconds: f64) {
        let (h, r) = (harness(harness_name), known(&RUN_RESULTS, result));
        let mut m = self.lock();
        *m.runs.entry((h, r)).or_default() += 1;
        m.run_seconds.entry(h).or_default().observe(&RUN_BUCKETS, seconds);
    }

    /// An audit event as `Db::record` writes it: counted if its action is in `EVENTS`.
    pub fn audited(&self, action: &str, outcome: &str, refusal: Option<&str>) {
        let a = known(&EVENTS, action);
        if a == "other" {
            return;
        }
        let mut m = self.lock();
        *m.events.entry((a, known(&OUTCOMES, outcome))).or_default() += 1;
        if action == "bot.run_refused" {
            let mut r = reason(refusal.unwrap_or(""));
            if !m.refused.contains_key(&r) && m.refused.len() >= MAX_REASONS {
                r = "other".into();
            }
            *m.refused.entry(r).or_default() += 1;
        }
    }

    pub fn reconciled(&self, at_ms: i64, seconds: f64) {
        let mut m = self.lock();
        m.reconciles += 1;
        m.reconcile_last = Some((at_ms, seconds));
    }

    /// The counters, histograms and in-process gauges, in the text format.
    pub fn render(&self, out: &mut String) {
        let m = self.lock();
        family(out, "superbot_http_requests_total", "counter", "HTTP requests botd answered, by route class, method and status class.");
        for ((class, method, status), n) in &m.http {
            sample(out, "superbot_http_requests_total", &[("route_class", class), ("method", method), ("status_class", status)], *n as f64);
        }
        family(out, "superbot_http_request_duration_seconds", "histogram", "Time to answer a request (to the first byte of a stream), by route class.");
        for (class, h) in &m.http_seconds {
            histogram(out, "superbot_http_request_duration_seconds", &[("route_class", class)], &HTTP_BUCKETS, h);
        }
        family(out, "superbot_runs_total", "counter", "Bot runs that finished, by harness and result.");
        for ((harness, result), n) in &m.runs {
            sample(out, "superbot_runs_total", &[("harness", harness), ("result", result)], *n as f64);
        }
        family(out, "superbot_run_duration_seconds", "histogram", "How long finished Bot runs took, by harness.");
        for (harness, h) in &m.run_seconds {
            histogram(out, "superbot_run_duration_seconds", &[("harness", harness)], &RUN_BUCKETS, h);
        }
        family(out, "superbot_runs_active", "gauge", "Bot runs underway now, by harness.");
        for (harness, n) in &m.runs_active {
            sample(out, "superbot_runs_active", &[("harness", harness)], *n as f64);
        }
        family(out, "superbot_runs_refused_total", "counter", "Bot runs refused before they started, by reason.");
        for (r, n) in &m.refused {
            sample(out, "superbot_runs_refused_total", &[("reason", r)], *n as f64);
        }
        family(out, "superbot_events_total", "counter", "Audit events an operator may alert on, by action and outcome.");
        for ((a, o), n) in &m.events {
            sample(out, "superbot_events_total", &[("event", a), ("outcome", o)], *n as f64);
        }
        family(out, "superbot_machine_reconcile_passes_total", "counter", "Passes of the machine reconciler.");
        sample(out, "superbot_machine_reconcile_passes_total", &[], m.reconciles as f64);
        if let Some((at, took)) = m.reconcile_last {
            family(out, "superbot_machine_reconcile_last_pass_timestamp_seconds", "gauge", "When the machine reconciler last finished a pass.");
            sample(out, "superbot_machine_reconcile_last_pass_timestamp_seconds", &[], at as f64 / 1000.0);
            family(out, "superbot_machine_reconcile_last_pass_duration_seconds", "gauge", "How long the machine reconciler's last pass took.");
            sample(out, "superbot_machine_reconcile_last_pass_duration_seconds", &[], took);
        }
    }
}

pub fn family(out: &mut String, name: &str, kind: &str, help: &str) {
    let _ = writeln!(out, "# HELP {name} {help}");
    let _ = writeln!(out, "# TYPE {name} {kind}");
}

/// Label values are escaped as the format requires, though every value botd uses is
/// plain: they come from the fixed lists above.
pub fn sample(out: &mut String, name: &str, labels: &[(&str, &str)], v: f64) {
    out.push_str(name);
    if !labels.is_empty() {
        out.push('{');
        for (i, (k, val)) in labels.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            let val = val.replace('\\', "\\\\").replace('"', "\\\"").replace('\n', "\\n");
            let _ = write!(out, "{k}=\"{val}\"");
        }
        out.push('}');
    }
    let _ = writeln!(out, " {}", number(v));
}

fn number(v: f64) -> String {
    if v.is_infinite() {
        return if v > 0.0 { "+Inf".into() } else { "-Inf".into() };
    }
    if v.fract() == 0.0 && v.abs() < 1e15 { format!("{}", v as i64) } else { format!("{v}") }
}

fn histogram(out: &mut String, name: &str, labels: &[(&str, &str)], bounds: &[f64], h: &Histogram) {
    let bucket = format!("{name}_bucket");
    for (b, n) in bounds.iter().zip(&h.le) {
        let le = number(*b);
        let mut l = labels.to_vec();
        l.push(("le", &le));
        sample(out, &bucket, &l, *n as f64);
    }
    let mut l = labels.to_vec();
    l.push(("le", "+Inf"));
    sample(out, &bucket, &l, h.count as f64);
    sample(out, &format!("{name}_sum"), labels, h.sum);
    sample(out, &format!("{name}_count"), labels, h.count as f64);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn labels_come_only_from_fixed_lists() {
        let m = Metrics::default();
        m.request("bots", method("BREW"), 418, 0.02);
        m.run_finished("someone@example.com", "it broke: secret", 3.0);
        drop(m.run_started("../../etc/passwd"));
        m.audited("auth.login_failed", "failure", None);
        m.audited("user.email_changed", "success", None);
        m.audited("bot.run_refused", "denied", Some("Alex's key sk-live-123"));
        let mut out = String::new();
        m.render(&mut out);
        assert!(out.contains(r#"superbot_http_requests_total{route_class="bots",method="other",status_class="4xx"} 1"#), "{out}");
        assert!(out.contains(r#"superbot_runs_total{harness="other",result="other"} 1"#), "{out}");
        assert!(out.contains(r#"superbot_runs_active{harness="other"} 0"#), "{out}");
        assert!(out.contains(r#"superbot_events_total{event="auth.login_failed",outcome="failure"} 1"#), "{out}");
        assert!(out.contains(r#"superbot_runs_refused_total{reason="other"} 1"#), "{out}");
        for bad in ["BREW", "example.com", "secret", "passwd", "email_changed", "sk-live", "Alex"] {
            assert!(!out.contains(bad), "{bad} leaked into: {out}");
        }
    }

    #[test]
    fn refusal_reasons_are_capped() {
        let m = Metrics::default();
        for i in 0..(MAX_REASONS + 10) {
            let r: String = std::iter::repeat_n('a', i + 1).collect();
            m.audited("bot.run_refused", "denied", Some(&r));
        }
        assert!(m.lock().refused.len() <= MAX_REASONS + 1);
        assert!(m.lock().refused.get("other").is_some_and(|n| *n >= 10));
    }

    #[test]
    fn histograms_are_cumulative_and_end_in_inf() {
        let m = Metrics::default();
        m.run_finished("claude", "done", 2.0);
        m.run_finished("claude", "error", 4000.0);
        let mut out = String::new();
        m.render(&mut out);
        assert!(out.contains(r#"superbot_run_duration_seconds_bucket{harness="claude",le="1"} 0"#), "{out}");
        assert!(out.contains(r#"superbot_run_duration_seconds_bucket{harness="claude",le="5"} 1"#), "{out}");
        assert!(out.contains(r#"superbot_run_duration_seconds_bucket{harness="claude",le="3600"} 1"#), "{out}");
        assert!(out.contains(r#"superbot_run_duration_seconds_bucket{harness="claude",le="+Inf"} 2"#), "{out}");
        assert!(out.contains(r#"superbot_run_duration_seconds_count{harness="claude"} 2"#), "{out}");
        assert!(out.contains(r#"superbot_run_duration_seconds_sum{harness="claude"} 4002"#), "{out}");
    }
}
