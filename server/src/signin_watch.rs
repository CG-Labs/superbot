//! Suspicious sign-in patterns (ADR 0104): a burst of failed sign-ins from one IP or
//! against one account, a sign-in that works right after such a burst, and an admin
//! signing in from a network none of their kept sessions came from. Each detection is
//! an `auth.suspicious_sign_in` audit event and a count in the opt-in metrics; the ones
//! about one account also go to the admins' alert channels.
//!
//! Counts live in memory, keyed by IP and user id, and are forgotten once they fall out
//! of the window or botd restarts. Nothing new is stored: the new-network check reads
//! the sessions botd already keeps (and prunes 30 days after they end).

use crate::audit::{Actor, Outcome, Source, Who};
use crate::db::{self, User};
use crate::rbac::Role;
use crate::{users, Auth};
use serde_json::json;
use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::Mutex;

pub const ACTION: &str = "auth.suspicious_sign_in";
/// What a detection can be, as `superbot_signin_suspicious_total` labels it.
pub const PATTERNS: [&str; 4] = ["ip_failures", "account_failures", "success_after_failures", "new_ip"];
/// Failed sign-ins that guess a credential, as `superbot_signin_failures_total` labels them.
/// Expired sessions, Bot and SCIM tokens, and IdP errors aren't guesses.
pub const METHODS: [&str; 4] = ["password", "code", "totp", "recovery_code"];

const MINUTE: i64 = 60_000;
const MAX_WINDOW_MS: i64 = 24 * 60 * MINUTE;
const MAX_TRACKED: usize = 10_000;
/// Earlier sessions' IPs the new-network check compares against.
const MAX_IPS_COMPARED: u32 = 500;
/// Detections written to the audit log per minute, over every IP and account. The rest
/// are still counted in the metrics, and the next one written says how many weren't.
const MAX_EVENTS_PER_MINUTE: u32 = 60;
/// Email and webhook alerts per minute, kept apart from the audit budget so bursts from
/// many IPs can't use it up.
const MAX_ALERTS_PER_MINUTE: u32 = 10;

/// Whose sign-ins from a new network are reported.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NewIp {
    Off,
    /// Admins, which includes the owner account.
    Admins,
    All,
}

impl NewIp {
    fn as_str(self) -> &'static str {
        match self {
            NewIp::Off => "no one",
            NewIp::Admins => "admins",
            NewIp::All => "everyone",
        }
    }

    fn covers(self, u: &User) -> bool {
        match self {
            NewIp::Off => false,
            NewIp::Admins => u.role == Role::Admin || u.id == users::OPERATOR,
            NewIp::All => true,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Settings {
    /// SIGNIN_ALERTS: on unless `off`.
    pub enabled: bool,
    /// SIGNIN_ALERT_IP_FAILURES: failed guesses from one IP within the window.
    pub ip_failures: u32,
    /// SIGNIN_ALERT_ACCOUNT_FAILURES: failed guesses at one account, from any IP.
    pub person_failures: u32,
    /// SIGNIN_ALERT_WINDOW.
    pub window_ms: i64,
    /// SIGNIN_ALERT_NEW_IP.
    pub new_ip: NewIp,
}

impl Default for Settings {
    fn default() -> Self {
        Settings { enabled: true, ip_failures: 10, person_failures: 5, window_ms: 15 * MINUTE, new_ip: NewIp::Admins }
    }
}

impl Settings {
    pub fn from_env(var: &dyn Fn(&str) -> String) -> Result<Settings, String> {
        let d = Settings::default();
        let raw = var("SIGNIN_ALERTS");
        let enabled = match raw.trim().to_ascii_lowercase().as_str() {
            "" | "on" | "1" | "true" | "yes" => true,
            "off" | "0" | "false" | "no" => false,
            _ => return Err(format!("SIGNIN_ALERTS must be on or off, not \"{raw}\"")),
        };
        let count = |key: &str, default: u32| -> Result<u32, String> {
            let raw = var(key);
            let raw = raw.trim();
            if raw.is_empty() {
                return Ok(default);
            }
            raw.parse::<u32>().ok().filter(|n| (2..=1000).contains(n)).ok_or_else(|| format!("{key} must be a number from 2 to 1000, not \"{raw}\""))
        };
        let window_ms = users::parse_duration("SIGNIN_ALERT_WINDOW", &var("SIGNIN_ALERT_WINDOW"), d.window_ms)?;
        if window_ms > MAX_WINDOW_MS {
            return Err("SIGNIN_ALERT_WINDOW must be at most 24h".into());
        }
        let raw = var("SIGNIN_ALERT_NEW_IP");
        let new_ip = match raw.trim().to_ascii_lowercase().as_str() {
            "" | "admins" | "admin" => NewIp::Admins,
            "all" | "everyone" => NewIp::All,
            "off" | "none" => NewIp::Off,
            _ => return Err(format!("SIGNIN_ALERT_NEW_IP must be admins, all, or off, not \"{raw}\"")),
        };
        Ok(Settings {
            enabled,
            ip_failures: count("SIGNIN_ALERT_IP_FAILURES", d.ip_failures)?,
            person_failures: count("SIGNIN_ALERT_ACCOUNT_FAILURES", d.person_failures)?,
            window_ms,
            new_ip,
        })
    }

    pub fn describe(&self) -> String {
        if !self.enabled {
            return "off (SIGNIN_ALERTS=off)".into();
        }
        format!(
            "on: {} failed sign-ins from one IP or {} at one account within {} minutes; sign-ins from a new network reported for {}",
            self.ip_failures,
            self.person_failures,
            self.window_ms / MINUTE,
            self.new_ip.as_str()
        )
    }
}

/// One key's recent failures (at most its limit, oldest first), when it last alerted,
/// and when it last reached its limit with no sign-in reported since.
#[derive(Default)]
struct Track {
    fails: VecDeque<i64>,
    alerted_at: Option<i64>,
    burst_at: Option<i64>,
}

impl Track {
    fn recent(&mut self, at: i64, window: i64) -> usize {
        while self.fails.front().is_some_and(|t| at - t >= window) {
            self.fails.pop_front();
        }
        self.fails.len()
    }

    fn last(&self) -> i64 {
        self.fails.back().copied().into_iter().chain(self.alerted_at).chain(self.burst_at).max().unwrap_or(i64::MIN)
    }

    fn live(&self, at: i64, window: i64) -> bool {
        at - self.last() < window
    }

    fn bursting(&self, at: i64, window: i64) -> bool {
        self.burst_at.is_some_and(|b| at - b < window)
    }
}

#[derive(Default)]
struct State {
    ips: HashMap<String, Track>,
    accounts: HashMap<String, Track>,
    /// The current minute's start, and detections written in it.
    minute: (i64, u32),
    unrecorded: u64,
    /// The current minute's start, and alerts sent in it.
    alerts: (i64, u32),
    swept_at: i64,
}

impl State {
    /// Forgets keys whose window has passed, at most once a minute.
    fn sweep(&mut self, at: i64, window: i64) {
        if at - self.swept_at < MINUTE {
            return;
        }
        self.swept_at = at;
        self.ips.retain(|_, t| t.live(at, window));
        self.accounts.retain(|_, t| t.live(at, window));
    }
}

fn track<'a>(m: &'a mut HashMap<String, Track>, key: &str, at: i64, window: i64) -> &'a mut Track {
    if !m.contains_key(key) && m.len() >= MAX_TRACKED {
        m.retain(|_, t| t.live(at, window));
        // Still full of live keys: drop the tenth least recently seen, keeping bursts.
        if m.len() >= MAX_TRACKED {
            let mut by_age: Vec<(bool, i64, String)> = m.iter().map(|(k, t)| (t.bursting(at, window), t.last(), k.clone())).collect();
            by_age.sort_unstable();
            for (_, _, k) in by_age.into_iter().take(MAX_TRACKED / 10) {
                m.remove(&k);
            }
        }
    }
    m.entry(key.to_string()).or_default()
}

/// What was seen, and the failures that made it (none for a new network).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Detection {
    pub pattern: &'static str,
    /// `ip` or `account`: what the failures were counted by.
    pub scope: &'static str,
    pub failures: usize,
}

pub struct Watch {
    pub settings: Settings,
    state: Mutex<State>,
}

impl Default for Watch {
    fn default() -> Self {
        Watch::new(Settings::default())
    }
}

impl Watch {
    pub fn new(settings: Settings) -> Watch {
        Watch { settings, state: Mutex::default() }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// A failed guess from `ip` at `account` (when the account is known). A key that
    /// reaches its limit within the window is reported once per window, so a burst that
    /// goes on is reported again each window it lasts.
    pub fn failed(&self, ip: Option<&str>, account: Option<&str>, at: i64) -> Vec<Detection> {
        let s = self.settings;
        if !s.enabled {
            return Vec::new();
        }
        let mut st = self.lock();
        st.sweep(at, s.window_ms);
        let mut out = Vec::new();
        for (scope, key, limit, pattern) in [("ip", ip, s.ip_failures, "ip_failures"), ("account", account, s.person_failures, "account_failures")] {
            let Some(key) = key.filter(|k| !k.is_empty()) else { continue };
            let map = if scope == "ip" { &mut st.ips } else { &mut st.accounts };
            let t = track(map, key, at, s.window_ms);
            t.fails.push_back(at);
            let n = t.recent(at, s.window_ms);
            while t.fails.len() > limit as usize {
                t.fails.pop_front();
            }
            if n >= limit as usize {
                t.burst_at = Some(at);
            }
            if n >= limit as usize && t.alerted_at.is_none_or(|a| at - a >= s.window_ms) {
                t.alerted_at = Some(at);
                out.push(Detection { pattern, scope, failures: n });
            }
        }
        out
    }

    /// A sign-in that worked, from `ip` to `account`: reported when either reached its
    /// limit within the last window, even if some of those failures have aged out since.
    /// That key's count then starts over, so the next sign-in isn't reported again.
    pub fn succeeded(&self, ip: Option<&str>, account: &str, at: i64) -> Option<Detection> {
        let s = self.settings;
        if !s.enabled {
            return None;
        }
        let mut st = self.lock();
        st.sweep(at, s.window_ms);
        let mut found = None;
        for (scope, key, limit) in [("account", Some(account), s.person_failures), ("ip", ip, s.ip_failures)] {
            let Some(key) = key.filter(|k| !k.is_empty()) else { continue };
            let map = if scope == "ip" { &mut st.ips } else { &mut st.accounts };
            let Some(t) = map.get_mut(key) else { continue };
            let n = t.recent(at, s.window_ms);
            if n >= limit as usize || t.bursting(at, s.window_ms) {
                t.fails.clear();
                t.burst_at = None;
                found = found.or(Some(Detection { pattern: "success_after_failures", scope, failures: n.max(limit as usize) }));
            }
        }
        found
    }

    /// Whether a detection goes to the audit log now, with how many weren't since the
    /// last that did.
    fn budget(&self, at: i64) -> Option<u64> {
        let mut st = self.lock();
        if at - st.minute.0 >= MINUTE {
            st.minute = (at, 0);
        }
        if st.minute.1 >= MAX_EVENTS_PER_MINUTE {
            st.unrecorded += 1;
            return None;
        }
        st.minute.1 += 1;
        Some(std::mem::take(&mut st.unrecorded))
    }

    /// Whether an email and webhook alert may go now.
    fn alert_budget(&self, at: i64) -> bool {
        let mut st = self.lock();
        if at - st.alerts.0 >= MINUTE {
            st.alerts = (at, 0);
        }
        st.alerts.1 += 1;
        st.alerts.1 <= MAX_ALERTS_PER_MINUTE
    }

    /// Forgets IPs and accounts whose window has passed, so a quiet server doesn't keep them.
    pub fn sweep(&self, at: i64) {
        self.lock().sweep(at, self.settings.window_ms);
    }
}

/// Two addresses on the same network: the same /24 for IPv4, the same /64 for IPv6,
/// so a home router's or phone's address changing within its range isn't news.
pub fn same_network(a: &str, b: &str) -> bool {
    match (a.parse::<IpAddr>().map(|i| i.to_canonical()), b.parse::<IpAddr>().map(|i| i.to_canonical())) {
        (Ok(IpAddr::V4(a)), Ok(IpAddr::V4(b))) => a.octets()[..3] == b.octets()[..3],
        (Ok(IpAddr::V6(a)), Ok(IpAddr::V6(b))) => a.segments()[..4] == b.segments()[..4],
        _ => a == b,
    }
}

/// Whether `user` signing in from `source` now would be from a network none of their
/// kept sessions came from. Call it before the new session is saved. False for a first
/// sign-in, which has nothing to compare against.
pub fn new_network(a: &Auth, user: &User, source: &Source) -> bool {
    let s = a.watch.settings;
    let (Some(app), Some(ip)) = (&a.app, source.ip.as_deref()) else { return false };
    if !s.enabled || !s.new_ip.covers(user) {
        return false;
    }
    let before = app.db.session_ips(&user.id, MAX_IPS_COMPARED);
    !before.is_empty() && !before.iter().any(|p| same_network(p, ip))
}

/// A failed sign-in. Counted when `method` guesses a credential; `account` is the user it
/// was for, when botd knows (the owner for the break-glass password, the person whose
/// second factor was wrong).
pub fn failed(a: &Auth, source: &Source, method: &str, account: Option<&str>) {
    if !METHODS.contains(&method) {
        return;
    }
    if let Some(app) = &a.app {
        app.db.metrics().signin_failed(method);
    }
    for d in a.watch.failed(source.ip.as_deref(), account, db::now()) {
        report(a, source, d, method, (d.scope == "account").then_some(account).flatten(), None);
    }
}

/// A sign-in that worked. `new_network` is what `new_network` said before the session
/// was saved; `session` is its id, when there is one.
pub fn succeeded(a: &Auth, source: &Source, user_id: &str, method: &str, new_network: bool, session: Option<&str>) {
    if let Some(d) = a.watch.succeeded(source.ip.as_deref(), user_id, db::now()) {
        report(a, source, d, method, Some(user_id), session);
    }
    if new_network {
        report(a, source, Detection { pattern: "new_ip", scope: "account", failures: 0 }, method, Some(user_id), session);
    }
}

fn report(a: &Auth, source: &Source, d: Detection, method: &str, account: Option<&str>, session: Option<&str>) {
    let Some(app) = &a.app else { return };
    app.db.metrics().signin_suspicious(d.pattern);
    let s = a.watch.settings;
    let at = db::now();
    if let Some(unrecorded) = a.watch.budget(at) {
        record(app, source, d, method, account, session, unrecorded, s);
    }
    // Bursts from one IP are the internet's background noise; these point at one person.
    if let (true, Some(id)) = (matches!(d.pattern, "account_failures" | "success_after_failures"), account) {
        if !a.watch.alert_budget(at) {
            return;
        }
        let name = app.db.user(id).map(|u| u.email.unwrap_or(u.name)).unwrap_or_else(|| id.to_string());
        let title = match d.pattern {
            "account_failures" => format!("{} failed sign-in attempts at {name}'s account", d.failures),
            _ => format!("{name} signed in right after {} failed attempts", d.failures),
        };
        let lines = vec![
            format!("Method: {method}. Counted by {} over the last {} minutes.", if d.scope == "ip" { "source IP" } else { "account" }, s.window_ms / MINUTE),
            "The source IP and every attempt are in the audit log (auth.suspicious_sign_in, auth.login_failed).".into(),
        ];
        crate::notify::alert(app, crate::notify::Alert { event: ACTION.into(), title, lines, target_type: "user".into(), target_id: id.into(), link: None }, "audit");
    }
}

#[allow(clippy::too_many_arguments)]
fn record(app: &crate::AppState, source: &Source, d: Detection, method: &str, account: Option<&str>, session: Option<&str>, unrecorded: u64, s: Settings) {
    let mut details = json!({ "pattern": d.pattern, "scope": d.scope, "method": method });
    if d.failures > 0 {
        details["failures"] = json!(d.failures);
        details["threshold"] = json!(if d.scope == "ip" { s.ip_failures } else { s.person_failures });
        details["windowSeconds"] = json!(s.window_ms / 1000);
    }
    if let Some(id) = session {
        details["session"] = json!(id);
    }
    if unrecorded > 0 {
        details["unrecordedSinceLast"] = json!(unrecorded);
    }
    let failure = matches!(d.pattern, "ip_failures" | "account_failures");
    let who = Who { actor: Actor::system("signin_watch"), source: source.clone() };
    let mut e = who.event(ACTION).outcome(if failure { Outcome::Failure } else { Outcome::Success }).details(details);
    if let Some(u) = account {
        e = e.target("user", u);
    }
    app.db.record(&e);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn watch(ip: u32, account: u32) -> Watch {
        Watch::new(Settings { ip_failures: ip, person_failures: account, ..Settings::default() })
    }

    #[test]
    fn settings_default_on_and_check_their_values() {
        let none = |_: &str| String::new();
        assert_eq!(Settings::from_env(&none).unwrap(), Settings::default());
        let set = |k: &str| {
            match k {
                "SIGNIN_ALERTS" => "on",
                "SIGNIN_ALERT_IP_FAILURES" => "25",
                "SIGNIN_ALERT_ACCOUNT_FAILURES" => "3",
                "SIGNIN_ALERT_WINDOW" => "1h",
                "SIGNIN_ALERT_NEW_IP" => "all",
                _ => "",
            }
            .to_string()
        };
        assert_eq!(Settings::from_env(&set).unwrap(), Settings { enabled: true, ip_failures: 25, person_failures: 3, window_ms: 60 * MINUTE, new_ip: NewIp::All });
        let off = |k: &str| if k == "SIGNIN_ALERTS" { "off".into() } else { String::new() };
        assert!(!Settings::from_env(&off).unwrap().enabled);
        for (k, v) in [("SIGNIN_ALERTS", "maybe"), ("SIGNIN_ALERT_IP_FAILURES", "1"), ("SIGNIN_ALERT_ACCOUNT_FAILURES", "lots"), ("SIGNIN_ALERT_WINDOW", "2d"), ("SIGNIN_ALERT_WINDOW", "1m"), ("SIGNIN_ALERT_NEW_IP", "bots")] {
            let bad = |key: &str| if key == k { v.to_string() } else { String::new() };
            let e = Settings::from_env(&bad).unwrap_err();
            assert!(e.contains(k), "{k}={v}: {e}");
        }
    }

    #[test]
    fn a_burst_from_one_ip_is_reported_once_per_window() {
        let w = watch(3, 100);
        let t = 1_000_000;
        assert!(w.failed(Some("203.0.113.9"), None, t).is_empty());
        assert!(w.failed(Some("203.0.113.9"), None, t + 1).is_empty());
        assert_eq!(w.failed(Some("203.0.113.9"), None, t + 2), [Detection { pattern: "ip_failures", scope: "ip", failures: 3 }]);
        // Another IP has its own count.
        assert!(w.failed(Some("198.51.100.1"), None, t + 3).is_empty());
        // More in the same window aren't reported again.
        for i in 0..10 {
            assert!(w.failed(Some("203.0.113.9"), None, t + 10 + i).is_empty());
        }
        // A burst that goes on is reported again a window later.
        let later = t + 2 + w.settings.window_ms;
        assert_eq!(w.failed(Some("203.0.113.9"), None, later).len(), 1);
        // Failures spread wider than the window never add up.
        let w = watch(3, 100);
        for i in 0..10 {
            assert!(w.failed(Some("203.0.113.9"), None, t + i * w.settings.window_ms / 2).is_empty());
        }
    }

    #[test]
    fn one_account_is_counted_across_ips() {
        let w = watch(100, 3);
        let t = 1_000_000;
        assert!(w.failed(Some("203.0.113.1"), Some("u1"), t).is_empty());
        assert!(w.failed(Some("198.51.100.2"), Some("u1"), t + 1).is_empty());
        assert!(w.failed(Some("192.0.2.3"), Some("u2"), t + 1).is_empty());
        assert_eq!(w.failed(Some("192.0.2.4"), Some("u1"), t + 2), [Detection { pattern: "account_failures", scope: "account", failures: 3 }]);
        assert!(w.failed(None, Some(""), t + 3).is_empty(), "no key, nothing counted");
    }

    #[test]
    fn a_sign_in_after_a_burst_is_reported_once() {
        let w = watch(3, 100);
        let t = 1_000_000;
        assert_eq!(w.succeeded(Some("203.0.113.9"), "u1", t), None);
        for i in 0..2 {
            w.failed(Some("203.0.113.9"), None, t + i);
        }
        assert_eq!(w.succeeded(Some("203.0.113.9"), "u1", t + 5), None, "under the limit");
        w.failed(Some("203.0.113.9"), None, t + 6);
        assert_eq!(w.succeeded(Some("203.0.113.9"), "u1", t + 7), Some(Detection { pattern: "success_after_failures", scope: "ip", failures: 3 }));
        assert_eq!(w.succeeded(Some("203.0.113.9"), "u1", t + 8), None);
        // Once the window has passed, a sign-in is just a sign-in.
        let w = watch(3, 2);
        w.failed(Some("203.0.113.9"), Some("u1"), t);
        w.failed(Some("198.51.100.2"), Some("u1"), t);
        assert_eq!(w.succeeded(Some("192.0.2.1"), "u1", t + w.settings.window_ms), None);
    }

    #[test]
    fn a_sign_in_soon_after_a_burst_is_reported_though_its_first_failures_aged_out() {
        let w = watch(100, 5);
        let t = 1_000_000;
        for i in 0..5 {
            w.failed(Some("203.0.113.9"), Some("u1"), t + i * MINUTE);
        }
        // Minute 15: the first failure has left the window, but the limit was reached at minute 4.
        let d = w.succeeded(Some("192.0.2.1"), "u1", t + 15 * MINUTE + 1);
        assert_eq!(d, Some(Detection { pattern: "success_after_failures", scope: "account", failures: 5 }));
        assert_eq!(w.succeeded(Some("192.0.2.1"), "u1", t + 15 * MINUTE + 2), None, "reported once");
    }

    #[test]
    fn expired_keys_are_swept_without_waiting_for_the_map_to_fill() {
        let w = watch(5, 5);
        let t = 1_000_000;
        w.failed(Some("203.0.113.9"), Some("u1"), t);
        let sizes = |w: &Watch| {
            let st = w.lock();
            (st.ips.len(), st.accounts.len())
        };
        w.sweep(t + w.settings.window_ms - 1);
        assert_eq!(sizes(&w), (1, 1));
        w.sweep(t + w.settings.window_ms + MINUTE);
        assert_eq!(sizes(&w), (0, 0));
    }

    #[test]
    fn a_full_map_keeps_live_bursts() {
        let w = watch(3, 100);
        let t = 1_000_000;
        for i in 0..3 {
            w.failed(Some("203.0.113.9"), None, t + i);
        }
        for i in 0..(MAX_TRACKED as i64 + 50) {
            w.failed(Some(&format!("ip{i}")), None, t + 10);
        }
        assert!(w.lock().ips.len() <= MAX_TRACKED);
        assert_eq!(w.succeeded(Some("203.0.113.9"), "u1", t + 20).map(|d| d.pattern), Some("success_after_failures"));
    }

    #[test]
    fn alerts_have_their_own_budget() {
        let w = Watch::default();
        let t = 1_000_000;
        for _ in 0..MAX_EVENTS_PER_MINUTE {
            w.budget(t);
        }
        assert_eq!(w.budget(t), None);
        for _ in 0..MAX_ALERTS_PER_MINUTE {
            assert!(w.alert_budget(t));
        }
        assert!(!w.alert_budget(t));
        assert!(w.alert_budget(t + MINUTE));
    }

    #[test]
    fn off_sees_nothing() {
        let w = Watch::new(Settings { enabled: false, ip_failures: 2, person_failures: 2, ..Settings::default() });
        for i in 0..10 {
            assert!(w.failed(Some("203.0.113.9"), Some("u1"), i).is_empty());
        }
        assert_eq!(w.succeeded(Some("203.0.113.9"), "u1", 11), None);
    }

    #[test]
    fn tracking_stays_bounded() {
        let w = watch(5, 5);
        for i in 0..(MAX_TRACKED as i64 + 50) {
            w.failed(Some(&format!("ip{i}")), Some(&format!("u{i}")), 1_000_000);
        }
        let st = w.lock();
        assert!(st.ips.len() <= MAX_TRACKED && st.accounts.len() <= MAX_TRACKED);
        assert!(st.ips.values().all(|t| t.fails.len() <= 5));
    }

    #[test]
    fn the_audit_budget_caps_a_minute_and_counts_the_rest() {
        let w = Watch::default();
        let t = 1_000_000;
        for _ in 0..MAX_EVENTS_PER_MINUTE {
            assert_eq!(w.budget(t), Some(0));
        }
        assert_eq!(w.budget(t + 1), None);
        assert_eq!(w.budget(t + 2), None);
        assert_eq!(w.budget(t + MINUTE), Some(2));
    }

    #[test]
    fn networks_are_compared_by_prefix() {
        assert!(same_network("203.0.113.9", "203.0.113.200"));
        assert!(!same_network("203.0.113.9", "203.0.114.9"));
        assert!(same_network("2001:db8:1:2::1", "2001:db8:1:2:aaaa::9"));
        assert!(!same_network("2001:db8:1:2::1", "2001:db8:1:3::1"));
        assert!(same_network("::ffff:203.0.113.9", "203.0.113.1"));
        assert!(!same_network("203.0.113.9", "2001:db8::1"));
    }
}
