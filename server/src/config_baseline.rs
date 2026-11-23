//! The configuration baseline, checked by botd itself (ADR 0193): every setting in
//! `docs/security/configuration-baseline.md` has a rule here that judges botd's effective
//! value, as it parsed it at startup and as it stands in the database now. Each rule
//! passes, fails, is waived by an approved exception (`CONFIG_BASELINE_EXCEPTIONS`), is
//! left for a person to check (botd can't see an image signature or a contract), or
//! doesn't apply to this server (no machines, say).
//!
//! `CONFIG_BASELINE=on` checks at every start, which follows every upgrade and every
//! change of settings, and audits it as `server.baseline_checked`; `required` also refuses
//! to start while a rule fails. `GET /api/baseline` (`botctl baseline`, admins) checks on
//! request, audited the same way, whatever the setting. The evidence bundle keeps the
//! check as of its making and every check in its period (`baseline.json`, ADR 0142).
//!
//! What a check shows is codes and numbers from a fixed vocabulary: never a value an
//! operator typed, a secret, a path or a host.

use crate::audit::{self, Actor, Event, Outcome, Who};
use crate::db::{AuditEvent, now};
use crate::machines::route::Routing;
use crate::mfa;
use crate::runner::App;
use crate::{AppState, Res};
use axum::Json;
use axum::extract::{Extension, State};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::sync::Arc;

pub const CHECKED: &str = "server.baseline_checked";
/// Bumped when the report's shape changes.
pub const FORMAT: u32 = 1;
const ACTOR: &str = "baseline";
/// The longest common Type II observation period (12 months) plus the year after it that
/// the audit log must outlive it by (the evidence plan's retention rule).
pub const AUDIT_DAYS_NEEDED: u32 = 730;

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub enum Mode {
    #[default]
    Off,
    On,
    Required,
}

impl Mode {
    pub fn as_str(self) -> &'static str {
        match self {
            Mode::Off => "off",
            Mode::On => "on",
            Mode::Required => "required",
        }
    }
}

/// `CONFIG_BASELINE` and `CONFIG_BASELINE_EXCEPTIONS`.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Settings {
    pub mode: Mode,
    /// Settings whose failure an approved exception waives, by name.
    pub exceptions: Vec<&'static str>,
}

impl Settings {
    pub fn from_env(var: &dyn Fn(&str) -> String) -> Result<Settings, String> {
        let mode = match var("CONFIG_BASELINE").trim().to_ascii_lowercase().as_str() {
            "" | "off" => Mode::Off,
            "on" => Mode::On,
            "required" => Mode::Required,
            other => {
                return Err(format!("CONFIG_BASELINE must be off, on or required, not \"{}\"", audit::clip(other, 20)));
            }
        };
        let mut exceptions = Vec::new();
        for name in var("CONFIG_BASELINE_EXCEPTIONS").split([',', ' ']).map(str::trim).filter(|s| !s.is_empty()) {
            let known = RULES
                .iter()
                .find(|r| r.setting.eq_ignore_ascii_case(name))
                .ok_or_else(|| format!("CONFIG_BASELINE_EXCEPTIONS: \"{}\" isn't a setting the baseline checks (docs/security/configuration-baseline.md)", audit::clip(name, 40)))?;
            if !exceptions.contains(&known.setting) {
                exceptions.push(known.setting);
            }
        }
        Ok(Settings { mode, exceptions })
    }
}

/// What botd parsed at startup and keeps nowhere else.
#[derive(Clone, Debug, Default)]
pub struct Startup {
    pub settings: Settings,
    /// AUTH_MFA, when set: the policy no admin can change in the app.
    pub mfa_pinned: Option<mfa::Policy>,
    pub break_glass: bool,
    pub signin_alerts: bool,
    pub testing: bool,
    pub chromium_sandbox: bool,
    /// METRICS_LISTEN, when on: whether on loopback, and whether METRICS_TOKEN is set.
    pub metrics: Option<(bool, bool)>,
    /// MACHINE_FIREWALL_EGRESS, as the control plane read it.
    pub firewall_egress: bool,
    pub evidence_monthly: bool,
}

/// The users' machines, when the control plane is on.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Machines {
    /// MACHINE_CONTROL_URL is set, so machines enroll and their agent applies the rest.
    pub enrolled: bool,
    pub hardening: bool,
    pub run_limits: bool,
    pub bot_user: bool,
    pub teammate_users: bool,
    pub firewall: bool,
    pub firewall_egress: bool,
    pub suspend_on_disable: bool,
    /// Off-host machine backups' age recipients, when those backups are on.
    pub backup_recipients: Option<usize>,
}

/// Everything the rules judge: plain values, so tests can build any server.
#[derive(Clone, Debug, Default)]
pub struct Facts {
    pub version: String,
    pub mfa: mfa::Policy,
    pub mfa_pinned: bool,
    pub break_glass: bool,
    pub signin_alerts: bool,
    pub testing: bool,
    pub database_encryption: Option<&'static str>,
    pub backup_encryption: Option<&'static str>,
    /// SERVER_BACKUP_OFF_HOST, and whether a store is set.
    pub off_host: Option<(&'static str, bool)>,
    pub machines: Option<Machines>,
    /// Some Bots run on this server (MACHINE_ROUTING isn't `on`).
    pub bots_run_here: bool,
    pub isolation: bool,
    pub teams: bool,
    pub chromium_sandbox: bool,
    pub metrics: Option<(bool, bool)>,
    pub audit_days: Option<u32>,
    pub chat_days: Option<u32>,
    pub sessions_days: Option<u32>,
    pub teammate_files_days: Option<u32>,
    pub evidence_monthly: bool,
    pub mode: Mode,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Status {
    Pass,
    Fail,
    /// Failing, under an approved exception.
    Exception,
    /// For a person to check: botd can't tell.
    Manual,
    NotApplicable,
}

impl Status {
    pub fn as_str(self) -> &'static str {
        match self {
            Status::Pass => "pass",
            Status::Fail => "fail",
            Status::Exception => "exception",
            Status::Manual => "manual",
            Status::NotApplicable => "not_applicable",
        }
    }
}

/// One row of the baseline's table: the setting, its baseline as the table says it, and
/// how botd judges it.
pub struct Rule {
    pub setting: &'static str,
    pub baseline: &'static str,
    judge: fn(&Facts) -> (Status, String),
}

use Status::{Fail, Manual, NotApplicable as Na, Pass};

fn on_off(b: bool) -> String {
    if b { "on".into() } else { "off".into() }
}

fn days(d: Option<u32>) -> String {
    d.map_or_else(|| "kept forever".into(), |d| format!("{d} days"))
}

/// A rule that is met when `b`.
fn flag(b: bool) -> (Status, String) {
    (if b { Pass } else { Fail }, on_off(b))
}

/// A machine rule: not applicable without enrolled machines.
fn machine(f: &Facts, get: fn(&Machines) -> bool) -> (Status, String) {
    match &f.machines {
        Some(m) if m.enrolled => flag(get(m)),
        Some(_) => (Na, "machines don't enroll (MACHINE_CONTROL_URL unset)".into()),
        None => (Na, "no machines (the control plane is off)".into()),
    }
}

fn policy(p: Option<&'static str>, want: &str) -> (Status, String) {
    match p {
        Some(p) => (if p == want { Pass } else { Fail }, p.into()),
        None => (Fail, "unknown".into()),
    }
}

/// The baseline, in the table's order. A test holds this to the table.
pub const RULES: [Rule; 26] = [
    Rule { setting: "SUPERBOT_VERSION", baseline: "A released, signed version, never a local build", judge: |f| (Manual, format!("botd {}; check its image's signature", f.version)) },
    Rule {
        setting: "AUTH_MFA",
        baseline: "admins or all",
        judge: |f| match (f.mfa, f.mfa_pinned) {
            (mfa::Policy::Off, _) => (Fail, "off".into()),
            (p, true) => (Pass, p.as_str().into()),
            (p, false) => (Fail, format!("{}, set in the app, not by AUTH_MFA, so an admin can turn it off", p.as_str())),
        },
    },
    Rule {
        setting: "AUTH_BREAK_GLASS",
        baseline: "0 once admins sign in with SSO or sign-in codes",
        judge: |f| {
            if f.break_glass { (Fail, "1: the owner's password signs in".into()) } else { (Pass, "0".into()) }
        },
    },
    Rule { setting: "SIGNIN_ALERTS", baseline: "on (the default)", judge: |f| flag(f.signin_alerts) },
    Rule {
        setting: "TESTING_MODE",
        baseline: "Unset",
        judge: |f| {
            if f.testing { (Fail, "on".into()) } else { (Pass, "off".into()) }
        },
    },
    Rule { setting: "SUPERBOT_DATABASE_ENCRYPTION", baseline: "required", judge: |f| policy(f.database_encryption, "required") },
    Rule { setting: "SUPERBOT_BACKUP_ENCRYPTION", baseline: "required", judge: |f| policy(f.backup_encryption, "required") },
    Rule {
        setting: "SERVER_BACKUP_OFF_HOST",
        baseline: "on, with a store set",
        judge: |f| match f.off_host {
            Some((mode, store)) => (if mode == "on" && store { Pass } else { Fail }, format!("{mode}, {}", if store { "with a store" } else { "no store" })),
            None => (Fail, "unknown".into()),
        },
    },
    Rule {
        setting: "MACHINE_BACKUP_AGE_RECIPIENTS",
        baseline: "Set, with the key kept off the host",
        judge: |f| match f.machines.as_ref().map(|m| m.backup_recipients) {
            Some(Some(0)) => (Fail, "unset: machines' backups are plain".into()),
            Some(Some(n)) => (Pass, format!("{n} recipients; the key's place is the operator's to check")),
            Some(None) => (Na, "machines' off-host backups are off".into()),
            None => (Na, "no machines (the control plane is off)".into()),
        },
    },
    Rule {
        setting: "ISOLATION",
        baseline: "users on a server where Bots run locally",
        judge: |f| match (f.bots_run_here, f.isolation) {
            (false, _) => (Na, "Bots run only on users' machines (MACHINE_ROUTING=on)".into()),
            (true, true) => (Pass, "users".into()),
            (true, false) => (Fail, "off".into()),
        },
    },
    Rule {
        setting: "TEAMS",
        baseline: "on when more than one customer shares a server",
        judge: |f| {
            if f.teams { (Pass, "on".into()) } else { (Manual, "off; botd can't tell whether more than one customer shares this server".into()) }
        },
    },
    Rule { setting: "MACHINE_HARDENING", baseline: "on (the default)", judge: |f| machine(f, |m| m.hardening) },
    Rule { setting: "MACHINE_RUN_LIMITS", baseline: "on (the default)", judge: |f| machine(f, |m| m.run_limits) },
    Rule { setting: "MACHINE_BOT_USER", baseline: "on (the default)", judge: |f| machine(f, |m| m.bot_user) },
    Rule { setting: "MACHINE_TEAMMATE_USERS", baseline: "on", judge: |f| machine(f, |m| m.teammate_users) },
    Rule {
        setting: "MACHINE_FIREWALL",
        baseline: "on for Linode machines",
        judge: |f| match &f.machines {
            Some(m) => flag(m.firewall),
            None => (Na, "no machines (the control plane is off)".into()),
        },
    },
    Rule {
        setting: "MACHINE_FIREWALL_EGRESS",
        baseline: "on (the default with the firewall)",
        judge: |f| match &f.machines {
            Some(m) if m.firewall => flag(m.firewall_egress),
            Some(_) => (Na, "no firewall (MACHINE_FIREWALL)".into()),
            None => (Na, "no machines (the control plane is off)".into()),
        },
    },
    Rule {
        setting: "MACHINE_ON_DISABLE",
        baseline: "suspend (the default)",
        judge: |f| match &f.machines {
            Some(m) if m.suspend_on_disable => (Pass, "suspend".into()),
            Some(_) => (Fail, "keep".into()),
            None => (Na, "no machines (the control plane is off)".into()),
        },
    },
    Rule { setting: "SUPERBOT_CHROMIUM_SANDBOX", baseline: "Unset (Chromium's sandbox on)", judge: |f| flag(f.chromium_sandbox) },
    Rule {
        setting: "METRICS_LISTEN",
        baseline: "Off, loopback, or with METRICS_TOKEN",
        judge: |f| match f.metrics {
            None => (Pass, "off".into()),
            Some((true, _)) => (Pass, "loopback".into()),
            Some((false, true)) => (Pass, "off loopback, with METRICS_TOKEN".into()),
            Some((false, false)) => (Fail, "off loopback, without METRICS_TOKEN".into()),
        },
    },
    Rule {
        setting: "AUDIT_RETENTION_DAYS",
        baseline: "Empty, or at least the observation period plus a year",
        judge: |f| match f.audit_days {
            Some(d) if d < AUDIT_DAYS_NEEDED => (Fail, format!("{d} days, under {AUDIT_DAYS_NEEDED}: a 12-month period plus a year")),
            d => (Pass, days(d)),
        },
    },
    Rule { setting: "CHAT_RETENTION_DAYS", baseline: "What the retention policy and customers' contracts say", judge: |f| (Manual, days(f.chat_days)) },
    Rule { setting: "HARNESS_SESSION_RETENTION_DAYS", baseline: "What the retention policy and customers' contracts say", judge: |f| (Manual, days(f.sessions_days)) },
    Rule { setting: "TEAMMATE_FILES_RETENTION_DAYS", baseline: "What the retention policy and customers' contracts say", judge: |f| (Manual, days(f.teammate_files_days)) },
    Rule {
        setting: "EVIDENCE_BUNDLES",
        baseline: "monthly",
        judge: |f| {
            if f.evidence_monthly { (Pass, "monthly".into()) } else { (Fail, "off".into()) }
        },
    },
    Rule {
        setting: "CONFIG_BASELINE",
        baseline: "on or required",
        judge: |f| match f.mode {
            Mode::Off => (Fail, "off: botd doesn't check itself at start".into()),
            m => (Pass, m.as_str().into()),
        },
    },
];

/// One rule's result.
#[derive(Clone, Debug, PartialEq)]
pub struct Check {
    pub setting: &'static str,
    pub baseline: &'static str,
    pub status: Status,
    pub observed: String,
}

#[derive(Clone, Debug)]
pub struct Report {
    pub checked_at: i64,
    pub version: String,
    pub mode: Mode,
    pub checks: Vec<Check>,
    /// Exceptions whose setting doesn't fail: due for removal.
    pub unused_exceptions: Vec<&'static str>,
    /// SHA-256 of each check's setting, status and observed value: the same settings give
    /// the same digest, whenever checked.
    pub digest: String,
}

impl Report {
    pub fn ok(&self) -> bool {
        !self.checks.iter().any(|c| c.status == Fail)
    }

    pub fn with(&self, s: Status) -> Vec<&'static str> {
        self.checks.iter().filter(|c| c.status == s).map(|c| c.setting).collect()
    }

    pub fn counts(&self) -> Value {
        let n = |s| self.checks.iter().filter(|c| c.status == s).count();
        json!({ "pass": n(Pass), "fail": n(Fail), "exception": n(Status::Exception), "manual": n(Manual), "notApplicable": n(Na) })
    }

    pub fn view(&self) -> Value {
        json!({
            "format": FORMAT,
            "checkedAt": rfc3339(self.checked_at),
            "botd": self.version,
            "mode": self.mode.as_str(),
            "baseline": "docs/security/configuration-baseline.md",
            "ok": self.ok(),
            "counts": self.counts(),
            "failing": self.with(Fail),
            "excepted": self.with(Status::Exception),
            "unusedExceptions": self.unused_exceptions,
            "digest": self.digest,
            "checks": self.checks.iter().map(|c| json!({ "setting": c.setting, "baseline": c.baseline, "status": c.status.as_str(), "observed": c.observed })).collect::<Vec<_>>(),
        })
    }

    /// The audit event's details: counts and setting names, no observed values.
    fn details(&self, source: &str) -> Value {
        json!({
            "source": source, "mode": self.mode.as_str(), "ok": self.ok(), "counts": self.counts(), "failed": self.with(Fail),
            "excepted": self.with(Status::Exception), "unusedExceptions": self.unused_exceptions, "digest": self.digest, "version": self.version,
        })
    }
}

fn rfc3339(ms: i64) -> String {
    chrono::DateTime::from_timestamp_millis(ms).map(|t| t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)).unwrap_or_default()
}

/// Judges `f` against every rule, waiving the failures `exceptions` names.
pub fn evaluate(f: &Facts, exceptions: &[&'static str], now_ms: i64) -> Report {
    let checks: Vec<Check> = RULES
        .iter()
        .map(|r| {
            let (status, observed) = (r.judge)(f);
            let status = if status == Fail && exceptions.contains(&r.setting) { Status::Exception } else { status };
            Check { setting: r.setting, baseline: r.baseline, status, observed }
        })
        .collect();
    let unused_exceptions = exceptions.iter().copied().filter(|e| !checks.iter().any(|c| c.setting == *e && c.status == Status::Exception)).collect();
    let mut hash = Sha256::new();
    for c in &checks {
        hash.update(format!("{}\t{}\t{}\n", c.setting, c.status.as_str(), c.observed).as_bytes());
    }
    let digest = hash.finalize().iter().map(|b| format!("{b:02x}")).collect();
    Report { checked_at: now_ms, version: f.version.clone(), mode: f.mode, checks, unused_exceptions, digest }
}

/// This server's facts now: what it parsed at startup, and what the database says.
pub fn facts(app: &App, s: &Startup) -> Facts {
    let setting = |k: &str| app.db.setting(k).and_then(|v| v.parse::<u32>().ok()).filter(|d| *d > 0);
    let cp = app.control_plane.get().filter(|cp| cp.enabled());
    let machines = cp.map(|cp| {
        let e = cp.enrollment.as_deref();
        Machines {
            enrolled: e.is_some(),
            hardening: e.is_some_and(|e| e.hardening.is_some()),
            run_limits: e.is_some_and(|e| e.run_limits),
            bot_user: e.is_some_and(|e| e.bot_user),
            teammate_users: e.is_some_and(|e| e.teammate_users),
            firewall: cp.firewall.is_some(),
            firewall_egress: s.firewall_egress,
            suspend_on_disable: cp.suspend_on_disable,
            backup_recipients: cp.offsite.as_ref().map(|o| o.s.recipients.len()),
        }
    });
    let sb = app.server_backups.get();
    Facts {
        version: env!("CARGO_PKG_VERSION").into(),
        mfa: s.mfa_pinned.unwrap_or_else(|| app.db.setting(mfa::POLICY_KEY).as_deref().and_then(mfa::Policy::parse).unwrap_or(mfa::Policy::Off)),
        mfa_pinned: s.mfa_pinned.is_some(),
        break_glass: s.break_glass,
        signin_alerts: s.signin_alerts,
        testing: s.testing,
        database_encryption: app.database.get().map(|d| d.policy.as_str()),
        backup_encryption: sb.map(|sb| sb.encryption.as_str()),
        off_host: sb.map(|sb| (sb.mode.as_str(), sb.target.is_some())),
        machines,
        bots_run_here: cp.is_none_or(|cp| cp.routing != Routing::On),
        isolation: app.isolation().is_some(),
        teams: app.teams.get().is_some_and(|t| t.strict),
        chromium_sandbox: s.chromium_sandbox,
        metrics: s.metrics,
        audit_days: app.db.audit_retention(),
        chat_days: app.db.chat_retention(),
        sessions_days: setting(crate::file_retention::SESSIONS_KEY),
        teammate_files_days: setting(crate::file_retention::FILES_KEY),
        evidence_monthly: s.evidence_monthly,
        mode: s.settings.mode,
    }
}

/// The check of this server now, not audited.
pub fn check(app: &App, now_ms: i64) -> Report {
    let fallback = Startup::default();
    let s = app.baseline.get().map_or(&fallback, |s| s.as_ref());
    evaluate(&facts(app, s), &s.settings.exceptions, now_ms)
}

/// The startup line, then a warning per failing setting.
pub fn lines(r: &Report) -> (String, Vec<String>) {
    let applicable = r.checks.iter().filter(|c| c.status != Na).count();
    let mut line = format!("{} of {applicable} settings met", r.with(Pass).len());
    for (s, what) in [(Status::Exception, "waived by an exception"), (Manual, "for a person to check"), (Fail, "failing")] {
        let names = r.with(s);
        if !names.is_empty() {
            line.push_str(&format!("; {} {what} ({})", names.len(), names.join(", ")));
        }
    }
    line.push_str(&format!(", CONFIG_BASELINE={}", r.mode.as_str()));
    let warnings = r
        .checks
        .iter()
        .filter(|c| c.status == Fail)
        .map(|c| format!("{} isn't as the configuration baseline says ({}): {} (docs/security/configuration-baseline.md, ADR 0193).", c.setting, c.baseline, c.observed))
        .chain(r.unused_exceptions.iter().map(|e| format!("CONFIG_BASELINE_EXCEPTIONS lists {e}, which doesn't fail: remove it.")))
        .collect();
    (line, warnings)
}

/// Keeps `s` for later checks and, with `CONFIG_BASELINE` on, checks now and audits it.
/// With `required`, a failing setting is an error: botd doesn't start.
pub fn at_startup(app: &App, s: Startup) -> Result<(), String> {
    let mode = s.settings.mode;
    let _ = app.baseline.set(Arc::new(s));
    if mode == Mode::Off {
        crate::obs::log::log_info!("Configuration baseline: not checked at start (CONFIG_BASELINE=off); `botctl baseline` checks it now (ADR 0193).");
        return Ok(());
    }
    let r = check(app, now());
    let (line, warnings) = lines(&r);
    crate::obs::log::log_info!("Configuration baseline: {line} (ADR 0193).");
    for w in &warnings {
        crate::obs::log::log_warn!("WARNING: {w}");
    }
    let refused = mode == Mode::Required && !r.ok();
    let mut d = r.details("start");
    d["refused"] = json!(refused);
    let outcome = if r.ok() { Outcome::Success } else { Outcome::Failure };
    app.db.record(&Event::new(Actor::system(ACTOR), CHECKED).outcome(outcome).target("server", "baseline").details(d));
    match refused {
        true => Err(format!(
            "Configuration baseline: CONFIG_BASELINE=required, and {} isn't as the baseline says. Fix it, or list it in CONFIG_BASELINE_EXCEPTIONS under an approved exception (docs/security/configuration-baseline.md, ADR 0193)",
            r.with(Fail).join(", ")
        )),
        false => Ok(()),
    }
}

/// A `server.baseline_checked` event as the evidence bundle lists it: only known setting
/// names, codes, counts and the digest.
pub fn entry(e: &AuditEvent) -> Value {
    let d = &e.details;
    let names = |k: &str| -> Vec<&'static str> { d[k].as_array().into_iter().flatten().filter_map(|n| RULES.iter().find(|r| Some(r.setting) == n.as_str()).map(|r| r.setting)).collect() };
    let code = |k: &str, allowed: &[&'static str]| allowed.iter().copied().find(|a| d[k].as_str() == Some(*a));
    let digest = d["digest"].as_str().filter(|s| s.len() == 64 && s.bytes().all(|c| c.is_ascii_hexdigit()));
    let count = |k: &str| d["counts"][k].as_u64();
    json!({
        "id": e.id,
        "time": e.time,
        "outcome": e.outcome,
        "actor": e.actor_kind,
        "source": code("source", &["start", "request"]),
        "mode": code("mode", &["off", "on", "required"]),
        "refused": d["refused"].as_bool(),
        "ok": d["ok"].as_bool(),
        "counts": { "pass": count("pass"), "fail": count("fail"), "exception": count("exception"), "manual": count("manual"), "notApplicable": count("notApplicable") },
        "failed": names("failed"),
        "excepted": names("excepted"),
        "digest": digest,
    })
}

/// `GET /api/baseline` (admins): this server checked against the baseline now, audited.
pub async fn get(State(app): State<AppState>, Extension(by): Extension<Who>) -> Res<Json<Value>> {
    let r = check(&app, now());
    let outcome = if r.ok() { Outcome::Success } else { Outcome::Failure };
    app.db.record(&by.event(CHECKED).outcome(outcome).target("server", "baseline").details(r.details("request")));
    Ok(Json(r.view()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A server set up as the baseline says, with machines.
    pub fn managed() -> Facts {
        Facts {
            version: "0.1.0".into(),
            mfa: mfa::Policy::Admins,
            mfa_pinned: true,
            signin_alerts: true,
            database_encryption: Some("required"),
            backup_encryption: Some("required"),
            off_host: Some(("on", true)),
            machines: Some(Machines {
                enrolled: true,
                hardening: true,
                run_limits: true,
                bot_user: true,
                teammate_users: true,
                firewall: true,
                firewall_egress: true,
                suspend_on_disable: true,
                backup_recipients: Some(2),
            }),
            bots_run_here: true,
            isolation: true,
            teams: true,
            chromium_sandbox: true,
            metrics: Some((true, false)),
            audit_days: None,
            chat_days: Some(365),
            evidence_monthly: true,
            mode: Mode::On,
            ..Facts::default()
        }
    }

    fn status(r: &Report, setting: &str) -> (Status, String) {
        let c = r.checks.iter().find(|c| c.setting == setting).unwrap_or_else(|| panic!("{setting}"));
        (c.status, c.observed.clone())
    }

    #[test]
    fn a_server_set_up_as_the_baseline_says_passes_but_for_what_a_person_checks() {
        let r = evaluate(&managed(), &[], 0);
        assert!(r.ok(), "{:#}", r.view());
        assert_eq!(r.with(Manual), ["SUPERBOT_VERSION", "CHAT_RETENTION_DAYS", "HARNESS_SESSION_RETENTION_DAYS", "TEAMMATE_FILES_RETENTION_DAYS"]);
        assert_eq!(r.with(Na), Vec::<&str>::new());
        assert_eq!(r.counts(), json!({ "pass": 22, "fail": 0, "exception": 0, "manual": 4, "notApplicable": 0 }));
        assert_eq!(status(&r, "CHAT_RETENTION_DAYS").1, "365 days");
        assert_eq!(status(&r, "HARNESS_SESSION_RETENTION_DAYS").1, "kept forever");
        assert_eq!(status(&r, "MACHINE_BACKUP_AGE_RECIPIENTS").1, "2 recipients; the key's place is the operator's to check");
        let (line, warnings) = lines(&r);
        assert!(line.starts_with("22 of 26 settings met; 4 for a person to check (SUPERBOT_VERSION, "), "{line}");
        assert!(warnings.is_empty(), "{warnings:?}");
    }

    #[test]
    fn a_fresh_self_hosted_server_fails_what_is_off_by_default() {
        let fresh = Facts {
            version: "0.1.0".into(),
            signin_alerts: true,
            database_encryption: Some("auto"),
            backup_encryption: Some("auto"),
            off_host: Some(("auto", false)),
            bots_run_here: true,
            chromium_sandbox: true,
            break_glass: true,
            ..Facts::default()
        };
        let r = evaluate(&fresh, &[], 0);
        assert!(!r.ok());
        assert_eq!(
            r.with(Fail),
            ["AUTH_MFA", "AUTH_BREAK_GLASS", "SUPERBOT_DATABASE_ENCRYPTION", "SUPERBOT_BACKUP_ENCRYPTION", "SERVER_BACKUP_OFF_HOST", "ISOLATION", "EVIDENCE_BUNDLES", "CONFIG_BASELINE"]
        );
        assert_eq!(r.with(Na).len(), 8, "every machine setting: {:?}", r.with(Na));
        assert_eq!(status(&r, "MACHINE_HARDENING").1, "no machines (the control plane is off)");
        assert_eq!(status(&r, "SERVER_BACKUP_OFF_HOST").1, "auto, no store");
        assert_eq!(status(&r, "TEAMS"), (Manual, "off; botd can't tell whether more than one customer shares this server".into()));
        assert_eq!(status(&r, "METRICS_LISTEN"), (Pass, "off".into()));
        let (line, warnings) = lines(&r);
        assert!(line.contains("8 failing (AUTH_MFA, ") && line.ends_with("CONFIG_BASELINE=off"), "{line}");
        assert_eq!(warnings.len(), 8);
        assert!(warnings[1].starts_with("AUTH_BREAK_GLASS isn't as the configuration baseline says (0 once admins sign in with SSO or sign-in codes): 1: "), "{}", warnings[1]);
    }

    #[test]
    fn each_rule_judges_its_setting() {
        let r = |f: Facts| evaluate(&f, &[], 0);
        let with = |change: fn(&mut Facts)| {
            let mut f = managed();
            change(&mut f);
            r(f)
        };
        let off = |change: fn(&mut Machines)| {
            let mut f = managed();
            change(f.machines.as_mut().unwrap());
            r(f)
        };
        assert_eq!(status(&with(|f| f.mfa_pinned = false), "AUTH_MFA").0, Fail, "an admin could turn it off");
        assert_eq!(status(&with(|f| f.mfa = mfa::Policy::All), "AUTH_MFA"), (Pass, "all".into()));
        assert_eq!(status(&with(|f| f.mfa = mfa::Policy::Off), "AUTH_MFA"), (Fail, "off".into()));
        assert_eq!(status(&with(|f| f.testing = true), "TESTING_MODE"), (Fail, "on".into()));
        assert_eq!(status(&with(|f| f.signin_alerts = false), "SIGNIN_ALERTS"), (Fail, "off".into()));
        assert_eq!(status(&with(|f| f.database_encryption = Some("off")), "SUPERBOT_DATABASE_ENCRYPTION"), (Fail, "off".into()));
        assert_eq!(status(&with(|f| f.database_encryption = None), "SUPERBOT_DATABASE_ENCRYPTION"), (Fail, "unknown".into()));
        assert_eq!(status(&with(|f| f.off_host = Some(("auto", true))), "SERVER_BACKUP_OFF_HOST"), (Fail, "auto, with a store".into()));
        assert_eq!(status(&with(|f| f.chromium_sandbox = false), "SUPERBOT_CHROMIUM_SANDBOX").0, Fail);
        assert_eq!(status(&with(|f| f.metrics = Some((false, true))), "METRICS_LISTEN").0, Pass);
        assert_eq!(status(&with(|f| f.metrics = Some((false, false))), "METRICS_LISTEN").0, Fail);
        assert_eq!(status(&with(|f| f.audit_days = Some(730)), "AUDIT_RETENTION_DAYS"), (Pass, "730 days".into()));
        assert_eq!(status(&with(|f| f.audit_days = Some(400)), "AUDIT_RETENTION_DAYS").0, Fail);
        assert_eq!(status(&with(|f| f.mode = Mode::Required), "CONFIG_BASELINE"), (Pass, "required".into()));
        assert_eq!(status(&with(|f| f.bots_run_here = false), "ISOLATION").0, Na, "Bots only on machines");
        assert_eq!(status(&with(|f| f.isolation = false), "ISOLATION").0, Fail);
        for (setting, r) in [
            ("MACHINE_HARDENING", off(|m| m.hardening = false)),
            ("MACHINE_RUN_LIMITS", off(|m| m.run_limits = false)),
            ("MACHINE_BOT_USER", off(|m| m.bot_user = false)),
            ("MACHINE_TEAMMATE_USERS", off(|m| m.teammate_users = false)),
            ("MACHINE_FIREWALL", off(|m| m.firewall = false)),
            ("MACHINE_FIREWALL_EGRESS", off(|m| m.firewall_egress = false)),
            ("MACHINE_ON_DISABLE", off(|m| m.suspend_on_disable = false)),
            ("MACHINE_BACKUP_AGE_RECIPIENTS", off(|m| m.backup_recipients = Some(0))),
        ] {
            assert_eq!(status(&r, setting).0, Fail, "{setting}");
            assert_eq!(r.with(Fail), [setting], "only {setting} fails");
        }
        assert_eq!(status(&off(|m| m.firewall = false), "MACHINE_FIREWALL_EGRESS").0, Na, "no firewall, no outbound rules to judge");
        assert_eq!(status(&off(|m| m.backup_recipients = None), "MACHINE_BACKUP_AGE_RECIPIENTS").0, Na);
        let unenrolled = off(|m| m.enrolled = false);
        assert_eq!(status(&unenrolled, "MACHINE_HARDENING"), (Na, "machines don't enroll (MACHINE_CONTROL_URL unset)".into()));
    }

    #[test]
    fn an_exception_waives_a_failure_and_one_not_needed_is_reported() {
        let mut f = managed();
        f.break_glass = true;
        let r = evaluate(&f, &["AUTH_BREAK_GLASS", "TEAMS"], 0);
        assert!(r.ok());
        assert_eq!((r.with(Status::Exception), r.unused_exceptions.clone()), (vec!["AUTH_BREAK_GLASS"], vec!["TEAMS"]));
        let (line, warnings) = lines(&r);
        assert!(line.contains("1 waived by an exception (AUTH_BREAK_GLASS)"), "{line}");
        assert_eq!(warnings, ["CONFIG_BASELINE_EXCEPTIONS lists TEAMS, which doesn't fail: remove it."]);
        assert_ne!(r.digest, evaluate(&managed(), &[], 0).digest);
    }

    #[test]
    fn the_digest_depends_on_the_settings_not_the_time() {
        let (a, b) = (evaluate(&managed(), &[], 0), evaluate(&managed(), &[], 1_800_000_000_000));
        assert_eq!(a.digest, b.digest);
        assert_eq!(a.digest.len(), 64);
        let mut f = managed();
        f.audit_days = Some(800);
        assert_ne!(evaluate(&f, &[], 0).digest, a.digest, "an observed value counts");
    }

    #[test]
    fn settings_are_off_by_default_and_exceptions_must_be_checked_settings() {
        fn from(vars: &[(&str, &str)]) -> Result<Settings, String> {
            Settings::from_env(&|k| vars.iter().find(|(n, _)| *n == k).map(|(_, v)| v.to_string()).unwrap_or_default())
        }
        assert_eq!(from(&[]), Ok(Settings::default()));
        assert_eq!(from(&[("CONFIG_BASELINE", " Required ")]).unwrap().mode, Mode::Required);
        assert_eq!(from(&[("CONFIG_BASELINE", "on"), ("CONFIG_BASELINE_EXCEPTIONS", "auth_break_glass, TEAMS,TEAMS")]), Ok(Settings { mode: Mode::On, exceptions: vec!["AUTH_BREAK_GLASS", "TEAMS"] }));
        assert!(from(&[("CONFIG_BASELINE", "strict")]).unwrap_err().contains("off, on or required"));
        assert!(from(&[("CONFIG_BASELINE_EXCEPTIONS", "AUTH_PASSWORD")]).unwrap_err().contains("isn't a setting the baseline checks"));
    }

    #[test]
    fn audit_entries_keep_only_known_settings_and_codes() {
        let r = evaluate(&Facts { break_glass: true, ..managed() }, &[], 0);
        let mut d = r.details("start");
        d["failed"].as_array_mut().unwrap().push(json!("jane@example.com"));
        d["source"] = json!("Jane's laptop");
        let db = crate::db::Db::open(&crate::db::temp_path("baseline-entry").join("app.sqlite")).unwrap();
        db.record(&Event::new(Actor::system(ACTOR), CHECKED).outcome(Outcome::Failure).details(d));
        let e = db.audit_events(&audit::Filter { actions: vec![CHECKED.into()], ..Default::default() }, 1, false).pop().unwrap();
        let v = entry(&e);
        assert_eq!((v["outcome"].as_str(), v["actor"].as_str()), (Some("failure"), Some("system")));
        assert_eq!(v["failed"], json!(["AUTH_BREAK_GLASS"]));
        assert_eq!((v["source"].clone(), v["mode"].clone(), v["ok"].clone()), (Value::Null, json!("on"), json!(false)));
        assert_eq!((v["counts"]["fail"].as_u64(), v["digest"].as_str()), (Some(1), Some(r.digest.as_str())));
    }

    /// The table in `docs/security/configuration-baseline.md`, as (setting, baseline) with
    /// Markdown's backticks and links taken out.
    fn table() -> Vec<(String, String)> {
        let md = include_str!("../../docs/security/configuration-baseline.md");
        let section = md.split("## Settings").nth(1).and_then(|s| s.split("\n## ").next()).expect("a Settings section");
        let plain = |s: &str| {
            let s = s.replace('`', "");
            let mut out = String::new();
            let mut rest = s.as_str();
            while let Some(i) = rest.find('[') {
                out.push_str(&rest[..i]);
                let after = &rest[i + 1..];
                match (after.find("]("), after.find(')')) {
                    (Some(j), Some(k)) if j < k => {
                        out.push_str(&after[..j]);
                        rest = &after[k + 1..];
                    }
                    _ => {
                        out.push('[');
                        rest = after;
                    }
                }
            }
            out.push_str(rest);
            out.trim().to_string()
        };
        let mut rows = Vec::new();
        for line in section.lines().filter(|l| l.starts_with("| `")) {
            let cells: Vec<&str> = line.split('|').map(str::trim).collect();
            for name in cells[1].split(',') {
                rows.push((plain(name), plain(cells[2])));
            }
        }
        rows
    }

    /// A row added to the baseline needs a rule, and a rule's baseline is the table's.
    #[test]
    fn every_row_of_the_baseline_has_a_rule_in_its_order() {
        let rows = table();
        let rules: Vec<(String, String)> = RULES.iter().map(|r| (r.setting.to_string(), r.baseline.to_string())).collect();
        assert_eq!(rows, rules);
    }
}
