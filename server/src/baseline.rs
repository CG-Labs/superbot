//! The configuration baseline, checked by botd itself (ADR 0192). Each setting in
//! `docs/security/configuration-baseline.md` has a rule here that reads the value botd
//! runs with, through the same parser botd started with, and judges it: meets the
//! baseline, doesn't, excepted (`BASELINE_EXCEPTIONS`), doesn't apply to this server
//! (machine settings without machines), or only a person can tell (the image's
//! signature, retention periods a contract sets). `GET /api/evidence/baseline` (admins,
//! audited as `evidence.baseline_checked`) and `botctl evidence baseline` run it on
//! request; every evidence bundle (ADR 0142) carries it as `baseline.json`.
//!
//! Never in it: a setting's value when it could be a secret, an address or a name. Values
//! are codes (`on`, `required`, `admins`), day counts, botd's version, or `set`/`unset`.

use crate::audit::Who;
use crate::db::now;
use crate::mfa;
use crate::runner::App;
use crate::{AppState, Auth};
use axum::Json;
use axum::extract::{Extension, State};
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::sync::Arc;

/// Bumped when `baseline.json`'s shape changes.
pub const FORMAT: u32 = 1;
pub const CHECKED: &str = "evidence.baseline_checked";
pub const EXCEPTIONS_VAR: &str = "BASELINE_EXCEPTIONS";
/// The longest observation period an auditor commonly agrees (12 months) plus the year
/// the retention policy keeps audit events after it.
pub const MIN_AUDIT_DAYS: u32 = 730;

/// Each setting the baseline names, in its table's order, with the value it asks for.
/// A unit test holds this to the baseline's table.
pub const SETTINGS: [(&str, &str); 25] = [
    ("SUPERBOT_VERSION", "a released, signed version"),
    ("AUTH_MFA", "admins or all"),
    ("AUTH_BREAK_GLASS", "0 once another admin signs in"),
    ("SIGNIN_ALERTS", "on"),
    ("TESTING_MODE", "unset"),
    ("SUPERBOT_DATABASE_ENCRYPTION", "required"),
    ("SUPERBOT_BACKUP_ENCRYPTION", "required"),
    ("SERVER_BACKUP_OFF_HOST", "on"),
    ("MACHINE_BACKUP_AGE_RECIPIENTS", "set"),
    ("ISOLATION", "users where Bots run locally"),
    ("TEAMS", "on when customers share the server"),
    ("MACHINE_HARDENING", "on"),
    ("MACHINE_RUN_LIMITS", "on"),
    ("MACHINE_BOT_USER", "on"),
    ("MACHINE_TEAMMATE_USERS", "on"),
    ("MACHINE_FIREWALL", "on for Linode machines"),
    ("MACHINE_FIREWALL_EGRESS", "on with the firewall"),
    ("MACHINE_ON_DISABLE", "suspend"),
    ("SUPERBOT_CHROMIUM_SANDBOX", "unset or on"),
    ("METRICS_LISTEN", "off, loopback, or with METRICS_TOKEN"),
    ("AUDIT_RETENTION_DAYS", "unset, or at least 730"),
    ("CHAT_RETENTION_DAYS", "what the retention policy and contracts say"),
    ("HARNESS_SESSION_RETENTION_DAYS", "what the retention policy and contracts say"),
    ("TEAMMATE_FILES_RETENTION_DAYS", "what the retention policy and contracts say"),
    ("EVIDENCE_BUNDLES", "monthly"),
];

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum Status {
    Pass,
    Fail,
    /// Fails, but an exception approved under the information security policy covers it.
    Excepted,
    NotApplicable,
    /// Only a person can judge it; the value is recorded for them.
    Manual,
}

/// What a check reads besides the environment: what botd holds at run time.
pub struct Observed<'a> {
    /// botd's environment, as `main` reads it.
    pub var: &'a dyn Fn(&str) -> String,
    /// Whether a secret is set in the environment, a `_FILE` or the secret store.
    pub secret_set: &'a dyn Fn(&str) -> bool,
    /// The MFA policy in force, from `AUTH_MFA` or an admin.
    pub mfa: mfa::Policy,
    pub audit_days: Option<u32>,
    pub chat_days: Option<u32>,
    pub harness_days: Option<u32>,
    pub teammate_days: Option<u32>,
    /// Admins other than the break-glass owner who have signed in.
    pub other_admins_signed_in: usize,
    /// Whether this server runs users' machines (a control plane with a provider).
    pub machines: bool,
    pub evidence_monthly: bool,
    pub version: &'a str,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Finding {
    pub setting: &'static str,
    pub status: Status,
    pub value: String,
    pub baseline: &'static str,
    pub note: &'static str,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Report {
    pub findings: Vec<Finding>,
    /// Names in `BASELINE_EXCEPTIONS` the baseline doesn't have.
    pub unknown_exceptions: Vec<String>,
    /// Settings excepted that meet the baseline anyway, so the exception can go.
    pub unneeded_exceptions: Vec<&'static str>,
}

fn on(b: bool) -> String {
    if b { "on" } else { "off" }.into()
}

fn days(d: Option<u32>) -> String {
    d.map_or("unset".into(), |d| d.to_string())
}

fn invalid() -> (Status, String, &'static str) {
    (Status::Fail, "invalid".into(), "botd can't read this value; it would refuse to start with it")
}

fn flag(r: Result<bool, String>, want: bool, note: &'static str) -> (Status, String, &'static str) {
    match r {
        Ok(v) => (if v == want { Status::Pass } else { Status::Fail }, on(v), note),
        Err(_) => invalid(),
    }
}

/// One setting's status, value and why.
fn judge(setting: &str, o: &Observed) -> (Status, String, &'static str) {
    use Status::*;
    let var = o.var;
    let machines = |r: (Status, String, &'static str)| if o.machines { r } else { (NotApplicable, r.1, "this server runs no users' machines") };
    match setting {
        "SUPERBOT_VERSION" => (Manual, o.version.into(), "botd can't verify its own image: run cosign verify on the image the server runs"),
        "AUTH_MFA" => (if o.mfa == mfa::Policy::Off { Fail } else { Pass }, o.mfa.as_str().into(), "the policy in force, from AUTH_MFA or an admin"),
        "AUTH_BREAK_GLASS" => match crate::users::break_glass_flag(&var("AUTH_BREAK_GLASS")) {
            Ok(false) => (Pass, "0".into(), "the owner's password is off"),
            Ok(true) if o.other_admins_signed_in > 0 => (Fail, "1".into(), "another admin has signed in, so the owner's password should be off"),
            Ok(true) => (NotApplicable, "1".into(), "no admin besides the owner has signed in yet"),
            Err(_) => invalid(),
        },
        "SIGNIN_ALERTS" => flag(crate::signin_watch::Settings::from_env(var).map(|s| s.enabled), true, "suspicious sign-ins are reported"),
        "TESTING_MODE" => match crate::license::testing_flag(&var("TESTING_MODE")) {
            Ok(false) => (Pass, "unset".into(), "licensing and billing are on"),
            Ok(true) => (Fail, "on".into(), "testing mode is for test servers only"),
            Err(_) => invalid(),
        },
        "SUPERBOT_DATABASE_ENCRYPTION" => match crate::database_encryption::Policy::from_env(var) {
            Ok(p) => (if p == crate::database_encryption::Policy::Required { Pass } else { Fail }, p.as_str().into(), "required refuses to start on a plain database"),
            Err(_) => invalid(),
        },
        "SUPERBOT_BACKUP_ENCRYPTION" => match crate::backup_encryption::Policy::from_env(var) {
            Ok(p) => (if p == crate::backup_encryption::Policy::Required { Pass } else { Fail }, p.as_str().into(), "required refuses to write a plain backup"),
            Err(_) => invalid(),
        },
        "SERVER_BACKUP_OFF_HOST" => match var("SERVER_BACKUP_OFF_HOST").trim().to_ascii_lowercase().as_str() {
            "on" => (Pass, "on".into(), "botd refuses to start without a store"),
            "" | "auto" => (Fail, "auto".into(), "auto copies only while a store is set; on refuses to start without one"),
            "off" => (Fail, "off".into(), "server backups stay on this host"),
            _ => invalid(),
        },
        "MACHINE_BACKUP_AGE_RECIPIENTS" => {
            let set = ["MACHINE_BACKUP_AGE_RECIPIENTS", "MACHINE_BACKUP_AGE_RECIPIENTS_FILE"].iter().any(|k| !var(k).trim().is_empty());
            machines((if set { Pass } else { Fail }, if set { "set" } else { "unset" }.into(), "keeping the private key off the host is checked by hand"))
        }
        "ISOLATION" => {
            let users = var("ISOLATION").trim() == "users";
            let value = if users { "users" } else { "off" };
            match crate::machines::route::Routing::parse(&var("MACHINE_ROUTING")) {
                Ok(crate::machines::route::Routing::On) if !users => (NotApplicable, value.into(), "every Bot runs on its user's machine (MACHINE_ROUTING=on)"),
                Ok(_) => (if users { Pass } else { Fail }, value.into(), "Bots run on this server, each user's as their own account"),
                Err(_) => invalid(),
            }
        }
        "TEAMS" => match crate::teams::Settings::from_env(var) {
            Ok(s) if s.strict => (Pass, "on".into(), "sharing stops at a team"),
            Ok(_) => (Manual, "off".into(), "needed when more than one customer shares this server, which botd can't tell"),
            Err(_) => invalid(),
        },
        "MACHINE_HARDENING" => machines(flag(crate::machines::hardening::Settings::from_env(var).map(|s| s.is_some()), true, "machines are hardened at first boot")),
        "MACHINE_RUN_LIMITS" => machines(match var("MACHINE_RUN_LIMITS").trim() {
            "" | "on" => (Pass, "on".into(), "each run is held to its tier's limits"),
            "off" => (Fail, "off".into(), "runs have no limits"),
            _ => invalid(),
        }),
        "MACHINE_BOT_USER" => machines(flag(crate::machines::botuser::from_env(var), true, "Bots run as an unprivileged user")),
        "MACHINE_TEAMMATE_USERS" => {
            let bot_user = crate::machines::botuser::from_env(var).unwrap_or(true);
            machines(flag(crate::machines::teammate::from_env(var, bot_user), true, "teammates' runs can't read the owner's files"))
        }
        "MACHINE_FIREWALL" => {
            let provider = var("MACHINE_PROVIDER").trim().to_ascii_lowercase();
            let r = flag(crate::machines::firewall::Settings::from_env(var).map(|s| s.is_some()), true, "only botd reaches a machine's agent");
            match provider.as_str() {
                "" | "linode" => machines(r),
                _ => (NotApplicable, r.1, "the baseline asks for it on Linode machines only"),
            }
        }
        "MACHINE_FIREWALL_EGRESS" => match crate::machines::firewall::Settings::from_env(var) {
            Ok(Some(_)) => machines(flag(crate::machines::firewall::egress_from_env(var), true, "the provider's firewall keeps machines off private ranges")),
            Ok(None) => (NotApplicable, "off".into(), "only with MACHINE_FIREWALL=on"),
            Err(_) => invalid(),
        },
        "MACHINE_ON_DISABLE" => machines(match var("MACHINE_ON_DISABLE").trim().to_ascii_lowercase().as_str() {
            "" | "suspend" => (Pass, "suspend".into(), "a disabled user's machine is powered off"),
            "keep" => (Fail, "keep".into(), "a disabled user's machine keeps running"),
            _ => invalid(),
        }),
        "SUPERBOT_CHROMIUM_SANDBOX" => flag(crate::chromium::parse_sandbox(&var("SUPERBOT_CHROMIUM_SANDBOX")), true, "browsers stay sandboxed"),
        "METRICS_LISTEN" => {
            let raw = var("METRICS_LISTEN");
            let addr = match raw.trim().to_ascii_lowercase().as_str() {
                "" | "off" => return (Pass, "off".into(), "no metrics listener"),
                "on" => Some(true),
                s => s.parse::<std::net::SocketAddr>().ok().map(|a| a.ip().is_loopback()),
            };
            match (addr, (o.secret_set)("METRICS_TOKEN")) {
                (None, _) => invalid(),
                (Some(_), true) => (Pass, "token".into(), "scrapers send a bearer token"),
                (Some(true), false) => (Pass, "loopback".into(), "only this host can reach it"),
                (Some(false), false) => (Fail, "public".into(), "metrics are reachable without a token"),
            }
        }
        "AUDIT_RETENTION_DAYS" => match o.audit_days {
            None => (Pass, "unset".into(), "audit events are kept forever"),
            Some(d) if d >= MIN_AUDIT_DAYS => (Pass, d.to_string(), "covers a 12-month period plus a year"),
            Some(d) => (Fail, d.to_string(), "shorter than a 12-month period plus a year"),
        },
        "CHAT_RETENTION_DAYS" => (Manual, days(o.chat_days), "compare with the retention policy and customers' contracts"),
        "HARNESS_SESSION_RETENTION_DAYS" => (Manual, days(o.harness_days), "compare with the retention policy and customers' contracts"),
        "TEAMMATE_FILES_RETENTION_DAYS" => (Manual, days(o.teammate_days), "compare with the retention policy and customers' contracts"),
        "EVIDENCE_BUNDLES" => (if o.evidence_monthly { Pass } else { Fail }, if o.evidence_monthly { "monthly" } else { "off" }.into(), "each month's bundle is written on the 1st"),
        _ => (Manual, "unknown".into(), "no rule for this setting"),
    }
}

/// Every setting judged, with `BASELINE_EXCEPTIONS` applied.
pub fn check(o: &Observed) -> Report {
    let listed: Vec<String> = (o.var)(EXCEPTIONS_VAR).split(',').map(|s| s.trim().to_ascii_uppercase()).filter(|s| !s.is_empty()).collect();
    let mut r = Report { findings: Vec::new(), unknown_exceptions: Vec::new(), unneeded_exceptions: Vec::new() };
    for (setting, baseline) in SETTINGS {
        let (mut status, value, note) = judge(setting, o);
        if listed.iter().any(|s| s == setting) {
            match status {
                Status::Fail => status = Status::Excepted,
                Status::Pass => r.unneeded_exceptions.push(setting),
                Status::Excepted | Status::NotApplicable | Status::Manual => {}
            }
        }
        r.findings.push(Finding { setting, status, value, baseline, note });
    }
    for s in listed {
        if !SETTINGS.iter().any(|(k, _)| *k == s) && !r.unknown_exceptions.contains(&s) {
            r.unknown_exceptions.push(s);
        }
    }
    r
}

impl Report {
    pub fn count(&self, s: Status) -> usize {
        self.findings.iter().filter(|f| f.status == s).count()
    }

    fn named(&self, s: Status) -> Vec<&'static str> {
        self.findings.iter().filter(|f| f.status == s).map(|f| f.setting).collect()
    }

    /// Nothing fails and every exception names a setting of the baseline.
    pub fn ok(&self) -> bool {
        self.count(Status::Fail) == 0 && self.unknown_exceptions.is_empty()
    }

    /// SHA-256 of one line per setting, in the baseline's order: setting, status and
    /// value, tab-separated, each ending in a newline. The same settings give the same
    /// digest, so two checks can be compared without their files.
    pub fn digest(&self) -> String {
        let mut h = Sha256::new();
        for f in &self.findings {
            let status = serde_json::to_value(f.status).ok().and_then(|v| v.as_str().map(String::from)).unwrap_or_default();
            h.update(format!("{}\t{status}\t{}\n", f.setting, f.value).as_bytes());
        }
        h.finalize().iter().map(|b| format!("{b:02x}")).collect()
    }

    pub fn counts(&self) -> Value {
        json!({
            "pass": self.count(Status::Pass),
            "fail": self.count(Status::Fail),
            "excepted": self.count(Status::Excepted),
            "notApplicable": self.count(Status::NotApplicable),
            "manual": self.count(Status::Manual),
        })
    }

    /// `baseline.json` and the API's answer.
    pub fn view(&self, checked_at: &str) -> Value {
        json!({
            "format": FORMAT,
            "checkedAt": checked_at,
            "baseline": "docs/security/configuration-baseline.md",
            "ok": self.ok(),
            "counts": self.counts(),
            "digest": self.digest(),
            "settings": self.findings,
            "exceptions": {
                "deviations": self.named(Status::Fail),
                "excepted": self.named(Status::Excepted),
                "unknownExceptions": self.unknown_exceptions,
            },
            "unneededExceptions": self.unneeded_exceptions,
        })
    }

    /// What `evidence.baseline_checked` records: counts and setting names only.
    pub fn audit_details(&self) -> Value {
        json!({
            "ok": self.ok(),
            "counts": self.counts(),
            "digest": self.digest(),
            "deviations": self.named(Status::Fail),
            "excepted": self.named(Status::Excepted),
            "unknownExceptions": self.unknown_exceptions.len(),
        })
    }
}

fn env(k: &str) -> String {
    std::env::var(k).unwrap_or_default()
}

fn secret_set(k: &str) -> bool {
    !env(k).trim().is_empty() || crate::secrets::global().get(k).ok().flatten().is_some()
}

/// The baseline checked against this botd now, with the MFA policy in force.
pub fn run(app: &App, mfa: mfa::Policy) -> Report {
    let other_admins_signed_in = app.db.users().into_iter().filter(|u| u.role == crate::rbac::Role::Admin && u.active() && u.id != crate::users::OPERATOR && u.last_login_at.is_some()).count();
    let o = Observed {
        var: &env,
        secret_set: &secret_set,
        mfa,
        audit_days: app.db.audit_retention(),
        chat_days: app.db.chat_retention(),
        harness_days: app.db.retention_days(crate::file_retention::SESSIONS_KEY),
        teammate_days: app.db.retention_days(crate::file_retention::FILES_KEY),
        other_admins_signed_in,
        machines: app.control_plane.get().is_some_and(|cp| cp.enabled()),
        evidence_monthly: app.evidence.get().is_some_and(|s| s.monthly),
        version: env!("CARGO_PKG_VERSION"),
    };
    check(&o)
}

fn rfc3339(ms: i64) -> String {
    chrono::DateTime::from_timestamp_millis(ms).map(|t| t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)).unwrap_or_default()
}

/// `GET /api/evidence/baseline` (admins): each setting against the baseline. Audited, so
/// the quarterly check and the one after each change leave a record.
pub async fn get(State(app): State<AppState>, Extension(a): Extension<Arc<Auth>>, Extension(by): Extension<Who>) -> Json<Value> {
    let policy = mfa::policy(&a, &app.db);
    let r = run(&app, policy);
    app.db.record(&by.event(CHECKED).target("setup", "server").details(r.audit_details()));
    Json(r.view(&rfc3339(now())))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn observed<'a>(var: &'a dyn Fn(&str) -> String, secret: &'a dyn Fn(&str) -> bool) -> Observed<'a> {
        Observed {
            var,
            secret_set: secret,
            mfa: mfa::Policy::Admins,
            audit_days: None,
            chat_days: Some(90),
            harness_days: None,
            teammate_days: None,
            other_admins_signed_in: 1,
            machines: true,
            evidence_monthly: true,
            version: "0.9.0",
        }
    }

    fn vars(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    fn status(r: &Report, setting: &str) -> (Status, String) {
        let f = r.findings.iter().find(|f| f.setting == setting).unwrap();
        (f.status, f.value.clone())
    }

    /// What the managed service sets: every rule passes, but for those only a person can judge.
    const MANAGED: [(&str, &str); 9] = [
        ("AUTH_BREAK_GLASS", "0"),
        ("SUPERBOT_DATABASE_ENCRYPTION", "required"),
        ("SUPERBOT_BACKUP_ENCRYPTION", "required"),
        ("SERVER_BACKUP_OFF_HOST", "on"),
        ("MACHINE_BACKUP_AGE_RECIPIENTS", "age1qqqq"),
        ("ISOLATION", "users"),
        ("TEAMS", "on"),
        ("MACHINE_TEAMMATE_USERS", "on"),
        ("MACHINE_FIREWALL", "on"),
    ];

    fn managed() -> HashMap<String, String> {
        let mut v = vars(&MANAGED);
        v.insert("MACHINE_CONTROL_URL".into(), "https://192.0.2.1:8443".into());
        v
    }

    #[test]
    fn a_managed_server_meets_the_baseline() {
        let v = managed();
        let get = |k: &str| v.get(k).cloned().unwrap_or_default();
        let r = check(&observed(&get, &|_| false));
        assert!(r.ok(), "{:#?}", r.findings.iter().filter(|f| f.status == Status::Fail).collect::<Vec<_>>());
        let manual: Vec<_> = r.findings.iter().filter(|f| f.status == Status::Manual).map(|f| f.setting).collect();
        assert_eq!(manual, ["SUPERBOT_VERSION", "CHAT_RETENTION_DAYS", "HARNESS_SESSION_RETENTION_DAYS", "TEAMMATE_FILES_RETENTION_DAYS"]);
        assert_eq!(status(&r, "CHAT_RETENTION_DAYS"), (Status::Manual, "90".into()));
        assert_eq!(status(&r, "MACHINE_BACKUP_AGE_RECIPIENTS"), (Status::Pass, "set".into()), "never the key itself");
        assert_eq!(status(&r, "MACHINE_FIREWALL_EGRESS"), (Status::Pass, "on".into()), "on by default with the firewall");
        assert_eq!(r.count(Status::Pass), SETTINGS.len() - 4);
    }

    #[test]
    fn a_default_install_fails_where_protections_are_off_by_default() {
        let get = |_: &str| String::new();
        let mut o = observed(&get, &|_| false);
        o.mfa = mfa::Policy::Off;
        o.evidence_monthly = false;
        o.machines = false;
        let r = check(&o);
        assert!(!r.ok());
        let fails: Vec<_> = r.findings.iter().filter(|f| f.status == Status::Fail).map(|f| f.setting).collect();
        assert_eq!(fails, ["AUTH_MFA", "AUTH_BREAK_GLASS", "SUPERBOT_DATABASE_ENCRYPTION", "SUPERBOT_BACKUP_ENCRYPTION", "SERVER_BACKUP_OFF_HOST", "ISOLATION", "EVIDENCE_BUNDLES"]);
        for s in ["MACHINE_HARDENING", "MACHINE_TEAMMATE_USERS", "MACHINE_FIREWALL", "MACHINE_BACKUP_AGE_RECIPIENTS", "MACHINE_ON_DISABLE"] {
            assert_eq!(status(&r, s).0, Status::NotApplicable, "{s} without machines");
        }
        assert_eq!(status(&r, "SERVER_BACKUP_OFF_HOST"), (Status::Fail, "auto".into()));
        assert_eq!(status(&r, "TEAMS"), (Status::Manual, "off".into()));
        assert_eq!(status(&r, "SIGNIN_ALERTS"), (Status::Pass, "on".into()));
        assert_eq!(status(&r, "TESTING_MODE"), (Status::Pass, "unset".into()));
    }

    #[test]
    fn each_rule_reads_the_value_as_botd_does() {
        let cases: [(&[(&str, &str)], &str, Status, &str); 18] = [
            (&[("AUTH_BREAK_GLASS", "off")], "AUTH_BREAK_GLASS", Status::Pass, "0"),
            (&[("SIGNIN_ALERTS", "no")], "SIGNIN_ALERTS", Status::Fail, "off"),
            (&[("TESTING_MODE", "yes")], "TESTING_MODE", Status::Fail, "on"),
            (&[("TESTING_MODE", "maybe")], "TESTING_MODE", Status::Fail, "invalid"),
            (&[("SUPERBOT_DATABASE_ENCRYPTION", "Required")], "SUPERBOT_DATABASE_ENCRYPTION", Status::Pass, "required"),
            (&[("SERVER_BACKUP_OFF_HOST", "off")], "SERVER_BACKUP_OFF_HOST", Status::Fail, "off"),
            (&[("MACHINE_BACKUP_AGE_RECIPIENTS_FILE", "/run/keys/age.pub")], "MACHINE_BACKUP_AGE_RECIPIENTS", Status::Pass, "set"),
            (&[("MACHINE_ROUTING", "on")], "ISOLATION", Status::NotApplicable, "off"),
            (&[("MACHINE_ROUTING", "assigned")], "ISOLATION", Status::Fail, "off"),
            (&[("MACHINE_CONTROL_URL", "https://192.0.2.1:8443"), ("MACHINE_HARDENING", "off")], "MACHINE_HARDENING", Status::Fail, "off"),
            (&[("MACHINE_RUN_LIMITS", "off")], "MACHINE_RUN_LIMITS", Status::Fail, "off"),
            (&[("MACHINE_BOT_USER", "off"), ("MACHINE_TEAMMATE_USERS", "on")], "MACHINE_TEAMMATE_USERS", Status::Fail, "invalid"),
            (&[("MACHINE_PROVIDER", "incus")], "MACHINE_FIREWALL", Status::NotApplicable, "off"),
            (&[("MACHINE_FIREWALL", "on"), ("MACHINE_CONTROL_URL", "https://192.0.2.1:8443"), ("MACHINE_FIREWALL_EGRESS", "off")], "MACHINE_FIREWALL_EGRESS", Status::Fail, "off"),
            (&[], "MACHINE_FIREWALL_EGRESS", Status::NotApplicable, "off"),
            (&[("MACHINE_ON_DISABLE", "keep")], "MACHINE_ON_DISABLE", Status::Fail, "keep"),
            (&[("SUPERBOT_CHROMIUM_SANDBOX", "off")], "SUPERBOT_CHROMIUM_SANDBOX", Status::Fail, "off"),
            (&[("METRICS_LISTEN", "0.0.0.0:9464")], "METRICS_LISTEN", Status::Fail, "public"),
        ];
        for (env, setting, want, value) in cases {
            let v = vars(env);
            let get = |k: &str| v.get(k).cloned().unwrap_or_default();
            let r = check(&observed(&get, &|_| false));
            assert_eq!(status(&r, setting), (want, value.to_string()), "{setting} with {env:?}");
        }
        let v = vars(&[("METRICS_LISTEN", "0.0.0.0:9464")]);
        let get = |k: &str| v.get(k).cloned().unwrap_or_default();
        assert_eq!(status(&check(&observed(&get, &|k| k == "METRICS_TOKEN")), "METRICS_LISTEN"), (Status::Pass, "token".into()));
        let v = vars(&[("METRICS_LISTEN", "on")]);
        let get = |k: &str| v.get(k).cloned().unwrap_or_default();
        assert_eq!(status(&check(&observed(&get, &|_| false)), "METRICS_LISTEN"), (Status::Pass, "loopback".into()));
    }

    #[test]
    fn break_glass_and_audit_retention_depend_on_what_botd_holds() {
        let get = |_: &str| String::new();
        let mut o = observed(&get, &|_| false);
        o.other_admins_signed_in = 0;
        assert_eq!(status(&check(&o), "AUTH_BREAK_GLASS"), (Status::NotApplicable, "1".into()));
        for (d, want) in [(Some(729), Status::Fail), (Some(730), Status::Pass), (None, Status::Pass)] {
            o.audit_days = d;
            assert_eq!(status(&check(&o), "AUDIT_RETENTION_DAYS").0, want, "{d:?}");
        }
        o.mfa = mfa::Policy::All;
        assert_eq!(status(&check(&o), "AUTH_MFA"), (Status::Pass, "all".into()));
    }

    #[test]
    fn exceptions_cover_a_deviation_and_say_when_they_are_unknown_or_unneeded() {
        let mut v = managed();
        v.insert("TEAMS".into(), String::new());
        v.insert("MACHINE_ON_DISABLE".into(), "keep".into());
        v.insert(EXCEPTIONS_VAR.into(), "machine_on_disable, TEAMS ,AUTH_MFA,NOT_A_SETTING,NOT_A_SETTING".into());
        let get = |k: &str| v.get(k).cloned().unwrap_or_default();
        let r = check(&observed(&get, &|_| false));
        assert_eq!(status(&r, "MACHINE_ON_DISABLE").0, Status::Excepted);
        assert_eq!(status(&r, "TEAMS").0, Status::Manual, "a judgement isn't a deviation");
        assert_eq!(r.unneeded_exceptions, ["AUTH_MFA"]);
        assert_eq!(r.unknown_exceptions, ["NOT_A_SETTING"]);
        assert!(!r.ok(), "an unknown exception is a mistake to fix");
        let view = r.view("2027-01-01T00:00:00Z");
        assert_eq!(view["exceptions"]["excepted"], json!(["MACHINE_ON_DISABLE"]));
        assert_eq!(view["exceptions"]["deviations"], json!([]));
        assert_eq!(view["counts"]["excepted"], 1);
        v.insert(EXCEPTIONS_VAR.into(), "MACHINE_ON_DISABLE".into());
        let get = |k: &str| v.get(k).cloned().unwrap_or_default();
        assert!(check(&observed(&get, &|_| false)).ok());
    }

    #[test]
    fn the_digest_follows_the_settings_not_the_time() {
        let v = managed();
        let get = |k: &str| v.get(k).cloned().unwrap_or_default();
        let a = check(&observed(&get, &|_| false));
        assert_eq!(a.view("2027-01-01T00:00:00Z")["digest"], a.view("2027-04-01T00:00:00Z")["digest"]);
        assert_eq!(a.digest().len(), 64);
        let mut o = observed(&get, &|_| false);
        o.mfa = mfa::Policy::All;
        assert_ne!(check(&o).digest(), a.digest());
    }

    #[test]
    fn values_are_codes_never_secrets_or_addresses() {
        let v = vars(&[("MACHINE_BACKUP_AGE_RECIPIENTS", "age1secretlookingkey"), ("METRICS_LISTEN", "203.0.113.9:9464"), ("METRICS_TOKEN", "t0ps3cr3tt0ps3cr3tt0ps3cr3tt0ps3cr3t")]);
        let get = |k: &str| v.get(k).cloned().unwrap_or_default();
        let r = check(&observed(&get, &|k| !get(k).is_empty()));
        let text = r.view("2027-01-01T00:00:00Z").to_string();
        for leak in ["age1secret", "203.0.113.9", "t0ps3cr3t"] {
            assert!(!text.contains(leak), "{leak} in {text}");
        }
        let audit = r.audit_details().to_string();
        assert!(!audit.contains("age1secret") && !audit.contains("note"), "{audit}");
    }

    /// The rules match the baseline's table setting for setting, in its order, and each
    /// has a rule of its own.
    #[test]
    fn every_setting_in_the_baseline_has_a_rule() {
        let md = include_str!("../../docs/security/configuration-baseline.md");
        let documented: Vec<String> = md
            .lines()
            .filter_map(|l| l.strip_prefix("| `"))
            .flat_map(|first| first.split(" |").next().unwrap_or_default().split(", ").map(|s| s.trim_matches('`').to_string()).collect::<Vec<_>>())
            .collect();
        let ours: Vec<&str> = SETTINGS.iter().map(|(k, _)| *k).collect();
        assert_eq!(documented, ours, "the configuration baseline's table and baseline::SETTINGS differ");
        let get = |_: &str| String::new();
        for (k, _) in SETTINGS {
            assert_ne!(judge(k, &observed(&get, &|_| false)).2, "no rule for this setting", "{k}");
        }
    }
}
