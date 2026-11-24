//! The monthly health check (ADR 0252): each item of `docs/support/health-check.md`'s
//! checklist, judged from what botd holds, for the technical account manager's monthly
//! check of an Enterprise customer. Most items read the 30-day health score (ADR 0144) and
//! its history (ADR 0157); the rest read botd's settings and records: the setup wizard,
//! status page incidents and their review drafts, native SAML certificates, SCIM tokens,
//! custom roles, access reviews, backups, machine restores, residency warnings, run
//! refusals and the license. An item is done, open (the TAM acts on it this month), for a
//! person to confirm (botd can't see it), or not applicable to this server.
//! `GET /api/support/health-check` (admins, audited as `support.health_checked`) and
//! `botctl health-check`.
//!
//! Codes, counts, provider ids and incident ids only: never a person's name or email, an
//! incident's title, an address or a bucket, so the report can go in the customer's record.

use crate::audit::{Filter, Who};
use crate::db::now;
use crate::{AppState, Auth, Res, bad};
use axum::Json;
use axum::extract::{ConnectInfo, Extension, Query, State};
use axum::http::HeaderMap;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

/// Bumped when the report's shape changes.
pub const FORMAT: u32 = 1;
pub const CHECKED: &str = "support.health_checked";
/// What the Google Workspace sync audits each pass as (`scim::google`).
const GOOGLE_SYNC: &str = "scim.google_sync";
const DAY_MS: i64 = 86_400_000;
/// The health score's window, as the checklist runs it.
pub const SCORE_DAYS: i64 = 30;
/// "Last month": the score's history, incidents and machine restores.
pub const MONTH_DAYS: i64 = 31;
/// A native SAML certificate ending within this many days goes in the customer's record.
pub const CERT_DAYS: i64 = 60;
/// A license ending within this many days has its renewal with the account owner.
pub const RENEWAL_DAYS: i64 = 90;
/// "This quarter", for an access review.
pub const QUARTER_DAYS: i64 = 92;
/// Status page impacts whose incidents need a review.
pub const REVIEWED_IMPACTS: [&str; 2] = ["major", "critical"];
/// Run refusals at a plan's limit.
pub const LIMIT_REASONS: [&str; 3] = ["tier_limit", "tier_token_limit", "storage_limit"];
const EGRESS_PENDING: &str = "egress_policy_pending";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    Done,
    /// Something for the TAM to act on this month.
    Open,
    /// botd can't see it; a person confirms it with the customer.
    Confirm,
    NotApplicable,
}

impl Status {
    pub fn as_str(self) -> &'static str {
        match self {
            Status::Done => "done",
            Status::Open => "open",
            Status::Confirm => "confirm",
            Status::NotApplicable => "n/a",
        }
    }
}

pub const SECTIONS: [(&str, &str); 6] = [
    ("score", "1. The score"),
    ("deployment", "2. The deployment"),
    ("identity", "3. Identity"),
    ("data", "4. Data and backups"),
    ("bots", "5. Bots and machines"),
    ("account", "6. The account"),
];

pub struct Item {
    pub id: &'static str,
    pub section: &'static str,
    pub label: &'static str,
    /// How the item's line in health-check.md starts, after `- [ ] `. A test holds the two together.
    #[cfg_attr(not(test), allow(dead_code))]
    pub line: &'static str,
    /// Repo-relative, with an anchor where the page has one.
    pub guide: &'static str,
}

const fn item(id: &'static str, section: &'static str, label: &'static str, line: &'static str, guide: &'static str) -> Item {
    Item { id, section, label, line, guide }
}

/// Every item of the checklist, in its order.
pub const ITEMS: [Item; 22] = [
    item("score", "score", "Health score and band", "`botctl health-score` for the last 30 days", "docs/support/health-score.md"),
    item("trend", "score", "Compared with last month", "Compared with last month's", "docs/support/health-score.md#history"),
    item("actions", "score", "Signals at watch or at risk have an action", "Each signal at risk has a ticket", "docs/support/health-score.md#the-signals"),
    item("version", "deployment", "Version and security releases", "Version:", "CHANGELOG.md"),
    item("setup", "deployment", "Setup still complete", "Setup:", "docs/adr/0034-onboarding-wizard.md"),
    item("incidents", "deployment", "Incidents closed and reviewed", "Status:", "docs/support/incident-review.md#the-review-draft"),
    item("sign_in", "identity", "Sign-in and SCIM failures", "Sign-in:", "docs/support/runbook-sign-in.md"),
    item("saml", "identity", "SAML certificates not ending", "SAML (if used):", "docs/support/runbook-saml.md"),
    item("scim", "identity", "SCIM tokens working", "SCIM (if used):", "docs/sso/scim.md"),
    item("roles", "identity", "Custom roles still needed", "Roles:", "docs/support/runbook-custom-roles.md"),
    item("access_review", "identity", "Access review this quarter", "Access review:", "docs/adr/0099-access-review-report.md"),
    item("backups", "data", "Server backups within their RPO", "`botctl backups`:", "docs/ops/backup-restore.md"),
    item("machine_recovery", "data", "Machines within their RPO and RTO", "`botctl machine recovery` (managed machines):", "docs/ops/machine-recovery.md"),
    item("residency", "data", "No residency warnings", "Residency (if pinned):", "docs/support/runbook-residency.md"),
    item("restore_drill", "data", "Next restore drill booked", "The next restore drill is booked", "docs/support/tam.md#cadence"),
    item("runs", "bots", "Bot runs not failing", "Runs:", "docs/support/runbook-harness-outage.md"),
    item("egress", "bots", "Run limits and allow-lists as agreed", "Run limits and allow-lists (if used):", "docs/support/runbook-run-limits-egress.md"),
    item("approvals", "bots", "Approvals answered", "Approvals:", "docs/support/runbook-approvals-stuck.md"),
    item("usage", "bots", "Nobody held at a plan's limit", "Usage:", "docs/support/tiers.md"),
    item("license", "account", "License end and seats", "License (self-host):", "docs/support/health-score.md#license"),
    item("tickets", "account", "Tickets within their targets", "Tickets:", "docs/support/support-report.md"),
    item("changes", "account", "Changes at the customer", "Anything from the customer since last time:", "docs/support/tam.md#what-a-tam-does"),
];

/// A health score signal as the score's report gives it.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Signal {
    /// `ok`, `watch`, `risk` or `n/a`.
    pub status: String,
    pub summary: String,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Score {
    pub score: Option<u32>,
    /// `healthy`, `watch`, `at_risk` or `unknown`.
    pub band: String,
    pub at_risk: Vec<String>,
    pub watch: Vec<String>,
    /// The audit log keeps less than the score's window.
    pub partial: bool,
    pub identity: Signal,
    pub runs: Signal,
    pub approvals: Signal,
    pub scim_failed: u64,
}

#[derive(Clone, Debug, PartialEq)]
pub enum Trend {
    /// `HEALTH_SCORE_HISTORY_DAYS=0`.
    Off,
    /// Days recorded in the last month, fewer than two.
    Few(usize),
    Read { from_score: Option<u32>, to_score: Option<u32>, worse: Vec<String>, better: Vec<String> },
    Unreadable,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Incidents {
    /// Ids of incidents still open on the status page.
    pub open: Vec<String>,
    /// Incidents resolved in the last month, of any impact.
    pub resolved: usize,
    /// Ids of those of a reviewed impact, open or resolved in the last month, with no review drafted.
    pub unreviewed: Vec<String>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Cert {
    pub provider: String,
    /// `saml_expiry::Role::as_str`.
    pub role: String,
    pub days_left: i64,
    /// Another certificate of the same role outlives `CERT_DAYS`.
    pub covered: bool,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Saml {
    pub providers: usize,
    pub certs: usize,
    /// Certificates in use ending within `CERT_DAYS`.
    pub ending: Vec<Cert>,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Scim {
    pub working_tokens: usize,
    /// A working token was used in the score's window.
    pub used_recently: bool,
    pub tenants_expiring: usize,
    /// GOOGLE_DIRECTORY_SYNC=on: its tenant takes no SCIM token, so its passes stand in for one.
    pub google: Option<GoogleSync>,
}

/// The Google Workspace sync's passes in the score's window, from the audit log.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct GoogleSync {
    /// Why the latest pass didn't succeed, when it didn't.
    pub last_failed: Option<String>,
    pub passed_recently: bool,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct ServerBackups {
    pub off_host: bool,
    pub breach: bool,
    pub age_hours: Option<i64>,
    pub rpo_hours: i64,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Machines {
    pub rpo_breaches: usize,
    pub backups_failed: u64,
    /// Restores asked for in the last month, and how many took longer than their RTO.
    pub restores: usize,
    pub restores_past_rto: usize,
    /// Days since the newest restore botd recorded, if any.
    pub last_restore_days: Option<i64>,
    /// Runs refused while a machine's egress policy was still being applied, and runs held to run limits.
    pub egress_pending: u64,
    pub run_limited: u64,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct License {
    pub mode: String,
    pub usable: bool,
    pub seats_used: u64,
    pub seat_cap: Option<u64>,
    pub days_left: Option<i64>,
}

/// Everything the check reads, so judging is a pure function.
#[derive(Clone, Debug, PartialEq)]
pub struct Inputs {
    pub score: Score,
    pub trend: Trend,
    pub version: String,
    /// The setup wizard's checklist items not done.
    pub setup_open: Vec<String>,
    pub incidents: Incidents,
    /// None when no native SAML provider is set up.
    pub saml: Option<Saml>,
    /// None when SCIM is off.
    pub scim: Option<Scim>,
    pub custom_roles: usize,
    /// Active people holding a custom role across the server, and how many of those end.
    pub role_holders: usize,
    pub role_holders_time_bound: usize,
    /// Days since the newest `access_review.completed`, if any.
    pub access_review_days: Option<i64>,
    /// None when botd doesn't make server backups.
    pub server_backups: Option<ServerBackups>,
    /// None when botd runs no users' machines.
    pub machines: Option<Machines>,
    /// None when the server offers no data regions; else its residency warnings.
    pub residency_warnings: Option<usize>,
    pub approvals_ask: bool,
    /// Run refusals at a plan's limit in the score's window, by reason.
    pub limit_refusals: Vec<(String, u64)>,
    pub token_limits_reached: u64,
    /// None in testing mode with no license.
    pub license: Option<License>,
}

impl Default for Inputs {
    fn default() -> Self {
        Inputs {
            score: Score::default(),
            trend: Trend::Off,
            version: String::new(),
            setup_open: Vec::new(),
            incidents: Incidents::default(),
            saml: None,
            scim: None,
            custom_roles: 0,
            role_holders: 0,
            role_holders_time_bound: 0,
            access_review_days: None,
            server_backups: None,
            machines: None,
            residency_warnings: None,
            approvals_ask: true,
            limit_refusals: Vec::new(),
            token_limits_reached: 0,
            license: None,
        }
    }
}

fn plural(n: u64, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
}

fn list(ids: &[String]) -> String {
    ids.join(", ")
}

/// `s` with its first letter in capitals.
fn sentence(s: &str) -> String {
    let mut c = s.chars();
    c.next().map_or_else(String::new, |f| f.to_uppercase().chain(c).collect())
}

fn band_words(b: &str) -> &str {
    match b {
        "at_risk" => "at risk",
        b => b,
    }
}

/// A health score signal as an item: at watch or at risk is open, ok is done, nothing to judge doesn't apply.
fn from_signal(s: &Signal, then: &str) -> (Status, String) {
    match s.status.as_str() {
        "risk" => (Status::Open, format!("At risk. {} {then}", s.summary)),
        "watch" => (Status::Open, format!("Worth a look. {} {then}", s.summary)),
        "ok" => (Status::Done, s.summary.clone()),
        _ => (Status::NotApplicable, s.summary.clone()),
    }
}

fn role_words(role: &str) -> &str {
    match role {
        "sp_signing" => "SuperBot's signing certificate",
        "sp_encryption" => "SuperBot's encryption certificate",
        "idp_signing" => "the IdP's signing certificate",
        "metadata_signing" => "the metadata signing certificate",
        _ => "a certificate",
    }
}

/// One item's status and what botd saw.
fn judge(id: &str, i: &Inputs) -> (Status, String) {
    use Status::*;
    let s = &i.score;
    match id {
        "score" => {
            let partial = if s.partial { " The audit log keeps less than 30 days, so some signals see less." } else { "" };
            let shown = s.score.map_or("no score".to_string(), |n| format!("Score {n}"));
            match s.band.as_str() {
                "healthy" => (Done, format!("{shown}, healthy: no signal at risk.{partial}")),
                "watch" | "at_risk" => {
                    let mut parts = Vec::new();
                    if !s.at_risk.is_empty() {
                        parts.push(format!("at risk: {}", list(&s.at_risk)));
                    }
                    if !s.watch.is_empty() {
                        parts.push(format!("worth a look: {}", list(&s.watch)));
                    }
                    (Open, format!("{shown}, {}; {}.{partial}", band_words(&s.band), parts.join("; ")))
                }
                _ => (Confirm, format!("botd has nothing to judge the score by yet.{partial}")),
            }
        }
        "trend" => match &i.trend {
            Trend::Off => (Confirm, "botd doesn't record the score (HEALTH_SCORE_HISTORY_DAYS=0): compare with last month's in the customer's record.".into()),
            Trend::Few(n) => (
                Confirm,
                format!("botd recorded {} in the last {MONTH_DAYS} days, too few for a trend: compare with last month's in the customer's record.", plural(*n as u64, "day", "days")),
            ),
            Trend::Unreadable => (Confirm, "botd couldn't read the score's history: see botctl health-score history.".into()),
            Trend::Read { from_score, to_score, worse, better } => {
                let score = |n: &Option<u32>| n.map_or("no score".to_string(), |n| n.to_string());
                let moved = format!("Score from {} to {} over the last {MONTH_DAYS} days", score(from_score), score(to_score));
                let better = if better.is_empty() { String::new() } else { format!(" Better: {}.", list(better)) };
                if worse.is_empty() {
                    (Done, format!("{moved}; no signal got worse.{better}"))
                } else {
                    (Open, format!("{moved}; worse: {}. Find out why.{better}", list(worse)))
                }
            }
        },
        "actions" => {
            let mut parts = Vec::new();
            if !s.at_risk.is_empty() {
                parts.push(format!("{} at risk has a ticket or an action with an owner and a date", list(&s.at_risk)));
            }
            if !s.watch.is_empty() {
                parts.push(format!("{} worth a look is on the next check-in's agenda", list(&s.watch)));
            }
            if parts.is_empty() { (Done, "No signal is at watch or at risk.".into()) } else { (Confirm, format!("Confirm {}.", parts.join(", and "))) }
        }
        "version" => (
            Confirm,
            format!("botd {}. botd can't see newer releases: check the changelog for a security fix since, and agree an upgrade window if there is one.", i.version),
        ),
        "setup" => match i.setup_open.is_empty() {
            true => (Done, "Every item of botctl setup is done.".into()),
            false => (Open, format!("Open in botctl setup: {}.", list(&i.setup_open))),
        },
        "incidents" => {
            let c = &i.incidents;
            let mut open = Vec::new();
            if !c.open.is_empty() {
                open.push(format!("still open on the status page: {}", list(&c.open)));
            }
            if !c.unreviewed.is_empty() {
                open.push(format!("of major or critical impact with no review drafted: {} (botctl incident review)", list(&c.unreviewed)));
            }
            if open.is_empty() {
                (Done, format!("No open incident; {} resolved in the last {MONTH_DAYS} days, each major or critical one with a review drafted.", plural(c.resolved as u64, "incident", "incidents")))
            } else {
                (Open, format!("{}.", sentence(&open.join("; "))))
            }
        }
        "sign_in" => from_signal(&s.identity, "See the score's identity reasons and the sign-in or SAML runbook."),
        "saml" => match &i.saml {
            None => (NotApplicable, "No native SAML provider.".into()),
            Some(m) => {
                let ending = |covered: bool| -> Vec<String> {
                    m.ending.iter().filter(|c| c.covered == covered).map(|c| format!("{}'s {} in {}", c.provider, role_words(&c.role), plural(c.days_left.max(0) as u64, "day", "days"))).collect()
                };
                let (bare, covered) = (ending(false), ending(true));
                let of = format!("{} across {}", plural(m.certs as u64, "certificate", "certificates"), plural(m.providers as u64, "provider", "providers"));
                if !bare.is_empty() {
                    (Open, format!("Ending within {CERT_DAYS} days with nothing to replace it: {}. Record who rotates each (botctl sso saml <provider>).", bare.join("; ")))
                } else if !covered.is_empty() {
                    (Done, format!("{of}; ending within {CERT_DAYS} days, each with a newer one already in use: {}.", covered.join("; ")))
                } else {
                    (Done, format!("{of}; none ends within {CERT_DAYS} days."))
                }
            }
        },
        "scim" => match &i.scim {
            None => (NotApplicable, "SCIM is off.".into()),
            Some(Scim { google: Some(GoogleSync { last_failed: Some(why), .. }), .. }) => {
                (Open, format!("The Google Workspace sync's latest pass didn't succeed ({why}): botctl scim google."))
            }
            Some(Scim { google: Some(GoogleSync { passed_recently: false, .. }), .. }) => {
                (Open, format!("The Google Workspace sync has no successful pass in the last {SCORE_DAYS} days: botctl scim google."))
            }
            Some(c) if c.working_tokens == 0 && c.google.is_none() => (Open, "SCIM is on, but no tenant has a working token: botctl scim token create.".into()),
            Some(c) if c.tenants_expiring > 0 => {
                (Open, format!("Every token of {} ends within {} days: botctl scim token rotate.", plural(c.tenants_expiring as u64, "tenant", "tenants"), crate::scim::WARN_DAYS))
            }
            Some(c) if c.working_tokens > 0 && !c.used_recently => (Open, format!("No SCIM request in the last {SCORE_DAYS} days: check provisioning is still on at the identity provider.")),
            Some(_) if s.scim_failed > 0 => (
                Open,
                format!("{} failed in the last {SCORE_DAYS} days: see the score's identity reasons and the IdP's provisioning log.", plural(s.scim_failed, "SCIM request", "SCIM requests")),
            ),
            Some(c) => {
                let mut sources = Vec::new();
                if c.google.is_some() {
                    sources.push("The Google Workspace sync passing".to_string());
                }
                if c.working_tokens > 0 {
                    sources.push(format!("{}, used", plural(c.working_tokens as u64, "working token", "working tokens")));
                }
                (
                    Confirm,
                    format!(
                        "{} in the last {SCORE_DAYS} days, and no request failed: confirm the IdP's provisioning log shows no errors and people who left are disabled.",
                        sentence(&sources.join("; "))
                    ),
                )
            }
        },
        "roles" => match i.custom_roles {
            0 => (Confirm, "No custom roles: confirm the built-in roles (botctl roles) are what the customer expects.".into()),
            n => (
                Confirm,
                format!(
                    "{}; {} one across the server, {} time-bound: confirm each still needs it.",
                    plural(n as u64, "custom role", "custom roles"),
                    plural(i.role_holders as u64, "person holds", "people hold"),
                    i.role_holders_time_bound
                ),
            ),
        },
        "access_review" => match i.access_review_days {
            Some(d) if d <= QUARTER_DAYS => (Done, format!("An access review was signed off {} ago.", plural(d as u64, "day", "days"))),
            Some(d) => (Confirm, format!("The last access review was signed off {d} days ago: if the customer's policy asks for one each quarter, it's due.")),
            None => (Confirm, "botd has no access review signed off: if the customer's policy asks for one each quarter, it's due.".into()),
        },
        "backups" => match &i.server_backups {
            None => (Open, "botd doesn't make server backups: see botctl backups.".into()),
            Some(b) if !b.off_host => (Open, "Server backups stay on this host: set SERVER_BACKUP_S3_BUCKET to copy them off.".into()),
            Some(b) if b.breach => (Open, format!("The newest copy off the host is past its RPO of {} hours: see botctl backups.", b.rpo_hours)),
            Some(b) => match b.age_hours {
                None => (Open, "Copies are set up, but none has been made yet: see botctl backups.".into()),
                Some(h) => (Done, format!("The newest copy off the host is {} old, within its RPO of {} hours.", plural(h as u64, "hour", "hours"), b.rpo_hours)),
            },
        },
        "machine_recovery" => match &i.machines {
            None => (NotApplicable, "This server runs no users' machines.".into()),
            Some(m) => {
                let mut open = Vec::new();
                if m.rpo_breaches > 0 {
                    open.push(format!("{} past {} RPO", plural(m.rpo_breaches as u64, "machine is", "machines are"), if m.rpo_breaches == 1 { "its" } else { "their" }));
                }
                if m.restores_past_rto > 0 {
                    open.push(format!("{} of {} in the last {MONTH_DAYS} days took longer than the RTO", m.restores_past_rto, plural(m.restores as u64, "restore", "restores")));
                }
                if m.backups_failed > 0 {
                    open.push(format!("{} failed in the last {SCORE_DAYS} days", plural(m.backups_failed, "machine backup", "machine backups")));
                }
                if open.is_empty() {
                    (Done, format!("No machine is past its RPO; {} in the last {MONTH_DAYS} days, none past the RTO.", plural(m.restores as u64, "restore", "restores")))
                } else {
                    (Open, format!("{}: see botctl machine recovery.", sentence(&open.join("; "))))
                }
            }
        },
        "residency" => match i.residency_warnings {
            None => (NotApplicable, "This server offers no data regions (MACHINE_REGIONS).".into()),
            Some(0) => (Done, "No residency warnings.".into()),
            Some(n) => (Open, format!("{}: see botctl regions.", plural(n as u64, "residency warning", "residency warnings"))),
        },
        "restore_drill" => {
            let last = match i.machines.as_ref().and_then(|m| m.last_restore_days) {
                Some(d) => format!(" The newest machine restore botd recorded was {} ago.", plural(d as u64, "day", "days")),
                None => String::new(),
            };
            (Confirm, format!("botd can't see bookings: confirm the next server and machine restore drill is booked.{last}"))
        }
        "runs" => from_signal(&s.runs, "See the score's results by harness and the harness runbook."),
        "egress" => match &i.machines {
            None => (NotApplicable, "This server runs no users' machines.".into()),
            Some(m) if m.egress_pending > 0 => (
                Open,
                format!("{} refused in the last {SCORE_DAYS} days while a machine's egress policy was still being applied: see botctl machine egress.", plural(m.egress_pending, "run was", "runs were")),
            ),
            Some(m) => (
                Confirm,
                format!(
                    "No run refused for a pending egress policy; {} held to run limits in the last {SCORE_DAYS} days. Confirm botctl machine egress is what the customer agreed.",
                    plural(m.run_limited, "run", "runs")
                ),
            ),
        },
        "approvals" => match (i.approvals_ask, s.approvals.status.as_str()) {
            (false, _) => (Open, "Approvals are off (bypass): Bots run risky actions without asking. Confirm that's what the customer wants, or set the policy to ask.".into()),
            (true, "risk" | "watch") => from_signal(&s.approvals, "See the approvals runbook."),
            (true, _) => (Confirm, format!("{} Confirm the policy (botctl policy) still fits how they work.", s.approvals.summary)),
        },
        "usage" => {
            let refused: u64 = i.limit_refusals.iter().map(|(_, n)| n).sum();
            if refused == 0 && i.token_limits_reached == 0 {
                return (Done, format!("No run was refused at a plan's limit in the last {SCORE_DAYS} days."));
            }
            let mut parts = Vec::new();
            if refused > 0 {
                let by: Vec<String> = i.limit_refusals.iter().filter(|(_, n)| *n > 0).map(|(r, n)| format!("{r} {n}")).collect();
                parts.push(format!("{} refused at a plan's limit ({})", plural(refused, "run was", "runs were"), by.join(", ")));
            }
            if i.token_limits_reached > 0 {
                parts.push(format!("a monthly token limit was reached {}", plural(i.token_limits_reached, "time", "times")));
            }
            (Open, format!("In the last {SCORE_DAYS} days, {}: see botctl usage for who, and whether they need another plan.", parts.join("; ")))
        }
        "license" => match &i.license {
            None => (NotApplicable, "Testing mode, with no license installed.".into()),
            Some(l) => {
                let seats = match l.seat_cap {
                    Some(cap) => format!("{} of {cap} seats in use", l.seats_used),
                    None => format!("{} in use, no seat limit", plural(l.seats_used, "seat", "seats")),
                };
                let full = l.seat_cap.is_some_and(|cap| l.seats_used * 100 >= cap * crate::health_score::SEATS_WATCH);
                match l.days_left {
                    _ if !l.usable => (Open, format!("There's no usable license, so Bots don't run ({}): see botctl license; {seats}.", l.mode)),
                    _ if l.mode == "grace" => (Open, format!("The license has ended and is in its grace period: the renewal is with the account owner; {seats}.")),
                    Some(d) if d < RENEWAL_DAYS => (Open, format!("The license ends in {}: the renewal is with the account owner; {seats}.", plural(d.max(0) as u64, "day", "days"))),
                    _ if full => (Open, format!("{seats}: talk about seats with the account owner.")),
                    Some(d) => (Done, format!("The license has {} left; {seats}.", plural(d as u64, "day", "days"))),
                    None => (Done, format!("The license doesn't end; {seats}.")),
                }
            }
        },
        "tickets" => (Confirm, "Kept in the ticket system, which botd can't see: run botctl support-report on its export for the customer.".into()),
        "changes" => (Confirm, "Ask the customer about changes to their IdP, network, team or plans.".into()),
        _ => (Confirm, "No rule for this item.".into()),
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Judged {
    pub id: &'static str,
    pub status: Status,
    pub detail: String,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Report {
    pub score: Option<u32>,
    pub band: String,
    pub items: Vec<Judged>,
}

/// Every item judged.
pub fn check(i: &Inputs) -> Report {
    Report { score: i.score.score, band: i.score.band.clone(), items: ITEMS.iter().map(|it| { let (status, detail) = judge(it.id, i); Judged { id: it.id, status, detail } }).collect() }
}

impl Report {
    pub fn count(&self, s: Status) -> usize {
        self.items.iter().filter(|j| j.status == s).count()
    }

    fn ids(&self, s: Status) -> Vec<&'static str> {
        self.items.iter().filter(|j| j.status == s).map(|j| j.id).collect()
    }

    /// Nothing open: everything is done, doesn't apply, or is for a person to confirm.
    pub fn clear(&self) -> bool {
        self.count(Status::Open) == 0
    }

    pub fn counts(&self) -> Value {
        json!({ "done": self.count(Status::Done), "open": self.count(Status::Open), "confirm": self.count(Status::Confirm), "notApplicable": self.count(Status::NotApplicable) })
    }

    pub fn view(&self, checked_at: &str) -> Value {
        let items: Vec<Value> = self
            .items
            .iter()
            .zip(ITEMS.iter())
            .map(|(j, it)| json!({ "id": j.id, "section": it.section, "label": it.label, "status": j.status.as_str(), "detail": j.detail, "guide": it.guide }))
            .collect();
        json!({
            "format": FORMAT,
            "checkedAt": checked_at,
            "checklist": "docs/support/health-check.md",
            "windowDays": SCORE_DAYS,
            "score": self.score,
            "band": self.band,
            "clear": self.clear(),
            "counts": self.counts(),
            "open": self.ids(Status::Open),
            "sections": SECTIONS.iter().map(|(id, title)| json!({ "id": id, "title": title })).collect::<Vec<_>>(),
            "items": items,
        })
    }

    /// What `support.health_checked` records: the score, counts and item ids only.
    pub fn audit_details(&self) -> Value {
        json!({ "score": self.score, "band": self.band, "clear": self.clear(), "counts": self.counts(), "open": self.ids(Status::Open) })
    }
}

fn strings(v: &Value) -> Vec<String> {
    v.as_array().into_iter().flatten().filter_map(|s| s.as_str().map(String::from)).collect()
}

/// The parts of the health score's report (ADR 0144) the check reads.
pub fn score_of(r: &Value) -> Score {
    let signal = |id: &str| r["signals"].as_array().into_iter().flatten().find(|s| s["id"] == id).cloned().unwrap_or(Value::Null);
    let as_signal = |s: &Value| Signal { status: s["status"].as_str().unwrap_or("n/a").into(), summary: s["summary"].as_str().unwrap_or_default().into() };
    let identity = signal("identity");
    Score {
        score: r["score"].as_u64().and_then(|s| u32::try_from(s).ok()),
        band: r["band"].as_str().unwrap_or("unknown").into(),
        at_risk: strings(&r["atRisk"]),
        watch: strings(&r["watch"]),
        partial: r["partial"] == true,
        identity: as_signal(&identity),
        runs: as_signal(&signal("runs")),
        approvals: as_signal(&signal("approvals")),
        scim_failed: identity["facts"]["scimFailed"].as_u64().unwrap_or(0),
    }
}

/// The trend across the score's history (ADR 0157) for the last month.
pub fn trend_of(h: Option<&Value>) -> Trend {
    let Some(h) = h else { return Trend::Unreadable };
    if h["recording"] != true {
        return Trend::Off;
    }
    let t = &h["trend"];
    if t.is_null() {
        return Trend::Few(h["points"].as_array().map_or(0, Vec::len));
    }
    let score = |v: &Value| v.as_u64().and_then(|s| u32::try_from(s).ok());
    Trend::Read { from_score: score(&t["fromScore"]), to_score: score(&t["toScore"]), worse: strings(&t["worse"]), better: strings(&t["better"]) }
}

fn days_since(ms: i64, now_ms: i64) -> i64 {
    (now_ms - ms).max(0) / DAY_MS
}

/// The inputs, from the health score, its history, the database, botd's settings and the setup wizard's checklist.
pub fn gather(app: &AppState, a: &Auth, setup: &Value, now_ms: i64) -> Inputs {
    let report = crate::health_score::build(app, now_ms, SCORE_DAYS);
    let score = score_of(&report);
    let history = crate::health_history::history(app, now_ms, MONTH_DAYS).ok();
    let month = now_ms - MONTH_DAYS * DAY_MS;
    let window = now_ms - SCORE_DAYS * DAY_MS;

    let incidents = app.db.status_incidents(month, 1000, 0).unwrap_or_default();
    let from = incidents.iter().map(|i| i.created_at).min().unwrap_or(month);
    let reviewed: std::collections::HashSet<String> = app
        .db
        .audit_events(&Filter { from: Some(from), actions: vec!["status.incident_reviewed".into()], ..Default::default() }, 10_000, false)
        .into_iter()
        .filter_map(|e| e.target_id)
        .collect();
    let incidents = Incidents {
        open: incidents.iter().filter(|i| i.resolved_at.is_none()).map(|i| i.id.clone()).collect(),
        resolved: incidents.iter().filter(|i| i.resolved_at.is_some()).count(),
        unreviewed: incidents.iter().filter(|i| REVIEWED_IMPACTS.contains(&i.impact.as_str()) && !reviewed.contains(&i.id)).map(|i| i.id.clone()).collect(),
    };

    let samls: Vec<&Arc<crate::sso::Provider>> = a.sso.providers.iter().filter(|p| p.saml_sp()).collect();
    let saml = (!samls.is_empty()).then(|| {
        let mut m = Saml { providers: samls.len(), ..Default::default() };
        let end = now_ms + CERT_DAYS * DAY_MS;
        for p in samls {
            let certs = crate::sso::saml_expiry::certificates(app, p);
            m.certs += certs.len();
            let ends_soon = |c: &crate::sso::saml_expiry::InUse| c.cert.not_after.saturating_mul(1000) <= end;
            for c in certs.iter().filter(|c| ends_soon(c)) {
                let covered = certs.iter().any(|o| o.role == c.role && o.cert.sha256 != c.cert.sha256 && !ends_soon(o));
                m.ending.push(Cert { provider: p.id.clone(), role: c.role.as_str().into(), days_left: crate::sso::saml_expiry::days_left(c.cert.not_after, now_ms), covered });
            }
        }
        m
    });

    let scim = a.scim.enabled.then(|| {
        let tokens = app.db.scim_tokens();
        let working = |t: &&crate::db::ScimToken| !matches!(crate::scim::token_state(t, now_ms), "revoked" | "expired");
        Scim {
            working_tokens: tokens.iter().filter(working).count(),
            used_recently: tokens.iter().filter(working).any(|t| t.last_used_at.is_some_and(|u| u >= window)),
            tenants_expiring: crate::scim::tenants_expiring(&tokens, now_ms).len(),
            google: a.scim.google.as_ref().map(|_| {
                let passes = |outcome: Option<&str>| {
                    let f = Filter { from: Some(window), actions: vec![GOOGLE_SYNC.into()], outcome: outcome.map(String::from), ..Default::default() };
                    app.db.audit_events(&f, 1, false)
                };
                let last_failed = passes(None).into_iter().next().filter(|e| e.outcome != "success").map(|e| match e.details["reason"].as_str() {
                    Some(r) => r.to_string(),
                    None => plural(e.details["failed"].as_u64().unwrap_or(0), "write failed", "writes failed"),
                });
                GoogleSync { last_failed, passed_recently: !passes(Some("success")).is_empty() }
            }),
        }
    });

    let users = app.db.users();
    let holders: Vec<&crate::db::User> = users.iter().filter(|u| u.active() && u.role_id.is_some()).collect();
    let access_review = app.db.audit_events(&Filter { actions: vec![crate::access_review::COMPLETED.into()], ..Default::default() }, 1, false);

    let counts = app.db.audit_counts(window, &["bot.run_refused", "machine.run_limited", "usage.token_limit_reached"]);
    let count = |action: &str, code: Option<&str>| -> u64 { counts.iter().filter(|c| c.action == action && code.is_none_or(|k| c.code.as_deref() == Some(k))).map(|c| c.n).sum() };

    let fact = |id: &str| report["signals"].as_array().into_iter().flatten().find(|s| s["id"] == id).map(|s| s["facts"].clone()).unwrap_or(Value::Null);
    let backups = fact("backups");
    let server_backups = backups["server"].as_object().map(|s| ServerBackups {
        off_host: s.get("offHost") == Some(&json!(true)),
        breach: s.get("breach") == Some(&json!(true)),
        age_hours: s.get("ageHours").and_then(Value::as_i64),
        rpo_hours: s.get("rpoHours").and_then(Value::as_i64).unwrap_or_default(),
    });
    let cp = &a.machines;
    let machines = cp.enabled().then(|| {
        let restores = app.db.machine_restores_recent(1000);
        let month_restores: Vec<&crate::db::MachineRestore> = restores.iter().filter(|r| r.created_at >= month).collect();
        Machines {
            rpo_breaches: app.db.machine_rpo_breaches_open().len(),
            backups_failed: backups["machineBackupsFailed"].as_u64().unwrap_or(0),
            restores: month_restores.len(),
            restores_past_rto: month_restores.iter().filter(|r| r.rto_exceeded_at.is_some()).count(),
            last_restore_days: restores.first().map(|r| days_since(r.created_at, now_ms)),
            egress_pending: count("bot.run_refused", Some(EGRESS_PENDING)),
            run_limited: count("machine.run_limited", None),
        }
    });
    let license = fact("license");
    let license = license.is_object().then(|| License {
        mode: license["mode"].as_str().unwrap_or_default().into(),
        usable: license["usable"] == true,
        seats_used: license["seatsUsed"].as_u64().unwrap_or(0),
        seat_cap: license["seats"].as_u64(),
        days_left: license["daysLeft"].as_i64(),
    });

    Inputs {
        score,
        trend: trend_of(history.as_ref()),
        version: env!("CARGO_PKG_VERSION").into(),
        setup_open: setup["checklist"].as_array().into_iter().flatten().filter(|c| c["done"] != true).filter_map(|c| c["id"].as_str().map(String::from)).collect(),
        incidents,
        saml,
        scim,
        custom_roles: app.db.custom_roles().len(),
        role_holders: holders.len(),
        role_holders_time_bound: holders.iter().filter(|u| u.role_expires_at.is_some()).count(),
        access_review_days: access_review.first().map(|e| days_since(e.at, now_ms)),
        server_backups,
        machines,
        residency_warnings: (cp.enabled() && !cp.regions.is_empty()).then(|| crate::machines::residency::warnings(app, cp).len()),
        approvals_ask: app.db.global_policy().mode == crate::policy::Mode::Ask,
        limit_refusals: LIMIT_REASONS.iter().map(|r| (r.to_string(), count("bot.run_refused", Some(r)))).collect(),
        token_limits_reached: count("usage.token_limit_reached", None),
        license,
    }
}

fn rfc3339(ms: i64) -> String {
    chrono::DateTime::from_timestamp_millis(ms).map(|t| t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)).unwrap_or_default()
}

type Peer = Option<Extension<ConnectInfo<SocketAddr>>>;

/// `GET /api/support/health-check` (admins): each item of the monthly health check.
/// Audited, so the TAM's monthly checks show in the log.
pub async fn get(
    State(app): State<AppState>,
    Extension(a): Extension<Arc<Auth>>,
    Extension(by): Extension<Who>,
    Query(q): Query<HashMap<String, String>>,
    headers: HeaderMap,
    peer: Peer,
) -> Res {
    if let Some(k) = q.keys().next() {
        let shown = if k.len() <= 40 && k.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') { k.as_str() } else { "[text]" };
        return Err(bad(format!("Unknown parameter \"{shown}\". The health check takes none: it covers the last {SCORE_DAYS} days.")));
    }
    let peer: Option<IpAddr> = peer.map(|Extension(ConnectInfo(p))| p.ip());
    let setup = crate::setup::report(&app, &a, &headers, peer);
    let now_ms = now();
    let r = {
        let (app, a) = (app.clone(), a.clone());
        tokio::task::spawn_blocking(move || check(&gather(&app, &a, &setup, now_ms)))
            .await
            .map_err(|e| crate::ApiError(axum::http::StatusCode::INTERNAL_SERVER_ERROR, format!("Couldn't run the health check: {e}")))?
    };
    app.db.record(&by.event(CHECKED).target("setup", "server").details(r.audit_details()));
    Ok(Json(r.view(&rfc3339(now_ms))))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signal(status: &str, summary: &str) -> Signal {
        Signal { status: status.into(), summary: summary.into() }
    }

    /// A healthy Enterprise customer: SSO and SCIM working, machines with backups and
    /// regions, nothing botd can see out of place.
    fn healthy() -> Inputs {
        Inputs {
            score: Score {
                score: Some(96),
                band: "healthy".into(),
                at_risk: Vec::new(),
                watch: Vec::new(),
                partial: false,
                identity: signal("ok", "In the last 30 days, 2 of 102 single sign-on attempts (2%) failed; 0 SCIM requests failed."),
                runs: signal("ok", "4 of 200 runs (2%) failed or timed out in the last 30 days."),
                approvals: signal("ok", "2 of 50 approvals (4%) expired unanswered in the last 30 days; 0 waiting now."),
                scim_failed: 0,
            },
            trend: Trend::Read { from_score: Some(92), to_score: Some(96), worse: Vec::new(), better: vec!["adoption".into()] },
            version: "0.1.0".into(),
            setup_open: Vec::new(),
            incidents: Incidents { open: Vec::new(), resolved: 1, unreviewed: Vec::new() },
            saml: Some(Saml { providers: 1, certs: 3, ending: Vec::new() }),
            scim: Some(Scim { working_tokens: 1, used_recently: true, ..Default::default() }),
            custom_roles: 2,
            role_holders: 3,
            role_holders_time_bound: 1,
            access_review_days: Some(40),
            server_backups: Some(ServerBackups { off_host: true, breach: false, age_hours: Some(3), rpo_hours: 26 }),
            machines: Some(Machines { restores: 1, last_restore_days: Some(12), run_limited: 2, ..Default::default() }),
            residency_warnings: Some(0),
            approvals_ask: true,
            limit_refusals: LIMIT_REASONS.iter().map(|r| (r.to_string(), 0)).collect(),
            token_limits_reached: 0,
            license: Some(License { mode: "active".into(), usable: true, seats_used: 40, seat_cap: Some(60), days_left: Some(200) }),
        }
    }

    fn status(r: &Report, id: &str) -> (Status, String) {
        let j = r.items.iter().find(|j| j.id == id).unwrap_or_else(|| panic!("no {id}"));
        (j.status, j.detail.clone())
    }

    fn of(r: &Report, s: Status) -> Vec<&'static str> {
        r.items.iter().filter(|j| j.status == s).map(|j| j.id).collect()
    }

    #[test]
    fn items_are_unique_and_in_known_sections() {
        let ids: std::collections::HashSet<_> = ITEMS.iter().map(|i| i.id).collect();
        assert_eq!(ids.len(), ITEMS.len());
        for it in &ITEMS {
            assert!(SECTIONS.iter().any(|(s, _)| *s == it.section), "{}", it.id);
            assert_ne!(judge(it.id, &healthy()).1, "No rule for this item.", "{}", it.id);
        }
    }

    #[test]
    fn a_healthy_customer_has_nothing_open() {
        let r = check(&healthy());
        assert!(r.clear(), "{:#?}", of(&r, Status::Open));
        assert_eq!(of(&r, Status::Confirm), ["version", "scim", "roles", "restore_drill", "egress", "approvals", "tickets", "changes"]);
        assert_eq!(status(&r, "score").1, "Score 96, healthy: no signal at risk.");
        assert_eq!(status(&r, "trend").1, "Score from 92 to 96 over the last 31 days; no signal got worse. Better: adoption.");
        assert_eq!(status(&r, "incidents").1, "No open incident; 1 incident resolved in the last 31 days, each major or critical one with a review drafted.");
        assert_eq!(status(&r, "saml").1, "3 certificates across 1 provider; none ends within 60 days.");
        assert_eq!(status(&r, "roles").1, "2 custom roles; 3 people hold one across the server, 1 time-bound: confirm each still needs it.");
        assert_eq!(status(&r, "access_review"), (Status::Done, "An access review was signed off 40 days ago.".into()));
        assert_eq!(status(&r, "backups").1, "The newest copy off the host is 3 hours old, within its RPO of 26 hours.");
        assert_eq!(status(&r, "machine_recovery").1, "No machine is past its RPO; 1 restore in the last 31 days, none past the RTO.");
        assert!(status(&r, "restore_drill").1.ends_with("The newest machine restore botd recorded was 12 days ago."));
        assert_eq!(status(&r, "license").1, "The license has 200 days left; 40 of 60 seats in use.");
        assert_eq!(r.count(Status::Done), ITEMS.len() - 8);
    }

    #[test]
    fn a_new_server_shows_what_to_look_at() {
        let i = Inputs { score: Score { score: Some(50), band: "watch".into(), watch: vec!["backups".into()], ..Default::default() }, ..Default::default() };
        let r = check(&i);
        assert!(!r.clear());
        assert_eq!(of(&r, Status::Open), ["score", "backups"]);
        assert_eq!(of(&r, Status::NotApplicable), ["sign_in", "saml", "scim", "machine_recovery", "residency", "runs", "egress", "license"]);
        assert_eq!(status(&r, "score").1, "Score 50, watch; worth a look: backups.");
        assert_eq!(status(&r, "trend").0, Status::Confirm, "no history recorded");
        assert_eq!(status(&r, "actions").1, "Confirm backups worth a look is on the next check-in's agenda.");
    }

    #[test]
    fn the_score_and_its_trend() {
        let mut i = healthy();
        i.score.band = "at_risk".into();
        i.score.score = Some(45);
        i.score.at_risk = vec!["backups".into(), "license".into()];
        i.score.watch = vec!["runs".into()];
        i.score.partial = true;
        let r = check(&i);
        assert_eq!(
            status(&r, "score"),
            (Status::Open, "Score 45, at risk; at risk: backups, license; worth a look: runs. The audit log keeps less than 30 days, so some signals see less.".into())
        );
        assert_eq!(
            status(&r, "actions"),
            (Status::Confirm, "Confirm backups, license at risk has a ticket or an action with an owner and a date, and runs worth a look is on the next check-in's agenda.".into())
        );
        i.trend = Trend::Read { from_score: Some(80), to_score: Some(45), worse: vec!["backups".into(), "license".into()], better: Vec::new() };
        assert_eq!(status(&check(&i), "trend"), (Status::Open, "Score from 80 to 45 over the last 31 days; worse: backups, license. Find out why.".into()));
        i.trend = Trend::Few(1);
        assert!(status(&check(&i), "trend").1.starts_with("botd recorded 1 day in the last 31 days"));
        i.trend = Trend::Unreadable;
        assert_eq!(status(&check(&i), "trend").0, Status::Confirm);
    }

    #[test]
    fn open_and_unreviewed_incidents_are_open() {
        let mut i = healthy();
        i.incidents = Incidents { open: vec!["inc_a1".into()], resolved: 2, unreviewed: vec!["inc_b2".into()] };
        assert_eq!(
            status(&check(&i), "incidents"),
            (Status::Open, "Still open on the status page: inc_a1; of major or critical impact with no review drafted: inc_b2 (botctl incident review).".into())
        );
        i.incidents.open.clear();
        assert!(status(&check(&i), "incidents").1.starts_with("Of major or critical impact"));
    }

    #[test]
    fn saml_certificates_ending_without_a_replacement_are_open() {
        let mut i = healthy();
        let cert = |role: &str, days: i64, covered: bool| Cert { provider: "okta".into(), role: role.into(), days_left: days, covered };
        i.saml.as_mut().unwrap().ending = vec![cert("idp_signing", 21, true)];
        assert_eq!(
            status(&check(&i), "saml"),
            (Status::Done, "3 certificates across 1 provider; ending within 60 days, each with a newer one already in use: okta's the IdP's signing certificate in 21 days.".into())
        );
        i.saml.as_mut().unwrap().ending.push(cert("sp_signing", 1, false));
        assert_eq!(
            status(&check(&i), "saml"),
            (Status::Open, "Ending within 60 days with nothing to replace it: okta's SuperBot's signing certificate in 1 day. Record who rotates each (botctl sso saml <provider>).".into())
        );
    }

    #[test]
    fn scim_follows_its_tokens_and_failures() {
        let mut i = healthy();
        let cases = [
            (Scim { working_tokens: 0, ..Default::default() }, 0, "SCIM is on, but no tenant has a working token"),
            (Scim { working_tokens: 2, tenants_expiring: 1, used_recently: true, ..Default::default() }, 0, "Every token of 1 tenant ends within 14 days"),
            (Scim { working_tokens: 1, ..Default::default() }, 0, "No SCIM request in the last 30 days"),
            (Scim { working_tokens: 1, used_recently: true, ..Default::default() }, 3, "3 SCIM requests failed in the last 30 days"),
        ];
        for (s, failed, want) in cases {
            i.scim = Some(s);
            i.score.scim_failed = failed;
            let (st, d) = status(&check(&i), "scim");
            assert!(st == Status::Open && d.starts_with(want), "{d}");
        }
    }

    #[test]
    fn the_google_sync_stands_in_for_a_token() {
        let mut i = healthy();
        let google = |last_failed: Option<&str>, passed_recently| Scim { google: Some(GoogleSync { last_failed: last_failed.map(String::from), passed_recently }), ..Default::default() };
        i.scim = Some(google(None, true));
        assert_eq!(
            status(&check(&i), "scim"),
            (
                Status::Confirm,
                "The Google Workspace sync passing in the last 30 days, and no request failed: confirm the IdP's provisioning log shows no errors and people who left are disabled.".into()
            )
        );
        i.scim = Some(Scim { working_tokens: 1, used_recently: true, ..google(None, true) });
        assert!(status(&check(&i), "scim").1.starts_with("The Google Workspace sync passing; 1 working token, used in the last 30 days"));
        for (s, want) in [
            (google(Some("too_many_removals"), true), "The Google Workspace sync's latest pass didn't succeed (too_many_removals): botctl scim google."),
            (google(None, false), "The Google Workspace sync has no successful pass in the last 30 days: botctl scim google."),
            (Scim { working_tokens: 1, ..google(None, true) }, "No SCIM request in the last 30 days"),
        ] {
            i.scim = Some(s);
            let (st, d) = status(&check(&i), "scim");
            assert!(st == Status::Open && d.starts_with(want), "{d}");
        }
    }

    #[test]
    fn signals_at_watch_or_risk_are_open() {
        let mut i = healthy();
        i.score.identity = signal("risk", "In the last 30 days, 30 of 100 single sign-on attempts (30%) failed.");
        i.score.runs = signal("watch", "8 of 100 runs (8%) failed or timed out in the last 30 days.");
        i.score.approvals = signal("risk", "20 of 50 approvals (40%) expired unanswered in the last 30 days; 3 waiting now.");
        let r = check(&i);
        assert_eq!(
            status(&r, "sign_in"),
            (Status::Open, "At risk. In the last 30 days, 30 of 100 single sign-on attempts (30%) failed. See the score's identity reasons and the sign-in or SAML runbook.".into())
        );
        assert!(status(&r, "runs").1.starts_with("Worth a look. 8 of 100 runs"));
        assert_eq!(status(&r, "approvals").0, Status::Open);
        i = healthy();
        i.approvals_ask = false;
        assert!(status(&check(&i), "approvals").1.starts_with("Approvals are off (bypass)"));
    }

    #[test]
    fn backups_and_machines() {
        let mut i = healthy();
        for (b, want) in [
            (None, "botd doesn't make server backups"),
            (Some(ServerBackups { off_host: false, ..Default::default() }), "Server backups stay on this host"),
            (Some(ServerBackups { off_host: true, breach: true, age_hours: Some(40), rpo_hours: 26 }), "The newest copy off the host is past its RPO of 26 hours"),
            (Some(ServerBackups { off_host: true, age_hours: None, rpo_hours: 26, ..Default::default() }), "Copies are set up, but none has been made yet"),
        ] {
            i.server_backups = b;
            let (s, d) = status(&check(&i), "backups");
            assert!(s == Status::Open && d.starts_with(want), "{d}");
        }
        i = healthy();
        let m = i.machines.as_mut().unwrap();
        (m.rpo_breaches, m.restores, m.restores_past_rto, m.backups_failed) = (2, 3, 1, 4);
        assert_eq!(
            status(&check(&i), "machine_recovery"),
            (Status::Open, "2 machines are past their RPO; 1 of 3 restores in the last 31 days took longer than the RTO; 4 machine backups failed in the last 30 days: see botctl machine recovery.".into())
        );
        i.machines.as_mut().unwrap().egress_pending = 3;
        assert_eq!(status(&check(&i), "egress").0, Status::Open);
        i.residency_warnings = Some(2);
        assert_eq!(status(&check(&i), "residency"), (Status::Open, "2 residency warnings: see botctl regions.".into()));
        i.machines = None;
        assert_eq!((status(&check(&i), "egress").0, status(&check(&i), "machine_recovery").0), (Status::NotApplicable, Status::NotApplicable));
    }

    #[test]
    fn people_at_a_limit_and_the_license() {
        let mut i = healthy();
        i.limit_refusals = vec![("tier_limit".into(), 4), ("tier_token_limit".into(), 0), ("storage_limit".into(), 1)];
        i.token_limits_reached = 2;
        assert_eq!(
            status(&check(&i), "usage"),
            (
                Status::Open,
                "In the last 30 days, 5 runs were refused at a plan's limit (tier_limit 4, storage_limit 1); a monthly token limit was reached 2 times: see botctl usage for who, and whether they need another plan.".into()
            )
        );
        let l = i.license.as_mut().unwrap();
        l.days_left = Some(60);
        assert_eq!(status(&check(&i), "license"), (Status::Open, "The license ends in 60 days: the renewal is with the account owner; 40 of 60 seats in use.".into()));
        let l = i.license.as_mut().unwrap();
        (l.days_left, l.seats_used) = (Some(300), 55);
        assert_eq!(status(&check(&i), "license"), (Status::Open, "55 of 60 seats in use: talk about seats with the account owner.".into()));
        let l = i.license.as_mut().unwrap();
        (l.mode, l.days_left) = ("grace".into(), Some(-2));
        assert!(status(&check(&i), "license").1.starts_with("The license has ended and is in its grace period"));
        i.license.as_mut().unwrap().usable = false;
        assert!(status(&check(&i), "license").1.starts_with("There's no usable license"));
        i.license = None;
        assert_eq!(status(&check(&i), "license").0, Status::NotApplicable);
    }

    #[test]
    fn the_score_report_and_history_become_inputs() {
        let report = crate::health_score::report(
            &crate::health_score::Inputs {
                days: 30,
                scim_token_used: true,
                scim_failed: [("uniqueness".to_string(), 2)].into_iter().collect(),
                server_backups: Some(crate::health_score::ServerBackups { off_host: true, breach: false, age_hours: Some(5), rpo_hours: 26 }),
                ..Default::default()
            },
            0,
        );
        let s = score_of(&report);
        assert_eq!((s.band.as_str(), s.scim_failed, s.identity.status.as_str()), ("watch", 2, "watch"), "{report:#}");
        assert_eq!(s.watch, ["identity"]);
        assert_eq!(s.runs.status, "n/a");
        assert_eq!(trend_of(None), Trend::Unreadable);
        assert_eq!(trend_of(Some(&json!({ "recording": false }))), Trend::Off);
        assert_eq!(trend_of(Some(&json!({ "recording": true, "points": [{}], "trend": null }))), Trend::Few(1));
        assert_eq!(
            trend_of(Some(&json!({ "recording": true, "points": [{}, {}], "trend": { "fromScore": 90, "toScore": 70, "worse": ["runs"], "better": [] } }))),
            Trend::Read { from_score: Some(90), to_score: Some(70), worse: vec!["runs".into()], better: Vec::new() }
        );
    }

    #[test]
    fn the_view_and_audit_hold_ids_and_counts() {
        let mut i = healthy();
        i.setup_open = vec!["domain".into()];
        let r = check(&i);
        let v = r.view("2027-01-01T00:00:00Z");
        assert_eq!((v["format"].clone(), v["clear"].clone(), v["open"].clone(), v["score"].clone()), (json!(FORMAT), json!(false), json!(["setup"]), json!(96)));
        assert_eq!(v["items"].as_array().unwrap().len(), ITEMS.len());
        assert_eq!(v["items"][4], json!({ "id": "setup", "section": "deployment", "label": "Setup still complete", "status": "open", "detail": "Open in botctl setup: domain.", "guide": "docs/adr/0034-onboarding-wizard.md" }));
        assert_eq!(v["sections"][5], json!({ "id": "account", "title": "6. The account" }));
        assert_eq!(r.audit_details(), json!({ "score": 96, "band": "healthy", "clear": false, "counts": r.counts(), "open": ["setup"] }));
    }

    /// Each item is a line of health-check.md's checklist, in its section and order, and
    /// each guide is a file in the repository with the anchor it names.
    #[test]
    fn the_items_are_the_checklist() {
        let md = include_str!("../../docs/support/health-check.md");
        let mut section = None;
        let mut lines: Vec<(&str, &str)> = Vec::new();
        for l in md.lines() {
            if let Some(h) = l.strip_prefix("## ") {
                section = SECTIONS.iter().find(|(_, title)| *title == h).map(|(id, _)| *id);
            } else if let Some(text) = l.strip_prefix("- [ ] ") {
                lines.push((section.unwrap_or_else(|| panic!("a checklist line outside the six sections: {l}")), text));
            }
        }
        assert_eq!(lines.len(), ITEMS.len(), "health-check.md has {} checklist lines", lines.len());
        for ((sec, text), it) in lines.iter().zip(ITEMS.iter()) {
            assert_eq!(*sec, it.section, "{}", it.id);
            assert!(text.starts_with(it.line), "{}: health-check.md says \"{text}\"", it.id);
        }
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        for it in &ITEMS {
            let (file, anchor) = it.guide.split_once('#').unwrap_or((it.guide, ""));
            let page = std::fs::read_to_string(root.join(file)).unwrap_or_else(|e| panic!("{}'s guide {file}: {e}", it.id));
            if !anchor.is_empty() {
                let slugs: Vec<String> = page
                    .lines()
                    .filter(|l| l.starts_with('#'))
                    .map(|l| l.trim_start_matches('#').trim().to_lowercase().chars().filter(|c| c.is_alphanumeric() || *c == ' ' || *c == '-' || *c == '_').collect::<String>().replace(' ', "-"))
                    .collect();
                assert!(slugs.iter().any(|s| s == anchor), "{file} has no #{anchor}");
            }
        }
    }

    #[test]
    fn details_never_hold_names_addresses_or_buckets() {
        let mut i = healthy();
        i.setup_open = vec!["backups".into()];
        i.incidents.unreviewed = vec!["inc_1".into()];
        let text = check(&i).view("2027-01-01T00:00:00Z").to_string();
        for leak in ["@", "s3://", "http://", "https://"] {
            assert!(!text.contains(leak), "{leak} in {text}");
        }
    }
}
