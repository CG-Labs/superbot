//! The onboarding check (ADR 0233): each item of `docs/support/onboarding.md`'s checklist,
//! judged from what botd holds, for the technical account manager or support engineer
//! taking a customer from signed to live. An item is done, open, for a person to confirm
//! (botd can't see it: contacts, the IdP's MFA, a drill's times), not applicable to this
//! server, or skipped because it was agreed at kickoff that the customer doesn't need it.
//! `GET /api/support/onboarding[?skip=a,b]` (admins, audited as
//! `support.onboarding_checked`) and `botctl onboarding`.
//!
//! Codes, counts and provider ids only: never a person's name or email, an address, a
//! bucket or a licensee, so the report can go in the customer's onboarding record as it is.

use crate::audit::{Filter, Who};
use crate::db::now;
use crate::runner::App;
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
pub const CHECKED: &str = "support.onboarding_checked";
const DAY_MS: i64 = 86_400_000;
const HOUR_MS: i64 = 3_600_000;
/// How recently SCIM must have been used to count as working.
pub const SCIM_RECENT_DAYS: i64 = 30;
/// How far back machine restores count towards a drill.
pub const RESTORE_DAYS: i64 = 180;
/// The pilot's week.
pub const PILOT_DAYS: i64 = 7;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    Done,
    Open,
    /// botd can't see it; a person confirms it with the customer.
    Confirm,
    NotApplicable,
    /// Agreed at kickoff that this customer doesn't need it.
    Skipped,
}

impl Status {
    pub fn as_str(self) -> &'static str {
        match self {
            Status::Done => "done",
            Status::Open => "open",
            Status::Confirm => "confirm",
            Status::NotApplicable => "n/a",
            Status::Skipped => "skipped",
        }
    }
}

pub const SECTIONS: [(&str, &str); 6] = [
    ("kickoff", "1. Kickoff"),
    ("identity", "2. Identity: SSO and SCIM"),
    ("isolation", "3. Isolation"),
    ("backups", "4. Backups and recovery"),
    ("residency", "5. Data residency"),
    ("go_live", "6. Monitoring and go-live"),
];

pub struct Item {
    pub id: &'static str,
    pub section: &'static str,
    pub label: &'static str,
    /// How the item's line in onboarding.md starts, after `- [ ] `. A test holds the two together.
    #[cfg_attr(not(test), allow(dead_code))]
    pub line: &'static str,
    /// Repo-relative, with an anchor where the page has one.
    pub guide: &'static str,
}

const fn item(id: &'static str, section: &'static str, label: &'static str, line: &'static str, guide: &'static str) -> Item {
    Item { id, section, label, line, guide }
}

/// Every item of the checklist, in its order.
pub const ITEMS: [Item; 32] = [
    item("plan", "kickoff", "Plan, seats and support tier confirmed", "Plan, seats and support tier confirmed", "docs/support/tiers.md"),
    item("contacts", "kickoff", "Customer contacts recorded", "Customer contacts:", "docs/support/escalation.md"),
    item("deployment", "kickoff", "Deployment chosen and licensed", "Deployment chosen:", "deploy/README.md"),
    item("region", "kickoff", "Data region chosen", "Data region chosen", "docs/support/onboarding.md#5-data-residency"),
    item("security_pack", "kickoff", "Security pack and DPA sent", "The customer has the [security pack]", "docs/security/README.md"),
    item("go_live_date", "kickoff", "Go-live date and first users", "Go-live date", "docs/support/onboarding.md#1-kickoff"),
    item("idp", "identity", "Identity provider set up", "The identity provider set up", "docs/support/onboarding.md#2-identity-sso-and-scim"),
    item("sso_admin", "identity", "An admin signs in with SSO", "One admin signs in with SSO", "docs/support/runbook-sign-in.md"),
    item("jit_allow_list", "identity", "Just-in-time sign-up has an allow-list", "Just-in-time sign-up has an allow-list", "docs/adr/0103-sso-jit-needs-an-allow-list.md"),
    item("mfa", "identity", "MFA required", "MFA required", "docs/sso/oidc.md#require-mfa-at-the-idp"),
    item("scim", "identity", "SCIM provisioning tested", "SCIM, if they want", "docs/sso/scim.md"),
    item("break_glass", "identity", "Break-glass sign-in off", "Break-glass:", "docs/support/runbook-sign-in.md"),
    item("signin_alerts", "identity", "Sign-in alerts on", "Sign-in alerts on", "docs/security/access-control.md#authentication"),
    item("isolation", "isolation", "Where Bots run decided", "Where Bots run is decided", "deploy/README.md#one-unix-account-per-user"),
    item("hardening", "isolation", "Machines hardened", "Machines hardened at first boot", "docs/adr/0126-per-user-machine-hardening.md"),
    item("approvals", "isolation", "Approval policy reviewed", "Approval policy reviewed", "deploy/README.md#approval-notifications"),
    item("teams", "isolation", "Shared Bots and teams set up", "Shared Bots and teams set up", "docs/security/access-control.md#isolation-between-users"),
    item("server_backups", "backups", "Server backups off the host, encrypted", "Server backups run and are copied off the host", "docs/ops/backup-restore.md"),
    item("keys_off_host", "backups", "Age identity and master key kept elsewhere", "The age identity that decrypts them", "docs/ops/master-key-rotation.md"),
    item("database_encryption", "backups", "Database encrypted at rest", "The database encrypted at rest", "docs/ops/database-encryption.md"),
    item("machine_backups", "backups", "Machine backups within their RPO", "Machine backups on with the plan's RPO", "docs/ops/machine-recovery.md"),
    item("restore_drill", "backups", "A restore drilled", "A restore drilled before go-live", "docs/ops/backup-restore.md#drills"),
    item("recovery_objectives", "backups", "Recovery objectives shared", "The customer has the [recovery objectives]", "docs/security/machine-recovery-objectives.md"),
    item("residency_region", "residency", "Customer's region set", "The customer's region set before their first machine", "docs/ops/incus-containers.md#data-regions"),
    item("backup_region", "residency", "Machine backups stay in the region", "Machine backups stay in the same region", "docs/adr/0117-uk-eu-data-regions.md"),
    item("model_providers", "residency", "Model providers' regions reviewed", "Model providers and their regions reviewed", "docs/security/data-flows.md"),
    item("status_page", "go_live", "Status page and an outside probe", "The status page reachable", "deploy/README.md#status-page-and-slo-alerts"),
    item("metrics", "go_live", "Metrics and alerts wired up", "Metrics, alert rules and structured logs wired up", "deploy/README.md#metrics-and-logs"),
    item("setup", "go_live", "Setup wizard's checklist complete", "The setup wizard's checklist complete", "docs/adr/0034-onboarding-wizard.md"),
    item("first_bundle", "go_live", "A first support bundle made", "A first support bundle made", "docs/support/support-bundle.md"),
    item("pilot", "go_live", "Pilot team for a week", "The pilot team uses it for a week", "docs/support/onboarding.md#success-cadence"),
    item("go_live", "go_live", "Go-live confirmed in writing", "Go-live confirmed in writing", "docs/support/escalation.md"),
];

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Provider {
    pub id: String,
    pub kind: String,
    pub ready: bool,
    pub jit: bool,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Scim {
    /// Tokens neither revoked nor expired.
    pub working_tokens: usize,
    /// A token was used in the last `SCIM_RECENT_DAYS`.
    pub used_recently: bool,
    /// Tenants whose every working token ends within `scim::WARN_DAYS`.
    pub tenants_expiring: usize,
    /// People SCIM (or the Google sync through it) has deprovisioned, as far back as the audit log goes.
    pub deprovisions: u64,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct ServerBackups {
    pub off_host: bool,
    pub copied: bool,
    pub breach: bool,
    pub rpo_hours: i64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Where {
    /// Every Bot here as botd's own account.
    #[default]
    Shared,
    /// Each user's Bots here as their own account (ISOLATION=users).
    Users,
    /// Every Bot on its owner's machine (MACHINE_ROUTING=on).
    Machines,
    /// Assigned users' Bots on their machines, the rest here as botd's account.
    Assigned,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Machines {
    pub hardening: bool,
    pub own_kernel_tiers: usize,
    /// Off-host backups (MACHINE_BACKUP_S3_BUCKET) or the provider's own.
    pub off_host_backups: bool,
    pub provider_backups: bool,
    pub rpo_breaches: usize,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Residency {
    pub regions: usize,
    pub users_with_region: usize,
    pub teams_with_region: usize,
    pub pins: usize,
    pub warnings: usize,
    /// None when machines' backups aren't copied off the host; else whether
    /// MACHINE_BACKUP_RESIDENCY is strict, and the regions whose backups leave them.
    pub backups: Option<(bool, usize)>,
}

/// Everything the check reads, so judging is a pure function.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Inputs {
    pub tiers: usize,
    pub tiers_from_file: bool,
    pub seats_used: u32,
    pub seat_cap: Option<u32>,
    /// The license is in order, as the setup wizard judges it.
    pub license_ok: bool,
    /// Testing mode with no license.
    pub testing: bool,
    pub license_mode: String,
    pub providers: Vec<Provider>,
    /// Active admins besides the owner account, and how many of them have signed in with SSO.
    pub admins: usize,
    pub admins_with_sso: usize,
    /// The MFA policy in force: off, admins or all.
    pub mfa: String,
    pub scim: Option<Scim>,
    pub break_glass: bool,
    pub signin_alerts: bool,
    pub bots_run: Where,
    pub machines: Option<Machines>,
    pub approvals_ask: bool,
    /// A notice of a pending approval reaches someone: email, a webhook or push.
    pub notices: bool,
    pub teams: usize,
    pub server_backups: Option<ServerBackups>,
    pub backups_encrypted: bool,
    pub database_encrypted: bool,
    pub machine_restores: u64,
    pub residency: Option<Residency>,
    pub status_page: bool,
    /// None when metrics are off; else whether they're on loopback only (no token).
    pub metrics: Option<bool>,
    /// The setup wizard's checklist items not done.
    pub setup_open: Vec<String>,
    pub bundles: u64,
    pub people: u64,
    pub active_this_week: u64,
}

fn plural(n: u64, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
}

fn list(ids: &[String]) -> String {
    ids.join(", ")
}

/// One item's status and what botd saw.
fn judge(id: &str, i: &Inputs) -> (Status, String) {
    use Status::*;
    let ready: Vec<&Provider> = i.providers.iter().filter(|p| p.ready).collect();
    match id {
        "plan" => {
            let plans = if i.tiers_from_file { format!("{} from the tiers file", plural(i.tiers as u64, "plan", "plans")) } else { "the built-in self-host plan".to_string() };
            let seats = match i.seat_cap {
                Some(cap) => format!("{} of {cap} seats in use", i.seats_used),
                None => format!("{} in use, no seat limit", plural(u64::from(i.seats_used), "seat", "seats")),
            };
            (Confirm, format!("This server sells {plans}; {seats}. Confirm the plan, seats and support tier with the customer."))
        }
        "contacts" => (Confirm, "Kept in the support system, which botd can't see.".into()),
        "deployment" => match (i.license_ok, i.testing) {
            (true, false) => (Done, format!("The license is in order ({}).", i.license_mode)),
            (_, true) => (Open, "Testing mode, with no license: install the customer's key (botctl license install) before go-live.".into()),
            (false, false) => (Open, format!("The license isn't in order ({}): see botctl license.", i.license_mode)),
        },
        "region" => match &i.residency {
            Some(r) => (Confirm, format!("This server offers {}; set the customer's in section 5.", plural(r.regions as u64, "data region", "data regions"))),
            None => (NotApplicable, "This server offers no data regions (MACHINE_REGIONS).".into()),
        },
        "security_pack" | "go_live_date" | "keys_off_host" | "recovery_objectives" | "model_providers" | "go_live" => (Confirm, "botd can't see this; record it in the customer's onboarding record.".into()),
        "idp" => {
            let waiting: Vec<String> = i.providers.iter().filter(|p| !p.ready).map(|p| p.id.clone()).collect();
            if i.providers.is_empty() {
                (Open, "No single sign-on provider yet: set one up from its guide (botctl setup has the settings).".into())
            } else if !waiting.is_empty() {
                (Open, format!("Waiting for a secret or IdP metadata: {}.", list(&waiting)))
            } else {
                let named: Vec<String> = ready.iter().map(|p| format!("{} ({})", p.id, p.kind)).collect();
                (Done, format!("Ready: {}.", list(&named)))
            }
        }
        "sso_admin" => match (ready.is_empty(), i.admins, i.admins_with_sso) {
            (true, ..) => (Open, "Needs a ready identity provider first.".into()),
            (false, 0, _) => (Open, "No admin besides the owner account yet: add one in Users and have them sign in with SSO.".into()),
            (false, n, 0) => (Open, format!("None of the {} besides the owner has signed in with SSO yet.", plural(n as u64, "admin", "admins"))),
            (false, n, s) => (Done, format!("{s} of {} besides the owner {} signed in with SSO.", plural(n as u64, "admin", "admins"), if s == 1 { "has" } else { "have" })),
        },
        "jit_allow_list" => {
            let jit: Vec<String> = i.providers.iter().filter(|p| p.jit).map(|p| p.id.clone()).collect();
            if i.providers.is_empty() {
                (NotApplicable, "No single sign-on provider.".into())
            } else if jit.is_empty() {
                (Done, "Just-in-time sign-up is off: people are added by hand or by SCIM.".into())
            } else {
                (Done, format!("Just-in-time sign-up is on for {}, each with the allow-list botd requires before it starts.", list(&jit)))
            }
        }
        "mfa" => match i.mfa.as_str() {
            "admins" => (Done, "SuperBot requires a second factor of admins (AUTH_MFA or the console).".into()),
            "all" => (Done, "SuperBot requires a second factor of everyone (AUTH_MFA or the console).".into()),
            _ if !ready.is_empty() => (Confirm, "SuperBot's own second factor isn't required; SSO sign-ins rely on the IdP's MFA, which botd can't see: confirm the IdP requires it.".into()),
            _ => (Open, "No second factor is required, and there's no SSO: set AUTH_MFA=admins or all.".into()),
        },
        "scim" => match &i.scim {
            None => (Confirm, "SCIM is off: confirm the customer adds and removes people by hand, or set SCIM=on.".into()),
            Some(s) if s.working_tokens == 0 => (Open, "SCIM is on, but no tenant has a working token: botctl scim token create.".into()),
            Some(s) if s.tenants_expiring > 0 => (Open, format!("Every token of {} ends within 14 days: botctl scim token rotate.", plural(s.tenants_expiring as u64, "tenant", "tenants"))),
            Some(s) if !s.used_recently => (Open, format!("No SCIM request in the last {SCIM_RECENT_DAYS} days: check provisioning is on at the identity provider.")),
            Some(s) if s.deprovisions == 0 => (Open, "SCIM hasn't deprovisioned anyone yet: unassign a test user at the identity provider and check they're disabled.".into()),
            Some(s) => (
                Done,
                format!("{}, used in the last {SCIM_RECENT_DAYS} days; SCIM has deprovisioned {}.", plural(s.working_tokens as u64, "working token", "working tokens"), plural(s.deprovisions, "person", "people")),
            ),
        },
        "break_glass" => match (i.break_glass, i.admins_with_sso) {
            (false, _) => (Done, "Break-glass sign-in is off (AUTH_BREAK_GLASS=0).".into()),
            (true, 0) => (Open, "Break-glass sign-in is on: turn it off (AUTH_BREAK_GLASS=0) once every admin signs in with SSO.".into()),
            (true, _) => (Open, "Break-glass sign-in is on, and admins sign in with SSO: set AUTH_BREAK_GLASS=0 and restart botd.".into()),
        },
        "signin_alerts" => match i.signin_alerts {
            true => (Done, "Suspicious sign-ins are reported (SIGNIN_ALERTS).".into()),
            false => (Open, "Sign-in alerts are off: unset SIGNIN_ALERTS or set it on.".into()),
        },
        "isolation" => match i.bots_run {
            Where::Machines => (Done, "Every Bot runs on its owner's machine (MACHINE_ROUTING=on).".into()),
            Where::Users => (Done, "Each user's Bots on this server run as their own Unix account (ISOLATION=users).".into()),
            Where::Assigned => (Open, "Bots of people without a machine run on this server as botd's own account: set ISOLATION=users or MACHINE_ROUTING=on.".into()),
            Where::Shared => (Open, "Every Bot runs on this server as botd's own account: set ISOLATION=users, or give people machines.".into()),
        },
        "hardening" => match &i.machines {
            None => (NotApplicable, "This server runs no users' machines.".into()),
            Some(m) if !m.hardening => (Open, "MACHINE_HARDENING is off: new machines aren't hardened at first boot.".into()),
            Some(m) => (Done, format!("Machines are hardened at first boot; {} held to a kernel of their own (MACHINE_OWN_KERNEL_TIERS).", plural(m.own_kernel_tiers as u64, "plan is", "plans are"))),
        },
        "approvals" => match (i.approvals_ask, i.notices) {
            (false, _) => (Open, "Approvals are off (bypass): Bots run risky actions without asking.".into()),
            (true, false) => (Open, "Bots ask before risky actions, but no notice reaches anyone: set up email, a webhook or push in the console's Notifications.".into()),
            (true, true) => (Confirm, "Bots ask before risky actions and notices go out: review the risky classes, the timeout and who's notified with the customer.".into()),
        },
        "teams" => (Confirm, format!("{} on this server: confirm shared Bots and teams match how the customer works.", plural(i.teams as u64, "team", "teams"))),
        "server_backups" => match &i.server_backups {
            None => (Open, "Server backups stay on this host: set SERVER_BACKUP_S3_BUCKET to copy them off.".into()),
            Some(b) if !b.off_host => (Open, "Server backups stay on this host: set SERVER_BACKUP_S3_BUCKET to copy them off.".into()),
            Some(b) if b.breach => (Open, format!("The newest copy off the host is past its RPO of {} hours: see botctl backups.", b.rpo_hours)),
            Some(b) if !b.copied => (Open, "Copies are set up, but none has been made yet: see botctl backups.".into()),
            Some(_) if !i.backups_encrypted => (Open, "Copied off the host within the RPO, but not every backup is encrypted: see botctl backups.".into()),
            Some(b) => (Done, format!("Copied off the host within the RPO of {} hours, and encrypted.", b.rpo_hours)),
        },
        "database_encryption" => match i.database_encrypted {
            true => (Done, "The database is encrypted at rest.".into()),
            false => (Open, "The database isn't encrypted at rest: encrypt it, or skip this if the customer doesn't require it.".into()),
        },
        "machine_backups" => match &i.machines {
            None => (NotApplicable, "This server runs no users' machines.".into()),
            Some(m) if !m.off_host_backups && !m.provider_backups => (Open, "Machines aren't backed up: turn on off-host backups (Incus) or the provider's backups (Linode).".into()),
            Some(m) if m.rpo_breaches > 0 => (Open, format!("{} past {} RPO: see botctl machine recovery.", plural(m.rpo_breaches as u64, "machine is", "machines are"), if m.rpo_breaches == 1 { "its" } else { "their" })),
            Some(_) => (Done, "Machines are backed up, and none is past its RPO.".into()),
        },
        "restore_drill" => (
            Confirm,
            format!(
                "botd recorded {} in the last {RESTORE_DAYS} days; confirm a server and a machine restore were drilled, with their times against the RTO.",
                plural(i.machine_restores, "machine restore", "machine restores")
            ),
        ),
        "residency_region" => match &i.residency {
            None => (NotApplicable, "This server offers no data regions (MACHINE_REGIONS).".into()),
            Some(r) if r.warnings > 0 => (Open, format!("{}: see botctl regions.", plural(r.warnings as u64, "residency warning", "residency warnings"))),
            Some(r) if r.users_with_region + r.teams_with_region + r.pins == 0 => (Open, "No user or team has a region yet: botctl user region or botctl team region.".into()),
            Some(r) => (
                Done,
                format!(
                    "{} and {} have a region, {} pinned; no residency warnings.",
                    plural(r.users_with_region as u64, "user", "users"),
                    plural(r.teams_with_region as u64, "team", "teams"),
                    r.pins
                ),
            ),
        },
        "backup_region" => match i.residency.as_ref().map(|r| r.backups) {
            None => (NotApplicable, "This server offers no data regions (MACHINE_REGIONS).".into()),
            Some(None) => (NotApplicable, "Machines' backups aren't copied off the host, so they stay with the provider.".into()),
            Some(Some((true, _))) => (Done, "MACHINE_BACKUP_RESIDENCY=strict: each region's backups stay in a store there. The server backups' bucket is for the customer to accept.".into()),
            Some(Some((false, 0))) => (Done, "Every region's backups go to a store in it. The server backups' bucket is for the customer to accept.".into()),
            Some(Some((false, n))) => (Open, format!("Backups of machines in {} go to the default store: set a store there, or MACHINE_BACKUP_RESIDENCY=strict.", plural(n as u64, "region", "regions"))),
        },
        "status_page" => match i.status_page {
            true => (Confirm, "The status page is on (/status); botd can't see an outside probe: confirm one checks /status.json.".into()),
            false => (Open, "The status page is off (STATUS_PAGE=off).".into()),
        },
        "metrics" => match i.metrics {
            None => (Open, "Metrics are off: set METRICS_LISTEN, then load the alert rules in deploy/prometheus.".into()),
            Some(true) => (Done, "Metrics are on, on loopback. Confirm the alert rules are loaded and logs are shipped.".into()),
            Some(false) => (Done, "Metrics are on, with a bearer token. Confirm the alert rules are loaded and logs are shipped.".into()),
        },
        "setup" => match i.setup_open.is_empty() {
            true => (Done, "Every item of botctl setup is done.".into()),
            false => (Open, format!("Still open in botctl setup: {}.", list(&i.setup_open))),
        },
        "first_bundle" => match i.bundles {
            0 => (Open, "None made yet: botctl support-bundle, then read it with the customer.".into()),
            n => (Done, format!("{} made.", plural(n, "support bundle", "support bundles"))),
        },
        "pilot" => (
            Confirm,
            format!("{} of {} signed in or used SuperBot in the last {PILOT_DAYS} days.", i.active_this_week, plural(i.people, "person", "people")),
        ),
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
    pub items: Vec<Judged>,
    /// Skipped ids that were done or didn't apply anyway.
    pub unneeded_skips: Vec<&'static str>,
}

/// Each skip names an item; an unknown one is a mistake, refused with the ids there are.
pub fn skips(raw: &str) -> Result<Vec<&'static str>, String> {
    let mut out = Vec::new();
    for s in raw.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        let Some(it) = ITEMS.iter().find(|it| it.id.eq_ignore_ascii_case(s)) else {
            let shown = if s.len() <= 40 && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-') { s } else { "[text]" };
            return Err(format!("skip: no item \"{shown}\". Items: {}.", ITEMS.iter().map(|i| i.id).collect::<Vec<_>>().join(", ")));
        };
        if !out.contains(&it.id) {
            out.push(it.id);
        }
    }
    Ok(out)
}

/// Every item judged, with `skip` applied to what's open or left to a person.
pub fn check(i: &Inputs, skip: &[&str]) -> Report {
    let mut r = Report { items: Vec::new(), unneeded_skips: Vec::new() };
    for it in &ITEMS {
        let (mut status, detail) = judge(it.id, i);
        if skip.contains(&it.id) {
            match status {
                Status::Open | Status::Confirm => status = Status::Skipped,
                _ => r.unneeded_skips.push(it.id),
            }
        }
        r.items.push(Judged { id: it.id, status, detail });
    }
    r
}

impl Report {
    pub fn count(&self, s: Status) -> usize {
        self.items.iter().filter(|j| j.status == s).count()
    }

    fn ids(&self, s: Status) -> Vec<&'static str> {
        self.items.iter().filter(|j| j.status == s).map(|j| j.id).collect()
    }

    /// Nothing open: everything is done, doesn't apply, is skipped, or is for a person to confirm.
    pub fn ready(&self) -> bool {
        self.count(Status::Open) == 0
    }

    pub fn counts(&self) -> Value {
        json!({
            "done": self.count(Status::Done),
            "open": self.count(Status::Open),
            "confirm": self.count(Status::Confirm),
            "notApplicable": self.count(Status::NotApplicable),
            "skipped": self.count(Status::Skipped),
        })
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
            "checklist": "docs/support/onboarding.md",
            "ready": self.ready(),
            "counts": self.counts(),
            "open": self.ids(Status::Open),
            "skipped": self.ids(Status::Skipped),
            "unneededSkips": self.unneeded_skips,
            "sections": SECTIONS.iter().map(|(id, title)| json!({ "id": id, "title": title })).collect::<Vec<_>>(),
            "items": items,
        })
    }

    /// What `support.onboarding_checked` records: counts and item ids only.
    pub fn audit_details(&self) -> Value {
        json!({ "ready": self.ready(), "counts": self.counts(), "open": self.ids(Status::Open), "skipped": self.ids(Status::Skipped) })
    }
}

fn audit_total(app: &App, from: i64, action: &str) -> u64 {
    app.db.audit_counts(from, &[action]).iter().map(|c| c.n).sum()
}

/// The inputs, from the database, botd's settings and the setup wizard's checklist.
pub fn gather(app: &App, a: &Auth, setup: &Value, now_ms: i64) -> Inputs {
    let t = app.tiers();
    let lic = app.license.status_at(now_ms);
    let seats = app.db.active_seats();
    let lv = lic.view(seats);
    let users = app.db.users();
    let admins: Vec<&crate::db::User> = users.iter().filter(|u| u.role == crate::rbac::Role::Admin && u.active() && !u.service && u.id != crate::users::OPERATOR).collect();
    let admins_with_sso = admins
        .iter()
        .filter(|u| {
            let f = Filter { actions: vec!["auth.login".into()], methods: vec!["sso".into()], actor_id: Some(u.id.clone()), ..Default::default() };
            !app.db.audit_events(&f, 1, false).is_empty()
        })
        .count();
    let scim = a.scim.enabled.then(|| {
        let tokens = app.db.scim_tokens();
        let from = now_ms - SCIM_RECENT_DAYS * DAY_MS;
        let f = Filter { actions: vec!["user.deprovisioned".into()], ..Default::default() };
        let via_scim = |e: &crate::db::AuditEvent| e.details["via"].as_str().is_some_and(|v| v == crate::deprovision::SCIM || v == crate::deprovision::SCIM_DELETE);
        Scim {
            working_tokens: tokens.iter().filter(|t| !matches!(crate::scim::token_state(t, now_ms), "revoked" | "expired")).count(),
            used_recently: tokens.iter().any(|t| t.last_used_at.is_some_and(|u| u >= from)),
            tenants_expiring: crate::scim::tenants_expiring(&tokens, now_ms).len(),
            deprovisions: app.db.audit_events(&f, 10_000, false).iter().filter(|e| via_scim(e)).count() as u64,
        }
    });
    let cp = &a.machines;
    let machines_on = cp.enabled();
    let users_isolated = app.isolation.get().is_some();
    let bots_run = match (machines_on.then_some(cp.routing), users_isolated) {
        (Some(crate::machines::route::Routing::On), _) => Where::Machines,
        (_, true) => Where::Users,
        (Some(crate::machines::route::Routing::Assigned), false) => Where::Assigned,
        _ => Where::Shared,
    };
    let env = |k: &str| std::env::var(k).unwrap_or_default();
    let machines = machines_on.then(|| Machines {
        hardening: crate::machines::hardening::Settings::from_env(&env).is_ok_and(|s| s.is_some()),
        own_kernel_tiers: cp.own_kernel_tiers.len(),
        off_host_backups: cp.offsite.is_some(),
        provider_backups: cp.provider_backups.is_some(),
        rpo_breaches: app.db.machine_rpo_breaches_open().len(),
    });
    let residency = (machines_on && !cp.regions.is_empty()).then(|| Residency {
        regions: cp.regions.len(),
        users_with_region: users.iter().filter(|u| u.active() && u.region.is_some()).count(),
        teams_with_region: app.db.teams().iter().filter(|t| t.region.is_some()).count(),
        pins: app.db.residency_pins().len(),
        warnings: crate::machines::residency::warnings(app, cp).len(),
        backups: cp.offsite.as_deref().map(|o| (o.s.residency == crate::machines::backup::Residency::Strict, o.warnings().len())),
    });
    let server_backups = app.server_backups.get().map(|sb| {
        let st = crate::server_backups::status(app, sb);
        ServerBackups { off_host: sb.target.is_some(), copied: st.last.is_some(), breach: st.breach, rpo_hours: sb.rpo_ms / HOUR_MS }
    });
    let started = app.db.audit_events(&Filter { actions: vec!["server.started".into()], ..Default::default() }, 1, false);
    let metrics = started.first().and_then(|e| e.details.get("metrics")).filter(|m| m.is_object()).map(|m| m["token"] != true);
    let setup_open = setup["checklist"].as_array().into_iter().flatten().filter(|c| c["done"] != true).filter_map(|c| c["id"].as_str().map(String::from)).collect();
    let (people, active_this_week) = app.db.people_active_since(now_ms - PILOT_DAYS * DAY_MS);
    Inputs {
        tiers: t.all().len(),
        tiers_from_file: t.source != "built-in",
        seats_used: seats,
        seat_cap: lic.seat_cap(),
        license_ok: lv["ok"] == true && lv["warnings"].as_array().is_none_or(Vec::is_empty),
        testing: lic.testing_mode && lic.claims.is_none(),
        license_mode: lv["mode"].as_str().unwrap_or_default().to_string(),
        providers: a.sso.providers.iter().map(|p| Provider { id: p.id.clone(), kind: p.type_name().into(), ready: p.ready(), jit: p.jit_role.is_some() }).collect(),
        admins: admins.len(),
        admins_with_sso,
        mfa: crate::mfa::policy(a, &app.db).as_str().into(),
        scim,
        break_glass: a.break_glass,
        signin_alerts: a.watch.settings.enabled,
        bots_run,
        machines,
        approvals_ask: app.db.global_policy().mode == crate::policy::Mode::Ask,
        notices: app.notifier.get().is_some_and(|n| n.any_channel(&app.db, &crate::notify::load(&app.db))),
        teams: app.db.teams().len(),
        server_backups,
        backups_encrypted: crate::backup_encryption::checklist(app).0,
        database_encrypted: crate::database_encryption::checklist(app).0,
        machine_restores: audit_total(app, now_ms - RESTORE_DAYS * DAY_MS, "machine.restored"),
        residency,
        status_page: app.status.enabled(),
        metrics,
        setup_open,
        bundles: audit_total(app, 0, "support.bundle_created"),
        people,
        active_this_week,
    }
}

fn rfc3339(ms: i64) -> String {
    chrono::DateTime::from_timestamp_millis(ms).map(|t| t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)).unwrap_or_default()
}

type Peer = Option<Extension<ConnectInfo<SocketAddr>>>;

/// `GET /api/support/onboarding[?skip=scim,database_encryption]` (admins): each item of the
/// onboarding checklist. Audited, so the record shows how onboarding went.
pub async fn get(
    State(app): State<AppState>,
    Extension(a): Extension<Arc<Auth>>,
    Extension(by): Extension<Who>,
    Query(q): Query<HashMap<String, String>>,
    headers: HeaderMap,
    peer: Peer,
) -> Res {
    if let Some(k) = q.keys().find(|k| k.as_str() != "skip") {
        let shown = if k.len() <= 40 && k.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') { k.as_str() } else { "[text]" };
        return Err(bad(format!("Unknown parameter \"{shown}\". Send skip, a comma-separated list of items.")));
    }
    let skip = skips(q.get("skip").map_or("", String::as_str)).map_err(bad)?;
    let peer: Option<IpAddr> = peer.map(|Extension(ConnectInfo(p))| p.ip());
    let setup = crate::setup::report(&app, &a, &headers, peer);
    let now_ms = now();
    let r = {
        let (app, a) = (app.clone(), a.clone());
        tokio::task::spawn_blocking(move || check(&gather(&app, &a, &setup, now_ms), &skip))
            .await
            .map_err(|e| crate::ApiError(axum::http::StatusCode::INTERNAL_SERVER_ERROR, format!("Couldn't check onboarding: {e}")))?
    };
    app.db.record(&by.event(CHECKED).target("setup", "server").details(r.audit_details()));
    Ok(Json(r.view(&rfc3339(now_ms))))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A customer ready to go live: SSO with an admin on it, SCIM tested, machines with
    /// backups and regions, everything botd can see done.
    fn live() -> Inputs {
        Inputs {
            tiers: 3,
            tiers_from_file: true,
            seats_used: 40,
            seat_cap: Some(50),
            license_ok: true,
            testing: false,
            license_mode: "active".into(),
            providers: vec![Provider { id: "okta".into(), kind: "oidc".into(), ready: true, jit: true }],
            admins: 2,
            admins_with_sso: 2,
            mfa: "off".into(),
            scim: Some(Scim { working_tokens: 1, used_recently: true, tenants_expiring: 0, deprovisions: 1 }),
            break_glass: false,
            signin_alerts: true,
            bots_run: Where::Machines,
            machines: Some(Machines { hardening: true, own_kernel_tiers: 1, off_host_backups: true, provider_backups: false, rpo_breaches: 0 }),
            approvals_ask: true,
            notices: true,
            teams: 4,
            server_backups: Some(ServerBackups { off_host: true, copied: true, breach: false, rpo_hours: 26 }),
            backups_encrypted: true,
            database_encrypted: true,
            machine_restores: 2,
            residency: Some(Residency { regions: 2, users_with_region: 0, teams_with_region: 1, pins: 1, warnings: 0, backups: Some((true, 0)) }),
            status_page: true,
            metrics: Some(false),
            setup_open: Vec::new(),
            bundles: 1,
            people: 40,
            active_this_week: 31,
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
            assert_ne!(judge(it.id, &live()).1, "No rule for this item.", "{}", it.id);
        }
    }

    #[test]
    fn a_customer_ready_to_go_live_has_nothing_open() {
        let r = check(&live(), &[]);
        assert!(r.ready(), "{:#?}", of(&r, Status::Open));
        assert_eq!(
            of(&r, Status::Confirm),
            [
                "plan", "contacts", "region", "security_pack", "go_live_date", "mfa", "approvals", "teams", "keys_off_host", "restore_drill", "recovery_objectives",
                "model_providers", "status_page", "pilot", "go_live"
            ]
        );
        assert_eq!(status(&r, "plan").1, "This server sells 3 plans from the tiers file; 40 of 50 seats in use. Confirm the plan, seats and support tier with the customer.");
        assert_eq!(status(&r, "idp"), (Status::Done, "Ready: okta (oidc).".into()));
        assert_eq!(status(&r, "sso_admin").1, "2 of 2 admins besides the owner have signed in with SSO.");
        assert_eq!(status(&r, "scim").1, "1 working token, used in the last 30 days; SCIM has deprovisioned 1 person.");
        assert_eq!(status(&r, "residency_region").1, "0 users and 1 team have a region, 1 pinned; no residency warnings.");
        assert_eq!(status(&r, "pilot").1, "31 of 40 people signed in or used SuperBot in the last 7 days.");
        assert_eq!(r.count(Status::Done), ITEMS.len() - 15);
    }

    #[test]
    fn a_fresh_install_shows_what_to_do_first() {
        let i = Inputs { mfa: "off".into(), break_glass: true, signin_alerts: true, approvals_ask: true, tiers: 1, testing: true, license_mode: "unlicensed".into(), ..Default::default() };
        let r = check(&i, &[]);
        assert!(!r.ready());
        assert_eq!(
            of(&r, Status::Open),
            ["deployment", "idp", "sso_admin", "mfa", "break_glass", "isolation", "approvals", "server_backups", "database_encryption", "status_page", "metrics", "first_bundle"]
        );
        assert_eq!(of(&r, Status::NotApplicable), ["region", "jit_allow_list", "hardening", "machine_backups", "residency_region", "backup_region"]);
        assert_eq!(status(&r, "plan").1, "This server sells the built-in self-host plan; 0 seats in use, no seat limit. Confirm the plan, seats and support tier with the customer.");
        assert_eq!(status(&r, "scim").0, Status::Confirm, "SCIM off is a choice to confirm");
        assert_eq!(status(&r, "status_page"), (Status::Open, "The status page is off (STATUS_PAGE=off).".into()));
    }

    #[test]
    fn identity_items_follow_the_providers_and_admins() {
        let mut i = live();
        i.providers.push(Provider { id: "entra".into(), kind: "entra".into(), ready: false, jit: false });
        assert_eq!(status(&check(&i, &[]), "idp"), (Status::Open, "Waiting for a secret or IdP metadata: entra.".into()));
        i = live();
        i.admins_with_sso = 0;
        let r = check(&i, &[]);
        assert_eq!(status(&r, "sso_admin"), (Status::Open, "None of the 2 admins besides the owner has signed in with SSO yet.".into()));
        i.admins = 0;
        assert!(status(&check(&i, &[]), "sso_admin").1.starts_with("No admin besides the owner account yet"));
        i = live();
        i.providers[0].jit = false;
        assert_eq!(status(&check(&i, &[]), "jit_allow_list").1, "Just-in-time sign-up is off: people are added by hand or by SCIM.");
        i.mfa = "admins".into();
        assert_eq!(status(&check(&i, &[]), "mfa").0, Status::Done);
        i.mfa = "off".into();
        i.providers.clear();
        assert_eq!(status(&check(&i, &[]), "mfa").0, Status::Open, "no SSO and no second factor");
        i = live();
        i.break_glass = true;
        assert_eq!(status(&check(&i, &[]), "break_glass"), (Status::Open, "Break-glass sign-in is on, and admins sign in with SSO: set AUTH_BREAK_GLASS=0 and restart botd.".into()));
        i.signin_alerts = false;
        assert_eq!(status(&check(&i, &[]), "signin_alerts").0, Status::Open);
    }

    #[test]
    fn scim_is_done_only_once_it_has_deprovisioned_someone() {
        let mut i = live();
        let cases = [
            (Scim { working_tokens: 0, ..Default::default() }, "SCIM is on, but no tenant has a working token: botctl scim token create."),
            (Scim { working_tokens: 2, tenants_expiring: 1, used_recently: true, deprovisions: 3 }, "Every token of 1 tenant ends within 14 days: botctl scim token rotate."),
            (Scim { working_tokens: 1, ..Default::default() }, "No SCIM request in the last 30 days: check provisioning is on at the identity provider."),
            (Scim { working_tokens: 1, used_recently: true, ..Default::default() }, "SCIM hasn't deprovisioned anyone yet: unassign a test user at the identity provider and check they're disabled."),
        ];
        for (s, want) in cases {
            i.scim = Some(s);
            assert_eq!(status(&check(&i, &[]), "scim"), (Status::Open, want.into()));
        }
    }

    #[test]
    fn isolation_and_machines() {
        let mut i = live();
        for (w, want) in [(Where::Users, Status::Done), (Where::Assigned, Status::Open), (Where::Shared, Status::Open)] {
            i.bots_run = w;
            assert_eq!(status(&check(&i, &[]), "isolation").0, want, "{w:?}");
        }
        i = live();
        i.machines.as_mut().unwrap().hardening = false;
        assert_eq!(status(&check(&i, &[]), "hardening").0, Status::Open);
        i = live();
        i.machines.as_mut().unwrap().rpo_breaches = 3;
        assert_eq!(status(&check(&i, &[]), "machine_backups"), (Status::Open, "3 machines are past their RPO: see botctl machine recovery.".into()));
        let m = i.machines.as_mut().unwrap();
        (m.off_host_backups, m.provider_backups, m.rpo_breaches) = (false, false, 0);
        assert_eq!(status(&check(&i, &[]), "machine_backups").0, Status::Open);
        i.machines.as_mut().unwrap().provider_backups = true;
        assert_eq!(status(&check(&i, &[]), "machine_backups").0, Status::Done);
        i = live();
        i.notices = false;
        assert_eq!(status(&check(&i, &[]), "approvals").0, Status::Open, "Bots ask, but nobody hears");
        i.approvals_ask = false;
        assert!(status(&check(&i, &[]), "approvals").1.starts_with("Approvals are off (bypass)"));
    }

    #[test]
    fn server_backups_need_a_copy_within_the_rpo_and_encryption() {
        let mut i = live();
        let base = ServerBackups { off_host: true, copied: true, breach: false, rpo_hours: 26 };
        for (b, want) in [
            (ServerBackups { off_host: false, ..base.clone() }, "Server backups stay on this host"),
            (ServerBackups { breach: true, ..base.clone() }, "The newest copy off the host is past its RPO of 26 hours"),
            (ServerBackups { copied: false, ..base.clone() }, "Copies are set up, but none has been made yet"),
        ] {
            i.server_backups = Some(b);
            let (s, d) = status(&check(&i, &[]), "server_backups");
            assert!(s == Status::Open && d.starts_with(want), "{d}");
        }
        i.server_backups = Some(base);
        i.backups_encrypted = false;
        assert!(status(&check(&i, &[]), "server_backups").1.contains("not every backup is encrypted"));
        i.database_encrypted = false;
        assert_eq!(status(&check(&i, &[]), "database_encryption").0, Status::Open);
    }

    #[test]
    fn residency_follows_regions_warnings_and_backup_stores() {
        let mut i = live();
        i.residency.as_mut().unwrap().warnings = 2;
        assert_eq!(status(&check(&i, &[]), "residency_region"), (Status::Open, "2 residency warnings: see botctl regions.".into()));
        i = live();
        let r = i.residency.as_mut().unwrap();
        (r.teams_with_region, r.pins) = (0, 0);
        assert_eq!(status(&check(&i, &[]), "residency_region").0, Status::Open);
        i = live();
        i.residency.as_mut().unwrap().backups = Some((false, 1));
        assert_eq!(
            status(&check(&i, &[]), "backup_region"),
            (Status::Open, "Backups of machines in 1 region go to the default store: set a store there, or MACHINE_BACKUP_RESIDENCY=strict.".into())
        );
        i.residency.as_mut().unwrap().backups = Some((false, 0));
        assert_eq!(status(&check(&i, &[]), "backup_region").0, Status::Done);
        i.residency.as_mut().unwrap().backups = None;
        assert_eq!(status(&check(&i, &[]), "backup_region").0, Status::NotApplicable);
    }

    #[test]
    fn go_live_items() {
        let mut i = live();
        i.setup_open = vec!["domain".into(), "license".into()];
        i.bundles = 0;
        i.metrics = None;
        let r = check(&i, &[]);
        assert_eq!(status(&r, "setup"), (Status::Open, "Still open in botctl setup: domain, license.".into()));
        assert_eq!(status(&r, "first_bundle").0, Status::Open);
        assert_eq!(status(&r, "metrics").0, Status::Open);
        i.metrics = Some(true);
        assert_eq!(status(&check(&i, &[]), "metrics").1, "Metrics are on, on loopback. Confirm the alert rules are loaded and logs are shipped.");
    }

    #[test]
    fn skips_cover_what_is_open_or_to_confirm_and_say_when_unneeded() {
        let mut i = live();
        i.database_encrypted = false;
        i.scim = None;
        let r = check(&i, &skips("database_encryption, SCIM,idp,database_encryption").unwrap());
        assert!(r.ready());
        assert_eq!((status(&r, "database_encryption").0, status(&r, "scim").0), (Status::Skipped, Status::Skipped));
        assert_eq!(r.unneeded_skips, ["idp"]);
        let v = r.view("2027-01-01T00:00:00Z");
        assert_eq!(v["skipped"], json!(["scim", "database_encryption"]));
        assert_eq!(v["unneededSkips"], json!(["idp"]));
        assert_eq!(v["counts"]["skipped"], 2);
        assert_eq!(skips("").unwrap(), Vec::<&str>::new());
        let e = skips("scim,nope").unwrap_err();
        assert!(e.starts_with("skip: no item \"nope\". Items: plan, contacts,"), "{e}");
        assert!(skips("jane@example.com").unwrap_err().contains("\"[text]\""), "a typed note or address is never echoed");
    }

    #[test]
    fn the_view_and_audit_hold_ids_and_counts() {
        let mut i = live();
        i.bundles = 0;
        let r = check(&i, &[]);
        let v = r.view("2027-01-01T00:00:00Z");
        assert_eq!((v["format"].clone(), v["ready"].clone(), v["open"].clone()), (json!(FORMAT), json!(false), json!(["first_bundle"])));
        assert_eq!(v["items"].as_array().unwrap().len(), ITEMS.len());
        assert_eq!(v["items"][0], json!({ "id": "plan", "section": "kickoff", "label": ITEMS[0].label, "status": "confirm", "detail": status(&r, "plan").1, "guide": "docs/support/tiers.md" }));
        assert_eq!(v["sections"][5], json!({ "id": "go_live", "title": "6. Monitoring and go-live" }));
        assert_eq!(r.audit_details(), json!({ "ready": false, "counts": r.counts(), "open": ["first_bundle"], "skipped": [] }));
    }

    /// Each item is a line of onboarding.md's checklist, in its section and order, and
    /// each guide is a file in the repository.
    #[test]
    fn the_items_are_the_checklist() {
        let md = include_str!("../../docs/support/onboarding.md");
        let mut section = None;
        let mut lines: Vec<(&str, &str)> = Vec::new();
        for l in md.lines() {
            if let Some(h) = l.strip_prefix("## ") {
                section = SECTIONS.iter().find(|(_, title)| *title == h).map(|(id, _)| *id);
            } else if let Some(text) = l.strip_prefix("- [ ] ") {
                lines.push((section.unwrap_or_else(|| panic!("a checklist line outside the six sections: {l}")), text));
            }
        }
        assert_eq!(lines.len(), ITEMS.len(), "onboarding.md has {} checklist lines", lines.len());
        for ((sec, text), it) in lines.iter().zip(ITEMS.iter()) {
            assert_eq!(*sec, it.section, "{}", it.id);
            assert!(text.starts_with(it.line), "{}: onboarding.md says \"{text}\"", it.id);
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
        let mut i = live();
        i.setup_open = vec!["backups".into()];
        let text = check(&i, &[]).view("2027-01-01T00:00:00Z").to_string();
        for leak in ["@", "s3://", "http://", "https://"] {
            assert!(!text.contains(leak), "{leak} in {text}");
        }
    }
}
