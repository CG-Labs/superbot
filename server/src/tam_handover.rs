//! The TAM handover draft (ADR 0278): the handover note `docs/support/tam.md#handover`
//! asks for when an Enterprise customer changes technical account manager, or its TAM is
//! away for more than two weeks, with the parts botd can fill in from its own records: the
//! deployment summary (version, sign-in providers, SCIM, roles, machines and regions,
//! backups, approvals, Bots by harness, people and seats, the license), the health score
//! now with its signals at watch or at risk and its trend, the last monthly health check
//! (`support.health_checked`, ADR 0252) and business review (`support.business_review_drafted`,
//! ADR 0262), what the monthly health check finds open now, incidents still open or
//! without a review (ADR 0201), and the dates coming up. Tickets, promises, the people and
//! the dates botd can't see are left for the TAM, marked "To fill in".
//!
//! `GET /api/support/tam-handover[?format=markdown]` (admins, audited as
//! `support.tam_handover_drafted`) and `botctl tam-handover`. Codes, counts, dates, provider ids,
//! harness names, region ids and incident ids only: never a person's name or email, an
//! incident's title, an address or a bucket.

use crate::audit::{Filter, Who};
use crate::business_review::{Format, Incident, Ym, cell, code, date, duration, plural, utc};
use crate::health_check::{self, Status};
use crate::{ApiError, AppState, Auth, Res, bad};
use axum::Json;
use axum::extract::{ConnectInfo, Extension, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use serde_json::{Value, json};
use std::collections::{BTreeMap, HashMap};
use std::fmt::Write;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

/// Bumped when the JSON's shape changes.
pub const FORMAT: u32 = 1;
pub const DRAFTED: &str = "support.tam_handover_drafted";
pub const GUIDE: &str = "docs/support/tam.md#handover";
const TODO: &str = "_To fill in._";
const MINUTE: i64 = 60_000;
const DAY_MS: i64 = 86_400_000;
/// Incidents of a reviewed impact resolved this long ago or less, with no review, are still owed one.
pub const REVIEW_DAYS: i64 = health_check::QUARTER_DAYS;
const REPO: &str = "https://github.com/CG-Labs/superbot/blob/main";

/// `?format=json|markdown`; anything else is refused without echoing what isn't an id.
pub fn parse_query(q: &HashMap<String, String>) -> Result<Format, String> {
    if let Some(k) = q.keys().find(|k| k.as_str() != "format") {
        let shown = if k.len() <= 40 && k.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') { k.as_str() } else { "[text]" };
        return Err(format!("Unknown parameter \"{shown}\". The handover takes format=json or markdown, and covers the deployment as it is now."));
    }
    match q.get("format").map(|v| v.trim()) {
        None | Some("" | "json") => Ok(Format::Json),
        Some("markdown" | "md") => Ok(Format::Markdown),
        Some(_) => Err("format must be json or markdown".into()),
    }
}

#[derive(Clone, Debug, Default, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SignIn {
    pub provider: String,
    /// `entra`, `google`, `oidc`, `apple`, `github`, `saml_broker` or `saml`.
    pub kind: String,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Harness {
    pub harness: String,
    pub bots: usize,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Deployment {
    pub version: String,
    pub sign_in: Vec<SignIn>,
    pub scim: bool,
    pub scim_working_tokens: usize,
    pub google_sync: bool,
    pub custom_roles: usize,
    pub role_holders: usize,
    pub machines: bool,
    /// The data regions offered, when botd runs users' machines.
    pub regions: Vec<String>,
    /// The health score's backups summary.
    pub backups: String,
    /// Approvals ask (`true`) or are bypassed.
    pub approvals_ask: bool,
    /// Most Bots first.
    pub harnesses: Vec<Harness>,
    pub people: u64,
    pub active: u64,
    pub seats_used: Option<u64>,
    pub seat_cap: Option<u64>,
    /// None in testing mode with no license.
    pub license_mode: Option<String>,
    pub license_usable: bool,
    pub license_ends_at: Option<i64>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Signal {
    pub id: String,
    /// `watch` or `risk`.
    pub status: String,
    pub summary: String,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Health {
    pub score: Option<u32>,
    pub band: String,
    /// Signals at risk first, then at watch, in the playbook's order.
    pub signals: Vec<Signal>,
    /// The audit log keeps less than the score's window.
    pub partial: bool,
    pub history_recording: bool,
    /// `health_history::trend` over the last month, or null.
    pub trend: Value,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LastCheck {
    pub at: i64,
    pub score: Option<u32>,
    pub band: String,
    pub open: Vec<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LastReview {
    pub at: i64,
    /// The quarter's months, `YYYY-MM`.
    pub from: String,
    pub to: String,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Open {
    pub id: String,
    pub label: String,
    pub detail: String,
    pub guide: String,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Due {
    /// `license_end`, `saml_certificate`, `scim_tokens`, `health_check`, `business_review` or `access_review`.
    pub what: String,
    /// `YYYY-MM-DD`, when botd knows the day.
    pub on: Option<String>,
    /// The day has passed.
    pub overdue: bool,
    pub detail: String,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Draft {
    pub format: u32,
    pub drafted_at: i64,
    pub guide: &'static str,
    pub deployment: Deployment,
    pub health: Health,
    pub last_health_check: Option<LastCheck>,
    pub last_business_review: Option<LastReview>,
    /// The monthly health check's items open now, in its order.
    pub open: Vec<Open>,
    /// Still open, or of a reviewed impact with no review drafted, oldest first.
    pub incidents: Vec<Incident>,
    /// Days known first, soonest first; then those botd knows only roughly.
    pub dates: Vec<Due>,
}

fn kind_of(k: &crate::sso::Kind) -> &'static str {
    use crate::sso::Kind::*;
    match k {
        Entra { .. } => "entra",
        Google { .. } => "google",
        Oidc { .. } => "oidc",
        Apple { .. } => "apple",
        GitHub { .. } => "github",
        Saml { .. } => "saml_broker",
        SamlSp { .. } => "saml",
    }
}

fn kind_words(k: &str) -> &str {
    match k {
        "entra" => "Microsoft Entra ID",
        "google" => "Google",
        "oidc" => "OpenID Connect",
        "apple" => "Sign in with Apple",
        "github" => "GitHub",
        "saml_broker" => "SAML through a broker",
        "saml" => "native SAML",
        k => code(k),
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

fn strings(v: &Value) -> Vec<String> {
    v.as_array().into_iter().flatten().filter_map(|s| s.as_str().map(|s| code(s).to_string())).collect()
}

fn due(what: &str, on: Option<i64>, today: &str, detail: String) -> Due {
    let on = on.map(date);
    Due { what: what.into(), overdue: on.as_deref().is_some_and(|d| d < today), on, detail }
}

/// The dates coming up, from what the draft already holds and the health check's inputs.
pub fn dates(d: &Draft, saml: &[health_check::Cert], scim_tenants_expiring: usize, access_review_at: Option<i64>, now_ms: i64) -> Vec<Due> {
    let today = date(now_ms);
    let mut out = Vec::new();
    let dep = &d.deployment;
    if let (Some(mode), Some(end)) = (dep.license_mode.as_deref(), dep.license_ends_at) {
        let detail = match mode {
            "grace" => "The license has ended and is in its grace period: the renewal is with the account owner.".to_string(),
            _ if end <= now_ms => "The license has ended: botctl license.".to_string(),
            _ => "The license ends: its renewal is with the account owner, 90 days before.".to_string(),
        };
        out.push(due("license_end", Some(end), &today, detail));
    }
    for c in saml {
        let detail = format!(
            "{}'s {} {}{}.",
            code(&c.provider),
            role_words(&c.role),
            if c.ends_at <= now_ms { "has ended" } else { "ends" },
            if c.covered { ", with a newer one already in use" } else { ": nothing replaces it yet; record who rotates it (botctl sso saml <provider>)" }
        );
        out.push(due("saml_certificate", Some(c.ends_at), &today, detail));
    }
    let check = d.last_health_check.as_ref().map_or(now_ms, |c| c.at + health_check::MONTH_DAYS * DAY_MS);
    let detail = match &d.last_health_check {
        Some(c) => format!("The next monthly health check; the last was on {}.", date(c.at)),
        None => "The monthly health check: botd has none recorded, so it's due now (botctl health-check).".into(),
    };
    out.push(due("health_check", Some(check), &today, detail));
    match d.last_business_review.as_ref().and_then(|r| Ym::parse(&r.to).map(|to| (r, to))) {
        Some((r, to)) => out.push(due(
            "business_review",
            Some(to.plus(4).start_ms()),
            &today,
            format!("The next quarterly business review, for {} to {}; the last draft covered {} to {}.", to.plus(1).id(), to.plus(3).id(), code(&r.from), code(&r.to)),
        )),
        None => out.push(due("business_review", None, &today, "botd has no business review drafted: draft the last quarter's with botctl business-review.".into())),
    }
    match access_review_at {
        Some(at) => out.push(due(
            "access_review",
            Some(at + health_check::QUARTER_DAYS * DAY_MS),
            &today,
            format!("An access review, if the customer's policy asks for one each quarter; the last was signed off on {}.", date(at)),
        )),
        None => out.push(due("access_review", None, &today, "botd has no access review signed off: one is due if the customer's policy asks for one each quarter.".into())),
    }
    if scim_tenants_expiring > 0 {
        out.push(due(
            "scim_tokens",
            None,
            &today,
            format!(
                "Every SCIM token of {} ends within {} days: botctl scim token rotate.",
                plural(scim_tenants_expiring as u64, "tenant", "tenants"),
                crate::scim::WARN_DAYS
            ),
        ));
    }
    out.sort_by(|a, b| match (&a.on, &b.on) {
        (Some(x), Some(y)) => x.cmp(y),
        (Some(_), None) => std::cmp::Ordering::Less,
        (None, Some(_)) => std::cmp::Ordering::Greater,
        (None, None) => std::cmp::Ordering::Equal,
    });
    out
}

/// The draft as of `now_ms`, from the 30-day health score, the last month's history, the
/// health check's reading of botd's records and the setup wizard's checklist.
pub fn build(app: &AppState, a: &Auth, setup: &Value, now_ms: i64) -> rusqlite::Result<Draft> {
    let report = crate::health_score::build(app, now_ms, health_check::SCORE_DAYS);
    let history = crate::health_history::history(app, now_ms, health_check::MONTH_DAYS)?;
    let since = now_ms - REVIEW_DAYS * DAY_MS;
    let listed = app.db.status_incidents_between(since, i64::MAX)?;
    let inputs = health_check::gather_with(app, a, setup, now_ms, &report, Some(&history));
    let checked = health_check::check(&inputs);

    let signal = |id: &str| report["signals"].as_array().into_iter().flatten().find(|s| s["id"] == id).cloned().unwrap_or(Value::Null);
    let mut signals = Vec::new();
    for want in ["risk", "watch"] {
        for s in &crate::health_score::SIGNALS {
            let v = signal(s.id);
            if v["status"] == want {
                signals.push(Signal { id: s.id.into(), status: want.into(), summary: v["summary"].as_str().unwrap_or_default().into() });
            }
        }
    }

    let newest = |action: &str| app.db.audit_events(&Filter { actions: vec![action.into()], ..Default::default() }, 1, false).into_iter().next();
    let last_health_check = newest(health_check::CHECKED).map(|e| LastCheck {
        at: e.at,
        score: e.details["score"].as_u64().and_then(|s| u32::try_from(s).ok()),
        band: code(e.details["band"].as_str().unwrap_or("unknown")).to_string(),
        open: strings(&e.details["open"]),
    });
    let last_business_review = newest(crate::business_review::DRAFTED).map(|e| LastReview {
        at: e.at,
        from: code(e.details["from"].as_str().unwrap_or_default()).to_string(),
        to: code(e.details["to"].as_str().unwrap_or_default()).to_string(),
    });
    let access_review_at = newest(crate::access_review::COMPLETED).map(|e| e.at);

    let reviewed = |id: &str| {
        let f = Filter { from: listed.iter().map(|i| i.created_at).min(), actions: vec!["status.incident_reviewed".into()], target_id: Some(id.into()), ..Default::default() };
        !app.db.audit_events(&f, 1, false).is_empty()
    };
    let mut incidents: Vec<Incident> = listed
        .iter()
        .map(|i| Incident {
            id: i.id.clone(),
            impact: i.impact.clone(),
            posted_at: i.created_at,
            resolved_at: i.resolved_at,
            minutes: (i.resolved_at.unwrap_or(now_ms) - i.created_at).max(0) / MINUTE,
            reviewed: reviewed(&i.id),
        })
        .filter(|i| i.resolved_at.is_none() || i.needs_review())
        .collect();
    incidents.sort_by_key(|i| i.posted_at);

    let mut by: BTreeMap<String, usize> = BTreeMap::new();
    for b in app.db.bots() {
        *by.entry(code(&b.harness).to_string()).or_default() += 1;
    }
    let mut harnesses: Vec<Harness> = by.into_iter().map(|(harness, bots)| Harness { harness, bots }).collect();
    harnesses.sort_by(|a, b| b.bots.cmp(&a.bots).then(a.harness.cmp(&b.harness)));

    let (adoption, lf) = (signal("adoption"), signal("license")["facts"].clone());
    let cp = &a.machines;
    let deployment = Deployment {
        version: inputs.version.clone(),
        sign_in: a.sso.providers.iter().map(|p| SignIn { provider: code(&p.id).to_string(), kind: kind_of(&p.kind).into() }).collect(),
        scim: inputs.scim.is_some(),
        scim_working_tokens: inputs.scim.as_ref().map_or(0, |s| s.working_tokens),
        google_sync: inputs.scim.as_ref().is_some_and(|s| s.google.is_some()),
        custom_roles: inputs.custom_roles,
        role_holders: inputs.role_holders,
        machines: cp.enabled(),
        regions: if cp.enabled() { cp.regions.iter().map(|r| code(r).to_string()).collect() } else { Vec::new() },
        backups: signal("backups")["summary"].as_str().unwrap_or_default().to_string(),
        approvals_ask: inputs.approvals_ask,
        harnesses,
        people: adoption["facts"]["people"].as_u64().unwrap_or(0),
        active: adoption["facts"]["active"].as_u64().unwrap_or(0),
        seats_used: lf["seatsUsed"].as_u64(),
        seat_cap: lf["seats"].as_u64(),
        license_mode: lf["mode"].as_str().map(|m| code(m).to_string()),
        license_usable: lf["usable"] == true,
        license_ends_at: lf.is_object().then(|| app.license.status_at(now_ms).expires_at()).flatten(),
    };

    let mut d = Draft {
        format: FORMAT,
        drafted_at: now_ms,
        guide: GUIDE,
        deployment,
        health: Health {
            score: inputs.score.score,
            band: code(&inputs.score.band).to_string(),
            signals,
            partial: inputs.score.partial,
            history_recording: history["recording"] == true,
            trend: history["trend"].clone(),
        },
        last_health_check,
        last_business_review,
        open: checked
            .items
            .iter()
            .zip(health_check::ITEMS.iter())
            .filter(|(j, _)| j.status == Status::Open)
            .map(|(j, it)| Open { id: j.id.into(), label: it.label.into(), detail: j.detail.clone(), guide: it.guide.into() })
            .collect(),
        incidents,
        dates: Vec::new(),
    };
    let ending = inputs.saml.as_ref().map(|s| s.ending.clone()).unwrap_or_default();
    let expiring = inputs.scim.as_ref().map_or(0, |s| s.tenants_expiring);
    d.dates = dates(&d, &ending, expiring, access_review_at, now_ms);
    Ok(d)
}

fn ids(v: &[String]) -> String {
    v.iter().map(|s| format!("`{}`", code(s))).collect::<Vec<_>>().join(", ")
}

impl Draft {
    pub fn json(&self) -> Value {
        serde_json::to_value(self).unwrap_or_default()
    }

    /// The handover note as `tam.md` lists it, with what botd can't see left for the TAM.
    pub fn markdown(&self) -> String {
        let mut m = String::new();
        let _ = writeln!(m, "# `<customer>`: TAM handover\n");
        let _ = writeln!(
            m,
            "Draft made by botd on {} UTC from its own records, for the [handover]({REPO}/{GUIDE}) when a customer changes technical account manager \
             or its TAM is away for more than two weeks ([ADR 0278]({REPO}/docs/adr/0278-tam-handover-draft.md)). \
             From `<old-tam>` to `<new-tam>`. Replace every \"{TODO}\" and keep the note in the customer's record: botd names nobody.\n",
            utc(self.drafted_at)
        );

        let d = &self.deployment;
        let _ = writeln!(m, "## 1. The deployment\n");
        let _ = writeln!(m, "- **Where it runs:** {TODO} Managed shared, dedicated, VPC or on-premises; connected or air-gapped; who operates it.");
        let _ = writeln!(m, "- **Version:** botd {}. Releases since with an action for them: {TODO}", code(&d.version));
        if d.sign_in.is_empty() {
            let _ = writeln!(m, "- **Sign-in:** no single sign-on provider; passwords and sign-in codes only.");
        } else {
            let by: Vec<String> = d.sign_in.iter().map(|s| format!("`{}` ({})", code(&s.provider), kind_words(&s.kind))).collect();
            let _ = writeln!(m, "- **Sign-in:** {}. The identity provider's admin and their MFA policy: {TODO}", by.join(", "));
        }
        let scim = match (d.scim, d.google_sync) {
            (false, _) => "off.".to_string(),
            (true, true) => format!("on, with the Google Workspace sync and {}.", plural(d.scim_working_tokens as u64, "working token", "working tokens")),
            (true, false) => format!("on, with {}.", plural(d.scim_working_tokens as u64, "working token", "working tokens")),
        };
        let _ = writeln!(m, "- **SCIM:** {scim}");
        let _ = writeln!(
            m,
            "- **Roles:** {}; {} one across the server.",
            plural(d.custom_roles as u64, "custom role", "custom roles"),
            plural(d.role_holders as u64, "person holds", "people hold")
        );
        if d.machines {
            let regions = if d.regions.is_empty() { "no data regions offered".to_string() } else { format!("data regions {}", ids(&d.regions)) };
            let _ = writeln!(m, "- **Machines:** botd runs users' machines; {regions}. Residency pins: `botctl regions`.");
        } else {
            let _ = writeln!(m, "- **Machines:** botd runs no users' machines.");
        }
        if !d.backups.is_empty() {
            let _ = writeln!(m, "- **Backups:** {}", cell(&d.backups));
        }
        let _ = writeln!(
            m,
            "- **Approvals:** {}",
            if d.approvals_ask { "risky actions ask (`botctl policy`)." } else { "**off (bypass)**: Bots run risky actions without asking." }
        );
        if d.harnesses.is_empty() {
            let _ = writeln!(m, "- **Bots:** none yet.");
        } else {
            let by: Vec<String> = d.harnesses.iter().map(|h| format!("`{}` {}", code(&h.harness), h.bots)).collect();
            let total: usize = d.harnesses.iter().map(|h| h.bots).sum();
            let _ = writeln!(m, "- **Bots:** {}, by harness: {}. Model provider accounts: {TODO}", plural(total as u64, "Bot", "Bots"), by.join(", "));
        }
        let seats = match (d.seats_used, d.seat_cap) {
            (Some(used), Some(cap)) => format!("; {used} of {cap} licensed seats in use"),
            (Some(used), None) => format!("; {}, no seat limit", plural(used, "seat in use", "seats in use")),
            _ => String::new(),
        };
        let _ = writeln!(m, "- **People:** {} of {} signed in or used SuperBot in the last 30 days{seats}.", d.active, plural(d.people, "person", "people"));
        let license = match (d.license_mode.as_deref(), d.license_ends_at) {
            (None, _) => "testing mode, with no license installed.".to_string(),
            (Some(mode), _) if !d.license_usable => format!("no usable license ({}), so Bots don't run: `botctl license`.", code(mode)),
            (Some("grace"), _) => "ended, in its grace period.".to_string(),
            (Some(_), Some(end)) if end > self.drafted_at => format!("ends on {}.", date(end)),
            (Some(_), Some(_)) => "ended.".to_string(),
            (Some(_), None) => "doesn't end.".to_string(),
        };
        let _ = writeln!(m, "- **License:** {license}");
        let _ = writeln!(m, "- **Network:** {TODO} Proxies, outbound allow-lists (`botctl machine egress`), and anything unusual.\n");

        let h = &self.health;
        let _ = writeln!(m, "## 2. Health\n");
        let score = h.score.map_or("no score".to_string(), |s| s.to_string());
        let band = if h.band == "at_risk" { "at risk" } else { code(&h.band) };
        let partial = if h.partial { " The audit log keeps less than 30 days, so some signals see less." } else { "" };
        let _ = writeln!(m, "The [health score]({REPO}/docs/support/health-score.md) over the last 30 days is {score}, {band}.{partial}\n");
        if h.signals.is_empty() {
            let _ = writeln!(m, "- No signal is at watch or at risk.");
        } else {
            for s in &h.signals {
                let state = if s.status == "risk" { "at risk" } else { "at watch" };
                let _ = writeln!(m, "- `{}`, {state}: {} What's being done: {TODO}", code(&s.id), cell(&s.summary));
            }
        }
        let t = &h.trend;
        if !h.history_recording {
            let _ = writeln!(m, "- botd doesn't record the score (`HEALTH_SCORE_HISTORY_DAYS=0`): take last month's from the customer's record.");
        } else if t.is_null() {
            let _ = writeln!(m, "- botd recorded too few days in the last {} for a trend.", plural(health_check::MONTH_DAYS as u64, "day", "days"));
        } else {
            let s = |v: &Value| v.as_u64().map_or("no score".to_string(), |s| s.to_string());
            let mut moved = format!(
                "- Over the last {} days the score went from {} on {} to {} on {}",
                health_check::MONTH_DAYS,
                s(&t["fromScore"]),
                code(t["from"].as_str().unwrap_or_default()),
                s(&t["toScore"]),
                code(t["to"].as_str().unwrap_or_default())
            );
            for (key, word) in [("worse", "worse"), ("better", "better")] {
                let list = strings(&t[key]);
                if !list.is_empty() {
                    moved.push_str(&format!("; {word}: {}", ids(&list)));
                }
            }
            let _ = writeln!(m, "{moved}.");
        }
        match &self.last_health_check {
            Some(c) => {
                let open = if c.open.is_empty() { "nothing open".to_string() } else { format!("open: {}", ids(&c.open)) };
                let score = c.score.map_or("no score".to_string(), |s| format!("score {s}"));
                let _ = writeln!(m, "- The last monthly health check was on {}: {score}, {open}.", date(c.at));
            }
            None => _ = writeln!(m, "- botd has no monthly health check recorded: run `botctl health-check`."),
        }
        match &self.last_business_review {
            Some(r) => _ = writeln!(m, "- The last business review draft was made on {}, for {} to {}.", date(r.at), code(&r.from), code(&r.to)),
            None => _ = writeln!(m, "- botd has no business review drafted: `botctl business-review`."),
        }
        let _ = writeln!(m);

        let _ = writeln!(m, "## 3. Open work\n");
        if self.open.is_empty() {
            let _ = writeln!(m, "The [monthly health check]({REPO}/docs/support/health-check.md) finds nothing open now.\n");
        } else {
            let _ = writeln!(m, "What the [monthly health check]({REPO}/docs/support/health-check.md) finds open now, each with its owner and date in the customer's record:\n");
            let _ = writeln!(m, "| Item | What botd sees | Guide |\n|---|---|---|");
            for o in &self.open {
                let _ = writeln!(m, "| {} | {} | [{}]({REPO}/{}) |", cell(&o.label), cell(&o.detail), cell(o.guide.split('#').next().unwrap_or_default()), cell(&o.guide));
            }
            let _ = writeln!(m);
        }
        if self.incidents.is_empty() {
            let _ = writeln!(m, "- No status page incident is open, and every major or critical one in the last {REVIEW_DAYS} days has a review drafted.");
        } else {
            let _ = writeln!(m, "Status page incidents still open, or major or critical with no review drafted (UTC):\n");
            let _ = writeln!(m, "| Incident | Impact | Posted | State | Duration | Next |\n|---|---|---|---|---|---|");
            for i in &self.incidents {
                let state = i.resolved_at.map_or("still open".to_string(), |r| format!("resolved {}", utc(r)));
                let mut next = Vec::new();
                if i.resolved_at.is_none() {
                    next.push("resolve it".to_string());
                }
                if i.needs_review() {
                    next.push(format!("`botctl incident review {}`", code(&i.id)));
                }
                let _ = writeln!(m, "| `{}` | {} | {} | {state} | {} | {} |", code(&i.id), code(&i.impact), utc(i.posted_at), duration(i.minutes), next.join("; "));
            }
            let _ = writeln!(m);
        }
        let _ = writeln!(
            m,
            "- **Open tickets:** {TODO} botd can't see the ticket system: `botctl support-report <export> --customer \"<customer>\"` lists what's still open."
        );
        let _ = writeln!(m, "- **Open incident actions:** {TODO} From each review's actions table.");
        let _ = writeln!(m, "- **Promises made:** {TODO} A feature, a date, a call.\n");

        let _ = writeln!(m, "## 4. The people\n");
        let _ = writeln!(
            m,
            "{TODO} The customer's owner, sponsor, IdP admin and security contact, and who may raise Severity 1, by role; how they like to work (channel, meeting times, who decides). \
             Kept in the customer's record, never in this draft's copy in a ticket.\n"
        );

        let _ = writeln!(m, "## 5. Upcoming dates\n");
        let _ = writeln!(m, "| When | What |\n|---|---|");
        for due in &self.dates {
            let when = match (&due.on, due.overdue) {
                (Some(d), true) => format!("{} (**overdue**)", code(d)),
                (Some(d), false) => code(d).to_string(),
                (None, _) => "not known".to_string(),
            };
            let _ = writeln!(m, "| {when} | {} |", cell(&due.detail));
        }
        for what in ["The renewal, and any change of seats or plan", "Upgrade windows agreed", "The next restore drill", "The next check-in, where the old TAM introduces the new one"] {
            let _ = writeln!(m, "| {TODO} | {what} |");
        }
        let _ = writeln!(m, "\nThe old TAM joins the next check-in to introduce the new one. Keep the filled-in note in the customer's record, with access limited to the people who work with them.");
        m
    }

    /// What `support.tam_handover_drafted` records: codes and counts only.
    pub fn audit_details(&self, format: Format) -> Value {
        json!({
            "format": if format == Format::Markdown { "markdown" } else { "json" },
            "score": self.health.score,
            "band": self.health.band,
            "open": self.open.iter().map(|o| o.id.as_str()).collect::<Vec<_>>(),
            "incidents": self.incidents.len(),
            "overdue": self.dates.iter().filter(|d| d.overdue).map(|d| d.what.as_str()).collect::<Vec<_>>(),
        })
    }
}

type Peer = Option<Extension<ConnectInfo<SocketAddr>>>;

/// `GET /api/support/tam-handover[?format=markdown]` (admins). Audited, so each handover shows
/// in the log beside the monthly checks and quarterly reviews.
pub async fn get(
    State(app): State<AppState>,
    Extension(a): Extension<Arc<Auth>>,
    Extension(by): Extension<Who>,
    Query(q): Query<HashMap<String, String>>,
    headers: HeaderMap,
    peer: Peer,
) -> Res<Response> {
    let format = parse_query(&q).map_err(bad)?;
    let peer: Option<IpAddr> = peer.map(|Extension(ConnectInfo(p))| p.ip());
    let setup = crate::setup::report(&app, &a, &headers, peer);
    let now_ms = crate::db::now();
    let d = {
        let app = app.clone();
        tokio::task::spawn_blocking(move || build(&app, &a, &setup, now_ms))
            .await
            .map_err(|e| ApiError(StatusCode::INTERNAL_SERVER_ERROR, format!("Couldn't draft the handover: {e}")))?
            // A record botd can't read isn't one it doesn't have: no draft, rather than one saying "none".
            .map_err(|e| ApiError(StatusCode::INTERNAL_SERVER_ERROR, format!("Couldn't read botd's records for the handover: {e}")))?
    };
    app.db.record(&by.event(DRAFTED).target("setup", "server").details(d.audit_details(format)));
    if format == Format::Json {
        return Ok(Json(d.json()).into_response());
    }
    let mut res = d.markdown().into_response();
    let h = res.headers_mut();
    h.insert(header::CONTENT_TYPE, HeaderValue::from_static("text/markdown; charset=utf-8"));
    if let Ok(v) = HeaderValue::from_str(&format!("attachment; filename=\"tam-handover-{}.md\"", date(now_ms))) {
        h.insert(header::CONTENT_DISPOSITION, v);
    }
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    h.insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    Ok(res)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 2026-11-24T22:00:00Z.
    const NOW: i64 = 1_795_557_600_000;

    fn q(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    fn ms(day: &str) -> i64 {
        chrono::NaiveDate::parse_from_str(day, "%Y-%m-%d").unwrap().and_hms_opt(9, 0, 0).unwrap().and_utc().timestamp_millis()
    }

    /// An Enterprise customer with a little of everything: SAML and SCIM, machines in two
    /// regions, a signal at risk and one at watch, an open item, an incident owed a review.
    fn draft() -> Draft {
        Draft {
            format: FORMAT,
            drafted_at: NOW,
            guide: GUIDE,
            deployment: Deployment {
                version: "0.9.0".into(),
                sign_in: vec![SignIn { provider: "okta".into(), kind: "saml".into() }, SignIn { provider: "google".into(), kind: "google".into() }],
                scim: true,
                scim_working_tokens: 2,
                custom_roles: 2,
                role_holders: 3,
                machines: true,
                regions: vec!["eu".into(), "us".into()],
                backups: "The newest server backup off the host is 3 hours old, within its RPO of 26 hours; no machine is past its RPO.".into(),
                approvals_ask: true,
                harnesses: vec![Harness { harness: "claude".into(), bots: 3 }, Harness { harness: "codex".into(), bots: 1 }],
                people: 40,
                active: 31,
                seats_used: Some(40),
                seat_cap: Some(60),
                license_mode: Some("active".into()),
                license_usable: true,
                license_ends_at: Some(ms("2027-02-01")),
                ..Default::default()
            },
            health: Health {
                score: Some(64),
                band: "watch".into(),
                signals: vec![
                    Signal { id: "backups".into(), status: "risk".into(), summary: "Server backups aren't set up.".into() },
                    Signal { id: "runs".into(), status: "watch".into(), summary: "8 of 100 runs (8%) failed or timed out in the last 30 days.".into() },
                ],
                history_recording: true,
                trend: json!({ "from": "2026-10-25", "to": "2026-11-24", "fromScore": 80, "toScore": 64, "worse": ["backups"], "better": [] }),
                ..Default::default()
            },
            last_health_check: Some(LastCheck { at: ms("2026-11-03"), score: Some(70), band: "watch".into(), open: vec!["backups".into()] }),
            last_business_review: Some(LastReview { at: ms("2026-10-06"), from: "2026-07".into(), to: "2026-09".into() }),
            open: vec![Open {
                id: "backups".into(),
                label: "Server backups within their RPO".into(),
                detail: "Server backups stay on this host: set SERVER_BACKUP_S3_BUCKET to copy them off.".into(),
                guide: "docs/ops/backup-restore.md".into(),
            }],
            incidents: vec![Incident { id: "inc_7".into(), impact: "major".into(), posted_at: ms("2026-11-10"), resolved_at: Some(ms("2026-11-10") + 90 * MINUTE), minutes: 90, reviewed: false }],
            dates: Vec::new(),
        }
    }

    fn with_dates(mut d: Draft) -> Draft {
        let certs = [
            health_check::Cert { provider: "okta".into(), role: "idp_signing".into(), days_left: 20, ends_at: NOW + 20 * DAY_MS, covered: false },
            health_check::Cert { provider: "okta".into(), role: "sp_signing".into(), days_left: 45, ends_at: NOW + 45 * DAY_MS, covered: true },
        ];
        d.dates = dates(&d, &certs, 1, Some(ms("2026-07-01")), NOW);
        d
    }

    #[test]
    fn the_query_takes_a_format_and_nothing_else() {
        assert_eq!(parse_query(&q(&[])), Ok(Format::Json));
        assert_eq!(parse_query(&q(&[("format", "json")])), Ok(Format::Json));
        assert_eq!(parse_query(&q(&[("format", "markdown")])), Ok(Format::Markdown));
        assert_eq!(parse_query(&q(&[("format", "md")])), Ok(Format::Markdown));
        assert_eq!(parse_query(&q(&[("format", "pdf")])), Err("format must be json or markdown".into()));
        assert!(parse_query(&q(&[("days", "30")])).unwrap_err().starts_with("Unknown parameter \"days\""));
        let e = parse_query(&q(&[("jane@example.com", "1")])).unwrap_err();
        assert!(e.starts_with("Unknown parameter \"[text]\"") && !e.contains("jane"), "{e}");
    }

    #[test]
    fn dates_come_soonest_first_and_say_when_overdue() {
        let d = with_dates(draft());
        let order: Vec<(&str, Option<&str>, bool)> = d.dates.iter().map(|x| (x.what.as_str(), x.on.as_deref(), x.overdue)).collect();
        assert_eq!(
            order,
            [
                ("access_review", Some("2026-10-01"), true),
                ("health_check", Some("2026-12-04"), false),
                ("saml_certificate", Some("2026-12-14"), false),
                ("business_review", Some("2027-01-01"), false),
                ("saml_certificate", Some("2027-01-08"), false),
                ("license_end", Some("2027-02-01"), false),
                ("scim_tokens", None, false),
            ]
        );
        let detail = |what: &str| d.dates.iter().find(|x| x.what == what).unwrap().detail.clone();
        assert_eq!(detail("business_review"), "The next quarterly business review, for 2026-10 to 2026-12; the last draft covered 2026-07 to 2026-09.");
        assert!(d.dates[2].detail.contains("nothing replaces it yet") && d.dates[4].detail.contains("a newer one already in use"), "{:#?}", d.dates);
        assert_eq!(detail("scim_tokens"), "Every SCIM token of 1 tenant ends within 14 days: botctl scim token rotate.");
    }

    #[test]
    fn a_certificate_that_has_ended_is_overdue() {
        let d = draft();
        let ended = health_check::Cert { provider: "okta".into(), role: "idp_signing".into(), days_left: 0, ends_at: NOW - 30 * 3_600_000, covered: false };
        let due = dates(&d, &[ended], 0, None, NOW).into_iter().find(|x| x.what == "saml_certificate").unwrap();
        assert_eq!((due.on.as_deref(), due.overdue), (Some("2026-11-23"), true), "{due:?}");
        assert!(due.detail.starts_with("okta's the IdP's signing certificate has ended"), "{due:?}");
        assert_eq!(with_dates(d).audit_details(Format::Json)["overdue"], json!(["access_review"]));
    }

    #[test]
    fn with_no_records_the_checks_are_due_now() {
        let mut d = draft();
        (d.last_health_check, d.last_business_review, d.deployment.license_mode, d.deployment.license_ends_at) = (None, None, None, None);
        d.dates = dates(&d, &[], 0, None, NOW);
        let order: Vec<(&str, Option<&str>)> = d.dates.iter().map(|x| (x.what.as_str(), x.on.as_deref())).collect();
        assert_eq!(order, [("health_check", Some("2026-11-24")), ("business_review", None), ("access_review", None)]);
        assert!(!d.dates[0].overdue && d.dates[0].detail.contains("due now"));
        d.deployment.license_mode = Some("grace".into());
        d.deployment.license_ends_at = Some(ms("2026-11-20"));
        let grace = dates(&d, &[], 0, None, NOW).into_iter().find(|x| x.what == "license_end").unwrap();
        assert!(grace.overdue && grace.detail.contains("grace period"), "{grace:?}");
    }

    #[test]
    fn the_draft_has_the_handover_sections_in_order() {
        let md = with_dates(draft()).markdown();
        let headings: Vec<&str> = md.lines().filter(|l| l.starts_with("## ")).collect();
        assert_eq!(headings, ["## 1. The deployment", "## 2. Health", "## 3. Open work", "## 4. The people", "## 5. Upcoming dates"]);
        for want in [
            "# `<customer>`: TAM handover",
            "From `<old-tam>` to `<new-tam>`.",
            "- **Sign-in:** `okta` (native SAML), `google` (Google).",
            "- **SCIM:** on, with 2 working tokens.",
            "- **Roles:** 2 custom roles; 3 people hold one across the server.",
            "- **Machines:** botd runs users' machines; data regions `eu`, `us`.",
            "- **Bots:** 4 Bots, by harness: `claude` 3, `codex` 1.",
            "- **People:** 31 of 40 people signed in or used SuperBot in the last 30 days; 40 of 60 licensed seats in use.",
            "- **License:** ends on 2027-02-01.",
            "over the last 30 days is 64, watch.",
            "- `backups`, at risk: Server backups aren't set up. What's being done: _To fill in._",
            "- `runs`, at watch: 8 of 100 runs",
            "- Over the last 31 days the score went from 80 on 2026-10-25 to 64 on 2026-11-24; worse: `backups`.",
            "- The last monthly health check was on 2026-11-03: score 70, open: `backups`.",
            "- The last business review draft was made on 2026-10-06, for 2026-07 to 2026-09.",
            "| Server backups within their RPO | Server backups stay on this host",
            "| `inc_7` | major | 2026-11-10 09:00 | resolved 2026-11-10 10:30 | 1 h 30 min | `botctl incident review inc_7` |",
            "| 2026-10-01 (**overdue**) | An access review",
            "| not known | Every SCIM token of 1 tenant",
            "| _To fill in._ | The renewal, and any change of seats or plan |",
            "- **Promises made:** _To fill in._",
        ] {
            assert!(md.contains(want), "no {want:?} in:\n{md}");
        }
    }

    #[test]
    fn a_new_server_reads_plainly() {
        let mut d = Draft { drafted_at: NOW, health: Health { band: "unknown".into(), ..Default::default() }, ..Default::default() };
        d.dates = dates(&d, &[], 0, None, NOW);
        let md = d.markdown();
        for want in [
            "- **Sign-in:** no single sign-on provider; passwords and sign-in codes only.",
            "- **SCIM:** off.",
            "- **Machines:** botd runs no users' machines.",
            "- **Approvals:** **off (bypass)**",
            "- **Bots:** none yet.",
            "- **License:** testing mode, with no license installed.",
            "is no score, unknown.",
            "- No signal is at watch or at risk.",
            "- botd doesn't record the score (`HEALTH_SCORE_HISTORY_DAYS=0`)",
            "- botd has no monthly health check recorded: run `botctl health-check`.",
            "- botd has no business review drafted: `botctl business-review`.",
            "finds nothing open now.",
            "- No status page incident is open, and every major or critical one in the last 92 days has a review drafted.",
        ] {
            assert!(md.contains(want), "no {want:?} in:\n{md}");
        }
    }

    #[test]
    fn an_open_incident_is_to_resolve_and_text_cant_break_the_tables() {
        let mut d = draft();
        d.incidents = vec![Incident { id: "inc_8".into(), impact: "critical".into(), posted_at: ms("2026-11-24"), resolved_at: None, minutes: 60, reviewed: false }];
        d.open[0].detail = "a | b\nc".into();
        d.deployment.sign_in[0].provider = "evil](https://x.example)".into();
        let md = d.markdown();
        assert!(md.contains("| still open | 1 h | resolve it; `botctl incident review inc_8` |"), "{md}");
        assert!(md.contains("a \\| b c"), "{md}");
        assert!(md.contains("`[text]` (native SAML)") && !md.contains("x.example"), "{md}");
        for line in md.lines().filter(|l| l.contains("](")) {
            assert!(line.contains(&format!("]({REPO}/")), "a link off the repository: {line}");
        }
    }

    #[test]
    fn the_json_and_audit_hold_codes_and_counts() {
        let d = with_dates(draft());
        let v = d.json();
        assert_eq!((v["format"].clone(), v["guide"].clone()), (json!(FORMAT), json!(GUIDE)));
        assert_eq!(v["deployment"]["signIn"][0], json!({ "provider": "okta", "kind": "saml" }));
        assert_eq!(v["dates"][0], json!({ "what": "access_review", "on": "2026-10-01", "overdue": true, "detail": d.dates[0].detail }));
        assert_eq!(
            d.audit_details(Format::Markdown),
            json!({ "format": "markdown", "score": 64, "band": "watch", "open": ["backups"], "incidents": 1, "overdue": ["access_review"] })
        );
        let text = format!("{v}{}", d.markdown());
        assert!(!text.contains('@'), "{text}");
    }
}
