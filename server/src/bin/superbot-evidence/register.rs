//! `superbot-evidence register` (ADR 0204): the records people keep, checked and bundled.
//! The policy register is a JSON file the security owner keeps outside this repository
//! (docs/security/policy-register.md): who holds each role and deputises, each policy's
//! approvals, acknowledgements and training, the risk register and its reviews, management
//! reviews, vendor assessments and reviews, and exceptions. For a period this checks it
//! against the policies' cadences (a role without a holder, a policy unapproved, changed
//! since approval or past its yearly review, an acknowledgement or training overdue, a risk
//! unreviewed or accepted without management, a quarter without a management review, a
//! vendor unassessed or unreviewed, an exception over a year or unreviewed, a server's
//! baseline exception the register never approved) and writes a dated bundle in the shape
//! of the others, which the coverage report checks (ADR 0169).
//!
//! Never in it: names, titles, notes or reasons from the register, nor the register
//! itself. People, risks, vendors and exceptions are named by their register ids; the
//! register's SHA-256 identifies the copy kept beside the bundle.

use crate::changes::{Bundle, Section, json_file, rfc3339, sha256};
use crate::period::Period;
use chrono::{Datelike, NaiveDate, TimeDelta};
use serde::{Deserialize, Deserializer};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

/// Bumped when a file's shape changes.
pub const FORMAT: u32 = 1;
pub const PREFIX: &str = "superbot-register-";
/// The register's own format, in its `superbotRegister` field.
pub const REGISTER_FORMAT: u64 = 1;
/// A register larger than this isn't read: years of records come nowhere near it.
pub const MAX_REGISTER_BYTES: u64 = 8 << 20;
/// A baseline check larger than this isn't one.
const MAX_BASELINE_BYTES: u64 = 4 << 20;

/// The roles of the information security policy's roles table.
pub const ROLES: [&str; 6] = ["Management", "Security owner", "Engineering lead", "Operator", "People lead", "Privacy lead"];
/// The policy set, by file name, when no `--policies` folder is given.
pub const POLICIES: [&str; 8] = ["information-security", "access-control", "change-management", "incident-response", "vendor-management", "business-continuity", "data-classification-and-retention", "acceptable-use"];
/// The policies everyone with access acknowledges at hire and yearly (policy set README).
pub const ACKNOWLEDGED: [&str; 2] = ["information-security", "acceptable-use"];
/// The training everyone takes at onboarding and yearly (information security policy).
pub const AWARENESS: &str = "security-awareness";

/// Yearly: policy reviews, acknowledgements, training, risk and vendor reviews.
pub const YEAR_DAYS: i64 = 365;
/// Quarterly: management reviews and exception reviews.
pub const QUARTER_DAYS: i64 = 92;
/// How long after joining, or after a policy's first approval, an acknowledgement or the
/// awareness training is due.
pub const GRACE_DAYS: i64 = 30;
/// An exception's end is at most a year after its approval.
pub const MAX_EXCEPTION_DAYS: i64 = 365;
/// A baseline check may be from up to this long after the period: botd's monthly bundle,
/// whose `baseline.json` this is, is made after its month ends (coverage warns past 7 days).
pub const BASELINE_LATE_DAYS: i64 = 7;
/// The longest period one bundle covers. Its rows are judged as of the period's end, so a
/// longer period would let a late record cover the months before it.
pub const MAX_PERIOD_DAYS: i64 = 31;

/// Each file and the criteria and checklist rows it can be evidence for. The manifest maps
/// a file to a row only while the register holds a current record for it (a role filled
/// in the period, an approval within a year, a management review within a quarter), so a
/// register that stopped being kept shows as a gap in the coverage report.
pub const SECTIONS: [Section; 7] = [
    Section { file: "roles.json", criteria: &["CC1.3"], rows: &["CC1.3-1"] },
    Section { file: "policies.json", criteria: &["CC3.1", "CC5.3"], rows: &["CC3.1-1", "CC5.3-1"] },
    Section { file: "people.json", criteria: &["CC1.4", "CC2.2"], rows: &["CC1.4-1", "CC2.2-1"] },
    Section { file: "risks.json", criteria: &["CC3.2", "CC3.3"], rows: &["CC3.2-1", "CC3.3-1"] },
    Section { file: "management-reviews.json", criteria: &["CC1.2"], rows: &["CC1.2-1"] },
    Section { file: "vendors.json", criteria: &["CC6.4", "CC9.2"], rows: &["CC6.4-1", "CC9.2-1"] },
    Section { file: "policy-exceptions.json", criteria: &["CC5.1"], rows: &["CC5.1-1"] },
];

const README: &str = "SuperBot policy register bundle
===============================

Made by superbot-evidence, for a SOC 2 Type II evidence store
(docs/security/soc2-evidence-plan.md, ADR 0204), from the provider's private policy
register (docs/security/policy-register.md). It covers the period in manifest.json: from
its first day (00:00 UTC) up to, not including, its last. Records the register dates
after the period are left out.

  roles.json               each role's holders and deputies in the period, the days
                           without either, and holders who weren't personnel
  policies.json            each policy's latest approval, whether the text approved is
                           the text in force, and whether its yearly review is overdue
  people.json              everyone with access in the period, by register id, with their
                           acknowledgements and training, due, late or overdue
  risks.json               the open risks, scored, treated and reviewed, the full yearly
                           reviews, accepted risks and who accepted them, fraud risks
  management-reviews.json  the quarterly management reviews, who attended (by role), and
                           quarters without one
  vendors.json             vendors in use, assessed before use and reviewed yearly
  policy-exceptions.json   exceptions in force, their approvals, ends and quarterly
                           reviews, and each server's baseline exceptions held to them
  manifest.json            what is in this bundle, the period, the register's SHA-256,
                           and each file's SHA-256
  SHA256SUMS               the same digests, for `sha256sum -c SHA256SUMS`

Never in it: names, titles, notes or reasons from the register, or the register itself.
Keep the register as it was when this was made beside this bundle; its SHA-256 is in
manifest.json.
";

// The register

fn parse_day(s: &str) -> Result<NaiveDate, String> {
    NaiveDate::parse_from_str(s, "%Y-%m-%d").ok().filter(|_| s.len() == 10).ok_or(format!("{s:.40} isn't a date: use YYYY-MM-DD"))
}

fn day<'de, D: Deserializer<'de>>(d: D) -> Result<NaiveDate, D::Error> {
    parse_day(&String::deserialize(d)?).map_err(serde::de::Error::custom)
}

fn opt_day<'de, D: Deserializer<'de>>(d: D) -> Result<Option<NaiveDate>, D::Error> {
    Option::<String>::deserialize(d)?.map(|s| parse_day(&s)).transpose().map_err(serde::de::Error::custom)
}

fn days<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<NaiveDate>, D::Error> {
    Vec::<String>::deserialize(d)?.iter().map(|s| parse_day(s)).collect::<Result<_, _>>().map_err(serde::de::Error::custom)
}

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Register {
    #[allow(dead_code, reason = "checked before the register is read")]
    pub superbot_register: u64,
    #[serde(default)]
    #[allow(dead_code, reason = "accepted in the register, never put in evidence")]
    pub notes: Option<String>,
    /// The highest risk score (likelihood times impact) accepted without management.
    #[serde(default)]
    pub risk_appetite: Option<u8>,
    #[serde(default)]
    pub people: Vec<Person>,
    #[serde(default)]
    pub roles: Vec<Role>,
    #[serde(default)]
    pub policy_approvals: Vec<Approval>,
    #[serde(default)]
    pub acknowledgements: Vec<Acknowledgement>,
    #[serde(default)]
    pub training: Vec<Training>,
    #[serde(default)]
    pub risks: Vec<Risk>,
    #[serde(default)]
    pub risk_reviews: Vec<RiskReview>,
    #[serde(default)]
    pub management_reviews: Vec<ManagementReview>,
    #[serde(default)]
    pub vendors: Vec<Vendor>,
    #[serde(default)]
    pub exceptions: Vec<PolicyException>,
}

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Person {
    pub id: String,
    #[serde(default)]
    #[allow(dead_code, reason = "accepted in the register, never put in evidence")]
    pub name: Option<String>,
    #[serde(deserialize_with = "day")]
    pub joined: NaiveDate,
    /// The day their access ended, not included.
    #[serde(default, deserialize_with = "opt_day")]
    pub left: Option<NaiveDate>,
}

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Role {
    pub role: String,
    pub holder: String,
    #[serde(default)]
    pub deputy: Option<String>,
    #[serde(deserialize_with = "day")]
    pub from: NaiveDate,
    /// The day it passed to someone else, not included.
    #[serde(default, deserialize_with = "opt_day")]
    pub until: Option<NaiveDate>,
}

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Approval {
    pub policy: String,
    /// The SHA-256 of the policy's file as approved.
    pub sha256: String,
    #[serde(default)]
    pub commit: Option<String>,
    pub approved_by: String,
    #[serde(deserialize_with = "day")]
    pub approved_at: NaiveDate,
}

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Acknowledgement {
    pub person: String,
    pub policy: String,
    #[serde(deserialize_with = "day")]
    pub at: NaiveDate,
}

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Training {
    pub person: String,
    pub course: String,
    #[serde(deserialize_with = "day")]
    pub at: NaiveDate,
}

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Risk {
    pub id: String,
    #[serde(default)]
    #[allow(dead_code, reason = "accepted in the register, never put in evidence")]
    pub title: Option<String>,
    /// A role, never a person.
    pub owner: String,
    pub likelihood: u8,
    pub impact: u8,
    pub treatment: String,
    #[serde(default)]
    pub controls: Vec<String>,
    #[serde(default)]
    pub fraud: bool,
    #[serde(deserialize_with = "day")]
    pub identified: NaiveDate,
    #[serde(default, deserialize_with = "days")]
    pub reviewed: Vec<NaiveDate>,
    #[serde(default)]
    pub accepted_by: Option<String>,
    #[serde(default, deserialize_with = "opt_day")]
    pub accepted_at: Option<NaiveDate>,
    /// When an accepted risk is next reviewed.
    #[serde(default, deserialize_with = "opt_day")]
    pub accepted_until: Option<NaiveDate>,
    #[serde(default, deserialize_with = "opt_day")]
    pub closed: Option<NaiveDate>,
    #[serde(default)]
    #[allow(dead_code, reason = "accepted in the register, never put in evidence")]
    pub notes: Option<String>,
}

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RiskReview {
    #[serde(deserialize_with = "day")]
    pub at: NaiveDate,
    pub by: String,
}

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ManagementReview {
    #[serde(deserialize_with = "day")]
    pub at: NaiveDate,
    pub attendees: Vec<String>,
    /// The SHA-256 of the minutes, kept beside the register.
    #[serde(default)]
    pub minutes_sha256: Option<String>,
}

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Vendor {
    pub id: String,
    /// `critical`, `high` or `low`, from the vendor management policy's tiers.
    pub tier: String,
    /// It hosts the service, so its assurance report covers physical security (CC6.4-1).
    #[serde(default)]
    pub hosting: bool,
    #[serde(deserialize_with = "day")]
    pub since: NaiveDate,
    #[serde(default, deserialize_with = "opt_day")]
    pub until: Option<NaiveDate>,
    #[serde(default, deserialize_with = "opt_day")]
    pub assessed: Option<NaiveDate>,
    #[serde(default)]
    pub approved_by: Option<String>,
    #[serde(default, deserialize_with = "days")]
    pub reviewed: Vec<NaiveDate>,
    #[serde(default)]
    #[allow(dead_code, reason = "accepted in the register, never put in evidence")]
    pub notes: Option<String>,
}

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PolicyException {
    pub id: String,
    pub policy: String,
    /// The configuration baseline setting it excepts, as listed in `BASELINE_EXCEPTIONS`.
    #[serde(default)]
    pub setting: Option<String>,
    pub approved_by: String,
    #[serde(deserialize_with = "day")]
    pub approved_at: NaiveDate,
    /// The day it ends, not included.
    #[serde(deserialize_with = "day")]
    pub ends: NaiveDate,
    #[serde(default, deserialize_with = "days")]
    pub reviewed: Vec<NaiveDate>,
    #[serde(default, deserialize_with = "opt_day")]
    pub closed: Option<NaiveDate>,
    #[serde(default)]
    #[allow(dead_code, reason = "accepted in the register, never put in evidence")]
    pub notes: Option<String>,
}

/// A policy the register's approvals and acknowledgements may name.
#[derive(Clone, Debug)]
pub struct Policy {
    pub id: String,
    /// The role whose approval counts, from the policy's header.
    pub approver: String,
    /// The SHA-256 of its file as it is now, when read from a folder.
    pub sha256: Option<String>,
}

/// The built-in policy set, approved by management, with no text to compare.
pub fn builtin_policies() -> Vec<Policy> {
    POLICIES.iter().map(|id| Policy { id: id.to_string(), approver: "Management".into(), sha256: None }).collect()
}

/// The policies in a folder: every `.md` file but `README.md`, with the approver its
/// header names (`| Approver | Management |`) and the file's SHA-256.
pub fn read_policies(dir: &Path) -> Result<Vec<Policy>, String> {
    let mut out = Vec::new();
    let entries = std::fs::read_dir(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    for e in entries.filter_map(Result::ok) {
        let name = e.file_name().to_string_lossy().into_owned();
        let Some(id) = name.strip_suffix(".md").filter(|id| *id != "README" && !id.starts_with('.')) else { continue };
        let bytes = std::fs::read(e.path()).map_err(|err| format!("{name}: {err}"))?;
        let text = String::from_utf8_lossy(&bytes);
        let approver = text
            .lines()
            .find_map(|l| l.strip_prefix("| Approver |").map(|r| r.trim().trim_end_matches('|').trim().to_string()))
            .unwrap_or_else(|| "Management".into());
        if !ROLES.contains(&approver.as_str()) {
            return Err(format!("{name}: its approver ({approver:.40}) isn't one of the roles: {}", ROLES.join(", ")));
        }
        out.push(Policy { id: id.to_string(), approver, sha256: Some(sha256(&bytes)) });
    }
    if out.is_empty() {
        return Err(format!("{} has no policies (.md files other than README.md)", dir.display()));
    }
    out.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(out)
}

fn plain_id(s: &str) -> bool {
    !s.is_empty() && s.len() <= 64 && s.bytes().all(|c| c.is_ascii_alphanumeric() || b"._-".contains(&c))
}

fn hex(s: &str, lens: std::ops::RangeInclusive<usize>) -> bool {
    lens.contains(&s.len()) && s.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

fn setting_name(s: &str) -> bool {
    !s.is_empty() && s.len() <= 64 && s.bytes().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == b'_')
}

fn row_id(s: &str) -> bool {
    s.split_once('-').is_some_and(|(c, n)| c.contains('.') && c.len() <= 8 && c.bytes().all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'.') && !n.is_empty() && n.len() <= 3 && n.bytes().all(|b| b.is_ascii_digit()))
}

/// Parses a register and checks it holds together: known format, plain unique ids, every
/// person, role and policy it names known, dates in order, scores in range. Every problem
/// is listed, since each is the register's keeper's to fix.
pub fn parse(bytes: &[u8], policies: &[Policy]) -> Result<Register, String> {
    let head: Value = serde_json::from_slice(bytes).map_err(|e| format!("The register isn't JSON: {e}"))?;
    match head.get("superbotRegister").and_then(Value::as_u64) {
        Some(REGISTER_FORMAT) => {}
        Some(n) => return Err(format!("The register is format {n}, which this tool doesn't know; use a newer superbot-evidence")),
        None => return Err("The register has no superbotRegister format (1): see docs/security/policy-register.md".into()),
    }
    let r: Register = serde_json::from_value(head).map_err(|e| format!("The register doesn't read: {e}"))?;
    let mut bad: Vec<String> = Vec::new();
    let people: BTreeSet<&str> = r.people.iter().map(|p| p.id.as_str()).collect();
    let known = |what: &str, id: &str, bad: &mut Vec<String>| {
        if !people.contains(id) {
            bad.push(format!("{what} names {id:.64}, who isn't in people"));
        }
    };
    let policy_ids: BTreeSet<&str> = policies.iter().map(|p| p.id.as_str()).collect();
    let policy = |what: &str, id: &str, bad: &mut Vec<String>| {
        if !policy_ids.contains(id) {
            bad.push(format!("{what} names the policy {id:.64}, which isn't one of: {}", policy_ids.iter().copied().collect::<Vec<_>>().join(", ")));
        }
    };
    let role = |what: &str, name: &str, bad: &mut Vec<String>| {
        if !ROLES.contains(&name) {
            bad.push(format!("{what} names the role {name:.64}, which isn't one of: {}", ROLES.join(", ")));
        }
    };
    let unique = |what: &str, ids: Vec<&str>, bad: &mut Vec<String>| {
        let mut seen = BTreeSet::new();
        for id in ids {
            if !plain_id(id) {
                bad.push(format!("{what} id {id:.64} isn't plain (letters, digits, . _ -, up to 64): ids go in evidence, so no names or emails"));
            } else if !seen.insert(id) {
                bad.push(format!("{what} id {id} is used twice"));
            }
        }
    };
    unique("person", r.people.iter().map(|p| p.id.as_str()).collect(), &mut bad);
    unique("risk", r.risks.iter().map(|x| x.id.as_str()).collect(), &mut bad);
    unique("vendor", r.vendors.iter().map(|x| x.id.as_str()).collect(), &mut bad);
    unique("exception", r.exceptions.iter().map(|x| x.id.as_str()).collect(), &mut bad);
    if r.risk_appetite.is_some_and(|a| !(1..=25).contains(&a)) {
        bad.push("riskAppetite is a score from 1 to 25 (likelihood times impact)".into());
    }
    for p in &r.people {
        if p.left.is_some_and(|l| l <= p.joined) {
            bad.push(format!("person {}: left must be after joined", p.id));
        }
    }
    for x in &r.roles {
        let what = format!("{} from {}", x.role, x.from);
        role("a role", &x.role, &mut bad);
        known(&what, &x.holder, &mut bad);
        if let Some(d) = &x.deputy {
            known(&what, d, &mut bad);
        }
        if x.until.is_some_and(|u| u <= x.from) {
            bad.push(format!("{what}: until must be after from"));
        }
    }
    for a in &r.policy_approvals {
        let what = format!("the approval of {} on {}", a.policy, a.approved_at);
        policy(&what, &a.policy, &mut bad);
        known(&what, &a.approved_by, &mut bad);
        if !hex(&a.sha256, 64..=64) {
            bad.push(format!("{what}: sha256 is the policy file's SHA-256 as approved, 64 lowercase hex digits (`sha256sum` at the commit)"));
        }
        if a.commit.as_deref().is_some_and(|c| !hex(c, 7..=40)) {
            bad.push(format!("{what}: commit is a git commit id, 7 to 40 lowercase hex digits"));
        }
    }
    for a in &r.acknowledgements {
        let what = format!("an acknowledgement on {}", a.at);
        known(&what, &a.person, &mut bad);
        policy(&what, &a.policy, &mut bad);
    }
    for t in &r.training {
        let what = format!("training on {}", t.at);
        known(&what, &t.person, &mut bad);
        if !plain_id(&t.course) {
            bad.push(format!("{what}: course {:.64} isn't a plain id, such as {AWARENESS}", t.course));
        }
    }
    for x in &r.risks {
        let what = format!("risk {}", x.id);
        role(&what, &x.owner, &mut bad);
        if !(1..=5).contains(&x.likelihood) || !(1..=5).contains(&x.impact) {
            bad.push(format!("{what}: likelihood and impact are 1 to 5"));
        }
        if !matches!(x.treatment.as_str(), "reduce" | "accept" | "transfer" | "avoid") {
            bad.push(format!("{what}: treatment is reduce, accept, transfer or avoid"));
        }
        for c in &x.controls {
            if !row_id(c) {
                bad.push(format!("{what}: control {c:.40} isn't a readiness checklist row id, such as CC6.1-1"));
            }
        }
        if x.treatment != "accept" && (x.accepted_by.is_some() || x.accepted_at.is_some() || x.accepted_until.is_some()) {
            bad.push(format!("{what}: acceptedBy, acceptedAt and acceptedUntil are for accepted risks only"));
        }
        if x.accepted_by.is_some() != x.accepted_at.is_some() {
            bad.push(format!("{what}: acceptedBy and acceptedAt go together"));
        }
        if let Some(by) = &x.accepted_by {
            known(&what, by, &mut bad);
        }
        if x.accepted_at.is_some_and(|a| a < x.identified) || x.accepted_until.is_some_and(|u| x.accepted_at.is_none_or(|a| u <= a)) {
            bad.push(format!("{what}: acceptedAt can't be before identified, and acceptedUntil comes after acceptedAt"));
        }
        if x.closed.is_some_and(|c| c < x.identified) || x.reviewed.iter().any(|d| *d < x.identified) {
            bad.push(format!("{what}: reviewed and closed can't be before identified"));
        }
    }
    for v in &r.risk_reviews {
        known(&format!("the risk register review on {}", v.at), &v.by, &mut bad);
    }
    for m in &r.management_reviews {
        let what = format!("the management review on {}", m.at);
        if m.attendees.is_empty() {
            bad.push(format!("{what} has no attendees"));
        }
        for a in &m.attendees {
            known(&what, a, &mut bad);
        }
        if m.minutes_sha256.as_deref().is_some_and(|s| !hex(s, 64..=64)) {
            bad.push(format!("{what}: minutesSha256 is the minutes' SHA-256, 64 lowercase hex digits"));
        }
    }
    for v in &r.vendors {
        let what = format!("vendor {}", v.id);
        if !matches!(v.tier.as_str(), "critical" | "high" | "low") {
            bad.push(format!("{what}: tier is critical, high or low"));
        }
        if v.until.is_some_and(|u| u <= v.since) {
            bad.push(format!("{what}: until must be after since"));
        }
        if let Some(by) = &v.approved_by {
            known(&what, by, &mut bad);
        }
    }
    for x in &r.exceptions {
        let what = format!("exception {}", x.id);
        policy(&what, &x.policy, &mut bad);
        known(&what, &x.approved_by, &mut bad);
        if x.ends <= x.approved_at {
            bad.push(format!("{what}: ends must be after approvedAt"));
        }
        if x.setting.as_deref().is_some_and(|s| !setting_name(s)) {
            bad.push(format!("{what}: setting is a configuration baseline setting's name, as in BASELINE_EXCEPTIONS"));
        }
    }
    if bad.is_empty() {
        return Ok(r);
    }
    let n = bad.len();
    bad.truncate(25);
    Err(format!("The register has {n} problems to fix:\n  {}{}", bad.join("\n  "), if n > 25 { "\n  ..." } else { "" }))
}

// A server's baseline check

/// `botctl evidence baseline json`'s answer, or `baseline.json` from botd's bundle
/// (ADR 0195): when it was checked and the settings it found excepted.
#[derive(Debug, Clone)]
pub struct Baseline {
    pub file: String,
    pub bytes: usize,
    pub sha256: String,
    pub checked_at: String,
    pub checked_on: NaiveDate,
    pub digest: Option<String>,
    pub excepted: Vec<String>,
}

pub fn baseline(file: &str, bytes: &[u8], p: &Period) -> Result<Baseline, String> {
    let v: Value = serde_json::from_slice(bytes).map_err(|_| format!("{file} isn't JSON: give `botctl evidence baseline json`'s output, or baseline.json from an evidence bundle"))?;
    let at = v["checkedAt"].as_str().ok_or(format!("{file} doesn't say when it was checked (checkedAt): is it a baseline check?"))?;
    let t = chrono::DateTime::parse_from_rfc3339(at).map_err(|_| format!("{file}: checkedAt isn't a time"))?.with_timezone(&chrono::Utc);
    if t.timestamp_millis() < p.start_ms() || t.timestamp_millis() >= p.end_ms() + BASELINE_LATE_DAYS * 86_400_000 {
        return Err(format!("{file} was checked at {at:.40}, outside the period {} to {} (or the {BASELINE_LATE_DAYS} days after it, when its evidence bundle is made)", p.from, p.to));
    }
    let excepted = v["exceptions"]["excepted"].as_array().ok_or(format!("{file} has no exceptions.excepted list: is it a baseline check?"))?;
    let excepted: Vec<String> = excepted.iter().map(|s| s.as_str().filter(|s| setting_name(s)).map(String::from).ok_or(format!("{file}: an excepted setting isn't a setting's name"))).collect::<Result<_, _>>()?;
    Ok(Baseline {
        file: Path::new(file).file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default(),
        bytes: bytes.len(),
        sha256: sha256(bytes),
        checked_at: rfc3339(t.timestamp_millis()),
        checked_on: t.date_naive(),
        digest: v["digest"].as_str().filter(|d| hex(d, 64..=64)).map(String::from),
        excepted,
    })
}

// Checking it for a period

fn plus(d: NaiveDate, n: i64) -> NaiveDate {
    d.checked_add_signed(TimeDelta::days(n)).unwrap_or(d)
}

fn age(cut: NaiveDate, d: NaiveDate) -> i64 {
    (cut - d).num_days()
}

fn ds(d: NaiveDate) -> String {
    d.to_string()
}

fn period_days(p: &Period) -> Vec<NaiveDate> {
    p.from.iter_days().take_while(|d| *d < p.to).collect()
}

/// Everything the checks need: the register, the period's end (not included), and the
/// policies it is checked against.
pub struct Check<'a> {
    pub r: &'a Register,
    pub p: Period,
    pub policies: &'a [Policy],
    pub baselines: &'a [Baseline],
}

impl Check<'_> {
    fn cut(&self) -> NaiveDate {
        self.p.to
    }

    fn person(&self, id: &str) -> Option<&Person> {
        self.r.people.iter().find(|p| p.id == id)
    }

    fn personnel_on(&self, id: &str, d: NaiveDate) -> bool {
        self.person(id).is_some_and(|p| p.joined <= d && p.left.is_none_or(|l| d < l))
    }

    fn assignments_on<'b>(&'b self, role: &'b str, d: NaiveDate) -> impl Iterator<Item = &'b Role> + 'b {
        self.r.roles.iter().filter(move |x| x.role == role && x.from <= d && x.until.is_none_or(|u| d < u))
    }

    /// The role, of `roles`, that `person` held or deputised on `d`, while personnel.
    fn held(&self, person: &str, roles: &[&str], d: NaiveDate) -> Option<String> {
        if !self.personnel_on(person, d) {
            return None;
        }
        roles.iter().find_map(|role| {
            self.assignments_on(role, d).find_map(|x| {
                if x.holder == person {
                    Some(role.to_string())
                } else if x.deputy.as_deref() == Some(person) {
                    Some(format!("{role} (deputy)"))
                } else {
                    None
                }
            })
        })
    }

    fn approver_of(&self, policy: &str) -> &str {
        self.policies.iter().find(|p| p.id == policy).map_or("Management", |p| p.approver.as_str())
    }

    fn first_approval(&self, policy: &str) -> Option<NaiveDate> {
        self.r.policy_approvals.iter().filter(|a| a.policy == policy && a.approved_at < self.cut()).map(|a| a.approved_at).min()
    }

    /// Records the register dates on or after the period's end, left out.
    pub fn after_period(&self) -> usize {
        let c = self.cut();
        let r = self.r;
        r.roles.iter().filter(|x| x.from >= c).count()
            + r.policy_approvals.iter().filter(|x| x.approved_at >= c).count()
            + r.acknowledgements.iter().filter(|x| x.at >= c).count()
            + r.training.iter().filter(|x| x.at >= c).count()
            + r.risks.iter().filter(|x| x.identified >= c).count()
            + r.risk_reviews.iter().filter(|x| x.at >= c).count()
            + r.management_reviews.iter().filter(|x| x.at >= c).count()
            + r.vendors.iter().filter(|x| x.since >= c).count()
            + r.exceptions.iter().filter(|x| x.approved_at >= c).count()
    }

    pub fn roles(&self) -> (Value, Vec<&'static str>) {
        let p = self.p;
        let (mut unfilled, mut no_deputy, mut same, mut not_personnel, mut overlapping) = (Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new());
        let mut out = Vec::new();
        let mut any = false;
        for role in ROLES {
            let (mut held, mut deputised) = (BTreeSet::new(), BTreeSet::new());
            let (mut flagged, mut overlap_flagged) = (BTreeSet::new(), false);
            for d in period_days(&p) {
                let on: Vec<&Role> = self.assignments_on(role, d).collect();
                if on.len() > 1 && !std::mem::replace(&mut overlap_flagged, true) {
                    overlapping.push(json!(format!("{role} on {d}: {}", on.iter().map(|x| x.holder.as_str()).collect::<Vec<_>>().join(", "))));
                }
                for x in &on {
                    held.insert(d);
                    if x.deputy.is_some() {
                        deputised.insert(d);
                    }
                    for who in std::iter::once(x.holder.as_str()).chain(x.deputy.as_deref()) {
                        if !self.personnel_on(who, d) && flagged.insert(who) {
                            not_personnel.push(json!(format!("{role}: {who} on {d}")));
                        }
                    }
                }
            }
            let gaps = crate::coverage::gaps(&p, &held);
            let deputy_gaps = crate::coverage::gaps(&p, &deputised);
            let range = |g: &[Value]| g.iter().map(|g| format!("{} to {}", g["from"].as_str().unwrap_or_default(), g["to"].as_str().unwrap_or_default())).collect::<Vec<_>>().join(", ");
            if !gaps.is_empty() {
                unfilled.push(json!(format!("{role}: {}", range(&gaps))));
            }
            if !deputy_gaps.is_empty() {
                no_deputy.push(json!(format!("{role}: {}", range(&deputy_gaps))));
            }
            let assignments: Vec<Value> = self
                .r
                .roles
                .iter()
                .filter(|x| x.role == role && x.from < p.to && x.until.is_none_or(|u| u > p.from))
                .map(|x| {
                    if x.deputy.as_deref() == Some(x.holder.as_str()) {
                        same.push(json!(format!("{role} from {}: {}", x.from, x.holder)));
                    }
                    json!({ "holder": x.holder, "deputy": x.deputy, "from": ds(x.from), "until": x.until.map(ds) })
                })
                .collect();
            any |= !assignments.is_empty();
            out.push(json!({ "role": role, "assignments": assignments, "daysHeld": held.len(), "daysWithDeputy": deputised.len(), "daysWithoutHolder": gaps }));
        }
        let v = json!({
            "basis": "a role is held on a day when an assignment runs from its from day up to, not including, its until day; holder and deputy must be personnel (joined, and not left) that day; the information security policy names a holder and a deputy for each role",
            "summary": { "roles": ROLES.len(), "filledEveryDay": out.iter().filter(|r| r["daysWithoutHolder"].as_array().is_some_and(Vec::is_empty)).count(), "days": p.days() },
            "exceptions": { "roleUnfilled": unfilled, "noDeputy": no_deputy, "holderIsDeputy": same, "notPersonnel": not_personnel, "overlapping": overlapping },
            "roles": out,
        });
        (v, if any { vec!["CC1.3-1"] } else { vec![] })
    }

    pub fn policies(&self) -> (Value, Vec<&'static str>) {
        let cut = self.cut();
        let (mut not_approved, mut overdue, mut changed, mut wrong_approver) = (Vec::new(), Vec::new(), Vec::new(), Vec::new());
        let mut rows = Vec::new();
        let mut out = Vec::new();
        for pol in self.policies {
            let mut approvals: Vec<&Approval> = self.r.policy_approvals.iter().filter(|a| a.policy == pol.id && a.approved_at < cut).collect();
            approvals.sort_by_key(|a| a.approved_at);
            let approver = self.approver_of(&pol.id);
            for a in &approvals {
                if self.held(&a.approved_by, &[approver], a.approved_at).is_none() {
                    wrong_approver.push(json!(format!("{} on {}: {} didn't hold {approver}", pol.id, a.approved_at, a.approved_by)));
                }
            }
            let latest = approvals.last();
            let matches = latest.and_then(|a| pol.sha256.as_ref().map(|s| *s == a.sha256));
            match latest {
                None => not_approved.push(json!(pol.id)),
                Some(a) => {
                    if age(cut, a.approved_at) > YEAR_DAYS {
                        overdue.push(json!(format!("{} (approved {})", pol.id, a.approved_at)));
                    } else {
                        rows.push(if pol.id == "information-security" { "CC3.1-1" } else { "CC5.3-1" });
                        rows.push("CC5.3-1");
                    }
                    if matches == Some(false) {
                        changed.push(json!(pol.id));
                    }
                }
            }
            out.push(json!({
                "policy": pol.id,
                "approverRole": approver,
                "approvals": approvals.len(),
                "latest": latest.map(|a| json!({ "approvedAt": ds(a.approved_at), "approvedBy": a.approved_by, "heldRole": self.held(&a.approved_by, &[approver], a.approved_at), "sha256": a.sha256, "commit": a.commit })),
                "reviewDue": latest.map(|a| ds(plus(a.approved_at, YEAR_DAYS))),
                "currentSha256": pol.sha256,
                "textApproved": matches,
            }));
        }
        rows.sort_unstable();
        rows.dedup();
        let v = json!({
            "basis": "each policy's latest approval before the period's end: by someone holding (or deputising) the role its header names as approver on that day, at most a year old (every policy is reviewed yearly), and, when the policy files were given, of the text in force: the file's SHA-256 now is the one approved",
            "textsChecked": self.policies.iter().any(|p| p.sha256.is_some()),
            "summary": { "policies": self.policies.len(), "approved": out.iter().filter(|p| !p["latest"].is_null()).count(), "current": self.policies.len() - not_approved.len() - overdue.len() },
            "exceptions": { "notApproved": not_approved, "reviewOverdue": overdue, "changedSinceApproval": changed, "approverNotInRole": wrong_approver },
            "policies": out,
        });
        (v, rows)
    }

    pub fn people(&self) -> (Value, Vec<&'static str>) {
        let (p, cut) = (self.p, self.cut());
        let (mut missing, mut late, mut overdue) = (Vec::new(), Vec::new(), Vec::new());
        let (mut t_missing, mut t_late, mut t_overdue) = (Vec::new(), Vec::new(), Vec::new());
        let mut out = Vec::new();
        let at_end = |x: &Person| x.joined < cut && x.left.is_none_or(|l| l >= cut);
        let training_from = self.first_approval("information-security");
        for x in self.r.people.iter().filter(|x| x.joined < cut && x.left.is_none_or(|l| l > p.from)) {
            let mut acks = serde_json::Map::new();
            for pol in ACKNOWLEDGED.iter().filter(|id| self.policies.iter().any(|q| q.id == **id)) {
                let mut at: Vec<NaiveDate> = self.r.acknowledgements.iter().filter(|a| a.person == x.id && a.policy == *pol && a.at < cut).map(|a| a.at).collect();
                at.sort_unstable();
                let due = self.first_approval(pol).map(|f| plus(f.max(x.joined), GRACE_DAYS));
                if at_end(x) {
                    if let Some(due) = due.filter(|d| *d < cut) {
                        match (at.first(), at.last()) {
                            (None, _) => missing.push(json!(format!("{} {pol} (due {due})", x.id))),
                            (Some(first), Some(last)) => {
                                if *first > due {
                                    late.push(json!(format!("{} {pol} ({first}, due {due})", x.id)));
                                }
                                if age(cut, *last) > YEAR_DAYS {
                                    overdue.push(json!(format!("{} {pol} (last {last})", x.id)));
                                }
                            }
                            _ => {}
                        }
                    }
                }
                acks.insert(pol.to_string(), json!({ "count": at.len(), "first": at.first().copied().map(ds), "last": at.last().copied().map(ds), "due": due.map(ds) }));
            }
            let mut courses: BTreeMap<&str, Vec<NaiveDate>> = BTreeMap::new();
            for t in self.r.training.iter().filter(|t| t.person == x.id && t.at < cut) {
                courses.entry(t.course.as_str()).or_default().push(t.at);
            }
            courses.values_mut().for_each(|v| v.sort_unstable());
            let due = training_from.map(|f| plus(f.max(x.joined), GRACE_DAYS));
            if at_end(x) {
                if let Some(due) = due.filter(|d| *d < cut) {
                    match courses.get(AWARENESS) {
                        None => t_missing.push(json!(format!("{} (due {due})", x.id))),
                        Some(at) => {
                            if at[0] > due {
                                t_late.push(json!(format!("{} ({}, due {due})", x.id, at[0])));
                            }
                            if age(cut, *at.last().expect("not empty")) > YEAR_DAYS {
                                t_overdue.push(json!(format!("{} (last {})", x.id, at.last().expect("not empty"))));
                            }
                        }
                    }
                }
            }
            let training: Value = courses.iter().map(|(c, at)| (c.to_string(), json!({ "count": at.len(), "last": at.last().copied().map(ds) }))).collect::<serde_json::Map<_, _>>().into();
            out.push(json!({ "id": x.id, "joined": ds(x.joined), "left": x.left.map(ds), "atEnd": at_end(x), "acknowledgements": acks, "training": training, "awarenessDue": due.map(ds) }));
        }
        let recent = |d: NaiveDate| d < cut && age(cut, d) <= YEAR_DAYS;
        let mut rows = Vec::new();
        if self.r.training.iter().any(|t| recent(t.at)) {
            rows.push("CC1.4-1");
        }
        if self.r.acknowledgements.iter().any(|a| recent(a.at)) {
            rows.push("CC2.2-1");
        }
        let v = json!({
            "basis": format!("everyone with access at the period's end acknowledges {} and takes {AWARENESS} training within {GRACE_DAYS} days of joining or of the policy's first approval (training: the information security policy's), whichever is later, and again within each year; people are named by their register id only", ACKNOWLEDGED.join(" and ")),
            "summary": { "people": out.len(), "atEnd": out.iter().filter(|x| x["atEnd"] == true).count(), "acknowledgements": self.r.acknowledgements.iter().filter(|a| a.at < cut).count(), "training": self.r.training.iter().filter(|t| t.at < cut).count() },
            "exceptions": { "notAcknowledged": missing, "acknowledgedLate": late, "acknowledgementOverdue": overdue, "notTrained": t_missing, "trainedLate": t_late, "trainingOverdue": t_overdue },
            "people": out,
        });
        (v, rows)
    }

    pub fn risks(&self) -> (Value, Vec<&'static str>) {
        let cut = self.cut();
        let open: Vec<&Risk> = self.r.risks.iter().filter(|x| x.identified < cut && x.closed.is_none_or(|c| c >= cut)).collect();
        let (mut overdue, mut unapproved, mut not_accepted, mut no_date, mut lapsed, mut no_controls) = (Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new());
        let mut out = Vec::new();
        for x in &open {
            let last = x.reviewed.iter().copied().filter(|d| *d < cut).max().unwrap_or(x.identified).max(x.identified);
            if age(cut, last) > YEAR_DAYS {
                overdue.push(json!(format!("{} (last {last})", x.id)));
            }
            let score = x.likelihood * x.impact;
            let above = self.r.risk_appetite.is_none_or(|a| score > a);
            let acceptance = x.accepted_by.as_deref().zip(x.accepted_at).filter(|(_, at)| *at < cut);
            if x.treatment == "accept" {
                let management = acceptance.and_then(|(by, at)| self.held(by, &["Management"], at));
                let owner = acceptance.and_then(|(by, at)| self.held(by, &[x.owner.as_str()], at));
                if acceptance.is_none() {
                    not_accepted.push(json!(x.id));
                } else if above && management.is_none() {
                    unapproved.push(json!(x.id));
                } else if !above && management.is_none() && owner.is_none() {
                    not_accepted.push(json!(x.id));
                }
                match x.accepted_until {
                    None => no_date.push(json!(x.id)),
                    Some(u) if u < cut => lapsed.push(json!(format!("{} (until {u})", x.id))),
                    _ => {}
                }
            }
            if x.treatment == "reduce" && x.controls.is_empty() {
                no_controls.push(json!(x.id));
            }
            out.push(json!({
                "id": x.id, "owner": x.owner, "likelihood": x.likelihood, "impact": x.impact, "score": score, "aboveAppetite": above,
                "treatment": x.treatment, "controls": x.controls, "fraud": x.fraud,
                "identified": ds(x.identified), "lastReviewed": ds(last), "reviewDue": ds(plus(last, YEAR_DAYS)),
                "acceptedBy": acceptance.map(|(by, _)| by), "acceptedAt": acceptance.map(|(_, at)| ds(at)), "acceptedUntil": acceptance.and(x.accepted_until).map(ds),
            }));
        }
        let mut reviews: Vec<&RiskReview> = self.r.risk_reviews.iter().filter(|v| v.at < cut).collect();
        reviews.sort_by_key(|v| v.at);
        let last_full = reviews.last().map(|v| v.at);
        let no_full: Vec<Value> = if last_full.is_none_or(|d| age(cut, d) > YEAR_DAYS) { vec![json!(format!("none in the year to {cut}{}", last_full.map(|d| format!(" (last {d})")).unwrap_or_default()))] } else { vec![] };
        let current = |x: &&&Risk| age(cut, x.reviewed.iter().copied().filter(|d| *d < cut).max().unwrap_or(x.identified).max(x.identified)) <= YEAR_DAYS;
        let fraud: Vec<&&Risk> = open.iter().filter(|x| x.fraud).collect();
        let no_fraud: Vec<Value> = if fraud.is_empty() { vec![json!("no open risk is marked fraud")] } else { vec![] };
        let mut rows = Vec::new();
        if open.iter().any(|x| current(&x)) {
            rows.push("CC3.2-1");
        }
        if fraud.iter().any(current) {
            rows.push("CC3.3-1");
        }
        let v = json!({
            "basis": "the risks open at the period's end (identified before it, not closed), each reviewed within a year; the register reviewed in full within a year; an accepted risk has an acceptance dated before the period's end, by someone holding or deputising Management that day when it scores above the appetite (all of them when none is set), and otherwise Management or the risk's owner role, with a review date not passed; risks reduced name the checklist rows of their controls; the yearly assessment includes fraud",
            "riskAppetite": self.r.risk_appetite,
            "summary": { "open": open.len(), "closed": self.r.risks.iter().filter(|x| x.closed.is_some_and(|c| c < cut)).count(), "accepted": open.iter().filter(|x| x.treatment == "accept").count(), "fraud": fraud.len(), "lastFullReview": last_full.map(ds) },
            "exceptions": { "noFullReview": no_full, "reviewOverdue": overdue, "acceptedWithoutManagement": unapproved, "notAccepted": not_accepted, "acceptanceNoReviewDate": no_date, "acceptanceLapsed": lapsed, "reducedWithoutControls": no_controls, "noFraudRisk": no_fraud },
            "fullReviews": reviews.iter().map(|v| json!({ "at": ds(v.at), "by": v.by, "heldRole": self.held(&v.by, &["Security owner", "Management"], v.at) })).collect::<Vec<_>>(),
            "risks": out,
        });
        (v, rows)
    }

    pub fn management_reviews(&self) -> (Value, Vec<&'static str>) {
        let (p, cut) = (self.p, self.cut());
        let reviews: Vec<&ManagementReview> = {
            let mut v: Vec<&ManagementReview> = self.r.management_reviews.iter().filter(|m| m.at < cut && age(cut, m.at) <= YEAR_DAYS).collect();
            v.sort_by_key(|m| m.at);
            v
        };
        let mut without = Vec::new();
        let mut no_minutes = Vec::new();
        let out: Vec<Value> = reviews
            .iter()
            .map(|m| {
                let management = m.attendees.iter().any(|a| self.held(a, &["Management"], m.at).is_some());
                let owner = m.attendees.iter().any(|a| self.held(a, &["Security owner"], m.at).is_some());
                if !(management && owner) {
                    without.push(json!(ds(m.at)));
                }
                if m.minutes_sha256.is_none() {
                    no_minutes.push(json!(ds(m.at)));
                }
                json!({ "at": ds(m.at), "attendees": m.attendees.len(), "management": management, "securityOwner": owner, "minutesSha256": m.minutes_sha256 })
            })
            .collect();
        let mut missed = Vec::new();
        let mut quarters = Vec::new();
        for (label, start, end) in quarters_ended(&p) {
            let n = self.r.management_reviews.iter().filter(|m| m.at >= start && m.at < end).count();
            if n == 0 {
                missed.push(json!(label));
            }
            quarters.push(json!({ "quarter": label, "from": ds(start), "to": ds(end), "reviews": n }));
        }
        let rows = if reviews.last().is_some_and(|m| age(cut, m.at) <= QUARTER_DAYS) { vec!["CC1.2-1"] } else { vec![] };
        let v = json!({
            "basis": "management and the security owner meet at least quarterly (information security policy): each calendar quarter that overlaps the period and has ended by its end has a review; each review has someone holding or deputising Management and the Security owner that day, and its minutes' SHA-256",
            "summary": { "reviewsInTheYear": out.len(), "lastReview": reviews.last().map(|m| ds(m.at)), "quartersChecked": quarters.len() },
            "exceptions": { "quarterWithoutReview": missed, "withoutManagementOrSecurityOwner": without, "noMinutes": no_minutes },
            "quarters": quarters,
            "reviews": out,
        });
        (v, rows)
    }

    pub fn vendors(&self) -> (Value, Vec<&'static str>) {
        let (p, cut) = (self.p, self.cut());
        let (mut unassessed, mut unapproved, mut overdue) = (Vec::new(), Vec::new(), Vec::new());
        let mut out = Vec::new();
        let mut rows = BTreeSet::new();
        let in_use: Vec<&Vendor> = self.r.vendors.iter().filter(|v| v.since < cut && v.until.is_none_or(|u| u > p.from)).collect();
        for v in &in_use {
            let assessed = v.assessed.filter(|a| *a < cut);
            let last = assessed.into_iter().chain(v.reviewed.iter().copied()).filter(|d| *d < cut).max();
            let at_end = v.until.is_none_or(|u| u >= cut);
            let assessed_by = v.approved_by.as_deref().zip(assessed).and_then(|(by, at)| self.held(by, &["Security owner", "Management"], at));
            if v.tier != "low" {
                if assessed.is_none_or(|a| a > v.since) {
                    unassessed.push(json!(format!("{} (in use since {})", v.id, v.since)));
                }
                if assessed_by.is_none() {
                    unapproved.push(json!(v.id));
                }
                if at_end && last.is_none_or(|d| age(cut, d) > YEAR_DAYS) {
                    overdue.push(json!(format!("{}{}", v.id, last.map(|d| format!(" (last {d})")).unwrap_or_default())));
                }
                if last.is_some_and(|d| age(cut, d) <= YEAR_DAYS) {
                    rows.insert("CC9.2-1");
                    if v.hosting {
                        rows.insert("CC6.4-1");
                    }
                }
            }
            out.push(json!({
                "id": v.id, "tier": v.tier, "hosting": v.hosting, "since": ds(v.since), "until": v.until.map(ds), "inUseAtEnd": at_end,
                "assessed": assessed.map(ds), "approvedBy": assessed.and(v.approved_by.as_deref()), "heldRole": assessed_by, "lastReviewed": last.map(ds), "reviewDue": last.map(|d| ds(plus(d, YEAR_DAYS))),
            }));
        }
        let no_hosting: Vec<Value> = if in_use.iter().any(|v| v.hosting && v.tier != "low") { vec![] } else { vec![json!("no critical or high vendor in use is marked hosting")] };
        let v = json!({
            "basis": "every critical and high vendor in use in the period is assessed before use (an assessment dated on or after the period's end isn't this period's) and approved by someone holding or deputising the Security owner or Management, and reviewed within a year while in use (vendor management policy); a hosting provider's yearly review of its assurance report covers physical security (CC6.4-1); low vendors are listed only",
            "summary": { "inUse": out.len(), "criticalOrHigh": in_use.iter().filter(|v| v.tier != "low").count(), "hosting": in_use.iter().filter(|v| v.hosting).count() },
            "exceptions": { "notAssessedBeforeUse": unassessed, "notApproved": unapproved, "reviewOverdue": overdue, "noHostingVendor": no_hosting },
            "vendors": out,
        });
        (v, rows.into_iter().collect())
    }

    fn exception_on(&self, x: &PolicyException, d: NaiveDate) -> bool {
        x.approved_at <= d && d < x.ends && x.closed.is_none_or(|c| c > d)
    }

    pub fn exceptions(&self) -> (Value, Vec<&'static str>) {
        let (p, cut) = (self.p, self.cut());
        let (mut long, mut wrong, mut overdue) = (Vec::new(), Vec::new(), Vec::new());
        let mut out = Vec::new();
        for x in self.r.exceptions.iter().filter(|x| x.approved_at < cut && x.ends > p.from && x.closed.is_none_or(|c| c > p.from)) {
            if age(x.ends, x.approved_at) > MAX_EXCEPTION_DAYS {
                long.push(json!(format!("{} (approved {}, ends {})", x.id, x.approved_at, x.ends)));
            }
            let by = self.held(&x.approved_by, &["Security owner", "Management"], x.approved_at);
            if by.is_none() {
                wrong.push(json!(x.id));
            }
            let at_end = self.exception_on(x, cut.pred_opt().unwrap_or(cut));
            let last = x.reviewed.iter().copied().filter(|d| *d < cut).max().unwrap_or(x.approved_at).max(x.approved_at);
            if at_end && age(cut, last) > QUARTER_DAYS {
                overdue.push(json!(format!("{} (last {last})", x.id)));
            }
            out.push(json!({
                "id": x.id, "policy": x.policy, "setting": x.setting, "approvedBy": x.approved_by, "heldRole": by, "approvedAt": ds(x.approved_at),
                "ends": ds(x.ends), "closed": x.closed.map(ds), "inForceAtEnd": at_end, "lastReviewed": ds(last),
            }));
        }
        let mut unapproved = Vec::new();
        let checks: Vec<Value> = self
            .baselines
            .iter()
            .map(|b| {
                let missing: Vec<&String> = b.excepted.iter().filter(|s| !self.r.exceptions.iter().any(|x| x.approved_at < cut && x.setting.as_deref() == Some(s.as_str()) && self.exception_on(x, b.checked_on))).collect();
                unapproved.extend(missing.iter().map(|s| json!(format!("{s} on {} (checked {})", b.file, b.checked_at))));
                json!({ "file": b.file, "bytes": b.bytes, "sha256": b.sha256, "checkedAt": b.checked_at, "digest": b.digest, "excepted": b.excepted, "notInRegister": missing })
            })
            .collect();
        let rows = if self.baselines.is_empty() { vec![] } else { vec!["CC5.1-1"] };
        let v = json!({
            "basis": format!("exceptions in force at some time in the period: approved by someone holding or deputising the Security owner or Management that day, ending at most {MAX_EXCEPTION_DAYS} days after approval, and reviewed within each quarter while in force (information security policy); and each server's baseline check given, every setting it found excepted (BASELINE_EXCEPTIONS) held to an exception approved before the period's end and in force for that setting on the day it was checked (a check up to {BASELINE_LATE_DAYS} days after the period, such as an evidence bundle's, counts)"),
            "summary": { "inPeriod": out.len(), "inForceAtEnd": out.iter().filter(|x| x["inForceAtEnd"] == true).count(), "baselineChecks": checks.len() },
            "exceptions": { "overAYear": long, "approverNotInRole": wrong, "reviewOverdue": overdue, "baselineExceptionNotApproved": unapproved },
            "baselineChecks": checks,
            "exceptionsInPeriod": out,
        });
        (v, rows)
    }
}

/// The calendar quarters that overlap the period and have ended by its end.
pub fn quarters_ended(p: &Period) -> Vec<(String, NaiveDate, NaiveDate)> {
    let mut out = Vec::new();
    let (mut y, mut q) = (p.from.year(), p.from.month0() / 3);
    loop {
        let Some(start) = NaiveDate::from_ymd_opt(y, q * 3 + 1, 1) else { break };
        if start >= p.to {
            break;
        }
        let (ny, nq) = if q == 3 { (y + 1, 0) } else { (y, q + 1) };
        let Some(end) = NaiveDate::from_ymd_opt(ny, nq * 3 + 1, 1) else { break };
        if end <= p.to {
            out.push((format!("{y}-Q{}", q + 1), start, end));
        }
        (y, q) = (ny, nq);
    }
    out
}

// The bundle

/// Where the register came from, for the manifest.
pub struct Source {
    pub file: String,
    pub bytes: usize,
    pub sha256: String,
}

pub fn name(p: &Period, now_ms: i64) -> String {
    let stamp = chrono::DateTime::from_timestamp_millis(now_ms).map(|t| t.format("%Y%m%dT%H%M%SZ").to_string()).unwrap_or_default();
    format!("{PREFIX}{}-{stamp}", p.label())
}

/// Each file's JSON and the rows its manifest maps it to.
pub fn files(c: &Check) -> Vec<(&'static str, Value, Vec<&'static str>)> {
    let period = json!({ "from": c.p.from.to_string(), "to": c.p.to.to_string(), "days": c.p.days() });
    let parts = [c.roles(), c.policies(), c.people(), c.risks(), c.management_reviews(), c.vendors(), c.exceptions()];
    SECTIONS
        .iter()
        .zip(parts)
        .map(|(s, (mut v, rows))| {
            v["periodCovered"] = period.clone();
            (s.file, v, rows)
        })
        .collect()
}

pub fn build(c: &Check, src: &Source, now_ms: i64) -> Bundle {
    let name = name(&c.p, now_ms);
    let created = rfc3339(now_ms);
    let parts = files(c);
    let mut files: Vec<(&str, Vec<u8>)> = vec![("README.txt", README.as_bytes().to_vec())];
    files.extend(parts.iter().map(|(n, v, _)| (*n, json_file(v))));
    let listed: Vec<Value> = files
        .iter()
        .map(|(n, b)| {
            let rows: Vec<&str> = parts.iter().find(|(f, _, _)| f == n).map(|(_, _, r)| r.clone()).unwrap_or_default();
            let criteria: Vec<&str> = SECTIONS.iter().find(|s| s.file == *n).map(|s| s.criteria.iter().copied().filter(|cr| rows.iter().any(|r| r.starts_with(&format!("{cr}-")))).collect()).unwrap_or_default();
            json!({ "name": n, "bytes": b.len(), "sha256": sha256(b), "criteria": criteria, "checklist": rows })
        })
        .collect();
    let exceptions: usize = parts.iter().map(|(_, v, _)| v["exceptions"].as_object().map_or(0, |m| m.values().filter_map(Value::as_array).map(Vec::len).sum())).sum();
    let manifest = json!({
        "product": "SuperBot",
        "kind": "policy-register",
        "format": FORMAT,
        "tool": concat!("superbot-evidence ", env!("CARGO_PKG_VERSION")),
        "createdAt": created,
        "period": { "from": c.p.from.to_string(), "to": c.p.to.to_string(), "days": c.p.days() },
        "source": {
            "register": src.file, "registerBytes": src.bytes, "registerSha256": src.sha256, "registerFormat": REGISTER_FORMAT,
            "policies": c.policies.iter().map(|p| p.id.clone()).collect::<Vec<_>>(),
            "policyTextsChecked": c.policies.iter().any(|p| p.sha256.is_some()),
            "baselineChecks": c.baselines.len(),
        },
        "recordsAfterPeriod": c.after_period(),
        "exceptions": exceptions,
        "files": listed,
        "notIncluded": "names, titles, notes and reasons from the register, and the register itself: keep it beside this bundle, where registerSha256 identifies it",
    });
    files.push(("manifest.json", json_file(&manifest)));
    let sums: String = files.iter().map(|(n, b)| format!("{}  {n}\n", sha256(b))).collect();
    let manifest_sha256 = sha256(&files.last().expect("the manifest").1);
    files.push(("SHA256SUMS", sums.into_bytes()));
    let entries: Vec<(String, Vec<u8>)> = files.iter().map(|(n, b)| (format!("{name}/{n}"), b.clone())).collect();
    let tar = crate::ustar::tar(&entries, (now_ms / 1000).max(0) as u64);
    Bundle { sha256: sha256(&tar), manifest_sha256, name, tar }
}

/// The lines printed after saving: each file's exceptions.
pub fn summary(c: &Check) -> String {
    let mut out = String::new();
    for (file, v, rows) in files(c) {
        let ex: Vec<String> = v["exceptions"].as_object().into_iter().flatten().filter_map(|(k, x)| x.as_array().filter(|a| !a.is_empty()).map(|a| format!("{k} {}", a.len()))).collect();
        out += &format!("\n  {file}: {}; evidence for {}", if ex.is_empty() { "no exceptions".into() } else { ex.join(", ") }, if rows.is_empty() { "no row".into() } else { rows.join(", ") });
    }
    out
}

// The command

pub const USAGE: &str = "  superbot-evidence register <register.json> [--policies <folder>] [--baseline <file>]...
                    [--from <YYYY-MM-DD> --to <YYYY-MM-DD>] [-o <file>]";

struct Args {
    register: String,
    policies: Option<String>,
    baselines: Vec<String>,
    from: Option<String>,
    to: Option<String>,
    out: Option<String>,
}

fn parse_args(args: &[String]) -> Result<Args, String> {
    let mut a = Args { register: String::new(), policies: None, baselines: Vec::new(), from: None, to: None, out: None };
    let mut it = args.iter();
    while let Some(flag) = it.next() {
        let value = |it: &mut std::slice::Iter<String>| it.next().filter(|v| !v.starts_with("--") && !v.is_empty()).cloned().ok_or(format!("{flag} needs a value"));
        let slot = match flag.as_str() {
            "--baseline" => {
                a.baselines.push(value(&mut it)?);
                continue;
            }
            "--policies" => &mut a.policies,
            "--from" => &mut a.from,
            "--to" => &mut a.to,
            "-o" | "--out" => &mut a.out,
            s if !s.starts_with('-') && a.register.is_empty() => {
                a.register = s.to_string();
                continue;
            }
            _ => return Err(format!("Unknown option {flag}.\n\n{USAGE}")),
        };
        if slot.is_some() {
            return Err(format!("{flag} is given twice"));
        }
        *slot = Some(value(&mut it)?);
    }
    if a.register.is_empty() {
        return Err(format!("Give the policy register's file.\n\n{USAGE}"));
    }
    Ok(a)
}

fn read_capped(file: &str, max: u64) -> Result<Vec<u8>, String> {
    let size = std::fs::metadata(file).map_err(|e| format!("{file}: {e}"))?.len();
    if size > max {
        return Err(format!("{file} is over {} MiB, larger than any it could be", max >> 20));
    }
    std::fs::read(file).map_err(|e| format!("{file}: {e}"))
}

pub fn run(args: &[String], now: chrono::DateTime<chrono::Utc>) -> Result<String, String> {
    let a = parse_args(args)?;
    let p = Period::parse(a.from.as_deref(), a.to.as_deref(), now.date_naive())?;
    if p.days() > MAX_PERIOD_DAYS {
        return Err(format!("A register bundle covers one month at most ({MAX_PERIOD_DAYS} days), since what it shows is judged as of the period's end: make one for each month of {} to {}", p.from, p.to));
    }
    let policies = match &a.policies {
        Some(dir) => read_policies(Path::new(dir))?,
        None => builtin_policies(),
    };
    let bytes = read_capped(&a.register, MAX_REGISTER_BYTES)?;
    let register = parse(&bytes, &policies).map_err(|e| format!("{}: {e}", a.register))?;
    let mut baselines: Vec<Baseline> = Vec::new();
    for f in &a.baselines {
        let b = baseline(f, &read_capped(f, MAX_BASELINE_BYTES)?, &p)?;
        if baselines.iter().any(|x| x.sha256 == b.sha256) {
            return Err(format!("{f} is the same baseline check as another --baseline"));
        }
        baselines.push(b);
    }
    let c = Check { r: &register, p, policies: &policies, baselines: &baselines };
    let src = Source { file: Path::new(&a.register).file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default(), bytes: bytes.len(), sha256: sha256(&bytes) };
    let b = build(&c, &src, now.timestamp_millis());
    let file = a.out.clone().unwrap_or_else(|| format!("{}.tar", b.name));
    crate::save_private(&file, &b.tar)?;
    Ok(format!(
        "Saved {file} ({} KB) from the register {} (SHA-256 {}) for {} to {} (not included){}:{}\nManifest SHA-256: {}\nBundle SHA-256: {}\nKeep it in the evidence store, with the register as it is now; to check it:\n  tar -xf {} && (cd {} && sha256sum -c SHA256SUMS)",
        b.tar.len().div_ceil(1024),
        src.file,
        src.sha256,
        p.from,
        p.to,
        if a.policies.is_some() { ", against the policy files given" } else { ", without the policy files (--policies), so approved texts weren't compared" },
        summary(&c),
        b.manifest_sha256,
        b.sha256,
        crate::quote(&file),
        crate::quote(&b.name),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(s: &str) -> NaiveDate {
        parse_day(s).unwrap()
    }

    fn period() -> Period {
        Period { from: d("2027-03-01"), to: d("2027-04-01") }
    }

    const ZERO: &str = "0000000000000000000000000000000000000000000000000000000000000000";

    /// A register kept well for the first quarter of 2027, but for what each test breaks.
    fn good() -> Value {
        let approvals: Vec<Value> = POLICIES.iter().map(|p| json!({ "policy": p, "sha256": ZERO, "commit": "abc1234", "approvedBy": "p-mgmt", "approvedAt": "2027-01-05" })).collect();
        let mut acks = Vec::new();
        let mut training = Vec::new();
        for who in ["p-mgmt", "p-sec", "p-eng", "p-ops"] {
            for pol in ACKNOWLEDGED {
                acks.push(json!({ "person": who, "policy": pol, "at": "2027-01-10" }));
            }
            training.push(json!({ "person": who, "course": AWARENESS, "at": "2027-01-20" }));
        }
        let role = |r: &str, h: &str, dep: &str| json!({ "role": r, "holder": h, "deputy": dep, "from": "2027-01-01" });
        json!({
            "superbotRegister": 1,
            "riskAppetite": 9,
            "people": [
                { "id": "p-mgmt", "name": "Alice Example", "joined": "2026-06-01" },
                { "id": "p-sec", "name": "Bob Example", "joined": "2026-06-01" },
                { "id": "p-eng", "name": "Carol Example", "joined": "2026-06-01" },
                { "id": "p-ops", "name": "Dan Example", "joined": "2026-06-01" },
            ],
            "roles": [
                role("Management", "p-mgmt", "p-sec"), role("Security owner", "p-sec", "p-mgmt"), role("Engineering lead", "p-eng", "p-ops"),
                role("Operator", "p-ops", "p-eng"), role("People lead", "p-mgmt", "p-sec"), role("Privacy lead", "p-sec", "p-mgmt"),
            ],
            "policyApprovals": approvals,
            "acknowledgements": acks,
            "training": training,
            "risks": [
                { "id": "R-01", "title": "Cross-user data leak between machines", "owner": "Security owner", "likelihood": 2, "impact": 5, "treatment": "reduce", "controls": ["CC6.3-1"], "identified": "2027-01-05" },
                { "id": "R-02", "title": "Signup abuse for free compute", "owner": "Security owner", "likelihood": 3, "impact": 2, "treatment": "reduce", "controls": ["CC3.3-1"], "fraud": true, "identified": "2027-01-05" },
                { "id": "R-03", "title": "Single botd, no failover", "owner": "Management", "likelihood": 2, "impact": 5, "treatment": "accept", "identified": "2027-01-05", "acceptedBy": "p-mgmt", "acceptedAt": "2027-01-06", "acceptedUntil": "2028-01-06", "notes": "secret reasoning" },
            ],
            "riskReviews": [{ "at": "2027-01-06", "by": "p-sec" }],
            "managementReviews": [{ "at": "2027-03-20", "attendees": ["p-mgmt", "p-sec"], "minutesSha256": ZERO }],
            "vendors": [
                { "id": "linode", "tier": "critical", "hosting": true, "since": "2027-01-15", "assessed": "2027-01-10", "approvedBy": "p-sec" },
                { "id": "github", "tier": "low", "since": "2026-01-01" },
            ],
            "exceptions": [
                { "id": "EX-01", "policy": "information-security", "setting": "MACHINE_ON_DISABLE", "approvedBy": "p-sec", "approvedAt": "2027-02-01", "ends": "2027-08-01", "reviewed": ["2027-03-15"], "notes": "why" },
            ],
        })
    }

    fn check(v: &Value, f: &dyn Fn(&Check)) {
        let r = parse(&serde_json::to_vec(v).unwrap(), &builtin_policies()).unwrap();
        f(&Check { r: &r, p: period(), policies: &builtin_policies(), baselines: &[] });
    }

    fn exceptions(v: &Value) -> usize {
        v["exceptions"].as_object().unwrap().values().map(|a| a.as_array().unwrap().len()).sum()
    }

    #[test]
    fn a_well_kept_register_has_no_exceptions_and_covers_every_row() {
        check(&good(), &|c| {
            for (file, v, rows) in files(c) {
                assert_eq!(exceptions(&v), 0, "{file}: {}", v["exceptions"]);
                let want: Vec<&str> = SECTIONS.iter().find(|s| s.file == file).unwrap().rows.to_vec();
                if file == "policy-exceptions.json" {
                    assert!(rows.is_empty(), "no baseline check given");
                } else {
                    assert_eq!(rows, want, "{file}");
                }
            }
        });
    }

    #[test]
    fn roles_without_a_holder_or_deputy_and_holders_who_left() {
        let mut v = good();
        v["roles"][3]["until"] = json!("2027-03-10");
        v["roles"].as_array_mut().unwrap().push(json!({ "role": "Operator", "holder": "p-eng", "from": "2027-03-20" }));
        v["roles"][4]["deputy"] = json!("p-mgmt");
        v["people"][2]["left"] = json!("2027-03-25");
        check(&v, &|c| {
            let (r, rows) = c.roles();
            let ex = &r["exceptions"];
            assert_eq!(ex["roleUnfilled"], json!(["Operator: 2027-03-10 to 2027-03-20"]));
            assert_eq!(ex["noDeputy"], json!(["Operator: 2027-03-10 to 2027-04-01"]));
            assert_eq!(ex["holderIsDeputy"], json!(["People lead from 2027-01-01: p-mgmt"]));
            assert_eq!(ex["notPersonnel"], json!(["Engineering lead: p-eng on 2027-03-25", "Operator: p-eng on 2027-03-25"]));
            assert_eq!(rows, ["CC1.3-1"]);
        });
        let mut empty = good();
        empty["roles"] = json!([]);
        check(&empty, &|c| {
            let (r, rows) = c.roles();
            assert_eq!(r["exceptions"]["roleUnfilled"].as_array().unwrap().len(), 6);
            assert!(rows.is_empty(), "no role in force maps nothing");
        });
    }

    #[test]
    fn policies_unapproved_overdue_changed_or_approved_by_the_wrong_role() {
        let mut v = good();
        v["policyApprovals"].as_array_mut().unwrap().retain(|a| a["policy"] != "acceptable-use");
        v["policyApprovals"][1]["approvedAt"] = json!("2026-03-01");
        v["policyApprovals"][1]["approvedBy"] = json!("p-ops");
        let r = parse(&serde_json::to_vec(&v).unwrap(), &builtin_policies()).unwrap();
        let mut texts = builtin_policies();
        texts.iter_mut().for_each(|p| p.sha256 = Some(ZERO.into()));
        texts[2].sha256 = Some("1".repeat(64));
        let c = Check { r: &r, p: period(), policies: &texts, baselines: &[] };
        let (pol, rows) = c.policies();
        let ex = &pol["exceptions"];
        assert_eq!(ex["notApproved"], json!(["acceptable-use"]));
        assert_eq!(ex["reviewOverdue"], json!(["access-control (approved 2026-03-01)"]));
        assert_eq!(ex["changedSinceApproval"], json!(["change-management"]));
        assert_eq!(ex["approverNotInRole"], json!(["access-control on 2026-03-01: p-ops didn't hold Management"]));
        assert_eq!(pol["textsChecked"], true);
        assert_eq!(rows, ["CC3.1-1", "CC5.3-1"]);
        let infosec = pol["policies"].as_array().unwrap().iter().find(|p| p["policy"] == "information-security").unwrap();
        assert_eq!((infosec["latest"]["heldRole"].as_str(), infosec["textApproved"].as_bool()), (Some("Management"), Some(true)));
        check(&good(), &|c| assert_eq!(c.policies().0["textsChecked"], false));
    }

    #[test]
    fn acknowledgements_and_training_due_late_and_overdue() {
        let mut v = good();
        v["people"].as_array_mut().unwrap().push(json!({ "id": "p-new", "joined": "2027-02-01" }));
        v["people"].as_array_mut().unwrap().push(json!({ "id": "p-gone", "joined": "2026-01-01", "left": "2027-03-05" }));
        v["acknowledgements"].as_array_mut().unwrap().push(json!({ "person": "p-new", "policy": "information-security", "at": "2027-03-20" }));
        v["acknowledgements"].as_array_mut().unwrap().retain(|a| !(a["person"] == "p-ops" && a["policy"] == "acceptable-use"));
        v["training"][0]["at"] = json!("2026-01-01");
        v["training"].as_array_mut().unwrap().push(json!({ "person": "p-mgmt", "course": AWARENESS, "at": "2026-02-01" }));
        check(&v, &|c| {
            let (pe, _) = c.people();
            let ex = &pe["exceptions"];
            assert_eq!(ex["notAcknowledged"], json!(["p-ops acceptable-use (due 2027-02-04)", "p-new acceptable-use (due 2027-03-03)"]));
            assert_eq!(ex["acknowledgedLate"], json!(["p-new information-security (2027-03-20, due 2027-03-03)"]));
            assert_eq!(ex["notTrained"], json!(["p-new (due 2027-03-03)"]));
            assert_eq!(ex["trainingOverdue"], json!(["p-mgmt (last 2026-02-01)"]));
            assert_eq!(ex["acknowledgementOverdue"], json!([]));
            let gone = pe["people"].as_array().unwrap().iter().find(|x| x["id"] == "p-gone").unwrap();
            assert_eq!(gone["atEnd"], false, "a leaver in the period is listed, not chased");
            assert!(!pe.to_string().contains("Example"), "no names: {pe}");
        });
        let mut later = good();
        later["policyApprovals"].as_array_mut().unwrap().iter_mut().for_each(|a| a["approvedAt"] = json!("2027-03-20"));
        later["acknowledgements"] = json!([]);
        later["training"] = json!([]);
        check(&later, &|c| assert_eq!(exceptions(&c.people().0), 0, "due 30 days after the first approval, after the period"));
    }

    #[test]
    fn risks_unreviewed_accepted_without_management_and_no_fraud() {
        let mut v = good();
        v["risks"][0]["identified"] = json!("2025-12-01");
        v["risks"][0]["reviewed"] = json!(["2026-01-15"]);
        v["risks"][1]["fraud"] = json!(false);
        v["risks"][2]["acceptedBy"] = json!("p-ops");
        v["risks"][2]["acceptedUntil"] = json!("2027-03-15");
        v["risks"].as_array_mut().unwrap().push(json!({ "id": "R-04", "owner": "Operator", "likelihood": 1, "impact": 2, "treatment": "accept", "identified": "2027-02-01" }));
        v["risks"].as_array_mut().unwrap().push(json!({ "id": "R-05", "owner": "Operator", "likelihood": 4, "impact": 4, "treatment": "reduce", "identified": "2027-02-01", "closed": "2027-02-20" }));
        v["riskReviews"] = json!([{ "at": "2026-01-15", "by": "p-sec" }]);
        check(&v, &|c| {
            let (r, rows) = c.risks();
            let ex = &r["exceptions"];
            assert_eq!(ex["reviewOverdue"], json!(["R-01 (last 2026-01-15)"]));
            assert_eq!(ex["acceptedWithoutManagement"], json!(["R-03"]), "R-04 is within the appetite");
            assert_eq!(ex["acceptanceLapsed"], json!(["R-03 (until 2027-03-15)"]));
            assert_eq!(ex["acceptanceNoReviewDate"], json!(["R-04"]));
            assert_eq!(ex["notAccepted"], json!(["R-04"]), "an accepted risk needs a dated acceptance, even within the appetite");
            assert_eq!(ex["noFraudRisk"], json!(["no open risk is marked fraud"]));
            assert_eq!(ex["noFullReview"], json!(["none in the year to 2027-04-01 (last 2026-01-15)"]));
            assert_eq!((r["summary"]["open"].as_u64(), r["summary"]["closed"].as_u64()), (Some(4), Some(1)));
            assert_eq!(rows, ["CC3.2-1"]);
            let s = r.to_string();
            assert!(!s.contains("Cross-user") && !s.contains("secret reasoning"), "no titles or notes: {s}");
        });
        let mut small = good();
        small["risks"][2]["likelihood"] = json!(1);
        small["risks"][2]["acceptedBy"] = json!("p-eng");
        check(&small, &|c| assert_eq!((c.risks().0["exceptions"]["acceptedWithoutManagement"].clone(), c.risks().0["exceptions"]["notAccepted"].clone()), (json!([]), json!(["R-03"])), "within the appetite, but p-eng isn't the owner's role"));
        small["risks"][2]["owner"] = json!("Engineering lead");
        check(&small, &|c| assert_eq!(c.risks().0["exceptions"]["notAccepted"], json!([]), "the owner accepts it within the appetite"));
        let mut late = good();
        late["risks"][2]["acceptedAt"] = json!("2027-04-02");
        check(&late, &|c| assert_eq!(c.risks().0["exceptions"]["notAccepted"], json!(["R-03"]), "an acceptance after the period doesn't count for it"));
        let mut gone = good();
        gone["people"][0]["left"] = json!("2027-01-02");
        check(&gone, &|c| assert_eq!(c.risks().0["exceptions"]["acceptedWithoutManagement"], json!(["R-03"]), "someone who had left holds no role"));
        small["riskAppetite"] = Value::Null;
        check(&small, &|c| assert_eq!(c.risks().0["exceptions"]["acceptedWithoutManagement"], json!(["R-03"]), "with no appetite every acceptance needs management"));
        small["risks"][2]["acceptedBy"] = json!("p-sec");
        check(&small, &|c| assert_eq!(c.risks().0["exceptions"]["acceptedWithoutManagement"], json!([]), "management's deputy accepts it"));
    }

    #[test]
    fn management_reviews_by_quarter() {
        let q = Period { from: d("2026-12-01"), to: d("2027-04-01") };
        assert_eq!(quarters_ended(&q).iter().map(|x| x.0.as_str()).collect::<Vec<_>>(), ["2026-Q4", "2027-Q1"]);
        assert!(quarters_ended(&Period { from: d("2027-01-01"), to: d("2027-02-01") }).is_empty(), "Q1 hasn't ended");
        let mut v = good();
        v["managementReviews"] = json!([{ "at": "2027-01-20", "attendees": ["p-eng"] }]);
        let r = parse(&serde_json::to_vec(&v).unwrap(), &builtin_policies()).unwrap();
        let c = Check { r: &r, p: q, policies: &builtin_policies(), baselines: &[] };
        let (m, rows) = c.management_reviews();
        assert_eq!(m["exceptions"]["quarterWithoutReview"], json!(["2026-Q4"]));
        assert_eq!(m["exceptions"]["withoutManagementOrSecurityOwner"], json!(["2027-01-20"]));
        assert_eq!(m["exceptions"]["noMinutes"], json!(["2027-01-20"]));
        assert_eq!(rows, ["CC1.2-1"], "within a quarter of the end");
        let late = Check { r: &r, p: Period { from: d("2027-05-01"), to: d("2027-06-01") }, policies: &builtin_policies(), baselines: &[] };
        assert!(late.management_reviews().1.is_empty(), "the last review is over a quarter old");
    }

    #[test]
    fn vendors_assessed_before_use_and_reviewed_yearly() {
        let mut v = good();
        v["vendors"][0]["assessed"] = json!("2027-02-01");
        v["vendors"][0]["approvedBy"] = json!("p-ops");
        v["vendors"].as_array_mut().unwrap().push(json!({ "id": "stripe", "tier": "high", "since": "2025-01-01", "assessed": "2024-12-01", "approvedBy": "p-sec", "reviewed": ["2025-12-01"] }));
        v["vendors"].as_array_mut().unwrap().push(json!({ "id": "old-smtp", "tier": "high", "since": "2025-01-01", "until": "2027-01-01" }));
        check(&v, &|c| {
            let (x, rows) = c.vendors();
            let ex = &x["exceptions"];
            assert_eq!(ex["notAssessedBeforeUse"], json!(["linode (in use since 2027-01-15)"]));
            assert_eq!(ex["notApproved"], json!(["linode", "stripe"]), "p-ops is neither the security owner nor management; p-sec held no role in 2024");
            assert_eq!(ex["reviewOverdue"], json!(["stripe (last 2025-12-01)"]));
            assert_eq!(ex["noHostingVendor"], json!([]));
            assert_eq!(x["summary"]["inUse"], 3, "a vendor left before the period isn't listed");
            assert_eq!(rows, ["CC6.4-1", "CC9.2-1"]);
        });
        let mut late = good();
        late["vendors"][0]["assessed"] = json!("2027-04-02");
        check(&late, &|c| {
            let ex = &c.vendors().0["exceptions"];
            assert_eq!((ex["notAssessedBeforeUse"].clone(), ex["notApproved"].clone()), (json!(["linode (in use since 2027-01-15)"]), json!(["linode"])), "an assessment after the period isn't this period's");
        });
    }

    #[test]
    fn exceptions_and_the_servers_baseline_exceptions() {
        let mut v = good();
        v["exceptions"].as_array_mut().unwrap().push(json!({ "id": "EX-02", "policy": "access-control", "approvedBy": "p-eng", "approvedAt": "2026-10-01", "ends": "2027-12-01" }));
        let r = parse(&serde_json::to_vec(&v).unwrap(), &builtin_policies()).unwrap();
        let json_check = |at: &str, excepted: &[&str]| serde_json::to_vec(&json!({ "format": 1, "checkedAt": at, "digest": ZERO, "ok": true, "exceptions": { "deviations": [], "excepted": excepted, "unknownExceptions": [] } })).unwrap();
        let b1 = baseline("/srv/evidence/baseline-a.json", &json_check("2027-03-10T09:00:00Z", &["MACHINE_ON_DISABLE", "TEAMS"]), &period()).unwrap();
        assert_eq!((b1.file.as_str(), b1.checked_on), ("baseline-a.json", d("2027-03-10")), "the file's name, never its folder");
        let b2 = baseline("b.json", &json_check("2027-04-01T00:00:05Z", &[]), &period()).unwrap();
        assert_eq!(b2.checked_on, d("2027-04-01"), "the month's evidence bundle, made on the 1st");
        let bs = [b1, b2];
        let c = Check { r: &r, p: period(), policies: &builtin_policies(), baselines: &bs };
        let (x, rows) = c.exceptions();
        let ex = &x["exceptions"];
        assert_eq!(ex["overAYear"], json!(["EX-02 (approved 2026-10-01, ends 2027-12-01)"]));
        assert_eq!(ex["approverNotInRole"], json!(["EX-02"]));
        assert_eq!(ex["reviewOverdue"], json!(["EX-02 (last 2026-10-01)"]));
        assert_eq!(ex["baselineExceptionNotApproved"], json!(["TEAMS on baseline-a.json (checked 2027-03-10T09:00:00Z)"]));
        assert_eq!(rows, ["CC5.1-1"]);
        assert!(!x.to_string().contains("\"why\""), "no notes");

        for (bytes, want) in [
            (b"nope".to_vec(), "isn't JSON"),
            (serde_json::to_vec(&json!({ "exceptions": { "excepted": [] } })).unwrap(), "checkedAt"),
            (json_check("2027-04-08T00:00:00Z", &[]), "outside the period"),
            (json_check("2027-02-28T23:59:59Z", &[]), "outside the period"),
            (serde_json::to_vec(&json!({ "checkedAt": "2027-03-02T00:00:00Z" })).unwrap(), "exceptions.excepted"),
            (json_check("2027-03-02T00:00:00Z", &["a b"]), "isn't a setting's name"),
        ] {
            let e = baseline("x.json", &bytes, &period()).unwrap_err();
            assert!(e.contains(want), "{want}: {e}");
        }
    }

    #[test]
    fn a_register_that_doesnt_hold_together_is_refused_with_every_problem() {
        let mut v = good();
        v["people"].as_array_mut().unwrap().push(json!({ "id": "alice@example.com", "joined": "2026-01-01" }));
        v["people"].as_array_mut().unwrap().push(json!({ "id": "p-sec", "joined": "2026-01-01" }));
        v["roles"][0]["holder"] = json!("p-nobody");
        v["roles"][1]["role"] = json!("CISO");
        v["policyApprovals"][0]["sha256"] = json!("abc");
        v["policyApprovals"][1]["policy"] = json!("code-of-conduct");
        v["risks"][0]["likelihood"] = json!(6);
        v["risks"][0]["treatment"] = json!("ignore");
        v["risks"][0]["controls"] = json!(["CC6.1"]);
        v["risks"][1]["acceptedUntil"] = json!("2027-06-01");
        v["vendors"][0]["tier"] = json!("medium");
        v["exceptions"][0]["ends"] = json!("2027-01-01");
        v["exceptions"][0]["setting"] = json!("machine_on_disable");
        let e = parse(&serde_json::to_vec(&v).unwrap(), &builtin_policies()).unwrap_err();
        for want in [
            "person id alice@example.com isn't plain",
            "person id p-sec is used twice",
            "names p-nobody, who isn't in people",
            "names the role CISO",
            "sha256 is the policy file's SHA-256",
            "names the policy code-of-conduct",
            "likelihood and impact are 1 to 5",
            "treatment is reduce, accept, transfer or avoid",
            "control CC6.1 isn't a readiness checklist row id",
            "acceptedBy, acceptedAt and acceptedUntil are for accepted risks only",
            "tier is critical, high or low",
            "ends must be after approvedAt",
            "setting is a configuration baseline setting's name",
        ] {
            assert!(e.contains(want), "{want}\n{e}");
        }
        for (edit, want) in [
            (json!({ "superbotRegister": 2 }), "format 2"),
            (json!({ "people": [] }), "no superbotRegister"),
            (json!({ "superbotRegister": 1, "peple": [] }), "unknown field `peple`"),
            (json!({ "superbotRegister": 1, "people": [{ "id": "p", "joined": "1 March" }] }), "isn't a date"),
        ] {
            let e = parse(&serde_json::to_vec(&edit).unwrap(), &builtin_policies()).unwrap_err();
            assert!(e.contains(want), "{want}: {e}");
        }
        assert!(parse(b"{", &builtin_policies()).unwrap_err().contains("isn't JSON"));
    }

    #[test]
    fn records_after_the_period_are_left_out() {
        let mut v = good();
        v["managementReviews"].as_array_mut().unwrap().push(json!({ "at": "2027-04-02", "attendees": ["p-mgmt"] }));
        v["policyApprovals"].as_array_mut().unwrap().push(json!({ "policy": "access-control", "sha256": "1".repeat(64), "approvedBy": "p-eng", "approvedAt": "2027-04-01" }));
        check(&v, &|c| {
            assert_eq!(c.after_period(), 2);
            assert_eq!(exceptions(&c.policies().0), 0, "a later approval by the wrong person isn't this period's");
            assert_eq!(c.management_reviews().0["summary"]["reviewsInTheYear"], 1);
        });
    }

    #[test]
    fn the_bundle_maps_only_what_the_register_holds_and_names_nobody() {
        let mut v = good();
        v["managementReviews"] = json!([]);
        let bytes = serde_json::to_vec(&v).unwrap();
        let r = parse(&bytes, &builtin_policies()).unwrap();
        let c = Check { r: &r, p: period(), policies: &builtin_policies(), baselines: &[] };
        let src = Source { file: "register.json".into(), bytes: bytes.len(), sha256: sha256(&bytes) };
        let now = period().end_ms() + 3_600_000;
        let b = build(&c, &src, now);
        assert!(b.name.starts_with("superbot-register-2027-03-01_2027-04-01-") && b.name.len() + "/management-reviews.json".len() <= 100, "{}", b.name);
        assert!(![crate::changes::PREFIX, crate::vulns::PREFIX, crate::drills::PREFIX, "superbot-evidence-"].iter().any(|p| b.name.starts_with(p)));
        let entries = crate::coverage::untar(&b.tar).unwrap();
        let all: String = entries.iter().map(|(_, x)| String::from_utf8_lossy(x).into_owned()).collect();
        for never in ["Alice", "Example", "Cross-user", "secret reasoning", "Signup abuse"] {
            assert!(!all.contains(never), "{never:?} is in the bundle");
        }
        let manifest: Value = serde_json::from_slice(&entries.iter().find(|(n, _)| n.ends_with("/manifest.json")).unwrap().1).unwrap();
        assert_eq!((manifest["kind"].as_str(), manifest["source"]["registerSha256"].as_str()), (Some("policy-register"), Some(sha256(&bytes).as_str())));
        let file = |n: &str| manifest["files"].as_array().unwrap().iter().find(|f| f["name"] == n).unwrap().clone();
        assert_eq!((file("management-reviews.json")["checklist"].clone(), file("management-reviews.json")["criteria"].clone()), (json!([]), json!([])), "no review within a quarter");
        assert_eq!((file("policies.json")["checklist"].clone(), file("policies.json")["criteria"].clone()), (json!(["CC3.1-1", "CC5.3-1"]), json!(["CC3.1", "CC5.3"])));
        let found = crate::coverage::check("b.tar".into(), &b.name, &entries.iter().map(|(n, x)| (n.rsplit('/').next().unwrap().to_string(), x.clone())).collect::<BTreeMap<String, Vec<u8>>>());
        assert!(found.verified(), "{:?}", found.problems);
        assert!(found.warnings.is_empty(), "{:?}", found.warnings);
        assert_eq!(found.exceptions["management-reviews.json"]["quarterWithoutReview"], 1);
        assert!(summary(&c).contains("management-reviews.json: quarterWithoutReview 1"), "{}", summary(&c));
    }

    #[test]
    fn options() {
        let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>();
        let a = parse_args(&s(&["r.json", "--policies", "docs", "--baseline", "a.json", "--baseline", "b.json", "--from", "2027-03-01", "--to", "2027-04-01", "-o", "x.tar"])).unwrap();
        assert_eq!((a.register.as_str(), a.policies.as_deref(), a.baselines.len(), a.out.as_deref()), ("r.json", Some("docs"), 2, Some("x.tar")));
        for bad in [&[][..], &["--policies", "d"], &["r.json", "s.json"], &["r.json", "--from"], &["r.json", "-o", "a", "-o", "b"], &["r.json", "--token", "x"], &["r.json", "--baseline"]] {
            assert!(parse_args(&s(bad)).is_err(), "{bad:?}");
        }
    }

    /// The policy files' headers name an approver this tool knows, and the template in the
    /// security pack reads, names every role and policy, and names no real person.
    #[test]
    fn the_real_policies_and_the_template() {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../docs/security/policies");
        let real = read_policies(&dir).unwrap();
        assert_eq!(real.iter().map(|p| p.id.as_str()).collect::<BTreeSet<_>>(), POLICIES.iter().copied().collect::<BTreeSet<_>>(), "the built-in set is the policy set");
        assert!(real.iter().all(|p| p.approver == "Management" && p.sha256.as_ref().is_some_and(|s| s.len() == 64)));
        let template = include_str!("../../../../docs/security/policy-register-template.json");
        let r = parse(template.as_bytes(), &real).unwrap();
        assert_eq!(r.roles.iter().map(|x| x.role.as_str()).collect::<BTreeSet<_>>(), ROLES.iter().copied().collect::<BTreeSet<_>>());
        assert_eq!(r.policy_approvals.iter().map(|a| a.policy.as_str()).collect::<BTreeSet<_>>(), POLICIES.iter().copied().collect::<BTreeSet<_>>());
        assert!(r.people.iter().all(|p| p.name.as_deref().is_none_or(|n| n.starts_with('<'))), "placeholders only");
        assert!(r.risks.iter().any(|x| x.fraud), "the template has a fraud risk to start from");
    }

    /// Every file maps to criteria the control mapping has and rows the readiness checklist
    /// has, each under one of its criteria, and the evidence plan's register table lists
    /// each file with them.
    #[test]
    fn every_file_maps_to_real_controls_and_the_evidence_plan_says_so() {
        let mapping = include_str!("../../../../docs/security/soc2-control-mapping.md");
        let checklist = include_str!("../../../../docs/security/soc2-readiness-checklist.md");
        let plan = include_str!("../../../../docs/security/soc2-evidence-plan.md");
        let section = plan.split("## The register bundle").nth(1).and_then(|s| s.split("\n## ").next()).expect("the evidence plan has a register bundle section");
        for s in &SECTIONS {
            for c in s.criteria {
                assert!(mapping.contains(&format!("| {c} ")), "{}: {c} isn't a criterion of the control mapping", s.file);
            }
            for r in s.rows {
                assert!(checklist.contains(&format!("| {r} |")), "{}: {r} isn't a row of the readiness checklist", s.file);
                assert!(s.criteria.iter().any(|c| r.starts_with(&format!("{c}-"))), "{}: {r} isn't under one of its criteria", s.file);
            }
            let line = section.lines().find(|l| l.starts_with(&format!("| `{}` |", s.file))).unwrap_or_else(|| panic!("the evidence plan's register table has no row for `{}`", s.file));
            for id in s.criteria.iter().chain(s.rows) {
                assert!(line.contains(id), "the evidence plan's row for `{}` doesn't name {id}", s.file);
            }
        }
    }
}
