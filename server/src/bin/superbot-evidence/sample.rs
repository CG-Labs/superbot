//! `superbot-evidence sample` and `results` (ADR 0296): testing controls the way a Type II
//! auditor does, on samples drawn from the populations the evidence store already holds.
//! `sample` reads every bundle in the store that checks (as `coverage` does, ADR 0169),
//! gathers each test's population for the period (merged pull requests, production
//! changes, access grants and reviews, security events, vulnerabilities, pages, days of
//! backups), says where a population can't be complete, and draws a sample of each by a
//! seeded SHA-256 ranking anyone can re-perform, into a bundle with a worksheet for the
//! tester. `results` checks the filled-in worksheet against that bundle and writes what
//! was tested, by whom and the deviations, as a bundle of its own. Local files only: no
//! token, no network, nothing written into the store.

use crate::changes::{json_file, rfc3339, sha256};
use crate::coverage::{self, Files, Found};
use crate::period::Period;
use crate::register::plain_id;
use chrono::NaiveDate;
use serde_json::{Map, Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

/// Bumped when a bundle's shape changes.
pub const FORMAT: u32 = 1;
pub const PREFIX: &str = "superbot-samples-";
pub const RESULTS_PREFIX: &str = "superbot-results-";
pub const SAMPLES_FILE: &str = "samples.json";
pub const WORKSHEET_FILE: &str = "worksheet.csv";
pub const RESULTS_FILE: &str = "results.json";

/// A samples bundle or a worksheet larger than this isn't read.
const MAX_BYTES: u64 = 64 << 20;

/// A `--seed`'s longest.
const MAX_SEED: usize = 128;

/// A worksheet `reference`'s longest: a ticket id, a URL or a SHA-256.
const MAX_REFERENCE: usize = 200;

/// One population and what a tester checks on each item drawn from it.
pub struct Test {
    pub id: &'static str,
    pub title: &'static str,
    /// The coverage kind of the bundles it is read from.
    pub kind: &'static str,
    pub file: &'static str,
    /// The list in the file holding the population; empty for the days of each bundle's period.
    pub list: &'static str,
    /// The field dating each item, which must fall in the period.
    pub date: &'static str,
    /// Only items whose field has this value.
    pub only: Option<(&'static str, &'static str)>,
    /// The fields naming an item, joined by `/`.
    pub key: &'static [&'static str],
    /// The fields copied into the sample; a dot reads into an object.
    pub fields: &'static [&'static str],
    pub criteria: &'static [&'static str],
    pub rows: &'static [&'static str],
    pub check: &'static str,
}

pub const TESTS: [Test; 9] = [
    Test {
        id: "merged-pull-requests",
        title: "Pull requests merged into the main branch",
        kind: "change-management",
        file: "pull-requests.json",
        list: "pullRequests",
        date: "mergedAt",
        only: None,
        key: &["number"],
        fields: &["number", "url", "author", "mergedAt", "mergedBy", "approvers", "approvedFinalCommit", "checks.allRequiredPassed"],
        criteria: &["CC3.4", "CC8.1"],
        rows: &["CC3.4-1", "CC8.1-1", "CC8.1-2"],
        check: "On GitHub: approved by someone other than its author before the merge, on its last commit; its required checks passed at the merge; if it changed a control, its ADR and the security pack's update are in it",
    },
    Test {
        id: "production-changes",
        title: "Production and emergency changes in the policy register",
        kind: "policy-register",
        file: "production-changes.json",
        list: "changes",
        date: "made",
        only: None,
        key: &["id"],
        fields: &["id", "kind", "system", "recordSha256", "recorded", "approved", "approvedBy", "made", "madeBy", "checked", "reviewed", "pullRequest"],
        criteria: &["CC8.1"],
        rows: &["CC8.1-2"],
        check: "The change record (by its SHA-256): approved before the change by someone other than who made it, or for an emergency change by the incident's commander, then reviewed by a second person and its code followed by a pull request; announced ahead if it could interrupt the service; checked afterwards",
    },
    Test {
        id: "access-grants",
        title: "Grants of production access",
        kind: "policy-register",
        file: "access.json",
        list: "grants",
        date: "granted",
        only: None,
        key: &["person", "system", "level", "granted"],
        fields: &["person", "system", "level", "requested", "approved", "approvers", "granted", "removed"],
        criteria: &["CC6.2"],
        rows: &["CC6.2-2"],
        check: "The written request and approval: dated on or before the grant, by the security owner (and Management for admin access to a managed server or the hosting provider), not the grantee; the access on the system is the level approved; a leaver's access removed by their last day",
    },
    Test {
        id: "access-reviews",
        title: "Reviews of production access",
        kind: "policy-register",
        file: "access.json",
        list: "reviews",
        date: "at",
        only: None,
        key: &["system", "at"],
        fields: &["system", "at", "by", "listSha256", "mfa", "signedOffAt", "findings"],
        criteria: &["CC6.1", "CC6.3"],
        rows: &["CC6.1-2", "CC6.3-2"],
        check: "The user list (by its SHA-256) and the reviewer's sign-off: every account on it judged, MFA recorded as the system has it, each finding fixed by its due date; for a managed server, the access_review.completed event of the same digest that day",
    },
    Test {
        id: "security-events",
        title: "Security events in the policy register",
        kind: "policy-register",
        file: "incidents.json",
        list: "incidents",
        date: "detected",
        only: None,
        key: &["id"],
        fields: &["id", "detected", "triaged", "severity", "commander", "breach", "customersNotifiedAt", "closed", "reviewed", "reviewSha256"],
        criteria: &["CC7.3", "CC7.4", "CC7.5"],
        rows: &["CC7.3-1", "CC7.4-1", "CC7.4-2", "CC7.5-1"],
        check: "The ticket: triaged within its severity's window by the commander recorded, contained and recovered as the incident response plan says; a possible breach's notice to customers within the DPA's hours; the written review (by its SHA-256) where one is required, with its actions done",
    },
    Test {
        id: "reported-vulnerabilities",
        title: "Vulnerabilities found outside the scans",
        kind: "policy-register",
        file: "vulnerabilities.json",
        list: "vulnerabilities",
        date: "received",
        only: None,
        key: &["id"],
        fields: &["id", "source", "received", "acknowledged", "assessed", "severity", "fixDue", "fixed", "accepted", "acceptedBy"],
        criteria: &["CC2.3", "CC4.2"],
        rows: &["CC2.3-1", "CC4.2-1"],
        check: "The report or finding: acknowledged (reports) and assessed in time, and fixed by a merged pull request or accepted with a reason by the security owner or Management within its severity's window",
    },
    Test {
        id: "closed-vulnerability-alerts",
        title: "Dependabot and code scanning alerts closed",
        kind: "vulnerability-management",
        file: "vulnerability-alerts.json",
        list: "alerts",
        date: "closedAt",
        only: None,
        key: &["source", "number"],
        fields: &["source", "number", "url", "severity", "createdAt", "closedAt", "closedHow", "dismissedReason", "dismissedBy", "dueAt", "withinWindow"],
        criteria: &["CC4.2", "CC7.1"],
        rows: &["CC4.2-1", "CC7.1-2"],
        check: "On GitHub: fixed by a merged pull request, or dismissed with a reason by someone allowed to accept it, by its due date",
    },
    Test {
        id: "pages",
        title: "Pages from the alert rules",
        kind: "alerting",
        file: crate::alerts::FILE,
        list: "episodes",
        date: "from",
        only: Some(("severity", "page")),
        key: &["id"],
        fields: &["id", "alert", "from", "lastSeen", "minutes"],
        criteria: &["CC7.2"],
        rows: &["CC7.2-1"],
        check: "The response on record (a ticket, or an incident in the policy register): someone looked at it while it fired, and what was done",
    },
    Test {
        id: "backup-days",
        title: "Days of a managed server's backups",
        kind: "evidence",
        file: "backups.json",
        list: "",
        date: "",
        only: None,
        key: &[],
        fields: &[],
        criteria: &["A1.2"],
        rows: &["A1.2-1"],
        check: "In the off-host store's listing: that day's server copies and machine backups are there, encrypted, as many as the day's counts; a failure or RPO breach that day was followed up",
    },
];

/// The sample size for a population: as a control done yearly (1), quarterly or monthly
/// (2), weekly (5), or daily and more often (25); never more than the population.
pub const SIZES: [(usize, usize); 4] = [(1, 1), (12, 2), (52, 5), (usize::MAX, 25)];

pub fn size_for(population: usize) -> usize {
    SIZES.iter().find(|(up_to, _)| population <= *up_to).map_or(0, |(_, n)| *n).min(population)
}

/// An item's rank: the lowest ranks are the sample.
pub fn rank(seed: &str, test: &str, item: &str) -> String {
    sha256(format!("{seed}\n{test}\n{item}\n").as_bytes())
}

/// A population's digest: one id a line, sorted.
pub fn population_sha256(ids: &BTreeSet<String>) -> String {
    sha256(ids.iter().map(|i| format!("{i}\n")).collect::<String>().as_bytes())
}

fn day_of(v: &Value) -> Option<NaiveDate> {
    v.as_str().and_then(|s| s.get(..10)).and_then(|s| NaiveDate::parse_from_str(s, "%Y-%m-%d").ok())
}

fn text(v: &Value) -> Option<String> {
    match v {
        Value::String(s) if !s.is_empty() => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

fn pick(v: &Value, fields: &[&str]) -> Value {
    let mut out = Map::new();
    for f in fields {
        let got = f.split('.').fold(v, |at, k| &at[k]);
        out.insert((*f).to_string(), got.clone());
    }
    Value::Object(out)
}

/// One member of a population.
#[derive(Clone, Debug)]
pub struct Item {
    pub id: String,
    pub bundle: String,
    created: String,
    pub fields: Value,
}

/// A test's population for the period, and what stops it being complete.
#[derive(Debug, Default)]
pub struct Population {
    pub items: BTreeMap<String, Item>,
    pub bundles: BTreeSet<String>,
    pub missing: Vec<Value>,
    pub failed: Vec<String>,
    pub without_file: Vec<String>,
    /// Sources a bundle couldn't read (a scanner GitHub refused), as `<path>: <source>`.
    pub unread: Vec<String>,
}

impl Population {
    pub fn complete(&self) -> bool {
        self.missing.is_empty() && self.failed.is_empty() && self.without_file.is_empty() && self.unread.is_empty()
    }
}

/// Whether a bundle of a kind can hold items dated in the period. A register bundle of a
/// later period still carries a change, grant or finding open at its start (a change
/// checked after the month it was made in), with its newer state; the other kinds list
/// only what their own period holds.
fn may_hold(kind: &str, b: &Period, p: &Period) -> bool {
    p.from < b.to && (kind == "policy-register" || b.from < p.to)
}

/// The population of one test: every item dated in the period, from the bundles of its
/// kind that check; an item in more than one bundle is taken from the newest.
pub fn population(t: &Test, store: &[(Found, Files)], p: &Period) -> Population {
    let mut pop = Population::default();
    let mut covered = BTreeSet::new();
    for (f, files) in store {
        let (Some(kind), Some(bp)) = (f.kind, f.period) else {
            // A damaged tar, or a bundle whose name gives no period, could be of any kind
            // or period, so every population it might belong to is incomplete.
            if !f.verified() && f.kind.is_none_or(|k| k.id == t.kind) {
                pop.failed.push(f.path.clone());
            }
            continue;
        };
        if kind.id != t.kind || !may_hold(kind.id, &bp, p) {
            continue;
        }
        if !f.verified() {
            pop.failed.push(f.path.clone());
            continue;
        }
        let Some(v) = files.get(t.file).and_then(|b| serde_json::from_slice::<Value>(b).ok()) else {
            pop.without_file.push(f.path.clone());
            continue;
        };
        let days = bp.from.iter_days().take_while(|d| *d < bp.to).filter(|d| *d >= p.from && *d < p.to);
        covered.extend(days.clone());
        pop.bundles.insert(f.name.clone());
        for (source, s) in v["sources"].as_object().into_iter().flatten() {
            if s["available"] == false {
                pop.unread.push(format!("{}: {source}", f.path));
            }
        }
        // Ids are unique within one repository, so a store of several keeps each apart.
        let scope = v["repository"].as_str().filter(|r| !r.is_empty()).map(|r| format!("{r}#"));
        let created = f.created.clone().unwrap_or_default();
        let mut add = |id: String, fields: Value| {
            let newer = pop.items.get(&id).is_none_or(|old| (created.as_str(), f.name.as_str()) > (old.created.as_str(), old.bundle.as_str()));
            if newer {
                pop.items.insert(id.clone(), Item { id, bundle: f.name.clone(), created: created.clone(), fields });
            }
        };
        if t.list.is_empty() {
            // Two servers' bundles can share a name; their manifests never match, and a
            // copy of one bundle (its tar and its folder) is still one.
            let manifest = f.manifest_sha256.as_deref().unwrap_or_default();
            let bundle = format!("{}@{}", f.name, &manifest[..manifest.len().min(16)]);
            for d in days {
                let day = d.to_string();
                let counts = v["period"]["daily"].get(&day).cloned().unwrap_or_else(|| json!({}));
                add(format!("{bundle}/{day}"), json!({ "day": day, "counts": counts }));
            }
            continue;
        }
        for x in v[t.list].as_array().into_iter().flatten() {
            if t.only.is_some_and(|(k, want)| x[k] != want) || day_of(&x[t.date]).is_none_or(|d| d < p.from || d >= p.to) {
                continue;
            }
            let parts: Option<Vec<String>> = t.key.iter().map(|k| text(&x[*k])).collect();
            if let Some(parts) = parts {
                add(format!("{}{}", scope.as_deref().unwrap_or_default(), parts.join("/")), pick(x, t.fields));
            }
        }
    }
    pop.missing = coverage::gaps(p, &covered);
    pop
}

// Drawing the samples

pub struct Draw {
    pub period: Period,
    pub seed: Option<String>,
    pub sizes: BTreeMap<String, usize>,
}

/// The seed a store gives when none is: fixed by the populations, so anyone reading the
/// same store draws the same samples, and nobody can choose them without changing it.
pub fn store_seed(p: &Period, pops: &[(&Test, Population)]) -> String {
    let lines: String = pops.iter().map(|(t, pop)| format!("{} {}\n", t.id, population_sha256(&pop.items.keys().cloned().collect()))).collect();
    sha256(format!("superbot-samples\n{}\n{lines}", p.label()).as_bytes())
}

fn worksheet_cell(s: &str) -> String {
    if s.contains([',', '"', '\n', '\r']) { format!("\"{}\"", s.replace('"', "\"\"")) } else { s.to_string() }
}

/// What every samples bundle holds, and the worksheet's columns.
pub const COLUMNS: [&str; 10] = ["test", "item", "bundle", "rows", "check", "result", "tester", "tested_on", "reference", "notes"];

pub struct Samples {
    pub samples: Value,
    pub worksheet: String,
}

pub fn draw(store: &[(Found, Files)], d: &Draw) -> Samples {
    let p = &d.period;
    let pops: Vec<(&Test, Population)> = TESTS.iter().map(|t| (t, population(t, store, p))).collect();
    let (seed, seed_from) = match &d.seed {
        Some(s) => (s.clone(), "given"),
        None => (store_seed(p, &pops), "store"),
    };
    let mut rows = vec![COLUMNS.join(",")];
    let mut tests = Vec::new();
    let (mut empty, mut incomplete, mut sampled_total) = (Vec::new(), Vec::new(), 0);
    for (t, pop) in &pops {
        let ids: BTreeSet<String> = pop.items.keys().cloned().collect();
        let n = pop.items.len();
        let (size, size_from) = match d.sizes.get(t.id) {
            Some(&k) => (k.min(n), "--size"),
            None => (size_for(n), "table"),
        };
        let mut ranked: Vec<(String, &Item)> = pop.items.values().map(|i| (rank(&seed, t.id, &i.id), i)).collect();
        ranked.sort_by(|a, b| (&a.0, &a.1.id).cmp(&(&b.0, &b.1.id)));
        ranked.truncate(size);
        sampled_total += ranked.len();
        let rows_text = t.rows.join(" ");
        for (_, i) in &ranked {
            let cells = [t.id, i.id.as_str(), i.bundle.as_str(), rows_text.as_str(), t.check, "", "", "", "", ""];
            rows.push(cells.iter().map(|c| worksheet_cell(c)).collect::<Vec<_>>().join(","));
        }
        let complete = pop.complete();
        if n == 0 {
            empty.push(json!(t.id));
        }
        if !complete {
            incomplete.push(json!(t.id));
        }
        tests.push(json!({
            "id": t.id,
            "title": t.title,
            "criteria": t.criteria,
            "rows": t.rows,
            "check": t.check,
            "source": { "kind": t.kind, "file": t.file, "list": if t.list.is_empty() { Value::Null } else { json!(t.list) }, "only": t.only.map(|(k, v)| json!({ k: v })) },
            "population": {
                "size": n,
                "sha256": population_sha256(&ids),
                "complete": complete,
                "missingDays": pop.missing,
                "bundlesFailed": pop.failed,
                "bundlesWithoutFile": pop.without_file,
                "sourcesUnread": pop.unread,
                "bundles": pop.bundles,
                "items": ids,
            },
            "sampleSize": ranked.len(),
            "sizeFrom": size_from,
            "sample": ranked.iter().map(|(r, i)| json!({ "item": i.id, "rank": r, "bundle": i.bundle, "fields": i.fields })).collect::<Vec<_>>(),
        }));
    }
    let samples = json!({
        "basis": "each test's population is every item dated in the period in the bundles of its kind that check against their digests, register bundles of later periods included since they carry an item's later state, an item in more than one bundle taken from the newest (ids are prefixed with their repository where the file names one, and a day of backups is named by its bundle's manifest digest, so several repositories or servers are kept apart); a population is complete only when those bundles cover every day of the period and none that could hold its items failed (a damaged bundle whose kind can't be told counts for every test), lacked the file, or couldn't read one of its sources (a scanner GitHub refused). Each item's rank is the SHA-256 of the seed, the test's id and the item's id, each followed by a newline, and the sample is the items with the lowest ranks, so anyone with the store and the seed can draw it again. Sizes follow the table unless --size was given; the auditor decides the sizes they rely on. Exceptions the bundles list are reviewed in full, not sampled",
        "periodCovered": { "from": p.from.to_string(), "to": p.to.to_string(), "days": p.days() },
        "seed": seed,
        "seedFrom": seed_from,
        "sizes": { "table": SIZES.iter().map(|(up_to, n)| json!({ "populationUpTo": if *up_to == usize::MAX { Value::Null } else { json!(up_to) }, "sample": n })).collect::<Vec<_>>(), "given": d.sizes },
        "summary": {
            "tests": TESTS.len(),
            "itemsSampled": sampled_total,
            "populationsEmpty": empty,
            "populationsIncomplete": incomplete,
        },
        "tests": tests,
    });
    let mut worksheet = rows.join("\n");
    worksheet.push('\n');
    Samples { samples, worksheet }
}

const README: &str = "SuperBot audit samples (superbot-evidence sample, ADR 0296)

samples.json: each test's population for the period, read from the evidence store's
bundles that check against their digests, whether it is complete, and the items drawn
for testing with the seed that drew them. worksheet.csv: one line per item drawn; the
tester fills in result (pass, fail or n/a), tester (their policy register id),
tested_on (YYYY-MM-DD), reference (the ticket, URL or SHA-256 they checked) and notes,
then `superbot-evidence results` checks it against this bundle.

A sample is what was drawn, not a test of it, and not a SOC 2 opinion: the auditor
decides the populations, sizes and samples they rely on.
";

pub struct Bundle {
    pub name: String,
    pub tar: Vec<u8>,
    pub sha256: String,
    pub manifest_sha256: String,
}

fn seal(name: &str, mut files: Vec<(&str, Vec<u8>)>, manifest: Value, now_ms: i64) -> Bundle {
    files.push(("manifest.json", json_file(&manifest)));
    let sums: String = files.iter().map(|(n, b)| format!("{}  {n}\n", sha256(b))).collect();
    let manifest_sha256 = sha256(&files.last().expect("the manifest").1);
    files.push(("SHA256SUMS", sums.into_bytes()));
    let entries: Vec<(String, Vec<u8>)> = files.iter().map(|(n, b)| (format!("{name}/{n}"), b.clone())).collect();
    let tar = crate::ustar::tar(&entries, (now_ms / 1000).max(0) as u64);
    Bundle { sha256: sha256(&tar), manifest_sha256, name: name.to_string(), tar }
}

fn listed(files: &[(&str, Vec<u8>)], criteria: &[&str]) -> Vec<Value> {
    files.iter().map(|(n, b)| json!({ "name": n, "bytes": b.len(), "sha256": sha256(b), "criteria": if *n == "README.txt" { &[][..] } else { criteria }, "checklist": [] })).collect()
}

fn stamp(now_ms: i64) -> String {
    chrono::DateTime::from_timestamp_millis(now_ms).map(|t| t.format("%Y%m%dT%H%M%SZ").to_string()).unwrap_or_default()
}

pub fn build(s: &Samples, store: &[(Found, Files)], p: &Period, now_ms: i64) -> Bundle {
    let name = format!("{PREFIX}{}-{}", p.label(), stamp(now_ms));
    let files: Vec<(&str, Vec<u8>)> = vec![("README.txt", README.as_bytes().to_vec()), (SAMPLES_FILE, json_file(&s.samples)), (WORKSHEET_FILE, s.worksheet.clone().into_bytes())];
    let read: Vec<Value> = store
        .iter()
        .filter(|(f, _)| f.verified() && TESTS.iter().any(|t| f.kind.is_some_and(|k| k.id == t.kind && f.period.is_some_and(|bp| may_hold(k.id, &bp, p)))))
        .map(|(f, _)| json!({ "name": f.name, "path": f.path, "kind": f.kind.map(|k| k.id), "manifestSha256": f.manifest_sha256 }))
        .collect();
    let manifest = json!({
        "product": "SuperBot",
        "kind": "audit-samples",
        "format": FORMAT,
        "tool": concat!("superbot-evidence ", env!("CARGO_PKG_VERSION")),
        "createdAt": rfc3339(now_ms),
        "period": { "from": p.from.to_string(), "to": p.to.to_string(), "days": p.days() },
        "seed": s.samples["seed"],
        "seedFrom": s.samples["seedFrom"],
        "store": { "bundles": store.len(), "verified": store.iter().filter(|(f, _)| f.verified()).count(), "read": read },
        "itemsSampled": s.samples["summary"]["itemsSampled"],
        "files": listed(&files, &[]),
        "notIncluded": "anything the bundles drawn from leave out; the store's other files",
    });
    seal(&name, files, manifest, now_ms)
}

// Checking the tester's results

/// A worksheet, as RFC 4180 CSV: rows of cells, quoted cells with `""` for a quote.
pub fn parse_csv(s: &str) -> Result<Vec<Vec<String>>, String> {
    let (mut rows, mut row, mut cell) = (Vec::new(), Vec::new(), String::new());
    let (mut quoted, mut was_quoted) = (false, false);
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        match (quoted, c) {
            (true, '"') if chars.peek() == Some(&'"') => {
                chars.next();
                cell.push('"');
            }
            (true, '"') => quoted = false,
            (true, c) => cell.push(c),
            (false, '"') if cell.is_empty() && !was_quoted => (quoted, was_quoted) = (true, true),
            (false, ',') => {
                row.push(std::mem::take(&mut cell));
                was_quoted = false;
            }
            (false, '\r') if chars.peek() == Some(&'\n') => {}
            (false, '\n') => {
                row.push(std::mem::take(&mut cell));
                rows.push(std::mem::take(&mut row));
                was_quoted = false;
            }
            (false, '"') => return Err(format!("line {}: a quote inside a cell that isn't quoted", rows.len() + 1)),
            (false, c) => cell.push(c),
        }
    }
    if quoted {
        return Err("the worksheet ends inside a quoted cell".into());
    }
    if !cell.is_empty() || !row.is_empty() {
        row.push(cell);
        rows.push(row);
    }
    rows.retain(|r| !(r.len() == 1 && r[0].trim().is_empty()));
    Ok(rows)
}

/// A samples bundle's files, checked against its own `SHA256SUMS` and manifest.
pub fn read_samples(path: &Path) -> Result<(String, Files), String> {
    let shown = path.display();
    let meta = std::fs::metadata(path).map_err(|e| format!("{shown}: {e}"))?;
    let (name, files) = if meta.is_dir() {
        let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        let mut files = Files::new();
        for e in std::fs::read_dir(path).map_err(|e| format!("{shown}: {e}"))?.filter_map(Result::ok) {
            let n = e.file_name().to_string_lossy().into_owned();
            let m = std::fs::metadata(e.path()).map_err(|e| format!("{n}: {e}"))?;
            if !m.is_file() || m.len() > MAX_BYTES {
                return Err(format!("{shown}: {n} isn't a file of a samples bundle"));
            }
            files.insert(n, std::fs::read(e.path()).map_err(|e| format!("{shown}: {e}"))?);
        }
        (name, files)
    } else {
        if meta.len() > MAX_BYTES {
            return Err(format!("{shown} is over {} MiB, larger than any samples bundle", MAX_BYTES >> 20));
        }
        let entries = coverage::untar(&std::fs::read(path).map_err(|e| format!("{shown}: {e}"))?).map_err(|e| format!("{shown}: {e}"))?;
        let tops: BTreeSet<String> = entries.iter().map(|(n, _)| n.split('/').next().unwrap_or_default().to_string()).collect();
        if tops.len() != 1 {
            return Err(format!("{shown} holds more than one folder: give the samples bundle as made"));
        }
        let top = tops.into_iter().next().unwrap_or_default();
        let mut files = Files::new();
        for (n, b) in entries {
            match n.strip_prefix(&format!("{top}/")) {
                Some(f) if !f.is_empty() && !f.contains('/') => {
                    if files.insert(f.to_string(), b).is_some() {
                        return Err(format!("{shown}: {f} is in the tar more than once"));
                    }
                }
                Some("") => {}
                _ => return Err(format!("{shown}: {n} isn't a file of the bundle's folder")),
            }
        }
        (top, files)
    };
    if !name.starts_with(PREFIX) {
        return Err(format!("{shown} isn't a samples bundle ({PREFIX}...): give the bundle superbot-evidence sample made"));
    }
    let mut problems = Vec::new();
    let sums = files.get("SHA256SUMS").map(|b| String::from_utf8_lossy(b).into_owned()).unwrap_or_default();
    let mut listed = BTreeSet::new();
    for line in sums.lines().filter(|l| !l.trim().is_empty()) {
        match line.split_once("  ") {
            Some((d, f)) if files.get(f).is_some_and(|b| sha256(b) == d) => {
                listed.insert(f.to_string());
            }
            Some((_, f)) => problems.push(format!("{f} doesn't match SHA256SUMS")),
            None => problems.push("SHA256SUMS has a line that isn't <sha256>  <file>".into()),
        }
    }
    problems.extend(files.keys().filter(|n| *n != "SHA256SUMS" && !listed.contains(*n)).map(|n| format!("{n} isn't in SHA256SUMS")));
    let manifest: Value = files.get("manifest.json").and_then(|b| serde_json::from_slice(b).ok()).unwrap_or_default();
    if manifest["product"] != "SuperBot" || manifest["kind"] != "audit-samples" {
        problems.push("manifest.json isn't a SuperBot samples manifest".into());
    }
    for f in manifest["files"].as_array().into_iter().flatten() {
        let n = f["name"].as_str().unwrap_or_default();
        if files.get(n).is_none_or(|b| f["sha256"].as_str() != Some(sha256(b).as_str())) {
            problems.push(format!("{n} doesn't match manifest.json"));
        }
    }
    for need in [SAMPLES_FILE, WORKSHEET_FILE] {
        if !files.contains_key(need) {
            problems.push(format!("it has no {need}"));
        }
    }
    if problems.is_empty() { Ok((name, files)) } else { Err(format!("{shown} doesn't check, so its samples can't be relied on:\n- {}", problems.join("\n- "))) }
}

/// One line of the worksheet, as the tester filled it in.
#[derive(Debug, PartialEq)]
pub struct Line {
    pub test: String,
    pub item: String,
    pub result: Option<String>,
    pub tester: Option<String>,
    pub tested_on: Option<NaiveDate>,
    pub reference: Option<String>,
}

fn plain_reference(s: &str) -> bool {
    s.len() <= MAX_REFERENCE && s.bytes().all(|c| c.is_ascii_graphic() && c != b',')
}

/// The worksheet's lines, refused (listing every problem) unless each names an item drawn,
/// once, and every result has a tester and a day.
pub fn read_worksheet(csv: &str, sampled: &BTreeSet<(String, String)>, today: NaiveDate) -> Result<Vec<Line>, String> {
    let rows = parse_csv(csv)?;
    let Some((head, body)) = rows.split_first() else { return Err("the worksheet is empty".into()) };
    let col = |name: &str| head.iter().position(|h| h.trim().eq_ignore_ascii_case(name));
    let need = ["test", "item", "result", "tester", "tested_on"];
    let missing: Vec<&str> = need.iter().copied().filter(|n| col(n).is_none()).collect();
    if !missing.is_empty() {
        return Err(format!("the worksheet has no {} column: use the one in the samples bundle", missing.join(", ")));
    }
    let repeated: Vec<&str> = COLUMNS.iter().copied().filter(|c| head.iter().filter(|h| h.trim().eq_ignore_ascii_case(c)).count() > 1).collect();
    if !repeated.is_empty() {
        return Err(format!("the worksheet has more than one {} column, so which to read is unclear", repeated.join(", ")));
    }
    let at = |r: &Vec<String>, name: &str| col(name).and_then(|i| r.get(i)).map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
    let (mut out, mut problems, mut seen) = (Vec::new(), Vec::new(), BTreeSet::new());
    for (n, r) in body.iter().enumerate() {
        let line = n + 2;
        let (test, item) = (at(r, "test").unwrap_or_default(), at(r, "item").unwrap_or_default());
        if !sampled.contains(&(test.clone(), item.clone())) {
            problems.push(format!("line {line}: {test} {item} wasn't drawn in this samples bundle"));
            continue;
        }
        if !seen.insert((test.clone(), item.clone())) {
            problems.push(format!("line {line}: {test} {item} is on the worksheet more than once"));
            continue;
        }
        let result = at(r, "result").map(|s| s.to_ascii_lowercase());
        let tester = at(r, "tester");
        let tested_on = at(r, "tested_on");
        let reference = at(r, "reference");
        let day = tested_on.as_deref().map(|d| NaiveDate::parse_from_str(d, "%Y-%m-%d"));
        if let Some(res) = &result {
            if !matches!(res.as_str(), "pass" | "fail" | "n/a") {
                problems.push(format!("line {line}: result {res} isn't pass, fail or n/a"));
            }
            if !tester.as_deref().is_some_and(plain_id) {
                problems.push(format!("line {line}: a result needs the tester's policy register id (letters, digits, . _ -)"));
            }
            match &day {
                Some(Ok(d)) if *d > today => problems.push(format!("line {line}: tested_on {d} is in the future")),
                Some(Ok(_)) => {}
                _ => problems.push(format!("line {line}: a result needs tested_on as YYYY-MM-DD")),
            }
        }
        if reference.as_deref().is_some_and(|x| !plain_reference(x)) {
            problems.push(format!("line {line}: reference must be one ticket id, URL or SHA-256, with no spaces or commas, up to {MAX_REFERENCE} characters"));
        }
        out.push(Line { test, item, result, tester, tested_on: day.and_then(Result::ok), reference });
    }
    if problems.is_empty() { Ok(out) } else { Err(format!("The worksheet doesn't hold together, so nothing was written:\n- {}", problems.join("\n- "))) }
}

/// What the worksheet shows for each test drawn, and the exceptions.
pub fn results(samples: &Value, lines: &[Line], drawn_on: Option<NaiveDate>) -> Value {
    let by: BTreeMap<(&str, &str), &Line> = lines.iter().map(|l| ((l.test.as_str(), l.item.as_str()), l)).collect();
    let (mut deviations, mut untested, mut not_applicable, mut early, mut unreferenced) = (Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new());
    let mut testers = BTreeSet::new();
    let (mut tests, mut items) = (Vec::new(), Vec::new());
    let mut incomplete = Vec::new();
    let (mut total, mut tested_total, mut passed_total) = (0, 0, 0);
    for t in samples["tests"].as_array().into_iter().flatten() {
        let id = t["id"].as_str().unwrap_or_default();
        if t["population"]["complete"] != true {
            incomplete.push(json!(id));
        }
        let (mut n, mut tested, mut passed, mut failed, mut na) = (0, 0, 0, 0, 0);
        for s in t["sample"].as_array().into_iter().flatten() {
            let item = s["item"].as_str().unwrap_or_default();
            let label = format!("{id} {item}");
            n += 1;
            let Some(l) = by.get(&(id, item)).filter(|l| l.result.is_some()) else {
                untested.push(json!(label));
                items.push(json!({ "test": id, "item": item, "result": Value::Null }));
                continue;
            };
            tested += 1;
            if let Some(who) = &l.tester {
                testers.insert(who.clone());
            }
            match l.result.as_deref() {
                Some("pass") => passed += 1,
                Some("fail") => {
                    failed += 1;
                    if l.reference.is_none() {
                        unreferenced.push(json!(label));
                    }
                    deviations.push(json!(label));
                }
                _ => {
                    na += 1;
                    not_applicable.push(json!(label));
                }
            }
            if let (Some(on), Some(drawn)) = (l.tested_on, drawn_on)
                && on < drawn
            {
                early.push(json!(format!("{label} (tested {on}, drawn {drawn})")));
            }
            items.push(json!({ "test": id, "item": item, "result": l.result, "tester": l.tester, "testedOn": l.tested_on.map(|d| d.to_string()), "reference": l.reference }));
        }
        total += n;
        tested_total += tested;
        passed_total += passed;
        let conclusion = match (n, tested, failed) {
            (0, _, _) => "nothing to test: the population was empty".to_string(),
            (_, 0, _) => "not tested".to_string(),
            (n, t, 0) if t == n => format!("no deviations in the {n} items tested"),
            (n, t, 0) => format!("no deviations in {t} of {n} items tested so far"),
            (n, t, f) => format!("{f} deviation{} in {t} of {n} items tested", if f == 1 { "" } else { "s" }),
        };
        tests.push(json!({ "id": id, "rows": t["rows"], "populationSize": t["population"]["size"], "populationComplete": t["population"]["complete"], "sampled": n, "tested": tested, "passed": passed, "deviations": failed, "notApplicable": na, "conclusion": conclusion }));
    }
    json!({
        "basis": "each item drawn in the samples bundle with the result the tester recorded on the worksheet: pass when it had every attribute of its test's check, fail (a deviation) when it lacked one, n/a when the check didn't apply. A test with no deviations says the items tested had the attributes checked, not that the control operated effectively: only an auditor concludes on that, on the populations, sizes and samples they rely on. Notes stay on the worksheet, kept beside this bundle by its SHA-256",
        "summary": { "sampled": total, "tested": tested_total, "passed": passed_total, "deviations": deviations.len(), "notApplicable": not_applicable.len(), "untested": untested.len(), "testers": testers.len() },
        "exceptions": { "deviations": deviations, "deviationsWithoutReference": unreferenced, "untested": untested, "notApplicable": not_applicable, "testedBeforeDrawn": early, "populationsIncomplete": incomplete },
        "tests": tests,
        "items": items,
    })
}

const RESULTS_README: &str = "SuperBot audit sample results (superbot-evidence results, ADR 0296)

results.json: each item drawn in the samples bundle named in the manifest, with the
result its tester recorded on the worksheet, by test, with the deviations, the items not
tested, those marked not applicable, and the populations that weren't complete. The
worksheet itself, with its notes, is kept beside this bundle by its SHA-256.

No deviations in a sample is not a SOC 2 opinion: only an auditor concludes on whether
a control operated effectively.
";

pub fn build_results(r: &Value, samples_name: &str, samples_manifest_sha256: &str, samples: &Value, worksheet: (&str, &[u8]), now_ms: i64) -> Bundle {
    let p = &samples["periodCovered"];
    let label = format!("{}_{}", p["from"].as_str().unwrap_or_default(), p["to"].as_str().unwrap_or_default());
    let name = format!("{RESULTS_PREFIX}{label}-{}", stamp(now_ms));
    let files: Vec<(&str, Vec<u8>)> = vec![("README.txt", RESULTS_README.as_bytes().to_vec()), (RESULTS_FILE, json_file(r))];
    let manifest = json!({
        "product": "SuperBot",
        "kind": "audit-results",
        "format": FORMAT,
        "tool": concat!("superbot-evidence ", env!("CARGO_PKG_VERSION")),
        "createdAt": rfc3339(now_ms),
        "period": p,
        "samples": { "name": samples_name, "manifestSha256": samples_manifest_sha256, "seed": samples["seed"], "seedFrom": samples["seedFrom"] },
        "worksheet": { "file": worksheet.0, "bytes": worksheet.1.len(), "sha256": sha256(worksheet.1) },
        "summary": r["summary"],
        "files": listed(&files, &["CC4.1", "CC4.2"]),
        "notIncluded": "the worksheet's notes and check text; anything the samples bundle leaves out",
    });
    seal(&name, files, manifest, now_ms)
}

// The commands

pub const USAGE: &str = "  superbot-evidence sample <evidence store> [--from <YYYY-MM-DD> --to <YYYY-MM-DD>]
                    [--seed <text>] [--size <test>=<n>]... [-o <file>]
  superbot-evidence results <samples bundle> <worksheet.csv> [-o <file>]";

struct SampleArgs {
    store: String,
    from: Option<String>,
    to: Option<String>,
    seed: Option<String>,
    sizes: BTreeMap<String, usize>,
    out: Option<String>,
}

fn value<'a>(it: &mut std::slice::Iter<'a, String>, flag: &str) -> Result<&'a String, String> {
    it.next().filter(|v| !v.starts_with("--") && !v.is_empty()).ok_or(format!("{flag} needs a value"))
}

fn parse_sample(args: &[String]) -> Result<SampleArgs, String> {
    let mut a = SampleArgs { store: String::new(), from: None, to: None, seed: None, sizes: BTreeMap::new(), out: None };
    let mut it = args.iter();
    while let Some(flag) = it.next() {
        let slot = match flag.as_str() {
            "--from" => &mut a.from,
            "--to" => &mut a.to,
            "--seed" => &mut a.seed,
            "-o" | "--out" => &mut a.out,
            "--size" => {
                let v = value(&mut it, flag)?;
                let (test, n) = v.split_once('=').ok_or(format!("--size {v}: give <test>=<n>"))?;
                if !TESTS.iter().any(|t| t.id == test) {
                    return Err(format!("--size {v}: {test} isn't a test; the tests are {}", TESTS.iter().map(|t| t.id).collect::<Vec<_>>().join(", ")));
                }
                let n: usize = n.parse().ok().filter(|n| *n > 0).ok_or(format!("--size {v}: the size must be a whole number above 0"))?;
                if a.sizes.insert(test.to_string(), n).is_some() {
                    return Err(format!("--size {test} is given twice"));
                }
                continue;
            }
            s if !s.starts_with('-') && a.store.is_empty() => {
                a.store = s.to_string();
                continue;
            }
            _ => return Err(format!("Unknown option {flag}.\n\n{USAGE}")),
        };
        if slot.is_some() {
            return Err(format!("{flag} is given twice"));
        }
        *slot = Some(value(&mut it, flag)?.clone());
    }
    if a.store.is_empty() {
        return Err(format!("Give the evidence store's folder.\n\n{USAGE}"));
    }
    if a.seed.as_deref().is_some_and(|s| s.len() > MAX_SEED || !s.bytes().all(|c| c.is_ascii_alphanumeric() || b"._:-".contains(&c))) {
        return Err(format!("--seed must be up to {MAX_SEED} letters, digits and . _ : -"));
    }
    Ok(a)
}

pub fn run_sample(args: &[String], now: chrono::DateTime<chrono::Utc>) -> Result<String, String> {
    let a = parse_sample(args)?;
    let p = Period::parse(a.from.as_deref(), a.to.as_deref(), now.date_naive())?;
    let keep: Vec<&str> = TESTS.iter().map(|t| t.file).collect::<BTreeSet<_>>().into_iter().collect();
    let (store, _) = coverage::scan_keeping(Path::new(&a.store), &keep)?;
    let s = draw(&store, &Draw { period: p, seed: a.seed.clone(), sizes: a.sizes.clone() });
    let b = build(&s, &store, &p, now.timestamp_millis());
    let file = a.out.clone().unwrap_or_else(|| format!("{}.tar", b.name));
    crate::save_private(&file, &b.tar)?;
    let lines: Vec<String> = s.samples["tests"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|t| {
            let pop = &t["population"];
            let note = if pop["complete"] == true { String::new() } else { " (incomplete: see missingDays, bundlesFailed, bundlesWithoutFile and sourcesUnread)".into() };
            format!("  {}: {} of {}{note}", t["id"].as_str().unwrap_or_default(), t["sampleSize"], pop["size"])
        })
        .collect();
    Ok(format!(
        "Saved {file} ({} KB): samples for {} to {} (not included) from {} bundles that check, seed {} ({}).\n{}\nManifest SHA-256: {}\nBundle SHA-256: {}\nTest each item on its worksheet.csv, then: superbot-evidence results {} <worksheet.csv>",
        b.tar.len().div_ceil(1024),
        p.from,
        p.to,
        store.iter().filter(|(f, _)| f.verified()).count(),
        s.samples["seed"].as_str().unwrap_or_default(),
        if s.samples["seedFrom"] == "given" { "given" } else { "from the store" },
        lines.join("\n"),
        b.manifest_sha256,
        b.sha256,
        crate::quote(&file),
    ))
}

pub fn run_results(args: &[String], now: chrono::DateTime<chrono::Utc>) -> Result<(String, bool), String> {
    let (mut given, mut out) = (Vec::new(), None);
    let mut it = args.iter();
    while let Some(flag) = it.next() {
        match flag.as_str() {
            "-o" | "--out" if out.is_none() => out = Some(value(&mut it, flag)?.clone()),
            s if !s.starts_with('-') && given.len() < 2 => given.push(s.to_string()),
            _ => return Err(format!("Unknown option {flag}.\n\n{USAGE}")),
        }
    }
    let [bundle, sheet] = &given[..] else { return Err(format!("Give the samples bundle and the filled-in worksheet.\n\n{USAGE}")) };
    let (name, files) = read_samples(Path::new(bundle))?;
    let samples: Value = serde_json::from_slice(&files[SAMPLES_FILE]).map_err(|e| format!("{SAMPLES_FILE}: {e}"))?;
    let manifest_sha256 = sha256(&files["manifest.json"]);
    if std::fs::metadata(sheet).map_err(|e| format!("{sheet}: {e}"))?.len() > MAX_BYTES {
        return Err(format!("{sheet} is over {} MiB, larger than any worksheet", MAX_BYTES >> 20));
    }
    let bytes = std::fs::read(sheet).map_err(|e| format!("{sheet}: {e}"))?;
    let csv = String::from_utf8(bytes.clone()).map_err(|_| format!("{sheet} isn't UTF-8 text"))?;
    let sampled: BTreeSet<(String, String)> = samples["tests"]
        .as_array()
        .into_iter()
        .flatten()
        .flat_map(|t| t["sample"].as_array().into_iter().flatten().map(move |s| (t["id"].as_str().unwrap_or_default().to_string(), s["item"].as_str().unwrap_or_default().to_string())))
        .collect();
    let lines = read_worksheet(csv.trim_start_matches('\u{feff}'), &sampled, now.date_naive())?;
    let manifest: Value = serde_json::from_slice(&files["manifest.json"]).unwrap_or_default();
    let drawn_on = day_of(&manifest["createdAt"]);
    let r = results(&samples, &lines, drawn_on);
    let sheet_name = Path::new(sheet).file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    let b = build_results(&r, &name, &manifest_sha256, &samples, (&sheet_name, &bytes), now.timestamp_millis());
    let file = out.unwrap_or_else(|| format!("{}.tar", b.name));
    crate::save_private(&file, &b.tar)?;
    let s = &r["summary"];
    let clean = s["deviations"] == 0 && s["untested"] == 0 && r["exceptions"]["populationsIncomplete"].as_array().is_some_and(Vec::is_empty);
    let lines: Vec<String> = r["tests"].as_array().into_iter().flatten().map(|t| format!("  {}: {}", t["id"].as_str().unwrap_or_default(), t["conclusion"].as_str().unwrap_or_default())).collect();
    Ok((
        format!(
            "Saved {file} ({} KB): {} of {} items tested by {} testers, {} deviations, {} not tested.\n{}\nManifest SHA-256: {}\nBundle SHA-256: {}\nKeep it with the samples bundle and the worksheet (SHA-256 {}).",
            b.tar.len().div_ceil(1024),
            s["tested"],
            s["sampled"],
            s["testers"],
            s["deviations"],
            s["untested"],
            lines.join("\n"),
            b.manifest_sha256,
            b.sha256,
            sha256(&bytes),
        ),
        clean,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(s: &str) -> NaiveDate {
        NaiveDate::parse_from_str(s, "%Y-%m-%d").unwrap()
    }

    fn p(from: &str, to: &str) -> Period {
        Period { from: d(from), to: d(to) }
    }

    /// A bundle of `kind` that checks, with `body` as `file` and every other file its kind
    /// always has as `{}`.
    fn bundle(kind: &str, period: Period, made: &str, file: &str, body: &Value) -> (Found, Files) {
        let k = coverage::KINDS.iter().find(|k| k.id == kind).unwrap();
        let name = format!("{}{}-{}", k.prefix, period.label(), made.replace(['-', ':'], ""));
        let mut files = Files::new();
        let mut listed = Vec::new();
        for (f, criteria, rows) in coverage::expected(kind) {
            let b = if f == file { json_file(body) } else { json_file(&json!({})) };
            listed.push(json!({ "name": f, "sha256": sha256(&b), "criteria": criteria, "checklist": rows }));
            files.insert(f.into(), b);
        }
        let mut manifest = json!({ "product": "SuperBot", "format": k.format, "createdAt": made, "period": { "from": period.from.to_string(), "to": period.to.to_string(), "days": period.days() }, "files": listed });
        if let Some(mk) = k.manifest_kind {
            manifest["kind"] = json!(mk);
        }
        files.insert("manifest.json".into(), json_file(&manifest));
        let sums: String = files.iter().map(|(n, b)| format!("{}  {n}\n", sha256(b))).collect();
        files.insert("SHA256SUMS".into(), sums.into_bytes());
        let f = coverage::check(format!("store/{name}.tar"), &name, &files);
        assert!(f.verified(), "{:?}", f.problems);
        (f, files)
    }

    fn prs(numbers: std::ops::RangeInclusive<u64>, month: &str) -> Value {
        json!({ "pullRequests": numbers.map(|n| json!({ "number": n, "url": format!("https://github.com/o/r/pull/{n}"), "author": "a", "mergedAt": format!("{month}-{:02}T10:00:00Z", n % 28 + 1), "approvers": ["b"], "approvedFinalCommit": true, "checks": { "allRequiredPassed": true, "runs": ["never copied"] }, "title": "never copied" })).collect::<Vec<_>>() })
    }

    fn store() -> Vec<(Found, Files)> {
        let reg = |changes: Value| json!({ "changes": changes, "exceptions": {} });
        vec![
            bundle("change-management", p("2027-01-01", "2027-02-01"), "2027-02-01T03:00:00Z", "pull-requests.json", &prs(1..=40, "2027-01")),
            bundle("change-management", p("2027-02-01", "2027-03-01"), "2027-03-01T03:00:00Z", "pull-requests.json", &prs(41..=70, "2027-02")),
            bundle(
                "policy-register",
                p("2027-01-01", "2027-02-01"),
                "2027-02-02T09:00:00Z",
                "production-changes.json",
                &reg(json!([{ "id": "CHG-1", "kind": "standard", "made": "2027-01-10", "notes": "never copied" }, { "id": "CHG-2", "kind": "emergency", "made": "2027-01-20", "checked": null }])),
            ),
            bundle(
                "policy-register",
                p("2027-02-01", "2027-03-01"),
                "2027-03-02T09:00:00Z",
                "production-changes.json",
                &reg(json!([{ "id": "CHG-2", "kind": "emergency", "made": "2027-01-20", "checked": "2027-02-01" }, { "id": "CHG-3", "kind": "standard", "made": "2027-02-03" }, { "id": "CHG-0", "kind": "standard", "made": "2026-12-30" }])),
            ),
            bundle("alerting", p("2027-01-01", "2027-02-01"), "2027-02-01T05:00:00Z", crate::alerts::FILE, &json!({ "episodes": [{ "id": "SuperBotDown-1", "severity": "page", "from": "2027-01-04T10:00:00Z" }, { "id": "SuperBotSlow-1", "severity": "ticket", "from": "2027-01-05T10:00:00Z" }] })),
            bundle("evidence", p("2027-01-01", "2027-02-01"), "2027-02-01T00:05:00Z", "backups.json", &json!({ "period": { "daily": { "2027-01-03": { "server.backup_copied ok": 24 } } } })),
        ]
    }

    fn test(s: &Value, id: &str) -> Value {
        s["tests"].as_array().unwrap().iter().find(|t| t["id"] == id).unwrap().clone()
    }

    #[test]
    fn sizes_follow_the_table_and_never_exceed_the_population() {
        let got: Vec<usize> = [0, 1, 2, 3, 12, 13, 52, 53, 400, 100_000].iter().map(|n| size_for(*n)).collect();
        assert_eq!(got, vec![0, 1, 2, 2, 2, 5, 5, 25, 25, 25]);
    }

    #[test]
    fn populations_come_from_bundles_that_check_with_the_newest_copy_of_each_item() {
        let st = store();
        let pop = population(&TESTS[1], &st, &p("2027-01-01", "2027-03-01"));
        assert_eq!(pop.items.keys().collect::<Vec<_>>(), vec!["CHG-1", "CHG-2", "CHG-3"], "made in the period only");
        assert_eq!(pop.items["CHG-2"].fields["checked"], "2027-02-01", "from the newer bundle");
        assert!(pop.items["CHG-1"].fields.get("notes").is_none(), "only the listed fields");
        assert!(pop.missing.is_empty() && pop.failed.is_empty());

        let january = population(&TESTS[1], &st, &p("2027-01-01", "2027-02-01"));
        assert_eq!(january.items.keys().collect::<Vec<_>>(), vec!["CHG-1", "CHG-2"]);
        assert_eq!(january.items["CHG-2"].fields["checked"], "2027-02-01", "February's bundle carries January's change as later checked");
        assert_eq!((january.bundles.len(), january.missing.len()), (2, 0));
        let december = population(&TESTS[1], &st, &p("2026-12-01", "2027-01-01"));
        assert_eq!(december.items.keys().collect::<Vec<_>>(), vec!["CHG-0"], "from a later bundle, though none covers December's days");
        assert_eq!(december.missing.len(), 1);

        let pages = population(&TESTS[7], &st, &p("2027-01-01", "2027-03-01"));
        assert_eq!(pages.items.keys().collect::<Vec<_>>(), vec!["SuperBotDown-1"], "pages only");
        assert_eq!(pages.missing, vec![json!({ "from": "2027-02-01", "to": "2027-03-01", "days": 28 })], "no alerts bundle for February");

        let days = population(&TESTS[8], &st, &p("2027-01-01", "2027-02-01"));
        assert_eq!(days.items.len(), 31);
        let name = format!("{}@{}", st[5].0.name, &st[5].0.manifest_sha256.as_deref().unwrap()[..16]);
        assert_eq!(days.items[&format!("{name}/2027-01-03")].fields["counts"], json!({ "server.backup_copied ok": 24 }));
        assert_eq!(days.items[&format!("{name}/2027-01-04")].fields["counts"], json!({}));

        let mut two = st.clone();
        two.push(bundle("evidence", p("2027-01-01", "2027-02-01"), "2027-02-01T00:05:00Z", "backups.json", &json!({ "period": { "daily": { "2027-01-03": { "server.backup_copied ok": 12 } } } })));
        assert_eq!(two[5].0.name, two[6].0.name, "two servers' scheduled bundles, made the same second");
        assert_eq!(population(&TESTS[8], &two, &p("2027-01-01", "2027-02-01")).items.len(), 62, "each server's days kept apart");
        two.push(two[5].clone());
        assert_eq!(population(&TESTS[8], &two, &p("2027-01-01", "2027-02-01")).items.len(), 62, "a copy of one bundle is still one");

        let mut repos = st.clone();
        let mut other = prs(1..=3, "2027-01");
        other["repository"] = json!("o/other");
        repos.push(bundle("change-management", p("2027-01-01", "2027-02-01"), "2027-02-01T03:00:00Z", "pull-requests.json", &other));
        let both = population(&TESTS[0], &repos, &p("2027-01-01", "2027-02-01"));
        assert_eq!(both.items.len(), 43, "another repository's #1 to #3 are other pull requests");
        assert!(both.items.contains_key("o/other#1") && both.items.contains_key("1"));

        let prs = population(&TESTS[0], &st, &p("2027-01-15", "2027-02-15"));
        assert!(prs.items.values().all(|i| i.fields["mergedAt"].as_str().unwrap() >= "2027-01-15" && i.fields["mergedAt"].as_str().unwrap() < "2027-02-15"));
        assert_eq!(prs.items["20"].fields["checks.allRequiredPassed"], true);
        assert!(prs.items["20"].fields.get("title").is_none());
    }

    #[test]
    fn a_changed_bundle_is_left_out_and_makes_its_populations_incomplete() {
        let mut st = store();
        let (f, files) = &mut st[1];
        files.insert("pull-requests.json".into(), json_file(&prs(41..=99, "2027-02")));
        *f = coverage::check(f.path.clone(), &f.name.clone(), files);
        assert!(!f.verified());
        let pop = population(&TESTS[0], &st, &p("2027-01-01", "2027-03-01"));
        assert_eq!(pop.items.len(), 40, "January's only");
        assert_eq!(pop.failed, vec![st[1].0.path.clone()]);
        assert_eq!(pop.missing.len(), 1);

        let january = population(&TESTS[0], &st, &p("2027-01-01", "2027-02-01"));
        assert!(january.failed.is_empty() && january.missing.is_empty(), "February's failed pull requests can't be January's");

        let unread = json!({ "repository": "o/r", "sources": { "dependabot": { "available": false, "status": 403 }, "codeScanning": { "available": true } }, "alerts": [] });
        st.push(bundle("vulnerability-management", p("2027-01-01", "2027-02-01"), "2027-02-01T03:00:00Z", "vulnerability-alerts.json", &unread));
        let alerts = population(&TESTS[6], &st, &p("2027-01-01", "2027-02-01"));
        assert!(alerts.missing.is_empty() && alerts.items.is_empty());
        assert!(!alerts.complete(), "no alerts because GitHub refused Dependabot's isn't none");
        assert_eq!(alerts.unread, vec![format!("{}: dependabot", st.last().unwrap().0.path)]);

        st.push((Found { path: "renamed.tar".into(), name: "renamed".into(), problems: vec!["it can't be read as a tar".into()], ..Found::default() }, Files::new()));
        for t in &TESTS {
            assert!(population(t, &st, &p("2027-01-01", "2027-02-01")).failed.contains(&"renamed.tar".to_string()), "{}: a damaged tar could be of any kind", t.id);
        }
    }

    #[test]
    fn the_draw_is_reproducible_from_the_store_or_a_given_seed() {
        let st = store();
        let period = p("2027-01-01", "2027-03-01");
        let one = draw(&st, &Draw { period, seed: None, sizes: BTreeMap::new() });
        let two = draw(&st, &Draw { period, seed: None, sizes: BTreeMap::new() });
        assert_eq!(one.samples, two.samples);
        assert_eq!(one.worksheet, two.worksheet);
        assert_eq!(one.samples["seedFrom"], "store");

        let prs = test(&one.samples, "merged-pull-requests");
        assert_eq!((prs["population"]["size"].as_u64(), prs["sampleSize"].as_u64(), prs["sizeFrom"].as_str()), (Some(70), Some(25), Some("table")));
        let seed = one.samples["seed"].as_str().unwrap();
        let sample: Vec<&Value> = prs["sample"].as_array().unwrap().iter().collect();
        let mut ranks: Vec<String> = (1..=70).map(|n| rank(seed, "merged-pull-requests", &n.to_string())).collect();
        ranks.sort();
        assert_eq!(sample.iter().map(|s| s["rank"].as_str().unwrap().to_string()).collect::<Vec<_>>(), ranks[..25].to_vec(), "the 25 lowest ranks, re-performed");
        let ids: BTreeSet<String> = (1..=70).map(|n| n.to_string()).collect();
        assert_eq!(prs["population"]["sha256"].as_str().unwrap(), population_sha256(&ids));

        let given = draw(&st, &Draw { period, seed: Some("auditor-2027".into()), sizes: BTreeMap::from([("merged-pull-requests".to_string(), 40), ("pages".to_string(), 9)]) });
        let g = test(&given.samples, "merged-pull-requests");
        assert_eq!((given.samples["seedFrom"].as_str(), g["sampleSize"].as_u64(), g["sizeFrom"].as_str()), (Some("given"), Some(40), Some("--size")));
        assert_eq!(test(&given.samples, "pages")["sampleSize"], 1, "never more than the population");
        assert_ne!(g["sample"].as_array().unwrap()[..25], prs["sample"].as_array().unwrap()[..], "another seed, another sample");

        let mut more = store();
        more.push(bundle("policy-register", p("2027-01-01", "2027-02-01"), "2027-02-03T09:00:00Z", "access.json", &json!({ "grants": [{ "person": "p-c", "system": "hosting", "level": "admin", "granted": "2027-01-05", "approvers": [{ "id": "p-b" }] }], "reviews": [] })));
        let changed = draw(&more, &Draw { period, seed: None, sizes: BTreeMap::new() });
        assert_ne!(changed.samples["seed"], one.samples["seed"], "a different store, a different seed");
        let grants = test(&changed.samples, "access-grants");
        assert_eq!(grants["sample"][0]["item"], "p-c/hosting/admin/2027-01-05");
    }

    #[test]
    fn the_worksheet_lists_every_item_drawn_and_says_which_populations_fall_short() {
        let st = store();
        let s = draw(&st, &Draw { period: p("2027-01-01", "2027-03-01"), seed: Some("s".into()), sizes: BTreeMap::new() });
        let rows = parse_csv(&s.worksheet).unwrap();
        assert_eq!(rows[0], COLUMNS.iter().map(|c| c.to_string()).collect::<Vec<_>>());
        assert_eq!(rows.len() - 1, s.samples["summary"]["itemsSampled"].as_u64().unwrap() as usize);
        assert!(rows[1..].iter().all(|r| r.len() == COLUMNS.len() && r[5..].iter().all(String::is_empty)));
        let incomplete = s.samples["summary"]["populationsIncomplete"].as_array().unwrap();
        assert!(incomplete.contains(&json!("pages")) && incomplete.contains(&json!("backup-days")) && !incomplete.contains(&json!("merged-pull-requests")), "{incomplete:?}");
        assert!(s.samples["summary"]["populationsEmpty"].as_array().unwrap().contains(&json!("security-events")));
        let text = serde_json::to_string(&s.samples).unwrap();
        assert!(!text.contains("never copied"));
    }

    #[test]
    fn csv_cells_quote_and_unquote() {
        let rows = parse_csv("a,\"b, c\",\"say \"\"hi\"\"\"\r\nx,,\"multi\nline\"\n\n").unwrap();
        assert_eq!(rows, vec![vec!["a", "b, c", "say \"hi\""], vec!["x", "", "multi\nline"]]);
        assert!(parse_csv("a,\"b").is_err());
        assert!(parse_csv("a,b\"c\n").is_err());
        assert_eq!(worksheet_cell("plain"), "plain");
        assert_eq!(worksheet_cell("a, \"b\""), "\"a, \"\"b\"\"\"");
    }

    #[test]
    fn results_count_deviations_and_refuse_a_worksheet_that_doesnt_hold_together() {
        let st = store();
        let s = draw(&st, &Draw { period: p("2027-01-01", "2027-03-01"), seed: Some("s".into()), sizes: BTreeMap::from([("merged-pull-requests".to_string(), 3)]) });
        let prs = test(&s.samples, "merged-pull-requests");
        let item = |i: usize| prs["sample"][i]["item"].as_str().unwrap().to_string();
        let sampled: BTreeSet<(String, String)> = s.samples["tests"].as_array().unwrap().iter().flat_map(|t| t["sample"].as_array().unwrap().iter().map(|x| (t["id"].as_str().unwrap().to_string(), x["item"].as_str().unwrap().to_string()))).collect();
        let today = d("2027-03-20");
        let sheet = format!(
            "test,item,result,tester,tested_on,reference,notes\nmerged-pull-requests,{},pass,p-e,2027-03-10,https://github.com/o/r/pull/{},\"looked, fine\"\nmerged-pull-requests,{},FAIL,p-e,2027-03-01,,approval after merge\nmerged-pull-requests,{},n/a,p-f,2027-03-10,,\n",
            item(0),
            item(0),
            item(1),
            item(2)
        );
        let lines = read_worksheet(&sheet, &sampled, today).unwrap();
        assert_eq!(lines[1].result.as_deref(), Some("fail"));
        let r = results(&s.samples, &lines, Some(d("2027-03-05")));
        let t = r["tests"].as_array().unwrap().iter().find(|t| t["id"] == "merged-pull-requests").unwrap();
        assert_eq!((t["sampled"].as_u64(), t["tested"].as_u64(), t["passed"].as_u64(), t["deviations"].as_u64(), t["notApplicable"].as_u64()), (Some(3), Some(3), Some(1), Some(1), Some(1)));
        assert_eq!(t["conclusion"], "1 deviation in 3 of 3 items tested");
        assert_eq!(r["exceptions"]["deviations"], json!([format!("merged-pull-requests {}", item(1))]));
        assert_eq!(r["exceptions"]["deviationsWithoutReference"], r["exceptions"]["deviations"]);
        assert_eq!(r["exceptions"]["testedBeforeDrawn"].as_array().unwrap().len(), 1);
        assert_eq!(r["summary"]["testers"], 2);
        let others = s.samples["summary"]["itemsSampled"].as_u64().unwrap() - 3;
        assert_eq!(r["summary"]["untested"].as_u64(), Some(others), "every other item drawn, not on the sheet");
        assert!(!serde_json::to_string(&r).unwrap().contains("looked, fine"), "notes stay on the worksheet");

        for (bad, why) in [
            ("test,item,result,tester,tested_on\nmerged-pull-requests,9999,pass,p-e,2027-03-10\n".to_string(), "wasn't drawn"),
            (format!("test,item,result,tester,tested_on\nmerged-pull-requests,{0},pass,p-e,2027-03-10\nmerged-pull-requests,{0},pass,p-e,2027-03-10\n", item(0)), "more than once"),
            (format!("test,item,result,tester,tested_on\nmerged-pull-requests,{},ok,p-e,2027-03-10\n", item(0)), "isn't pass, fail or n/a"),
            (format!("test,item,result,tester,tested_on\nmerged-pull-requests,{},pass,Erin Example,2027-03-10\n", item(0)), "register id"),
            (format!("test,item,result,tester,tested_on\nmerged-pull-requests,{},pass,p-e,2027-04-01\n", item(0)), "in the future"),
            (format!("test,item,result,tester,tested_on\nmerged-pull-requests,{},pass,p-e,\n", item(0)), "tested_on"),
            (format!("test,item,result,tester,tested_on,reference\nmerged-pull-requests,{},pass,p-e,2027-03-10,see the ticket\n", item(0)), "reference"),
            ("test,item,result\n".to_string(), "no tester, tested_on column"),
            (format!("test,item,result,tester,tested_on,Result\nmerged-pull-requests,{},pass,p-e,2027-03-10,fail\n", item(0)), "more than one result column"),
        ] {
            let e = read_worksheet(&bad, &sampled, today).unwrap_err();
            assert!(e.contains(why), "{why}: {e}");
        }
    }

    #[test]
    fn the_tests_read_files_their_kinds_have() {
        for t in &TESTS {
            assert!(coverage::expected(t.kind).iter().any(|(f, _, _)| *f == t.file), "{} reads {} from {}", t.id, t.file, t.kind);
            assert!(t.rows.iter().all(|r| t.criteria.iter().any(|c| r.starts_with(&format!("{c}-")))), "{}", t.id);
            assert_eq!(t.list.is_empty(), t.key.is_empty(), "{}", t.id);
        }
        assert_eq!(TESTS.iter().map(|t| t.id).collect::<BTreeSet<_>>().len(), TESTS.len());
    }

    /// The evidence plan's table of tests matches these.
    #[test]
    fn the_evidence_plans_table_matches_the_tests() {
        let plan = include_str!("../../../../docs/security/soc2-evidence-plan.md");
        let section = plan.split("## Testing samples").nth(1).expect("a Testing samples section").split("\n## ").next().unwrap();
        let rows: Vec<Vec<String>> = section.lines().filter(|l| l.starts_with("| `")).map(|l| l.split('|').map(|c| c.trim().to_string()).collect()).collect();
        assert_eq!(rows.len(), TESTS.len(), "one row per test");
        for (row, t) in rows.iter().zip(&TESTS) {
            assert_eq!(row[1], format!("`{}`", t.id));
            assert!(row[2].contains(&format!("`{}`", t.file)), "{}: {}", t.id, row[2]);
            assert_eq!(row[4], t.rows.join(", "), "{}", t.id);
        }
    }
}
