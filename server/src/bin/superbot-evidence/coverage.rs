//! `superbot-evidence coverage` (ADR 0169): checks an evidence store against an
//! observation period. Every bundle in it (botd's evidence bundles, ADR 0142; the
//! change-management bundles, ADR 0148; the vulnerability bundles, ADR 0086; the restore
//! drill bundles, ADR 0177; the policy register bundles, ADR 0204) is checked
//! against its own `SHA256SUMS` and manifest, and the report says which days of the period
//! each kind of bundle, each readiness checklist row and each criterion has evidence for,
//! and where the gaps are. Reads local files only: no token, no network, nothing written
//! into the store.

use crate::changes::{self, json_file, rfc3339, sha256};
use crate::drills;
use crate::period::Period;
use crate::register;
use crate::vulns;
use chrono::{Datelike, NaiveDate};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

/// Bumped when the report's shape changes.
pub const FORMAT: u32 = 1;

/// A file a kind of bundle always has, and the controls its manifest maps it to.
pub struct Expected {
    pub file: &'static str,
    pub criteria: &'static [&'static str],
    pub rows: &'static [&'static str],
}

/// botd's evidence bundle (ADR 0142). botd's `evidence::SECTIONS` isn't reachable from
/// this binary; a test checks this against the evidence plan's table, as botd's does.
pub const EVIDENCE: [Expected; 6] = [
    Expected { file: "access-review.json", criteria: &["CC1.3", "CC6.1", "CC6.2", "CC6.3"], rows: &["CC6.1-1", "CC6.2-1", "CC6.3-1", "CC6.3-2"] },
    Expected { file: "changes.json", criteria: &["CC5.1", "CC5.2", "CC8.1"], rows: &["CC5.1-1", "CC8.1-2"] },
    Expected { file: "backups.json", criteria: &["A1.2", "A1.3", "CC6.7", "CC7.5", "CC9.1"], rows: &["A1.2-1", "A1.2-2", "CC6.7-2"] },
    Expected { file: "retention.json", criteria: &["C1.2", "CC6.5"], rows: &["C1.2-1", "CC6.5-1", "CC6.5-2"] },
    Expected { file: "sign-ins-and-alerts.json", criteria: &["CC6.1", "CC6.6", "CC7.2"], rows: &["CC6.1-1", "CC7.2-1"] },
    Expected { file: "audit-summary.json", criteria: &["CC2.1", "CC4.1", "CC7.2"], rows: &[] },
];

/// Files of botd's bundle that bundles made before them lack (ADR 0195): checked like
/// the rest when listed, never required, so only the test against the evidence plan
/// reads this.
#[cfg(test)]
pub const EVIDENCE_LATER: [Expected; 1] = [Expected { file: "baseline.json", criteria: &["CC5.1"], rows: &["CC5.1-1"] }];

/// One kind of bundle the evidence plan collects monthly.
#[derive(Debug)]
pub struct Kind {
    pub id: &'static str,
    pub prefix: &'static str,
    /// The manifest's `kind`; botd's manifest has none.
    pub manifest_kind: Option<&'static str>,
    /// The newest manifest format this tool knows.
    pub format: u64,
    pub title: &'static str,
    pub made_by: &'static str,
}

pub const KINDS: [Kind; 5] = [
    Kind { id: "evidence", prefix: "superbot-evidence-", manifest_kind: None, format: 2, title: "Evidence bundle", made_by: "botd (EVIDENCE_BUNDLES=monthly, or botctl evidence bundle)" },
    Kind {
        id: "change-management",
        prefix: changes::PREFIX,
        manifest_kind: Some("change-management"),
        format: changes::FORMAT as u64,
        title: "Change-management bundle",
        made_by: "superbot-evidence github (the change-evidence workflow)",
    },
    Kind {
        id: "vulnerability-management",
        prefix: vulns::PREFIX,
        manifest_kind: Some("vulnerability-management"),
        format: vulns::FORMAT as u64,
        title: "Vulnerability bundle",
        made_by: "superbot-evidence vulnerabilities (the change-evidence workflow)",
    },
    Kind {
        id: "recovery-drills",
        prefix: drills::PREFIX,
        manifest_kind: Some("recovery-drills"),
        format: drills::FORMAT as u64,
        title: "Drill bundle",
        made_by: "superbot-evidence drills (the change-evidence workflow, with the operator's drill records)",
    },
    Kind {
        id: "policy-register",
        prefix: register::PREFIX,
        manifest_kind: Some("policy-register"),
        format: register::FORMAT as u64,
        title: "Register bundle",
        made_by: "superbot-evidence register (from the security owner's private policy register)",
    },
];

/// Each file a kind always has, with its criteria and rows.
pub fn expected(kind: &str) -> Vec<(&'static str, &'static [&'static str], &'static [&'static str])> {
    match kind {
        "evidence" => EVIDENCE.iter().map(|e| (e.file, e.criteria, e.rows)).collect(),
        "change-management" => changes::SECTIONS.iter().map(|s| (s.file, s.criteria, s.rows)).collect(),
        "vulnerability-management" => vulns::SECTIONS.iter().map(|s| (s.file, s.criteria, s.rows)).collect(),
        "recovery-drills" => drills::SECTIONS.iter().map(|s| (s.file, s.criteria, s.rows)).collect(),
        "policy-register" => register::SECTIONS.iter().map(|s| (s.file, s.criteria, s.rows)).collect(),
        _ => Vec::new(),
    }
}

/// The manifest format from which a kind's bundles have a file; older bundles needn't.
fn since_format(kind: &str, file: &str) -> u64 {
    match kind {
        "policy-register" => register::SINCE_FORMAT.iter().find(|(f, _)| *f == file).map_or(1, |(_, n)| *n),
        _ => 1,
    }
}

/// The files whose `exceptions` an auditor samples first.
const EXCEPTION_FILES: [&str; 13] = [
    "pull-requests.json",
    "vulnerability-alerts.json",
    "ci-drills.json",
    "operator-drills.json",
    "baseline.json",
    "roles.json",
    "policies.json",
    "people.json",
    "risks.json",
    "management-reviews.json",
    "vendors.json",
    "policy-exceptions.json",
    "conduct.json",
];

/// A bundle file larger than this isn't read: no bundle comes near it.
const MAX_TAR: u64 = 256 << 20;

/// How deep the store is searched; the plan's layout is `<criterion>/<month>/`.
const MAX_DEPTH: usize = 8;

/// A bundle made this many days after its period ends has snapshots of then, not of it.
const LATE_DAYS: i64 = 7;

// Reading tars

/// The plain files in a tar, by name. Reads the ustar our bundles are written in, and
/// what GNU and BSD tar write when a bundle is unpacked and packed again (directory
/// entries, `./` names, long names). Anything else that isn't a plain file is refused.
pub fn untar(b: &[u8]) -> Result<Vec<(String, Vec<u8>)>, String> {
    fn text(f: &[u8]) -> String {
        let end = f.iter().position(|&c| c == 0).unwrap_or(f.len());
        String::from_utf8_lossy(&f[..end]).into_owned()
    }
    fn octal(f: &[u8]) -> Option<u64> {
        let s = text(f);
        let s = s.trim_matches(|c: char| c == ' ' || c == '\0');
        if s.is_empty() { Some(0) } else { u64::from_str_radix(s, 8).ok() }
    }
    let mut out = Vec::new();
    let (mut i, mut long): (usize, Option<String>) = (0, None);
    while i + 512 <= b.len() {
        let h = &b[i..i + 512];
        if h.iter().all(|&c| c == 0) {
            return Ok(out);
        }
        let sum: u64 = h.iter().enumerate().map(|(j, &c)| if (148..156).contains(&j) { 32 } else { u64::from(c) }).sum();
        if octal(&h[148..156]) != Some(sum) {
            return Err(format!("a tar header at byte {i} is damaged"));
        }
        let size = octal(&h[124..136]).ok_or(format!("a tar header at byte {i} is damaged"))? as usize;
        let start = i + 512;
        let end = start.checked_add(size).filter(|&e| e <= b.len()).ok_or("the tar is cut short")?;
        let data = &b[start..end];
        let prefix = if &h[257..262] == b"ustar" { text(&h[345..500]) } else { String::new() };
        let name = long.take().unwrap_or_else(|| if prefix.is_empty() { text(&h[..100]) } else { format!("{prefix}/{}", text(&h[..100])) });
        match h[156] {
            b'0' | 0 | b'7' => out.push((name.trim_start_matches("./").to_string(), data.to_vec())),
            b'5' | b'g' => {}
            b'L' => long = Some(text(data)),
            b'x' => long = String::from_utf8_lossy(data).lines().find_map(|l| l.split_once(' ').and_then(|(_, kv)| kv.strip_prefix("path=")).map(String::from)),
            _ => return Err(format!("{name} isn't a plain file")),
        }
        i = start + size.div_ceil(512) * 512;
    }
    Err("the tar has no end".into())
}

// Checking one bundle

/// A bundle found in the store, and what checking it showed.
#[derive(Debug, Default)]
pub struct Found {
    /// Where it is, relative to the store.
    pub path: String,
    /// Its folder's name.
    pub name: String,
    pub kind: Option<&'static Kind>,
    pub period: Option<Period>,
    pub created: Option<String>,
    pub format: Option<u64>,
    pub manifest_sha256: Option<String>,
    /// Anything that means it can't be relied on: a digest that doesn't match, a file
    /// missing or not listed, a manifest that disagrees with its name.
    pub problems: Vec<String>,
    /// Worth knowing, but the bundle still counts.
    pub warnings: Vec<String>,
    /// Each file's criteria and checklist rows, from the manifest.
    pub files: Vec<(String, Vec<String>, Vec<String>)>,
    /// Each exception list's length, by file.
    pub exceptions: BTreeMap<String, BTreeMap<String, usize>>,
}

impl Found {
    pub fn verified(&self) -> bool {
        self.problems.is_empty() && self.kind.is_some() && self.period.is_some()
    }
}

/// The kind a bundle's folder name says it is.
pub fn kind_of(name: &str) -> Option<&'static Kind> {
    KINDS.iter().find(|k| name.starts_with(k.prefix))
}

/// The period a bundle's folder name says it covers: `<prefix><from>_<to>-<UTC time>`.
pub fn period_of(name: &str) -> Option<Period> {
    let rest = name.strip_prefix(kind_of(name)?.prefix)?;
    let day = |s: &str| NaiveDate::parse_from_str(s, "%Y-%m-%d").ok();
    let (from, to) = (day(rest.get(..10)?)?, day(rest.get(11..21)?)?);
    (rest.get(10..11)? == "_" && rest.get(21..22)? == "-" && to > from).then_some(Period { from, to })
}

fn strings(v: &Value) -> Vec<String> {
    v.as_array().map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect()).unwrap_or_default()
}

/// Checks one bundle's files (by name, inside its folder) against its `SHA256SUMS` and
/// manifest, and reads what it covers.
pub fn check(path: String, name: &str, files: &BTreeMap<String, Vec<u8>>) -> Found {
    let mut f = Found { path, name: name.to_string(), kind: kind_of(name), period: period_of(name), ..Found::default() };
    let Some(kind) = f.kind else {
        f.problems.push("its name isn't a bundle's".into());
        return f;
    };
    if f.period.is_none() {
        f.problems.push("its name doesn't say its period (<from>_<to>-<time>)".into());
    }
    let digests: BTreeMap<&str, String> = files.iter().map(|(n, b)| (n.as_str(), sha256(b))).collect();

    match files.get("SHA256SUMS").map(|b| String::from_utf8_lossy(b).into_owned()) {
        None => f.problems.push("it has no SHA256SUMS".into()),
        Some(sums) => {
            let mut listed = BTreeSet::new();
            for line in sums.lines().filter(|l| !l.trim().is_empty()) {
                let Some((digest, file)) = line.split_once("  ").or_else(|| line.split_once(" *")) else {
                    f.problems.push(format!("SHA256SUMS has a line that isn't <sha256>  <file>: {line:.80}"));
                    continue;
                };
                listed.insert(file.to_string());
                match digests.get(file) {
                    None => f.problems.push(format!("{file} is in SHA256SUMS but missing")),
                    Some(d) if !d.eq_ignore_ascii_case(digest.trim()) => f.problems.push(format!("{file} doesn't match its SHA-256 in SHA256SUMS: it changed after the bundle was made")),
                    Some(_) => {}
                }
            }
            for n in digests.keys().filter(|n| **n != "SHA256SUMS" && !listed.contains(**n)) {
                f.problems.push(format!("{n} isn't in SHA256SUMS: it was added after the bundle was made"));
            }
        }
    }

    let Some(bytes) = files.get("manifest.json") else {
        f.problems.push("it has no manifest.json".into());
        return f;
    };
    f.manifest_sha256 = Some(sha256(bytes));
    let Ok(m) = serde_json::from_slice::<Value>(bytes) else {
        f.problems.push("manifest.json isn't JSON".into());
        return f;
    };
    if m["product"] != "SuperBot" {
        f.problems.push("manifest.json isn't a SuperBot manifest".into());
    }
    if m["kind"].as_str() != kind.manifest_kind {
        f.problems.push(format!("manifest.json's kind ({}) isn't what its name says ({})", m["kind"].as_str().unwrap_or("none"), kind.manifest_kind.unwrap_or("none")));
    }
    f.format = m["format"].as_u64();
    match f.format {
        None => f.problems.push("manifest.json has no format".into()),
        Some(0) => f.problems.push("manifest.json's format (0) isn't one any superbot-evidence made".into()),
        Some(n) if n > kind.format => f.warnings.push(format!("its format ({n}) is newer than this tool knows ({}); use a newer superbot-evidence", kind.format)),
        Some(_) => {}
    }
    if let Some(p) = f.period {
        if m["period"]["from"].as_str() != Some(&p.from.to_string()) || m["period"]["to"].as_str() != Some(&p.to.to_string()) {
            f.problems.push(format!("manifest.json's period ({} to {}) isn't the one its name says ({} to {})", m["period"]["from"].as_str().unwrap_or("?"), m["period"]["to"].as_str().unwrap_or("?"), p.from, p.to));
        }
        f.created = m["createdAt"].as_str().map(String::from);
        match f.created.as_deref().and_then(|c| chrono::DateTime::parse_from_rfc3339(c).ok()) {
            None => f.problems.push("manifest.json doesn't say when it was made".into()),
            Some(at) => {
                let at = at.with_timezone(&chrono::Utc);
                if at.timestamp_millis() < p.end_ms() {
                    f.warnings.push("it was made before its period ended, so its last events may be missing".into());
                } else if (at.date_naive() - p.to).num_days() > LATE_DAYS {
                    f.warnings.push(format!("it was made {} days after its period, so its snapshots are of then, not of the period", (at.date_naive() - p.to).num_days()));
                }
            }
        }
    }

    let mut in_manifest = BTreeSet::new();
    for e in m["files"].as_array().into_iter().flatten() {
        let Some(n) = e["name"].as_str() else {
            f.problems.push("manifest.json lists a file without a name".into());
            continue;
        };
        in_manifest.insert(n.to_string());
        match digests.get(n) {
            None => f.problems.push(format!("{n} is in manifest.json but missing")),
            Some(d) if e["sha256"].as_str().is_none_or(|s| !d.eq_ignore_ascii_case(s)) => f.problems.push(format!("{n} doesn't match its SHA-256 in manifest.json")),
            Some(_) => {}
        }
        f.files.push((n.to_string(), strings(&e["criteria"]), strings(&e["checklist"])));
    }
    for n in digests.keys().filter(|n| !matches!(**n, "manifest.json" | "SHA256SUMS") && !in_manifest.contains(**n)) {
        f.problems.push(format!("{n} isn't in manifest.json"));
    }
    for (file, _, _) in expected(kind.id) {
        if !in_manifest.contains(file) && f.format.is_some_and(|n| n >= since_format(kind.id, file)) {
            f.problems.push(format!("it has no {file}, which every {} has", kind.title.to_lowercase()));
        }
    }

    for file in EXCEPTION_FILES {
        let Some(v) = files.get(file).and_then(|b| serde_json::from_slice::<Value>(b).ok()) else { continue };
        let counts: BTreeMap<String, usize> = v["exceptions"].as_object().into_iter().flatten().filter_map(|(k, x)| x.as_array().map(|a| (k.clone(), a.len()))).collect();
        if !counts.is_empty() {
            f.exceptions.insert(file.to_string(), counts);
        }
    }
    f
}

/// One bundle's files from its folder name and the tar's entries; `None` when the tar
/// isn't a bundle at all.
fn from_entries(path: String, entries: Vec<(String, Vec<u8>)>) -> Option<Found> {
    let tops: BTreeSet<&str> = entries.iter().map(|(n, _)| n.split('/').next().unwrap_or_default()).collect();
    let bundles: Vec<&str> = tops.iter().copied().filter(|t| kind_of(t).is_some()).collect();
    match bundles.as_slice() {
        [] => None,
        [top] if tops.len() == 1 => {
            let mut files = BTreeMap::new();
            let (mut nested, mut repeated) = (Vec::new(), BTreeSet::new());
            for (n, b) in &entries {
                match n.strip_prefix(&format!("{top}/")) {
                    Some(file) if !file.is_empty() && !file.contains('/') => {
                        // `tar -x` keeps the last copy, so an earlier one is never checked.
                        if files.insert(file.to_string(), b.clone()).is_some() {
                            repeated.insert(file.to_string());
                        }
                    }
                    Some("") => {}
                    _ => nested.push(n.clone()),
                }
            }
            let mut f = check(path, top, &files);
            f.problems.extend(nested.into_iter().map(|n| format!("{n} isn't a file of the bundle's folder")));
            f.problems.extend(repeated.into_iter().map(|n| format!("{n} is in the tar more than once, so not every copy can be checked")));
            Some(f)
        }
        _ => Some(Found { path, name: bundles.join(", "), problems: vec!["the tar holds more than one folder; keep one bundle per tar, as made".into()], ..Found::default() }),
    }
}

/// Every bundle in the store, as a `.tar` (as made) or unpacked into its folder, and the
/// other files that were passed over. Hidden files (botd's partial writes) are skipped.
pub fn scan(store: &Path) -> Result<(Vec<Found>, Vec<String>), String> {
    fn rel(store: &Path, p: &Path) -> String {
        p.strip_prefix(store).unwrap_or(p).to_string_lossy().into_owned()
    }
    fn walk(store: &Path, dir: &Path, depth: usize, found: &mut Vec<Found>, other: &mut Vec<String>) -> Result<(), String> {
        let mut entries: Vec<_> = std::fs::read_dir(dir).map_err(|e| format!("{}: {e}", dir.display()))?.filter_map(Result::ok).collect();
        entries.sort_by_key(|e| e.file_name());
        for e in entries {
            let (p, name) = (e.path(), e.file_name().to_string_lossy().into_owned());
            let Ok(meta) = std::fs::metadata(&p) else { continue };
            if name.starts_with('.') {
                continue;
            }
            if meta.is_dir() {
                // Named as a bundle is enough: one that lost its manifest and sums must still fail.
                if kind_of(&name).is_some() {
                    found.push(folder(rel(store, &p), &name, &p));
                } else if depth < MAX_DEPTH {
                    walk(store, &p, depth + 1, found, other)?;
                }
            } else if name.ends_with(".tar") {
                if meta.len() > MAX_TAR {
                    found.push(Found { path: rel(store, &p), name, problems: vec![format!("it is over {} MiB, larger than any bundle", MAX_TAR >> 20)], ..Found::default() });
                    continue;
                }
                let read = std::fs::read(&p).map_err(|e| e.to_string()).and_then(|b| untar(&b));
                match read {
                    Ok(entries) => match from_entries(rel(store, &p), entries) {
                        Some(f) => found.push(f),
                        None => other.push(rel(store, &p)),
                    },
                    // Bundles are renamed in stores, so a damaged tar may be one whatever its name.
                    Err(why) => found.push(Found { path: rel(store, &p), name: name.trim_end_matches(".tar").into(), problems: vec![format!("it can't be read as a tar, so it can't be checked: {why}")], ..Found::default() }),
                }
            } else {
                other.push(rel(store, &p));
            }
        }
        Ok(())
    }
    fn folder(path: String, name: &str, dir: &Path) -> Found {
        let mut files = BTreeMap::new();
        let mut odd = Vec::new();
        for e in std::fs::read_dir(dir).into_iter().flatten().filter_map(Result::ok) {
            let n = e.file_name().to_string_lossy().into_owned();
            match std::fs::metadata(e.path()) {
                Ok(m) if m.is_file() && m.len() <= MAX_TAR => match std::fs::read(e.path()) {
                    Ok(b) => {
                        files.insert(n, b);
                    }
                    Err(why) => odd.push(format!("{n} can't be read: {why}")),
                },
                _ => odd.push(format!("{n} isn't a file of the bundle")),
            }
        }
        let mut f = check(path, name, &files);
        f.problems.extend(odd);
        f
    }
    if !store.is_dir() {
        return Err(format!("{} isn't a folder", store.display()));
    }
    let (mut found, mut other) = (Vec::new(), Vec::new());
    walk(store, store, 0, &mut found, &mut other)?;
    Ok((found, other))
}

// The report

fn days(p: &Period) -> Vec<NaiveDate> {
    p.from.iter_days().take_while(|d| *d < p.to).collect()
}

/// The runs of days in `p` not in `covered`, each as `[from, to)`.
pub fn gaps(p: &Period, covered: &BTreeSet<NaiveDate>) -> Vec<Value> {
    let mut out = Vec::new();
    let mut start: Option<NaiveDate> = None;
    for d in days(p) {
        match (covered.contains(&d), start) {
            (false, None) => start = Some(d),
            (true, Some(s)) => {
                out.push(json!({ "from": s.to_string(), "to": d.to_string(), "days": (d - s).num_days() }));
                start = None;
            }
            _ => {}
        }
    }
    if let Some(s) = start {
        out.push(json!({ "from": s.to_string(), "to": p.to.to_string(), "days": (p.to - s).num_days() }));
    }
    out
}

fn span(b: &Period, p: &Period) -> impl Iterator<Item = NaiveDate> {
    let (from, to) = (b.from.max(p.from), b.to.min(p.to));
    from.iter_days().take_while(move |d| *d < to)
}

fn months(p: &Period) -> Vec<(String, Period)> {
    let mut out = Vec::new();
    let mut m = p.from.with_day(1).unwrap_or(p.from);
    while m < p.to {
        let next = if m.month() == 12 { NaiveDate::from_ymd_opt(m.year() + 1, 1, 1) } else { NaiveDate::from_ymd_opt(m.year(), m.month() + 1, 1) }.unwrap_or(p.to);
        out.push((m.format("%Y-%m").to_string(), Period { from: m.max(p.from), to: next.min(p.to) }));
        m = next;
    }
    out
}

fn coverage(p: &Period, covered: &BTreeSet<NaiveDate>) -> Value {
    let n = days(p).iter().filter(|d| covered.contains(d)).count();
    json!({ "coveredDays": n, "days": p.days(), "complete": n as i64 == p.days(), "gaps": gaps(p, covered) })
}

/// The readiness checklist's rows and their statuses, from its Markdown.
pub fn checklist_rows(md: &str) -> BTreeMap<String, String> {
    md.lines()
        .filter_map(|l| {
            let cells: Vec<&str> = l.split('|').map(str::trim).collect();
            let id = *cells.get(1)?;
            let (crit, n) = id.split_once('-')?;
            let ok = crit.contains('.') && crit.starts_with(|c: char| c.is_ascii_uppercase()) && !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit());
            ok.then(|| (id.to_string(), cells.get(6).map(|s| s.to_string()).unwrap_or_default()))
        })
        .collect()
}

/// The coverage report for `p` from what was found in the store.
pub fn report(found: &[Found], other: &[String], p: &Period, checklist: Option<&str>, now_ms: i64) -> Value {
    let used: Vec<&Found> = found.iter().filter(|f| f.verified() && f.period.is_some_and(|b| b.from < p.to && b.to > p.from)).collect();
    let mut problems: Vec<String> = found.iter().filter(|f| !f.verified()).flat_map(|f| f.problems.iter().map(move |x| format!("{}: {x}", f.path))).collect();

    let mut kinds = Vec::new();
    for k in &KINDS {
        let mut covered = BTreeSet::new();
        for f in used.iter().filter(|f| f.kind.is_some_and(|x| x.id == k.id)) {
            covered.extend(span(&f.period.expect("verified"), p));
        }
        let c = coverage(p, &covered);
        for g in c["gaps"].as_array().into_iter().flatten() {
            problems.push(format!("No verified {} covers {} to {} ({} days)", k.title.to_lowercase(), g["from"].as_str().unwrap_or_default(), g["to"].as_str().unwrap_or_default(), g["days"]));
        }
        let by_month: Vec<Value> = months(p)
            .iter()
            .map(|(m, mp)| {
                let n = days(mp).iter().filter(|d| covered.contains(d)).count() as i64;
                json!({ "month": m, "status": if n == mp.days() { "complete" } else if n == 0 { "missing" } else { "partial" } })
            })
            .collect();
        let mut v = json!({ "kind": k.id, "title": k.title, "madeBy": k.made_by, "bundles": used.iter().filter(|f| f.kind.is_some_and(|x| x.id == k.id)).count(), "months": by_month });
        v.as_object_mut().expect("an object").extend(c.as_object().cloned().unwrap_or_default());
        kinds.push(v);
    }

    // Rows and criteria: those every kind is expected to cover, and any a manifest names.
    let mut rows: BTreeMap<String, (BTreeSet<&str>, BTreeSet<NaiveDate>)> = BTreeMap::new();
    let mut criteria: BTreeMap<String, (BTreeSet<&str>, BTreeSet<NaiveDate>)> = BTreeMap::new();
    for k in &KINDS {
        for (_, cs, rs) in expected(k.id) {
            rs.iter().for_each(|r| _ = rows.entry(r.to_string()).or_default().0.insert(k.id));
            cs.iter().for_each(|c| _ = criteria.entry(c.to_string()).or_default().0.insert(k.id));
        }
    }
    for f in &used {
        let (kind, period) = (f.kind.expect("verified").id, f.period.expect("verified"));
        for (_, cs, rs) in &f.files {
            for r in rs {
                let e = rows.entry(r.clone()).or_default();
                e.0.insert(kind);
                e.1.extend(span(&period, p));
            }
            for c in cs {
                let e = criteria.entry(c.clone()).or_default();
                e.0.insert(kind);
                e.1.extend(span(&period, p));
            }
        }
    }
    let view = |m: &BTreeMap<String, (BTreeSet<&str>, BTreeSet<NaiveDate>)>, key: &str| -> Vec<Value> {
        m.iter()
            .map(|(id, (from, covered))| {
                let mut v = json!({ key: id, "from": from });
                v.as_object_mut().expect("an object").extend(coverage(p, covered).as_object().cloned().unwrap_or_default());
                v
            })
            .collect()
    };
    let rows_view: Vec<Value> = view(&rows, "row")
        .into_iter()
        .map(|mut v| {
            let crit = v["row"].as_str().and_then(|r| r.split_once('-')).map(|(c, _)| c.to_string());
            v["criterion"] = json!(crit);
            v
        })
        .collect();

    let mut warnings: Vec<String> = found.iter().filter(|f| f.verified()).flat_map(|f| f.warnings.iter().map(move |x| format!("{}: {x}", f.path))).collect();
    let checklist_view = checklist.map(|md| {
        let all = checklist_rows(md);
        for r in rows.keys().filter(|r| !all.contains_key(*r)) {
            warnings.push(format!("{r} is named by a bundle but isn't a row of this checklist"));
        }
        let manual: Vec<Value> = all.iter().filter(|(id, _)| !rows.contains_key(*id)).map(|(id, status)| json!({ "row": id, "status": status })).collect();
        json!({ "rows": all.len(), "withAutomatedEvidence": all.keys().filter(|r| rows.contains_key(*r)).count(), "noAutomatedEvidence": manual })
    });

    let bundles: Vec<Value> = found
        .iter()
        .map(|f| {
            json!({
                "path": f.path, "name": f.name, "kind": f.kind.map(|k| k.id),
                "period": f.period.map(|b| json!({ "from": b.from.to_string(), "to": b.to.to_string() })),
                "createdAt": f.created, "format": f.format, "manifestSha256": f.manifest_sha256,
                "verified": f.verified(), "inPeriod": f.period.is_some_and(|b| b.from < p.to && b.to > p.from),
                "problems": f.problems, "warnings": f.warnings, "exceptions": f.exceptions,
            })
        })
        .collect();
    let exceptions: usize = used.iter().flat_map(|f| f.exceptions.values().flat_map(|m| m.values())).sum();
    json!({
        "product": "SuperBot",
        "kind": "evidence-coverage",
        "format": FORMAT,
        "tool": concat!("superbot-evidence ", env!("CARGO_PKG_VERSION")),
        "createdAt": rfc3339(now_ms),
        "period": { "from": p.from.to_string(), "to": p.to.to_string(), "days": p.days() },
        "basis": "a day counts for a kind of bundle, a checklist row or a criterion when a bundle whose SHA256SUMS and manifest check covers it and its manifest names that row or criterion; this shows evidence was collected and not changed since, not that the controls worked",
        "complete": problems.is_empty(),
        "summary": {
            "bundles": found.len(),
            "verified": found.iter().filter(|f| f.verified()).count(),
            "failed": found.iter().filter(|f| !f.verified()).count(),
            "inPeriod": used.len(),
            "otherFiles": other.len(),
            "kindsComplete": kinds.iter().filter(|k| k["complete"] == true).count(),
            "rowsComplete": rows_view.iter().filter(|r| r["complete"] == true).count(),
            "rows": rows_view.len(),
            "exceptionsInBundles": exceptions,
        },
        "problems": problems,
        "warnings": warnings,
        "kinds": kinds,
        "rows": rows_view,
        "criteria": view(&criteria, "criterion"),
        "checklist": checklist_view,
        "bundles": bundles,
        "otherFiles": other,
    })
}

fn cell(s: &str) -> String {
    s.replace('|', "\\|").replace('\n', " ")
}

fn gap_text(v: &Value) -> String {
    let g: Vec<String> = v["gaps"].as_array().into_iter().flatten().map(|g| format!("{} to {}", g["from"].as_str().unwrap_or_default(), g["to"].as_str().unwrap_or_default())).collect();
    if g.is_empty() { "none".into() } else { g.join(", ") }
}

/// The report as Markdown, for the evidence store and the management review.
pub fn markdown(r: &Value) -> String {
    let s = &r["summary"];
    let mut o = format!(
        "# SOC 2 evidence coverage, {} to {} (not included)\n\nMade by {} at {} from the bundles in an evidence store ([ADR 0169](https://github.com/CG-Labs/superbot/blob/main/docs/adr/0169-evidence-coverage-report.md)). {} bundles found: {} check, {} don't, {} cover this period; {} other files passed over.\n\n",
        r["period"]["from"].as_str().unwrap_or_default(),
        r["period"]["to"].as_str().unwrap_or_default(),
        r["tool"].as_str().unwrap_or_default(),
        r["createdAt"].as_str().unwrap_or_default(),
        s["bundles"],
        s["verified"],
        s["failed"],
        s["inPeriod"],
        s["otherFiles"],
    );
    o += if r["complete"] == true {
        "**Complete:** every kind of bundle covers every day of the period, and every bundle found checks against its digests.\n\n".to_string()
    } else {
        format!("**Not complete:** {} problems, listed below.\n\n", r["problems"].as_array().map_or(0, Vec::len))
    }
    .as_str();
    o += "This shows evidence was collected for each day and not changed since. It doesn't show the controls worked: that is for the people reviewing the evidence, and the auditor.\n";
    let list = |o: &mut String, title: &str, key: &str| {
        if let Some(items) = r[key].as_array().filter(|a| !a.is_empty()) {
            *o += &format!("\n## {title}\n\n");
            for i in items {
                *o += &format!("- {}\n", i.as_str().unwrap_or_default());
            }
        }
    };
    list(&mut o, "Problems", "problems");
    list(&mut o, "Warnings", "warnings");

    o += "\n## Bundles by month\n\n| Month |";
    let kinds = r["kinds"].as_array().cloned().unwrap_or_default();
    for k in &kinds {
        o += &format!(" {} |", k["title"].as_str().unwrap_or_default());
    }
    o += "\n|---|";
    o += &"---|".repeat(kinds.len());
    o += "\n";
    let months: Vec<&str> = kinds.first().and_then(|k| k["months"].as_array()).into_iter().flatten().filter_map(|m| m["month"].as_str()).collect();
    for (i, m) in months.iter().enumerate() {
        o += &format!("| {m} |");
        for k in &kinds {
            o += &format!(" {} |", k["months"][i]["status"].as_str().unwrap_or_default());
        }
        o += "\n";
    }
    o += "\n| Kind | Made by | Bundles | Days covered | Gaps |\n|---|---|---|---|---|\n";
    for k in &kinds {
        o += &format!("| {} | {} | {} | {} of {} | {} |\n", k["title"].as_str().unwrap_or_default(), k["madeBy"].as_str().unwrap_or_default(), k["bundles"], k["coveredDays"], k["days"], gap_text(k));
    }

    o += "\n## Checklist rows\n\nEach [readiness checklist](https://github.com/CG-Labs/superbot/blob/main/docs/security/soc2-readiness-checklist.md) row a bundle collects evidence for.\n\n| Row | Bundles | Days covered | Gaps |\n|---|---|---|---|\n";
    for row in r["rows"].as_array().into_iter().flatten() {
        o += &format!("| {} | {} | {} of {} | {} |\n", row["row"].as_str().unwrap_or_default(), strings(&row["from"]).join(", "), row["coveredDays"], row["days"], gap_text(row));
    }
    o += "\n## Criteria\n\n| Criterion | Bundles | Days covered | Gaps |\n|---|---|---|---|\n";
    for c in r["criteria"].as_array().into_iter().flatten() {
        o += &format!("| {} | {} | {} of {} | {} |\n", c["criterion"].as_str().unwrap_or_default(), strings(&c["from"]).join(", "), c["coveredDays"], c["days"], gap_text(c));
    }
    if let Some(c) = r["checklist"].as_object() {
        o += &format!("\n## Rows with no automated evidence\n\n{} of the checklist's {} rows have evidence in a bundle. These have none: their evidence is records people keep, on the [evidence plan](https://github.com/CG-Labs/superbot/blob/main/docs/security/soc2-evidence-plan.md)'s calendar.\n\n| Row | Status |\n|---|---|\n", c["withAutomatedEvidence"], c["rows"]);
        for m in c["noAutomatedEvidence"].as_array().into_iter().flatten() {
            o += &format!("| {} | {} |\n", m["row"].as_str().unwrap_or_default(), cell(m["status"].as_str().unwrap_or_default()));
        }
    }

    o += "\n## Bundles\n\nCompare each manifest's SHA-256 with what was recorded when it was made: botd's `evidence.bundle_created` audit event, or the workflow run's summary.\n\n| Bundle | Period | Made | Manifest SHA-256 | Checks | Exceptions |\n|---|---|---|---|---|---|\n";
    for b in r["bundles"].as_array().into_iter().flatten() {
        let exceptions: Vec<String> = b["exceptions"].as_object().into_iter().flatten().flat_map(|(_, m)| m.as_object().into_iter().flatten().filter(|(_, n)| n.as_u64() > Some(0)).map(|(k, n)| format!("{k} {n}"))).collect();
        let checks = if b["verified"] == true { if b["inPeriod"] == true { "yes" } else { "yes, outside the period" } } else { "**no**" };
        o += &format!(
            "| {} | {} | {} | `{}` | {} | {} |\n",
            cell(b["path"].as_str().unwrap_or_default()),
            b["period"].as_object().map(|p| format!("{} to {}", p["from"].as_str().unwrap_or_default(), p["to"].as_str().unwrap_or_default())).unwrap_or_default(),
            b["createdAt"].as_str().unwrap_or_default(),
            b["manifestSha256"].as_str().unwrap_or("none"),
            checks,
            if exceptions.is_empty() { "none".into() } else { exceptions.join(", ") },
        );
    }
    o
}

// The command

pub const USAGE: &str = "  superbot-evidence coverage <evidence store> [--from <YYYY-MM-DD> --to <YYYY-MM-DD>]
                    [--checklist <soc2-readiness-checklist.md>] [--json] [-o <file>]";

struct Args {
    store: String,
    from: Option<String>,
    to: Option<String>,
    checklist: Option<String>,
    json: bool,
    out: Option<String>,
}

fn parse(args: &[String]) -> Result<Args, String> {
    let mut a = Args { store: String::new(), from: None, to: None, checklist: None, json: false, out: None };
    let mut it = args.iter();
    while let Some(flag) = it.next() {
        let slot = match flag.as_str() {
            "--json" => {
                a.json = true;
                continue;
            }
            "--from" => a.from.get_or_insert_with(String::new),
            "--to" => a.to.get_or_insert_with(String::new),
            "--checklist" => a.checklist.get_or_insert_with(String::new),
            "-o" | "--out" => a.out.get_or_insert_with(String::new),
            s if !s.starts_with('-') && a.store.is_empty() => {
                a.store = s.to_string();
                continue;
            }
            _ => return Err(format!("Unknown option {flag}.\n\n{USAGE}")),
        };
        if !slot.is_empty() {
            return Err(format!("{flag} is given twice"));
        }
        *slot = it.next().filter(|v| !v.starts_with("--") && !v.is_empty()).ok_or(format!("{flag} needs a value"))?.clone();
    }
    if a.store.is_empty() {
        return Err(format!("Give the evidence store's folder.\n\n{USAGE}"));
    }
    Ok(a)
}

/// The period to report on: the one given, or from the first verified bundle's start to
/// the last one's end.
fn period(a: &Args, found: &[Found], today: NaiveDate) -> Result<Period, String> {
    if a.from.is_some() || a.to.is_some() {
        return Period::parse(a.from.as_deref(), a.to.as_deref(), today);
    }
    let ps: Vec<Period> = found.iter().filter(|f| f.verified()).filter_map(|f| f.period).collect();
    let (Some(from), Some(to)) = (ps.iter().map(|p| p.from).min(), ps.iter().map(|p| p.to).max()) else {
        return Err("No bundle in the store checks, so there is no period to report on. Give --from and --to to see what is missing.".into());
    };
    Period::parse(Some(&from.to_string()), Some(&to.to_string()), today).map_err(|e| format!("The bundles span {from} to {to}: {e} Give --from and --to."))
}

/// Runs the command: the text to print, and whether the store is complete for the period.
pub fn run(args: &[String], now: chrono::DateTime<chrono::Utc>) -> Result<(String, bool), String> {
    let a = parse(args)?;
    let checklist = a.checklist.as_deref().map(|p| std::fs::read_to_string(p).map_err(|e| format!("{p}: {e}"))).transpose()?;
    let (found, other) = scan(Path::new(&a.store))?;
    let p = period(&a, &found, now.date_naive())?;
    let r = report(&found, &other, &p, checklist.as_deref(), now.timestamp_millis());
    let complete = r["complete"] == true;
    let text = if a.json { String::from_utf8_lossy(&json_file(&r)).into_owned() } else { markdown(&r) };
    let Some(file) = a.out else { return Ok((text, complete)) };
    crate::save_private(&file, text.as_bytes())?;
    let s = &r["summary"];
    Ok((
        format!(
            "Saved {file}: {} to {} (not included), {} of {} bundles check, {} of {} kinds and {} of {} checklist rows cover every day; {}.\nSHA-256: {}",
            p.from,
            p.to,
            s["verified"],
            s["bundles"],
            s["kindsComplete"],
            KINDS.len(),
            s["rowsComplete"],
            s["rows"],
            if complete { "complete".to_string() } else { format!("{} problems", r["problems"].as_array().map_or(0, Vec::len)) },
            sha256(text.as_bytes()),
        ),
        complete,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    type Files = BTreeMap<String, Vec<u8>>;

    fn d(s: &str) -> NaiveDate {
        NaiveDate::parse_from_str(s, "%Y-%m-%d").unwrap()
    }

    fn p(from: &str, to: &str) -> Period {
        Period { from: d(from), to: d(to) }
    }

    /// A bundle as its tool writes it: files, a manifest naming each with its controls,
    /// and SHA256SUMS.
    pub fn bundle(kind: &Kind, period: Period, made: &str) -> (String, BTreeMap<String, Vec<u8>>) {
        let name = format!("{}{}-{}", kind.prefix, period.label(), made.replace(['-', ':'], ""));
        let mut files: BTreeMap<String, Vec<u8>> = BTreeMap::new();
        files.insert("README.txt".into(), b"readme\n".to_vec());
        let mut listed = vec![json!({ "name": "README.txt", "sha256": sha256(b"readme\n"), "criteria": [], "checklist": [] })];
        for (file, criteria, rows) in expected(kind.id) {
            let body = if file == "pull-requests.json" { json_file(&json!({ "exceptions": { "noIndependentApproval": [101, 102], "directCommits": [] } })) } else { json_file(&json!({ "file": file })) };
            listed.push(json!({ "name": file, "sha256": sha256(&body), "criteria": criteria, "checklist": rows }));
            files.insert(file.into(), body);
        }
        let mut manifest = json!({ "product": "SuperBot", "format": 1, "createdAt": made, "period": { "from": period.from.to_string(), "to": period.to.to_string(), "days": period.days() }, "files": listed });
        if let Some(k) = kind.manifest_kind {
            manifest["kind"] = json!(k);
        }
        files.insert("manifest.json".into(), json_file(&manifest));
        seal(&mut files);
        (name, files)
    }

    /// One tar entry with the given type flag, without the end-of-archive blocks.
    fn entry(name: &str, flag: u8, data: &[u8]) -> Vec<u8> {
        let mut t = crate::ustar::tar(&[(name.to_string(), data.to_vec())], 0);
        t.truncate(t.len() - 1024);
        t[156] = flag;
        let sum: u32 = t[..512].iter().enumerate().map(|(j, &c)| if (148..156).contains(&j) { 32 } else { u32::from(c) }).sum();
        t[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
        t
    }

    fn seal(files: &mut BTreeMap<String, Vec<u8>>) {
        files.remove("SHA256SUMS");
        let sums: String = files.iter().map(|(n, b)| format!("{}  {n}\n", sha256(b))).collect();
        files.insert("SHA256SUMS".into(), sums.into_bytes());
    }

    fn month(kind: &Kind, from: &str, to: &str) -> Found {
        let (name, files) = bundle(kind, p(from, to), &format!("{to}T00:05:00Z"));
        check(format!("{name}.tar"), &name, &files)
    }

    /// botd's bundles gained `baseline.json` (ADR 0195): one with it checks and counts its
    /// deviations, and one made before it still checks.
    #[test]
    fn botds_baseline_file_is_checked_when_there_and_never_required() {
        let (name, mut files) = bundle(&KINDS[0], p("2027-01-01", "2027-02-01"), "2027-02-01T00:05:00Z");
        assert!(check(format!("{name}.tar"), &name, &files).verified(), "a bundle without it");
        let body = json_file(&json!({ "ok": false, "exceptions": { "deviations": ["AUTH_MFA", "TEAMS"], "excepted": ["MACHINE_ON_DISABLE"], "unknownExceptions": [] } }));
        let mut m: Value = serde_json::from_slice(&files["manifest.json"]).unwrap();
        let e = &EVIDENCE_LATER[0];
        m["files"].as_array_mut().unwrap().push(json!({ "name": e.file, "sha256": sha256(&body), "criteria": e.criteria, "checklist": e.rows }));
        files.insert(e.file.into(), body);
        files.insert("manifest.json".into(), json_file(&m));
        seal(&mut files);
        let f = check(format!("{name}.tar"), &name, &files);
        assert!(f.verified(), "{:?}", f.problems);
        assert_eq!((f.exceptions["baseline.json"]["deviations"], f.exceptions["baseline.json"]["excepted"]), (2, 1));
        assert!(f.files.iter().any(|(n, _, rows)| n == "baseline.json" && rows == &["CC5.1-1".to_string()]));
        files.insert(e.file.into(), b"{}\n".to_vec());
        assert!(!check(format!("{name}.tar"), &name, &files).verified(), "changed after it was made");
    }

    /// Register bundles gained `conduct.json` in format 2 (ADR 0214): one of format 1
    /// without it still checks, one of format 2 must have it, and its exceptions count.
    #[test]
    fn register_bundles_have_conduct_json_from_format_2() {
        let kind = KINDS.iter().find(|k| k.id == "policy-register").unwrap();
        assert_eq!(kind.format, 2);
        let (name, files) = bundle(kind, p("2027-01-01", "2027-02-01"), "2027-02-01T00:05:00Z");
        let with_format = |n: u64, conduct: Option<&[u8]>| {
            let mut fs = files.clone();
            let mut m: Value = serde_json::from_slice(&fs["manifest.json"]).unwrap();
            m["format"] = json!(n);
            m["files"].as_array_mut().unwrap().retain(|f| f["name"] != "conduct.json");
            fs.remove("conduct.json");
            if let Some(body) = conduct {
                m["files"].as_array_mut().unwrap().push(json!({ "name": "conduct.json", "sha256": sha256(body), "criteria": ["CC1.1"], "checklist": ["CC1.1-1"] }));
                fs.insert("conduct.json".into(), body.to_vec());
            }
            fs.insert("manifest.json".into(), json_file(&m));
            seal(&mut fs);
            check(format!("{name}.tar"), &name, &fs)
        };
        let old = with_format(1, None);
        assert!(old.verified(), "made before conduct.json: {:?}", old.problems);
        let missing = with_format(2, None);
        assert!(!missing.verified() && missing.problems.iter().any(|x| x.contains("it has no conduct.json")), "{:?}", missing.problems);
        let body = json_file(&json!({ "exceptions": { "triagedLate": ["CC-1 (received 2027-01-02, not triaged, due 2027-01-09)"], "closedLate": [], "handlerNotInRole": [] } }));
        let f = with_format(2, Some(&body));
        assert!(f.verified(), "{:?}", f.problems);
        assert_eq!(f.exceptions["conduct.json"]["triagedLate"], 1);
        assert!(f.files.iter().any(|(n, _, rows)| n == "conduct.json" && rows == &["CC1.1-1".to_string()]));
    }

    #[test]
    fn a_bundle_checks_against_its_digests_and_manifest() {
        let f = month(&KINDS[1], "2027-01-01", "2027-02-01");
        assert!(f.verified(), "{:?}", f.problems);
        assert_eq!(f.period, Some(p("2027-01-01", "2027-02-01")));
        assert_eq!(f.exceptions["pull-requests.json"]["noIndependentApproval"], 2);
        assert!(f.files.iter().any(|(n, _, rows)| n == "pull-requests.json" && rows.contains(&"CC8.1-1".to_string())));

        let (name, files) = bundle(&KINDS[0], p("2027-01-01", "2027-02-01"), "2027-02-01T00:01:00Z");
        let tamper = |change: &dyn Fn(&mut Files), want: &str| {
            let mut fs = files.clone();
            change(&mut fs);
            let f = check("x".into(), &name, &fs);
            assert!(!f.verified() && f.problems.iter().any(|x| x.contains(want)), "{want}: {:?}", f.problems);
        };
        tamper(&|fs| _ = fs.insert("backups.json".into(), b"{}".to_vec()), "backups.json doesn't match its SHA-256 in SHA256SUMS");
        tamper(&|fs| _ = fs.remove("retention.json"), "retention.json is in SHA256SUMS but missing");
        tamper(&|fs| _ = fs.insert("extra.json".into(), b"{}".to_vec()), "extra.json isn't in SHA256SUMS");
        tamper(&|fs| _ = fs.remove("SHA256SUMS"), "no SHA256SUMS");
        // Changed and resealed: SHA256SUMS agrees, the manifest doesn't.
        tamper(
            &|fs| {
                fs.insert("backups.json".into(), b"{}".to_vec());
                seal(fs);
            },
            "backups.json doesn't match its SHA-256 in manifest.json",
        );
        // A file added and resealed is still not in the manifest.
        tamper(
            &|fs| {
                fs.insert("extra.json".into(), b"{}".to_vec());
                seal(fs);
            },
            "extra.json isn't in manifest.json",
        );
        let rewrite = |edit: &dyn Fn(&mut Value), want: &str| {
            tamper(
                &|fs| {
                    let mut m: Value = serde_json::from_slice(&fs["manifest.json"]).unwrap();
                    edit(&mut m);
                    fs.insert("manifest.json".into(), json_file(&m));
                    seal(fs);
                },
                want,
            )
        };
        rewrite(&|m| m["period"]["to"] = json!("2027-03-01"), "isn't the one its name says");
        rewrite(&|m| m["kind"] = json!("change-management"), "kind (change-management) isn't what its name says (none)");
        rewrite(&|m| m["files"].as_array_mut().unwrap().retain(|f| f["name"] != "backups.json"), "backups.json isn't in manifest.json");
        rewrite(&|m| m["product"] = json!("Other"), "isn't a SuperBot manifest");
        rewrite(&|m| _ = m.as_object_mut().unwrap().remove("format"), "no format");
        rewrite(&|m| m["format"] = json!(0), "format (0) isn't one");
        rewrite(&|m| _ = m.as_object_mut().unwrap().remove("createdAt"), "when it was made");
        // A bundle without one of its kind's files, consistently sealed, still fails.
        tamper(
            &|fs| {
                fs.remove("backups.json");
                let mut m: Value = serde_json::from_slice(&fs["manifest.json"]).unwrap();
                m["files"].as_array_mut().unwrap().retain(|f| f["name"] != "backups.json");
                fs.insert("manifest.json".into(), json_file(&m));
                seal(fs);
            },
            "it has no backups.json",
        );

        let mut newer: Value = serde_json::from_slice(&files["manifest.json"]).unwrap();
        newer["format"] = json!(9);
        newer["createdAt"] = json!("2027-03-15T00:00:00Z");
        let mut fs = files.clone();
        fs.insert("manifest.json".into(), json_file(&newer));
        seal(&mut fs);
        let f = check("x".into(), &name, &fs);
        assert!(f.verified(), "{:?}", f.problems);
        assert!(f.warnings.iter().any(|w| w.contains("newer than this tool")) && f.warnings.iter().any(|w| w.contains("42 days after")), "{:?}", f.warnings);
    }

    #[test]
    fn names_say_kind_and_period() {
        assert_eq!(period_of("superbot-evidence-2026-10-01_2026-11-01-20261101T000100Z"), Some(p("2026-10-01", "2026-11-01")));
        assert_eq!(kind_of("superbot-vulns-2026-10-01_2026-11-01-20261101T000100Z").map(|k| k.id), Some("vulnerability-management"));
        assert_eq!(kind_of("superbot-changes-x").map(|k| k.id), Some("change-management"));
        for bad in ["superbot-evidence-2026-11-01_2026-10-01-x", "superbot-evidence-2026-10-01-2026-11-01-x", "superbot-evidence-2026-10-01_2026-11-01", "other-2026-10-01_2026-11-01-x"] {
            assert_eq!(period_of(bad), None, "{bad}");
        }
        let f = check("x".into(), "superbot-evidence-garbage", &BTreeMap::new());
        assert!(!f.verified());
    }

    #[test]
    fn real_change_vulnerability_drill_and_register_bundles_check() {
        let period = p("2027-01-01", "2027-02-01");
        let now = d("2027-02-01").and_hms_opt(4, 17, 0).unwrap().and_utc().timestamp_millis();
        let src = changes::Source { api_host: "api.github.com".into(), requests: 1, scopes: None };
        let c = changes::Collected {
            repo: json!({ "fullName": "example-org/example-repo", "private": false }),
            branch: "main".into(),
            protection: json!({}),
            required: changes::Required::default(),
            pulls: vec![],
            commits: json!({ "total": 0, "commits": [] }),
            updates: Ok(vec![]),
            runs: vec![],
            runs_truncated: false,
        };
        let v = vulns::Collected { repo: json!({ "fullName": "example-org/example-repo" }), branch: "main".into(), dependabot: Ok(0), code_scanning: Ok(0), alerts: vec![], accepted: vec![], as_of: now };
        let d = drills::Collected { repo: json!({ "fullName": "example-org/example-repo" }), branch: "main".into(), workflows: vec![], executions: vec![] };
        let reg = register::parse(br#"{ "superbotRegister": 1 }"#, &register::builtin_policies()).unwrap();
        let policies = register::builtin_policies();
        let rc = register::Check { r: &reg, p: period, policies: &policies, baselines: &[] };
        let rsrc = register::Source { file: "register.json".into(), bytes: 24, sha256: sha256(b"register") };
        for tar in [
            changes::build(&c, &period, &src, now).tar,
            vulns::build(&v, &period, &vulns::Windows::default(), &src, now).tar,
            drills::build(Some(&d), &[], &period, &src, now).tar,
            drills::build(None, &[], &period, &src, now).tar,
            register::build(&rc, &rsrc, now).tar,
        ] {
            let f = from_entries("b.tar".into(), untar(&tar).unwrap()).expect("a bundle");
            assert!(f.verified(), "{}: {:?}", f.name, f.problems);
            assert_eq!(f.period, Some(period));
            assert!(f.warnings.is_empty(), "{:?}", f.warnings);
        }
    }

    #[test]
    fn tars_as_made_and_as_packed_again() {
        let (name, files) = bundle(&KINDS[2], p("2027-01-01", "2027-02-01"), "2027-02-01T04:17:00Z");
        let entries: Vec<(String, Vec<u8>)> = files.iter().map(|(n, b)| (format!("{name}/{n}"), b.clone())).collect();
        let tar = crate::ustar::tar(&entries, 0);
        assert_eq!(untar(&tar).unwrap().len(), files.len());
        assert!(from_entries("v.tar".into(), untar(&tar).unwrap()).unwrap().verified());

        // GNU tar's `./` names and a directory entry.
        let mut repacked = vec![(format!("./{name}/README.txt"), b"readme\n".to_vec())];
        repacked.extend(entries.iter().filter(|(n, _)| !n.ends_with("README.txt")).cloned());
        let mut raw = crate::ustar::tar(&repacked, 0);
        raw.truncate(raw.len() - 1024);
        let mut dir = crate::ustar::tar(&[(format!("{name}/"), Vec::new())], 0);
        dir[156] = b'5';
        let sum: u32 = dir[..512].iter().enumerate().map(|(j, &c)| if (148..156).contains(&j) { 32 } else { u32::from(c) }).sum();
        dir[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
        let mut all = dir[..512].to_vec();
        all.extend(raw);
        all.resize(all.len() + 1024, 0);
        let f = from_entries("v.tar".into(), untar(&all).unwrap()).unwrap();
        assert!(f.verified(), "{:?}", f.problems);

        // Long names: a pax header's path and a GNU long name each name the next file; a
        // pax header without a path leaves the next file's own name.
        let long = format!("{name}/{}", "x".repeat(120));
        let pax = |kv: &str| {
            let rest = format!(" {kv}\n");
            let mut n = rest.len() + 1;
            while format!("{n}{rest}").len() != n {
                n += 1;
            }
            format!("{n}{rest}").into_bytes()
        };
        let mut t = entry("PaxHeaders/a", b'x', &pax(&format!("path={long}")));
        t.extend(entry("short-a", b'0', b"one"));
        t.extend(entry("././@LongLink", b'L', format!("{name}/gnu-{}\0", "y".repeat(110)).as_bytes()));
        t.extend(entry("short-b", b'0', b"two"));
        t.extend(entry("PaxHeaders/c", b'x', &pax("mtime=0")));
        t.extend(entry(&format!("{name}/own"), b'0', b"three"));
        t.resize(t.len() + 1024, 0);
        let got: Vec<(String, Vec<u8>)> = untar(&t).unwrap();
        assert_eq!(got, vec![(long, b"one".to_vec()), (format!("{name}/gnu-{}", "y".repeat(110)), b"two".to_vec()), (format!("{name}/own"), b"three".to_vec())]);

        let mut broken = tar.clone();
        broken[600] ^= 1;
        assert!(untar(&broken[..1000]).is_err(), "cut short");
        let mut header = tar.clone();
        header[10] ^= 1;
        assert!(untar(&header).unwrap_err().contains("damaged"));
        let mut link = crate::ustar::tar(&[("a/b".into(), Vec::new())], 0);
        link[156] = b'2';
        let sum: u32 = link[..512].iter().enumerate().map(|(j, &c)| if (148..156).contains(&j) { 32 } else { u32::from(c) }).sum();
        link[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
        assert!(untar(&link).unwrap_err().contains("isn't a plain file"));

        // A changed copy hidden before the original: only the last would reach the check.
        let mut twice = vec![(format!("{name}/accepted-findings.json"), b"changed".to_vec())];
        twice.extend(entries.iter().cloned());
        let f = from_entries("d.tar".into(), untar(&crate::ustar::tar(&twice, 0)).unwrap()).unwrap();
        assert!(!f.verified() && f.problems.iter().any(|x| x.contains("accepted-findings.json is in the tar more than once")), "{:?}", f.problems);

        let two = crate::ustar::tar(&[(format!("{name}/a"), vec![]), ("superbot-evidence-2027-01-01_2027-02-01-x/b".into(), vec![])], 0);
        assert!(from_entries("t.tar".into(), untar(&two).unwrap()).unwrap().problems[0].contains("more than one folder"));
        assert!(from_entries("o.tar".into(), untar(&crate::ustar::tar(&[("photos/a.jpg".into(), vec![1])], 0)).unwrap()).is_none());
    }

    #[test]
    fn a_damaged_folder_still_counts_and_other_files_are_listed() {
        let store = std::env::temp_dir().join(format!("coverage-scan-{}-{}", std::process::id(), line!()));
        let _ = std::fs::remove_dir_all(&store);
        let (name, files) = bundle(&KINDS[0], p("2027-01-01", "2027-02-01"), "2027-02-01T00:01:00Z");
        let damaged = store.join("2027-01").join(&name);
        std::fs::create_dir_all(&damaged).unwrap();
        std::fs::write(damaged.join("backups.json"), &files["backups.json"]).unwrap();
        std::fs::write(store.join("notes.txt"), "by hand").unwrap();
        std::fs::write(store.join(".partial.tar"), "half").unwrap();
        let entries: Vec<(String, Vec<u8>)> = files.iter().map(|(n, b)| (format!("{name}/{n}"), b.clone())).collect();
        let mut renamed = crate::ustar::tar(&entries, 0);
        renamed[1024 + 10] ^= 1;
        std::fs::write(store.join("october.tar"), &renamed).unwrap();
        let (mut found, other) = scan(&store).unwrap();
        let _ = std::fs::remove_dir_all(&store);
        let unreadable = found.pop().unwrap();
        assert_eq!(unreadable.path, "october.tar");
        assert!(!unreadable.verified() && unreadable.problems[0].contains("can't be read as a tar"), "{:?}", unreadable.problems);
        assert_eq!(found.len(), 1);
        assert!(!found[0].verified() && found[0].problems.iter().any(|x| x.contains("no SHA256SUMS")) && found[0].problems.iter().any(|x| x.contains("no manifest.json")), "{:?}", found[0].problems);
        assert_eq!(other, ["notes.txt"]);
        found.push(unreadable);
        let r = report(&found, &other, &p("2027-01-01", "2027-02-01"), None, 0);
        assert!(strings(&r["problems"]).iter().any(|x| x.starts_with("october.tar: ")));
        assert_eq!((r["bundles"][0]["verified"].as_bool(), r["bundles"][0]["inPeriod"].as_bool()), (Some(false), Some(true)));
        assert_eq!(r["summary"]["otherFiles"], 1);
    }

    #[test]
    fn gaps_and_months() {
        let q = p("2027-01-01", "2027-04-01");
        let covered: BTreeSet<NaiveDate> = p("2027-02-01", "2027-03-01").from.iter_days().take(28).collect();
        let g = gaps(&q, &covered);
        assert_eq!(g, vec![json!({ "from": "2027-01-01", "to": "2027-02-01", "days": 31 }), json!({ "from": "2027-03-01", "to": "2027-04-01", "days": 31 })]);
        assert!(gaps(&q, &days(&q).into_iter().collect()).is_empty());
        let ms = months(&p("2026-12-15", "2027-02-10"));
        assert_eq!(ms.iter().map(|(m, _)| m.as_str()).collect::<Vec<_>>(), ["2026-12", "2027-01", "2027-02"]);
        assert_eq!((ms[0].1, ms[2].1), (p("2026-12-15", "2027-01-01"), p("2027-02-01", "2027-02-10")));
    }

    #[test]
    fn the_report_finds_each_missing_day_and_failed_bundle() {
        let q = p("2027-01-01", "2027-04-01");
        let mut found = vec![];
        for (from, to) in [("2027-01-01", "2027-02-01"), ("2027-02-01", "2027-03-01"), ("2027-03-01", "2027-04-01")] {
            found.push(month(&KINDS[0], from, to));
            found.push(month(&KINDS[2], from, to));
            found.push(month(&KINDS[3], from, to));
            found.push(month(&KINDS[4], from, to));
        }
        // Change management: January only, and a tampered February.
        found.push(month(&KINDS[1], "2027-01-01", "2027-02-01"));
        let mut bad = month(&KINDS[1], "2027-02-01", "2027-03-01");
        bad.problems.push("pull-requests.json doesn't match its SHA-256 in SHA256SUMS: it changed after the bundle was made".into());
        found.push(bad);
        // Outside the period: checked, not counted.
        found.push(month(&KINDS[0], "2026-12-01", "2027-01-01"));

        let checklist = "| ID | Item | Kind | Owner | Evidence | Status | Where |\n|----|---|---|---|---|---|---|\n| CC8.1-1 | x | Product | E | e | Gap | w |\n| CC1.5-1 | x | Process | M | e | Gap | w |\n| CC6.1-1 | x | Product | E | e | Done | w |\n";
        let r = report(&found, &["notes.txt".into()], &q, Some(checklist), 0);
        assert_eq!(r["complete"], false);
        let problems = strings(&r["problems"]);
        assert!(problems.iter().any(|x| x.contains("superbot-changes-2027-02-01") && x.contains("changed after")), "{problems:?}");
        assert!(problems.iter().any(|x| x == "No verified change-management bundle covers 2027-02-01 to 2027-04-01 (59 days)"), "{problems:?}");
        assert_eq!(problems.len(), 2, "{problems:?}");
        assert_eq!(r["summary"]["inPeriod"], 13);
        assert_eq!(r["summary"]["failed"], 1);
        assert_eq!(r["summary"]["kindsComplete"], 4);
        assert_eq!(r["summary"]["exceptionsInBundles"], 2);

        let kind = |id: &str| r["kinds"].as_array().unwrap().iter().find(|k| k["kind"] == id).unwrap().clone();
        assert_eq!(kind("evidence")["complete"], true);
        let cm = kind("change-management");
        assert_eq!((cm["coveredDays"].as_u64(), cm["days"].as_u64()), (Some(31), Some(90)));
        assert_eq!(cm["months"].as_array().unwrap().iter().map(|m| m["status"].as_str().unwrap()).collect::<Vec<_>>(), ["complete", "missing", "missing"]);

        let row = |id: &str| r["rows"].as_array().unwrap().iter().find(|x| x["row"] == id).unwrap().clone();
        assert_eq!(row("CC8.1-1")["coveredDays"], 31);
        assert_eq!(row("CC8.1-1")["criterion"], "CC8.1");
        // CC8.1-2 is in both the botd bundle and the change-management bundle.
        assert_eq!(row("CC8.1-2")["complete"], true);
        assert_eq!(strings(&row("CC8.1-2")["from"]), ["change-management", "evidence"]);
        assert_eq!(row("CC4.2-1")["complete"], true);
        assert_eq!((row("A1.3-1")["complete"].as_bool(), strings(&row("A1.3-1")["from"])), (Some(true), vec!["recovery-drills".to_string()]));
        assert_eq!(row("CC9.1-2")["coveredDays"], 90);
        let crit = r["criteria"].as_array().unwrap().iter().find(|c| c["criterion"] == "CC3.4").unwrap().clone();
        assert_eq!(crit["complete"], false);

        let c = &r["checklist"];
        assert_eq!((c["rows"].as_u64(), c["withAutomatedEvidence"].as_u64()), (Some(3), Some(2)));
        assert_eq!(c["noAutomatedEvidence"], json!([{ "row": "CC1.5-1", "status": "Gap" }]));
        assert!(strings(&r["warnings"]).iter().any(|w| w.starts_with("CC6.2-1 is named by a bundle")));

        let md = markdown(&r);
        for want in ["**Not complete:** 2 problems", "| 2027-02 | complete | missing | complete | complete | complete |", "| CC8.1-1 | change-management | 31 of 90 | 2027-02-01 to 2027-04-01 |", "| CC1.5-1 | Gap |", "**no**", "yes, outside the period", "noIndependentApproval 2"] {
            assert!(md.contains(want), "{want}\n{md}");
        }

        let all: Vec<Found> = found.into_iter().filter(|f| f.verified()).collect();
        let full = report(&all, &[], &p("2027-01-01", "2027-02-01"), None, 0);
        assert_eq!(full["complete"], true, "{:?}", full["problems"]);
        assert!(markdown(&full).contains("**Complete:**"));
        assert_eq!(full["checklist"], Value::Null);
    }

    #[test]
    fn options_and_the_default_period() {
        let a = parse(&["store".into(), "--from".into(), "2027-01-01".into(), "--to".into(), "2027-02-01".into(), "--json".into(), "-o".into(), "r.json".into(), "--checklist".into(), "c.md".into()]).unwrap();
        assert_eq!((a.store.as_str(), a.json, a.out.as_deref(), a.checklist.as_deref()), ("store", true, Some("r.json"), Some("c.md")));
        for bad in [&[][..], &["--json"], &["s", "t"], &["s", "--from"], &["s", "--token", "x"], &["s", "-o", "a", "-o", "b"]] {
            let v: Vec<String> = bad.iter().map(|s| s.to_string()).collect();
            assert!(parse(&v).is_err(), "{bad:?}");
        }
        let today = d("2027-06-15");
        let none = parse(&["s".into()]).unwrap();
        let found = vec![month(&KINDS[0], "2027-02-01", "2027-03-01"), month(&KINDS[1], "2027-01-01", "2027-02-01")];
        assert_eq!(period(&none, &found, today).unwrap(), p("2027-01-01", "2027-03-01"));
        assert!(period(&none, &[], today).unwrap_err().contains("--from"));
        let one = parse(&["s".into(), "--from".into(), "2027-01-01".into()]).unwrap();
        assert!(period(&one, &found, today).is_err());
    }

    #[test]
    fn checklist_rows_are_read_from_the_real_checklist() {
        let rows = checklist_rows(include_str!("../../../../docs/security/soc2-readiness-checklist.md"));
        assert!(rows.len() > 50, "{}", rows.len());
        assert!(rows.get("CC8.1-1").is_some_and(|s| ["Done", "Partial", "Gap"].contains(&s.as_str())));
        assert!(rows.keys().all(|r| r.contains('-') && r.contains('.')));
    }

    /// The botd kind's files and controls match the evidence plan's bundle table (which
    /// botd's own test holds to `evidence::SECTIONS`) and its format botd's.
    #[test]
    fn the_evidence_kind_matches_botd_and_the_evidence_plan() {
        let plan = include_str!("../../../../docs/security/soc2-evidence-plan.md");
        let section = plan.split("## The evidence bundle").nth(1).and_then(|s| s.split("\n## ").next()).unwrap();
        let rows: Vec<&str> = section.lines().filter(|l| l.starts_with("| `")).collect();
        assert_eq!(rows.len(), EVIDENCE.len() + EVIDENCE_LATER.len());
        for e in EVIDENCE.iter().chain(&EVIDENCE_LATER) {
            let line = rows.iter().find(|l| l.starts_with(&format!("| `{}` |", e.file))).unwrap_or_else(|| panic!("{}", e.file));
            let cells: Vec<&str> = line.split('|').map(str::trim).collect();
            let ids = |s: &str| -> Vec<String> { s.split(',').map(|x| x.trim().to_string()).filter(|x| !x.is_empty() && x != "None").collect() };
            assert_eq!(ids(cells[3]), e.criteria.iter().map(|s| s.to_string()).collect::<Vec<_>>(), "{}", e.file);
            assert_eq!(ids(cells[4]), e.rows.iter().map(|s| s.to_string()).collect::<Vec<_>>(), "{}", e.file);
        }
        let botd = include_str!("../../evidence.rs");
        assert!(botd.contains("pub const BASELINE_FILE: &str = \"baseline.json\";") && botd.contains("BASELINE_CRITERIA: [&str; 1] = [\"CC5.1\"]") && botd.contains("BASELINE_ROWS: [&str; 1] = [\"CC5.1-1\"]"));
        assert!(botd.contains(&format!("pub const FORMAT: u32 = {};", KINDS[0].format)));
        assert!(botd.contains(&format!("const PREFIX: &str = \"{}\";", KINDS[0].prefix)));
    }
}
