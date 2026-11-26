//! `superbot-evidence deficiencies` (ADR 0326): the deficiency log for the quarterly
//! management review. Reads the evidence store as `coverage` does (ADR 0169) and lists
//! every exception the bundles that check report for the period, each tracked across the
//! bundles that list it: when it was first and last listed, and whether the newest bundle
//! of its source still lists it. Each comes with the checklist rows it bears on and their
//! owners, beside the control-testing results' deviations (ADR 0296), the store's own
//! problems, and what changed since the previous log. Local files only: no token, no
//! network, nothing written into the store.

use crate::changes::{json_file, rfc3339, sha256};
use crate::coverage::{self, Files, Found};
use crate::period::Period;
use crate::sample;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

/// Bumped when the log's shape changes.
pub const FORMAT: u32 = 1;
pub const PREFIX: &str = "superbot-deficiencies-";
/// The manifest's kind.
pub const KIND: &str = "deficiency-log";
pub const FILE: &str = "deficiencies.json";
pub const MARKDOWN: &str = "deficiencies.md";

/// The source a results bundle's findings are listed under.
pub const RESULTS: &str = "audit-results";

/// A checklist larger than this isn't read.
const MAX_CHECKLIST: u64 = 4 << 20;

/// An item shown in the Markdown is cut to this many characters; the JSON keeps it whole.
const MAX_SHOWN: usize = 160;

/// The role that answers for the store's own problems: the evidence plan has the
/// security owner check its coverage each month.
pub const STORE_OWNER: &str = "Security owner";

/// A bundle's identity: its name and the start of its manifest's SHA-256, so two
/// servers' same-named bundles stay apart and a tar and its unpacked folder are one.
fn ident(name: &str, manifest_sha256: &str) -> String {
    format!("{name}@{}", &manifest_sha256[..manifest_sha256.len().min(16)])
}

fn text(v: &Value) -> Option<String> {
    match v {
        Value::String(s) if !s.is_empty() => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

/// What an exception item is tracked by from one bundle to the next. Bundles write an
/// item as its id followed by its state in brackets (`CHG-2 emergency on hosting (made
/// 2027-01-06, not reviewed, due 2027-01-08)`), so a string is known by what comes before
/// its first ` (`, or before a `: ` that starts a date span (`Engineering lead: 2026-08-01
/// to 2026-09-01`), with the bundle's own period boundaries, which only clip a condition
/// to the bundle (`none in the year to 2026-09-01`), read as such; a number (a pull
/// request) by itself; an object by its `id` or `number`, or else whole.
pub fn key(item: &Value, p: &Period) -> String {
    match item {
        Value::String(s) => {
            let mut k = s.split_once(" (").map(|(k, _)| k).filter(|k| !k.trim().is_empty()).unwrap_or(s);
            if let Some((at, _)) = k.match_indices(": ").find(|(i, _)| k[i + 2..].starts_with(|c: char| c.is_ascii_digit())) {
                k = &k[..at];
            }
            k.trim().replace(&p.from.to_string(), "<period start>").replace(&p.to.to_string(), "<period end>")
        }
        Value::Object(o) => ["id", "number"].iter().find_map(|k| o.get(*k).and_then(text)).unwrap_or_else(|| item.to_string()),
        Value::Number(n) => n.to_string(),
        other => other.to_string(),
    }
}

/// The criteria and checklist rows a kind of bundle's file serves.
pub fn controls(kind: &str, file: &str) -> (Vec<String>, Vec<String>) {
    let later: Vec<(&str, &[&str], &[&str])> = if kind == "evidence" { coverage::EVIDENCE_LATER.iter().map(|e| (e.file, e.criteria, e.rows)).collect() } else { Vec::new() };
    let own = |xs: &[&str]| xs.iter().map(|x| x.to_string()).collect::<Vec<_>>();
    coverage::expected(kind).into_iter().chain(later).find(|(f, _, _)| *f == file).map(|(_, c, r)| (own(c), own(r))).unwrap_or_default()
}

/// The criteria and rows of the control test a results item names (`<test> <item>`).
fn tested(key: &str) -> (Vec<String>, Vec<String>) {
    let id = key.split_whitespace().next().unwrap_or_default();
    sample::TESTS.iter().find(|t| t.id == id).map(|t| (t.criteria.iter().map(|c| c.to_string()).collect(), t.rows.iter().map(|r| r.to_string()).collect())).unwrap_or_default()
}

/// A readiness checklist row: its item, owner and status.
#[derive(Clone, Debug, PartialEq)]
pub struct Row {
    pub item: String,
    pub owner: String,
    pub status: String,
}

/// The readiness checklist's rows, by id, from its Markdown tables (`| ID | Item | Kind |
/// Owner | Evidence | Status | Where |`).
pub fn checklist(md: &str) -> BTreeMap<String, Row> {
    let all = coverage::checklist_rows(md);
    md.lines()
        .filter_map(|l| {
            let cells: Vec<&str> = l.split('|').map(str::trim).collect();
            let id = *cells.get(1).filter(|id| all.contains_key(**id))?;
            Some((id.to_string(), Row { item: cells.get(2)?.to_string(), owner: cells.get(4)?.to_string(), status: cells.get(6)?.to_string() }))
        })
        .collect()
}

/// One bundle listing an item.
#[derive(Clone, Debug)]
struct Listing {
    bundle: String,
    ident: String,
    period: Period,
    created: String,
    item: Value,
}

impl Listing {
    fn order(&self) -> (chrono::NaiveDate, &str, &str) {
        (self.period.to, self.created.as_str(), self.bundle.as_str())
    }

    fn view(&self) -> Value {
        json!({ "bundle": self.bundle, "from": self.period.from.to_string(), "to": self.period.to.to_string() })
    }
}

/// One exception item, across every bundle that lists it.
#[derive(Debug)]
struct Finding {
    source: String,
    title: String,
    scope: Option<String>,
    file: String,
    list: String,
    key: String,
    criteria: Vec<String>,
    rows: Vec<String>,
    listings: Vec<Listing>,
}

/// Where a finding comes from: its source (a kind of bundle, or results), scope (the
/// repository, or the samples' period), file and exception list.
type Group = (String, Option<String>, String, String);

#[derive(Default)]
struct Gathered {
    findings: BTreeMap<String, Finding>,
    /// Each group's bundles that had the list, as `(listing, ident)` with no item.
    bundles: BTreeMap<Group, Vec<Listing>>,
}

/// A finding's id: the first 16 hex digits of the SHA-256 of what it is tracked by, so
/// the same exception has the same id in every log and the register can name it.
pub fn finding_id(source: &str, scope: Option<&str>, file: &str, list: &str, key: &str) -> String {
    sha256(format!("{source}\n{}\n{file}\n{list}\n{key}\n", scope.unwrap_or_default()).as_bytes())[..16].to_string()
}

impl Gathered {
    /// Every exception `v` lists, as listed by the bundle `at`.
    fn add(&mut self, source: &str, title: &str, scope: Option<String>, file: &str, v: &Value, at: &Listing, controls: &dyn Fn(&str) -> (Vec<String>, Vec<String>)) {
        for (list, items) in v["exceptions"].as_object().into_iter().flatten() {
            // A list that isn't one (null: the bundle couldn't judge it) says nothing either way.
            let Some(items) = items.as_array() else { continue };
            let group = (source.to_string(), scope.clone(), file.to_string(), list.clone());
            let listings = self.bundles.entry(group).or_default();
            if !listings.iter().any(|l| l.ident == at.ident) {
                listings.push(at.clone());
            }
            for item in items {
                let k = key(item, &at.period);
                let id = finding_id(source, scope.as_deref(), file, list, &k);
                let (criteria, rows) = controls(&k);
                let f = self.findings.entry(id).or_insert_with(|| Finding { source: source.into(), title: title.into(), scope: scope.clone(), file: file.into(), list: list.clone(), key: k, criteria, rows, listings: Vec::new() });
                if !f.listings.iter().any(|l| l.ident == at.ident) {
                    f.listings.push(Listing { item: item.clone(), ..at.clone() });
                }
            }
        }
    }

    /// The bundles that count as the newest of a group: the latest by period, then by when
    /// it was made. botd's evidence bundles name no server, so for them every bundle of the
    /// latest period counts: one server's newest bundle can't clear another's finding.
    fn newest(&self, g: &Group) -> BTreeSet<String> {
        let all = self.bundles.get(g).map(Vec::as_slice).unwrap_or_default();
        let Some(top) = all.iter().max_by(|a, b| a.order().cmp(&b.order())) else { return BTreeSet::new() };
        if g.0 == "evidence" { all.iter().filter(|l| l.period.to == top.period.to).map(|l| l.ident.clone()).collect() } else { BTreeSet::from([top.ident.clone()]) }
    }
}

/// What the log is made from.
pub struct Inputs<'a> {
    /// The store's bundles, with their manifest and exception files kept.
    pub store: &'a [(Found, Files)],
    /// The store's files that aren't bundles.
    pub other: &'a [String],
    /// Each `--results` bundle: its name and files, as read.
    pub results: &'a [(String, Files)],
    /// The previous log, as read.
    pub since: Option<&'a (String, Files)>,
    pub checklist: Option<&'a str>,
}

fn parse(files: &Files, file: &str, bundle: &str) -> Result<Value, String> {
    files.get(file).and_then(|b| serde_json::from_slice(b).ok()).ok_or(format!("{bundle}: {file} isn't JSON"))
}

fn day(v: &Value) -> Option<chrono::NaiveDate> {
    v.as_str().and_then(|s| chrono::NaiveDate::parse_from_str(s, "%Y-%m-%d").ok())
}

/// The log for `p`.
pub fn log(i: &Inputs, p: &Period, now_ms: i64) -> Result<Value, String> {
    let rows = i.checklist.map(checklist);
    let mut g = Gathered::default();
    let mut read = Vec::new();
    for (f, files) in i.store {
        let (Some(kind), Some(bp)) = (f.kind, f.period) else { continue };
        if !f.verified() || bp.from >= p.to || bp.to <= p.from {
            continue;
        }
        let manifest: Value = files.get("manifest.json").and_then(|b| serde_json::from_slice(b).ok()).unwrap_or_default();
        let scope = manifest["source"]["repository"].as_str().filter(|r| !r.is_empty()).map(String::from);
        let at = Listing { bundle: f.name.clone(), ident: ident(&f.name, f.manifest_sha256.as_deref().unwrap_or_default()), period: bp, created: f.created.clone().unwrap_or_default(), item: Value::Null };
        for file in coverage::EXCEPTION_FILES {
            let Some(v) = files.get(file).and_then(|b| serde_json::from_slice::<Value>(b).ok()) else { continue };
            let (c, r) = controls(kind.id, file);
            g.add(kind.id, kind.title, scope.clone(), file, &v, &at, &|_| (c.clone(), r.clone()));
        }
        read.push(json!({ "name": f.name, "path": f.path, "kind": kind.id, "manifestSha256": f.manifest_sha256 }));
    }

    let mut testing = Vec::new();
    for (name, files) in i.results {
        let manifest = parse(files, "manifest.json", name)?;
        let r = parse(files, sample::RESULTS_FILE, name)?;
        let mp = &manifest["period"];
        let (Some(from), Some(to)) = (day(&mp["from"]), day(&mp["to"])) else { return Err(format!("{name}: its manifest doesn't say the period tested")) };
        let tp = Period { from, to };
        let manifest_sha256 = sha256(&files["manifest.json"]);
        let at = Listing { bundle: name.clone(), ident: ident(name, &manifest_sha256), period: tp, created: manifest["createdAt"].as_str().unwrap_or_default().to_string(), item: Value::Null };
        g.add(RESULTS, "Results bundle", Some(tp.label()), sample::RESULTS_FILE, &r, &at, &tested);
        testing.push(json!({ "bundle": name, "manifestSha256": manifest_sha256, "periodTested": { "from": from.to_string(), "to": to.to_string() }, "samples": manifest["samples"]["name"], "summary": r["summary"] }));
    }

    let owners = |fr: &[String]| -> Vec<String> { rows.as_ref().map(|rs| fr.iter().filter_map(|r| rs.get(r).map(|x| x.owner.clone())).collect::<BTreeSet<_>>().into_iter().collect()).unwrap_or_default() };
    let mut findings: Vec<Value> = Vec::new();
    let mut still = BTreeSet::new();
    for (id, f) in &g.findings {
        let group = (f.source.clone(), f.scope.clone(), f.file.clone(), f.list.clone());
        let newest = g.newest(&group);
        let listed = f.listings.iter().any(|l| newest.contains(&l.ident));
        let first = f.listings.iter().min_by(|a, b| (a.period.from, a.created.as_str(), a.bundle.as_str()).cmp(&(b.period.from, b.created.as_str(), b.bundle.as_str()))).expect("listed at least once");
        let last = f.listings.iter().max_by(|a, b| a.order().cmp(&b.order())).expect("listed at least once");
        if listed {
            still.insert(id.clone());
        }
        let newest_names: BTreeSet<&str> = g.bundles[&group].iter().filter(|l| newest.contains(&l.ident)).map(|l| l.bundle.as_str()).collect();
        findings.push(json!({
            "id": id,
            "source": f.source,
            "title": f.title,
            "scope": f.scope,
            "file": f.file,
            "exception": f.list,
            "item": f.key,
            "asLastListed": last.item,
            "criteria": f.criteria,
            "rows": f.rows,
            "owners": owners(&f.rows),
            "firstListed": first.view(),
            "lastListed": last.view(),
            "listedIn": f.listings.len(),
            "stillListed": listed,
            "newestBundles": newest_names,
        }));
    }
    findings.sort_by(|a, b| {
        let k = |v: &Value| (v["stillListed"] != true, v["source"].as_str().unwrap_or_default().to_string(), v["scope"].as_str().unwrap_or_default().to_string(), v["file"].as_str().unwrap_or_default().to_string(), v["exception"].as_str().unwrap_or_default().to_string(), v["item"].as_str().unwrap_or_default().to_string());
        k(a).cmp(&k(b))
    });

    let found: Vec<Found> = i.store.iter().map(|(f, _)| f.clone()).collect();
    let cov = coverage::report(&found, i.other, p, None, now_ms);
    let store_problems: Vec<Value> = cov["problems"].as_array().cloned().unwrap_or_default();

    let since = match i.since {
        None => Value::Null,
        Some((name, files)) => {
            let prev = parse(files, FILE, name)?;
            let manifest = parse(files, "manifest.json", name)?;
            let ids: BTreeSet<String> = g.findings.keys().cloned().collect();
            let was: BTreeSet<String> = prev["findings"].as_array().into_iter().flatten().filter(|f| f["stillListed"] == true).filter_map(|f| f["id"].as_str().map(String::from)).collect();
            let known: BTreeSet<String> = prev["findings"].as_array().into_iter().flatten().filter_map(|f| f["id"].as_str().map(String::from)).collect();
            json!({
                "bundle": name,
                "manifestSha256": sha256(&files["manifest.json"]),
                "period": manifest["period"],
                "stillListed": was.intersection(&still).collect::<Vec<_>>(),
                "noLongerListed": was.iter().filter(|id| !still.contains(*id)).collect::<Vec<_>>(),
                "new": ids.iter().filter(|id| !known.contains(*id)).collect::<Vec<_>>(),
            })
        }
    };

    let checklist_view = rows.as_ref().map(|rs| {
        let open: Vec<(&String, &Row)> = rs.iter().filter(|(_, r)| r.status != "Done").collect();
        let mut by_owner: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
        for (id, r) in &open {
            by_owner.entry(r.owner.as_str()).or_default().push(id.as_str());
        }
        json!({
            "sha256": i.checklist.map(|c| sha256(c.as_bytes())),
            "rows": rs.len(),
            "open": open.iter().map(|(id, r)| json!({ "row": id, "item": r.item, "owner": r.owner, "status": r.status })).collect::<Vec<_>>(),
            "openByOwner": by_owner,
        })
    });

    let mut by_owner: BTreeMap<String, usize> = BTreeMap::new();
    let mut by_source: BTreeMap<String, usize> = BTreeMap::new();
    for f in findings.iter().filter(|f| f["stillListed"] == true) {
        *by_source.entry(f["source"].as_str().unwrap_or_default().to_string()).or_default() += 1;
        for o in f["owners"].as_array().into_iter().flatten() {
            *by_owner.entry(o.as_str().unwrap_or_default().to_string()).or_default() += 1;
        }
    }
    let deviations = findings.iter().filter(|f| f["source"] == RESULTS && f["exception"] == "deviations" && f["stillListed"] == true).count();
    Ok(json!({
        "basis": "every exception listed by a bundle in the store whose SHA256SUMS and manifest check and whose period overlaps this one, and by each results bundle given; an item is tracked by its source (the kind of bundle, or results), scope (the repository of a change-management, vulnerability or drill bundle, or the period a results bundle tested), file, exception list and key (a string up to its first ' (' or a ': ' that starts a date span, with the bundle's own period boundaries read as such, so a condition that runs on is one finding; a number; or an object's id or number), and is still listed when the newest bundle of that source, scope and file that has the list lists it (for botd's evidence bundles, which name no server, any bundle of the latest period). An item no longer listed was either put right or was about something past, such as a pull request merged without an approval; the register says which. This lists what the bundles flagged, not every deficiency, and is not a SOC 2 opinion",
        "periodCovered": { "from": p.from.to_string(), "to": p.to.to_string(), "days": p.days() },
        "summary": {
            "findings": findings.len(),
            "stillListed": still.len(),
            "noLongerListed": findings.len() - still.len(),
            "stillListedByOwner": by_owner,
            "stillListedBySource": by_source,
            "testingDeviations": deviations,
            "storeComplete": store_problems.is_empty(),
            "storeProblems": store_problems.len(),
            "openChecklistRows": checklist_view.as_ref().map(|c| c["open"].as_array().map_or(0, Vec::len)),
        },
        "findings": findings,
        "testing": testing,
        "store": { "owner": STORE_OWNER, "complete": store_problems.is_empty(), "problems": store_problems, "warnings": cov["warnings"], "bundlesRead": read },
        "since": since,
        "checklist": checklist_view,
    }))
}

fn cell(s: &str) -> String {
    let s = s.replace('|', "\\|").replace(['\n', '\r'], " ");
    if s.chars().count() > MAX_SHOWN { format!("{}…", s.chars().take(MAX_SHOWN).collect::<String>()) } else { s }
}

fn shown(v: &Value) -> String {
    cell(&v.as_str().map(String::from).unwrap_or_else(|| v.to_string()))
}

fn listed_view(v: &Value) -> String {
    format!("{} to {}", v["from"].as_str().unwrap_or_default(), v["to"].as_str().unwrap_or_default())
}

fn strings(v: &Value) -> Vec<String> {
    v.as_array().into_iter().flatten().filter_map(|x| x.as_str().map(String::from)).collect()
}

/// The log as Markdown, for the management review's papers.
pub fn markdown(l: &Value, tool: &str, created: &str) -> String {
    let s = &l["summary"];
    let p = &l["periodCovered"];
    let mut o = format!(
        "# SOC 2 deficiency log, {} to {} (not included)\n\nMade by {tool} at {created} from an evidence store ([ADR 0326](https://github.com/CG-Labs/superbot/blob/main/docs/adr/0326-deficiency-log-for-the-management-review.md)), for the quarterly management review the draft [information security policy](https://github.com/CG-Labs/superbot/blob/main/docs/security/policies/information-security.md#management-review) asks for.\n\n**{} findings still listed** by the newest bundle of their source, {} no longer listed; {} control-testing deviations still listed; the store {}.\n\n",
        p["from"].as_str().unwrap_or_default(),
        p["to"].as_str().unwrap_or_default(),
        s["stillListed"],
        s["noLongerListed"],
        s["testingDeviations"],
        if s["storeComplete"] == true { "covers every day and every bundle checks".to_string() } else { format!("has {} problems", s["storeProblems"]) },
    );
    o += "These are the exceptions the bundles flagged, not every deficiency, and not a SOC 2 opinion. Record each one still listed in the [policy register](https://github.com/CG-Labs/superbot/blob/main/docs/security/policy-register.md) with a severity, owner and due date (as a risk, or as an `internal` vulnerability), or the reason it is accepted, and keep this log beside the review's minutes. One no longer listed was put right or was about something past; the register says which.\n";

    let findings = l["findings"].as_array().cloned().unwrap_or_default();
    let (open, closed): (Vec<&Value>, Vec<&Value>) = findings.iter().partition(|f| f["stillListed"] == true);
    let head = "| Finding | Bundle | Exception | Item | Rows | First listed | Last listed |\n|---|---|---|---|---|---|---|\n";
    let line = |f: &Value| {
        let scope = f["scope"].as_str().map(|s| format!(" ({s})")).unwrap_or_default();
        format!(
            "| `{}` | {}{} `{}` | {} | {} | {} | {} | {} |\n",
            f["id"].as_str().unwrap_or_default(),
            f["title"].as_str().unwrap_or_default(),
            cell(&scope),
            f["file"].as_str().unwrap_or_default(),
            cell(f["exception"].as_str().unwrap_or_default()),
            shown(&f["asLastListed"]),
            strings(&f["rows"]).join(", "),
            listed_view(&f["firstListed"]),
            listed_view(&f["lastListed"]),
        )
    };
    o += "\n## Still listed, by owner\n\n";
    if open.is_empty() {
        o += "None.\n";
    }
    let mut by: BTreeMap<String, Vec<&Value>> = BTreeMap::new();
    for f in &open {
        let owners = strings(&f["owners"]);
        by.entry(if owners.is_empty() { "No owner named (give --checklist)".into() } else { owners.join(", ") }).or_default().push(f);
    }
    for (owner, fs) in by {
        o += &format!("### {owner}\n\n{head}");
        for f in fs {
            o += &line(f);
        }
        o += "\n";
    }
    if !closed.is_empty() {
        o += &format!("\n## No longer listed\n\n{head}");
        for f in closed {
            o += &line(f);
        }
    }

    if let Some(t) = l["testing"].as_array().filter(|t| !t.is_empty()) {
        o += "\n## Control testing\n\n| Results bundle | Period tested | Tested | Deviations | Untested |\n|---|---|---|---|---|\n";
        for r in t {
            let s = &r["summary"];
            o += &format!("| {} | {} | {} of {} | {} | {} |\n", cell(r["bundle"].as_str().unwrap_or_default()), listed_view(&r["periodTested"]), s["tested"], s["sampled"], s["deviations"], s["untested"]);
        }
    }

    let st = &l["store"];
    o += &format!("\n## The evidence store\n\nOwner: {}. ", st["owner"].as_str().unwrap_or_default());
    match st["problems"].as_array().filter(|a| !a.is_empty()) {
        None => o += "Every kind of bundle covers every day of the period, and every bundle checks against its digests.\n",
        Some(ps) => {
            o += "What the coverage report finds:\n\n";
            for x in ps {
                o += &format!("- {}\n", cell(x.as_str().unwrap_or_default()));
            }
        }
    }

    if let Some(sn) = l["since"].as_object() {
        let n = |k: &str| sn.get(k).and_then(Value::as_array).map_or(0, Vec::len);
        o += &format!(
            "\n## Since the last log\n\nAgainst {} ({}): {} findings it listed are still listed, {} are no longer listed, and {} are new.\n",
            cell(sn.get("bundle").and_then(Value::as_str).unwrap_or_default()),
            sn.get("manifestSha256").and_then(Value::as_str).unwrap_or_default(),
            n("stillListed"),
            n("noLongerListed"),
            n("new")
        );
        for (k, title) in [("noLongerListed", "No longer listed"), ("new", "New")] {
            let ids = strings(&sn.get(k).cloned().unwrap_or_default());
            if !ids.is_empty() {
                o += &format!("\n{title}: {}\n", ids.iter().map(|i| format!("`{i}`")).collect::<Vec<_>>().join(", "));
            }
        }
    }

    if let Some(c) = l["checklist"].as_object() {
        o += &format!("\n## Open checklist rows\n\n{} of the [readiness checklist](https://github.com/CG-Labs/superbot/blob/main/docs/security/soc2-readiness-checklist.md)'s {} rows aren't Done.\n\n| Owner | Rows |\n|---|---|\n", c.get("open").and_then(Value::as_array).map_or(0, Vec::len), c.get("rows").cloned().unwrap_or_default());
        for (owner, rs) in c.get("openByOwner").and_then(Value::as_object).into_iter().flatten() {
            o += &format!("| {} | {} |\n", cell(owner), strings(rs).join(", "));
        }
    }
    o
}

const README: &str = "SuperBot deficiency log (superbot-evidence deficiencies, ADR 0326)

deficiencies.json: every exception the evidence store's bundles that check listed for the
period, and each results bundle given, tracked across the bundles that list it: when it
was first and last listed, whether the newest bundle of its source still lists it, and
the checklist rows it bears on with their owners; the store's own problems; with --since,
what changed since the previous log; with --checklist, the rows that aren't Done by
owner. deficiencies.md: the same for the management review's papers.

It lists what the bundles flagged, not every deficiency, and it is not a SOC 2 opinion.
Record each finding still listed in the policy register with a severity, owner and due
date, or why it is accepted, and keep this log beside the review's minutes.
";

pub struct Bundle {
    pub name: String,
    pub tar: Vec<u8>,
    pub sha256: String,
    pub manifest_sha256: String,
}

fn stamp(now_ms: i64) -> String {
    chrono::DateTime::from_timestamp_millis(now_ms).map(|t| t.format("%Y%m%dT%H%M%SZ").to_string()).unwrap_or_default()
}

pub fn build(l: &Value, i: &Inputs, p: &Period, now_ms: i64) -> Bundle {
    let name = format!("{PREFIX}{}-{}", p.label(), stamp(now_ms));
    let tool = concat!("superbot-evidence ", env!("CARGO_PKG_VERSION"));
    let created = rfc3339(now_ms);
    let mut files: Vec<(&str, Vec<u8>)> = vec![("README.txt", README.as_bytes().to_vec()), (FILE, json_file(l)), (MARKDOWN, markdown(l, tool, &created).into_bytes())];
    let listed: Vec<Value> = files.iter().map(|(n, b)| json!({ "name": n, "bytes": b.len(), "sha256": sha256(b), "criteria": if *n == "README.txt" { &[][..] } else { &["CC1.2", "CC4.2"][..] }, "checklist": [] })).collect();
    let manifest = json!({
        "product": "SuperBot",
        "kind": KIND,
        "format": FORMAT,
        "tool": tool,
        "createdAt": created,
        "period": { "from": p.from.to_string(), "to": p.to.to_string(), "days": p.days() },
        "store": { "bundles": i.store.len(), "verified": i.store.iter().filter(|(f, _)| f.verified()).count(), "read": l["store"]["bundlesRead"] },
        "results": l["testing"].as_array().into_iter().flatten().map(|t| json!({ "name": t["bundle"], "manifestSha256": t["manifestSha256"] })).collect::<Vec<_>>(),
        "since": l["since"].as_object().map(|s| json!({ "name": s.get("bundle"), "manifestSha256": s.get("manifestSha256") })),
        "checklistSha256": l["checklist"]["sha256"],
        "summary": l["summary"],
        "files": listed,
        "notIncluded": "anything the bundles read leave out; the store's other files; the register's records of each finding",
    });
    files.push(("manifest.json", json_file(&manifest)));
    let sums: String = files.iter().map(|(n, b)| format!("{}  {n}\n", sha256(b))).collect();
    let manifest_sha256 = sha256(&files.last().expect("the manifest").1);
    files.push(("SHA256SUMS", sums.into_bytes()));
    let entries: Vec<(String, Vec<u8>)> = files.iter().map(|(n, b)| (format!("{name}/{n}"), b.clone())).collect();
    let tar = crate::ustar::tar(&entries, (now_ms / 1000).max(0) as u64);
    Bundle { sha256: sha256(&tar), manifest_sha256, name, tar }
}

// The command

pub const USAGE: &str = "  superbot-evidence deficiencies <evidence store> [--from <YYYY-MM-DD> --to <YYYY-MM-DD>]
                    [--checklist <soc2-readiness-checklist.md>] [--results <results bundle>]...
                    [--since <previous deficiency log>] [-o <file>]";

#[derive(Debug, Default, PartialEq)]
struct Args {
    store: String,
    from: Option<String>,
    to: Option<String>,
    checklist: Option<String>,
    results: Vec<String>,
    since: Option<String>,
    out: Option<String>,
}

fn parse_args(args: &[String]) -> Result<Args, String> {
    let mut a = Args::default();
    let mut it = args.iter();
    let value = |it: &mut std::slice::Iter<String>, flag: &str| it.next().filter(|v| !v.starts_with("--") && !v.is_empty()).cloned().ok_or(format!("{flag} needs a value"));
    while let Some(flag) = it.next() {
        let slot = match flag.as_str() {
            "--from" => &mut a.from,
            "--to" => &mut a.to,
            "--checklist" => &mut a.checklist,
            "--since" => &mut a.since,
            "-o" | "--out" => &mut a.out,
            "--results" => {
                let v = value(&mut it, flag)?;
                if a.results.contains(&v) {
                    return Err(format!("--results {v} is given twice"));
                }
                a.results.push(v);
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
        *slot = Some(value(&mut it, flag)?);
    }
    if a.store.is_empty() {
        return Err(format!("Give the evidence store's folder.\n\n{USAGE}"));
    }
    Ok(a)
}

/// The files the log reads from each bundle in the store.
fn keep() -> Vec<&'static str> {
    let mut k: Vec<&str> = coverage::EXCEPTION_FILES.to_vec();
    k.push("manifest.json");
    k
}

pub fn run(args: &[String], now: chrono::DateTime<chrono::Utc>) -> Result<(String, bool), String> {
    let a = parse_args(args)?;
    let p = Period::parse(a.from.as_deref(), a.to.as_deref(), now.date_naive())?;
    let checklist = match &a.checklist {
        None => None,
        Some(c) => {
            if std::fs::metadata(c).map_err(|e| format!("{c}: {e}"))?.len() > MAX_CHECKLIST {
                return Err(format!("{c} is over {} MiB, larger than any checklist", MAX_CHECKLIST >> 20));
            }
            let md = std::fs::read_to_string(c).map_err(|e| format!("{c}: {e}"))?;
            if checklist(&md).is_empty() {
                return Err(format!("{c} has no checklist rows: give docs/security/soc2-readiness-checklist.md"));
            }
            Some(md)
        }
    };
    let results: Vec<(String, Files)> = a.results.iter().map(|r| sample::read_made(Path::new(r), sample::RESULTS_PREFIX, RESULTS, &[sample::RESULTS_FILE], "results")).collect::<Result<_, _>>()?;
    let since = a.since.as_deref().map(|s| sample::read_made(Path::new(s), PREFIX, KIND, &[FILE], "deficiency log")).transpose()?;
    let (store, other) = coverage::scan_keeping(Path::new(&a.store), &keep())?;
    let inputs = Inputs { store: &store, other: &other, results: &results, since: since.as_ref(), checklist: checklist.as_deref() };
    let l = log(&inputs, &p, now.timestamp_millis())?;
    let b = build(&l, &inputs, &p, now.timestamp_millis());
    let file = a.out.clone().unwrap_or_else(|| format!("{}.tar", b.name));
    crate::save_private(&file, &b.tar)?;
    let s = &l["summary"];
    let clean = s["stillListed"] == 0 && s["storeComplete"] == true;
    let owners: Vec<String> = s["stillListedByOwner"].as_object().into_iter().flatten().map(|(o, n)| format!("  {o}: {n}")).collect();
    Ok((
        format!(
            "Saved {file} ({} KB): {} to {} (not included), {} findings from {} bundles that check, {} still listed, {} no longer listed; the store {}.\n{}Manifest SHA-256: {}\nBundle SHA-256: {}\nRecord each finding still listed in the policy register, and keep the log with the management review's minutes.",
            b.tar.len().div_ceil(1024),
            p.from,
            p.to,
            s["findings"],
            l["store"]["bundlesRead"].as_array().map_or(0, Vec::len),
            s["stillListed"],
            s["noLongerListed"],
            if s["storeComplete"] == true { "is complete".to_string() } else { format!("has {} problems", s["storeProblems"]) },
            if owners.is_empty() { String::new() } else { format!("Still listed by owner:\n{}\n", owners.join("\n")) },
            b.manifest_sha256,
            b.sha256,
        ),
        clean,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(s: &str) -> chrono::NaiveDate {
        chrono::NaiveDate::parse_from_str(s, "%Y-%m-%d").unwrap()
    }

    fn p(from: &str, to: &str) -> Period {
        Period { from: d(from), to: d(to) }
    }

    /// A bundle of `kind` that checks, with `bodies` as its files and every other file its
    /// kind always has as `{}`; `repo` goes in its manifest's source.
    fn bundle(kind: &str, period: Period, made: &str, bodies: &[(&str, Value)], repo: Option<&str>) -> (Found, Files) {
        let k = coverage::KINDS.iter().find(|k| k.id == kind).unwrap();
        let name = format!("{}{}-{}", k.prefix, period.label(), made.replace(['-', ':'], ""));
        let mut files = Files::new();
        let mut listed = Vec::new();
        let mut all: Vec<(&str, &[&str], &[&str])> = coverage::expected(kind);
        for (f, _) in bodies {
            if !all.iter().any(|(x, _, _)| x == f) {
                all.push((f, &[], &[]));
            }
        }
        for (f, criteria, rows) in all {
            let b = bodies.iter().find(|(x, _)| *x == f).map_or_else(|| json_file(&json!({})), |(_, v)| json_file(v));
            listed.push(json!({ "name": f, "sha256": sha256(&b), "criteria": criteria, "checklist": rows }));
            files.insert(f.into(), b);
        }
        let mut manifest = json!({ "product": "SuperBot", "format": k.format, "createdAt": made, "period": { "from": period.from.to_string(), "to": period.to.to_string(), "days": period.days() }, "files": listed, "source": { "repository": repo } });
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

    fn reg(month: &str, to: &str, incidents: Value) -> (Found, Files) {
        bundle("policy-register", p(&format!("{month}-01"), to), &format!("{to}T09:00:00Z"), &[("incidents.json", json!({ "exceptions": incidents }))], None)
    }

    fn prs(month: &str, to: &str, repo: &str, missing: Value) -> (Found, Files) {
        bundle("change-management", p(&format!("{month}-01"), to), &format!("{to}T03:00:00Z"), &[("pull-requests.json", json!({ "exceptions": { "noIndependentApproval": missing, "requiredChecksNotPassed": null } }))], Some(repo))
    }

    fn store() -> Vec<(Found, Files)> {
        vec![
            reg("2027-01", "2027-02-01", json!({ "reviewOverdue": ["INC-1 (closed 2027-01-04, not reviewed, due 2027-01-18)"], "actionOverdue": ["A-1 of incident INC-1 (Operator, due 2027-01-20)"] })),
            reg("2027-02", "2027-03-01", json!({ "reviewOverdue": ["INC-1 (closed 2027-01-04, not reviewed, due 2027-01-18)"], "actionOverdue": [] })),
            reg("2027-03", "2027-04-01", json!({ "reviewOverdue": ["INC-1 (closed 2027-01-04, not reviewed, due 2027-01-18)", "INC-4 (closed 2027-03-02, not reviewed, due 2027-03-16)"], "actionOverdue": [] })),
            prs("2027-01", "2027-02-01", "o/r", json!([101, 102])),
            prs("2027-02", "2027-03-01", "o/r", json!([])),
            prs("2027-03", "2027-04-01", "o/r", json!([130])),
            prs("2027-01", "2027-02-01", "o/other", json!([101])),
        ]
    }

    fn quarter() -> Period {
        p("2027-01-01", "2027-04-01")
    }

    fn inputs<'a>(st: &'a [(Found, Files)], checklist: Option<&'a str>) -> Inputs<'a> {
        Inputs { store: st, other: &[], results: &[], since: None, checklist }
    }

    fn find<'a>(l: &'a Value, source: &str, item: &str) -> &'a Value {
        l["findings"].as_array().unwrap().iter().find(|f| f["source"] == source && f["item"] == item).unwrap_or_else(|| panic!("{source} {item}: {}", l["findings"]))
    }

    const CHECKLIST: &str = "| ID | Item | Kind | Owner | Evidence to collect | Status | Where it stands |\n|----|------|------|-------|----|----|----|\n| CC7.3-1 | Triage | Process | Security owner | x | Partial | y |\n| CC7.5-1 | Post-incident reviews | Process | Security owner | x | Gap | y |\n| CC7.4-1 | Plan | Process | Security owner | x | Partial | y |\n| CC7.4-2 | Notices | Process | Privacy lead | x | Partial | y |\n| CC8.1-1 | Branch protection | Process | Engineering lead | x | Gap | y |\n| CC8.1-2 | Policy | Process | Engineering lead | x | Partial | y |\n| CC3.4-1 | Changes | Process | Engineering lead | x | Partial | y |\n| CC8.1-3 | Notes | Process | Engineering lead | x | Done | y |\n";

    #[test]
    fn items_are_tracked_by_their_id_not_their_state() {
        let (jan, feb) = (p("2027-01-01", "2027-02-01"), p("2027-02-01", "2027-03-01"));
        let key = |v: Value| key(&v, &jan);
        assert_eq!(key(json!("CHG-2 emergency on hosting (made 2027-01-06, not reviewed, due 2027-01-08)")), "CHG-2 emergency on hosting");
        assert_eq!(key(json!("p-1 on github (user): left 2027-01-05, not removed")), "p-1 on github");
        assert_eq!(key(json!("botd-1 on 2027-01-10: no sign-off")), "botd-1 on 2027-01-10: no sign-off");
        assert_eq!(key(json!("linode: AR-1 (soc2-type2) covers to 2027-01-10")), "linode: AR-1");
        assert_eq!(key(json!(" (odd)")), "(odd)");
        assert_eq!(key(json!(101)), "101");
        assert_eq!(key(json!({ "id": "SuperBotDown-1", "minutes": 12 })), "SuperBotDown-1");
        assert_eq!(key(json!({ "number": 7, "source": "dependabot" })), "7");
        assert_eq!(key(json!({ "from": "2027-01-03T00:00:00Z" })), r#"{"from":"2027-01-03T00:00:00Z"}"#);
        // A condition that runs on is one finding from month to month.
        assert_eq!(key(json!("Engineering lead: 2027-01-01 to 2027-02-01")), "Engineering lead");
        assert_eq!(super::key(&json!("Engineering lead: 2027-02-01 to 2027-03-01"), &feb), "Engineering lead");
        assert_eq!(key(json!("none in the year to 2027-02-01")), "none in the year to <period end>");
        assert_eq!(super::key(&json!("none in the year to 2027-03-01"), &feb), "none in the year to <period end>");
        assert_eq!(finding_id("a", None, "f", "l", "k"), finding_id("a", None, "f", "l", "k"));
        assert_ne!(finding_id("a", Some("o/r"), "f", "l", "k"), finding_id("a", Some("o/s"), "f", "l", "k"));
        assert_eq!(finding_id("a", None, "f", "l", "k").len(), 16);
    }

    #[test]
    fn a_finding_is_still_listed_only_while_the_newest_bundle_of_its_source_lists_it() {
        let st = store();
        let l = log(&inputs(&st, Some(CHECKLIST)), &quarter(), 0).unwrap();
        let inc1 = find(&l, "policy-register", "INC-1");
        assert_eq!((inc1["stillListed"].as_bool(), inc1["listedIn"].as_u64()), (Some(true), Some(3)));
        assert_eq!(inc1["firstListed"]["from"], "2027-01-01");
        assert_eq!(inc1["lastListed"]["from"], "2027-03-01");
        assert_eq!(inc1["asLastListed"], "INC-1 (closed 2027-01-04, not reviewed, due 2027-01-18)");
        assert_eq!(inc1["rows"], json!(["CC7.3-1", "CC7.4-1", "CC7.4-2", "CC7.5-1"]));
        assert_eq!(inc1["owners"], json!(["Privacy lead", "Security owner"]));
        let a1 = find(&l, "policy-register", "A-1 of incident INC-1");
        assert_eq!((a1["stillListed"].as_bool(), a1["lastListed"]["to"].as_str()), (Some(false), Some("2027-02-01")), "February's bundle no longer lists it");
        assert_eq!(find(&l, "policy-register", "INC-4")["firstListed"]["from"], "2027-03-01");

        let pr101 = l["findings"].as_array().unwrap().iter().filter(|f| f["item"] == "101").collect::<Vec<_>>();
        assert_eq!(pr101.len(), 2, "o/r#101 and o/other#101 are two findings");
        let ours = pr101.iter().find(|f| f["scope"] == "o/r").unwrap();
        assert_eq!(ours["stillListed"], false, "o/r's March bundle doesn't list it");
        let theirs = pr101.iter().find(|f| f["scope"] == "o/other").unwrap();
        assert_eq!(theirs["stillListed"], true, "o/other's newest bundle is January's, which lists it");
        assert_eq!(find(&l, "change-management", "130")["owners"], json!(["Engineering lead"]));

        let s = &l["summary"];
        assert_eq!((s["findings"].as_u64(), s["stillListed"].as_u64(), s["noLongerListed"].as_u64()), (Some(7), Some(4), Some(3)));
        assert_eq!(s["stillListedByOwner"], json!({ "Engineering lead": 2, "Privacy lead": 2, "Security owner": 2 }));
        assert_eq!(s["stillListedBySource"], json!({ "change-management": 2, "policy-register": 2 }));
        let first_closed = l["findings"].as_array().unwrap().iter().position(|f| f["stillListed"] == false).unwrap();
        assert!(l["findings"].as_array().unwrap()[first_closed..].iter().all(|f| f["stillListed"] == false), "still listed first");
        assert!(l["findings"].as_array().unwrap().iter().all(|f| f["exception"] != "requiredChecksNotPassed"), "a list that is null says nothing");

        let c = &l["checklist"];
        assert_eq!((c["rows"].as_u64(), c["open"].as_array().unwrap().len()), (Some(8), 7));
        assert_eq!(c["openByOwner"]["Engineering lead"], json!(["CC3.4-1", "CC8.1-1", "CC8.1-2"]));
        assert_eq!(s["openChecklistRows"], 7);

        let none = log(&inputs(&st, None), &quarter(), 0).unwrap();
        assert_eq!(find(&none, "policy-register", "INC-1")["owners"], json!([]));
        assert!(none["checklist"].is_null() && none["summary"]["openChecklistRows"].is_null());
    }

    #[test]
    fn only_bundles_that_check_and_overlap_the_period_count() {
        let mut st = store();
        let (f, files) = &mut st[2];
        files.insert("incidents.json".into(), json_file(&json!({ "exceptions": { "reviewOverdue": [] } })));
        *f = coverage::check(f.path.clone(), &f.name.clone(), files);
        assert!(!f.verified());
        let l = log(&inputs(&st, None), &quarter(), 0).unwrap();
        assert_eq!(find(&l, "policy-register", "INC-1")["lastListed"]["from"], "2027-02-01", "March's changed bundle isn't read");
        assert!(l["findings"].as_array().unwrap().iter().all(|f| f["item"] != "INC-4"));
        assert_eq!(l["summary"]["storeComplete"], false);
        assert!(l["store"]["problems"].as_array().unwrap().iter().any(|x| x.as_str().unwrap().contains("changed after the bundle was made")), "{}", l["store"]["problems"]);

        let january = log(&inputs(&store(), None), &p("2027-01-01", "2027-02-01"), 0).unwrap();
        assert_eq!(find(&january, "policy-register", "A-1 of incident INC-1")["stillListed"], true, "January's bundle is the newest of January");
        assert_eq!(january["store"]["bundlesRead"].as_array().unwrap().len(), 3);
    }

    #[test]
    fn evidence_bundles_of_the_latest_period_all_count_as_newest() {
        let ev = |made: &str, devs: Value| bundle("evidence", p("2027-03-01", "2027-04-01"), made, &[("baseline.json", json!({ "exceptions": { "deviations": devs, "excepted": [] } }))], None);
        let st = vec![
            bundle("evidence", p("2027-02-01", "2027-03-01"), "2027-03-01T00:05:00Z", &[("baseline.json", json!({ "exceptions": { "deviations": ["AUTH_MFA", "TEAMS"] } }))], None),
            ev("2027-04-01T00:05:00Z", json!(["AUTH_MFA"])),
            ev("2027-04-01T00:06:00Z", json!([])),
        ];
        let l = log(&inputs(&st, Some("| CC5.1-1 | Baseline | Process | Operator | x | Partial | y |\n")), &quarter(), 0).unwrap();
        let mfa = find(&l, "evidence", "AUTH_MFA");
        assert_eq!(mfa["stillListed"], true, "another server's March bundle doesn't clear it");
        assert_eq!(mfa["rows"], json!(["CC5.1-1"]));
        assert_eq!(mfa["owners"], json!(["Operator"]));
        assert_eq!(mfa["newestBundles"].as_array().unwrap().len(), 2);
        assert_eq!(find(&l, "evidence", "TEAMS")["stillListed"], false);
    }

    fn results(name: &str, tested: (&str, &str), made: &str, deviations: Value) -> (String, Files) {
        let r = json!({ "summary": { "sampled": 3, "tested": 3, "deviations": deviations.as_array().unwrap().len(), "untested": 0 }, "exceptions": { "deviations": deviations, "untested": [], "populationsIncomplete": ["pages"] } });
        let mut files = Files::new();
        files.insert(sample::RESULTS_FILE.into(), json_file(&r));
        files.insert("manifest.json".into(), json_file(&json!({ "product": "SuperBot", "kind": RESULTS, "createdAt": made, "period": { "from": tested.0, "to": tested.1 }, "samples": { "name": "superbot-samples-x" } })));
        (name.to_string(), files)
    }

    #[test]
    fn control_testing_deviations_are_findings_of_their_tests_rows() {
        let st = store();
        let rs = vec![
            results("superbot-results-2027-01-01_2027-04-01-20270405T100000Z", ("2027-01-01", "2027-04-01"), "2027-04-05T10:00:00Z", json!(["access-grants p-c/hosting/admin/2027-01-05", "merged-pull-requests o/r#7"])),
            results("superbot-results-2027-01-01_2027-04-01-20270410T100000Z", ("2027-01-01", "2027-04-01"), "2027-04-10T10:00:00Z", json!(["access-grants p-c/hosting/admin/2027-01-05"])),
        ];
        let i = Inputs { store: &st, other: &[], results: &rs, since: None, checklist: Some("| CC6.2-2 | Grants | Process | Security owner | x | Partial | y |\n") };
        let l = log(&i, &quarter(), 0).unwrap();
        let grant = find(&l, RESULTS, "access-grants p-c/hosting/admin/2027-01-05");
        assert_eq!((grant["stillListed"].as_bool(), grant["rows"].clone(), grant["owners"].clone()), (Some(true), json!(["CC6.2-2"]), json!(["Security owner"])));
        assert_eq!(grant["scope"], "2027-01-01_2027-04-01");
        assert_eq!(find(&l, RESULTS, "merged-pull-requests o/r#7")["stillListed"], false, "the newer results of the same samples no longer list it");
        assert_eq!(find(&l, RESULTS, "pages")["rows"], json!(["CC7.2-1"]));
        assert_eq!(l["summary"]["testingDeviations"], 1);
        assert_eq!(l["testing"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn since_says_what_was_put_right_and_what_is_new() {
        let st = store();
        let first = log(&inputs(&st[..2], None), &p("2027-01-01", "2027-03-01"), 0).unwrap();
        let prev_files = Files::from([(FILE.to_string(), json_file(&first)), ("manifest.json".to_string(), json_file(&json!({ "period": first["periodCovered"] })))]);
        let prev = ("superbot-deficiencies-2027-01-01_2027-03-01-x".to_string(), prev_files);
        let i = Inputs { store: &st, other: &[], results: &[], since: Some(&prev), checklist: None };
        let l = log(&i, &quarter(), 0).unwrap();
        let id = |item: &str| find(&l, "policy-register", item)["id"].as_str().unwrap().to_string();
        assert_eq!(l["since"]["stillListed"], json!([id("INC-1")]));
        assert!(l["since"]["noLongerListed"].as_array().unwrap().is_empty(), "A-1 was no longer listed already");
        let new = l["since"]["new"].as_array().unwrap();
        assert!(new.contains(&json!(id("INC-4"))) && !new.contains(&json!(id("INC-1"))));
        assert_eq!(new.len(), 5, "INC-4 and the four pull requests");
    }

    #[test]
    fn the_markdown_groups_what_is_still_listed_by_owner() {
        let st = store();
        let l = log(&inputs(&st, Some(CHECKLIST)), &quarter(), 0).unwrap();
        let md = markdown(&l, "superbot-evidence test", "2027-04-02T00:00:00Z");
        assert!(md.contains("**4 findings still listed**"), "{md}");
        assert!(md.contains("### Engineering lead\n") && md.contains("### Privacy lead, Security owner\n"), "{md}");
        assert!(md.contains("## No longer listed"));
        assert!(md.contains("| Engineering lead | CC3.4-1, CC8.1-1, CC8.1-2 |"));
        assert!(md.contains("INC-1 (closed 2027-01-04, not reviewed, due 2027-01-18)"));
        assert!(md.contains("not a SOC 2 opinion"));
        assert_eq!(cell("a|b\nc"), "a\\|b c");
        assert_eq!(cell(&"x".repeat(MAX_SHOWN + 5)).chars().count(), MAX_SHOWN + 1);
    }

    #[test]
    fn the_bundle_checks_against_its_own_digests() {
        let st = store();
        let i = inputs(&st, None);
        let l = log(&i, &quarter(), 1_806_000_000_000).unwrap();
        let b = build(&l, &i, &quarter(), 1_806_000_000_000);
        assert!(b.name.starts_with("superbot-deficiencies-2027-01-01_2027-04-01-"));
        let entries = coverage::untar(&b.tar).unwrap();
        let files: Files = entries.into_iter().map(|(n, x)| (n.split_once('/').unwrap().1.to_string(), x)).collect();
        let dir = std::env::temp_dir().join(format!("superbot-deficiencies-unit-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let folder = dir.join(&b.name);
        std::fs::create_dir_all(&folder).unwrap();
        for (n, x) in &files {
            std::fs::write(folder.join(n), x).unwrap();
        }
        let (name, read) = sample::read_made(&folder, PREFIX, KIND, &[FILE], "deficiency log").unwrap();
        assert_eq!(name, b.name);
        assert_eq!(sha256(&read["manifest.json"]), b.manifest_sha256);
        let m: Value = serde_json::from_slice(&read["manifest.json"]).unwrap();
        assert_eq!(m["files"].as_array().unwrap().iter().map(|f| f["name"].as_str().unwrap()).collect::<Vec<_>>(), vec!["README.txt", FILE, MARKDOWN]);
        assert_eq!(m["store"]["read"].as_array().unwrap().len(), 7);
        std::fs::write(folder.join(FILE), b"{}").unwrap();
        assert!(sample::read_made(&folder, PREFIX, KIND, &[FILE], "deficiency log").unwrap_err().contains("doesn't check"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn options() {
        let args = |s: &[&str]| s.iter().map(|x| x.to_string()).collect::<Vec<_>>();
        let a = parse_args(&args(&["store", "--from", "2027-01-01", "--to", "2027-04-01", "--checklist", "c.md", "--results", "r1", "--results", "r2", "--since", "prev.tar", "-o", "x.tar"])).unwrap();
        assert_eq!((a.store.as_str(), a.results.len(), a.since.as_deref(), a.checklist.as_deref()), ("store", 2, Some("prev.tar"), Some("c.md")));
        for bad in [&[][..], &["store", "--since", "a", "--since", "b"], &["store", "--results", "r", "--results", "r"], &["store", "--bogus"], &["store", "--checklist"]] {
            assert!(parse_args(&args(bad)).is_err(), "{bad:?}");
        }
    }

    /// Every file whose exceptions the log reads is one a kind of bundle has, so each
    /// finding names its rows.
    #[test]
    fn every_exception_file_maps_to_its_controls() {
        for file in coverage::EXCEPTION_FILES {
            assert!(coverage::KINDS.iter().any(|k| !controls(k.id, file).1.is_empty()), "{file} names no rows for any kind");
        }
        for t in &sample::TESTS {
            assert_eq!(tested(&format!("{} some-item", t.id)).1, t.rows.iter().map(|r| r.to_string()).collect::<Vec<_>>());
        }
    }
}
