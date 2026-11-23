//! The security pack (`docs/security/`, #41) is read by buyers outside the repo, so a
//! broken link there is a broken promise. Every relative link in it must name a file
//! or folder that exists, and every `#anchor` into a Markdown file a heading in it.
//! External (`https:`, `mailto:`) links aren't fetched. Unlinked references count too:
//! every `ADR NNNN` must name an ADR that exists, and every repository path in inline code
//! (`server/src/...`) a file that exists. The SOC 2 control mapping must also keep one
//! row, with a status, for every criterion it claims to cover, and the readiness
//! checklist (#50) a well-formed row for every gap the mapping lists. The legal templates
//! (#48) and the DPIA template (#58) must say they are drafts for legal review and not
//! legal advice, claim no certification, and keep the provider's details as placeholders.
//! The policy set (`docs/security/policies/`, #57, ADR 0130) is checked like the rest of
//! the pack, and each policy must name a role as its owner, a review cadence and only
//! checklist items that exist; the Type II evidence plan must keep a row for every
//! criterion and list every checklist row under its own criterion.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..")
}

fn pack() -> PathBuf {
    repo().join("docs/security")
}

/// The text outside fenced code blocks and inline code spans.
fn prose(md: &str) -> Vec<(usize, String)> {
    let mut fenced = false;
    let mut out = Vec::new();
    for (i, line) in md.lines().enumerate() {
        if line.trim_start().starts_with("```") {
            fenced = !fenced;
            continue;
        }
        if fenced {
            continue;
        }
        let mut text = String::new();
        let mut code = false;
        for c in line.chars() {
            if c == '`' {
                code = !code;
            } else if !code {
                text.push(c);
            }
        }
        out.push((i + 1, text));
    }
    out
}

/// Targets of inline links, `[text](target)`, with their line numbers.
fn links(md: &str) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    for (n, line) in prose(md) {
        let mut rest = line.as_str();
        while let Some(at) = rest.find("](") {
            let after = &rest[at + 2..];
            let Some(end) = after.find(')') else { break };
            let target = after[..end].split_whitespace().next().unwrap_or("").to_string();
            out.push((n, target));
            rest = &after[end..];
        }
    }
    out
}

/// GitHub's anchor for a heading: lower case, punctuation dropped, spaces to hyphens,
/// and `-1`, `-2`, ... on repeats.
fn anchors(md: &str) -> HashSet<String> {
    let mut seen: HashMap<String, usize> = HashMap::new();
    let mut out = HashSet::new();
    let mut fenced = false;
    for line in md.lines() {
        if line.trim_start().starts_with("```") {
            fenced = !fenced;
        }
        if fenced || !line.starts_with('#') {
            continue;
        }
        let title = line.trim_start_matches('#').trim();
        let slug: String = title
            .to_lowercase()
            .chars()
            .filter(|c| c.is_alphanumeric() || *c == ' ' || *c == '-' || *c == '_')
            .map(|c| if c == ' ' { '-' } else { c })
            .collect();
        let n = seen.entry(slug.clone()).or_insert(0);
        out.insert(if *n == 0 { slug.clone() } else { format!("{slug}-{n}") });
        *n += 1;
    }
    out
}

fn broken(file: &Path) -> Vec<String> {
    let md = fs::read_to_string(file).unwrap();
    let mut bad = Vec::new();
    for (line, target) in links(&md) {
        if target.is_empty() || target.contains("://") || target.starts_with("mailto:") {
            continue;
        }
        let (path, anchor) = match target.split_once('#') {
            Some((p, a)) => (p, Some(a)),
            None => (target.as_str(), None),
        };
        let resolved = if path.is_empty() { file.to_path_buf() } else { file.parent().unwrap().join(path) };
        let at = format!("{}:{line}: {target}", file.file_name().unwrap().to_string_lossy());
        if !resolved.exists() {
            bad.push(format!("{at} (no such file)"));
            continue;
        }
        if let Some(a) = anchor
            && resolved.extension().is_some_and(|e| e == "md")
            && !anchors(&fs::read_to_string(&resolved).unwrap()).contains(a)
        {
            bad.push(format!("{at} (no such heading)"));
        }
    }
    let name = file.file_name().unwrap().to_string_lossy();
    let adrs = fs::read_dir(repo().join("docs/adr")).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().into_owned()).collect::<Vec<_>>();
    for (line, n) in adr_refs(&md) {
        if !adrs.iter().any(|f| f.starts_with(&format!("{n}-")) && f.ends_with(".md")) {
            bad.push(format!("{name}:{line}: ADR {n} (no such ADR)"));
        }
    }
    for (line, p) in path_refs(&md) {
        if !repo().join(&p).exists() {
            bad.push(format!("{name}:{line}: `{p}` (no such file)"));
        }
    }
    bad
}

/// `ADR NNNN` mentions in prose, linked or not, with their line numbers.
fn adr_refs(md: &str) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    for (n, line) in prose(md) {
        let mut rest = line.as_str();
        while let Some(at) = rest.find("ADR ") {
            let digits: String = rest[at + 4..].chars().take_while(char::is_ascii_digit).collect();
            if digits.len() == 4 {
                out.push((n, digits));
            }
            rest = &rest[at + 4..];
        }
    }
    out
}

/// Top-level folders of this repository, so `server/src/x.rs` in inline code is a path
/// to check while `actions/checkout@v4` or `/api/users` is not.
const REPO_DIRS: &[&str] = &["server/", "deploy/", "docs/", "apps/", "web/", "site/", ".github/", ".cargo/"];

/// Repository paths written as inline code outside fenced blocks, with their line numbers.
fn path_refs(md: &str) -> Vec<(usize, String)> {
    let mut fenced = false;
    let mut out = Vec::new();
    for (i, line) in md.lines().enumerate() {
        if line.trim_start().starts_with("```") {
            fenced = !fenced;
            continue;
        }
        if fenced {
            continue;
        }
        for span in line.split('`').skip(1).step_by(2) {
            if !span.is_empty() && !span.contains(char::is_whitespace) && REPO_DIRS.iter().any(|d| span.starts_with(d)) {
                out.push((i + 1, span.trim_end_matches('/').to_string()));
            }
        }
    }
    out
}

fn policies() -> PathBuf {
    pack().join("policies")
}

/// The Markdown files directly in `dir`, sorted.
fn markdown_in(dir: &Path) -> Vec<PathBuf> {
    let mut files: Vec<PathBuf> = fs::read_dir(dir)
        .unwrap_or_else(|_| panic!("{} exists", dir.display()))
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|e| e == "md"))
        .collect();
    files.sort();
    files
}

#[test]
fn every_link_in_the_security_pack_resolves() {
    let mut files = markdown_in(&pack());
    assert!(files.iter().any(|f| f.ends_with("README.md")), "docs/security/README.md indexes the pack");
    files.extend(markdown_in(&policies()));
    let bad: Vec<String> = files.iter().flat_map(|f| broken(f)).collect();
    assert!(bad.is_empty(), "broken links in docs/security:\n{}", bad.join("\n"));
}

/// The link targets in `index`, without anchors.
fn linked_from(index: &Path) -> HashSet<String> {
    let md = fs::read_to_string(index).unwrap();
    links(&md).into_iter().map(|(_, t)| t.split('#').next().unwrap().to_string()).collect()
}

#[test]
fn the_index_links_every_page_of_the_pack() {
    for (index, dir) in [(pack().join("README.md"), pack()), (policies().join("README.md"), policies())] {
        let linked = linked_from(&index);
        for file in markdown_in(&dir) {
            let name = file.file_name().unwrap().to_string_lossy().into_owned();
            if name != "README.md" {
                assert!(linked.contains(&name), "{} doesn't link {name}", index.display());
            }
        }
    }
    assert!(linked_from(&pack().join("README.md")).contains("policies/README.md"), "docs/security/README.md must link the policy set's index");
}

/// The AICPA 2017 Trust Services Criteria the SOC 2 mapping covers: Security (CC1-CC9),
/// Availability (A1) and Confidentiality (C1).
const CRITERIA: &[(&str, u32)] =
    &[("CC1", 5), ("CC2", 3), ("CC3", 4), ("CC4", 2), ("CC5", 3), ("CC6", 8), ("CC7", 5), ("CC8", 1), ("CC9", 2), ("A1", 3), ("C1", 2)];
const STATUSES: &[&str] = &["Product", "Operator", "Customer", "Gap"];

/// `(criterion id, status cell)` for each table row that starts with a criterion id.
fn criterion_rows(md: &str) -> Vec<(String, String)> {
    md.lines()
        .filter_map(|l| {
            let cells: Vec<&str> = l.strip_prefix('|')?.split('|').map(str::trim).collect();
            let id = cells.first()?.split_whitespace().next()?;
            let (group, n) = id.split_once('.')?;
            (CRITERIA.iter().any(|(g, _)| *g == group) && n.parse::<u32>().is_ok()).then(|| (id.to_string(), cells.get(1).unwrap_or(&"").to_string()))
        })
        .collect()
}

#[test]
fn the_soc2_mapping_covers_every_criterion_with_a_status() {
    let md = fs::read_to_string(pack().join("soc2-control-mapping.md")).expect("docs/security/soc2-control-mapping.md exists");
    let rows = criterion_rows(&md);
    let want: Vec<String> = CRITERIA.iter().flat_map(|(g, n)| (1..=*n).map(move |i| format!("{g}.{i}"))).collect();
    let got: Vec<String> = rows.iter().map(|(id, _)| id.clone()).collect();
    assert_eq!(got, want, "soc2-control-mapping.md must have one row per criterion, in order");
    for (id, status) in &rows {
        let parts: Vec<&str> = status.split(';').map(str::trim).collect();
        assert!(
            !parts.is_empty() && parts.iter().all(|p| STATUSES.contains(p)),
            "{id}: status `{status}` must be one or more of {STATUSES:?}, separated by `;`"
        );
    }
    assert!(md.contains("not SOC 2 certified"), "the mapping must say plainly that SuperBot is not certified");
}

const KINDS: &[&str] = &["Product", "Process"];
const OWNERS: &[&str] = &["Management", "Security owner", "Engineering lead", "Operator", "People lead", "Privacy lead"];
const CHECK_STATUSES: [&str; 3] = ["Done", "Partial", "Gap"];

/// A criterion id (`CC6.1`) or a whole area (`CC6`) that the mapping covers.
fn criterion(id: &str) -> Option<(&'static str, Option<u32>)> {
    let (group, n) = match id.split_once('.') {
        Some((g, n)) => (g, Some(n.parse::<u32>().ok()?)),
        None => (id, None),
    };
    let &(g, max) = CRITERIA.iter().find(|(g, _)| *g == group)?;
    n.is_none_or(|n| (1..=max).contains(&n)).then_some((g, n))
}

/// The checklist's rows, `| CC6.1-1 | item | kind | owner | evidence | status | where |`, as cells.
fn checklist_rows(md: &str) -> Vec<Vec<String>> {
    md.lines()
        .filter_map(|l| {
            let cells: Vec<String> = l.strip_prefix('|')?.trim_end().strip_suffix('|')?.split('|').map(|c| c.trim().to_string()).collect();
            let (id, n) = cells.first()?.split_once('-')?;
            (criterion(id).is_some_and(|(_, n)| n.is_some()) && n.parse::<u32>().is_ok()).then_some(cells)
        })
        .collect()
}

/// Criteria and areas named in the mapping's list of gaps for the checklist, with ranges
/// (`CC7.3 to CC7.5`) expanded to every criterion in them.
fn gap_list_criteria(mapping: &str) -> Vec<String> {
    let list = mapping.split("## Gaps for the SOC 2 readiness checklist").nth(1).unwrap_or("");
    let tokens: Vec<&str> = list.split(|c: char| !(c.is_ascii_alphanumeric() || c == '.')).map(|t| t.trim_end_matches('.')).filter(|t| !t.is_empty()).collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < tokens.len() {
        let Some((group, from)) = criterion(tokens[i]) else {
            i += 1;
            continue;
        };
        if let (Some(from), Some(&"to"), Some(Some((g, Some(to))))) = (from, tokens.get(i + 1), tokens.get(i + 2).map(|t| criterion(t)))
            && g == group
            && to >= from
        {
            out.extend((from..=to).map(|n| format!("{group}.{n}")));
            i += 3;
        } else {
            out.push(tokens[i].to_string());
            i += 1;
        }
    }
    out
}

#[test]
fn the_soc2_readiness_checklist_is_well_formed_and_covers_every_gap() {
    let md = fs::read_to_string(pack().join("soc2-readiness-checklist.md")).expect("docs/security/soc2-readiness-checklist.md exists");
    assert!(md.contains("not SOC 2 certified"), "the checklist must say plainly that SuperBot is not certified");
    let headings = anchors(&md);
    for h in ["summary", "before-engaging-an-auditor", "type-i-and-type-ii"] {
        assert!(headings.contains(h), "the checklist needs a `{h}` section");
    }

    let rows = checklist_rows(&md);
    assert!(!rows.is_empty(), "the checklist has no rows");
    let mut ids = HashSet::new();
    let mut counts: HashMap<&str, [usize; 3]> = HashMap::new();
    for r in &rows {
        let id = &r[0];
        assert_eq!(r.len(), 7, "{id}: a row has 7 cells: ID, item, kind, owner, evidence, status, where it stands");
        assert!(ids.insert(id.clone()), "{id}: duplicate ID");
        assert!(!r[1].is_empty() && !r[4].is_empty(), "{id}: needs an item and the evidence to collect");
        assert!(KINDS.contains(&r[2].as_str()), "{id}: kind `{}` must be one of {KINDS:?}", r[2]);
        assert!(OWNERS.contains(&r[3].as_str()), "{id}: owner `{}` must be one of {OWNERS:?}", r[3]);
        let status = CHECK_STATUSES.iter().position(|s| *s == r[5]).unwrap_or_else(|| panic!("{id}: status `{}` must be one of {CHECK_STATUSES:?}", r[5]));
        if status < 2 {
            let evidence = links(&r[6]).into_iter().any(|(_, t)| !t.contains("://"));
            assert!(evidence, "{id}: a {} row must link its evidence in the repository", r[5]);
        }
        let area = criterion(id.split_once('-').unwrap().0).unwrap().0;
        counts.entry(area).or_default()[status] += 1;
    }

    let mapping = fs::read_to_string(pack().join("soc2-control-mapping.md")).unwrap();
    let wanted = gap_list_criteria(&mapping);
    assert!(wanted.len() > 10, "found too few criteria in the mapping's gap list: {wanted:?}");
    for c in wanted {
        assert!(ids.iter().any(|id| id.starts_with(&format!("{c}-")) || id.starts_with(&format!("{c}."))), "the mapping lists a gap under {c}, but the checklist has no row for it");
    }

    for (area, _) in CRITERIA {
        let line = md.lines().find(|l| l.strip_prefix("| ").is_some_and(|l| l.starts_with(&format!("{area} ")))).unwrap_or_else(|| panic!("the summary has no {area} row"));
        let got: Vec<usize> = line.split('|').filter_map(|c| c.trim().parse().ok()).collect();
        let want = counts.get(area).copied().unwrap_or_default();
        assert_eq!(got, want.to_vec(), "summary for {area} must be done, partial, gap = {want:?}");
    }
}

/// Legal drafts in the pack (#48, #58) that a managed provider fills in and has reviewed.
const LEGAL_TEMPLATES: &[&str] = &["privacy-policy-template.md", "terms-of-service-outline.md", "dpa-template.md", "dpia-template.md"];

/// Lines that call something "certified" without a "not" or "no" shortly before it.
fn certification_claims(md: &str) -> Vec<usize> {
    let mut out = Vec::new();
    for (n, line) in prose(md) {
        let lower = line.to_lowercase();
        for (at, _) in lower.match_indices("certified") {
            let before = &lower[lower[..at].char_indices().rev().nth(59).map_or(0, |(i, _)| i)..at];
            if !before.split(|c: char| !c.is_alphanumeric()).any(|w| w == "not" || w == "no") {
                out.push(n);
            }
        }
    }
    out
}

#[test]
fn the_legal_templates_are_labelled_drafts_with_placeholders() {
    for name in LEGAL_TEMPLATES.iter().chain(&["gdpr-self-hosting.md"]) {
        let md = fs::read_to_string(pack().join(name)).unwrap_or_else(|_| panic!("docs/security/{name} exists"));
        let top = md.lines().take(6).collect::<Vec<_>>().join("\n").to_lowercase();
        assert!(top.contains("not legal advice"), "{name} must say near the top that it is not legal advice");
        assert_eq!(certification_claims(&md), Vec::<usize>::new(), "{name} must not claim a certification (lines listed)");
    }
    for name in LEGAL_TEMPLATES {
        let md = fs::read_to_string(pack().join(name)).unwrap();
        let top = md.lines().take(6).collect::<Vec<_>>().join("\n");
        assert!(top.contains("Draft for legal review"), "{name} must say near the top that it is a draft for legal review");
        for p in ["[Company legal name]", "[Registered address]", "[Contact email]"] {
            assert!(md.contains(p), "{name} must leave the provider's details as placeholders, such as {p}");
        }
    }
    let dpa = fs::read_to_string(pack().join("dpa-template.md")).unwrap();
    let headings = anchors(&dpa);
    for h in ["8-personal-data-breaches", "annex-ii-technical-and-organisational-measures", "annex-iii-subprocessors", "annex-iv-data-residency", "iv4-model-providers"] {
        assert!(headings.contains(h), "the DPA template needs a `{h}` section");
    }
    let annex = dpa.split("## Annex III").nth(1).unwrap_or("");
    assert!(links(annex).iter().any(|(_, t)| t == "subprocessors.md"), "the DPA's subprocessor annex must link subprocessors.md");
    let dpia = fs::read_to_string(pack().join("dpia-template.md")).unwrap();
    let headings = anchors(&dpia);
    for h in ["1-need-for-a-dpia", "2-the-processing", "4-necessity-and-proportionality", "5-risks", "6-measures-to-reduce-the-risks", "7-sign-off"] {
        assert!(headings.contains(h), "the DPIA template needs a `{h}` section");
    }
}

/// The policy set the checklist's CC5.3-1 asks for, plus acceptable use (ADR 0130).
const POLICIES: &[&str] = &[
    "information-security.md",
    "access-control.md",
    "change-management.md",
    "incident-response.md",
    "vendor-management.md",
    "business-continuity.md",
    "data-classification-and-retention.md",
    "acceptable-use.md",
];
const CADENCES: &[&str] = &["yearly", "quarterly", "monthly"];

/// A policy's header table, `| Field | Value |` rows before its first `## ` heading.
fn header(md: &str) -> HashMap<String, String> {
    md.lines()
        .take_while(|l| !l.starts_with("## "))
        .filter_map(|l| {
            let cells: Vec<&str> = l.strip_prefix('|')?.trim_end().strip_suffix('|')?.split('|').map(str::trim).collect();
            (cells.len() == 2).then(|| (cells[0].to_string(), cells[1].to_string()))
        })
        .collect()
}

/// Words that look like email addresses, so no policy names a person by one.
fn emails(md: &str) -> Vec<String> {
    md.split(|c: char| c.is_whitespace() || "()<>[]`,;\"'|".contains(c))
        .filter_map(|w| {
            let (user, host) = w.split_once('@')?;
            let host = host.trim_end_matches('.');
            (!user.is_empty() && host.contains('.') && !host.starts_with('.')).then(|| w.to_string())
        })
        .collect()
}

fn checklist_ids() -> HashSet<String> {
    let md = fs::read_to_string(pack().join("soc2-readiness-checklist.md")).unwrap();
    checklist_rows(&md).into_iter().map(|r| r[0].clone()).collect()
}

#[test]
fn the_policy_set_is_complete_and_well_formed() {
    let ids = checklist_ids();
    let index = fs::read_to_string(policies().join("README.md")).expect("docs/security/policies/README.md indexes the policy set");
    for name in std::iter::once("README.md").chain(POLICIES.iter().copied()) {
        let md = fs::read_to_string(policies().join(name)).unwrap_or_else(|_| panic!("docs/security/policies/{name} exists"));
        assert_eq!(certification_claims(&md), Vec::<usize>::new(), "{name} must not claim a certification (lines listed)");
        assert_eq!(emails(&md), Vec::<String>::new(), "{name} must name roles, never people: no email addresses");
        assert!(md.contains("not SOC 2 certified"), "{name} must say plainly that SuperBot is not certified");
    }
    assert!(index.to_lowercase().contains("drafts, not adopted"), "the policy index must say the policies are drafts until adopted");
    let mut covered = HashSet::new();
    for name in POLICIES {
        let md = fs::read_to_string(policies().join(name)).unwrap();
        let h = header(&md);
        let field = |f: &str| h.get(f).unwrap_or_else(|| panic!("{name}: its header table needs a `{f}` row"));
        assert!(OWNERS.contains(&field("Owner").as_str()), "{name}: owner `{}` must be a role from the checklist, one of {OWNERS:?}", field("Owner"));
        assert!(OWNERS.contains(&field("Approver").as_str()), "{name}: approver `{}` must be one of {OWNERS:?}", field("Approver"));
        let review = field("Review").to_lowercase();
        assert!(CADENCES.iter().any(|c| review.contains(c)), "{name}: review `{review}` must give a cadence, one of {CADENCES:?}");
        let status = field("Status");
        assert!(status.starts_with("Draft") || status.starts_with("Approved"), "{name}: status `{status}` must start with Draft or Approved");
        let controls: Vec<&str> = field("Controls").split(',').map(str::trim).filter(|c| !c.is_empty()).collect();
        assert!(!controls.is_empty(), "{name}: must name the checklist items it covers");
        for c in controls {
            assert!(ids.contains(c), "{name}: `{c}` isn't a row of the readiness checklist");
            covered.insert(c.to_string());
        }
    }
    for want in ["CC5.3-1", "CC7.3-1", "CC7.4-1", "CC7.5-1", "CC8.1-2", "CC9.1-2", "CC9.2-1", "C1.1-2"] {
        assert!(covered.contains(want), "no policy covers {want}, which asks for one");
    }

    let ir = fs::read_to_string(policies().join("incident-response.md")).unwrap();
    let headings = anchors(&ir);
    for h in ["severity-levels", "roles", "runbook", "communication", "post-incident-review", "testing-the-plan"] {
        assert!(headings.contains(h), "the incident response plan needs a `{h}` section");
    }
    for sev in ["SEV-1", "SEV-2", "SEV-3", "SEV-4"] {
        assert!(ir.contains(&format!("| {sev} ")), "the incident response plan's severity table needs a {sev} row");
    }

    let bcp = fs::read_to_string(policies().join("business-continuity.md")).unwrap();
    let targets = linked_from(&policies().join("business-continuity.md"));
    for want in ["../../ops/backup-restore.md", "../../ops/machine-recovery.md", "../machine-recovery-objectives.md"] {
        assert!(targets.contains(want), "the business continuity plan must link {want}");
    }
    assert!(bcp.contains("RPO") && bcp.contains("RTO"), "the business continuity plan must state its RPO and RTO");

    let dc = fs::read_to_string(policies().join("data-classification-and-retention.md")).unwrap();
    let cited: HashSet<String> = adr_refs(&dc).into_iter().map(|(_, n)| n).collect();
    for adr in ["0009", "0098", "0102", "0112"] {
        assert!(cited.contains(adr), "the data classification and retention policy must cite ADR {adr}");
    }
    assert!(linked_from(&policies().join("data-classification-and-retention.md")).contains("../data-flows.md"), "the data classification policy must link data flows");
}

#[test]
fn the_type_ii_evidence_plan_covers_every_criterion() {
    let md = fs::read_to_string(pack().join("soc2-evidence-plan.md")).expect("docs/security/soc2-evidence-plan.md exists");
    assert!(md.contains("not SOC 2 certified"), "the evidence plan must say plainly that SuperBot is not certified");
    assert_eq!(certification_claims(&md), Vec::<usize>::new(), "the evidence plan must not claim a certification (lines listed)");
    let rows: Vec<Vec<String>> = md
        .lines()
        .filter_map(|l| {
            let cells: Vec<String> = l.strip_prefix('|')?.trim_end().strip_suffix('|')?.split('|').map(|c| c.trim().to_string()).collect();
            criterion(cells.first()?.split_whitespace().next()?).is_some_and(|(_, n)| n.is_some()).then_some(cells)
        })
        .collect();
    let want: Vec<String> = CRITERIA.iter().flat_map(|(g, n)| (1..=*n).map(move |i| format!("{g}.{i}"))).collect();
    let got: Vec<String> = rows.iter().map(|r| r[0].split_whitespace().next().unwrap().to_string()).collect();
    assert_eq!(got, want, "soc2-evidence-plan.md must have one row per criterion, in order");
    let ids = checklist_ids();
    let mut listed = HashSet::new();
    for r in &rows {
        let c = r[0].split_whitespace().next().unwrap();
        assert_eq!(r.len(), 5, "{c}: a row has 5 cells: criterion, already produced, how it's collected, still manual, checklist rows");
        assert!(r[1..4].iter().all(|cell| !cell.is_empty()), "{c}: every cell needs something, even `None`");
        for id in r[4].split(',').map(str::trim).filter(|s| !s.is_empty()) {
            assert!(ids.contains(id), "{c}: `{id}` isn't a row of the readiness checklist");
            assert!(id.starts_with(&format!("{c}-")), "{c}: `{id}` belongs under its own criterion");
            listed.insert(id.to_string());
        }
    }
    let mut missing: Vec<&String> = ids.iter().filter(|id| !listed.contains(*id)).collect();
    missing.sort();
    assert!(missing.is_empty(), "the evidence plan must list every checklist row under its criterion; missing {missing:?}");
    for want in ["policies/README.md", "soc2-readiness-checklist.md"] {
        assert!(linked_from(&pack().join("soc2-evidence-plan.md")).contains(want), "the evidence plan must link {want}");
    }
}

/// The settings in the first column of the configuration baseline's table, in backticks.
fn baseline_settings(md: &str) -> Vec<String> {
    md.lines()
        .filter_map(|l| l.strip_prefix("| `"))
        .flat_map(|first| first.split(" |").next().unwrap_or_default().split(", ").map(|s| s.trim_matches('`').to_string()).collect::<Vec<_>>())
        .collect()
}

#[test]
fn the_configuration_baseline_names_only_documented_settings() {
    let md = fs::read_to_string(pack().join("configuration-baseline.md")).expect("docs/security/configuration-baseline.md exists");
    assert!(md.contains("not SOC 2 certified"), "the baseline must say plainly that SuperBot is not certified");
    assert_eq!(certification_claims(&md), Vec::<usize>::new(), "the baseline must not claim a certification (lines listed)");
    let documented = fs::read_to_string(repo().join(".env.example")).unwrap() + &fs::read_to_string(repo().join("deploy/README.md")).unwrap();
    let settings = baseline_settings(&md);
    assert!(settings.len() >= 15, "the baseline's table lists the settings: {settings:?}");
    for s in &settings {
        assert!(s.chars().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_'), "`{s}` isn't a setting's name");
        assert!(documented.contains(&format!("{s}=")) || documented.contains(&format!("`{s}`")), "the baseline names `{s}`, which neither .env.example nor deploy/README.md documents");
    }
    for want in ["AUTH_MFA", "SUPERBOT_BACKUP_ENCRYPTION", "SUPERBOT_DATABASE_ENCRYPTION", "SERVER_BACKUP_OFF_HOST", "MACHINE_FIREWALL", "MACHINE_BOT_USER", "MACHINE_TEAMMATE_USERS", "TEAMS"] {
        assert!(settings.iter().any(|s| s == want), "the baseline must set {want}, which the information security policy names");
    }
}

#[test]
fn the_checker_catches_what_it_should() {
    assert_eq!(baseline_settings("| Setting | x |\n| `A_B` | on |\n| `C`, `D_2` | x |\nnot `E`\n"), vec!["A_B", "C", "D_2"]);
    assert_eq!(certification_claims("We are SOC 2 certified.\nSuperBot is not SOC 2 certified.\nNo one here is certified.\n`certified`\n"), vec![1]);
    assert_eq!(adr_refs("See ADR 0089 and [ADR 0090](x.md), not ADR 12 or `ADR 0001`."), vec![(1, "0089".to_string()), (1, "0090".to_string())]);
    let md = "`server/src/a.rs` `actions/checkout@v4` `/api/x` `docs/sso/` `deploy/a b`\n```\n`web/x.js`\n```\n";
    assert_eq!(path_refs(md), vec![(1, "server/src/a.rs".to_string()), (1, "docs/sso".to_string())]);
    assert_eq!(criterion("CC6.1"), Some(("CC6", Some(1))));
    assert_eq!(criterion("CC1"), Some(("CC1", None)));
    assert_eq!(criterion("CC6.9"), None);
    assert_eq!(criterion("C2"), None);
    let rows = checklist_rows("| ID | Item |\n| CC6.1-1 | MFA | Product | Engineering lead | e | Gap | none |\n| CC6.9-1 | x |\n| A1.3 | x |\n");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0][5], "Gap");
    assert_eq!(
        gap_list_criteria("x CC9.9\n## Gaps for the SOC 2 readiness checklist (M4)\n1. MFA (CC6.1).\n2. Policies (CC1, CC7.3 to CC7.5, M4).\n3. Odd (CC2.3 to CC6.1, A1.3 to A1.2)."),
        vec!["CC6.1", "CC1", "CC7.3", "CC7.4", "CC7.5", "CC2.3", "CC6.1", "A1.3", "A1.2"]
    );
    let rows = criterion_rows("| Criterion | Status |\n| CC6.1 Access | Product; Gap | x |\n| CC10.1 No | Gap |\n| Not CC1.1 | Gap |\n");
    assert_eq!(rows, vec![("CC6.1".to_string(), "Product; Gap".to_string())]);
    let md = "# Data flows\n## At rest\n## At rest\n`[x](nope.md)`\n```\n[y](nope.md)\n```\n[z](#at-rest-1) [w](https://x.example)\n";
    assert_eq!(links(md), vec![(8, "#at-rest-1".to_string()), (8, "https://x.example".to_string())]);
    let a = anchors(md);
    assert!(a.contains("data-flows") && a.contains("at-rest") && a.contains("at-rest-1"));
    assert!(anchors("## Bots: a token for each run").contains("bots-a-token-for-each-run"));
    assert_eq!(emails("Ask ops@example.com, not @greptileai or user:<email> or a@b."), vec!["ops@example.com"]);
    let h = header("# P\n\n| Field | Value |\n|-------|-------|\n| Owner | Security owner |\n| Controls | CC5.3-1, CC7.4-1 |\n\n## Scope\n| Owner | Nobody |\n");
    assert_eq!(h.get("Owner").map(String::as_str), Some("Security owner"));
    assert_eq!(h.get("Controls").map(String::as_str), Some("CC5.3-1, CC7.4-1"));
}
