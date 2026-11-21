//! The security pack (`docs/security/`, #41) is read by buyers outside the repo, so a
//! broken link there is a broken promise. Every relative link in it must name a file
//! or folder that exists, and every `#anchor` into a Markdown file a heading in it.
//! External (`https:`, `mailto:`) links aren't fetched. Unlinked references count too:
//! every `ADR NNNN` must name an ADR that exists, and every repository path in inline code
//! (`server/src/...`) a file that exists. The SOC 2 control mapping must also keep one
//! row, with a status, for every criterion it claims to cover, and the readiness
//! checklist (#50) a well-formed row for every gap the mapping lists.

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

#[test]
fn every_link_in_the_security_pack_resolves() {
    let mut files: Vec<PathBuf> = fs::read_dir(pack())
        .expect("docs/security exists")
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|e| e == "md"))
        .collect();
    files.sort();
    assert!(files.iter().any(|f| f.ends_with("README.md")), "docs/security/README.md indexes the pack");
    let bad: Vec<String> = files.iter().flat_map(|f| broken(f)).collect();
    assert!(bad.is_empty(), "broken links in docs/security:\n{}", bad.join("\n"));
}

#[test]
fn the_index_links_every_page_of_the_pack() {
    let index = fs::read_to_string(pack().join("README.md")).unwrap();
    let linked: HashSet<String> = links(&index).into_iter().map(|(_, t)| t.split('#').next().unwrap().to_string()).collect();
    for entry in fs::read_dir(pack()).unwrap() {
        let name = entry.unwrap().file_name().to_string_lossy().into_owned();
        if name.ends_with(".md") && name != "README.md" {
            assert!(linked.contains(&name), "docs/security/README.md doesn't link {name}");
        }
    }
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

/// Criteria and areas named in the mapping's list of gaps for the checklist.
fn gap_list_criteria(mapping: &str) -> Vec<String> {
    let list = mapping.split("## Gaps for the SOC 2 readiness checklist").nth(1).unwrap_or("");
    list.split(|c: char| !(c.is_ascii_alphanumeric() || c == '.'))
        .map(|t| t.trim_end_matches('.'))
        .filter(|t| criterion(t).is_some())
        .map(str::to_string)
        .collect()
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

#[test]
fn the_checker_catches_what_it_should() {
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
    assert_eq!(gap_list_criteria("x CC9.9\n## Gaps for the SOC 2 readiness checklist (M4)\n1. MFA (CC6.1).\n2. Policies (CC1, CC7.3 to CC7.5, M4)."), vec!["CC6.1", "CC1", "CC7.3", "CC7.5"]);
    let rows = criterion_rows("| Criterion | Status |\n| CC6.1 Access | Product; Gap | x |\n| CC10.1 No | Gap |\n| Not CC1.1 | Gap |\n");
    assert_eq!(rows, vec![("CC6.1".to_string(), "Product; Gap".to_string())]);
    let md = "# Data flows\n## At rest\n## At rest\n`[x](nope.md)`\n```\n[y](nope.md)\n```\n[z](#at-rest-1) [w](https://x.example)\n";
    assert_eq!(links(md), vec![(8, "#at-rest-1".to_string()), (8, "https://x.example".to_string())]);
    let a = anchors(md);
    assert!(a.contains("data-flows") && a.contains("at-rest") && a.contains("at-rest-1"));
    assert!(anchors("## Bots: a token for each run").contains("bots-a-token-for-each-run"));
}
