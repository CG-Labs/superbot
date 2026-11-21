//! The security pack (`docs/security/`, #41) is read by buyers outside the repo, so a
//! broken link there is a broken promise. Every relative link in it must name a file
//! or folder that exists, and every `#anchor` into a Markdown file a heading in it.
//! External (`https:`, `mailto:`) links aren't fetched. The SOC 2 control mapping must
//! also keep one row, with a status, for every criterion it claims to cover.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

fn pack() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../docs/security")
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
    bad
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

#[test]
fn the_checker_catches_what_it_should() {
    let rows = criterion_rows("| Criterion | Status |\n| CC6.1 Access | Product; Gap | x |\n| CC10.1 No | Gap |\n| Not CC1.1 | Gap |\n");
    assert_eq!(rows, vec![("CC6.1".to_string(), "Product; Gap".to_string())]);
    let md = "# Data flows\n## At rest\n## At rest\n`[x](nope.md)`\n```\n[y](nope.md)\n```\n[z](#at-rest-1) [w](https://x.example)\n";
    assert_eq!(links(md), vec![(8, "#at-rest-1".to_string()), (8, "https://x.example".to_string())]);
    let a = anchors(md);
    assert!(a.contains("data-flows") && a.contains("at-rest") && a.contains("at-rest-1"));
    assert!(anchors("## Bots: a token for each run").contains("bots-a-token-for-each-run"));
}
