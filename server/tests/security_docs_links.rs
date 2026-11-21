//! The security pack (`docs/security/`, #41) is read by buyers outside the repo, so a
//! broken link there is a broken promise. Every relative link in it must name a file
//! or folder that exists, and every `#anchor` into a Markdown file a heading in it.
//! External (`https:`, `mailto:`) links aren't fetched.

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

#[test]
fn the_checker_catches_what_it_should() {
    let md = "# Data flows\n## At rest\n## At rest\n`[x](nope.md)`\n```\n[y](nope.md)\n```\n[z](#at-rest-1) [w](https://x.example)\n";
    assert_eq!(links(md), vec![(8, "#at-rest-1".to_string()), (8, "https://x.example".to_string())]);
    let a = anchors(md);
    assert!(a.contains("data-flows") && a.contains("at-rest") && a.contains("at-rest-1"));
    assert!(anchors("## Bots: a token for each run").contains("bots-a-token-for-each-run"));
}
