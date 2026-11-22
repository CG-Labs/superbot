//! Checks the built site on its own: every relative `href` and `src` in every HTML file
//! must name a file in the site, and every `#anchor` into a page an `id` on it. Links
//! starting with `/` are errors too, so the site works under any path. Links with a
//! scheme (`https:`, `mailto:`) aren't fetched.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path;

use crate::markdown::is_external;

/// Values of the given attribute (`href`, `src`, `id`) in an HTML document.
pub fn attr_values(html: &str, attr: &str) -> Vec<String> {
    let mut out = Vec::new();
    let needle = format!("{attr}=");
    let mut rest = html;
    while let Some(at) = rest.find(&needle) {
        let before = rest[..at].chars().next_back();
        rest = &rest[at + needle.len()..];
        if !before.is_some_and(char::is_whitespace) {
            continue;
        }
        let Some(quote) = rest.chars().next().filter(|c| *c == '"' || *c == '\'') else { continue };
        let Some(end) = rest[1..].find(quote) else { break };
        out.push(rest[1..1 + end].replace("&amp;", "&"));
        rest = &rest[1 + end..];
    }
    out
}

fn html_files(dir: &Path, prefix: &str, out: &mut Vec<String>) -> std::io::Result<()> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        let path = if prefix.is_empty() { name.clone() } else { format!("{prefix}/{name}") };
        if entry.file_type()?.is_dir() {
            html_files(&entry.path(), &path, out)?;
        } else if name.ends_with(".html") {
            out.push(path);
        }
    }
    Ok(())
}

fn join(from: &str, link: &str) -> Option<String> {
    let mut parts: Vec<&str> = from.split('/').collect();
    parts.pop();
    for part in link.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop()?;
            }
            p => parts.push(p),
        }
    }
    let mut path = parts.join("/");
    if link.ends_with('/') || path.is_empty() {
        path = if path.is_empty() { "index.html".into() } else { format!("{path}/index.html") };
    }
    Some(path)
}

/// Every broken internal link in the site at `root`, as `page: link (reason)`.
pub fn check(root: &Path) -> std::io::Result<(usize, Vec<String>)> {
    let mut pages = Vec::new();
    html_files(root, "", &mut pages)?;
    pages.sort();
    let mut ids: HashMap<String, HashSet<String>> = HashMap::new();
    let mut links = Vec::new();
    for page in &pages {
        let html = fs::read_to_string(root.join(page))?;
        ids.insert(page.clone(), attr_values(&html, "id").into_iter().collect());
        for link in attr_values(&html, "href").into_iter().chain(attr_values(&html, "src")) {
            links.push((page.clone(), link));
        }
    }
    let mut bad = Vec::new();
    for (page, link) in &links {
        if is_external(link) {
            continue;
        }
        let at = format!("{page}: {link}");
        if link.starts_with('/') {
            bad.push(format!("{at} (starts with /, so it breaks under a path)"));
            continue;
        }
        let (path, frag) = match link.split_once('#') {
            Some((p, f)) => (p, Some(f)),
            None => (link.as_str(), None),
        };
        let path = path.split('?').next().unwrap_or("");
        let target = match path.is_empty() {
            true => page.clone(),
            false => match join(page, path) {
                Some(t) => t,
                None => {
                    bad.push(format!("{at} (outside the site)"));
                    continue;
                }
            },
        };
        if !root.join(&target).is_file() {
            bad.push(format!("{at} (no such file)"));
            continue;
        }
        if let Some(f) = frag.filter(|f| !f.is_empty())
            && target.ends_with(".html")
            && !ids.get(&target).is_some_and(|ids| ids.contains(f))
        {
            bad.push(format!("{at} (no id {f})"));
        }
    }
    Ok((links.len(), bad))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attributes_are_found() {
        let html = r#"<a href="a.html#x" data-href="no"><img src='i.png' alt=""><p id="x">"#;
        assert_eq!(attr_values(html, "href"), ["a.html#x"]);
        assert_eq!(attr_values(html, "src"), ["i.png"]);
        assert_eq!(attr_values(html, "id"), ["x"]);
        assert_eq!(attr_values(r#"<a href="?a=1&amp;b=2">"#, "href"), ["?a=1&b=2"]);
    }

    #[test]
    fn broken_links_are_reported() {
        let root = std::env::temp_dir().join(format!("superbot-site-check-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("docs/sso")).unwrap();
        fs::write(root.join("index.html"), r#"<a href="docs/">Docs</a> <a href="https://example.com/">x</a>"#).unwrap();
        fs::write(
            root.join("docs/index.html"),
            r##"<h2 id="top">T</h2><a href="#top">ok</a><a href="sso/entra.html#setup">ok</a><a href="../index.html">ok</a>
            <a href="#gone">1</a><a href="sso/okta.html">2</a><a href="sso/entra.html#nope">3</a><a href="/docs/">4</a>
            <a href="../../x.html">5</a><img src="../assets/missing.css">"##,
        )
        .unwrap();
        fs::write(root.join("docs/sso/entra.html"), r#"<h2 id="setup">Setup</h2><a href="../index.html#top">ok</a>"#).unwrap();
        let (n, bad) = check(&root).unwrap();
        fs::remove_dir_all(&root).unwrap();
        assert_eq!(n, 12);
        assert_eq!(
            bad,
            [
                "docs/index.html: #gone (no id gone)",
                "docs/index.html: sso/okta.html (no such file)",
                "docs/index.html: sso/entra.html#nope (no id nope)",
                "docs/index.html: /docs/ (starts with /, so it breaks under a path)",
                "docs/index.html: ../../x.html (outside the site)",
                "docs/index.html: ../assets/missing.css (no such file)",
            ]
        );
    }
}
