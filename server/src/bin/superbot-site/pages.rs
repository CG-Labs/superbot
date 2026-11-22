//! Which Markdown files become portal pages, where each one lands in the site, and the
//! sections the navigation groups them into.

use std::fs;
use std::path::Path;

/// Repository files outside `docs/` that the portal carries, and the page each becomes.
pub const EXTRA: &[(&str, &str)] = &[
    ("deploy/README.md", "docs/install.html"),
    ("SECURITY.md", "docs/security-policy.html"),
    ("CHANGELOG.md", "docs/changelog.html"),
];

/// Files under `docs/` kept out of the portal: notes about another vendor's product,
/// whose name SuperBot doesn't publish under (AGENTS.md). Links to them go to GitHub.
pub const EXCLUDED: &[&str] = &["docs/grok-bot-reference.md", "docs/background/grok-bot-computer-specs.md"];

/// Navigation sections, in order: the `docs/` folder each holds and its heading.
/// Top-level `docs/*.md` and the extras are "Guides"; an unlisted folder gets its own
/// section after these, named after the folder.
pub const SECTIONS: &[(&str, &str)] = &[
    ("", "Guides"),
    ("sso", "Single sign-on"),
    ("ops", "Operations"),
    ("security", "Security pack"),
    ("support", "Support"),
    ("adr", "Decisions"),
    ("background", "Background"),
];

#[derive(Debug, Clone)]
pub struct Page {
    /// Repository path of the Markdown source, e.g. `docs/sso/entra.md`.
    pub src: String,
    /// Site path of the page, e.g. `docs/sso/entra.html`.
    pub out: String,
    pub section: String,
    pub title: String,
    pub md: String,
}

/// The site path for a `docs/` Markdown file: `.md` becomes `.html`, `README.md` `index.html`.
pub fn out_path(src: &str) -> String {
    if let Some((_, out)) = EXTRA.iter().find(|(s, _)| *s == src) {
        return out.to_string();
    }
    match src.strip_suffix("README.md") {
        Some(dir) => format!("{dir}index.html"),
        None => format!("{}.html", src.strip_suffix(".md").unwrap_or(src)),
    }
}

pub fn section_of(src: &str) -> String {
    let folder = match src.strip_prefix("docs/").and_then(|r| r.split_once('/')) {
        Some((dir, _)) => dir,
        None => "",
    };
    match SECTIONS.iter().find(|(d, _)| *d == folder) {
        Some((_, name)) => name.to_string(),
        None => {
            let mut c = folder.chars();
            c.next().map(|f| f.to_uppercase().chain(c).collect()).unwrap_or_default()
        }
    }
}

/// The text of the first `# ` heading, or the file name without `.md`.
pub fn title_of(src: &str, md: &str) -> String {
    let mut fenced = false;
    for line in md.lines() {
        if line.trim_start().starts_with("```") {
            fenced = !fenced;
        }
        if !fenced && let Some(t) = line.strip_prefix("# ") {
            return crate::markdown::inline_text(t.trim());
        }
    }
    let name = src.rsplit('/').next().unwrap_or(src);
    name.strip_suffix(".md").unwrap_or(name).to_string()
}

/// Every portal page, sorted by section order, then README first, then by file name for
/// decisions (they're numbered) and by title elsewhere, with the install guide first.
pub fn discover(repo: &Path) -> Result<Vec<Page>, String> {
    let mut srcs = Vec::new();
    walk(repo, "docs", &mut srcs)?;
    srcs.retain(|s| !EXCLUDED.contains(&s.as_str()));
    srcs.extend(EXTRA.iter().map(|(s, _)| s.to_string()));
    let mut pages = Vec::new();
    for src in srcs {
        let md = fs::read_to_string(repo.join(&src)).map_err(|e| format!("{src}: {e}"))?;
        pages.push(Page { out: out_path(&src), section: section_of(&src), title: title_of(&src, &md), src, md });
    }
    let mut outs: Vec<&str> = pages.iter().map(|p| p.out.as_str()).collect();
    outs.push("docs/index.html");
    outs.sort_unstable();
    if let Some(w) = outs.windows(2).find(|w| w[0] == w[1]) {
        return Err(format!("two pages would be written to {}", w[0]));
    }
    let rank = |p: &Page| {
        let s = SECTIONS.iter().position(|(_, n)| *n == p.section).unwrap_or(SECTIONS.len());
        let first = !(p.src.ends_with("README.md") || p.src == EXTRA[0].0);
        let key = if p.section == "Decisions" { p.src.clone() } else { p.title.to_lowercase() };
        (s, p.section.clone(), first, key)
    };
    pages.sort_by_key(rank);
    Ok(pages)
}

fn walk(repo: &Path, dir: &str, out: &mut Vec<String>) -> Result<(), String> {
    let entries = fs::read_dir(repo.join(dir)).map_err(|e| format!("{dir}: {e}"))?;
    for entry in entries {
        let entry = entry.map_err(|e| e.to_string())?;
        let name = entry.file_name().to_string_lossy().into_owned();
        let path = format!("{dir}/{name}");
        if entry.file_type().map_err(|e| e.to_string())?.is_dir() {
            walk(repo, &path, out)?;
        } else if name.ends_with(".md") {
            out.push(path);
        }
    }
    Ok(())
}
