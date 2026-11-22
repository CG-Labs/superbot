//! Markdown to HTML for the portal, with GitHub's heading anchors, and every relative
//! link checked and rewritten: to another page of the site, to a copied image, or to the
//! file on GitHub. A link that names a missing file or heading is an error.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path;

use pulldown_cmark::{CowStr, Event, LinkType, Options, Parser, Tag, TagEnd, html};

pub fn options() -> Options {
    Options::ENABLE_TABLES
        | Options::ENABLE_FOOTNOTES
        | Options::ENABLE_STRIKETHROUGH
        | Options::ENABLE_TASKLISTS
        | Options::ENABLE_GFM
}

/// GitHub's anchor for a heading: lower case, punctuation dropped, spaces to hyphens.
pub fn slug(text: &str) -> String {
    text.trim()
        .to_lowercase()
        .chars()
        .filter(|c| c.is_alphanumeric() || *c == ' ' || *c == '-' || *c == '_')
        .map(|c| if c == ' ' { '-' } else { c })
        .collect()
}

/// Hands out anchors for a page's headings, adding `-1`, `-2`, ... on repeats as GitHub does.
#[derive(Default)]
struct Slugger(HashMap<String, usize>);

impl Slugger {
    fn next(&mut self, text: &str) -> String {
        let base = slug(text);
        let n = self.0.entry(base.clone()).or_insert(0);
        let id = if *n == 0 { base.clone() } else { format!("{base}-{n}") };
        *n += 1;
        id
    }
}

/// Plain text of a line of inline Markdown, e.g. a title with `code` in it.
pub fn inline_text(md: &str) -> String {
    let mut out = String::new();
    for event in Parser::new_ext(md, options()) {
        if let Event::Text(t) | Event::Code(t) = event {
            out.push_str(&t);
        }
    }
    out
}

/// The anchors of a document's headings, in order.
pub fn anchors(md: &str) -> Vec<String> {
    let mut slugger = Slugger::default();
    let mut out = Vec::new();
    let mut text: Option<String> = None;
    for event in Parser::new_ext(md, options()) {
        match event {
            Event::Start(Tag::Heading { .. }) => text = Some(String::new()),
            Event::End(TagEnd::Heading(_)) => out.push(slugger.next(&text.take().unwrap_or_default())),
            Event::Text(t) | Event::Code(t) => {
                if let Some(s) = text.as_mut() {
                    s.push_str(&t);
                }
            }
            _ => {}
        }
    }
    out
}

/// What the renderer knows about the site: the repository and every page in it.
pub struct Site<'a> {
    pub repo: &'a Path,
    /// Repository URL that links to files outside the portal point into.
    pub repo_url: &'a str,
    /// Source path to (site path, heading anchors) for every page.
    pub pages: HashMap<String, (String, HashSet<String>)>,
}

#[derive(Debug, PartialEq)]
pub enum Resolved {
    Href(String),
    /// A repository file to copy into the site at `out`, linked as `href`.
    Asset { src: String, out: String, href: String },
}

#[derive(Default)]
pub struct Rendered {
    pub html: String,
    pub text: String,
    pub headings: Vec<String>,
    pub assets: Vec<(String, String)>,
    pub errors: Vec<String>,
}

/// Whether a link has a scheme (`https:`, `mailto:`) or is protocol-relative.
pub fn is_external(dest: &str) -> bool {
    if dest.starts_with("//") {
        return true;
    }
    let Some(colon) = dest.find(':') else { return false };
    let scheme = &dest[..colon];
    scheme.chars().next().is_some_and(|c| c.is_ascii_alphabetic())
        && scheme.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
}

/// The relative URL from one site file to another.
pub fn rel(from: &str, to: &str) -> String {
    let from_dir: Vec<&str> = from.split('/').collect::<Vec<_>>().split_last().map(|(_, d)| d.to_vec()).unwrap_or_default();
    let to_parts: Vec<&str> = to.split('/').collect();
    let common = from_dir.iter().zip(&to_parts).take_while(|(a, b)| a == b).count();
    let mut out = "../".repeat(from_dir.len() - common);
    out.push_str(&to_parts[common..].join("/"));
    out
}

/// `a/b/../c` to `a/c`; `None` if it climbs out of the repository.
fn normalize(path: &str) -> Option<String> {
    let mut parts: Vec<&str> = Vec::new();
    for part in path.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop()?;
            }
            p => parts.push(p),
        }
    }
    Some(parts.join("/"))
}

pub fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && let Some(b) = s.get(i + 1..i + 3).and_then(|h| u8::from_str_radix(h, 16).ok())
        {
            out.push(b);
            i += 3;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn is_image(path: &str) -> bool {
    let ext = path.rsplit('.').next().unwrap_or("").to_ascii_lowercase();
    matches!(ext.as_str(), "png" | "jpg" | "jpeg" | "gif" | "svg" | "webp")
}

/// Where a copied image lives in the site: at its own path under `docs/`, else under `assets/repo/`.
fn asset_out(src: &str) -> String {
    match src.starts_with("docs/") {
        true => src.to_string(),
        false => format!("assets/repo/{src}"),
    }
}

impl Site<'_> {
    fn frag(&self, frag: Option<&str>, anchors: impl FnOnce() -> HashSet<String>) -> Result<String, String> {
        match frag {
            None => Ok(String::new()),
            Some(f) if anchors().contains(&percent_decode(f)) => Ok(format!("#{f}")),
            Some(f) => Err(format!("no heading #{f}")),
        }
    }

    fn page_anchors(&self, src: &str) -> HashSet<String> {
        self.pages.get(src).map(|(_, a)| a.clone()).unwrap_or_default()
    }

    /// Checks and rewrites one link from the page `from_src` (written to `from_out`).
    pub fn resolve(&self, from_src: &str, from_out: &str, dest: &str) -> Result<Resolved, String> {
        if dest.is_empty() {
            return Err("empty link".into());
        }
        if is_external(dest) {
            return Ok(Resolved::Href(dest.to_string()));
        }
        let (before, frag) = match dest.split_once('#') {
            Some((p, f)) => (p, Some(f)),
            None => (dest, None),
        };
        let path = before.split('?').next().unwrap_or("");
        if path.is_empty() {
            let f = self.frag(frag, || self.page_anchors(from_src))?;
            return Ok(Resolved::Href(if f.is_empty() { "#".into() } else { f }));
        }
        let decoded = percent_decode(path);
        let joined = match decoded.strip_prefix('/') {
            Some(rooted) => rooted.to_string(),
            None => match from_src.rsplit_once('/') {
                Some((dir, _)) => format!("{dir}/{decoded}"),
                None => decoded.clone(),
            },
        };
        let norm = normalize(&joined).ok_or("outside the repository")?;
        let full = self.repo.join(&norm);
        if norm.is_empty() || full.is_dir() {
            let readme = if norm.is_empty() { "README.md".to_string() } else { format!("{norm}/README.md") };
            if let Some((out, anchors)) = self.pages.get(&readme) {
                let f = self.frag(frag, || anchors.clone())?;
                return Ok(Resolved::Href(format!("{}{f}", rel(from_out, out))));
            }
            let f = frag.map(|f| format!("#{f}")).unwrap_or_default();
            return Ok(Resolved::Href(format!("{}/tree/main/{norm}{f}", self.repo_url)));
        }
        if !full.is_file() {
            return Err("no such file".into());
        }
        if let Some((out, anchors)) = self.pages.get(&norm) {
            let f = self.frag(frag, || anchors.clone())?;
            return Ok(Resolved::Href(format!("{}{f}", rel(from_out, out))));
        }
        if is_image(&norm) {
            let out = asset_out(&norm);
            return Ok(Resolved::Asset { href: rel(from_out, &out), src: norm, out });
        }
        let f = match norm.ends_with(".md") {
            true => self.frag(frag, || anchors(&fs::read_to_string(&full).unwrap_or_default()).into_iter().collect())?,
            false => frag.map(|f| format!("#{f}")).unwrap_or_default(),
        };
        Ok(Resolved::Href(format!("{}/blob/main/{norm}{f}", self.repo_url)))
    }

    /// Renders one page, rewriting its links and collecting its search text and errors.
    pub fn render(&self, src: &str, out: &str, md: &str) -> Rendered {
        let mut r = Rendered::default();
        let mut events: Vec<(Event, std::ops::Range<usize>)> = Parser::new_ext(md, options()).into_offset_iter().collect();
        let mut slugger = Slugger::default();
        let line = |at: usize| md[..at].matches('\n').count() + 1;
        for i in 0..events.len() {
            let at = events[i].1.start;
            if matches!(events[i].0, Event::Start(Tag::Heading { .. })) {
                let mut text = String::new();
                for (e, _) in &events[i + 1..] {
                    match e {
                        Event::End(TagEnd::Heading(_)) => break,
                        Event::Text(t) | Event::Code(t) => text.push_str(t),
                        _ => {}
                    }
                }
                let anchor = slugger.next(&text);
                r.headings.push(text);
                if let Event::Start(Tag::Heading { id, .. }) = &mut events[i].0 {
                    *id = Some(CowStr::from(anchor));
                }
                continue;
            }
            match &mut events[i].0 {
                Event::Start(Tag::Link { link_type, dest_url, .. } | Tag::Image { link_type, dest_url, .. }) => {
                    if *link_type == LinkType::Email {
                        continue;
                    }
                    match self.resolve(src, out, dest_url) {
                        Ok(Resolved::Href(h)) => *dest_url = CowStr::from(h),
                        Ok(Resolved::Asset { src: from, out: to, href }) => {
                            r.assets.push((from, to));
                            *dest_url = CowStr::from(href);
                        }
                        Err(e) => r.errors.push(format!("{src}:{}: {dest_url} ({e})", line(at))),
                    }
                }
                Event::Text(t) | Event::Code(t) => {
                    r.text.push_str(t);
                    r.text.push(' ');
                }
                _ => {}
            }
        }
        html::push_html(&mut r.html, events.into_iter().map(|(e, _)| e));
        r
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn repo() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("..")
    }

    fn site(repo: &Path) -> Site<'_> {
        let mut pages = HashMap::new();
        for (src, out, md) in [
            ("docs/slo.md", "docs/slo.html", "# SLO\n\n## Targets\n"),
            ("docs/security/README.md", "docs/security/index.html", "# Pack\n\n## Contents\n"),
            ("docs/sso/entra.md", "docs/sso/entra.html", "# Entra\n\n## Setup\n\n## Setup\n\n## Café\n"),
        ] {
            pages.insert(src.to_string(), (out.to_string(), anchors(md).into_iter().collect()));
        }
        Site { repo, repo_url: "https://github.com/o/r", pages }
    }

    #[test]
    fn slugs_match_github() {
        assert_eq!(slug("Decisions (19 Nov 2026)"), "decisions-19-nov-2026");
        assert_eq!(slug("M4 — Public launch"), "m4--public-launch");
        assert_eq!(slug("`botctl` and the API"), "botctl-and-the-api");
        assert_eq!(anchors("# A\n## Setup\n## Setup\n```\n# not a heading\n```\n"), ["a", "setup", "setup-1"]);
    }

    #[test]
    fn relative_urls() {
        assert_eq!(rel("docs/sso/entra.html", "docs/ops/x.html"), "../ops/x.html");
        assert_eq!(rel("docs/index.html", "docs/sso/entra.html"), "sso/entra.html");
        assert_eq!(rel("index.html", "docs/index.html"), "docs/index.html");
        assert_eq!(rel("docs/adr/a.html", "assets/site.css"), "../../assets/site.css");
        assert_eq!(rel("docs/slo.html", "docs/slo.html"), "slo.html");
    }

    #[test]
    fn external_links() {
        for d in ["https://x.example/a", "mailto:a@b.c", "//cdn.example/x"] {
            assert!(is_external(d), "{d}");
        }
        for d in ["slo.md", "../adr/0001-backend.md#x", "#top", "../adr/x.md#a:b"] {
            assert!(!is_external(d), "{d}");
        }
    }

    #[test]
    fn links_to_pages_are_rewritten_and_checked() {
        let repo = repo();
        let s = site(&repo);
        let r = |dest: &str| s.resolve("docs/sso/entra.md", "docs/sso/entra.html", dest);
        assert_eq!(r("../slo.md#targets"), Ok(Resolved::Href("../slo.html#targets".into())));
        assert_eq!(r("../security/"), Ok(Resolved::Href("../security/index.html".into())));
        assert_eq!(r("../security#contents"), Ok(Resolved::Href("../security/index.html#contents".into())));
        assert_eq!(r("#setup-1"), Ok(Resolved::Href("#setup-1".into())));
        assert_eq!(r("#caf%C3%A9"), Ok(Resolved::Href("#caf%C3%A9".into())));
        assert_eq!(r("#café"), Ok(Resolved::Href("#café".into())));
        assert_eq!(r("/docs/slo.md"), Ok(Resolved::Href("../slo.html".into())));
        assert_eq!(r("../slo.md#nope"), Err("no heading #nope".into()));
        assert_eq!(r("#nope"), Err("no heading #nope".into()));
        assert_eq!(r("../nope.md"), Err("no such file".into()));
        assert_eq!(r("../../../../etc/passwd"), Err("outside the repository".into()));
        assert_eq!(r(""), Err("empty link".into()));
        assert_eq!(r("https://example.com/x"), Ok(Resolved::Href("https://example.com/x".into())));
    }

    #[test]
    fn links_outside_the_portal_go_to_github() {
        let repo = repo();
        let s = site(&repo);
        let r = |dest: &str| s.resolve("docs/slo.md", "docs/slo.html", dest);
        assert_eq!(r("../server/Cargo.toml"), Ok(Resolved::Href("https://github.com/o/r/blob/main/server/Cargo.toml".into())));
        assert_eq!(r("../server/src/"), Ok(Resolved::Href("https://github.com/o/r/tree/main/server/src".into())));
        assert_eq!(r("../AGENTS.md#rules"), Ok(Resolved::Href("https://github.com/o/r/blob/main/AGENTS.md#rules".into())));
        assert_eq!(r("../AGENTS.md#nope"), Err("no heading #nope".into()));
    }

    #[test]
    fn images_are_copied() {
        let repo = repo();
        let s = site(&repo);
        let r = s.resolve("docs/slo.md", "docs/slo.html", "images/superbot-hero.png").unwrap();
        assert_eq!(
            r,
            Resolved::Asset { src: "docs/images/superbot-hero.png".into(), out: "docs/images/superbot-hero.png".into(), href: "images/superbot-hero.png".into() }
        );
    }

    #[test]
    fn render_sets_anchors_and_reports_broken_links_with_lines() {
        let repo = repo();
        let s = site(&repo);
        let md = "# Entra\n\n## Setup\n\n## Setup\n\nSee [SLO](../slo.md) and [gone](gone.md).\n\n![x](../images/superbot-hero.png)\n";
        let r = s.render("docs/sso/entra.md", "docs/sso/entra.html", md);
        assert!(r.html.contains(r#"<h2 id="setup-1">Setup</h2>"#), "{}", r.html);
        assert!(r.html.contains(r#"href="../slo.html""#));
        assert!(r.html.contains(r#"src="../images/superbot-hero.png""#));
        assert_eq!(r.errors, ["docs/sso/entra.md:7: gone.md (no such file)"]);
        assert_eq!(r.headings, ["Entra", "Setup", "Setup"]);
        assert_eq!(r.assets, [("docs/images/superbot-hero.png".to_string(), "docs/images/superbot-hero.png".to_string())]);
        assert!(r.text.contains("See"));
    }

    #[test]
    fn titles_are_plain_text() {
        assert_eq!(inline_text("0038: `botctl` *license*"), "0038: botctl license");
    }
}
