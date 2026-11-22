//! The HTML around every page: head, header, docs sidebar with search, and footer. Every
//! link is relative (`root` is the way back to the site's top), so the site works from
//! any path or straight from disk.

use crate::pages::Page;

pub fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

/// `../` once per folder `out` is in.
pub fn root_of(out: &str) -> String {
    "../".repeat(out.matches('/').count())
}

pub struct Shell<'a> {
    pub out: &'a str,
    pub title: &'a str,
    pub description: &'a str,
    pub repo_url: &'a str,
    /// Whether this is a docs page, which gets the docs styles, search and Docs marked current.
    pub docs: bool,
}

pub fn page(s: &Shell, main: &str) -> String {
    let root = root_of(s.out);
    let search = match s.docs {
        true => format!("\n  <script src=\"{root}assets/search.js\" defer></script>"),
        false => String::new(),
    };
    let current = if s.docs { " aria-current=\"page\"" } else { "" };
    format!(
        r##"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>{title}</title>
  <meta name="description" content="{description}" />
  <meta name="color-scheme" content="dark light" />
  <meta name="theme-color" content="#171717" media="(prefers-color-scheme: dark)" />
  <meta name="theme-color" content="#fafafa" media="(prefers-color-scheme: light)" />
  <link rel="icon" type="image/svg+xml" href="{root}assets/mark.svg" />
  <link rel="stylesheet" href="{root}assets/site.css" />
  <link rel="stylesheet" href="{root}assets/docs.css" />{search}
</head>
<body>
  <a class="skip" href="#main">Skip to content</a>
  <header class="top">
    <div class="wrap top-row">
      <a class="brand" href="{root}index.html" aria-label="SuperBot home">
        <span class="tile"><img src="{root}assets/mark.svg" alt="" width="28" height="28" /></span>
        <span>SuperBot</span>
      </a>
      <nav aria-label="Main">
        <ul class="nav">
          <li class="nav-extra"><a href="{root}index.html#features">Features</a></li>
          <li class="nav-extra"><a href="{root}index.html#plans">Plans</a></li>
          <li><a href="{root}docs/index.html"{current}>Docs</a></li>
          <li><a class="btn btn-primary btn-small" href="{repo}">GitHub</a></li>
        </ul>
      </nav>
    </div>
  </header>
{main}
  <footer class="foot">
    <div class="wrap foot-row">
      <span>&copy; SuperBot</span>
      <nav aria-label="Footer">
        <ul class="nav">
          <li><a href="{root}docs/index.html">Docs</a></li>
          <li><a href="{root}docs/security/index.html">Security</a></li>
          <li><a href="{root}docs/changelog.html">Changelog</a></li>
          <li><a href="{repo}">Source</a></li>
        </ul>
      </nav>
    </div>
  </footer>
</body>
</html>
"##,
        title = esc(s.title),
        description = esc(s.description),
        repo = esc(s.repo_url),
    )
}

/// The docs sidebar: search (shown once its script runs) and every page by section, with
/// the current page marked and its section open. "Decisions" starts closed elsewhere.
pub fn sidebar(pages: &[Page], out: &str) -> String {
    let root = root_of(out);
    let mut html = format!(
        r#"    <aside class="sidebar" aria-label="Documentation">
      <form class="search" role="search" data-root="{root}" hidden>
        <label class="sr-only" for="search">Search the docs</label>
        <input id="search" type="search" placeholder="Search the docs" autocomplete="off" spellcheck="false" />
        <ol class="results" aria-label="Search results"></ol>
        <p class="results-none" hidden>No pages match.</p>
      </form>
      <nav class="toc">
"#
    );
    let mut sections: Vec<&str> = Vec::new();
    for p in pages {
        if !sections.contains(&p.section.as_str()) {
            sections.push(&p.section);
        }
    }
    for section in sections {
        let here = pages.iter().any(|p| p.section == section && p.out == out);
        let open = if here || (section != "Decisions" && !out.starts_with("docs/adr/")) { " open" } else { "" };
        html.push_str(&format!("        <details{open}>\n          <summary>{}</summary>\n          <ul>\n", esc(section)));
        for p in pages.iter().filter(|p| p.section == section) {
            let cur = if p.out == out { " aria-current=\"page\"" } else { "" };
            html.push_str(&format!(
                "            <li><a href=\"{}\"{cur}>{}</a></li>\n",
                crate::markdown::rel(out, &p.out),
                esc(&p.title)
            ));
        }
        html.push_str("          </ul>\n        </details>\n");
    }
    html.push_str("      </nav>\n    </aside>\n");
    html
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_html() {
        assert_eq!(esc(r#"<a href="x">'&'</a>"#), "&lt;a href=&quot;x&quot;&gt;&#39;&amp;&#39;&lt;/a&gt;");
    }

    #[test]
    fn roots() {
        assert_eq!(root_of("index.html"), "");
        assert_eq!(root_of("docs/sso/entra.html"), "../../");
    }

    #[test]
    fn sidebar_marks_the_current_page() {
        let page = |src: &str, out: &str, section: &str, title: &str| Page {
            src: src.into(),
            out: out.into(),
            section: section.into(),
            title: title.into(),
            md: String::new(),
        };
        let pages = [
            page("docs/slo.md", "docs/slo.html", "Guides", "SLO"),
            page("docs/adr/0001-backend.md", "docs/adr/0001-backend.html", "Decisions", "0001: Backend"),
        ];
        let html = sidebar(&pages, "docs/slo.html");
        assert!(html.contains(r#"<a href="slo.html" aria-current="page">SLO</a>"#), "{html}");
        assert!(html.contains(r#"<a href="adr/0001-backend.html">0001: Backend</a>"#));
        assert!(html.contains("<details open>\n          <summary>Guides"));
        assert!(html.contains("<details>\n          <summary>Decisions"));
        let html = sidebar(&pages, "docs/adr/0001-backend.html");
        assert!(html.contains("<details open>\n          <summary>Decisions"));
        assert!(html.contains(r#"<a href="../slo.html">SLO</a>"#));
    }
}
