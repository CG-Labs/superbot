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
    /// The managed server's `/pricing` (`--pricing-url`). None: the landing page's plans.
    pub pricing_url: Option<&'a str>,
    /// Whether this is a docs page, which gets the docs styles, search and Docs marked current.
    pub docs: bool,
}

pub fn page(s: &Shell, main: &str) -> String {
    let root = root_of(s.out);
    let search = match s.docs {
        true => format!("\n  <script src=\"{root}assets/search.js\" defer></script>"),
        false => String::new(),
    };
    let current = match (s.docs, s.out == "docs/index.html") {
        (true, true) => " aria-current=\"page\"",
        (true, false) => " aria-current=\"true\"",
        _ => "",
    };
    format!(
        r##"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>{title}</title>
  <meta name="description" content="{description}" />
  <meta name="color-scheme" content="light dark" />
  <meta name="theme-color" content="#faf9f7" media="(prefers-color-scheme: light)" />
  <meta name="theme-color" content="#1b1a19" media="(prefers-color-scheme: dark)" />
  <link rel="icon" type="image/svg+xml" href="{root}assets/mark.svg" />
  <link rel="stylesheet" href="{root}assets/site.css" />
  <link rel="stylesheet" href="{root}assets/docs.css" />{search}
</head>
<body>
  <a class="skip" href="#main">Skip to content</a>
  <header class="top">
    <div class="wrap top-row">
      <a class="brand" href="{root}index.html" aria-label="SuperBot home">
        <span class="tile"><img src="{root}assets/mark.svg" alt="" width="24" height="24" /></span>
        <span>SuperBot</span>
      </a>
      <nav aria-label="Main">
        <ul class="nav">
          <li class="nav-extra"><a href="{root}index.html#computer">Product</a></li>
          <li class="nav-extra"><a href="{root}index.html#security">Security</a></li>
          <li class="nav-extra"><a href="{pricing}">Pricing</a></li>
          <li><a href="{root}docs/index.html"{current}>Docs</a></li>
          <li><a class="btn btn-primary btn-small" href="{repo}">GitHub</a></li>
        </ul>
      </nav>
    </div>
  </header>
{main}
  <footer class="foot">
    <div class="wrap">
      <div class="foot-grid">
        <div class="foot-about">
          <a class="brand" href="{root}index.html" aria-label="SuperBot home"><span class="tile"><img src="{root}assets/mark.svg" alt="" width="24" height="24" /></span><span>SuperBot</span></a>
          <p>AI teammates with their own computer. Open source, self-hosted or managed.</p>
        </div>
        <nav aria-labelledby="foot-product">
          <h2 id="foot-product">Product</h2>
          <ul>
            <li><a href="{root}index.html#computer">Your own computer</a></li>
            <li><a href="{root}index.html#features">Features</a></li>
            <li><a href="{root}index.html#self-host">Self-host</a></li>
            <li><a href="{pricing}">Pricing</a></li>
          </ul>
        </nav>
        <nav aria-labelledby="foot-docs">
          <h2 id="foot-docs">Resources</h2>
          <ul>
            <li><a href="{root}docs/index.html">Docs</a></li>
            <li><a href="{root}docs/install.html">Install</a></li>
            <li><a href="{root}docs/security/index.html">Security pack</a></li>
            <li><a href="{root}docs/changelog.html">Changelog</a></li>
          </ul>
        </nav>
        <nav aria-labelledby="foot-project">
          <h2 id="foot-project">Project</h2>
          <ul>
            <li><a href="{repo}">Source on GitHub</a></li>
            <li><a href="{root}docs/security-policy.html">Security policy</a></li>
            <li><a href="{root}docs/index.html#decisions">Decisions</a></li>
          </ul>
        </nav>
      </div>
      <div class="foot-base"><span>&copy; SuperBot</span></div>
    </div>
  </footer>
</body>
</html>
"##,
        title = esc(s.title),
        description = esc(s.description),
        repo = esc(s.repo_url),
        pricing = pricing_href(s.pricing_url, &root),
    )
}

/// Where "Pricing" links: the managed server's `/pricing` when the site is given one,
/// else the plans on this site's landing page.
pub fn pricing_href(pricing_url: Option<&str>, root: &str) -> String {
    match pricing_url {
        Some(u) => esc(u),
        None => format!("{root}index.html#plans"),
    }
}

/// The docs sidebar: search (shown once its script runs) and every page by section, with
/// the current page marked and its section open. "Decisions" starts closed elsewhere.
pub fn sidebar(pages: &[Page], out: &str) -> String {
    let mut html = String::from(
        r#"    <aside class="sidebar" aria-label="Documentation">
      <form class="search" role="search" hidden>
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
    fn pricing_links_to_the_server_page_or_the_plans() {
        let shell = |out, pricing_url| Shell { out, title: "t", description: "d", repo_url: "https://github.com/o/r", pricing_url, docs: false };
        let html = page(&shell("docs/sso/entra.html", None), "");
        assert_eq!(html.matches(r#"<a href="../../index.html#plans">Pricing</a>"#).count(), 2, "nav and footer: {html}");
        assert!(!html.contains(">Plans<"));
        let html = page(&shell("index.html", Some("https://app.example.com/pricing?a=1&b=2")), "");
        assert_eq!(html.matches(r#"<a href="https://app.example.com/pricing?a=1&amp;b=2">Pricing</a>"#).count(), 2, "{html}");
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
