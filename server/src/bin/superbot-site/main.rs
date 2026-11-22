//! superbot-site: builds the public site (a landing page and the docs portal) as static
//! files from this repository. Every page is rendered from the Markdown in `docs/` (and
//! the install guide, security policy and changelog), with navigation and search, and
//! the build fails on any broken internal link. ADR 0119.
//!
//! Usage: superbot-site [--out DIR] [--repo DIR] [--tiers FILE] [--contact-url URL] [--repo-url URL]

mod check;
mod landing;
mod layout;
mod markdown;
mod pages;

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use layout::{Shell, esc, root_of};
use pages::Page;

const USAGE: &str = "Usage: superbot-site [--out DIR] [--repo DIR] [--tiers FILE] [--contact-url URL] [--repo-url URL]

Builds the public site (landing page and docs portal) as static files and checks every
internal link in it. Exits 1 on any broken link.

  --out DIR          where to write the site (default: <repo>/target/site)
  --repo DIR         the repository to read (default: this checkout)
  --tiers FILE       tiers file the managed plans come from (default: <repo>/deploy/tiers.example.json)
  --contact-url URL  where \"Contact sales\" links (default: $SUPERBOT_SITE_CONTACT_URL, else the repository)
  --repo-url URL     the repository on GitHub, for links to files outside the portal
";

/// Marks a folder as this tool's output, so a rebuild may replace it.
const MARKER: &str = ".superbot-site";
/// Search text kept per page; the roadmap alone is far longer.
const SEARCH_TEXT_CHARS: usize = 30_000;

pub struct Args {
    pub repo: PathBuf,
    pub out: PathBuf,
    pub tiers: PathBuf,
    pub contact_url: String,
    pub repo_url: String,
}

impl Args {
    fn parse(argv: impl Iterator<Item = String>) -> Result<Self, String> {
        let mut flags: HashMap<String, String> = HashMap::new();
        let mut argv = argv.peekable();
        while let Some(a) = argv.next() {
            if a == "-h" || a == "--help" {
                return Err(String::new());
            }
            let known = ["--out", "--repo", "--tiers", "--contact-url", "--repo-url"];
            if !known.contains(&a.as_str()) {
                return Err(format!("unknown argument {a}"));
            }
            let v = argv.next().ok_or(format!("{a} needs a value"))?;
            flags.insert(a, v);
        }
        let repo = flags.remove("--repo").map(PathBuf::from).unwrap_or_else(|| Path::new(env!("CARGO_MANIFEST_DIR")).join(".."));
        let repo = fs::canonicalize(&repo).unwrap_or(repo);
        let repo_url = flags.remove("--repo-url").unwrap_or_else(|| "https://github.com/CG-Labs/superbot".into());
        let contact_url = flags
            .remove("--contact-url")
            .or_else(|| std::env::var("SUPERBOT_SITE_CONTACT_URL").ok().filter(|v| !v.is_empty()))
            .unwrap_or_else(|| repo_url.clone());
        if !["https://", "http://", "mailto:"].iter().any(|s| contact_url.starts_with(s)) {
            return Err(format!("--contact-url must be an https:, http: or mailto: URL, not {contact_url}"));
        }
        Ok(Args {
            out: flags.remove("--out").map(PathBuf::from).unwrap_or_else(|| repo.join("target/site")),
            tiers: flags.remove("--tiers").map(PathBuf::from).unwrap_or_else(|| repo.join("deploy/tiers.example.json")),
            repo,
            contact_url,
            repo_url,
        })
    }
}

#[derive(Debug)]
pub struct Summary {
    pub pages: usize,
    pub links: usize,
}

fn main() -> ExitCode {
    let args = match Args::parse(std::env::args().skip(1)) {
        Ok(a) => a,
        Err(e) if e.is_empty() => {
            print!("{USAGE}");
            return ExitCode::SUCCESS;
        }
        Err(e) => {
            eprintln!("superbot-site: {e}\n\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    match build(&args) {
        Ok(s) => {
            println!("Built {} pages into {}; {} internal links checked, none broken.", s.pages, args.out.display(), s.links);
            ExitCode::SUCCESS
        }
        Err(errors) => {
            for e in &errors {
                eprintln!("superbot-site: {e}");
            }
            eprintln!("superbot-site: {} problem(s); see above.", errors.len());
            ExitCode::FAILURE
        }
    }
}

fn write(out: &Path, path: &str, body: &[u8]) -> Result<(), String> {
    let file = out.join(path);
    if let Some(dir) = file.parent() {
        fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    }
    fs::write(&file, body).map_err(|e| format!("{}: {e}", file.display()))
}

/// Refuses to replace a non-empty folder this tool didn't make.
fn replaceable(out: &Path) -> Result<(), String> {
    if !out.exists() {
        return Ok(());
    }
    let empty = fs::read_dir(out).map_err(|e| format!("{}: {e}", out.display()))?.next().is_none();
    match empty || out.join(MARKER).is_file() {
        true => Ok(()),
        false => Err(format!("won't replace {}: it isn't empty and wasn't built by superbot-site", out.display())),
    }
}

/// Empties `out` for a fresh build, refusing a non-empty folder this tool didn't make.
fn prepare(out: &Path) -> Result<(), String> {
    replaceable(out)?;
    if out.exists() {
        fs::remove_dir_all(out).map_err(|e| format!("{}: {e}", out.display()))?;
    }
    fs::create_dir_all(out).map_err(|e| format!("{}: {e}", out.display()))?;
    write(out, MARKER, b"Built by superbot-site (server/src/bin/superbot-site). Safe to delete.\n")
}

/// Siblings of `out` that a build uses: `.<name>.<what>`, so swaps are renames on one disk.
fn sibling(out: &Path, what: &str) -> Result<PathBuf, String> {
    let name = out.file_name().ok_or(format!("--out {} has no folder name", out.display()))?;
    Ok(out.with_file_name(format!(".{}.{what}", name.to_string_lossy())))
}

/// An exclusive lock on building into `out`, held until dropped. The kernel releases it if
/// the process dies, so a crashed build never leaves it stuck.
fn lock(out: &Path) -> Result<fs::File, String> {
    use std::os::fd::AsRawFd;
    let path = sibling(out, "lock")?;
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    }
    let file = fs::OpenOptions::new().create(true).truncate(false).write(true).open(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    // SAFETY: flock on a descriptor this function owns; it only takes an advisory lock.
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err(format!("another superbot-site build into {} is running", out.display()));
    }
    Ok(file)
}

/// Removes staging and old folders that earlier builds into `out` left behind. Call it
/// only while holding the lock.
fn sweep(out: &Path) {
    let (Some(dir), Some(name)) = (out.parent(), out.file_name()) else { return };
    let dir = if dir.as_os_str().is_empty() { Path::new(".") } else { dir };
    let prefixes = [format!(".{}.building-", name.to_string_lossy()), format!(".{}.old-", name.to_string_lossy())];
    for entry in fs::read_dir(dir).into_iter().flatten().flatten() {
        let n = entry.file_name().to_string_lossy().into_owned();
        if prefixes.iter().any(|p| n.starts_with(p)) && entry.path().join(MARKER).is_file() {
            let _ = fs::remove_dir_all(entry.path());
        }
    }
}

fn docs_page(pages: &[Page], page: &Page, article: &str, repo_url: &str) -> String {
    let main = format!(
        r#"  <div class="wrap docs-layout">
{sidebar}    <main id="main" class="doc">
      <p class="crumbs"><a href="{root}docs/index.html">Docs</a> <span aria-hidden="true">/</span> {section}</p>
      <article>
{article}      </article>
      <p class="source"><a href="{repo}/blob/main/{src}">View this page's source on GitHub</a></p>
    </main>
  </div>
"#,
        sidebar = layout::sidebar(pages, &page.out),
        root = root_of(&page.out),
        section = esc(&page.section),
        repo = esc(repo_url),
        src = esc(&page.src),
    );
    let title = format!("{} · SuperBot docs", page.title);
    let description = format!("{}: {} in the SuperBot documentation.", page.title, page.section);
    layout::page(&Shell { out: &page.out, title: &title, description: &description, repo_url, docs: true }, &main)
}

fn docs_index(pages: &[Page], repo_url: &str) -> String {
    let out = "docs/index.html";
    let mut body = String::new();
    let mut sections: Vec<&str> = Vec::new();
    for p in pages {
        if !sections.contains(&p.section.as_str()) {
            sections.push(&p.section);
        }
    }
    for s in sections {
        body.push_str(&format!(
            "      <section aria-labelledby=\"{id}\">\n        <h2 id=\"{id}\">{name}</h2>\n        <ul class=\"doc-list\">\n",
            id = markdown::slug(s),
            name = esc(s)
        ));
        for p in pages.iter().filter(|p| p.section == s) {
            body.push_str(&format!("          <li><a href=\"{}\">{}</a></li>\n", markdown::rel(out, &p.out), esc(&p.title)));
        }
        body.push_str("        </ul>\n      </section>\n");
    }
    let main = format!(
        r#"  <div class="wrap docs-layout">
{sidebar}    <main id="main" class="doc">
      <h1>SuperBot docs</h1>
      <p class="lede">How to install, sign in to, run and secure SuperBot, and every decision behind it. Search from the box on the left, or browse by section.</p>
{body}    </main>
  </div>
"#,
        sidebar = layout::sidebar(pages, out),
    );
    let shell = Shell {
        out,
        title: "SuperBot docs",
        description: "Guides, single sign-on, operations, the security pack and every design decision for SuperBot.",
        repo_url,
        docs: true,
    };
    layout::page(&shell, &main)
}

/// Whitespace collapsed, cut to `max` characters.
fn squash(text: &str, max: usize) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ").chars().take(max).collect()
}

/// Builds the site and checks it in a folder beside `args.out`, then puts it in place of
/// `args.out`. A failed build leaves `args.out` as it was. Returns every problem found.
pub fn build(args: &Args) -> Result<Summary, Vec<String>> {
    let one = |e: String| vec![e];
    replaceable(&args.out).map_err(one)?;
    let _lock = lock(&args.out).map_err(one)?;
    sweep(&args.out);
    let stage = sibling(&args.out, &format!("building-{}", std::process::id())).map_err(one)?;
    prepare(&stage).map_err(one)?;
    let built = build_into(args, &stage);
    if built.is_err() {
        let _ = fs::remove_dir_all(&stage);
        return built;
    }
    swap(&stage, &args.out).map_err(one)?;
    built
}

/// Puts `stage` in place of `out` by renames, so `out` is never missing for long, and
/// puts the old site back if the second rename fails.
fn swap(stage: &Path, out: &Path) -> Result<(), String> {
    let err = |e: std::io::Error| format!("{} to {}: {e}", stage.display(), out.display());
    if !out.exists() {
        return fs::rename(stage, out).map_err(err);
    }
    let old = sibling(out, &format!("old-{}", std::process::id()))?;
    fs::rename(out, &old).map_err(|e| format!("{}: {e}", out.display()))?;
    if let Err(e) = fs::rename(stage, out) {
        let _ = fs::rename(&old, out);
        return Err(err(e));
    }
    let _ = fs::remove_dir_all(&old);
    Ok(())
}

fn build_into(args: &Args, dir: &Path) -> Result<Summary, Vec<String>> {
    let one = |e: String| vec![e];
    let pages = pages::discover(&args.repo).map_err(one)?;
    let tiers = fs::read_to_string(&args.tiers).map_err(|e| vec![format!("{}: {e}", args.tiers.display())])?;
    let plans = landing::plans(&tiers).map_err(one)?;
    let site = markdown::Site {
        repo: &args.repo,
        repo_url: &args.repo_url,
        pages: pages.iter().map(|p| (p.src.clone(), (p.out.clone(), markdown::anchors(&p.md).into_iter().collect()))).collect(),
    };
    let mut errors = Vec::new();
    let mut assets: Vec<(String, String)> = Vec::new();
    let mut index = Vec::new();
    for page in &pages {
        let r = site.render(&page.src, &page.out, &page.md);
        errors.extend(r.errors);
        assets.extend(r.assets);
        let mut headings: Vec<String> = Vec::new();
        for h in r.headings.into_iter().skip(1) {
            if !headings.contains(&h) {
                headings.push(h);
            }
        }
        index.push(serde_json::json!({
            "t": page.title,
            "u": page.out,
            "s": page.section,
            "h": headings,
            "x": squash(&r.text, SEARCH_TEXT_CHARS),
        }));
        let indented: String = r.html.lines().map(|l| format!("{l}\n")).collect();
        write(dir, &page.out, docs_page(&pages, page, &indented, &args.repo_url).as_bytes()).map_err(one)?;
    }
    write(dir, "docs/index.html", docs_index(&pages, &args.repo_url).as_bytes()).map_err(one)?;
    write(dir, "index.html", landing::landing(&plans, &args.contact_url, &args.repo_url).as_bytes()).map_err(one)?;
    assets.sort();
    assets.dedup();
    assets.push(("site/assets/site.css".into(), "assets/site.css".into()));
    assets.push(("site/assets/mark.svg".into(), "assets/mark.svg".into()));
    for (src, out) in &assets {
        let body = fs::read(args.repo.join(src)).map_err(|e| vec![format!("{src}: {e}")])?;
        write(dir, out, &body).map_err(one)?;
    }
    write(dir, "assets/docs.css", include_bytes!("assets/docs.css")).map_err(one)?;
    write(dir, "assets/search.js", include_bytes!("assets/search.js")).map_err(one)?;
    let index = serde_json::to_string(&index).map_err(|e| vec![e.to_string()])?;
    write(dir, "assets/search-index.js", format!("window.SUPERBOT_SEARCH_INDEX = {index};\n").as_bytes()).map_err(one)?;
    // A broken source link is left as written, so checking the output would only repeat it.
    if !errors.is_empty() {
        return Err(errors);
    }
    let (links, broken) = check::check(dir).map_err(|e| vec![format!("checking {}: {e}", dir.display())])?;
    match broken.is_empty() {
        true => Ok(Summary { pages: pages.len() + 2, links }),
        false => Err(broken.into_iter().map(|b| format!("built site: {b}")).collect()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn repo() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("..")
    }

    fn args(out: &Path) -> Args {
        Args {
            repo: repo(),
            out: out.to_path_buf(),
            tiers: repo().join("deploy/tiers.example.json"),
            contact_url: "mailto:sales@example.com".into(),
            repo_url: "https://github.com/CG-Labs/superbot".into(),
        }
    }

    fn tmp(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("superbot-site-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn arguments() {
        let parse = |a: &[&str]| Args::parse(a.iter().map(|s| s.to_string()));
        let a = parse(&["--out", "/tmp/x", "--contact-url", "https://example.com/sales"]).unwrap();
        assert_eq!(a.out, PathBuf::from("/tmp/x"));
        assert_eq!(a.contact_url, "https://example.com/sales");
        assert!(a.tiers.ends_with("deploy/tiers.example.json"));
        assert_eq!(parse(&["--help"]).err().unwrap(), "");
        assert_eq!(parse(&["--nope"]).err().unwrap(), "unknown argument --nope");
        assert_eq!(parse(&["--out"]).err().unwrap(), "--out needs a value");
        assert!(parse(&["--contact-url", "/get-started"]).is_err());
        assert!(parse(&["--contact-url", "javascript:alert(1)"]).is_err());
        assert_eq!(parse(&["--contact-url", "mailto:sales@example.com"]).unwrap().contact_url, "mailto:sales@example.com");
    }

    /// The real docs build with no broken links, every page is in the search index, and
    /// every index entry and nav link points at a page that was written.
    #[test]
    fn the_repository_builds_with_no_broken_links() {
        let out = tmp("build");
        let summary = build(&args(&out)).unwrap_or_else(|e| panic!("{}", e.join("\n")));
        assert!(summary.pages > 100, "{summary:?}");
        assert!(summary.links > 1000, "{summary:?}");
        for page in ["index.html", "docs/index.html", "docs/install.html", "docs/slo.html", "docs/security/index.html", "docs/sso/entra.html", "docs/adr/0001-backend.html"] {
            assert!(out.join(page).is_file(), "{page}");
        }
        for excluded in ["docs/grok-bot-reference.html", "docs/background/grok-bot-computer-specs.html"] {
            assert!(!out.join(excluded).exists(), "{excluded}");
        }
        let index = fs::read_to_string(out.join("assets/search-index.js")).unwrap();
        let json = index.strip_prefix("window.SUPERBOT_SEARCH_INDEX = ").unwrap().trim_end().strip_suffix(';').unwrap();
        let entries: Vec<serde_json::Value> = serde_json::from_str(json).unwrap();
        assert_eq!(entries.len(), summary.pages - 2);
        for e in &entries {
            let u = e["u"].as_str().unwrap();
            assert!(out.join(u).is_file(), "{u}");
            assert!(!e["t"].as_str().unwrap().is_empty());
        }
        assert!(entries.iter().any(|e| e["t"] == "SuperBot product roadmap"));
        let slo = fs::read_to_string(out.join("docs/slo.html")).unwrap();
        assert!(slo.contains(r#"<a href="slo.html" aria-current="page">"#));
        assert!(slo.contains("../assets/search.js"));
        let landing = fs::read_to_string(out.join("index.html")).unwrap();
        assert!(landing.contains(r#"href="mailto:sales@example.com""#));
        fs::remove_dir_all(&out).unwrap();
    }

    #[test]
    fn a_broken_link_fails_the_build() {
        let repo = tmp("repo");
        let src = self::repo();
        for f in ["deploy/README.md", "SECURITY.md", "CHANGELOG.md", "deploy/tiers.example.json", "site/assets/site.css", "site/assets/mark.svg"] {
            fs::create_dir_all(repo.join(f).parent().unwrap()).unwrap();
            fs::copy(src.join(f), repo.join(f)).unwrap();
        }
        // The extras link into the real docs; give them plain bodies.
        for f in ["deploy/README.md", "SECURITY.md", "CHANGELOG.md"] {
            fs::write(repo.join(f), "# Page\n").unwrap();
        }
        // Sections the landing page and footer link to.
        for (f, body) in [("docs/security/README.md", "# Pack\n"), ("docs/ops/backup.md", "# Backups\n"), ("docs/adr/0001-a.md", "# 0001: A\n")] {
            fs::create_dir_all(repo.join(f).parent().unwrap()).unwrap();
            fs::write(repo.join(f), body).unwrap();
        }
        fs::create_dir_all(repo.join("docs/sso")).unwrap();
        fs::write(repo.join("docs/slo.md"), "# SLO\n\n## Targets\n\nSee [Entra](sso/entra.md#setup).\n").unwrap();
        fs::write(repo.join("docs/sso/entra.md"), "# Entra\n\nBack to [targets](../slo.md#targets) and [gone](../gone.md).\n").unwrap();
        let out = repo.join("target/site");
        let a = Args { repo: repo.clone(), ..args(&out) };
        let errors = build(&a).unwrap_err();
        assert_eq!(errors, ["docs/slo.md:5: sso/entra.md#setup (no heading #setup)", "docs/sso/entra.md:3: ../gone.md (no such file)"]);
        assert!(!out.exists(), "a failed first build leaves nothing");
        fs::write(repo.join("docs/sso/entra.md"), "# Entra\n\n## Setup\n\nBack to [targets](../slo.md#targets).\n").unwrap();
        let s = build(&a).unwrap_or_else(|e| panic!("{}", e.join("\n")));
        assert_eq!(s.pages, 10);
        // A failed rebuild leaves the working site in place.
        fs::write(repo.join("docs/slo.md"), "# SLO\n\n## Targets\n\n[gone](gone.md)\n").unwrap();
        assert_eq!(build(&a).unwrap_err(), ["docs/slo.md:5: gone.md (no such file)"]);
        assert!(fs::read_to_string(out.join("docs/slo.html")).unwrap().contains("sso/entra.html#setup"));
        assert!(out.join(MARKER).is_file());
        let left: Vec<String> = fs::read_dir(repo.join("target")).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().into_owned()).collect();
        assert!(left.iter().all(|n| n == "site" || n == ".site.lock"), "{left:?}");
        // A build into the same folder while one is running is refused, and changes nothing.
        let held = lock(&out).unwrap();
        let err = build(&a).unwrap_err();
        assert!(err[0].contains("another superbot-site build"), "{err:?}");
        assert!(out.join("docs/slo.html").is_file());
        drop(held);
        // Leftovers from a build that died are cleared by the next one.
        let stale = repo.join("target/.site.building-1");
        prepare(&stale).unwrap();
        fs::write(repo.join("docs/slo.md"), "# SLO\n\n## Targets\n").unwrap();
        build(&a).unwrap_or_else(|e| panic!("{}", e.join("\n")));
        assert!(!stale.exists());
        fs::remove_dir_all(&repo).unwrap();
    }

    #[test]
    fn output_folders_it_did_not_make_are_left_alone() {
        let out = tmp("foreign");
        fs::create_dir_all(&out).unwrap();
        fs::write(out.join("keep.txt"), "mine").unwrap();
        let err = prepare(&out).unwrap_err();
        assert!(err.contains("won't replace"), "{err}");
        assert!(out.join("keep.txt").is_file());
        fs::remove_file(out.join("keep.txt")).unwrap();
        prepare(&out).unwrap();
        fs::write(out.join("old.html"), "").unwrap();
        prepare(&out).unwrap();
        assert!(!out.join("old.html").exists());
        fs::remove_dir_all(&out).unwrap();
    }
}
