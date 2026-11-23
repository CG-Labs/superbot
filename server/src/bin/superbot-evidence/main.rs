//! superbot-evidence: exports SOC 2 evidence from GitHub. `github` (ADR 0148): for a
//! period, every pull request merged into the branch with its reviews, approvers, required
//! checks and merge commit, the commits that reached the branch without one, the branch's
//! protection, and every CI run on the branch. `vulnerabilities` (ADR 0086): every
//! Dependabot and code scanning alert open in the period, judged against its severity's
//! remediation window, and the findings accepted with a reason. Each is a dated bundle
//! with SHA-256 digests beside botd's evidence bundles (ADR 0142). `coverage` (ADR 0166):
//! checks every bundle in an evidence store against its digests and reports the days of
//! an observation period each kind of bundle, checklist row and criterion has none for.
//!
//! Reads GitHub only, with a token from `GITHUB_TOKEN` (or `GH_TOKEN`), never from the
//! command line. Run by the `change-evidence` workflow each month, or by an operator.
//! `coverage` reads local files only.

mod changes;
mod coverage;
mod github;
#[path = "../../evidence_period.rs"]
mod period;
#[path = "../../ustar.rs"]
mod ustar;
mod vulns;

use std::io::Write;
use std::process::ExitCode;

const USAGE: &str = "superbot-evidence: SOC 2 evidence from GitHub (ADR 0148, ADR 0086), and its coverage (ADR 0166).

  superbot-evidence github --repo <owner/name> [--branch <name>]
                    [--from <YYYY-MM-DD> --to <YYYY-MM-DD>] [-o <file>] [--no-titles]
  superbot-evidence vulnerabilities --repo <owner/name> [--branch <name>]
                    [--from <YYYY-MM-DD> --to <YYYY-MM-DD>] [-o <file>]
                    [--windows critical=30,high=30,medium=90,low=90]
  superbot-evidence coverage <evidence store> [--from <YYYY-MM-DD> --to <YYYY-MM-DD>]
                    [--checklist <soc2-readiness-checklist.md>] [--json] [-o <file>]

Writes one bundle for the period (whole UTC days, --to not included; neither: last month):
every pull request merged into the branch (default: the repository's default branch) with
its reviews, approvers, checks and merge commit; commits that reached the branch without a
merged pull request; the branch's protection now; and every GitHub Actions run on the
branch. With a manifest and SHA256SUMS. Never overwrites a file. --no-titles leaves pull
request titles out.

Needs a read-only token in GITHUB_TOKEN (or GH_TOKEN): a fine-grained token with read
access to Metadata, Contents, Pull requests, Actions, Checks and Commit statuses, plus
Administration to include classic branch protection; or the workflow's own token.
GITHUB_API_URL points at GitHub Enterprise Server (default https://api.github.com).

vulnerabilities writes one bundle for the period of every Dependabot and code scanning
alert open at any time in it, each with the date it was due (opened plus its severity's
window: by default the information security policy's 30 days for Critical and High and 90
for Medium and Low) and whether it was fixed or dismissed in time or overdue at the
period's end; and the findings .cargo/audit.toml and .grype.yaml accept, with their
reasons. Needs read access to Metadata, Contents, Dependabot alerts and Code scanning
alerts (in a workflow: contents, security-events and vulnerability-alerts read). What the
token can't read is recorded in the bundle, not skipped silently.

coverage reads every bundle in an evidence store (as .tar files or unpacked folders, at any
depth): botd's evidence bundles and both bundles above. It checks each against its
SHA256SUMS and manifest, and reports, for the period (neither: from the first bundle to the
last), the days each kind of bundle, each checklist row and each criterion has no verified
evidence for, month by month, with each manifest's SHA-256 to compare with what was recorded
when it was made. --checklist also lists the rows no bundle collects evidence for. Markdown,
or --json. Exits 0 when complete, 2 when a bundle fails or a day is missing, 1 on an error.
No token and no network; it writes nothing into the store.";

#[derive(Clone, Copy, Debug, PartialEq)]
enum Kind {
    Changes,
    Vulnerabilities,
}

struct Args {
    kind: Kind,
    repo: String,
    branch: Option<String>,
    from: Option<String>,
    to: Option<String>,
    out: Option<String>,
    titles: bool,
    windows: Option<String>,
}

fn parse(args: &[String]) -> Result<Args, String> {
    let (kind, rest) = match args.split_first().map(|(c, r)| (c.as_str(), r)) {
        Some(("github", rest)) => (Kind::Changes, rest),
        Some(("vulnerabilities", rest)) => (Kind::Vulnerabilities, rest),
        _ => return Err(USAGE.into()),
    };
    let mut a = Args { kind, repo: String::new(), branch: None, from: None, to: None, out: None, titles: true, windows: None };
    let mut it = rest.iter();
    while let Some(flag) = it.next() {
        if flag == "--no-titles" && kind == Kind::Changes {
            a.titles = false;
            continue;
        }
        if matches!(flag.as_str(), "--token" | "-t") {
            return Err("Pass the token in GITHUB_TOKEN, never on the command line, where other users and shell history see it.".into());
        }
        let slot = match flag.as_str() {
            "--repo" => &mut a.repo,
            "--branch" => a.branch.get_or_insert_with(String::new),
            "--from" => a.from.get_or_insert_with(String::new),
            "--to" => a.to.get_or_insert_with(String::new),
            "-o" | "--out" => a.out.get_or_insert_with(String::new),
            "--windows" if kind == Kind::Vulnerabilities => a.windows.get_or_insert_with(String::new),
            _ => return Err(format!("Unknown option {flag}.\n\n{USAGE}")),
        };
        if !slot.is_empty() {
            return Err(format!("{flag} is given twice"));
        }
        *slot = it.next().filter(|v| !v.starts_with("--") && !v.is_empty()).ok_or(format!("{flag} needs a value"))?.clone();
    }
    if !changes::valid_repo(&a.repo) {
        return Err(format!("--repo must be owner/name.\n\n{USAGE}"));
    }
    if a.branch.as_deref().is_some_and(|b| !changes::valid_branch(b)) {
        return Err("--branch must be a plain branch name (letters, digits, . _ - /)".into());
    }
    Ok(a)
}

/// The token, from the environment only; never echoed.
fn token(get: &dyn Fn(&str) -> Option<String>) -> Result<String, String> {
    ["GITHUB_TOKEN", "GH_TOKEN"]
        .iter()
        .find_map(|k| get(k).map(|v| v.trim().to_string()).filter(|v| !v.is_empty()))
        .ok_or_else(|| "Set GITHUB_TOKEN (or GH_TOKEN) to a read-only GitHub token. See superbot-evidence --help.".into())
}

/// Writes a new file only its owner can read; never over an existing one.
fn save_private(path: &str, bytes: &[u8]) -> Result<(), String> {
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut o, 0o600);
    o.open(path).and_then(|mut f| f.write_all(bytes).and_then(|_| f.sync_all())).map_err(|e| format!("{path}: {e}"))
}

fn quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

fn hint(f: &github::Failure) -> String {
    match f.status {
        401 => format!("{}\nThe token was refused: check GITHUB_TOKEN.", f.message),
        403 | 404 => format!("{}\nThe token can't read this. See superbot-evidence --help for the read access each command needs.", f.message),
        _ => f.message.clone(),
    }
}

fn run(args: &[String]) -> Result<String, String> {
    if args.is_empty() || matches!(args[0].as_str(), "-h" | "--help" | "help") {
        return Ok(USAGE.into());
    }
    let a = parse(args)?;
    let now = chrono::Utc::now();
    let p = period::Period::parse(a.from.as_deref(), a.to.as_deref(), now.date_naive())?;
    let token = token(&|k| std::env::var(k).ok())?;
    let base = std::env::var("GITHUB_API_URL").unwrap_or_default();
    let mut gh = github::GitHub::new(&base, &token)?;
    if a.kind == Kind::Vulnerabilities {
        return vulnerabilities(&a, p, &mut gh, &token, now);
    }
    let opts = changes::Options { repo: a.repo.clone(), branch: a.branch.clone(), period: p, titles: a.titles };
    let c = changes::collect(&mut gh, &opts).map_err(|f| hint(&f))?;
    if gh.scopes.as_deref().is_some_and(changes::can_write) {
        eprintln!("Warning: this token can write ({}). Use a fine-grained token with read-only access.", gh.scopes.as_deref().unwrap_or_default());
    }
    let src = changes::Source { api_host: gh.host(), requests: gh.requests, scopes: gh.scopes.clone() };
    let b = changes::build(&c, &p, &src, now.timestamp_millis());
    if b.tar.windows(token.len()).any(|w| w == token.as_bytes()) {
        return Err("The bundle would contain the token, so it wasn't written.".into());
    }
    let file = a.out.clone().unwrap_or_else(|| format!("{}.tar", b.name));
    save_private(&file, &b.tar)?;
    Ok(format!(
        "Saved {file} ({} KB) for {} from {} to {} (not included), in {} requests.\n{}\nManifest SHA-256: {}\nBundle SHA-256: {}\nKeep it in the evidence store; to check it:\n  tar -xf {} && (cd {} && sha256sum -c SHA256SUMS)",
        b.tar.len().div_ceil(1024),
        c.repo["fullName"].as_str().unwrap_or(&a.repo),
        p.from,
        p.to,
        gh.requests,
        changes::summary(&c),
        b.manifest_sha256,
        b.sha256,
        quote(&file),
        quote(&b.name),
    ))
}

fn vulnerabilities(a: &Args, p: period::Period, gh: &mut github::GitHub, token: &str, now: chrono::DateTime<chrono::Utc>) -> Result<String, String> {
    let windows = a.windows.as_deref().map(vulns::Windows::parse).transpose()?.unwrap_or_default();
    let opts = vulns::Options { repo: a.repo.clone(), branch: a.branch.clone(), period: p, windows: windows.clone() };
    let c = vulns::collect(gh, &opts, now.timestamp_millis()).map_err(|f| hint(&f))?;
    if gh.scopes.as_deref().is_some_and(changes::can_write) {
        eprintln!("Warning: this token can write ({}). Use a fine-grained token with read-only access.", gh.scopes.as_deref().unwrap_or_default());
    }
    let src = changes::Source { api_host: gh.host(), requests: gh.requests, scopes: gh.scopes.clone() };
    let b = vulns::build(&c, &p, &windows, &src, now.timestamp_millis());
    if b.tar.windows(token.len()).any(|w| w == token.as_bytes()) {
        return Err("The bundle would contain the token, so it wasn't written.".into());
    }
    let file = a.out.clone().unwrap_or_else(|| format!("{}.tar", b.name));
    save_private(&file, &b.tar)?;
    Ok(format!(
        "Saved {file} ({} KB) for {} from {} to {} (not included), in {} requests.\n{}\nManifest SHA-256: {}\nBundle SHA-256: {}\nKeep it in the evidence store; to check it:\n  tar -xf {} && (cd {} && sha256sum -c SHA256SUMS)",
        b.tar.len().div_ceil(1024),
        c.repo["fullName"].as_str().unwrap_or(&a.repo),
        p.from,
        p.to,
        gh.requests,
        vulns::summary(&c),
        b.manifest_sha256,
        b.sha256,
        quote(&file),
        quote(&b.name),
    ))
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().is_some_and(|a| a == "coverage") {
        return match coverage::run(&args[1..], chrono::Utc::now()) {
            Ok((out, complete)) => {
                println!("{out}");
                if complete { ExitCode::SUCCESS } else { ExitCode::from(2) }
            }
            Err(e) => {
                eprintln!("{e}");
                ExitCode::FAILURE
            }
        };
    }
    match run(&args) {
        Ok(out) => {
            println!("{out}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("{e}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(s: &[&str]) -> Vec<String> {
        s.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn options_and_the_token_only_from_the_environment() {
        let a = parse(&args(&["github", "--repo", "o/r", "--from", "2026-10-01", "--to", "2026-11-01", "-o", "x.tar", "--no-titles", "--branch", "main"])).unwrap();
        assert_eq!((a.repo.as_str(), a.branch.as_deref(), a.from.as_deref(), a.to.as_deref(), a.out.as_deref(), a.titles), ("o/r", Some("main"), Some("2026-10-01"), Some("2026-11-01"), Some("x.tar"), false));
        for bad in [&["github"][..], &["github", "--repo", "nope"], &["github", "--repo", "o/r", "--repo", "o/s"], &["github", "--repo", "o/r", "--from"], &["github", "--repo", "o/r", "--bogus", "x"], &["gitlab", "--repo", "o/r"], &["github", "--repo", "o/r", "--branch", "a b"]] {
            assert!(parse(&args(bad)).is_err(), "{bad:?}");
        }
        let e = parse(&args(&["github", "--repo", "o/r", "--token", "ghp_x"])).err().unwrap();
        assert!(e.contains("GITHUB_TOKEN") && !e.contains("ghp_x"), "{e}");
        assert_eq!(token(&|k| (k == "GH_TOKEN").then(|| " t1 ".into())).unwrap(), "t1");
        assert_eq!(token(&|k| Some(if k == "GITHUB_TOKEN" { "t2" } else { "t1" }.into())).unwrap(), "t2");
        assert!(token(&|_| Some("  ".into())).is_err());

        let v = parse(&args(&["vulnerabilities", "--repo", "o/r", "--windows", "critical=7", "-o", "v.tar"])).unwrap();
        assert_eq!((v.kind, v.windows.as_deref(), v.out.as_deref()), (Kind::Vulnerabilities, Some("critical=7"), Some("v.tar")));
        assert!(parse(&args(&["vulnerabilities", "--repo", "o/r", "--no-titles"])).is_err(), "titles are the change bundle's");
        assert!(parse(&args(&["github", "--repo", "o/r", "--windows", "high=1"])).is_err(), "windows are the vulnerability bundle's");
        assert!(parse(&args(&["vulnerabilities", "--repo", "o/r", "--token", "x"])).is_err());
    }
}
