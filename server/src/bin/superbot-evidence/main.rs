//! superbot-evidence: exports SOC 2 evidence from GitHub. `github` (ADR 0148): for a
//! period, every pull request merged into the branch with its reviews, approvers, required
//! checks and merge commit, the commits that reached the branch without one, the branch's
//! protection, and every CI run on the branch. `vulnerabilities` (ADR 0086): every
//! Dependabot and code scanning alert open in the period, judged against its severity's
//! remediation window, and the findings accepted with a reason. `drills` (ADR 0177): every
//! restore drill CI ran on the branch, with its step's result and time and the artifacts
//! it kept, and the records of drills the operator ran on their own servers. Each is a
//! dated bundle with SHA-256 digests beside botd's evidence bundles (ADR 0142). `coverage` (ADR 0169):
//! checks every bundle in an evidence store against its digests and reports the days of
//! an observation period each kind of bundle, checklist row and criterion has none for.
//! `register` (ADR 0204): checks the security owner's private policy register (role
//! holders, policy approvals, acknowledgements and training, risks, management reviews,
//! vendors, exceptions, conduct concerns, security incidents and tabletop exercises)
//! against the policies' cadences, as a bundle naming people by id. `uptime` (ADR 0249):
//! the availability SLO measured from the outside probe's checks, from Prometheus or the
//! probe's exported files, month by month against the objectives. `alerts` (ADR 0288):
//! every SuperBot alert the operator's Prometheus fired, the stretches it wasn't watching
//! botd, the rules loaded against those shipped, and Alertmanager's notifications.
//! `sample` and `results` (ADR 0296): samples drawn from the store's populations by a
//! seeded ranking anyone can re-perform, with a worksheet for the tester, and the
//! filled-in worksheet checked against them. `deficiencies` (ADR 0326): every exception
//! the store's bundles and the control-testing results list for a period, tracked from
//! bundle to bundle with its rows and owners, as the management review's deficiency log.
//!
//! Reads GitHub only, with a token from `GITHUB_TOKEN` (or `GH_TOKEN`), never from the
//! command line. Run by the `change-evidence` workflow each month, or by an operator.
//! `coverage`, `register`, `sample`, `results` and `deficiencies` read local files only, and so do `drills --no-ci` and
//! `uptime --checks`; `uptime --prometheus` and `alerts` read only the operator's
//! Prometheus.

mod alerts;
mod changes;
mod coverage;
mod deficiencies;
mod drills;
mod github;
#[path = "../../evidence_period.rs"]
mod period;
mod prometheus;
mod register;
mod sample;
mod uptime;
#[path = "../../ustar.rs"]
mod ustar;
mod vulns;

use std::io::Write;
use std::process::ExitCode;

const USAGE: &str = "superbot-evidence: SOC 2 evidence from GitHub (ADR 0148, ADR 0086), restore drills (ADR 0177), the policy register (ADR 0204), uptime (ADR 0249), alert history (ADR 0288), its coverage (ADR 0169), samples to test it on (ADR 0296), and the deficiencies it lists (ADR 0326).

  superbot-evidence github --repo <owner/name> [--branch <name>]
                    [--from <YYYY-MM-DD> --to <YYYY-MM-DD>] [-o <file>] [--no-titles]
  superbot-evidence vulnerabilities --repo <owner/name> [--branch <name>]
                    [--from <YYYY-MM-DD> --to <YYYY-MM-DD>] [-o <file>]
                    [--windows critical=30,high=30,medium=90,low=90]
  superbot-evidence drills --repo <owner/name> [--branch <name>] [--record <drill output>]...
                    [--from <YYYY-MM-DD> --to <YYYY-MM-DD>] [-o <file>] [--no-ci]
  superbot-evidence coverage <evidence store> [--from <YYYY-MM-DD> --to <YYYY-MM-DD>]
                    [--checklist <soc2-readiness-checklist.md>] [--json] [-o <file>]
  superbot-evidence register <register.json> [--policies <folder>] [--baseline <file>]...
                    [--from <YYYY-MM-DD> --to <YYYY-MM-DD>] [-o <file>]
  superbot-evidence uptime (--prometheus <url> [--query <selector>] | --checks <file>...)
                    [--objective <percent>] [--maintenance <from>/<to>]...
                    [--from <YYYY-MM-DD> --to <YYYY-MM-DD>] [-o <file>]
  superbot-evidence alerts --prometheus <url> [--watch <selector>] [--rules <rule file>]...
                    [--from <YYYY-MM-DD> --to <YYYY-MM-DD>] [-o <file>]
  superbot-evidence sample <evidence store> [--from <YYYY-MM-DD> --to <YYYY-MM-DD>]
                    [--seed <text>] [--size <test>=<n>]... [-o <file>]
  superbot-evidence results <samples bundle> <worksheet.csv> [-o <file>]
  superbot-evidence deficiencies <evidence store> [--from <YYYY-MM-DD> --to <YYYY-MM-DD>]
                    [--checklist <soc2-readiness-checklist.md>] [--results <results bundle>]...
                    [--since <previous deficiency log>] [-o <file>]

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

drills writes one bundle for the period of every run on the branch of the restore drills
CI performs (the installer's restore onto a fresh host in server.yml, the Compose restore
in docker.yml, and an Incus container's restore and a lost host's in incus-e2e.yml): each
drill step's result, start and duration, and the drill artifacts the run kept, with
GitHub's digest and expiry. Needs read access to Metadata and Actions. Each --record is the
saved output of a drill the operator ran (deploy/backup-drill.sh or
deploy/machine-restore-drill.sh); its record line, timed against its objective, and the
output's SHA-256 go in the bundle, and it must have finished in the period. --no-ci reads
only the records: no --repo, token or network.

coverage reads every bundle in an evidence store (as .tar files or unpacked folders, at any
depth): botd's evidence bundles and the three bundles above. It checks each against its
SHA256SUMS and manifest, and reports, for the period (neither: from the first bundle to the
last), the days each kind of bundle, each checklist row and each criterion has no verified
evidence for, month by month, with each manifest's SHA-256 to compare with what was recorded
when it was made. --checklist also lists the rows no bundle collects evidence for. Markdown,
or --json. Exits 0 when complete, 2 when a bundle fails or a day is missing, 1 on an error.
No token and no network; it writes nothing into the store.

register reads the security owner's policy register (docs/security/policy-register.md; a
JSON file kept outside this repository) and writes one bundle for the period (a month at
most, judged as of its end) of what it shows: each role's holder and deputy every day, each policy's latest approval (by the
role its header names, within a year, and with --policies, of the text in force),
everyone's acknowledgements and awareness training, engineers' secure-development
training and everyone's screening before access, recorded by the people lead (ADR 0312;
with --training docs/security/training, the courses' texts in force are recorded), the
open risks and their reviews, a management
review each quarter, vendors assessed before use and reviewed yearly, their SOC 2 or
ISO 27001 reports reviewed in the year, still current, with complementary controls
noted and findings treated as risks (ADR 0279), exceptions
approved, ended within a year and reviewed quarterly, conduct concerns triaged within
7 days and closed within 90 (ADR 0214), and security events triaged in time by the
security owner or operator, breach notices sent within the DPA's hours, post-incident
reviews within 10 business days of closing, their actions done on time and a tabletop
exercise each year (ADR 0223), and production access granted on the security owner's
(and for admin to a managed server or the hosting provider, Management's) approval,
removed by a leaver's last day, and reviewed each quarter with MFA recorded and findings
fixed in time (ADR 0231), and vulnerabilities found outside the scans acknowledged,
assessed and fixed or accepted within SECURITY.md's targets, and a penetration test each
year with its critical and high findings retested (ADR 0241), and production changes
recorded and approved by someone else before they were made, announced 48 hours ahead
when they could interrupt the service and checked the next business day, and emergency
changes approved by the incident commander, reviewed by a second person within 2
business days and listed at the next management review (ADR 0270); with each --baseline (botctl
evidence baseline json, or the month's evidence bundle's baseline.json, checked in the
period or the 7 days after it), every setting the server excepted held to an exception in
force; with each --access-review <system>=<file> (a managed server's register id and its
evidence bundle access-review.json), each review of that server matched to an access_review.completed sign-off of the same
digest that day. Refuses a register that
doesn't hold together (unknown people, roles or policies, ids that aren't plain), listing
every problem. People are named by register id; names, titles and notes stay out. No
token and no network.

uptime writes one bundle for the period of the availability SLO (docs/slo.md) measured
from the outside probe's checks of /status.json: a minute is down when it had checks and
every one failed, unmeasured when it had none; each calendar month and the period against
--objective (default 99.9, the strictest plan on the server) and every plan's, the error
budget spent, every outage and those that spent more than a quarter of the 30-day budget
(a written review is due), and the gaps in the probe's record. --prometheus reads the
blackbox exporter's raw samples of --query (default probe_success{job=\"superbot-status\"})
a day at a time, with a token from PROMETHEUS_TOKEN if it needs one (https, or http to
this computer). --checks reads any other probe's export instead: one check a line,
<time>,<result>[,<location>], the time as RFC 3339 or Unix seconds and the result 1/0,
true/false or up/down. Each --maintenance window was announced maintenance and doesn't
count, up to 4 hours a month. It maps to A1.1-3 only while the probe's gaps fit in the
error budget.

alerts writes one bundle for the period of what the operator's Prometheus alerted on:
every SuperBot alert that fired (from ALERTS{alertstate=\"firing\"}, read a day at a time
like uptime), as episodes with their severity and minutes, the pages listed for their
response records; the stretches of more than 5 minutes with no sample of --watch (default
up{job=\"superbot\"}, botd's scrape), when no alert could fire; the alerting rules loaded
now against those deploy/prometheus ships (or each --rules file the operator loads):
missing, failing, not evaluated, or with another severity; and Alertmanager's
notifications sent and failed each day, where Prometheus scrapes it. Labels that could
name a host stay out. It maps to CC2.1-1, CC7.2-1 and A1.1-1 only while the unwatched
minutes fit in the 99.9% error budget and every expected rule is loaded, healthy and
evaluated. Token and address as for uptime --prometheus.

sample reads the evidence store as coverage does and, for the period, gathers each test's
population from the bundles that check (docs/security/soc2-evidence-plan.md, Testing
samples): merged pull requests, production changes, access grants and reviews, security
events, reported vulnerabilities, closed scanner alerts, pages and days of backups. It
draws each sample by ranking every item on SHA-256 of the seed, test and item and taking
the lowest: 1 of 1, 2 of up to 12, 5 of up to 52, else 25, or --size. The seed is derived
from the store unless --seed gives the auditor's. It writes a bundle of the samples, each
population's size, SHA-256 and the days or bundles it is missing, and worksheet.csv for
the tester; it copies no evidence. results checks a filled-in copy of that worksheet (a
result of pass, fail or n/a, the tester's register id and the day tested for each item)
against the samples bundle and writes a bundle of the results and each test's deviations,
untested items and incomplete populations. Exits 0 when nothing deviated and everything
was tested, 2 otherwise, 1 on an error. No token and no network.

deficiencies reads the evidence store as coverage does and writes one bundle for the
period (for the quarterly management review, give the quarter) of every exception the
bundles that check list, and each --results bundle's deviations, untested items and
incomplete populations: each tracked from bundle to bundle by its id, with when it was
first and last listed, whether the newest bundle of its source still lists it, and the
checklist rows it bears on; with --checklist, their owners and the rows that aren't Done;
with --since, which findings of the previous log are still listed, no longer listed or
new; and the store's own problems, from the coverage report. deficiencies.md has the same
for the review's papers. Exits 0 when nothing is still listed and the store is complete,
2 otherwise, 1 on an error. No token and no network; it writes nothing into the store.";

#[derive(Clone, Copy, Debug, PartialEq)]
enum Kind {
    Changes,
    Vulnerabilities,
    Drills,
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
    records: Vec<String>,
    ci: bool,
}

fn parse(args: &[String]) -> Result<Args, String> {
    let (kind, rest) = match args.split_first().map(|(c, r)| (c.as_str(), r)) {
        Some(("github", rest)) => (Kind::Changes, rest),
        Some(("vulnerabilities", rest)) => (Kind::Vulnerabilities, rest),
        Some(("drills", rest)) => (Kind::Drills, rest),
        _ => return Err(USAGE.into()),
    };
    let mut a = Args { kind, repo: String::new(), branch: None, from: None, to: None, out: None, titles: true, windows: None, records: Vec::new(), ci: true };
    let mut it = rest.iter();
    while let Some(flag) = it.next() {
        if flag == "--no-titles" && kind == Kind::Changes {
            a.titles = false;
            continue;
        }
        if flag == "--no-ci" && kind == Kind::Drills {
            a.ci = false;
            continue;
        }
        if flag == "--record" && kind == Kind::Drills {
            a.records.push(it.next().filter(|v| !v.starts_with("--") && !v.is_empty()).ok_or("--record needs a file")?.clone());
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
    if kind == Kind::Drills && !a.ci {
        if !a.repo.is_empty() || a.branch.is_some() {
            return Err("--no-ci reads only the drill records: leave out --repo and --branch".into());
        }
        if a.records.is_empty() {
            return Err("--no-ci needs at least one --record".into());
        }
        return Ok(a);
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
    if a.kind == Kind::Drills && !a.ci {
        return drills(&a, p, None, now);
    }
    let token = token(&|k| std::env::var(k).ok())?;
    let base = std::env::var("GITHUB_API_URL").unwrap_or_default();
    let mut gh = github::GitHub::new(&base, &token)?;
    if a.kind == Kind::Vulnerabilities {
        return vulnerabilities(&a, p, &mut gh, &token, now);
    }
    if a.kind == Kind::Drills {
        return drills(&a, p, Some((&mut gh, &token)), now);
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

/// Each `--record`'s drill record, read before GitHub so a wrong file fails fast.
fn records(files: &[String], p: &period::Period) -> Result<Vec<serde_json::Value>, String> {
    let mut out: Vec<serde_json::Value> = Vec::new();
    for f in files {
        let size = std::fs::metadata(f).map_err(|e| format!("{f}: {e}"))?.len();
        if size > drills::MAX_RECORD_BYTES {
            return Err(format!("{f} is over {} MiB, larger than any drill's output", drills::MAX_RECORD_BYTES >> 20));
        }
        let r = drills::record(f, &std::fs::read(f).map_err(|e| format!("{f}: {e}"))?, p)?;
        if out.iter().any(|x| x["fileSha256"] == r["fileSha256"]) {
            return Err(format!("{f} is the same output as another --record"));
        }
        out.push(r);
    }
    out.sort_by(|a, b| a["finishedAt"].as_str().cmp(&b["finishedAt"].as_str()));
    Ok(out)
}

fn drills(a: &Args, p: period::Period, gh: Option<(&mut github::GitHub, &str)>, now: chrono::DateTime<chrono::Utc>) -> Result<String, String> {
    let recs = records(&a.records, &p)?;
    let (c, src, token) = match gh {
        Some((gh, token)) => {
            let opts = drills::Options { repo: a.repo.clone(), branch: a.branch.clone(), period: p };
            let c = drills::collect(gh, &opts, now.timestamp_millis()).map_err(|f| hint(&f))?;
            if gh.scopes.as_deref().is_some_and(changes::can_write) {
                eprintln!("Warning: this token can write ({}). Use a fine-grained token with read-only access.", gh.scopes.as_deref().unwrap_or_default());
            }
            (Some(c), changes::Source { api_host: gh.host(), requests: gh.requests, scopes: gh.scopes.clone() }, Some(token))
        }
        None => (None, changes::Source { api_host: String::new(), requests: 0, scopes: None }, None),
    };
    let b = drills::build(c.as_ref(), &recs, &p, &src, now.timestamp_millis());
    if token.is_some_and(|t| b.tar.windows(t.len()).any(|w| w == t.as_bytes())) {
        return Err("The bundle would contain the token, so it wasn't written.".into());
    }
    let file = a.out.clone().unwrap_or_else(|| format!("{}.tar", b.name));
    save_private(&file, &b.tar)?;
    let what = c.as_ref().map(|c| c.repo["fullName"].as_str().unwrap_or(&a.repo).to_string()).unwrap_or_else(|| "the operator's drill records".into());
    Ok(format!(
        "Saved {file} ({} KB) for {what} from {} to {} (not included), in {} requests.\n{}\nManifest SHA-256: {}\nBundle SHA-256: {}\nKeep it in the evidence store, with each drill output it names; to check it:\n  tar -xf {} && (cd {} && sha256sum -c SHA256SUMS)",
        b.tar.len().div_ceil(1024),
        p.from,
        p.to,
        src.requests,
        drills::summary(c.as_ref(), &recs),
        b.manifest_sha256,
        b.sha256,
        quote(&file),
        quote(&b.name),
    ))
}

/// A command that parses its own options and prints what it saved.
type Command = fn(&[String], chrono::DateTime<chrono::Utc>) -> Result<String, String>;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let own: Option<Command> = match args.first().map(String::as_str) {
        Some("register") => Some(register::run),
        Some("uptime") => Some(uptime::run),
        Some("alerts") => Some(alerts::run),
        Some("sample") => Some(sample::run_sample),
        _ => None,
    };
    if let Some(run) = own {
        return match run(&args[1..], chrono::Utc::now()) {
            Ok(out) => {
                println!("{out}");
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("{e}");
                ExitCode::FAILURE
            }
        };
    }
    let judged: Option<fn(&[String], chrono::DateTime<chrono::Utc>) -> Result<(String, bool), String>> = match args.first().map(String::as_str) {
        Some("coverage") => Some(coverage::run),
        Some("results") => Some(sample::run_results),
        Some("deficiencies") => Some(deficiencies::run),
        _ => None,
    };
    if let Some(judge) = judged {
        return match judge(&args[1..], chrono::Utc::now()) {
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

        let d = parse(&args(&["drills", "--repo", "o/r", "--record", "a.log", "--record", "b.log"])).unwrap();
        assert_eq!((d.kind, d.records.clone(), d.ci), (Kind::Drills, vec!["a.log".to_string(), "b.log".to_string()], true));
        let offline = parse(&args(&["drills", "--no-ci", "--record", "a.log"])).unwrap();
        assert!(!offline.ci && offline.repo.is_empty());
        for bad in [&["drills", "--no-ci"][..], &["drills", "--no-ci", "--repo", "o/r", "--record", "a"], &["drills", "--repo", "o/r", "--record"], &["github", "--repo", "o/r", "--record", "a"], &["vulnerabilities", "--repo", "o/r", "--no-ci"], &["drills", "--record", "a"]] {
            assert!(parse(&args(bad)).is_err(), "{bad:?}");
        }
    }
}
