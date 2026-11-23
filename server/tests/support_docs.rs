//! The support playbooks (`docs/support/`, #60) are what support staff follow under
//! pressure and what customers are promised, so they must stay true. Every link and
//! anchor resolves and every `ADR NNNN` exists; the support tiers list every plan the
//! shipped tiers file sells with the SLO's availability and recovery numbers; severity
//! targets cover every plan; the runbooks keep their shape; the TAM cadence runs from
//! kickoff through health checks to reviews; every `botctl` command they name exists; and no contact person, email or phone number is invented: contacts are
//! placeholders the Provider fills in.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..")
}

fn support() -> PathBuf {
    repo().join("docs/support")
}

fn read(name: &str) -> String {
    fs::read_to_string(support().join(name)).unwrap_or_else(|e| panic!("docs/support/{name}: {e}"))
}

fn pages() -> Vec<PathBuf> {
    let mut files: Vec<PathBuf> = fs::read_dir(support())
        .expect("docs/support exists")
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|e| e == "md"))
        .collect();
    files.sort();
    files
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

fn links(md: &str) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    for (n, line) in prose(md) {
        let mut rest = line.as_str();
        while let Some(at) = rest.find("](") {
            let after = &rest[at + 2..];
            let Some(end) = after.find(')') else { break };
            out.push((n, after[..end].split_whitespace().next().unwrap_or("").to_string()));
            rest = &after[end..];
        }
    }
    out
}

/// GitHub's anchor for each heading.
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
        let slug: String = line
            .trim_start_matches('#')
            .trim()
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
    let name = file.file_name().unwrap().to_string_lossy().into_owned();
    let mut bad = Vec::new();
    for (line, target) in links(&md) {
        if target.is_empty() || target.contains("://") || target.starts_with("mailto:") {
            continue;
        }
        let (path, anchor) = target.split_once('#').map_or((target.as_str(), None), |(p, a)| (p, Some(a)));
        let resolved = if path.is_empty() { file.to_path_buf() } else { file.parent().unwrap().join(path) };
        if !resolved.exists() {
            bad.push(format!("{name}:{line}: {target} (no such file)"));
        } else if let Some(a) = anchor
            && resolved.extension().is_some_and(|e| e == "md")
            && !anchors(&fs::read_to_string(&resolved).unwrap()).contains(a)
        {
            bad.push(format!("{name}:{line}: {target} (no such heading)"));
        }
    }
    let adrs: Vec<String> = fs::read_dir(repo().join("docs/adr")).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().into_owned()).collect();
    for (line, text) in prose(&md) {
        let mut rest = text.as_str();
        while let Some(at) = rest.find("ADR ") {
            let n: String = rest[at + 4..].chars().take_while(char::is_ascii_digit).collect();
            if n.len() == 4 && !adrs.iter().any(|f| f.starts_with(&format!("{n}-"))) {
                bad.push(format!("{name}:{line}: ADR {n} (no such ADR)"));
            }
            rest = &rest[at + 4..];
        }
    }
    bad
}

/// Table rows as trimmed cells, for rows whose first cell is one of `keys`.
fn rows<'a>(md: &'a str, keys: &[&str]) -> HashMap<String, Vec<&'a str>> {
    md.lines()
        .filter_map(|l| {
            let cells: Vec<&str> = l.strip_prefix('|')?.strip_suffix('|')?.split('|').map(str::trim).collect();
            let key = cells.first()?.trim_matches('*');
            keys.contains(&key).then(|| (key.to_string(), cells))
        })
        .collect()
}

/// The labels of the tiers the shipped tiers file sells (ADR 0121: a Stripe or published price).
fn sold() -> Vec<String> {
    let tiers: serde_json::Value = serde_json::from_str(&fs::read_to_string(repo().join("deploy/tiers.example.json")).unwrap()).unwrap();
    tiers["tiers"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|t| t.get("stripePrices").is_some() || t.get("publishedPrices").is_some())
        .map(|t| t["label"].as_str().unwrap().to_string())
        .collect()
}

#[test]
fn every_link_in_the_playbooks_resolves() {
    let mut files = pages();
    files.push(repo().join("docs/adr/0131-support-bundle.md"));
    files.push(repo().join("docs/adr/0144-tam-programme-and-health-score.md"));
    files.push(repo().join("docs/adr/0157-health-score-history-and-console.md"));
    files.push(repo().join("docs/adr/0167-support-report-from-ticket-exports.md"));
    files.push(repo().join("docs/adr/0187-offline-support-check-and-bundle.md"));
    files.push(repo().join("docs/adr/0201-incident-review-drafts.md"));
    files.push(repo().join("docs/adr/0211-support-readiness-check.md"));
    let bad: Vec<String> = files.iter().flat_map(|f| broken(f)).collect();
    assert!(bad.is_empty(), "broken links:\n{}", bad.join("\n"));
}

#[test]
fn the_index_links_every_playbook() {
    let index = read("README.md");
    let linked: HashSet<String> = links(&index).into_iter().map(|(_, t)| t.split('#').next().unwrap().to_string()).collect();
    for page in pages() {
        let name = page.file_name().unwrap().to_string_lossy().into_owned();
        if name != "README.md" {
            assert!(linked.contains(&name), "docs/support/README.md doesn't link {name}");
        }
    }
}

#[test]
fn support_tiers_match_the_plans_and_the_slo() {
    let sold = sold();
    assert!(!sold.is_empty(), "the example tiers file sells plans");
    let keys: Vec<&str> = sold.iter().map(String::as_str).chain(["Self-host (licensed)", "Enterprise"]).collect();
    let tiers = read("tiers.md");
    let support = rows(&tiers, &keys);
    let slo_md = fs::read_to_string(repo().join("docs/slo.md")).unwrap();
    let slo = rows(&slo_md, &keys);
    for plan in &sold {
        let ours = support.get(plan).unwrap_or_else(|| panic!("tiers.md has no row for {plan}"));
        let theirs = slo.get(plan).unwrap_or_else(|| panic!("slo.md has no row for {plan}"));
        assert_eq!(ours[4], theirs[1], "{plan}'s availability differs from the SLO");
        assert_eq!(ours[5], theirs[3], "{plan}'s RPO / RTO differs from the SLO");
    }
    assert_eq!(support["Enterprise"][4], slo["Enterprise"][1], "Enterprise's availability");
    assert!(support["Enterprise"].iter().skip(1).filter(|c| c.contains("agreement")).count() >= 3, "Enterprise is by agreement");
    assert!(support.contains_key("Self-host (licensed)"), "the licensed self-host plan has support too");
    assert!(tiers.contains("Hermes Agent") && tiers.contains("best effort"), "the SLA covers Hermes, others best effort");
}

#[test]
fn severity_targets_cover_every_plan_and_severity() {
    let md = read("severity.md");
    let header = md.lines().find(|l| l.starts_with("| Severity | Self-host")).expect("the response targets table");
    for plan in sold().iter().map(String::as_str).chain(["Self-host (licensed)", "Enterprise"]) {
        assert!(header.contains(plan), "response targets have no column for {plan}");
    }
    let columns = header.matches('|').count() - 1;
    let section = md.split("## Response targets").nth(1).unwrap().split("\n## ").next().unwrap();
    let targets = rows(section, &["1", "2", "3", "4"]);
    assert_eq!(targets.len(), 4, "a row per severity");
    for (sev, cells) in &targets {
        assert_eq!(cells.len(), columns, "severity {sev}'s row");
        assert!(cells.iter().skip(1).all(|c| !c.is_empty()), "severity {sev} has an empty target");
    }
    for sev in ["1: Critical", "2: High", "3: Normal", "4: Low"] {
        assert!(md.contains(&format!("**{sev}**")), "severity {sev} isn't defined");
    }
}

#[test]
fn runbooks_say_what_to_do_first_and_when_to_escalate() {
    let names: Vec<String> = pages().iter().map(|p| p.file_name().unwrap().to_string_lossy().into_owned()).filter(|n| n.starts_with("runbook-")).collect();
    assert!(names.len() >= 9, "the runbooks: {names:?}");
    for name in &names {
        let md = read(name);
        for heading in ["## First five minutes", "## Escalate when", "## Afterwards"] {
            assert!(md.lines().any(|l| l == heading), "{name} has no \"{heading}\"");
        }
        assert!(md.contains("severity.md"), "{name} doesn't size the incident");
    }
}

#[test]
fn every_botctl_command_named_exists() {
    let botctl = fs::read_to_string(repo().join("server/src/bin/botctl.rs")).unwrap();
    let mut bad = Vec::new();
    for page in pages() {
        let md = fs::read_to_string(&page).unwrap();
        let mut rest = md.as_str();
        while let Some(at) = rest.find("botctl ") {
            let words: Vec<&str> = rest[at + 7..].split(|c: char| c.is_whitespace() || c == '`').take(2).collect();
            let first = words[0];
            if first.chars().all(|c| c.is_ascii_lowercase() || c == '-') && !first.is_empty() {
                let second = words.get(1).copied().unwrap_or("");
                let cmd = if second.chars().all(|c| c.is_ascii_lowercase() || c == '-') && !second.is_empty() { format!("{first} {second}") } else { first.to_string() };
                if !botctl.contains(&format!("botctl {cmd}")) && !botctl.contains(&format!("botctl {first}")) {
                    bad.push(format!("{}: botctl {cmd}", page.file_name().unwrap().to_string_lossy()));
                }
            }
            rest = &rest[at + 7..];
        }
    }
    assert!(bad.is_empty(), "commands botctl doesn't have:\n{}", bad.join("\n"));
}

#[test]
fn contacts_are_placeholders_never_invented() {
    for page in pages() {
        let name = page.file_name().unwrap().to_string_lossy().into_owned();
        let md = fs::read_to_string(&page).unwrap();
        for (line, text) in prose(&md) {
            let digits_run = text.split(|c: char| !(c.is_ascii_digit() || " +-().".contains(c))).map(|s| s.chars().filter(char::is_ascii_digit).count()).max().unwrap_or(0);
            assert!(digits_run < 9, "{name}:{line} looks like a phone number: {text}");
            let email = text.split_whitespace().any(|w| {
                let w = w.trim_matches(|c: char| !c.is_alphanumeric());
                w.split_once('@').is_some_and(|(l, d)| !l.is_empty() && d.contains('.'))
            });
            assert!(!email, "{name}:{line} has an email address; use a placeholder: {text}");
        }
    }
    let readme = read("README.md");
    for placeholder in ["<support-email>", "<support-portal-url>", "<security-email>", "<status-page-url>"] {
        assert!(readme.contains(placeholder), "README.md lacks {placeholder}");
    }
    assert!(read("tiers.md").contains("<tam-name>"), "the named contact is a placeholder");
    assert!(read("escalation.md").contains("<on-call-pager>"), "the on-call route is a placeholder");
    let tam = read("tam.md");
    for placeholder in ["<tam-name>", "<tam-email>", "<backup-tam-name>"] {
        assert!(tam.contains(placeholder), "tam.md lacks {placeholder}");
    }
}

#[test]
fn the_tam_cadence_runs_kickoff_health_checks_and_reviews() {
    let tam = read("tam.md");
    let cadence = tam.split("## Cadence").nth(1).expect("tam.md has a cadence").split("\n## ").next().unwrap();
    for needle in ["(#kickoff-agenda)", "(health-check.md)", "(health-score.md)", "(qbr-template.md)", "Severity 1"] {
        assert!(cadence.contains(needle), "the cadence lacks {needle}");
    }
    for page in ["health-check.md", "qbr-template.md"] {
        let md = read(page);
        assert!(md.contains("botctl health-score"), "{page} doesn't start from the health score");
    }
}

#[test]
fn the_support_report_page_documents_every_option_and_field() {
    let code = fs::read_to_string(repo().join("server/src/support_report.rs")).unwrap();
    let usage = code.split("pub const USAGE: &str = \"").nth(1).unwrap().split("\";").next().unwrap();
    let page = read("support-report.md");
    let options: HashSet<&str> = usage.split(|c: char| c.is_whitespace() || "[]|".contains(c)).filter(|w| w.starts_with("--")).collect();
    assert!(options.len() >= 12, "the usage's options: {options:?}");
    for o in options {
        assert!(page.contains(&format!("`{o}")), "support-report.md doesn't explain {o}");
    }
    let fields = code.split("fn name(self) -> &'static str {").nth(1).unwrap().split("\n    }\n").next().unwrap();
    for f in fields.split("=> \"").skip(1).map(|r| r.split('"').next().unwrap()) {
        assert!(page.contains(&format!("| `{f}` |")), "support-report.md has no row for the {f} field");
    }
    for page in ["severity.md", "qbr-template.md", "health-check.md"] {
        assert!(read(page).contains("(support-report.md"), "{page} doesn't point at the support report");
    }
}

#[test]
fn the_support_check_page_documents_every_check_and_option() {
    let code = fs::read_to_string(repo().join("server/src/support_check.rs")).unwrap();
    let usage = code.split("const USAGE: &str = \"").nth(1).unwrap().split("\n\n").next().unwrap();
    let page = read("support-check.md");
    let options: HashSet<&str> = usage.split(|c: char| c.is_whitespace() || "[]|".contains(c)).filter(|w| w.starts_with('-') && w.len() > 1).collect();
    assert!(options.len() >= 7, "the usage's options: {options:?}");
    for o in options {
        assert!(page.contains(&format!("`{o}")), "support-check.md doesn't explain {o}");
    }
    let ids: HashSet<&str> = code.split("Finding::new(\"").skip(1).map(|r| r.split('"').next().unwrap()).collect();
    assert_eq!(ids.len(), 7, "the checks: {ids:?}");
    let headings = anchors(&page);
    for id in ids {
        assert!(headings.contains(id), "support-check.md has no section for the {id} check");
    }
    for runbook in ["runbook-upgrade.md", "runbook-server-restore.md", "runbook-machine-down.md"] {
        assert!(read(runbook).contains("botd support check"), "{runbook} doesn't start from the support check");
    }
    assert!(read("runbook-upgrade.md").contains("--before-upgrade"), "the upgrade runbook checks before it upgrades");
    assert!(read("support-bundle.md").contains("(support-check.md#the-offline-bundle)"), "the support bundle points at the offline one");
}

#[test]
fn the_incidents_page_documents_both_commands_and_the_draft() {
    let botctl = fs::read_to_string(repo().join("server/src/bin/botctl.rs")).unwrap();
    let usage = botctl.split("const INCIDENT_USAGE: &str = \"").nth(1).unwrap().split("\";").next().unwrap();
    let page = read("incident-review.md");
    let options: HashSet<&str> = usage.split(|c: char| c.is_whitespace() || "[]|".contains(c)).filter(|w| w.starts_with('-') && w.len() > 1).collect();
    assert!(options.len() >= 9, "the usage's options: {options:?}");
    for o in options {
        assert!(page.contains(&format!("`{o}")), "incident-review.md doesn't explain {o}");
    }
    let code = fs::read_to_string(repo().join("server/src/incident_review.rs")).unwrap();
    let sections: Vec<&str> = code.split("## ").skip(1).map(|r| r.split(['\\', '"']).next().unwrap()).collect();
    assert!(sections.len() >= 8, "the draft's sections: {sections:?}");
    let lower = page.to_lowercase();
    for s in sections {
        assert!(lower.contains(&s.to_lowercase()), "incident-review.md doesn't describe the draft's \"{s}\" section");
    }
    let runbook = read("runbook-major-incident.md");
    for cmd in ["botctl incident open", "botctl incident update", "botctl incident resolve", "botctl incident review", "--detected"] {
        assert!(runbook.contains(cmd), "the Severity 1 runbook doesn't use {cmd}");
    }
    let escalation = read("escalation.md");
    assert!(escalation.contains("botctl incident review") && escalation.contains("(runbook-major-incident.md)"), "escalation doesn't point at the review draft and the runbook");
}

#[test]
fn the_readiness_page_documents_every_option_field_and_placeholder() {
    let code = fs::read_to_string(repo().join("server/src/support_readiness.rs")).unwrap();
    let usage = code.split("pub const USAGE: &str = \"").nth(1).unwrap().split("\";").next().unwrap();
    let page = read("readiness.md");
    let options: HashSet<&str> = usage.split(|c: char| c.is_whitespace() || "[]|".contains(c)).filter(|w| w.starts_with("--")).collect();
    assert!(options.len() >= 15, "the usage's options: {options:?}");
    for o in options {
        assert!(page.contains(&format!("`{o}")), "readiness.md doesn't explain {o}");
    }
    let fields = code.split("pub fn name(self) -> &'static str {").nth(1).unwrap().split("\n    }\n").next().unwrap();
    let fields: Vec<&str> = fields.split("=> \"").skip(1).map(|r| r.split('"').next().unwrap()).collect();
    assert_eq!(fields.len(), 7, "the fields: {fields:?}");
    for f in fields {
        assert!(page.contains(&format!("| `{f}` |")), "readiness.md has no row for the {f} field");
    }

    let list = |name: &str| -> Vec<String> {
        let body = code.split(&format!("pub const {name}: [&str; ")).nth(1).unwrap().split("];").next().unwrap();
        body.split('"').skip(1).step_by(2).map(String::from).collect()
    };
    let (provider, per_customer) = (list("PROVIDER_PLACEHOLDERS"), list("PER_CUSTOMER_PLACEHOLDERS"));
    assert!(provider.len() >= 15 && per_customer.len() == 3, "{provider:?} {per_customer:?}");
    let all: String = pages().iter().map(|p| fs::read_to_string(p).unwrap()).collect();
    for p in provider.iter().chain(&per_customer) {
        assert!(all.contains(p.as_str()), "no playbook uses {p}");
    }
    for name in ["README.md", "tiers.md", "severity.md", "escalation.md", "tam.md", "runbook-major-incident.md"] {
        let md = read(name);
        for code_span in md.split('`').skip(1).step_by(2) {
            let is_placeholder = code_span.starts_with('<') && code_span.ends_with('>') && code_span[1..code_span.len() - 1].chars().all(|c| c.is_ascii_lowercase() || c == '-');
            if is_placeholder {
                assert!(provider.iter().chain(&per_customer).any(|p| p == code_span), "{name}'s {code_span} isn't on support-readiness's lists");
            }
        }
    }
    for p in &provider {
        assert!(!page.contains(p.as_str()), "readiness.md has {p} in brackets, so it would count against itself");
        assert!(page.contains(&p[1..p.len() - 1]), "readiness.md doesn't name {p}");
    }

    for (name, needle) in [("README.md", "(readiness.md"), ("tam.md", "botctl support-readiness"), ("escalation.md", "botctl support-readiness"), ("support-report.md", "(readiness.md")] {
        assert!(read(name).contains(needle), "{name} doesn't point at support readiness");
    }
}
