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
    files.push(repo().join("docs/adr/0220-support-bundle-triage.md"));
    files.push(repo().join("docs/adr/0233-onboarding-check.md"));
    files.push(repo().join("docs/adr/0243-onboarding-check-in-the-console-and-the-bundle.md"));
    files.push(repo().join("docs/adr/0252-monthly-health-check.md"));
    files.push(repo().join("docs/adr/0262-business-review-draft.md"));
    files.push(repo().join("docs/adr/0271-health-check-in-the-support-bundle.md"));
    files.push(repo().join("docs/adr/0278-tam-handover-draft.md"));
    files.push(repo().join("docs/adr/0286-update-targets-from-a-replies-export.md"));
    files.push(repo().join("docs/adr/0289-escalations-due-now-from-the-ticket-exports.md"));
    files.push(repo().join("docs/adr/0295-tam-cadence-across-accounts.md"));
    files.push(repo().join("docs/adr/0307-health-score-alerts.md"));
    files.push(repo().join("docs/adr/0313-runbooks-for-scim-backups-and-the-license.md"));
    files.push(repo().join("docs/adr/0322-runbooks-for-the-secrets-store-and-the-audit-trail.md"));
    files.push(repo().join("docs/adr/0331-every-alert-links-its-runbook.md"));
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
fn the_support_report_page_documents_update_targets() {
    let code = fs::read_to_string(repo().join("server/src/support_updates.rs")).unwrap();
    let page = read("support-report.md");
    let section = page.split("\n## Update targets\n").nth(1).expect("support-report.md has an Update targets section").split("\n## ").next().unwrap();
    let fields = code.split("fn name(self) -> &'static str {").nth(1).unwrap().split("\n    }\n").next().unwrap();
    let fields: Vec<&str> = fields.split("=> \"").skip(1).map(|r| r.split('"').next().unwrap()).collect();
    assert_eq!(fields.len(), 5, "{fields:?}");
    for f in fields {
        assert!(section.contains(&format!("| `{f}` |")), "the update targets section has no row for the {f} field");
    }
    for needle in ["Severity 1", "Severity 2", "Severity 3", "Severity 4", "first answer", "overdue", "--update-target 2=4h", "ADR 0286"] {
        assert!(page.contains(needle), "support-report.md's update targets don't mention {needle}");
    }
    for page in ["severity.md", "qbr-template.md", "escalation.md", "README.md"] {
        assert!(read(page).contains("(support-report.md#update-targets)"), "{page} doesn't point at the update targets");
    }
}

#[test]
fn the_escalation_check_page_documents_every_option_and_code() {
    let code = fs::read_to_string(repo().join("server/src/support_escalations.rs")).unwrap();
    let usage = code.split("pub const USAGE: &str = \"").nth(1).unwrap().split("\";").next().unwrap();
    let page = read("escalation-check.md");
    let options: HashSet<&str> = usage.split(|c: char| c.is_whitespace() || "[]|".contains(c)).filter(|w| w.starts_with("--")).collect();
    assert!(options.len() >= 14, "the usage's options: {options:?}");
    for o in options {
        assert!(page.contains(&format!("`{o}")), "escalation-check.md doesn't explain {o}");
    }
    let flags = page.split("\n## What it flags\n").nth(1).expect("escalation-check.md has a What it flags section").split("\n## ").next().unwrap();
    let codes = code.split("pub fn code(self) -> &'static str {").nth(1).unwrap().split("\n    }\n").next().unwrap();
    let codes: Vec<&str> = codes.split("=> \"").skip(1).map(|r| r.split('"').next().unwrap()).collect();
    assert_eq!(codes.len(), 7, "{codes:?}");
    for c in codes {
        assert!(flags.contains(&format!("| `{c}` |")), "escalation-check.md has no row for {c}");
    }
    for needle in ["ADR 0289", "tells nobody", "exits 1", "Severity 1", "Severity 2", "about to be missed", "(support-report.md#the-export)", "(support-report.md#update-targets)"] {
        assert!(page.contains(needle), "escalation-check.md doesn't mention {needle}");
    }
    for name in ["escalation.md", "README.md", "runbook-major-incident.md"] {
        assert!(read(name).contains("(escalation-check.md"), "{name} doesn't point at the escalation check");
    }
}

#[test]
fn the_tam_cadence_page_documents_every_option_field_and_item() {
    let code = fs::read_to_string(repo().join("server/src/tam_cadence.rs")).unwrap();
    let usage = code.split("pub const USAGE: &str = \"").nth(1).unwrap().split("\";").next().unwrap();
    let page = read("tam-cadence.md");
    let options: HashSet<&str> = usage.split(|c: char| c.is_whitespace() || "[]|".contains(c)).filter(|w| w.starts_with("--")).collect();
    assert!(options.len() >= 11, "the usage's options: {options:?}");
    for o in options {
        assert!(page.contains(&format!("`{o}")), "tam-cadence.md doesn't explain {o}");
    }
    let export = page.split("\n## The export\n").nth(1).expect("tam-cadence.md has an export section").split("\n## ").next().unwrap();
    let fields = code.split("pub fn name(self) -> &'static str {").nth(1).unwrap().split("\n    }\n").next().unwrap();
    let fields: Vec<&str> = fields.split("=> \"").skip(1).map(|r| r.split('"').next().unwrap()).collect();
    assert_eq!(fields.len(), 12, "{fields:?}");
    for f in fields {
        assert!(export.contains(&format!("| `{f}` |")), "tam-cadence.md has no row for the {f} field");
    }
    let flags = page.split("\n## What it flags\n").nth(1).expect("tam-cadence.md has a What it flags section").split("\n## ").next().unwrap();
    let items = code.split("pub fn code(self) -> &'static str {").nth(1).unwrap().split("\n    }\n").next().unwrap();
    let items: Vec<&str> = items.split("=> \"").skip(1).map(|r| r.split('"').next().unwrap()).collect();
    assert_eq!(items.len(), 7, "{items:?}");
    for i in items {
        assert!(flags.contains(&format!("| `{i}` |")), "tam-cadence.md has no row for {i}");
    }
    for needle in ["ADR 0295", "tells nobody", "exits 1", "Severity 1", "5 business days", "31 days", "183 days", "(tam.md#cadence)", "(readiness.md#the-tam-list)"] {
        assert!(page.contains(needle), "tam-cadence.md doesn't mention {needle}");
    }
    for name in ["tam.md", "README.md", "readiness.md"] {
        assert!(read(name).contains("(tam-cadence.md"), "{name} doesn't point at the TAM cadence check");
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

/// The quoted names in `code` followed by `then`: `("api", api_health` gives `api`.
fn quoted_before<'a>(code: &'a str, then: &str) -> Vec<&'a str> {
    code.split("(\"").skip(1).filter_map(|r| r.split_once('"')).filter(|(_, rest)| rest.starts_with(then)).map(|(name, _)| name).collect()
}

#[test]
fn the_triage_page_documents_every_option_and_finding() {
    let full = fs::read_to_string(repo().join("server/src/support_triage.rs")).unwrap();
    let code = full.split("#[cfg(test)]\nmod tests").next().unwrap();
    let page = read("triage.md");
    let usage = code.split("pub const USAGE: &str = \"").nth(1).unwrap().split("\";").next().unwrap();
    let options: HashSet<&str> = usage.split(|c: char| c.is_whitespace() || "[]|".contains(c)).filter(|w| w.starts_with("--")).collect();
    assert!(options.len() >= 6, "the usage's options: {options:?}");
    for o in options {
        assert!(page.contains(&format!("`{o}")), "triage.md doesn't explain {o}");
    }
    let mut ids: HashSet<String> = code.split("Finding::new(").skip(1).filter_map(|r| r.trim_start().strip_prefix('"')).map(|r| r.split('"').next().unwrap().to_string()).collect();
    assert!(ids.len() >= 20, "the findings: {ids:?}");
    let groups = code.split("fn audit_group").nth(1).unwrap().split("\n}\n").next().unwrap();
    let groups = quoted_before(groups, ", \"");
    assert!(groups.len() >= 9, "the audit groups: {groups:?}");
    ids.extend(groups.iter().map(|g| format!("audit.{g}")));
    let status = fs::read_to_string(repo().join("server/src/status.rs")).unwrap();
    let components = quoted_before(status.split("pub fn checks").nth(1).unwrap().split("\n}\n").next().unwrap(), ", ");
    assert_eq!(components, ["api", "database", "machines", "runners", "notifications"], "the status page's components");
    for c in &components {
        assert!(code.contains(&format!("\"{c}\"")), "support_triage doesn't place the {c} component");
    }
    ids.extend(components.iter().map(|c| format!("status.{c}")));
    let score = fs::read_to_string(repo().join("server/src/health_score.rs")).unwrap();
    ids.extend(score.split("Signal { id: \"").skip(1).map(|r| format!("signal.{}", r.split('"').next().unwrap())));
    let check = fs::read_to_string(repo().join("server/src/support_check.rs")).unwrap();
    ids.extend(check.split("Finding::new(\"").skip(1).map(|r| format!("check.{}", r.split('"').next().unwrap())));
    for id in &ids {
        assert!(page.contains(&format!("`{id}`")), "triage.md doesn't explain the {id} finding");
    }
    for (name, needle) in [("README.md", "(triage.md"), ("support-bundle.md", "botctl support-triage"), ("escalation.md", "botctl support-triage")] {
        assert!(read(name).contains(needle), "{name} doesn't point at bundle triage");
    }
}

#[test]
fn the_onboarding_check_page_documents_every_item_status_and_option() {
    let full = fs::read_to_string(repo().join("server/src/onboarding.rs")).unwrap();
    let code = full.split("#[cfg(test)]\nmod tests").next().unwrap();
    let page = read("onboarding-check.md");
    let ids: Vec<&str> = code.split("    item(\"").skip(1).map(|r| r.split('"').next().unwrap()).collect();
    assert_eq!(ids.len(), 32, "the items: {ids:?}");
    for id in &ids {
        assert!(page.contains(&format!("| `{id}` |")), "onboarding-check.md doesn't explain the {id} item");
    }
    let as_str = code.split("pub fn as_str").nth(1).unwrap().split("\n    }\n").next().unwrap();
    let statuses: Vec<&str> = as_str.split("=> \"").skip(1).map(|r| r.split('"').next().unwrap()).collect();
    assert_eq!(statuses, ["done", "open", "confirm", "n/a", "skipped"], "the statuses");
    for s in &statuses {
        assert!(page.contains(&format!("| `{s}` |")), "onboarding-check.md doesn't explain {s}");
    }
    let botctl = fs::read_to_string(repo().join("server/src/bin/botctl.rs")).unwrap();
    let usage = botctl.lines().find(|l| l.contains("botctl onboarding [")).expect("botctl's usage has onboarding");
    for o in ["--skip", "markdown", "json"] {
        assert!(usage.contains(o), "botctl's usage lacks {o}");
        assert!(page.contains(&format!("| `{o}")), "onboarding-check.md doesn't explain {o}");
    }
    assert!(page.contains("support.onboarding_checked") && page.contains("GET /api/support/onboarding"), "the audit action and the route");
    for (name, needle) in [("README.md", "(onboarding-check.md"), ("onboarding.md", "botctl onboarding"), ("tam.md", "botctl onboarding")] {
        assert!(read(name).contains(needle), "{name} doesn't point at the onboarding check");
    }
    for (heading, needle) in [("In the console", "Check onboarding"), ("In the support bundle", "onboarding.json")] {
        assert!(anchors(&page).contains(&heading.to_lowercase().replace(' ', "-")), "onboarding-check.md has no \"{heading}\" section");
        assert!(page.contains(needle), "onboarding-check.md doesn't mention {needle}");
    }
}

/// ADR 0252: the health check page explains every item `botctl health-check` judges, its
/// statuses and options, the route and the audit action, and the TAM's cadence points at it.
#[test]
fn the_health_check_page_documents_every_item_status_and_option() {
    let full = fs::read_to_string(repo().join("server/src/health_check.rs")).unwrap();
    let code = full.split("#[cfg(test)]\nmod tests").next().unwrap();
    let page = read("health-check.md");
    let ids: Vec<&str> = code.split("    item(\"").skip(1).map(|r| r.split('"').next().unwrap()).collect();
    assert_eq!(ids.len(), 22, "the items: {ids:?}");
    let reads = page.split("## What botd reads").nth(1).expect("health-check.md has a \"What botd reads\" section");
    let rows: Vec<&str> = reads.lines().filter_map(|l| l.strip_prefix("| `")).filter_map(|l| l.split('`').next()).collect();
    assert_eq!(rows, ids, "health-check.md's table of what botd reads, in the checklist's order");
    let as_str = code.split("pub fn as_str").nth(1).unwrap().split("\n    }\n").next().unwrap();
    let statuses: Vec<&str> = as_str.split("=> \"").skip(1).map(|r| r.split('"').next().unwrap()).collect();
    assert_eq!(statuses, ["done", "open", "confirm", "n/a"], "the statuses");
    for s in &statuses {
        assert!(page.contains(&format!("| `{s}` |")), "health-check.md doesn't explain {s}");
    }
    let botctl = fs::read_to_string(repo().join("server/src/bin/botctl.rs")).unwrap();
    let usage = botctl.lines().find(|l| l.contains("botctl health-check [")).expect("botctl's usage has health-check");
    for o in ["markdown", "json"] {
        assert!(usage.contains(o), "botctl's usage lacks {o}");
        assert!(page.contains(&format!("| `{o}")), "health-check.md doesn't explain {o}");
    }
    for needle in ["support.health_checked", "GET /api/support/health-check", "Run health check"] {
        assert!(page.contains(needle), "health-check.md doesn't mention {needle}");
    }
    for (name, needle) in [("README.md", "botctl health-check"), ("tam.md", "botctl health-check")] {
        assert!(read(name).contains(needle), "{name} doesn't point at botctl health-check");
    }
    // ADR 0271: the bundle carries the check, and triage reads it.
    assert!(anchors(&page).contains("in-the-support-bundle"), "health-check.md has no \"In the support bundle\" section");
    let bundle = page.split("## In the support bundle").nth(1).unwrap().split("\n## ").next().unwrap();
    for needle in ["health-check.json", "support.health_checked", "health_check.open", "health_check.saml"] {
        assert!(bundle.contains(needle), "health-check.md's bundle section doesn't mention {needle}");
    }
    let triage = fs::read_to_string(repo().join("server/src/support_triage.rs")).unwrap();
    let shown = triage.split("HEALTH_CHECK_SHOWN_ELSEWHERE: [&str; ").nth(1).unwrap().split(';').next().unwrap();
    for id in shown.split('"').skip(1).step_by(2) {
        assert!(bundle.contains(&format!("`{id}`")), "health-check.md's bundle section doesn't say triage leaves out {id}");
    }
}

/// ADR 0262: the business review template explains `botctl business-review`, each of its
/// options, the route, the audit action and the console's link, and says what botd fills in
/// for each of its sections; the index and the TAM's cadence point at the command.
#[test]
fn the_business_review_template_documents_its_draft() {
    let page = read("qbr-template.md");
    let botctl = fs::read_to_string(repo().join("server/src/bin/botctl.rs")).unwrap();
    let usage = botctl.lines().find(|l| l.contains("botctl business-review [")).expect("botctl's usage has business-review");
    let options: Vec<&str> = usage.split(|c: char| c.is_whitespace() || "[]".contains(c)).filter(|w| w.starts_with('-')).collect();
    assert_eq!(options, ["--to", "--json", "-o"], "the usage's options");
    for o in options {
        assert!(page.contains(&format!("| `{o}")), "qbr-template.md doesn't explain {o}");
    }
    for needle in ["support.business_review_drafted", "GET /api/support/business-review", "Draft business review", "## Draft it first"] {
        assert!(page.contains(needle), "qbr-template.md doesn't mention {needle}");
    }
    let sections: Vec<&str> = page.lines().filter_map(|l| l.strip_prefix("### ")).filter(|l| l.starts_with(|c: char| c.is_ascii_digit())).collect();
    assert_eq!(sections.len(), 7, "the template's sections: {sections:?}");
    let fills = page.split("## Draft it first").nth(1).unwrap().split("\n---").next().unwrap();
    for s in sections {
        assert!(fills.contains(&format!("| {s} |")), "the draft's table doesn't say what botd fills in for {s}");
    }
    for (name, needle) in [("README.md", "botctl business-review"), ("tam.md", "botctl business-review")] {
        assert!(read(name).contains(needle), "{name} doesn't point at botctl business-review");
    }
}

/// ADR 0278: the TAM page explains `botctl tam-handover`, each of its options, the route,
/// the audit action and the console's link, and says what botd fills in for each part of
/// the handover; the index points at the command.
#[test]
fn the_tam_page_documents_the_handover_draft() {
    let page = read("tam.md");
    let botctl = fs::read_to_string(repo().join("server/src/bin/botctl.rs")).unwrap();
    let usage = botctl.lines().find(|l| l.contains("botctl tam-handover [")).expect("botctl's usage has tam-handover");
    let options: Vec<&str> = usage.split(|c: char| c.is_whitespace() || "[]".contains(c)).filter(|w| w.starts_with('-')).collect();
    assert_eq!(options, ["--json", "-o"], "the usage's options");
    let draft = page.split("### Draft it first").nth(1).expect("tam.md has the handover draft").split("\n## ").next().unwrap();
    for o in options {
        assert!(draft.contains(&format!("| `{o}")), "tam.md doesn't explain {o}");
    }
    for needle in ["support.tam_handover_drafted", "GET /api/support/tam-handover", "Draft TAM handover"] {
        assert!(draft.contains(needle), "tam.md's handover draft doesn't mention {needle}");
    }
    let code = fs::read_to_string(repo().join("server/src/tam_handover.rs")).unwrap();
    let parts: Vec<&str> = code.lines().filter_map(|l| l.trim().strip_prefix("let _ = writeln!(m, \"## ")).filter_map(|l| l.split("\\n").next()).collect();
    assert_eq!(parts.len(), 5, "the draft's parts: {parts:?}");
    for p in parts {
        assert!(draft.contains(&format!("| {p} |")), "tam.md's table doesn't say what botd fills in for {p}");
    }
    assert!(read("README.md").contains("botctl tam-handover"), "README.md doesn't point at botctl tam-handover");
}

/// ADR 0307: the health score page explains the alerts: the audit action, every gauge
/// `health_alert::render` writes and the rule file, every alert of which is a ticket;
/// the TAM page and the index point at them.
#[test]
fn the_health_score_page_documents_its_alerts() {
    let page = read("health-score.md");
    let alerts = page.split("\n## Alerts\n").nth(1).expect("health-score.md has Alerts").split("\n## ").next().unwrap();
    let code = fs::read_to_string(repo().join("server/src/health_alert.rs")).unwrap();
    assert!(code.contains("pub const FELL: &str = \"support.health_score_fell\";"));
    let render = code.split("pub fn render(").nth(1).unwrap().split("\n}\n").next().unwrap();
    let gauges: Vec<&str> = render.split("metrics::family(out, \"").skip(1).filter_map(|r| r.split('"').next()).collect();
    assert_eq!(gauges.len(), 4, "the gauges: {gauges:?}");
    for needle in gauges.iter().copied().chain(["support.health_score_fell", "superbot-health-score.rules.yml", "HEALTH_SCORE_HISTORY_DAYS"]) {
        assert!(alerts.contains(needle), "health-score.md's alerts don't mention {needle}");
    }
    let rules = fs::read_to_string(repo().join("deploy/prometheus/superbot-health-score.rules.yml")).unwrap();
    assert_eq!(rules.matches("- alert:").count(), 4);
    assert_eq!(rules.matches("severity: ticket").count(), 4, "the score changes once a day: nothing pages");
    assert!(read("tam.md").contains("(health-score.md#alerts)"), "tam.md doesn't point at the alerts");
    assert!(read("README.md").contains("(health-score.md#alerts)"), "README.md doesn't point at the alerts");
}

/// The code of a source file under `server/src/`, without its unit tests.
fn source(path: &str) -> String {
    let full = fs::read_to_string(repo().join("server/src").join(path)).unwrap_or_else(|e| panic!("server/src/{path}: {e}"));
    full.split("#[cfg(test)]\nmod tests").next().unwrap().to_string()
}

/// A runbook section's inline code, from its heading to the next.
fn codes_in(md: &str, heading: &str) -> HashSet<String> {
    let section = md.split(&format!("\n{heading}\n")).nth(1).unwrap_or_else(|| panic!("no \"{heading}\"")).split("\n## ").next().unwrap();
    section.split('`').skip(1).step_by(2).map(String::from).collect()
}

/// ADR 0313: every reason botd records on `scim.request_failed` (`insufficient_scope`, a
/// `scimType` in snake case, or `status_` and the status when there's none) is in the SCIM
/// runbook's table, with the two the health score names for tokens it no longer accepts.
#[test]
fn the_scim_runbook_explains_every_reason_botd_records() {
    let mut files = vec!["scim.rs".to_string()];
    let mut sub: Vec<String> = fs::read_dir(repo().join("server/src/scim"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|e| e == "rs"))
        .map(|p| format!("scim/{}", p.file_name().unwrap().to_string_lossy()))
        .collect();
    sub.sort();
    files.extend(sub);
    let mut reasons: HashSet<String> = ["insufficient_scope", "revoked_token", "expired_token"].map(String::from).into();
    for f in &files {
        for r in source(f).split("ScimError::new(StatusCode::").skip(1) {
            let (status, rest) = r.split_once(", ").unwrap();
            if let Some(t) = rest.strip_prefix("Some(\"") {
                let t = t.split('"').next().unwrap();
                reasons.insert(t.chars().flat_map(|c| if c.is_ascii_uppercase() { vec!['_', c.to_ascii_lowercase()] } else { vec![c] }).collect());
            } else {
                let code = match status {
                    "NOT_FOUND" | "UNAUTHORIZED" => continue,
                    "BAD_REQUEST" => 400,
                    "FORBIDDEN" => 403,
                    "METHOD_NOT_ALLOWED" => 405,
                    "CONFLICT" => 409,
                    "PAYLOAD_TOO_LARGE" => 413,
                    "TOO_MANY_REQUESTS" => 429,
                    "INTERNAL_SERVER_ERROR" => 500,
                    "NOT_IMPLEMENTED" => 501,
                    "SERVICE_UNAVAILABLE" => 503,
                    other => panic!("{f}: a SCIM error with status {other}: add it here and to runbook-scim.md"),
                };
                reasons.insert(format!("status_{code}"));
            }
        }
    }
    assert!(reasons.len() >= 15 && reasons.contains("uniqueness") && reasons.contains("status_501"), "the reasons: {reasons:?}");
    let table = codes_in(&read("runbook-scim.md"), "## Reasons and fixes");
    let mut missing: Vec<&String> = reasons.iter().filter(|r| !table.contains(*r)).collect();
    missing.sort();
    assert!(missing.is_empty(), "runbook-scim.md's reasons and fixes don't explain {missing:?}");
}

/// ADR 0313: the license runbook explains every mode a license can be in, every reason a
/// key isn't one (its token's, the setting's, and an install's refusal), and every
/// `license.*` audit action.
#[test]
fn the_license_runbook_explains_every_mode_reason_and_action() {
    let page = read("runbook-license.md");
    let token = source("license/token.rs");
    let code = token.split("pub fn code(self)").nth(1).unwrap().split("\n    }\n").next().unwrap();
    let mut reasons: Vec<String> = code.split("=> \"").skip(1).map(|r| r.split('"').next().unwrap().to_string()).collect();
    let lic = source("license/mod.rs");
    reasons.extend(lic.split("Problem { code: \"").skip(1).map(|r| r.split('"').next().unwrap().to_string()));
    reasons.extend(lic.split("refuse(\"").skip(1).map(|r| r.split('"').next().unwrap().to_string()));
    assert!(reasons.len() >= 11 && reasons.contains(&"unknown_key".to_string()) && reasons.contains(&"set_in_env".to_string()), "the reasons: {reasons:?}");
    let table = codes_in(&page, "## Reasons and fixes");
    for r in &reasons {
        assert!(table.contains(r), "runbook-license.md's reasons and fixes don't explain {r}");
    }
    let modes_enum = lic.split("pub enum Mode {").nth(1).unwrap().split('}').next().unwrap();
    let modes: Vec<String> = modes_enum.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with("//")).map(|l| l.trim_end_matches(',').to_lowercase()).collect();
    assert_eq!(modes, ["unlicensed", "active", "grace", "expired", "invalid"], "the modes");
    let table = codes_in(&page, "## Modes");
    for m in &modes {
        assert!(table.contains(m), "runbook-license.md's modes don't explain {m}");
    }
    let actions: HashSet<&str> = ["event(\"license.", "), \"license."].iter().flat_map(|p| lic.split(p).skip(1)).map(|r| r.split('"').next().unwrap()).collect();
    assert!(actions.len() >= 5, "the actions: {actions:?}");
    for a in actions {
        assert!(page.contains(&format!("`license.{a}`")), "runbook-license.md doesn't mention license.{a}");
    }
}

/// ADR 0313: every failure botd audits for server and machine backups is in the backups
/// runbook, where bundle triage's `audit.backups` points.
#[test]
fn the_backups_runbook_names_every_backup_failure() {
    let page = read("runbook-backups.md");
    let mut failures = HashSet::new();
    for (file, prefixes) in [
        ("server_backups.rs", &["\"server.backup_"][..]),
        ("machines/backup.rs", &["\"machine.backup"][..]),
        ("machines/mod.rs", &["\"machine.backup"][..]),
        ("machines/recovery.rs", &["\"machine.rpo_"][..]),
    ] {
        let code = source(file);
        for p in prefixes {
            for (i, _) in code.match_indices(p) {
                let action = code[i + 1..].split('"').next().unwrap();
                if ["_failed", "_breached", "_refused"].iter().any(|s| action.ends_with(s)) {
                    failures.insert(action.to_string());
                }
            }
        }
    }
    assert!(failures.len() >= 7 && failures.contains("server.backup_rpo_breached") && failures.contains("machine.rpo_breached"), "the failures: {failures:?}");
    for f in &failures {
        assert!(page.contains(&format!("`{f}`")), "runbook-backups.md doesn't name {f}");
    }
    let triage = source("support_triage.rs");
    assert!(triage.contains("(\"backups\", \"backup failures\", Some(\"support/runbook-backups.md\"))"), "triage's audit.backups points at the runbook");
}

/// ADR 0313: the health score's SCIM, backups and license playbooks, the health check's
/// items and the index point at their runbooks.
#[test]
fn scim_backups_and_license_have_runbooks() {
    let score = read("health-score.md");
    for (signal, book) in [("identity", "runbook-scim.md"), ("backups", "runbook-backups.md"), ("license", "runbook-license.md")] {
        let section = score.split(&format!("\n### `{signal}`\n")).nth(1).unwrap().split("\n#").next().unwrap();
        assert!(section.contains(&format!("({book}")), "health-score.md's {signal} doesn't point at {book}");
    }
    let check = source("health_check.rs");
    for (item, book) in [("scim", "runbook-scim.md"), ("backups", "runbook-backups.md"), ("license", "runbook-license.md")] {
        let line = check.lines().find(|l| l.trim_start().starts_with(&format!("item(\"{item}\""))).unwrap();
        assert!(line.contains(&format!("\"docs/support/{book}\"")), "the health check's {item} item's guide isn't {book}");
    }
    let index = read("README.md");
    for book in ["runbook-scim.md", "runbook-backups.md", "runbook-license.md"] {
        assert!(index.contains(&format!("]({book})")), "README.md's runbooks don't list {book}");
    }
}

/// ADR 0131, 0243: the support bundle's page lists every file `support::build` writes,
/// and so does the README inside the bundle.
#[test]
fn the_support_bundle_page_lists_every_file_in_it() {
    let code = fs::read_to_string(repo().join("server/src/support.rs")).unwrap();
    let build = code.split("pub fn build(").nth(1).unwrap().split("\n}\n").next().unwrap();
    let files: Vec<&str> = quoted_before(build, ", ").into_iter().filter(|n| n.contains('.')).collect();
    assert!(files.len() >= 10 && files.contains(&"onboarding.json") && files.contains(&"manifest.json"), "the bundle's files: {files:?}");
    let page = read("support-bundle.md");
    let readme = code.split("const README: &str = \"").nth(1).unwrap().split("\";").next().unwrap();
    for f in files {
        assert!(page.contains(&format!("| `{f}` |")), "support-bundle.md doesn't list {f}");
        assert!(f == "README.txt" || readme.contains(&format!("  {f}")), "the bundle's README.txt doesn't list {f}");
    }
}

/// The quoted code after each `marker` in `code`: `Err(("delivery_failed", ...` gives
/// `delivery_failed`.
fn quoted_after(code: &str, marker: &str) -> Vec<String> {
    code.split(marker).skip(1).filter_map(|r| r.split('"').next()).filter(|c| !c.is_empty() && c.chars().all(|c| c.is_ascii_lowercase() || c == '_')).map(String::from).collect()
}

/// ADR 0322: every reason botd records when the audit export fails or stops, when a check
/// of the chain fails (with its checkpoints' and timestamps' reasons), and when timestamps
/// fail, is in the audit trail runbook's section for it; triage and the rules point there.
#[test]
fn the_audit_trail_runbook_explains_every_reason_botd_records() {
    let page = read("runbook-audit-trail.md");
    let mut export: HashSet<String> = HashSet::new();
    for f in ["audit_export.rs", "audit_azure.rs", "audit_secops.rs", "audit_datadog.rs", "audit_archive.rs"] {
        let code = source(f);
        export.extend(quoted_after(&code, "Err((\""));
        export.extend(quoted_after(&code, "|e| (\""));
    }
    export.extend(quoted_after(&source("audit_archive.rs"), "pub const NOT_WRITE_ONCE: &str = \""));
    assert!(export.len() >= 5 && ["delivery_failed", "sign_in_failed", "unreadable", "cursor_unsaved", "not_write_once"].iter().all(|r| export.contains(*r)), "the export's reasons: {export:?}");
    let table = codes_in(&page, "## The export is failing");
    let mut missing: Vec<&String> = export.iter().filter(|r| !table.contains(*r)).collect();
    missing.sort();
    assert!(missing.is_empty(), "runbook-audit-trail.md's export section doesn't explain {missing:?}");

    let stopped = source("audit_export.rs");
    assert!(stopped.contains(r#"d["reason"] = json!(if sinks.is_empty() { "export_off" } else { "removed" });"#), "the stop's reasons moved: update this test and the runbook");
    let table = codes_in(&page, "## A sink was stopped");
    for r in ["export_off", "removed", "audit.export_stopped", "audit.export_resumed", "audit.export_started"] {
        assert!(table.contains(r), "runbook-audit-trail.md's stopped section doesn't explain {r}");
    }

    let chain = source("audit_chain.rs");
    let mut reasons: HashSet<String> = quoted_after(&chain, "Some(\"").into_iter().collect();
    reasons.extend(quoted_after(&chain, ".broke(id, \""));
    reasons.extend(quoted_after(&chain, ".broke(p.id, \""));
    reasons.extend(quoted_after(&chain, "self.broke(id, \""));
    let checkpoint = source("audit_checkpoint.rs");
    reasons.extend(quoted_after(&checkpoint, "Some(\""));
    let line = source("audit_line.rs");
    let check = line.split("pub fn check_checkpoint").nth(1).expect("audit_line's check_checkpoint").split("\n}\n").next().unwrap();
    reasons.extend(quoted_after(check, "Err((\""));
    reasons.extend(quoted_after(&checkpoint, "fault(id, \""));
    reasons.extend(quoted_after(&checkpoint, "reason: \""));
    for r in ["contents", "link", "unsealed", "erased", "pin", "checkpoint", "timestamp", "archive", "unreadable", "broken", "head", "key", "signature", "record", "malformed"] {
        assert!(reasons.contains(r), "botd no longer records {r} for a broken chain: update this test and the runbook ({reasons:?})");
    }
    let table = codes_in(&page, "## The chain check failed");
    let mut missing: Vec<&String> = reasons.iter().filter(|r| !table.contains(*r)).collect();
    missing.sort();
    assert!(missing.is_empty(), "runbook-audit-trail.md's chain section doesn't explain {missing:?}");

    let tsa = source("tsa.rs");
    let mut stamps: HashSet<String> = quoted_after(&tsa, "bad(\"").into_iter().collect();
    let stamp = checkpoint.split("async fn stamp(").nth(1).expect("audit_checkpoint's stamp").split("\n}\n").next().unwrap();
    stamps.extend(quoted_after(stamp, "Err((\""));
    stamps.extend(quoted_after(stamp, "| (\""));
    assert!(stamps.len() >= 9 && stamps.contains("unreachable") && stamps.contains("unsaved") && stamps.contains("untrusted"), "the timestamps' reasons: {stamps:?}");
    let table = codes_in(&page, "## Timestamps are failing");
    let mut missing: Vec<&String> = stamps.iter().filter(|r| !table.contains(*r)).collect();
    missing.sort();
    assert!(missing.is_empty(), "runbook-audit-trail.md's timestamps section doesn't explain {missing:?}");

    let triage = source("support_triage.rs");
    assert!(triage.contains(r#""audit" => ("audit_trail", "audit trail failures and stopped sinks", Some("support/runbook-audit-trail.md")),"#), "triage's audit.audit_trail points at the runbook");
    let rules = fs::read_to_string(repo().join("deploy/prometheus/superbot-audit-trail.rules.yml")).unwrap();
    let headings = anchors(&page);
    let linked: Vec<&str> = rules.split("docs/support/runbook-audit-trail.md#").skip(1).map(|r| r.split(|c: char| !(c.is_ascii_lowercase() || c == '-')).next().unwrap()).collect();
    assert_eq!(linked.len(), rules.matches("- alert:").count(), "every audit trail alert links its section");
    for a in linked {
        assert!(headings.contains(a), "the rules link runbook-audit-trail.md#{a}, which isn't a heading");
    }
    assert!(page.contains("superbot-audit-trail.rules.yml"), "the runbook names its alert rules");
    let guide = fs::read_to_string(repo().join("docs/ops/audit-export.md")).unwrap();
    assert!(guide.contains("(../support/runbook-audit-trail.md") && guide.contains("superbot-audit-trail.rules.yml"), "the audit export guide points at the runbook and the rules");

    // Evidence of a changed log is an online copy: a plain one of app.sqlite misses the WAL.
    for (what, text) in [("the runbook", page.as_str()), ("the audit export guide", guide.as_str()), ("the rules", rules.as_str()), ("triage", triage.as_str())] {
        assert!(text.contains("botd database backup") && text.contains("app.sqlite-wal"), "{what} saves evidence with botd database backup, and says why");
    }
}

/// ADR 0322: every `secret.*` action the external store, its sign-ins and per-run
/// credentials record, and every `error` kind they carry, is in the secrets runbook, as
/// is the refusal runs get; triage and the guides point there.
#[test]
fn the_secrets_runbook_names_every_failure_botd_records() {
    let page = read("runbook-secrets.md");
    let mut files: Vec<String> = Vec::new();
    for dir in ["secrets", "secrets/vault"] {
        for e in fs::read_dir(repo().join("server/src").join(dir)).unwrap() {
            let p = e.unwrap().path();
            // The sealed store is botd's own database, not the external store.
            if p.extension().is_some_and(|x| x == "rs") && !p.ends_with("sealed.rs") {
                files.push(format!("{dir}/{}", p.file_name().unwrap().to_string_lossy()));
            }
        }
    }
    files.sort();
    let mut actions: HashSet<String> = HashSet::new();
    let mut errors: HashSet<String> = HashSet::new();
    for f in &files {
        let code = source(f);
        for (i, _) in code.match_indices("\"secret.") {
            let a = code[i + 1..].split('"').next().unwrap();
            if a.chars().all(|c| c.is_ascii_lowercase() || c == '_' || c == '.') {
                actions.insert(a.to_string());
            }
        }
        errors.extend(quoted_after(&code, "d[\"error\"] = json!(\""));
    }
    assert!(actions.len() >= 10 && actions.contains("secret.read") && actions.contains("secret.lease_renewed") && actions.contains("secret.read_events_dropped"), "the actions: {actions:?}");
    let mut missing: Vec<&String> = actions.iter().filter(|a| !page.contains(&format!("`{a}`"))).collect();
    missing.sort();
    assert!(missing.is_empty(), "runbook-secrets.md doesn't name {missing:?}");

    let kinds = source("secrets/mod.rs");
    let kinds = kinds.split("pub fn kind(&self) -> &'static str {").nth(1).unwrap().split("\n    }\n").next().unwrap();
    let kinds: Vec<String> = kinds.split("=> \"").skip(1).map(|r| r.split('"').next().unwrap().to_string()).collect();
    assert_eq!(kinds, ["read-only", "invalid", "store error", "unavailable"], "secrets::Error's kinds");
    errors.extend(kinds);
    assert!(errors.len() >= 9 && errors.contains("narrowing") && errors.contains("missing_fields") && errors.contains("expired"), "the error kinds: {errors:?}");
    let reading = codes_in(&page, "## Reading and signing in");
    let leases = codes_in(&page, "## Short-lived credentials for each run");
    let mut missing: Vec<&String> = errors.iter().filter(|e| !reading.contains(*e) && !leases.contains(*e)).collect();
    missing.sort();
    assert!(missing.is_empty(), "runbook-secrets.md's tables don't explain {missing:?}");

    let runner = source("runner.rs");
    assert!(runner.contains(r#""reason": "secrets_unavailable""#), "runs are refused secrets_unavailable");
    assert!(codes_in(&page, "## Runs refused").contains("secrets_unavailable"), "runbook-secrets.md's runs refused section names the reason");
    let triage = source("support_triage.rs");
    assert!(triage.contains(r#""secret" => ("secrets", "secrets store failures", Some("support/runbook-secrets.md")),"#), "triage's audit.secrets points at the runbook");
    assert!(triage.contains(r#"f.runbook("support/runbook-secrets.md#runs-refused")"#), "runs refused secrets_unavailable point at the runbook");
    for guide in ["docs/ops/vault.md", "docs/ops/cloud-secrets.md"] {
        assert!(fs::read_to_string(repo().join(guide)).unwrap().contains("(../support/runbook-secrets.md"), "{guide} doesn't point at the secrets runbook");
    }
}

/// The shipped Prometheus rule files.
fn rule_files() -> Vec<PathBuf> {
    let mut files: Vec<PathBuf> = fs::read_dir(repo().join("deploy/prometheus"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.file_name().unwrap().to_string_lossy().ends_with(".rules.yml"))
        .collect();
    files.sort();
    files
}

/// Each alert in a rule file, with its description.
fn alerts(rules: &str) -> Vec<(String, String)> {
    rules
        .split("- alert: ")
        .skip(1)
        .map(|block| {
            let name = block.lines().next().unwrap().trim().to_string();
            let description = block.split("description: ").nth(1).map_or("", |d| d.lines().next().unwrap()).trim().trim_matches('"').to_string();
            (name, description)
        })
        .collect()
}

/// A heading's section, by its anchor: from the heading to the next one as high or higher.
fn section(md: &str, anchor: &str) -> Option<String> {
    let level = |l: &str| l.starts_with('#').then(|| l.chars().take_while(|c| *c == '#').count());
    let mut lines = md.lines().skip_while(|l| level(l).is_none() || anchors(l).iter().next().map(String::as_str) != Some(anchor));
    let head = lines.next()?;
    let top = level(head).unwrap();
    Some(lines.take_while(|l| level(l).is_none_or(|n| n > top)).collect::<Vec<_>>().join("\n"))
}

/// ADR 0331: every alert SuperBot ships ends with `See docs/support/<page>#<section>.`, and
/// that section names it, so whoever is paged opens the right runbook.
#[test]
fn every_shipped_alert_links_a_runbook_section_that_names_it() {
    let (mut count, mut books, mut bad) = (0, HashSet::new(), Vec::new());
    for file in rule_files() {
        let fname = file.file_name().unwrap().to_string_lossy().into_owned();
        for (name, description) in alerts(&fs::read_to_string(&file).unwrap()) {
            count += 1;
            let Some(at) = description.rfind("See docs/support/") else {
                bad.push(format!("{fname}: {name} doesn't end with its runbook"));
                continue;
            };
            let link = description[at + "See docs/support/".len()..].split(|c: char| c.is_whitespace() || c == '"').next().unwrap().trim_end_matches('.');
            let Some((page, anchor)) = link.split_once('#').filter(|(_, a)| !a.is_empty() && !a.contains('{')) else {
                bad.push(format!("{fname}: {name} links {link}, not a section"));
                continue;
            };
            let Ok(md) = fs::read_to_string(support().join(page)) else {
                bad.push(format!("{fname}: {name} links {page}, which doesn't exist"));
                continue;
            };
            match section(&md, anchor) {
                None => bad.push(format!("{fname}: {name} links {page}#{anchor}, which isn't a heading")),
                Some(s) if !s.contains(&format!("`{name}`")) => bad.push(format!("{fname}: {page}#{anchor} doesn't name {name}")),
                Some(_) => {
                    books.insert(page.to_string());
                }
            }
        }
    }
    assert!(count >= 43, "the shipped alerts: {count}");
    assert!(bad.is_empty(), "alerts without their runbook:\n{}", bad.join("\n"));
    for b in ["runbook-capacity.md", "runbook-encryption.md", "runbook-server-errors.md", "runbook-sign-in.md", "runbook-audit-trail.md"] {
        assert!(books.contains(b), "no alert links {b}");
    }
}

/// ADR 0331: every rule file has promtool tests, and CI checks and tests both.
#[test]
fn every_rule_file_is_checked_and_tested_in_ci() {
    let ci = fs::read_to_string(repo().join(".github/workflows/server.yml")).unwrap();
    for file in rule_files() {
        let name = file.file_name().unwrap().to_string_lossy().into_owned();
        let test = name.replace(".rules.yml", ".rules.test.yml");
        let tests = fs::read_to_string(file.with_file_name(&test)).unwrap_or_else(|e| panic!("{name} has no {test}: {e}"));
        assert!(tests.contains(&format!("rule_files:\n  - {name}\n")), "{test} doesn't load {name}");
        assert!(ci.contains(&format!("promtool check rules deploy/prometheus/{name}\n")), "CI doesn't check {name}");
        assert!(ci.contains(&format!("promtool test rules deploy/prometheus/{test}\n")), "CI doesn't run {test}");
    }
}

/// Whether `span` has `pattern`'s literal pieces, in order, its `{...}` placeholders aside:
/// `{} has {} of {max} machines` fits `has 40 of 40 machines`.
fn fits(span: &str, pattern: &str) -> bool {
    let mut pieces = vec![String::new()];
    let mut inside = false;
    for c in pattern.chars() {
        match c {
            '{' => inside = true,
            '}' => {
                inside = false;
                pieces.push(String::new());
            }
            _ if !inside => pieces.last_mut().unwrap().push(c),
            _ => {}
        }
    }
    let mut rest = span;
    for p in pieces.iter().map(|p| p.trim()).filter(|p| !p.is_empty()) {
        let Some(at) = rest.find(p) else { return false };
        rest = &rest[at + p.len()..];
    }
    !span.is_empty()
}

/// ADR 0331: the capacity runbook explains every reason placement gives for a host it
/// won't use, and triage's placement failures point at it.
#[test]
fn the_capacity_runbook_explains_every_reason_placement_gives() {
    let page = read("runbook-capacity.md");
    let spans = codes_in(&page, "## No room for new machines");
    let code = source("machines/placement.rs");
    let own = code.split("const OWN_HOSTS: &str = \"").nth(1).unwrap().split('"').next().unwrap();
    let mut reasons: Vec<String> = Vec::new();
    for f in ["pub fn closed(", "pub fn elsewhere(", "pub fn not_for(", "pub fn room("] {
        let body = code.split(f).nth(1).unwrap_or_else(|| panic!("placement.rs has no {f}")).split("\n    }\n").next().unwrap();
        reasons.extend(body.split("format!(\"").skip(1).map(|r| r.split('"').next().unwrap().replace("{OWN_HOSTS}", own)));
    }
    assert!(reasons.len() >= 9 && reasons.iter().any(|r| r.contains("is drained")), "placement's reasons: {reasons:?}");
    for r in &reasons {
        assert!(spans.iter().any(|s| fits(s, r)), "runbook-capacity.md's no room section doesn't explain \"{r}\"");
    }
    assert!(code.contains("none is configured") && spans.contains("none is configured"), "no host configured");
    let triage = source("support_triage.rs");
    assert!(triage.contains(r#"return ("capacity", "machines refused or waiting for room", Some("support/runbook-capacity.md#no-room-for-new-machines"));"#), "triage's audit.capacity points at the runbook");
    assert!(page.contains("`audit.capacity`") && page.contains("`machine.placement_failed`"), "the runbook names triage's group and the event");
}

/// ADR 0331: the encryption runbook names every backup target botd reports and the plain
/// copy encrypting leaves.
#[test]
fn the_encryption_runbook_names_every_backup_target_and_the_plain_copy() {
    let page = read("runbook-encryption.md");
    let code = source("backup_encryption.rs");
    let targets: Vec<&str> = ["vec![target(\"", "out.push(target(\""].iter().flat_map(|p| code.split(p).skip(1)).map(|r| r.split('"').next().unwrap()).collect();
    assert!(targets.len() >= 4 && targets.contains(&"chat_stores"), "the backup targets: {targets:?}");
    let table = codes_in(&page, "## Backups aren't encrypted");
    for t in targets {
        assert!(table.contains(t), "runbook-encryption.md's backups section doesn't name {t}");
    }
    let db = source("database_encryption.rs");
    let prefix = db.split("pub const PLAIN_COPY_PREFIX: &str = \"").nth(1).unwrap().split('"').next().unwrap();
    assert!(codes_in(&page, "## A plain copy is left").iter().any(|c| c.starts_with(prefix)), "runbook-encryption.md doesn't name the plain copy ({prefix}...)");
    assert!(read("runbook-backups.md").contains("(runbook-encryption.md#backups-arent-encrypted)"), "the backups runbook points at it");
}

/// ADR 0331: the errors runbook explains every route class `/metrics` counts requests under
/// and the error reports' outcomes; triage's panics point at it.
#[test]
fn the_errors_runbook_explains_every_route_class() {
    let page = read("runbook-server-errors.md");
    let obs = source("obs/mod.rs");
    let body = obs.split("pub fn route_class(").nth(1).unwrap().split("\n}\n").next().unwrap();
    let classes: HashSet<&str> = body.split("=> \"").skip(1).map(|r| r.split('"').next().unwrap()).collect();
    assert!(classes.len() >= 15 && classes.contains("api_other") && classes.contains("approval_hook"), "the route classes: {classes:?}");
    let table = codes_in(&page, "## Requests failing");
    let mut missing: Vec<&&str> = classes.iter().filter(|c| !table.contains(**c)).collect();
    missing.sort();
    assert!(missing.is_empty(), "runbook-server-errors.md's requests section doesn't explain {missing:?}");
    let errors = source("obs/errors.rs");
    assert!(errors.contains(r#"pub const OUTCOMES: [&str; 3] = ["sent", "failed", "dropped"];"#), "the error reports' outcomes moved: update this test and the runbook");
    let reports = codes_in(&page, "## Error reports aren't arriving");
    assert!(reports.contains("failed") && reports.contains("dropped"), "the runbook tells failed reports from dropped ones");
    assert!(source("support_triage.rs").contains(r#".runbook("support/runbook-server-errors.md#panics")"#), "triage's panics point at the runbook");
}

/// ADR 0331: the sign-in runbook explains every suspicious pattern botd watches for.
#[test]
fn the_sign_in_runbook_explains_every_suspicious_pattern() {
    let code = source("signin_watch.rs");
    let patterns = code.split("pub const PATTERNS: [&str; ").nth(1).unwrap().split("= [").nth(1).unwrap().split(']').next().unwrap();
    let patterns: Vec<&str> = patterns.split('"').skip(1).step_by(2).collect();
    assert_eq!(patterns.len(), 4, "the patterns: {patterns:?}");
    let table = codes_in(&read("runbook-sign-in.md"), "## Suspicious sign-ins");
    for p in patterns {
        assert!(table.contains(p), "runbook-sign-in.md's suspicious sign-ins don't explain {p}");
    }
}
