//! ADR 0111 (SOC 2 CC8.1-3, CC2.3-1): `.github/workflows/release.yml` checks CHANGELOG.md
//! on every change to it or the version, and turns each `v<semver>` tag into a GitHub
//! release whose notes come from CHANGELOG.md, only from `main` and only after the check.
//! Only the release job can write, and only `contents`. `deploy/release-notes.sh` holds the
//! logic and tests itself; this checks the workflow wires it up. It reads lines, like
//! `image_supply_chain.rs`.

use std::fs;
use std::path::{Path, PathBuf};

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..")
}

fn read(rel: &str) -> String {
    fs::read_to_string(repo().join(rel)).unwrap_or_else(|e| panic!("{rel}: {e}"))
}

fn indent(line: &str) -> usize {
    line.len() - line.trim_start().len()
}

/// The blocks of lines under `parent` that start at `at` columns.
fn blocks<'a>(lines: &[&'a str], parent: usize, at: usize) -> Vec<Vec<&'a str>> {
    let mut out: Vec<Vec<&str>> = Vec::new();
    for line in &lines[parent + 1..] {
        if line.trim().is_empty() || line.trim_start().starts_with('#') {
            continue;
        }
        if indent(line) < at {
            break;
        }
        if indent(line) == at {
            out.push(Vec::new());
        }
        if let Some(last) = out.last_mut() {
            last.push(line);
        }
    }
    out
}

fn jobs(yaml: &str) -> Vec<(String, Vec<&str>)> {
    let lines: Vec<&str> = yaml.lines().collect();
    let at = lines.iter().position(|l| *l == "jobs:").expect("a jobs: key");
    blocks(&lines, at, 2).into_iter().map(|b| (b[0].trim().trim_end_matches(':').to_string(), b)).collect()
}

fn job<'a>(all: &'a [(String, Vec<&'a str>)], id: &str) -> &'a [&'a str] {
    &all.iter().find(|(j, _)| j == id).unwrap_or_else(|| panic!("release.yml has no `{id}` job")).1
}

fn steps<'a>(job: &[&'a str]) -> Vec<String> {
    let at = job.iter().position(|l| l.trim() == "steps:").expect("steps:");
    blocks(job, at, indent(job[at]) + 2).into_iter().map(|s| s.join("\n")).collect()
}

fn value<'a>(block: &[&'a str], key: &str) -> Option<&'a str> {
    let key = format!("{key}:");
    block.iter().find_map(|l| l.trim_start().trim_start_matches("- ").strip_prefix(&key)).map(str::trim)
}

fn permissions(block: &[&str]) -> Vec<String> {
    let at = block.iter().position(|l| l.trim() == "permissions:").expect("permissions:");
    let mut out: Vec<String> = blocks(block, at, indent(block[at]) + 2).iter().map(|b| b[0].trim().to_string()).collect();
    out.sort();
    out
}

#[test]
fn only_the_release_job_can_write_and_only_contents() {
    let yaml = read(".github/workflows/release.yml");
    let top: Vec<&str> = yaml.lines().take_while(|l| *l != "jobs:").collect();
    assert_eq!(permissions(&top), ["contents: read"], "workflow-level permissions stay read-only");
    for (id, body) in jobs(&yaml) {
        let allowed: &[&str] = match id.as_str() {
            "changelog" => &["contents: read"],
            "release" => &["contents: write"],
            other => panic!("new job `{other}`: give it its permissions here (ADR 0111)"),
        };
        assert_eq!(permissions(&body), allowed, "{id}");
    }
}

#[test]
fn every_change_to_the_changelog_or_version_is_checked() {
    let yaml = read(".github/workflows/release.yml");
    let on: Vec<&str> = yaml.lines().take_while(|l| !l.starts_with("permissions:")).collect();
    let on = on.join("\n");
    assert!(on.contains("tags: ['v*']"), "release.yml runs on every v* tag");
    for path in ["'CHANGELOG.md'", "'server/Cargo.toml'", "'deploy/release-notes.sh'", "'.github/workflows/release.yml'"] {
        assert_eq!(on.matches(&format!("- {path}")).count(), 2, "push and pull_request both watch {path}");
    }
    let all = jobs(&yaml);
    let check = steps(job(&all, "changelog")).join("\n");
    assert!(check.contains("fetch-depth: 0"), "the check sees every tag");
    for want in ["shellcheck -S style deploy/release-notes.sh", "deploy/release-notes.sh self-test", "deploy/release-notes.sh check"] {
        assert!(check.contains(want), "the changelog job must run `{want}`");
    }
}

#[test]
fn a_release_comes_only_from_a_checked_tag_on_main() {
    let yaml = read(".github/workflows/release.yml");
    let all = jobs(&yaml);
    let release = job(&all, "release");
    assert_eq!(value(release, "needs"), Some("changelog"), "the release waits for the check");
    assert_eq!(value(release, "if"), Some("github.event_name == 'push' && startsWith(github.ref, 'refs/tags/v')"));
    let s = steps(release);
    let at = |want: &str| s.iter().position(|step| step.contains(want)).unwrap_or_else(|| panic!("the release job must run `{want}`"));
    let on_main = at(r#"git merge-base --is-ancestor "$GITHUB_SHA" origin/main"#);
    let notes = at(r#"deploy/release-notes.sh notes "$TAG""#);
    let publish = at(r#"gh release create "$TAG" --verify-tag"#);
    assert!(on_main < notes && notes < publish, "check main, then write the notes, then publish");
    assert!(s[notes].contains("TAG: ${{ github.ref_name }}"), "the tag reaches the shell through env");
    assert!(s[publish].contains(r#"--notes-file "$RUNNER_TEMP/notes.md""#), "the release's notes are the changelog's");
    assert!(s[publish].contains("GH_TOKEN: ${{ github.token }}"), "the release uses the job's own token");
}

#[test]
fn the_changelog_and_security_policy_exist() {
    let changelog = read("CHANGELOG.md");
    assert!(changelog.starts_with("# Changelog\n"));
    assert!(changelog.contains("keepachangelog.com/en/1.1.0"), "CHANGELOG.md names the format it follows");
    let security = read("SECURITY.md");
    for want in ["## Supported versions", "## Reporting a vulnerability", "security/advisories/new", "## What happens next", "## Scope", "## Safe harbour"] {
        assert!(security.contains(want), "SECURITY.md must contain `{want}`");
    }
}

#[test]
fn the_reader_splits_jobs_and_steps() {
    let yaml = "permissions:\n  contents: read\njobs:\n  a:\n    permissions:\n      contents: write\n    steps:\n      - run: one\n\n      # note\n      - name: two\n        run: |\n          echo hi\n  b:\n    needs: a\n    steps:\n      - run: true\n";
    let all = jobs(yaml);
    assert_eq!(all.iter().map(|(j, _)| j.as_str()).collect::<Vec<_>>(), ["a", "b"]);
    assert_eq!(permissions(job(&all, "a")), ["contents: write"]);
    assert_eq!(steps(job(&all, "a")).len(), 2);
    assert_eq!(value(job(&all, "b"), "needs"), Some("a"));
}
