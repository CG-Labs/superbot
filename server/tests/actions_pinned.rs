//! ADR 0100 (SOC 2 CC5.2-1): every action a workflow or composite action under `.github/`
//! runs from elsewhere is pinned to a full 40-character commit SHA, with the version it
//! stands for in a trailing comment (`uses: actions/checkout@<sha> # v4.4.0`), so a moved
//! tag can't change what CI runs and Dependabot can still update it. Local actions
//! (`./...`) are this repository's own code; `docker://` images must be pinned by digest.

use std::fs;
use std::path::{Path, PathBuf};

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..")
}

fn yaml_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else { return };
    for e in entries.flatten() {
        let p = e.path();
        if p.is_dir() {
            yaml_files(&p, out);
        } else if p.extension().is_some_and(|x| x == "yml" || x == "yaml") {
            out.push(p);
        }
    }
}

fn hex(s: &str, len: usize) -> bool {
    s.len() == len && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn indent(line: &str) -> usize {
    line.len() - line.trim_start().len()
}

/// `(line number, line)` for the lines that hold YAML keys: not comments, and not the body
/// of a block scalar (`run: |`), whose shell may say anything.
fn yaml_lines(yaml: &str) -> Vec<(usize, &str)> {
    let mut out = Vec::new();
    let mut block: Option<usize> = None;
    for (i, line) in yaml.lines().enumerate() {
        if let Some(parent) = block {
            if line.trim().is_empty() || indent(line) > parent {
                continue;
            }
            block = None;
        }
        if line.trim_start().starts_with('#') {
            continue;
        }
        let code = line.find(" #").map_or(line, |at| &line[..at]).trim_end();
        let opens_block = code.rsplit_once(' ').is_some_and(|(head, tok)| {
            let head = head.trim_end();
            (head.ends_with(':') || head.ends_with('-'))
                && tok.starts_with(['|', '>'])
                && tok[1..].chars().all(|c| c == '+' || c == '-' || c.is_ascii_digit())
        });
        if opens_block {
            // The body is indented past the key that opened it (`name` in `- name: |`), and
            // that key's siblings (`uses:` under it) are not; a bare `- |` counts from its dash.
            let mut key = line.trim_start();
            let mut dash = indent(line);
            while let Some(rest) = key.strip_prefix("- ").map(str::trim_start) {
                dash = line.len() - key.len();
                key = rest;
            }
            block = Some(if key.starts_with(['|', '>']) { dash } else { line.len() - key.len() });
        }
        out.push((i + 1, line));
    }
    out
}

/// `(line number, value, trailing comment)` for each `uses:` key in a YAML file.
fn uses(yaml: &str) -> Vec<(usize, String, String)> {
    let mut out = Vec::new();
    for (n, line) in yaml_lines(yaml) {
        let t = line.trim_start();
        let t = t.strip_prefix("- ").map(str::trim_start).unwrap_or(t);
        let Some(rest) = t.strip_prefix("uses:") else { continue };
        let (value, comment) = match rest.find(" #") {
            Some(at) => (&rest[..at], rest[at + 2..].trim()),
            None => (rest, ""),
        };
        let value = value.trim().trim_matches(|c| c == '"' || c == '\'');
        out.push((n, value.to_string(), comment.to_string()));
    }
    out
}

/// Lines with a `uses` key that `uses()` can't read: quoted (`'uses':`) or in a flow
/// mapping (`- { uses: ... }`). There's no YAML parser here, so these are refused rather
/// than skipped, and a step has to be written the plain way.
fn other_uses_keys(yaml: &str) -> Vec<usize> {
    let mut out = Vec::new();
    for (n, line) in yaml_lines(yaml) {
        let t = line.trim_start();
        let item = t.strip_prefix("- ").map(str::trim_start).unwrap_or(t);
        if !item.starts_with(['{', '"', '\'', '?']) {
            continue;
        }
        let key_at = |at: usize| {
            let before = line[..at].trim_end();
            let opens = |b: &str| b.is_empty() || b.ends_with(['-', '{', ',', '?']);
            let quoted = before.ends_with(['"', '\'']) && opens(before[..before.len() - 1].trim_end());
            let after = line[at + 4..].trim_start_matches(['"', '\'']).trim_start();
            (opens(before) || quoted) && after.strip_prefix(':').is_some_and(|r| r.is_empty() || r.starts_with([' ', '\t']))
        };
        if line.match_indices("uses").any(|(at, _)| key_at(at)) {
            out.push(n);
        }
    }
    out
}

/// Why `value` (with its trailing `comment`) isn't an acceptable reference, if it isn't.
fn problem(value: &str, comment: &str) -> Option<String> {
    if value.starts_with("./") {
        return None;
    }
    if let Some(image) = value.strip_prefix("docker://") {
        return match image.rsplit_once("@sha256:") {
            Some((_, digest)) if hex(digest, 64) => None,
            _ => Some("a docker:// image must be pinned by @sha256:<digest>".into()),
        };
    }
    let Some((action, git_ref)) = value.rsplit_once('@') else {
        return Some("a remote action needs @<commit sha>".into());
    };
    if action.split('/').filter(|s| !s.is_empty()).count() < 2 {
        return Some(format!("`{action}` isn't owner/repo"));
    }
    if !hex(git_ref, 40) {
        return Some(format!("`@{git_ref}` isn't a full 40-character commit SHA"));
    }
    if comment.is_empty() {
        return Some("a pinned action needs the version it stands for in a trailing comment (`# v1.2.3`)".into());
    }
    None
}

#[test]
fn every_remote_action_is_pinned_to_a_commit() {
    let mut files = Vec::new();
    yaml_files(&repo().join(".github"), &mut files);
    files.sort();
    assert!(files.iter().any(|f| f.ends_with("server.yml")), "found no workflows under .github/");
    let mut bad = Vec::new();
    let mut seen = 0;
    for f in &files {
        let yaml = fs::read_to_string(f).unwrap();
        let rel = f.strip_prefix(repo()).unwrap_or(f).display().to_string();
        for (n, value, comment) in uses(&yaml) {
            seen += 1;
            if let Some(why) = problem(&value, &comment) {
                bad.push(format!("{rel}:{n}: `{value}`: {why}"));
            }
        }
        for n in other_uses_keys(&yaml) {
            bad.push(format!("{rel}:{n}: write `uses:` as a plain block key (`- uses: owner/repo@<sha> # vX`) so it can be checked"));
        }
    }
    assert!(seen > 0, "found no `uses:` under .github/");
    assert!(bad.is_empty(), "actions not pinned by commit (ADR 0100):\n{}", bad.join("\n"));
}

#[test]
fn dependabot_updates_the_pinned_actions() {
    let config = fs::read_to_string(repo().join(".github/dependabot.yml")).expect(".github/dependabot.yml exists");
    assert!(config.contains(r#"package-ecosystem: "github-actions""#), "dependabot.yml must update github-actions");
}

#[test]
fn the_checker_catches_what_it_should() {
    let sha = "11d5960a326750d5838078e36cf38b85af677262";
    let yaml = format!(
        "steps:\n  - uses: actions/checkout@{sha} # v4.4.0\n  - name: x\n    uses: \"docker/login-action@v3\"\n  # uses: in a comment\n  - run: echo uses: x\n"
    );
    assert_eq!(
        uses(&yaml),
        vec![(2, format!("actions/checkout@{sha}"), "v4.4.0".to_string()), (4, "docker/login-action@v3".to_string(), String::new())]
    );
    assert_eq!(other_uses_keys(&yaml), Vec::<usize>::new());
    let odd = "steps:\n  - { uses: actions/checkout@v4 }\n  - 'uses': actions/checkout@v4\n  - \"uses\" : a/b@v1\n  - {name: x, uses: a/b@v1}\n  - run: echo uses: x\n  # - { uses: a/b@v1 }\n  - name: uses\n";
    assert_eq!(other_uses_keys(odd), vec![2, 3, 4, 5]);
    let shell = "steps:\n  - run: echo '{\"uses\": \"x\"}'\n  - run: |\n      echo '{\"uses\": \"x\"}'\n      cat <<EOF\n      uses: a/b@v1\n      - { uses: a/b@v1 }\n      EOF\n\n      true\n  - name: after\n    uses: a/b@v1\n  - run: >-\n      uses: c/d@v1\n";
    assert_eq!(other_uses_keys(shell), Vec::<usize>::new());
    assert_eq!(uses(shell), vec![(12, "a/b@v1".to_string(), String::new())]);
    let names = "steps:\n  - name: |\n      Checkout\n    uses: actions/checkout@v4\n  - name: >-\n      x\n    'uses': a/b@v1\n  - - |\n      uses: in a list\n    - uses: e/f@v1\n";
    assert_eq!(uses(names), vec![(4, "actions/checkout@v4".to_string(), String::new()), (10, "e/f@v1".to_string(), String::new())]);
    assert_eq!(other_uses_keys(names), vec![7]);
    assert_eq!(uses("  - uses:\n      actions/checkout@v4\n"), vec![(1, String::new(), String::new())]);
    assert!(problem("", "").is_some());

    assert_eq!(problem(&format!("actions/checkout@{sha}"), "v4.4.0"), None);
    assert_eq!(problem(&format!("owner/repo/.github/workflows/ci.yml@{sha}"), "v1"), None);
    assert_eq!(problem(&format!("owner/repo/sub/action@{sha}"), "v1"), None);
    assert_eq!(problem("./.github/actions/setup", ""), None);
    assert_eq!(problem(&format!("docker://alpine@sha256:{}", "a".repeat(64)), ""), None);

    assert!(problem("actions/checkout@v4", "").is_some());
    assert!(problem("dtolnay/rust-toolchain@stable", "").is_some());
    assert!(problem("actions/checkout@11d5960", "v4").is_some());
    assert!(problem(&format!("actions/checkout@{}", sha.to_uppercase()), "v4").is_some());
    assert!(problem(&format!("actions/checkout@{sha}"), "").is_some());
    assert!(problem("actions/checkout", "").is_some());
    assert!(problem(&format!("checkout@{sha}"), "v4").is_some());
    assert!(problem("docker://alpine:3.20", "").is_some());
    assert!(problem("docker://alpine@sha256:abc", "").is_some());
}
