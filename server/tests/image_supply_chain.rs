//! ADR 0101 (SOC 2 CC7.1-3, CC5.2-2): every image `.github/workflows/docker.yml` builds is
//! scanned, the results go to code scanning from pushes, the weekly run and tags (never from
//! pull requests), a fixable Critical fails CI, and every published image is signed with
//! cosign and carries build provenance and an SBOM. Each job holds only the permissions it
//! needs, and the operator docs say how to verify. It reads lines, like `actions_pinned.rs`.

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

/// The blocks of lines under `parent` (a line index) that start at `at` columns: each block
/// runs until the next line at `at` or less that isn't blank.
fn blocks<'a>(lines: &[&'a str], parent: usize, at: usize) -> Vec<Vec<&'a str>> {
    let mut out: Vec<Vec<&str>> = Vec::new();
    for line in &lines[parent + 1..] {
        if line.trim().is_empty() || line.trim_start().starts_with('#') {
            if let Some(last) = out.last_mut() {
                last.push(line);
            }
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
    for b in &mut out {
        while b.last().is_some_and(|l| l.trim().is_empty() || l.trim_start().starts_with('#')) {
            b.pop();
        }
    }
    out
}

/// `(job id, its lines)` for each job in a workflow.
fn jobs(yaml: &str) -> Vec<(String, Vec<&str>)> {
    let lines: Vec<&str> = yaml.lines().collect();
    let at = lines.iter().position(|l| *l == "jobs:").expect("a jobs: key");
    blocks(&lines, at, 2)
        .into_iter()
        .map(|b| (b[0].trim().trim_end_matches(':').to_string(), b))
        .collect()
}

fn job<'a>(all: &'a [(String, Vec<&'a str>)], id: &str) -> &'a [&'a str] {
    &all.iter().find(|(j, _)| j == id).unwrap_or_else(|| panic!("docker.yml has no `{id}` job")).1
}

/// A job's `steps:`, each as its lines.
fn steps<'a>(job: &[&'a str]) -> Vec<Vec<&'a str>> {
    let at = job.iter().position(|l| l.trim() == "steps:").expect("steps:");
    blocks(job, at, indent(job[at]) + 2)
}

/// The step that uses `action` (`owner/repo[/path]`); there must be exactly `n` of them.
fn using<'a>(job: &[&'a str], action: &str, n: usize) -> Vec<Vec<&'a str>> {
    let prefix = format!("uses: {action}@");
    let found: Vec<_> = steps(job).into_iter().filter(|s| s.iter().any(|l| l.trim_start().trim_start_matches("- ").starts_with(&prefix))).collect();
    assert_eq!(found.len(), n, "expected {n} step(s) using {action}");
    found
}

/// The value of `key:` in a block, at any depth.
fn value<'a>(block: &[&'a str], key: &str) -> Option<&'a str> {
    let key = format!("{key}:");
    block.iter().find_map(|l| l.trim_start().trim_start_matches("- ").strip_prefix(&key)).map(str::trim)
}

/// A key's own lines and those nested under it (`if: >-` and the like).
fn key_text(block: &[&str], key: &str) -> String {
    let want = format!("{key}:");
    let Some(at) = block.iter().position(|l| l.trim_start().trim_start_matches("- ").starts_with(&want)) else {
        return String::new();
    };
    let mut text = block[at].to_string();
    for l in &block[at + 1..] {
        if !l.trim().is_empty() && indent(l) <= indent(block[at]) {
            break;
        }
        text.push(' ');
        text.push_str(l.trim());
    }
    text
}

/// A job's `permissions:` as sorted `scope: level` pairs.
fn permissions(job: &[&str]) -> Vec<String> {
    let at = job.iter().position(|l| l.trim() == "permissions:").expect("job-level permissions:");
    let mut out: Vec<String> = blocks(job, at, indent(job[at]) + 2).iter().map(|b| b[0].trim().to_string()).collect();
    out.sort();
    out
}

/// The condition that keeps a step to pushes to main, tags and the weekly run.
fn not_from_pull_requests(cond: &str) -> bool {
    cond.contains("github.event_name != 'pull_request'")
        && cond.contains("github.ref == 'refs/heads/main'")
        && cond.contains("startsWith(github.ref, 'refs/tags/v')")
}

#[test]
fn docker_workflow_scans_every_image() {
    let yaml = read(".github/workflows/docker.yml");
    let all = jobs(&yaml);
    let build = job(&all, "build");

    let scan = steps(build)
        .into_iter()
        .find(|s| s.iter().any(|l| l.contains("$GRYPE")))
        .expect("build scans with Grype");
    let scan = scan.join("\n");
    for want in ["docker:${pair#*=}", "--config .grype.yaml", "json=$out.json", "sarif=$out.sarif", "superbot=superbot:ci", "caddy=superbot-caddy:ci"] {
        assert!(scan.contains(want), "the scan step must contain `{want}`");
    }
    using(build, "anchore/scan-action/download-grype", 1);
    let upload = using(build, "actions/upload-artifact", 2);
    assert!(upload.iter().any(|s| s.iter().any(|l| l.trim() == "name: image-scan-${{ matrix.arch }}")), "scan results are kept as an artifact");
    assert!(repo().join(".grype.yaml").is_file(), ".grype.yaml lists accepted findings");

    let gate = job(&all, "image-scan");
    assert_eq!(value(gate, "needs"), Some("build"));
    assert_eq!(value(gate, "image"), Some("[superbot, caddy]"));
    assert_eq!(value(gate, "arch"), Some("[amd64, arm64]"));
    assert_eq!(permissions(gate), ["contents: read", "security-events: write"]);
    let sarif = &using(gate, "github/codeql-action/upload-sarif", 1)[0];
    assert!(not_from_pull_requests(&key_text(sarif, "if")), "SARIF is uploaded only from main, tags and the weekly run");
    let policy = steps(gate).into_iter().map(|s| s.join("\n")).find(|s| s.contains("exit 1")).expect("the severity gate");
    for want in ["\"Critical\"", ".vulnerability.fix.state == \"fixed\"", ".grype.yaml"] {
        assert!(policy.contains(want), "the severity gate must contain `{want}`");
    }
}

#[test]
fn docker_workflow_signs_and_attests_what_it_publishes() {
    let yaml = read(".github/workflows/docker.yml");
    let all = jobs(&yaml);
    let build = job(&all, "build");
    assert_eq!(permissions(build), ["contents: read", "packages: write"]);
    let pushes: Vec<_> = steps(build).into_iter().filter(|s| s.iter().any(|l| l.contains("push-by-digest=true"))).collect();
    assert_eq!(pushes.len(), 2, "two images are pushed by digest");
    for p in &pushes {
        assert_eq!(value(p, "provenance"), Some("mode=max"), "each push carries BuildKit provenance");
        let sbom = value(p, "sbom").unwrap_or_default();
        assert!(sbom.starts_with("generator=") && sbom.contains("@sha256:"), "each push carries an SBOM from a generator pinned by digest");
    }

    let publish = job(&all, "publish");
    assert_eq!(permissions(publish), ["attestations: write", "contents: read", "id-token: write", "packages: write"]);
    assert!(value(publish, "needs").is_some_and(|n| n.contains("image-scan")), "publish waits for the scan");
    let cond = key_text(publish, "if");
    assert!(not_from_pull_requests(&cond), "publish never runs for pull requests");
    assert!(cond.contains("needs.image-scan.result == 'success' || !startsWith(github.ref, 'refs/tags/')"), "a failed scan holds back a release");

    using(publish, "sigstore/cosign-installer", 1);
    let sign = steps(publish).into_iter().map(|s| s.join("\n")).find(|s| s.contains("cosign sign")).expect("publish signs");
    for want in [r#"cosign sign --yes --recursive "$IMAGE@$DIGEST""#, r#"cosign sign --yes --recursive "$CADDY_IMAGE@$CADDY_DIGEST""#] {
        assert!(sign.contains(want), "publish must run `{want}`");
    }
    let attest = using(publish, "actions/attest", 2);
    let mut subjects: Vec<_> = attest.iter().map(|s| value(s, "subject-name").unwrap_or_default()).collect();
    subjects.sort();
    assert_eq!(subjects, ["${{ env.CADDY_IMAGE }}", "${{ env.IMAGE }}"]);
    for s in &attest {
        assert_eq!(value(s, "push-to-registry"), Some("true"));
        assert!(value(s, "subject-digest").is_some_and(|d| d.starts_with("${{ steps.index.outputs.")));
    }

    // Public tags move only once both images are signed and attested.
    let names: Vec<String> = steps(publish).iter().map(|s| value(s, "name").unwrap_or_default().to_string()).collect();
    let at = |name: &str| names.iter().position(|n| n == name).unwrap_or_else(|| panic!("publish has no step `{name}`"));
    let tag = at("Tag the multi-arch images");
    for before in ["Create the multi-arch images", "Sign the images", "Attest build provenance", "Attest build provenance (Caddy)"] {
        assert!(at(before) < tag, "`{before}` must come before the public tags move");
    }
    let tagging = steps(publish)[tag].join("\n");
    assert!(tagging.contains(r#""$image@$digest""#) && tagging.contains("not the signed"), "public tags point at the signed digest, checked");
}

#[test]
fn only_the_jobs_that_need_them_get_write_tokens() {
    let yaml = read(".github/workflows/docker.yml");
    let top: Vec<&str> = yaml.lines().take_while(|l| *l != "jobs:").collect();
    assert_eq!(permissions(&top), ["contents: read"], "workflow-level permissions stay read-only");
    for (id, body) in jobs(&yaml) {
        let perms = permissions(&body);
        let allowed: &[&str] = match id.as_str() {
            "build" => &["contents: read", "packages: write"],
            "image-scan" => &["contents: read", "security-events: write"],
            "publish" => &["attestations: write", "contents: read", "id-token: write", "packages: write"],
            other => panic!("new job `{other}`: give it its permissions here (ADR 0101)"),
        };
        assert_eq!(perms, allowed, "{id}");
    }
}

#[test]
fn operators_can_verify_the_images() {
    let docs = read("deploy/README.md");
    let identity = "--certificate-identity https://github.com/CG-Labs/superbot/.github/workflows/docker.yml@refs/heads/main";
    for want in [
        "cosign verify ghcr.io/cg-labs/superbot:main",
        identity,
        "--certificate-oidc-issuer https://token.actions.githubusercontent.com",
        "gh attestation verify oci://ghcr.io/cg-labs/superbot:main",
        "--signer-workflow CG-Labs/superbot/.github/workflows/docker.yml",
    ] {
        assert!(docs.contains(want), "deploy/README.md must show `{want}`");
    }
}

#[test]
fn the_reader_splits_jobs_and_steps() {
    let yaml = "on: push\npermissions:\n  contents: read\njobs:\n  a:\n    permissions:\n      packages: write\n      contents: read\n    steps:\n      - uses: x/y@1 # v1\n        with:\n          k: v\n\n      # note\n      - name: run\n        if: >-\n          one\n          && two\n        run: |\n          echo hi\n  b:\n    needs: a\n    steps:\n      - run: true\n";
    let all = jobs(yaml);
    assert_eq!(all.iter().map(|(j, _)| j.as_str()).collect::<Vec<_>>(), ["a", "b"]);
    let a = job(&all, "a");
    assert_eq!(permissions(a), ["contents: read", "packages: write"]);
    assert_eq!(steps(a).len(), 2);
    assert_eq!(using(a, "x/y", 1)[0].len(), 3);
    assert_eq!(value(&using(a, "x/y", 1)[0], "k"), Some("v"));
    assert_eq!(key_text(&steps(a)[1], "if"), "        if: >- one && two");
    assert_eq!(value(job(&all, "b"), "needs"), Some("a"));
}
