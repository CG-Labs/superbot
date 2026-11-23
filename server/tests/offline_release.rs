//! ADR 0140 (#59): `.github/workflows/offline.yml` makes the offline bundles for every `v*` tag
//! once the docker workflow has published and signed that tag's images, from that tag's own
//! commit on `main`, and attaches them, signed, to the tag's release. Its CI job pushes a
//! bundle's images to a mirror and checks the digests, and (ADR 0147) pushes both arches'
//! bundles of a signed image to a mirror with no network, where cosign verifies the signed
//! index. `deploy/test-offline.sh` tests the bundles themselves; this checks the workflow wires
//! them up. It reads lines, like `release_workflow.rs`.

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
    &all.iter().find(|(j, _)| j == id).unwrap_or_else(|| panic!("offline.yml has no `{id}` job")).1
}

fn steps(job: &[&str]) -> Vec<String> {
    let at = job.iter().position(|l| l.trim() == "steps:").expect("steps:");
    blocks(job, at, indent(job[at]) + 2).into_iter().map(|s| s.join("\n")).collect()
}

/// A job-level key's value, with a folded (`>-`) value's lines joined by spaces.
fn key(job: &[&str], name: &str) -> String {
    let at = indent(job[0]) + 2;
    let prefix = format!("{name}:");
    let start = job.iter().position(|l| indent(l) == at && l.trim_start().starts_with(&prefix)).unwrap_or_else(|| panic!("no `{name}:`"));
    let first = job[start].trim_start()[prefix.len()..].trim();
    if first != ">-" {
        return first.to_string();
    }
    job[start + 1..].iter().take_while(|l| indent(l) > at).map(|l| l.trim()).collect::<Vec<_>>().join(" ")
}

fn permissions(block: &[&str]) -> Vec<String> {
    let Some(at) = block.iter().position(|l| l.trim() == "permissions:") else {
        return Vec::new();
    };
    let mut out: Vec<String> = blocks(block, at, indent(block[at]) + 2).iter().map(|b| b[0].trim().to_string()).collect();
    out.sort();
    out
}

#[test]
fn bundles_follow_the_docker_workflow_for_every_tag() {
    let docker = read(".github/workflows/docker.yml");
    assert!(docker.starts_with("name: docker\n"), "offline.yml's workflow_run names the docker workflow `docker`");
    assert!(docker.contains("tags: ['v*']"), "the docker workflow publishes every v* tag's images");
    let yaml = read(".github/workflows/offline.yml");
    let on: String = yaml.lines().take_while(|l| !l.starts_with("permissions:")).collect::<Vec<_>>().join("\n");
    assert!(on.contains("  workflow_run:\n    workflows: [docker]\n    types: [completed]"), "release-bundle starts when a docker run finishes");
    assert!(on.contains("  workflow_dispatch:"), "a manual run can still bundle a published release");
    let all = jobs(&yaml);
    let release = job(&all, "release-bundle");
    let when = key(release, "if");
    for want in [
        "github.event_name == 'workflow_dispatch' ||",
        "github.event_name == 'workflow_run' && github.event.workflow_run.event == 'push'",
        "github.event.workflow_run.conclusion == 'success'",
        "github.event.workflow_run.head_repository.full_name == github.repository",
        "startsWith(github.event.workflow_run.head_branch, 'v')",
    ] {
        assert!(when.contains(want), "release-bundle's `if` must have `{want}`, got `{when}`");
    }
    assert_eq!(
        key(job(&all, "install-offline"), "if"),
        "github.event_name == 'push' || github.event_name == 'pull_request'",
        "the install test runs on pushes and pull requests, never for a docker run or a release"
    );
}

#[test]
fn only_release_bundle_can_write_and_sign() {
    let yaml = read(".github/workflows/offline.yml");
    let top: Vec<&str> = yaml.lines().take_while(|l| *l != "jobs:").collect();
    assert_eq!(permissions(&top), ["contents: read"], "workflow-level permissions stay read-only");
    for (id, body) in jobs(&yaml) {
        let allowed: &[&str] = match id.as_str() {
            "install-offline" => &[],
            "release-bundle" => &["contents: write", "id-token: write"],
            other => panic!("new job `{other}`: give it its permissions here (ADR 0140)"),
        };
        assert_eq!(permissions(&body), allowed, "{id}");
    }
}

#[test]
fn a_release_bundle_is_the_tags_own_commit_on_main_and_signed() {
    let yaml = read(".github/workflows/offline.yml");
    let all = jobs(&yaml);
    let release = job(&all, "release-bundle");
    let env = release.join("\n");
    assert!(
        env.contains("TAG: ${{ github.event_name == 'workflow_dispatch' && format('v{0}', inputs.version) || github.event.workflow_run.head_branch }}"),
        "the tag comes from the docker run, or the version given by hand"
    );
    assert!(env.contains("TAG_SHA: ${{ github.event.workflow_run.head_sha }}"), "the docker run's commit is checked");
    let s = steps(release);
    for step in &s {
        if let Some(run) = step.split_once("run:").map(|(_, r)| r) {
            assert!(!run.contains("${{"), "values reach the shell through env, not `${{{{ }}}}` in a script:\n{step}");
        }
    }
    let at = |want: &str| s.iter().position(|step| step.contains(want)).unwrap_or_else(|| panic!("release-bundle must have `{want}`"));
    let version = at(r#"[[ $TAG =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]]"#);
    let checkout = at("ref: refs/tags/${{ env.TAG }}");
    let on_main = at("git merge-base --is-ancestor HEAD origin/main");
    let bundle = at("deploy/offline-bundle.sh build --out dist");
    let sign = at(r#"cosign sign-blob --yes --bundle "$f.sigstore.json" "$f""#);
    let upload = at(r#"gh release upload "$TAG" dist/superbot-offline-* --clobber"#);
    assert!(version < checkout && checkout < on_main && on_main < bundle && bundle < sign && sign < upload, "check, check out, check main, bundle, sign, then attach");
    assert!(s[checkout].contains("fetch-depth: 0"), "the main check sees main's history");
    assert!(s[on_main].contains(r#"$(git rev-parse HEAD) == "$TAG_SHA""#), "the bundle is made from the commit whose images were published");
    for want in [
        r#"--image "superbot=ghcr.io/${GITHUB_REPOSITORY,,}:$VERSION""#,
        r#"--image "caddy=ghcr.io/${GITHUB_REPOSITORY,,}-caddy:$VERSION""#,
        r#"--image-identity "https://github.com/$GITHUB_REPOSITORY/.github/workflows/docker.yml@refs/tags/v$VERSION""#,
    ] {
        assert!(s[bundle].contains(want), "the bundle step must pass `{want}`");
    }
    assert!(!s[bundle].contains("--allow-unsigned"), "release bundles carry only signature-checked images");
    assert!(s[sign].contains(r#"deploy/offline-bundle.sh verify "$f""#), "the signed bundle is verified before it is attached");
    assert!(s[upload].contains(r#"gh release view "$TAG""#), "the upload waits for the release workflow's release");
}

#[test]
fn ci_pushes_a_bundles_images_to_a_mirror_with_their_digests() {
    let yaml = read(".github/workflows/offline.yml");
    let all = jobs(&yaml);
    let s = steps(job(&all, "install-offline")).join("\n");
    for want in [
        "--image multi=localhost:5000/superbot-offline-multi:1",
        r#"images/multi.digest") == "$MULTI_DIGEST" ]]"#,
        "sudo unshare --net -- deploy/offline-bundle.sh load",
        "--registry localhost:5001/mirror",
        r#"push "$b" --sha256 "$(cut -c1-64 "$b.sha256")""#,
        r#"sha256sum | cut -c1-64) == "${MULTI_DIGEST#sha256:}" ]]"#,
    ] {
        assert!(s.contains(want), "install-offline must have `{want}`");
    }
}

#[test]
fn ci_puts_both_arches_signed_index_in_a_mirror_with_no_network() {
    let yaml = read(".github/workflows/offline.yml");
    let all = jobs(&yaml);
    for id in ["install-offline", "release-bundle"] {
        let build = steps(job(&all, id)).into_iter().find(|s| s.contains("cargo build --release")).unwrap_or_else(|| panic!("{id} builds the binaries"));
        assert!(build.contains("--bin superbot-oci"), "{id} builds superbot-oci, which bundles with images carry");
    }
    let s = steps(job(&all, "install-offline"));
    let all_steps = s.join("\n");
    for want in [
        "--sbom=true --provenance=mode=max --push",
        "cosign signing-config create --out signing-config.json",
        "cosign sign --yes --recursive --key cosign.key --signing-config signing-config.json",
        "cosign attest --yes --key cosign.key --signing-config signing-config.json --type slsaprovenance1",
        "for a in x86_64 aarch64; do",
        r#"--image signed=localhost:5000/superbot-offline-signed:1 --image-key "$RUNNER_TEMP/cosign.pub""#,
    ] {
        assert!(all_steps.contains(want), "install-offline must have `{want}`");
    }
    let mirror = s.iter().find(|s| s.contains("--registry localhost:5002/mirror")).expect("a push of both arches' bundles");
    for want in [
        "sudo ip netns exec offline bash -c",
        "the network is still up",
        r#"x86="$bundles/superbot-offline-$version-x86_64.tar.gz" arm="$bundles/superbot-offline-$version-aarch64.tar.gz""#,
        r#"push "$x86" "$arm" --sha256 "$(cut -c1-64 "$x86.sha256")" --sha256 "$(cut -c1-64 "$arm.sha256")""#,
        "($index, the signed index for linux/amd64, linux/arm64)",
        r#""$cosign" verify "${v[@]}" localhost:5002/mirror/superbot-offline-signed:1"#,
        r#""$cosign" verify "${v[@]}" "localhost:5002/mirror/superbot-offline-signed@$d""#,
        r#""$cosign" verify-attestation "${v[@]}" --type slsaprovenance1 localhost:5002/mirror/superbot-offline-signed:1"#,
    ] {
        assert!(mirror.contains(want), "the mirror step must have `{want}`");
    }
}

#[test]
fn the_reader_joins_folded_values() {
    let job = ["  a:", "    if: >-", "      one ||", "      two", "    runs-on: x", "    steps:", "      - run: true"];
    assert_eq!(key(&job, "if"), "one || two");
    assert_eq!(key(&job, "runs-on"), "x");
}
