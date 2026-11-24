//! ADR 0140 (#59): `.github/workflows/offline.yml` makes the offline bundles for every `v*` tag
//! once the docker workflow has published and signed that tag's images, from that tag's own
//! commit on `main`, and attaches them, signed, to the tag's release. Its CI job pushes a
//! bundle's images to a mirror and checks the digests, and (ADR 0147) pushes both arches'
//! bundles of a signed image to a mirror with no network, where cosign verifies the signed
//! index. ADR 0172: what release-bundle attached is then checked end to end by
//! `offline-release-check.yml` (also weekly and by hand), against ghcr.io and with no network, and
//! the CI job runs the same check on its own signed release. `deploy/test-offline.sh` and
//! `deploy/test-offline-release-check.sh` test the scripts themselves; this checks the workflows
//! wire them up. It reads lines, like `release_workflow.rs`.

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
            "release-check" => &["contents: read"],
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
    let mirror = s.iter().find(|s| s.contains("--mirror localhost:5002/mirror")).expect("a push of both arches' bundles");
    for want in [
        "sudo ip netns exec offline env PATH=",
        "the network is still up",
        r#"deploy/offline-release-check.sh offline "$bundles" --mirror localhost:5002/mirror --key "$key""#,
        "($index, the signed index for linux/amd64, linux/arm64)",
        "is the signed index $index; it, its 4 manifests and its provenance verify with no network",
        "attestation-manifest",
    ] {
        assert!(mirror.contains(want), "the mirror step must have `{want}`");
    }
}

#[test]
fn ci_checks_its_own_signed_release_as_a_published_one() {
    let yaml = read(".github/workflows/offline.yml");
    let all = jobs(&yaml);
    let s = steps(job(&all, "install-offline"));
    let at = |want: &str| s.iter().position(|step| step.contains(want)).unwrap_or_else(|| panic!("install-offline must have `{want}`"));
    let unit = at("run: deploy/test-offline-release-check.sh");
    let lint = at("shellcheck -x -S style");
    assert!(s[lint].contains("deploy/offline-release-check.sh deploy/test-offline-release-check.sh"), "ShellCheck covers the release check");
    let sign = at(r#"cosign sign-blob --yes --key cosign.key --signing-config signing-config.json --bundle "$f.sigstore.json" "$f""#);
    let online = at("deploy/offline-release-check.sh\" online signed");
    let offline = at("deploy/offline-release-check.sh offline");
    let load = at("deploy/offline-bundle.sh load \"$RUNNER_TEMP/signed/");
    assert!(lint < unit && load < sign && sign == online && online < offline, "lint, unit test, load unsigned, sign and check connected, then offline");
    for want in ["--key cosign.pub --any-binary-arch", r#"--commit "$(git -C "$GITHUB_WORKSPACE" rev-parse HEAD)""#, "signed/release-check.expected"] {
        assert!(s[online].contains(want), "the connected check must have `{want}`");
    }
    let on: String = yaml.lines().take_while(|l| !l.starts_with("permissions:")).collect::<Vec<_>>().join("\n");
    for path in ["deploy/offline-release-check.sh", "deploy/test-offline-release-check.sh", ".github/workflows/offline-release-check.yml"] {
        assert_eq!(on.matches(&format!("'{path}'")).count(), 2, "pushes and pull requests that change {path} run offline.yml");
    }
}

#[test]
fn every_release_is_checked_end_to_end_after_its_bundles_are_attached() {
    let yaml = read(".github/workflows/offline.yml");
    let all = jobs(&yaml);
    let check = job(&all, "release-check");
    assert_eq!(key(check, "needs"), "release-bundle", "the check waits for both arches' bundles");
    assert_eq!(key(check, "uses"), "./.github/workflows/offline-release-check.yml");
    assert!(
        check.join("\n").contains("tag: ${{ github.event_name == 'workflow_dispatch' && format('v{0}', inputs.version) || github.event.workflow_run.head_branch }}"),
        "it checks the tag release-bundle bundled"
    );
}

#[test]
fn the_release_check_reads_ghcr_anonymously_and_verifies_offline() {
    let yaml = read(".github/workflows/offline-release-check.yml");
    assert!(yaml.starts_with("name: offline-release-check\n"));
    let on: String = yaml.lines().take_while(|l| !l.starts_with("permissions:")).collect::<Vec<_>>().join("\n");
    for want in ["  workflow_call:\n    inputs:\n      tag:", "  workflow_dispatch:", "  schedule:"] {
        assert!(on.contains(want), "offline-release-check.yml must run on `{want}`");
    }
    let top: Vec<&str> = yaml.lines().take_while(|l| *l != "jobs:").collect();
    assert_eq!(permissions(&top), ["contents: read"]);
    let all = jobs(&yaml);
    assert_eq!(all.len(), 1, "one job");
    let (id, body) = &all[0];
    assert_eq!(permissions(body), ["contents: read"], "{id} only reads: no id-token, packages or writes");
    for login in ["docker login", "skopeo login", "cosign login", "login-action", "packages:"] {
        assert!(!yaml.contains(login), "no registry login (`{login}`): ghcr.io is read as a customer reads it");
    }
    let s = steps(body);
    for step in &s {
        if let Some(run) = step.split_once("run:").map(|(_, r)| r) {
            assert!(!run.contains("${{"), "values reach the shell through env, not `${{{{ }}}}` in a script:\n{step}");
        }
    }
    let at = |want: &str| s.iter().position(|step| step.contains(want)).unwrap_or_else(|| panic!("offline-release-check.yml must have `{want}`"));
    let download = at(r#"gh release download "$TAG" --pattern 'superbot-offline-*'"#);
    let root = at("cosign initialize");
    let online = at(r#"deploy/offline-release-check.sh online "$RUNNER_TEMP/release""#);
    let netns = at("sudo ip netns add offline");
    let offline = at(r#"deploy/offline-release-check.sh offline "$release" --mirror localhost:5002/superbot --trusted-root "$root""#);
    let install = at(r#"--offline "$b" --bundle-sha256 "$sum""#);
    assert!(download < root && root < online && online < netns && netns < offline && offline < install, "download, trust root, connected, namespace, offline, install");
    assert!(s[root].contains("tuf-repo-cdn.sigstore.dev/targets/trusted_root.json"), "the trusted root is the one the guide tells operators to copy");
    for want in [
        r#"--commit "$COMMIT""#,
        "--max-glibc 2.35",
        r#"--image "superbot=ghcr.io/${GITHUB_REPOSITORY,,}:$VERSION""#,
        r#"--image "caddy=ghcr.io/${GITHUB_REPOSITORY,,}-caddy:$VERSION""#,
        r#"--image-identity "https://github.com/$GITHUB_REPOSITORY/.github/workflows/docker.yml@refs/tags/v$VERSION""#,
    ] {
        assert!(s[online].contains(want), "the connected check must pass `{want}`");
    }
    assert!(!s[online].contains("--key") && !s[online].contains("--any-binary-arch"), "a real release is checked keyless, binaries and all");
    for i in [offline, install] {
        assert!(s[i].contains("sudo ip netns exec offline"), "step {i} runs with no network");
    }
    assert!(s[offline].contains("the network is still up"), "the offline step checks it has no network");
    for want in ["SIGSTORE_TRUSTED_ROOT=", "grep -Fq 'Bundle signature verified'", "http://127.0.0.1:3000/healthz", "NetworkNamespacePath"] {
        assert!(s[install].contains(want) || s[netns].contains(want), "the install must have `{want}`");
    }
}

// ADR 0200: a Hermes bundle per arch is made, signed and attached with the release's bundles,
// and CI installs Hermes Agent from one with no network.
#[test]
fn hermes_bundles_are_signed_released_and_installed_with_no_network() {
    let yaml = read(".github/workflows/offline.yml");
    let all = jobs(&yaml);
    let s = steps(job(&all, "release-bundle"));
    let at = |want: &str| s.iter().position(|step| step.contains(want)).unwrap_or_else(|| panic!("release-bundle must have `{want}`"));
    let hermes = at("sudo deploy/offline-bundle.sh hermes --out");
    let upload = at(r#"gh release upload "$TAG" dist/superbot-hermes-* --clobber"#);
    assert!(hermes < upload, "Hermes bundles are made before they are attached");
    for want in [r#"cosign sign-blob --yes --bundle "$f.sigstore.json" "$f""#, r#"deploy/offline-bundle.sh verify "$f""#, r#"mv "$f" "$f.sha256" "$f.sigstore.json" dist/"#] {
        assert!(s[hermes].contains(want), "each Hermes bundle is signed, verified and attached with its signature: `{want}`");
    }
    let s = steps(job(&all, "install-offline"));
    let at = |want: &str| s.iter().position(|step| step.contains(want)).unwrap_or_else(|| panic!("install-offline must have `{want}`"));
    let build = at("sudo deploy/offline-bundle.sh hermes --out");
    let install = at(r#"--with-hermes --hermes-bundle "$HB""#);
    assert!(at("Install from the bundle with no network") < build && build < install, "botd installs offline, then Hermes is bundled, then installed offline");
    assert!(s[build].contains(r#"deploy/offline-bundle.sh verify "$hb""#), "CI verifies the Hermes bundle it made");
    for want in ["sudo ip netns exec offline bash deploy/install.sh", "the network is still up", "sudo -u nobody", "is already installed in /opt/hermes", "an upgrade without --with-hermes touched Hermes Agent"] {
        assert!(s[install].contains(want), "the Hermes install step must have `{want}`");
    }
    let on: String = yaml.lines().take_while(|l| !l.starts_with("permissions:")).collect::<Vec<_>>().join("\n");
    assert_eq!(on.matches("'deploy/hermes-share.sh'").count(), 2, "pushes and pull requests that change hermes-share.sh, which Hermes bundles run, run offline.yml");
}

// ADR 0232: a harness bundle per arch, at the pins of the botd built from the tag, is made,
// signed and attached with the release's bundles, and CI installs the harness CLIs from one
// with no network.
#[test]
fn harness_bundles_are_signed_released_and_installed_with_no_network() {
    let yaml = read(".github/workflows/offline.yml");
    let all = jobs(&yaml);
    let s = steps(job(&all, "release-bundle"));
    let at = |want: &str| s.iter().position(|step| step.contains(want)).unwrap_or_else(|| panic!("release-bundle must have `{want}`"));
    let botd = at("cargo build --release --bin botd");
    let harnesses = at(r#"deploy/offline-bundle.sh harnesses --out "$RUNNER_TEMP/n" --version "$VERSION""#);
    let upload = at(r#"gh release upload "$TAG" dist/superbot-harnesses-* --clobber"#);
    assert!(botd < harnesses && harnesses < upload, "the tag's botd is built, then its pins bundled, then attached");
    for want in [r#"cosign sign-blob --yes --bundle "$f.sigstore.json" "$f""#, r#"deploy/offline-bundle.sh verify "$f""#, r#"mv "$f" "$f.sha256" "$f.sigstore.json" dist/"#] {
        assert!(s[harnesses].contains(want), "each harness bundle is signed, verified and attached with its signature: `{want}`");
    }
    let s = steps(job(&all, "install-offline"));
    let at = |want: &str| s.iter().position(|step| step.contains(want)).unwrap_or_else(|| panic!("install-offline must have `{want}`"));
    let build = at("deploy/offline-bundle.sh harnesses --out");
    let install = at(r#"--harness-bundle "$NB""#);
    assert!(at("Install from the bundle with no network") < build && build < install, "botd installs offline, then the harness CLIs are bundled, then installed offline");
    assert!(s[build].contains(r#"deploy/offline-bundle.sh verify "$nb""#), "CI verifies the harness bundle it made");
    for want in [
        "sudo ip netns exec offline bash deploy/install.sh",
        "the network is still up",
        "sudo -u nobody",
        "for b in claude codex pi; do",
        "are already installed in /opt/superbot-harnesses",
        "an upgrade without --harness-bundle touched the harness CLIs",
    ] {
        assert!(s[install].contains(want), "the harness install step must have `{want}`");
    }
}

#[test]
fn the_reader_joins_folded_values() {
    let job = ["  a:", "    if: >-", "      one ||", "      two", "    runs-on: x", "    steps:", "      - run: true"];
    assert_eq!(key(&job, "if"), "one || two");
    assert_eq!(key(&job, "runs-on"), "x");
}
