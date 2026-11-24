//! Harness CLIs on users' machines from bundles botd serves, with no internet.
//! MACHINE_HERMES_BUNDLE names Hermes bundles (ADR 0200, ADR 0210), and
//! MACHINE_HARNESS_BUNDLE harness bundles (ADR 0232, ADR 0242): at most one per arch
//! each, every one checked at start as `deploy/install.sh` checks one. botd serves them
//! to enrolled machines at `/v1/hermes/<arch>` and `/v1/harnesses/<arch>`, over the
//! machine port's mutual TLS, and plans those harnesses from there instead of from
//! Hermes's installer or npm, pinned to each bundle's SHA-256.

use super::hermes_bundle::{self, Manifest};
use super::wire::{BundleKind, Download, HarnessPlan, InstallSource};
use crate::adapters::install;
use axum::http::header;
use axum::response::{IntoResponse, Response};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};

/// Where machines download a bundle: `<MACHINE_CONTROL_URL><route>/<arch>`.
pub fn route(kind: BundleKind) -> &'static str {
    match kind {
        BundleKind::Hermes => "/v1/hermes",
        BundleKind::Harnesses => "/v1/harnesses",
    }
}

/// The setting that names a kind's bundles.
pub fn key(kind: BundleKind) -> &'static str {
    match kind {
        BundleKind::Hermes => "MACHINE_HERMES_BUNDLE",
        BundleKind::Harnesses => "MACHINE_HARNESS_BUNDLE",
    }
}

fn what(kind: BundleKind) -> &'static str {
    match kind {
        BundleKind::Hermes => "Hermes bundle",
        BundleKind::Harnesses => "harness bundle",
    }
}

/// Where a kind's tree runs on machines, as on a server.
fn prefix(kind: BundleKind) -> &'static str {
    match kind {
        BundleKind::Hermes => install::HERMES_PREFIX,
        BundleKind::Harnesses => install::HARNESSES_PREFIX,
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Bundle {
    pub file: PathBuf,
    /// The SHA-256 of the whole file, as checked at start.
    pub sha256: String,
    pub manifest: Manifest,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Bundles {
    pub kind: BundleKind,
    /// MACHINE_CONTROL_URL, without its trailing `/`.
    pub url: String,
    pub by_arch: BTreeMap<String, Bundle>,
}

fn hex64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn short(s: &str) -> &str {
    s.get(..12).unwrap_or(s)
}

/// `file`'s SHA-256, read in full.
fn sha256_of(file: &Path) -> Result<String, String> {
    let mut f = std::fs::File::open(file).map_err(|e| format!("{}: {e}", file.display()))?;
    let (mut h, mut buf) = (Sha256::new(), vec![0u8; 1 << 20]);
    loop {
        match f.read(&mut buf).map_err(|e| format!("{}: {e}", file.display()))? {
            0 => break,
            n => h.update(&buf[..n]),
        }
    }
    Ok(h.finalize().iter().map(|b| format!("{b:02x}")).collect())
}

impl Bundle {
    /// The `kind` bundle at `path`, checked: its SHA-256 against `pin`, else the
    /// `.sha256` beside it; then everything `hermes_bundle::read` checks; and that it was
    /// made for the prefix machines run it in.
    fn check(kind: BundleKind, path: &str, pin: Option<&str>) -> Result<Bundle, String> {
        let (key, what) = (key(kind), what(kind));
        let file = PathBuf::from(path);
        if !file.is_absolute() {
            return Err(format!("{key} must name bundles by absolute path, not \"{path}\""));
        }
        let meta = std::fs::metadata(&file).map_err(|e| format!("{key} ({path}): {e}"))?;
        if !meta.is_file() || meta.len() > hermes_bundle::MAX_BUNDLE {
            return Err(format!("{key} ({path}) isn't a {what} under {} GiB", hermes_bundle::MAX_BUNDLE >> 30));
        }
        let side = format!("{path}.sha256");
        let (pin, from) = match pin {
            Some(p) => (p.to_string(), "as given".to_string()),
            None => {
                let text = std::fs::read_to_string(&side).map_err(|_| {
                    format!("{key} ({path}): there is no {side} beside it; give its SHA-256 as {key}={path}=<sha-256>")
                })?;
                let p = text.split_whitespace().next().unwrap_or_default().to_string();
                if !hex64(&p) {
                    return Err(format!("{key} ({path}): {side} doesn't start with a SHA-256"));
                }
                (p, format!("in {side}"))
            }
        };
        let (manifest, sha256) = hermes_bundle::read(&file, kind, None).map_err(|e| format!("{key}: refusing {path}: {e}"))?;
        if sha256 != pin {
            return Err(format!("{key}: {path} has SHA-256 {sha256}, not {pin} ({from}): carry it in again"));
        }
        if manifest.prefix != prefix(kind) {
            return Err(format!("{key}: refusing {path}: it was installed for {}, not {}", manifest.prefix, prefix(kind)));
        }
        Ok(Bundle { file, sha256, manifest })
    }
}

impl Bundles {
    /// `kind`'s setting: `<file>` or `<file>=<sha-256>`, comma-separated, one per arch.
    pub fn from_env(var: &dyn Fn(&str) -> String, kind: BundleKind) -> Result<Option<Bundles>, String> {
        let key = key(kind);
        let raw = var(key);
        let mut by_arch: BTreeMap<String, Bundle> = BTreeMap::new();
        for item in raw.split(',').map(str::trim).filter(|s| !s.is_empty()) {
            let (path, pin) = match item.rsplit_once('=') {
                Some((p, sha)) if hex64(sha) => (p, Some(sha)),
                Some((_, sha)) => return Err(format!("{key}: \"{sha}\" isn't a SHA-256 (64 lowercase hex digits)")),
                None => (item, None),
            };
            let b = Bundle::check(kind, path, pin)?;
            if let Some(o) = by_arch.get(&b.manifest.arch) {
                return Err(format!("{key} names two bundles for {}: {} and {path}", b.manifest.arch, o.file.display()));
            }
            by_arch.insert(b.manifest.arch.clone(), b);
        }
        if by_arch.is_empty() {
            return Ok(None);
        }
        let url = var("MACHINE_CONTROL_URL").trim().trim_end_matches('/').to_string();
        if url.is_empty() {
            return Err(format!("{key} needs MACHINE_CONTROL_URL: machines download the bundles from there"));
        }
        Ok(Some(Bundles { kind, url, by_arch }))
    }

    fn downloads(&self) -> BTreeMap<String, Download> {
        let route = route(self.kind);
        self.by_arch
            .iter()
            .map(|(arch, b)| (arch.clone(), Download { url: format!("{}{route}/{arch}", self.url), sha256: b.sha256.clone() }))
            .collect()
    }

    /// `plan` with what these bundles hold from them. Each must hold exactly what the
    /// plan pins: a bundle can't change what machines run, only where it comes from.
    pub fn apply(&self, plan: HarnessPlan) -> Result<HarnessPlan, String> {
        match self.kind {
            BundleKind::Hermes => self.apply_hermes(plan),
            BundleKind::Harnesses => self.apply_harnesses(plan),
        }
    }

    fn apply_hermes(&self, mut plan: HarnessPlan) -> Result<HarnessPlan, String> {
        for h in plan.harnesses.iter_mut().filter(|h| h.name == "hermes") {
            if let Some(b) = self.by_arch.values().find(|b| b.manifest.commit != h.version) {
                return Err(format!(
                    "{}: {} holds Hermes Agent {}, but machines' plan pins {}: use the Hermes bundle made for this release",
                    key(self.kind),
                    b.file.display(),
                    short(&b.manifest.commit),
                    short(&h.version)
                ));
            }
            *h = install::hermes_from_bundles(h, self.downloads());
        }
        Ok(plan)
    }

    /// Every npm harness in `plan` from these bundles, each of which must hold it at the
    /// version, package and integrity the plan pins, on the Node.js it pins for that
    /// bundle's arch. The tree has its own Node.js, so a plan left with no npm harness
    /// plans none.
    fn apply_harnesses(&self, mut plan: HarnessPlan) -> Result<HarnessPlan, String> {
        let key = key(self.kind);
        let release = "use the harness bundle made for this release";
        let mut any = false;
        for h in plan.harnesses.iter_mut() {
            let InstallSource::Npm { package, integrity } = &h.source else { continue };
            let want = format!("{} {package} {}", h.version, integrity.as_deref().unwrap_or("(no pinned integrity)"));
            for b in self.by_arch.values() {
                match b.manifest.harnesses.get(&h.name) {
                    Some(have) if *have == want => {}
                    Some(have) => return Err(format!("{key}: {} holds {} {have}, but machines' plan pins {want}: {release}", b.file.display(), h.name)),
                    None => return Err(format!("{key}: {} doesn't hold {}, which machines' plan names: {release}, or leave {} out of MACHINE_HARNESSES", b.file.display(), h.name, h.name)),
                }
                if let Some(n) = &plan.node {
                    let pinned = n.downloads.get(&b.manifest.arch).map(|d| format!("{} {}", n.version, d.sha256));
                    if pinned.as_deref() != Some(b.manifest.node.as_str()) {
                        return Err(format!(
                            "{key}: {} holds Node.js {}, but machines' plan pins {} for {}: {release}",
                            b.file.display(),
                            b.manifest.node,
                            pinned.unwrap_or_else(|| "none".into()),
                            b.manifest.arch
                        ));
                    }
                }
            }
            *h = install::harness_from_bundles(h, self.downloads());
            any = true;
        }
        if any && !plan.harnesses.iter().any(|h| matches!(h.source, InstallSource::Npm { .. })) {
            plan.node = None;
        }
        Ok(plan)
    }

    pub fn describe(&self, plan: Option<&HarnessPlan>) -> String {
        let each: Vec<String> = self.by_arch.iter().map(|(arch, b)| format!("{arch} ({})", b.file.display())).collect();
        let (whose, none) = match self.kind {
            BundleKind::Hermes => ("Hermes Agent on machines from botd's Hermes bundles", "machines' plan has no Hermes Agent"),
            BundleKind::Harnesses => ("Claude Code, Codex and Pi on machines from botd's harness bundles", "machines' plan has none of their harnesses"),
        };
        let mut s = format!("{whose}: {}", each.join(", "));
        if !plan.is_some_and(|p| bundled_kind(p, self.kind)) {
            s.push_str(&format!(" ({} is set, but {none})", key(self.kind)));
        }
        s
    }

    /// Whether the file served for `arch` is still the one `sha256` pins.
    pub async fn recheck(&self, arch: &str, sha256: &str) -> Result<(), String> {
        let b = self.by_arch.get(arch).ok_or(format!("botd serves no {} for {arch}", what(self.kind)))?;
        let file = b.file.clone();
        let got = tokio::task::spawn_blocking(move || sha256_of(&file)).await.map_err(|e| e.to_string())??;
        if got != sha256 {
            return Err(format!("{} has SHA-256 {got} now, not the {sha256} botd checked at start: put the bundle back, or restart botd with the new one", b.file.display()));
        }
        Ok(())
    }
}

/// `botd harness check-bundles FILE...` (ADR 0247): what this botd makes of FILEs as
/// MACHINE_HERMES_BUNDLE and MACHINE_HARNESS_BUNDLE (by their names), with machines' plan
/// naming every harness it pins. Each is checked in full against the `.sha256` beside it, as
/// at start, and must hold exactly what that plan pins. One line per bundle, then the
/// harnesses machines would install from them. Reads no settings; serves and starts nothing.
pub fn check_files(files: &[String]) -> Result<String, String> {
    if files.is_empty() {
        return Err("Give the Hermes and harness bundles to check".into());
    }
    let (mut hermes, mut clis) = (Vec::new(), Vec::new());
    for f in files {
        let name = Path::new(f).file_name().and_then(|n| n.to_str()).unwrap_or_default();
        let list = if name.starts_with("superbot-hermes-") {
            &mut hermes
        } else if name.starts_with("superbot-harnesses-") {
            &mut clis
        } else {
            return Err(format!("{f} isn't named as a Hermes bundle (superbot-hermes-*) or a harness bundle (superbot-harnesses-*)"));
        };
        let abs = std::path::absolute(f).map_err(|e| format!("{f}: {e}"))?;
        list.push(abs.display().to_string());
    }
    let all = install::bins().join(",");
    let var = |k: &str| match k {
        "MACHINE_HARNESSES" => all.clone(),
        "MACHINE_HERMES_BUNDLE" => hermes.join(","),
        "MACHINE_HARNESS_BUNDLE" => clis.join(","),
        // Only named in the plan's download URLs, which nothing here fetches.
        "MACHINE_CONTROL_URL" => "https://botd.invalid".into(),
        _ => String::new(),
    };
    let mut plan = super::upkeep::parse_harnesses(&all)?.ok_or("this botd pins no harnesses")?;
    let mut out = String::new();
    for kind in [BundleKind::Harnesses, BundleKind::Hermes] {
        let Some(b) = Bundles::from_env(&var, kind)? else { continue };
        plan = b.apply(plan)?;
        for (arch, x) in &b.by_arch {
            let m = &x.manifest;
            let holds = match kind {
                BundleKind::Hermes => format!("Hermes Agent {} ({})", m.tag, short(&m.commit)),
                BundleKind::Harnesses => {
                    let each: Vec<String> = m.harnesses.iter().map(|(h, v)| format!("{h} {}", v.split(' ').next().unwrap_or_default())).collect();
                    format!("{} on Node.js {}", each.join(", "), m.node.split(' ').next().unwrap_or_default())
                }
            };
            out.push_str(&format!("{arch} {} {}: {holds}, SHA-256 {}\n", what(kind), x.file.display(), x.sha256));
        }
    }
    super::tools::check(&plan).map_err(|e| format!("machines couldn't install from these bundles: {e}"))?;
    let (from, rest): (Vec<_>, Vec<_>) = plan.harnesses.iter().partition(|h| matches!(h.source, InstallSource::Bundle { .. }));
    let names = |l: &[&super::wire::HarnessInstall]| l.iter().map(|h| h.name.as_str()).collect::<Vec<_>>().join(", ");
    out.push_str(&format!("Machines would install {} from these bundles", names(&from)));
    if !rest.is_empty() {
        out.push_str(&format!(", and {} from the internet or the operator's mirrors", names(&rest)));
    }
    out.push('\n');
    Ok(out)
}

/// Whether only an agent that says `CAN_HARNESS_BUNDLES` can install `plan`.
pub fn bundled(plan: &HarnessPlan) -> bool {
    plan.harnesses.iter().any(|h| matches!(h.source, InstallSource::Bundle { .. }))
}

/// Whether `plan` installs something from a `kind` bundle. With a harness bundle, only an
/// agent that also says `CAN_HARNESS_CLI_BUNDLES` can install it.
pub fn bundled_kind(plan: &HarnessPlan, kind: BundleKind) -> bool {
    plan.harnesses.iter().any(|h| matches!(&h.source, InstallSource::Bundle { holds: k, .. } if *k == kind))
}

/// `file`, streamed: a bundle is too large to hold in memory, as the agent binary is.
pub async fn body(file: &Path) -> Result<Response, String> {
    use tokio::io::AsyncReadExt;
    let f = tokio::fs::File::open(file).await.map_err(|e| format!("{}: {e}", file.display()))?;
    let len = f.metadata().await.map_err(|e| format!("{}: {e}", file.display()))?.len();
    let chunks = futures_util::stream::unfold(Some(f), |f| async move {
        let mut f = f?;
        let mut buf = vec![0u8; 256 << 10];
        match f.read(&mut buf).await {
            Ok(0) => None,
            Ok(n) => {
                buf.truncate(n);
                Some((Ok::<_, std::io::Error>(axum::body::Bytes::from(buf)), Some(f)))
            }
            Err(e) => Some((Err(e), None)),
        }
    });
    Ok((
        [(header::CONTENT_TYPE, "application/octet-stream".to_string()), (header::CONTENT_LENGTH, len.to_string())],
        axum::body::Body::from_stream(chunks),
    )
        .into_response())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::machines::hermes_bundle::standin;

    const KEY: &str = "MACHINE_HERMES_BUNDLE";

    fn temp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("superbot-hs-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn pinned_commit() -> String {
        install::install("hermes", None, None).unwrap().version
    }

    /// A stand-in bundle for `arch` at `commit`, with its `.sha256` beside it.
    fn bundle_file(dir: &Path, arch: &str, commit: &str) -> (PathBuf, String) {
        let body = standin::bundle(
            &format!("superbot-hermes-v0.23.3-{arch}"),
            &[("MANIFEST", standin::manifest(commit, arch, "/opt/hermes").into_bytes()), ("hermes.tar", standin::tree("#!/bin/sh\necho hermes\n"))],
            None,
        );
        let f = dir.join(format!("superbot-hermes-v0.23.3-{arch}.tar.gz"));
        std::fs::write(&f, &body).unwrap();
        let sha: String = Sha256::digest(&body).iter().map(|b| format!("{b:02x}")).collect();
        std::fs::write(dir.join(format!("superbot-hermes-v0.23.3-{arch}.tar.gz.sha256")), format!("{sha}  superbot-hermes-v0.23.3-{arch}.tar.gz\n")).unwrap();
        (f, sha)
    }

    fn env(pairs: Vec<(&'static str, String)>) -> impl Fn(&str) -> String {
        move |k: &str| pairs.iter().find(|(key, _)| *key == k).map(|(_, v)| v.clone()).unwrap_or_default()
    }

    #[test]
    fn bundles_are_checked_at_start() {
        let dir = temp("hermes-serve");
        let (x86, sha) = bundle_file(&dir, "x86_64", &pinned_commit());
        let (arm, _) = bundle_file(&dir, "aarch64", &pinned_commit());
        let url = || ("MACHINE_CONTROL_URL", "https://10.0.0.5:8443/".to_string());
        assert_eq!(Bundles::from_env(&env(vec![url()]), BundleKind::Hermes).unwrap(), None, "off by default");

        let b = Bundles::from_env(&env(vec![url(), (KEY, format!("{}, {}", x86.display(), arm.display()))]), BundleKind::Hermes).unwrap().unwrap();
        assert_eq!(b.url, "https://10.0.0.5:8443");
        assert_eq!(b.by_arch.keys().collect::<Vec<_>>(), ["aarch64", "x86_64"]);
        assert_eq!(b.by_arch["x86_64"].sha256, sha);
        let pinned = Bundles::from_env(&env(vec![url(), (KEY, format!("{}={sha}", x86.display()))]), BundleKind::Hermes).unwrap().unwrap();
        assert_eq!(pinned.by_arch["x86_64"].sha256, sha, "a SHA-256 given instead of the .sha256");

        let refused = |v: String, why: &str| {
            let err = Bundles::from_env(&env(vec![url(), (KEY, v.clone())]), BundleKind::Hermes).unwrap_err();
            assert!(err.contains(why), "{v}: {err}");
        };
        refused(format!("{}={}", x86.display(), "a".repeat(64)), &format!("not {}", "a".repeat(64)));
        refused(format!("{}=abc", x86.display()), "isn't a SHA-256");
        refused("superbot-hermes.tar.gz".into(), "absolute path");
        refused(dir.join("missing.tar.gz").display().to_string(), "missing.tar.gz");
        refused(format!("{},{}", x86.display(), x86.display()), "two bundles for x86_64");
        let (other, _) = bundle_file(&dir, "x86_64", &"b".repeat(40));
        std::fs::write(dir.join("lone.tar.gz"), std::fs::read(&other).unwrap()).unwrap();
        refused(dir.join("lone.tar.gz").display().to_string(), "no ");
        let wrong_prefix = standin::bundle(
            "superbot-hermes-v0.23.3-x86_64",
            &[("MANIFEST", standin::manifest(&pinned_commit(), "x86_64", "/srv/hermes").into_bytes()), ("hermes.tar", standin::tree("x"))],
            None,
        );
        let f = dir.join("prefix.tar.gz");
        std::fs::write(&f, &wrong_prefix).unwrap();
        let sha: String = Sha256::digest(&wrong_prefix).iter().map(|b| format!("{b:02x}")).collect();
        refused(format!("{}={sha}", f.display()), "installed for /srv/hermes");
        std::fs::write(&f, b"not a bundle").unwrap();
        let sha: String = Sha256::digest(b"not a bundle").iter().map(|b| format!("{b:02x}")).collect();
        refused(format!("{}={sha}", f.display()), "refusing");
        let err = Bundles::from_env(&env(vec![(KEY, x86.display().to_string())]), BundleKind::Hermes).unwrap_err();
        assert!(err.contains("needs MACHINE_CONTROL_URL"), "{err}");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_bundle_changes_where_hermes_comes_from_never_its_commit() {
        let dir = temp("hermes-apply");
        let (x86, sha) = bundle_file(&dir, "x86_64", &pinned_commit());
        let b = Bundles::from_env(&env(vec![("MACHINE_CONTROL_URL", "https://10.0.0.5:8443".into()), (KEY, x86.display().to_string())]), BundleKind::Hermes).unwrap().unwrap();
        let claude = install::install("claude", None, None).unwrap();
        let hermes = install::install("hermes", None, None).unwrap();
        let plan = install::plan(vec![claude.clone(), hermes.clone()]);
        let out = b.apply(plan.clone()).unwrap();
        assert_eq!(out.harnesses[0], claude, "npm harnesses are left alone");
        assert_eq!(out.harnesses[1].version, hermes.version);
        match &out.harnesses[1].source {
            InstallSource::Bundle { holds: kind, downloads, prefix, bin, readable, after } => {
                assert_eq!(downloads["x86_64"], Download { url: "https://10.0.0.5:8443/v1/hermes/x86_64".into(), sha256: sha });
                assert_eq!((*kind, prefix.as_str()), (BundleKind::Hermes, "/opt/hermes"));
                assert_eq!(bin, ".hermes/superbot/hermes");
                assert!(readable.contains(&".hermes/installs".to_string()));
                assert_eq!(after.as_deref(), Some(install::HERMES_SHARE));
            }
            s => panic!("{s:?}"),
        }
        crate::machines::tools::check(&out).unwrap();
        assert!(bundled(&out) && !bundled(&plan));
        assert!(b.describe(Some(&out)).contains("x86_64 ("), "{}", b.describe(Some(&out)));
        assert!(b.describe(Some(&install::plan(vec![claude.clone()]))).contains("has no Hermes Agent"));

        let other = install::install("hermes", Some(&"b".repeat(40)), Some(&"c".repeat(64))).unwrap();
        let err = b.apply(install::plan(vec![other])).unwrap_err();
        assert!(err.contains("but machines' plan pins bbbbbbbbbbbb"), "{err}");
        let none = install::plan(vec![claude]);
        assert_eq!(b.apply(none.clone()).unwrap(), none, "no Hermes, nothing changes");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn the_served_file_is_checked_again_on_request() {
        let dir = temp("hermes-recheck");
        let (x86, sha) = bundle_file(&dir, "x86_64", &pinned_commit());
        let b = Bundles::from_env(&env(vec![("MACHINE_CONTROL_URL", "https://10.0.0.5:8443".into()), (KEY, x86.display().to_string())]), BundleKind::Hermes).unwrap().unwrap();
        b.recheck("x86_64", &sha).await.unwrap();
        assert!(b.recheck("aarch64", &sha).await.unwrap_err().contains("no Hermes bundle for aarch64"));
        std::fs::write(&x86, b"changed").unwrap();
        assert!(b.recheck("x86_64", &sha).await.unwrap_err().contains("restart botd"));
        let _ = std::fs::remove_dir_all(dir);
    }

    const HARNESS_KEY: &str = "MACHINE_HARNESS_BUNDLE";

    /// This build's pins for `bins` on `arch`, as a harness bundle's MANIFEST lines.
    pub(crate) fn real_pins(arch: &str, bins: &[&str]) -> String {
        let n = install::node();
        let mut s = format!("harnesses={}\nnode={} {}\n", bins.join(" "), n.version, n.downloads[arch].sha256);
        for b in bins {
            let h = install::install(b, None, None).unwrap();
            let InstallSource::Npm { package, integrity: Some(i) } = h.source else { panic!("{b}") };
            s.push_str(&format!("harness_{b}={} {package} {i}\n", h.version));
        }
        s
    }

    /// A stand-in harness bundle for `arch` with MANIFEST `pins`, and its `.sha256`.
    fn harness_file(dir: &Path, arch: &str, pins: &str) -> (PathBuf, String) {
        let body = standin::good_harnesses(arch, &[("claude", "2.1.329")], pins);
        let f = dir.join(format!("superbot-harnesses-0.1.0-{arch}.tar.gz"));
        std::fs::write(&f, &body).unwrap();
        let sha: String = Sha256::digest(&body).iter().map(|b| format!("{b:02x}")).collect();
        std::fs::write(dir.join(format!("superbot-harnesses-0.1.0-{arch}.tar.gz.sha256")), format!("{sha}\n")).unwrap();
        (f, sha)
    }

    fn harness_bundles(dir: &Path, pins: &[(&str, String)]) -> Result<Option<Bundles>, String> {
        let files: Vec<String> = pins.iter().map(|(arch, p)| harness_file(dir, arch, p).0.display().to_string()).collect();
        Bundles::from_env(&env(vec![("MACHINE_CONTROL_URL", "https://10.0.0.5:8443".into()), (HARNESS_KEY, files.join(","))]), BundleKind::Harnesses)
    }

    #[test]
    fn a_harness_bundle_serves_every_npm_harness_at_its_pins() {
        let dir = temp("harness-apply");
        let all = ["claude", "codex", "pi"];
        let b = harness_bundles(&dir, &[("x86_64", real_pins("x86_64", &all)), ("aarch64", real_pins("aarch64", &all))]).unwrap().unwrap();
        assert_eq!((b.kind, b.by_arch.keys().collect::<Vec<_>>()), (BundleKind::Harnesses, vec![&"aarch64".to_string(), &"x86_64".to_string()]));
        let hermes = install::install("hermes", None, None).unwrap();
        let plan = install::plan(all.iter().map(|h| install::install(h, None, None).unwrap()).chain([hermes.clone()]).collect());
        let out = b.apply(plan.clone()).unwrap();
        assert_eq!(out.node, None, "the tree has its own Node.js");
        assert_eq!(out.harnesses[3], hermes, "Hermes is left alone");
        for (h, was) in out.harnesses.iter().zip(&plan.harnesses).take(3) {
            assert_eq!(h.version, was.version);
            match &h.source {
                InstallSource::Bundle { holds: kind, downloads, prefix, bin, readable, after } => {
                    assert_eq!((*kind, prefix.as_str(), bin.clone()), (BundleKind::Harnesses, "/opt/superbot-harnesses", format!("superbot/{}", h.name)));
                    assert_eq!(downloads["x86_64"], Download { url: "https://10.0.0.5:8443/v1/harnesses/x86_64".into(), sha256: b.by_arch["x86_64"].sha256.clone() });
                    assert_eq!(downloads.len(), 2);
                    assert!(readable.contains(&"lib".to_string()) && after.is_none(), "{readable:?}");
                }
                s => panic!("{s:?}"),
            }
        }
        crate::machines::tools::check(&out).unwrap();
        assert!(bundled_kind(&out, BundleKind::Harnesses) && !bundled_kind(&out, BundleKind::Hermes) && !bundled_kind(&plan, BundleKind::Harnesses));
        assert!(b.describe(Some(&out)).starts_with("Claude Code, Codex and Pi on machines from botd's harness bundles: aarch64 ("), "{}", b.describe(Some(&out)));
        let hermes_only = install::plan(vec![hermes]);
        assert_eq!(b.apply(hermes_only.clone()).unwrap(), hermes_only, "no npm harness, nothing changes");
        assert!(b.describe(Some(&hermes_only)).contains("MACHINE_HARNESS_BUNDLE is set, but machines' plan has none of their harnesses"));
        let some = b.apply(install::plan(vec![install::install("pi", None, None).unwrap()])).unwrap();
        assert_eq!(some.harnesses.len(), 1, "a bundle may hold more than the plan names");

        let refused = |bundles: &Bundles, plan: HarnessPlan, why: &str| {
            let err = bundles.apply(plan).unwrap_err();
            assert!(err.starts_with("MACHINE_HARNESS_BUNDLE: ") && err.contains(why), "{why}: {err}");
        };
        refused(&b, install::plan(vec![install::install("claude", Some("2.2.0"), None).unwrap()]), "but machines' plan pins 2.2.0 @anthropic-ai/claude-code (no pinned integrity)");
        let other = harness_bundles(&temp("harness-other"), &[("x86_64", real_pins("x86_64", &["claude", "pi"]))]).unwrap().unwrap();
        refused(&other, plan.clone(), "doesn't hold codex, which machines' plan names");
        let node = real_pins("x86_64", &all).replace(&install::node().downloads["x86_64"].sha256, &"b".repeat(64));
        let old_node = harness_bundles(&temp("harness-node"), &[("x86_64", node)]).unwrap().unwrap();
        refused(&old_node, plan.clone(), "holds Node.js");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn harness_bundles_are_checked_at_start_and_on_request() {
        let dir = temp("harness-serve");
        let pins = real_pins("x86_64", &["claude"]);
        let (x86, sha) = harness_file(&dir, "x86_64", &pins);
        let with = |v: String| Bundles::from_env(&env(vec![("MACHINE_CONTROL_URL", "https://10.0.0.5:8443".into()), (HARNESS_KEY, v)]), BundleKind::Harnesses);
        assert_eq!(with(String::new()).unwrap(), None, "off by default");
        let b = with(format!("{}={sha}", x86.display())).unwrap().unwrap();
        b.recheck("x86_64", &sha).await.unwrap();
        assert!(b.recheck("aarch64", &sha).await.unwrap_err().contains("no harness bundle for aarch64"));

        let (hermes, _) = bundle_file(&dir, "x86_64", &pinned_commit());
        let err = with(hermes.display().to_string()).unwrap_err();
        assert!(err.contains("MACHINE_HARNESS_BUNDLE: refusing") && err.contains("isn't a harness bundle"), "{err}");
        let err = Bundles::from_env(&env(vec![(KEY, x86.display().to_string())]), BundleKind::Hermes).unwrap_err();
        assert!(err.contains("isn't a Hermes bundle"), "and the other way: {err}");
        let elsewhere = standin::bundle(
            "superbot-harnesses-0.1.0-x86_64",
            &[("MANIFEST", standin::harness_manifest("x86_64", "/usr/local", &pins).into_bytes()), ("harnesses.tar", standin::harness_tree(&[("claude", "2.1.329")]))],
            None,
        );
        let f = dir.join("elsewhere.tar.gz");
        std::fs::write(&f, &elsewhere).unwrap();
        let sha2: String = Sha256::digest(&elsewhere).iter().map(|b| format!("{b:02x}")).collect();
        assert!(with(format!("{}={sha2}", f.display())).unwrap_err().contains("installed for /usr/local, not /opt/superbot-harnesses"));
        assert!(with(format!("{},{}", x86.display(), x86.display())).unwrap_err().contains("two bundles for x86_64"));
        let err = Bundles::from_env(&env(vec![(HARNESS_KEY, x86.display().to_string())]), BundleKind::Harnesses).unwrap_err();
        assert!(err.contains("MACHINE_HARNESS_BUNDLE needs MACHINE_CONTROL_URL"), "{err}");

        std::fs::write(&x86, b"changed").unwrap();
        assert!(b.recheck("x86_64", &sha).await.unwrap_err().contains("restart botd"));
        let _ = std::fs::remove_dir_all(dir);
    }

    // ADR 0247: `botd harness check-bundles`, as the release check runs it on a release's
    // Hermes and harness bundles.
    #[test]
    fn check_bundles_says_what_machines_would_take() {
        let dir = temp("check-bundles");
        let all = ["claude", "codex", "pi"];
        let (hx, hsha) = bundle_file(&dir, "x86_64", &pinned_commit());
        let (ha, _) = bundle_file(&dir, "aarch64", &pinned_commit());
        let (nx, nsha) = harness_file(&dir, "x86_64", &real_pins("x86_64", &all));
        let (na, _) = harness_file(&dir, "aarch64", &real_pins("aarch64", &all));
        let files = |l: &[&PathBuf]| l.iter().map(|p| p.display().to_string()).collect::<Vec<_>>();

        let out = check_files(&files(&[&hx, &ha, &nx, &na])).unwrap();
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines.len(), 5, "{out}");
        let versions: Vec<String> = all.iter().map(|h| format!("{h} {}", install::install(h, None, None).unwrap().version)).collect();
        let na_sha: String = Sha256::digest(std::fs::read(&na).unwrap()).iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(lines[0], format!("aarch64 harness bundle {}: {} on Node.js {}, SHA-256 {na_sha}", na.display(), versions.join(", "), install::node().version));
        assert!(lines[1].starts_with(&format!("x86_64 harness bundle {}: ", nx.display())) && lines[1].ends_with(&format!(", SHA-256 {nsha}")), "{out}");
        assert!(lines[2].starts_with(&format!("aarch64 Hermes bundle {}: ", ha.display())), "{out}");
        assert_eq!(lines[3], format!("x86_64 Hermes bundle {}: Hermes Agent v0.23.3 ({}), SHA-256 {hsha}", hx.display(), &pinned_commit()[..12]));
        assert_eq!(lines[4], format!("Machines would install {} from these bundles", install::bins().join(", ")));
        let only = check_files(&files(&[&nx])).unwrap();
        assert!(only.ends_with("Machines would install claude, codex, pi from these bundles, and hermes from the internet or the operator's mirrors\n"), "{only}");

        let refused = |l: Vec<String>, why: &str| {
            let err = check_files(&l).unwrap_err();
            assert!(err.contains(why), "{why}: {err}");
        };
        refused(Vec::new(), "Give the Hermes and harness bundles");
        refused(vec![dir.join("botd").display().to_string()], "isn't named as a Hermes bundle");
        refused(files(&[&hx, &hx]), "two bundles for x86_64");
        let other = temp("check-bundles-other");
        let (old, _) = bundle_file(&other, "x86_64", &"b".repeat(40));
        refused(files(&[&old]), "holds Hermes Agent bbbbbbbbbbbb, but machines' plan pins");
        let (few, _) = harness_file(&other, "aarch64", &real_pins("aarch64", &["claude", "pi"]));
        refused(files(&[&few]), "doesn't hold codex, which machines' plan names");
        std::fs::rename(&few, other.join("superbot-hermes-v0.23.3-aarch64.tar.gz")).unwrap();
        std::fs::rename(other.join("superbot-harnesses-0.1.0-aarch64.tar.gz.sha256"), other.join("superbot-hermes-v0.23.3-aarch64.tar.gz.sha256")).unwrap();
        refused(vec![other.join("superbot-hermes-v0.23.3-aarch64.tar.gz").display().to_string()], "isn't a Hermes bundle");
        std::fs::remove_file(other.join("superbot-hermes-v0.23.3-aarch64.tar.gz.sha256")).unwrap();
        refused(vec![other.join("superbot-hermes-v0.23.3-aarch64.tar.gz").display().to_string()], "there is no");
        std::fs::write(dir.join("superbot-harnesses-0.1.0-x86_64.tar.gz.sha256"), format!("{}\n", "a".repeat(64))).unwrap();
        refused(files(&[&nx]), &format!("has SHA-256 {nsha}, not {}", "a".repeat(64)));
        let _ = std::fs::remove_dir_all(dir);
        let _ = std::fs::remove_dir_all(other);
    }
}
