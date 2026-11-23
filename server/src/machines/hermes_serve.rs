//! Hermes Agent on users' machines with no internet (ADR 0210). MACHINE_HERMES_BUNDLE
//! names Hermes bundles (ADR 0200), at most one per arch, each checked at start as
//! `deploy/install.sh` checks one. botd serves them to enrolled machines at
//! `/v1/hermes/<arch>`, over the machine port's mutual TLS, and plans Hermes from there
//! instead of from its installer, pinned to each bundle's SHA-256.

use super::hermes_bundle::{self, Manifest};
use super::wire::{Download, HarnessPlan, InstallSource};
use crate::adapters::install;
use axum::http::header;
use axum::response::{IntoResponse, Response};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};

/// Where machines download a bundle: `<MACHINE_CONTROL_URL>/v1/hermes/<arch>`.
pub const ROUTE: &str = "/v1/hermes";
const KEY: &str = "MACHINE_HERMES_BUNDLE";

#[derive(Clone, Debug, PartialEq)]
pub struct Bundle {
    pub file: PathBuf,
    /// The SHA-256 of the whole file, as checked at start.
    pub sha256: String,
    pub manifest: Manifest,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Bundles {
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
    /// The bundle at `path`, checked: its SHA-256 against `pin`, else the `.sha256`
    /// beside it; then everything `hermes_bundle::read` checks; and that it was made
    /// for the prefix machines run Hermes in.
    fn check(path: &str, pin: Option<&str>) -> Result<Bundle, String> {
        let file = PathBuf::from(path);
        if !file.is_absolute() {
            return Err(format!("{KEY} must name bundles by absolute path, not \"{path}\""));
        }
        let meta = std::fs::metadata(&file).map_err(|e| format!("{KEY} ({path}): {e}"))?;
        if !meta.is_file() || meta.len() > hermes_bundle::MAX_BUNDLE {
            return Err(format!("{KEY} ({path}) isn't a Hermes bundle under {} GiB", hermes_bundle::MAX_BUNDLE >> 30));
        }
        let side = format!("{path}.sha256");
        let (pin, from) = match pin {
            Some(p) => (p.to_string(), "as given".to_string()),
            None => {
                let text = std::fs::read_to_string(&side).map_err(|_| {
                    format!("{KEY} ({path}): there is no {side} beside it; give its SHA-256 as {KEY}={path}=<sha-256>")
                })?;
                let p = text.split_whitespace().next().unwrap_or_default().to_string();
                if !hex64(&p) {
                    return Err(format!("{KEY} ({path}): {side} doesn't start with a SHA-256"));
                }
                (p, format!("in {side}"))
            }
        };
        let (manifest, sha256) = hermes_bundle::read(&file, None).map_err(|e| format!("{KEY}: refusing {path}: {e}"))?;
        if sha256 != pin {
            return Err(format!("{KEY}: {path} has SHA-256 {sha256}, not {pin} ({from}): carry it in again"));
        }
        if manifest.prefix != install::HERMES_PREFIX {
            return Err(format!("{KEY}: refusing {path}: it was installed for {}, not {}", manifest.prefix, install::HERMES_PREFIX));
        }
        Ok(Bundle { file, sha256, manifest })
    }
}

impl Bundles {
    /// `<file>` or `<file>=<sha-256>`, comma-separated, one per arch.
    pub fn from_env(var: &dyn Fn(&str) -> String) -> Result<Option<Bundles>, String> {
        let raw = var(KEY);
        let mut by_arch: BTreeMap<String, Bundle> = BTreeMap::new();
        for item in raw.split(',').map(str::trim).filter(|s| !s.is_empty()) {
            let (path, pin) = match item.rsplit_once('=') {
                Some((p, sha)) if hex64(sha) => (p, Some(sha)),
                Some((_, sha)) => return Err(format!("{KEY}: \"{sha}\" isn't a SHA-256 (64 lowercase hex digits)")),
                None => (item, None),
            };
            let b = Bundle::check(path, pin)?;
            if let Some(o) = by_arch.get(&b.manifest.arch) {
                return Err(format!("{KEY} names two bundles for {}: {} and {path}", b.manifest.arch, o.file.display()));
            }
            by_arch.insert(b.manifest.arch.clone(), b);
        }
        if by_arch.is_empty() {
            return Ok(None);
        }
        let url = var("MACHINE_CONTROL_URL").trim().trim_end_matches('/').to_string();
        if url.is_empty() {
            return Err(format!("{KEY} needs MACHINE_CONTROL_URL: machines download the bundles from there"));
        }
        Ok(Some(Bundles { url, by_arch }))
    }

    /// `plan` with its Hermes from these bundles. Each must hold the commit the plan
    /// pins: a bundle can't change what machines run, only where it comes from.
    pub fn apply(&self, mut plan: HarnessPlan) -> Result<HarnessPlan, String> {
        for h in plan.harnesses.iter_mut().filter(|h| h.name == "hermes") {
            if let Some(b) = self.by_arch.values().find(|b| b.manifest.commit != h.version) {
                return Err(format!(
                    "{KEY}: {} holds Hermes Agent {}, but machines' plan pins {}: use the Hermes bundle made for this release",
                    b.file.display(),
                    short(&b.manifest.commit),
                    short(&h.version)
                ));
            }
            let downloads = self
                .by_arch
                .iter()
                .map(|(arch, b)| (arch.clone(), Download { url: format!("{}{ROUTE}/{arch}", self.url), sha256: b.sha256.clone() }))
                .collect();
            *h = install::hermes_from_bundles(h, downloads);
        }
        Ok(plan)
    }

    pub fn describe(&self, plan: Option<&HarnessPlan>) -> String {
        let each: Vec<String> = self.by_arch.iter().map(|(arch, b)| format!("{arch} ({})", b.file.display())).collect();
        let mut s = format!("Hermes Agent on machines from botd's Hermes bundles: {}", each.join(", "));
        if !plan.is_some_and(bundled) {
            s.push_str(&format!(" ({KEY} is set, but machines' plan has no Hermes Agent)"));
        }
        s
    }

    /// Whether the file served for `arch` is still the one `sha256` pins.
    pub async fn recheck(&self, arch: &str, sha256: &str) -> Result<(), String> {
        let b = self.by_arch.get(arch).ok_or(format!("botd serves no Hermes bundle for {arch}"))?;
        let file = b.file.clone();
        let got = tokio::task::spawn_blocking(move || sha256_of(&file)).await.map_err(|e| e.to_string())??;
        if got != sha256 {
            return Err(format!("{} has SHA-256 {got} now, not the {sha256} botd checked at start: put the bundle back, or restart botd with the new one", b.file.display()));
        }
        Ok(())
    }
}

/// Whether only an agent that says `CAN_HARNESS_BUNDLES` can install `plan`.
pub fn bundled(plan: &HarnessPlan) -> bool {
    plan.harnesses.iter().any(|h| matches!(h.source, InstallSource::Bundle { .. }))
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
        assert_eq!(Bundles::from_env(&env(vec![url()])).unwrap(), None, "off by default");

        let b = Bundles::from_env(&env(vec![url(), (KEY, format!("{}, {}", x86.display(), arm.display()))])).unwrap().unwrap();
        assert_eq!(b.url, "https://10.0.0.5:8443");
        assert_eq!(b.by_arch.keys().collect::<Vec<_>>(), ["aarch64", "x86_64"]);
        assert_eq!(b.by_arch["x86_64"].sha256, sha);
        let pinned = Bundles::from_env(&env(vec![url(), (KEY, format!("{}={sha}", x86.display()))])).unwrap().unwrap();
        assert_eq!(pinned.by_arch["x86_64"].sha256, sha, "a SHA-256 given instead of the .sha256");

        let refused = |v: String, why: &str| {
            let err = Bundles::from_env(&env(vec![url(), (KEY, v.clone())])).unwrap_err();
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
        let err = Bundles::from_env(&env(vec![(KEY, x86.display().to_string())])).unwrap_err();
        assert!(err.contains("needs MACHINE_CONTROL_URL"), "{err}");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_bundle_changes_where_hermes_comes_from_never_its_commit() {
        let dir = temp("hermes-apply");
        let (x86, sha) = bundle_file(&dir, "x86_64", &pinned_commit());
        let b = Bundles::from_env(&env(vec![("MACHINE_CONTROL_URL", "https://10.0.0.5:8443".into()), (KEY, x86.display().to_string())])).unwrap().unwrap();
        let claude = install::install("claude", None, None).unwrap();
        let hermes = install::install("hermes", None, None).unwrap();
        let plan = install::plan(vec![claude.clone(), hermes.clone()]);
        let out = b.apply(plan.clone()).unwrap();
        assert_eq!(out.harnesses[0], claude, "npm harnesses are left alone");
        assert_eq!(out.harnesses[1].version, hermes.version);
        match &out.harnesses[1].source {
            InstallSource::Bundle { downloads, prefix, bin, readable, after } => {
                assert_eq!(downloads["x86_64"], Download { url: "https://10.0.0.5:8443/v1/hermes/x86_64".into(), sha256: sha });
                assert_eq!(prefix, "/opt/hermes");
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
        let b = Bundles::from_env(&env(vec![("MACHINE_CONTROL_URL", "https://10.0.0.5:8443".into()), (KEY, x86.display().to_string())])).unwrap().unwrap();
        b.recheck("x86_64", &sha).await.unwrap();
        assert!(b.recheck("aarch64", &sha).await.unwrap_err().contains("no Hermes bundle for aarch64"));
        std::fs::write(&x86, b"changed").unwrap();
        assert!(b.recheck("x86_64", &sha).await.unwrap_err().contains("restart botd"));
        let _ = std::fs::remove_dir_all(dir);
    }
}
