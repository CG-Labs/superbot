//! Each harness's CLI as a user's machine installs it (ADR 0039): its npm package or
//! installer script, pinned to an exact version and, where the source has one, a
//! checksum. The machine agent installs whatever botd sends and knows none of this.
//! The Dockerfile and deploy/install.sh install the same CLIs on a server.
//! The `harness-e2e` workflow tests approvals through exactly these pins
//! (`deploy/install-harness-clis.sh` reads them from here, ADR 0057), so a bump runs it.

use crate::machines::wire::{Download, HarnessInstall, HarnessPlan, InstallSource, NodeRuntime};

enum Source {
    /// `integrity`: the registry's SHA-512 of the package's own tarball. npm checks
    /// its dependencies (Claude Code's and Codex's native builds among them) against
    /// the registry's hashes.
    Npm { package: &'static str, integrity: &'static str },
    /// Hermes Agent's own installer at `version` (a commit), checked against `sha256`.
    Hermes { sha256: &'static str },
}

struct Pin {
    bin: &'static str,
    version: &'static str,
    source: Source,
}

const PINS: [Pin; 4] = [
    Pin {
        bin: "claude",
        version: "2.1.329",
        source: Source::Npm {
            package: "@anthropic-ai/claude-code",
            integrity: "sha512-WQ7RY331gsODjOoDBbeG1fjMfKY1Ur9yxWAOI9SgdLZvqA9sAREaezXt7e3uNbHlgjVAZg1IqlJT1J7WKViEFA==",
        },
    },
    Pin {
        bin: "codex",
        version: "0.171.0",
        source: Source::Npm {
            package: "@openai/codex",
            integrity: "sha512-1IOFzL2Xg86tLdw6kDo3GoKbkQENgQi7TI6rlEvN132R7ngSw7SNOIQoTcnKzSZZ8kf9N9GynCweSoaFbqk2Eg==",
        },
    },
    Pin {
        bin: "pi",
        version: "1.5.2",
        source: Source::Npm {
            package: "@earendil-works/pi-coding-agent",
            integrity: "sha512-mUWI04rqF1Vd/m1q+Ps1XeWsTXEVvRUnsmRa83I3Dzua0Tx5bYS93imeqtIfrXf7PkkaR6ERz+AuQhIJlom5yA==",
        },
    },
    // The commit of tag v0.23.2, as the Dockerfile and install.sh pin it.
    Pin {
        bin: "hermes",
        version: "ae2a81ccc00e9b7c06301523e5bb09608397149c",
        source: Source::Hermes { sha256: "c73dad4dcf7c9ecadb98578e28cc763d23d7be3fa1b513545319038795493214" },
    },
];

/// Run after Hermes's installer on a machine, as on a server: every Bot then shares the
/// install's one dependency environment instead of building its own (ADR 0072).
const HERMES_SEAL: &str = include_str!("../../../deploy/hermes-seal.sh");

/// Node.js for the npm harnesses: the LTS line the server image uses, checked
/// against nodejs.org's SHASUMS256.txt.
const NODE: &str = "22.23.5";
const NODE_SHA256: [(&str, &str, &str); 2] = [
    ("x86_64", "x64", "cdeb8670a0c81f51b4dc4ac61919f9b1ad917b304bf8221eb939570663d240f8"),
    ("aarch64", "arm64", "2babb9eb5264860d540849f4b064a6fbdebcdc323657d9d382ce23d313fd5e09"),
];

pub fn node() -> NodeRuntime {
    NodeRuntime {
        version: NODE.into(),
        downloads: NODE_SHA256
            .iter()
            .map(|(arch, name, sha256)| {
                let url = format!("https://nodejs.org/dist/v{NODE}/node-v{NODE}-linux-{name}.tar.xz");
                (arch.to_string(), Download { url, sha256: sha256.to_string() })
            })
            .collect(),
    }
}

/// The plan for `harnesses`, with Node.js when one is an npm package.
pub fn plan(harnesses: Vec<HarnessInstall>) -> HarnessPlan {
    let npm = harnesses.iter().any(|h| matches!(h.source, InstallSource::Npm { .. }));
    HarnessPlan { node: npm.then(node), harnesses }
}

/// How an admin puts `bin` at its pin on a server, for an npm harness: what botd
/// suggests when a guarded run's harness there is too old (ADR 0059).
pub fn server_update(bin: &str) -> Option<String> {
    let pin = PINS.iter().find(|p| p.bin == bin)?;
    match pin.source {
        Source::Npm { package, .. } => Some(format!("npm install -g {package}@{}", pin.version)),
        Source::Hermes { .. } => None,
    }
}

/// Whether `v` is an exact semver version, not a tag or range.
fn exact(v: &str) -> bool {
    let (core, pre) = v.split_once('-').map_or((v, None), |(c, p)| (c, Some(p)));
    let parts: Vec<&str> = core.split('.').collect();
    parts.len() == 3
        && parts.iter().all(|p| !p.is_empty() && p.len() <= 9 && p.bytes().all(|b| b.is_ascii_digit()))
        && pre.is_none_or(|p| !p.is_empty() && p.len() <= 40 && p.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.'))
}

/// `bin` as its machine install: the pinned version, or `version` with `checksum`.
/// An npm harness at another version may go without a checksum (the registry's own
/// hashes still apply); Hermes's installer may not.
pub fn install(bin: &str, version: Option<&str>, checksum: Option<&str>) -> Result<HarnessInstall, String> {
    let pin = PINS
        .iter()
        .find(|p| p.bin == bin)
        .ok_or(format!("\"{bin}\" isn't a harness: use {}", PINS.map(|p| p.bin).join(", ")))?;
    let version = version.unwrap_or(pin.version);
    let pinned = version == pin.version;
    let source = match &pin.source {
        Source::Npm { package, integrity } => {
            if !exact(version) {
                return Err(format!("{bin}@{version}: give an exact version, like {}", pin.version));
            }
            let integrity = match checksum {
                Some(c) => Some(c.to_string()),
                None if pinned => Some(integrity.to_string()),
                None => None,
            };
            InstallSource::Npm { package: package.to_string(), integrity }
        }
        Source::Hermes { sha256 } => {
            if version.len() != 40 || !version.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
                return Err(format!("{bin}@{version}: give a full commit, like {}", pin.version));
            }
            let sha256 = match checksum {
                Some(c) => c.to_string(),
                None if pinned => sha256.to_string(),
                None => return Err(format!("{bin}@{version}: give the SHA-256 of its scripts/install.sh too ({bin}@<commit>=<sha256>)")),
            };
            InstallSource::Script {
                url: format!("https://raw.githubusercontent.com/NousResearch/hermes-agent/{version}/scripts/install.sh"),
                sha256,
                args: ["--non-interactive", "--skip-browser", "--skip-computer-use", "--commit", version]
                    .map(String::from)
                    .into(),
                bin: ".hermes/hermes-agent/.hermes/bin/hermes".into(),
                after: Some(HERMES_SEAL.into()),
            }
        }
    };
    Ok(HarnessInstall { name: bin.into(), version: version.into(), source })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapters;

    #[test]
    fn every_adapter_has_a_pin_and_every_pin_an_adapter() {
        let bins: Vec<&str> = PINS.iter().map(|p| p.bin).collect();
        assert_eq!(bins, crate::machines::wire::HARNESS_BINS);
        for b in bins {
            assert_eq!(adapters::get(b).map(|a| a.bin()), Some(b), "{b}");
        }
    }

    #[test]
    fn every_machine_login_word_is_one_an_agent_takes() {
        use crate::machines::wire;
        let mut words: Vec<&str> = wire::HARNESS_BINS
            .iter()
            .filter_map(|b| adapters::get(b)?.machine_login())
            .flat_map(|l| l.args.iter().copied())
            .collect();
        words.sort();
        words.dedup();
        let mut known = wire::LOGIN_WORDS.to_vec();
        known.sort();
        assert_eq!(words, known);
    }

    #[test]
    fn pins_are_exact_and_overrides_are_checked() {
        let c = install("claude", None, None).unwrap();
        assert_eq!(c.version, "2.1.329");
        assert!(matches!(&c.source, InstallSource::Npm { integrity: Some(i), .. } if i.starts_with("sha512-")));
        let other = install("codex", Some("0.172.0"), None).unwrap();
        assert!(matches!(other.source, InstallSource::Npm { integrity: None, .. }), "another version has no pinned hash");
        for (bin, v) in [("claude", "latest"), ("claude", "^2.1.0"), ("claude", "2.1"), ("pi", "1.5.2 "), ("hermes", "v0.23.2"), ("nope", "1.0.0")] {
            assert!(install(bin, Some(v), None).is_err(), "{bin}@{v}");
        }
        assert!(install("claude", Some("2.2.0-beta.1"), None).is_ok());
        let h = install("hermes", None, None).unwrap();
        assert!(matches!(&h.source, InstallSource::Script { url, args, .. } if url.contains(&h.version) && args.contains(&h.version)));
        assert!(install("hermes", Some(&"b".repeat(40)), None).is_err(), "a new commit needs its installer's hash");
        assert!(install("hermes", Some(&"b".repeat(40)), Some(&"c".repeat(64))).is_ok());
        let p = plan(vec![c, h.clone()]);
        assert!(crate::machines::tools::check(&p).is_ok(), "{:?}", crate::machines::tools::check(&p));
        assert!(p.node.is_some_and(|n| n.downloads.contains_key("x86_64") && n.downloads.contains_key("aarch64")));
        assert!(plan(vec![h]).node.is_none(), "Hermes alone needs no Node.js");
    }

    #[test]
    fn hermes_is_sealed_after_install_where_the_agent_can() {
        use crate::machines::wire;
        let p = plan(vec![install("hermes", None, None).unwrap()]);
        let after = |p: &HarnessPlan| match &p.harnesses[0].source {
            InstallSource::Script { after, .. } => after.clone(),
            _ => unreachable!(),
        };
        assert!(after(&p).is_some_and(|a| a.contains("updateMechanism")));
        assert_eq!(after(&p.for_agent(&[wire::CAN_SCRIPT_AFTER.into()])), after(&p));
        let old = p.for_agent(&[]);
        assert_eq!(after(&old), None, "an older agent would refuse the field");
        let json = serde_json::to_value(&old).unwrap();
        assert!(json["harnesses"][0]["source"].get("after").is_none());
        assert!(crate::machines::tools::check(&p).is_ok() && crate::machines::tools::check(&old).is_ok());
    }

    #[test]
    fn pins_run_the_hooks_their_adapters_need() {
        for p in &PINS {
            if let Some(min) = adapters::get(p.bin).unwrap().hooks_since() {
                assert_eq!(adapters::version::assess(min, Ok(p.version.into())), Ok(()), "{}", p.bin);
            }
        }
        assert_eq!(server_update("codex"), Some("npm install -g @openai/codex@0.171.0".into()));
        assert_eq!(server_update("hermes"), None);
    }

    /// The pins, really installed: `cargo test -- --ignored real_harness_installs`.
    /// Needs the internet and about 1 GB.
    #[tokio::test]
    #[ignore]
    async fn real_harness_installs() {
        let dir = crate::db::temp_path("real-tools");
        let tools = crate::machines::tools::Tools::new(dir.clone(), None).unwrap();
        let p = plan(["claude", "codex", "pi"].map(|b| install(b, None, None).unwrap()).into());
        tools.set_plan(p).unwrap();
        let worker = tokio::spawn(tools.clone().work());
        let done = |s: &crate::machines::wire::HarnessStatus| s.state != "queued" && s.state != "installing";
        while !tools.report().1.values().all(done) {
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        }
        worker.abort();
        for (name, st) in tools.report().1 {
            assert_eq!(st.state, "installed", "{name}: {:?}", st.error);
            let out = std::process::Command::new(dir.join("bin").join(&name))
                .arg("--version")
                .env("PATH", dir.join("bin"))
                .output()
                .unwrap();
            assert!(out.status.success(), "{name}: {}", String::from_utf8_lossy(&out.stderr));
            println!("{name}: {}", String::from_utf8_lossy(&out.stdout).trim());
        }
    }
}
