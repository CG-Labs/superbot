//! Each harness's CLI as a user's machine installs it (ADR 0039): its npm package or
//! installer script, pinned to an exact version and, where the source has one, a
//! checksum. The machine agent installs whatever botd sends and knows none of this.
//! The Dockerfile and deploy/install.sh install the same CLIs on a server.
//! The `harness-e2e` workflow tests approvals through exactly these pins
//! (`deploy/install-harness-clis.sh` reads them from here, ADR 0057), so a bump runs it.

use crate::machines::wire::{CAN_INSTALL_AFTER, Download, HarnessInstall, HarnessPlan, InstallSource, NodeRuntime};

enum Source {
    /// `integrity`: the registry's SHA-512 of the package's own tarball. npm checks
    /// its dependencies (Claude Code's and Codex's native builds among them) against
    /// the registry's hashes.
    Npm { package: &'static str, integrity: &'static str },
    /// Hermes Agent's own installer at `version` (a commit), checked against `sha256`.
    /// `tag` is the stable release that commit is; `deploy/hermes-pin.sh` checks it
    /// upstream and moves all three together (ADR 0075).
    Hermes { tag: &'static str, sha256: &'static str },
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
    // The Dockerfile and install.sh pin the same commit; change all three with
    // `deploy/hermes-pin.sh bump` (ADR 0075).
    Pin {
        bin: "hermes",
        version: "caafe5389ae585ef77387a962aee05b1bcf17029",
        source: Source::Hermes { tag: "v0.23.3", sha256: "c73dad4dcf7c9ecadb98578e28cc763d23d7be3fa1b513545319038795493214" },
    },
];

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
    HarnessPlan { node: npm.then(node), harnesses, ..Default::default() }
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

/// How an admin installs `bin` on this server, for a Bot that says it isn't there.
pub fn server_hint(bin: &str) -> String {
    match PINS.iter().find(|p| p.bin == bin).map(|p| &p.source) {
        Some(Source::Hermes { .. }) => "`deploy/install.sh --with-hermes` (offline, with `--hermes-bundle`), or hermes in SUPERBOT_HARNESSES for Docker".into(),
        Some(Source::Npm { .. }) => server_update(bin).map(|c| format!("`{c}`")).unwrap_or_default(),
        None => format!("put {bin} on botd's PATH"),
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
        Source::Hermes { tag, sha256 } => {
            if version.len() != 40 || !version.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
                return Err(format!("{bin}@{version}: give a full commit, like {} (release {tag})", pin.version));
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
                bin: HERMES_SHARED_BIN.into(),
                after: Some(HERMES_SHARE.into()),
            }
        }
    };
    Ok(HarnessInstall { name: bin.into(), version: version.into(), source })
}

/// Makes one Hermes install's environment every Bot's (ADR 0072). The Dockerfile,
/// deploy/install.sh and deploy/install-harness-clis.sh run the same file.
pub const HERMES_SHARE: &str = include_str!("../../../deploy/hermes-share.sh");
/// Where `HERMES_SHARE` leaves the `hermes` Bots run, under the installer's HOME.
const HERMES_SHARED_BIN: &str = ".hermes/superbot/hermes";
/// Hermes's own launcher there, which runs a Bot's own environment.
const HERMES_LAUNCHER: &str = ".hermes/hermes-agent/.hermes/bin/hermes";

/// Where a Hermes bundle's tree runs, and only there (ADR 0200).
pub const HERMES_PREFIX: &str = "/opt/hermes";
/// What other accounts run in it: the checkout, its installs, its tools and uv's
/// Python, as `deploy/install.sh` opens them. Hermes's own data root stays closed.
const HERMES_READABLE: [&str; 4] = [".hermes/hermes-agent", ".hermes/installs", ".hermes/tools", ".local/share/uv"];

/// `h`, Hermes at its commit, from Hermes bundles botd serves (ADR 0210) instead of
/// its installer: `downloads` by arch, each pinned to its bundle's SHA-256.
pub fn hermes_from_bundles(h: &HarnessInstall, downloads: std::collections::BTreeMap<String, Download>) -> HarnessInstall {
    HarnessInstall {
        source: InstallSource::Bundle {
            downloads,
            prefix: HERMES_PREFIX.into(),
            bin: HERMES_SHARED_BIN.into(),
            readable: HERMES_READABLE.map(String::from).into(),
            after: Some(HERMES_SHARE.into()),
        },
        ..h.clone()
    }
}

/// `plan` as an agent that says `can` takes it: one that can't run an `after` script
/// installs Hermes with its own launcher, and each Bot builds its own environment.
pub fn plan_for(plan: &HarnessPlan, can: &[String]) -> HarnessPlan {
    let mut plan = plan.clone();
    if can.iter().any(|c| c == CAN_INSTALL_AFTER) {
        return plan;
    }
    for h in &mut plan.harnesses {
        if let InstallSource::Script { bin, after, .. } = &mut h.source
            && after.take().is_some()
            && bin == HERMES_SHARED_BIN
        {
            *bin = HERMES_LAUNCHER.into();
        }
    }
    plan
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
        assert!(install("hermes", Some("main"), None).unwrap_err().contains(" (release v"), "names the pinned release");
        assert!(install("hermes", Some(&"b".repeat(40)), None).is_err(), "a new commit needs its installer's hash");
        assert!(install("hermes", Some(&"b".repeat(40)), Some(&"c".repeat(64))).is_ok());
        let p = plan(vec![c, h.clone()]);
        assert!(crate::machines::tools::check(&p).is_ok(), "{:?}", crate::machines::tools::check(&p));
        assert!(p.node.is_some_and(|n| n.downloads.contains_key("x86_64") && n.downloads.contains_key("aarch64")));
        assert!(plan(vec![h]).node.is_none(), "Hermes alone needs no Node.js");
    }

    #[test]
    fn agents_without_after_get_the_plan_they_always_did() {
        let p = plan(vec![install("claude", None, None).unwrap(), install("hermes", None, None).unwrap()]);
        let hermes = |p: &HarnessPlan| match &p.harnesses[1].source {
            InstallSource::Script { bin, after, .. } => (bin.clone(), after.is_some()),
            _ => unreachable!(),
        };
        assert_eq!(hermes(&p), (HERMES_SHARED_BIN.into(), true));
        let can = vec![CAN_INSTALL_AFTER.to_string()];
        assert_eq!(plan_for(&p, &can).id(), p.id());
        let old = plan_for(&p, &[]);
        assert_eq!(hermes(&old), (HERMES_LAUNCHER.into(), false));
        let json = serde_json::to_string(&old).unwrap();
        assert!(!json.contains("\"after\""), "an old agent denies unknown fields: {json}");
        assert_eq!(old.harnesses[0], p.harnesses[0]);
        assert!(crate::machines::tools::check(&old).is_ok());
    }

    /// `HERMES_SHARE` against a fake install laid out as Hermes lays one out.
    #[test]
    fn bots_share_one_hermes_environment_and_keep_their_own_records() {
        use sha2::{Digest, Sha256};
        use std::os::unix::fs::PermissionsExt;
        use std::path::Path;
        use std::process::Command;
        let dir = crate::db::temp_path("hermes-share");
        std::fs::create_dir_all(&dir).unwrap();
        let dir = std::fs::canonicalize(dir).unwrap();
        let write = |p: &Path, s: &str| {
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, s).unwrap();
        };
        let mode = |p: &Path, m: u32| std::fs::set_permissions(p, std::fs::Permissions::from_mode(m)).unwrap();
        let home = dir.join("install");
        let root = home.join(".hermes");
        let launcher = root.join("hermes-agent/.hermes/bin/hermes");
        write(&launcher, "#!/bin/sh\n[ \"$1\" = pm ] && { echo \"$*\" >\"$0.pm\"; exit 0; }\necho \"lazy=${HERMES_DISABLE_LAZY_INSTALLS:-} $*\"\n");
        mode(&launcher, 0o755);
        let checkout = root.join("hermes-agent").display().to_string();
        let key: String = Sha256::digest(&checkout).iter().take(8).map(|b| format!("{b:02x}")).collect();
        let state = root.join("installs").join(&key);
        let facts = |g: &str| format!("{{\n  \"environment\": \"{}/environments/{g}/venv\",\n  \"python\": \"3.12\"\n}}\n", state.display());
        write(&state.join("facts.json"), &facts("g2"));
        write(&state.join("inputs/uv.lock.stamp"), "a");
        write(&state.join("environments/g2/venv/bin/python"), "");
        write(&state.join("environments/g2/.lease-managed"), "");
        write(&state.join("environments/g2/.leases/old"), "");
        write(&state.join("environments/g1/venv/bin/python"), "");
        let script = dir.join("hermes-share.sh");
        write(&script, HERMES_SHARE);
        let run = |bin: &Path, env: &[(&str, &Path)], args: &[&str]| {
            let out = Command::new("sh")
                .arg(bin)
                .args(args)
                .env_clear()
                .env("PATH", "/usr/bin:/bin")
                .envs(env.iter().map(|(k, v)| (*k, v.as_os_str())))
                .output()
                .unwrap();
            assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
            String::from_utf8_lossy(&out.stdout).trim().to_string()
        };

        let wrapper = run(&script, &[("HOME", &home)], &[]);
        assert_eq!(Path::new(&wrapper), root.join("superbot/hermes"));
        assert_eq!(home.join(HERMES_SHARED_BIN), root.join("superbot/hermes"));
        assert_eq!(home.join(HERMES_LAUNCHER), launcher);
        let wrapper = Path::new(&wrapper).to_path_buf();
        assert!(!state.join("environments/g1").exists(), "an earlier install's environment goes");
        assert!(state.join("environments/g2/venv").exists());
        assert!(!state.join("environments/g2/.lease-managed").exists(), "Bots take no leases, so Hermes never collects it");
        assert!(!state.join("environments/g2/.leases").exists());
        let pm = std::fs::read_to_string(launcher.with_extension("pm")).unwrap_or_default();
        assert_eq!(pm.trim(), "pm install --extra anthropic", "the installer adds what Anthropic Messages endpoints need");

        assert_eq!(run(&wrapper, &[], &["--version"]), "lazy= --version", "no Bot home: just Hermes");
        assert_eq!(run(&wrapper, &[("HERMES_HOME", &root)], &["x"]), "lazy= x", "the install's own home");

        for s in [&state, &state.join("environments"), &state.join("inputs")] {
            mode(s, 0o555);
        }
        let bot = dir.join("bots/a/hermes");
        assert_eq!(run(&wrapper, &[("HERMES_HOME", &bot)], &["chat"]), "lazy=1 chat");
        let own = bot.join("installs").join(&key);
        assert_eq!(std::fs::read_to_string(own.join("facts.json")).unwrap(), facts("g2"));
        assert_eq!(std::fs::read_link(own.join("environments")).unwrap(), state.join("environments"));
        assert_eq!(std::fs::read_to_string(own.join("inputs/uv.lock.stamp")).unwrap(), "a");
        assert_eq!(std::fs::metadata(&own).unwrap().permissions().mode() & 0o777, 0o700);
        assert_eq!(std::fs::read_to_string(bot.join("config.yaml")).unwrap(), "", "Hermes reads fallbacks only with one");
        assert_eq!(std::fs::metadata(bot.join("config.yaml")).unwrap().permissions().mode() & 0o777, 0o600);
        write(&bot.join("config.yaml"), "model: x\n");
        run(&wrapper, &[("HERMES_HOME", &bot)], &[]);
        assert_eq!(std::fs::read_to_string(bot.join("config.yaml")).unwrap(), "model: x\n", "a Bot's own settings stay");

        let old = dir.join("bots/b/hermes");
        write(&old.join("installs").join(&key).join("environments/g0/venv/lib/big"), "x");
        run(&wrapper, &[("HERMES_HOME", &old)], &[]);
        let link = old.join("installs").join(&key).join("environments");
        assert_eq!(std::fs::read_link(link).unwrap(), state.join("environments"), "a Bot's own old environment goes");

        mode(&state, 0o755);
        write(&state.join("facts.json"), &facts("g3"));
        run(&wrapper, &[("HERMES_HOME", &bot)], &[]);
        assert_eq!(std::fs::read_to_string(own.join("facts.json")).unwrap(), facts("g3"), "a new install's record follows");
        for s in [&state.join("environments"), &state.join("inputs")] {
            mode(s, 0o755);
        }
        let _ = std::fs::remove_dir_all(dir);
    }

    /// The Dockerfile and deploy/install.sh install the Hermes commit machines do, and
    /// name the same stable tag (ADR 0075). `deploy/hermes-pin.sh verify` checks the
    /// tag against upstream.
    #[test]
    fn hermes_is_pinned_to_one_stable_release_everywhere() {
        let pin = PINS.iter().find(|p| p.bin == "hermes").unwrap();
        let Source::Hermes { tag, .. } = pin.source else { unreachable!() };
        let core = tag.strip_prefix('v').unwrap_or_default();
        assert!(exact(core) && !core.contains('-'), "{tag}: a stable vMAJOR.MINOR.PATCH tag, never a canary");
        let repo = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        for (file, line) in [("Dockerfile", "ARG HERMES_COMMIT="), ("deploy/install.sh", "HERMES_COMMIT=${HERMES_COMMIT:-")] {
            let text = std::fs::read_to_string(repo.join(file)).unwrap();
            let commit = text.lines().find_map(|l| l.strip_prefix(line)).unwrap_or_else(|| panic!("{file}: no {line}"));
            assert_eq!(commit.trim_end_matches('}'), pin.version, "{file}");
            assert!(text.contains(&format!("the commit of tag {tag} ")), "{file} names another tag than {tag}");
        }
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
