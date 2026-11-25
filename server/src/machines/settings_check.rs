//! `botd machines check` (ADR 0294): whether this botd takes an install's machine
//! settings as its start would, before an upgrade puts it in place. A release can move
//! the pins machines install, and botd won't start while MACHINE_HERMES_BUNDLE or
//! MACHINE_HARNESS_BUNDLE names bundles that don't hold them, so `install.sh --offline`
//! runs the new bundle's botd on the old `.env` before it changes anything.

use super::ControlPlane;
use super::enroll::Enrollment;
use crate::secrets::{self, SecretStore};
use std::path::Path;

const USAGE: &str =
    "Usage: botd machines check [--home <dir> | --env-file <file>] [--set NAME=VALUE]...

Whether this botd would take the machine settings it reads at start: the control plane,
machine enrollment, machines' harness plan, and the Hermes and harness bundles it serves
them, each read and checked in full. Starts and changes nothing. It reaches only the
secrets manager SECRETS_BACKEND names, as botd does at start.
  --home <dir>       the installer's layout: settings from <dir>/superbot/.env
                     (sudo -u superbot botd machines check --home /home/superbot)
  --env-file <file>  settings from this file, over botd's environment
  --set NAME=VALUE   a setting over both, as the next .env will have it; may repeat
Exits 1 when botd wouldn't start with them, 2 for a usage error.
Docs: docs/ops/air-gapped.md#upgrading";

/// What botd's start makes of the machine settings in `var` and `store`, with this botd's
/// files in `bin_dir`: the lines it would say, or the error it would stop with, worded and
/// prefixed as there.
pub fn check(
    var: &dyn Fn(&str) -> String,
    store: &dyn SecretStore,
    bin_dir: &Path,
) -> Result<Vec<String>, String> {
    let tiers =
        crate::tiers::Tiers::from_env(|k: &str| var(k)).map_err(|e| format!("Tiers: {e}"))?;
    let mut cp = ControlPlane::from_env(store, |k: &str| var(k))
        .map_err(|e| format!("Control plane: {e}"))?;
    let provider = cp.provider.as_deref().map(|p| p.name());
    // Only the machine CA comes from it, and nothing here signs or keeps a certificate.
    let cipher = secrets::sealed::Cipher::new(&secrets::key::MasterKey::generate());
    let Some(mut e) = Enrollment::from_env(var, store, &cipher, bin_dir)
        .map_err(|e| format!("Machine enrollment: {e}"))?
    else {
        return Ok(vec![match provider {
            Some(p) => format!(
                "Machines: {p}, with no enrollment (MACHINE_CONTROL_URL isn't set), so botd serves them nothing"
            ),
            None => "Machines: off (no control plane)".into(),
        }]);
    };
    let managed: Vec<&str> = tiers
        .managed_defaults()
        .into_iter()
        .filter_map(|h| crate::adapters::get(h).map(|a| a.bin()))
        .collect();
    e.upkeep
        .default_to(&managed)
        .map_err(|err| format!("Machine enrollment: {err}"))?;
    let mut out = vec![
        format!(
            "Machines: {}, enrolling at {}",
            provider.unwrap_or("no control plane"),
            e.url
        ),
        format!("Machine upkeep: {}", e.upkeep.describe()),
    ];
    for b in [&e.upkeep.harness_bundle, &e.upkeep.hermes]
        .into_iter()
        .flatten()
    {
        out.extend(b.holdings().lines().map(String::from));
    }
    if let Some(plan) = &e.upkeep.plan {
        out.push(
            super::hermes_serve::from_where(plan, "botd's bundles")
                .trim_end()
                .into(),
        );
    }
    cp.enroll_with(e)
        .map_err(|e| format!("Machine enrollment: {e}"))?;
    Ok(out)
}

struct Args<'a> {
    home: Option<&'a str>,
    env_file: Option<&'a str>,
    set: Vec<(&'a str, &'a str)>,
}

fn parse<'a>(rest: &[&'a str]) -> Result<Args<'a>, String> {
    let mut a = Args {
        home: None,
        env_file: None,
        set: Vec::new(),
    };
    let mut it = rest.iter();
    while let Some(&flag) = it.next() {
        let v = *it.next().ok_or(format!("{flag} needs a value\n{USAGE}"))?;
        match flag {
            "--home" => a.home = Some(v),
            "--env-file" => a.env_file = Some(v),
            "--set" => {
                let (k, val) = v.split_once('=').ok_or(format!(
                    "--set takes NAME=VALUE, not \"{}\"\n{USAGE}",
                    crate::audit::clip(v, 40)
                ))?;
                if k.is_empty()
                    || !k
                        .bytes()
                        .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == b'_')
                {
                    return Err(format!(
                        "--set: \"{}\" isn't a setting's name\n{USAGE}",
                        crate::audit::clip(k, 40)
                    ));
                }
                a.set.push((k, val));
            }
            _ => return Err(format!("Unknown option {flag}\n{USAGE}")),
        }
    }
    if a.home.is_some() && a.env_file.is_some() {
        return Err(format!("Use --home or --env-file, not both\n{USAGE}"));
    }
    Ok(a)
}

/// `botd machines check ...`: prints what botd would say of its machine settings and
/// returns 0, 1 if it wouldn't start with them (or they can't be read), or 2 for a usage
/// error.
pub fn cli(args: &[String]) -> i32 {
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let Some((&"check", rest)) = args.split_first() else {
        eprintln!("{USAGE}");
        return 2;
    };
    let a = match parse(rest) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("{e}");
            return 2;
        }
    };
    let s = match crate::support_check::Settings::load(a.home, a.env_file) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("botd machines: {e}");
            return 1;
        }
    };
    match s.source()["envFile"].as_str() {
        Some(f) => println!("Settings: {f}, over botd's environment"),
        None => println!("Settings: botd's environment"),
    }
    for (k, _) in &a.set {
        println!("Settings: {k} as given with --set");
    }
    // Everything below reads the process environment, as botd's start does under systemd's
    // EnvironmentFile. This runs before botd starts anything else that reads it.
    for (k, v) in s
        .vars()
        .into_iter()
        .chain(a.set.iter().map(|(k, v)| (k.to_string(), v.to_string())))
    {
        unsafe { std::env::set_var(k, v) };
    }
    if let Some(dir) = a
        .home
        .map(|h| Path::new(h).join("superbot"))
        .filter(|d| d.is_dir())
    {
        let _ = std::env::set_current_dir(dir);
    }
    let var = |k: &str| {
        std::env::var(k)
            .ok()
            .filter(|v| !v.is_empty())
            .unwrap_or_default()
    };
    let bin_dir = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(Path::to_path_buf))
        .unwrap_or_default();
    let process = secrets::env::EnvStore::process();
    let r = secrets::external::from_env(&var, &process)
        .map_err(|e| format!("Secrets backend: {e}"))
        .and_then(|x| match x {
            Some(x) => x.check().map(|_| Some(x)).map_err(|e| {
                format!("Secrets backend: {e}. botd won't start without its secrets (ADR 0125).")
            }),
            None => Ok(None),
        })
        .and_then(|external| {
            let shared = external.map(secrets::external::Shared);
            let store = secrets::external::Layered(
                std::iter::once(&process as &dyn SecretStore)
                    .chain(shared.as_ref().map(|s| s as &dyn SecretStore))
                    .collect(),
            );
            check(&var, &store, &bin_dir)
        });
    match r {
        Ok(lines) => {
            for l in lines {
                println!("{l}");
            }
            println!("botd would start with these machine settings.");
            0
        }
        Err(e) => {
            println!("botd wouldn't start with these settings: {e}");
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapters::install;
    use crate::machines::hermes_bundle::standin;
    use crate::secrets::env::EnvStore;
    use sha2::{Digest, Sha256};
    use std::path::PathBuf;

    fn temp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("superbot-msc-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn pinned_commit() -> String {
        install::install("hermes", None, None).unwrap().version
    }

    /// A stand-in Hermes bundle for x86_64 at `commit`, with its `.sha256` beside it.
    fn hermes_file(dir: &Path, tag: &str, commit: &str) -> PathBuf {
        hermes_file_for(dir, tag, commit, "x86_64")
    }

    fn hermes_file_for(dir: &Path, tag: &str, commit: &str, arch: &str) -> PathBuf {
        let name = format!("superbot-hermes-{tag}-{arch}");
        let body = standin::bundle(
            &name,
            &[
                (
                    "MANIFEST",
                    standin::manifest(commit, arch, "/opt/hermes").into_bytes(),
                ),
                ("hermes.tar", standin::tree("#!/bin/sh\necho hermes\n")),
            ],
            None,
        );
        let f = dir.join(format!("{name}.tar.gz"));
        std::fs::write(&f, &body).unwrap();
        let sha: String = Sha256::digest(&body)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        std::fs::write(
            dir.join(format!("{name}.tar.gz.sha256")),
            format!("{sha}  {name}.tar.gz\n"),
        )
        .unwrap();
        f
    }

    /// The check with these settings, a Linode token among botd's secrets.
    fn run(pairs: &[(&str, String)]) -> Result<Vec<String>, String> {
        let var = |k: &str| {
            pairs
                .iter()
                .rev()
                .find(|(n, _)| *n == k)
                .map(|(_, v)| v.clone())
                .unwrap_or_default()
        };
        let store = EnvStore::fixed(&[("LINODE_TOKEN", "settings-check-token-5b1e")]);
        check(&var, &store, &crate::db::temp_path("settings-check-bin"))
    }

    /// Enrolled Linode machines with `extra` over them.
    fn machines<'a>(extra: &[(&'a str, String)]) -> Vec<(&'a str, String)> {
        let mut v = vec![
            ("MACHINE_REGIONS", "gb-lon".to_string()),
            ("MACHINE_CONTROL_URL", "https://10.0.0.5:8443".to_string()),
            ("MACHINE_HARNESSES", "claude,hermes".to_string()),
        ];
        v.extend(extra.iter().cloned());
        v
    }

    const SHIPPED_TIERS: &str =
        concat!(env!("CARGO_MANIFEST_DIR"), "/../deploy/tiers.example.json");

    #[test]
    fn says_what_machines_get_from_the_settings() {
        let off = check(
            &|_| String::new(),
            &EnvStore::fixed(&[]),
            Path::new("/nonexistent"),
        )
        .unwrap();
        assert_eq!(off, ["Machines: off (no control plane)"]);
        let unenrolled = run(&[("MACHINE_REGIONS", "gb-lon".into())]).unwrap();
        assert!(
            unenrolled[0].contains("Machines: linode, with no enrollment"),
            "{unenrolled:?}"
        );

        let out = run(&machines(&[])).unwrap();
        assert_eq!(
            out[0], "Machines: linode, enrolling at https://10.0.0.5:8443",
            "{out:?}"
        );
        assert!(
            out[1].starts_with("Machine upkeep: harnesses on machines: claude@"),
            "{out:?}"
        );
        assert_eq!(
            out.last().unwrap(),
            "Machines would install claude, hermes from the internet or the operator's mirrors",
            "{out:?}"
        );

        let dir = temp("ok");
        let f = hermes_file(&dir, "v0.23.3", &pinned_commit());
        let out = run(&machines(&[(
            "MACHINE_HERMES_BUNDLE",
            f.display().to_string(),
        )]))
        .unwrap();
        assert!(
            out.iter().any(|l| l.starts_with(&format!(
                "x86_64 Hermes bundle {}: Hermes Agent v0.23.3 (",
                f.display()
            ))),
            "{out:?}"
        );
        assert_eq!(
            out.last().unwrap(),
            "Machines would install hermes from botd's bundles, and claude from the internet or the operator's mirrors",
            "{out:?}"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    // systemd joins a line ending in `\` to the next, so a long list may be split.
    #[test]
    fn a_bundle_list_continued_on_the_next_line_of_env_is_read_as_botd_gets_it() {
        let dir = temp("continued");
        let x = hermes_file_for(&dir, "v0.23.3", &pinned_commit(), "x86_64");
        let a = hermes_file_for(&dir, "v0.23.3", &pinned_commit(), "aarch64");
        let env = crate::support_check::parse_env_file(&format!(
            "MACHINE_HERMES_BUNDLE={},\\\n  {}\n",
            x.display(),
            a.display()
        ));
        let out = run(&machines(&[(
            "MACHINE_HERMES_BUNDLE",
            env["MACHINE_HERMES_BUNDLE"].clone(),
        )]))
        .unwrap();
        for (arch, f) in [("x86_64", &x), ("aarch64", &a)] {
            assert!(
                out.iter()
                    .any(|l| l.starts_with(&format!("{arch} Hermes bundle {}:", f.display()))),
                "{out:?}"
            );
        }
        let _ = std::fs::remove_dir_all(dir);
    }

    // The upgrade this is for: .env names last release's bundle, and this botd pins another commit.
    #[test]
    fn a_bundle_from_another_release_is_refused_as_at_start() {
        let dir = temp("stale");
        let old = hermes_file(&dir, "v0.22.0", &"b".repeat(40));
        let err = run(&machines(&[(
            "MACHINE_HERMES_BUNDLE",
            old.display().to_string(),
        )]))
        .unwrap_err();
        assert!(
            err.starts_with("Machine enrollment: MACHINE_HERMES_BUNDLE"),
            "{err}"
        );
        assert!(
            err.contains("holds Hermes Agent bbbbbbbbbbbb, but machines' plan pins"),
            "{err}"
        );

        // With MACHINE_HARNESSES unset, the plan is the managed tiers' default, as at start.
        let defaulted = run(&machines(&[
            ("MACHINE_HARNESSES", String::new()),
            ("TIERS_FILE", SHIPPED_TIERS.into()),
            ("MACHINE_HERMES_BUNDLE", old.display().to_string()),
        ]))
        .unwrap_err();
        assert!(
            defaulted.contains("holds Hermes Agent bbbbbbbbbbbb"),
            "{defaulted}"
        );
        let none = run(&machines(&[
            ("MACHINE_HARNESSES", "none".into()),
            ("MACHINE_HERMES_BUNDLE", old.display().to_string()),
        ]))
        .unwrap();
        assert!(
            none[1].contains("machines' plan has no Hermes Agent"),
            "nothing to install from it: {none:?}"
        );

        let missing = run(&machines(&[(
            "MACHINE_HERMES_BUNDLE",
            dir.join("superbot-hermes-v0.23.3-x86_64.tar.gz")
                .display()
                .to_string(),
        )]))
        .unwrap_err();
        assert!(
            missing.starts_with("Machine enrollment: MACHINE_HERMES_BUNDLE (")
                && missing.contains("No such file"),
            "{missing}"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn other_settings_botd_refuses_are_said_with_their_area() {
        let err = run(&machines(&[(
            "MACHINE_APT_MIRROR",
            "http://mirror.corp.example/ubuntu".into(),
        )]))
        .unwrap_err();
        assert!(
            err.starts_with("Machine enrollment: MACHINE_APT_MIRROR"),
            "{err}"
        );
        let err = run(&[("MACHINE_REGIONS", String::new())]).unwrap_err();
        assert!(
            err.starts_with("Control plane: MACHINE_REGIONS is needed"),
            "{err}"
        );
        let err = check(
            &|k| {
                if k == "MACHINE_CONTROL_URL" {
                    "https://10.0.0.5:8443".into()
                } else {
                    String::new()
                }
            },
            &EnvStore::fixed(&[]),
            Path::new("/x"),
        )
        .unwrap_err();
        assert!(
            err.starts_with("Machine enrollment: MACHINE_CONTROL_URL needs the control plane"),
            "{err}"
        );
        let err = check(
            &|k| {
                if k == "TIERS_FILE" {
                    "/nonexistent/tiers.json".into()
                } else {
                    String::new()
                }
            },
            &EnvStore::fixed(&[]),
            Path::new("/x"),
        )
        .unwrap_err();
        assert!(err.starts_with("Tiers: "), "{err}");
    }

    #[test]
    fn options() {
        fn p<'a>(
            l: &[&'a str],
        ) -> Result<(Option<&'a str>, Option<&'a str>, Vec<(&'a str, &'a str)>), String> {
            parse(l).map(|a| (a.home, a.env_file, a.set))
        }
        assert_eq!(
            p(&["--home", "/home/sb", "--set", "MACHINE_HERMES_BUNDLE=/a=b"]).unwrap(),
            (
                Some("/home/sb"),
                None,
                vec![("MACHINE_HERMES_BUNDLE", "/a=b")]
            )
        );
        assert_eq!(
            p(&["--set", "MACHINE_HERMES_BUNDLE="]).unwrap().2,
            vec![("MACHINE_HERMES_BUNDLE", "")]
        );
        for (bad, why) in [
            (&["--home", "/h", "--env-file", "/e"][..], "not both"),
            (&["--set", "nope"][..], "NAME=VALUE"),
            (&["--set", "lower=1"][..], "isn't a setting's name"),
            (&["--home"][..], "needs a value"),
            (&["--json", "x"][..], "Unknown option --json"),
        ] {
            assert!(p(bad).unwrap_err().contains(why), "{bad:?}");
        }
        assert_eq!(cli(&["nope".into()]), 2);
        assert_eq!(cli(&["check".into(), "--bogus".into(), "1".into()]), 2);
    }
}
