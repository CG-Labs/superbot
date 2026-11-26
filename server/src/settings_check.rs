//! `botd settings check` (ADR 0310): whether this botd would start with an install's
//! settings, all those its start reads and refuses before it opens the database, not only
//! machines' (ADR 0294). A release can tighten a setting it used to take, and botd won't
//! start while one is refused, so `install.sh --offline` runs the new bundle's botd on the
//! old `.env` before it changes anything.

use crate::machines::settings_check as machines_check;
use crate::secrets::SecretStore;
use crate::{
    accounts, acl, adapters, audit, audit_checkpoint, audit_export, backup_encryption, billing,
    billing_mail, chromium, database_encryption, evidence, handover, health_history, license,
    machines, mfa, notify, obs, paths, plans, retention, runner, scim, screen, server_backups,
    signin_watch, signups, slots, sso, status, teams, tiers, users,
};
use std::path::Path;

const USAGE: &str =
    "Usage: botd settings check [--home <dir> | --env-file <file>] [--set NAME=VALUE]...

Whether this botd would start with an install's settings: each one its start reads and
refuses before it opens the database, read and checked in full, machines' among them
(botd machines check). Starts nothing and changes no file, though, as botd's start does,
it may make DATA_DIR, WORKSPACE_DIR and regional chat stores' folders and keep the last
botd's alone (0700). It reaches only the secrets manager SECRETS_BACKEND names, as botd
does at start.
  --home <dir>       the installer's layout: settings from <dir>/superbot/.env
                     (sudo -u superbot botd settings check --home /home/superbot)
  --env-file <file>  settings from this file, over botd's environment
  --set NAME=VALUE   a setting over both, as the next .env will have it; may repeat
Exits 1 when botd wouldn't start with them, 2 for a usage error.
Docs: docs/ops/air-gapped.md#upgrading";

/// What botd's start reads but this leaves to others, each with why.
pub const NOT_CHECKED: &str = "Not checked here: the database and master key (botd support check), the license (botd license check), \
     screens' ports (they depend on Xvfb being installed), and listening ports, which the running botd holds";

/// One area of botd's settings, as its start judges it.
#[derive(Debug, PartialEq)]
pub enum Verdict {
    Ok,
    /// What botd would stop with, worded as its start logs it.
    Refused(String),
    /// Not judged, as it reads an area refused before it.
    Skipped(String),
}

#[derive(Debug, Default)]
pub struct Report {
    pub areas: Vec<(&'static str, Verdict)>,
    /// What `botd machines check` says of machines, when they were judged.
    pub machines: Vec<String>,
}

impl Report {
    /// What botd would stop with, the first being what its start would say first.
    pub fn refusals(&self) -> Vec<&str> {
        self.areas
            .iter()
            .filter_map(|(_, v)| match v {
                Verdict::Refused(e) => Some(e.as_str()),
                _ => None,
            })
            .collect()
    }

    /// `r` as `area`, logged as botd's start logs it: `prefixed`, as `<area>: <error>`.
    fn judge<T>(&mut self, area: &'static str, prefixed: bool, r: Result<T, String>) -> Option<T> {
        match r {
            Ok(v) => {
                self.areas.push((area, Verdict::Ok));
                Some(v)
            }
            Err(e) => {
                let e = if prefixed { format!("{area}: {e}") } else { e };
                self.areas.push((area, Verdict::Refused(e)));
                None
            }
        }
    }

    fn skip(&mut self, area: &'static str, needs: &str) {
        self.areas.push((area, Verdict::Skipped(format!("reads {needs}, refused above"))));
    }
}

/// What botd's start makes of the settings in `var`, with secrets from `store` and
/// AUTH_PASSWORD from `process` (the environment alone, as at start), and this botd's files
/// in `bin_dir`. `names` lists every setting set, for those botd finds by name.
pub fn check(var: &dyn Fn(&str) -> String, names: &[String], process: &dyn SecretStore, store: &dyn SecretStore, bin_dir: &Path) -> Report {
    let or = |k: &str, d: &str| Some(var(k)).filter(|v| !v.is_empty()).unwrap_or_else(|| d.into());
    let mut r = Report::default();
    r.judge("Observability", true, obs::Settings::from_env(var, store));
    r.judge("Status page", false, status::Page::parse(&var("STATUS_PAGE")));
    let break_glass = r.judge("Break-glass sign-in", false, users::break_glass_flag(&var("AUTH_BREAK_GLASS")));
    r.judge("Two-factor sign-in", false, mfa::policy_flag(&var("AUTH_MFA")));
    let sessions = r.judge("Sessions", false, users::SessionConfig::from_env(&var("SESSION_IDLE_TIMEOUT"), &var("SESSION_MAX_AGE")));
    r.judge("Sign-in alerts", true, signin_watch::Settings::from_env(var));
    let sso = r.judge("SSO", true, sso::Sso::from_vars(&|k| Some(var(k))));
    let signups = r.judge("Sign-ups", true, signups::Signups::from_env(store, &var("SIGNUPS"), &var("TURNSTILE_SITE_KEY")));
    let control_plane = r.judge("Control plane", true, machines::ControlPlane::from_env(store, var));
    let shared_bots = match &control_plane {
        Some(cp) => r.judge("Shared Bots", true, acl::SharedBots::parse(&var("SHARED_BOTS"), cp.routing != machines::route::Routing::Off)),
        None => {
            r.skip("Shared Bots", "the control plane");
            None
        }
    };
    r.judge("Teams", true, teams::Settings::from_env(var));
    r.judge("Routines on enable", false, handover::resume_on_enable(&var("ROUTINES_ON_ENABLE")));
    let scim = r.judge("SCIM", true, scim::Scim::from_env(&var("SCIM"), &var("SCIM_DEFAULT_ROLE"), &var("SCIM_GROUPS"), &var("SCIM_GROUP_ROLES")));
    match (&scim, &sso) {
        (Some(scim), Some(sso)) => {
            r.judge("Google Workspace sync", true, scim::google::Settings::from_env(var, scim, &|p| sso.provider(p).map(|p| p.type_name())));
        }
        _ => r.skip("Google Workspace sync", "SCIM and SSO"),
    }
    let tiers = r.judge("Tiers", true, tiers::Tiers::from_env(var));
    r.judge("Harnesses", false, adapters::NAMES.iter().try_for_each(|name| adapters::get(name).expect("listed adapter").check_env(var)));
    let testing = r.judge("Testing mode", false, license::testing_flag(&var("TESTING_MODE")));
    let payments = match testing {
        Some(testing) => r.judge("Billing", true, billing::Billing::configured(store, var, testing)).map(|(b, _)| b),
        None => {
            r.skip("Billing", "TESTING_MODE");
            None
        }
    };
    let notifier = match sessions {
        Some(s) => r.judge("Notifications", true, notify::Notifier::from_env(var, s)),
        None => {
            r.skip("Notifications", "the session settings");
            None
        }
    };
    match (&payments, &notifier) {
        (Some(p), Some(n)) => {
            r.judge("Billing emails", true, billing_mail::configured(var, p.enabled(), n.smtp.as_ref(), n.links.base.as_deref()));
        }
        _ => r.skip("Billing emails", "billing and notifications"),
    }
    match (&payments, &signups) {
        (Some(p), Some(s)) => {
            r.judge("Pricing page", true, plans::Settings::from_env(var, p.enabled(), p.checkout_enabled(), s.enabled));
        }
        _ => r.skip("Pricing page", "billing and sign-ups"),
    }
    let port = var("PORT");
    r.judge("Address", false, match port.is_empty() || port.parse::<u16>().is_ok() {
        true => Ok(()),
        false => Err("PORT must be a number".to_string()),
    });
    match break_glass {
        Some(b) => {
            r.judge("Sign-in", false, sign_in(&or("HOST", "127.0.0.1"), process, b, &var("ALLOW_NO_AUTH")));
        }
        None => r.skip("Sign-in", "AUTH_BREAK_GLASS"),
    }
    let harness = or("DEFAULT_HARNESS", "claude");
    r.judge("Default harness", false, match adapters::get(&harness) {
        Some(_) => Ok(()),
        None => Err(format!("DEFAULT_HARNESS must be one of: {}", adapters::NAMES.join(", "))),
    });
    r.judge("Audit retention", false, audit::retention_days(&var("AUDIT_RETENTION_DAYS")));
    r.judge("Audit export", true, audit_export::Settings::from_env(var, store));
    r.judge("Audit checkpoints", true, audit_checkpoint::Settings::from_env(var));
    r.judge(
        "Retention",
        false,
        ["CHAT_RETENTION_DAYS", "HARNESS_SESSION_RETENTION_DAYS", "TEAMMATE_FILES_RETENTION_DAYS"].iter().try_for_each(|k| retention::days(k, &var(k)).map(|_| ())),
    );
    let root = |k: &str, d: &str| paths::root(&or(k, d)).map_err(|e| format!("{k}: {e}"));
    let data_dir = r.judge("DATA_DIR", false, root("DATA_DIR", "data"));
    r.judge("WORKSPACE_DIR", false, root("WORKSPACE_DIR", "workspace"));
    match &data_dir {
        Some(d) => {
            r.judge("Evidence bundles", true, evidence::Settings::from_env(var, d));
        }
        None => r.skip("Evidence bundles", "DATA_DIR"),
    }
    r.judge("Health score history", true, health_history::Settings::from_env(var));
    r.judge("Database encryption", true, database_encryption::Policy::from_env(var));
    let backups = match &data_dir {
        Some(d) => r.judge("Server backups", true, server_backups::ServerBackups::from_env(store, var, d)),
        None => {
            r.skip("Server backups", "DATA_DIR");
            None
        }
    };
    let server_data = match (&control_plane, &backups) {
        (Some(cp), Some(b)) => {
            let off_host = b.target.as_ref().map(|t| (t.source, t.destination()));
            r.judge("Server data region", true, machines::server_data::ServerData::from_env(var, &cp.regions, off_host))
        }
        _ => {
            r.skip("Server data region", "the control plane and server backups");
            None
        }
    };
    r.judge("Residency kept pins", false, machines::residency::KeptPins::parse(&var("RESIDENCY_KEPT_PINS")));
    let chat_stores = match (&control_plane, &server_data, &data_dir) {
        (Some(cp), Some(sd), Some(d)) => r.judge("Regional chat stores", true, machines::chat_stores::Settings::from_env(var, cp.enabled(), &cp.regions, sd, d)),
        _ => {
            r.skip("Regional chat stores", "the control plane, the server data region and DATA_DIR");
            None
        }
    };
    let chat_copies = match &chat_stores {
        Some(cs) => {
            let buckets = machines::chat_store_copies::named(names.iter().cloned());
            r.judge(
                "Regional chat stores' copies",
                false,
                machines::chat_store_copies::Settings::from_env(store, var, cs, &buckets)
                    .and_then(|s| s.map(machines::chat_store_copies::Copies::new).transpose())
                    .map_err(|e| format!("Regional chat stores: {e}")),
            )
        }
        None => {
            r.skip("Regional chat stores' copies", "regional chat stores");
            None
        }
    };
    match (&control_plane, &tiers) {
        (Some(_), Some(_)) => match machines_check::check(var, store, bin_dir) {
            Ok(lines) => {
                r.areas.push(("Machine enrollment", Verdict::Ok));
                r.machines = lines;
            }
            Err(e) => r.areas.push(("Machine enrollment", Verdict::Refused(e))),
        },
        _ => r.skip("Machine enrollment", "the control plane and tiers"),
    }
    let isolation = match &data_dir {
        Some(d) => r.judge("Isolation", true, accounts::Isolation::from_env(var, bin_dir, d)),
        None => {
            r.skip("Isolation", "DATA_DIR");
            None
        }
    };
    // Start stops at a missing users' folder or helper before it reads the rest of
    // isolation's settings, so those are judged here too, to be said with it.
    let awaiting_setup = matches!(r.areas.last(), Some(("Isolation", Verdict::Refused(e))) if made_by_setup(e));
    if awaiting_setup && let Some(d) = &data_dir {
        r.judge("Isolation's other settings", false, isolation_beyond_setup(var, d).map_err(|e| format!("Isolation: {e}")));
    }
    let accounts_on = match &isolation {
        Some(iso) => Some(iso.is_some()),
        None => awaiting_setup.then_some(true),
    };
    match (accounts_on, &shared_bots) {
        (Some(on), Some(sb)) => {
            r.judge("Teammates' accounts", false, accounts::teammates_flag(&var("ISOLATION_TEAMMATES"), on, *sb == acl::SharedBots::Isolated).map_err(|e| format!("Isolation: {e}")));
        }
        _ => r.skip("Teammates' accounts", "isolation and shared Bots"),
    }
    r.judge("Screen viewers", false, screen::init_listen_addr(&var("SCREEN_ADDR")));
    r.judge("Chromium sandbox", false, chromium::parse_sandbox(&var("SUPERBOT_CHROMIUM_SANDBOX")));
    r.judge("Runs at once", false, slots::parse_cap(&var("MAX_CONCURRENT_RUNS")));
    r.judge("Approval hook test timeout", false, runner::test_hook_secs(&var(runner::TEST_HOOK_TIMEOUT)));
    r.judge("Residency at startup", false, machines::residency::Startup::parse(&var("RESIDENCY_STARTUP")));
    match (&backups, &control_plane, &chat_stores) {
        (Some(b), Some(cp), Some(_)) => {
            let machine_backups = cp.offsite.as_ref().map(|o| &o.s);
            let copies = chat_copies.as_ref().and_then(|c| c.as_ref()).map(|c| c.settings());
            r.judge("Backup encryption", true, backup_encryption::check(b, machine_backups, copies));
        }
        _ => r.skip("Backup encryption", "server backups, the control plane and regional chat stores"),
    }
    r
}

/// What `install.sh --isolation` makes: the users' folder, root's, and the helpers.
/// Start's refusals for those say so; `install.sh --offline` lets them pass when it turns
/// isolation on, as it makes them after the check.
fn made_by_setup(e: &str) -> bool {
    e.ends_with("Run deploy/install.sh --isolation.") || e.ends_with("must be a folder owned by root that only root can write")
}

/// The isolation settings start reads after the folder (`accounts::Isolation::from_env`).
fn isolation_beyond_setup(var: &dyn Fn(&str) -> String, data_dir: &Path) -> Result<(), String> {
    let dir = Some(var("ISOLATION_DIR")).map(|v| v.trim().to_string()).filter(|v| !v.is_empty());
    let root = std::path::PathBuf::from(dir.unwrap_or_else(|| accounts::DEFAULT_DIR.into()));
    let data = std::fs::canonicalize(data_dir).unwrap_or_else(|_| data_dir.to_path_buf());
    if data.starts_with(&root) || root.starts_with(&data) {
        return Err("ISOLATION_DIR and DATA_DIR must not hold each other".into());
    }
    machines::offboard::Settings::from_vars(var, "ISOLATION_TEAMMATE_FILES", "ISOLATION_TEAMMATE_FILES_DAYS").map(|_| ())
}

/// botd's start with break-glass sign-in (`auth_startup`): AUTH_PASSWORD, or ALLOW_NO_AUTH=1
/// on loopback only.
fn sign_in(host: &str, process: &dyn SecretStore, break_glass: bool, allow_no_auth: &str) -> Result<(), String> {
    let password = process.get("AUTH_PASSWORD").map_err(|e| e.to_string())?;
    if !break_glass || password.is_some_and(|p| !p.expose().is_empty()) {
        return Ok(());
    }
    if !crate::is_loopback_host(host) {
        return Err("Refusing to listen on a public address without AUTH_PASSWORD.".into());
    }
    match allow_no_auth {
        "1" => Ok(()),
        _ => Err("Refusing to start: set AUTH_PASSWORD (recommended), or set ALLOW_NO_AUTH=1 only for loopback development (HOST=127.0.0.1, localhost, or ::1).".into()),
    }
}

/// The report as `botd settings check` prints it, after the lines saying where settings
/// came from: each area, what machines get, what it leaves to other checks, and the verdict.
pub fn lines(r: &Report) -> Vec<String> {
    let mut out: Vec<String> = r
        .areas
        .iter()
        .map(|(area, v)| match v {
            Verdict::Ok => format!("  ok       {area}"),
            Verdict::Refused(e) => format!("  refused  {area:<28} {e}"),
            Verdict::Skipped(why) => format!("  skipped  {area:<28} {why}"),
        })
        .collect();
    out.extend(r.machines.iter().cloned());
    out.push(NOT_CHECKED.into());
    match r.refusals().as_slice() {
        [] => out.push("botd would start with these settings.".into()),
        refused => out.extend(refused.iter().map(|e| format!("botd wouldn't start with these settings: {e}"))),
    }
    out
}

/// `botd settings check ...`: prints what botd would make of its settings and returns 0, 1
/// if it wouldn't start with them (or they can't be read), or 2 for a usage error.
pub fn cli(args: &[String]) -> i32 {
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let Some((&"check", rest)) = args.split_first() else {
        eprintln!("{USAGE}");
        return 2;
    };
    let a = match machines_check::parse_with(rest, USAGE) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("{e}");
            return 2;
        }
    };
    if let Err(e) = machines_check::load(&a) {
        eprintln!("botd settings: {e}");
        return 1;
    }
    let names: Vec<String> = std::env::vars_os().filter_map(|(k, _)| k.into_string().ok()).collect();
    let process = crate::secrets::env::EnvStore::process();
    let report = machines_check::with_startup_store(|store| {
        Ok(check(&machines_check::var, &names, &process, store, &machines_check::bin_dir()))
    })
    .unwrap_or_else(|e| Report { areas: vec![("Secrets backend", Verdict::Refused(e))], machines: Vec::new() });
    for l in lines(&report) {
        println!("{l}");
    }
    i32::from(!report.refusals().is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secrets::env::EnvStore;
    use std::path::PathBuf;

    fn temp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("superbot-ssc-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// The check with these settings, DATA_DIR and WORKSPACE_DIR in a folder of its own,
    /// and AUTH_PASSWORD set unless given.
    fn run(name: &str, pairs: &[(&str, &str)]) -> Report {
        let dir = temp(name);
        let data = dir.join("data").display().to_string();
        let work = dir.join("workspace").display().to_string();
        let mut all: Vec<(&str, &str)> = vec![("DATA_DIR", &data), ("WORKSPACE_DIR", &work), ("AUTH_PASSWORD", "settings-check-pw")];
        all.extend_from_slice(pairs);
        let var = |k: &str| all.iter().rev().find(|(n, _)| *n == k).map(|(_, v)| v.to_string()).unwrap_or_default();
        let names: Vec<String> = all.iter().map(|(k, _)| k.to_string()).collect();
        let store = EnvStore::fixed(&all);
        let r = check(&var, &names, &store, &store, &dir.join("bin"));
        let _ = std::fs::remove_dir_all(dir);
        r
    }

    fn verdict<'a>(r: &'a Report, area: &str) -> &'a Verdict {
        &r.areas.iter().find(|(a, _)| *a == area).unwrap_or_else(|| panic!("no {area}: {r:?}")).1
    }

    #[test]
    fn a_plain_install_starts() {
        let r = run("plain", &[]);
        assert!(r.refusals().is_empty(), "{r:?}");
        assert!(r.areas.iter().all(|(_, v)| *v == Verdict::Ok), "{r:?}");
        assert_eq!(r.machines, ["Machines: off (no control plane)"]);
        let out = lines(&r);
        assert_eq!(out.last().unwrap(), "botd would start with these settings.");
        assert!(out.contains(&"  ok       SSO".to_string()), "{out:?}");
        assert!(out.contains(&NOT_CHECKED.to_string()), "{out:?}");
    }

    // The upgrade this is for: a setting the server has, which the new botd refuses at start.
    #[test]
    fn settings_outside_machines_are_refused_as_at_start() {
        for (pairs, area, starts) in [
            (&[("SSO_PROVIDERS", "okta")][..], "SSO", "SSO: SSO_PUBLIC_URL is required with SSO_PROVIDERS"),
            (&[("STATUS_PAGE", "maybe")][..], "Status page", "STATUS_PAGE must be on or off"),
            (&[("SERVER_BACKUP_OFF_HOST", "sometimes")][..], "Server backups", "Server backups: SERVER_BACKUP_OFF_HOST must be auto, on or off"),
            (&[("SUPERBOT_DATABASE_ENCRYPTION", "maybe")][..], "Database encryption", "Database encryption: "),
            (&[("TESTING_MODE", "sometimes")][..], "Testing mode", "TESTING_MODE"),
            (&[("MAX_CONCURRENT_RUNS", "lots")][..], "Runs at once", "MAX_CONCURRENT_RUNS"),
            (&[("DEFAULT_HARNESS", "nope")][..], "Default harness", "DEFAULT_HARNESS must be one of: claude, codex, pi, hermes"),
            (&[("PORT", "http")][..], "Address", "PORT must be a number"),
            (&[("ISOLATION", "maybe")][..], "Isolation", "Isolation: ISOLATION must be off or users"),
            (&[("SCIM", "maybe")][..], "SCIM", "SCIM: "),
            (&[("TIERS_FILE", "/nonexistent/tiers.json")][..], "Tiers", "Tiers: "),
        ] {
            let r = run("refused", pairs);
            match verdict(&r, area) {
                Verdict::Refused(e) => assert!(e.starts_with(starts), "{area}: {e}"),
                v => panic!("{pairs:?} gave {area} {v:?}"),
            }
            assert_eq!(r.refusals().len(), 1, "{pairs:?}: {:?}", r.refusals());
            let out = lines(&r);
            assert!(out.last().unwrap().starts_with(&format!("botd wouldn't start with these settings: {starts}")), "{out:?}");
        }
    }

    #[test]
    fn every_refusal_is_said_and_what_reads_a_refused_area_is_skipped() {
        let r = run("several", &[("STATUS_PAGE", "maybe"), ("SESSION_IDLE_TIMEOUT", "soon"), ("TESTING_MODE", "x")]);
        let refused = r.refusals();
        assert_eq!(refused.len(), 3, "{refused:?}");
        assert!(refused[0].starts_with("STATUS_PAGE"), "botd's first refusal is first: {refused:?}");
        assert!(matches!(verdict(&r, "Notifications"), Verdict::Skipped(w) if w.contains("session")), "{r:?}");
        assert!(matches!(verdict(&r, "Billing"), Verdict::Skipped(_)), "{r:?}");
        assert!(matches!(verdict(&r, "Billing emails"), Verdict::Skipped(_)), "{r:?}");
        let out = lines(&r);
        assert_eq!(out.iter().filter(|l| l.starts_with("botd wouldn't start with these settings: ")).count(), 3, "{out:?}");
        assert!(out.iter().any(|l| l.starts_with("  skipped  Notifications")), "{out:?}");
    }

    #[test]
    fn isolation_awaiting_setup_still_judges_its_other_settings() {
        let missing = temp("iso-missing").join("users").display().to_string();
        let iso = |extra: &[(&'static str, &'static str)]| {
            let mut pairs: Vec<(&str, &str)> = vec![("ISOLATION", "users"), ("ISOLATION_DIR", &missing)];
            pairs.extend_from_slice(extra);
            run("iso-setup", &pairs)
        };
        let r = iso(&[]);
        assert!(matches!(verdict(&r, "Isolation"), Verdict::Refused(e) if made_by_setup(e) && e.starts_with("Isolation: ISOLATION_DIR")), "{r:?}");
        assert_eq!(r.refusals().len(), 1, "{r:?}");
        assert!(matches!(verdict(&r, "Isolation's other settings"), Verdict::Ok), "{r:?}");
        assert!(matches!(verdict(&r, "Teammates' accounts"), Verdict::Ok), "{r:?}");

        let r = iso(&[("ISOLATION_TEAMMATE_FILES", "sometimes"), ("ISOLATION_TEAMMATES", "maybe")]);
        let refused: Vec<&str> = r.refusals();
        assert_eq!(refused.len(), 3, "{r:?}");
        assert!(refused[1].starts_with("Isolation: ISOLATION_TEAMMATE_FILES must be archive or delete"), "{refused:?}");
        assert!(refused[2].starts_with("Isolation: ISOLATION_TEAMMATES must be on or off"), "{refused:?}");
        assert!(refused[1..].iter().all(|e| !made_by_setup(e)), "{refused:?}");

        let r = run("iso-bad", &[("ISOLATION", "maybe"), ("ISOLATION_TEAMMATE_FILES", "sometimes")]);
        assert!(matches!(verdict(&r, "Isolation"), Verdict::Refused(e) if !made_by_setup(e)), "{r:?}");
        assert!(!r.areas.iter().any(|(a, _)| *a == "Isolation's other settings"), "{r:?}");
        assert!(matches!(verdict(&r, "Teammates' accounts"), Verdict::Skipped(_)), "{r:?}");
    }

    #[test]
    fn sign_in_needs_a_password_off_loopback_as_at_start() {
        let none = EnvStore::fixed(&[]);
        assert!(sign_in("127.0.0.1", &none, true, "1").is_ok());
        assert!(sign_in("127.0.0.1", &none, true, "").unwrap_err().starts_with("Refusing to start: set AUTH_PASSWORD"));
        assert!(sign_in("0.0.0.0", &none, true, "1").unwrap_err().contains("public address without AUTH_PASSWORD"));
        assert!(sign_in("0.0.0.0", &none, false, "").is_ok(), "break-glass off needs no password");
        assert!(sign_in("0.0.0.0", &EnvStore::fixed(&[("AUTH_PASSWORD", "pw")]), true, "").is_ok());
        let r = run("no-password", &[("AUTH_PASSWORD", ""), ("HOST", "0.0.0.0")]);
        assert!(matches!(verdict(&r, "Sign-in"), Verdict::Refused(e) if e.contains("without AUTH_PASSWORD")), "{r:?}");
    }

    #[test]
    fn machines_are_judged_with_the_rest() {
        let r = run("machines", &[("MACHINE_CONTROL_URL", "https://10.0.0.5:8443")]);
        match verdict(&r, "Machine enrollment") {
            Verdict::Refused(e) => assert!(e.starts_with("Machine enrollment: MACHINE_CONTROL_URL needs the control plane"), "{e}"),
            v => panic!("{v:?}"),
        }
        let r = run("no-regions", &[("LINODE_TOKEN", "settings-check-token"), ("MACHINE_REGIONS", "")]);
        assert!(matches!(verdict(&r, "Control plane"), Verdict::Refused(e) if e.starts_with("Control plane: MACHINE_REGIONS is needed")), "{r:?}");
        for skipped in ["Shared Bots", "Server data region", "Regional chat stores", "Machine enrollment", "Backup encryption"] {
            assert!(matches!(verdict(&r, skipped), Verdict::Skipped(_)), "{skipped}: {r:?}");
        }
    }

    #[test]
    fn options() {
        assert_eq!(cli(&["nope".into()]), 2);
        assert_eq!(cli(&["check".into(), "--bogus".into(), "1".into()]), 2);
        assert_eq!(cli(&["check".into(), "--home".into(), "/h".into(), "--env-file".into(), "/e".into()]), 2);
    }

    /// Air-gapped servers (ADR 0128): the check reads files and the environment only.
    #[test]
    fn the_check_reaches_no_network() {
        let code = include_str!("settings_check.rs").split("\n#[cfg(test)]\n").next().unwrap();
        for needle in ["reqwest", "hyper", "TcpStream", "UdpSocket", "ToSocketAddrs", "lookup_host", "http://", "https://", "tokio"] {
            assert!(!code.contains(needle), "settings_check.rs uses {needle}: the check must work with no network (ADR 0310)");
        }
    }

    /// Every setting botd's start stops on, before it opens the database, is judged here, or
    /// listed as left to another check. A new one in `main` fails this until it is either.
    #[test]
    fn every_refusal_at_start_is_checked() {
        const ELSEWHERE: [&str; 14] = [
            // The database and master key: botd support check.
            "database_encryption::lock_data_dir",
            "secrets::Keys::locate",
            "database_encryption::prepare",
            "secrets::init",
            "machines::chat_stores::open",
            "machines::chat_store_copies::check_destinations",
            "machines::residency::at_startup",
            "machines::hosts::load",
            "scim::google::Directory::new",
            "secrets::global",
            // Moving files from before ADR 0029, which a check mustn't do.
            "isolation::migrate_workspace",
            "isolation::migrate_user_file",
            // Listening ports, which the running botd holds.
            "tokio::net::TcpListener::bind",
            // Screens' ports: Xvfb on botd's PATH decides whether there are any.
            "s.check_ports",
        ];
        let main = include_str!("main.rs");
        // From the first setting read, after the subcommands, each a `cli` of its own.
        let body = &main[main.find("async fn main()").unwrap()..];
        let body = &body[body.find("let port: u16").unwrap()..];
        let body = &body[..body.find("\n}\n").unwrap()];
        let own = [include_str!("settings_check.rs"), include_str!("machines/settings_check.rs")].map(|f| f.split("\n#[cfg(test)]\n").next().unwrap()).concat();
        let (mut missing, mut found) = (Vec::new(), 0);
        for stmt in body.split(';').filter(|s| s.contains("exit(")) {
            let Some(call) = first_call(stmt) else { continue };
            found += 1;
            // As this and `botd machines check` call them.
            let alias = [("sso::Sso::from_env", "sso::Sso::from_vars"), ("machines::enroll::Enrollment::from_env", "Enrollment::from_env")];
            let covered = own.contains(&call) || ELSEWHERE.contains(&call.as_str()) || alias.iter().any(|(c, a)| *c == call && own.contains(a));
            if !covered {
                missing.push(call);
            }
        }
        assert!(found > 40, "only {found} refusals found in main: the scan no longer reads it");
        assert!(missing.is_empty(), "botd's start stops on these, which botd settings check doesn't judge: {missing:?}. Judge each in settings_check::check (ADR 0310), or list it in ELSEWHERE with why");
    }

    /// The first call in `stmt` to a path in this crate (`sso::Sso::from_env`), or to a
    /// method of a local (`s.check_ports`), skipping std, types and macros.
    fn first_call(stmt: &str) -> Option<String> {
        let b = stmt.as_bytes();
        let ident = |c: u8| c.is_ascii_alphanumeric() || c == b'_';
        let mut i = 0;
        while i < b.len() {
            if !ident(b[i]) || (i > 0 && (ident(b[i - 1]) || b[i - 1] == b':')) {
                i += 1;
                continue;
            }
            let mut j = i;
            while j < b.len() && (ident(b[j]) || b[j] == b':' || b[j] == b'.') {
                j += 1;
            }
            let path = &stmt[i..j];
            let lower = b[i].is_ascii_lowercase();
            let call = j < b.len() && b[j] == b'(';
            let ours = (path.contains("::") && !path.starts_with("std::") && !path.contains('.')) || path == "s.check_ports";
            if lower && call && ours {
                return Some(path.to_string());
            }
            i = j.max(i + 1);
        }
        None
    }

    #[test]
    fn first_calls_are_found() {
        assert_eq!(first_call("let x = status::Page::parse(&env(\"STATUS_PAGE\", \"\")).unwrap_or_else(|e| exit(e))").as_deref(), Some("status::Page::parse"));
        assert_eq!(first_call("scim.google = Some(Arc::new(scim::google::Directory::new(&app, s).unwrap()))").as_deref(), Some("scim::google::Directory::new"));
        assert_eq!(first_call("let n = std::env::var(k).map(|v| v.len())").as_deref(), None);
        assert_eq!(first_call("if let Some(s) = &screens {\n s.check_ports().unwrap_or_else(|e| exit(e))").as_deref(), Some("s.check_ports"));
    }
}
