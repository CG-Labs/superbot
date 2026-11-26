//! `botd license check` (ADR 0305): what this botd makes of an install's license, read as its
//! start reads it, offline and changing nothing. A release can stop trusting the key a license
//! was signed with, and a renewal can come with fewer seats, so `install.sh --offline` runs the
//! running release's botd and the bundle's on the server's settings before an upgrade or a
//! rollback changes anything, and stops when Bots run now but wouldn't after.

use super::{Licensing, Source, Status};
use crate::database_encryption::{self, DbKey, Format};
use crate::support_check::{self, Settings};
use serde_json::{Value, json};
use std::io::Read;
use std::path::Path;

const USAGE: &str = "Usage: botd license check [--home <dir> | --env-file <file>] [--key-file <file> | --key-file -] [--json]

Whether this botd would run Bots with an install's license, read as botd's start reads it:
LICENSE_KEY, else LICENSE_KEY_FILE, else DATA_DIR/license.key, checked against the keys built
into this botd, with TESTING_MODE. Seats in use are counted in botd's database, opened read-only.
Opens no connection and changes nothing.
  --home <dir>       the installer's layout: settings from <dir>/superbot/.env
                     (sudo -u superbot botd license check --home /home/superbot)
  --env-file <file>  settings from this file, over botd's environment
  --key-file <file>  a key judged as if installed as DATA_DIR/license.key, such as a renewal
                     before you install it; - reads it from stdin
  --json             the result as JSON
Exits 0 when Bots would run (a license, or testing mode), 1 when they wouldn't, 2 for a usage
error, 3 when the settings or the key can't be read.
Docs: docs/ops/air-gapped.md#the-license-through-upgrades";

/// What this botd makes of a license: its status, and the seats in use when they could be counted.
pub struct Verdict {
    pub status: Status,
    /// The key was given with `--key-file`.
    pub key_given: bool,
    /// Where DATA_DIR/license.key is, or LICENSE_KEY_FILE names.
    pub file: String,
    pub seats: Result<Option<u32>, String>,
    /// `TESTING_MODE` botd won't start with.
    pub refused: Option<String>,
}

impl Verdict {
    pub fn usable(&self) -> bool {
        self.refused.is_none() && self.status.usable()
    }

    fn from(&self) -> String {
        let over = if self.key_given { ", which wins over the key given with --key-file" } else { "" };
        match self.status.source {
            Source::Env => format!("LICENSE_KEY{over}"),
            Source::EnvFile => format!("LICENSE_KEY_FILE ({}){over}", self.file),
            Source::File if self.key_given => format!("the key given with --key-file, as {}", self.file),
            Source::File => self.file.clone(),
            Source::None if self.key_given => "nothing: the key given with --key-file is empty".into(),
            Source::None => "nothing: no license is set".into(),
        }
    }

    fn seat_line(&self) -> String {
        let cap = self.status.seat_cap();
        match (&self.seats, cap) {
            (Err(e), _) => format!("Seats: not counted ({e})"),
            (Ok(None), _) => "Seats: not counted (no database yet)".into(),
            (Ok(Some(used)), None) => format!("Seats: {used} in use, no limit"),
            (Ok(Some(used)), Some(0)) => format!("Seats: {used} in use, and none allowed"),
            (Ok(Some(used)), Some(cap)) => format!("Seats: {used} of {cap} in use"),
        }
    }

    fn warnings(&self) -> Vec<String> {
        let detail = self.status.detail();
        let used = *self.seats.as_ref().ok().and_then(Option::as_ref).unwrap_or(&0);
        self.status.warnings(used).into_iter().filter(|w| *w != detail).collect()
    }

    /// Lines a script reads: `License: <mode>, from ...`, its detail indented, the seats, each
    /// `Warning: `, and last whether Bots would run.
    pub fn text(&self) -> String {
        let mut out = format!("License: {}, from {}\n  {}\n", mode_word(&self.status), self.from(), self.status.detail());
        if let Some(p) = &self.status.problem {
            out.push_str(&format!("  {}\n", p.text));
        }
        out.push_str(&self.seat_line());
        out.push('\n');
        for w in self.warnings() {
            out.push_str(&format!("Warning: {w}\n"));
        }
        let me = env!("CARGO_PKG_VERSION");
        match &self.refused {
            Some(e) => out.push_str(&format!("Bots wouldn't run with this license (botd {me}): botd wouldn't start: {e}\n")),
            None if self.usable() => out.push_str(&format!("Bots would run with this license (botd {me}).\n")),
            None => out.push_str(&format!("Bots wouldn't run with this license (botd {me}): {}\n", self.status.detail())),
        }
        out
    }

    pub fn json(&self, settings: Value) -> Value {
        let used = *self.seats.as_ref().ok().and_then(Option::as_ref).unwrap_or(&0);
        json!({
            "botd": env!("CARGO_PKG_VERSION"),
            "settings": settings,
            "keyGiven": self.key_given,
            "from": self.from(),
            "license": self.status.view(used),
            "seatsCounted": matches!(self.seats, Ok(Some(_))),
            "seatsError": self.seats.as_ref().err(),
            "refused": self.refused,
            "usable": self.usable(),
        })
    }
}

fn mode_word(s: &Status) -> &'static str {
    match s.mode {
        super::Mode::Unlicensed if s.testing() => "testing",
        super::Mode::Unlicensed => "unlicensed",
        super::Mode::Active => "active",
        super::Mode::Grace => "grace",
        super::Mode::Expired => "expired",
        super::Mode::Invalid => "invalid",
    }
}

/// Active people other than the owner, in `data_dir`'s database: None when there is none yet.
fn seats_used(s: &Settings, data_dir: &Path) -> Result<Option<u32>, String> {
    let path = data_dir.join("app.sqlite");
    let key = match database_encryption::format(&path)? {
        Format::Missing => return Ok(None),
        Format::Plain => None,
        Format::Encrypted => {
            let keys = support_check::master_keys(s, data_dir)?;
            Some(keys.iter().map(DbKey::derive).find(|k| database_encryption::opens(&path, k)).ok_or("the database is encrypted, and no master key here opens it")?)
        }
    };
    let c = database_encryption::open_read_only(&path, key.as_ref()).map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(Some(crate::db::Db::seats_used(&c)))
}

/// What this botd's start would make of the license `s` sets, with `key` in place of
/// DATA_DIR/license.key when given.
pub fn judge(s: &Settings, key: Option<&str>) -> Verdict {
    let data_dir = s.data_dir();
    let lic = Licensing::new(super::trusted(), &data_dir);
    let testing = super::testing_flag(&s.get("TESTING_MODE"));
    lic.set_testing(*testing.as_ref().unwrap_or(&false));
    lic.load_or(|k| support_check::license_setting(s, k), key);
    let status = lic.status();
    let file = match status.source {
        Source::EnvFile => support_check::license_setting(s, "LICENSE_KEY_FILE"),
        _ => data_dir.join(super::FILE).display().to_string(),
    };
    Verdict { status, key_given: key.is_some(), file, seats: seats_used(s, &data_dir), refused: testing.err() }
}

struct Args<'a> {
    home: Option<&'a str>,
    env_file: Option<&'a str>,
    key_file: Option<&'a str>,
    json: bool,
}

fn parse<'a>(rest: &[&'a str]) -> Result<Args<'a>, String> {
    let mut a = Args { home: None, env_file: None, key_file: None, json: false };
    let mut it = rest.iter();
    while let Some(&flag) = it.next() {
        if flag == "--json" {
            a.json = true;
            continue;
        }
        let v = *it.next().ok_or(format!("{flag} needs a value\n{USAGE}"))?;
        match flag {
            "--home" => a.home = Some(v),
            "--env-file" => a.env_file = Some(v),
            "--key-file" => a.key_file = Some(v),
            _ => return Err(format!("Unknown option {flag}\n{USAGE}")),
        }
    }
    if a.home.is_some() && a.env_file.is_some() {
        return Err(format!("Use --home or --env-file, not both\n{USAGE}"));
    }
    Ok(a)
}

/// The key named by `--key-file`, at most a license's size, read as botd reads its own file.
fn read_key(from: &str) -> Result<String, String> {
    let mut s = String::new();
    let cap = super::token::MAX_TOKEN as u64 + 1;
    let read = if from == "-" {
        std::io::stdin().take(cap).read_to_string(&mut s)
    } else {
        std::fs::File::open(from).and_then(|f| f.take(cap).read_to_string(&mut s))
    };
    read.map_err(|e| format!("--key-file {from}: {e}"))?;
    Ok(s.trim().to_string())
}

/// `botd license check ...`: prints what this botd makes of the license, and returns 0 when
/// Bots would run, 1 when they wouldn't, 2 for a usage error, 3 when something can't be read.
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
    let s = match Settings::load(a.home, a.env_file) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("botd license: {e}");
            return 3;
        }
    };
    let key = match a.key_file.map(read_key).transpose() {
        Ok(k) => k,
        Err(e) => {
            eprintln!("botd license: {e}");
            return 3;
        }
    };
    let v = judge(&s, key.as_deref());
    if a.json {
        println!("{}", serde_json::to_string_pretty(&v.json(s.source())).unwrap_or_default());
    } else {
        match s.source()["envFile"].as_str() {
            Some(f) => println!("Settings: {f}, over botd's environment"),
            None => println!("Settings: botd's environment"),
        }
        print!("{}", v.text());
    }
    if v.usable() { 0 } else { 1 }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::license::test_keys::{claims, mint};
    use crate::license::{GRACE_DAYS, Mode};
    use crate::rbac::Role;
    use crate::secrets::key::MasterKey;
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    fn data(tag: &str) -> PathBuf {
        let d = crate::db::temp_path(tag);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn settings(pairs: &[(&str, &str)]) -> Settings {
        let map: BTreeMap<String, String> = pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        Settings::new(Some((PathBuf::from("/srv/superbot/.env"), map)), None, BTreeMap::new())
    }

    /// A database with `n` active people besides the owner, and one disabled.
    fn people(db: &crate::db::Db, n: usize) {
        db.create_user(Some(crate::users::OPERATOR), None, "Owner", Role::Admin).unwrap();
        for i in 0..n {
            db.create_user(None, Some(&format!("p{i}@example.com")), "P", Role::Member).unwrap();
        }
        let gone = db.create_user(None, Some("gone@example.com"), "Gone", Role::Member).unwrap();
        db.update_user(&gone.id, crate::db::UserPatch { status: Some("disabled"), ..Default::default() }).unwrap();
    }

    #[test]
    fn the_servers_license_and_a_key_given_are_judged_as_botd_would_start_with_them() {
        let d = data("lc-file");
        let dd = d.display().to_string();
        let c = claims(Some(5), 200);
        std::fs::write(d.join("license.key"), format!("{}\n", mint(&c))).unwrap();
        let v = judge(&settings(&[("DATA_DIR", &dd)]), None);
        assert!(v.usable());
        let t = v.text();
        assert!(t.starts_with(&format!("License: active, from {}/license.key\n  Licensed to Acme Ltd (business, 5 seats) until ", d.display())), "{t}");
        assert!(t.contains("Seats: not counted (no database yet)") && t.ends_with(&format!("Bots would run with this license (botd {}).\n", env!("CARGO_PKG_VERSION"))), "{t}");

        // A renewal with fewer seats than people active: Bots run, and it says nobody can be added.
        people(&crate::db::Db::open(&d.join("app.sqlite")).unwrap(), 4);
        let fewer = mint(&claims(Some(3), 400));
        let v = judge(&settings(&[("DATA_DIR", &dd)]), Some(&fewer));
        let t = v.text();
        assert!(v.usable() && v.key_given, "{t}");
        assert!(t.contains(&format!("from the key given with --key-file, as {}/license.key", d.display())), "{t}");
        assert!(t.contains("Seats: 4 of 3 in use\nWarning: 4 people are active, over the 3 seats allowed."), "{t}");
        assert_eq!(std::fs::read_to_string(d.join("license.key")).unwrap().trim(), mint(&c), "nothing is installed");

        // LICENSE_KEY wins over the key given, as over the file.
        let v = judge(&settings(&[("DATA_DIR", &dd), ("LICENSE_KEY", &mint(&c))]), Some(&fewer));
        assert!(v.text().contains("License: active, from LICENSE_KEY, which wins over the key given with --key-file"), "{}", v.text());
        assert_eq!(v.status.seat_cap(), Some(5));
        let j = v.json(json!({}));
        assert_eq!((j["usable"].as_bool(), j["license"]["seats"]["used"].as_u64(), j["seatsCounted"].as_bool()), (Some(true), Some(4), Some(true)));
    }

    // The upgrade this is for: the new release no longer trusts the key the license was signed with.
    #[test]
    fn a_key_this_botd_doesnt_trust_or_an_ended_license_runs_no_bots() {
        let d = data("lc-bad");
        let dd = d.display().to_string();
        let foreign = crate::license::token::sign(&crate::license::test_keys::stranger(), "cg-2031", &claims(Some(5), 200)).unwrap();
        let v = judge(&settings(&[("DATA_DIR", &dd)]), Some(&foreign));
        let t = v.text();
        assert!(!v.usable(), "{t}");
        assert!(t.starts_with("License: invalid, from the key given") && t.contains("isn't valid (unknown_key)"), "{t}");
        assert!(t.contains("\n  This license was signed by a key this version of SuperBot doesn't know."), "{t}");
        assert!(t.contains(&format!("Bots wouldn't run with this license (botd {}): The license key isn't valid (unknown_key).", env!("CARGO_PKG_VERSION"))), "{t}");

        let ended = mint(&claims(Some(5), -(GRACE_DAYS + 1)));
        let v = judge(&settings(&[("DATA_DIR", &dd)]), Some(&ended));
        assert_eq!((v.status.mode, v.usable()), (Mode::Expired, false));
        let grace = mint(&claims(Some(5), -1));
        let v = judge(&settings(&[("DATA_DIR", &dd)]), Some(&grace));
        assert!(v.usable() && v.text().starts_with("License: grace,"), "{}", v.text());

        // Testing mode runs Bots with no license, and with a bad one; a TESTING_MODE botd refuses doesn't.
        let v = judge(&settings(&[("DATA_DIR", &dd), ("TESTING_MODE", "on")]), None);
        assert!(v.usable() && v.text().starts_with("License: testing, from nothing: no license is set"), "{}", v.text());
        assert!(judge(&settings(&[("DATA_DIR", &dd), ("TESTING_MODE", "on")]), Some(&foreign)).usable());
        let v = judge(&settings(&[("DATA_DIR", &dd), ("TESTING_MODE", "maybe")]), None);
        assert!(!v.usable() && v.text().contains("botd wouldn't start: TESTING_MODE must be on or off"), "{}", v.text());
        let v = judge(&settings(&[("DATA_DIR", &dd)]), Some(""));
        assert!(!v.usable() && v.text().starts_with("License: unlicensed, from nothing: the key given with --key-file is empty"), "{}", v.text());
    }

    #[test]
    fn seats_are_counted_in_an_encrypted_database_with_the_master_key() {
        use std::os::unix::fs::OpenOptionsExt;
        let d = data("lc-encrypted");
        let key = MasterKey::generate();
        let key_file = d.parent().unwrap().join(format!("master-{}.key", crate::short_id()));
        let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&key_file).unwrap();
        std::io::Write::write_all(&mut f, format!("{}\n", key.base64().as_str()).as_bytes()).unwrap();
        people(&crate::db::Db::open_keyed(&d.join("app.sqlite"), &DbKey::derive(&key)), 2);
        let (dd, kf) = (d.display().to_string(), key_file.display().to_string());
        let lic = mint(&claims(None, 100));
        let v = judge(&settings(&[("DATA_DIR", &dd), ("SUPERBOT_MASTER_KEY_FILE", &kf)]), Some(&lic));
        assert!(v.text().contains("Seats: 2 in use, no limit"), "{}", v.text());
        let v = judge(&settings(&[("DATA_DIR", &dd)]), Some(&lic));
        assert!(v.usable() && v.text().contains("Seats: not counted (the database is encrypted, and no master key here opens it)"), "{}", v.text());
        let _ = std::fs::remove_file(key_file);
    }

    #[test]
    fn options() {
        let p = |l: &[&'static str]| parse(l).map(|a| (a.home, a.env_file, a.key_file, a.json));
        assert_eq!(p(&["--home", "/h", "--key-file", "-", "--json"]), Ok((Some("/h"), None, Some("-"), true)));
        for (bad, why) in [(&["--home", "/h", "--env-file", "/e"][..], "not both"), (&["--key-file"][..], "needs a value"), (&["--set", "A=1"][..], "Unknown option --set")] {
            assert!(p(bad).unwrap_err().contains(why), "{bad:?}");
        }
        assert_eq!(cli(&["nope".into()]), 2);
        assert_eq!(cli(&["check".into(), "--bogus".into(), "1".into()]), 2);
        assert_eq!(cli(&["check".into(), "--env-file".into(), "/nonexistent/.env".into()]), 3);
        assert_eq!(cli(&["check".into(), "--key-file".into(), "/nonexistent/license.key".into()]), 3);
        assert!(read_key("/nonexistent/k").unwrap_err().starts_with("--key-file /nonexistent/k: "));
    }
}
