//! Secrets: API keys and tokens Bots need, and the sensitive data botd keeps.
//!
//! Stores are asked in order and the first that has a name wins:
//! 1. `EnvStore`: environment variables and `NAME_FILE` files (the default; nothing to set up).
//! 2. `SealedStore`: values the operator saves with `botctl secret set` or the API,
//!    encrypted in SQLite with the master key (see `key`, `sealed`).
//!
//! A store for Vault, Azure Key Vault, or GCP Secret Manager is another `SecretStore`
//! added to that list. Values never leave botd except into a harness's environment;
//! the API lists names only. Every known value is redacted from saved text, events,
//! and the audit log (`redact`). See docs/adr/0010-secrets.md.

pub mod env;
pub mod key;
pub mod redact;
pub mod sealed;

use env::EnvStore;
use serde::Serialize;
use std::path::Path;
use std::sync::{Arc, OnceLock};
use zeroize::Zeroizing;

/// A secret value. Zeroed when dropped; never printed by `{:?}`.
pub struct Secret(Zeroizing<String>);

impl Secret {
    pub fn new(v: impl Into<String>) -> Secret {
        Secret(Zeroizing::new(v.into()))
    }

    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str(redact::MARK)
    }
}

#[derive(Debug)]
pub enum Error {
    /// No store here takes writes (e.g. only the environment).
    ReadOnly,
    /// A bad name or value, or conflicting settings.
    Invalid(String),
    /// The store failed: I/O, database, or a value that won't decrypt.
    Store(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Error::ReadOnly => f.write_str("secrets here are read-only"),
            Error::Invalid(m) | Error::Store(m) => f.write_str(m),
        }
    }
}

/// Where secrets come from. Read-only stores keep the default `put` and `delete`.
pub trait SecretStore: Send + Sync {
    /// Short name shown to the operator: "env", "sealed", "vault", ...
    fn kind(&self) -> &'static str;
    fn get(&self, name: &str) -> Result<Option<Secret>, Error>;
    /// Names this store has. Never values.
    fn names(&self) -> Result<Vec<String>, Error>;
    fn writable(&self) -> bool {
        false
    }
    fn put(&self, _name: &str, _value: &str) -> Result<(), Error> {
        Err(Error::ReadOnly)
    }
    /// True if the name existed.
    fn delete(&self, _name: &str) -> Result<bool, Error> {
        Err(Error::ReadOnly)
    }
    /// True if harnesses already inherit this value from botd's own environment.
    fn inherited(&self, _name: &str) -> bool {
        false
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Listed {
    pub name: String,
    pub store: &'static str,
    pub writable: bool,
    /// An earlier store with the same name, whose value wins.
    pub shadowed_by: Option<&'static str>,
    /// False for botd's own secrets (`server_secret`), which no Bot receives.
    pub for_bots: bool,
}

/// Names botd or the harnesses rely on; a stored secret must not replace them in a Bot's environment.
const RESERVED: [&str; 13] = ["AUTH_PASSWORD", "LICENSE_KEY", "STRIPE_WEBHOOK_SECRET", "PATH", "HOME", "USER", "LOGNAME", "SHELL", "ENV", "BASH_ENV", "NODE_OPTIONS", "DISPLAY", "DBUS_SESSION_BUS_ADDRESS"];
const RESERVED_PREFIXES: [&str; 7] = ["SUPERBOT_", "BOT_", "SSO_", "LD_", "DYLD_", "AGENT_BROWSER_", "VOXL_"];
pub const MAX_VALUE: usize = 64 * 1024;

fn env_shaped(name: &str) -> bool {
    !name.is_empty() && name.len() <= 128 && name.bytes().enumerate().all(|(i, b)| b == b'_' || b.is_ascii_uppercase() || (i > 0 && b.is_ascii_digit()))
}

pub fn check_name(name: &str) -> Result<(), Error> {
    if !env_shaped(name) {
        return Err(Error::Invalid("Use an environment variable name: A-Z, 0-9, and _, not starting with a digit.".into()));
    }
    if RESERVED.contains(&name) || RESERVED_PREFIXES.iter().any(|p| name.starts_with(p)) {
        return Err(Error::Invalid(format!("{name} is reserved by SuperBot.")));
    }
    Ok(())
}

/// botd's own secrets: saved and listed like the others, but never given to a Bot.
/// Today these are SSO client secrets (`SSO_<PROVIDER>_CLIENT_SECRET`, ADR 0014),
/// Apple's signing keys (`SSO_<PROVIDER>_PRIVATE_KEY`, ADR 0018), and `SERVER_SECRETS`.
pub fn server_secret(name: &str) -> bool {
    let provider = |suffix: &str| name.strip_prefix("SSO_").and_then(|n| n.strip_suffix(suffix)).is_some_and(|id| !id.is_empty());
    env_shaped(name) && (provider("_CLIENT_SECRET") || provider("_PRIVATE_KEY") || SERVER_SECRETS.contains(&name))
}

/// The Turnstile secret (ADR 0022), and the Linode token, which can rent and delete
/// every user's machine (ADR 0025).
pub const SERVER_SECRETS: [&str; 2] = ["TURNSTILE_SECRET", "LINODE_TOKEN"];

fn check_saveable(name: &str) -> Result<(), Error> {
    if server_secret(name) { Ok(()) } else { check_name(name) }
}

/// A user's secret goes to their Bots, so botd's own names are refused too.
fn check_user_name(name: &str) -> Result<(), Error> {
    check_name(name)?;
    if server_secret(name) {
        return Err(Error::Invalid(format!("{name} is SuperBot's own; no Bot gets it.")));
    }
    Ok(())
}

fn check_value(v: &str) -> Result<(), Error> {
    if v.is_empty() || v.len() > MAX_VALUE || v.contains('\0') {
        return Err(Error::Invalid(format!("The value must be 1 to {MAX_VALUE} bytes, without NUL.")));
    }
    Ok(())
}

/// A user's own secret, as listed to them. Never the value.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UserListed {
    pub name: String,
    pub updated_at: i64,
}

pub struct Secrets {
    stores: Vec<Box<dyn SecretStore>>,
    /// Each user's own (ADR 0029). None: no store for them here.
    users: Option<sealed::UserSecrets>,
}

impl Secrets {
    pub fn new(stores: Vec<Box<dyn SecretStore>>) -> Secrets {
        Secrets { stores, users: None }
    }

    pub fn with_users(mut self, users: sealed::UserSecrets) -> Secrets {
        self.users = Some(users);
        self
    }

    fn users(&self) -> Result<&sealed::UserSecrets, Error> {
        self.users.as_ref().ok_or(Error::ReadOnly)
    }

    pub fn user_list(&self, user_id: &str) -> Result<Vec<UserListed>, Error> {
        Ok(self.users()?.names(user_id)?.into_iter().map(|(name, updated_at)| UserListed { name, updated_at }).collect())
    }

    /// Saves a secret that reaches only `user_id`'s Bots, over a server-wide one of the
    /// same name. botd's own secrets can't be saved here: no Bot may get them.
    pub fn user_put(&self, user_id: &str, name: &str, value: &str) -> Result<UserListed, Error> {
        check_user_name(name)?;
        check_value(value)?;
        redact::register_for(user_id, value);
        let users = self.users()?;
        users.put(user_id, name, value)?;
        self.user_list(user_id)?.into_iter().find(|l| l.name == name).ok_or_else(|| Error::Store(format!("{name} was not saved")))
    }

    pub fn user_delete(&self, user_id: &str, name: &str) -> Result<bool, Error> {
        check_user_name(name)?;
        self.users()?.delete(user_id, name)
    }

    /// Drops every secret a user saved. For when the user is deleted.
    pub fn user_forget(&self, user_id: &str) -> Result<usize, Error> {
        let Ok(users) = self.users() else { return Ok(0) };
        let names = users.names(user_id)?;
        for (n, _) in &names {
            users.delete(user_id, n)?;
        }
        Ok(names.len())
    }

    /// `harness_env` for a Bot owned by `owner`: the server-wide values, with the
    /// owner's own on top. Another user's never appear.
    pub fn harness_env_for(&self, owner: &str) -> Vec<(String, Secret)> {
        let mut out = self.harness_env();
        let Ok(users) = self.users() else { return out };
        for (name, _) in users.names(owner).unwrap_or_default() {
            if check_user_name(&name).is_err() {
                continue;
            }
            match users.get(owner, &name) {
                Ok(Some(v)) => {
                    out.retain(|(n, _)| *n != name);
                    out.push((name, v));
                }
                Ok(None) => {}
                Err(e) => eprintln!("secret {name} of {owner}: {e}"),
            }
        }
        out
    }

    /// The value and the store it came from.
    fn find(&self, name: &str) -> Result<Option<(Secret, &dyn SecretStore)>, Error> {
        for s in &self.stores {
            if let Some(v) = s.get(name)? {
                return Ok(Some((v, s.as_ref())));
            }
        }
        Ok(None)
    }

    /// For code inside botd that needs a value; harnesses get theirs through `harness_env`.
    pub fn get(&self, name: &str) -> Result<Option<Secret>, Error> {
        Ok(self.find(name)?.map(|(v, _)| v))
    }

    /// The store whose value wins for `name` (`env` or `sealed`), and whether it can be written.
    pub fn source(&self, name: &str) -> Result<Option<(&'static str, bool)>, Error> {
        Ok(self.find(name)?.map(|(_, s)| (s.kind(), s.writable())))
    }

    fn writable(&self) -> Result<&dyn SecretStore, Error> {
        self.stores.iter().find(|s| s.writable()).map(|s| s.as_ref()).ok_or(Error::ReadOnly)
    }

    pub fn put(&self, name: &str, value: &str) -> Result<Listed, Error> {
        check_saveable(name)?;
        check_value(value)?;
        redact::register(value);
        self.writable()?.put(name, value)?;
        self.list()?.into_iter().find(|l| l.name == name && l.writable).ok_or_else(|| Error::Store(format!("{name} was not saved")))
    }

    pub fn delete(&self, name: &str) -> Result<bool, Error> {
        check_saveable(name)?;
        self.writable()?.delete(name)
    }

    /// Names Bots can get, then botd's own SSO client secrets (`for_bots: false`), store
    /// by store, marking names an earlier store overrides. Other names botd keeps for
    /// itself (AUTH_PASSWORD, SUPERBOT_*) are left out.
    pub fn list(&self) -> Result<Vec<Listed>, Error> {
        let mut out: Vec<Listed> = Vec::new();
        for s in &self.stores {
            for name in s.names()?.into_iter().filter(|n| check_saveable(n).is_ok()) {
                let shadowed_by = out.iter().find(|l| l.name == name).map(|l| l.store);
                let for_bots = !server_secret(&name);
                out.push(Listed { name, store: s.kind(), writable: s.writable(), shadowed_by, for_bots });
            }
        }
        Ok(out)
    }

    /// Values to add to a Bot's environment: the winning value of every name, except
    /// those the harness already inherits (plain environment variables). So `NAME_FILE`
    /// arrives as `NAME`, and saved secrets arrive unless the environment sets the name.
    pub fn harness_env(&self) -> Vec<(String, Secret)> {
        self.harness_env_where(false)
    }

    /// What `harness_env` leaves out because local children inherit it from botd's own
    /// environment. A run elsewhere doesn't inherit anything, so it gets these too.
    pub fn inherited_harness_env(&self) -> Vec<(String, Secret)> {
        self.harness_env_where(true)
    }

    fn harness_env_where(&self, inherited: bool) -> Vec<(String, Secret)> {
        let mut seen: Vec<String> = Vec::new();
        let mut out = Vec::new();
        for s in &self.stores {
            for name in s.names().unwrap_or_default() {
                if seen.contains(&name) || check_name(&name).is_err() || server_secret(&name) {
                    continue;
                }
                seen.push(name.clone());
                match self.find(&name) {
                    Ok(Some((v, from))) => {
                        // Files can change after startup, so learn the value as it is now.
                        self.learn(from, &v);
                        if from.inherited(&name) == inherited {
                            out.push((name, v));
                        }
                    }
                    Ok(None) => {}
                    Err(e) => eprintln!("secret {name}: {e}"),
                }
            }
        }
        out
    }

    /// Teaches the redactor a value. Environment names are a guess from the name, so
    /// only random-looking values from the first store count.
    fn learn(&self, from: &dyn SecretStore, v: &Secret) {
        if self.stores.first().is_some_and(|first| std::ptr::addr_eq(first.as_ref(), from)) {
            redact::register_if_random(v.expose());
        } else {
            redact::register(v.expose());
        }
    }

    /// Teaches the redactor every value this can read.
    fn register_all(&self) -> usize {
        let mut n = 0;
        for s in &self.stores {
            for name in s.names().unwrap_or_default() {
                if let Ok(Some(v)) = s.get(&name) {
                    self.learn(s.as_ref(), &v);
                    n += 1;
                }
            }
        }
        for (user, v) in self.users.as_ref().map(|u| u.all_values()).unwrap_or_default() {
            redact::register_for(&user, v.expose());
            n += 1;
        }
        n
    }
}

static GLOBAL: OnceLock<Secrets> = OnceLock::new();

/// The secrets set up by `init`.
pub fn global() -> &'static Secrets {
    #[cfg(test)]
    return GLOBAL.get_or_init(|| {
        let path = crate::db::temp_path("secrets").join("app.sqlite");
        let c = sealed::connect(&path).unwrap();
        let users = sealed::UserSecrets::new(sealed::connect(&path).unwrap(), sealed::cipher());
        Secrets::new(vec![Box::new(EnvStore::fixed(&[])), Box::new(sealed::SealedStore::new(c, sealed::cipher()))]).with_users(users)
    });
    #[cfg(not(test))]
    GLOBAL.get().expect("secrets::init runs at startup")
}

#[derive(Debug)]
pub struct Report {
    pub key_source: String,
    pub created: bool,
    /// Plaintext approval inputs sealed on this start (an upgrade from an older botd).
    pub sealed: usize,
    /// Saved chat and approval rows a known secret was removed from.
    pub redacted: usize,
    pub discarded: usize,
    pub stored: usize,
}

/// Startup: find or make the master key, check it, seal plaintext left by older
/// versions, and redact known secrets already saved. Runs after `Db::open`, before
/// anything is served. An error means botd must not start.
pub fn init(db_path: &Path) -> Result<Report, String> {
    let c = sealed::connect(db_path)?;
    let forget = std::env::var("SUPERBOT_FORGET_SEALED").is_ok_and(|v| v == "1");
    // Known values are redacted from approval inputs before they're sealed, so learn them first.
    let env = EnvStore::process();
    for name in env.names().unwrap_or_default() {
        if let Ok(Some(v)) = env.get(&name) {
            redact::register_if_random(v.expose());
        }
    }
    let data_dir = db_path.parent().unwrap_or(Path::new("."));
    let (found, mut key_source) = match key::locate(data_dir)? {
        Some((k, source)) => (Some(k), source),
        None => (None, String::new()),
    };
    if let Some(k) = &found {
        k.register_redactions();
    }
    let (cipher, boot) = sealed::bootstrap(
        &c,
        found,
        || {
            let (k, source) = key::create(data_dir)?;
            k.register_redactions();
            key_source = source;
            Ok(k)
        },
        forget,
    )?;
    if forget && boot.discarded == 0 {
        eprintln!("SUPERBOT_FORGET_SEALED=1 is set, but the master key works, so nothing was dropped. Remove the setting.");
    }
    let cipher = sealed::install(cipher)?;
    let store = sealed::SealedStore::new(sealed::connect(db_path)?, Arc::clone(&cipher));
    let users = sealed::UserSecrets::new(sealed::connect(db_path)?, Arc::clone(&cipher));
    let secrets = Secrets::new(vec![Box::new(env), Box::new(store)]).with_users(users);
    let stored = secrets.stores[1].names().map_err(|e| e.to_string())?.len();
    secrets.register_all();
    let redacted = redact::scrub_rows(&c).map_err(|e| format!("database: {e}"))?;
    if boot.sealed + redacted + boot.discarded > 0 {
        sealed::purge_old_pages(&c).map_err(|e| format!("database: {e}"))?;
    }
    GLOBAL.set(secrets).map_err(|_| "secrets::init ran twice".to_string())?;
    Ok(Report { key_source, created: boot.created, sealed: boot.sealed, redacted, discarded: boot.discarded, stored })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secrets(env: &[(&str, &str)]) -> Secrets {
        let path = crate::db::temp_path("facade").join("app.sqlite");
        let c = sealed::connect(&path).unwrap();
        let users = sealed::UserSecrets::new(sealed::connect(&path).unwrap(), sealed::cipher());
        Secrets::new(vec![Box::new(EnvStore::fixed(env)), Box::new(sealed::SealedStore::new(c, sealed::cipher()))]).with_users(users)
    }

    #[test]
    fn a_users_secrets_reach_only_their_bots() {
        let s = secrets(&[("GITHUB_TOKEN", "team-wide-env-value")]);
        let a = format!("sk-ant-a-{}", crate::random_hex(12));
        s.put("OPENAI_API_KEY", "team-openai-value").unwrap();
        assert_eq!(s.user_put("ua", "ANTHROPIC_API_KEY", &a).unwrap().name, "ANTHROPIC_API_KEY");
        s.user_put("ua", "OPENAI_API_KEY", "a-openai-value").unwrap();
        s.user_put("ub", "GH_TOKEN", "b-gh-value").unwrap();
        let env = |u: &str| -> Vec<(String, String)> {
            let mut e: Vec<_> = s.harness_env_for(u).into_iter().map(|(k, v)| (k, v.expose().to_string())).collect();
            e.sort();
            e
        };
        let pair = |k: &str, v: &str| (k.to_string(), v.to_string());
        assert_eq!(env("ua"), [pair("ANTHROPIC_API_KEY", &a), pair("OPENAI_API_KEY", "a-openai-value")], "A's own beat the team's");
        assert_eq!(env("ub"), [pair("GH_TOKEN", "b-gh-value"), pair("OPENAI_API_KEY", "team-openai-value")], "none of A's");
        assert_eq!(env("uc"), [pair("OPENAI_API_KEY", "team-openai-value")]);
        assert_eq!(redact::text_for(&["ua"], &a), redact::MARK, "redacted from A's Bots");
        assert_eq!(redact::text_for(&["ub"], "deploy to b-gh-value"), "deploy to [redacted]");
        assert_eq!(redact::text(&a), a.as_str(), "not from everyone's: any member can save any value");
        assert_eq!(redact::text_for(&["ub"], &a), a.as_str());
        for bad in ["PATH", "BOT_TOKEN", "SSO_X_CLIENT_SECRET", "LINODE_TOKEN", "TURNSTILE_SECRET", "lower"] {
            assert!(matches!(s.user_put("ua", bad, "v"), Err(Error::Invalid(_))), "{bad}");
        }
        assert!(s.list().unwrap().iter().all(|l| l.name != "ANTHROPIC_API_KEY"), "not in the server-wide list");
        assert_eq!(s.user_list("ub").unwrap().len(), 1);
        assert!(!s.user_delete("ub", "ANTHROPIC_API_KEY").unwrap());
        assert_eq!(s.user_forget("ua").unwrap(), 2);
        assert!(s.user_list("ua").unwrap().is_empty());
        assert!(matches!(Secrets::new(vec![]).user_put("ua", "X_TOKEN", "v"), Err(Error::ReadOnly)));
        redact::forget_for("ua", &a);
        redact::forget_for("ua", "a-openai-value");
        redact::forget_for("ub", "b-gh-value");
        redact::forget("team-openai-value");
    }

    #[test]
    fn names_are_checked() {
        for ok in ["OPENAI_API_KEY", "A", "_X", "GH_TOKEN2"] {
            assert!(check_name(ok).is_ok(), "{ok}");
        }
        for bad in ["", "lower", "2X", "A-B", "A B", "PATH", "AUTH_PASSWORD", "SUPERBOT_MASTER_KEY", "BOT_TOKEN", "LD_PRELOAD", &"A".repeat(129)] {
            assert!(check_name(bad).is_err(), "{bad}");
        }
        assert!(check_value("").is_err() && check_value("a\0b").is_err() && check_value(&"x".repeat(MAX_VALUE + 1)).is_err());
    }

    #[test]
    fn environment_wins_and_stored_values_reach_harnesses() {
        let npm = crate::db::temp_path("npm").join("token");
        std::fs::write(&npm, "npm-from-file\n").unwrap();
        let s = secrets(&[
            ("GITHUB_TOKEN", "from-env-value-1"),
            ("NPM_TOKEN_FILE", npm.to_str().unwrap()),
            ("AUTH_PASSWORD", "pw"),
            ("SUPERBOT_MASTER_KEY_FILE", "/k"),
        ]);
        let stored = format!("stored-{}", crate::random_hex(8));
        s.put("GITHUB_TOKEN", "from-db-value-1").unwrap();
        let l = s.put("OPENAI_API_KEY", &stored).unwrap();
        assert_eq!(l, Listed { name: "OPENAI_API_KEY".into(), store: "sealed", writable: true, shadowed_by: None, for_bots: true });
        assert_eq!(s.get("GITHUB_TOKEN").unwrap().unwrap().expose(), "from-env-value-1");
        assert_eq!(s.get("OPENAI_API_KEY").unwrap().unwrap().expose(), stored);

        let list = s.list().unwrap();
        assert!(!list.iter().any(|l| l.name == "AUTH_PASSWORD" || l.name.starts_with("SUPERBOT_")), "{list:?}");
        let gh: Vec<_> = list.iter().filter(|l| l.name == "GITHUB_TOKEN").collect();
        assert_eq!(gh.len(), 2);
        assert_eq!((gh[0].store, gh[0].shadowed_by), ("env", None));
        assert_eq!((gh[1].store, gh[1].shadowed_by), ("sealed", Some("env")));
        assert_eq!(s.source("GITHUB_TOKEN").unwrap(), Some(("env", false)), "the saved one can't replace it");
        assert_eq!(s.source("NPM_TOKEN").unwrap(), Some(("env", false)));
        assert_eq!(s.source("OPENAI_API_KEY").unwrap(), Some(("sealed", true)));
        assert_eq!(s.source("NOPE").unwrap(), None);

        let env: Vec<(String, String)> = s.harness_env().into_iter().map(|(k, v)| (k, v.expose().to_string())).collect();
        assert_eq!(
            env,
            [("NPM_TOKEN".to_string(), "npm-from-file".to_string()), ("OPENAI_API_KEY".to_string(), stored.clone())],
            "files arrive under their base name; inherited and shadowed values aren't repeated"
        );
        let inherited: Vec<String> = s.inherited_harness_env().into_iter().map(|(k, _)| k).collect();
        assert!(inherited.contains(&"GITHUB_TOKEN".to_string()) && !inherited.contains(&"OPENAI_API_KEY".to_string()), "{inherited:?}");
        assert!(!inherited.iter().any(|k| k == "AUTH_PASSWORD" || k.starts_with("SUPERBOT_")), "never server secrets: {inherited:?}");
        assert_eq!(redact::text(&stored), redact::MARK, "a saved value is redacted from then on");
        let rotated = format!("npm_{}", crate::random_hex(12));
        std::fs::write(&npm, &rotated).unwrap();
        assert!(s.harness_env().iter().any(|(k, v)| k == "NPM_TOKEN" && v.expose() == rotated));
        assert_eq!(redact::text(&rotated), redact::MARK, "a file changed after startup is redacted before a Bot gets it");
        redact::forget(&rotated);

        assert!(s.delete("OPENAI_API_KEY").unwrap());
        assert!(!s.delete("OPENAI_API_KEY").unwrap());
        assert!(matches!(s.put("PATH", "x"), Err(Error::Invalid(_))));
        assert_eq!(format!("{:?}", s.get("GITHUB_TOKEN").unwrap().unwrap()), "[redacted]");
        redact::forget(&stored);
    }

    #[test]
    fn sso_client_secrets_are_saved_but_never_reach_bots() {
        let s = secrets(&[("SSO_GOOGLE_CLIENT_SECRET", "from-env-value-2"), ("SSO_ENTRA_TENANT", "x")]);
        let value = format!("entra-{}", crate::random_hex(12));
        assert!(check_name("SSO_ENTRA_CLIENT_SECRET").is_err(), "Bots can't be given an SSO_ name");
        let l = s.put("SSO_ENTRA_CLIENT_SECRET", &value).unwrap();
        assert_eq!((l.store, l.for_bots), ("sealed", false));
        assert_eq!(s.get("SSO_ENTRA_CLIENT_SECRET").unwrap().unwrap().expose(), value);
        assert!(s.harness_env().is_empty(), "neither the sealed nor the env client secret goes to a Bot");
        let names: Vec<_> = s.list().unwrap().into_iter().map(|l| (l.name, l.for_bots)).collect();
        assert_eq!(names, [("SSO_GOOGLE_CLIENT_SECRET".to_string(), false), ("SSO_ENTRA_CLIENT_SECRET".to_string(), false)]);
        for bad in ["SSO_ENTRA_TENANT", "SSO__CLIENT_SECRET", "SSO_ENTRA_client_SECRET", "SSO__PRIVATE_KEY", "SSO_APPLE_TEAM_ID", "SSO_PRIVATE_KEY"] {
            assert!(s.put(bad, "v").is_err(), "{bad}");
        }
        assert!(s.delete("SSO_ENTRA_CLIENT_SECRET").unwrap());
        redact::forget(&value);

        let key = format!("-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----", crate::random_hex(32));
        assert!(check_name("SSO_APPLE_PRIVATE_KEY").is_err());
        let l = s.put("SSO_APPLE_PRIVATE_KEY", &key).unwrap();
        assert_eq!((l.store, l.for_bots), ("sealed", false), "Apple's signing key is botd's own");
        assert!(s.harness_env().is_empty());
        assert!(s.delete("SSO_APPLE_PRIVATE_KEY").unwrap());
        redact::forget(&key);
    }

    #[test]
    fn hosting_and_turnstile_secrets_never_reach_bots() {
        let linode = crate::db::temp_path("linode").join("token");
        std::fs::write(&linode, "linode-from-file-7c1e\n").unwrap();
        let s = secrets(&[("LINODE_TOKEN_FILE", linode.to_str().unwrap()), ("TURNSTILE_SECRET", "0x4AAA-env")]);
        assert_eq!(s.get("LINODE_TOKEN").unwrap().unwrap().expose(), "linode-from-file-7c1e", "botd still reads it");
        s.put("TURNSTILE_SECRET", "0x4AAA-sealed").unwrap();
        assert!(s.harness_env().is_empty(), "not from a file, the environment, or the store");
        assert!(s.list().unwrap().iter().all(|l| !l.for_bots), "listed as botd's own");
        redact::forget("linode-from-file-7c1e");
        redact::forget("0x4AAA-sealed");
    }

    #[test]
    fn the_license_key_never_reaches_bots() {
        let f = crate::db::temp_path("license-env").join("license.key");
        std::fs::write(&f, "eyJ.license.file\n").unwrap();
        for vars in [vec![("LICENSE_KEY", "eyJ.license.inline")], vec![("LICENSE_KEY_FILE", f.to_str().unwrap())]] {
            let s = secrets(&vars);
            assert!(s.harness_env().is_empty() && s.inherited_harness_env().is_empty(), "{vars:?}");
            assert!(s.list().unwrap().is_empty(), "{vars:?}");
        }
        assert!(secrets(&[]).put("LICENSE_KEY", "x").is_err(), "installed through /api/license, not as a secret");
    }

    #[test]
    fn the_stripe_webhook_secret_never_reaches_bots() {
        let f = crate::db::temp_path("stripe-env").join("whsec");
        std::fs::write(&f, "whsec_from_file_test\n").unwrap();
        for vars in [vec![("STRIPE_WEBHOOK_SECRET", "whsec_inline_test")], vec![("STRIPE_WEBHOOK_SECRET_FILE", f.to_str().unwrap())]] {
            let s = secrets(&vars);
            assert!(s.harness_env().is_empty() && s.inherited_harness_env().is_empty(), "{vars:?}");
            assert!(s.list().unwrap().is_empty(), "{vars:?}");
        }
        assert!(secrets(&[]).put("STRIPE_WEBHOOK_SECRET", "whsec_x").is_err(), "set in the environment, not as a secret");
        assert!(secrets(&[]).user_put("ua", "STRIPE_WEBHOOK_SECRET", "whsec_x").is_err());
    }

    #[test]
    fn env_only_is_read_only() {
        let s = Secrets::new(vec![Box::new(EnvStore::fixed(&[]))]);
        assert!(matches!(s.put("X_TOKEN", "v"), Err(Error::ReadOnly)));
        assert!(matches!(s.delete("X_TOKEN"), Err(Error::ReadOnly)));
    }
}
