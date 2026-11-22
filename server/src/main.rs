//! botd: the server. Owns Bots, chats, memory files, and routines; runs each Bot
//! on its harness (Claude Code, Codex, Pi, or Hermes Agent); serves the web app and its API.

mod access_review;
#[cfg(test)]
mod access_review_http_tests;
mod accounts;
#[cfg(test)]
mod accounts_http_tests;
#[cfg(test)]
mod accounts_os_tests;
mod acl;
#[cfg(test)]
mod acl_http_tests;
mod adapters;
mod approvals;
mod audit;
mod audit_chain;
#[cfg(test)]
mod audit_chain_http_tests;
mod audit_export;
#[cfg(test)]
mod audit_http_tests;
#[cfg(test)]
mod auth_review_http_tests;
#[cfg(test)]
mod backup_deletion_http_tests;
mod backup_encryption;
#[cfg(test)]
mod backup_encryption_http_tests;
#[cfg(test)]
mod interface_http_tests;
#[cfg(test)]
mod command_analysis_http_tests;
mod chromium;
mod cron;
mod handover;
#[cfg(test)]
mod handover_http_tests;
#[cfg(test)]
mod harness_version_http_tests;
mod health_score;
#[cfg(test)]
mod health_score_http_tests;
mod isolation;
#[cfg(test)]
mod isolation_http_tests;
mod database_encryption;
#[cfg(test)]
mod database_encryption_http_tests;
mod db;
mod deprovision;
#[cfg(test)]
mod deprovision_http_tests;
mod erasure;
mod evidence;
#[cfg(test)]
mod evidence_http_tests;
mod file_retention;
#[cfg(test)]
mod file_retention_http_tests;
#[cfg(test)]
mod erasure_http_tests;
mod license;
#[cfg(test)]
mod license_http_tests;
mod machines;
mod mfa;
#[cfg(test)]
mod mfa_http_tests;
#[cfg(test)]
mod machines_backup_tests;
#[cfg(test)]
mod machines_bot_user_tests;
#[cfg(test)]
mod machines_egress_policy_tests;
#[cfg(test)]
mod machines_hardening_tests;
#[cfg(test)]
mod machines_hosts_tests;
#[cfg(test)]
mod machines_http_tests;
#[cfg(test)]
mod machines_incus_e2e_tests;
#[cfg(test)]
mod machines_incus_tests;
#[cfg(test)]
mod machines_lockdown_tests;
#[cfg(test)]
mod machines_mtls_tests;
#[cfg(test)]
mod machines_logins_tests;
#[cfg(test)]
mod machines_upkeep_tests;
#[cfg(test)]
mod machines_rebuild_tests;
#[cfg(test)]
mod machines_screens_tests;
#[cfg(test)]
mod machines_teammates_tests;
#[cfg(test)]
mod machines_offboard_tests;
#[cfg(test)]
mod machines_placement_tests;
#[cfg(test)]
mod machines_provider_backup_tests;
#[cfg(test)]
mod machines_resize_tests;
#[cfg(test)]
mod machines_region_tests;
#[cfg(test)]
mod machines_residency_tests;
mod passwd;
mod plans;
#[cfg(test)]
mod plans_http_tests;
mod signin_watch;
#[cfg(test)]
mod signin_watch_http_tests;
mod notify;
#[cfg(test)]
mod notify_http_tests;
mod obs;
#[cfg(test)]
mod obs_http_tests;
#[cfg(test)]
mod push_http_tests;
mod paths;
mod policy;
#[cfg(test)]
mod policy_http_tests;
#[cfg(test)]
mod prompts_http_tests;
mod rbac;
mod retention;
#[cfg(test)]
mod retention_http_tests;
mod roles;
#[cfg(test)]
mod roles_http_tests;
#[cfg(test)]
mod run_grants_http_tests;
#[cfg(test)]
mod run_tokens_http_tests;
mod runner;
mod sandbox;
mod scim;
#[cfg(test)]
mod scim_groups_http_tests;
#[cfg(test)]
mod scim_http_tests;
mod screen;
mod secrets;
mod server_backups;
#[cfg(test)]
mod server_backups_http_tests;
mod setup;
#[cfg(test)]
mod setup_http_tests;
#[cfg(test)]
mod shared_bots_http_tests;
mod scripts;
mod shell;
mod slots;
#[cfg(test)]
mod slots_http_tests;
mod signups;
#[cfg(test)]
mod signups_http_tests;
mod sso;
mod status;
#[cfg(test)]
mod status_http_tests;
mod support;
#[cfg(test)]
mod support_http_tests;
mod stripe;
mod tiers;
mod billing;
mod billing_mail;
#[cfg(test)]
mod tiers_http_tests;
#[cfg(test)]
mod billing_http_tests;
#[cfg(test)]
mod billing_mail_http_tests;
mod usage;
#[cfg(test)]
mod usage_http_tests;
mod storage;
#[cfg(test)]
mod storage_http_tests;
mod sweep;
mod users;
mod walk;
#[cfg(test)]
mod users_http_tests;
#[cfg(test)]
mod sso_http_tests;
#[cfg(test)]
mod sso_saml_http_tests;
#[cfg(test)]
mod sso_saml_sp_http_tests;
#[cfg(test)]
mod sso_social_http_tests;
#[cfg(test)]
mod teammate_accounts_http_tests;
mod teammate_logins;
mod teammate_removals;
#[cfg(test)]
mod teammate_removals_http_tests;
mod team_billing;
#[cfg(test)]
mod team_billing_http_tests;
mod teams;
#[cfg(test)]
mod teams_http_tests;
#[cfg(test)]
mod teams_offboard_tests;

use acl::{Access, Viewer, Visibility};
use approvals::{DecideError, Remember};
use audit::{Actor, Event, Outcome, Source, Who};
use axum::extract::{ConnectInfo, DefaultBodyLimit, Extension, Path, Query, Request, State};
use axum::http::{header, HeaderValue, Method, StatusCode};
use axum::middleware::{self, Next};
use axum::response::sse::{Event as SseEvent, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::{any, delete, get, patch, post, put};
use axum::{Json, Router};
use std::collections::HashMap;
use db::{BotPatch, Db};
use obs::log::{log_info, log_warn};
use rbac::{Perm, Principal, Role};
use runner::{App, Config};
use users::{Caller, SessionConfig};
use serde_json::{json, Value};
use std::convert::Infallible;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use tokio_stream::wrappers::ReceiverStream;
use tower_http::cors::{AllowOrigin, CorsLayer};

type AppState = Arc<App>;
type EventStream = std::pin::Pin<Box<dyn tokio_stream::Stream<Item = Result<SseEvent, Infallible>> + Send>>;

static WEB_DIR: OnceLock<Option<PathBuf>> = OnceLock::new();
static SITE_DIR: OnceLock<Option<PathBuf>> = OnceLock::new();

const COLORS: [&str; 11] = ["#f5f5f5", "#9a6b3f", "#e5484d", "#e8702e", "#e9a23b", "#4cc06a", "#4fb5a5", "#3b82f6", "#8b5cf6", "#e64a9c", "#7a7a7a"];
const SHAPES: [&str; 12] = ["waddle", "drop", "cloud", "bean", "onigiri", "peanut", "pebble", "square", "jelly", "gem", "gear", "heart"];

fn env(key: &str, default: &str) -> String {
    std::env::var(key).ok().filter(|v| !v.is_empty()).unwrap_or_else(|| default.into())
}

pub fn random_bytes(n: usize) -> Vec<u8> {
    use std::io::Read;
    let mut b = vec![0u8; n];
    std::fs::File::open("/dev/urandom").and_then(|mut f| f.read_exact(&mut b)).expect("read /dev/urandom");
    b
}

fn random_hex(n: usize) -> String {
    random_bytes(n).iter().map(|x| format!("{x:02x}")).collect()
}

pub fn short_id() -> String {
    random_hex(4)
}

fn is_loopback_host(host: &str) -> bool {
    ["127.0.0.1", "localhost", "::1"].contains(&host)
}

fn pick<'a>(a: &[&'a str]) -> &'a str {
    a[random_bytes(1)[0] as usize % a.len()]
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().is_some_and(|a| a == "database") {
        std::process::exit(database_encryption::cli(&args[1..]));
    }
    let port: u16 = env("PORT", "3000").parse().expect("PORT must be a number");
    let host = env("HOST", "127.0.0.1");
    let password = auth_password();
    let default_harness = env("DEFAULT_HARNESS", "claude");
    let exit = |e: String| -> ! {
        log_warn!("{e}");
        std::process::exit(1);
    };
    // An external secrets manager (ADR 0125), asked after the environment by everything
    // that reads a secret at startup, and by `secrets::global()` after that.
    let process_env = secrets::env::EnvStore::process();
    let external = secrets::external::from_env(&|k| env(k, ""), &process_env).unwrap_or_else(|e| exit(format!("Secrets backend: {e}")));
    let external_names = external.as_ref().map(|x| x.check().unwrap_or_else(|e| exit(format!("Secrets backend: {e}. botd won't start without its secrets (ADR 0125)."))));
    let external_shared = external.clone().map(secrets::external::Shared);
    let startup_store = secrets::external::Layered(std::iter::once(&process_env as &dyn secrets::SecretStore).chain(external_shared.as_ref().map(|s| s as &dyn secrets::SecretStore)).collect());
    let observe = obs::Settings::from_env(&|k| env(k, ""), &startup_store).unwrap_or_else(|e| exit(format!("Observability: {e}")));
    obs::log::set_format(observe.log);
    match (&external, external_names) {
        (Some(x), Some(n)) => log_info!("Secrets backend: {} ({n} names; SECRETS_BACKEND, ADR 0125).", x.describe()),
        _ => log_info!("Secrets backend: local (the environment and the sealed store; SECRETS_BACKEND=vault, azure-keyvault or gcp-secret-manager adds one, ADR 0125, ADR 0136)."),
    }
    obs::errors::install_panic_hook();
    obs::errors::start(&observe.errors);
    let status_page = status::Page::parse(&env("STATUS_PAGE", "")).unwrap_or_else(|e| exit(e));
    let break_glass = users::break_glass_flag(&env("AUTH_BREAK_GLASS", "")).unwrap_or_else(|e| exit(e));
    let mfa_pinned = mfa::policy_flag(&env("AUTH_MFA", "")).unwrap_or_else(|e| exit(e));
    let sessions = SessionConfig::from_env(&env("SESSION_IDLE_TIMEOUT", ""), &env("SESSION_MAX_AGE", "")).unwrap_or_else(|e| exit(e));
    let signin_alerts = signin_watch::Settings::from_env(&|k| env(k, "")).unwrap_or_else(|e| exit(format!("Sign-in alerts: {e}")));
    let sso = sso::Sso::from_env().unwrap_or_else(|e| exit(format!("SSO: {e}")));
    let signups = signups::Signups::from_env(&startup_store, &env("SIGNUPS", ""), &env("TURNSTILE_SITE_KEY", ""))
        .unwrap_or_else(|e| exit(format!("Sign-ups: {e}")));
    let mut control_plane = machines::ControlPlane::from_env(&startup_store, |k| env(k, ""))
        .unwrap_or_else(|e| exit(format!("Control plane: {e}")));
    let shared_bots = acl::SharedBots::parse(&env("SHARED_BOTS", ""), control_plane.routing != machines::route::Routing::Off)
        .unwrap_or_else(|e| exit(format!("Shared Bots: {e}")));
    let teams = teams::Settings::from_env(&|k| env(k, "")).unwrap_or_else(|e| exit(format!("Teams: {e}")));
    let resume_routines = handover::resume_on_enable(&env("ROUTINES_ON_ENABLE", "")).unwrap_or_else(|e| exit(e));
    let scim = scim::Scim::from_env(&env("SCIM", ""), &env("SCIM_DEFAULT_ROLE", ""), &env("SCIM_GROUPS", "")).unwrap_or_else(|e| exit(format!("SCIM: {e}")));
    let tiers = tiers::Tiers::from_env(|k| env(k, "")).unwrap_or_else(|e| exit(format!("Tiers: {e}")));
    for name in adapters::NAMES {
        adapters::get(name).expect("listed adapter").check_env(&|k| env(k, "")).unwrap_or_else(|e| exit(e));
    }
    let testing = license::testing_flag(&env("TESTING_MODE", "")).unwrap_or_else(|e| exit(e));
    let (payments, ignored_stripe) =
        billing::Billing::configured(&startup_store, &|k| env(k, ""), testing).unwrap_or_else(|e| exit(format!("Billing: {e}")));
    let notifier = notify::Notifier::from_env(&|k| env(k, ""), sessions).unwrap_or_else(|e| exit(format!("Notifications: {e}")));
    let (billing_mail, plan_mail_said) = billing_mail::configured(&|k| env(k, ""), payments.enabled(), notifier.smtp.as_ref(), notifier.links.base.as_deref())
        .unwrap_or_else(|e| exit(format!("Billing emails: {e}")));
    let plans = plans::Settings::from_env(&|k| env(k, ""), payments.enabled(), payments.checkout_enabled(), signups.enabled)
        .unwrap_or_else(|e| exit(format!("Pricing page: {e}")));
    let allow_no_auth = auth_startup(&host, &password, break_glass);
    secrets::redact::register(&password);
    if adapters::get(&default_harness).is_none() {
        log_warn!("DEFAULT_HARNESS must be one of: {}", adapters::NAMES.join(", "));
        std::process::exit(1);
    }
    let retention = audit::retention_days(&env("AUDIT_RETENTION_DAYS", "")).unwrap_or_else(|e| {
        log_warn!("{e}");
        std::process::exit(1);
    });
    let audit_export = audit_export::Settings::from_env(&|k| env(k, ""), &startup_store).unwrap_or_else(|e| exit(format!("Audit export: {e}")));
    let chat_retention = retention::days("CHAT_RETENTION_DAYS", &env("CHAT_RETENTION_DAYS", "")).unwrap_or_else(|e| exit(e));
    let session_retention = retention::days("HARNESS_SESSION_RETENTION_DAYS", &env("HARNESS_SESSION_RETENTION_DAYS", "")).unwrap_or_else(|e| exit(e));
    let teammate_files_retention = retention::days("TEAMMATE_FILES_RETENTION_DAYS", &env("TEAMMATE_FILES_RETENTION_DAYS", "")).unwrap_or_else(|e| exit(e));
    let bot_key = random_hex(32);
    secrets::redact::register(&bot_key);
    WEB_DIR.set(std::env::var("WEB_DIR").ok().map(PathBuf::from)).unwrap();
    SITE_DIR.set(std::env::var("SITE_DIR").ok().map(PathBuf::from)).unwrap();

    let root = |key: &str, default: &str| {
        paths::root(&env(key, default)).unwrap_or_else(|e| {
            log_warn!("{key}: {e}");
            std::process::exit(1);
        })
    };
    let data_dir = root("DATA_DIR", "data");
    let evidence = evidence::Settings::from_env(&|k| env(k, ""), &data_dir).unwrap_or_else(|e| exit(format!("Evidence bundles: {e}")));
    let workspace = root("WORKSPACE_DIR", "workspace");
    let db_path = paths::child(&data_dir, "app.sqlite").unwrap();
    let data_lock = database_encryption::lock_data_dir(&db_path).unwrap_or_else(|e| exit(format!("Database: {e}")));
    std::mem::forget(data_lock);
    let db_policy = database_encryption::Policy::from_env(&|k| env(k, "")).unwrap_or_else(|e| exit(format!("Database encryption: {e}")));
    let mut keys = secrets::Keys::locate(&data_dir).unwrap_or_else(|e| exit(format!("Secrets: {e}")));
    let (db_key, db_start) =
        database_encryption::prepare(&db_path, db_policy, &mut keys).unwrap_or_else(|e| exit(format!("Database encryption: {e}")));
    if let Some(k) = db_key {
        database_encryption::install(k);
    }
    let database = database_encryption::State::new(db_policy, db_start, &data_dir);
    let (db_line, db_warnings) = database_encryption::startup_lines(&database, &database_encryption::plain_copies(&data_dir));
    log_info!("Database encryption: {db_line} (ADR 0116).");
    for w in db_warnings {
        log_warn!("WARNING: {w}");
    }
    let db = Db::open(&db_path).expect("open database");
    match secrets::init(&db_path, keys, external) {
        Ok(r) => {
            log_info!("Master key: {}{}.", r.key_source, if r.created { " (new)" } else { "" });
            if r.sealed + r.redacted + r.discarded > 0 {
                log_info!("Secrets: sealed {} saved tool inputs, redacted {} saved rows, discarded {} sealed values.", r.sealed, r.redacted, r.discarded);
            }
            log_info!("Stored secrets: {}.", r.stored);
            if let Some((from, done)) = &r.rotated {
                log_info!(
                    "Master key rotated from {from}: sealed {} values again under the new key ({} already were). Remove the previous key now (docs/ops/master-key-rotation.md).",
                    done.resealed,
                    done.current
                );
                if done.unreadable > 0 {
                    log_warn!("Master key rotation: {} sealed values open with neither key and were left as they were.", done.unreadable);
                }
            }
            if let Some(from) = &r.previous_unused {
                log_warn!("{from} is set, but the master key already opens everything, so there is nothing to rotate. Remove it.");
            }
        }
        Err(e) => {
            log_warn!("Secrets: {e}");
            std::process::exit(1);
        }
    }
    let server_backups = server_backups::ServerBackups::from_env(&startup_store, &|k| env(k, ""), &data_dir)
        .unwrap_or_else(|e| exit(format!("Server backups: {e}")));
    // Machine enrollment's CA key is derived from the master key (ADR 0031).
    let bin_dir = std::env::current_exe().unwrap().parent().unwrap().to_path_buf();
    // Users' machines get the managed tiers' default harnesses unless told otherwise (ADR 0079).
    let managed_bins: Vec<&str> = tiers.managed_defaults().into_iter().filter_map(|h| adapters::get(h).map(|a| a.bin())).collect();
    let enrollment = machines::enroll::Enrollment::from_env(&|k| env(k, ""), &secrets::sealed::cipher(), &bin_dir)
        .unwrap_or_else(|e| exit(format!("Machine enrollment: {e}")))
        .map(|mut e| {
            e.upkeep.default_to(&managed_bins).unwrap_or_else(|err| exit(format!("Machine enrollment: {err}")));
            control_plane.enroll_with(e).unwrap_or_else(|e| exit(format!("Machine enrollment: {e}")))
        });

    let mut isolation = accounts::Isolation::from_env(|k| env(k, ""), &bin_dir, &data_dir).unwrap_or_else(|e| exit(format!("Isolation: {e}")));
    let teammate_accounts = accounts::teammates_flag(&env("ISOLATION_TEAMMATES", ""), isolation.is_some(), shared_bots == acl::SharedBots::Isolated)
        .unwrap_or_else(|e| exit(format!("Isolation: {e}")));
    if let Some(iso) = isolation.as_mut() {
        iso.teammates = teammate_accounts;
    }
    let screen_addr = screen::init_listen_addr(&env("SCREEN_ADDR", "")).unwrap_or_else(|e| exit(e));
    let chromium_sandbox = chromium::parse_sandbox(&env("SUPERBOT_CHROMIUM_SANDBOX", "")).unwrap_or_else(|e| exit(e));
    // Screens are X displays botd's account runs; any local account could open them.
    let screens = if isolation.is_some() { None } else { paths::child(&data_dir, "screens").and_then(screen::Screens::from_env) };
    if let Some(s) = &screens {
        s.check_ports().unwrap_or_else(|e| exit(format!("Screens: {e}")));
    }
    if let (Some(local), Some(machine)) = (&screens, enrollment.as_ref().and_then(|e| e.screens.as_ref())) {
        let (a, b) = local.ports();
        if a <= machine.ports.1 && machine.ports.0 <= b {
            exit(format!(
                "MACHINE_SCREEN_PORTS ({}-{}) overlaps this server's own screen ports ({a}-{b}); move one (SCREEN_BASE, MAX_SCREENS)",
                machine.ports.0, machine.ports.1
            ));
        }
    }
    let app = App::new(db, Config {
        data_dir,
        workspace,
        user_name: env("USER_NAME", "the user"),
        // `botctl` ships next to `botd`.
        bin_dir,
        api_url: format!("http://127.0.0.1:{port}"),
        bot_key: bot_key.clone(),
        run_timeout: Duration::from_secs(60 * env("RUN_TIMEOUT_MINUTES", "60").parse::<u64>().unwrap_or(60)),
        default_harness,
        sandbox_host: sandbox::host(),
        home: std::env::var_os("HOME").map(PathBuf::from),
    }, screens);
    let _ = app.tiers.set(Arc::new(tiers));
    let database_summary = json!({ "policy": database.policy.as_str(), "encrypted": database.encrypted() });
    let _ = app.database.set(database);
    log_info!("Tiers: {}.", app.tiers().describe());
    let run_cap = slots::parse_cap(&env("MAX_CONCURRENT_RUNS", "")).unwrap_or_else(|e| exit(e));
    let _ = app.run_cap.set(run_cap);
    match run_cap {
        Some(n) => log_info!("Runs at once: {n} on this server, and on a machine whose owner's tier sets no concurrentRuns; more wait their turn (MAX_CONCURRENT_RUNS, ADR 0073)."),
        None => log_info!("Runs at once: no cap on this server (MAX_CONCURRENT_RUNS=off); machines follow their owner's tier's concurrentRuns."),
    }
    let _ = app.shared_bots.set(shared_bots);
    app.db.set_teams_strict(teams.strict);
    let _ = app.teams.set(teams);
    log_info!("Teams: {} (ADR 0087).", teams.describe());
    app.status.set_enabled(status_page);
    log_info!("Status page: {} (STATUS_PAGE, ADR 0090).", if status_page { "on, at /status and /status.json" } else { "off" });
    let _ = app.resume_routines_on_enable.set(resume_routines);
    log_info!(
        "Shared Bots: {}.",
        match shared_bots {
            acl::SharedBots::Open => "open (a Bot acts with its owner's access and keys for everyone who uses it; SHARED_BOTS=isolated limits that)",
            acl::SharedBots::Isolated => "isolated (a run for someone other than its owner gets their access at most and only server-wide keys; new Bots are private)",
        }
    );
    match isolation {
        Some(iso) => {
            log_info!(
                "Isolation: each user's Bots run as their own account ({}<user id>), in {}/<user id>; harnesses: {}.",
                accounts::PREFIX,
                iso.root.display(),
                accounts::HARNESSES.join(", ")
            );
            if iso.teammates {
                log_info!(
                    "Isolation: a teammate's run of a shared Bot uses its own account ({}<hash>), in {}/<owner>-<teammate>, with the teammate's own harness logins (ADR 0064).",
                    accounts::TEAMMATE_PREFIX,
                    iso.root.display()
                );
                log_info!(
                    "Isolation: a teammate's account goes when they leave or lose the owner's Bots; their work is {} (ADR 0066).",
                    match (iso.offboard.files, iso.offboard.grace_days) {
                        (machines::offboard::Files::Archive, _) => "handed to the owner, in workspace/from-teammates (ISOLATION_TEAMMATE_FILES=delete deletes it)".to_string(),
                        (_, 0) => "deleted at once".to_string(),
                        (_, d) => format!("held aside and deleted after {d} days"),
                    }
                );
            } else if shared_bots == acl::SharedBots::Isolated {
                log_info!("Isolation: ISOLATION_TEAMMATES=off, so a teammate's run of a shared Bot uses its owner's account (ADR 0046).");
            }
            let mut own = vec![app.cfg.data_dir.clone(), PathBuf::from(".env")];
            own.extend(["SUPERBOT_MASTER_KEY_FILE", "SUPERBOT_MASTER_KEY_PREVIOUS_FILE"].iter().filter_map(|k| std::env::var_os(k).map(PathBuf::from)));
            for p in accounts::close_to_others(&own) {
                log_warn!("WARNING: other accounts can read {p}, which botd couldn't change. Per-user accounts must not read botd's files: chmod o-rwx it.");
            }
            if accounts::others_visible() {
                log_warn!("WARNING: other accounts' processes are visible in /proc, so Bots can read each other's command lines. Run botd with ProtectProc=invisible (deploy/install.sh --isolation sets it).");
            }
            let _ = app.isolation.set(Arc::new(iso));
        }
        None => log_info!(
            "Isolation: off (every Bot runs as this account and could read .env, the database and the master key). \
             New installs have it on; to opt in, re-run deploy/install.sh --isolation, or set ISOLATION=users with Docker Compose (deploy/README.md)."
        ),
    }
    app.start_isolation();
    teammate_removals::start(&app);
    let paused = handover::pause_already_disabled(&app, &Who { actor: Actor::system("bootstrap"), source: Source::default() });
    if paused > 0 {
        log_info!("Routines: paused {paused} that ran for disabled users (ADR 0047).");
    }
    for t in app.db.assigned_tiers().into_iter().filter(|t| app.tiers().get(t).is_none()) {
        log_warn!("WARNING: some users have tier \"{t}\", which TIERS_FILE no longer lists. They get the default tier ({}) until an admin picks another.", app.tiers().default_tier().name);
    }
    adapters::withhold(app.tiers().providers().iter().map(|p| p.key_secret.clone()));
    let saved = |k: &str| secrets::global().get(k).ok().flatten().is_some_and(|v| !v.expose().trim().is_empty());
    for p in app.tiers().providers().iter().filter(|p| !saved(&p.key_secret)) {
        log_warn!("WARNING: TIERS_FILE provider \"{}\" has no key: the secret its keySecret names isn't saved or set in botd's environment. Runs routed to it are refused until it is (botctl secret set).", p.name);
    }
    {
        let installed = adapters::installed();
        let here = (control_plane.routing != machines::route::Routing::On).then_some(installed.as_slice());
        let upkeep = control_plane.enrollment.as_ref().map(|e| &e.upkeep).filter(|_| control_plane.routing != machines::route::Routing::Off);
        let on_machines: Option<Vec<&str>> = upkeep.map(|u| {
            let defaults = app.tiers().managed_defaults();
            let lacking = u.lacks(&defaults.iter().filter_map(|h| adapters::get(h).map(|a| a.bin())).collect::<Vec<_>>());
            defaults.into_iter().filter(|h| adapters::get(h).is_some_and(|a| !lacking.contains(&a.bin()))).collect()
        });
        let (line, warnings) = app.tiers().default_harness_notes(&app.cfg.default_harness, here, on_machines.as_deref());
        if let Some(line) = line {
            log_info!("{line}");
        }
        for w in warnings {
            log_warn!("WARNING: {w}");
        }
    }
    secrets::redact::register(env("LICENSE_KEY", "").trim());
    app.license.set_testing(testing);
    app.license.load(|k| env(k, ""));
    let license = app.license.status();
    log_info!("License: {}", license.detail());
    for w in license.warnings(app.db.active_seats()).into_iter().filter(|w| *w != license.detail()) {
        log_warn!("WARNING: {w}");
    }
    if !license.usable() {
        log_warn!("WARNING: {}", license.detail());
    }
    if license.testing() {
        log_warn!("WARNING: testing mode is on (TESTING_MODE). No license, billing off; not for production.");
    }
    match runner::test_hook_secs(&env(runner::TEST_HOOK_TIMEOUT, "")) {
        Err(e) => exit(e),
        Ok(Some(s)) if license.testing() => log_warn!("WARNING: {} is set: every approval hook times out after {s} seconds.", runner::TEST_HOOK_TIMEOUT),
        Ok(Some(_)) => log_warn!("WARNING: {} is ignored: it only applies in testing mode.", runner::TEST_HOOK_TIMEOUT),
        Ok(None) => {}
    }

    // Each user's Bots work in that user's folders (ADR 0029). Files from before were
    // the owner account's.
    match isolation::migrate_workspace(&app.cfg.workspace, users::OPERATOR, &app.cfg.data_dir) {
        Ok(0) => {}
        Ok(n) => log_info!("Workspace: moved {n} shared files and folders into users/{}.", users::OPERATOR),
        Err(e) => exit(format!("WORKSPACE_DIR: couldn't move the shared files into users/{}: {e}", users::OPERATOR)),
    }
    match isolation::migrate_user_file(&app.cfg.data_dir, users::OPERATOR) {
        Ok(true) => log_info!("USER.md: moved to users/{}/USER.md.", users::OPERATOR),
        Ok(false) => {}
        Err(e) => exit(format!("DATA_DIR: couldn't move USER.md: {e}")),
    }

    // First start: create the primary Bot.
    if app.db.bots().is_empty() {
        let name = env("PRIMARY_BOT_NAME", "Assistant");
        let harness = default_harness_for(&app, users::OPERATOR);
        let bot = app.db.create_bot(&name, "#f5f5f5", "waddle", &harness, None, true);
        app.init_bot_files(&bot);
    }
    // First start, or the first after upgrading to users: the owner becomes the admin
    // that break-glass signs in as.
    users::ensure_operator(&app.db, &env("USER_NAME", "Owner"), std::env::var("OWNER_EMAIL").ok().as_deref());

    let auth_state = Arc::new(Auth {
        password: password.clone(),
        break_glass,
        allow_no_auth,
        hosts: allowed_hosts(&host, port, &env("ALLOWED_HOSTS", "")),
        trust_forwarded: env("TRUST_FORWARDED_FOR", "") == "1",
        sessions,
        sso,
        signups,
        machines: Arc::new(control_plane),
        scim,
        payments,
        mfa: mfa::Mfa::with_policy(mfa_pinned),
        watch: signin_watch::Watch::new(signin_alerts),
        ..Auth::new(Some(app.clone()))
    });
    log_info!("Control plane: {}.", auth_state.machines.describe());
    let recorded = app.db.machine_backup_stores();
    for w in auth_state.machines.offsite.as_deref().map(|o| [o.warnings(), o.unreachable(&recorded)].concat()).unwrap_or_default() {
        log_warn!("WARNING: {w}");
    }
    if auth_state.machines.enabled() {
        for w in machines::residency::warnings(&app, &auth_state.machines) {
            log_warn!("WARNING: {w}");
        }
    }
    if let Some(m) = auth_state.payments.meter() {
        let _ = app.meter.set(m);
    }
    if let Some(s) = auth_state.payments.seats() {
        let _ = app.team_seats.set(s);
    }
    let notifications = notify::load(&app.db);
    log_info!("Notifications: {}.", notifier.describe(&notifications));
    let notify_summary = json!({
        "email": notifier.smtp.is_some() && notifications.email.enabled,
        "webhook": notifications.webhook.enabled,
        "push": notifier.push.as_ref().map(|p| p.provider()),
        "bots": notifications.bots.len(),
    });
    let _ = app.notifier.set(Arc::new(notifier));
    if let Some(w) = &ignored_stripe {
        log_warn!("WARNING: {w}");
    }
    log_info!("Billing: {}.", billing::describe(auth_state.payments.enabled(), auth_state.payments.checkout_enabled(), app.meter.get().is_some(), app.tiers()));
    log_info!("Billing emails: {plan_mail_said}.");
    let (plans_line, plans_warnings) = plans.describe(app.tiers());
    log_info!("Pricing page: {plans_line} (ADR 0121).");
    for w in plans_warnings {
        log_warn!("WARNING: {w}");
    }
    let _ = app.plans.set(plans);
    if let Some(m) = billing_mail {
        let _ = app.billing_mail.set(Arc::new(m));
    }
    match auth_state.scim.enabled {
        true => log_info!(
            "SCIM: on at /scim/v2; new users get the {} role; groups {}.",
            auth_state.scim.default_role.as_str(),
            if auth_state.scim.groups { "are teams (SCIM_GROUPS=on)" } else { "off (SCIM_GROUPS=off)" }
        ),
        false => log_info!("SCIM: off (SCIM=off)."),
    }
    log_info!(
        "Sign-ups: {}.",
        match (auth_state.signups.enabled, auth_state.signups.turnstile.is_some()) {
            (false, _) => "off (SIGNUPS=off)",
            (true, true) => "on, with Turnstile",
            (true, false) => "on (set TURNSTILE_SECRET and TURNSTILE_SITE_KEY to add a bot check)",
        }
    );
    auth_state.sso.load_saved(&app.db);
    for p in &auth_state.sso.providers {
        let ready = p.not_ready().unwrap_or_else(|| "ready".into());
        log_info!("SSO: {} ({}, {}), {ready}; {}; just-in-time sign-up {}.", p.id, p.label, p.type_name(), p.audience(), p.jit_role.map_or("off", |r| r.as_str()));
    }
    let sso_ids: Vec<String> = auth_state.sso.providers.iter().map(|p| p.id.clone()).collect();
    let control_plane = auth_state.machines.clone();
    let _ = app.control_plane.set(control_plane.clone());
    let auth_state_scim = auth_state.scim.enabled;
    let auth_state_scim_groups = auth_state.scim.enabled && auth_state.scim.groups;
    let auth_state_billing = auth_state.payments.enabled();
    let auth_state_checkout = auth_state.payments.checkout_enabled();
    let mfa_policy = mfa::policy(&auth_state, &app.db);
    log_info!("Two-factor sign-in: required for {}{} (ADR 0094).", match mfa_policy { mfa::Policy::Off => "no one", mfa::Policy::Admins => "admins", mfa::Policy::All => "everyone" }, if mfa_pinned.is_some() { ", set by AUTH_MFA" } else { "" });
    log_info!("Sign-in alerts: {} (ADR 0104).", auth_state.watch.settings.describe());
    let watch = auth_state.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(60)).await;
            watch.watch.sweep(db::now());
        }
    });
    log_info!("Server backups: {} (ADR 0109).", server_backups.describe());
    if let Some(w) = server_backups.warning() {
        log_warn!("WARNING: {w}");
    }
    let machine_backups = control_plane.offsite.as_ref().map(|o| &o.s);
    backup_encryption::check(&server_backups, machine_backups).unwrap_or_else(|e| exit(format!("Backup encryption: {e}")));
    let backup_targets = backup_encryption::targets(&server_backups, machine_backups);
    let (encryption_line, encryption_warnings) = backup_encryption::startup_lines(server_backups.encryption, &backup_targets);
    log_info!("Backup encryption: {encryption_line} (ADR 0114).");
    for w in encryption_warnings {
        log_warn!("WARNING: {w}");
    }
    let server_backups_summary = json!({
        "offHost": server_backups.target.is_some(),
        "mode": server_backups.mode.as_str(),
        "store": server_backups.target.as_ref().map(|t| t.source.as_str()),
        "rpoHours": server_backups.target.as_ref().map(|_| server_backups.rpo_ms / 3_600_000),
        "retentionDays": server_backups.target.as_ref().and(server_backups.retention_days),
        "encryption": server_backups.encryption.as_str(),
        "unencrypted": backup_targets.iter().filter(|t| !t.encrypted).map(|t| t.id).collect::<Vec<_>>(),
    });
    let _ = app.server_backups.set(Arc::new(server_backups));
    let router = router(app.clone(), auth_state);
    let policy = app.db.global_policy();
    app.db.record(&Event::new(Actor::system("server"), "server.started").details(json!({
        "version": env!("CARGO_PKG_VERSION"),
        "defaultHarness": app.cfg.default_harness,
        "policyMode": policy.mode,
        "sandbox": policy.sandbox,
        "sandboxHost": app.cfg.sandbox_host,
        "auth": match (break_glass, password.is_empty()) {
            (true, false) => "sessions+password",
            (true, true) => "none",
            (false, _) => "sessions",
        },
        "mfaPolicy": mfa_policy.as_str(),
        "sessionIdleMinutes": sessions.idle_ms / 60_000,
        "sessionMaxMinutes": sessions.max_ms / 60_000,
        "auditRetentionDays": retention,
        "auditExport": audit_export.sink.as_ref().map(|s| json!({ "kind": s.kind(), "sink": s.shown })),
        "chatRetentionDays": chat_retention,
        "harnessSessionRetentionDays": session_retention,
        "teammateFilesRetentionDays": teammate_files_retention,
        "screens": app.screens.is_some(),
        "isolation": if app.isolation().is_some() { "users" } else { "off" },
        "isolationTeammates": app.teammate_accounts(),
        "isolationTeammateFiles": app.isolation().map(|i| i.offboard.files.as_str()),
        "sharedBots": app.shared_bots(),
        "sso": sso_ids,
        "controlPlane": control_plane.enabled(),
        "scim": auth_state_scim,
        "scimGroups": auth_state_scim_groups,
        "billing": auth_state_billing,
        "billingCheckout": auth_state_checkout,
        "billingEmails": app.billing_mail.get().is_some(),
        "notifications": notify_summary,
        "tiers": app.tiers().all().iter().map(|t| &t.name).collect::<Vec<_>>(),
        "defaultTier": app.tiers().default_tier().name,
        "tierHarnesses": app.tiers().all().iter().filter_map(|t| Some((t.name.clone(), json!(t.default_harness.as_ref()?)))).collect::<serde_json::Map<_, _>>(),
        "license": license.summary(),
        "logFormat": observe.log.as_str(),
        "metrics": observe.metrics.as_ref().map(|m| json!({ "loopback": m.addr.ip().is_loopback(), "token": m.token.is_some() })),
        "errorReports": observe.errors.dsn.is_some(),
        "statusPage": status_page,
        "serverBackups": server_backups_summary,
        "databaseEncryption": database_summary,
    })));
    license::start(app.clone());
    log_info!("Audit export: {} (ADR 0122).", audit_export.describe());
    audit_export::start(&app, audit_export);
    audit::start_retention(app.clone(), retention);
    secrets::external::start_audit(app.clone());
    audit_chain::start(app.clone());
    retention::start(app.clone(), retention::Settings { chat: chat_retention, sessions: session_retention, teammate_files: teammate_files_retention });
    server_backups::start(app.clone());
    evidence::start(app.clone(), evidence, sessions, mfa_pinned);
    backup_encryption::start(app.clone());
    database_encryption::start(app.clone());
    users::start_pruning(app.clone(), sessions);
    machines::hosts::load(&app, &control_plane).unwrap_or_else(|e| exit(format!("Incus hosts: {e}")));
    if observe.metrics.is_some() {
        app.db.metrics().want_host_use();
        app.db.metrics().want_tiers();
    }
    app.db.tracer().start(&observe.traces);
    machines::start(app.clone(), control_plane);
    if policy.mode == policy::Mode::Bypass {
        log_warn!(
            "WARNING: harness policy is bypass: Bots run every tool without asking. \
             Opt in to approvals with `botctl policy set global mode=ask` (see docs/backend.md)."
        );
    }
    if !policy.sandbox {
        log_warn!("Harness sandboxes: off. Turn them on with `botctl policy set global sandbox=on` (ADR 0055).");
    } else {
        let (with, can) = sandbox_harnesses(&app.cfg.sandbox_host);
        let cant: Vec<_> = with.into_iter().filter(|h| !can.contains(h)).collect();
        if !cant.is_empty() {
            log_warn!(
                "WARNING: harness sandboxes are on, but {}'s can't start here (no unprivileged user namespaces, or no working bubblewrap or socat), \
                 so those runs on this server go without. Install bubblewrap and socat, or allow user namespaces (ADR 0055).",
                cant.join(" and ")
            );
        }
    }

    app.recover();
    cron::start(app.clone());
    billing::start_metering(app.clone());
    billing_mail::start(app.clone());
    team_billing::start(app.clone());
    if app.screens.is_some() {
        let app = app.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(60)).await;
                app.screens.as_ref().unwrap().reap(|id| app.is_running(id)).await;
            }
        });
    }

    let listener = tokio::net::TcpListener::bind((host.as_str(), port)).await.expect("bind");
    log_info!("Listening on http://{host}:{port}");
    log_info!("Observability: {} (ADR 0089).", observe.describe());
    if let Some(m) = observe.metrics {
        let l = tokio::net::TcpListener::bind(m.addr).await.unwrap_or_else(|err| exit(format!("METRICS_LISTEN {}: {err}", m.addr)));
        tokio::spawn(obs::serve(l, app.clone(), m.token));
    }
    if let Some(e) = enrollment {
        let machine_listener = tokio::net::TcpListener::bind(e.listen).await.unwrap_or_else(|err| exit(format!("MACHINE_LISTEN {}: {err}", e.listen)));
        log_info!("Machines enroll at {} (listening on {}).", e.url, e.listen);
        // Bots on machines reach this API through the machine port, as if from loopback.
        let api = machines::enroll::Api { router: router.clone(), host: format!("127.0.0.1:{port}") };
        tokio::spawn(machines::enroll::serve(machine_listener, app.clone(), e, Some(api)));
    }
    log_info!("Harnesses on PATH: {}. Default: {}.", adapters::installed().join(", "), app.cfg.default_harness);
    log_info!(
        "Screens: {}.",
        match (app.screens.is_some(), app.isolation().is_some()) {
            (true, _) if screen_addr.is_loopback() => "on".to_string(),
            (true, _) => format!("on (viewers listen on {screen_addr}, SCREEN_ADDR)"),
            (false, true) => "off (per-user screens don't exist yet, so ISOLATION=users turns them off)".into(),
            (false, false) => "off (install Xvfb and openbox to turn them on)".into(),
        }
    );
    // The image's Chromium (ADR 0107); a bash install's Chrome for Testing keeps agent-browser's own choice.
    if let Some(browser) = chromium::browser() {
        if chromium_sandbox {
            tokio::spawn(async move {
                match chromium::check(&browser).await {
                    Ok(()) => log_info!("Chromium sandbox: on (checked: {} starts sandboxed).", browser.display()),
                    Err(e) => log_warn!(
                        "Chromium sandbox: on, but Chromium can't start sandboxed here, so Bots' browsers won't open: {e}. Give the container user namespaces (Compose: deploy/docker/seccomp-chromium.json), or set SUPERBOT_CHROMIUM_SANDBOX=off to run it without its sandbox (ADR 0107)."
                    ),
                }
            });
        } else {
            log_warn!("Chromium sandbox: off (SUPERBOT_CHROMIUM_SANDBOX=off): pages the Bots open run in Chromium without its sandbox (ADR 0107).");
        }
    }

    // On SIGTERM/SIGINT: stop agents (queued work runs after restart), then exit.
    let shutdown_app = app.clone();
    tokio::spawn(async move {
        use tokio::signal::unix::{signal, SignalKind};
        let (mut term, mut int) = (signal(SignalKind::terminate()).unwrap(), signal(SignalKind::interrupt()).unwrap());
        tokio::select! { _ = term.recv() => {}, _ = int.recv() => {} }
        shutdown_app.shutdown();
        for _ in 0..60 {
            if shutdown_app.is_idle() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        shutdown_app.db.tracer().flush(Duration::from_secs(3)).await;
        std::process::exit(0);
    });

    axum::serve(listener, router.into_make_service_with_connect_info::<SocketAddr>()).await.unwrap();
}

fn router(app: AppState, auth_state: Arc<Auth>) -> Router {
    let api = Router::new()
        .route("/state", get(state))
        .route("/events", get(events))
        .route("/harnesses/{name}/models", get(list_models))
        .route("/bots", get(list_bots).post(create_bot))
        .route("/bots/{id}", patch(update_bot).delete(delete_bot))
        .route("/bots/{id}/access", get(get_access).patch(update_access))
        .route("/bots/{id}/grants/{user}", put(put_grant).delete(delete_grant))
        .route("/bots/{id}/messages", get(list_messages).post(send_message))
        .route("/bots/{id}/read", post(mark_read))
        .route("/bots/{id}/stop", post(stop_bot))
        .route("/bots/{id}/routines", get(list_routines).post(create_routine))
        .route("/routines/{id}", patch(update_routine).delete(delete_routine))
        .route("/bots/{id}/screen", get(screen_info))
        .route("/bots/{id}/policy", get(get_bot_policy).put(put_bot_policy).delete(delete_bot_policy))
        .route("/policy", get(get_policy).put(put_policy))
        .route("/notifications", get(get_notifications).put(put_notifications))
        .route("/notifications/test", post(test_notifications))
        .route("/bots/{id}/notifications", get(get_bot_notifications).put(put_bot_notifications))
        .route("/policy/rules", get(list_rules).post(add_rule))
        .route("/policy/rules/{id}", delete(delete_rule))
        .route("/approvals", get(list_approvals))
        // A file write's full content passes through here, so allow big bodies.
        .route("/approvals/check", post(check_approval).layer(DefaultBodyLimit::max(32 * 1024 * 1024)))
        .route("/approvals/{id}/approve", post(approve))
        .route("/approvals/{id}/deny", post(deny))
        .route("/audit", get(list_audit))
        .route("/audit/export.csv", get(export_audit))
        .route("/audit/verify", get(audit_chain::get))
        .route("/audit/siem", get(audit_export::get))
        .route("/access-review", get(access_review::get))
        .route("/access-review/export.csv", get(access_review::export))
        .route("/access-review/complete", post(access_review::complete))
        .route("/retention", get(retention::get))
        .route("/retention/holds/{bot}", put(retention::put_hold).delete(retention::delete_hold))
        .route("/backups", get(server_backups::get).post(server_backups::copy_now))
        .route("/database", get(database_encryption::get))
        .route("/support/bundle", get(support::bundle))
        .route("/support/health-score", get(health_score::get))
        .route("/evidence", get(evidence::get))
        .route("/evidence/bundle", get(evidence::bundle))
        .route("/secrets", get(list_secrets))
        .route("/secrets/{name}", put(put_secret).delete(delete_secret))
        .route("/me/tier", get(my_tier))
        .route("/me/usage", get(usage::mine))
        .route("/tiers", get(list_tiers))
        .route("/tiers/{name}/move-bots", post(move_bots))
        .route("/usage", get(admin_usage))
        .route("/billing", get(billing::info))
        .route("/billing/checkout", post(billing::checkout))
        .route("/billing/portal", post(billing::portal))
        .route("/setup", get(setup::status).patch(setup::update))
        .route("/license", get(license::get).put(license::put).delete(license::delete))
        .route("/me/emails", get(billing_mail::get_mine).put(billing_mail::put_mine))
        .route("/me/push", get(notify::push::get_mine).put(notify::push::put_mine).delete(notify::push::delete_mine))
        .route("/me/secrets", get(list_my_secrets))
        .route("/me/secrets/{name}", put(put_my_secret).delete(delete_my_secret))
        .route("/ask", post(ask))
        .route("/handoff", post(handoff))
        .route("/auth/login", post(users::login))
        .route("/auth/logout", post(users::logout))
        .route("/auth/me", get(users::me))
        .route("/auth/mfa", get(mfa::status))
        .route("/auth/mfa/enroll", post(mfa::enroll))
        .route("/auth/mfa/confirm", post(mfa::confirm))
        .route("/auth/mfa/recovery-codes", post(mfa::new_recovery))
        .route("/auth/mfa/disable", post(mfa::disable))
        .route("/auth/mfa/policy", put(mfa::put_policy))
        .route("/auth/sso", get(sso::list))
        .route("/auth/sso/{id}/start", get(sso::start))
        .route("/auth/sso/{id}/callback", get(sso::callback).post(sso::callback_post))
        .route("/auth/sso/{id}/acs", post(sso::acs))
        .route("/auth/sso/{id}/metadata", get(sso::saml_metadata))
        .route("/auth/sso/{id}/slo", get(sso::slo_get).post(sso::slo_post))
        .route("/sso/{id}/saml", get(sso::saml_status))
        .route("/sso/{id}/saml/idp-metadata", put(sso::saml_import))
        .route("/users", get(users::list_users).post(users::create_user))
        .route("/users/{key}", get(users::get_user).patch(users::update_user))
        .route("/users/{key}/login-codes", post(users::create_login_code))
        .route("/users/{key}/sessions", delete(users::revoke_user_sessions))
        .route("/users/{key}/mfa", delete(mfa::reset))
        .route("/users/{key}/erase", post(erasure::erase))
        .route("/users/{key}/bots", get(users::user_bots))
        .route("/users/{key}/usage", get(usage::of_user))
        .route("/users/{key}/routines", get(handover::list))
        .route("/users/{key}/routines/resume", post(handover::resume_for))
        .route("/users/{key}/handover", post(handover::handover))
        .route("/users/{key}/secrets", get(list_user_secrets).delete(delete_user_secrets))
        .route("/users/{key}/isolation", get(accounts::http::get).post(accounts::http::ensure))
        .route("/users/{key}/harness-login", post(accounts::http::harness_login))
        .route("/users/{key}/identities", get(sso::list_identities).post(sso::link_identity))
        .route("/users/{key}/identities/{id}", delete(sso::unlink_identity))
        .route("/users/{key}/machine", get(machines::get).post(machines::request).delete(machines::destroy))
        .route("/users/{key}/region", get(machines::region::get_user).put(machines::region::set_user))
        .route("/users/{key}/machine/egress-policy", get(machines::egress_policy::get_user).put(machines::egress_policy::set_user))
        .route("/users/{key}/residency", get(machines::region::get_user).put(machines::residency::pin_user).delete(machines::residency::unpin_user))
        .route("/users/{key}/machine/suspend", post(machines::suspend))
        .route("/users/{key}/machine/resume", post(machines::resume))
        .route("/users/{key}/machine/resize", get(machines::resize::status).post(machines::resize))
        .route("/users/{key}/machine/enrollment", post(machines::enroll::issue_token))
        .route("/users/{key}/machine/certificates", delete(machines::enroll::revoke))
        .route("/users/{key}/machine/agent", get(machines::upkeep::get))
        .route("/users/{key}/machine/agent/upgrade", post(machines::upkeep::upgrade_now))
        .route("/users/{key}/machine/agent/hold", put(machines::upkeep::hold).delete(machines::upkeep::release))
        .route(
            "/users/{key}/machine/rebuild",
            get(machines::rebuild::get).post(machines::rebuild::request).delete(machines::rebuild::cancel_now),
        )
        .route("/users/{key}/machine/backups", get(machines::backup::list).post(machines::backup::create))
        .route("/users/{key}/machine/restore", get(machines::backup::restore_status).post(machines::backup::restore_request))
        .route("/users/{key}/machine/harnesses", post(machines::upkeep::harnesses_now))
        .route("/users/{key}/machine/bot-user", post(machines::botuser::now_for))
        .route("/users/{key}/machine/screens", get(machines::screens::list))
        .route("/users/{key}/machine/screens/{bot}", axum::routing::delete(machines::screens::close_now))
        .route("/users/{key}/machine/harness-login", post(machines::logins::admin_start))
        .route("/users/{key}/machine/harness-login/{id}", delete(machines::logins::admin_abort))
        .route("/users/{key}/machine/harness-login/{id}/input", post(machines::logins::admin_input))
        .route("/users/{key}/machine/harness-logins", get(machines::logins::admin_status))
        .route("/users/{key}/machine/harness-logins/{harness}", delete(machines::logins::admin_logout))
        .route("/users/{key}/machine/teammates/{teammate}/harness-logins", get(machines::logins::admin_teammate_status))
        .route("/users/{key}/machine/teammates/{teammate}/harness-logins/{harness}", delete(machines::logins::admin_teammate_logout))
        .route("/users/{key}/machine/folder-sync", get(machines::folder::get).post(machines::folder::now_copy))
        .route("/users/{key}/machine/teammates", get(machines::offboard::on_machine))
        .route("/users/{key}/machine/teammates/{teammate}/remove", post(machines::offboard::remove_now))
        .route("/users/{key}/placement", get(machines::placement).put(machines::assign).delete(machines::unassign))
        .route("/machines", get(machines::list_all))
        .route("/machines/placements", get(machines::placements))
        .route("/machines/resizes", get(machines::resize::list))
        .route("/machines/backups", get(machines::backup::list_all))
        .route("/machines/{id}/backups", delete(machines::backup::delete_all))
        .route("/machines/recovery", get(machines::recovery::get))
        .route("/machines/substrate", get(machines::substrate))
        .route("/machines/egress-policy", get(machines::egress_policy::get_server).put(machines::egress_policy::set_server))
        .route("/regions", get(machines::region::list))
        .route("/machines/hosts", get(machines::hosts::list))
        .route("/machines/hosts/{name}/recover", post(machines::hosts::recover))
        .route("/machines/hosts/{name}/drain", put(machines::hosts::drain).delete(machines::hosts::undrain))
        .route("/machines/legacy", get(machines::rebuild::legacy_list))
        .route("/machines/reconcile", post(machines::reconcile_now))
        .route("/machines/teammate-removals", get(machines::offboard::list_all))
        .route("/users/{key}/teammate-accounts", get(teammate_removals::of_user))
        .route("/users/{key}/teammate-accounts/{teammate}/remove", post(teammate_removals::remove_now))
        .route("/isolation/teammate-removals", get(teammate_removals::list_all))
        .route("/teams", get(teams::list).post(teams::create))
        .route("/teams/{id}", get(teams::get).patch(teams::update).delete(teams::delete))
        .route("/teams/{id}/region", get(machines::region::get_team).put(machines::region::set_team))
        .route("/teams/{id}/residency", get(machines::region::get_team).put(machines::residency::pin_team).delete(machines::residency::unpin_team))
        .route("/teams/{id}/members/{user}", put(teams::put_member).delete(teams::delete_member))
        .route("/team", get(teams::mine))
        .route("/team/leave", post(teams::leave_mine))
        .route("/team/billing/checkout", post(team_billing::checkout))
        .route("/team/billing/portal", post(team_billing::portal))
        .route("/team/invites", post(teams::invite))
        .route("/team/invites/{id}", delete(teams::uninvite))
        .route("/team/members/{user}", patch(teams::set_role).delete(teams::remove))
        .route("/team/members/{user}/offboarding", get(teams::offboarding))
        .route("/team/members/{user}/machine", post(teams::give_machine))
        .route("/team/members/{user}/machine/suspend", post(teams::suspend))
        .route("/team/members/{user}/machine/resume", post(teams::resume))
        .route("/me/team-invites", get(teams::my_invites))
        .route("/me/team-invites/{id}", delete(teams::decline))
        .route("/me/team-invites/{id}/accept", post(teams::accept))
        .route("/machine", get(machines::mine))
        .route("/machine/harness-login", post(machines::logins::my_start))
        .route("/machine/harness-login/{id}", delete(machines::logins::my_abort))
        .route("/machine/harness-login/{id}/input", post(machines::logins::my_input))
        .route("/machine/harness-logins", get(machines::logins::my_status))
        .route("/machine/harness-logins/{harness}", delete(machines::logins::my_logout))
        .route("/machine/teammate/{owner}/harness-login", post(machines::logins::teammate_start))
        .route("/machine/teammate/{owner}/harness-login/{id}", delete(machines::logins::teammate_abort))
        .route("/machine/teammate/{owner}/harness-login/{id}/input", post(machines::logins::teammate_input))
        .route("/machine/teammate/{owner}/harness-logins", get(machines::logins::teammate_status))
        .route("/machine/teammate/{owner}/harness-logins/{harness}", delete(machines::logins::teammate_logout))
        .route("/roles", get(roles::list).post(roles::create))
        .route("/roles/{id}", get(roles::get).patch(roles::update).delete(roles::delete))
        .route("/roles/{id}/users/{user}", put(roles::assign).delete(roles::unassign))
        .route("/roles/{id}/teams/{team}/users/{user}", put(roles::assign_in_team).delete(roles::unassign_in_team))
        .route("/sessions", get(users::list_sessions))
        .route("/sessions/{id}", delete(users::revoke_session))
        .route("/signups", get(signups::list).post(signups::submit).layer(DefaultBodyLimit::max(signups::MAX_BODY)))
        .route("/signups/config", get(signups::config))
        .route("/plans", get(plans::json_page))
        .route("/signups/{id}", get(signups::get))
        .route("/signups/{id}/approve", post(signups::approve))
        .route("/signups/{id}/reject", post(signups::reject))
        .route("/scim/tokens", get(scim::list_tokens).post(scim::create_token))
        .route("/scim/tokens/{id}", delete(scim::revoke_token))
        .route("/scim/groups", get(scim::groups::list_links).post(scim::groups::link))
        .route("/scim/groups/{team}", delete(scim::groups::unlink))
        .route("/status/incidents", get(status::list).post(status::create))
        .route("/status/incidents/{id}", patch(status::edit).delete(status::delete))
        .route("/status/incidents/{id}/updates", post(status::add_update))
        .route_layer(middleware::from_fn(obs::note_route));
    // SCIM has its own bearer tokens and error format, so its own guard, not `auth` (ADR 0023).
    let scim_routes = Router::new()
        .route("/scim/v2/ServiceProviderConfig", get(scim::service_provider_config))
        .route("/scim/v2/ResourceTypes", get(scim::resource_types))
        .route("/scim/v2/ResourceTypes/{id}", get(scim::resource_type))
        .route("/scim/v2/Schemas", get(scim::schemas))
        .route("/scim/v2/Schemas/{id}", get(scim::schema))
        .route("/scim/v2/Users", get(scim::list_users).post(scim::create_user))
        .route("/scim/v2/Users/{id}", get(scim::get_user).put(scim::replace_user).patch(scim::patch_user).delete(scim::delete_user))
        // An Okta PUT carries the whole member list (ADR 0095).
        .route("/scim/v2/Groups", get(scim::groups::list).post(scim::groups::create).layer(DefaultBodyLimit::max(scim::groups::MAX_BODY)))
        .route(
            "/scim/v2/Groups/{id}",
            get(scim::groups::get).put(scim::groups::replace).patch(scim::groups::patch).delete(scim::groups::delete).layer(DefaultBodyLimit::max(scim::groups::MAX_BODY)),
        )
        .route("/scim/v2", any(scim::unknown))
        .route("/scim/v2/{*rest}", any(scim::unknown))
        .route_layer(middleware::from_fn(obs::note_route))
        .layer(DefaultBodyLimit::max(scim::MAX_BODY))
        .layer(middleware::from_fn_with_state(auth_state.clone(), scim::guard))
        .layer(Extension(auth_state.clone()));
    // Stripe signs its webhook; there are no credentials to check (ADR 0040).
    let billing_routes = Router::new()
        .route("/billing/stripe/webhook", post(billing::webhook))
        .route_layer(middleware::from_fn(obs::note_route))
        .layer(DefaultBodyLimit::max(billing::MAX_BODY))
        .layer(Extension(auth_state.clone()));
    Router::new()
        .route("/healthz", get(|| async { Json(json!({ "ok": true })) }))
        // Open to anyone, like /healthz: no tenant data (ADR 0090).
        .route("/status", get(status::html_page))
        .route("/status.json", get(status::json_page))
        // Open too: the tiers' published prices and limits (ADR 0121).
        .route("/pricing", get(plans::html_page))
        .merge(scim_routes)
        .merge(billing_routes)
        .merge(
            Router::new()
                .nest("/api", api)
                .route("/login", get(login_page))
                .route_layer(middleware::from_fn(obs::note_route))
                .fallback(get(web))
                .layer(middleware::from_fn_with_state(auth_state.clone(), auth))
                .layer(Extension(auth_state)),
        )
        .layer(cors_layer())
        .layer(obs::catch_panics())
        .layer(middleware::from_fn_with_state(app.clone(), obs::track))
        .with_state(app)
}

// Errors

#[derive(Debug)]
struct ApiError(StatusCode, String);

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(json!({ "error": self.1 }))).into_response()
    }
}

fn bad(msg: impl Into<String>) -> ApiError {
    ApiError(StatusCode::BAD_REQUEST, msg.into())
}

fn not_found(what: &str) -> ApiError {
    ApiError(StatusCode::NOT_FOUND, format!("{what} not found"))
}

type Res<T = Json<Value>> = Result<T, ApiError>;

// CORS for the SuperBot client (web/Electron). Native apps are not browser-bound.
fn cors_layer() -> CorsLayer {
    let raw = env("CORS_ORIGINS", "");
    let mut layer = CorsLayer::new()
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::PATCH,
            Method::DELETE,
            Method::OPTIONS,
        ])
        .allow_headers([
            header::AUTHORIZATION,
            header::CONTENT_TYPE,
            header::ACCEPT,
        ])
        .expose_headers([header::CONTENT_DISPOSITION]);
    layer = match raw.as_str() {
        "*" => layer.allow_origin(AllowOrigin::any()),
        "" => layer.allow_origin(AllowOrigin::list([
            HeaderValue::from_static("http://localhost:8081"),
            HeaderValue::from_static("http://localhost:19006"),
            HeaderValue::from_static("http://127.0.0.1:8081"),
            HeaderValue::from_static("http://127.0.0.1:19006"),
        ])),
        _ => {
            let origins: Vec<HeaderValue> = raw.split(',').filter_map(|o| o.trim().parse().ok()).collect();
            layer.allow_origin(AllowOrigin::list(origins))
        }
    };
    layer
}

// Auth: sessions (a cookie for the web app, a bearer token for the client and
// botctl), break-glass AUTH_PASSWORD (HTTP Basic, any username), or the Bots' token
// for `botctl`. Then one permission check per request (rbac::classify). ADR 0012.

struct Auth {
    password: String,
    /// AUTH_BREAK_GLASS: AUTH_PASSWORD signs in as the owner. Off: the password is ignored.
    break_glass: bool,
    /// Only when ALLOW_NO_AUTH=1 and loopback: empty password does not skip login on its own.
    allow_no_auth: bool,
    /// Host headers we answer to, lowercase.
    hosts: Vec<String>,
    /// TRUST_FORWARDED_FOR=1: take the client IP from X-Forwarded-For from any peer,
    /// not only a proxy on loopback. Set when botd is reachable only through a proxy.
    trust_forwarded: bool,
    sessions: SessionConfig,
    logins: audit::Logins,
    limiter: users::Limiter,
    /// Single sign-on providers and sign-ins in progress (ADR 0014).
    sso: sso::Sso,
    /// The public "Get started" form (ADR 0022).
    signups: signups::Signups,
    /// Per-user machines (ADR 0025). Off unless LINODE_TOKEN is set.
    machines: Arc<machines::ControlPlane>,
    /// SCIM provisioning (ADR 0023).
    scim: scim::Scim,
    /// Stripe subscriptions set users' tiers (ADR 0040), and with STRIPE_SECRET_KEY people
    /// buy and manage them on Stripe's pages (ADR 0042). Off unless STRIPE_WEBHOOK_SECRET is set.
    // Not `billing`: CodeQL reads that name as private data and flags every Stripe call.
    payments: billing::Billing,
    /// Second factors for password and code sign-ins (ADR 0094).
    mfa: mfa::Mfa,
    /// Suspicious sign-in patterns (ADR 0104).
    watch: signin_watch::Watch,
    /// The database: sessions and audit events. None in tests of auth alone.
    app: Option<AppState>,
}

impl Auth {
    fn new(app: Option<AppState>) -> Auth {
        Auth {
            password: String::new(),
            break_glass: true,
            allow_no_auth: false,
            hosts: Vec::new(),
            trust_forwarded: false,
            sessions: SessionConfig::default(),
            logins: audit::Logins::default(),
            limiter: users::Limiter::default(),
            sso: sso::Sso::default(),
            signups: signups::Signups::default(),
            machines: Arc::default(),
            scim: scim::Scim::default(),
            payments: billing::Billing::default(),
            mfa: mfa::Mfa::default(),
            watch: signin_watch::Watch::default(),
            app,
        }
    }

    fn record(&self, e: Event) {
        if let Some(app) = &self.app {
            app.db.record(&e);
        }
    }

    /// The owner account, which break-glass and ALLOW_NO_AUTH act as.
    fn operator(&self) -> Option<db::User> {
        self.app.as_ref()?.db.user(users::OPERATOR)
    }

    /// Logs the first good Basic-auth request of a client (see `audit::Logins`).
    /// Session sign-ins are logged once, by `users::login`.
    fn login_ok(&self, source: &Source, actor: &Actor, method: &str) {
        if let Some(id) = actor.id.as_deref().filter(|_| method == "password") {
            signin_watch::succeeded(self, source, id, method, false, None);
        }
        let client = format!("{}|{}", source.ip.as_deref().unwrap_or(""), source.user_agent.as_deref().unwrap_or(""));
        if self.logins.success(&client, db::now()) {
            let who = Who { actor: actor.clone(), source: source.clone() };
            self.record(who.event("auth.login").details(json!({ "method": method })));
        }
    }

    /// Logs a bad password, code, or token, throttled per IP. Never logs what was sent.
    fn login_failed(&self, source: &Source, method: &str, reason: Option<&str>) {
        // Not guesses: the right password refused for want of a second factor, and any password
        // once break-glass is off (browsers resend one they cached before, on every request).
        if !matches!(reason, Some("mfa_required" | "break_glass_off")) {
            signin_watch::failed(self, source, method, (method == "password").then_some(users::OPERATOR));
        }
        let client = format!("{}|{method}", source.ip.as_deref().unwrap_or(""));
        let Some(missed) = self.logins.failure(&client, db::now()) else { return };
        let actor = match method {
            "bot_token" => Actor::bot(None, None),
            "scim_token" => Actor::system("scim"),
            _ => Actor { id: None, ..Actor::operator() },
        };
        let actor = actor.method(method);
        let who = Who { actor, source: source.clone() };
        let mut details = json!({ "method": method, "unloggedSinceLast": missed });
        if let Some(r) = reason {
            details["reason"] = json!(r);
        }
        self.record(who.event("auth.login_failed").outcome(Outcome::Failure).details(details));
    }

    /// The live session for a token, or why there isn't one.
    fn session(&self, token: &str) -> Option<(db::Session, db::User)> {
        let app = self.app.as_ref()?;
        if !token.starts_with(users::SESSION_PREFIX) {
            return None;
        }
        let at = db::now();
        let found = app.db.live_session(&users::hash(token), at, self.sessions.idle_ms, self.sessions.max_ms)?;
        app.db.touch_session(&found.0.id, at);
        Some(found)
    }

    /// The Bot a token was issued to, acting for its owner, and for whomever its run is
    /// for (ADR 0046), so what it queues runs for them too.
    fn bot_actor(&self, bot_id: Option<&str>) -> Actor {
        let app = self.app.as_ref();
        match bot_id.and_then(|id| app?.db.bot(id)) {
            Some(b) => Actor { asker: app.map(|a| a.acting_for(&b)).filter(|a| *a != b.owner_id), ..Actor::for_bot(&b) },
            None => Actor::bot(bot_id, None),
        }
        .method("bot_token")
    }
}

/// The client's IP and user agent. Behind a proxy on loopback (Caddy on the same
/// host), the IP is the last X-Forwarded-For entry: the one the proxy added.
fn request_source(req: &Request, trust_forwarded: bool) -> Source {
    let peer = req.extensions().get::<ConnectInfo<SocketAddr>>().map(|c| c.0.ip().to_canonical());
    let forwarded = req
        .headers()
        .get_all("x-forwarded-for")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .map(str::trim)
        .rfind(|v| !v.is_empty())
        .and_then(|v| v.parse::<IpAddr>().ok());
    let ip = match forwarded {
        Some(f) if trust_forwarded || peer.is_some_and(|p| p.is_loopback()) => Some(f.to_canonical()),
        _ => peer,
    };
    let user_agent = req.headers().get(header::USER_AGENT).and_then(|v| v.to_str().ok()).map(|u| audit::clip(u.trim(), 256)).filter(|u| !u.is_empty());
    Source { ip: ip.map(|i| i.to_string()), user_agent }
}

/// AUTH_PASSWORD, or the file named by AUTH_PASSWORD_FILE. Empty when neither is set.
fn auth_password() -> String {
    use secrets::SecretStore;
    match secrets::env::EnvStore::process().get("AUTH_PASSWORD") {
        Ok(p) => p.map(|p| p.expose().to_string()).unwrap_or_default(),
        Err(e) => {
            log_warn!("{e}");
            std::process::exit(1);
        }
    }
}

/// With break-glass on (the default), refuse to start without AUTH_PASSWORD unless
/// ALLOW_NO_AUTH=1 on loopback only. With it off, people sign in with sessions only.
fn auth_startup(host: &str, password: &str, break_glass: bool) -> bool {
    if !break_glass {
        log_info!(
            "Break-glass password sign-in is off (AUTH_BREAK_GLASS=0){}. People sign in with sessions; \
             set AUTH_BREAK_GLASS=1 and restart to get back in with AUTH_PASSWORD.",
            if password.is_empty() { "" } else { "; AUTH_PASSWORD is ignored" }
        );
        return false;
    }
    if !password.is_empty() {
        return false;
    }
    if !is_loopback_host(host) {
        log_warn!("Refusing to listen on a public address without AUTH_PASSWORD.");
        std::process::exit(1);
    }
    if env("ALLOW_NO_AUTH", "") == "1" {
        log_warn!(
            "WARNING: ALLOW_NO_AUTH=1 with empty AUTH_PASSWORD on {host}. \
             Any local process that passes the Host allowlist can use the API without login. \
             Set AUTH_PASSWORD for real use."
        );
        return true;
    }
    log_warn!(
        "Refusing to start: set AUTH_PASSWORD (recommended), or set ALLOW_NO_AUTH=1 only for \
         loopback development (HOST=127.0.0.1, localhost, or ::1)."
    );
    std::process::exit(1);
}

/// `host:port`, with brackets for IPv6.
fn host_port(host: &str, port: u16) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

/// The server's own address and loopback names on its port, plus ALLOWED_HOSTS (comma separated).
pub fn allowed_hosts(host: &str, port: u16, extra: &str) -> Vec<String> {
    let names = [host, "localhost", "127.0.0.1", "::1"];
    let mut own: Vec<String> = names.map(|h| host_port(h, port)).into();
    if port == 80 {
        own.extend(names.map(|h| {
            if h.contains(':') {
                format!("[{h}]")
            } else {
                h.to_owned()
            }
        }));
    }
    let extra = extra
        .split(',')
        .map(str::trim)
        .filter(|h| !h.is_empty())
        .map(String::from);
    own.into_iter()
        .chain(extra)
        .map(|h| h.to_ascii_lowercase())
        .collect()
}

async fn auth(State(a): State<Arc<Auth>>, req: Request, next: Next) -> Response {
    let host = req
        .headers()
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if !a.hosts.iter().any(|h| h.eq_ignore_ascii_case(host)) {
        return (StatusCode::FORBIDDEN, "Unknown Host. Add it to ALLOWED_HOSTS.").into_response();
    }
    let source = request_source(&req, a.trust_forwarded);
    let (method, path) = (req.method().clone(), req.uri().path().to_string());
    let mut req = req;
    req.extensions_mut().insert(source.clone());
    // Signing in, the page to do it on, the public site, and asking for access need no credentials.
    let open = match method {
        Method::GET | Method::HEAD => path == "/login" || sso_path(&path).is_some() || site_file(&path).is_some() || path == "/api/signups/config" || path == plans::JSON_PATH,
        // Apple posts its answer to the callback (response_mode=form_post), SAML IdPs theirs to
        // the ACS and their logout messages to the SLO URL.
        Method::POST => path == "/api/auth/login" || matches!(sso_path(&path), Some("callback" | "acs" | "slo")) || path == "/api/signups",
        _ => false,
    };
    if open {
        return next.run(req).await;
    }
    let caller = match authenticate(&a, &req, &source) {
        Ok(c) => c,
        Err(res) => return *res,
    };
    // Per-tier metrics and traces (ADR 0118): the plan of whoever sent it, a Bot's owner's.
    if let Some(app) = a.app.as_ref().filter(|app| obs::wants_tiers(app)) {
        let owner = match caller.principal {
            Principal::Bot => caller.bot.as_deref().and_then(|id| app.db.bot(id)).map(|b| b.owner_id),
            Principal::User(_) => caller.user.as_ref().map(|u| u.id.clone()),
        };
        obs::note_tier(&req, owner.as_deref().map_or(obs::NO_TIER, |o| app.tier_of(o).name.as_str()));
    }
    let actor = match (&caller.principal, &caller.user) {
        (Principal::Bot, _) => a.bot_actor(caller.bot.as_deref()),
        (_, Some(u)) => users::actor(&a, u, caller.session.as_ref(), caller.method),
        (_, None) => Actor::operator().method(caller.method),
    };
    if caller.method != "session" && caller.principal != Principal::Bot {
        a.login_ok(&source, &actor, caller.method);
    }
    let by = Who { actor, source };
    let need = rbac::classify(&method, &path);
    let denied = |reason: &str, msg: String| {
        a.record(by.event("access.denied").outcome(Outcome::Denied).details(json!({ "method": method.as_str(), "path": path, "need": need.as_str(), "reason": reason })));
        ApiError(StatusCode::FORBIDDEN, msg).into_response()
    };
    // Older botctl names its Bot in a header. It must be the Bot the token names.
    let claimed = req.headers().get("x-superbot-bot").map(|v| v.to_str().unwrap_or("").to_string());
    if caller.principal == Principal::Bot && claimed.as_deref().is_some_and(|id| Some(id) != caller.bot.as_deref()) {
        return denied("bot_mismatch", "This token belongs to another Bot.".into());
    }
    if !caller.can(need) {
        let custom = caller.user.as_ref().and_then(|u| u.role_id.as_deref()).and_then(|id| a.app.as_ref()?.db.custom_role(id));
        let msg = match (caller.principal, custom) {
            (Principal::Bot, _) => "Only a signed-in person can do this, not a Bot.".to_string(),
            (_, Some(r)) => format!("Your role ({}) can't do this.", r.name),
            (Principal::User(r), None) => format!("Your role ({}) can't do this.", r.as_str()),
        };
        return denied("role", msg);
    }
    // A Bot acts for its owner, so it can't do what the owner's role can't (ADR 0029).
    if caller.principal == Principal::Bot
        && let Some(app) = &a.app
    {
        let owner = caller.bot.as_deref().and_then(|id| app.db.bot(id)).and_then(|b| app.db.user(&b.owner_id)).filter(|u| u.active());
        if !owner.is_some_and(|u| rbac::allows(Principal::User(u.role), need)) {
            return denied("owner_role", "This Bot's owner can't do this.".into());
        }
        // Nor anything for a person disabled since the run began (ADR 0124): the teammate the
        // token is bound to, else whoever asked for the Bot's run, in any SHARED_BOTS mode.
        let bound_off = caller.bot_for.as_deref().is_some_and(|u| !app.db.user(u).is_some_and(|u| u.active()));
        let asker_off = || caller.bot.as_deref().and_then(|id| app.db.bot(id)).map(|b| app.requested_by(&b)).and_then(|u| app.db.user(&u)).is_some_and(|u| !u.active());
        if bound_off || asker_off() {
            return denied("for_user_disabled", "The person this run is for is turned off.".into());
        }
    }
    // A cookie, a password the browser cached, or ALLOW_NO_AUTH rides along on any request the
    // browser makes, so writes on them must come from our own pages. Only a Bearer token is sent on
    // purpose. Some GETs act too (opening a screen starts it), so only plain reads are exempt.
    let safe = matches!(method, Method::GET | Method::HEAD | Method::OPTIONS) && matches!(need, rbac::Perm::Account | rbac::Perm::Read | rbac::Perm::Review);
    let ambient = !req.headers().get(header::AUTHORIZATION).and_then(|v| v.to_str().ok()).is_some_and(|h| h.starts_with("Bearer "));
    if ambient && !safe && !users::same_origin(req.headers()) {
        return denied("cross_site", "Cross-site request refused.".into());
    }
    let principal = caller.principal;
    req.extensions_mut().insert(principal);
    req.extensions_mut().insert(caller);
    req.extensions_mut().insert(by.clone());
    let res = next.run(req).await;
    if principal == Principal::Bot && res.status() == StatusCode::FORBIDDEN {
        a.record(by.event("access.denied").outcome(Outcome::Denied).details(json!({ "method": method.as_str(), "path": path })));
    }
    res
}

/// `/api/auth/sso` (the list), `/api/auth/sso/{id}/start`, `/api/auth/sso/{id}/callback`, and native
/// SAML's `/api/auth/sso/{id}/acs`, `/metadata`, and `/slo`: which one.
fn sso_path(path: &str) -> Option<&str> {
    match path.strip_prefix("/api/auth/sso")? {
        "" => Some("list"),
        rest => rest.strip_prefix('/').and_then(|r| r.split_once('/')).filter(|(id, step)| !id.is_empty() && !id.contains('/') && matches!(*step, "start" | "callback" | "acs" | "metadata" | "slo")).map(|(_, step)| step),
    }
}

/// Who sent this request, from (in order) the Authorization header, the session
/// cookie, or ALLOW_NO_AUTH. A request that sends bad credentials is refused even if
/// it also has good ones elsewhere.
fn authenticate(a: &Auth, req: &Request, source: &Source) -> Result<Caller, Box<Response>> {
    let h = req.headers().get(header::AUTHORIZATION).and_then(|v| v.to_str().ok()).unwrap_or("");
    let operator = |method: &'static str| Caller { principal: Principal::User(Role::Admin), user: a.operator(), session: None, method, bot: None, bot_for: None, bot_token: None, grants: rbac::Perms::NONE };
    let from_session = |(s, u): (db::Session, db::User)| match &a.app {
        Some(app) => Caller::person(&app.db, u, Some(s), "session"),
        None => Caller { principal: Principal::User(u.role), user: Some(u), session: Some(s), method: "session", bot: None, bot_for: None, bot_token: None, grants: rbac::Perms::NONE },
    };
    let fail = |method: &str, reason: Option<&str>, clear: bool| {
        a.login_failed(source, method, reason);
        Err(Box::new(unauthorized(a, req, clear)))
    };
    if let Some(t) = h.strip_prefix("Bearer ") {
        let t = t.trim();
        // Each run carries its own token, live only while that run is (ADR 0029, 0083).
        // A forged one, one from an earlier start or an ended run, one past its expiry,
        // one for a Bot since deleted, or one from before the Bot changed hands is refused.
        if t.starts_with(isolation::BOT_TOKEN_PREFIX) {
            let Some(app) = a.app.as_ref() else { return fail("bot_token", Some("bad_token"), false) };
            return match app.run_tokens.check(t, db::now()) {
                Ok(e) => match app.db.bot(&e.bot) {
                    None => fail("bot_token", Some("bot_gone"), false),
                    Some(b) if b.owner_id != e.owner => fail("bot_token", Some("bot_moved"), false),
                    Some(_) => {
                        // A Bot's call during its run (its approval hook, botctl) is part of the run's trace.
                        obs::trace::join_run(&e.run);
                        Ok(Caller { principal: Principal::Bot, user: None, session: None, method: "bot_token", bot: Some(e.bot), bot_for: e.for_user, bot_token: Some(e.id), grants: rbac::Perms::NONE })
                    }
                },
                Err(r) => fail("bot_token", Some(r.reason()), false),
            };
        }
        return match a.session(t) {
            Some(found) => Ok(from_session(found)),
            None if t.starts_with(users::SESSION_PREFIX) => fail("session", Some("unknown_or_expired"), false),
            // A provisioning token works only under /scim/v2 (ADR 0023); one sent here may have leaked.
            None if t.starts_with(scim::TOKEN_PREFIX) => fail("scim_token", Some("not_for_api"), false),
            None => fail("bot_token", None, false),
        };
    }
    if let Some(b) = h.strip_prefix("Basic ") {
        if !a.break_glass {
            // Browsers keep sending a password they cached before break-glass was turned off.
            if let Some(found) = users::cookie_token(req.headers()).and_then(|t| a.session(&t)) {
                return Ok(from_session(found));
            }
            return fail("password", Some("break_glass_off"), false);
        }
        let ok = base64_decode(b).is_some_and(|creds| {
            let pass = creds.splitn(2, |c| *c == b':').nth(1).unwrap_or_default();
            !a.password.is_empty() && same(pass, a.password.as_bytes())
        });
        if a.allow_no_auth {
            return Ok(operator(if ok { "password" } else { "none" }));
        }
        // Every API route takes the password, so guesses here count against the sign-in limiter too.
        let (ip, at) = (source.ip.clone().unwrap_or_default(), db::now());
        if let Some(retry) = a.limiter.blocked(&ip, at) {
            return Err(Box::new(users::too_many(retry)));
        }
        if !ok {
            a.limiter.fail(&ip, at);
            return fail("password", None, false);
        }
        // The password can't carry a second factor (ADR 0094): once the owner needs one,
        // it works only at sign-in, for a session.
        if mfa::guards_password(a) {
            if let Some(found) = users::cookie_token(req.headers()).and_then(|t| a.session(&t)) {
                return Ok(from_session(found));
            }
            a.login_failed(source, "password", Some("mfa_required"));
            let res = unauthorized(a, req, false);
            if res.status() != StatusCode::UNAUTHORIZED {
                return Err(Box::new(res));
            }
            let msg = "The owner account uses two-factor authentication, so the password works only at sign-in. Sign in at /login, or with botctl login, for a session.";
            return Err(Box::new(ApiError(StatusCode::UNAUTHORIZED, msg.into()).into_response()));
        }
        return Ok(operator("password"));
    }
    if !h.is_empty() {
        return fail("unknown_scheme", None, false);
    }
    if let Some(t) = users::cookie_token(req.headers()) {
        return match a.session(&t) {
            Some(found) => Ok(from_session(found)),
            None if a.allow_no_auth => Ok(operator("none")),
            None => fail("session", Some("unknown_or_expired"), true),
        };
    }
    if a.allow_no_auth {
        return Ok(operator("none"));
    }
    // No credentials at all: a browser's first visit, or a client that hasn't signed in.
    Err(Box::new(unauthorized(a, req, false)))
}

/// Not signed in. A browser opening a page without credentials goes to the
/// sign-in page instead of a 401. The Basic challenge (break-glass) is only offered
/// when the browser itself would show it to a person: not to the web app's own
/// fetches, or a cookie session that ended would pop up a password box.
fn unauthorized(a: &Auth, req: &Request, clear_cookie: bool) -> Response {
    let h = req.headers();
    let page = !req.uri().path().starts_with("/api/") && matches!(*req.method(), Method::GET | Method::HEAD);
    // HTTP Basic is offered only while the password alone can sign in (ADR 0094).
    let basic = a.break_glass && !mfa::guards_password(a);
    // With break-glass on, a page sent with a wrong password gets the browser's password box again.
    let mut res = if page && (!basic || !h.contains_key(header::AUTHORIZATION)) {
        (StatusCode::SEE_OTHER, [(header::LOCATION, "/login")]).into_response()
    } else {
        ApiError(StatusCode::UNAUTHORIZED, "Login required".into()).into_response()
    };
    let fetch = h.get("sec-fetch-mode").and_then(|v| v.to_str().ok()).is_some_and(|m| m != "navigate");
    if res.status() == StatusCode::UNAUTHORIZED && basic && !fetch && users::cookie_token(h).is_none() {
        res.headers_mut().insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Basic realm=\"Bots\""));
    }
    if clear_cookie {
        res.headers_mut().insert(header::SET_COOKIE, HeaderValue::from_static(users::clear_cookie()));
    }
    res
}

/// Approvals and policy changes are for people. Bots hold a token too, so without
/// this a Bot could approve its own request. The auth middleware already refuses
/// these by role; this is the second lock.
fn need_user(p: Principal) -> Res<()> {
    match p {
        Principal::User(_) => Ok(()),
        Principal::Bot => Err(ApiError(StatusCode::FORBIDDEN, "Only a signed-in person can do this, not a Bot.".into())),
    }
}

/// Constant-time comparison of what a caller sent with a secret. The time depends only on
/// `presented`'s length, so it shows neither where they differ nor how long the secret is.
fn same(presented: &[u8], secret: &[u8]) -> bool {
    if secret.is_empty() {
        return presented.is_empty();
    }
    let diff = presented.iter().enumerate().fold((presented.len() != secret.len()) as u8, |acc, (i, x)| acc | (x ^ secret[i % secret.len()]));
    std::hint::black_box(diff) == 0
}

fn base64_decode(s: &str) -> Option<Vec<u8>> {
    const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let (mut out, mut buf, mut bits) = (Vec::new(), 0u32, 0);
    for c in s.trim().bytes().filter(|c| *c != b'=') {
        buf = (buf << 6) | T.iter().position(|x| *x == c)? as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
        }
    }
    Some(out)
}

// The public site (`site/`: the landing page and the "Get started" form) and the
// built-in console (`web/`, at /console/). Both are embedded in the binary; set
// SITE_DIR or WEB_DIR to serve from disk while editing them. ADR 0022.

/// The `site/` file a public path serves.
fn site_file(path: &str) -> Option<&'static str> {
    Some(match path {
        "/" | "/index.html" => "index.html",
        "/get-started" | "/get-started/" => "get-started.html",
        "/site/site.css" => "assets/site.css",
        "/site/get-started.js" => "assets/get-started.js",
        "/site/mark.svg" => "assets/mark.svg",
        _ => return None,
    })
}

/// The public pages run only their own scripts, plus Cloudflare's when Turnstile is on.
pub const SITE_CSP: &str = "default-src 'self'; script-src 'self' https://challenges.cloudflare.com; frame-src https://challenges.cloudflare.com; \
     style-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'";

fn content_type(file: &str) -> &'static str {
    match file.rsplit('.').next() {
        Some("html") => "text/html; charset=utf-8",
        Some("js") => "text/javascript; charset=utf-8",
        Some("svg") => "image/svg+xml",
        _ => "text/css; charset=utf-8",
    }
}

fn site(file: &'static str) -> Response {
    let body = match SITE_DIR.get().and_then(|d| d.as_ref()) {
        Some(dir) => std::fs::read_to_string(dir.join(file)).unwrap_or_default(),
        None => match file {
            "index.html" => include_str!("../../site/index.html"),
            "get-started.html" => include_str!("../../site/get-started.html"),
            "assets/site.css" => include_str!("../../site/assets/site.css"),
            "assets/get-started.js" => include_str!("../../site/assets/get-started.js"),
            _ => include_str!("../../site/assets/mark.svg"),
        }
        .to_string(),
    };
    (
        [
            (header::CONTENT_TYPE, content_type(file)),
            (header::CACHE_CONTROL, "no-cache"),
            (header::CONTENT_SECURITY_POLICY, SITE_CSP),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
            (header::REFERRER_POLICY, "strict-origin-when-cross-origin"),
        ],
        body,
    )
        .into_response()
}

/// Where a signed-in person lands on the web. The Expo client at /app/ is the interface
/// for everyone; the console is an admin page only (ADR 0027, ADR 0032).
pub fn landing(p: Principal) -> &'static str {
    match p {
        Principal::User(Role::Admin) => "/console/",
        _ => "/app/",
    }
}

/// botd only sees /app/ when Caddy has no web client to serve there.
const NO_CLIENT: &str = r#"<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>SuperBot</title><p style="font:16px system-ui;margin:2rem">The SuperBot web app isn't installed on this server. Use the desktop or mobile app, or ask an admin to install the web client.</p>"#;

async fn web(uri: axum::http::Uri, principal: Option<Extension<Principal>>) -> Response {
    let path = uri.path();
    if let Some(file) = site_file(path) {
        return site(file);
    }
    let see = |to: &'static str| (StatusCode::SEE_OTHER, [(header::LOCATION, to)]).into_response();
    let admin = principal.is_some_and(|Extension(p)| p == Principal::User(Role::Admin));
    let file = match path {
        "/console" => return (StatusCode::PERMANENT_REDIRECT, [(header::LOCATION, "/console/")]).into_response(),
        p if p == "/app" || p.starts_with("/app/") => {
            return match admin {
                true => see("/console/"),
                false => (StatusCode::NOT_FOUND, [(header::CONTENT_TYPE, "text/html; charset=utf-8"), (header::CACHE_CONTROL, "no-cache")], NO_CLIENT).into_response(),
            };
        }
        p if p.starts_with("/console/") && !admin => return see("/app/"),
        "/console/" | "/console/index.html" => "index.html",
        "/console/app.js" => "app.js",
        "/console/styles.css" => "styles.css",
        _ => return (StatusCode::NOT_FOUND, "Not found").into_response(),
    };
    let body = match WEB_DIR.get().and_then(|d| d.as_ref()) {
        Some(dir) => std::fs::read_to_string(dir.join(file)).unwrap_or_default(),
        None => match file {
            "index.html" => include_str!("../../web/index.html"),
            "app.js" => include_str!("../../web/app.js"),
            _ => include_str!("../../web/styles.css"),
        }
        .to_string(),
    };
    (
        [
            (header::CONTENT_TYPE, content_type(file)),
            (header::CACHE_CONTROL, "no-cache"),
            (header::CONTENT_SECURITY_POLICY, CONSOLE_CSP),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
            (header::REFERRER_POLICY, "same-origin"),
        ],
        body,
    )
        .into_response()
}

/// The console is admin-only (ADR 0032): it runs only its own script, talks only to
/// this server, and can't be framed.
pub const CONSOLE_CSP: &str = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; \
     connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'";

// Live updates: one Server-Sent Events stream with everything.

async fn events(State(app): State<AppState>, Extension(a): Extension<Arc<Auth>>, Extension(c): Extension<Caller>, Extension(by): Extension<Who>) -> impl IntoResponse {
    // Each stream carries only the Bots its caller can see (ADR 0017).
    let mut filter = acl::StreamFilter::new(viewer(&app, &c, &by));
    let session = c.session.map(|s| s.id);
    let user = c.user.filter(|_| session.is_some()).map(|u| u.id);
    let bot = c.bot.filter(|_| c.principal == Principal::Bot);
    let bot_owner = bot.as_deref().and_then(|id| app.db.bot_owner(id));
    let bot_for = c.bot_for.filter(|_| bot.is_some());
    let bot_token = c.bot_token.filter(|_| bot.is_some());
    // The stream outlives the request that opened it, so it closes within seconds of
    // its session being revoked, expiring, or its user being disabled, and follows
    // role changes. A Bot's closes when its run ends (ADR 0083), the Bot is deleted,
    // changes hands, or its owner is disabled, and follows its owner's role. One bound
    // to a teammate (ADR 0048) closes once the Bot's latest run isn't theirs, never
    // taking the owner's access.
    let (tx, rx) = tokio::sync::mpsc::channel::<Result<SseEvent, Infallible>>(64);
    let mut sub = app.tx.subscribe();
    let cfg = a.sessions;
    const RESYNC: &str = r#"{"type":"resync"}"#;
    tokio::spawn(async move {
        let mut check = tokio::time::interval(SESSION_RECHECK);
        loop {
            tokio::select! {
                r = sub.recv() => {
                    let data = match r {
                        Ok(d) => d,
                        // A slow client that missed events is told to reload its state.
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => RESYNC.into(),
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                    };
                    let Some(mut data) = filter.apply(&app.db, &data) else { continue };
                    // Admins (people, not their Bots) see each Bot's model and route, as in `bot_view_for`.
                    if bot.is_none() && filter.viewer == Viewer::All
                        && let Ok(mut v) = serde_json::from_str::<Value>(&data)
                        && let Some(b) = v["bot"]["id"].as_str().and_then(|id| app.db.bot(id))
                    {
                        app.bot_admin_fields(&b, &mut v["bot"]);
                        data = v.to_string();
                    }
                    if tx.send(Ok(SseEvent::default().data(data))).await.is_err() {
                        break;
                    }
                }
                _ = check.tick(), if session.is_some() || bot.is_some() => {
                    let now = if let Some(id) = bot.as_deref() {
                        if !bot_token.as_deref().is_some_and(|t| app.run_tokens.is_live(t, db::now())) {
                            break;
                        }
                        match app.db.bot(id) {
                            Some(b) if bot_for.as_deref().is_some_and(|u| app.acting_for(&b) != u) => break,
                            Some(b) if Some(&b.owner_id) == bot_owner.as_ref() => match app.bot_viewer(&b) {
                                Viewer::Nobody => break,
                                v => v,
                            },
                            _ => break,
                        }
                    } else {
                        if !session.as_deref().is_some_and(|s| app.db.session_is_live(s, db::now(), cfg.idle_ms, cfg.max_ms)) {
                            break;
                        }
                        match user.as_deref().and_then(|id| app.db.user(id)) {
                            Some(u) if u.role == Role::Admin => Viewer::All,
                            Some(u) => Viewer::User { id: u.id, role: u.role },
                            None => Viewer::Nobody,
                        }
                    };
                    if now != filter.viewer {
                        filter.reset(now);
                        if tx.send(Ok(SseEvent::default().data(RESYNC))).await.is_err() {
                            break;
                        }
                    }
                }
                _ = tx.closed() => break,
            }
        }
    });
    ([("x-accel-buffering", "no")], Sse::new(Box::pin(ReceiverStream::new(rx)) as EventStream).keep_alive(KeepAlive::default()))
}

#[cfg(not(test))]
const SESSION_RECHECK: Duration = Duration::from_secs(5);
#[cfg(test)]
const SESSION_RECHECK: Duration = Duration::from_millis(100);

async fn login_page() -> Response {
    let body = match WEB_DIR.get().and_then(|d| d.as_ref()) {
        Some(dir) => std::fs::read_to_string(dir.join("login.html")).unwrap_or_default(),
        None => include_str!("../../web/login.html").to_string(),
    };
    ([(header::CONTENT_TYPE, "text/html; charset=utf-8"), (header::CACHE_CONTROL, "no-cache")], body).into_response()
}

// Bots

/// Whose plan applies to the caller: a person's own, a Bot's owner's (ADR 0033).
fn plan_user(app: &App, c: &Caller) -> String {
    match (&c.user, c.principal) {
        (Some(u), _) => u.id.clone(),
        (None, Principal::Bot) => c.bot.as_deref().and_then(|id| app.db.bot(id)).map_or_else(String::new, |b| b.owner_id),
        (None, _) => users::OPERATOR.into(),
    }
}

/// Every Bot the caller can see, each with their `access` to it.
fn visible_bots(app: &App, c: &Caller, by: &Who) -> Vec<Value> {
    viewer(app, c, by).bots(&app.db).iter().map(|(b, a)| bot_view_for(app, c, b, *a)).collect()
}

async fn state(State(app): State<AppState>, Extension(c): Extension<Caller>, Extension(by): Extension<Who>) -> Json<Value> {
    let bots = visible_bots(&app, &c, &by);
    let approvals = if rbac::allows(c.principal, Perm::Review) { visible_approvals(&app, &c, &by, Some("pending"), None, 200) } else { vec![] };
    // The owner keeps USER_NAME, as before users existed.
    let name = match &c.user {
        Some(u) if u.id != users::OPERATOR => u.name.clone(),
        _ => env("USER_NAME", "You"),
    };
    let role = match c.principal {
        Principal::User(r) => json!(r),
        Principal::Bot => json!("bot"),
    };
    // New Bots are the caller's (a Bot's are its owner's), so the harnesses offered are that tier's.
    let plan_id = plan_user(&app, &c);
    let me_id = plan_id.as_str();
    let tier = app.tier_of(me_id);
    let harnesses: Vec<&str> = adapters::installed().into_iter().filter(|h| tier.allows_harness(h)).collect();
    Json(json!({
        "me": { "name": name, "id": c.user.as_ref().map(|u| &u.id), "email": c.user.as_ref().and_then(|u| u.email.as_ref()), "role": role, "permissions": c.permissions(), "session": c.session.is_some(), "tier": tier.view() },
        "harnesses": harnesses,
        "defaultHarness": default_harness_for(&app, me_id),
        "bots": bots,
        "policy": app.db.global_policy(),
        "approvals": approvals,
    }))
}

/// Models and reasoning efforts the harness offers on this server. On a managed tier
/// the plan picks the model, so only admins may list them (ADR 0033). `?tier=` (admins):
/// only that tier's models for the harness, for picking one for a Bot on that tier.
async fn list_models(State(app): State<AppState>, Extension(c): Extension<Caller>, Path(name): Path<String>, Query(q): Query<HashMap<String, String>>) -> Res {
    if adapters::get(&name).is_none() {
        return Err(not_found("Harness"));
    }
    let admin = c.principal == Principal::User(Role::Admin);
    if !admin && (q.contains_key("tier") || app.tier_of(&plan_user(&app, &c)).managed()) {
        return Err(ApiError(StatusCode::FORBIDDEN, "Your plan picks the model.".into()));
    }
    let tier = match q.get("tier") {
        None => None,
        Some(t) => Some(app.tiers().get(t).cloned().ok_or_else(|| not_found("Tier"))?),
    };
    let harness = name.clone();
    let list = tokio::task::spawn_blocking(move || adapters::models(&name)).await.unwrap_or_default();
    let Some(routes) = tier.and_then(|t| t.routes) else { return Ok(Json(json!(list))) };
    // The tier's own models, named as the harness names them. "Default model" (no id)
    // is always offered by clients, so routes without a model add nothing here.
    let picked: Vec<adapters::ModelOption> = routes
        .iter()
        .filter(|r| r.harness == harness)
        .filter_map(|r| {
            let id = r.model.clone()?;
            let known = list.iter().find(|m| m.id == id || m.aliases.contains(&id));
            Some(adapters::ModelOption { label: known.map_or_else(|| id.clone(), |m| m.label.clone()), id, efforts: vec![], aliases: vec![] })
        })
        .collect();
    Ok(Json(json!(picked)))
}

/// The harness new Bots of this user get when none is asked for: their plan's on a
/// managed tier (ADR 0079), `DEFAULT_HARNESS` on an open one.
fn default_harness_for(app: &App, user_id: &str) -> String {
    app.tier_of(user_id).new_bot_harness(&app.cfg.default_harness).to_string()
}

/// `GET /api/me/tier`: your plan, its limits, and what you've used this month. No
/// model names. People only: a Bot's plan is its owner's.
async fn my_tier(State(app): State<AppState>, Extension(c): Extension<Caller>) -> Res {
    need_user(c.principal)?;
    let id = c.user.as_ref().map_or(users::OPERATOR, |u| u.id.as_str());
    storage::warm(&app, &[id.to_string()]).await;
    Ok(Json(tier_usage(&app, id)))
}

/// A user's tier and their use of it: runs this month, routine runs today (UTC), Bots,
/// and storage as last measured (`storage::warm` first for a recent number, ADR 0082).
pub(crate) fn tier_usage(app: &App, user_id: &str) -> Value {
    let at = db::now();
    let (period, day) = (app.billing_period(user_id, at), tiers::day(at));
    let mut v = app.tier_of(user_id).view();
    v["usage"] = json!({
        "period": period.key, "runs": app.db.runs_used(user_id, &period.key), "bots": app.db.owned_bot_count(user_id),
        "day": day, "routineRuns": app.db.routine_runs_used(user_id, &day),
        "tokens": app.db.tokens_used(user_id, period.start, period.end),
        "periodStart": period.start, "periodEnd": period.end, "periodSource": period.source.as_str(),
        "storage": storage::view(app, user_id),
    });
    v["machine"] = machines::resize::plan_view(app, user_id);
    v
}

/// `GET /api/usage` (admins): every user's plan, limits, and use, their machine against
/// the plan's size, and their subscription (ADR 0040). `over` names limits a user is
/// past, which happens after a downgrade: nothing is deleted, new use is refused.
async fn admin_usage(State(app): State<AppState>, Extension(a): Extension<Arc<Auth>>) -> Json<Value> {
    let all = app.db.users();
    storage::warm(&app, &all.iter().map(|u| u.id.clone()).collect::<Vec<_>>()).await;
    let users: Vec<Value> = all
        .iter()
        .map(|u| {
            let plan = tier_usage(&app, &u.id);
            let limits = &app.tier_of(&u.id).limits;
            let machine = app.db.user_machine(&u.id);
            let fits = |m: &db::Machine| limits.machine_type.as_ref().is_none_or(|t| *t == m.plan);
            let used = |k: &str| plan["usage"][k].as_u64().unwrap_or(0);
            let mut over = Vec::new();
            for (name, limit, n) in [
                ("bots", limits.max_bots.map(u64::from), used("bots")),
                ("monthlyRuns", limits.monthly_runs.map(u64::from), used("runs")),
                ("monthlyTokens", limits.monthly_tokens, used("tokens")),
                ("dailyRoutineRuns", limits.daily_routine_runs.map(u64::from), used("routineRuns")),
            ] {
                if limit.is_some_and(|l| n > l) {
                    over.push(name);
                }
            }
            if machine.as_ref().is_some_and(|m| !fits(m)) {
                over.push("machineType");
            }
            if plan["usage"]["storage"]["state"] == "over" {
                over.push("maxStorageMb");
            }
            json!({
                "user": { "id": u.id, "email": u.email, "name": u.name, "role": u.role, "status": u.status },
                "tier": u.tier,
                "plan": plan,
                "machine": machine.as_ref().map(|m| json!({ "tier": m.tier, "plan": m.plan, "state": m.state, "fits": fits(m), "resize": machines::resize::view(m) })),
                "subscription": app.db.subscription(&u.id),
                "customer": app.db.customer_of(&u.id),
                "over": over,
            })
        })
        .collect();
    Json(json!({ "users": users, "billing": a.payments.enabled(), "checkout": a.payments.checkout_enabled() }))
}

/// `GET /api/tiers` (admins): every tier with its routes, and the default.
async fn list_tiers(State(app): State<AppState>) -> Json<Value> {
    Json(app.tiers().admin_view())
}

/// `POST /api/tiers/{name}/move-bots` (admins) `{user?, dryRun?}`: moves the Bots of a
/// managed tier's users (or one of them) that run on another harness onto the tier's
/// default (ADR 0079). Nothing moves on its own: a Bot keeps its harness until an admin
/// does this. As with any harness change, its session, model and effort are cleared.
/// A Bot that is running or has work waiting is skipped, so a run never changes under it.
async fn move_bots(State(app): State<AppState>, Extension(by): Extension<Who>, Path(name): Path<String>, Json(v): Json<Value>) -> Res {
    let tier = app.tiers().get(&name).cloned().ok_or_else(|| not_found("Tier"))?;
    let Some(to) = tier.default_harness.clone() else {
        return Err(bad(format!("The {} tier is open: its Bots run on whatever harness they're set to, and new ones get DEFAULT_HARNESS.", tier.label)));
    };
    // It clears sessions and models, so a malformed request is refused, never widened.
    let Some(body) = v.as_object() else { return Err(bad("Send {\"user\"?: \"<user>\", \"dryRun\"?: true|false}.")) };
    if let Some(k) = body.keys().find(|k| !matches!(k.as_str(), "user" | "dryRun")) {
        return Err(bad(format!("Unknown field \"{k}\": send user and dryRun only.")));
    }
    let dry_run = match &v["dryRun"] {
        Value::Null => false,
        Value::Bool(b) => *b,
        _ => return Err(bad("dryRun must be true or false.")),
    };
    let user = match &v["user"] {
        Value::Null => None,
        Value::String(key) if !key.trim().is_empty() => Some(key.trim()),
        _ => return Err(bad("user must be a user's id or email.")),
    };
    let user = match user {
        None => None,
        Some(key) => {
            let u = users::need_user_key(&app, key)?;
            let on = app.tier_of(&u.id);
            if on.name != tier.name {
                return Err(ApiError(StatusCode::CONFLICT, format!("{} is on the {} plan, not {}.", u.email.as_deref().unwrap_or(&u.name), on.label, tier.label)));
            }
            Some(u.id)
        }
    };
    let (mut moved, mut skipped) = (Vec::new(), Vec::new());
    let bots = app.db.bots().into_iter().filter(|b| b.harness != to && user.as_ref().is_none_or(|u| *u == b.owner_id) && app.tier_of(&b.owner_id).name == tier.name);
    for b in bots {
        let busy = || json!({ "id": b.id, "name": b.name, "owner": b.owner_id, "from": b.harness, "reason": "busy" });
        let item = json!({ "id": b.id, "name": b.name, "owner": b.owner_id, "from": b.harness });
        if dry_run {
            if app.is_busy(&b.id) {
                skipped.push(busy());
            } else {
                moved.push(item);
            }
            continue;
        }
        // Checked and changed under the queue's lock: no run can start on the old settings in between.
        let patch = BotPatch { harness: Some(to.clone()), session_id: Some(None), model: Some(None), effort: Some(None), ..Default::default() };
        if app.while_idle(&b.id, || app.db.update_bot(&b.id, patch)).is_none() {
            skipped.push(busy());
            continue;
        }
        app.push_bot(&b.id);
        let after = need_bot(&app, &b.id)?;
        let details = json!({ "changes": bot_changes(&b, &after), "via": "tier_default", "tier": tier.name });
        app.db.record(&by.event("bot.updated").target("bot", &b.id).bot(&b.id).details(details));
        moved.push(item);
    }
    if !dry_run {
        let details = json!({ "to": to, "moved": moved.len(), "skipped": skipped.len(), "user": user });
        app.db.record(&by.event("tier.bots_moved").target("tier", &tier.name).details(details));
    }
    Ok(Json(json!({ "tier": tier.name, "to": to, "dryRun": dry_run, "moved": moved, "skipped": skipped })))
}

/// The Bot settings must fit the owner's tier: harness, model, and effort, and on
/// create a free Bot slot (ADR 0033). Admins too: the tier is the routing table.
/// `current` is the Bot's model when only its effort changes.
fn check_tier(app: &App, owner_id: &str, harness: &str, model: Option<&str>, effort: Option<&str>, current: Option<&str>) -> Res<()> {
    app.tier_of(owner_id).check(harness, model, effort, current).map_err(|e| ApiError(StatusCode::FORBIDDEN, e))
}


async fn list_bots(State(app): State<AppState>, Extension(c): Extension<Caller>, Extension(by): Extension<Who>) -> Json<Value> {
    Json(json!(visible_bots(&app, &c, &by)))
}

fn need_bot(app: &App, id: &str) -> Res<db::Bot> {
    app.db.bot(id).ok_or_else(|| not_found("Bot"))
}

/// Whose Bot access a request has. A Bot acts with its owner's: its token names it,
/// so it can't borrow another user's (ADR 0029). With isolated shared Bots, no more
/// than that of the person its run is for (ADR 0046).
fn viewer(app: &App, c: &Caller, _by: &Who) -> Viewer {
    match (c.principal, c.bot.as_deref().and_then(|id| app.db.bot(id))) {
        (Principal::Bot, Some(b)) if c.bot_for.as_deref().is_some_and(|u| app.acting_for(&b) != u) => Viewer::Nobody,
        (Principal::Bot, Some(b)) => app.bot_viewer(&b),
        (Principal::Bot, None) => Viewer::Nobody,
        _ => Viewer::of(c),
    }
}

/// The Bot a request acts as (`from`). A Bot is the one its token names and can't
/// name another (ADR 0029); a person names one they can operate.
fn acting_bot(app: &App, c: &Caller, by: &Who, named: Option<&str>) -> Res<db::Bot> {
    let named = named.map(str::trim).filter(|n| !n.is_empty());
    match c.principal {
        Principal::Bot => {
            let own = c.bot.as_deref().unwrap_or("");
            if named.is_some_and(|n| n != own) {
                return Err(ApiError(StatusCode::FORBIDDEN, "A Bot can only act as itself.".into()));
            }
            app.db.bot(own).ok_or_else(|| bad("Unknown Bot (BOT_ID)"))
        }
        Principal::User(_) => {
            let id = named.ok_or_else(|| bad("Say which Bot (from)"))?;
            need_bot_access(app, c, by, id, Access::Operate).map(|(b, _)| b)
        }
    }
}

/// The Bot, when the caller has at least `need` on it (ADR 0017). A Bot they can't see
/// is a 404, the same as one that doesn't exist; one they can see but not use is a 403.
fn need_bot_access(app: &App, c: &Caller, by: &Who, id: &str, need: Access) -> Res<(db::Bot, Access)> {
    let bot = need_bot(app, id)?;
    let has = viewer(app, c, by).access(&app.db, &bot);
    if has >= need {
        return Ok((bot, has));
    }
    // Its owner could, but the person it runs for can't: always worth a record.
    if let Some(for_user) = capped_by_asker(app, c, |owner| owner.access(&app.db, &bot) >= need) {
        let details = json!({ "reason": "asker_acl", "need": need, "has": has, "forUser": for_user });
        app.db.record(&by.event("access.denied").target("bot", id).bot(id).outcome(Outcome::Denied).details(details));
    } else if c.principal != Principal::Bot || has == Access::None {
        // The auth middleware already records every 403 a Bot gets.
        let details = json!({ "reason": "bot_acl", "need": need, "has": has });
        app.db.record(&by.event("access.denied").target("bot", id).bot(id).outcome(Outcome::Denied).details(details));
    }
    Err(match (has, c.principal) {
        (Access::None, _) => not_found("Bot"),
        (_, Principal::User(Role::Readonly)) => ApiError(StatusCode::FORBIDDEN, "Your role (readonly) can only view Bots.".into()),
        (_, _) if need == Access::Manage => ApiError(StatusCode::FORBIDDEN, "Only this Bot's owner or an admin can do this.".into()),
        _ => ApiError(StatusCode::FORBIDDEN, "You can view this Bot but not use it. Ask its owner for operator access.".into()),
    })
}

/// When the caller is a Bot running for someone other than its owner (ADR 0046) and
/// `owner_could` holds for its owner's own access: whom it runs for.
fn capped_by_asker(app: &App, c: &Caller, owner_could: impl FnOnce(&Viewer) -> bool) -> Option<String> {
    let b = c.bot.as_deref().filter(|_| c.principal == Principal::Bot).and_then(|id| app.db.bot(id))?;
    let for_user = app.acting_for(&b);
    (for_user != b.owner_id && owner_could(&Viewer::owner_of(&app.db, &b))).then_some(for_user)
}

/// Newest approvals for Bots the caller can see; `bot` narrows to one they can see.
fn visible_approvals(app: &App, c: &Caller, by: &Who, status: Option<&str>, bot: Option<&str>, limit: i64) -> Vec<db::Approval> {
    let viewer = viewer(app, c, by);
    if viewer == Viewer::All || bot.is_some() {
        return app.db.approvals(status, bot, limit);
    }
    let ids: Vec<String> = viewer.bots(&app.db).into_iter().map(|(b, _)| b.id).collect();
    app.db.approvals_among(status, &ids, limit)
}

/// A Bot view as this caller sees it. Admins also see its model and route.
fn bot_view_for(app: &App, c: &Caller, b: &db::Bot, access: Access) -> Value {
    let mut v = app.bot_view(b);
    v["access"] = json!(access);
    if c.principal == Principal::User(Role::Admin) {
        app.bot_admin_fields(b, &mut v);
    }
    v
}

fn bot_patch(v: &Value) -> Res<BotPatch> {
    let mut p = BotPatch::default();
    if let Some(n) = v["name"].as_str().map(str::trim).filter(|n| !n.is_empty()) {
        p.name = Some(n.chars().take(60).collect());
    }
    if let Some(c) = v["color"].as_str().filter(|c| c.len() == 7 && c.starts_with('#') && c[1..].chars().all(|x| x.is_ascii_hexdigit())) {
        p.color = Some(c.into());
    }
    if let Some(s) = v["shape"].as_str().filter(|s| SHAPES.contains(s)) {
        p.shape = Some(s.into());
    }
    if let Some(h) = v["hidden"].as_bool() {
        p.hidden = Some(h);
    }
    match &v["model"] {
        Value::Null if v.get("model").is_some() => p.model = Some(None),
        Value::String(m) => p.model = Some(Some(m.trim().to_string()).filter(|m| !m.is_empty())),
        _ => {}
    }
    // Effort words like "high" or "xhigh". Null = the harness default.
    match &v["effort"] {
        Value::Null if v.get("effort").is_some() => p.effort = Some(None),
        Value::String(e) if e.is_empty() => p.effort = Some(None),
        Value::String(e) if e.len() <= 20 && e.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') => {
            p.effort = Some(Some(e.clone()))
        }
        Value::String(_) => return Err(bad("Invalid effort")),
        _ => {}
    }
    if let Some(h) = v.get("harness") {
        let h = h.as_str().filter(|h| adapters::get(h).is_some());
        let h = h.ok_or_else(|| bad(format!("Harness must be one of: {}", adapters::NAMES.join(", "))))?;
        p.harness = Some(h.into());
    }
    if let Some(list) = v.get("prompts") {
        p.prompts = Some(prompts_field(list)?);
    }
    Ok(p)
}

/// Most suggested prompts a Bot shows (ADR 0054), and the longest one, in characters.
const MAX_PROMPTS: usize = 6;
const MAX_PROMPT_CHARS: usize = 200;

/// Suggested prompts: null for the defaults, or a list of non-blank strings, trimmed
/// and without repeats. An empty list shows none.
fn prompts_field(v: &Value) -> Res<Option<Vec<String>>> {
    let Some(items) = v.as_array() else {
        return if v.is_null() { Ok(None) } else { Err(bad("Prompts must be a list of text, or null for the defaults")) };
    };
    let mut out: Vec<String> = Vec::new();
    for item in items {
        let t = item.as_str().ok_or_else(|| bad("Prompts must be a list of text, or null for the defaults"))?.trim();
        if t.chars().count() > MAX_PROMPT_CHARS {
            return Err(bad(format!("A prompt can be at most {MAX_PROMPT_CHARS} characters")));
        }
        if !t.is_empty() && !out.iter().any(|o| o == t) {
            out.push(t.to_string());
        }
    }
    if out.len() > MAX_PROMPTS {
        return Err(bad(format!("A Bot can have at most {MAX_PROMPTS} suggested prompts")));
    }
    Ok(Some(out))
}

fn visibility_field(v: &Value) -> Res<Option<Visibility>> {
    match v.get("visibility") {
        None | Some(Value::Null) => Ok(None),
        Some(x) => x.as_str().and_then(Visibility::parse).map(Some).ok_or_else(|| bad("Visibility must be private or shared")),
    }
}

async fn create_bot(State(app): State<AppState>, Extension(c): Extension<Caller>, Extension(by): Extension<Who>, Json(v): Json<Value>) -> Res<(StatusCode, Json<Value>)> {
    let p = bot_patch(&v)?;
    let name = p.name.ok_or_else(|| bad("Name is required"))?;
    // Shared unless asked otherwise, as every Bot was before ACLs; private with
    // isolated shared Bots, so sharing one is a choice (ADR 0046).
    let visibility = visibility_field(&v)?.unwrap_or(match app.shared_bots() {
        acl::SharedBots::Open => Visibility::Shared,
        acl::SharedBots::Isolated => Visibility::Private,
    });
    // A Bot running for a teammate can't add Bots to its owner's account.
    if let Some(for_user) = capped_by_asker(&app, &c, |_| true) {
        let details = json!({ "reason": "asker_acl", "action": "bot.create", "forUser": for_user });
        let id = c.bot.as_deref().unwrap_or_default();
        app.db.record(&by.event("access.denied").target("bot", id).bot(id).outcome(Outcome::Denied).details(details));
        return Err(ApiError(StatusCode::FORBIDDEN, "A Bot working for a teammate can't make new Bots. Ask its owner.".into()));
    }
    // A person owns what they make. A Bot's new Bot belongs to that Bot's owner.
    let owner = match (&c.user, c.principal) {
        (Some(u), _) => u.id.clone(),
        (None, Principal::Bot) => acting_bot(&app, &c, &by, None)?.owner_id,
        (None, _) => users::OPERATOR.into(),
    };
    let tier = app.tier_of(&owner);
    let (harness, harness_from) = match p.harness {
        Some(h) => (h, "chosen"),
        None => (default_harness_for(&app, &owner), if tier.managed() { "plan" } else { "server" }),
    };
    check_tier(&app, &owner, &harness, p.model.clone().flatten().as_deref(), p.effort.clone().flatten().as_deref(), None)?;
    let max = tier.limits.max_bots;
    let made = erasure::unless_erasing(&[&owner], || {
        app.db.create_bot_capped(
            &name,
            p.color.as_deref().unwrap_or(pick(&COLORS)),
            p.shape.as_deref().unwrap_or(pick(&SHAPES)),
            &harness,
            p.model.flatten().as_deref(),
            false,
            &owner,
            visibility,
            max,
        )
    });
    // Not audited: the event would name them after their erasure rewrote the log.
    let Some(made) = made else {
        return Err(ApiError(StatusCode::CONFLICT, "This account is being erased, so it can't have new Bots.".into()));
    };
    let bot = made.ok_or_else(|| {
            let details = json!({ "reason": "tier_bot_limit", "name": name, "owner": owner, "tier": tier.name, "limit": max });
            app.db.record(&by.event("bot.create_refused").target("user", &owner).outcome(Outcome::Denied).details(details));
            ApiError(StatusCode::FORBIDDEN, format!("The {} plan allows {} Bots, and they're all in use. Delete one first.", tier.label, max.unwrap_or(0)))
        })?;
    app.init_bot_files(&bot);
    app.push_bot(&bot.id);
    let details = json!({
        "name": bot.name, "harness": bot.harness, "harnessFrom": harness_from, "tier": tier.name, "model": bot.model, "owner": bot.owner_id, "visibility": bot.visibility,
    });
    app.db.record(&by.event("bot.created").target("bot", &bot.id).bot(&bot.id).details(details));
    let access = viewer(&app, &c, &by).access(&app.db, &bot);
    Ok((StatusCode::CREATED, Json(bot_view_for(&app, &c, &bot, access))))
}

/// Settings that changed, as `{field: {from, to}}`.
fn bot_changes(before: &db::Bot, after: &db::Bot) -> serde_json::Map<String, Value> {
    let mut m = serde_json::Map::new();
    let mut diff = |k: &str, a: Value, b: Value| {
        if a != b {
            m.insert(k.into(), json!({ "from": a, "to": b }));
        }
    };
    diff("name", json!(before.name), json!(after.name));
    diff("color", json!(before.color), json!(after.color));
    diff("shape", json!(before.shape), json!(after.shape));
    diff("harness", json!(before.harness), json!(after.harness));
    diff("model", json!(before.model), json!(after.model));
    diff("effort", json!(before.effort), json!(after.effort));
    diff("hidden", json!(before.hidden), json!(after.hidden));
    diff("prompts", json!(before.prompts), json!(after.prompts));
    m
}

async fn update_bot(State(app): State<AppState>, Extension(c): Extension<Caller>, Extension(by): Extension<Who>, Path(id): Path<String>, Json(v): Json<Value>) -> Res {
    let (bot, access) = need_bot_access(&app, &c, &by, &id, Access::Manage)?;
    let mut p = bot_patch(&v)?;
    if p.harness.as_ref().is_some_and(|h| *h != bot.harness) {
        // Sessions don't carry across harnesses, nor do model names and efforts unless given anew.
        p.session_id = Some(None);
        p.model.get_or_insert(None);
        p.effort.get_or_insert(None);
    }
    let harness = p.harness.clone().unwrap_or_else(|| bot.harness.clone());
    let model = p.model.clone().unwrap_or_else(|| bot.model.clone());
    let effort = p.effort.clone().unwrap_or_else(|| bot.effort.clone());
    if p.harness.is_some() || p.model.is_some() || p.effort.is_some() {
        // Only what's changing is checked against the tier: a Bot set up before its
        // owner's tier changed can still be renamed, and runs on the tier's route anyway.
        let current = model.clone();
        let (model, effort) = (p.model.is_some().then_some(model).flatten(), p.effort.is_some().then_some(effort).flatten());
        check_tier(&app, &bot.owner_id, &harness, model.as_deref(), effort.as_deref(), current.as_deref())?;
    }
    app.db.update_bot(&id, p);
    app.push_bot(&id);
    let after = need_bot(&app, &id)?;
    let changes = bot_changes(&bot, &after);
    if !changes.is_empty() {
        app.db.record(&by.event("bot.updated").target("bot", &id).bot(&id).details(json!({ "changes": changes })));
    }
    Ok(Json(bot_view_for(&app, &c, &after, access)))
}

async fn delete_bot(State(app): State<AppState>, Extension(c): Extension<Caller>, Extension(by): Extension<Who>, Path(id): Path<String>) -> Res {
    let (bot, _) = need_bot_access(&app, &c, &by, &id, Access::Manage)?;
    if bot.primary {
        return Err(bad("The primary Bot can't be deleted"));
    }
    let held = || ApiError(StatusCode::CONFLICT, "This Bot's chat is held (a retention hold on it, or on a Bot that wrote in its chat), so it can't be deleted until an admin releases the hold.".into());
    if app.db.bot_chat_held(&id) {
        return Err(held());
    }
    app.stop(&id);
    if let Some(screens) = &app.screens {
        screens.remove(&id).await;
    }
    machines::screens::close(&app, &by, &id, "bot_deleted").await;
    // A hold placed while the screen closed still wins: the Bot is stopped, but nothing is lost.
    if !app.db.delete_bot_unless_held(&id) {
        return Err(if app.db.bot_chat_held(&id) { held() } else { not_found("Bot") });
    }
    notify::forget_bot(&app, &id);
    app.db.record(&by.event("bot.deleted").target("bot", &id).bot(&id).details(json!({ "name": bot.name, "harness": bot.harness })));
    machines::offboard::check_owner(&app, &by, &bot.owner_id);
    app.send(json!({ "type": "botDeleted", "botId": id }));
    Ok(Json(json!({ "ok": true })))
}

// Bot ACLs (ADR 0017): owner, visibility, and grants.

fn person(u: Option<db::User>, id: &str) -> Value {
    match u {
        Some(u) => json!({ "id": u.id, "name": u.name, "email": u.email }),
        None => json!({ "id": id, "name": null, "email": null }),
    }
}

/// Who can see a Bot. Grants are only shown to those who can change them.
fn access_view(app: &App, b: &db::Bot, access: Access) -> Value {
    let mut v = json!({
        "botId": b.id,
        "owner": person(app.db.user(&b.owner_id), &b.owner_id),
        "visibility": b.visibility,
        "access": access,
    });
    if access == Access::Manage {
        let grants: Vec<Value> = app
            .db
            .grants(&b.id)
            .into_iter()
            .map(|g| json!({ "user": person(app.db.user(&g.user_id), &g.user_id), "level": g.level, "createdAt": g.created_at, "createdBy": g.created_by }))
            .collect();
        v["grants"] = json!(grants);
    }
    v
}

/// After an ACL change: everyone's lists and live streams start over, since who
/// sees the Bot may have changed. The resync goes first: it clears each stream's
/// cached access, so the Bot's update reaches exactly who can now see it.
/// When someone may have lost access, its screen also gets a new token: the
/// proxy sends screen traffic straight to voxl, so an old link would keep working.
/// That waits on the screen, so it comes after the resync: streams must not run on
/// stale access meanwhile. Teammates who lost the owner's Bots lose their users on
/// the owner's machine (ADR 0052).
async fn acl_changed(app: &AppState, by: &Who, id: &str, narrowed: bool) {
    app.send(json!({ "type": "resync" }));
    app.push_bot(id);
    if narrowed && let Some(screens) = &app.screens {
        screens.rotate_token(id).await;
    }
    if narrowed {
        machines::screens::rotate(app, id).await;
        if let Some(b) = app.db.bot(id) {
            machines::offboard::check_owner(app, by, &b.owner_id);
        }
    }
}

/// Gives `bot` to `to` (an admin's choice): it takes one of their Bot slots, work
/// started for the old owner ends, and its memory follows it. Its harness and model
/// they can change after.
pub(crate) async fn give_bot(app: &AppState, by: &Who, bot: &db::Bot, to: &db::User) -> Res<()> {
    if to.id == bot.owner_id {
        return Ok(());
    }
    let id = &bot.id;
    let tier = app.tier_of(&to.id);
    let max = tier.limits.max_bots;
    // Work started for the old owner runs in their folder with their keys; it
    // ends here, and its token stops working (it names the old owner). A refused
    // transfer (another request took the last slot) leaves that work running.
    // Neither the old owner nor the new one may be being erased (ADR 0102).
    let mut erasing = false;
    let moved = app.stop_if(id, || {
        let from = app.db.bot(id).map(|b| b.owner_id).unwrap_or_default();
        erasure::unless_erasing(&[&from, &to.id], || app.db.set_bot_owner_capped(id, &to.id, max)).unwrap_or_else(|| {
            erasing = true;
            false
        })
    });
    if erasing {
        return Err(ApiError(StatusCode::CONFLICT, "Its owner or the one it would go to is being erased. Try again once that's done.".into()));
    }
    if !moved {
        let details = json!({ "reason": "tier_bot_limit", "from": bot.owner_id, "to": to.id, "tier": tier.name, "limit": max });
        app.db.record(&by.event("bot.transfer_refused").target("bot", id).bot(id).outcome(Outcome::Denied).details(details));
        return Err(ApiError(StatusCode::FORBIDDEN, format!("{}'s plan ({}) allows {} Bots, and they're all in use.", to.name, tier.label, max.unwrap_or(0))));
    }
    // The new owner manages it anyway; a leftover grant would only confuse.
    app.db.remove_grant(id, &to.id);
    app.hand_over_memory(id, &bot.owner_id, &to.id);
    app.db.record(&by.event("bot.owner_changed").target("bot", id).bot(id).details(json!({ "from": bot.owner_id, "to": to.id })));
    acl_changed(app, by, id, true).await;
    // It runs on the new owner's machine now: teammates may have no use for the old one.
    machines::offboard::check_owner(app, by, &bot.owner_id);
    Ok(())
}

async fn get_access(State(app): State<AppState>, Extension(c): Extension<Caller>, Extension(by): Extension<Who>, Path(id): Path<String>) -> Res {
    let (bot, access) = need_bot_access(&app, &c, &by, &id, Access::View)?;
    Ok(Json(access_view(&app, &bot, access)))
}

/// Body: `{visibility?: "private" | "shared", owner?: <user id or email>}`. The owner
/// or an admin can change visibility; only an admin can give a Bot to someone else.
async fn update_access(State(app): State<AppState>, Extension(c): Extension<Caller>, Extension(by): Extension<Who>, Path(id): Path<String>, Json(v): Json<Value>) -> Res {
    need_user(c.principal)?;
    let (bot, _) = need_bot_access(&app, &c, &by, &id, Access::Manage)?;
    let visibility = visibility_field(&v)?;
    let owner = match v.get("owner") {
        None | Some(Value::Null) => None,
        Some(o) => {
            if c.principal != Principal::User(Role::Admin) {
                return Err(ApiError(StatusCode::FORBIDDEN, "Only an admin can change who owns a Bot.".into()));
            }
            let key = o.as_str().map(str::trim).filter(|k| !k.is_empty()).ok_or_else(|| bad("owner must be a user id or email"))?;
            let u = app.db.find_user(key).ok_or_else(|| not_found("User"))?;
            if !u.active() {
                return Err(bad("That user is disabled"));
            }
            Some(u)
        }
    };
    if visibility.is_none() && owner.is_none() {
        return Err(bad("Send visibility or owner"));
    }
    let mut narrowed = false;
    // The owner first: it can be refused for the new owner's Bot limit.
    if let Some(u) = owner.filter(|u| u.id != bot.owner_id) {
        give_bot(&app, &by, &bot, &u).await?;
        narrowed = true;
    }
    if let Some(to) = visibility.filter(|to| *to != bot.visibility) {
        app.db.set_bot_visibility(&id, to);
        app.db.record(&by.event("bot.visibility_changed").target("bot", &id).bot(&id).details(json!({ "from": bot.visibility, "to": to })));
        narrowed |= to == Visibility::Private;
    }
    acl_changed(&app, &by, &id, narrowed).await;
    let after = need_bot(&app, &id)?;
    let access = viewer(&app, &c, &by).access(&app.db, &after);
    Ok(Json(access_view(&app, &after, access)))
}

/// Body: `{level: "viewer" | "operator"}`. Adds or changes one user's grant.
async fn put_grant(State(app): State<AppState>, Extension(c): Extension<Caller>, Extension(by): Extension<Who>, Path((id, key)): Path<(String, String)>, Json(v): Json<Value>) -> Res {
    need_user(c.principal)?;
    let (bot, access) = need_bot_access(&app, &c, &by, &id, Access::Manage)?;
    let level = v["level"].as_str().and_then(acl::Grant::parse).ok_or_else(|| bad("level must be viewer or operator"))?;
    let u = app.db.find_user(&key).ok_or_else(|| not_found("User"))?;
    if u.id == bot.owner_id {
        return Err(ApiError(StatusCode::CONFLICT, "That user owns this Bot already.".into()));
    }
    // A grant reaches only the owner's team (ADR 0087). Only admins learn the person exists.
    if !app.db.same_team(&bot.owner_id, &u.id) {
        let details = json!({ "reason": "other_team", "user": u.id, "level": level });
        app.db.record(&by.event("bot.access_refused").target("bot", &id).bot(&id).outcome(Outcome::Denied).details(details));
        return Err(match c.principal {
            Principal::User(Role::Admin) => ApiError(StatusCode::CONFLICT, "They aren't on this Bot's owner's team, so a grant wouldn't reach them.".into()),
            _ => not_found("User"),
        });
    }
    let by_id = c.user.as_ref().map_or(users::OPERATOR, |u| u.id.as_str());
    let before = app.db.set_grant(&id, &u.id, level, by_id);
    if before != Some(level) {
        app.db.record(&by.event("bot.access_granted").target("bot", &id).bot(&id).details(json!({ "user": u.id, "level": level, "from": before })));
        acl_changed(&app, &by, &id, before == Some(acl::Grant::Operator) && level == acl::Grant::Viewer).await;
    }
    Ok(Json(access_view(&app, &bot, access)))
}

async fn delete_grant(State(app): State<AppState>, Extension(c): Extension<Caller>, Extension(by): Extension<Who>, Path((id, key)): Path<(String, String)>) -> Res {
    need_user(c.principal)?;
    let (bot, access) = need_bot_access(&app, &c, &by, &id, Access::Manage)?;
    let u = app.db.find_user(&key).ok_or_else(|| not_found("User"))?;
    let level = app.db.remove_grant(&id, &u.id).ok_or_else(|| not_found("Grant"))?;
    app.db.record(&by.event("bot.access_revoked").target("bot", &id).bot(&id).details(json!({ "user": u.id, "level": level })));
    acl_changed(&app, &by, &id, true).await;
    Ok(Json(access_view(&app, &bot, access)))
}

async fn mark_read(State(app): State<AppState>, Extension(c): Extension<Caller>, Extension(by): Extension<Who>, Path(id): Path<String>) -> Res {
    need_bot_access(&app, &c, &by, &id, Access::Operate)?;
    app.db.update_bot(&id, BotPatch { unread: Some(false), ..Default::default() });
    app.push_bot(&id);
    Ok(Json(json!({ "ok": true })))
}

async fn stop_bot(State(app): State<AppState>, Extension(c): Extension<Caller>, Extension(by): Extension<Who>, Path(id): Path<String>) -> Res {
    need_bot_access(&app, &c, &by, &id, Access::Operate)?;
    app.stop(&id);
    app.db.record(&by.event("bot.stopped").target("bot", &id).bot(&id));
    Ok(Json(json!({ "ok": true })))
}

// Messages

async fn list_messages(State(app): State<AppState>, Extension(c): Extension<Caller>, Extension(by): Extension<Who>, Path(id): Path<String>) -> Res {
    need_bot_access(&app, &c, &by, &id, Access::View)?;
    Ok(Json(json!(app.db.messages(&id, 200))))
}

async fn send_message(State(app): State<AppState>, Extension(c): Extension<Caller>, Extension(by): Extension<Who>, Path(id): Path<String>, Json(v): Json<Value>) -> Res<(StatusCode, Json<Value>)> {
    need_bot_access(&app, &c, &by, &id, Access::Operate)?;
    let text = v["text"].as_str().map(str::trim).filter(|t| !t.is_empty()).ok_or_else(|| bad("Text is required"))?;
    let text: String = text.chars().take(100_000).collect();
    let answered = v["answer"]["messageId"].as_i64().and_then(|mid| app.db.message(mid)).filter(|m| m.bot_id == id);
    let answered_id = answered.as_ref().map(|m| m.id);
    let waiter = answered_id.and_then(|mid| app.take_handoff(mid));
    // Storage full (ADR 0082): nothing new is taken in for the owner until files go. A
    // Bot still waiting on a handoff gets its answer, and a refused answer leaves its card open.
    if waiter.is_none()
        && let Some(bot) = app.db.bot(&id)
        && let Some((m, limit, storage::State::Over)) = storage::check(&app, &bot.owner_id).await
    {
        let tier = app.tier_of(&bot.owner_id);
        let details = storage::details(&m, json!({ "reason": "storage_limit", "owner": bot.owner_id, "tier": tier.name, "limit": limit }));
        app.db.record(&by.event("bot.message_refused").bot(&id).outcome(Outcome::Denied).details(details));
        billing_mail::storage(&app, &bot.owner_id, tier, m.used(), limit, true);
        return Err(ApiError(StatusCode::FORBIDDEN, storage::refusal_text(&tier.label, &m, limit)));
    }
    // Answering a choice card: remember which option was picked.
    let mut handoff = None;
    if let (Some(mid), Some(opt)) = (answered_id, v["answer"]["option"].as_u64())
        && let Some(mut q) = answered.and_then(|m| m.question)
    {
        if q["handoff"] == json!(true) && q["picked"].is_null() {
            handoff = Some((mid, q["options"][opt as usize].as_str().map(String::from)));
        }
        q["picked"] = json!(opt);
        app.db.set_question(mid, &q);
    }
    if let Some((mid, option)) = handoff {
        let details = json!({ "option": option, "botWasWaiting": waiter.is_some() });
        app.db.record(&by.event("handoff.answered").target("handoff", &mid.to_string()).bot(&id).details(details));
    }
    // Answering a handoff card the Bot is still waiting on: hand the answer to it directly.
    if let Some(tx) = waiter {
        let mut msg = app.db.add_message(&id, "user", &text, None, false, Some("done"));
        app.db.set_requested_by(msg.id, &by);
        msg.requested_by = Some(by.clone());
        app.push_message(&msg);
        let _ = tx.send(text);
        return Ok((StatusCode::ACCEPTED, Json(json!(msg))));
    }
    let mut msg = app.db.add_message(&id, "user", &text, None, false, Some("queued"));
    app.db.set_requested_by(msg.id, &by);
    msg.requested_by = Some(by.clone());
    app.push_message(&msg);
    app.enqueue(msg.clone());
    Ok((StatusCode::ACCEPTED, Json(json!(msg))))
}

// Bot to Bot: `botctl ask`. Waits for the reply and returns it as plain text.

async fn ask(State(app): State<AppState>, Extension(c): Extension<Caller>, Extension(by): Extension<Who>, Json(v): Json<Value>) -> Result<String, ApiError> {
    let from = acting_bot(&app, &c, &by, v["from"].as_str())?;
    // A Bot asks with its owner's access. A person needs to be able to run both Bots.
    let viewer = viewer(&app, &c, &by);
    let to_key = v["to"].as_str().map(str::trim).unwrap_or("");
    let bots: Vec<db::Bot> = viewer.bots(&app.db).into_iter().filter(|(_, a)| *a >= Access::Operate).map(|(b, _)| b).collect();
    let find = |bots: &[db::Bot]| bots.iter().find(|b| b.id == to_key).or_else(|| bots.iter().find(|b| b.name.eq_ignore_ascii_case(to_key))).cloned();
    let Some(to) = find(&bots) else {
        // Hidden only because of whom it runs for (ADR 0046): the same answer, and a record.
        let owners = |o: &Viewer| find(&o.bots(&app.db).into_iter().filter(|(_, a)| *a >= Access::Operate).map(|(b, _)| b).collect::<Vec<_>>());
        if let Some(for_user) = capped_by_asker(&app, &c, |o| owners(o).is_some()) {
            let hidden = owners(&Viewer::owner_of(&app.db, &from)).map(|b| b.id).unwrap_or_default();
            let details = json!({ "reason": "asker_acl", "need": Access::Operate, "forUser": for_user });
            app.db.record(&by.event("access.denied").target("bot", &hidden).bot(&from.id).outcome(Outcome::Denied).details(details));
        }
        return Err(bad(format!("No Bot named \"{to_key}\". Run `botctl bots` to list them.")));
    };
    let to = &to;
    if to.id == from.id {
        return Err(bad("You can't ask yourself"));
    }
    let text = v["text"].as_str().map(str::trim).filter(|t| !t.is_empty()).ok_or_else(|| bad("Message is required"))?;
    // A Bot asks as itself, for its owner, and on for whomever its run is for; a person as themselves.
    let by = match c.principal {
        Principal::Bot => {
            let mut actor = Actor::for_bot(&from).method("bot_token");
            actor.asker = Some(app.acting_for(&from)).filter(|a| *a != from.owner_id);
            Who { actor, source: by.source.clone() }
        }
        Principal::User(_) => by,
    };
    app.db.record(&by.event("bot.asked").target("bot", &to.id).bot(&from.id).details(json!({ "to": to.name })));
    let wait = Duration::from_secs(9 * 60); // under the 10 minute max most harnesses allow a command
    Ok(match app.ask(&from, to, text, wait, &by).await {
        Some(reply) => reply,
        None => format!("{} is still working on it. Their reply will arrive later as a new message.", to.name),
    })
}

// Screens: the live view of a Bot's screen. Opening it starts the screen.

/// The caller as they are now, role read again: None once their session is revoked or
/// expired, or they're disabled.
fn caller_now(app: &App, a: &Auth, c: &Caller) -> Option<Caller> {
    let Some(s) = &c.session else { return Some(c.clone()) };
    if !app.db.session_is_live(&s.id, db::now(), a.sessions.idle_ms, a.sessions.max_ms) {
        return None;
    }
    let u = app.db.user(&s.user_id)?;
    Some(Caller { principal: Principal::User(u.role), grants: app.db.user_perms(&u), user: Some(u), ..c.clone() })
}

/// With teammates' own users on machines (ADR 0048), whose screen of `bot` a caller
/// gets: a teammate their own, the owner theirs; an admin the owner's, or a teammate's
/// with `?for=<user>`. A Bot's token gets the screen of the person its run is for.
/// None: the owner's.
fn screen_for(app: &App, c: &Caller, bot: &db::Bot, asked: Option<&str>) -> Res<Option<String>> {
    let on = app.control_plane.get().is_some_and(|cp| cp.teammate_users()) && app.shared_bots() == acl::SharedBots::Isolated;
    let me = match (&c.user, &c.bot) {
        (Some(u), _) => Some(u.id.clone()),
        (None, Some(b)) => app.db.bot(b).map(|b| app.acting_for(&b)),
        (None, None) => None,
    };
    let admin = c.principal == Principal::User(Role::Admin);
    let who = match asked.map(str::trim).filter(|u| !u.is_empty()) {
        Some(u) if !on => return Err(bad(format!("Screens are per teammate only with MACHINE_TEAMMATE_USERS=on, so there's no screen for {u}."))),
        Some(u) if admin || me.as_deref() == Some(u) => Some(u.to_string()),
        Some(_) => return Err(ApiError(StatusCode::FORBIDDEN, "Only an admin can open someone else's screen of this Bot.".into())),
        None if on && !admin => me,
        None => None,
    };
    let who = who.filter(|u| *u != bot.owner_id);
    if let Some(u) = &who
        && Viewer::person(&app.db, u).access(&app.db, bot) < Access::Operate
    {
        return Err(ApiError(StatusCode::NOT_FOUND, "That person can't use this Bot, so it has no screen for them.".into()));
    }
    Ok(who)
}

async fn screen_info(
    State(app): State<AppState>,
    Extension(a): Extension<Arc<Auth>>,
    Extension(c): Extension<Caller>,
    Extension(by): Extension<Who>,
    Path(id): Path<String>,
    Query(q): Query<HashMap<String, String>>,
) -> Res {
    // The link gives control of the screen.
    let (bot, _) = need_bot_access(&app, &c, &by, &id, Access::Operate)?;
    let for_user = screen_for(&app, &c, &bot, q.get("for").map(String::as_str))?;
    // A Bot on its owner's machine is shown from there or not at all (ADR 0045). Its
    // screen may change hands while this waits on it, so access is checked again then.
    let still = || match caller_now(&app, &a, &c) {
        Some(now) => need_bot_access(&app, &now, &by, &id, Access::Operate).map(drop),
        None => Err(ApiError(StatusCode::UNAUTHORIZED, "Your session has ended. Sign in again.".into())),
    };
    if let Some(url) = machines::screens::open(&app, &by, &bot, for_user.as_deref(), still).await? {
        return Ok(Json(json!({ "url": url })));
    }
    let off = || ApiError(StatusCode::NOT_FOUND, "Screens are off on this server. Install Xvfb, openbox, and voxl.".into());
    let screens = app.screens.as_ref().filter(|_| screen::on_path("voxl")).ok_or_else(off)?;
    let info = screens.ensure(&id, |b| app.is_running(b)).await;
    let info = info.ok_or_else(|| ApiError(StatusCode::SERVICE_UNAVAILABLE, "All screens are in use. Try again when a Bot finishes.".into()))?;
    still()?;
    // A frame loaded before voxl listens gets the proxy's 502 and stays blank, so only hand out a link that works.
    if !screen::wait_for_port(info.port, 50).await {
        return Err(ApiError(StatusCode::SERVICE_UNAVAILABLE, "The screen is still starting. Try again in a moment.".into()));
    }
    // The proxy in front serves /screen/<port>/ from that local voxl port.
    Ok(Json(json!({ "url": format!("/screen/{}/?token={}", info.port, info.token) })))
}

// A Bot hands its screen to the user: `botctl handoff`. Waits for "Done".

async fn handoff(State(app): State<AppState>, Extension(c): Extension<Caller>, Extension(by): Extension<Who>, Json(v): Json<Value>) -> Result<String, ApiError> {
    let bot = acting_bot(&app, &c, &by, v["from"].as_str())?;
    let text = v["text"].as_str().map(str::trim).filter(|t| !t.is_empty()).ok_or_else(|| bad("Say what you need"))?;
    let text: String = text.chars().take(300).collect();
    let wait = Duration::from_secs(9 * 60); // under the 10 minute max most harnesses allow a command
    Ok(match app.handoff(&bot, &text, wait).await {
        Some(answer) => format!("The user answered: {answer}"),
        None => "The user hasn't answered yet. Stop here and tell them in one line what you need. You'll get their answer as a new message.".into(),
    })
}

// Routines

async fn list_routines(State(app): State<AppState>, Extension(c): Extension<Caller>, Extension(by): Extension<Who>, Path(id): Path<String>) -> Res {
    need_bot_access(&app, &c, &by, &id, Access::View)?;
    Ok(Json(json!(app.db.routines(Some(&id)))))
}

/// Routine fields from a create or edit body. Absent fields are None; present ones
/// must be non-empty strings (trimmed), a valid cron, and a boolean `enabled`.
#[derive(Debug, Default, PartialEq)]
struct RoutineFields {
    name: Option<String>,
    cron: Option<String>,
    instruction: Option<String>,
    enabled: Option<bool>,
}

fn routine_fields(v: &Value) -> Res<RoutineFields> {
    let text = |key: &str, max: usize| -> Res<Option<String>> {
        match v.get(key) {
            None | Some(Value::Null) => Ok(None),
            Some(Value::String(s)) if !s.trim().is_empty() => Ok(Some(s.trim().chars().take(max).collect())),
            Some(_) => Err(bad(format!("{key} can't be empty"))),
        }
    };
    let f = RoutineFields {
        name: text("name", 100)?,
        cron: text("cron", 100)?,
        instruction: text("instruction", 100_000)?,
        enabled: match v.get("enabled") {
            None | Some(Value::Null) => None,
            Some(Value::Bool(b)) => Some(*b),
            Some(_) => return Err(bad("enabled must be true or false")),
        },
    };
    if let Some(c) = &f.cron {
        cron::parse(c).map_err(bad)?;
    }
    Ok(f)
}

async fn create_routine(State(app): State<AppState>, Extension(c): Extension<Caller>, Extension(by): Extension<Who>, Path(id): Path<String>, Json(v): Json<Value>) -> Res<(StatusCode, Json<Value>)> {
    need_bot_access(&app, &c, &by, &id, Access::Operate)?;
    let f = routine_fields(&v)?;
    let (Some(name), Some(cron_expr), Some(instruction)) = (f.name, f.cron, f.instruction) else {
        return Err(bad("name, cron, and instruction are required"));
    };
    let author = routine_author(&app, &c);
    if f.enabled != Some(false) {
        need_unblocked(&app, &id, author.as_deref())?;
    }
    let r = app.db.add_routine_by(&id, &name, &cron_expr, &instruction, f.enabled != Some(false), author.as_deref());
    let details = json!({ "name": r.name, "cron": r.cron, "enabled": r.enabled, "author": r.author_id });
    app.db.record(&by.event("routine.created").target("routine", &r.id).bot(&id).details(details));
    Ok((StatusCode::CREATED, Json(json!(r))))
}

/// Whom a routine's runs are for once the caller writes its instruction (ADR 0046): a
/// person, or the person a Bot's run is for. None: its Bot's owner.
fn routine_author(app: &App, c: &Caller) -> Option<String> {
    match (&c.user, c.principal) {
        (Some(u), _) => Some(u.id.clone()),
        (None, Principal::Bot) => c.bot.as_deref().and_then(|id| app.db.bot(id)).map(|b| app.acting_for(&b)),
        _ => None,
    }
}

/// A routine can't be turned on while its Bot's owner or its author is disabled (ADR 0047).
fn need_unblocked(app: &App, bot_id: &str, author: Option<&str>) -> Res<()> {
    let Some(owner) = app.db.bot_owner(bot_id) else { return Err(not_found("Bot")) };
    match handover::blocked(&app.db, &owner, author) {
        None => Ok(()),
        Some((reason, _)) => {
            let whose = if reason == handover::OWNER_DISABLED { "this Bot's owner" } else { "whoever wrote it" };
            Err(ApiError(StatusCode::CONFLICT, format!("This routine runs for {whose}, whose account is turned off. An admin can hand their Bots and routines to someone else.")))
        }
    }
}

/// Logs `routine.enabled`/`routine.disabled`, and `routine.updated` for other changes.
/// The instruction is a message to the Bot, so only the fact that it changed is kept.
fn routine_events(by: &Who, before: &db::Routine, after: &db::Routine) -> Vec<Event> {
    let mut out = Vec::new();
    let ev = |action: &str| by.event(action).target("routine", &after.id).bot(&after.bot_id);
    if before.enabled != after.enabled {
        let action = if after.enabled { "routine.enabled" } else { "routine.disabled" };
        out.push(ev(action).details(json!({ "name": after.name })));
    }
    let mut changes = serde_json::Map::new();
    if before.name != after.name {
        changes.insert("name".into(), json!({ "from": before.name, "to": after.name }));
    }
    if before.cron != after.cron {
        changes.insert("cron".into(), json!({ "from": before.cron, "to": after.cron }));
    }
    if before.instruction != after.instruction {
        changes.insert("instruction".into(), json!("changed"));
    }
    if before.author_id != after.author_id {
        changes.insert("author".into(), json!({ "from": before.author_id, "to": after.author_id }));
    }
    if !changes.is_empty() {
        out.push(ev("routine.updated").details(json!({ "name": after.name, "changes": changes })));
    }
    out
}

/// The routine, when the caller can run its Bot. A routine on a hidden Bot is a 404.
fn need_routine(app: &App, c: &Caller, by: &Who, id: &str) -> Res<db::Routine> {
    let r = app.db.routine(id).ok_or_else(|| not_found("Routine"))?;
    need_bot_access(app, c, by, &r.bot_id, Access::Operate).map_err(|e| if e.0 == StatusCode::NOT_FOUND { not_found("Routine") } else { e })?;
    Ok(r)
}

async fn update_routine(State(app): State<AppState>, Extension(c): Extension<Caller>, Extension(by): Extension<Who>, Path(id): Path<String>, Json(v): Json<Value>) -> Res {
    let before = need_routine(&app, &c, &by, &id)?;
    let f = routine_fields(&v)?;
    // Whoever writes the instruction is whom it runs for.
    let author = routine_author(&app, &c);
    if f.enabled == Some(true) {
        let rewrites = f.instruction.as_deref().is_some_and(|i| i != before.instruction);
        let author_after = if rewrites && author.is_some() { author.clone() } else { before.author_id.clone() };
        need_unblocked(&app, &before.bot_id, author_after.as_deref())?;
    }
    app.db.update_routine(&id, f.name.as_deref(), f.cron.as_deref(), f.instruction.as_deref(), f.enabled, author.as_deref());
    let after = app.db.routine(&id).ok_or_else(|| not_found("Routine"))?;
    for e in routine_events(&by, &before, &after) {
        app.db.record(&e);
    }
    Ok(Json(json!(after)))
}

async fn delete_routine(State(app): State<AppState>, Extension(c): Extension<Caller>, Extension(by): Extension<Who>, Path(id): Path<String>) -> Res {
    let r = need_routine(&app, &c, &by, &id)?;
    app.db.delete_routine(&id);
    app.db.record(&by.event("routine.deleted").target("routine", &id).bot(&r.bot_id).details(json!({ "name": r.name, "cron": r.cron })));
    Ok(Json(json!({ "ok": true })))
}

// Harness policy: global default, per-Bot overrides, and allow/deny rules.
// Anyone signed in can read it; only a person can change it.

fn classes_view() -> Value {
    json!(policy::CLASSES.iter().map(|(id, label)| json!({ "id": id, "label": label })).collect::<Vec<_>>())
}

/// Harnesses with a sandbox of their own, and those whose sandbox can start on `host`.
fn sandbox_harnesses(host: &sandbox::Host) -> (Vec<&'static str>, Vec<&'static str>) {
    let with: Vec<_> = adapters::NAMES.iter().copied().filter_map(|n| adapters::get(n).filter(|a| a.has_sandbox()).map(|a| (n, a))).collect();
    let can = with.iter().filter(|(_, a)| host.has(a.sandbox_needs())).map(|(n, _)| *n).collect();
    (with.into_iter().map(|(n, _)| n).collect(), can)
}

/// What the policy's `sandbox` can do here (ADR 0055): which harnesses have one, and
/// which of those can start it on this server. A machine reports its own at each run.
fn sandbox_view(app: &App) -> Value {
    let (harnesses, available) = sandbox_harnesses(&app.cfg.sandbox_host);
    json!({ "harnesses": harnesses, "available": available })
}

async fn get_policy(State(app): State<AppState>) -> Json<Value> {
    Json(json!({ "policy": app.db.global_policy(), "classes": classes_view(), "rules": app.db.rules(None), "sandbox": sandbox_view(&app) }))
}

async fn put_policy(State(app): State<AppState>, Extension(who): Extension<Principal>, Extension(by): Extension<Who>, Json(v): Json<Value>) -> Res {
    need_user(who)?;
    let before = app.db.global_policy();
    let after = policy::parse_patch(&v).map_err(bad)?.apply(&before);
    app.db.set_global_policy(&after);
    app.db.record(&by.event("policy.updated").target("policy", "global").details(json!({ "before": before, "after": after })));
    app.send(json!({ "type": "policy", "policy": after }));
    app.stop_unguarded_runs();
    for b in app.db.bots() {
        app.push_bot(&b.id);
    }
    Ok(Json(json!({ "policy": after })))
}

fn bot_policy_view(app: &App, id: &str) -> Value {
    json!({ "policy": app.db.effective_policy(id), "override": app.db.bot_override(id), "classes": classes_view(), "rules": app.db.rules(Some(id)), "sandbox": sandbox_view(app) })
}

async fn get_bot_policy(State(app): State<AppState>, Extension(c): Extension<Caller>, Extension(by): Extension<Who>, Path(id): Path<String>) -> Res {
    need_bot_access(&app, &c, &by, &id, Access::View)?;
    Ok(Json(bot_policy_view(&app, &id)))
}

async fn put_bot_policy(State(app): State<AppState>, Extension(who): Extension<Principal>, Extension(by): Extension<Who>, Path(id): Path<String>, Json(v): Json<Value>) -> Res {
    need_user(who)?;
    need_bot(&app, &id)?;
    let before = app.db.bot_override(&id);
    let o = policy::patch_override(&before.clone().unwrap_or_default(), &v).map_err(bad)?;
    app.db.set_bot_override(&id, Some(&o).filter(|o| !o.is_empty()));
    app.db.record(&by.event("policy.updated").target("policy", &id).bot(&id).details(json!({ "before": before, "after": o })));
    app.stop_unguarded_runs();
    app.push_bot(&id);
    Ok(Json(bot_policy_view(&app, &id)))
}

async fn delete_bot_policy(State(app): State<AppState>, Extension(who): Extension<Principal>, Extension(by): Extension<Who>, Path(id): Path<String>) -> Res {
    need_user(who)?;
    need_bot(&app, &id)?;
    let before = app.db.bot_override(&id);
    app.db.set_bot_override(&id, None);
    app.db.record(&by.event("policy.reset").target("policy", &id).bot(&id).details(json!({ "before": before })));
    app.stop_unguarded_runs();
    app.push_bot(&id);
    Ok(Json(bot_policy_view(&app, &id)))
}

// Approval notifications (ADR 0061). Admin-only (rbac::classify).

async fn get_notifications(State(app): State<AppState>) -> Json<Value> {
    Json(notify::api::view(&app))
}

async fn put_notifications(State(app): State<AppState>, Extension(who): Extension<Principal>, Extension(by): Extension<Who>, Json(v): Json<Value>) -> Res {
    need_user(who)?;
    Ok(Json(notify::api::update(&app, &by, &v).map_err(bad)?))
}

async fn test_notifications(State(app): State<AppState>, Extension(who): Extension<Principal>, Json(v): Json<Value>) -> Res {
    need_user(who)?;
    let bot = match v.get("botId").and_then(Value::as_str) {
        Some(id) => Some(need_bot(&app, id)?),
        None => None,
    };
    let Some(n) = app.notifier.get() else { return Err(bad("Notifications are off on this server")) };
    let sent = n.test(&app, bot.as_ref()).await.map_err(bad)?;
    Ok(Json(json!({ "ok": sent.iter().all(|s| s["ok"] == true), "results": sent })))
}

async fn get_bot_notifications(State(app): State<AppState>, Path(id): Path<String>) -> Res {
    let bot = need_bot(&app, &id)?;
    Ok(Json(notify::api::bot_view(&app, &bot)))
}

async fn put_bot_notifications(State(app): State<AppState>, Extension(who): Extension<Principal>, Extension(by): Extension<Who>, Path(id): Path<String>, Json(v): Json<Value>) -> Res {
    need_user(who)?;
    let bot = need_bot(&app, &id)?;
    Ok(Json(notify::api::update_bot(&app, &by, &bot, &v).map_err(bad)?))
}

async fn list_rules(State(app): State<AppState>, Extension(c): Extension<Caller>, Extension(by): Extension<Who>, Query(q): Query<HashMap<String, String>>) -> Res {
    let bot = q.get("bot").map(String::as_str).filter(|b| !b.is_empty());
    if let Some(b) = bot {
        need_bot_access(&app, &c, &by, b, Access::View)?;
    }
    Ok(Json(json!(app.db.rules(bot))))
}

async fn add_rule(State(app): State<AppState>, Extension(who): Extension<Principal>, Extension(by): Extension<Who>, Json(v): Json<Value>) -> Res<(StatusCode, Json<Value>)> {
    need_user(who)?;
    let bot = v["botId"].as_str().filter(|b| !b.is_empty());
    if let Some(b) = bot {
        need_bot(&app, b)?;
    }
    let action = match v["action"].as_str() {
        Some("allow") => policy::Action::Allow,
        Some("deny") => policy::Action::Deny,
        _ => return Err(bad("action must be \"allow\" or \"deny\"")),
    };
    let pattern = v["pattern"].as_str().map(str::trim).filter(|p| !p.is_empty()).ok_or_else(|| bad("pattern is required"))?;
    let tool = v["tool"].as_str().map(str::trim).filter(|t| !t.is_empty()).unwrap_or("*");
    let note = v["note"].as_str().map(str::trim).filter(|n| !n.is_empty());
    if pattern.chars().count() > policy::RULE_PATTERN_MAX {
        return Err(bad(format!("pattern must be {} characters or fewer", policy::RULE_PATTERN_MAX)));
    }
    if tool.chars().count() > policy::RULE_TOOL_MAX || tool.chars().any(char::is_whitespace) {
        return Err(bad(format!("tool must be \"*\", a kind, or a tool name: no spaces, {} characters or fewer", policy::RULE_TOOL_MAX)));
    }
    if note.is_some_and(|n| n.chars().count() > policy::RULE_NOTE_MAX) {
        return Err(bad(format!("note must be {} characters or fewer", policy::RULE_NOTE_MAX)));
    }
    let r = app.db.add_rule(bot, action, tool, pattern, note);
    let added = by.event("rule.added").target("rule", &r.id).details(json!({ "rule": r }));
    app.db.record(&match bot {
        Some(b) => added.bot(b),
        None => added,
    });
    Ok((StatusCode::CREATED, Json(json!(r))))
}

async fn delete_rule(State(app): State<AppState>, Extension(who): Extension<Principal>, Extension(by): Extension<Who>, Path(id): Path<String>) -> Res {
    need_user(who)?;
    let r = app.db.rule(&id).ok_or_else(|| not_found("Rule"))?;
    app.db.delete_rule(&id);
    let removed = by.event("rule.removed").target("rule", &id).details(json!({ "rule": r }));
    app.db.record(&match r.bot_id.as_deref() {
        Some(b) => removed.bot(b),
        None => removed,
    });
    Ok(Json(json!({ "ok": true })))
}

// Approvals

async fn list_approvals(State(app): State<AppState>, Extension(c): Extension<Caller>, Extension(by): Extension<Who>, Query(q): Query<HashMap<String, String>>) -> Res {
    need_user(c.principal)?;
    let limit = q.get("limit").and_then(|l| l.parse().ok()).unwrap_or(100).clamp(1, 1000);
    let status = q.get("status").map(String::as_str).filter(|s| *s != "all");
    let bot = q.get("bot").map(String::as_str).filter(|b| !b.is_empty());
    if let Some(b) = bot {
        need_bot_access(&app, &c, &by, b, Access::View)?;
    }
    Ok(Json(json!(visible_approvals(&app, &c, &by, status, bot, limit))))
}

async fn approve(state: State<AppState>, c: Extension<Caller>, by: Extension<Who>, id: Path<String>, body: axum::body::Bytes) -> Res {
    decide(state, c, by, id, body, true).await
}

async fn deny(state: State<AppState>, c: Extension<Caller>, by: Extension<Who>, id: Path<String>, body: axum::body::Bytes) -> Res {
    decide(state, c, by, id, body, false).await
}

/// Body: `{scope?: "once" | "run", remember?: "bot" | "global" | true, note?}`. Remember
/// saves a rule for this exact call, which is a policy change, so it needs an admin.
/// `scope: "run"` approves calls of the same kind for the rest of the Bot's run without
/// saving anything (ADR 0051), so it takes only what approving once takes.
async fn decide(State(app): State<AppState>, Extension(c): Extension<Caller>, Extension(by): Extension<Who>, Path(id): Path<String>, body: axum::body::Bytes, approve: bool) -> Res {
    let who = c.principal;
    need_user(who)?;
    // Answering lets the Bot act, so it takes operator access to that Bot.
    if let Some(a) = app.db.approval(&id) {
        need_bot_access(&app, &c, &by, &a.bot_id, Access::Operate).map_err(|e| if e.0 == StatusCode::NOT_FOUND { not_found("Approval") } else { e })?;
    }
    let v: Value = if body.iter().all(u8::is_ascii_whitespace) {
        Value::Null
    } else {
        serde_json::from_slice(&body).map_err(|e| bad(format!("Invalid JSON: {e}")))?
    };
    let remember = match &v["remember"] {
        Value::Bool(true) => Some(Remember::Bot),
        Value::String(s) if s == "bot" => Some(Remember::Bot),
        Value::String(s) if s == "global" => Some(Remember::Global),
        Value::Null | Value::Bool(false) => None,
        _ => return Err(bad("remember must be \"bot\", \"global\", or true")),
    };
    let for_run = match &v["scope"] {
        Value::Null => false,
        Value::String(s) if s == "once" => false,
        Value::String(s) if s == "run" => true,
        _ => return Err(bad("scope must be \"once\" or \"run\"")),
    };
    if for_run && !approve {
        return Err(bad("Only an approval can cover the rest of a task. A denial is for this call; to keep denying it, remember it."));
    }
    if for_run && remember.is_some() {
        return Err(bad("Pick one: approve for the rest of this task, or remember a lasting rule."));
    }
    if remember.is_some() && !rbac::allows(who, rbac::Perm::Admin) {
        app.db.record(&by.event("access.denied").outcome(Outcome::Denied).details(json!({ "path": format!("/api/approvals/{id}"), "need": "admin", "reason": "remember" })));
        return Err(ApiError(StatusCode::FORBIDDEN, "Only an admin can save a lasting rule. Approve or deny just this call.".into()));
    }
    let note: Option<String> = v["note"].as_str().map(|n| n.trim().chars().take(500).collect()).filter(|n: &String| !n.is_empty());
    let decided = if for_run { app.approve_for_run(&id, note.as_deref(), &by) } else { app.decide(&id, approve, remember, note.as_deref(), &by) };
    match decided {
        Ok(a) => Ok(Json(json!(a))),
        Err(DecideError::NotFound) => Err(not_found("Approval")),
        Err(DecideError::Closed(s)) => Err(ApiError(StatusCode::CONFLICT, format!("This approval is already {s}"))),
        Err(DecideError::TooLong) => Err(bad("This call is too long to remember. Approve or deny it without remembering.")),
        Err(DecideError::OnceOnly) => Err(bad("This call can only be approved once. Approve or deny just this call.")),
        Err(DecideError::RunEnded) => Err(ApiError(StatusCode::CONFLICT, "The task this call came from has ended.".into())),
    }
}

/// The harness hook (`botctl hook <harness>`) asks here before each tool call.
/// Body: `{from, harness, event}` with the harness's PreToolUse payload. Waits while
/// the user decides. Replies in plain text: "allow" or "deny", then the reason.
async fn check_approval(State(app): State<AppState>, Extension(c): Extension<Caller>, Extension(by): Extension<Who>, Json(v): Json<Value>) -> Response {
    let reply = |allow: bool, reason: &str| {
        let body = format!("{}\n{reason}", if allow { "allow" } else { "deny" });
        ([(header::CONTENT_TYPE, "text/plain; charset=utf-8")], body).into_response()
    };
    // A hook gets a plain "deny" it can show; a person gets the usual error.
    let bot = match acting_bot(&app, &c, &by, v["from"].as_str()) {
        Ok(b) => b,
        Err(ApiError(_, msg)) if c.principal == Principal::Bot => return reply(false, &msg),
        Err(e) => return e.into_response(),
    };
    let e = &v["event"];
    let Some(tool) = e["tool_name"].as_str().filter(|t| !t.is_empty()) else {
        return reply(false, "The hook sent no tool name");
    };
    let harness = v["harness"].as_str().unwrap_or(&bot.harness).to_string();
    let cwd = e["cwd"].as_str().filter(|c| c.starts_with('/')).map(PathBuf::from);
    let verdict = app.check(&bot, &harness, tool, e["tool_input"].clone(), cwd, v["run"].as_str()).await;
    reply(verdict.action == policy::Action::Allow, &verdict.reason)
}

/// The append-only audit log, newest first, filtered (see `audit::Filter`).
/// `nextBefore` pages back: pass it as `?before=`.
async fn list_audit(State(app): State<AppState>, Extension(who): Extension<Principal>, Query(q): Query<HashMap<String, String>>) -> Res {
    need_user(who)?;
    let limit = q.get("limit").and_then(|l| l.parse().ok()).unwrap_or(100).clamp(1, 1000);
    let f = audit_filter(&app, &q)?;
    let events = app.db.audit_events(&f, limit, false);
    let next = (events.len() as i64 == limit).then(|| events.last().map(|e| e.id)).flatten();
    Ok(Json(json!({ "events": events, "nextBefore": next })))
}

/// `?actor=user:<email>` and `?onBehalfOf=<email>` find the person by their email now.
fn audit_filter(app: &App, q: &HashMap<String, String>) -> Result<audit::Filter, ApiError> {
    let mut f = audit::Filter::from_query(q).map_err(bad)?;
    f.resolve_users(|key| app.db.find_user(key).map(|u| u.id));
    Ok(f)
}

/// The filtered log as RFC 4180 CSV, oldest first, streamed in batches.
async fn export_audit(State(app): State<AppState>, Extension(who): Extension<Principal>, Extension(by): Extension<Who>, Query(q): Query<HashMap<String, String>>) -> Result<Response, ApiError> {
    need_user(who)?;
    let mut f = audit_filter(&app, &q)?;
    app.db.record(&by.event("audit.exported").target("audit", "csv").details(f.describe()));
    // A snapshot: events written while the export streams are left out.
    let newest = app.db.audit_events(&audit::Filter::default(), 1, false).first().map_or(0, |e| e.id);
    f.before = Some(f.before.map_or(newest + 1, |b| b.min(newest + 1)));
    let (tx, rx) = tokio::sync::mpsc::channel::<Result<String, Infallible>>(4);
    tokio::task::spawn_blocking(move || {
        const BATCH: i64 = 500;
        if tx.blocking_send(Ok(audit::CSV_HEADER.into())).is_err() {
            return;
        }
        loop {
            let rows = app.db.audit_events(&f, BATCH, true);
            let Some(last) = rows.last() else { break };
            f.after = Some(last.id);
            if tx.blocking_send(Ok(rows.iter().map(audit::csv_row).collect())).is_err() || (rows.len() as i64) < BATCH {
                break;
            }
        }
    });
    let name = format!("attachment; filename=\"superbot-audit-{}.csv\"", chrono::Utc::now().format("%Y%m%d-%H%M%S"));
    let headers = [(header::CONTENT_TYPE, "text/csv; charset=utf-8".to_string()), (header::CONTENT_DISPOSITION, name), (header::CACHE_CONTROL, "no-store".into())];
    Ok((headers, axum::body::Body::from_stream(ReceiverStream::new(rx))).into_response())
}

// Secrets: names only. Values go in and reach harnesses; they never come back out.

fn secret_error(e: secrets::Error) -> ApiError {
    match e {
        secrets::Error::Invalid(m) => bad(m),
        secrets::Error::ReadOnly => ApiError(StatusCode::CONFLICT, e.to_string()),
        secrets::Error::Store(m) => {
            log_warn!("secrets: {m}");
            ApiError(StatusCode::INTERNAL_SERVER_ERROR, "The secret store failed; see the server log.".into())
        }
        secrets::Error::Unavailable(m) => {
            log_warn!("secrets: {m}");
            ApiError(StatusCode::SERVICE_UNAVAILABLE, "The external secret store can't be read right now; see the server log.".into())
        }
    }
}

async fn list_secrets(Extension(who): Extension<Principal>) -> Res {
    need_user(who)?;
    Ok(Json(json!({ "secrets": secrets::global().list().map_err(secret_error)? })))
}

async fn put_secret(State(app): State<AppState>, Extension(who): Extension<Principal>, Extension(by): Extension<Who>, Path(name): Path<String>, Json(v): Json<Value>) -> Res {
    need_user(who)?;
    let value = v["value"].as_str().ok_or_else(|| bad("Send {\"value\": \"...\"}."))?;
    let listed = secrets::global().put(&name, value).map_err(secret_error)?;
    app.db.record(&by.event("secret.set").target("secret", &name).details(json!({ "store": listed.store })));
    Ok(Json(json!({ "secret": listed })))
}

async fn delete_secret(State(app): State<AppState>, Extension(who): Extension<Principal>, Extension(by): Extension<Who>, Path(name): Path<String>) -> Res {
    need_user(who)?;
    if !secrets::global().delete(&name).map_err(secret_error)? {
        return Err(not_found("Secret"));
    }
    app.db.record(&by.event("secret.deleted").target("secret", &name));
    Ok(Json(json!({ "ok": true })))
}

// Your own secrets (ADR 0029): harness logins and API keys that reach only your Bots,
// over a server-wide one of the same name. A person's, never a Bot's: a Bot that could
// read or change them could take its owner's keys elsewhere.

/// The signed-in person whose secrets these are.
fn secrets_owner(c: &Caller) -> Res<String> {
    need_user(c.principal)?;
    c.user.as_ref().map(|u| u.id.clone()).ok_or_else(|| ApiError(StatusCode::FORBIDDEN, "Sign in as a user to keep your own secrets.".into()))
}

async fn list_my_secrets(Extension(c): Extension<Caller>) -> Res {
    let me = secrets_owner(&c)?;
    Ok(Json(json!({ "secrets": secrets::global().user_list(&me).map_err(secret_error)? })))
}

async fn put_my_secret(State(app): State<AppState>, Extension(c): Extension<Caller>, Extension(by): Extension<Who>, Path(name): Path<String>, Json(v): Json<Value>) -> Res {
    let me = secrets_owner(&c)?;
    let value = v["value"].as_str().ok_or_else(|| bad("Send {\"value\": \"...\"}."))?;
    let (listed, replaced) = secrets::global().user_save(&me, &name, value).map_err(secret_error)?;
    app.db.record(&by.event("secret.set").target("secret", &name).details(json!({ "scope": "user", "userId": me, "replaced": replaced })));
    Ok(Json(json!({ "secret": listed })))
}

async fn delete_my_secret(State(app): State<AppState>, Extension(c): Extension<Caller>, Extension(by): Extension<Who>, Path(name): Path<String>) -> Res {
    let me = secrets_owner(&c)?;
    if !secrets::global().user_delete(&me, &name).map_err(secret_error)? {
        return Err(not_found("Secret"));
    }
    app.db.record(&by.event("secret.deleted").target("secret", &name).details(json!({ "scope": "user", "userId": me })));
    Ok(Json(json!({ "ok": true })))
}

/// Admin: a user's secret names, never values.
async fn list_user_secrets(State(app): State<AppState>, Path(key): Path<String>) -> Res {
    let u = users::need_user_key(&app, &key)?;
    Ok(Json(json!({ "user": u.id, "secrets": secrets::global().user_list(&u.id).map_err(secret_error)? })))
}

/// Admin: drops every secret a user saved, e.g. when they leave.
async fn delete_user_secrets(State(app): State<AppState>, Extension(by): Extension<Who>, Path(key): Path<String>) -> Res {
    let u = users::need_user_key(&app, &key)?;
    let n = secrets::global().user_forget(&u.id).map_err(secret_error)?;
    app.db.record(&by.event("secret.deleted").target("user", &u.id).details(json!({ "scope": "user", "userId": u.id, "count": n })));
    Ok(Json(json!({ "deleted": n })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// Auth in front of a stub route, with no app. Returns the port and a Bot's bearer
    /// token, which nothing here can check.
    async fn serve(password: &str, allow_no_auth: bool, extra_hosts: &str) -> (u16, String) {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let bot_token = isolation::RunTokens::new(&random_hex(16)).issue("b1", users::OPERATOR, "r1", None, db::now(), 60_000).0;
        let state = Arc::new(Auth {
            password: password.into(),
            allow_no_auth,
            hosts: allowed_hosts("127.0.0.1", port, extra_hosts),
            ..Auth::new(None)
        });
        let router = Router::new()
            .route("/api/state", get(|| async { "ok" }))
            .layer(middleware::from_fn_with_state(state, super::auth));
        tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        (port, bot_token)
    }

    async fn status(port: u16, host: &str, authorization: &str) -> u16 {
        let mut s = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let auth = if authorization.is_empty() {
            String::new()
        } else {
            format!("Authorization: {authorization}\r\n")
        };
        let req = format!("GET /api/state HTTP/1.1\r\nHost: {host}\r\n{auth}Connection: close\r\n\r\n");
        s.write_all(req.as_bytes()).await.unwrap();
        let mut res = String::new();
        s.read_to_string(&mut res).await.unwrap();
        res.split_whitespace().nth(1).unwrap().parse().unwrap()
    }

    pub(super) fn basic(password: &str) -> String {
        const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::new();
        for c in format!("anyone:{password}").as_bytes().chunks(3) {
            let n = c.iter().enumerate().fold(0u32, |n, (i, b)| n | ((*b as u32) << (16 - 8 * i)));
            for i in 0..4 {
                out.push(if i <= c.len() {
                    T[((n >> (18 - 6 * i)) & 63) as usize] as char
                } else {
                    '='
                });
            }
        }
        format!("Basic {out}")
    }

    #[test]
    fn startup_requires_password_or_opt_out() {
        assert!(!is_loopback_host("0.0.0.0"));
        assert!(is_loopback_host("127.0.0.1"));
    }

    #[tokio::test]
    async fn spoofed_host_is_refused() {
        let pw = random_hex(16);
        let (port, _) = serve(&pw, false, "bots.example.com").await;
        assert_eq!(status(port, "attacker.example", &basic(&pw)).await, 403);
        assert_eq!(status(port, &format!("attacker.example:{port}"), &basic(&pw)).await, 403);
        assert_eq!(status(port, "127.0.0.1:1", &basic(&pw)).await, 403);
    }

    #[tokio::test]
    async fn own_hosts_and_login() {
        let pw = random_hex(16);
        let (port, bot_token) = serve(&pw, false, "bots.example.com").await;
        let host = format!("127.0.0.1:{port}");
        assert_eq!(status(port, &host, &basic(&pw)).await, 200);
        assert_eq!(status(port, &host, &basic(&random_hex(16))).await, 401);
        assert_eq!(status(port, &host, &format!("Bearer {bot_token}")).await, 401, "no run is live without an app");
        assert_eq!(status(port, "bots.example.com", &basic(&pw)).await, 200);
    }

    #[tokio::test]
    // An empty String, not "": code scanning reads a literal as a hard-coded password.
    #[allow(clippy::unnecessary_owned_empty_strings)]
    async fn empty_password_requires_opt_in_even_on_loopback() {
        let (port, _) = serve(&String::new(), false, "").await;
        let host = format!("127.0.0.1:{port}");
        assert_eq!(status(port, &host, "").await, 401);
        assert_eq!(status(port, &host, &basic(&String::new())).await, 401);
    }

    #[tokio::test]
    #[allow(clippy::unnecessary_owned_empty_strings)]
    async fn allow_no_auth_permits_anonymous_on_loopback() {
        let (port, _) = serve(&String::new(), true, "").await;
        let host = format!("127.0.0.1:{port}");
        assert_eq!(status(port, &host, "").await, 200);
    }

    /// Mints the `Authorization` header a Bot's run gets (ADR 0029, 0083), for the Bot's
    /// owner now (the owner account when there's no app or no such Bot), as if a run of
    /// it had just started. With no app, it's signed with key `.0` and never live here.
    #[derive(Clone)]
    pub(super) struct BotKey(pub String, pub Option<AppState>);

    impl BotKey {
        pub(super) fn auth(&self, bot_id: &str) -> String {
            let owner = self.1.as_ref().and_then(|app| app.db.bot_owner(bot_id)).unwrap_or_else(|| users::OPERATOR.into());
            self.auth_as(bot_id, &owner)
        }

        pub(super) fn auth_as(&self, bot_id: &str, owner: &str) -> String {
            self.auth_run(bot_id, owner, None).0
        }

        /// A run token for `bot_id` as `owner`'s, bound to `for_user` if any, and its id.
        pub(super) fn auth_run(&self, bot_id: &str, owner: &str, for_user: Option<&str>) -> (String, String) {
            let run = format!("r{}", random_hex(8));
            let (t, e) = match &self.1 {
                Some(app) => app.run_tokens.issue(bot_id, owner, &run, for_user, db::now(), 3_600_000),
                None => isolation::RunTokens::new(&self.0).issue(bot_id, owner, &run, for_user, db::now(), 3_600_000),
            };
            (format!("Bearer {t}"), e.id)
        }
    }

    /// The real router on a fresh install (policy: ask), with a random password.
    /// Returns the port, the app, the person's Authorization header, and the key Bots' tokens come from.
    pub(super) async fn serve_app() -> (u16, AppState, String, BotKey) {
        serve_app_with(|_| {}).await
    }

    /// `serve_app`, with Auth changed first (break-glass, session lifetimes).
    pub(super) async fn serve_app_with(tweak: impl FnOnce(&mut Auth)) -> (u16, AppState, String, BotKey) {
        let (port, app, password, bot, _) = serve_app_and_router(tweak).await;
        (port, app, password, bot)
    }

    /// `serve_app_with`, and the router it serves, for botd's machine port.
    pub(super) async fn serve_app_and_router(tweak: impl FnOnce(&mut Auth)) -> (u16, AppState, String, BotKey, Router) {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let password = random_hex(16);
        let app = runner::test_app();
        users::ensure_operator(&app.db, "Owner", None);
        let mut auth = Auth {
            password: password.clone(),
            hosts: allowed_hosts("127.0.0.1", port, ""),
            ..Auth::new(Some(app.clone()))
        };
        tweak(&mut auth);
        let password = auth.password.clone();
        let _ = app.control_plane.set(auth.machines.clone());
        let auth = Arc::new(auth);
        let bot = BotKey(app.cfg.bot_key.clone(), Some(app.clone()));
        let r = router(app.clone(), auth);
        let served = r.clone();
        tokio::spawn(async move {
            axum::serve(listener, served.into_make_service_with_connect_info::<SocketAddr>()).await.unwrap();
        });
        (port, app, basic(&password), bot, r)
    }

    pub(super) async fn call(port: u16, method: &str, path: &str, authorization: &str, body: &str) -> (u16, String) {
        let (code, _, body) = call_with(port, method, path, authorization, "", body).await;
        (code, body)
    }

    /// `extra` is more header lines, each ending in \r\n. HTTP/1.0, so bodies are never chunked.
    pub(super) async fn call_with(port: u16, method: &str, path: &str, authorization: &str, extra: &str, body: &str) -> (u16, String, String) {
        let mut s = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let auth = if authorization.is_empty() { String::new() } else { format!("Authorization: {authorization}\r\n") };
        let req = format!(
            "{method} {path} HTTP/1.0\r\nHost: 127.0.0.1:{port}\r\n{auth}{extra}Content-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        s.write_all(req.as_bytes()).await.unwrap();
        let mut res = String::new();
        s.read_to_string(&mut res).await.unwrap();
        let code = res.split_whitespace().nth(1).unwrap().parse().unwrap();
        let (head, body) = res.split_once("\r\n\r\n").unwrap_or((&res, ""));
        (code, head.to_string(), body.to_string())
    }

    pub(super) fn audit_list(body: &str) -> Vec<Value> {
        serde_json::from_str::<Value>(body).unwrap()["events"].as_array().cloned().unwrap_or_default()
    }

    #[tokio::test]
    async fn healthz_is_open_and_new_endpoints_need_login() {
        let (port, _, _, _) = serve_app().await;
        assert_eq!(call(port, "GET", "/healthz", "", "").await.0, 200);
        for (m, p) in [
            ("GET", "/api/policy"),
            ("PUT", "/api/policy"),
            ("GET", "/api/approvals"),
            ("POST", "/api/approvals/x/approve"),
            ("POST", "/api/approvals/check"),
            ("GET", "/api/audit"),
            ("GET", "/api/audit/export.csv"),
            ("GET", "/api/audit?action=bot.*"),
            ("GET", "/api/policy/rules"),
        ] {
            assert_eq!(call(port, m, p, "", "{}").await.0, 401, "{m} {p}");
        }
    }

    #[tokio::test]
    async fn bots_cannot_approve_or_change_policy() {
        let (port, app, user, key) = serve_app().await;
        let bot = app.db.create_bot("A", "#fff", "waddle", "claude", None, true);
        let bot_auth = key.auth(&bot.id);
        for (m, p, b) in [
            ("PUT", "/api/policy".to_string(), r#"{"mode":"bypass"}"#),
            ("PUT", format!("/api/bots/{}/policy", bot.id), r#"{"mode":"bypass"}"#),
            ("DELETE", format!("/api/bots/{}/policy", bot.id), ""),
            ("POST", "/api/policy/rules".to_string(), r#"{"action":"allow","pattern":"*"}"#),
            ("GET", "/api/approvals".to_string(), ""),
            ("POST", "/api/approvals/x/approve".to_string(), "{}"),
            ("POST", "/api/approvals/x/deny".to_string(), "{}"),
            ("GET", "/api/audit".to_string(), ""),
            ("GET", "/api/audit/export.csv".to_string(), ""),
        ] {
            assert_eq!(call(port, m, &p, &bot_auth, b).await.0, 403, "{m} {p}");
        }
        assert_eq!(app.db.global_policy().mode, policy::Mode::Ask);
        assert_eq!(call(port, "GET", "/api/policy", &bot_auth, "").await.0, 200);

        let (code, body) = call(port, "PUT", "/api/policy", &user, r#"{"timeoutMinutes":3}"#).await;
        assert_eq!((code, serde_json::from_str::<Value>(&body).unwrap()["policy"]["timeoutMinutes"].as_u64()), (200, Some(3)));
        assert_eq!(call(port, "PUT", "/api/policy", &user, r#"{"mode":"yolo"}"#).await.0, 400);
        let (_, audit) = call(port, "GET", "/api/audit?action=policy.*", &user, "").await;
        assert_eq!(audit_list(&audit)[0]["action"], "policy.updated");
        // Each refused Bot call is on the record.
        let (_, denied) = call(port, "GET", "/api/audit?action=access.denied&actor=bot", &user, "").await;
        let denied = audit_list(&denied);
        assert_eq!(denied.len(), 9);
        assert_eq!((denied[0]["outcome"].as_str(), denied[0]["details"]["path"].as_str()), (Some("denied"), Some("/api/audit/export.csv")));
    }

    #[tokio::test]
    async fn admin_actions_are_audited() {
        let (port, app, user, key) = serve_app().await;
        let browser = "User-Agent: TestBrowser/1.0\r\n";
        let (code, _, body) = call_with(port, "POST", "/api/bots", &user, browser, r#"{"name":"Helper","harness":"claude"}"#).await;
        assert_eq!(code, 201);
        let id = serde_json::from_str::<Value>(&body).unwrap()["id"].as_str().unwrap().to_string();
        call_with(port, "PATCH", &format!("/api/bots/{id}"), &user, browser, r#"{"name":"Helper 2","hidden":true}"#).await;
        call_with(port, "PATCH", &format!("/api/bots/{id}"), &user, browser, r#"{"name":"Helper 2"}"#).await; // no change, no event

        // A Bot's token names it; routine calls are logged with that Bot as the actor.
        let bot_auth = key.auth(&id);
        let botctl = "User-Agent: botctl\r\n";
        let body = r#"{"name":"Standup","cron":"0 9 * * 1-5","instruction":"secret plan: email the team"}"#;
        let (code, _, r) = call_with(port, "POST", &format!("/api/bots/{id}/routines"), &bot_auth, botctl, body).await;
        assert_eq!(code, 201);
        let rid = serde_json::from_str::<Value>(&r).unwrap()["id"].as_str().unwrap().to_string();
        call_with(port, "PATCH", &format!("/api/routines/{rid}"), &bot_auth, botctl, r#"{"enabled":false,"cron":"0 10 * * *"}"#).await;
        call_with(port, "PATCH", &format!("/api/routines/{rid}"), &user, browser, r#"{"enabled":true}"#).await;
        call_with(port, "DELETE", &format!("/api/routines/{rid}"), &bot_auth, botctl, "").await;
        call_with(port, "POST", &format!("/api/bots/{id}/stop"), &user, browser, "").await;
        call_with(port, "DELETE", &format!("/api/bots/{id}"), &user, browser, "").await;
        let wrong_password = random_hex(16);
        let wrong = basic(&wrong_password);
        assert_eq!(call_with(port, "GET", "/api/state", &wrong, browser, "").await.0, 401);
        assert_eq!(call_with(port, "GET", "/api/state", &wrong, browser, "").await.0, 401);
        assert_eq!(call_with(port, "GET", "/api/state", "Bearer nope", "", "").await.0, 401);

        let (code, body) = call(port, "GET", "/api/audit?limit=1000", &user, "").await;
        assert_eq!(code, 200);
        let events = audit_list(&body);
        let mut seen: Vec<(String, String, Option<String>, String)> = events
            .iter()
            .filter(|e| !["policy.initialized", "audit.exported"].contains(&e["action"].as_str().unwrap()))
            .map(|e| {
                let s = |k: &str| e[k].as_str().map(String::from);
                (s("action").unwrap(), s("actorKind").unwrap(), s("actorId"), s("outcome").unwrap())
            })
            .collect();
        seen.reverse();
        let op = Some("operator".to_string());
        let me = Some(id.clone());
        assert_eq!(
            seen,
            [
                ("user.created".into(), "system".into(), Some("bootstrap".into()), "success".into()),
                ("auth.login".into(), "user".into(), op.clone(), "success".into()),
                ("bot.created".into(), "user".into(), op.clone(), "success".into()),
                ("bot.updated".into(), "user".into(), op.clone(), "success".into()),
                ("routine.created".into(), "bot".into(), me.clone(), "success".into()),
                ("routine.disabled".into(), "bot".into(), me.clone(), "success".into()),
                ("routine.updated".into(), "bot".into(), me.clone(), "success".into()),
                ("routine.enabled".into(), "user".into(), op.clone(), "success".into()),
                ("routine.deleted".into(), "bot".into(), me.clone(), "success".into()),
                ("bot.stopped".into(), "user".into(), op.clone(), "success".into()),
                ("bot.deleted".into(), "user".into(), op.clone(), "success".into()),
                ("auth.login_failed".into(), "user".into(), None, "failure".into()),
                ("auth.login_failed".into(), "bot".into(), None, "failure".into()),
                ("auth.login".into(), "user".into(), op.clone(), "success".into()),
            ],
            "the second wrong password from the same IP is throttled; the audit read is a new client (no user agent)"
        );
        let find = |a: &str| events.iter().find(|e| e["action"] == a).unwrap().clone();
        let created = find("bot.created");
        assert_eq!((created["ip"].as_str(), created["userAgent"].as_str()), (Some("127.0.0.1"), Some("TestBrowser/1.0")));
        assert_eq!((created["targetType"].as_str(), created["targetId"].as_str()), (Some("bot"), Some(id.as_str())));
        assert_eq!(find("bot.updated")["details"]["changes"]["name"], json!({ "from": "Helper", "to": "Helper 2" }));
        let routine = find("routine.created");
        assert_eq!((routine["actorName"].as_str(), routine["userAgent"].as_str()), (Some("Helper 2"), Some("botctl")));
        assert_eq!(find("routine.updated")["details"]["changes"]["cron"]["to"], "0 10 * * *");
        assert!(!body.contains("secret plan"), "routine instructions are messages, not audit data");
        assert!(!body.contains(&wrong_password), "passwords are never logged");
        assert_eq!(find("bot.deleted")["details"]["name"], "Helper 2");
        // The log outlives the Bot.
        assert!(app.db.bot(&id).is_none());

        let (_, page) = call(port, "GET", "/api/audit?limit=2", &user, "").await;
        let page: Value = serde_json::from_str(&page).unwrap();
        let next = page["nextBefore"].as_i64().unwrap();
        let (_, older) = call(port, "GET", &format!("/api/audit?limit=2&before={next}"), &user, "").await;
        assert!(audit_list(&older).iter().all(|e| e["id"].as_i64().unwrap() < next));
        let (_, mine) = call(port, "GET", &format!("/api/audit?actor=bot:{id}&action=routine.*"), &user, "").await;
        assert_eq!(audit_list(&mine).len(), 4);
        assert_eq!(call(port, "GET", "/api/audit?from=last-week", &user, "").await.0, 400);
        assert_eq!(call(port, "GET", "/api/audit/export.csv?actor=root", &user, "").await.0, 400);
    }

    #[tokio::test]
    async fn approvals_and_handoffs_are_audited() {
        let (port, app, user, key) = serve_app().await;
        let bot = app.db.create_bot("A", "#fff", "waddle", "claude", None, true);
        let bot_auth = key.auth(&bot.id);
        let check = json!({ "from": bot.id, "harness": "claude", "event": { "tool_name": "Bash", "tool_input": { "command": "git push https://x:tok3n@example.com" }, "cwd": "/tmp" } }).to_string();
        let hook = tokio::spawn({
            let bot_auth = bot_auth.clone();
            async move { call(port, "POST", "/api/approvals/check", &bot_auth, &check).await }
        });
        let pending = loop {
            if let Some(a) = app.db.approvals(Some("pending"), None, 1).pop() {
                break a;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        };
        let (code, _, _) = call_with(port, "POST", &format!("/api/approvals/{}/deny", pending.id), &user, "X-Forwarded-For: 198.51.100.7\r\n", "{}").await;
        assert_eq!(code, 200);
        hook.await.unwrap();

        let handoff = tokio::spawn({
            let (app, bot) = (app.clone(), bot.clone());
            async move { app.handoff(&bot, "Log in to the bank", Duration::from_secs(30)).await }
        });
        let card = loop {
            if let Some(m) = app.db.messages(&bot.id, 10).into_iter().find(|m| m.question.is_some()) {
                break m;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        };
        let answer = json!({ "text": "Done", "answer": { "messageId": card.id, "option": 0 } }).to_string();
        assert_eq!(call(port, "POST", &format!("/api/bots/{}/messages", bot.id), &user, &answer).await.0, 202);
        assert_eq!(handoff.await.unwrap().as_deref(), Some("Done"));

        let (_, body) = call(port, "GET", "/api/audit?action=approval.*,handoff.*", &user, "").await;
        let ev = audit_list(&body);
        let actions: Vec<&str> = ev.iter().map(|e| e["action"].as_str().unwrap()).collect();
        assert_eq!(actions, ["handoff.answered", "handoff.requested", "approval.denied", "approval.requested"]);
        // Behind a proxy on loopback, the client IP is the forwarded one.
        assert_eq!((ev[2]["actorId"].as_str(), ev[2]["ip"].as_str()), (Some("operator"), Some("198.51.100.7")));
        assert_eq!(ev[0]["details"], json!({ "option": "Done", "botWasWaiting": true }));
        assert!(!body.contains("tok3n") && !body.contains("bank"), "{body}");
    }

    #[tokio::test]
    async fn csv_export_is_rfc4180_and_formula_safe() {
        let (port, app, user, _) = serve_app().await;
        let evil = r#"{"name":"=HYPERLINK(\"http://evil.example\",\"x\"), ok"}"#;
        let (code, created) = call(port, "POST", "/api/bots", &user, evil).await;
        assert_eq!(code, 201, "{created}");
        let (code, head, body) = call_with(port, "GET", "/api/audit/export.csv?action=bot.created", &user, "", "").await;
        assert_eq!(code, 200);
        let head = head.to_ascii_lowercase();
        assert!(head.contains("content-type: text/csv; charset=utf-8"), "{head}");
        assert!(head.contains("content-disposition: attachment; filename=\"superbot-audit-"), "{head}");
        let lines: Vec<&str> = body.split("\r\n").collect();
        assert_eq!(format!("{}\r\n", lines[0]), audit::CSV_HEADER);
        assert_eq!(lines.len(), 3, "header, one row, and the final CRLF: {body:?}");
        assert!(lines[1].contains(r#""{""harness"":""claude"",""harnessFrom"":""server"",""model"":null,""name"":""=HYPERLINK"#), "{}", lines[1]);
        assert!(lines[1].split(',').nth(6) == Some("bot.created"));
        // The export itself is audited, and a cell that starts a formula is defused.
        let exported = &app.db.audit_events(&audit::Filter { actions: vec!["audit.exported".into()], ..Default::default() }, 10, false)[0];
        assert_eq!(exported.details["actions"], json!(["bot.created"]));
        let row = audit::csv_row(&db::AuditEvent { actor_name: Some("=1+2".into()), ..exported.clone() });
        assert!(row.contains(",'=1+2,"), "{row}");
        // Many rows stream in batches, oldest first.
        for i in 0..1200 {
            app.db.record(&Event::new(Actor::system("test"), "test.bulk").details(json!({ "i": i })));
        }
        let (_, _, body) = call_with(port, "GET", "/api/audit/export.csv?action=test.bulk", &user, "", "").await;
        let rows: Vec<&str> = body.trim_end().split("\r\n").skip(1).collect();
        assert_eq!(rows.len(), 1200);
        assert!(rows[0].ends_with(r#""{""i"":0}",,,,,,,"#), "{}", rows[0]);
        assert!(rows[1199].ends_with(r#""{""i"":1199}",,,,,,,"#), "{}", rows[1199]);
    }

    #[tokio::test]
    async fn hook_waits_for_a_person_then_runs() {
        let (port, app, user, key) = serve_app().await;
        let bot = app.db.create_bot("A", "#fff", "waddle", "claude", None, true);
        let bot_auth = key.auth(&bot.id);
        let check = |cmd: &str| {
            json!({ "from": bot.id, "harness": "claude", "event": { "tool_name": "Bash", "tool_input": { "command": cmd }, "cwd": "/tmp" } }).to_string()
        };

        let (code, body) = call(port, "POST", "/api/approvals/check", &bot_auth, &check("ls -la")).await;
        assert_eq!((code, body.lines().next()), (200, Some("allow")));

        let hook = tokio::spawn({
            let body = check("git push origin main");
            let bot_auth = bot_auth.clone();
            async move { call(port, "POST", "/api/approvals/check", &bot_auth, &body).await }
        });
        let pending = loop {
            let (_, list) = call(port, "GET", "/api/approvals?status=pending", &user, "").await;
            let list: Vec<Value> = serde_json::from_str(&list).unwrap();
            if let Some(a) = list.into_iter().next() {
                break a;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        };
        assert_eq!(pending["class"], "git_push");
        let id = pending["id"].as_str().unwrap();
        assert_eq!(call(port, "POST", &format!("/api/approvals/{id}/approve"), &bot_auth, "{}").await.0, 403);
        let (code, done) = call(port, "POST", &format!("/api/approvals/{id}/approve"), &user, r#"{"remember":"bot"}"#).await;
        assert_eq!((code, serde_json::from_str::<Value>(&done).unwrap()["status"].as_str()), (200, Some("approved")));
        assert_eq!(hook.await.unwrap().1.lines().next(), Some("allow"));
        assert_eq!(call(port, "POST", &format!("/api/approvals/{id}/deny"), &user, "").await.0, 409);

        let (_, again) = call(port, "POST", "/api/approvals/check", &bot_auth, &check("git push origin main")).await;
        assert_eq!(again.lines().next(), Some("allow"), "remembered");

        let (_, unknown) = call(port, "POST", "/api/approvals/check", &bot_auth, r#"{"from":"nobody","event":{"tool_name":"Bash"}}"#).await;
        assert_eq!(unknown.lines().next(), Some("deny"));

        let deep = format!("echo \"{}{}\"", "$(".repeat(100_000), ")".repeat(100_000));
        for cmd in ["echo \"$(git push", deep.as_str()] {
            let (code, bad) = call(port, "POST", "/api/approvals/check", &bot_auth, &check(cmd)).await;
            assert_eq!((code, bad.lines().next()), (200, Some("deny")), "{cmd:.40}");
        }
        for input in [json!({}), json!({ "command": "ls", "cmd": "git push" })] {
            let body = json!({ "from": bot.id, "harness": "codex", "event": { "tool_name": "exec_command", "tool_input": input } }).to_string();
            let (_, bad) = call(port, "POST", "/api/approvals/check", &bot_auth, &body).await;
            assert_eq!(bad.lines().next(), Some("deny"), "{input}");
        }
        let (_, list) = call(port, "GET", "/api/approvals?status=pending", &user, "").await;
        assert_eq!(list.trim(), "[]", "refused without asking");
    }

    #[tokio::test]
    async fn secrets_api_takes_values_and_never_returns_them() {
        let (port, app, user, key) = serve_app().await;
        let bot_auth = key.auth(&app.db.create_bot("Z", "#fff", "waddle", "claude", None, false).id);
        let name = format!("TEST_{}_API_KEY", random_hex(4).to_uppercase());
        let value = format!("sk-test-{}", random_hex(16));
        let path = format!("/api/secrets/{name}");
        let body = json!({ "value": value }).to_string();
        assert_eq!(call(port, "GET", "/api/secrets", "", "").await.0, 401);
        assert_eq!(call(port, "GET", "/api/secrets", &bot_auth, "").await.0, 403);
        assert_eq!(call(port, "PUT", &path, &bot_auth, &body).await.0, 403);
        assert_eq!(call(port, "PUT", "/api/secrets/PATH", &user, &body).await.0, 400);
        assert_eq!(call(port, "PUT", &path, &user, "{}").await.0, 400);

        let (code, res) = call(port, "PUT", &path, &user, &body).await;
        assert_eq!(code, 200, "{res}");
        assert!(!res.contains(&value));
        let (code, list) = call(port, "GET", "/api/secrets", &user, "").await;
        assert_eq!(code, 200);
        assert!(list.contains(&name) && !list.contains(&value), "{list}");
        assert_eq!(secrets::global().get(&name).unwrap().unwrap().expose(), value);
        assert!(secrets::global().harness_env().iter().any(|(k, v)| *k == name && v.expose() == value));

        // A Bot echoing the value: the saved chat and the audit log hold the mark instead.
        let bot = app.db.create_bot("A", "#fff", "waddle", "claude", None, true);
        let m = app.db.add_message(&bot.id, "bot", &format!("key={value}"), None, false, None);
        assert_eq!(m.text, "key=[redacted]");
        app.db.record(&Event::new(Actor::bot(Some(&bot.id), None), "test.echo").bot(&bot.id).details(json!({ "said": value })));
        let (_, audit) = call(port, "GET", "/api/audit", &user, "").await;
        assert!(!audit.contains(&value) && audit.contains("secret.set") && audit.contains(&name), "{audit}");

        assert_eq!(call(port, "DELETE", &path, &bot_auth, "").await.0, 403);
        assert_eq!(call(port, "DELETE", &path, &user, "").await.0, 200);
        assert_eq!(call(port, "DELETE", &path, &user, "").await.0, 404);
        assert!(secrets::global().get(&name).unwrap().is_none());
    }

    #[test]
    fn routine_fields_validate_and_trim() {
        let f = routine_fields(&json!({ "name": "  Digest ", "cron": "0 9 * * 1-5", "instruction": " Sum up email ", "enabled": false })).unwrap();
        assert_eq!(
            f,
            RoutineFields { name: Some("Digest".into()), cron: Some("0 9 * * 1-5".into()), instruction: Some("Sum up email".into()), enabled: Some(false) }
        );
        assert_eq!(routine_fields(&json!({})).unwrap(), RoutineFields::default());
        assert_eq!(routine_fields(&json!({ "name": null })).unwrap(), RoutineFields::default());
        assert!(routine_fields(&json!({ "name": "   " })).is_err());
        assert!(routine_fields(&json!({ "instruction": "" })).is_err());
        assert!(routine_fields(&json!({ "name": 5 })).is_err());
        assert!(routine_fields(&json!({ "cron": "61 * * * *" })).is_err());
        assert!(routine_fields(&json!({ "cron": "* * *" })).is_err());
        assert!(routine_fields(&json!({ "enabled": "no" })).is_err());
        let long = routine_fields(&json!({ "name": "x".repeat(500) })).unwrap();
        assert_eq!(long.name.unwrap().len(), 100);
    }

    async fn serve_routines() -> (u16, Arc<App>, String, PathBuf) {
        let dir = std::env::temp_dir().join(format!("botd-test-{}", random_hex(6)));
        std::fs::create_dir_all(&dir).unwrap();
        let db = Db::open(&dir.join("app.sqlite")).unwrap();
        let app = App::new(db, Config {
            data_dir: dir.clone(),
            workspace: dir.clone(),
            user_name: "the user".into(),
            bin_dir: dir.clone(),
            api_url: "http://127.0.0.1:0".into(),
            bot_key: "bot-key".into(),
            run_timeout: Duration::from_secs(60),
            default_harness: "claude".into(),
            sandbox_host: sandbox::Host { namespaces: true, programs: sandbox::PROGRAMS.map(String::from).into() },
            home: None,
        }, None);
        app.license.set_testing(true);
        users::ensure_operator(&app.db, "Owner", None);
        let bot = app.db.create_bot("Tester", "#f5f5f5", "waddle", "claude", None, true);
        let router = Router::new()
            .route("/api/bots/{id}/routines", get(list_routines).post(create_routine))
            .route("/api/routines/{id}", patch(update_routine).delete(delete_routine))
            .layer(Extension(Who { actor: Actor::operator(), source: Source::default() }))
            .layer(Extension(Caller { principal: Principal::User(Role::Admin), user: None, session: None, method: "none", bot: None, bot_for: None, bot_token: None, grants: rbac::Perms::NONE }))
            .with_state(app.clone());
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        (port, app, bot.id, dir)
    }

    async fn call_json(port: u16, method: &str, path: &str, body: Option<Value>) -> (u16, Value) {
        let (code, res) = call(port, method, path, "", &body.map(|b| b.to_string()).unwrap_or_default()).await;
        (code, serde_json::from_str(&res).unwrap_or(Value::Null))
    }

    #[tokio::test]
    async fn routine_create_edit_delete() {
        let (port, app, bot, dir) = serve_routines().await;
        let base = format!("/api/bots/{bot}/routines");

        let (code, _) = call_json(port, "POST", &base, Some(json!({ "name": "", "cron": "0 9 * * *", "instruction": "x" }))).await;
        assert_eq!(code, 400);
        let (code, _) = call_json(port, "POST", &base, Some(json!({ "name": "A", "cron": "nope", "instruction": "x" }))).await;
        assert_eq!(code, 400);
        let (code, _) = call_json(port, "POST", "/api/bots/missing/routines", Some(json!({ "name": "A", "cron": "0 9 * * *", "instruction": "x" }))).await;
        assert_eq!(code, 404);

        let (code, r) = call_json(port, "POST", &base, Some(json!({ "name": " Digest ", "cron": "0 9 * * *", "instruction": "Sum up" }))).await;
        assert_eq!(code, 201);
        assert_eq!(r["name"], "Digest");
        assert_eq!(r["enabled"], true);
        let id = r["id"].as_str().unwrap().to_string();
        let path = format!("/api/routines/{id}");

        let (code, paused) = call_json(port, "POST", &base, Some(json!({ "name": "B", "cron": "0 9 * * *", "instruction": "y", "enabled": false }))).await;
        assert_eq!(code, 201);
        assert_eq!(paused["enabled"], false);

        let (code, _) = call_json(port, "PATCH", &path, Some(json!({ "name": "   " }))).await;
        assert_eq!(code, 400);
        let (code, _) = call_json(port, "PATCH", &path, Some(json!({ "cron": "99 * * * *" }))).await;
        assert_eq!(code, 400);
        assert_eq!(app.db.routine(&id).unwrap().name, "Digest");
        assert_eq!(app.db.routine(&id).unwrap().cron, "0 9 * * *");

        let edit = json!({ "name": " Weekday digest ", "cron": "30 8 * * 1-5", "instruction": "Sum up email", "enabled": false });
        let (code, r) = call_json(port, "PATCH", &path, Some(edit)).await;
        assert_eq!(code, 200);
        assert_eq!(r["name"], "Weekday digest");
        assert_eq!(r["cron"], "30 8 * * 1-5");
        assert_eq!(r["instruction"], "Sum up email");
        assert_eq!(r["enabled"], false);

        let (code, list) = call_json(port, "GET", &base, None).await;
        assert_eq!(code, 200);
        assert_eq!(list.as_array().unwrap().len(), 2);

        let (code, _) = call_json(port, "DELETE", &path, None).await;
        assert_eq!(code, 200);
        assert!(app.db.routine(&id).is_none());
        let (code, _) = call_json(port, "PATCH", &path, Some(json!({ "enabled": true }))).await;
        assert_eq!(code, 404);
        let (code, _) = call_json(port, "DELETE", &path, None).await;
        assert_eq!(code, 404);

        let events = app.db.audit_events(&audit::Filter { actions: vec!["routine.*".into()], ..Default::default() }, 100, true);
        let seen: Vec<(&str, Option<&str>)> = events.iter().map(|e| (e.action.as_str(), e.target_id.as_deref())).collect();
        let paused_id = paused["id"].as_str();
        assert_eq!(
            seen,
            [
                ("routine.created", Some(id.as_str())),
                ("routine.created", paused_id),
                ("routine.disabled", Some(id.as_str())),
                ("routine.updated", Some(id.as_str())),
                ("routine.deleted", Some(id.as_str())),
            ],
            "rejected and missing-routine requests are not logged"
        );
        assert!(events.iter().all(|e| e.actor_id.as_deref() == Some("operator") && e.bot_id.as_deref() == Some(bot.as_str())));
        assert_eq!(events[1].details["enabled"], false);
        assert_eq!(events[3].details["changes"]["instruction"], "changed", "the instruction text is not logged");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn bot_view_reports_the_open_handoff() {
        let (_, app, bot, dir) = serve_routines().await;
        let card = |title: &str| json!({ "title": title, "options": ["Done", "I can't right now"], "handoff": true });
        let view = |app: &App| app.bot_view(&app.db.bot(&bot).unwrap())["handoff"].clone();
        assert_eq!(view(&app), Value::Null);

        app.db.add_message(&bot, "bot", "", Some(&json!({ "title": "Pick", "options": ["A", "B"] })), false, None);
        assert_eq!(view(&app), Value::Null);

        let first = app.db.add_message(&bot, "bot", "", Some(&card("Log in")), false, None);
        assert_eq!(view(&app), json!(first.id));
        app.db.add_message(&bot, "user", "later", None, false, None);
        assert_eq!(view(&app), Value::Null);

        let second = app.db.add_message(&bot, "bot", "", Some(&card("2FA")), false, None);
        assert_eq!(view(&app), json!(second.id));
        let mut q = card("2FA");
        q["picked"] = json!(0);
        app.db.set_question(second.id, &q);
        assert_eq!(view(&app), Value::Null);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn allowed_host_names() {
        assert_eq!(
            allowed_hosts("::1", 3000, "")[0..4],
            ["[::1]:3000", "localhost:3000", "127.0.0.1:3000", "[::1]:3000"]
        );
        let list = allowed_hosts("127.0.0.1", 3000, " Bots.Example.com ,");
        assert!(list.iter().any(|h| h == "bots.example.com"));
    }
}
